"""Read-only, revision-pinned GitHub dependency scanning. Never runs repository code."""

import asyncio
import base64
import difflib
import hashlib
import json
import os
import re
import time
from pathlib import PurePosixPath
from urllib.parse import quote, urlparse
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from packageurl import PackageURL
from pydantic import BaseModel, ConfigDict, Field

from .enterprise import human
from .github_integration import admin
from .governance import Governance
from .investigation.ledger import digest
from .osv import OSVError
from .sbom import Package

router = APIRouter(prefix="/api/repositories")
PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)\s*==\s*(?P<version>[0-9][A-Za-z0-9.!+_-]*)(?P<tail>\s*(?:#.*)?)$"
)
SHA = re.compile(r"[0-9a-f]{40}")
NUMERIC = re.compile(r"\d+\.\d+\.\d+")


def repository_name(value):
    value = value.strip().removesuffix("/")
    if value.startswith("https://"):
        parsed = urlparse(value)
        if parsed.netloc != "github.com" or parsed.query or parsed.fragment:
            raise ValueError("Use a github.com repository URL, without query parameters.")
        value = parsed.path.lstrip("/")
    value = value.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", value) or value.split("/")[1] in (".", ".."):
        raise ValueError("Enter a repository such as https://github.com/owner/project.")
    return value


class ScanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repository: str = Field(min_length=3, max_length=250)


class Choice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: int


class Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: str = Field(pattern="^(approved|rejected)$")
    sha256: str = Field(pattern="^[a-f0-9]{64}$")


class GitHubReader:
    def __init__(self, repository):
        self.repository = repository

    async def get(self, path):
        # No caller-controlled host or redirects; public repositories only.
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            async with client.stream(
                "GET",
                "https://api.github.com/repos/" + self.repository + path,
                headers={"Accept": "application/vnd.github+json"},
            ) as response:
                if response.status_code != 200:
                    raise ValueError(
                        "GitHub could not read this public repository. Check the URL or try again after its rate limit resets."
                    )
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > 8_000_000:
                        raise ValueError("GitHub response exceeds this scanner's size limit.")
                return json.loads(content)

    async def snapshot(self):
        metadata = await self.get("")
        if metadata.get("private"):
            raise ValueError("This scanner currently accepts public repositories only.")
        branch = metadata["default_branch"]
        commit = await self.get("/commits/" + quote(branch, safe=""))
        sha = commit["sha"]
        if not SHA.fullmatch(sha):
            raise ValueError("GitHub returned an invalid revision.")
        tree = await self.get("/git/trees/" + commit["commit"]["tree"]["sha"] + "?recursive=1")
        if tree.get("truncated") or len(tree["tree"]) > 20000:
            raise ValueError(
                "Repository is too large for a complete scan here (20,000 file entries). No clean result is claimed."
            )
        files, skipped, modes = {}, [], {}
        entries = []
        unsupported = {
            "poetry.lock",
            "uv.lock",
            "Pipfile.lock",
            "yarn.lock",
            "pnpm-lock.yaml",
            "pom.xml",
            "go.mod",
            "Cargo.lock",
            "composer.lock",
            "Gemfile.lock",
            "pyproject.toml",
        }
        for entry in tree["tree"]:
            path = entry["path"]
            parts = PurePosixPath(path).parts
            if any(p in ("node_modules", ".venv", "venv", "vendor") for p in parts):
                continue
            name = parts[-1]
            if name in unsupported:
                skipped.append({"path": path, "reason": "This dependency file format is not supported yet."})
            supported = (name.startswith("requirements") and name.endswith(".txt")) or name in (
                "package-lock.json",
                "package.json",
            )
            if not supported:
                continue
            if entry.get("mode") not in ("100644", "100755") or entry.get("type") != "blob":
                skipped.append({"path": path, "reason": "Links and submodules are not followed."})
                continue
            if any(x in path for x in ("\n", "\r", "\t", "\x00", "\\")) or ".." in parts:
                raise ValueError("Unsupported repository filename.")
            if entry.get("size", 0) > 1_000_000:
                raise ValueError("A dependency file exceeds the 1 MB scan limit.")
            entries.append(entry)
        if len(entries) > 40:
            raise ValueError(
                "Repository contains more than 40 supported dependency files. Scan a smaller repository."
            )
        for entry in entries:
            if not SHA.fullmatch(entry["sha"]):
                raise ValueError("Invalid GitHub file revision.")
            blob = await self.get("/git/blobs/" + entry["sha"])
            raw = base64.b64decode(blob["content"])
            if (
                len(raw) > 1_000_000
                or hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() != entry["sha"]
            ):
                raise ValueError("Repository file integrity check failed.")
            files[entry["path"]] = raw.decode("utf-8")
            modes[entry["path"]] = entry["mode"]
        return {
            "repository": self.repository,
            "branch": branch,
            "commit": sha,
            "files": files,
            "modes": modes,
            "skipped": skipped,
        }


def inventory(files):
    packages, locations, skipped = {}, {}, []

    def add(kind, name, version, path, line=None):
        if not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.!+_-]{0,99}", version):
            skipped.append({"path": path, "reason": f"{name}: no exact supported installed version."})
            return
        namespace = None
        if kind == "npm" and name.startswith("@") and "/" in name:
            namespace, name = name.split("/", 1)
        purl = PackageURL(type=kind, namespace=namespace, name=name, version=version).to_string()
        packages[purl] = Package(
            name=(namespace + "/" if namespace else "") + name,
            version=version,
            purl=purl,
            refs=[path],
            relationships=["unknown"],
        )
        locations.setdefault(purl, []).append({"path": path, "line": line})

    for path, content in files.items():
        name = PurePosixPath(path).name
        if name.startswith("requirements") and name.endswith(".txt"):
            for index, line in enumerate(content.splitlines(), 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                match = PIN.fullmatch(line.strip())
                if match:
                    add("pypi", match["name"], match["version"], path, index)
                else:
                    skipped.append(
                        {
                            "path": path,
                            "reason": f"Line {index}: not a simple exact version. Includes, ranges, extras, hashes and environment conditions require a resolved inventory.",
                        }
                    )
        elif name == "package-lock.json":
            data = json.loads(content)
            if data.get("lockfileVersion") not in (2, 3) or not isinstance(data.get("packages"), dict):
                skipped.append({"path": path, "reason": "Only npm lockfile versions 2 and 3 are supported."})
                continue
            for location, package in data["packages"].items():
                if not location or package.get("link") or "node_modules/" not in location:
                    continue
                package_name = package.get("name") or location.rsplit("node_modules/", 1)[1]
                add("npm", package_name, package.get("version"), path)
        elif name == "package.json":
            lock = str(PurePosixPath(path).with_name("package-lock.json"))
            if lock in files:
                continue
            data = json.loads(content)
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for package, version in data.get(section, {}).items():
                    add("npm", package, version, path)
            skipped.append(
                {
                    "path": path,
                    "reason": "No npm lockfile: only exact direct versions are checked; indirect dependencies are unknown.",
                }
            )
    if len(packages) > 250:
        raise ValueError(
            "More than 250 distinct package versions found. No partial clean result is reported."
        )
    return list(packages.values()), locations, skipped


def group_findings(findings):
    """Merge aliases for the same package/version; retain every source report."""
    groups = []
    for finding in findings:
        record = finding.model_dump()
        identifiers = {record["advisory_id"], *record["aliases"]}
        matching = [
            g
            for g in groups
            if g["package"]["purl"] == record["package"]["purl"] and identifiers.intersection(g["report_ids"])
        ]
        reports = [{"id": record["advisory_id"], "url": record["url"], "summary": record["summary"]}]
        for group in matching:
            identifiers.update(group["report_ids"])
            reports.extend(group["reports"])
            groups.remove(group)
        if matching:
            record = matching[0].copy()
        record["report_ids"] = sorted(identifiers)
        record["reports"] = reports
        record["aliases"] = sorted(identifiers - {record["advisory_id"]})
        groups.append(record)
    for index, group in enumerate(groups, 1):
        group["id"] = index
    return groups


def initialize(state):
    with state.store.connection() as db:
        db.execute("CREATE TABLE IF NOT EXISTS repository_scans (id TEXT PRIMARY KEY, payload TEXT NOT NULL)")
        for row in db.execute("SELECT id,payload FROM repository_scans").fetchall():
            data = json.loads(row["payload"])
            if data["status"] == "scanning":
                data.update(
                    status="failed",
                    error="The server restarted during this scan. Start a new scan; no complete result was recorded.",
                )
                db.execute("UPDATE repository_scans SET payload=? WHERE id=?", (json.dumps(data), row["id"]))
    state.repository_tasks = set()


def save(store, data):
    with store.connection() as db:
        db.execute("INSERT OR REPLACE INTO repository_scans VALUES (?,?)", (data["id"], json.dumps(data)))


def read(store, identifier):
    with store.connection(read_only=True) as db:
        row = db.execute("SELECT payload FROM repository_scans WHERE id=?", (str(identifier),)).fetchone()
    if not row:
        raise HTTPException(404, "Scan not found.")
    return json.loads(row["payload"])


def public(data):
    return {k: v for k, v in data.items() if k != "files"}


async def scan(state, data):
    try:
        async with asyncio.timeout(150):
            snapshot = await GitHubReader(data["repository"]).snapshot()
            data.update(snapshot)
            packages, locations, skipped = inventory(data["files"])
            data["skipped"].extend(skipped)
            data["packages"] = [p.model_dump() for p in packages]
            data["locations"] = locations
            data["stage"] = "Checking exact package versions against public vulnerability reports"
            save(state.store, data)
            findings = await state.osv.enrich(packages) if packages else []
            data["findings"] = group_findings(findings)
            data["source_report_count"] = len(findings)
            data["status"] = "complete"
            data["stage"] = "Scan complete"
            data["finished"] = time.time()
    except (ValueError, OSVError) as error:
        data.update(status="failed", error=str(error))
    except Exception:
        data.update(
            status="failed",
            error="The scan could not finish. GitHub or the vulnerability service may be unavailable. Try again; no clean result is claimed.",
        )
    save(state.store, data)


@router.post("", status_code=202)
async def start(request: Request, body: ScanInput):
    human(request)
    state = request.app.state
    if len(state.repository_tasks) >= 2:
        raise HTTPException(429, "Two scans are already running. Wait for one to finish.")
    try:
        repo = repository_name(body.repository)
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    data = {
        "id": str(uuid4()),
        "repository": repo,
        "created": time.time(),
        "status": "scanning",
        "stage": "Reading the repository's default branch",
        "findings": [],
        "skipped": [],
        "packages": [],
        "proposals": [],
        "audit": [],
        "mode": "live_dependency_scan",
        "model_cost_usd": 0,
    }
    save(state.store, data)
    task = asyncio.create_task(scan(state, data))
    state.repository_tasks.add(task)
    task.add_done_callback(state.repository_tasks.discard)
    return public(data)


@router.get("")
def history(request: Request):
    with request.app.state.store.connection(read_only=True) as db:
        rows = db.execute("SELECT payload FROM repository_scans ORDER BY rowid DESC LIMIT 20").fetchall()
    return [
        {k: d.get(k) for k in ("id", "repository", "status", "created", "commit")}
        for d in (json.loads(row["payload"]) for row in rows)
    ]


@router.get("/{identifier}")
def result(request: Request, identifier: UUID):
    return public(read(request.app.state.store, identifier))


async def candidate_for(package):
    python = package.purl.startswith("pkg:pypi/")
    url = (
        ("https://pypi.org/pypi/" + quote(package.name, safe="") + "/json")
        if python
        else ("https://registry.npmjs.org/" + quote(package.name, safe="") + "/latest")
    )
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.get(url)
        response.raise_for_status()
        data = response.json()
    version = data["info"]["version"] if python else data["version"]
    if (
        not NUMERIC.fullmatch(version)
        or not NUMERIC.fullmatch(package.version)
        or tuple(map(int, version.split("."))) <= tuple(map(int, package.version.split(".")))
    ):
        raise ValueError("No newer stable numeric release could be selected automatically.")
    if python and not any(not f.get("yanked") for f in data.get("urls", [])):
        raise ValueError("The candidate release has no available non-withdrawn distribution.")
    if not python and (data.get("deprecated") or not data.get("dist", {}).get("integrity")):
        raise ValueError("The npm release is deprecated or lacks integrity metadata.")
    return version


@router.post("/{identifier}/proposals")
async def propose(request: Request, identifier: UUID, choice: Choice):
    human(request)
    store = request.app.state.store
    data = read(store, identifier)
    if data["status"] != "complete":
        raise HTTPException(409, "Wait for a complete scan before preparing a change.")
    finding = next((f for f in data["findings"] if f["id"] == choice.finding_id), None)
    if not finding:
        raise HTTPException(404, "Finding not found.")
    for proposal in data["proposals"]:
        if (
            proposal["finding_id"] == choice.finding_id
            or proposal.get("package_purl") == finding["package"]["purl"]
        ):
            return proposal
    package = Package.model_validate(finding["package"])
    is_python = package.purl.startswith("pkg:pypi/")
    changes, patch = [], ""
    version = None
    check = "Not run: lockfile changes need the project's package manager."
    npm_direct = package.purl.startswith("pkg:npm/") and all(
        PurePosixPath(loc["path"]).name == "package.json" for loc in data["locations"][package.purl]
    )
    if is_python or npm_direct:
        try:
            version = await candidate_for(package)
            upgraded = package.model_copy(
                update={
                    "version": version,
                    "purl": package.purl.rsplit("@", 1)[0] + "@" + version,
                }
            )
            remaining = await request.app.state.osv.enrich([upgraded])
            if remaining:
                raise ValueError(
                    "The candidate still has reported vulnerabilities. No automatic patch was prepared."
                )
            for location in data["locations"][package.purl]:
                path = location["path"]
                if any(c["path"] == path for c in changes):
                    continue
                before = data["files"][path]
                if is_python:
                    lines = before.splitlines(keepends=True)
                    for loc in data["locations"][package.purl]:
                        if loc["path"] == path:
                            index = loc["line"] - 1
                            lines[index] = (
                                lines[index].replace("==" + package.version, "==" + version)
                                if "==" + package.version in lines[index]
                                else re.sub(
                                    r"(==\s*)" + re.escape(package.version) + r"(?=\s|$)",
                                    lambda m: m[1] + version,
                                    lines[index],
                                )
                            )
                    after = "".join(lines)
                else:
                    manifest = json.loads(before)
                    for section in ("dependencies", "devDependencies", "optionalDependencies"):
                        if manifest.get(section, {}).get(package.name) == package.version:
                            manifest[section][package.name] = version
                    after = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
                if before != after:
                    changes.append(
                        {
                            "path": path,
                            "before": before,
                            "after": after,
                            "mode": data.get("modes", {}).get(path, "100644"),
                        }
                    )
                    patch += "".join(
                        line if line.endswith("\n") else line + "\n\\ No newline at end of file\n"
                        for line in difflib.unified_diff(
                            before.splitlines(True),
                            after.splitlines(True),
                            fromfile="a/" + path,
                            tofile="b/" + path,
                        )
                    )
            check = "The proposed package version returned no known vulnerabilities in the new OSV query. This does not prove application compatibility."
        except (ValueError, OSVError) as error:
            raise HTTPException(409, str(error)) from error
        except Exception as error:
            raise HTTPException(
                503,
                "Could not verify an upgrade with the package registry and OSV. No proposal was saved; try again.",
            ) from error
    title = f"Update {package.name} from {package.version}" + (
        f" to {version}" if version else " to address reported vulnerabilities"
    )
    related = [f for f in data["findings"] if f["package"]["purl"] == package.purl]
    body = (
        f"## Proposed change\n{title}.\n\nRepository: {data['repository']}\nReviewed revision: {data['commit']}\n\n## Why\n"
        + "\n".join(f"- {f['advisory_id']}: {f['url']}" for f in related)
    )
    body += (
        "\n\n## Checks\n"
        + check
        + "\nApplication tests have NOT been run. Run the project's tests and review compatibility before merging."
    )
    if data["repository"].lower().endswith("/juice-shop"):
        body += "\n\n## Training application\nJuice Shop is intentionally vulnerable. This dependency update may disable challenges or change training behavior; review that tradeoff before merging."
    if not changes:
        body += "\n\n## Required developer work\nUpdate the affected dependency with the project's package manager, regenerate the lockfile, inspect indirect dependency changes, and rerun the vulnerability scan. No file changes have been generated."
    proposal = {
        "id": str(uuid4()),
        "finding_id": choice.finding_id,
        "package_purl": package.purl,
        "title": title,
        "body": body,
        "changes": changes,
        "patch": patch,
        "candidate": version,
        "validation": check,
        "tests": "Not run",
        "status": "pending",
        "created": time.time(),
        "target": data["repository"],
        "base_commit": data["commit"],
        "expires": None,
    }
    proposal["sha256"] = proposal_digest(proposal)
    # Re-read inside a transaction to avoid overwriting a concurrent proposal/review.
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        current = json.loads(
            db.execute("SELECT payload FROM repository_scans WHERE id=?", (str(identifier),)).fetchone()[
                "payload"
            ]
        )
        existing = next(
            (
                p
                for p in current["proposals"]
                if p["finding_id"] == choice.finding_id or p.get("package_purl") == package.purl
            ),
            None,
        )
        if existing:
            return existing
        current["proposals"].append(proposal)
        audit(store, db, current, "proposal.prepared", "pending", "No GitHub files changed")
        db.execute("UPDATE repository_scans SET payload=? WHERE id=?", (json.dumps(current), str(identifier)))
    return proposal


def proposal_digest(proposal):
    return digest({k: proposal[k] for k in ("title", "body", "changes", "patch", "target", "base_commit")})


def audit(store, db, data, action, decision, reason):
    data["audit"].append({"time": time.time(), "action": action, "decision": decision, "reason": reason})
    Governance(store)._event(db, "local-human", action, "repository:" + data["id"], decision, reason)


@router.post("/{identifier}/proposals/{proposal_id}/review")
def review(request: Request, identifier: UUID, proposal_id: UUID, choice: Review):
    human(request, admin=True)
    store = request.app.state.store
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT payload FROM repository_scans WHERE id=?", (str(identifier),)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found.")
        data = json.loads(row["payload"])
        proposal = next((p for p in data["proposals"] if p["id"] == str(proposal_id)), None)
        if not proposal or proposal["status"] in ("publishing", "published", "uncertain"):
            raise HTTPException(409, "This proposal can no longer be reviewed.")
        if choice.sha256 != proposal_digest(proposal) or choice.sha256 != proposal["sha256"]:
            raise HTTPException(409, "The change differs from what you reviewed. Reload before approving.")
        proposal.update(
            status=choice.decision, expires=time.time() + 300 if choice.decision == "approved" else None
        )
        audit(
            store,
            db,
            data,
            "proposal.review",
            choice.decision,
            "Exact proposal reviewed; approval lasts five minutes",
        )
        db.execute("UPDATE repository_scans SET payload=? WHERE id=?", (json.dumps(data), str(identifier)))
    return proposal


@router.get("/{identifier}/proposals/{proposal_id}/patch")
def download(request: Request, identifier: UUID, proposal_id: UUID):
    human(request)
    data = read(request.app.state.store, identifier)
    proposal = next((p for p in data["proposals"] if p["id"] == str(proposal_id)), None)
    if (
        not proposal
        or proposal["status"] != "approved"
        or proposal["expires"] <= time.time()
        or proposal["sha256"] != proposal_digest(proposal)
    ):
        raise HTTPException(
            403, "Review and approve this exact change before downloading it. Approval lasts five minutes."
        )
    if not proposal["patch"]:
        raise HTTPException(409, "This is a developer action plan; no patch has been generated.")
    return Response(
        proposal["patch"],
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="proposed-change.patch"'},
    )


def publishing_repositories():
    value = os.getenv("AGENTSEC_GITHUB_REPOSITORIES", "") or os.getenv("AGENTSEC_GITHUB_REPOSITORY", "")
    try:
        return [repository_name(r.strip()).lower() for r in value.split(",") if r.strip()]
    except ValueError:
        return []


@router.get("/settings/publishing")
def publishing_settings():
    return {
        "repositories": publishing_repositories(),
        "configured": bool(
            publishing_repositories()
            and os.getenv("AGENTSEC_GITHUB_TOKEN")
            and len(os.getenv("AGENTSEC_APPROVER_PASSWORD", "")) >= 16
        ),
    }


@router.post("/{identifier}/proposals/{proposal_id}/publish")
async def publish(request: Request, identifier: UUID, proposal_id: UUID, actor: str = Depends(admin)):
    token = os.getenv("AGENTSEC_GITHUB_TOKEN", "")
    if not token:
        raise HTTPException(503, "GitHub publishing is not connected.")
    store = request.app.state.store
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT payload FROM repository_scans WHERE id=?", (str(identifier),)).fetchone()
        if not row:
            raise HTTPException(404, "Scan not found.")
        data = json.loads(row["payload"])
        repo = data["repository"]
        proposal = next((p for p in data["proposals"] if p["id"] == str(proposal_id)), None)
        if (
            not proposal
            or proposal["status"] != "approved"
            or proposal["expires"] <= time.time()
            or proposal["sha256"] != proposal_digest(proposal)
            or proposal["target"].lower() != repo.lower()
            or repo.lower() not in publishing_repositories()
            or not proposal["changes"]
        ):
            raise HTTPException(
                403, "A current approval for this exact repository and file change is required."
            )
        proposal["status"] = "publishing"
        audit(store, db, data, "github.pull_request", "claimed", "Single-use approved proposal claimed")
        db.execute("UPDATE repository_scans SET payload=? WHERE id=?", (json.dumps(data), str(identifier)))
    branch = "agentsec/" + proposal["id"]
    wrote = False
    try:
        async with httpx.AsyncClient(
            base_url="https://api.github.com",
            timeout=20,
            follow_redirects=False,
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json"},
        ) as client:

            async def call(method, path, body=None):
                response = await client.request(method, "/repos/" + repo + path, json=body)
                response.raise_for_status()
                return response.json()

            latest = await call("GET", "/commits/" + quote(data["branch"], safe=""))
            if latest["sha"] != proposal["base_commit"]:
                raise ValueError("The repository changed since this scan. Scan it again before publishing.")
            wrote = True
            tree = await call(
                "POST",
                "/git/trees",
                {
                    "base_tree": latest["commit"]["tree"]["sha"],
                    "tree": [
                        {
                            "path": c["path"],
                            "mode": c.get("mode", "100644"),
                            "type": "blob",
                            "content": c["after"],
                        }
                        for c in proposal["changes"]
                    ],
                },
            )
            commit = await call(
                "POST",
                "/git/commits",
                {"message": proposal["title"], "tree": tree["sha"], "parents": [latest["sha"]]},
            )
            await call("POST", "/git/refs", {"ref": "refs/heads/" + branch, "sha": commit["sha"]})
            pr = await call(
                "POST",
                "/pulls",
                {
                    "title": proposal["title"],
                    "body": proposal["body"],
                    "head": branch,
                    "base": data["branch"],
                    "draft": True,
                },
            )
            url = pr["html_url"]
            if not url.startswith("https://github.com/" + repo + "/pull/"):
                raise ValueError("Unexpected GitHub result URL.")
            proposal.update(status="published", pull_request_url=url)
    except Exception:
        proposal.update(
            status="uncertain" if wrote else "rejected",
            publication_error="GitHub may have received part of this change. Check branch "
            + branch
            + " before retrying."
            if wrote
            else "Could not confirm the original repository revision. Start a new scan before publishing.",
        )
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        current = json.loads(
            db.execute("SELECT payload FROM repository_scans WHERE id=?", (str(identifier),)).fetchone()[
                "payload"
            ]
        )
        current["proposals"] = [proposal if p["id"] == proposal["id"] else p for p in current["proposals"]]
        audit(
            store,
            db,
            current,
            "github.pull_request",
            proposal["status"],
            proposal.get("publication_error", "Draft pull request created; nothing merged"),
        )
        db.execute("UPDATE repository_scans SET payload=? WHERE id=?", (json.dumps(current), str(identifier)))
    return proposal
