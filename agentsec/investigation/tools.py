import asyncio
import hashlib
import io
import json
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import httpx

from ..governance import TOOL_ACTIONS, Governance

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "samples/redirect-client"
ADVISORY = "GHSA-34jh-p97f-mpxf"
ORIGINAL = "1.26.18"
TOOLS = {
    "inspect_repository": "repository.read",
    "lookup_advisory": "vulnerability.read",
    "check_candidate": "vulnerability.read",
    "propose_patch": "remediation.patch",
    "validate_patch": "validation.execute",
}

TOOL_ACTIONS.update(TOOLS)


async def fetch(url):
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def prepare(work):
    work.mkdir(parents=True, exist_ok=True)
    meta = await fetch("https://pypi.org/pypi/urllib3/json")
    candidate = meta["info"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", candidate):
        raise RuntimeError("Registry candidate is not a stable numeric version")
    for label, version in [("before", ORIGINAL), ("after", candidate)]:
        folder = work / label
        folder.mkdir(exist_ok=True)
        for name in ("client.py", "test_client.py"):
            shutil.copyfile(SAMPLE / name, folder / name)
        (folder / "requirements.txt").write_text(f"urllib3=={ORIGINAL}\n")
        registry = await fetch(f"https://pypi.org/pypi/urllib3/{version}/json")
        wheel = next(
            f
            for f in registry["urls"]
            if f["filename"].endswith("py3-none-any.whl") or f["filename"].endswith("py2.py3-none-any.whl")
        )
        if not wheel["url"].startswith("https://files.pythonhosted.org/"):
            raise RuntimeError("Untrusted artifact host")
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.get(wheel["url"])
            response.raise_for_status()
        if (
            len(response.content) > 5_000_000
            or hashlib.sha256(response.content).hexdigest() != wheel["digests"]["sha256"]
        ):
            raise RuntimeError("Wheel integrity validation failed")
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            for entry in archive.infolist():
                path = (folder / entry.filename).resolve()
                if (
                    not path.is_relative_to(folder.resolve())
                    or (entry.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise RuntimeError("Unsafe wheel path")
            archive.extractall(folder)
        (folder / "artifact.json").write_text(
            json.dumps({"version": version, "sha256": wheel["digests"]["sha256"], "source": wheel["url"]})
        )
    return candidate


def validate_folder(folder):
    folder = folder.resolve()
    python = Path(sys.executable).resolve()
    if platform.system() == "Darwin" and Path("/usr/bin/sandbox-exec").exists():
        # No user home reads, no network, and no executable other than this Python interpreter.
        read_roots = [
            str(folder),
            str(Path(sys.base_prefix).resolve()),
            "/System",
            "/opt/homebrew/Cellar",
            "/opt/homebrew/opt",
            "/usr/lib",
            "/usr/share",
            "/dev",
            "/private/var/db/timezone",
        ]
        profile = (
            "(version 1)(deny default)(allow sysctl-read)(allow process-fork)(allow file-read-metadata)(allow mach-lookup (global-name "
            + json.dumps("com.apple.system.logger")
            + "))"
        )
        profile += "(allow process-exec (subpath " + json.dumps(str(Path(sys.base_prefix).resolve())) + "))"
        profile += (
            '(allow file-read* (literal "/") '
            + " ".join("(subpath " + json.dumps(p) + ")" for p in read_roots)
            + ")"
        )
        profile += "(allow file-write* (subpath " + json.dumps(str(folder)) + "))"
        command = [
            "/usr/bin/sandbox-exec",
            "-p",
            profile,
            str(python),
            "-B",
            "-I",
            "-c",
            "import sys,runpy;sys.path.insert(0,"
            + repr(str(folder))
            + ");runpy.run_path("
            + repr(str(folder / "test_client.py"))
            + ',run_name="__main__")',
        ]
        backend = "macOS Seatbelt: deny network, scoped reads/writes, fixed Python command"
    elif shutil.which("docker"):
        # Container image must already exist; never fetch or mount the Docker socket inside it.
        command = [
            "docker",
            "run",
            "--rm",
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--pids-limit=32",
            "--memory=128m",
            "--cpus=1",
            "--user=65534:65534",
            "-v",
            f"{folder}:/sample:ro",
            "-w",
            "/sample",
            "python:3.12-slim",
            "python",
            "-B",
            "-I",
            "-c",
            "import sys,runpy;sys.path.insert(0,'/sample');runpy.run_path('/sample/test_client.py',run_name='__main__')",
        ]
        backend = "Docker: network disabled, read-only filesystem, bounded resources"
    else:
        raise RuntimeError("No supported sandbox; validation refused")
    result = subprocess.run(
        command,
        cwd=folder,
        env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
        capture_output=True,
        text=True,
        timeout=20,
    )
    output = (result.stdout + result.stderr)[-12000:]
    if "Ran 3 tests" not in output:
        raise RuntimeError(
            "Sandbox could not execute the curated tests (exit "
            + str(result.returncode)
            + "): "
            + output[-500:]
        )
    return {
        "exit_code": result.returncode,
        "passed": result.returncode == 0,
        "output": output,
        "sandbox": backend,
        "checks": 3,
    }


class ToolRunner:
    def __init__(self, store, token, run_id, work, candidate):
        self.policy = Governance(store)
        self.token = token
        self.resource = "scan:" + run_id
        self.work = Path(work)
        self.candidate = candidate

    async def run(self, tool):
        self.policy.authorize(self.token, tool, self.resource)
        if tool == "inspect_repository":
            return {
                "repository": "curated redirect-client",
                "original": ORIGINAL,
                "candidate": self.candidate,
                "files": {
                    p: (self.work / "before" / p).read_text()
                    for p in ("requirements.txt", "client.py", "test_client.py")
                },
            }
        if tool == "lookup_advisory":
            advisory = await fetch("https://api.osv.dev/v1/vulns/" + ADVISORY)
            return {
                "id": advisory["id"],
                "source": "https://osv.dev/vulnerability/" + ADVISORY,
                "summary": advisory.get("summary"),
                "details": advisory.get("details", "")[:10000],
                "affected": advisory.get("affected"),
                "modified": advisory.get("modified"),
            }
        if tool == "check_candidate":
            async with httpx.AsyncClient(timeout=15) as client:
                findings = {}
                for version in (ORIGINAL, self.candidate):
                    r = await client.post(
                        "https://api.osv.dev/v1/query",
                        json={"package": {"ecosystem": "PyPI", "name": "urllib3"}, "version": version},
                    )
                    r.raise_for_status()
                    findings[version] = [v["id"] for v in r.json().get("vulns", [])]
            return {
                "source": "OSV live query",
                "by_version": findings,
                "target_found_before": ADVISORY in findings[ORIGINAL],
                "target_found_after": ADVISORY in findings[self.candidate],
                "reachability": "unknown",
            }
        if tool == "propose_patch":
            import difflib

            before = (self.work / "before/requirements.txt").read_text()
            (self.work / "after/requirements.txt").write_text(f"urllib3=={self.candidate}\n")
            after = (self.work / "after/requirements.txt").read_text()
            patch = "".join(
                difflib.unified_diff(
                    before.splitlines(True),
                    after.splitlines(True),
                    fromfile="a/requirements.txt",
                    tofile="b/requirements.txt",
                )
            )
            (self.work / "remediation.patch").write_text(patch)
            return {
                "diff": patch,
                "sha256": hashlib.sha256(patch.encode()).hexdigest(),
                "effect": "Dependency pin changed in isolated after workspace; source repository unchanged",
            }
        if tool == "validate_patch":
            if not (self.work / "remediation.patch").exists():
                raise RuntimeError("Generate the isolated patch before validating it")
            before = await asyncio.to_thread(validate_folder, self.work / "before")
            after = await asyncio.to_thread(validate_folder, self.work / "after")
            return {
                "before": before,
                "after": after,
                "scope": "Package policy regression and sample compatibility; not proof of exploit prevention",
            }
        raise RuntimeError("Unknown tool")
