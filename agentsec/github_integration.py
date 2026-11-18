"""Opt-in GitHub adapter; no network retries after an ambiguous write outcome."""

import os
import re
import secrets
import time
from uuid import UUID, uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, ConfigDict

from .enterprise import human
from .governance import PRIMARY_AGENT, Governance

router = APIRouter(prefix="/api/connected")
basic = HTTPBasic(auto_error=False)


class Proposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: UUID
    finding_id: int


def admin(credentials: HTTPBasicCredentials | None = Depends(basic)):
    password = os.getenv("AGENTSEC_APPROVER_PASSWORD", "")
    if (
        not credentials
        or len(password) < 16
        or credentials.username != "administrator"
        or not secrets.compare_digest(credentials.password.encode(), password.encode())
    ):
        raise HTTPException(
            401, "Connected administrator credentials required.", headers={"WWW-Authenticate": "Basic"}
        )
    return "connected-administrator"


def configured():
    repo = os.getenv("AGENTSEC_GITHUB_REPOSITORY", "")
    token = os.getenv("AGENTSEC_GITHUB_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not token:
        raise HTTPException(503, "Configure an allowlisted test repository and fine-grained GitHub token.")
    return repo, token


def initialize(store):
    with store.connection() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS github_requests (
            id TEXT PRIMARY KEY, agent TEXT NOT NULL, repository TEXT NOT NULL,
            title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL, approver TEXT, issue_url TEXT,
            UNIQUE(repository,title)
        )""")


@router.get("/requests")
def requests(request: Request, actor: str = Depends(admin)):
    with request.app.state.store.connection(read_only=True) as db:
        return [dict(r) for r in db.execute("SELECT * FROM github_requests ORDER BY created DESC")]


@router.post("/requests")
def propose(request: Request, body: Proposal):
    human(request)
    repo, _ = configured()
    store = request.app.state.store
    finding = store.finding(body.scan_id, body.finding_id)
    rec = store.recommendation(body.scan_id, body.finding_id)
    if not finding or not rec:
        raise HTTPException(409, "A live scan and validated recommendation are required.")
    title = f"Review {finding.advisory_id} in {finding.package.purl}"[:220]
    content = "\n\n".join(
        [
            finding.url,
            rec.assessment.risk.text,
            *[s.text for s in rec.assessment.steps],
            rec.assessment.uncertainty,
        ]
    )
    with store.connection() as db:
        db.execute(
            "INSERT OR IGNORE INTO github_requests VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()),
                PRIMARY_AGENT,
                repo,
                title,
                content,
                "pending",
                time.time(),
                time.time() + 600,
                None,
                None,
            ),
        )
        row = db.execute(
            "SELECT * FROM github_requests WHERE repository=? AND title=?", (repo, title)
        ).fetchone()
        Governance(store)._event(db, PRIMARY_AGENT, "github.permission.request", repo, "pending", row["id"])
    return dict(row)


@router.post("/requests/{request_id}/approve")
def approve(request: Request, request_id: str, actor: str = Depends(admin)):
    repo, _ = configured()
    with request.app.state.store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM github_requests WHERE id=?", (request_id,)).fetchone()
        if (
            not row
            or row["status"] != "pending"
            or row["expires"] <= time.time()
            or row["repository"] != repo
        ):
            raise HTTPException(409, "Request unavailable, expired or target changed.")
        db.execute(
            "UPDATE github_requests SET status='approved',approver=?,expires=? WHERE id=?",
            (actor, time.time() + 300, request_id),
        )
        Governance(request.app.state.store)._event(
            db, actor, "github.permission.approve", repo, "approved", request_id
        )
    return {"status": "approved"}


@router.post("/requests/{request_id}/revoke")
def revoke(request: Request, request_id: str, actor: str = Depends(admin)):
    with request.app.state.store.connection() as db:
        cursor = db.execute(
            "UPDATE github_requests SET status='revoked' WHERE id=? AND status IN ('pending','approved')",
            (request_id,),
        )
        if cursor.rowcount != 1:
            raise HTTPException(409, "Request cannot be revoked after execution begins.")
        Governance(request.app.state.store)._event(
            db, actor, "github.permission.revoke", request_id, "revoked", "Human decision"
        )
    return {"status": "revoked"}


@router.post("/requests/{request_id}/execute")
def execute(request: Request, request_id: str, actor: str = Depends(admin)):
    repo, token = configured()
    store = request.app.state.store
    denied = None
    with store.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM github_requests WHERE id=?", (request_id,)).fetchone()
        agent = db.execute("SELECT status FROM agents WHERE id=?", (PRIMARY_AGENT,)).fetchone()
        if (
            not row
            or row["agent"] != PRIMARY_AGENT
            or row["repository"] != repo
            or row["status"] != "approved"
            or row["approver"] != actor
            or row["expires"] <= time.time()
            or agent["status"] != "active"
        ):
            denied = "Capability unavailable, expired, consumed or agent inactive"
        else:
            # Claim before sending: concurrent requests and ambiguous network failures cannot retry.
            db.execute("UPDATE github_requests SET status='executing' WHERE id=?", (request_id,))
        Governance(store)._event(
            db,
            PRIMARY_AGENT,
            "github.issue.write",
            repo,
            "denied" if denied else "allowed",
            denied or request_id,
        )
    if denied:
        raise HTTPException(403, denied)
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            response = client.post(
                f"https://api.github.com/repos/{repo}/issues",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                json={"title": row["title"], "body": row["body"]},
            )
        response.raise_for_status()
        number = response.json()["number"]
        if type(number) is not int or number < 1:
            raise ValueError("Invalid issue number")
        issue_url = f"https://github.com/{repo}/issues/{number}"
    except (httpx.HTTPError, ValueError, KeyError):
        with store.connection() as db:
            db.execute("UPDATE github_requests SET status='uncertain' WHERE id=?", (request_id,))
            Governance(store)._event(
                db,
                PRIMARY_AGENT,
                "github.issue.result",
                repo,
                "uncertain",
                "Check repository manually; automatic retry disabled",
            )
        raise HTTPException(
            502, "GitHub result uncertain. Inspect the repository; do not retry automatically."
        ) from None
    with store.connection() as db:
        db.execute(
            "UPDATE github_requests SET status='consumed',issue_url=? WHERE id=?", (issue_url, request_id)
        )
        Governance(store)._event(db, PRIMARY_AGENT, "github.issue.result", repo, "completed", issue_url)
    return {"mode": "connected", "issue_url": issue_url}
