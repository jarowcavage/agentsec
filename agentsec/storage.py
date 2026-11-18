import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel

from .osv import Finding
from .recommend import Recommendation
from .sbom import Skipped
from .telemetry import Trace, Usage


class Scan(BaseModel):
    id: UUID
    component_count: int
    queried_package_count: int
    skipped: list[Skipped]
    findings: list[Finding]


class IssueReview(BaseModel):
    id: UUID
    title: str
    body: str
    status: Literal["pending", "approved", "rejected"]
    integration: Literal["local_mock"] = "local_mock"
    issue_number: int | None = None


class ReviewConflict(RuntimeError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY, payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recommendations (
    scan_id TEXT NOT NULL REFERENCES scans(id), finding_id INTEGER NOT NULL,
    payload TEXT NOT NULL, PRIMARY KEY (scan_id, finding_id)
);
CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, finding_id INTEGER NOT NULL,
    title TEXT NOT NULL, body TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
    UNIQUE (scan_id, finding_id),
    FOREIGN KEY (scan_id, finding_id) REFERENCES recommendations(scan_id, finding_id)
);
CREATE TABLE IF NOT EXISTS mock_issues (
    issue_number INTEGER PRIMARY KEY, review_id TEXT NOT NULL UNIQUE REFERENCES reviews(id),
    title TEXT NOT NULL, body TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS model_usage (
    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS model_usage_by_scan ON model_usage(scan_id);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL, finding_id INTEGER,
    operation TEXT NOT NULL, outcome TEXT NOT NULL, duration_ms REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS audit_by_scan ON audit(scan_id);
"""


class Store:
    def __init__(self, path: Path):
        self.path = path.resolve()

    def initialize(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.touch(mode=0o600, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(SCHEMA)
        from .governance import Governance

        Governance(self).initialize()

    @contextmanager
    def connection(self, *, read_only: bool = False):
        path = self.path.as_uri() + "?mode=ro" if read_only else str(self.path)
        db = sqlite3.connect(path, uri=read_only, timeout=3)
        db.row_factory = sqlite3.Row
        try:
            with db:
                db.execute("PRAGMA foreign_keys=ON")
                yield db
        finally:
            db.close()

    def save_scan(self, scan: Scan):
        with self.connection() as db:
            db.execute("INSERT INTO scans VALUES (?, ?)", (str(scan.id), scan.model_dump_json()))

    def scan(self, scan_id: UUID) -> Scan | None:
        with self.connection(read_only=True) as db:
            row = db.execute("SELECT payload FROM scans WHERE id=?", (str(scan_id),)).fetchone()
        return Scan.model_validate_json(row["payload"]) if row else None

    def finding(self, scan_id: UUID, finding_id: int) -> Finding | None:
        scan = self.scan(scan_id)
        if scan and 1 <= finding_id <= len(scan.findings):
            return scan.findings[finding_id - 1]
        return None

    def recommendation(self, scan_id: UUID, finding_id: int) -> Recommendation | None:
        with self.connection(read_only=True) as db:
            row = db.execute(
                "SELECT payload FROM recommendations WHERE scan_id=? AND finding_id=?",
                (str(scan_id), finding_id),
            ).fetchone()
        return Recommendation.model_validate_json(row["payload"]) if row else None

    def save_recommendation(self, scan_id: UUID, finding_id: int, recommendation: Recommendation):
        with self.connection() as db:
            db.execute(
                "INSERT INTO recommendations VALUES (?, ?, ?)",
                (str(scan_id), finding_id, recommendation.model_dump_json()),
            )

    def audit(
        self, scan_id: UUID, finding_id: int | None, operation: str, outcome: str, duration_ms: float = 0
    ):
        with self.connection() as db:
            db.execute(
                "INSERT INTO audit(scan_id,finding_id,operation,outcome,duration_ms) VALUES (?,?,?,?,?)",
                (str(scan_id), finding_id, operation, outcome, duration_ms),
            )

    def save_usage(self, scan_id: UUID, usage: Usage):
        with self.connection() as db:
            db.execute(
                "INSERT INTO model_usage(scan_id,payload) VALUES (?,?)",
                (str(scan_id), usage.model_dump_json()),
            )

    def trace(self, scan_id: UUID) -> Trace:
        with self.connection(read_only=True) as db:
            events = db.execute(
                """SELECT finding_id,operation,outcome,duration_ms FROM audit
                   WHERE scan_id=? ORDER BY id DESC LIMIT 200""",
                (str(scan_id),),
            ).fetchall()
            usage = db.execute(
                "SELECT payload FROM model_usage WHERE scan_id=? ORDER BY id DESC LIMIT 200",
                (str(scan_id),),
            ).fetchall()
        return Trace(
            events=[dict(row) for row in reversed(events)],
            model_usage=[Usage.model_validate_json(row["payload"]) for row in reversed(usage)],
        )

    def review(self, scan_id: UUID, finding_id: int) -> IssueReview | None:
        with self.connection(read_only=True) as db:
            return self._review(db, scan_id, finding_id)

    def _review(self, db: sqlite3.Connection, scan_id: UUID, finding_id: int) -> IssueReview | None:
        row = db.execute(
            """SELECT reviews.id, reviews.title, reviews.body, status, issue_number
               FROM reviews LEFT JOIN mock_issues ON mock_issues.review_id=reviews.id
               WHERE scan_id=? AND finding_id=?""",
            (str(scan_id), finding_id),
        ).fetchone()
        return IssueReview.model_validate(dict(row)) if row else None

    def propose(self, scan_id: UUID, finding_id: int, title: str, body: str) -> IssueReview:
        with self.connection() as db:
            db.execute(
                """INSERT INTO reviews(id,scan_id,finding_id,title,body) VALUES (?,?,?,?,?)
                   ON CONFLICT(scan_id,finding_id) DO NOTHING""",
                (str(uuid4()), str(scan_id), finding_id, title, body),
            )
            return self._review(db, scan_id, finding_id)

    def decide(
        self, scan_id: UUID, finding_id: int, review_id: UUID, decision: Literal["approved", "rejected"]
    ) -> IssueReview | None:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            review = self._review(db, scan_id, finding_id)
            if review is None or review.id != review_id:
                return None
            if review.status == decision:
                return review
            if review.status != "pending":
                raise ReviewConflict("This review already has a final decision.")
            db.execute("UPDATE reviews SET status=? WHERE id=?", (decision, str(review_id)))
            if decision == "approved":
                db.execute(
                    "INSERT INTO mock_issues(review_id,title,body) VALUES (?,?,?)",
                    (str(review_id), review.title, review.body),
                )
            db.execute(
                "INSERT INTO audit(scan_id,finding_id,operation,outcome) VALUES (?,?,?,?)",
                (str(scan_id), finding_id, "human_review", decision),
            )
            return self._review(db, scan_id, finding_id)
