import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class LimitExceeded(RuntimeError):
    pass


class Ledger:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS calls(id TEXT PRIMARY KEY,run_id TEXT NOT NULL,
                cache_key TEXT NOT NULL,reserved REAL NOT NULL,actual REAL,
                response TEXT,created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS publications(run_id TEXT PRIMARY KEY,digest TEXT NOT NULL,
                status TEXT NOT NULL,expires REAL NOT NULL,approver TEXT);
            """)

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def save(self, state):
        with self.db() as db:
            db.execute(
                "INSERT INTO runs VALUES (?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
                (state["id"], json.dumps(state)),
            )

    def get(self, run_id):
        with self.db() as db:
            row = db.execute("SELECT payload FROM runs WHERE id=?", (run_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def history(self):
        with self.db() as db:
            return [
                json.loads(row["payload"])
                for row in db.execute("SELECT payload FROM runs ORDER BY rowid DESC LIMIT 50")
            ]

    def reserve(self, run_id, cache_key, maximum, budget=1.0, campaign=3.0, calls=10):
        if not 0 < budget <= 1 or not 0 < campaign <= 3 or maximum <= 0:
            raise LimitExceeded("Invalid spending limits")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            used = db.execute("SELECT COALESCE(SUM(COALESCE(actual,reserved)),0) FROM calls").fetchone()[0]
            run_used, count = db.execute(
                "SELECT COALESCE(SUM(COALESCE(actual,reserved)),0),COUNT(*) FROM calls WHERE run_id=?",
                (run_id,),
            ).fetchone()
            if used + maximum > campaign or run_used + maximum > budget or count >= calls:
                raise LimitExceeded("Budget or model-call limit exhausted; no request sent")
            call_id = str(uuid4())
            db.execute(
                "INSERT INTO calls VALUES (?,?,?,?,?,?,?)",
                (call_id, run_id, cache_key, maximum, None, None, time.time()),
            )
        return call_id

    def cached(self, key):
        with self.db() as db:
            row = db.execute(
                "SELECT response FROM calls WHERE cache_key=? AND response IS NOT NULL ORDER BY created DESC LIMIT 1",
                (key,),
            ).fetchone()
        return json.loads(row["response"]) if row else None

    def settle(self, call_id, response, actual):
        with self.db() as db:
            row = db.execute("SELECT reserved FROM calls WHERE id=?", (call_id,)).fetchone()
            if actual is not None and (actual < 0 or actual > row["reserved"]):
                raise LimitExceeded(
                    "Reported usage exceeded conservative reservation; stop and review pricing"
                )
            db.execute(
                "UPDATE calls SET actual=?,response=? WHERE id=?", (actual, json.dumps(response), call_id)
            )

    def spending(self, run_id=None):
        with self.db() as db:
            rows = db.execute(
                "SELECT reserved,actual FROM calls" + (" WHERE run_id=?" if run_id else ""),
                (run_id,) if run_id else (),
            ).fetchall()
        return {
            "calls": len(rows),
            "estimated_usd": round(sum(r["actual"] or 0 for r in rows), 9),
            "unsettled_reservation_usd": round(sum(r["reserved"] for r in rows if r["actual"] is None), 9),
        }


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
