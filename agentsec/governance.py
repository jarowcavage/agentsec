"""Persistent, provider-independent policy enforcement for local agent processes.

Opaque credentials authenticate a process, never a tool argument. The database and
launcher are trusted: this is not a sandbox against an attacker with local DB access.
"""

import hashlib
import json
import secrets
import time
from uuid import uuid4

from .storage import Store

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL,
 purpose TEXT NOT NULL, owner TEXT NOT NULL, team TEXT NOT NULL,
 environment TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
 created REAL NOT NULL, last_activity REAL, last_review REAL,
 synthetic INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_credentials (
 digest TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
 expires REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
 scope TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_permissions (
 agent_id TEXT NOT NULL REFERENCES agents(id), action TEXT NOT NULL,
 resource TEXT NOT NULL, PRIMARY KEY(agent_id,action,resource)
);
CREATE TABLE IF NOT EXISTS governance_events (
 id INTEGER PRIMARY KEY, timestamp REAL NOT NULL, principal TEXT NOT NULL,
 action TEXT NOT NULL, resource TEXT NOT NULL, outcome TEXT NOT NULL,
 reason TEXT NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0
);
"""
TOOL_ACTIONS = {
    "lookup_vulnerability": "vulnerability.read",
    "get_dependency_context": "sbom.read",
    "retrieve_security_guidance": "remediation.analyze",
}
PRIMARY_AGENT = "agentsec-remediation"


class AuthorizationDenied(PermissionError):
    pass


class Governance:
    def __init__(self, store: Store):
        self.store = store

    def initialize(self):
        with self.store.connection() as db:
            db.executescript(SCHEMA)
            db.execute(
                "INSERT OR IGNORE INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    PRIMARY_AGENT,
                    "AgentSec remediation",
                    "Local evidence retrieval agent",
                    "Investigate dependencies and draft evidence-backed remediation",
                    "Local operator",
                    "Application Security",
                    "local",
                    "active",
                    time.time(),
                    None,
                    None,
                    0,
                ),
            )
            # Only bootstrap once: initialization must never restore revoked permissions.
            if db.execute("SELECT COUNT(*) FROM governance_events").fetchone()[0] == 0:
                for action in TOOL_ACTIONS.values():
                    db.execute(
                        "INSERT OR IGNORE INTO agent_permissions VALUES (?,?,?)",
                        (PRIMARY_AGENT, action, "scan:*"),
                    )
                self._event(db, "system", "registry.initialize", PRIMARY_AGENT, "allowed", "Bootstrap")

    def _event(self, db, principal, action, resource, outcome, reason):
        db.execute(
            """INSERT INTO governance_events
            (timestamp,principal,action,resource,outcome,reason) VALUES (?,?,?,?,?,?)""",
            (time.time(), principal, action, resource, outcome, reason),
        )

    def register(self, name, owner="", team="Security", synthetic=False):
        agent_id = str(uuid4())
        with self.store.connection() as db:
            db.execute(
                "INSERT INTO agents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    agent_id,
                    name,
                    "Registered local agent",
                    "Security investigation",
                    owner,
                    team,
                    "demo" if synthetic else "local",
                    "active",
                    time.time(),
                    None,
                    None,
                    int(synthetic),
                ),
            )
            self._event(db, "human", "agent.register", agent_id, "allowed", "No default permissions")
        return agent_id

    def credential(self, agent_id, resource, lifetime=60):
        """Trusted launcher API; not exposed as an agent tool or public HTTP route."""
        token = secrets.token_urlsafe(32)
        with self.store.connection() as db:
            agent = db.execute("SELECT status FROM agents WHERE id=?", (agent_id,)).fetchone()
            if not agent or agent["status"] != "active":
                raise AuthorizationDenied("Agent unavailable.")
            db.execute(
                "INSERT INTO agent_credentials VALUES (?,?,?,?,?)",
                (
                    hashlib.sha256(token.encode()).hexdigest(),
                    agent_id,
                    time.time() + min(lifetime, 300),
                    0,
                    resource,
                ),
            )
        return token

    def authorize(self, token, tool, resource):
        action = TOOL_ACTIONS.get(tool)
        digest = hashlib.sha256(token.encode()).hexdigest()
        reason = "Unknown tool"
        principal = "unauthenticated"
        allowed = False
        with self.store.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT c.*,a.status FROM agent_credentials c
                JOIN agents a ON a.id=c.agent_id WHERE digest=?""",
                (digest,),
            ).fetchone()
            if row:
                principal = row["agent_id"]
            if not row or row["revoked"] or row["expires"] <= time.time():
                reason = "Credential invalid or expired"
            elif row["status"] != "active":
                reason = "Agent inactive"
            elif row["scope"] != resource:
                reason = "Resource outside session scope"
            elif action:
                permissions = db.execute(
                    """SELECT resource FROM agent_permissions
                    WHERE agent_id=? AND action=?""",
                    (principal, action),
                ).fetchall()
                allowed = any(
                    p["resource"] == resource or (p["resource"] == "scan:*" and resource.startswith("scan:"))
                    for p in permissions
                )
                reason = "Permission matched" if allowed else "Permission missing"
            self._event(db, principal, action or tool, resource, "allowed" if allowed else "denied", reason)
            if allowed:
                db.execute("UPDATE agents SET last_activity=? WHERE id=?", (time.time(), principal))
        # Raise outside the transaction so denials survive rollback.
        if not allowed:
            raise AuthorizationDenied("Tool access denied: " + reason + ".")
        return principal

    def change(self, agent_id, *, status=None, owner=None, revoke=None, certify=False):
        with self.store.connection() as db:
            if status is not None:
                if status not in ("active", "suspended", "revoked"):
                    raise ValueError("Invalid status")
                old = db.execute("SELECT status FROM agents WHERE id=?", (agent_id,)).fetchone()
                if not old or old["status"] == "revoked":
                    raise ValueError("Agent unavailable or permanently revoked")
                db.execute("UPDATE agents SET status=? WHERE id=?", (status, agent_id))
            if owner is not None:
                db.execute("UPDATE agents SET owner=? WHERE id=?", (owner, agent_id))
            if revoke:
                db.execute("DELETE FROM agent_permissions WHERE agent_id=? AND action=?", (agent_id, revoke))
            if certify:
                db.execute("UPDATE agents SET last_review=? WHERE id=?", (time.time(), agent_id))
            self._event(
                db,
                "human",
                "agent.change",
                agent_id,
                "allowed",
                json.dumps({"status": status, "owner": owner, "revoke": revoke, "certify": certify}),
            )

    def inventory(self):
        with self.store.connection(read_only=True) as db:
            agents = [dict(row) for row in db.execute("SELECT * FROM agents ORDER BY created")]
            for agent in agents:
                agent["permissions"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT action,resource FROM agent_permissions WHERE agent_id=?", (agent["id"],)
                    )
                ]
                agent["tools"] = [
                    tool
                    for tool, action in TOOL_ACTIONS.items()
                    if action in {p["action"] for p in agent["permissions"]}
                ]
                agent["risks"] = []
                if not agent["owner"]:
                    agent["risks"].append("Missing human owner")
                if not agent["last_review"]:
                    agent["risks"].append("Access not certified")
                if not agent["last_activity"]:
                    agent["risks"].append("No observed activity")
                elif agent["last_activity"] < time.time() - 30 * 86400:
                    agent["risks"].append("No activity in 30 days")
                if any(p["action"].endswith((".write", ".manage")) for p in agent["permissions"]):
                    agent["risks"].append("Sensitive standing permission: review necessity")
                agent["credentials"] = [
                    dict(row)
                    for row in db.execute(
                        "SELECT expires,revoked,scope FROM agent_credentials WHERE agent_id=?", (agent["id"],)
                    )
                ]
        return agents

    def events(self):
        with self.store.connection(read_only=True) as db:
            return [
                dict(row) for row in db.execute("SELECT * FROM governance_events ORDER BY id DESC LIMIT 200")
            ]
