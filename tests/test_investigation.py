import time
from uuid import uuid4

import pytest

from agentsec.investigation.engine import Engine, initialize_actor
from agentsec.investigation.gateway import Decision
from agentsec.investigation.ledger import Ledger, LimitExceeded, digest
from agentsec.main import app


def test_budget_reserves_unknown_charges_and_cache(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db")
    call = ledger.reserve("run", "key", 0.6)
    with pytest.raises(LimitExceeded):
        ledger.reserve("run", "next", 0.5)
    ledger.settle(call, {"decision": {"tool": "finish"}}, 0.01)
    assert ledger.cached("key")["decision"]["tool"] == "finish"
    ledger.reserve("run", "next", 0.5)
    for index in range(2):
        ledger.reserve(str(index), "x", 0.9)
    with pytest.raises(LimitExceeded):
        ledger.reserve("other", "x", 0.8)
    assert ledger.spending()["unsettled_reservation_usd"] == 2.3


def test_invalid_decision_rejected():
    with pytest.raises(ValueError):
        Decision(tool="shell", explanation="run arbitrary code")
    with pytest.raises(ValueError):
        Decision(tool="finish", explanation="done", agent_id="administrator")


def seed(client):
    state = app.state
    initialize_actor(state.store)
    run = {
        "id": str(uuid4()),
        "mode": "live",
        "status": "awaiting_approval",
        "budget": 1,
        "created": time.time(),
        "deadline": time.time() + 60,
        "iteration": 1,
        "candidate": "2.2.2",
        "observations": {"propose_patch": {"diff": "test patch"}},
        "events": [],
    }
    state.investigations.save(run)
    return run


def test_publication_is_scoped_single_use_and_audited(client):
    run = seed(client)
    path = "/api/investigations/" + run["id"]
    assert client.post(path + "/publish").status_code == 403
    assert client.post(path + "/approve").status_code == 200
    assert client.post(path + "/publish").status_code == 200
    assert client.post(path + "/publish").status_code == 403
    assert client.get(path).json()["status"] == "completed"
    assert client.post(path + "/challenge").json()["decision"] == "denied"


def test_changed_artifact_and_expired_grants_deny(client):
    run = seed(client)
    path = "/api/investigations/" + run["id"]
    client.post(path + "/approve")
    run["observations"]["propose_patch"]["diff"] = "changed"
    app.state.investigations.save(run)
    assert client.post(path + "/publish").status_code == 403
    with app.state.investigations.db() as db:
        db.execute("UPDATE publications SET expires=0")
    assert client.post(path + "/publish").status_code == 403
    assert client.post(path + "/approve").status_code == 200


def test_no_implicit_paid_run(client, monkeypatch):
    assert client.post("/api/investigations", json={}).status_code == 422
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert client.post("/api/investigations", json={"consent": True}).status_code == 503
    assert client.post("/api/investigations", json={"budget": 3, "consent": True}).status_code == 422


def test_completion_requires_actual_evidence():
    engine = object.__new__(Engine)
    assert not engine.ready({"observations": {"validate_patch": {"after": {"passed": True}}}})
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})


def test_real_mcp_returns_typed_repository_data(client, tmp_path):
    import asyncio
    import shutil

    from agentsec.investigation.tools import SAMPLE

    run_id = str(uuid4())
    folder = tmp_path / run_id / "before"
    folder.mkdir(parents=True)
    for name in ("requirements.txt", "client.py", "test_client.py"):
        shutil.copyfile(SAMPLE / name, folder / name)
    engine = Engine(app.state.investigations, app.state.store, tmp_path)
    result = asyncio.run(engine.tool({"id": run_id, "candidate": "2.8.0"}, "inspect_repository"))
    assert result["original"] == "1.26.18"
    assert "urllib3==1.26.18" in result["files"]["requirements.txt"]


def test_recording_requires_real_provenance_and_integrity(client, monkeypatch, tmp_path):
    from agentsec.investigation import api

    monkeypatch.setattr(api, "ROOT", tmp_path)
    assert client.get("/api/investigations/recording").status_code == 404
    import json

    (tmp_path / "recordings").mkdir()
    (tmp_path / "recordings/hero.json").write_text(
        json.dumps({"run": {"mode": "fixture"}, "sha256": digest({"mode": "fixture"})})
    )
    assert client.get("/api/investigations/recording").status_code == 409


def test_publication_denied_after_identity_revocation(client):
    from agentsec.governance import Governance
    from agentsec.investigation.engine import ACTOR

    run = seed(client)
    path = "/api/investigations/" + run["id"]
    client.post(path + "/approve")
    Governance(app.state.store).change(ACTOR, status="suspended")
    assert client.post(path + "/publish").status_code == 403


def test_no_sandbox_fails_closed(monkeypatch, tmp_path):
    from agentsec.investigation import tools

    monkeypatch.setattr(tools.platform, "system", lambda: "Unknown")
    monkeypatch.setattr(tools.shutil, "which", lambda _: None)
    with pytest.raises(RuntimeError, match="No supported sandbox"):
        tools.validate_folder(tmp_path)


def test_graph_rejects_premature_finish(client, tmp_path):
    import asyncio

    engine = Engine(app.state.investigations, app.state.store, tmp_path)

    class Model:
        async def decide(self, state):
            return Decision(tool="finish", explanation="Cannot establish evidence"), {"cache_hit": False}

    engine.gateway = Model()
    run = seed(client)
    run.update(candidate="2.8.0", status="investigating", iteration=0, observations={}, decision=None)
    asyncio.run(engine.run(run))
    saved = app.state.investigations.get(run["id"])
    assert saved["status"] == "paused"
    assert saved["events"][-1]["kind"] == "error"


def test_grant_revocation_and_published_bytes_integrity(client):
    run = seed(client)
    path = "/api/investigations/" + run["id"]
    client.post(path + "/approve")
    assert client.post(path + "/revoke").status_code == 200
    assert client.post(path + "/publish").status_code == 403
    assert client.post(path + "/approve").status_code == 200
    assert client.post(path + "/publish").status_code == 200
    assert client.get(path + "/artifact").text == "test patch"
    saved = app.state.investigations.get(run["id"])
    saved["observations"]["propose_patch"]["diff"] = "tampered"
    app.state.investigations.save(saved)
    assert client.get(path + "/artifact").status_code == 409


def test_suspension_challenge_and_role_checks(client):
    run = seed(client)
    path = "/api/investigations/" + run["id"]
    assert client.post(path + "/suspend-agent").status_code == 200
    result = client.post(path + "/challenge")
    assert result.status_code == 200
    assert result.json()["audit"]["action"] == "credential.issue"
    client.post("/api/enterprise/session", json={"role": "analyst"})
    assert client.post(path + "/restore-agent").status_code == 403
    assert client.post(path + "/approve").status_code == 403


def test_patch_tool_changes_isolated_manifest_and_requires_authorization(client, tmp_path):
    import asyncio

    from agentsec.governance import Governance
    from agentsec.investigation.engine import ACTOR
    from agentsec.investigation.tools import ToolRunner

    initialize_actor(app.state.store)
    run_id = str(uuid4())
    for side in ("before", "after"):
        (tmp_path / side).mkdir()
        (tmp_path / side / "requirements.txt").write_text("urllib3==1.26.18\n")
    token = Governance(app.state.store).credential(ACTOR, "scan:" + run_id)
    runner = ToolRunner(app.state.store, token, run_id, tmp_path, "2.8.0")
    with pytest.raises(RuntimeError, match="Generate the isolated patch"):
        asyncio.run(runner.run("validate_patch"))
    output = asyncio.run(runner.run("propose_patch"))
    assert (tmp_path / "before/requirements.txt").read_text() == "urllib3==1.26.18\n"
    assert (tmp_path / "after/requirements.txt").read_text() == "urllib3==2.8.0\n"
    assert "+urllib3==2.8.0" in output["diff"]
    Governance(app.state.store).change(ACTOR, revoke="remediation.patch")
    with pytest.raises(PermissionError):
        asyncio.run(runner.run("propose_patch"))


@pytest.mark.parametrize("failure", ["timeout", "failed_validation"])
def test_incomplete_validation_cannot_publish_and_preserves_recovery(client, tmp_path, failure):
    import asyncio

    engine = Engine(app.state.investigations, app.state.store, tmp_path)
    calls = []

    class Model:
        async def decide(self, state):
            calls.append(state["observations"].copy())
            tool = "validate_patch" if len(calls) == 1 else "finish"
            return Decision(tool=tool, explanation="Verify or report uncertainty"), {}

    async def tool(state, name):
        if failure == "timeout":
            raise TimeoutError("provider body must not leak")
        return {"before": {"passed": False}, "after": {"passed": False}}

    engine.gateway = Model()
    engine.tool = tool
    run = seed(client)
    run.update(status="investigating", iteration=0, observations={}, decision=None)
    asyncio.run(engine.run(run))
    saved = app.state.investigations.get(run["id"])
    assert saved["status"] == "paused"
    assert len(calls) == 2
    assert "last_error" in calls[1] if failure == "timeout" else "validate_patch" in calls[1]
    assert "provider body" not in str(saved)
    assert client.post("/api/investigations/" + run["id"] + "/approve").status_code == 409


def test_deadline_cancels_inflight_decision_and_saves_state(client, tmp_path):
    import asyncio

    engine = Engine(app.state.investigations, app.state.store, tmp_path)
    cancelled = []

    class Model:
        async def decide(self, state):
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.append(True)

    engine.gateway = Model()
    run = seed(client)
    run.update(deadline=time.time() + 0.1, status="investigating", iteration=0, decision=None)
    started = time.monotonic()
    asyncio.run(engine.run(run))
    saved = app.state.investigations.get(run["id"])
    assert cancelled and time.monotonic() - started < 2
    assert saved["status"] == "paused"
    assert "deadline exhausted" in saved["error"]
