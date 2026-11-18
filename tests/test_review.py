from uuid import uuid4

from fastapi.testclient import TestClient

from agentsec.main import app

from .test_workflow import recommendation_route, upload


def issue_route(scan):
    return f"/api/scans/{scan['id']}/findings/1/issue-review"


def test_pending_review_survives_an_app_restart_and_creates_once(upstreams):
    with TestClient(app, base_url="http://localhost") as client:
        client.post("/api/enterprise/session", json={"role": "administrator"})
        scan = upload(client).json()
        path = issue_route(scan)
        assert client.post(path).status_code == 404
        assert client.post(recommendation_route(scan)).status_code == 200
        draft = client.post(path).json()
        assert draft["status"] == "pending"
        assert draft["integration"] == "local_mock"
        assert draft["issue_number"] is None
        with app.state.store.connection(read_only=True) as db:
            assert db.execute("SELECT COUNT(*) FROM mock_issues").fetchone()[0] == 0
            tools = db.execute(
                "SELECT operation,outcome FROM audit WHERE operation LIKE 'lookup_%'"
            ).fetchall()
            assert [tuple(row) for row in tools] == [("lookup_vulnerability", "ok")]

    with TestClient(app, base_url="http://localhost") as client:
        client.post("/api/enterprise/session", json={"role": "administrator"})
        assert client.get(f"/api/scans/{scan['id']}").json() == scan
        assert client.get(path).json() == draft
        route = f"{path}/{draft['id']}/decision"
        decision = {"decision": "approved"}
        accepted = client.post(route, json=decision)
        assert accepted.status_code == 200
        assert accepted.json()["issue_number"] == 1
        assert client.post(route, json=decision).json() == accepted.json()
        assert client.post(route, json={"decision": "rejected"}).status_code == 409
        assert client.post(recommendation_route(scan)).status_code == 200
        assert len(upstreams.model_requests) == 1
        with app.state.store.connection(read_only=True) as db:
            assert db.execute("SELECT COUNT(*) FROM mock_issues").fetchone()[0] == 1


def test_cross_scan_and_forged_decisions_cannot_create_an_issue(client):
    scan = upload(client).json()
    assert client.post(recommendation_route(scan)).status_code == 200
    path = issue_route(scan)
    draft = client.post(path).json()
    assert client.post(f"{path}/{uuid4()}/decision", json={"decision": "approved"}).status_code == 404
    assert (
        client.post(
            f"{issue_route({'id': str(uuid4())})}/{draft['id']}/decision", json={"decision": "approved"}
        ).status_code
        == 404
    )
    route = f"{path}/{draft['id']}/decision"
    assert client.post(route, json={"decision": "approved", "title": "Arbitrary issue"}).status_code == 422
    assert client.post(route, json={"decision": "rejected"}).json()["status"] == "rejected"
    assert client.post(route, json={"decision": "approved"}).status_code == 409
    with app.state.store.connection(read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM mock_issues").fetchone()[0] == 0
