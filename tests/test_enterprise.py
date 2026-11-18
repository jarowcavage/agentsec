from agentsec.main import app


def login(client, monkeypatch, role="administrator"):
    monkeypatch.setenv("AGENTSEC_DEMO", "1")
    assert client.post("/api/enterprise/session", json={"role": role}).status_code == 200


def test_human_role_separation_and_attack(client, monkeypatch):
    client.cookies.clear()
    assert client.get("/api/enterprise/overview").status_code == 401
    login(client, monkeypatch, "analyst")
    assert client.post("/api/enterprise/agents", json={"name": "test"}).status_code == 403
    result = client.post("/api/enterprise/attack").json()
    assert result["decision"] == "denied"
    assert result["audit"]["outcome"] == "denied"
    assert (
        client.post(
            "/api/enterprise/session",
            json={"role": "administrator"},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    monkeypatch.setenv("AGENTSEC_DEMO", "0")
    assert client.post("/api/enterprise/session", json={"role": "administrator"}).status_code == 403


def test_offline_approval_single_use_and_revocation(client, monkeypatch, upstreams):
    login(client, monkeypatch, "analyst")
    scenario = client.post("/api/enterprise/scenario")
    assert scenario.status_code == 200, scenario.text
    scan_id = scenario.json()["scan"]["id"]
    assert not upstreams.model_requests and not upstreams.osv_requests
    request_id = client.post(f"/api/enterprise/requests/from-finding/{scan_id}/1").json()["id"]
    route = f"/api/enterprise/requests/{request_id}"
    assert client.post(route + "/execute").status_code == 403
    assert client.post(route + "/decision", json={"decision": "approved"}).status_code == 403
    login(client, monkeypatch)
    assert client.post(route + "/decision", json={"decision": "approved"}).status_code == 200
    assert client.post(route + "/execute").status_code == 200
    assert client.post(route + "/execute").status_code == 403
    assert client.post(route + "/decision", json={"decision": "approved"}).status_code == 409
    overview = client.get("/api/enterprise/overview").json()
    assert len(overview["issues"]) == 1
    assert overview["approvals"][0]["status"] == "consumed"
    assert (
        client.post("/api/enterprise/agents/agentsec-remediation", json={"status": "suspended"}).status_code
        == 200
    )
    assert client.post("/api/enterprise/scenario").status_code == 409


def test_expired_or_manipulated_capability_cannot_execute(client, monkeypatch):
    login(client, monkeypatch)
    scan_id = client.post("/api/enterprise/scenario").json()["scan"]["id"]
    request_id = client.post(f"/api/enterprise/requests/from-finding/{scan_id}/1").json()["id"]
    route = f"/api/enterprise/requests/{request_id}"
    assert (
        client.post(route + "/decision", json={"decision": "approved", "resource": "prod"}).status_code == 422
    )
    assert client.post(route + "/decision", json={"decision": "approved"}).status_code == 200
    with app.state.demo.store.connection() as db:
        db.execute("UPDATE capabilities SET expires=0 WHERE id=?", (request_id,))
    assert client.post(route + "/execute").status_code == 403
    assert client.get("/api/enterprise/overview").json()["approvals"][0]["status"] == "expired"


def test_revoked_grant_and_reset_isolation(client, monkeypatch):
    from .test_workflow import upload

    live = upload(client).json()
    login(client, monkeypatch)
    scan = client.post("/api/enterprise/scenario").json()["scan"]
    request_id = client.post(f"/api/enterprise/requests/from-finding/{scan['id']}/1").json()["id"]
    path = f"/api/enterprise/requests/{request_id}"
    assert client.post(path + "/decision", json={"decision": "approved"}).status_code == 200
    assert client.post(path + "/decision", json={"decision": "revoked"}).status_code == 200
    assert client.post(path + "/execute").status_code == 403
    assert (
        client.post("/api/enterprise/attack", json={"agent_id": "administrator"}).json()["decision"]
        == "denied"
    )
    assert client.post("/api/enterprise/reset").status_code == 200
    assert not client.get("/api/enterprise/overview").json()["approvals"]
    assert client.get(f"/api/scans/{live['id']}").status_code == 200


def test_legacy_approval_also_requires_human_admin(client, monkeypatch):
    from .test_workflow import recommendation_route, upload

    scan = upload(client).json()
    client.post(recommendation_route(scan))
    route = f"/api/scans/{scan['id']}/findings/1/issue-review"
    review = client.post(route).json()
    client.cookies.clear()
    assert (
        client.post(route + "/" + review["id"] + "/decision", json={"decision": "approved"}).status_code
        == 401
    )
    login(client, monkeypatch, "analyst")
    assert (
        client.post(route + "/" + review["id"] + "/decision", json={"decision": "approved"}).status_code
        == 403
    )
