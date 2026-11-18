import httpx

from .test_workflow import recommendation_route, upload


def setup(client, monkeypatch):
    monkeypatch.setenv("AGENTSEC_GITHUB_REPOSITORY", "example/security-sandbox")
    monkeypatch.setenv("AGENTSEC_GITHUB_TOKEN", "test-token-not-real")
    monkeypatch.setenv("AGENTSEC_APPROVER_PASSWORD", "test-password-not-real-123")
    scan = upload(client).json()
    assert client.post(recommendation_route(scan)).status_code == 200
    response = client.post("/api/connected/requests", json={"scan_id": scan["id"], "finding_id": 1})
    assert response.status_code == 200
    return "/api/connected/requests/" + response.json()["id"]


AUTH = ("administrator", "test-password-not-real-123")


def test_connected_requires_independent_approval_and_consumes(client, monkeypatch):
    path = setup(client, monkeypatch)
    assert client.post(path + "/approve").status_code == 401
    assert client.post(path + "/execute", auth=AUTH).status_code == 403
    assert client.post(path + "/approve", auth=AUTH).status_code == 200
    calls = []

    def post(self, url, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(201, json={"number": 17}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.Client, "post", post)
    # TestClient uses the patched class too: invoke its request method instead.
    result = client.request("POST", path + "/execute", auth=AUTH)
    assert result.status_code == 200, result.text
    assert result.json()["issue_url"].endswith("/issues/17")
    assert client.request("POST", path + "/execute", auth=AUTH).status_code == 403
    assert len(calls) == 1
    assert calls[0][0] == "https://api.github.com/repos/example/security-sandbox/issues"


def test_target_change_revocation_and_ambiguous_write(client, monkeypatch):
    path = setup(client, monkeypatch)
    assert client.post(path + "/approve", auth=AUTH).status_code == 200
    monkeypatch.setenv("AGENTSEC_GITHUB_REPOSITORY", "example/production")
    assert client.post(path + "/execute", auth=AUTH).status_code == 403
    monkeypatch.setenv("AGENTSEC_GITHUB_REPOSITORY", "example/security-sandbox")

    def timeout(self, *args, **kwargs):
        raise httpx.ReadTimeout("sensitive provider error")

    monkeypatch.setattr(httpx.Client, "post", timeout)
    response = client.request("POST", path + "/execute", auth=AUTH)
    assert response.status_code == 502
    assert "sensitive" not in response.text
    assert client.request("POST", path + "/execute", auth=AUTH).status_code == 403
