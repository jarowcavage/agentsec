import json

import pytest

from agentsec.main import app
from agentsec.sbom import MAX_UPLOAD

from .conftest import ADVISORY, SAMPLE, VULNERABLE


def upload(client, payload=None):
    return client.post(
        "/api/scans",
        content=SAMPLE.read_bytes() if payload is None else payload,
        headers={"Content-Type": "application/json"},
    )


def recommendation_route(scan, finding=1):
    return f"/api/scans/{scan['id']}/findings/{finding}/recommendation"


def test_end_to_end_and_cache(client, upstreams):
    assert client.get("/health").json()["recommendations_configured"]
    assert client.get("/sample").content == SAMPLE.read_bytes()
    result = upload(client)
    assert result.status_code == 201
    assert result.headers["Cache-Control"] == "no-store"
    scan = result.json()
    assert scan["queried_package_count"] == 2
    (finding,) = scan["findings"]
    assert finding["advisory_id"] == ADVISORY
    assert finding["package"]["purl"] == VULNERABLE
    assert finding["fixed_candidates"] == ["2.15.0"]
    first_query = json.loads(upstreams.osv_requests[0].content)
    assert len(first_query["queries"]) == 2
    assert "synthetic-demo" not in str(first_query)
    assert not upstreams.model_requests
    result = client.post(recommendation_route(scan))
    assert result.status_code == 200, result.text
    data = result.json()
    assert data["assessment"]["risk"]["source_id"] == "osv"
    assert "injection-exposure" in {source["id"] for source in data["evidence"]}
    (request,) = upstreams.model_requests
    assert request["text"]["format"]["strict"]
    assert request["store"] is False
    assert request["reasoning"] == {"effort": "none"}
    assert "tools" not in request
    assert "synthetic-demo" not in request["input"]
    assert client.post(recommendation_route(scan)).json() == data
    assert len(upstreams.model_requests) == 1


def test_no_matches(client, upstreams):
    bom = json.loads(SAMPLE.read_bytes())
    bom["components"] = bom["components"][1:]
    result = upload(client, json.dumps(bom))
    assert result.json()["queried_package_count"] == 1
    assert result.json()["findings"] == []
    assert len(upstreams.osv_requests) == 1


@pytest.mark.parametrize("mode", ["invalid_quote", "refusal", "unavailable"])
def test_model_failures_can_be_retried(client, upstreams, mode):
    scan = upload(client).json()
    upstreams.mode = mode
    error = client.post(recommendation_route(scan))
    assert error.status_code == 502
    assert "private error payload" not in error.text
    upstreams.mode = "valid"
    assert client.post(recommendation_route(scan)).status_code == 200


def test_unconfigured_model_and_missing_scan(client, upstreams):
    from uuid import uuid4

    scan = upload(client).json()
    app.state.recommender = None
    assert client.post(recommendation_route(scan)).status_code == 503
    assert client.post(recommendation_route(scan, 2)).status_code == 404
    assert client.post(recommendation_route({"id": str(uuid4())})).status_code == 404
    assert not upstreams.model_requests


def test_upload_rejections(client, upstreams):
    assert client.post("/api/scans", content="other").status_code == 415
    assert upload(client, "{").status_code == 422
    assert upload(client, b" " * (MAX_UPLOAD + 1)).status_code == 413
    assert not upstreams.osv_requests
