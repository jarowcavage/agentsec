import os

import pytest
from fastapi.testclient import TestClient

from agentsec.main import app

from .conftest import ADVISORY, VULNERABLE
from .test_workflow import recommendation_route, upload

pytestmark = pytest.mark.live


def test_live_osv():
    if os.getenv("AGENTSEC_LIVE_OSV") != "1":
        pytest.skip("Set AGENTSEC_LIVE_OSV=1 to query OSV.")
    with TestClient(app, base_url="http://localhost") as client:
        response = upload(client)
        assert response.status_code == 201, response.text
        assert response.json()["queried_package_count"] == 2
        (finding,) = (
            finding
            for finding in response.json()["findings"]
            if finding["advisory_id"] == ADVISORY and finding["package"]["purl"] == VULNERABLE
        )
        assert "CVE-2021-44228" in finding["aliases"]
        assert "2.15.0" in finding["fixed_candidates"]


def test_live_openai():
    if os.getenv("AGENTSEC_LIVE_OPENAI") != "1" or not os.getenv("OPENAI_API_KEY"):
        pytest.skip("Set AGENTSEC_LIVE_OPENAI=1 and OPENAI_API_KEY to make one OpenAI request.")
    with TestClient(app, base_url="http://localhost") as client:
        response = upload(client)
        assert response.status_code == 201, response.text
        scan = response.json()
        (finding,) = (finding for finding in scan["findings"] if finding["advisory_id"] == ADVISORY)
        result = client.post(recommendation_route(scan, finding["id"]))
        assert result.status_code == 200, result.text
        assert result.json()["assessment"]["steps"]
