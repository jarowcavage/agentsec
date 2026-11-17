import asyncio
import json

import httpx
import pytest

from agentsec.osv import OSVClient, OSVError
from agentsec.sbom import parse_sbom

from .conftest import ADVISORY, SAMPLE, VULNERABLE

PACKAGES = parse_sbom(SAMPLE.read_bytes()).packages


def enrich(handler):
    async def scan():
        async with httpx.AsyncClient(
            base_url="https://api.osv.dev", transport=httpx.MockTransport(handler)
        ) as client:
            return await OSVClient(client).enrich(PACKAGES)

    return asyncio.run(scan())


def test_retry_and_paginate_only_the_affected_query():
    batch_calls = []

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"id": ADVISORY})
        batch_calls.append(json.loads(request.content)["queries"])
        if len(batch_calls) == 1:
            return httpx.Response(503)
        if len(batch_calls) == 2:
            return httpx.Response(200, json={"results": [{"next_page_token": "continue"}, {}]})
        assert batch_calls[-1] == [{"package": {"purl": VULNERABLE}, "page_token": "continue"}]
        return httpx.Response(200, json={"results": [{"vulns": [{"id": ADVISORY}]}]})

    (finding,) = enrich(handler)
    assert batch_calls[0] == batch_calls[1]
    assert finding.advisory_id == ADVISORY
    assert finding.fixed_candidates == []
    assert finding.severity == []


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"results": [{}]}, "result count"),
        ({"results": ["invalid", {}]}, "unexpected format"),
        ({"results": [{"vulns": [{"id": "../malicious"}]}, {}]}, "invalid advisory ID"),
    ],
)
def test_osv_invalid_responses_are_scan_errors(body, message):
    def handler(request):
        assert request.method == "POST"
        return httpx.Response(200, json=body)

    with pytest.raises(OSVError, match=message):
        enrich(handler)


def test_withdrawn_advisory_is_filtered():
    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": ADVISORY}]}, {}]})
        return httpx.Response(200, json={"id": ADVISORY, "withdrawn": "2025-10-01T00:00:00Z"})

    assert enrich(handler) == []
