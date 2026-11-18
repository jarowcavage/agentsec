"""Explicit synthetic providers for the offline interview scenario."""

import json
from pathlib import Path
from uuid import uuid4

import httpx

from .osv import OSVClient
from .recommend import CitedStatement, ModelRecommendation, Recommendation
from .workflow import ScanRuntime, TriageRuntime, build_scan_graph, build_triage_graph


class FixtureModel:
    async def generate(self, relationships, evidence):
        advisory = next(item for item in evidence if item.id == "osv")
        guidance = next(item for item in evidence if item.kind == "guidance")
        return Recommendation(
            model="synthetic-fixture (no AI request)",
            evidence=evidence,
            assessment=ModelRecommendation(
                risk=CitedStatement(
                    text="Synthetic advisory reports a vulnerable dependency. Runtime reachability is unknown.",
                    source_id=advisory.id,
                    quote=advisory.excerpt[:100],
                ),
                steps=[
                    CitedStatement(
                        text="Review the applicable supported upgrade, test compatibility and regenerate the SBOM.",
                        source_id=guidance.id,
                        quote=guidance.excerpt[:100],
                    )
                ],
                uncertainty="Fixture data only. Reachability, exposure, KEV and EPSS are not verified.",
            ),
        )


def provider(request):
    if request.url.path == "/v1/querybatch":
        queries = json.loads(request.content)["queries"]
        return httpx.Response(
            200,
            json={
                "results": [
                    {"vulns": [{"id": "DEMO-2026-001"}]} if "log4j-core" in q["package"]["purl"] else {}
                    for q in queries
                ]
            },
        )
    return httpx.Response(
        200,
        json={
            "id": "DEMO-2026-001",
            "summary": "Synthetic remote code execution advisory",
            "details": "Synthetic enterprise demo: a vulnerable logging dependency requires investigation. No runtime reachability is established.",
            "affected": [
                {
                    "package": {"purl": "pkg:maven/org.apache.logging.log4j/log4j-core"},
                    "ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "2.17.1"}]}],
                }
            ],
        },
    )


async def run(state):
    scan_id = uuid4()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(provider), base_url="https://api.osv.dev"
    ) as client:
        result = await build_scan_graph().ainvoke(
            {
                "scan_id": scan_id,
                "data": (Path(__file__).parent.parent / "samples/workbench-demo.cdx.json").read_bytes(),
            },
            context=ScanRuntime(OSVClient(client), state.store),
        )
    scan = result["scan"]
    recommendation = await build_triage_graph().ainvoke(
        {"scan_id": scan_id, "finding": scan.findings[0]},
        context=TriageRuntime(state.mcp, FixtureModel(), state.store),
    )
    return {
        "mode": "synthetic-fixture",
        "scan": scan.model_dump(mode="json"),
        "recommendation": recommendation["recommendation"].model_dump(mode="json"),
        "reachability": "unknown",
        "priority": "Investigate: synthetic code-execution advisory; exposure unverified",
    }
