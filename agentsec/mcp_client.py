import asyncio
import sys
from pathlib import Path
from time import perf_counter
from uuid import UUID

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import BaseModel, Field

from .osv import Finding
from .recommend import Evidence, Guidance, RecommendationError, advisory_evidence
from .storage import Store

TOOLS = ("lookup_vulnerability", "get_dependency_context", "retrieve_security_guidance")


class RetrievedContext(BaseModel):
    relationships: list[str]
    evidence: list[Evidence]


class GuidanceResult(BaseModel):
    sources: list[Evidence] = Field(min_length=1, max_length=3)


class MCPEvidence:
    def __init__(self, store: Store, corpus: list[Guidance]):
        self.store = store
        self.allowed_guidance = {
            item.id: Evidence(id=item.id, title=item.title, kind="guidance", excerpt=item.excerpt)
            for item in corpus
        }
        self.parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "agentsec.mcp_server", "--database", str(store.path)],
            cwd=Path(__file__).resolve().parent.parent,
            env={"PYTHONNOUSERSITE": "1"},
        )

    async def collect(self, scan_id: UUID, finding: Finding) -> RetrievedContext:
        arguments = {"scan_id": str(scan_id), "finding_id": finding.id}
        try:
            async with (
                asyncio.timeout(12),
                stdio_client(self.parameters) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                payloads = []
                for tool in TOOLS:
                    started = perf_counter()
                    outcome = "error"
                    try:
                        reply = await session.call_tool(tool, arguments)
                        if reply.isError or reply.structuredContent is None:
                            raise ValueError("Invalid MCP tool response.")
                        payloads.append(reply.structuredContent)
                        outcome = "ok"
                    finally:
                        self.store.audit(
                            scan_id, finding.id, tool, outcome, (perf_counter() - started) * 1000
                        )

            advisory = Evidence.model_validate(payloads[0])
            relationships = payloads[1]["relationships"]
            guidance = GuidanceResult.model_validate(payloads[2]).sources
            if advisory != advisory_evidence(finding) or relationships != finding.package.relationships:
                raise ValueError("MCP evidence does not match the saved finding.")
            if len({source.id for source in guidance}) != len(guidance) or any(
                source != self.allowed_guidance.get(source.id) for source in guidance
            ):
                raise ValueError("MCP returned an unknown or modified guidance excerpt.")
            return RetrievedContext(relationships=relationships, evidence=[advisory, *guidance])
        except Exception as error:
            self.store.audit(scan_id, finding.id, "mcp_context", "error")
            raise RecommendationError("Could not verify evidence from the local MCP server.") from error
