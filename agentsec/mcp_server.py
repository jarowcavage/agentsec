import argparse
import os
from pathlib import Path
from typing import Annotated
from uuid import UUID

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from .governance import Governance
from .osv import Finding
from .recommend import Evidence, GuidanceIndex, advisory_evidence, load_guidance
from .storage import Store

FindingId = Annotated[int, Field(strict=True, ge=1, le=250)]


def build_server(store: Store, token: str = "") -> FastMCP:
    server = FastMCP("AgentSec evidence")
    guidance = GuidanceIndex(load_guidance())
    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)

    def finding(scan_id: UUID, finding_id: int, tool: str) -> Finding:
        Governance(store).authorize(token, tool, f"scan:{scan_id}")
        item = store.finding(scan_id, finding_id)
        if item is None:
            raise ValueError("Finding not found.")
        return item

    @server.tool(annotations=read_only)
    def lookup_vulnerability(scan_id: UUID, finding_id: FindingId) -> Evidence:
        """Read the OSV evidence already attached to this finding."""
        return advisory_evidence(finding(scan_id, finding_id, "lookup_vulnerability"))

    @server.tool(annotations=read_only)
    def get_dependency_context(scan_id: UUID, finding_id: FindingId) -> dict[str, list[str]]:
        """Read dependency relationships derived from the uploaded SBOM."""
        return {"relationships": finding(scan_id, finding_id, "get_dependency_context").package.relationships}

    @server.tool(annotations=read_only)
    def retrieve_security_guidance(scan_id: UUID, finding_id: FindingId) -> dict[str, list[Evidence]]:
        """Retrieve local guidance excerpts relevant to this finding."""
        return {"sources": guidance.retrieve(finding(scan_id, finding_id, "retrieve_security_guidance"))}

    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", type=Path, required=True)
    build_server(Store(parser.parse_args().database), os.getenv("AGENTSEC_AGENT_TOKEN", "")).run(
        transport="stdio"
    )
