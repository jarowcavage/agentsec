import argparse
import os
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from ..storage import Store
from .tools import ToolRunner

parser = argparse.ArgumentParser()
parser.add_argument("--database", required=True)
parser.add_argument("--run", required=True)
parser.add_argument("--workspace", required=True)
parser.add_argument("--candidate", required=True)
args = parser.parse_args()
runner = ToolRunner(
    Store(Path(args.database)),
    os.getenv("AGENTSEC_AGENT_TOKEN", ""),
    args.run,
    args.workspace,
    args.candidate,
)
server = FastMCP("AgentSec constrained investigation")


class ToolOutput(BaseModel):
    data: dict[str, Any]


@server.tool()
async def investigate(
    tool: Literal[
        "inspect_repository", "lookup_advisory", "check_candidate", "propose_patch", "validate_patch"
    ],
) -> ToolOutput:
    """Execute one typed, authorized operation against the launcher-bound curated workspace."""
    return ToolOutput(data=await runner.run(tool))


if __name__ == "__main__":
    server.run(transport="stdio")
