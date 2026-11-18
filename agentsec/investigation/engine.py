import asyncio
import sys
import time
from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..governance import TOOL_ACTIONS, Governance
from .gateway import Gateway
from .tools import ROOT, TOOLS, prepare

ACTOR = "agentsec-investigator"
TOOL_ACTIONS.update(TOOLS)


def initialize_actor(store):
    with store.connection() as db:
        if not db.execute("SELECT id FROM agents WHERE id=?", (ACTOR,)).fetchone():
            db.execute(
                """INSERT INTO agents SELECT ?,?,?,?,?,?,?,?, ?,NULL,NULL,0 FROM agents WHERE id='agentsec-remediation' """,
                (
                    ACTOR,
                    "AgentSec investigator",
                    "Curated repository investigation",
                    "Validated dependency remediation",
                    "Local operator",
                    "AppSec",
                    "local",
                    "active",
                    time.time(),
                ),
            )
            for action in set(TOOLS.values()):
                db.execute("INSERT INTO agent_permissions VALUES (?,?,?)", (ACTOR, action, "scan:*"))
            Governance(store)._event(
                db,
                "system",
                "agent.initialize",
                ACTOR,
                "allowed",
                "Bounded curated repository tools; no publication permission",
            )


class State(TypedDict, total=False):
    id: str
    mode: str
    status: str
    budget: float
    created: float
    deadline: float
    iteration: int
    candidate: str
    observations: dict
    events: list
    decision: dict | None
    error: str | None


class Engine:
    def __init__(self, ledger, store, workroot):
        self.ledger, self.store, self.workroot = ledger, store, workroot
        self.gateway = Gateway(ledger)
        initialize_actor(store)

    def event(self, state, kind, **fields):
        state["events"].append(
            {"sequence": len(state["events"]) + 1, "timestamp": time.time(), "kind": kind, **fields}
        )
        self.ledger.save(state)

    async def tool(self, state, tool):
        token = Governance(self.store).credential(ACTOR, "scan:" + state["id"], lifetime=120)
        params = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "agentsec.investigation.mcp_server",
                "--database",
                str(self.store.path),
                "--run",
                state["id"],
                "--workspace",
                str(self.workroot / state["id"]),
                "--candidate",
                state["candidate"],
            ],
            cwd=ROOT,
            env={"PYTHONNOUSERSITE": "1", "AGENTSEC_AGENT_TOKEN": token},
        )
        async with (
            asyncio.timeout(55),
            stdio_client(params) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            result = await session.call_tool("investigate", {"tool": tool})
            if result.isError or result.structuredContent is None:
                raise RuntimeError("Tool failed; no successful result recorded")
            return result.structuredContent["data"]

    def ready(self, state):
        obs = state["observations"]
        check = obs.get("check_candidate", {})
        validation = obs.get("validate_patch", {})
        return (
            all(t in obs for t in TOOLS)
            and check.get("target_found_before") is True
            and check.get("target_found_after") is False
            and validation.get("before", {}).get("passed") is False
            and validation.get("after", {}).get("passed") is True
        )

    async def run(self, state):
        try:
            async with asyncio.timeout(max(0, state["deadline"] - time.time())):
                await self._run(state)
        except TimeoutError:
            state = self.ledger.get(state["id"]) or state
            state["status"] = "paused"
            state["error"] = "Investigation deadline exhausted; no successful result claimed."
            self.event(state, "error", summary=state["error"])

    async def _run(self, state):
        try:
            if not state.get("candidate"):
                state["status"] = "preparing"
                self.event(
                    state,
                    "preparation",
                    summary="Fetching verified package artifacts from PyPI; no repository commands executed",
                )
                state["candidate"] = await prepare(self.workroot / state["id"])
                self.ledger.save(state)

            async def reason(s):
                if time.time() >= s["deadline"] or s["iteration"] >= 10:
                    raise RuntimeError("Investigation time or iteration limit exhausted")
                s["status"] = "investigating"
                decision, usage = await self.gateway.decide(s)
                s["iteration"] += 1
                s["decision"] = decision.model_dump()
                self.event(s, "decision", tool=decision.tool, summary=decision.explanation, usage=usage)
                if decision.tool == "finish":
                    if not self.ready(s):
                        s["observations"]["completion_requirement"] = (
                            "Finish denied: inspect, advisory, OSV before/after, patch and passing after/failed before tests are required."
                        )
                        s["decision"] = None
                        s["status"] = "paused"
                        s["error"] = (
                            "Agent stopped without sufficient verification; no successful result claimed."
                        )
                        self.event(s, "error", summary=s["error"])
                    else:
                        s["status"] = "awaiting_approval"
                        s["decision"] = None
                        self.event(
                            s,
                            "result",
                            summary=decision.explanation,
                            limitations="Package-level and curated regression verification only; runtime exposure unknown",
                        )
                return s

            async def execute(s):
                tool = s["decision"]["tool"]
                if tool in s["observations"]:
                    raise RuntimeError("Agent repeated a completed tool; stopped to avoid a loop")
                started = time.monotonic()
                self.event(
                    s, "tool_start", tool=tool, summary="Executing authorized MCP tool", input={"tool": tool}
                )
                try:
                    result = await self.tool(s, tool)
                    s["observations"][tool] = result
                    self.event(
                        s,
                        "tool_result",
                        tool=tool,
                        output=result,
                        duration_seconds=round(time.monotonic() - started, 3),
                        outcome="passed",
                    )
                except Exception:
                    s["observations"]["last_error"] = {
                        "tool": tool,
                        "message": "Tool unavailable or authorization denied. Reconsider or stop; no success implied.",
                    }
                    self.event(
                        s,
                        "tool_result",
                        tool=tool,
                        outcome="failed",
                        duration_seconds=round(time.monotonic() - started, 3),
                    )
                s["decision"] = None
                self.ledger.save(s)
                return s

            graph = StateGraph(State)
            graph.add_node("reason", reason)
            graph.add_node("tool", execute)
            graph.add_conditional_edges(
                START,
                lambda s: "tool" if s.get("decision") and s["decision"]["tool"] != "finish" else "reason",
            )
            graph.add_conditional_edges(
                "reason",
                lambda s: (
                    END
                    if s["status"] in ("awaiting_approval", "paused")
                    else ("tool" if s.get("decision") else "reason")
                ),
            )
            graph.add_edge("tool", "reason")
            await graph.compile().ainvoke(state, config={"recursion_limit": 32})
        except Exception as error:
            # Do not include provider exception bodies or tokens in public traces.
            state = self.ledger.get(state["id"]) or state
            state["status"] = "paused"
            state["error"] = (
                str(error)
                if isinstance(error, RuntimeError)
                else "Provider or tool failed; inspect recorded events and resume safely."
            )
            self.event(state, "error", summary=state["error"])
