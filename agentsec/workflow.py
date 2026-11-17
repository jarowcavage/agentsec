from dataclasses import dataclass
from time import perf_counter
from typing import Literal, TypedDict
from uuid import UUID

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from .mcp_client import MCPEvidence, RetrievedContext
from .osv import Finding, OSVClient
from .recommend import Recommendation, Recommender, validate_evidence
from .sbom import Inventory, parse_sbom
from .storage import IssueReview, Scan, Store


class ScanState(TypedDict, total=False):
    scan_id: UUID
    data: bytes
    inventory: Inventory
    scan: Scan


@dataclass
class ScanRuntime:
    osv: OSVClient
    store: Store


class TriageState(TypedDict, total=False):
    scan_id: UUID
    finding: Finding
    context: RetrievedContext
    recommendation: Recommendation


@dataclass
class TriageRuntime:
    mcp: MCPEvidence
    model: Recommender
    store: Store


class ReviewState(TypedDict, total=False):
    scan_id: UUID
    finding_id: int
    review_id: UUID
    decision: Literal["approved", "rejected"]
    review: IssueReview | None


def audit(node):
    async def run(state, runtime):
        started = perf_counter()
        outcome = "error"
        try:
            result = await node(state, runtime)
            outcome = "ok"
            return result
        finally:
            finding = state.get("finding")
            runtime.context.store.audit(
                state["scan_id"],
                finding.id if finding else None,
                node.__name__,
                outcome,
                (perf_counter() - started) * 1000,
            )

    return run


def build_scan_graph():
    async def validate_upload(state: ScanState, runtime: Runtime[ScanRuntime]):
        return {"inventory": parse_sbom(state["data"]), "data": b""}

    async def enrich(state: ScanState, runtime: Runtime[ScanRuntime]):
        inventory = state["inventory"]

        def observe(outcome, duration):
            runtime.context.store.audit(state["scan_id"], None, "osv_attempt", outcome, duration)

        findings = await runtime.context.osv.enrich(inventory.packages, observe=observe)
        return {
            "scan": Scan(
                id=state["scan_id"],
                component_count=inventory.component_count,
                queried_package_count=len(inventory.packages),
                skipped=inventory.skipped,
                findings=findings,
            )
        }

    async def save_scan(state: ScanState, runtime: Runtime[ScanRuntime]):
        runtime.context.store.save_scan(state["scan"])
        return {}

    graph = StateGraph(ScanState, context_schema=ScanRuntime)
    graph.add_node("validate_upload", audit(validate_upload))
    graph.add_node("enrich_osv", audit(enrich))
    graph.add_node("save_scan", audit(save_scan))
    graph.add_edge(START, "validate_upload")
    graph.add_edge("validate_upload", "enrich_osv")
    graph.add_edge("enrich_osv", "save_scan")
    graph.add_edge("save_scan", END)
    return graph.compile()


def build_triage_graph():
    async def retrieve_context(state: TriageState, runtime: Runtime[TriageRuntime]):
        return {"context": await runtime.context.mcp.collect(state["scan_id"], state["finding"])}

    async def analyze(state: TriageState, runtime: Runtime[TriageRuntime]):
        context = state["context"]
        recommendation = await runtime.context.model.generate(context.relationships, context.evidence)
        if recommendation.usage:
            runtime.context.store.save_usage(state["scan_id"], recommendation.usage)
        return {"recommendation": recommendation}

    async def validate_response(state: TriageState, runtime: Runtime[TriageRuntime]):
        recommendation = state["recommendation"]
        validate_evidence(recommendation.assessment, recommendation.evidence)
        return {}

    async def finalize(state: TriageState, runtime: Runtime[TriageRuntime]):
        runtime.context.store.save_recommendation(
            state["scan_id"], state["finding"].id, state["recommendation"]
        )
        return {}

    graph = StateGraph(TriageState, context_schema=TriageRuntime)
    for node in (retrieve_context, analyze, validate_response, finalize):
        graph.add_node(node.__name__, audit(node))
    graph.add_edge(START, "retrieve_context")
    graph.add_edge("retrieve_context", "analyze")
    graph.add_edge("analyze", "validate_response")
    graph.add_edge("validate_response", "finalize")
    graph.add_edge("finalize", END)
    return graph.compile()


def build_review_graph():
    async def human_approval(state: ReviewState, runtime: Runtime[Store]):
        # The pending proposal in SQLite is the durable boundary between requests.
        review = runtime.context.decide(
            state["scan_id"],
            state["finding_id"],
            state["review_id"],
            state["decision"],
        )
        return {"review": review}

    graph = StateGraph(ReviewState, context_schema=Store)
    graph.add_node("human_approval", human_approval)
    graph.add_edge(START, "human_approval")
    graph.add_edge("human_approval", END)
    return graph.compile()
