import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict

from .enterprise import human
from .enterprise import initialize as initialize_enterprise
from .enterprise import router as enterprise_router
from .github_integration import initialize as initialize_github
from .github_integration import router as github_router
from .investigation.api import initialize as initialize_investigations
from .investigation.api import router as investigation_router
from .mcp_client import MCPEvidence
from .osv import OSVClient, OSVError
from .recommend import Recommendation, RecommendationError, Recommender, load_guidance
from .sbom import MAX_UPLOAD, InvalidSBOM
from .storage import IssueReview, ReviewConflict, Scan, Store
from .telemetry import Trace
from .workflow import ScanRuntime, TriageRuntime, build_review_graph, build_scan_graph, build_triage_graph

ROOT = Path(__file__).parent.parent
SCAN_GRAPH = build_scan_graph()
TRIAGE_GRAPH = build_triage_graph()
REVIEW_GRAPH = build_review_graph()


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = Store(Path(os.getenv("AGENTSEC_DATABASE", ROOT / ".agentsec/workbench.db")))
    store.initialize()
    app.state.store = store
    initialize_enterprise(app.state)
    initialize_github(store)
    initialize_investigations(app.state)
    app.state.mcp = MCPEvidence(store, load_guidance())
    app.state.pending = set()
    app.state.recommender = None
    async with httpx.AsyncClient(base_url="https://api.osv.dev", timeout=8) as osv:
        app.state.osv = OSVClient(osv)
        key = os.getenv("OPENAI_API_KEY", "").strip()
        if key:
            async with AsyncOpenAI(api_key=key, timeout=40, max_retries=0) as client:
                model = os.getenv("OPENAI_MODEL", "").strip() or "gpt-6-luna"
                app.state.recommender = Recommender(client, model)
                yield
        else:
            yield


app = FastAPI(title="AgentSec Workbench", version="0.1.0", lifespan=lifespan)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.include_router(enterprise_router)
app.include_router(github_router)
app.include_router(investigation_router)
app.mount("/static", StaticFiles(directory=ROOT / "agentsec/static"), name="static")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": "Cross-origin mutation denied."}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    if not request.url.path.startswith(("/docs", "/redoc")):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )
    return response


@app.get("/", include_in_schema=False)
async def home():
    return FileResponse(ROOT / "agentsec/static/workspace.html")


@app.get("/legacy", include_in_schema=False)
async def legacy():
    return FileResponse(ROOT / "agentsec/static/index.html")


@app.get("/console", include_in_schema=False)
async def console():
    return FileResponse(ROOT / "agentsec/static/console.html")


@app.get("/sample", include_in_schema=False)
async def sample():
    return FileResponse(ROOT / "samples/workbench-demo.cdx.json", media_type="application/json")


@app.get("/health")
async def health(request: Request):
    return {"status": "ok", "recommendations_configured": request.app.state.recommender is not None}


@app.post(
    "/api/scans",
    response_model=Scan,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {"type": "object", "description": "CycloneDX 1.4–1.7 JSON SBOM, up to 2 MiB."}
                }
            },
        }
    },
)
async def scan_upload(request: Request):
    if request.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
        raise HTTPException(415, "Upload CycloneDX JSON with Content-Type: application/json.")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_UPLOAD:
            raise HTTPException(413, "The maximum SBOM size is 2 MiB.")
        data.extend(chunk)
    state = request.app.state
    try:
        result = await SCAN_GRAPH.ainvoke(
            {"scan_id": uuid4(), "data": bytes(data)}, context=ScanRuntime(state.osv, state.store)
        )
        return result["scan"]
    except InvalidSBOM as error:
        raise HTTPException(422, str(error)) from error
    except OSVError as error:
        raise HTTPException(502, str(error)) from error


@app.get("/api/scans/{scan_id}", response_model=Scan)
async def get_scan(request: Request, scan_id: UUID):
    scan = request.app.state.store.scan(scan_id)
    if scan is None:
        raise HTTPException(404, "This scan is unavailable. Run the scan again.")
    return scan


@app.post("/api/scans/{scan_id}/findings/{finding_id}/recommendation", response_model=Recommendation)
async def recommend(request: Request, scan_id: UUID, finding_id: int):
    state = request.app.state
    finding = state.store.finding(scan_id, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found in this scan.")
    saved = state.store.recommendation(scan_id, finding_id)
    if saved:
        return saved
    key = (scan_id, finding_id)
    if key in state.pending:
        raise HTTPException(409, "A recommendation for this finding is already in progress.")
    if state.recommender is None:
        raise HTTPException(503, "Set OPENAI_API_KEY and restart the server to generate recommendations.")
    state.pending.add(key)
    try:
        result = await TRIAGE_GRAPH.ainvoke(
            {"scan_id": scan_id, "finding": finding},
            context=TriageRuntime(state.mcp, state.recommender, state.store),
        )
        return result["recommendation"]
    except RecommendationError as error:
        raise HTTPException(502, str(error)) from error
    finally:
        state.pending.remove(key)


REVIEW_PATH = "/api/scans/{scan_id}/findings/{finding_id}/issue-review"


@app.get(REVIEW_PATH, response_model=IssueReview | None)
async def get_issue_review(request: Request, scan_id: UUID, finding_id: int):
    return request.app.state.store.review(scan_id, finding_id)


@app.post(REVIEW_PATH, response_model=IssueReview)
async def propose_issue(request: Request, scan_id: UUID, finding_id: int):
    store = request.app.state.store
    finding = store.finding(scan_id, finding_id)
    recommendation = store.recommendation(scan_id, finding_id)
    if finding is None or recommendation is None:
        raise HTTPException(404, "Generate a recommendation for this finding first.")
    assessment = recommendation.assessment
    title = f"Review {finding.advisory_id} in {finding.package.purl}"[:220]
    body = "\n".join(
        [
            finding.url,
            "",
            assessment.risk.text,
            "",
            *[f"- {step.text}" for step in assessment.steps],
            "",
            assessment.uncertainty,
        ]
    )
    return store.propose(scan_id, finding_id, title, body)


@app.post(REVIEW_PATH + "/{review_id}/decision", response_model=IssueReview)
async def decide_issue(request: Request, scan_id: UUID, finding_id: int, review_id: UUID, body: Decision):
    human(request, admin=True)
    try:
        result = await REVIEW_GRAPH.ainvoke(
            {"scan_id": scan_id, "finding_id": finding_id, "review_id": review_id, "decision": body.decision},
            context=request.app.state.store,
        )
    except ReviewConflict as error:
        raise HTTPException(409, str(error)) from error
    if result["review"] is None:
        raise HTTPException(404, "Issue review not found for this finding.")
    return result["review"]


@app.get("/api/scans/{scan_id}/findings/{finding_id}/recommendation", response_model=Recommendation | None)
async def get_recommendation(request: Request, scan_id: UUID, finding_id: int):
    return request.app.state.store.recommendation(scan_id, finding_id)


@app.get("/api/scans/{scan_id}/trace", response_model=Trace)
async def get_trace(request: Request, scan_id: UUID):
    store = request.app.state.store
    if store.scan(scan_id) is None:
        raise HTTPException(404, "Scan not found.")
    return store.trace(scan_id)
