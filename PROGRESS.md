# AgentSec Workbench progress

## Completed milestones

| Milestone | Shipped | Verification |
| --- | --- | --- |
| Phase 1 | CycloneDX upload, live OSV enrichment, local guidance, structured OpenAI recommendations | `e866bf7` implements the slice. `167c853` records the successful live OpenAI check after the API credit issue cleared. |
| Phase 2 | LangGraph, three read-only MCP tools, durable SQLite state, mock issue approval | `c9ea1c5`. All 31 tests passed with desktop and mobile Chrome, live OSV, and live OpenAI enabled. |
| Phase 3 | Local TF-IDF vector retrieval, execution trace, token and cost reporting, failure handling, deterministic evaluation | `e42d246`. The suite passed 58 tests with desktop and mobile Chrome and live OSV. One additional live smoke verified OpenAI through MCP, four citations, 1,315 input and 305 output tokens, and a $0.000284 estimated API cost. All 28 deterministic evaluation cases passed. |
| Phase 4 local deliverables | Dockerfile, Compose, GitHub Actions, HTTP smoke check, deployment runbook, architecture, threat model, demo walkthrough, interview notes, and résumé bullets | Compose syntax and `actionlint` passed. The HTTP smoke passed against native Uvicorn across a real restart. Hosted CI and Docker restart/persistence verified in run 44173605698. |

The local Workbench is available at [127.0.0.1:8000](http://127.0.0.1:8000/) when Uvicorn is running. The latest native startup returned healthy with recommendations configured. Use the [README](README.md) to restart it.

## Verification and current scope

- Phase 4 verification completed: [CI run 44173605698](https://github.com/jarowcavage/agentsec/actions/runs/44173605698) passed both test and container jobs at public commit `82e9dbd`. Docker startup, health, sample and restart persistence passed. The preceding run exposed a Linux mobile overflow; the committed grid sizing fix passed the rerun.
- Local regression: 57 offline tests passed, including desktop/mobile browsers; lint, formatting and dependency checks passed.
- Public repository: https://github.com/jarowcavage/agentsec (publication explicitly authorized). Local history retains earlier milestones in addition to published snapshot commits.
- Hosted app deployment deferred at user request. Local Docker remains unavailable due to another user's socket permissions.
- Local server restart was blocked by automatic approval review exhausting its usage allowance, not by a safety determination. The last health check found no listener; do not assume the demo is running.

## Exact next steps

1. Implement the enterprise expansion attachment in tested milestones; see docs/IMPLEMENTATION_PLAN.md.
2. Maintain the working AppSec regression suite and record new verification here.
3. Start and verify the local demo once execution approval is available. Do not provision hosting.

## Enterprise expansion P0

Persistent agent registry, server-issued short-lived scoped MCP credentials, tool-boundary default-deny enforcement, immediate permission/status revocation, and timestamped authorization audit implemented. Baseline plus new policy tests: 58 passed (browser/live excluded). New agents have no permissions. Initialization does not restore revoked permissions. P1 approval/UI work in progress.

## Enterprise P1 and local P2 milestone

Implemented isolated demo database, server-side analyst/admin sessions (explicit AGENTSEC_DEMO=1), ten-minute immutable action requests, administrator decisions, atomic single-use local issue execution, immediate identity suspension, deterministic hostile tool proposal and persistent audit. Legacy mock approval now also requires an administrator session. Added responsive console with investigation, identities, approvals, attack demonstration, audit, reset, narrative selector and assumption-based ROI calculator. Offline providers run through existing LangGraph/MCP/citation validation. Reset preserves live scans.

Verification: 67 tests passed with desktop/mobile browser flows enabled; 2 opt-in live tests excluded. No OpenAI calls or external writes. Mobile navigation overflow found and fixed by the browser regression. Local P2 is functional; connected GitHub issue creation is not implemented. Production identity federation, stronger session administration and advanced intelligence remain out of scope for this milestone.

## Enterprise integration and interview readiness

2026-11-18: Added optional allowlisted GitHub issue adapter with independent administrator authentication, exact stored approval, five-minute approved grant, pre-network claim, duplicate-request prevention and terminal uncertain outcomes. HTTP-fixture tests passed; no real GitHub issue was created. Connected requests live outside the resettable demo DB.

Added measured demo scan/finding/recommendation counts, recorded workflow-stage timing and approval waiting time. Added generated security evaluation report (10/10 cases), visible test details, process-credential metadata, access certification and transparent risk indicators. Added all requested SE demo/narrative/business/runbook documents and updated architecture. Local console at http://127.0.0.1:8000/console was started and the offline scenario visually verified.

Final native regression: **69 passed, 2 opt-in live tests excluded**, including four desktop/mobile browser tests. Ruff, formatting and JavaScript syntax checks passed. No new paid AI calls or real external writes. Latest expansion still needs Linux CI/container rerun after publication.

### Remaining work ranked by impact

1. Run the published expansion through Linux CI/container checks; record result. Preserve local-only hosting choice.
2. Optional live GitHub acceptance requires an explicitly configured disposable repository, fine-grained token and separate administrator password. Adapter behavior is fixture-tested; real write is unverified.
3. Broaden the synthetic sample to multiple priority levels, add verified KEV/EPSS data and deterministic multi-finding prioritization. Current sample contains one synthetic advisory; runtime reachability remains unknown.
4. Improve production human identity/session lifecycle, individual audit attribution, multi-tenancy, versioned migrations, audit integrity/retention and external-write reconciliation. Local role switching is intentionally demo-only.
5. Broaden labeled security/quality datasets and measure actual human triage effort. ROI values are assumptions; workflow stage times are not human effort.

### Exact resume steps

Read this file, inspect `git status --short --branch`, and inspect the latest Actions run. Do not repeat completed implementation or spend model calls to recheck fixture behavior. Use `AGENTSEC_DEMO=1 uvicorn agentsec.main:app --host 127.0.0.1 --port 8000` for the console and `docs/DEMO_RUNBOOK.md` for the complete setup/test/reset workflow. Do not run connected writes without configured credentials and the application's explicit human approval.

Expansion CI run 44267317926 found a Docker packaging failure: the existing deny-all build context excluded `evals/`. Added only the generated security report to `.dockerignore`'s allowlist. Container rerun pending; application unit/integration/evaluation checks passed before the packaging fix.
