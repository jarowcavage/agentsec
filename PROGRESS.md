# AgentSec Workbench progress

## Completed milestones

| Milestone | Shipped | Verification |
| --- | --- | --- |
| Phase 1 | CycloneDX upload, live OSV enrichment, local guidance, structured OpenAI recommendations | `e866bf7` implements the slice. `167c853` records the successful live OpenAI check after the API credit issue cleared. |
| Phase 2 | LangGraph, three read-only MCP tools, durable SQLite state, mock issue approval | `c9ea1c5`. All 31 tests passed with desktop and mobile Chrome, live OSV, and live OpenAI enabled. |
| Phase 3 | Local TF-IDF vector retrieval, execution trace, token and cost reporting, failure handling, deterministic evaluation | `e42d246`. The suite passed 58 tests with desktop and mobile Chrome and live OSV. One additional live smoke verified OpenAI through MCP, four citations, 1,315 input and 305 output tokens, and a $0.000284 estimated API cost. All 28 deterministic evaluation cases passed. |
| Phase 4 local deliverables | Dockerfile, Compose, GitHub Actions, HTTP smoke check, deployment runbook, architecture, threat model, demo walkthrough, interview notes, and résumé bullets | Compose syntax and `actionlint` passed. The HTTP smoke passed against native Uvicorn across a real restart. Hosted CI and Docker restart/persistence verified in run 44173605698. |

## Current status — 2026-11-18

The previous Phase 4 is verified and the enterprise expansion is implemented in tested milestones. Hosting remains local by user choice. Public source: https://github.com/jarowcavage/agentsec. Local milestone commits preserve implementation history; the public branch contains corresponding published snapshots.

### Implemented

- P0: persistent agent registry, short-lived opaque process credentials, exact scan scopes, default-deny MCP authorization, immediate revocation/status checks and timestamped persistent policy audit. Commit `5be5236`.
- P1/local P2: administrator/analyst backend sessions, immutable scoped approval requests, expiration, atomic single-use local issue creation, replay denial, deterministic malicious tool-proposal demonstration and isolated demo reset. Responsive console preserves the original live SBOM workflow. Commit `a35ce57`.
- Optional connected mode: allowlisted GitHub adapter, independent administrator password, exact reviewed payload, expiring claim, duplicate prevention and uncertain-outcome handling. Fixture-tested only; no real issue was created. Connected requests are outside the resettable demo DB.
- P3 subset: ownership/access certification, explicit governance risk flags, process credential metadata, measured demo operation summaries, generated test results and assumptions-only ROI calculator.
- P4 materials: architecture, business case, setup/reset/test runbook, 20-minute demo and identity/AppSec/supply-chain narratives. Commit `33bbfe5`.

### Verification

- Native regression: **69 passed, 2 opt-in live tests excluded**, including four desktop/mobile browser tests. No new paid OpenAI calls.
- Generated security evaluation: **10/10** deterministic cases, including GitHub HTTP fixtures. This small suite is not a production security guarantee.
- Ruff, formatting and both JavaScript syntax checks passed.
- Expansion application CI passed in run 44267317926. Its Docker build exposed a missing build-context allowlist entry for the generated evaluation report. Fixed in local `9a07a10` / public `9c68b15`.
- **Final Linux CI is green:** [run 44268059453](https://github.com/jarowcavage/agentsec/actions/runs/44268059453), public code commit `57aaa00`. Fresh dependency setup, lint, unit/API/MCP tests, 28 AppSec evaluations, desktop/mobile browser flows and Docker build/startup/restart persistence all passed.
- Final audit edge-case fix (`0679f86` local): denied credential issuance for suspended agents is persisted before raising, so the attack UI shows the current denial. All 10 focused security tests passed again; final CI includes this fix.
- Native local server returned healthy with recommendations configured. The console's offline scenario was visually verified. Open http://127.0.0.1:8000/console while Uvicorn is running. Server execution approval is now available; the earlier usage-limit interruption is resolved.

### Remaining work ranked by demo/business impact

1. Optional real GitHub acceptance test in an explicitly configured disposable repository. Requires a fine-grained Issues-write token and a separate strong approver password. No live integration success is claimed.
2. Broader synthetic sample with multiple priorities; verified KEV/EPSS enrichment and deterministic multi-finding prioritization. Current offline sample has one synthetic advisory; reachability/exposure remain unknown.
3. Production human identity federation, per-user attribution, multi-tenancy, session administration, versioned migrations, audit integrity/retention and external-write reconciliation. Demo role switching intentionally lets a local operator select roles.
4. Larger labeled evaluation corpus and actual human-effort measurements. Recorded stage time is not analyst triage time; ROI values are assumptions.

### Exact resume steps

1. Inspect `git status --short --branch` and this file; do not repeat finished implementation.
2. If needed, launch from repository root with `AGENTSEC_DEMO=1 uvicorn agentsec.main:app --host 127.0.0.1 --port 8000`. Use the configured virtual environment. See `docs/DEMO_RUNBOOK.md` for install/test/reset commands.
3. Follow `docs/DEMO_SCRIPT.md`: Analyst investigation → exact action request → Administrator approval → one-time execution → attack denial → audit → suspension → reset. The default path needs no external credentials.
4. Prioritize the ranked remaining work only as requested. Keep hosting local. Do not perform external writes without explicit approval and configured credentials.

### Known environment constraints

Docker Desktop's local socket belongs to another macOS account and is inaccessible; container verification ran successfully in GitHub Actions. Native Python is the local demo path. No paid infrastructure or public application was deployed.
