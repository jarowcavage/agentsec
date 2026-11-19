# AgentSec Workbench progress

## Latest checkpoint — real repositories, November 18, 2026

This section supersedes historical status and next-step notes below. The home page is now the plain-English real repository workflow; the recorded model-selected AI workflow is at `/example`.

- Running locally at http://127.0.0.1:8000/ using native Uvicorn, not local Docker. GitHub Actions verifies Docker on Linux. No hosted application was deployed.
- GitHub connected for jarowcavage/agentsec and jarowcavage/juice-shop. Credentials remain only in ignored local `.env`; never display or commit them. User manually generated the token and requested no expiration; token expiry was not independently verified.
- Real scans accepted for both repositories. Actual [Juice Shop draft PR #15](https://github.com/jarowcavage/juice-shop/pull/15) changes sanitize-html 1.4.2 to 2.18.2. Verified draft/open/unmerged. API acceptance proved unapproved writes, scan-only approval and repeated publication are denied. No claim of a separate human clicking approval. AgentSec scan/proposal accepted, no AgentSec PR created against its deliberately vulnerable fixture.
- Native tests: 106 passed, two optional legacy live tests excluded. First full Linux CI 44439987248 passed 70 unit/API/MCP tests, 28 evaluation cases and eight browser cases. Docker build/startup/persistence and actual Linux sample validation passed (expected original regression failure; three patched checks passed). Final code [CI 44440499848](https://github.com/jarowcavage/agentsec/actions/runs/44440499848) also passed all 106 tests and both jobs.
- Latest public implementation: `9a397cf82db30872d41224abca6eaceded2e05a7`. Full acceptance facts: `evals/repository-acceptance.json`. Primary demo: `docs/REPOSITORY_WORKFLOW.md`.
- Repository scanning/proposals use zero AI calls; the separate AI example remains available. Campaign ledger at verification: 12 calls, $0.0019937 estimated, no outstanding reservations, below the $3 ceiling. No new model calls for this repository acceptance.

Limits and blockers: dependency analysis only, not source-code/secrets scanning. Exact Python pins and npm lockfile v2/v3 scanning; automatic npm edits require exact package.json pins without a lockfile. Ranges/other formats are explicitly incomplete. Generic app compatibility tests are not run. Reviewer switching is local demo identity, not enterprise SSO. Direct desktop UI inspection preceded final small refinements; further visual inspection was blocked by automatic approval-review usage quota, while automated desktop/mobile tests passed. Linux validation is now accepted; a separate Docker containment probe is not claimed.

Exact resume steps:
1. Implementation and acceptance are complete. Check Git status and this checkpoint before continuing; do not repeat completed work.
2. Open the local home page. Choose the completed Juice Shop scan in recent checks and show its existing draft PR; avoid duplicate PRs. For another repository, enter its public GitHub URL and inspect coverage before proposing a change.
3. For publishing another reviewed change, use the separate approval password in local `.env`; never share it in chat. Do not merge PRs. Juice Shop fixes may affect its deliberately vulnerable training lessons.
4. Keep hosting local and preserve history/cost ledger. Future work is broader resolved dependency formats, compatibility execution for arbitrary repositories, and production identity. Do not recreate the successful AI recording or rerun paid calls unnecessarily.

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

## AgentSec 2.0 — active scope

The 2.0 specification supersedes the previous expansion priorities. Milestone 1 audit/baseline checkpoint: 69 tests passed with live tests excluded. Fixed missing dashboard initialization and restored the server-authenticated persona on reload; all 4 browser tests passed after the repair. No paid API calls. See docs/AGENTSEC_2_IMPLEMENTATION.md for the audited gaps, sourced urllib3 hero scenario and implementation sequence.

Historical checkpoint superseded by the implementation and acceptance status below.

## AgentSec 2.0 implementation — current checkpoint

User authorized the remaining implementation and up to $3 total new OpenAI usage. Implemented the bounded agent, constrained MCP tools, durable state and cost ledger, real sandbox validation, patch publication, unified presentation workspace and authentic replay. The captured real scenario upgrades urllib3 1.26.18 to 2.8.0, verifies the targeted advisory no longer matches, observes the original regression failure and three passing patched checks, exercises policy denial and releases the reviewed local patch.

Three live attempts: two development failures, one successful capture. Eleven paid calls total; $0.0016695 estimated across all attempts, no outstanding reservations. Successful capture: six calls, $0.0012082 estimated. No more paid calls are needed. Replay is in recordings/hero.json; all attempt outcomes are in recordings/capture-evaluation.json. No GitHub issue or public deployment was created.

Verification: 84 tests passed, including six desktop/mobile browser flows; two opt-in legacy live tests excluded. Thirteen focused investigation/policy tests passed. Direct visual review was blocked by automatic approval review hitting its usage quota. This is distinct from the successful browser tests. Do not bypass that browser restriction with another automation mechanism.

Exact next steps: finish source/recording checks, commit the verified milestone, publish the authorized source changes, inspect Linux CI/container results, and update this file. Direct screenshot review remains outstanding until approval review is available. Native local server was started on 127.0.0.1:8000 with replay as the default. Use docs/AGENTSEC_2_RUNBOOK.md and the 5-/15-minute scripts.

Follow-up hardening: the patch tool now writes the replacement manifest only when invoked, and validation refuses to run before patch creation. Its targeted authorization/side-effect test passed; all 14 focused investigation tests pass. This refines the same captured diff and does not require another paid capture. Docker smoke now checks replay provenance/integrity and the recorded validation result as well as restart persistence.


## Acceptance update — 2026-11-18

Source milestone published as `41eca5969d39c37ad9fa519f7242c7d66c63d432`. Direct browser review is now unblocked: desktop (1280px) evidence/test presentation and mobile (390px) layout inspected; reset and replay worked. Local screenshots are saved in the workspace work/ directory. This supersedes the earlier visual-review blocker.

Clean Linux CI run 44392384706 has passed the container build, replay integrity/validation checks, health and restart persistence. Unit/API/MCP, lint and evaluation jobs passed; browser job is still finishing at this checkpoint.

Additional acceptance hardening enforces the overall investigation deadline during in-flight operations, preserves paused state on cancellation, and tests tool timeouts and failed patch validation. All 17 focused investigation tests passed with no API charges. Remaining next step: publish this tested hardening and verify its final CI, then record final totals and limitations. No additional paid calls authorized beyond the existing $3 campaign ceiling are needed.


## Final verified status — AgentSec 2.0, 2026-11-18

The curated 2.0 interview workflow is implemented and verified. Final code: local `589152a`, public `ea12c49eecb49d302cbf21ce006cfd8956583a08`. Clean Linux CI [44392759807](https://github.com/jarowcavage/agentsec/actions/runs/44392759807) is green: **54 unit/API/MCP/policy tests + 28 evaluation cases + 6 desktop/mobile browser tests = 88 passing tests**. Two optional legacy live tests were excluded. Lint, formatting, JavaScript checks, dependency consistency, Docker build/startup, replay integrity, health and restart persistence passed. Local non-browser regression independently passed 82 tests. Desktop/mobile screenshots were visually inspected.

Works: real model-selected tool investigation, actual curated dependency patch, before/after OSV evidence and sandbox tests, scoped denial/approval/local artifact release, persistent recovery and spending gates, unified workspace, presentation controls, authentic zero-new-cost replay and 5-/15-minute scripts. Original SBOM workflow and governance console remain available. Local server restarted with latest code at http://127.0.0.1:8000/.

Failures disclosed: first two development captures failed (MCP structured response mismatch and repeated completed tool); fixes preceded the successful third capture. All attempts remain counted: **11 paid calls, $0.0016695 estimated, zero unsettled reservations**. No additional paid calls during final verification. These small-sample results are not a reliability benchmark or a billing receipt.

Current blockers: none for the curated native/replay demo. Limits: only the curated urllib3 repository is supported; production reachability is unknown; local role selection is not enterprise SSO; the optional connected GitHub write path is fixture-tested, not live-accepted; native macOS validation is verified, while the alternative Docker sample-validation executor has not had a separate live acceptance run. Docker application/replay verification is green and does not establish nested validation support. No public application was deployed.

Exact next steps: open the local URL, select Investigate Repository, then follow docs/DEMO_5_MINUTES.md or docs/DEMO_15_MINUTES.md. Replay needs no key or spending. For fresh runs use the explicitly initiated live mode and retain the campaign ledger. Future scope, if requested: separately accept the Linux sandbox executor, expand repository/lockfile support, and integrate production identity. Do not repeat completed milestones or recreate the recording unnecessarily.

## Active follow-up — real repositories and understandable review, 2026-11-18

User rejected the confusing curated-only primary UI and requested real GitHub scanning and suggested PRs. Home is now a plain-English repository input, package findings, before/after file review and explicit approve/reject flow. The Python recording moved to `/example` with an honest Play the Python example label. Public GitHub files are pinned to a real revision, fetched read-only with integrity checks, and all supported package versions are queried against OSV. Duplicate aliases are grouped; unsupported/ranged dependencies remain visible as incomplete coverage.

Supported changes: exact Python requirements pins and exact npm package.json dependencies without a lockfile. npm lockfiles v2/v3 can be scanned, but automatic lockfile rewriting is not claimed. New app tests are not run; proposals explicitly require compatibility testing before merge. The new workflow is deterministic with zero model calls, separate from the existing model-selected AI example.

Native verification: **106 passed, 2 legacy live tests excluded**, including eight desktop/mobile browser cases. New tests cover real patch application, npm manifest edits, alias grouping, scope/expiry/tampering, rejection, changed GitHub revision, single-use publication and ambiguous outcomes. Direct desktop UI review occurred before the final small refinements; further direct browser review encountered the approval-review quota. The user manually finished token creation; token access to both authorized repositories was verified without exposing it.

GitHub publishing is configured locally for `jarowcavage/agentsec` and `jarowcavage/juice-shop`, with a separate local approval password in ignored `.env`. Never commit or display credentials. User requested no token expiration. No merges are authorized. Real Juice Shop scan `97dc8e7c-cf9e-4f63-9ab8-1c8f258e792c` at `185add266e7cb0ba71c67c421e6c0970b9a5c381`: 10 exact package versions, 15 grouped problems, 220 skipped/partially covered entries. Its missing lockfile makes full installed dependency coverage unavailable. Live npm proposal acceptance is complete; see the latest checkpoint above.

This historical follow-up is complete; use the latest checkpoint at the top for current next steps.
