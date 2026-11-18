# AgentSec 2.0 implementation ledger

## Audit and reusable components

Keep FastAPI, SQLite, CycloneDX/OSV adapters, exact citation validation, real stdio MCP, server-issued scoped credentials, persistent policy audit and guarded connected writes. Existing LangGraph investigation is linear, not autonomous tool selection. Existing demo is synthetic provider execution, not authentic replay. Existing proposals create issues, not code patches. Local Docker access remains unavailable; container execution must fail closed until a usable sandbox exists.

## Curated hero scenario

Use a disposable Python HTTP-client sample pinned to urllib3 1.26.18. Investigate CVE-2024-37891 / GHSA-34jh-p97f-mpxf: cross-origin redirect handling of Proxy-Authorization. The public advisory identifies 1.26.19 and 2.2.2 as fixes for this specific advisory. Those historical versions must not be described as free of all vulnerabilities; fresh OSV lookup must evaluate candidate upgrades. Source: https://github.com/advisories/GHSA-34jh-p97f-mpxf

Generate an inspectable manifest diff in an isolated workspace, regenerate package inventory, query the targeted advisory before and after, and run checked-in compatibility tests plus a deterministic redirect-header regression in a network-disabled container. No arbitrary repository commands on the host. This proves bounded package/regression behavior, not general runtime exploit prevention.

## Verified increments

1. Baseline and repair: test existing application; restore authenticated dashboard on reload without silently assuming a persona.
2. Stateful investigation: typed model-selected tools, bounded conditional LangGraph routing, durable checkpoints and centralized budget reservation. Default $1 reservation; configurable prices, token/call/iteration/time caps; no paid execution without explicit approval.
3. Remediation: curated sample, sandbox executor, patch artifact, real tests and before/after inventory/advisory evidence. Fail closed without sandbox.
4. Governance: authorize each tool/action, bind approval to artifact hash and target; preserve revocation/replay controls.
5. Unified workspace: findings/navigation, investigation timeline, contextual evidence/diff; retire competing entry points after parity tests.
6. Presentation/replay: immutable authenticated capture of a successful real run, separate from fixture tests; 5/15-minute presentation paths. Replay is unavailable until an actual authorized live run exists.
7. Acceptance: clean startup, browser/security/failure-path checks and verified milestones committed.

## Current verified status

Milestones 2–6 implemented: bounded model-selected LangGraph/MCP investigation, persistent state and spending reservations, verified package artifacts, actual isolated before/after tests, dependency diff, local hash-bound publication, unified workspace, presentation controls and authentic replay. The live capture used macOS Seatbelt; no arbitrary repository commands ran outside sandboxing. Docker is an alternative validation executor and remains to be separately acceptance-tested.

Milestone 7: 84 automated tests passed with six desktop/mobile browser flows; two opt-in legacy live tests were excluded. The complete curated live scenario succeeded on the third development attempt. The first failed on an MCP response schema mismatch, the second on repeated completed-tool selection; both remain disclosed. Eleven paid calls across all three attempts had estimated total usage of $0.0016695, within the user's $3 authorization. The successful six-call recording cost $0.0012082 estimated.

No further paid calls are needed for replay or default tests. Direct screenshot review was blocked by the automatic approval-review usage limit; no screenshot or subjective visual-polish acceptance is claimed. Final Linux CI/container verification is pending publication. See PROGRESS.md for the latest status.

The recording has a content hash and versioned source provenance, not a digital signature. Durable graph checkpoints are application-owned SQLite snapshots, not a claim of native LangGraph interrupt/checkpoint plugins. The primary local artifact release has no external-write side effects. Existing connected GitHub issues remain optional and fixture-tested.
