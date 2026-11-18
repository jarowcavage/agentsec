# Fifteen-minute technical demonstration

## 0–3: outcome and scope

Follow the first three steps of DEMO_5_MINUTES.md. Explain the deliberately narrow curated repository, public CVE-2024-37891 evidence, actual dependency patch and sample tests. Unknowns remain explicit: production exposure, reachability and broader compatibility. Historical affected/patched versions come from the public advisory; the actual captured candidate came from PyPI and was checked against OSV.

## 3–6: agent decisions and MCP

Restart the presentation and advance **Next recorded step**. Expand decisions and actual tool outputs. The LangGraph state alternates between `reason` and `tool` nodes with conditional termination. The structured decision selects among typed tool operations. The server does not supply a predetermined next tool. Repeated completed tools and premature finish are rejected. Repository files are evidence, never executable model instructions.

One MCP stdio endpoint accepts a constrained operation enum; the launcher binds identity, resource and workspace outside tool arguments. Explain why MCP is useful here: it separates the tool process from model context and keeps credentials out of the prompt. The server checks action, scan scope, expiration and current identity permissions before executing the operation.

## 6–9: sandbox and verified artifacts

Inspect the diff and test logs. PyPI wheel SHA-256 values are checked before extraction; paths and symlinks are validated. The fixed sample tests run with network denied in macOS Seatbelt. Docker is an alternative executor using a read-only filesystem, no network, dropped capabilities and bounded CPU/memory/processes; it fails closed when no supported executor is available. No model-generated shell command is accepted. The native capture tested Seatbelt; do not claim that the Docker validation branch was live-verified on this machine.

The evidence proves this package-level advisory check and this specific regression/compatibility suite. It does not prove that every vulnerability is fixed or that arbitrary application tests pass.

## 9–11: permissions and human boundary

Select Access and inspect the recorded policy denial and grant. The deterministic attack input attempts to claim permission through untrusted text, but the backend has no standing publication right. The approver selects an exact patch hash. The database consumes the grant and persists completion in one transaction. A second publication attempt is denied. The downloaded bytes must match the approved hash.

In a fresh live run, switch the local human role to Administrator to approve, revoke, suspend or restore the investigator. Role switching is deliberately local-demo authentication, not enterprise SSO. Live GitHub issue creation remains a separate opt-in adapter with an independent approver password; this scenario releases a local artifact.

## 11–13: budgets, recovery and failures

Open **Engineering & trust boundaries**. SQLite saves observations and graph state after transitions. Startup marks interrupted work paused; resume uses the saved decision/observations while the original deadline remains valid. Unknown model charges remain reserved. The gateway checks both a $1 per-run and $3 campaign ceiling before each request; calls have output bounds, timeouts, versioned prompts, configurable pricing and content-addressed caching. Cache hits are labeled.

Disclose all capture attempts: two failed during development (MCP response-contract mismatch and repeated tool selection), then one successful capture. They are not a reliability benchmark. Total estimated new usage across the three attempts was $0.0016695. The replay is the successful run, with the failures preserved in the capture evaluation report.

## 13–15: engineering and next validation

Show tests/CI and explain trade-offs: FastAPI for typed APIs, SQLite for inspectable local persistence, one bounded LangGraph agent rather than multiple artificial agents, MCP for a meaningful execution boundary, browser-native modules rather than a large frontend framework.

Ask the panel which failure mode or repository would make a convincing next evaluation. Limitations include single-operator trust, curated Python-only remediation, no generic repository execution, no signed audit ledger, no hosted deployment and no claim of production security certification. End with the actual patch and resettable zero-new-cost presentation.
