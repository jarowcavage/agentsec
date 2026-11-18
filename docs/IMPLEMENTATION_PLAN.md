# Enterprise expansion implementation plan

## Assessment

Existing Python FastAPI application serves vanilla JavaScript UI; LangGraph orchestrates OSV enrichment, real stdio MCP evidence retrieval, structured OpenAI recommendations and SQLite mock issue review. Citation checks compare exact quotes to known excerpts. SQLite persists scans, recommendations, timing/token usage and approvals. Automated provider fixtures, MCP integration, browser tests and 28 evaluation cases exist. CI and container restart persistence passed on Linux.

## Weaknesses and missing capabilities

MCP has an allowlist but no authenticated per-agent principal or resource permissions. Approval routes have no human authentication. Audit lacks timestamps/principals. No identity inventory, temporary capabilities, governance dashboard, offline interview workflow or real GitHub writes. Evidence provenance is checked, not semantic correctness; reachability is unknown. Single-user local deployment is not enterprise authentication or tenant isolation.

## Architecture and milestones

Preserve FastAPI, SQLite, vanilla UI, LangGraph and stdio MCP. Add a persistent governance service shared by MCP and HTTP workflows. Bind subprocess identity via a server-issued opaque credential, never model arguments. Evaluate exact action/resource and current identity status at tool execution. Add expiring single-use grants tied to immutable action proposals; authenticated human roles decide requests. Append timestamped authorization and governance events. Demo identities and fixture-derived output must be explicitly labeled.

- P0: registry, credential authentication, default-deny permissions, scoped MCP authorization, persistent audit and bypass tests.
- P1: human roles, narrowly scoped one-use approvals, revocation and deterministic hostile tool proposal demonstration.
- P2: integrated dashboard, fixture-backed investigation, approval/execution UI, reset and optional allowlisted GitHub integration.
- P3: access certification, transparent risk flags, operational counts and assumption-based ROI.
- P4: narrative/runbook documentation, complete regression and browser verification.

## Demo acceptance

An operator investigates an explicitly labeled synthetic finding, inspects the agent, observes a denied write, requests exact scoped access, switches to a human administrator, approves and executes once, observes replay denial and immediate revocation, inspects timestamped audit events and resets only demo-owned data. No model or external service required for this path. Live OSV/OpenAI remain explicit separate workflows. No external write without configured allowlist and exact human approval.

## Status

Assessment and the core P0–P2 implementation are complete. See verified milestones and remaining scope below.

## Verified milestones

P0 complete: scoped authenticated MCP, registry, revocation and audit; 58 non-browser/non-live tests passed at its checkpoint.
P1 and local P2 complete: temporary local issue capabilities, administrator separation, injection attempt denial, isolated offline scenario and reset, responsive UI. Regression including four desktop/mobile workflows: 67 passed, 2 live tests excluded.

At the local P2 checkpoint the GitHub adapter was still pending; it was subsequently implemented and fixture-tested as recorded below. P3 partial: access certification, explainable missing-owner/unreviewed/no-activity flags and assumptions-only ROI exist. Credential aging, measured dashboard summaries and evaluation reporting are next. No SSO, multi-tenancy or production security certification is claimed.

## Final local verification

Optional connected GitHub adapter implemented after the local milestone: allowlisted repository, independent HTTP Basic approver, exact stored payload, expiring one-use claim, deduplication and uncertain-outcome handling. Two adapter tests use mocked HTTP responses; live write is unverified. Generated security report: 10/10 cases. Complete native regression: 69 passed, 2 live tests excluded, including four desktop/mobile flows. UI inspected in the local browser.

P3 delivers access reviews, explicit risk flags, observed operation summaries, actual synthetic test report and assumptions-only ROI. Advanced multi-finding prioritization, KEV/EPSS and broader sample severity levels remain incomplete. P4 documentation is present, including a 20-minute script and vendor narratives. Final Linux CI and Docker build/startup/restart verification passed in run 44268059453 at public code commit 57aaa00. Production authentication and hosted deployment are not claimed.
