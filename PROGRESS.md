# AgentSec Workbench progress

## Completed milestones

| Milestone | Shipped | Verification |
| --- | --- | --- |
| Phase 1 | CycloneDX upload, live OSV enrichment, local guidance, structured OpenAI recommendations | `e866bf7` implements the slice. `167c853` records the successful live OpenAI check after the API credit issue cleared. |
| Phase 2 | LangGraph, three read-only MCP tools, durable SQLite state, mock issue approval | `c9ea1c5`. All 31 tests passed with desktop and mobile Chrome, live OSV, and live OpenAI enabled. |
| Phase 3 | Local TF-IDF vector retrieval, execution trace, token and cost reporting, failure handling, deterministic evaluation | `e42d246`. The suite passed 58 tests with desktop and mobile Chrome and live OSV. One additional live smoke verified OpenAI through MCP, four citations, 1,315 input and 305 output tokens, and a $0.000284 estimated API cost. All 28 deterministic evaluation cases passed. |
| Phase 4 local deliverables | Dockerfile, Compose, GitHub Actions, HTTP smoke check, deployment runbook, architecture, threat model, demo walkthrough, interview notes, and résumé bullets | Compose syntax and `actionlint` passed. The HTTP smoke passed against native Uvicorn across a real restart. A container startup and a hosted CI run remain unverified. |

The local Workbench is available at [127.0.0.1:8000](http://127.0.0.1:8000/) when Uvicorn is running. The latest native startup returned healthy with recommendations configured. Use the [README](README.md) to restart it.

## Remaining work and blockers

- **Docker runtime:** Docker Desktop is running under another macOS account. A resume check on 2026-11-17 found its socket at `/Users/admin2/.docker/run/docker.sock`, but a direct connection returned permission denied. The default socket is still absent. Container build and startup remain unverified.
- **Hosted CI:** This checkout has no Git remote. The workflow has been validated locally with `actionlint`. The connected GitHub account is `jarowcavage`; its accessible owned repositories contain no AgentSec repository. The user approved creating the private `jarowcavage/agentsec-workbench` repository and pushing the code. The connector has no create-repository tool. The browser is at GitHub sign-in, and the user has been asked to sign in before repository creation can continue. A publication check confirmed the configured API key is absent from tracked files and credentials and runtime databases are excluded.
- **Hosted demo:** A target and approval are still required for deployment. The [deployment runbook](docs/deployment.md) describes an SSH-tunneled demo on an existing approved host and the requirements for public access.

## Exact next steps

1. Read this file and run `git status --short --branch` and `git log -5 --oneline`. Resume with infrastructure verification. The implementation and local application tests are complete.
2. From a user session with an approved Docker engine, run `docker info` and `docker compose --env-file .env.example up -d --build --wait`. Set `AGENTSEC_PORT=8001` and pass `--base-url http://127.0.0.1:8001` to the smoke script if native Uvicorn is using 8000. Follow the save, restart, and verify sequence in the runbook.
3. After the user signs in to GitHub, create the already-authorized private `jarowcavage/agentsec-workbench` repository, push the committed branch, and inspect the first Actions run. Its container job can perform Docker verification even while local socket access is blocked. Record the run link and actual result here.
4. Once an approved hosting target is available, use the deployment runbook and record the tested commit, access method, health response, sample result, and restart check.
