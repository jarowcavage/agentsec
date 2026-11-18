# AgentSec

**Investigate a real vulnerability. Produce a patch. Prove the change. Govern its release.**

AgentSec is a local portfolio application built with FastAPI, LangGraph, MCP, SQLite and OpenAI. Its curated investigation repairs a urllib3 dependency in a disposable Python client. The default experience replays an authentic captured execution, with real evidence, model decisions, a dependency diff, sandbox test results and hash-bound human approval.

## Start the interview demo — no API key required

```sh
docker compose up --build
```

Open [AgentSec](http://127.0.0.1:8000/), click **Investigate Repository**, then **Show complete outcome**. Inspect Evidence, Diff, Tests and Access. Replay makes **zero new AI calls** and performs **no external writes**.

Without Docker, use Python 3.12+:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
AGENTSEC_DEMO=1 uvicorn agentsec.main:app --host 127.0.0.1 --port 8000
```

## What is real

- A bounded LangGraph agent chooses typed MCP operations; server checks enforce completion criteria.
- Public OSV advisory/version checks and hash-verified PyPI artifacts.
- An inspectable urllib3 dependency patch in an isolated workspace.
- Actual sample tests: the original version fails the redirect-header policy regression; the captured upgraded version passes all three tests.
- Tool-boundary identity authorization, scoped expiring capabilities, revocation and single-use local artifact publication.
- Durable investigation history, explicit resume, persistent spending reservations and content-addressed model caching.

The captured successful run used six OpenAI calls at an estimated **$0.0012082**. All three development attempts, including two failures, totaled **$0.0016695**. These are observed estimates for this scenario, not general performance or billing guarantees. See [capture outcomes](recordings/capture-evaluation.json).

## Modes and boundaries

**Replay** is the default, immutable recorded experience. **Live** requires explicit initiation, an exported OpenAI key and a supported sandbox. **Fixture tests** mock providers and are never presented as live investigations. The primary workflow releases a local patch; it does not pretend to create a pull request.

Live defaults: $1/run, $3 cumulative campaign estimate/reservations, 10 model calls, 900 output tokens/call and a seven-minute deadline. Unsupported pricing or sandbox configuration fails closed. See the [runbook](docs/AGENTSEC_2_RUNBOOK.md) before enabling live execution or recapturing a paid run.

This is a single-operator prototype for a curated Python repository, not arbitrary-repository autonomous repair or production SaaS. Package-level and regression evidence do not establish runtime reachability or universal exploit prevention. Demo role switching is not SSO. No public application is deployed.

## Demonstrate and inspect

- [5-minute recruiter demo](docs/DEMO_5_MINUTES.md)
- [15-minute technical demo](docs/DEMO_15_MINUTES.md)
- [Setup, reset, tests and failure recovery](docs/AGENTSEC_2_RUNBOOK.md)
- [Architecture, trust boundaries and decisions](docs/AGENTSEC_2_ARCHITECTURE.md)
- [Implementation ledger](docs/AGENTSEC_2_IMPLEMENTATION.md) and [progress/resume notes](PROGRESS.md)
- [Business case and assumptions](docs/BUSINESS_CASE.md)

Existing CycloneDX/OSV/OpenAI triage remains at `/legacy`; agent governance and optional connected GitHub issues remain at `/console`. Those interfaces preserve earlier functionality and have separate, explicit synthetic/live labels.

## Verify

```sh
ruff check .
ruff format --check .
python -m pytest -q -m 'not live and not browser'
python -m playwright install chromium
AGENTSEC_BROWSER=1 python -m pytest -q -m browser
```

Default tests spend no OpenAI credits. Fresh live capture is a separate opt-in operation; configuration and approvals are documented in the runbook.
