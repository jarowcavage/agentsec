# AgentSec

**Check a GitHub repository. Understand the findings. Review a proposed fix.**

AgentSec checks a public GitHub repository at a pinned revision for known vulnerabilities in its dependencies. It shows the affected files, coverage gaps and proposed changes in plain English, with a visible approve/reject step before a change can be downloaded or sent to GitHub.

The bounded LangGraph/OpenAI investigation remains available as a clearly labeled recorded Python example at `/example`. Repository scanning is deterministic and makes **no AI calls**; it is not presented as autonomous model reasoning.

## Start locally

```sh
AGENTSEC_DEMO=1 docker compose up --build
```

Open [AgentSec](http://127.0.0.1:8000/), paste a public GitHub repository URL, and click **Check repository**. Choose an affected package, then **Prepare suggested pull request**. Review the original/proposed files and limitations, switch to the local reviewer, and approve or reject. Nothing is merged automatically.

Without Docker, use Python 3.12+:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
AGENTSEC_DEMO=1 uvicorn agentsec.main:app --host 127.0.0.1 --port 8000
```

## Repository scanning and pull requests

- Python: exact pins in `requirements*.txt`. npm: version 2/3 lockfiles (direct and indirect packages), or exact direct versions in package.json. All matched reports are checked; aliases for the same problem are grouped.
- Unsupported files, version ranges and missing indirect dependency coverage are shown, not hidden. Maximum 40 dependency files, 250 distinct versions and 20,000 repository entries. Public repositories only.
- Python proposals modify real requirements files and query OSV for the replacement version. **Application tests are not run**, and compatibility is unverified. Exact npm pins without a lockfile can produce real package.json changes. Locked npm projects receive developer plans, not fabricated lockfile edits.
- A `.patch` describes edits; downloading it does not apply them.
- Optional publishing creates a new branch and **draft** PR only after exact, expiring approval plus separate connected authentication. Changed base revisions and duplicate retries are blocked. Configure a fine-grained token for the allowed repositories, with Contents and Pull requests write permissions. See [setup](docs/REPOSITORY_WORKFLOW.md).

This is dependency scanning (SCA), not application source-code analysis (SAST), secret scanning, or proof of exploitability.

## What is real in the recorded AI example

- A bounded LangGraph agent chooses typed MCP operations; server checks enforce completion criteria.
- Public OSV advisory/version checks and hash-verified PyPI artifacts.
- An inspectable urllib3 dependency patch in an isolated workspace.
- Actual sample tests: the original version fails the redirect-header policy regression; the captured upgraded version passes all three tests.
- Tool-boundary identity authorization, scoped expiring capabilities, revocation and single-use local artifact publication.
- Durable investigation history, explicit resume, persistent spending reservations and content-addressed model caching.

The captured successful run used six OpenAI calls at an estimated **$0.0012082**. All three development attempts, including two failures, totaled **$0.0016695**. These are observed estimates for this scenario, not general performance or billing guarantees. See [capture outcomes](recordings/capture-evaluation.json).

## Modes and boundaries

**Replay** at `/example` is an immutable recorded experience. **Live** requires explicit initiation, an exported OpenAI key and a supported sandbox. **Fixture tests** mock providers and are never presented as live investigations. The recorded example releases a local patch. The separate repository flow can create a real draft PR when configured and approved.

Live defaults: $1/run, $3 cumulative campaign estimate/reservations, 10 model calls, 900 output tokens/call and a seven-minute deadline. Unsupported pricing or sandbox configuration fails closed. See the [runbook](docs/AGENTSEC_2_RUNBOOK.md) before enabling live execution or recapturing a paid run.

This is a single-operator prototype with bounded repository scanning and a curated Python AI scenario, not arbitrary-repository autonomous repair or production SaaS. Package-level and regression evidence do not establish runtime reachability or universal exploit prevention. Demo role switching is not SSO. No public application is deployed.

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
