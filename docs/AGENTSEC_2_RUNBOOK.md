# AgentSec 2.0 runbook

## Zero-new-cost interview startup

```sh
docker compose up --build
```

Open http://127.0.0.1:8000/. The default recording requires no API key and makes no external writes. The image includes the real captured execution and sample repository. This command requires a working Docker engine; do not alter another user's Docker socket permissions.

Native alternative, Python 3.12 or later:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
AGENTSEC_DEMO=1 uvicorn agentsec.main:app --host 127.0.0.1 --port 8000
```

Click Investigate Repository, Show complete outcome, then inspect Evidence / Diff / Tests / Access. Restart presentation clears only browser presentation state; recordings and live history remain intact. See DEMO_5_MINUTES.md and DEMO_15_MINUTES.md.

## Explicit fresh live run

Load OPENAI_API_KEY into the server environment using the existing ignored `.env` instructions. Enable AGENTSEC_DEMO=1 for local analyst/admin sessions. A native macOS Seatbelt runtime or a usable Docker CLI/engine with `python:3.12-slim` already available is required. Running the app inside ordinary Compose does not expose a Docker socket and does not automatically enable nested validation; use native supported execution for fresh investigations. Never mount the Docker socket into the application container just for this demo.

Choose Fresh live investigation and accept its explicit $1 maximum. The campaign ledger caps the cumulative estimate/reservations at $3. Max 10 calls, 900 output tokens/call, bounded context and a seven-minute investigation deadline. Model calls use no automatic provider retries. A failed/unknown call stays reserved. Model selection uses AGENTSEC_INVESTIGATION_MODEL; non-default models require explicit AGENTSEC_MODEL_PRICING_JSON entries with input/output prices per million tokens and date. Verify prices before changing them. Raising budgets is not exposed as an automatic action.

After validation select Access, demonstrate unauthorized publication, choose Administrator and inspect/approve the precise local artifact. Release it once. Revoke an unused grant or suspend the agent to demonstrate denial; restoration does not restore revoked grants. Reapprove expired/revoked grants only after reviewing the same hash. A consumed grant cannot be reused.

## Tests and recording

```sh
ruff check .
ruff format --check .
python -m pytest -q -m 'not live and not browser'
python -m playwright install chromium
AGENTSEC_BROWSER=1 python -m pytest -q -m browser
```

No paid calls occur in default tests. Browser tests replay the genuine saved capture and use fixtures for legacy provider flows. On macOS an installed browser can be selected with AGENTSEC_CHROMIUM.

`AGENTSEC_CAPTURE_APPROVED=1 python -m scripts.capture_investigation` is an explicitly paid capture operation, not a default test. It runs the live agent and the real local approval API, never a GitHub write. Run only with paid-call and local-release authorization. It records a success only after actual validation and publication. All attempts consume the persistent campaign ledger; do not delete it to evade spending limits.

## Recovery

History lists live runs. Server restart marks in-flight work paused. Resume preserves observations, reservations and the original deadline; expired runs require a new investigation. A provider error never becomes a synthetic success. Missing model configuration leaves replay usable. Missing sandbox prevents validation and therefore successful completion. Missing/corrupted recording fails visibly. Session expiry requires re-establishing a local persona; no role is inferred from model output.

State lives beside the configured AGENTSEC_DATABASE in `*.investigations.db` and an `investigations/` workspace directory. These are ignored runtime files. Recordings contain public evidence and sanitized paths, not credentials. Original CycloneDX uploads remain at `/legacy`; extended governance and separately configured GitHub issues remain at `/console`.
