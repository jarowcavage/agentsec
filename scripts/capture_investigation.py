"""Explicit paid live capture; never run as part of the default test suite."""

import json
import os
import time
from pathlib import Path

from fastapi.testclient import TestClient

from agentsec.investigation.ledger import digest
from agentsec.main import app


def main():
    if os.getenv("AGENTSEC_CAPTURE_APPROVED") != "1":
        raise SystemExit("Set AGENTSEC_CAPTURE_APPROVED=1 only with explicit paid-run approval.")
    os.environ["AGENTSEC_DEMO"] = "1"
    with TestClient(app, base_url="http://localhost") as client:
        client.post("/api/enterprise/session", json={"role": "analyst"}).raise_for_status()
        result = client.post("/api/investigations", json={"consent": True, "budget": 1})
        result.raise_for_status()
        run_id = result.json()["id"]
        print("Live run:", run_id, flush=True)
        previous = None
        for _ in range(220):
            run = client.get("/api/investigations/" + run_id).json()
            summary = (run["status"], len(run["events"]))
            if summary != previous:
                print(
                    summary,
                    run["events"][-1].get("summary", "") if run["events"] else "",
                    run["spending"],
                    flush=True,
                )
                previous = summary
            if run["status"] in ("awaiting_approval", "paused"):
                break
            time.sleep(2)
        if run["status"] != "awaiting_approval":
            raise SystemExit("Run did not validate; no recording written. " + str(run.get("error")))
        challenge = client.post(f"/api/investigations/{run_id}/challenge")
        challenge.raise_for_status()
        client.post("/api/enterprise/session", json={"role": "administrator"}).raise_for_status()
        approval = client.post(f"/api/investigations/{run_id}/approve")
        approval.raise_for_status()
        release = client.post(f"/api/investigations/{run_id}/publish")
        release.raise_for_status()
        run = client.get("/api/investigations/" + run_id).json()
        run["policy_challenge"] = challenge.json()
        run["approval"] = approval.json()
        run["artifact"] = release.json()
        # Remove machine-specific path prefixes, preserving recorded outcomes and timings.
        workspace = str(app.state.investigation_work / run_id)
        run = json.loads(json.dumps(run).replace(workspace, "[isolated-workspace]"))
        record = {
            "format": 1,
            "provenance": "Real OpenAI, PyPI, OSV and sandbox execution; paths redacted. Local artifact release explicitly approved.",
            "run": run,
            "sha256": digest(run),
        }
        Path("recordings/hero.json").write_text(json.dumps(record, indent=2) + "\n")
        print(
            "Captured",
            run_id,
            "spending",
            run["spending"],
            "campaign",
            app.state.investigations.spending(),
            flush=True,
        )


if __name__ == "__main__":
    main()
