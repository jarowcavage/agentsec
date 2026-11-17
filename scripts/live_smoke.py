"""Measure one real OSV and OpenAI run on the public bundled sample."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from agentsec.main import app  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "evals/live-smoke.json")
    args = parser.parse_args()
    if not os.getenv("OPENAI_API_KEY", "").strip():
        parser.error("Set OPENAI_API_KEY to authorize one real OpenAI request.")

    with TemporaryDirectory() as directory:
        os.environ["AGENTSEC_DATABASE"] = str(Path(directory) / "smoke.db")
        with TestClient(app, base_url="http://localhost") as client:
            started = perf_counter()
            response = client.post(
                "/api/scans",
                content=(ROOT / "samples/workbench-demo.cdx.json").read_bytes(),
                headers={"Content-Type": "application/json"},
            )
            scan_ms = (perf_counter() - started) * 1000
            if not response.is_success:
                raise SystemExit(f"OSV scan failed ({response.status_code}).")
            scan = response.json()
            finding = next(f for f in scan["findings"] if f["advisory_id"] == "GHSA-jfh8-c2jp-5v3q")
            started = perf_counter()
            response = client.post(f"/api/scans/{scan['id']}/findings/{finding['id']}/recommendation")
            triage_ms = (perf_counter() - started) * 1000
            if not response.is_success:
                raise SystemExit(
                    f"Live recommendation failed ({response.status_code}): {response.json()['detail']}"
                )
            result = response.json()
            trace = client.get(f"/api/scans/{scan['id']}/trace").json()
            assert result["usage"] and trace["model_usage"] == [result["usage"]]
            report = {
                "date_utc": datetime.now(UTC).isoformat(timespec="seconds"),
                "providers": "live OSV and OpenAI",
                "calls": 1,
                "advisory": finding["advisory_id"],
                "findings": len(scan["findings"]),
                "model": result["model"],
                "validated_citations": 1 + len(result["assessment"]["steps"]),
                "scan_ms": round(scan_ms, 3),
                "triage_ms": round(triage_ms, 3),
                "usage": result["usage"],
                "stages": [event["operation"] for event in trace["events"]],
            }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Saved {args.output}")


if __name__ == "__main__":
    main()
