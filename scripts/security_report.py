"""Execute governance tests and persist actual outcomes, never prerecorded passes."""

import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "results.xml"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-q",
                "tests/test_governance.py",
                "tests/test_enterprise.py",
                "tests/test_github_integration.py",
                f"--junitxml={report}",
            ],
            cwd=ROOT,
            check=False,
        )
        if not report.exists():
            return result.returncode or 1
        cases = []
        for case in ET.parse(report).iter("testcase"):
            outcome = "passed"
            for kind in ("failure", "error", "skipped"):
                if case.find(kind) is not None:
                    outcome = kind
            cases.append(
                {
                    "name": case.attrib["name"],
                    "outcome": outcome,
                    "duration_seconds": float(case.attrib.get("time", 0)),
                }
            )
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "Synthetic deterministic governance tests; not production certification",
            "passed": sum(c["outcome"] == "passed" for c in cases),
            "total": len(cases),
            "cases": cases,
        }
        (ROOT / "evals/security-results.json").write_text(json.dumps(payload, indent=2) + "\n")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
