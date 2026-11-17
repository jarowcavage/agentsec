"""Run the deterministic evaluation suite and save observed case results."""

import argparse
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean

import pytest

ROOT = Path(__file__).resolve().parents[1]


class Results:
    def __init__(self):
        self.cases = {}

    def pytest_runtest_logreport(self, report):
        identifier = report.nodeid.rsplit("[", 1)[-1].rstrip("]")
        if report.when == "call" or report.failed:
            self.cases[identifier] = {
                "outcome": report.outcome,
                "latency_ms": round(report.duration * 1000, 3),
            }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "evals/results.json")
    args = parser.parse_args()
    recorder = Results()
    status = pytest.main(["-q", str(ROOT / "tests/test_evaluation.py")], plugins=[recorder])
    fixtures = json.loads((ROOT / "evals/cases.json").read_text())
    cases = [
        {
            "id": fixture["id"],
            "metric": fixture["metric"],
            **recorder.cases.get(fixture["id"], {"outcome": "not_run", "latency_ms": None}),
        }
        for fixture in fixtures
    ]
    by_metric = defaultdict(list)
    for case in cases:
        by_metric[case["metric"]].append(case)
    timings = [case["latency_ms"] for case in cases if case["latency_ms"] is not None]
    report = {
        "providers": "OSV and OpenAI HTTP fixtures; in-process FastAPI and real MCP except fault injection cases",
        "case_count": len(cases),
        "passed": sum(case["outcome"] == "passed" for case in cases),
        "average_case_latency_ms": round(mean(timings), 3) if timings else None,
        "real_openai_calls": 0,
        "real_token_usage": 0,
        "real_estimated_api_cost_usd": 0,
        "metrics": {
            metric: {
                "passed": sum(case["outcome"] == "passed" for case in group),
                "total": len(group),
            }
            for metric, group in by_metric.items()
        },
        "cases": cases,
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(f"Saved {args.output}")
    return int(status)


if __name__ == "__main__":
    raise SystemExit(main())
