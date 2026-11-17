# Evaluation results

The deterministic fixture run passed 28 of 28 cases. Average measured case execution time was 548.235 ms. This excludes fixture setup and does not represent provider latency. The evaluation used real LangGraph and MCP on ordinary paths, HTTP fixtures for OSV and OpenAI, and injected MCP failures where called for.

| Measure | Result | Interpretation |
| --- | ---: | --- |
| Package matching | 8/8 | Coordinates, normalization, and skipped inputs matched expected values. |
| Workflow behavior | 6/6 | Covers successful triage, no-match cases, provider failures, and approved issue creation. Intended error responses count as a pass. |
| Tool use and retrieval | 7/7 | Covers expected guidance and safe handling of malformed, timed-out, or tampered MCP results. |
| Answer grounding checks | 3/3 | Covers acceptance of a real quote and rejection of unsupported quotes and unknown sources. |
| Unauthorized action prevention | 4/4 | Covers prompt injection, forged decisions, a pending draft, and explicit rejection. |

The fixture run made zero OpenAI calls and incurred zero model API cost. A separate live run found nine OSV advisories, generated one GPT‑6 Luna recommendation, and validated four citations. The scan took 803 ms and recommendation took 4,969 ms, including local MCP. OpenAI reported 1,315 input and 305 output tokens. The estimated cost was $0.000284. The live smoke is a single observation with no claim about typical latency, semantic grounding, or provider success rate.

- [Case definitions](../evals/cases.json)
- [Machine-readable fixture results](../evals/results.json)
- [Machine-readable live smoke results](../evals/live-smoke.json)
