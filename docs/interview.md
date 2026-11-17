# Staff and Principal SE interview notes

1. **Why call the model after a finding is selected?** Package matching is deterministic, and many results never need model triage. Waiting for the operator limits cost and focuses the prompt on one exact advisory and package.
2. **What does LangGraph add here?** It makes the order and state handoff between evidence retrieval, generation, validation, and persistence explicit. Separate review execution starts only with an operator decision. The project uses one workflow rather than coordinating multiple agents.
3. **What makes this a real MCP integration?** The application starts a separate SDK server over stdio and uses MCP initialization and tool calls. The model receives validated results, while the application controls which tools run.
4. **How does the retrieval system work?** Curated passages and the finding query are embedded as TF-IDF vectors and ranked by cosine similarity. Vocabulary overlap is a deliberate trade-off for a small corpus with local, reproducible retrieval and no paid embeddings.
5. **Does a valid citation guarantee the model is right?** It proves the quote is present in the named source. Whether it supports the prose, whether the application is exploitable, and whether the proposed release is compatible remain review decisions.
6. **How do you contain prompt injection?** Treat external text as evidence, supply no model tools, validate MCP results against known data, and render output as text. The issue write path requires an explicit operator decision scoped to a saved draft.
7. **What happens if OSV or MCP fails?** OSV retries transient errors within a deadline and rejects incomplete enrichment. MCP has a deadline and a fail-closed evidence check. The trace records failures without dumping upstream contents.
8. **How do you prevent duplicate issues?** SQLite serializes the decision, with a unique index on the review ID for issued records. Replaying the same decision returns the prior outcome. A conflicting decision returns HTTP 409.
9. **How did you measure quality and cost?** The 28 fixtures exercise matching, citation validation, tool use, workflow behavior, and authorization. They measure implementation behavior with controlled providers. A separate live smoke captures actual tokens, latency, and an estimated cost using published rates.
10. **What would you change before a rollout?** Add authenticated reviewers, per-resource permissions, spend limits, retention and backup procedures, and broader evaluation of claims against sources. A real issue tracker would also need narrowly scoped credentials and external idempotency.

## Résumé bullets

- Built AgentSec Workbench, an AI-assisted vulnerability triage prototype integrating CycloneDX inventories, live OSV enrichment, scoped MCP evidence retrieval, and structured OpenAI remediation with source and quote validation.
- Implemented durable human approval for a mock issue tracker and verified package matching, citation controls, MCP failure handling, and authorization across 28 deterministic evaluation cases, supplemented by a measured live provider run.
