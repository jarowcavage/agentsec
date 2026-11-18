# Five-minute recruiter demonstration

Open `/`. Stay in **Recorded investigation**: the included trace was captured from a real OpenAI, MCP, PyPI, OSV and sandbox execution. Replaying it makes no new model calls or external writes.

1. **0:00–0:30 — Problem.** “AgentSec investigates a dependency vulnerability, produces an actual patch, proves what changed, and requires scoped human approval before releasing it.” Click **Investigate Repository**, then **Show complete outcome** for an immediate view of the artifact and measured result.
2. **0:30–1:30 — Investigation.** Show the activity timeline and one expanded tool output. The model selected the investigative tools. The repository is a deliberately vulnerable disposable Python client, not a customer repository.
3. **1:30–2:30 — Remediation.** Select **Diff**. Show the actual urllib3 pin change from 1.26.18 to 2.8.0. Select **Tests**: the original dependency fails the redirect-header policy regression; the replacement passes all three sample tests. OSV no longer matches the targeted advisory to the replacement. This does not establish general runtime exploit prevention.
4. **2:30–3:30 — Governance.** Select **Access**, then **Inspect recorded denial**. This was an actual policy decision triggered by a deterministic challenge, not proof the model attempted an attack. Expand the recorded grant: it binds approval to one investigation, an exact patch hash and five minutes. Publication consumed it once.
5. **3:30–4:30 — Outcome.** Download the real patch. Show recorded processing time and estimated cost. The successful capture cost $0.0012082 in estimated model usage; replay costs $0 in new model calls. No production repository was changed.
6. **4:30–5:00 — Close.** “This demonstrates bounded investigation and governed remediation. The next validation would be representative repositories and human effort measurement.” Click **Restart presentation**; the immutable recording and live history are preserved.

Use **Presentation mode** for larger labels. No login or API key is needed for replay. If asked for fresh autonomy, select **Fresh live investigation** only when its explicit budget, provider configuration and supported sandbox are acceptable.
