# Three-minute demo

Prepare the Workbench locally, verify that OSV responds, and load your API key. Use the bundled synthetic SBOM. Keep the machine-readable evaluation reports open in a separate tab if presenting live.

| Time | Walkthrough and talk track |
| --- | --- |
| 0:00–0:35 | Click **Run sample scan**. “This inventory includes Log4j Core 2.14.1 and its API package. The app derives package coordinates and dependency depth, then batches exact version lookups against OSV. Here is the coverage count and the advisory for Log4Shell.” |
| 0:35–1:25 | Select **Remote code injection in Log4j** and click **Generate recommendation**. “LangGraph calls a real MCP server over stdio to read the advisory, dependency context and ranked guidance. OpenAI drafts a risk assessment and remediation steps only after I select a finding.” |
| 1:25–2:05 | Open **Inspect source excerpts**. “Every displayed quote must exist in its named source. I still check whether the quote supports the claim, whether the code is exposed in the deployed environment, and which release branch to upgrade.” |
| 2:05–2:35 | Click **Draft mock issue**, read the preview, then click **Approve and create mock issue**. “The database keeps the draft pending until I decide. The decision and mock issue commit together. The model cannot invoke the write path.” |
| 2:35–3:00 | Open **Execution trace**. “Here are the MCP calls, model timing and token counts. The deterministic suite passed 28 cases. A separate smoke test measured one live request, so fixture results and live costs are reported separately.” |

If the upstream model is unavailable during a demo, show the interruption and use the saved live smoke report or a previously saved recommendation from the same local database. State which evidence was recorded earlier.
