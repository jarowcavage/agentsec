# Twenty-minute customer demonstration

Persona: a hypothetical security engineering lead supporting developers and AI automation. No customer deployment or savings are claimed.

## 0–3 minutes: discover the problem

Ask: How many findings require manual research? Who owns automation identities? Which actions require approval today? How would you revoke a compromised agent? What evidence would make a pilot successful?

Agree on two outcomes: evidence that helps an engineer decide what to fix, and enforceable control over the automation carrying out that decision.

## 3–6 minutes: investigate

Open `/console`. Choose Security Analyst and **Switch persona**. In Overview select the narrative appropriate to the audience, then **Run Demo Scenario**. Explain the synthetic-provider badge before presenting results. Expand evidence excerpts. Show the package, fixture fixed candidate and explicit unknown reachability. The sample follows the actual LangGraph and MCP code; no OpenAI or OSV availability is required.

For a live optional extension use **Live SBOM workbench**, upload the provided CycloneDX file, run OSV and generate one recommendation. This uses network services and incurs a model call. Do not substitute live and fixture results without explaining the change.

## 6–9 minutes: connect the finding to its identity

Open **Agent identities**. Inspect AgentSec remediation's owner, permissions and tools. Explain that subprocess credentials are short-lived and tied to one scan, and that the server checks permissions rather than believing a model-provided identity. Additional synthetic agents appear after **Reset Demo**; reset before starting the meeting if desired.

Return to Investigation and **Request temporary issue permission**. In Approvals expand **Exact proposed issue content**. Show the target, expiration and requesting agent. As Analyst click **approved**: the backend denies the action.

## 9–12 minutes: demonstrate controlled action

Choose Security Administrator and **Switch persona**. Click **approved**, then **Execute once**. The status becomes consumed and the simulated-issue count increases. Click **Execute once** again: replay is denied. Explain that this transaction writes only to the local mock tracker; it is not a GitHub issue.

The separate Connected GitHub panel requires a configured test repository, fine-grained token, independent administrator password and a live validated finding. It has explicit real-write confirmation and is not part of the default interview path. Its adapter is tested with HTTP fixtures, not a claimed live issue creation.

## 12–15 minutes: prove the security boundary

Open **Security demonstration** and click **Attempt unauthorized write**. Read the malicious advisory text, proposed tool action, denial reason and audit event. This is a deterministic simulated model attempt; the policy blocks it independently of model behavior. It is not evidence that all prompt injections are prevented.

Open Audit explorer and inspect the corresponding denial. Open Agent identities and suspend AgentSec remediation. Try Run Demo Scenario again: evidence retrieval cannot proceed. Suspension is checked by the tool boundary. Reset restores the isolated synthetic demo only.

## 15–18 minutes: discuss measurable value

Overview shows actual scan/recommendation counts, recorded workflow-stage duration, approval waiting time and the timestamped security test report. Stage time is not human triage time. Open Business impact and edit the assumptions with the buyer. Explain the displayed formula and what it excludes. Do not turn these assumptions into a claim of realized savings.

## 18–20 minutes: close and agree a pilot

Restate the buyer's success criteria: useful recommendations, visible ownership, scoped approval and auditable execution. Ask which repository and approval process would be appropriate for a controlled pilot. Name remaining production work: federated human identity, multi-user authorization, durable session management, audit integrity, live connected validation and broader evaluation. Finish with Overview; optionally Reset Demo after the meeting.
