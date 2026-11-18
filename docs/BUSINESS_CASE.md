# Business case and limitations

AgentSec connects two buyer concerns: expensive vulnerability investigation and uncontrolled access by automation identities. Security engineering leads need useful evidence; developers need actionable remediation work; identity teams need owners, scoped permissions and revocation; executives need a defensible measurement plan.

The prototype differentiates through a demonstrable connection between an SBOM finding, its evidence, the agent retrieving that evidence, a human-approved action and a persistent policy audit. It is a reference implementation, not a replacement for an enterprise identity platform, commercial scanner or software supply-chain service.

Observed metrics include scan and recommendation counts, workflow-stage duration, approval waiting time, policy decisions and actual live-workbench token usage. Synthetic providers consume no OpenAI tokens. The ROI calculator uses user-entered assumptions for monthly volume, manual and assisted effort, review overhead, labor cost and platform costs. Estimated capacity hours = volume × (manual − assisted − review minutes) / 60. Estimated net value = hours × hourly rate − platform cost. Negative outcomes are retained. Human time is not automatically measured.

A pilot should compare representative investigations with a baseline, independently review evidence quality and remediation correctness, measure analyst and developer effort, and test revocation and approval controls. Set success criteria with the buyer before running it. Avoid extrapolating a small synthetic test suite into a security or financial guarantee.

Remaining production work includes human federation, multi-tenancy, individual attribution, session lifecycle/rate limits, database migration/versioning, audit integrity and retention, credential rotation, durable external-write reconciliation, verified EPSS/KEV ingestion and broader labeled evaluations. The GitHub adapter is tested against mocked HTTP responses; no live write is claimed. Neither model-driven autonomous tool selection nor universal prompt-injection prevention is claimed.
