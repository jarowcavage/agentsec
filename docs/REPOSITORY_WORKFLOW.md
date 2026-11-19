# Real repository checks and human review

The home screen now accepts a public GitHub URL. It reads the default branch once, pins the commit/tree, fetches supported dependency files by blob ID, validates their hashes and queries OSV for every supported exact version. It never clones or executes repository code. Plain-language labels distinguish reported vulnerabilities, skipped coverage and compatibility that has not been tested. Multiple reports with shared aliases are grouped without discarding their source links.

Supported: Python exact pins in requirements*.txt; npm package-lock v2/v3 including indirect packages; exact package.json entries when no npm lockfile exists. Poetry, uv, Yarn, pnpm, Java, Go and other formats are explicitly reported as unsupported. Includes, ranges, hashes, extras and conditional Python requirements need a resolved inventory. The existing CycloneDX upload can check additional ecosystems, but this repository parser does not claim that coverage.

Limits: public repositories, 40 dependency files, 1 MB per file, 250 distinct versions, 20,000 tree entries, 150-second scan deadline, two concurrent scans. A truncated tree or exceeded package limit fails the scan rather than reporting a partial clean bill. OSV has its own bounded request/pagination limits. GitHub rate limits can interrupt scanning. Results persist in SQLite; interrupted scans are marked incomplete and must be restarted. No model calls occur in this path.

## Proposals and approvals

Choose a package and prepare a suggested pull request. Simple Python exact pins can produce a real requirements diff with the latest stable PyPI version, but only after a new OSV query finds no known vulnerabilities for that version. This is a proposal, not compatibility proof; application tests are explicitly **not run**. Exact npm versions in package.json without an existing lockfile also produce real manifest changes, verified against npm registry metadata and OSV. npm lockfile changes remain developer action plans; no guessed lockfile edits are produced.

The reviewer sees the repository, revision, original and proposed files, PR title/body, vulnerability evidence and test limitations. Scanning access cannot approve. The local demo reviewer can approve or reject. Approval binds a digest of the target, revision, exact files, diff and PR description, expires in five minutes and is required even for patch download. Rejection/revocation and tampering block release. Local role switching is not enterprise authentication.

## Connect actual draft PR publishing

In the ignored server `.env`, set:

- `AGENTSEC_DEMO=1` for local reviewer access.
- `AGENTSEC_GITHUB_REPOSITORIES=owner/repository,owner/second-repository` for an explicit list of repositories you control.
- `AGENTSEC_GITHUB_TOKEN` to a fine-grained token scoped to that repository with Contents and Pull requests read/write. Do not grant Administration, Workflows or account access.
- `AGENTSEC_APPROVER_PASSWORD` to a separate password of at least 16 characters.

Load the environment and restart the local app. Do not commit or share these secrets. For token lifecycle use GitHub's token settings; expiration or revocation will prevent future writes.

After reviewing and approving a supported file change, explicitly click **Create draft pull request on GitHub** with the connected approver password. The server claims the approval once, checks the default branch still matches the reviewed revision, writes a tree/commit on a new `agentsec/<proposal-id>` branch and opens a draft PR. It does not merge. Partial or ambiguous network outcomes are persisted as uncertain and cannot be retried automatically; inspect GitHub first. A changed branch requires a new scan. Separate authentication is required even if the local role is administrator.

The GitHub implementation uses the official [tree API](https://docs.github.com/en/rest/git/trees) and [blob API](https://docs.github.com/en/rest/git/blobs). Reads are pinned and writes preserve existing file modes. The token goes only to `api.github.com`; redirects are disabled. The frontend never receives the token.

## Five-minute primary demo

1. Explain: “We check the packages a project depends on, show the actual proposed change, and leave the release decision with a person.”
2. Paste a public repository URL. Use `jarowcavage/agentsec` for a real source scan containing an intentionally vulnerable sample; point out the sample's path rather than implying it is a production dependency.
3. Show the named repository/revision, package count, grouped problems and skipped coverage. Select the affected package.
4. Prepare a suggested PR. Compare old/new file contents, show the evidence check, and point out that full application tests have not run.
5. Switch to local reviewer, reject once to demonstrate the boundary, then review/approve. Download the patch or, if connected and intended, create a real draft PR. Show the decision history. Never merge during a demo.

For an offline interview, use **Watch the recorded example** (`/example`). That is the captured model-selected LangGraph/MCP investigation with real sample sandbox tests and zero new AI charges. It is explicitly a different mode, not a live GitHub scan. The original detailed 5-/15-minute scripts describe this recorded AI path.
