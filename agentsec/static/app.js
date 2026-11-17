"use strict";

const get = (id) => document.getElementById(id);
const ui = {
  form: get("upload-form"), file: get("sbom"), sample: get("sample"),
  scanStatus: get("scan-status"), workspace: get("workspace"), metrics: get("metrics"),
  skipped: get("skipped"), skipList: get("skip-list"), findings: get("finding-list"),
  details: get("finding-detail"), detail: get("detail"), result: get("recommendation"),
  recommendStatus: get("recommend-status"),
};
let activeScan = null;
let selectedFinding = null;
const recommendations = new Map();
const pending = new Set();

function element(tag, value, className) {
  const node = document.createElement(tag);
  if (value !== undefined) node.textContent = value;
  if (className) node.className = className;
  return node;
}

function status(node, message = "", error = false) {
  node.textContent = message;
  node.hidden = !message;
  node.className = error ? "status error" : "status";
}

async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json().catch(() => undefined);
  if (!response.ok || data === undefined) {
    throw new Error(typeof data?.detail === "string" ? data.detail : "The request failed. Try again.");
  }
  return data;
}

async function runScan(readFile) {
  ui.form.querySelector("button").disabled = true;
  ui.sample.disabled = true;
  activeScan = null;
  selectedFinding = null;
  recommendations.clear();
  ui.workspace.hidden = true;
  status(ui.scanStatus, "Checking package versions against OSV…");
  try {
    activeScan = await api("/api/scans", {
      method: "POST", headers: {"Content-Type": "application/json"}, body: await readFile(),
    });
    history.replaceState(null, "", "#" + activeScan.id);
    renderScan();
    status(ui.scanStatus, "Scan complete.");
  } catch (error) {
    status(ui.scanStatus, error.message, true);
  } finally {
    ui.form.querySelector("button").disabled = false;
    ui.sample.disabled = false;
  }
}

function renderScan() {
  const scan = activeScan;
  ui.metrics.replaceChildren();
  for (const [value, label] of [
    [scan.component_count, "Components"],
    [scan.queried_package_count, "Unique packages checked"],
    [scan.findings.length, "OSV findings"],
  ]) {
    const metric = element("div", undefined, "metric");
    metric.append(element("strong", value), element("span", label));
    ui.metrics.append(metric);
  }
  ui.skipList.replaceChildren(...scan.skipped.map(
    (item) => element("li", `${item.name} — ${item.reason}`),
  ));
  ui.skipped.hidden = !scan.skipped.length;
  ui.skipped.open = false;
  ui.findings.replaceChildren();
  for (const finding of scan.findings) {
    const button = element("button", finding.summary);
    button.type = "button";
    button.dataset.finding = finding.id;
    button.append(element("small", `${finding.advisory_id} · ${finding.package.name} ${finding.package.version}`));
    button.addEventListener("click", () => selectFinding(finding));
    ui.findings.append(button);
  }
  ui.detail.hidden = !scan.findings.length;
  if (scan.findings.length) {
    selectFinding(scan.findings[0]);
  } else {
    const message = scan.queried_package_count
      ? "OSV returned no active advisories for the packages checked."
      : "The SBOM had no supported, versioned package URLs to query.";
    ui.findings.append(element("p", message, "muted"));
  }
  get("trace").open = false;
  get("trace-content").replaceChildren();
  status(get("trace-status"));
  ui.workspace.hidden = false;
}

function advisoryLink(identifier) {
  const link = element("a", identifier);
  link.href = `https://osv.dev/vulnerability/${encodeURIComponent(identifier)}`;
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  return link;
}

function selectFinding(finding) {
  selectedFinding = finding;
  for (const button of ui.findings.querySelectorAll("button")) {
    button.setAttribute("aria-pressed", String(Number(button.dataset.finding) === finding.id));
  }
  status(ui.recommendStatus);
  ui.result.replaceChildren();
  const info = element("dl");
  for (const [label, value] of [
    ["Advisory", advisoryLink(finding.advisory_id)],
    ["Aliases", finding.aliases.join(", ") || "None reported"],
    ["Package URL", finding.package.purl],
    ["Dependency", finding.package.relationships.join(", ")],
    ["Severity vectors", finding.severity.map((entry) => entry.score).join(" · ") || "Unavailable"],
    ["Fixed endpoints", finding.fixed_candidates.join(", ") || "Unavailable"],
  ]) {
    const definition = element("dd");
    definition.append(value);
    info.append(element("dt", label), definition);
  }
  const button = element("button", "Generate recommendation", "recommend-button");
  button.type = "button";
  const key = `${activeScan.id}/${finding.id}`;
  const existing = recommendations.get(key);
  button.disabled = pending.has(key);
  button.hidden = Boolean(existing);
  button.addEventListener("click", () => generate(activeScan, finding, button));
  ui.details.replaceChildren(element("h3", finding.summary), info);
  if (finding.details) {
    const advisory = element("details", undefined, "advisory");
    advisory.append(element("summary", "Read advisory excerpt"), element("p", finding.details));
    ui.details.append(advisory);
  }
  if (finding.fixed_candidates.length) {
    ui.details.append(element("p", "Verify that a fixed endpoint applies to your release branch before upgrading.", "muted"));
  }
  ui.details.append(button);
  if (existing) {
    renderRecommendation(existing);
  } else if (!pending.has(key)) {
    restoreRecommendation(activeScan, finding);
  }
  if (button.disabled) status(ui.recommendStatus, "Generating a recommendation…");
}

async function generate(scan, finding, button) {
  const key = `${scan.id}/${finding.id}`;
  if (pending.has(key)) return;
  pending.add(key);
  button.disabled = true;
  status(ui.recommendStatus, "Generating a recommendation…");
  const isSelected = () => activeScan === scan && selectedFinding === finding;
  try {
    const data = await api(`/api/scans/${scan.id}/findings/${finding.id}/recommendation`, {method: "POST"});
    if (activeScan === scan) recommendations.set(key, data);
    if (isSelected()) selectFinding(finding);
  } catch (error) {
    if (isSelected()) {
      selectFinding(finding);
      status(ui.recommendStatus, error.message, true);
    }
  } finally {
    pending.delete(key);
    if (isSelected()) {
      const current = ui.details.querySelector(".recommend-button");
      current.disabled = false;
      if (recommendations.has(key)) status(ui.recommendStatus, "Recommendation ready.");
    }
  }
}

function cited(statement, sources, parent) {
  parent.append(element("p", statement.text));
  const source = sources.get(statement.source_id);
  const quote = element("blockquote", `“${statement.quote}” · `, "citation");
  quote.append(source.kind === "advisory" ? advisoryLink(source.title) : source.title);
  parent.append(quote);
}

async function restoreRecommendation(scan, finding) {
  const key = `${scan.id}/${finding.id}`;
  try {
    const result = await api(`/api/scans/${scan.id}/findings/${finding.id}/recommendation`);
    if (result && scan === activeScan && !recommendations.has(key) && !pending.has(key)) {
      recommendations.set(key, result);
      if (finding === selectedFinding) selectFinding(finding);
    }
  } catch {
    // The finding remains available to generate if the saved result cannot be loaded.
  }
}

function renderRecommendation(data) {
  const result = element("div", undefined, "recommend-result");
  const sources = new Map(data.evidence.map((source) => [source.id, source]));
  result.append(element("h2", "Remediation recommendation"), element("p", data.model, "muted"),
    element("h3", "Risk assessment"));
  cited(data.assessment.risk, sources, result);
  result.append(element("h3", "Recommended steps"));
  const steps = element("ol");
  for (const step of data.assessment.steps) {
    const item = element("li");
    cited(step, sources, item);
    steps.append(item);
  }
  result.append(steps, element("h3", "What to verify"), element("p", data.assessment.uncertainty));
  const evidence = element("details");
  evidence.append(element("summary", "Inspect source excerpts"));
  for (const source of data.evidence) {
    evidence.append(element("h3", source.title), element("p", source.excerpt));
  }
  const review = element("section", undefined, "issue-review");
  result.append(evidence, review);
  ui.result.replaceChildren(result);
  showReview(review, `/api/scans/${activeScan.id}/findings/${selectedFinding.id}/issue-review`);
}

ui.form.addEventListener("submit", (event) => {
  event.preventDefault();
  const file = ui.file.files[0];
  if (!file) return;
  if (file.size > 2 * 1024 * 1024) {
    status(ui.scanStatus, "The maximum SBOM size is 2 MiB.", true);
    return;
  }
  runScan(() => file);
});

ui.sample.addEventListener("click", () => runScan(async () => {
  const response = await fetch("/sample");
  if (!response.ok) throw new Error("The sample SBOM could not be loaded.");
  return response.blob();
}));

async function showReview(container, path) {
  const feedback = element("p");
  feedback.setAttribute("role", "status");
  const content = element("div");
  container.replaceChildren(element("h3", "Issue review"), content, feedback);

  function draw(review) {
    content.replaceChildren(element("p", "Local mock issue tracker", "muted"));
    if (!review) {
      addAction(content, "Draft mock issue", () => api(path, {method: "POST"}));
      return;
    }
    const draft = element("details");
    draft.append(element("summary", review.title), element("p", review.body));
    draft.open = review.status === "pending";
    content.append(draft);
    if (review.status === "pending") {
      const choices = element("div", undefined, "sample-actions");
      for (const [label, decision] of [["Approve and create mock issue", "approved"], ["Reject", "rejected"]]) {
        addAction(choices, label, () => api(`${path}/${review.id}/decision`, {
          method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({decision}),
        }));
      }
      content.append(choices);
    } else {
      content.append(element("p", review.status === "approved"
        ? `Mock issue #${review.issue_number} created.` : "Issue rejected."));
    }
  }

  function addAction(parent, label, submit) {
    const button = element("button", label, "secondary");
    button.type = "button";
    button.addEventListener("click", async () => {
      const buttons = content.querySelectorAll("button");
      buttons.forEach((item) => { item.disabled = true; });
      status(feedback, "Saving…");
      try {
        draw(await submit());
        status(feedback, "");
      } catch (error) {
        status(feedback, error.message, true);
        buttons.forEach((item) => { item.disabled = false; });
      }
    });
    parent.append(button);
  }

  try {
    draw(await api(path));
  } catch (error) {
    status(feedback, error.message, true);
  }
}

async function restoreScan() {
  const id = location.hash.slice(1);
  if (!/^[0-9a-f-]{36}$/i.test(id)) return;
  try {
    const scan = await api(`/api/scans/${id}`);
    if (!activeScan && !ui.sample.disabled) {
      activeScan = scan;
      renderScan();
    }
  } catch (error) {
    if (!activeScan && !ui.sample.disabled) status(ui.scanStatus, error.message, true);
  }
}

restoreScan();

async function refreshTrace() {
  const scan = activeScan;
  if (!scan) return;
  const feedback = get("trace-status");
  status(feedback, "Loading trace…");
  try {
    const trace = await api(`/api/scans/${scan.id}/trace`);
    if (activeScan !== scan) return;
    const events = element("ol");
    for (const event of trace.events) {
      const label = event.operation.replaceAll("_", " ");
      events.append(element("li", `${label} · ${event.outcome} · ${event.duration_ms.toFixed(1)} ms`));
    }
    const details = get("trace-content");
    details.replaceChildren(events);
    for (const usage of trace.model_usage) {
      const cost = usage.estimated_usd === null ? "Estimate unavailable" : `Estimated cost $${usage.estimated_usd.toFixed(6)}`;
      details.append(element("p", `${usage.input_tokens} input tokens (${usage.cached_input_tokens} cached) · ${usage.output_tokens} output tokens · ${cost}`));
    }
    status(feedback);
  } catch (error) {
    if (activeScan === scan) status(feedback, error.message, true);
  }
}

get("refresh-trace").addEventListener("click", refreshTrace);
get("trace").addEventListener("toggle", () => {
  if (get("trace").open) refreshTrace();
});
