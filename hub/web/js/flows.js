// Data flows between tools and the hub's apps: the flow table, its actions (enable, schedule, run, repair, remove)
// and the detail view. Used by the Integration hub and by a tool's Connection tab.
import { del, patch, post } from "./api.js";
import { xDomains, xHref } from "./extensions.js";
import {
  actions, badge, can, confirmDialog, dateTime, field, html, icon, modal, options, timeAgo, timeIn, toast,
} from "./ui.js";

export const DOMAINS = {
  assets: { label: "Assets", icon: "box", app: "Hub Assets", href: "#/assets" },
  vulnerabilities: { label: "Vulnerabilities", icon: "bug", app: "Hub Vulnerabilities", href: "#/vulnerabilities" },
  risks: { label: "Risks", icon: "alert", app: "Hub risk register", href: "#/compliance/risks" },
  controls: { label: "Controls", icon: "shield", app: "Hub controls and evidence", href: "#/compliance/controls" },
  people: { label: "People", icon: "contact", app: "Hub People", href: "#/people" },
  accounts: { label: "Accounts", icon: "key", app: "Hub People (accounts)", href: "#/people/accounts" },
};

/** A data domain ("assets", or "x:alerts" of an extension pack) as {label, icon, app, href}. */
export function domainInfo(domain) {
  if (DOMAINS[domain]) return DOMAINS[domain];
  const key = String(domain || "").startsWith("x:") ? domain.slice(2) : null;
  const d = key ? xDomains.find((x) => x.key === key) : null;
  if (d) return { label: d.title, icon: d.icon, app: `Hub ${d.title}`, href: xHref(d.key) };
  return { label: key ? `${key} (extension)` : domain, icon: key ? "puzzle" : "flow", app: "Hub" };
}
const ASSET_TYPES = ["server", "workstation", "network", "software", "saas", "cloud", "data", "other"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const SCHEDULES = [[0, "Only when run by hand"], [15, "Every 15 minutes"], [30, "Every 30 minutes"], [60, "Every hour"],
  [180, "Every 3 hours"], [360, "Every 6 hours"], [720, "Every 12 hours"], [1440, "Every day"], [10080, "Every week"],
  [43200, "Every 30 days"]];
const RETIRE_LABEL = {
  assets: "Retire assets that disappear from the tool",
  vulnerabilities: "Mark findings fixed that the tool no longer reports",
  risks: "Close risks that disappear from the tool",
  people: "Count people who disappear from the directory as having left it",
  accounts: "Remove accounts that disappear from the tool",
};

export function scheduleLabel(minutes) {
  if (!minutes) return "by hand";
  if (minutes % 1440 === 0) return minutes === 1440 ? "daily" : minutes === 10080 ? "weekly" : `every ${minutes / 1440} days`;
  if (minutes % 60 === 0) return minutes === 60 ? "hourly" : `every ${minutes / 60} h`;
  return `every ${minutes} min`;
}

/** "3 new, 2 updated" from a run's counts (the total and zeros left out). */
export function countsText(counts) {
  return Object.entries(counts || {}).filter(([k, v]) => k !== "total" && typeof v === "number" && v)
    .map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(", ");
}

/** A flow end ("hub" or "tool:<id>") as a name. */
export function endName(end, domain, names = {}) {
  if (end === "hub") return domainInfo(domain).app;
  const id = String(end || "").replace(/^tool:/, "");
  return names[id] || id;
}

const failing = (f) => f.last_result && f.last_result.ok === false;

function statusCell(f) {
  if (f.status === "proposed") {
    return html`${badge("proposed")}<div class="row" style="gap:6px;margin-top:6px" data-min-role="operator">
      <button class="btn sm ok" data-act="flow-enable" data-id="${f.id}" title="Approve and enable this flow">${icon("check")}Enable</button>
      <button class="btn sm" data-act="flow-dismiss" data-id="${f.id}" title="Reject the proposal; the flow stays disabled">Dismiss</button></div>`;
  }
  const on = f.status === "enabled";
  // a turned-down proposal: switching it on proposes it again (it waits for approval)
  const label = on ? `Disable ${f.title}` : f.rejected ? `Propose ${f.title} again` : `Enable ${f.title}`;
  return html`<div class="row" style="gap:8px;flex-wrap:nowrap">
    <button type="button" class="toggle" role="switch" aria-checked="${on ? "true" : "false"}" aria-label="${label}" title="${label}"
      data-act="flow-toggle" data-id="${f.id}" data-min-role="operator"></button>${f.rejected ? badge("rejected", "warn") : badge(f.status)}</div>`;
}

function runCell(f) {
  const job = f.job;
  if (job?.status === "running") {
    return html`<div class="row" style="gap:6px"><span class="dot working"></span><span>Scanning ${(job.hosts || []).length} host(s)</span></div>
      <div class="progress" style="margin-top:6px;max-width:160px"><span style="width:${Math.max(3, Math.min(100, Number(job.progress) || 0))}%"></span></div>`;
  }
  if (job?.status === "awaiting_approval") return html`<a href="#/approvals">${badge("scan awaiting approval", "warn")}</a>`;
  if (f.running) return html`<div class="row" style="gap:6px"><span class="dot working"></span>running</div>`;
  const r = f.last_result;
  if (!r) return html`<span class="faint">never run</span>`;
  const text = r.ok ? countsText(r.counts) || r.detail || "nothing changed" : r.error?.message || "failed";
  return html`<div class="row" style="gap:6px">${r.ok ? badge("ok") : badge("failed", "bad")}<span class="faint" title="${dateTime(r.at)}">${timeAgo(r.at)}</span>
      ${f.failures ? html`<span class="faint" style="font-size:12px">${f.failures} in a row</span>` : ""}</div>
    <div class="flow-result ${r.ok ? "" : "bad"}" title="${text}">${text}</div>`;
}

function repairControl(f) {
  if (!failing(f) || !f.last_result.error) return "";
  if (f.repair && f.repair !== "requested") return html`<a class="btn sm" href="#/approvals" title="A repair waits for approval">${icon("wrench")}Repair proposed</a>`;
  if (f.repair === "requested") return html`<span class="faint" style="font-size:12px">diagnosing...</span>`;
  return html`<button class="btn sm" data-act="flow-repair" data-id="${f.id}" data-min-role="operator" title="Ask the Patch Agent to diagnose the failure">${icon("wrench")}Repair</button>`;
}

function flowRow(f, showTool, names) {
  const d = domainInfo(f.domain);
  const runnable = (f.status !== "proposed" && !f.rejected) || f.job;
  return html`<tr class="${failing(f) && f.status === "enabled" ? "flow-failing" : ""}">
    <td style="min-width:240px"><div class="row" style="gap:8px;flex-wrap:nowrap;align-items:flex-start">${icon(f.direction === "scan" ? "radar" : d.icon)}
      <div style="min-width:0"><b class="flow-title">${f.title}</b>
        <div class="row" style="gap:6px;margin-top:3px">${badge(d.label, "accent")}${badge(f.direction === "scan" ? "scan" : f.direction === "pull" ? "into the hub" : "from the hub")}
          ${f.strategy === "generated" ? badge("generated connector", "info") : ""}
          ${showTool ? html`<a href="#/tools/${f.tool_id}/connection" style="font-size:12px">${names[f.tool_id] || f.tool_id}</a>` : ""}</div></div></div></td>
    <td>${statusCell(f)}</td>
    <td style="white-space:nowrap">${scheduleLabel(f.schedule_minutes)}${f.next_run && !f.job ? html`<div class="faint" style="font-size:12px" title="${dateTime(f.next_run)}">next ${timeIn(f.next_run)}</div>` : ""}</td>
    <td style="min-width:200px;max-width:340px">${runCell(f)}</td>
    <td><div class="row" style="gap:6px;justify-content:flex-end;flex-wrap:nowrap">
      ${repairControl(f)}
      ${runnable ? html`<button class="btn sm" data-act="flow-run" data-id="${f.id}" data-min-role="operator" ${f.running ? "disabled" : ""}
        title="${f.job?.status === "running" ? "Check the scan's progress" : "Run now"}">${icon(f.job?.status === "running" ? "refresh" : "play")}${f.job?.status === "running" ? "Check" : "Run"}</button>` : ""}
      <button class="icon-btn sm" data-act="flow-info" data-id="${f.id}" title="Details" aria-label="Details">${icon("file")}</button>
      <button class="icon-btn sm" data-act="flow-edit" data-id="${f.id}" data-min-role="operator" title="Schedule and options" aria-label="Schedule and options">${icon("sliders")}</button>
      <button class="icon-btn sm danger" data-act="flow-delete" data-id="${f.id}" data-min-role="operator" title="Remove" aria-label="Remove">${icon("trash")}</button>
    </div></td></tr>`;
}

/** The flow table. `names`: tool id -> name; `showTool` links each flow to its tool's Connection tab. */
export function flowsTable(flows, { showTool = true, names = {}, empty = "No data flows yet." } = {}) {
  if (!flows.length) return html`<p class="muted" style="padding:4px 0">${empty}</p>`;
  return html`<div class="table-wrap"><table class="table flows"><thead><tr><th>Flow</th><th>Status</th><th>Schedule</th><th>Last run</th><th></th></tr></thead>
    <tbody>${flows.map((f) => flowRow(f, showTool, names))}</tbody></table></div>`;
}

/** The option fields of a flow (or a pseudo-flow {domain, direction, options}); read back with readOptions. */
export function optionsForm(f) {
  const o = f.options || {};
  const parts = [];
  if (f.domain === "assets" && f.direction === "push") {
    const chosen = new Set(o.asset_types || []);
    parts.push(field("Asset types to send", html`<div class="check-grid">${ASSET_TYPES.map((t) => html`<label class="check">
      <input type="checkbox" name="asset_types" value="${t}" ${chosen.has(t) ? "checked" : ""}> ${t}</label>`)}</div>`, "None ticked: every type."));
  }
  if (f.direction === "pull") {
    parts.push(html`<label class="check" style="margin-bottom:12px"><input type="checkbox" name="retire_missing" ${o.retire_missing === false ? "" : "checked"}>
      ${RETIRE_LABEL[f.domain] || (f.domain.startsWith("x:") ? "Mark records stale that the tool no longer reports" : "Retire records that disappear from the tool")}</label>`);
  }
  if (f.domain === "vulnerabilities" && f.direction === "push") {
    parts.push(field("Lowest severity to send", html`<select name="min_severity">${options(SEVERITIES, o.min_severity || "low")}</select>`));
  }
  if (f.domain === "vulnerabilities" && (f.direction === "pull" || f.direction === "scan")) {
    parts.push(html`<label class="check" style="margin-bottom:12px"><input type="checkbox" name="include_info" ${o.include_info ? "checked" : ""}>
      Also import informational results (severity info / log)</label>`);
  }
  if (f.direction === "scan") {
    parts.push(field("Scan name", html`<input name="scan_name" value="${o.scan_name || ""}" maxlength="80" placeholder="Atrium scan <date>">`,
      "Shown in the scanner. Letters, digits, spaces, dots, colons and dashes."));
  }
  return parts;
}

export function readOptions(f, form) {
  const out = {};
  if (f.domain === "assets" && f.direction === "push") out.asset_types = [...form.querySelectorAll("[name=asset_types]:checked")].map((c) => c.value);
  if (f.direction === "pull") out.retire_missing = form.querySelector("[name=retire_missing]").checked;
  if (f.domain === "vulnerabilities" && f.direction === "push") out.min_severity = form.querySelector("[name=min_severity]").value;
  if (f.domain === "vulnerabilities" && (f.direction === "pull" || f.direction === "scan")) out.include_info = form.querySelector("[name=include_info]").checked;
  if (f.direction === "scan") {
    const name = form.querySelector("[name=scan_name]").value.trim();
    if (name) out.scan_name = name;
  }
  return out;
}

function editFlow(f, done) {
  const presets = SCHEDULES.some(([m]) => m === f.schedule_minutes) ? SCHEDULES : [...SCHEDULES, [f.schedule_minutes, scheduleLabel(f.schedule_minutes)]];
  modal({
    title: f.title,
    minRole: "operator",
    body: html`${f.reason ? html`<p class="muted" style="margin-bottom:12px">${f.reason}</p>` : ""}
      ${field("Schedule", html`<select name="schedule">${options(presets.map(([m, label]) => [String(m), label]), String(f.schedule_minutes))}</select>`,
        f.direction === "scan" ? "Scheduled scans wait for approval unless the hub is autonomous or an administrator turned that guardrail off." : "")}
      ${optionsForm(f)}`,
    async onSubmit(data, form) {
      const updated = await patch(`/flows/${encodeURIComponent(f.id)}`, { schedule_minutes: Number(data.get("schedule")), options: readOptions(f, form) });
      toast("Flow saved", "ok");
      done?.(updated);
    },
  });
}

function showFlow(f, names) {
  const r = f.last_result;
  const job = f.job;
  const info = domainInfo(f.domain);
  modal({
    title: f.title,
    wide: true,
    submit: null,
    cancel: "Close",
    body: html`${f.reason ? html`<p class="muted" style="margin-bottom:12px">${f.reason}</p>` : ""}
      <dl class="kv" style="margin-bottom:14px">
        <dt>Data</dt><dd>${info.href ? html`<a href="${info.href}">${info.label}</a>` : info.label}</dd>
        <dt>From</dt><dd>${endName(f.source, f.domain, names)}</dd><dt>To</dt><dd>${endName(f.target, f.domain, names)}</dd>
        <dt>Status</dt><dd>${badge(f.status)}${f.approval_id ? html` <a href="#/approvals">waiting for approval</a>` : ""}</dd>
        <dt>Schedule</dt><dd>${scheduleLabel(f.schedule_minutes)}${f.next_run ? html` <span class="faint">(next ${dateTime(f.next_run)})</span>` : ""}</dd>
        <dt>How</dt><dd>${f.strategy === "generated" ? "Generated REST connector" : f.domain.startsWith("x:") ? "Generic REST mapping from an extension pack" : "Built-in connector"}, run by <code>${f.owner}</code></dd>
        ${Object.keys(f.options || {}).length ? html`<dt>Options</dt><dd class="mono" style="font-size:12px">${JSON.stringify(f.options)}</dd>` : ""}
        <dt>Created</dt><dd>${dateTime(f.created_at)} by ${f.created_by}</dd>
      </dl>
      ${job ? html`<h3 style="margin-bottom:8px">Scan</h3><dl class="kv" style="margin-bottom:14px"><dt>State</dt><dd>${badge(job.status)}
          ${job.progress != null ? html` ${job.progress}%` : ""}${job.scanner_status ? html` <span class="faint">(${job.scanner_status})</span>` : ""}</dd>
        ${job.started_at ? html`<dt>Started</dt><dd>${dateTime(job.started_at)}</dd>` : ""}
        <dt>Hosts</dt><dd><div class="tag-list">${(job.hosts || []).map((h) => html`<span class="badge mono">${h}</span>`)}</div></dd></dl>` : ""}
      <h3 style="margin-bottom:8px">Last run</h3>
      ${r ? html`<dl class="kv" style="margin-bottom:12px">
          <dt>Result</dt><dd>${r.ok ? badge("ok") : badge("failed", "bad")} ${dateTime(r.at)}${r.duration != null ? html` <span class="faint">(${r.duration}s)</span>` : ""}</dd>
          <dt>Started by</dt><dd>${r.trigger || "-"}</dd>
          ${r.detail ? html`<dt>Detail</dt><dd>${r.detail}</dd>` : ""}
          ${Object.keys(r.counts || {}).length ? html`<dt>Counts</dt><dd>${Object.entries(r.counts).map(([k, v]) => html`<span class="badge">${k.replace(/_/g, " ")} ${typeof v === "object" ? JSON.stringify(v) : v}</span> `)}</dd>` : ""}
          ${f.failures ? html`<dt>Failures</dt><dd>${f.failures} in a row${f.failures >= 3 ? " - a repair is requested from the Patch Agent" : ""}</dd>` : ""}
        </dl>
        ${r.error ? html`<div class="notice bad" style="margin-bottom:12px">${icon("alert")}<div style="min-width:0"><b>${r.error.status ? `HTTP ${r.error.status}: ` : ""}</b><span style="white-space:pre-line;overflow-wrap:anywhere">${r.error.message}</span>
          ${r.error.excerpt ? html`<pre class="code wrap" style="margin-top:8px;max-height:200px">${r.error.excerpt}</pre>` : ""}</div></div>` : ""}
        ${r.sample ? html`<details><summary class="muted" style="cursor:pointer">Sample of what was sent or received (secrets masked)</summary>
          <pre class="code" style="margin-top:8px">${JSON.stringify(r.sample, null, 2)}</pre></details>` : ""}`
        : html`<p class="muted">This flow has not run yet.</p>`}`,
  });
}

function runToast(r) {
  if (r.error) return toast(`Failed: ${r.error.message}`, "bad");
  if (r.pending) return toast(r.detail || "Started - it continues in the background", "info");
  const moved = countsText(r.counts);
  toast(moved ? `Done: ${moved}` : r.detail || "Done - nothing changed", "ok");
}

/**
 * Wire the flow actions inside `root`. `find(id)` returns the flow as last rendered; `refresh()` reloads the view.
 */
export function wireFlows(root, { find, refresh, names = () => ({}) }) {
  const setStatus = async (id, status) => {
    try {
      const updated = await patch(`/flows/${encodeURIComponent(id)}`, { status });
      if (status === "enabled" && updated?.status === "proposed") toast("Proposed again - the flow waits for approval", "info");
      else toast(status === "enabled" ? "Flow enabled" : "Flow disabled", status === "enabled" ? "ok" : "info");
    } catch (err) {
      toast(err.message, "bad");
    }
    refresh();
  };
  actions(root, {
    "flow-toggle": (d) => setStatus(d.id, find(d.id)?.status === "enabled" ? "disabled" : "enabled"),
    "flow-enable": (d) => setStatus(d.id, "enabled"),
    "flow-dismiss": (d) => setStatus(d.id, "disabled"),
    async "flow-run"(d, btn) {
      btn.disabled = true;
      try {
        runToast(await post(`/flows/${encodeURIComponent(d.id)}/run`));
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
      refresh();
    },
    async "flow-repair"(d, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/flows/${encodeURIComponent(d.id)}/repair`);
        if (r.existing) toast("A repair is already waiting for approval", "info");
        else if (r.applied) toast("Repair applied - the flow runs again", "ok");
        else if (r.approval_id) toast(`Repair proposed (${(r.diagnosis || "").replace(/_/g, " ")}) - see Approvals`, "ok");
        else toast("The Patch Agent found nothing to repair through", "warn");
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
      refresh();
    },
    "flow-edit": (d) => { const f = find(d.id); if (f && can("operator")) editFlow(f, refresh); },
    "flow-info": (d) => { const f = find(d.id); if (f) showFlow(f, names()); },
    async "flow-delete"(d) {
      const f = find(d.id);
      if (!f || !(await confirmDialog("Remove data flow", `Remove "${f.title}"? Records already exchanged stay. The planner may propose it again later - to keep it off, disable it instead.`, "Remove"))) return;
      try {
        await del(`/flows/${encodeURIComponent(d.id)}`);
        toast("Flow removed", "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
      refresh();
    },
  });
}

/** Ask the Hub Supervisor to propose flows for every connection. */
export async function planFlows(refresh) {
  try {
    const r = await post("/flows/plan");
    const n = r.proposed?.length || 0;
    const waiting = (r.proposed || []).some((f) => f.status === "proposed");
    toast(n ? `${n} data flow${n > 1 ? "s" : ""} ${waiting ? "proposed - see Approvals" : "enabled"}` : "No new data flows to propose", n ? "ok" : "info");
  } catch (err) {
    toast(err.message, "bad");
  }
  refresh?.();
}
