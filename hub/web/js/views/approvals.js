import { get, post } from "../api.js";
import { DOMAINS, endName, scheduleLabel } from "../flows.js";
import { loadIdentity, openProviderPicker } from "../sso.js";
import { actions, badge, diffView, emptyState, html, icon, setHTML, timeAgo, toast } from "../ui.js";
import { ssoPlan } from "./tools.js";

const KIND_ICON = { command: "terminal", patch: "wrench", process: "play", flow: "flow", scan: "radar", repair: "wrench" };
const APPROVE_LABEL = { flow: "Enable flow", scan: "Start scan" };
const DIAGNOSIS = {
  credentials: "credentials refused", base_path: "API path", validation: "rejected data", unreachable: "unreachable", unknown: "unknown error",
  mapping: "mapping change", config: "settings change", manual: "needs a person", generated: "generated connector",
};

const diffLines = (diff) => (diff ? diff.split("\n").length : 0);
const toolLink = (id, names) => (id ? html`<a href="#/tools/${id}/connection">${names[id] || id}</a>` : "-");

function collapsibleDiff(diff, what = "diff") {
  return diffLines(diff) > 30
    ? html`<details><summary class="muted" style="cursor:pointer">Show ${what} (${diffLines(diff)} lines)</summary><div style="margin-top:8px">${diffView(diff)}</div></details>`
    : diffView(diff);
}

function flowDetails(p, names) {
  return html`<dl class="kv" style="margin:10px 0">
    <dt>Data</dt><dd>${DOMAINS[p.domain]?.label || p.domain}${p.action === "scan" ? " (scan in-scope assets)" : ""}</dd>
    <dt>From</dt><dd>${endName(p.source, p.domain, names)}</dd><dt>To</dt><dd>${endName(p.target, p.domain, names)}</dd>
    <dt>Schedule</dt><dd>${scheduleLabel(p.schedule_minutes)} <span class="faint">(changeable later in the Integration hub)</span></dd>
    <dt>Tool</dt><dd>${toolLink(p.tool_id, names)}</dd></dl>`;
}

function scanDetails(p, names) {
  const hosts = p.hosts || [];
  return html`<dl class="kv" style="margin:10px 0">
    <dt>Scanner</dt><dd>${toolLink(p.tool_id, names)}</dd>
    <dt>Assets</dt><dd>${(p.asset_ids || []).length} in scan scope</dd>
    <dt>Hosts</dt><dd><div class="tag-list">${hosts.slice(0, 40).map((h) => html`<span class="badge mono">${h}</span>`)}${hosts.length > 40 ? html`<span class="faint">+${hosts.length - 40} more</span>` : ""}</div></dd>
    ${p.origin ? html`<dt>Requested by</dt><dd>${p.origin}</dd>` : ""}</dl>`;
}

function repairDetails(p, names) {
  const change = p.change;
  return html`<div class="row" style="margin:6px 0 10px;gap:6px">${badge(DIAGNOSIS[p.diagnosis] || p.diagnosis, p.diagnosis === "generated" ? "info" : "warn")}
      <span class="faint" style="font-size:12px">${toolLink(p.tool_id, names)}</span></div>
    ${p.error?.message ? html`<div class="notice bad" style="margin-bottom:10px">${icon("alert")}<div style="min-width:0;overflow-wrap:anywhere">
      <b>${p.error.status ? `HTTP ${p.error.status}: ` : ""}</b>${p.error.message}</div></div>` : ""}
    ${p.tried?.length ? html`<details style="margin-bottom:10px"><summary class="muted" style="cursor:pointer">Tried ${p.tried.length} variant(s)</summary>
      <div style="margin-top:6px">${p.tried.map((t) => html`<div class="check-row"><div class="ico ${t.ok ? "pass" : "fail"}">${icon(t.ok ? "check" : "x")}</div>
        <div style="min-width:0"><code>${t.field}</code> = <span class="mono">${t.value}</span>${t.detail ? html`<div class="faint" style="font-size:12px">${t.detail}</div>` : ""}</div></div>`)}</div></details>` : ""}
    ${change ? html`<p style="font-size:12.5px;margin-bottom:6px">${p.diagnosis === "generated"
        ? html`Approving creates a <b>${change.kind === "generic_rest" ? "Generic REST" : change.kind}</b> connection without credentials; an administrator enters them in the tool's Connection tab.`
        : html`Approving changes these connection settings (never the address the credentials go to) and runs the flow again:`}</p>
      ${collapsibleDiff(p.diff, "settings change")}`
      : html`<p class="faint" style="font-size:12.5px">No settings change: approving runs the flow again once the cause is fixed.</p>`}`;
}

function pendingCard(a, names) {
  const p = a.patch;
  return html`<section class="card">
    <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
      <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:12px;min-width:0">
        <div class="stat-icon">${icon(KIND_ICON[a.kind] || "checkCircle")}</div>
        <div style="min-width:0"><h3 style="overflow-wrap:anywhere">${a.title}</h3>
          <div class="faint" style="font-size:12px">requested by <b>${a.requested_by}</b> - ${timeAgo(a.created_at)}</div></div></div>
      ${badge(a.kind === "flow" ? "data flow" : a.kind, "accent")}</div>
    ${a.detail ? html`<p class="muted" style="margin:10px 0;white-space:pre-line;overflow-wrap:anywhere">${a.detail}</p>` : ""}
    ${a.kind === "command" ? html`<dl class="kv" style="margin:10px 0"><dt>Target</dt><dd>${a.payload.target}</dd>
        <dt>Command</dt><dd><code>${a.payload.command}</code></dd>${a.payload.cwd ? html`<dt>Directory</dt><dd><code>${a.payload.cwd}</code></dd>` : ""}</dl>` : ""}
    ${a.kind === "flow" ? flowDetails(a.payload, names) : ""}
    ${a.kind === "scan" ? scanDetails(a.payload, names) : ""}
    ${a.kind === "repair" ? repairDetails(a.payload, names) : ""}
    ${p ? html`<div class="row" style="margin:6px 0 10px;gap:6px"><span class="badge">${p.target}</span><span class="badge">${p.strategy.replace(/_/g, " ")}</span>
        ${p.target === "repo" ? html`<span class="faint" style="font-size:12px">applied on a new git branch in a separate worktree - your checkout is not touched</span>` : ""}
        ${p.sso ? html`<span class="spacer"></span><button class="btn sm" data-act="sso-change" data-tool="${a.payload.tool_id}" data-provider="${p.sso.provider}"
          data-min-role="operator">${icon("link")}Change provider</button>` : ""}</div>
      ${ssoPlan(p.sso)}
      ${collapsibleDiff(p.diff)}` : ""}
    <div class="row" style="margin-top:12px" data-min-role="operator">
      <input placeholder="Note (optional)" data-note="${a.id}" style="flex:1;min-width:180px" aria-label="Note">
      <button class="btn" data-act="reject" data-id="${a.id}">${icon("x")}Reject</button>
      <button class="btn ok" data-act="approve" data-id="${a.id}">${icon("check")}${a.kind === "repair" ? (a.payload.change ? "Apply" : "Approve & retry") : APPROVE_LABEL[a.kind] || "Approve"}</button>
    </div></section>`;
}

function resultText(a) {
  const r = a.result;
  if (!r) return "";
  if (r.error) return r.error;
  if (r.branch) return r.branch;
  if (r.exit_code !== undefined) return `exit ${r.exit_code}`;
  if (r.location) return r.location;
  if (r.applied !== undefined) return r.applied ? "settings changed" : "retried";
  if (r.counts) return Object.entries(r.counts).filter(([k, v]) => k !== "total" && v).map(([k, v]) => `${v} ${k}`).join(", ") || "scan finished";
  if (r.status) return r.status;
  return "";
}

export async function render(el, ctx) {
  let tab = "pending";
  const draw = async () => {
    const all = await get("/approvals");
    const names = Object.fromEntries(ctx.state.tools.map((t) => [t.id, t.name]));
    const pending = all.filter((a) => a.status === "pending");
    const history = all.filter((a) => a.status !== "pending");
    setHTML(el, html`
      <div class="page-head"><div><h1>Approvals</h1><p class="muted">Agents ask before they change anything: commands, patches, data flows, scans and repairs.
        Commands typed by a person in the Operator run directly.</p></div></div>
      <div class="tabs"><button class="${tab === "pending" ? "active" : ""}" data-act="tab" data-tab="pending">Waiting (${pending.length})</button>
        <button class="${tab === "history" ? "active" : ""}" data-act="tab" data-tab="history">History (${history.length})</button></div>
      ${tab === "pending" ? (pending.length ? html`<div class="stack">${pending.map((a) => pendingCard(a, names))}</div>`
        : html`<section class="card">${emptyState("checkCircle", "Nothing waiting", "When an agent wants to run a state-changing command, apply a patch, start a data flow or a scan, or repair an integration, it shows up here.")}</section>`)
      : html`<section class="card flush">${history.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Action</th><th>Kind</th><th>By</th><th>Decision</th><th>Result</th><th>When</th></tr></thead><tbody>
          ${history.map((a) => html`<tr><td style="max-width:420px;overflow-wrap:anywhere">${a.title}${a.note ? html`<div class="faint">Note: ${a.note}</div>` : ""}</td>
            <td>${badge(a.kind)}</td><td>${a.requested_by}</td><td>${badge(a.status)}${a.decided_by ? html`<div class="faint" style="font-size:12px">by ${a.decided_by}</div>` : ""}</td>
            <td class="faint" style="font-size:12px;max-width:260px;overflow-wrap:anywhere">${resultText(a)}</td>
            <td class="faint">${timeAgo(a.decided_at || a.created_at)}</td></tr>`)}</tbody></table></div>`
        : emptyState("checkCircle", "No decisions yet", "Approved and rejected actions are kept here as an audit trail.")}</section>`}`);
  };
  const decide = async (id, approve) => {
    const note = el.querySelector(`[data-note="${CSS.escape(id)}"]`)?.value || null;
    try {
      await post(`/approvals/${id}`, { approve, note });
      toast(approve ? "Approved - the agent is carrying it out" : "Rejected", approve ? "ok" : "warn");
    } catch (err) {
      toast(err.message, "bad");
    }
    draw();
  };
  actions(el, {
    tab: (d) => { tab = d.tab; draw(); },
    approve: (d) => decide(d.id, true),
    reject: (d) => decide(d.id, false),
    async "sso-change"(d) {
      try {
        const data = await loadIdentity();
        const name = data.tools.find((t) => t.tool_id === d.tool)?.name || d.tool;
        openProviderPicker({ toolId: d.tool, toolName: name, data, current: d.provider, done: draw });
      } catch (err) {
        toast(err.message, "bad");
      }
    },
  });
  await draw();
  ctx.live(["approval"], draw, 400);
}
