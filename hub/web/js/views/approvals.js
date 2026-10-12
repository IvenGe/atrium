import { get, post } from "../api.js";
import { session } from "../auth.js";
import { DESIGNER_LABEL, jsonView, modeView, packHref, packItems, safeUrl, summaryChips, testsView } from "../extensions.js";
import { domainInfo, endName, scheduleLabel } from "../flows.js";
import { loadIdentity, openProviderPicker } from "../sso.js";
import { actions, badge, can, diffView, emptyState, html, icon, setHTML, timeAgo, toast } from "../ui.js";
import { proposedMember } from "./agents.js";
import { ssoPlan } from "./tools.js";

const KIND_ICON = { command: "terminal", patch: "wrench", process: "play", flow: "flow", scan: "radar", repair: "wrench", agent_team: "users",
  firewall: "shield",
  extension: "puzzle", self_patch: "branch" };
const KIND_LABEL = { flow: "data flow", agent_team: "agent team", self_patch: "change to Atrium", firewall: "network change" };
const APPROVE_LABEL = { flow: "Enable flow", scan: "Start scan", agent_team: "Create team", extension: "Enable extension",
  firewall: "Approve change" };
// changes to Atrium itself and new agents: only administrators decide them (the server enforces it)
const ADMIN_KINDS = new Set(["extension", "self_patch", "agent_team"]);
const DESIGNER = { templates: "templates", claude: "designed by Claude", auto: "automatic" };
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
    <dt>Data</dt><dd>${domainInfo(p.domain).label}${p.action === "scan" ? " (scan in-scope assets)" : ""}</dd>
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

function teamDetails(p, names) {
  const members = p.members || [];
  return html`<dl class="kv" style="margin:10px 0">
      <dt>Team</dt><dd>${p.tool_id ? toolLink(p.tool_id, names) : p.team}${p.depth > 1 ? html` <span class="faint">(sub-team, depth ${p.depth})</span>` : ""}</dd>
      <dt>Lead</dt><dd class="mono">${p.parent}</dd>
      <dt>Designed with</dt><dd>${DESIGNER[p.designer] || p.designer || "-"}${p.category ? ` - ${p.category}` : ""}</dd>
      ${p.on_behalf_of ? html`<dt>Asked by</dt><dd class="mono">${p.on_behalf_of} <span class="faint">(members get none of the permissions it lacks)</span></dd>` : ""}</dl>
    ${p.rationale ? html`<p class="muted" style="margin:0 0 10px;white-space:pre-line;overflow-wrap:anywhere">${p.rationale}</p>` : ""}
    <p style="font-size:12.5px;margin-bottom:6px">Approving creates ${members.length} agent${members.length === 1 ? "" : "s"}, checked again against the guardrails as they are then:</p>
    <div class="stack" style="gap:8px">${members.map((m) => proposedMember(m, providerNames))}</div>`;
}

function extensionDetails(a, names) {
  const p = a.payload;
  const pack = p.pack || {};
  return html`<dl class="kv" style="margin:10px 0">
      <dt>Pack</dt><dd><b>${pack.name || p.extension_id}</b> <span class="badge mono">${p.version}</span>
        <a class="mono" style="font-size:12px" href="${packHref(p.extension_id)}">${p.extension_id}</a></dd>
      <dt>For</dt><dd>${toolLink(p.tool_id, names)}</dd>
      <dt>Written by</dt><dd>${DESIGNER_LABEL[p.designer] || p.designer || "-"}</dd>
      <dt>Adds</dt><dd>${summaryChips(p.summary || {})}</dd>
      ${p.gaps?.length ? html`<dt>Closes</dt><dd>${p.gaps.map((g) => html`<div>${g.title}</div>`)}</dd>` : ""}</dl>
    <p style="font-size:12.5px;margin-bottom:6px">Approving enables the pack at once: its data types become apps, its connector mappings are merged into the tool's
      Generic REST connection (the API token is entered there), and its compliance rules and team templates apply. Nothing in a pack is executed.</p>
    <details><summary class="muted" style="cursor:pointer">Preview the ${pack.items?.length || 0} item${pack.items?.length === 1 ? "" : "s"}</summary>
      <div style="margin-top:8px">${packItems(pack.items || [], { pack })}</div></details>
    <details style="margin-top:6px"><summary class="muted" style="cursor:pointer">Pack JSON</summary>${jsonView(pack, "360px")}</details>`;
}

function selfPatchDetails(a, names) {
  const p = a.payload;
  const sp = a.self_patch;
  return html`<dl class="kv" style="margin:10px 0">
      <dt>Branch</dt><dd><span class="mono">${p.branch}</span>${p.base_branch ? html` <span class="faint">from ${p.base_branch}</span>` : ""}</dd>
      <dt>Files</dt><dd><div class="tag-list">${(p.files || []).map((f) => html`<span class="badge mono">${f}</span>`)}</div></dd>
      ${p.tool_id ? html`<dt>For</dt><dd>${toolLink(p.tool_id, names)}</dd>` : ""}
      ${sp?.goal ? html`<dt>Asked for</dt><dd style="white-space:pre-line">${sp.goal}</dd>` : ""}</dl>
    <div style="margin-bottom:10px">${modeView(sp?.mode || p.mode, sp?.mode_reason || p.mode_reason, p.base_branch)}</div>
    <div style="margin-bottom:10px">${testsView(sp?.tests || p.tests, selfPatching.requires_tests)}</div>
    ${sp ? html`${collapsibleDiff(sp.diff, "the change")}
      <p class="faint" style="font-size:12px;margin-top:6px"><a href="#/extensions/self-patches/${encodeURIComponent(sp.id)}">Self-patch details</a></p>`
      : html`<p class="warn-text" style="font-size:12.5px">The self-patch no longer exists - reject this request.</p>`}`;
}

// Local model provider names for team proposals and the self-patch guardrails (loaded only while one is waiting).
let providerNames = {};
let selfPatching = {};

function firewallDetails(a) {
  const p = a.payload || {};
  const violations = p.violations || [];
  return html`<p class="faint" style="font-size:12.5px">Proposed by <b>${p.proposed_by || "unknown"}</b>
    ${p.justification ? html` · ${p.justification}` : ""}</p>
    ${violations.length ? html`<div class="notice bad">${icon("alert")}<div><b>Violates ${violations.map((v) => v.control || "policy").join(", ")}</b></div></div>` : ""}
    ${p.diff ? diffView(p.diff) : ""}`;
}

function pendingCard(a, names) {
  const p = a.patch;
  const admin = ADMIN_KINDS.has(a.kind);
  const firewallOwn = a.kind === "firewall" && session.user && a.payload?.proposed_by === session.user.username;
  const firewallBlocked = a.kind === "firewall" && (!can("admin") || firewallOwn);
  const tests = a.self_patch?.tests || a.payload.tests;
  const blocked = a.kind === "self_patch" && selfPatching.requires_tests && !tests?.ok;
  const approveLabel = a.kind === "repair" ? (a.payload.change ? "Apply" : "Approve & retry")
    : a.kind === "self_patch" ? ((a.self_patch?.mode || a.payload.mode) === "pull_request" ? "Approve & open pull request" : "Approve & merge")
      : APPROVE_LABEL[a.kind] || "Approve";
  return html`<section class="card">
    <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
      <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:12px;min-width:0">
        <div class="stat-icon">${icon(a.kind === "process" && a.payload.action === "stop" ? "stop" : KIND_ICON[a.kind] || "checkCircle")}</div>
        <div style="min-width:0"><h3 style="overflow-wrap:anywhere">${a.title}</h3>
          <div class="faint" style="font-size:12px">requested by <b>${a.requested_by}</b> - ${timeAgo(a.created_at)}</div></div></div>
      ${badge(KIND_LABEL[a.kind] || a.kind, "accent")}</div>
    ${a.detail && a.kind !== "agent_team" ? html`<p class="muted" style="margin:10px 0;white-space:pre-line;overflow-wrap:anywhere">${a.kind === "self_patch" ? a.self_patch?.rationale || a.detail : a.detail}</p>` : ""}
    ${a.kind === "command" ? html`<dl class="kv" style="margin:10px 0"><dt>Target</dt><dd>${a.payload.target}</dd>
        <dt>Command</dt><dd><code>${a.payload.command}</code></dd>${a.payload.cwd ? html`<dt>Directory</dt><dd><code>${a.payload.cwd}</code></dd>` : ""}</dl>` : ""}
    ${a.kind === "flow" ? flowDetails(a.payload, names) : ""}
    ${a.kind === "scan" ? scanDetails(a.payload, names) : ""}
    ${a.kind === "repair" ? repairDetails(a.payload, names) : ""}
    ${a.kind === "agent_team" ? teamDetails(a.payload, names) : ""}
    ${a.kind === "extension" ? extensionDetails(a, names) : ""}
    ${a.kind === "self_patch" ? selfPatchDetails(a, names) : ""}
    ${a.kind === "firewall" ? firewallDetails(a) : ""}
    ${p ? html`<div class="row" style="margin:6px 0 10px;gap:6px"><span class="badge">${p.target}</span><span class="badge">${p.strategy.replace(/_/g, " ")}</span>
        ${p.target === "repo" ? html`<span class="faint" style="font-size:12px">applied on a new git branch in a separate worktree - your checkout is not touched</span>` : ""}
        ${p.sso ? html`<span class="spacer"></span><button class="btn sm" data-act="sso-change" data-tool="${a.payload.tool_id}" data-provider="${p.sso.provider}"
          data-min-role="operator">${icon("link")}Change provider</button>` : ""}</div>
      ${ssoPlan(p.sso)}
      ${collapsibleDiff(p.diff)}` : ""}
    <div class="row" style="margin-top:12px" data-min-role="${admin ? "admin" : "operator"}">
      <input placeholder="Note (optional)" data-note="${a.id}" style="flex:1;min-width:180px" aria-label="Note">
      <button class="btn" data-act="reject" data-id="${a.id}">${icon("x")}Reject</button>
      ${firewallBlocked ? "" : html`<button class="btn ok" data-act="approve" data-id="${a.id}" ${blocked ? "disabled" : ""}
        title="${blocked ? "The tests failed: it cannot be approved while the guardrail \"Self-patches must pass the tests\" is on" : ""}">${icon("check")}${approveLabel}</button>`}
    </div>
    ${a.kind === "firewall" && !can("admin") ? html`<p class="faint" style="margin-top:8px;font-size:12.5px">Only an administrator can approve a network change.</p>` : ""}
    ${firewallOwn ? html`<p class="faint" style="margin-top:8px;font-size:12.5px">You proposed this change. Someone else has to approve it.</p>` : ""}
    ${admin && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">${a.kind === "agent_team"
      ? "Only administrators decide new agent teams (they create agent definitions)."
      : "Only administrators decide changes to Atrium itself (extensions and self-patches)."}</p>` : ""}</section>`;
}

/** The history's result column: links for pull requests, "Apply again" for a self-patch that could not be applied. */
function resultCell(a) {
  const r = a.result;
  if (!r || r.error) return resultText(a);
  if (a.kind === "extension" && r.enabled !== undefined) return `${r.enabled ? "enabled" : "not enabled"}${r.notes?.length ? ` - ${r.notes.join("; ")}` : ""}`;
  if (a.kind !== "self_patch") return resultText(a);
  const pr = safeUrl(r.pr_url);
  if (pr) return html`<a href="${pr}" target="_blank" rel="noopener noreferrer">${icon("external")}pull request</a>`;
  if (r.ok && r.mode === "merge") return `merged into ${r.branch}${r.commit ? ` (${r.commit.slice(0, 10)})` : ""} - restart required`;
  return html`${r.detail || ""}${a.self_patch?.status === "approved" ? html`<div style="margin-top:4px"><button class="btn sm" data-act="sp-apply"
    data-id="${a.self_patch.id}" data-min-role="admin">${icon("merge")}Apply again</button></div>` : ""}`;
}

function resultText(a) {
  const r = a.result;
  if (!r) return "";
  if (r.error) return r.error;
  if (r.created) {
    const skipped = (r.skipped || []).map((s) => `${s.name}: ${s.reason}`).join("; ");
    return `${r.created.length} agent(s) created${skipped ? `; skipped ${skipped}` : ""}`;
  }
  if (r.stopped !== undefined) return r.stopped ? "stopped" : "was not running";
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
    if (pending.some((a) => a.kind === "agent_team")) {
      providerNames = await get("/llm/providers").then((r) => Object.fromEntries(r.choices.map((c) => [c.id, c.label]))).catch(() => ({}));
    }
    if (pending.some((a) => a.kind === "self_patch")) {
      selfPatching = await get("/self-patches").then((r) => r.availability).catch(() => ({}));
    }
    setHTML(el, html`
      <div class="page-head"><div><h1>Approvals</h1><p class="muted">Agents ask before they change anything: commands, patches, data flows, scans, repairs, new agent teams,
        extensions and changes to Atrium's own code. Commands typed by a person in the Operator run directly.</p></div></div>
      <div class="tabs"><button class="${tab === "pending" ? "active" : ""}" data-act="tab" data-tab="pending">Waiting (${pending.length})</button>
        <button class="${tab === "history" ? "active" : ""}" data-act="tab" data-tab="history">History (${history.length})</button></div>
      ${tab === "pending" ? (pending.length ? html`<div class="stack">${pending.map((a) => pendingCard(a, names))}</div>`
        : html`<section class="card">${emptyState("checkCircle", "Nothing waiting", "When an agent wants to run a state-changing command, apply a patch, start a data flow or a scan, repair an integration, build an agent team or extend Atrium itself, it shows up here.")}</section>`)
      : html`<section class="card flush">${history.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Action</th><th>Kind</th><th>By</th><th>Decision</th><th>Result</th><th>When</th></tr></thead><tbody>
          ${history.map((a) => html`<tr><td style="max-width:420px;overflow-wrap:anywhere">${a.title}${a.note ? html`<div class="faint">Note: ${a.note}</div>` : ""}</td>
            <td>${badge(KIND_LABEL[a.kind] || a.kind, "")}</td><td>${a.requested_by}</td><td>${badge(a.status)}${a.decided_by ? html`<div class="faint" style="font-size:12px">by ${a.decided_by}</div>` : ""}</td>
            <td class="faint" style="font-size:12px;max-width:260px;overflow-wrap:anywhere">${resultCell(a)}</td>
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
    async "sp-apply"(d, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/self-patches/${encodeURIComponent(d.id)}/apply`);
        toast(r.detail || (r.ok ? "Applied" : "Not applied"), r.ok ? "ok" : "bad");
      } catch (err) {
        toast(err.message, "bad");
      }
      draw();
    },
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
