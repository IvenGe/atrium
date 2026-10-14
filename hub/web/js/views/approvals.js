import { get, post } from "../api.js";
import { session } from "../auth.js";
import { DESIGNER_LABEL, jsonView, modeView, packHref, packItems, safeUrl, summaryChips, testsView } from "../extensions.js";
import { domainInfo, endName, scheduleLabel } from "../flows.js";
import { OP_LABEL, changeHref, countdown, rollbackLabel, startTicker, statusBadge, stepsView, violationsBanner } from "../netchanges.js";
import { loadIdentity, openProviderPicker } from "../sso.js";
import { actions, badge, can, dateTime, diffView, emptyState, html, icon, setHTML, timeAgo, timeIn, toast } from "../ui.js";
import { proposedMember } from "./agents.js";
import { ssoPlan } from "./tools.js";

const KIND_ICON = { command: "terminal", patch: "wrench", process: "play", flow: "flow", scan: "radar", repair: "wrench", agent_team: "users",
  extension: "puzzle", self_patch: "branch", firewall: "firewall" };
const KIND_LABEL = { flow: "data flow", agent_team: "agent team", self_patch: "change to Atrium", firewall: "device change" };
const APPROVE_LABEL = { flow: "Enable flow", scan: "Start scan", agent_team: "Create team", extension: "Enable extension", firewall: "Approve change" };
// changes to Atrium itself, new agents and network device changes: only administrators decide them (the server enforces it)
const ADMIN_KINDS = new Set(["extension", "self_patch", "agent_team", "firewall"]);
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
    <dt>Tool</dt><dd>${toolLink(p.tool_id, names)}</dd>
    ${p.proposed_by ? html`<dt>Proposed by</dt><dd>${p.proposed_by}</dd>` : ""}</dl>
    ${p.flow_id ? html`<p style="margin:-4px 0 10px"><a href="#/integration/map/flow/${encodeURIComponent(p.flow_id)}">${icon("plug")} Open on map</a></p>` : ""}`;
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

/** A network device change (kind firewall): what it does, the policy violations, who proposed it and why, when it would be
 *  applied, and when the approval expires. The diff and steps carry device text: rendered as text only. */
function firewallDetails(a, names) {
  const p = a.payload;
  const c = a.firewall_change;
  const mine = proposedByMe(p);
  const mw = c?.maintenance || p.maintenance || {}; // as of now (windows added since the proposal count), else the proposal-time copy
  const when = c?.status === "scheduled" ? html`scheduled${c.scheduled_for ? html` for ${dateTime(c.scheduled_for)}` : " - waits for a maintenance window"}`
    : !mw.required ? "at once after approval (no maintenance window required)"
      : mw.open ? html`now: the window "${mw.open.name}" is open` : mw.next ? html`in the next maintenance window, ${dateTime(mw.next.start)} (${timeIn(mw.next.start)})`
        : html`<span class="warn-text">when a maintenance window that covers the device exists - none yet</span>`;
  const expired = p.expires_at && p.expires_at <= Date.now() / 1000;
  // the next window opens only after this approval expires: it can only be applied as an emergency
  const late = c?.status === "scheduled" ? c.expires_before_window : !c || c.status === "proposed" ? mw.expires_before_window : false;
  return html`${violationsBanner(p.violations)}
    ${p.policy_unknown ? html`<div class="notice warn">${icon("alert")}<div style="min-width:0"><b>The segmentation policy could not be checked</b>
      <div class="muted" style="font-size:12.5px">No stored snapshot has this backup's revision, so Atrium cannot compare its rules with the current ones: the restore may re-open
        traffic the policy forbids. Only an administrator could propose it, with a justification.</div></div></div>` : ""}
    ${late ? html`<div class="notice warn">${icon("calendar")}<div style="min-width:0"><b>The approval expires before the next maintenance window opens</b>
      <div class="muted" style="font-size:12.5px">Approved, the change waits for that window and expires first - unless an administrator applies it as an emergency.
        Propose it again closer to the window, or add an earlier window in Settings > Network changes.</div></div></div>` : ""}
    <div class="nc-card-meta">
      <div><b>Device</b><a href="#/network/${encodeURIComponent(p.firewall)}">${names[p.firewall] || p.firewall}</a></div>
      <div><b>Operation</b>${OP_LABEL[p.op] || p.op}${c && c.status !== "proposed" ? html` ${statusBadge(c.status)}` : ""}</div>
      <div><b>Proposed by</b>${p.proposed_by}${mine ? " (you)" : ""}</div>
      <div><b>Applied</b>${when}</div>
      <div><b>Rollback</b>${rollbackLabel(p.rollback)}</div>
      <div><b>Expires</b>${expired ? html`<span class="warn-text">expired ${timeAgo(p.expires_at)}</span>` : html`${dateTime(p.expires_at)} (${countdown(p.expires_at)})`}</div>
      ${p.impact ? html`<div><b>Impact</b>${p.impact.assets} asset${p.impact.assets === 1 ? "" : "s"} in ${(p.impact.zones || []).length} zone${(p.impact.zones || []).length === 1 ? "" : "s"}</div>` : ""}
      <div><b>Bound to</b><span class="mono" title="Applying re-reads the device: another revision, or other operations, and nothing is applied">revision ${p.base_revision || "-"}, ${String(p.ops_hash || "").slice(0, 19)}</span></div>
      ${p.revert_of ? html`<div><b>Reverts</b><a href="${changeHref(p.firewall, p.revert_of)}">${p.revert_of}</a></div>` : ""}
      ${p.op === "restore" && p.backup_id ? html`<div><b>Backup</b><a class="mono" href="#/network/${encodeURIComponent(p.firewall)}/backups">${p.backup_id}</a></div>` : ""}</div>
    ${p.justification ? html`<div style="margin-bottom:10px"><b style="font-size:12.5px">Justification</b><div class="nc-just">${p.justification}</div></div>` : ""}
    ${p.steps?.length ? html`<div style="margin-bottom:10px">${stepsView(p.steps)}</div>` : ""}
    ${collapsibleDiff(p.diff, "the diff")}
    <p class="faint" style="font-size:12px;margin-top:6px">Rule text in the diff comes from the device. A backup is taken before applying (unless that guardrail is off); the change is verified and
      rolled back automatically when the checks fail. <a href="${changeHref(p.firewall, p.change_id)}">Open the change</a>
      ${p.edge ? html` · <a href="#/integration/segmentation/change/${encodeURIComponent(p.change_id)}">${icon("network")} Open on map</a>` : ""}</p>`;
}

/** Whether the signed-in person proposed it - themselves, or with an API token they created (``proposer_ids``). */
function proposedByMe(p) {
  const me = session.user?.username;
  return !!me && [p.proposed_by, ...(p.proposer_ids || [])].includes(me);
}

/** Why this person may not approve (the server refuses it too): the second-person rule, or an expired approval. */
function approveBlock(a) {
  const p = a.payload || {};
  if (p.expires_at && p.expires_at <= Date.now() / 1000) return "This approval has expired: the change must be proposed again.";
  if (!proposedByMe(p)) return null;
  const rule = a.kind === "firewall" ? "device_changes_need_second_person" : "approvals_need_second_person";
  if (!secondPerson[rule]) return null; // switched off (or unknown): the server decides
  return "You proposed this, so another administrator approves it (second-person rule). You can still reject it.";
}

// Local model provider names for team proposals, the self-patch guardrails and the second-person switches (loaded only
// while such an approval is waiting).
let providerNames = {};
let selfPatching = {};
let secondPerson = {};

/** A command on the hub machine or starting a tool runs with Atrium's own privileges: only administrators approve it,
 * operators may reject it (the server enforces it). */
function runsOnHub(a) {
  if (a.kind === "command") return (a.payload.target || "local") === "local";
  return a.kind === "process" && a.payload.action !== "stop";
}

/** A repair of a network device's connection: only administrators approve it (the server enforces it). */
function deviceRepair(a) {
  return a.kind === "repair" && !!a.payload.device;
}

function pendingCard(a, names) {
  const p = a.patch;
  const admin = ADMIN_KINDS.has(a.kind);
  const hostRun = runsOnHub(a);
  const adminApproves = hostRun || deviceRepair(a);
  const tests = a.self_patch?.tests || a.payload.tests;
  const blocked = a.kind === "self_patch" && selfPatching.requires_tests && !tests?.ok;
  const refused = approveBlock(a);
  const approveLabel = a.kind === "repair" ? (a.payload.change ? "Apply" : "Approve & retry")
    : a.kind === "self_patch" ? ((a.self_patch?.mode || a.payload.mode) === "pull_request" ? "Approve & open pull request" : "Approve & merge")
      : APPROVE_LABEL[a.kind] || "Approve";
  return html`<section class="card">
    <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
      <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:12px;min-width:0">
        <div class="stat-icon">${icon(a.kind === "process" && a.payload.action === "stop" ? "stop" : KIND_ICON[a.kind] || "checkCircle")}</div>
        <div style="min-width:0"><h3 style="overflow-wrap:anywhere">${a.title}</h3>
          <div class="faint" style="font-size:12px">${a.kind === "firewall" ? html`proposed by <b>${a.payload.proposed_by}</b> through the Network Supervisor`
            : html`requested by <b>${a.requested_by}</b>`} - ${timeAgo(a.created_at)}</div></div></div>
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
    ${a.kind === "firewall" ? firewallDetails(a, names) : ""}
    ${p ? html`<div class="row" style="margin:6px 0 10px;gap:6px"><span class="badge">${p.target}</span><span class="badge">${p.strategy.replace(/_/g, " ")}</span>
        ${p.target === "repo" ? html`<span class="faint" style="font-size:12px">applied on a new git branch in a separate worktree - your checkout is not touched</span>` : ""}
        ${p.sso ? html`<span class="spacer"></span><button class="btn sm" data-act="sso-change" data-tool="${a.payload.tool_id}" data-provider="${p.sso.provider}"
          data-min-role="operator">${icon("link")}Change provider</button>` : ""}</div>
      ${ssoPlan(p.sso)}
      ${collapsibleDiff(p.diff)}` : ""}
    <div class="row" style="margin-top:12px" data-min-role="${admin ? "admin" : "operator"}">
      <input placeholder="Note (optional)" data-note="${a.id}" style="flex:1;min-width:180px" aria-label="Note">
      <button class="btn" data-act="reject" data-id="${a.id}">${icon("x")}Reject</button>
      ${refused ? "" : html`<button class="btn ok" data-act="approve" data-id="${a.id}" ${blocked ? "disabled" : ""} ${adminApproves ? html`data-min-role="admin"` : ""}
        title="${blocked ? "The tests failed: it cannot be approved while the guardrail \"Self-patches must pass the tests\" is on" : ""}">${icon("check")}${approveLabel}</button>`}
    </div>
    ${refused ? html`<p class="faint" style="margin-top:8px;font-size:12.5px" data-min-role="${admin ? "admin" : "operator"}">${refused}</p>` : ""}
    ${admin && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">${a.kind === "agent_team"
      ? "Only administrators decide new agent teams (they create agent definitions)."
      : a.kind === "firewall" ? "Only an administrator who did not propose it approves a network device change."
        : "Only administrators decide changes to Atrium itself (extensions and self-patches)."}</p>` : ""}
    ${hostRun && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">Only administrators approve this: it runs on the
      hub machine with Atrium's own privileges. You can still reject it.</p>` : ""}
    ${deviceRepair(a) && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">Only administrators approve a repair of a
      network device's connection. You can still reject it.</p>` : ""}</section>`;
}

/** The history's result column: links for pull requests, "Apply again" for a self-patch that could not be applied. */
function resultCell(a) {
  const r = a.result;
  if (a.kind === "firewall" && a.firewall_change) {
    const c = a.firewall_change;
    return html`${statusBadge(c.status)} <a href="${changeHref(c.firewall, c.id)}">${c.id}</a>${r?.error ? html`<div>${r.error}</div>` : ""}`;
  }
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
    if (pending.some((a) => a.payload?.proposed_by)) {
      secondPerson = await get("/settings").then((r) => r.guardrails || {}).catch(() => ({}));
    }
    setHTML(el, html`
      <div class="page-head"><div><h1>Approvals</h1><p class="muted">Agents ask before they change anything: commands, patches, data flows, scans, repairs, new agent teams,
        extensions, changes to Atrium's own code and network device changes. Commands typed by a person in the Operator run directly.</p></div></div>
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
  startTicker(el);
  ctx.live(["approval", "firewall_change"], draw, 400);
}
