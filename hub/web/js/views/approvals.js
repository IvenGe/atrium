import { get, post } from "../api.js";
import { session } from "../auth.js";
import { DESIGNER_LABEL, jsonView, modeView, packHref, packItems, safeUrl, summaryChips, testsView } from "../extensions.js";
import { domainInfo, endName, scheduleLabel } from "../flows.js";
import { OP_LABEL, changeHref, countdown, rollbackLabel, startTicker, statusBadge, stepsView, violationsBanner } from "../netchanges.js";
import { loadIdentity, openProviderPicker } from "../sso.js";
import { severityTone } from "../llm.js";
import {
  MODE_LABEL, UNTRUSTED, actionFacts, bridgeActions, changesList, charterFacts, coreFacts, decider, isSubsidiaryApproval, paramsTable, testsFacts,
  untrustedBox,
} from "../subsidiary-model.js";
import { actions, badge, can, dateTime, diffView, emptyState, html, icon, setHTML, timeAgo, timeIn, toast } from "../ui.js";
import { proposedMember } from "./agents.js";
import { ssoPlan } from "./tools.js";

const KIND_ICON = { command: "terminal", patch: "wrench", process: "play", flow: "flow", scan: "radar", repair: "wrench", agent_team: "users",
  extension: "puzzle", self_patch: "branch", firewall: "firewall", agent_escalation: "bell", subsidiary_charter: "file", subsidiary_action: "building" };
const KIND_LABEL = { flow: "data flow", agent_team: "agent team", self_patch: "change to Atrium", firewall: "device change", agent_escalation: "escalation",
  subsidiary_charter: "subsidiary charter", subsidiary_action: "change inside a tool" };
const APPROVE_LABEL = { flow: "Enable flow", scan: "Start scan", agent_team: "Create team", extension: "Enable extension", firewall: "Approve change",
  agent_escalation: "Acknowledge", subsidiary_charter: "Approve the charter", subsidiary_action: "Approve this change" };
const REJECT_LABEL = { agent_escalation: "Dismiss" };
// changes to Atrium itself, new agents and network device changes: only administrators decide them (the server enforces it)
const ADMIN_KINDS = new Set(["extension", "self_patch", "agent_team", "firewall"]);
const DESIGNER = { templates: "templates", model: "designed by the AI model", claude: "designed by Claude", auto: "automatic" };
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

/** An agent's escalation: who asks, how urgent, what it needs; the note is the answer it reads in its next turn. */
function escalationDetails(a) {
  const p = a.payload || {};
  return html`<div class="row" style="gap:6px;margin:8px 0">${badge(p.severity || "warning", severityTone(p.severity))}
      ${badge(p.needs === "information" ? "needs information" : "needs a decision", "")}
      <a href="#/agents/${encodeURIComponent(p.agent_id || a.requested_by)}/settings/escalation" style="font-size:12.5px">${p.agent_name || a.requested_by}</a></div>
    <p class="faint" style="font-size:12.5px;margin:0">Acknowledge or dismiss it; the note is your answer - ${p.agent_name || "the agent"} reads it in its next chat turn or run.</p>`;
}

// ---------- a subsidiary's approvals (round4-spec 11.1): facts Atrium computed; what the team or a model wrote is plain
// text under its label ----------

const subLink = (toolId, names, tab = "") => html`<a href="#/subsidiaries/${encodeURIComponent(toolId)}${tab ? `/${tab}` : ""}">${names[toolId] || toolId}</a>`;
const expiry = (ts) => (!ts ? "-" : ts <= Date.now() / 1000 ? html`<span class="warn-text">expired ${timeAgo(ts)}</span>` : html`${dateTime(ts)} (${timeIn(ts)})`);

/** "{staff} wants to {title} in {tool}" (the title): its risk, the exact parameters (escaped), how its run started, what
 *  the run read before it asked, the injection flags, and its reason in the untrusted box. */
function subsidiaryActionDetails(a, names) {
  const p = a.payload || {};
  const f = actionFacts(p);
  return html`<div class="row" style="gap:6px;margin:8px 0">${badge(`${f.risk} risk`, f.riskTone)}
      ${badge(f.reversible ? "reversible" : "not reversible", f.reversible ? "" : "warn")}${f.external ? badge("external effect", "bad") : ""}
      ${f.steered ? badge("panel: user-steered", "warn") : ""}${f.flags ? badge(`${f.flags} injection flag${f.flags === 1 ? "" : "s"}`, "bad") : ""}</div>
    <dl class="kv sub-card-facts">
      <dt>Inside</dt><dd>${subLink(p.tool_id, names)} <span class="faint">${f.mode === "bridge" ? "through its bridge, with a single-use grant for exactly these bytes"
        : "carried out by Atrium's supervisor through the connection (API only)"}</span></dd>
      <dt>Action</dt><dd class="mono">${f.action}</dd>
      <dt>Asked in</dt><dd>${f.steered ? html`<span class="warn-text">${f.trigger}</span> <span class="faint">(a tool user's question steered it)</span>` : f.trigger}</dd>
      <dt>Read first</dt><dd>${f.provenance.length ? html`<ul class="sub-checks">${f.provenance.map((x) => html`<li>${x}</li>`)}</ul>` : html`<span class="faint">nothing from the tool</span>`}</dd>
      ${f.flags ? html`<dt>Injection flags</dt><dd class="bad-text">${f.flags} passage${f.flags === 1 ? "" : "s"} the run read looked like instructions</dd>` : ""}
      <dt>Expires</dt><dd>${expiry(f.expiresAt)}</dd></dl>
    <b class="sub-small">Exact parameters: approved, they run exactly like this, once</b>
    ${paramsTable(p.params)}
    ${untrustedBox(f.reason, `Its reason - ${UNTRUSTED}`)}`;
}

/** A staff member the charter creates, with its scope in the new charter. */
function memberView(m) {
  const scope = m.scope || {};
  return html`<div class="sub-member"><b>${m.name}</b> <span class="faint">${m.title}</span> <span class="mono faint sub-small">${m.id}</span>
    <div class="tag-list" style="margin-top:4px">${(scope.actions || []).map((x) => html`<span class="badge mono">${x}</span>`)}
      ${(scope.actions || []).length ? "" : html`<span class="faint sub-small">no actions</span>`}
      ${(scope.hub_tools || []).map((t) => html`<span class="badge">hub: ${t.replace(/_/g, " ")}</span>`)}</div>
    <div class="faint sub-small" style="margin-top:4px">permissions: ${(m.permissions || []).join(", ").replace(/_/g, " ") || "none"}${m.schedule_minutes
      ? ` - every ${m.schedule_minutes} min` : ""}${m.provider ? ` - model: ${providerNames[m.provider] || m.provider}` : ""}</div>
    ${m.task ? html`<div class="sub-small sub-text" style="margin-top:4px"><span class="faint">Standing task:</span> ${m.task}</div>` : ""}</div>`;
}

/** A subsidiary's charter: what widens (highlighted), the diff against the charter in force, the routing warning, the
 *  conformance state and the staff it creates with their scopes. */
function subsidiaryCharterDetails(a, names) {
  const p = a.payload || {};
  const f = charterFacts(p, subsidiaries[p.tool_id], providerChoices);
  const c = f.conformance;
  return html`${f.widening.length ? html`<div class="notice warn sub-card-facts">${icon("alert")}<div style="min-width:0"><b>${f.first ? "The first charter: everything in it is new"
      : "It widens the charter in force:"}</b><ul class="sub-checks">${f.widening.map((r) => html`<li>${r}</li>`)}</ul></div></div>` : ""}
    ${f.routingWarning ? html`<div class="notice warn sub-card-facts">${icon("cloud")}<div style="min-width:0"><b>${f.routingWarning}</b></div></div>` : ""}
    <dl class="kv sub-card-facts">
      <dt>Subsidiary</dt><dd>${subLink(p.tool_id, names, "charter")}${f.mode ? html` ${badge(MODE_LABEL[f.mode] || f.mode, "accent")}` : ""}</dd>
      <dt>Version</dt><dd>${f.version}${f.first ? html` <span class="faint">(the first)</span>` : ""}</dd>
      <dt>Conformance</dt><dd>${c ? html`${badge(c.ok ? "passed" : "failed", c.ok ? "ok" : "bad")} <span class="faint">${c.originText}</span>` : html`<span class="warn-text">not run yet</span>`}</dd>
      ${f.routing.length ? html`<dt>Model</dt><dd>${f.routing.map((r) => html`<div class="${r.third ? "warn-text" : ""}">${r.text}${r.default ? " (default)" : ""}</div>`)}</dd>` : ""}
      ${f.mandate ? html`<dt>Mandate</dt><dd class="sub-text">${f.mandate}</dd>` : ""}
      <dt>Expires</dt><dd>${expiry(p.expires_at)}</dd></dl>
    ${f.changes ? html`<details ${f.changes.length <= 10 ? "open" : ""}><summary class="sub-summary">Every change (${f.changes.length})</summary>${changesList(f.changes)}</details>`
      : f.stale ? html`<p class="warn-text sub-small">The subsidiary no longer holds this version as its next charter: reject this request.</p>` : ""}
    ${f.members.length ? html`<p class="sub-small" style="margin:10px 0 6px">Approving creates ${f.members.length} staff member${f.members.length === 1 ? "" : "s"} placed in the sidecar,
      checked again against the guardrails as they are then:</p><div class="stack" style="gap:8px">${f.members.map(memberView)}</div>` : ""}`;
}

/** A bridge patch: the tests (passed, failed, or not run with the reason - then admin only, with a warning), the static
 *  checks, the vendored or AI-written core, the action table Atrium computed, the setup steps; the model's rationale is
 *  labelled as its own words. The generic patch rows below add the branch's diff. */
function bridgePatchDetails(a, names) {
  const p = a.payload || {};
  const plan = a.patch?.bridge || {};
  const t = testsFacts(p.tests);
  const core = coreFacts(p);
  const rows = bridgeActions(plan);
  const checks = plan.checks || [];
  const rationale = a.patch?.rationale || "";
  return html`${t.warning ? html`<div class="notice warn sub-card-facts">${icon("alert")}<div style="min-width:0"><b>${t.warning}</b></div></div>` : ""}
    <div class="row" style="gap:6px;margin:8px 0">${badge(`tests ${t.status.replace(/_/g, " ")}`, t.tone)}${badge(p.checks_ok ? "static checks passed" : "static checks failed", p.checks_ok ? "ok" : "bad")}
      ${badge(core.vendored ? "vendored core" : "core written by an AI model", core.tone)}${badge(p.designer === "model" ? "glue written by an AI model" : "glue from the template", p.designer === "model" ? "info" : "")}
      ${p.mounted === false ? badge("not mounted", "warn") : ""}</div>
    <dl class="kv sub-card-facts">
      <dt>For</dt><dd>${p.subsidiary_id ? subLink(p.tool_id, names, "setup") : names[p.tool_id] || p.tool_id} <span class="faint">(stack ${p.stack || "-"})</span></dd>
      <dt>Core</dt><dd>${core.text}</dd>
      <dt>Tool tests</dt><dd>${t.text}${p.tests?.command ? html` <code>${p.tests.command}</code>` : ""}</dd>
      <dt>Branch</dt><dd><span class="mono">${p.branch || "-"}</span> <span class="faint mono">${String(p.commit || "").slice(0, 12)}</span></dd>
      <dt>Expires</dt><dd>${expiry(p.expires_at)}</dd></dl>
    ${rationale ? (p.designer === "model" ? untrustedBox(rationale, "The AI model's rationale (its own words, not checked)")
      : html`<p class="muted sub-text" style="margin:8px 0">${rationale}</p>`) : ""}
    <h4 class="sub-h" style="margin-top:12px">Actions, with the risks Atrium computed</h4>
    ${rows.length ? html`<div class="table-wrap"><table class="table compact sub-actions"><thead><tr><th>Action</th><th>Risk</th><th>Reversible</th><th>External effect</th>
        <th>On behalf of the asker</th></tr></thead><tbody>${rows.map((r) => html`<tr><td><span class="mono">${r.id}</span><div class="faint sub-small">${r.title}</div></td>
        <td>${badge(r.risk, { read: "", propose: "info", write: "warn", admin: "bad" }[r.risk])}${r.floor ? html`<div class="warn-text sub-small">${r.floor}</div>` : ""}</td>
        <td>${r.reversible ? "yes" : "no"}</td><td>${r.external_effect ? html`<span class="warn-text">yes</span>` : "no"}</td><td>${r.on_behalf_of ? "yes" : "no"}</td></tr>`)}</tbody></table></div>`
      : html`<p class="faint sub-small">No tool actions yet: the template has the built-ins only.</p>`}
    ${(plan.removed || []).length ? html`<p class="sub-small" style="margin-top:8px"><b>Left out:</b></p><ul class="sub-checks">${plan.removed.map((r) => html`<li><span class="mono">${r.id}</span> - ${r.rule}: ${r.reason}</li>`)}</ul>` : ""}
    <p class="sub-small" style="margin-top:8px">${plan.panel ? "\"Ask the team\" panel: on" : "\"Ask the team\" panel: off"}${(plan.events || []).length ? html` - events: <span class="mono">${plan.events.join(", ")}</span>` : ""}</p>
    ${checks.length ? html`<details style="margin-top:6px"><summary class="sub-summary">Static check findings (${checks.length})</summary><ul class="sub-checks">${checks.map((c) => html`<li>
      ${badge(c.level || "error", c.level === "warn" ? "warn" : "bad")} <b>${c.rule}</b> <span class="mono">${c.file || ""}${c.line ? `:${c.line}` : ""}</span> ${c.detail || ""}</li>`)}</ul></details>` : ""}
    ${p.mounted === false && (plan.mount_steps || []).length ? html`<p class="sub-small warn-text" style="margin-top:8px"><b>Not mounted: a person adds these lines</b></p>
      <ol class="sub-steps-list">${plan.mount_steps.map((x) => html`<li>${x}</li>`)}</ol>` : ""}
    ${(plan.setup_steps || []).length ? html`<p class="sub-small" style="margin-top:8px"><b>Setup after approval</b></p><ol class="sub-steps-list">${plan.setup_steps.map((x) => html`<li>${x}</li>`)}</ol>` : ""}
    <p class="faint sub-small" style="margin:8px 0">${icon("lock")} Administrators only, in person - never the one who asked for the team. Approving keeps the branch;
      the tool still has to be deployed with its bridge.env, and the team works only after conformance and an approved charter.</p>`;
}

/** Whether the signed-in person proposed it - themselves, or with an API token they created (``proposer_ids``). A
 *  subsidiary's run records its person as a bus id ("user:alice"). */
function proposedByMe(p) {
  const me = session.user?.username;
  return !!me && [p.proposed_by, ...(p.proposer_ids || [])].some((x) => x === me || x === `user:${me}`);
}

/** Why this person may not approve (the server refuses it too): the second-person rule, or an expired approval. */
function approveBlock(a) {
  const p = a.payload || {};
  if (p.expires_at && p.expires_at <= Date.now() / 1000) return "This approval has expired: the change must be proposed again.";
  if (!proposedByMe(p)) return null;
  if (isSubsidiaryApproval(a)) { // a subsidiary's proposer never approves their own request, whatever the guardrail says
    return `You asked for this, so another ${decider(a) === "admin" ? "administrator" : "person"} approves it. You can still reject it.`;
  }
  const rule = a.kind === "firewall" ? "device_changes_need_second_person" : "approvals_need_second_person";
  if (!guards[rule]) return null; // switched off (or unknown): the server decides
  return "You proposed this, so another administrator approves it (second-person rule). You can still reject it.";
}

// AI provider names for team proposals, charters and "written by", the self-patch guardrails, the guardrail values (the
// second-person switches, the bridge patch's tests) and the subsidiaries of waiting charters (loaded only while such an
// approval is waiting).
let providerNames = {};
let providerChoices = [];
let selfPatching = {};
let guards = {};
let subsidiaries = {};

/** A patch that changes what runs when its tool is started - the launch command, setup, working folder, environment
 * files, launch secrets or environment other than PORT (the server's gapfix.touches_launch, read from the stored patch
 * GET /api/approvals returns). */
function touchesLaunch(p) {
  const launch = p?.manifest_update?.launch;
  if (!launch || typeof launch !== "object") return false;
  if (["command", "setup", "cwd", "env_files", "secret_env"].some((k) => k in launch)) return true;
  return Object.keys(launch.env || {}).some((k) => k !== "PORT");
}

/** A command on the hub machine, starting a tool, or a patch that changes how a tool is started runs with Atrium's own
 * privileges: only administrators approve it, operators may reject it (the server enforces it). */
function runsOnHub(a) {
  if (a.kind === "command") return (a.payload.target || "local") === "local";
  if (a.kind === "patch") return touchesLaunch(a.patch);
  return a.kind === "process" && a.payload.action !== "stop";
}

/** A repair of a network device's connection: only administrators approve it (the server enforces it). */
function deviceRepair(a) {
  return a.kind === "repair" && !!a.payload.device;
}

/** What a launch_command patch would run on the hub machine, shown like a command approval - marked when an AI model
 *  proposed it (from a README anyone may have written), above the model's own reasoning. */
function launchCommand(a) {
  const p = a.patch;
  const launch = a.kind === "patch" && p?.strategy === "launch_command" ? p.manifest_update?.launch : null;
  if (!launch || !(launch.command || launch.setup)) return "";
  return html`<div class="notice warn" style="margin:10px 0" data-launch-command>${icon("alert")}<div style="min-width:0">
      <div class="row" style="gap:6px;margin-bottom:6px">${p.generated_by ? badge("AI-proposed", "warn") : ""}<b>Runs on the hub machine with Atrium's privileges</b></div>
      <dl class="kv" style="margin:0">${launch.command ? html`<dt>Command</dt><dd><code style="overflow-wrap:anywhere">${launch.command}</code></dd>` : ""}
        ${launch.setup ? html`<dt>Setup</dt><dd><code style="overflow-wrap:anywhere">${launch.setup}</code></dd>` : ""}
        ${launch.cwd ? html`<dt>Directory</dt><dd><code>${launch.cwd}</code></dd>` : ""}</dl></div></div>`;
}

/** Which AI model wrote a proposal (patches, repairs, extension packs, self-patches, team designs). */
function writtenBy(a) {
  const g = a.payload?.generated_by || a.patch?.generated_by || a.self_patch?.generated_by;
  return g ? html`<p class="faint" style="font-size:12px;margin:6px 0">${icon("bot")} Written by ${g.model} (${providerNames[g.provider] || g.provider})</p>` : "";
}

function pendingCard(a, names) {
  const p = a.patch;
  const sub = decider(a); // a subsidiary's approval: "admin" or "operator" decides it, always in person
  const bridge = a.kind === "patch" && a.payload.strategy === "atrium_bridge";
  const adminKind = ADMIN_KINDS.has(a.kind);
  const admin = adminKind || sub === "admin";
  const hostRun = runsOnHub(a);
  const adminApproves = hostRun || deviceRepair(a);
  const tests = a.self_patch?.tests || a.payload.tests;
  const blocked = (a.kind === "self_patch" && selfPatching.requires_tests && !tests?.ok)
    || (bridge && guards.subsidiary_bridge_requires_tests !== false && (!a.payload.checks_ok || tests?.ok === false));
  const refused = approveBlock(a);
  const approveLabel = a.kind === "repair" ? (a.payload.change ? "Apply" : "Approve & retry")
    : a.kind === "self_patch" ? ((a.self_patch?.mode || a.payload.mode) === "pull_request" ? "Approve & open pull request" : "Approve & merge")
      : bridge ? "Approve the bridge" : APPROVE_LABEL[a.kind] || "Approve";
  return html`<section class="card">
    <div class="row" style="justify-content:space-between;flex-wrap:nowrap;align-items:flex-start">
      <div class="row" style="flex-wrap:nowrap;align-items:flex-start;gap:12px;min-width:0">
        <div class="stat-icon">${icon(a.kind === "process" && a.payload.action === "stop" ? "stop" : KIND_ICON[a.kind] || "checkCircle")}</div>
        <div style="min-width:0"><h3 style="overflow-wrap:anywhere">${a.title}</h3>
          <div class="faint" style="font-size:12px">${a.kind === "firewall" ? html`proposed by <b>${a.payload.proposed_by}</b> through the Network Supervisor`
            : html`requested by <b>${a.requested_by}</b>`} - ${timeAgo(a.created_at)}</div></div></div>
      ${badge(bridge ? "bridge patch" : KIND_LABEL[a.kind] || a.kind, "accent")}</div>
    ${launchCommand(a)}
    ${a.detail && a.kind !== "agent_team" && !sub ? html`<p class="muted" style="margin:10px 0;white-space:pre-line;overflow-wrap:anywhere">${a.kind === "self_patch" ? a.self_patch?.rationale || a.detail : a.detail}</p>` : ""}
    ${writtenBy(a)}
    ${a.kind === "command" ? html`<dl class="kv" style="margin:10px 0"><dt>Target</dt><dd>${a.payload.target}</dd>
        <dt>Command</dt><dd><code>${a.payload.command}</code></dd>${a.payload.cwd ? html`<dt>Directory</dt><dd><code>${a.payload.cwd}</code></dd>` : ""}</dl>` : ""}
    ${a.kind === "flow" ? flowDetails(a.payload, names) : ""}
    ${a.kind === "scan" ? scanDetails(a.payload, names) : ""}
    ${a.kind === "repair" ? repairDetails(a.payload, names) : ""}
    ${a.kind === "agent_team" ? teamDetails(a.payload, names) : ""}
    ${a.kind === "extension" ? extensionDetails(a, names) : ""}
    ${a.kind === "self_patch" ? selfPatchDetails(a, names) : ""}
    ${a.kind === "firewall" ? firewallDetails(a, names) : ""}
    ${a.kind === "agent_escalation" ? escalationDetails(a) : ""}
    ${a.kind === "subsidiary_action" ? subsidiaryActionDetails(a, names) : ""}
    ${a.kind === "subsidiary_charter" ? subsidiaryCharterDetails(a, names) : ""}
    ${bridge ? bridgePatchDetails(a, names) : ""}
    ${p ? html`<div class="row" style="margin:6px 0 10px;gap:6px"><span class="badge">${p.target}</span><span class="badge">${p.strategy.replace(/_/g, " ")}</span>
        ${p.target === "repo" ? html`<span class="faint" style="font-size:12px">applied on a new git branch in a separate worktree - your checkout is not touched</span>` : ""}
        ${p.sso ? html`<span class="spacer"></span><button class="btn sm" data-act="sso-change" data-tool="${a.payload.tool_id}" data-provider="${p.sso.provider}"
          data-min-role="operator">${icon("link")}Change provider</button>` : ""}</div>
      ${ssoPlan(p.sso)}
      ${collapsibleDiff(p.diff)}` : ""}
    <div class="row" style="margin-top:12px" data-min-role="${admin ? "admin" : "operator"}">
      <input placeholder="${a.kind === "agent_escalation" ? "Answer for the agent (optional)" : "Note (optional)"}" data-note="${a.id}" style="flex:1;min-width:180px"
        aria-label="${a.kind === "agent_escalation" ? "Answer for the agent" : "Note"}" maxlength="2000">
      <button class="btn" data-act="reject" data-id="${a.id}" data-kind="${a.kind}">${icon("x")}${REJECT_LABEL[a.kind] || "Reject"}</button>
      ${refused ? "" : html`<button class="btn ok" data-act="approve" data-id="${a.id}" data-kind="${a.kind}" ${blocked ? "disabled" : ""} ${adminApproves ? html`data-min-role="admin"` : ""}
        title="${!blocked ? "" : bridge ? "The static checks or the tool's tests failed: it cannot be approved while the guardrail \"Bridge patches must pass their checks and tests\" is on"
          : "The tests failed: it cannot be approved while the guardrail \"Self-patches must pass the tests\" is on"}">${icon("check")}${approveLabel}</button>`}
    </div>
    ${refused ? html`<p class="faint" style="margin-top:8px;font-size:12.5px" data-min-role="${admin ? "admin" : "operator"}">${refused}</p>` : ""}
    ${sub === "admin" && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">${a.kind === "subsidiary_action"
      ? "A high-risk change inside a tool (admin risk or an external effect): only an administrator decides it, in person."
      : a.kind === "subsidiary_charter" ? "Only administrators decide a subsidiary's charter, in person - never the one who asked for it."
        : "Only administrators decide a bridge patch, in person - never the one who asked for the team."}</p>` : ""}
    ${sub && can(sub) ? html`<p class="faint" style="margin-top:8px;font-size:12px">Decided in person on this page (an API token may only reject it); never by the one who asked.</p>` : ""}
    ${adminKind && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">${a.kind === "agent_team"
      ? "Only administrators decide new agent teams (they create agent definitions)."
      : a.kind === "firewall" ? "Only an administrator who did not propose it approves a network device change."
        : "Only administrators decide changes to Atrium itself (extensions and self-patches)."}</p>` : ""}
    ${hostRun && !can("admin") ? html`<p class="faint" style="margin-top:12px;font-size:12.5px">Only administrators approve this: ${a.kind === "patch"
      ? "it changes how the tool is started on the hub machine, where it runs" : "it runs on the hub machine"} with Atrium's own privileges. You can
      still reject it.</p>` : ""}
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
    if (pending.some((a) => a.kind === "agent_team" || a.kind === "subsidiary_charter")) {
      providerChoices = await get("/llm/providers").then((r) => r.choices).catch(() => []);
      providerNames = Object.fromEntries(providerChoices.map((c) => [c.id, c.kind === "local" ? `Local: ${c.label}` : c.label]));
    }
    // a charter's card compares it with the charter in force: its subsidiary (staff names, conformance, both charters)
    const charterTools = [...new Set(pending.filter((a) => a.kind === "subsidiary_charter").map((a) => a.payload?.tool_id).filter(Boolean))];
    subsidiaries = Object.fromEntries(await Promise.all(charterTools.map((t) => get(`/subsidiaries/${encodeURIComponent(t)}`)
      .then((s) => [t, s]).catch(() => [t, null]))));
    if (pending.some((a) => a.kind === "self_patch")) {
      selfPatching = await get("/self-patches").then((r) => r.availability).catch(() => ({}));
    }
    if (pending.some((a) => a.payload?.proposed_by || isSubsidiaryApproval(a))) {
      guards = await get("/settings").then((r) => r.guardrails || {}).catch(() => ({}));
    }
    setHTML(el, html`
      <div class="page-head"><div><h1>Approvals</h1><p class="muted">Agents ask before they change anything: commands, patches, data flows, scans, repairs, new agent teams,
        extensions, changes to Atrium's own code, network device changes, and the subsidiaries' charters, bridges and changes inside their tools. Commands an administrator types in the Operator run directly; an operator's commands
        on the hub machine (other than read-only ones) and tool starts wait here for an administrator. Agents also escalate questions here: acknowledge or dismiss
        them with an answer.</p></div></div>
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
  const decide = async (id, approve, kind) => {
    const note = el.querySelector(`[data-note="${CSS.escape(id)}"]`)?.value || null;
    try {
      await post(`/approvals/${id}`, { approve, note });
      toast(kind === "agent_escalation" ? (approve ? "Acknowledged - the agent reads your answer in its next turn" : "Dismissed")
        : approve ? "Approved - the agent is carrying it out" : "Rejected", approve ? "ok" : "warn");
    } catch (err) {
      toast(err.message, "bad");
    }
    draw();
  };
  actions(el, {
    tab: (d) => { tab = d.tab; draw(); },
    approve: (d) => decide(d.id, true, d.kind),
    reject: (d) => decide(d.id, false, d.kind),
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
  ctx.live(["approval", "firewall_change", "subsidiary"], draw, 400);
}
