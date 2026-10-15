// Subsidiaries app (round4-spec 11.1): agent teams that work inside a tool - through a bridge patched into its code or
// through its API - from a sidecar next to it, governed by Atrium as the parent company. The group dashboard lists every
// subsidiary; a subsidiary's page shows its org chart, its charter (amended in the editor), its audit trail and runs, its
// reports and its setup. Text the team wrote (reports, escalations, run results) and data from the tool are untrusted:
// plain text through html`` only, under "Written by the subsidiary team (untrusted)". Mutating controls carry
// data-min-role; the server enforces every rule again (auth/policy.py, the approvals route, the guards).
// Routes: #/subsidiaries and #/subsidiaries/<tool id>[/overview|charter|activity|reports|setup].
import { del, get, post, put } from "../api.js";
import {
  BUDGETS, HUB_TOOLS, MODE_LABEL, POLICY_LABEL, RISK_TONE, UNTRUSTED, WORKING, budgetMeters, changesList, charterBody, charterChanges, classify, compact,
  conformanceFacts, defaultPolicy, filterAudit, flagInfo, floorMarker, grantLinks, kindGroup, kindLabel, meter, policyChoices, routingFacts,
  setupSteps, staffId, staffState, statusInfo, triggerText, untrustedBox,
} from "../subsidiary-model.js";
import {
  actions, appIcon, badge, builtinIcon, can, colorFor, confirmDialog, copyText, dateTime, emptyState, field, html, icon, modal, options,
  setHTML, timeAgo, toast,
} from "../ui.js";

const enc = encodeURIComponent;
const TABS = [["overview", "Overview"], ["charter", "Charter"], ["activity", "Activity"], ["reports", "Reports"], ["setup", "Setup"]];
const LIVE = ["subsidiary", "subsidiary_report", "approval", "agent", "agent_removed", "tool", "tool_removed"];
const TRIGGERS = [["", "Any trigger"], ["schedule", "Scheduled"], ["manual", "Run now"], ["task", "Task"], ["chat", "Atrium chat"], ["panel", "Panel (user-steered)"]];
const RISKS = [["", "Any risk"], ["read", "Read"], ["propose", "Propose"], ["write", "Write"], ["admin", "Admin"]];
const SCHEDULES = [["0", "No schedule"], ["60", "Every hour"], ["240", "Every 4 hours"], ["1440", "Once a day"]];
const STEP_ICON = { done: "check", current: "arrow", todo: "minus", failed: "x" };

const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const statusBadge = (status) => { const i = statusInfo(status); return html`<span class="badge ${i.tone}" title="${i.help}">${i.text}</span>`; };
const flagBadges = (flags) => (flags || []).map((f) => { const i = flagInfo(f); return html`<span class="badge ${i.tone}" title="${i.help}">${i.text}</span>`; });
const modeBadge = (mode) => html`<span class="badge accent" title="${mode === "bridge" ? "Works through a bridge patched into the tool's code"
  : "Works through the tool's API with its own read-only account; Atrium carries out its changes"}">${MODE_LABEL[mode] || mode}</span>`;
const when = (ts) => (ts ? html`<span title="${dateTime(ts)}">${timeAgo(ts)}</span>` : html`<span class="faint">-</span>`);
const short = (hash, n = 12) => (hash ? html`<span class="mono" title="${hash}">${String(hash).slice(0, n)}</span>` : html`<span class="faint">-</span>`);

function meterView(m) {
  return html`<div class="sub-meter"><div class="sub-meter-head"><span>${m.label}</span><span class="sub-tone-${m.tone}">${m.text}</span></div>
    <div class="sub-bar ${m.tone}" role="img" aria-label="${m.label}: ${m.text}${m.tone === "bad" ? " (used up)" : ""}"><span style="width:${m.limit ? m.pct : 0}%"></span></div></div>`;
}

/** Redraw `fn` keeping the focus (and caret) on the field that had it, by id. */
function keepFocus(fn) {
  const active = document.activeElement;
  const id = active?.id;
  const caret = active && "selectionStart" in active ? [active.selectionStart, active.selectionEnd] : null;
  fn();
  if (!id) return;
  const again = document.getElementById(id);
  if (again && again !== active) {
    again.focus({ preventScroll: true });
    if (caret && again.setSelectionRange) try { again.setSelectionRange(...caret); } catch { /* not a text field */ }
  }
}

const failed = (err) => { if (err.status !== 401) toast(err.message, "bad"); };

// ---------- giving a tool a team (the tool page's "Give it a team inside") ----------

const MODES = [
  ["auto", "Automatic", "A bridge when Atrium has the tool's source code, otherwise through its API."],
  ["bridge", "Bridge", "The Patch Agent adds a small bridge to the tool's code: typed actions, an \"Ask the team\" panel for its users and an events outbox. An administrator approves the patch."],
  ["sidecar_only", "API only", "No change to the tool: the team reads through its API with its own read-only account; Atrium itself carries out the changes people approve."],
];
const DESIGNERS = [
  ["auto", "Automatic", "An AI model designs the staff when one is ready, the templates otherwise."],
  ["templates", "Templates", "A front desk for the panel and a clerk with a standing task from your goals."],
  ["model", "AI model", "An AI model designs the staff from the tool's actions and your goals."],
];

/** "Give it a team inside" (operators): the goals, the mode and who designs the staff. When subsidiaries are switched off
 *  it says that an administrator must first allow them; a tool that has one links to it. */
export async function openGiveTeam({ toolId, toolName }) {
  let group;
  try {
    group = await get("/subsidiaries");
  } catch (err) {
    return failed(err);
  }
  const existing = group.subsidiaries.find((s) => s.tool_id === toolId);
  if (existing) {
    location.hash = `#/subsidiaries/${enc(toolId)}`;
    return toast(`${toolName} already has a team inside (${statusInfo(existing.status).text})`, "info");
  }
  if (!group.allowed) {
    const m = modal({
      title: `Give ${toolName} a team inside`, submit: null, cancel: "Close",
      body: html`<div class="notice warn">${icon("lock")}<div><b>Subsidiaries are switched off.</b>
          <p class="muted" style="margin-top:4px">An administrator must first allow subsidiaries: Settings &gt; Agent guardrails, "Allow subsidiaries
            (agent teams inside tools)". It is off by default; switching it on is logged and shows in compliance.</p></div></div>
        <p style="margin-top:12px" data-min-role="admin"><a href="#/settings/guardrails" data-act="to-settings">Open the agent guardrails</a></p>`,
    });
    actions(m.el, { "to-settings": () => { m.close(); location.hash = "#/settings/guardrails"; } });
    return;
  }
  const radios = (name, list) => html`<div class="stack sub-radios">${list.map(([value, title, text], i) => html`<label class="radio-card">
    <input type="radio" name="${name}" value="${value}" ${i === 0 ? "checked" : ""}><div><b>${title}</b><p class="muted">${text}</p></div></label>`)}</div>`;
  modal({
    title: `Give ${toolName} a team inside`, wide: true, minRole: "operator", submit: "Propose the team",
    body: html`<p class="muted" style="margin-bottom:12px">A small team of AI agents (a "subsidiary") works inside ${toolName} from a sidecar next to it. Atrium is the
        parent company: an administrator approves its charter (actions, staff, budgets, model), and every change the team wants to make in the tool
        waits for a person's approval. You proposed it, so another person approves its bridge and charter.</p>
      ${field(`What should the team do in ${toolName}?`, html`<textarea name="goals" rows="3" maxlength="2000" placeholder="e.g. Keep tickets triaged: set priorities, draft replies, answer users' questions"></textarea>`,
        "The goals become its mandate and the clerk's standing task. Up to 2000 characters.")}
      <div class="sub-two">
        <div><h3 class="sub-h">How it works inside the tool</h3>${radios("mode", MODES)}</div>
        <div><h3 class="sub-h">Who designs the staff</h3>${radios("designer", DESIGNERS)}</div></div>`,
    async onSubmit(data) {
      const body = { mode: String(data.get("mode") || "auto"), designer: String(data.get("designer") || "auto"), goals: String(data.get("goals") || "").trim() };
      const made = await post(`/tools/${enc(toolId)}/subsidiary`, body);
      toast(made.mode === "bridge" ? `Proposed: the Patch Agent prepares ${toolName}'s bridge patch` : `Proposed: ${toolName}'s charter is drafted`, "ok");
      location.hash = `#/subsidiaries/${enc(toolId)}`;
    },
  });
}

// ---------- the group dashboard ----------

function groupCard(s, tool) {
  const [tokens, approvals] = budgetMeters(s.usage);
  const open = s.open || {};
  return html`<section class="card sub-group-card" data-tool="${s.tool_id}">
    <header class="sub-card-head">${tool ? appIcon(tool, "sm") : builtinIcon("building", colorFor(s.tool_id), "sm")}
      <div style="min-width:0;flex:1"><h2><a href="#/subsidiaries/${enc(s.tool_id)}">${s.tool_name}</a></h2>
        <div class="row sub-badges">${modeBadge(s.mode)}${statusBadge(s.status)}${flagBadges(s.flags)}</div></div></header>
    ${s.status === "paused" && s.pause_reason ? html`<p class="sub-small faint sub-text">Paused: ${s.pause_reason}</p>` : ""}
    <dl class="sub-facts">
      <div><dt>Staff</dt><dd>${s.staff_count}</dd></div>
      <div><dt>Approvals waiting</dt><dd>${s.pending_approvals ? html`<a href="#/approvals">${s.pending_approvals}</a>` : "0"}</dd></div>
      <div><dt>Open escalations</dt><dd>${open.escalations ? html`<a href="#/subsidiaries/${enc(s.tool_id)}/reports" class="${open.critical ? "bad-text" : ""}">${open.escalations}${open.critical ? ` (${open.critical} critical)` : ""}</a>` : "0"}</dd></div>
      <div><dt>Last seen</dt><dd>${s.last_seen ? when(s.last_seen) : html`<span class="faint">${s.enrolled ? "never" : "not enrolled"}</span>`}</dd></div></dl>
    ${meterView(tokens)}${meterView(approvals)}</section>`;
}

async function renderGroup(el, ctx) {
  let data = null;
  const draw = () => keepFocus(() => {
    const subs = data.subsidiaries;
    const tools = Object.fromEntries(ctx.state.tools.map((t) => [t.id, t]));
    const critical = subs.reduce((n, s) => n + (s.open?.critical || 0), 0);
    const escalations = subs.reduce((n, s) => n + (s.open?.escalations || 0), 0);
    const working = subs.filter((s) => WORKING.includes(s.status)).length;
    const stat = (label, value, sub, iconName, extra = "", href = "") => {
      const inner = html`<div class="stat-icon">${icon(iconName)}</div><div><div class="label">${label}</div><div class="value">${value}</div>${sub ? html`<div class="sub">${sub}</div>` : ""}</div>`;
      return href ? html`<a class="card stat ${extra}" href="${href}">${inner}</a>` : html`<div class="card stat ${extra}">${inner}</div>`;
    };
    setHTML(el, html`
      <div class="page-head"><div><h1>Subsidiaries</h1><p class="muted">Agent teams that work inside a tool, from a sidecar next to it. Atrium is the parent company:
          an approved charter sets what each team may do, people approve every change it wants to make in its tool, and an operator can pause any team at once.</p></div>
        <div class="row"><a class="btn" href="#/tools">${icon("grid")}Give a tool a team</a>
          <button type="button" class="btn danger" data-act="pause-all" data-min-role="operator" ${working ? "" : "disabled"}>${icon("pause")}Pause all</button></div></div>
      ${data.allowed ? "" : html`<div class="notice warn" style="margin-bottom:16px">${icon("lock")}<div><b>Subsidiaries are switched off.</b>
        <span class="muted">Every team is paused and its sidecar gets no answers, tickets or grants. An administrator allows them in</span>
        <a href="#/settings/guardrails">Settings &gt; Agent guardrails</a>.</div></div>`}
      <div class="grid cols-5 sub-stats">
        ${stat("Subsidiaries", subs.length, working ? `${working} working` : "none working", "building")}
        ${stat("Approvals waiting", data.pending_approvals, "charters and in-tool changes", "checkCircle", data.pending_approvals ? "" : "", "#/approvals")}
        ${stat("Open escalations", escalations, critical ? `${critical} critical` : "from the teams' staff", "alert", critical ? "alarm" : "")}
        ${stat("Paused", subs.filter((s) => s.status === "paused").length, "resumed by an administrator", "pause")}</div>
      ${subs.length ? html`<div class="sub-grid">${subs.map((s) => groupCard(s, tools[s.tool_id]))}</div>`
        : html`<section class="card">${emptyState("building", "No subsidiaries yet", "Open a tool in Apps and choose \"Give it a team inside\": the Patch Agent prepares a bridge, or the team works through the tool's API.",
          html`<a class="btn primary" href="#/tools">${icon("grid")}Open Apps</a>`)}</section>`}
      ${data.archived ? html`<p class="faint sub-small" style="margin-top:12px">${plural(data.archived, "archived subsidiary", "archived subsidiaries")} kept for the audit trail.</p>` : ""}`);
  });
  const load = async () => {
    data = await get("/subsidiaries");
    if (el.isConnected) draw();
  };
  actions(el, {
    "pause-all"() {
      pauseDialog("Pause every subsidiary", "Every working team stops at once: no model answers, actions or runs; their pending in-tool changes are withdrawn and queued work is cancelled, so resuming releases no backlog. Bridges refuse calls once their last ticket expires. An administrator resumes each one.",
        "/subsidiaries/pause-all", (r) => { toast(r.paused?.length ? `Paused ${plural(r.paused.length, "subsidiary", "subsidiaries")}` : "Nothing was working", "ok"); load(); });
    },
  });
  await load();
  ctx.live(LIVE, () => load().catch(() => {}), 500);
}

function pauseDialog(title, text, path, done) {
  modal({
    title, submit: "Pause", minRole: "operator",
    body: html`<p class="muted" style="margin-bottom:12px">${text}</p>${field("Reason (optional)", html`<input name="reason" maxlength="500" placeholder="e.g. investigating a wrong priority change">`)}`,
    async onSubmit(data) { done(await post(path, { reason: String(data.get("reason") || "").trim() })); },
  });
}

// ---------- one subsidiary: the tabs ----------

function orgChart(sub, agents) {
  const recs = Object.fromEntries((agents || []).map((a) => [a.id, a]));
  const lead = recs[`tool:${sub.tool_id}`];
  const waiting = (sub.pending_approvals || []).map((p) => p.agent_id).filter(Boolean);
  const staff = sub.staff || [];
  const fresh = (sub.pending_members || []).filter((m) => !staff.some((s) => s.id === m.id));
  const desk = sub.charter?.panel?.enabled ? sub.charter.panel.desk : null;
  const member = (m) => {
    const s = staffState(m, recs[m.id], waiting, sub);
    const scope = m.scope || {};
    return html`<li><div class="sub-node">${builtinIcon("bot", colorFor(m.id), "sm")}
      <div class="sub-node-text"><b><a href="#/agents/${enc(m.id)}/settings">${m.name}</a></b><div class="faint">${m.title}${desk === m.id ? " - answers the panel" : ""}</div>
        <div class="faint sub-small">${plural((scope.actions || []).length, "action")}${(scope.hub_tools || []).length ? `, ${plural(scope.hub_tools.length, "hub tool")}` : ""}${m.schedule_minutes ? ` - every ${m.schedule_minutes} min` : ""}</div></div>
      <span class="badge ${s.tone}" title="${s.why || ""}">${s.state}</span></div>${s.why ? html`<div class="sub-why faint">${s.why}</div>` : ""}</li>`;
  };
  return html`<section class="card"><header><h2>Organisation</h2><span class="faint sub-small">live</span></header>
    <ol class="sub-org" aria-label="Organisation of the ${sub.tool_name} subsidiary">
      <li><div class="sub-node parent">${builtinIcon("building", "#4f46e5", "sm")}<div class="sub-node-text"><b>Atrium</b><div class="faint">Parent company: charter, approvals, budgets, audit, pause and stop</div></div></div>
        <ol><li><div class="sub-node">${builtinIcon("grid", colorFor(sub.tool_id), "sm")}<div class="sub-node-text"><b>${lead?.name || `${sub.tool_name} Supervisor`}</b>
            <div class="faint">Managing director: requests the team's approvals and settles their decisions</div></div>${lead ? html`<span class="badge">${lead.status}</span>` : ""}</div>
          ${staff.length || fresh.length ? html`<ol>${staff.map(member)}${fresh.map((m) => html`<li><div class="sub-node pending">${builtinIcon("bot", "var(--surface-2)", "sm")}
              <div class="sub-node-text"><b>${m.name}</b><div class="faint">${m.title}</div></div><span class="badge warn">created when the charter is approved</span></div></li>`)}</ol>`
            : html`<p class="faint sub-small sub-none">No staff yet: they are created when an administrator approves the charter.</p>`}</li></ol></li></ol></section>`;
}

function overview(sub, agents) {
  const usage = sub.usage || {};
  const budgets = sub.charter?.budgets || {};
  const info = sub.sidecar;
  const ping = info?.bridge_ping;
  const keyStaged = (sub.keys || []).some((k) => k.status === "next");
  const runtime = info?.runtime || {};
  return html`<div class="sub-cols">
    <div class="stack">
      ${orgChart(sub, agents)}
      <section class="card"><header><h2>Today</h2><span class="faint sub-small">UTC day ${usage.day || ""}</span></header>
        ${budgetMeters(usage).map(meterView)}
        ${meterView(meter(usage.panel_questions, budgets.panel_questions_per_day, "Panel questions today"))}
        <p class="faint sub-small" style="margin-top:8px">${plural(usage.model_calls || 0, "model call")}, ${plural(usage.runs || 0, "run")}, ${plural(usage.denied || 0, "refused request")} today.</p></section>
    </div>
    <div class="stack">
      <section class="card"><header><h2>Status</h2></header><dl class="kv">
        <dt>Status</dt><dd>${statusBadge(sub.status)} <span class="faint">${statusInfo(sub.status).help}</span></dd>
        <dt>Flags</dt><dd>${(sub.flags || []).length ? html`<ul class="sub-flag-list">${sub.flags.map((f) => html`<li>${flagBadges([f])} ${flagInfo(f).help}</li>`)}</ul>` : html`<span class="faint">none</span>`}</dd>
        <dt>Mode</dt><dd>${modeBadge(sub.mode)}</dd>
        <dt>Charter</dt><dd>${sub.charter_version ? html`version ${sub.charter_version}${sub.charter_approved_by ? html` - last approved by ${sub.charter_approved_by} ${when(sub.charter_approved_at)}` : ""}`
          : html`<span class="faint">none in force</span>`}${sub.pending_charter_approval ? html` - <a href="#/approvals">a charter waits for approval</a>` : ""}</dd>
        <dt>Approvals waiting</dt><dd>${(sub.pending_approvals || []).length ? html`<a href="#/approvals">${plural(sub.pending_approvals.length, "approval")}</a>` : html`<span class="faint">none</span>`}</dd>
        <dt>Proposed</dt><dd>by ${sub.created_by || "-"} ${when(sub.created_at)}</dd>
        ${sub.goals ? html`<dt>Goals</dt><dd class="sub-text">${sub.goals}</dd>` : ""}</dl></section>
      <section class="card"><header><h2>Sidecar</h2><span class="faint sub-small">as the sidecar reports it (claimed)</span></header>
        ${info ? html`<dl class="kv">
          <dt>Version</dt><dd class="mono">${info.version || "-"}</dd>
          <dt>Key</dt><dd class="mono">${info.key_fingerprint}</dd>
          <dt>Runtime</dt><dd>${runtime.container === true ? "in a container" : runtime.container === false ? html`<span class="warn-text">not in a container</span>` : "-"}${runtime.uid !== undefined ? ` - uid ${runtime.uid}` : ""}${runtime.uid === 0 ? html` <span class="warn-text">(root)</span>` : ""}${runtime.hostname_hash ? html` - host ${short(runtime.hostname_hash, 10)}` : ""}</dd>
          <dt>Last seen</dt><dd>${when(info.last_seen)}${(sub.flags || []).includes("offline") ? html` ${badge("offline", "warn")}` : ""}</dd>
          <dt>Clock skew</dt><dd class="${Math.abs(info.clock_skew || 0) > 60 ? "warn-text" : ""}">${info.clock_skew || 0} s</dd>
          <dt>Health</dt><dd>${info.health?.status ? badge(info.health.status, info.health.status === "ok" ? "ok" : info.health.status === "failing" ? "bad" : "warn") : "-"}${info.health?.runs ? ` - ${plural(info.health.runs, "run")} under way` : ""}</dd>
          <dt>Enrolled</dt><dd>${when(info.enrolled_at)}</dd></dl>`
          : html`<p class="muted sub-small">Not enrolled yet.${sub.enrollment_pending ? " A one-time code was issued: start the sidecar with it." : " An administrator issues a one-time enrollment code (Setup)."}</p>`}</section>
      ${sub.mode === "bridge" ? html`<section class="card"><header><h2>Bridge</h2></header>
        ${sub.bridge ? html`<dl class="kv">
          <dt>Contract</dt><dd class="mono">${sub.bridge.contract}</dd>
          <dt>Core</dt><dd>${sub.bridge.vendored_core ? badge("vendored", "ok") : badge("written by an AI model", "warn")} <span class="mono">${sub.bridge.core}</span> <span class="faint">(${sub.bridge.stack})</span></dd>
          <dt>Manifest</dt><dd>${short(sub.bridge.manifest_sha256, 16)} <span class="faint">${plural((sub.bridge.manifest?.actions || []).length, "action")}</span></dd>
          <dt>Last ping</dt><dd>${ping ? html`${ping.ok === false ? badge("failed", "bad") : badge("ok", "ok")}${ping.manifest_sha256 && ping.manifest_sha256 !== sub.bridge.manifest_sha256 ? html` ${badge("manifest differs", "bad")}` : ""}${ping.error ? html` <span class="faint sub-text">${ping.error}</span>` : ""}` : html`<span class="faint">none yet</span>`}</dd>
          ${sub.bridge.bridge_url ? html`<dt>Served at</dt><dd class="mono sub-text">${sub.bridge.bridge_url}</dd>` : ""}</dl>`
          : html`<p class="muted sub-small">The bridge patch is not applied yet: an administrator approves it in <a href="#/approvals">Approvals</a>.</p>`}</section>`
        : html`<section class="card"><header><h2>API access</h2></header><p class="muted sub-small">The team reads ${sub.tool_name} through its API with its own read-only account
          (${sub.has_credential ? "entered, encrypted" : html`<span class="warn-text">not entered yet</span>`}); Atrium's ${sub.tool_name} Supervisor carries out the changes people approve, with the hub's connection.</p></section>`}
      <section class="card" data-min-role="admin"><header><h2>Administration</h2></header>
        <p class="muted sub-small" style="margin-bottom:10px">A new enrollment revokes the sidecar's token (the team goes back to probation); rotating the key stages a second key in bridge.env, then retires the old one.</p>
        <div class="row">
          <button type="button" class="btn" data-act="enroll" ${["stopped", "archived"].includes(sub.status) ? "disabled" : ""}>${icon("key")}New enrollment</button>
          ${sub.mode === "bridge" ? html`<button type="button" class="btn" data-act="${keyStaged ? "finish-key" : "rotate-key"}" ${["stopped", "archived"].includes(sub.status) ? "disabled" : ""}>${icon("refresh")}${keyStaged ? "Finish the key rotation" : "Rotate the key"}</button>` : ""}
          <button type="button" class="btn" data-act="conformance" ${sub.sidecar || sub.mode === "bridge" ? "" : "disabled"}>${icon("shield")}Re-run conformance</button></div></section>
    </div></div>`;
}

/** Names of the staff (existing and proposed) and of the model providers, for labels. */
function names(sub, providers = []) {
  return {
    ...Object.fromEntries((sub.pending_members || []).map((m) => [m.id, m.name])),
    ...Object.fromEntries((sub.staff || []).map((m) => [m.id, m.name])),
    ...Object.fromEntries(providers.map((p) => [p.id, p.label])),
  };
}

function charterView(sub, providers) {
  const c = sub.charter || sub.pending_charter;
  if (!c) {
    return html`<section class="card">${emptyState("file", "No charter yet", sub.mode === "bridge" ? "The charter is drafted with the bridge patch; an administrator approves it once the bridge passed conformance."
      : "The charter is drafted from the tool's API; an administrator approves it once the sidecar passed its checks.")}</section>`;
  }
  const label = names(sub, providers);
  const declared = Object.fromEntries((sub.bridge?.manifest?.actions || []).map((a) => [a.id, a.risk]));
  const users = (id) => Object.entries(c.staff || {}).filter(([, s]) => (s.actions || []).includes(id)).map(([sid]) => label[sid] || sid);
  const draftOnly = !sub.charter;
  const pending = sub.pending_charter && sub.charter && sub.pending_charter.version !== sub.charter.version ? sub.pending_charter : null;
  const history = sub.charter_history || [];
  const routing = routingFacts(c.model_routing, providers);
  return html`
    ${draftOnly ? html`<div class="notice warn sub-gap">${icon("file")}<div><b>Draft charter v${c.version}: not in force yet.</b>
      <span class="muted">${sub.pending_charter_approval ? html`It waits for an administrator in <a href="#/approvals">Approvals</a>.` : "Atrium asks an administrator to approve it once conformance passed."}</span></div></div>` : ""}
    ${pending ? html`<div class="notice warn sub-gap">${icon("file")}<div style="min-width:0"><b>Charter v${pending.version} ${sub.pending_charter_approval ? html`waits for approval in <a href="#/approvals">Approvals</a>` : "is drafted (not requested)"}.</b>
      <div class="muted sub-small">It widens the charter in force: ${classify(sub.charter, pending).join("; ") || "no widening"}.</div>
      <details style="margin-top:6px"><summary class="sub-summary">Every change</summary>${changesList(charterChanges(sub.charter, pending, label))}</details></div></div>` : ""}
    <section class="card sub-gap"><header><h2>Mandate</h2><span class="row" style="gap:6px">${draftOnly ? badge("draft", "warn") : badge(`version ${c.version}`, "")}
        <button type="button" class="btn sm" data-act="amend" data-min-role="admin">${icon("edit")}Amend</button></span></header>
      <p class="sub-text sub-mandate">${c.mandate || html`<span class="faint">No mandate.</span>`}</p>
      <p class="faint sub-small" style="margin-top:6px">Part of every prompt the staff think with; Atrium composes the prompt, never the sidecar.</p></section>
    <section class="card flush sub-gap"><header><h2>Actions</h2><span class="faint sub-small">${plural((c.actions || []).filter((a) => a.policy !== "forbidden").length, "usable action")}</span></header>
      <div class="table-wrap"><table class="table compact sub-actions"><thead><tr><th>Action</th><th>Risk</th><th>Category</th><th>Reversible</th><th>External effect</th>
        <th>On behalf of the asker</th><th>Policy</th><th>Staff</th></tr></thead><tbody>
        ${(c.actions || []).map((a) => {
          const floor = floorMarker(a, declared[a.id]);
          return html`<tr class="${a.policy === "forbidden" ? "off" : ""}"><td><span class="mono">${a.id}</span><div class="faint sub-small">${a.title}</div></td>
            <td>${badge(a.risk, RISK_TONE[a.risk])}${floor ? html`<div class="sub-small warn-text" title="${floor}">${icon("arrow")} floor</div>` : ""}</td>
            <td>${a.category}</td><td>${a.reversible ? "yes" : "no"}</td><td>${a.external_effect ? html`<span class="warn-text">yes</span>` : "no"}</td><td>${a.on_behalf_of ? "yes" : "no"}</td>
            <td>${badge(POLICY_LABEL[a.policy] || a.policy, a.policy === "auto" ? "warn" : a.policy === "forbidden" ? "" : a.policy === "approval" ? "info" : "ok")}</td>
            <td class="sub-small">${users(a.id).join(", ") || html`<span class="faint">nobody</span>`}</td></tr>`;
        })}</tbody></table></div></section>
    <div class="sub-cols sub-gap">
      <section class="card"><header><h2>Staff scopes</h2></header>
        ${Object.keys(c.staff || {}).length ? html`<div class="stack" style="gap:10px">${Object.entries(c.staff).map(([id, s]) => html`<div class="sub-scope">
          <b>${label[id] || id}</b> <span class="mono faint sub-small">${id}</span>${c.panel?.enabled && c.panel.desk === id ? html` ${badge("front desk", "info")}` : ""}
          <div class="tag-list" style="margin-top:4px">${(s.actions || []).map((a) => html`<span class="badge mono">${a}</span>`)}${(s.actions || []).length ? "" : html`<span class="faint sub-small">no actions</span>`}</div>
          ${(s.hub_tools || []).length ? html`<div class="sub-small faint" style="margin-top:4px">Hub tools: ${s.hub_tools.join(", ")}</div>` : ""}</div>`)}</div>`
          : html`<p class="faint sub-small">No staff.</p>`}</section>
      <section class="card"><header><h2>Model routing</h2></header>
        ${routing.length ? html`<ul class="sub-routing">${routing.map((r) => html`<li class="${r.third ? "third" : "local"}">${icon(r.third ? "cloud" : "server")}<span>${r.text}${r.default ? html` ${badge("default", "")}` : ""}</span></li>`)}</ul>`
          : html`<div class="notice warn">${icon("alert")}<div class="sub-small">No AI model is allowed: the staff cannot think until an administrator allows one.</div></div>`}
        <h3 class="sub-h" style="margin-top:14px">Panel and events</h3>
        <p class="sub-small">${sub.mode !== "bridge" ? "API-only teams have no panel inside the tool: people ask the team from Atrium."
          : c.panel?.enabled ? html`"Ask the team" is on inside ${sub.tool_name}; ${label[c.panel.desk] || c.panel.desk} answers.` : `"Ask the team" is off.`}
          ${sub.mode === "bridge" ? (c.events?.relay ? " The tool's events are relayed to Atrium's tool bus." : " Tool events are not relayed.") : ""}</p>
        <h3 class="sub-h" style="margin-top:14px">Data</h3>
        <p class="sub-small">${c.data?.transcripts ? "Transcripts are kept (encrypted)" : "No transcripts are kept (hashes and lengths only)"}; reports are kept ${c.data?.report_retention_days || 180} days.</p></section>
    </div>
    <section class="card sub-gap"><header><h2>Budgets</h2><span class="faint sub-small">a day in UTC unless said otherwise</span></header>
      <dl class="sub-budgets">${BUDGETS.map(([k, l]) => html`<div><dt>${l}</dt><dd>${compact(c.budgets?.[k] ?? 0)}</dd></div>`)}</dl></section>
    <section class="card"><header><h2>Versions</h2></header>
      ${history.length ? html`<ol class="sub-history">${history.map((h, i) => {
        const prev = history[i + 1]?.charter || null;
        return html`<li><div class="row" style="gap:6px"><b>Version ${h.version}</b>${badge(h.narrowing ? "narrowed" : "approved", h.narrowing ? "" : "ok")}
            <span class="faint sub-small">${h.narrowing ? `by ${h.applied_by || "-"}` : `approved by ${h.approved_by || h.applied_by || "-"}`} ${dateTime(h.applied_at)}</span></div>
          ${prev || i === history.length - 1 ? html`<details><summary class="sub-summary">${prev ? "Changes from the version before" : "First version recorded"}</summary>
            ${prev ? changesList(charterChanges(prev, h.charter, label)) : html`<p class="faint sub-small">${h.version > 1 ? "Earlier versions were not recorded." : "The first charter of this subsidiary."}</p>`}</details>` : ""}</li>`;
      })}</ol>` : html`<p class="faint sub-small">${sub.charter ? `Version ${sub.charter_version} is in force; no earlier versions were recorded.` : "No version is in force yet."}</p>`}</section>`;
}

function runsTable(runs, label) {
  if (!runs.length) return html`<p class="faint sub-small" style="padding:0 16px 16px">No runs yet.</p>`;
  return html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Started</th><th>Staff</th><th>Trigger</th><th>Outcome</th><th>Read from the tool</th>
      <th title="Passages the injection heuristics flagged">Flags</th><th>Tokens</th><th>Calls</th></tr></thead><tbody>
    ${runs.map((r) => html`<tr><td class="sub-nowrap">${when(r.started_at)}</td><td>${label[r.agent_id] || r.agent_id}</td>
      <td>${r.trigger === "panel" ? badge("panel: user-steered", "warn") : triggerText(r.trigger, r.person)}</td>
      <td>${r.outcome ? badge(r.outcome, ["answered", "done"].includes(r.outcome) ? "ok" : ["failed", "budget", "tool_unavailable", "expired"].includes(r.outcome) ? "bad" : "") : r.ended_at ? "-" : badge("running", "info")}</td>
      <td class="sub-small">${r.tainted ? html`${badge("tainted", "warn")} <span class="mono">${(r.taint || []).join(", ")}</span>` : html`<span class="faint">nothing</span>`}</td>
      <td>${r.injection_flags ? badge(String(r.injection_flags), "bad") : "0"}</td><td class="sub-nowrap">${compact(r.tokens_in)} / ${compact(r.tokens_out)}</td>
      <td class="sub-nowrap">${r.model_calls} model, ${r.tool_calls} tool</td></tr>`)}</tbody></table></div>`;
}

function auditRows(entries, label, detail) {
  const grants = grantLinks(entries);
  return html`<div class="table-wrap"><table class="table compact sub-audit"><thead><tr><th>#</th><th>When</th><th>Seen</th><th>What</th><th>Staff</th><th>Action</th><th>Links</th>
      ${detail ? html`<th>Detail</th>` : ""}</tr></thead><tbody>
    ${entries.slice().reverse().map((e) => {
      const g = e.grant_jti ? grants[e.grant_jti] : null;
      return html`<tr id="audit-${e.seq}" tabindex="-1"><td class="mono">${e.seq}</td><td class="sub-nowrap">${when(e.ts)}</td>
        <td>${e.origin === "observed" ? badge("observed", "ok") : badge("claimed", "")}</td>
        <td><b>${kindLabel(e.kind)}</b>${e.outcome ? html` ${badge(e.outcome, "")}` : ""}</td>
        <td>${e.agent_id ? label[e.agent_id] || e.agent_id : html`<span class="faint">-</span>`}</td>
        <td class="mono sub-small">${e.action_id || ""}</td>
        <td class="sub-small">${e.approval_id && e.approval_id !== "auto" ? html`<a href="#/approvals" title="Approval ${e.approval_id}">approval ${e.approval_id}</a>` : e.approval_id === "auto" ? badge("no approval", "warn") : ""}
          ${g ? html`<div>grant <span class="mono" title="${e.grant_jti}">${String(e.grant_jti).slice(0, 8)}</span>${e.kind === "grant.issue" && g.result
            ? html` - <button type="button" class="linkish" data-act="jump" data-seq="${g.result}">result #${g.result}</button>`
            : e.kind === "grant.result" && g.issued ? html` - <button type="button" class="linkish" data-act="jump" data-seq="${g.issued}">issued #${g.issued}</button>` : ""}</div>` : ""}
          ${e.run_id ? html`<div class="faint mono">${e.run_id}</div>` : ""}</td>
        ${detail ? html`<td class="sub-small sub-detail">${e.taint?.length ? html`<div>read: <span class="mono">${e.taint.join(", ")}</span></div>` : ""}${Object.entries(e.detail || {}).map(([k, v]) => html`<div><span class="faint">${k}:</span> ${typeof v === "string" ? v : JSON.stringify(v)}</div>`)}</td>` : ""}</tr>`;
    })}</tbody></table></div>`;
}

function activityView(sub, audit, runs, f, verify, providers) {
  const label = names(sub, providers);
  const detail = can("operator");
  const entries = audit?.entries || [];
  const risks = Object.fromEntries((sub.charter?.actions || []).map((a) => [a.id, a.risk]));
  const triggers = Object.fromEntries((runs || []).map((r) => [r.id, r.trigger]));
  const shown = filterAudit(entries, f, { risks, triggers });
  const kinds = [...new Set(entries.map((e) => kindGroup(e.kind)))].sort();
  const staffIds = [...new Set(entries.map((e) => e.agent_id).filter(Boolean))];
  const head = audit?.head || {};
  return html`
    <section class="card flush sub-gap"><header><h2>Runs</h2><span class="faint sub-small">the newest ${runs?.length || 0}</span></header>${runsTable(runs || [], label)}</section>
    <section class="card flush"><header><h2>Audit trail</h2>
        <span class="row" style="gap:8px"><span class="sub-small faint" title="Each entry holds the hash of the one before it">${icon("link")} chain head #${head.seq || 0} ${short(head.hash, 10)}</span>
          <button type="button" class="btn sm" data-act="verify" data-min-role="operator">${icon("shield")}Verify</button></span></header>
      <div style="padding:0 16px">
        ${verify ? html`<div class="notice ${verify.ok ? "ok" : "bad"} sub-gap">${icon(verify.ok ? "check" : "alert")}<div><b>${verify.ok ? `The chain is intact: ${plural(verify.entries, "entry", "entries")}.` : `The chain is broken: ${plural(verify.problems.length, "problem")}.`}</b>
          ${verify.ok ? "" : html`<ul class="sub-small">${verify.problems.map((p) => html`<li>#${p.seq}: ${p.problem}</li>`)}</ul>`}</div></div>` : ""}
        <p class="faint sub-small">"Observed" entries are what Atrium saw itself; "claimed" ones the sidecar reported. ${detail ? "" : "Operators also see each entry's detail."}</p>
        <div class="row filters sub-filters">
          <select id="sub-f-kind" class="input-sm" data-filter="kind" aria-label="Kind">${options([["", "Every kind"], ...kinds.map((k) => [k, k.replace(/_/g, " ")])], f.kind)}</select>
          <select id="sub-f-staff" class="input-sm" data-filter="staff" aria-label="Staff member">${options([["", "Every staff member"], ...staffIds.map((id) => [id, label[id] || id])], f.staff)}</select>
          <select id="sub-f-risk" class="input-sm" data-filter="risk" aria-label="Risk">${options(RISKS, f.risk)}</select>
          <select id="sub-f-trigger" class="input-sm" data-filter="trigger" aria-label="Trigger">${options(TRIGGERS, f.trigger)}</select>
          <span class="spacer"></span><span class="faint sub-small">${shown.length} of ${plural(entries.length, "entry", "entries")}</span></div></div>
      ${shown.length ? auditRows(shown, label, detail) : html`<p class="faint sub-small" style="padding:0 16px 16px">${entries.length ? "Nothing matches the filters." : "No entries yet."}</p>`}
      ${audit?.before ? html`<div style="padding:0 16px 16px"><button type="button" class="btn sm" data-act="older">${icon("clock")}Load older entries</button></div>` : ""}</section>`;
}

function reportsView(sub, data, all, providers) {
  const label = names(sub, providers);
  const items = (data?.reports || []).filter((r) => all || r.status === "open");
  const sevTone = { critical: "bad", warning: "warn", info: "" };
  return html`<div class="row sub-gap"><div class="seg" role="group" aria-label="Which reports">
      <button type="button" class="${all ? "" : "active"}" data-act="reports-open" aria-pressed="${all ? "false" : "true"}">Open</button>
      <button type="button" class="${all ? "active" : ""}" data-act="reports-all" aria-pressed="${all ? "true" : "false"}">All</button></div>
    <span class="spacer"></span>${data?.texts ? "" : html`<span class="faint sub-small">Viewers see the titles; operators read the text.</span>`}</div>
    ${items.length ? html`<div class="stack">${items.map((r) => html`<section class="card sub-report ${r.kind}">
      <header><div style="min-width:0"><div class="row" style="gap:6px">${badge(r.kind, r.kind === "escalation" ? sevTone[r.severity] || "warn" : "info")}${badge(r.severity, sevTone[r.severity] ?? "")}${badge(r.status, r.status === "open" ? "warn" : "")}</div>
          <h3 class="sub-text" style="margin-top:6px">${r.title}</h3>
          <div class="faint sub-small">${label[r.agent_id] || r.agent_id} - ${when(r.created_at)}${r.handled_by ? ` - handled by ${r.handled_by}` : ""}</div></div></header>
      ${data.texts ? html`${untrustedBox(r.text)}
        ${(r.findings || []).length ? html`<div class="sub-untrusted"><div class="sub-untrusted-label">Findings - ${UNTRUSTED}</div>
          <ul class="sub-findings">${r.findings.map((x) => html`<li>${badge(x.severity, { critical: "bad", high: "warn", medium: "info" }[x.severity] ?? "")} <span class="sub-text">${x.title}</span>${x.evidence ? html`<div class="faint sub-text">${x.evidence}</div>` : ""}</li>`)}</ul></div>` : ""}` : ""}
      ${r.status === "open" ? html`<div class="row" style="margin-top:10px" data-min-role="operator">
        <button type="button" class="btn sm" data-act="report-task" data-id="${r.id}">${icon("send")}Give the team a task</button>
        <button type="button" class="btn sm" data-act="report-promote" data-id="${r.id}">${icon("flag")}Promote to a risk</button>
        <button type="button" class="btn sm" data-act="report-close" data-id="${r.id}">${icon("check")}Close</button></div>` : ""}</section>`)}</div>`
      : html`<section class="card">${emptyState("file", all ? "No reports yet" : "No open reports", "The staff file reports and escalate what they cannot do; escalations also reach the Tool Supervisor.")}</section>`}`;
}

function bridgeEnv(sub) {
  const panel = sub.bridge?.manifest?.panel?.enabled ? "on" : "off";
  return [`ATRIUM_BRIDGE_KEYS=${sub.bridge_keys || ""}`, `ATRIUM_TOOL_ID=${sub.tool_id}`, `ATRIUM_SUBSIDIARY_ID=${sub.id}`, `ATRIUM_PANEL=${panel}`].join("\n");
}

function setupView(sub, credential) {
  const steps = setupSteps(sub);
  const conf = conformanceFacts(sub.conformance);
  const bundle = sub.bundle || {};
  const admin = can("admin");
  const closed = ["stopped", "archived"].includes(sub.status);
  const stepAction = (s) => {
    if (s.state === "done" || closed) return "";
    if (s.id === "patch" || (s.id === "charter" && sub.pending_charter_approval)) return html`<a class="btn sm" href="#/approvals">${icon("checkCircle")}Approvals</a>`;
    if (s.id === "enroll" && s.state === "current") return html`<button type="button" class="btn sm" data-act="enroll" data-min-role="admin">${icon("key")}New enrollment</button>`;
    if (s.id === "conformance" && s.state !== "todo") return html`<button type="button" class="btn sm" data-act="conformance" data-min-role="admin">${icon("shield")}Run it again</button>`;
    return "";
  };
  return html`<section class="card sub-gap"><header><h2>Setup</h2></header>
      <ol class="sub-steps">${steps.map((s) => html`<li class="${s.state}"><span class="sub-step-ico" aria-hidden="true">${icon(STEP_ICON[s.state] || "minus")}</span>
        <div class="sub-step-text"><b>${s.title}</b> <span class="sr-only">(${s.state})</span>${badge(s.state === "current" ? "next" : s.state, s.state === "done" ? "ok" : s.state === "failed" ? "bad" : s.state === "current" ? "info" : "")}
          <div class="faint sub-small">${s.text}</div></div>${stepAction(s)}</li>`)}</ol></section>
    <section class="card flush sub-gap"><header><h2>Conformance</h2>${conf ? html`<span class="faint sub-small">${conf.ok ? "passed" : "failed"} - ${conf.originText} - ${when(conf.at)}</span>` : ""}</header>
      ${conf ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Check</th><th>What it proves</th><th>Result</th><th>Answer</th><th>Detail</th></tr></thead><tbody>
          ${conf.rows.map((r) => html`<tr><td class="mono">${r.id}</td><td>${r.title}</td><td>${r.ok ? badge("passed", "ok") : badge("failed", "bad")}</td>
            <td class="mono sub-small">${r.status ?? ""}${r.code ? ` ${r.code}` : ""}</td><td class="sub-small sub-text">${r.detail}</td></tr>`)}</tbody></table></div>
          ${conf.observed ? "" : html`<p class="faint sub-small" style="padding:8px 16px 16px">Claimed: the sidecar ran the vectors because Atrium could not reach the bridge. Compliance control HB-AC-8 shows it as partial.</p>`}`
        : html`<p class="faint sub-small" style="padding:0 16px 16px">Not run yet: it runs once the sidecar has enrolled.</p>`}</section>
    <div class="sub-cols">
      <section class="card"><header><h2>Deployment bundle</h2></header>
        <dl class="kv"><dt>Folder</dt><dd class="mono sub-text">${bundle.dir || "-"}</dd>
          <dt>Sidecar</dt><dd><span class="mono sub-text">${bundle.sidecar_dir || "-"}</span>${(bundle.sidecar_files || []).length ? html`<div class="tag-list" style="margin-top:4px">${bundle.sidecar_files.map((f) => html`<span class="badge mono">${f}</span>`)}</div>`
            : html`<div class="faint sub-small">Written with the first enrollment${sub.mode === "bridge" ? " (or when the bridge patch is applied)" : ""}.</div>`}</dd></dl>
        <p class="faint sub-small" style="margin-top:8px">Run the sidecar as its own container or OS user, never as Atrium's account; its README.md in that folder has the steps. It connects out to Atrium only and listens on no port.</p>
        ${sub.mode === "bridge" ? html`<h3 class="sub-h" style="margin-top:14px">bridge.env ${bundle.bridge_env ? badge("written", "ok") : badge("not written yet", "warn")}</h3>
          <p class="faint sub-small">Public values (no secret): the tool loads them at start.</p><pre class="code wrap sub-env">${bridgeEnv(sub)}</pre>` : ""}</section>
      <section class="card"><header><h2>Signing keys</h2></header>
        ${(sub.keys || []).length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Key</th><th>Fingerprint</th><th>Status</th><th>Created</th></tr></thead><tbody>
          ${sub.keys.map((k) => html`<tr><td class="mono">${k.kid}</td><td class="mono sub-small sub-text">${k.fingerprint}</td><td>${badge(k.status, k.status === "current" ? "ok" : k.status === "next" ? "info" : "")}</td><td>${when(k.created_at)}</td></tr>`)}</tbody></table></div>`
          : html`<p class="faint sub-small">No keys.</p>`}
        <p class="faint sub-small" style="margin-top:8px">Atrium signs tickets and grants with these; the bridge holds only the public keys.</p></section>
    </div>
    ${sub.mode === "sidecar_only" ? html`<section class="card sub-gap"><header><h2>Dedicated read-only credential</h2>${sub.has_credential ? badge("entered", "ok") : badge("not entered", "warn")}</header>
      <p class="muted sub-small" style="margin-bottom:10px">Create a separate read-only account in ${sub.tool_name} for the team: it is encrypted, bound to the tool's address and only ever given to the
        sidecar, which keeps it in memory. It must differ from the hub's own connection credential. When you stop the team, revoke that account in the tool.</p>
      ${admin && !closed ? credentialForm(credential, sub.has_credential) : html`<p class="faint sub-small">An administrator enters it.</p>`}</section>` : ""}`;
}

function credentialForm(credential, has) {
  if (!credential) return html`<p class="faint sub-small">The tool has no connection to read its fields from: set one up in the tool's Connection tab.</p>`;
  return html`<form class="sub-cred" data-form="credential" autocomplete="off">
    ${credential.fields.length ? html`<div class="form-grid">${credential.fields.map((f) => field(f.label + (f.required ? "" : " (optional)"), html`<input type="password" name="${f.name}" autocomplete="new-password" ${f.required ? "required" : ""}>`, f.help || ""))}</div>`
      : html`<p class="faint sub-small">The ${credential.title} connector has no secret fields.</p>`}
    <div class="row"><button type="submit" class="btn primary">${icon("key")}${has ? "Replace the credential" : "Save the credential"}</button>
      ${has ? html`<button type="button" class="btn danger" data-act="credential-clear">${icon("trash")}Clear it</button>` : ""}</div></form>`;
}

/** The secret fields of the tool's connector (the dedicated credential has the same ones as the hub's connection). */
async function credentialFields(toolId) {
  const cls = (await get(`/tools/${enc(toolId)}/connection`))?.connector;
  if (!cls) return null;
  return { title: cls.title, fields: (cls.fields || []).filter((f) => f.kind === "secret").map((f) => ({ name: f.name, label: f.label || f.name, required: !!f.required, help: f.help || "" })) };
}

// ---------- the charter editor (Amend) ----------

function readDraft(form, base, catalog, members) {
  const q = (sel) => form.querySelector(sel);
  const included = [];
  for (const a of catalog) {
    const policy = q(`[data-policy="${CSS.escape(a.id)}"]`)?.value;
    if (policy) included.push({ ...a, policy });
  }
  const ids = included.map((a) => a.id);
  const staff = {};
  for (const id of [...Object.keys(base.staff || {}), ...members.map((m) => m.id)]) {
    if (q(`[data-remove="${CSS.escape(id)}"]`)?.checked) continue;
    staff[id] = {
      actions: ids.filter((aid) => q(`[data-scope="${CSS.escape(id)}"][data-action="${CSS.escape(aid)}"]`)?.checked),
      hub_tools: HUB_TOOLS.map(([t]) => t).filter((t) => q(`[data-hub="${CSS.escape(id)}"][data-tool="${t}"]`)?.checked),
    };
  }
  const allowed = [...form.querySelectorAll("[data-provider]")].filter((x) => x.checked).map((x) => x.dataset.provider);
  const wanted = q('[name="default_provider"]')?.value || "";
  const budgets = { ...(base.budgets || {}) };
  for (const [key] of BUDGETS) {
    const text = String(q(`[data-budget="${key}"]`)?.value ?? "").trim();
    const v = Number(text);
    if (text && Number.isInteger(v) && v >= 0) budgets[key] = v; // an emptied field keeps the budget in force
  }
  const panelBox = q('[name="panel_enabled"]');
  const enabled = panelBox ? panelBox.checked : !!base.panel?.enabled;
  const desk = q('[name="desk"]')?.value || base.panel?.desk || null;
  const days = Number(q('[name="retention"]')?.value);
  return {
    ...base, mandate: q('[name="mandate"]')?.value ?? base.mandate, actions: included, staff,
    model_routing: { allowed, default: allowed.includes(wanted) ? wanted : allowed[0] || null }, budgets,
    panel: { enabled, desk: enabled ? (desk in staff ? desk : Object.keys(staff)[0] || null) : base.panel?.desk || null },
    events: { relay: q('[name="relay"]') ? q('[name="relay"]').checked : !!base.events?.relay },
    data: { transcripts: !!q('[name="transcripts"]')?.checked, report_retention_days: Number.isInteger(days) && days > 0 ? days : base.data?.report_retention_days || 180 },
  };
}

function staffSection(base, catalog, members, label, inCharter) {
  const ids = [...Object.keys(base.staff || {}), ...members.map((m) => m.id)];
  if (!ids.length) return html`<p class="faint sub-small">No staff yet.</p>`;
  return ids.map((id) => {
    const scope = base.staff?.[id] || { actions: [], hub_tools: [] };
    const fresh = members.some((m) => m.id === id);
    return html`<fieldset class="sub-fieldset"><legend><b>${label[id] || members.find((m) => m.id === id)?.name || id}</b> <span class="mono faint sub-small">${id}</span>${fresh ? html` ${badge("new", "warn")}` : ""}</legend>
      <div class="check-grid">${catalog.map((a) => html`<label class="check"><input type="checkbox" data-scope="${id}" data-action="${a.id}" ${(scope.actions || []).includes(a.id) ? "checked" : ""} ${inCharter.includes(a.id) ? "" : "disabled"}>
        <span class="mono">${a.id}</span></label>`)}</div>
      <div class="check-grid" style="margin-top:6px">${HUB_TOOLS.map(([t, text]) => html`<label class="check" title="${text}"><input type="checkbox" data-hub="${id}" data-tool="${t}" ${(scope.hub_tools || []).includes(t) ? "checked" : ""}>
        <span>hub: ${t.replace(/_/g, " ")}</span></label>`)}</div>
      <div class="row" style="margin-top:6px">${fresh ? html`<button type="button" class="btn sm danger" data-act="drop-member" data-id="${id}">${icon("trash")}Remove this new member</button>`
        : html`<label class="check"><input type="checkbox" data-remove="${id}"><span>Take out of the charter (disabled, not deleted)</span></label>`}</div></fieldset>`;
  });
}

async function openAmend(sub, providers, done) {
  const base = structuredClone(sub.charter || sub.pending_charter);
  if (!base) return toast("There is no charter to amend yet", "warn");
  let guards = {};
  try { guards = (await get("/settings")).guardrails || {}; } catch { /* the guard re-checks auto anyway */ }
  const current = sub.charter || null;
  // the tool's catalog, and actions of the charter it no longer lists (shown, so they can be taken out)
  const catalog = [...(sub.catalog || []), ...base.actions.filter((a) => !(sub.catalog || []).some((c) => c.id === a.id))];
  const writesAuto = guards.subsidiary_tool_writes_need_approval === false;
  const label = names(sub, providers);
  const members = [];
  const usable = [...providers.filter((p) => p.id !== "rules"), ...(base.model_routing?.allowed || [])
    .filter((id) => !providers.some((p) => p.id === id)).map((id) => ({ id, label: id, location: null, available: false, reason: "unknown provider" }))];
  const choicesOf = (a) => {
    const list = policyChoices(a, writesAuto);
    const now = policyOf(a);
    return now && !list.includes(now) ? [now, ...list] : list; // never drop the policy in force without the person choosing
  };
  const panelOk = sub.mode === "bridge" && !!sub.bridge?.manifest?.panel?.enabled;
  const eventsOk = sub.mode === "bridge" && (sub.bridge?.manifest?.events?.names || []).length > 0;
  const policyOf = (a) => base.actions.find((x) => x.id === a.id)?.policy || "";
  const cap = (guards.subsidiary_max_tokens_per_day || 300) * 1000;
  const m = modal({
    title: `Amend the charter of ${sub.tool_name}`, wide: true, minRole: "admin", submit: "Save the charter",
    body: html`<p class="muted" style="margin-bottom:12px">Narrowing applies at once (the sidecar is told; staff taken out are disabled, not deleted). Anything that widens the charter -
        a new action or looser policy, more staff or reach, higher budgets, another model provider, the panel or event relay, transcripts, a new mandate - waits for a
        new charter approval, which another administrator decides.</p>
      ${sub.pending_charter_approval && sub.pending_charter && sub.charter ? html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div class="sub-small">
        <b>Charter v${sub.pending_charter.version} waits for approval.</b> This editor starts from version ${sub.charter_version}, the one in force. Saving a narrower
        charter withdraws the waiting one; saving a wider one replaces it with a new request.</div></div>` : ""}
      ${field("Mandate", html`<textarea name="mandate" rows="3" maxlength="4000">${base.mandate || ""}</textarea>`, "The team's purpose: every prompt of its staff starts with it.")}
      <h3 class="sub-h">Actions</h3>
      <div class="table-wrap"><table class="table compact"><thead><tr><th>Action</th><th>Risk</th><th>Policy</th></tr></thead><tbody>
        ${catalog.map((a) => html`<tr><td><span class="mono">${a.id}</span><div class="faint sub-small">${a.title}</div></td><td>${badge(a.risk, RISK_TONE[a.risk])}${a.reversible ? html` <span class="faint sub-small">reversible</span>` : ""}${a.external_effect ? html` <span class="warn-text sub-small">external effect</span>` : ""}</td>
          <td><select class="input-sm" data-policy="${a.id}" aria-label="Policy of ${a.id}">${options([["", "not in the charter"], ...choicesOf(a).map((p) => [p, POLICY_LABEL[p] || p])], policyOf(a))}</select></td></tr>`)}</tbody></table></div>
      ${writesAuto ? "" : html`<p class="faint sub-small">Writes always need a person's approval while the guardrail "In-tool changes of subsidiaries need a person" is on.</p>`}
      <h3 class="sub-h" style="margin-top:14px">Staff</h3><div data-staff></div>
      <button type="button" class="btn sm" data-act="add-member">${icon("plus")}Add a staff member</button>
      <div class="sub-two" style="margin-top:14px">
        <div><h3 class="sub-h">Model routing</h3>
          <div class="stack" style="gap:6px">${usable.map((p) => html`<label class="check"><input type="checkbox" data-provider="${p.id}" ${(base.model_routing?.allowed || []).includes(p.id) ? "checked" : ""}>
            <span>${p.label} <span class="faint sub-small">${p.location === "self_hosted" ? "own hardware: tool data stays local" : "third-party: tool data is sent to it"}${p.available ? "" : ` - not available: ${p.reason || ""}`}</span></span></label>`)}</div>
          ${field("Default provider", html`<select name="default_provider">${options([["", "The first allowed"], ...usable.map((p) => [p.id, p.label])], base.model_routing?.default || "")}</select>`)}</div>
        <div><h3 class="sub-h">Panel, events and data</h3>
          ${panelOk ? html`<label class="check"><input type="checkbox" name="panel_enabled" ${base.panel?.enabled ? "checked" : ""}><span>"Ask the team" inside ${sub.tool_name}</span></label>
            ${field("Front desk (answers the panel)", html`<select name="desk" data-desk></select>`)}` : html`<p class="faint sub-small">${sub.mode === "bridge" ? "The bridge has no panel." : "API-only teams have no panel."}</p>`}
          ${eventsOk ? html`<label class="check"><input type="checkbox" name="relay" ${base.events?.relay ? "checked" : ""}><span>Relay the tool's events to Atrium</span></label>` : ""}
          <label class="check"><input type="checkbox" name="transcripts" ${base.data?.transcripts ? "checked" : ""}><span>Keep transcripts (encrypted)</span></label>
          ${field("Keep reports (days)", html`<input type="number" name="retention" min="1" max="3650" step="1" value="${base.data?.report_retention_days || 180}">`)}</div></div>
      <h3 class="sub-h" style="margin-top:6px">Budgets</h3>
      <div class="sub-budget-grid">${BUDGETS.map(([k, l]) => field(l, html`<input type="number" min="1" step="1" data-budget="${k}" value="${base.budgets?.[k] ?? ""}" ${k === "tokens_per_day" ? html`max="${cap}"` : ""}>`,
        k === "tokens_per_day" ? `At most ${compact(cap)} (guardrail).` : ""))}</div>
      <h3 class="sub-h" style="margin-top:6px">What saving does</h3><div data-changes aria-live="polite"></div>`,
    async onSubmit() {
      const draft = readDraft(form, base, catalog, members);
      const r = await put(`/subsidiaries/${enc(sub.tool_id)}/charter`, charterBody(draft, members));
      if (!r.changed) toast("Nothing changed", "info");
      else if (r.applied) toast(`Charter v${r.charter_version} is in force (narrowed)`, "ok");
      else toast("The wider charter waits for another administrator's approval", "ok", { href: "#/approvals", text: "Approvals" });
      done();
    },
  });
  const form = m.el;
  const included = () => catalog.filter((a) => form.querySelector(`[data-policy="${CSS.escape(a.id)}"]`)?.value).map((a) => a.id);
  const boxKey = (x) => ["scope", "action", "hub", "tool", "remove"].map((k) => x.dataset[k] ?? "").join("|");
  const drawStaff = () => {
    const host = form.querySelector("[data-staff]");
    const ticked = new Map([...host.querySelectorAll("input[type=checkbox]")].map((x) => [boxKey(x), x.checked])); // survives the redraw
    setHTML(host, staffSection(base, catalog, members, label, included()));
    for (const box of host.querySelectorAll("input[type=checkbox]")) if (ticked.has(boxKey(box))) box.checked = ticked.get(boxKey(box));
    const deskSel = form.querySelector("[data-desk]");
    if (deskSel) {
      const ids = [...Object.keys(base.staff || {}), ...members.map((x) => x.id)];
      setHTML(deskSel, options(ids.map((id) => [id, label[id] || members.find((x) => x.id === id)?.name || id]), deskSel.value || base.panel?.desk || ""));
    }
  };
  const refresh = () => setHTML(form.querySelector("[data-changes]"), html`${changesList(charterChanges(current, readDraft(form, base, catalog, members), {
    ...label, ...Object.fromEntries(members.map((x) => [x.id, x.name])) }))}
    <p class="sub-small" style="margin-top:6px">${classify(current, readDraft(form, base, catalog, members)).length
      ? html`<b class="warn-text">Saving asks for a new charter approval:</b> another administrator approves it (you proposed it). The charter in force stays until then.`
      : html`<b>Saving applies at once.</b>`}</p>`);
  form.addEventListener("change", (e) => {
    if (e.target.dataset?.policy !== undefined) {
      const on = !!e.target.value;
      form.querySelectorAll(`[data-action="${CSS.escape(e.target.dataset.policy)}"]`).forEach((box) => { box.disabled = !on; });
    }
    refresh();
  });
  form.addEventListener("input", refresh);
  actions(form, {
    "add-member": () => addMember(sub, usable, [...Object.keys(base.staff || {}), ...members.map((x) => x.id)], (member) => {
      members.push(member);
      drawStaff();
      refresh();
    }),
    "drop-member"(d) {
      const at = members.findIndex((x) => x.id === d.id);
      if (at >= 0) members.splice(at, 1);
      drawStaff();
      refresh();
    },
  });
  drawStaff();
  refresh();
}

function addMember(sub, providers, taken, done) {
  modal({
    title: `A new staff member of ${sub.tool_name}`, submit: "Add", minRole: "admin",
    body: html`<div class="form-grid">${field("Name", html`<input name="name" required maxlength="80" placeholder="e.g. Night clerk">`)}
        ${field("Role", html`<input name="title" maxlength="80" value="Clerk">`)}</div>
      ${field("Instructions", html`<textarea name="instructions" rows="3" maxlength="20000" placeholder="What it does and how (written to it: 'You ...')"></textarea>`)}
      ${field("Standing task", html`<input name="task" maxlength="4000" placeholder="e.g. Raise overdue tickets to high priority">`)}
      <div class="form-grid">${field("Schedule", html`<select name="schedule">${options(SCHEDULES, "0")}</select>`)}
        ${field("Model provider", html`<select name="provider">${options([["", "The charter's default"], ...providers.map((p) => [p.id, p.label])], "")}</select>`, "It must be one the charter allows.")}</div>
      <p class="faint sub-small">It gets the read and tool-actions permissions; tick its actions in the staff list. It is created when the charter is approved.</p>`,
    async onSubmit(data) {
      const name = String(data.get("name") || "").trim();
      if (!name) throw new Error("Give the staff member a name");
      done({ id: staffId(sub.tool_id, name, taken), name, title: String(data.get("title") || "").trim() || "Staff",
        instructions: String(data.get("instructions") || ""), task: String(data.get("task") || ""), schedule_minutes: Number(data.get("schedule") || 0),
        provider: String(data.get("provider") || ""), permissions: ["read", "tool_actions"] });
    },
  });
}

// ---------- one subsidiary ----------

async function renderOne(el, ctx, toolId, initialTab) {
  let tab = TABS.some(([k]) => k === initialTab) ? initialTab : "overview";
  let sub = null;
  let agents = [];
  let providers = [];
  let audit = null;
  let runs = null;
  let reports = null;
  let verify = null;
  let allReports = false;
  let credential = null;
  const f = { kind: "", staff: "", risk: "", trigger: "" };
  const path = (rest = "") => `/subsidiaries/${enc(toolId)}${rest}`;

  const load = async () => {
    [sub, agents, providers] = await Promise.all([get(path()), get("/agents").catch(() => agents),
      providers.length ? providers : get("/llm/providers").then((r) => r.choices || []).catch(() => [])]);
    if (tab === "activity") {
      [audit, runs] = await Promise.all([get(path(`/audit?limit=200${can("operator") ? "&detail=1" : ""}`)), get(path("/runs?limit=30")).then((r) => r.runs)]);
    }
    if (tab === "reports") reports = await get(path("/reports"));
    if (tab === "setup" && sub.mode === "sidecar_only" && can("admin")) credential = await credentialFields(toolId).catch(() => null);
  };

  const head = () => {
    const tool = ctx.state.tools.find((t) => t.id === toolId);
    const closed = ["stopped", "archived"].includes(sub.status);
    return html`<section class="card sub-head">
      <div class="row" style="align-items:flex-start;flex-wrap:nowrap;gap:14px">
        ${tool ? appIcon(tool, "lg") : builtinIcon("building", colorFor(toolId), "lg")}
        <div style="flex:1;min-width:0">
          <div class="row" style="gap:8px"><h1>${sub.tool_name}</h1>${modeBadge(sub.mode)}${statusBadge(sub.status)}${flagBadges(sub.flags)}</div>
          <p class="muted" style="margin-top:4px">The ${sub.tool_name} subsidiary: ${statusInfo(sub.status).help}</p>
          ${sub.status === "paused" ? html`<p class="sub-small sub-text" style="margin-top:4px">Paused by ${sub.paused_by || "Atrium"} ${when(sub.paused_at)}${sub.pause_reason ? `: ${sub.pause_reason}` : ""}</p>` : ""}
          <p class="faint mono sub-small" style="margin-top:4px">${sub.id}</p></div></div>
      <div class="row sub-controls">
        ${WORKING.includes(sub.status) ? html`<button type="button" class="btn" data-act="pause" data-min-role="operator">${icon("pause")}Pause</button>` : ""}
        ${sub.status === "paused" ? html`<button type="button" class="btn primary" data-act="resume" data-min-role="admin">${icon("play")}Resume</button>` : ""}
        ${sub.status === "active" ? html`<button type="button" class="btn" data-act="task" data-min-role="operator">${icon("send")}Give the team a task</button>` : ""}
        <a class="btn" href="#/tools/${enc(toolId)}">${icon("grid")}The tool's page</a>
        <span class="spacer"></span>
        ${!closed ? html`<button type="button" class="btn danger" data-act="stop" data-min-role="admin">${icon("stop")}Stop</button>` : ""}
        ${sub.status === "stopped" ? html`<button type="button" class="btn danger" data-act="archive" data-min-role="admin">${icon("trash")}Archive</button>` : ""}</div></section>`;
  };

  const open = () => (sub.open?.reports || 0) + (sub.open?.escalations || 0);
  const draw = () => keepFocus(() => {
    ctx.crumb(`Subsidiaries / ${sub.tool_name}`);
    const body = tab === "charter" ? charterView(sub, providers) : tab === "activity" ? activityView(sub, audit, runs, f, verify, providers)
      : tab === "reports" ? reportsView(sub, reports, allReports, providers) : tab === "setup" ? setupView(sub, credential) : overview(sub, agents);
    setHTML(el, html`${head()}
      <div class="tabs" role="tablist" aria-label="${sub.tool_name} subsidiary">${TABS.map(([k, label]) => html`<button type="button" role="tab" id="sub-tab-${k}" aria-selected="${tab === k ? "true" : "false"}"
        class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}${k === "reports" && open() ? ` (${open()})` : ""}</button>`)}</div>
      <div role="tabpanel" aria-labelledby="sub-tab-${tab}">${body}</div>`);
  });

  const reload = async () => {
    try {
      await load();
      if (el.isConnected) draw();
    } catch (err) {
      if (err.status === 404) return notFound();
      failed(err);
    }
  };

  const notFound = () => {
    const tool = ctx.state.tools.find((t) => t.id === toolId);
    ctx.crumb("Subsidiaries");
    setHTML(el, html`<section class="card">${emptyState("building", tool ? `${tool.name} has no team inside` : "No such subsidiary",
      tool ? "Give it a team inside: a sidecar next to the tool, governed by Atrium." : "The tool may have been removed.",
      html`${tool ? html`<button type="button" class="btn primary" data-act="give" data-min-role="operator">${icon("users")}Give it a team inside</button> ` : ""}<a class="btn" href="#/subsidiaries">All subsidiaries</a>`)}</section>`);
  };

  const act = async (fn, okText) => {
    try {
      const r = await fn();
      if (okText) toast(typeof okText === "function" ? okText(r) : okText, "ok");
    } catch (err) {
      failed(err);
    }
    reload();
  };

  const staffChoices = () => {
    const desk = sub.charter?.panel?.enabled ? sub.charter.panel.desk : null;
    const ids = Object.keys(sub.charter?.staff || {});
    const label = names(sub);
    return [...ids.filter((id) => id !== desk), ...ids.filter((id) => id === desk)].map((id) => [id, `${label[id] || id}${id === desk ? " (front desk)" : ""}`]);
  };

  const giveTask = (text = "") => {
    modal({
      title: `Give the ${sub.tool_name} team a task`, submit: "Send the task", minRole: "operator",
      body: html`${field("Staff member", html`<select name="agent_id">${options(staffChoices(), staffChoices()[0]?.[0])}</select>`)}
        ${field("Task", html`<textarea name="text" rows="4" maxlength="4000" required placeholder="What should it do in ${sub.tool_name}?">${text}</textarea>`)}
        <p class="faint sub-small">It runs once in the sidecar. Changes it asks for wait in Approvals, and since the task is yours, another person approves them.</p>`,
      async onSubmit(data) {
        const r = await post(path("/tasks"), { agent_id: String(data.get("agent_id") || "") || null, text: String(data.get("text") || "").trim() });
        toast(`Task queued (run ${r.run_id}): its result shows on the Agents page`, "ok");
      },
    });
  };

  const enrollment = async () => {
    if (!(await confirmDialog("Issue a new enrollment", `A one-time code (valid 30 minutes) for the ${sub.tool_name} sidecar. ${sub.sidecar
      ? "The current sidecar's token is revoked at once and the team goes back to probation until it proves conformance again." : ""}`, "Issue the code"))) return;
    let r;
    try {
      r = await post(path("/enrollment"));
    } catch (err) {
      return failed(err);
    }
    const m = modal({
      title: "Enrollment code (shown once)", submit: null, cancel: "Done", sticky: true,
      body: html`<div class="notice warn">${icon("key")}<div class="sub-small"><b>Copy it now: Atrium shows it once and never stores it.</b> It works once, until ${dateTime(r.expires_at)}.</div></div>
        <div class="row sub-code"><input readonly value="${r.code}" aria-label="Enrollment code" class="mono" data-code><button type="button" class="btn" data-act="copy">${icon("copy")}Copy</button></div>
        <ol class="sub-small sub-howto"><li>Copy the bundle in <span class="mono sub-text">${r.bundle?.sidecar_dir || "-"}</span> to where the sidecar runs (its own container or OS user).</li>
          <li>Start it with the code in <code>ATRIUM_ENROLLMENT_CODE</code>; it enrolls with Atrium (<span class="mono">${r.atrium_path}</span>) and forgets the code.</li>
          <li>It proves conformance; then the charter is approved and the team starts.</li></ol>`,
    });
    actions(m.el, { copy: () => copyText(r.code, m.el.querySelector("[data-code]")) });
    reload();
  };

  const stop = () => {
    modal({
      title: `Stop the ${sub.tool_name} subsidiary`, submit: "Stop for good", minRole: "admin",
      body: html`<div class="notice bad">${icon("alert")}<div class="sub-small"><b>This cannot be undone.</b> The sidecar's token is revoked, every pending approval is withdrawn, the staff are disabled
          and the signing key is replaced, so the deployed bridge refuses every new ticket. A new team means a new proposal.${sub.mode === "sidecar_only" ? " Revoke the team's read-only account in the tool too." : ""}</div></div>
        ${field(`Type ${sub.tool_name} to confirm`, html`<input name="confirm" autocomplete="off" required>`)}`,
      async onSubmit(data) {
        const confirm = String(data.get("confirm") || "").trim();
        if (confirm !== sub.tool_name && confirm !== sub.tool_id) throw new Error(`Type ${sub.tool_name} to confirm`);
        await post(path("/stop"), { confirm });
        toast(`The ${sub.tool_name} subsidiary is stopped`, "warn");
        reload();
      },
    });
  };

  actions(el, {
    tab(d) {
      tab = d.tab;
      history.replaceState(null, "", `#/subsidiaries/${enc(toolId)}${tab === "overview" ? "" : `/${tab}`}`);
      reload().then(() => el.querySelector(`#sub-tab-${tab}`)?.focus({ preventScroll: true }));
    },
    give: () => openGiveTeam({ toolId, toolName: ctx.state.tools.find((t) => t.id === toolId)?.name || toolId }),
    pause: () => pauseDialog(`Pause the ${sub.tool_name} subsidiary`, "The team stops at once: no model answers, actions or runs; its pending in-tool changes are withdrawn and queued work is cancelled. The bridge refuses calls once its last ticket expires. An administrator resumes it.",
      path("/pause"), () => { toast(`The ${sub.tool_name} subsidiary is paused`, "warn"); reload(); }),
    async resume() {
      if (!(await confirmDialog(`Resume the ${sub.tool_name} subsidiary`, "It gets a new ticket at its next heartbeat; the circuit breaker is reset. Nothing that was withdrawn comes back.", "Resume"))) return;
      act(() => post(path("/resume")), (r) => `The ${sub.tool_name} subsidiary is ${statusInfo(r.status).text}`);
    },
    task: () => giveTask(),
    stop,
    async archive() {
      if (!(await confirmDialog(`Archive the ${sub.tool_name} subsidiary`, "It is kept for its audit trail; its keys and inbox go. The tool can then get a new team.", "Archive"))) return;
      act(() => del(path()), "Archived");
    },
    enroll: enrollment,
    async "rotate-key"() {
      if (!(await confirmDialog("Rotate the signing key", "A second key is staged: bridge.env lists both. Deploy it to the tool, then finish the rotation to retire the old key.", "Stage a new key"))) return;
      act(() => post(path("/rotate-key")), "A new key is staged: deploy the new bridge.env, then finish the rotation");
    },
    async "finish-key"() {
      if (!(await confirmDialog("Finish the key rotation", "The old key is retired: a bridge still started with the old bridge.env refuses every ticket. Deploy the new bridge.env first.", "Retire the old key"))) return;
      act(() => post(path("/rotate-key?finish=1")), "The old key is retired");
    },
    conformance: (_, btn) => {
      btn.disabled = true;
      act(() => post(path("/conformance")), (r) => (r.conformance ? `Conformance ${r.conformance.ok ? "passed" : "failed"} (${r.by === "atrium" ? "observed by Atrium" : "run by the sidecar"})`
        : "The sidecar was asked to run the checks"));
    },
    amend: () => openAmend(sub, providers, reload),
    async verify(_, btn) {
      btn.disabled = true;
      try {
        verify = await post(path("/audit/verify"));
      } catch (err) {
        failed(err);
      }
      reload();
    },
    async older() {
      try {
        const more = await get(path(`/audit?limit=200&before=${audit.before}${can("operator") ? "&detail=1" : ""}`));
        audit = { ...audit, entries: [...more.entries, ...audit.entries], before: more.before };
        draw();
      } catch (err) {
        failed(err);
      }
    },
    jump(d) {
      const row = el.querySelector(`#audit-${CSS.escape(d.seq)}`);
      if (!row) return toast(`Entry #${d.seq} is hidden by the filters or older than the page`, "info");
      row.scrollIntoView({ behavior: "smooth", block: "center" });
      row.focus({ preventScroll: true });
    },
    "reports-open": () => { allReports = false; draw(); },
    "reports-all": () => { allReports = true; draw(); },
    "report-close": (d) => act(() => post(path(`/reports/${enc(d.id)}/close`)), "Report closed"),
    async "report-promote"(d) {
      const r = reports?.reports.find((x) => x.id === d.id);
      if (!r || !(await confirmDialog("Promote to a risk", `A risk is created from "${r.title}", labelled as written by the subsidiary; review and score it in the Compliance hub.`, "Create the risk"))) return;
      act(() => post(path(`/reports/${enc(d.id)}/promote`)), (x) => `Risk ${x.risk.id} created`);
    },
    "report-task"(d) {
      const r = reports?.reports.find((x) => x.id === d.id);
      giveTask(r ? `Follow up on the report "${r.title}".` : "");
    },
    async "credential-clear"() {
      if (!(await confirmDialog("Clear the dedicated credential", "The sidecar can no longer read the tool; revoke that account in the tool too.", "Clear"))) return;
      act(() => del(path("/credential")), "Credential cleared");
    },
  });
  el.addEventListener("change", (e) => {
    const key = e.target.dataset?.filter;
    if (!key) return;
    f[key] = e.target.value;
    draw();
  });
  el.addEventListener("submit", async (e) => {
    if (e.target.dataset?.form !== "credential") return;
    e.preventDefault();
    const secrets = Object.fromEntries([...e.target.querySelectorAll("input[type=password]")].filter((x) => x.value).map((x) => [x.name, x.value]));
    const btn = e.target.querySelector("button[type=submit]");
    btn.disabled = true;
    try {
      await put(path("/credential"), { secrets });
      toast("Credential saved (encrypted)", "ok");
      e.target.reset();
    } catch (err) {
      failed(err);
    } finally {
      btn.disabled = false;
    }
    reload();
  });
  await reload();
  // a live update never wipes what a person is typing (the dedicated credential's fields)
  const typing = () => [...el.querySelectorAll(".sub-cred input")].some((x) => x.value) || (el.contains(document.activeElement) && document.activeElement.matches("input, textarea"));
  ctx.live(LIVE, () => (typing() ? null : reload()), 600);
}

export async function render(el, ctx) {
  const [toolId, tab] = ctx.params;
  if (toolId) return renderOne(el, ctx, toolId, tab);
  return renderGroup(el, ctx);
}
