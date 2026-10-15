import { del, get, patch, post } from "../api.js";
import { scheduleLabel } from "../flows.js";
import { attentionText, blockedText, effectiveText, memoryText, modelLabel, retryText, severityTone } from "../llm.js";
import { actions, badge, builtinIcon, can, colorFor, confirmDialog, field, html, icon, md, modal, options, setHTML, timeAgo, timeIn, toast } from "../ui.js";
import { render as renderSettings } from "./agent-settings.js";

// Chat transcripts (one per agent) survive navigation inside the app; redraw belongs to the Agents page currently shown.
const chat = { agent: "supervisor", logs: {}, busy: new Set(), redraw: null, memory: {} };

/** Forget the transcripts, e.g. on sign-out, so the next person starts fresh. */
export function resetChat() {
  chat.agent = "supervisor";
  chat.logs = {};
  chat.busy = new Set();
  chat.memory = {};
}

const GROUPS = [
  ["Orchestration", (a) => a.role === "supervisor"],
  ["Specialists", (a) => a.role === "patcher" || a.role === "operator"],
  ["App supervisors - built-in apps", (a) => a.role === "module-supervisor"],
];
const ROLE_ICON = { supervisor: "bot", patcher: "wrench", operator: "terminal", "module-supervisor": "shield", "tool-supervisor": "grid", "team-agent": "bot" };
const MODULE_ICON = { "module:assets": "box", "module:people": "contact", "module:vulns": "bug" };
const agentIcon = (a) => MODULE_ICON[a.id] || ROLE_ICON[a.role] || "bot";
const PROVIDER_ICON = { anthropic: "bot", openai: "bot", local: "server", rules: "sliders" };
const MODE = { llm: "AI model", local: "local model", rules: "rules", sidecar: "the team's sidecar" };
const DESIGNERS = [
  ["auto", "Automatic", "The AI model designs the team when one is connected; otherwise the templates for this kind of tool."],
  ["templates", "Templates", "Roles proven for this kind of tool (SIEM, GRC, inventory, scanner) plus a maintainer."],
  ["model", "AI model", "The AI model reads the tool's manifest and designs the roles, tasks and permissions."],
];
const enc = encodeURIComponent;
const chatty = (a) => a.id === "supervisor" || a.kind === "custom";

/** The effective model badge: "<model> · <where it comes from>" (amber with the reason when no model can run). The
 * title and a visually hidden text hold the levels that were skipped. */
function providerBadge(a) {
  const e = a.llm?.purposes?.[a.llm?.primary];
  if (!e) return a.uses_llm ? badge("rules mode") : badge("deterministic");
  const kind = e.provider_kind || a.provider_kind || "rules";
  const ready = a.llm?.ready || (e.provider === "rules" && e.source !== "rules"); // rules on purpose is not a problem
  const tone = !ready ? "warn" : kind === "local" ? "info" : kind === "rules" ? "" : "accent";
  const text = !ready ? `No AI model${a.provider_label && a.provider_label !== "Rules" ? `: ${a.provider_label} unavailable` : ""}` : effectiveText(e);
  const skipped = blockedText(e);
  const tip = [effectiveText(e), skipped && `skipped: ${skipped}`, a.llm?.local_only && "local only"].filter(Boolean).join(" - ");
  return html`<span class="badge model-badge ${tone}" title="${tip}">${icon(PROVIDER_ICON[kind] || "bot")}${text}${a.llm?.local_only ? html` ${icon("lock")}` : ""}
    ${skipped || a.llm?.local_only ? html`<span class="sr-only">${[skipped && ` (skipped: ${skipped})`, a.llm?.local_only && " (local only)"].filter(Boolean).join("")}</span>` : ""}</span>`;
}

const settingsHref = (a, tab = "") => `#/agents/${enc(a.id)}/settings${tab ? `/${tab}` : ""}`;
// a subsidiary's staff member works in the sidecar next to its tool: its scope is the subsidiary's charter
const sidecar = (a) => a.placement === "sidecar";
const charterHref = (a) => `#/subsidiaries/${enc(a.works_inside || a.team)}/charter`;
const insideBadge = (a) => (sidecar(a) ? html`<a class="badge accent" href="#/subsidiaries/${enc(a.works_inside || a.team)}"
  title="A subsidiary's staff member: it runs in the sidecar next to the tool, within its approved charter">works inside ${a.team_name || a.works_inside}</a>` : "");
const budgetBadge = (a) => (a.llm?.budget_reached ? html`<a class="badge warn" href="${settingsHref(a, "limits")}" title="A budget of ${a.name} is reached">budget reached</a>` : "");
const pausedBadge = (a) => (a.schedule_paused ? html`<a class="badge warn" href="${settingsHref(a, "escalation")}">schedule paused after ${a.failures} failure${a.failures === 1 ? "" : "s"}</a>` : "");

/** One item of the "Needs attention" strip: what happened (text, never colour alone), a link, and - for the people the
 * agent's notifications target - a "for you" mark. */
function attentionItem(i) {
  const agentLink = (id, name) => html`<a href="${settingsHref({ id })}">${name}</a>`;
  const go = i.kind === "escalation" ? html`<a class="btn sm" href="#/approvals">${icon("checkCircle")}Open in Approvals</a>`
    : i.kind === "budget" ? html`<a class="btn sm" href="${settingsHref({ id: i.agent_id }, "limits")}">${icon("sliders")}Limits</a>`
      : i.kind === "paused" ? html`<button type="button" class="btn sm" data-act="resume-schedule" data-id="${i.agent_id}" data-min-role="admin">${icon("play")}Resume schedule</button>
          <a class="btn sm ghost" href="${settingsHref({ id: i.agent_id }, "escalation")}">Settings</a>`
        : i.kind === "blocked" ? html`<span class="faint" style="font-size:12px">${i.agents.slice(0, 6).map((a, n) => html`${n ? ", " : ""}${agentLink(a.id, a.name)}`)}${i.agents.length > 6 ? ` +${i.agents.length - 6}` : ""}</span>`
          : html`<a class="btn sm ghost" href="${settingsHref({ id: i.agent_id })}">Settings</a>`;
  const tone = i.kind === "escalation" ? severityTone(i.severity) : i.kind === "blocked" || i.kind === "held" ? "" : "warn";
  const label = { escalation: "escalation", budget: "budget", paused: "schedule paused", held: "held", blocked: "no model" }[i.kind] || i.kind;
  return html`<li class="attention-item${i.for_you ? " for-you" : ""}">${badge(label, tone)}
    <span class="attention-text">${attentionText(i)}${i.for_you ? html` <b class="for-you-mark">(for you)</b>` : ""}</span>
    <span class="row" style="gap:6px">${go}</span></li>`;
}

function attentionView(items) {
  if (!items?.length) return "";
  const mine = items.filter((i) => i.for_you).length;
  return html`<section class="card attention" aria-labelledby="attention-title">
    <header><h2 id="attention-title" tabindex="-1">${icon("bell")} Needs attention</h2>
      <span class="faint" style="font-size:12px">${items.length} item${items.length === 1 ? "" : "s"}${mine ? `, ${mine} for you` : ""}</span></header>
    <ul class="attention-list">${items.map(attentionItem)}</ul></section>`;
}

function agentCard(a) {
  const tone = a.status === "working" ? "working" : a.status === "paused" ? "warn" : "ok";
  return html`<div class="card agent-card">
    <div class="head">${builtinIcon(agentIcon(a), a.role === "tool-supervisor" ? colorFor(a.scope) : "#7c3aed", "sm")}
      <div style="flex:1;min-width:0"><b>${a.name}</b><div class="faint" style="font-size:12px">${a.title}</div></div>
      <span class="row" style="gap:6px;font-size:12px"><span class="dot ${tone}"></span>${a.status}</span></div>
    <div class="desc">${a.description}</div>
    <div class="meta"><span>${a.handled} handled</span>${a.errors ? html`<span style="color:var(--bad)">${a.errors} errors</span>` : ""}
      ${a.queued ? html`<span>${a.queued} queued</span>` : ""}<span>${a.last_active ? `active ${timeAgo(a.last_active)}` : "not active yet"}</span></div>
    <div class="row" style="justify-content:space-between">
      <span class="row" style="gap:6px;min-width:0">${providerBadge(a)}${budgetBadge(a)}
        ${a.custom_instructions ? badge("custom instructions", "info") : ""}</span>
      ${coreButtons(a)}</div>
  </div>`;
}

function coreButtons(a) {
  return html`<span class="row" style="gap:6px">
    <button class="btn sm" data-act="toggle" data-id="${a.id}" data-paused="${a.paused}" data-min-role="admin">${icon(a.paused ? "play" : "pause")}${a.paused ? "Resume" : "Pause"}</button>
    <a class="btn sm" href="${settingsHref(a)}" aria-label="Settings of ${a.name}">${icon("sliders")}Settings</a></span>`;
}

/** The lead of a team (a core agent): compact, with the same pause and settings controls as its card. */
function leadRow(a) {
  const tone = a.status === "working" ? "working" : a.status === "paused" ? "warn" : "ok";
  return html`<div class="team-lead">
    ${builtinIcon(agentIcon(a), a.role === "tool-supervisor" ? colorFor(a.scope) : "#7c3aed", "sm")}
    <div style="flex:1 1 150px;min-width:0"><div class="row" style="gap:6px"><b>${a.name}</b>${badge("lead", "accent")}</div>
      <div class="faint" style="font-size:12px"><span class="dot ${tone}"></span> ${a.status} - ${a.handled} handled${a.last_active ? ` - active ${timeAgo(a.last_active)}` : ""}</div></div>
    ${a.id === "supervisor" ? html`<button class="icon-btn sm" data-act="chat-with" data-id="${a.id}" title="Chat with ${a.name}" aria-label="Chat with ${a.name}" data-min-role="operator">${icon("chat")}</button>` : ""}
    ${coreButtons(a)}</div>`;
}

function memberRow(a, leadId) {
  const r = a.last_result;
  const notGranted = (a.permissions || []).filter((p) => !(a.effective_permissions || []).includes(p));
  const state = !a.enabled ? badge("disabled") : a.running ? badge("running") : a.outside_guardrails ? badge("held", "warn") : "";
  const schedule = a.schedule_minutes && a.task ? html`<span title="${a.task}">${icon("refresh")} ${scheduleLabel(a.schedule_minutes)}${a.schedule_paused ? " - paused"
      : a.next_run ? ` - next ${timeIn(a.next_run)}` : ""}</span>${a.schedule_paused ? html`<button type="button" class="chip-link" data-act="resume-schedule" data-id="${a.id}"
      data-min-role="admin">Resume schedule</button>` : ""}`
    : html`<span>no schedule</span>`;
  return html`<div class="member" style="${a.depth > 1 ? `margin-left:${(a.depth - 1) * 18}px` : ""}">
    <div class="member-head">${builtinIcon("bot", colorFor(a.id), "sm")}
      <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><b>${a.name}</b><span class="faint" style="font-size:12px">${a.title}</span></div>
        <div class="row" style="gap:6px;margin-top:4px;min-width:0">${insideBadge(a)}${providerBadge(a)}${budgetBadge(a)}${pausedBadge(a)}${state}</div></div>
      <span class="row" style="gap:2px;flex-wrap:nowrap">
        <button class="icon-btn sm" data-act="chat-with" data-id="${a.id}" title="Chat" aria-label="Chat with ${a.name}" data-min-role="operator" ${a.enabled ? "" : "disabled"}>${icon("chat")}</button>
        <button class="icon-btn sm" data-act="run" data-id="${a.id}" title="Run now" aria-label="Run ${a.name} now" data-min-role="operator" ${a.enabled && !a.running ? "" : "disabled"}>${icon("play")}</button>
        <a class="icon-btn sm" href="${settingsHref(a)}" title="Settings" aria-label="Settings of ${a.name}">${icon("sliders")}</a>
        ${sidecar(a) ? html`<a class="icon-btn sm" href="${charterHref(a)}" title="Its actions, reach, model and budgets: the subsidiary's charter (amended there)"
          aria-label="Charter of ${a.name}">${icon("file")}</a>`
          : html`<button class="icon-btn sm danger" data-act="remove" data-id="${a.id}" title="Remove" aria-label="Remove ${a.name}" data-min-role="admin">${icon("trash")}</button>`}</span></div>
    ${a.description ? html`<div class="desc">${a.description}</div>` : ""}
    <div class="tag-list">${(a.effective_permissions || []).map((p) => badge(p))}
      ${notGranted.length ? html`<span class="badge warn" title="Not granted: the parent does not have these (guardrail limit_to_parent_permissions)">not granted: ${notGranted.join(", ").replace(/_/g, " ")}</span>` : ""}</div>
    <div class="meta">${schedule}
      ${r ? html`<button type="button" class="chip-link" data-act="result" data-id="${a.id}">${r.ok ? "last run ok" : "last run failed"} ${timeAgo(r.at)}</button>` : html`<span>never run</span>`}
      ${a.parent && a.parent !== leadId ? html`<span>reports to ${a.parent}</span>` : ""}</div>
    ${a.outside_guardrails ? html`<div class="notice warn">${icon("alert")}<div style="font-size:12.5px;min-width:0">${sidecar(a) ? "Held" : "May not act"}: ${a.outside_guardrails}</div></div>` : ""}
  </div>`;
}

/** The team's model default as text: "Suite default", "Ollama (default model)", "GPT-6 Luna (OpenAI)", plus local only. */
function teamModelText(t, providers) {
  const c = t.llm;
  if (!c || (!c.provider && !c.local_only)) return "Suite default";
  const p = providers.find((x) => x.id === c.provider);
  const model = !c.provider ? "Suite default" : c.provider === "rules" ? "Rules" : c.model ? `${modelLabel({ id: c.provider, label: p?.label }, c.model)} (${p?.label || c.provider})` : `${p?.label || c.provider} (default model)`;
  return `${model}${c.local_only ? ", local only" : ""}`;
}

function teamCard(t, providers = []) {
  const full = t.max_size != null && t.size >= t.max_size;
  const kind = t.kind === "tool" ? t.category_title || "Tool" : t.kind === "hub" ? "Hub" : "Built-in app";
  return html`<section class="card team-card">
    <header><div style="min-width:0"><h2>${t.name}</h2>
        <div class="faint" style="font-size:12px">${kind} - ${t.size}${t.max_size != null ? ` of ${t.max_size}` : ""} team agent${t.size === 1 ? "" : "s"}</div>
        <div class="faint" style="font-size:12px">Model: ${teamModelText(t, providers)}
          <button type="button" class="chip-link" data-act="team-model" data-team="${t.team}" data-min-role="admin" aria-label="Change the model of the ${t.name} team">Change</button></div></div>
      <span class="row" style="gap:6px">
        ${t.pending_approval ? html`<a class="badge warn" href="#/approvals">proposal waiting</a>` : ""}
        ${t.can_propose && !t.pending_approval ? html`<button class="btn sm" data-act="propose" data-team="${t.team}" data-min-role="operator"
          ${t.lead?.paused ? html`disabled title="${t.lead.name} is paused - resume it to propose a team"` : ""}>${icon("users")}Propose team</button>` : ""}
        <button class="btn sm" data-act="new" data-team="${t.team}" data-min-role="admin" ${full ? html`disabled title="The team is at its maximum size (guardrail)"` : ""}>${icon("plus")}Add</button></span></header>
    ${t.lead ? leadRow(t.lead) : ""}
    ${t.members.length ? html`<div class="members">${t.members.map((m) => memberRow(m, t.lead?.id))}</div>`
      : html`<p class="faint" style="font-size:12.5px">No team agents yet.${t.suggested?.length ? ` Suggested for this tool: ${t.suggested.join(", ")}.` : ""}</p>`}
  </section>`;
}

function groupsView(agents, overview) {
  const teams = overview.teams.filter((t) => t.kind === "tool" || t.size || t.pending_approval);
  return html`${GROUPS.map(([title, test]) => {
      const list = agents.filter(test);
      return list.length ? html`<div><h3 class="muted" style="margin:0 0 10px">${title}</h3><div class="grid cols-3">${list.map(agentCard)}</div></div>` : "";
    })}
    <div><h3 class="muted" style="margin:0 0 4px">Agent teams</h3>
      <p class="faint" style="font-size:12.5px;margin-bottom:10px">Each tool's supervisor leads its team. Team agents run on their own model choice, their team's, or the suite's
        (Settings &gt; AI models) - Claude, OpenAI, a local model, or rules - with only the permissions they are given.</p>
      ${teams.length ? html`<div class="team-grid">${teams.map((t) => teamCard(t, overview.providers || []))}</div>` : html`<p class="faint">Import a tool to give it a team.</p>`}</div>`;
}

function greeting(a) {
  if (!a || a.id === "supervisor") {
    return "Hi! I'm the **Hub Supervisor**. I coordinate the other agents. Try `status`, `import owner/repo`, `run df -h`, `compliance`, or just describe what you want.";
  }
  const rules = a.provider_kind === "rules" ? " I run on rules: I can check health, run data flows and summarize the state." : "";
  return `Hi! I'm **${a.name}**, ${a.title} in the ${a.team_name || a.team} team.${rules}`;
}

function chatView(agents) {
  const list = agents.filter(chatty);
  const a = list.find((x) => x.id === chat.agent) || list[0];
  const log = chat.logs[a?.id] || [];
  const busy = chat.busy.has(a?.id);
  const off = !a || a.paused || a.enabled === false;
  return html`<header><h2>Chat</h2>
      <select id="chat-agent" class="input-sm" aria-label="Agent to chat with">${options(list.map((x) => [x.id, `${x.name}${x.kind === "custom" ? ` (${x.team_name || x.team})` : ""}`]), a?.id)}</select>
      <span class="spacer"></span>
      <button type="button" class="btn sm ghost" data-act="reset" data-min-role="operator" ${off ? "disabled" : ""}>${icon("refresh")}New conversation</button></header>
    ${a ? html`<div class="row" style="gap:6px;margin-bottom:8px;font-size:12px">${providerBadge(a)}${budgetBadge(a)}
      ${off ? badge(a.kind === "custom" ? "disabled" : "paused", "warn") : ""}${a.outside_guardrails ? badge("held", "warn") : ""}</div>
      ${chat.memory[a.id] ? html`<p class="faint chat-note">${memoryText(chat.memory[a.id])}</p>` : ""}` : ""}
    <div class="msgs" id="chat-msgs">${log.length ? html`${log.map((m) => html`<div class="bubble ${m.me ? "me" : "bot"}">${m.me ? m.text
        : m.untrusted ? html`<div class="sub-untrusted-label">${m.untrusted}</div><div class="sub-untrusted-text">${m.text}</div>` : md(m.text)}
        ${!m.me && (m.meta || m.mode) ? html`<div class="faint" style="font-size:11px;margin-top:4px">via ${m.meta?.model ? modelLabel({ id: m.meta.provider, label: m.meta.provider_label }, m.meta.model) : MODE[m.mode] || m.mode}${m.meta?.fallback_from ? " (fallback)" : ""}</div>` : ""}
        ${m.limited ? html`<div class="faint" style="font-size:11px;margin-top:4px">${m.limited}</div>` : ""}</div>`)}
        ${busy ? html`<div class="bubble bot faint">Thinking${a.id === "supervisor" ? " and asking the other agents" : ""}...</div>` : ""}`
      : html`<div class="bubble bot">${md(greeting(a))}</div>`}</div>
    <form id="chat-form" data-min-role="operator"><input name="text" placeholder="Message ${a?.name || "the agent"}..." autocomplete="off" aria-label="Message" ${busy || off ? "disabled" : ""}>
      <button class="btn primary" ${busy || off ? "disabled" : ""} aria-label="Send">${icon("send")}</button></form>
    ${can("operator") ? "" : html`<p class="faint" style="font-size:12.5px">Chatting with agents needs the operator role.</p>`}`;
}

function streamView(messages) {
  return html`${messages.slice().reverse().map((m) => html`<div class="msg-line">
    <span class="route">${m.sender} &rarr; ${m.recipient}</span><span><span class="subj">${m.subject}</span> <span class="faint">${m.kind}</span></span>
    <span class="faint">${timeAgo(m.ts)}</span></div>`)}`;
}

function resultModal(a, r) {
  modal({
    title: `${a.name}: ${r.ok ? "task done" : "task failed"}`, wide: true, submit: null, cancel: "Close",
    body: html`<div class="row" style="gap:6px;margin-bottom:10px">${badge(r.ok ? "ok" : "failed")}${r.mode ? badge(MODE[r.mode] || r.mode) : ""}
        <span class="faint" style="font-size:12px">${r.trigger || ""} - ${timeAgo(r.at)}${r.duration != null ? ` - ${r.duration}s` : ""}</span></div>
      ${r.untrusted ? html`<div class="sub-untrusted"><div class="sub-untrusted-label">${r.untrusted}</div><div class="sub-untrusted-text">${r.reply || ""}</div></div>`
        : html`<div class="prose-box">${md(r.reply || "")}</div>`}`,
  });
}

export async function render(el, ctx) {
  if (ctx.params[0] && ctx.params[1] === "settings") return renderSettings(el, ctx); // #/agents/<id>/settings[/<tab>]
  let [agents, overview, messages, attention] = await Promise.all([get("/agents"), get("/agents/teams"), get("/messages?limit=80"),
    get("/agents/attention").then((r) => r.items).catch(() => [])]);
  const find = (id) => agents.find((x) => x.id === id);
  const providerLabels = () => Object.fromEntries(overview.providers.map((p) => [p.id, p.kind === "local" ? `Local: ${p.label}` : p.label]));

  setHTML(el, html`
    <div class="page-head"><div><h1 id="agents-title" tabindex="-1">Agents</h1><p class="muted">The Hub Supervisor talks to every agent. Each app has its own supervisor; tool supervisors lead their tool's team of AI agents.</p></div>
      <button class="btn primary" data-act="new" data-min-role="admin">${icon("plus")}New agent</button></div>
    <div id="attention"></div>
    <div class="grid split">
      <div class="stack" id="agent-groups"></div>
      <div class="stack">
        <section class="card chat" id="chat-card"></section>
        <section class="card"><header><h2>Agent conversations</h2><span class="faint" style="font-size:12px">live</span></header>
          <div class="scroll" style="max-height:360px" id="msg-stream"></div></section>
      </div>
    </div>`);
  const groupsEl = el.querySelector("#agent-groups");
  const chatEl = el.querySelector("#chat-card");
  const attentionEl = el.querySelector("#attention");
  // a live refresh leaves the strip alone while focus is in it; after acting on it (`force`) focus goes to its heading
  const drawAttention = (force = false) => {
    if (!force && attentionEl.contains(document.activeElement)) return;
    setHTML(attentionEl, attentionView(attention));
    if (force) (attentionEl.querySelector("#attention-title") || el.querySelector("#agents-title"))?.focus(); // stable across live redraws
  };
  const drawGroups = () => {
    setHTML(groupsEl, groupsView(agents, overview));
    drawAttention();
  };
  const drawChat = (focus = false) => {
    if (!agents.some((a) => chatty(a) && a.id === chat.agent)) chat.agent = "supervisor";
    const draft = chatEl.querySelector("#chat-form input")?.value || "";
    setHTML(chatEl, chatView(agents));
    const input = chatEl.querySelector("#chat-form input");
    if (draft && input && !input.disabled) input.value = draft;
    const box = chatEl.querySelector("#chat-msgs");
    box.scrollTop = box.scrollHeight;
    if (focus && input && !input.disabled && can("operator")) input.focus({ preventScroll: true });
  };
  const reload = async () => {
    [agents, overview, attention] = await Promise.all([get("/agents"), get("/agents/teams"),
      get("/agents/attention").then((r) => r.items).catch(() => attention)]);
    if (!el.isConnected) return;
    drawGroups();
    if (!chatEl.contains(document.activeElement)) drawChat();
  };
  chat.redraw = () => { if (el.isConnected) drawChat(); }; // the reply may arrive after the person left and came back

  el.addEventListener("submit", async (e) => {
    if (e.target.id !== "chat-form") return;
    e.preventDefault();
    const input = e.target.querySelector("input");
    const text = input.value.trim();
    const id = chat.agent;
    if (!text || chat.busy.has(id)) return;
    const logs = chat.logs; // a sign-out meanwhile swaps in new transcripts; the reply stays with these
    const busy = chat.busy;
    const log = (logs[id] ||= []);
    log.push({ me: true, text });
    busy.add(id);
    input.value = "";
    drawChat();
    try {
      const reply = await post(`/agents/${enc(id)}/chat`, { text });
      log.push({ me: false, text: reply.reply, mode: reply.mode, meta: reply.meta, untrusted: reply.untrusted });
    } catch (err) {
      if (err.status === 429) { // a budget or rate limit: say why, and when to try again
        const retry = retryText(err.retryAfter);
        log.push({ me: false, text: err.message, limited: [err.code === "budget_exceeded" ? "Budget reached" : "Too many requests", retry].filter(Boolean).join(" - ") });
      } else log.push({ me: false, text: `Error: ${err.message}` });
    } finally {
      busy.delete(id);
      if (logs === chat.logs && chat.agent === id) chat.redraw?.();
    }
  });
  el.addEventListener("change", (e) => {
    if (e.target.id !== "chat-agent") return;
    chat.agent = e.target.value;
    drawChat(true);
    loadMemory(chat.agent);
  });
  // how long the agent remembers the person's conversation (its memory setting; operators may read their own)
  async function loadMemory(id) {
    if (!can("operator") || !id) return;
    try {
      chat.memory[id] = (await get(`/agents/${enc(id)}/conversation`)).memory;
      if (chat.agent === id) chat.redraw?.();
    } catch { /* not a chat agent, or gone */ }
  }
  loadMemory(chat.agent);

  actions(el, {
    async toggle(d) {
      await patch(`/agents/${enc(d.id)}`, { paused: d.paused !== "true" }).catch((e) => toast(e.message, "bad"));
    },
    new(d) { agentForm(d.team || "hub"); },
    async "resume-schedule"(d) {
      try {
        const a = await post(`/agents/${enc(d.id)}/schedule/resume`);
        toast(`${a.name}: schedule resumed`, "ok");
        await reload();
        drawAttention(true);
      } catch (err) {
        toast(err.message, "bad");
      }
    },
    "team-model"(d) {
      const t = overview.teams.find((x) => x.team === d.team);
      if (t) teamModel(t);
    },
    async remove(d) {
      const a = find(d.id);
      if (!a) return;
      const kids = agents.filter((x) => x.parent === a.id).length;
      const ok = await confirmDialog(`Remove ${a.name}?`, `${a.name} stops and its definition is deleted.${kids ? ` Its ${kids} team member(s) will report to its parent.` : ""} Pending team proposals it made are withdrawn.`, "Remove");
      if (!ok) return;
      try {
        await del(`/agents/${enc(a.id)}`);
        delete chat.logs[a.id];
        toast(`${a.name} removed`, "ok");
        reload();
      } catch (err) {
        toast(err.message, "bad");
      }
    },
    "chat-with"(d) {
      chat.agent = d.id;
      drawChat(true);
      chatEl.scrollIntoView({ behavior: "smooth", block: "nearest" });
    },
    run(d) {
      const a = find(d.id);
      if (a) runModal(a);
    },
    result(d) {
      const a = find(d.id);
      if (a?.last_result) resultModal(a, a.last_result);
    },
    propose(d) {
      const t = overview.teams.find((x) => x.team === d.team);
      if (t) proposeModal(t);
    },
    async reset() {
      const id = chat.agent;
      try {
        await post(`/agents/${enc(id)}/chat/reset`);
        chat.logs[id] = [];
        drawChat(true);
      } catch (err) {
        toast(err.message, "bad");
      }
    },
  });

  /** A team's model default (admin): provider and model, or the suite default, and whether it is local only. */
  async function teamModel(t) {
    let sel;
    try {
      sel = await get("/llm/selection");
    } catch (err) {
      return toast(err.message, "bad");
    }
    const current = sel.selection.teams?.[t.team] || { provider: "", model: "", local_only: false };
    const providers = (overview.providers || []).filter((p) => p.id !== "rules");
    const reach = t.kind === "tool" ? "its team agents and its supervisor" : "its team agents (not the app's supervisor)";
    const m = modal({
      title: `Model of the ${t.name} team`, minRole: "admin", submit: "Save",
      body: html`<p class="muted" style="margin-bottom:12px">Applies to ${reach} unless an agent chooses its own model.</p>
        <div class="form-grid">
          ${field("Provider", html`<select name="provider">${options([["", "Suite default"], ...providers.map((p) => [p.id, `${p.label}${p.available ? "" : ` (not available: ${p.reason})`}`]),
            ["rules", "Rules (no AI model)"]], current.provider)}</select>`)}
          ${field("Model", html`<input name="model" list="team-models" maxlength="200" value="${current.model || ""}" placeholder="Provider default">
            <datalist id="team-models"></datalist>`, "Leave empty for the provider's default model.")}</div>
        <label class="check"><input type="checkbox" name="local_only" ${current.local_only ? "checked" : ""}><span>Local only
          <span class="faint" style="display:block;font-size:12px">Its agents never run on a cloud provider: they use a self-hosted model, or rules.</span></span></label>`,
      async onSubmit(data) {
        const provider = String(data.get("provider") || "");
        const body = { teams: { [t.team]: { provider, model: provider && provider !== "rules" ? String(data.get("model") || "").trim() : "",
          local_only: data.get("local_only") === "on" } }, version: sel.selection.version };
        try {
          await patch("/llm/selection", body);
        } catch (err) {
          if (err.status === 409) { toast("Someone else changed the model choice - open it again", "warn"); return; }
          throw err;
        }
        toast(`${t.name} team: model saved`, "ok");
        reload();
      },
    });
    const pick = m.el.querySelector('[name="provider"]');
    const fill = () => {
      const p = providers.find((x) => x.id === pick.value);
      setHTML(m.el.querySelector("#team-models"), html`${[...new Set([...(p?.pinned_models || []), ...(p?.models || [])])].map((x) => html`<option value="${x}">`)}`);
      const input = m.el.querySelector('[name="model"]');
      input.disabled = !p;
      input.placeholder = p?.default_model ? `Provider default (${p.default_model})` : p ? "Provider default" : "-";
    };
    pick.addEventListener("change", fill);
    fill();
  }

  function parentChoices(team, self) {
    const t = overview.teams.find((x) => x.team === team);
    const out = t?.lead ? [[t.lead.id, `${t.lead.name} (lead)`]] : [];
    for (const m of t?.members || []) if (m.id !== self) out.push([m.id, `${m.name} - ${m.title}`]);
    return out;
  }

  /** A new custom agent (admin): who it is and where it sits; everything else is on its settings page, which opens next. */
  function agentForm(teamId) {
    const suite = overview.suite_model || {};
    const limits = overview.limits || {};
    const nested = limits.allow_nested_teams;
    const leadOf = (tid) => overview.teams.find((x) => x.team === tid)?.lead?.id;
    const m = modal({
      title: "New agent", wide: true, minRole: "admin", submit: "Create agent",
      body: html`
        <div class="form-grid">
          ${field("Name", html`<input name="name" required maxlength="80" placeholder="e.g. Alert triage analyst">`)}
          ${field("Role", html`<input name="title" maxlength="80" value="Team agent">`)}
        </div>
        ${field("Description", html`<input name="description" maxlength="1000" placeholder="What this agent is for">`)}
        <div class="form-grid">
          ${field("Team", html`<select name="team">${options(overview.teams.map((t) => [t.team, t.kind === "tool" ? t.name : `${t.name} (${t.kind === "hub" ? "hub" : "built-in app"})`]), teamId)}</select>`,
            "The tool (or app) it works on; its supervisor leads the team.")}
          ${nested ? field("Reports to", html`<select name="parent">${options(parentChoices(teamId), leadOf(teamId))}</select>`,
            `Nested teams are allowed up to depth ${limits.max_team_depth}.`) : html`<div></div>`}
        </div>
        ${field("Permissions", html`<div class="check-grid perm-grid">${overview.permissions.map((p) => html`<label class="check" title="${p.description}">
            <input type="checkbox" name="perm" value="${p.id}" ${p.id === "read" ? "checked" : ""}><span>${p.id.replace(/_/g, " ")}</span></label>`)}</div>`,
          limits.limit_to_parent_permissions ? "Permissions the parent agent lacks are not granted (guardrail). Hover a permission for what it allows." : "Hover a permission for what it allows.")}
        <p class="faint" style="font-size:12.5px">It inherits the team's or the suite's model (now ${suite.ready ? suite.provider_label : "none available: rules"}; defaults under
          <a href="#/settings/ai">Settings &gt; AI models</a>). Its settings page opens next: model, instructions, standing task and schedule, tools and limits.</p>`,
      async onSubmit(data) {
        const body = {
          name: String(data.get("name") || "").trim(), title: String(data.get("title") || "").trim() || "Team agent",
          description: String(data.get("description") || ""), team: String(data.get("team")), permissions: data.getAll("perm").map(String),
        };
        if (!body.name) {
          toast("Give the agent a name", "bad");
          return true;
        }
        const parent = data.get("parent");
        if (parent) body.parent = String(parent);
        const saved = await post("/agents", body);
        if (saved.clamped?.length) toast(`Not granted (the parent lacks them): ${saved.clamped.join(", ")}`, "warn");
        toast(`${saved.name} created - set it up here`, "ok");
        location.hash = settingsHref(saved, "behaviour"); // its settings page: task, schedule, instructions, model
      },
    });
    const form = m.el;
    const parentSel = form.querySelector('[name="parent"]');
    if (parentSel) {
      form.querySelector('[name="team"]').addEventListener("change", (e) => {
        setHTML(parentSel, html`${options(parentChoices(e.target.value), leadOf(e.target.value))}`);
      });
    }
  }

  function runModal(a) {
    modal({
      title: `Run ${a.name} now`,
      minRole: "operator",
      submit: "Run now",
      body: html`${a.outside_guardrails ? html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div class="muted">May not act: ${a.outside_guardrails}</div></div>` : ""}
        ${field("Task", html`<textarea name="task" rows="4" maxlength="4000" placeholder="${a.task || "Describe the task"}"></textarea>`,
          a.task ? "Leave empty to run its standing task; anything you type runs once instead." : "It has no standing task: describe what it should do.")}
        <p class="faint" style="font-size:12.5px">Commands and patches it asks for go through the Operator policy and the approval queue as usual.</p>`,
      async onSubmit(data, form) {
        const task = String(data.get("task") || "").trim();
        if (!task && !a.task) {
          toast("Describe the task", "bad");
          return true;
        }
        const btn = form.querySelector('button[type="submit"]');
        btn.textContent = "Running...";
        const r = await post(`/agents/${enc(a.id)}/run`, task ? { task } : {}).finally(() => { btn.textContent = "Run now"; });
        resultModal(r.agent || a, r);
        reload();
      },
    });
  }

  function proposeModal(t) {
    const ready = t.lead?.llm_active; // the tool's supervisor has an AI model for designing
    modal({
      title: `Propose a team for ${t.name}`,
      minRole: "operator",
      submit: "Propose",
      body: html`<p class="muted" style="margin-bottom:12px">${t.lead?.name || "The tool supervisor"} proposes the team${t.category_title ? html` for a <b>${t.category_title}</b> tool` : ""}.
          ${overview.limits?.team_requires_approval ? "The proposal waits in Approvals (unless the hub is autonomous)." : html`<b>New teams need no approval</b> (guardrail off): the agents are created at once.`}</p>
        ${t.suggested?.length ? html`<p style="font-size:12.5px;margin-bottom:12px">Template roles: ${t.suggested.join(", ")}</p>` : ""}
        <div class="stack" style="gap:8px">${DESIGNERS.map(([value, title, text]) => html`<label class="radio-card">
          <input type="radio" name="designer" value="${value}" ${value === "auto" ? "checked" : ""} ${value === "model" && !ready ? "disabled" : ""}>
          <div><b>${title}</b><p class="muted">${text}${value === "model" && !ready ? " (No AI model is connected.)" : ""}</p></div></label>`)}</div>`,
      async onSubmit(data, form) {
        const btn = form.querySelector('button[type="submit"]');
        btn.textContent = "Designing...";
        const r = await post(`/tools/${enc(t.team)}/team`, { designer: data.get("designer") || "auto" }).finally(() => { btn.textContent = "Propose"; });
        proposalResult(t, r);
        reload();
      },
    });
  }

  function proposalResult(t, r) {
    modal({
      title: r.approval_id ? "Team proposed" : r.created?.length ? "Team created" : "Nothing proposed",
      wide: true, cancel: "Close",
      submit: r.approval_id ? "Open approvals" : null,
      onSubmit: () => { location.hash = "#/approvals"; },
      body: html`<p class="muted" style="margin-bottom:12px">${r.detail || ""}</p>
        ${(r.members || []).length ? html`<div class="stack" style="gap:8px">${r.members.map((x) => proposedMember(x, providerLabels()))}</div>` : ""}
        ${(r.skipped || []).length ? html`<p class="faint" style="font-size:12.5px;margin-top:10px">Skipped: ${r.skipped.map((s) => `${s.name} (${s.reason})`).join("; ")}</p>` : ""}`,
    });
  }

  drawGroups();
  drawChat();
  ctx.live(["agent", "agent_removed", "approval", "llm_provider", "llm_selection", "agent_settings", "tool", "tool_removed"], reload, 400);
  ctx.live(["message"], async () => {
    messages = await get("/messages?limit=80");
    const stream = el.querySelector("#msg-stream");
    if (stream) setHTML(stream, streamView(messages));
  }, 400);
  setHTML(el.querySelector("#msg-stream"), streamView(messages));
}

/** A member of a team proposal (approvals and the propose result share it). */
export function proposedMember(m, labels = {}) {
  return html`<div class="sub-card">
    <div class="row" style="gap:6px"><b>${m.name}</b><span class="faint" style="font-size:12px">${m.title}</span><span class="spacer"></span>
      ${badge(!m.provider ? "Default model" : m.provider === "anthropic" ? "Claude" : m.provider === "rules" ? "Rules" : labels[m.provider] || m.provider, m.provider === "rules" ? "" : m.provider === "anthropic" || m.provider === "openai" || !m.provider ? "accent" : "info")}</div>
    ${m.description ? html`<p class="muted" style="font-size:12.5px;margin-top:4px">${m.description}</p>` : ""}
    <div class="tag-list" style="margin-top:6px">${(m.permissions || []).map((p) => badge(p))}${(m.permissions || []).length ? "" : html`<span class="faint" style="font-size:12px">no permissions</span>`}
      ${(m.clamped || []).length ? html`<span class="badge warn" title="The parent lacks these (guardrail limit_to_parent_permissions)">not granted: ${m.clamped.join(", ").replace(/_/g, " ")}</span>` : ""}</div>
    ${m.schedule_minutes && m.task ? html`<p style="font-size:12.5px;margin-top:6px">${icon("refresh")} ${scheduleLabel(m.schedule_minutes)}: ${m.task}</p>`
      : m.task ? html`<p style="font-size:12.5px;margin-top:6px">Task: ${m.task}</p>` : ""}
    ${m.instructions ? html`<details style="margin-top:6px"><summary class="faint" style="cursor:pointer;font-size:12px">Instructions</summary>
      <pre class="code wrap" style="font-size:12px;margin-top:6px">${m.instructions}</pre></details>` : ""}
  </div>`;
}
