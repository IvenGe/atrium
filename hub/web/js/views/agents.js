import { del, get, patch, post } from "../api.js";
import { scheduleLabel } from "../flows.js";
import { actions, badge, builtinIcon, can, colorFor, confirmDialog, field, html, icon, md, modal, options, setHTML, timeAgo, timeIn, toast } from "../ui.js";

// Chat transcripts (one per agent) survive navigation inside the app; redraw belongs to the Agents page currently shown.
const chat = { agent: "supervisor", logs: {}, busy: new Set(), redraw: null };

/** Forget the transcripts, e.g. on sign-out, so the next person starts fresh. */
export function resetChat() {
  chat.agent = "supervisor";
  chat.logs = {};
  chat.busy = new Set();
}

const GROUPS = [
  ["Orchestration", (a) => a.role === "supervisor"],
  ["Specialists", (a) => a.role === "patcher" || a.role === "operator"],
  ["App supervisors - built-in apps", (a) => a.role === "module-supervisor"],
];
const ROLE_ICON = { supervisor: "bot", patcher: "wrench", operator: "terminal", "module-supervisor": "shield", "tool-supervisor": "grid", "team-agent": "bot" };
const PROVIDER_ICON = { anthropic: "bot", local: "server", rules: "sliders" };
const MODE = { llm: "Claude", local: "local model", rules: "rules" };
const DESIGNERS = [
  ["auto", "Automatic", "Claude designs the team when it is connected; otherwise the templates for this kind of tool."],
  ["templates", "Templates", "Roles proven for this kind of tool (SIEM, GRC, inventory, scanner) plus a maintainer."],
  ["claude", "Claude", "Claude reads the tool's manifest and designs the roles, tasks and permissions."],
];
const enc = encodeURIComponent;
const chatty = (a) => a.id === "supervisor" || a.kind === "custom";

function providerBadge(a) {
  const kind = a.provider_kind || (a.uses_llm ? "anthropic" : "rules");
  const usable = kind === "rules" || a.llm_active;
  const tone = !usable ? "warn" : kind === "anthropic" ? "accent" : kind === "local" ? "info" : "";
  const text = kind === "local" ? `Local: ${a.provider_label}` : kind === "anthropic" ? "Claude" : "Rules";
  const tip = !usable ? (kind === "anthropic" ? "Claude is not connected - the agent cannot use a model"
    : "This provider has not passed a test yet (Settings > AI providers)") : a.model || text;
  return html`<span class="badge ${tone}" title="${tip}">${icon(PROVIDER_ICON[kind] || "bot")}${text}</span>`;
}

function agentCard(a) {
  const tone = a.status === "working" ? "working" : a.status === "paused" ? "warn" : "ok";
  return html`<div class="card agent-card">
    <div class="head">${builtinIcon(a.id === "module:assets" ? "box" : ROLE_ICON[a.role] || "bot", a.role === "tool-supervisor" ? colorFor(a.scope) : "#7c3aed", "sm")}
      <div style="flex:1;min-width:0"><b>${a.name}</b><div class="faint" style="font-size:12px">${a.title}</div></div>
      <span class="row" style="gap:6px;font-size:12px"><span class="dot ${tone}"></span>${a.status}</span></div>
    <div class="desc">${a.description}</div>
    <div class="meta"><span>${a.handled} handled</span>${a.errors ? html`<span style="color:var(--bad)">${a.errors} errors</span>` : ""}
      ${a.queued ? html`<span>${a.queued} queued</span>` : ""}<span>${a.last_active ? `active ${timeAgo(a.last_active)}` : "not active yet"}</span></div>
    <div class="row" style="justify-content:space-between">
      <span class="row" style="gap:6px">${a.uses_llm ? (a.llm_active ? badge(a.model, "accent") : badge("rules mode")) : badge("deterministic")}
        ${a.custom_instructions ? badge("custom instructions", "info") : ""}</span>
      ${coreButtons(a)}</div>
  </div>`;
}

function coreButtons(a) {
  return html`<span class="row" style="gap:6px">
    <button class="btn sm" data-act="toggle" data-id="${a.id}" data-paused="${a.paused}" data-min-role="admin">${icon(a.paused ? "play" : "pause")}${a.paused ? "Resume" : "Pause"}</button>
    <button class="btn sm" data-act="configure" data-id="${a.id}" data-min-role="admin">${icon("sliders")}Configure</button></span>`;
}

/** The lead of a team (a core agent): compact, with the same pause/configure controls as its card. */
function leadRow(a) {
  const tone = a.status === "working" ? "working" : a.status === "paused" ? "warn" : "ok";
  return html`<div class="team-lead">
    ${builtinIcon(ROLE_ICON[a.role] || "bot", a.role === "tool-supervisor" ? colorFor(a.scope) : "#7c3aed", "sm")}
    <div style="flex:1 1 150px;min-width:0"><div class="row" style="gap:6px"><b>${a.name}</b>${badge("lead", "accent")}</div>
      <div class="faint" style="font-size:12px"><span class="dot ${tone}"></span> ${a.status} - ${a.handled} handled${a.last_active ? ` - active ${timeAgo(a.last_active)}` : ""}</div></div>
    ${a.id === "supervisor" ? html`<button class="icon-btn sm" data-act="chat-with" data-id="${a.id}" title="Chat with ${a.name}" aria-label="Chat with ${a.name}" data-min-role="operator">${icon("chat")}</button>` : ""}
    ${coreButtons(a)}</div>`;
}

function memberRow(a, leadId) {
  const r = a.last_result;
  const notGranted = (a.permissions || []).filter((p) => !(a.effective_permissions || []).includes(p));
  const state = !a.enabled ? badge("disabled") : a.running ? badge("running") : a.outside_guardrails ? badge("held", "warn") : "";
  const schedule = a.schedule_minutes && a.task ? html`<span title="${a.task}">${icon("refresh")} ${scheduleLabel(a.schedule_minutes)}${a.next_run ? ` - next ${timeIn(a.next_run)}` : ""}</span>`
    : html`<span>no schedule</span>`;
  return html`<div class="member" style="${a.depth > 1 ? `margin-left:${(a.depth - 1) * 18}px` : ""}">
    <div class="member-head">${builtinIcon("bot", colorFor(a.id), "sm")}
      <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><b>${a.name}</b><span class="faint" style="font-size:12px">${a.title}</span></div>
        <div class="row" style="gap:6px;margin-top:4px">${providerBadge(a)}${a.model ? html`<span class="faint mono" style="font-size:11.5px">${a.model}</span>` : ""}${state}</div></div>
      <span class="row" style="gap:2px;flex-wrap:nowrap">
        <button class="icon-btn sm" data-act="chat-with" data-id="${a.id}" title="Chat" aria-label="Chat with ${a.name}" data-min-role="operator" ${a.enabled ? "" : "disabled"}>${icon("chat")}</button>
        <button class="icon-btn sm" data-act="run" data-id="${a.id}" title="Run now" aria-label="Run ${a.name} now" data-min-role="operator" ${a.enabled && !a.running ? "" : "disabled"}>${icon("play")}</button>
        <button class="icon-btn sm" data-act="edit" data-id="${a.id}" title="${can("admin") ? "Edit" : "Details"}" aria-label="${can("admin") ? "Edit" : "Details of"} ${a.name}">${icon(can("admin") ? "edit" : "file")}</button>
        <button class="icon-btn sm danger" data-act="remove" data-id="${a.id}" title="Remove" aria-label="Remove ${a.name}" data-min-role="admin">${icon("trash")}</button></span></div>
    ${a.description ? html`<div class="desc">${a.description}</div>` : ""}
    <div class="tag-list">${(a.effective_permissions || []).map((p) => badge(p))}
      ${notGranted.length ? html`<span class="badge warn" title="Not granted: the parent does not have these (guardrail limit_to_parent_permissions)">not granted: ${notGranted.join(", ").replace(/_/g, " ")}</span>` : ""}</div>
    <div class="meta">${schedule}
      ${r ? html`<button type="button" class="chip-link" data-act="result" data-id="${a.id}">${r.ok ? "last run ok" : "last run failed"} ${timeAgo(r.at)}</button>` : html`<span>never run</span>`}
      ${a.parent && a.parent !== leadId ? html`<span>reports to ${a.parent}</span>` : ""}</div>
    ${a.outside_guardrails ? html`<div class="notice warn">${icon("alert")}<div style="font-size:12.5px;min-width:0">May not act: ${a.outside_guardrails}</div></div>` : ""}
  </div>`;
}

function teamCard(t) {
  const full = t.max_size != null && t.size >= t.max_size;
  const kind = t.kind === "tool" ? t.category_title || "Tool" : t.kind === "hub" ? "Hub" : "Built-in app";
  return html`<section class="card team-card">
    <header><div style="min-width:0"><h2>${t.name}</h2>
        <div class="faint" style="font-size:12px">${kind} - ${t.size}${t.max_size != null ? ` of ${t.max_size}` : ""} team agent${t.size === 1 ? "" : "s"}</div></div>
      <span class="row" style="gap:6px">
        ${t.pending_approval ? html`<a class="badge warn" href="#/approvals">proposal waiting</a>` : ""}
        ${t.can_propose && !t.pending_approval ? html`<button class="btn sm" data-act="propose" data-team="${t.team}" data-min-role="operator">${icon("users")}Propose team</button>` : ""}
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
      <p class="faint" style="font-size:12.5px;margin-bottom:10px">Each tool's supervisor leads its team. Team agents run on Claude, a local model or rules, with only the permissions they are given.</p>
      ${teams.length ? html`<div class="team-grid">${teams.map(teamCard)}</div>` : html`<p class="faint">Import a tool to give it a team.</p>`}</div>`;
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
    ${a ? html`<div class="row" style="gap:6px;margin-bottom:8px;font-size:12px">${providerBadge(a)}${a.model ? html`<span class="faint mono">${a.model}</span>` : ""}
      ${off ? badge(a.kind === "custom" ? "disabled" : "paused", "warn") : ""}${a.outside_guardrails ? badge("held", "warn") : ""}</div>` : ""}
    <div class="msgs" id="chat-msgs">${log.length ? html`${log.map((m) => html`<div class="bubble ${m.me ? "me" : "bot"}">${m.me ? m.text : md(m.text)}
        ${!m.me && m.mode && m.mode !== "llm" ? html`<div class="faint" style="font-size:11px;margin-top:4px">via ${MODE[m.mode] || m.mode}</div>` : ""}</div>`)}
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
      <div class="prose-box">${md(r.reply || "")}</div>`,
  });
}

export async function render(el, ctx) {
  let [agents, overview, messages] = await Promise.all([get("/agents"), get("/agents/teams"), get("/messages?limit=80")]);
  const find = (id) => agents.find((x) => x.id === id);
  const providerLabels = () => Object.fromEntries(overview.providers.map((p) => [p.id, p.label]));

  setHTML(el, html`
    <div class="page-head"><div><h1>Agents</h1><p class="muted">The Hub Supervisor talks to every agent. Each app has its own supervisor; tool supervisors lead their tool's team of AI agents.</p></div>
      <button class="btn primary" data-act="new" data-min-role="admin">${icon("plus")}New agent</button></div>
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
  const drawGroups = () => setHTML(groupsEl, groupsView(agents, overview));
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
    [agents, overview] = await Promise.all([get("/agents"), get("/agents/teams")]);
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
      log.push({ me: false, text: reply.reply, mode: reply.mode });
    } catch (err) {
      log.push({ me: false, text: `Error: ${err.message}` });
    } finally {
      busy.delete(id);
      if (logs === chat.logs && chat.agent === id) chat.redraw?.();
    }
  });
  el.addEventListener("change", (e) => {
    if (e.target.id !== "chat-agent") return;
    chat.agent = e.target.value;
    drawChat(true);
  });

  actions(el, {
    async toggle(d) {
      await patch(`/agents/${enc(d.id)}`, { paused: d.paused !== "true" }).catch((e) => toast(e.message, "bad"));
    },
    configure(d) {
      const a = find(d.id);
      if (a) configureCore(a);
    },
    new(d) { agentForm(null, d.team || "hub"); },
    edit(d) {
      const a = find(d.id);
      if (a) agentForm(a, a.team);
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

  function configureCore(a) {
    modal({
      title: `Configure ${a.name}`,
      wide: true,
      minRole: "admin",
      body: html`<p class="muted" style="margin-bottom:12px">${a.description}</p>
        ${a.uses_llm ? html`${field("Model", html`<input name="model" list="models" value="${a.model_override || ""}" placeholder="Default: ${a.model}">
          <datalist id="models"><option value="claude-opus-5-5"><option value="claude-sonnet-5-5"><option value="claude-haiku-5-5"><option value="claude-fable-5-1"></datalist>`,
          "Leave empty to use the hub default from Settings.")}
          ${field("Instructions (system prompt)", html`<textarea name="instructions" rows="12" class="mono" style="font-size:12.5px">${a.instructions}</textarea>`,
            "Clear the box to restore the built-in instructions.")}`
        : html`<p>This agent is deterministic - it follows the hub's policies and has no model to configure.</p>`}`,
      async onSubmit(data) {
        if (!a.uses_llm) return;
        const instructions = String(data.get("instructions") ?? "");
        await patch(`/agents/${enc(a.id)}`, {
          model: String(data.get("model") ?? ""),
          instructions: instructions.trim() === a.instructions.trim() && !a.custom_instructions ? "" : instructions,
        });
        toast(`${a.name} updated`, "ok");
      },
    });
  }

  function parentChoices(team, self) {
    const t = overview.teams.find((x) => x.team === team);
    const out = t?.lead ? [[t.lead.id, `${t.lead.name} (lead)`]] : [];
    for (const m of t?.members || []) if (m.id !== self) out.push([m.id, `${m.name} - ${m.title}`]);
    return out;
  }

  function agentForm(a, teamId) {
    const providers = overview.providers;
    const limits = overview.limits || {};
    const fallback = (providers.find((p) => p.id === "anthropic" && p.available) || providers.find((p) => p.kind === "local" && p.available) || { id: "rules" }).id;
    const provider = a?.provider || fallback;
    const perms = new Set(a ? a.permissions : ["read"]);
    const team = a?.team || teamId;
    const nested = limits.allow_nested_teams;
    const leadOf = (tid) => overview.teams.find((x) => x.team === tid)?.lead?.id;
    const models = (pid) => providers.find((p) => p.id === pid) || {};
    const m = modal({
      title: a ? `${can("admin") ? "Edit" : ""} ${a.name}`.trim() : "New agent",
      wide: true,
      minRole: "admin",
      submit: a ? "Save" : "Create agent",
      body: html`
        <div class="form-grid">
          ${field("Name", html`<input name="name" required maxlength="80" value="${a?.name || ""}" placeholder="e.g. Alert triage analyst">`)}
          ${field("Role", html`<input name="title" maxlength="80" value="${a?.title || "Team agent"}">`)}
        </div>
        ${field("Description", html`<input name="description" maxlength="1000" value="${a?.description || ""}" placeholder="What this agent is for">`)}
        <div class="form-grid">
          ${field("Team", html`<select name="team">${options(overview.teams.map((t) => [t.team, t.kind === "tool" ? t.name : `${t.name} (${t.kind === "hub" ? "hub" : "built-in app"})`]), team)}</select>`,
            "The tool (or app) it works on; its supervisor leads the team.")}
          ${nested ? field("Reports to", html`<select name="parent">${options(parentChoices(team, a?.id), a?.parent || leadOf(team))}</select>`,
            `Nested teams are allowed up to depth ${limits.max_team_depth}.`) : html`<div></div>`}
        </div>
        <div class="form-grid">
          ${field("Runs on", html`<select name="provider">${options(providers.map((p) => [p.id, `${p.kind === "local" ? `Local: ${p.label}` : p.label}${p.available ? "" : " (not available)"}`]), provider)}</select>`,
            html`Local providers are added in <a href="#/settings">Settings &gt; AI providers</a>.`)}
          ${field("Model", html`<input name="model" list="agent-models" maxlength="200" value="${a?.model_override || ""}" placeholder="${models(provider).default_model ? `Default: ${models(provider).default_model}` : "Provider default"}">
            <datalist id="agent-models">${(models(provider).models || []).map((x) => html`<option value="${x}">`)}</datalist>`, "Leave empty for the provider's default.")}
        </div>
        ${field("Permissions", html`<div class="check-grid perm-grid">${overview.permissions.map((p) => html`<label class="check" title="${p.description}">
            <input type="checkbox" name="perm" value="${p.id}" ${perms.has(p.id) ? "checked" : ""}><span>${p.id.replace(/_/g, " ")}</span></label>`)}</div>`,
          limits.limit_to_parent_permissions ? "Permissions the parent agent lacks are not granted (guardrail). Hover a permission for what it allows." : "Hover a permission for what it allows.")}
        <div class="form-grid">
          ${field("Schedule (minutes)", html`<input type="number" name="schedule_minutes" min="0" max="525600" step="1" value="${a?.schedule_minutes ?? 0}">`, "0 = only when asked; otherwise at least 5.")}
          <label class="check" style="align-self:center"><input type="checkbox" name="enabled" ${a?.enabled === false ? "" : "checked"}><span>Enabled</span></label>
        </div>
        ${field("Standing task", html`<textarea name="task" rows="3" maxlength="4000" placeholder="What it does on its schedule or when you press Run now">${a?.task || ""}</textarea>`)}
        ${field("Instructions (system prompt)", html`<textarea name="instructions" rows="6" class="mono" style="font-size:12.5px" maxlength="20000" placeholder="Default: the name, role and description">${a?.custom_instructions ? a.instructions : ""}</textarea>`)}
        ${a ? html`<p class="faint" style="font-size:12px">Created by ${a.created_by || "-"} ${timeAgo(a.created_at)}${a.updated_by ? ` - changed by ${a.updated_by} ${timeAgo(a.updated_at)}` : ""}</p>` : ""}`,
      async onSubmit(data) {
        const schedule = Number(data.get("schedule_minutes") || 0);
        if (!Number.isInteger(schedule) || (schedule !== 0 && (schedule < 5 || schedule > 525600))) {
          toast("The schedule is 0 or a whole number of minutes from 5 to 525600", "bad");
          return true;
        }
        const body = {
          name: String(data.get("name") || "").trim(), title: String(data.get("title") || "").trim() || "Team agent",
          description: String(data.get("description") || ""), team: String(data.get("team")),
          provider: String(data.get("provider")), model: String(data.get("model") || "").trim(),
          permissions: data.getAll("perm").map(String), schedule_minutes: schedule, task: String(data.get("task") || ""),
          instructions: String(data.get("instructions") || ""), enabled: data.get("enabled") === "on",
        };
        if (!body.name) {
          toast("Give the agent a name", "bad");
          return true;
        }
        const parent = data.get("parent");
        if (parent && parent !== a?.parent) body.parent = String(parent);
        const saved = a ? await patch(`/agents/${enc(a.id)}`, body) : await post("/agents", body);
        if (saved.clamped?.length) toast(`Not granted (the parent lacks them): ${saved.clamped.join(", ")}`, "warn");
        toast(a ? `${saved.name} updated` : `${saved.name} created`, "ok");
        reload();
      },
    });
    const form = m.el;
    form.querySelector('[name="provider"]').addEventListener("change", (e) => {
      const p = models(e.target.value);
      form.querySelector('[name="model"]').placeholder = p.default_model ? `Default: ${p.default_model}` : "Provider default";
      setHTML(form.querySelector("#agent-models"), html`${(p.models || []).map((x) => html`<option value="${x}">`)}`);
    });
    const parentSel = form.querySelector('[name="parent"]');
    if (parentSel) {
      form.querySelector('[name="team"]').addEventListener("change", (e) => {
        setHTML(parentSel, html`${options(parentChoices(e.target.value, a?.id), leadOf(e.target.value))}`);
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
    const claude = overview.providers.find((p) => p.id === "anthropic")?.available;
    modal({
      title: `Propose a team for ${t.name}`,
      minRole: "operator",
      submit: "Propose",
      body: html`<p class="muted" style="margin-bottom:12px">${t.lead?.name || "The tool supervisor"} proposes the team${t.category_title ? html` for a <b>${t.category_title}</b> tool` : ""}.
          ${overview.limits?.team_requires_approval ? "The proposal waits in Approvals (unless the hub is autonomous)." : html`<b>New teams need no approval</b> (guardrail off): the agents are created at once.`}</p>
        ${t.suggested?.length ? html`<p style="font-size:12.5px;margin-bottom:12px">Template roles: ${t.suggested.join(", ")}</p>` : ""}
        <div class="stack" style="gap:8px">${DESIGNERS.map(([value, title, text]) => html`<label class="radio-card">
          <input type="radio" name="designer" value="${value}" ${value === "auto" ? "checked" : ""} ${value === "claude" && !claude ? "disabled" : ""}>
          <div><b>${title}</b><p class="muted">${text}${value === "claude" && !claude ? " (Claude is not connected.)" : ""}</p></div></label>`)}</div>`,
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
  ctx.live(["agent", "agent_removed", "approval", "llm_provider", "tool", "tool_removed"], reload, 400);
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
      ${badge(m.provider === "anthropic" ? "Claude" : m.provider === "rules" ? "Rules" : `Local: ${labels[m.provider] || m.provider}`, m.provider === "rules" ? "" : m.provider === "anthropic" ? "accent" : "info")}</div>
    ${m.description ? html`<p class="muted" style="font-size:12.5px;margin-top:4px">${m.description}</p>` : ""}
    <div class="tag-list" style="margin-top:6px">${(m.permissions || []).map((p) => badge(p))}${(m.permissions || []).length ? "" : html`<span class="faint" style="font-size:12px">no permissions</span>`}
      ${(m.clamped || []).length ? html`<span class="badge warn" title="The parent lacks these (guardrail limit_to_parent_permissions)">not granted: ${m.clamped.join(", ").replace(/_/g, " ")}</span>` : ""}</div>
    ${m.schedule_minutes && m.task ? html`<p style="font-size:12.5px;margin-top:6px">${icon("refresh")} ${scheduleLabel(m.schedule_minutes)}: ${m.task}</p>`
      : m.task ? html`<p style="font-size:12.5px;margin-top:6px">Task: ${m.task}</p>` : ""}
    ${m.instructions ? html`<details style="margin-top:6px"><summary class="faint" style="cursor:pointer;font-size:12px">Instructions</summary>
      <pre class="code wrap" style="font-size:12px;margin-top:6px">${m.instructions}</pre></details>` : ""}
  </div>`;
}
