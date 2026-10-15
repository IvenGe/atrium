// The agent settings page (#/agents/<id>/settings[/<tab>]), reached from the Agents page: what model an agent runs
// on and why (Overview); its own model choice and parameters (Model); instructions, reply language and memory, and for
// a custom agent its definition (Behaviour); the tools it may use (Tools); budgets and rate limits (Limits); trying a
// prompt on the saved settings or the unsaved draft, against a second model (Playground); when it escalates to a
// person, pausing its schedule after failed runs, and its notifications (Escalation; "Notifications" for agents that do
// not chat); and earlier versions to restore (History). Viewers read; administrators edit one draft for all tabs and save it with the version they read;
// leaving with unsaved changes asks first.
import { get, patch, post } from "../api.js";
import { columns, table } from "../dashboard/charts.js";
import {
  LANGUAGES, budgetText, capsAllowTemperature, capsUnknown, chainLine, changeWords, cleanRules, diffSettings, effectiveText, effortChoices,
  errorPath, languageChoice, meterTone, modelLabel, settingsBody, sourceLabel, tabOf, tokenCapWarning,
} from "../llm.js";
import { actions, badge, builtinIcon, can, colorFor, confirmDialog, emptyState, html, icon, md, modal, raw, setHTML, timeAgo, toast } from "../ui.js";

const TAB_LABELS = { overview: "Overview", model: "Model", behaviour: "Behaviour", tools: "Tools", limits: "Limits", escalation: "Escalation",
  playground: "Playground", history: "History" };
const TASKS = { code: "Code changes (patches, self-patches)", generate: "Structured generation (connectors, extensions, team designs)" };
const PURPOSES = { chat: "Chat and agent tasks", code: "Code changes", generate: "Structured generation" };
const ROLE_ICON = { supervisor: "bot", patcher: "wrench", operator: "terminal", "module-supervisor": "shield", "tool-supervisor": "grid", "team-agent": "bot" };
const MEMORY = [["off", "Off", "Every message starts afresh: the agent remembers nothing."],
  ["session", "Session", "Kept per person until the hub restarts (the default)."],
  ["persisted", "Kept", "Stored encrypted per person, deleted after the retention period without a message."]];
const enc = encodeURIComponent;
const clone = (v) => JSON.parse(JSON.stringify(v));
const num = (n) => Number(n || 0).toLocaleString("en-US");
const usd = (n) => `$${Number(n || 0).toFixed(2)}`;
function setPath(obj, path, value) {
  const keys = path.split(".");
  const last = keys.pop();
  const parent = keys.reduce((o, k) => (o[k] ??= {}), obj);
  parent[last] = value;
}
const dis = (admin) => (admin ? "" : raw("disabled"));

/** The provider list of a select, with each provider this agent may not use disabled and the reason as text. */
function providerOptions(view, providers, draft, first, value) {
  const localOnly = draft.config.local_only || view.effective?.local_only_from === "team";
  const sel = (v) => (v === (value || "") ? raw("selected") : "");
  return html`${first.map(([v, l]) => html`<option value="${v}" ${sel(v)}>${l}</option>`)}
    ${providers.filter((p) => p.id !== "rules").map((p) => {
      const blocked = localOnly && p.location === "third_party" ? "cloud provider - this agent is local-only"
        : /cloud providers are switched off/.test(p.reason || "") ? "cloud providers are switched off (guardrail)" : null;
      const why = blocked || (p.available ? "" : `not available: ${p.reason || "unknown"}`);
      return html`<option value="${p.id}" ${blocked && p.id !== value ? raw("disabled") : ""} ${sel(p.id)}>${p.label}${why ? ` (${why})` : ""}</option>`;
    })}
    <option value="rules" ${sel("rules")}>Rules (no AI model)</option>`;
}

function modelField(id, choice, providers, label, admin) {
  const p = providers.find((x) => x.id === choice?.provider);
  const models = p ? [...new Set([...(p.pinned_models || []), ...(p.models || [])])] : [];
  const caps = p && choice?.model ? p.capabilities?.[choice.model] : p ? p.capabilities?.[p.default_model] : null;
  const model = choice?.model || p?.default_model || "";
  const off = !p || p.id === "rules";
  return html`<div class="field"><label for="${id}">${label}</label>
    <input id="${id}" data-model list="${id}-list" maxlength="200" value="${off ? "" : choice?.model || ""}" ${off || !admin ? "disabled" : ""}
      placeholder="${p?.default_model ? `Provider default (${p.default_model})` : off ? "-" : "Provider default"}">
    <datalist id="${id}-list">${models.map((m) => html`<option value="${m}">`)}</datalist>
    ${admin && !off && model && p.kind !== "anthropic" && capsUnknown(caps) ? html`<span class="hint">Tools and JSON support of ${model} are not known yet.
      <button type="button" class="btn sm" data-act="probe" data-provider="${p.id}" data-model="${model}">${icon("activity")}Check tools and JSON</button></span>` : ""}</div>`;
}

/** A number input bound to a draft path: empty = no limit / the default (`nullable`). */
function numberField(path, label, value, { min, max, step = 1, hint = "", nullable = true, admin, placeholder = "" }) {
  const id = `as-${path.replace(/\./g, "-")}`;
  return html`<div class="field"><label for="${id}">${label}</label>
    <input id="${id}" type="number" inputmode="decimal" data-path="${path}" data-type="${nullable ? "number-null" : "number"}" min="${min ?? ""}" max="${max ?? ""}"
      step="${step}" value="${value ?? ""}" placeholder="${placeholder}" ${dis(admin)} ${hint ? raw(`aria-describedby="${id}-hint"`) : ""}>
    ${hint ? html`<span class="hint" id="${id}-hint">${hint}</span>` : ""}</div>`;
}

function meterLine(label, spent, limit, text) {
  if (limit == null) return html`<div class="meter-line"><span>${label}</span><span class="faint">${text} (no limit)</span></div>`;
  return html`<div class="meter-line"><span>${label}</span>
    <meter min="0" max="${limit}" low="${limit * 0.8}" high="${limit * 0.9999}" optimum="0" value="${Math.min(Number(spent || 0), limit)}" aria-label="${label}: ${text}"></meter>
    <span class="${meterTone(spent, limit) === "bad" ? "warn-text" : ""}">${text}</span></div>`;
}

function limitsSummary(view) {
  const s = view.budget_state;
  if (!s) return "";
  return html`${meterLine("Cost today", s.spent_today, s.limit, budgetText(s))}
    ${meterLine("Tokens today", s.tokens_today, s.token_limit, `${num(s.tokens_today)}${s.token_limit != null ? ` of ${num(s.token_limit)}` : ""} tokens`)}
    ${s.monthly_limit != null ? meterLine("Cost this month", s.spent_month, s.monthly_limit, `${usd(s.spent_month)} of ${usd(s.monthly_limit)}`) : ""}`;
}

function overviewTab(view, agent) {
  if (!view.uses_model) {
    return html`<p class="muted">${view.name} works without an AI model: it follows the hub's rules and policies, so there is no model to choose.</p>`;
  }
  const usage = view.usage;
  const days = usage?.days || [];
  const total = days.reduce((s, d) => ({ calls: s.calls + d.calls, cost: s.cost + d.cost_usd }), { calls: 0, cost: 0 });
  const t = usage?.today || {};
  const s = view.budget_state;
  return html`<div class="stack" style="gap:16px">
    ${Object.entries(view.effective.purposes || {}).map(([purpose, e]) => html`<section>
      <h3 class="as-h3">${Object.keys(view.effective.purposes).length > 1 ? PURPOSES[purpose] || purpose : "Model"}</h3>
      <p style="margin:0 0 6px">${badge(effectiveText(e), e.provider === "rules" ? (e.source === "rules" ? "warn" : "") : e.location === "third_party" ? "accent" : "info")}
        ${e.location === "third_party" ? html`<span class="faint" style="font-size:12px">cloud provider</span>` : e.location === "self_hosted" ? html`<span class="faint" style="font-size:12px">self-hosted</span>` : ""}</p>
      <ol class="chain-list" aria-label="How the model for ${(PURPOSES[purpose] || purpose).toLowerCase()} is chosen">${(view.chain[purpose] || []).map((row, n) => html`<li class="${row.status === "blocked" ? "blocked" : row.status === "used" ? "used" : "faint"}">
        ${chainLine(row, n + 1).replace(/^\d+\. /, "")}</li>`)}</ol></section>`)}
    ${view.effective.local_only ? html`<p class="faint" style="font-size:12.5px">${icon("lock")} Local only${view.effective.local_only_from === "team" ? ` (rule of the ${view.team_name} team)` : ""}: cloud providers are skipped.</p>` : ""}
    <section><h3 class="as-h3">Limits today</h3>${limitsSummary(view)}
      ${s?.stopped ? html`<p class="warn-text" style="font-size:12.5px">${icon("alert")} Stopped for today: new model calls are refused until 00:00 UTC (Limits tab).</p>` : ""}</section>
    <section><h3 class="as-h3">Usage</h3>
      <p class="faint" style="font-size:12.5px;margin:0 0 6px">Today (UTC): ${num(t.calls)} model call${t.calls === 1 ? "" : "s"}, ${num(t.input_tokens)} tokens in, ${num(t.output_tokens)} out,
        about ${usd(t.cost_usd)}. Last 30 days: ${num(total.calls)} call${total.calls === 1 ? "" : "s"}, about ${usd(total.cost)}. Costs are estimates from the price table.</p>
      ${total.calls ? html`${columns(days.map((d) => ({ day: d.day, count: d.calls })), { noun: "model calls" })}
        <details><summary class="faint" style="cursor:pointer;font-size:12.5px">Usage per day (table)</summary>
          ${table([{ label: "Day (UTC)" }, { label: "Calls", numeric: true }, { label: "Errors", numeric: true }, { label: "Tokens in", numeric: true },
            { label: "Tokens out", numeric: true }, { label: "Cost (USD, est.)", numeric: true }],
          days.filter((d) => d.calls).reverse().map((d) => [d.day, num(d.calls), num(d.errors), num(d.input_tokens), num(d.output_tokens), d.cost_usd.toFixed(4)]),
          { caption: `Model calls of ${view.name} per day` })}</details>` : html`<p class="faint" style="font-size:12.5px">No model calls in the last 30 days.</p>`}</section>
    ${agent?.kind === "custom" ? html`<section><h3 class="as-h3">Last run</h3>
      ${agent.last_result ? html`<p style="font-size:13px">${badge(agent.last_result.skipped ? "skipped" : agent.last_result.ok ? "ok" : "failed", agent.last_result.ok ? "ok" : agent.last_result.skipped ? "warn" : "bad")} ${agent.last_result.trigger || ""} ${timeAgo(agent.last_result.at)}
        ${agent.last_result.mode ? html`<span class="faint">via ${agent.last_result.mode}</span>` : ""}</p>` : html`<p class="faint" style="font-size:12.5px">Never run.</p>`}</section>` : ""}
  </div>`;
}

function paramsSection(view, draft, admin) {
  const primary = view.purposes[0];
  const now = view.models?.[primary] || {};
  const caps = now.caps;
  const levels = effortChoices(caps, now.kind);
  const effort = draft.config.params.effort || "";
  const efforts = [...levels, ...(effort && !levels.includes(effort) ? [effort] : [])];
  const temp = draft.config.params.temperature;
  const allowsTemp = capsAllowTemperature(caps, now.kind);
  const modelName = now.model ? modelLabel({ id: now.provider }, now.model) : "This model";
  const warning = tokenCapWarning(draft.config.params.max_output_tokens, view.call_tokens);
  return html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Parameters</legend>
    <p class="faint" style="font-size:12.5px;margin:0 0 8px">For the model this agent runs on now: ${now.model ? `${modelName} (${now.provider})` : "no model"}. They apply to every model call of the agent.</p>
    <div class="form-grid">
      <div class="field"><label for="as-effort">Effort</label>
        <select id="as-effort" data-path="config.params.effort" data-type="text" aria-describedby="as-effort-hint">
          <option value="" ${effort ? "" : raw("selected")}>Default for each task</option>
          ${efforts.map((e) => html`<option value="${e}" ${e === effort ? raw("selected") : ""}>${e}${levels.includes(e) ? "" : " (not supported by this model)"}</option>`)}</select>
        <span class="hint" id="as-effort-hint">More effort: better answers on hard tasks, more tokens. ${levels.length ? "" : "This model has no effort setting."}</span></div>
      ${numberField("config.params.max_output_tokens", "Max output tokens", draft.config.params.max_output_tokens, { min: 256, max: 200000, step: 256, admin,
        placeholder: "Each task's own", hint: warning || "A cap: no call of this agent asks for more. Empty: each task's own." })}
      ${view.chats ? numberField("config.params.max_tool_rounds", "Max tool rounds", draft.config.params.max_tool_rounds, { min: 1, max: 30, nullable: false, admin,
        hint: "How many times the agent may call tools in one answer (1-30)." }) : ""}
    </div>
    <div class="field"><span class="label" id="as-temp-label">Temperature</span>
      ${allowsTemp ? html`<label class="check"><input type="checkbox" data-act-change="temp-toggle" ${temp != null ? "checked" : ""}><span>Set a temperature (otherwise the model's default)</span></label>
        ${temp != null ? html`<div class="row" style="gap:8px;margin-top:6px"><input type="range" min="0" max="2" step="0.1" value="${temp}" data-path="config.params.temperature" data-type="number" aria-labelledby="as-temp-label" style="flex:1;max-width:260px">
          <input type="number" min="0" max="2" step="0.1" value="${temp}" data-path="config.params.temperature" data-type="number" aria-labelledby="as-temp-label" style="width:90px"></div>` : ""}`
        : html`<p class="faint" style="font-size:12.5px;margin:0">${modelName} sets its own sampling - use effort instead.</p>
          ${temp != null ? html`<p class="warn-text" style="font-size:12.5px">A temperature (${temp}) is set but this model refuses it.
            <button type="button" class="btn sm" data-act="temp-clear">Clear it</button></p>` : ""}`}</div>
  </fieldset>`;
}

function modelTab(view, providers, draft, admin) {
  const inherit = !draft.llm.provider;
  const primary = view.purposes[0];
  const inh = view.inherited?.[primary];
  const now = inh ? (inh.provider === "rules" ? "rules" : `${modelLabel({ id: inh.provider, label: inh.provider_label }, inh.model)} from ${sourceLabel(inh).toLowerCase()}`) : "";
  const teamRule = view.effective?.local_only_from === "team";
  return html`<div class="stack" style="gap:16px">
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Model</legend>
      <label class="radio-line"><input type="radio" name="llm-mode" value="inherit" ${inherit ? "checked" : ""} data-mode>
        <span>Inherit${now ? html` <span class="faint">(currently ${now})</span>` : ""}</span></label>
      <label class="radio-line"><input type="radio" name="llm-mode" value="choose" ${inherit ? "" : "checked"} data-mode><span>Choose a provider and model</span></label>
      ${inherit ? "" : html`<div class="choice-row" data-choice="llm">
        <div class="field"><label for="as-provider">Provider</label>
          <select id="as-provider" data-provider>${providerOptions(view, providers, draft, [], draft.llm.provider)}</select></div>
        ${modelField("as-model", draft.llm, providers, "Model", admin)}</div>`}
    </fieldset>
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Where it may run</legend>
      <label class="check"><input type="checkbox" data-local-only ${draft.config.local_only ? "checked" : ""} aria-describedby="as-local-hint">
        <span>Local only</span></label>
      <p class="hint faint" id="as-local-hint" style="font-size:12.5px;margin:4px 0 0">Keeps this agent on self-hosted models: cloud providers are skipped at every level, also in
        the suite default. It binds the agent, not the data: another agent on a cloud model can still read the same hub data through its tools.
        ${teamRule ? html`<b>Its team (${view.team_name}) is local-only already.</b>` : ""}</p>
    </fieldset>
    ${view.per_task.length ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Per task</legend>
      ${view.per_task.map((task) => {
        const c = draft.config.purposes[task] || { provider: "", model: "" };
        const same = view.inherited_task?.[task];
        const sameText = same ? (same.provider === "rules" ? "rules" : modelLabel({ id: same.provider, label: same.provider_label }, same.model)) : "";
        return html`<div class="choice-row" data-choice="task:${task}">
          <div class="field"><label for="as-task-${task}">${TASKS[task] || task}</label>
            <select id="as-task-${task}" data-provider>${providerOptions(view, providers, draft, [["", `Same as this agent${sameText ? ` (${sameText})` : ""}`]], c.provider)}</select></div>
          ${modelField(`as-task-${task}-model`, c, providers, `Model for ${(TASKS[task] || task).split(" (")[0].toLowerCase()}`, admin)}</div>`;
      })}</fieldset>` : ""}
    ${paramsSection(view, draft, admin)}
    <p class="faint" style="font-size:12.5px">Suite, task and team defaults are under <a href="#/settings/ai">Settings &gt; AI models</a>.</p>
  </div>`;
}

function behaviourTab(view, draft, admin, langOther = false) {
  const custom = view.kind === "custom";
  const replace = draft.config.instructions_mode === "replace";
  const lang = langOther ? "other" : languageChoice(draft.config.language);
  const suiteLang = view.language?.suite || "auto";
  const suiteText = suiteLang === "auto" ? "automatic" : (LANGUAGES.find(([c]) => c === suiteLang)?.[1] || suiteLang);
  const mem = draft.config.memory;
  return html`<div class="stack" style="gap:16px">
    ${custom ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Definition</legend>
      <div class="form-grid">
        <div class="field"><label for="as-name">Name</label><input id="as-name" data-path="name" data-type="text" maxlength="80" value="${draft.name}" required></div>
        <div class="field"><label for="as-title">Role</label><input id="as-title" data-path="title" data-type="text" maxlength="80" value="${draft.title}"></div></div>
      <div class="field"><label for="as-description">Description</label><input id="as-description" data-path="description" data-type="text" maxlength="1000" value="${draft.description}"></div>
      <div class="field"><label for="as-instructions">Instructions (system prompt)</label>
        <textarea id="as-instructions" data-path="instructions" data-type="text" rows="6" class="mono" style="font-size:12.5px" maxlength="20000" placeholder="Default: the name, role and description">${draft.instructions}</textarea>
        <span class="hint">A fixed part about acting only through tools and approvals is always added after them.</span></div>
      <div class="field"><label for="as-task">Standing task</label><textarea id="as-task" data-path="task" data-type="text" rows="3" maxlength="4000" placeholder="What it does on its schedule or when someone presses Run now">${draft.task}</textarea></div>
      <div class="form-grid">
        ${numberField("schedule_minutes", "Schedule (minutes)", draft.schedule_minutes, { min: 0, max: 525600, nullable: false, admin, hint: "0 = only when asked; otherwise at least 5." })}
        <label class="check" style="align-self:center"><input type="checkbox" data-path="enabled" data-type="bool" ${draft.enabled ? "checked" : ""}><span>Enabled</span></label></div>
    </fieldset>` : html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Instructions</legend>
      <details><summary class="faint" style="cursor:pointer;font-size:12.5px">Built-in instructions (${num(view.builtin_instructions.length)} characters)</summary>
        <pre class="mono as-builtin">${view.builtin_instructions}</pre></details>
      ${replace ? html`<div class="field"><label for="as-replace">Instructions (they replace the built-in ones)</label>
          <textarea id="as-replace" data-path="instructions" data-type="text" rows="12" class="mono" style="font-size:12.5px" maxlength="20000">${draft.instructions}</textarea>
          <span class="hint warn-text">Later improvements to the built-in instructions do not reach this agent while they are replaced.</span></div>`
        : html`<div class="field"><label for="as-extra">Additional instructions</label>
          <textarea id="as-extra" data-path="config.extra_instructions" data-type="text" rows="5" style="font-size:13px" maxlength="20000"
            placeholder="e.g. Always name the ids you looked up." aria-describedby="as-extra-hint">${draft.config.extra_instructions}</textarea>
          <span class="hint" id="as-extra-hint">Added after the built-in instructions in every model call of this agent; improvements to the built-in text still apply.</span></div>`}
      <label class="check"><input type="checkbox" data-act-change="replace-toggle" ${replace ? "checked" : ""}><span>Advanced: replace the built-in instructions</span></label>
    </fieldset>`}
    ${view.chats ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Reply language</legend>
      <div class="form-grid"><div class="field"><label for="as-language">Language</label>
        <select id="as-language" data-act-change="language">
          <option value="" ${lang === "" ? raw("selected") : ""}>Suite default (now ${suiteText})</option>
          <option value="auto" ${lang === "auto" ? raw("selected") : ""}>Automatic (the language people write in)</option>
          ${LANGUAGES.map(([c, l]) => html`<option value="${c}" ${lang === c ? raw("selected") : ""}>${l}</option>`)}
          <option value="other" ${lang === "other" ? raw("selected") : ""}>Other (a language code)</option></select>
        <span class="hint">Chat replies and run results. Ids, commands, code and quoted tool output stay unchanged.</span></div>
        ${lang === "other" ? html`<div class="field"><label for="as-language-code">Language code</label>
          <input id="as-language-code" data-path="config.language" data-type="text" maxlength="35" value="${draft.config.language}" placeholder="e.g. pt-BR"></div>` : ""}</div>
    </fieldset>
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Memory</legend>
      ${MEMORY.map(([value, label, hint]) => html`<label class="radio-line"><input type="radio" name="as-memory" value="${value}" data-path="config.memory.mode" data-type="text" data-redraw
          ${mem.mode === value ? "checked" : ""}><span>${label} <span class="faint">- ${hint}</span></span></label>`)}
      <div class="form-grid">
        ${mem.mode !== "off" ? numberField("config.memory.max_turns", "Max turns", mem.max_turns, { min: 2, max: 200, nullable: false, admin,
          hint: "A longer conversation starts afresh, with a notice in the reply." }) : ""}
        ${mem.mode === "persisted" ? numberField("config.memory.retention_days", "Retention (days)", mem.retention_days, { min: 1, max: 365, nullable: false, admin,
          hint: "Deleted after this many days without a message." }) : ""}</div>
      <p class="faint" style="font-size:12.5px;margin:0">Always per person: nobody reads another person's conversation (administrators see counts only).
        Now: ${num(view.memory?.sessions)} active, ${num(view.memory?.stored)} stored.
        ${view.settings.config.memory.mode === "persisted" && mem.mode !== "persisted" ? html`<b class="warn-text">Saving deletes the stored conversations.</b>` : ""}</p>
    </fieldset>` : ""}
  </div>`;
}

function toolsTab(view, draft, admin) {
  if (!view.chats) {
    return html`<p class="muted">${view.name} has no chat tools: it writes structured results (patches, connector mappings, analyses) that people review
      through approvals.</p>`;
  }
  const custom = view.kind === "custom";
  const all = draft.config.allowed_tools == null;
  const allowed = new Set(draft.config.allowed_tools || []);
  const granted = new Set(view.effective_permissions || []);
  const groups = [...new Set(view.tools_catalog.map((t) => t.permission))];
  const notGranted = custom ? (draft.permissions || []).filter((p) => !granted.has(p) && (view.settings.permissions || []).includes(p)) : [];
  return html`<div class="stack" style="gap:16px">
    ${custom ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Permissions</legend>
      <div class="check-grid perm-grid">${view.permissions_catalog.map((p) => html`<label class="check" title="${p.description}">
        <input type="checkbox" data-perm value="${p.id}" ${(draft.permissions || []).includes(p.id) ? "checked" : ""}><span>${p.id.replace(/_/g, " ")}
          <span class="faint" style="display:block;font-size:11.5px">${p.description}</span></span></label>`)}</div>
      ${notGranted.length ? html`<p class="warn-text" style="font-size:12.5px">Not granted (its parent lacks them, guardrail): ${notGranted.join(", ").replace(/_/g, " ")}</p>` : ""}
      <p class="faint" style="font-size:12.5px;margin:0">Tool availability below follows the saved permissions; save to see a change there.</p>
    </fieldset>` : ""}
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Allowed tools</legend>
      <div class="row" style="gap:10px;flex-wrap:nowrap"><button type="button" role="switch" class="toggle" aria-checked="${all ? "true" : "false"}" data-act="all-tools" id="as-all-tools" ${dis(admin)}></button>
        <label for="as-all-tools">All tools these permissions allow</label></div>
      <p class="faint" style="font-size:12.5px">Narrow what the model may call within the permissions${custom ? "" : " (the Hub Supervisor's permissions are fixed)"}. A call to a tool that is not allowed is refused.</p>
      ${all ? "" : groups.map((perm) => html`<fieldset class="tool-group"><legend>${perm.replace(/_/g, " ")}</legend>
        ${view.tools_catalog.filter((t) => t.permission === perm).map((t) => html`<label class="check tool-check">
          <input type="checkbox" data-tool value="${t.name}" ${allowed.has(t.name) && t.granted ? "checked" : ""} ${t.granted ? "" : raw("disabled")}>
          <span><span class="mono">${t.name}</span>${t.granted ? "" : html` <span class="faint">(needs ${perm.replace(/_/g, " ")})</span>`}
            <span class="faint" style="display:block;font-size:11.5px">${t.description}</span></span></label>`)}</fieldset>`)}
    </fieldset>
  </div>`;
}

function limitsTab(view, draft, admin) {
  const b = draft.config.budget;
  const r = draft.config.rate;
  const s = view.budget_state || {};
  const primary = view.models?.[view.purposes[0]] || {};
  const suite = view.suite_budget || {};
  return html`<div class="stack" style="gap:16px">
    <section><h3 class="as-h3">Today</h3>${limitsSummary(view)}
      ${s.stopped ? html`<div class="notice warn" style="margin-top:8px">${icon("alert")}<div><b>${budgetText(s)}</b>: new model calls of ${view.name} are refused until
        ${s.reached?.includes("monthly_cost") ? "the month ends" : "00:00 UTC"}.
        ${admin ? html`<button type="button" class="btn sm" data-act="lift" style="margin-left:6px">Lift today's stop</button>` : ""}</div></div>`
        : s.reached?.length ? html`<p class="warn-text" style="font-size:12.5px">Over budget, but the hard stop is off: it keeps running.</p>` : ""}
      ${s.override ? html`<p class="faint" style="font-size:12.5px">Lifted today${s.override.lifted ? " (no stop for the rest of the day)" : ""}: ${(s.override.entries || []).map((e) => `${e.actor} - ${e.reason}`).join("; ")}</p>` : ""}
      ${primary.priced === false ? html`<p class="warn-text" style="font-size:12.5px">${primary.model} has no price in the price table: cost budgets cannot stop it (token budgets still work).</p>` : ""}
      <p class="faint" style="font-size:12.5px">Suite cap: ${suite.enabled ? `${usd(suite.spent_today)} of $${suite.limit} today for all agents` : "off"} (Settings &gt; Agent guardrails). Days are UTC days.</p></section>
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Budgets</legend>
      <div class="form-grid">
        ${numberField("config.budget.daily_tokens", "Daily tokens", b.daily_tokens, { min: 1000, step: 1000, admin, placeholder: "No limit" })}
        ${numberField("config.budget.daily_cost_usd", "Daily cost (USD)", b.daily_cost_usd, { min: 0.01, step: 0.01, admin, placeholder: "No limit" })}
        ${numberField("config.budget.monthly_cost_usd", "Monthly cost (USD)", b.monthly_cost_usd, { min: 0.01, step: 0.01, admin, placeholder: "No limit" })}</div>
      <div class="row" style="gap:10px;flex-wrap:nowrap"><button type="button" role="switch" class="toggle" aria-checked="${b.hard_stop ? "true" : "false"}" data-act="hard-stop" id="as-hard-stop" ${dis(admin)}></button>
        <label for="as-hard-stop">Stop the agent when a budget is reached</label></div>
      <p class="faint" style="font-size:12.5px;margin:4px 0 0">Off: a reached budget is only reported (activity log). A call already running finishes, so one call can go over.</p>
    </fieldset>
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Rate limits</legend>
      <div class="form-grid">
        ${numberField("config.rate.calls_per_minute", "Model calls per minute", r.calls_per_minute, { min: 1, max: 600, admin, placeholder: "No limit" })}
        ${view.chats ? numberField("config.rate.runs_per_hour", "Chats and runs per hour", r.runs_per_hour, { min: 1, max: 3600, admin, placeholder: "No limit" }) : ""}</div>
    </fieldset>
  </div>`;
}

function escalationTab(view, draft, admin, users) {
  const esc = draft.config.escalation;
  const nt = draft.config.notify;
  const s = view.escalation;
  const sched = view.schedule;
  const events = new Set(nt.events);
  const targets = new Set(nt.targets);
  const known = Object.fromEntries([...(view.notify_targets || []), ...(users || []).map((u) => ({ id: `user:${u.id}`, label: u.username }))].map((t) => [t.id, t.label]));
  const people = nt.targets.filter((t) => t.startsWith("user:"));
  const narrowed = draft.config.allowed_tools != null && !draft.config.allowed_tools.includes("escalate");
  const listeners = view.toolbus_listeners || [];
  return html`<div class="stack" style="gap:16px">
    ${view.chats ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Escalate to a person</legend>
      <div class="row" style="gap:10px;flex-wrap:nowrap"><button type="button" role="switch" class="toggle" aria-checked="${esc.tool ? "true" : "false"}" data-act="esc-tool" id="as-esc-tool" data-error-for="config.escalation.tool" ${dis(admin)}></button>
        <label for="as-esc-tool">${view.name} may escalate (the escalate tool)</label></div>
      <p class="faint" style="font-size:12.5px;margin:4px 0 0">Instead of deciding itself it asks in Approvals; an operator acknowledges or dismisses it, with a note it reads in its next turn.</p>
      ${narrowed && esc.tool ? html`<p class="warn-text" style="font-size:12.5px">The Tools tab narrows its tools and leaves escalate out: it cannot escalate until escalate is allowed there too.</p>` : ""}
      <div class="field" style="margin-top:12px"><span class="label" id="as-rules-label">Escalation rules</span>
        <span class="hint" id="as-rules-hint">When one of these applies it must escalate instead of deciding (at most 20, 300 characters each). It also escalates when blocked or unsure an action is safe.</span>
        ${esc.rules.length ? html`<ol class="esc-rules" aria-labelledby="as-rules-label">${esc.rules.map((r, i) => html`<li>
          <input data-rule="${i}" maxlength="300" value="${r}" aria-label="Rule ${i + 1}" aria-describedby="as-rules-hint" ${dis(admin)}>
          ${admin ? html`<button type="button" class="icon-btn sm" data-act="rule-remove" data-i="${i}" aria-label="Remove rule ${i + 1}" title="Remove">${icon("trash")}</button>` : ""}</li>`)}</ol>`
          : html`<p class="faint" style="font-size:12.5px;margin:4px 0">No rules.</p>`}
        ${admin && esc.rules.length < 20 ? html`<div><button type="button" class="btn sm" data-act="rule-add" data-error-for="config.escalation.rules">${icon("plus")}Add rule</button></div>` : ""}</div>
      <div class="form-grid">${numberField("config.escalation.max_per_day", "Escalations per day", esc.max_per_day, { min: 1, max: 50, nullable: false, admin,
        hint: "Beyond it the tool refuses (until 00:00 UTC), so injected text cannot flood the approval queue." })}</div>
      ${s ? html`<p class="faint" style="font-size:12.5px;margin:0">Today: ${s.today} of ${s.limit} escalations.
        ${s.pending ? html`<a href="#/approvals">${s.pending} waiting in Approvals</a>.` : "None waiting."}
        ${s.answers_waiting ? `${s.answers_waiting} answer${s.answers_waiting === 1 ? "" : "s"} wait for its next turn.` : ""}</p>` : ""}
    </fieldset>` : html`<p class="muted" style="margin:0">${view.name} does not chat, so it has no escalate tool: what it proposes waits in Approvals anyway. Here you choose
      which of its events are notifications.</p>`}
    ${sched ? html`<fieldset class="plain choice-group" ${dis(admin)}><legend>Failed runs</legend>
      <div class="form-grid">${numberField("config.escalation.failed_runs", "Failed runs before pausing", esc.failed_runs, { min: 0, max: 20, nullable: false, admin,
        hint: "In a row; 0 = never pause. A run skipped for a budget or rate limit does not count." })}
        <label class="check" style="align-self:center"><input type="checkbox" data-path="config.escalation.pause_schedule" data-type="bool" ${esc.pause_schedule ? "checked" : ""}><span>Pause the schedule</span></label></div>
      ${sched.paused ? html`<div class="notice warn">${icon("alert")}<div><b>Schedule paused</b> after ${sched.failures} failed runs in a row: it runs only when started by hand.
          ${admin ? html`<button type="button" class="btn sm" data-act="resume-schedule" style="margin-left:6px">${icon("play")}Resume schedule</button>` : ""}</div></div>`
        : html`<p class="faint" style="font-size:12.5px;margin:0">${sched.failures ? `${sched.failures} failed run${sched.failures === 1 ? "" : "s"} in a row now.` : "No failed runs in a row."}${sched.has_schedule ? "" : " It has no schedule (Behaviour tab)."}</p>`}
    </fieldset>` : ""}
    <fieldset class="plain choice-group" ${dis(admin)}><legend>Notifications</legend>
      <p class="faint" style="font-size:12.5px;margin:0 0 8px">A notification is the event's entry in the activity log, highlighted in the "Needs attention" strip on the Agents page
        for the people it targets. Everyone who signs in can read the activity log, so it holds no more than the agent, the event and a masked summary. Atrium sends no email.</p>
      <fieldset class="tool-group"><legend>Events</legend>
        ${view.notify_events.map((e) => html`<label class="check"><input type="checkbox" data-notify-event value="${e.id}" ${events.has(e.id) ? "checked" : ""}><span>${e.label}</span></label>`)}</fieldset>
      <fieldset class="tool-group" id="as-targets"><legend>Targets</legend>
        ${view.target_roles.map((r) => html`<label class="check"><input type="checkbox" data-target value="${r.id}" ${targets.has(r.id) ? "checked" : ""}><span>${r.label}</span></label>`)}
        ${people.map((t) => html`<label class="check"><input type="checkbox" data-target value="${t}" checked><span>${known[t] || "(removed account)"}</span></label>`)}
        ${admin ? html`<div class="field" style="max-width:320px"><label for="as-add-target">Add a person</label>
          <select id="as-add-target" data-act-change="add-target" data-error-for="config.notify.targets"><option value="">Choose an account</option>
            ${(users || []).filter((u) => !targets.has(`user:${u.id}`)).map((u) => html`<option value="user:${u.id}">${u.username} (${u.role})</option>`)}</select></div>` : ""}</fieldset>
      <label class="check"><input type="checkbox" data-path="config.notify.toolbus" data-type="bool" ${nt.toolbus ? "checked" : ""}><span>Also send to integrated tools (tool bus event hub.agent.&lt;event&gt;)
        <span class="faint" style="display:block;font-size:12px">${listeners.length ? `Listening now: ${listeners.map((t) => t.name).join(", ")}.` : "No integrated tool listens for hub.agent.* events yet."}
          They get the agent, the event, the severity, a masked summary (500 characters) and a link.</span></span></label>
    </fieldset>
  </div>`;
}

function runCard(run) {
  const label = run.provider === "rules" || !run.model ? run.provider_label || run.provider : `${modelLabel({ id: run.provider, label: run.provider_label }, run.model)} (${run.provider_label || run.provider})`;
  const seconds = run.latency_ms ? `${(run.latency_ms / 1000).toFixed(1)} s` : "";
  return html`<article class="card pg-card"><header><h3 class="as-h3" style="margin:0">${label}</h3>${badge(run.source === "compare" ? "compared" : "these settings", run.source === "compare" ? "" : "accent")}</header>
    ${run.error ? html`<p class="warn-text">${icon("alert")} ${run.error}</p>` : html`<div class="prose-box">${md(run.reply || "")}</div>`}
    <p class="faint" style="font-size:12px;margin:6px 0 0">${[run.tokens ? `${num(run.tokens)} tokens` : "", run.cost_usd ? `~$${run.cost_usd.toFixed(4)}` : "", seconds,
      run.fallback_from ? `fallback from ${run.fallback_from}` : "", run.mode && run.mode !== "llm" ? run.mode : ""].filter(Boolean).join(" - ")}</p>
    ${run.tool_calls?.length ? html`<details><summary class="faint" style="cursor:pointer;font-size:12.5px">${run.tool_calls.length} tool call(s)</summary>
      <ol class="pg-trace">${run.tool_calls.map((c) => html`<li><span class="mono">${c.name}</span> ${badge(c.ok ? "ok" : "refused", c.ok ? "ok" : "warn")}
        <div class="mono faint">${c.arguments}</div>${c.result_preview ? html`<div class="mono faint">${c.result_preview}</div>` : ""}</li>`)}</ol></details>` : ""}
  </article>`;
}

function playgroundTab(view, providers, play, dirty, admin) {
  if (!admin) return html`<p class="muted">Only administrators can use the playground: it spends tokens and may act.</p>`;
  const cmp = providers.find((p) => p.id === play.compareProvider);
  return html`<div class="stack" style="gap:12px">
    <p class="faint" style="font-size:12.5px;margin:0">Try ${view.name} on a prompt. Nothing is saved or remembered and the prompt is not logged; the calls count toward the
      suite's daily cap, not the agent's budget.${view.chats ? "" : " It answers without tools (its real tasks write structured results)."}</p>
    <div class="field"><label for="pg-prompt">Prompt</label><textarea id="pg-prompt" data-pg="prompt" rows="4" maxlength="8000">${play.prompt}</textarea></div>
    <div class="form-grid">
      <div class="field"><label for="pg-compare">Compare with</label><select id="pg-compare" data-pg="compareProvider">
        <option value="">Nothing (one run)</option>${providers.filter((p) => p.id !== "rules").map((p) => html`<option value="${p.id}" ${p.id === play.compareProvider ? raw("selected") : ""}>${p.label}${p.available ? "" : ` (not available: ${p.reason || "unknown"})`}</option>`)}</select></div>
      ${play.compareProvider ? html`<div class="field"><label for="pg-model">Model to compare</label><input id="pg-model" data-pg="compareModel" list="pg-models" maxlength="200" value="${play.compareModel}"
        placeholder="${cmp?.default_model ? `Provider default (${cmp.default_model})` : "Provider default"}">
        <datalist id="pg-models">${[...new Set([...(cmp?.pinned_models || []), ...(cmp?.models || [])])].map((m) => html`<option value="${m}">`)}</datalist></div>` : html`<div></div>`}</div>
    <label class="check"><input type="checkbox" data-pg="useDraft" ${play.useDraft && dirty ? "checked" : ""} ${dirty ? "" : raw("disabled")}><span>Use my unsaved changes${dirty ? "" : " (there are none)"}</span></label>
    ${view.chats ? html`<label class="check"><input type="checkbox" data-pg="allowActions" ${play.allowActions ? "checked" : ""}><span>Allow actions (commands, patches, flows; approvals still apply, as you)
      <span class="faint" style="display:block;font-size:12px">Off: only tools that read.</span></span></label>` : ""}
    <div><button type="button" class="btn primary" data-act="pg-run" aria-busy="${play.busy ? "true" : "false"}" ${play.busy ? raw("disabled") : ""}>${icon("play")}${play.busy ? "Running..." : "Run"}</button></div>
    <div class="pg-runs" aria-live="polite">${play.runs.map(runCard)}</div>
  </div>`;
}

function historyTab(view, history, admin) {
  if (history == null) return html`<p class="faint">Loading the history...</p>`;
  if (!history.length) return html`<p class="muted">No changes yet. Every saved change keeps a version here (the last 20), which an administrator can restore.</p>`;
  return html`<ol class="as-history">${history.map((h) => html`<li><div><b>Version ${h.version}</b>${h.version === view.version ? html` ${badge("current", "ok")}` : ""}
      <span class="faint"> - ${h.actor || "before the first change"}${h.at ? `, ${timeAgo(h.at)}` : ""}${h.restored_from != null ? ` (restored version ${h.restored_from})` : ""}</span></div>
    ${h.changed?.length ? html`<div class="faint" style="font-size:12px">Changed: ${changeWords(h.changed).join(", ")}</div>` : ""}
    ${admin && h.version !== view.version ? html`<button type="button" class="btn sm" data-act="restore" data-version="${h.version}">${icon("refresh")}Restore</button>` : ""}</li>`)}</ol>
    <p class="faint" style="font-size:12.5px">Restoring brings back the model, behaviour, tools and limits of that version as a new version; a custom agent's team and reporting line stay as they are.</p>`;
}

/** Renders the settings page of agent `ctx.params[0]` (tab `ctx.params[2]`). */
export async function render(el, ctx) {
  const id = ctx.params[0];
  const admin = can("admin");
  // `base`: the settings (and version) the draft started from - a live refresh keeps it while the draft has changes, so
  // saving meets a newer version (409) instead of silently undoing someone else's change
  const state = { view: null, providers: [], agent: null, draft: null, base: null, tab: ctx.params[2] || "overview", error: "", history: null, users: null,
    play: { prompt: "", compareProvider: "", compareModel: "", useDraft: true, allowActions: false, busy: false, runs: [] } };
  const load = async (keepDraft = false) => {
    const [view, pv, agents] = await Promise.all([get(`/agents/${enc(id)}/settings`), get("/llm/providers"), get("/agents")]);
    const dirty = state.draft && changed().length;
    Object.assign(state, { view, providers: pv.choices || [], agent: agents.find((a) => a.id === id) || null });
    if (!(keepDraft && dirty)) rebase();
  };
  const rebase = () => {
    state.base = { settings: clone(state.view.settings), version: state.view.version };
    state.draft = clone(state.view.settings);
    state.langOther = false;
  };
  const changed = () => (state.base ? diffSettings(state.base.settings, state.draft) : []);
  const loadHistory = async () => {
    try {
      state.history = await get(`/agents/${enc(id)}/settings/history`);
    } catch (err) {
      state.history = [];
      toast(err.message, "bad");
    }
  };
  try {
    await load();
  } catch (err) {
    setHTML(el, emptyState("alert", err.status === 404 ? "No such agent" : "Agent settings unavailable", err.message, html`<a class="btn" href="#/agents">${icon("arrow")}Back to Agents</a>`));
    return;
  }
  ctx.crumb(`${state.view.name} - settings`);
  const tabs = () => state.view.tabs || ["overview"];
  if (!tabs().includes(state.tab)) state.tab = "overview";
  if (state.tab === "history") loadHistory().then(() => draw());
  // the accounts an administrator can add as notification targets (GET /users is for administrators)
  const loadUsers = async () => {
    if (!admin || state.users) return;
    state.users = await get("/users").catch(() => []);
    if (state.tab === "escalation") draw();
  };
  if (state.tab === "escalation") loadUsers();

  const header = () => {
    const a = state.agent;
    const e = state.view.effective?.purposes?.[state.view.effective.primary];
    const tone = a?.status === "working" ? "working" : a?.status === "paused" ? "warn" : "ok";
    return html`<div class="as-head">${builtinIcon(ROLE_ICON[state.view.role] || "bot", state.view.role === "tool-supervisor" || state.view.kind === "custom" ? colorFor(a?.scope || id) : "#7c3aed", "sm")}
      <div class="as-title" style="min-width:0"><h1>${state.view.name}</h1><div class="faint" style="font-size:12.5px">${state.view.title}${a ? html` - <span class="dot ${tone}"></span> ${a.status}` : ""}</div></div>
      ${e ? html`<span class="badge model-badge ${e.provider === "rules" ? "" : "accent"}" title="${effectiveText(e)}">${icon("bot")}${effectiveText(e)}</span>` : badge("deterministic")}
      ${state.view.budget_state?.stopped ? badge("budget reached", "warn") : ""}
      <a class="btn sm" href="#/agents">${icon("arrow")}Back to Agents</a></div>`;
  };
  const footer = () => {
    const keys = changed();
    if (!admin || !keys.length) return "";
    return html`<div class="as-footer" role="region" aria-label="Unsaved changes"><span><b>Unsaved changes</b>: ${changeWords(keys).join(", ")}</span>
      ${state.error ? html`<span class="warn-text" id="as-error" role="alert">${state.error}</span>` : ""}<span class="spacer"></span>
      <button type="button" class="btn" data-act="discard">Discard</button>
      <button type="button" class="btn primary" data-act="save">${icon("check")}Save</button></div>`;
  };
  const body = () => {
    const { view, providers, draft, play } = state;
    switch (state.tab) {
      case "model": return modelTab(view, providers, draft, admin);
      case "behaviour": return behaviourTab(view, draft, admin, state.langOther);
      case "tools": return toolsTab(view, draft, admin);
      case "limits": return limitsTab(view, draft, admin);
      case "escalation": return escalationTab(view, draft, admin, state.users);
      case "playground": return playgroundTab(view, providers, play, changed().length > 0, admin);
      case "history": return historyTab(view, state.history, admin);
      default: return overviewTab(view, state.agent);
    }
  };
  const dirtyTabs = () => new Set(changed().map(tabOf));
  const tablist = () => {
    const marked = dirtyTabs();
    return html`${tabs().map((k) => html`<button type="button" role="tab" id="as-tab-${k}"
      aria-controls="as-panel" aria-selected="${k === state.tab ? "true" : "false"}" tabindex="${k === state.tab ? "0" : "-1"}" class="${k === state.tab ? "active" : ""}"
      data-act="tab" data-tab="${k}">${k === "escalation" && !state.view.chats ? "Notifications" : TAB_LABELS[k] || k}${marked.has(k) ? html` <span data-mark aria-label="(unsaved changes)">*</span>` : ""}</button>`)}`;
  };
  let chrome = ""; // what the footer and the tab marks show now (drawChrome)
  const draw = (focus) => {
    if (!el.isConnected) return;
    // a redraw after an async load (history, accounts) keeps the focus where it was, e.g. on the tab just reached by arrow key
    const was = document.activeElement;
    const keep = !focus && was && was !== document.body && el.contains(was) && was.id ? `#${CSS.escape(was.id)}` : null;
    const inside = state.agent?.placement === "sidecar" ? state.agent.works_inside || state.agent.team : null; // a subsidiary's staff member
    setHTML(el, html`${header()}
      ${admin ? "" : html`<div class="notice" style="margin-bottom:12px">${icon("lock")}<div class="muted">Only administrators can change an agent's settings.</div></div>`}
      ${inside ? html`<div class="notice" style="margin-bottom:12px">${icon("building")}<div class="muted">${state.view.name} works inside ${state.agent.team_name || inside},
        in the sidecar next to it. Its actions, reach into the hub, model providers and budgets are set by the subsidiary's approved charter, and its
        team and placement never change: <a href="#/subsidiaries/${enc(inside)}/charter">open the charter</a>.</div></div>` : ""}
      <div class="tabs as-tabs" role="tablist" aria-label="${state.view.name} settings" data-tablist>${tablist()}</div>
      <section class="card" id="as-panel" role="tabpanel" aria-labelledby="as-tab-${state.tab}" tabindex="-1">${body()}</section>
      <div data-footer>${footer()}</div>`);
    chrome = JSON.stringify([changed(), state.error, state.tab]);
    if (focus || keep) el.querySelector(focus || keep)?.focus();
  };
  // after typing: the footer and the tabs' change marks, without redrawing the field being typed in - and only when
  // they change (a blur's "change" event must not replace the button the pointer is about to click)
  const drawChrome = () => {
    const key = JSON.stringify([changed(), state.error, state.tab]);
    if (key === chrome) return;
    chrome = key;
    setHTML(el.querySelector("[data-footer]"), footer());
    const marked = dirtyTabs();
    el.querySelectorAll("[data-tablist] [role=tab]").forEach((b) => {
      const mark = b.querySelector("[data-mark]");
      if (marked.has(b.dataset.tab) && !mark) b.insertAdjacentHTML("beforeend", ' <span data-mark aria-label="(unsaved changes)">*</span>');
      else if (!marked.has(b.dataset.tab) && mark) mark.remove();
    });
  };
  draw();

  const showTab = (tab, focus = true) => {
    state.tab = tab;
    history.replaceState(null, "", `#/agents/${enc(id)}/settings/${tab}`);
    if (tab === "history") {
      state.history = null;
      loadHistory().then(() => { if (state.tab === "history") draw(); });
    }
    if (tab === "escalation") loadUsers();
    draw(focus ? `#as-tab-${tab}` : null);
  };
  el.addEventListener("keydown", (e) => {
    const tab = e.target.closest('[role="tab"]');
    if (!tab) return;
    const keys = tabs();
    const i = keys.indexOf(tab.dataset.tab);
    const next = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: keys.length - 1 }[e.key];
    if (next === undefined) return;
    e.preventDefault();
    showTab(keys[(next + keys.length) % keys.length]);
  });

  const setChoice = (row, model) => {
    const key = row.dataset.choice;
    const provider = row.querySelector("[data-provider]").value;
    const value = { provider, model: provider && provider !== "rules" ? model : "" };
    if (key === "llm") state.draft.llm = value;
    else if (!provider) delete state.draft.config.purposes[key.split(":")[1]];
    else state.draft.config.purposes[key.split(":")[1]] = value;
  };
  const valueOf = (t) => {
    if (t.dataset.type === "bool") return t.checked;
    if (t.dataset.type === "number-null") return t.value === "" ? null : Number(t.value);
    if (t.dataset.type === "number") return t.value === "" ? null : Number(t.value);
    return t.value;
  };
  const bind = (t) => {
    setPath(state.draft, t.dataset.path, valueOf(t));
    if (t.dataset.path === "config.params.temperature") el.querySelectorAll('[data-path="config.params.temperature"]').forEach((x) => { if (x !== t) x.value = t.value; });
  };
  el.addEventListener("change", async (e) => {
    const t = e.target;
    state.error = "";
    if (t.matches("[data-mode]")) {
      state.draft.llm = t.value === "inherit" ? { provider: "", model: "" }
        : { provider: state.base.settings.llm.provider || state.view.effective?.purposes?.[state.view.purposes[0]]?.provider || "rules", model: state.base.settings.llm.model || "" };
      if (t.value === "choose" && !state.base.settings.llm.provider && state.draft.llm.provider === "rules") state.draft.llm.provider = state.providers.find((p) => p.available && p.id !== "rules")?.id || "rules";
      return draw(`[data-mode][value="${t.value}"]`);
    }
    if (t.matches("[data-local-only]")) {
      state.draft.config.local_only = t.checked;
      return draw("[data-local-only]");
    }
    const row = t.closest("[data-choice]");
    if (row && t.matches("[data-provider]")) {
      setChoice(row, "");
      return draw(`[data-choice="${CSS.escape(row.dataset.choice)}"] [data-provider]`);
    }
    if (t.matches("[data-perm]")) {
      const perms = new Set(state.draft.permissions || []);
      t.checked ? perms.add(t.value) : perms.delete(t.value);
      state.draft.permissions = (state.view.permissions_catalog || []).map((p) => p.id).filter((p) => perms.has(p));
      return drawChrome();
    }
    if (t.matches("[data-notify-event]")) {
      const on = new Set(state.draft.config.notify.events);
      t.checked ? on.add(t.value) : on.delete(t.value);
      state.draft.config.notify.events = state.view.notify_events.map((x) => x.id).filter((x) => on.has(x))
        .concat(state.draft.config.notify.events.filter((x) => on.has(x) && !state.view.notify_events.some((e) => e.id === x)));
      return drawChrome();
    }
    if (t.matches("[data-target]")) {
      const keep = state.draft.config.notify.targets.filter((x) => x !== t.value);
      state.draft.config.notify.targets = t.checked ? [...keep, t.value] : keep;
      return t.value.startsWith("user:") && !t.checked ? draw("#as-add-target") : drawChrome();
    }
    if (t.matches("[data-rule]")) return drawChrome(); // bound while typing; the server trims and drops empty rules
    if (t.matches("[data-tool]")) {
      const tools = new Set(state.draft.config.allowed_tools || []);
      t.checked ? tools.add(t.value) : tools.delete(t.value);
      state.draft.config.allowed_tools = state.view.tools_catalog.map((x) => x.name).filter((n) => tools.has(n));
      return drawChrome();
    }
    if (t.matches("[data-pg]")) {
      state.play[t.dataset.pg] = t.type === "checkbox" ? t.checked : t.value;
      if (t.dataset.pg === "compareProvider") { state.play.compareModel = ""; draw("#pg-compare"); }
      return;
    }
    const act = t.dataset.actChange;
    if (act === "add-target") {
      if (t.value && !state.draft.config.notify.targets.includes(t.value)) state.draft.config.notify.targets = [...state.draft.config.notify.targets, t.value];
      return draw("#as-add-target");
    }
    if (act === "temp-toggle") {
      state.draft.config.params.temperature = t.checked ? 0.7 : null;
      return draw('[data-act-change="temp-toggle"]');
    }
    if (act === "language") { // "other": a code typed in the field that appears
      state.langOther = t.value === "other";
      state.draft.config.language = state.langOther ? (languageChoice(state.base.settings.config.language) === "other" ? state.base.settings.config.language : "") : t.value;
      return draw(state.langOther ? "#as-language-code" : "#as-language");
    }
    if (act === "replace-toggle") {
      if (t.checked) {
        const ok = await confirmDialog("Replace the built-in instructions?", "This agent then runs on your text only: later improvements to the built-in "
          + "instructions in new versions of Atrium do not reach it. The text starts as a copy of the built-in instructions.", "Replace");
        if (!ok) { t.checked = false; return; }
        state.draft.config.instructions_mode = "replace";
        state.draft.instructions = state.draft.instructions || state.view.builtin_instructions;
      } else {
        state.draft.config.instructions_mode = "append";
        state.draft.instructions = state.base.settings.config.instructions_mode === "replace" ? "" : state.base.settings.instructions;
      }
      return draw('[data-act-change="replace-toggle"]');
    }
    if (t.dataset.path) {
      bind(t);
      if (t.dataset.redraw !== undefined) return draw(`[data-path="${t.dataset.path}"][value="${CSS.escape(t.value)}"]`);
      drawChrome();
    }
  });
  el.addEventListener("input", (e) => {
    const t = e.target;
    if (t.matches("[data-pg]") && t.type !== "checkbox") { state.play[t.dataset.pg] = t.value; return; }
    if (t.matches("[data-rule]")) { // kept as typed until the field is left (then cleaned like the server does)
      state.draft.config.escalation.rules[Number(t.dataset.rule)] = t.value;
      return drawChrome();
    }
    const row = t.closest("[data-choice]");
    if (row && t.matches("[data-model]")) {
      setChoice(row, t.value.trim());
      return drawChrome();
    }
    if (t.dataset.path && t.type !== "radio" && t.type !== "checkbox") {
      bind(t);
      drawChrome();
    }
  });

  async function save() {
    if (!admin) return;
    const body = settingsBody(state.base.settings, state.draft, state.base.version, state.view.per_task);
    try {
      await patch(`/agents/${enc(id)}/settings`, body);
      toast(`${state.view.name}: settings saved`, "ok");
      state.error = "";
      state.history = null;
      await load();
      if (state.tab === "history") await loadHistory();
      draw(`#as-tab-${state.tab}`);
    } catch (err) {
      if (err.status === 409) return conflict();
      state.error = err.message;
      const path = errorPath(err.message);
      const target = path ? `[data-path="${path}"], [data-error-for="${path}"]` : /^Code changes/.test(err.message) ? "#as-task-code" : /^Structured generation/.test(err.message) ? "#as-task-generate"
        : /local-only/.test(err.message) ? "[data-local-only]" : /^Allowed tools/.test(err.message) ? "#as-all-tools" : "#as-provider";
      const tab = path ? tabOf(path) : "model";
      if (state.tab !== tab && tabs().includes(tab)) showTab(tab, false);
      else drawChrome();
      const field = el.querySelector(target);
      const described = (field?.getAttribute("aria-describedby") || "").split(" ").filter((x) => x && x !== "as-error");
      field?.setAttribute("aria-describedby", [...described, "as-error"].join(" "));
      field?.focus();
    }
  }

  function conflict() {
    modal({
      title: "Changed elsewhere", submit: "Reload (your changes are lost)", cancel: "Keep editing", minRole: "admin",
      body: html`<p>Someone else changed ${state.view.name}'s settings since you opened this page.</p>
        <p class="muted" style="font-size:12.5px">Reload shows their version; Keep editing lets you copy your changes first. Saving again needs a reload.</p>`,
      async onSubmit() {
        await load();
        draw(`#as-tab-${state.tab}`);
      },
    });
  }

  function liftModal() {
    modal({
      title: `Lift today's stop of ${state.view.name}`, submit: "Lift the stop", minRole: "admin",
      body: html`<p class="muted" style="margin-bottom:10px">${budgetText(state.view.budget_state)}. Raise today's limits by an amount, or leave both empty to remove the
        stop for the rest of the UTC day. It is logged as a warning with your reason.</p>
        <div class="field"><label for="lift-reason">Reason</label><input id="lift-reason" name="reason" required minlength="5" maxlength="500" placeholder="e.g. incident 42 needs the analysis"></div>
        <div class="form-grid"><div class="field"><label for="lift-usd">Extra cost today (USD)</label><input id="lift-usd" name="extra_usd" type="number" min="0.01" step="0.01"></div>
          <div class="field"><label for="lift-tokens">Extra tokens today</label><input id="lift-tokens" name="extra_tokens" type="number" min="1" step="1000"></div></div>`,
      async onSubmit(data) {
        const extraUsd = String(data.get("extra_usd") || "");
        const extraTokens = String(data.get("extra_tokens") || "");
        await post(`/agents/${enc(id)}/budget/override`, { reason: String(data.get("reason") || "").trim(),
          extra_usd: extraUsd ? Number(extraUsd) : null, extra_tokens: extraTokens ? Number(extraTokens) : null });
        toast(`${state.view.name}: today's stop lifted`, "ok");
        await load(true);
        draw("#as-tab-limits");
      },
    });
  }

  async function runPlayground() {
    const play = state.play;
    if (!play.prompt.trim()) return toast("Write a prompt first", "bad");
    play.busy = true;
    draw();
    const dirty = changed().length > 0;
    const draft = play.useDraft && dirty ? settingsBody(state.base.settings, state.draft, undefined, state.view.per_task) : {};
    delete draft.version;
    try {
      const r = await post(`/agents/${enc(id)}/playground`, {
        prompt: play.prompt, draft, allow_actions: play.allowActions,
        compare_with: play.compareProvider ? { provider: play.compareProvider, model: play.compareModel.trim() } : null });
      play.runs = r.runs || [];
    } catch (err) {
      play.runs = [];
      toast(err.message, "bad");
    } finally {
      play.busy = false;
      draw('[data-act="pg-run"]');
    }
  }

  actions(el, {
    tab(d) { showTab(d.tab); },
    save() { save(); },
    discard() {
      rebase(); // the latest saved settings
      state.error = "";
      draw(`#as-tab-${state.tab}`);
    },
    "temp-clear"() {
      state.draft.config.params.temperature = null;
      draw("#as-effort");
    },
    "all-tools"() {
      if (!admin) return;
      const all = state.draft.config.allowed_tools == null;
      state.draft.config.allowed_tools = all ? state.view.tools_catalog.filter((t) => t.allowed).map((t) => t.name) : null;
      draw("#as-all-tools");
    },
    async "hard-stop"() {
      if (!admin) return;
      const on = state.draft.config.budget.hard_stop;
      if (on && !(await confirmDialog("Keep running over budget?", `${state.view.name} then keeps calling models after a budget is reached; it is only reported in the activity log.
        The suite's daily cap still applies.`, "Turn the stop off"))) return;
      state.draft.config.budget.hard_stop = !on;
      draw("#as-hard-stop");
    },
    lift() { liftModal(); },
    "esc-tool"() {
      if (!admin) return;
      state.draft.config.escalation.tool = !state.draft.config.escalation.tool;
      draw("#as-esc-tool");
    },
    "rule-add"() {
      if (!admin) return;
      const rules = cleanRules(state.draft.config.escalation.rules);
      state.draft.config.escalation.rules = [...rules, ""];
      draw(`[data-rule="${rules.length}"]`);
    },
    "rule-remove"(d) {
      if (!admin) return;
      const rules = state.draft.config.escalation.rules.filter((_, i) => i !== Number(d.i));
      state.draft.config.escalation.rules = rules;
      draw(rules.length ? `[data-rule="${Math.min(Number(d.i), rules.length - 1)}"]` : '[data-act="rule-add"]');
    },
    async "resume-schedule"() {
      try {
        await post(`/agents/${enc(id)}/schedule/resume`);
        toast(`${state.view.name}: schedule resumed`, "ok");
        await load(true);
        draw("#as-tab-escalation");
      } catch (err) {
        toast(err.message, "bad");
      }
    },
    "pg-run"() { runPlayground(); },
    async restore(d) {
      const version = Number(d.version);
      if (changed().length) return toast("Save or discard your changes first", "warn");
      if (!(await confirmDialog(`Restore version ${version}?`, `${state.view.name}'s settings go back to version ${version}, saved as a new version; the current settings stay in the history.`, "Restore"))) return;
      try {
        await post(`/agents/${enc(id)}/settings/restore`, { version, base_version: state.base.version });
        toast(`${state.view.name}: version ${version} restored`, "ok");
        await load();
        await loadHistory();
        draw("#as-tab-history");
      } catch (err) {
        if (err.status === 409) return conflict();
        toast(err.message, "bad");
      }
    },
    async probe(d, btn) {
      btn.disabled = true;
      const said = (v) => (v === true ? "yes" : v === false ? "no" : "unknown");
      try {
        const r = await post(`/llm/providers/${enc(d.provider)}/probe`, { model: d.model });
        toast(`${d.model}: tools ${said(r.caps.tools)}, JSON ${said(r.caps.json_schema)} (${r.tokens} tokens)`, "ok");
        await load(true);
        draw("[data-model]");
      } catch (err) {
        toast(err.message, "bad");
        btn.disabled = false;
      }
    },
  });

  // unsaved changes: ask before leaving the page or closing the browser tab
  ctx.guardLeave?.(() => (changed().length ? confirmDialog("Leave without saving?", `Your changes to ${state.view.name}'s settings are not saved.`, "Leave") : Promise.resolve(true)));
  const beforeUnload = (e) => { if (changed().length) { e.preventDefault(); e.returnValue = ""; } };
  window.addEventListener("beforeunload", beforeUnload);
  ctx.onLeave(() => window.removeEventListener("beforeunload", beforeUnload));

  ctx.live(["agent_settings", "llm_selection", "llm_provider", "llm_provider_removed", "settings", "agent_removed", "llm_usage"], async () => {
    if (!el.isConnected || state.play.busy) return;
    try {
      await load(true); // an unsaved draft is kept; saving it then meets the newer version (409)
    } catch {
      return; // removed meanwhile: the next navigation shows it
    }
    if (!el.contains(document.activeElement) || document.activeElement === document.body) draw();
  }, 400);
}
