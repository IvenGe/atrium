// Settings > Model choice: which model agents use when they do not choose one - the suite default (Automatic: Claude,
// else OpenAI, else a local model), a default per task (chat, code changes, structured generation) and the fallback
// chain tried when a provider fails - plus what every agent runs on now. Administrators edit and save with the version
// they read; ordering the fallback chain uses Move up / Move down buttons (no dragging).
import { get, patch } from "../api.js";
import { LANGUAGES, blockedText, diffSettings, languageChoice, modelLabel, reorder, sourceLabel } from "../llm.js";
import { actions, badge, can, html, icon, options, setHTML, toast } from "../ui.js";

const TASKS = [
  ["chat", "Chat and agent tasks (with tools)", "The most frequent calls: chat with agents and their scheduled tasks."],
  ["code", "Code changes (patches, self-patches)", "Code changes need the strongest model."],
  ["generate", "Structured generation (connectors, extensions, team designs, tool analysis)", "Answers in a fixed JSON shape."],
];
const AUTO = "Automatic (Claude, else OpenAI, else a local model)";
const enc = encodeURIComponent;
let uid = 0;

const clone = (v) => JSON.parse(JSON.stringify(v));
const editable = (sel) => ({ default: sel.default, purposes: Object.fromEntries(TASKS.map(([k]) => [k, sel.purposes?.[k] || null])), fallback: sel.fallback || [],
  language: sel.language || "auto" });

/** The provider options of a select: every provider with why it cannot take calls now (still selectable). */
function providerOptions(choices, first) {
  return [...first, ...choices.filter((c) => c.id !== "rules").map((c) => [c.id, `${c.label}${c.available ? "" : ` (not available: ${c.reason || "unknown"})`}`]),
    ["rules", "Rules only (no AI model)"]];
}

function modelInput(id, choice, providers, label) {
  const p = providers.find((x) => x.id === choice?.provider);
  const models = p ? [...new Set([...(p.pinned_models || []), ...(p.models || [])])] : [];
  const off = !p || p.id === "rules";
  return html`<div class="field"><label for="${id}">${label}</label>
    <input id="${id}" data-model list="${id}-list" maxlength="200" value="${off ? "" : choice?.model || ""}" ${off ? "disabled" : ""}
      placeholder="${p?.default_model ? `Provider default (${p.default_model})` : off ? "-" : "Provider default"}">
    <datalist id="${id}-list">${models.map((m) => html`<option value="${m}">`)}</datalist></div>`;
}

function choiceRow(key, title, hint, choice, first, providers, admin) {
  const id = `ad${++uid}`;
  return html`<div class="choice-row" data-choice="${key}">
    <div class="field"><label for="${id}-p">${title}</label>
      <select id="${id}-p" data-provider ${admin ? "" : "disabled"} aria-describedby="${id}-hint">${options(providerOptions(providers, first), choice?.provider || first[0][0])}</select>
      <span class="hint" id="${id}-hint">${hint}</span></div>
    ${modelInput(`${id}-m`, choice, providers, html`Model<span class="sr-only"> for ${title.split(" (")[0].toLowerCase()}</span>`)}</div>`;
}

function effectiveRows(agents) {
  const rows = [];
  for (const a of agents) {
    const purposes = Object.entries(a.llm?.purposes || {});
    for (const [purpose, e] of purposes) rows.push({ a, purpose: purposes.length > 1 ? purpose : null, e });
  }
  return rows;
}

function effectiveTable(agents) {
  const rows = effectiveRows(agents);
  const task = { chat: "chat", code: "code changes", generate: "structured generation" };
  return html`<div class="table-wrap"><table class="table eff-table"><caption class="sr-only">Effective model per agent</caption>
    <thead><tr><th scope="col">Agent</th><th scope="col">Model</th><th scope="col">Provider</th><th scope="col">From</th><th scope="col">Status</th></tr></thead>
    <tbody>${rows.map(({ a, purpose, e }) => {
      const ready = e.provider !== "rules" || e.source !== "rules";
      const why = blockedText(e);
      return html`<tr><td data-label="Agent"><a href="#/agents/${enc(a.agent_id)}/settings">${a.name}</a>${purpose ? html` <span class="faint">(${task[purpose] || purpose})</span>` : ""}</td>
        <td data-label="Model">${e.provider === "rules" ? "-" : modelLabel({ id: e.provider, label: e.provider_label }, e.model)}</td>
        <td data-label="Provider">${e.provider_label || e.provider}</td>
        <td data-label="From">${sourceLabel(e)}</td>
        <td data-label="Status">${ready ? badge(e.provider === "rules" ? "rules" : "ready", e.provider === "rules" ? "" : "ok") : badge("no model", "warn")}
          ${why ? html`<div class="faint" style="font-size:11.5px">Skipped: ${why}</div>` : ""}</td></tr>`;
    })}</tbody></table></div>`;
}

function view(state, admin) {
  const { draft, providers, data } = state;
  const choices = providers.filter((p) => p.id !== "rules");
  const suite = data.suite || {};
  const available = choices.some((c) => c.available);
  const fallbackNames = Object.fromEntries(choices.map((c) => [c.id, c.label]));
  const addable = choices.filter((c) => !draft.fallback.includes(c.id));
  const dirty = diffSettings(editable(state.base), draft).length > 0;
  return html`<header><h2 tabindex="-1">Model choice</h2><span class="spacer"></span><div class="card-actions" data-slot="home"></div></header>
    <p class="muted" style="margin-bottom:12px">What agents run on when they do not choose a model. Choose per agent on each agent's settings page (Agents),
      or drag agents between providers in the AI models widget on Home.</p>
    ${available ? "" : html`<div class="notice" style="margin-bottom:12px">${icon("bot")}<div class="muted">No AI model provider is usable now: agents use deterministic
      rules and templates. Add an API key for Claude or OpenAI, or a local model server, under AI providers.</div></div>`}
    <fieldset class="plain choice-group"><legend>Suite default</legend>
      ${choiceRow("default", "Default for all agents", "Applies to every agent and task without a more specific choice.", draft.default?.provider === "auto" ? { provider: "auto" } : draft.default,
        [["auto", AUTO]], providers, admin)}
      <p class="faint" style="font-size:12.5px">${data.selection.default?.provider === "auto"
        ? html`Automatic currently means <b>${suite.provider === "rules" ? "rules (no usable provider)" : `${modelLabel({ id: suite.provider, label: suite.provider_label }, suite.model)} (${suite.provider_label})`}</b>.`
        : html`Now: <b>${suite.provider === "rules" ? "rules" : `${modelLabel({ id: suite.provider, label: suite.provider_label }, suite.model)} (${suite.provider_label})`}</b>.`}</p>
    </fieldset>
    <fieldset class="plain choice-group"><legend>By task</legend>
      ${TASKS.map(([key, title, hint]) => choiceRow(`purpose:${key}`, title, hint, draft.purposes[key], [["", "Same as the suite default"]], providers, admin))}
    </fieldset>
    <fieldset class="plain choice-group"><legend>Fallback when a provider is unavailable</legend>
      <p class="faint" style="font-size:12.5px;margin-bottom:6px">Tried in this order when the chosen provider fails during a call. A local-only agent
        with an explicit cloud default moves on to rules unless a local provider is in this list.</p>
      <ol class="fallback-list">${draft.fallback.map((id, i) => html`<li data-fallback="${id}"><span class="grow">${fallbackNames[id] || id}</span>
          <span class="row" style="gap:4px" data-min-role="admin">
            <button type="button" class="btn sm" data-act="fb-move" data-i="${i}" data-dir="-1" ${i === 0 ? "disabled" : ""} aria-label="Move ${fallbackNames[id] || id} up">Up</button>
            <button type="button" class="btn sm" data-act="fb-move" data-i="${i}" data-dir="1" ${i === draft.fallback.length - 1 ? "disabled" : ""} aria-label="Move ${fallbackNames[id] || id} down">Down</button>
            <button type="button" class="btn sm" data-act="fb-remove" data-i="${i}" aria-label="Remove ${fallbackNames[id] || id} from the fallback chain">${icon("x")}Remove</button></span></li>`)}
        <li class="faint">then rules (always last)</li></ol>
      ${admin && addable.length ? html`<div class="row" style="gap:6px;margin-top:8px"><label for="fb-add" class="sr-only">Add a fallback provider</label>
        <select id="fb-add" class="input-sm">${options(addable.map((c) => [c.id, c.label]))}</select>
        <button type="button" class="btn sm" data-act="fb-add">${icon("plus")}Add fallback</button></div>` : ""}
      <p class="sr-only" aria-live="polite" data-live></p>
    </fieldset>
    <fieldset class="plain choice-group"><legend>Default reply language</legend>
      <div class="choice-row"><div class="field"><label for="ad-lang">Language of chat replies and run results</label>
        <select id="ad-lang" data-lang ${admin ? "" : "disabled"} aria-describedby="ad-lang-hint">
          ${options([["auto", "Automatic (the language people write in)"], ...LANGUAGES, ["other", "Other (a language code)"]], languageChoice(draft.language) || "auto")}</select>
        <span class="hint" id="ad-lang-hint">Agents that chat answer in it unless their own settings choose another. Ids, commands and code stay unchanged.</span></div>
        ${languageChoice(draft.language) === "other" ? html`<div class="field"><label for="ad-lang-code">Language code</label>
          <input id="ad-lang-code" data-lang-code maxlength="35" value="${draft.language === "other" ? "" : draft.language}" placeholder="e.g. pt-BR" ${admin ? "" : "disabled"}></div>` : ""}</div>
    </fieldset>
    <details class="eff-details"><summary>Effective model per agent (${data.effective.length}${data.deterministic ? `; ${data.deterministic} more work without a model` : ""})</summary>
      ${effectiveTable(data.effective)}</details>
    <div class="row" style="gap:8px;margin-top:12px" data-min-role="admin" data-footer>${footer(dirty)}</div>`;
}

function footer(dirty) {
  return html`<button type="button" class="btn primary" data-act="sel-save" ${dirty ? "" : "disabled"}>${icon("check")}Save model choice</button>
    <button type="button" class="btn" data-act="sel-discard" ${dirty ? "" : "disabled"}>Discard</button>
    <span class="warn-text" style="font-size:12.5px" aria-live="polite">${dirty ? "Unsaved changes" : ""}</span>`;
}

/** Renders the panel into `el`, keeps it current on model events, and wires its actions. */
export async function mount(el, ctx) {
  const admin = can("admin");
  // `base`: the selection the draft started from; a live refresh keeps it while the draft has changes, so Save meets
  // the newer version (409) instead of silently undoing someone else's change
  const state = { data: null, providers: [], draft: null, base: null };
  const isDirty = () => Boolean(state.base) && diffSettings(editable(state.base), state.draft).length > 0;
  const load = async (keepDraft = false) => {
    const [data, pv] = await Promise.all([get("/llm/selection"), get("/llm/providers")]);
    const dirty = isDirty();
    state.data = data;
    state.providers = pv.choices || [];
    if (!(keepDraft && dirty)) {
      state.base = clone(data.selection);
      state.draft = clone(editable(data.selection));
    }
  };
  const draw = (focus) => {
    if (!el.isConnected) return;
    setHTML(el, view(state, admin));
    if (focus) el.querySelector(focus)?.focus();
  };
  await load();
  draw();

  const announce = (text) => { const live = el.querySelector("[data-live]"); if (live) live.textContent = text; };
  const label = (id) => state.providers.find((p) => p.id === id)?.label || id;

  // provider and model fields write into the draft as they change; a new provider redraws its row's model list, a
  // typed model only updates the footer (a redraw on blur would pull focus back)
  const write = (row, model) => {
    const key = row.dataset.choice;
    const provider = row.querySelector("[data-provider]").value;
    const value = provider ? { provider, model: provider === "auto" || provider === "rules" ? "" : model } : null;
    if (key === "default") state.draft.default = value || { provider: "auto", model: "" };
    else state.draft.purposes[key.split(":")[1]] = value;
    return key;
  };
  el.addEventListener("change", (e) => {
    if (e.target.matches("[data-lang]")) {
      state.draft.language = e.target.value === "other" ? (languageChoice(state.base.language) === "other" ? state.base.language : "other") : e.target.value;
      return draw(e.target.value === "other" ? "#ad-lang-code" : "#ad-lang");
    }
    const row = e.target.closest("[data-choice]");
    if (!row || !e.target.matches("[data-provider]")) return;
    draw(`[data-choice="${CSS.escape(write(row, ""))}"] [data-provider]`);
  });
  el.addEventListener("input", (e) => {
    if (e.target.matches("[data-lang-code]")) {
      state.draft.language = e.target.value.trim() || "other";
      const box = el.querySelector("[data-footer]");
      if (box) setHTML(box, footer(isDirty()));
      return;
    }
    const row = e.target.closest("[data-choice]");
    if (!row || !e.target.matches("[data-model]")) return;
    write(row, e.target.value.trim());
    const box = el.querySelector("[data-footer]");
    if (box) setHTML(box, footer(isDirty()));
  });

  actions(el, {
    "fb-move"(d) {
      const i = Number(d.i);
      const dir = Number(d.dir);
      state.draft.fallback = reorder(state.draft.fallback, i, dir);
      const id = state.draft.fallback[i + dir];
      draw();
      const moved = el.querySelector(`[data-fallback="${CSS.escape(id)}"] [data-dir="${dir}"]:not(:disabled)`)
        || el.querySelector(`[data-fallback="${CSS.escape(id)}"] [data-act="fb-move"]:not(:disabled)`);
      moved?.focus();
      announce(`${label(id)} moved to position ${i + dir + 1}`);
    },
    "fb-remove"(d) {
      const i = Number(d.i);
      const [id] = state.draft.fallback.splice(i, 1);
      draw();
      (el.querySelectorAll('[data-act="fb-remove"]')[Math.min(i, state.draft.fallback.length - 1)] || el.querySelector("#fb-add"))?.focus();
      announce(`${label(id)} removed from the fallback chain`);
    },
    "fb-add"() {
      const id = el.querySelector("#fb-add")?.value;
      if (!id || state.draft.fallback.length >= 8) return toast("The fallback chain has at most 8 providers", "bad");
      state.draft.fallback = [...state.draft.fallback, id];
      draw("#fb-add");
      announce(`${label(id)} added at position ${state.draft.fallback.length}`);
    },
    async "sel-save"(d, btn) {
      if (!admin) return;
      const { draft } = state;
      if (draft.language === "other") return toast("Type a language code, or choose a language", "bad");
      btn.disabled = true;
      try {
        const body = { default: draft.default, purposes: Object.fromEntries(TASKS.map(([k]) => [k, draft.purposes[k] || null])),
          fallback: draft.fallback, version: state.base.version };
        if (draft.language !== (state.base.language || "auto")) body.language = draft.language;
        await patch("/llm/selection", body);
        toast("Model choice saved", "ok");
        await load();
        draw("[data-act=sel-save]");
      } catch (err) {
        if (err.status === 409) {
          toast("Someone else changed the model choice - reloaded", "warn");
          await load();
          draw();
        } else {
          toast(err.message, "bad");
          btn.disabled = false;
        }
      }
    },
    "sel-discard"() {
      state.base = clone(state.data.selection);
      state.draft = clone(editable(state.data.selection));
      draw("[data-act=sel-save]");
    },
  });
  let stale = false;
  const refresh = async () => {
    if (!el.isConnected) return;
    if (el.contains(document.activeElement)) { stale = true; return; } // never redraw under someone's cursor
    stale = false;
    await load(true); // an unsaved draft is kept; Save then meets the newer version (409)
    draw();
  };
  el.addEventListener("focusout", (e) => { if (stale && !el.contains(e.relatedTarget)) setTimeout(refresh, 0); });
  ctx.live(["llm_selection", "llm_provider", "llm_provider_removed", "agent_settings", "settings"], refresh, 400);
}
