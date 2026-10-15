// The AI models widget (round4-dashboard-spec.md 6.7 and 10.17, stage D4): every agent that uses a model is a chip in
// the lane of the provider it chose ("Inherits" for agents without their own choice), with the suite default in the
// header. Administrators move a chip to another lane by dragging it (pointer), by picking it up with Space and choosing
// a lane with the arrow keys (keyboard), or with its "Change..." button (single pointer); the default marker moves the
// same way, with "Set as default..." on each lane and "Use automatic" as its single-pointer path. Everyone else sees the
// same lanes read-only.
//
// Writes go through R4-LLM's admin routes only - PATCH /api/agents/{id}/settings {llm, version} and
// PATCH /api/llm/selection {default, version} - with the versions the widget data carries, so a change made elsewhere
// meanwhile is refused (409) instead of overwritten. The renderer and the helpers are pure (node tests); createAiModels
// wires the interactions on the Home page.
import { patch } from "../api.js";
import { modelLabel, sourceLabel } from "../llm.js";
import { badge, confirmDialog, html, icon, modal, toast } from "../ui.js";

export const INHERIT = "";
export const AUTO = "auto";
const RULES = "rules";
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const isCloud = (p) => p?.location === "third_party";
const INHERIT_LANE = { id: INHERIT, kind: "inherit", label: "Inherits", location: null, available: true, reason: null, default_model: "", models: [] };

// ---------- pure helpers ----------

/** A lane's name: "Claude (Anthropic)", "OpenAI (ChatGPT models)", a local server's own name, "Rules (no model)". */
export function laneLabel(p) {
  if (!p || p.id === INHERIT) return "Inherits";
  if (p.id === RULES || p.kind === RULES) return "Rules (no model)";
  const label = p.label || p.id;
  if (p.kind === "anthropic") return /anthropic/i.test(label) ? label : `${label} (Anthropic)`;
  if (p.kind === "openai" && p.variant === "azure") return /azure/i.test(label) ? label : `${label} (Azure OpenAI)`;
  if (p.kind === "openai") return /chatgpt/i.test(label) ? label : `${label} (ChatGPT models)`;
  return label;
}

/** A lane's status as text (never colour only): [text, tone, icon]. */
export function laneStatus(p) {
  if (!p || p.id === INHERIT) return ["", "", ""];
  if (p.id === RULES) return ["no model: fixed rules and templates", "", "sliders"];
  if (p.available) return ["connected", "ok", "check"];
  const reason = String(p.reason || "not available");
  if (reason.startsWith("cloud providers are switched off")) return ["blocked: cloud providers are switched off", "warn", "lock"];
  if (reason.startsWith("failing")) return ["failing: it will be retried", "bad", "alert"];
  if (reason === "HUB_LLM=off") return ["off (HUB_LLM=off)", "warn", "pause"];
  if (reason === "provider removed") return ["removed", "bad", "alert"];
  return [`not connected: ${reason}`, "warn", "alert"];
}

/** Why `agent` may not go into `lane` (a reason to show and announce), or null when it may. */
export function refusal(agent, lane) {
  if (!lane || lane.id === INHERIT) return null;
  if (!lane.available) return `${lane.label || lane.id} is ${laneStatus(lane)[0]}`;
  if (agent?.local_only && isCloud(lane)) {
    return agent.local_only_from === "team" ? `${agent.name}'s team is local-only` : `${agent.name} is local-only`;
  }
  return null;
}

/** The lane of an agent: its own provider choice ("" = it inherits). */
export const laneOf = (agent) => String(agent?.choice?.provider || INHERIT);

/** The lanes in order: Inherits, the providers as listed, providers an agent chose that are gone, then Rules. */
export function lanesOf(data) {
  const providers = data?.providers || [];
  const known = new Set(providers.map((p) => p.id));
  const gone = [...new Set((data?.agents || []).map(laneOf).filter((id) => id && !known.has(id)))]
    .map((id) => ({ id, kind: "local", label: id, location: null, available: false, reason: "provider removed", default_model: "", models: [] }));
  const rules = providers.find((p) => p.id === RULES) || { id: RULES, kind: RULES, label: "Rules", location: null, available: true, reason: null, default_model: "", models: [] };
  return [INHERIT_LANE, ...providers.filter((p) => p.id !== RULES), ...gone, rules];
}

/** The lane ids `agent` may be moved to, in lane order (its current lane included, as the place a move starts from). */
export function validLanes(agent, providers) {
  return lanesOf({ providers, agents: [agent] }).filter((l) => l.id === laneOf(agent) || !refusal(agent, l)).map((l) => l.id);
}

/** Whether a move to `lane` needs a model named: a provider without a default model. */
export const needsModel = (lane) => Boolean(lane) && ![INHERIT, RULES, AUTO].includes(lane.id) && !lane.default_model;

/** The body of PATCH /api/agents/{id}/settings for moving `agent` to `lane` ("" = inherit; an empty model = the
 *  provider's default model). Throws when the lane needs a model and none is given. */
export function dropPayload(agent, lane, model = "") {
  const id = typeof lane === "string" ? lane : lane?.id ?? INHERIT;
  const chosen = String(model || "").trim();
  if (typeof lane === "object" && needsModel(lane) && !chosen) throw new Error(`Choose a model: ${laneLabel(lane)} has no default model`);
  if (chosen.length > 200) throw new Error("A model name has at most 200 characters");
  return { llm: { provider: id, model: id === INHERIT || id === RULES ? "" : chosen }, version: agent.settings_version };
}

/** The body of PATCH /api/llm/selection making `lane` the suite default ("auto" for automatic). */
export function defaultPayload(lane, version, model = "") {
  const id = typeof lane === "string" ? lane : lane?.id;
  const provider = !id || id === AUTO ? AUTO : id;
  const chosen = String(model || "").trim();
  if (typeof lane === "object" && needsModel(lane) && !chosen) throw new Error(`Choose a model: ${laneLabel(lane)} has no default model`);
  return { default: { provider, model: provider === AUTO || provider === RULES ? "" : chosen }, version };
}

/** Where the default marker may go: "auto", every usable provider, and rules. */
export function defaultTargets(providers) {
  return [AUTO, ...(providers || []).filter((p) => p.id !== RULES && p.available).map((p) => p.id), RULES];
}

/** What runs: "Claude Opus 5.5", "GPT-6 Luna", or "Ollama on gpu-01 · llama3.1:8b" for a model name that does not say
 *  where it runs; "Rules" without a model. */
export function runsOn(provider, label, model) {
  if (!provider || provider === RULES) return "Rules";
  const pretty = modelLabel({ id: provider, label }, model);
  return model && pretty === model ? `${label || provider} · ${model}` : pretty;
}

/** The header's default line: "Automatic (now Claude Opus 5.5)", "GPT-6 Luna", "Rules (no model)". */
export function defaultText(d) {
  if (!d) return "";
  const r = d.resolved || {};
  const now = r.ready ? runsOn(r.provider, r.provider_label, r.model) : "rules: no usable provider";
  if (d.provider === AUTO) return `Automatic (now ${now})`;
  if (d.provider === RULES) return "Rules (no model)";
  const usable = r.ready && r.provider === d.provider;
  const chosen = runsOn(d.provider, d.label, d.model || (usable ? r.model : ""));
  return usable ? chosen : `${chosen} (not usable now: ${now})`;
}

/** What a chip says the agent runs on: "Claude Opus 5.5", "Rules". */
export function chipModel(agent) {
  const e = agent?.effective || {};
  if (e.provider === RULES || !e.provider) return e.source === "rules" ? "No AI model available" : "Rules";
  return runsOn(e.provider, e.provider_label, e.model);
}

/** Where the model comes from, worth saying when the chip is not simply on its own choice. */
export function chipSource(agent) {
  const e = agent?.effective || {};
  const own = laneOf(agent);
  if (own !== INHERIT && e.source === "agent") return "";
  if (own !== INHERIT && e.source !== "agent_purpose" && e.provider !== own) return `${sourceLabel(e)} - its own choice is not usable now`;
  return sourceLabel(e);
}

/** The announcement after a move: "Patch Agent moved to OpenAI; its per-task choices still apply". */
export function moveText(agent, lane, model = "") {
  const where = !lane || lane.id === INHERIT ? `${agent.name} now inherits its model` : `${agent.name} moved to ${lane.label || lane.id}${model ? ` (${model})` : ""}`;
  return agent.per_task ? `${where}; its ${agent.per_task === 1 ? "per-task choice still applies" : "per-task choices still apply"}` : where;
}

// ---------- the renderer (pure) ----------

function chipHTML(a, lane, wid, interactive) {
  const source = chipSource(a);
  const name = interactive
    ? html`<button type="button" class="ai-grab" data-act="ai-grab" data-id="${a.id}" data-ai-drag="agent" data-agent="${a.id}" aria-describedby="ai-help-${wid}"
        aria-label="${a.name}, in ${laneLabel(lane)}"><span class="ai-grip" aria-hidden="true">${icon("grip")}</span><b title="${a.name}">${a.name}</b></button>`
    : html`<b class="ai-name" title="${a.name}">${a.name}</b>`;
  const settings = typeof a.href === "string" && /^#\/agents\/[^\s"'<>`]+\/settings$/.test(a.href) ? a.href : null;
  const model = chipModel(a);
  return html`<li class="ai-chip ${a.effective?.ready ? "" : "not-ready"}" data-ai-agent="${a.id}">
    <div class="ai-chip-top">${name}${a.local_only ? badge("local only") : ""}
      ${interactive ? html`<button type="button" class="icon-btn sm ai-change" data-act="ai-change" data-id="${a.id}"
        aria-label="Change the model of ${a.name}" title="Change...">${icon("edit")}</button>` : ""}</div>
    <div class="ai-chip-model"><span class="clip-1" title="${source ? `${model} - ${source}` : model}">${model}${source ? html`<span class="faint"> · ${source}</span>` : ""}</span>
      ${a.per_task && settings ? html`<a class="ai-pertask" href="${settings}/model">+${a.per_task} per task</a>` : ""}</div></li>`;
}

function laneHTML(lane, agents, d, wid, n, interactive) {
  const [text, tone, ic] = laneStatus(lane);
  const isDefault = d.default?.provider === lane.id && lane.id !== INHERIT;
  const hid = `ai-${wid}-lane-${n}`;
  const settable = interactive && lane.id !== INHERIT && !isDefault && (lane.available || lane.id === RULES);
  return html`<section class="ai-lane ${lane.id === INHERIT ? "inherit" : ""} ${lane.available ? "" : "off"}" data-ai-lane="${lane.id}" aria-labelledby="${hid}">
    <header class="ai-lane-head"><h4 id="${hid}">${laneLabel(lane)}</h4>
      ${isDefault ? html`<span class="badge accent ai-isdefault">${icon("flag")}Default</span>` : ""}
      ${isCloud(lane) ? html`<span class="badge" title="A third-party (cloud) provider">Cloud</span>` : ""}</header>
    ${text ? html`<p class="ai-status ${tone}">${icon(ic)}<span>${text}</span></p>` : html`<p class="ai-status faint">From team, task or suite defaults</p>`}
    <ul class="ai-chips" aria-label="${laneLabel(lane)}: ${plural(agents.length, "agent")}">
      ${agents.length ? agents.map((a) => chipHTML(a, lane, wid, interactive)) : html`<li class="ai-empty faint">No agents</li>`}</ul>
    ${settable ? html`<button type="button" class="linkish ai-setdef" data-act="ai-set-default" data-id="${lane.id}"
      aria-label="Set ${laneLabel(lane)} as the suite default">Set as default...</button>` : ""}</section>`;
}

/** The widget body: (data, instance, ctx) -> html``. ctx.admin and not ctx.editing: the edit affordances. */
export function aiModelsBody(d, inst, ctx = {}) {
  const wid = inst.id;
  const interactive = Boolean(ctx.admin) && !ctx.editing;
  const lanes = lanesOf(d);
  const byLane = new Map(lanes.map((l) => [l.id, []]));
  for (const a of d.agents || []) byLane.get(laneOf(a))?.push(a);
  const auto = d.default?.provider === AUTO;
  const head = html`<div class="ai-head" data-ai-lane="${AUTO}">
    <p class="ai-default-line">Default for agents without their own choice: <b>${defaultText(d.default)}</b></p>
    ${interactive ? html`<div class="ai-head-actions">
      <button type="button" class="ai-marker" data-act="ai-marker" data-ai-drag="default" aria-describedby="ai-help-${wid}"
        aria-label="Suite default: ${d.default?.label || "Automatic"}. Move it to another provider">${icon("grip")}${icon("flag")}Default</button>
      ${auto ? html`<span class="ai-auto-target faint">Automatic: Claude, else OpenAI, else a local model</span>`
        : html`<button type="button" class="btn sm" data-act="ai-auto">Use automatic</button>`}</div>` : ""}</div>`;
  const editing = ctx.admin && ctx.editing ? html`<p class="faint dash-small">Finish editing the dashboard to change models here.</p>` : "";
  const shown = (d.agents || []).length;
  // everyone sees the same lanes; Inherits (usually the busiest) beside the providers, so every place a chip can go
  // is near the top
  return html`<div class="ai-models" data-ai="${wid}">${head}${editing}
    <div class="ai-lanes">${laneHTML(lanes[0], byLane.get(INHERIT), d, wid, 0, interactive)}
      <div class="ai-providers">${lanes.slice(1).map((l, n) => laneHTML(l, byLane.get(l.id), d, wid, n + 1, interactive))}</div></div>
    <p class="faint dash-foot">${shown ? "" : "No agents to show. "}${d.deterministic ? `${plural(d.deterministic, "agent")} work without a model. ` : ""}<a href="#/settings/ai">AI model settings</a></p>
    ${interactive ? html`<p class="sr-only" id="ai-help-${wid}">Drag to another provider, or press Space to pick up, the arrow keys to choose a provider, Space to drop and Escape to cancel.</p>` : ""}</div>`;
}

/** The configure preview's summary. */
export const aiModelsSummary = (d) => `${plural((d.agents || []).length, "agent")}, default ${d.default?.label || "Automatic"}`;

// ---------- interactions (Home page) ----------

const enc = encodeURIComponent;

function promptModel(lane, who) {
  return new Promise((resolve) => {
    let done = false;
    const list = `ai-models-${Math.random().toString(36).slice(2, 8)}`;
    modal({
      title: `Which model on ${laneLabel(lane)}?`, submit: "Use this model", minRole: "admin",
      body: html`<p class="muted" style="margin-bottom:12px">${laneLabel(lane)} has no default model. Name the model ${who} runs on.</p>
        <div class="field"><label for="${list}-in">Model</label>
          <input id="${list}-in" name="model" required maxlength="200" list="${list}" autocomplete="off" spellcheck="false"
            value="${lane.models?.[0] || ""}" placeholder="e.g. llama3.1:8b">
          <datalist id="${list}">${(lane.models || []).map((m) => html`<option value="${m}">`)}</datalist></div>`,
      onSubmit(data) {
        const model = String(data.get("model") || "").trim();
        if (!model) { toast("Name a model", "bad"); return true; }
        done = true;
        resolve(model);
      },
      onClose: () => { if (!done) resolve(null); },
    });
  });
}

/**
 * Wires the AI models widgets inside `root` (the Home page). hooks: result(wid) -> the widget's WidgetResult;
 * refresh(wid) -> Promise (refetch its data); release(wid, force = true) (draw its body from the data it has: forced,
 * a chip moved ahead of a save goes back); announce(text).
 * While a chip or the default marker is picked up or being saved, holding(wid) is true and the page holds the widget's
 * new data back (10.17).
 */
export function createAiModels(root, hooks) {
  let pick = null; // {wid, kind, id, from, targets, at, mode, el, btn, pointerId, sx, sy, active, over}
  const saving = new Set();
  let raf = 0;
  const dataOf = (wid) => hooks.result(wid)?.data || null;
  const widgetEl = (wid) => root.querySelector(`.ai-models[data-ai="${CSS.escape(wid)}"]`);
  const laneEl = (wid, id) => widgetEl(wid)?.querySelector(`[data-ai-lane="${CSS.escape(id)}"]`);
  const lane = (d, id) => (id === AUTO ? { id: AUTO, label: "Automatic", available: true } : lanesOf(d).find((l) => l.id === id) || null);
  const agentOf = (d, id) => (d?.agents || []).find((a) => a.id === id) || null;

  function targetsOf(d, kind, id) {
    if (kind === "default") return defaultTargets(d.providers);
    const agent = agentOf(d, id);
    return agent ? validLanes(agent, d.providers) : [];
  }

  function mark() {
    const w = widgetEl(pick.wid);
    if (!w) return;
    w.classList.add("ai-dragging");
    const allowed = new Set(pick.targets);
    w.querySelectorAll("[data-ai-lane]").forEach((x) => {
      const id = x.dataset.aiLane;
      if (pick.kind === "agent" && id === AUTO) return; // the header is the default marker's target only
      const own = id === pick.from;
      x.classList.toggle("ai-valid", allowed.has(id) && !own);
      x.classList.toggle("ai-invalid", !allowed.has(id) && !own);
      x.classList.toggle("ai-over", id === pick.over && allowed.has(id) && !own);
      x.classList.toggle("ai-here", id === pick.over && own && pick.mode === "keyboard");
    });
  }

  function unmark(wid) {
    const w = widgetEl(wid);
    if (!w) return;
    w.classList.remove("ai-dragging");
    w.querySelectorAll(".ai-valid, .ai-invalid, .ai-over, .ai-here").forEach((x) => x.classList.remove("ai-valid", "ai-invalid", "ai-over", "ai-here"));
    w.querySelectorAll(".ai-lifted, .ai-picked").forEach((x) => { x.classList.remove("ai-lifted", "ai-picked"); x.style.transform = ""; });
  }

  function start(btn, mode, e = null) {
    const w = btn.closest(".ai-models");
    const wid = w?.dataset.ai;
    const d = dataOf(wid);
    if (!d || saving.has(wid)) return false;
    const kind = btn.dataset.aiDrag;
    const id = kind === "agent" ? btn.dataset.agent : "default";
    const agent = kind === "agent" ? agentOf(d, id) : null;
    if (kind === "agent" && !agent) return false;
    const from = kind === "agent" ? laneOf(agent) : d.default?.provider || AUTO;
    const targets = targetsOf(d, kind, id);
    // `data`: what the person sees while moving it; newer data waits, and the drop sends these versions, so a change
    // made elsewhere meanwhile is refused (409) instead of overwritten
    pick = { wid, data: d, kind, id, from, targets, at: Math.max(0, targets.indexOf(from)), mode, btn, el: kind === "agent" ? btn.closest(".ai-chip") : btn,
      pointerId: e?.pointerId ?? null, sx: e?.clientX ?? 0, sy: e?.clientY ?? 0, x: e?.clientX ?? 0, y: e?.clientY ?? 0,
      scroll0: (btn.closest(".widget-body")?.scrollTop || 0) + window.scrollY,
      active: mode === "keyboard", over: from };
    return true;
  }

  function finish() {
    const p = pick;
    pick = null;
    if (raf) { cancelAnimationFrame(raf); raf = 0; }
    if (p) {
      unmark(p.wid);
      document.body.classList.remove("dash-dragging");
      if (p.pointerId !== null) {
        p.btn.removeEventListener("pointermove", onMove);
        p.btn.removeEventListener("pointerup", onUp);
        p.btn.removeEventListener("pointercancel", onLost);
        p.btn.removeEventListener("lostpointercapture", onLost);
      }
    }
    return p;
  }

  const nameOf = (p) => (p.kind === "default" ? "The suite default" : agentOf(dataOf(p.wid), p.id)?.name || "The agent");

  /** Drops what `p` carried on lane `to`: refuses with the reason, or saves. */
  async function drop(p, to) {
    const d = p.data || dataOf(p.wid);
    if (!d) return hooks.release(p.wid);
    if (to === p.from) {
      hooks.announce("Dropped. Not moved");
      return hooks.release(p.wid);
    }
    const target = to === AUTO && p.kind === "agent" ? null : lane(d, to);
    const refuse = (why) => {
      toast(why, "warn");
      hooks.announce(`Not moved: ${why}`);
      return hooks.release(p.wid);
    };
    if (p.kind === "agent") {
      const agent = agentOf(d, p.id);
      if (!agent) return hooks.release(p.wid);
      const why = target ? refusal(agent, target) : "Drop it on a provider";
      return why ? refuse(why) : moveAgent(p.wid, agent, target, p.el);
    }
    if (!target || !p.targets.includes(to)) {
      return refuse(target && target.id !== INHERIT ? refusal(null, target) || "Not available" : "The suite default is a provider, rules or automatic");
    }
    return setDefault(p.wid, target, null, d.selection_version);
  }

  async function moveAgent(wid, agent, target, chipEl = null, given = null) {
    const d = dataOf(wid);
    let model = given ?? "";
    if (given === null && needsModel(target)) {
      saving.add(wid); // the data stays as it is while the dialog is open
      model = await promptModel(target, agent.name);
      saving.delete(wid);
      if (model === null) {
        hooks.announce("Move cancelled");
        return hooks.release(wid);
      }
    }
    let body;
    try {
      body = dropPayload(agent, target, model);
    } catch (err) {
      toast(err.message, "bad");
      return hooks.release(wid);
    }
    const ul = laneEl(wid, target.id)?.querySelector(".ai-chips");
    if (chipEl && ul) { // optimistic: the chip is in its new lane at once
      ul.querySelector(".ai-empty")?.remove();
      ul.append(chipEl);
      chipEl.setAttribute("aria-busy", "true");
      chipEl.querySelector("[data-ai-drag]")?.focus({ preventScroll: true });
    }
    saving.add(wid);
    let ok = false;
    try {
      await patch(`/agents/${enc(agent.id)}/settings`, body);
      ok = true;
      const text = moveText(agent, target, body.llm.model);
      hooks.announce(text);
      toast(text, "ok");
    } catch (err) {
      if (err.status === 409) toast("Changed elsewhere; the widget was reloaded. Try again.", "warn");
      else if (err.status !== 401) toast(err.message, "bad");
      hooks.announce(`Not moved: ${err.message}`);
    } finally {
      saving.delete(wid);
    }
    if (!ok) hooks.release(wid); // the chip goes back
    if (d) await hooks.refresh(wid);
    return ok;
  }

  async function setDefault(wid, target, given = null, version = dataOf(wid)?.selection_version) {
    if (version === undefined || !target) return hooks.release(wid);
    let model = given ?? "";
    if (target.id === RULES && given === null) {
      saving.add(wid);
      const yes = await confirmDialog("Make rules the suite default?", "Agents without their own choice will stop using an AI model: they "
        + "answer with fixed rules and templates until you choose a provider again.", "Use rules");
      saving.delete(wid);
      if (!yes) { hooks.announce("Not changed"); return hooks.release(wid); }
    } else if (given === null && needsModel(target)) {
      saving.add(wid);
      model = await promptModel(target, "the suite default");
      saving.delete(wid);
      if (model === null) { hooks.announce("Not changed"); return hooks.release(wid); }
    }
    let body;
    try {
      body = defaultPayload(target, version, model);
    } catch (err) {
      toast(err.message, "bad");
      return hooks.release(wid);
    }
    saving.add(wid);
    let ok = false;
    try {
      await patch("/llm/selection", body);
      ok = true;
      const text = target.id === AUTO ? "The suite default is now automatic" : `The suite default is now ${laneLabel(target)}`;
      hooks.announce(text);
      toast(text, "ok");
    } catch (err) {
      if (err.status === 409) toast("Changed elsewhere; the widget was reloaded. Try again.", "warn");
      else if (err.status !== 401) toast(err.message, "bad");
      hooks.announce(`Not changed: ${err.message}`);
    } finally {
      saving.delete(wid);
    }
    if (!ok) hooks.release(wid);
    await hooks.refresh(wid);
    return ok;
  }

  // ---------- pointer ----------
  function laneAt(x, y) {
    const hit = document.elementFromPoint(x, y)?.closest?.("[data-ai-lane]");
    if (!hit || !widgetEl(pick.wid)?.contains(hit)) return null;
    return pick.kind === "agent" && hit.dataset.aiLane === AUTO ? null : hit.dataset.aiLane;
  }

  function onDown(e) {
    const btn = e.target.closest?.("[data-ai-drag]");
    if (!btn || !root.contains(btn) || pick || e.button !== 0) return;
    if (e.pointerType === "touch" && !e.target.closest(".ai-grip, .ai-marker")) return; // touch scrolls unless on the grip
    if (!start(btn, "pointer", e)) return;
    try { btn.setPointerCapture(e.pointerId); } catch { /* the pointer is gone already */ }
    btn.addEventListener("pointermove", onMove);
    btn.addEventListener("pointerup", onUp);
    btn.addEventListener("pointercancel", onLost);
    btn.addEventListener("lostpointercapture", onLost);
    if (e.pointerType === "mouse") e.preventDefault();
    btn.focus({ preventScroll: true });
  }

  function onMove(e) {
    if (!pick || e.pointerId !== pick.pointerId) return;
    pick.x = e.clientX;
    pick.y = e.clientY;
    if (!pick.active) {
      if (Math.hypot(pick.x - pick.sx, pick.y - pick.sy) < (e.pointerType === "touch" ? 8 : 4)) return;
      pick.active = true;
      pick.el.classList.add("ai-lifted");
      document.body.classList.add("dash-dragging");
      hooks.announce(`Picked up ${nameOf(pick)}`);
    }
    if (!raf) raf = requestAnimationFrame(frame);
  }

  const scrolled = (body) => (body?.scrollTop || 0) + window.scrollY;

  function frame() {
    raf = 0;
    if (!pick?.active) return;
    const body = pick.el.closest(".widget-body");
    // near an edge, scroll the widget, else the page (one column on phones): the lanes may be out of sight
    const r = body?.getBoundingClientRect();
    const dy = r && pick.y < r.top + 24 && body.scrollTop > 0 ? -8
      : r && pick.y > r.bottom - 24 && body.scrollTop + body.clientHeight < body.scrollHeight ? 8 : 0;
    if (dy) body.scrollTop += dy;
    else if (pick.y < 48 || pick.y > window.innerHeight - 48) window.scrollBy(0, pick.y < 48 ? -10 : 10);
    if (dy || pick.y < 48 || pick.y > window.innerHeight - 48) { if (!raf) raf = requestAnimationFrame(frame); } // keep scrolling while held there
    // the chip follows the pointer; scrolling moves its place in the layout, so that is added back
    pick.el.style.transform = `translate(${pick.x - pick.sx}px, ${pick.y - pick.sy + scrolled(body) - pick.scroll0}px)`;
    const over = laneAt(pick.x, pick.y);
    if (over !== pick.over) {
      pick.over = over;
      mark();
    }
  }

  function onUp(e) {
    if (!pick || e.pointerId !== pick.pointerId) return;
    const active = pick.active;
    const to = active ? laneAt(e.clientX, e.clientY) : null;
    const p = finish();
    if (!active) return hooks.release(p.wid, false); // a click: data that arrived meanwhile is applied
    if (to === null) {
      hooks.announce("Move cancelled");
      return hooks.release(p.wid);
    }
    drop(p, to);
  }

  function onLost(e) {
    if (!pick || e.pointerId !== pick.pointerId) return;
    const p = finish();
    if (p.active) {
      hooks.announce("Move cancelled");
      hooks.release(p.wid);
    }
  }

  // ---------- keyboard ----------
  function laneName(d, id) {
    if (id === AUTO) return "Automatic";
    const l = lane(d, id);
    return l ? laneLabel(l) : id;
  }

  function onKey(e) {
    if (pick?.mode === "pointer" && pick.active && e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      const p = finish();
      hooks.announce("Move cancelled");
      return hooks.release(p.wid);
    }
    const btn = e.target.closest?.("[data-ai-drag]");
    if (!btn || !root.contains(btn)) return;
    const k = e.key;
    if (!pick) {
      if (k !== " " && k !== "Enter") return;
      e.preventDefault();
      if (!start(btn, "keyboard")) return;
      pick.el.classList.add("ai-picked");
      mark();
      const d = dataOf(pick.wid);
      hooks.announce(`Picked up ${nameOf(pick)}, in ${laneName(d, pick.from)}. ${pick.targets.length > 1
        ? "Use the arrow keys to choose a provider, Space to drop, Escape to cancel." : "There is no other provider it can go to. Press Escape."}`);
      return;
    }
    if (pick.mode !== "keyboard" || pick.btn !== btn) return;
    if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End", " ", "Enter", "Escape"].includes(k)) e.preventDefault();
    const d = dataOf(pick.wid);
    if (k === "Escape") {
      e.stopPropagation();
      const p = finish();
      hooks.announce("Move cancelled");
      return hooks.release(p.wid);
    }
    if (k === " " || k === "Enter") {
      const p = finish();
      return drop(p, p.over);
    }
    const n = pick.targets.length;
    if (!n) return;
    if (k === "ArrowRight" || k === "ArrowDown") pick.at = (pick.at + 1) % n;
    else if (k === "ArrowLeft" || k === "ArrowUp") pick.at = (pick.at - 1 + n) % n;
    else if (k === "Home") pick.at = 0;
    else if (k === "End") pick.at = n - 1;
    else return;
    pick.over = pick.targets[pick.at];
    mark();
    laneEl(pick.wid, pick.over)?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
    hooks.announce(`${laneName(d, pick.over)}${pick.over === pick.from ? ", where it is now" : ""}`);
  }

  function onFocusOut(e) {
    if (!pick || pick.mode !== "keyboard" || e.target !== pick.btn || e.relatedTarget === pick.btn) return;
    const p = finish();
    hooks.announce("Move cancelled");
    hooks.release(p.wid);
  }

  // ---------- single pointer: the Change... dialog, Set as default..., Use automatic ----------
  function change(wid, agentId) {
    const d = dataOf(wid);
    const agent = agentOf(d, agentId);
    if (!d || !agent) return;
    const lanes = lanesOf(d).filter((l) => l.reason !== "provider removed" || l.id === laneOf(agent));
    let saved = false;
    let conflict = false;
    const list = `ai-change-${Math.random().toString(36).slice(2, 8)}`;
    const opt = (l) => {
      const why = l.id === laneOf(agent) ? null : refusal(agent, l);
      const label = l.id === INHERIT ? "Inherit (team, task or suite default)" : laneLabel(l);
      return html`<option value="${l.id}" ${l.id === laneOf(agent) ? "selected" : ""} ${why ? "disabled" : ""}>${label}${why ? ` - ${why}` : ""}</option>`;
    };
    saving.add(wid);
    const m = modal({
      title: `Model of ${agent.name}`, submit: "Save", minRole: "admin",
      body: html`<p class="muted" style="margin-bottom:12px">Now: <b>${chipModel(agent)}</b>${chipSource(agent) ? ` (${chipSource(agent)})` : ""}.
          ${agent.per_task ? html` Its ${plural(agent.per_task, "per-task choice")} stay as they are (<a href="${agent.href}/model">edit them</a>).` : ""}</p>
        <div class="form-grid">
          <div class="field"><label for="${list}-p">Provider</label><select id="${list}-p" name="provider">${lanes.map(opt)}</select></div>
          <div class="field"><label for="${list}-m">Model</label><input id="${list}-m" name="model" maxlength="200" list="${list}" autocomplete="off" spellcheck="false"
            value="${agent.choice?.model || ""}"><datalist id="${list}"></datalist><span class="hint" data-model-hint></span></div></div>`,
      async onSubmit(data) {
        const target = lanes.find((l) => l.id === String(data.get("provider") ?? ""));
        const model = String(data.get("model") || "").trim();
        if (!target) return true;
        if (target.id === laneOf(agent) && (target.id === INHERIT || target.id === RULES || model === (agent.choice?.model || ""))) {
          toast("Nothing changed", "info");
          return false;
        }
        if (needsModel(target) && !model) { toast(`Name a model: ${laneLabel(target)} has no default model`, "bad"); return true; }
        try {
          await patch(`/agents/${enc(agent.id)}/settings`, dropPayload(agent, target, model));
        } catch (err) {
          if (err.status !== 409) throw err; // the dialog stays open with the message
          toast("Changed elsewhere; the widget was reloaded. Try again.", "warn");
          conflict = true;
          return false;
        }
        saved = true;
        const text = moveText(agent, target, model);
        hooks.announce(text);
        toast(text, "ok");
        return false;
      },
      onClose: () => {
        saving.delete(wid);
        hooks.release(wid, false);
        if (saved || conflict) hooks.refresh(wid);
      },
    });
    const select = m.el.querySelector("select");
    const input = m.el.querySelector('input[name="model"]');
    const sync = () => {
      const l = lanes.find((x) => x.id === select.value);
      const none = !l || l.id === INHERIT || l.id === RULES;
      input.disabled = none;
      if (none) input.value = "";
      input.placeholder = none ? "No model" : l.default_model ? `Provider default (${l.default_model})` : "Required: this provider has no default model";
      input.required = Boolean(l && needsModel(l));
      const dl = m.el.querySelector("datalist");
      dl.replaceChildren(...(none ? [] : l.models || []).map((x) => Object.assign(document.createElement("option"), { value: x })));
      m.el.querySelector("[data-model-hint]").textContent = none ? "" : "Leave empty to use the provider's default model.";
    };
    select.addEventListener("change", sync);
    sync();
  }

  function setDefaultFrom(wid, laneId) {
    const d = dataOf(wid);
    const target = d ? lane(d, laneId) : null;
    if (!target) return;
    if (target.id !== RULES && target.id !== AUTO && !target.available) return toast(refusal(null, target) || "Not available", "warn");
    setDefault(wid, target);
  }

  function onClick(e) {
    const btn = e.target.closest?.("[data-act]");
    if (!btn || !root.contains(btn) || !btn.closest(".ai-models")) return;
    const { act, id } = btn.dataset;
    const wid = btn.closest(".ai-models").dataset.ai;
    if (act === "ai-change") { e.preventDefault(); change(wid, id); }
    else if (act === "ai-set-default") { e.preventDefault(); setDefaultFrom(wid, id); }
    else if (act === "ai-auto") { e.preventDefault(); setDefaultFrom(wid, AUTO); }
  }

  root.addEventListener("pointerdown", onDown);
  root.addEventListener("keydown", onKey, true);
  root.addEventListener("focusout", onFocusOut);
  root.addEventListener("click", onClick);

  return {
    /** Whether the widget's new data must wait (a pick-up or a save in progress). */
    holding: (wid) => Boolean((pick && pick.wid === wid) || saving.has(wid)),
    destroy() {
      const p = finish();
      if (p) hooks.release(p.wid);
      root.removeEventListener("pointerdown", onDown);
      root.removeEventListener("keydown", onKey, true);
      root.removeEventListener("focusout", onFocusOut);
      root.removeEventListener("click", onClick);
    },
  };
}
