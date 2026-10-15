// The stage-D4 settings widgets (round4-dashboard-spec.md 6.7, 10.16-10.17): the AI models widget's pure helpers (which
// lanes an agent may go to, the bodies it sends to R4-LLM's routes), its renderer (escaped text, edit affordances only
// for administrators outside edit mode, accessible lane names), the safety and accounts renderers, and the planning of
// "Add to Home" (hub/web/js/dashboard/aimodels.js, widgets.js, addhome.js).
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  AUTO, INHERIT, aiModelsBody, aiModelsSummary, chipModel, chipSource, defaultPayload, defaultTargets, defaultText, dropPayload, laneLabel,
  laneOf, laneStatus, lanesOf, moveText, needsModel, refusal, validLanes,
} from "../../hub/web/js/dashboard/aimodels.js";
import { HOME_WIDGETS, MY_DASHBOARD, canonical, homeTarget, placeWidget, sameWidget } from "../../hub/web/js/dashboard/addhome.js";
import { widgetBody } from "../../hub/web/js/dashboard/widgets.js";

const EVIL = `<img src=x onerror="alert(1)">`;
const s = (x) => String(x);
const safe = (out, label) => {
  assert.doesNotMatch(out, /<img/i, label);
  assert.doesNotMatch(out, /onerror="/i, label);
};
const inst = (type, extra = {}) => ({ id: "w_ai0000001", type, x: 0, y: 0, w: 8, h: 4, title: null, config: {}, ...extra });
const ok = (data) => ({ status: "ok", data, code: null, message: null, hint: null, version: "v1", generated_at: 1000, stale_after: 2000 });

const CLAUDE = { id: "anthropic", kind: "anthropic", variant: null, label: "Claude", location: "third_party", available: true, reason: null,
  default_model: "claude-opus-5-5", models: ["claude-opus-5-5"] };
const OPENAI = { id: "openai", kind: "openai", variant: "openai", label: "OpenAI", location: "third_party", available: false, reason: "no API key",
  default_model: "", models: [] };
const OLLAMA = { id: "lp_ollama", kind: "openai_compatible", variant: null, label: "Ollama on gpu-01", location: "self_hosted", available: true,
  reason: null, default_model: "llama3.1:8b", models: ["llama3.1:8b", "qwen3:8b"] };
const BARE = { id: "lp_bare", kind: "openai_compatible", variant: null, label: "Bare server", location: "self_hosted", available: true, reason: null,
  default_model: "", models: ["phi4"] };
const RULES = { id: "rules", kind: "rules", variant: null, label: "Rules", location: null, available: true, reason: null, default_model: "", models: [] };
const PROVIDERS = [CLAUDE, OPENAI, RULES, OLLAMA, BARE];

const agent = (id, name, extra = {}) => ({
  id, name, title: "", team: "hub", kind: "core", settings_version: 4, choice: { provider: "", model: "" }, local_only: false,
  local_only_from: null, per_task: 0, href: `#/agents/${encodeURIComponent(id)}/settings`,
  effective: { provider: "anthropic", provider_label: "Claude", model: "claude-opus-5-5", location: "third_party", source: "suite",
    source_label: "Suite default (automatic)", fallback: false, ready: true },
  ...extra,
});
const SUPERVISOR = agent("supervisor", "Hub Supervisor");
const LOCAL = agent("triage", "Triage", { kind: "custom", local_only: true, local_only_from: "agent", choice: { provider: "lp_ollama", model: "" },
  effective: { provider: "lp_ollama", provider_label: "Ollama on gpu-01", model: "llama3.1:8b", location: "self_hosted", source: "agent",
    source_label: "This agent's choice", fallback: false, ready: true } });
const PATCHER = agent("patcher", "Patch Agent", { per_task: 1 });
const DATA = {
  selection_version: 3, providers: PROVIDERS, agents: [SUPERVISOR, LOCAL, PATCHER], deterministic: 3, href: "#/settings/ai",
  default: { provider: "auto", model: "", label: "Automatic",
    resolved: { provider: "anthropic", provider_label: "Claude", model: "claude-opus-5-5", ready: true, fallback: false } },
};

test("lanes have readable names and a status in words", () => {
  assert.equal(laneLabel(CLAUDE), "Claude (Anthropic)");
  assert.equal(laneLabel(OPENAI), "OpenAI (ChatGPT models)");
  assert.equal(laneLabel({ ...OPENAI, label: "Production", variant: "azure" }), "Production (Azure OpenAI)");
  assert.equal(laneLabel({ ...OPENAI, label: "Azure prod", variant: "azure" }), "Azure prod");
  assert.equal(laneLabel(OLLAMA), "Ollama on gpu-01");
  assert.equal(laneLabel(RULES), "Rules (no model)");
  assert.equal(laneLabel({ id: INHERIT }), "Inherits");
  assert.deepEqual(laneStatus(CLAUDE).slice(0, 2), ["connected", "ok"]);
  assert.equal(laneStatus(OPENAI)[0], "not connected: no API key");
  assert.equal(laneStatus({ ...CLAUDE, available: false, reason: "cloud providers are switched off (guardrail)" })[0],
    "blocked: cloud providers are switched off");
  assert.equal(laneStatus({ ...OLLAMA, available: false, reason: "failing" })[1], "bad");
});

test("lanes come in order: Inherits, the providers, providers that are gone, then Rules", () => {
  const gone = agent("old", "Old", { choice: { provider: "lp_removed", model: "x" } });
  const ids = lanesOf({ providers: PROVIDERS, agents: [SUPERVISOR, gone] }).map((l) => l.id);
  assert.deepEqual(ids, [INHERIT, "anthropic", "openai", "lp_ollama", "lp_bare", "lp_removed", "rules"]);
  const removed = lanesOf({ providers: PROVIDERS, agents: [gone] }).find((l) => l.id === "lp_removed");
  assert.equal(removed.available, false);
  assert.equal(laneOf(gone), "lp_removed");
  assert.equal(laneOf(SUPERVISOR), INHERIT);
});

test("validLanes leaves out unavailable providers, and cloud providers for a local-only agent", () => {
  assert.deepEqual(validLanes(SUPERVISOR, PROVIDERS), [INHERIT, "anthropic", "lp_ollama", "lp_bare", "rules"]);
  assert.deepEqual(validLanes(LOCAL, PROVIDERS), [INHERIT, "lp_ollama", "lp_bare", "rules"]);
  // its own lane stays a valid place to start from (and drop back on) even when it cannot take calls now
  const stuck = agent("s", "Stuck", { choice: { provider: "openai", model: "gpt-6" } });
  assert.ok(validLanes(stuck, PROVIDERS).includes("openai"));
  assert.equal(refusal(SUPERVISOR, OPENAI), "OpenAI is not connected: no API key");
  assert.equal(refusal(LOCAL, CLAUDE), "Triage is local-only");
  assert.equal(refusal({ ...LOCAL, local_only_from: "team" }, CLAUDE), "Triage's team is local-only");
  assert.equal(refusal(LOCAL, OLLAMA), null);
  assert.equal(refusal(LOCAL, { id: INHERIT }), null);
});

test("dropPayload is what PATCH /api/agents/{id}/settings takes: inherit is an empty provider", () => {
  assert.deepEqual(dropPayload(SUPERVISOR, lanesOf(DATA)[0]), { llm: { provider: "", model: "" }, version: 4 });
  assert.deepEqual(dropPayload(SUPERVISOR, OLLAMA), { llm: { provider: "lp_ollama", model: "" }, version: 4 });
  assert.deepEqual(dropPayload(SUPERVISOR, RULES, "ignored"), { llm: { provider: "rules", model: "" }, version: 4 });
  assert.ok(needsModel(BARE) && !needsModel(OLLAMA) && !needsModel(RULES) && !needsModel({ id: INHERIT }));
  assert.throws(() => dropPayload(SUPERVISOR, BARE), /has no default model/);
  assert.deepEqual(dropPayload(SUPERVISOR, BARE, " phi4 "), { llm: { provider: "lp_bare", model: "phi4" }, version: 4 });
  assert.throws(() => dropPayload(SUPERVISOR, BARE, "m".repeat(201)), /200 characters/);
  assert.deepEqual(dropPayload(SUPERVISOR, "anthropic"), { llm: { provider: "anthropic", model: "" }, version: 4 });
});

test("defaultPayload is what PATCH /api/llm/selection takes for the default marker", () => {
  assert.deepEqual(defaultPayload(AUTO, 3), { default: { provider: "auto", model: "" }, version: 3 }); // "Use automatic"
  assert.deepEqual(defaultPayload({ id: AUTO, label: "Automatic" }, 3), { default: { provider: "auto", model: "" }, version: 3 });
  assert.deepEqual(defaultPayload(OLLAMA, 3), { default: { provider: "lp_ollama", model: "" }, version: 3 });
  assert.deepEqual(defaultPayload(RULES, 7), { default: { provider: "rules", model: "" }, version: 7 });
  assert.throws(() => defaultPayload(BARE, 3), /has no default model/);
  assert.deepEqual(defaultPayload(BARE, 3, "phi4"), { default: { provider: "lp_bare", model: "phi4" }, version: 3 });
  assert.deepEqual(defaultTargets(PROVIDERS), [AUTO, "anthropic", "lp_ollama", "lp_bare", "rules"]);
});

test("the default line, chips and announcements say where a model comes from", () => {
  assert.equal(defaultText(DATA.default), "Automatic (now Claude Opus 5.5)");
  assert.equal(defaultText({ provider: "rules", model: "", label: "Rules", resolved: { provider: "rules", ready: false } }), "Rules (no model)");
  const onOllama = { provider: "lp_ollama", model: "", label: "Ollama on gpu-01",
    resolved: { provider: "lp_ollama", provider_label: "Ollama on gpu-01", model: "llama3.1:8b", ready: true } };
  assert.equal(defaultText(onOllama), "Ollama on gpu-01 · llama3.1:8b");
  const down = { ...onOllama, resolved: { provider: "anthropic", provider_label: "Claude", model: "claude-opus-5-5", ready: true } };
  assert.match(defaultText(down), /not usable now: Claude Opus/);
  assert.equal(chipModel(SUPERVISOR), "Claude Opus 5.5");
  assert.equal(chipSource(SUPERVISOR), "Suite default (automatic)");
  assert.equal(chipSource(LOCAL), "");
  const fellBack = { ...LOCAL, effective: { ...SUPERVISOR.effective, source: "fallback", source_label: "Fallback" } };
  assert.equal(chipSource(fellBack), "Fallback - its own choice is not usable now");
  const perTask = { ...LOCAL, effective: { ...SUPERVISOR.effective, source: "agent_purpose", source_label: "This agent's choice for code changes" } };
  assert.equal(chipSource(perTask), "This agent's choice for code changes");
  assert.equal(chipModel({ effective: { provider: "rules", source: "rules" } }), "No AI model available");
  assert.equal(chipModel({ effective: { provider: "rules", source: "agent" } }), "Rules");
  assert.equal(moveText(PATCHER, { id: "openai", label: "OpenAI" }), "Patch Agent moved to OpenAI; its per-task choice still applies");
  assert.equal(moveText(SUPERVISOR, { id: INHERIT }), "Hub Supervisor now inherits its model");
  assert.equal(moveText(SUPERVISOR, BARE, "phi4"), "Hub Supervisor moved to Bare server (phi4)");
  assert.equal(aiModelsSummary(DATA), "3 agents, default Automatic");
});

test("the AI models widget escapes names and labels from agents and model servers", () => {
  const evilProvider = { ...OLLAMA, id: "lp_evil", label: EVIL, default_model: EVIL, models: [EVIL] };
  const evilAgent = agent("evil", EVIL, { title: EVIL, choice: { provider: "lp_evil", model: EVIL },
    effective: { ...OLLAMA, provider: "lp_evil", provider_label: EVIL, model: EVIL, source: "agent", source_label: EVIL, ready: true } });
  const data = { ...DATA, providers: [...PROVIDERS, evilProvider], agents: [evilAgent, SUPERVISOR],
    default: { provider: "lp_evil", model: EVIL, label: EVIL, resolved: { provider: "lp_evil", provider_label: EVIL, model: EVIL, ready: true } } };
  for (const admin of [false, true]) {
    const out = s(widgetBody(ok(data), inst("ai_models"), { admin }));
    safe(out, `admin ${admin}`);
    assert.match(out, /&lt;img/);
  }
});

test("administrators get drag handles, Change and default buttons; everyone else reads the same lanes", () => {
  const admin = s(aiModelsBody(DATA, inst("ai_models"), { admin: true }));
  assert.equal((admin.match(/data-ai-drag="agent"/g) || []).length, 3);
  assert.equal((admin.match(/data-act="ai-change"/g) || []).length, 3);
  assert.match(admin, /data-ai-drag="default"/);
  assert.match(admin, /data-act="ai-set-default" data-id="lp_ollama"/);
  assert.doesNotMatch(admin, /data-act="ai-set-default" data-id="openai"/); // not usable: not offered as the default
  assert.doesNotMatch(admin, /data-act="ai-auto"/); // already automatic
  assert.match(admin, /aria-describedby="ai-help-w_ai0000001"/);
  assert.match(admin, /id="ai-help-w_ai0000001"/);
  assert.match(admin, /aria-label="Hub Supervisor, in Inherits"/);
  assert.match(admin, /aria-label="Triage, in Ollama on gpu-01"/);
  assert.match(admin, /aria-label="Inherits: 2 agents"/);
  assert.match(admin, /aria-label="Ollama on gpu-01: 1 agent"/);
  assert.match(admin, /aria-label="OpenAI \(ChatGPT models\): 0 agents"/); // every lane, also the ones that cannot take calls
  assert.match(admin, /not connected: no API key/);
  assert.match(admin, />Cloud</);
  assert.match(admin, /local only/);
  assert.match(admin, /href="#\/agents\/patcher\/settings\/model">\+1 per task/);
  assert.match(admin, /3 agents work without a model/);
  const onProvider = s(aiModelsBody({ ...DATA, default: { ...DATA.default, provider: "lp_ollama", label: "Ollama on gpu-01" } }, inst("ai_models"), { admin: true }));
  assert.match(onProvider, /data-act="ai-auto"/);
  assert.doesNotMatch(onProvider, /data-act="ai-set-default" data-id="lp_ollama"/); // it is the default already
  for (const ctx of [{}, { admin: false }, { admin: true, editing: true }]) {
    const out = s(aiModelsBody(DATA, inst("ai_models"), ctx));
    assert.doesNotMatch(out, /data-ai-drag|data-act="ai-|ai-grip/, JSON.stringify(ctx));
    assert.match(out, /aria-label="Inherits: 2 agents"/);
    assert.match(out, /aria-label="OpenAI \(ChatGPT models\): 0 agents"/); // the same lanes as administrators see
  }
  assert.match(s(aiModelsBody(DATA, inst("ai_models"), { admin: true, editing: true })), /Finish editing the dashboard/);
  assert.match(s(aiModelsBody({ ...DATA, agents: [] }, inst("ai_models"), {})), /No agents to show/);
});

test("a chip's settings link is only ever an internal agent settings route", () => {
  const out = s(aiModelsBody({ ...DATA, agents: [{ ...PATCHER, href: "javascript:alert(1)" }] }, inst("ai_models"), { admin: true }));
  assert.doesNotMatch(out, /javascript:/);
  assert.doesNotMatch(out, /per task/);
});

test("the safety settings and hub accounts widgets", () => {
  const safety = s(widgetBody(ok({ autonomy: "autonomous", relaxed: [{ key: "x", title: EVIL, group: "models", control: "HB-AC-6" }],
    controls_affected: ["HB-AC-6"], total_guardrails: 20, device_changes_on: true, cloud_ai: false, spend_limit: null, href: "#/settings" }),
    inst("safety_settings"), {}));
  safe(safety, "safety_settings");
  assert.match(safety, /Autonomous/);
  assert.match(safety, /1<\/b><span>guardrail relaxed/);
  assert.match(safety, /AI models and spending/);
  assert.match(safety, /cloud AI blocked/);
  assert.match(safety, /no AI spending cap/);
  assert.match(safety, /Weakens compliance control HB-AC-6/);
  const calm = s(widgetBody(ok({ autonomy: "assisted", relaxed: [], controls_affected: [], total_guardrails: 20, device_changes_on: false,
    cloud_ai: true, spend_limit: 20, href: "#/settings" }), inst("safety_settings"), {}));
  assert.match(calm, /All 20 guardrails are at their safe setting/);
  assert.match(calm, /AI spending cap \$20\/day/);
  const accounts = s(widgetBody(ok({ by_role: { admin: 1, operator: 2, viewer: 0 }, total: 4, disabled: 1, dormant_total: 1,
    dormant_90d: [{ username: EVIL, last_seen: null }], tokens_active: 1, href: "#/users" }), inst("hub_accounts"), { now: 2000 }));
  safe(accounts, "hub_accounts");
  assert.match(accounts, /1 API token active/);
  assert.match(accounts, /never signed in/);
});

test("Add to Home: the target dashboard, the free place and no duplicates", () => {
  const list = (dashboards, home_id, default_id = "s_0000000001") => ({ dashboards, home_id, default_id });
  const shared = { id: "s_0000000001", scope: "shared" };
  const mine = { id: "p_0000000001", scope: "personal" };
  const other = { id: "p_0000000002", scope: "personal" };
  assert.deepEqual(homeTarget(list([shared, mine, other], other.id)), { id: other.id }); // the home, when personal
  assert.deepEqual(homeTarget(list([shared, mine], shared.id)), { id: mine.id }); // else the first personal one
  assert.deepEqual(homeTarget(list([shared], shared.id)), { create: true, from: shared.id, home: true }); // else a copy
  assert.deepEqual(homeTarget(list([], null, null)), { create: true, from: null, home: true });
  assert.equal(MY_DASHBOARD, "My dashboard");
  assert.equal(canonical({ b: [1, { d: 2, c: 1 }], a: null }), '{"a":null,"b":[1,{"c":1,"d":2}]}');
  assert.ok(sameWidget({ type: "ai_models", config: { show: "all" } }, HOME_WIDGETS.ai_models));
  assert.ok(!sameWidget({ type: "ai_models", config: { show: "custom" } }, HOME_WIDGETS.ai_models));
  assert.ok(sameWidget({ type: "metric", config: { metric: "llm_spend_today" } }, HOME_WIDGETS.llm_spend_today));
  const widgets = [{ id: "w_a", type: "metric", x: 0, y: 0, w: 12, h: 1, config: {} }, { id: "w_b", type: "note", x: 0, y: 1, w: 4, h: 2, config: {} }];
  const added = placeWidget(widgets, HOME_WIDGETS.ai_models, { w: 8, h: 4 });
  assert.deepEqual({ x: added.x, y: added.y, w: added.w, h: added.h, type: added.type, title: added.title }, { x: 4, y: 1, w: 8, h: 4, type: "ai_models", title: null });
  assert.match(added.id, /^w_[0-9a-z]{10}$/);
  assert.deepEqual(added.config, { show: "all" });
  assert.equal(placeWidget(widgets, HOME_WIDGETS.ai_models, { w: 8, h: 4 }, 2), null); // the widget limit
  assert.deepEqual(Object.keys(HOME_WIDGETS).sort(), ["ai_models", "llm_spend_today", "network_overview", "safety_settings"]);
});
