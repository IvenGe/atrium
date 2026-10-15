// The AI model screens' pure helpers (hub/web/js/llm.js): provider kinds, status badges, key lines, capability chips
// and where a model server runs (the same rule as hub/llm/registry.py location_of).
import assert from "node:assert/strict";
import { test } from "node:test";
import {
  attentionText, blockedText, budgetText, capsAllowTemperature, capsChips, capsUnknown, chainLine, changeWords, cleanRules, diffSettings,
  effectiveText, effortChoices, errorPath, hostLocation, keyLine, languageChoice, memoryText, meterTone, modelLabel, parseModels, plainHttp,
  providerKind, providerStatus, reorder, retryText, settingsBody, severityTone, sourceLabel, tabOf, tokenCapWarning,
} from "../../hub/web/js/llm.js";

test("provider kinds", () => {
  assert.equal(providerKind({ kind: "anthropic" }), "anthropic");
  assert.equal(providerKind({ kind: "openai", variant: "openai" }), "openai");
  assert.equal(providerKind({ kind: "openai", variant: "azure" }), "azure");
  assert.equal(providerKind({ kind: "openai_compatible", location: "self_hosted" }), "local");
  assert.equal(providerKind({ kind: "openai_compatible", location: "third_party" }), "cloud");
  assert.equal(providerKind(null), "rules");
});

test("status badges say why a provider cannot take calls", () => {
  const claude = { id: "anthropic", kind: "anthropic" };
  assert.deepEqual(providerStatus(claude, { available: false, reason: "HUB_LLM=off" }), ["off (HUB_LLM=off)", "warn"]);
  assert.deepEqual(providerStatus(claude, { available: false, reason: "failing - retry in 30s" }), ["failing", "bad"]);
  assert.deepEqual(providerStatus(claude, { available: false, reason: "no API key" }), ["not connected", "warn"]);
  assert.deepEqual(providerStatus(claude, { available: true, key_source: "env" }), ["key from environment", "ok"]);
  assert.deepEqual(providerStatus(claude, { available: true, key_source: "stored" }), ["connected", "ok"]);
  assert.deepEqual(providerStatus({ kind: "openai", id: "openai" }, { available: false, reason: "switched off" }), ["switched off", ""]);
  const local = { kind: "openai_compatible" };
  assert.deepEqual(providerStatus(local, { available: true }), ["not tested", "warn"]);
  assert.deepEqual(providerStatus({ ...local, last_test: { ok: true } }, { available: true }), ["tested ok", "ok"]);
  assert.deepEqual(providerStatus({ ...local, last_test: { ok: false } }, { available: true }), ["test failed", "bad"]);
});

test("the key line names the source, never a key", () => {
  assert.match(keyLine({ id: "openai", key_source: "env", api_key_set: true }), /OPENAI_API_KEY from the environment \(it overrides/);
  assert.match(keyLine({ id: "anthropic", key_source: "profile" }), /ant auth login/);
  assert.equal(keyLine({ id: "azure", kind: "openai", key_source: "stored", api_key_set: true }), "API key stored (encrypted)");
  assert.match(keyLine({ id: "x", kind: "openai_compatible" }), /most local servers need none/);
});

test("capability chips", () => {
  assert.deepEqual(capsChips(null), []);
  const chips = capsChips({ tools: true, json_schema: false, json_object: true, effort_levels: ["none", "low", "medium", "high", "xhigh", "max"],
    max_output_tokens: 128000, temperature: false, lifecycle: "deprecated", retires_at: "2027-01-31T00:00:00Z" });
  assert.deepEqual(chips.map(([t]) => t), ["tools", "JSON mode only", "effort: none-max", "fixed sampling", "128k out", "deprecated - retires 2027-01-31"]);
  assert.deepEqual(capsChips({ tools: false, effort_levels: [] }).map(([t]) => t), ["no tools", "no effort setting"]);
  assert.deepEqual(capsChips({ max_output_tokens: 1_050_000 }).map(([t]) => t), ["1.1M out"]);
  assert.ok(capsUnknown(undefined) && capsUnknown({ tools: true }) && !capsUnknown({ tools: false, json_schema: true }));
});

test("where a model server runs follows the server-side rule", () => {
  const cases = [
    ["http://localhost:11434/v1", "self_hosted"], ["http://127.0.0.1:8000/v1", "self_hosted"], ["http://10.1.2.3/v1", "self_hosted"],
    ["http://192.168.1.20:1234/v1", "self_hosted"], ["http://172.20.0.5/v1", "self_hosted"], ["http://[fd00::5]:8000/v1", "self_hosted"],
    ["http://gpu-box:11434/v1", "self_hosted"], ["http://ollama.local/v1", "self_hosted"], ["https://llm.example.com/v1", "third_party"],
    ["https://8.8.8.8/v1", "third_party"], ["http://gpu-box.lan:11434/v1", "third_party"], ["http://172.32.0.1/v1", "third_party"],
    ["not a url", null],
  ];
  for (const [url, where] of cases) assert.equal(hostLocation(url), where, url);
});

test("plain http to another machine is flagged; models typed one per line", () => {
  assert.equal(plainHttp("http://gpu-box:11434/v1"), "gpu-box");
  assert.equal(plainHttp("http://localhost:11434/v1"), null);
  assert.equal(plainHttp("http://127.0.0.1:1234/v1"), null);
  assert.equal(plainHttp("https://gpu-box/v1"), null);
  assert.deepEqual(parseModels(" prod-gpt \n\nbatch-gpt, prod-gpt\n"), ["prod-gpt", "batch-gpt"]);
});

test("model labels read like the providers name their models", () => {
  assert.equal(modelLabel("anthropic", "claude-opus-5-5"), "Claude Opus 5.5");
  assert.equal(modelLabel("anthropic", "claude-fable-5-1"), "Claude Fable 5.1");
  assert.equal(modelLabel("anthropic", "claude-sonnet-5"), "Claude Sonnet 5");
  assert.equal(modelLabel({ id: "openai", label: "OpenAI" }, "gpt-6.1-sol"), "GPT-6.1 Sol");
  assert.equal(modelLabel("openai", "gpt-6-luna"), "GPT-6 Luna");
  assert.equal(modelLabel("ollama", "qwen3:8b"), "qwen3:8b");
  assert.equal(modelLabel({ id: "ollama", label: "Ollama on gpu-01" }, ""), "Ollama on gpu-01 (default model)");
  assert.equal(modelLabel("rules", ""), "Rules");
  assert.equal(modelLabel("", ""), "Rules");
});

test("where a model comes from", () => {
  const team = { provider: "openai", provider_label: "OpenAI", model: "gpt-6-luna", source: "team", source_label: "Compliance team default", blocked: [] };
  assert.equal(sourceLabel(team), "Compliance team default");
  assert.equal(effectiveText(team), "GPT-6 Luna · Compliance team default");
  assert.equal(sourceLabel({ provider: "rules", source: "rules", source_label: "No AI model available" }), "No AI model available");
  assert.equal(sourceLabel({ source: "suite" }), "Suite default");
  assert.equal(sourceLabel(null), "");
  assert.equal(effectiveText({ provider: "rules", source: "agent", source_label: "This agent's choice" }), "Rules · This agent's choice");
  const blocked = { blocked: [{ level: "agent", provider: "anthropic", reason: "agent is local-only" }, { level: "suite", provider: "auto", reason: "no usable provider" }] };
  assert.equal(blockedText(blocked), "anthropic: agent is local-only; automatic choice: no usable provider");
});

test("reordering the fallback chain by buttons", () => {
  assert.deepEqual(reorder(["a", "b", "c"], 1, -1), ["b", "a", "c"]);
  assert.deepEqual(reorder(["a", "b", "c"], 1, 1), ["a", "c", "b"]);
  assert.deepEqual(reorder(["a", "b", "c"], 0, -1), ["a", "b", "c"]); // already first
  assert.deepEqual(reorder(["a", "b", "c"], 2, 1), ["a", "b", "c"]); // already last
  const list = ["x", "y"];
  reorder(list, 0, 1);
  assert.deepEqual(list, ["x", "y"]); // never in place
});

test("the dirty footer counts changed settings", () => {
  const saved = { llm: { provider: "", model: "" }, config: { purposes: {}, local_only: false } };
  assert.deepEqual(diffSettings(saved, structuredClone(saved)), []);
  assert.deepEqual(diffSettings(saved, { ...saved, llm: { provider: "openai", model: "" } }), ["llm.provider"]);
  assert.deepEqual(diffSettings(saved, { ...saved, config: { purposes: { code: { provider: "o", model: "" } }, local_only: true } }),
    ["config.purposes.code", "config.local_only"]);
});

test("temperature only where the model takes it, and budget lines", () => {
  assert.equal(capsAllowTemperature({ temperature: false }, "local"), false);
  assert.equal(capsAllowTemperature({ temperature: true }, "openai"), true);
  assert.equal(capsAllowTemperature({}, "local"), true);
  assert.equal(capsAllowTemperature(null, "anthropic"), false);
  assert.equal(budgetText({ spent_today: 4.2, limit: 20 }), "$4.20 of $20.00 today");
  assert.equal(budgetText({ spent_today: 5, limit: 5, stopped: true }), "Stopped for today - $5.00 of $5.00");
  assert.equal(budgetText({ spent_today: 1 }), "$1.00 today (no limit)");
});

test("the resolution chain reads as an ordered list", () => {
  assert.equal(chainLine({ title: "This agent", status: "not set" }, 1), "1. This agent: not set");
  assert.equal(chainLine({ title: "Code changes default", provider: "openai", provider_label: "OpenAI", model: "gpt-6.1-sol", status: "used" }, 3),
    "3. Code changes default: GPT-6.1 Sol (OpenAI) - used");
  assert.equal(chainLine({ title: "This agent", provider: "openai", provider_label: "OpenAI", model: "", status: "blocked", reason: "no API key" }, 1),
    "1. This agent: OpenAI (default model) - skipped: no API key");
  assert.equal(chainLine({ title: "Suite default", provider: "auto", provider_label: "Automatic", status: "not reached" }, 4), "4. Suite default: Automatic - not reached");
  assert.equal(chainLine({ level: "rules", title: "Rules", provider: "rules", status: "not reached" }, 5), "5. Rules (no AI model)");
  assert.equal(chainLine({ level: "rules", title: "Rules", provider: "rules", status: "used" }, 2), "2. Rules (no AI model) - used");
});

// ---------- agent settings (stage 4) ----------

const CONFIG = { purposes: {}, local_only: false, params: { effort: "", temperature: null, max_output_tokens: null, max_tool_rounds: 12 },
  instructions_mode: "append", extra_instructions: "", language: "", allowed_tools: null,
  budget: { daily_tokens: null, daily_cost_usd: null, monthly_cost_usd: null, hard_stop: true },
  rate: { calls_per_minute: null, runs_per_hour: null }, memory: { mode: "session", max_turns: 40, retention_days: 30 } };

test("the save body holds only what changed, nested groups whole", () => {
  const base = { llm: { provider: "", model: "" }, config: CONFIG, instructions: "" };
  const draft = JSON.parse(JSON.stringify(base));
  assert.deepEqual(settingsBody(base, draft, 3), { version: 3 });
  draft.config.budget.daily_cost_usd = 5;
  draft.config.allowed_tools = ["list_tools"];
  draft.instructions = "Mine.";
  assert.deepEqual(settingsBody(base, draft, 3), { version: 3, instructions: "Mine.",
    config: { budget: { ...CONFIG.budget, daily_cost_usd: 5 }, allowed_tools: ["list_tools"] } });
  draft.config.purposes = { code: { provider: "ollama", model: "" } };
  assert.deepEqual(settingsBody(base, draft, 3, ["code", "generate"]).config.purposes, { code: { provider: "ollama", model: "" }, generate: null });
  const custom = { ...base, name: "A", permissions: ["read"] };
  assert.deepEqual(settingsBody(custom, { ...custom, permissions: ["read", "flows"] }, 1), { version: 1, permissions: ["read", "flows"] });
});

test("changed keys name their tab and their words", () => {
  assert.equal(tabOf("llm.provider"), "model");
  assert.equal(tabOf("config.params.effort"), "model");
  assert.equal(tabOf("config.memory.mode"), "behaviour");
  assert.equal(tabOf("name"), "behaviour");
  assert.equal(tabOf("config.allowed_tools"), "tools");
  assert.equal(tabOf("permissions"), "tools");
  assert.equal(tabOf("config.budget.daily_cost_usd"), "limits");
  assert.equal(tabOf("config.rate.runs_per_hour"), "limits");
  assert.deepEqual(changeWords(["llm.model", "config.budget.hard_stop", "config.rate.calls_per_minute", "config.extra_instructions", "instructions", "task"]),
    ["model", "budgets", "rate limits", "instructions", "definition"]);
});

test("a validation message names the setting to focus", () => {
  assert.equal(errorPath("Daily cost: Input should be greater than or equal to 0.01"), "config.budget.daily_cost_usd");
  assert.equal(errorPath("Temperature: Claude claude-opus-5-5 sets its own sampling"), "config.params.temperature");
  assert.equal(errorPath("Allowed tools: unknown tool 'fly'"), "config.allowed_tools");
  assert.equal(errorPath("name: String should have at least 1 character"), "name");
  assert.equal(errorPath("Model: unknown provider 'x'"), null);
});

test("effort choices follow the model, else its kind of provider", () => {
  assert.deepEqual(effortChoices({ effort_levels: ["low", "high"] }, "anthropic"), ["low", "high"]);
  assert.deepEqual(effortChoices(null, "anthropic"), ["low", "medium", "high", "xhigh", "max"]);
  assert.deepEqual(effortChoices({ effort_levels: [] }, "openai"), ["none", "low", "medium", "high", "xhigh", "max"]);
  assert.deepEqual(effortChoices(null, "rules"), []);
});

test("limits, retries, memory and languages in words", () => {
  assert.equal(meterTone(1, 20), "ok");
  assert.equal(meterTone(16, 20), "warn");
  assert.equal(meterTone(20, 20), "bad");
  assert.equal(meterTone(5, null), "ok");
  assert.equal(retryText(12), "Retry in 12s");
  assert.equal(retryText(600), "Retry in 10 min");
  assert.equal(retryText(30000), "Retry after 00:00 UTC");
  assert.equal(retryText(null), "");
  assert.equal(memoryText({ mode: "off" }), "This agent does not remember earlier messages.");
  assert.equal(memoryText({ mode: "persisted", retention_days: 7 }), "Memory: this conversation is kept for you only (7 days).");
  assert.match(memoryText({ mode: "session" }), /until the hub restarts/);
  assert.equal(languageChoice(""), "");
  assert.equal(languageChoice("auto"), "auto");
  assert.equal(languageChoice("nl"), "nl");
  assert.equal(languageChoice("pt-BR"), "other");
  assert.equal(tokenCapWarning(null, { code: 64000 }), "");
  assert.equal(tokenCapWarning(70000, { code: 64000 }), "");
  assert.match(tokenCapWarning(8000, { code: 64000, generate: 32000 }), /up to 64,000 output tokens/);
});

test("escalation and notifications: tabs, words, errors and the needs-attention strip", () => {
  assert.equal(tabOf("config.escalation.rules"), "escalation");
  assert.equal(tabOf("config.notify.targets"), "escalation");
  assert.deepEqual(changeWords(["config.escalation.tool", "config.notify.events", "config.budget.hard_stop"]), ["escalation", "notifications", "budgets"]);
  assert.equal(errorPath("Escalation rules: String should have at most 300 characters"), "config.escalation.rules");
  assert.equal(errorPath("Notification targets: no account with the id 'u_1'"), "config.notify.targets");
  assert.equal(errorPath("Failed runs before pausing: too many"), "config.escalation.failed_runs");
  const base = { config: { escalation: { tool: true, rules: [] }, notify: { events: ["run_failed"], targets: ["role:admin"], toolbus: false } } };
  const draft = { config: { escalation: { tool: true, rules: ["A rule"] }, notify: { events: ["run_failed"], targets: ["role:admin"], toolbus: true } } };
  assert.deepEqual(settingsBody(base, draft, 3), { version: 3, config: { escalation: draft.config.escalation, notify: draft.config.notify } });
  assert.deepEqual(cleanRules(["  a   rule ", "", "a rule", "Other"]), ["a rule", "Other"]);
  assert.equal(severityTone("critical"), "bad");
  assert.equal(severityTone("info"), "info");
  assert.equal(severityTone("warning"), "warn");
  assert.equal(attentionText({ kind: "escalation", title: "Triage: Port 22?", severity: "critical" }), "Triage: Port 22? - critical, waiting in Approvals");
  assert.equal(attentionText({ kind: "budget", agent_name: "Triage", stopped: true }), "Triage: a budget is reached - stopped for today");
  assert.equal(attentionText({ kind: "paused", agent_name: "Watch", failures: 3 }), "Watch: schedule paused after 3 failed runs in a row");
  assert.equal(attentionText({ kind: "held", agent_name: "Watch", reason: "team too big" }), "Watch may not act: team too big");
  assert.equal(attentionText({ kind: "blocked", agents: [{ id: "a", name: "A" }, { id: "b", name: "B" }], reason: "OpenAI: no API key" }),
    "2 agents cannot use the chosen model - OpenAI: no API key");
  assert.equal(attentionText({ kind: "blocked", agents: [{ id: "a", name: "A" }], reason: "x" }), "A cannot use the chosen model - x");
});
