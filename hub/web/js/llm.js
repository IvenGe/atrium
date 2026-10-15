// Pure helpers for the AI model screens (no DOM): what kind of provider a record is, its status line, the capability
// chips of a model, and where a model server runs (the same rule as hub/llm/registry.py location_of).

export const KIND_LABELS = { anthropic: "Anthropic", openai: "OpenAI", azure: "Azure OpenAI", local: "Local", cloud: "OpenAI-compatible cloud", rules: "Rules" };

/** anthropic | openai | azure | local | cloud (a model server with an OpenAI-compatible API run by a third party). */
export function providerKind(p) {
  if (!p) return "rules";
  if (p.kind === "anthropic") return "anthropic";
  if (p.kind === "openai") return p.variant === "azure" ? "azure" : "openai";
  return p.location === "third_party" ? "cloud" : "local";
}

/** [text, tone] of a provider card's status badge, from its record and its row in /llm/providers `llm.providers`. */
export function providerStatus(p, row = {}) {
  const reason = row.reason || "";
  if (reason === "HUB_LLM=off") return ["off (HUB_LLM=off)", "warn"];
  if (reason.startsWith("failing")) return ["failing", "bad"];
  if (reason === "switched off") return ["switched off", ""];
  if (reason.startsWith("cloud providers are switched off")) return ["blocked: cloud providers are switched off", "warn"];
  if (row.available === false) return ["not connected", "warn"];
  if (p.kind === "openai_compatible") {
    if (!p.last_test) return ["not tested", "warn"];
    return p.last_test.ok ? ["tested ok", "ok"] : ["test failed", "bad"];
  }
  if (p.last_test && !p.last_test.ok) return ["test failed", "bad"];
  if (row.key_source === "env" || row.key_source === "profile") return ["key from environment", "ok"];
  return ["connected", "ok"];
}

/** The line about a provider's key - never the key itself. */
export function keyLine(p) {
  const env = { anthropic: "ANTHROPIC_API_KEY", openai: "OPENAI_API_KEY" }[p.id];
  if (p.key_source === "env") return `Using ${env || "the API key"} from the environment${p.api_key_set ? " (it overrides the stored key)" : ""}`;
  if (p.key_source === "profile") return "Using the ant auth login profile on the hub machine";
  if (p.api_key_set) return "API key stored (encrypted)";
  return p.kind === "openai_compatible" ? "No API key (most local servers need none)" : "No API key";
}

function compact(n) {
  return n >= 1_000_000 ? `${Math.round(n / 100_000) / 10}M` : n >= 1000 ? `${Math.round(n / 1000)}k` : String(n);
}

/** Short capability chips of one model: [text, tone] - "tools", "no tools", "JSON", "effort: low-max", "128k out"... */
export function capsChips(caps) {
  if (!caps) return [];
  const out = [];
  if (caps.tools === true) out.push(["tools", "ok"]);
  if (caps.tools === false) out.push(["no tools", "warn"]);
  if (caps.json_schema === true) out.push(["JSON", "ok"]);
  if (caps.json_schema === false) out.push(caps.json_object ? ["JSON mode only", ""] : ["no JSON schema", "warn"]);
  if (Array.isArray(caps.effort_levels)) {
    const levels = caps.effort_levels;
    out.push(levels.length ? [`effort: ${levels.length > 2 ? `${levels[0]}-${levels[levels.length - 1]}` : levels.join(", ")}`, ""] : ["no effort setting", ""]);
  }
  if (caps.temperature === false) out.push(["fixed sampling", ""]);
  if (caps.max_output_tokens) out.push([`${compact(caps.max_output_tokens)} out`, ""]);
  if (caps.lifecycle === "deprecated") out.push([`deprecated${caps.retires_at ? ` - retires ${String(caps.retires_at).slice(0, 10)}` : ""}`, "warn"]);
  return out;
}

/** Whether a model's tools and JSON support is still unknown (worth a "Check tools and JSON"). */
export const capsUnknown = (caps) => !caps || caps.tools == null || caps.json_schema == null;

function ipv4(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return m && m.slice(1).every((x) => Number(x) <= 255) ? m.slice(1).map(Number) : null;
}

/** "self_hosted" for loopback, private and link-local addresses, *.local and single-label host names; otherwise
 * "third_party" (null when the URL cannot be read). */
export function hostLocation(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase(); } catch { return null; }
  if (!host) return null;
  const v4 = ipv4(host);
  if (v4) {
    const [a, b] = v4;
    const local = a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
    return local ? "self_hosted" : "third_party";
  }
  if (host.startsWith("[")) {
    const v6 = host.slice(1, -1);
    return v6 === "::1" || /^f[cd][0-9a-f]{2}:/.test(v6) || /^fe[89ab][0-9a-f]:/.test(v6) ? "self_hosted" : "third_party";
  }
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".localhost") || !host.includes(".")) return "self_hosted";
  return "third_party";
}

/** Whether a self-hosted server is reached over plain http on a non-loopback address (traffic is unencrypted). */
export function plainHttp(url) {
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    return u.protocol === "http:" && !(host === "localhost" || host === "[::1]" || host.startsWith("127.")) ? host : null;
  } catch {
    return null;
  }
}

/** Model names typed one per line (or comma separated): trimmed, without duplicates. */
export function parseModels(text) {
  return [...new Set(String(text || "").split(/[\n,]/).map((s) => s.trim()).filter(Boolean))];
}

// ---------- which model an agent runs on, and where that choice comes from (shared by Settings, Agents and Home) ----------

const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

/** A readable model name: "claude-opus-5-5" -> "Claude Opus 5.5", "gpt-6.1-sol" -> "GPT-6.1 Sol"; other ids as they
 * are. `provider` (an id or a {id, kind, label} choice) names the model when there is none ("Ollama (default model)").
 * Rules have no model. */
export function modelLabel(provider, model) {
  const id = typeof provider === "string" ? provider : provider?.id;
  const label = typeof provider === "string" ? provider : provider?.label || provider?.id;
  if (id === "rules" || (!id && !model)) return "Rules";
  if (!model) return `${label} (default model)`;
  const claude = /^claude-([a-z]+)-(\d+)(?:-(\d{1,2}))?(?:-\d{8})?$/.exec(model);
  if (claude) return `Claude ${cap(claude[1])} ${claude[2]}${claude[3] ? `.${claude[3]}` : ""}`;
  const gpt = /^gpt-(\d+(?:\.\d+)?[a-z]?)(?:-([a-z][a-z0-9-]*))?$/.exec(model);
  if (gpt) return `GPT-${gpt[1]}${gpt[2] ? ` ${gpt[2].split("-").map(cap).join(" ")}` : ""}`;
  return model;
}

const SOURCE_LABELS = {
  agent_purpose: "This agent's choice for the task", agent: "This agent's choice", team: "Team default",
  purpose: "Task default", suite: "Suite default", fallback: "Fallback", rules: "No AI model available",
  deterministic: "Deterministic", explicit: "Chosen for this call",
};

/** Where an agent's model comes from ("Compliance team default", "Suite default (automatic)"...), from the effective
 * entry of its record's `llm` block (or an R4-DASH widget's `effective`). */
export function sourceLabel(effective) {
  if (!effective) return "";
  if (effective.provider === "rules" && effective.source === "rules") return "No AI model available";
  return effective.source_label || SOURCE_LABELS[effective.source] || effective.source || "";
}

/** One line for a badge: "GPT-6 Luna · Compliance team default"; a blocked level is named in `blockedText`. */
export function effectiveText(effective, providerLabel) {
  if (!effective) return "";
  const model = effective.provider === "rules" ? "Rules" : modelLabel({ id: effective.provider, label: providerLabel || effective.provider_label }, effective.model);
  const source = sourceLabel(effective);
  return source && source !== model ? `${model} · ${source}` : model;
}

/** The levels skipped on the way, as text ("OpenAI: no API key; automatic choice: ..."). */
export function blockedText(effective) {
  return (effective?.blocked || []).map((b) => `${b.provider === "auto" ? "automatic choice" : b.provider}: ${b.reason}`).join("; ");
}

/** A copy of `list` with item `i` moved one place up (dir -1) or down (dir 1); unchanged at the ends. */
export function reorder(list, i, dir) {
  const out = [...list];
  const j = i + dir;
  if (i < 0 || i >= out.length || j < 0 || j >= out.length) return out;
  [out[i], out[j]] = [out[j], out[i]];
  return out;
}

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);

/** The dotted keys that differ between saved settings and a draft ("llm", "config.local_only"...): what the dirty
 * footer counts. Objects are compared key by key, everything else as a whole. */
export function diffSettings(saved, draft, prefix = "") {
  const out = [];
  const keys = new Set([...Object.keys(saved || {}), ...Object.keys(draft || {})]);
  for (const key of keys) {
    const a = saved?.[key];
    const b = draft?.[key];
    const path = prefix ? `${prefix}.${key}` : key;
    if (isObject(a) && isObject(b)) out.push(...diffSettings(a, b, path));
    else if (JSON.stringify(a ?? null) !== JSON.stringify(b ?? null)) out.push(path);
  }
  return out;
}

/** Whether a temperature setting applies: never where the model refuses it, always where it is known to work, and
 * for local models while unknown (they accept it). */
export function capsAllowTemperature(caps, kind) {
  if (caps?.temperature === false) return false;
  return caps?.temperature === true || kind === "local";
}

const usd = (n) => `$${Number(n || 0).toFixed(2)}`;

/** A budget line: "$4.20 of $20.00 today", "Stopped for today - $5.00 of $5.00", or the spend without a limit. */
export function budgetText(state) {
  if (!state) return "";
  const spent = usd(state.spent_today);
  if (state.limit == null) return `${spent} today (no limit)`;
  return `${state.stopped ? "Stopped for today - " : ""}${spent} of ${usd(state.limit)}${state.stopped ? "" : " today"}`;
}

/** The ordered resolution chain of the agent settings page as one line per level: "3. Code changes default: GPT-6.1
 * Sol (OpenAI) - used". */
export function chainLine(row, n) {
  if (row.level === "rules") return `${n}. Rules (no AI model)${row.status === "used" ? " - used" : ""}`;
  let what = "not set";
  if (row.provider === "rules") what = "Rules";
  else if (row.provider === "auto" && row.status !== "used") what = "Automatic";
  else if (row.provider) what = row.model ? `${modelLabel({ id: row.provider, label: row.provider_label }, row.model)} (${row.provider_label})` : `${row.provider_label} (default model)`;
  const status = row.status === "blocked" ? `skipped: ${row.reason || "not available"}` : row.status === "not set" ? "" : row.status;
  return `${n}. ${row.title}: ${what}${status ? ` - ${status}` : ""}`;
}

// ---------- agent settings (stage 4): tabs, effort choices, the save body, limits and memory wording ----------

/** The reply languages offered first; any other BCP 47 code can be typed ("other"). */
export const LANGUAGES = [["en", "English"], ["nl", "Nederlands"], ["fr", "Français"], ["de", "Deutsch"], ["es", "Español"]];

/** The select value for a stored language code: "" (suite default), "auto", a listed code, or "other". */
export function languageChoice(code) {
  if (!code || code === "auto") return code || "";
  return LANGUAGES.some(([c]) => c === code) ? code : "other";
}

const EFFORTS = { anthropic: ["low", "medium", "high", "xhigh", "max"], openai: ["none", "low", "medium", "high", "xhigh", "max"],
  local: ["low", "medium", "high"] };

/** The effort levels to offer for a model: what it is known to support, else what its kind of provider accepts. */
export function effortChoices(caps, kind) {
  if (Array.isArray(caps?.effort_levels) && caps.effort_levels.length) return caps.effort_levels;
  return EFFORTS[kind] || [];
}

const KEY_WORDS = [
  ["llm", "model"], ["config.purposes", "per-task models"], ["config.local_only", "local only"], ["config.params", "model parameters"],
  ["config.instructions_mode", "instructions"], ["config.extra_instructions", "instructions"], ["instructions", "instructions"],
  ["config.language", "language"], ["config.memory", "memory"], ["config.allowed_tools", "tools"], ["permissions", "permissions"],
  ["config.budget", "budgets"], ["config.rate", "rate limits"], ["config.escalation", "escalation"], ["config.notify", "notifications"],
];
const TAB_OF = { model: ["llm", "config.purposes", "config.local_only", "config.params"],
  behaviour: ["instructions", "config.instructions_mode", "config.extra_instructions", "config.language", "config.memory", "name", "title",
    "description", "task", "schedule_minutes", "enabled"],
  tools: ["config.allowed_tools", "permissions"], limits: ["config.budget", "config.rate"], escalation: ["config.escalation", "config.notify"] };

/** The settings page tab a changed key (diffSettings) belongs to. */
export function tabOf(key) {
  return Object.keys(TAB_OF).find((tab) => TAB_OF[tab].some((k) => key === k || key.startsWith(`${k}.`))) || "behaviour";
}

/** The words of the unsaved-changes footer for changed keys: "model, budgets, definition". */
export function changeWords(keys) {
  return [...new Set(keys.map((k) => KEY_WORDS.find(([p]) => k === p || k.startsWith(`${p}.`))?.[1] || "definition"))];
}

/** The PATCH /agents/{id}/settings body for a draft: only what changed - a nested group (params, budget, rate, memory)
 * whole, per-task models for every task (null = same as the agent), plus the version the draft started from. */
export function settingsBody(base, draft, version, tasks = []) {
  const keys = diffSettings(base, draft);
  const body = { version };
  const config = {};
  for (const key of keys) {
    const [top, sub] = key.split(".");
    if (top === "config") {
      if (sub === "purposes") config.purposes = Object.fromEntries(tasks.map((t) => [t, draft.config.purposes?.[t] || null]));
      else config[sub] = draft.config[sub];
    } else body[top] = draft[top];
  }
  if (Object.keys(config).length) body.config = config;
  return body;
}

/** "ok" below 80 % of a limit, "warn" from 80 %, "bad" from 100 % (a meter's tone; the text says the numbers). */
export function meterTone(spent, limit) {
  if (!limit) return "ok";
  const share = Number(spent || 0) / Number(limit);
  return share >= 1 ? "bad" : share >= 0.8 ? "warn" : "ok";
}

/** When a refused chat may be tried again: "Retry in 12s", "Retry in 3 min", "Retry after 00:00 UTC". */
export function retryText(seconds) {
  const s = Number(seconds || 0);
  if (!s) return "";
  if (s < 90) return `Retry in ${Math.ceil(s)}s`;
  if (s < 3600) return `Retry in ${Math.ceil(s / 60)} min`;
  return "Retry after 00:00 UTC";
}

/** The chat panel's memory line for an agent's memory setting ({mode, retention_days} or a config.memory). */
export function memoryText(memory) {
  if (!memory) return "";
  if (memory.mode === "off") return "This agent does not remember earlier messages.";
  if (memory.mode === "persisted") return `Memory: this conversation is kept for you only (${memory.retention_days || 30} days).`;
  return "Memory: this conversation is kept for you only, until the hub restarts.";
}

/** The warning under "Max output tokens" when the cap is below what one of the agent's tasks asks for. */
export function tokenCapWarning(cap, needs) {
  const most = Math.max(0, ...Object.values(needs || {}));
  if (!cap || cap >= most) return "";
  return `Some of this agent's tasks ask for up to ${most.toLocaleString("en-US")} output tokens: a lower cap cuts those answers off.`;
}

const ERROR_PATHS = {
  Effort: "config.params.effort", Temperature: "config.params.temperature", "Max output tokens": "config.params.max_output_tokens",
  "Max tool rounds": "config.params.max_tool_rounds", "Additional instructions": "config.extra_instructions", Instructions: "instructions",
  Language: "config.language", "Allowed tools": "config.allowed_tools", "Daily tokens": "config.budget.daily_tokens",
  "Daily cost": "config.budget.daily_cost_usd", "Monthly cost": "config.budget.monthly_cost_usd", "Hard stop": "config.budget.hard_stop",
  "Calls per minute": "config.rate.calls_per_minute", "Runs per hour": "config.rate.runs_per_hour", Memory: "config.memory.mode",
  "Max turns": "config.memory.max_turns", "Retention days": "config.memory.retention_days", name: "name", title: "title",
  description: "description", task: "task", schedule_minutes: "schedule_minutes", permissions: "permissions",
  Escalation: "config.escalation.tool", "Escalate tool": "config.escalation.tool", "Escalation rules": "config.escalation.rules",
  "Escalations per day": "config.escalation.max_per_day", "Failed runs before pausing": "config.escalation.failed_runs",
  "Pause the schedule": "config.escalation.pause_schedule", Notifications: "config.notify.events",
  "Notification events": "config.notify.events", "Notification targets": "config.notify.targets", "Tool bus": "config.notify.toolbus",
};

/** The setting a validation message of PATCH /agents/{id}/settings names ("Daily cost: ..." -> its dotted path), or null. */
export function errorPath(message) {
  const head = String(message || "").split(":")[0].trim();
  return ERROR_PATHS[head] || null;
}

// ---------- escalation and notifications (stage 5) ----------

/** The text of a "Needs attention" item (GET /agents/attention): what happened, without colour. */
export function attentionText(item) {
  switch (item?.kind) {
    case "escalation": return `${item.title} - ${item.severity || "warning"}, waiting in Approvals`;
    case "budget": return `${item.agent_name}: a budget is reached${item.stopped ? " - stopped for today" : " (it keeps running: the hard stop is off)"}`;
    case "paused": return `${item.agent_name}: schedule paused after ${item.failures} failed run${item.failures === 1 ? "" : "s"} in a row`;
    case "held": return `${item.agent_name} may not act: ${item.reason}`;
    case "blocked": {
      const n = (item.agents || []).length;
      return `${n === 1 ? item.agents[0].name : `${n} agents`} cannot use the chosen model - ${item.reason}`;
    }
    default: return "";
  }
}

/** A badge tone for an escalation severity (the badge text names it too). */
export function severityTone(severity) {
  return severity === "critical" ? "bad" : severity === "info" ? "info" : "warn";
}

/** The rules list of the Escalation tab after an edit: trimmed, without empty lines and duplicates (what the server keeps). */
export function cleanRules(rules) {
  return [...new Set((rules || []).map((r) => String(r).replace(/\s+/g, " ").trim()).filter(Boolean))];
}
