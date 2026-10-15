// The Subsidiaries app's model (round4-spec 11.1): status and flag texts, budget meters, what changes between two charters
// (widening or narrowing - the same rules as hub/subsidiary/charter.py classify), the facts of the three approval cards,
// the setup steps, the staff's live states and the audit trail's filters. Pure: no DOM, unit-tested under Node
// (tests/js/subsidiary-model.test.mjs). Text a subsidiary or a tool wrote (reasons, reports, mandates a model drafted,
// parameter values) is data: it only goes through html`` (escaped) and is shown as plain text.
import { html } from "./ui.js";

export const UNTRUSTED = "Written by the subsidiary team (untrusted)";
export const MODE_LABEL = { bridge: "Bridge", sidecar_only: "API only" };
export const WORKING = ["deploying", "probation", "active"]; // what a pause applies to
export const BLOCKING_FLAGS = ["bridge_mismatch", "circuit_open", "owner_disabled"];
// the hub tools a staff member may be given (hub/agents/toolkit.py SIDECAR_HUB_TOOLS)
export const HUB_TOOLS = [
  ["get_tool", "Look up its own tool in Atrium"], ["tool_health", "Check its tool's health"], ["data_flows", "See its tool's data flows"],
  ["propose_patches", "Ask the Patch Agent for patches (always approved by a person)"],
  ["request_code_patch", "Ask for a code patch (always approved by a person)"],
];
export const POLICY_LABEL = { allow: "allowed", approval: "needs approval", auto: "runs without approval", forbidden: "forbidden" };
export const RISK_TONE = { read: "", propose: "info", write: "warn", admin: "bad" };
const RISK_RANK = { read: 0, propose: 1, write: 2, admin: 3 };

const STATUS = {
  proposed: ["proposed", "warn", "Its bridge patch or first charter is being prepared."],
  deploying: ["being deployed", "info", "Deploy the tool with its bridge, then enroll the sidecar."],
  probation: ["on probation", "info", "The sidecar is enrolled; it proves conformance and waits for an approved charter."],
  active: ["active", "ok", "The team works inside the tool within its charter."],
  paused: ["paused", "warn", "Atrium paused the team: no model answers, tickets, grants or runs."],
  stopped: ["stopped", "bad", "Stopped for good: its token is revoked and its signing key replaced."],
  archived: ["archived", "", "Kept for the audit trail."],
};
const FLAGS = {
  offline: ["offline", "warn", "the sidecar is offline (no heartbeat for 90 seconds)"],
  bridge_mismatch: ["bridge changed", "bad", "the bridge in the tool changed: its tickets drop to probation"],
  over_budget: ["over budget", "warn", "a budget is exhausted for today"],
  owner_disabled: ["token dead", "bad", "the sidecar's token no longer works: another administrator issues a new enrollment"],
  clock_skew: ["clock skew", "warn", "the sidecar's clock is off by more than a minute"],
  circuit_open: ["circuit open", "bad", "the circuit breaker opened and paused the team: an administrator resumes it"],
};

/** {text, tone, help} of a subsidiary status. */
export function statusInfo(status) {
  const [text, tone, help] = STATUS[status] || [String(status || "unknown"), "", ""];
  return { text, tone, help };
}

/** {text, tone, help} of a flag. */
export function flagInfo(flag) {
  const [text, tone, help] = FLAGS[flag] || [String(flag), "warn", ""];
  return { text, tone, help };
}

// ---------- numbers and meters ----------

/** 1234 -> "1.2k", 300000 -> "300k", 2500000 -> "2.5M". */
export function compact(n) {
  const v = Number(n) || 0;
  if (Math.abs(v) >= 1e6) return `${+(v / 1e6).toFixed(1)}M`;
  if (Math.abs(v) >= 1e4) return `${Math.round(v / 1e3)}k`;
  if (Math.abs(v) >= 1e3) return `${+(v / 1e3).toFixed(1)}k`;
  return String(Math.round(v));
}

/** A budget meter: how much of `limit` is used, its tone (warn from 80 %, bad when used up) and its text. */
export function meter(used, limit, label = "") {
  const u = Math.max(0, Number(used) || 0);
  const l = Number(limit) || 0;
  const pct = l > 0 ? Math.min(100, Math.round((u / l) * 100)) : 0;
  const tone = l > 0 && u >= l ? "bad" : pct >= 80 ? "warn" : "ok";
  return { label, used: u, limit: l || null, pct, tone, text: l > 0 ? `${compact(u)} of ${compact(l)}` : compact(u) };
}

/** Today's meters of a subsidiary's usage (governance.usage_today): tokens and approval requests against their budgets. */
export function budgetMeters(usage) {
  const u = usage || {};
  return [meter(u.tokens, u.tokens_per_day, "Model tokens today"), meter(u.approval_requests, u.approval_requests_per_day, "Approval requests today")];
}

// ---------- charters: what widens, what narrows ----------

export const POLICY_RANK = { forbidden: 0, approval: 1, allow: 2, auto: 2 };
const policyRank = (a) => POLICY_RANK[a.policy] + (a.policy === "auto" ? 1 : 0); // forbidden < approval < allow/auto

/** JSON with sorted keys: two values compare equal when their content is (Python's model_dump comparison). */
export function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(",")}}`;
  return JSON.stringify(value ?? null);
}

/** An action as its schema matters for a charter (title, description and policy aside; defaults filled in). */
function shape(a) {
  return stable({ id: a.id, risk: a.risk, category: a.category ?? "other", reversible: !!a.reversible, external_effect: !!a.external_effect,
    on_behalf_of: !!a.on_behalf_of, params: a.params ?? {} });
}

const sortedDiff = (a, b) => [...new Set(a || [])].filter((x) => !(b || []).includes(x)).sort();
const BUDGET_KEYS = ["tokens_per_day", "model_calls_per_hour", "approval_requests_per_day", "max_pending_approvals", "actions_per_minute",
  "max_concurrent_runs", "panel_questions_per_user_hour", "panel_questions_per_day"];

/** Why `next` widens `prev` (empty: it only narrows or changes nothing) - hub/subsidiary/charter.py classify, word for word. */
export function classify(prev, next) {
  if (!prev) return ["the first charter of this subsidiary"];
  const reasons = [];
  const before = Object.fromEntries((prev.actions || []).map((a) => [a.id, a]));
  for (const action of next.actions || []) {
    const old = before[action.id];
    if (!old) {
      if (action.policy !== "forbidden") reasons.push(`action ${action.id} added`);
    } else if (policyRank(action) > policyRank(old)) {
      reasons.push(`action ${action.id} loosened from ${old.policy} to ${action.policy}`);
    } else if (shape(action) !== shape(old) && action.policy !== "forbidden") {
      reasons.push(`action ${action.id} changed`);
    }
  }
  for (const [id, scope] of Object.entries(next.staff || {})) {
    const old = (prev.staff || {})[id];
    if (!old) { reasons.push(`staff member ${id} added`); continue; }
    const actions = sortedDiff(scope.actions, old.actions);
    if (actions.length) reasons.push(`${id} may use ${actions.join(", ")}`);
    const tools = sortedDiff(scope.hub_tools, old.hub_tools);
    if (tools.length) reasons.push(`${id} may use the hub tools ${tools.join(", ")}`);
  }
  for (const key of Object.keys(next.budgets || {})) {
    if (next.budgets[key] > (prev.budgets || {})[key]) reasons.push(`budget ${key} raised to ${next.budgets[key]}`);
  }
  const providers = sortedDiff(next.model_routing?.allowed, prev.model_routing?.allowed);
  if (providers.length) reasons.push(`model provider ${providers.join(", ")} added`);
  if (next.panel?.enabled && !prev.panel?.enabled) reasons.push("the panel enabled");
  else if (next.panel?.enabled && next.panel.desk !== prev.panel?.desk) reasons.push("another front desk");
  if (next.events?.relay && !prev.events?.relay) reasons.push("the event relay enabled");
  if (next.data?.transcripts && !prev.data?.transcripts) reasons.push("transcripts turned on");
  if ((next.data?.report_retention_days ?? 0) > (prev.data?.report_retention_days ?? 0)) reasons.push("reports kept longer");
  if (String(next.mandate || "").trim() !== String(prev.mandate || "").trim()) reasons.push("the mandate changed");
  return reasons;
}

/** Every change from `prev` to `next`, each labelled: widens (needs an administrator's approval) or not (applies at once).
 *  Any widening item means classify() finds a reason; `names` gives staff and provider labels. */
export function charterChanges(prev, next, names = {}) {
  if (!prev) return [{ area: "charter", text: "The first charter of this subsidiary", widens: true }];
  const label = (id) => names[id] || id;
  const out = [];
  const add = (area, text, widens) => out.push({ area, text, widens });
  if (String(next.mandate || "").trim() !== String(prev.mandate || "").trim()) add("mandate", "The mandate changes", true);
  const before = Object.fromEntries((prev.actions || []).map((a) => [a.id, a]));
  const after = Object.fromEntries((next.actions || []).map((a) => [a.id, a]));
  for (const a of next.actions || []) {
    const old = before[a.id];
    if (!old) add("actions", `Add ${a.id} (${POLICY_LABEL[a.policy] || a.policy})`, a.policy !== "forbidden");
    else if (a.policy !== old.policy) {
      add("actions", `${a.id}: ${POLICY_LABEL[old.policy] || old.policy} -> ${POLICY_LABEL[a.policy] || a.policy}`, policyRank(a) > policyRank(old));
    } else if (shape(a) !== shape(old)) add("actions", `${a.id} changed in the tool's catalog`, a.policy !== "forbidden");
  }
  for (const a of prev.actions || []) if (!after[a.id]) add("actions", `Remove ${a.id}`, false);
  const staffBefore = prev.staff || {};
  const staffAfter = next.staff || {};
  for (const [id, scope] of Object.entries(staffAfter)) {
    const old = staffBefore[id];
    if (!old) { add("staff", `Add staff member ${label(id)}`, true); continue; }
    const more = sortedDiff(scope.actions, old.actions);
    const fewer = sortedDiff(old.actions, scope.actions);
    if (more.length) add("staff", `${label(id)} may use ${more.join(", ")}`, true);
    if (fewer.length) add("staff", `${label(id)} no longer uses ${fewer.join(", ")}`, false);
    const tools = sortedDiff(scope.hub_tools, old.hub_tools);
    const dropped = sortedDiff(old.hub_tools, scope.hub_tools);
    if (tools.length) add("staff", `${label(id)} may use the hub tools ${tools.join(", ")}`, true);
    if (dropped.length) add("staff", `${label(id)} no longer uses the hub tools ${dropped.join(", ")}`, false);
  }
  for (const id of Object.keys(staffBefore)) if (!staffAfter[id]) add("staff", `Remove ${label(id)} (disabled, not deleted)`, false);
  const keys = [...new Set([...BUDGET_KEYS, ...Object.keys(next.budgets || {})])];
  for (const key of keys) {
    const a = (prev.budgets || {})[key], b = (next.budgets || {})[key];
    if (b === undefined || a === b) continue;
    add("budgets", `${budgetLabel(key)}: ${a ?? "-"} -> ${b}`, b > a);
  }
  for (const p of sortedDiff(next.model_routing?.allowed, prev.model_routing?.allowed)) add("routing", `Allow the model provider ${label(p)}`, true);
  for (const p of sortedDiff(prev.model_routing?.allowed, next.model_routing?.allowed)) add("routing", `No longer allow ${label(p)}`, false);
  if ((next.model_routing?.default || null) !== (prev.model_routing?.default || null)) {
    add("routing", `Default model provider: ${label(next.model_routing?.default) || "none"}`, false);
  }
  if (next.panel?.enabled && !prev.panel?.enabled) add("panel", "Switch the Ask-the-team panel on", true);
  else if (!next.panel?.enabled && prev.panel?.enabled) add("panel", "Switch the Ask-the-team panel off", false);
  else if (next.panel?.enabled && next.panel.desk !== prev.panel?.desk) add("panel", `Another front desk: ${label(next.panel.desk)}`, true);
  if (!!next.events?.relay !== !!prev.events?.relay) add("events", next.events?.relay ? "Relay the tool's events" : "Stop relaying the tool's events", !!next.events?.relay);
  if (!!next.data?.transcripts !== !!prev.data?.transcripts) add("data", next.data?.transcripts ? "Keep transcripts (encrypted)" : "Keep no transcripts", !!next.data?.transcripts);
  const days = [prev.data?.report_retention_days, next.data?.report_retention_days];
  if (days[1] !== undefined && days[0] !== days[1]) add("data", `Keep reports ${days[1]} days (was ${days[0] ?? "-"})`, (days[1] ?? 0) > (days[0] ?? 0));
  return out;
}

/** The labelled changes as a list: "widens: needs approval" (highlighted) or "narrows: applies now" - text, not colour only. */
export function changesList(changes) {
  if (!changes.length) return html`<p class="faint sub-small">No changes.</p>`;
  return html`<ul class="sub-changes">${changes.map((c) => html`<li class="${c.widens ? "widens" : ""}"><span class="badge ${c.widens ? "warn" : "ok"}">${c.widens
    ? "widens: needs approval" : "narrows: applies now"}</span><span>${c.text}</span></li>`)}</ul>`;
}

const BUDGET_LABELS = {
  tokens_per_day: "Model tokens a day", model_calls_per_hour: "Model calls an hour", approval_requests_per_day: "Approval requests a day",
  max_pending_approvals: "Pending approvals at once", actions_per_minute: "Bridge calls a minute", max_concurrent_runs: "Runs at once",
  panel_questions_per_user_hour: "Panel questions per tool user an hour", panel_questions_per_day: "Panel questions a day",
};
export const budgetLabel = (key) => BUDGET_LABELS[key] || key.replace(/_/g, " ");
export const BUDGETS = BUDGET_KEYS.map((k) => [k, BUDGET_LABELS[k]]);

/** The policies an action may have in a charter (governance.charter_problems): reads and drafts are allowed or forbidden,
 *  writes need approval - or run without it when reversible, without external effect and the guardrail is off - and
 *  admin-risk actions always need approval. */
export function policyChoices(action, writesAuto = false) {
  if (action.risk === "read" || action.risk === "propose") return ["allow", "forbidden"];
  if (action.risk === "write" && action.reversible && !action.external_effect && writesAuto) return ["approval", "auto", "forbidden"];
  return ["approval", "forbidden"];
}

/** The policy a new action starts with (charter.DEFAULT_POLICY). */
export const defaultPolicy = (action) => (action.risk === "read" || action.risk === "propose" ? "allow" : "approval");

/** Whether Atrium raised an action's risk above what the bridge declared (the floor marker), or null. */
export function floorMarker(action, declared) {
  if (!declared || !(declared in RISK_RANK) || RISK_RANK[action.risk] <= RISK_RANK[declared]) return null;
  return `raised from ${declared} to ${action.risk} (Atrium's floor)`;
}

/** A charter edited in the Amend dialog as the PUT body (only what the route takes; actions by id and policy). */
export function charterBody(c, members = []) {
  return {
    mandate: String(c.mandate || ""),
    actions: (c.actions || []).map((a) => ({ id: a.id, policy: a.policy })),
    staff: Object.fromEntries(Object.entries(c.staff || {}).map(([id, s]) => [id, { actions: [...(s.actions || [])], hub_tools: [...(s.hub_tools || [])] }])),
    model_routing: { allowed: [...(c.model_routing?.allowed || [])], default: c.model_routing?.default || null },
    budgets: { ...(c.budgets || {}) },
    panel: { enabled: !!c.panel?.enabled, desk: c.panel?.enabled ? c.panel.desk || null : c.panel?.desk || null },
    events: { relay: !!c.events?.relay },
    data: { transcripts: !!c.data?.transcripts, report_retention_days: Number(c.data?.report_retention_days) || 180 },
    members,
  };
}

/** An agent id for a new staff member: agent:<tool>-<name>, unique among `taken`. */
export function staffId(toolId, name, taken = []) {
  const slug = String(name || "staff").toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 30) || "staff";
  const base = `agent:${String(toolId).toLowerCase().replace(/[^a-z0-9-]+/g, "-").slice(0, 24)}-${slug}`;
  let id = base, n = 2;
  while (taken.includes(id)) id = `${base}-${n++}`;
  return id;
}

/** "Tool data is sent to X (third-party)" or "stays on your own hardware" for each allowed provider. */
export function routingFacts(routing, providers = []) {
  const byId = Object.fromEntries(providers.map((p) => [p.id, p]));
  return (routing?.allowed || []).map((id) => {
    const p = byId[id];
    const third = !p || p.location !== "self_hosted";
    return { id, label: p?.label || id, third, default: routing.default === id,
      text: third ? `Tool data is sent to ${p?.label || id} (third-party)` : `${p?.label || id} runs on your own hardware: tool data stays local` };
  });
}

// ---------- the in-tool action approval card ----------

const personName = (who) => {
  const s = String(who || "");
  return /^(user|token):/.test(s) ? s.slice(s.indexOf(":") + 1) : s || "someone";
};

/** How a run started, in words (actions.TRIGGER_TEXT): scheduled, a task by alice, an Atrium chat, or a panel question. */
export function triggerText(trigger, person) {
  return { schedule: "scheduled run", manual: `run started by ${personName(person)}`, task: `task by ${personName(person)}`,
    chat: `Atrium chat by ${personName(person)}`, panel: "panel: user-steered" }[trigger] || String(trigger || "unknown");
}

/** What a run read before it asked (its taint sources), in words. */
export function provenance(taint) {
  return (taint || []).map((source) => {
    const s = String(source);
    const at = s.indexOf(":");
    const [kind, name] = at < 0 ? [s, ""] : [s.slice(0, at), s.slice(at + 1)];
    if (kind === "panel") return `panel question ${name} by a tool user (not verified by Atrium)`;
    if (kind === "bridge") return `${name} (read through the bridge)`;
    if (kind === "connector") return `${name} records (read through the connection)`;
    return s;
  });
}

/** The exact parameters as rows of [name, value text] - values are the tool's or the model's data (shown escaped). */
export function paramRows(params) {
  return Object.entries(params || {}).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]);
}

/** Everything an in-tool action's card shows, from its approval payload (actions.create_approval). */
export function actionFacts(p, now = Date.now() / 1000) {
  const payload = p || {};
  return {
    risk: payload.risk || "write", riskTone: RISK_TONE[payload.risk] ?? "warn",
    adminOnly: payload.risk === "admin" || !!payload.external_effect,
    reversible: !!payload.reversible, external: !!payload.external_effect,
    trigger: triggerText(payload.trigger, payload.proposed_by), steered: !!payload.user_steered || payload.trigger === "panel",
    provenance: provenance(payload.taint), flags: Number(payload.injection_flags) || 0,
    params: paramRows(payload.params), reason: String(payload.reason_untrusted || ""),
    expired: !!payload.expires_at && payload.expires_at <= now, expiresAt: payload.expires_at || null,
    mode: payload.mode || "bridge", action: payload.action_id || "", agent: payload.agent_id || "",
  };
}

/** The parameters as a key/value table: every name and value escaped (they come from the model and the tool). */
export function paramsTable(params) {
  const rows = paramRows(params);
  if (!rows.length) return html`<p class="faint" style="font-size:12.5px">No parameters.</p>`;
  return html`<table class="table compact sub-params"><thead><tr><th>Parameter</th><th>Exact value</th></tr></thead><tbody>
    ${rows.map(([k, v]) => html`<tr><td class="mono">${k}</td><td class="mono sub-value">${v}</td></tr>`)}</tbody></table>`;
}

/** Text the subsidiary wrote: plain, no links, under the untrusted label. */
export function untrustedBox(text, label = UNTRUSTED) {
  if (!String(text || "").trim()) return "";
  return html`<div class="sub-untrusted"><div class="sub-untrusted-label">${label}</div><div class="sub-untrusted-text">${text}</div></div>`;
}

// ---------- who decides, and the charter approval card ----------

export const SUBSIDIARY_KINDS = ["subsidiary_charter", "subsidiary_action"];

/** Whether an approval is a subsidiary's: its charter, an in-tool action or its bridge patch. */
export const isSubsidiaryApproval = (a) => SUBSIDIARY_KINDS.includes(a?.kind) || (a?.kind === "patch" && a.payload?.strategy === "atrium_bridge");

/** Who decides a subsidiary's approval (api.subsidiary_decider): "admin" for charters, bridge patches and in-tool actions
 *  of admin risk or with an external effect, "operator" for other in-tool actions, null for any other approval. Always
 *  a person, never the one who proposed it (the server enforces both). */
export function decider(a) {
  if (a?.kind === "subsidiary_charter" || (a?.kind === "patch" && a.payload?.strategy === "atrium_bridge")) return "admin";
  if (a?.kind === "subsidiary_action") return a.payload?.risk === "admin" || a.payload?.external_effect ? "admin" : "operator";
  return null;
}

/** Everything a charter approval's card shows: the widening reasons Atrium computed (payload), the diff against the charter
 *  in force (when the subsidiary still holds this version as its pending charter), the routing warning, the conformance
 *  state and the staff the approval creates with their scopes in the new charter. */
export function charterFacts(payload, sub, providers = []) {
  const p = payload || {};
  const pending = sub?.pending_charter && sub.pending_charter.version === p.charter_version ? sub.pending_charter : null;
  const names = { ...Object.fromEntries((p.members || []).map((m) => [m.id, m.name])), ...Object.fromEntries((sub?.staff || []).map((m) => [m.id, m.name])),
    ...Object.fromEntries(providers.map((x) => [x.id, x.label])) };
  return {
    version: p.charter_version, first: !sub?.charter, widening: [...(p.widening || [])], routingWarning: p.routing_warning || null,
    changes: pending ? charterChanges(sub.charter || null, pending, names) : null, stale: !!sub && !pending,
    conformance: conformanceFacts(sub?.conformance), routing: pending ? routingFacts(pending.model_routing, providers) : [],
    members: (p.members || []).map((m) => ({ ...m, scope: pending?.staff?.[m.id] || { actions: [], hub_tools: [] } })),
    mandate: pending ? String(pending.mandate || "") : null, mode: sub?.mode || null,
  };
}

// ---------- the bridge patch approval card ----------

/** {status, text, tone, warning} of a bridge patch's tool tests (passed, failed or not run with the reason). */
export function testsFacts(tests) {
  const t = tests || {};
  if (t.ok === true) return { status: "passed", text: `The tool's tests passed${t.runtime ? ` (${t.runtime})` : ""}`, tone: "ok", warning: null };
  if (t.ok === false) return { status: "failed", text: `The tool's tests failed${t.reason ? `: ${t.reason}` : ""}`, tone: "bad", warning: null };
  if (t.status === "not_run") {
    return { status: "not_run", text: `The tool's tests did not run: ${t.reason || "no reason given"}`, tone: "warn",
      warning: "Tests did not run: only an administrator approves this bridge, and compliance control HB-AC-8 shows it (partial)." };
  }
  return { status: "unknown", text: "No test result", tone: "", warning: null };
}

/** The bridge's core: vendored (byte-identical, tested by Atrium) or written by an AI model (conformance must prove it). */
export function coreFacts(plan) {
  const p = plan || {};
  return p.vendored_core
    ? { vendored: true, text: `Vendored core ${p.core || ""}: byte-identical to Atrium's, tested on the contract's vectors`, tone: "ok" }
    : { vendored: false, text: `Core written by an AI model (${p.core || "unknown"}): the conformance vectors must prove it before the team can work`, tone: "warn" };
}

/** The action table of a bridge plan: each action with Atrium's floor marker when it raised the risk. */
export function bridgeActions(plan) {
  const raised = Object.fromEntries((plan?.raised || []).map((r) => [r.id, r]));
  return (plan?.actions || []).map((a) => ({ ...a, floor: raised[a.id] ? `raised from ${raised[a.id].declared} (${raised[a.id].reason || "Atrium's floor"})` : null }));
}

// ---------- conformance and setup ----------

export const VECTOR_TITLES = {
  V1: "GET /health answers without authentication", V2: "A call without a ticket is refused", V3: "A ticket signed with another key is refused",
  V4: "A ticket for another tool or subsidiary is refused", V5: "An expired ticket is refused", V6: "A request not signed with the ticket's key is refused",
  V7: "A body changed after signing is refused", V8: "The same request twice: the second is a replay", V9: "A request dated 5 minutes ago is refused",
  V10: "A probation ticket cannot call a tool action", V11: "An action the ticket does not list is refused", V12: "A write without a grant is refused",
  V13: "A grant for another body is refused", V14: "A grant for another tool or action is refused", V15: "A valid grant is used once",
  V16: "An unknown parameter is refused before anything runs", V17: "A 70 KiB body is refused", V18: "A JOSE-style ticket (alg none) is refused",
  V19: "Ping and describe answer with the approved manifest", V20: "panel.js is served byte-identical to the vendored widget",
  K1: "The dedicated credential passes the connector's test", K2: "The connection is not a network device",
  K3: "The dedicated credential differs from the hub's own",
};

/** Conformance rows with their titles, and whether Atrium observed them or the sidecar claimed them. */
export function conformanceFacts(c) {
  if (!c) return null;
  return { ok: !!c.ok, at: c.at, origin: c.origin, observed: c.origin === "observed",
    originText: c.origin === "observed" ? "observed by Atrium" : "claimed by the sidecar (Atrium could not reach the bridge)",
    rows: (c.rows || []).map((r) => ({ ...r, title: VECTOR_TITLES[r.id] || r.id })) };
}

/** The setup steps of a subsidiary and each one's state: done, current, todo or failed. */
export function setupSteps(sub) {
  const s = sub || {};
  const stopped = s.status === "stopped" || s.status === "archived";
  const enrolled = !!s.sidecar;
  const conf = s.conformance;
  const charter = (s.charter_version || 0) > 0;
  const steps = [];
  const step = (id, title, state, text) => steps.push({ id, title, state: stopped && state !== "done" ? "todo" : state, text });
  if (s.mode === "bridge") {
    const applied = !!s.bridge;
    step("patch", "Bridge patch", applied ? "done" : "current", applied ? `Applied (patch ${s.bridge.patch_id || "-"}, core ${s.bridge.core})`
      : "The Patch Agent prepares the bridge patch; an administrator approves it in Approvals.");
    step("deploy", "Deploy the tool with bridge.env", enrolled || conf ? "done" : applied ? "current" : "todo",
      "Merge the bridge branch and start the tool with the public bridge.env (Atrium-launched tools load it).");
  } else {
    step("credential", "Dedicated read-only credential", s.has_credential ? "done" : "current",
      s.has_credential ? "Entered (encrypted; never shown again)" : "An administrator enters a read-only account of the tool.");
  }
  const canEnroll = s.mode === "bridge" ? !!s.bridge : !!s.has_credential;
  step("enroll", "Enroll the sidecar", enrolled ? "done" : canEnroll ? "current" : "todo",
    enrolled ? `Enrolled (key ${s.sidecar.key_fingerprint})` : s.enrollment_pending ? "A one-time code was issued: start the sidecar with it."
      : "An administrator issues a one-time enrollment code; the sidecar enrolls with it.");
  step("conformance", "Conformance", conf?.ok ? "done" : conf ? "failed" : enrolled ? "current" : "todo",
    conf ? `${conf.ok ? "Passed" : "Failed"} (${conf.origin === "observed" ? "observed by Atrium" : "claimed by the sidecar"})`
      : s.mode === "bridge" ? "Vectors V1 to V20 prove the bridge verifies Atrium's signatures." : "Checks K1 to K3.");
  step("charter", "Charter", charter ? "done" : s.pending_charter_approval ? "current" : conf?.ok ? "current" : "todo",
    charter ? `Version ${s.charter_version} in force` : s.pending_charter_approval ? "Waiting for an administrator in Approvals."
      : "Atrium asks an administrator to approve the charter once conformance passed.");
  return steps;
}

// ---------- the org chart ----------

/** A staff member's live state: disabled, running, waiting for approval, held or idle. */
export function staffState(member, record, waiting = [], sub = {}) {
  if (member && member.enabled === false) return { state: "disabled", tone: "" };
  if (record?.running) return { state: "running", tone: "info" };
  if (waiting.includes(member?.id)) return { state: "waiting for approval", tone: "warn" };
  if (record?.outside_guardrails || (sub.status && sub.status !== "active")) {
    return { state: "held", tone: "warn", why: record?.outside_guardrails || `the subsidiary is ${statusInfo(sub.status).text}` };
  }
  return { state: "idle", tone: "ok" };
}

// ---------- the audit trail ----------

const KIND_LABELS = {
  enroll: "Sidecar enrolled", "enrollment.issue": "Enrollment issued", "enrollment.expire": "Enrollment expired", "token.rotate": "Token rotated",
  "token.retire": "Old token retired", "token.unusable": "Token no longer works", "key.rotate": "Signing key rotated", "ticket.issue": "Ticket issued",
  "model.call": "Model call", "action.request": "Action requested", "action.decision": "Action decided", "action.result": "Action carried out",
  "grant.issue": "Grant issued", "grant.result": "Grant result", "grant.expire": "Grant expired", "grant.regrant": "Grant replaced",
  "hub.request": "Hub request", conformance: "Conformance", "conformance.run": "Conformance run", "charter.draft": "Charter drafted",
  "charter.request": "Charter approval requested", "charter.approve": "Charter approved", "charter.narrow": "Charter narrowed",
  "charter.reject": "Charter rejected", "charter.load": "Charter loaded", report: "Report", escalation: "Escalation", "report.close": "Report closed",
  "report.promote": "Report promoted to a risk", "events.batch": "Tool events relayed", "credential.set": "Credential set",
  "credential.clear": "Credential cleared", "credential.fetch": "Credential fetched", "pause.backlog": "Backlog withdrawn", stop: "Stopped",
  alarm: "Alarm", "circuit.open": "Circuit breaker opened", "bridge.applied": "Bridge applied", "bridge.mismatch": "Bridge changed",
  "run.start": "Run started", "run.end": "Run ended", "run.reply": "Run replied", "spool.dropped": "Spool lines dropped",
  "grant.receipt": "Bridge receipt checked", "grant.reapprove": "Asked a person again", "grant.revoke": "Grants revoked",
  "conformance.hold": "Held: conformance failed", "spool.capped": "Spool over its cap",
};

/** A readable label of an audit entry's kind ("status.paused" -> "Status: paused"). */
export function kindLabel(kind) {
  const k = String(kind || "");
  if (KIND_LABELS[k]) return KIND_LABELS[k];
  if (k.startsWith("status.")) return `Status: ${statusInfo(k.slice(7)).text}`;
  return k.replace(/[._]/g, " ");
}

/** The group of a kind for the filter ("grant.issue" -> "grant"). */
export const kindGroup = (kind) => String(kind || "").split(".")[0];

/** Entries that pass the filters: kind group, staff member, risk (of the action, from the charter or the entry) and trigger
 *  (of the run the entry belongs to). */
export function filterAudit(entries, f = {}, { risks = {}, triggers = {} } = {}) {
  return (entries || []).filter((e) => (!f.kind || kindGroup(e.kind) === f.kind)
    && (!f.staff || e.agent_id === f.staff)
    && (!f.risk || (risks[e.action_id] || e.detail?.risk) === f.risk)
    && (!f.trigger || triggers[e.run_id] === f.trigger));
}

/** Grant rows linked: for each grant id, its approval and the entries that issued it and reported its result. */
export function grantLinks(entries) {
  const out = {};
  for (const e of entries || []) {
    if (!e.grant_jti) continue;
    const g = (out[e.grant_jti] ||= { approval: null, issued: null, result: null });
    if (e.approval_id) g.approval = e.approval_id;
    if (e.kind === "grant.issue" || (e.kind === "action.request" && e.outcome === "auto")) g.issued = e.seq;
    if (e.kind === "grant.result") g.result = e.seq;
  }
  return out;
}
