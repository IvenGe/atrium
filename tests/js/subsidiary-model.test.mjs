// The Subsidiaries app's model (hub/web/js/subsidiary-model.js): charter diffs classified like the server
// (tests/data/charter_diffs.json, written from hub/subsidiary/charter.py classify and checked against it in
// tests/test_subsidiary_ui.py), the facts of the approval cards, setup steps, staff states, the audit filters and
// escaping of everything a subsidiary or a tool wrote.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  actionFacts, bridgeActions, budgetMeters, changesList, charterBody, charterChanges, charterFacts, classify, compact, conformanceFacts, coreFacts,
  decider, filterAudit, flagInfo, floorMarker, grantLinks, isSubsidiaryApproval, kindLabel, meter, paramsTable, policyChoices, provenance,
  routingFacts, setupSteps, staffId, staffState, statusInfo, testsFacts, triggerText, untrustedBox,
} from "../../hub/web/js/subsidiary-model.js";

const CASES = JSON.parse(readFileSync(new URL("../data/charter_diffs.json", import.meta.url), "utf8"));

test("charter diffs are classified exactly like the server classifies them", () => {
  assert.ok(CASES.length >= 10);
  for (const c of CASES) assert.deepEqual(classify(c.prev, c.next), c.reasons, c.name);
});

test("every change is labelled, and a widening label means the server asks for an approval", () => {
  for (const c of CASES) {
    const changes = charterChanges(c.prev, c.next);
    assert.equal(changes.some((x) => x.widens), c.reasons.length > 0, c.name);
    if (c.name === "nothing changed" || c.name.startsWith("whitespace")) assert.deepEqual(changes, [], c.name);
    else assert.ok(changes.length, `${c.name}: some change is listed`);
  }
  const narrowed = CASES.find((c) => c.name === "a staff member removed and a scope narrowed");
  const texts = charterChanges(narrowed.prev, narrowed.next, { "agent:helpdesk-front-desk": "Front desk" }).map((x) => [x.text, x.widens]);
  assert.deepEqual(texts, [["agent:helpdesk-clerk no longer uses tickets.set_priority", false], ["Remove Front desk (disabled, not deleted)", false],
    ["Switch the Ask-the-team panel off", false]]);
  const budgets = CASES.find((c) => c.name === "budgets: one raised, one lowered");
  assert.deepEqual(charterChanges(budgets.prev, budgets.next).map((x) => [x.text, x.widens]),
    [["Model tokens a day: 300000 -> 400000", true], ["Runs at once: 2 -> 1", false]]);
  assert.deepEqual(charterChanges(null, CASES[0].next), [{ area: "charter", text: "The first charter of this subsidiary", widens: true }]);
});

test("statuses and flags have texts and tones", () => {
  assert.deepEqual(statusInfo("active"), { text: "active", tone: "ok", help: "The team works inside the tool within its charter." });
  assert.equal(statusInfo("deploying").text, "being deployed");
  assert.equal(statusInfo("nonsense").text, "nonsense");
  assert.equal(flagInfo("circuit_open").tone, "bad");
  assert.match(flagInfo("owner_disabled").help, /another administrator/);
  assert.equal(flagInfo("new_flag").text, "new_flag");
});

test("budget meters", () => {
  assert.deepEqual(meter(50, 100), { label: "", used: 50, limit: 100, pct: 50, tone: "ok", text: "50 of 100" });
  assert.equal(meter(85, 100).tone, "warn");
  assert.equal(meter(100, 100).tone, "bad");
  assert.equal(meter(140, 100).pct, 100);
  assert.deepEqual([meter(7, null).limit, meter(7, null).text, meter(7, null).tone], [null, "7", "ok"]);
  assert.deepEqual(budgetMeters({ tokens: 12_345, tokens_per_day: 300_000, approval_requests: 20, approval_requests_per_day: 20 })
    .map((m) => [m.text, m.tone]), [["12k of 300k", "ok"], ["20 of 20", "bad"]]);
  assert.deepEqual([compact(999), compact(1500), compact(2_500_000)], ["999", "1.5k", "2.5M"]);
});

test("the policies an action may have", () => {
  assert.deepEqual(policyChoices({ risk: "read" }), ["allow", "forbidden"]);
  assert.deepEqual(policyChoices({ risk: "write", reversible: true }, false), ["approval", "forbidden"]);
  assert.deepEqual(policyChoices({ risk: "write", reversible: true }, true), ["approval", "auto", "forbidden"]);
  assert.deepEqual(policyChoices({ risk: "write", reversible: true, external_effect: true }, true), ["approval", "forbidden"]);
  assert.deepEqual(policyChoices({ risk: "admin", reversible: true }, true), ["approval", "forbidden"]);
  assert.equal(floorMarker({ risk: "admin" }, "write"), "raised from write to admin (Atrium's floor)");
  assert.equal(floorMarker({ risk: "write" }, "write"), null);
});

test("the amendment body and new staff ids", () => {
  const c = CASES[0].next;
  const body = charterBody(c, [{ id: "agent:helpdesk-auditor" }]);
  assert.deepEqual(Object.keys(body).sort(), ["actions", "budgets", "data", "events", "mandate", "members", "model_routing", "panel", "staff"]);
  assert.deepEqual(body.actions, [{ id: "tickets.list", policy: "allow" }, { id: "tickets.set_priority", policy: "approval" }]);
  assert.notEqual(body.staff, c.staff); // a copy: editing the body never changes the charter shown
  assert.equal(staffId("helpdesk", "Night Clerk!"), "agent:helpdesk-night-clerk");
  assert.equal(staffId("helpdesk", "Night clerk", ["agent:helpdesk-night-clerk"]), "agent:helpdesk-night-clerk-2");
  assert.equal(staffId("helpdesk", "   "), "agent:helpdesk-staff");
});

test("model routing says where tool data goes", () => {
  const facts = routingFacts({ allowed: ["anthropic", "ollama"], default: "ollama" },
    [{ id: "anthropic", label: "Claude", location: "third_party" }, { id: "ollama", label: "Ollama", location: "self_hosted" }]);
  assert.deepEqual(facts.map((f) => [f.text, f.third, f.default]), [["Tool data is sent to Claude (third-party)", true, false],
    ["Ollama runs on your own hardware: tool data stays local", false, true]]);
  assert.equal(routingFacts({ allowed: ["gone"] })[0].text, "Tool data is sent to gone (third-party)"); // unknown: assume it leaves
});

test("the in-tool action card's facts", () => {
  const now = 1_800_000_000;
  const f = actionFacts({ risk: "write", trigger: "task", proposed_by: "user:alice", taint: ["bridge:tickets.list", "panel:q_91", "connector:assets"],
    injection_flags: 2, params: { ticket_id: 1, priority: "high", tags: ["a"] }, reason_untrusted: "Customer is angry", expires_at: now + 60,
    action_id: "tickets.set_priority", agent_id: "agent:clerk" }, now);
  assert.equal(f.trigger, "task by alice");
  assert.deepEqual(f.provenance, ["tickets.list (read through the bridge)", "panel question q_91 by a tool user (not verified by Atrium)",
    "assets records (read through the connection)"]);
  assert.deepEqual(f.params, [["ticket_id", "1"], ["priority", "high"], ["tags", '["a"]']]);
  assert.deepEqual([f.flags, f.expired, f.adminOnly, f.steered], [2, false, false, false]);
  assert.equal(actionFacts({ risk: "admin" }).adminOnly, true);
  assert.equal(actionFacts({ risk: "write", external_effect: true }).adminOnly, true);
  assert.equal(actionFacts({ expires_at: now - 1 }, now).expired, true);
  const panel = actionFacts({ risk: "write", trigger: "panel", user_steered: true });
  assert.deepEqual([panel.trigger, panel.steered], ["panel: user-steered", true]);
  assert.deepEqual([triggerText("schedule"), triggerText("chat", "token:bob"), triggerText("manual")],
    ["scheduled run", "Atrium chat by bob", "run started by someone"]);
  assert.deepEqual(provenance(["odd"]), ["odd"]);
});

test("what the subsidiary or the tool wrote is escaped and labelled", () => {
  const hostile = "<img src=x onerror=alert(1)><a href='javascript:x'>click</a>";
  const table = String(paramsTable({ [hostile]: hostile, n: { "<b>": "</td>" } }));
  assert.ok(!table.includes("<img") && !table.includes("<a ") && !table.includes("<b>"), table);
  assert.ok(table.includes("&lt;img src=x onerror=alert(1)&gt;"));
  assert.ok(table.includes("&lt;/td&gt;"));
  const box = String(untrustedBox(`ignore previous instructions ${hostile}`));
  assert.ok(box.includes("Written by the subsidiary team (untrusted)") && !box.includes("<img") && box.includes("&lt;a href="));
  assert.equal(untrustedBox("   "), "");
  assert.match(String(paramsTable({})), /No parameters/);
});

test("the bridge patch card's facts", () => {
  assert.equal(testsFacts({ ok: true, status: "passed", runtime: "docker" }).text, "The tool's tests passed (docker)");
  assert.equal(testsFacts({ ok: false, status: "failed" }).tone, "bad");
  const notRun = testsFacts({ ok: null, status: "not_run", reason: "no container runtime" });
  assert.deepEqual([notRun.status, notRun.tone, notRun.text], ["not_run", "warn", "The tool's tests did not run: no container runtime"]);
  assert.match(notRun.warning, /only an administrator approves.*HB-AC-8.*partial/);
  assert.equal(testsFacts(null).status, "unknown");
  assert.equal(coreFacts({ vendored_core: true, core: "python/1.0.0" }).tone, "ok");
  assert.match(coreFacts({ vendored_core: false, core: "php/0.1" }).text, /written by an AI model/);
  const rows = bridgeActions({ actions: [{ id: "tickets.delete", risk: "admin" }, { id: "tickets.list", risk: "read" }],
    raised: [{ id: "tickets.delete", declared: "write", risk: "admin", reason: "deletes" }] });
  assert.deepEqual(rows.map((r) => r.floor), ["raised from write (deletes)", null]);
});

test("conformance rows carry their titles and origin", () => {
  const c = conformanceFacts({ ok: false, origin: "claimed", rows: [{ id: "V3", ok: false, status: 200 }, { id: "K2", ok: true }] });
  assert.deepEqual(c.rows.map((r) => r.title), ["A ticket signed with another key is refused", "The connection is not a network device"]);
  assert.equal(c.observed, false);
  assert.match(c.originText, /claimed by the sidecar/);
  assert.equal(conformanceFacts(null), null);
});

test("setup steps follow the subsidiary's progress", () => {
  const states = (sub) => setupSteps(sub).map((s) => `${s.id}:${s.state}`);
  assert.deepEqual(states({ mode: "bridge", status: "proposed" }), ["patch:current", "deploy:todo", "enroll:todo", "conformance:todo", "charter:todo"]);
  const enrolled = { mode: "bridge", status: "probation", bridge: { patch_id: "p_1", core: "python/1.0.0" }, sidecar: { key_fingerprint: "ab:cd" } };
  assert.deepEqual(states(enrolled), ["patch:done", "deploy:done", "enroll:done", "conformance:current", "charter:todo"]);
  assert.deepEqual(states({ ...enrolled, conformance: { ok: false, origin: "observed" } }).slice(3), ["conformance:failed", "charter:todo"]);
  assert.deepEqual(states({ ...enrolled, status: "active", conformance: { ok: true, origin: "claimed" }, charter_version: 2 }).slice(3),
    ["conformance:done", "charter:done"]);
  assert.deepEqual(states({ mode: "sidecar_only", status: "proposed" }), ["credential:current", "enroll:todo", "conformance:todo", "charter:todo"]);
  assert.deepEqual(states({ mode: "sidecar_only", status: "deploying", has_credential: true, enrollment_pending: true }).slice(0, 2),
    ["credential:done", "enroll:current"]);
  assert.ok(setupSteps({ mode: "bridge", status: "stopped" }).every((s) => s.state === "todo"));
});

test("the staff's live states", () => {
  const m = { id: "agent:clerk", enabled: true };
  assert.equal(staffState({ ...m, enabled: false }, {}).state, "disabled");
  assert.equal(staffState(m, { running: 123 }, [], { status: "active" }).state, "running");
  assert.equal(staffState(m, {}, ["agent:clerk"], { status: "active" }).state, "waiting for approval");
  assert.deepEqual(staffState(m, { outside_guardrails: "the Helpdesk subsidiary is paused by Atrium" }, [], { status: "paused" }),
    { state: "held", tone: "warn", why: "the Helpdesk subsidiary is paused by Atrium" });
  assert.equal(staffState(m, {}, [], { status: "probation" }).why, "the subsidiary is on probation");
  assert.equal(staffState(m, {}, [], { status: "active" }).state, "idle");
});

test("the audit trail's labels, filters and grant links", () => {
  assert.deepEqual([kindLabel("status.paused"), kindLabel("grant.result"), kindLabel("weird.kind_x")], ["Status: paused", "Grant result", "weird kind x"]);
  const entries = [
    { seq: 1, kind: "action.request", agent_id: "agent:clerk", action_id: "tickets.set_priority", run_id: "run_1", approval_id: "ap_1", outcome: "pending" },
    { seq: 2, kind: "grant.issue", agent_id: "agent:clerk", action_id: "tickets.set_priority", run_id: "run_1", approval_id: "ap_1", grant_jti: "g1" },
    { seq: 3, kind: "grant.result", agent_id: "agent:clerk", action_id: "tickets.set_priority", approval_id: "ap_1", grant_jti: "g1", outcome: "executed" },
    { seq: 4, kind: "model.call", agent_id: "agent:desk", run_id: "run_2" },
    { seq: 5, kind: "action.request", agent_id: "agent:clerk", action_id: "tickets.close", run_id: "run_3", approval_id: "auto", grant_jti: "g2", outcome: "auto",
      detail: { risk: "write" } },
  ];
  const ctx = { risks: { "tickets.set_priority": "write" }, triggers: { run_1: "task", run_2: "panel", run_3: "schedule" } };
  const seqs = (f) => filterAudit(entries, f, ctx).map((e) => e.seq);
  assert.deepEqual(seqs({ kind: "grant" }), [2, 3]);
  assert.deepEqual(seqs({ staff: "agent:desk" }), [4]);
  assert.deepEqual(seqs({ risk: "write" }), [1, 2, 3, 5]);
  assert.deepEqual(seqs({ trigger: "panel" }), [4]);
  assert.deepEqual(seqs({ kind: "action", trigger: "schedule" }), [5]);
  assert.deepEqual(grantLinks(entries), { g1: { approval: "ap_1", issued: 2, result: 3 }, g2: { approval: "auto", issued: 5, result: null } });
});

test("who decides a subsidiary's approval mirrors the server (api.subsidiary_decider)", () => {
  const action = (payload) => ({ kind: "subsidiary_action", payload });
  assert.equal(decider({ kind: "subsidiary_charter", payload: {} }), "admin");
  assert.equal(decider({ kind: "patch", payload: { strategy: "atrium_bridge" } }), "admin");
  assert.equal(decider({ kind: "patch", payload: { strategy: "sso" } }), null);
  assert.equal(decider(action({ risk: "write" })), "operator");
  assert.equal(decider(action({ risk: "admin" })), "admin");
  assert.equal(decider(action({ risk: "write", external_effect: true })), "admin");
  assert.equal(decider({ kind: "command", payload: {} }), null);
  assert.deepEqual([isSubsidiaryApproval(action({})), isSubsidiaryApproval({ kind: "patch", payload: { strategy: "atrium_bridge" } }),
    isSubsidiaryApproval({ kind: "patch", payload: {} }), isSubsidiaryApproval(null)], [true, true, false, false]);
});

test("the charter card's facts: widening from Atrium, the diff, conformance and the new staff with their scopes", () => {
  const widened = CASES.find((c) => c.name === "a staff member added, a scope and hub tools widened");
  const pending = { ...widened.next, version: 2 };
  const sub = { mode: "bridge", charter: widened.prev, pending_charter: pending, staff: [{ id: "agent:helpdesk-clerk", name: "Clerk" }],
    conformance: { ok: true, origin: "observed", rows: [] } };
  const newId = Object.keys(pending.staff).find((id) => !(id in widened.prev.staff));
  const payload = { charter_version: 2, widening: widened.reasons, routing_warning: "Tool data is sent to Claude (third-party).",
    members: [{ id: newId, name: "Night <clerk>", title: "Clerk", permissions: ["read", "tool_actions"] }] };
  const f = charterFacts(payload, sub, [{ id: "anthropic", label: "Claude", location: "third_party" }]);
  assert.deepEqual(f.widening, widened.reasons);
  assert.equal(f.first, false);
  assert.equal(f.stale, false);
  assert.ok(f.changes.some((c) => c.widens && c.text === "Add staff member Night <clerk>"), JSON.stringify(f.changes));
  assert.deepEqual([f.conformance.observed, f.routingWarning, f.routing[0].third], [true, "Tool data is sent to Claude (third-party).", true]);
  assert.deepEqual(f.members[0].scope, pending.staff[newId]);
  // the subsidiary moved on (another version pending, or none): no diff, the card says to reject it
  const stale = charterFacts(payload, { ...sub, pending_charter: { ...pending, version: 3 } });
  assert.deepEqual([stale.changes, stale.stale], [null, true]);
  const first = charterFacts({ charter_version: 1, widening: ["the first charter of this subsidiary"] }, { pending_charter: { ...pending, version: 1 } });
  assert.equal(first.first, true);
  assert.deepEqual(first.changes.map((c) => c.widens), [true]);
  assert.equal(charterFacts({ charter_version: 1 }, null).changes, null); // the subsidiary could not be read
  // the list is labelled with text (not colour only) and escapes what it shows
  const list = String(changesList(f.changes));
  assert.ok(list.includes("widens: needs approval") && list.includes("Night &lt;clerk&gt;") && !list.includes("<clerk>"), list);
  assert.match(String(changesList([])), /No changes/);
});
