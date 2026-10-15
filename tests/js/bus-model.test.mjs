// The Agent bus page's pure helpers (hub/web/js/bus-model.js): parties, titles, the transcript's nesting and
// request/reply pairs, where recorded failures show, durations, the filters in the address and the live list's merge.
import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  agentEventsReload, agentIcon, anyFilter, apiQuery, appendPage, bodyPreview, busHref, chatThreadOf, durationText,
  errorKindText, errorsLabel, filterQuery, filtersFrom, hiddenText, initiatorText, listLoads, mergeThreads, ownChatText,
  pairInfo, partyIcon, partyKind, partyName, statusChip, threadTitle, transcript, truncatedNote,
} from "../../hub/web/js/bus-model.js";

const names = { supervisor: "Hub Supervisor", patcher: "Patch Agent", "tool:crm": "CRM Supervisor" };

test("parties: people, the hub's schedule and agents", () => {
  assert.equal(partyKind("user:alice"), "person");
  assert.equal(partyKind("token:ci"), "person");
  assert.equal(partyKind("hub"), "schedule");
  assert.equal(partyKind("tool:crm"), "agent");
  assert.equal(partyName("user:alice"), "alice");
  assert.equal(partyName("token:ci"), "API token ci");
  assert.equal(partyName("subsidiary:crm"), "crm sidecar");
  assert.equal(partyName("hub"), "Atrium");
  assert.equal(partyName("patcher", names), "Patch Agent");
  assert.equal(partyName("custom:x"), "custom:x");
  assert.equal(partyIcon("user:alice"), "user");
  assert.equal(partyIcon("hub"), "clock");
  assert.equal(partyIcon("patcher"), "wrench");
  assert.equal(partyIcon("tool:crm"), "grid");
  assert.equal(partyIcon("module:assets"), "box");
  assert.equal(partyIcon("module:grc"), "shield");
  assert.equal(partyIcon("custom:x", { "custom:x": { id: "custom:x", role: "team-agent" } }), "bot");
  assert.equal(agentIcon({ id: "operator", role: "operator" }), "terminal");
});

test("titles: the reader's own words, someone else's chat stays private, else the subject", () => {
  const chat = { subject: "chat", title: "chat", private: true, mine: false, participants: ["user:alice", "supervisor"], initiator: { id: "user:alice", kind: "person" } };
  assert.equal(threadTitle(chat, names), "Private chat with Hub Supervisor");
  assert.equal(threadTitle({ ...chat, mine: true, title: "patch crm" }, names), "patch crm");
  assert.equal(threadTitle({ subject: "health.sweep", title: "health.sweep" }), "health.sweep");
  assert.equal(threadTitle({}), "Conversation");
  assert.equal(initiatorText(chat, names), "alice");
  assert.equal(initiatorText({ initiator: { id: "hub", kind: "schedule" } }), "Scheduled");
  assert.equal(initiatorText({ initiator: { id: "supervisor", kind: "agent" } }, names), "Hub Supervisor");
  assert.deepEqual(statusChip("open"), ["working", "info"]);
  assert.deepEqual(statusChip("failed"), ["failed", "bad"]);
  assert.deepEqual(statusChip("answered"), ["answered", "ok"]);
});

test("durations", () => {
  assert.equal(durationText(null), "");
  assert.equal(durationText(undefined), "");
  assert.equal(durationText(-1), "");
  assert.equal(durationText(0), "under 1 ms");
  assert.equal(durationText(0.35), "350 ms");
  assert.equal(durationText(1.234), "1.2 s");
  assert.equal(durationText(42.4), "42 s");
  assert.equal(durationText(185), "3 min 5 s");
  assert.equal(durationText(120), "2 min");
  assert.equal(durationText(7440), "2 h 4 min");
});

// person -> supervisor -> patcher -> tool supervisor, and the answers back (tests/test_agent_bus.py's chain)
const chain = [
  { id: "m1", sender: "user:alice", recipient: "supervisor", subject: "chat", kind: "request", parent: null, reply_id: "m6", duration: 3.2 },
  { id: "m2", sender: "supervisor", recipient: "patcher", subject: "propose", kind: "request", parent: "m1", reply_id: "m5", duration: 2 },
  { id: "m3", sender: "patcher", recipient: "tool:crm", subject: "describe", kind: "request", parent: "m2", reply_id: null, pending: false },
  { id: "m4", sender: "patcher", recipient: "tool:crm", subject: "notice", kind: "event", parent: "m2" },
  { id: "m5", sender: "patcher", recipient: "supervisor", subject: "propose", kind: "reply", reply_to: "m2", parent: "m2", duration: 2, failed: true, error: "boom" },
  { id: "m6", sender: "supervisor", recipient: "user:alice", subject: "chat", kind: "reply", reply_to: "m1", parent: "m1", duration: 3.2 },
];

test("the transcript nests an ask chain and pairs requests with their answers", () => {
  const { rows } = transcript(chain);
  assert.deepEqual(rows.map((r) => [r.n, r.depth, r.pair]), [[1, 0, 6], [2, 1, 5], [3, 2, null], [4, 2, null], [5, 1, 2], [6, 0, 1]]);
  assert.deepEqual(pairInfo(rows[0], rows), { state: "answered", text: "answered in #6", duration: "3.2 s", failed: false });
  assert.deepEqual(pairInfo(rows[1], rows), { state: "answered", text: "answered in #5", duration: "2.0 s", failed: true });
  assert.equal(pairInfo(rows[2], rows).state, "unanswered");
  assert.equal(pairInfo({ ...rows[2], m: { ...rows[2].m, pending: true } }, rows).state, "pending");
  assert.equal(pairInfo(rows[3], rows), null);
  assert.deepEqual(pairInfo(rows[4], rows), { state: "reply", text: "answer to #2", duration: "2.0 s", failed: true });
});

test("the transcript survives a cut log: replies without their request, parents out of reach, deep chains", () => {
  const { rows } = transcript(chain.slice(2));
  assert.deepEqual(rows.map((r) => [r.depth, r.pair]), [[0, null], [0, null], [0, null], [0, null]]);
  assert.equal(pairInfo(rows[2], rows).text, "answer");
  const deep = Array.from({ length: 9 }, (_, i) => ({ id: `d${i}`, kind: "request", parent: i ? `d${i - 1}` : null }));
  assert.equal(Math.max(...transcript(deep).rows.map((r) => r.depth)), 5);
  const self = transcript([{ id: "x", kind: "reply", reply_to: "x", parent: "x" }]).rows[0];
  assert.deepEqual([self.depth, self.pair], [0, null]);
});

test("a recorded failure shows on the answer to the message that failed, else on that message", () => {
  const errors = [
    { id: "e1", message: "m2", kind: "exception", agent: "patcher" },
    { id: "e2", message: "m3", kind: "timeout", agent: "tool:crm" },
    { id: "e3", message: "m4", kind: "exception", agent: "tool:crm" },
    { id: "e4", message: "gone", kind: "llm", agent: "supervisor" },
    { id: "e5", message: null, kind: "llm", agent: "supervisor" },
  ];
  const { rows, other } = transcript(chain, errors);
  assert.deepEqual(rows.map((r) => r.errors.map((e) => e.id)), [[], [], ["e2"], ["e3"], ["e1"], []]);
  assert.deepEqual(other.map((e) => e.id), ["e4", "e5"]);
  assert.equal(errorKindText("timeout"), "no answer in time");
  assert.equal(errorKindText("odd"), "odd");
});

test("bodies: the reader's own chat words, previews, summaries, why one is hidden", () => {
  assert.equal(ownChatText({ mine: true, subject: "chat", kind: "request", body: { text: "patch crm" } }), "patch crm");
  assert.equal(ownChatText({ mine: true, subject: "chat", kind: "reply", body: { reply: "Done", mode: "rules" } }), "Done");
  assert.equal(ownChatText({ mine: false, subject: "chat", kind: "request", body: { text: "x" } }), null);
  assert.equal(ownChatText({ mine: true, subject: "propose", kind: "request", body: { text: "x" } }), null);
  assert.equal(ownChatText({ mine: true, subject: "chat", kind: "reply", body: { error: "no" } }), null);
  assert.equal(bodyPreview({}), "");
  assert.equal(bodyPreview(null), "");
  assert.equal(bodyPreview({ tool_id: "crm" }), '{"tool_id":"crm"}');
  assert.equal(bodyPreview({ text: "x".repeat(200) }, 20).length, 20);
  assert.equal(truncatedNote({ count: 3, _truncated: "90000 bytes, not logged in full" }), "90000 bytes, not logged in full");
  assert.equal(truncatedNote({ count: 3 }), null);
  assert.equal(hiddenText("role")[0], "hidden: your role");
  assert.equal(hiddenText("private")[0], "private chat");
  assert.equal(hiddenText("other")[0], "hidden");
});

test("the agent card's errors button", () => {
  assert.equal(errorsLabel({ errors: 0, errors_unacknowledged: 0 }), null);
  assert.equal(errorsLabel({}), null);
  assert.deepEqual(errorsLabel({ errors: 2, errors_unacknowledged: 1 }), { text: "1 error", tone: "bad", title: "1 not acknowledged, 2 since the hub started - show them" });
  assert.equal(errorsLabel({ errors: 0, errors_unacknowledged: 3 }).text, "3 errors"); // after a restart: from the store
  assert.deepEqual(errorsLabel({ errors: 2, errors_unacknowledged: 0 }), { text: "2 errors, acknowledged", tone: "", title: "2 since the hub started, all acknowledged - show them" });
});

test("the conversation a person's chat started, from the live message event", () => {
  const event = { type: "message", data: { kind: "request", subject: "chat", sender: "user:alice", recipient: "supervisor", thread: "m1" } };
  assert.equal(chatThreadOf(event, "user:alice", "supervisor"), "m1");
  assert.equal(chatThreadOf(event, "user:bob", "supervisor"), null);
  assert.equal(chatThreadOf(event, "user:alice", "patcher"), null);
  assert.equal(chatThreadOf({ data: { ...event.data, kind: "reply" } }, "user:alice", "supervisor"), null);
  assert.equal(chatThreadOf({ data: { ...event.data, subject: "chat.reset" } }, "user:alice", "supervisor"), null);
  assert.equal(chatThreadOf(null, "user:alice", "supervisor"), null);
});

test("filters: from the address, back to it, and to the API", () => {
  const none = filtersFrom(new URLSearchParams(""));
  assert.deepEqual(none, { agent: "", status: "", errors: false, mine: false, q: "" });
  assert.equal(anyFilter(none), false);
  const f = filtersFrom(new URLSearchParams("agent=tool%3Acrm&status=failed&errors=1&mine=1&q=disk"));
  assert.deepEqual(f, { agent: "tool:crm", status: "failed", errors: true, mine: true, q: "disk" });
  assert.equal(anyFilter(f), true);
  assert.equal(filtersFrom(new URLSearchParams("status=bogus&errors=yes")).status, "");
  assert.equal(filtersFrom({ q: "x".repeat(500) }).q.length, 200);
  assert.equal(filterQuery(f), "agent=tool%3Acrm&status=failed&errors=1&mine=1&q=disk");
  assert.equal(busHref("m_1", f), "#/bus/m_1?agent=tool%3Acrm&status=failed&errors=1&mine=1&q=disk");
  assert.equal(busHref("seq:12"), "#/bus/seq%3A12");
  assert.equal(busHref(null, none), "#/bus");
  assert.equal(apiQuery(f, { limit: 50, before: 99 }), "limit=50&agent=tool%3Acrm&status=failed&errors_only=true&person_only=true&q=disk&before=99");
  assert.equal(apiQuery({ ...none, q: "   " }), "limit=50");
});

test("the live list: a refresh of the first page keeps what Load more added below it", () => {
  const t = (id, last_seq) => ({ id, last_seq });
  const first = { threads: [t("a", 10), t("b", 9)], total: 4, next_before: 9 };
  let list = mergeThreads(null, first);
  assert.deepEqual(list, { threads: first.threads, total: 4, next_before: 9, more: false });
  list = appendPage(list, { threads: [t("c", 8), t("d", 7)], total: 4, next_before: null });
  assert.deepEqual(list.threads.map((x) => x.id), ["a", "b", "c", "d"]);
  assert.equal(list.more, true);
  // "c" got a new message: it moves to the top, "b" drops below the first page
  const refreshed = mergeThreads(list, { threads: [t("c", 11), t("a", 10)], total: 4, next_before: 10 });
  assert.deepEqual(refreshed.threads.map((x) => x.id), ["c", "a", "b", "d"]);
  assert.equal(refreshed.next_before, null);
  // the whole list fits on the first page now: the page alone
  assert.deepEqual(mergeThreads(list, { threads: [t("a", 10)], total: 1, next_before: null }).threads.map((x) => x.id), ["a"]);
  // nothing was loaded below: the page alone
  assert.deepEqual(mergeThreads({ ...first, more: false }, { threads: [t("e", 12)], total: 5, next_before: 12 }).threads.map((x) => x.id), ["e"]);
});

test("the list's loads: a live refresh never drops an older page, new filters drop everything still loading", () => {
  const loads = listLoads();
  const first = loads.list(true);
  assert.equal(loads.current(first), true);
  const more = loads.more(); // "Show older conversations"
  assert.equal(loads.paging, true);
  assert.equal(loads.more(), null); // one at a time
  const refresh = loads.list(); // a live refresh that started anyway (the view holds them back while paging)
  assert.equal(loads.current(more), true); // the older page still lands
  assert.equal(loads.current(refresh), true);
  assert.equal(loads.current(first), false); // a newer first page supersedes an older one
  loads.done(more);
  assert.equal(loads.paging, false);
  const again = loads.more();
  const filtered = loads.list(true); // the filters changed: the older page of the old filters no longer applies
  assert.equal(loads.current(again), false);
  assert.equal(loads.current(filtered), true);
  loads.done(again);
  assert.equal(loads.paging, false);
  assert.equal(loads.current(null), false);
});

test("the errors drawer reloads for its agent's events, also when another agent's event comes right after", () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    let loads = 0;
    const live = agentEventsReload("patcher", () => { loads += 1; }, 400);
    // a failure cascade: the tool's supervisor, then the Patch Agent that asked it, then the Hub Supervisor
    live({ type: "agent_error", data: { agent: "tool:crm" } });
    live({ type: "agent_error", data: { agent: "patcher" } });
    live({ type: "agent_error", data: { agent: "supervisor" } });
    mock.timers.tick(399);
    assert.equal(loads, 0);
    mock.timers.tick(1);
    assert.equal(loads, 1); // once, after the burst
    live({ type: "agent_error", data: { agent: "supervisor" } });
    mock.timers.tick(1000);
    assert.equal(loads, 1); // another agent's alone: nothing to reload
    live({ type: "agent_errors_cleared", data: {} });
    mock.timers.tick(400);
    assert.equal(loads, 2); // an event about no agent in particular
  } finally {
    mock.timers.reset();
  }
});
