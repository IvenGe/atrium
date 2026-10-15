// Pure helpers for the Agent bus page and the agents' errors (no DOM): who a party on the bus is, a conversation's
// title and status, the transcript's order (numbers, nesting, request/reply pairs, which recorded failure shows on
// which message), durations, the filters in the address and the live list's merge (API: hub/bus_api.py).

export const CHAT_SUBJECTS = new Set(["chat", "chat.reset"]); // hub/bus.py PRIVATE_SUBJECTS
export const PRIVATE_TEXT = "[private: quotes a person's chat]"; // hub/bus.py PRIVATE_TEXT
export const STATUSES = ["open", "answered", "failed"];
const MAX_DEPTH = 5; // deeper ask chains stay at this indent

// ---------- parties ----------

const ROLE_ICON = { supervisor: "bot", patcher: "wrench", operator: "terminal", "module-supervisor": "shield", "tool-supervisor": "grid", "team-agent": "bot" };
const MODULE_ICON = { "module:assets": "box", "module:people": "contact", "module:vulns": "bug" };

/** The icon of an agent record ({id, role}). */
export const agentIcon = (a) => MODULE_ICON[a?.id] || ROLE_ICON[a?.role] || "bot";

/** person (an account "user:<name>" or an API token "token:<name>") | schedule (the hub itself) | agent. */
export function partyKind(id) {
  const s = String(id || "");
  if (s.startsWith("user:") || s.startsWith("token:")) return "person";
  return s === "hub" ? "schedule" : "agent";
}

/** A party as people read it: an agent's name (from `names`, id -> name), "alice" for user:alice, "API token ci". */
export function partyName(id, names = {}) {
  const s = String(id || "");
  if (names[s]) return names[s];
  if (s.startsWith("user:")) return s.slice(5);
  if (s.startsWith("token:")) return `API token ${s.slice(6)}`;
  if (s.startsWith("subsidiary:")) return `${s.slice(11)} sidecar`;
  if (s === "hub") return "Atrium";
  return s || "unknown";
}

/** The icon of a party: a person, the hub's schedule, or the agent's own (`agents`: id -> agent record). */
export function partyIcon(id, agents = {}) {
  const kind = partyKind(id);
  if (kind === "person") return "user";
  if (kind === "schedule") return "clock";
  const s = String(id || "");
  const role = s.startsWith("tool:") ? "tool-supervisor" : s.startsWith("module:") ? "module-supervisor" : s;
  return agentIcon(agents[s] || { id: s, role });
}

/** Who started a conversation, in words: a person's name, an agent's, or "Scheduled". */
export function initiatorText(t, names = {}) {
  const i = t?.initiator || {};
  return i.kind === "schedule" ? "Scheduled" : partyName(i.id, names);
}

// ---------- conversations ----------

/** A conversation's title: the reader's own words for their chat (the API gives them), "Private chat with <agent>"
 *  for someone else's, else what it was about (its first message's subject). */
export function threadTitle(t, names = {}) {
  if (t?.private && !t.mine && CHAT_SUBJECTS.has(t.subject)) {
    const agent = (t.participants || []).find((p) => partyKind(p) === "agent");
    return `Private chat${agent ? ` with ${partyName(agent, names)}` : ""}`;
  }
  return t?.title || t?.subject || "Conversation";
}

const STATUS = { open: ["working", "info"], answered: ["answered", "ok"], failed: ["failed", "bad"] };
/** [label, badge tone] of a conversation's status (open | answered | failed). */
export const statusChip = (status) => STATUS[status] || [String(status || "unknown"), ""];

/** "350 ms", "1.2 s", "42 s", "3 min 5 s", "2 h 4 min"; "" when unknown. */
export function durationText(seconds) {
  const s = Number(seconds);
  if (seconds == null || !Number.isFinite(s) || s < 0) return "";
  if (s < 0.001) return "under 1 ms";
  if (s < 1) return `${Math.round(s * 1000)} ms`;
  if (s < 10) return `${(Math.round(s * 10) / 10).toFixed(1)} s`;
  if (s < 60) return `${Math.round(s)} s`;
  const min = Math.floor(s / 60);
  if (min < 60) {
    const rest = Math.round(s - min * 60);
    return rest ? `${min} min ${rest} s` : `${min} min`;
  }
  return `${Math.floor(min / 60)} h ${min % 60} min`;
}

export const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

/**
 * The transcript, oldest first: each row {m, n (its number, #1...), depth (what caused it: a request or notice sits
 * under the message whose handling sent it, a reply beside its request), pair (the number of a request's reply or a
 * reply's request), errors (the recorded failures it shows)}. A failure shows on the answer to the message that
 * failed, else on that message; `other`: failures of messages the transcript does not hold.
 */
export function transcript(messages = [], errors = []) {
  const byId = new Map();
  const rows = messages.map((m, i) => {
    const row = { m, n: i + 1, depth: 0, pair: null, errors: [] };
    if (m.id) byId.set(m.id, row);
    return row;
  });
  for (const row of rows) {
    const { m } = row;
    const request = m.kind === "reply" ? byId.get(m.reply_to) : null;
    if (request && request !== row) {
      row.depth = request.depth;
      row.pair = request.n;
      request.pair ??= row.n;
    } else {
      const parent = m.parent ? byId.get(m.parent) : null;
      row.depth = parent && parent !== row ? Math.min(parent.depth + 1, MAX_DEPTH) : 0;
    }
  }
  const other = [];
  for (const e of errors) {
    const at = e.message ? byId.get(e.message) : null;
    const target = at && at.m.kind === "request" && at.pair ? rows[at.pair - 1] : at;
    if (target) target.errors.push(e);
    else other.push(e);
  }
  return { rows, other };
}

/** How a request was answered, or which request a reply answers: {state, text, duration, failed}; null for a notice.
 *  state: answered | pending | unanswered (a request), reply. */
export function pairInfo(row, rows) {
  const { m } = row;
  const other = row.pair ? rows[row.pair - 1]?.m : null;
  if (m.kind === "request") {
    if (row.pair || m.reply_id) {
      return { state: "answered", text: row.pair ? `answered in #${row.pair}` : "answered", duration: durationText(m.duration),
        failed: Boolean(other?.failed) };
    }
    return m.pending ? { state: "pending", text: "waiting for the answer", duration: "", failed: false }
      : { state: "unanswered", text: "no answer", duration: "", failed: true };
  }
  if (m.kind === "reply") {
    return { state: "reply", text: row.pair ? `answer to #${row.pair}` : "answer", duration: durationText(m.duration), failed: Boolean(m.failed) };
  }
  return null;
}

/** The words of the reader's own chat message (what they asked, or the agent's answer); null for any other. */
export function ownChatText(m) {
  if (!m?.mine || !CHAT_SUBJECTS.has(m.subject) || !m.body || typeof m.body !== "object") return null;
  const text = m.kind === "reply" ? m.body.reply : m.body.text;
  return typeof text === "string" ? text : null;
}

/** Why a body is not shown: [short label, explanation]. */
export const HIDDEN = {
  role: ["hidden: your role", "Operators and administrators read message bodies. Your role reads the routing, status and errors."],
  private: ["private chat", "A person's chat with an agent: only that person reads its text."],
  unavailable: ["body unavailable", "The hub cannot read its secrets to mask this body, so it is not shown."],
};
export const hiddenText = (reason) => HIDDEN[reason] || ["hidden", ""];

/** One line of a body for the collapsed view ("" for an empty body). */
export function bodyPreview(body, max = 96) {
  if (body == null) return "";
  let text;
  try { text = JSON.stringify(body); } catch { text = String(body); }
  if (!text || text === "{}" || text === "[]") return "";
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export function pretty(body) {
  try { return JSON.stringify(body, null, 2); } catch { return String(body); }
}

/** A body the log kept as a summary (over its size limit): the note it carries, else null. */
export const truncatedNote = (body) => (body && typeof body === "object" && typeof body._truncated === "string" ? body._truncated : null);

// ---------- errors ----------

export const ERROR_KINDS = { exception: "crashed", reply: "answered with an error", timeout: "no answer in time", unreachable: "not reachable", llm: "AI model call failed" };
export const errorKindText = (kind) => ERROR_KINDS[kind] || String(kind || "failed");

/** The agent card's errors button: {text, tone, title}, or null when the agent has no errors to show. */
export function errorsLabel(a) {
  const open = Number(a?.errors_unacknowledged) || 0;
  const since = Number(a?.errors) || 0;
  if (!open && !since) return null;
  if (open) {
    return { text: plural(open, "error"), tone: "bad",
      title: `${open} not acknowledged${since ? `, ${since} since the hub started` : ""} - show them` };
  }
  return { text: `${plural(since, "error")}, acknowledged`, tone: "", title: `${since} since the hub started, all acknowledged - show them` };
}

/** The conversation a person's chat started, from a live "message" event: the thread of the chat request `me` sent to
 *  `agent`; null for any other message. */
export function chatThreadOf(event, me, agent) {
  const m = event?.data || event;
  return m && m.kind === "request" && m.subject === "chat" && m.sender === me
    && m.recipient === agent && m.thread ? m.thread : null;
}

// ---------- filters and the list ----------

/** The list's filters from the address (#/bus[/<thread>]?agent=&status=&errors=1&mine=1&q=). */
export function filtersFrom(query) {
  const get = (k) => String((query?.get ? query.get(k) : query?.[k]) ?? "");
  const status = get("status");
  return { agent: get("agent"), status: STATUSES.includes(status) ? status : "", errors: get("errors") === "1",
    mine: get("mine") === "1", q: get("q").slice(0, 200) };
}

export const anyFilter = (f) => Boolean(f.agent || f.status || f.errors || f.mine || f.q.trim());

/** The filters as the address keeps them ("" when none). */
export function filterQuery(f) {
  const p = new URLSearchParams();
  if (f.agent) p.set("agent", f.agent);
  if (f.status) p.set("status", f.status);
  if (f.errors) p.set("errors", "1");
  if (f.mine) p.set("mine", "1");
  if (f.q.trim()) p.set("q", f.q.trim());
  return p.toString();
}

/** The address of a conversation (or of the list) with the filters kept. */
export function busHref(thread, f = null) {
  const q = f ? filterQuery(f) : "";
  return `#/bus${thread ? `/${encodeURIComponent(thread)}` : ""}${q ? `?${q}` : ""}`;
}

/** The query of GET /api/bus/threads for the filters and a page. */
export function apiQuery(f, { limit = 50, before = null } = {}) {
  const p = new URLSearchParams({ limit: String(limit) });
  if (f.agent) p.set("agent", f.agent);
  if (f.status) p.set("status", f.status);
  if (f.errors) p.set("errors_only", "true");
  if (f.mine) p.set("person_only", "true");
  if (f.q.trim()) p.set("q", f.q.trim());
  if (before != null) p.set("before", String(before));
  return p.toString();
}

/** The list after a live refresh of its first page: `page` (latest activity first) replaces what it covers, and the
 *  conversations loaded below it with "Load more" (`old.more`) stay there. */
export function mergeThreads(old, page) {
  const fresh = { threads: page?.threads || [], total: page?.total ?? 0, next_before: page?.next_before ?? null, more: false };
  if (!old?.more || fresh.next_before == null || !fresh.threads.length) return fresh;
  const ids = new Set(fresh.threads.map((t) => t.id));
  const floor = Math.min(...fresh.threads.map((t) => t.last_seq));
  const below = old.threads.filter((t) => !ids.has(t.id) && t.last_seq < floor);
  return below.length ? { ...fresh, threads: [...fresh.threads, ...below], next_before: old.next_before, more: true } : fresh;
}

/** The list with the next page ("Load more") added below. */
export function appendPage(old, page) {
  const ids = new Set(old.threads.map((t) => t.id));
  return { threads: [...old.threads, ...(page?.threads || []).filter((t) => !ids.has(t.id))], total: page?.total ?? old.total,
    next_before: page?.next_before ?? null, more: true };
}

/** Coordinates the conversation list's loads so none is lost: a new first page (`list(fresh)`, fresh when the filters
 *  changed) supersedes the first pages still loading, and with new filters also an older page still loading; an older
 *  page (`more()`, "Show older conversations"; null while one loads) is never dropped by a live refresh - the view
 *  holds refreshes back while `paging` and they merge with the longer list afterwards. Each start returns a token:
 *  `current(token)` says whether its answer still applies, `done(token)` ends it. */
export function listLoads() {
  let filters = 0, lists = 0, paging = false;
  return {
    get paging() { return paging; },
    list(fresh = false) {
      if (fresh) filters += 1;
      lists += 1;
      return { kind: "list", filters, n: lists };
    },
    more() {
      if (paging) return null;
      paging = true;
      return { kind: "more", filters };
    },
    current: (t) => Boolean(t) && t.filters === filters && (t.kind === "more" || t.n === lists),
    done(t) { if (t?.kind === "more") paging = false; },
  };
}

/** The live handler of an agent's errors drawer: `reload` once `ms` after the last event about agent `id` (or about
 *  no agent in particular). Events are filtered before they are gathered: another agent's event in the same burst (a
 *  failure cascades through the agents that asked) never takes the place of this one's. */
export function agentEventsReload(id, reload, ms = 400) {
  let timer = null;
  return (event) => {
    const agent = event?.data?.agent;
    if (agent && agent !== id) return;
    clearTimeout(timer);
    timer = setTimeout(() => reload(), ms);
  };
}
