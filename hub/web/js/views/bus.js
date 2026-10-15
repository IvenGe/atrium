// The Agent bus page (#/bus[/<thread>]): every conversation on the agent bus - a person's chat and everything it made
// the agents ask each other, scheduled work, notices - with who asked whom, what they answered, how long it took and
// what failed. Left: the live list of conversations with filters; right: one conversation as a transcript. Also the
// errors drawer of an agent (openErrors), which the Agents page opens. Privacy is the server's (hub/conversations.py):
// viewers read routing, status and error texts; a person's chat text only that person.
import { del, eventsOk, get, onEvent, post } from "../api.js";
import { session } from "../auth.js";
import {
  PRIVATE_TEXT, agentEventsReload, anyFilter, apiQuery, appendPage, bodyPreview, busHref, errorKindText, filtersFrom, hiddenText,
  initiatorText, listLoads, mergeThreads, ownChatText, pairInfo, partyIcon, partyKind, partyName, plural, pretty, statusChip,
  threadTitle, transcript, truncatedNote,
} from "../bus-model.js";
import {
  actions, badge, can, colorFor, confirmDialog, dateTime, debounce, emptyState, esc, html, icon, md, modal, options, raw, setHTML,
  timeAgo, toast,
} from "../ui.js";

const enc = encodeURIComponent;
const PAGE = 50;
const LIVE_WAIT = 800; // ms: live events are gathered this long before the list and the transcript are read again
const SEARCH_WAIT = 10000; // ms: while a search is set the list is read again at most this often (it may read the whole log)
const narrow = () => window.matchMedia("(max-width: 1000px)").matches;
const clock = (ts) => (ts ? new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
const me = () => (session.user ? `user:${session.user.username}` : "");

/** Agent names and records by id, plus "You" for the signed-in person. */
function directory(agents) {
  const byId = Object.fromEntries(agents.map((a) => [a.id, a]));
  const names = Object.fromEntries(agents.map((a) => [a.id, a.name]));
  if (me()) names[me()] = "You";
  return { byId, names };
}

function partyColor(id, dir) {
  const kind = partyKind(id);
  if (kind === "person") return colorFor(String(id).replace(/^\w+:/, ""));
  if (kind === "schedule") return "#64748b";
  const a = dir.byId[id];
  if (a?.role === "tool-supervisor") return colorFor(a.scope || id);
  return a?.role === "team-agent" ? colorFor(id) : "#7c3aed";
}

/** A party's round icon (its name as the title, and for screen readers when `label`). */
export function partyAvatar(id, dir, label = true) {
  const name = partyName(id, dir.names);
  return html`<span class="bus-ava" style="background:${partyColor(id, dir)}" title="${name}" ${label ? html`role="img" aria-label="${name}"` : html`aria-hidden="true"`}>${icon(partyIcon(id, dir.byId))}</span>`;
}

const party = (id, dir) => html`<span class="bus-party">${partyAvatar(id, dir, false)}<span>${partyName(id, dir.names)}</span></span>`;

/** Participants as a row of icons (at most `max`, then "+N"). */
function partyRow(ids, dir, max = 6) {
  const shown = ids.slice(0, max);
  return html`<span class="bus-parties">${shown.map((id) => partyAvatar(id, dir))}${ids.length > max ? html`<span class="bus-more faint">+${ids.length - max}</span>` : ""}</span>`;
}

/** Escaped JSON with the private-quote marker set apart. */
function jsonView(body) {
  const marker = esc(JSON.stringify(PRIVATE_TEXT).slice(1, -1));
  const text = esc(pretty(body)).split(marker).join(`<mark class="bus-private" title="Replaced: it quoted a person's chat">${marker}</mark>`);
  return raw(`<pre class="code wrap bus-json">${text}</pre>`);
}

/** One recorded failure (an ErrorRecord of hub/agent_errors.py). */
function errorView(e, dir, { conversation = false } = {}) {
  const acked = e.acknowledged_at != null;
  return html`<div class="bus-err ${acked ? "acked" : ""}">${icon("alert")}
    <div class="bus-err-main">
      <div><b>${partyName(e.agent, dir.names)}</b> ${errorKindText(e.kind)}
        <span class="faint mono" style="font-size:11.5px">${[e.error_class, e.code].filter(Boolean).join(" · ")}</span></div>
      ${e.error ? html`<pre class="bus-err-text">${e.error}</pre>`
        : e.error_hidden === "private" ? html`<p class="faint">The error text is private: it is about a person's chat.</p>` : ""}
      <div class="row bus-err-foot">
        ${conversation && e.thread ? html`<a href="${busHref(e.thread)}">${icon("messages")}Open conversation</a>` : ""}
        <span class="spacer"></span>
        ${acked ? html`<span class="faint">${icon("check")} Acknowledged${e.acknowledged_by ? ` by ${e.acknowledged_by}` : ""} ${timeAgo(e.acknowledged_at)}</span>`
          : html`<button type="button" class="btn sm" data-act="ack" data-agent="${e.agent}" data-id="${e.id}" data-min-role="operator">${icon("check")}Acknowledge</button>`}
      </div></div></div>`;
}

// ---------- the errors drawer of an agent (opened from the Agents page) ----------

/** Opens the errors of agent `a` ({id, name}) in a drawer: what failed, for whom, when, the conversation it happened in;
 *  operators acknowledge them, an administrator clears them. `agents`: the agent records, for names. */
export function openErrors(a, agents = []) {
  const dir = directory(agents);
  const st = { data: null, error: null, onlyOpen: false, limit: PAGE, busy: false };
  const m = modal({
    title: `${a.name}: errors`, drawer: true, submit: null, cancel: "Close",
    body: html`<div class="errs" aria-busy="true"><p class="faint">Loading...</p></div>`,
    onClose: () => off(),
  });
  const box = m.el.querySelector(".errs");
  const load = async () => {
    const q = new URLSearchParams({ limit: String(st.limit) });
    if (st.onlyOpen) q.set("unacknowledged", "true");
    try {
      st.data = await get(`/agents/${enc(a.id)}/errors?${q}`);
      st.error = null;
    } catch (err) {
      st.error = err.message;
    }
    if (box.isConnected) draw();
  };
  const draw = () => {
    const keep = box.contains(document.activeElement) ? document.activeElement : null;
    const keepSel = keep?.matches("[data-only-open]") ? "[data-only-open]"
      : keep?.dataset?.act ? `[data-act="${keep.dataset.act}"]${keep.dataset.id ? `[data-id="${CSS.escape(keep.dataset.id)}"]` : ""}` : null;
    box.removeAttribute("aria-busy");
    if (st.error) return setHTML(box, emptyState("alert", "Could not load the errors", st.error));
    const d = st.data;
    setHTML(box, html`<div class="errs-head">
        <p>${badge(`${d.unacknowledged} not acknowledged`, d.unacknowledged ? "bad" : "ok")}
          <span class="faint">${plural(d.since_start, "error")} since the hub started, ${d.total} kept${st.onlyOpen ? " (not acknowledged)" : ""}</span></p>
        <div class="row">
          <label class="check"><input type="checkbox" data-only-open ${st.onlyOpen ? "checked" : ""}><span>Not acknowledged only</span></label>
          <span class="spacer"></span>
          <button type="button" class="btn sm" data-act="ack-all" data-min-role="operator" ${d.unacknowledged ? "" : "disabled"}>${icon("check")}Acknowledge all</button>
          <button type="button" class="btn sm danger" data-act="clear" data-min-role="admin" ${d.total || d.since_start ? "" : "disabled"}>${icon("trash")}Clear all</button>
        </div>
        <a href="${busHref(null, { agent: a.id, status: "", errors: true, mine: false, q: "" })}">${icon("messages")}Conversations of ${a.name} with errors</a></div>
      ${d.errors.length ? html`<ol class="errs-list">${d.errors.map((e) => html`<li class="errs-item" data-err="${e.id}">
          <div class="row" style="gap:6px"><code>${e.subject}</code>${badge(errorKindText(e.kind), e.acknowledged_at != null ? "" : "bad")}
            <span class="spacer"></span><time class="faint" datetime="${new Date(e.ts * 1000).toISOString()}" title="${dateTime(e.ts)}">${timeAgo(e.ts)}</time></div>
          ${e.sender ? html`<div class="faint" style="font-size:12.5px">Asked by ${party(e.sender, dir)}</div>` : ""}
          ${errorView(e, dir, { conversation: true })}</li>`)}</ol>`
        : emptyState("checkCircle", st.onlyOpen ? "Nothing left to acknowledge" : "No errors kept", st.onlyOpen ? "Every error of this agent is acknowledged."
          : "Failures of this agent show up here with the conversation they happened in.")}
      ${d.next_before != null ? html`<button type="button" class="btn sm" data-act="more">Show older errors</button>` : ""}`);
    if (!keep) return;
    const again = keepSel && box.querySelector(keepSel);
    // after acknowledging, focus goes on to the next error to acknowledge
    (again && !again.disabled ? again : box.querySelector(".errs-list button[data-act=ack]") || box.querySelector("[data-only-open]"))
      ?.focus({ preventScroll: true });
  };
  box.addEventListener("change", (e) => {
    if (!e.target.matches("[data-only-open]")) return;
    st.onlyOpen = e.target.checked;
    st.limit = PAGE;
    load();
  });
  actions(box, {
    async ack(d) {
      try {
        await post(`/agents/${enc(a.id)}/errors/${enc(d.id)}/ack`);
        await load();
      } catch (err) { toast(err.message, "bad"); }
    },
    async "ack-all"() {
      try {
        const r = await post(`/agents/${enc(a.id)}/errors/ack`);
        toast(`${plural(r.acknowledged, "error")} acknowledged`, "ok");
        await load();
      } catch (err) { toast(err.message, "bad"); }
    },
    async clear() {
      if (!(await confirmDialog(`Clear the errors of ${a.name}?`, "Every error kept for this agent is deleted, and its count since the hub started goes back to 0. This cannot be undone.", "Clear all"))) return;
      try {
        const r = await del(`/agents/${enc(a.id)}/errors`);
        toast(`${plural(r.cleared, "error")} cleared`, "ok");
        await load();
      } catch (err) { toast(err.message, "bad"); }
    },
    more() {
      st.limit = Math.min(500, st.limit + PAGE);
      load();
    },
  });
  // a new failure or someone else's acknowledgement shows at once
  const off = onEvent(["agent_error", "agent_errors_acknowledged", "agent_errors_cleared"], agentEventsReload(a.id, load, 400));
  load();
  return m;
}

// ---------- the page ----------

export async function render(el, ctx) {
  const st = {
    filters: filtersFrom(ctx.query),
    list: null, listError: null,
    selected: ctx.params[0] || null,
    detail: null, detailError: null, detailFor: null,
    open: new Set(), // message ids whose body is expanded
    dir: directory([]), agents: [],
    loads: listLoads(), detailSeq: 0, listAt: 0,
  };

  setHTML(el, html`
    <div class="page-head bus-head"><div><h1 id="bus-title" tabindex="-1">Agent bus</h1>
      <p class="muted">Every conversation between people and agents: who asked whom, what they answered, how long it took and what failed.</p></div>
      <span class="bus-live" id="bus-live" role="status"></span></div>
    <div class="bus" data-view="${st.selected ? "thread" : "list"}">
      <section class="card bus-list" aria-labelledby="bus-list-title">
        <h2 id="bus-list-title" class="sr-only">Conversations</h2>
        <form class="bus-filters" role="search" aria-label="Filter conversations">
          <div class="bus-search">${icon("search")}<input type="search" name="q" maxlength="200" value="${st.filters.q}" autocomplete="off"
            placeholder="${can("operator") ? "Search subjects, agents and messages" : "Search subjects and agents"}" aria-label="Search conversations"></div>
          <div class="row bus-filter-row">
            <select name="agent" class="input-sm" aria-label="Agent"></select>
            <select name="status" class="input-sm" aria-label="Status">${options([["", "Any status"], ["open", "Working"], ["answered", "Answered"], ["failed", "Failed"]], st.filters.status)}</select>
            <label class="check"><input type="checkbox" name="errors" ${st.filters.errors ? "checked" : ""}><span>Errors only</span></label>
            <label class="check"><input type="checkbox" name="mine" ${st.filters.mine ? "checked" : ""}><span>My chats</span></label>
          </div>
        </form>
        <div class="bus-count faint" id="bus-count" aria-live="polite"></div>
        <ul class="bus-threads" id="bus-threads" aria-label="Conversations"></ul>
      </section>
      <section class="card bus-detail" id="bus-detail" aria-label="Conversation"></section>
    </div>
    <div class="sr-only" aria-live="polite" id="bus-announce"></div>`);

  const $ = (sel) => el.querySelector(sel);
  const layout = $(".bus");
  const listEl = $("#bus-threads");
  const detailEl = $("#bus-detail");
  const form = $(".bus-filters");

  // ---------- the list ----------

  const agentChoices = () => [["", "Any agent"], ...st.agents.map((a) => [a.id, a.name]).sort((x, y) => x[1].localeCompare(y[1])),
    ...(st.filters.agent && !st.dir.byId[st.filters.agent] ? [[st.filters.agent, partyName(st.filters.agent)]] : [])];
  const drawAgentFilter = () => setHTML(form.querySelector("[name=agent]"), html`${options(agentChoices(), st.filters.agent)}`);

  function threadItem(t) {
    const title = threadTitle(t, st.dir.names);
    const [label, tone] = statusChip(t.status);
    const sel = t.id === st.selected;
    const others = (t.participants || []).filter((p) => p !== t.initiator?.id);
    return html`<li><a class="bus-thread${sel ? " sel" : ""}" href="${busHref(t.id, st.filters)}" data-thread="${t.id}" ${sel ? html`aria-current="true"` : ""}>
      ${partyAvatar(t.initiator?.id, st.dir, false)}
      <span class="bus-thread-main">
        <span class="bus-thread-top"><span class="bus-thread-title">${t.private && !t.mine ? html`${icon("lock")}<span class="sr-only">Private: </span>` : ""}${title}</span>
          <time datetime="${new Date(t.last * 1000).toISOString()}" title="${dateTime(t.last)}">${timeAgo(t.last)}</time></span>
        <span class="bus-thread-sub">${initiatorText(t, st.dir.names)} &middot; ${plural(t.count, "message")}</span>
        <span class="bus-thread-foot">${others.length ? partyRow(others, st.dir) : ""}<span class="spacer"></span>
          ${badge(label, tone)}${t.errors ? badge(plural(t.errors, "error"), "bad") : ""}</span>
      </span></a></li>`;
  }

  function drawList() {
    const keep = listEl.contains(document.activeElement) ? document.activeElement.dataset.thread || document.activeElement.dataset.act : null;
    const count = $("#bus-count");
    if (st.listError) {
      setHTML(count, "");
      setHTML(listEl, html`<li>${emptyState("alert", "Could not load the conversations", st.listError)}</li>`);
      return;
    }
    if (!st.list) return;
    const { threads, total, next_before: next } = st.list;
    setHTML(count, total ? `${plural(total, "conversation")}${anyFilter(st.filters) ? " match" : ""}` : "");
    setHTML(listEl, threads.length ? html`${threads.map(threadItem)}
        ${next != null ? html`<li class="bus-more-row"><button type="button" class="btn sm" data-act="more">Show older conversations</button></li>` : ""}`
      : html`<li>${anyFilter(st.filters)
        ? emptyState("search", "No conversations match", "Change or clear the filters.", html`<button type="button" class="btn sm" data-act="clear-filters">Clear filters</button>`)
        : emptyState("messages", "No conversations yet", "When you chat with an agent or the agents ask each other for something, the conversation shows up here.")}</li>`);
    if (keep) (listEl.querySelector(`[data-thread="${CSS.escape(keep)}"]`) || listEl.querySelector(`[data-act="${CSS.escape(keep)}"]`))?.focus({ preventScroll: true });
  }

  async function loadList({ fresh = false } = {}) {
    const token = st.loads.list(fresh);
    st.listAt = Date.now();
    try {
      const page = await get(`/bus/threads?${apiQuery(st.filters, { limit: PAGE })}`);
      if (!st.loads.current(token) || !el.isConnected) return;
      st.list = fresh ? mergeThreads(null, page) : mergeThreads(st.list, page);
      st.listError = null;
    } catch (err) {
      if (!st.loads.current(token) || !el.isConnected) return;
      st.listError = err.message;
    }
    drawList();
  }

  // An older page is never lost to a live refresh (that waits for it, see refreshList); new filters drop it.
  async function loadMore(button) {
    if (st.list?.next_before == null) return;
    const token = st.loads.more();
    if (!token) return; // one is loading already
    button?.setAttribute("aria-busy", "true");
    try {
      const page = await get(`/bus/threads?${apiQuery(st.filters, { limit: PAGE, before: st.list.next_before })}`);
      if (!st.loads.current(token) || !el.isConnected) return;
      const before = st.list.threads.length;
      st.list = appendPage(st.list, page);
      drawList();
      listEl.querySelectorAll(".bus-thread")[before]?.focus({ preventScroll: false }); // the first one just added
    } catch (err) {
      if (st.loads.current(token) && el.isConnected) toast(err.message, "bad");
    } finally {
      st.loads.done(token);
      button?.removeAttribute("aria-busy");
    }
  }

  const syncAddress = () => history.replaceState(null, "", busHref(st.selected, st.filters));
  const applyFilters = () => {
    const data = new FormData(form);
    st.filters = { agent: String(data.get("agent") || ""), status: String(data.get("status") || ""), errors: data.get("errors") === "on",
      mine: data.get("mine") === "on", q: String(data.get("q") || "").slice(0, 200) };
    syncAddress();
    loadList({ fresh: true });
  };
  const searchLater = debounce(applyFilters, 500); // a search of message bodies reads the whole log: not on every key
  form.addEventListener("change", (e) => { if (e.target.name !== "q") applyFilters(); });
  form.addEventListener("input", (e) => { if (e.target.name === "q") searchLater(); });
  form.addEventListener("submit", (e) => { e.preventDefault(); applyFilters(); });

  // ---------- one conversation ----------

  function bodyView(m) {
    const own = ownChatText(m);
    if (own != null) return m.kind === "reply" ? html`<div class="bus-chat md">${md(own)}</div>` : html`<div class="bus-chat">${own}</div>`;
    if (m.body_hidden && !m.mine) {
      const [label, why] = hiddenText(m.body_hidden);
      return html`<p class="bus-hidden" title="${why}">${icon("lock")}${label}<span class="sr-only">: ${why}</span></p>`;
    }
    const preview = bodyPreview(m.body);
    if (!preview) return "";
    const note = truncatedNote(m.body);
    return html`<details class="bus-body" data-id="${m.id}" ${st.open.has(m.id) ? "open" : ""}>
      <summary><span class="bus-body-label">Body</span><span class="bus-preview mono">${preview}</span>${note ? badge("summarized", "info") : ""}</summary>
      ${note ? html`<p class="faint" style="font-size:12px;margin:6px 0">The log keeps a summary of this body (${note}).</p>` : ""}
      ${jsonView(m.body)}</details>`;
  }

  function pairView(row, rows) {
    const info = pairInfo(row, rows);
    if (!info) return "";
    const jump = (n) => html`<button type="button" class="link-btn" data-act="jump" data-n="${n}" aria-label="Go to message ${n}">#${n}</button>`;
    if (info.state === "pending") return html`<div class="bus-pair pending"><span class="pulse-dot" aria-hidden="true"></span><span>waiting for the answer</span></div>`;
    if (info.state === "unanswered") return html`<div class="bus-pair bad">${icon("x")}<span>no answer</span></div>`;
    if (info.state === "answered") {
      return html`<div class="bus-pair ${info.failed ? "bad" : "ok"}">${icon(info.failed ? "alert" : "check")}<span>${row.pair ? html`answered in ${jump(row.pair)}` : "answered"}${info.failed ? " with an error" : ""}${info.duration ? ` after ${info.duration}` : ""}</span></div>`;
    }
    return html`<div class="bus-pair">${icon("undo")}<span>${row.pair ? html`answer to ${jump(row.pair)}` : "answer"}${info.duration ? `, took ${info.duration}` : ""}</span></div>`;
  }

  function bubble(row, rows) {
    const { m } = row;
    const person = partyKind(m.sender) === "person";
    const bad = m.failed || row.errors.some((e) => e.acknowledged_at == null) || (m.kind === "request" && !row.pair && !m.reply_id && !m.pending);
    const kind = m.kind === "event" ? "notice" : m.kind;
    return html`<li class="bus-msg${person ? " person" : ""}${bad ? " failed" : ""}" data-n="${row.n}" tabindex="-1" style="--depth:${row.depth}"
        aria-label="Message ${row.n}: ${partyName(m.sender, st.dir.names)} to ${partyName(m.recipient, st.dir.names)}, ${m.subject}, ${kind}">
      <div class="bus-msg-head">
        <span class="bus-num">#${row.n}</span>
        <span class="bus-route">${party(m.sender, st.dir)}<span class="bus-arrow" aria-hidden="true">${icon("arrow")}</span><span class="sr-only">to</span>${party(m.recipient, st.dir)}</span>
        <code class="bus-subj">${m.subject}</code>${badge(kind)}
        <span class="spacer"></span>
        <time class="faint" datetime="${new Date(m.ts * 1000).toISOString()}" title="${dateTime(m.ts)}">${clock(m.ts)}</time>
      </div>
      ${pairView(row, rows)}
      ${bodyView(m)}
      ${row.errors.length ? row.errors.map((e) => errorView(e, st.dir))
        : m.failed ? html`<div class="bus-err">${icon("alert")}<div class="bus-err-main"><b>Failed</b>
            ${m.error ? html`<pre class="bus-err-text">${m.error}</pre>`
              : m.private ? html`<p class="faint">The error text is private: it is about a person's chat.</p>` : ""}</div></div>` : ""}
    </li>`;
  }

  function detailView() {
    if (!st.selected) {
      return emptyState("messages", "Pick a conversation", "Choose one on the left to read how the agents worked on it, message by message.");
    }
    if (st.detailError) {
      return html`${backButton()}${st.detailError.status === 404
        ? emptyState("search", "Conversation not found", "It may be older than the message log keeps, or the link is wrong.")
        : emptyState("alert", "Could not load the conversation", st.detailError.message)}`;
    }
    const d = st.detail;
    if (!d) return html`${backButton()}<p class="faint" style="padding:16px">Loading...</p>`;
    const t = d.thread;
    const { rows, other } = transcript(d.messages, d.errors);
    const [label, tone] = statusChip(t.status);
    const total = t.count || d.messages.length;
    return html`<header class="bus-detail-head">${backButton()}
        <div class="bus-detail-title">
          <h2 id="bus-thread-title" tabindex="-1">${t.private && !t.mine ? html`${icon("lock")} ` : ""}${threadTitle(t, st.dir.names)}</h2>
          <div class="row bus-detail-meta">${badge(label, tone)}${t.errors ? badge(plural(t.errors, "error"), "bad") : ""}
            <span>${t.initiator?.kind === "schedule" ? "Background work, started" : html`Started by <b>${initiatorText(t, st.dir.names)}</b>`}
              <span title="${dateTime(t.started)}">${timeAgo(t.started)}</span></span>
            <span class="faint">${plural(total, "message")}${t.last && t.started ? ` over ${durationOf(t)}` : ""}</span>
            ${t.status === "open" ? html`<span class="bus-working"><span class="pulse-dot" aria-hidden="true"></span>agents at work</span>` : ""}</div>
          <div class="bus-detail-parties">${(t.participants || []).map((p) => party(p, st.dir))}</div>
        </div></header>
      <div class="bus-scroll" id="bus-scroll">
      ${t.private ? html`<p class="notice bus-note">${icon("lock")}<span>${t.mine
        ? "Your chat: only you read your words and the agents' answers to you. Everyone else sees this conversation without them."
        : "A person's private chat: their words, and what the agents quoted of them, are hidden for you."}</span></p>` : ""}
      ${!can("operator") ? html`<p class="notice bus-note">${icon("shield")}<span>Your role reads who asked whom, the status and the errors. Operators and administrators also read the messages.</span></p>` : ""}
      ${d.truncated ? html`<p class="notice warn bus-note">${icon("alert")}<span>A long conversation: the last ${d.messages.length} of its ${t.count} messages are shown.</span></p>` : ""}
        ${rows.length ? html`<ol class="bus-msgs" aria-label="Messages">${rows.map((r) => bubble(r, rows))}</ol>`
          : html`<p class="faint" style="padding:8px 2px">Its messages are not in the log (routine checks are not logged); only its failures are kept.</p>`}
        ${other.length ? html`<div class="bus-other"><h3>${rows.length ? "Other failures in this conversation" : "Failures"}</h3>${other.map((e) => errorView(e, st.dir))}</div>` : ""}
      </div>`;
  }

  const durationOf = (t) => {
    const s = Math.max(0, t.last - t.started);
    return s < 1 ? "under a second" : s < 60 ? `${Math.round(s)} s` : s < 3600 ? `${Math.round(s / 60)} min` : `${Math.round(s / 3600)} h`;
  };
  const backButton = () => html`<button type="button" class="btn sm ghost bus-back" data-act="back">${icon("arrow")}All conversations</button>`;

  function drawDetail({ first = false } = {}) {
    const scroller = detailEl.querySelector("#bus-scroll");
    const atBottom = scroller ? scroller.scrollHeight - scroller.scrollTop - scroller.clientHeight < 40 : false;
    const top = scroller?.scrollTop || 0;
    const active = detailEl.contains(document.activeElement) ? document.activeElement : null;
    const keep = active && (active.dataset.n && active.matches(".bus-msg") ? `.bus-msg[data-n="${active.dataset.n}"]`
      : active.dataset.act ? `[data-act="${active.dataset.act}"]${active.dataset.id ? `[data-id="${CSS.escape(active.dataset.id)}"]` : active.dataset.n ? `[data-n="${active.dataset.n}"]` : ""}`
        : active.matches("summary") ? `details[data-id="${CSS.escape(active.parentElement.dataset.id || "")}"] > summary` : active.id ? `#${CSS.escape(active.id)}` : null);
    setHTML(detailEl, detailView());
    const next = detailEl.querySelector("#bus-scroll");
    if (next) {
      if (first) next.scrollTop = st.detail?.thread?.status === "open" ? next.scrollHeight : 0;
      else next.scrollTop = atBottom ? next.scrollHeight : top;
    }
    if (keep) detailEl.querySelector(keep)?.focus({ preventScroll: true });
  }

  async function loadDetail({ first = false } = {}) {
    const id = st.selected;
    if (!id) return drawDetail();
    const seq = ++st.detailSeq;
    if (first) {
      st.detail = null;
      st.detailError = null;
      drawDetail();
    }
    try {
      const d = await get(`/bus/threads/${enc(id)}`);
      if (seq !== st.detailSeq || !el.isConnected || st.selected !== id) return;
      st.detail = d;
      st.detailError = null;
    } catch (err) {
      if (seq !== st.detailSeq || !el.isConnected || st.selected !== id) return;
      if (!first && err.status !== 404) return; // a failed live refresh keeps what is shown
      st.detail = null;
      st.detailError = err;
    }
    drawDetail({ first });
    if (first && st.detail) {
      const title = threadTitle(st.detail.thread, st.dir.names);
      document.title = `${title} - Agent bus - Atrium`;
      $("#bus-announce").textContent = `Conversation: ${title}, ${plural(st.detail.messages.length, "message")}`;
    }
  }

  function select(id, { push = true, focus = false } = {}) {
    if (!id) return;
    st.selected = id;
    st.open.clear();
    if (push) history.pushState(null, "", busHref(id, st.filters));
    layout.dataset.view = "thread";
    listEl.querySelectorAll(".bus-thread").forEach((a) => {
      const on = a.dataset.thread === id;
      a.classList.toggle("sel", on);
      if (on) a.setAttribute("aria-current", "true"); else a.removeAttribute("aria-current");
    });
    loadDetail({ first: true }).then(() => {
      if (focus || narrow()) detailEl.querySelector("#bus-thread-title")?.focus({ preventScroll: !narrow() });
      if (narrow()) window.scrollTo({ top: 0 });
    });
  }

  function back() {
    const was = st.selected;
    st.selected = null;
    st.detail = null;
    history.pushState(null, "", busHref(null, st.filters));
    document.title = "Agent bus - Atrium";
    layout.dataset.view = "list";
    listEl.querySelectorAll(".bus-thread.sel").forEach((a) => { a.classList.remove("sel"); a.removeAttribute("aria-current"); });
    drawDetail();
    (listEl.querySelector(`[data-thread="${CSS.escape(was || "")}"]`) || form.querySelector("input"))?.focus();
  }

  listEl.addEventListener("click", (e) => {
    const a = e.target.closest("a.bus-thread");
    if (!a || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey || e.button !== 0) return; // a new tab keeps the link's own way
    e.preventDefault();
    select(a.dataset.thread);
  });
  // Up and Down move between conversations
  listEl.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    const links = [...listEl.querySelectorAll("a.bus-thread")];
    const i = links.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    links[Math.max(0, Math.min(links.length - 1, i + (e.key === "ArrowDown" ? 1 : -1)))].focus();
  });
  detailEl.addEventListener("toggle", (e) => {
    const id = e.target.dataset?.id;
    if (!e.target.matches?.("details.bus-body") || !id) return;
    if (e.target.open) st.open.add(id); else st.open.delete(id);
  }, true);

  actions(el, {
    more: (_d, button) => loadMore(button),
    "clear-filters"() {
      for (const name of ["q", "agent", "status"]) form.elements[name].value = "";
      for (const name of ["errors", "mine"]) form.elements[name].checked = false;
      applyFilters();
      form.querySelector("[name=q]").focus();
    },
    back: () => back(),
    jump(d) {
      const target = detailEl.querySelector(`.bus-msg[data-n="${d.n}"]`);
      if (!target) return;
      target.scrollIntoView({ block: "center", behavior: "smooth" });
      target.classList.remove("flash");
      void target.offsetWidth; // restart the highlight
      target.classList.add("flash");
      target.focus({ preventScroll: true });
    },
    async ack(d) {
      try {
        await post(`/agents/${enc(d.agent)}/errors/${enc(d.id)}/ack`);
        await loadDetail();
      } catch (err) { toast(err.message, "bad"); }
    },
  });

  // ---------- live ----------

  const live = $("#bus-live");
  const drawLive = (ok = eventsOk()) => setHTML(live, ok ? html`<span class="pulse-dot ok" aria-hidden="true"></span>Live`
    : html`<span class="dot warn" aria-hidden="true"></span>Live updates paused`);
  // Live events are gathered for LIVE_WAIT before the list or the open conversation is read again (at most once per
  // LIVE_WAIT, never starved by a stream of events); while a search is set, the list at most once per SEARCH_WAIT.
  const timers = { list: null, detail: null };
  const refreshList = () => {
    timers.list = null;
    if (!el.isConnected) return;
    const wait = st.loads.paging ? LIVE_WAIT : st.filters.q.trim() ? SEARCH_WAIT - (Date.now() - st.listAt) : 0;
    if (wait > 0) timers.list = setTimeout(refreshList, wait); // an older page loading: refreshed after it landed
    else loadList();
  };
  const refreshDetail = () => {
    timers.detail = null;
    if (el.isConnected && st.selected) loadDetail();
  };
  const later = (list, detail) => {
    if (list && !timers.list) timers.list = setTimeout(refreshList, LIVE_WAIT);
    if (detail && !timers.detail) timers.detail = setTimeout(refreshDetail, LIVE_WAIT);
  };
  const offEvents = onEvent(["message", "agent_error", "agent_errors_acknowledged", "agent_errors_cleared"], (e) => {
    // a message or failure of the open conversation, or acknowledgements that may cover its failures
    later(true, st.selected && (e.data?.thread === st.selected || e.type === "agent_errors_acknowledged" || e.type === "agent_errors_cleared"));
  });
  const onStatus = (e) => drawLive(e.detail.ok);
  const onReconnect = () => later(true, true);
  window.addEventListener("atrium:events-status", onStatus);
  window.addEventListener("atrium:events-reconnected", onReconnect);
  ctx.onLeave(() => {
    offEvents();
    clearTimeout(timers.list);
    clearTimeout(timers.detail);
    window.removeEventListener("atrium:events-status", onStatus);
    window.removeEventListener("atrium:events-reconnected", onReconnect);
  });

  // ---------- first load ----------

  drawLive();
  st.agents = await get("/agents").catch(() => []); // names and icons first, so nothing is drawn with bare ids
  if (!el.isConnected) return;
  st.dir = directory(st.agents);
  drawAgentFilter();
  drawDetail();
  await Promise.all([loadList({ fresh: true }), st.selected ? loadDetail({ first: true }) : null]);
  if (!el.isConnected || !st.selected) return;
  listEl.querySelector(".bus-thread.sel")?.scrollIntoView({ block: "nearest" }); // a link to a conversation further down the list
  if (narrow()) detailEl.querySelector("#bus-thread-title")?.focus({ preventScroll: true });
}
