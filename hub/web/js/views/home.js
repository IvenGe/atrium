// Home: the dashboards (round4-dashboard-spec.md 10). Tabs of shared and personal dashboards, each a grid of widgets
// whose data the server computes from the stored configuration. People arrange widgets by dragging, with the keyboard
// or from the options menus; personal dashboards save on their own, shared ones are an administrator's draft until
// published. Live updates refetch only the widgets whose events arrived, in one request.
//
// The layout math is js/dashboard/grid.js, the arranging board.js, the renderers widgets.js and charts.js, the widget
// gallery gallery.js and the configure dialog configure.js. Personal dashboards are private: they are never on the
// event stream, so another tab of the same person notices a change when it becomes visible again (or by a 409).
import { del, eventsOk, get, onEvent, post, put } from "../api.js";
import { actions, can, confirmDialog, emptyState, html, icon, modal, raw, setHTML, toast } from "../ui.js";
import { createAiModels } from "../dashboard/aimodels.js";
import { createBoard } from "../dashboard/board.js";
import { defaultTitle, openConfigure } from "../dashboard/configure.js";
import { openGallery } from "../dashboard/gallery.js";
import { COLS, MAX_ROWS, bottom, firstFit, moveInOrder, moveTo, newWidgetId, resizeTo, sizePreset, sortReading, step, validate } from "../dashboard/grid.js";
import { RENDERERS, feedItem, frameHTML, staleChip, toolCard, widgetBody, widgetLink, widgetTitle } from "../dashboard/widgets.js";
import { openImport } from "./tools.js";

export { feedItem, toolCard }; // the People app shows activity entries with feedItem

const ICON_CHOICES = [["home", "Home"], ["grid", "Grid"], ["shield", "Shield"], ["bug", "Bug"], ["box", "Box"], ["contact", "People"],
  ["network", "Network"], ["bot", "Agent"], ["activity", "Activity"], ["flag", "Flag"], ["server", "Server"], ["cloud", "Cloud"],
  ["database", "Data"], ["sliders", "Settings"], ["key", "Key"], ["calendar", "Calendar"]];
const ICON_KEYS = new Set(ICON_CHOICES.map(([k]) => k));
const APP_NAMES = { tools: "Apps", integration: "the Integration hub", agents: "Agents", approvals: "Approvals", operator: "Operator",
  network: "Network", assets: "Assets", people: "People", vulnerabilities: "Vulnerabilities", compliance: "the Compliance hub",
  extensions: "Extensions", settings: "Settings", users: "Users & access", x: "the extension app", portal: "the tool" };
const NOTICE_EVENTS = new Set(["llm_provider", "llm_provider_removed", "llm_selection", "settings"]);
const DEFAULT_LIMITS = { widgets: 40, personal_dashboards: 20, shared_dashboards: 30 };
const TICK = 15000; // periodic refresh and stale checks, only while the page is visible

let page = null; // the Home page on screen, for the command palette
let intent = null; // what the palette asked for before Home was on screen

/** Command palette: "Customize dashboard". */
export function customize() {
  if (page) page.customize();
  else { intent = "customize"; location.hash = "#/"; }
}

/** Command palette: "Add a widget". */
export function addWidget() {
  if (page) page.add();
  else { intent = "add"; location.hash = "#/"; }
}

const strip = ({ id, type, x, y, w, h, title, config }) => ({ id, type, x, y, w, h, title: title ?? null, config: config || {} });
const dataSig = (w) => JSON.stringify([w.type, w.config || {}]);
const contentSig = (w) => JSON.stringify([w.type, w.config || {}, w.title ?? null, w.x, w.y, w.w, w.h]);
const opt = (value, label, selected = false) => html`<option value="${value}" ${selected ? raw("selected") : ""}>${label}</option>`;
const dashIcon = (name) => (ICON_KEYS.has(name) || name === "home" ? name : "grid");
const copyTitle = (title) => `${String(title).slice(0, 52)} (mine)`;

function storage(fn, fallback = null) {
  try { return fn(); } catch { return fallback; }
}

export async function render(el, ctx) {
  const st = {
    list: null, catalog: null, catalogAt: 0, dash: null, items: [], saved: new Map(), published: [], results: new Map(),
    fetchedAt: new Map(), failed: new Set(), requested: new Set(), edit: null, eventsDown: false, gallery: null,
    dead: false, saving: null, saveAgain: false, basedOn: null, loadSeq: 0,
  };
  let board = null;
  let ai = null; // the AI models widgets' drags and dialogs (js/dashboard/aimodels.js)
  let io = null;
  let menu = null;
  let saveTimer = 0;
  const offs = [];
  const part = (name) => el.querySelector(`[data-part="${name}"]`);
  const grid = () => el.querySelector(".dash-grid");
  const article = (id) => grid()?.querySelector(`.widget[data-wid="${CSS.escape(id)}"]`);
  const item = (id) => st.items.find((i) => i.id === id);
  const limits = () => ({ ...DEFAULT_LIMITS, ...(st.list?.limits || {}) });
  const typeOf = (key) => st.catalog?.types.find((t) => t.key === key) || null;
  const titleOf = (inst) => (inst ? (inst.title || inst.default_title || (st.catalog ? defaultTitle(st.catalog, inst) : widgetTitle(inst))) : "Widget");
  const visibleDashes = () => (st.list?.dashboards || []).filter((d) => !d.hidden);
  const summaryOf = (id) => st.list?.dashboards.find((d) => d.id === id) || null;
  const now = () => Date.now() / 1000;

  function announce(text) {
    const live = part("live");
    if (!live) return;
    live.textContent = "";
    setTimeout(() => { live.textContent = text; }, 30);
  }

  setHTML(el, html`
    <div class="hero">
      <div><h1>Your suite</h1><p class="muted">Open-source, closed-source and SaaS tools - integrated, patched and supervised by agents.</p></div>
      <div class="row"><a class="btn" href="#/agents" data-min-role="operator">${icon("chat")}Ask the supervisor</a>
        <button type="button" class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import tool</button></div>
    </div>
    <div data-part="notice"></div>
    <div class="dash-bar">
      <div class="dash-tabs" role="tablist" aria-label="Dashboards" data-part="tabs"></div>
      <span class="badge warn dash-paused" data-part="paused" ${st.eventsDown ? "" : raw("hidden")}>${icon("pause")}Live updates paused</span>
      <div class="dash-bar-actions" data-part="bar"></div>
    </div>
    <div data-part="banner"></div>
    <div data-part="toolbar"></div>
    <div data-part="panel"><div class="dash-loading" aria-hidden="true"></div></div>
    <p class="sr-only" id="dash-move-help">Press Space to pick up. Use the arrow keys to move, Space to drop, Escape to cancel.</p>
    <p class="sr-only" id="dash-resize-help">Press Space to resize. Use the arrow keys to change the size, Space to finish, Escape to cancel.</p>
    <div class="sr-only" aria-live="polite" data-part="live"></div>`);

  ai = createAiModels(el, {
    result: (id) => st.results.get(id),
    refresh: (id) => (item(id) ? fetchData([id]) : Promise.resolve()),
    release: (id, force = true) => updateBody(id, force),
    announce: (text) => announce(text),
  });
  offs.push(() => ai.destroy());

  // ---------- the AI notice (outside the grid: it is not a widget) ----------
  function drawNotice(overview = ctx.state.overview) {
    const llm = overview?.llm;
    setHTML(part("notice"), llm && llm.available === false ? html`<div class="notice dash-notice">${icon("bot")}<div><b>Agents run in rules mode.</b>
      <span class="muted">Everything works, but no AI model provider is set up. An administrator can add Claude, OpenAI or a local model in Settings &gt; AI models.</span>
      <a href="#/settings/ai" data-min-role="admin">Open the AI model settings</a></div></div>` : "");
  }

  // ---------- tabs and the dashboard bar ----------
  function drawTabs() {
    const tabs = visibleDashes();
    const current = st.dash?.id;
    const focusedTab = document.activeElement?.closest?.(".dash-tab")?.dataset.tab;
    setHTML(part("tabs"), tabs.map((d) => html`<button type="button" role="tab" class="dash-tab" id="dash-tab-${d.id}" data-tab="${d.id}"
        aria-selected="${d.id === current ? "true" : "false"}" aria-controls="dash-panel" tabindex="${d.id === current || (!current && d === tabs[0]) ? 0 : -1}">
        ${icon(dashIcon(d.icon))}<span>${d.title}</span>${d.id === st.list.home_id ? html`<span class="sr-only">, your home</span>` : ""}${d.scope === "shared" ? html`<span class="dash-tag">Shared</span>` : ""}</button>`));
    if (focusedTab) el.querySelector(`.dash-tab[data-tab="${CSS.escape(focusedTab)}"]`)?.focus({ preventScroll: true });
    el.querySelector('.dash-tab[aria-selected="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }

  function drawBar() {
    const d = st.dash;
    const label = d?.scope === "shared" && d.editable ? "Edit shared dashboard" : "Customize";
    setHTML(part("bar"), html`
      <button type="button" class="icon-btn sm" data-act="d-new" aria-label="New dashboard" title="New dashboard">${icon("plus")}</button>
      ${d && !st.edit ? html`<button type="button" class="btn sm" data-act="d-customize">${icon("edit")}${label}</button>` : ""}
      ${st.list ? html`<button type="button" class="icon-btn sm" data-act="d-menu" aria-label="Dashboard options" title="Dashboard options" aria-haspopup="true" aria-expanded="false">${icon("more")}</button>` : ""}`);
  }

  function drawBanner(content = "") {
    setHTML(part("banner"), content);
  }

  // ---------- the edit toolbar ----------
  function unpublished() {
    if (!st.edit || st.dash?.scope !== "shared") return 0;
    const pub = new Map(st.published.map((w) => [w.id, contentSig(w)]));
    let n = st.items.filter((w) => pub.get(w.id) !== contentSig(w)).length;
    n += st.published.filter((w) => !st.items.some((i) => i.id === w.id)).length;
    const meta = st.edit.meta;
    if (meta && (meta.title !== st.edit.publishedMeta.title || meta.icon !== st.edit.publishedMeta.icon || meta.description !== st.edit.publishedMeta.description)) n += 1;
    return n;
  }

  function saveStatus() {
    const e = st.edit;
    if (st.dash.scope === "shared") {
      const n = unpublished();
      return n ? html`<span class="dash-save warn">${icon("edit")}Unpublished changes (${n})</span>` : html`<span class="dash-save">No unpublished changes</span>`;
    }
    if (e.status === "error") return html`<span class="dash-save bad">${icon("alert")}Not saved</span><button type="button" class="btn sm" data-act="e-retry">Retry</button>`;
    return html`<span class="dash-save">${e.status === "saving" || e.status === "pending" ? "Saving..." : html`${icon("check")}Saved`}</span>`;
  }

  function drawToolbar() {
    const e = st.edit;
    const holder = part("toolbar");
    if (!e) { setHTML(holder, ""); return; }
    const focused = document.activeElement?.closest?.(".dash-toolbar [data-act]")?.dataset.act;
    const shared = st.dash.scope === "shared";
    const full = st.items.length >= limits().widgets;
    const n = unpublished();
    setHTML(holder, html`<div class="dash-toolbar" role="group" aria-label="Edit the dashboard ${st.dash.title}">
      <button type="button" class="btn sm primary" data-act="e-add" ${full ? raw('aria-disabled="true"') : ""}>${icon("plus")}Add widget</button>
      <button type="button" class="btn sm" data-act="e-undo" aria-keyshortcuts="Control+Z" ${e.undo.length ? "" : raw("disabled")}>${icon("undo")}Undo</button>
      <button type="button" class="btn sm" data-act="e-redo" aria-keyshortcuts="Control+Shift+Z" ${e.redo.length ? "" : raw("disabled")}>${icon("undo", "flip")}Redo</button>
      ${resetChoices().length ? html`<button type="button" class="btn sm" data-act="e-reset">${icon("refresh")}Reset...</button>` : ""}
      <span class="spacer"></span>
      ${full ? html`<span class="faint dash-small">${limits().widgets} widgets: the maximum</span>` : ""}
      ${saveStatus()}
      ${shared ? html`<button type="button" class="btn sm" data-act="e-discard" ${n ? "" : raw("disabled")}>Discard</button>
        <button type="button" class="btn sm primary" data-act="e-publish" ${n ? "" : raw("disabled")}>${icon("upload")}Publish</button>` : ""}
      <button type="button" class="btn sm" data-act="e-done">${icon("check")}Done</button></div>`);
    if (focused) {
      const again = holder.querySelector(`[data-act="${focused}"]:not(:disabled)`)
        || holder.querySelector(focused === "e-undo" ? '[data-act="e-redo"]:not(:disabled)' : '[data-act="e-undo"]:not(:disabled)')
        || holder.querySelector('[data-act="e-add"]');
      again?.focus({ preventScroll: true });
    }
  }

  // ---------- the grid and the widget bodies ----------
  const frameSig = (inst) => JSON.stringify([inst.type, titleOf(inst), Boolean(st.edit)]);
  const tableOn = (id) => storage(() => localStorage.getItem(`hub.dash.table.${id}`) === "1", false);
  const bodyCtx = (id) => ({ editing: Boolean(st.edit), editable: Boolean(st.dash?.editable), table: tableOn(id), now: now(),
    stack: board?.mode() === "stack", // stack mode: one column, so wide widgets render their narrow form (lists as cards)
    admin: can("admin") }); // edit affordances of widgets that change settings (AI models); the server checks the role

  function frameEl(inst) {
    const holder = document.createElement("div");
    setHTML(holder, frameHTML(inst, { title: titleOf(inst), editing: Boolean(st.edit) }));
    const a = holder.firstElementChild;
    a.dataset.sig = frameSig(inst);
    return a;
  }

  function emptyPanel() {
    const d = st.dash;
    if (st.items.length) return "";
    if (st.edit) return html`<p class="muted dash-edit-empty">This dashboard is empty. Use <b>Add widget</b>${board?.mode() === "grid" ? ", or drag a card from the widget gallery onto the grid" : ""}.</p>`;
    if (d.editable) {
      return emptyState("grid", "This dashboard is empty", "Add widgets from your tools and the hub apps.",
        html`<button type="button" class="btn primary" data-act="e-add">${icon("plus")}Add widget</button>`);
    }
    return emptyState("grid", "This dashboard is empty", "An administrator has not added widgets yet.",
      html`<button type="button" class="btn" data-act="d-copy">${icon("copy")}Make a personal copy</button>`);
  }

  function drawPanel() {
    board?.destroy();
    board = null;
    io?.disconnect();
    const d = st.dash;
    const panel = part("panel");
    setHTML(panel, html`${d.hidden_widgets ? html`<p class="faint dash-small dash-hidden-note">${icon("lock")}${d.hidden_widgets === 1 ? "1 widget needs" : `${d.hidden_widgets} widgets need`} a higher role and ${d.hidden_widgets === 1 ? "is" : "are"} not shown.</p>` : ""}
      <section class="dash-grid ${st.edit ? "editing" : ""}" id="dash-panel" role="tabpanel" aria-labelledby="dash-tab-${d.id}" aria-label="Dashboard: ${d.title}"></section>
      <div data-part="empty"></div>`);
    const section = panel.querySelector(".dash-grid");
    for (const inst of st.items) section.append(frameEl(inst));
    board = createBoard(section, {
      items: () => st.items,
      size: (id) => typeOf(item(id)?.type)?.size || null,
      title: (id) => titleOf(item(id)),
      editing: () => Boolean(st.edit),
      commit: (next, info) => { if (board?.mode() === "stack") stackNote(); commit(next, info); },
      announce,
      modeChanged: () => { setHTML(part("empty"), emptyPanel()); st.items.forEach((i) => updateBody(i.id)); },
    });
    board.place(st.items);
    board.sortDom(st.items);
    setHTML(part("empty"), emptyPanel());
    st.items.forEach((i) => updateBody(i.id, true));
    io = new IntersectionObserver((entries) => {
      const ids = entries.filter((x) => x.isIntersecting).map((x) => x.target.dataset.wid).filter((id) => !st.results.has(id) && !st.requested.has(id));
      if (ids.length) fetchData(ids);
    }, { rootMargin: "200px 0px" }); // UNVERIFIED: the margin defers widgets below the fold until they are near
    section.querySelectorAll(".widget").forEach((a) => io.observe(a));
  }

  /** Re-renders a widget's body (only when its data version, table view or mode changed), keeping the focus. */
  function updateBody(id, force = false) {
    const a = article(id);
    const inst = item(id);
    if (!a || !inst || ai?.holding(id)) return; // an AI models widget holds new data while a chip is moved (10.17)
    const res = st.results.get(id);
    const body = a.querySelector('[data-part="body"]');
    const key = `${res?.version ?? "-"}|${res?.status ?? "-"}|${tableOn(id)}|${Boolean(st.edit)}|${board?.mode()}`;
    if (force || body.dataset.v !== key) {
      const restore = keepFocus(body, a);
      setHTML(body, widgetBody(res, inst, bodyCtx(id)));
      body.dataset.v = key;
      setHTML(a.querySelector('[data-part="link"]'), widgetLink(res, inst));
      restore();
    }
    updateStatus(id);
  }

  /** Before a body is replaced: a function that puts the focus back on the same control (or on the widget heading). */
  function keepFocus(body, a) {
    const active = document.activeElement;
    if (!active || !body.contains(active)) return () => {};
    const sel = active.getAttribute("href") ? `a[href="${CSS.escape(active.getAttribute("href"))}"]`
      : active.dataset?.act ? `[data-act="${CSS.escape(active.dataset.act)}"]${active.dataset.id ? `[data-id="${CSS.escape(active.dataset.id)}"]` : ""}` : null;
    return () => (sel && body.querySelector(sel) || a.querySelector("h3"))?.focus({ preventScroll: true });
  }

  function updateStatus(id) {
    const a = article(id);
    if (!a) return;
    const res = st.results.get(id);
    const stale = (st.eventsDown || st.failed.has(id)) ? staleChip(res, item(id), now()) : "";
    const holder = a.querySelector('[data-part="status"]');
    if (holder.dataset.v !== String(stale)) {
      setHTML(holder, stale);
      holder.dataset.v = String(stale);
    }
  }

  /** Brings the frames in line with st.items after a change: removed ones go, new ones come, changed titles or types are
   *  re-rendered, and widgets whose type or config changed get their data again. */
  function syncFrames(before = new Map()) {
    const section = grid();
    if (!section || !board) return drawPanel();
    const ids = new Set(st.items.map((i) => i.id));
    section.querySelectorAll(":scope > .widget").forEach((a) => {
      if (!ids.has(a.dataset.wid)) { io?.unobserve(a); a.remove(); }
    });
    const refetch = [];
    for (const inst of st.items) {
      let a = article(inst.id);
      const old = before.get(inst.id);
      const changedData = old && dataSig(old) !== dataSig(inst);
      if (changedData) st.results.delete(inst.id);
      if (!a || a.dataset.sig !== frameSig(inst)) {
        const fresh = frameEl(inst);
        if (a) { io?.unobserve(a); a.replaceWith(fresh); } else section.append(fresh);
        a = fresh;
        io?.observe(a);
        updateBody(inst.id, true);
      } else if (changedData) updateBody(inst.id, true);
      if (!st.results.has(inst.id) && (changedData || !old)) refetch.push(inst.id);
    }
    board.place(st.items);
    board.sortDom(st.items);
    setHTML(part("empty"), emptyPanel());
    if (refetch.length) fetchData(refetch);
  }

  // ---------- data ----------
  /** Fetches widget data: stored, unchanged widgets in batches of at most 40 from the dashboard's data route, the
   *  others (added or reconfigured but not saved yet, a shared draft) one by one through the preview route. */
  async function fetchData(ids) {
    const d = st.dash;
    if (!d || st.dead) return;
    ids = [...new Set(ids)].filter((id) => item(id));
    if (!ids.length) return;
    ids.forEach((id) => st.requested.add(id));
    const sigs = new Map(ids.map((id) => [id, dataSig(item(id))]));
    const stored = ids.filter((id) => st.saved.get(id) === sigs.get(id));
    const local = ids.filter((id) => !stored.includes(id));
    const apply = (id, res) => {
      if (st.dead || st.dash?.id !== d.id || !item(id) || dataSig(item(id)) !== sigs.get(id)) return;
      st.results.set(id, res);
      st.fetchedAt.set(id, now());
      st.failed.delete(id);
      updateBody(id);
    };
    const failed = (id, message) => {
      if (st.dead || st.dash?.id !== d.id || !item(id)) return;
      st.failed.add(id);
      if (!st.results.has(id)) apply(id, { status: "error", data: null, message, version: "err", generated_at: now(), stale_after: now() });
      else updateStatus(id);
    };
    const jobs = [];
    for (let i = 0; i < stored.length; i += limits().widgets_per_request || 40) {
      const chunk = stored.slice(i, i + (limits().widgets_per_request || 40));
      jobs.push(get(`/dashboards/${encodeURIComponent(d.id)}/data?widgets=${chunk.join(",")}`).then((r) => {
        for (const id of chunk) {
          if (r.widgets[id]) apply(id, r.widgets[id]);
          else failed(id, "This widget is not on the saved dashboard.");
        }
      }).catch((err) => chunk.forEach((id) => failed(id, err.message))));
    }
    for (const id of local) {
      const inst = item(id);
      jobs.push(get(`/widgets/preview?type=${encodeURIComponent(inst.type)}&config=${encodeURIComponent(JSON.stringify(inst.config || {}))}`)
        .then((res) => apply(id, res))
        .catch((err) => apply(id, { status: err.status === 403 ? "forbidden" : "error", data: null, message: err.message, version: `e${err.status}`, generated_at: now(), stale_after: now() + 60 })));
    }
    await Promise.all(jobs);
    ids.forEach((id) => st.requested.delete(id));
  }

  const eventsOf = (inst) => st.results.get(inst.id)?.events || inst.events || typeOf(inst.type)?.events || [];
  const pending = new Set();
  let flushTimer = 0;
  function flushEvents() {
    flushTimer = 0;
    const types = new Set(pending);
    pending.clear();
    if (!st.dash || document.visibilityState === "hidden") { if (st.dash) st.hiddenEvents = true; return; }
    const ids = st.items.filter((i) => st.results.has(i.id) && eventsOf(i).some((t) => types.has(t))).map((i) => i.id);
    if (ids.length) fetchData(ids);
  }
  offs.push(onEvent("*", (e) => {
    if (st.dead) return;
    if (e.type === "dashboard") return onDashboardEvent(e.data || {});
    if (e.type === "dashboard_settings") return refreshList();
    if (NOTICE_EVENTS.has(e.type)) refreshNotice();
    pending.add(e.type);
    if (!flushTimer) flushTimer = setTimeout(flushEvents, 800); // at most one batched request per 0.8 s, never starved
  }));
  offs.push(() => clearTimeout(flushTimer));

  let noticeTimer = 0;
  function refreshNotice() {
    clearTimeout(noticeTimer);
    noticeTimer = setTimeout(() => get("/overview").then((ov) => { if (!st.dead) drawNotice(ov); }).catch(() => {}), 1000);
  }

  const tick = setInterval(() => {
    if (st.dead || !st.dash || document.visibilityState !== "visible") return;
    if (st.eventsDown === eventsOk()) onStatus({ detail: { ok: eventsOk() } });
    const t = now();
    const due = st.items.filter((i) => {
      const r = st.results.get(i.id);
      const at = st.fetchedAt.get(i.id);
      return r?.refresh && at && t - at >= r.refresh; // UNVERIFIED: Page Visibility keeps background tabs quiet
    }).map((i) => i.id);
    if (due.length) fetchData(due);
    st.items.forEach((i) => updateStatus(i.id));
  }, TICK);
  offs.push(() => clearInterval(tick));

  const onReconnected = () => {
    if (st.dead || !st.dash) return;
    fetchData(st.items.filter((i) => st.results.has(i.id)).map((i) => i.id));
    refreshList();
  };
  const onStatus = (e) => {
    st.eventsDown = !e.detail?.ok;
    const chip = part("paused");
    if (chip) chip.hidden = !st.eventsDown;
    st.items.forEach((i) => updateStatus(i.id));
  };
  const onVisible = () => {
    if (document.visibilityState !== "visible" || st.dead) return;
    refreshList();
    if (st.hiddenEvents) { st.hiddenEvents = false; onReconnected(); }
  };
  // the stream may still be connecting while the page renders: the chip shows only if it is still down a moment later
  const firstCheck = setTimeout(() => { if (!st.dead && !eventsOk()) onStatus({ detail: { ok: false } }); }, 5000);
  offs.push(() => clearTimeout(firstCheck));
  window.addEventListener("atrium:events-reconnected", onReconnected);
  window.addEventListener("atrium:events-status", onStatus);
  document.addEventListener("visibilitychange", onVisible);
  offs.push(() => {
    window.removeEventListener("atrium:events-reconnected", onReconnected);
    window.removeEventListener("atrium:events-status", onStatus);
    document.removeEventListener("visibilitychange", onVisible);
  });

  // ---------- loading dashboards ----------
  async function loadList() {
    st.list = await get("/dashboards");
  }

  let listBusy = null, listAgain = false;
  async function refreshList() {
    if (listBusy) { listAgain = true; return listBusy; }
    listBusy = (async () => {
      const list = await get("/dashboards").catch(() => null);
      if (!list || st.dead) return;
      st.list = list;
      drawTabs();
      drawBar();
      const cur = list.dashboards.find((x) => x.id === st.dash?.id);
      if (st.dash && !cur) {
        if (!st.edit) {
          toast(`The dashboard ${st.dash.title} was deleted`, "warn");
          await openDash(list.home_id, { push: true });
        }
      } else if (cur && st.dash && cur.version > st.dash.version && !st.edit && !board?.busy()) {
        await reloadDash({ quiet: true, actor: cur.updated_by });
      }
    })();
    try { await listBusy; } finally {
      listBusy = null;
      if (listAgain) { listAgain = false; refreshList(); }
    }
  }

  async function ensureCatalog(force = false) {
    if (!st.catalog || force || now() - st.catalogAt > 30) {
      st.catalog = await get("/widgets/catalog");
      st.catalogAt = now();
    }
    return st.catalog;
  }

  function setDash(d) {
    st.dash = d;
    st.items = sortReading(d.widgets.map((w) => ({ ...w })));
    st.saved = new Map(d.widgets.map((w) => [w.id, dataSig(w)]));
    st.published = d.scope === "shared" ? d.widgets.map(strip) : [];
    st.basedOn = null;
    drawTabs();
    drawBar();
    drawPanel();
    offerDraft();
    document.title = d.id === st.list?.home_id || !location.hash.startsWith("#/d/") ? "Home - Atrium" : `${d.title} - Atrium`;
  }

  /** Opens a dashboard tab; push: put #/d/<id> in the address (without reloading the page). */
  async function openDash(id, { push = false, focusTab = false } = {}) {
    if (st.edit && !(await leaveEdit({ reason: "switch" }))) return false;
    closeMenu();
    st.gallery?.close();
    const seq = ++st.loadSeq;
    if (push && id) history.pushState(null, "", id === st.list?.home_id && !location.hash.startsWith("#/d/") ? "#/" : `#/d/${encodeURIComponent(id)}`);
    st.results.clear();
    st.fetchedAt.clear();
    st.failed.clear();
    st.requested.clear();
    drawBanner();
    if (!id) {
      st.dash = null;
      st.items = [];
      board?.destroy();
      board = null;
      drawTabs();
      drawBar();
      const hidden = (st.list?.dashboards || []).filter((d) => d.hidden).length;
      setHTML(part("panel"), emptyState("home", "No dashboard yet", "Create one to arrange widgets for the tools you use.",
        html`<button type="button" class="btn primary" data-act="d-new">${icon("plus")}New dashboard</button>
          ${hidden ? html` <button type="button" class="btn" data-act="d-unhide">Show hidden dashboards (${hidden})</button>` : ""}`));
      return true;
    }
    try {
      const d = await get(`/dashboards/${encodeURIComponent(id)}`);
      if (seq !== st.loadSeq || st.dead) return false;
      setDash(d);
      if (focusTab) el.querySelector(`.dash-tab[data-tab="${CSS.escape(id)}"]`)?.focus();
      return true;
    } catch (err) {
      if (seq !== st.loadSeq || st.dead) return false;
      st.dash = null;
      st.items = [];
      drawTabs();
      drawBar();
      setHTML(part("panel"), emptyState("alert", "Could not load the dashboard", err.message,
        html`<button type="button" class="btn" data-act="d-retry" data-id="${id}">${icon("refresh")}Retry</button>`));
      return false;
    }
  }

  /** Loads the open dashboard again (another admin published it, another tab of yours saved it), keeping the focus. */
  async function reloadDash({ quiet = false, actor = null } = {}) {
    const d = st.dash;
    if (!d) return;
    const active = document.activeElement;
    const wid = active?.closest?.(".widget")?.dataset.wid;
    const sel = active?.dataset?.act ? `[data-act="${CSS.escape(active.dataset.act)}"]` : active?.getAttribute?.("href") ? `a[href="${CSS.escape(active.getAttribute("href"))}"]` : null;
    let fresh;
    try { fresh = await get(`/dashboards/${encodeURIComponent(d.id)}`); } catch { return; }
    if (st.dead || st.dash?.id !== d.id) return;
    const keep = new Map(st.items.map((i) => [i.id, dataSig(i)]));
    const results = new Map([...st.results].filter(([id]) => fresh.widgets.some((w) => w.id === id && dataSig(w) === keep.get(id))));
    st.results = results;
    setDash(fresh);
    if (wid && article(wid)) (sel && article(wid).querySelector(sel) || article(wid).querySelector("h3"))?.focus({ preventScroll: true });
    if (quiet && actor) announce(`Dashboard updated by ${actor}`);
  }

  function onDashboardEvent(data) {
    if (data.id && data.id === st.dash?.id && st.dash.scope === "shared") {
      if (data.removed) { refreshList(); return; }
      if (st.edit && data.version > (st.edit.base ?? st.dash.version)) {
        drawBanner(html`<div class="notice warn dash-banner">${icon("alert")}<div class="grow"><b>${data.updated_by || "An administrator"} published a newer version.</b>
          <span class="muted">Your draft is based on version ${st.edit.base}.</span></div>
          <button type="button" class="btn sm" data-act="b-reload">Reload (lose draft)</button>
          <button type="button" class="btn sm" data-act="b-keep">Keep editing</button></div>`);
        return;
      }
    }
    refreshList();
  }

  // ---------- shared drafts kept in this browser tab ----------
  const draftKey = (id) => `hub.dash.draft.${id}`;
  function saveDraft() {
    if (!st.edit || st.dash?.scope !== "shared") return;
    const meta = st.edit.meta || {};
    storage(() => sessionStorage.setItem(draftKey(st.dash.id), JSON.stringify({ base_version: st.edit.base, widgets: st.items.map(strip), ...meta })));
  }
  const clearDraft = (id) => storage(() => sessionStorage.removeItem(draftKey(id)));
  const readDraft = (id) => storage(() => JSON.parse(sessionStorage.getItem(draftKey(id)) || "null"));

  function offerDraft() {
    const d = st.dash;
    const draft = d.scope === "shared" && d.editable && !st.edit ? readDraft(d.id) : null;
    if (!draft) return;
    drawBanner(html`<div class="notice dash-banner">${icon("edit")}<div class="grow"><b>You have unpublished changes to ${d.title}.</b>
      <span class="muted">They are kept in this browser tab${draft.base_version !== d.version ? ` and based on version ${draft.base_version} (now ${d.version})` : ""}.</span></div>
      <button type="button" class="btn sm primary" data-act="b-restore">Restore and edit</button>
      <button type="button" class="btn sm" data-act="b-forget">Discard them</button></div>`);
  }

  // ---------- edit mode ----------
  function resetChoices() {
    const d = st.dash;
    if (!d) return [];
    const out = [];
    if (d.scope === "personal" && d.based_on && summaryOf(d.based_on)) out.push(["shared", "Reset to the shared version", `Replace the widgets with those of ${summaryOf(d.based_on).title} as it is now.`]);
    if (d.template && st.catalog?.templates.some((t) => t.key === d.template)) out.push(["template", "Reset to template", `Replace the widgets with the "${st.catalog.templates.find((t) => t.key === d.template).title}" template.`]);
    return out;
  }

  async function enterEdit() {
    const d = st.dash;
    if (!d) return false;
    if (st.edit) return true;
    if (!d.editable) { await customizeCopy(); return Boolean(st.edit); }
    try { await ensureCatalog(); } catch (err) { toast(err.message, "bad"); return false; }
    if (st.dead || st.dash !== d) return false;
    const meta = { title: d.title, icon: d.icon, description: d.description || "" };
    st.edit = { undo: [], redo: [], status: "saved", error: null, base: d.version, meta: { ...meta }, publishedMeta: meta };
    drawBanner();
    drawBar();
    drawToolbar();
    drawPanel();
    window.addEventListener("beforeunload", onBeforeUnload);
    part("toolbar").querySelector('[data-act="e-add"]')?.focus();
    announce(d.scope === "shared" ? `Editing the shared dashboard ${d.title}. Changes are a draft until you publish them.`
      : `Editing ${d.title}. Changes are saved automatically.`);
    return true;
  }

  function unsaved() {
    if (!st.edit) return false;
    return st.dash.scope === "shared" ? unpublished() > 0 : Boolean(saveTimer || st.saving || st.edit.status === "error");
  }
  function onBeforeUnload(e) {
    if (unsaved()) { e.preventDefault(); e.returnValue = ""; }
  }

  /** A dialog with several choices: resolves with the chosen key, or null. */
  function choose(title, text, buttons) {
    return new Promise((resolve) => {
      let picked = null;
      const m = modal({
        title, body: html`<p>${text}</p>`, submit: null, cancel: null,
        footer: html`<button type="button" class="btn" data-close>Cancel</button>${buttons.map(([key, label, primary]) => html`<button type="button" class="btn ${primary ? "primary" : ""}" data-choice="${key}">${label}</button>`)}`,
        onClose: () => resolve(picked),
      });
      m.el.addEventListener("click", (e) => {
        const b = e.target.closest("[data-choice]");
        if (!b) return;
        picked = b.dataset.choice;
        m.close();
      });
    });
  }

  /** Leaves edit mode: a personal dashboard saves what is pending; a shared draft with changes asks what to do. */
  async function leaveEdit({ reason = "done" } = {}) {
    if (!st.edit) return true;
    board?.cancel(true);
    closeMenu();
    const d = st.dash;
    if (d.scope === "personal") {
      if (saveTimer || st.saving) await saveNow();
      if (st.edit?.status === "error" && !(await confirmDialog("Leave without saving?",
        `Your last changes to ${d.title} could not be saved: ${st.edit.error}`, "Leave without saving"))) return false;
    } else if (unpublished()) {
      const choice = await choose("Unpublished changes", reason === "done"
        ? `Publish your changes to ${d.title} for everyone, or discard them?`
        : `Publish your changes to ${d.title} now, or keep them as a draft in this browser tab?`,
      reason === "done" ? [["discard", "Discard changes"], ["publish", "Publish", true]] : [["keep", "Keep as draft"], ["publish", "Publish", true]]);
      if (!choice) return false;
      if (choice === "publish" && !(await publish())) return false;
      if (choice === "discard") clearDraft(d.id);
      if (choice === "discard" && !st.dead) {
        st.edit = null;
        window.removeEventListener("beforeunload", onBeforeUnload);
        drawToolbar();
        await reloadDash();
        return true;
      }
    }
    if (!st.edit) return true;
    st.edit = null;
    window.removeEventListener("beforeunload", onBeforeUnload);
    st.gallery?.close();
    drawToolbar();
    drawBar();
    drawPanel();
    return true;
  }

  function commit(next, { id = null, message = "" } = {}) {
    if (!st.edit) return;
    const problems = validate(next, COLS, MAX_ROWS);
    if (problems.length) { announce("There is no room for that"); board?.place(st.items); return; }
    st.edit.undo.push(st.items);
    if (st.edit.undo.length > 50) st.edit.undo.shift();
    st.edit.redo = [];
    setItems(next);
    if (message) announce(message);
    if (id) focusHandle(id);
  }

  function setItems(next) {
    const before = new Map(st.items.map((i) => [i.id, i]));
    st.items = sortReading(next);
    syncFrames(before);
    changed();
  }

  function changed() {
    if (!st.edit) return;
    if (st.dash.scope === "personal") queueSave();
    else saveDraft();
    drawToolbar();
    st.gallery?.setFull(st.items.length >= limits().widgets);
  }

  function undo() {
    if (!st.edit?.undo.length) return announce("Nothing to undo");
    st.edit.redo.push(st.items);
    setItems(st.edit.undo.pop());
    announce("Undone");
  }
  function redo() {
    if (!st.edit?.redo.length) return announce("Nothing to redo");
    st.edit.undo.push(st.items);
    setItems(st.edit.redo.pop());
    announce("Redone");
  }

  /** Whether the open gallery drawer covers a control: it is fixed on the right over the whole height, so a control
   *  below its left edge is hidden however the page scrolls. */
  function underDrawer(node) {
    const drawer = el.querySelector(".dash-drawer");
    if (!drawer || !node) return false;
    const a = node.getBoundingClientRect(), b = drawer.getBoundingClientRect();
    return a.right > b.left && a.left < b.right;
  }

  function focusHandle(id, { scroll = false } = {}) {
    const a = article(id);
    if (!a) return;
    const target = a.querySelector(".dash-handle") || a.querySelector("h3");
    if (scroll) a.scrollIntoView({ block: "nearest" });
    // a widget added under the open gallery drawer: the focus stays in the drawer rather than on a hidden handle
    // (WCAG 2.4.11); the announcement says where the widget went
    if (underDrawer(target)) return;
    target?.focus({ preventScroll: true });
  }

  // ---------- saving ----------
  function docBody(base) {
    const meta = st.edit?.meta || { title: st.dash.title, icon: st.dash.icon, description: st.dash.description || "" };
    return { title: meta.title, icon: meta.icon, description: meta.description || "", widgets: st.items.map(strip), base_version: base };
  }

  /** The server's view of a saved dashboard: its version and the widgets' availability, default titles and events
   *  (local changes made while the request ran are kept). */
  function adopt(view) {
    const prev = st.dash;
    st.dash = view;
    st.saved = new Map(view.widgets.map((w) => [w.id, dataSig(w)]));
    if (view.scope === "shared") st.published = view.widgets.map(strip);
    const server = new Map(view.widgets.map((w) => [w.id, w]));
    st.items = st.items.map((i) => {
      const s = server.get(i.id);
      return s && dataSig(s) === dataSig(i)
        ? { ...i, available: s.available, reason: s.reason, min_role: s.min_role, default_title: s.default_title, events: s.events } : i;
    });
    if (prev && (prev.title !== view.title || prev.icon !== view.icon)) refreshList();
    syncFrames(new Map(st.items.map((i) => [i.id, i])));
  }

  function setSave(status, error = null) {
    if (!st.edit) return;
    st.edit.status = status;
    st.edit.error = error;
    drawToolbar();
  }

  function queueSave() {
    setSave("pending");
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => saveNow(), 800);
  }

  async function saveOnce(id) {
    setSave("saving");
    try {
      const body = docBody(st.dash.version);
      if (st.basedOn) body.based_on_version = st.basedOn;
      const view = await put(`/dashboards/mine/${encodeURIComponent(id)}`, body);
      st.basedOn = null;
      if (st.dead || st.dash?.id !== id) return;
      adopt(view);
      setSave("saved");
    } catch (err) {
      if (st.dead || st.dash?.id !== id) return;
      if (err.status === 409 && err.code === "version_conflict") await saveConflict();
      else {
        setSave("error", err.message);
        if (err.status !== 401) toast(err.message, "bad");
      }
    }
  }

  /** Saves a personal dashboard now (debounced saves land here): one request at a time, later changes in one more. */
  async function saveNow() {
    clearTimeout(saveTimer);
    saveTimer = 0;
    if (!st.dash || st.dash.scope !== "personal") return;
    if (st.saving) { st.saveAgain = true; return st.saving; }
    const id = st.dash.id;
    st.saving = (async () => {
      do {
        st.saveAgain = false;
        await saveOnce(id);
      } while (st.saveAgain && !st.dead && st.dash?.id === id);
    })();
    try { await st.saving; } finally { st.saving = null; }
  }

  async function saveConflict() {
    setSave("error", "This dashboard changed in another window");
    const choice = await choose("This dashboard changed in another window",
      "Reload it (your last change is dropped), or keep your version and save it over the other one?",
      [["reload", "Reload"], ["mine", "Keep mine", true]]);
    if (st.dead) return;
    if (choice === "reload") {
      if (st.edit) { st.edit.undo = []; st.edit.redo = []; st.edit.status = "saved"; }
      await reloadDash();
      drawToolbar();
    } else if (choice === "mine") {
      const current = await get(`/dashboards/${encodeURIComponent(st.dash.id)}`).catch(() => null);
      if (!current) return;
      st.dash = { ...st.dash, version: current.version };
      queueSave();
    }
  }

  async function publish() {
    const d = st.dash;
    try {
      const view = await put(`/dashboards/shared/${encodeURIComponent(d.id)}`, docBody(st.edit.base));
      if (st.dead) return true;
      st.edit.base = view.version;
      st.edit.meta = { title: view.title, icon: view.icon, description: view.description || "" };
      st.edit.publishedMeta = { ...st.edit.meta };
      adopt(view);
      clearDraft(d.id);
      drawBanner();
      drawToolbar();
      toast(`Published ${view.title}`, "ok");
      announce(`Published ${view.title} for everyone`);
      return true;
    } catch (err) {
      if (err.status === 409 && err.code === "version_conflict") {
        const choice = await choose("A newer version was published", `Someone published ${d.title} while you were editing. Reload it (your draft is dropped), or publish your version over it?`,
          [["reload", "Reload (lose draft)"], ["mine", "Publish mine", true]]);
        if (choice === "reload") { clearDraft(d.id); st.edit = null; drawToolbar(); await reloadDash(); return true; }
        if (choice === "mine") {
          const current = await get(`/dashboards/${encodeURIComponent(d.id)}`).catch(() => null);
          if (!current) return false;
          st.edit.base = current.version;
          return publish();
        }
        return false;
      }
      toast(err.message, "bad");
      return false;
    }
  }

  async function discard() {
    const d = st.dash;
    if (!(await confirmDialog("Discard your changes?", `Your unpublished changes to ${d.title} are dropped and the published version is shown again.`, "Discard changes"))) return;
    clearDraft(d.id);
    const fresh = await get(`/dashboards/${encodeURIComponent(d.id)}`).catch((err) => { toast(err.message, "bad"); return null; });
    if (!fresh || st.dead) return;
    const meta = { title: fresh.title, icon: fresh.icon, description: fresh.description || "" };
    st.edit = { undo: [], redo: [], status: "saved", error: null, base: fresh.version, meta: { ...meta }, publishedMeta: meta };
    setDash(fresh);
    drawToolbar();
    drawBanner();
    announce("Changes discarded");
  }

  async function reset() {
    const choices = resetChoices();
    if (!choices.length) return;
    const picked = await new Promise((resolve) => {
      modal({
        title: "Reset this dashboard", submit: "Reset",
        body: html`<p class="muted" style="margin-bottom:10px">You can undo a reset until you leave edit mode.</p>
          ${choices.map(([key, label, text], n) => html`<label class="radio-card"><input type="radio" name="what" value="${key}" ${n ? "" : raw("checked")}>
            <div><b>${label}</b><p class="muted">${text}</p></div></label>`)}`,
        onSubmit: (fd) => { resolve(fd.get("what")); },
        onClose: () => resolve(null),
      });
    });
    if (!picked) return;
    try {
      let widgets, basedOn = null;
      if (picked === "shared") {
        const shared = await get(`/dashboards/${encodeURIComponent(st.dash.based_on)}`);
        widgets = shared.widgets.map(strip);
        basedOn = shared.version;
      } else {
        widgets = (await get(`/widgets/templates/${encodeURIComponent(st.dash.template)}`)).widgets.map(strip);
      }
      if (st.dead || !st.edit) return;
      commit(widgets, { message: picked === "shared" ? "Reset to the shared version" : "Reset to the template" });
      if (basedOn) st.basedOn = basedOn;
    } catch (err) {
      toast(err.message, "bad");
    }
  }

  // ---------- adding and configuring widgets ----------
  async function openAdd() {
    if (!st.dash) return;
    if (!st.edit && !(await enterEdit())) return;
    try { await ensureCatalog(true); } catch (err) { return toast(err.message, "bad"); }
    if (st.dead || !st.edit) return;
    if (st.gallery?.open) {
      el.querySelector(".dash-drawer .dash-search")?.focus();
      return;
    }
    const drawer = board?.mode() === "grid";
    el.classList.toggle("dash-drawer-open", drawer);
    st.gallery = openGallery({
      catalog: st.catalog, host: el, drawer, full: st.items.length >= limits().widgets, limit: limits().widgets,
      onAdd: (entry) => addFrom(entry),
      onConfigure: (entry) => configureNew(entry),
      onDrag: (e, entry) => board?.dragNew(e, { w: entry.size[0], h: entry.size[1], label: entry.title,
        onDrop: (layout, tempId) => dropNew(layout, tempId, entry) }),
      onClose: () => {
        st.gallery = null;
        el.classList.remove("dash-drawer-open");
        const active = document.activeElement;
        if (!active || active === document.body || !active.isConnected) part("toolbar")?.querySelector('[data-act="e-add"]')?.focus();
      },
    });
  }

  // a suggestion keeps its gallery title ("OpenVAS: overdue findings", "Warnings and errors") unless the widget would
  // generate the same one anyway (a metric's label), so a later rename of the label still shows
  const ownTitle = (entry) => (entry.title !== defaultTitle(st.catalog, { type: entry.type, config: entry.config }) ? entry.title.slice(0, 80) : null);

  function addFrom(entry) {
    add({ type: entry.type, config: entry.config, title: ownTitle(entry), w: entry.size[0], h: entry.size[1] });
  }

  function isFull() {
    const lim = limits().widgets;
    if (st.items.length < lim) return false;
    toast(`This dashboard has ${lim} widgets, the maximum`, "warn");
    return true;
  }

  /** A new widget instance of a type, its size within the type's bounds (placed by the caller). */
  function newInst({ type, config, title = null, w, h }) {
    const t = typeOf(type);
    if (t) {
      w = Math.min(Math.max(w || t.size.default.w, t.size.min.w), t.size.max.w);
      h = Math.min(Math.max(h || t.size.default.h, t.size.min.h), t.size.max.h);
    }
    return { id: newWidgetId(st.items.map((i) => i.id)), type, x: 0, y: 0, w, h, title, config: structuredClone(config || {}), events: t?.events };
  }

  /** Adds a widget at the first free place ("Add"); focus goes to its move handle. */
  function add(spec) {
    if (!st.edit || isFull()) return null;
    const inst = newInst(spec);
    const spot = firstFit(st.items, inst.w, inst.h, COLS, MAX_ROWS);
    if (!spot) { toast("There is no room left on this dashboard", "warn"); return null; }
    Object.assign(inst, spot);
    commit([...st.items, inst], { id: inst.id, message: `Added ${titleOf(inst)} at row ${spot.y + 1}, column ${spot.x + 1}` });
    article(inst.id)?.scrollIntoView({ block: "nearest" });
    return inst;
  }

  /** Adds a widget where it was dropped from the gallery: the others as the drag previewed them. One undo step. */
  function addAt(spec, layout, at) {
    if (!st.edit || isFull()) { board?.place(st.items); return null; }
    const inst = { ...newInst(spec), x: at.x, y: at.y };
    const next = [...layout.map((o) => ({ ...item(o.id), x: o.x, y: o.y })), inst];
    if (validate(next, COLS, MAX_ROWS).length) return add(spec);
    commit(next, { id: inst.id, message: `Added ${titleOf(inst)} at row ${at.y + 1}, column ${at.x + 1}` });
    return inst;
  }

  function dropNew(layout, tempId, entry) {
    const at = layout.find((i) => i.id === tempId);
    const others = layout.filter((i) => i.id !== tempId);
    if (entry.kind === "type") return configureNew(entry, { layout: others, at });
    addAt({ type: entry.type, config: entry.config, title: ownTitle(entry), w: at.w, h: at.h }, others, at);
  }

  async function configureNew(entry, drop = null) {
    try { await ensureCatalog(); } catch (err) { return toast(err.message, "bad"); }
    openConfigure({
      catalog: st.catalog, isNew: true,
      inst: { id: "w_new", type: entry.type, config: entry.config || {}, title: null, w: entry.size[0], h: entry.size[1] },
      onSave: ({ config, title }) => {
        const spec = { type: entry.type, config, title, w: entry.size[0], h: entry.size[1] };
        if (drop) addAt(spec, drop.layout, drop.at); else add(spec);
      },
    });
    if (drop) board?.place(st.items);
  }

  async function configure(id) {
    const inst = item(id);
    if (!inst) return;
    if (!st.edit && !(await enterEdit())) return;
    try { await ensureCatalog(true); } catch (err) { return toast(err.message, "bad"); } // fresh: a tool may have gone
    if (!typeOf(inst.type)) return toast("This kind of widget is not available any more; remove it instead", "warn");
    openConfigure({
      catalog: st.catalog, inst: item(id),
      onSave: ({ config, title }) => {
        const next = st.items.map((i) => (i.id === id ? { ...i, config, title, default_title: null, available: true, reason: null } : i));
        commit(next, { message: `${titleOf({ ...inst, config, title, default_title: null })} updated` });
      },
    });
  }

  function remove(id) {
    const inst = item(id);
    if (!inst || !st.edit) return;
    const order = sortReading(st.items);
    const next = order[order.findIndex((i) => i.id === id) + 1] || order[order.findIndex((i) => i.id === id) - 1];
    commit(st.items.filter((i) => i.id !== id), { message: `Removed ${titleOf(inst)}. Undo brings it back.` });
    if (next) focusHandle(next.id);
    else part("toolbar")?.querySelector('[data-act="e-add"]')?.focus();
  }

  // ---------- menus (a plain popover of buttons; Esc closes it and returns to its button) ----------
  function closeMenu(focus = false) {
    if (!menu) return;
    const m = menu;
    menu = null;
    m.pop.remove();
    m.btn.setAttribute("aria-expanded", "false");
    document.removeEventListener("pointerdown", m.outside, true);
    window.removeEventListener("scroll", m.away, true);
    window.removeEventListener("resize", m.away);
    if (focus && m.btn.isConnected) m.btn.focus({ preventScroll: true });
  }

  function openMenu(btn, content, run) {
    if (menu?.btn === btn) return closeMenu(true);
    closeMenu();
    const pop = document.createElement("div");
    pop.className = "dash-pop";
    pop.setAttribute("role", "group");
    pop.setAttribute("aria-label", btn.getAttribute("aria-label") || "Options");
    setHTML(pop, content);
    btn.after(pop);
    // anchored to its button: it follows a scroll, and closes once the button is out of view
    const anchor = () => {
      const r = btn.getBoundingClientRect();
      if (r.bottom < 0 || r.top > window.innerHeight) return closeMenu();
      const w = pop.offsetWidth, h = pop.offsetHeight;
      pop.style.left = `${Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8))}px`;
      pop.style.top = `${r.bottom + 4 + h > window.innerHeight - 8 ? Math.max(8, r.top - h - 4) : r.bottom + 4}px`;
    };
    anchor();
    btn.setAttribute("aria-expanded", "true");
    const outside = (e) => { if (!pop.contains(e.target) && !btn.contains(e.target)) closeMenu(); };
    const away = (e) => { if (!(e?.target instanceof Node) || !pop.contains(e.target)) anchor(); };
    document.addEventListener("pointerdown", outside, true);
    window.addEventListener("scroll", away, true);
    window.addEventListener("resize", away);
    pop.addEventListener("keydown", (e) => {
      const items = [...pop.querySelectorAll("button:not(:disabled), a[href]")];
      const i = items.indexOf(document.activeElement);
      const go = (n) => { e.preventDefault(); items[(n + items.length) % items.length]?.focus(); };
      if (e.key === "Escape" || e.key === "Tab") { e.preventDefault(); e.stopPropagation(); closeMenu(true); }
      else if (e.key === "ArrowDown" || e.key === "ArrowRight") go(i + 1);
      else if (e.key === "ArrowUp" || e.key === "ArrowLeft") go(i - 1);
      else if (e.key === "Home") go(0);
      else if (e.key === "End") go(items.length - 1);
    });
    pop.addEventListener("click", (e) => {
      const b = e.target.closest("[data-m]");
      if (e.target.closest("a[href]")) { closeMenu(); return; }
      if (!b || b.disabled) return;
      e.preventDefault();
      e.stopPropagation();
      closeMenu(true);
      run(b.dataset.m, b.dataset);
    });
    menu = { btn, pop, outside, away };
    pop.querySelector("button:not(:disabled), a[href]")?.focus();
  }

  const mi = (key, label, iconName, { disabled = false, extra = "" } = {}) =>
    html`<button type="button" class="menu-item" data-m="${key}" ${disabled ? raw("disabled") : ""}>${iconName ? icon(iconName, extra) : ""}${label}</button>`;
  const pad = (key, label, iconName, extra = "") => html`<button type="button" class="btn sm dash-pad-btn" data-m="${key}" aria-label="${label}">${icon(iconName, extra)}<span>${label.replace(/^Move (.)/, (_, c) => c.toUpperCase())}</span></button>`;

  function widgetMenu(btn, id) {
    const inst = item(id);
    if (!inst) return;
    const res = st.results.get(id);
    const r = RENDERERS[inst.type];
    const link = res?.data && r?.link ? r.link(res.data) : null;
    const app = link?.href ? APP_NAMES[link.href.slice(2).split(/[/?]/)[0]] : null;
    const chart = r?.chart;
    const editing = Boolean(st.edit);
    const stack = board?.mode() === "stack";
    const type = typeOf(inst.type);
    const content = editing ? html`
      <h4>Move</h4>
      <div class="dash-pads">${pad("up", "Move up", "arrow", "rot-270")}${pad("down", "Move down", "arrow", "rot-90")}
        ${stack ? "" : html`${pad("left", "Move left", "arrow", "rot-180")}${pad("right", "Move right", "arrow")}`}</div>
      ${mi("start", "Move to start", "undo")}${mi("end", "Move to end", "download")}${mi("to", "Move to...", "expand")}
      <h4>Size</h4>
      ${stack ? html`<p class="faint dash-small dash-pop-note">Resize on a wider screen.</p>` : type ? html`<div class="dash-pads">
        ${pad("s-small", "Small", "minus")}${pad("s-medium", "Medium", "grid")}${pad("s-large", "Large", "expand")}${pad("s-wide", "Wide", "arrow")}${pad("s-tall", "Tall", "arrow", "rot-90")}</div>
        <div class="dash-pads">${pad("narrower", "Narrower", "minus")}${pad("wider", "Wider", "plus")}${pad("shorter", "Shorter", "minus")}${pad("taller", "Taller", "plus")}</div>`
        : html`<p class="faint dash-small dash-pop-note">This kind of widget is not available any more.</p>`}
      <div class="menu-sep"></div>
      ${type ? mi("configure", "Configure...", "sliders") : ""}
      ${chart ? mi("table", tableOn(id) ? "Show as chart" : "Show as table", "table") : ""}
      ${mi("copy", "Copy to dashboard...", "copy")}${mi("moveto", "Move to dashboard...", "arrow")}
      <div class="menu-sep"></div>${html`<button type="button" class="menu-item danger" data-m="remove">${icon("trash")}Remove</button>`}`
      : html`${mi("refresh", "Refresh", "refresh")}
        ${chart ? mi("table", tableOn(id) ? "Show as chart" : "Show as table", "table") : ""}
        ${link?.href ? html`<a class="menu-item" href="${link.href}">${icon("external")}Open ${app ? `in ${app}` : link.text}</a>` : ""}
        ${mi("copy", "Copy to dashboard...", "copy")}
        ${st.dash.editable ? mi("configure", "Configure...", "sliders") : ""}`;
    openMenu(btn, content, (key) => widgetAction(key, id));
  }

  /** Reordering a narrow screen's stack changes the one layout every screen shows: said once per browser tab. */
  function stackNote() {
    if (storage(() => sessionStorage.getItem("hub.dash.stack-note"))) return;
    storage(() => sessionStorage.setItem("hub.dash.stack-note", "1"));
    toast("Order changed; wide screens show the new order too", "info");
  }

  function moved(next, id, verb = "Moved") {
    if (!next) return;
    if (board?.mode() === "stack") stackNote();
    const it = next.find((i) => i.id === id);
    const where = board?.mode() === "stack" ? `position ${sortReading(next).findIndex((i) => i.id === id) + 1} of ${next.length}` : `row ${it.y + 1}, column ${it.x + 1}`;
    commit(next, { message: `${verb} ${titleOf(item(id))} to ${where}` });
  }

  function sized(next, id) {
    if (!next) return;
    const it = next.find((i) => i.id === id);
    const old = item(id);
    if (it.w === old.w && it.h === old.h) return announce("Size unchanged");
    commit(next, { message: `${titleOf(old)} is now ${it.w} columns wide, ${it.h} rows tall` });
  }

  function widgetAction(key, id) {
    const inst = item(id);
    if (!inst) return;
    const stack = board?.mode() === "stack";
    const size = typeOf(inst.type)?.size;
    const order = sortReading(st.items);
    const index = order.findIndex((i) => i.id === id);
    const nothing = (text) => announce(`${titleOf(inst)} ${text}`);
    switch (key) {
      case "refresh": return fetchData([id]).then(() => announce(`${titleOf(inst)} refreshed`));
      case "table":
        storage(() => (tableOn(id) ? localStorage.removeItem(`hub.dash.table.${id}`) : localStorage.setItem(`hub.dash.table.${id}`, "1")));
        updateBody(id, true);
        return announce(tableOn(id) ? "Shown as a table" : "Shown as a chart");
      case "configure": return configure(id);
      case "copy": return copyTo(inst, false);
      case "moveto": return copyTo(inst, true);
      case "remove": return remove(id);
      case "up": case "down": case "left": case "right": {
        const [dx, dy] = { up: [0, -1], down: [0, 1], left: [-1, 0], right: [1, 0] }[key];
        const next = stack ? (dy ? moveInOrder(st.items, id, dy, COLS) : null) : step(st.items, id, dx, dy, COLS);
        return next ? moved(next, id) : nothing(`cannot move further ${key}`);
      }
      case "start": {
        const next = stack ? moveInOrder(st.items, id, -index, COLS) : moveTo(st.items, id, 0, 0, COLS);
        return next && index ? moved(next, id) : nothing("is first already");
      }
      case "end": {
        const next = stack ? moveInOrder(st.items, id, order.length - 1 - index, COLS)
          : moveTo(st.items, id, inst.x, bottom(st.items.filter((i) => i.id !== id)), COLS);
        return next && index < order.length - 1 ? moved(next, id) : nothing("is last already");
      }
      case "to": return moveToDialog(id);
      default: break;
    }
    if (!size || stack) return;
    if (key.startsWith("s-")) {
      const [w, h] = sizePreset(key.slice(2), size);
      return sized(resizeTo(st.items, id, w, h, COLS, size), id);
    }
    const delta = { narrower: [-1, 0], wider: [1, 0], shorter: [0, -1], taller: [0, 1] }[key];
    if (delta) sized(resizeTo(st.items, id, inst.w + delta[0], inst.h + delta[1], COLS, size), id);
  }

  function moveToDialog(id) {
    const inst = item(id);
    const stack = board?.mode() === "stack";
    const order = sortReading(st.items);
    modal({
      title: `Move ${titleOf(inst)}`,
      submit: "Move",
      body: stack ? html`<div class="field"><label for="mt-pos">Position (1 to ${order.length})</label>
          <input id="mt-pos" name="pos" type="number" min="1" max="${order.length}" value="${order.findIndex((i) => i.id === id) + 1}" required></div>`
        : html`<div class="form-grid"><div class="field"><label for="mt-row">Row</label><input id="mt-row" name="row" type="number" min="1" max="${MAX_ROWS}" value="${inst.y + 1}" required></div>
          <div class="field"><label for="mt-col">Column (1 to ${COLS - inst.w + 1})</label><input id="mt-col" name="col" type="number" min="1" max="${COLS - inst.w + 1}" value="${inst.x + 1}" required></div></div>
          <p class="faint dash-small">Widgets fall up into free space, so it may land higher than the row you enter.</p>`,
      onSubmit: (fd) => {
        let next;
        if (stack) {
          const pos = Math.max(1, Math.min(order.length, Number(fd.get("pos")) || 1));
          next = moveInOrder(st.items, id, pos - 1 - order.findIndex((i) => i.id === id), COLS);
          if (!next) return;
        } else {
          const row = Number(fd.get("row")), col = Number(fd.get("col"));
          if (!Number.isInteger(row) || !Number.isInteger(col) || row < 1 || col < 1 || col > COLS - inst.w + 1) {
            toast(`Choose a row from 1 and a column from 1 to ${COLS - inst.w + 1}`, "warn");
            return true;
          }
          next = moveTo(st.items, id, col - 1, row - 1, COLS);
        }
        moved(next, id);
      },
    });
  }

  async function copyTo(inst, move) {
    const mine = (st.list?.dashboards || []).filter((d) => d.scope === "personal" && d.id !== st.dash.id);
    modal({
      title: `${move ? "Move" : "Copy"} ${titleOf(inst)} to another dashboard`,
      submit: move ? "Move" : "Copy",
      body: html`<div class="field"><label for="ct-target">Dashboard</label><select id="ct-target" name="target">
        ${mine.map((d, n) => opt(d.id, d.title, n === 0))}${opt("__new", "A new dashboard: My dashboard", !mine.length)}</select>
        <span class="hint">Only your own dashboards can take widgets.</span></div>`,
      onSubmit: async (fd) => {
        let target = fd.get("target");
        if (target === "__new") target = (await post("/dashboards/mine", { title: "My dashboard", icon: "home" })).id;
        for (let attempt = 0; attempt < 2; attempt++) {
          const doc = await get(`/dashboards/${encodeURIComponent(target)}`);
          const widgets = doc.widgets.map(strip);
          if (widgets.length >= limits().widgets) throw new Error(`${doc.title} has ${limits().widgets} widgets, the maximum`);
          const spot = firstFit(widgets, inst.w, inst.h, COLS, MAX_ROWS);
          if (!spot) throw new Error(`There is no room left on ${doc.title}`);
          widgets.push({ ...strip(inst), id: newWidgetId(widgets.map((w) => w.id)), x: spot.x, y: spot.y });
          try {
            await put(`/dashboards/mine/${encodeURIComponent(target)}`, { title: doc.title, icon: doc.icon, description: doc.description || "", widgets, base_version: doc.version });
          } catch (err) {
            if (err.status === 409 && attempt === 0) continue; // changed meanwhile: once more on the fresh version
            throw err;
          }
          toast(`${move ? "Moved" : "Copied"} to ${doc.title}`, "ok");
          if (move && st.edit) remove(inst.id);
          refreshList();
          return;
        }
      },
    });
  }

  // ---------- dashboard menu, tabs, new dashboards and preferences ----------
  async function savePrefs(update) {
    for (let attempt = 0; attempt < 2; attempt++) {
      const prefs = st.list.prefs;
      const next = update({ order: st.list.dashboards.map((d) => d.id), hidden: [...prefs.hidden], home: prefs.home });
      try {
        await put("/dashboards/prefs", { ...next, base_version: prefs.version });
        await refreshList();
        return true;
      } catch (err) {
        if (err.status === 409 && attempt === 0) { await refreshList(); continue; }
        toast(err.message, "bad");
        return false;
      }
    }
    return false;
  }

  function dashMenu(btn) {
    const d = st.dash;
    const s = d && summaryOf(d.id);
    const vis = visibleDashes();
    const at = d ? vis.findIndex((x) => x.id === d.id) : -1;
    const admin = can("admin");
    const hidden = (st.list?.dashboards || []).filter((x) => x.hidden);
    const content = html`
      ${d && (d.scope === "personal" || admin) ? mi("rename", "Rename...", "edit") : ""}
      ${d && st.list.home_id !== d.id ? mi("home", "Set as my home", "home") : ""}
      ${d?.scope === "shared" ? mi("copy", "Make a personal copy", "copy") : ""}
      ${d?.scope === "shared" ? mi("hide", "Hide from my tabs", "x") : ""}
      ${d ? html`${mi("left", "Move tab left", "arrow", { disabled: at <= 0, extra: "rot-180" })}${mi("right", "Move tab right", "arrow", { disabled: at < 0 || at >= vis.length - 1 })}` : ""}
      ${d?.scope === "personal" && s?.based_on_newer ? mi("reset-shared", "Reset to the shared version...", "refresh") : ""}
      ${hidden.length ? mi("unhide", `Show hidden dashboards (${hidden.length})...`, "grid") : ""}
      ${d?.scope === "personal" ? html`<div class="menu-sep"></div><button type="button" class="menu-item danger" data-m="delete">${icon("trash")}Delete this dashboard</button>` : ""}
      ${admin && d ? html`<div class="menu-sep"></div><h4>Administrators</h4>
        ${d.scope === "shared" && !d.is_default ? mi("default", "Make it the default for everyone", "flag") : ""}
        ${d.scope === "personal" ? mi("publish-shared", "Publish as a shared dashboard...", "upload") : ""}
        ${d.scope === "shared" ? html`<button type="button" class="menu-item danger" data-m="delete-shared" ${d.is_default ? raw("disabled") : ""}>${icon("trash")}Delete for everyone${d.is_default ? " (it is the default)" : ""}</button>` : ""}` : ""}`;
    openMenu(btn, content, (key) => dashAction(key));
  }

  async function dashAction(key) {
    const d = st.dash;
    switch (key) {
      case "rename": return renameDialog();
      case "home": if (await savePrefs((p) => ({ ...p, home: d.id }))) announce(`${d.title} is your home dashboard`); return;
      case "copy": return copyDashboard(d);
      case "hide": {
        if (!(await savePrefs((p) => ({ ...p, hidden: [...new Set([...p.hidden, d.id])], home: p.home === d.id ? null : p.home })))) return;
        toast(`${d.title} is hidden from your tabs. "Show hidden dashboards" in the dashboard menu brings it back.`, "info");
        return openDash(st.list.home_id, { push: true, focusTab: true });
      }
      case "left": case "right": return moveTab(d.id, key === "left" ? -1 : 1);
      case "unhide": return unhideDialog();
      case "delete": {
        if (!(await confirmDialog("Delete this dashboard?", `${d.title} and its widgets are deleted. This cannot be undone.`, "Delete"))) return;
        try { await del(`/dashboards/mine/${encodeURIComponent(d.id)}`); } catch (err) { return toast(err.message, "bad"); }
        if (st.edit) { st.edit = null; window.removeEventListener("beforeunload", onBeforeUnload); drawToolbar(); }
        clearTimeout(saveTimer);
        saveTimer = 0;
        await loadList();
        toast(`Deleted ${d.title}`, "ok");
        return openDash(st.list.home_id, { push: true, focusTab: true });
      }
      case "reset-shared": {
        if (!(await enterEdit())) return;
        return reset();
      }
      case "default":
        try {
          await put("/dashboards/default", { dashboard_id: d.id });
          await refreshList();
          toast(`${d.title} is now the default dashboard`, "ok");
        } catch (err) { toast(err.message, "bad"); }
        return;
      case "publish-shared":
        return modal({
          title: "Publish as a shared dashboard", submit: "Publish",
          body: html`<p class="muted" style="margin-bottom:10px">Everyone sees a shared dashboard; administrators change it. Your own dashboard stays as it is.</p>
            <div class="field"><label for="ps-title">Name</label><input id="ps-title" name="title" value="${d.title}" maxlength="60" required></div>
            <div class="field"><label for="ps-desc">Description</label><input id="ps-desc" name="description" maxlength="300" value=""></div>`,
          onSubmit: async (fd) => {
            const created = await post("/dashboards/shared", { title: fd.get("title"), icon: d.icon, description: fd.get("description") || "", from: d.id });
            await refreshList();
            toast(`Published ${created.title} for everyone${created.dropped ? `; ${created.dropped} widgets were left out` : ""}`, "ok");
          },
        });
      case "delete-shared": {
        if (!(await confirmDialog("Delete this shared dashboard?", `${d.title} is deleted for everyone. Personal copies of it stay. This cannot be undone.`, "Delete for everyone"))) return;
        try { await del(`/dashboards/shared/${encodeURIComponent(d.id)}`); } catch (err) { return toast(err.message, "bad"); }
        if (st.edit) { st.edit = null; window.removeEventListener("beforeunload", onBeforeUnload); drawToolbar(); }
        clearDraft(d.id);
        await loadList();
        return openDash(st.list.home_id, { push: true, focusTab: true });
      }
      default:
    }
  }

  async function moveTab(id, delta) {
    const vis = visibleDashes().map((d) => d.id);
    const i = vis.indexOf(id);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= vis.length) return;
    vis.splice(i, 1);
    vis.splice(j, 0, id);
    if (await savePrefs((p) => ({ ...p, order: [...vis, ...p.order.filter((x) => !vis.includes(x))] }))) {
      el.querySelector(`.dash-tab[data-tab="${CSS.escape(id)}"]`)?.focus();
      announce(`Tab moved to position ${j + 1} of ${vis.length}`);
    }
  }

  function unhideDialog() {
    const hidden = st.list.dashboards.filter((d) => d.hidden);
    const m = modal({
      title: "Hidden dashboards", submit: null, cancel: "Close",
      body: hidden.length ? html`<ul class="dash-list">${hidden.map((d) => html`<li><span class="grow">${icon(dashIcon(d.icon))} ${d.title}</span>
        <button type="button" class="btn sm" data-show="${d.id}">Show it again</button></li>`)}</ul>` : html`<p class="muted">No dashboard is hidden.</p>`,
    });
    m.el.addEventListener("click", async (e) => {
      const b = e.target.closest("[data-show]");
      if (!b) return;
      const id = b.dataset.show;
      if (await savePrefs((p) => ({ ...p, hidden: p.hidden.filter((x) => x !== id) }))) {
        b.closest("li").remove();
        toast("It is back in your tabs", "ok");
        if (!st.dash) openDash(id, { push: true });
      }
    });
  }

  function renameDialog() {
    const d = st.dash;
    const meta = st.edit?.meta || { title: d.title, icon: d.icon, description: d.description || "" };
    modal({
      title: "Rename the dashboard", submit: "Save",
      body: html`<div class="field"><label for="rn-title">Name</label><input id="rn-title" name="title" value="${meta.title}" maxlength="60" required></div>
        <div class="field"><label for="rn-icon">Icon</label><select id="rn-icon" name="icon">${ICON_CHOICES.map(([k, l]) => opt(k, l, k === meta.icon))}</select></div>
        ${d.scope === "shared" ? html`<div class="field"><label for="rn-desc">Description</label><input id="rn-desc" name="description" value="${meta.description}" maxlength="300"></div>` : ""}
        ${d.scope === "shared" && !st.edit ? html`<p class="faint dash-small">This publishes the new name for everyone.</p>` : ""}`,
      onSubmit: async (fd) => {
        const next = { title: String(fd.get("title") || "").trim(), icon: fd.get("icon"), description: d.scope === "shared" ? String(fd.get("description") || "") : meta.description };
        if (!next.title) { toast("A dashboard needs a name", "warn"); return true; }
        if (st.edit) {
          st.edit.meta = next;
          st.dash = { ...st.dash, ...next };
          changed();
          drawTabsLocal(next);
          return;
        }
        const path = d.scope === "shared" ? `/dashboards/shared/${encodeURIComponent(d.id)}` : `/dashboards/mine/${encodeURIComponent(d.id)}`;
        const view = await put(path, { ...next, widgets: d.widgets.map(strip), base_version: d.version });
        st.dash = view;
        st.published = view.scope === "shared" ? view.widgets.map(strip) : [];
        await refreshList();
        announce(`Renamed to ${view.title}`);
      },
    });
  }

  function drawTabsLocal(meta) {
    const s = summaryOf(st.dash.id);
    if (s) Object.assign(s, { title: meta.title, icon: meta.icon });
    drawTabs();
  }

  async function copyDashboard(d) {
    try {
      const created = await post("/dashboards/mine", { title: copyTitle(d.title), icon: d.icon, from: d.id });
      if (created.dropped) toast(`${created.dropped} widget${created.dropped === 1 ? " needs" : "s need"} a higher role and ${created.dropped === 1 ? "was" : "were"} left out`, "warn");
      await loadList();
      await openDash(created.id, { push: true, focusTab: true });
      return created;
    } catch (err) {
      toast(err.message, "bad");
      return null;
    }
  }

  /** "Customize" on a shared dashboard someone may not change: a personal copy, opened in edit mode. */
  function customizeCopy() {
    const d = st.dash;
    return new Promise((resolve) => {
      modal({
        title: "Make a personal copy to customize?", submit: "Make my copy",
        body: html`<p>${d.title} is shared: everyone sees the version an administrator publishes. Make your own copy to arrange it your way.</p>
          <label class="check" style="margin-top:12px"><input type="checkbox" name="hide" checked><span>Hide the shared ${d.title} from my tabs</span></label>`,
        onSubmit: async (fd) => {
          const created = await post("/dashboards/mine", { title: copyTitle(d.title), icon: d.icon, from: d.id });
          if (created.dropped) toast(`${created.dropped} widget${created.dropped === 1 ? " needs" : "s need"} a higher role and ${created.dropped === 1 ? "was" : "were"} left out`, "warn");
          await loadList();
          const hide = fd.has("hide");
          await savePrefs((p) => {
            const order = p.order.filter((x) => x !== created.id);
            order.splice(Math.max(0, order.indexOf(d.id)), 0, created.id); // the copy takes the shared one's place
            const wasHome = p.home === d.id || (!p.home && st.list.home_id === d.id);
            return { order, hidden: hide ? [...new Set([...p.hidden, d.id])] : p.hidden, home: wasHome ? created.id : p.home };
          });
          await openDash(created.id, { push: true });
          await enterEdit();
          resolve(true);
        },
        onClose: () => resolve(false),
      });
    });
  }

  async function newDashboard() {
    const lim = limits();
    const mine = (st.list?.dashboards || []).filter((d) => d.scope === "personal").length;
    let templates = [];
    try { templates = (await ensureCatalog()).templates; } catch { /* blank still works */ }
    const admin = can("admin");
    const d = st.dash;
    modal({
      title: "New dashboard", submit: "Create",
      body: html`${mine >= lim.personal_dashboards && !admin ? html`<p class="notice warn">${icon("alert")}<span>You have ${lim.personal_dashboards} dashboards, the most you can have. Delete one first.</span></p>` : ""}
        <div class="field"><label for="nd-title">Name</label><input id="nd-title" name="title" maxlength="60" required placeholder="My dashboard"></div>
        <div class="field"><label for="nd-icon">Icon</label><select id="nd-icon" name="icon">${ICON_CHOICES.map(([k, l]) => opt(k, l, k === "grid"))}</select></div>
        <fieldset class="field plain"><legend>Start from</legend>
          <label class="radio-card"><input type="radio" name="from" value="" checked><div><b>Blank</b><p class="muted">Add the widgets you want.</p></div></label>
          ${templates.map((t) => html`<label class="radio-card"><input type="radio" name="from" value="template:${t.key}"><div><b>${t.title}</b><p class="muted">${t.description}</p></div></label>`)}
          ${d ? html`<label class="radio-card"><input type="radio" name="from" value="${d.id}"><div><b>A copy of ${d.title}</b><p class="muted">The widgets of the dashboard you are looking at.</p></div></label>` : ""}
        </fieldset>
        ${admin ? html`<label class="check"><input type="checkbox" name="shared"><span>Shared: everyone sees it (administrators change it)</span></label>` : ""}`,
      onSubmit: async (fd) => {
        const title = String(fd.get("title") || "").trim();
        if (!title) { toast("A dashboard needs a name", "warn"); return true; }
        const from = fd.get("from") || null;
        const shared = admin && fd.has("shared");
        const created = await post(shared ? "/dashboards/shared" : "/dashboards/mine", { title, icon: fd.get("icon"), ...(from ? { from } : {}) });
        if (created.dropped) toast(`${created.dropped} widget${created.dropped === 1 ? " needs" : "s need"} a higher role and ${created.dropped === 1 ? "was" : "were"} left out`, "warn");
        await loadList();
        if (await openDash(created.id, { push: true })) {
          if (!from) { await enterEdit(); openAdd(); } else el.querySelector(`.dash-tab[data-tab="${CSS.escape(created.id)}"]`)?.focus();
        }
      },
    });
  }

  // tab reorder by dragging (4 px threshold); the dashboard menu's "Move tab left/right" is the alternative
  let tabDrag = null;
  let swallowClick = false;
  const tabsEl = part("tabs");
  tabsEl.addEventListener("pointerdown", (e) => {
    const tab = e.target.closest(".dash-tab");
    if (!tab || e.button !== 0 || st.edit) return;
    tabDrag = { tab, id: tab.dataset.tab, sx: e.clientX, pointerId: e.pointerId, active: false, index: -1 };
    try { tab.setPointerCapture(e.pointerId); } catch { /* gone */ }
  });
  tabsEl.addEventListener("pointermove", (e) => {
    const t = tabDrag;
    if (!t || e.pointerId !== t.pointerId) return;
    const dx = e.clientX - t.sx;
    if (!t.active && Math.abs(dx) < 4) return;
    t.active = true;
    t.tab.classList.add("dragging");
    t.tab.style.transform = `translateX(${dx}px)`;
    const others = [...tabsEl.querySelectorAll(".dash-tab")].filter((x) => x !== t.tab);
    t.index = others.filter((x) => { const r = x.getBoundingClientRect(); return r.left + r.width / 2 < e.clientX; }).length;
    others.forEach((x, n) => { x.classList.toggle("drop-before", n === t.index); x.classList.toggle("drop-after", n === others.length - 1 && t.index === others.length); });
  });
  const endTabDrag = async (e, commitIt) => {
    const t = tabDrag;
    if (!t || e.pointerId !== t.pointerId) return;
    tabDrag = null;
    tabsEl.querySelectorAll(".dash-tab").forEach((x) => { x.classList.remove("drop-before", "drop-after", "dragging"); x.style.transform = ""; });
    if (!t.active) return;
    swallowClick = true;
    setTimeout(() => { swallowClick = false; }, 0);
    if (!commitIt) return;
    const vis = visibleDashes().map((d) => d.id).filter((x) => x !== t.id);
    vis.splice(t.index, 0, t.id);
    if (await savePrefs((p) => ({ ...p, order: [...vis, ...p.order.filter((x) => !vis.includes(x))] }))) {
      announce(`Tab moved to position ${t.index + 1} of ${vis.length}`);
      el.querySelector(`.dash-tab[data-tab="${CSS.escape(t.id)}"]`)?.focus();
    }
  };
  tabsEl.addEventListener("pointerup", (e) => endTabDrag(e, true));
  tabsEl.addEventListener("pointercancel", (e) => endTabDrag(e, false));
  tabsEl.addEventListener("click", (e) => {
    const tab = e.target.closest(".dash-tab");
    if (!tab) return;
    if (swallowClick) { e.preventDefault(); return; }
    if (tab.dataset.tab !== st.dash?.id) openDash(tab.dataset.tab, { push: true, focusTab: true });
  });
  // manual activation: arrows move the focus, Enter or Space opens the dashboard (UNVERIFIED: APG tabs pattern)
  tabsEl.addEventListener("keydown", (e) => {
    const tabs = [...tabsEl.querySelectorAll(".dash-tab")];
    const i = tabs.indexOf(document.activeElement);
    if (i < 0) return;
    const to = { ArrowLeft: i - 1, ArrowRight: i + 1, Home: 0, End: tabs.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    tabs[(to + tabs.length) % tabs.length].focus();
  });

  // ---------- shortcuts and the Esc of chart tooltips ----------
  const onKeys = (e) => {
    if (!st.edit || document.querySelector(".backdrop") || board?.busy()) return;
    if (!(e.ctrlKey || e.metaKey) || e.key.toLowerCase() !== "z") return;
    const t = e.target;
    if (!el.contains(t) && t !== document.body) return;
    if (t.matches?.("input, textarea, select, [contenteditable]")) return;
    e.preventDefault();
    if (e.shiftKey) redo(); else undo();
  };
  document.addEventListener("keydown", onKeys);
  offs.push(() => document.removeEventListener("keydown", onKeys));
  el.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    const row = e.target.closest?.(".bar-row, .col, .mx-cell");
    if (row && !row.classList.contains("tip-off")) { row.classList.add("tip-off"); e.stopPropagation(); }
  });
  el.addEventListener("focusin", () => el.querySelectorAll(".tip-off").forEach((x) => x.classList.remove("tip-off")));
  el.addEventListener("pointerover", (e) => { if (!e.target.closest?.(".tip-off")) el.querySelectorAll(".tip-off").forEach((x) => x.classList.remove("tip-off")); });

  actions(el, {
    import: () => openImport(),
    "d-new": () => newDashboard(),
    "d-customize": () => enterEdit(),
    "d-menu": (_, btn) => dashMenu(btn),
    "d-copy": () => copyDashboard(st.dash),
    "d-unhide": () => unhideDialog(),
    "d-retry": (ds) => openDash(ds.id),
    "e-add": () => openAdd(),
    "e-undo": () => undo(),
    "e-redo": () => redo(),
    "e-reset": () => reset(),
    "e-retry": () => saveNow(),
    "e-publish": () => publish(),
    "e-discard": () => discard(),
    "e-done": async () => {
      if (await leaveEdit({ reason: "done" })) el.querySelector('[data-act="d-customize"]')?.focus();
    },
    "w-menu": (ds, btn) => widgetMenu(btn, ds.id),
    "w-retry": (ds) => { st.failed.delete(ds.id); fetchData([ds.id]); },
    "w-remove": (ds) => remove(ds.id),
    "w-configure": (ds) => configure(ds.id),
    "b-reload": async () => { clearDraft(st.dash.id); st.edit = null; window.removeEventListener("beforeunload", onBeforeUnload); drawToolbar(); drawBanner(); await reloadDash(); },
    "b-keep": () => drawBanner(),
    "b-restore": async () => {
      const draft = readDraft(st.dash.id);
      drawBanner();
      if (!draft || !(await enterEdit())) return;
      st.edit.base = draft.base_version ?? st.dash.version;
      if (draft.title) st.edit.meta = { title: draft.title, icon: draft.icon || st.dash.icon, description: draft.description || "" };
      const before = new Map(st.items.map((i) => [i.id, i]));
      st.items = sortReading((draft.widgets || []).map((w) => ({ ...w })));
      syncFrames(before);
      drawToolbar();
      announce("Your unpublished changes are back");
    },
    "b-forget": () => { clearDraft(st.dash.id); drawBanner(); },
  });

  const api = { customize: () => enterEdit(), add: () => openAdd() };
  ctx.onLeave(() => {
    st.dead = true;
    if (page === api) page = null;
    closeMenu();
    st.gallery?.close();
    board?.destroy();
    io?.disconnect();
    offs.forEach((off) => off());
    window.removeEventListener("beforeunload", onBeforeUnload);
    if (st.edit && st.dash?.scope === "personal" && (saveTimer || st.saveAgain)) {
      clearTimeout(saveTimer);
      put(`/dashboards/mine/${encodeURIComponent(st.dash.id)}`, docBody(st.dash.version)).catch((err) => toast(`${st.dash.title}: ${err.message}`, "bad"));
    }
    if (st.edit && st.dash?.scope === "shared" && unpublished()) {
      toast(`Your unpublished changes to ${st.dash.title} are kept in this browser tab`, "info");
    }
  });

  // ---------- start ----------
  drawNotice();
  drawBar();
  try {
    await loadList();
  } catch (err) {
    setHTML(part("panel"), emptyState("alert", "Could not load the dashboards", err.message));
    return;
  }
  if (st.dead) return;
  page = api;
  const wanted = location.hash.match(/^#\/d\/([^/?]+)/)?.[1];
  const id = wanted && st.list.dashboards.some((d) => d.id === decodeURIComponent(wanted)) ? decodeURIComponent(wanted) : st.list.home_id;
  if (wanted && id !== decodeURIComponent(wanted)) toast("That dashboard does not exist or is not yours", "warn");
  await openDash(id);
  if (st.dead) return;
  const next = intent;
  intent = null;
  if (next === "customize") await enterEdit();
  if (next === "add") await openAdd();
}
