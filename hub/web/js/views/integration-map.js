// The Integration map (canvas-design 5): tools and the hub apps in lanes (identity providers | sources | hub apps |
// destinations | not connected), linked by data flows; single sign-on, event routes and capabilities on demand.
// Operators reorder items (shared arrangement), drag from a grip (or click the grip, then the target) to connect a tool
// to a hub app or another tool through the Connect panel, and propose single sign-on by connecting a tool and an
// identity provider. Every drag has a non-drag path (inspector buttons, the List view, the keyboard).
// Mounted by views/integration.js as the "Map" tab: mount(container, ctx, {params}) -> {dispose, select}.
// Deep links: #/integration/map/node/<item id>, #/integration/map/flow/<flow id> (and /edge/<edge id>).
import { del, get, onEvent, patch, post } from "../api.js";
import { xColor } from "../extensions.js";
import { countsText, domainInfo, flowsTable, optionsForm, readOptions, scheduleLabel, SCHEDULES, wireFlows } from "../flows.js";
import { identityCard, openProviderPicker, runRegistration, statusBadge, strategyBadge, wireIdentity } from "../sso.js";
import {
  actions, appIcon, badge, can, colorFor, confirmDialog, dateTime, debounce, emptyState, field, html, icon, modal, options, ring, setHTML,
  timeAgo, timeIn, toast,
} from "../ui.js";
import { createCanvas } from "../canvas/engine.js";
import { integrationFixture } from "../canvas/fixture.js";
import {
  DIRECTION_LABEL, KIND_LABEL, LANES, PORT_LABELS, STATE_WORDS, buildModel, canConnect, compareItems, edgeName, flowFromEvent, gripSides,
  isNewer, itemName, laneOf, movableLanes,
} from "../canvas/integration-model.js";
import { planMove } from "../canvas/lanes.js";
import { layoutStore } from "../canvas/layout.js";
import { font, measure } from "../canvas/text.js";
import { openImport } from "./tools.js";

const VIEW = "integration";
const enc = encodeURIComponent;
const PREFS = `hub.canvas.${VIEW}`;
const REFETCH_SOON = ["tool", "tool_removed", "connection", "patch", "toolbus", "extension", "extension_removed"];
const REFETCH_LATER = ["approval"];
const MARKER = { running: "flow", repair: "bad", failing: "bad", proposed: "proposed", scan_waiting: "proposed", enabled: "flow", disabled: "muted" };
const COLOR = /^#[0-9a-f]{3,8}$/i;
const LANE_TITLE = Object.fromEntries(LANES.map((l) => [l.id, l.title]));
const PILL_FONT = font(10.5, 650);
const domainLabel = (d) => PORT_LABELS[d] || domainInfo(d).label;

const readPref = (key, fallback) => {
  try { const v = JSON.parse(localStorage.getItem(`${PREFS}.${key}`)); return v ?? fallback; } catch { return fallback; }
};
const writePref = (key, value) => { try { localStorage.setItem(`${PREFS}.${key}`, JSON.stringify(value)); } catch { /* private mode */ } };

export function mount(container, ctx, { params = [] } = {}) {
  const debug = (() => { try { return localStorage.getItem("hub.canvas.debug") === "1" && !!localStorage.getItem("hub.canvas.fixture"); } catch { return false; } })();
  let data = null;
  let model = { items: new Map(), edges: new Map(), counts: { tools: 0, apps: 0, flows: 0, failing: 0, proposed: 0 } };
  let hidden = new Set(readPref("hidden", []));
  const filters = { sso: false, events: false, capabilities: false, flows: "all", ...readPref("filters", {}) };
  let find = "";
  let focusSelection = false;
  let disposed = false;
  // #/integration/map/failing (the Overview's "Show failing flows") narrows the flows for this visit only
  if (params[0] === "failing" || params[0] === "proposed") filters.flows = params[0];
  let pendingLink = params.length && !["failing", "proposed"].includes(params[0]) ? params : null;
  const operator = can("operator") && !debug; // the fixture is read-only

  setHTML(container, html`<div data-part="map-host"></div>`);
  const host = container.querySelector('[data-part="map-host"]');
  const store = layoutStore(VIEW, { apply: (doc) => canvas?.replaceLayout(doc) });

  const names = () => Object.fromEntries((data?.nodes || []).map((n) => [n.ref, n.label]));
  const item = (id) => model.items.get(id);
  const label = (id) => item(id)?.label || id;
  const stored = () => store.doc.items || {};
  const toolRef = (id) => String(id).replace(/^tool:/, "");
  const findFlow = (flowId) => data?.flows.find((f) => f.id === flowId);

  // ---------- drawing ----------
  function tile(g, c, x, y, size, color, text, glyph) {
    c.el("rect", { x, y, width: size, height: size, rx: Math.round(size / 4), fill: COLOR.test(color || "") ? color : colorFor(text || "?") }, g);
    if (glyph) c.use(g, glyph, x + (size - 18) / 2, y + (size - 18) / 2, 18, { class: "glyph tile-glyph" });
    else c.txt(g, String(text || "?").trim().slice(0, 2).toUpperCase() || "?", { class: "tile-text", x: x + size / 2, y: y + size / 2 + 5, "text-anchor": "middle" });
  }

  function pills(g, c, list, right, y) {
    const box = c.el("g", { class: "bdgs" }, g);
    let x = right;
    for (const [text, tone] of list) {
      const shown = c.ellipsize(text, 110, PILL_FONT);
      const w = Math.ceil(measure(shown, PILL_FONT)) + 14;
      x -= w;
      const p = c.el("g", { class: `bdg ${tone}`, transform: `translate(${x} ${y})` }, box);
      c.el("rect", { width: w, height: 16, rx: 8 }, p);
      c.txt(p, shown, { x: 7, y: 11.5 });
      x -= 4;
    }
  }

  function toolBadges(it) {
    const out = [];
    if (it.failing) out.push([`${it.failing} failing`, "bad"]);
    if (it.proposed) out.push([`${it.proposed} proposed`, "warn"]);
    if (it.sso?.state === "pending") out.push(["SSO pending", "warn"]);
    if (!it.connection && !it.is_idp) out.push(["no connection", ""]);
    if (it.is_idp) out.push(["IdP", "info"]);
    if (it.actions.includes("scan")) out.push(["scanner", "info"]);
    if (it.sor.length) out.push(["system of record", ""]);
    return out.slice(0, 2);
  }

  function drawTool(it, g, c) {
    const n = it.node;
    c.el("rect", { class: "node", width: c.w, height: c.h, rx: 10 }, g);
    tile(g, c, 10, 10, 36, n.ui?.color, n.ui?.icon || it.label, null);
    const healthy = n.health ? n.health.ok !== false : null;
    c.el("circle", { cx: 44, cy: 44, r: 5, class: n.running && healthy !== false ? "dot-ok" : healthy === false ? "dot-bad" : "dot-off" }, g);
    const room = c.w - 56 - (it.sso ? 34 : 10);
    c.txt(g, c.ellipsize(it.label, room, c.font(13, 650)), { class: "name", x: 56, y: 24 });
    const conn = n.connection ? `${n.connection.kind}${n.connection.generated ? " (generated)" : ""}` : it.is_idp ? "identity provider" : "no connection";
    c.txt(g, c.ellipsize(`${KIND_LABEL[n.kind] || "Tool"} · ${conn}`, c.w - 66, c.font(11.5, 500)), { class: "sub", x: 56, y: 41 });
    if (it.sso) {
      const k = c.el("g", { class: `sso-key ${it.sso.state === "pending" ? "pending" : ""}`, transform: `translate(${c.w - 34} 6)` }, g);
      c.el("rect", { width: 28, height: 16, rx: 8 }, k);
      c.use(k, "key", 3, 2, 12);
      c.txt(k, String(it.sso.name || "?").trim()[0]?.toUpperCase() || "?", { x: 17, y: 12 });
    }
    pills(g, c, toolBadges(it), c.w - 8, c.h - 8);
  }

  function drawApp(it, g, c) {
    c.el("rect", { class: "node", width: c.w, height: c.h, rx: 12 }, g);
    if (!it.active) g.classList.add("inactive");
    const color = it.extension ? xColor(it.id.replace(/^app:x:/, "")) : it.color;
    tile(g, c, 10, 8, 24, color, it.label, it.icon);
    c.txt(g, c.ellipsize(it.label, c.w - 90, c.font(13, 650)), { class: "name", x: 42, y: 25 });
    c.txt(g, `${it.flowCount} flow${it.flowCount === 1 ? "" : "s"}`, { class: "sub", x: c.w - 10, y: 25, "text-anchor": "end" });
    c.el("line", { class: "head-line", x1: 0, y1: 40, x2: c.w, y2: 40 }, g);
    it.domains.forEach((d, i) => {
      const y = 40 + 22 * i + 11;
      const p = c.el("g", { class: "port" }, g);
      c.el("circle", { cx: 0, cy: y, r: 4 }, p);
      c.el("circle", { cx: c.w, cy: y, r: 4 }, p);
      c.txt(p, c.ellipsize(domainLabel(d), c.w - 28, c.font(12, 550)), { x: 14, y: y + 4 });
    });
  }

  function edgeStyle(e) {
    if (e.kind === "flow") {
      const f = e.flow;
      const scan = f.direction === "scan";
      const quiet = e.state === "enabled" ? (scan ? "scan + import" : scheduleLabel(f.schedule_minutes)) : e.state === "disabled" ? "disabled" : null;
      // a scan is one edge scanner <-> Vulnerabilities and always says so (canvas-design 5.3)
      return { cls: `k-flow st-${e.state}`, marker: MARKER[e.state], arrow: e.arrow, chip: e.chip || (scan && e.state === "enabled" ? "scan + import" : null), chipSelected: e.chip || quiet,
        glyph: e.state === "repair" ? "wrench" : e.state === "failing" ? "alert" : scan ? "radar" : null };
    }
    if (e.kind === "sso") return { cls: `k-sso st-${e.state}`, marker: e.state === "pending" ? "proposed" : "ok", arrow: "to", chip: null, chipSelected: e.chip || "single sign-on", glyph: "key" };
    if (e.kind === "event") return { cls: `k-event st-${e.state}`, marker: e.state === "failing" ? "bad" : "event", arrow: "to", chip: null, chipSelected: e.event.event };
    return { cls: "k-cap", marker: "cap", arrow: "to", chip: null, chipSelected: e.cap.capability };
  }

  function signature(it) {
    if (it.kind === "app") return `a|${it.label}|${it.flowCount}|${it.active}|${it.domains.join(",")}`;
    const n = it.node;
    return `t|${it.label}|${n.kind}|${JSON.stringify(n.connection)}|${n.running}|${n.health?.ok}|${it.failing}|${it.proposed}|${it.sso?.state}|${it.sso?.name}|${n.ui?.color}|${n.ui?.icon}`;
  }

  // ---------- tooltips and names ----------
  const nameOf = (id) => {
    const it = item(id);
    if (it) return itemName(it, LANE_TITLE[laneOf(it, stored())]);
    const e = model.edges.get(id);
    return e ? edgeName(e, label) : id;
  };

  function tipOf(id) {
    const it = item(id);
    if (it?.kind === "tool") {
      const n = it.node;
      return html`<b>${it.label}</b><div class="muted">${KIND_LABEL[n.kind] || "Tool"} · ${n.connection ? `connected through ${n.connection.kind}` : "no connection"}</div>
        <div>${it.flowCount} data flow${it.flowCount === 1 ? "" : "s"}${it.failing ? `, ${it.failing} failing` : ""}${it.proposed ? `, ${it.proposed} proposed` : ""}</div>
        ${it.sso ? html`<div>${it.sso.state === "connected" ? `Signs in through ${it.sso.name}` : "Single sign-on awaiting approval"}</div>` : ""}
        ${n.health?.ok === false ? html`<div class="warn-text">Health check failing</div>` : ""}`;
    }
    if (it?.kind === "app") {
      return html`<b>${it.label}</b><div class="muted">Hub app: ${it.domains.map((d) => domainLabel(d)).join(", ")}</div><div>${it.flowCount} data flow${it.flowCount === 1 ? "" : "s"}</div>`;
    }
    const e = model.edges.get(id);
    if (!e) return null;
    if (e.kind === "flow") {
      const f = e.flow, r = f.last_result;
      return html`<b>${f.title}</b>
        ${f.direction === "scan" ? html`<div class="muted">Scans in-scope assets from Hub Assets; findings land in Hub Vulnerabilities.</div>` : ""}
        <div>${STATE_WORDS[e.state]} · ${scheduleLabel(f.schedule_minutes)}</div>
        <div class="muted">${r ? `Last run ${timeAgo(r.at)}: ${r.ok ? countsText(r.counts) || "ok" : r.error?.message || "failed"}` : "Never run"}</div>`;
    }
    return html`<span>${nameOf(id)}</span>`;
  }

  // ---------- canvas ----------
  const canvas = createCanvas(host, {
    view: VIEW, label: "Integration map", roledescription: "integration map", lanes: LANES,
    help: "Integration map. Arrow keys move between tools and hub apps, Enter opens the details, E moves along an item's connections, C connects (operators), M moves (operators), L shows the same information as tables, question mark lists every shortcut.",
    permissions: { move: operator, connect: operator },
    helpRows: [["S", "Single sign-on for the focused tool (operators)"], ["/", "Find"]],
    bar: html`
      <button type="button" class="btn sm" data-act="map-filters" aria-expanded="false" aria-haspopup="true">${icon("sliders")}Filters</button>
      <input type="search" class="cv-find" data-part="map-find" placeholder="Find..." aria-label="Find on the map">
      <button type="button" class="btn sm" data-act="map-focus" aria-pressed="false" title="Dim everything not connected to the selection">Focus on selection</button>
      <button type="button" class="btn sm" data-act="map-reset" data-min-role="operator" title="Put every item back in its default place, for everyone">${icon("undo")}Reset arrangement</button>`,
    adapter: {
      size: (it) => ({ w: it.w, h: it.h }),
      lane: (it, s) => laneOf(it, s),
      compare: compareItems,
      signature,
      draw: (it, g, c) => (it.kind === "app" ? drawApp(it, g, c) : drawTool(it, g, c)),
      edgeStyle,
      name: nameOf,
      role: (id) => {
        const it = item(id);
        if (it) return it.kind === "app" ? "hub app" : it.is_idp ? "identity provider" : "tool";
        return { flow: "data flow", sso: "single sign-on", event: "event route", cap: "capability" }[model.edges.get(id)?.kind] || "connection";
      },
      tip: tipOf,
      grips: (it) => gripSides(it, stored()),
      canConnect: (a, b) => canConnect(model.items, a, b),
      canMove: (it) => ({ lanes: movableLanes(it, stored()) }),
      onConnect: connect,
      onMove: moveItem,
      onSelect: selected,
      onOpen: (id) => { selected(id); canvas.showInspector(true); setTimeout(() => canvas.inspector.querySelector("button, a, select, input")?.focus(), 0); },
      onDelete: deleteKey,
      onKey(k, id) {
        if (k === "/") { canvas.shell.querySelector('[data-part="map-find"]').focus(); return true; }
        if (k === "s") {
          const it = id && item(id);
          if (!operator) { canvas.announce("Operators can set up single sign-on"); return true; }
          if (it?.kind === "tool" && !it.is_idp) ssoPicker(it.node.ref, id);
          else canvas.announce("Single sign-on: focus a tool first");
          return true;
        }
        return false;
      },
      onUndo: () => store.undo(),
      onRedo: () => store.redo(),
      onEscape: () => closeMenu(),
      summary: () => `${model.counts.tools} tools, ${model.counts.apps} hub apps, ${model.counts.flows} data flows`,
      list: renderList,
    },
  });

  // ---------- data ----------
  function rebuild() {
    if (!data) return;
    model = buildModel(data, { hidden, show: filters, flows: filters.flows, selection: canvas.selection });
    canvas.update(model, store.doc);
    applyFilter();
    notices();
    if (canvas.selection) renderInspector(canvas.selection);
    if (canvas.listView) renderList(canvas.list);
  }

  function notices() {
    const tools = (data?.nodes || []).length;
    const connected = (data?.nodes || []).some((n) => n.connection);
    if (!tools) {
      canvas.setNotice(html`${icon("plug")}<div style="flex:1"><b>Nothing to connect yet.</b> <span class="muted">Import a tool and it appears here next to the hub apps.</span></div>
        <button type="button" class="btn sm primary" data-act="map-import" data-min-role="operator">${icon("plus")}Import tool</button>`);
    } else if (!connected) {
      canvas.setNotice(html`${icon("plug")}<div class="muted">Tools exchange data through the hub apps. ${operator
        ? "An administrator sets up a tool's connection (Tool > Connection); then drag from the tool to an app."
        : "Operators can connect tools once an administrator has set up their connections."}</div>`);
    } else if (find && !matchCount()) {
      canvas.setNotice(html`${icon("search")}<div style="flex:1" class="muted">No items match the filter.</div>
        <button type="button" class="btn sm" data-act="map-clear-find">Clear filter</button>`, "warn");
    } else canvas.setNotice(null);
  }

  let loading = null;
  async function load() {
    if (debug) {
      data = integrationFixture();
      store.set(data.layout);
      overlay(null);
      return rebuild();
    }
    fetching ??= [];
    loading ??= get("/integration/map").finally(() => { loading = null; });
    let next;
    try {
      next = await loading;
    } catch (err) {
      queue.push(...(fetching || [])); // keep what arrived meanwhile
      fetching = null;
      if (data) drainFlows();
      if (!data) overlay(emptyState("alert", "Could not load the map", err.message, html`<button type="button" class="btn" data-act="map-retry">Retry</button>`));
      else toast(`The map could not be refreshed: ${err.message}`, "warn");
      return;
    }
    if (disposed) return;
    if (next !== data) {
      data = next;
      // flow events that arrived during the fetch go on top of the snapshot when they are not older than its copy
      queue.push(...(fetching || []));
      fetching = null;
      drainFlows(false);
    }
    store.set(data.layout);
    overlay(null);
    rebuild();
    if (pendingLink) followLink(pendingLink);
  }
  const refetchSoon = debounce(load, 500);
  const refetchLater = debounce(load, 1000);

  function overlay(content) {
    let o = canvas.shell.querySelector(".cv-overlay");
    if (!content) return o?.remove();
    if (!o) {
      o = document.createElement("div");
      o.className = "cv-overlay";
      canvas.shell.querySelector(".canvas-stage").append(o);
    }
    setHTML(o, content);
  }

  // live updates (canvas-design 4.8): subscribed before the first fetch; flow events received while a snapshot is
  // being fetched are applied on top of it (when not older than its copy), others once per frame
  const buffered = [];
  let ready = false;
  let fetching = null;
  let queue = [];
  let queued = 0;
  function onFlowEvent(e) {
    if (fetching) return fetching.push(e);
    queue.push(e);
    if (!queued) queued = requestAnimationFrame(() => drainFlows());
  }
  function drainFlows(redraw = true) {
    cancelAnimationFrame(queued);
    queued = 0;
    if (!data) return;
    let changed = false;
    for (const e of queue) {
      if (e.type === "flow_removed") {
        const before = data.flows.length;
        data.flows = data.flows.filter((f) => f.id !== e.data?.id);
        changed ||= data.flows.length !== before;
        continue;
      }
      const raw = e.data || {};
      const i = data.flows.findIndex((f) => f.id === raw.id);
      const current = i >= 0 ? data.flows[i] : null;
      if (!isNewer(raw, current)) continue;
      const next = flowFromEvent(raw, current);
      if (i >= 0) data.flows[i] = next; else data.flows.push(next);
      changed = true;
      if (canvas.selection === `flow:${raw.id}` && current && current.status !== next.status) canvas.announce(`Data flow ${next.title}: ${next.status}`);
    }
    queue = [];
    if (changed && redraw) rebuild();
  }

  const offs = [];
  if (!debug) {
    offs.push(onEvent(["flow", "flow_removed"], onFlowEvent));
    offs.push(onEvent(REFETCH_SOON, () => (ready ? refetchSoon() : buffered.push({ type: "refetch" }))));
    offs.push(onEvent(REFETCH_LATER, () => (ready ? refetchLater() : buffered.push({ type: "refetch" }))));
    offs.push(onEvent("canvas_layout", (e) => { if (e.data?.view === VIEW) store.remote(e.data.version); }));
  }
  const onReconnect = () => load();
  const onVisible = () => { if (document.visibilityState === "visible") load(); };
  window.addEventListener("atrium:events-reconnected", onReconnect);
  document.addEventListener("visibilitychange", onVisible);
  const timer = setInterval(() => { if (document.visibilityState === "visible" && !debug) load(); }, 120000);

  overlay(html`<div class="empty faint">Loading map...</div>`);
  load().then(() => {
    ready = true;
    const refetch = buffered.length > 0; // another relevant change during the first fetch: fetch once more
    buffered.length = 0;
    if (refetch) load();
  });
  if (innerWidth < 560) canvas.setList(true);

  // ---------- selection, inspector, deep links ----------
  function linkFor(id) {
    if (!id) return "#/integration/map";
    if (id.startsWith("flow:")) return `#/integration/map/flow/${enc(id.slice(5))}`;
    return model.items.has(id) ? `#/integration/map/node/${enc(id)}` : `#/integration/map/edge/${enc(id)}`;
  }
  function followLink(p) {
    pendingLink = null;
    const [kind, ref] = p;
    const id = kind === "flow" ? `flow:${ref}` : ref;
    if (!id || !(model.items.has(id) || model.edges.has(id))) {
      if (kind && ref) toast(kind === "flow" ? "That data flow is not on the map (it may have been removed or filtered out)" : "That item is not on the map", "warn");
      return;
    }
    canvas.select(id, { reveal: true });
    canvas.showInspector(true);
  }

  let lastSel = null;
  function selected(id) {
    if (location.hash.startsWith("#/integration/map")) history.replaceState(null, "", linkFor(id));
    const ssoNear = (x) => x && (model.edges.has(`sso:${toolRef(x)}`) || (data?.sso || []).some((s) => s.source === x || s.target === x));
    const rebuildSso = !filters.sso && (ssoNear(id) || ssoNear(lastSel));
    lastSel = id;
    if (!id) {
      canvas.showInspector(false);
      if (rebuildSso) rebuild(); else applyFilter();
      return;
    }
    renderInspector(id);
    canvas.showInspector(true);
    if (rebuildSso) rebuild(); else applyFilter();
  }

  function incident(id) {
    return [...model.edges.values()].filter((e) => e.from.id === id || e.to.id === id);
  }

  function renderInspector(id) {
    const root = canvas.inspector;
    const active = document.activeElement && root.contains(document.activeElement) ? document.activeElement : null;
    const again = active && (active.dataset.act ? `[data-act="${CSS.escape(active.dataset.act)}"]${active.dataset.id ? `[data-id="${CSS.escape(active.dataset.id)}"]` : ""}` : null);
    const it = item(id);
    const e = model.edges.get(id);
    const head = (title, sub, tileHtml = "") => html`<div class="cv-insp-head">${tileHtml}<div style="min-width:0"><h2>${title}</h2>${sub ? html`<div class="faint" style="font-size:12px">${sub}</div>` : ""}</div>
      <button type="button" class="icon-btn sm" data-act="insp-close" aria-label="Close details">${icon("x")}</button></div>`;
    let body;
    if (it?.kind === "tool") body = toolPanel(it, head);
    else if (it?.kind === "app") body = appPanel(it, head);
    else if (e?.kind === "flow") body = flowPanel(e, head);
    else if (e?.kind === "sso") body = ssoPanel(e, head);
    else if (e?.kind === "event") body = eventPanel(e, head);
    else if (e) body = html`${head("Capability", "")}<p>${nameOf(id)}</p>`;
    else return canvas.showInspector(false);
    setHTML(root, body);
    if (again) root.querySelector(again)?.focus();
  }

  const edgeButtons = (id) => {
    const list = incident(id);
    return list.length ? html`<div class="cv-edge-list">${list.map((x) => html`<button type="button" class="menu-item" data-act="insp-select" data-id="${x.id}">
      ${icon(x.kind === "flow" ? (x.flow.direction === "scan" ? "radar" : "flow") : x.kind === "sso" ? "key" : x.kind === "event" ? "send" : "link")}
      <span style="min-width:0;overflow-wrap:anywhere">${x.kind === "flow" ? x.flow.title : nameOf(x.id)}</span>${x.kind === "flow" && x.state !== "enabled" ? badge(STATE_WORDS[x.state], x.state === "failing" || x.state === "repair" ? "bad" : x.state === "disabled" ? "" : "warn") : ""}</button>`)}</div>`
      : html`<p class="muted">No connections on the map${filters.sso ? "" : " (single sign-on, events and capabilities are under Filters)"}.</p>`;
  };

  const moveButtons = (it) => {
    if (!operator) return "";
    const lane = laneOf(it, stored());
    const other = lane === "left" ? "right" : lane === "right" ? "left" : null;
    return html`<button type="button" class="btn sm" data-act="insp-move" data-dir="up">Move up</button>
      <button type="button" class="btn sm" data-act="insp-move" data-dir="down">Move down</button>
      ${other ? html`<button type="button" class="btn sm" data-act="insp-move" data-dir="swap">Move to ${LANE_TITLE[other]}</button>` : ""}`;
  };

  function toolPanel(it, head) {
    const n = it.node;
    const idt = (data.identity?.tools || []).find((t) => t.tool_id === n.ref);
    const providers = data.identity?.providers || [];
    const caps = Object.entries(n.capabilities || {});
    const lane = laneOf(it, stored());
    return html`${head(it.label, `${it.is_idp ? "Identity provider" : "Tool"} · ${LANE_TITLE[lane]}`, appIcon({ id: n.ref, name: n.label, manifest: { ui: n.ui || {} }, running: n.running }, "sm"))}
      <div class="row" style="gap:6px;margin-bottom:10px">${toolBadges(it).map(([t, tone]) => badge(t, tone))}</div>
      <div class="row" style="gap:12px;margin-bottom:10px;flex-wrap:nowrap">${ring(n.score, 46)}<dl class="kv" style="flex:1">
        <dt>Kind</dt><dd>${KIND_LABEL[n.kind] || "-"}</dd>
        <dt>Connector</dt><dd>${n.connection ? html`<code>${n.connection.kind}</code>${n.connection.generated ? " (generated)" : ""}` : html`<span class="muted">no connection</span>`}</dd>
        ${n.connection ? html`<dt>Last test</dt><dd>${n.connection.tested ? html`${n.connection.tested.ok ? badge("ok") : badge("failed", "bad")} <span class="faint">${timeAgo(n.connection.tested.at)}</span>` : html`<span class="muted">not tested</span>`}</dd>` : ""}
        <dt>Health</dt><dd>${n.health ? (n.health.ok === false ? badge("failing", "bad") : badge("ok")) : html`<span class="muted">unknown</span>`}${n.running ? "" : html` <span class="faint">not running</span>`}</dd></dl></div>
      ${caps.length ? html`<div class="cv-insp-section"><h3>Capabilities</h3><table class="cv-caps"><thead><tr><th>Data</th><th>Read</th><th>Write</th></tr></thead><tbody>
        ${caps.map(([d, ops]) => html`<tr><td>${domainLabel(d)}${(n.system_of_record || []).includes(d) ? html` <span class="faint">(system of record)</span>` : ""}</td>
          <td>${ops.includes("read") ? icon("check") : "-"}</td><td>${ops.includes("write") ? icon("check") : "-"}</td></tr>`)}</tbody></table>
        ${(n.actions || []).length ? html`<p class="faint" style="font-size:12px;margin-top:4px">Actions: ${n.actions.join(", ")}</p>` : ""}</div>` : ""}
      ${!it.is_idp && providers.length ? html`<div class="cv-insp-section"><h3>Single sign-on</h3><div class="row" style="gap:6px">${statusBadge(idt?.status || "not_connected")}
        ${idt?.connected_to ? html`<span>${providers.find((p) => p.tool_id === idt.connected_to)?.name || idt.connected_to}</span>` : idt?.pending?.provider ? html`<span>${providers.find((p) => p.tool_id === idt.pending.provider)?.name || idt.pending.provider}</span> <a href="#/approvals">Approvals</a>` : ""}
        ${strategyBadge(idt?.pending?.strategy)}</div></div>` : ""}
      <div class="cv-insp-actions">
        <a class="btn sm" href="#/tools/${enc(n.ref)}">${icon("external")}Tool page</a>
        <a class="btn sm" href="#/tools/${enc(n.ref)}/connection">${icon("plug")}Connection</a>
        ${operator ? html`<button type="button" class="btn sm" data-act="insp-connect">${icon("link")}Connect to...</button>` : ""}
        ${operator && !it.is_idp && providers.length ? html`<button type="button" class="btn sm" data-act="insp-sso">${icon("key")}Single sign-on...</button>` : ""}
        ${operator && idt?.applied?.can_register ? html`<button type="button" class="btn sm" data-act="insp-register">${icon("play")}Run provider registration</button>` : ""}
        ${operator && n.connection ? html`<button type="button" class="btn sm" data-act="insp-test">${icon("activity")}Test connection</button>` : ""}
        ${moveButtons(it)}
        <button type="button" class="btn sm" data-act="insp-hide">${icon("x")}Hide from my map</button></div>
      <div class="cv-insp-section"><h3>Connections</h3>${edgeButtons(it.id)}</div>`;
  }

  function appPanel(it, head) {
    return html`${head(it.label, it.extension ? "Extension app" : "Hub app")}
      <dl class="kv"><dt>Takes</dt><dd>${it.domains.map((d) => domainLabel(d)).join(", ")}</dd><dt>Data flows</dt><dd>${it.flowCount}${it.failing ? html` ${badge(`${it.failing} failing`, "bad")}` : ""}</dd>
        ${it.active ? "" : html`<dt>State</dt><dd>${badge("inactive")} <span class="muted">its extension is disabled</span></dd>`}</dl>
      <div class="cv-insp-actions"><a class="btn sm" href="${it.href}">${icon("external")}Open ${it.label}</a>
        ${operator && it.active ? html`<button type="button" class="btn sm" data-act="insp-connect">${icon("link")}Connect to...</button>` : ""}
        ${moveButtons(it)}
        <button type="button" class="btn sm" data-act="insp-hide">${icon("x")}Hide from my map</button></div>
      <div class="cv-insp-section"><h3>Connections</h3>${edgeButtons(it.id)}</div>`;
  }

  function flowPanel(e, head) {
    const f = e.flow;
    const r = f.last_result;
    const d = domainInfo(f.domain);
    const runnable = f.status !== "proposed" || f.job;
    const failing = r && r.ok === false;
    return html`${head(f.title, "Data flow")}
      <div class="row" style="gap:6px;margin-bottom:10px">${badge(STATE_WORDS[e.state], { failing: "bad", repair: "bad", proposed: "warn", scan_waiting: "warn", running: "info", enabled: "ok" }[e.state] || "")}
        ${badge(d.label, "accent")}${badge(DIRECTION_LABEL[f.direction] || f.direction)}</div>
      ${f.reason ? html`<p class="muted" style="margin-bottom:10px;overflow-wrap:anywhere">${f.reason}</p>` : ""}
      <dl class="kv"><dt>Data</dt><dd>${d.href ? html`<a href="${d.href}">${d.label}</a>` : d.label}</dd>
        <dt>Direction</dt><dd>${DIRECTION_LABEL[f.direction] || f.direction}</dd>
        <dt>Run by</dt><dd><code>${f.owner || "-"}</code></dd>
        <dt>Schedule</dt><dd>${scheduleLabel(f.schedule_minutes)}</dd>
        ${f.next_run ? html`<dt>Next run</dt><dd title="${dateTime(f.next_run)}">${timeIn(f.next_run)}</dd>` : ""}
        <dt>Last run</dt><dd>${r ? html`${r.ok ? badge("ok") : badge("failed", "bad")} <span title="${dateTime(r.at)}">${timeAgo(r.at)}</span>${r.duration != null ? html` <span class="faint">(${r.duration}s)</span>` : ""}
          ${r.ok && countsText(r.counts) ? html`<div class="faint">${countsText(r.counts)}</div>` : ""}${r.trigger ? html`<div class="faint">started by ${r.trigger}</div>` : ""}` : html`<span class="muted">never</span>`}</dd>
        ${f.approval_id ? html`<dt>Approval</dt><dd><a href="#/approvals">waiting for approval</a></dd>` : ""}</dl>
      ${failing && r.error ? html`<div class="notice bad" style="margin-top:10px">${icon("alert")}<div style="min-width:0"><b>${r.error.status ? `HTTP ${r.error.status}: ` : ""}</b>
        <span style="white-space:pre-line;overflow-wrap:anywhere">${r.error.message}</span>${r.error.excerpt ? html`<pre class="code wrap" style="margin-top:6px;max-height:160px">${r.error.excerpt}</pre>` : ""}</div></div>` : ""}
      <div class="cv-insp-actions" data-min-role="operator">
        ${f.status === "proposed" ? html`<button type="button" class="btn sm ok" data-act="flow-enable" data-id="${f.id}">${icon("check")}Enable</button>
          <button type="button" class="btn sm" data-act="flow-dismiss" data-id="${f.id}">Dismiss</button>`
          : html`<button type="button" class="btn sm" data-act="flow-toggle" data-id="${f.id}">${f.status === "enabled" ? "Disable" : "Enable"}</button>`}
        ${runnable ? html`<button type="button" class="btn sm" data-act="flow-run" data-id="${f.id}" ${f.running ? "disabled" : ""}>${icon("play")}Run now</button>` : ""}
        ${failing && r.error && !f.repair ? html`<button type="button" class="btn sm" data-act="flow-repair" data-id="${f.id}">${icon("wrench")}Repair</button>` : ""}
        ${f.repair && f.repair !== "requested" ? html`<a class="btn sm" href="#/approvals">${icon("wrench")}Repair proposed</a>` : ""}
        <button type="button" class="btn sm" data-act="flow-edit" data-id="${f.id}">${icon("sliders")}Schedule and options</button>
        <button type="button" class="btn sm danger" data-act="flow-delete" data-id="${f.id}">${icon("trash")}Remove</button></div>
      <div class="cv-insp-actions"><button type="button" class="btn sm" data-act="flow-info" data-id="${f.id}">${icon("file")}Details</button>
        <button type="button" class="btn sm" data-act="insp-select" data-id="${e.from.id}">${label(e.from.id)}</button>
        <button type="button" class="btn sm" data-act="insp-select" data-id="${e.to.id}">${label(e.to.id)}</button></div>`;
  }

  function ssoPanel(e, head) {
    const s = e.sso;
    const idt = (data.identity?.tools || []).find((t) => `tool:${t.tool_id}` === s.target);
    return html`${head("Single sign-on", `${label(s.target)} signs in through ${label(s.source)}`)}
      <dl class="kv"><dt>Provider</dt><dd>${label(s.source)}</dd><dt>Tool</dt><dd>${label(s.target)}</dd><dt>Protocol</dt><dd>${(s.protocol || "-").toUpperCase()}</dd>
        <dt>State</dt><dd>${statusBadge(s.state === "pending" ? "pending" : "connected")}${s.state === "pending" ? html` <a href="#/approvals">Approvals</a>` : ""}</dd>
        ${idt?.pending?.strategy ? html`<dt>How</dt><dd>${strategyBadge(idt.pending.strategy)}</dd>` : ""}</dl>
      <div class="cv-insp-actions">${operator ? html`<button type="button" class="btn sm" data-act="insp-sso-change">${icon("key")}Change provider</button>` : ""}
        ${operator && idt?.applied?.can_register ? html`<button type="button" class="btn sm" data-act="insp-register-edge">${icon("play")}Run provider registration</button>` : ""}</div>
      <p class="faint" style="font-size:12.5px">Single sign-on can be changed here, not removed.</p>`;
  }

  function eventPanel(e, head) {
    const ev = e.event;
    const recent = ev.last_delivery;
    return html`${head("Event route", `${label(ev.source)} to ${label(ev.target)}`)}
      <dl class="kv"><dt>Event</dt><dd><code>${ev.event}</code></dd><dt>Pattern</dt><dd><code>${ev.pattern}</code></dd>
        <dt>Webhook</dt><dd>${ev.has_webhook ? badge("webhook set", "ok") : badge("no webhook", "warn")}</dd>
        <dt>Last delivery</dt><dd>${recent ? html`${recent.ok ? badge("ok") : badge("failed", "bad")} ${timeAgo(recent.ts)}` : html`<span class="muted">none yet</span>`}</dd></dl>
      <p class="faint" style="font-size:12.5px;margin-top:10px">Event routes come from the tools' manifests.</p>`;
  }

  // inspector actions (flow buttons reuse flows.js through wireFlows)
  const refresh = () => load();
  wireFlows(canvas.inspector, { find: findFlow, refresh, names });
  actions(canvas.inspector, {
    "insp-close": () => { canvas.select(null); canvas.focusMap(); },
    "insp-select": (d) => canvas.select(d.id, { reveal: true }),
    "insp-connect": () => connectTo(canvas.selection),
    "insp-sso": () => { const it = item(canvas.selection); if (it) ssoPicker(it.node.ref, it.id); },
    "insp-sso-change": () => { const e = model.edges.get(canvas.selection); if (e) ssoPicker(toolRef(e.to.id), e.to.id, toolRef(e.from.id)); },
    "insp-register": () => { const it = item(canvas.selection); if (it) register(it.node.ref); },
    "insp-register-edge": () => { const e = model.edges.get(canvas.selection); if (e) register(toolRef(e.to.id)); },
    async "insp-test"(_, btn) {
      const it = item(canvas.selection);
      if (!it) return;
      btn.disabled = true;
      try {
        const r = await post(`/tools/${enc(it.node.ref)}/connection/test`);
        toast(r.ok ? `${it.label}: connection ok` : `${it.label}: ${r.detail || "test failed"}`, r.ok ? "ok" : "bad");
        canvas.announce(r.ok ? "Connection test passed" : "Connection test failed");
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
      load();
    },
    "insp-move": (d) => moveBy(canvas.selection, d.dir),
    "insp-hide": () => hide(canvas.selection),
  });

  function register(ref) {
    const t = (data.identity?.tools || []).find((x) => x.tool_id === ref);
    const provider = (data.identity?.providers || []).find((p) => p.tool_id === t?.applied?.provider);
    runRegistration(ref, t?.name || ref, provider?.name).then(refresh);
  }

  // ---------- connecting ----------
  function ssoPicker(ref, toolId, provider) {
    const identity = data.identity || { providers: [], tools: [] };
    if (!identity.providers.length) return toast("There is no identity provider in the suite yet", "warn");
    const t = identity.tools.find((x) => x.tool_id === ref);
    openProviderPicker({ toolId: ref, toolName: t?.name || label(toolId), data: identity,
      current: provider || t?.choice || t?.pending?.provider || t?.connected_to || t?.selected, done: refresh });
  }

  function connect(a, b) {
    const verdict = canConnect(model.items, a, b);
    if (!verdict.ok) return toast(verdict.reason, "warn");
    if (verdict.sso) {
      const [idp, tool] = item(a).is_idp ? [item(a), item(b)] : [item(b), item(a)];
      const t = (data.identity?.tools || []).find((x) => x.tool_id === tool.node.ref);
      if (t?.status === "connected" && t.connected_to === idp.node.ref) {
        const text = `${tool.label} already signs in through ${idp.label}`;
        toast(text, "info");
        return canvas.announce(text);
      }
      return ssoPicker(tool.node.ref, tool.id, idp.node.ref);
    }
    openConnectPanel(a, b);
  }

  function connectTo(from) {
    const it = item(from);
    if (!it) return;
    const choices = [...model.items.values()].filter((x) => x.id !== from && canConnect(model.items, from, x.id).ok)
      .sort((x, y) => (x.kind === y.kind ? String(x.label).localeCompare(String(y.label)) : x.kind === "app" ? -1 : 1));
    if (!choices.length) {
      const reason = [...model.items.values()].filter((x) => x.id !== from).map((x) => canConnect(model.items, from, x.id).reason)[0];
      return toast(`Nothing to connect ${it.label} to${reason ? `: ${reason}` : ""}`, "info");
    }
    modal({
      title: `Connect ${it.label} to...`, submit: "Next", minRole: "operator",
      body: field("Connect to", html`<select name="target">${options(choices.map((x) => [x.id, `${x.label} (${x.kind === "app" ? "hub app" : x.is_idp ? "identity provider" : "tool"})`]))}</select>`,
        "Data flows go through a hub app; connecting a tool and an identity provider sets up single sign-on."),
      onSubmit(form) { setTimeout(() => connect(from, String(form.get("target"))), 0); },
    });
  }

  async function openConnectPanel(a, b) {
    let o;
    try {
      o = await get(`/integration/map/options?a=${enc(a)}&b=${enc(b)}`);
    } catch (err) {
      return toast(err.message, "bad");
    }
    const autonomous = data.autonomy === "autonomous";
    const opener = canvas.selection;
    const rows = o.options || [];
    const usable = (opt) => !opt.blocked && opt.parts.some((p) => !p.exists);
    const drawn = rows.find((opt) => usable(opt) && opt.parts[0].source === (item(a)?.kind === "tool" ? a : "hub")) || rows.find((opt) => usable(opt) && opt.recommended) || rows.find(usable);
    const partState = (p, i, optId) => {
      if (!p.exists) return "";
      const x = p.exists;
      return html`<span class="cv-part">${badge(x.status)}
        <button type="button" class="btn sm" data-act="cp-show" data-flow="${x.flow_id}">Show</button>
        ${x.status === "disabled" && !p.blocked ? html`<button type="button" class="btn sm" data-act="cp-enable" data-flow="${x.flow_id}" data-opt="${optId}" data-part="${i}">Enable</button>` : ""}
        ${x.approval_id ? html`<a class="btn sm" href="#/approvals">Open approval</a>` : ""}</span>`;
    };
    const body = html`
      ${(o.notes || []).map((n) => html`<div class="notice" style="margin-bottom:10px">${icon("alert")}<div class="muted">${n}</div></div>`)}
      ${(o.needs_connection || []).length ? html`<p style="margin-bottom:10px">${(o.needs_connection || []).map((ref) => html`<a class="btn sm" href="#/tools/${enc(ref)}/connection" data-min-role="admin">${icon("plug")}Open connection settings of ${label(`tool:${ref}`)}</a> `)}</p>` : ""}
      ${rows.length ? html`<div role="radiogroup" aria-label="What to connect">${rows.map((opt) => {
        const missing = opt.parts.filter((p) => !p.exists);
        const disabled = !!opt.blocked || !missing.length;
        return html`<label class="cv-option ${disabled ? "blocked" : ""}">
          <input type="radio" name="option" value="${opt.id}" ${disabled ? "disabled" : ""} ${opt === drawn ? "checked" : ""}>
          <div style="min-width:0;flex:1"><div class="row" style="gap:6px"><b style="overflow-wrap:anywhere">${opt.title}</b>
            ${badge(opt.kind === "chain" ? "through the hub" : DIRECTION_LABEL[opt.kind] || opt.kind)}${opt.recommended ? badge("recommended", "ok") : ""}
            ${!missing.length ? badge("exists") : ""}</div>
            ${opt.reason ? html`<div class="reason">${opt.reason}</div>` : ""}
            ${opt.blocked ? html`<div class="reason warn-text">${opt.blocked}</div>` : ""}
            ${opt.parts.map((p, i) => html`${opt.parts.length > 1 ? html`<div class="cv-part"><span class="faint">${i + 1}.</span> ${p.title}${p.blocked && p.blocked !== opt.blocked ? html` <span class="warn-text">${p.blocked}</span>` : ""}</div>` : ""}
              ${partState(p, i, opt.id)}<div class="cv-result" data-result="${opt.id}:${i}" role="status"></div>`)}</div></label>`;
      })}</div>
      <div data-part="cp-fields"></div>` : html`<p class="muted">Nothing can be connected between these two.</p>`}
      ${(o.events || []).length ? html`<h3 style="margin:14px 0 6px">Event routes between them</h3>${o.events.map((ev) => html`<div class="msg-line"><span class="route">${label(ev.source)} &rarr; ${label(ev.target)}</span><code>${ev.event}</code>
        <span>${ev.has_webhook ? badge("webhook", "ok") : badge("no webhook", "warn")}</span></div>`)}<p class="faint" style="font-size:12px">From the tools' manifests; shown for information.</p>` : ""}`;
    const m = modal({
      title: `Connect ${label(a)} and ${label(b)}`, wide: true, minRole: "operator",
      submit: rows.some(usable) ? (autonomous ? "Enable" : "Propose") : null, cancel: rows.some(usable) ? "Cancel" : "Close",
      body,
      onClose: () => { if (opener && item(opener)) canvas.focus(opener); },
      async onSubmit(_, form) {
        const opt = rows.find((x) => x.id === form.querySelector("[name=option]:checked")?.value);
        if (!opt) throw new Error("Choose what to connect");
        let failed = false;
        let last = null;
        for (const [i, p] of opt.parts.entries()) {
          if (p.exists) continue;
          const out = form.querySelector(`[data-result="${CSS.escape(`${opt.id}:${i}`)}"]`);
          const opts = form.querySelector(`[data-opts="${i}"]`);
          const sched = form.querySelector(`[name="schedule-${i}"]`);
          try {
            const r = await post("/flows", { domain: p.domain, source: p.source, target: p.target, action: p.action,
              schedule_minutes: Number(sched?.value ?? p.default_schedule), options: opts ? readOptions({ domain: p.domain, direction: p.direction }, opts) : {} });
            p.exists = { flow_id: r.flow.id, status: r.flow.status, approval_id: r.approval_id };
            last = r.flow;
            setHTML(out, r.approval_id ? html`<span class="ok">${icon("check")} Proposed - waiting for approval.</span> <a href="#/approvals">Approvals</a>`
              : html`<span class="ok">${icon("check")} Enabled.</span>`);
            out.className = "cv-result ok";
            canvas.announce(`${r.approval_id ? "Proposed" : "Enabled"} data flow ${r.flow.title}${r.approval_id ? ", awaiting approval" : ""}`);
          } catch (err) {
            failed = true;
            out.className = "cv-result bad";
            out.textContent = err.message;
            break;
          }
        }
        await load();
        if (failed) return true;
        toast(last ? (autonomous ? "Data flow enabled" : "Data flow proposed - see Approvals") : "Nothing new to create", "ok");
        if (last) setTimeout(() => canvas.select(`flow:${last.id}`, { reveal: true }), 50);
      },
    });
    const drawFields = () => {
      const slot = m.el.querySelector('[data-part="cp-fields"]');
      if (!slot) return;
      const opt = rows.find((x) => x.id === m.el.querySelector("[name=option]:checked")?.value);
      if (!opt) return setHTML(slot, "");
      setHTML(slot, html`${opt.parts.map((p, i) => (p.exists ? "" : html`<fieldset class="plain" style="margin-top:12px">
        ${opt.parts.length > 1 ? html`<h3 style="margin-bottom:8px">${i + 1}. ${p.title}</h3>` : ""}
        ${field("Schedule", html`<select name="schedule-${i}">${options(SCHEDULES.map(([v, t]) => [String(v), t]), String(p.default_schedule))}</select>`,
          p.direction === "scan" ? (data.guardrails?.scans_need_approval && !autonomous ? "Each scan waits for approval." : "Scans start without approval.") : "")}
        <div data-opts="${i}">${optionsForm({ domain: p.domain, direction: p.direction, options: {} })}</div></fieldset>`))}`);
    };
    m.el.addEventListener("change", (e) => { if (e.target.name === "option") drawFields(); });
    actions(m.el, {
      "cp-show": (d) => { m.close(); canvas.select(`flow:${d.flow}`, { reveal: true }); },
      async "cp-enable"(d, btn) {
        btn.disabled = true;
        try {
          const updated = await patch(`/flows/${enc(d.flow)}`, { status: "enabled" });
          toast(updated?.status === "proposed" ? "Proposed again - the flow waits for approval" : "Flow enabled",
            updated?.status === "proposed" ? "info" : "ok");
          btn.remove();
        } catch (err) {
          toast(err.message, "bad");
          btn.disabled = false;
        }
        load();
      },
    });
    drawFields();
  }

  // ---------- moving, hiding, deleting ----------
  function moveItem(id, { lane, changes }) {
    const it = item(id);
    const items = {};
    for (const [x, order] of Object.entries(changes)) items[x] = { order };
    if (it?.kind === "tool" && (it.node.lane_default === "left" || it.node.lane_default === "right")) items[id].lane = lane === it.node.lane_default ? null : lane;
    store.move(items);
  }

  function moveBy(id, dir) {
    const it = item(id);
    const sc = canvas.scene;
    if (!it || !sc) return;
    const lane = laneOf(it, stored());
    if (dir === "swap") {
      const other = lane === "left" ? "right" : "left";
      const entries = (sc.order.get(other) || []).filter((e) => e.id !== id);
      return moveItem(id, { lane: other, changes: planMove(entries, id, entries.length) });
    }
    const entries = sc.order.get(lane) || [];
    const at = entries.findIndex((e) => e.id === id);
    const to = dir === "up" ? at - 1 : at + 1;
    if (at < 0 || to < 0 || to >= entries.length) return canvas.announce(`${it.label} is already ${dir === "up" ? "first" : "last"} in ${LANE_TITLE[lane]}`);
    const others = entries.filter((e) => e.id !== id);
    moveItem(id, { lane, changes: planMove(others, id, to) });
    canvas.announce(`${it.label} moved to position ${to + 1} in ${LANE_TITLE[lane]}`);
  }
  function hide(id) {
    if (!id || !item(id)) return;
    hidden.add(id);
    writePref("hidden", [...hidden]);
    const name = label(id);
    canvas.select(null, { quiet: true });
    rebuild();
    toast(`${name} is hidden from your map (Filters > Hidden items shows it again)`, "info");
    canvas.announce(`${name} hidden from your map`);
  }

  async function deleteKey(id) {
    const e = model.edges.get(id);
    if (!e) return canvas.announce(item(id) ? "Select a connection to act on it; items cannot be removed from the map" : "Nothing is selected");
    if (e.kind === "sso") return canvas.announce("Single sign-on can be changed here, not removed.");
    if (e.kind === "event") return canvas.announce("Event routes come from the tools' manifests.");
    if (e.kind !== "flow") return canvas.announce("Capabilities come from the tools' manifests.");
    if (!operator) return canvas.announce("Operators can disable or remove data flows");
    const f = e.flow;
    const m = modal({
      title: f.title, submit: null, cancel: null, minRole: "operator",
      body: html`<p>Disable this data flow, or remove it? Records already exchanged stay either way. A removed flow may be proposed again by the planner; a disabled one stays off.</p>`,
      footer: html`<button type="button" class="btn primary" data-act="dlg-disable" ${f.status === "disabled" ? "disabled" : ""}>Disable</button>
        <button type="button" class="btn danger" data-act="dlg-remove">${icon("trash")}Remove</button><button type="button" class="btn" data-close>Cancel</button>`,
      onClose: () => { if (model.edges.has(id)) canvas.focus(id); },
    });
    setTimeout(() => m.el.querySelector('[data-act="dlg-disable"]:not(:disabled)')?.focus(), 40);
    actions(m.el, {
      async "dlg-disable"() {
        try { await patch(`/flows/${enc(f.id)}`, { status: "disabled" }); toast("Flow disabled", "info"); canvas.announce("Data flow disabled"); } catch (err) { toast(err.message, "bad"); }
        m.close();
        load();
      },
      async "dlg-remove"() {
        try { await del(`/flows/${enc(f.id)}`); toast("Flow removed", "ok"); canvas.announce("Data flow removed"); } catch (err) { toast(err.message, "bad"); }
        m.close();
        load();
      },
    });
  }

  // ---------- filters, find, focus on selection ----------
  const neighbourhood = () => {
    const sel = canvas.selection;
    if (!sel) return null;
    const near = new Set([sel]);
    const e = model.edges.get(sel);
    if (e) { near.add(e.from.id); near.add(e.to.id); }
    for (const x of model.edges.values()) if (x.from.id === sel || x.to.id === sel) { near.add(x.id); near.add(x.from.id); near.add(x.to.id); }
    return near;
  };
  const matches = (id) => !find || String(item(id)?.label || "").toLowerCase().includes(find);
  const matchCount = () => [...model.items.keys()].filter(matches).length;

  function applyFilter() {
    const near = focusSelection ? neighbourhood() : null;
    if (!find && !near) return canvas.setFilter(null);
    canvas.setFilter((kind, id) => {
      if (near && !near.has(id)) return false;
      if (!find) return true;
      if (kind === "item") return matches(id);
      const e = model.edges.get(id);
      return !!e && (matches(e.from.id) || matches(e.to.id));
    });
  }

  let menu = null;
  function closeMenu() {
    if (!menu) return false;
    menu.remove();
    menu = null;
    const b = canvas.shell.querySelector('[data-act="map-filters"]');
    b.setAttribute("aria-expanded", "false");
    b.focus();
    return true;
  }
  function openMenu() {
    if (menu) return closeMenu();
    menu = document.createElement("div");
    menu.className = "cv-menu";
    menu.setAttribute("role", "dialog");
    menu.setAttribute("aria-label", "Map filters");
    const check = (key, text, legend) => html`<label class="check"><input type="checkbox" data-filter="${key}" ${filters[key] ? "checked" : ""}><span class="cv-legend ${legend}"></span>${text}</label>`;
    setHTML(menu, html`<h4>Show</h4>
      <label class="check"><input type="checkbox" checked disabled><span class="cv-legend"></span>Data flows</label>
      ${check("sso", "Single sign-on (always for the selection)", "sso")}${check("events", "Event routes", "event")}${check("capabilities", "Capabilities", "cap")}
      <h4>Data flows</h4>
      <div class="seg" role="group" aria-label="Which data flows">${[["all", "All"], ["failing", "Failing only"], ["proposed", "Proposed only"]].map(([k, t]) => html`<button type="button" data-flows="${k}" aria-pressed="${filters.flows === k}" class="${filters.flows === k ? "active" : ""}">${t}</button>`)}</div>
      <h4>Legend</h4><div class="faint" style="font-size:12px;line-height:1.9">
        <div><span class="cv-legend"></span>enabled (arrow: where the data goes)</div><div><span class="cv-legend proposed"></span>proposed, awaiting approval</div>
        <div><span class="cv-legend bad"></span>failing or repair pending</div><div><span class="cv-legend muted"></span>disabled</div></div>
      <h4>Hidden items (${hidden.size})</h4>
      ${hidden.size ? html`<div class="stack" style="gap:4px">${[...hidden].map((x) => html`<div class="row" style="justify-content:space-between;flex-wrap:nowrap"><span style="min-width:0;overflow-wrap:anywhere">${(data?.nodes || []).find((n) => n.id === x)?.label || (data?.apps || []).find((a) => a.id === x)?.label || x}</span>
        <button type="button" class="btn sm" data-unhide="${x}">Show</button></div>`)}</div>` : html`<p class="faint" style="font-size:12px">Hide items from your own map in their details panel. Others still see them.</p>`}`);
    canvas.shell.append(menu);
    canvas.shell.querySelector('[data-act="map-filters"]').setAttribute("aria-expanded", "true");
    menu.querySelector("input:not(:disabled)")?.focus();
    menu.addEventListener("change", (e) => {
      const key = e.target.dataset.filter;
      if (!key) return;
      filters[key] = e.target.checked;
      writePref("filters", filters);
      rebuild();
    });
    menu.addEventListener("click", (e) => {
      const flows = e.target.closest("[data-flows]")?.dataset.flows;
      const unhide = e.target.closest("[data-unhide]")?.dataset.unhide;
      if (flows) {
        filters.flows = flows;
        writePref("filters", filters);
        menu.querySelectorAll("[data-flows]").forEach((b) => { b.classList.toggle("active", b.dataset.flows === flows); b.setAttribute("aria-pressed", String(b.dataset.flows === flows)); });
        rebuild();
      }
      if (unhide) {
        hidden.delete(unhide);
        writePref("hidden", [...hidden]);
        closeMenu();
        rebuild();
        openMenu();
      }
    });
  }
  const outside = (e) => { if (menu && !menu.contains(e.target) && !e.target.closest('[data-act="map-filters"]')) closeMenu(); };
  document.addEventListener("pointerdown", outside);

  const findInput = canvas.shell.querySelector('[data-part="map-find"]');
  findInput.addEventListener("input", debounce(() => { find = findInput.value.trim().toLowerCase(); applyFilter(); notices(); }, 150));
  findInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      const first = canvas.scene && canvas.scene.lanes.flatMap((l) => (canvas.scene.order.get(l.id) || []).map((x) => x.id)).find(matches);
      if (first) { canvas.select(first, { reveal: true }); } else canvas.announce("No items match");
    }
    if (e.key === "Escape" && findInput.value) { e.preventDefault(); e.stopPropagation(); findInput.value = ""; find = ""; applyFilter(); notices(); }
  });

  actions(canvas.shell, {
    "map-filters": () => openMenu(),
    "map-focus"(_, btn) {
      focusSelection = !focusSelection;
      btn.setAttribute("aria-pressed", String(focusSelection));
      applyFilter();
      canvas.announce(focusSelection ? "Showing only what is connected to the selection" : "Showing everything");
    },
    async "map-reset"() {
      if (!(await confirmDialog("Reset arrangement", "Put every tool and hub app back in its default place? This changes the map for everyone.", "Reset"))) return;
      try { await store.reset(); toast("Arrangement reset", "ok"); } catch (err) { toast(err.message, "bad"); }
    },
    "map-import": () => openImport(),
    "map-retry": () => load(),
    "map-clear-find": () => { findInput.value = ""; find = ""; applyFilter(); notices(); },
  });

  // ---------- list view (the main screen-reader path) ----------
  let listWired = false;
  function renderList(el) {
    if (!data) return setHTML(el, html`<div class="empty faint">Loading...</div>`);
    if (!listWired) {
      listWired = true;
      wireFlows(el, { find: findFlow, refresh, names });
      wireIdentity(el, () => data.identity, refresh);
      actions(el, {
        "ls-select": (d) => { canvas.setList(false); setTimeout(() => canvas.select(d.id, { reveal: true }), 30); },
        "ls-connect": (d) => connectTo(d.id),
        "ls-sso": (d) => ssoPicker(toolRef(d.id), d.id),
      });
    }
    const tools = [...model.items.values()].filter((x) => x.kind === "tool").sort(compareItems);
    const apps = [...model.items.values()].filter((x) => x.kind === "app");
    const flows = (data.flows || []).slice().sort((x, y) => ({ proposed: 0, enabled: 1, disabled: 2 }[x.status] - { proposed: 0, enabled: 1, disabled: 2 }[y.status]) || x.title.localeCompare(y.title));
    setHTML(el, html`
      <h3>Hub apps</h3>
      <div class="table-wrap"><table class="table compact"><thead><tr><th>App</th><th>Takes</th><th>Data flows</th><th></th></tr></thead><tbody>
        ${apps.map((a) => html`<tr><td><a href="${a.href}">${a.label}</a></td><td>${a.domains.map((d) => domainLabel(d)).join(", ")}</td><td>${a.flowCount}${a.failing ? html` ${badge(`${a.failing} failing`, "bad")}` : ""}</td>
          <td><button type="button" class="btn sm" data-act="ls-select" data-id="${a.id}">Select on map</button></td></tr>`)}</tbody></table></div>
      <h3>Tools</h3>
      ${tools.length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Tool</th><th>Lane</th><th>Connection</th><th>Data flows</th><th>Single sign-on</th><th></th></tr></thead><tbody>
        ${tools.map((t) => html`<tr><td><a href="#/tools/${enc(t.node.ref)}">${t.label}</a>${t.is_idp ? html` ${badge("IdP", "info")}` : ""}</td><td>${LANE_TITLE[laneOf(t, stored())]}</td>
          <td>${t.connection ? html`<code>${t.connection.kind}</code>${t.connection.tested?.ok === false ? html` ${badge("test failed", "bad")}` : ""}` : html`<span class="muted">none</span>`}</td>
          <td>${t.flowCount}${t.failing ? html` ${badge(`${t.failing} failing`, "bad")}` : ""}${t.proposed ? html` ${badge(`${t.proposed} proposed`, "warn")}` : ""}</td>
          <td>${t.sso ? (t.sso.state === "connected" ? `through ${t.sso.name}` : badge("awaiting approval", "warn")) : html`<span class="muted">-</span>`}</td>
          <td><div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end"><button type="button" class="btn sm" data-act="ls-select" data-id="${t.id}">Select on map</button>
            <button type="button" class="btn sm" data-act="ls-connect" data-id="${t.id}" data-min-role="operator">Connect to...</button>
            ${!t.is_idp && (data.identity?.providers || []).length ? html`<button type="button" class="btn sm" data-act="ls-sso" data-id="${t.id}" data-min-role="operator">Single sign-on...</button>` : ""}</div></td></tr>`)}
        </tbody></table></div>` : html`<p class="muted">No tools yet.</p>`}
      ${hidden.size ? html`<p class="faint" style="font-size:12.5px;margin-top:6px">${hidden.size} item${hidden.size === 1 ? " is" : "s are"} hidden from your map (Filters > Hidden items).</p>` : ""}
      <h3>Data flows</h3>${flowsTable(flows, { names: names(), empty: "No data flows yet." })}
      <div style="margin-top:16px">${identityCard(data.identity || { providers: [], tools: [] })}</div>
      <h3>Event routes</h3>
      ${(data.events || []).length ? html`<div class="table-wrap"><table class="table compact"><thead><tr><th>From</th><th>To</th><th>Event</th><th>Webhook</th><th>Last delivery</th></tr></thead><tbody>
        ${data.events.map((ev) => html`<tr><td>${label(ev.source)}</td><td>${label(ev.target)}</td><td><code>${ev.event}</code></td><td>${ev.has_webhook ? badge("set", "ok") : badge("none", "warn")}</td>
          <td>${ev.last_delivery ? html`${ev.last_delivery.ok ? badge("ok") : badge("failed", "bad")} ${timeAgo(ev.last_delivery.ts)}` : html`<span class="muted">-</span>`}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">No event routes.</p>`}`);
  }

  return {
    dispose() {
      disposed = true;
      offs.forEach((off) => off());
      window.removeEventListener("atrium:events-reconnected", onReconnect);
      document.removeEventListener("visibilitychange", onVisible);
      document.removeEventListener("pointerdown", outside);
      clearInterval(timer);
      cancelAnimationFrame(queued);
      canvas.destroy();
    },
    select(kind, id) {
      if (!data) { pendingLink = [kind, id]; return; }
      followLink([kind, id]);
    },
  };
}
