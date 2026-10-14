// The canvas engine (canvas-design 4): a lane-based SVG map with a camera, keyed rendering, a pointer state machine
// (select, pan, pinch, reorder, connect by drag or click-click), keyboard navigation and modes, tooltips, a focus ring,
// a live region and a List view host. Views supply an adapter that builds the model and draws items; the engine
// never interprets the data. Everything an adapter draws goes through el()/txt() (createElementNS + textContent),
// so text from tools and devices is never parsed as markup.
//
//   const canvas = createCanvas(container, {view, label, roledescription, help, lanes, gutter, detour, model, layout,
//                                           permissions, adapter, bar, markers});
//   (detour: edges that skip lanes run below the items in between instead of through them; see route.js)
//   canvas.update(model, layout)  canvas.patchEdge(id, edge|null)  canvas.applyLayout(items)
//   canvas.select(id, {reveal})   canvas.fit()  canvas.zoomBy(f)  canvas.setFilter(fn)  canvas.setList(bool)
//   canvas.setFocusMode(bool)     canvas.announce(text)  canvas.setPermissions(p)  canvas.showInspector(open)
//   canvas.setNotice(content, tone)  canvas.setLive(ok)  canvas.destroy()
//
// adapter: size(item) -> {w, h}; lane(item, stored) -> lane id; compare(a, b) (default order in a lane);
//   signature(item) -> string (an item is redrawn only when it changes); draw(item, g, ctx);
//   edgeStyle(edge) -> {cls, marker, arrow: "to"|"from"|"both"|null, chip, chipSelected, glyph, width, under: "hatch"|"halo"|null};
//   name(id); role(id);
//   tip(id) -> html``; grips(item) -> ["left"|"right"]; canConnect(a, b) -> {ok, reason}; canMove(item) -> {lanes};
//   onConnect(a, b), onMove(id, {lane, index, changes}), onSelect(id|null), onOpen(id), onDelete(id), onKey(key, id),
//   onUndo(), onRedo(), onEscape() -> bool, connectHint() -> why connecting is off, summary() -> "14 tools, ...", list(el),
//   helpRows -> [[keys, text]].
import { eventsOk } from "../api.js";
import { ICONS, debounce, html, icon, modal, setHTML, toast } from "../ui.js";
import * as camera from "./camera.js";
import { insertionIndex, laneAt, planMove } from "./lanes.js";
import { scene } from "./scene.js";
import { ellipsize, font, measure } from "./text.js";

const NS = "http://www.w3.org/2000/svg";
const MARKERS = ["flow", "ok", "proposed", "bad", "event", "cap", "muted", "accent"];
const DRAG_PX = { mouse: 4, pen: 4, touch: 10 }; // [U] thresholds
const EDGE_ZONE = 32; // auto-pan when the pointer is this close to the viewport edge
const LOD1 = 0.5, LOD2 = 0.35;
const CHIP_FONT = font(11, 600);
let seq = 0;

/** createElementNS with attributes; appended to `parent` when given. Never sets markup. */
export function el(tag, attrs = {}, parent = null) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined && v !== false) node.setAttribute(k, String(v));
  if (parent) parent.append(node);
  return node;
}

/** An SVG <text> whose content is set with textContent (untrusted text stays text). */
export function txt(parent, text, attrs = {}) {
  const node = el("text", attrs, parent);
  node.textContent = String(text ?? "");
  return node;
}

const reducedMotion = () => window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
const coarse = () => window.matchMedia?.("(pointer: coarse)").matches;
const store = {
  get(key) { try { return localStorage.getItem(key); } catch { return null; } },
  set(key, value) { try { localStorage.setItem(key, value); } catch { /* private mode */ } },
};

export function createCanvas(container, opts) {
  const { view, label, roledescription, adapter, gutter = 176 } = opts;
  const laneDefs = opts.lanes;
  const id = `cv${++seq}`;
  const helpId = `${id}-help`;
  const debug = store.get("hub.canvas.debug") === "1";
  let model = opts.model || { items: new Map(), edges: new Map() };
  let layout = opts.layout || { version: 0, items: {} };
  let permissions = { move: false, connect: false, ...(opts.permissions || {}) };
  const st = {
    cam: { k: 1, tx: 0, ty: 0 }, vp: { w: 800, h: 500, insets: { top: 0, right: 0, bottom: 0, left: 0 } }, rect: null, placed: false,
    sel: null, hover: null, focus: null, mode: "idle", gesture: null, ghost: null, insert: null, pick: null, kb: null,
    filter: null, list: false, full: false, scene: null, deferred: null, live: true, tipFor: null, popover: null,
  };
  const pointers = new Map();
  const disposers = [];
  const on = (target, type, fn, o) => { target.addEventListener(type, fn, o); disposers.push(() => target.removeEventListener(type, fn, o)); };

  // ---------- DOM ----------
  const shell = document.createElement("div");
  shell.className = "canvas-shell";
  shell.dataset.view = view;
  setHTML(shell, html`
    <div class="canvas-bar" role="group" aria-label="Map controls">
      <button type="button" class="icon-btn sm" data-act="cv-zoom-out" title="Zoom out (-)" aria-label="Zoom out">${icon("minus")}</button>
      <button type="button" class="btn sm cv-zoom" data-act="cv-zoom-reset" title="Zoom to 100%" aria-label="Zoom 100%">100%</button>
      <button type="button" class="icon-btn sm" data-act="cv-zoom-in" title="Zoom in (+)" aria-label="Zoom in">${icon("plus")}</button>
      <button type="button" class="btn sm" data-act="cv-fit" title="Fit the map (0)">Fit</button>
      <span class="cv-sep" aria-hidden="true"></span>
      ${opts.bar || ""}
      <span class="spacer"></span>
      <span class="badge warn" data-part="cv-live" hidden>${icon("pause")}Live updates paused</span>
      <button type="button" class="btn sm" data-act="cv-list" aria-pressed="false" title="Map or list (L)">${icon("file")}<span>List</span></button>
      <button type="button" class="icon-btn sm" data-act="cv-full" aria-pressed="false" title="Focus mode (F)" aria-label="Focus mode">${icon("expand")}</button>
      <button type="button" class="icon-btn sm" data-act="cv-help" title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts">${icon("keyboard")}</button>
    </div>
    <div class="notice" data-part="canvas-notice" hidden></div>
    <a class="skip-link" href="#" data-act="cv-skip">Skip to list view</a>
    <div class="canvas-body">
      <div class="canvas-stage">
        <div class="canvas-pill" hidden></div>
        <div class="canvas-tip" hidden aria-hidden="true"></div>
        <div class="canvas-pop" hidden></div>
        ${debug ? html`<div class="canvas-debug"></div>` : ""}
      </div>
      <aside class="canvas-inspector" aria-label="Details" hidden></aside>
    </div>
    <div class="canvas-list" hidden></div>
    <p class="sr-only" id="${helpId}">${opts.help || "Arrow keys move between items, Enter opens the details, Space selects, L shows the list view, question mark lists every shortcut."}</p>
    <div class="sr-only" aria-live="polite" data-live></div>`);
  container.append(shell);
  const $ = (sel) => shell.querySelector(sel);
  const stage = $(".canvas-stage"), inspector = $(".canvas-inspector"), listEl = $(".canvas-list"), body = $(".canvas-body");
  const tip = $(".canvas-tip"), pill = $(".canvas-pill"), pop = $(".canvas-pop"), live = $("[data-live]"), dbg = $(".canvas-debug");

  const svg = el("svg", { class: "canvas", tabindex: 0, role: "graphics-document", "aria-roledescription": roledescription,
    "aria-describedby": helpId, focusable: "true" });
  stage.prepend(svg);
  const defs = el("defs", {}, svg);
  // static markup only: markers, the hatch pattern and icon symbols from ui.js's constant ICONS
  defs.innerHTML = [
    ...[...MARKERS, ...(opts.markers || [])].map((m) => `<marker id="${id}-mk-${m}" class="mk mk-${m}" viewBox="0 0 10 10" refX="9" refY="5"
      markerUnits="userSpaceOnUse" markerWidth="10" markerHeight="10" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z"/></marker>`),
    `<marker id="${id}-mk-ghost" class="mk mk-accent" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="12" markerHeight="12" orient="auto"><path d="M0,0 L10,5 L0,10 z"/></marker>`,
    `<pattern id="${id}-hatch" patternUnits="userSpaceOnUse" width="6" height="6" patternTransform="rotate(45)"><line class="hatch-line" x1="0" y1="0" x2="0" y2="6"/></pattern>`,
    ...Object.entries(ICONS).map(([name, body]) => `<symbol id="${id}-i-${name}" viewBox="0 0 24 24">${body}</symbol>`),
  ].join("");
  el("rect", { class: "canvas-bg", width: "100%", height: "100%" }, svg);
  const camG = el("g", { class: "cam" }, svg);
  const lanesG = el("g", { class: "l-lanes" }, camG);
  const edgesG = el("g", { class: "l-edges" }, camG);
  const itemsG = el("g", { class: "l-items" }, camG);
  const chipsG = el("g", { class: "l-chips" }, camG);
  const screenG = el("g", { class: "l-screen" }, svg);

  /** Icon <use> for adapters: `use(parent, "box", x, y, size)`. */
  const use = (parent, name, x, y, size = 18, attrs = {}) => el("use", { href: `#${id}-i-${ICONS[name] ? name : "grid"}`, x, y, width: size, height: size, class: "glyph", ...attrs }, parent);
  const drawCtx = { el, txt, use, ellipsize, font, hatch: `url(#${id}-hatch)` };

  // ---------- helpers ----------
  const itemEls = new Map(); // id -> {g, sig}
  const edgeEls = new Map(); // id -> {g, line, hit, sig}
  const chipEls = new Map();
  let placedChips = []; // chip boxes of the current render, to keep chips from covering each other
  const rectOf = (itemId) => st.scene?.rects.get(itemId);
  const screenPt = (e) => ({ x: e.clientX - (st.rect?.left || 0), y: e.clientY - (st.rect?.top || 0) });
  const kindOf = (x) => (model.items.has(x) ? "item" : model.edges.has(x) ? "edge" : null);
  const nameOf = (x) => `${adapter.name(x)}${st.sel === x ? ", selected" : ""}`;
  const laneTitle = (laneId) => laneDefs.find((l) => l.id === laneId)?.title || laneId;

  function announce(text) {
    live.textContent = "";
    setTimeout(() => { live.textContent = text; }, 30);
  }

  // ---------- frame scheduling ----------
  let frame = 0;
  const dirty = new Set();
  function invalidate(...parts) {
    parts.forEach((p) => dirty.add(p));
    if (!frame) frame = requestAnimationFrame(flush);
  }
  function flush() {
    frame = 0;
    const t0 = performance.now();
    if (dirty.has("scene")) relayout();
    if (dirty.has("scene") || dirty.has("items") || dirty.has("edges")) render();
    if (dirty.size) renderCamera();
    dirty.clear();
    if (debug) showDebug({ frame: performance.now() - t0 });
  }

  // ---------- layout and keyed render ----------
  let timings = {};
  const mark = (name) => { if (debug) performance.mark(`canvas:${view}:${name}`); };
  const measureSpan = (name) => { if (debug) try { performance.measure(`canvas:${view}:${name}`, `canvas:${view}:${name}:start`, `canvas:${view}:${name}:end`); } catch { /* cleared */ } };
  function relayout() {
    mark("scene:start");
    const t0 = performance.now();
    st.scene = scene(model, laneDefs, layout.items || {}, { laneOf: (item, stored) => adapter.lane(item, stored), compare: adapter.compare,
      size: (item) => adapter.size(item), gutter, detour: !!opts.detour });
    timings.scene = performance.now() - t0;
    mark("scene:end");
    measureSpan("scene");
    place();
  }

  /** The first camera, once the stage has a size and the model has items: this viewer's last one, else fit. */
  function place() {
    if (st.placed || !st.rect?.width || !st.scene?.rects.size) return;
    st.placed = true;
    st.cam = camera.parseCamera(store.get(`hub.canvas.${view}.camera`)) || camera.fit(bounds(), st.vp);
  }

  function bounds() {
    const rects = st.scene ? [...st.scene.rects.values()] : [];
    return camera.boundsOf(rects.length ? [...rects, ...st.scene.boxes.values()].map((r) => ({ ...r, y: Math.max(0, r.y) })) : []);
  }

  function render() {
    mark("render:start");
    const t0 = performance.now();
    const sc = st.scene;
    if (!sc) return;
    // lanes
    const laneH = Math.max(0, ...[...sc.boxes.values()].map((b) => b.h));
    lanesG.replaceChildren();
    for (const lane of sc.lanes) {
      const g = el("g", { class: `lane lane-${lane.id}`, "data-hit": "lane", "data-lane": lane.id }, lanesG);
      el("rect", { class: "lane-bg", x: lane.x - 12, y: 0, width: lane.width + 24, height: laneH, rx: 12 }, g);
      txt(g, lane.title, { class: "lane-title", x: lane.x + lane.width / 2, y: 30, "text-anchor": "middle" });
    }
    // items (keyed: redrawn only when their signature or size changes)
    const seen = new Set();
    for (const [itemId, r] of sc.rects) {
      const item = model.items.get(itemId);
      if (!item) continue;
      seen.add(itemId);
      let entry = itemEls.get(itemId);
      const sig = `${adapter.signature(item)}|${r.w}x${r.h}`;
      if (!entry) {
        const g = el("g", { class: "item", "data-hit": "item", "data-id": itemId, role: "graphics-object", tabindex: -1 }, itemsG);
        entry = { g, sig: null };
        itemEls.set(itemId, entry);
      }
      if (entry.sig !== sig) {
        entry.g.replaceChildren();
        adapter.draw(item, entry.g, { ...drawCtx, w: r.w, h: r.h });
        entry.sig = sig;
      }
      if (st.gesture?.dragging !== itemId) entry.g.setAttribute("transform", `translate(${r.x} ${r.y})`);
      entry.g.setAttribute("aria-roledescription", adapter.role(itemId));
      entry.g.setAttribute("aria-label", nameOf(itemId));
      entry.g.classList.toggle("selected", st.sel === itemId);
      entry.g.classList.toggle("dim", !!st.filter && !st.filter("item", itemId));
    }
    for (const [itemId, entry] of itemEls) if (!seen.has(itemId)) { entry.g.remove(); itemEls.delete(itemId); }
    // edges and their chips
    const seenE = new Set();
    placedChips = [];
    for (const [edgeId, edge] of model.edges) {
      const geo = sc.routes.get(edgeId);
      if (!geo) continue;
      seenE.add(edgeId);
      const s = adapter.edgeStyle(edge);
      let entry = edgeEls.get(edgeId);
      if (!entry) {
        const g = el("g", { "data-hit": "edge", "data-id": edgeId, role: "graphics-symbol", tabindex: -1 }, edgesG);
        entry = { g, hit: el("path", { class: "hit" }, g), line: el("path", { class: "line" }, g), sig: null };
        edgeEls.set(edgeId, entry);
      }
      const sig = `${geo.d}|${s.cls}|${s.arrow}|${s.marker}|${s.width || ""}|${s.under || ""}`;
      if (entry.sig !== sig) {
        entry.hit.setAttribute("d", geo.d);
        entry.line.setAttribute("d", geo.d);
        // an underlay below the line: "hatch" (any service) or "halo" (a possible policy violation)
        if (s.under) {
          entry.under ||= entry.g.insertBefore(el("path", {}), entry.line);
          entry.under.setAttribute("class", `under ${s.under}`);
          entry.under.setAttribute("d", geo.d);
          if (s.under === "hatch") entry.under.style.stroke = drawCtx.hatch; else entry.under.style.removeProperty("stroke");
        } else if (entry.under) {
          entry.under.remove();
          entry.under = null;
        }
        const mk = `url(#${id}-mk-${s.marker || "flow"})`;
        entry.line.setAttribute("marker-end", s.arrow === "to" || s.arrow === "both" ? mk : "none");
        entry.line.setAttribute("marker-start", s.arrow === "from" || s.arrow === "both" ? mk : "none");
        if (s.width) entry.line.style.strokeWidth = `${s.width}px`; else entry.line.style.removeProperty("stroke-width");
        entry.sig = sig;
      }
      entry.g.setAttribute("class", `edge ${s.cls || ""}${st.sel === edgeId ? " selected" : ""}${st.focus === edgeId ? " focused" : ""}${st.filter && !st.filter("edge", edgeId) ? " dim" : ""}`);
      entry.g.setAttribute("aria-roledescription", adapter.role(edgeId));
      entry.g.setAttribute("aria-label", nameOf(edgeId));
      const chipText = st.sel === edgeId || st.focus === edgeId ? s.chipSelected || s.chip : s.chip;
      drawChip(edgeId, chipText, s, geo.label);
    }
    for (const [edgeId, entry] of edgeEls) if (!seenE.has(edgeId)) { entry.g.remove(); edgeEls.delete(edgeId); }
    for (const [edgeId, chip] of chipEls) if (!seenE.has(edgeId)) { chip.g.remove(); chipEls.delete(edgeId); }
    roving();
    svg.setAttribute("aria-label", `${label}: ${adapter.summary()}`);
    timings.render = performance.now() - t0;
    mark("render:end");
    measureSpan("render");
  }

  function drawChip(edgeId, text, s, at) {
    let chip = chipEls.get(edgeId);
    if (!text) {
      if (chip) { chip.g.remove(); chipEls.delete(edgeId); }
      return;
    }
    const sig = `${text}|${s.glyph || ""}|${s.cls}|${at.x}|${at.y}|${st.sel === edgeId || st.focus === edgeId}`;
    if (chip?.sig === sig) { placedChips.push(chip.box); return; }
    if (!chip) {
      chip = { g: el("g", { "data-hit": "edge", "data-id": edgeId, "aria-hidden": "true" }, chipsG) };
      chipEls.set(edgeId, chip);
    }
    chip.g.replaceChildren();
    const label = ellipsize(text, 150, CHIP_FONT);
    const w = Math.ceil(measure(label, CHIP_FONT)) + (s.glyph ? 30 : 16);
    chip.g.setAttribute("class", `chip ${s.cls || ""}${st.sel === edgeId || st.focus === edgeId ? " sel" : ""}`);
    let x = at.align === "start" ? at.x : at.align === "end" ? at.x - w : at.x - w / 2;
    let y = at.y - 10;
    for (let i = 0; i < 4 && placedChips.some((r) => x < r.x + r.w && r.x < x + w && y < r.y + 20 && r.y < y + 20); i++) y += 22;
    chip.box = { x, y, w };
    placedChips.push(chip.box);
    chip.g.setAttribute("transform", `translate(${Math.round(x)} ${Math.round(y)})`);
    el("rect", { width: w, height: 20, rx: 10 }, chip.g);
    if (s.glyph) use(chip.g, s.glyph, 7, 3, 14);
    txt(chip.g, label, { x: s.glyph ? 24 : 8, y: 14 });
    chip.sig = sig;
  }

  // ---------- camera and screen layer ----------
  function renderCamera() {
    const { k, tx, ty } = st.cam;
    camG.setAttribute("transform", `translate(${tx} ${ty}) scale(${k})`);
    svg.classList.toggle("lod-1", k < LOD1);
    svg.classList.toggle("lod-2", k < LOD2);
    $(".cv-zoom").textContent = `${Math.round(k * 100)}%`;
    renderScreen();
    settleMarkers();
    saveCamera();
  }

  const settleMarkers = debounce(() => {
    const size = String(10 / st.cam.k);
    defs.querySelectorAll(`marker.mk:not(#${id}-mk-ghost)`).forEach((m) => { m.setAttribute("markerWidth", size); m.setAttribute("markerHeight", size); });
  }, 150);
  const saveCamera = debounce(() => store.set(`hub.canvas.${view}.camera`, JSON.stringify(st.cam)), 400);

  function toScreenRect(r, pad = 0) {
    const p = camera.toScreen(st.cam, r.x, r.y);
    return { x: p.x - pad, y: p.y - pad, w: r.w * st.cam.k + 2 * pad, h: r.h * st.cam.k + 2 * pad };
  }

  function renderScreen() {
    screenG.replaceChildren();
    // focus ring (screen space: constant size at any zoom)
    const active = document.activeElement;
    const focusId = active && svg.contains(active) ? st.kb?.target || active.closest?.("[data-hit]")?.dataset.id : null;
    if (focusId) {
      let r = null;
      if (model.items.has(focusId) && rectOf(focusId)) r = toScreenRect(rectOf(focusId), 4);
      else if (edgeEls.has(focusId)) {
        try {
          const b = edgeEls.get(focusId).line.getBBox();
          r = toScreenRect({ x: b.x, y: b.y, w: b.width, h: b.height }, 6);
        } catch { /* not rendered */ }
      }
      if (r) {
        el("rect", { class: "ring-halo", x: r.x, y: r.y, width: r.w, height: r.h, rx: 10 }, screenG);
        el("rect", { class: "ring", x: r.x, y: r.y, width: r.w, height: r.h, rx: 10 }, screenG);
      }
    }
    // connect grips on the hovered or selected item
    const gripFor = st.mode === "idle" || st.mode === "press" ? (coarse() ? st.sel : st.hover || st.sel) : null;
    if (permissions.connect && gripFor && model.items.has(gripFor) && rectOf(gripFor)) {
      const r = toScreenRect(rectOf(gripFor));
      const radius = coarse() ? 16 : 12;
      for (const side of adapter.grips(model.items.get(gripFor))) {
        const cx = side === "right" ? r.x + r.w : r.x, cy = r.y + r.h / 2;
        const g = el("g", { class: "grip", "data-hit": "grip", "data-id": gripFor, "data-side": side, "aria-hidden": "true" }, screenG);
        el("circle", { cx, cy, r: radius }, g);
        el("path", { d: `M${cx - 5},${cy} H${cx + 5} M${cx},${cy - 5} V${cy + 5}` }, g);
      }
    }
    // ghost arrow (connect by drag, keyboard connect)
    if (st.ghost) {
      const { x1, y1, x2, y2, ok } = st.ghost;
      el("path", { class: `ghost ${ok === false ? "no" : ""}`, d: `M${x1},${y1} L${x2},${y2}`, "marker-end": `url(#${id}-mk-ghost)` }, screenG);
    }
    // insertion bar (reorder)
    if (st.insert) {
      const lane = st.scene.lanes.find((l) => l.id === st.insert.lane);
      if (lane) {
        const p1 = camera.toScreen(st.cam, lane.x - 6, st.insert.y), p2 = camera.toScreen(st.cam, lane.x + lane.width + 6, st.insert.y);
        el("line", { class: "insert-bar", x1: p1.x, y1: p1.y, x2: p2.x, y2: p2.y }, screenG);
      }
    }
  }

  let anim = 0;
  function moveCamera(target, animate = true) {
    cancelAnimationFrame(anim);
    if (!animate || reducedMotion()) {
      st.cam = target;
      return invalidate("camera");
    }
    const from = st.cam, t0 = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - t0) / 180);
      st.cam = camera.lerp(from, target, t);
      invalidate("camera");
      if (t < 1) anim = requestAnimationFrame(step);
    };
    anim = requestAnimationFrame(step);
  }

  function fit() { moveCamera(camera.fit(bounds(), st.vp)); }
  function zoomBy(f) { moveCamera(camera.zoomTo(st.cam, st.vp, st.cam.k * f)); }

  function reveal(x) {
    let r = rectOf(x);
    if (!r && edgeEls.has(x)) {
      try { const b = edgeEls.get(x).line.getBBox(); r = { x: b.x, y: b.y, w: b.width, h: b.height }; } catch { r = null; }
    }
    if (r) moveCamera(camera.ensureVisible(st.cam, r, st.vp));
  }

  // ---------- selection, focus ----------
  function select(x, { reveal: show = false, quiet = false } = {}) {
    if (x !== null && !kindOf(x)) x = null;
    const changed = st.sel !== x;
    st.sel = x;
    if (show && x) reveal(x);
    invalidate("items", "edges");
    if (changed) {
      adapter.onSelect?.(x);
      if (!quiet) announce(x ? `${adapter.name(x)}, selected` : "Selection cleared");
    }
  }

  function roving() {
    const current = st.focus && (itemEls.get(st.focus)?.g || edgeEls.get(st.focus)?.g);
    const first = current || itemEls.get(st.sel)?.g || firstItemEl();
    for (const { g } of itemEls.values()) g.setAttribute("tabindex", g === first ? "0" : "-1");
    for (const { g } of edgeEls.values()) g.setAttribute("tabindex", g === first ? "0" : "-1");
    svg.setAttribute("tabindex", first ? "-1" : "0");
  }
  function firstItemEl() {
    const sc = st.scene;
    if (!sc) return null;
    for (const lane of sc.lanes) {
      const first = sc.order.get(lane.id)?.[0];
      if (first && itemEls.has(first.id)) return itemEls.get(first.id).g;
    }
    return null;
  }

  function focusOn(x) {
    const g = itemEls.get(x)?.g || edgeEls.get(x)?.g;
    if (!g) return;
    st.focus = x;
    roving();
    g.focus({ preventScroll: true });
    reveal(x);
    showTip(x, null);
    invalidate("edges", "camera");
  }

  const laneItems = (laneId) => (st.scene?.order.get(laneId) || []).map((e) => e.id).filter((x) => itemEls.has(x));
  const nonEmptyLanes = () => st.scene.lanes.filter((l) => laneItems(l.id).length);

  function neighbour(x, dir) {
    if (!rectOf(x)) return x;
    const lane = rectOf(x).lane;
    const list = laneItems(lane);
    const i = list.indexOf(x);
    if (dir === "up") return list[Math.max(0, i - 1)];
    if (dir === "down") return list[Math.min(list.length - 1, i + 1)];
    if (dir === "home") return list[0];
    if (dir === "end") return list.at(-1);
    const lanes = nonEmptyLanes();
    const li = lanes.findIndex((l) => l.id === lane);
    const next = lanes[li + (dir === "left" ? -1 : 1)];
    if (!next) return x;
    const y = rectOf(x).y + rectOf(x).h / 2;
    return laneItems(next.id).reduce((best, c) => {
      const r = rectOf(c), d = Math.abs(r.y + r.h / 2 - y);
      return !best || d < best.d ? { id: c, d } : best;
    }, null)?.id ?? x;
  }

  /** The item a connection was reached from with E (else its source end). */
  const edgeBase = (edgeId) => {
    const e = model.edges.get(edgeId);
    return st.edgeBase && (e.from.id === st.edgeBase || e.to.id === st.edgeBase) ? st.edgeBase : e.from.id;
  };
  const edgesOf = (x) => [...model.edges.values()].filter((e) => (e.from.id === x || e.to.id === x) && edgeEls.has(e.id)).map((e) => e.id);

  // ---------- tooltip and popover ----------
  let tipTimer = 0, tipHide = 0;
  /** `note`: why the item is not a valid connect target, shown above its usual tooltip (canvas-design 4.6). */
  function showTip(x, at, delay = 0, note = null) {
    clearTimeout(tipTimer);
    clearTimeout(tipHide);
    tipTimer = setTimeout(() => {
      const content = x && adapter.tip?.(x);
      if (!content && !note) return hideTip();
      st.tipFor = x;
      setHTML(tip, note ? html`<div class="tip-why">${icon("alert")}<span>${note}</span></div>${content || ""}` : content);
      tip.hidden = false;
      let p = at;
      if (!p) {
        const r = rectOf(x) ? toScreenRect(rectOf(x)) : null;
        p = r ? { x: r.x + r.w / 2, y: r.y + r.h + 8 } : { x: st.vp.w / 2, y: 40 };
      } else p = { x: at.x + 14, y: at.y + 16 };
      const w = tip.offsetWidth, h = tip.offsetHeight;
      tip.style.left = `${Math.max(4, Math.min(st.vp.w - w - 4, p.x - (at ? 0 : w / 2)))}px`;
      tip.style.top = `${p.y + h > st.vp.h - 4 ? Math.max(4, p.y - h - 30) : p.y}px`;
    }, delay);
  }
  function hideTip(soon = 0) {
    clearTimeout(tipTimer);
    clearTimeout(tipHide);
    const doHide = () => { tip.hidden = true; st.tipFor = null; };
    if (soon) tipHide = setTimeout(doHide, soon); else doHide();
  }
  on(tip, "pointerenter", () => clearTimeout(tipHide));
  on(tip, "pointerleave", () => hideTip(150));

  function closePopover() {
    if (pop.hidden) return false;
    pop.hidden = true;
    pop.replaceChildren();
    return true;
  }

  /** Several edges under one click: a small list of buttons to pick one (canvas-design 4.6, F12). */
  function chooseEdge(ids, p) {
    setHTML(pop, html`<div class="faint" style="font-size:12px;margin-bottom:4px">${ids.length} connections here</div>
      ${ids.map((x) => html`<button type="button" class="menu-item" data-pick="${x}">${adapter.name(x)}</button>`)}`);
    pop.hidden = false;
    pop.style.left = `${Math.max(4, Math.min(st.vp.w - 300, p.x))}px`;
    pop.style.top = `${Math.max(4, Math.min(st.vp.h - pop.offsetHeight - 4, p.y))}px`;
    pop.querySelector("button")?.focus();
  }
  on(pop, "click", (e) => {
    const b = e.target.closest("[data-pick]");
    if (!b) return;
    closePopover();
    select(b.dataset.pick);
    focusOn(b.dataset.pick);
  });

  // ---------- modes ----------
  function setPill(text) {
    pill.hidden = !text;
    pill.textContent = text || "";
  }

  function cancelMode(silent = false) {
    const had = st.mode !== "idle" || st.kb || st.pick;
    if (st.gesture?.dragging) {
      const r = rectOf(st.gesture.dragging);
      const entry = itemEls.get(st.gesture.dragging);
      if (entry && r) { entry.g.setAttribute("transform", `translate(${r.x} ${r.y})`); entry.g.classList.remove("dragging"); }
    }
    if (st.gesture?.pointerId !== undefined && svg.hasPointerCapture?.(st.gesture.pointerId)) {
      try { svg.releasePointerCapture(st.gesture.pointerId); } catch { /* gone */ }
    }
    st.gesture = null;
    st.ghost = null;
    st.insert = null;
    st.pick = null;
    st.kb = null;
    st.mode = "idle";
    svg.classList.remove("connecting", "moving", "panning");
    itemEls.forEach(({ g }) => g.classList.remove("target-ok", "target-no", "kb-target"));
    setPill("");
    applyDeferred();
    invalidate("camera");
    if (had && !silent) announce("Cancelled");
    return had;
  }

  function markTargets(from) {
    for (const [x, { g }] of itemEls) {
      if (x === from) continue;
      const verdict = adapter.canConnect(from, x);
      g.classList.toggle("target-ok", verdict.ok);
      g.classList.toggle("target-no", !verdict.ok);
    }
  }

  function startPick(from) {
    cancelMode(true);
    st.mode = "pickTarget";
    st.pick = from;
    markTargets(from);
    svg.classList.add("connecting");
    setPill("Choose a target · Esc to cancel");
    announce(`Connect ${adapter.name(from)}: choose a target, or press Escape to cancel`);
  }

  function tryConnect(from, to) {
    const verdict = adapter.canConnect(from, to);
    cancelMode(true);
    if (!verdict.ok) {
      toast(verdict.reason, "warn");
      announce(verdict.reason);
      return;
    }
    adapter.onConnect?.(from, to);
  }

  function itemAt(clientX, clientY, except) {
    for (const node of document.elementsFromPoint(clientX, clientY)) {
      const hit = node.closest?.("[data-hit=item]");
      if (hit && svg.contains(hit) && hit.dataset.id !== except) return hit.dataset.id;
    }
    return null;
  }

  function dropSlot(itemId, world) {
    const item = model.items.get(itemId);
    const allowed = adapter.canMove(item)?.lanes || [];
    const lane = laneAt(st.scene.lanes, world.x, gutter);
    if (!lane || !allowed.includes(lane)) return null;
    const others = laneItems(lane).filter((x) => x !== itemId).map((x) => ({ id: x, ...rectOf(x) }));
    const index = insertionIndex(others, world.y);
    const prev = others[index - 1], next = others[index];
    const y = prev && next ? (prev.y + prev.h + next.y) / 2 : prev ? prev.y + prev.h + 12 : next ? next.y - 12 : 56;
    return { lane, index, y };
  }

  function commitMove(itemId, slot) {
    const entries = (st.scene.order.get(slot.lane) || []).filter((e) => e.id !== itemId);
    const from = rectOf(itemId);
    const fromEntries = st.scene.order.get(from.lane) || [];
    const oldIndex = fromEntries.findIndex((e) => e.id === itemId);
    if (slot.lane === from.lane && (slot.index === oldIndex)) return false;
    const changes = planMove(entries, itemId, slot.index);
    adapter.onMove?.(itemId, { lane: slot.lane, index: slot.index, changes, from: { lane: from.lane, index: oldIndex } });
    announce(`${model.items.get(itemId)?.label || "Item"} moved to position ${slot.index + 1} in ${laneTitle(slot.lane)}`);
    return true;
  }

  // ---------- pointer state machine ----------
  function onDown(e) {
    if (e.button === 2) return;
    closePopover();
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY, type: e.pointerType });
    if (pointers.size === 2 && e.pointerType === "touch") return startPinch();
    if (pointers.size > 1) return;
    const hit = e.target.closest?.("[data-hit]");
    const kind = e.button === 1 ? "empty" : hit?.dataset.hit || "empty";
    const target = { kind, id: hit?.dataset.id || null, side: hit?.dataset.side || null };
    if (kind === "grip" && !permissions.connect) target.kind = "item";
    st.gesture = { pointerId: e.pointerId, type: e.pointerType, x0: e.clientX, y0: e.clientY, cam0: st.cam, target, moved: false, dragging: null };
    st.mode = "press";
    try { svg.setPointerCapture(e.pointerId); } catch { /* old browsers */ }
    if (kind === "grip" || (kind === "item" && permissions.move)) e.preventDefault();
    hideTip();
  }

  let lastMove = null, moveFrame = 0;
  function onMove(e) {
    if (pointers.has(e.pointerId)) pointers.set(e.pointerId, { x: e.clientX, y: e.clientY, type: e.pointerType });
    if (st.mode === "pinch") return pinchMove();
    if (!st.gesture) return hoverAt(e);
    lastMove = e;
    if (!moveFrame) moveFrame = requestAnimationFrame(() => { moveFrame = 0; if (lastMove) gestureMove(lastMove); });
  }

  function hoverAt(e) {
    const hit = e.target.closest?.("[data-hit]");
    const x = hit?.dataset.hit === "item" || hit?.dataset.hit === "grip" ? hit.dataset.id : hit?.dataset.hit === "edge" ? hit.dataset.id : null;
    const itemHover = hit?.dataset.hit === "edge" ? st.hover : x;
    if (itemHover !== st.hover && (hit?.dataset.hit !== "edge")) {
      st.hover = itemHover;
      invalidate("camera");
    }
    if (st.mode === "pickTarget" && x && model.items.has(x)) {
      const verdict = adapter.canConnect(st.pick, x);
      showTip(x, screenPt(e), 0, verdict.ok ? null : verdict.reason);
      if (!verdict.ok) setPill(`${verdict.reason} · Esc to cancel`); else setPill("Choose a target · Esc to cancel");
      return;
    }
    if (x && hit.dataset.hit !== "grip") {
      if (st.tipFor !== x) showTip(x, screenPt(e), 350);
    } else if (!x) hideTip(150);
  }

  function gestureMove(e) {
    const g = st.gesture;
    if (!g) return;
    const dx = e.clientX - g.x0, dy = e.clientY - g.y0;
    if (!g.moved) {
      if (Math.hypot(dx, dy) <= (DRAG_PX[g.type] || 4)) return;
      g.moved = true;
      const t = g.target;
      if (t.kind === "grip") {
        st.mode = "connect";
        svg.classList.add("connecting");
        markTargets(t.id);
      } else if (t.kind === "item" && permissions.move && (adapter.canMove(model.items.get(t.id))?.lanes || []).length) {
        st.mode = "move";
        g.dragging = t.id;
        svg.classList.add("moving");
        itemEls.get(t.id)?.g.classList.add("dragging");
      } else {
        st.mode = "pan";
        svg.classList.add("panning");
      }
    }
    const p = screenPt(e);
    if (st.mode === "pan") {
      st.cam = camera.pan(g.cam0, dx, dy);
      invalidate("camera");
    } else if (st.mode === "move") {
      const r = rectOf(g.dragging);
      const w = camera.toWorld(st.cam, p.x, p.y);
      const grab = g.grab || (g.grab = (() => { const w0 = camera.toWorld(g.cam0, g.x0 - (st.rect?.left || 0), g.y0 - (st.rect?.top || 0)); return { x: w0.x - r.x, y: w0.y - r.y }; })());
      itemEls.get(g.dragging)?.g.setAttribute("transform", `translate(${w.x - grab.x} ${w.y - grab.y})`);
      st.insert = dropSlot(g.dragging, { x: w.x - grab.x + r.w / 2, y: w.y - grab.y + r.h / 2 });
      autoPan(p);
      invalidate("camera");
    } else if (st.mode === "connect") {
      const from = rectOf(g.target.id);
      const fr = toScreenRect(from);
      const target = itemAt(e.clientX, e.clientY, g.target.id);
      const verdict = target ? adapter.canConnect(g.target.id, target) : null;
      st.ghost = { x1: g.target.side === "right" ? fr.x + fr.w : fr.x, y1: fr.y + fr.h / 2, x2: p.x, y2: p.y, ok: verdict ? verdict.ok : null };
      g.over = target;
      if (target && !verdict.ok) showTip(target, p, 0, verdict.reason);
      else if (st.tipFor) hideTip();
      autoPan(p);
      invalidate("camera");
    }
  }

  let panFrame = 0;
  function autoPan(p) {
    const vx = p.x < EDGE_ZONE ? 1 : p.x > st.vp.w - EDGE_ZONE ? -1 : 0;
    const vy = p.y < EDGE_ZONE ? 1 : p.y > st.vp.h - EDGE_ZONE ? -1 : 0;
    cancelAnimationFrame(panFrame);
    if (!vx && !vy) return;
    panFrame = requestAnimationFrame(() => {
      if (st.mode !== "move" && st.mode !== "connect") return;
      st.cam = camera.pan(st.cam, vx * 12, vy * 12);
      if (st.gesture) st.gesture.cam0 = camera.pan(st.gesture.cam0, vx * 12, vy * 12);
      if (lastMove) gestureMove(lastMove);
    });
  }

  function onUp(e) {
    pointers.delete(e.pointerId);
    if (st.mode === "pinch") {
      if (!pointers.size) { st.mode = "idle"; st.gesture = null; }
      return;
    }
    const g = st.gesture;
    if (!g || g.pointerId !== e.pointerId) return;
    cancelAnimationFrame(moveFrame);
    moveFrame = 0;
    lastMove = null;
    cancelAnimationFrame(panFrame);
    try { svg.releasePointerCapture(e.pointerId); } catch { /* released */ }
    const t = g.target;
    if (!g.moved) {
      st.gesture = null;
      if (st.mode === "press") st.mode = st.pick ? "pickTarget" : "idle";
      return click(t, e);
    }
    if (st.mode === "move") {
      const slot = st.insert;
      const itemId = g.dragging;
      const entry = itemEls.get(itemId);
      entry?.g.classList.remove("dragging");
      st.gesture = null;
      st.insert = null;
      st.mode = "idle";
      svg.classList.remove("moving");
      const moved = slot ? commitMove(itemId, slot) : false;
      const r = rectOf(itemId);
      if (!moved && entry && r) entry.g.setAttribute("transform", `translate(${r.x} ${r.y})`);
      applyDeferred();
      invalidate("camera");
      return;
    }
    if (st.mode === "connect") {
      const over = g.over;
      const from = t.id;
      cancelMode(true);
      if (over) tryConnect(from, over);
      return;
    }
    st.gesture = null;
    st.mode = "idle";
    svg.classList.remove("panning");
    applyDeferred();
  }

  function click(t, e) {
    if (st.mode === "pickTarget") {
      if (t.kind === "item" && t.id !== st.pick) return tryConnect(st.pick, t.id);
      return cancelMode();
    }
    if (t.kind === "grip") return startPick(t.id);
    if (t.kind === "item") {
      select(t.id);
      focusOn(t.id);
      return;
    }
    if (t.kind === "edge") {
      const ids = [...new Set(document.elementsFromPoint(e.clientX, e.clientY)
        .map((n) => n.closest?.("[data-hit=edge]")).filter((n) => n && svg.contains(n)).map((n) => n.dataset.id))];
      if (ids.length > 1) return chooseEdge(ids, screenPt(e));
      select(t.id);
      focusOn(t.id);
      return;
    }
    select(null);
  }

  function onCancel(e) {
    pointers.delete(e.pointerId);
    if (st.gesture && st.gesture.pointerId === e.pointerId) cancelMode(st.mode === "pan" || st.mode === "press");
  }

  // pinch: two touch pointers zoom around their midpoint and pan with it
  function startPinch() {
    if (st.mode === "move" || st.mode === "connect") cancelMode(true);
    const [a, b] = [...pointers.values()];
    st.mode = "pinch";
    st.gesture = { pinch: { d0: Math.hypot(a.x - b.x, a.y - b.y) || 1, m0: { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }, cam0: st.cam } };
  }
  function pinchMove() {
    const [a, b] = [...pointers.values()];
    if (!a || !b || !st.gesture?.pinch) return;
    const { d0, m0, cam0 } = st.gesture.pinch;
    const m = { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    const rect = st.rect || { left: 0, top: 0 };
    const zoomed = camera.zoomAt(cam0, m0.x - rect.left, m0.y - rect.top, Math.hypot(a.x - b.x, a.y - b.y) / d0);
    st.cam = camera.pan(zoomed, m.x - m0.x, m.y - m0.y);
    invalidate("camera");
  }

  function onWheel(e) {
    e.preventDefault();
    const p = screenPt(e);
    if (e.ctrlKey || e.metaKey) {
      st.cam = camera.zoomAt(st.cam, p.x, p.y, camera.wheelZoomFactor(e.deltaY));
    } else {
      const { dx, dy } = camera.wheelPixels(e.deltaX, e.deltaY, e.deltaMode, st.vp.h);
      st.cam = camera.pan(st.cam, -(e.shiftKey && !dx ? dy : dx), -(e.shiftKey && !dx ? 0 : dy));
    }
    hideTip();
    invalidate("camera");
  }

  // ---------- keyboard ----------
  function onKey(e) {
    if (e.target.closest?.("input, textarea, select")) return;
    const k = e.key;
    const cur = st.kb?.target || st.focus || st.sel;
    const mod = e.ctrlKey || e.metaKey;
    if (mod && k.toLowerCase() === "z") {
      e.preventDefault();
      if (!permissions.move) return announce("Operators can arrange the map");
      const done = e.shiftKey ? adapter.onRedo?.() : adapter.onUndo?.();
      return announce(done ? (e.shiftKey ? "Move redone" : "Move undone") : "Nothing to undo");
    }
    if (mod || e.altKey) return;
    if (st.kb?.mode === "move") return kbMoveKey(e);
    if (st.kb?.mode === "connect") return kbConnectKey(e);
    const arrows = { ArrowUp: "up", ArrowDown: "down", ArrowLeft: "left", ArrowRight: "right", Home: "home", End: "end" };
    if (arrows[k]) {
      e.preventDefault();
      if (e.shiftKey && k.startsWith("Arrow")) {
        const d = { up: [0, 64], down: [0, -64], left: [64, 0], right: [-64, 0] }[arrows[k]];
        st.cam = camera.pan(st.cam, d[0], d[1]);
        return invalidate("camera");
      }
      if (cur && model.edges.has(cur)) return focusOn(edgeBase(cur)); // from a connection back to its item
      if (cur && model.items.has(cur)) return focusOn(neighbour(cur, arrows[k]));
      const first = firstItemEl()?.dataset.id;
      if (first) focusOn(first);
      return;
    }
    switch (k) {
      case "Enter":
        if (cur) { e.preventDefault(); select(cur, { quiet: true }); adapter.onOpen?.(cur); }
        return;
      case " ":
        e.preventDefault();
        if (cur) select(st.sel === cur ? null : cur);
        return;
      case "e": case "E": {
        const base = cur && model.edges.has(cur) ? edgeBase(cur) : cur;
        if (!base || !model.items.has(base)) return;
        const list = edgesOf(base);
        if (!list.length) return announce(`${adapter.name(base)} has no connections on the map`);
        const i = list.indexOf(cur);
        const next = list[(i + (e.shiftKey ? -1 : 1) + list.length + (i === -1 && e.shiftKey ? 1 : 0)) % list.length];
        st.edgeBase = base;
        return focusOn(next);
      }
      case "m": case "M":
        return startKbMove(cur);
      case "c": case "C":
        return startKbConnect(cur);
      case "Delete": case "Backspace":
        e.preventDefault();
        if (cur) adapter.onDelete?.(cur); else announce("Nothing is selected");
        return;
      case "+": case "=":
        return zoomBy(1.25);
      case "-": case "_":
        return zoomBy(0.8);
      case "0":
        return fit();
      case "l": case "L":
        return setList(!st.list);
      case "f": case "F":
        return setFocusMode(!st.full);
      case "?":
        return openHelp();
      default:
        if (k.length === 1 && adapter.onKey?.(k.toLowerCase(), cur)) e.preventDefault();
    }
  }

  function startKbMove(x) {
    if (!permissions.move) return announce("Operators can arrange the map");
    if (!x || !model.items.has(x)) return announce("Move: focus an item first");
    const lanes = adapter.canMove(model.items.get(x))?.lanes || [];
    if (!lanes.length) return announce(`${adapter.name(x)} cannot be moved`);
    const r = rectOf(x);
    const list = laneItems(r.lane);
    st.kb = { mode: "move", target: x, lane: r.lane, index: list.indexOf(x), lanes };
    st.mode = "kbMove";
    kbMovePreview();
    setPill("Move: arrow keys · Enter to drop · Esc to cancel");
  }
  function kbMovePreview() {
    const { target, lane, index } = st.kb;
    const others = laneItems(lane).filter((x) => x !== target).map((x) => ({ id: x, ...rectOf(x) }));
    const i = Math.max(0, Math.min(index, others.length));
    const prev = others[i - 1], next = others[i];
    st.insert = { lane, index: i, y: prev && next ? (prev.y + prev.h + next.y) / 2 : prev ? prev.y + prev.h + 12 : next ? next.y - 12 : 56 };
    invalidate("camera");
    announce(`Position ${i + 1} of ${others.length + 1} in ${laneTitle(lane)}`);
  }
  function kbMoveKey(e) {
    const kb = st.kb;
    const k = e.key;
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Enter", "Escape", " "].includes(k)) e.preventDefault();
    const size = laneItems(kb.lane).filter((x) => x !== kb.target).length;
    if (k === "ArrowUp") kb.index = Math.max(0, kb.index - 1);
    else if (k === "ArrowDown") kb.index = Math.min(size, kb.index + 1);
    else if (k === "ArrowLeft" || k === "ArrowRight") {
      const lanes = st.scene.lanes.map((l) => l.id);
      const i = lanes.indexOf(kb.lane) + (k === "ArrowLeft" ? -1 : 1);
      const next = lanes[i];
      if (!next || !kb.lanes.includes(next)) return announce(`${adapter.name(kb.target)} stays in ${laneTitle(kb.lane)}`);
      kb.lane = next;
      kb.index = Math.min(kb.index, laneItems(next).filter((x) => x !== kb.target).length);
    } else if (k === "Enter") {
      const slot = { lane: kb.lane, index: kb.index };
      const x = kb.target;
      st.kb = null;
      st.insert = null;
      st.mode = "idle";
      setPill("");
      if (!commitMove(x, slot)) announce("Not moved");
      invalidate("camera");
      return;
    } else if (k === "Escape") {
      e.stopPropagation();
      return cancelMode();
    } else return;
    kbMovePreview();
  }

  function startKbConnect(x) {
    if (!permissions.connect) return announce(adapter.connectHint?.() || "Operators can connect items");
    if (!x || !model.items.has(x)) return announce("Connect: focus an item first");
    const order = st.scene.lanes.flatMap((l) => laneItems(l.id));
    const targets = order.filter((t) => t !== x && adapter.canConnect(x, t).ok);
    if (!targets.length) {
      const reason = order.filter((t) => t !== x).map((t) => adapter.canConnect(x, t).reason)[0] || "nothing to connect to";
      return announce(`No valid targets: ${reason}`);
    }
    st.kb = { mode: "connect", from: x, targets, i: 0, target: targets[0] };
    st.mode = "kbConnect";
    markTargets(x);
    setPill("Connect: arrow keys choose a target · Enter to connect · Esc to cancel");
    kbConnectPreview();
  }
  function kbConnectPreview() {
    const { from, target } = st.kb;
    itemEls.forEach(({ g }, x) => g.classList.toggle("kb-target", x === target));
    const a = toScreenRect(rectOf(from)), b = toScreenRect(rectOf(target));
    const right = a.x < b.x;
    st.ghost = { x1: right ? a.x + a.w : a.x, y1: a.y + a.h / 2, x2: right ? b.x : b.x + b.w, y2: b.y + b.h / 2, ok: true };
    reveal(target);
    invalidate("camera");
    announce(`${adapter.name(target)}, target ${st.kb.i + 1} of ${st.kb.targets.length}`);
  }
  function kbConnectKey(e) {
    const kb = st.kb;
    const k = e.key;
    if (["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Enter", "Escape", "Tab"].includes(k)) e.preventDefault();
    if (k === "ArrowDown" || k === "ArrowRight") kb.i = (kb.i + 1) % kb.targets.length;
    else if (k === "ArrowUp" || k === "ArrowLeft") kb.i = (kb.i - 1 + kb.targets.length) % kb.targets.length;
    else if (k === "Enter") {
      const { from, target } = kb;
      cancelMode(true);
      focusOn(from);
      return tryConnect(from, target);
    } else if (k === "Escape") {
      e.stopPropagation();
      const from = kb.from;
      cancelMode();
      return focusOn(from);
    } else return;
    kb.target = kb.targets[kb.i];
    kbConnectPreview();
  }

  // Esc cascade: mode, then popover / tooltip, then the inspector, then the selection, then focus mode
  function onEscape(e) {
    if (e.key !== "Escape" || e.defaultPrevented) return;
    if (document.querySelector(".backdrop")) return; // a dialog handles its own Esc
    if (cancelMode(true)) { announce("Cancelled"); return e.preventDefault(); }
    if (closePopover() || adapter.onEscape?.()) return e.preventDefault();
    if (!tip.hidden) { hideTip(); return e.preventDefault(); }
    if (!inspector.hidden && inspector.contains(document.activeElement)) {
      e.preventDefault();
      const back = st.sel && (itemEls.get(st.sel) || edgeEls.get(st.sel));
      return back ? focusOn(st.sel) : svg.focus();
    }
    if (!inspector.hidden) { showInspector(false); return e.preventDefault(); }
    if (st.sel) { select(null); return e.preventDefault(); }
    if (st.full) { setFocusMode(false); e.preventDefault(); }
  }

  function openHelp() {
    const rows = [
      ["Arrow keys", "Move between items: up and down in a lane, left and right to the next lane"], ["Home / End", "First or last item in the lane"],
      ["Enter", "Open the details (Esc returns to the map)"], ["Space", "Select or clear the selection"],
      ["E / Shift+E", "Next or previous connection of the focused item"],
      ["M", "Move mode (operators): arrows reorder, Enter drops, Esc cancels"],
      ["C", "Connect mode (operators): arrows choose a valid target, Enter connects"],
      ...(opts.helpRows || []),
      ["Delete / Backspace", "On a selected connection: what can be done with it"], ["+ / - / 0", "Zoom in, zoom out, fit"],
      ["Shift + arrows", "Pan"], ["L", "Map or list view"], ["F", "Focus mode"],
      ["Ctrl+Z / Cmd+Z", "Undo a move (Shift to redo)"], ["Esc", "Cancel, close, clear the selection, leave focus mode"],
    ];
    modal({ title: "Map keyboard shortcuts", submit: null, cancel: "Close",
      body: html`<p class="muted" style="margin-bottom:10px">Single-key shortcuts work while the map has focus. Everything can also be done in the list view
        (L) and the details panel.</p><table class="table compact"><tbody>${rows.map(([keys, text]) => html`<tr><td style="white-space:nowrap"><kbd>${keys}</kbd></td><td>${text}</td></tr>`)}</tbody></table>` });
  }

  // ---------- inspector, list, focus mode, notices ----------
  function showInspector(open) {
    const was = !inspector.hidden;
    inspector.hidden = !open;
    if (was !== open) {
      measureStage();
      if (open && st.sel) reveal(st.sel); // the stage narrowed: keep the selection in view
    }
  }
  function setList(on) {
    st.list = !!on;
    listEl.hidden = !st.list;
    body.hidden = st.list;
    const b = $('[data-act="cv-list"]');
    b.setAttribute("aria-pressed", String(st.list));
    b.querySelector("span").textContent = st.list ? "Map" : "List";
    if (st.list) { hideTip(); adapter.list?.(listEl); } else requestAnimationFrame(measureStage);
  }
  function setFocusMode(on) {
    st.full = !!on;
    shell.classList.toggle("full", st.full);
    $('[data-act="cv-full"]').setAttribute("aria-pressed", String(st.full));
    sizeShell();
  }
  function setNotice(content, tone = "") {
    const n = $('[data-part="canvas-notice"]');
    n.hidden = !content;
    n.className = `notice ${tone}`;
    if (content) setHTML(n, content); else n.replaceChildren();
    sizeShell();
  }
  function setLive(ok) {
    st.live = ok;
    $('[data-part="cv-live"]').hidden = ok;
  }

  function sizeShell() {
    if (st.full) { shell.style.removeProperty("height"); return requestAnimationFrame(measureStage); }
    const top = shell.getBoundingClientRect().top + window.scrollY;
    shell.style.height = `${Math.max(420, innerHeight - top - (innerWidth <= 860 ? 16 : 24))}px`;
    requestAnimationFrame(measureStage);
  }
  function measureStage() {
    const r = stage.getBoundingClientRect();
    st.rect = r;
    const overlay = !inspector.hidden && getComputedStyle(inspector).position === "absolute";
    st.vp = { w: r.width, h: r.height, insets: { top: 0, right: 0, bottom: overlay ? inspector.offsetHeight : 0, left: 0 } };
    place();
    invalidate("camera");
  }

  function showDebug(extra) {
    if (!dbg) return;
    Object.assign(timings, extra);
    dbg.textContent = `scene ${(timings.scene || 0).toFixed(1)} ms · render ${(timings.render || 0).toFixed(1)} ms · frame ${(timings.frame || 0).toFixed(1)} ms · `
      + `${svg.getElementsByTagName("*").length} elements · k ${st.cam.k.toFixed(2)}`;
  }

  // ---------- model updates ----------
  function applyDeferred() {
    if (!st.deferred || st.gesture) return;
    const d = st.deferred;
    st.deferred = null;
    update(d.model, d.layout);
  }

  function update(nextModel, nextLayout = layout) {
    if (st.gesture?.dragging || (st.mode === "connect" && st.gesture)) {
      st.deferred = { model: nextModel, layout: nextLayout };
      const lost = st.gesture.dragging || st.gesture.target?.id;
      if (lost && !nextModel.items.has(lost)) {
        const name = model.items.get(lost)?.label || "The item";
        cancelMode(true);
        announce(`${name} was removed; ${st.mode === "connect" ? "connect" : "move"} cancelled`);
      }
      return;
    }
    model = nextModel;
    layout = nextLayout || layout;
    if (st.sel && !kindOf(st.sel)) select(null, { quiet: true });
    if (st.focus && !kindOf(st.focus)) st.focus = null;
    if (st.hover && !model.items.has(st.hover)) st.hover = null;
    if (st.kb && (!model.items.has(st.kb.target) || (st.kb.from && !model.items.has(st.kb.from)))) cancelMode();
    invalidate("scene");
  }

  // ---------- wiring ----------
  on(svg, "pointerdown", onDown);
  on(svg, "pointermove", onMove);
  on(svg, "pointerup", onUp);
  on(svg, "pointercancel", onCancel);
  on(svg, "lostpointercapture", (e) => { if (st.gesture && st.gesture.pointerId === e.pointerId && st.mode !== "idle" && st.mode !== "press") onCancel(e); });
  on(svg, "pointerleave", () => { if (!st.gesture) { st.hover = null; hideTip(200); invalidate("camera"); } });
  on(svg, "wheel", onWheel, { passive: false });
  on(svg, "dblclick", (e) => {
    const hit = e.target.closest?.("[data-hit=item], [data-hit=edge]");
    if (hit) { select(hit.dataset.id, { quiet: true }); adapter.onOpen?.(hit.dataset.id); }
  });
  on(svg, "keydown", onKey);
  on(svg, "focusin", (e) => {
    const hit = e.target.closest?.("[data-hit=item], [data-hit=edge]");
    if (hit && hit.dataset.id !== st.focus) { st.focus = hit.dataset.id; roving(); showTip(st.focus, null); }
    invalidate("camera");
  });
  on(svg, "focusout", (e) => { if (!svg.contains(e.relatedTarget)) { hideTip(); invalidate("camera"); } });
  on(svg, "contextmenu", (e) => { if (st.mode !== "idle") e.preventDefault(); });
  on(shell, "keydown", onEscape);
  on(window, "resize", debounce(sizeShell, 100));
  on(window, "scroll", () => { st.rect = stage.getBoundingClientRect(); }, { passive: true });
  on(shell, "click", (e) => {
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (!act?.startsWith("cv-")) return;
    e.preventDefault();
    if (act === "cv-zoom-in") zoomBy(1.25);
    else if (act === "cv-zoom-out") zoomBy(0.8);
    else if (act === "cv-zoom-reset") moveCamera(camera.zoomTo(st.cam, st.vp, 1));
    else if (act === "cv-fit") fit();
    else if (act === "cv-list") setList(!st.list);
    else if (act === "cv-skip") { setList(true); listEl.querySelector("a, button, input, select, [tabindex]")?.focus(); }
    else if (act === "cv-full") setFocusMode(!st.full);
    else if (act === "cv-help") openHelp();
  });
  const onStatus = (e) => setLive(!!e.detail?.ok);
  on(window, "atrium:events-status", onStatus);
  setLive(eventsOk());
  const ro = typeof ResizeObserver !== "undefined" ? new ResizeObserver(() => measureStage()) : null;
  ro?.observe(stage);
  sizeShell();
  invalidate("scene");

  return {
    shell, svg, inspector, list: listEl,
    get camera() { return st.cam; },
    get selection() { return st.sel; },
    get listView() { return st.list; },
    get scene() { return st.scene; },
    update,
    patchEdge(edgeId, edge) {
      const edges = new Map(model.edges);
      if (edge) edges.set(edgeId, edge); else edges.delete(edgeId);
      update({ ...model, edges }, layout);
    },
    applyLayout(items, version) {
      const next = { ...layout, items: { ...(layout.items || {}) } };
      const dragging = st.gesture?.dragging;
      for (const [x, v] of Object.entries(items || {})) {
        if (x === dragging) continue;
        if (v === null) delete next.items[x]; else next.items[x] = v;
      }
      if (version !== undefined) next.version = version;
      update(model, next);
    },
    replaceLayout(doc) { update(model, doc); },
    select(x, o = {}) { select(x, o); if (o.reveal && x) focusOn(x); },
    focus(x) { focusOn(x); },
    focusMap() { (itemEls.get(st.sel)?.g || firstItemEl() || svg).focus(); },
    fit, zoomBy,
    setFilter(fn) { st.filter = fn; invalidate("items", "edges"); },
    setList, setFocusMode, setNotice, setLive, showInspector, announce,
    setPermissions(p) { permissions = { ...permissions, ...p }; invalidate("camera"); },
    startConnect(x) { startPick(x); },
    cancel: () => cancelMode(true),
    destroy() {
      cancelAnimationFrame(frame);
      cancelAnimationFrame(anim);
      cancelAnimationFrame(moveFrame);
      cancelAnimationFrame(panFrame);
      clearTimeout(tipTimer);
      clearTimeout(tipHide);
      ro?.disconnect();
      disposers.forEach((off) => off());
      shell.remove();
    },
  };
}
