/** Shared SVG canvas: pan, zoom, selection, drag-to-reorder, list view, keyboard. */

import { ensureVisible, fit, toWorld, zoomAt } from "./camera.js";
import { insertionIndex, laneRects, normalize, orderAt } from "./lanes.js";
import { cubic, labelAnchor, tracks } from "./route.js";

const NS = "http://www.w3.org/2000/svg";
const DRAG_PX = 4;

function el(name, attrs = {}) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) {
    if (v != null) node.setAttribute(k, String(v));
  }
  return node;
}

function text(parent, value, attrs) {
  const node = el("text", attrs);
  node.textContent = value == null ? "" : String(value);
  parent.append(node);
  return node;
}

export function createCanvas(container, options) {
  const opts = options || {};
  const adapter = opts.adapter || {};
  const state = {
    model: opts.model || { items: new Map(), edges: new Map() },
    layout: opts.layout || { version: 0, items: {} },
    lanes: opts.lanes || [],
    camera: { k: 1, tx: 24, ty: 24 },
    selection: null,
    list: false,
    focus: false,
    filter: "",
    dragging: null,
  };
  let rects = [];
  let destroyed = false;

  container.replaceChildren();
  const shell = document.createElement("div");
  shell.className = "canvas-shell";
  shell.dataset.view = opts.view || "";
  shell.innerHTML = `
    <div class="canvas-bar" role="group" aria-label="Map controls">
      <button type="button" class="btn sm" data-cv="zoom-in" aria-label="Zoom in">+</button>
      <button type="button" class="btn sm" data-cv="zoom-out" aria-label="Zoom out">−</button>
      <button type="button" class="btn sm" data-cv="fit">Fit</button>
      <button type="button" class="btn sm" data-cv="list">List</button>
      <button type="button" class="btn sm" data-cv="focus">Focus</button>
      <span class="canvas-live-chip" data-cv="paused" hidden>Live updates paused</span>
      <span class="canvas-count" data-cv="count"></span>
    </div>
    <a class="skip-link" href="#" data-cv="list">Skip to list view</a>
    <div class="canvas-stage">
      <svg class="canvas" tabindex="0" role="graphics-document"></svg>
    </div>
    <aside class="canvas-inspector" aria-label="Details" hidden></aside>
    <div class="canvas-list" hidden></div>
    <p class="sr-only" data-cv="help"></p>
    <div class="sr-only" aria-live="polite" data-cv="live"></div>`;
  container.append(shell);

  const svg = shell.querySelector("svg.canvas");
  const inspector = shell.querySelector(".canvas-inspector");
  const listEl = shell.querySelector(".canvas-list");
  const live = shell.querySelector("[data-cv=live]");
  const countEl = shell.querySelector("[data-cv=count]");
  svg.setAttribute("aria-roledescription", opts.roledescription || "map");
  shell.querySelector("[data-cv=help]").textContent =
    "Arrow keys move between items. Plus and minus zoom. F fits the map. L switches to the list. Escape clears the selection.";

  const defs = el("defs");
  const marker = el("marker", { id: `arr-${opts.view || "map"}`, viewBox: "0 0 10 10", refX: "9", refY: "5",
    markerWidth: "7", markerHeight: "7", orient: "auto-start-reverse", markerUnits: "userSpaceOnUse" });
  marker.append(el("path", { d: "M0,0 L10,5 L0,10 z", fill: "context-stroke" }));
  defs.append(marker);
  const cam = el("g", { class: "cam" });
  const gEdges = el("g", { class: "l-edges" });
  const gItems = el("g", { class: "l-items" });
  cam.append(gEdges, gItems);
  svg.append(defs, cam);

  function visibleItems() {
    const q = state.filter.trim().toLowerCase();
    const items = [...state.model.items.values()];
    if (!q) return items;
    return items.filter((item) => {
      const name = adapter.name ? adapter.name(item.id) : item.label || item.id;
      return String(name).toLowerCase().includes(q);
    });
  }

  function layoutLanes() {
    const shown = new Set(visibleItems().map((item) => item.id));
    return (state.lanes || []).map((lane) => ({
      ...lane,
      items: normalize([...state.model.items.values()]
        .filter((item) => shown.has(item.id) && (adapter.lane ? adapter.lane(item, state.layout) : item.lane) === lane.id)
        .map((item) => {
          const saved = state.layout.items?.[item.id] || {};
          const size = adapter.size ? adapter.size(item) : { w: 220, h: item.h || 72 };
          return { id: item.id, h: size.h, order: Number.isFinite(saved.order) ? saved.order : (item.order || 0) };
        })),
    }));
  }

  function boundsOf(list) {
    if (!list.length) return { minX: 0, minY: 0, maxX: 400, maxY: 240 };
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const r of list) {
      minX = Math.min(minX, r.x);
      minY = Math.min(minY, r.y);
      maxX = Math.max(maxX, r.x + r.w);
      maxY = Math.max(maxY, r.y + r.h);
    }
    return { minX, minY, maxX, maxY };
  }

  function applyCamera() {
    cam.setAttribute("transform", `translate(${state.camera.tx} ${state.camera.ty}) scale(${state.camera.k})`);
  }

  function paint() {
    if (destroyed) return;
    const lanes = layoutLanes();
    rects = laneRects(lanes, 12, 36);
    const byId = new Map(rects.map((r) => [r.id, r]));
    gItems.replaceChildren();
    for (const lane of state.lanes || []) {
      const title = el("g", { "data-hit": "lane", "data-id": lane.id });
      title.append(el("rect", {
        x: lane.x, y: 0, width: lane.width, height: Math.max(320, ...rects.filter((r) => r.lane === lane.id).map((r) => r.y + r.h + 24), 0),
        class: "lane-bg", rx: 12,
      }));
      text(title, lane.title || lane.id, { x: lane.x + 16, y: 22, class: "lane-title" });
      gItems.append(title);
    }
    for (const rect of rects) {
      const item = state.model.items.get(rect.id);
      if (!item) continue;
      const g = el("g", { "data-id": item.id, "data-hit": "item", transform: `translate(${rect.x} ${rect.y})` });
      if (state.selection === item.id) g.classList.add("is-selected");
      if (adapter.draw) adapter.draw(item, g, { w: rect.w, h: rect.h, selected: state.selection === item.id, k: state.camera.k });
      else {
        g.append(el("rect", { width: rect.w, height: rect.h, rx: 10, class: "node-card" }));
        text(g, item.label || item.id, { x: 12, y: 28, class: "node-label" });
      }
      const title = adapter.name ? adapter.name(item.id) : (item.label || item.id);
      g.setAttribute("role", "button");
      g.setAttribute("tabindex", "-1");
      const name = document.createElementNS(NS, "title");
      name.textContent = title;
      g.append(name);
      gItems.append(g);
    }
    const edgeList = [...state.model.edges.values()].filter((edge) => byId.has(edge.source) && byId.has(edge.target));
    const trackOf = tracks(edgeList);
    gEdges.replaceChildren();
    for (const edge of edgeList) {
      const a = byId.get(edge.source);
      const b = byId.get(edge.target);
      const x1 = a.x + a.w;
      const y1 = a.y + a.h / 2;
      const x2 = b.x;
      const y2 = b.y + b.h / 2;
      const style = adapter.edgeStyle ? adapter.edgeStyle(edge) : { cls: "" };
      const d = style.primary ? cubic(x1, y1, x2, y2) : cubic(x1, y1, x2, y2);
      const path = el("path", {
        d, class: `edge ${style.cls || ""}`, fill: "none",
        "marker-end": `url(#arr-${opts.view || "map"})`,
        "data-id": edge.id, "data-hit": "edge",
      });
      if (style.dash) path.setAttribute("stroke-dasharray", style.dash);
      const hit = el("path", { d, class: "edge-hit", "data-id": edge.id, "data-hit": "edge" });
      gEdges.append(path, hit);
      if (style.chip && state.camera.k >= 0.5) {
        const anchor = labelAnchor(x1, y1, x2, y2);
        const chip = el("g", { transform: `translate(${anchor.x} ${anchor.y - 8 + (trackOf.get(edge.id) || 0) * 12})` });
        text(chip, style.chip, { class: "edge-chip", "text-anchor": "middle" });
        gEdges.append(chip);
      }
    }
    const nItems = state.model.items.size;
    const nEdges = state.model.edges.size;
    const label = `${opts.label || "Map"}: ${nItems} items, ${nEdges} links`;
    svg.setAttribute("aria-label", label);
    countEl.textContent = `${nItems} items · ${nEdges} links`;
    paintList();
    applyCamera();
  }

  function paintList() {
    listEl.replaceChildren();
    if (!state.list) return;
    const ul = document.createElement("ul");
    ul.className = "canvas-list-items";
    for (const item of visibleItems()) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "canvas-list-btn";
      btn.textContent = adapter.name ? adapter.name(item.id) : (item.label || item.id);
      if (state.selection === item.id) btn.setAttribute("aria-current", "true");
      btn.addEventListener("click", () => select(item.id, { reveal: true }));
      li.append(btn);
      ul.append(li);
    }
    if (!ul.childElementCount) {
      const p = document.createElement("p");
      p.className = "muted";
      p.textContent = "Nothing matches this map.";
      listEl.append(p);
    } else listEl.append(ul);
  }

  function select(id, extra = {}) {
    state.selection = id && state.model.items.has(id) ? id : (state.model.edges.has(id) ? id : null);
    if (extra.reveal && state.selection && state.model.items.has(state.selection)) {
      const rect = rects.find((r) => r.id === state.selection);
      const box = svg.getBoundingClientRect();
      if (rect) state.camera = ensureVisible(state.camera, rect, { w: box.width, h: box.height }, { top: 8, right: inspector.hidden ? 8 : 280 });
    }
    paint();
    adapter.onSelect?.(state.selection);
    if (id) announce(adapter.name ? adapter.name(id) : id);
  }

  function announce(text) {
    live.textContent = text || "";
  }

  function viewport() {
    const box = svg.getBoundingClientRect();
    return { w: box.width || 800, h: box.height || 480 };
  }

  function doFit() {
    state.camera = fit(boundsOf(rects), viewport());
    applyCamera();
  }

  function setList(on) {
    state.list = on;
    listEl.hidden = !on;
    shell.querySelector("[data-cv=list]").setAttribute("aria-pressed", on ? "true" : "false");
    if (on) paintList();
  }

  function setFocusMode(on) {
    state.focus = on;
    shell.classList.toggle("full", on);
    shell.querySelector("[data-cv=focus]").setAttribute("aria-pressed", on ? "true" : "false");
  }

  shell.addEventListener("click", (event) => {
    const btn = event.target.closest("[data-cv]");
    if (!btn) return;
    event.preventDefault();
    const act = btn.dataset.cv;
    if (act === "zoom-in") { state.camera = zoomAt(state.camera, viewport().w / 2, viewport().h / 2, 1.2); applyCamera(); }
    if (act === "zoom-out") { state.camera = zoomAt(state.camera, viewport().w / 2, viewport().h / 2, 1 / 1.2); applyCamera(); }
    if (act === "fit") doFit();
    if (act === "list") setList(!state.list);
    if (act === "focus") setFocusMode(!state.focus);
  });

  svg.addEventListener("wheel", (event) => {
    event.preventDefault();
    const box = svg.getBoundingClientRect();
    const sx = event.clientX - box.left;
    const sy = event.clientY - box.top;
    if (event.ctrlKey || event.metaKey) {
      state.camera = zoomAt(state.camera, sx, sy, Math.exp(-event.deltaY * 0.0015));
    } else {
      const scale = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? box.height : 1;
      state.camera.tx -= event.deltaX * scale;
      state.camera.ty -= event.deltaY * scale;
    }
    applyCamera();
  }, { passive: false });

  let press = null;
  svg.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 && event.button !== 1) return;
    const hit = event.target.closest?.("[data-hit]");
    svg.setPointerCapture(event.pointerId);
    const box = svg.getBoundingClientRect();
    press = {
      id: hit?.dataset.hit === "item" ? hit.dataset.id : null,
      x: event.clientX, y: event.clientY,
      sx: event.clientX - box.left, sy: event.clientY - box.top,
      pan: !hit || hit.dataset.hit === "lane" || event.button === 1,
      moved: false,
    };
  });
  svg.addEventListener("pointermove", (event) => {
    if (!press) return;
    const dx = event.clientX - press.x;
    const dy = event.clientY - press.y;
    if (!press.moved && Math.hypot(dx, dy) < DRAG_PX) return;
    press.moved = true;
    if (press.pan || !press.id || !opts.permissions?.move) {
      state.camera.tx += event.movementX;
      state.camera.ty += event.movementY;
      applyCamera();
      return;
    }
    state.dragging = press.id;
  });
  svg.addEventListener("pointerup", (event) => {
    if (!press) return;
    const current = press;
    press = null;
    state.dragging = null;
    if (!current.moved && current.id) {
      select(current.id);
      return;
    }
    if (current.moved && current.id && opts.permissions?.move && adapter.onMove) {
      const box = svg.getBoundingClientRect();
      const world = toWorld(state.camera, event.clientX - box.left, event.clientY - box.top);
      const lanes = layoutLanes();
      const lane = lanes.find((entry) => world.x >= entry.x && world.x <= entry.x + entry.width)
        || lanes.find((entry) => entry.id === (state.layout.items?.[current.id]?.lane));
      const item = state.model.items.get(current.id);
      const allowed = adapter.canMove ? adapter.canMove(item) : { lanes: lanes.map((entry) => entry.id) };
      if (lane && (!allowed.lanes || allowed.lanes.includes(lane.id))) {
        const index = insertionIndex(lane.items.filter((entry) => entry.id !== current.id), world.y);
        const order = orderAt(lane.items.filter((entry) => entry.id !== current.id), index);
        adapter.onMove(current.id, { lane: lane.id, order });
      }
    }
  });
  svg.addEventListener("pointercancel", () => { press = null; state.dragging = null; });

  svg.addEventListener("keydown", (event) => {
    const items = rects.map((r) => r.id);
    const index = items.indexOf(state.selection);
    if (event.key === "+" || event.key === "=") { state.camera = zoomAt(state.camera, viewport().w / 2, viewport().h / 2, 1.2); applyCamera(); event.preventDefault(); }
    if (event.key === "-" || event.key === "_") { state.camera = zoomAt(state.camera, viewport().w / 2, viewport().h / 2, 1 / 1.2); applyCamera(); event.preventDefault(); }
    if (event.key === "f" || event.key === "F") { doFit(); event.preventDefault(); }
    if (event.key === "l" || event.key === "L") { setList(!state.list); event.preventDefault(); }
    if (event.key === "Escape") { select(null); setFocusMode(false); }
    if (event.key === "ArrowDown" || event.key === "ArrowRight") {
      select(items[Math.min(items.length - 1, index + 1)] || items[0], { reveal: true });
      event.preventDefault();
    }
    if (event.key === "ArrowUp" || event.key === "ArrowLeft") {
      select(items[Math.max(0, index - 1)] || items[0], { reveal: true });
      event.preventDefault();
    }
    if (event.key === "Enter" && state.selection) adapter.onOpen?.(state.selection);
  });

  svg.addEventListener("click", (event) => {
    const hit = event.target.closest?.("[data-hit=edge]");
    if (hit) select(hit.dataset.id);
  });

  const api = {
    shell, svg, inspector,
    update(model, layout) {
      if (model) state.model = model;
      if (layout) state.layout = layout;
      paint();
      if (!state.camera._fitted) { doFit(); state.camera._fitted = true; }
    },
    applyLayout(items) {
      const next = { ...state.layout, items: { ...(state.layout.items || {}) } };
      for (const [id, spec] of Object.entries(items || {})) {
        if (id === state.dragging) continue;
        next.items[id] = { ...(next.items[id] || {}), ...spec };
      }
      state.layout = next;
      paint();
    },
    select,
    fit: doFit,
    zoomBy(factor) { state.camera = zoomAt(state.camera, viewport().w / 2, viewport().h / 2, factor); applyCamera(); },
    setFilter(fn) {
      state.filter = typeof fn === "string" ? fn : "";
      paint();
    },
    setList, setFocusMode, announce,
    setPaused(on) { shell.querySelector("[data-cv=paused]").hidden = !on; },
    destroy() {
      destroyed = true;
      shell.remove();
    },
    get camera() { return state.camera; },
    get selection() { return state.selection; },
  };
  paint();
  return api;
}

export { text };
