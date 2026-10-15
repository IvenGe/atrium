// Arranging a dashboard (round4-dashboard-spec.md 10.5, 10.6, 10.14): pointer drags and resizes, keyboard moves and
// resizes, and the two layouts - grid mode (12 columns, the frames placed through the CSS variables --x, --y, --w, --h)
// and stack mode (a container narrower than 960 px: one column of cards in reading order). The page (views/home.js)
// owns the widgets and their data; the board places the frames it rendered and hands every finished change to
// hooks.commit(items, {id, message}). It never saves anything itself.
//
// Drags use Pointer Events with pointer capture: one path for mouse, pen and touch. touch-action: none is set on the
// handles only, in edit mode only (CSS), so touch scrolling is never captured elsewhere. Every drag has a keyboard path
// here and a single-pointer path in the options menu (home.js).
import {
  COLS, MAX_ROWS, bottom, cellFromPoint, fromOrder, moveInOrder, moveTo, resizeTo, sizeFromPoint, sortReading, step, validate,
} from "./grid.js";

export const GRID_MIN = 960; // container width (not viewport width: the sidebar takes space) for grid mode
const EDGE = 48; // auto-scroll band at the top and bottom of the viewport

const same = (a, b) => JSON.stringify(a.map(({ id, x, y, w, h }) => [id, x, y, w, h]).sort())
  === JSON.stringify(b.map(({ id, x, y, w, h }) => [id, x, y, w, h]).sort());

/**
 * hooks: items() -> the committed items; size(id) -> the type's {min, default, max} or null; title(id) -> text;
 * editing() -> bool; commit(items, {id, message}); announce(text); modeChanged(mode).
 */
export function createBoard(section, hooks) {
  let mode = "grid";
  let drag = null; // a pointer drag or resize in progress
  let kb = null; // a keyboard pick-up {id, resize, base, preview, el}
  let raf = 0;
  const drop = document.createElement("div");
  drop.className = "dash-drop";
  drop.hidden = true;
  const tip = document.createElement("div");
  tip.className = "dash-size-tip";
  tip.hidden = true;
  tip.setAttribute("aria-hidden", "true");
  tip.append(document.createElement("span"));

  const article = (id) => section.querySelector(`.widget[data-wid="${CSS.escape(id)}"]`);
  const metrics = () => {
    const cs = getComputedStyle(section);
    return { row: parseFloat(cs.getPropertyValue("--dash-row")) || 88, gap: parseFloat(cs.getPropertyValue("--dash-gap")) || 16 };
  };
  const find = (items, id) => items.find((i) => i.id === id);
  const where = (items, id) => {
    const it = find(items, id);
    return mode === "grid" ? `row ${it.y + 1}, column ${it.x + 1}` : `position ${sortReading(items).findIndex((i) => i.id === id) + 1} of ${items.length}`;
  };
  const fits = (items) => validate(items, COLS, MAX_ROWS).length === 0;

  /** Places the frames: CSS variables in both modes (stack mode reads --h and the "narrow" class), DOM order in stack
   *  mode. `except` keeps one frame where it is (the one being dragged). */
  function place(items, { except = null, keep = null } = {}) {
    for (const it of items) {
      if (it.id === except) continue;
      const el = article(it.id);
      if (!el) continue;
      for (const k of ["x", "y", "w", "h"]) el.style.setProperty(`--${k}`, it[k]);
      el.classList.toggle("narrow", it.w <= 3);
    }
    section.style.setProperty("--rows", Math.max(1, bottom(items)) + (hooks.editing() ? 2 : 0));
    if (mode === "stack") sortDom(items, keep);
  }

  /** Puts the frames in reading order without ever moving `keep` (or the frame that has the focus): moving a focused
   *  element out of the document would lose the focus. */
  function sortDom(items, keep = null) {
    const els = sortReading(items).map((i) => article(i.id)).filter(Boolean);
    const now = [...section.querySelectorAll(":scope > .widget")];
    if (els.length === now.length && els.every((el, n) => el === now[n])) return;
    const fixed = keep || els.find((el) => el.contains(document.activeElement));
    if (!fixed) {
      els.forEach((el) => section.append(el));
    } else {
      const p = els.indexOf(fixed);
      els.slice(0, p).forEach((el) => fixed.before(el));
      let cursor = fixed;
      els.slice(p + 1).forEach((el) => { cursor.after(el); cursor = el; });
    }
    section.append(drop, tip);
  }

  function showDrop(it) {
    if (!it || mode !== "grid") { drop.hidden = true; return; }
    for (const k of ["x", "y", "w", "h"]) drop.style.setProperty(`--${k}`, it[k]);
    drop.hidden = false;
  }

  function setMode() {
    const next = section.clientWidth >= GRID_MIN ? "grid" : "stack";
    if (next === mode && section.classList.contains(`${mode === "grid" ? "grid" : "stack"}-mode`)) return;
    cancel(true);
    mode = next;
    section.classList.toggle("grid-mode", mode === "grid");
    section.classList.toggle("stack-mode", mode === "stack");
    place(hooks.items());
    if (mode === "grid") sortDom(hooks.items());
    hooks.modeChanged?.(mode);
  }
  const ro = new ResizeObserver(() => setMode());
  ro.observe(section);
  section.append(drop, tip);
  setMode();

  // ---------- pointer drags ----------
  function onDown(e) {
    if (!hooks.editing() || drag || kb || e.button !== 0) return;
    const handle = e.target.closest(".dash-handle, .dash-resize");
    let grip = handle;
    if (!grip) {
      const head = e.target.closest(".widget-head");
      if (!head || e.target.closest("button, a, input, select, textarea")) return;
      grip = head;
    }
    const el = grip.closest(".widget");
    if (!el || el.parentElement !== section) return;
    const resize = grip.classList.contains("dash-resize");
    if (resize && mode !== "grid") return;
    drag = {
      id: el.dataset.wid, el, grip, resize, pointerId: e.pointerId, sx: e.clientX, sy: e.clientY, x: e.clientX, y: e.clientY,
      threshold: e.pointerType === "touch" ? 8 : 4, active: false, base: hooks.items(), preview: null, cell: null, tx: 0, ty: 0,
    };
    try { grip.setPointerCapture(e.pointerId); } catch { /* the pointer is gone already */ }
    grip.addEventListener("pointermove", onMove);
    grip.addEventListener("pointerup", onUp);
    grip.addEventListener("pointercancel", onLost);
    grip.addEventListener("lostpointercapture", onLost);
    if (e.pointerType === "mouse") e.preventDefault(); // no text selection; the handle gets the focus here instead
    handle?.focus({ preventScroll: true });
  }

  function onMove(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    drag.x = e.clientX;
    drag.y = e.clientY;
    if (!drag.active) {
      if (Math.hypot(drag.x - drag.sx, drag.y - drag.sy) < drag.threshold) return;
      drag.active = true;
      const r = drag.el.getBoundingClientRect();
      drag.grab = { x: drag.sx - r.left, y: drag.sy - r.top };
      drag.el.classList.add(drag.resize ? "resizing" : "dragging");
      document.body.classList.add("dash-dragging");
    }
    if (!raf) raf = requestAnimationFrame(frame);
  }

  function follow() {
    if (!drag.el || drag.isNew) return;
    const r = drag.el.getBoundingClientRect();
    drag.tx += drag.x - drag.grab.x - r.left;
    drag.ty += drag.y - drag.grab.y - r.top;
    drag.el.style.transform = `translate(${drag.tx}px, ${drag.ty}px)`;
  }

  function autoScroll() {
    const h = window.innerHeight;
    const dy = drag.y < EDGE ? -(EDGE - drag.y) / 2 : drag.y > h - EDGE ? (EDGE - (h - drag.y)) / 2 : 0;
    if (dy) window.scrollBy(0, dy);
  }

  function frame() {
    raf = 0;
    if (!drag?.active) return;
    autoScroll();
    const rect = section.getBoundingClientRect();
    const m = metrics();
    const point = { x: drag.x, y: drag.y };
    if (drag.resize) {
      const { w, h } = sizeFromPoint(rect, point, find(drag.base, drag.id), COLS, m.row, m.gap);
      if (!drag.cell || drag.cell.w !== w || drag.cell.h !== h) {
        drag.cell = { w, h };
        const next = resizeTo(drag.base, drag.id, w, h, COLS, hooks.size(drag.id));
        if (fits(next)) drag.preview = next;
        place(drag.preview || drag.base);
        const it = find(drag.preview || drag.base, drag.id);
        tip.firstChild.textContent = `${it.w} × ${it.h}`;
        for (const k of ["x", "y", "w", "h"]) tip.style.setProperty(`--${k}`, it[k]);
        tip.hidden = false;
      }
    } else if (drag.isNew) {
      const inside = point.x >= rect.left && point.x <= rect.right && point.y >= rect.top - 40 && point.y <= rect.bottom + 80;
      drag.ghost.style.transform = `translate(${drag.x - drag.grab.x}px, ${drag.y - drag.grab.y}px)`;
      const cell = inside ? cellFromPoint(rect, point, drag.grab, COLS, m.row, m.gap) : null;
      if (JSON.stringify(cell) !== JSON.stringify(drag.cell)) {
        drag.cell = cell;
        const next = cell ? moveTo([...drag.base, drag.temp], drag.temp.id, cell.x, cell.y, COLS) : null;
        drag.preview = next && fits(next) ? next : null;
        place(drag.preview ? drag.preview.filter((i) => i.id !== drag.temp.id) : drag.base);
        showDrop(drag.preview && find(drag.preview, drag.temp.id));
      }
    } else if (mode === "grid") {
      const cell = cellFromPoint(rect, point, drag.grab, COLS, m.row, m.gap);
      if (!drag.cell || drag.cell.x !== cell.x || drag.cell.y !== cell.y) {
        drag.cell = cell;
        const next = moveTo(drag.base, drag.id, cell.x, cell.y, COLS);
        if (fits(next)) drag.preview = next;
        place(drag.preview || drag.base, { except: drag.id });
        showDrop(find(drag.preview || drag.base, drag.id));
      }
      follow();
    } else {
      // stack mode: the frames before the pointer (above it, or left of it in the same row) come first
      const others = [...section.querySelectorAll(":scope > .widget")].filter((el) => el !== drag.el);
      const index = others.filter((el) => {
        const r = el.getBoundingClientRect();
        return r.bottom < point.y || (r.top <= point.y && point.y <= r.bottom && r.left + r.width / 2 < point.x);
      }).length;
      if (index !== drag.cell) {
        drag.cell = index;
        const ids = others.map((el) => el.dataset.wid);
        ids.splice(index, 0, drag.id);
        const next = fromOrder(ids, drag.base, COLS);
        if (next) {
          drag.preview = next;
          sortDom(next, drag.el);
        }
      }
      follow();
    }
    raf = requestAnimationFrame(frame);
  }

  function release() {
    const d = drag;
    drag = null;
    cancelAnimationFrame(raf);
    raf = 0;
    if (!d) return null;
    d.grip?.removeEventListener("pointermove", onMove);
    d.grip?.removeEventListener("pointerup", onUp);
    d.grip?.removeEventListener("pointercancel", onLost);
    d.grip?.removeEventListener("lostpointercapture", onLost);
    try { if (d.grip?.hasPointerCapture?.(d.pointerId)) d.grip.releasePointerCapture(d.pointerId); } catch { /* released already */ }
    document.body.classList.remove("dash-dragging");
    d.ghost?.remove();
    if (d.el && !d.isNew) {
      d.el.classList.add("settle"); // straight to the new place, no slide from where it started
      d.el.classList.remove("dragging", "resizing");
      d.el.style.transform = "";
      requestAnimationFrame(() => requestAnimationFrame(() => d.el.classList.remove("settle")));
    }
    drop.hidden = true;
    tip.hidden = true;
    return d;
  }

  function onUp(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    const d = release();
    if (!d.active) return; // a click: the menu holds the single-pointer moves
    if (d.isNew) {
      if (!d.preview) { place(d.base); hooks.announce("Not added"); return; }
      place(d.preview.filter((i) => i.id !== d.temp.id));
      d.onDrop(d.preview, d.temp.id);
      return;
    }
    if (!d.preview || same(d.preview, d.base)) {
      place(d.base);
      hooks.announce(d.resize ? "Size unchanged" : "Not moved");
      return;
    }
    place(d.preview);
    const it = find(d.preview, d.id);
    hooks.commit(d.preview, {
      id: d.id,
      message: d.resize ? `Resized ${hooks.title(d.id)} to ${it.w} columns by ${it.h} rows` : `Moved ${hooks.title(d.id)} to ${where(d.preview, d.id)}`,
    });
  }

  function onLost(e) {
    if (!drag || e.pointerId !== drag.pointerId) return;
    const d = release();
    if (d.active) {
      place(d.base);
      hooks.announce(d.isNew ? "Not added" : d.resize ? "Resize cancelled" : "Move cancelled");
    }
  }

  /** Drags a new widget in from the gallery (grid mode): a ghost of w x h follows the pointer; onDrop(items, tempId)
   *  gets the layout with the new item placed. False when a drag cannot start now. */
  function dragNew(e, { w, h, label, onDrop }) {
    if (mode !== "grid" || drag || kb || e.button !== 0) return false;
    const m = metrics();
    const rect = section.getBoundingClientRect();
    const colW = (rect.width - m.gap * (COLS - 1)) / COLS;
    const ghost = document.createElement("div");
    ghost.className = "dash-ghost-new";
    ghost.textContent = label;
    ghost.style.width = `${w * colW + (w - 1) * m.gap}px`;
    ghost.style.height = `${h * m.row + (h - 1) * m.gap}px`;
    document.body.append(ghost);
    const grip = e.currentTarget instanceof Element ? e.currentTarget : e.target;
    drag = {
      isNew: true, ghost, grip, temp: { id: "__new", x: 0, y: 0, w, h }, onDrop, pointerId: e.pointerId, sx: e.clientX, sy: e.clientY,
      x: e.clientX, y: e.clientY, threshold: 0, active: true, base: hooks.items(), preview: null, cell: undefined, grab: { x: 16, y: 16 },
    };
    try { grip.setPointerCapture(e.pointerId); } catch { /* the pointer is gone already */ }
    grip.addEventListener("pointermove", onMove);
    grip.addEventListener("pointerup", onUp);
    grip.addEventListener("pointercancel", onLost);
    grip.addEventListener("lostpointercapture", onLost);
    document.body.classList.add("dash-dragging");
    e.preventDefault();
    raf = requestAnimationFrame(frame);
    return true;
  }

  // ---------- keyboard ----------
  const ARROWS = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] };
  const DIRS = { ArrowLeft: "left", ArrowRight: "right", ArrowUp: "up", ArrowDown: "down" };

  function pickUp(id, resize, btn) {
    const base = hooks.items();
    const it = find(base, id);
    if (!it) return;
    kb = { id, resize, base, preview: base, el: article(id), btn };
    kb.el.classList.add(resize ? "resizing" : "picked");
    const title = hooks.title(id);
    if (resize) hooks.announce(`Resizing ${title}: ${it.w} columns wide, ${it.h} rows tall. Arrow keys change the size, Space finishes, Escape cancels.`);
    else hooks.announce(`Picked up ${title}. ${where(base, id).replace(/^./, (c) => c.toUpperCase())}${mode === "grid" ? `, ${it.w} by ${it.h}` : ""}.`);
  }

  function endKb() {
    const k = kb;
    kb = null;
    k?.el?.classList.remove("picked", "resizing");
    return k;
  }

  function preview(next) {
    kb.preview = next;
    place(next, { keep: kb.el });
    kb.el.scrollIntoView({ block: "nearest" });
  }

  function onKey(e) {
    if (!hooks.editing()) return;
    if (drag?.active && e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      const d = release();
      place(d.base);
      hooks.announce(d.isNew ? "Not added" : d.resize ? "Resize cancelled" : "Move cancelled");
      return;
    }
    const btn = e.target.closest?.(".dash-handle, .dash-resize");
    if (!btn || !section.contains(btn)) return;
    const id = btn.closest(".widget").dataset.wid;
    const resize = btn.classList.contains("dash-resize");
    const k = e.key;
    if (!kb) {
      if (k === " " || k === "Enter") {
        e.preventDefault();
        pickUp(id, resize, btn);
      }
      return;
    }
    if (kb.id !== id || kb.resize !== resize) return;
    if (k in ARROWS || ["Home", "End", " ", "Enter", "Escape"].includes(k)) e.preventDefault();
    const title = hooks.title(id);
    const it = find(kb.preview, id);
    if (k === "Escape") {
      e.stopPropagation();
      const done = endKb();
      place(done.base, { keep: done.el });
      hooks.announce(resize ? "Resize cancelled" : "Move cancelled");
      return;
    }
    if (k === " " || k === "Enter") {
      const done = endKb();
      if (same(done.preview, done.base)) {
        hooks.announce(resize ? "Size unchanged" : "Dropped. Not moved");
        return;
      }
      const after = find(done.preview, id);
      hooks.commit(done.preview, { id, message: resize ? `${title} is ${after.w} columns wide, ${after.h} rows tall` : `Dropped at ${where(done.preview, id)}.` });
      return;
    }
    if (resize) {
      if (!(k in ARROWS)) return;
      const [dx, dy] = ARROWS[k];
      const next = resizeTo(kb.preview, id, it.w + dx, it.h + dy, COLS, hooks.size(id));
      const after = find(next, id);
      if (after.w === it.w && after.h === it.h) {
        const size = hooks.size(id);
        const atMin = (dx < 0 && it.w <= (size?.min.w ?? 1)) || (dy < 0 && it.h <= (size?.min.h ?? 1));
        hooks.announce(atMin ? "Minimum size" : dx > 0 && it.x + it.w >= COLS ? "No room to grow wider" : "Maximum size");
        return;
      }
      if (!fits(next)) return hooks.announce("No room");
      preview(next);
      hooks.announce(`${after.w} columns wide, ${after.h} rows tall`);
      return;
    }
    let next = null;
    if (mode === "grid") {
      if (k in ARROWS) {
        next = step(kb.preview, id, ...ARROWS[k], COLS);
        if (!next) return hooks.announce(`${title} cannot move further ${DIRS[k]}`);
      } else if (k === "Home" || k === "End") {
        next = moveTo(kb.preview, id, k === "Home" ? 0 : COLS - it.w, it.y, COLS);
      } else return;
    } else {
      const order = sortReading(kb.preview);
      const i = order.findIndex((o) => o.id === id);
      const delta = k === "ArrowUp" ? -1 : k === "ArrowDown" ? 1 : k === "Home" ? -i : k === "End" ? order.length - 1 - i : 0;
      if (!delta) return;
      next = moveInOrder(kb.preview, id, delta, COLS);
      if (!next) return hooks.announce(delta < 0 ? `${title} is first` : `${title} is last`);
    }
    if (!fits(next)) return hooks.announce("No room");
    preview(next);
    hooks.announce(where(next, id).replace(/^./, (c) => c.toUpperCase()));
  }

  function onFocusOut(e) {
    if (!kb || e.target !== kb.btn) return;
    if (e.relatedTarget === kb.btn) return;
    const done = endKb();
    place(done.base);
    hooks.announce(done.resize ? "Resize cancelled" : "Move cancelled");
  }

  section.addEventListener("pointerdown", onDown);
  section.addEventListener("focusout", onFocusOut);
  document.addEventListener("keydown", onKey, true);

  /** Stops a drag or a keyboard pick-up, putting the frames back (quiet: no announcement). */
  function cancel(quiet = false) {
    if (drag) {
      const d = release();
      if (d.active) place(d.base);
    }
    if (kb) {
      const done = endKb();
      place(done.base);
      if (!quiet) hooks.announce("Move cancelled");
    }
  }

  return {
    place,
    sortDom,
    dragNew,
    cancel,
    mode: () => mode,
    busy: () => Boolean(drag?.active || kb),
    refreshMode: setMode,
    destroy() {
      cancel(true);
      ro.disconnect();
      document.removeEventListener("keydown", onKey, true);
    },
  };
}
