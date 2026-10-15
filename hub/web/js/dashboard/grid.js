// Layout math of the Home dashboards (round4-dashboard-spec.md 10.5): pure functions over items {id, x, y, w, h} in a
// grid of `cols` columns with vertical gravity. Every function returns new objects and never changes its arguments;
// other keys of an item are kept. hub/dashboards/layout.py is the Python port the server checks saved layouts with;
// both are tested against tests/data/dashboard_layouts.json.

export const COLS = 12;
export const MAX_ROWS = 200;

const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

export function collides(a, b) {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

const byReading = (a, b) => a.y - b.y || a.x - b.x || (String(a.id) < String(b.id) ? -1 : String(a.id) > String(b.id) ? 1 : 0);

/** Reading order: row, then column, then id. */
export const sortReading = (items) => [...items].sort(byReading);

/** The first row below every item (0 for none). */
export const bottom = (items) => items.reduce((m, i) => Math.max(m, i.y + i.h), 0);

/** Vertical gravity: each item, in reading order, moves up while y > 0 and it does not collide with the items already
 *  placed. Returns the items in reading order. */
export function compact(items) {
  const placed = [];
  for (const item of sortReading(items)) {
    const moved = { ...item };
    while (moved.y > 0 && !placed.some((p) => collides({ ...moved, y: moved.y - 1 }, p))) moved.y -= 1;
    placed.push(moved);
  }
  return sortReading(placed);
}

// Makes room for `fixed` (already in `layout`, whose items are this call's own copies): an item it overlaps moves just
// above it when it fits there (only for the person's own move, `swap`), else just below it, and whatever that one then
// overlaps is pushed down in turn. The swap is what lets an item move down past another one under gravity: pushed
// below, the other item would fall back above it on compaction. The lowest items go first, so a column pushed down
// keeps its order.
function makeRoom(layout, fixed, swap) {
  for (const hit of sortReading(layout.filter((o) => o.id !== fixed.id && collides(o, fixed))).reverse()) {
    const other = layout.find((o) => o.id === hit.id);
    if (!collides(other, fixed)) continue; // moved already by an earlier push
    const above = { ...other, y: fixed.y - other.h };
    if (swap && above.y >= 0 && !layout.some((o) => o.id !== other.id && collides(above, o))) {
      other.y = above.y;
      continue;
    }
    other.y = fixed.y + fixed.h;
    makeRoom(layout, other, false);
  }
}

/** Moves item `id` to (x, y): x clamped to the grid, the items in the way moved aside, then gravity. */
export function moveTo(items, id, x, y, cols = COLS) {
  const item = items.find((i) => i.id === id);
  if (!item) return items.map((i) => ({ ...i }));
  const moved = { ...item, x: clamp(Math.round(x), 0, Math.max(0, cols - item.w)), y: Math.max(0, Math.round(y)) };
  const layout = items.map((i) => (i.id === id ? moved : { ...i }));
  makeRoom(layout, moved, true);
  return compact(layout);
}

/** One keyboard step (dx, dy in -1..1): the next position in that direction where the layout really changes (under
 *  gravity a single row down can fall back to where it was); null when the item cannot go further that way. */
export function step(items, id, dx, dy, cols = COLS) {
  const item = items.find((i) => i.id === id);
  if (!item) return null;
  const limit = Math.max(1, bottom(items) + 1);
  for (let k = 1; k <= limit; k++) {
    const x = item.x + dx * k, y = item.y + dy * k;
    if (x < 0 || x + item.w > cols || y < 0) return null;
    const next = moveTo(items, id, x, y, cols);
    const after = next.find((i) => i.id === id);
    if (after.x !== item.x || after.y !== item.y) return next;
    if (dx) return null;
  }
  return null;
}

/** Resizes item `id` to w x h, clamped to `size` ({min: {w, h}, max: {w, h}}, the catalog's) and to the grid, pushing the
 *  items in the way down, then gravity. */
export function resizeTo(items, id, w, h, cols = COLS, size = null) {
  const item = items.find((i) => i.id === id);
  if (!item) return items.map((i) => ({ ...i }));
  const min = size?.min || { w: 1, h: 1 }, max = size?.max || { w: cols, h: 12 };
  const sized = { ...item, w: Math.min(cols - item.x, clamp(Math.round(w), min.w, max.w)), h: clamp(Math.round(h), min.h, max.h) };
  const layout = items.map((i) => (i.id === id ? sized : { ...i }));
  makeRoom(layout, sized, false);
  return compact(layout);
}

/** The first free {x, y} for a w x h item, scanning rows top-down and columns left to right; null when full. */
export function firstFit(items, w, h, cols = COLS, maxRows = MAX_ROWS, from = null) {
  w = clamp(w, 1, cols);
  for (let y = from ? from.y : 0; y <= maxRows - h; y++) {
    for (let x = from && y === from.y ? from.x : 0; x <= cols - w; x++) {
      const spot = { x, y, w, h };
      if (!items.some((t) => collides(spot, t))) return { x, y };
    }
  }
  return null;
}

/** Positions for items of these [w, h] sizes added one after another with firstFit (templates, "Add"). */
export function place(sizes, cols = COLS, maxRows = MAX_ROWS) {
  const taken = [];
  return sizes.map(([w, h], n) => {
    const spot = firstFit(taken, w, h, cols, maxRows);
    if (spot) taken.push({ id: n, ...spot, w, h });
    return spot;
  });
}

/** Re-packs the items in the order of `ids` (the rest after them, in reading order): each one goes to the first free
 *  spot after the previous one, so the reading order is exactly that order (stack-mode reordering). Null when they no
 *  longer fit in maxRows. */
export function fromOrder(ids, items, cols = COLS, maxRows = MAX_ROWS) {
  const byId = new Map(items.map((i) => [i.id, i]));
  const order = [...new Set(ids)].filter((id) => byId.has(id));
  for (const i of sortReading(items)) if (!order.includes(i.id)) order.push(i.id);
  const out = [];
  let from = null;
  for (const id of order) {
    const item = byId.get(id);
    const spot = firstFit(out, item.w, item.h, cols, maxRows, from);
    if (!spot) return null;
    out.push({ ...item, ...spot });
    from = { x: spot.x + 1, y: spot.y };
  }
  return sortReading(out);
}

/** Moves item `id` by `delta` places in reading order: a swap of positions with an equally sized neighbour, else a
 *  re-pack in the new order (fromOrder). Null when it cannot move that far. */
export function moveInOrder(items, id, delta, cols = COLS) {
  const order = sortReading(items);
  const i = order.findIndex((o) => o.id === id);
  const j = i + delta;
  if (i < 0 || !delta || j < 0 || j >= order.length) return null;
  const a = order[i], b = order[j];
  if (Math.abs(delta) === 1 && a.w === b.w && a.h === b.h) {
    return sortReading(items.map((o) => (o.id === a.id ? { ...o, x: b.x, y: b.y } : o.id === b.id ? { ...o, x: a.x, y: a.y } : { ...o })));
  }
  const ids = order.map((o) => o.id);
  ids.splice(i, 1);
  ids.splice(j, 0, id);
  return fromOrder(ids, items, cols);
}

/** The server's layout rules as a list of problems {code, id} (empty: valid): duplicate_id, out_of_bounds and overlap
 *  (named once, by the later item in input order). */
export function validate(items, cols = COLS, maxRows = MAX_ROWS) {
  const problems = [];
  const seen = new Set();
  const checked = [];
  for (const item of items) {
    const id = String(item.id);
    if (seen.has(id)) { problems.push({ code: "duplicate_id", id }); continue; }
    seen.add(id);
    if (item.x < 0 || item.y < 0 || item.w < 1 || item.h < 1 || item.x + item.w > cols || item.y + item.h > maxRows) {
      problems.push({ code: "out_of_bounds", id });
      continue;
    }
    if (checked.some((o) => collides(item, o))) problems.push({ code: "overlap", id });
    checked.push(item);
  }
  return problems;
}

/** The cell {x, y} whose top-left corner is nearest to where an item's top-left corner is while it is dragged: the
 *  pointer minus where the item was grabbed, in a grid at `rect` (its client rect) with rows of rowPx and gaps of gapPx. */
export function cellFromPoint(rect, point, grab, cols = COLS, rowPx = 88, gapPx = 16) {
  const colW = (rect.width - gapPx * (cols - 1)) / cols;
  const left = point.x - rect.left - grab.x, top = point.y - rect.top - grab.y;
  return { x: Math.max(0, Math.round(left / (colW + gapPx))), y: Math.max(0, Math.round(top / (rowPx + gapPx))) };
}

/** The size {w, h} an item at (item.x, item.y) gets when its bottom-right corner is dragged to `point`. */
export function sizeFromPoint(rect, point, item, cols = COLS, rowPx = 88, gapPx = 16) {
  const colW = (rect.width - gapPx * (cols - 1)) / cols;
  const width = point.x - rect.left - item.x * (colW + gapPx), height = point.y - rect.top - item.y * (rowPx + gapPx);
  return { w: Math.max(1, Math.round((width + gapPx) / (colW + gapPx))), h: Math.max(1, Math.round((height + gapPx) / (rowPx + gapPx))) };
}

/** Where a dragged item goes in a stack of items whose vertical middles are `mids` (top to bottom): before the first
 *  middle below the pointer. */
export const indexFromPoint = (mids, y) => mids.filter((m) => m < y).length;

/** The [w, h] of a size preset of the options menu, from a type's size bounds {min, default, max}. */
export function sizePreset(name, size) {
  const { min, max } = size, def = size.default;
  const mid = (a, b) => Math.ceil((a + b) / 2);
  return { small: [min.w, min.h], medium: [def.w, def.h], large: [mid(def.w, max.w), mid(def.h, max.h)],
    wide: [max.w, def.h], tall: [def.w, max.h] }[name] || null;
}

const ID_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz";

/** A new widget id (^w_[0-9a-z]{10}$) not in `taken`. */
export function newWidgetId(taken = []) {
  const used = new Set(taken);
  for (;;) {
    const bytes = new Uint8Array(10);
    if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
    else for (let i = 0; i < 10; i++) bytes[i] = Math.floor(Math.random() * 256);
    const id = `w_${[...bytes].map((b) => ID_CHARS[b % 36]).join("")}`;
    if (!used.has(id)) return id;
  }
}
