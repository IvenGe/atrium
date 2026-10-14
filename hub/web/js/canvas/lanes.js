// Lane (swimlane) geometry and the shared order of items in a lane (canvas-design 4.1, 4.9). Pure: no DOM,
// unit-tested under Node (tests/js/lanes.test.mjs).
//
// Order keys are fractional numbers stored per item in the shared layout ({id: {order, lane?}}). An item without a
// stored order takes its default rank in the lane (0, 1, 2 ...); items sort by (order, id), so equal keys from two
// people moving at once still give one stable order.

export const ITEM_GAP = 24;
export const LANE_TOP = 56; // room for the lane titles above the first item
export const MAX_ORDER = 1e9; // the server refuses larger keys

/** Lane x positions from their widths, left to right with `gutter` px between: [{id, width, ...}] -> [{..., x}]. */
export function placeLanes(defs, gutter = 176) {
  let x = 0;
  return defs.map((d) => {
    const lane = { ...d, x };
    x += d.width + gutter;
    return lane;
  });
}

/** Items per lane in display order: Map laneId -> [{id, order, stored}]. `laneOf(item)` gives an item's lane,
 *  `compare(a, b)` the default order (used for items without a stored order), `stored` is layout.items. */
export function arrange(items, stored, laneOf, compare) {
  const groups = new Map();
  for (const item of items) {
    const lane = laneOf(item);
    if (lane == null) continue;
    if (!groups.has(lane)) groups.set(lane, []);
    groups.get(lane).push(item);
  }
  const out = new Map();
  for (const [lane, list] of groups) {
    list.sort(compare);
    const entries = list.map((item, rank) => {
      const s = stored?.[item.id];
      const ok = s && Number.isFinite(s.order);
      return { id: item.id, order: ok ? s.order : rank, stored: !!ok };
    });
    out.set(lane, sortEntries(entries));
  }
  return out;
}

/** Collision normalization: sort by (order, id). */
export function sortEntries(entries) {
  return entries.sort((a, b) => a.order - b.order || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Item rectangles. `lanes`: [{id, x, width, items: [{id, w, h}]}] with items in display order; each item is centred
 * in its lane, stacked from `top` with `gap` between. Returns {rects: Map id -> {x, y, w, h, lane, index},
 * boxes: Map laneId -> {x, y, w, h}} (a lane box spans its items, at least `minHeight`).
 */
export function layoutLanes(lanes, { top = LANE_TOP, gap = ITEM_GAP, minHeight = 120 } = {}) {
  const rects = new Map();
  const boxes = new Map();
  for (const lane of lanes) {
    let y = top;
    lane.items.forEach((item, index) => {
      rects.set(item.id, { x: lane.x + (lane.width - item.w) / 2, y, w: item.w, h: item.h, lane: lane.id, index });
      y += item.h + gap;
    });
    boxes.set(lane.id, { x: lane.x, y: 0, w: lane.width, h: Math.max(minHeight, y - gap + top / 2) });
  }
  return { rects, boxes };
}

/** Where a dragged item would land in a lane: the index among `rects` (that lane's other items, in order) for a
 *  pointer at world y - before the first item whose middle is below the pointer. */
export function insertionIndex(rects, y) {
  const i = rects.findIndex((r) => y < r.y + r.h / 2);
  return i === -1 ? rects.length : i;
}

/** A key between two neighbours (null for "none"); null when there is no room (equal or too close keys). */
export function between(a, b) {
  if (a == null && b == null) return 1;
  if (a == null) return b - 1;
  if (b == null) return a + 1;
  const m = (a + b) / 2;
  return m > a && m < b ? m : null;
}

/**
 * The stored orders a move needs: `entries` are the target lane's items in display order WITHOUT the moved one,
 * `index` its new place among them. When every neighbour has a stored order only the moved item gets a key
 * between its new neighbours; otherwise (defaults, or no room left) the whole lane is renumbered 1..n, so later
 * moves need one key again. Returns {id: order}.
 */
export function planMove(entries, id, index) {
  const at = Math.max(0, Math.min(index, entries.length));
  if (entries.every((e) => e.stored)) {
    const order = between(entries[at - 1]?.order ?? null, entries[at]?.order ?? null);
    if (order !== null && Math.abs(order) <= MAX_ORDER) return { [id]: order };
  }
  const ids = [...entries.slice(0, at).map((e) => e.id), id, ...entries.slice(at).map((e) => e.id)];
  return Object.fromEntries(ids.map((x, i) => [x, i + 1]));
}

/** The lane under a world x: the lane whose box, widened by half the gutter on each side, holds it (null outside). */
export function laneAt(lanes, x, gutter = 176) {
  return lanes.find((l) => x >= l.x - gutter / 2 && x < l.x + l.width + gutter / 2)?.id ?? null;
}
