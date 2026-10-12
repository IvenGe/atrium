/** Lane geometry: rectangles from ordered items, insertion index, fractional order keys. */

export function between(a, b) {
  if (a == null && b == null) return 1;
  if (a == null) return b - 1;
  if (b == null) return a + 1;
  if (!Number.isFinite(a) || !Number.isFinite(b)) return 1;
  return (a + b) / 2;
}

export function normalize(items) {
  return [...(items || [])].sort((a, b) => {
    const ao = Number.isFinite(a.order) ? a.order : 0;
    const bo = Number.isFinite(b.order) ? b.order : 0;
    if (ao !== bo) return ao - bo;
    return String(a.id).localeCompare(String(b.id));
  });
}

/**
 * lanes: [{id, x, width, items: [{id, h, order}]}]
 * Returns one rectangle per item, stacked top to bottom inside the lane.
 */
export function laneRects(lanes, gap = 12, pad = 16) {
  const out = [];
  for (const lane of lanes || []) {
    let y = pad;
    for (const item of normalize(lane.items)) {
      const h = item.h || 64;
      const w = Math.max(40, (lane.width || 0) - pad * 2);
      out.push({
        id: item.id, lane: lane.id, x: (lane.x || 0) + pad, y, w, h,
        order: Number.isFinite(item.order) ? item.order : 0,
      });
      y += h + gap;
    }
  }
  return out;
}

/** Index at which a drop at world-y would land, compared with each item's midpoint. */
export function insertionIndex(laneItems, y, gap = 12, pad = 16) {
  const items = normalize(laneItems);
  let cursor = pad;
  for (let i = 0; i < items.length; i++) {
    const h = items[i].h || 64;
    if (y < cursor + h / 2) return i;
    cursor += h + gap;
  }
  return items.length;
}

/** Order key that inserts `id` at `index` among the lane's current items. */
export function orderAt(laneItems, index) {
  const items = normalize(laneItems);
  const prev = index > 0 ? items[index - 1].order : null;
  const next = index < items.length ? items[index].order : null;
  return between(prev, next);
}
