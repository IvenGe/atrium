// Edge geometry (canvas-design 5.3): primary edges between items in adjacent lanes are H-V-H gutter routes - out of
// the item, along the edge's own track (a vertical line in the gutter), into the other item - with one track per
// edge in each gutter; every other edge is a cubic Bézier. Pure: no DOM, unit-tested under Node
// (tests/js/route.test.mjs). Output is deterministic for the same input.

export const TRACK = 8; // track spacing; compresses when a gutter holds more edges than fit
export const MARGIN = 16; // kept free on both sides of a gutter
export const RADIUS = 8; // corner radius
const SPREAD = 6; // px between edge ends that share an item side without an explicit port

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const r1 = (v) => Math.round(v * 10) / 10;

/**
 * Track x per edge: `edges` [{id, gutter: {key, x0, x1}, y1, y2}]. Edges of one gutter are ordered by the y of the
 * end they enter (y2), then y1, then id, and spread evenly around the gutter's middle: 8 px apart, closer when the
 * gutter is full. Two edges of one gutter never share a track. Returns Map id -> x.
 */
export function assignTracks(edges, { spacing = TRACK, margin = MARGIN } = {}) {
  const groups = new Map();
  for (const e of edges) {
    if (!groups.has(e.gutter.key)) groups.set(e.gutter.key, []);
    groups.get(e.gutter.key).push(e);
  }
  const out = new Map();
  for (const list of groups.values()) {
    list.sort((a, b) => a.y2 - b.y2 || a.y1 - b.y1 || cmp(a.id, b.id));
    const { x0, x1 } = list[0].gutter;
    const usable = Math.max(1, x1 - x0 - 2 * margin);
    const step = list.length > 1 ? Math.min(spacing, usable / (list.length - 1)) : 0;
    const start = (x0 + x1) / 2 - (step * (list.length - 1)) / 2;
    list.forEach((e, i) => out.set(e.id, start + i * step));
  }
  return out;
}

/** SVG path of an H-V-H route from (x1, y1) along track tx to (x2, y2), corners rounded by up to r. */
export function hvhPath(x1, y1, tx, x2, y2, r = RADIUS) {
  const dy = y2 - y1;
  if (Math.abs(dy) < 0.5) return `M${r1(x1)},${r1(y1)} H${r1(x2)}`;
  const c = Math.max(0, Math.min(r, Math.abs(dy) / 2, Math.abs(tx - x1), Math.abs(x2 - tx)));
  const sx1 = Math.sign(tx - x1) || 1, sx2 = Math.sign(x2 - tx) || 1, sy = Math.sign(dy);
  return `M${r1(x1)},${r1(y1)} H${r1(tx - sx1 * c)} Q${r1(tx)},${r1(y1)} ${r1(tx)},${r1(y1 + sy * c)}`
    + ` V${r1(y2 - sy * c)} Q${r1(tx)},${r1(y2)} ${r1(tx + sx2 * c)},${r1(y2)} H${r1(x2)}`;
}

/** A cubic Bézier leaving (x1, y1) towards side1 ("left" | "right") and entering (x2, y2) from side2, with its
 *  point at t = 0.5 as the label anchor. Ends on the same side bend out on that side (a loop). */
export function bezier(x1, y1, side1, x2, y2, side2) {
  const d1 = side1 === "left" ? -1 : 1, d2 = side2 === "left" ? -1 : 1;
  const c = side1 === side2 ? 60 + Math.abs(y2 - y1) * 0.25 : Math.max(40, Math.abs(x2 - x1) * 0.5);
  const c1x = x1 + d1 * c, c2x = x2 + d2 * c;
  const mid = { x: (x1 + 3 * c1x + 3 * c2x + x2) / 8, y: (y1 + 3 * y1 + 3 * y2 + y2) / 8 };
  return { d: `M${r1(x1)},${r1(y1)} C${r1(c1x)},${r1(y1)} ${r1(c2x)},${r1(y2)} ${r1(x2)},${r1(y2)}`, mid };
}

export const DETOUR_CLEAR = 24; // the first detour channel lies this far below the lowest item it passes
export const DETOUR_STEP = 14; // channels whose spans overlap are at least this far apart

/** A detour: out of (x1, y1) into the gutter at gx1, down (or up) to channel yc, along it to gx2, into (x2, y2).
 *  Both turns are S-curves with horizontal tangents, so arrowheads at either end stay horizontal. */
export function detourPath(x1, y1, gx1, yc, gx2, x2, y2) {
  const m1 = (x1 + gx1) / 2, m2 = (gx2 + x2) / 2;
  return `M${r1(x1)},${r1(y1)} C${r1(m1)},${r1(y1)} ${r1(m1)},${r1(yc)} ${r1(gx1)},${r1(yc)} H${r1(gx2)}`
    + ` C${r1(m2)},${r1(yc)} ${r1(m2)},${r1(y2)} ${r1(x2)},${r1(y2)}`;
}

/**
 * Channels for edges that skip lanes (opt-in `detour`): an edge whose straight Bézier would cross an item in a lane
 * between its ends runs below every item of those lanes instead, turning in the gutters next to its own items. Each
 * gets its own channel: shorter spans first, a channel moves down while it is closer than DETOUR_STEP to one already
 * placed whose x range overlaps. `list`: [{id, ia, ib, y1, y2, side1}]; returns Map id -> {gx1, gx2, yc}.
 */
function detours(list, rects, lanes) {
  const bottom = new Map(); // lane index -> lowest item bottom
  const top = new Map();
  for (const r of rects.values()) {
    const i = lanes.findIndex((l) => l.id === r.lane);
    bottom.set(i, Math.max(bottom.get(i) ?? -Infinity, r.y + r.h));
    top.set(i, Math.min(top.get(i) ?? Infinity, r.y));
  }
  const mid = (i, dir) => { // the middle of the gutter on side dir (+1 right, -1 left) of lane i
    const l = lanes[i], n = lanes[i + dir];
    return dir > 0 ? (l.x + l.width + n.x) / 2 : (n.x + n.width + l.x) / 2;
  };
  const wanted = [];
  for (const e of list) {
    const lo = Math.min(e.ia, e.ib), hi = Math.max(e.ia, e.ib);
    let floor = -Infinity, crosses = false;
    for (let i = lo + 1; i < hi; i++) {
      if (!bottom.has(i)) continue;
      floor = Math.max(floor, bottom.get(i));
      // the straight Bézier stays between y1 and y2: it crosses lane i when that band meets the lane's items
      if (Math.min(e.y1, e.y2) < bottom.get(i) + 8 && Math.max(e.y1, e.y2) > top.get(i) - 8) crosses = true;
    }
    if (!crosses) continue;
    const dir = e.ib > e.ia ? 1 : -1;
    const gx1 = mid(e.ia, dir), gx2 = mid(e.ib, -dir);
    wanted.push({ ...e, gx1, gx2, x0: Math.min(gx1, gx2), x1: Math.max(gx1, gx2), base: floor + DETOUR_CLEAR, span: hi - lo });
  }
  wanted.sort((a, b) => a.span - b.span || a.x0 - b.x0 || cmp(a.id, b.id));
  const placed = [];
  const out = new Map();
  for (const w of wanted) {
    const near = placed.filter((p) => p.x0 <= w.x1 && w.x0 <= p.x1).map((p) => p.yc).sort((a, b) => a - b);
    let yc = w.base;
    for (const y of near) if (Math.abs(y - yc) < DETOUR_STEP) yc = y + DETOUR_STEP;
    // nested turns: a lower channel turns a little closer to its items, so its vertical leg does not cross a higher
    // channel that leaves the same gutter
    const k = Math.min(4, Math.round((yc - w.base) / DETOUR_STEP));
    const nudge = (2 - k) * 4;
    const dir = w.ib > w.ia ? 1 : -1;
    placed.push({ x0: w.x0, x1: w.x1, yc });
    out.set(w.id, { gx1: w.gx1 + dir * nudge, gx2: w.gx2 - dir * nudge, yc });
  }
  return out;
}

/**
 * Geometry of every edge. `edges`: [{id, from: {id, port?}, to: {id, port?}, primary}] (port: y offset of the
 * end inside its item); `rects`: Map itemId -> {x, y, w, h, lane}; `lanes`: [{id, x, width}] left to right.
 * Returns Map edgeId -> {kind: "gutter" | "bezier" | "detour", d, x1, y1, x2, y2, side1, side2, track?, yc?,
 * label: {x, y}}.
 * A gutter route's label starts just outside the `from` item, on its own end (align "start": the label extends to the
 * right of x; "end": to the left), so a chip never covers the item;
 * with `detour`, non-gutter edges that would cross items of the lanes they skip run below them (see detours());
 * edges whose ends are missing are left out.
 */
export function routeEdges(edges, rects, lanes, { detour = false } = {}) {
  const laneIndex = new Map(lanes.map((l, i) => [l.id, i]));
  const ends = [];
  for (const e of edges) {
    const a = rects.get(e.from.id), b = rects.get(e.to.id);
    if (!a || !b) continue;
    const ia = laneIndex.get(a.lane) ?? 0, ib = laneIndex.get(b.lane) ?? 0;
    let side1, side2;
    if (ia === ib && e.from.id !== e.to.id) {
      side1 = side2 = ia === lanes.length - 1 ? "left" : "right";
    } else {
      const ab = a.x + a.w / 2 <= b.x + b.w / 2;
      side1 = ab ? "right" : "left";
      side2 = ab ? "left" : "right";
    }
    ends.push({ e, a, b, ia, ib, side1, side2 });
  }
  // ends without a port share their item side: spread them, ordered by where the other end is
  const shared = new Map();
  const share = (rectId, side, otherY, slot) => {
    const key = `${rectId}|${side}`;
    if (!shared.has(key)) shared.set(key, []);
    shared.get(key).push({ otherY, slot });
  };
  const ys = ends.map(({ e, a, b, side1, side2 }) => {
    const y = { y1: a.y + (e.from.port ?? a.h / 2), y2: b.y + (e.to.port ?? b.h / 2) };
    if (e.from.port == null) share(e.from.id, side1, y.y2, { y, which: "y1", rect: a, id: e.id });
    if (e.to.port == null) share(e.to.id, side2, y.y1, { y, which: "y2", rect: b, id: e.id });
    return y;
  });
  for (const list of shared.values()) {
    if (list.length < 2) continue;
    list.sort((p, q) => p.otherY - q.otherY || cmp(p.slot.id, q.slot.id));
    const room = Math.max(0, list[0].slot.rect.h / 2 - 8);
    const step = Math.min(SPREAD, (2 * room) / (list.length - 1));
    list.forEach((p, i) => { p.slot.y[p.slot.which] += (i - (list.length - 1) / 2) * step; });
  }
  const gutterEdges = [];
  const geo = ends.map(({ e, a, b, ia, ib, side1, side2 }, i) => {
    const { y1, y2 } = ys[i];
    const x1 = side1 === "right" ? a.x + a.w : a.x, x2 = side2 === "right" ? b.x + b.w : b.x;
    const g = { id: e.id, x1, y1, x2, y2, side1, side2 };
    if (e.primary && Math.abs(ia - ib) === 1) {
      const left = lanes[Math.min(ia, ib)], right = lanes[Math.max(ia, ib)];
      g.gutter = { key: `${left.id}|${right.id}`, x0: left.x + left.width, x1: right.x };
      gutterEdges.push(g);
    }
    return g;
  });
  const tracks = assignTracks(gutterEdges);
  const channels = detour
    ? detours(ends.map(({ e, ia, ib }, i) => (!geo[i].gutter && Math.abs(ia - ib) > 1 ? { id: e.id, ia, ib, y1: geo[i].y1, y2: geo[i].y2 } : null))
      .filter(Boolean), rects, lanes)
    : new Map();
  const out = new Map();
  for (const g of geo) {
    const { id, x1, y1, x2, y2, side1, side2 } = g;
    const ch = channels.get(id);
    if (ch) {
      out.set(id, { kind: "detour", d: detourPath(x1, y1, ch.gx1, ch.yc, ch.gx2, x2, y2), x1, y1, x2, y2, side1, side2, yc: ch.yc,
        label: { x: (ch.gx1 + ch.gx2) / 2, y: ch.yc } });
    } else if (g.gutter) {
      const tx = tracks.get(id);
      out.set(id, { kind: "gutter", d: hvhPath(x1, y1, tx, x2, y2), x1, y1, x2, y2, side1, side2, track: tx,
        label: { x: x1 + (side1 === "right" ? 8 : -8), y: y1, align: side1 === "right" ? "start" : "end" } });
    } else {
      const bz = bezier(x1, y1, side1, x2, y2, side2);
      out.set(id, { kind: "bezier", d: bz.d, x1, y1, x2, y2, side1, side2, label: bz.mid });
    }
  }
  return out;
}
