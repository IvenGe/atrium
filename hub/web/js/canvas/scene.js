// Layout and routing of a whole canvas model in one pure step: lanes placed left to right, items ordered in their
// lane (shared layout order, else the default order), item rectangles, and the geometry of every edge. The engine
// calls it on each update; the Node tests measure it against the fixtures (canvas-design 4.10: <= 50 ms).
import { arrange, layoutLanes, placeLanes } from "./lanes.js";
import { routeEdges } from "./route.js";

/**
 * `model` {items: Map id -> item, edges: Map id -> edge}; `laneDefs` [{id, title, width}] left to right; `stored`
 * the layout's items ({id: {order, lane?}}). `laneOf(item, stored)` and `compare(a, b)` (default order) come from
 * the view; `size(item)` -> {w, h} (default: the item's own w/h); `top`/`gap` as in layoutLanes; `detour` as in
 * routeEdges (the lane boxes then reach below the lowest detour channel, so lanes and fit() include it).
 * Returns {lanes, order: Map laneId -> [{id, order, stored}], rects, boxes, routes}.
 */
export function scene(model, laneDefs, stored, { laneOf, compare, size = (i) => i, gutter = 176, top, gap, detour = false } = {}) {
  const lanes = placeLanes(laneDefs, gutter);
  const order = arrange(model.items.values(), stored || {}, (item) => laneOf(item, stored || {}), compare);
  const opts = {};
  if (top !== undefined) opts.top = top;
  if (gap !== undefined) opts.gap = gap;
  const laid = layoutLanes(lanes.map((l) => ({
    ...l,
    items: (order.get(l.id) || []).map((e) => {
      const { w, h } = size(model.items.get(e.id));
      return { id: e.id, w, h };
    }),
  })), opts);
  const routes = routeEdges([...model.edges.values()], laid.rects, lanes, { detour });
  let low = -Infinity;
  for (const r of routes.values()) if (r.kind === "detour") low = Math.max(low, r.yc);
  if (low > -Infinity) for (const b of laid.boxes.values()) b.h = Math.max(b.h, low + 20 - b.y);
  return { lanes, order, rects: laid.rects, boxes: laid.boxes, routes };
}
