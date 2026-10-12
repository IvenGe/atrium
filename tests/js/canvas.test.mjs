import assert from "node:assert/strict";
import test from "node:test";
import { clampK, ensureVisible, fit, toScreen, toWorld, zoomAt } from "../../hub/web/js/canvas/camera.js";
import { between, insertionIndex, laneRects, orderAt } from "../../hub/web/js/canvas/lanes.js";
import { cubic, gutter, labelAnchor, tracks } from "../../hub/web/js/canvas/route.js";

test("camera clamps zoom and converts coordinates", () => {
  assert.equal(clampK(0), 0.3);
  assert.equal(clampK(9), 2);
  assert.equal(clampK(Number.NaN), 1);
  const camera = { k: 2, tx: 10, ty: 20 };
  assert.deepEqual(toScreen(camera, 5, 6), { x: 20, y: 32 });
  assert.deepEqual(toWorld(camera, 20, 32), { x: 5, y: 6 });
  const zoomed = zoomAt(camera, 20, 32, 0.5);
  assert.equal(zoomed.k, 1);
  assert.deepEqual(toWorld(zoomed, 20, 32), { x: 5, y: 6 });
});

test("fit keeps the bounds inside the viewport and caps k", () => {
  const camera = fit({ minX: 0, minY: 0, maxX: 100, maxY: 100 }, { w: 1000, h: 1000 }, 48, 1.25);
  assert.ok(camera.k <= 1.25);
  assert.ok(camera.k >= 0.3);
  const origin = toScreen(camera, 0, 0);
  const far = toScreen(camera, 100, 100);
  assert.ok(origin.x >= 40 && origin.y >= 40);
  assert.ok(far.x <= 960 && far.y <= 960);
});

test("ensureVisible pans a clipped item back into view", () => {
  const next = ensureVisible({ k: 1, tx: 0, ty: 0 }, { x: -100, y: 10, w: 40, h: 20 }, { w: 400, h: 300 }, { left: 0 });
  assert.ok(next.tx > 0);
});

test("lanes stack by order and insert between neighbours", () => {
  assert.equal(between(1, 3), 2);
  assert.equal(between(null, 1), 0);
  const rects = laneRects([{ id: "a", x: 0, width: 200, items: [{ id: "b", h: 40, order: 2 }, { id: "a", h: 40, order: 1 }] }]);
  assert.deepEqual(rects.map((r) => r.id), ["a", "b"]);
  assert.ok(rects[1].y > rects[0].y);
  const items = [{ id: "a", h: 40, order: 1 }, { id: "b", h: 40, order: 3 }];
  assert.equal(insertionIndex(items, 0), 0);
  assert.equal(insertionIndex(items, 10_000), 2);
  const order = orderAt(items, 1);
  assert.ok(order > 1 && order < 3);
});

test("routes are deterministic and tracks differ for a repeated pair", () => {
  const path = cubic(0, 0, 100, 40);
  assert.equal(path, cubic(0, 0, 100, 40));
  assert.match(gutter(0, 0, 80, 40, 1), /^M0,0 H/);
  assert.deepEqual(labelAnchor(0, 0, 10, 20), { x: 5, y: 10 });
  const assigned = tracks([{ id: "e1", source: "a", target: "b" }, { id: "e2", source: "b", target: "a" }]);
  assert.notEqual(assigned.get("e1"), assigned.get("e2"));
});
