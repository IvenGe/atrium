// Lane geometry and order keys (hub/web/js/canvas/lanes.js).
import assert from "node:assert/strict";
import { test } from "node:test";
import { arrange, between, insertionIndex, laneAt, layoutLanes, placeLanes, planMove, sortEntries } from "../../hub/web/js/canvas/lanes.js";

test("between() orders keys and reports when there is no room", () => {
  assert.equal(between(null, null), 1);
  assert.equal(between(null, 3), 2);
  assert.equal(between(3, null), 4);
  const m = between(1, 2);
  assert.ok(m > 1 && m < 2);
  assert.equal(between(2, 2), null);
  assert.equal(between(1, 1 + Number.EPSILON), null);
  // repeated halving keeps strict order until the keys run out
  let lo = 0, hi = 1, n = 0;
  for (let x = between(lo, hi); x !== null; x = between(lo, hi)) { hi = x; n += 1; }
  assert.ok(n > 40);
});

test("placeLanes spaces lanes by width and gutter", () => {
  const lanes = placeLanes([{ id: "a", width: 100 }, { id: "b", width: 200 }, { id: "c", width: 100 }], 50);
  assert.deepEqual(lanes.map((l) => l.x), [0, 150, 400]);
  assert.equal(laneAt(lanes, 120, 50), "a");
  assert.equal(laneAt(lanes, 130, 50), "b");
  assert.equal(laneAt(lanes, 900, 50), null);
});

test("arrange uses stored orders, default ranks otherwise, and sorts collisions by id", () => {
  const items = [{ id: "t:c", name: "c" }, { id: "t:a", name: "a" }, { id: "t:b", name: "b" }, { id: "t:z", name: "z", lane: "other" }];
  const byName = (x, y) => x.name.localeCompare(y.name);
  const out = arrange(items, { "t:c": { order: -1 } }, (i) => i.lane || "main", byName);
  assert.deepEqual(out.get("main").map((e) => e.id), ["t:c", "t:a", "t:b"]);
  assert.deepEqual(out.get("main").map((e) => e.stored), [true, false, false]);
  assert.deepEqual(out.get("other").map((e) => e.id), ["t:z"]);
  const tie = arrange(items.slice(0, 3), { "t:c": { order: 1 }, "t:a": { order: 1 }, "t:b": { order: 1 } }, () => "main", byName);
  assert.deepEqual(tie.get("main").map((e) => e.id), ["t:a", "t:b", "t:c"]);
  assert.deepEqual(sortEntries([{ id: "b", order: 2 }, { id: "a", order: 2 }, { id: "c", order: 1 }]).map((e) => e.id), ["c", "a", "b"]);
});

test("layoutLanes stacks items centred in their lane", () => {
  const { rects, boxes } = layoutLanes([{ id: "l", x: 100, width: 200, items: [{ id: "a", w: 100, h: 50 }, { id: "b", w: 200, h: 30 }] }], { top: 10, gap: 5 });
  assert.deepEqual(rects.get("a"), { x: 150, y: 10, w: 100, h: 50, lane: "l", index: 0 });
  assert.deepEqual(rects.get("b"), { x: 100, y: 65, w: 200, h: 30, lane: "l", index: 1 });
  assert.equal(boxes.get("l").x, 100);
  assert.ok(boxes.get("l").h >= 95);
});

test("insertionIndex picks the slot by item middles", () => {
  const rects = [{ y: 0, h: 50 }, { y: 70, h: 50 }, { y: 140, h: 50 }];
  assert.equal(insertionIndex(rects, -10), 0);
  assert.equal(insertionIndex(rects, 24), 0);
  assert.equal(insertionIndex(rects, 26), 1);
  assert.equal(insertionIndex(rects, 100), 2);
  assert.equal(insertionIndex(rects, 500), 3);
  assert.equal(insertionIndex([], 5), 0);
});

test("planMove writes one key between stored neighbours, else renumbers the lane", () => {
  const stored = [{ id: "a", order: 1, stored: true }, { id: "b", order: 2, stored: true }];
  const one = planMove(stored, "x", 1);
  assert.deepEqual(Object.keys(one), ["x"]);
  assert.ok(one.x > 1 && one.x < 2);
  assert.deepEqual(planMove(stored, "x", 0), { x: 0 });
  assert.deepEqual(planMove(stored, "x", 9), { x: 3 });
  assert.deepEqual(planMove([{ id: "a", order: 0, stored: false }, { id: "b", order: 1, stored: true }], "x", 1), { a: 1, x: 2, b: 3 });
  assert.deepEqual(planMove([{ id: "a", order: 1, stored: true }, { id: "b", order: 1, stored: true }], "x", 1), { a: 1, x: 2, b: 3 });
  assert.deepEqual(planMove([], "x", 0), { x: 1 });
});
