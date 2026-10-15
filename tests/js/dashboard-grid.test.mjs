// The dashboard layout math (hub/web/js/dashboard/grid.js): the shared fixtures with the Python port
// (hub/dashboards/layout.py, tests/data/dashboard_layouts.json), moves, resizes, stack-mode reordering and a property
// test over random sequences.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  bottom, cellFromPoint, collides, compact, firstFit, fromOrder, indexFromPoint, moveInOrder, moveTo, newWidgetId, place,
  resizeTo, sizeFromPoint, sizePreset, sortReading, step, validate,
} from "../../hub/web/js/dashboard/grid.js";

const FIX = JSON.parse(readFileSync(new URL("../data/dashboard_layouts.json", import.meta.url), "utf8"));
const it = (id, x, y, w, h) => ({ id, x, y, w, h });
const at = (items, id) => { const i = items.find((o) => o.id === id); return [i.x, i.y, i.w, i.h]; };

test("shared fixtures: collides, sortReading, compact, firstFit, place, validate (same as layout.py)", () => {
  for (const c of FIX.collides) assert.equal(collides(c.a, c.b), c.expected, JSON.stringify(c));
  for (const c of FIX.sortReading) assert.deepEqual(sortReading(c.items).map((i) => i.id), c.expected);
  for (const c of FIX.compact) assert.deepEqual(compact(c.items), c.expected, c.name);
  for (const c of FIX.firstFit) {
    const spot = firstFit(c.items, c.w, c.h, FIX.cols, FIX.max_rows);
    assert.deepEqual(spot && [spot.x, spot.y], c.expected, c.name);
  }
  for (const c of FIX.place) assert.deepEqual(place(c.sizes, FIX.cols, FIX.max_rows).map((s) => s && [s.x, s.y]), c.expected, c.name);
  for (const c of FIX.validate) assert.deepEqual(validate(c.items, FIX.cols, FIX.max_rows), c.expected, c.name);
});

test("compact keeps the reading order of items that do not move and never changes x", () => {
  const out = compact([it("b", 3, 4, 3, 1), it("a", 0, 0, 3, 1), it("c", 9, 9, 3, 2)]);
  assert.deepEqual(out.map((i) => [i.id, i.x, i.y]), [["a", 0, 0], ["b", 3, 0], ["c", 9, 0]]);
  const input = [it("a", 0, 5, 2, 1)];
  compact(input);
  assert.equal(input[0].y, 5, "the arguments are never changed");
});

test("moveTo: push-down chains, clamping at the edges, no-op moves and moving into a gap", () => {
  const base = compact([it("a", 0, 0, 4, 2), it("b", 4, 0, 4, 2), it("c", 4, 2, 4, 1), it("d", 4, 3, 4, 1)]);
  // a lands on b's column: b, then c and d below it, are pushed down in a chain (b cannot swap above a at row 0)
  const pushed = moveTo(base, "a", 4, 0);
  assert.deepEqual(at(pushed, "a"), [4, 0, 4, 2]);
  assert.deepEqual(at(pushed, "b"), [4, 2, 4, 2]);
  assert.deepEqual(at(pushed, "c"), [4, 4, 4, 1]);
  assert.deepEqual(at(pushed, "d"), [4, 5, 4, 1]);
  assert.deepEqual(validate(pushed), []);
  // clamped: x beyond the grid stops at cols - w, negative coordinates at 0
  assert.deepEqual(at(moveTo(base, "a", 40, 0), "a"), [8, 0, 4, 2]);
  assert.deepEqual(at(moveTo(base, "b", -3, -2), "b"), [0, 0, 4, 2]);
  // a no-op move returns an equal layout
  assert.deepEqual(moveTo(base, "a", 0, 0), base);
  // a gap: the item moves there and gravity keeps it at the top
  assert.deepEqual(at(moveTo(base, "a", 8, 6), "a"), [8, 0, 4, 2]);
  // an unknown id changes nothing
  assert.deepEqual(moveTo(base, "zz", 1, 1), base);
});

test("moveTo: moving an item down onto the one below swaps them (it would fall back above it otherwise)", () => {
  const base = [it("a", 0, 0, 4, 2), it("b", 0, 2, 4, 2)];
  assert.deepEqual(moveTo(base, "a", 0, 1), base, "one row down only overlaps b: gravity puts a back");
  const swapped = moveTo(base, "a", 0, 2);
  assert.deepEqual(at(swapped, "b"), [0, 0, 4, 2]);
  assert.deepEqual(at(swapped, "a"), [0, 2, 4, 2]);
  // moving up over the item above swaps too
  const up = moveTo(swapped, "a", 0, 1);
  assert.deepEqual(at(up, "a"), [0, 0, 4, 2]);
  assert.deepEqual(at(up, "b"), [0, 2, 4, 2]);
});

test("step: a keyboard move goes to the next position where the layout changes, or nowhere", () => {
  const base = [it("a", 0, 0, 4, 2), it("b", 0, 2, 4, 2), it("c", 4, 0, 2, 1)];
  const down = step(base, "a", 0, 1);
  assert.deepEqual(at(down, "a"), [0, 2, 4, 2]);
  assert.deepEqual(at(down, "b"), [0, 0, 4, 2]);
  assert.equal(step(down, "a", 0, 1), null, "nothing below: gravity keeps it");
  assert.equal(step(base, "a", 0, -1), null, "already at the top");
  assert.equal(step(base, "a", -1, 0), null, "already at the left edge");
  assert.deepEqual(at(step(base, "c", 1, 0), "c"), [5, 0, 2, 1]);
  assert.equal(step([it("r", 10, 0, 2, 1)], "r", 1, 0), null, "already at the right edge");
  const back = step(down, "a", 0, -1);
  assert.deepEqual(at(back, "a"), [0, 0, 4, 2]);
});

test("resizeTo: clamped to the type bounds and the grid, pushing the items below down", () => {
  const size = { min: { w: 3, h: 2 }, default: { w: 4, h: 3 }, max: { w: 8, h: 6 } };
  const base = [it("a", 0, 0, 4, 3), it("b", 0, 3, 4, 2), it("c", 4, 0, 4, 1)];
  const wider = resizeTo(base, "a", 6, 3, 12, size);
  assert.deepEqual(at(wider, "a"), [0, 0, 6, 3]);
  assert.deepEqual(at(wider, "c"), [4, 3, 4, 1], "c overlapped and was pushed below a");
  assert.deepEqual(validate(wider), []);
  assert.deepEqual(at(resizeTo(base, "a", 1, 1, 12, size), "a"), [0, 0, 3, 2], "minimum size");
  assert.deepEqual(at(resizeTo(base, "a", 20, 20, 12, size), "a"), [0, 0, 8, 6], "maximum size");
  assert.deepEqual(at(resizeTo([it("r", 10, 0, 2, 1)], "r", 6, 1, 12), "r"), [10, 0, 2, 1], "never past the last column");
  const taller = resizeTo(base, "a", 4, 5, 12, size);
  assert.deepEqual(at(taller, "b"), [0, 5, 4, 2]);
});

test("firstFit on full and holey layouts", () => {
  assert.deepEqual(firstFit([], 4, 3), { x: 0, y: 0 });
  assert.deepEqual(firstFit([it("a", 0, 0, 3, 1), it("b", 6, 0, 6, 1)], 3, 1), { x: 3, y: 0 });
  assert.deepEqual(firstFit([it("a", 0, 0, 12, 4)], 2, 2), { x: 0, y: 4 });
  assert.equal(firstFit([it("a", 0, 0, 12, 2)], 1, 1, 12, 2), null);
  assert.deepEqual(firstFit([it("a", 0, 0, 3, 1)], 3, 1, 12, 200, { x: 4, y: 0 }), { x: 4, y: 0 }, "from a starting point");
});

test("fromOrder re-packs in the given order and keeps exactly that reading order", () => {
  const overview = [it("t1", 0, 0, 3, 1), it("t2", 3, 0, 3, 1), it("t3", 6, 0, 3, 1), it("t4", 9, 0, 3, 1),
    it("m1", 0, 1, 4, 1), it("m2", 4, 1, 4, 1), it("m3", 8, 1, 4, 1), it("apps", 0, 2, 7, 5), it("act", 7, 2, 5, 5)];
  assert.deepEqual(fromOrder(sortReading(overview).map((i) => i.id), overview), sortReading(overview), "the same order reproduces the layout");
  const order = ["t1", "t2", "t3", "t4", "m1", "m2", "apps", "m3", "act"];
  const out = fromOrder(order, overview);
  assert.deepEqual(out.map((i) => i.id), order);
  assert.deepEqual(validate(out), []);
  // ids left out come after the given ones, in reading order
  assert.deepEqual(fromOrder(["act"], overview).map((i) => i.id)[0], "act");
  // a big item placed after small ones never fills a hole before them
  const flow = fromOrder(["s1", "big", "s2"], [it("s1", 0, 0, 4, 1), it("big", 0, 1, 10, 2), it("s2", 0, 3, 4, 1)]);
  assert.deepEqual(flow.map((i) => i.id), ["s1", "big", "s2"]);
  assert.equal(fromOrder(["a", "b"], [it("a", 0, 0, 12, 2), it("b", 0, 2, 12, 2)], 12, 3), null, "no room");
});

test("moveInOrder swaps equal neighbours and re-packs otherwise", () => {
  const items = [it("a", 0, 0, 3, 1), it("b", 3, 0, 3, 1), it("c", 0, 1, 12, 3)];
  const swapped = moveInOrder(items, "a", 1);
  assert.deepEqual(swapped.map((i) => [i.id, i.x, i.y]), [["b", 0, 0], ["a", 3, 0], ["c", 0, 1]]);
  const repacked = moveInOrder(items, "c", -2);
  assert.deepEqual(repacked.map((i) => i.id), ["c", "a", "b"]);
  assert.deepEqual(validate(repacked), []);
  assert.equal(moveInOrder(items, "a", -1), null, "already first");
  assert.equal(moveInOrder(items, "c", 1), null, "already last");
});

test("cellFromPoint rounds to the nearest cell at the boundaries; sizeFromPoint and indexFromPoint", () => {
  // 12 columns of 64 px with 16 px gaps: 12 * 64 + 11 * 16 = 944 px; a column step is 80 px, a row step 104 px
  const rect = { left: 100, top: 50, width: 944 };
  const cell = (px, py) => cellFromPoint(rect, { x: 100 + px, y: 50 + py }, { x: 0, y: 0 }, 12, 88, 16);
  assert.deepEqual(cell(0, 0), { x: 0, y: 0 });
  assert.deepEqual(cell(39, 51), { x: 0, y: 0 });
  assert.deepEqual(cell(40, 52), { x: 1, y: 1 }, "exactly half a step rounds up");
  assert.deepEqual(cell(-500, -500), { x: 0, y: 0 }, "never negative");
  assert.deepEqual(cellFromPoint(rect, { x: 100 + 250, y: 50 + 10 }, { x: 90, y: 10 }, 12, 88, 16), { x: 2, y: 0 }, "the grab offset counts");
  assert.deepEqual(sizeFromPoint(rect, { x: 100 + 3 * 80 - 16, y: 50 + 2 * 104 - 16 }, { x: 0, y: 0 }, 12, 88, 16), { w: 3, h: 2 });
  assert.deepEqual(sizeFromPoint(rect, { x: 100 + 80 + 10, y: 50 + 5 }, { x: 1, y: 0 }, 12, 88, 16), { w: 1, h: 1 }, "at least 1 x 1");
  assert.equal(indexFromPoint([10, 50, 90], 5), 0);
  assert.equal(indexFromPoint([10, 50, 90], 60), 2);
  assert.equal(indexFromPoint([10, 50, 90], 200), 3);
});

test("size presets come from the type's bounds; widget ids match the server's pattern and are unique", () => {
  const size = { min: { w: 3, h: 2 }, default: { w: 6, h: 4 }, max: { w: 12, h: 8 } };
  assert.deepEqual(["small", "medium", "large", "wide", "tall"].map((n) => sizePreset(n, size)), [[3, 2], [6, 4], [9, 6], [12, 4], [6, 8]]);
  assert.equal(sizePreset("huge", size), null);
  const ids = new Set();
  for (let i = 0; i < 300; i++) {
    const id = newWidgetId([...ids]);
    assert.match(id, /^w_[0-9a-z]{10}$/);
    ids.add(id);
  }
  assert.equal(ids.size, 300);
  assert.equal(bottom([]), 0);
});

test("property: 500 random move, resize and reorder sequences keep the layout valid", () => {
  let seed = 42;
  const rand = (n) => { seed = (seed * 1103515245 + 12345) % 2147483648; return Math.floor((seed / 2147483648) * n); };
  const size = { min: { w: 2, h: 1 }, default: { w: 4, h: 2 }, max: { w: 12, h: 6 } };
  for (let run = 0; run < 500; run++) {
    const sizes = Array.from({ length: 2 + rand(10) }, () => [1 + rand(12), 1 + rand(5)]);
    let items = place(sizes).map((s, n) => ({ id: `w${n}`, ...s, w: sizes[n][0], h: sizes[n][1] }));
    for (let op = 0; op < 8; op++) {
      const id = items[rand(items.length)].id;
      const kind = rand(5);
      const next = kind === 0 ? moveTo(items, id, rand(14) - 1, rand(12) - 1)
        : kind === 1 ? resizeTo(items, id, 1 + rand(12), 1 + rand(6), 12, size)
          : kind === 2 ? moveInOrder(items, id, rand(5) - 2)
            : kind === 3 ? step(items, id, rand(3) - 1, 0) || step(items, id, 0, rand(3) - 1) : compact(items);
      if (!next) continue;
      assert.deepEqual(validate(next), [], `run ${run} op ${op} kind ${kind}`);
      assert.equal(next.length, items.length);
      assert.deepEqual(new Set(next.map((i) => i.id)), new Set(items.map((i) => i.id)));
      items = next;
    }
  }
});
