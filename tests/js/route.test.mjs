// Edge routing (hub/web/js/canvas/route.js): gutter tracks, deterministic output.
import assert from "node:assert/strict";
import { test } from "node:test";
import { assignTracks, bezier, hvhPath, routeEdges } from "../../hub/web/js/canvas/route.js";

const lanes = [{ id: "left", x: 0, width: 184 }, { id: "spine", x: 360, width: 208 }, { id: "right", x: 744, width: 184 }];

function grid(nTools, nEdges) {
  const rects = new Map();
  rects.set("app", { x: 360, y: 56, w: 208, h: 200, lane: "spine" });
  for (let i = 0; i < nTools; i++) rects.set(`t${i}`, { x: i % 2 ? 744 : 0, y: 56 + Math.floor(i / 2) * 80, w: 184, h: 56, lane: i % 2 ? "right" : "left" });
  const edges = [];
  for (let i = 0; i < nEdges; i++) edges.push({ id: `e${i}`, from: { id: `t${i % nTools}` }, to: { id: "app", port: 40 + 22 * (i % 4) + 11 }, primary: true });
  return { rects, edges };
}

test("two edges in the same gutter never share a track", () => {
  for (const n of [2, 10, 30, 200]) {
    const { rects, edges } = grid(40, n);
    const routes = routeEdges(edges, rects, lanes);
    const byGutter = new Map();
    for (const [id, r] of routes) {
      assert.equal(r.kind, "gutter", id);
      const key = r.x1 < 360 ? "left" : "right";
      if (!byGutter.has(key)) byGutter.set(key, new Set());
      const tracks = byGutter.get(key);
      assert.ok(!tracks.has(r.track), `${id} shares track ${r.track}`);
      tracks.add(r.track);
      // the track lies inside the gutter
      if (key === "left") assert.ok(r.track > 184 && r.track < 360);
      else assert.ok(r.track > 568 && r.track < 744);
    }
  }
});

test("routes are deterministic whatever the input order", () => {
  const { rects, edges } = grid(12, 30);
  const a = routeEdges(edges, rects, lanes);
  const b = routeEdges([...edges].reverse(), rects, lanes);
  for (const [id, r] of a) assert.deepEqual(b.get(id), r);
});

test("tracks are 8 px apart until the gutter is full, then compress", () => {
  const g = { key: "g", x0: 0, x1: 176 };
  const few = assignTracks([{ id: "a", gutter: g, y1: 0, y2: 10 }, { id: "b", gutter: g, y1: 0, y2: 20 }]);
  assert.equal(few.get("b") - few.get("a"), 8);
  const many = assignTracks(Array.from({ length: 50 }, (_, i) => ({ id: `e${i}`, gutter: g, y1: 0, y2: i })));
  const xs = [...many.values()].sort((p, q) => p - q);
  assert.ok(xs[0] >= 16 - 1e-9 && xs.at(-1) <= 160 + 1e-9);
  assert.equal(new Set(xs).size, 50);
});

test("edges between non-adjacent lanes and secondary edges are Béziers", () => {
  const rects = new Map([["a", { x: 0, y: 0, w: 184, h: 56, lane: "left" }], ["b", { x: 744, y: 100, w: 184, h: 56, lane: "right" }],
    ["c", { x: 0, y: 200, w: 184, h: 56, lane: "left" }]]);
  const routes = routeEdges([
    { id: "far", from: { id: "a" }, to: { id: "b" }, primary: true },
    { id: "same", from: { id: "a" }, to: { id: "c" }, primary: false },
    { id: "gone", from: { id: "a" }, to: { id: "missing" }, primary: true },
  ], rects, lanes);
  assert.equal(routes.get("far").kind, "bezier");
  assert.equal(routes.get("same").kind, "bezier");
  assert.equal(routes.get("same").side1, "right");
  assert.equal(routes.get("same").side2, "right");
  assert.ok(!routes.has("gone"));
});

test("path helpers", () => {
  assert.equal(hvhPath(0, 10, 50, 100, 10), "M0,10 H100");
  const d = hvhPath(0, 0, 50, 100, 100);
  assert.match(d, /^M0,0 H42 Q50,0 50,8 V92 Q50,100 58,100 H100$/);
  const bz = bezier(0, 0, "right", 100, 100, "left");
  assert.match(bz.d, /^M0,0 C/);
  assert.deepEqual(bz.mid, { x: 50, y: 50 });
});

// one item per lane on one row, like a small firewall's zones (segmentation map)
const row = [0, 1, 2, 3, 4].map((i) => ({ id: `L${i}`, x: i * 380, width: 300 }));
const rowRects = () => new Map(row.map((l, i) => [`z${i}`, { x: l.x, y: 56, w: 300, h: 90, lane: l.id }]));

test("detour: edges that skip lanes run below the items in between, each on its own channel", () => {
  const rects = rowRects();
  const edges = [
    { id: "a", from: { id: "z0" }, to: { id: "z2" }, primary: false },
    { id: "b", from: { id: "z0" }, to: { id: "z3" }, primary: false },
    { id: "c", from: { id: "z4" }, to: { id: "z1" }, primary: false },
    { id: "near", from: { id: "z1" }, to: { id: "z2" }, primary: false },
  ];
  const plain = routeEdges(edges, rects, row);
  for (const r of plain.values()) assert.equal(r.kind, "bezier"); // off by default: the Integration map is unchanged
  const routes = routeEdges(edges, rects, row, { detour: true });
  assert.equal(routes.get("near").kind, "bezier"); // adjacent lanes: the gutter is free
  const bottom = 56 + 90;
  const ys = ["a", "b", "c"].map((id) => {
    const r = routes.get(id);
    assert.equal(r.kind, "detour", id);
    assert.ok(r.yc >= bottom + 24, `${id} runs below the items`);
    assert.match(r.d, /^M[\d.]+,[\d.]+ C.* H[\d.]+ C.*$/);
    assert.equal(r.label.y, r.yc); // the chip sits on the channel, clear of every item
    return r.yc;
  });
  // overlapping spans never share a channel
  const sorted = [...ys].sort((p, q) => p - q);
  for (let i = 1; i < sorted.length; i++) assert.ok(sorted[i] - sorted[i - 1] >= 14, `channels ${sorted}`);
  // the shorter span takes the higher channel; the turns lie in the gutters next to the ends
  assert.ok(routes.get("a").yc < routes.get("b").yc);
  const turns = routes.get("a").d.match(/H([\d.]+)/)[1];
  assert.ok(Number(turns) > 680 && Number(turns) < 760, `turn x ${turns} in the gutter before lane 2`);
  // right-to-left keeps its sides: out of the left side, into the right side
  assert.equal(routes.get("c").side1, "left");
  assert.equal(routes.get("c").side2, "right");
  assert.deepEqual(routeEdges([...edges].reverse(), rects, row, { detour: true }), routes); // deterministic
});

test("detour: a skip-lane edge whose band is free of items stays a Bézier; the scene's lanes reach the channels", async () => {
  const rects = rowRects();
  rects.set("z1", { x: 380, y: 400, w: 300, h: 90, lane: "L1" }); // the item in between sits far below the ends
  const free = routeEdges([{ id: "a", from: { id: "z0" }, to: { id: "z2" }, primary: false }], rects, row, { detour: true });
  assert.equal(free.get("a").kind, "bezier");
  const { scene } = await import("../../hub/web/js/canvas/scene.js");
  const items = new Map(row.map((l, i) => [`z${i}`, { id: `z${i}`, lane: l.id, w: 300, h: 90 }]));
  const model = { items, edges: new Map([["far", { id: "far", from: { id: "z0" }, to: { id: "z4" }, primary: false }]]) };
  const sc = scene(model, row.map(({ id, width }) => ({ id, width })), {}, { laneOf: (i) => i.lane, compare: () => 0, gutter: 80, detour: true });
  const r = sc.routes.get("far");
  assert.equal(r.kind, "detour");
  for (const b of sc.boxes.values()) assert.ok(b.y + b.h >= r.yc + 20, "every lane box reaches below the channel");
});
