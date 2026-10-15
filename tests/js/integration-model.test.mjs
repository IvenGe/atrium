// The Integration map's model (hub/web/js/canvas/integration-model.js) and the measurement gate of canvas-design
// 4.10: the 200-tool / 400-flow fixture lays out and routes in 50 ms or less under Node.
import assert from "node:assert/strict";
import { test } from "node:test";
import { integrationFixture, segmentationFixture } from "../../hub/web/js/canvas/fixture.js";
import {
  LANES, buildModel, canConnect, compareItems, edgeName, flowFromEvent, flowState, gripSides, isNewer, itemName, laneOf, movableLanes, toolLane,
} from "../../hub/web/js/canvas/integration-model.js";
import { scene } from "../../hub/web/js/canvas/scene.js";

const base = { status: "enabled", failures: 0, last_result: null, running: null, repair: null, job: null };

test("flow states follow the first-match table", () => {
  assert.equal(flowState({ ...base, running: 1 }).state, "running");
  assert.equal(flowState({ ...base, job: { status: "running", progress: 40 } }).chip, "scan 40%");
  assert.equal(flowState({ ...base, repair: "ap_1", failures: 3 }).state, "repair");
  assert.equal(flowState({ ...base, repair: "requested" }).chip, "diagnosing");
  assert.deepEqual(flowState({ ...base, failures: 2 }), { state: "failing", chip: "failed 2×" });
  assert.equal(flowState({ ...base, last_result: { ok: false } }).chip, "failed 1×");
  assert.equal(flowState({ ...base, status: "proposed" }).state, "proposed");
  assert.equal(flowState({ ...base, status: "disabled", job: { status: "awaiting_approval" } }).state, "scan_waiting");
  assert.deepEqual(flowState(base), { state: "enabled", chip: null });
  assert.equal(flowState({ ...base, status: "disabled", failures: 4 }).state, "disabled");
});

test("live flow events: computed fields and age check", () => {
  const prev = { id: "f", title: "Snipe-IT assets -> Hub Assets", owner: "module:assets", updated_at: 10 };
  const raw = { id: "f", domain: "assets", source: "tool:snipe", target: "hub", action: null, status: "enabled", schedule_minutes: 60, last_run: 100, title: "", updated_at: 11 };
  const f = flowFromEvent(raw, prev);
  assert.equal(f.direction, "pull");
  assert.equal(f.tool_id, "snipe");
  assert.equal(f.next_run, 100 + 3600);
  assert.equal(f.title, prev.title);
  assert.equal(f.owner, "module:assets");
  assert.equal(flowFromEvent({ ...raw, source: "hub", target: "tool:scan", action: "scan", status: "proposed" }).direction, "scan");
  assert.equal(flowFromEvent({ ...raw, status: "disabled" }).next_run, null);
  assert.ok(isNewer(raw, prev));
  assert.ok(!isNewer({ ...raw, updated_at: 9 }, prev));
  assert.ok(isNewer(raw, null));
});

test("lanes: defaults, swaps for connected tools only, grips facing the spine", () => {
  const left = { lane_default: "left", id: "tool:a" };
  assert.equal(toolLane(left, {}), "left");
  assert.equal(toolLane(left, { "tool:a": { order: 1, lane: "right" } }), "right");
  assert.equal(toolLane({ lane_default: "shelf", id: "tool:b" }, { "tool:b": { order: 1, lane: "left" } }), "shelf");
  const data = integrationFixture({ tools: 20, flows: 30 });
  const { items } = buildModel(data);
  const tool = [...items.values()].find((i) => i.kind === "tool" && laneOf(i, {}) === "left");
  assert.deepEqual(movableLanes(tool, {}), ["left", "right"]);
  assert.deepEqual(gripSides(tool, {}), ["right"]);
  assert.deepEqual(movableLanes(items.get("app:assets"), {}), ["spine"]);
  assert.deepEqual(gripSides(items.get("app:assets"), {}), ["left", "right"]);
});

test("buildModel: flows to the app port of their domain, filters, hidden items, SSO near the selection", () => {
  const data = integrationFixture({ tools: 40, flows: 60 });
  const all = buildModel(data);
  assert.equal(all.counts.tools, 40);
  assert.equal(all.counts.apps, 5);
  const flowEdges = [...all.edges.values()].filter((e) => e.kind === "flow");
  assert.equal(flowEdges.length, data.flows.length);
  for (const e of flowEdges) {
    const app = all.items.get(e.to.id);
    assert.ok(app.domains.includes(e.flow.domain));
    assert.equal(e.to.port, 40 + 22 * app.domains.indexOf(e.flow.domain) + 11);
    assert.equal(e.arrow, { pull: "to", push: "from", scan: "both" }[e.flow.direction]);
  }
  assert.ok(![...all.edges.values()].some((e) => e.kind === "sso"));
  const failing = buildModel(data, { flows: "failing" });
  assert.ok([...failing.edges.values()].every((e) => e.state === "failing" || e.state === "repair"));
  const hiddenId = flowEdges[0].from.id;
  const hidden = buildModel(data, { hidden: new Set([hiddenId]) });
  assert.ok(!hidden.items.has(hiddenId));
  assert.ok(![...hidden.edges.values()].some((e) => e.from.id === hiddenId || e.to.id === hiddenId));
  const sso = data.sso[0];
  const near = buildModel(data, { selection: sso.target });
  assert.ok(near.edges.has(sso.id));
  assert.ok(buildModel(data, { show: { sso: true, events: true } }).edges.size > all.edges.size);
});

test("canConnect hints follow the table", () => {
  const items = new Map([
    ["app:assets", { id: "app:assets", kind: "app", label: "Assets", domains: ["assets"], active: true }],
    ["app:compliance", { id: "app:compliance", kind: "app", label: "Compliance hub", domains: ["controls", "risks"], active: true }],
    ["tool:inv", { id: "tool:inv", kind: "tool", label: "Inventory", connection: { kind: "x" }, caps: { assets: ["read", "write"] }, sor: ["assets"], actions: [] }],
    ["tool:grc", { id: "tool:grc", kind: "tool", label: "GRC", connection: { kind: "y" }, caps: { assets: ["write"], controls: ["write"] }, sor: [], actions: [] }],
    ["tool:new", { id: "tool:new", kind: "tool", label: "New", connection: null, caps: {}, sor: [], actions: [] }],
    ["tool:kc", { id: "tool:kc", kind: "tool", label: "Keycloak", is_idp: true, connection: null, caps: {}, sor: [], actions: [] }],
    ["tool:ak", { id: "tool:ak", kind: "tool", label: "authentik", is_idp: true, connection: null, caps: {}, sor: [], actions: [] }],
  ]);
  assert.equal(canConnect(items, "tool:inv", "tool:inv").ok, false);
  assert.equal(canConnect(items, "app:assets", "app:compliance").reason, "Hub apps share data internally");
  assert.equal(canConnect(items, "tool:kc", "tool:ak").reason, "Identity providers do not sign in through each other");
  assert.deepEqual(canConnect(items, "tool:new", "tool:kc"), { ok: true, reason: "single sign-on", sso: true });
  assert.equal(canConnect(items, "tool:new", "app:assets").reason, "New has no connection yet");
  assert.equal(canConnect(items, "tool:inv", "app:assets").ok, true);
  assert.equal(canConnect(items, "app:compliance", "tool:inv").ok, false);
  assert.equal(canConnect(items, "tool:grc", "app:compliance").ok, true);
  assert.equal(canConnect(items, "tool:inv", "tool:grc").ok, true); // inventory reads assets, GRC takes them
  assert.equal(canConnect(items, "tool:grc", "tool:new").ok, false);
});

test("accessible names carry the state", () => {
  const data = integrationFixture({ tools: 10, flows: 10 });
  const { items, edges } = buildModel(data);
  const tool = [...items.values()].find((i) => i.kind === "tool" && i.connection);
  assert.match(itemName(tool, "Sources"), new RegExp(`^${tool.label}, tool, Sources, `));
  assert.match(itemName(items.get("app:assets")), /^Assets, hub app, \d+ data flows?/);
  const edge = [...edges.values()][0];
  assert.match(edgeName(edge, (id) => items.get(id).label, 1760000000), /^Data flow, .+ to .+, /);
});

test("measurement gate: the integration fixture lays out and routes in 50 ms or less", () => {
  const data = integrationFixture({ tools: 200, flows: 400 });
  const run = () => {
    const model = buildModel(data);
    return scene(model, LANES, {}, { laneOf, compare: compareItems });
  };
  run(); // warm up the JIT
  const times = [];
  let out;
  for (let i = 0; i < 5; i++) {
    const t0 = performance.now();
    out = run();
    times.push(performance.now() - t0);
  }
  times.sort((a, b) => a - b);
  assert.equal(out.rects.size, 205);
  assert.ok(out.routes.size >= 390);
  assert.ok(times[2] <= 50, `median ${times[2].toFixed(1)} ms`);
});

test("the segmentation fixture has the documented size and shape", () => {
  const seg = segmentationFixture();
  assert.equal(seg.zones.length, 50);
  assert.equal(seg.assets.length, 1000);
  assert.equal(seg.edges.length, 300);
  assert.equal(seg.zones[0].id, "z:internet");
  for (const e of seg.edges) assert.ok(seg.zones.some((z) => z.id === e.source) && seg.zones.some((z) => z.id === e.target));
  assert.deepEqual(segmentationFixture(), seg); // deterministic
});
