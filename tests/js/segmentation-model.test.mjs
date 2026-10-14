// The Segmentation map's model (hub/web/js/canvas/segmentation-model.js) and the element / time budget of the
// segmentation fixture (canvas-design 4.10, B3): 50 zones, 1000 assets and 300 allowed-traffic edges.
import assert from "node:assert/strict";
import { test } from "node:test";
import { segmentationFixture } from "../../hub/web/js/canvas/fixture.js";
import {
  AUTO_ALL, CHIP_LIMIT, GUTTER, LANES, MATRIX_MAX, MAX_CLUSTERS, buildModel, canAllow, canConnect, changeRequest, chipBox, compareZones,
  edgeChips, edgeName, edgeWidth, findingsText, matrix, pairEdges, portsProblem, ruleChange, servicesFrom, servicesText, severityLine, splitPair,
  verdictOf, zoneContents, zoneName, zoneSize,
} from "../../hub/web/js/canvas/segmentation-model.js";
import { placeLanes } from "../../hub/web/js/canvas/lanes.js";
import { scene } from "../../hub/web/js/canvas/scene.js";

const zone = (id, role, extra = {}) => ({ id, kind: "interface", name: id.split(":").pop().toUpperCase(), label: null, role, role_source: "manual",
  lane: { internet: "internet", users: "users", servers: "servers", management: "core", guest: "edge", unknown: "unclassified" }[role],
  badges: [], subnets: role === "internet" ? [] : [`10.0.${id.length}.0/24`], interfaces: [], vlan: null, native_id: role === "internet" ? null : id.split(":").pop(),
  firewall: "fw", same_subnet_as: [], vuln: { critical: 0, high: 0, medium: 0, low: 0, info: 0, overdue: 0 }, asset_count: 0, ...extra });
const edge = (s, t, extra = {}) => ({ id: `zp:${s}>${t}`, source: s, target: t, services: [{ proto: "tcp", ports: "443", label: "HTTPS", rule_ids: ["fw:r1"] }],
  any_service: false, rule_count: 1, bidirectional: false, approximate: true, notes: [], evaluable: true, violations: [], exposure: null, pending_changes: [],
  rules: [{ id: "fw:r1", order: 1, action: "pass", enabled: true, interfaces: ["lan"], source: "LAN net", destination: "any", service: "tcp/443", description: "web" }], ...extra });

function sample() {
  const zones = [zone("z:internet", "internet", { kind: "pseudo" }), zone("z:fw:lan", "users"), zone("z:fw:srv", "servers"), zone("z:fw:mgmt", "management"),
    zone("z:fw:guest", "guest", { role_source: "heuristic", badges: ["role not confirmed"] })];
  const edges = [
    edge("z:fw:lan", "z:fw:srv"), edge("z:fw:srv", "z:fw:lan", { services: [{ proto: "udp", ports: "53", label: "DNS", rule_ids: ["fw:r2"] }] }),
    edge("z:fw:lan", "z:fw:mgmt", { violations: [{ policy: "untrusted-to-management", verdict: "forbidden", control: "HB-NW-1", possible: true }] }),
    edge("z:internet", "z:fw:srv", { exposure: { critical: 2, high: 1, not_on_allowed_ports: { critical: 0, high: 0 } } }),
    edge("z:fw:guest", "z:internet", { any_service: true, services: [] }),
  ];
  return { zones, edges, assets: [], unplaced: [], changes: [] };
}

test("pairs allowed both ways are one edge with two arrowheads, raw ids map to it", () => {
  const { pairs, index } = pairEdges(sample().edges);
  assert.equal(pairs.length, 4);
  const both = pairs.find((p) => p.backward);
  assert.equal(both.id, "zp:z:fw:lan>z:fw:srv"); // the direction whose source sorts first
  assert.equal(index.get("zp:z:fw:srv>z:fw:lan"), both.id);
  const m = buildModel(sample(), { traffic: "all" });
  assert.equal(m.edges.get(both.id).arrow, "both");
  assert.equal(servicesText(m.edges.get(both.id).raw), "HTTPS, DNS");
  assert.equal(m.counts.edges, 4);
});

test("zone ids holding '>' still split into their two zones", () => {
  const known = new Set(["z:fw:a>b", "z:fw:c"]);
  assert.deepEqual(splitPair("zp:z:fw:a>b>z:fw:c", (x) => known.has(x)), ["z:fw:a>b", "z:fw:c"]);
  assert.equal(splitPair("zp:z:fw:x>z:fw:c", (x) => known.has(x)), null);
  assert.equal(splitPair("chg:1", () => true), null);
});

test("traffic filter: focus keeps violations, proposed changes and the selection's edges; auto switches at the limit", () => {
  const data = sample();
  const focus = buildModel(data, { traffic: "focus" });
  assert.deepEqual([...focus.edges.keys()], ["zp:z:fw:lan>z:fw:mgmt"]);
  const sel = buildModel(data, { traffic: "focus", selection: "z:fw:srv" });
  assert.deepEqual([...sel.edges.keys()].sort(), ["zp:z:fw:lan>z:fw:mgmt", "zp:z:fw:lan>z:fw:srv", "zp:z:internet>z:fw:srv"]);
  assert.equal(buildModel(data).traffic, "all");
  const big = segmentationFixture({ zones: 20, assets: 50, edges: AUTO_ALL + 40 });
  assert.equal(buildModel(big).traffic, "focus");
});

test("proposed allow changes are ghost edges; proposed disables mark their edge", () => {
  const data = sample();
  data.changes = [
    { id: "chg_1", status: "proposed", op: "allow", edge: "zp:z:fw:guest>z:fw:srv", proposed_by: "alice" },
    { id: "chg_2", status: "approved", op: "disable_rules", edge: "zp:z:fw:srv>z:fw:lan", proposed_by: "bob" },
    { id: "chg_3", status: "applied", op: "allow", edge: "zp:z:fw:lan>z:fw:guest" }, // finished: not drawn
  ];
  const m = buildModel(data, { traffic: "focus" });
  const ghost = m.edges.get("chg:chg_1");
  assert.equal(ghost.kind, "change");
  assert.deepEqual([ghost.from.id, ghost.to.id], ["z:fw:guest", "z:fw:srv"]);
  const marked = m.edges.get("zp:z:fw:lan>z:fw:srv"); // kept by the focus filter because of its pending change
  assert.equal(marked.disabling.id, "chg_2");
  assert.equal(edgeChips(marked).chip, "disable approved");
  assert.ok(!m.edges.has("chg:chg_3"));
  const names = (id) => m.items.get(id).label;
  assert.equal(edgeName(ghost, names), "Proposed change chg_1, allow GUEST to SRV, proposed by alice");
  const verifying = { ...ghost, change: { ...ghost.change, status: "verifying" } };
  assert.equal(edgeName(verifying, names), "Change chg_1, allow GUEST to SRV, verifying, proposed by alice");
  assert.match(edgeName(marked, names), /and back, HTTPS, DNS, 2 rules, disable approved$/);
});

test("chips: violations and exposure only with their overlay, any service otherwise", () => {
  const m = buildModel(sample(), { traffic: "all" });
  const bad = m.edges.get("zp:z:fw:lan>z:fw:mgmt");
  assert.equal(edgeChips(bad, { compliance: true }).chip, "may violate HB-NW-1");
  assert.equal(edgeChips(bad, {}).chip, null);
  assert.equal(edgeChips(m.edges.get("zp:z:internet>z:fw:srv"), { vulns: true }).chip, "exposes 2 critical and 1 high");
  assert.equal(edgeChips(m.edges.get("zp:z:fw:guest>z:internet"), {}).chip, "any");
  assert.equal(verdictOf([bad.forward]), "forbidden");
  assert.equal(edgeWidth([bad.forward]), 1.5);
  assert.equal(edgeWidth([{ services: Array.from({ length: 11 }, (_, i) => ({ label: `p${i}` })) }]), 5);
  assert.equal(edgeWidth([{ any_service: true, services: [] }]), 3);
});

test("zone contents: chips up to the limit, then at most 8 type clusters with the worst finding", () => {
  const assets = (n, types) => Array.from({ length: n }, (_, i) => ({ id: `a${i}`, name: `host-${i}`, type: types[i % types.length], vuln: { critical: i === 3 ? 1 : 0, high: i === 4 ? 1 : 0 } }));
  const few = zoneContents(assets(CHIP_LIMIT, ["server"]));
  assert.equal(few.mode, "chips");
  assert.equal(few.chips.length, CHIP_LIMIT);
  assert.equal(few.chips.find((c) => c.id === "a3").worst, "critical");
  const many = zoneContents(assets(40, ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]));
  assert.equal(many.mode, "clusters");
  assert.equal(many.clusters.length, MAX_CLUSTERS);
  assert.equal(many.clusters.reduce((n, c) => n + c.count, 0), 40);
  assert.equal(many.clusters.at(-1).type, "other types");
  assert.equal(zoneContents([]).mode, "empty");
  const h1 = zoneSize(few, false).h, h2 = zoneSize(few, true).h;
  assert.equal(h2 - h1, 16);
  assert.ok(chipBox(CHIP_LIMIT - 1, 56).y + 22 <= h1);
});

test("connect hints: only zones with networks, never the Internet pseudo-zone", () => {
  const m = buildModel(sample());
  assert.ok(canConnect(m.items, "z:fw:lan", "z:fw:srv").ok);
  assert.match(canConnect(m.items, "z:fw:lan", "z:fw:lan").reason, /inside a zone/);
  assert.match(canConnect(m.items, "z:internet", "z:fw:srv").reason, /Internet/);
  assert.ok(!canAllow({ id: "z:fw:x", subnets: [], native_id: "x" }));
});

test("accessible names carry role, confirmation, networks, assets and findings", () => {
  const data = sample();
  data.zones[4].vuln = { critical: 1, high: 2, medium: 0, low: 0, info: 0, overdue: 1 };
  const m = buildModel(data);
  assert.equal(zoneName(m.items.get("z:fw:guest")), "GUEST, Guest zone, role not confirmed, 10.0.10.0/24, 0 assets, 1 critical and 2 high findings, 1 overdue, 1 allowed traffic connection");
  assert.equal(findingsText({ critical: 0, high: 0 }), null);
  assert.equal(severityLine({ critical: 2, high: 5, overdue: 1 }), "critical 2 · high 5 · overdue 1");
});

test("default order: by role in the lane, then by name", () => {
  const data = { zones: [zone("z:fw:b", "guest"), zone("z:fw:a", "guest"), { ...zone("z:fw:d", "dmz"), lane: "edge" }], edges: [] };
  const m = buildModel(data);
  const sorted = [...m.items.values()].sort(compareZones).map((i) => i.id);
  assert.deepEqual(sorted, ["z:fw:d", "z:fw:a", "z:fw:b"]);
});

test("matrix: every ordered pair, offered up to 20 zones", () => {
  const data = sample();
  const mx = matrix(data.zones, data.edges);
  assert.equal(mx.zones[0].id, "z:internet");
  assert.equal(mx.cell("z:fw:lan", "z:fw:mgmt").violations[0].control, "HB-NW-1");
  assert.equal(mx.cell("z:fw:mgmt", "z:fw:lan"), null);
  assert.equal(matrix(Array.from({ length: MATRIX_MAX + 1 }, (_, i) => zone(`z:fw:${i}`, "users")), []), null);
});

test("Change panel services and requests: presets, custom ports, no 'any'", () => {
  assert.equal(portsProblem("443"), null);
  assert.equal(portsProblem("80,443,8000-8080"), null);
  assert.match(portsProblem(""), /no 'any'/);
  assert.match(portsProblem("70000"), /1 to 65535/);
  assert.match(portsProblem("90-80"), /backwards/);
  assert.match(portsProblem("http"), /not a port/);
  const { services, problems } = servicesFrom(["https", "dns"], [{ proto: "tcp", ports: "443" }, { proto: "udp", ports: "" }, { proto: "icmp" }, { proto: "tcp", ports: "x" }]);
  assert.deepEqual(services, [{ proto: "tcp", ports: "443" }, { proto: "udp", ports: "53" }, { proto: "tcp", ports: "53" }, { proto: "icmp", ports: null }]);
  assert.equal(problems.length, 1);
  assert.equal(servicesFrom([], Array.from({ length: 17 }, (_, i) => ({ proto: "tcp", ports: String(1000 + i) }))).problems.length, 1);
  assert.equal(changeRequest({ firewall: "fw", op: "allow", source: "z:fw:lan", services: [] }), null);
  assert.deepEqual(changeRequest({ firewall: "fw", op: "allow", source: "a", target: "b", services: [{ proto: "tcp", ports: "22" }], log: true, description: "x".repeat(130) }),
    { firewall: "fw", op: "allow", log: true, description: "x".repeat(120), source_zone: "a", target_zone: "b", services: [{ proto: "tcp", ports: "22" }] });
  assert.equal(changeRequest({ firewall: "fw", op: "disable_rules", rules: [] }), null);
  assert.deepEqual(changeRequest({ firewall: "fw", op: "disable_rules", rules: ["fw:r1"], edge: "zp:a>b", justification: "because" }),
    { firewall: "fw", op: "disable_rules", log: true, description: "", justification: "because", rule_ids: ["fw:r1"], edge: "zp:a>b" });
});

test("rules added by Atrium: the marker is the bare change id (netmodel.find_marker); anything else is not a change", () => {
  assert.equal(ruleChange({ marker: "chg_31" }), "chg_31");
  assert.equal(ruleChange({ marker: "atrium:chg_31" }), "chg_31");
  for (const marker of [null, undefined, "", "chg 31", "<b>x</b>", "../x", "a".repeat(65)]) assert.equal(ruleChange({ marker }), null, String(marker));
  assert.equal(ruleChange(null), null);
  const rules = segmentationFixture({ zones: 6, assets: 10, edges: 4 }).edges.flatMap((e) => e.rules);
  assert.deepEqual(rules.map(ruleChange).filter(Boolean), ["chg_fx1"]);
});

test("segmentation fixture: bounded elements and layout within budget", () => {
  const data = segmentationFixture();
  const t0 = performance.now();
  const m = buildModel(data, { traffic: "focus", overlays: { compliance: true, vulns: true } });
  const sc = scene(m, LANES, {}, { laneOf: (i) => i.lane, compare: compareZones, size: (i) => ({ w: i.w, h: i.h }), gutter: GUTTER, detour: true });
  const ms = performance.now() - t0;
  assert.equal(m.items.size, 50);
  for (const it of m.items.values()) assert.ok(it.contents.chips.length <= CHIP_LIMIT && it.contents.clusters.length <= MAX_CLUSTERS);
  assert.ok(m.edges.size < m.counts.edges, "the focus filter draws fewer edges than exist");
  assert.equal(sc.rects.size, 50);
  assert.equal(sc.routes.size, m.edges.size);
  assert.deepEqual(placeLanes(LANES, GUTTER).map((l) => l.x), [0, 380, 760, 1140, 1520, 1900]);
  const all = buildModel(data, { traffic: "all" });
  assert.ok(all.edges.size > 200);
  let best = Infinity;
  for (let i = 0; i < 5; i++) {
    const s = performance.now();
    const mm = buildModel(data, { traffic: "all", overlays: { compliance: true, vulns: true } });
    scene(mm, LANES, {}, { laneOf: (x) => x.lane, compare: compareZones, size: (x) => ({ w: x.w, h: x.h }), gutter: GUTTER, detour: true });
    best = Math.min(best, performance.now() - s);
  }
  assert.ok(best < 50, `model + layout + routing took ${best.toFixed(1)} ms (first run ${ms.toFixed(1)} ms)`);
});
