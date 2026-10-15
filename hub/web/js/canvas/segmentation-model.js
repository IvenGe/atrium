// The Segmentation map's model (canvas-design 6.2-6.6, 9.2, 9.4): lanes by zone role, zone items with their asset
// chips or type clusters, allowed-traffic edges (a zone pair allowed both ways is one edge with two arrowheads), the
// default traffic filter, ghost edges for proposed changes, accessible names, the zone-pair matrix and the Change
// panel's services. Pure: no DOM, unit-tested under Node (tests/js/segmentation-model.test.mjs); the drawing is in
// views/segmentation-map.js. Zone, rule and alias names come from devices: they are data (textContent / html`` only).

export const LANES = [
  { id: "internet", title: "Internet", width: 300 },
  { id: "edge", title: "Edge", width: 300 },
  { id: "users", title: "Users", width: 300 },
  { id: "servers", title: "Servers", width: 300 },
  { id: "core", title: "Core", width: 300 },
  { id: "unclassified", title: "Unclassified", width: 300 },
];
export const GUTTER = 80; // lanes at x = 0, 380, 760 ... (canvas-design 6.2)
export const ZONE_W = 300, HEAD_H = 56, VULN_LINE = 16, CHIP_H = 22, CHIP_GAP = 6, PAD = 10, COLS = 2, COL_GAP = 8;
export const CHIP_W = (ZONE_W - 2 * PAD - (COLS - 1) * COL_GAP) / COLS;
export const CHIP_LIMIT = 12; // more assets than this: type clusters
export const MAX_CLUSTERS = 8;
export const AUTO_ALL = 24; // the automatic traffic filter shows every edge up to this many
export const MATRIX_MAX = 20; // the zone-pair matrix is offered up to this many zones
export const INTERNET = "z:internet";
export const OPEN = ["proposed", "approved", "scheduled", "applying", "verifying"];

export const ROLE_LABEL = {
  internet: "Internet", dmz: "DMZ", remote: "Remote access", guest: "Guest", iot: "IoT", users: "Users", servers: "Servers",
  dev: "Development", management: "Management", backup: "Backup", ot: "OT", unknown: "Unclassified",
};
export const ROLES = Object.keys(ROLE_LABEL);
// role is never colour alone (canvas-design 11): a glyph per role, the icon() fallback "grid" for the others
export const ROLE_GLYPH = { internet: "cloud", dmz: "shield", users: "users", servers: "server", management: "lock", unknown: "alert" };
export const roleGlyph = (role) => ROLE_GLYPH[role] || "grid";
// colour token per role: --zone-<color>
export const ROLE_COLOR = {
  internet: "internet", dmz: "edge", remote: "edge", guest: "edge", iot: "edge", users: "users", servers: "servers", dev: "dev",
  management: "core", backup: "core", ot: "ot", unknown: "unknown",
};
const LANE_OF_ROLE = {
  internet: "internet", dmz: "edge", remote: "edge", guest: "edge", iot: "edge", users: "users", servers: "servers", dev: "servers",
  management: "core", backup: "core", ot: "core", unknown: "unclassified",
};
const ROLE_RANK = Object.fromEntries(ROLES.map((r, i) => [r, i]));
export const TYPE_GLYPH = { server: "server", workstation: "terminal", network: "link", software: "grid", saas: "cloud", cloud: "cloud", data: "file", other: "box" };
export const TYPE_LABEL = { server: "server", workstation: "workstation", network: "network device", software: "software", saas: "SaaS", cloud: "cloud", data: "data", other: "other" };
export const CHANGE_WORD = { proposed: "proposed", approved: "approved", scheduled: "scheduled", applying: "applying", verifying: "verifying" };

const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const byName = (a, b) => String(a.name).localeCompare(String(b.name)) || (a.id < b.id ? -1 : 1);
const list = (items) => (items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items.at(-1)}`);

/** The name a person sees: an administrator's label, else the device's name. */
export const zoneLabel = (z) => z?.label || z?.name || z?.id || "";
export const laneOf = (zone) => zone?.lane || LANE_OF_ROLE[zone?.role] || "unclassified";
export const isUnconfirmed = (z) => z?.role_source === "heuristic" || z?.role === "unknown";

/** The worst open finding of an asset or a cluster: "critical" | "high" | null. */
export const worstOf = (v) => (v?.critical ? "critical" : v?.high ? "high" : null);

/** "2 critical and 1 high findings, 1 overdue" (open findings; null when there are none). */
export function findingsText(v) {
  if (!v) return null;
  const parts = ["critical", "high", "medium", "low"].filter((s) => v[s]).map((s) => `${v[s]} ${s}`);
  if (!parts.length) return null;
  const total = ["critical", "high", "medium", "low"].reduce((n, s) => n + (v[s] || 0), 0);
  return `${list(parts)} finding${total === 1 ? "" : "s"}${v.overdue ? `, ${v.overdue} overdue` : ""}`;
}

/** The zone header's severity line: "critical 2 · high 5 · overdue 1" (null without findings). */
export function severityLine(v) {
  if (!v) return null;
  const parts = ["critical", "high", "medium", "low"].filter((s) => v[s]).map((s) => `${s} ${v[s]}`);
  if (v.overdue) parts.push(`overdue ${v.overdue}`);
  return parts.length ? parts.join(" · ") : null;
}

/** What a zone shows: up to CHIP_LIMIT asset chips, else up to MAX_CLUSTERS type clusters ("server ×42"); with more
 *  types the last cluster gathers the rest. Bounded either way, so a zone never draws more than 12 chips. */
export function zoneContents(assets) {
  if (assets.length <= CHIP_LIMIT) {
    return {
      mode: assets.length ? "chips" : "empty", clusters: [],
      chips: assets.slice().sort(byName).map((a) => ({ id: a.id, name: a.name, type: a.type, worst: worstOf(a.vuln), badges: a.badges || [], warning: a.warning || null })),
    };
  }
  const groups = new Map();
  for (const a of assets) {
    const g = groups.get(a.type) || { type: a.type, count: 0, critical: 0, high: 0 };
    g.count += 1;
    g.critical += a.vuln?.critical ? 1 : 0;
    g.high += a.vuln?.high ? 1 : 0;
    groups.set(a.type, g);
  }
  let clusters = [...groups.values()].sort((x, y) => y.count - x.count || String(x.type).localeCompare(String(y.type)));
  if (clusters.length > MAX_CLUSTERS) {
    const rest = clusters.slice(MAX_CLUSTERS - 1);
    clusters = [...clusters.slice(0, MAX_CLUSTERS - 1), rest.reduce((g, c) => ({ ...g, count: g.count + c.count, critical: g.critical + c.critical, high: g.high + c.high }),
      { type: "other types", others: rest.map((c) => c.type), count: 0, critical: 0, high: 0 })];
  }
  return { mode: "clusters", chips: [], clusters: clusters.map((c) => ({ ...c, worst: worstOf(c) })) };
}

/** Header height (taller with the severity line of the vulnerability overlay). */
export const headHeight = (vulnLine) => HEAD_H + (vulnLine ? VULN_LINE : 0);

/** Where chip `i` sits inside a zone whose header is `head` px tall. */
export function chipBox(i, head) {
  return { x: PAD + (i % COLS) * (CHIP_W + COL_GAP), y: head + 4 + Math.floor(i / COLS) * (CHIP_H + CHIP_GAP), w: CHIP_W, h: CHIP_H };
}

export function zoneSize(contents, vulnLine) {
  const n = contents.mode === "chips" ? contents.chips.length : contents.clusters.length;
  const body = n ? Math.ceil(n / COLS) * (CHIP_H + CHIP_GAP) - CHIP_GAP : 16;
  return { w: ZONE_W, h: headHeight(vulnLine) + 4 + body + PAD + 2 };
}

/** A pair edge's two zone ids from its id "zp:<source>><target>" (zone ids may hold ">": both halves must be known). */
export function splitPair(id, has) {
  if (typeof id !== "string" || !id.startsWith("zp:")) return null;
  const s = id.slice(3);
  for (let i = s.indexOf(">"); i !== -1; i = s.indexOf(">", i + 1)) {
    const a = s.slice(0, i), b = s.slice(i + 1);
    if (has(a) && has(b)) return [a, b];
  }
  return null;
}

/** Drawn edges: a zone pair allowed both ways is one edge (the direction whose source sorts first) with two
 *  arrowheads. Returns {pairs: [{id, forward, backward}], index: Map raw edge id -> drawn id}. */
export function pairEdges(raw) {
  const byId = new Map(raw.map((e) => [e.id, e]));
  const pairs = [];
  const index = new Map();
  for (const e of raw) {
    if (index.has(e.id)) continue;
    const backId = `zp:${e.target}>${e.source}`;
    const back = byId.get(backId);
    if (back && back !== e) {
      const [a, b] = e.source < e.target ? [e, back] : [back, e];
      pairs.push({ id: a.id, forward: a, backward: b });
      index.set(a.id, a.id);
      index.set(b.id, a.id);
    } else {
      pairs.push({ id: e.id, forward: e, backward: null });
      index.set(e.id, e.id);
    }
  }
  return { pairs, index };
}

/** The distinct service labels of raw edges ("HTTPS", "tcp/8443", ...); `any` when one allows any service. */
export function serviceLabels(edges) {
  const out = [];
  for (const e of edges) for (const s of e?.services || []) if (!out.includes(s.label)) out.push(s.label);
  return { labels: out, any: edges.some((e) => e?.any_service) };
}

export function servicesText(edges, max = 3) {
  const { labels, any } = serviceLabels(edges);
  if (any) return labels.length ? `any service (also ${labels.slice(0, max).join(", ")})` : "any service";
  if (!labels.length) return "no service";
  return labels.length > max ? `${labels.slice(0, max).join(", ")} +${labels.length - max}` : labels.join(", ");
}

/** Stroke width by the number of services (canvas-design 6.4): 1.5 px (1-2), 3 px (3-10), 5 px (more); any: 3 px. */
export function edgeWidth(edges) {
  const { labels, any } = serviceLabels(edges);
  if (any) return 3;
  return labels.length <= 2 ? 1.5 : labels.length <= 10 ? 3 : 5;
}

/**
 * The Atrium change that added a rule, from its `marker`: the backend sends the bare change id it found in an
 * "atrium:<id>" marker in the rule's description (netmodel.find_marker). Device text is untrusted: only an id of the
 * marker's own shape is returned (a stray "atrium:" prefix is tolerated), anything else is null.
 */
export function ruleChange(rule) {
  const m = /^(?:atrium:)?([A-Za-z0-9_-]{1,64})$/.exec(String(rule?.marker ?? ""));
  return m ? m[1] : null;
}

/** The controls named by violations, once each ("HB-NW-1, HB-NW-5"). */
export const controlsOf = (violations) => [...new Set((violations || []).map((v) => v.control || v.policy))];

/** forbidden | restricted | unevaluable | ok, worst first. */
export function verdictOf(edges) {
  const vs = edges.flatMap((e) => e?.violations || []);
  if (vs.some((v) => v.verdict === "forbidden")) return "forbidden";
  if (vs.length) return "restricted";
  if (edges.some((e) => e && e.evaluable === false)) return "unevaluable";
  return "ok";
}

function exposureOf(edges) {
  let critical = 0, high = 0;
  for (const e of edges) {
    if (!e?.exposure) continue;
    critical += e.exposure.critical || 0;
    high += e.exposure.high || 0;
  }
  return critical || high ? { critical, high } : null;
}

export const exposureText = (x) => (x ? `exposes ${list([x.critical ? `${x.critical} critical` : "", x.high ? `${x.high} high` : ""].filter(Boolean))}` : null);

/** Whether a zone can be one end of an "allow" change: a real zone with networks (S13: a change never opens "any"). */
export const canAllow = (z) => !!z && z.id !== INTERNET && (z.subnets || []).length > 0 && !!z.native_id;

/**
 * Items and edges for the canvas from GET /api/segmentation. `opts`: {traffic: "auto" | "focus" | "all", selection,
 * overlays: {compliance, vulns}, hidden: Set of zone ids}. "focus" draws the traffic of the selected zone (or edge),
 * every possible violation and every edge with a proposed change; "auto" is "all" up to AUTO_ALL edges, else
 * "focus". Proposed allow changes are ghost edges ("chg:<id>"); proposed disables mark their edge.
 * Returns {items, edges, index, counts, traffic (the mode in effect)}.
 */
export function buildModel(data, { traffic = "auto", selection = null, overlays = {}, hidden = new Set() } = {}) {
  const items = new Map();
  const assets = new Map();
  for (const a of data.assets || []) {
    if (!assets.has(a.zone)) assets.set(a.zone, []);
    assets.get(a.zone).push(a);
  }
  const vulnLine = !!overlays.vulns;
  for (const z of data.zones || []) {
    if (hidden.has(z.id)) continue;
    const mine = assets.get(z.id) || [];
    const contents = zoneContents(mine);
    const line = vulnLine && severityLine(z.vuln) ? severityLine(z.vuln) : null;
    const { w, h } = zoneSize(contents, !!line);
    items.set(z.id, { id: z.id, kind: "zone", zone: z, label: zoneLabel(z), role: z.role, lane: laneOf(z), contents, vulnLine: line, w, h,
      rank: ROLE_RANK[z.role] ?? ROLES.length, assets: mine.length, connections: 0 });
  }
  const { pairs, index } = pairEdges(data.edges || []);
  const changes = (data.changes || []).filter((c) => OPEN.includes(c.status));
  const has = (id) => items.has(id);
  const edges = new Map();
  const drawn = [];
  for (const p of pairs) {
    const parts = [p.forward, p.backward].filter(Boolean);
    const from = p.forward.source, to = p.forward.target;
    if (!has(from) || !has(to)) continue;
    const pending = changes.filter((c) => c.op !== "allow" && c.edge && index.get(c.edge) === p.id);
    const disabling = pending.find((c) => c.op === "disable_rules") || null;
    const violations = parts.flatMap((e) => e.violations || []);
    drawn.push({
      id: p.id, kind: "traffic", forward: p.forward, backward: p.backward, raw: parts, from: { id: from }, to: { id: to }, primary: false,
      arrow: p.backward ? "both" : "to", violations, verdict: verdictOf(parts), exposure: exposureOf(parts), any: parts.some((e) => e.any_service),
      rules: parts.reduce((n, e) => n + (e.rule_count || 0), 0), width: edgeWidth(parts), pending, disabling,
      notes: [...new Set(parts.flatMap((e) => e.notes || []))],
    });
  }
  const mode = traffic === "auto" ? (drawn.length <= AUTO_ALL ? "all" : "focus") : traffic;
  const ghosts = [];
  for (const c of changes) {
    if (!(c.op === "allow" || (c.op === "revert" && !index.has(c.edge)))) continue;
    const ends = splitPair(c.edge, has);
    if (!ends) continue;
    ghosts.push({ id: `chg:${c.id}`, kind: "change", change: c, from: { id: ends[0] }, to: { id: ends[1] }, primary: false, arrow: "to", state: c.status });
  }
  const sel = selection && (items.has(selection) ? { zones: [selection] }
    : drawn.find((e) => e.id === selection) ? { edge: selection }
      : ghosts.find((g) => g.id === selection) ? { zones: [ghosts.find((g) => g.id === selection).from.id, ghosts.find((g) => g.id === selection).to.id] } : null);
  const keep = (e) => mode === "all" || e.violations.length || e.pending.length
    || (sel?.edge === e.id) || (sel?.zones || []).some((z) => z === e.from.id || z === e.to.id);
  let shown = 0;
  for (const e of drawn) {
    items.get(e.from.id).connections += 1;
    items.get(e.to.id).connections += 1;
    if (!keep(e)) continue;
    edges.set(e.id, e);
    shown += 1;
  }
  for (const g of ghosts) edges.set(g.id, g);
  const counts = {
    zones: items.size, assets: (data.assets || []).length, unplaced: (data.unplaced || []).length, edges: drawn.length, shown,
    violations: drawn.filter((e) => e.violations.length).length, pending: changes.length,
  };
  return { items, edges, index, counts, traffic: mode };
}

/** Default order in a lane: by role (DMZ before Guest in the Edge lane, ...), then by name. */
export function compareZones(a, b) {
  return (a.rank ?? 0) - (b.rank ?? 0) || String(a.label).localeCompare(String(b.label)) || (a.id < b.id ? -1 : 1);
}

const no = (reason) => ({ ok: false, reason });

/** Client-side hint for "allow traffic" drop targets; the server's preview decides. */
export function canConnect(items, a, b) {
  const A = items.get(a), B = items.get(b);
  if (!A || !B) return no("Choose a zone");
  if (a === b) return no("Traffic inside a zone does not cross the firewall: choose another zone");
  for (const z of [A, B]) {
    if (z.zone.id === INTERNET) return no("The Internet pseudo-zone cannot be used: a change never opens 'any'");
    if (!canAllow(z.zone)) return no(`${z.label} has no networks, so no rule can name it`);
  }
  return { ok: true, reason: "" };
}

/** Accessible name of a zone (state included; the engine appends ", selected"). */
export function zoneName(item) {
  const z = item.zone;
  const nets = (z.subnets || []).length ? `${z.subnets.slice(0, 3).join(", ")}${z.subnets.length > 3 ? ` and ${z.subnets.length - 3} more` : ""}`
    : z.id === INTERNET ? "every address outside the firewall's networks" : "no networks";
  const parts = [item.label, `${ROLE_LABEL[z.role] || z.role} zone${isUnconfirmed(z) ? ", role not confirmed" : ""}`, nets, plural(item.assets, "asset"),
    findingsText(z.vuln) || "no open findings", plural(item.connections, "allowed traffic connection")];
  if ((z.same_subnet_as || []).length) parts.push("same subnet on another firewall");
  return parts.join(", ");
}

/** Accessible name of an edge (allowed traffic or a proposed change). `names(id)` gives a zone's label. */
export function edgeName(edge, names) {
  const a = names(edge.from.id), b = names(edge.to.id);
  if (edge.kind === "change") {
    const c = edge.change;
    const verb = c.op === "revert" ? "restore traffic from" : "allow";
    const state = c.status === "proposed" ? "" : `, ${CHANGE_WORD[c.status] || c.status}`;
    return `${c.status === "proposed" ? "Proposed change" : "Change"} ${c.id}, ${verb} ${a} to ${b}${state}${c.proposed_by ? `, proposed by ${c.proposed_by}` : ""}`;
  }
  const parts = [`Allowed traffic, ${a} to ${b}${edge.backward ? " and back" : ""}`, servicesText(edge.raw), plural(edge.rules, "rule")];
  if (edge.violations.length) parts.push(`may violate ${controlsOf(edge.violations).join(", ")}`);
  if (edge.verdict === "unevaluable") parts.push("cannot evaluate: unclassified zone");
  const x = exposureText(edge.exposure);
  if (x) parts.push(x);
  if (edge.disabling) parts.push(`disable ${CHANGE_WORD[edge.disabling.status] || edge.disabling.status}`);
  else if (edge.pending.length) parts.push("change proposed");
  return parts.join(", ");
}

/** The one chip an edge shows without being selected (null: none) and the text when it is selected. */
export function edgeChips(edge, overlays = {}) {
  if (edge.kind === "change") return { chip: CHANGE_WORD[edge.change.status] || edge.change.status, selected: `${CHANGE_WORD[edge.change.status] || edge.change.status} · ${edge.change.id}` };
  const services = servicesText(edge.raw, 2);
  let chip = null;
  if (edge.disabling) chip = edge.disabling.status === "proposed" ? "disable proposed" : `disable ${CHANGE_WORD[edge.disabling.status] || edge.disabling.status}`;
  else if (edge.pending.length) chip = "change proposed";
  else if (overlays.compliance && edge.violations.length) chip = `may violate ${controlsOf(edge.violations).join(", ")}`;
  else if (overlays.vulns && edge.exposure) chip = exposureText(edge.exposure);
  else if (edge.any) chip = "any";
  return { chip, selected: chip && chip !== "any" ? `${chip} · ${services}` : services };
}

/** Zones in display order (lane, role, name) for tables and the matrix. */
export function orderedZones(zones) {
  const lane = Object.fromEntries(LANES.map((l, i) => [l.id, i]));
  return zones.slice().sort((a, b) => (lane[laneOf(a)] ?? 9) - (lane[laneOf(b)] ?? 9) || (ROLE_RANK[a.role] ?? 99) - (ROLE_RANK[b.role] ?? 99)
    || zoneLabel(a).localeCompare(zoneLabel(b)) || (a.id < b.id ? -1 : 1));
}

/** The zone-pair matrix (canvas-design 9.4): null above MATRIX_MAX zones; else {zones, cell(from, to) -> raw edge}. */
export function matrix(zones, edges) {
  if (zones.length > MATRIX_MAX) return null;
  const byPair = new Map((edges || []).map((e) => [`${e.source}\u0000${e.target}`, e]));
  return { zones: orderedZones(zones), cell: (a, b) => byPair.get(`${a}\u0000${b}`) || null };
}

// ---------- the Change panel ----------

export const PRESETS = [
  { id: "https", label: "HTTPS 443/tcp", services: [{ proto: "tcp", ports: "443" }] },
  { id: "ssh", label: "SSH 22/tcp", services: [{ proto: "tcp", ports: "22" }] },
  { id: "rdp", label: "RDP 3389/tcp", services: [{ proto: "tcp", ports: "3389" }] },
  { id: "dns", label: "DNS 53/udp+tcp", services: [{ proto: "udp", ports: "53" }, { proto: "tcp", ports: "53" }] },
  { id: "icmp", label: "ICMP", services: [{ proto: "icmp", ports: null }] },
];
export const MAX_SERVICES = 16;
const RANGE = /^(\d{1,5})(?:-(\d{1,5}))?$/;

/** Why a port list ("443", "8000-8080", "80,443") is not valid, or null when it is. */
export function portsProblem(text) {
  const value = String(text ?? "").replace(/\s+/g, "");
  if (!value) return "name the ports (no 'any')";
  for (const part of value.split(",")) {
    const m = RANGE.exec(part);
    if (!m) return `"${part}" is not a port or a range like 8000-8080`;
    const lo = Number(m[1]), hi = Number(m[2] ?? m[1]);
    if (lo < 1 || hi > 65535) return "ports are 1 to 65535";
    if (lo > hi) return `${part}: the range is backwards`;
  }
  return null;
}

/** The services of a Change panel: checked presets plus custom rows [{proto, ports}], deduplicated. */
export function servicesFrom(presetIds, custom = []) {
  const out = [];
  const problems = [];
  const add = (s) => { if (!out.some((x) => x.proto === s.proto && (x.ports || null) === (s.ports || null))) out.push(s); };
  for (const id of presetIds) for (const s of PRESETS.find((p) => p.id === id)?.services || []) add({ ...s });
  custom.forEach((row, i) => {
    if (row.proto === "icmp") return add({ proto: "icmp", ports: null });
    const ports = String(row.ports ?? "").replace(/\s+/g, "");
    if (!ports) return; // an empty row is ignored
    const problem = portsProblem(ports);
    if (problem) problems.push(`Service ${i + 1}: ${problem}`);
    else add({ proto: row.proto, ports });
  });
  if (out.length > MAX_SERVICES) problems.push(`At most ${MAX_SERVICES} services in one change`);
  return { services: out, problems };
}

/** The request body of POST /api/segmentation/changes[/preview]; null while it is incomplete. */
export function changeRequest(state) {
  const base = { firewall: state.firewall, op: state.op, log: state.log !== false, description: String(state.description || "").slice(0, 120) };
  if (state.justification) base.justification = state.justification;
  if (state.op === "disable_rules") {
    if (!state.rules?.length) return null;
    return { ...base, rule_ids: state.rules, edge: state.edge || null };
  }
  if (!state.source || !state.target || !state.services?.length) return null;
  return { ...base, source_zone: state.source, target_zone: state.target, services: state.services };
}
