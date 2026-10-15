// Synthetic, deterministic models for measuring the canvas (canvas-design 4.10): an integration map of 200 tools and
// 400 data flows shaped like GET /api/integration/map, and a segmentation view of 50 zones, 1000 assets and 300
// allowed-traffic edges shaped like GET /api/segmentation. Pure: used by the Node tests and, in the browser, only when
// localStorage "hub.canvas.debug" is "1" and "hub.canvas.fixture" is set (never real data).

/** A small seeded PRNG (mulberry32): the same seed gives the same model. */
export function rng(seed = 1) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const NOW = 1760000000;
const APPS = [
  { id: "app:assets", label: "Assets", domains: ["assets"], href: "#/assets", icon: "box" },
  { id: "app:vulnerabilities", label: "Vulnerabilities", domains: ["vulnerabilities"], href: "#/vulnerabilities", icon: "bug" },
  { id: "app:compliance", label: "Compliance hub", domains: ["controls", "risks", "frameworks", "assessments"], href: "#/compliance", icon: "shield" },
  { id: "app:people", label: "People", domains: ["people", "accounts"], href: "#/people", icon: "contact" },
  { id: "app:network", label: "Network", domains: ["network"], href: "#/network", icon: "server" },
];
const PROFILES = [
  { caps: { assets: ["read", "write"] }, sor: ["assets"], actions: [] },
  { caps: { vulnerabilities: ["read"] }, sor: [], actions: ["scan", "scan_status"] },
  { caps: { assets: ["write"], controls: ["write"], risks: ["read"], vulnerabilities: ["write"] }, sor: [], actions: [] },
  { caps: { people: ["read"], accounts: ["read"] }, sor: ["people"], actions: [] },
  { caps: { network: ["read"] }, sor: [], actions: [] },
  { caps: { vulnerabilities: ["read"] }, sor: [], actions: [] },
  { caps: { assets: ["read", "write"], vulnerabilities: ["write"], controls: ["write"], risks: ["read"], people: ["read"], accounts: ["read"] }, sor: [], actions: [] },
  { caps: { vulnerabilities: ["read", "write"], frameworks: ["read"], assessments: ["write"], network: ["read"], accounts: ["read"] }, sor: [], actions: [] },
];

function flowFor(tool, domain, direction, i, pick) {
  const id = `fl_fx${i}`;
  const end = `tool:${tool.ref}`;
  const status = pick < 0.7 ? "enabled" : pick < 0.85 ? "proposed" : "disabled";
  const failing = status === "enabled" && pick > 0.62;
  const source = direction === "pull" ? end : "hub", target = direction === "pull" ? "hub" : end;
  return {
    id, domain, source, target, action: direction === "scan" ? "scan" : null, title: `${tool.label} ${domain} (${direction})`, reason: "",
    schedule_minutes: 60, status, strategy: "connector", options: {}, created_by: "supervisor", created_at: NOW - 86400,
    updated_at: NOW - i, approval_id: status === "proposed" ? `ap_fx${i}` : null, running: pick > 0.6 && pick < 0.605 ? NOW : null,
    last_run: status === "enabled" ? NOW - 600 : null,
    last_result: status === "enabled" ? { ok: !failing, counts: { total: 3 }, error: failing ? { message: "HTTP 500" } : null, at: NOW - 600 } : null,
    failures: failing ? 2 : 0, repair: null, job: null, tool_id: tool.ref, direction, owner: "module:assets", next_run: null,
  };
}

/** GET /api/integration/map for `tools` tools and about `flows` flows. */
export function integrationFixture({ tools = 200, flows = 400, seed = 7 } = {}) {
  const r = rng(seed);
  const nodes = [];
  const idps = [];
  for (let i = 0; i < tools; i++) {
    const ref = `tool-${String(i).padStart(3, "0")}`;
    const idp = i % 67 === 3;
    const connected = !idp && r() < 0.85;
    const profile = PROFILES[i % PROFILES.length];
    const node = {
      id: `tool:${ref}`, ref, label: `Tool ${i}${i % 9 === 0 ? " with a rather long product name" : ""}`, kind: ["oss", "closed", "saas"][i % 3],
      source_type: "saas", ui: { icon: null, color: null }, status: "ready", running: r() < 0.9,
      health: { ok: r() < 0.9, checked_at: NOW - 120 }, score: Math.round(r() * 100), level: "good", is_idp: idp,
      lane_default: idp ? "idp" : connected ? (profile.actions.length || profile.caps.controls ? "right" : "left") : "shelf",
      connection: connected ? { kind: `fake_${i % PROFILES.length}`, generated: false, known: true, tested: { ok: r() < 0.9, at: NOW - 300 } } : null,
      capabilities: connected ? profile.caps : {}, actions: connected ? profile.actions : [], system_of_record: connected ? profile.sor : [],
    };
    nodes.push(node);
    if (idp) idps.push(node);
  }
  const out = [];
  const connected = nodes.filter((n) => n.connection);
  for (let i = 0; out.length < flows && i < flows * 20; i++) {
    const tool = connected[Math.floor(r() * connected.length)];
    const domains = Object.entries(tool.capabilities);
    const [domain, ops] = domains[Math.floor(r() * domains.length)];
    const direction = tool.actions.includes("scan") && domain === "vulnerabilities" ? "scan"
      : ops.includes("read") && (!ops.includes("write") || r() < 0.5) ? "pull" : "push";
    if (out.some((f) => f.tool_id === tool.ref && f.domain === domain && f.direction === direction)) continue;
    out.push(flowFor(tool, domain, direction, out.length, r()));
  }
  const providers = idps.map((n) => ({ tool_id: n.ref, name: n.label, label: "Keycloak", protocols: ["oidc"], issuer: `https://${n.ref}.example/realms/hub`,
    is_default: false, configured: true, connected: 0, settings: {}, setting_keys: [] }));
  const sso = [];
  const identityTools = nodes.filter((n) => !n.is_idp).map((n, i) => {
    const provider = idps.length && i % 3 === 0 ? idps[i % idps.length].ref : null;
    const status = provider ? (i % 6 === 0 ? "pending" : "connected") : "not_connected";
    if (provider) sso.push({ id: `sso:${n.ref}`, source: `tool:${provider}`, target: n.id, state: status, protocol: "oidc", approval_id: null });
    return { tool_id: n.ref, name: n.label, status, connected_to: status === "connected" ? provider : null, selected: provider, choice: null,
      pending: status === "pending" ? { provider, strategy: "sso_connect", approval_id: null } : null, sso: "oidc", strategy: "sso_connect", applied: null };
  });
  const events = [];
  for (let i = 0; i + 1 < connected.length && events.length < 40; i += 5) {
    const a = connected[i], b = connected[i + 1];
    events.push({ id: `event:${a.ref}:${b.ref}:item.created`, source: a.id, target: b.id, event: "item.created", pattern: "item.*",
      has_webhook: i % 2 === 0, last_delivery: i % 3 ? { ok: true, ts: NOW - 60 } : null });
  }
  return {
    generated_at: NOW, autonomy: "assisted", guardrails: { scans_need_approval: true },
    apps: APPS.map((a) => ({ ...a, extension: false, active: true })), nodes, flows: out, sso, events,
    capability_links: [], identity: { providers, tools: identityTools, default: null, needs_choice: false },
    layout: { id: "integration", version: 0, items: {} },
  };
}

const ROLES = ["dmz", "users", "servers", "management", "guest", "iot", "dev", "backup", "ot", "unknown", "remote"];
const LANE_OF = { internet: "internet", dmz: "edge", remote: "edge", guest: "edge", iot: "edge", users: "users", servers: "servers", dev: "servers",
  management: "core", backup: "core", ot: "core", unknown: "unclassified" };
const TYPES = ["server", "workstation", "network", "software", "cloud", "other"];
const SERVICES = [["tcp", "443", "HTTPS"], ["tcp", "22", "SSH"], ["udp", "53", "DNS"], ["tcp", "3389", "RDP"], ["tcp", "8080", "HTTP (8080)"]];

/** GET /api/segmentation for one firewall with `zones` zones (the Internet pseudo-zone included), `assets` assets and
 *  about `edges` aggregated edges. */
export function segmentationFixture({ zones = 50, assets = 1000, edges = 300, seed = 11 } = {}) {
  const r = rng(seed);
  const fw = "fw-1";
  const list = [{ id: "z:internet", kind: "pseudo", name: "Internet", label: null, role: "internet", role_source: "builtin", lane: "internet",
    badges: [], subnets: [], interfaces: [], vlan: null, native_id: null, firewall: null, parent: null, same_subnet_as: [] }];
  for (let i = 1; i < zones; i++) {
    const role = ROLES[i % ROLES.length];
    list.push({ id: `z:${fw}:vlan${100 + i}`, kind: "vlan", name: `${role.toUpperCase()}_${i}`, label: null, role, role_source: i % 4 ? "heuristic" : "manual",
      lane: LANE_OF[role], badges: i % 4 ? ["role not confirmed"] : [], subnets: [`10.${i}.0.0/24`], interfaces: [`vlan${100 + i}`], vlan: 100 + i,
      native_id: `vlan${100 + i}`, firewall: fw, parent: null, same_subnet_as: [] });
  }
  const placed = [];
  for (let i = 0; i < assets; i++) {
    // clustered: a few zones hold most assets, so some zones show type clusters
    const z = list[1 + Math.floor((r() ** 2) * (list.length - 1))];
    const crit = r(), high = r();
    placed.push({ id: `a_fx${i}`, name: `host-${i}`, type: TYPES[i % TYPES.length], criticality: "medium", zone: z.id, zones: [z.id],
      addresses: [`${z.subnets[0].split(".").slice(0, 3).join(".")}.${(i % 250) + 2}`], placement: "subnet", badges: [], warning: null,
      vuln: { critical: crit > 0.97 ? 1 : 0, high: high > 0.9 ? 1 : 0, overdue: 0 } });
  }
  const count = (z) => placed.filter((a) => a.zone === z.id);
  for (const z of list) {
    const mine = count(z);
    z.asset_count = mine.length;
    z.vuln = { critical: mine.reduce((n, a) => n + a.vuln.critical, 0), high: mine.reduce((n, a) => n + a.vuln.high, 0), medium: 0, low: 0, info: 0, overdue: 0 };
  }
  const seen = new Set();
  const out = [];
  for (let i = 0; out.length < edges && i < edges * 10; i++) {
    const s = list[Math.floor(r() * list.length)], d = list[Math.floor(r() * list.length)];
    const id = `zp:${s.id}>${d.id}`;
    if (s.id === d.id || seen.has(id)) continue;
    seen.add(id);
    const anyService = r() < 0.08;
    const svc = SERVICES[Math.floor(r() * SERVICES.length)];
    const ruleId = `${fw}:r${out.length}`;
    out.push({ id, source: s.id, target: d.id, services: anyService ? [] : [{ proto: svc[0], ports: svc[1], label: svc[2], rule_ids: [ruleId] }],
      any_service: anyService, rule_count: 1, hits: null, bidirectional: false, approximate: true, notes: [], evaluable: true,
      rules: [{ id: ruleId, order: out.length, action: "pass", enabled: true, interfaces: s.interfaces, floating: false, source: s.name,
        destination: d.name, service: anyService ? "any" : `${svc[0]}/${svc[1]}`, log: false, description: `rule ${out.length}`, hits: null,
        any_any: false, marker: out.length === 0 ? "chg_fx1" : null }], // the first rule was added by an Atrium change
      violations: d.role === "management" && ["internet", "guest", "iot", "users"].includes(s.role)
        ? [{ policy: "untrusted-to-management", verdict: "forbidden", control: "HB-NW-1", possible: true }] : [],
      exposure: null, pending_changes: [] });
  }
  for (const e of out) e.bidirectional = seen.has(`zp:${e.target}>${e.source}`);
  return {
    generated_at: NOW, selected: fw,
    firewalls: [{ tool_id: fw, name: "Fixture firewall", kind: "firewall", snapshot: { rev: 3, revision: "r-3", read_at: NOW - 60, age_s: 60, stale: false },
      write: { capable: true, ops: ["allow", "disable_rules"], rollback: { mode: "savepoint", window_s: 60 } }, writable: false, reason: "guardrail" }],
    evaluation: { mode: "approximate", notes: ["Approximate: block rules, rule order and NAT are not evaluated, so some edges may not be reachable."] },
    zones: list, assets: placed, unplaced: [{ id: "a_fxu", name: "printer-3", type: "other", reason: "hostname only" }], edges: out, changes: [],
    guardrails: { device_changes: false, device_changes_need_second_person: true }, policy_version: 1,
    layout: { id: "segmentation", version: 0, items: {} },
  };
}
