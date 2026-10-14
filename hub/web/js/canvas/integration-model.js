// The Integration map's model (canvas-design 5.1-5.5): lanes, items (hub apps and tools) and edges (data flows,
// single sign-on, event routes, capabilities) built from GET /api/integration/map, flow states, default lanes and
// order, the connect hint and live flow patches. Pure: no DOM, unit-tested under Node; the drawing is in
// views/integration-map.js.

export const LANES = [
  { id: "idp", title: "Identity providers", width: 184 },
  { id: "left", title: "Sources", width: 184 },
  { id: "spine", title: "Hub apps", width: 208 },
  { id: "right", title: "Destinations", width: 184 },
  { id: "shelf", title: "Not connected", width: 184 },
];
export const TOOL_W = 184, TOOL_H = 56, APP_W = 208, APP_HEAD = 40, PORT_H = 22;
// Hub app colours, copied from APPS in hub/web/js/app.js (keep them in step); extension apps use xColor(key).
export const APP_COLORS = {
  "app:assets": "#0d9488", "app:vulnerabilities": "#dc2626", "app:compliance": "#16a34a", "app:people": "#e11d48", "app:network": "#ea580c",
};
export const KIND_LABEL = { oss: "Source code", closed: "Closed source", saas: "SaaS" };
export const DIRECTION_LABEL = { pull: "into the hub", push: "from the hub", scan: "scan" };
const DOMAIN_WORDS = {
  assets: "assets", vulnerabilities: "vulnerabilities", controls: "controls", risks: "risks", frameworks: "frameworks", assessments: "assessments",
  people: "people", accounts: "accounts", network: "network data",
};
export const domainWord = (d) => DOMAIN_WORDS[d] || String(d || "").replace(/^x:/, "");
// Port labels for domains flows.js DOMAINS does not name (the app's own pages name them the same way).
export const PORT_LABELS = { frameworks: "Frameworks", assessments: "Assessments", network: "Network devices" };

const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;

/** "5 minutes ago" for an accessible name (`now` in seconds). */
export function ago(ts, now = Date.now() / 1000) {
  if (!ts) return "never";
  const s = Math.max(0, now - ts);
  if (s < 45) return "just now";
  if (s < 3600) return `${plural(Math.round(s / 60), "minute")} ago`;
  if (s < 86400) return `${plural(Math.round(s / 3600), "hour")} ago`;
  return `${plural(Math.round(s / 86400), "day")} ago`;
}

/** A flow's state on the map (canvas-design 5.3; first match wins) and the chip text it needs (null: no chip). */
export function flowState(f) {
  const job = f.job || {};
  if (f.running != null || job.status === "running") {
    return { state: "running", chip: job.status === "running" && job.progress != null ? `scan ${Math.round(Number(job.progress) || 0)}%` : "running" };
  }
  if (f.repair) return { state: "repair", chip: f.repair === "requested" ? "diagnosing" : "repair proposed" };
  if (f.status === "enabled" && (f.failures > 0 || f.last_result?.ok === false)) return { state: "failing", chip: `failed ${Math.max(1, f.failures || 0)}×` };
  if (f.status === "proposed") return { state: "proposed", chip: "awaiting approval" };
  if (job.status === "awaiting_approval") return { state: "scan_waiting", chip: "scan awaiting approval" };
  if (f.status === "enabled") return { state: "enabled", chip: null };
  return { state: "disabled", chip: null };
}
export const STATE_WORDS = {
  running: "running", repair: "repair pending", failing: "failing", proposed: "awaiting approval", scan_waiting: "scan awaiting approval",
  enabled: "enabled", disabled: "disabled",
};
export const isFailing = (f) => f.status === "enabled" && (f.failures > 0 || f.last_result?.ok === false);

/** The lane of a tool: its default, or an operator's Sources/Destinations swap for connected tools. */
export function toolLane(node, stored) {
  const d = node.lane_default;
  if (d !== "left" && d !== "right") return d === "idp" ? "idp" : "shelf";
  const lane = stored?.[node.id]?.lane;
  return lane === "left" || lane === "right" ? lane : d;
}

export const laneOf = (item, stored) => (item.kind === "app" ? "spine" : toolLane(item.node, stored));

/** Lanes an item may be dropped in: apps, identity providers and the shelf only reorder in their own lane. */
export function movableLanes(item, stored) {
  const lane = laneOf(item, stored);
  return lane === "left" || lane === "right" ? ["left", "right"] : [lane];
}

/** Sides with a connect grip: the side facing the spine (apps: both). */
export function gripSides(item, stored) {
  const lane = laneOf(item, stored);
  return lane === "spine" ? ["left", "right"] : lane === "idp" || lane === "left" ? ["right"] : ["left"];
}

/** A flow's tool end ("tool:<id>"). */
export const toolEnd = (f) => (String(f.target).startsWith("tool:") ? f.target : f.source);

/** The flow as GET /api/flows would show it, from a `flow` event's raw model plus what the client knew before:
 *  direction, tool_id and next_run are computed (flows.next_run), title and owner kept. */
export function flowFromEvent(raw, prev = null) {
  const direction = raw.action === "scan" ? "scan" : raw.target === "hub" ? "pull" : "push";
  const next_run = raw.status === "enabled" && raw.schedule_minutes > 0 ? (raw.last_run || 0) + raw.schedule_minutes * 60 : null;
  return { ...(prev || {}), ...raw, direction, tool_id: toolEnd(raw).slice(5), next_run, title: raw.title || prev?.title || "", owner: raw.owner || prev?.owner };
}

/** A live patch applies only when it is not older than what the client holds (canvas-design 4.8). */
export const isNewer = (raw, current) => !current || (Number(raw.updated_at) || 0) >= (Number(current.updated_at) || 0);

/** The app that takes a domain (null when none does). */
export function appFor(apps, domain) {
  return apps.find((a) => a.domains.includes(domain)) || null;
}

/**
 * Items and edges for the canvas. `opts`: {hidden: Set of item ids this viewer hid, show: {sso, events, capabilities},
 * flows: "all" | "failing" | "proposed", selection: id}. SSO edges show with the "Single sign-on" filter, or for the
 * selected tool or identity provider. Returns {items: Map, edges: Map, counts}.
 */
export function buildModel(data, { hidden = new Set(), show = {}, flows: flowFilter = "all", selection = null } = {}) {
  const items = new Map();
  const apps = data.apps || [];
  const appIndex = new Map(apps.map((a, i) => [a.id, i]));
  for (const a of apps) {
    if (hidden.has(a.id)) continue;
    items.set(a.id, {
      id: a.id, kind: "app", label: a.label, domains: a.domains, icon: a.icon, href: a.href, extension: !!a.extension, active: a.active !== false,
      color: APP_COLORS[a.id] || null, w: APP_W, h: APP_HEAD + PORT_H * a.domains.length + 6, rank: appIndex.get(a.id), flowCount: 0, failing: 0,
    });
  }
  const identity = new Map((data.identity?.tools || []).map((t) => [t.tool_id, t]));
  const providers = new Map((data.identity?.providers || []).map((p) => [p.tool_id, p]));
  const allFlows = data.flows || [];
  const byTool = new Map();
  for (const f of allFlows) {
    if (!byTool.has(f.tool_id)) byTool.set(f.tool_id, []);
    byTool.get(f.tool_id).push(f);
  }
  for (const n of data.nodes || []) {
    if (hidden.has(n.id)) continue;
    const flows = byTool.get(n.ref) || [];
    const sso = identity.get(n.ref);
    const ssoProvider = sso?.status === "connected" ? sso.connected_to : sso?.status === "pending" ? sso.pending?.provider : null;
    const ranks = (flows.length ? flows.map((f) => f.domain) : Object.keys(n.capabilities || {}))
      .map((d) => appIndex.get(appFor(apps, d)?.id)).filter((i) => i !== undefined);
    items.set(n.id, {
      id: n.id, kind: "tool", node: n, label: n.label, is_idp: !!n.is_idp, connection: n.connection, caps: n.capabilities || {},
      actions: n.actions || [], sor: n.system_of_record || [], w: TOOL_W, h: TOOL_H,
      rank: ranks.length ? Math.min(...ranks) : apps.length,
      flowCount: flows.length, failing: flows.filter(isFailing).length, proposed: flows.filter((f) => f.status === "proposed").length,
      sso: ssoProvider ? { provider: ssoProvider, name: providers.get(ssoProvider)?.name || ssoProvider, state: sso.status } : null,
    });
  }
  const edges = new Map();
  const counts = { tools: 0, apps: 0, flows: allFlows.length, failing: 0, proposed: 0 };
  for (const item of items.values()) counts[item.kind === "app" ? "apps" : "tools"] += 1;
  for (const f of allFlows) {
    const st = flowState(f);
    if (isFailing(f)) counts.failing += 1;
    if (f.status === "proposed") counts.proposed += 1;
    if (flowFilter === "failing" && !(st.state === "failing" || st.state === "repair")) continue;
    if (flowFilter === "proposed" && !(st.state === "proposed" || st.state === "scan_waiting")) continue;
    const app = appFor(apps, f.domain);
    const tool = items.get(`tool:${f.tool_id}`);
    if (!app || !tool || !items.has(app.id)) continue;
    const appItem = items.get(app.id);
    appItem.flowCount += 1;
    if (isFailing(f)) appItem.failing += 1;
    edges.set(`flow:${f.id}`, {
      id: `flow:${f.id}`, kind: "flow", flow: f, state: st.state, chip: st.chip, primary: true,
      from: { id: tool.id }, to: { id: app.id, port: APP_HEAD + PORT_H * app.domains.indexOf(f.domain) + PORT_H / 2 },
      arrow: f.direction === "scan" ? "both" : f.direction === "pull" ? "to" : "from",
    });
  }
  const selected = selection && items.get(selection);
  for (const s of data.sso || []) {
    const near = selected && (selection === s.source || selection === s.target);
    if (!(show.sso || near) || !items.has(s.source) || !items.has(s.target)) continue;
    edges.set(s.id, { id: s.id, kind: "sso", sso: s, state: s.state, primary: false, from: { id: s.source }, to: { id: s.target }, arrow: "to",
      chip: s.state === "pending" ? "SSO pending" : null });
  }
  if (show.events) {
    for (const e of data.events || []) {
      if (!items.has(e.source) || !items.has(e.target)) continue;
      edges.set(e.id, { id: e.id, kind: "event", event: e, state: e.last_delivery?.ok === false ? "failing" : "event", primary: false,
        from: { id: e.source }, to: { id: e.target }, arrow: "to", chip: null });
    }
  }
  if (show.capabilities) {
    for (const c of data.capability_links || []) {
      if (!items.has(c.source) || !items.has(c.target)) continue;
      edges.set(c.id, { id: c.id, kind: "cap", cap: c, state: "cap", primary: false, from: { id: c.source }, to: { id: c.target }, arrow: "to", chip: null });
    }
  }
  return { items, edges, counts };
}

/** Default order in a lane: the tool's first hub app (Assets, Vulnerabilities, Compliance, ...), then its name. */
export function compareItems(a, b) {
  return (a.rank ?? 0) - (b.rank ?? 0) || String(a.label).localeCompare(String(b.label)) || (a.id < b.id ? -1 : 1);
}

const no = (reason) => ({ ok: false, reason });
const exchange = (x, y) => Object.entries(x.caps).some(([d, ops]) => ops.includes("read") && (y.caps[d] || []).includes("write") && !y.sor.includes(d));

/** Client-side hint for highlighting drop targets (canvas-design 5.5); the server's options are authoritative. */
export function canConnect(items, a, b) {
  const A = items.get(a), B = items.get(b);
  if (!A || !B) return no("This item is not on the map");
  if (a === b) return no("Choose another item to connect to");
  if (A.kind === "app" && B.kind === "app") return no("Hub apps share data internally");
  if (A.kind === "tool" && B.kind === "tool") {
    if (A.is_idp && B.is_idp) return no("Identity providers do not sign in through each other");
    if (A.is_idp !== B.is_idp) return { ok: true, reason: "single sign-on", sso: true };
    const missing = !A.connection ? A : !B.connection ? B : null;
    if (missing) return no(`${missing.label} has no connection yet`);
    return exchange(A, B) || exchange(B, A) ? { ok: true, reason: "" } : no("No data these two can exchange through the hub");
  }
  const tool = A.kind === "tool" ? A : B, app = A.kind === "app" ? A : B;
  if (!app.active) return no(`${app.label} is not active (its extension is disabled)`);
  if (!tool.connection) return no(`${tool.label} has no connection yet`);
  const fits = app.domains.some((d) => {
    const ops = tool.caps[d] || [];
    return ops.includes("read") || (ops.includes("write") && !tool.sor.includes(d)) || (d === "vulnerabilities" && tool.actions.includes("scan"));
  });
  return fits ? { ok: true, reason: "" } : no(`${tool.label} cannot exchange ${app.domains.map(domainWord).join(", ")} with ${app.label}`);
}

/** Accessible name of a tool or app (state included; the engine appends ", selected"). */
export function itemName(item, laneTitle, now) {
  if (item.kind === "app") {
    return `${item.label}, hub app, ${plural(item.flowCount, "data flow")}${item.failing ? `, ${item.failing} failing` : ""}${item.active ? "" : ", inactive"}`;
  }
  const parts = [item.label, item.is_idp ? "identity provider" : "tool", laneTitle,
    item.connection ? (item.connection.tested?.ok === false ? "connection test failed" : "connected") : "no connection",
    plural(item.flowCount, "data flow"), item.failing ? `${item.failing} failing` : "none failing"];
  if (item.proposed) parts.push(`${item.proposed} proposed`);
  if (item.sso) parts.push(item.sso.state === "connected" ? `signs in through ${item.sso.name}` : "single sign-on awaiting approval");
  if (item.node?.health?.ok === false) parts.push("unhealthy");
  return parts.filter(Boolean).join(", ");
}

/** Accessible name of an edge. `names(itemId)` gives an item's label. */
export function edgeName(edge, names, now) {
  if (edge.kind === "flow") {
    const f = edge.flow;
    const tool = names(edge.from.id), app = names(edge.to.id);
    const [a, b] = f.direction === "pull" ? [tool, app] : f.direction === "push" ? [app, tool] : [app, tool];
    const r = f.last_result;
    const last = r ? `last run ${ago(r.at, now)}, ${r.ok ? "succeeded" : "failed"}` : "never run";
    return `Data flow, ${a} to ${b}, ${domainWord(f.domain)} ${DIRECTION_LABEL[f.direction] || f.direction}, ${STATE_WORDS[edge.state]}, ${last}`;
  }
  if (edge.kind === "sso") {
    return `Single sign-on, ${names(edge.to.id)} signs in through ${names(edge.from.id)}${edge.state === "pending" ? ", awaiting approval" : ""}`;
  }
  if (edge.kind === "event") {
    const e = edge.event;
    return `Event route, ${e.event} from ${names(edge.from.id)} to ${names(edge.to.id)}, ${e.has_webhook ? "webhook set" : "no webhook"}`;
  }
  return `Capability, ${names(edge.from.id)} provides ${edge.cap?.capability} to ${names(edge.to.id)}`;
}
