import { get, post } from "../api.js";
import { flowsTable, planFlows, wireFlows } from "../flows.js";
import { identityCard, loadIdentity, openProviderPicker, wireIdentity } from "../sso.js";
import { STRATEGY_IDS, STRATEGY_TITLES, stateBadge, strategyAction, wireStrategies } from "../strategies.js";
import { actions, badge, colorFor, emptyState, html, icon, ring, setHTML, timeAgo, toast } from "../ui.js";
import { mountMap } from "../canvas/maps.js";
import { openImport } from "./tools.js";

const LINK_COLORS = { capability: "#8b5cf6", identity: "#22c55e", event: "#f59e0b", flow: "#0ea5e9", failing: "#ef4444" };
const FLOW_FILTERS = [["all", "All"], ["proposed", "Proposed"], ["enabled", "Enabled"], ["disabled", "Disabled"]];

function graph(nodes, links, flowLinks) {
  const W = 760, H = 420, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 60;
  const pos = { hub: [cx, cy] };
  nodes.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, nodes.length) - Math.PI / 2;
    pos[n.id] = [cx + R * Math.cos(a) * 1.35, cy + R * Math.sin(a)];
  });
  const spokes = nodes.map((n) => html`<line x1="${cx}" y1="${cy}" x2="${pos[n.id][0]}" y2="${pos[n.id][1]}" stroke="var(--border-strong)" stroke-dasharray="3 5"/>`);
  const edges = links.filter((l) => pos[l.source] && pos[l.target]).map((l, i) => {
    const [x1, y1] = pos[l.source], [x2, y2] = pos[l.target];
    const mx = (x1 + x2) / 2 + (cy - (y1 + y2) / 2) * 0.18 + (i % 3) * 6, my = (y1 + y2) / 2 + ((x1 + x2) / 2 - cx) * 0.18;
    return html`<path d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" stroke="${LINK_COLORS[l.type]}" stroke-width="2.2" fill="none" marker-end="url(#arr-${l.type})" opacity=".9"><title>${l.source} &rarr; ${l.target}: ${l.via}</title></path>`;
  });
  // Data flows bend to the side of their direction, so a pull and a push between the same ends stay apart.
  const flows = flowLinks.filter((l) => pos[l.source] && pos[l.target] && l.source !== l.target).map((l) => {
    const [x1, y1] = pos[l.source], [x2, y2] = pos[l.target];
    const len = Math.hypot(x2 - x1, y2 - y1) || 1;
    const mx = (x1 + x2) / 2 - ((y2 - y1) / len) * 26, my = (y1 + y2) / 2 + ((x2 - x1) / len) * 26;
    const kind = l.failing ? "failing" : "flow";
    return html`<path d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" stroke="${LINK_COLORS[kind]}" stroke-width="2.4" fill="none" marker-end="url(#arr-${kind})"
      ${l.status === "enabled" ? "" : html`stroke-dasharray="6 5" opacity=".6"`}><title>Data flow: ${l.via} (${l.status}${l.failing ? ", failing" : ""})</title></path>`;
  });
  const markers = Object.entries(LINK_COLORS).map(([k, c]) => html`<marker id="arr-${k}" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`);
  const dots = nodes.map((n) => {
    const [x, y] = pos[n.id];
    return html`<g><circle cx="${x}" cy="${y}" r="20" fill="${colorFor(n.id)}"/><text x="${x}" y="${y + 5}" text-anchor="middle" style="fill:#fff;font-size:14px">${n.name[0]?.toUpperCase()}</text>
      <text x="${x}" y="${y + 38}" text-anchor="middle">${n.name}</text>${n.score != null ? html`<text x="${x}" y="${y + 53}" text-anchor="middle" style="fill:var(--muted);font-weight:500;font-size:11px">score ${n.score}</text>` : ""}</g>`;
  });
  return html`<svg class="graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="Integration graph"><defs>${markers}</defs>${spokes}${edges}${flows}
    <g><circle cx="${cx}" cy="${cy}" r="28" fill="var(--accent)"/><text x="${cx}" y="${cy + 5}" text-anchor="middle" style="fill:#fff">Hub</text></g>${dots}</svg>`;
}

function strategiesTable(data) {
  if (!data.tools.length) return html`<p class="muted">Strategies appear once tools are analysed.</p>`;
  return html`<div class="table-wrap"><table class="table strategies"><thead><tr><th>Tool</th>${STRATEGY_IDS.map((id) => html`<th>${STRATEGY_TITLES[id]}</th>`)}</tr></thead><tbody>
    ${data.tools.map((t) => {
      const byId = Object.fromEntries(t.strategies.map((s) => [s.id, s]));
      return html`<tr><td><a href="#/tools/${t.tool_id}"><b>${t.name}</b></a></td>
        ${STRATEGY_IDS.map((id) => {
          const s = byId[id];
          return s ? html`<td title="${s.detail}"><div class="strategy-cell">${stateBadge(s.state)}${s.action ? strategyAction(t.tool_id, s) : ""}</div></td>` : html`<td class="faint">-</td>`;
        })}</tr>`;
    })}</tbody></table></div>`;
}

function tabBar(tab) {
  return html`<div class="seg" role="tablist" aria-label="Integration views" style="margin-bottom:14px">
    ${[["overview", "Overview"], ["map", "Map"], ["segmentation", "Segmentation"]].map(([id, label]) =>
      html`<button type="button" role="tab" class="${tab === id ? "active" : ""}" aria-selected="${tab === id ? "true" : "false"}" data-act="tab" data-tab="${id}">${label}</button>`)}</div>`;
}

export async function render(el, ctx) {
  let tab = ctx.params[0] === "map" || ctx.params[0] === "segmentation" ? ctx.params[0] : "overview";
  let mapHandle = null;
  let identity = { providers: [], tools: [], default: null, needs_choice: false };
  let flowFilter = "all";
  let flows = [];
  let names = {};
  const draw = async () => {
    if (tab !== "overview") return;
    const [data, idp, strategies] = await Promise.all([get("/integration"), loadIdentity(), get("/integration/strategies")]);
    identity = idp;
    flows = data.flows || [];
    names = Object.fromEntries([...ctx.state.tools.map((t) => [t.id, t.name]), ...data.nodes.map((n) => [n.id, n.name])]);
    const counts = Object.fromEntries(FLOW_FILTERS.map(([k]) => [k, k === "all" ? flows.length : flows.filter((f) => f.status === k).length]));
    const shown = flows.filter((f) => flowFilter === "all" || f.status === flowFilter)
      .sort((a, b) => ({ proposed: 0, enabled: 1, disabled: 2 }[a.status] - { proposed: 0, enabled: 1, disabled: 2 }[b.status]) || a.title.localeCompare(b.title));
    const failing = flows.filter((f) => f.status === "enabled" && f.last_result?.ok === false);
    setHTML(el, html`
      ${tabBar(tab)}
      <div class="page-head"><div><h1>Integration hub</h1><p class="muted">How your tools fit together: shared capabilities, single sign-on, events, data flows and conflicts.</p></div>
        <div class="row" data-min-role="operator"><button class="btn" data-act="plan">${icon("flow")}Plan data flows</button>
          <button class="btn" data-act="evaluate">${icon("refresh")}Re-evaluate suite</button></div></div>
      ${!data.nodes.length ? html`<section class="card">${emptyState("plug", "Nothing to integrate yet", "Import two or more tools and the Hub Supervisor maps how they connect.")}</section>` : html`
      <div class="grid split" style="margin-bottom:16px">
        <section class="card"><header><h2>Suite map</h2><div class="legend"><span><i style="background:${LINK_COLORS.capability}"></i>capability</span>
          <span><i style="background:${LINK_COLORS.identity}"></i>single sign-on</span><span><i style="background:${LINK_COLORS.event}"></i>events</span>
          <span><i style="background:${LINK_COLORS.flow}"></i>data flow</span>${failing.length ? html`<span><i style="background:${LINK_COLORS.failing}"></i>failing</span>` : ""}</div></header>
          ${graph(data.nodes, data.links, data.flow_links || [])}</section>
        <section class="stack">
          <div class="card"><div class="row" style="flex-wrap:nowrap;gap:16px">${ring(data.suite_score, 72)}
            <div><h2>Suite score</h2><p class="muted">Average integration score of ${data.nodes.length} tools. Gaps are sent to the Patch Agent automatically.</p></div></div></div>
          <div class="card"><header><h3>Conflicts</h3></header>
            ${data.conflicts.length ? data.conflicts.map((c) => html`<div class="check-row"><div class="ico fail">${icon("x")}</div><div>Port <b>${c.port}</b> is used by ${c.tools.join(", ")}</div></div>`)
              : html`<p class="muted">No port conflicts.</p>`}</div>
          <div class="card"><header><h3>Missing dependencies</h3></header>
            ${Object.keys(data.unmet).length ? Object.entries(data.unmet).map(([id, caps]) => html`<div class="check-row"><div class="ico warn">${icon("minus")}</div>
              <div><b>${names[id] || id}</b> needs ${caps.map((c) => html`<span class="badge">${c}</span> `)}</div></div>`)
              : html`<p class="muted">Everything the tools consume is provided by the suite.</p>`}</div>
        </section>
      </div>
      <section class="card" style="margin-bottom:16px" id="data-flows"><header><div><h2>Data flows</h2>
          <p class="faint" style="font-size:12.5px;margin-top:2px">Records moving between tools and the hub's Assets, Vulnerabilities and Compliance apps.</p></div>
        <div class="seg">${FLOW_FILTERS.map(([k, label]) => html`<button class="${flowFilter === k ? "active" : ""}" data-act="flows-filter" data-f="${k}">${label} (${counts[k]})</button>`)}</div></header>
        ${failing.length ? html`<div class="notice bad" style="margin-bottom:12px">${icon("alert")}<div><b>${failing.length} flow${failing.length > 1 ? "s" : ""} failing.</b>
          <span class="muted">After 3 failures in a row the Patch Agent proposes a repair; you can also ask for one with Repair.</span></div></div>` : ""}
        ${counts.proposed && flowFilter !== "enabled" && flowFilter !== "disabled" ? html`<div class="notice" style="margin-bottom:12px">${icon("checkCircle")}<div class="muted">
          ${counts.proposed} proposed flow${counts.proposed > 1 ? "s wait" : " waits"} for a decision: enable or dismiss here, or in Approvals.</div></div>` : ""}
        ${flowsTable(shown, { names, empty: flows.length ? "No flows in this state." : "No data flows yet. Connect a tool's API in its Connection tab and test it: the Hub Supervisor then proposes flows." })}
      </section>
      <section class="card" style="margin-bottom:16px"><header><div><h2>Integration strategies</h2>
        <p class="faint" style="font-size:12.5px;margin-top:2px">Per tool: how far each way of integrating it has got. Hover a state for details.</p></div></header>
        ${strategiesTable(strategies)}</section>
      ${identityCard(identity)}
      <div class="grid cols-3">
        <section class="card"><header><h3>Connections (${data.links.length})</h3></header>
          ${data.links.length ? data.links.map((l) => html`<div class="msg-line"><span class="route">${names[l.source]} &rarr; ${names[l.target]}</span>
            <span>${badge(l.via, l.type === "identity" ? "ok" : l.type === "event" ? "warn" : "accent")}</span><span class="faint">${l.type}</span></div>`)
          : html`<p class="muted">No connections yet. Tools connect when one provides what another consumes, shares SSO, or listens to another's events.</p>`}</section>
        <section class="card"><header><h3>Event routes</h3></header>
          ${data.routes.length ? data.routes.map((r) => html`<div class="msg-line"><span class="route">${names[r.from]} &rarr; ${names[r.to]}</span><code>${r.event}</code>
            <span>${r.webhook ? badge("webhook", "ok") : badge("no webhook", "warn")}</span></div>`)
          : html`<p class="muted">No event routes. Tools publish to <code>POST /api/bus/publish</code>; tools with <code>events.listens</code> in their manifest receive them.</p>`}</section>
        <section class="card"><header><h3>Recent deliveries</h3></header>
          ${data.deliveries.length ? data.deliveries.slice().reverse().map((d) => html`<div class="msg-line"><code>${d.event}</code>
            <span class="muted">${d.deliveries.length} target(s) ${d.deliveries.every((x) => x.ok) ? "" : badge("failed", "bad")}</span><span class="faint">${timeAgo(d.ts)}</span></div>`)
          : html`<p class="muted">No events published yet.</p>`}</section>
      </div>`}`);
  };
  const refresh = () => draw().catch(() => {});
  const pickProvider = (toolId) => {
    const t = identity.tools.find((x) => x.tool_id === toolId);
    if (identity.providers.length) openProviderPicker({ toolId, toolName: t?.name || names[toolId] || toolId, data: identity, current: t?.choice || t?.pending?.provider || t?.connected_to || t?.selected, done: refresh });
    else openImport();
  };
  const openTab = async (next) => {
    tab = next;
    history.replaceState(null, "", next === "overview" ? "#/integration" : `#/integration/${next}`);
    mapHandle?.destroy();
    mapHandle = null;
    el._cleanup = null;
    if (tab === "overview") { await draw(); return; }
    setHTML(el, html`${tabBar(tab)}<div class="page-head"><div><h1>${tab === "map" ? "Integration map" : "Segmentation map"}</h1>
      <p class="muted">${tab === "map" ? "Tools and hub apps. Drag a card to remember its place. The list is the same map for a keyboard." : "Zones from the latest firewall snapshot. Propose a change from the side panel. Applying it needs the device-changes guardrail and a second administrator."}</p></div></div>
      <div id="map-host"></div>`);
    mapHandle = await mountMap(el.querySelector("#map-host"), tab === "map" ? "integration" : "segmentation", ctx);
    el._cleanup = () => mapHandle?.destroy();
  };

  actions(el, {
    tab: (d) => openTab(d.tab),
    async evaluate() { await post("/integration/evaluate"); toast("Suite re-evaluated", "ok"); draw(); },
    plan: () => planFlows(refresh),
    "flows-filter": (d) => { flowFilter = d.f; draw(); },
  });
  wireFlows(el, { find: (id) => flows.find((f) => f.id === id), refresh, names: () => names });
  wireStrategies(el, { refresh, handlers: { choose_provider: pickProvider, connect_sso: pickProvider, import_provider: () => openImport() } });
  wireIdentity(el, () => identity, refresh);
  if (tab === "overview") {
    await draw();
    ctx.live(["tool", "tool_removed", "toolbus", "patch", "approval", "flow", "flow_removed", "connection"], draw, 600);
  } else {
    await openTab(tab);
  }
}
