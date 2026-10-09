import { get, post } from "../api.js";
import { actions, badge, colorFor, emptyState, html, icon, ring, setHTML, timeAgo, toast } from "../ui.js";

const LINK_COLORS = { capability: "#8b5cf6", identity: "#22c55e", event: "#f59e0b" };

function graph(nodes, links) {
  const W = 760, H = 420, cx = W / 2, cy = H / 2, R = Math.min(W, H) / 2 - 60;
  const pos = {};
  nodes.forEach((n, i) => {
    const a = (2 * Math.PI * i) / Math.max(1, nodes.length) - Math.PI / 2;
    pos[n.id] = [cx + R * Math.cos(a) * 1.35, cy + R * Math.sin(a)];
  });
  const spokes = nodes.map((n) => html`<line x1="${cx}" y1="${cy}" x2="${pos[n.id][0]}" y2="${pos[n.id][1]}" stroke="var(--border-strong)" stroke-dasharray="3 5"/>`);
  const edges = links.map((l, i) => {
    const [x1, y1] = pos[l.source], [x2, y2] = pos[l.target];
    const mx = (x1 + x2) / 2 + (cy - (y1 + y2) / 2) * 0.18 + (i % 3) * 6, my = (y1 + y2) / 2 + ((x1 + x2) / 2 - cx) * 0.18;
    return html`<path d="M${x1},${y1} Q${mx},${my} ${x2},${y2}" stroke="${LINK_COLORS[l.type]}" stroke-width="2.2" fill="none" marker-end="url(#arr-${l.type})" opacity=".9"><title>${l.source} &rarr; ${l.target}: ${l.via}</title></path>`;
  });
  const markers = Object.entries(LINK_COLORS).map(([k, c]) => html`<marker id="arr-${k}" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`);
  const dots = nodes.map((n) => {
    const [x, y] = pos[n.id];
    return html`<g><circle cx="${x}" cy="${y}" r="20" fill="${colorFor(n.id)}"/><text x="${x}" y="${y + 5}" text-anchor="middle" style="fill:#fff;font-size:14px">${n.name[0]?.toUpperCase()}</text>
      <text x="${x}" y="${y + 38}" text-anchor="middle">${n.name}</text>${n.score != null ? html`<text x="${x}" y="${y + 53}" text-anchor="middle" style="fill:var(--muted);font-weight:500;font-size:11px">score ${n.score}</text>` : ""}</g>`;
  });
  return html`<svg class="graph" viewBox="0 0 ${W} ${H}" role="img" aria-label="Integration graph"><defs>${markers}</defs>${spokes}${edges}
    <g><circle cx="${cx}" cy="${cy}" r="28" fill="var(--accent)"/><text x="${cx}" y="${cy + 5}" text-anchor="middle" style="fill:#fff">Hub</text></g>${dots}</svg>`;
}

export async function render(el, ctx) {
  const draw = async () => {
    const data = await get("/integration");
    const names = Object.fromEntries(data.nodes.map((n) => [n.id, n.name]));
    setHTML(el, html`
      <div class="page-head"><div><h1>Integration hub</h1><p class="muted">How your tools fit together: shared capabilities, single sign-on, events and conflicts.</p></div>
        <button class="btn" data-act="evaluate">${icon("refresh")}Re-evaluate suite</button></div>
      ${!data.nodes.length ? html`<section class="card">${emptyState("plug", "Nothing to integrate yet", "Import two or more tools and the Hub Supervisor maps how they connect.")}</section>` : html`
      <div class="grid split" style="margin-bottom:16px">
        <section class="card"><header><h2>Suite map</h2><div class="legend"><span><i style="background:${LINK_COLORS.capability}"></i>capability</span>
          <span><i style="background:${LINK_COLORS.identity}"></i>single sign-on</span><span><i style="background:${LINK_COLORS.event}"></i>events</span></div></header>
          ${graph(data.nodes, data.links)}</section>
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
  actions(el, { async evaluate() { await post("/integration/evaluate"); toast("Suite re-evaluated", "ok"); draw(); } });
  await draw();
  ctx.live(["tool", "tool_removed", "toolbus"], draw, 600);
}
