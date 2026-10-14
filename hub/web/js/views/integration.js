// Integration hub: tabs Overview (suite score, data flows, strategies, identity, event routes), Map (the Integration
// map, views/integration-map.js) and Segmentation (views/segmentation-map.js). Tabs switch with history.replaceState
// and an in-view re-render; #/integration/<tab>[/...] deep-links into a tab (canvas-design 3.1).
import { get, post } from "../api.js";
import { flowsTable, planFlows, wireFlows } from "../flows.js";
import { identityCard, loadIdentity, openProviderPicker, wireIdentity } from "../sso.js";
import { STRATEGY_IDS, STRATEGY_TITLES, stateBadge, strategyAction, wireStrategies } from "../strategies.js";
import { actions, badge, emptyState, html, icon, ring, setHTML, timeAgo, toast } from "../ui.js";
import * as integrationMap from "./integration-map.js";
import * as segmentationMap from "./segmentation-map.js";
import { openImport } from "./tools.js";

const TABS = [["overview", "Overview"], ["map", "Map"], ["segmentation", "Segmentation"]];
const FLOW_FILTERS = [["all", "All"], ["proposed", "Proposed"], ["enabled", "Enabled"], ["disabled", "Disabled"]];
const MODULES = { map: integrationMap, segmentation: segmentationMap };

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

/** The Overview tab: today's integration page; the suite graph moved to the Map tab (a summary card links there). */
function overview(el, ctx) {
  let identity = { providers: [], tools: [], default: null, needs_choice: false };
  let flowFilter = "all";
  let flows = [];
  let names = {};
  const draw = async () => {
    const [data, idp, strategies] = await Promise.all([get("/integration"), loadIdentity(), get("/integration/strategies")]);
    if (!el.isConnected) return;
    identity = idp;
    flows = data.flows || [];
    names = Object.fromEntries([...ctx.state.tools.map((t) => [t.id, t.name]), ...data.nodes.map((n) => [n.id, n.name])]);
    const counts = Object.fromEntries(FLOW_FILTERS.map(([k]) => [k, k === "all" ? flows.length : flows.filter((f) => f.status === k).length]));
    const shown = flows.filter((f) => flowFilter === "all" || f.status === flowFilter)
      .sort((a, b) => ({ proposed: 0, enabled: 1, disabled: 2 }[a.status] - { proposed: 0, enabled: 1, disabled: 2 }[b.status]) || a.title.localeCompare(b.title));
    const failing = flows.filter((f) => f.status === "enabled" && f.last_result?.ok === false);
    setHTML(el, html`
      ${!data.nodes.length ? html`<section class="card" style="margin-bottom:16px">${emptyState("plug", "Nothing to integrate yet", "Import two or more tools and the Hub Supervisor maps how they connect.",
        html`<button type="button" class="btn primary" data-act="import" data-min-role="operator">Import tool</button>`)}</section>` : html`
      <div class="grid split" style="margin-bottom:16px">
        <section class="card"><header><h2>Map</h2><a class="btn sm" href="#/integration/map">${icon("plug")}Open map</a></header>
          <div class="int-summary"><div class="grow"><p style="font-size:15px"><b>${data.nodes.length} tool${data.nodes.length === 1 ? "" : "s"}</b>, ${flows.length} data flow${flows.length === 1 ? "" : "s"}
            ${failing.length || counts.proposed ? html`<span class="muted">(${[failing.length ? `${failing.length} failing` : "", counts.proposed ? `${counts.proposed} proposed` : ""].filter(Boolean).join(", ")})</span>` : ""}</p>
            <p class="muted" style="margin-top:6px">The map shows every tool next to the hub apps it exchanges data with, single sign-on and event routes. Operators draw an arrow from a tool to an app to propose a data flow.</p></div></div>
          <div class="row" style="gap:6px;margin-top:12px">${failing.length ? html`<a class="btn sm" href="#/integration/map/failing">${icon("alert")}Show failing flows on the map</a>` : ""}
            <a class="btn sm" href="#/integration/segmentation">${icon("network")}Network segmentation</a></div></section>
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
      </div>`}
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
            <span>${r.has_webhook ?? r.webhook ? badge("webhook", "ok") : badge("no webhook", "warn")}</span></div>`)
          : html`<p class="muted">No event routes. Tools publish to <code>POST /api/bus/publish</code>; tools with <code>events.listens</code> in their manifest receive them.</p>`}</section>
        <section class="card"><header><h3>Recent deliveries</h3></header>
          ${data.deliveries.length ? data.deliveries.slice().reverse().map((d) => html`<div class="msg-line"><code>${d.event}</code>
            <span class="muted">${d.deliveries.length} target(s) ${d.deliveries.every((x) => x.ok) ? "" : badge("failed", "bad")}</span><span class="faint">${timeAgo(d.ts)}</span></div>`)
          : html`<p class="muted">No events published yet.</p>`}</section>
      </div>`);
  };
  const refresh = () => draw().catch(() => {});
  const pickProvider = (toolId) => {
    const t = identity.tools.find((x) => x.tool_id === toolId);
    if (identity.providers.length) openProviderPicker({ toolId, toolName: t?.name || names[toolId] || toolId, data: identity, current: t?.choice || t?.pending?.provider || t?.connected_to || t?.selected, done: refresh });
    else openImport();
  };
  actions(el, {
    "flows-filter": (d) => { flowFilter = d.f; refresh(); },
    import: () => openImport(),
  });
  wireFlows(el, { find: (id) => flows.find((f) => f.id === id), refresh, names: () => names });
  wireStrategies(el, { refresh, handlers: { choose_provider: pickProvider, connect_sso: pickProvider, import_provider: () => openImport() } });
  wireIdentity(el, () => identity, refresh);
  return draw;
}

export async function render(el, ctx) {
  let tab = TABS.some(([k]) => k === ctx.params[0]) ? ctx.params[0] : "overview";
  let mounted = null;
  let drawOverview = null;
  setHTML(el, html`
    <div class="page-head"><div><h1>Integration hub</h1><p class="muted">How your tools fit together: shared capabilities, single sign-on, events, data flows and conflicts.</p></div>
      <div class="row" data-min-role="operator"><button class="btn" data-act="plan">${icon("flow")}Plan data flows</button>
        <button class="btn" data-act="evaluate">${icon("refresh")}Re-evaluate suite</button></div></div>
    <div class="tabs" role="tablist" aria-label="Integration hub">${TABS.map(([k, label]) => html`<button type="button" role="tab" data-act="tab" data-tab="${k}"
      aria-selected="${tab === k ? "true" : "false"}" class="${tab === k ? "active" : ""}">${label}</button>`)}</div>
    <div data-part="tab-body"></div>`);
  const body = el.querySelector('[data-part="tab-body"]');

  async function mountTab(name, params = []) {
    mounted?.dispose();
    mounted = null;
    drawOverview = null;
    tab = name;
    el.querySelectorAll('[data-act="tab"]').forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === name);
      b.setAttribute("aria-selected", String(b.dataset.tab === name));
    });
    // a fresh container per tab: listeners wired by the previous tab go with it
    const host = document.createElement("div");
    body.replaceChildren(host);
    ctx.crumb(name === "overview" ? "Integration hub" : `Integration hub / ${TABS.find(([k]) => k === name)[1]}`);
    if (name === "overview") {
      setHTML(host, html`<div class="empty faint">Loading...</div>`);
      drawOverview = overview(host, ctx);
      await drawOverview().catch((err) => setHTML(host, emptyState("alert", "Could not load the overview", err.message)));
    } else {
      mounted = MODULES[name].mount(host, ctx, { params });
    }
  }

  actions(el, {
    async evaluate() { await post("/integration/evaluate"); toast("Suite re-evaluated", "ok"); drawOverview?.().catch(() => {}); },
    plan: () => planFlows(() => drawOverview?.().catch(() => {})),
    tab(d) {
      if (d.tab === tab) return;
      history.replaceState(null, "", d.tab === "overview" ? "#/integration" : `#/integration/${d.tab}`);
      mountTab(d.tab);
    },
  });
  ctx.onLeave(() => mounted?.dispose());
  ctx.live(["tool", "tool_removed", "toolbus", "patch", "approval", "flow", "flow_removed", "connection"], () => {
    if (tab === "overview" && drawOverview) drawOverview().catch(() => {});
  }, 600);
  await mountTab(tab, ctx.params.slice(1));
}
