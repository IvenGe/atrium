// Settings > AI usage and spending: model calls, tokens and estimated cost per agent and per provider over today, 7 or
// 30 UTC days, the suite's daily cap against today's spending, a 30-day chart of the daily cost (with the same numbers
// as a table for screen readers), and - for administrators - the price table behind the estimates.
import { get, put } from "../api.js";
import { meterTone } from "../llm.js";
import { actions, badge, can, html, icon, modal, raw, setHTML, toast } from "../ui.js";

const PERIODS = [[1, "Today"], [7, "7 days"], [30, "30 days"]];
const SORTS = [["calls", "Calls"], ["tokens", "Tokens"], ["cost_usd", "Cost (est.)"]];
const KINDS = [["input", "Input"], ["cached_input", "Cached input"], ["cache_write", "Cache write"], ["output", "Output"]];
const enc = encodeURIComponent;
const num = (n) => Number(n || 0).toLocaleString("en-US");
const usd = (n, digits = 2) => `$${Number(n || 0).toFixed(digits)}`;
const tokens = (r) => (r.input_tokens || 0) + (r.cached_input_tokens || 0) + (r.cache_write_tokens || 0) + (r.output_tokens || 0);
const DAY = 86400000;

/** The last `n` UTC days ending at `to` (YYYY-MM-DD), each with its cost (0 when nothing was called). */
function series(rows, to, n = 30) {
  const byDay = Object.fromEntries(rows.map((r) => [r.key, r.cost_usd || 0]));
  const end = Date.parse(`${to}T00:00:00Z`);
  return Array.from({ length: n }, (_, i) => {
    const day = new Date(end - (n - 1 - i) * DAY).toISOString().slice(0, 10);
    return { day, cost: byDay[day] || 0 };
  });
}

/** Daily cost as columns (the dashboard's column style, one series, so no legend) and the same data as a table. */
function costChart(days) {
  const max = Math.max(0.0001, ...days.map((d) => d.cost));
  const total = days.reduce((s, d) => s + d.cost, 0);
  if (!total) return html`<p class="faint" style="font-size:12.5px">No estimated cost in the last 30 days.</p>`;
  return html`<div class="dash-cols-wrap"><ol class="dash-cols" aria-hidden="true">${days.map((d) => html`<li><span class="col">
      <span class="col-fill" style="height:${((d.cost / max) * 100).toFixed(1)}%"></span>
      <span class="dash-tip">${d.day}: ${usd(d.cost, 4)}</span></span></li>`)}</ol>
    <div class="dash-cols-axis" aria-hidden="true"><span>${days[0].day}</span><span>${days.at(-1).day}</span></div></div>
    <table class="sr-only"><caption>Estimated AI cost per day (UTC), last 30 days</caption><thead><tr><th scope="col">Day</th><th scope="col">Cost (USD)</th></tr></thead>
      <tbody>${days.map((d) => html`<tr><th scope="row">${d.day}</th><td>${d.cost.toFixed(4)}</td></tr>`)}</tbody></table>`;
}

function sortedRows(rows, sort, dir) {
  const value = (r) => (sort === "tokens" ? tokens(r) : r[sort] || 0);
  return [...rows].sort((a, b) => (dir === "asc" ? value(a) - value(b) : value(b) - value(a)) || String(a.key).localeCompare(String(b.key)));
}

function usageTable(rows, state, { label, link }) {
  const head = (key, text) => {
    const active = state.sort === key;
    const aria = active ? (state.dir === "asc" ? "ascending" : "descending") : "none";
    return html`<th scope="col" class="num" aria-sort="${aria}"><button type="button" data-act="sort" data-key="${key}">${text}${active ? (state.dir === "asc" ? " ▲" : " ▼") : ""}
      <span class="sr-only">${active ? "" : " (sort)"}</span></button></th>`;
  };
  if (!rows.length) return html`<p class="faint" style="font-size:12.5px">No model calls in this period.</p>`;
  return html`<div class="table-wrap"><table class="table compact ai-usage-table"><caption class="sr-only">${label}: model use in the period, sortable</caption>
    <thead><tr><th scope="col">${label}</th>${SORTS.map(([k, t]) => head(k, t))}</tr></thead>
    <tbody>${sortedRows(rows, state.sort, state.dir).map((r) => html`<tr><th scope="row">${link ? html`<a href="#/agents/${enc(r.key)}/settings">${r.name || r.key}</a>` : r.name || r.key}
      ${r.errors ? html` <span class="faint" style="font-size:11.5px">(${num(r.errors)} failed)</span>` : ""}${r.stopped ? html` <span class="faint" style="font-size:11.5px">(${num(r.stopped)} stopped by a limit)</span>` : ""}</th>
      <td class="num">${num(r.calls)}</td><td class="num">${num(tokens(r))}</td><td class="num">${usd(r.cost_usd, r.cost_usd && r.cost_usd < 0.1 ? 4 : 2)}</td></tr>`)}</tbody></table></div>`;
}

function budgetLine(b) {
  if (!b?.enabled) return html`<p class="warn-text" style="font-size:12.5px">${icon("alert")} No daily cap: the guardrail "Cap the AI model spending per day" is off.</p>`;
  const tone = meterTone(b.spent_today, b.limit);
  return html`<div class="meter-line"><span>Suite cap today</span>
    <meter min="0" max="${b.limit}" low="${b.limit * 0.8}" high="${b.limit * 0.9999}" optimum="0" value="${Math.min(b.spent_today, b.limit)}"
      aria-label="AI spending today: ${usd(b.spent_today)} of $${b.limit}"></meter>
    <span>${usd(b.spent_today)} of $${b.limit} today</span>
    ${tone === "bad" ? badge("cap reached: new calls stop", "bad") : tone === "warn" ? badge("over 80 %", "warn") : ""}</div>`;
}

function view(state, admin) {
  const { agents, providers, daily } = state;
  const t = agents.totals;
  return html`<header><h2 tabindex="-1">AI usage and spending</h2><span class="spacer"></span><div class="card-actions" data-slot="home"></div></header>
    <fieldset class="plain period-group"><legend class="sr-only">Period</legend><div class="row" style="gap:12px;flex-wrap:wrap">
      ${PERIODS.map(([d, label]) => html`<label class="radio-line" style="margin:0"><input type="radio" name="ai-usage-period" value="${d}" ${d === state.days ? raw("checked") : ""} data-period>
        <span>${label}</span></label>`)}</div></fieldset>
    <p style="font-size:13px;margin:10px 0 6px"><b>${num(t.calls)}</b> model calls, <b>${num(t.input_tokens + t.cached_input_tokens + t.cache_write_tokens)}</b> tokens in,
      <b>${num(t.output_tokens)}</b> out, about <b>${usd(agents.totals.cost_usd)}</b> (${agents.from === agents.to ? agents.to : `${agents.from} to ${agents.to}`}, UTC).</p>
    ${budgetLine(agents.suite_budget)}
    <h3 class="as-h3" style="margin-top:12px">By agent</h3>${usageTable(agents.rows, state, { label: "Agent", link: true })}
    <h3 class="as-h3" style="margin-top:12px">By provider</h3>${usageTable(providers.rows, state, { label: "Provider" })}
    <h3 class="as-h3" style="margin-top:12px">Estimated cost per day (last 30 days)</h3>${costChart(series(daily.rows, daily.to))}
    <p class="faint" style="font-size:12px;margin-top:8px">Cost is estimated from the price table${agents.prices_as_of ? ` (shipped prices as of ${agents.prices_as_of})` : ""}; Atrium does not read
      the providers' bills. ${agents.unpriced?.length ? `Models without a price are not counted: ${agents.unpriced.join(", ")}.` : "Models without a price are not counted."}
      Each agent's own budgets are on its settings page (Limits).</p>
    ${admin ? html`<button type="button" class="btn sm" data-act="prices">${icon("edit")}Edit prices</button>` : ""}`;
}

/** The price table editor: one row per provider:model in use (or overridden), USD per 1M tokens. */
async function pricesModal(state, done) {
  let prices;
  try {
    prices = await get("/llm/prices");
  } catch (err) {
    return toast(err.message, "bad");
  }
  const used = new Set((state.agents.rows || []).flatMap((r) => r.models || []));
  const keys = [...new Set([...used, ...Object.keys(prices.overrides || {})])].sort();
  modal({
    title: "AI prices (USD per 1M tokens)", wide: true, minRole: "admin", submit: "Save prices",
    body: html`<p class="muted" style="margin-bottom:10px">Used for the cost estimates and the cost budgets. Shipped prices are dated and sourced; a price you set
      replaces it until you reset it. Local models without a price cost $0.</p>
      ${keys.length ? html`<div class="table-wrap"><table class="table compact"><caption class="sr-only">Prices per model</caption>
        <thead><tr><th scope="col">Provider:model</th>${KINDS.map(([, l]) => html`<th scope="col" class="num">${l}</th>`)}<th scope="col">Reset</th></tr></thead>
        <tbody>${keys.map((key) => {
          const p = prices.effective?.[key] || {};
          const own = Boolean(prices.overrides?.[key]);
          return html`<tr data-price="${key}"><th scope="row" class="mono" style="font-size:12px">${key}${p.tiers?.length ? html`<span class="faint"> (tiered)</span>` : ""}
              <div class="faint" style="font-size:11px">${own ? "set here" : p.as_of ? `shipped, as of ${p.as_of}` : "no price"}</div></th>
            ${KINDS.map(([k, l]) => html`<td><input type="number" min="0" max="10000" step="0.001" style="width:90px" name="${key}|${k}" value="${p[k] ?? ""}" aria-label="${l} price of ${key}"></td>`)}
            <td>${own ? html`<label class="check"><input type="checkbox" name="${key}|reset"><span class="sr-only">Reset ${key} to the shipped price</span><span aria-hidden="true">Reset</span></label>` : ""}</td></tr>`;
        })}</tbody></table></div>` : html`<p class="faint">No model has been called yet.</p>`}`,
    async onSubmit(data) {
      const overrides = {};
      for (const key of keys) {
        if (data.get(`${key}|reset`) === "on") { overrides[key] = null; continue; }
        const p = prices.effective?.[key] || {};
        const value = Object.fromEntries(KINDS.map(([k]) => [k, Number(data.get(`${key}|${k}`) || 0)]));
        if (KINDS.every(([k]) => Number(p[k] || 0) === value[k])) continue;
        overrides[key] = { ...value, tiers: p.tiers || [] };
      }
      if (!Object.keys(overrides).length) return;
      await put("/llm/prices", { overrides });
      toast("Prices saved", "ok");
      done();
    },
  });
}

/** Renders the panel into `el` and keeps it current on usage and settings events. */
export async function mount(el, ctx) {
  const admin = can("admin");
  const state = { days: 30, sort: "cost_usd", dir: "desc", agents: null, providers: null, daily: null };
  const load = async () => {
    const [agents, providers, daily] = await Promise.all([get(`/llm/usage?days=${state.days}&group=agent`),
      get(`/llm/usage?days=${state.days}&group=provider`), get("/llm/usage?days=30&group=day")]);
    Object.assign(state, { agents, providers, daily });
  };
  const draw = (focus) => {
    if (!el.isConnected) return;
    setHTML(el, view(state, admin));
    if (focus) el.querySelector(focus)?.focus();
  };
  await load();
  draw();
  el.addEventListener("change", async (e) => {
    if (!e.target.matches("[data-period]")) return;
    state.days = Number(e.target.value);
    await load();
    draw(`[data-period][value="${state.days}"]`);
  });
  actions(el, {
    sort(d) {
      state.dir = state.sort === d.key && state.dir === "desc" ? "asc" : "desc";
      state.sort = d.key;
      draw(`[data-act="sort"][data-key="${d.key}"]`);
    },
    prices() { pricesModal(state, async () => { await load(); draw(); }); },
  });
  ctx.live(["llm_usage", "settings"], async () => {
    if (!el.isConnected || el.contains(document.activeElement)) return;
    await load();
    draw();
  }, 1500);
}
