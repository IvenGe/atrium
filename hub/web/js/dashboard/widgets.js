// Widget renderers of the Home dashboards (round4-dashboard-spec.md 10.3, 10.10, 10.13): the widget frame, the states
// (loading, empty, error, forbidden, unavailable, disabled, stale) and one renderer per widget type. All pure:
// (data, instance, ctx) -> html``, no DOM access, so they run in Node tests. Text that comes from tools or people is only
// interpolated through html``, which escapes it; links are the server's internal routes (#/...), checked again here.
//
// ctx: {editing, editable (the viewer may change this dashboard), table (show the chart as a table), now (seconds),
//      stack (the one-column stack mode of narrow screens: wide widgets use their narrow form)}.
// Stage D3 adds the record widgets (counts, lists and timelines over every domain), the compliance, network and people
// widgets, and declared widgets (drawn like the widget they compile to); D4 adds the settings widgets: AI models
// (aimodels.js, where administrators drag agents between providers; ctx.admin), safety settings and hub accounts.
import { appIcon, badge, dateTime, emptyState, html, icon, md, ring, timeAgo } from "../ui.js";
import { aiModelsBody, aiModelsSummary } from "./aimodels.js";
import { SEVERITIES, bars, barsTable, columns, matrix, matrixTable, table } from "./charts.js";

/** An internal route from widget data, else the fallback (the server only sends #/..., this keeps it that way). */
export const route = (href, fallback = null) => (typeof href === "string" && /^#\/[^\s"'<>`]*$/.test(href) ? href : fallback);
const plural = (n, word, many = `${word}s`) => `${n} ${n === 1 ? word : many}`;
const when = (ts) => (ts ? html`<span class="when" title="${dateTime(ts)}">${timeAgo(ts)}</span>` : "");
const kindLabel = (kind) => (kind === "saas" ? "SaaS" : kind === "closed" ? "Closed source" : "Source code");
const none = (text) => html`<p class="muted dash-none">${text}</p>`;

// ---------- shared pieces (also used by the People app) ----------

/** A tool record of GET /api/tools as a card. */
export function toolCard(t) {
  const level = t.report?.level;
  return html`<a class="tool-card" href="#/tools/${t.id}">
    <div class="top">${appIcon(t)}<div style="min-width:0;flex:1"><div class="name">${t.name}</div>
      <div class="faint" style="font-size:12px">${kindLabel(t.manifest?.kind)} - ${t.source_type}</div></div>
      ${ring(t.report?.score)}</div>
    <div class="row">${badge(t.status)}${level ? badge(level) : ""}${t.running ? badge("running", "ok") : ""}
      ${t.health && t.health.ok === false ? badge("down", "bad") : ""}</div></a>`;
}

/** One activity entry {actor, level, text, ts}. */
export function feedItem(a) {
  const tone = a.level === "error" ? "bad" : a.level === "warn" ? "warn" : "ok";
  return html`<div class="feed-item"><span class="dot ${tone}" style="margin-top:7px"></span>
    <div><span class="who">${a.actor}</span> <span class="muted">${a.text}</span></div><span class="when" title="${dateTime(a.ts)}">${timeAgo(a.ts)}</span></div>`;
}

// ---------- renderers of the stage-D1 types ----------

function metricBody(d, inst) {
  const label = inst.title || d.label;
  const value = d.value === null || d.value === undefined ? "-" : d.display ?? `${d.value}${d.unit || ""}`;
  const tone = ["ok", "warn", "bad"].includes(d.tone) ? d.tone : "";
  // a hint ("estimated") is part of the tile's name and its tooltip
  return html`<a class="card stat dash-stat ${tone ? `tone-${tone}` : ""}" href="${route(d.href, "#/")}" ${d.hint ? html`title="${label} (${d.hint})"` : ""}>
    <div class="stat-icon">${icon(d.icon || "grid")}</div>
    <div class="stat-text"><div class="label">${label}${d.hint ? html`<span class="sr-only"> (${d.hint})</span>` : ""}</div><div class="value">${value}</div>
      <div class="sub" title="${d.sub || ""}">${d.sub || ""}</div></div></a>`;
}

function toolTile(r) {
  const tool = { id: r.id, name: r.name, running: r.running, manifest: { ui: r.ui || {} } };
  const failing = r.flows?.failing || 0;
  return html`<a class="tool-card" href="${route(r.href, "#/tools")}">
    <div class="top">${appIcon(tool)}<div style="min-width:0;flex:1"><div class="name">${r.name}</div>
      <div class="faint" style="font-size:12px">${kindLabel(r.kind)} - ${r.source_type}</div></div>${ring(r.score)}</div>
    <div class="row">${badge(r.status)}${r.level ? badge(r.level) : ""}${r.running ? badge("running", "ok") : ""}
      ${r.health?.ok === false ? badge("down", "bad") : ""}${r.connection?.tested_ok === false ? badge("connection failing", "bad") : ""}
      ${failing ? badge(`${plural(failing, "flow")} failing`, "bad") : ""}</div></a>`;
}

function toolHealthBody(d) {
  if (!d.total) {
    return emptyState("grid", "No tools yet", "Import a GitHub repository, a local project or a SaaS service. A supervisor agent is assigned to each one.",
      html`<button type="button" class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import your first tool</button>`);
  }
  if (!d.rows.length) return none(`All ${plural(d.total, "app")} are healthy.`);
  const more = d.shown > d.rows.length ? html`<p class="faint dash-foot">${d.rows.length} of ${d.shown} shown.</p>` : "";
  return html`<div class="tool-grid">${d.rows.map(toolTile)}</div>${more}`;
}

function toolOverviewBody(d, inst, ctx) {
  const t = d.tool;
  const tool = { id: t.id, name: t.name, running: t.running, manifest: { ui: t.ui || {} } };
  const counted = d.domains.filter((x) => typeof x.count === "number");
  const other = d.domains.filter((x) => typeof x.count !== "number");
  const groups = counted.map((x) => ({ key: x.domain, label: x.label, count: x.count, href: route(x.href) }));
  return html`<div class="dash-tool-head">${appIcon(tool, "sm")}<div class="grow">
      <div class="name"><a href="${route(t.href, "#/tools")}">${t.name}</a></div>
      <div class="row">${badge(t.status)}${t.running ? badge("running", "ok") : ""}${t.health?.ok === false ? badge("down", "bad") : ""}
        ${t.connection?.tested_ok === false ? badge("connection failing", "bad") : ""}</div></div>${ring(t.score, 38)}</div>
    <h4 class="dash-sub">Data it brings</h4>
    ${groups.length ? (ctx.table ? barsTable(groups, { label: "Data" }) : bars(groups, { label: `${t.name}: records by data type` }))
      : !other.length ? none("No data from this tool yet.") : ""}
    ${other.length ? html`<p class="dash-also">${other.map((x, i) => html`${i ? ", " : ""}<a href="${route(x.href, "#/")}">${x.label}</a>`)}</p>` : ""}
    <h4 class="dash-sub">Data flows</h4>
    ${d.flows.length ? html`<ul class="dash-list">${d.flows.map((f) => html`<li>
      <span class="dot ${f.last_result?.ok === false ? "bad" : f.last_result?.ok ? "ok" : ""}"></span>
      <span class="grow clip-1">${f.title}</span>${badge(f.status)}${when(f.last_result?.at)}</li>`)}</ul>` : none("No data flows yet.")}
    ${d.recent.length ? html`<h4 class="dash-sub">Recent activity</h4><div class="feed">${d.recent.map(feedItem)}</div>` : ""}`;
}

function activityBody(d) {
  return d.items.length ? html`<div class="feed">${d.items.map(feedItem)}</div>` : none("Nothing yet.");
}

function agentsBody(d) {
  if (!d.rows.length) return none("No agents in this team.");
  return html`<ul class="dash-list">${d.rows.map((a) => html`<li>
    <span class="dot ${a.status === "working" ? "working" : a.status === "error" ? "bad" : a.paused ? "warn" : "ok"}"></span>
    <div class="grow"><div class="clip-1"><b>${a.name}</b>${a.title && a.title !== a.name ? html` <span class="faint">${a.title}</span>` : ""}</div>
      ${a.provider_label ? html`<div class="faint dash-small clip-1">${a.provider_label}${a.model ? ` - ${a.model}` : ""}</div>` : ""}</div>
    ${a.paused ? badge("paused", "warn") : badge(a.status || "idle", a.status === "working" ? "info" : "")}</li>`)}</ul>`;
}

function approvalsBody(d) {
  const head = html`<p class="dash-count"><b>${d.pending}</b> ${d.pending === 1 ? "decision" : "decisions"} waiting</p>`;
  if (!d.rows.length) return html`${head}${none("Nothing is waiting for a decision.")}`;
  return html`${head}<ul class="dash-list">${d.rows.map((r) => html`<li><a class="dash-row" href="#/approvals">
    ${badge(r.kind.replace(/_/g, " "), "info")}<span class="grow clip-1">${r.title}</span>
    ${r.needs_admin ? badge("admin", "warn") : ""}<span class="faint dash-small clip-1">${r.requested_by}</span>${when(r.created_at)}</a></li>`)}</ul>`;
}

function noteBody(d, inst, ctx) {
  if (!String(d.text || "").trim()) {
    return html`<p class="muted dash-none">This note is empty.${ctx.editable ? html` <button type="button" class="linkish" data-act="w-configure" data-id="${inst.id}">Write it</button>` : ""}</p>`;
  }
  return html`<div class="policy-body dash-note">${md(d.text)}</div>`;
}

function linksBody(d, inst, ctx) {
  if (!d.items.length) {
    return html`<p class="muted dash-none">No links yet.${ctx.editable ? html` <button type="button" class="linkish" data-act="w-configure" data-id="${inst.id}">Add links</button>` : ""}</p>`;
  }
  return html`<ul class="dash-links">${d.items.map((i) => (i.available && route(i.href)
    ? html`<li><a href="${route(i.href)}">${icon(i.icon || "link")}<span>${i.label}</span></a></li>`
    : html`<li class="faint">${icon("alert")}<span>${i.label}</span> <span>(the tool was removed)</span></li>`))}</ul>`;
}

// ---------- renderers of the stage-D3 types ----------

const num = (n) => (typeof n === "number" && Number.isFinite(n) ? n.toLocaleString("en-US") : "-");
const sev = (s) => html`<span class="sev ${SEVERITIES.includes(s) ? s : "info"}">${s}</span>`;
const from = (d) => (d.source_label && d.source_label !== "All sources" ? html` <span class="faint">from ${d.source_label}</span>` : "");

/** A time relative to now, past ("3d ago") or future ("in 3d", a deadline), with the exact time as its title. */
export function relTime(ts, now = Date.now() / 1000) {
  if (typeof ts !== "number") return "";
  const ahead = ts - now;
  if (ahead <= 45) return html`<span class="when" title="${dateTime(ts)}">${timeAgo(ts)}</span>`;
  const text = ahead < 3600 ? `in ${Math.round(ahead / 60)}m` : ahead < 86400 ? `in ${Math.round(ahead / 3600)}h` : `in ${Math.round(ahead / 86400)}d`;
  return html`<span class="when" title="${dateTime(ts)}">${text}</span>`;
}

/** One list cell by its field type; text from tools is only ever escaped text, links are http(s) and open outside. */
export function cellHTML(value, type, now) {
  if (value === null || value === undefined || value === "") return html`<span class="faint">-</span>`;
  switch (type) {
    case "date": return relTime(value, now);
    case "number": return num(value);
    case "bool": return value ? "Yes" : "No";
    case "severity": return sev(value);
    case "enum": return badge(String(value));
    case "link": return /^https?:\/\//i.test(String(value))
      ? html`<a href="${value}" target="_blank" rel="noopener noreferrer">${icon("external")}Open</a>` : html`<span class="faint">-</span>`;
    default: return html`<span class="clip-1" title="${value}">${value}</span>`;
  }
}

function countBody(d, inst, ctx) {
  if (d.view === "number" || !d.group_by) {
    return html`<a class="dash-number" href="${route(d.href, "#/")}" aria-label="${num(d.total)} ${d.noun}${d.source_label && d.source_label !== "All sources" ? ` from ${d.source_label}` : ""}">
      <b>${num(d.total)}</b><span>${d.noun}</span>${d.source_label && d.source_label !== "All sources" ? html`<span class="faint dash-small">from ${d.source_label}</span>` : ""}</a>`;
  }
  const head = html`<p class="dash-count"><b>${num(d.total)}</b> ${d.noun}${from(d)}</p>`;
  const groups = d.groups.map((g) => ({ ...g, href: route(g.href) }));
  const opts = { other: d.other, total: d.total, ordinal: d.ordinal || null, noun: d.noun, href: route(d.href) };
  if (ctx.table) return html`${head}${barsTable(groups, { ...opts, label: d.group_label || "Group" })}`;
  if (d.view === "list") {
    return html`${head}<ul class="dash-list">${groups.map((g) => html`<li><a class="dash-row" href="${g.href || route(d.href, "#/")}">
      ${g.tone ? html`<span class="dash-mark ${g.tone.startsWith("sev-") ? `tone-${g.tone}` : ""}" aria-hidden="true"></span>` : ""}
      <span class="grow clip-1">${g.label}</span><b>${num(g.count)}</b></a></li>`)}
      ${d.other ? html`<li><span class="grow">Other</span><b>${num(d.other)}</b></li>` : ""}</ul>`;
  }
  return html`${head}${bars(groups, { ...opts, label: `${d.domain_label} by ${(d.group_label || "").toLowerCase()}` })}`;
}

function listBody(d, inst, ctx) {
  const head = html`<p class="dash-count"><b>${num(d.total)}</b> ${d.noun}${from(d)}</p>`;
  if (!d.rows?.length) return html`${head}${none("Nothing matches.")}`;
  const cols = d.columns.filter((c) => c.field !== d.title_field);
  const titleLabel = d.columns.find((c) => c.field === d.title_field)?.label || "Name";
  const more = d.total > d.rows.length
    ? html`<p class="faint dash-foot">${d.rows.length} of ${num(d.total)} shown. <a href="${route(d.href, "#/")}">Open ${d.domain_label}</a></p>` : "";
  const title = (r) => html`${r.tone ? html`<span class="dash-mark tone-${r.tone}" aria-hidden="true"></span>` : ""}<a href="${route(r.href, route(d.href, "#/"))}">${r.title}</a>`;
  if (ctx.table || ((inst.w ?? 6) >= 4 && !ctx.stack)) {
    return html`${head}${table([{ label: titleLabel }, ...cols.map((c) => ({ label: c.label, numeric: c.type === "number" }))],
      d.rows.map((r) => [title(r), ...cols.map((c) => cellHTML(r.cells[c.field], c.type, ctx.now))]), { caption: `${d.domain_label}: ${d.noun}` })}${more}`;
  }
  return html`${head}<ul class="dash-list">${d.rows.map((r) => html`<li><div class="grow"><div class="clip-1">${title(r)}</div>
    <div class="faint dash-small dash-cells">${cols.slice(0, 2).map((c, i) => html`${i ? " - " : ""}${c.type === "bool" || c.type === "date" ? `${c.label}: ` : ""}${cellHTML(r.cells[c.field], c.type, ctx.now)}`)}</div></div></li>`)}</ul>${more}`;
}

function timelineBody(d, inst, ctx) {
  const head = html`<p class="dash-count"><b>${num(d.total)}</b> ${d.noun} by ${String(d.date_label || "date").toLowerCase()}, last ${d.days} days${from(d)}</p>`;
  const skipped = d.skipped ? html`<p class="faint dash-foot">${num(d.skipped)} without this date are not counted.</p>` : "";
  if (ctx.table) {
    return html`${head}${table([{ label: "Day (UTC)" }, { label: d.noun[0].toUpperCase() + d.noun.slice(1), numeric: true }],
      (d.buckets || []).filter((b) => b.count).map((b) => [b.day, num(b.count)]), { caption: `${d.domain_label} per day` })}${skipped}`;
  }
  return html`${head}${columns(d.buckets || [], { noun: d.noun, href: route(d.href) })}${skipped}`;
}

function meter(score) {
  const value = typeof score === "number" ? Math.max(0, Math.min(100, score)) : null;
  return html`<span class="dash-meter" aria-hidden="true"><span style="width:${value ?? 0}%"></span></span><b class="dash-pct">${value === null ? "-" : `${value}%`}</b>`;
}

function complianceBody(d, inst, ctx) {
  const parts = [];
  if (d.frameworks.length) {
    parts.push(ctx.table
      ? table([{ label: "Framework" }, { label: "Score", numeric: true }, { label: "Passing", numeric: true }, { label: "Failing", numeric: true }],
        d.frameworks.map((f) => [html`<a href="${route(f.href, "#/compliance")}">${f.name}</a>`, f.score === null ? "-" : `${f.score}%`, num(f.passing), num(f.failing)]))
      : html`<ul class="dash-list">${d.frameworks.map((f) => html`<li><a class="dash-row" href="${route(f.href, "#/compliance")}"
          aria-label="${f.name}: ${f.score === null ? "no score yet" : `${f.score}%`}, ${f.passing} of ${f.total} controls passing">
          <span class="grow clip-1">${f.name}</span>${meter(f.score)}</a></li>`)}</ul>`);
  }
  if (d.cyfun) {
    const c = d.cyfun;
    const tone = c.verdict === "met" ? "ok" : c.verdict === "not_met" ? "bad" : "warn";
    parts.push(html`<h4 class="dash-sub">Latest self-assessment</h4><a class="dash-row" href="${route(c.href, "#/compliance/frameworks")}">
      <span class="grow clip-1"><b>${c.name}</b> <span class="faint">${c.framework_name}, ${c.target_name}</span></span>
      ${badge(String(c.verdict).replace(/_/g, " "), tone)}<span class="faint dash-small">${c.progress?.scored ?? 0} of ${c.progress?.total ?? 0} scored</span></a>`);
  }
  if (d.external.length) {
    parts.push(html`<h4 class="dash-sub">From your GRC tools</h4><ul class="dash-list">${d.external.map((f) => html`<li><a class="dash-row" href="${route(f.href, "#/compliance/frameworks")}">
      <span class="grow clip-1">${f.name} <span class="faint">${f.source_tool}</span></span>
      ${f.score !== null && f.score !== undefined ? meter(f.score) : html`<span class="faint dash-small">${f.assessments ? "not rated" : "no assessment"}</span>`}</a></li>`)}</ul>`);
  }
  return parts.length ? parts : none(d.evaluated ? "No frameworks to show." : "The controls have not been evaluated yet.");
}

const CONTROL_ORDER = ["fail", "partial", "manual", "pass", "na"];
const CONTROL_LABELS = { fail: "fail", partial: "partial", manual: "to check", pass: "pass", na: "n/a" };

function controlsBody(d) {
  const chips = html`<p class="dash-chips-static">${CONTROL_ORDER.filter((k) => d.counts?.[k]).map((k) => html`${badge(`${d.counts[k]} ${CONTROL_LABELS[k]}`, k === "fail" ? "bad" : k === "partial" ? "warn" : k === "pass" ? "ok" : "")} `)}</p>`;
  if (!d.rows.length) return html`${chips}${none("No controls with this status.")}`;
  return html`${chips}<ul class="dash-list">${d.rows.map((r) => html`<li><a class="dash-row" href="#/compliance/controls" title="${r.detail}">
    ${badge(r.status)}<span class="faint dash-small">${r.id}</span><span class="grow clip-1">${r.title}</span></a></li>`)}</ul>
    ${d.total > d.rows.length ? html`<p class="faint dash-foot">${d.rows.length} of ${d.total} shown.</p>` : ""}`;
}

function riskMatrixBody(d, inst, ctx) {
  const head = html`<p class="dash-count"><b>${num(d.total)}</b> ${d.total === 1 ? "risk" : "risks"}${from(d)}</p>`;
  return html`${head}${ctx.table ? matrixTable(d.cells) : matrix(d.cells, { href: route(d.href) })}`;
}

function slaBody(d) {
  const kpi = (label, value, tone = "") => html`<div class="dash-kpi ${tone}"><b>${value}</b><span>${label}</span></div>`;
  const coverage = d.in_scope_assets
    ? html`<p class="faint dash-foot">Scan coverage: ${num(d.scanned_last_30_days)} of ${plural(d.in_scope_assets, "in-scope asset")} scanned in the last 30 days.</p>`
    : html`<p class="faint dash-foot">No assets are in scan scope.</p>`;
  return html`<div class="dash-kpis">${kpi("open", num(d.open))}${kpi("past deadline", num(d.overdue), d.overdue ? "bad" : "")}
      ${kpi("fixed (30 days)", num(d.fixed_last_30_days))}</div>
    ${table([{ label: "Severity" }, { label: "Open", numeric: true }, { label: "Overdue", numeric: true }, { label: "Deadline", numeric: true }],
      SEVERITIES.map((s) => [sev(s), num(d.by_severity?.[s] ?? 0), num(d.overdue_by_severity?.[s] ?? 0), d.sla_days?.[s] ? `${d.sla_days[s]} days` : "-"]),
      { caption: "Open findings and deadlines by severity" })}${coverage}`;
}

function networkBody(d, inst, ctx) {
  const waiting = (d.changes?.proposed || 0) + (d.changes?.scheduled || 0) + (d.changes?.verifying || 0);
  const head = html`<p class="dash-chips-static">${badge(`${d.drift.open} drift open`, d.drift.critical_open ? "bad" : d.drift.open ? "warn" : "ok")}
    ${waiting ? badge(`${waiting} ${waiting === 1 ? "change" : "changes"} waiting`, "info") : ""}
    ${badge(d.device_changes_on ? "device changes on" : "device changes off", d.device_changes_on ? "warn" : "")}</p>`;
  if (!d.devices.length) return html`${head}${none("No firewall or network device is connected.")}`;
  return html`${head}<ul class="dash-list">${d.devices.map((v) => html`<li><a class="dash-row" href="${route(v.href, "#/network")}">
    <span class="dot ${v.connection === "failing" ? "bad" : v.stale ? "warn" : "ok"}" aria-hidden="true"></span>
    <span class="grow clip-1"><b>${v.name}</b>${v.product ? html` <span class="faint">${v.product}</span>` : ""}</span>
    ${v.stale ? badge("out of date", "warn") : ""}${v.open_drift ? badge(`${v.open_drift} drift`, v.critical_drift ? "bad" : "warn") : ""}
    ${relTime(v.snapshot_at, ctx.now)}</a></li>`)}</ul>`;
}

function leaversBody(d) {
  if (!d.total) return none("Nobody who left still holds anything.");
  const holds = (h) => [h.assets ? plural(h.assets, "asset") : "", h.accounts ? plural(h.accounts, "account") : "",
    h.atrium_account ? "an Atrium sign-in" : ""].filter(Boolean).join(", ");
  return html`<p class="dash-count"><b>${num(d.total)}</b> ${d.total === 1 ? "leaver still holds" : "leavers still hold"} something</p>
    <ul class="dash-list">${d.rows.map((r) => html`<li><a class="dash-row" href="${route(r.href, "#/people/leavers")}">
      <span class="dot ${r.severity === "fail" ? "bad" : "warn"}" aria-hidden="true"></span>
      <span class="grow clip-1"><b>${r.display_name}</b> <span class="faint">${holds(r.holds)}</span></span>${badge(r.status)}</a></li>`)}</ul>
    ${d.total > d.rows.length ? html`<p class="faint dash-foot">${d.rows.length} of ${d.total} shown.</p>` : ""}`;
}

// ---------- renderers of the stage-D4 settings widgets (ai_models is in aimodels.js) ----------

const AUTONOMY = {
  manual: ["Manual", "ok", "Every agent command and patch waits for approval."],
  assisted: ["Assisted", "ok", "Read-only commands run; changes wait for approval."],
  autonomous: ["Autonomous", "bad", "Agents act without asking, except blocked commands."],
};
const GUARD_GROUPS = { teams: "Agent teams", agents: "Agent actions", commands: "Commands", scans: "Vulnerability scans",
  extensions: "Extensions", self_patching: "Self-patching", models: "AI models and spending", network: "Network changes" };

function safetyBody(d) {
  const [level, tone, text] = AUTONOMY[d.autonomy] || [d.autonomy, "", ""];
  const relaxed = d.relaxed || [];
  const chips = html`<p class="dash-chips-static">
    ${badge(d.device_changes_on ? "device changes on" : "device changes off", d.device_changes_on ? "warn" : "")}
    ${badge(d.cloud_ai ? "cloud AI allowed" : "cloud AI blocked", d.cloud_ai ? "" : "ok")}
    ${badge(d.spend_limit != null ? `AI spending cap $${d.spend_limit}/day` : "no AI spending cap", d.spend_limit != null ? "" : "warn")}</p>`;
  return html`<div class="dash-kpis"><div class="dash-kpi ${tone === "bad" ? "bad" : ""}"><b>${level}</b><span>autonomy</span></div>
      <div class="dash-kpi ${relaxed.length ? "warn" : ""}"><b>${relaxed.length}</b><span>${relaxed.length === 1 ? "guardrail relaxed" : "guardrails relaxed"}</span></div></div>
    <p class="faint dash-small">${text}</p>${chips}
    ${relaxed.length ? html`<ul class="dash-list">${relaxed.map((g) => html`<li><span class="dot warn" aria-hidden="true"></span>
        <span class="grow clip-1" title="${g.title}">${g.title}</span><span class="faint dash-small">${GUARD_GROUPS[g.group] || g.group}</span>
        ${g.control ? badge(g.control) : ""}</li>`)}</ul>
      ${d.controls_affected?.length ? html`<p class="faint dash-foot">Weakens compliance ${d.controls_affected.length === 1 ? "control" : "controls"} ${d.controls_affected.join(", ")}.</p>` : ""}`
      : none(`All ${d.total_guardrails} guardrails are at their safe setting.`)}`;
}

function accountsBody(d, inst, ctx) {
  const r = d.by_role || {};
  const kpi = (label, value, tone = "") => html`<div class="dash-kpi ${tone}"><b>${num(value)}</b><span>${label}</span></div>`;
  return html`<div class="dash-kpis">${kpi(r.admin === 1 ? "admin" : "admins", r.admin)}${kpi(r.operator === 1 ? "operator" : "operators", r.operator)}
      ${kpi(r.viewer === 1 ? "viewer" : "viewers", r.viewer)}</div>
    <p class="dash-chips-static">${badge(`${num(d.tokens_active)} API ${d.tokens_active === 1 ? "token" : "tokens"} active`)}
      ${d.disabled ? badge(`${num(d.disabled)} disabled`) : ""}
      ${badge(d.dormant_total ? `${num(d.dormant_total)} dormant` : "none dormant", d.dormant_total ? "warn" : "ok")}</p>
    ${d.dormant_total ? html`<h4 class="dash-sub">No sign-in for 90 days</h4><ul class="dash-list">${d.dormant_90d.map((u) => html`<li>
        <span class="grow clip-1"><b>${u.username}</b></span><span class="faint dash-small">${u.last_seen ? html`last ${relTime(u.last_seen, ctx.now)}` : "never signed in"}</span></li>`)}</ul>
      ${d.dormant_total > d.dormant_90d.length ? html`<p class="faint dash-foot">${d.dormant_90d.length} of ${d.dormant_total} shown.</p>` : ""}` : ""}`;
}

/** A declared widget: drawn by the widget it compiles to, with who suggested it. */
function declaredBody(d, inst, ctx) {
  const r = RENDERERS[d.compiled];
  if (!r || d.compiled === "declared") return none("This page cannot show this kind of widget yet.");
  const by = d.declared_by ? html`<p class="faint dash-small dash-by">${d.declared_by.kind === "tool" ? "Suggested by" : "From"} ${d.declared_by.name}</p>` : "";
  return html`${r.body(d, inst, ctx)}${by}`;
}

/**
 * Renderers by widget type: body(data, inst, ctx) -> html``; optional link(data) -> {href, text} for the header,
 * chart (has a table view), ownEmpty (renders its own empty state), summary(data) -> text for the configure preview.
 */
export const RENDERERS = {
  metric: { body: metricBody, compact: true, summary: (d) => `${d.label}: ${d.value ?? "-"}${d.unit || ""}` },
  tool_health: { body: toolHealthBody, ownEmpty: true, link: (d) => ({ href: route(d.href, "#/tools"), text: "All apps" }),
    summary: (d) => (d.total ? `${plural(d.rows.length, "app")} shown of ${d.total}` : "No tools yet") },
  tool_overview: { body: toolOverviewBody, chart: true, link: (d) => ({ href: route(d.href, "#/tools"), text: "Open app" }),
    summary: (d) => `${d.tool.name}: ${plural(d.domains.length, "data type")}, ${plural(d.flows.length, "data flow")}` },
  agent_activity: { body: activityBody, link: () => ({ href: "#/agents", text: "Agents" }), summary: (d) => plural(d.items.length, "entry", "entries") },
  agents_status: { body: agentsBody, link: () => ({ href: "#/agents", text: "Agents" }), summary: (d) => plural(d.rows.length, "agent") },
  approvals_queue: { body: approvalsBody, link: () => ({ href: "#/approvals", text: "Approvals" }), summary: (d) => `${d.pending} waiting` },
  note: { body: noteBody, summary: (d) => (String(d.text || "").trim() ? "Note" : "Empty note") },
  links: { body: linksBody, summary: (d) => plural(d.items.length, "link") },
  domain_count: { body: countBody, chart: true, link: (d) => ({ href: route(d.href, "#/"), text: d.domain_label }),
    summary: (d) => `${num(d.total)} ${d.noun}` },
  domain_list: { body: listBody, link: (d) => ({ href: route(d.href, "#/"), text: d.domain_label }),
    summary: (d) => `${num(d.total)} ${d.noun}, ${plural(d.rows.length, "row")} shown` },
  domain_timeline: { body: timelineBody, chart: true, link: (d) => ({ href: route(d.href, "#/"), text: d.domain_label }),
    summary: (d) => `${num(d.total)} ${d.noun} in ${d.days} days` },
  compliance_overview: { body: complianceBody, chart: true, link: () => ({ href: "#/compliance", text: "Compliance" }),
    summary: (d) => `${plural(d.frameworks.length + d.external.length, "framework")}` },
  controls_status: { body: controlsBody, link: () => ({ href: "#/compliance/controls", text: "Controls" }),
    summary: (d) => `${plural(d.total, "control")}` },
  risk_matrix: { body: riskMatrixBody, chart: true, link: () => ({ href: "#/compliance/risks", text: "Risks" }),
    summary: (d) => plural(d.total, "risk") },
  vuln_sla: { body: slaBody, link: (d) => ({ href: route(d.href, "#/vulnerabilities"), text: "Vulnerabilities" }),
    summary: (d) => `${num(d.open)} open, ${num(d.overdue)} past their deadline` },
  network_overview: { body: networkBody, link: () => ({ href: "#/network", text: "Network" }), summary: (d) => plural(d.devices.length, "device") },
  leavers: { body: leaversBody, link: () => ({ href: "#/people/leavers", text: "Leavers" }), summary: (d) => plural(d.total, "leaver") },
  ai_models: { body: aiModelsBody, link: () => ({ href: "#/settings/ai", text: "AI settings" }), summary: aiModelsSummary },
  safety_settings: { body: safetyBody, link: (d) => ({ href: route(d.href, "#/settings"), text: "Open Settings" }),
    summary: (d) => `${(AUTONOMY[d.autonomy] || [d.autonomy])[0]} autonomy, ${plural((d.relaxed || []).length, "guardrail")} relaxed` },
  hub_accounts: { body: accountsBody, link: (d) => ({ href: route(d.href, "#/users"), text: "Users & access" }),
    summary: (d) => `${plural(d.total ?? 0, "account")}, ${num(d.dormant_total ?? 0)} dormant` },
  declared: { body: declaredBody, chart: true, link: (d) => RENDERERS[d.compiled]?.link?.(d) ?? null,
    summary: (d) => RENDERERS[d.compiled]?.summary?.(d) ?? "Declared widget" },
};

const STATE_ICONS = { forbidden: "lock", unavailable: "alert", disabled: "pause", error: "alert" };

/** The body of a widget for its WidgetResult (undefined while loading). */
export function widgetBody(result, inst, ctx = {}) {
  if (!result) return html`<div class="dash-skel" aria-hidden="true"><i></i><i></i><i></i></div><span class="sr-only">Loading</span>`;
  const r = RENDERERS[inst.type];
  const { status } = result;
  if ((status === "ok" || status === "empty") && result.data) {
    if (!r) return none("This page cannot show this kind of widget yet.");
    const hint = status === "empty" && result.hint && !r.ownEmpty && route(result.hint.href)
      ? html`<p class="dash-hint"><a href="${route(result.hint.href)}" ${result.hint.min_role ? html`data-min-role="${result.hint.min_role}"` : ""}>${result.hint.text}</a></p>` : "";
    return html`${r.body(result.data, inst, ctx)}${hint}`;
  }
  const edit = ctx.editing && ctx.editable;
  const remove = edit ? html`<button type="button" class="btn sm" data-act="w-remove" data-id="${inst.id}">${icon("trash")}Remove widget</button>` : "";
  const msg = result.message || "";
  if (status === "forbidden") return html`<div class="dash-state">${icon("lock")}<p>${msg || "Needs a higher role."}</p>${remove}</div>`;
  if (status === "unavailable") {
    const again = edit ? html`<button type="button" class="btn sm" data-act="w-configure" data-id="${inst.id}">${icon("sliders")}${result.code === "tool_removed" ? "Choose another tool" : "Configure"}</button>` : "";
    return html`<div class="dash-state">${icon("alert")}<p>${msg || "This widget is not available."}</p>${remove || again ? html`<div class="row">${remove}${again}</div>` : ""}</div>`;
  }
  if (status === "disabled") return html`<div class="dash-state">${icon(STATE_ICONS.disabled)}<p>${msg}</p></div>`;
  return html`<div class="dash-state">${icon("alert")}<p>Could not load this widget.</p>
    ${msg ? html`<p class="faint dash-small">${msg}</p>` : ""}<button type="button" class="btn sm" data-act="w-retry" data-id="${inst.id}">${icon("refresh")}Retry</button></div>`;
}

/** The header link of a widget for its result ("All apps", "Agents"), or "". */
export function widgetLink(result, inst) {
  const r = RENDERERS[inst.type];
  const link = result?.data && r?.link ? r.link(result.data) : null;
  return link?.href ? html`<a href="${link.href}">${link.text} &rarr;</a>` : "";
}

/** The "Updated 12m ago" chip of a widget whose data is older than its stale_after (a button that refreshes it). */
export function staleChip(result, inst, now) {
  if (!result?.stale_after || now <= result.stale_after) return "";
  return html`<button type="button" class="dash-stale" data-act="w-retry" data-id="${inst.id}" title="Refresh">${icon("clock")}Updated ${timeAgo(result.generated_at)}</button>`;
}

/** What a preview shows in its live summary ("Preview: 3 agents"). */
export function summary(result, inst) {
  if (!result) return "Loading the preview";
  if (result.status === "ok" || result.status === "empty") {
    const text = RENDERERS[inst.type]?.summary?.(result.data);
    return `Preview: ${text || "ready"}`;
  }
  return `Preview: ${result.message || result.status}`;
}

/** The title a widget shows: its own, the server's default, the type's. */
export const widgetTitle = (inst, typeTitle = "Widget") => inst.title || inst.default_title || typeTitle;

/** A widget frame (10.3, 10.6): in edit mode the move handle, the content, the options button and the resize handle,
 *  in that tab order. Its position is the CSS variables --x, --y, --w, --h of the 12-column grid. */
export function frameHTML(inst, { title, editing = false, body = null } = {}) {
  const tid = `w-${inst.id}-title`;
  const compact = RENDERERS[inst.type]?.compact;
  return html`<article class="widget t-${inst.type} ${compact ? "compact" : ""}" id="w-${inst.id}" data-wid="${inst.id}" aria-labelledby="${tid}"
      style="--x:${inst.x};--y:${inst.y};--w:${inst.w};--h:${inst.h}">
    <header class="widget-head">
      ${editing ? html`<button type="button" class="dash-handle" data-act="w-handle" data-id="${inst.id}" aria-label="Move ${title}" aria-describedby="dash-move-help">${icon("grip")}</button>` : ""}
      <h3 id="${tid}" class="${compact ? "sr-only" : ""}" tabindex="-1">${title}</h3>
      <span class="widget-status" data-part="status"></span>
      <span class="widget-link" data-part="link"></span>
    </header>
    <div class="widget-body" data-part="body">${body ?? widgetBody(undefined, inst)}</div>
    <button type="button" class="icon-btn sm widget-menu-btn" data-act="w-menu" data-id="${inst.id}" aria-label="Options for ${title}" aria-haspopup="true" aria-expanded="false">${icon("more")}</button>
    ${editing ? html`<button type="button" class="dash-resize" data-act="w-resize" data-id="${inst.id}" aria-label="Resize ${title}" aria-describedby="dash-resize-help">${icon("resize")}</button>` : ""}
  </article>`;
}
