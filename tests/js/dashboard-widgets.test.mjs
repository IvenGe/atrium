// Dashboard widget renderers and charts (hub/web/js/dashboard/widgets.js, charts.js): untrusted text is escaped,
// breakdowns keep severity order, every bar has a full accessible name, tables have header scopes, the frame keeps the
// edit-mode tab order and every state renders.
import assert from "node:assert/strict";
import { test } from "node:test";
import { barRows, bars, barsTable, columns, isOrdinal, matrix, matrixTable, riskBand, table } from "../../hub/web/js/dashboard/charts.js";
import { RENDERERS, feedItem, frameHTML, route, staleChip, summary, toolCard, widgetBody, widgetLink, widgetTitle } from "../../hub/web/js/dashboard/widgets.js";

const EVIL = `<img src=x onerror="alert(1)">`;
const s = (x) => String(x);
const inst = (type, extra = {}) => ({ id: "w_abcdefgh12", type, x: 0, y: 0, w: 4, h: 3, title: null, config: {}, ...extra });
const ok = (data, extra = {}) => ({ status: "ok", data, code: null, message: null, hint: null, version: "v1", generated_at: 1000, stale_after: 2000, ...extra });
const safe = (out, label) => {
  assert.doesNotMatch(out, /<img/i, label);
  assert.doesNotMatch(out, /onerror="/i, label);
};

const toolRow = {
  id: "evil", name: EVIL, source_type: EVIL, ui: { icon: EVIL, color: "red;position:fixed" }, kind: "oss", status: "ready", running: true,
  health: { ok: false, checked_at: 1 }, connection: { kind: "rest", tested_ok: false, tested_at: 1 }, flows: { enabled: 2, failing: 1, last_run: 1 },
  score: 80, level: "native", href: "#/tools/evil", portal_href: null,
};
const SAMPLES = {
  metric: { key: "tools", value: 3, unit: null, label: EVIL, sub: EVIL, href: "#/tools", icon: "grid", tone: "warn" },
  tool_health: { rows: [toolRow], total: 1, shown: 1, href: "#/tools" },
  tool_overview: {
    tool: toolRow, href: "#/tools/evil",
    domains: [{ domain: "assets", label: EVIL, count: 4, href: "#/assets" }, { domain: "network", label: EVIL, count: null, href: "#/network/evil" }],
    flows: [{ id: "f1", title: EVIL, domain: "assets", direction: "in", status: "enabled", last_result: { ok: false, at: 1 } }],
    recent: [{ seq: 1, ts: 1, actor: EVIL, level: "warn", text: EVIL }],
  },
  agent_activity: { items: [{ seq: 1, ts: 1, actor: EVIL, level: "error", text: EVIL }], href: "#/agents" },
  agents_status: { rows: [{ id: "a", name: EVIL, title: EVIL, team: EVIL, kind: "core", status: "working", paused: false, provider_label: EVIL, model: EVIL }], total: 1 },
  approvals_queue: { pending: 1, href: "#/approvals", rows: [{ id: "x", kind: "command", title: EVIL, requested_by: EVIL, created_at: 1, needs_admin: true }] },
  note: { text: `# ${EVIL}\n- ${EVIL}` },
  links: { items: [{ label: EVIL, href: "#/assets", icon: "box", available: true }, { label: EVIL, href: null, icon: "external", available: false }] },
};

test("every renderer escapes untrusted text in titles, cells, labels and names", () => {
  for (const [type, data] of Object.entries(SAMPLES)) {
    for (const table of [false, true]) {
      const out = s(widgetBody(ok(data), inst(type, { title: EVIL }), { editing: true, editable: true, table }));
      safe(out, type);
      assert.match(out, /&lt;img/, `${type} shows the text, escaped`);
    }
    safe(s(frameHTML(inst(type), { title: EVIL, editing: true })), `${type} frame`);
  }
  safe(s(toolCard({ id: "t", name: EVIL, source_type: EVIL, status: "ready", manifest: { kind: "saas", ui: { icon: EVIL } } })), "toolCard");
  safe(s(feedItem({ actor: EVIL, text: EVIL, level: "info", ts: 1 })), "feedItem");
  safe(s(bars([{ key: EVIL, label: EVIL, count: 2, href: "#/x" }])), "bars");
  safe(s(barsTable([{ key: EVIL, label: EVIL, count: 2 }], { label: EVIL })), "barsTable");
  safe(s(table([{ label: EVIL }], [[EVIL]])), "table");
  safe(s(columns([{ day: EVIL, count: 1 }], { href: "#/x" })), "columns");
});

test("a metric tile is one link with its tone as a class and the subtext as its explanation", () => {
  const out = s(widgetBody(ok(SAMPLES.metric), inst("metric"), {}));
  assert.equal((out.match(/<a /g) || []).length, 1);
  assert.match(out, /class="card stat dash-stat tone-warn" href="#\/tools"/);
  assert.match(widgetBody(ok({ ...SAMPLES.metric, value: null, tone: "red" }), inst("metric"), {}).toString(), /class="value">-</);
  const titled = s(widgetBody(ok({ ...SAMPLES.metric, label: "Apps integrated" }), inst("metric", { title: "My apps" }), {}));
  assert.match(titled, /class="label">My apps</, "a title override replaces the label");
});

test("links from widget data are internal routes only", () => {
  assert.equal(route("#/assets/a%20b"), "#/assets/a%20b");
  for (const bad of ["javascript:alert(1)", "https://evil.example/", "//evil.example", "#/x\" onmouseover=\"y", null, 3]) assert.equal(route(bad), null, String(bad));
  const out = s(widgetBody(ok({ ...SAMPLES.metric, href: "javascript:alert(1)" }), inst("metric"), {}));
  assert.doesNotMatch(out, /javascript:/);
  const links = s(widgetBody(ok({ items: [{ label: "x", href: "javascript:alert(1)", icon: "link", available: true }] }), inst("links"), {}));
  assert.doesNotMatch(links, /javascript:/);
  assert.doesNotMatch(s(widgetLink(ok({ ...SAMPLES.tool_health, href: "https://evil.example" }), inst("tool_health"))), /evil/);
});

test("breakdowns keep severity order and sort other keys by count, with Other last", () => {
  const sev = [{ key: "critical", count: 1 }, { key: "high", count: 9 }, { key: "medium", count: 4 }, { key: "low", count: 0 }];
  assert.ok(isOrdinal(sev));
  assert.deepEqual(barRows(sev).map((r) => r.key), ["critical", "high", "medium", "low"]);
  const types = [{ key: "laptop", count: 2 }, { key: "server", count: 7 }, { key: "phone", count: 5 }];
  assert.ok(!isOrdinal(types));
  assert.deepEqual(barRows(types, { other: 3 }).map((r) => r.key), ["server", "phone", "laptop", "__other"]);
  const out = s(bars(sev, { noun: "open findings" }));
  const order = [...out.matchAll(/aria-label="(\w+):/g)].map((m) => m[1]);
  assert.deepEqual(order, ["critical", "high", "medium", "low"]);
});

test("every bar, column and matrix cell has an accessible name with its label, count and share", () => {
  const out = s(bars([{ key: "high", label: "High", count: 12, tone: "sev-high", href: "#/vulnerabilities" }, { key: "low", label: "Low", count: 28 }],
    { noun: "open findings", href: "#/vulnerabilities" }));
  assert.match(out, /<a class="bar-row" href="#\/vulnerabilities" aria-label="High: 12 open findings, 30%">/);
  assert.match(out, /aria-label="Low: 28 open findings, 70%"/);
  assert.match(out, /class="bar-fill tone-sev-high"/, "severity uses its reserved token");
  assert.match(out, /class="bar-label">High</, "the text label is always shown");
  const plain = s(bars([{ key: "a", label: "A", count: 1 }]));
  assert.match(plain, /role="img" aria-label="A: 1 records, 100%"/, "without a link the row is still named");
  assert.match(s(columns([{ day: "2026-10-01", count: 3 }, { day: "2026-10-02", count: 1 }])), /aria-label="2026-10-01: 3 records, 75%"/);
  const cells = Array.from({ length: 5 }, () => [0, 0, 0, 0, 0]);
  cells[4][4] = 2;
  const mx = s(matrix(cells, { href: "#/compliance/risks" }));
  assert.match(mx, /aria-label="Likelihood 5, impact 5: 2 risks \(critical\)"/);
  assert.equal((mx.match(/class="mx-cell/g) || []).length, 25);
  assert.deepEqual([riskBand(25), riskBand(10), riskBand(6), riskBand(4)], ["critical", "high", "medium", "low"]);
});

test("table views have column and row header scopes", () => {
  const t = s(barsTable([{ key: "a", label: "A", count: 3 }], { label: "Type", noun: "assets" }));
  assert.match(t, /<th scope="col" class="">Type<\/th>/);
  assert.match(t, /<th scope="col" class="num">Assets<\/th>/);
  assert.match(t, /<th scope="row">A<\/th><td class="num">3<\/td><td class="num">100%<\/td>/);
  const cells = Array.from({ length: 5 }, () => [0, 0, 0, 0, 0]);
  cells[1][2] = 4;
  assert.match(s(matrixTable(cells)), /<th scope="row">Likelihood 2, impact 3<\/th><td class="num">4<\/td><td class="">medium<\/td>/);
  const overview = s(widgetBody(ok(SAMPLES.tool_overview), inst("tool_overview"), { table: true }));
  assert.match(overview, /<table/);
  assert.ok(RENDERERS.tool_overview.chart);
});

test("the frame keeps the edit-mode tab order: move handle, content, options, resize handle", () => {
  const out = s(frameHTML(inst("tool_health"), { title: "Apps", editing: true, body: "BODY" }));
  const pos = (needle) => out.indexOf(needle);
  assert.ok(pos('data-act="w-handle"') < pos("BODY"));
  assert.ok(pos("BODY") < pos('data-act="w-menu"'));
  assert.ok(pos('data-act="w-menu"') < pos('data-act="w-resize"'));
  assert.match(out, /aria-label="Move Apps" aria-describedby="dash-move-help"/);
  assert.match(out, /aria-label="Resize Apps"/);
  assert.match(out, /aria-labelledby="w-w_abcdefgh12-title"/);
  assert.match(out, /style="--x:0;--y:0;--w:4;--h:3"/);
  const view = s(frameHTML(inst("tool_health"), { title: "Apps" }));
  assert.doesNotMatch(view, /w-handle|w-resize/, "no drag handles in view mode");
  assert.match(s(frameHTML(inst("metric"), { title: "Apps" })), /class="sr-only" tabindex="-1">Apps</, "a KPI tile keeps its heading for screen readers");
});

test("states: loading, empty with a role-gated hint, error, forbidden, unavailable, disabled and stale", () => {
  assert.match(s(widgetBody(undefined, inst("metric"))), /dash-skel/);
  const empty = s(widgetBody({ status: "empty", data: { items: [] }, hint: { text: "Set up a data flow", href: "#/tools/openvas/connection", min_role: "admin" } }, inst("agent_activity")));
  assert.match(empty, /<a href="#\/tools\/openvas\/connection" data-min-role="admin">Set up a data flow<\/a>/);
  const noTools = s(widgetBody({ status: "empty", data: { rows: [], total: 0, shown: 0 }, hint: { text: "Import your first tool", href: "#/tools", min_role: "operator" } }, inst("tool_health")));
  assert.match(noTools, /No tools yet/);
  assert.match(noTools, /data-act="import" data-min-role="operator"/);
  assert.doesNotMatch(noTools, /dash-hint/, "the type shows its own empty state");
  const err = s(widgetBody({ status: "error", message: "Could not compute this widget." }, inst("metric")));
  assert.match(err, /Could not load this widget/);
  assert.match(err, /data-act="w-retry"/);
  const forbidden = { status: "forbidden", message: "Needs the admin role." };
  assert.match(s(widgetBody(forbidden, inst("metric"))), /Needs the admin role/);
  assert.doesNotMatch(s(widgetBody(forbidden, inst("metric"))), /w-remove/);
  assert.match(s(widgetBody(forbidden, inst("metric"), { editing: true, editable: true })), /data-act="w-remove"/);
  const gone = { status: "unavailable", code: "tool_removed", message: "openvas was removed." };
  const edit = s(widgetBody(gone, inst("tool_overview"), { editing: true, editable: true }));
  assert.match(edit, /openvas was removed/);
  assert.match(edit, /Remove widget/);
  assert.match(edit, /Choose another tool/);
  assert.match(s(widgetBody({ status: "disabled", message: "Switched off." }, inst("metric"))), /Switched off/);
  assert.match(s(widgetBody(ok({ x: 1 }), inst("no_such_type"))), /cannot show this kind of widget yet/);
  assert.equal(staleChip(ok({}), inst("metric"), 1500), "");
  assert.match(s(staleChip(ok({}), inst("metric"), 2500)), /class="dash-stale" data-act="w-retry"/);
});

test("summaries, header links and titles", () => {
  assert.equal(summary(ok(SAMPLES.agents_status), inst("agents_status")), "Preview: 1 agent");
  assert.equal(summary(ok({ ...SAMPLES.metric, label: "Assets", value: 42 }), inst("metric")), "Preview: Assets: 42");
  assert.equal(summary({ status: "unavailable", message: "Gone." }, inst("metric")), "Preview: Gone.");
  assert.match(s(widgetLink(ok(SAMPLES.tool_health), inst("tool_health"))), /<a href="#\/tools">All apps &rarr;<\/a>/);
  assert.equal(widgetLink(ok(SAMPLES.note), inst("note")), "");
  assert.equal(widgetTitle(inst("metric", { title: "Mine", default_title: "Apps" })), "Mine");
  assert.equal(widgetTitle(inst("metric", { default_title: "Apps" })), "Apps");
  assert.equal(widgetTitle(inst("metric"), "Metric"), "Metric");
});

test("the gallery: per-tool suggestions under 'From your tools', hub ones by category, one card per type; search", async () => {
  const { galleryEntries, filterEntries } = await import("../../hub/web/js/dashboard/gallery.js");
  const { defaultTitle } = await import("../../hub/web/js/dashboard/configure.js");
  const type = (key, category) => ({ key, title: key.toUpperCase(), description: `${key} widget`, category, size: { min: { w: 1, h: 1 }, default: { w: 3, h: 2 }, max: { w: 12, h: 8 } } });
  const catalog = {
    types: [type("metric", "overview"), type("note", "notes"), type("tool_overview", "tools"), type("tool_page", "embedded")],
    metrics: [{ key: "assets", label: "Assets" }],
    tools: [{ id: "snipe", name: "Snipe-IT", ui: {} }],
    suggestions: [
      { id: "sg:1", group: "tool:snipe", type: "tool_overview", config: { tool_id: "snipe" }, title: "Snipe-IT: overview", description: "", size: [4, 3] },
      { id: "sg:2", group: "hub", type: "metric", config: { metric: "assets" }, title: "Assets", description: "Assets in the register", size: [3, 1] },
      { id: "sg:3", group: "hub", type: "note", config: { text: "" }, title: "Note", description: "", size: [4, 2] },
      { id: "sg:4", group: "tool:gone", type: "nope", config: {}, title: "x", description: "", size: [1, 1] },
    ],
  };
  const entries = galleryEntries(catalog);
  assert.deepEqual(entries.filter((e) => e.kind === "suggestion").map((e) => [e.key, e.category]), [["sg:1", "mine"], ["sg:2", "overview"]],
    "a hub note would be empty (its own card asks for the text); unknown types are left out");
  assert.deepEqual(entries.filter((e) => e.kind === "type").map((e) => e.type), ["metric", "note", "tool_overview"], "no tool_page card: stage D5 is not built");
  assert.equal(entries.find((e) => e.key === "sg:1").tool.name, "Snipe-IT");
  assert.deepEqual(filterEntries(entries, { query: "snipe" }).map((e) => e.key), ["sg:1"], "the tool's name matches");
  assert.deepEqual(filterEntries(entries, { category: "notes" }).map((e) => e.key), ["type:note"]);
  assert.equal(defaultTitle(catalog, { type: "metric", config: { metric: "assets" } }), "Assets");
  assert.equal(defaultTitle(catalog, { type: "note", config: {} }), "NOTE");
  assert.equal(defaultTitle(catalog, { type: "metric", config: {}, default_title: "From the server" }), "From the server");
});

// ---------- stage D3: record, compliance, network, people and declared widgets ----------

const NOW = 1_700_000_000;
const D3 = {
  domain_count: { domain: "x:alerts", domain_label: EVIL, noun: "alerts", icon: "puzzle", source: "tool:siem", source_label: EVIL, href: "#/x/alerts",
    view: "bars", total: 5, group_by: "severity", group_label: "Severity", ordinal: true, other: 0,
    groups: [{ key: "low", label: "low", count: 3, tone: "sev-low", href: "#/x/alerts" }, { key: "critical", label: "critical", count: 2, tone: "sev-critical", href: "#/x/alerts" }] },
  domain_list: { domain: "x:alerts", domain_label: "Alerts", noun: "alerts", source: "all", source_label: "All sources", href: "#/x/alerts", total: 9,
    sort: "detected", order: "desc", title_field: "title",
    columns: [{ field: "title", label: "Title", type: "text" }, { field: "host", label: "Host", type: "text" }, { field: "link", label: "Link", type: "link" },
      { field: "detected", label: "Detected", type: "date" }],
    rows: [{ id: "x_1", title: EVIL, href: "#/x/alerts/x_1", tone: "sev-high", cells: { title: EVIL, host: EVIL, link: "javascript:alert(1)", detected: NOW - 3600 } },
      { id: "x_2", title: "Two", href: "#/x/alerts/x_2", tone: null, cells: { title: "Two", host: null, link: "https://siem.example.com/2", detected: NOW + 3 * 86400 } }] },
  domain_timeline: { domain: "vulnerabilities", domain_label: "Vulnerabilities", noun: "findings", source_label: EVIL, href: "#/vulnerabilities", date_field: "first_seen",
    date_label: "First seen", days: 7, total: 3, skipped: 2, buckets: [{ day: "2026-10-08", count: 0 }, { day: "2026-10-09", count: 2 }, { day: "2026-10-10", count: 1 }] },
  compliance_overview: { evaluated: true, href: "#/compliance",
    frameworks: [{ id: "BASELINE", name: EVIL, score: 72, passing: 10, failing: 3, total: 20, href: "#/compliance" }],
    cyfun: { id: "fa_1", name: EVIL, framework: "cyfun2025", framework_name: "CyFun 2025", target_name: "Basic", status: "in_progress", verdict: "not_met",
      maturity: 2, progress: { total: 10, scored: 4, na: 0 }, assessed_at: NOW, stale: false, href: "#/compliance/frameworks/cyfun2025/fa_1" },
    external: [{ id: "ext:c:1", name: EVIL, tool_id: "c", source_tool: EVIL, assessments: 1, score: 40, maturity: 2.5, href: "#/compliance/frameworks/ext%3Ac%3A1" }] },
  controls_status: { counts: { pass: 3, partial: 1, fail: 2, manual: 0, na: 0 }, total: 3, evaluated: true, href: "#/compliance/controls",
    rows: [{ id: "HB-1", title: EVIL, family: "Access", status: "fail", detail: EVIL, automated: true }] },
  risk_matrix: { cells: [[1, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], [0, 0, 0, 2, 0]], total: 3, source: "tool:grc", source_label: EVIL, href: "#/compliance/risks" },
  vuln_sla: { open: 4, overdue: 1, by_severity: { critical: 1, high: 2, medium: 0, low: 1, info: 0 }, overdue_by_severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    sla_days: { critical: 7, high: 30, medium: 90, low: 180, info: 365 }, fixed_last_30_days: 2, in_scope_assets: 3, scanned_last_30_days: 2, source: "all",
    source_label: EVIL, href: "#/vulnerabilities?status=active" },
  network_overview: { devices: [{ tool_id: "fw", name: EVIL, product: EVIL, snapshot_at: NOW - 60, stale: true, writable: false, open_drift: 2, critical_drift: 1,
    connection: "ok", href: "#/network/fw" }], drift: { open: 2, attributed: 0, acknowledged: 0, critical_open: 1 },
    changes: { proposed: 1, scheduled: 0, verifying: 0 }, device_changes_on: false, href: "#/network" },
  leavers: { total: 2, href: "#/people/leavers", rows: [{ id: "p1", display_name: EVIL, status: "suspended", severity: "fail", terminated_at: null,
    holds: { assets: 1, accounts: 2, atrium_account: true }, href: "#/people/p1" }] },
};

test("D3 renderers escape untrusted text, in chart and table views", () => {
  for (const [type, data] of Object.entries(D3)) {
    for (const table of [false, true]) {
      const out = s(widgetBody(ok(data), inst(type, { title: EVIL }), { table, now: NOW }));
      safe(out, `${type} table=${table}`);
      assert.doesNotMatch(out, /href="javascript:/i, type);
    }
  }
  const declared = s(widgetBody(ok({ ...D3.domain_count, compiled: "domain_count", declared_by: { kind: "tool", id: "siem", name: EVIL } }), inst("declared"), {}));
  safe(declared, "declared");
  assert.match(declared, /Suggested by &lt;img/);
});

test("a count is one number, bars in severity order or a list of groups", () => {
  const number = s(widgetBody(ok({ ...D3.domain_count, view: "number", source_label: "All sources" }), inst("domain_count"), {}));
  assert.equal((number.match(/<a /g) || []).length, 1);
  assert.match(number, /aria-label="5 alerts"/);
  const barsOut = s(widgetBody(ok(D3.domain_count), inst("domain_count"), {}));
  // ordinal groups keep the server's order (not re-sorted by count)
  assert.ok(barsOut.indexOf('aria-label="low: 3 alerts, 60%"') < barsOut.indexOf('aria-label="critical: 2 alerts, 40%"'));
  const list = s(widgetBody(ok({ ...D3.domain_count, view: "list", other: 4 }), inst("domain_count"), {}));
  assert.equal((list.match(/<li>/g) || []).length, 3, "two groups and Other");
  assert.match(list, /class="dash-mark tone-sev-low"/);
  const asTable = s(widgetBody(ok(D3.domain_count), inst("domain_count"), { table: true }));
  assert.match(asTable, /<th scope="col"[^>]*>Severity<\/th>/);
  assert.match(asTable, /<th scope="row">/);
});

test("a list is a table in wide widgets and stacked cards in narrow ones; cells by type", () => {
  const wide = s(widgetBody(ok(D3.domain_list), inst("domain_list", { w: 6 }), { now: NOW }));
  assert.match(wide, /<table/);
  assert.equal((wide.match(/<th scope="col"[^>]*>Title<\/th>/g) || []).length, 1, "the title column is the linked row header, not repeated");
  assert.match(wide, /<a href="#\/x\/alerts\/x_2">Two<\/a>/);
  assert.match(wide, /<a href="https:\/\/siem\.example\.com\/2" target="_blank" rel="noopener noreferrer">/);
  assert.doesNotMatch(wide, /javascript:/);
  assert.match(wide, />in 3d</, "a future date reads as a deadline");
  assert.match(wide, /2 of 9 shown/);
  const narrow = s(widgetBody(ok(D3.domain_list), inst("domain_list", { w: 3 }), { now: NOW }));
  assert.doesNotMatch(narrow, /<table/);
  assert.doesNotMatch(s(widgetBody(ok(D3.domain_list), inst("domain_list", { w: 6 }), { now: NOW, stack: true })), /<table/,
    "the one-column stack mode of narrow screens shows cards too");
  assert.match(narrow, /<ul class="dash-list">/);
  assert.equal(s(widgetBody(ok({ ...D3.domain_list, rows: [], total: 0 }), inst("domain_list"), {})).includes("Nothing matches."), true);
});

test("timelines, risk matrix, SLA, network and leavers", () => {
  const cols = s(widgetBody(ok(D3.domain_timeline), inst("domain_timeline"), {}));
  assert.equal((cols.match(/class="col"/g) || []).length, 3);
  assert.match(cols, /2 without this date are not counted/);
  const colsTable = s(widgetBody(ok(D3.domain_timeline), inst("domain_timeline"), { table: true }));
  assert.equal((colsTable.match(/<th scope="row">/g) || []).length, 2, "days with records only");
  const mx = s(widgetBody(ok(D3.risk_matrix), inst("risk_matrix"), {}));
  assert.match(mx, /aria-label="Likelihood 5, impact 4: 2 risks \(critical\)"/);
  assert.match(s(widgetBody(ok(D3.risk_matrix), inst("risk_matrix"), { table: true })), /Likelihood 5, impact 4/);
  const sla = s(widgetBody(ok(D3.vuln_sla), inst("vuln_sla"), {}));
  assert.match(sla, /class="dash-kpi bad"><b>1<\/b>/);
  assert.match(sla, /<td class="num">30 days<\/td>/);
  const net = s(widgetBody(ok(D3.network_overview), inst("network_overview"), { now: NOW }));
  assert.match(net, /out of date/);
  assert.match(net, /2 drift/);
  assert.match(net, /href="#\/network\/fw"/);
  const left = s(widgetBody(ok(D3.leavers), inst("leavers"), {}));
  assert.match(left, /1 asset, 2 accounts, an Atrium sign-in/);
  assert.match(s(widgetBody(ok({ total: 0, rows: [], href: "#/people/leavers" }), inst("leavers"), {})), /Nobody who left/);
  const controls = s(widgetBody(ok(D3.controls_status), inst("controls_status"), {}));
  assert.ok(controls.indexOf("2 fail") < controls.indexOf("1 partial") && controls.indexOf("1 partial") < controls.indexOf("3 pass"));
});

test("a declared widget renders like the widget it compiles to", () => {
  const data = { ...D3.domain_list, compiled: "domain_list", declared_by: { kind: "pack", id: "siem", name: "SIEM alerts" }, declared_title: "Critical" };
  const out = s(widgetBody(ok(data), inst("declared", { w: 6 }), { now: NOW }));
  assert.ok(out.startsWith(s(widgetBody(ok(D3.domain_list), inst("domain_list", { w: 6 }), { now: NOW }))));
  assert.match(out, /From SIEM alerts/);
  assert.equal(summary(ok(data), inst("declared")), "Preview: 9 alerts, 2 rows shown");
  assert.match(s(widgetLink(ok(data), inst("declared"))), /href="#\/x\/alerts"/);
  assert.match(s(widgetBody(ok({ compiled: "nope" }), inst("declared"), {})), /cannot show this kind/);
});

test("the gallery offers packs' widgets and shows a declaration that does not fit, without an Add", async () => {
  const { galleryEntries, filterEntries } = await import("../../hub/web/js/dashboard/gallery.js");
  const catalog = {
    types: [{ key: "declared", title: "Declared widget", description: "", category: "records", size: { min: { w: 2, h: 1 }, default: { w: 4, h: 3 }, max: { w: 12, h: 8 } } }],
    metrics: [], tools: [{ id: "siem", name: "SIEM", ui: {} }],
    suggestions: [
      { id: "sg:a", group: "pack:siem-alerts", type: "declared", config: { ref: "pack:siem-alerts/open" }, title: "Open alerts", description: "", size: [4, 3],
        declared_by: { kind: "pack", id: "siem-alerts", name: "SIEM alerts" } },
      { id: "sg:b", group: "tool:siem", type: "declared", config: { ref: "tool:siem/x" }, title: "Assets seen", description: "", size: [4, 3],
        declared_by: { kind: "tool", id: "siem", name: "SIEM" }, invalid: "domain: SIEM's connection does not read this data" },
    ],
  };
  const entries = galleryEntries(catalog);
  const pack = entries.find((e) => e.key === "sg:a");
  assert.deepEqual([pack.category, pack.pack, pack.invalid], ["mine", { id: "siem-alerts", name: "SIEM alerts" }, null]);
  assert.equal(entries.find((e) => e.key === "sg:b").invalid, "domain: SIEM's connection does not read this data");
  assert.deepEqual(filterEntries(entries, { query: "siem alerts" }).map((e) => e.key), ["sg:a"], "the pack's name matches");
});

test("configure: a new domain clears what belonged to the old one; sources are the tools that read the domain", async () => {
  const { forDomain, sourceTools } = await import("../../hub/web/js/dashboard/configure.js");
  const catalog = { domains: [{ key: "assets", group_by: ["type"] }, { key: "x:alerts", group_by: ["severity"] }],
    tools: [{ id: "inv", reads: ["assets"] }, { id: "siem", reads: ["x:alerts"] }] };
  const fields = [{ name: "domain", kind: "domain" }, { name: "source", kind: "tool", depends_on: "domain" },
    { name: "filters", kind: "filters" }, { name: "group_by", kind: "field", options: "group_by" }, { name: "columns", kind: "field", options: "columns" },
    { name: "view", kind: "select" }];
  const next = forDomain(fields, { domain: "x:alerts", source: "tool:inv", filters: [{ field: "type" }], group_by: "type", columns: ["name"], view: "list" }, catalog);
  assert.deepEqual(next, { domain: "x:alerts", source: "all", filters: [], group_by: "severity", view: "list" });
  assert.equal(forDomain(fields, { domain: "assets", source: "tool:inv" }, catalog).source, "tool:inv", "a tool that brings the domain stays");
  assert.deepEqual(sourceTools(catalog, "x:alerts").map((t) => t.id), ["siem"]);
  const { defaultTitle } = await import("../../hub/web/js/dashboard/configure.js");
  const titled = { types: [], metrics: [], domains: [{ key: "vulnerabilities", label: "Vulnerabilities", fields: { severity: { label: "Severity" } } }] };
  assert.equal(defaultTitle(titled, { type: "domain_count", config: { domain: "vulnerabilities", group_by: "severity" } }), "Vulnerabilities by severity");
  assert.equal(defaultTitle(titled, { type: "domain_timeline", config: { domain: "vulnerabilities" } }), "Vulnerabilities over time");
});
