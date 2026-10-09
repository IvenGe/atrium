// Vulnerabilities app: findings from scanners and tools with remediation deadlines (SLA), "Scan now" of the assets in
// scan scope, and management of that scope.
import { get, patch, post } from "../api.js";
import {
  actions, badge, dateTime, debounce, emptyState, field, html, icon, modal, options, setHTML, timeAgo, timeIn, toast,
} from "../ui.js";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const STATUSES = [["open", "Open"], ["in_progress", "In progress"], ["accepted", "Risk accepted"], ["false_positive", "False positive"], ["fixed", "Fixed"]];
const STATUS_FILTERS = [["active", "Open"], ["fixed", "Fixed"], ["accepted", "Accepted"], ["false_positive", "False positive"], ["", "All"]];
const SCOPE_FILTERS = [["all", "All assets"], ["in", "In scope"], ["out", "Not in scope"], ["noaddr", "In scope, no address"]];
const ADDRESS_FACTS = ["address", "hostname", "fqdn", "ip", "ip_address"];
const CVE_RE = /^CVE-\d{4}-\d{4,}$/i;
const DAY = 86400;

export const sevBadge = (s) => html`<span class="sev ${SEVERITIES.includes(s) ? s : "info"}">${s}</span>`;

/** IPs and hostnames an asset is known by (as the Asset Supervisor reads them). */
export function assetAddresses(a) {
  const found = [];
  const listed = Array.isArray(a.facts?.addresses) ? a.facts.addresses : [];
  for (const v of [...listed, ...ADDRESS_FACTS.map((k) => a.facts?.[k])]) {
    const text = typeof v === "string" || typeof v === "number" ? String(v).trim().toLowerCase().replace(/\.$/, "") : "";
    if (text && !found.includes(text)) found.push(text);
  }
  return found;
}

function cveLinks(cves) {
  if (!cves?.length) return html`<span class="faint">none</span>`;
  return html`<span class="tag-list">${cves.map((c) => (CVE_RE.test(c)
    ? html`<a class="badge mono" href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.toUpperCase())}" target="_blank" rel="noopener noreferrer">${c}${icon("external")}</a>`
    : html`<span class="badge mono">${c}</span>`))}</span>`;
}

function dueCell(v) {
  if (v.status === "fixed") return html`<span class="faint" title="${dateTime(v.fixed_at)}">fixed ${timeAgo(v.fixed_at)}</span>`;
  if (!["open", "in_progress"].includes(v.status) || !v.due_at) return html`<span class="faint">-</span>`;
  if (v.overdue) return html`${badge("overdue", "bad")} <span class="faint" style="font-size:12px" title="${dateTime(v.due_at)}">${Math.ceil((Date.now() / 1000 - v.due_at) / DAY)}d</span>`;
  return html`<span title="${dateTime(v.due_at)}">${timeIn(v.due_at)}</span>`;
}

export async function render(el, ctx) {
  let tab = ctx.params[0] === "scope" ? "scope" : "findings";
  const filter = { status: "active", severity: "", source: "", overdue: false, q: "", asset: "" };
  let scopeFilter = "all";
  let scopeQuery = "";
  const picked = new Set();
  let summary = null;
  let vulns = [];
  let assets = [];
  let activeVulns = [];
  let toolNames = {};

  const part = (name) => el.querySelector(`[data-part="${name}"]`);
  const assetName = (id) => assets.find((a) => a.id === id)?.name;

  // ---------- page skeleton (rendered once per tab, so typing in the search keeps focus) ----------
  function shell() {
    setHTML(el, html`
      <div class="page-head"><div><h1>Vulnerabilities</h1><p class="muted">Findings from your scanners and tools, with remediation deadlines.
          Only assets in scan scope are ever scanned.</p></div>
        <div class="row" data-min-role="operator"><button class="btn primary" data-act="scan">${icon("radar")}Scan now</button></div></div>
      <div data-part="tiles"></div>
      <div class="tabs"><button class="${tab === "findings" ? "active" : ""}" data-act="tab" data-tab="findings">Findings</button>
        <button class="${tab === "scope" ? "active" : ""}" data-act="tab" data-tab="scope" data-part="scope-tab">Scan scope</button></div>
      ${tab === "findings" ? html`
        <div data-part="scanners"></div>
        <div class="row filters" style="margin-bottom:12px">
          <div class="seg" data-part="status-filter"></div>
          <select data-filter="severity" class="input-sm" aria-label="Severity"><option value="">Any severity</option>${options(SEVERITIES)}</select>
          <select data-filter="source" class="input-sm" aria-label="Source" data-part="source-filter"><option value="">Any source</option></select>
          <label class="check"><input type="checkbox" data-filter="overdue"> Overdue only</label>
          <span data-part="asset-filter"></span>
          <span class="spacer"></span>
          <input data-filter="q" placeholder="Search title, host, CVE..." style="max-width:260px" aria-label="Search findings"></div>
        <section class="card flush" data-part="table"><div class="empty faint">Loading...</div></section>`
      : html`
        <div class="row filters" style="margin-bottom:12px">
          <div class="seg" data-part="scope-filter"></div><span class="spacer"></span>
          <input data-filter="scope-q" placeholder="Search assets..." style="max-width:260px" aria-label="Search assets"></div>
        <div class="bulk-bar" data-part="bulk" data-min-role="operator"></div>
        <section class="card flush" data-part="scope"><div class="empty faint">Loading...</div></section>`}`);
    const sev = el.querySelector('[data-filter="severity"]');
    if (sev) {
      sev.value = filter.severity;
      el.querySelector('[data-filter="overdue"]').checked = filter.overdue;
      el.querySelector('[data-filter="q"]').value = filter.q;
    }
    const sq = el.querySelector('[data-filter="scope-q"]');
    if (sq) sq.value = scopeQuery;
  }

  // ---------- data ----------
  async function load() {
    const params = new URLSearchParams({ limit: "1000" });
    if (filter.status) params.set("status", filter.status);
    if (filter.severity) params.set("severity", filter.severity);
    if (filter.source) params.set("source", filter.source);
    if (filter.overdue) params.set("overdue", "true");
    if (filter.q) params.set("q", filter.q);
    if (filter.asset) params.set("asset_id", filter.asset);
    const [s, a, tools, list, active] = await Promise.all([
      get("/vulnerabilities/summary"), get("/assets"), get("/tools"),
      tab === "findings" ? get(`/vulnerabilities?${params}`) : Promise.resolve(vulns),
      tab === "scope" ? get("/vulnerabilities?status=active&limit=10000") : Promise.resolve(activeVulns),
    ]);
    summary = s;
    assets = a;
    vulns = list;
    activeVulns = active;
    toolNames = Object.fromEntries(tools.map((t) => [t.id, t.name]));
  }

  function renderTiles() {
    const s = summary;
    const coverage = s.in_scope_assets ? Math.round((s.scanned_last_30_days / s.in_scope_assets) * 100) : null;
    setHTML(part("tiles"), html`<div class="sev-tiles">
      ${SEVERITIES.map((sev) => html`<button type="button" class="card sev-tile ${sev} ${filter.severity === sev ? "active" : ""}" data-act="sev" data-sev="${sev}"
        title="Show open ${sev} findings"><div class="label">${sev}</div><div class="value">${s.by_severity[sev] || 0}</div>
        <div class="sub">${s.overdue_by_severity[sev] ? html`<span style="color:var(--bad)">${s.overdue_by_severity[sev]} overdue</span>` : sev === "info" ? "informational" : `fix within ${s.sla_days[sev]}d`}</div></button>`)}
      <button type="button" class="card sev-tile overdue ${filter.overdue ? "active" : ""}" data-act="overdue-tile" title="Show overdue findings">
        <div class="label">Overdue</div><div class="value">${s.overdue}</div><div class="sub">past their SLA</div></button>
      <div class="card sev-tile fixed"><div class="label">Fixed</div><div class="value">${s.fixed_last_30_days}</div><div class="sub">last 30 days</div></div>
      <div class="card sev-tile coverage" title="In-scope assets scanned in the last 30 days (control HB-VM-2)"><div class="label">Scan coverage</div>
        <div class="value">${coverage == null ? "-" : `${coverage}%`}</div>
        <div class="sub">${s.in_scope_assets ? `${s.scanned_last_30_days}/${s.in_scope_assets} in scope, 30d` : "no assets in scope"}</div></div>
    </div>`);
    const scopeTab = part("scope-tab");
    if (scopeTab) scopeTab.textContent = `Scan scope (${s.in_scope_assets})`;
  }

  function renderScanners() {
    const box = part("scanners");
    if (!box) return;
    const list = summary.scanners;
    if (!list.length) {
      setHTML(box, html`<div class="notice" style="margin-bottom:14px">${icon("radar")}<div><b>No vulnerability scanner connected.</b>
        <span class="muted">Import OpenVAS / Greenbone (or another scanner) as a tool and set up its API in the tool's Connection tab. Findings pulled
        from other tools also land here.</span></div></div>`);
      return;
    }
    setHTML(box, html`<div class="scanner-list">${list.map((sc) => {
      const job = sc.job;
      const r = sc.last_result;
      return html`<div class="scanner">
        <div class="row" style="gap:8px;flex-wrap:nowrap">${icon("radar")}<a href="#/tools/${sc.tool_id}/connection"><b>${sc.name}</b></a>
          ${sc.flow_status ? badge(sc.flow_status === "enabled" ? "scheduled" : sc.flow_status, sc.flow_status === "enabled" ? "ok" : sc.flow_status === "proposed" ? "warn" : "") : ""}</div>
        <div class="scanner-state">
          ${job?.status === "running" ? html`<div class="row" style="gap:8px"><span class="dot working"></span>Scanning ${(job.hosts || []).length} host(s)
              <span class="faint">${job.progress ?? 0}%</span>
              <button class="btn sm" data-act="poll" data-flow="${sc.flow_id}" data-min-role="operator">${icon("refresh")}Check</button></div>
            <div class="progress" style="margin-top:6px"><span style="width:${Math.max(3, Math.min(100, Number(job.progress) || 0))}%"></span></div>`
          : job?.status === "awaiting_approval" ? html`<a href="#/approvals">${badge("scan awaiting approval", "warn")}</a>`
          : r ? html`<span class="row" style="gap:6px">${r.ok ? badge("last scan ok") : badge("last run failed", "bad")}<span class="faint" title="${dateTime(r.at)}">${timeAgo(r.at)}</span></span>
            ${!r.ok && r.error ? html`<div class="flow-result bad" title="${r.error.message}">${r.error.message}</div>` : ""}`
          : html`<span class="faint">No scan yet</span>`}
        </div></div>`;
    })}</div>`);
  }

  function renderStatusFilter() {
    setHTML(part("status-filter"), STATUS_FILTERS.map(([k, label]) => html`<button class="${filter.status === k ? "active" : ""}" data-act="status-filter" data-f="${k}">${label}</button>`));
    const sources = [...new Set([...summary.scanners.map((s) => s.tool_id), ...vulns.map((v) => v.source), filter.source].filter(Boolean))];
    setHTML(part("source-filter"), html`<option value="">Any source</option>${options(sources.map((s) => [s, toolNames[s] || s]), filter.source)}`);
    el.querySelector('[data-filter="severity"]').value = filter.severity;
    el.querySelector('[data-filter="overdue"]').checked = filter.overdue;
    setHTML(part("asset-filter"), filter.asset ? html`<button class="chip-link" data-act="asset-clear" title="Show every asset's findings">
      ${icon("box")}${assetName(filter.asset) || filter.asset}${icon("x")}</button>` : "");
  }

  function renderTable() {
    const box = part("table");
    if (!vulns.length) {
      const none = !summary.total;
      setHTML(box, emptyState(none ? "bug" : "search", none ? "No findings yet" : "Nothing matches",
        none ? "Put assets in scan scope and press Scan now, or connect a tool that reports vulnerabilities." : "Change the filters to see other findings."));
      return;
    }
    setHTML(box, html`<div class="table-wrap"><table class="table"><thead><tr><th>Severity</th><th>Finding</th><th>Asset / host</th><th>Status</th><th>Due</th><th>Found</th><th>Source</th></tr></thead><tbody>
      ${vulns.map((v) => html`<tr class="clickable" data-act="open" data-id="${v.id}">
        <td>${sevBadge(v.severity)}${v.cvss != null ? html`<div class="faint" style="font-size:11.5px;margin-top:2px">CVSS ${v.cvss}</div>` : ""}</td>
        <td style="min-width:240px;max-width:460px"><b class="clip">${v.title}</b>${v.cves.length ? html`<div class="faint mono clip" style="font-size:11.5px">${v.cves.slice(0, 4).join(", ")}${v.cves.length > 4 ? ` +${v.cves.length - 4}` : ""}</div>` : ""}</td>
        <td>${v.asset_id && assetName(v.asset_id) ? html`<div>${assetName(v.asset_id)}</div>` : ""}<div class="faint mono" style="font-size:12px">${v.host || "-"}${v.port ? `:${v.port}` : ""}</div></td>
        <td>${badge(v.status, v.status === "open" ? "warn" : undefined)}</td>
        <td style="white-space:nowrap">${dueCell(v)}</td>
        <td class="faint" title="${dateTime(v.first_seen)}">${timeAgo(v.first_seen)}</td>
        <td class="faint">${toolNames[v.source] || v.source}</td></tr>`)}</tbody></table></div>
      ${vulns.length >= 1000 ? html`<p class="faint" style="padding:10px 14px;font-size:12px">Showing the first 1000 findings - narrow the filters to see others.</p>` : ""}`);
  }

  function scopeRows() {
    const q = scopeQuery.toLowerCase();
    return assets.filter((a) => a.status !== "retired").filter((a) => {
      const addr = assetAddresses(a);
      if (scopeFilter === "in" && !a.scan_scope) return false;
      if (scopeFilter === "out" && a.scan_scope) return false;
      if (scopeFilter === "noaddr" && (!a.scan_scope || addr.length)) return false;
      return !q || `${a.name} ${a.type} ${a.owner || ""} ${addr.join(" ")}`.toLowerCase().includes(q);
    }).sort((a, b) => (b.scan_scope - a.scan_scope) || a.name.localeCompare(b.name));
  }

  function renderBulk() {
    const box = part("bulk");
    if (!box) return;
    setHTML(box, html`<span class="muted">${picked.size ? `${picked.size} selected` : "Select assets to change their scope"}</span>
      <button class="btn sm" data-act="scope-set" data-in="1" ${picked.size ? "" : "disabled"}>${icon("radar")}Put in scan scope</button>
      <button class="btn sm" data-act="scope-set" data-in="0" ${picked.size ? "" : "disabled"}>${icon("minus")}Take out of scope</button>
      ${picked.size ? html`<button class="btn sm ghost" data-act="scope-clear">Clear selection</button>` : ""}`);
  }

  function renderScope() {
    const s = summary;
    setHTML(part("scope-filter"), SCOPE_FILTERS.map(([k, label]) => html`<button class="${scopeFilter === k ? "active" : ""}" data-act="scope-filter" data-f="${k}">${label}</button>`));
    const rows = scopeRows();
    const open = {};
    for (const v of activeVulns) if (v.asset_id) open[v.asset_id] = (open[v.asset_id] || 0) + 1;
    for (const id of [...picked]) if (!assets.some((a) => a.id === id && a.status !== "retired")) picked.delete(id);
    const allPicked = rows.length && rows.every((a) => picked.has(a.id));
    setHTML(part("scope"), html`
      <div style="padding:12px 16px 4px">${s.in_scope_without_address ? html`<div class="notice warn" style="margin-bottom:8px">${icon("alert")}<div>
          <b>${s.in_scope_without_address} in-scope asset${s.in_scope_without_address > 1 ? "s have" : " has"} no IP address or hostname</b>
          <span class="muted">and cannot be scanned. Add addresses in the asset's edit dialog (Assets).</span></div></div>` : ""}
        <p class="muted" style="font-size:12.5px">${s.in_scope_assets} of ${s.assets} active assets in scope. Scans only ever target the IP addresses and hostnames
          of in-scope assets; control HB-VM-2 expects each of them scanned within 30 days.</p></div>
      ${rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
          <th style="width:34px" data-min-role="operator"><input type="checkbox" data-pick-all aria-label="Select all shown" ${allPicked ? "checked" : ""}></th>
          <th>Asset</th><th>Addresses</th><th>Scan scope</th><th>Last scanned</th><th>Open findings</th></tr></thead><tbody>
        ${rows.map((a) => {
          const addr = assetAddresses(a);
          return html`<tr>
            <td data-min-role="operator"><input type="checkbox" data-pick="${a.id}" aria-label="Select ${a.name}" ${picked.has(a.id) ? "checked" : ""}></td>
            <td><b>${a.name}</b><div class="faint" style="font-size:12px">${a.type}${a.owner ? ` - ${a.owner}` : ""}</div></td>
            <td class="mono" style="font-size:12px;max-width:280px">${addr.length ? addr.slice(0, 4).join(", ") + (addr.length > 4 ? ` +${addr.length - 4}` : "")
              : html`<span class="${a.scan_scope ? "warn-text" : "faint"}">no address</span>`}</td>
            <td><div class="row" style="gap:8px;flex-wrap:nowrap">
              <button type="button" class="toggle" role="switch" aria-checked="${a.scan_scope ? "true" : "false"}" aria-label="Scan scope of ${a.name}"
                data-act="scope-one" data-id="${a.id}" data-min-role="operator"></button>${a.scan_scope ? badge("in scope", "info") : html`<span class="faint">out</span>`}</div></td>
            <td class="faint" title="${dateTime(a.last_scanned_at)}">${a.last_scanned_at ? timeAgo(a.last_scanned_at) : a.scan_scope ? html`<span class="warn-text">never</span>` : "-"}</td>
            <td>${open[a.id] ? html`<a href="#/vulnerabilities" data-act="asset-findings" data-id="${a.id}">${open[a.id]} open</a>` : html`<span class="faint">0</span>`}</td></tr>`;
        })}</tbody></table></div>`
      : emptyState("box", "No assets here", scopeFilter === "all" ? "Add assets in the Assets app, or pull them from an inventory tool such as Snipe-IT." : "No asset matches this filter.")}`);
    renderBulk();
  }

  async function draw() {
    await load();
    if (!el.querySelector("[data-part]")) shell();
    renderTiles();
    if (tab === "findings") { renderScanners(); renderStatusFilter(); renderTable(); } else renderScope();
  }
  const refresh = () => draw().catch((err) => toast(err.message, "bad"));
  const reload = debounce(refresh, 250);

  async function setScope(ids, inScope) {
    try {
      const r = await post("/assets/scan-scope", { asset_ids: ids, in_scope: inScope });
      if (r.without_address?.length) toast(`In scope, but without an IP address or hostname: ${r.without_address.slice(0, 5).join(", ")}${r.without_address.length > 5 ? "..." : ""}`, "warn");
      else toast(r.changed.length ? `${r.changed.length} asset${r.changed.length > 1 ? "s" : ""} ${inScope ? "put in" : "taken out of"} scan scope` : "Nothing changed", r.changed.length ? "ok" : "info");
    } catch (err) {
      toast(err.message, "bad");
    }
    refresh();
  }

  function openFinding(v) {
    const tool = toolNames[v.source];
    const m = modal({
      title: v.title,
      wide: true,
      minRole: "operator",
      body: html`<div class="row" style="gap:8px;margin-bottom:12px">${sevBadge(v.severity)}${v.cvss != null ? html`<span class="badge">CVSS ${v.cvss}</span>` : ""}
          ${badge(v.status, v.status === "open" ? "warn" : undefined)}${v.overdue ? badge("overdue", "bad") : ""}</div>
        <dl class="kv" style="margin-bottom:14px">
          <dt>Asset</dt><dd>${v.asset_id && assetName(v.asset_id) ? assetName(v.asset_id) : html`<span class="faint">not matched to an asset</span>`}</dd>
          <dt>Host</dt><dd class="mono">${v.host || "-"}${v.port ? html` <span class="faint">port ${v.port}</span>` : ""}</dd>
          <dt>CVEs</dt><dd>${cveLinks(v.cves)}</dd>
          <dt>Source</dt><dd>${tool ? html`<a href="#/tools/${v.source}" data-close>${tool}</a>` : v.source}${v.external_id ? html` <span class="faint mono" style="font-size:11.5px">${v.external_id}</span>` : ""}</dd>
          <dt>First seen</dt><dd>${dateTime(v.first_seen)}</dd><dt>Last seen</dt><dd>${dateTime(v.last_seen)}</dd>
          <dt>Due</dt><dd>${v.due_at ? html`${dateTime(v.due_at)} ${v.overdue ? html`<span style="color:var(--bad)">(overdue)</span>` : ""}` : html`<span class="faint">no deadline</span>`}</dd>
          ${v.fixed_at ? html`<dt>Fixed</dt><dd>${dateTime(v.fixed_at)}</dd>` : ""}
        </dl>
        ${v.description ? html`<h3 style="margin-bottom:6px">Description</h3><div class="prose-box">${v.description}</div>` : ""}
        ${v.solution ? html`<h3 style="margin:12px 0 6px">Solution</h3><div class="prose-box">${v.solution}</div>` : ""}
        <div class="form-grid" style="margin-top:14px">
          ${field("Status", html`<select name="status">${options(STATUSES, v.status)}</select>`,
            "Fixed findings reopen if a later scan finds them again; a rescan that no longer finds one marks it fixed.")}
          ${field("Note", html`<textarea name="note" rows="3" maxlength="4000" placeholder="e.g. ticket, compensating control, reason for accepting">${v.note || ""}</textarea>`)}</div>`,
      async onSubmit(data) {
        await patch(`/vulnerabilities/${encodeURIComponent(v.id)}`, { status: data.get("status"), note: String(data.get("note") || "") });
        toast("Finding updated", "ok");
        refresh();
      },
    });
    m.el.querySelectorAll("a[data-close]").forEach((a) => a.addEventListener("click", m.close));
  }

  function openScan() {
    const list = summary.scanners;
    if (!list.length) {
      toast("Connect a vulnerability scanner (such as OpenVAS / Greenbone) in its tool's Connection tab first", "warn");
      return;
    }
    const inScope = assets.filter((a) => a.scan_scope && a.status !== "retired");
    if (!inScope.length) {
      toast("No assets are in scan scope - put the assets to scan in scope first", "warn");
      tab = "scope";
      shell();
      refresh();
      return;
    }
    const busy = list.filter((sc) => sc.job?.status);
    modal({
      title: "Scan for vulnerabilities",
      submit: "Start scan",
      minRole: "operator",
      wide: true,
      body: html`<div class="notice warn" style="margin-bottom:14px">${icon("alert")}<div class="muted">The scanner actively probes these hosts; scans can load the
          scanned systems. Only assets in scan scope are offered.</div></div>
        ${field("Scanner", html`<select name="scanner">${options(list.map((sc) => [sc.tool_id, `${sc.name}${sc.job?.status ? ` (${sc.job.status.replace(/_/g, " ")})` : ""}`]))}</select>`,
          busy.length ? "A scanner that is already scanning keeps its current scan." : "")}
        <div class="field"><label>Assets (${inScope.length} in scope)</label>
          <div class="pick-list">${inScope.map((a) => {
            const addr = assetAddresses(a);
            return html`<label class="check"><input type="checkbox" name="asset" value="${a.id}" ${addr.length ? "checked" : "disabled"}>
              <span><b>${a.name}</b> <span class="faint mono" style="font-size:12px">${addr.length ? addr.slice(0, 3).join(", ") : "no address - cannot be scanned"}</span></span></label>`;
          })}</div></div>`,
      async onSubmit(data) {
        const ids = data.getAll("asset").map(String);
        if (!ids.length) throw new Error("Choose at least one asset with an address");
        const r = await post("/vulnerabilities/scan", { scanner_tool_id: data.get("scanner"), asset_ids: ids });
        if (r.error) toast(`Scan failed: ${r.error.message}`, "bad");
        else toast(r.detail || "Scan started", r.pending ? "info" : "ok");
        refresh();
      },
    });
  }

  actions(el, {
    tab: (d) => { tab = d.tab; history.replaceState(null, "", tab === "scope" ? "#/vulnerabilities/scope" : "#/vulnerabilities"); shell(); refresh(); },
    sev: (d) => {
      filter.severity = filter.severity === d.sev ? "" : d.sev;
      filter.status = filter.severity ? "active" : filter.status;
      if (tab !== "findings") { tab = "findings"; shell(); }
      refresh();
    },
    "overdue-tile": () => { filter.overdue = !filter.overdue; if (tab !== "findings") { tab = "findings"; shell(); } refresh(); },
    "status-filter": (d) => { filter.status = d.f; refresh(); },
    open: (d) => { const v = vulns.find((x) => x.id === d.id); if (v) openFinding(v); },
    scan: () => openScan(),
    async poll(d, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/flows/${encodeURIComponent(d.flow)}/run`);
        toast(r.error ? `Scan failed: ${r.error.message}` : r.detail || "Scan finished", r.error ? "bad" : "info");
      } catch (err) {
        toast(err.message, "bad");
      }
      refresh();
    },
    "scope-filter": (d) => { scopeFilter = d.f; renderScope(); },
    "scope-one": (d) => { const a = assets.find((x) => x.id === d.id); if (a) setScope([a.id], !a.scan_scope); },
    "scope-set": (d) => { if (picked.size) setScope([...picked], d.in === "1").then(() => { picked.clear(); renderBulk(); }); },
    "scope-clear": () => { picked.clear(); renderScope(); },
    "asset-clear": () => { filter.asset = ""; refresh(); },
    "asset-findings": (d) => {
      Object.assign(filter, { status: "active", severity: "", source: "", overdue: false, q: "", asset: d.id });
      tab = "findings";
      history.replaceState(null, "", "#/vulnerabilities");
      shell();
      refresh();
    },
  });
  el.addEventListener("input", (e) => {
    const name = e.target.dataset?.filter;
    if (name === "q") { filter.q = e.target.value.trim(); reload(); }
    if (name === "scope-q") { scopeQuery = e.target.value.trim(); renderScope(); }
  });
  el.addEventListener("change", (e) => {
    const t = e.target;
    if (t.dataset?.filter === "severity") { filter.severity = t.value; refresh(); }
    if (t.dataset?.filter === "source") { filter.source = t.value; refresh(); }
    if (t.dataset?.filter === "overdue") { filter.overdue = t.checked; refresh(); }
    if (t.matches("[data-pick]")) { if (t.checked) picked.add(t.dataset.pick); else picked.delete(t.dataset.pick); renderBulk(); }
    if (t.matches("[data-pick-all]")) {
      for (const a of scopeRows()) { if (t.checked) picked.add(a.id); else picked.delete(a.id); }
      renderScope();
    }
  });

  shell();
  await draw();
  ctx.live(["vulnerability", "flow", "asset", "asset_removed", "connection"], refresh, 600);
}
