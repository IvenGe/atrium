// Network app: the firewalls, routers, switches and host firewalls Atrium reads - their rules, interfaces and zones,
// snapshot history with diffs, configuration drift, Atrium-managed backups and guarded changes. Atrium only reads
// devices unless an administrator switches device changes on; every change is then a proposal an administrator
// approves (netchanges.js). Text read from devices (rule descriptions, interface, zone and alias names, drift lines)
// is untrusted: it only goes through html`` (escaped), diffView or textContent.
// Routes: #/network[/drift|/changes] and #/network/<tool id>[/<tab>[/<change id>]].
import { del, get, post } from "../api.js";
import {
  ACTIVE, OP_LABEL, REASONS, ROLLBACK, WAITING, changeSummary, countdown, lifecycle, openChange, proposeRestore, reasonText,
  rollbackLabel, startTicker, stateBanner,
} from "../netchanges.js";
import {
  actions, badge, builtinIcon, colorFor, confirmDialog, dateTime, diffView, emptyState, field, html, icon, modal, options,
  setHTML, timeAgo, toast,
} from "../ui.js";
import { openImport } from "./tools.js";

const enc = encodeURIComponent;
const KIND_ICON = { firewall: "firewall", router: "router", switch: "switch", host: "server" };
const LIST_TABS = ["devices", "drift", "changes"];
const DEVICE_TABS = [["rules", "Rules"], ["interfaces", "Interfaces & zones"], ["history", "History"], ["drift", "Drift"], ["backups", "Backups"],
  ["changes", "Changes"]];
const CONN = { ok: ["ok", "connected"], failing: ["bad", "failing"], untested: ["warn", "not tested"], none: ["", "no connection"] };
const SEV_TONE = { critical: "bad", warn: "warn", info: "" };
const DRIFT_LABEL = {
  rule_added: "Rule added", rule_removed: "Rule removed", rule_changed: "Rule changed", rule_enabled: "Rule enabled", rule_disabled: "Rule disabled",
  rules_reordered: "Rules reordered", interface_added: "Interface added", interface_removed: "Interface removed", interface_changed: "Interface changed",
  zone_added: "Zone added", zone_removed: "Zone removed", zone_changed: "Zone changed", alias_added: "Alias added", alias_removed: "Alias removed",
  alias_changed: "Alias changed", default_policy_changed: "Default policy changed", device_changed: "Device changed",
  any_any_introduced: "Any-to-any rule introduced", management_exposed: "Management exposed",
};
const DRIFT_STATUS = [["open", "Open"], ["attributed", "Made by Atrium"], ["acknowledged", "Acknowledged"], ["", "All"]];
const CHANGE_STATUS = [["", "Any status"], ["active", "Waiting or in progress"], ["proposed", "Proposed"], ["approved", "Approved"], ["scheduled", "Scheduled"],
  ["applied", "Applied"], ["rolled_back", "Rolled back"], ["failed", "Failed"], ["rejected", "Rejected"], ["withdrawn", "Withdrawn"], ["expired", "Expired"],
  ["stale", "Stale"], ["blocked", "Blocked"]];
const WEEK = 7 * 86400;
const VENDORS = "OPNsense, pfSense, MikroTik RouterOS, FortiGate, PAN-OS, Cisco IOS-XE, Linux host firewalls (nftables, ufw, firewalld) and Windows Defender Firewall";
const LIVE = ["network_snapshot", "network_drift", "network_baseline", "device_backup", "network_settings", "firewall_change", "connection", "flow",
  "flow_removed", "tool", "tool_removed"];

// ---------- shared pieces ----------

const kindTile = (d) => html`<span title="${d.kind || "network device"}${d.vendor ? ` - ${d.vendor}` : ""}">${builtinIcon(KIND_ICON[d.kind] || "network", colorFor(d.vendor || d.connector || d.tool_id), "sm")}</span>`;
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

const stat = (label, value, sub, iconName, extra = "", href = "") => {
  const inner = html`<div class="stat-icon">${icon(iconName)}</div><div><div class="label">${label}</div><div class="value">${value ?? "-"}</div>${sub ? html`<div class="sub">${sub}</div>` : ""}</div>`;
  return href ? html`<a class="card stat ${extra}" href="${href}">${inner}</a>` : html`<div class="card stat ${extra}">${inner}</div>`;
};

function connCell(c) {
  const [tone, text] = CONN[c?.state] || CONN.none;
  return html`<span class="row nw-nowrap" style="gap:6px" title="${c?.detail || ""}"><span class="dot ${tone}"></span>${text}</span>
    ${c?.tested_at ? html`<div class="faint nw-sub">tested ${timeAgo(c.tested_at)}</div>` : ""}`;
}

function snapshotCell(d) {
  const s = d.snapshot;
  if (!s) return badge("not read yet", "warn");
  return html`<span class="nw-nowrap">rev ${s.rev}</span> ${s.stale ? badge("stale", "warn") : ""}${s.errors ? badge(plural(s.errors, "error"), "bad") : ""}
    <div class="faint nw-sub" title="${dateTime(s.read_at)}">read ${timeAgo(s.read_at)}</div>`;
}

function driftCell(dr) {
  if (!dr?.open) return html`<span class="faint">none open</span>`;
  return badge(`${dr.open} open${dr.critical ? `, ${dr.critical} critical` : ""}`, dr.critical ? "bad" : "warn");
}

function backupCell(b) {
  if (!b?.supported) return html`<span class="faint" title="This connector cannot take configuration backups">not supported</span>`;
  if (!b.last_at) return badge("none yet", "warn");
  const old = Date.now() / 1000 - b.last_at > WEEK;
  return html`<span title="${dateTime(b.last_at)}">${old ? badge(timeAgo(b.last_at), "warn") : timeAgo(b.last_at)}</span><div class="faint nw-sub">${plural(b.count, "backup")}</div>`;
}

function writeCell(w) {
  if (!w?.capable) return html`<span class="badge" title="${REASONS.not_capable}">read-only</span>`;
  const mode = w.rollback?.mode;
  return html`<span class="badge info" title="${ROLLBACK[mode]?.[1] || ""}">${rollbackLabel(w.rollback)}</span>
    <div class="nw-sub ${w.writable ? "" : "faint"}" title="${(w.reasons || []).map(reasonText).join("\n")}">${w.writable ? "changes possible" : reasonText(w.reason).split(" (")[0].split(" - ")[0]}</div>`;
}

function baselineText(b) {
  if (!b?.rev) return html`<span class="faint">no baseline</span>`;
  return b.matches ? badge("matches baseline", "ok") : badge(`${plural(b.deviations || 0, "deviation")} from baseline`, "warn");
}

/** Redraw `fn` while keeping the focus (and caret) on the field that had it, by id. */
function keepFocus(fn) {
  const active = document.activeElement;
  const id = active?.id;
  const caret = active && "selectionStart" in active ? [active.selectionStart, active.selectionEnd] : null;
  fn();
  if (!id) return;
  const again = document.getElementById(id);
  if (again && again !== active) {
    again.focus({ preventScroll: true });
    if (caret && again.setSelectionRange) try { again.setSelectionRange(...caret); } catch { /* not a text field */ }
  }
}

/** Clicks on a table row (outside its links, buttons and fields) open it; the row's own link or button is the keyboard path. */
function onRowClick(root, fn) {
  root.addEventListener("click", (e) => {
    if (e.target.closest("a, button, input, select, label, textarea")) return;
    const row = e.target.closest("tr[data-row]");
    if (row && root.contains(row)) fn(row);
  });
}

function driftTable(items, names, { device = true } = {}) {
  return html`<div class="table-wrap"><table class="table nw-table"><thead><tr><th>Severity</th>${device ? html`<th>Device</th>` : ""}<th>What changed</th>
      <th>Before</th><th>After</th><th>Detected</th><th>Status</th><th></th></tr></thead><tbody>
    ${items.map((d) => html`<tr>
      <td>${badge(d.severity, SEV_TONE[d.severity] ?? "")}</td>
      ${device ? html`<td class="nw-nowrap"><a href="#/network/${enc(d.tool_id)}/drift">${names[d.tool_id] || d.tool_id}</a></td>` : ""}
      <td><b>${DRIFT_LABEL[d.kind] || d.kind}</b><div class="nw-text">${d.subject}</div></td>
      <td class="nw-line">${d.before ?? html`<span class="faint">-</span>`}</td>
      <td class="nw-line">${d.after ?? html`<span class="faint">-</span>`}</td>
      <td class="nw-nowrap" title="${dateTime(d.detected_at)}">${d.detected_at ? timeAgo(d.detected_at) : html`<span class="faint">-</span>`}${d.rev ? html`<div class="faint nw-sub">rev ${d.from_rev ?? "-"} -> ${d.rev}</div>` : ""}</td>
      <td>${d.status === "baseline" ? badge("differs from baseline", "warn") : d.status === "attributed" ? html`${badge("made by Atrium", "ok")}${d.change_id ? html`<div class="nw-sub"><a href="#/network/${enc(d.tool_id)}/changes/${enc(d.change_id)}">${d.change_id}</a></div>` : ""}`
        : d.status === "acknowledged" ? html`${badge("acknowledged")}<div class="faint nw-sub">${d.acknowledged_by} ${timeAgo(d.acknowledged_at)}</div>${d.note ? html`<div class="nw-text faint">${d.note}</div>` : ""}`
          : badge("open", d.severity === "critical" ? "bad" : "warn")}</td>
      <td>${d.status === "open" ? html`<button type="button" class="btn sm" data-act="ack" data-id="${d.id}" data-min-role="operator">${icon("check")}Acknowledge</button>` : ""}</td></tr>`)}
    </tbody></table></div>`;
}

function changesTable(items, names, { device = true } = {}) {
  return html`<div class="table-wrap"><table class="table nw-table"><thead><tr><th>Change</th>${device ? html`<th>Device</th>` : ""}<th>Lifecycle</th>
      <th>Proposed</th><th>Approval</th></tr></thead><tbody>
    ${items.map((c) => html`<tr class="clickable" data-row="change" data-id="${c.id}" data-fw="${c.firewall}">
      <td><button type="button" class="nw-link" data-act="change" data-id="${c.id}" data-fw="${c.firewall}"><b>${OP_LABEL[c.op] || c.op}</b></button>
        ${c.emergency ? badge("emergency", "bad") : ""}<div class="nw-text faint">${changeSummary(c)}</div><div class="mono faint nw-sub">${c.id}</div></td>
      ${device ? html`<td><a href="#/network/${enc(c.firewall)}/changes">${names[c.firewall] || c.firewall}</a></td>` : ""}
      <td>${lifecycle(c, true)}${c.status === "verifying" && c.rollback_until ? html`<div class="nw-sub">confirming - ${countdown(c.rollback_until)}</div>` : ""}
        ${c.status === "scheduled" ? html`<div class="faint nw-sub">${c.scheduled_for ? `applied ${dateTime(c.scheduled_for)}` : "waits for a maintenance window"}</div>` : ""}</td>
      <td class="nw-nowrap">${c.proposed_by}<div class="faint nw-sub" title="${dateTime(c.created_at)}">${timeAgo(c.created_at)}</div></td>
      <td>${c.approval ? html`${badge(c.approval.status)}${c.approval.status === "pending" ? html`<div class="nw-sub"><a href="#/approvals">Approvals</a></div>`
        : c.approval.decided_by ? html`<div class="faint nw-sub">${c.approval.decided_by}</div>` : ""}` : "-"}</td></tr>`)}
    </tbody></table></div>`;
}

const changeQuery = (status, firewall) => {
  const q = new URLSearchParams({ limit: "200" });
  if (firewall) q.set("firewall", firewall);
  if (status && status !== "active") q.set("status", status);
  return `/segmentation/changes?${q}`;
};
const activeFilter = (status) => (c) => status !== "active" || [...WAITING, ...ACTIVE].includes(c.status);

async function ackDrift(item) {
  modal({
    title: "Acknowledge drift", submit: "Acknowledge", minRole: "operator",
    body: html`<p class="muted" style="margin-bottom:12px">Acknowledging records that someone looked at this change and accepts it (control HB-NW-2 counts unexplained,
        unacknowledged drift). It does not change the device.</p>
      <p class="nw-line" style="margin-bottom:12px"><b>${DRIFT_LABEL[item.kind] || item.kind}</b>: ${item.subject}</p>
      ${field("Note (optional)", html`<input name="note" maxlength="500" placeholder="e.g. emergency change by the network team, ticket NET-123">`)}`,
    async onSubmit(data) {
      await post(`/network/drift/${enc(item.id)}/ack`, { note: String(data.get("note") || "").trim() || null });
      toast("Drift acknowledged", "ok");
    },
  });
}

function connectHelp(fake) {
  const m = modal({
    title: "Connect a network device", submit: null, cancel: "Close", wide: true,
    body: html`<ol class="nw-steps">
        <li><b>Import the device as a tool</b> - in Apps, "Import tool", choose SaaS / web service and enter its management address.</li>
        <li><b>Pick its connector</b> in the tool's Connection tab: ${VENDORS}${fake ? ", or the fake firewall (development)" : ""}.
          Use a read-only account or API key: Atrium only reads devices until device changes are switched on.</li>
        <li><b>Test the connection.</b> The checklist shows reachability, TLS, authentication, privileges, version and API features.</li>
        <li><b>Approve the proposed network data flow</b> in Approvals. The Network Supervisor then reads the device every 10 minutes.</li></ol>
      <div class="notice">${icon("lock")}<div class="muted">Device changes are off by default. An administrator can switch them on in Settings > Network changes;
        every change is then a proposal approved by a second administrator, with a backup first, a maintenance window and an automatic rollback.</div></div>`,
    footer: html`<button type="button" class="btn" data-close>Close</button>
      <button type="button" class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import a tool</button>`,
  });
  actions(m.el, { import: () => { m.close(); openImport(); } });
}

async function refreshDevices(ids, btn) {
  if (btn) btn.disabled = true;
  try {
    const r = ids.length === 1 ? await post(`/network/devices/${enc(ids[0])}/refresh`) : await post("/network/refresh", { tool_ids: ids });
    const failed = (r.results || []).filter((x) => !x.ok);
    const skipped = r.skipped || [];
    const why = (x) => (typeof x.error === "string" ? x.error : x.error?.message) || x.detail;
    if (failed.length) toast(failed.map(why).filter(Boolean).join("; ") || "The device could not be read", "bad");
    else if (skipped.length && !r.started?.length) toast(skipped.map((s) => s.reason).join("; "), "warn");
    else toast(r.results?.length === 1 ? r.results[0].detail || "Read" : `${plural(r.started?.length || 0, "device")} read`, "ok");
  } catch (err) {
    if (err.status !== 401) toast(err.message, "bad");
  } finally {
    if (btn?.isConnected) btn.disabled = false;
  }
}

// ---------- the device list ----------

async function renderList(el, ctx, initialTab) {
  let tab = initialTab;
  let data = null;
  let changes = null;
  let drift = null;
  const f = { driftStatus: "open", driftDevice: "", changeStatus: "active", changeDevice: "" };
  const $ = (sel) => el.querySelector(sel);

  setHTML(el, html`
    <div class="page-head"><div><h1>Network</h1><p class="muted">The firewalls, routers, switches and host firewalls Atrium reads: their rules, interfaces and zones,
        configuration history, drift and backups. Changes are proposals that an administrator approves.</p></div>
      <div class="row"><button type="button" class="btn" data-act="help">${icon("plug")}Connect a device</button>
        <button type="button" class="btn" data-act="refresh-all" data-min-role="operator">${icon("refresh")}Read all now</button></div></div>
    <div data-guard></div><div data-stats></div><div class="tabs" data-tabs role="tablist"></div><div data-body></div>`);

  const names = () => Object.fromEntries((data?.devices || []).map((d) => [d.tool_id, d.name]));

  const drawHead = () => {
    const devs = data.devices;
    const failing = devs.filter((d) => ["failing", "untested", "none"].includes(d.connection?.state)).length;
    const driftOpen = devs.reduce((n, d) => n + (d.drift?.open || 0), 0);
    const critical = devs.reduce((n, d) => n + (d.drift?.critical || 0), 0);
    const oldBackups = devs.filter((d) => d.backup?.supported && (!d.backup.last_at || Date.now() / 1000 - d.backup.last_at > WEEK)).length;
    const inFlight = (changes?.changes || []).filter((c) => [...WAITING, ...ACTIVE].includes(c.status)).length;
    const all = $('[data-act="refresh-all"]');
    if (all) all.disabled = !devs.length;
    const kinds = Object.entries(devs.reduce((acc, d) => ({ ...acc, [d.kind || "unread"]: (acc[d.kind || "unread"] || 0) + 1 }), {}))
      .map(([k, n]) => plural(n, k)).join(", ");
    setHTML($("[data-guard]"), data.device_changes
      ? html`<div class="notice warn" style="margin-bottom:16px">${icon("alert")}<div><b>Device changes are on.</b> <span class="muted">People can propose rule changes; each needs an administrator's
          approval and is applied with a backup, verification and an automatic rollback.</span> <a href="#/settings/network">Network changes settings</a></div></div>`
      : html`<div class="notice" style="margin-bottom:16px">${icon("lock")}<div><b>Atrium only reads these devices.</b> <span class="muted">Device changes are off (the default).
          An administrator can switch them on in</span> <a href="#/settings/network">Settings > Network changes</a>.</div></div>`);
    setHTML($("[data-stats]"), html`<div class="grid cols-5" style="margin-bottom:16px">
      ${stat("Devices", devs.length, kinds, "network")}
      ${stat("Connections not ok", failing, failing ? "failing, untested or missing" : devs.length ? "every device answers" : "", "plug", failing ? "alarm" : "")}
      ${stat("Open drift", driftOpen, critical ? `${critical} critical` : "unexplained configuration changes", "activity", critical ? "alarm" : "", "#/network/drift")}
      ${stat("Changes in progress", inFlight, "proposed, approved, scheduled or applying", "flow", "", "#/network/changes")}
      ${stat("Backups older than 7 days", oldBackups, "control HB-NW-4", "database", oldBackups ? "alarm" : "")}</div>`);
    setHTML($("[data-tabs]"), [["devices", `Devices (${devs.length})`], ["drift", `Drift (${driftOpen} open)`], ["changes", `Changes (${inFlight} in progress)`]]
      .map(([k, label]) => html`<button type="button" role="tab" aria-selected="${tab === k ? "true" : "false"}" class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`));
  };

  const drawDevices = () => {
    const devs = data.devices;
    setHTML($("[data-body]"), devs.length ? html`<section class="card flush"><div class="table-wrap"><table class="table nw-table"><thead><tr>
        <th>Device</th><th>Connection</th><th>Snapshot</th><th>Rules</th><th>Drift</th><th>Backup</th><th>Changes</th><th>Baseline</th></tr></thead><tbody>
      ${devs.map((d) => html`<tr class="clickable" data-row="device" data-id="${d.tool_id}">
        <td><div class="row" style="gap:10px;flex-wrap:nowrap">${kindTile(d)}<div style="min-width:0"><a href="#/network/${enc(d.tool_id)}"><b>${d.name}</b></a>
          <div class="faint nw-sub">${[d.vendor, d.model, d.version].filter(Boolean).join(" ") || d.connector || "not read yet"}${d.management_address ? ` - ${d.management_address}` : ""}</div></div></div></td>
        <td>${connCell(d.connection)}${d.flow && d.flow.status !== "enabled" ? html`<div class="nw-sub">${badge(`flow ${d.flow.status}`, "warn")}</div>` : !d.flow ? html`<div class="nw-sub">${badge("no data flow", "warn")}</div>` : ""}</td>
        <td>${snapshotCell(d)}</td>
        <td class="nw-nowrap">${d.snapshot ? html`${d.counts.enabled_rules}<span class="faint">/${d.counts.rules}</span><div class="faint nw-sub">${d.counts.pass_rules} pass, ${plural(d.counts.interfaces, "interface")}</div>` : "-"}</td>
        <td>${driftCell(d.drift)}</td><td>${backupCell(d.backup)}</td><td>${writeCell(d.write)}</td><td>${baselineText(d.baseline)}</td></tr>`)}
      </tbody></table></div></section>`
      : html`<section class="card">${emptyState("network", "No network devices yet",
        html`Import a firewall, router, switch or host as a tool and connect it in its Connection tab (${VENDORS}). Atrium reads its rules, interfaces and zones;
          changes are off by default.`,
        html`<button type="button" class="btn primary" data-act="help">How to connect a device</button>`)}
        ${data.fake_devices ? html`<p class="faint" style="text-align:center;font-size:12.5px;margin-top:-12px;padding-bottom:12px">Development: the fake firewall connector is registered (HUB_DEV_FAKE_DEVICES=1).</p>` : ""}</section>`);
  };

  const filterRow = (kind) => {
    const deviceOpts = [["", "Every device"], ...data.devices.map((d) => [d.tool_id, d.name])];
    return kind === "drift"
      ? html`<div class="row filters" style="margin-bottom:12px"><select class="input-sm" data-filter="driftStatus" aria-label="Drift status">${options(DRIFT_STATUS, f.driftStatus)}</select>
          <select class="input-sm" data-filter="driftDevice" aria-label="Device">${options(deviceOpts, f.driftDevice)}</select><span class="spacer"></span>
          <span class="faint" style="font-size:12.5px">${drift.total} item${drift.total === 1 ? "" : "s"}${drift.counts?.critical_open ? ` - ${drift.counts.critical_open} critical open` : ""}</span></div>`
      : html`<div class="row filters" style="margin-bottom:12px"><select class="input-sm" data-filter="changeStatus" aria-label="Status">${options(CHANGE_STATUS, f.changeStatus)}</select>
          <select class="input-sm" data-filter="changeDevice" aria-label="Device">${options(deviceOpts, f.changeDevice)}</select></div>`;
  };

  const drawDrift = () => {
    setHTML($("[data-body]"), html`${filterRow("drift")}<section class="card flush">${drift.items.length ? driftTable(drift.items, names())
      : emptyState("checkCircle", f.driftStatus === "open" ? "No open drift" : "Nothing here", "Each read compares the device with the previous snapshot and its baseline. Changes nobody made through Atrium show up here to acknowledge.")}</section>`);
  };

  const drawChanges = () => {
    const shown = (changes?.changes || []).filter(activeFilter(f.changeStatus));
    setHTML($("[data-body]"), html`${filterRow("changes")}<section class="card flush">${shown.length ? changesTable(shown, names())
      : emptyState("flow", "No changes here", data.device_changes ? "Rule changes are proposed from the segmentation map in the Integration hub; restores from a device's Backups tab."
        : "Device changes are off: Atrium only reads devices. An administrator switches them on in Settings > Network changes.")}</section>`);
  };

  const draw = () => keepFocus(() => {
    drawHead();
    if (tab === "drift") drawDrift(); else if (tab === "changes") drawChanges(); else drawDevices();
  });

  const load = async () => {
    const driftQ = new URLSearchParams({ limit: "500" });
    if (f.driftStatus) driftQ.set("status", f.driftStatus);
    if (f.driftDevice) driftQ.set("tool_id", f.driftDevice);
    [data, changes, drift] = await Promise.all([get("/network/devices"), get(changeQuery(f.changeStatus, f.changeDevice)),
      tab === "drift" ? get(`/network/drift?${driftQ}`) : Promise.resolve(drift)]);
    if (el.isConnected) draw();
  };
  const reload = () => load().catch((err) => toast(err.message, "bad"));

  actions(el, {
    tab(d) {
      tab = d.tab;
      history.replaceState(null, "", tab === "devices" ? "#/network" : `#/network/${tab}`);
      reload();
    },
    help: () => connectHelp(data?.fake_devices),
    "refresh-all": (_, btn) => refreshDevices(data.devices.map((d) => d.tool_id), btn).then(reload),
    ack(d) { const item = drift?.items.find((x) => x.id === d.id); if (item) ackDrift(item); },
    change: (d) => openChange(d.id, { deviceName: names()[d.fw] }).catch((err) => toast(err.message, "bad")),
  });
  onRowClick(el, (row) => {
    if (row.dataset.row === "device") location.hash = `#/network/${enc(row.dataset.id)}`;
    else openChange(row.dataset.id, { deviceName: names()[row.dataset.fw] }).catch((err) => toast(err.message, "bad"));
  });
  el.addEventListener("change", (e) => {
    const key = e.target.dataset?.filter;
    if (!key) return;
    f[key] = e.target.value;
    reload();
  });
  await load();
  startTicker(el);
  ctx.live(LIVE, reload, 600);
}

// ---------- one device ----------

function endpoint(e, names) {
  if (!e || e.any || !(e.cidrs?.length || e.aliases?.length || e.nets?.length || e.self)) {
    return html`${e?.negate ? html`<b title="not">!</b>` : ""}<span class="nw-any">any</span>`;
  }
  const parts = [...(e.nets || []).map((n) => `${names[n] || n} net`), ...(e.aliases || []), ...(e.cidrs || []), ...(e.self ? ["this device"] : [])];
  return html`${e.negate ? html`<b title="not">! </b>` : ""}${parts.map((p) => html`<span class="nw-tok">${p}</span>`)}`;
}

function services(list) {
  if (!list?.length) return html`<span class="nw-any">any</span>`;
  return list.map((s) => html`<span class="nw-tok">${s.ports ? `${s.proto}/${s.ports}` : s.alias ? `${s.proto}/${s.alias}` : s.proto}</span>`);
}

function where(r, names) {
  const parts = [];
  if (r.interfaces?.length) parts.push(`${r.direction === "out" ? "out on" : "on"} ${r.interfaces.map((i) => names[i] || i).join(", ")}`);
  if (r.out_interfaces?.length) parts.push(`to ${r.out_interfaces.map((i) => names[i] || i).join(", ")}`);
  if (r.source_zones?.length || r.destination_zones?.length) parts.push(`zones ${(r.source_zones || []).join(",") || "any"} > ${(r.destination_zones || []).join(",") || "any"}`);
  if (!parts.length) parts.push(r.floating ? "floating" : "any interface");
  return parts.join(" ");
}

const ACTION_TONE = { pass: "ok", block: "bad", reject: "bad" };

function rulesTable(rules, names, toolId) {
  return html`<div class="table-wrap"><table class="table compact nw-table nw-rules"><thead><tr><th title="Evaluation order">#</th><th>Action</th><th>Where</th>
      <th>Source</th><th>Destination</th><th>Services</th><th>Description</th><th title="Hit counter, when the device reports one">Hits</th></tr></thead><tbody>
    ${rules.map((r) => html`<tr class="${r.enabled === false ? "off" : ""}" title="${r.line || ""}">
      <td class="mono">${r.order}</td>
      <td class="nw-nowrap">${badge(r.action, ACTION_TONE[r.action] ?? "")}${r.enabled === false ? badge("disabled") : ""}${r.log ? html`<span class="faint nw-sub" title="Matches are logged"> log</span>` : ""}</td>
      <td>${where(r, names)}</td><td>${endpoint(r.source, names)}</td><td>${endpoint(r.destination, names)}</td><td>${services(r.services)}</td>
      <td class="nw-desc">${r.description ? html`<span class="nw-text">${r.description}</span>` : html`<span class="faint">-</span>`}
        ${r.marker ? html`<div><a class="badge accent" href="#/network/${enc(toolId)}/changes/${enc(r.marker)}" title="The description carries an Atrium change marker">atrium:${r.marker}</a></div>` : ""}
        <div class="mono faint nw-sub" title="The device's own id for this rule">${r.vendor_ref}</div></td>
      <td class="mono">${r.hits ?? html`<span class="faint">-</span>`}</td></tr>`)}
    </tbody></table></div>`;
}

function interfacesView(rec) {
  const names = Object.fromEntries((rec.interfaces || []).map((i) => [i.id, i.name || i.id]));
  return html`<section class="card flush" style="margin-bottom:16px"><header><h2>Interfaces</h2><span class="faint">${rec.interfaces.length}</span></header>
      <div class="table-wrap"><table class="table compact nw-table"><thead><tr><th>Interface</th><th>Role</th><th>VLAN</th><th>Networks</th><th>Addresses</th><th>State</th></tr></thead><tbody>
      ${rec.interfaces.map((i) => html`<tr><td><b>${i.name || i.id}</b><div class="mono faint nw-sub">${i.id}</div>${i.description ? html`<div class="nw-text faint">${i.description}</div>` : ""}</td>
        <td>${badge(i.role, i.role === "wan" ? "warn" : i.role === "mgmt" ? "info" : "")}</td><td>${i.vlan ?? html`<span class="faint">-</span>`}</td>
        <td>${(i.subnets || []).map((s) => html`<span class="nw-tok">${s}</span>`)}</td><td>${(i.addresses || []).map((s) => html`<span class="nw-tok">${s}</span>`)}</td>
        <td>${i.enabled === false ? badge("disabled") : badge("up", "ok")}</td></tr>`)}</tbody></table></div></section>
    <div class="grid cols-3" style="margin-bottom:16px">
      <section class="card"><header><h2>Zones</h2><span class="faint">${rec.zones.length}</span></header>
        ${rec.zones.length ? html`<div class="stack" style="gap:8px">${rec.zones.map((z) => html`<div><b>${z.name || z.id}</b> <span class="mono faint">${z.id}</span>
            <div class="nw-sub">${(z.interfaces || []).map((i) => html`<span class="nw-tok">${names[i] || i}</span>`)}</div>${z.description ? html`<div class="nw-text faint">${z.description}</div>` : ""}</div>`)}</div>`
          : html`<p class="muted" style="font-size:12.5px">This device has no vendor zones: each interface acts as a zone on the segmentation map.</p>`}</section>
      <section class="card"><header><h2>Defaults</h2></header><dl class="kv">
        ${Object.entries(rec.default_policy || {}).map(([k, v]) => html`<dt>${k}</dt><dd>${badge(v, v === "pass" ? "warn" : v === "unknown" ? "" : "ok")}</dd>`)}
        <dt>Device addresses</dt><dd>${(rec.self_addresses || []).map((a) => html`<span class="nw-tok">${a}</span>`)}</dd>
        <dt>NAT</dt><dd>${rec.nat_evaluated ? "evaluated" : html`<span class="faint">not evaluated</span>`}</dd></dl></section>
      <section class="card"><header><h2>Read notes</h2></header>
        ${[...(rec.notes || []), ...(rec.errors || [])].length ? html`<ul class="nw-notes">${(rec.notes || []).map((n) => html`<li>${n}</li>`)}${(rec.errors || []).map((n) => html`<li class="warn-text">${n}</li>`)}</ul>`
          : html`<p class="faint" style="font-size:12.5px">None.</p>`}</section></div>
    <section class="card flush"><header><h2>Aliases</h2><span class="faint">${rec.aliases.length}</span></header>
      ${rec.aliases.length ? html`<div class="table-wrap"><table class="table compact nw-table"><thead><tr><th>Name</th><th>Kind</th><th>Contents</th><th>Resolved</th></tr></thead><tbody>
        ${rec.aliases.map((a) => html`<tr><td class="nw-text"><b>${a.name}</b></td><td>${a.kind}</td>
          <td>${(a.cidrs || []).map((c) => html`<span class="nw-tok">${c}</span>`)}${a.ports ? html`<span class="nw-tok">${a.ports}</span>` : ""}</td>
          <td>${a.resolved === false ? badge("unresolved", "warn") : badge("yes", "ok")}</td></tr>`)}</tbody></table></div>`
        : html`<p class="faint" style="padding:0 16px 16px;font-size:12.5px">No aliases.</p>`}</section>`;
}

const driftSummary = (counts) => Object.entries(counts || {}).map(([k, n]) => html`<span class="badge">${n} ${(DRIFT_LABEL[k] || k).toLowerCase()}</span>`);

async function downloadBackup(b, btn) {
  btn.disabled = true;
  try {
    const res = await fetch(`/api/network/backups/${enc(b.id)}/download`);
    if (res.status === 401) window.dispatchEvent(new CustomEvent("atrium:signed-out"));
    if (!res.ok) {
      const data = await res.json().catch(() => null);
      const detail = data?.detail;
      throw new Error(typeof detail === "string" ? detail : detail?.message || `${res.status} ${res.statusText}`);
    }
    const name = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "")?.[1] || `${b.id}.${b.format || "bin"}`;
    const url = URL.createObjectURL(await res.blob());
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
    toast(`${name} downloaded (the download is logged)`, "ok");
  } catch (err) {
    toast(err.message, "bad");
  } finally {
    btn.disabled = false;
  }
}

async function renderDevice(el, ctx, id, initialTab, openId) {
  let tab = DEVICE_TABS.some(([k]) => k === initialTab) ? initialTab : "rules";
  let d = null;
  let conn = null;
  let changes = [];
  let drift = null;
  let diff = null;
  let netSettings = null;
  const ui = { q: "", action: "", disabled: true, driftStatus: "open", from: "", to: "" };
  const $ = (sel) => el.querySelector(sel);
  const names = () => Object.fromEntries((d.record?.interfaces || []).map((i) => [i.id, i.name || i.id]));

  const head = () => {
    const w = d.write;
    const checks = conn?.last_test?.checks || [];
    return html`
      <div class="page-head"><div class="row" style="gap:14px;flex-wrap:nowrap;align-items:flex-start">${kindTile(d)}<div style="min-width:0">
          <h1 class="nw-title">${d.name}</h1>
          <p class="muted">${[d.vendor, d.model, d.version].filter(Boolean).join(" ") || "Not read yet"}${d.hostname ? ` - ${d.hostname}` : ""}${d.management_address ? ` - ${d.management_address}` : ""}
            ${d.kind ? html` - ${d.kind}` : ""}</p></div></div>
        <div class="row"><a class="btn" href="#/tools/${enc(d.tool_id)}/connection">${icon("plug")}Connection</a>
          <button type="button" class="btn" data-act="refresh" data-min-role="operator">${icon("refresh")}Read now</button>
          ${d.backup?.supported ? html`<button type="button" class="btn" data-act="backup" data-min-role="operator">${icon("database")}Take backup</button>` : ""}</div></div>
      ${changes.filter((c) => ACTIVE.includes(c.status) || c.status === "scheduled").map((c) => html`<div style="margin-bottom:12px">${stateBanner(c, d.name)}
        <div style="margin:-4px 0 0 2px"><button type="button" class="nw-link" data-act="change" data-id="${c.id}">Open change ${c.id}</button></div></div>`)}
      <div class="grid cols-3 nw-cards" style="margin-bottom:16px">
        <section class="card"><header><h2>Connection</h2>${connCell(d.connection)}</header>
          ${checks.length ? html`<div class="nw-checks">${checks.map((c) => html`<div class="nw-check" title="${c.detail || ""}"><span class="dot ${c.ok ? "ok" : "bad"}"></span>
            <span>${String(c.name).replace(/_/g, " ")}</span><span class="faint nw-text">${c.detail || ""}</span></div>`)}</div>`
            : html`<p class="faint" style="font-size:12.5px">${d.connection?.detail || "Test the connection in the tool's Connection tab."}</p>`}
          ${d.flow ? html`<p class="faint nw-sub" style="margin-top:8px">Read every ${d.flow.schedule_minutes} min by the Network Supervisor${d.flow.last_run ? html`, last ${timeAgo(d.flow.last_run)}` : ""}
            ${d.flow.error ? html` - <span class="warn-text">${d.flow.error}</span>` : ""}</p>` : html`<p class="warn-text nw-sub" style="margin-top:8px">No network data flow: approve it in Approvals.</p>`}</section>
        <section class="card"><header><h2>Snapshot</h2>${d.snapshot?.stale ? badge("stale", "warn") : d.snapshot ? badge("fresh", "ok") : ""}</header>
          ${d.snapshot ? html`<dl class="kv"><dt>Revision</dt><dd>rev ${d.snapshot.rev} <span class="mono faint">${d.snapshot.revision}</span></dd>
            <dt>Read</dt><dd title="${dateTime(d.snapshot.read_at)}">${timeAgo(d.snapshot.read_at)}</dd>
            <dt>Rules</dt><dd>${d.counts.enabled_rules} enabled of ${d.counts.rules} (${d.counts.pass_rules} pass)</dd>
            <dt>Baseline</dt><dd>${baselineText(d.baseline)}</dd>
            <dt>Drift</dt><dd>${driftCell(d.drift)}</dd></dl>` : html`<p class="muted" style="font-size:12.5px">Not read yet: read it now, or wait for its data flow.</p>`}</section>
        <section class="card"><header><h2>Changes</h2>${w.capable ? (w.writable ? badge("possible", "ok") : badge("not now")) : badge("read-only")}</header>
          ${w.capable ? html`<dl class="kv"><dt>Operations</dt><dd>${w.ops.map((o) => html`<span class="nw-tok">${o.replace(/_/g, " ")}</span>`)}</dd>
              <dt>Rollback</dt><dd>${rollbackLabel(w.rollback)}<div class="faint nw-sub">${ROLLBACK[w.rollback?.mode]?.[1] || ""}</div></dd></dl>`
            : html`<p class="muted" style="font-size:12.5px">${REASONS.not_capable}. Atrium reads it only.</p>`}
          ${w.reasons?.length ? html`<ul class="nw-notes">${w.reasons.filter((r) => r !== "not_capable").map((r) => html`<li>${reasonText(r)}</li>`)}</ul>` : ""}</section>
      </div>
      <div class="tabs" role="tablist">${DEVICE_TABS.map(([k, label]) => {
        const n = k === "rules" ? d.counts.rules : k === "history" ? d.history.length : k === "drift" ? d.drift.open : k === "backups" ? d.backups.length
          : k === "changes" ? changes.length : null;
        return html`<button type="button" role="tab" aria-selected="${tab === k ? "true" : "false"}" class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}${n !== null ? ` (${n})` : ""}</button>`;
      })}</div>`;
  };

  const shownRules = () => {
    const q = ui.q.trim().toLowerCase();
    return d.record.rules.filter((r) => (ui.disabled || r.enabled !== false) && (!ui.action || r.action === ui.action)
      && (!q || [r.line, r.vendor_ref, r.id].join(" ").toLowerCase().includes(q)));
  };
  const rulesTableBody = (rules) => html`<section class="card flush">${rules.length ? rulesTable(rules, names(), d.tool_id)
    : emptyState("search", "No rules match", "Change the search or the filters.")}</section>`;
  const rulesBody = () => {
    const rec = d.record;
    if (!rec) return html`<section class="card">${emptyState("network", "Not read yet", "Read the device to see its rules.")}</section>`;
    const rules = shownRules();
    return html`<div class="row filters" style="margin-bottom:12px">
        <input id="nw-rule-q" type="search" value="${ui.q}" placeholder="Search rules: address, port, interface, description..." aria-label="Search rules" style="max-width:320px">
        <select class="input-sm" data-ui="action" aria-label="Action">${options([["", "Any action"], ["pass", "Pass"], ["block", "Block"], ["reject", "Reject"]], ui.action)}</select>
        <label class="check"><input type="checkbox" data-ui="disabled" ${ui.disabled ? "checked" : ""}> Show disabled rules</label>
        <span class="spacer"></span><span class="faint" style="font-size:12.5px" data-rule-count>${rules.length} of ${rec.rules.length}</span></div>
      <div data-rules>${rulesTableBody(rules)}</div>
      <p class="faint" style="font-size:12px;margin-top:8px">Read-only: the rule text comes from the device. Default: ${Object.entries(rec.default_policy || {}).map(([k, v]) => `${k} ${v}`).join(", ") || "unknown"}.
        ${rec.nat_evaluated ? "" : "NAT is not evaluated."}</p>`;
  };
  const drawRules = () => {
    const box = $("[data-rules]");
    if (!box || !d.record) return draw();
    const rules = shownRules();
    setHTML(box, rulesTableBody(rules));
    $("[data-rule-count]").textContent = `${rules.length} of ${d.record.rules.length}`;
  };

  const historyBody = () => {
    const hist = d.history;
    if (!hist.length) return html`<section class="card">${emptyState("clock", "No history yet", "Atrium keeps a revision each time the configuration it reads changes.")}</section>`;
    const revs = hist.map((h) => [String(h.rev), `rev ${h.rev} - ${dateTime(h.read_at)}`]);
    return html`<section class="card" style="margin-bottom:16px"><header><h2>Compare revisions</h2><span class="faint" style="font-size:12.5px">${hist.length} revision${hist.length === 1 ? "" : "s"} kept${d.settings?.history_limit ? ` (at most ${d.settings.history_limit})` : ""}</span></header>
        <div class="row" style="margin-bottom:10px"><label class="faint" for="nw-from">From</label><select id="nw-from" class="input-sm" data-ui="from">${options(revs, ui.from)}</select>
          <label class="faint" for="nw-to">to</label><select id="nw-to" class="input-sm" data-ui="to">${options([["", "current snapshot"], ...revs], ui.to)}</select>
          <button type="button" class="btn sm" data-act="compare">${icon("arrow")}Compare</button></div>
        <div data-diff>${diff === null ? html`<p class="faint" style="font-size:12.5px">Pick two revisions.</p>` : diff.diff ? diffView(diff.diff)
          : html`<p class="muted" style="font-size:12.5px">No difference between rev ${diff.from_rev} and ${diff.to_rev ? `rev ${diff.to_rev}` : "the current snapshot"}.</p>`}</div></section>
      <section class="card flush"><div class="table-wrap"><table class="table nw-table"><thead><tr><th>Revision</th><th>Read</th><th>Cause</th><th>What changed</th><th>Hash</th><th></th></tr></thead><tbody>
        ${hist.map((h, i) => html`<tr><td><b>rev ${h.rev}</b> <span class="mono faint">${h.revision}</span>${i === 0 ? html` ${badge("current", "ok")}` : ""}</td>
          <td title="${dateTime(h.read_at)}">${timeAgo(h.read_at)}</td>
          <td>${h.cause ? html`<a href="#/network/${enc(d.tool_id)}/changes/${enc(h.cause)}">${h.cause}</a>` : html`<span class="faint">read</span>`}</td>
          <td><div class="tag-list">${driftSummary(h.drift)}</div>${Object.keys(h.drift || {}).length || i === hist.length - 1 ? "" : html`<span class="faint">-</span>`}${i === hist.length - 1 && !Object.keys(h.drift || {}).length ? html`<span class="faint">first kept revision</span>` : ""}</td>
          <td class="mono faint" title="${h.hash}">${String(h.hash || "").replace("sha256:", "").slice(0, 12)}</td>
          <td>${i < hist.length - 1 ? html`<button type="button" class="btn sm" data-act="diff-prev" data-rev="${h.rev}" data-prev="${hist[i + 1].rev}">Diff</button>` : ""}</td></tr>`)}
      </tbody></table></div></section>`;
  };

  const driftBody = () => {
    const b = d.baseline;
    return html`<section class="card" style="margin-bottom:16px"><header><h2>Baseline</h2>${baselineText(b)}</header>
        <p class="muted" style="font-size:12.5px;margin-bottom:10px">An approved configuration to compare every read against. Accepting the current snapshot as the baseline
          acknowledges the device's open drift.</p>
        ${b?.rev ? html`<dl class="kv" style="margin-bottom:10px"><dt>Baseline</dt><dd>rev ${b.rev}${b.revision ? html` <span class="mono faint">${b.revision}</span>` : ""}</dd>
          <dt>Accepted</dt><dd>${b.accepted_by || "-"} ${b.accepted_at ? timeAgo(b.accepted_at) : ""}</dd></dl>` : ""}
        <div class="row" data-min-role="admin"><button type="button" class="btn sm" data-act="baseline" ${d.snapshot ? "" : "disabled"}>${icon("flag")}Accept current as baseline</button>
          ${b?.rev ? html`<button type="button" class="btn sm danger" data-act="baseline-clear">${icon("x")}Remove baseline</button>` : ""}</div>
        ${d.baseline_deviations?.length ? html`<h3 style="margin:14px 0 8px">Differences from the baseline (${d.baseline_deviations.length})</h3>${driftTable(d.baseline_deviations.map((x) => ({ ...x, status: "baseline" })), {}, { device: false })}` : ""}</section>
      <div class="row filters" style="margin-bottom:12px"><select class="input-sm" data-ui="driftStatus" aria-label="Drift status">${options(DRIFT_STATUS, ui.driftStatus)}</select>
        <span class="faint" style="font-size:12.5px">Changes between consecutive reads. Changes Atrium made itself are attributed to their change.</span></div>
      <section class="card flush">${drift?.items.length ? driftTable(drift.items, {}, { device: false })
        : emptyState("checkCircle", ui.driftStatus === "open" ? "No open drift" : "Nothing here", "Configuration changes nobody made through Atrium show up here to acknowledge.")}</section>`;
  };

  const backupsBody = () => {
    const s = d.settings || {};
    // a restore rewrites the configuration: it needs a writable device (not read only, a rollback) and a connector that restores
    const restoreBlocked = [...new Set([...(d.backup?.restore ? [] : ["not_capable"]),
      ...(d.write.reasons || []).filter((r) => r !== "op_not_supported")])];
    if (!d.backup?.supported) {
      return html`<section class="card">${emptyState("database", "Backups not supported", "This device's connector cannot take configuration backups. Back it up with the vendor's own tools.")}</section>`;
    }
    return html`<div class="notice" style="margin-bottom:12px">${icon("lock")}<div class="muted">Backups are stored encrypted with a SHA-256 checksum${s.backup_retention ? `; the last ${s.backup_retention} per device are kept` : ""}${s.backup_interval_hours ? `, a scheduled one every ${s.backup_interval_hours} h` : ""}.
        Only administrators download them (logged). Restoring one is a change proposal that another administrator approves.</div></div>
      <section class="card flush">${d.backups.length ? html`<div class="table-wrap"><table class="table nw-table"><thead><tr><th>Taken</th><th>Reason</th><th>By</th><th>Device revision</th>
          <th>Size</th><th>SHA-256</th><th></th></tr></thead><tbody>
        ${d.backups.map((b) => html`<tr><td title="${dateTime(b.taken_at)}">${dateTime(b.taken_at)}<div class="faint nw-sub">${timeAgo(b.taken_at)}</div></td>
          <td>${badge(b.reason, b.reason === "pre-change" ? "info" : "")}${b.change_id ? html`<div class="nw-sub"><a href="#/network/${enc(d.tool_id)}/changes/${enc(b.change_id)}">${b.change_id}</a></div>` : ""}</td>
          <td>${b.taken_by}</td><td class="mono">${b.revision || "-"}</td><td class="nw-nowrap">${(b.size / 1024).toFixed(1)} KB <span class="faint">${b.format}</span></td>
          <td class="mono faint" title="${b.sha256}">${String(b.sha256).slice(0, 12)}</td>
          <td class="nw-nowrap"><button type="button" class="btn sm" data-act="download" data-id="${b.id}" data-min-role="admin">${icon("download")}Download</button>
            <button type="button" class="btn sm" data-act="restore" data-id="${b.id}" data-min-role="operator" ${restoreBlocked.length ? html`disabled title="${restoreBlocked.map(reasonText).join("\n")}"` : ""}>${icon("undo")}Restore...</button></td></tr>`)}
        </tbody></table></div>` : emptyState("database", "No backups yet", "Take one now; the Network Supervisor also takes one before every change and on a schedule.",
          html`<button type="button" class="btn" data-act="backup" data-min-role="operator">${icon("database")}Take backup</button>`)}</section>
      ${restoreBlocked.length ? html`<p class="faint" style="font-size:12px;margin-top:8px">Restore is not possible now: ${restoreBlocked.map(reasonText).join("; ")}.</p>` : ""}`;
  };

  const changesBody = () => html`<section class="card flush">${changes.length ? changesTable(changes, { [d.tool_id]: d.name }, { device: false })
    : emptyState("flow", "No changes yet", d.write.capable ? "Rule changes are proposed from the segmentation map in the Integration hub, restores from the Backups tab. Each needs an administrator's approval."
      : "This device is read-only for Atrium.")}</section>`;

  const draw = () => keepFocus(() => {
    ctx.crumb(`Network / ${d.name}`);
    const body = tab === "interfaces" ? (d.record ? interfacesView(d.record) : html`<section class="card">${emptyState("network", "Not read yet", "Read the device first.")}</section>`)
      : tab === "history" ? historyBody() : tab === "drift" ? driftBody() : tab === "backups" ? backupsBody() : tab === "changes" ? changesBody() : rulesBody();
    setHTML(el, html`${head()}<div data-tab-body>${body}</div>`);
  });

  const load = async () => {
    const driftQ = new URLSearchParams({ tool_id: id, limit: "500" });
    if (ui.driftStatus) driftQ.set("status", ui.driftStatus);
    let detail;
    try {
      detail = await get(`/network/devices/${enc(id)}`);
    } catch (err) {
      if (err.status !== 404) throw err;
      ctx.crumb("Network / device not found");
      setHTML(el, html`<section class="card">${emptyState("network", "Device not found", "It is not a connected network device (any more).",
        html`<a class="btn" href="#/network">${icon("arrow")}All devices</a>`)}</section>`);
      return false;
    }
    const [c, ch, dr, st] = await Promise.all([get(`/tools/${enc(id)}/connection`).catch(() => null), get(changeQuery("", id)),
      tab === "drift" ? get(`/network/drift?${driftQ}`) : Promise.resolve(drift), netSettings ? Promise.resolve(netSettings) : get("/network/settings").catch(() => ({}))]);
    d = { ...detail, settings: st };
    netSettings = st;
    [conn, changes, drift] = [c, ch.changes, dr];
    if (!ui.from && d.history.length > 1) ui.from = String(d.history[1].rev);
    if (el.isConnected) draw();
    return true;
  };
  const reload = () => load().catch((err) => toast(err.message, "bad"));

  const compare = async (from, to) => {
    try {
      diff = await get(`/network/devices/${enc(id)}/diff?${new URLSearchParams({ from_rev: from, ...(to ? { to_rev: to } : {}) })}`);
    } catch (err) {
      diff = null;
      if (err.status !== 401) toast(err.message, "bad");
    }
    if (el.isConnected) draw();
  };

  const showChange = (cid) => {
    history.replaceState(null, "", `#/network/${enc(id)}/changes/${enc(cid)}`);
    openChange(cid, {
      deviceName: d?.name,
      onClose: () => { if (location.hash.startsWith(`#/network/${enc(id)}/changes/`)) history.replaceState(null, "", `#/network/${enc(id)}/${tab}`); },
    }).catch((err) => toast(err.message, "bad"));
  };

  actions(el, {
    tab(t) {
      tab = t.tab;
      history.replaceState(null, "", `#/network/${enc(id)}${tab === "rules" ? "" : `/${tab}`}`);
      if (tab === "drift" || tab === "history") reload(); else draw();
      if (tab === "history" && diff === null && ui.from) compare(ui.from, ui.to);
    },
    refresh: (_, btn) => refreshDevices([id], btn).then(reload),
    async backup(_, btn) {
      btn.disabled = true;
      try {
        const r = await post(`/network/devices/${enc(id)}/backups`);
        toast(`Backup taken (${(r.backup.size / 1024).toFixed(1)} KB, SHA-256 ${r.backup.sha256.slice(0, 12)}...)`, "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      reload();
    },
    download(t, btn) { const b = d.backups.find((x) => x.id === t.id); if (b) downloadBackup(b, btn); },
    restore(t) { const b = d.backups.find((x) => x.id === t.id); if (b) proposeRestore(b, d.name); },
    ack(t) { const item = drift?.items.find((x) => x.id === t.id); if (item) ackDrift(item); },
    async baseline() {
      if (!(await confirmDialog("Accept the current configuration as the baseline?", `Rev ${d.snapshot?.rev} of ${d.name} becomes the approved configuration every later read is compared with. Its open drift is acknowledged.`, "Accept as baseline"))) return;
      try {
        await post(`/network/devices/${enc(id)}/baseline`);
        toast("Baseline accepted", "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      reload();
    },
    async "baseline-clear"() {
      if (!(await confirmDialog("Remove the baseline?", "Reads are then only compared with the previous snapshot.", "Remove"))) return;
      try {
        await del(`/network/devices/${enc(id)}/baseline`);
        toast("Baseline removed", "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      reload();
    },
    compare: () => (ui.from ? compare(ui.from, ui.to) : toast("Pick a revision to compare from", "warn")),
    "diff-prev"(t) {
      ui.from = t.prev;
      ui.to = t.rev === String(d.history[0]?.rev) ? "" : t.rev;
      compare(ui.from, ui.to);
    },
    change: (t) => showChange(t.id),
  });
  onRowClick(el, (row) => showChange(row.dataset.id));
  el.addEventListener("input", (e) => {
    if (e.target.id !== "nw-rule-q") return;
    ui.q = e.target.value;
    drawRules();
  });
  el.addEventListener("change", (e) => {
    const key = e.target.dataset?.ui;
    if (!key) return;
    ui[key] = e.target.type === "checkbox" ? e.target.checked : e.target.value;
    if (key === "driftStatus") reload(); else if (key === "action" || key === "disabled") drawRules(); else draw();
  });

  if (!(await load())) return;
  startTicker(el);
  if (tab === "history" && ui.from) compare(ui.from, ui.to);
  if (openId) showChange(openId);
  ctx.live([...LIVE, "approval"], reload, 600);
}

export async function render(el, ctx) {
  const [first, second, third] = ctx.params;
  if (!first || LIST_TABS.includes(first)) return renderList(el, ctx, first || "devices");
  return renderDevice(el, ctx, first, second || "rules", second === "changes" ? third : null);
}
