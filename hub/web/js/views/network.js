// Network app: devices, rules, drift, backups and approved changes. Device text is shown as text, never as HTML.
import { get, post } from "../api.js";
import { actions, badge, can, emptyState, html, icon, setHTML, timeAgo, toast } from "../ui.js";

const TABS = [["rules", "Rules"], ["interfaces", "Interfaces & zones"], ["history", "History"], ["drift", "Drift"],
  ["backups", "Backups"], ["changes", "Changes"]];

export async function render(el, ctx) {
  const toolId = ctx.params[0] || "";
  const tab = ctx.params[1] || "rules";
  if (!toolId) return drawList(el);
  return drawDevice(el, toolId, tab);
}

async function drawList(el) {
  const { devices } = await get("/network/devices");
  setHTML(el, html`<div class="page-head"><div><h1>Network</h1>
    <p class="muted">Firewalls, routers, switches and host firewalls. Device changes are off until an administrator turns them on.</p></div></div>
    ${devices.length ? html`<div class="stack">${devices.map(deviceCard)}</div>`
      : emptyState("radar", "No network devices yet", "Connect a firewall or host firewall from Apps. Its connection needs a network read, and a data flow pulls a snapshot.")}`);
}

function deviceCard(d) {
  const write = d.write || {};
  const state = d.connection?.state || "none";
  return html`<a class="card" href="#/network/${d.tool_id}" style="display:block;text-decoration:none;color:inherit">
    <div class="row" style="gap:8px"><b>${d.name}</b>
      ${badge(state, state === "ok" ? "ok" : state === "failing" ? "bad" : "warn")}
      ${d.drift?.open ? badge(`${d.drift.open} drift`, d.drift.critical ? "bad" : "warn") : badge("no open drift", "ok")}
      <span class="spacer"></span>
      <span class="faint">${write.capable ? (write.rollback ? write.rollback.mode : "read only") : "read only"}</span></div>
    <p class="muted" style="margin:6px 0 0">${[d.vendor, d.model, d.version, d.hostname].filter(Boolean).join(" · ") || "No snapshot yet"}</p>
  </a>`;
}

async function drawDevice(el, toolId, tab) {
  const [device, drift, backups, changes] = await Promise.all([
    get(`/network/devices/${toolId}`),
    get(`/network/drift?tool_id=${encodeURIComponent(toolId)}`),
    get(`/network/backups?tool_id=${encodeURIComponent(toolId)}`),
    get(`/segmentation/changes?firewall=${encodeURIComponent(toolId)}`),
  ]);
  const record = device.record || {};
  setHTML(el, html`<div class="page-head"><div><a href="#/network" class="faint">Network</a>
    <h1>${device.name}</h1>
    <p class="muted">${[device.vendor, device.version, device.hostname].filter(Boolean).join(" · ") || "No snapshot yet"}</p></div>
    ${can("operator") ? html`<button class="btn" data-act="backup" data-min-role="operator">${icon("download")}Back up now</button>` : ""}</div>
    <div class="tabs">${TABS.map(([k, label]) => html`<a class="${tab === k ? "active" : ""}" href="#/network/${toolId}/${k}">${label}</a>`)}</div>
    ${tab === "rules" ? rulesTable(record) : ""}
    ${tab === "interfaces" ? interfacesTable(record) : ""}
    ${tab === "history" ? historyTable(device.history || []) : ""}
    ${tab === "drift" ? driftTable(drift.drift || [], device) : ""}
    ${tab === "backups" ? backupTable(backups.backups || []) : ""}
    ${tab === "changes" ? changeTable(changes.changes || []) : ""}`);
  actions(el, {
    backup: async () => {
      await post(`/network/devices/${toolId}/backups`, {});
      toast("Backup stored", "ok");
      drawDevice(el, toolId, tab);
    },
    ack: async (b) => {
      await post(`/network/drift/${b.dataset.id}/ack`, { note: "Reviewed in the Network app" });
      toast("Drift acknowledged", "ok");
      drawDevice(el, toolId, "drift");
    },
    baseline: async () => {
      await post(`/network/devices/${toolId}/baseline`, {});
      toast("Current snapshot is the baseline", "ok");
      drawDevice(el, toolId, "drift");
    },
  });
}

function rulesTable(record) {
  const rules = record.rules || [];
  if (!rules.length) return emptyState("radar", "No rules in the snapshot", "Pull a snapshot from the device's data flow.");
  return html`<div class="table-wrap"><table class="table"><thead><tr><th>#</th><th>Action</th><th>Rule</th><th>Enabled</th></tr></thead><tbody>
    ${rules.map((r) => html`<tr><td>${r.order ?? ""}</td><td>${r.action || ""}</td><td>${r.line || r.description || r.id}</td>
      <td>${r.enabled === false ? "no" : "yes"}</td></tr>`)}</tbody></table></div>`;
}

function interfacesTable(record) {
  const ifaces = record.interfaces || [];
  const zones = record.zones || [];
  return html`<section class="card"><header><h2>Interfaces</h2></header>
    ${ifaces.length ? html`<ul>${ifaces.map((i) => html`<li>${i.name || i.id} ${i.role ? `(${i.role})` : ""} ${(i.subnets || []).join(", ")}</li>`)}</ul>`
      : html`<p class="muted">None reported.</p>`}</section>
    <section class="card"><header><h2>Zones</h2></header>
    ${zones.length ? html`<ul>${zones.map((z) => html`<li>${z.name || z.id}</li>`)}</ul>` : html`<p class="muted">The device did not report vendor zones. Interfaces are used as zones on the segmentation map.</p>`}</section>`;
}

function historyTable(history) {
  if (!history.length) return html`<p class="muted">No earlier revisions.</p>`;
  return html`<ul>${history.map((h) => html`<li>Rev ${h.rev} · ${h.revision || ""} · ${timeAgo(h.read_at)}</li>`)}</ul>`;
}

function driftTable(items, device) {
  return html`<div class="row" style="margin-bottom:8px">${can("admin") ? html`<button class="btn sm" data-act="baseline" data-min-role="admin">Accept current as baseline</button>` : ""}</div>
    ${items.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>When</th><th>Kind</th><th>Status</th><th></th></tr></thead><tbody>
      ${items.map((d) => html`<tr><td>${timeAgo(d.detected_at)}</td><td>${d.kind}</td><td>${d.status}</td>
        <td>${d.status === "open" && can("operator") ? html`<button class="btn sm" data-act="ack" data-id="${d.id}" data-min-role="operator">Acknowledge</button>` : ""}</td></tr>`)}
      </tbody></table></div>` : html`<p class="muted">No drift items.</p>`}
    ${device.baseline ? html`<p class="faint">Baseline rev ${device.baseline.rev ?? ""}.</p>` : ""}`;
}

function backupTable(items) {
  if (!items.length) return html`<p class="muted">No backups yet. An operator can take one now. Downloads are for administrators.</p>`;
  return html`<ul>${items.map((b) => html`<li>${timeAgo(b.taken_at)} · ${b.reason} · ${b.size} bytes
    ${can("admin") ? html`<a href="/api/network/backups/${b.id}/download">Download</a>` : ""}</li>`)}</ul>`;
}

function changeTable(items) {
  if (!items.length) return html`<p class="muted">No proposed changes. Propose one from the segmentation map. Applying a change needs the device-changes guardrail, an approval from a different administrator, and a fresh snapshot.</p>`;
  return html`<ul>${items.map((c) => html`<li><a href="#/approvals">${c.op}</a> · ${c.status} · ${timeAgo(c.created_at)}</li>`)}</ul>`;
}
