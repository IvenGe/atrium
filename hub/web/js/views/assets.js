import { del, get, patch, post } from "../api.js";
import { actions, badge, can, confirmDialog, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";

const TYPES = ["server", "workstation", "network", "software", "saas", "cloud", "data", "other"];
const TYPE_ICON = { server: "server", workstation: "terminal", network: "link", software: "grid", saas: "cloud", cloud: "cloud", data: "file", other: "box" };
const CRIT = ["low", "medium", "high", "critical"];
const KEY_FACTS = ["os", "version", "url", "address", "license", "cpus"];

function assetForm(a = {}) {
  return html`<div class="form-grid">
      ${field("Name", html`<input name="name" value="${a.name || ""}" required>`)}
      ${field("Type", html`<select name="type">${options(TYPES, a.type || "server")}</select>`)}
      ${field("Owner", html`<input name="owner" value="${a.owner || ""}" placeholder="person or team accountable">`)}
      ${field("Criticality", html`<select name="criticality">${options(CRIT, a.criticality || "medium")}</select>`)}
      ${field("Status", html`<select name="status">${options(["active", "maintenance", "retired"], a.status || "active")}</select>`)}
      ${field("Tags", html`<input name="tags" value="${(a.tags || []).join(", ")}" placeholder="comma separated">`)}</div>
    ${a.facts && Object.keys(a.facts).length ? html`<h3 style="margin:6px 0 8px">Discovered facts</h3><dl class="kv">${Object.entries(a.facts).map(([k, v]) => html`<dt>${k}</dt><dd>${typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>`)}</dl>` : ""}
    ${a.source && a.source !== "manual" ? html`<p class="faint" style="margin-top:10px;font-size:12px">Managed by the Asset Supervisor (source <code>${a.source}</code>) - facts refresh automatically; owner, criticality and tags are yours.</p>` : ""}`;
}

function formData(data) {
  return {
    name: String(data.get("name") || "").trim(), type: data.get("type"), owner: String(data.get("owner") || "").trim() || null,
    criticality: data.get("criticality"), status: data.get("status"),
    tags: String(data.get("tags") || "").split(",").map((t) => t.trim()).filter(Boolean),
  };
}

export async function render(el, ctx) {
  let filter = "all";
  let query = "";
  let assets = [];
  const draw = async () => {
    assets = await get("/assets");
    const active = assets.filter((a) => a.status !== "retired");
    const shown = assets.filter((a) => (filter === "all" ? a.status !== "retired" : filter === "retired" ? a.status === "retired" : a.type === filter && a.status !== "retired"))
      .filter((a) => !query || `${a.name} ${a.owner || ""} ${a.tags.join(" ")} ${JSON.stringify(a.facts)}`.toLowerCase().includes(query));
    const counts = Object.fromEntries(TYPES.map((t) => [t, active.filter((a) => a.type === t).length]));
    setHTML(el, html`
      <div class="page-head"><div><h1>Assets</h1><p class="muted">The asset register. The Asset Supervisor keeps tools, SaaS services and hosts in sync; add anything else by hand.</p></div>
        <div class="row" data-min-role="operator"><button class="btn" data-act="sync">${icon("refresh")}Sync now</button><button class="btn primary" data-act="add">${icon("plus")}Add asset</button></div></div>
      <div class="grid cols-5" style="margin-bottom:16px">
        <div class="card stat"><div class="stat-icon">${icon("box")}</div><div><div class="label">Active assets</div><div class="value">${active.length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("alert")}</div><div><div class="label">Without owner</div><div class="value">${active.filter((a) => !a.owner).length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("shield")}</div><div><div class="label">Critical</div><div class="value">${active.filter((a) => a.criticality === "critical").length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("cloud")}</div><div><div class="label">SaaS services</div><div class="value">${counts.saas}</div></div></div>
      </div>
      <div class="row" style="margin-bottom:12px;justify-content:space-between">
        <div class="seg">${["all", ...TYPES.filter((t) => counts[t]), "retired"].map((t) => html`<button class="${filter === t ? "active" : ""}" data-act="filter" data-f="${t}">${t}${t !== "all" && t !== "retired" ? ` (${counts[t]})` : ""}</button>`)}</div>
        <input id="asset-q" placeholder="Search assets..." value="${query}" style="max-width:260px" aria-label="Search assets"></div>
      <section class="card flush">${shown.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Asset</th><th>Type</th><th>Owner</th><th>Criticality</th><th>Status</th><th>Details</th><th>Updated</th></tr></thead><tbody>
        ${shown.map((a) => {
          const key = KEY_FACTS.find((k) => a.facts[k]);
          return html`<tr class="clickable" data-act="edit" data-id="${a.id}">
          <td><div class="row" style="flex-wrap:nowrap;gap:8px">${icon(TYPE_ICON[a.type])}<b>${a.name}</b>${a.source !== "manual" ? html`<span class="badge" title="Managed by the Asset Supervisor">auto</span>` : ""}</div></td>
          <td>${a.type}</td><td>${a.owner || html`<span style="color:var(--warn)">unassigned</span>`}</td><td>${badge(a.criticality)}</td><td>${badge(a.status)}</td>
          <td class="faint" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${key ? `${key}: ${a.facts[key]}` : ""}</td>
          <td class="faint">${timeAgo(a.updated_at)}</td></tr>`;
        })}</tbody></table></div>`
        : emptyState("box", "No assets here", "Import tools or add hosts and the Asset Supervisor registers them automatically.")}</section>`);
    const q = el.querySelector("#asset-q");
    q.addEventListener("input", () => { query = q.value.toLowerCase(); const pos = q.selectionStart; draw().then(() => { const n = el.querySelector("#asset-q"); n.focus(); n.setSelectionRange(pos, pos); }); });
  };
  actions(el, {
    filter: (d) => { filter = d.f; draw(); },
    async sync() { const r = await post("/assets/sync"); toast(`Synced: ${r.created} new, ${r.updated} updated, ${r.retired} retired`, "ok"); draw(); },
    add() {
      modal({ title: "Add asset", body: assetForm(), submit: "Add", minRole: "operator",
        async onSubmit(data) { await post("/assets", formData(data)); toast("Asset added", "ok"); draw(); } });
    },
    edit(d) {
      const a = assets.find((x) => x.id === d.id);
      const m = modal({
        title: a.name, body: assetForm(a), submit: "Save", wide: true, minRole: "operator",
        footer: html`<button type="button" class="btn danger" data-del style="margin-right:auto" data-min-role="operator">${icon("trash")}Delete</button>
          <button type="button" class="btn" data-close>${can("operator") ? "Cancel" : "Close"}</button><button type="submit" class="btn primary" data-min-role="operator">Save</button>`,
        async onSubmit(data) { await patch(`/assets/${a.id}`, formData(data)); toast("Saved", "ok"); draw(); },
      });
      m.el.querySelector("[data-del]").addEventListener("click", async () => {
        m.close();
        if (await confirmDialog("Delete asset", `Delete ${a.name} from the register?`, "Delete")) { await del(`/assets/${a.id}`); draw(); }
      });
    },
  });
  await draw();
  ctx.live(["asset", "asset_removed"], draw, 500);
}
