import { del, get, patch, post } from "../api.js";
import { followPicker, loadPeople, personChip, personOptions } from "../people.js";
import { actions, badge, can, confirmDialog, dateTime, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";
import { assetAddresses } from "./vulnerabilities.js";

const TYPES = ["server", "workstation", "network", "software", "saas", "cloud", "data", "other"];
const TYPE_ICON = { server: "server", workstation: "terminal", network: "link", software: "grid", saas: "cloud", cloud: "cloud", data: "file", other: "box" };
const CRIT = ["low", "medium", "high", "critical"];
const KEY_FACTS = ["os", "version", "url", "address", "license", "cpus"];
const AUTO = "__auto";

const listed = (a) => (Array.isArray(a.facts?.addresses) ? a.facts.addresses.map(String) : []);
const parseAddresses = (text) => [...new Set(String(text || "").split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean))].slice(0, 50);
/** The inventory tool's assigned user (Snipe-IT checkout), which links the asset to a person while it is automatic. */
const inventoryUser = (a) => [a.facts?.assigned_email, a.facts?.assigned_username].find((v) => typeof v === "string" && v) || "";

function assignedField(a, people) {
  const inventory = inventoryUser(a);
  const auto = inventory && (a.assigned_source || "auto") === "auto";
  const linked = people.find((p) => p.id === a.assigned_person_id);
  const hint = auto ? (linked ? `Linked automatically to ${linked.display_name} (${inventory} in the inventory tool).` : `No person matches ${inventory} from the inventory tool yet.`)
    : a.assigned_source === "manual" && inventory ? `Set by hand - the inventory tool says ${inventory}; pick Automatic to follow it again.` : "Who uses it, e.g. the laptop's user.";
  return field("Used by", html`<select name="assigned_person_id">${personOptions(people, auto ? AUTO : a.assigned_person_id,
    { extra: inventory ? [[AUTO, `Automatic - follow the inventory (${inventory})`]] : [] })}</select>`, hint);
}

function assetForm(a = {}, people = []) {
  const other = a.facts ? assetAddresses(a).filter((x) => !listed(a).map((l) => l.toLowerCase()).includes(x)) : [];
  return html`<div class="form-grid">
      ${field("Name", html`<input name="name" value="${a.name || ""}" required>`)}
      ${field("Type", html`<select name="type">${options(TYPES, a.type || "server")}</select>`)}
      ${field("Owner", html`<select name="owner_person_id">${personOptions(people, a.owner_person_id, { none: "No person" })}</select>`,
        people.length ? "The accountable person (People app)." : "No people yet - add them in the People app.")}
      ${field("Owner as shown", html`<input name="owner" value="${a.owner || ""}" placeholder="person or team accountable">`, "Free text; picking a person fills it.")}
      ${assignedField(a, people)}
      ${field("Criticality", html`<select name="criticality">${options(CRIT, a.criticality || "medium")}</select>`)}
      ${field("Status", html`<select name="status">${options(["active", "maintenance", "retired"], a.status || "active")}</select>`)}
      ${field("Tags", html`<input name="tags" value="${(a.tags || []).join(", ")}" placeholder="comma separated">`)}</div>
    ${field("Addresses", html`<input name="addresses" value="${listed(a).join(", ")}" placeholder="10.0.0.12, web01.example.com" spellcheck="false">`,
      html`IP addresses and hostnames this asset is known by: vulnerability scans target them and data flows match on them.${other.length ? html` Also known from its facts: <span class="mono">${other.join(", ")}</span>.` : ""}`)}
    <label class="check scope-check"><input type="checkbox" name="scan_scope" ${a.scan_scope ? "checked" : ""}>
      <span><b>In vulnerability-scan scope</b><span class="faint" style="display:block;font-size:12px">Only assets in scope are ever scanned by a connected scanner.
        ${a.last_scanned_at ? html`Last scanned ${timeAgo(a.last_scanned_at)}.` : a.scan_scope ? "Not scanned yet." : ""}</span></span></label>
    ${a.facts && Object.keys(a.facts).length ? html`<h3 style="margin:14px 0 8px">Discovered facts</h3><dl class="kv">${Object.entries(a.facts).map(([k, v]) => html`<dt>${k}</dt><dd>${typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>`)}</dl>` : ""}
    ${a.source && a.source !== "manual" ? html`<p class="faint" style="margin-top:10px;font-size:12px">${a.source.startsWith("sync:")
      ? html`Created by a data flow from <code>${a.source.slice(5)}</code> - its facts follow the tool;` : html`Managed by the Asset Supervisor (source <code>${a.source}</code>) - facts refresh automatically;`}
      owner, criticality, tags and scan scope are yours.</p>` : ""}`;
}

function formData(data, a = null) {
  const out = {
    name: String(data.get("name") || "").trim(), type: data.get("type"), owner: String(data.get("owner") || "").trim() || null,
    criticality: data.get("criticality"), status: data.get("status"),
    tags: String(data.get("tags") || "").split(",").map((t) => t.trim()).filter(Boolean),
    scan_scope: data.get("scan_scope") === "on",
  };
  const owner = data.get("owner_person_id") || null;
  const used = data.get("assigned_person_id") || "";
  if (!a) {
    if (owner) out.owner_person_id = owner;
    if (used && used !== AUTO) out.assigned_person_id = used;
  } else {
    if (owner !== (a.owner_person_id || null)) out.owner_person_id = owner;
    if (used === AUTO) {
      if (a.assigned_source !== "auto") out.assigned_source = "auto";
    } else if ((used || null) !== (a.assigned_person_id || null) || (inventoryUser(a) && a.assigned_source === "auto")) {
      out.assigned_person_id = used || null; // set by hand: pulls leave it alone until it is automatic again
    }
  }
  const addresses = parseAddresses(data.get("addresses"));
  const before = a ? listed(a) : [];
  if (addresses.join("|") !== before.join("|")) { // only touch the facts when the addresses changed
    const facts = { ...(a?.facts || {}) };
    if (addresses.length) facts.addresses = addresses; else delete facts.addresses;
    out.facts = facts;
  }
  return out;
}

export async function render(el, ctx) {
  let filter = "all";
  let query = "";
  let assets = [];
  let people = [];
  let byId = {};
  const picked = new Set();
  const draw = async () => {
    [assets, people] = await Promise.all([get("/assets"), loadPeople()]);
    byId = Object.fromEntries(people.map((p) => [p.id, p]));
    const names = (a) => [byId[a.owner_person_id]?.display_name, byId[a.assigned_person_id]?.display_name].filter(Boolean).join(" ");
    const active = assets.filter((a) => a.status !== "retired");
    const shown = assets.filter((a) => (filter === "all" ? a.status !== "retired" : filter === "retired" ? a.status === "retired"
      : filter === "scope" ? a.scan_scope && a.status !== "retired" : a.type === filter && a.status !== "retired"))
      .filter((a) => !query || `${a.name} ${a.owner || ""} ${names(a)} ${a.tags.join(" ")} ${JSON.stringify(a.facts)}`.toLowerCase().includes(query));
    const counts = Object.fromEntries(TYPES.map((t) => [t, active.filter((a) => a.type === t).length]));
    const inScope = active.filter((a) => a.scan_scope).length;
    for (const id of [...picked]) if (!assets.some((a) => a.id === id)) picked.delete(id);
    const allPicked = shown.length && shown.every((a) => picked.has(a.id));
    setHTML(el, html`
      <div class="page-head"><div><h1>Assets</h1><p class="muted">The asset register. The Asset Supervisor keeps tools, SaaS services and hosts in sync; add anything else by hand.</p></div>
        <div class="row" data-min-role="operator"><button class="btn" data-act="sync">${icon("refresh")}Sync now</button><button class="btn primary" data-act="add">${icon("plus")}Add asset</button></div></div>
      <div class="grid cols-5" style="margin-bottom:16px">
        <div class="card stat"><div class="stat-icon">${icon("box")}</div><div><div class="label">Active assets</div><div class="value">${active.length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("alert")}</div><div><div class="label">Without owner</div><div class="value">${active.filter((a) => !a.owner && !a.owner_person_id).length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("shield")}</div><div><div class="label">Critical</div><div class="value">${active.filter((a) => a.criticality === "critical").length}</div></div></div>
        <div class="card stat"><div class="stat-icon">${icon("cloud")}</div><div><div class="label">SaaS services</div><div class="value">${counts.saas}</div></div></div>
        <a class="card stat" href="#/vulnerabilities/scope"><div class="stat-icon">${icon("radar")}</div><div><div class="label">In scan scope</div><div class="value">${inScope}</div>
          <div class="sub">vulnerability scanning</div></div></a>
      </div>
      <div class="row" style="margin-bottom:12px;justify-content:space-between">
        <div class="seg">${["all", ...TYPES.filter((t) => counts[t]), ...(inScope ? ["scope"] : []), "retired"].map((t) => html`<button class="${filter === t ? "active" : ""}" data-act="filter" data-f="${t}">${t === "scope" ? "in scan scope" : t}${t !== "all" && t !== "retired" ? ` (${t === "scope" ? inScope : counts[t]})` : ""}</button>`)}</div>
        <input id="asset-q" placeholder="Search assets..." value="${query}" style="max-width:260px" aria-label="Search assets"></div>
      ${picked.size ? html`<div class="bulk-bar" data-min-role="operator"><span class="muted">${picked.size} selected</span>
        <button class="btn sm" data-act="scope" data-in="1">${icon("radar")}Put in scan scope</button>
        <button class="btn sm" data-act="scope" data-in="0">${icon("minus")}Take out of scope</button>
        <button class="btn sm ghost" data-act="unpick">Clear selection</button></div>` : ""}
      <section class="card flush">${shown.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
        <th style="width:34px" data-min-role="operator"><input type="checkbox" data-pick-all aria-label="Select all shown" ${allPicked ? "checked" : ""}></th>
        <th>Asset</th><th>Type</th><th>Owner</th><th>Used by</th><th>Criticality</th><th>Status</th><th>Scan</th><th>Details</th><th>Updated</th></tr></thead><tbody>
        ${shown.map((a) => {
          const key = KEY_FACTS.find((k) => a.facts[k]);
          const addr = assetAddresses(a);
          return html`<tr class="clickable" data-act="edit" data-id="${a.id}">
          <td data-min-role="operator" data-act="pick-cell"><input type="checkbox" data-pick="${a.id}" aria-label="Select ${a.name}" ${picked.has(a.id) ? "checked" : ""}></td>
          <td><div class="row" style="flex-wrap:nowrap;gap:8px">${icon(TYPE_ICON[a.type])}<b>${a.name}</b>${a.source !== "manual" ? html`<span class="badge" title="Managed by the Asset Supervisor${a.source.startsWith("sync:") ? " (data flow)" : ""}">auto</span>` : ""}</div></td>
          <td>${a.type}</td>
          <td>${byId[a.owner_person_id] ? personChip(byId[a.owner_person_id], { link: false }) : a.owner || html`<span class="warn-text">unassigned</span>`}</td>
          <td>${byId[a.assigned_person_id] ? personChip(byId[a.assigned_person_id], { link: false })
            : a.facts.assigned_name ? html`<span class="faint" title="Assigned in the inventory tool; no matching person">${a.facts.assigned_name}</span>` : html`<span class="faint">-</span>`}</td>
          <td>${badge(a.criticality)}</td><td>${badge(a.status)}</td>
          <td>${a.scan_scope ? html`<span title="${a.last_scanned_at ? `Last scanned ${dateTime(a.last_scanned_at)}` : "Not scanned yet"}">${badge("in scope", addr.length ? "info" : "warn")}</span>
            ${addr.length ? "" : html`<div class="warn-text" style="font-size:11.5px">no address</div>`}` : html`<span class="faint">-</span>`}</td>
          <td class="faint" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${addr.length ? addr.slice(0, 2).join(", ") : key ? `${key}: ${a.facts[key]}` : ""}</td>
          <td class="faint">${timeAgo(a.updated_at)}</td></tr>`;
        })}</tbody></table></div>`
        : emptyState("box", "No assets here", "Import tools or add hosts and the Asset Supervisor registers them automatically.")}</section>`);
    const q = el.querySelector("#asset-q");
    q.addEventListener("input", () => { query = q.value.toLowerCase(); const pos = q.selectionStart; draw().then(() => { const n = el.querySelector("#asset-q"); n.focus(); n.setSelectionRange(pos, pos); }); });
  };
  el.addEventListener("change", (e) => {
    const t = e.target;
    if (t.matches("[data-pick]")) { if (t.checked) picked.add(t.dataset.pick); else picked.delete(t.dataset.pick); draw(); }
    if (t.matches("[data-pick-all]")) {
      for (const row of el.querySelectorAll("[data-pick]")) { if (t.checked) picked.add(row.dataset.pick); else picked.delete(row.dataset.pick); }
      draw();
    }
  });
  actions(el, {
    filter: (d) => { filter = d.f; draw(); },
    async sync() { const r = await post("/assets/sync"); toast(`Synced: ${r.created} new, ${r.updated} updated, ${r.retired} retired`, "ok"); draw(); },
    unpick: () => { picked.clear(); draw(); },
    async scope(d) {
      try {
        const r = await post("/assets/scan-scope", { asset_ids: [...picked], in_scope: d.in === "1" });
        if (r.without_address?.length) toast(`In scope, but without an IP address or hostname: ${r.without_address.slice(0, 5).join(", ")}`, "warn");
        else toast(`${r.changed.length} asset${r.changed.length === 1 ? "" : "s"} ${d.in === "1" ? "put in" : "taken out of"} scan scope`, "ok");
        picked.clear();
      } catch (err) {
        toast(err.message, "bad");
      }
      draw();
    },
    add() {
      const m = modal({ title: "Add asset", body: assetForm({}, people), submit: "Add", wide: true, minRole: "operator",
        async onSubmit(data) { await post("/assets", formData(data)); toast("Asset added", "ok"); draw(); } });
      followPicker(m.el.querySelector("[name=owner_person_id]"), m.el.querySelector("[name=owner]"), people);
    },
    edit: (d) => openAsset(d.id),
  });

  function openAsset(id) {
    const a = assets.find((x) => x.id === id);
    if (!a) return toast("That asset is no longer in the register", "warn");
    const m = modal({
      title: a.name, body: assetForm(a, people), submit: "Save", wide: true, minRole: "operator",
      footer: html`<button type="button" class="btn danger" data-del style="margin-right:auto" data-min-role="operator">${icon("trash")}Delete</button>
        <button type="button" class="btn" data-close>${can("operator") ? "Cancel" : "Close"}</button><button type="submit" class="btn primary" data-min-role="operator">Save</button>`,
      async onSubmit(data) { await patch(`/assets/${a.id}`, formData(data, a)); toast("Saved", "ok"); draw(); },
    });
    followPicker(m.el.querySelector("[name=owner_person_id]"), m.el.querySelector("[name=owner]"), people);
    m.el.querySelector("[data-del]").addEventListener("click", async () => {
      m.close();
      if (await confirmDialog("Delete asset", `Delete ${a.name} from the register?`, "Delete")) { await del(`/assets/${a.id}`); draw(); }
    });
  }

  await draw();
  if (ctx.params[0]) { // #/assets/<id>: open that asset (from People, the map or the search)
    history.replaceState(null, "", "#/assets");
    openAsset(ctx.params[0]);
  }
  ctx.live(["asset", "asset_removed", "person", "person_removed"], draw, 500);
}
