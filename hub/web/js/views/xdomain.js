// Extension apps: one per enabled extension domain (alerts, tickets, incidents...). A generic record table and a record
// page linked to its asset and person; the fields come from the domain's extension pack.
import { del, get, patch, post } from "../api.js";
import { fieldInput, fieldValue, packHref, readFields, SEVERITIES, xColor, xHref } from "../extensions.js";
import { loadPeople, personChip, personOptions } from "../people.js";
import {
  actions, badge, builtinIcon, confirmDialog, dateTime, debounce, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast,
} from "../ui.js";

const enc = encodeURIComponent;
const COLUMNS = 6;
const ROW_LIMIT = 500;
const LIVE = ["x_record", "x_record_removed", "extension", "extension_removed", "asset", "asset_removed", "person", "person_removed"];

const singular = (d) => d.singular || d.title;
const sevField = (d) => d.fields.find((f) => f.type === "severity");
const labelOf = (d, name) => d.fields.find((f) => f.name === name)?.label || name;

function notEnabled(el, ctx, key) {
  ctx.crumb(`Extensions / ${key}`);
  setHTML(el, html`<section class="card">${emptyState("puzzle", `No extension app "${key}"`,
    "No enabled extension pack defines it: the pack may have been disabled or removed, or extensions are switched off.",
    html`<a class="btn" href="#/extensions">${icon("puzzle")}Extensions</a>`)}</section>`);
}

/** How a link of a record came about. */
function linkNote(d, r, target) {
  if (r[`${target}_source`] === "manual") return "Set by hand - pulls keep it until it is made automatic again.";
  const rules = d.links.filter((l) => l.target === target).map((l) => `"${labelOf(d, l.field)}"`);
  return rules.length ? `Automatic, by ${target === "asset" ? "the address or hostname" : "the email or login"} in ${rules.join(" or ")}.`
    : `Automatic, but ${d.title} has no rule that links ${target === "asset" ? "assets" : "people"}.`;
}

// ---------- add / edit ----------

async function openRecordForm(d, rec, done) {
  const [assets, people] = await Promise.all([get("/assets").catch(() => []), loadPeople()]);
  const manualBefore = Boolean(rec && (rec.asset_source === "manual" || rec.person_source === "manual"));
  const rules = (target) => d.links.filter((l) => l.target === target).map((l) => labelOf(d, l.field));
  const auto = [rules("asset").length ? `an asset by ${rules("asset").join(" or ")}` : "", rules("person").length ? `a person by ${rules("person").join(" or ")}` : ""].filter(Boolean);
  const m = modal({
    title: rec ? `Edit ${singular(d).toLowerCase()}` : `Add ${singular(d).toLowerCase()}`,
    wide: true,
    minRole: "operator",
    submit: rec ? "Save" : "Add",
    body: html`${rec && rec.source !== "manual" ? html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div class="muted" style="font-size:12.5px">
        Pulled from <b>${rec.source_name}</b>: fields changed here are overwritten when ${rec.source_name} reports a change. Links set by hand stick.</div></div>` : ""}
      <div class="form-grid">${d.fields.map((f) => field(`${f.label}${f.required ? " *" : ""}`, fieldInput(f, rec?.fields[f.name]), f.description))}</div>
      <h3 style="margin:4px 0 8px">Links</h3>
      <div class="stack" style="gap:8px">
        <label class="radio-card"><input type="radio" name="link_mode" value="auto" ${manualBefore ? "" : "checked"}>
          <div><b>Automatic</b><p class="muted">${auto.length ? `Links ${auto.join(" and ")}, and follows the fields when they change.` : `${d.title} has no link rules.`}</p></div></label>
        <label class="radio-card"><input type="radio" name="link_mode" value="manual" ${manualBefore ? "checked" : ""}>
          <div style="flex:1;min-width:0"><b>By hand</b><p class="muted">Pulls keep these links until they are made automatic again.</p>
            <div class="form-grid" style="margin-top:8px">
              ${field("Asset", html`<select name="asset_id">${options([["", "No asset"], ...assets.map((a) => [a.id, `${a.name} (${a.type}${a.status !== "active" ? `, ${a.status}` : ""})`])], rec?.asset_id || "")}</select>`)}
              ${field("Person", html`<select name="person_id">${personOptions(people, rec?.person_id, { none: "Nobody" })}</select>`)}
            </div></div></label>
      </div>`,
    async onSubmit(data) {
      const fields = readFields(d, data);
      const manual = data.get("link_mode") === "manual";
      const assetId = data.get("asset_id") || null;
      const personId = data.get("person_id") || null;
      let saved;
      if (!rec) {
        const body = { fields: Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== null)) };
        if (manual && assetId) body.asset_id = assetId;
        if (manual && personId) body.person_id = personId;
        saved = await post(`/x/${enc(d.key)}`, body);
        toast(`${singular(d)} added`, "ok");
      } else {
        const body = {};
        const changed = d.fields.filter((f) => String(data.get(`f_${f.name}`) ?? "") !== String(initial.get(`f_${f.name}`) ?? ""));
        if (changed.length) body.fields = Object.fromEntries(changed.map((f) => [f.name, fields[f.name]]));
        if (!manual && manualBefore) body.relink = true;
        if (manual && (!manualBefore || assetId !== (rec.asset_id || null))) body.asset_id = assetId;
        if (manual && (!manualBefore || personId !== (rec.person_id || null))) body.person_id = personId;
        if (!Object.keys(body).length) return toast("Nothing changed", "info");
        saved = await patch(`/x/${enc(d.key)}/${enc(rec.id)}`, body);
        toast("Saved", "ok");
      }
      done?.(saved);
    },
  });
  const initial = new FormData(m.el);
  m.el.querySelectorAll("[name=asset_id], [name=person_id]").forEach((s) => s.addEventListener("change", () => {
    m.el.querySelector("[name=link_mode][value=manual]").checked = true;
  }));
}

// ---------- the table ----------

function tiles(d, rows, listing, sev) {
  const sf = sevField(d);
  if (sf) {
    const count = (s) => rows.filter((r) => r.fields[sf.name] === s).length;
    return html`<div class="sev-tiles">${SEVERITIES.map((s) => html`<button type="button" class="card sev-tile ${s} ${sev === s ? "active" : ""}" data-act="sev" data-sev="${s}"
        title="Show ${s} ${d.title.toLowerCase()} only"><div class="label">${s}</div><div class="value">${count(s)}</div><div class="sub">${sf.label.toLowerCase()}</div></button>`)}
      <div class="card sev-tile" title="Records their tool no longer reports"><div class="label">Stale</div><div class="value">${listing.stale}</div><div class="sub">no longer reported</div></div></div>`;
  }
  const stat = (label, value, iconName, sub = "") => html`<div class="card stat"><div class="stat-icon">${icon(iconName)}</div>
    <div><div class="label">${label}</div><div class="value">${value}</div>${sub ? html`<div class="sub">${sub}</div>` : ""}</div></div>`;
  return html`<div class="grid cols-5" style="margin-bottom:16px">
    ${stat(d.title, listing.total, d.icon, "current records")}
    ${stat("Linked to an asset", rows.filter((r) => r.asset_id).length, "box")}
    ${stat("Linked to a person", rows.filter((r) => r.person_id).length, "contact")}
    ${stat("Stale", listing.stale, "clock", "no longer reported")}</div>`;
}

function recordRow(d, cols, r) {
  return html`<tr class="clickable ${r.stale ? "stale" : ""}" data-act="open" data-id="${r.id}">
    <td style="min-width:200px"><div class="row" style="gap:6px;flex-wrap:nowrap"><b class="clip" style="max-width:320px" title="${r.title}">${r.title}</b>${r.stale ? badge("stale") : ""}</div>
      ${r.external_id ? html`<div class="faint mono" style="font-size:11.5px">#${r.external_id}</div>` : ""}</td>
    ${cols.map((f) => html`<td>${f.type === "text" ? html`<span class="clip" style="max-width:220px" title="${r.fields[f.name] ?? ""}">${fieldValue(f, r.fields[f.name])}</span>` : fieldValue(f, r.fields[f.name])}</td>`)}
    <td>${r.asset ? html`<a href="#/assets/${enc(r.asset.id)}" data-act="nav" class="row" style="gap:4px;flex-wrap:nowrap">${icon("box")}<span class="clip" style="max-width:160px">${r.asset.name}</span></a>` : html`<span class="faint">-</span>`}</td>
    <td>${r.person ? html`<span data-act="nav">${personChip(r.person)}</span>` : html`<span class="faint">-</span>`}</td>
    <td style="white-space:nowrap">${r.source === "manual" ? html`<span class="faint">by hand</span>` : html`<a href="#/tools/${enc(r.source)}" data-act="nav">${r.source_name}</a>`}</td>
    <td class="faint" title="${dateTime(r.updated_at)}" style="white-space:nowrap">${timeAgo(r.updated_at)}</td></tr>`;
}

async function renderList(el, ctx, key) {
  const filters = { q: "", source: "", stale: false };
  let sev = "";
  let listing = null;
  let seq = 0;
  const $ = (sel) => el.querySelector(sel);
  const skeleton = () => setHTML(el, html`<div data-head></div><div data-tiles></div>
    <div class="row filters" style="margin-bottom:12px">
      <input id="x-q" type="search" value="${filters.q}" placeholder="Search every field..." aria-label="Search" style="max-width:300px">
      <select class="input-sm" data-filter="source" aria-label="Source"></select>
      <label class="check"><input type="checkbox" data-stale ${filters.stale ? "checked" : ""}> Include stale</label>
      <span class="spacer"></span><span class="faint" data-count style="font-size:12.5px"></span></div>
    <section class="card flush" data-table></section>`);

  const draw = () => {
    if (!$("[data-table]")) skeleton(); // after the "not enabled" state, e.g. the pack was enabled again
    const d = listing.domain;
    const rows = listing.records.filter((r) => !sev || r.fields[sevField(d)?.name] === sev);
    const cols = d.fields.filter((f) => f.name !== d.title_field).slice(0, COLUMNS);
    ctx.crumb(`Extensions / ${d.title}`);
    setHTML($("[data-head]"), html`<div class="page-head"><div class="row" style="gap:14px;flex-wrap:nowrap;min-width:0">${builtinIcon(d.icon, xColor(d.key), "lg")}
        <div style="min-width:0"><h1>${d.title}</h1><p class="muted">${d.description || `${d.title} records, pulled from tools by data flows or added by hand.`}
          <span class="faint">Extension app from <a href="${packHref(d.extension_id)}">${d.extension_id}</a>.</span></p></div></div>
      <div class="row"><a class="btn" href="#/integration">${icon("flow")}Data flows</a>
        <button type="button" class="btn primary" data-act="add" data-min-role="operator">${icon("plus")}Add ${singular(d).toLowerCase()}</button></div></div>`);
    setHTML($("[data-tiles]"), tiles(d, listing.records, listing, sev));
    const sources = [["", "Every source"], ...listing.sources.map((s) => [s, s === "manual" ? "Added by hand" : listing.source_names[s] || s])];
    setHTML($("[data-filter=source]"), options(filters.source && !listing.sources.includes(filters.source) ? [...sources, [filters.source, filters.source]] : sources, filters.source));
    $("[data-count]").textContent = `${rows.length} of ${listing.total}${sev ? ` - ${sev} only` : ""}`;
    const titleLabel = labelOf(d, d.title_field);
    setHTML($("[data-table]"), rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>${titleLabel}</th>
        ${cols.map((f) => html`<th title="${f.description}">${f.label}</th>`)}<th>Asset</th><th>Person</th><th>Source</th><th>Updated</th></tr></thead>
        <tbody>${rows.slice(0, ROW_LIMIT).map((r) => recordRow(d, cols, r))}</tbody></table></div>
        ${rows.length > ROW_LIMIT ? html`<p class="faint" style="padding:10px 16px">Showing ${ROW_LIMIT} of ${rows.length} - search or filter to narrow the list.</p>` : ""}`
      : listing.total || filters.q || filters.source || sev ? emptyState("search", "Nothing matches", "Change the search or the filters.")
        : emptyState(d.icon, `No ${d.title.toLowerCase()} yet`, `A data flow from a connected tool fills ${d.title}; the Integration hub proposes one once the tool's connection maps it. Or add one by hand.`,
          html`<button type="button" class="btn primary" data-act="add" data-min-role="operator">${icon("plus")}Add ${singular(d).toLowerCase()}</button>`));
  };

  const load = async () => {
    const mine = ++seq;
    const params = new URLSearchParams({ q: filters.q, source: filters.source, stale: String(filters.stale), limit: "2000" });
    let data;
    try {
      data = await get(`/x/${enc(key)}?${params}`);
    } catch (err) {
      if (mine !== seq || !el.isConnected) return;
      if (err.status === 404) { listing = null; return notEnabled(el, ctx, key); }
      throw err;
    }
    if (mine !== seq || !el.isConnected) return;
    listing = data;
    draw();
  };
  const refresh = () => load().catch((err) => toast(err.message, "bad"));

  skeleton();
  const search = debounce((value) => { filters.q = value; refresh(); }, 250);
  el.addEventListener("input", (e) => { if (e.target.id === "x-q") search(e.target.value.trim()); });
  el.addEventListener("change", (e) => {
    if (e.target.matches("[data-filter=source]")) { filters.source = e.target.value; refresh(); }
    if (e.target.matches("[data-stale]")) { filters.stale = e.target.checked; refresh(); }
  });
  actions(el, {
    open: (dd) => { location.hash = xHref(key, dd.id); },
    sev: (dd) => { sev = sev === dd.sev ? "" : dd.sev; draw(); },
    add: () => listing && openRecordForm(listing.domain, null, (saved) => { location.hash = xHref(key, saved.id); }),
  });
  await load();
  ctx.live(LIVE, refresh, 600);
}

// ---------- one record ----------

async function renderRecord(el, ctx, key, id) {
  let r = null;
  const draw = async () => {
    if (!el.isConnected) return; // a late live refresh after leaving the page (e.g. the record was just removed)
    let data;
    try {
      data = await get(`/x/${enc(key)}/${enc(id)}`);
    } catch (err) {
      if (!el.isConnected) return;
      if (err.status !== 404) throw err;
      const enabled = await get(`/x/${enc(key)}?limit=1`).then(() => true, () => false);
      if (!enabled) return notEnabled(el, ctx, key);
      ctx.crumb(`Extensions / ${key} / not found`);
      setHTML(el, html`<section class="card">${emptyState("search", "Record not found", "It may have been removed.",
        html`<a class="btn" href="${xHref(key)}">${icon("arrow")}Back to the list</a>`)}</section>`);
      return;
    }
    if (!el.isConnected) return;
    r = data;
    const d = r.domain_def;
    const sf = sevField(d);
    ctx.crumb(`${d.title} / ${r.title}`);
    const manual = r.asset_source === "manual" || r.person_source === "manual";
    setHTML(el, html`
      <div class="page-head"><div class="row" style="gap:14px;flex-wrap:nowrap;min-width:0">${builtinIcon(d.icon, xColor(d.key), "lg")}
          <div style="min-width:0"><a href="${xHref(d.key)}" class="faint" style="font-size:12.5px">&larr; ${d.title}</a>
            <h1 style="overflow-wrap:anywhere">${r.title}</h1>
            <div class="row" style="gap:6px;margin-top:6px">${sf && r.fields[sf.name] ? fieldValue(sf, r.fields[sf.name]) : ""}${r.stale ? badge("stale") : ""}
              ${r.source === "manual" ? badge("added by hand") : html`<span class="badge accent">${icon("link")}${r.source_name}</span>`}
              ${r.external_id ? html`<span class="faint mono" style="font-size:12px">#${r.external_id}</span>` : ""}</div></div></div>
        <div class="row" data-min-role="operator"><button type="button" class="btn" data-act="edit">${icon("edit")}Edit</button>
          <button type="button" class="btn danger" data-act="delete">${icon("trash")}Remove</button></div></div>
      ${r.stale ? html`<div class="notice warn" style="margin-bottom:16px">${icon("clock")}<div class="muted">${r.source_name} no longer reports this ${singular(d).toLowerCase()}.
        It is kept for the record but no longer counted by compliance rules.</div></div>` : ""}
      <div class="grid split">
        <section class="card"><header><h2>${singular(d)}</h2></header>
          <dl class="kv">${d.fields.map((f) => html`<dt title="${f.description}">${f.label}</dt><dd>${fieldValue(f, r.fields[f.name], { full: true })}</dd>`)}</dl></section>
        <section class="stack">
          <div class="card"><header><h2>Links</h2>${manual ? html`<button type="button" class="btn sm" data-act="relink" data-min-role="operator"
              title="Link by the ${d.title} link rules again">${icon("refresh")}Make automatic</button>` : ""}</header>
            <div class="faint" style="font-size:12px;margin-bottom:4px">Asset</div>
            ${r.asset ? html`<a href="#/assets/${enc(r.asset.id)}" class="row" style="gap:6px">${icon("box")}<b>${r.asset.name}</b>
                <span class="faint" style="font-size:12px">${r.asset.type}${r.asset.status !== "active" ? ` - ${r.asset.status}` : ""}</span></a>` : html`<p class="muted">No asset</p>`}
            <div class="faint" style="font-size:11.5px;margin-top:2px">${linkNote(d, r, "asset")}</div>
            <div class="faint" style="font-size:12px;margin:14px 0 4px">Person</div>
            ${r.person ? personChip(r.person) : html`<p class="muted">Nobody</p>`}
            <div class="faint" style="font-size:11.5px;margin-top:2px">${linkNote(d, r, "person")}</div></div>
          <div class="card"><header><h2>Source</h2></header><dl class="kv">
            <dt>From</dt><dd>${r.source === "manual" ? "Added by hand" : html`<a href="#/tools/${enc(r.source)}">${r.source_name}</a> <span class="faint">(data flow)</span>`}</dd>
            ${r.external_id ? html`<dt>Id in the tool</dt><dd class="mono">${r.external_id}</dd>` : ""}
            <dt>Extension</dt><dd><a href="${packHref(r.extension_id)}">${r.extension_id}</a> <span class="faint mono">x:${d.key}</span></dd>
            <dt>Added</dt><dd title="${dateTime(r.created_at)}">${timeAgo(r.created_at)}</dd>
            <dt>Updated</dt><dd title="${dateTime(r.updated_at)}">${timeAgo(r.updated_at)}</dd></dl></div>
        </section>
      </div>`);
  };
  const refresh = () => draw().catch((err) => toast(err.message, "bad"));
  actions(el, {
    edit: () => r && openRecordForm(r.domain_def, r, refresh),
    async relink() {
      try {
        await patch(`/x/${enc(key)}/${enc(id)}`, { relink: true });
        toast("Links are automatic again", "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
      refresh();
    },
    async delete() {
      const d = r.domain_def;
      const pulled = r.source !== "manual" ? ` ${r.source_name} may report it again at its next pull.` : "";
      if (!(await confirmDialog(`Remove this ${singular(d).toLowerCase()}?`, `"${r.title}" is removed from ${d.title}.${pulled}`, "Remove"))) return;
      try {
        await del(`/x/${enc(key)}/${enc(id)}`);
        toast(`${singular(d)} removed`, "ok");
        location.hash = xHref(key);
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
    },
  });
  await draw();
  ctx.live(LIVE, refresh, 600);
}

export async function render(el, ctx) {
  const [key, id] = ctx.params;
  if (!key) { location.hash = "#/extensions"; return; }
  return id ? renderRecord(el, ctx, key, id) : renderList(el, ctx, key);
}
