// People app: the workforce directory merged from every connected directory, leavers (control HB-AC-7), the accounts
// people hold in tools, and a page per person with everything linked to them.
import { del, get, patch, post } from "../api.js";
import { roleBadge } from "../auth.js";
import { initialsOf, loadPeople, personAvatar, personChip, personOptions } from "../people.js";
import {
  actions, badge, can, colorFor, confirmDialog, dateTime, debounce, emptyState, field, glyph, html, icon, modal, options,
  setHTML, timeAgo, timeIn, toast,
} from "../ui.js";
import { feedItem } from "./home.js";
import { sevBadge } from "./vulnerabilities.js";

const enc = encodeURIComponent;
const TABS = ["people", "leavers", "accounts"];
const STATUS_FILTERS = [["", "Any status"], ["active", "Active"], ["suspended", "Suspended"], ["terminated", "Terminated"],
  ["suspended,terminated", "Left (suspended or terminated)"]];
const ACTION_ICON = { unassign_assets: "box", disable_atrium_account: "lock" };
const ROW_LIMIT = 500;
const LIVE = ["person", "person_removed", "account", "accounts_removed", "asset", "asset_removed"];

// ---------- shared pieces ----------

const stat = (label, value, sub, iconName, extra = "") => html`<div class="card stat ${extra}"><div class="stat-icon">${icon(iconName)}</div>
  <div><div class="label">${label}</div><div class="value">${value ?? "-"}</div>${sub ? html`<div class="sub">${sub}</div>` : ""}</div></div>`;

/** What a leaver still holds: assets, an Atrium account, active accounts in tools (to disable there). */
function holdings(f) {
  return html`<div class="holdings">
    ${f.assets.length ? html`<div><h4>${icon("box")}Assets (${f.assets.length})</h4><ul>${f.assets.map((a) => html`<li>
      <a href="#/assets/${enc(a.id)}">${a.name}</a> <span class="faint">${a.type} - ${a.relation === "owner" ? "owner" : "uses it"}</span></li>`)}</ul></div>` : ""}
    ${f.atrium_accounts.length ? html`<div><h4>${icon("lock")}Atrium account</h4><ul>${f.atrium_accounts.map((u) => html`<li>
      <b>@${u.username}</b> ${roleBadge(u.role)} <span class="faint">can still sign in</span></li>`)}</ul></div>` : ""}
    ${f.accounts.length ? html`<div><h4>${icon("key")}Active accounts in tools (${f.accounts.length})</h4><ul>${f.accounts.map((a) => html`<li>
      Disable or remove <b>${a.login || "the account"}</b>${a.app ? html` <span class="faint">(${a.app})</span>` : ""} in <a href="#/tools/${enc(a.tool_id)}">${a.tool}</a></li>`)}</ul></div>` : ""}
  </div>`;
}

const actionButtons = (personId, list) => list.map((a) => html`<button type="button" class="btn sm ${a.id === "disable_atrium_account" ? "danger" : ""}"
  data-act="person-action" data-id="${personId}" data-action="${a.id}" data-min-role="${a.role}" title="${a.description}">${icon(ACTION_ICON[a.id] || "check")}${a.title}</button>`);

/** Confirm and run a one-click leaver action; true when it ran. */
async function runAction(personId, actionId, name, list, btn) {
  const a = list.find((x) => x.id === actionId) || { title: actionId.replace(/_/g, " "), description: "" };
  if (!(await confirmDialog(`${a.title}: ${name}?`, a.description, a.title))) return false;
  if (btn) btn.disabled = true;
  try {
    const r = await post(`/people/${enc(personId)}/actions/${enc(actionId)}`);
    toast(r.detail, "ok");
    return true;
  } catch (err) {
    if (err.status !== 401) toast(err.message, "bad");
    return false;
  } finally {
    if (btn?.isConnected) btn.disabled = false;
  }
}

async function unassign(person, assetIds) {
  try {
    const r = await post(`/people/${enc(person.id)}/actions/unassign_assets`, assetIds ? { asset_ids: assetIds } : {});
    toast(r.detail, "ok");
  } catch (err) {
    if (err.status !== 401) toast(err.message, "bad");
  }
}

// ---------- add / edit ----------

function personForm(p, everyone, departments) {
  const manual = p.source_groups?.manual || [];
  const fromSources = [...new Set(Object.entries(p.source_groups || {}).filter(([k]) => k !== "manual").flatMap(([, g]) => g))];
  const directory = (p.source_list || []).some((s) => s.id !== "manual");
  const statusChoices = p.id ? [["", "None - follow the directories"], ["active", "Active"], ["suspended", "Suspended"], ["terminated", "Terminated"]]
    : [["active", "Active"], ["suspended", "Suspended"], ["terminated", "Terminated"]];
  return html`<div class="form-grid">
      ${field("Name", html`<input name="display_name" value="${p.display_name || ""}" maxlength="200" required>`)}
      ${field("Email", html`<input name="email" type="email" value="${p.email || ""}" maxlength="254" autocomplete="off" spellcheck="false">`,
        "Links them to assets, accounts in tools and their Atrium account.")}
      ${field("Login", html`<input name="login" value="${p.login || ""}" maxlength="254" autocomplete="off" spellcheck="false">`, "Used when an email does not match.")}
      ${field("Title", html`<input name="title" value="${p.title || ""}" maxlength="200">`)}
      ${field("Department", html`<input name="department" value="${p.department || ""}" maxlength="200" list="dept-list" autocomplete="off">
        <datalist id="dept-list">${departments.map((d) => html`<option value="${d}">`)}</datalist>`)}
      ${field("Manager", html`<select name="manager_id">${personOptions(everyone, p.manager_id, { none: "No manager", exclude: p.id })}</select>`)}
      ${field("Location", html`<input name="location" value="${p.location || ""}" maxlength="200">`)}
      ${field("Phone", html`<input name="phone" value="${p.phone || ""}" maxlength="64">`)}
    </div>
    ${field(p.id ? "Status set by hand" : "Status", html`<select name="status">${options(statusChoices, p.manual_status || (p.id ? "" : "active"))}</select>`,
      "A directory that says the person left still wins: a status set by hand can mark someone as gone, not bring them back.")}
    ${field("Groups set by hand", html`<input name="groups" value="${manual.join(", ")}" placeholder="comma separated">`,
      fromSources.length ? `From directories (managed there): ${fromSources.join(", ")}` : "")}
    ${directory ? html`<p class="faint" style="font-size:12px">Fields a directory sends are overwritten at its next pull.</p>` : ""}`;
}

/** The body to send: everything for a new person; for an existing one only what changed. */
function personData(f, p) {
  const text = (name) => String(f.get(name) || "").trim();
  const values = {
    display_name: text("display_name"), email: text("email") || null, login: text("login") || null, title: text("title") || null,
    department: text("department") || null, manager_id: f.get("manager_id") || null, location: text("location") || null,
    phone: text("phone") || null, groups: [...new Set(text("groups").split(",").map((g) => g.trim()).filter(Boolean))],
  };
  if (!values.display_name) throw new Error("Give the person a name");
  const status = f.get("status") || null;
  if (!p) return status && status !== "active" ? { ...values, status } : values;
  const changes = {};
  for (const [k, v] of Object.entries(values)) {
    const before = k === "groups" ? p.source_groups?.manual || [] : p[k] ?? null;
    if (JSON.stringify(before) !== JSON.stringify(v)) changes[k] = v;
  }
  if ((p.manual_status || null) !== status) changes.status = status;
  return changes;
}

async function openPersonForm(p, done) {
  const all = await get("/people").catch(() => ({ people: [], departments: [] }));
  modal({
    title: p ? `Edit ${p.display_name}` : "Add person",
    wide: true,
    minRole: "operator",
    submit: p ? "Save" : "Add person",
    body: personForm(p || {}, all.people, all.departments),
    async onSubmit(f) {
      const body = personData(f, p);
      if (p && !Object.keys(body).length) return toast("Nothing changed", "info");
      const saved = p ? await patch(`/people/${enc(p.id)}`, body) : await post("/people", body);
      toast(p ? "Saved" : `${saved.display_name} added`, "ok");
      done?.(saved);
    },
  });
}

/** Add a person by hand and open their page. */
export function openAddPerson() {
  return openPersonForm(null, (saved) => { location.hash = `#/people/${enc(saved.id)}`; });
}

async function openLinkAccount(a, done) {
  const people = await loadPeople();
  const m = modal({
    title: `Link ${a.login || a.email || a.external_id} in ${a.tool}`,
    minRole: "operator",
    body: html`<p class="muted" style="margin-bottom:12px">Pulls keep a link made by hand. Automatic links the account to the person with the same email, then login.</p>
      <div class="stack" style="gap:8px">
        <label class="radio-card"><input type="radio" name="mode" value="auto" ${a.person_source === "manual" ? "" : "checked"}>
          <div><b>Automatic</b><p class="muted">Email ${a.email || "none"} - login ${a.login || "none"}</p></div></label>
        <label class="radio-card"><input type="radio" name="mode" value="manual" ${a.person_source === "manual" ? "checked" : ""}>
          <div style="flex:1;min-width:0"><b>By hand</b>
            <select name="person_id" style="margin-top:6px" aria-label="Person">${personOptions(people, a.person_id, { none: "Not linked to anyone" })}</select></div></label>
      </div>`,
    async onSubmit(f) {
      const r = await patch(`/accounts/${enc(a.id)}`, f.get("mode") === "auto" ? { auto: true } : { person_id: f.get("person_id") || null });
      toast(r.person_id ? "Account linked" : "Account not linked to anyone", "ok");
      done?.();
    },
  });
  m.el.querySelector("[name=person_id]").addEventListener("change", () => { m.el.querySelector("[name=mode][value=manual]").checked = true; });
}

// ---------- list: people, leavers, accounts ----------

function personRow(p) {
  const left = p.status !== "active";
  const access = left && (p.active_accounts > 0 || (p.atrium_user && !p.atrium_user.disabled));
  const holds = left && (access || p.assets_owned || p.assets_assigned);
  return html`<tr class="clickable" data-act="open" data-id="${p.id}">
    <td><div class="row" style="flex-wrap:nowrap;gap:10px">${personAvatar(p)}<div style="min-width:0"><b>${p.display_name}</b>
      <div class="faint clip" style="font-size:12px;max-width:240px">${p.email || p.login || "no email"}</div></div></div></td>
    <td><div class="clip" style="max-width:200px">${p.title || html`<span class="faint">-</span>`}</div><div class="faint" style="font-size:12px">${p.department || ""}</div></td>
    <td>${p.manager ? html`<span class="clip" style="max-width:160px">${p.manager.display_name}</span>` : html`<span class="faint">-</span>`}</td>
    <td><div class="row" style="gap:4px">${badge(p.status)}${p.manual_status ? html`<span class="faint" style="font-size:11.5px" title="Status set by hand">by hand</span>` : ""}
      ${holds ? html`<span class="badge ${access ? "bad" : "warn"}" title="${access ? "Left, but can still sign in or use a tool account" : "Left, but still has company assets"}">${icon("alert")}${access ? "access" : "assets"}</span>` : ""}</div></td>
    <td><div class="tag-list">${p.source_list.map((s) => html`<span class="badge" title="${s.id === "manual" ? "Added by hand" : `${s.name} id ${s.external_id}${s.status ? ` - ${s.status}` : ""}`}">${s.id === "manual" ? "by hand" : s.name}</span>`)}</div></td>
    <td style="white-space:nowrap" title="Owns ${p.assets_owned}, uses ${p.assets_assigned}">${p.assets_owned || p.assets_assigned
      ? html`<span class="row" style="gap:4px;flex-wrap:nowrap">${icon("box")}${p.assets_owned} <span class="faint">own</span> ${p.assets_assigned} <span class="faint">use</span></span>` : html`<span class="faint">-</span>`}</td>
    <td>${p.accounts ? html`<span title="${p.active_accounts} active of ${p.accounts}">${p.active_accounts}<span class="faint">/${p.accounts}</span></span>` : html`<span class="faint">-</span>`}</td>
    <td>${p.atrium_user ? html`<span class="row" style="gap:4px;flex-wrap:nowrap">${roleBadge(p.atrium_user.role)}${p.atrium_user.disabled ? badge("disabled") : ""}</span>` : html`<span class="faint">-</span>`}</td></tr>`;
}

function leaverCard(f) {
  return html`<section class="card leaver ${f.severity}">
    <div class="row" style="gap:12px;flex-wrap:nowrap;align-items:flex-start">
      ${personAvatar({ id: f.person_id, display_name: f.display_name })}
      <div style="flex:1;min-width:0">
        <div class="row" style="gap:6px"><a href="#/people/${enc(f.person_id)}"><b>${f.display_name}</b></a>${badge(f.status)}
          ${f.severity === "fail" ? badge("still has access", "bad") : badge("still has assets", "warn")}
          ${f.terminated_at ? html`<span class="faint" style="font-size:12px" title="${dateTime(f.terminated_at)}">left ${timeAgo(f.terminated_at)}</span>` : ""}</div>
        <p class="muted" style="margin:4px 0 8px;font-size:13px">${f.summary}</p>
        ${holdings(f)}
      </div>
      <div class="row leaver-actions">${actionButtons(f.person_id, f.actions)}</div></div></section>`;
}

function accountRow(a) {
  return html`<tr>
    <td><a href="#/tools/${enc(a.tool_id)}">${a.tool}</a>${a.origin === "people" ? html`<div class="faint" style="font-size:11.5px">directory entry</div>` : ""}</td>
    <td><span class="mono" style="font-size:12.5px">${a.login || a.email || a.external_id}</span>${a.email && a.email !== a.login ? html`<div class="faint" style="font-size:12px">${a.email}</div>` : ""}</td>
    <td>${a.display_name || html`<span class="faint">-</span>`}${a.app ? html`<div class="faint" style="font-size:12px">app ${a.app}</div>` : ""}</td>
    <td>${a.active ? badge("active", "ok") : badge("inactive")}</td>
    <td class="faint" title="${dateTime(a.last_login)}">${a.last_login ? timeAgo(a.last_login) : "-"}</td>
    <td><div class="row" style="gap:6px">${a.person ? personChip(a.person) : badge("not linked", "warn")}
      ${a.person_source === "manual" ? html`<span class="faint" style="font-size:11.5px" title="Linked by hand: pulls keep this">by hand</span>` : ""}</div></td>
    <td style="text-align:right"><button type="button" class="btn sm" data-act="link-account" data-id="${a.id}" data-min-role="operator">${icon("link")}Link</button></td></tr>`;
}

async function renderList(el, ctx, initialTab) {
  let tab = initialTab;
  const filters = { q: "", status: "", department: "", source: "" };
  const acct = { tool: "", q: "", unlinked: false };
  let listing = null;
  let leaverData = null;
  let accounts = null;
  let seq = 0;
  const $ = (sel) => el.querySelector(sel);

  setHTML(el, html`
    <div class="page-head"><div><h1>People</h1><p class="muted">The workforce directory, merged from every connected directory by email and login,
        with the assets and accounts each person holds. The People Supervisor flags leavers who keep access.</p></div>
      <div class="row"><a class="btn" href="#/integration" data-min-role="admin">${icon("plug")}Connect a directory</a>
        <button type="button" class="btn primary" data-act="add" data-min-role="operator">${icon("plus")}Add person</button></div></div>
    <div data-stats></div>
    <div class="tabs" data-tabs></div>
    <div data-body></div>`);

  const drawHead = () => {
    const s = listing.statuses;
    setHTML($("[data-stats]"), html`<div class="grid cols-5" style="margin-bottom:16px">
      ${stat("People", listing.total, `${listing.sources.length} source${listing.sources.length === 1 ? "" : "s"}`, "contact")}
      ${stat("Active", s.active, "", "checkCircle")}
      ${stat("Suspended", s.suspended, "", "pause")}
      ${stat("Terminated", s.terminated, "", "logout")}
      <a class="card stat ${listing.leavers ? "alarm" : ""}" href="#/people/leavers" data-act="tab" data-tab="leavers"><div class="stat-icon">${icon("alert")}</div>
        <div><div class="label">Leavers holding something</div><div class="value">${listing.leavers}</div><div class="sub">control HB-AC-7</div></div></a></div>`);
    setHTML($("[data-tabs]"), [["people", `People (${listing.total})`], ["leavers", `Leavers (${listing.leavers})`], ["accounts", `Accounts in tools${accounts ? ` (${accounts.length})` : ""}`]]
      .map(([k, label]) => html`<button type="button" class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`));
  };

  const drawPeople = () => {
    const body = $("[data-body]");
    if (!body.querySelector("#people-q")) {
      setHTML(body, html`<div class="row filters" style="margin-bottom:12px">
          <input id="people-q" type="search" value="${filters.q}" placeholder="Search name, email, login, title, group..." aria-label="Search people" style="max-width:300px">
          <span class="row" data-selects style="gap:8px"></span><span class="spacer"></span><span class="faint" data-count style="font-size:12.5px"></span></div>
        <section class="card flush" data-table></section>`);
      body.querySelector("#people-q").addEventListener("input", debounce((e) => { filters.q = e.target.value.trim(); load(); }, 250));
    }
    const keep = (list, value) => (value && !list.some(([v]) => v === value) ? [...list, [value, value]] : list);
    setHTML(body.querySelector("[data-selects]"), html`
      <select class="input-sm" data-filter="status" aria-label="Status">${options(STATUS_FILTERS, filters.status)}</select>
      <select class="input-sm" data-filter="department" aria-label="Department">${options(keep([["", "Any department"], ...listing.departments.map((d) => [d, d])], filters.department), filters.department)}</select>
      <select class="input-sm" data-filter="source" aria-label="Source">${options(keep([["", "Any source"], ...listing.sources.map((s) => [s.id, s.name])], filters.source), filters.source)}</select>`);
    const rows = listing.people;
    const filtered = Object.values(filters).some(Boolean);
    body.querySelector("[data-count]").textContent = filtered ? `${rows.length} of ${listing.total}` : "";
    setHTML(body.querySelector("[data-table]"), rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
        <th>Person</th><th>Title</th><th>Manager</th><th>Status</th><th>Sources</th><th>Assets</th><th title="Active / all accounts in tools">Accounts</th><th>Atrium</th></tr></thead>
        <tbody>${rows.slice(0, ROW_LIMIT).map(personRow)}</tbody></table></div>
        ${rows.length > ROW_LIMIT ? html`<p class="faint" style="padding:10px 16px">Showing ${ROW_LIMIT} of ${rows.length} - search or filter to narrow the list.</p>` : ""}`
      : listing.total ? emptyState("search", "Nobody matches", "Change the search or the filters.")
        : emptyState("contact", "No people yet", "Connect a directory - Okta, Keycloak, any SCIM 2.0 service, or Snipe-IT users - in the Integration hub and the hub proposes the data flows. Or add people by hand.",
          html`<button type="button" class="btn primary" data-act="add" data-min-role="operator">${icon("plus")}Add person</button>`));
  };

  const drawLeavers = () => {
    setHTML($("[data-body]"), html`<div class="notice" style="margin-bottom:14px">${icon("shield")}<div style="min-width:0"><b>HB-AC-7 Leavers lose access and return assets.</b>
        <span class="muted">Fails while a suspended or terminated person keeps an enabled Atrium account or an active account in a tool; partial while they only keep assets.
        Accounts in other tools are closed there - the list says where.</span> <a href="#/compliance/controls">Controls &rarr;</a></div></div>
      ${leaverData.leavers.length ? html`<div class="stack" style="gap:10px">${leaverData.leavers.map(leaverCard)}</div>`
        : html`<section class="card">${emptyState("checkCircle", "No leavers holding anything", "Suspended or terminated people who still have assets, an Atrium account or an account in a tool show up here.")}</section>`}`);
  };

  const shownAccounts = () => {
    const q = acct.q.toLowerCase();
    return accounts.filter((a) => (!acct.tool || a.tool_id === acct.tool) && (!acct.unlinked || !a.person_id)
      && (!q || [a.login, a.email, a.display_name, a.app, a.person?.display_name].filter(Boolean).join(" ").toLowerCase().includes(q)));
  };
  const drawAccountTable = () => {
    const rows = shownAccounts();
    const unlinked = accounts.filter((a) => !a.person_id).length;
    $("[data-acct-count]").textContent = `${rows.length} of ${accounts.length}${unlinked ? ` - ${unlinked} not linked` : ""}`;
    setHTML($("[data-acct-table]"), rows.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
        <th>Tool</th><th>Account</th><th>Name</th><th>State</th><th>Last login</th><th>Person</th><th></th></tr></thead>
        <tbody>${rows.slice(0, ROW_LIMIT).map(accountRow)}</tbody></table></div>
        ${rows.length > ROW_LIMIT ? html`<p class="faint" style="padding:10px 16px">Showing ${ROW_LIMIT} of ${rows.length} - search to narrow the list.</p>` : ""}`
      : accounts.length ? emptyState("search", "No accounts match", "Change the search or the filters.")
        : emptyState("key", "No accounts yet", "Accounts come from directories (Okta, Keycloak, SCIM) and from accounts flows such as Snipe-IT users or Okta app links."));
  };
  const drawAccounts = () => {
    const tools = [...new Map(accounts.map((a) => [a.tool_id, a.tool])).entries()].sort((a, b) => a[1].localeCompare(b[1]));
    if (acct.tool && !tools.some(([id]) => id === acct.tool)) acct.tool = "";
    setHTML($("[data-body]"), html`<div class="row filters" style="margin-bottom:12px">
        <input id="acct-q" type="search" value="${acct.q}" placeholder="Search login, email, name, app, person..." aria-label="Search accounts" style="max-width:300px">
        <select class="input-sm" data-acct-tool aria-label="Tool">${options([["", "Every tool"], ...tools], acct.tool)}</select>
        <label class="check"><input type="checkbox" data-acct-unlinked ${acct.unlinked ? "checked" : ""}> Not linked only</label>
        <span class="spacer"></span><span class="faint" data-acct-count style="font-size:12.5px"></span></div>
      <section class="card flush" data-acct-table></section>`);
    $("#acct-q").addEventListener("input", debounce((e) => { acct.q = e.target.value.trim(); drawAccountTable(); }, 150));
    drawAccountTable();
  };

  /** Reload what the current tab shows (plus the counts); late answers from an older load are dropped. */
  const load = async () => {
    const mine = ++seq;
    const [list, extra] = await Promise.all([
      get(`/people?${new URLSearchParams(filters)}`),
      tab === "leavers" ? get("/people/leavers") : tab === "accounts" ? get("/accounts") : null,
    ]);
    if (mine !== seq || !el.isConnected) return;
    listing = list;
    if (tab === "leavers") leaverData = extra;
    if (tab === "accounts") accounts = extra;
    drawHead();
    if (tab === "people") drawPeople(); else if (tab === "leavers") drawLeavers(); else drawAccounts();
  };
  const refresh = () => load().catch((err) => toast(err.message, "bad"));

  el.addEventListener("change", (e) => {
    const t = e.target;
    if (t.matches("[data-filter]")) { filters[t.dataset.filter] = t.value; refresh(); }
    if (t.matches("[data-acct-tool]")) { acct.tool = t.value; drawAccountTable(); }
    if (t.matches("[data-acct-unlinked]")) { acct.unlinked = t.checked; drawAccountTable(); }
  });
  actions(el, {
    tab(d) {
      if (d.tab === tab) return;
      tab = d.tab;
      history.replaceState(null, "", tab === "people" ? "#/people" : `#/people/${tab}`);
      setHTML($("[data-body]"), html`<div class="empty faint">Loading...</div>`);
      refresh();
    },
    add: () => openAddPerson(),
    open: (d) => { location.hash = `#/people/${enc(d.id)}`; },
    async "person-action"(d, btn) {
      const f = leaverData?.leavers.find((x) => x.person_id === d.id);
      if (await runAction(d.id, d.action, f?.display_name || "this person", leaverData?.actions || [], btn)) refresh();
    },
    "link-account"(d) {
      const a = accounts?.find((x) => x.id === d.id);
      if (a) openLinkAccount(a, refresh);
    },
  });
  await load();
  ctx.live(LIVE, refresh, 600);
}

// ---------- person page ----------

const KIND_ORDER = ["manager", "atrium", "tool", "group", "asset"];
const KIND_LABEL = { manager: "Manager", atrium: "Atrium account", tool: "Tool", group: "Group", asset: "Asset" };
const KIND_ICON = { asset: "box", tool: "grid", group: "users", atrium: "lock" };
const RELATION = { owner: "owner", assigned: "uses", account: "account", directory: "directory", member: "member", manager: "manager", disabled: "disabled" };
const MAP_LIMIT = 24;
const short = (s, n = 18) => (String(s).length > n ? `${String(s).slice(0, n - 1)}...` : String(s));

/** SVG map: the person in the middle; assets, tools, groups, the manager and the Atrium account around them. */
function relationMap(g, personId) {
  const W = 640, H = 380, cx = W / 2, cy = H / 2 - 6;
  const all = g.nodes.slice().sort((a, b) => KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind));
  const nodes = all.slice(0, MAP_LIMIT);
  const rings = nodes.length > 12;
  const placed = nodes.map((n, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / nodes.length;
    const outer = !rings || i % 2 === 0;
    const [rx, ry] = outer ? [250, 136] : [150, 78];
    return { ...n, x: +(cx + rx * Math.cos(angle)).toFixed(1), y: +(cy + ry * Math.sin(angle)).toFixed(1) };
  });
  const navigable = (n) => n.kind === "asset" || n.kind === "tool" || n.kind === "manager" || (n.kind === "atrium" && can("admin"));
  const dashed = (n) => n.relation === "directory" || n.relation === "disabled" || n.relation === "assigned";
  const kinds = KIND_ORDER.filter((k) => nodes.some((n) => n.kind === k));
  const c = g.center;
  return html`<div class="relmap-wrap"><svg class="relmap" viewBox="0 0 ${W} ${H}" role="img" aria-label="${c.label}: ${all.length} linked item${all.length === 1 ? "" : "s"}">
      ${placed.map((n) => html`<line class="edge mk-${n.kind} ${dashed(n) ? "dashed" : ""}" x1="${cx}" y1="${cy}" x2="${n.x}" y2="${n.y}"/>`)}
      <g class="center st-${c.status}" transform="translate(${cx} ${cy})"><circle class="halo" r="33"/><circle r="28" style="fill:${colorFor(personId)}"/>
        <text class="ini big" dy="6">${c.initials}</text><text class="lbl strong" y="50">${short(c.label, 26)}</text></g>
      ${placed.map((n) => html`<g class="node mk-${n.kind} ${navigable(n) ? "link" : ""}" transform="translate(${n.x} ${n.y})"
          ${navigable(n) ? html`data-act="map-node" data-kind="${n.kind}" data-ref="${n.ref}" tabindex="0" role="link" aria-label="${KIND_LABEL[n.kind]} ${n.label}"` : ""}>
        <title>${KIND_LABEL[n.kind]}: ${n.label} (${RELATION[n.relation] || n.relation})</title>
        <circle r="17"/>${n.kind === "manager" ? html`<text class="ini" dy="4">${initialsOf(n.label)}</text>` : glyph(KIND_ICON[n.kind], -9, -9)}
        <text class="lbl" y="30">${short(n.label)}</text><text class="rel" y="42">${RELATION[n.relation] || n.relation}</text></g>`)}
      ${!nodes.length ? html`<text class="rel" x="${cx}" y="${cy + 76}">No assets, accounts or groups linked yet</text>` : ""}
      ${all.length > nodes.length ? html`<text class="rel" x="${W - 8}" y="${H - 8}" style="text-anchor:end">+${all.length - nodes.length} more</text>` : ""}
    </svg></div>
    ${kinds.length ? html`<div class="legend map-legend">${kinds.map((k) => html`<span class="mk-${k}"><i></i>${KIND_LABEL[k]}</span>`)}
      <span><i class="dash"></i>uses / directory only / disabled</span></div>` : ""}`;
}

function profileCard(p) {
  const row = (label, value) => (value ? html`<dt>${label}</dt><dd>${value}</dd>` : "");
  const said = p.source_list.filter((s) => s.status);
  return html`<div class="card"><header><h2>Profile</h2></header><dl class="kv">
    ${row("Email", p.email ? html`<a href="mailto:${p.email}">${p.email}</a>` : "")}
    ${row("Login", p.login ? html`<span class="mono">${p.login}</span>` : "")}
    ${row("Title", p.title)}${row("Department", p.department)}${row("Location", p.location)}${row("Phone", p.phone)}
    <dt>Status</dt><dd>${badge(p.status)}${said.length || p.manual_status ? html`<div class="faint" style="font-size:12px;margin-top:3px">
      ${[...said.map((s) => `${s.name}: ${s.status}`), ...(p.manual_status ? [`set by hand: ${p.manual_status}`] : [])].join(" - ")}</div>` : ""}</dd>
    ${row("Left", p.terminated_at ? dateTime(p.terminated_at) : "")}
    <dt>Sources</dt><dd>${p.source_list.map((s) => html`<div>${s.name}${s.id !== "manual" ? html` <span class="faint mono" style="font-size:11.5px">${s.external_id}</span>` : ""}</div>`)}</dd>
    <dt>Added</dt><dd title="${dateTime(p.created_at)}">${timeAgo(p.created_at)}</dd>
    <dt>Updated</dt><dd title="${dateTime(p.updated_at)}">${timeAgo(p.updated_at)}</dd></dl></div>`;
}

function orgCard(p) {
  return html`<div class="card"><header><h2>Manager &amp; reports</h2></header>
    <div class="faint" style="font-size:12px;margin-bottom:4px">Manager</div>
    ${p.manager ? personChip(p.manager) : html`<p class="muted">No manager</p>`}
    <div class="faint" style="font-size:12px;margin:12px 0 4px">Direct reports (${p.reports.length})</div>
    ${p.reports.length ? html`<div class="chip-list">${p.reports.map((r) => personChip(r))}</div>` : html`<p class="muted">None</p>`}</div>`;
}

function atriumCard(p) {
  const u = p.atrium;
  const left = p.status !== "active";
  return html`<div class="card"><header><h2>Atrium account</h2>${u ? (u.disabled ? badge("disabled") : badge("enabled", left ? "bad" : "ok")) : ""}</header>
    ${u ? html`<dl class="kv"><dt>Username</dt><dd><b>@${u.username}</b></dd><dt>Role</dt><dd>${roleBadge(u.role)}</dd>
        <dt>Sign-in</dt><dd>${u.auth_source === "oidc" ? "single sign-on" : "password"}</dd>
        <dt>Last login</dt><dd title="${dateTime(u.last_login)}">${u.last_login ? timeAgo(u.last_login) : "never"}</dd></dl>
      ${left && !u.disabled ? html`<div class="notice bad" style="margin-top:10px">${icon("alert")}<div style="font-size:12.5px">They have left but can still sign in to Atrium.</div></div>` : ""}
      <div class="row" style="gap:6px;margin-top:10px" data-min-role="admin">
        ${left && !u.disabled ? html`<button type="button" class="btn sm danger" data-act="person-action" data-id="${p.id}" data-action="disable_atrium_account">${icon("lock")}Disable account</button>` : ""}
        <a class="btn sm" href="#/users">${icon("users")}Users &amp; access</a></div>`
      : html`<p class="muted">${p.email ? `No Atrium account uses ${p.email}.` : "No email, so no Atrium account can be linked."}</p>`}</div>`;
}

function groupsCard(p) {
  const names = Object.fromEntries(p.source_list.map((s) => [s.id, s.name]));
  const entries = Object.entries(p.source_groups || {}).filter(([, groups]) => groups.length);
  return html`<div class="card"><header><h2>Groups (${p.groups.length})</h2></header>
    ${entries.length ? entries.map(([src, groups]) => html`<div style="margin-bottom:8px">
        <div class="faint" style="font-size:12px;margin-bottom:4px">${src === "manual" ? "Set by hand" : names[src] || src}</div>
        <div class="tag-list">${groups.map((g) => html`<span class="badge">${g}</span>`)}</div></div>`)
      : html`<p class="muted">No groups.</p>`}</div>`;
}

function grcCard(p) {
  const tone = (score) => (score >= 15 ? "bad" : score >= 9 ? "warn" : "");
  return html`<div class="card"><header><h2>Risks &amp; policies they own</h2></header>
    ${p.risks.length || p.policies.length ? html`
      ${p.risks.map((r) => html`<div class="msg-line">${badge(String(r.score), tone(r.score))}<a href="#/compliance/risks">${r.title}</a>${badge(r.status)}</div>`)}
      ${p.policies.map((x) => html`<div class="msg-line">${icon("file")}<a href="#/compliance/policies">${x.title} <span class="faint">v${x.version}</span></a>${badge(x.status)}</div>`)}`
      : html`<p class="muted">None. Pick ${p.display_name} as the owner of a risk or a policy in the Compliance hub.</p>`}</div>`;
}

function assetsCard(p) {
  const rows = p.assets;
  const how = (a) => (a.relation === "owner" && !a.also_assigned ? "set by hand" : a.assigned_source === "auto" ? "from the inventory" : "set by hand");
  return html`<div class="card flush"><header><h2>Assets (${rows.length})</h2>
      ${rows.length ? html`<button type="button" class="btn sm" data-act="unassign-all" data-min-role="operator">${icon("minus")}Unassign all</button>` : ""}</header>
    ${rows.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr><th>Asset</th><th>Relation</th><th>Criticality</th><th>Status</th><th>Linked</th><th></th></tr></thead><tbody>
      ${rows.map((a) => html`<tr>
        <td><a href="#/assets/${enc(a.id)}"><b>${a.name}</b></a><div class="faint" style="font-size:12px">${a.type}${a.source.startsWith("sync:") ? ` - from ${a.source.slice(5)}` : a.source !== "manual" ? " - auto" : ""}</div></td>
        <td>${a.also_assigned ? badge("owns and uses", "accent") : a.relation === "owner" ? badge("owner", "accent") : badge("uses", "info")}</td>
        <td>${badge(a.criticality)}</td><td>${badge(a.status)}</td><td class="faint" style="font-size:12px">${how(a)}</td>
        <td style="text-align:right"><button type="button" class="btn sm" data-act="unassign" data-id="${a.id}" data-min-role="operator">Unassign</button></td></tr>`)}
      </tbody></table></div>`
      : html`<p class="muted" style="padding:10px 16px 16px">No assets. Pick ${p.display_name} as owner or user of an asset, or let an inventory tool (Snipe-IT) assign devices.</p>`}</div>`;
}

function accountsCard(p) {
  const total = p.accounts_by_tool.reduce((n, t) => n + t.accounts.length, 0);
  return html`<div class="card flush"><header><h2>Accounts in tools (${total})</h2><a href="#/people/accounts" style="font-size:13px">All accounts &rarr;</a></header>
    ${total ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr><th>Tool</th><th>Account</th><th>App</th><th>State</th><th>Last login</th><th>Linked</th></tr></thead><tbody>
      ${p.accounts_by_tool.map((t) => t.accounts.map((a, i) => html`<tr>
        <td>${i === 0 ? html`<a href="#/tools/${enc(t.tool_id)}"><b>${t.tool}</b></a>` : ""}</td>
        <td><span class="mono" style="font-size:12.5px">${a.login || a.email || a.external_id}</span>${a.origin === "people" ? html` <span class="faint" style="font-size:12px">directory entry</span>` : ""}</td>
        <td>${a.app || html`<span class="faint">-</span>`}</td>
        <td>${a.active ? badge("active", p.status !== "active" ? "bad" : "ok") : badge("inactive")}</td>
        <td class="faint" title="${dateTime(a.last_login)}">${a.last_login ? timeAgo(a.last_login) : "-"}</td>
        <td class="faint" style="font-size:12px">${a.person_source === "manual" ? "by hand" : "by email or login"}</td></tr>`))}
      </tbody></table></div>`
      : html`<p class="muted" style="padding:10px 16px 16px">No accounts linked. Directories and accounts flows (Okta app links, SCIM, Snipe-IT users) link accounts by email, then login.</p>`}</div>`;
}

function vulnsCard(p) {
  const names = Object.fromEntries(p.assets.map((a) => [a.id, a.name]));
  return html`<div class="card flush"><header><h2>Open vulnerabilities on their assets (${p.vulnerabilities_open})</h2><a href="#/vulnerabilities" style="font-size:13px">Vulnerabilities &rarr;</a></header>
    ${p.vulnerabilities.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Due</th></tr></thead><tbody>
      ${p.vulnerabilities.map((v) => html`<tr><td>${sevBadge(v.severity)}</td><td><div class="clip">${v.title}</div></td>
        <td>${names[v.asset_id] || v.host || html`<span class="faint">-</span>`}</td>
        <td>${v.overdue ? badge("overdue", "bad") : v.due_at ? html`<span class="faint" title="${dateTime(v.due_at)}">${timeIn(v.due_at)}</span>` : html`<span class="faint">-</span>`}</td></tr>`)}
      </tbody></table></div>
      ${p.vulnerabilities_open > p.vulnerabilities.length ? html`<p class="faint" style="padding:8px 16px 12px;font-size:12.5px">Showing the ${p.vulnerabilities.length} most urgent.</p>` : ""}`
      : html`<p class="muted" style="padding:10px 16px 16px">No open findings on their assets.</p>`}</div>`;
}

function leaverNotice(p) {
  const f = p.leaver;
  return html`<div class="notice ${f.severity === "fail" ? "bad" : "warn"}" style="margin-bottom:16px">${icon("alert")}
    <div style="flex:1;min-width:0"><b>${f.severity === "fail" ? "Left, but still has access." : "Left, but still has company assets."}</b>
      <span class="muted">${f.summary}. Control HB-AC-7 ${f.severity === "fail" ? "fails" : "is partial"} until this is resolved.</span>
      ${holdings(f)}
      ${f.actions.length ? html`<div class="row" style="gap:6px;margin-top:8px">${actionButtons(p.id, f.actions)}</div>` : ""}</div></div>`;
}

function personPage(p) {
  const sources = p.source_list.filter((s) => s.id !== "manual");
  return html`
    <div class="page-head person-head">
      <div class="row" style="gap:16px;flex-wrap:nowrap;min-width:0">${personAvatar(p, "xl")}
        <div style="min-width:0"><a href="#/people" class="faint" style="font-size:12.5px">&larr; People</a>
          <h1>${p.display_name}</h1>
          <p class="muted">${[p.title, p.department].filter(Boolean).join(" - ") || "No title or department"}</p>
          <div class="row" style="gap:6px;margin-top:6px">${badge(p.status)}
            ${sources.map((s) => html`<span class="badge accent" title="${s.name} id ${s.external_id}">${icon("link")}${s.name}</span>`)}
            ${p.sources.manual ? badge("added by hand") : ""}</div></div></div>
      <div class="row" data-min-role="operator"><button type="button" class="btn" data-act="edit">${icon("edit")}Edit</button>
        <button type="button" class="btn danger" data-act="delete">${icon("trash")}Remove</button></div></div>
    ${p.leaver ? leaverNotice(p) : ""}
    <div class="grid split">
      <section class="stack">
        <div class="card"><header><h2>Relationships</h2><span class="faint" style="font-size:12px">click an asset, tool or manager to open it</span></header>${relationMap(p.graph, p.id)}</div>
        ${assetsCard(p)}
        ${accountsCard(p)}
        ${vulnsCard(p)}
        <div class="card"><header><h2>Recent activity</h2></header>${p.activity.length
          ? html`<div class="feed scroll">${p.activity.slice().reverse().map(feedItem)}</div>` : html`<p class="muted">Nothing recorded yet.</p>`}</div>
      </section>
      <section class="stack">${profileCard(p)}${orgCard(p)}${atriumCard(p)}${groupsCard(p)}${grcCard(p)}</section>
    </div>`;
}

async function renderPerson(el, ctx, id) {
  let p = null;
  const draw = async () => {
    let data;
    try {
      data = await get(`/people/${enc(id)}`);
    } catch (err) {
      if (err.status !== 404) throw err;
      ctx.crumb("People / not found");
      setHTML(el, html`<section class="card">${emptyState("contact", "Person not found", "They may have been removed.",
        html`<a class="btn" href="#/people">${icon("arrow")}All people</a>`)}</section>`);
      return;
    }
    if (!el.isConnected) return;
    p = data;
    ctx.crumb(`People / ${p.display_name}`);
    setHTML(el, personPage(p));
    const wrap = el.querySelector(".relmap-wrap"); // narrow screens: the map scrolls; start with the person in view
    if (wrap) wrap.scrollLeft = (wrap.scrollWidth - wrap.clientWidth) / 2;
  };
  const refresh = () => draw().catch((err) => toast(err.message, "bad"));
  actions(el, {
    edit: () => openPersonForm(p, refresh),
    async delete() {
      if (!(await confirmDialog(`Remove ${p.display_name}?`, "Links to their assets, accounts, risks and policies are cleared. A directory that still lists them brings them back at its next pull.", "Remove"))) return;
      try {
        await del(`/people/${enc(p.id)}`);
        toast(`${p.display_name} removed`, "ok");
        location.hash = "#/people";
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
    },
    async "person-action"(d, btn) {
      if (await runAction(p.id, d.action, p.display_name, p.actions, btn)) refresh();
    },
    async unassign(d) {
      const a = p.assets.find((x) => x.id === d.id);
      if (!a || !(await confirmDialog(`Unassign ${a.name}?`, `Take ${p.display_name} off ${a.name}. An assignment from the inventory tool stays off until someone sets it back to automatic in the asset.`, "Unassign"))) return;
      await unassign(p, [a.id]);
      refresh();
    },
    async "unassign-all"() {
      if (!(await confirmDialog(`Unassign every asset of ${p.display_name}?`, "Return the devices in the inventory tool too: the hub only removes its own links.", "Unassign all"))) return;
      await unassign(p, null);
      refresh();
    },
    "map-node"(d) {
      if (d.kind === "asset") location.hash = `#/assets/${enc(d.ref)}`;
      else if (d.kind === "tool") location.hash = `#/tools/${enc(d.ref)}`;
      else if (d.kind === "manager") location.hash = `#/people/${enc(d.ref)}`;
      else if (d.kind === "atrium") location.hash = "#/users";
    },
  });
  el.addEventListener("keydown", (e) => {
    const node = e.target.closest?.(".relmap [data-act]");
    if (node && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); node.dispatchEvent(new MouseEvent("click", { bubbles: true })); }
  });
  await draw();
  ctx.live([...LIVE, "risk", "risk_removed", "policy", "policy_removed", "vulnerability"], refresh, 600);
}

export async function render(el, ctx) {
  const [first] = ctx.params;
  if (first && !TABS.includes(first)) return renderPerson(el, ctx, first);
  return renderList(el, ctx, first || "people");
}
