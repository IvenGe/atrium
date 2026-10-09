// App shell: sign-in, top bar, Portals launcher, notifications, account menu, command palette, router.
import { connectEvents, disconnectEvents, get, onEvent, post } from "./api.js";
import { avatar, openChangePassword, openSessions, roleBadge, session, showAuth, showUnreachable } from "./auth.js";
import { xColor, xDomains, xHref } from "./extensions.js";
import { actions, appIcon, builtinIcon, can, debounce, emptyState, html, icon, modal, setHTML, timeAgo, toggleTheme } from "./ui.js";
import * as home from "./views/home.js";
import * as tools from "./views/tools.js";
import * as integration from "./views/integration.js";
import * as agents from "./views/agents.js";
import * as approvals from "./views/approvals.js";
import * as operator from "./views/operator.js";
import * as assets from "./views/assets.js";
import * as people from "./views/people.js";
import * as vulnerabilities from "./views/vulnerabilities.js";
import * as compliance from "./views/compliance.js";
import * as settings from "./views/settings.js";
import * as users from "./views/users.js";
import * as portal from "./views/portal.js";
import * as extensions from "./views/extensions.js";
import * as xdomain from "./views/xdomain.js";

// Built-in apps of the suite (shown in the sidebar and the Portals launcher). minRole hides an app from lower roles.
export const APPS = [
  { route: "", name: "Home", icon: "home", color: "#4f46e5", view: home },
  { route: "tools", name: "Apps", icon: "grid", color: "#7c3aed", view: tools },
  { route: "integration", name: "Integration hub", short: "Integration", icon: "plug", color: "#0ea5e9", view: integration },
  { route: "agents", name: "Agents", icon: "bot", color: "#9333ea", view: agents },
  { route: "approvals", name: "Approvals", icon: "checkCircle", color: "#ca8a04", view: approvals },
  { route: "operator", name: "Operator", icon: "terminal", color: "#334155", view: operator },
  { route: "assets", name: "Assets", icon: "box", color: "#0d9488", view: assets },
  { route: "people", name: "People", icon: "contact", color: "#e11d48", view: people },
  { route: "vulnerabilities", name: "Vulnerabilities", icon: "bug", color: "#dc2626", view: vulnerabilities },
  { route: "compliance", name: "Compliance hub", short: "Compliance", icon: "shield", color: "#16a34a", view: compliance },
  { route: "extensions", name: "Extensions", icon: "puzzle", color: "#c026d3", view: extensions },
  { route: "settings", name: "Settings", icon: "sliders", color: "#64748b", view: settings },
  { route: "users", name: "Users & access", short: "Users", icon: "users", color: "#db2777", view: users, minRole: "admin" },
];
const ROUTES = Object.fromEntries(APPS.map((a) => [a.route, a]));
ROUTES.portal = { route: "portal", name: "Portal", view: portal };
ROUTES.x = { route: "x", name: "Extension app", view: xdomain }; // #/x/<domain key>[/<record id>]

const state = { overview: null, tools: [], activity: [], restart: null };
const $ = (id) => document.getElementById(id);
let signedIn = false;
let restartHidden = null; // the merge commit whose "restart required" banner was hidden on this page load

// ---------- static chrome ----------
function chrome() {
  setHTML($("menu-btn"), icon("menu"));
  setHTML($("brand-mark"), icon("grid"));
  setHTML($("sun-icon"), icon("sun"));
  setHTML($("moon-icon"), icon("moon"));
  setHTML($("portals-btn"), html`${icon("grid")}<span class="txt">Portals</span>`);
  setHTML($("search-btn"), html`${icon("search")}<span class="label">Search...</span><kbd>Ctrl K</kbd>`);
  setHTML($("start-btn"), html`${icon("rocket")}<span class="txt">Get Started</span>`);

  renderNav();

  $("restart-banner").addEventListener("click", (e) => {
    if (!e.target.closest("[data-dismiss]")) return;
    restartHidden = state.restart?.commit || null;
    renderRestart();
  });
  $("theme-switch").addEventListener("click", toggleTheme);
  $("menu-btn").addEventListener("click", () => $("sidebar").classList.toggle("open"));
  $("portals-btn").addEventListener("click", (e) => { e.stopPropagation(); togglePopover("portals", $("portals-btn")); });
  $("bell-btn").addEventListener("click", (e) => { e.stopPropagation(); togglePopover("notifications", $("bell-btn")); });
  $("user-btn").addEventListener("click", (e) => { e.stopPropagation(); togglePopover("user-menu", $("user-btn")); });
  $("search-btn").addEventListener("click", openPalette);
  $("start-btn").addEventListener("click", getStarted);
  actions($("user-menu"), {
    password: () => { closePopovers(); openChangePassword(); },
    sessions: () => { closePopovers(); openSessions(); },
    signout: () => signOut(),
  });
  $("user-menu").addEventListener("click", (e) => { if (e.target.closest("a")) closePopovers(); });
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".popover")) closePopovers();
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k" && signedIn) { e.preventDefault(); openPalette(); }
    if (e.key === "Escape") closePopovers();
  });
}

// ---------- sidebar, extension apps, restart banner ----------
const xApp = (d) => ({ route: `x/${d.key}`, name: d.title, icon: d.icon, color: xColor(d.key), href: xHref(d.key) });

/** The sidebar: built-in apps, then one app per enabled extension domain (group "Extensions"). */
function renderNav() {
  const nav = [
    ...APPS.slice(0, 2),
    { section: "Run the suite" }, ...APPS.slice(2, 6),
    { section: "Govern" }, ...APPS.slice(6, 10),
    ...(xDomains.length ? [{ section: "Extensions" }, ...xDomains.map(xApp)] : []),
    { section: "" }, ...APPS.slice(10),
  ];
  setHTML($("nav"), nav.map((a) => a.section !== undefined
    ? html`<div class="section">${a.section}</div>`
    : html`<a href="${a.href || `#/${a.route}`}" data-route="${a.route}" ${a.minRole ? html`data-min-role="${a.minRole}"` : ""}>${icon(a.icon)}<span>${a.name}</span>${a.route === "approvals" ? html`<span class="count" id="nav-approvals" hidden></span>` : ""}</a>`));
  markActive();
}

let activeRoute = "";
function markActive() {
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === activeRoute));
}

/** Adopt a fresh list of extension domains; the sidebar is rebuilt only when the apps changed. */
function setXDomains(list) {
  const sig = (l) => JSON.stringify(l.map((d) => [d.key, d.title, d.icon]));
  if (sig(list) === sig(xDomains)) return;
  xDomains.splice(0, xDomains.length, ...list);
  renderNav();
  updateBadges();
}

function renderRestart() {
  const r = state.restart;
  const el = $("restart-banner");
  if (!r || !signedIn || restartHidden === r.commit) {
    el.hidden = true;
    return;
  }
  el.hidden = false;
  setHTML(el, html`${icon("refresh")}<div style="flex:1;min-width:0"><b>Restart required.</b>
      <span class="muted">The self-patch "${r.title}" was merged into ${r.branch || "the current branch"}${r.commit ? ` (${String(r.commit).slice(0, 10)})` : ""}${r.by ? ` by ${r.by}` : ""}.
      Restart Atrium to load the new code - changed web pages are served already.</span></div>
    <a class="btn sm" href="#/extensions/self-patches">Self-patches</a>
    <button type="button" class="icon-btn sm" data-dismiss title="Hide until the next page load" aria-label="Hide">${icon("x")}</button>`);
}

// ---------- popovers ----------
function togglePopover(id, anchor) {
  const pop = $(id);
  const open = !pop.classList.contains("open");
  closePopovers();
  if (!open) return;
  if (id === "portals") renderPortals(); else if (id === "user-menu") renderUserMenu(); else renderNotifications();
  const rect = anchor.getBoundingClientRect();
  pop.style.right = `${Math.max(12, window.innerWidth - rect.right)}px`;
  pop.classList.add("open");
  anchor.setAttribute("aria-expanded", "true");
  if (id === "notifications") {
    try { localStorage.setItem("hub.seen", String(state.activity.at(-1)?.seq || 0)); } catch {}
    updateBadges();
  }
}
function closePopovers() {
  document.querySelectorAll(".popover.open").forEach((p) => p.classList.remove("open"));
  document.querySelectorAll('[aria-expanded="true"]').forEach((b) => b.setAttribute("aria-expanded", "false"));
}

function renderPortals() {
  const builtins = APPS.filter((a) => a.route !== "settings" && can(a.minRole));
  setHTML($("portals"), html`
    <h4>Hub apps</h4>
    <div class="portal-grid">${builtins.map((a) => html`<a class="portal-tile" href="#/${a.route}">${builtinIcon(a.icon, a.color)}<span>${a.short || a.name}</span></a>`)}</div>
    ${xDomains.length ? html`<h4>Extensions</h4>
      <div class="portal-grid">${xDomains.map(xApp).map((a) => html`<a class="portal-tile" href="${a.href}" title="${a.name}">${builtinIcon(a.icon, a.color)}<span>${a.name}</span></a>`)}</div>` : ""}
    <h4>Your tools</h4>
    <div class="portal-grid">
      ${state.tools.map((t) => html`<a class="portal-tile" href="#/portal/${t.id}" title="${t.name}">${appIcon(t)}<span>${t.name}</span></a>`)}
      <a class="portal-tile" href="#/tools" data-import data-min-role="operator">${builtinIcon("plus", "var(--surface-2)")}<span>Import tool</span></a>
    </div>`);
  $("portals").querySelector("[data-import]").addEventListener("click", (e) => { e.preventDefault(); closePopovers(); tools.openImport(); });
  $("portals").querySelectorAll("a").forEach((a) => a.addEventListener("click", closePopovers));
}

function renderNotifications() {
  const pending = state.overview?.approvals_pending || 0;
  const items = state.activity.filter((a) => a.level !== "info" && !a.data?.approval_id).slice(-15).reverse();
  setHTML($("notifications"), html`
    <h4>Notifications</h4>
    <div class="notif-list">
      ${pending ? html`<a class="notif" href="#/approvals">${icon("checkCircle")}<div><b>${pending} agent action${pending > 1 ? "s" : ""} awaiting approval</b><div class="muted">Review commands and patches</div></div></a>` : ""}
      ${items.map((a) => html`<a class="notif" href="#/agents"><span class="dot ${a.level === "error" ? "bad" : "warn"}" style="margin-top:7px"></span>
        <div><div>${a.text}</div><div class="faint">${a.actor} - ${timeAgo(a.ts)}</div></div></a>`)}
      ${!pending && !items.length ? emptyState("bell", "All quiet", "Warnings and approvals show up here.") : ""}
    </div>`);
  $("notifications").querySelectorAll("a").forEach((a) => a.addEventListener("click", closePopovers));
}

// ---------- account ----------
function renderUserButton() {
  const u = session.user;
  setHTML($("user-btn"), avatar(u));
  $("user-btn").title = `${u.display_name || u.username} (${u.role})`;
}

function renderUserMenu() {
  const u = session.user;
  setHTML($("user-menu"), html`
    <div class="user-head">${avatar(u, "lg")}
      <div class="who"><b>${u.display_name || u.username}</b><span class="faint">@${u.username}</span></div>${roleBadge(u.role)}</div>
    ${u.has_password ? html`<button type="button" class="menu-item" data-act="password">${icon("key")}Change password</button>`
      : html`<div class="menu-note">${icon("shield")}Signs in through single sign-on</div>`}
    <button type="button" class="menu-item" data-act="sessions">${icon("monitor")}Sessions</button>
    <a class="menu-item" href="#/users" data-min-role="admin">${icon("users")}Users &amp; access</a>
    <div class="menu-sep"></div>
    <button type="button" class="menu-item danger" data-act="signout">${icon("logout")}Sign out</button>`);
}

async function signOut() {
  leaveApp();
  await post("/auth/logout").catch(() => {});
  boot({ text: "You have signed out.", tone: "ok" });
}

// ---------- command palette ----------
async function openPalette() {
  if (!signedIn) return;
  closePopovers();
  const [agentList, assetList, peopleList] = await Promise.all([get("/agents").catch(() => []), get("/assets").catch(() => []),
    get("/people?brief=1").then((r) => r.people).catch(() => [])]);
  const operatorActions = can("operator") ? [
    { label: "Import a tool", kind: "Action", icon: "plus", run: () => tools.openImport() },
    { label: "Add a person", kind: "Action", icon: "contact", run: () => people.openAddPerson() },
    { label: "Run a command", kind: "Action", icon: "terminal", go: "#/operator" },
    { label: "Scan for vulnerabilities", kind: "Action", icon: "radar", go: "#/vulnerabilities" },
    { label: "Ask the Hub Supervisor", kind: "Action", icon: "chat", go: "#/agents" },
  ] : [];
  const entries = [
    ...APPS.filter((a) => can(a.minRole)).map((a) => ({ label: a.name, kind: "Page", icon: a.icon, go: `#/${a.route}` })),
    { label: "Data flows", kind: "Page", icon: "flow", go: "#/integration", sub: "Integration hub" },
    { label: "Scan scope", kind: "Page", icon: "radar", go: "#/vulnerabilities/scope", sub: "Vulnerabilities" },
    { label: "Leavers", kind: "Page", icon: "alert", go: "#/people/leavers", sub: "People" },
    { label: "Accounts in tools", kind: "Page", icon: "key", go: "#/people/accounts", sub: "People" },
    ...(can("admin") ? [{ label: "Sign-in & SSO", kind: "Page", icon: "shield", go: "#/settings/sso", sub: "Settings" }] : []),
    ...xDomains.map(xApp).map((a) => ({ label: a.name, kind: "App", icon: a.icon, go: a.href, sub: "Extension" })),
    { label: "Gaps in Atrium", kind: "Page", icon: "alert", go: "#/extensions/gaps", sub: "Extensions" },
    { label: "Self-patches", kind: "Page", icon: "branch", go: "#/extensions/self-patches", sub: "Extensions" },
    ...(can("admin") ? [{ label: "Upload an extension pack", kind: "Action", icon: "upload", run: () => { location.hash = "#/extensions"; setTimeout(() => extensions.openUpload(), 50); } }] : []),
    ...operatorActions,
    ...(session.user?.has_password ? [{ label: "Change password", kind: "Account", icon: "key", run: openChangePassword }] : []),
    { label: "Sessions", kind: "Account", icon: "monitor", run: openSessions },
    { label: "Sign out", kind: "Account", icon: "logout", run: signOut },
    ...state.tools.map((t) => ({ label: t.name, kind: "Tool", icon: "grid", go: `#/tools/${t.id}`, sub: t.source })),
    ...agentList.map((a) => ({ label: a.name, kind: "Agent", icon: "bot", go: "#/agents", sub: a.title })),
    ...assetList.filter((a) => a.status !== "retired").map((a) => ({ label: a.name, kind: "Asset", icon: "box", go: `#/assets/${encodeURIComponent(a.id)}`, sub: a.type })),
    ...peopleList.map((p) => ({ label: p.display_name, kind: "Person", icon: "user", go: `#/people/${encodeURIComponent(p.id)}`,
      sub: [p.title, p.email, p.status !== "active" ? p.status : ""].filter(Boolean).join(" - ") })),
  ];
  if (!signedIn) return; // signed out while loading
  const backdrop = document.createElement("div");
  backdrop.className = "backdrop";
  setHTML(backdrop, html`<div class="palette" role="dialog" aria-label="Search">
    <div class="search">${icon("search")}<input placeholder="Search tools, agents, assets, pages..." aria-label="Search"><kbd>Esc</kbd></div>
    <ul role="listbox"></ul></div>`);
  document.body.append(backdrop);
  const input = backdrop.querySelector("input");
  const list = backdrop.querySelector("ul");
  let sel = 0, shown = [];
  const close = () => backdrop.remove();
  const choose = (entry) => { close(); if (entry.run) entry.run(); else location.hash = entry.go; };
  const draw = () => {
    const q = input.value.trim().toLowerCase();
    shown = entries.filter((e) => !q || `${e.label} ${e.kind} ${e.sub || ""}`.toLowerCase().includes(q)).slice(0, 40);
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    setHTML(list, shown.length ? shown.map((e, i) => html`<li class="${i === sel ? "sel" : ""}" data-i="${i}" role="option">${icon(e.icon)}<span>${e.label}${e.sub ? html` <span class="faint">${e.sub}</span>` : ""}</span><span class="kind">${e.kind}</span></li>`)
      : html`<li class="faint">No results</li>`);
  };
  input.addEventListener("input", () => { sel = 0; draw(); });
  input.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") { sel = Math.min(sel + 1, shown.length - 1); draw(); e.preventDefault(); }
    if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
    if (e.key === "Enter" && shown[sel]) choose(shown[sel]);
    if (e.key === "Escape") close();
  });
  list.addEventListener("click", (e) => { const li = e.target.closest("li[data-i]"); if (li) choose(shown[+li.dataset.i]); });
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop) close(); });
  draw();
  input.focus();
}

// ---------- get started ----------
function getStarted() {
  const llm = state.overview?.llm;
  const step = (n, title, text, act, label, minRole = "") => html`<div class="check-row"><div class="ico pass" style="width:28px;height:28px"><b>${n}</b></div>
    <div style="flex:1"><h3>${title}</h3><p class="muted">${text}</p></div><button type="button" class="btn sm" data-act="${act}" data-min-role="${minRole}">${label}</button></div>`;
  const m = modal({
    title: "Get started with Atrium",
    submit: null, cancel: "Close",
    body: html`<p class="muted" style="margin-bottom:8px">Atrium brings your open-source projects, closed-source apps and SaaS services together.
      A Hub Supervisor agent coordinates one supervisor agent per tool, a Patch Agent that makes tools fit, and an Operator Agent that runs commands.</p>
      ${step(1, "Import your first tool", "From GitHub, a folder on this machine, or a SaaS URL with its OpenAPI spec.", "import", "Import", "operator")}
      ${step(2, "Connect a server", "Register an SSH host so the Operator can run commands and the Asset Supervisor can inventory it.", "host", "Add host", "operator")}
      ${step(3, "Let tools exchange data", "Set up a tool's API in its Connection tab (Snipe-IT, OpenVAS, CISO Assistant or any REST API); the hub proposes data flows into Assets, Vulnerabilities and Compliance.", "flows", "Open")}
      ${step(4, "Review approvals", "Agents ask before they change anything. Approve or reject their patches, data flows, scans and repairs.", "approvals", "Open")}
      ${step(5, "Check compliance", "The GRC Supervisor maps live evidence to ISO 27001, SOC 2 and NIS2 controls.", "compliance", "Open")}
      ${can("admin") ? step(6, "Invite your team", "Give people their own accounts as viewer, operator or admin, and create API tokens for integrations.", "users", "Open") : ""}
      ${llm && !llm.available ? html`<div class="notice" style="margin-top:14px">${icon("bot")}<div><b>Agents are in rules mode.</b>
        <span class="muted">Set <code>ANTHROPIC_API_KEY</code> before starting the hub to let them plan in plain language and write code patches with Claude.</span></div></div>` : ""}`,
  });
  actions(m.el, {
    import: () => { m.close(); tools.openImport(); },
    host: () => { m.close(); location.hash = "#/operator"; setTimeout(() => operator.openAddHost(), 50); },
    flows: () => { m.close(); location.hash = "#/integration"; },
    approvals: () => { m.close(); location.hash = "#/approvals"; },
    compliance: () => { m.close(); location.hash = "#/compliance"; },
    users: () => { m.close(); location.hash = "#/users"; },
  });
}

// ---------- sub bar & badges ----------
function renderSubbar(app, extra) {
  const pending = state.overview?.approvals_pending || 0;
  setHTML($("subbar"), html`
    <div class="crumbs">Atrium / <b>${extra || app.name}</b></div>
    <div class="spacer"></div>
    ${pending ? html`<a class="chip-link" href="#/approvals"><span class="pulse"></span>${pending} agent action${pending > 1 ? "s" : ""} awaiting approval</a>` : ""}
    <a class="hub-link" href="#/compliance">Open the Compliance hub &rarr;</a>`);
}

function updateBadges() {
  const pending = state.overview?.approvals_pending || 0;
  const navCount = $("nav-approvals");
  if (navCount) { navCount.hidden = !pending; navCount.textContent = pending; }
  let seen = 0;
  try { seen = +(localStorage.getItem("hub.seen") || 0); } catch {}
  // approvals are counted once via `pending`, not again through their activity entries
  const unread = state.activity.filter((a) => a.level !== "info" && a.seq > seen && !a.data?.approval_id).length + pending;
  setHTML($("bell-btn"), html`${icon("bell")}${unread ? html`<span class="dot-badge">${unread > 99 ? "99+" : unread}</span>` : ""}`);
}

async function refreshState() {
  if (!signedIn) return;
  const [overview, toolList, activity, xList] = await Promise.all([get("/overview"), get("/tools"), get("/activity?limit=120"),
    get("/x").catch(() => null)]);
  if (!signedIn) return;
  Object.assign(state, { overview, tools: toolList, activity });
  if (xList) setXDomains(xList);
  if (!overview.restart_required) state.restart = null;
  else if (!state.restart) state.restart = await get("/self-patches").then((r) => r.restart_required).catch(() => null);
  renderRestart();
  updateBadges();
  if (currentApp) renderSubbar(currentApp, currentCrumb);
}

// ---------- router ----------
let cleanup = null;
let currentApp = null;
let currentCrumb = null;

async function route() {
  if (!signedIn) return;
  cleanup?.();
  const [name = "", ...params] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  const app = ROUTES[name] || ROUTES[""];
  currentApp = app;
  currentCrumb = null;
  activeRoute = app.route === "portal" ? "tools" : app.route === "x" ? `x/${params[0] || ""}` : app.route;
  markActive();
  $("sidebar").classList.remove("open");
  closePopovers();
  renderSubbar(app);
  // A fresh <main> per page drops the previous view's delegated listeners and any late async renders.
  const old = $("main");
  const main = old.cloneNode(false);
  old.replaceWith(main);
  setHTML(main, html`<div class="empty faint">Loading...</div>`);
  const disposers = [];
  const ctx = {
    params,
    state,
    live(types, fn, wait = 350) { disposers.push(onEvent(types, debounce(fn, wait))); },
    crumb(text) { currentCrumb = text; renderSubbar(app, text); document.title = `${text} - Atrium`; },
  };
  cleanup = () => disposers.forEach((off) => off());
  document.title = `${app.name} - Atrium`;
  try {
    await app.view.render(main, ctx);
  } catch (err) {
    setHTML(main, emptyState("alert", "Something went wrong", err.message));
  }
  if (!signedIn) main.replaceChildren(); // signed out while the page was loading: keep nothing behind
}

// ---------- session ----------
function startEvents() {
  connectEvents((ok, closed) => {
    $("brand-mark").style.opacity = ok ? "1" : ".45";
    if (!ok) checkSession(closed);
  });
}

// The event stream failed: find out whether the session ended, and reconnect if the browser gave up.
const checkSession = debounce(async (closed) => {
  if (!signedIn) return;
  try {
    const me = await get("/auth/me");
    if (!me.authenticated) return window.dispatchEvent(new CustomEvent("atrium:signed-out"));
    if (me.user?.must_change_password) return window.dispatchEvent(new CustomEvent("atrium:password-change"));
  } catch { /* hub unreachable */ }
  if (closed) setTimeout(() => { if (signedIn) startEvents(); }, 4000);
}, 1500);

function enterApp(user) {
  session.user = user;
  signedIn = true;
  setHTML($("auth"), "");
  document.body.dataset.role = user.role;
  document.body.classList.add("signed-in");
  renderUserButton();
  if (/^#\/(login|setup)\b/.test(location.hash)) history.replaceState(null, "", "#/");
  startEvents();
  refreshState().catch(() => {}).finally(route);
}

function leaveApp() {
  signedIn = false;
  session.user = null;
  disconnectEvents();
  cleanup?.();
  currentApp = null;
  closePopovers();
  document.querySelectorAll(".backdrop").forEach((b) => b.remove());
  document.body.classList.remove("signed-in");
  delete document.body.dataset.role;
  Object.assign(state, { overview: null, tools: [], activity: [], restart: null });
  renderRestart();
  setXDomains([]);
  agents.resetChat();
  setHTML($("main"), "");
  setHTML($("user-menu"), "");
}

/** Asks the server who is signed in, then starts the app or shows the sign-in screen. */
async function boot(notice) {
  let me;
  try {
    me = await get("/auth/me");
  } catch (err) {
    showUnreachable(err, () => boot(notice));
    return;
  }
  if (me.authenticated && me.user && !me.user.must_change_password) return enterApp(me.user);
  showAuth(me, { notice, onDone: (next) => boot(next) });
}

window.addEventListener("atrium:signed-out", () => {
  if (!signedIn) return;
  leaveApp();
  boot({ text: "Your session ended. Sign in again.", tone: "warn" });
});
window.addEventListener("atrium:password-change", () => {
  if (!signedIn) return;
  leaveApp();
  boot();
});
// The signed-in user's own record changed (e.g. an admin edited their name): refresh the account button.
window.addEventListener("atrium:user-updated", async () => {
  if (!signedIn) return;
  const me = await get("/auth/me").catch(() => null);
  if (!me?.user || !signedIn) return;
  session.user = me.user;
  document.body.dataset.role = me.user.role;
  renderUserButton();
});

// ---------- boot ----------
chrome();
window.addEventListener("hashchange", route);
onEvent(["approval", "tool", "tool_removed", "activity", "asset", "grc", "risk", "extension", "extension_removed"],
  debounce(() => refreshState().catch(() => {}), 500));
onEvent("restart_required", (e) => {
  if (!signedIn || !e.data) return;
  state.restart = e.data;
  renderRestart();
});
boot();
