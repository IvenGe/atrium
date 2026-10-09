// App shell: top bar, Portals launcher, notifications, command palette, router.
import { connectEvents, get, onEvent } from "./api.js";
import { actions, appIcon, builtinIcon, debounce, emptyState, html, icon, modal, setHTML, timeAgo } from "./ui.js";
import * as home from "./views/home.js";
import * as tools from "./views/tools.js";
import * as integration from "./views/integration.js";
import * as agents from "./views/agents.js";
import * as approvals from "./views/approvals.js";
import * as operator from "./views/operator.js";
import * as assets from "./views/assets.js";
import * as compliance from "./views/compliance.js";
import * as settings from "./views/settings.js";
import * as portal from "./views/portal.js";

// Built-in apps of the suite (shown in the sidebar and the Portals launcher).
export const APPS = [
  { route: "", name: "Home", icon: "home", color: "#4f46e5", view: home },
  { route: "tools", name: "Apps", icon: "grid", color: "#7c3aed", view: tools },
  { route: "integration", name: "Integration hub", short: "Integration", icon: "plug", color: "#0ea5e9", view: integration },
  { route: "agents", name: "Agents", icon: "bot", color: "#9333ea", view: agents },
  { route: "approvals", name: "Approvals", icon: "checkCircle", color: "#ca8a04", view: approvals },
  { route: "operator", name: "Operator", icon: "terminal", color: "#334155", view: operator },
  { route: "assets", name: "Assets", icon: "box", color: "#0d9488", view: assets },
  { route: "compliance", name: "Compliance hub", short: "Compliance", icon: "shield", color: "#16a34a", view: compliance },
  { route: "settings", name: "Settings", icon: "sliders", color: "#64748b", view: settings },
];
const ROUTES = Object.fromEntries(APPS.map((a) => [a.route, a]));
ROUTES.portal = { route: "portal", name: "Portal", view: portal };

const state = { overview: null, tools: [], activity: [] };
const $ = (id) => document.getElementById(id);

// ---------- static chrome ----------
function chrome() {
  setHTML($("menu-btn"), icon("menu"));
  setHTML($("brand-mark"), icon("grid"));
  setHTML($("sun-icon"), icon("sun"));
  setHTML($("moon-icon"), icon("moon"));
  setHTML($("portals-btn"), html`${icon("grid")}<span class="txt">Portals</span>`);
  setHTML($("search-btn"), html`${icon("search")}<span class="label">Search...</span><kbd>Ctrl K</kbd>`);
  setHTML($("start-btn"), html`${icon("rocket")}<span class="txt">Get Started</span>`);

  const nav = [
    ...APPS.slice(0, 2),
    { section: "Run the suite" }, ...APPS.slice(2, 6),
    { section: "Govern" }, ...APPS.slice(6, 8),
    { section: "" }, APPS[8],
  ];
  setHTML($("nav"), nav.map((a) => a.section !== undefined
    ? html`<div class="section">${a.section}</div>`
    : html`<a href="#/${a.route}" data-route="${a.route}">${icon(a.icon)}<span>${a.name}</span>${a.route === "approvals" ? html`<span class="count" id="nav-approvals" hidden></span>` : ""}</a>`));

  $("theme-switch").addEventListener("click", () => {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("hub.theme", next); } catch {}
  });
  $("menu-btn").addEventListener("click", () => $("sidebar").classList.toggle("open"));
  $("portals-btn").addEventListener("click", (e) => { e.stopPropagation(); togglePopover("portals", $("portals-btn")); });
  $("bell-btn").addEventListener("click", (e) => { e.stopPropagation(); togglePopover("notifications", $("bell-btn")); });
  $("search-btn").addEventListener("click", openPalette);
  $("start-btn").addEventListener("click", getStarted);
  document.addEventListener("click", (e) => {
    if (!e.target.closest(".popover")) closePopovers();
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    if (e.key === "Escape") closePopovers();
  });
}

// ---------- popovers ----------
function togglePopover(id, anchor) {
  const pop = $(id);
  const open = !pop.classList.contains("open");
  closePopovers();
  if (!open) return;
  if (id === "portals") renderPortals(); else renderNotifications();
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
  const builtins = APPS.filter((a) => a.route !== "settings");
  setHTML($("portals"), html`
    <h4>Hub apps</h4>
    <div class="portal-grid">${builtins.map((a) => html`<a class="portal-tile" href="#/${a.route}">${builtinIcon(a.icon, a.color)}<span>${a.short || a.name}</span></a>`)}</div>
    <h4>Your tools</h4>
    <div class="portal-grid">
      ${state.tools.map((t) => html`<a class="portal-tile" href="#/portal/${t.id}" title="${t.name}">${appIcon(t)}<span>${t.name}</span></a>`)}
      <a class="portal-tile" href="#/tools" data-import>${builtinIcon("plus", "var(--surface-2)")}<span>Import tool</span></a>
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

// ---------- command palette ----------
async function openPalette() {
  closePopovers();
  const [agentList, assetList] = await Promise.all([get("/agents").catch(() => []), get("/assets").catch(() => [])]);
  const entries = [
    ...APPS.map((a) => ({ label: a.name, kind: "Page", icon: a.icon, go: `#/${a.route}` })),
    { label: "Import a tool", kind: "Action", icon: "plus", run: () => tools.openImport() },
    { label: "Run a command", kind: "Action", icon: "terminal", go: "#/operator" },
    { label: "Ask the Hub Supervisor", kind: "Action", icon: "chat", go: "#/agents" },
    ...state.tools.map((t) => ({ label: t.name, kind: "Tool", icon: "grid", go: `#/tools/${t.id}`, sub: t.source })),
    ...agentList.map((a) => ({ label: a.name, kind: "Agent", icon: "bot", go: "#/agents", sub: a.title })),
    ...assetList.filter((a) => a.status !== "retired").map((a) => ({ label: a.name, kind: "Asset", icon: "box", go: "#/assets", sub: a.type })),
  ];
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
  const step = (n, title, text, act, label) => html`<div class="check-row"><div class="ico pass" style="width:28px;height:28px"><b>${n}</b></div>
    <div style="flex:1"><h3>${title}</h3><p class="muted">${text}</p></div><button type="button" class="btn sm" data-act="${act}">${label}</button></div>`;
  const m = modal({
    title: "Get started with Atrium",
    submit: null, cancel: "Close",
    body: html`<p class="muted" style="margin-bottom:8px">Atrium brings your open-source projects, closed-source apps and SaaS services together.
      A Hub Supervisor agent coordinates one supervisor agent per tool, a Patch Agent that makes tools fit, and an Operator Agent that runs commands.</p>
      ${step(1, "Import your first tool", "From GitHub, a folder on this machine, or a SaaS URL with its OpenAPI spec.", "import", "Import")}
      ${step(2, "Connect a server", "Register an SSH host so the Operator can run commands and the Asset Supervisor can inventory it.", "host", "Add host")}
      ${step(3, "Review approvals", "Agents ask before they change anything. Approve or reject their patches and commands.", "approvals", "Open")}
      ${step(4, "Check compliance", "The GRC Supervisor maps live evidence to ISO 27001, SOC 2 and NIS2 controls.", "compliance", "Open")}
      ${llm && !llm.available ? html`<div class="notice" style="margin-top:14px">${icon("bot")}<div><b>Agents are in rules mode.</b>
        <span class="muted">Set <code>ANTHROPIC_API_KEY</code> before starting the hub to let them plan in plain language and write code patches with Claude.</span></div></div>` : ""}`,
  });
  actions(m.el, {
    import: () => { m.close(); tools.openImport(); },
    host: () => { m.close(); location.hash = "#/operator"; setTimeout(() => operator.openAddHost(), 50); },
    approvals: () => { m.close(); location.hash = "#/approvals"; },
    compliance: () => { m.close(); location.hash = "#/compliance"; },
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
  const [overview, toolList, activity] = await Promise.all([get("/overview"), get("/tools"), get("/activity?limit=120")]);
  Object.assign(state, { overview, tools: toolList, activity });
  updateBadges();
  if (currentApp) renderSubbar(currentApp, currentCrumb);
}

// ---------- router ----------
let cleanup = null;
let currentApp = null;
let currentCrumb = null;

async function route() {
  cleanup?.();
  const [name = "", ...params] = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
  const app = ROUTES[name] || ROUTES[""];
  currentApp = app;
  currentCrumb = null;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === (app.route === "portal" ? "tools" : app.route)));
  $("sidebar").classList.remove("open");
  closePopovers();
  renderSubbar(app);
  const main = $("main");
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
}

// ---------- boot ----------
chrome();
window.addEventListener("hashchange", route);
connectEvents((ok) => $("brand-mark").style.opacity = ok ? "1" : ".45");
onEvent(["approval", "tool", "tool_removed", "activity", "asset", "grc", "risk"], debounce(() => refreshState().catch(() => {}), 500));
refreshState().catch(() => {}).finally(route);

