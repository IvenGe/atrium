// The widget gallery (round4-dashboard-spec.md 10.8): what can be added to a dashboard - each connected tool's
// suggestions ("From your tools"), the hub-wide suggestions, and the generic types, which open the configure dialog
// first. In grid mode it is a non-modal drawer whose cards can also be dragged onto the grid by their grip (the Add
// button is the single-pointer and keyboard path); in stack mode it is a modal. Cards show a small static schematic and
// never live data, so opening the gallery costs nothing but the catalog.
import { appIcon, html, icon, modal, setHTML } from "../ui.js";

export const CATEGORIES = [["all", "All"], ["mine", "From your tools"], ["overview", "Overview"], ["tools", "Tools"],
  ["records", "Records"], ["agents", "Agents"], ["compliance", "Compliance"], ["network", "Network"], ["people", "People"],
  ["settings", "Settings"], ["embedded", "Embedded"], ["notes", "Notes"]];
const SCHEMATIC = { metric: "number", tool_health: "tiles", tool_overview: "bars", agent_activity: "list", agents_status: "list",
  approvals_queue: "list", note: "text", links: "list", domain_count: "bars", domain_list: "list", domain_timeline: "bars",
  compliance_overview: "bars", controls_status: "list", risk_matrix: "tiles", vuln_sla: "number", network_overview: "list",
  leavers: "list", declared: "bars", ai_models: "tiles", safety_settings: "list", hub_accounts: "number" };
const BY_CATEGORY = { records: "bars", compliance: "bars", network: "list", people: "list", settings: "list", tools: "tiles" };
const ASK_FIRST = new Set(["note", "links"]); // a hub suggestion of these would be empty: their "build your own" card asks

/** The gallery's cards: {key, kind: "suggestion" | "type", group, category, title, description, type, config, size, tool,
 *  pack, declared_by, invalid}. A tool's and a pack's suggestions are "From your tools"; an invalid declaration is shown
 *  with its reason and cannot be added. */
export function galleryEntries(catalog) {
  const types = new Map(catalog.types.map((t) => [t.key, t]));
  const tools = new Map(catalog.tools.map((t) => [t.id, t]));
  const out = [];
  for (const s of catalog.suggestions || []) {
    const t = types.get(s.type);
    if (!t || (s.group === "hub" && ASK_FIRST.has(s.type))) continue;
    const toolId = s.group.startsWith("tool:") ? s.group.slice(5) : null;
    const packId = s.group.startsWith("pack:") ? s.group.slice(5) : null;
    out.push({ key: s.id, kind: "suggestion", group: s.group, category: toolId || packId ? "mine" : t.category, title: s.title,
      description: s.description || t.description, type: s.type, config: s.config, size: s.size,
      tool: toolId ? tools.get(toolId) || { id: toolId, name: toolId } : null,
      pack: packId ? { id: packId, name: s.declared_by?.name || packId } : null, declared_by: s.declared_by || null,
      invalid: s.invalid || null });
  }
  for (const t of catalog.types) {
    if (t.key === "tool_page") continue; // tools' own pages: the optional stage D5, not built
    out.push({ key: `type:${t.key}`, kind: "type", group: "types", category: t.category, title: `${t.title}...`, description: t.description,
      type: t.key, config: {}, size: [t.size.default.w, t.size.default.h], tool: null });
  }
  return out;
}

/** The cards of one category that match a search (title, description and tool name). */
export function filterEntries(entries, { category = "all", query = "" } = {}) {
  const q = query.trim().toLowerCase();
  return entries.filter((e) => (category === "all" || e.category === category)
    && (!q || `${e.title} ${e.description} ${e.tool?.name || ""} ${e.pack?.name || ""}`.toLowerCase().includes(q)));
}

function card(e, i, { drawer, full }) {
  const schem = SCHEMATIC[e.type] || BY_CATEGORY[e.category] || "list";
  const by = e.declared_by ? `${e.declared_by.kind === "pack" ? "From" : "Suggested by"} ${e.declared_by.name || e.declared_by.id}` : "";
  const why = e.invalid ? `g-why-${i}` : null;
  return html`<li class="dash-card ${e.invalid ? "invalid" : ""}">
    ${drawer && !e.invalid ? html`<span class="dash-card-grip" data-grip="${i}" aria-hidden="true" title="Drag onto the dashboard">${icon("grip")}</span>` : ""}
    <span class="dash-schem s-${schem}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>
    <div class="dash-card-text"><b>${e.title}</b><p>${e.description}</p>
      ${by && e.description !== by ? html`<span class="faint dash-small">${by}</span>` : ""}
      ${e.invalid ? html`<span class="dash-invalid" id="${why}">${icon("alert")}Cannot be added: ${e.invalid}</span>` : ""}</div>
    <button type="button" class="btn sm" data-act="g-add" data-i="${i}" ${full || e.invalid ? html`disabled` : ""} ${why ? html`aria-describedby="${why}"` : ""}
      aria-label="${e.kind === "type" ? `Add ${e.title.replace(/\.\.\.$/, "")}, choose its settings first` : `Add ${e.title}`}">${e.kind === "type" ? "Add..." : "Add"}</button></li>`;
}

/**
 * Opens the gallery. host: where the drawer goes; drawer: grid mode (else a modal); full: the dashboard holds the most
 * widgets it may; onAdd(entry) for a suggestion, onConfigure(entry) for a generic type, onDrag(event, entry) when a
 * card's grip is dragged; onClose() after it closed. Returns {close, setFull(full)}.
 */
export function openGallery({ catalog, host, drawer, full = false, limit = 40, onAdd, onConfigure, onDrag, onClose }) {
  const entries = galleryEntries(catalog);
  const st = { category: "all", query: "", full };
  const present = new Set(["all", ...entries.map((e) => e.category)]);
  const chips = CATEGORIES.filter(([k]) => present.has(k));
  const shell = html`<div class="dash-gallery">
    <input type="search" class="dash-search" placeholder="Search widgets and tools" aria-label="Search widgets and tools" autocomplete="off">
    <div class="dash-chips" role="group" aria-label="Categories">${chips.map(([k, label]) => html`<button type="button" class="dash-chip" data-cat="${k}" aria-pressed="${k === "all" ? "true" : "false"}">${label}</button>`)}</div>
    <p class="notice warn dash-full" data-full hidden>${icon("alert")}<span>This dashboard has ${limit} widgets, the maximum. Remove one to add another.</span></p>
    <div class="dash-gallery-list" data-list></div></div>`;
  let root, closeModal = null, closed = false;
  if (drawer) {
    root = document.createElement("aside");
    root.className = "dash-drawer";
    root.setAttribute("aria-label", "Add widgets");
    setHTML(root, html`<header><h2>Add widgets</h2><button type="button" class="icon-btn" data-g="close" aria-label="Close the widget gallery">${icon("x")}</button></header>${shell}`);
    host.append(root);
  } else {
    const m = modal({ title: "Add widgets", wide: true, submit: null, cancel: "Close", body: shell, onClose: () => finish() });
    root = m.el;
    closeModal = m.close;
  }
  const list = root.querySelector("[data-list]");
  let shown = [];

  function draw() {
    root.querySelector("[data-full]").hidden = !st.full;
    shown = filterEntries(entries, st);
    const sections = [];
    const byTool = new Map();
    for (const e of shown.filter((x) => x.tool)) {
      if (!byTool.has(e.tool.id)) byTool.set(e.tool.id, []);
      byTool.get(e.tool.id).push(e);
    }
    const index = (e) => shown.indexOf(e);
    const opts = { drawer, full: st.full };
    const byPack = new Map();
    for (const e of shown.filter((x) => x.pack)) {
      if (!byPack.has(e.pack.id)) byPack.set(e.pack.id, []);
      byPack.get(e.pack.id).push(e);
    }
    for (const group of byTool.values()) {
      const tool = group[0].tool;
      sections.push(html`<section class="dash-gsec"><h3>${appIcon({ id: tool.id, name: tool.name, manifest: { ui: tool.ui || {} } }, "sm")}<span>${tool.name}</span></h3>
        <ul class="dash-cards">${group.map((e) => card(e, index(e), opts))}</ul></section>`);
    }
    for (const group of byPack.values()) {
      sections.push(html`<section class="dash-gsec"><h3>${icon("puzzle")}<span>From ${group[0].pack.name}</span></h3>
        <ul class="dash-cards">${group.map((e) => card(e, index(e), opts))}</ul></section>`);
    }
    const hub = shown.filter((e) => e.kind === "suggestion" && !e.tool && !e.pack);
    if (hub.length) sections.push(html`<section class="dash-gsec"><h3>${icon("home")}<span>From the hub</span></h3><ul class="dash-cards">${hub.map((e) => card(e, index(e), opts))}</ul></section>`);
    const types = shown.filter((e) => e.kind === "type");
    if (types.length) sections.push(html`<section class="dash-gsec"><h3>${icon("sliders")}<span>Build your own</span></h3><ul class="dash-cards">${types.map((e) => card(e, index(e), opts))}</ul></section>`);
    setHTML(list, sections.length ? sections : html`<p class="muted dash-none">Nothing matches "${st.query}".</p>`);
  }

  function finish() {
    if (closed) return;
    closed = true;
    document.removeEventListener("keydown", onKey, true);
    if (drawer) root.remove();
    onClose?.();
  }
  function close() {
    if (closeModal) closeModal(); else finish();
  }
  function onKey(e) {
    if (e.key === "Escape" && drawer && root.contains(document.activeElement) && !document.querySelector(".backdrop")) {
      e.preventDefault();
      e.stopPropagation();
      close();
    }
  }
  document.addEventListener("keydown", onKey, true);

  root.addEventListener("input", (e) => {
    if (!e.target.matches(".dash-search")) return;
    st.query = e.target.value;
    draw();
  });
  root.addEventListener("click", (e) => {
    const chip = e.target.closest(".dash-chip");
    if (chip) {
      st.category = chip.dataset.cat;
      root.querySelectorAll(".dash-chip").forEach((c) => c.setAttribute("aria-pressed", String(c === chip)));
      draw();
      return;
    }
    if (e.target.closest('[data-g="close"]')) return close();
    const add = e.target.closest('[data-act="g-add"]');
    if (!add || add.disabled) return;
    const entry = shown[+add.dataset.i];
    if (!entry) return;
    if (!drawer) close(); // the modal goes; the drawer stays open for the next one
    if (entry.kind === "type") onConfigure(entry); else onAdd(entry);
  });
  root.addEventListener("pointerdown", (e) => {
    const grip = e.target.closest("[data-grip]");
    if (!grip || st.full) return;
    const entry = shown[+grip.dataset.grip];
    if (entry && !entry.invalid) onDrag(e, entry);
  });

  draw();
  if (drawer) setTimeout(() => root.querySelector(".dash-search")?.focus(), 20);
  return {
    close,
    setFull(next) {
      if (st.full === next) return;
      st.full = next;
      draw();
    },
    get open() { return !closed; },
  };
}
