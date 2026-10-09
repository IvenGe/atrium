// Small UI toolkit: safe HTML templating, icons, modals, toasts and formatting.

export class Raw {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}
export const raw = (s) => new Raw(String(s));

export function esc(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function fmt(v) {
  if (v instanceof Raw) return v.s;
  if (Array.isArray(v)) return v.map(fmt).join("");
  if (v === null || v === undefined || v === false) return "";
  return esc(v);
}

/** Tagged template: interpolations are escaped unless wrapped in raw() or produced by html``. */
export function html(strings, ...values) {
  let out = strings[0];
  values.forEach((v, i) => { out += fmt(v) + strings[i + 1]; });
  return new Raw(out);
}

export function setHTML(el, content) {
  el.innerHTML = fmt(content);
  return el;
}

const ICONS = {
  home: '<path d="M3 11 12 4l9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-5h4v5"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
  bell: '<path d="M18 16v-5a6 6 0 1 0-12 0v5l-2 2h16z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  rocket: '<path d="M14 4.5c3-1.5 6.5-1.5 6.5-1.5s0 3.5-1.5 6.5l-6 6-5-5z"/><path d="M9 10.5 5.5 10 3 12.5l4.5 1M13.5 15l.5 3.5-2.5 2.5-1-4.5"/><circle cx="15.5" cy="8.5" r="1.3"/><path d="M6 16.5c-1.5 1-2 3.5-2 3.5s2.5-.5 3.5-2"/>',
  box: '<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
  shield: '<path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6z"/><path d="m9 12 2 2 4-4"/>',
  plug: '<path d="M9 2v5M15 2v5"/><path d="M6 7h12v4a6 6 0 0 1-12 0z"/><path d="M12 17v5"/>',
  bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 4.5V8M9 14h.01M15 14h.01M9.5 17h5"/><circle cx="12" cy="3.5" r="1"/>',
  terminal: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3M13 15h4"/>',
  check: '<path d="m5 12.5 4.5 4.5L19 7.5"/>',
  checkCircle: '<circle cx="12" cy="12" r="9"/><path d="m8 12 3 3 5-6"/>',
  sliders: '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/><circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="18" r="2"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  play: '<path d="M7 4.5v15l12.5-7.5z"/>',
  stop: '<rect x="6" y="6" width="12" height="12" rx="2"/>',
  pause: '<path d="M8 5v14M16 5v14"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  external: '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v6H4V6h6"/>',
  send: '<path d="M4 12 20 4l-6 16-3-7z"/><path d="m11 13 9-9"/>',
  branch: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="7" r="2"/><path d="M6 7v10M18 9c0 5-6 4-11 8"/>',
  folder: '<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2h8.5A1.5 1.5 0 0 1 21 8.5v9a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17.5z"/>',
  cloud: '<path d="M7 18.5a4.5 4.5 0 0 1-.6-9A6 6 0 0 1 18 9a4.75 4.75 0 0 1 0 9.5z"/>',
  server: '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  alert: '<path d="M12 3.5 2.5 20h19z"/><path d="M12 10v4M12 17h.01"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  wrench: '<path d="M14.5 5.5a4 4 0 0 0-5 5L4 16l4 4 5.5-5.5a4 4 0 0 0 5-5l-2.5 2.5-2.5-.5-.5-2.5z"/>',
  chat: '<path d="M4 5h16v11H9l-5 4z"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  file: '<path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4M9 12h6M9 16h6"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  edit: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',
  minus: '<path d="M5 12h14"/>',
  user: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
  users: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0"/><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6"/>',
  key: '<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M16 7l3 3M14 9l2 2"/>',
  lock: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/>',
  copy: '<rect x="8" y="8" width="13" height="13" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/>',
  monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  bug: '<rect x="8" y="7" width="8" height="13" rx="4"/><path d="M10 7a2 2 0 0 1 4 0M12 11v9M8 13H4M20 13h-4M8 17.5l-3 1.5M16 17.5l3 1.5M8.5 9.5 5 7.5M15.5 9.5l3.5-2"/>',
  radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="m12 12 6.5-6.5"/><circle cx="12" cy="12" r="1"/>',
  flow: '<path d="M4 8h14M14 4l4 4-4 4M20 16H6M10 12l-4 4 4 4"/>',
  contact: '<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M5.5 16.5a3.5 3.5 0 0 1 7 0M15 10h3M15 13.5h3"/>',
  puzzle: '<path d="M10 4.5a2 2 0 1 1 4 0V6h4a1 1 0 0 1 1 1v4h-1.5a2 2 0 1 0 0 4H19v4a1 1 0 0 1-1 1h-4v-1.5a2 2 0 1 0-4 0V20H6a1 1 0 0 1-1-1v-4h1.5a2 2 0 1 0 0-4H5V7a1 1 0 0 1 1-1h4z"/>',
  ticket: '<path d="M4 6h16v3.5a2.5 2.5 0 0 0 0 5V18H4v-3.5a2.5 2.5 0 0 0 0-5z"/><path d="M14 6v2.5M14 11v2M14 15.5V18"/>',
  upload: '<path d="M12 15V4M7 9l5-5 5 5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
  download: '<path d="M12 4v11M7 10l5 5 5-5"/><path d="M4 15v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4"/>',
  undo: '<path d="M4 9h10a6 6 0 0 1 0 12H8"/><path d="m8 5-4 4 4 4"/>',
  merge: '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="12" r="2"/><path d="M6 7v10M6 7c0 4 6 5 10 5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/>',
  database: '<ellipse cx="12" cy="5.5" rx="8" ry="2.5"/><path d="M4 5.5v13c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-13M4 12c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5"/>',
  tag: '<path d="M3 12V4h8l10 10-8 8z"/><circle cx="7.5" cy="8.5" r="1.3"/>',
  flag: '<path d="M5 21V4M5 4h11l-2 4 2 4H5"/>',
};

export function icon(name, extra = "") {
  return raw(`<svg class="i ${extra}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.grid}</svg>`);
}

/** An icon placed inside an <svg> drawing, at (x, y) with an explicit size. */
export function glyph(name, x, y, size = 18) {
  return raw(`<svg class="glyph" x="${+x}" y="${+y}" width="${+size}" height="${+size}" viewBox="0 0 24 24" aria-hidden="true">${ICONS[name] || ICONS.grid}</svg>`);
}

// ---------- formatting ----------

export function timeAgo(ts) {
  if (!ts) return "";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** "in 5m" / "in 2h" for a time ahead; "due now" once it has passed. */
export function timeIn(ts) {
  if (!ts) return "";
  const s = ts - Date.now() / 1000;
  if (s < 45) return "due now";
  if (s < 3600) return `in ${Math.round(s / 60)}m`;
  if (s < 86400) return `in ${Math.round(s / 3600)}h`;
  return `in ${Math.round(s / 86400)}d`;
}

/** Local date and time of a unix timestamp, for tooltips and detail views. */
export function dateTime(ts) {
  return ts ? new Date(ts * 1000).toLocaleString() : "";
}

export function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ---------- roles & small helpers ----------

const RANK = { viewer: 1, operator: 2, admin: 3 };

/** True when the signed-in role (body[data-role]) is at least `min`; no `min` means everyone. */
export function can(min) {
  return !min || (RANK[document.body.dataset.role] || 0) >= (RANK[min] || Infinity);
}

export function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem("hub.theme", next); } catch {}
  return next;
}

/** Copy text; falls back to selecting `input` where the async clipboard API is unavailable (plain http). */
export async function copyText(text, input) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    input?.focus();
    input?.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch {}
    if (!ok) return toast("Press Ctrl+C to copy the selected text", "warn");
  }
  toast("Copied to the clipboard", "ok");
}

const PALETTE = ["#7c3aed", "#4f46e5", "#0ea5e9", "#0d9488", "#16a34a", "#ca8a04", "#ea580c", "#db2777", "#9333ea", "#2563eb"];
export function colorFor(text) {
  let h = 0;
  for (const c of String(text)) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

export function appIcon(tool, size = "") {
  const name = tool.name || tool.id || "?";
  const color = tool.manifest?.ui?.color || colorFor(tool.id || name);
  const glyph = tool.manifest?.ui?.icon || name.trim()[0]?.toUpperCase() || "?";
  const live = tool.running ? html`<i class="live" style="background:var(--ok)"></i>` : "";
  return html`<div class="app-icon ${size}" style="background:${color}">${glyph}${live}</div>`;
}

export function builtinIcon(name, color, size = "") {
  return html`<div class="app-icon ${size}" style="background:${color}">${icon(name)}</div>`;
}

const TONES = {
  pass: "ok", ok: "ok", ready: "ok", done: "ok", approved: "ok", applied: "ok", native: "ok", good: "ok", active: "ok", closed: "",
  warn: "warn", partial: "warn", pending: "warn", needs_patch: "warn", patchable: "warn", adapter: "info", proposed: "warn",
  analyzing: "info", importing: "info", maintenance: "warn", in_treatment: "info", draft: "warn", open: "bad",
  fail: "bad", error: "bad", failed: "bad", rejected: "bad", incompatible: "bad", denied: "bad", retired: "",
  low: "", medium: "info", high: "warn", critical: "bad", manual: "", na: "",
  enabled: "ok", disabled: "", fixed: "ok", in_progress: "info", accepted: "", false_positive: "", info: "",
  running: "info", awaiting_approval: "warn", failing: "bad", available: "info", needs_decision: "warn",
  needs_claude: "", unavailable: "", not_needed: "", withdrawn: "",
  suspended: "warn", terminated: "bad",
  merged: "ok", pull_request: "info", testing: "info", stale: "warn",
};
export function badge(text, tone) {
  const t = tone ?? TONES[text] ?? "";
  return html`<span class="badge ${t}">${String(text).replace(/_/g, " ")}</span>`;
}

export function scoreTone(score) {
  if (score === null || score === undefined) return "var(--faint)";
  return score >= 75 ? "var(--ok)" : score >= 45 ? "var(--warn)" : "var(--bad)";
}

export function ring(score, size = 46) {
  const r = (size - 6) / 2;
  const c = 2 * Math.PI * r;
  const pct = score == null ? 0 : Math.max(0, Math.min(100, score));
  return html`<div class="ring" style="width:${size}px;height:${size}px" title="Integration score">
    <svg width="${size}" height="${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="var(--border-strong)" stroke-width="5" fill="none"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="${scoreTone(score)}" stroke-width="5" fill="none" stroke-linecap="round"
      stroke-dasharray="${(c * pct) / 100} ${c}"/></svg><b>${score ?? "-"}</b></div>`;
}

/** Very small markdown renderer for chat replies and policies (input is escaped first). */
export function md(text) {
  const blocks = String(text || "").split(/```/);
  return raw(blocks.map((part, i) => {
    if (i % 2) return `<pre>${esc(part.replace(/^\w*\n/, ""))}</pre>`;
    const lines = esc(part).split("\n");
    let out = "", list = null;
    for (const line of lines) {
      const item = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)$/);
      if (item) {
        const tag = /^\s*\d+\./.test(line) ? "ol" : "ul";
        if (list !== tag) { if (list) out += `</${list}>`; out += `<${tag}>`; list = tag; }
        out += `<li>${inline(item[1])}</li>`;
        continue;
      }
      if (list) { out += `</${list}>`; list = null; }
      const head = line.match(/^(#{1,3})\s+(.*)$/);
      if (head) out += `<h${head[1].length + 1}>${inline(head[2])}</h${head[1].length + 1}>`;
      else if (line.trim()) out += `<p>${inline(line)}</p>`;
    }
    if (list) out += `</${list}>`;
    return out;
  }).join(""));
}
function inline(s) {
  return s.replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>");
}

export function diffView(diff) {
  if (!diff) return html`<p class="muted">No file changes - this patch only updates the hub's view of the tool.</p>`;
  const lines = diff.split("\n").map((l) => {
    const cls = l.startsWith("+++") || l.startsWith("---") ? "file" : l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
    return `<span class="${cls}">${esc(l)}</span>`;
  });
  return raw(`<pre class="code diff">${lines.join("\n")}</pre>`);
}

// ---------- toasts ----------

export function toast(message, tone = "info") {
  let box = document.querySelector(".toasts");
  if (!box) { box = document.createElement("div"); box.className = "toasts"; document.body.append(box); }
  const el = document.createElement("div");
  el.className = `toast ${tone}`;
  el.setAttribute("role", "status");
  el.textContent = message;
  box.append(el);
  setTimeout(() => el.remove(), 4200);
}

// ---------- modals ----------

/**
 * Opens a modal. `body` is html``; returns {el, close}. onSubmit receives FormData when the form is submitted.
 * `minRole`: below that role the body is read-only and the submit button hidden. `sticky`: only the buttons close it.
 */
export function modal({ title, body, submit = "Save", cancel = "Cancel", wide = false, onSubmit, footer, minRole, sticky = false }) {
  const readOnly = !can(minRole);
  const backdrop = document.createElement("div");
  backdrop.className = "backdrop";
  const foot = footer ?? html`${cancel ? html`<button type="button" class="btn" data-close>${readOnly && cancel === "Cancel" ? "Close" : cancel}</button>` : ""}
      ${submit ? html`<button type="submit" class="btn primary" ${minRole ? html`data-min-role="${minRole}"` : ""}>${submit}</button>` : ""}`;
  setHTML(backdrop, html`<form class="modal ${wide ? "wide" : ""}" role="dialog" aria-modal="true" novalidate>
    <header><h2>${title}</h2><button type="button" class="icon-btn" data-close aria-label="Close">${icon("x")}</button></header>
    <div class="body">${readOnly ? html`<fieldset class="plain" disabled>${body}</fieldset>` : body}</div>
    <footer>${foot}</footer></form>`);
  const form = backdrop.querySelector("form");
  const close = () => { backdrop.remove(); document.removeEventListener("keydown", onKey); };
  const onKey = (e) => { if (e.key === "Escape" && !sticky) close(); };
  document.addEventListener("keydown", onKey);
  backdrop.addEventListener("mousedown", (e) => { if (e.target === backdrop && !sticky) close(); });
  backdrop.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", close));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!onSubmit || readOnly) return close();
    const btn = form.querySelector('button[type="submit"]');
    if (btn) btn.disabled = true;
    try {
      const keep = await onSubmit(new FormData(form), form);
      if (keep !== true) close();
    } catch (err) {
      if (err.status !== 401) toast(err.message, "bad"); // a 401 already sent the person to the login screen
    } finally {
      if (btn) btn.disabled = false;
    }
  });
  document.body.append(backdrop);
  setTimeout(() => form.querySelector("input:not([type=hidden]):not([hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled)")?.focus(), 30);
  return { el: form, close };
}

export function confirmDialog(title, text, action = "Confirm") {
  return new Promise((resolve) => {
    const m = modal({
      title, body: html`<p>${text}</p>`, submit: action,
      onSubmit: () => resolve(true),
    });
    m.el.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => resolve(false)));
  });
}

export function field(label, control, hint) {
  return html`<div class="field"><label>${label}</label>${control}${hint ? html`<span class="hint">${hint}</span>` : ""}</div>`;
}

export function options(values, selected) {
  return values.map((v) => {
    const [value, label] = Array.isArray(v) ? v : [v, v];
    return html`<option value="${value}" ${value === selected ? raw("selected") : ""}>${label}</option>`;
  });
}

export function emptyState(iconName, title, text, action = "") {
  return html`<div class="empty">${icon(iconName)}<h3>${title}</h3><p>${text}</p>${action ? html`<div style="margin-top:14px">${action}</div>` : ""}</div>`;
}

/** Delegate clicks on [data-act] buttons inside `root` to handlers. */
export function actions(root, handlers) {
  root.addEventListener("click", (e) => {
    const target = e.target.closest("[data-act]");
    if (!target || !root.contains(target)) return;
    const fn = handlers[target.dataset.act];
    if (fn) { e.preventDefault(); fn(target.dataset, target, e); }
  });
}
