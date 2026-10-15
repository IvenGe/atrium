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

// Read-only outside this file (the canvas builds <symbol> definitions from it).
export const ICONS = {
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
  network: '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="3" y="16" width="6" height="5" rx="1"/><rect x="15" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M6 16v-4h12v4"/>',
  firewall: '<rect x="3" y="5" width="18" height="14" rx="1.5"/><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 5v4.7M6 9.7v4.6M12 9.7v4.6M18 9.7v4.6M9 14.3V19M15 14.3V19"/>',
  router: '<rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 16.5h.01M11 16.5h.01M15 16.5h3M12 13V9.5"/><path d="M8.8 7.3a4.5 4.5 0 0 1 6.4 0M6.3 4.8a8 8 0 0 1 11.4 0"/>',
  switch: '<rect x="2.5" y="7" width="19" height="10" rx="1.5"/><path d="M6 11h1.5M9.5 11H11M13 11h1.5M16.5 11H18M6 14h12"/>',
  expand: '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
  keyboard: '<rect x="2.5" y="6" width="19" height="12" rx="2"/><path d="M6 10h.01M10 10h.01M14 10h.01M18 10h.01M8 14h8"/>',
  more: '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
  grip: '<circle cx="9" cy="6" r="1.2"/><circle cx="15" cy="6" r="1.2"/><circle cx="9" cy="12" r="1.2"/><circle cx="15" cy="12" r="1.2"/><circle cx="9" cy="18" r="1.2"/><circle cx="15" cy="18" r="1.2"/>',
  resize: '<path d="M20 11v9h-9M20 20 11 11M15 20l5-5"/>',
  table: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 10h18M3 15h18M9 10v10"/>',
  building: '<path d="M4 21V4.5a1 1 0 0 1 1-1h9a1 1 0 0 1 1 1V21"/><path d="M15 9h4a1 1 0 0 1 1 1v11M2.5 21h19M8 8h3M8 12h3M8 16h3"/>',
  messages: '<path d="M4 4h11a1 1 0 0 1 1 1v7a1 1 0 0 1-1 1H8l-4 3z"/><path d="M16 8h4a1 1 0 0 1 1 1v11l-3-3h-7a1 1 0 0 1-1-1v-3"/>',
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

// A manifest's ui.color goes into a style attribute: only a hex colour may, or "#000;position:fixed;inset:0" would add
// declarations (a layer over the whole page). The server drops anything else too (models.PortalUi).
export const HEX_COLOR = /^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const GRAPHEMES = typeof Intl !== "undefined" && Intl.Segmenter ? new Intl.Segmenter(undefined, { granularity: "grapheme" }) : null;

/** The first `n` characters a person sees (an emoji with joiners counts as one). */
export function graphemes(text, n) {
  const s = String(text ?? "");
  return (GRAPHEMES ? [...GRAPHEMES.segment(s)].map((g) => g.segment) : [...s]).slice(0, n).join("");
}

/** The colour and glyph of a tool's tile: its manifest's when they are a hex colour and one or two characters. */
export function tileLook(tool) {
  const name = String(tool.name || tool.id || "?");
  const ui = tool.manifest?.ui || {};
  const color = typeof ui.color === "string" && HEX_COLOR.test(ui.color) ? ui.color : colorFor(tool.id || name);
  const own = typeof ui.icon === "string" ? ui.icon.trim() : "";
  const glyph = own && !/\s/.test(own) ? graphemes(own, 2) : graphemes(name.trim(), 1).toUpperCase() || "?";
  return { color, glyph };
}

export function appIcon(tool, size = "") {
  const { color, glyph } = tileLook(tool);
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
  needs_model: "", needs_claude: "", unavailable: "", not_needed: "", withdrawn: "",
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
  const label = String(score ?? "-");
  // "100" in a small ring: a smaller font, so the number stays inside the circle (13px otherwise)
  const font = label.length > 2 ? Math.min(13, Math.round(size * 0.27)) : 13;
  return html`<div class="ring" style="width:${size}px;height:${size}px" title="Integration score">
    <svg width="${size}" height="${size}"><circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="var(--border-strong)" stroke-width="5" fill="none"/>
    <circle cx="${size / 2}" cy="${size / 2}" r="${r}" stroke="${scoreTone(score)}" stroke-width="5" fill="none" stroke-linecap="round"
      stroke-dasharray="${(c * pct) / 100} ${c}"/></svg><b style="font-size:${font}px">${label}</b></div>`;
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

export function toast(message, tone = "info", link = null) {
  let box = document.querySelector(".toasts");
  if (!box) { box = document.createElement("div"); box.className = "toasts"; document.body.append(box); }
  const el = document.createElement("div");
  el.className = `toast ${tone}`;
  el.setAttribute("role", "status");
  el.textContent = message;
  if (link?.href?.startsWith("#/")) { // an in-app link after the text ("Added to My dashboard. Open")
    const a = Object.assign(document.createElement("a"), { href: link.href, textContent: link.text || "Open" });
    el.append(" ", a);
  }
  box.append(el);
  setTimeout(() => el.remove(), 4200);
}

// ---------- modals ----------

// The element that opened each open modal (by backdrop): a dialog opened from inside another one falls back to it.
const OPENERS = new WeakMap();

/** A selector that finds an element again after its view re-rendered (live updates replace the DOM): id or data-*. */
function locator(el) {
  if (!el) return null;
  if (el.id) return `#${CSS.escape(el.id)}`;
  const attrs = ["act", "id", "key", "tab"].filter((k) => el.dataset?.[k] !== undefined)
    .map((k) => `[data-${k}="${CSS.escape(el.dataset[k])}"]`).join("");
  return attrs ? `${el.tagName.toLowerCase()}${attrs}` : null;
}

/** After a modal closed: focus the first opener still on the page (or its re-rendered twin), unless focus already moved
 *  somewhere else or another dialog is open that the opener is not part of (that dialog keeps the focus). */
function returnFocus(candidates) {
  const active = document.activeElement;
  if (active && active !== document.body && active.isConnected) return;
  const top = [...document.querySelectorAll(".backdrop")].at(-1);
  const target = candidates.map(([el, sel]) => (el?.isConnected ? el : sel ? document.querySelector(sel) : null))
    .find((c) => c && (!top || top.contains(c)));
  target?.focus({ preventScroll: true });
}

/** The element that has the focus now, as a candidate for returnFocus() (null when it is the page itself). */
export function focusOrigin() {
  const active = document.activeElement;
  const el = (active instanceof HTMLElement || active instanceof SVGElement) && active !== document.body ? active : null;
  return [el, locator(el)];
}
export const restoreFocus = (...candidates) => returnFocus(candidates);

// ---------- dialog layers ----------
// Every open dialog (a modal or the command palette) is a .backdrop on <body>. While one is open, everything else on
// <body> is inert - the top bar, the sidebar, the page and any dialog below the top one - so Tab, a click or a screen
// reader cannot reach what the dialog covers (review F33). Navigating to another page closes them (review F34).

const LAYERS = new Map(); // backdrop -> {close, sticky}
const INERT_MARK = "data-dialog-inert"; // set on what this module made inert, so only that is undone

/** Makes everything on <body> but the top-most dialog inert, or nothing when no dialog is open. */
export function syncInert() {
  const top = [...document.querySelectorAll("body > .backdrop")].at(-1) || null;
  for (const el of document.body.children) {
    const cover = Boolean(top) && el !== top && !el.classList.contains("toasts") && el.tagName !== "SCRIPT";
    if (cover && !el.inert) { el.inert = true; el.setAttribute(INERT_MARK, ""); }
    else if (!cover && el.hasAttribute(INERT_MARK)) { el.inert = false; el.removeAttribute(INERT_MARK); }
  }
}

/** Registers an open dialog's backdrop (already on <body>). `close` must remove it and call dropLayer(). */
export function addLayer(backdrop, close, { sticky = false } = {}) {
  LAYERS.set(backdrop, { close, sticky });
  syncInert();
}

export function dropLayer(backdrop) {
  LAYERS.delete(backdrop);
  syncInert();
}

/** Closes the open dialogs, top-most first: on navigation every one but those that only their buttons may close
 *  (a token shown once), on sign-out (`all`) every one. */
export function closeDialogs({ all = false } = {}) {
  for (const [backdrop, layer] of [...LAYERS].reverse()) {
    try {
      if (all || !layer.sticky) layer.close();
    } catch (err) {
      console.error(err); // a failing onClose must not stop the page change
      if (all) backdrop.remove();
    }
    if (!backdrop.isConnected) LAYERS.delete(backdrop);
  }
  if (all) document.querySelectorAll("body > .backdrop").forEach((b) => b.remove());
  syncInert();
}

/** Keeps Tab and Shift+Tab inside `box` (for browsers without `inert`, and so focus never rests outside it). */
function trapTab(e, box) {
  const items = [...box.querySelectorAll('a[href], button, input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter((el) => !el.matches(":disabled") && el.getClientRects().length && el.closest("[inert]") === null);
  if (!items.length) { e.preventDefault(); return; }
  const first = items[0], last = items.at(-1), active = document.activeElement;
  if (!box.contains(active)) { e.preventDefault(); (e.shiftKey ? last : first).focus(); }
  else if (e.shiftKey && active === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
}

/** Keydown handling every dialog shares: Tab stays inside the top-most one. */
export function dialogKeys(e, backdrop, box) {
  const top = [...document.querySelectorAll("body > .backdrop")].at(-1) === backdrop;
  if (top && e.key === "Tab") trapTab(e, box);
  return top;
}

/**
 * Opens a modal. `body` is html``; returns {el, close}. onSubmit receives FormData when the form is submitted.
 * `minRole`: below that role the body is read-only and the submit button hidden. `sticky`: only the buttons close it.
 * `drawer`: a panel along the right edge instead of a centred box (same keyboard and focus handling).
 * `onClose` runs exactly once however the modal closes (buttons, Esc, backdrop, submit); focus then returns to the
 * element that opened it.
 */
export function modal({ title, body, submit = "Save", cancel = "Cancel", wide = false, drawer = false, onSubmit, footer, minRole, sticky = false, onClose }) {
  const readOnly = !can(minRole);
  // HTML or SVG (a map item): anything focusable that is not the page itself
  const active = document.activeElement;
  const opener = (active instanceof HTMLElement || active instanceof SVGElement) && active !== document.body ? active : null;
  const outer = opener?.closest(".backdrop");
  const fallback = outer ? OPENERS.get(outer) : null;
  const backdrop = document.createElement("div");
  const mine = [opener, locator(opener)];
  if (opener) OPENERS.set(backdrop, mine);
  backdrop.className = drawer ? "backdrop side" : "backdrop";
  const foot = footer ?? html`${cancel ? html`<button type="button" class="btn" data-close>${readOnly && cancel === "Cancel" ? "Close" : cancel}</button>` : ""}
      ${submit ? html`<button type="submit" class="btn primary" ${minRole ? html`data-min-role="${minRole}"` : ""}>${submit}</button>` : ""}`;
  setHTML(backdrop, html`<form class="modal ${wide ? "wide" : ""} ${drawer ? "drawer" : ""}" role="dialog" aria-modal="true" novalidate>
    <header><h2>${title}</h2><button type="button" class="icon-btn" data-close aria-label="Close">${icon("x")}</button></header>
    <div class="body">${readOnly ? html`<fieldset class="plain" disabled>${body}</fieldset>` : body}</div>
    <footer>${foot}</footer></form>`);
  const form = backdrop.querySelector("form");
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    backdrop.remove();
    dropLayer(backdrop); // the page (or the dialog below) is usable again before focus returns to it
    document.removeEventListener("keydown", onKey);
    try {
      onClose?.();
    } finally {
      returnFocus([mine, fallback || [null, null]]);
    }
  };
  // Esc closes the top-most dialog only (a dialog opened from another one closes first); Tab stays inside it
  const onKey = (e) => { if (dialogKeys(e, backdrop, form) && e.key === "Escape" && !sticky) close(); };
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
  addLayer(backdrop, close, { sticky });
  // focus moves into the dialog: its first field, else its first footer button (Cancel before a destructive action)
  setTimeout(() => (form.querySelector("input:not([type=hidden]):not([hidden]):not(:disabled), select:not(:disabled), textarea:not(:disabled)")
    || form.querySelector("footer button:not(:disabled)") || form.querySelector("[data-close]"))?.focus(), 30);
  return { el: form, close };
}

export function confirmDialog(title, text, action = "Confirm") {
  return new Promise((resolve) => {
    modal({
      title, body: html`<p>${text}</p>`, submit: action,
      onSubmit: () => resolve(true),
      onClose: () => resolve(false), // Cancel, Esc or a click outside (after a submit the promise is settled already)
    });
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
