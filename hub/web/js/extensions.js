// Extensions shared by the shell, the Extensions page, the extension apps, Approvals and the data flows: the cache of
// enabled extension domains (apps in the sidebar, Portals and Ctrl K), field formatting and the pieces of a pack.
import { get, post } from "./api.js";
import { badge, colorFor, dateTime, field, html, icon, modal, options, timeAgo, timeIn, toast } from "./ui.js";

export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export const ITEM_ICON = { domain: "box", connector: "plug", sso: "shield", controls: "checkCircle", team: "users" };
export const ITEM_LABEL = { domain: "data type", connector: "connector mapping", sso: "SSO recipe", controls: "compliance rules", team: "team template" };
export const DESIGNER_LABEL = { templates: "templates", claude: "written by Claude" };

/** The enabled extension domains as last loaded (GET /x); the shell keeps it current. */
export const xDomains = [];

export async function loadXDomains() {
  const list = await get("/x");
  xDomains.splice(0, xDomains.length, ...list);
  return xDomains;
}

export const xHref = (key, id) => `#/x/${encodeURIComponent(key)}${id ? `/${encodeURIComponent(id)}` : ""}`;
export const xColor = (key) => colorFor(`x:${key}`);
export const packHref = (id) => `#/extensions/packs/${encodeURIComponent(id)}`;

const when = (ts) => (ts > Date.now() / 1000 ? timeIn(ts) : timeAgo(ts));
const isHttp = (v) => /^https?:\/\//i.test(String(v));

export const sevBadge = (s) => html`<span class="sev ${SEVERITIES.includes(s) ? s : "info"}">${s}</span>`;

/** A record's value formatted by its field type; `full` for detail views (whole dates and links). */
export function fieldValue(f, value, { full = false } = {}) {
  if (value === null || value === undefined || value === "") return html`<span class="faint">-</span>`;
  switch (f?.type) {
    case "severity": return sevBadge(String(value));
    case "enum": return badge(String(value));
    case "date": return typeof value === "number"
      ? (full ? html`${dateTime(value)} <span class="faint">(${when(value)})</span>` : html`<span title="${dateTime(value)}">${when(value)}</span>`)
      : String(value);
    case "link": return isHttp(value) // data-act without a handler: a click opens the link, not the table row around it
      ? html`<a href="${value}" target="_blank" rel="noopener noreferrer" title="${value}" data-act="nav">${full ? value : html`${icon("external")}`}</a>` : String(value);
    default: return String(value);
  }
}

/** Datetime-local input value from POSIX seconds. */
function localInput(ts) {
  if (typeof ts !== "number") return "";
  const d = new Date(ts * 1000);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}

/** A form control for one field of a domain (names are "f_<field>"). */
export function fieldInput(f, value) {
  const name = `f_${f.name}`;
  const blank = f.required ? [] : [["", "-"]];
  switch (f.type) {
    case "number": return html`<input type="number" step="any" name="${name}" value="${value ?? ""}">`;
    case "date": return html`<input type="datetime-local" name="${name}" value="${localInput(value)}">`;
    case "severity": return html`<select name="${name}">${options([...blank, ...SEVERITIES], value || "")}</select>`;
    case "enum": return html`<select name="${name}">${options([...blank, ...f.values], value || "")}</select>`;
    case "link": return html`<input type="url" name="${name}" value="${value || ""}" placeholder="https://..." spellcheck="false">`;
    default: return String(value || "").length > 120 || f.description.length > 120
      ? html`<textarea name="${name}" rows="3">${value || ""}</textarea>` : html`<input name="${name}" value="${value || ""}" maxlength="4000">`;
  }
}

/** The fields of a record form, typed: numbers as numbers, dates as ISO text, blanks as null. */
export function readFields(domain, data) {
  const out = {};
  for (const f of domain.fields) {
    const v = String(data.get(`f_${f.name}`) ?? "").trim();
    if (!v) out[f.name] = null;
    else if (f.type === "number") out[f.name] = Number.isFinite(Number(v)) ? Number(v) : v;
    else if (f.type === "date") out[f.name] = Number.isNaN(new Date(v).getTime()) ? v : new Date(v).toISOString();
    else out[f.name] = v;
  }
  return out;
}

// ---------- pack pieces ----------

/** Chips for what a pack adds (its summary). */
export function summaryChips(s) {
  const chip = (kind, text, title = "") => html`<span class="item-chip" title="${title}">${icon(ITEM_ICON[kind])}${text}</span>`;
  return html`<div class="item-chips">
    ${(s.domains || []).map((k) => chip("domain", k, "Data type (extension app)"))}
    ${(s.connectors || []).map((t) => chip("connector", t, "Connector mapping for this tool"))}
    ${(s.sso || []).map((n) => chip("sso", n, "Single sign-on recipe"))}
    ${(s.controls || []).map((c) => chip("controls", c, "Compliance evidence for this control"))}
    ${(s.teams || []).map((t) => chip("team", t, "Agent-team template"))}
    ${Object.keys(s.kinds || {}).length ? "" : html`<span class="faint">nothing</span>`}</div>`;
}

const kv = (rows) => html`<dl class="kv">${rows.filter(([, v]) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && !v.length))
  .map(([k, v]) => html`<dt>${k}</dt><dd>${Array.isArray(v) ? v.join(", ") : v}</dd>`)}</dl>`;

const opText = { eq: "=", ne: "!=", in: "in", not_in: "not in", gte: ">=", lte: "<=", empty: "is empty", not_empty: "is not empty" };
const condition = (c) => `${c.field} ${opText[c.op] || c.op}${c.op === "empty" || c.op === "not_empty" ? "" : ` ${Array.isArray(c.value) ? c.value.join(", ") : c.value}`}`;

function domainItem(d, active) {
  return html`<div class="row" style="gap:6px;margin-bottom:6px">${badge(`x:${d.key}`, "accent")}${d.singular ? html`<span class="faint">one record: ${d.singular}</span>` : ""}
      ${active ? html`<a href="${xHref(d.key)}" style="font-size:12.5px">Open the app &rarr;</a>` : ""}</div>
    ${d.description ? html`<p class="muted" style="margin-bottom:8px;white-space:pre-line">${d.description}</p>` : ""}
    <div class="table-wrap"><table class="table compact"><thead><tr><th>Field</th><th>Label</th><th>Type</th><th></th></tr></thead><tbody>
      ${d.fields.map((f) => html`<tr><td class="mono">${f.name}</td><td>${f.label}${f.description ? html`<div class="faint" style="font-size:11.5px">${f.description}</div>` : ""}</td>
        <td>${f.type}${f.values?.length ? html` <span class="faint">(${f.values.join(", ")})</span>` : ""}</td>
        <td class="faint" style="font-size:11.5px">${[f.name === d.title_field ? "title" : "", f.required ? "required" : ""].filter(Boolean).join(", ")}</td></tr>`)}</tbody></table></div>
    ${d.links?.length ? html`<p class="faint" style="font-size:12px;margin-top:6px">Links: ${d.links.map((l) => `${l.target === "asset" ? "an asset by the address or hostname" : "a person by the email or login"} in "${l.field}"`).join("; ")}.</p>` : ""}`;
}

function connectorItem(c, pack) {
  return html`${kv([["Tool", c.tool || html`${pack?.source_tool || "-"} <span class="faint">(the pack's tool)</span>`],
      ["Base URL", c.base_url ? html`<span class="mono">${c.base_url}</span>` : html`<span class="faint">the tool's API address</span>`],
      ["Auth", c.auth === "header" ? `header ${c.auth_header}` : c.auth], ["TLS", c.verify_tls ? "verified" : html`<span class="warn-text">not verified</span>`],
      ["Maps", Object.keys(c.mapping || {}).map((k) => `${k}${c.mapping[k]?.list?.path ? ` (GET ${c.mapping[k].list.path})` : ""}`)]])}
    ${c.note ? html`<p class="faint" style="font-size:12px;margin-top:6px;white-space:pre-line">${c.note}</p>` : ""}
    <details style="margin-top:6px"><summary class="faint" style="cursor:pointer;font-size:12px">Mapping</summary>${jsonView(c.mapping, "200px")}</details>
    <p class="faint" style="font-size:12px;margin-top:6px">Enabling merges this mapping into the tool's Generic REST connection; the API token is entered there, never in a pack.</p>`;
}

function ssoItem(s) {
  return html`${kv([["Matches", s.match], ["Protocol", s.protocol.toUpperCase()], ["Callback", html`<span class="mono">${s.redirect_path}</span>`],
      ["ACS", s.acs_path ? html`<span class="mono">${s.acs_path}</span>` : ""], ["Logout", s.slo_path ? html`<span class="mono">${s.slo_path}</span>` : ""],
      ["Writes", html`<span class="mono">${s.file}</span>`], ["Client", s.public_client ? "public (no secret)" : "confidential"]])}
    ${s.steps?.length ? html`<ol class="muted" style="font-size:12.5px;margin:6px 0 0;padding-left:18px">${s.steps.map((x) => html`<li>${x}</li>`)}</ol>` : ""}
    <details style="margin-top:6px"><summary class="faint" style="cursor:pointer;font-size:12px">Configuration template</summary>
      <pre class="code wrap" style="margin-top:6px;max-height:200px">${s.template}</pre></details>`;
}

function controlsItem(c) {
  return html`<div class="table-wrap"><table class="table compact"><thead><tr><th>Control</th><th>Rule</th><th>Counts records where</th><th>Status</th></tr></thead><tbody>
    ${c.rules.map((r) => html`<tr><td><a href="#/compliance/controls">${r.control}</a></td><td>${r.title}<div class="faint" style="font-size:11.5px">domain ${r.domain}</div></td>
      <td class="mono" style="font-size:11.5px">${r.where.map(condition).join(" and ") || "every record"}${r.older_than_days != null ? html`<div>${r.age_field || "stored"} older than ${r.older_than_days} days</div>` : ""}</td>
      <td style="font-size:12px;white-space:nowrap">${r.fail_above != null ? html`<div>fail above ${r.fail_above}</div>` : ""}${r.partial_above != null ? html`<div>partial above ${r.partial_above}</div>` : ""}</td></tr>`)}</tbody></table></div>`;
}

function teamItem(t) {
  const m = t.match || {};
  return html`${kv([["Category", html`<span class="mono">${t.category}</span>`], ["For tools named", m.names], ["With capabilities", m.capabilities], ["With connectors", m.connector_kinds]])}
    <div class="stack" style="gap:6px;margin-top:8px">${t.roles.map((r) => html`<div class="member"><div class="row" style="gap:6px"><b>${r.title}</b><span class="faint mono" style="font-size:11.5px">${r.role}</span>
        ${r.permissions.map((p) => badge(p, p === "read" ? "" : "warn"))}${r.schedule_minutes ? badge(`every ${r.schedule_minutes} min`, "info") : ""}${r.rules_ok ? badge("works without a model") : ""}</div>
      ${r.description ? html`<div class="desc">${r.description}</div>` : ""}</div>`)}</div>`;
}

const itemTitle = (item) => ({ domain: item.title, connector: `Connector for ${item.tool || "the pack's tool"}`, sso: item.name,
  controls: `${item.rules?.length || 0} compliance rule${item.rules?.length === 1 ? "" : "s"}`, team: item.title }[item.kind] || item.kind);

/** Every item of a pack, readable. `activeDomains`: keys that are apps right now. */
export function packItems(items, { pack = null, activeDomains = new Set() } = {}) {
  return html`${items.map((item) => html`<div class="pack-item">
    <h4>${icon(item.kind === "domain" ? item.icon : ITEM_ICON[item.kind])}${itemTitle(item)}<span class="badge">${ITEM_LABEL[item.kind] || item.kind}</span></h4>
    ${item.kind === "domain" ? domainItem(item, activeDomains.has(item.key)) : item.kind === "connector" ? connectorItem(item, pack)
      : item.kind === "sso" ? ssoItem(item) : item.kind === "controls" ? controlsItem(item) : item.kind === "team" ? teamItem(item) : jsonView(item)}</div>`)}`;
}

/** Pretty JSON in a code block (escaped). */
export function jsonView(value, maxHeight = "420px") {
  return html`<pre class="code" style="margin-top:6px;max-height:${maxHeight}">${JSON.stringify(value, null, 2)}</pre>`;
}

/** Offer `value` as a JSON file download. */
export function downloadJson(value, name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Ask the Patch Agent to close a tool's hub-side gaps with an extension pack. `claude`: whether Claude is available. */
export function openExtend(tool, { claude = true, done } = {}) {
  modal({
    title: `Extend Atrium for ${tool.name}`,
    minRole: "admin",
    submit: "Ask the Patch Agent",
    body: html`<p class="muted" style="margin-bottom:12px">The Patch Agent looks for what Atrium itself lacks for ${tool.name} - a place for its data,
        a connector, an SSO recipe - and writes an extension pack (data only, nothing is executed). It waits in Approvals unless the guardrail
        "Generated extensions need approval" is off. When only a change to Atrium's code can close a gap, a self-patch is requested too (with Claude).</p>
      ${field("Written by", html`<select name="designer">${options([["auto", claude ? "Claude, with the templates as fallback" : "Automatic (templates; Claude is not connected)"],
        ["templates", "Templates only (SIEM alerts, service desk tickets, monitoring incidents)"],
        ...(claude ? [["claude", "Claude only"]] : [])], "auto")}</select>`)}`,
    async onSubmit(data) {
      toast(`The Patch Agent is looking at ${tool.name}...`, "info");
      const r = await post(`/tools/${encodeURIComponent(tool.id)}/extend`, { designer: data.get("designer") });
      const extra = r.self_patch === "requested" ? " A change to Atrium's code was requested as well." : "";
      if (r.enabled) toast(`Extension ${r.extension_id} enabled.${extra}`, "ok");
      else if (r.proposed) toast(`Extension ${r.extension_id} proposed - see Approvals.${extra}`, "ok");
      else toast(`${r.detail || "Nothing to do"}${extra}`, r.approval_id ? "info" : "warn");
      done?.(r);
    },
  });
}

/** Render a self-patch's test result. */
export function testsView(t, requiresTests) {
  if (!t) return html`<div class="notice">${icon("activity")}<div class="muted">The tests have not run yet.</div></div>`;
  const tone = t.ok ? "ok" : "bad";
  return html`<div class="notice ${tone}">${icon(t.ok ? "checkCircle" : "alert")}<div style="min-width:0;flex:1">
      <b>${t.ok ? "Tests passed" : t.timed_out ? "Tests timed out" : `Tests failed (exit code ${t.exit_code})`}</b>
      <span class="muted">in the worktree${t.duration != null ? `, ${t.duration}s` : ""}${t.command ? html` - <code>${t.command}</code>` : ""}</span>
      ${!t.ok && requiresTests ? html`<div style="font-size:12.5px;margin-top:4px">It cannot be approved while the guardrail "Self-patches must pass the tests" is on - reject it.</div>` : ""}
      ${t.tail ? html`<details style="margin-top:6px"><summary class="faint" style="cursor:pointer;font-size:12px">Test output (last lines, secrets masked)</summary>
        <pre class="code wrap" style="margin-top:6px;max-height:260px">${t.tail}</pre></details>` : ""}</div></div>`;
}

/** How an approved self-patch is applied. */
export function modeView(mode, reason, base) {
  return html`<div class="row" style="gap:6px">${mode === "pull_request" ? badge("pull request", "info") : badge("local merge", "warn")}
    <span class="faint" style="font-size:12.5px">${mode === "pull_request"
      ? "On approval the branch is pushed to origin and opened as a pull request (GitHub CLI). Nothing is merged here."
      : html`On approval the branch is merged into <b>${base || "the current branch"}</b> of this checkout (only with a clean working tree); Atrium must then be restarted.`}
      ${reason ? html` <span title="Why">(${reason})</span>` : ""}</span></div>`;
}

export const safeUrl = (u) => (isHttp(u) ? u : null);
