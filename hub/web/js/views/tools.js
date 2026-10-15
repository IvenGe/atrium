import { del, get, patch as patchJson, post } from "../api.js";
import { mountConnection } from "../connection.js";
import { openExtend } from "../extensions.js";
import { API_TYPES, EDITABLE_CHECKS, FIELDS, OVERRIDE_NOTE, editBody, formFrom, validate } from "../manifest-edit.js";
import { loadIdentity, openProviderPicker, runRegistration, statusBadge } from "../sso.js";
import { proposeToast, strategyCards, takeEditRequest, wireStrategies } from "../strategies.js";
import { statusInfo } from "../subsidiary-model.js";
import {
  actions, appIcon, badge, confirmDialog, diffView, emptyState, field, html, icon, modal, options, ring, setHTML, timeAgo, toast,
} from "../ui.js";
import { openGiveTeam } from "./subsidiaries.js";

const KIND_LABEL = { oss: "Source code", closed: "Closed source", saas: "SaaS" };
const SHAPE_LABEL = { release: "release folder", source: "source code", compose: "compose folder", saas: "SaaS service", other: "folder" };
const SOURCE_ICON = { github: "branch", local: "folder", saas: "cloud" };

// ---------- import dialog ----------
export function openImport(type = "github") {
  let current = type;
  const bodies = {
    github: html`${field("Repository", html`<input name="source" placeholder="https://github.com/owner/repo or owner/repo" required>`,
        "Public repositories, or private ones your git credentials can read.")}
      <div class="form-grid">${field("Name (optional)", html`<input name="name" placeholder="Derived from the repo">`)}
      ${field("Branch (optional)", html`<input name="branch" placeholder="default branch">`)}</div>`,
    local: html`${field("Folder on this machine", html`<input name="source" placeholder="C:\\Projects\\my-app or /home/me/my-app" required>`,
        "Source projects are analysed in place; patches go to a separate git branch. Folders with only binaries are treated as closed source.")}
      ${field("Name (optional)", html`<input name="name" placeholder="Derived from the folder">`)}`,
    saas: html`${field("Service URL", html`<input name="source" placeholder="https://app.example.com" required>`)}
      ${field("OpenAPI spec URL (optional)", html`<input name="openapi_url" placeholder="https://api.example.com/openapi.json">`,
        "With a spec the hub learns the API, auth methods and webhooks.")}
      ${field("Name (optional)", html`<input name="name" placeholder="Derived from the domain">`)}`,
  };
  const m = modal({
    title: "Import a tool",
    submit: "Import",
    minRole: "operator",
    body: html`<div class="seg" style="margin-bottom:16px">
        <button type="button" data-type="github">${icon("branch")}GitHub</button>
        <button type="button" data-type="local">${icon("folder")}Local project</button>
        <button type="button" data-type="saas">${icon("cloud")}SaaS</button></div>
      <div id="import-fields"></div>`,
    async onSubmit(data) {
      const body = { source_type: current, source: String(data.get("source") || "").trim() };
      for (const key of ["name", "branch", "openapi_url"]) if (data.get(key)) body[key] = String(data.get(key)).trim();
      if (!body.source) throw new Error("Please fill in the source");
      const tool = await post("/tools/import", body);
      toast(`Importing ${tool.name} - the Hub Supervisor is on it`, "ok");
      location.hash = `#/tools/${tool.id}`;
    },
  });
  const select = (t) => {
    current = t;
    m.el.querySelectorAll("[data-type]").forEach((b) => b.classList.toggle("active", b.dataset.type === t));
    setHTML(m.el.querySelector("#import-fields"), bodies[t]);
    m.el.querySelector("#import-fields input")?.focus();
  };
  m.el.querySelectorAll("[data-type]").forEach((b) => b.addEventListener("click", () => select(b.dataset.type)));
  select(type);
}

// ---------- list ----------
async function renderList(el, ctx) {
  const draw = async () => {
    const tools = await get("/tools");
    setHTML(el, html`
      <div class="page-head"><div><h1>Apps</h1><p class="muted">Every imported tool has its own supervisor agent and an integration score.</p></div>
        <button class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import tool</button></div>
      <section class="card flush">
      ${tools.length ? html`<div class="table-wrap"><table class="table"><thead><tr>
          <th>App</th><th>Type</th><th>Status</th><th>Integration</th><th>Health</th><th></th></tr></thead><tbody>
          ${tools.map((t) => html`<tr class="clickable" data-act="open" data-id="${t.id}">
            <td><div class="row" style="flex-wrap:nowrap">${appIcon(t, "sm")}<div><b>${t.name}</b><div class="faint mono" style="font-size:11.5px;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.source}</div></div></div></td>
            <td><span class="row" style="gap:6px">${icon(SOURCE_ICON[t.source_type])}${KIND_LABEL[t.manifest?.kind] || "-"}</span></td>
            <td>${badge(t.status)} ${t.running ? badge("running", "ok") : ""}</td>
            <td><div class="row" style="flex-wrap:nowrap">${ring(t.report?.score, 38)}${t.report ? badge(t.report.level) : ""}</div></td>
            <td>${t.health ? html`<span class="row" style="gap:6px"><span class="dot ${t.health.ok ? "ok" : t.health.ok === false ? "bad" : ""}"></span>${t.health.detail}</span>` : html`<span class="faint">-</span>`}</td>
            <td style="text-align:right">${t.manifest?.ui?.url ? html`<a class="btn sm" href="#/portal/${t.id}" data-stop>${icon("external")}Open</a>` : ""}</td>
          </tr>`)}</tbody></table></div>`
        : emptyState("grid", "No tools yet", "Import from GitHub, a local folder or a SaaS URL.",
          html`<button class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import tool</button>`)}
      </section>`);
    el.querySelectorAll("[data-stop]").forEach((a) => a.addEventListener("click", (e) => e.stopPropagation()));
  };
  actions(el, { import: () => openImport(), open: (d) => { location.hash = `#/tools/${d.id}`; } });
  await draw();
  ctx.live(["tool", "tool_removed"], draw);
}

// ---------- detail ----------
const CHECK_ICON = { pass: "check", warn: "minus", fail: "x" };

/** Single sign-on controls under the SSO check: connect to the selected provider, or pick another one. */
function ssoControls(tool, idp) {
  const row = idp?.providers.length ? idp.tools.find((t) => t.tool_id === tool.id) : null;
  if (!row) return ""; // no provider in the suite, or the tool is one
  const name = (pid) => idp.providers.find((p) => p.tool_id === pid)?.name || pid;
  const pick = row.status === "needs_choice" ? "Choose provider" : row.status === "not_connected" ? "Other provider" : "Change provider";
  return html`<div class="row" style="gap:6px;margin-top:8px">${statusBadge(row.status)}
    ${row.status === "connected" ? html`<span class="faint" style="font-size:12.5px">through ${name(row.connected_to)}</span>` : ""}
    ${row.pending ? html`<a style="font-size:12.5px" href="#/approvals">${row.pending.title}</a>` : ""}
    <span class="spacer"></span>
    <span class="row" style="gap:6px" data-min-role="operator">
      ${row.status === "not_connected" && row.selected ? html`<button class="btn sm primary" data-act="sso-connect" data-provider="${row.selected}">${icon("link")}Connect to ${name(row.selected)}</button>` : ""}
      <button class="btn sm" data-act="sso-pick">${icon("link")}${pick}</button></span></div>`;
}

function checksPanel(tool, idp) {
  if (!tool.report) return html`<p class="muted">Not analysed yet.</p>`;
  const editable = (c) => tool.manifest && EDITABLE_CHECKS.includes(c.id);
  return html`${tool.report.checks.map((c) => html`<div class="check-row">
      <div class="ico ${c.status}">${icon(CHECK_ICON[c.status])}</div>
      <div style="flex:1;min-width:0"><div class="row" style="gap:8px"><b>${c.title}</b>${c.fix ? html`<span class="badge accent">${icon("wrench")}${c.fix.replace(/_/g, " ")}</span>` : ""}
        ${editable(c) ? html`<span class="spacer"></span><button class="btn sm" data-act="edit-manifest" data-section="${c.id}" data-min-role="admin"
          title="Set it by hand: kept through every re-analysis">${icon("wrench")}Edit</button>` : ""}</div>
      <div class="muted" style="overflow-wrap:anywhere">${c.detail}</div>${c.id === "sso" ? ssoControls(tool, idp) : ""}</div></div>`)}`;
}

/** What an SSO patch connects to, and what a person still has to do. */
export function ssoPlan(sso) {
  if (!sso) return "";
  return html`<div class="sso-plan"><div class="row" style="gap:6px">${icon("shield")}<span>Signs in through <b>${sso.provider_name}</b>
      (${sso.protocol.toUpperCase()}) as client <code>${sso.client_id}</code></span></div>
    ${sso.redirect_uris.length ? html`<div class="faint" style="margin-top:4px;overflow-wrap:anywhere">Redirect: ${sso.redirect_uris.join(", ")}</div>` : ""}
    ${sso.steps.length ? html`<ol>${sso.steps.map((s) => html`<li>${s}</li>`)}</ol>` : ""}</div>`;
}

function manifestPanel(tool) {
  const m = tool.manifest;
  if (!m) return html`<p class="muted">Not analysed yet.</p>`;
  const list = (items) => (items?.length ? items.map((x) => html`<span class="badge">${x}</span> `) : html`<span class="faint">none</span>`);
  const source = m.native ? badge("native manifest", "ok") : m.known ? badge("built-in profile", "info") : badge("inferred", "warn");
  return html`<dl class="kv" style="margin-bottom:16px">
      <dt>Kind</dt><dd>${KIND_LABEL[m.kind]} ${source}</dd>
      ${m.known ? html`<dt>Recognised</dt><dd>${m.known.profile} (${SHAPE_LABEL[m.known.shape] || m.known.shape}${m.known.version ? `, version ${m.known.version}` : ""})</dd>` : ""}
      ${m.adopted ? html`<dt>Adopted manifest</dt><dd><span class="mono" style="overflow-wrap:anywhere">${m.adopted}</span> <span class="faint">(not merged yet)</span></dd>` : ""}
      ${tool.overridden?.length ? html`<dt>Set hub-side</dt><dd>${list(tool.overridden)} <span class="faint">(${OVERRIDE_NOTE}; kept through every analysis)</span></dd>` : ""}
      <dt>Version</dt><dd>${m.version || "unknown"}</dd><dt>License</dt><dd>${m.license || "unknown"}</dd>
      <dt>Stack</dt><dd>${list(m.stack)}</dd>
      <dt>Launch</dt><dd class="mono">${m.launch.setup ? html`${m.launch.setup} &amp;&amp; ` : ""}${m.launch.command || "-"}${m.launch.port ? html` <span class="faint">(port ${m.launch.port})</span>` : ""}</dd>
      ${m.launch.env_keys?.length ? html`<dt>Environment</dt><dd>${list(m.launch.env_keys)} <span class="faint">(names only: values are never shown)</span></dd>` : ""}
      <dt>Health</dt><dd class="mono">${m.health.url || "-"}</dd>
      <dt>API</dt><dd>${m.api.type}${m.api.endpoints ? ` - ${m.api.endpoints} operations` : ""}${m.api.base_url ? html` <span class="mono faint">${m.api.base_url}</span>` : ""}</dd>
      <dt>SSO</dt><dd>${m.auth.sso}${m.auth.notes ? html` <span class="faint">(${m.auth.notes})</span>` : ""}</dd>
      <dt>Provides</dt><dd>${list(m.provides)}</dd><dt>Consumes</dt><dd>${list(m.consumes)}</dd>
      <dt>Emits</dt><dd>${list(m.events.emits)}</dd><dt>Listens</dt><dd>${list(m.events.listens)}</dd>
    </dl>
    <details><summary class="muted" style="cursor:pointer">Raw manifest</summary><pre class="code" style="margin-top:8px">${JSON.stringify(m, null, 2)}</pre></details>`;
}

function patchesPanel(tool) {
  if (!tool.patches.length) return html`<p class="muted">No patches. The Patch Agent proposes them when the tool has integration gaps.</p>`;
  return html`${tool.patches.map((p) => html`<div class="check-row" style="display:block">
      <div class="row" style="justify-content:space-between"><div class="row" style="gap:8px">${icon("wrench")}<b>${p.title}</b>${badge(p.status)}<span class="badge">${p.target}</span></div>
        <span class="faint" style="font-size:12px">${timeAgo(p.created_at)}</span></div>
      <p class="muted" style="margin:6px 0;white-space:pre-line">${p.rationale}</p>
      ${p.approval_id ? html`<p style="font-size:12.5px"><a href="#/approvals">${p.status === "proposed" ? "Waiting for approval - review it on the Approvals page" : "Its approval"}</a></p>` : ""}
      ${ssoPlan(p.sso)}
      ${p.branch ? html`<p style="font-size:12.5px;overflow-wrap:anywhere">Branch <code>${p.branch}</code> in worktree <code>${p.location}</code></p>`
        : p.location ? html`<p style="font-size:12.5px;overflow-wrap:anywhere">Written to <code>${p.location}</code></p>` : ""}
      ${p.error ? html`<p style="color:var(--bad)">${p.error}</p>` : ""}
      <details><summary class="muted" style="cursor:pointer;font-size:12.5px">Show diff</summary><div style="margin-top:8px">${diffView(p.diff)}</div></details>
    </div>`)}`;
}

// ---------- manifest editor (administrators) ----------

const domId = (path) => `me-${path.replace(/[^A-Za-z0-9_-]/g, "-")}`;

/**
 * The administrators' manifest editor: how the hub starts the tool (not for SaaS), its health check, its API and its
 * portal address (PATCH /api/tools/{id}/manifest). What is set here is a hub-side setting every analysis keeps; a
 * field set by an administrator or an approved patch can be reset (back to what Atrium finds). Environment values are
 * write-only, never shown - only their names are; the ones marked secret (or named like a credential) are kept in the
 * hub's private launch secrets, the others are plain hub-side constants. `focus`: the section to start in
 * (launch | health | api).
 */
function openManifestEditor(tool, { focus, done } = {}) {
  const original = formFrom(tool);
  const f = original.fields;
  const saas = tool.manifest?.kind === "saas";
  const reset = new Set();
  const resetButton = (path, label) => html`<button type="button" class="btn sm" data-reset="${path}" aria-label="Reset ${label}">Reset</button>`;
  const note = (path, label) => (original.overridden.has(path)
    ? html`<span class="row hint" style="gap:6px" data-note="${path}"><span>${OVERRIDE_NOTE}</span>${resetButton(path, label)}</span>` : "");
  const error = (path) => html`<span class="hint warn-text" data-error="${path}" hidden></span>`;
  const row = (path, label, control, hint = "") => html`<div class="field" data-field="${path}"><label for="${domId(path)}">${label}</label>
    ${control}${hint ? html`<span class="hint">${hint}</span>` : ""}${note(path, label)}${error(path)}</div>`;
  const text = (path, placeholder, cls = "") => html`<input id="${domId(path)}" name="${path}" value="${f[path]}" placeholder="${placeholder}"
    class="${cls}" autocomplete="off" spellcheck="false">`;
  const envRows = original.env.map((e) => html`<div class="row" style="gap:8px;margin-bottom:6px" data-env="${e.key}">
      <code style="min-width:0;overflow-wrap:anywhere">${e.key}</code>${badge("set", "ok")}${e.secret ? badge("secret") : ""}
      <input type="password" name="env:${e.key}" placeholder="unchanged" autocomplete="new-password" aria-label="New value of ${e.key}" style="flex:1 1 160px;min-width:0">
      <label class="check"><input type="checkbox" name="secret:${e.key}" ${e.secret ? "checked" : ""}><span>Secret</span></label>
      ${e.overridden ? resetButton(`launch.env.${e.key}`, e.key) : ""}</div>${error(`launch.env.${e.key}`)}`);
  const launch = saas ? "" : html`<section data-section="launch"><h3 style="margin:0 0 8px">Launch</h3>
    ${row("launch.command", "Command", text("launch.command", "e.g. ./mvnw spring-boot:run", "mono"),
      "Runs on the hub machine, with Atrium's privileges, when someone starts the tool. One line.")}
    <div class="form-grid">
      ${row("launch.port", "Port", html`<input id="${domId("launch.port")}" name="launch.port" type="number" min="1" max="65535" inputmode="numeric" value="${f["launch.port"]}">`)}
      ${row("launch.cwd", "Working folder", text("launch.cwd", "."), "Inside the tool's folder.")}</div>
    <div class="field"><label>Environment</label>${envRows}
      <div class="row" style="gap:8px">
        <input name="env-new-key" class="mono" placeholder="NEW_VARIABLE" aria-label="New variable name" autocomplete="off" spellcheck="false" style="flex:1 1 140px;min-width:0">
        <input name="env-new-value" type="password" placeholder="value" aria-label="Its value" autocomplete="new-password" style="flex:1 1 140px;min-width:0">
        <label class="check"><input type="checkbox" name="env-new-secret"><span>Secret</span></label></div>
      <span class="hint">Values are write-only and never shown. A secret (and any variable named like PASSWORD, TOKEN or API_KEY) is kept in the hub's private launch secrets and masked in texts; other values are plain settings. Leave a value empty to keep it.</span>
      ${error("launch.env")}</div></section>`;
  const m = modal({
    title: `Settings of ${tool.name}`,
    submit: "Save",
    minRole: "admin",
    wide: true,
    body: html`<div data-error-box hidden><div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div data-error="*"></div></div></div>
      ${launch}
      <section data-section="health"><h3 style="margin:14px 0 8px">Health</h3>
        ${row("health.url", "Health URL", text("health.url", "http://localhost:8080/health or tcp://localhost:5432"))}</section>
      <section data-section="api"><h3 style="margin:14px 0 8px">API</h3>
        <div class="form-grid">
          ${row("api.type", "Type", html`<select id="${domId("api.type")}" name="api.type">${options(API_TYPES, f["api.type"])}</select>`)}
          ${row("api.base_url", "Base URL", text("api.base_url", "http://localhost:8080/api"))}</div>
        ${row("api.spec", "OpenAPI spec", text("api.spec", "https://.../openapi.json or a path in the tool's folder"))}</section>
      <section data-section="ui"><h3 style="margin:14px 0 8px">Portal</h3>
        ${row("ui.url", "Portal URL", text("ui.url", "http://localhost:8080"))}</section>
      <p class="faint" style="font-size:12.5px;margin-top:10px">Empty a field to go back to what Atrium finds. What you set is kept through every
        re-analysis and wins over the tool's own hub.manifest.</p>`,
    async onSubmit(data, form) {
      const values = { fields: {}, env: {}, secret: [], reset: [...reset] };
      for (const path of FIELDS) values.fields[path] = data.has(path) ? String(data.get(path) ?? "") : f[path];
      for (const e of original.env) {
        const v = data.get(`env:${e.key}`);
        if (v) values.env[e.key] = String(v);
        if (data.get(`secret:${e.key}`)) values.secret.push(e.key);
      }
      const newKey = String(data.get("env-new-key") || "").trim();
      const newValue = String(data.get("env-new-value") || "");
      const errors = validate({ ...values, env: newKey ? { ...values.env, [newKey]: newValue } : values.env }, original);
      if (newKey && !newValue) errors["launch.env"] = `Give a value for ${newKey}`;
      else if (!newKey && newValue) errors["launch.env"] = "Give the variable's name";
      else if (newKey) {
        values.env[newKey] = newValue;
        if (data.get("env-new-secret")) values.secret.push(newKey);
      }
      const shown = new Set();
      form.querySelectorAll("[data-error]").forEach((span) => {
        const message = errors[span.dataset.error];
        if (message) shown.add(span.dataset.error);
        span.textContent = message || "";
        span.hidden = !message;
      });
      const rest = Object.entries(errors).filter(([k]) => !shown.has(k)).map(([k, v]) => `${k.replace(/^launch\.env\./, "")}: ${v}`);
      const box = form.querySelector("[data-error-box]");
      box.hidden = !rest.length;
      box.querySelector("[data-error]").textContent = rest.join("; ");
      if (Object.keys(errors).length) {
        toast("Check the highlighted fields", "bad");
        return true;
      }
      const body = editBody(original, values);
      if (!Object.keys(body).length) {
        toast("Nothing changed", "info");
        return undefined;
      }
      const updated = await patchJson(`/tools/${encodeURIComponent(tool.id)}/manifest`, body);
      toast(reset.size || JSON.stringify(body).includes(":null")
        ? `Saved - ${tool.name} is analysed again for what you reset` : `Saved - ${tool.name}'s checks are scored again`, "ok");
      done?.(updated);
      return undefined;
    },
  });
  m.el.style.maxWidth = "calc(100vw - 32px)"; // the backdrop's grid track grows with its content: keep phones in view
  m.el.querySelectorAll("[data-reset]").forEach((btn) => btn.addEventListener("click", () => {
    const path = btn.dataset.reset;
    const on = !reset.has(path);
    if (on) reset.add(path); else reset.delete(path);
    btn.textContent = on ? "Undo reset" : "Reset";
    btn.setAttribute("aria-pressed", String(on));
    const target = path.startsWith("launch.env.") ? m.el.querySelector(`[name="env:${CSS.escape(path.slice("launch.env.".length))}"]`)
      : m.el.querySelector(`[name="${CSS.escape(path)}"]`);
    if (target) target.disabled = on;
    const label = btn.parentElement?.querySelector("span:not([data-error])");
    if (label && !path.startsWith("launch.env.")) label.textContent = on ? "back to what Atrium finds when you save" : OVERRIDE_NOTE;
  }));
  const section = saas && focus === "launch" ? "ui" : focus;
  if (section) {
    setTimeout(() => {
      const el = m.el.querySelector(`[data-section="${section}"]`);
      el?.scrollIntoView({ block: "nearest" });
      el?.querySelector("input:not(:disabled), select")?.focus();
    }, 60);
  }
  return m;
}

const TABS = ["integration", "connection", "manifest", "patches", "process", "supervisor"];

async function renderDetail(el, ctx, id, initialTab) {
  let tab = TABS.includes(initialTab) ? initialTab : "integration";
  let logs = [];
  let messages = [];
  let strategies = [];
  let idp = null;
  let toolName = id;
  let connection = null; // the Connection tab's panel: kept across redraws so unsaved settings survive live updates
  let current = null; // the tool as last drawn (the manifest editor starts from it)
  const draw = async () => {
    const [tool, identity, group] = await Promise.all([get(`/tools/${id}`), loadIdentity().catch(() => null), get("/subsidiaries").catch(() => null)]);
    current = tool;
    const team = group?.subsidiaries.find((s) => s.tool_id === id); // its agent team inside the tool (a subsidiary), if any
    idp = identity;
    toolName = tool.name;
    const ssoRow = idp?.tools.find((t) => t.tool_id === id);
    if (tab === "process") logs = (await get(`/tools/${id}/logs`)).lines;
    if (tab === "supervisor") messages = await get(`/agents/${encodeURIComponent(`tool:${id}`)}/messages?limit=80`);
    if (tab === "integration") strategies = tool.manifest ? await get(`/tools/${id}/strategies`).catch(() => []) : [];
    ctx.crumb(`Apps / ${tool.name}`);
    const m = tool.manifest;
    const busy = ["importing", "analyzing"].includes(tool.status);
    const running = tool.process?.running;
    setHTML(el, html`
      <section class="card" style="margin-bottom:16px">
        <div class="row" style="align-items:flex-start;flex-wrap:nowrap;gap:16px">
          ${appIcon(tool, "lg")}
          <div style="flex:1;min-width:0">
            <div class="row"><h1>${tool.name}</h1>${badge(tool.status)}${tool.report ? badge(tool.report.level) : ""}${running ? badge("running", "ok") : ""}</div>
            <p class="muted" style="margin-top:4px">${m?.description || (busy ? "The supervisor is analysing this tool..." : "No description.")}</p>
            <p class="faint mono" style="font-size:12px;margin-top:6px;overflow-wrap:anywhere">${icon(SOURCE_ICON[tool.source_type])} ${tool.source}</p>
            ${tool.error ? html`<div class="notice warn" style="margin-top:10px">${icon("alert")}<div>${tool.error}</div></div>` : ""}
            ${tool.notes?.length ? html`<ul class="muted" style="font-size:12.5px;margin:8px 0 0;padding-left:18px">${tool.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
          </div>
          ${ring(tool.report?.score, 64)}
        </div>
        <div class="row" style="margin-top:14px">
          ${m?.ui?.url ? html`<a class="btn primary" href="#/portal/${tool.id}">${icon("external")}Open portal</a>` : ""}
          ${m?.kind !== "saas" && m?.launch?.command ? (running
            ? html`<button class="btn" data-act="stop" data-min-role="operator">${icon("stop")}Stop</button>`
            : html`<button class="btn" data-act="start" data-min-role="operator">${icon("play")}Start</button>`) : ""}
          <button class="btn" data-act="health" data-min-role="operator" ${!m?.health?.url ? "disabled" : ""}>${icon("activity")}Check health</button>
          <button class="btn" data-act="analyze" data-min-role="operator" ${busy ? "disabled" : ""}>${icon("refresh")}Re-analyse</button>
          <button class="btn" data-act="patch" data-min-role="operator" ${!tool.report ? "disabled" : ""}>${icon("wrench")}Propose patches</button>
          <button class="btn" data-act="extend" data-min-role="admin" ${!m ? "disabled" : ""} title="Close what Atrium itself lacks for ${tool.name} with an extension pack">${icon("puzzle")}Extend Atrium</button>
          ${team ? html`<a class="btn" href="#/subsidiaries/${encodeURIComponent(id)}" title="Its agent team inside the tool: ${statusInfo(team.status).text}">${icon("building")}Team inside
              <span class="badge ${statusInfo(team.status).tone}">${statusInfo(team.status).text}</span></a>`
            : html`<button class="btn" data-act="team-inside" data-min-role="operator" ${busy ? "disabled" : ""}
              title="A team of AI agents that works inside ${tool.name}, from a sidecar next to it, governed by Atrium">${icon("building")}Give it a team inside</button>`}
          ${ssoRow?.applied?.can_register ? html`<button class="btn" data-act="sso-register" data-min-role="operator"
            title="Register ${tool.name} as a client at its identity provider">${icon("shield")}Run provider registration</button>` : ""}
          <span class="spacer"></span>
          <button class="btn danger" data-act="remove" data-min-role="operator">${icon("trash")}Remove</button>
        </div>
      </section>
      <div class="tabs">${[["integration", "Integration"], ["connection", "Connection"], ["manifest", "Manifest"], ["patches", `Patches (${tool.patches.length})`], ["process", "Process"], ["supervisor", "Supervisor"]]
        .map(([k, label]) => html`<button class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`)}</div>
      <section class="card">
        ${tab === "integration" && strategies.length ? html`<h3 style="margin-bottom:10px">Integration strategies</h3>${strategyCards(id, strategies)}
          <h3 style="margin:18px 0 2px">Checks</h3>` : ""}
        ${tab === "integration" ? checksPanel(tool, idp) : ""}
        ${tab === "connection" ? html`<div data-slot="connection"></div>` : ""}
        ${tab === "manifest" ? manifestPanel(tool) : ""}
        ${tab === "patches" ? patchesPanel(tool) : ""}
        ${tab === "process" ? html`<header><h3>${running ? `Running (pid ${tool.process.pid})` : "Not running"}</h3>
            ${tool.process?.exit_code != null ? html`<span class="faint">last exit code ${tool.process.exit_code}</span>` : ""}</header>
            <pre class="code wrap">${logs.length ? logs.join("\n") : "No output yet."}</pre>` : ""}
        ${tab === "supervisor" ? html`<p class="muted" style="margin-bottom:10px">Conversation of the <b>${tool.name} Supervisor</b> with the other agents.</p>
            ${messages.length ? messages.slice().reverse().map((msg) => html`<div class="msg-line"><span class="route">${msg.sender} &rarr; ${msg.recipient}</span>
              <span><span class="subj">${msg.subject}</span> <span class="faint">${msg.kind}</span></span><span class="faint">${timeAgo(msg.ts)}</span></div>`)
            : html`<p class="faint">No messages yet.</p>`}` : ""}
      </section>`);
    const slot = el.querySelector('[data-slot="connection"]');
    if (slot) {
      connection ||= mountConnection({ toolId: id, toolName: tool.name });
      slot.replaceWith(connection.el);
    } else {
      connection = null;
    }
  };
  const openEditor = (section) => {
    if (current?.manifest) openManifestEditor(current, { focus: section, done: () => draw().catch(() => {}) });
  };
  const pickProvider = () => {
    const row = idp?.tools.find((t) => t.tool_id === id);
    if (idp?.providers.length) openProviderPicker({ toolId: id, toolName, data: idp, current: row?.choice || row?.pending?.provider || row?.connected_to || row?.selected, done: draw });
  };
  actions(el, {
    tab: (d) => { tab = d.tab; history.replaceState(null, "", `#/tools/${encodeURIComponent(id)}/${tab}`); draw(); },
    async start() {
      const r = await post(`/tools/${id}/start`).catch((e) => toast(e.message, "bad"));
      if (!r) return;
      if (r.status === "needs_input") toast(r.reason, "warn"); // no launch command yet: the reason says what to do
      else toast(r.status === "pending_approval" ? "Waiting for approval" : r.status === "denied" ? r.reason : "Started", r.status === "denied" ? "bad" : "ok");
    },
    async stop() {
      const r = await post(`/tools/${id}/stop`).catch((e) => toast(e.message, "bad"));
      if (r?.status === "pending_approval") toast("Waiting for approval", "ok");
    },
    async health() {
      const r = await post(`/tools/${id}/health`).catch((e) => toast(e.message, "bad"));
      if (r) toast(`${r.ok ? "Healthy" : "Unhealthy"}: ${r.detail}`, r.ok ? "ok" : "bad");
    },
    async analyze() { await post(`/tools/${id}/analyze`); toast("Re-analysing - the supervisor will re-score the suite", "ok"); },
    async patch() {
      const r = await post(`/tools/${id}/patches`).catch((e) => toast(e.message, "bad"));
      if (r) proposeToast(id, r, () => draw().catch(() => {}));
    },
    "edit-manifest": (d) => openEditor(d.section),
    extend: () => openExtend({ id, name: toolName }, { model: ctx.state.overview?.llm?.available !== false }),
    "team-inside": () => openGiveTeam({ toolId: id, toolName }),
    async "sso-connect"(d) {
      const r = await post(`/tools/${id}/sso`, { provider: d.provider }).catch((e) => toast(e.message, "bad"));
      const why = (r?.skipped || []).map((s) => s.reason).join(" "); // e.g. an SSO proxy needs the tool's port first
      if (r) toast(r.patches.length ? "Single sign-on patch proposed - see Approvals" : r.pending ? "A patch is already waiting for approval"
        : why ? `Not proposed: ${why}` : "Nothing to do", !r.patches.length && !r.pending && why ? "warn" : "ok");
      draw();
    },
    "sso-pick": () => pickProvider(),
    "sso-register": () => {
      const row = idp?.tools.find((t) => t.tool_id === id);
      const provider = idp?.providers.find((p) => p.tool_id === row?.applied?.provider)?.name;
      runRegistration(id, toolName, provider).then(draw);
    },
    async remove() {
      if (!(await confirmDialog("Remove tool", "Remove this tool from the hub? Its supervisor is retired and cloned files are deleted. Your own folders are not touched.", "Remove"))) return;
      await del(`/tools/${id}`);
      toast("Tool removed", "ok");
      location.hash = "#/tools";
    },
  });
  wireStrategies(el, {
    refresh: () => draw().catch(() => {}),
    handlers: { choose_provider: pickProvider, connect_sso: pickProvider, import_provider: () => openImport(), edit_manifest: () => openEditor() },
  });
  await draw();
  if (takeEditRequest(id)) openEditor(); // asked for from the Integration hub's Adapters card
  ctx.live(["tool", "patch", "approval", "subsidiary"], draw, 500);
  ctx.live(["message"], () => (tab === "supervisor" ? draw() : null), 800);
  ctx.live(["connection", "flow", "flow_removed"], () => connection?.refresh(), 500);
  ctx.live(["connection", "flow", "flow_removed"], () => (tab === "integration" ? draw() : null), 800);
}

export async function render(el, ctx) {
  const [id, tab] = ctx.params;
  if (id) return renderDetail(el, ctx, id, tab);
  return renderList(el, ctx);
}
