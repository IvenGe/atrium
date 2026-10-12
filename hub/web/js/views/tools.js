import { del, get, patch, post } from "../api.js";
import { mountConnection } from "../connection.js";
import { openExtend } from "../extensions.js";
import { loadIdentity, openProviderPicker, runRegistration, statusBadge } from "../sso.js";
import { strategyCards, wireStrategies } from "../strategies.js";
import {
  actions, appIcon, badge, confirmDialog, diffView, emptyState, field, html, icon, modal, ring, setHTML, timeAgo, toast,
} from "../ui.js";

const KIND_LABEL = { oss: "Source code", closed: "Closed source", saas: "SaaS" };
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
  return html`${tool.report.checks.map((c) => html`<div class="check-row">
      <div class="ico ${c.status}">${icon(CHECK_ICON[c.status])}</div>
      <div style="flex:1;min-width:0"><div class="row" style="gap:8px"><b>${c.title}</b>${c.fix ? html`<span class="badge accent">${icon("wrench")}${c.fix.replace(/_/g, " ")}</span>` : ""}</div>
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
  return html`<dl class="kv" style="margin-bottom:16px">
      <dt>Kind</dt><dd>${KIND_LABEL[m.kind]}${m.native ? html` ${badge("native manifest", "ok")}` : html` ${badge("inferred", "warn")}`}</dd>
      <dt>Version</dt><dd>${m.version || "unknown"}</dd><dt>License</dt><dd>${m.license || "unknown"}</dd>
      <dt>Stack</dt><dd>${list(m.stack)}</dd>
      <dt>Launch</dt><dd class="mono">${m.launch.setup ? html`${m.launch.setup} &amp;&amp; ` : ""}${m.launch.command || "-"}${m.launch.port ? html` <span class="faint">(port ${m.launch.port})</span>` : ""}</dd>
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
      ${ssoPlan(p.sso)}
      ${p.branch ? html`<p style="font-size:12.5px">Branch <code>${p.branch}</code> in worktree <code>${p.location}</code></p>`
        : p.location ? html`<p style="font-size:12.5px">Written to <code>${p.location}</code></p>` : ""}
      ${p.error ? html`<p style="color:var(--bad)">${p.error}</p>` : ""}
      <details><summary class="muted" style="cursor:pointer;font-size:12.5px">Show diff</summary><div style="margin-top:8px">${diffView(p.diff)}</div></details>
    </div>`)}`;
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
  const draw = async () => {
    const [tool, identity] = await Promise.all([get(`/tools/${id}`), loadIdentity().catch(() => null)]);
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
            ${m?.ui?.url ? html`<form class="remote-form" style="margin-top:12px;padding:0;border:0;background:transparent" data-min-role="operator">
              ${field("Server where this app runs", html`<div class="row"><input name="portal-url" value="${m.ui.url}" spellcheck="false" autocomplete="off" placeholder="https://ciso.example.com or http://10.0.0.8:6333"><button type="button" class="btn" data-act="portal">${icon("link")}Connect</button></div>`,
                "Leave the local address, or point the portal at another server that already runs the app.")}
            </form>` : ""}
            ${tool.launch_error ? html`<div class="notice warn" style="margin-top:10px">${icon("alert")}<div>${tool.launch_error}</div></div>` : ""}
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
  const pickProvider = () => {
    const row = idp?.tools.find((t) => t.tool_id === id);
    if (idp?.providers.length) openProviderPicker({ toolId: id, toolName, data: idp, current: row?.choice || row?.pending?.provider || row?.connected_to || row?.selected, done: draw });
  };
  el.addEventListener("submit", (event) => {
    if (!(event.target instanceof HTMLFormElement) || !event.target.classList.contains("remote-form")) return;
    event.preventDefault();
    event.target.querySelector("[data-act=portal]")?.click();
  });
  actions(el, {
    tab: (d) => { tab = d.tab; history.replaceState(null, "", `#/tools/${encodeURIComponent(id)}/${tab}`); draw(); },
    async start() {
      const r = await post(`/tools/${id}/start`).catch((e) => toast(e.message, "bad"));
      if (!r) return;
      const failed = r.status === "denied" || r.status === "failed";
      toast(r.status === "pending_approval" ? "Waiting for approval" : failed ? (r.reason || "Could not start") : "Started", failed ? "bad" : "ok");
    },
    async portal() {
      const url = String(el.querySelector("[name=portal-url]")?.value || "").trim();
      if (!url) { toast("Enter the address of the server", "bad"); return; }
      const updated = await patch(`/tools/${id}/portal`, { url }).catch((e) => toast(e.message, "bad"));
      if (updated) toast(`Portal opens ${updated.manifest.ui.url}`, "ok");
      draw();
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
      if (r) toast(r.patches.length ? `${r.patches.length} patch(es) proposed - see Approvals` : "No new patches needed", "ok");
    },
    extend: () => openExtend({ id, name: toolName }, { claude: ctx.state.overview?.llm?.available !== false }),
    async "sso-connect"(d) {
      const r = await post(`/tools/${id}/sso`, { provider: d.provider }).catch((e) => toast(e.message, "bad"));
      if (r) toast(r.patches.length ? "Single sign-on patch proposed - see Approvals" : r.pending ? "A patch is already waiting for approval" : "Nothing to do", "ok");
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
    handlers: { choose_provider: pickProvider, connect_sso: pickProvider, import_provider: () => openImport() },
  });
  await draw();
  ctx.live(["tool", "patch", "approval"], draw, 500);
  ctx.live(["message"], () => (tab === "supervisor" ? draw() : null), 800);
  ctx.live(["connection", "flow", "flow_removed"], () => connection?.refresh(), 500);
  ctx.live(["connection", "flow", "flow_removed"], () => (tab === "integration" ? draw() : null), 800);
}

export async function render(el, ctx) {
  const [id, tab] = ctx.params;
  if (id) return renderDetail(el, ctx, id, tab);
  return renderList(el, ctx);
}
