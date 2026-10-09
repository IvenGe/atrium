import { del, get, post } from "../api.js";
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
        <button class="btn primary" data-act="import">${icon("plus")}Import tool</button></div>
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
          html`<button class="btn primary" data-act="import">${icon("plus")}Import tool</button>`)}
      </section>`);
    el.querySelectorAll("[data-stop]").forEach((a) => a.addEventListener("click", (e) => e.stopPropagation()));
  };
  actions(el, { import: () => openImport(), open: (d) => { location.hash = `#/tools/${d.id}`; } });
  await draw();
  ctx.live(["tool", "tool_removed"], draw);
}

// ---------- detail ----------
const CHECK_ICON = { pass: "check", warn: "minus", fail: "x" };

function checksPanel(tool) {
  if (!tool.report) return html`<p class="muted">Not analysed yet.</p>`;
  return html`${tool.report.checks.map((c) => html`<div class="check-row">
      <div class="ico ${c.status}">${icon(CHECK_ICON[c.status])}</div>
      <div style="flex:1;min-width:0"><div class="row" style="gap:8px"><b>${c.title}</b>${c.fix ? html`<span class="badge accent">${icon("wrench")}${c.fix.replace(/_/g, " ")}</span>` : ""}</div>
      <div class="muted" style="overflow-wrap:anywhere">${c.detail}</div></div></div>`)}`;
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
      <p class="muted" style="margin:6px 0">${p.rationale}</p>
      ${p.branch ? html`<p style="font-size:12.5px">Branch <code>${p.branch}</code> in worktree <code>${p.location}</code></p>`
        : p.location ? html`<p style="font-size:12.5px">Written to <code>${p.location}</code></p>` : ""}
      ${p.error ? html`<p style="color:var(--bad)">${p.error}</p>` : ""}
      <details><summary class="muted" style="cursor:pointer;font-size:12.5px">Show diff</summary><div style="margin-top:8px">${diffView(p.diff)}</div></details>
    </div>`)}`;
}

async function renderDetail(el, ctx, id) {
  let tab = "integration";
  let logs = [];
  let messages = [];
  const draw = async () => {
    const tool = await get(`/tools/${id}`);
    if (tab === "process") logs = (await get(`/tools/${id}/logs`)).lines;
    if (tab === "supervisor") messages = await get(`/agents/${encodeURIComponent(`tool:${id}`)}/messages?limit=80`);
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
            ? html`<button class="btn" data-act="stop">${icon("stop")}Stop</button>`
            : html`<button class="btn" data-act="start">${icon("play")}Start</button>`) : ""}
          <button class="btn" data-act="health" ${!m?.health?.url ? "disabled" : ""}>${icon("activity")}Check health</button>
          <button class="btn" data-act="analyze" ${busy ? "disabled" : ""}>${icon("refresh")}Re-analyse</button>
          <button class="btn" data-act="patch" ${!tool.report ? "disabled" : ""}>${icon("wrench")}Propose patches</button>
          <span class="spacer"></span>
          <button class="btn danger" data-act="remove">${icon("trash")}Remove</button>
        </div>
      </section>
      <div class="tabs">${[["integration", "Integration"], ["manifest", "Manifest"], ["patches", `Patches (${tool.patches.length})`], ["process", "Process"], ["supervisor", "Supervisor"]]
        .map(([k, label]) => html`<button class="${tab === k ? "active" : ""}" data-act="tab" data-tab="${k}">${label}</button>`)}</div>
      <section class="card">
        ${tab === "integration" ? checksPanel(tool) : ""}
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
  };
  actions(el, {
    tab: (d) => { tab = d.tab; draw(); },
    async start() {
      const r = await post(`/tools/${id}/start`).catch((e) => toast(e.message, "bad"));
      if (r) toast(r.status === "pending_approval" ? "Waiting for approval" : r.status === "denied" ? r.reason : "Started", r.status === "denied" ? "bad" : "ok");
    },
    async stop() { await post(`/tools/${id}/stop`).catch((e) => toast(e.message, "bad")); },
    async health() {
      const r = await post(`/tools/${id}/health`).catch((e) => toast(e.message, "bad"));
      if (r) toast(`${r.ok ? "Healthy" : "Unhealthy"}: ${r.detail}`, r.ok ? "ok" : "bad");
    },
    async analyze() { await post(`/tools/${id}/analyze`); toast("Re-analysing - the supervisor will re-score the suite", "ok"); },
    async patch() {
      const r = await post(`/tools/${id}/patches`).catch((e) => toast(e.message, "bad"));
      if (r) toast(r.patches.length ? `${r.patches.length} patch(es) proposed - see Approvals` : "No new patches needed", "ok");
    },
    async remove() {
      if (!(await confirmDialog("Remove tool", "Remove this tool from the hub? Its supervisor is retired and cloned files are deleted. Your own folders are not touched.", "Remove"))) return;
      await del(`/tools/${id}`);
      toast("Tool removed", "ok");
      location.hash = "#/tools";
    },
  });
  await draw();
  ctx.live(["tool", "patch"], draw, 500);
  ctx.live(["message"], () => (tab === "supervisor" ? draw() : null), 800);
}

export async function render(el, ctx) {
  const [id] = ctx.params;
  if (id) return renderDetail(el, ctx, id);
  return renderList(el, ctx);
}
