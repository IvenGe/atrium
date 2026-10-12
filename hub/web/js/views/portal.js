import { get, patch, post } from "../api.js";
import { actions, appIcon, emptyState, field, html, icon, setHTML, toast } from "../ui.js";

// Opens an imported tool inside the hub, like switching apps in an office suite.
// A tool that is not running on this machine can instead be opened at the address of a remote server.
export async function render(el, ctx) {
  const id = ctx.params[0];
  let showServer = false;

  const draw = async () => {
    const tool = await get(`/tools/${id}`);
    ctx.crumb(`Portals / ${tool.name}`);
    const url = tool.manifest?.ui?.url;
    if (!url) {
      setHTML(el, html`<section class="card">${emptyState("grid", `${tool.name} has no web interface`, "Add ui.url to its manifest, or use its API through the agents.",
        html`<a class="btn" href="#/tools/${tool.id}">Open app details</a>`)}</section>`);
      return;
    }
    const remote = !loopback(url);
    const running = Boolean(tool.process?.running || tool.running);
    const localDown = !remote && tool.manifest.kind !== "saas" && !running;
    const logs = localDown ? ((await get(`/tools/${id}/logs`)).lines || []).slice(-12) : [];
    const safe = /^https?:\/\//i.test(url) ? url : "about:blank";
    const dockerMissing = logs.some((line) => /docker: not found/i.test(line));
    const exitCode = tool.process?.exit_code;
    setHTML(el, html`<div class="portal-frame">
      <div class="row" style="margin-bottom:10px;justify-content:space-between">
        <div class="row">${appIcon(tool, "sm")}<b>${tool.name}</b><span class="faint mono" style="font-size:12px">${url}</span>
          ${remote ? html`<span class="badge info">remote server</span>` : ""}
          ${localDown ? html`<span class="badge warn">not running on this machine</span>` : ""}</div>
        <div class="row">
          ${localDown ? "" : html`<button type="button" class="btn sm" data-act="server" data-min-role="operator">${icon("server")}${showServer ? "Hide server" : "Remote server"}</button>`}
          <a class="btn sm" href="#/tools/${tool.id}">${icon("sliders")}Details</a>
          <a class="btn sm" href="${safe}" target="_blank" rel="noopener noreferrer">${icon("external")}Open in new tab</a></div></div>
      ${showServer || localDown ? serverForm(url) : ""}
      ${localDown ? offline(tool, logs, dockerMissing, exitCode) : html`<iframe src="${safe}" title="${tool.name}" referrerpolicy="no-referrer" sandbox="allow-forms allow-scripts allow-same-origin allow-popups allow-downloads"></iframe>
        <p class="faint" style="font-size:12px;margin-top:6px">Blank? Many apps forbid being embedded - use "Open in new tab".</p>`}</div>`);
  };

  el.addEventListener("submit", (event) => {
    if (!(event.target instanceof HTMLFormElement) || !event.target.classList.contains("remote-form")) return;
    event.preventDefault();
    event.target.querySelector("[data-act=connect]")?.click();
  });
  actions(el, {
    server() { showServer = !showServer; draw(); },
    async connect() {
      const input = el.querySelector("[name=portal-url]");
      const url = String(input?.value || "").trim();
      if (!url) { toast("Enter the address of the server", "bad"); return; }
      const updated = await patch(`/tools/${id}/portal`, { url }).catch((err) => toast(err.message, "bad"));
      if (!updated) return;
      showServer = false;
      toast(`Portal opens ${updated.manifest.ui.url}`, "ok");
      draw();
    },
    async start() {
      const result = await post(`/tools/${id}/start`).catch((err) => toast(err.message, "bad"));
      if (!result) return;
      if (result.status === "pending_approval") toast("Waiting for approval", "ok");
      else if (result.status === "denied" || result.status === "failed") toast(result.reason || "Could not start", "bad");
      else toast("Starting", "ok");
      draw();
    },
  });
  await draw();
  ctx.live(["tool"], () => draw(), 400);
}

function loopback(url) {
  try {
    const host = new URL(url).hostname.replace(/^\[|\]$/g, "").toLowerCase();
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
  } catch {
    return false;
  }
}

function serverForm(url) {
  return html`<form class="remote-form card" data-min-role="operator">
    ${field("Server where this app runs", html`<div class="row"><input name="portal-url" value="${url}" spellcheck="false" autocomplete="off" placeholder="https://ciso.example.com or http://10.0.0.8:6333"><button type="button" class="btn primary" data-act="connect">${icon("link")}Connect</button></div>`,
      "This machine, or another server that already runs the app. Health checks and the API address follow it when they still point at the old local port.")}
  </form>`;
}

function offline(tool, logs, dockerMissing, exitCode) {
  const why = tool.launch_error
    || (dockerMissing
      ? "Docker is not installed on this machine, so the start command cannot run here. Connect the portal to a server where the app is already running."
      : "Nothing is listening at the portal address, so the page cannot load. Start it here, or connect to a server that already runs it.");
  return html`<div class="portal-offline">
    <div class="panel">
      <h2 style="margin:0 0 6px">${tool.name} is not running here</h2>
      <p class="muted">${why}</p>
      ${tool.manifest?.launch?.command ? html`<p class="faint mono" style="font-size:12.5px">Last command: ${tool.manifest.launch.command}${exitCode != null ? ` (exit ${exitCode})` : ""}</p>` : ""}
      ${logs.length ? html`<pre class="code wrap">${logs.join("\n")}</pre>` : ""}
      <div class="row" style="margin-top:14px">
        ${tool.manifest?.launch?.command ? html`<button type="button" class="btn" data-act="start" data-min-role="operator">${icon("play")}Start here</button>` : ""}
      </div>
    </div>
  </div>`;
}
