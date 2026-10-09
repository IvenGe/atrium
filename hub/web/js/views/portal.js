import { get } from "../api.js";
import { appIcon, emptyState, html, icon, setHTML } from "../ui.js";

// Opens an imported tool inside the hub, like switching apps in an office suite.
export async function render(el, ctx) {
  const tool = await get(`/tools/${ctx.params[0]}`);
  ctx.crumb(`Portals / ${tool.name}`);
  const url = tool.manifest?.ui?.url;
  if (!url) {
    setHTML(el, html`<section class="card">${emptyState("grid", `${tool.name} has no web interface`, "Add ui.url to its manifest, or use its API through the agents.",
      html`<a class="btn" href="#/tools/${tool.id}">Open app details</a>`)}</section>`);
    return;
  }
  const safe = /^https?:\/\//i.test(url) ? url : "about:blank";
  setHTML(el, html`<div class="portal-frame">
    <div class="row" style="margin-bottom:10px;justify-content:space-between">
      <div class="row">${appIcon(tool, "sm")}<b>${tool.name}</b><span class="faint mono" style="font-size:12px">${url}</span>
        ${tool.manifest.kind !== "saas" && !tool.running ? html`<span class="badge warn">not running - start it from the app page</span>` : ""}</div>
      <div class="row"><a class="btn sm" href="#/tools/${tool.id}">${icon("sliders")}Details</a>
        <a class="btn sm" href="${safe}" target="_blank" rel="noopener noreferrer">${icon("external")}Open in new tab</a></div></div>
    <iframe src="${safe}" title="${tool.name}" referrerpolicy="no-referrer" sandbox="allow-forms allow-scripts allow-same-origin allow-popups allow-downloads"></iframe>
    <p class="faint" style="font-size:12px;margin-top:6px">Blank? Many apps forbid being embedded - use "Open in new tab".</p></div>`);
}
