import { get } from "../api.js";
import { actions, appIcon, badge, emptyState, html, icon, ring, setHTML, timeAgo } from "../ui.js";
import { openImport } from "./tools.js";

const stat = (label, value, sub, iconName, href) => html`
  <a class="card stat" href="${href}"><div class="stat-icon">${icon(iconName)}</div>
  <div><div class="label">${label}</div><div class="value">${value ?? "-"}</div><div class="sub">${sub}</div></div></a>`;

/** The rules-mode notice. Hidden once ChatGPT, Grok, a local model, or Claude can plan in plain language. */
export function modelNotice(ov, style = "margin-bottom:16px") {
  const model = ov?.model;
  if (!ov || ov.llm?.available || model?.plain_language) return "";
  if (model?.provider && model.provider !== "rules" && model.provider !== "anthropic") {
    const name = model.label || "The selected model";
    return html`<div class="notice" style="${style}">${icon("bot")}<div><b>${name} needs an API key.</b>
      <span class="muted">Add it under Settings so agents can plan in plain language.</span></div></div>`;
  }
  return html`<div class="notice" style="${style}">${icon("bot")}<div><b>Agents run in rules mode.</b>
    <span class="muted">Everything works. To let agents plan in plain language, pick ChatGPT, Grok or a local model in Settings, or start the hub with <code>ANTHROPIC_API_KEY</code> set. Code patches use Claude.</span></div></div>`;
}

export function toolCard(t) {
  const level = t.report?.level;
  return html`<a class="tool-card" href="#/tools/${t.id}">
    <div class="top">${appIcon(t)}<div style="min-width:0;flex:1"><div class="name">${t.name}</div>
      <div class="faint" style="font-size:12px">${t.manifest?.kind === "saas" ? "SaaS" : t.manifest?.kind === "closed" ? "Closed source" : "Source code"} - ${t.source_type}</div></div>
      ${ring(t.report?.score)}</div>
    <div class="row">${badge(t.status)}${level ? badge(level) : ""}${t.running ? badge("running", "ok") : ""}
      ${t.health && t.health.ok === false ? badge("down", "bad") : ""}</div></a>`;
}

export function feedItem(a) {
  const tone = a.level === "error" ? "bad" : a.level === "warn" ? "warn" : "ok";
  return html`<div class="feed-item"><span class="dot ${tone}" style="margin-top:7px"></span>
    <div><span class="who">${a.actor}</span> <span class="muted">${a.text}</span></div><span class="when">${timeAgo(a.ts)}</span></div>`;
}

export async function render(el, ctx) {
  const draw = async () => {
    const [ov, tools, activity] = await Promise.all([get("/overview"), get("/tools"), get("/activity?limit=40")]);
    setHTML(el, html`
      <div class="hero">
        <div><h1>Your suite</h1><p class="muted">Open-source, closed-source and SaaS tools - integrated, patched and supervised by agents.</p></div>
        <div class="row"><a class="btn" href="#/agents" data-min-role="operator">${icon("chat")}Ask the supervisor</a>
          <button class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import tool</button></div>
      </div>
      <div class="grid cols-5" style="margin-bottom:16px">
        ${stat("Apps integrated", ov.tools, ov.suite_score != null ? `suite score ${ov.suite_score} - ${ov.running} running` : "import your first tool", "grid", "#/tools")}
        ${stat("Agents", ov.agents, `${ov.agents_working} working now`, "bot", "#/agents")}
        ${stat("Awaiting approval", ov.approvals_pending, "agent commands & patches", "checkCircle", "#/approvals")}
        ${stat("Assets", ov.assets, "in the register", "box", "#/assets")}
        ${stat("People", ov.people, ov.leavers ? `${ov.leavers} leaver${ov.leavers === 1 ? "" : "s"} still holding something` : "in the directory", "contact", ov.leavers ? "#/people/leavers" : "#/people")}
        ${stat("Vulnerabilities", ov.vulnerabilities_open, ov.vulnerabilities_overdue ? `${ov.vulnerabilities_overdue} past their deadline` : "open findings", "bug", "#/vulnerabilities")}
        ${stat("Compliance", ov.compliance_score != null ? `${ov.compliance_score}%` : "-", `${ov.risks_open} open risks`, "shield", "#/compliance")}
      </div>
      ${modelNotice(ov)}
      <div class="grid split">
        <section class="card"><header><h2>Apps</h2><a href="#/tools">All apps &rarr;</a></header>
          ${tools.length ? html`<div class="tool-grid">${tools.map(toolCard)}</div>`
            : emptyState("grid", "No tools yet", "Import a GitHub repository, a local project or a SaaS service. A supervisor agent is assigned to each one.",
              html`<button class="btn primary" data-act="import" data-min-role="operator">${icon("plus")}Import your first tool</button>`)}
        </section>
        <section class="card"><header><h2>Live agent activity</h2><a href="#/agents">Agents &rarr;</a></header>
          <div class="feed scroll">${activity.length ? activity.slice().reverse().map(feedItem) : html`<p class="muted">Nothing yet.</p>`}</div>
        </section>
      </div>`);
  };
  actions(el, { import: () => openImport() });
  await draw();
  ctx.live(["tool", "tool_removed", "activity", "approval", "asset", "grc", "vulnerability", "person", "person_removed"], draw, 600);
}
