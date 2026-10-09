import { get, patch } from "../api.js";
import { badge, can, field, html, icon, setHTML, toast } from "../ui.js";

const LEVELS = [
  ["manual", "Manual", "Every agent command and patch waits for your approval."],
  ["assisted", "Assisted (recommended)", "Agents run read-only commands on their own; anything that changes state waits for approval."],
  ["autonomous", "Autonomous", "Agents act without asking, except for blocked commands. The GRC Supervisor flags this as a failing control."],
];
const SLA = ["critical", "high", "medium", "low"];

export async function render(el) {
  const s = await get("/settings");
  const admin = can("admin");
  setHTML(el, html`
    <div class="page-head"><div><h1>Settings</h1><p class="muted">How much the agents may do on their own, which Claude model they use, and vulnerability deadlines.</p></div></div>
    ${admin ? "" : html`<div class="notice" style="margin-bottom:16px">${icon("lock")}<div class="muted">Only administrators can change these settings.</div></div>`}
    <form id="settings-form" class="grid split">
      <section class="stack">
        <div class="card"><header><h2>Agent autonomy</h2></header>
          <div class="stack" style="gap:10px">${LEVELS.map(([value, title, text]) => html`<label class="radio-card">
            <input type="radio" name="autonomy" value="${value}" ${s.autonomy === value ? "checked" : ""}>
            <div><b>${title}</b><p class="muted">${text}</p></div></label>`)}</div></div>
        <div class="card"><header><h2>Vulnerability management</h2>${icon("bug")}</header>
          <p class="muted" style="margin-bottom:12px">Days to fix a finding, counted from when it was first seen. Open critical findings past their deadline raise a risk;
            control HB-VM-3 checks critical and high ones.</p>
          <div class="sla-grid">${SLA.map((sev) => field(html`<span class="sev ${sev}">${sev}</span>`,
            html`<input type="number" name="sla_${sev}" min="1" max="3650" step="1" value="${s.vuln_sla_days?.[sev] ?? ""}" required aria-label="${sev} SLA in days">`))}</div>
          <label class="check" style="margin-top:4px"><input type="checkbox" name="scans_need_approval" ${s.guardrails?.scans_need_approval !== false ? "checked" : ""}>
            <span>Scheduled and agent-started scans wait for approval<span class="faint" style="display:block;font-size:12px">A person pressing Scan now decides
              themselves; in autonomous mode scans never wait.</span></span></label></div>
      </section>
      <section class="stack">
        <div class="card"><header><h2>AI model</h2>${s.llm.available ? badge("Claude connected", "ok") : badge("rules mode", "warn")}</header>
          ${field("Default model for all agents", html`<input name="model" list="model-list" value="${s.model}">
            <datalist id="model-list"><option value="claude-opus-5-5"><option value="claude-sonnet-5-5"><option value="claude-haiku-5-5"><option value="claude-fable-5-1"></datalist>`,
            "Individual agents can override this on the Agents page.")}
          ${s.llm.available ? "" : html`<div class="notice">${icon("bot")}<div class="muted">No Claude credentials found. Set <code>ANTHROPIC_API_KEY</code> (or run <code>ant auth login</code>)
            and restart the hub. Without it the agents use deterministic rules and templates.</div></div>`}
          ${s.llm.last_error ? html`<p style="color:var(--bad);margin-top:8px;font-size:12.5px">Last error: ${s.llm.last_error}</p>` : ""}</div>
        <div class="card" data-min-role="admin"><header><h2>Users &amp; access</h2>${icon("users")}</header>
          <p class="muted" style="margin-bottom:10px">Accounts, roles and API tokens for scripts and integrations.</p>
          <a class="btn" href="#/users">${icon("arrow")}Manage users</a></div>
        <div class="card"><header><h2>About</h2></header><dl class="kv"><dt>Version</dt><dd>${s.version}</dd><dt>Data directory</dt><dd class="mono">${s.data_dir}</dd>
          <dt>API docs</dt><dd><a href="/api/docs" target="_blank" rel="noopener">/api/docs</a></dd></dl></div>
        <div data-min-role="admin"><button class="btn primary">${icon("check")}Save settings</button></div>
      </section>
    </form>`);
  const form = el.querySelector("#settings-form");
  if (!admin) form.querySelectorAll("input").forEach((input) => { input.disabled = true; });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!admin) return;
    const data = new FormData(e.target);
    const sla = Object.fromEntries(SLA.map((sev) => [sev, Number(data.get(`sla_${sev}`))]));
    if (Object.values(sla).some((d) => !Number.isInteger(d) || d < 1 || d > 3650)) {
      toast("Days to fix must be whole numbers from 1 to 3650", "bad");
      return;
    }
    try {
      await patch("/settings", {
        autonomy: data.get("autonomy"), model: String(data.get("model") || "").trim() || null,
        vuln_sla_days: sla, guardrails: { scans_need_approval: data.get("scans_need_approval") === "on" },
      });
      toast("Settings saved", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  });
}
