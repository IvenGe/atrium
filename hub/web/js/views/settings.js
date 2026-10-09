import { get, patch } from "../api.js";
import { badge, field, html, icon, setHTML, toast } from "../ui.js";

const LEVELS = [
  ["manual", "Manual", "Every agent command and patch waits for your approval."],
  ["assisted", "Assisted (recommended)", "Agents run read-only commands on their own; anything that changes state waits for approval."],
  ["autonomous", "Autonomous", "Agents act without asking, except for blocked commands. The GRC Supervisor flags this as a failing control."],
];

export async function render(el) {
  const s = await get("/settings");
  setHTML(el, html`
    <div class="page-head"><div><h1>Settings</h1><p class="muted">How much the agents may do on their own, and which Claude model they use.</p></div></div>
    <form id="settings-form" class="grid split">
      <section class="card"><header><h2>Agent autonomy</h2></header>
        <div class="stack" style="gap:10px">${LEVELS.map(([value, title, text]) => html`<label class="radio-card">
          <input type="radio" name="autonomy" value="${value}" ${s.autonomy === value ? "checked" : ""}>
          <div><b>${title}</b><p class="muted">${text}</p></div></label>`)}</div></section>
      <section class="stack">
        <div class="card"><header><h2>AI model</h2>${s.llm.available ? badge("Claude connected", "ok") : badge("rules mode", "warn")}</header>
          ${field("Default model for all agents", html`<input name="model" list="model-list" value="${s.model}">
            <datalist id="model-list"><option value="claude-opus-5-5"><option value="claude-sonnet-5-5"><option value="claude-haiku-5-5"><option value="claude-fable-5-1"></datalist>`,
            "Individual agents can override this on the Agents page.")}
          ${s.llm.available ? "" : html`<div class="notice">${icon("bot")}<div class="muted">No Claude credentials found. Set <code>ANTHROPIC_API_KEY</code> (or run <code>ant auth login</code>)
            and restart the hub. Without it the agents use deterministic rules and templates.</div></div>`}
          ${s.llm.last_error ? html`<p style="color:var(--bad);margin-top:8px;font-size:12.5px">Last error: ${s.llm.last_error}</p>` : ""}</div>
        <div class="card"><header><h2>About</h2></header><dl class="kv"><dt>Version</dt><dd>${s.version}</dd><dt>Data directory</dt><dd class="mono">${s.data_dir}</dd>
          <dt>API docs</dt><dd><a href="/api/docs" target="_blank" rel="noopener">/api/docs</a></dd></dl></div>
        <div><button class="btn primary">${icon("check")}Save settings</button></div>
      </section>
    </form>`);
  el.querySelector("#settings-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(e.target);
    try {
      await patch("/settings", { autonomy: data.get("autonomy"), model: String(data.get("model") || "").trim() || null });
      toast("Settings saved", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  });
}
