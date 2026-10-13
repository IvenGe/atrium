import { del, get, patch, post } from "../api.js";
import { mountSso } from "../signin.js";
import { actions, badge, can, confirmDialog, emptyState, field, html, icon, modal, setHTML, timeAgo, toast } from "../ui.js";

const LEVELS = [
  ["manual", "Manual", "Every agent command and patch waits for your approval."],
  ["assisted", "Assisted (recommended)", "Agents run read-only commands on their own; anything that changes state waits for approval."],
  ["autonomous", "Autonomous", "Agents act without asking, except for blocked commands. The GRC Supervisor flags this as a failing control."],
];
const SLA = ["critical", "high", "medium", "low"];
const GUARD_GROUPS = {
  teams: "Agent teams", agents: "Agent actions", commands: "Commands", scans: "Vulnerability scans",
  extensions: "Extensions", self_patching: "Self-patching (changes to Atrium's own code)",
  network: "Network changes",
};
const SERVERS = "Ollama: http://localhost:11434/v1 - LM Studio: http://localhost:1234/v1 - vLLM: http://<host>:8000/v1 - llama.cpp server: http://<host>:8080/v1";
const hosted = (pv, id) => (pv.providers || []).some((p) => p.preset === id || p.id === id);
// Switches that allow a capability are on by default, but off is their protective side (safe_value in hub/guardrails.py):
// switching them back on is logged as relaxing. The catalog does not carry that yet, so it is named here (or read from `safe`).
const SAFE_OFF = new Set(["allow_extensions", "allow_self_patching"]);
const safeSide = (g) => g.safe ?? (SAFE_OFF.has(g.key) ? false : g.default);

/** Whether setting guardrail `g` to `value` loosens it: a switch leaving its protective side, or a higher limit. */
function relaxes(g, value) {
  return g.kind === "bool" ? g.value === safeSide(g) && value !== safeSide(g) : Number(value) > Number(g.value);
}

/** What switching a guardrail off disrupts right away (asked before it happens, although it is the safe side). */
const DISRUPTS = {
  allow_extensions: "Every enabled pack becomes inactive at once: its apps leave the sidebar, its data flows stop running, and its SSO recipes, compliance rules and team templates no longer apply. Packs and records are kept, and switching it back on restores them. Connector mappings already merged into tools' connections stay until a pack is disabled.",
  allow_self_patching: "The Patch Agent no longer proposes changes to Atrium's own code. Self-patches already waiting in Approvals stay there.",
};

function guardrailsView(catalog, admin) {
  const byKey = Object.fromEntries(catalog.map((g) => [g.key, g]));
  const nested = new Set(catalog.map((g) => g.requires).filter(Boolean));
  const groups = [...new Set(catalog.map((g) => g.group))];
  const relaxed = catalog.filter((g) => g.relaxed).length;
  const number = (n, active) => html`<div class="guard-num ${active ? "" : "inactive"}">
    <label for="guard-${n.key}">${n.title}</label>
    <input id="guard-${n.key}" type="number" min="${n.min}" max="${n.max}" step="1" value="${n.value}" data-guard-num="${n.key}" ${admin ? "" : "disabled"}>
    <button type="button" class="btn sm" data-act="guard-num" data-key="${n.key}" data-min-role="admin">Apply</button>
    <span class="faint">${n.min}-${n.max}${n.value !== n.default ? `, default ${n.default}` : ""}</span></div>`;
  const row = (g) => {
    const num = g.requires ? byKey[g.requires] : null;
    return html`<div class="guard ${g.relaxed ? "relaxed" : ""}">
      ${g.kind === "bool" ? html`<button type="button" class="toggle" role="switch" aria-checked="${g.value ? "true" : "false"}" aria-label="${g.title}"
        data-act="guard" data-key="${g.key}" ${admin ? "" : "disabled"}></button>` : ""}
      <div style="flex:1;min-width:0"><div class="row" style="gap:6px"><b>${g.title}</b>${g.control ? html`<span class="badge" title="Compliance control this protects">${g.control}</span>` : ""}
          ${g.relaxed ? badge("relaxed", "warn") : ""}</div>
        <p>${g.description}</p>
        ${g.kind === "int" ? number(g, true) : num ? number(num, Boolean(g.value)) : ""}</div></div>`;
  };
  return html`<header><h2>Agent guardrails</h2>${relaxed ? badge(`${relaxed} relaxed`, "warn") : badge("all protections on", "ok")}</header>
    <p class="muted" style="margin-bottom:12px">Safety switches for the AI agents. Every change is logged with your name; relaxing one is logged as a warning
      and shows up in the compliance controls.</p>
    ${groups.map((group) => html`<div class="guard-group"><h3>${GUARD_GROUPS[group] || group}</h3>
      ${catalog.filter((g) => g.group === group && !nested.has(g.key)).map(row)}</div>`)}`;
}

function providersView(pv) {
  const claude = pv.anthropic || {};
  const presets = pv.presets || [];
  return html`<header><h2>AI providers</h2>
      <span class="row" style="gap:6px" data-min-role="admin">
        ${presets.map((preset) => html`<button type="button" class="btn sm" data-act="prov-preset" data-id="${preset.id}" ${hosted(pv, preset.id) ? "disabled" : ""}>${icon("plus")}${preset.name}</button>`)}
        <button type="button" class="btn sm" data-act="prov-add">${icon("plus")}Add local provider</button>
      </span></header>
    <p class="muted" style="margin-bottom:12px">Team agents run on Claude, on ChatGPT or Grok, on a local model server with an OpenAI-compatible API
      (Ollama, LM Studio, vLLM, llama.cpp server), or on rules. Pick the provider per agent on the Agents page. The Hub Supervisor and the Patch Agent stay on Claude.</p>
    <div class="stack" style="gap:8px">
      <div class="provider"><div class="row" style="gap:6px"><b>Claude</b>${claude.available ? badge("connected", "ok") : badge("not connected", "warn")}</div>
        <div class="faint" style="font-size:12px">Anthropic API - see "AI model" for the default model.</div></div>
      ${pv.providers.map((p) => html`<div class="provider">
        <div class="row" style="gap:6px"><b>${p.name}</b>${badge(p.preset ? "hosted" : "local", "info")}
          ${p.last_test ? badge(p.last_test.ok ? "tested ok" : "test failed", p.last_test.ok ? "ok" : "bad") : badge("not tested", "warn")}
          <span class="spacer"></span>
          <span class="row" style="gap:4px" data-min-role="admin">
            <button type="button" class="btn sm" data-act="prov-test" data-id="${p.id}">${icon("activity")}Test</button>
            <button type="button" class="icon-btn sm" data-act="prov-edit" data-id="${p.id}" title="Edit" aria-label="Edit ${p.name}">${icon("edit")}</button>
            <button type="button" class="icon-btn sm danger" data-act="prov-remove" data-id="${p.id}" title="Remove" aria-label="Remove ${p.name}">${icon("trash")}</button></span></div>
        <div class="url mono">${p.base_url}</div>
        <div class="faint" style="font-size:12px">Default model: ${p.default_model || "none"} - ${p.api_key_set ? "API key stored" : "no API key"} -
          ${p.tools ? "tool calling on" : "tool calling off"} - timeout ${p.timeout}s</div>
        ${p.default_model ? "" : html`<div class="warn-text" style="font-size:12px">No default model: agents on this provider need their own model. Edit it to pick one${p.models?.length ? " from the tested list" : ""}.</div>`}
        ${p.last_test ? html`<div class="faint" style="font-size:12px;overflow-wrap:anywhere">Last test ${timeAgo(p.last_test.at)}: ${p.last_test.detail}</div>` : ""}
        ${p.models?.length ? html`<details><summary class="faint" style="cursor:pointer;font-size:12px">${p.models.length} model${p.models.length === 1 ? "" : "s"}</summary>
          <div class="tag-list" style="margin-top:6px">${p.models.map((m) => html`<span class="badge mono">${m}</span>`)}</div></details>` : ""}
      </div>`)}
      ${pv.providers.length ? "" : html`<p class="faint" style="font-size:12.5px">No ChatGPT, Grok or local providers yet. Add one to run team agents on it.</p>`}
    </div>`;
}

/** Asks before a guardrail is relaxed, showing what that risks; resolves true to go ahead. */
function confirmRelax(g, value) {
  return new Promise((resolve) => {
    const verb = g.kind === "bool" ? (value ? "Switch on" : "Switch off") : "Raise";
    const m = modal({
      title: g.kind === "bool" ? `${verb}: ${g.title}?` : `Raise ${g.title.toLowerCase()} to ${value}?`,
      submit: verb,
      body: html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div><b>Risk.</b> ${g.risk}</div></div>
        ${g.control ? html`<p style="font-size:13px;margin-bottom:8px">Compliance control <b>${g.control}</b> will no longer pass while this protection is relaxed.</p>` : ""}
        <p class="muted" style="font-size:12.5px">The change is logged with your name as a warning. You can restore the protection here at any time.</p>`,
      onSubmit: () => resolve(true),
    });
    m.el.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => resolve(false)));
    m.el.closest(".backdrop").addEventListener("mousedown", (e) => { if (e.target === e.currentTarget) resolve(false); });
    document.addEventListener("keydown", function onKey(e) {
      if (e.key !== "Escape") return;
      document.removeEventListener("keydown", onKey);
      resolve(false);
    });
  });
}

export async function render(el, ctx) {
  let [s, pv] = await Promise.all([get("/settings"), get("/llm/providers")]);
  const admin = can("admin");
  setHTML(el, html`
    <div class="page-head"><div><h1>Settings</h1><p class="muted">How much the agents may do on their own, the guardrails they work within, which models they use, and vulnerability deadlines.</p></div></div>
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
          <p class="faint" style="font-size:12.5px">Whether scheduled and agent-started scans wait for approval is an agent guardrail (below).</p></div>
      </section>
      <section class="stack">
        <div class="card"><header><h2>AI model</h2>${s.llm.available ? badge("Claude connected", "ok") : badge("rules mode", "warn")}</header>
          ${field("Default model for all agents", html`<input name="model" list="model-list" value="${s.model}">
            <datalist id="model-list"><option value="claude-opus-5-5"><option value="claude-sonnet-5-5"><option value="claude-haiku-5-5"><option value="claude-fable-5-1"></datalist>`,
            "Individual agents can override this on the Agents page.")}
          ${s.llm.available ? "" : html`<div class="notice">${icon("bot")}<div class="muted">No Claude credentials found. Set <code>ANTHROPIC_API_KEY</code> (or run <code>ant auth login</code>)
            and restart the hub. Without it the agents use deterministic rules and templates, or a local model provider.</div></div>`}
          ${s.llm.last_error ? html`<p style="color:var(--bad);margin-top:8px;font-size:12.5px">Last error: ${s.llm.last_error}</p>` : ""}</div>
        <div class="card" data-min-role="admin"><header><h2>Users &amp; access</h2>${icon("users")}</header>
          <p class="muted" style="margin-bottom:10px">Accounts, roles and API tokens for scripts and integrations; single sign-on below.</p>
          <div class="row"><a class="btn" href="#/users">${icon("arrow")}Manage users</a><a class="btn" href="#/settings/sso" data-act="to-sso">${icon("shield")}Sign-in &amp; SSO</a></div></div>
        <div class="card"><header><h2>About</h2></header><dl class="kv"><dt>Version</dt><dd>${s.version}</dd><dt>Data directory</dt><dd class="mono">${s.data_dir}</dd>
          <dt>API docs</dt><dd><a href="/api/docs" target="_blank" rel="noopener">/api/docs</a></dd></dl></div>
        <div data-min-role="admin"><button class="btn primary">${icon("check")}Save settings</button></div>
      </section>
    </form>
    <div class="grid split" style="margin-top:16px">
      <section class="card" id="guardrails-card"></section>
      <section class="card" id="providers-card"></section>
    </div>
    ${admin ? html`<section class="card" id="sso-card" style="margin-top:16px"><div class="empty faint">Loading the sign-in settings...</div></section>` : ""}`);
  const guardEl = el.querySelector("#guardrails-card");
  const provEl = el.querySelector("#providers-card");
  const ssoEl = el.querySelector("#sso-card");
  const drawGuards = () => setHTML(guardEl, guardrailsView(s.guardrail_catalog || [], admin));
  const drawProviders = () => setHTML(provEl, providersView(pv));
  drawGuards();
  drawProviders();
  if (ssoEl) {
    mountSso(ssoEl).catch((err) => setHTML(ssoEl, emptyState("alert", "Sign-in settings unavailable", err.message)));
    if (ctx.params[0] === "sso") setTimeout(() => ssoEl.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
  }

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
      s = await patch("/settings", { autonomy: data.get("autonomy"), model: String(data.get("model") || "").trim() || null, vuln_sla_days: sla });
      toast("Settings saved", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
  });

  async function setGuardrail(key, value) {
    const g = s.guardrail_catalog.find((x) => x.key === key);
    if (!g || value === g.value) return;
    if (relaxes(g, value) && !(await confirmRelax(g, value))) return drawGuards();
    if (value === false && DISRUPTS[key] && !(await confirmDialog(`Switch off: ${g.title}?`, DISRUPTS[key], "Switch off"))) return drawGuards();
    try {
      s = await patch("/settings/guardrails", { [key]: value });
      const now = s.guardrail_catalog.find((x) => x.key === key);
      toast(`${g.title}: ${g.kind === "bool" ? (value ? "on" : "off") : value}`, now?.relaxed ? "warn" : "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
    if (el.isConnected) drawGuards();
  }

  const loadProviders = async () => {
    pv = await get("/llm/providers");
    if (el.isConnected) drawProviders();
  };

  async function testProvider(id, btn) {
    if (btn) { btn.disabled = true; btn.textContent = "Testing..."; }
    try {
      const r = await post(`/llm/providers/${encodeURIComponent(id)}/test`);
      toast(`${r.provider?.name || id}: ${r.detail}`, r.ok ? "ok" : "bad");
    } catch (err) {
      toast(err.message, "bad");
    }
    await loadProviders();
  }

  function providerForm(p, preset) {
    const models = [...new Set([...(preset?.suggested_models || []), ...(p?.models || [])])];
    const needsKey = Boolean(preset?.requires_key) && !p?.api_key_set;
    modal({
      title: p ? `Edit ${p.name}` : preset ? `Add ${preset.name}` : "Add a local model provider",
      wide: true,
      minRole: "admin",
      submit: p ? "Save" : "Add and test",
      body: html`<p class="muted" style="margin-bottom:12px">${preset ? preset.note : "A model server with an OpenAI-compatible API."} The hub calls <code>{base URL}/chat/completions</code>
          with tool definitions and lists models from <code>{base URL}/models</code>.</p>
        <div class="form-grid">
          ${field("Name", html`<input name="name" required maxlength="80" value="${p?.name || preset?.name || ""}" placeholder="e.g. Ollama on gpu-01">`)}
          ${field("Default model", html`<input name="default_model" list="prov-models" maxlength="200" value="${p?.default_model || preset?.default_model || ""}" placeholder="e.g. llama3.1:8b">
            <datalist id="prov-models">${models.map((m) => html`<option value="${m}">`)}</datalist>`, "Test the provider to list the models this key can call.")}
        </div>
        ${field("Base URL", html`<input name="base_url" required maxlength="500" class="mono" value="${p?.base_url || preset?.base_url || pv.default_base_url}">`, preset ? preset.vendor : SERVERS)}
        ${field(needsKey ? "API key" : "API key (optional)", html`<input name="api_key" type="password" autocomplete="new-password" maxlength="4096" ${needsKey ? "required" : ""}
            placeholder="${p?.api_key_set ? "Stored - leave empty to keep it" : needsKey ? "Required" : "Most local servers need none"}">`,
          "Stored encrypted and only ever sent to this base URL's address; it is never shown again. Changing the address requires entering it again.")}
        ${p?.api_key_set ? html`<label class="check" style="margin-bottom:12px"><input type="checkbox" name="clear_api_key"><span>Remove the stored API key</span></label>` : ""}
        <div class="form-grid">
          ${field("Timeout (seconds)", html`<input type="number" name="timeout" min="5" max="3600" step="1" value="${p?.timeout ?? 300}">`)}
          <label class="check" style="align-self:center"><input type="checkbox" name="tools" ${(p ? p.tools : preset ? preset.tools : true) ? "checked" : ""}>
            <span>Send tool definitions<span class="faint" style="display:block;font-size:12px">Turn off for models without tool calling.</span></span></label>
        </div>`,
      async onSubmit(data) {
        const timeout = Number(data.get("timeout"));
        if (!Number.isFinite(timeout) || timeout < 5 || timeout > 3600) {
          toast("The timeout is 5 to 3600 seconds", "bad");
          return true;
        }
        const body = {
          name: String(data.get("name") || "").trim(), base_url: String(data.get("base_url") || "").trim(),
          default_model: String(data.get("default_model") || "").trim(), tools: data.get("tools") === "on", timeout,
        };
        if (!p && preset) body.preset = preset.id;
        const key = String(data.get("api_key") || "");
        if (key) body.api_key = key;
        if (data.get("clear_api_key") === "on") body.clear_api_key = true;
        if (!body.name || !body.base_url) {
          toast("Give the provider a name and a base URL", "bad");
          return true;
        }
        if (needsKey && !key) {
          toast(`${preset.name} needs an API key`, "bad");
          return true;
        }
        const saved = p ? await patch(`/llm/providers/${encodeURIComponent(p.id)}`, body) : await post("/llm/providers", body);
        toast(`${saved.name} ${p ? "saved" : "added"}`, "ok");
        if (p) await loadProviders();
        else testProvider(saved.id);
      },
    });
  }

  actions(el, {
    guard(d) {
      const g = s.guardrail_catalog.find((x) => x.key === d.key);
      if (g && admin) setGuardrail(d.key, !g.value);
    },
    "guard-num"(d) {
      const g = s.guardrail_catalog.find((x) => x.key === d.key);
      const value = Number(el.querySelector(`[data-guard-num="${CSS.escape(d.key)}"]`)?.value);
      if (!g || !admin) return;
      if (!Number.isInteger(value) || value < g.min || value > g.max) {
        toast(`${g.title} is a whole number from ${g.min} to ${g.max}`, "bad");
        return;
      }
      setGuardrail(d.key, value);
    },
    "prov-add"() { providerForm(null, null); },
    "prov-preset"(d) {
      const preset = (pv.presets || []).find((x) => x.id === d.id);
      if (preset && !hosted(pv, preset.id)) providerForm(null, preset);
    },
    "prov-edit"(d) {
      const p = pv.providers.find((x) => x.id === d.id);
      if (p) providerForm(p);
    },
    "prov-test"(d, btn) { testProvider(d.id, btn); },
    "to-sso"() {
      history.replaceState(null, "", "#/settings/sso");
      ssoEl?.scrollIntoView({ behavior: "smooth", block: "start" });
    },
    async "prov-remove"(d) {
      const p = pv.providers.find((x) => x.id === d.id);
      if (!p || !(await confirmDialog(`Remove ${p.name}?`, "Agents can no longer run on it. Providers still used by agents cannot be removed.", "Remove"))) return;
      try {
        await del(`/llm/providers/${encodeURIComponent(p.id)}`);
        toast(`${p.name} removed`, "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
      await loadProviders();
    },
  });
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.dataset?.guardNum) {
      e.preventDefault();
      el.querySelector(`[data-act="guard-num"][data-key="${CSS.escape(e.target.dataset.guardNum)}"]`)?.click();
    }
  });
  ctx.live(["llm_provider"], loadProviders, 400);
}
