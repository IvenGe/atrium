import { del, get, patch, post } from "../api.js";
import { homeButton, keepHomeButton, onHomeAdd } from "../dashboard/addhome.js";
import { mount as mountDefaults } from "../settings/ai-defaults.js";
import { mount as mountProviders } from "../settings/ai-providers.js";
import { mount as mountUsage } from "../settings/ai-usage.js";
import { mountSso } from "../signin.js";
import { actions, badge, can, confirmDialog, dateTime, emptyState, field, html, icon, modal, options, setHTML, timeIn, toast } from "../ui.js";

const LEVELS = [
  ["manual", "Manual", "Every agent command and patch waits for your approval."],
  ["assisted", "Assisted (recommended)", "Agents run read-only commands on their own; anything that changes state waits for approval."],
  ["autonomous", "Autonomous", "Agents act without asking, except for blocked commands. The GRC Supervisor flags this as a failing control."],
];
const SLA = ["critical", "high", "medium", "low"];
const GUARD_GROUPS = {
  teams: "Agent teams", agents: "Agent actions", commands: "Commands", scans: "Vulnerability scans",
  extensions: "Extensions", self_patching: "Self-patching (changes to Atrium's own code)", models: "AI models and spending",
  subsidiaries: "Subsidiaries (agent teams inside tools)",
};
// Switches whose protective side is not their default (safe_value in hub/guardrails.py): "allow_*" switches are on by
// default but off is safe; the general second-person rule is off by default but on is safe. The catalog carries it as
// `safe`; this map only covers an older hub without that field.
const SAFE_SIDE = { allow_extensions: false, allow_self_patching: false, approvals_need_second_person: true };
const safeSide = (g) => g.safe ?? (g.key in SAFE_SIDE ? SAFE_SIDE[g.key] : g.default);
const DAYS = [["mon", "Mon"], ["tue", "Tue"], ["wed", "Wed"], ["thu", "Thu"], ["fri", "Fri"], ["sat", "Sat"], ["sun", "Sun"]];
const NET_SETTINGS = [
  ["backup_retention", "Backups kept per device", "The oldest are deleted beyond this number."],
  ["backup_interval_hours", "Scheduled backup every (hours)", "0 = only manual and pre-change backups."],
  ["history_limit", "Snapshot revisions kept per device", "For the History tab and its diffs."],
  ["stale_after_minutes", "Snapshot fresh for (minutes)", "Older snapshots must be read again before a change is proposed."],
];

/** Whether setting guardrail `g` to `value` loosens it: a switch leaving its protective side, or a higher limit. */
function relaxes(g, value) {
  return g.kind === "bool" ? g.value === safeSide(g) && value !== safeSide(g) : Number(value) > Number(g.value);
}

/** What switching a guardrail off disrupts right away (asked before it happens, although it is the safe side). */
const DISRUPTS = {
  allow_extensions: "Every enabled pack becomes inactive at once: its apps leave the sidebar, its data flows stop running, and its SSO recipes, compliance rules and team templates no longer apply. Packs and records are kept, and switching it back on restores them. Connector mappings already merged into tools' connections stay until a pack is disabled.",
  allow_self_patching: "The Patch Agent no longer proposes changes to Atrium's own code. Self-patches already waiting in Approvals stay there.",
  allow_cloud_llm: "Agents that use Claude, OpenAI or another cloud provider switch at once to a local model or to rules. Running conversations continue on the new model; a tool round already sent to a cloud provider finishes, and no further round goes there.",
  allow_subsidiaries: "This is the subsidiaries' kill switch: every agent team inside a tool is paused at once, its pending approvals are withdrawn and its sidecar gets no answers, tickets or grants. Bridges refuse every call once their last ticket expires. An administrator resumes each subsidiary after switching it back on.",
  device_changes: "This is the kill switch: approved and scheduled device changes that were not applied yet are blocked at once and never applied (they must be proposed again). A change being verified right now completes or rolls back as usual. Atrium keeps reading the devices.",
};

/** The guardrail rows of `list` (a switch with the number it requires nested under it). */
function guardRows(catalog, list, admin) {
  const byKey = Object.fromEntries(catalog.map((g) => [g.key, g]));
  const nested = new Set(catalog.map((g) => g.requires).filter(Boolean));
  // a number on its own row is named by the row's title already: its label is for screen readers only
  const number = (n, active, own = false) => html`<div class="guard-num ${active ? "" : "inactive"}">
    <label for="guard-${n.key}" class="${own ? "sr-only" : ""}">${n.title}</label>
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
        ${g.kind === "int" ? number(g, true, true) : num ? number(num, Boolean(g.value)) : ""}</div></div>`;
  };
  return list.filter((g) => !nested.has(g.key)).map(row);
}

function guardrailsView(catalog, admin) {
  const agentGuards = catalog.filter((g) => g.group !== "network"); // device changes have their own card
  const groups = [...new Set(agentGuards.map((g) => g.group))];
  const relaxed = agentGuards.filter((g) => g.relaxed).length;
  return html`<header><h2>Agent guardrails</h2><div class="card-actions">${relaxed ? badge(`${relaxed} relaxed`, "warn") : badge("all protections on", "ok")}
      ${homeButton("safety_settings")}</div></header>
    <p class="muted" style="margin-bottom:12px">Safety switches for the AI agents. Every change is logged with your name; relaxing one is logged as a warning
      and shows up in the compliance controls. Device changes are under Network changes.</p>
    ${groups.map((group) => html`<div class="guard-group"><h3>${GUARD_GROUPS[group] || group}</h3>
      ${guardRows(catalog, agentGuards.filter((g) => g.group === group), admin)}</div>`)}`;
}

/** Settings > Network changes: the device-change guardrails, maintenance windows and the backup / snapshot settings. */
function networkView(catalog, windows, net, devices, admin) {
  const guards = catalog.filter((g) => g.group === "network");
  const on = guards.find((g) => g.key === "device_changes")?.value;
  const relaxed = guards.filter((g) => g.relaxed && g.key !== "device_changes").length;
  const names = Object.fromEntries(devices.map((d) => [d.tool_id, d.name]));
  return html`<header><h2>Network changes</h2><div class="row card-actions" style="gap:6px">${on ? badge("device changes on", "warn") : badge("read-only: changes off", "ok")}
      ${relaxed ? badge(`${relaxed} relaxed`, "warn") : ""}${homeButton("network_overview")}</div></header>
    <p class="muted" style="margin-bottom:12px">Whether Atrium may change firewalls and network devices (the <a href="#/network">Network app</a>), and under which rules.
      Every change is a proposal; with the defaults an administrator other than the proposer approves it, a backup is taken first, and it is applied in a
      maintenance window with the device's automatic rollback. Control HB-CM-3 reflects these switches.</p>
    <div class="guard-group">${guardRows(catalog, guards, admin)}</div>
    <div class="guard-group"><h3>Maintenance windows</h3>
      <p class="muted" style="font-size:12.5px;margin-bottom:10px">${windows.required
        ? "Approved changes wait (status scheduled) until a window that covers their device opens; an administrator can still apply one at once as an emergency."
        : "The maintenance-window guardrail is off: approved changes are applied at once. Windows are kept for when it is switched back on."}</p>
      ${windows.windows.length ? html`<div class="mw-list">${windows.windows.map((w) => html`<div class="mw ${w.enabled ? "" : "off"}">${icon("calendar")}
          <div><div class="row" style="gap:6px"><b>${w.name}</b>${w.open_now ? badge("open now", "ok") : ""}${w.enabled ? "" : badge("disabled")}</div>
            <div class="faint" style="font-size:12.5px">${w.summary}</div>
            <div class="faint" style="font-size:12px">${w.devices?.length ? w.devices.map((d) => names[d] || d).join(", ") : "All devices"}
              ${w.next ? html` - next ${dateTime(w.next.start)} to ${dateTime(w.next.end)} your time (${timeIn(w.next.start)})` : " - no upcoming opening"}</div></div>
          <span class="row" style="gap:4px" data-min-role="admin">
            <button type="button" class="icon-btn sm" data-act="mw-edit" data-id="${w.id}" title="Edit" aria-label="Edit ${w.name}">${icon("edit")}</button>
            <button type="button" class="icon-btn sm danger" data-act="mw-remove" data-id="${w.id}" title="Remove" aria-label="Remove ${w.name}">${icon("trash")}</button></span></div>`)}</div>`
        : html`<p class="${windows.required && on ? "warn-text" : "faint"}" style="font-size:12.5px">No maintenance windows yet${windows.required ? ": approved changes wait until one exists (or an administrator applies them as an emergency)" : ""}.</p>`}
      <button type="button" class="btn sm" data-act="mw-add" data-min-role="admin" style="margin-top:10px">${icon("plus")}Add window</button></div>
    <div class="guard-group"><h3>Backups and snapshots</h3>
      <div class="form-grid">${NET_SETTINGS.map(([key, label, hint]) => field(label, html`<input type="number" step="1" data-net="${key}" min="${net.bounds?.[key]?.[0] ?? ""}"
          max="${net.bounds?.[key]?.[1] ?? ""}" value="${net[key] ?? ""}" ${admin ? "" : "disabled"} aria-label="${label}">`, `${hint} ${net.bounds?.[key] ? `${net.bounds[key][0]}-${net.bounds[key][1]}.` : ""}`))}</div>
      <button type="button" class="btn sm" data-act="net-save" data-min-role="admin">${icon("check")}Save</button></div>`;
}

/** Add or edit a maintenance window (administrators). */
function windowForm(w, devices, done) {
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  let zones = [];
  try { zones = Intl.supportedValuesOf("timeZone"); } catch { /* older browsers: free text */ }
  const once = w?.recurrence === "once";
  const local = (iso) => (iso ? String(iso).slice(0, 16) : ""); // the wall time in the window's own time zone
  const m = modal({
    title: w ? `Edit ${w.name}` : "Add a maintenance window", wide: true, minRole: "admin", submit: w ? "Save" : "Add window",
    body: html`${field("Name", html`<input name="name" required maxlength="80" value="${w?.name || ""}" placeholder="e.g. Weekend nights">`)}
      <div class="form-grid">
        ${field("Repeats", html`<select name="recurrence">${options([["weekly", "Every week"], ["once", "Once"]], once ? "once" : "weekly")}</select>`)}
        ${field("Time zone", html`<input name="timezone" list="mw-zones" maxlength="64" value="${w?.timezone || zone}" spellcheck="false">
          <datalist id="mw-zones">${zones.map((z) => html`<option value="${z}">`)}</datalist>`, "IANA name, e.g. Europe/Brussels")}</div>
      <div data-weekly ${once ? "hidden" : ""}>
        <label class="faint" style="font-size:12.5px;font-weight:600">Days</label>
        <div class="mw-days">${DAYS.map(([v, label]) => html`<label class="check"><input type="checkbox" name="days" value="${v}" ${w?.days?.includes(v) ? "checked" : ""}>${label}</label>`)}</div>
        <div class="form-grid">${field("From", html`<input type="time" name="start_time" value="${w?.start_time || "22:00"}">`)}
          ${field("Until", html`<input type="time" name="end_time" value="${w?.end_time || "02:00"}">`, "An end at or before the start ends the next day.")}</div></div>
      <div data-once ${once ? "" : "hidden"}><div class="form-grid">
        ${field("Starts", html`<input type="datetime-local" name="start" value="${local(w?.start)}">`)}
        ${field("Ends", html`<input type="datetime-local" name="end" value="${local(w?.end)}">`, "In the window's time zone; at most 14 days.")}</div></div>
      <label class="faint" style="font-size:12.5px;font-weight:600">Devices</label>
      ${devices.length ? html`<div class="mw-devices">${devices.map((d) => html`<label class="check"><input type="checkbox" name="devices" value="${d.tool_id}"
          ${w?.devices?.includes(d.tool_id) ? "checked" : ""}><span>${d.name}</span></label>`)}</div>`
        : html`<p class="faint" style="font-size:12.5px;margin-bottom:12px">No network devices yet.</p>`}
      <p class="faint" style="font-size:12px;margin:-6px 0 12px">None ticked: the window covers every device, also ones connected later.</p>
      <label class="check"><input type="checkbox" name="enabled" ${w && !w.enabled ? "" : "checked"}><span>Enabled</span></label>`,
    async onSubmit(data) {
      const recurrence = data.get("recurrence");
      const body = {
        name: String(data.get("name") || "").trim(), recurrence, timezone: String(data.get("timezone") || "").trim() || "UTC",
        devices: data.getAll("devices"), enabled: data.get("enabled") === "on",
      };
      if (recurrence === "weekly") {
        Object.assign(body, { days: data.getAll("days"), start_time: data.get("start_time") || null, end_time: data.get("end_time") || null });
        if (!body.days.length) {
          toast("Tick at least one day", "bad");
          return true;
        }
      } else {
        Object.assign(body, { start: data.get("start") || null, end: data.get("end") || null });
        if (!body.start || !body.end) {
          toast("Give the start and the end", "bad");
          return true;
        }
      }
      if (w) await patch(`/network/maintenance-windows/${encodeURIComponent(w.id)}`, body);
      else await post("/network/maintenance-windows", body);
      toast(`Maintenance window ${w ? "saved" : "added"}`, "ok");
      done();
    },
  });
  m.el.querySelector('[name="recurrence"]').addEventListener("change", (e) => {
    m.el.querySelector("[data-weekly]").hidden = e.target.value !== "weekly";
    m.el.querySelector("[data-once]").hidden = e.target.value !== "once";
  });
}

/** Asks before a guardrail is relaxed, showing what that risks; resolves true to go ahead. */
function confirmRelax(g, value) {
  return new Promise((resolve) => {
    const verb = g.kind === "bool" ? (value ? "Switch on" : "Switch off") : "Raise";
    modal({
      title: g.kind === "bool" ? `${verb}: ${g.title}?` : `Raise ${g.title.toLowerCase()} to ${value}?`,
      submit: verb,
      body: html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div><b>Risk.</b> ${g.risk}</div></div>
        ${g.control ? html`<p style="font-size:13px;margin-bottom:8px">Compliance control <b>${g.control}</b> will no longer pass while this protection is relaxed.</p>` : ""}
        <p class="muted" style="font-size:12.5px">The change is logged with your name as a warning. You can restore the protection here at any time.</p>`,
      onSubmit: () => resolve(true),
      onClose: () => resolve(false), // Cancel, Esc or a click outside (settled already after a submit)
    });
  });
}

export async function render(el, ctx) {
  let s = await get("/settings");
  const net = { windows: { windows: [], required: true }, settings: {}, devices: [], error: null };
  const loadNetwork = async () => {
    try {
      const [windows, settings, devices] = await Promise.all([get("/network/maintenance-windows"), get("/network/settings"), get("/network/devices")]);
      Object.assign(net, { windows, settings, devices: devices.devices, error: null });
    } catch (err) {
      net.error = err.message;
    }
  };
  await loadNetwork();
  const admin = can("admin");
  setHTML(el, html`
    <div class="page-head"><div><h1>Settings</h1><p class="muted">How much the agents may do on their own, the guardrails they work within, which models they use, and vulnerability deadlines.</p></div></div>
    ${admin ? "" : html`<div class="notice" style="margin-bottom:16px">${icon("lock")}<div class="muted">Only administrators can change these settings.</div></div>`}
    <form id="settings-form" class="grid split">
      <section class="stack">
        <div class="card"><header><h2>Agent autonomy</h2><div class="card-actions">${homeButton("safety_settings")}</div></header>
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
        <div class="card" data-min-role="admin"><header><h2>Users &amp; access</h2>${icon("users")}</header>
          <p class="muted" style="margin-bottom:10px">Accounts, roles and API tokens for scripts and integrations; single sign-on below.</p>
          <div class="row"><a class="btn" href="#/users">${icon("arrow")}Manage users</a><a class="btn" href="#/settings/sso" data-act="to-sso">${icon("shield")}Sign-in &amp; SSO</a></div></div>
        <div class="card"><header><h2>About</h2></header><dl class="kv"><dt>Version</dt><dd>${s.version}</dd><dt>Data directory</dt><dd class="mono">${s.data_dir}</dd>
          <dt>API docs</dt><dd><a href="/api/docs" target="_blank" rel="noopener">/api/docs</a></dd></dl></div>
        <div data-min-role="admin"><button class="btn primary">${icon("check")}Save settings</button></div>
      </section>
    </form>
    <div class="grid ai-panels" style="margin-top:16px">
      <section class="card" id="providers-card"></section>
      <section class="card" id="defaults-card"></section>
    </div>
    <section class="card" id="usage-card" style="margin-top:16px"></section>
    <section class="card" id="guardrails-card" style="margin-top:16px"></section>
    <section class="card" id="network-card" style="margin-top:16px"></section>
    ${admin ? html`<section class="card" id="sso-card" style="margin-top:16px"><div class="empty faint">Loading the sign-in settings...</div></section>` : ""}`);
  const guardEl = el.querySelector("#guardrails-card");
  const provEl = el.querySelector("#providers-card");
  const defaultsEl = el.querySelector("#defaults-card");
  const ssoEl = el.querySelector("#sso-card");
  const drawGuards = () => setHTML(guardEl, guardrailsView(s.guardrail_catalog || [], admin));
  const netEl = el.querySelector("#network-card");
  const drawNetwork = () => setHTML(netEl, net.error ? emptyState("alert", "Network settings unavailable", net.error)
    : networkView(s.guardrail_catalog || [], net.windows, net.settings, net.devices, admin));
  drawGuards();
  mountProviders(provEl, ctx).catch((err) => setHTML(provEl, emptyState("alert", "AI providers unavailable", err.message)));
  mountDefaults(defaultsEl, ctx).catch((err) => setHTML(defaultsEl, emptyState("alert", "Model choice unavailable", err.message)));
  const usageEl = el.querySelector("#usage-card");
  mountUsage(usageEl, ctx).catch((err) => setHTML(usageEl, emptyState("alert", "AI usage unavailable", err.message)));
  // R4-DASH "Add to Home" in the AI panels' header slots (the panels redraw themselves on live events)
  const slots = [keepHomeButton(provEl, "ai_models"), keepHomeButton(defaultsEl, "ai_models"), keepHomeButton(usageEl, "llm_spend_today")];
  ctx.onLeave(() => slots.forEach((off) => off()));
  drawNetwork();
  if (ctx.params[0] === "ai") setTimeout(() => provEl.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
  if (ctx.params[0] === "network") setTimeout(() => netEl.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
  if (ctx.params[0] === "guardrails") setTimeout(() => el.querySelector("#guardrails-card")?.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
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
      s = await patch("/settings", { autonomy: data.get("autonomy"), vuln_sla_days: sla }); // models: AI providers
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
    if (g.group === "network") await loadNetwork(); // the windows' "required" follows its guardrail
    if (el.isConnected) { drawGuards(); drawNetwork(); }
  }
  const reloadNetwork = async () => {
    await loadNetwork();
    if (el.isConnected) drawNetwork();
  };

  actions(el, {
    "home-add"(_, btn) { onHomeAdd(btn); },
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
    "mw-add"() { windowForm(null, net.devices, reloadNetwork); },
    "mw-edit"(d) {
      const w = net.windows.windows.find((x) => x.id === d.id);
      if (w) windowForm(w, net.devices, reloadNetwork);
    },
    async "mw-remove"(d) {
      const w = net.windows.windows.find((x) => x.id === d.id);
      if (!w || !(await confirmDialog(`Remove the maintenance window ${w.name}?`, net.windows.required
        ? "Approved changes that wait for it are applied in another window that covers their device, or keep waiting." : "It is not used while the maintenance-window guardrail is off.", "Remove"))) return;
      try {
        await del(`/network/maintenance-windows/${encodeURIComponent(w.id)}`);
        toast(`${w.name} removed`, "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
      reloadNetwork();
    },
    async "net-save"() {
      if (!admin) return;
      const body = {};
      for (const [key, label] of NET_SETTINGS) {
        const value = Number(netEl.querySelector(`[data-net="${key}"]`)?.value);
        const [lo, hi] = net.settings.bounds?.[key] || [0, Infinity];
        if (!Number.isInteger(value) || value < lo || value > hi) {
          toast(`${label} is a whole number from ${lo} to ${hi}`, "bad");
          return;
        }
        if (value !== net.settings[key]) body[key] = value;
      }
      if (!Object.keys(body).length) return toast("Nothing changed", "info");
      try {
        await patch("/network/settings", body);
        toast("Network settings saved", "ok");
      } catch (err) {
        toast(err.message, "bad");
      }
      reloadNetwork();
    },
    "to-sso"() {
      history.replaceState(null, "", "#/settings/sso");
      ssoEl?.scrollIntoView({ behavior: "smooth", block: "start" });
    },
  });
  el.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && e.target.dataset?.guardNum) {
      e.preventDefault();
      el.querySelector(`[data-act="guard-num"][data-key="${CSS.escape(e.target.dataset.guardNum)}"]`)?.click();
    }
  });
  ctx.live(["maintenance_window", "network_settings"], reloadNetwork, 400);
}
