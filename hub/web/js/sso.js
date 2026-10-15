// Single sign-on through the suite's identity providers: the Identity card, the provider picker, provider settings,
// running a provider registration and Atrium's own sign-in client. Used by the Integration hub, tool pages and Approvals.
import { get, patch, post, put } from "./api.js";
import { actions, badge, can, confirmDialog, copyText, emptyState, field, html, icon, modal, options, toast } from "./ui.js";

export const STATUS = {
  connected: ["connected", "ok"],
  pending: ["awaiting approval", "warn"],
  not_connected: ["not connected", "warn"],
  needs_choice: ["choose a provider", "warn"],
  no_provider: ["no provider", ""],
};
const STRATEGY = { sso_connect: "native connection", sso_code: "code patch (AI model)", sso_proxy: "SSO proxy" };
const SETTING = {
  realm: ["Realm", "Keycloak realm the clients are registered in. Default: hub."],
  slug: ["Application slug", "authentik application of Atrium's own sign-in (its issuer is .../application/o/<slug>/). Default: atrium. Each tool gets its own application."],
  base_url: ["Public URL", "The address browsers and tools reach the provider at. Default: the URL in its manifest."],
};

export const statusBadge = (status) => badge(...(STATUS[status] || [status, ""]));
export const strategyBadge = (strategy) => (strategy ? html`<span class="badge accent">${icon("wrench")}${STRATEGY[strategy] || strategy}</span>` : "");
export const loadIdentity = () => get("/identity-providers");
const providerName = (data, id) => data.providers.find((p) => p.tool_id === id)?.name || id;

/** Picker: which identity provider a tool signs in through. Replaces a pending SSO patch for another provider. */
export function openProviderPicker({ toolId, toolName, data, current, done }) {
  const selected = current || data.default || data.providers[0]?.tool_id;
  const m = modal({
    title: `Single sign-on for ${toolName}`,
    submit: "Connect",
    minRole: "operator",
    body: html`<p class="muted" style="margin-bottom:12px">The Patch Agent configures ${toolName} for the provider you choose and registers it there
        as a client. A patch waiting for approval for another provider is replaced.</p>
      <div class="stack" style="gap:8px">${data.providers.map((p) => html`<label class="radio-card">
        <input type="radio" name="provider" value="${p.tool_id}" ${p.tool_id === selected ? "checked" : ""}>
        <div style="min-width:0"><div class="row" style="gap:6px"><b>${p.name}</b>${badge(p.label, "info")}
          ${p.protocols.map((x) => badge(x.toUpperCase()))}${p.is_default ? badge("suite default", "accent") : ""}</div>
          <p class="faint mono" style="font-size:12px;overflow-wrap:anywhere;margin-top:4px">${p.issuer}</p></div></label>`)}</div>`,
    async onSubmit(form) {
      const provider = form.get("provider");
      if (!provider) throw new Error("Choose an identity provider");
      const r = await post(`/tools/${encodeURIComponent(toolId)}/sso`, { provider });
      const name = providerName(data, provider);
      if (r.patches.length) toast(`${toolName} -> ${name}: patch proposed${r.superseded.length ? ", the previous one was superseded" : ""}. See Approvals.`, "ok");
      else if (r.pending) toast(`A patch for ${name} is already waiting for approval`, "info");
      else if (r.skipped?.length) toast(`${toolName} -> ${name}: not proposed - ${r.skipped.map((s) => s.reason).join(" ")}`, "warn");
      else toast(`${toolName} signs in through ${name}`, "ok");
      done?.(r);
    },
  });
  return m;
}

/** Ask the Operator Agent to run the provider registration script of the tool's applied SSO patch. */
export async function runRegistration(toolId, toolName, providerLabel = "the identity provider") {
  if (!(await confirmDialog("Run provider registration", `Register ${toolName} as a client at ${providerLabel}? The Operator Agent runs the
      registration script from the hub's adapter folder; the command policy applies.`, "Run"))) return;
  try {
    report(await post(`/tools/${encodeURIComponent(toolId)}/sso/register`));
  } catch (err) {
    toast(err.message, "bad");
  }
}

function report(r) {
  if (r.status === "pending_approval") return toast("Waiting for approval (Approvals)", "warn");
  if (r.status === "denied") return toast(r.reason, "bad");
  const tail = (r.output || "").trim().split("\n").slice(-2).join(" ");
  toast(r.exit_code === 0 ? `Registered. ${tail}` : `Registration failed (exit ${r.exit_code}): ${tail}`, r.exit_code === 0 ? "ok" : "bad");
}

/** Admin: per-provider settings (realm, application slug, public URL). */
export function openProviderSettings(p, done) {
  modal({
    title: `${p.name} settings`,
    minRole: "admin",
    body: html`${p.setting_keys.map((key) => field(SETTING[key][0], html`<input name="${key}" value="${p.settings[key] || ""}"
        placeholder="${key === "realm" ? "hub" : key === "slug" ? "atrium" : p.base_url}" autocomplete="off" spellcheck="false">`, SETTING[key][1]))}
      <p class="faint" style="font-size:12.5px">Patches proposed after the change use the new values. Re-propose the SSO patches of tools that were
        already connected so their configuration follows.</p>`,
    async onSubmit(form) {
      const body = Object.fromEntries(p.setting_keys.map((key) => [key, String(form.get(key) || "").trim()]));
      await patch(`/identity-providers/${encodeURIComponent(p.tool_id)}`, body);
      toast(`${p.name} saved - the suite was re-scored`, "ok");
      done?.();
    },
  });
}

/** Admin: generate the client Atrium itself signs in with at a provider, and show the values. */
export async function openAtriumClient(p) {
  let c;
  try {
    c = await post(`/identity-providers/${encodeURIComponent(p.tool_id)}/atrium`, {});
  } catch (err) {
    return toast(err.message, "bad");
  }
  const m = modal({
    title: `Use ${p.name} for Atrium sign-in`,
    wide: true,
    submit: null,
    cancel: "Close",
    body: html`<p class="muted" style="margin-bottom:12px">The client for Atrium is ready in <code>${c.location}</code>. Its secret is only in
        <code>${c.secret_file}</code> on this machine; it is never shown here.</p>
      <dl class="kv" style="margin-bottom:14px"><dt>Issuer</dt><dd class="mono">${c.issuer}</dd><dt>Client ID</dt><dd class="mono">${c.client_id}</dd>
        <dt>Redirect URI</dt><dd class="mono">${c.redirect_uri}</dd><dt>Roles</dt><dd>groups <code>${c.admin_values.join(", ")}</code> (admin),
        <code>${c.operator_values.join(", ")}</code> (operator), everyone else viewer</dd></dl>
      ${field("Settings for Atrium's .env", html`<pre class="code wrap" data-env>${c.env}</pre>`)}
      <ol class="muted" style="padding-left:18px;margin:0 0 12px;font-size:13px">${c.steps.map((s) => html`<li>${s}</li>`)}</ol>
      <div class="row"><button type="button" class="btn" data-act="copy">${icon("copy")}Copy settings</button>
        ${c.register_command ? html`<button type="button" class="btn primary" data-act="register">${icon("play")}Register at ${p.name}</button>` : ""}</div>`,
  });
  actions(m.el, {
    copy: () => copyText(c.env),
    async register(_, btn) {
      btn.disabled = true;
      try {
        report((await post(`/identity-providers/${encodeURIComponent(p.tool_id)}/atrium`, { run_registration: true })).registration);
      } catch (err) {
        toast(err.message, "bad");
      } finally {
        btn.disabled = false;
      }
    },
  });
}

function toolActions(t, data) {
  if (!data.providers.length) return "";
  const pick = t.status === "needs_choice" ? "Choose provider" : t.status === "connected" || t.pending ? "Change provider" : "Connect";
  return html`<div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end" data-min-role="operator">
    ${t.applied?.can_register ? html`<button class="btn sm" data-act="register" data-id="${t.tool_id}" title="Run the provider registration script">${icon("play")}Register</button>` : ""}
    <button class="btn sm ${t.status === "not_connected" || t.status === "needs_choice" ? "primary" : ""}" data-act="connect" data-id="${t.tool_id}">${icon("link")}${pick}</button></div>`;
}

/** The Integration hub's Identity card. `refresh` re-renders the page after a change. */
export function identityCard(data) {
  const admin = can("admin");
  const providers = data.providers;
  const body = !providers.length
    ? emptyState("shield", "No identity provider in the suite", "Import Keycloak, authentik, Zitadel or Authelia - or any tool whose manifest provides auth.oidc or auth.saml - and the Patch Agent connects your tools to it natively.")
    : html`
      ${data.needs_choice ? html`<div class="notice warn" style="margin-bottom:12px">${icon("alert")}<div><b>${providers.length} identity providers.</b>
        <span class="muted">Pick a suite default${admin ? "" : " (administrators)"}, or choose a provider per tool below.</span></div></div>` : ""}
      <div class="grid cols-3" style="margin-bottom:14px">${providers.map((p) => html`<div class="idp">
        <div class="row" style="gap:6px"><b>${p.name}</b>${badge(p.label, "info")}${p.protocols.map((x) => badge(x.toUpperCase()))}
          ${p.is_default ? badge("default", "accent") : ""}${p.configured ? "" : badge("URL unknown", "warn")}</div>
        <div class="faint mono idp-url" title="Issuer">${p.issuer}</div>
        <div class="faint" style="font-size:12px">${p.connected} tool${p.connected === 1 ? "" : "s"} connected</div>
        <div class="row" style="gap:6px" data-min-role="admin">
          <button class="btn sm" data-act="settings" data-id="${p.tool_id}">${icon("sliders")}Settings</button>
          ${p.protocols.includes("oidc") ? html`<button class="btn sm" data-act="atrium" data-id="${p.tool_id}" title="Generate the client Atrium signs in with">${icon("key")}Atrium sign-in</button>` : ""}</div>
      </div>`)}</div>
      ${data.tools.length ? html`<div class="table-wrap"><table class="table"><thead><tr><th>Tool</th><th>Single sign-on</th><th>Provider</th><th>How</th><th></th></tr></thead><tbody>
        ${data.tools.map((t) => html`<tr>
          <td><a href="#/tools/${t.tool_id}"><b>${t.name}</b></a></td>
          <td>${statusBadge(t.status)}</td>
          <td>${t.connected_to ? providerName(data, t.connected_to) : t.pending?.provider ? providerName(data, t.pending.provider) : t.selected ? providerName(data, t.selected) : html`<span class="faint">-</span>`}
            ${t.choice ? html`<span class="faint" style="font-size:12px"> (chosen)</span>` : ""}</td>
          <td>${t.status === "connected" ? html`<span class="faint">${t.sso.toUpperCase()}</span>` : strategyBadge(t.pending?.strategy || t.strategy)}</td>
          <td>${toolActions(t, data)}</td></tr>`)}</tbody></table></div>`
        : html`<p class="muted">No other tools yet.</p>`}`;
  return html`<section class="card" style="margin-bottom:16px"><header><h2>Identity</h2>
      ${providers.length > 1 ? html`<label class="row" style="gap:8px;font-size:13px" data-min-role="admin"><span class="muted">Suite default</span>
        <select class="input-sm" data-default aria-label="Default identity provider">${options([["", "None - choose per tool"], ...providers.map((p) => [p.tool_id, p.name])], data.default || "")}</select></label>`
        : html`<span class="faint" style="font-size:12.5px">Tools sign in once, through the suite's identity provider.</span>`}</header>${body}</section>`;
}

/** Wire the Identity card inside `root`; `refresh` reloads and re-renders. */
export function wireIdentity(root, getData, refresh) {
  actions(root, {
    connect: (d) => {
      const data = getData();
      const t = data.tools.find((x) => x.tool_id === d.id);
      openProviderPicker({ toolId: d.id, toolName: t?.name || d.id, data, current: t?.choice || t?.pending?.provider || t?.connected_to || t?.selected, done: refresh });
    },
    register: (d) => {
      const data = getData();
      const t = data.tools.find((x) => x.tool_id === d.id);
      runRegistration(d.id, t?.name || d.id, providerName(data, t?.applied?.provider)).then(refresh);
    },
    settings: (d) => openProviderSettings(getData().providers.find((p) => p.tool_id === d.id), refresh),
    atrium: (d) => openAtriumClient(getData().providers.find((p) => p.tool_id === d.id)),
  });
  root.addEventListener("change", async (e) => {
    if (!e.target.matches("[data-default]")) return;
    try {
      await put("/identity-providers/default", { tool_id: e.target.value || null });
      toast(e.target.value ? "Default identity provider saved - single sign-on is re-planned" : "Default cleared", "ok");
    } catch (err) {
      toast(err.message, "bad");
    }
    refresh();
  });
}
