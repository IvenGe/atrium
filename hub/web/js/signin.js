// Settings > Sign-in & SSO (admin): Atrium's own OpenID Connect sign-in, managed here as well as through HUB_OIDC_*
// variables. A value set by the environment wins and is read-only here; the client secret is write-only (never shown).
import { del, get, post, put } from "./api.js";
import { actions, badge, confirmDialog, copyText, dateTime, field, html, icon, options, setHTML, timeAgo, toast } from "./ui.js";

const ROLES = [["viewer", "Viewer"], ["operator", "Operator"], ["admin", "Admin"]];
const list = (text) => [...new Set(String(text || "").split(",").map((v) => v.trim()).filter(Boolean))];

/** The form values shown for the saved (effective) settings; the secret field always starts empty. */
const fromView = (v) => ({
  provider_name: v.stored?.provider_name || "", issuer: v.values.issuer || "", client_id: v.values.client_id || "",
  scopes: v.values.scopes || "", role_claim: v.values.role_claim || "", admin_values: (v.values.admin_values || []).join(", "),
  operator_values: (v.values.operator_values || []).join(", "), default_role: v.values.default_role || "viewer",
  allow_http: Boolean(v.values.allow_http), client_secret: "", clear_client_secret: false, use_generated: false,
});

function initialChoice(v) {
  const imported = v.imported.find((i) => i.issuer && i.issuer === v.values.issuer);
  if (imported) return `imported:${imported.tool_id}`;
  if (v.stored?.preset) return `preset:${v.stored.preset}`;
  return v.values.issuer ? "preset:generic" : "";
}

function testView(t) {
  if (!t) return "";
  if (!t.ok) return html`<div class="notice bad" style="margin-top:12px">${icon("x")}<div style="min-width:0"><b>Test failed.</b> ${t.detail}
    <div class="faint" style="font-size:12px;margin-top:4px">Nothing was saved.</div></div></div>`;
  return html`<div class="notice ok" style="margin-top:12px">${icon("checkCircle")}<div style="min-width:0"><b>${t.detail}</b>
    <dl class="kv" style="margin-top:8px;font-size:12.5px"><dt>Sign-in endpoint</dt><dd class="mono">${t.authorization_endpoint}</dd>
      <dt>Token endpoint</dt><dd class="mono">${t.token_endpoint}</dd><dt>Signing keys</dt><dd>${t.signing_keys} at <span class="mono">${t.jwks_uri}</span></dd>
      <dt>PKCE (S256)</dt><dd>${t.pkce_s256 ? "advertised" : "not advertised"}</dd>
      ${t.scopes_supported ? html`<dt>Scopes offered</dt><dd>${t.scopes_supported.join(" ")}</dd>` : ""}</dl>
    ${t.notes?.length ? html`<ul style="margin:8px 0 0;padding-left:18px;font-size:12.5px">${t.notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
    <div class="faint" style="font-size:12px;margin-top:6px">Discovery and signing keys only - the client secret is checked at the first real sign-in. Nothing was saved.</div></div></div>`;
}

function cardView(v, choice, d, test) {
  const env = new Set(v.env);
  const envHint = (k) => html`${badge("environment", "info")} Set by <code>${v.env_vars[k]}</code> - read-only here.`;
  const text = (k, label, hint = "", placeholder = "", mono = false) => field(label,
    html`<input name="${k}" value="${d[k]}" placeholder="${placeholder}" class="${mono ? "mono" : ""}" autocomplete="off" spellcheck="false" ${env.has(k) ? "disabled" : ""}>`,
    env.has(k) ? envHint(k) : hint);
  const chosen = choice.startsWith("imported:") ? v.imported.find((i) => `imported:${i.tool_id}` === choice) : null;
  const preset = v.presets.find((p) => `preset:${p.id}` === choice || p.id === chosen?.preset);
  const notes = [
    ...(chosen ? [chosen.generated_secret ? `Atrium's sign-in client at ${chosen.name} is ready; its secret can be used without being shown.`
      : `Generate Atrium's sign-in client at ${chosen.name} first: Integration hub > Identity > Atrium sign-in.`] : []),
    ...(preset?.notes || []),
  ];
  const secretEnv = env.has("client_secret");
  return html`<header><h2>Sign-in &amp; SSO</h2>${v.enabled ? badge("on", "ok") : badge("off")}</header>
    <p class="muted" style="margin-bottom:12px">Let people sign in to Atrium with your identity provider over OpenID Connect. Their role comes from a claim:
      admin values make admins, operator values operators, everyone else gets the default role. Local accounts keep working.</p>
    ${v.enabled ? html`<div class="notice ok" style="margin-bottom:10px">${icon("shield")}<div>Single sign-on is on: the sign-in screen shows <b>${v.label}</b>.</div></div>`
      : html`<div class="notice" style="margin-bottom:10px">${icon("shield")}<div class="muted">Single sign-on is off. Pick your provider, fill in the issuer, client ID and secret, test, then save.</div></div>`}
    ${v.secret_error ? html`<div class="notice warn" style="margin-bottom:10px">${icon("alert")}<div>${v.secret_error}</div></div>` : ""}
    ${v.env.length ? html`<div class="notice" style="margin-bottom:10px">${icon("lock")}<div class="muted">Set by environment variables, which win over this page:
      ${v.env.map((k) => html`<code>${v.env_vars[k]}</code> `)}- change them in the hub's environment and restart.</div></div>` : ""}
    <dl class="kv" style="margin-bottom:14px"><dt>Redirect URI</dt><dd><span class="mono">${v.redirect_uri}</span>
        <button type="button" class="icon-btn sm" data-act="sso-copy" title="Copy" aria-label="Copy the redirect URI" style="display:inline-grid;vertical-align:middle">${icon("copy")}</button>
        <div class="faint" style="font-size:12px">Register it at the provider as the sign-in redirect URI.</div></dd>
      ${v.stored ? html`<dt>Saved</dt><dd title="${dateTime(v.stored.updated_at)}">by ${v.stored.updated_by} ${timeAgo(v.stored.updated_at)}</dd>` : ""}</dl>
    <form data-sso-form novalidate>
      <h3 class="sso-step">Provider</h3>
      <div class="preset-grid" role="radiogroup" aria-label="Identity provider">
        ${v.presets.map((p) => html`<label class="radio-card preset"><input type="radio" name="sso_choice" value="preset:${p.id}" ${choice === `preset:${p.id}` ? "checked" : ""}>
          <div style="min-width:0"><b>${p.name}</b><div class="faint mono preset-url">${p.issuer || "any issuer with discovery"}</div></div></label>`)}
        ${v.imported.map((i) => html`<label class="radio-card preset"><input type="radio" name="sso_choice" value="imported:${i.tool_id}" ${choice === `imported:${i.tool_id}` ? "checked" : ""}>
          <div style="min-width:0"><div class="row" style="gap:6px"><b>${i.name}</b>${badge("in the suite", "accent")}</div><div class="faint mono preset-url">${i.issuer}</div>
            ${i.generated_secret ? html`<div class="faint" style="font-size:11.5px">Atrium's client is ready</div>` : ""}</div></label>`)}
      </div>
      ${notes.length ? html`<ul class="sso-notes">${notes.map((n) => html`<li>${n}</li>`)}</ul>` : ""}
      <h3 class="sso-step">Connection</h3>
      <div class="form-grid">
        ${field("Provider name", html`<input name="provider_name" value="${d.provider_name}" maxlength="40" placeholder="${preset?.provider_name || "SSO"}" autocomplete="off">`,
          env.has("label") ? envHint("label") : html`The button says "Sign in with ${d.provider_name || preset?.provider_name || "SSO"}".`)}
        ${text("client_id", "Client ID", "From the application registered at the provider.", "", true)}
      </div>
      ${text("issuer", "Issuer URL", "Its /.well-known/openid-configuration must be reachable from this hub. https only (or localhost).", preset?.issuer || "https://idp.example.com", true)}
      ${field("Client secret", secretEnv ? html`<input type="password" disabled placeholder="Set by the environment" aria-label="Client secret">`
        : html`<input name="client_secret" type="password" autocomplete="new-password" maxlength="4096" spellcheck="false"
            placeholder="${v.client_secret_set ? "Stored - leave empty to keep it" : "Paste the client secret"}">`,
        secretEnv ? envHint("client_secret") : "Stored encrypted and only sent to the issuer it was entered for; never shown again. Changing the issuer means entering it again.")}
      ${!secretEnv && v.client_secret_set && v.source.client_secret === "database" ? html`<label class="check" style="margin:-4px 0 10px"><input type="checkbox" name="clear_client_secret" ${d.clear_client_secret ? "checked" : ""}> Remove the stored secret</label>` : ""}
      ${!secretEnv && chosen?.generated_secret ? html`<label class="check" style="margin:-4px 0 10px"><input type="checkbox" name="use_generated" ${d.use_generated ? "checked" : ""}>
        Use the client secret Atrium generated at ${chosen.name} (it is never shown)</label>` : ""}
      <h3 class="sso-step">Roles</h3>
      <div class="form-grid">
        ${text("role_claim", "Role claim", "A claim name or a dotted path such as realm_access.roles.", "groups", true)}
        ${field("Default role", html`<select name="default_role" ${env.has("default_role") ? "disabled" : ""}>${options(ROLES, d.default_role)}</select>`,
          env.has("default_role") ? envHint("default_role") : "For people with neither an admin nor an operator value.")}
        ${text("admin_values", "Admin values", "Comma separated, e.g. a group name.", "atrium-admins")}
        ${text("operator_values", "Operator values", "Comma separated.", "atrium-operators")}
      </div>
      ${text("scopes", "Scopes", "Separated by spaces; openid is always included.", "openid profile email", true)}
      <label class="check scope-check" style="margin-bottom:12px"><input type="checkbox" name="allow_http" ${d.allow_http ? "checked" : ""} ${env.has("allow_http") ? "disabled" : ""}>
        <span><b>Allow a plain-http issuer</b><span class="faint" style="display:block;font-size:12px">${env.has("allow_http") ? envHint("allow_http")
          : "Only for a lab: without TLS anyone on the network can tamper with sign-in. Localhost is always allowed."}</span></span></label>
      <div class="row">
        <button type="button" class="btn" data-act="sso-test">${icon("activity")}Test</button>
        <button type="submit" class="btn primary">${icon("check")}Save</button>
        <span class="spacer"></span>
        ${v.stored ? html`<button type="button" class="btn danger" data-act="sso-remove">${icon("trash")}Remove saved settings</button>` : ""}
      </div>
      <div data-sso-test>${testView(test)}</div>
    </form>`;
}

/** Fill `card` with the Sign-in & SSO settings (admins only: the API refuses everyone else). */
export async function mountSso(card) {
  let view = await get("/auth/sso");
  let choice = initialChoice(view);
  let draft = fromView(view);
  let test = null;
  const form = () => card.querySelector("[data-sso-form]");
  const imported = () => view.imported.find((i) => `imported:${i.tool_id}` === choice) || null;

  const draw = () => {
    setHTML(card, cardView(view, choice, draft, test));
    const secret = form().elements.namedItem("client_secret");
    if (secret) secret.value = draft.client_secret; // kept across redraws in memory only, never in markup
  };
  /** What is typed now (so a redraw keeps it). */
  const read = () => {
    const f = form();
    const value = (k) => { const el = f.elements.namedItem(k); return el ? (el.type === "checkbox" ? el.checked : el.value) : draft[k]; };
    for (const k of Object.keys(draft)) draft[k] = value(k);
  };
  const body = () => {
    const env = new Set(view.env);
    const p = imported() || view.presets.find((x) => `preset:${x.id}` === choice);
    const out = { provider_name: draft.provider_name.trim() };
    if (p) out.preset = p.preset || p.id;
    for (const k of ["issuer", "client_id", "scopes", "role_claim", "default_role"]) if (!env.has(k)) out[k] = String(draft[k]).trim();
    for (const k of ["admin_values", "operator_values"]) if (!env.has(k)) out[k] = list(draft[k]);
    if (!env.has("allow_http")) out.allow_http = Boolean(draft.allow_http);
    return out;
  };
  /** A provider was picked: prefill from its preset (fields set by the environment stay as they are). */
  const prefill = () => {
    const chosen = imported();
    const p = chosen || view.presets.find((x) => `preset:${x.id}` === choice);
    if (!p) return;
    const env = new Set(view.env);
    const set = (k, value) => { if (!env.has(k)) draft[k] = value; };
    draft.provider_name = p.provider_name;
    if (p.issuer) set("issuer", p.issuer);
    if (chosen) set("client_id", chosen.client_id);
    set("scopes", p.scopes);
    set("role_claim", p.role_claim);
    set("admin_values", p.admin_values.join(", "));
    set("operator_values", p.operator_values.join(", "));
    draft.use_generated = Boolean(chosen?.generated_secret);
  };

  card.addEventListener("change", (e) => {
    if (e.target.name !== "sso_choice") return;
    read();
    choice = e.target.value;
    prefill();
    test = null;
    draw();
    const issuer = form().elements.namedItem("issuer");
    const at = issuer && !issuer.disabled ? issuer.value.indexOf("<") : -1;
    if (at >= 0) { issuer.focus(); issuer.setSelectionRange(at, issuer.value.indexOf(">", at) + 1); }
  });
  card.addEventListener("submit", async (e) => {
    e.preventDefault();
    read();
    const out = body();
    if (draft.client_secret) out.client_secret = draft.client_secret;
    if (draft.clear_client_secret) out.clear_client_secret = true;
    if (draft.use_generated && imported()?.generated_secret) out.generated_secret_from = imported().tool_id;
    if (out.allow_http && !view.values.allow_http && !(await confirmDialog("Allow a plain-http issuer?",
      "Without TLS, anyone on the network between the hub and the provider can read or change sign-in traffic. Use it only in a lab. The change is logged as a warning.", "Allow http"))) return;
    const btn = form().querySelector('button[type="submit"]');
    btn.disabled = true;
    try {
      view = await put("/auth/sso", out);
      draft = fromView(view);
      choice = initialChoice(view);
      test = null;
      draw();
      toast(view.enabled ? `Saved - the sign-in screen shows "${view.label}"` : "Saved - single sign-on stays off until an issuer and a client ID are set", "ok");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "bad");
      if (btn.isConnected) btn.disabled = false;
    }
  });
  actions(card, {
    async "sso-test"(_, btn) {
      read();
      btn.disabled = true;
      setHTML(card.querySelector("[data-sso-test]"), html`<p class="faint" style="margin-top:12px">Testing discovery at the issuer...</p>`);
      try {
        test = await post("/auth/sso/test", body()); // never with the secret: discovery does not need it
      } catch (err) {
        if (err.status === 401) return;
        test = { ok: false, detail: err.message };
      }
      draw();
    },
    async "sso-remove"() {
      if (!(await confirmDialog("Remove the saved sign-in settings?", "The settings saved here, including the client secret, are deleted. HUB_OIDC_* environment variables still apply; without them single sign-on turns off. Local accounts keep working.", "Remove"))) return;
      try {
        view = await del("/auth/sso");
        draft = fromView(view);
        choice = initialChoice(view);
        test = null;
        draw();
        toast("Saved sign-in settings removed", "ok");
      } catch (err) {
        if (err.status !== 401) toast(err.message, "bad");
      }
    },
    "sso-copy": () => copyText(view.redirect_uri),
  });
  draw();
}
