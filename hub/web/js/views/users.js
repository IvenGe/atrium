import { del, get, patch, post } from "../api.js";
import { avatar, generatePassword, passwordProblem, POLICY_HINT, roleBadge, session, usernameProblem } from "../auth.js";
import { personChip } from "../people.js";
import { actions, badge, can, confirmDialog, copyText, emptyState, field, html, icon, modal, options, setHTML, timeAgo, toast } from "../ui.js";

const ROLES = [["viewer", "Viewer"], ["operator", "Operator"], ["admin", "Admin"]];
const TOKEN_ROLES = [...ROLES, ["integration", "Integration"]];
const ROLE_HELP = {
  viewer: "Viewer: sees everything, changes nothing.",
  operator: "Operator: everything a viewer can, plus importing tools, approvals, commands, hosts, assets, GRC edits and chat.",
  admin: "Admin: everything, plus users, API tokens, settings and agent configuration.",
  integration: "Integration: can only publish events (POST /api/bus/publish) and read /api/health. Use it for event adapters.",
};

const fullDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");
const userChanged = () => window.dispatchEvent(new CustomEvent("atrium:user-updated"));

/** Password input with Generate and Copy buttons. */
function passwordField(label, name) {
  return field(label, html`<div class="secret"><input name="${name}" class="mono" value="${generatePassword()}" autocomplete="new-password" spellcheck="false" required>
      <button type="button" class="btn" data-gen title="Generate a new password">${icon("refresh")}<span class="txt">Generate</span></button>
      <button type="button" class="btn" data-copy title="Copy">${icon("copy")}</button></div>`,
    `Share it with the person over a safe channel. ${POLICY_HINT}`);
}

function wirePassword(form, name) {
  const input = form.querySelector(`[name="${name}"]`);
  form.querySelector("[data-gen]").addEventListener("click", () => { input.value = generatePassword(); input.focus(); });
  form.querySelector("[data-copy]").addEventListener("click", () => copyText(input.value, input));
}

function wireRoleHelp(form) {
  const select = form.querySelector("[name=role]");
  const help = form.querySelector("[data-role-help]");
  select.addEventListener("change", () => { help.textContent = ROLE_HELP[select.value] || ""; });
}

export function openAddUser(done) {
  const m = modal({
    title: "Add user",
    submit: "Add user",
    minRole: "admin",
    body: html`<div class="form-grid">
        ${field("Username", html`<input name="username" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="jane.doe" required>`,
          "Lowercase letters, digits, dots, dashes, underscores.")}
        ${field("Role", html`<select name="role">${options(ROLES, "viewer")}</select>`)}
        ${field("Display name (optional)", html`<input name="display_name" autocomplete="off" placeholder="Jane Doe">`)}
        ${field("Email (optional)", html`<input name="email" type="email" autocomplete="off">`)}</div>
      <p class="faint" style="font-size:12.5px;margin:-4px 0 12px" data-role-help>${ROLE_HELP.viewer}</p>
      ${passwordField("Temporary password", "password")}
      <label class="check"><input type="checkbox" name="must_change_password" checked> Ask them to choose their own password when they first sign in</label>`,
    async onSubmit(data) {
      const username = String(data.get("username") || "").trim().toLowerCase();
      const password = String(data.get("password") || "");
      const problem = usernameProblem(username) || passwordProblem(password, username);
      if (problem) throw new Error(problem);
      const body = { username, password, role: data.get("role"), must_change_password: data.get("must_change_password") === "on" };
      const displayName = String(data.get("display_name") || "").trim();
      const email = String(data.get("email") || "").trim();
      if (displayName) body.display_name = displayName;
      if (email) body.email = email;
      await post("/users", body);
      toast(`${username} added as ${body.role}`, "ok");
      done?.();
    },
  });
  wirePassword(m.el, "password");
  wireRoleHelp(m.el);
}

export function openNewToken(done) {
  const m = modal({
    title: "New API token",
    submit: "Create token",
    minRole: "admin",
    body: html`${field("Name", html`<input name="name" autocomplete="off" spellcheck="false" placeholder="ci-pipeline or grafana-events" required>`,
        "Shown in the activity log as token:<name>.")}
      <div class="form-grid">
        ${field("Role", html`<select name="role">${options(TOKEN_ROLES, "integration")}</select>`)}
        ${field("Expires after (days)", html`<input name="expires_days" type="number" min="1" max="3650" step="1" value="90">`, "Empty: never expires.")}</div>
      <p class="faint" style="font-size:12.5px" data-role-help>${ROLE_HELP.integration}</p>`,
    async onSubmit(data) {
      const name = String(data.get("name") || "").trim();
      if (!name) throw new Error("Give the token a name");
      const days = String(data.get("expires_days") || "").trim();
      const expires_days = days ? Number(days) : null;
      if (days && (!Number.isInteger(expires_days) || expires_days < 1)) throw new Error("Expiry must be a whole number of days");
      const token = await post("/tokens", { name, role: data.get("role"), expires_days });
      showSecret(token);
      done?.();
    },
  });
  wireRoleHelp(m.el);
}

/** The only time a token secret is visible; the dialog closes only through its buttons. */
function showSecret(t) {
  const m = modal({
    title: "Copy your new token",
    submit: null,
    cancel: "Done",
    sticky: true,
    body: html`<div class="notice warn" style="margin-bottom:14px">${icon("alert")}<div><b>This is the only time the token is shown.</b>
        <span class="muted">Store it in your secret manager now. If it is lost, revoke it and create a new one.</span></div></div>
      ${field(html`${t.name} ${roleBadge(t.role)}`, html`<div class="secret"><input readonly class="mono" value="${t.token}" aria-label="API token" data-secret>
        <button type="button" class="btn primary" data-copy>${icon("copy")}Copy</button></div>`)}
      <p class="muted" style="font-size:12.5px">Send it as <code>Authorization: Bearer &lt;token&gt;</code>.
        ${t.role === "integration" ? html`Event adapters generated by the Patch Agent read it from the <code>HUB_TOKEN</code> environment variable.` : ""}</p>`,
  });
  const input = m.el.querySelector("[data-secret]");
  m.el.querySelector("[data-copy]").addEventListener("click", () => copyText(input.value, input));
  setTimeout(() => input.select(), 40);
}

/** The person in the People app with the same email; a leaver whose account is still enabled is flagged. */
function personCell(u) {
  if (!u.person) return html`<span class="faint" title="${u.email ? `No person in People has ${u.email}` : "Add an email to link this user to a person"}">-</span>`;
  const left = u.person.status !== "active";
  return html`<div class="row" style="gap:6px">${personChip(u.person)}
    ${left && !u.disabled ? html`<span class="badge bad" title="This person has left (${u.person.status}) but the account can still sign in">${icon("alert")}left - still enabled</span>` : ""}</div>`;
}

function userRow(u, self) {
  const details = [u.display_name, u.email].filter(Boolean).join(" - ");
  return html`<tr>
    <td><div class="row" style="flex-wrap:nowrap;gap:10px">${avatar(u)}
      <div style="min-width:0"><div class="row" style="gap:6px;flex-wrap:nowrap"><b>${u.username}</b>${self ? badge("you", "accent") : ""}</div>
        <div class="faint" style="font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${details || "-"}</div></div></div></td>
    <td>${personCell(u)}</td>
    <td><select class="input-sm" data-role-for="${u.id}" aria-label="Role of ${u.username}" ${self ? "disabled" : ""}>${options(ROLES, u.role)}</select></td>
    <td>${u.auth_source === "oidc" ? badge("SSO", "info") : badge("local")}</td>
    <td><div class="row" style="gap:6px">${u.disabled ? badge("disabled", "bad") : badge("active", "ok")}${u.must_change_password ? badge("password change pending", "warn") : ""}</div></td>
    <td class="faint" title="${fullDate(u.last_login)}">${u.last_login ? timeAgo(u.last_login) : "never"}</td>
    <td><div class="row" style="gap:6px;flex-wrap:nowrap;justify-content:flex-end">
      <button class="btn sm" data-act="edit-user" data-id="${u.id}" title="Edit name and email" aria-label="Edit ${u.username}">${icon("edit")}</button>
      ${self ? html`<span class="faint" style="font-size:12px">use the account menu</span>` : html`
        <button class="btn sm" data-act="reset" data-id="${u.id}">${icon("key")}${u.has_password ? "Reset password" : "Set password"}</button>
        <button class="btn sm" data-act="toggle-user" data-id="${u.id}">${u.disabled ? "Enable" : "Disable"}</button>
        <button class="btn sm danger" data-act="delete-user" data-id="${u.id}" aria-label="Delete ${u.username}">${icon("trash")}</button>`}
    </div></td></tr>`;
}

function expiry(ts) {
  if (!ts) return html`<span class="faint">never</span>`;
  if (ts * 1000 < Date.now()) return badge("expired", "bad");
  return html`<span class="faint" title="${fullDate(ts)}">${new Date(ts * 1000).toLocaleDateString()}</span>`;
}

function tokenRow(t) {
  return html`<tr>
    <td><b>${t.name}</b></td>
    <td>${roleBadge(t.role)}</td>
    <td class="mono faint" style="font-size:12.5px">atr_${t.prefix}...</td>
    <td class="faint" title="${fullDate(t.created_at)}">${timeAgo(t.created_at)}${t.created_by ? ` by ${t.created_by}` : ""}</td>
    <td class="faint" title="${fullDate(t.last_used)}">${t.last_used ? timeAgo(t.last_used) : "never"}</td>
    <td>${expiry(t.expires_at)}</td>
    <td style="text-align:right"><button class="btn sm danger" data-act="revoke" data-id="${t.id}">${icon("trash")}Revoke</button></td></tr>`;
}

export async function render(el) {
  if (!can("admin")) {
    setHTML(el, html`<section class="card">${emptyState("lock", "Administrators only", "Ask an administrator if you need to manage users or API tokens.")}</section>`);
    return;
  }
  let users = [];
  let tokens = [];
  const draw = async () => {
    [users, tokens] = await Promise.all([get("/users"), get("/tokens")]);
    const me = session.user?.id;
    const admins = users.filter((u) => u.role === "admin" && !u.disabled).length;
    setHTML(el, html`
      <div class="page-head"><div><h1>Users &amp; access</h1><p class="muted">Who can sign in to the hub and what they may do, plus the API tokens used by scripts and integrations.</p></div>
        <div class="row"><button class="btn" data-act="add-token">${icon("key")}New API token</button>
          <button class="btn primary" data-act="add-user">${icon("plus")}Add user</button></div></div>
      <section class="card flush" style="margin-bottom:16px"><header><h2>Users (${users.length})</h2>
          <span class="faint" style="font-size:12px">${admins} active admin${admins === 1 ? "" : "s"}</span></header>
        ${users.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr>
            <th>User</th><th title="The person in People with the same email">Person</th><th>Role</th><th>Sign-in</th><th>Status</th><th>Last login</th><th></th></tr></thead><tbody>
            ${users.map((u) => userRow(u, u.id === me))}</tbody></table></div>`
          : html`<div style="padding:0 16px 16px">${emptyState("users", "No users", "Add the people who run the suite.")}</div>`}
      </section>
      <section class="card flush"><header><h2>API tokens (${tokens.length})</h2>
          <button class="btn sm" data-act="add-token">${icon("plus")}New token</button></header>
        ${tokens.length ? html`<div class="table-wrap" style="margin-top:10px"><table class="table"><thead><tr>
            <th>Name</th><th>Role</th><th>Token</th><th>Created</th><th>Last used</th><th>Expires</th><th></th></tr></thead><tbody>
            ${tokens.map(tokenRow)}</tbody></table></div>`
          : html`<p class="muted" style="padding:0 16px 16px">No tokens yet. Create one for scripts, CI or an event adapter; it is sent as <code>Authorization: Bearer atr_...</code>.</p>`}
      </section>
      <p class="faint" style="font-size:12px;margin-top:12px">Locked out? On the server, <code>atrium user passwd USERNAME</code> resets a password without signing in.</p>`);
  };
  const find = (id) => users.find((u) => u.id === id);
  const refresh = () => draw().catch((err) => toast(err.message, "bad"));
  const attempt = async (fn, done) => {
    try { await fn(); if (done) toast(done, "ok"); } catch (err) { if (err.status !== 401) toast(err.message, "bad"); }
    refresh();
  };

  el.addEventListener("change", (e) => {
    const select = e.target.closest("select[data-role-for]");
    if (!select) return;
    const u = find(select.dataset.roleFor);
    if (u) attempt(() => patch(`/users/${encodeURIComponent(u.id)}`, { role: select.value }), `${u.username} is now ${select.value}`);
  });
  actions(el, {
    "add-user": () => openAddUser(refresh),
    "add-token": () => openNewToken(refresh),
    "edit-user"(d) {
      const u = find(d.id);
      if (!u) return;
      modal({
        title: `Edit ${u.username}`,
        minRole: "admin",
        body: html`${field("Display name", html`<input name="display_name" value="${u.display_name || ""}" autocomplete="off">`)}
          ${field("Email", html`<input name="email" type="email" value="${u.email || ""}" autocomplete="off">`,
            u.person ? html`Linked by this email to ${u.person.display_name} (${u.person.status}) in People.` : "The email links the user to a person in People.")}
          ${u.auth_source === "oidc" ? html`<p class="faint" style="font-size:12px">Signs in through SSO; the role is synced from the identity provider at each sign-in.</p>` : ""}`,
        async onSubmit(data) {
          await patch(`/users/${encodeURIComponent(u.id)}`, {
            display_name: String(data.get("display_name") || "").trim(),
            email: String(data.get("email") || "").trim() || null,
          });
          toast("Saved", "ok");
          if (u.id === session.user?.id) userChanged();
          refresh();
        },
      });
    },
    reset(d) {
      const u = find(d.id);
      if (!u) return;
      const m = modal({
        title: `${u.has_password ? "Reset" : "Set"} password for ${u.username}`,
        submit: u.has_password ? "Reset password" : "Set password",
        minRole: "admin",
        body: html`<p class="muted" style="margin-bottom:12px">All of ${u.username}'s sessions are signed out.
            ${u.auth_source === "oidc" ? "They can keep signing in with SSO; this adds a local password as well." : ""}</p>
          ${passwordField("New temporary password", "new_password")}
          <label class="check"><input type="checkbox" name="must_change_password" checked> Ask them to choose their own password at the next sign-in</label>`,
        async onSubmit(data) {
          const password = String(data.get("new_password") || "");
          const problem = passwordProblem(password, u.username);
          if (problem) throw new Error(problem);
          await post(`/users/${encodeURIComponent(u.id)}/password`, { new_password: password, must_change_password: data.get("must_change_password") === "on" });
          toast(`Password for ${u.username} updated - share it with them`, "ok");
          refresh();
        },
      });
      wirePassword(m.el, "new_password");
    },
    async "toggle-user"(d) {
      const u = find(d.id);
      if (!u) return;
      if (!u.disabled && !(await confirmDialog("Disable user", `Disable ${u.username}? They are signed out everywhere and cannot sign in until the account is enabled again.`, "Disable"))) return;
      attempt(() => patch(`/users/${encodeURIComponent(u.id)}`, { disabled: !u.disabled }), `${u.username} ${u.disabled ? "enabled" : "disabled"}`);
    },
    async "delete-user"(d) {
      const u = find(d.id);
      if (!u) return;
      if (!(await confirmDialog("Delete user", `Delete ${u.username}? They are signed out everywhere. Their name stays in the activity log.`, "Delete"))) return;
      attempt(() => del(`/users/${encodeURIComponent(u.id)}`), `${u.username} deleted`);
    },
    async revoke(d) {
      const t = tokens.find((x) => x.id === d.id);
      if (!t) return;
      if (!(await confirmDialog("Revoke token", `Revoke "${t.name}"? Anything using it stops working immediately.`, "Revoke"))) return;
      attempt(() => del(`/tokens/${encodeURIComponent(t.id)}`), `Token ${t.name} revoked`);
    },
  });
  await draw();
}
