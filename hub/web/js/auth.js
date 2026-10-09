// Sign-in screens (login, first-run setup, forced password change) and the account dialogs.
import { del, get, post } from "./api.js";
import { badge, colorFor, field, html, icon, modal, setHTML, timeAgo, toast, toggleTheme } from "./ui.js";

/** The signed-in user (public_user from /api/auth/me); set by the app shell. */
export const session = { user: null };

export const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{1,63}$/;
export const POLICY_HINT = "At least 12 characters, not containing the username.";
const ROLE_TONE = { admin: "accent", operator: "info", viewer: "", integration: "warn" };

// ---------- shared helpers ----------

/** Mirrors the server policy so people get instant feedback; the server stays authoritative. */
export function passwordProblem(password, username = "") {
  if (password.length < 12) return "Use at least 12 characters.";
  if (password.length > 256) return "Use at most 256 characters.";
  if (username && password.toLowerCase().includes(username.toLowerCase())) return "The password must not contain the username.";
  if (new Set(password).size < 5) return "Use at least 5 different characters.";
  return null;
}

export function usernameProblem(username) {
  return USERNAME_RE.test(username) ? null : "Usernames are 2-64 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.";
}

/** A random 20-character password in readable groups, e.g. "Kx7p-Qm4t-Zr9w-Hc3v". */
export function generatePassword() {
  const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const limit = 256 - (256 % alphabet.length);
  const out = [];
  while (out.length < 16) {
    for (const b of crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && out.length < 16) out.push(alphabet[b % alphabet.length]);
    }
  }
  return out.join("").match(/.{4}/g).join("-");
}

function initials(u) {
  const words = String(u.display_name || u.username || "").match(/[\p{L}\p{N}]+/gu) || [];
  return (words.length > 1 ? words[0][0] + words[1][0] : (words[0] || "?").slice(0, 2)).toUpperCase();
}

export function avatar(u, size = "") {
  return html`<span class="avatar ${size}" style="background:${colorFor(u.username || u.id || "")}" aria-hidden="true">${initials(u)}</span>`;
}

export const roleBadge = (role) => badge(role, ROLE_TONE[role] ?? "");

/** Short device description from a user agent string. */
export function device(ua = "") {
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox"
    : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : /curl\//i.test(ua) ? "curl" : "";
  const os = /Windows/.test(ua) ? "Windows" : /iPhone|iPad/.test(ua) ? "iOS" : /Android/.test(ua) ? "Android"
    : /Mac OS X/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return [browser, os].filter(Boolean).join(" on ") || "Unknown device";
}

const fullDate = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");

/** Query parameters of a hash route such as "#/setup?token=...". */
function hashParams(page) {
  const m = location.hash.match(new RegExp(`^#/${page}\\?(.*)$`));
  return new URLSearchParams(m ? m[1] : "");
}

// ---------- screens ----------

const root = () => document.getElementById("auth");

function screen(content, foot = "") {
  const el = root();
  const light = document.documentElement.dataset.theme === "light";
  setHTML(el, html`<button type="button" class="icon-btn auth-theme" data-theme-toggle aria-label="Toggle dark mode">${icon(light ? "moon" : "sun")}</button>
    <div class="auth-wrap">
      <div class="auth-card">
        <div class="auth-brand"><span class="brand-mark">${icon("grid")}</span><span>Atrium <small>suite</small></span></div>
        ${content}
      </div>
      ${foot ? html`<p class="auth-foot">${foot}</p>` : ""}
    </div>`);
  el.querySelector("[data-theme-toggle]").addEventListener("click", (e) => {
    setHTML(e.currentTarget, icon(toggleTheme() === "light" ? "moon" : "sun"));
  });
  setTimeout(() => el.querySelector("form input:not([type=hidden]):not([hidden])")?.focus(), 30);
  return el;
}

const noticeBox = (n) => html`<div class="notice ${n.tone || ""}" style="margin-bottom:16px">${icon(n.tone === "ok" ? "checkCircle" : n.tone === "info" ? "lock" : "alert")}<div>${n.text}</div></div>`;
const errorLine = html`<p class="auth-error" role="alert" hidden></p>`;

/** Runs `fn` with the submit button disabled; shows any error under the form. Returns true on success. */
async function submitting(form, fn) {
  const btn = form.querySelector('button[type="submit"]');
  const out = form.querySelector(".auth-error");
  out.hidden = true;
  btn.disabled = true;
  try {
    await fn();
    return true;
  } catch (err) {
    out.textContent = err.message;
    out.hidden = false;
    return false;
  } finally {
    btn.disabled = false;
  }
}

const value = (form, name) => String(new FormData(form).get(name) ?? "");

/**
 * Shows the right screen for an /api/auth/me answer: setup, login or forced password change.
 * onDone(notice?) re-checks the session (the app shell then starts or shows the next screen).
 */
export function showAuth(me, { notice, onDone }) {
  if (me.setup_required) return setupScreen(onDone);
  if (!me.authenticated || !me.user) return loginScreen(me, notice, onDone);
  return changeScreen(me.user, onDone);
}

function loginScreen(me, notice, onDone) {
  const error = hashParams("login").get("error");
  if (error) history.replaceState(null, "", "#/login");
  const msg = error ? { text: error, tone: "bad" } : notice;
  const el = screen(html`
    <h1>Sign in</h1>
    <p class="lead">Welcome back. Sign in to manage your suite.</p>
    ${msg ? noticeBox(msg) : ""}
    <form data-login novalidate>
      ${field("Username", html`<input name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required>`)}
      ${field("Password", html`<input name="password" type="password" autocomplete="current-password" required>`)}
      ${errorLine}
      <button type="submit" class="btn primary block">Sign in</button>
    </form>
    ${me.oidc?.enabled ? html`<div class="auth-sep">or</div>
      <button type="button" class="btn block" data-sso>${icon("shield")}${me.oidc.label || "Sign in with SSO"}</button>` : ""}`,
    "Forgot your password? Ask an administrator to reset it.");
  const form = el.querySelector("[data-login]");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = value(form, "username").trim().toLowerCase();
    const password = value(form, "password");
    const ok = await submitting(form, async () => {
      if (!username || !password) throw new Error("Enter your username and password.");
      await post("/auth/login", { username, password });
    });
    if (ok) return onDone();
    const pw = form.elements.namedItem("password");
    pw.value = "";
    (username ? pw : form.elements.namedItem("username")).focus();
  });
  el.querySelector("[data-sso]")?.addEventListener("click", () => { location.href = "/api/auth/oidc/login"; });
}

function setupScreen(onDone) {
  const token = hashParams("setup").get("token") || "";
  const el = screen(html`
    <h1>Create the administrator</h1>
    <p class="lead">First run. This account manages users, API tokens and settings; you can invite everyone else afterwards.</p>
    <form data-setup novalidate>
      ${token ? html`<input type="hidden" name="token" value="${token}">`
        : field("Setup token", html`<input name="token" class="mono" autocomplete="off" spellcheck="false" required>`,
          "Printed in the hub's console when it started (the line with #/setup?token=...).")}
      ${field("Username", html`<input name="username" autocomplete="username" autocapitalize="none" spellcheck="false" placeholder="admin" required>`,
        "Lowercase letters, digits, dots, dashes and underscores.")}
      ${field("Display name (optional)", html`<input name="display_name" autocomplete="name">`)}
      ${field("Email (optional)", html`<input name="email" type="email" autocomplete="email">`)}
      ${field("Password", html`<input name="password" type="password" autocomplete="new-password" required>`, POLICY_HINT)}
      ${field("Repeat password", html`<input name="confirm" type="password" autocomplete="new-password" required>`)}
      ${errorLine}
      <button type="submit" class="btn primary block">Create administrator</button>
    </form>`,
    html`Lost the link? Restart the hub to print a new one, or create an admin offline with <code>atrium user create NAME --role admin</code>.`);
  const form = el.querySelector("[data-setup]");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = {
      token: value(form, "token").trim(),
      username: value(form, "username").trim().toLowerCase(),
      password: value(form, "password"),
    };
    const displayName = value(form, "display_name").trim();
    const email = value(form, "email").trim();
    if (displayName) body.display_name = displayName;
    if (email) body.email = email;
    let conflict = false;
    const ok = await submitting(form, async () => {
      if (!body.token) throw new Error("Paste the setup token from the hub's console.");
      const problem = usernameProblem(body.username) || passwordProblem(body.password, body.username)
        || (body.password !== value(form, "confirm") ? "The passwords do not match." : null);
      if (problem) throw new Error(problem);
      try {
        await post("/auth/setup", body);
      } catch (err) {
        conflict = err.status === 409;
        throw err;
      }
    });
    if (ok) {
      history.replaceState(null, "", "#/");
      toast(`Welcome, ${body.display_name || body.username}. You are the administrator.`, "ok");
      onDone();
    } else if (conflict) {
      history.replaceState(null, "", "#/");
      onDone({ text: "The hub is already set up. Sign in instead.", tone: "info" });
    }
  });
}

function changeScreen(user, onDone) {
  const el = screen(html`
    <h1>Choose a new password</h1>
    <p class="lead">Signed in as <b>@${user.username}</b>. Your administrator gave you a temporary password; choose your own to continue.</p>
    <form data-change novalidate>
      <input name="username" value="${user.username}" autocomplete="username" hidden>
      ${field("Current (temporary) password", html`<input name="current_password" type="password" autocomplete="current-password" required>`)}
      ${field("New password", html`<input name="new_password" type="password" autocomplete="new-password" required>`, POLICY_HINT)}
      ${field("Repeat new password", html`<input name="confirm" type="password" autocomplete="new-password" required>`)}
      ${errorLine}
      <button type="submit" class="btn primary block">Change password and continue</button>
    </form>
    <button type="button" class="btn ghost block" data-signout style="margin-top:8px">${icon("logout")}Sign out</button>`);
  const form = el.querySelector("[data-change]");
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const current = value(form, "current_password");
    const next = value(form, "new_password");
    let expired = false;
    const ok = await submitting(form, async () => {
      if (!current) throw new Error("Enter your current password.");
      const problem = passwordProblem(next, user.username) || (next !== value(form, "confirm") ? "The new passwords do not match." : null);
      if (problem) throw new Error(problem);
      try {
        await post("/auth/password", { current_password: current, new_password: next });
      } catch (err) {
        expired = err.status === 401;
        throw err;
      }
    });
    if (ok) { toast("Password changed", "ok"); onDone(); }
    else if (expired) onDone({ text: "Your session ended. Sign in again.", tone: "warn" });
  });
  el.querySelector("[data-signout]").addEventListener("click", async () => {
    await post("/auth/logout").catch(() => {});
    onDone({ text: "You have signed out.", tone: "ok" });
  });
}

/** Shown when /api/auth/me cannot be reached; retries on its own every few seconds. */
export function showUnreachable(err, retry) {
  const el = screen(html`
    <h1>Can't reach the hub</h1>
    <p class="lead">${err.message || "The server did not answer."}</p>
    <button type="button" class="btn primary block" data-retry>${icon("refresh")}Try again</button>`);
  const timer = setTimeout(retry, 5000);
  el.querySelector("[data-retry]").addEventListener("click", () => { clearTimeout(timer); retry(); });
}

// ---------- account dialogs ----------

export function openChangePassword() {
  const user = session.user;
  if (!user) return;
  if (!user.has_password) return toast("Your account signs in through single sign-on.", "info");
  modal({
    title: "Change password",
    submit: "Change password",
    body: html`<input name="username" value="${user.username}" autocomplete="username" hidden>
      ${field("Current password", html`<input name="current_password" type="password" autocomplete="current-password" required>`)}
      ${field("New password", html`<input name="new_password" type="password" autocomplete="new-password" required>`, POLICY_HINT)}
      ${field("Repeat new password", html`<input name="confirm" type="password" autocomplete="new-password" required>`)}
      <p class="faint" style="font-size:12.5px">Your other sessions are signed out; this one stays signed in.</p>`,
    async onSubmit(data) {
      const current = String(data.get("current_password") || "");
      const next = String(data.get("new_password") || "");
      if (!current) throw new Error("Enter your current password.");
      const problem = passwordProblem(next, user.username) || (next !== data.get("confirm") ? "The new passwords do not match." : null);
      if (problem) throw new Error(problem);
      await post("/auth/password", { current_password: current, new_password: next });
      toast("Password changed. Your other sessions were signed out.", "ok");
    },
  });
}

export async function openSessions() {
  let list;
  try { list = await get("/auth/sessions"); } catch (err) { if (err.status !== 401) toast(err.message, "bad"); return; }
  const m = modal({
    title: "Your sessions",
    wide: true,
    body: html`<p class="muted" style="margin-bottom:12px">Browsers signed in to your account. Sessions end after a period of inactivity, and always after their expiry date.</p>
      <div data-list></div>`,
    footer: html`<button type="button" class="btn danger" data-revoke style="margin-right:auto">${icon("logout")}Sign out other sessions</button>
      <button type="button" class="btn" data-close>Close</button>`,
  });
  const box = m.el.querySelector("[data-list]");
  const revoke = m.el.querySelector("[data-revoke]");
  const draw = () => {
    const others = list.filter((s) => !s.current).length;
    revoke.disabled = !others;
    setHTML(box, html`<div class="table-wrap"><table class="table"><thead><tr><th>Device</th><th>IP address</th><th>Signed in</th><th>Last active</th><th>Expires</th></tr></thead><tbody>
      ${list.map((s) => html`<tr>
        <td><div class="row" style="flex-wrap:nowrap;gap:8px">${icon("monitor")}<span title="${s.user_agent || ""}">${device(s.user_agent || "")}</span>${s.current ? badge("this browser", "ok") : ""}</div></td>
        <td class="mono" style="font-size:12.5px">${s.ip || "-"}</td>
        <td class="faint" title="${fullDate(s.created_at)}">${timeAgo(s.created_at)}</td>
        <td class="faint" title="${fullDate(s.last_seen)}">${timeAgo(s.last_seen)}</td>
        <td class="faint">${s.expires_at ? new Date(s.expires_at * 1000).toLocaleDateString() : "-"}</td></tr>`)}
      </tbody></table></div>`);
  };
  revoke.addEventListener("click", async () => {
    revoke.disabled = true;
    try {
      const r = await del("/auth/sessions");
      toast(r.revoked ? `Signed out ${r.revoked} other session${r.revoked > 1 ? "s" : ""}` : "No other sessions", "ok");
      list = await get("/auth/sessions");
    } catch (err) {
      if (err.status !== 401) toast(err.message, "bad");
    }
    draw();
  });
  draw();
}
