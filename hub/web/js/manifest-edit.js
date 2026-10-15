// The administrators' manifest editor (Integration > Launch / Health / API > Edit) and the propose toast: pure helpers,
// no DOM. What the editor starts from (formFrom), the body of PATCH /api/tools/{id}/manifest it sends (editBody: a field
// left as it was is omitted, null puts a field back to what Atrium found, environment values only when typed - they
// are write-only - with the keys marked secret in `launch.secret`), the checks it runs before sending (validate; the
// server checks again, hub/integration/overrides.py check_edit), and the text of the "Propose patches" toast
// (proposeText, canAskAgain).

export const FIELDS = ["launch.command", "launch.port", "launch.cwd", "health.url", "api.type", "api.base_url", "api.spec", "ui.url"];
export const EDITABLE_CHECKS = ["launch", "health", "api"]; // the check rows that offer the editor
export const API_TYPES = ["rest", "graphql", "grpc", "none"];
export const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MAX_ENV = 16;
export const MAX_COMMAND = 500;
export const MAX_URL = 500;
export const OVERRIDE_NOTE = "set by an administrator or an approved patch";
const CREDENTIAL_PARAM = /token|key|secret|passw|pwd|auth|sig|credential|session/i; // hub/models.py CREDENTIAL_PARAM
// A variable named like a credential is always kept as a secret (hub/execution/runner.py SECRET_ENV, overrides.secret_like)
export const SECRET_NAME = /secret|token|password|passwd|credential|api[_-]?key|private[_-]?key|cookie|session|auth/i;

const read = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
const text = (value) => (value == null ? "" : String(value).trim());

/**
 * The editor's starting values from a tool as GET /api/tools/{id} shows it: `fields` (path -> text, "" when unset),
 * `env` (the launch environment's key names: [{key, secret, overridden}] - values are never shown) and `overridden`
 * (the paths hub-side overrides set, tool.overridden).
 */
export function formFrom(tool) {
  const m = tool?.manifest || {};
  const fields = Object.fromEntries(FIELDS.map((path) => [path, text(read(m, path))]));
  if (!fields["api.type"]) fields["api.type"] = "none";
  const overridden = new Set(tool?.overridden || []);
  const secrets = new Set(m.launch?.secret_env || []);
  const env = (m.launch?.env_keys || []).map((key) => ({
    key, secret: secrets.has(key), overridden: secrets.has(key) || overridden.has(`launch.env.${key}`),
  }));
  return { fields, env, overridden };
}

function normal(path, value) {
  const t = text(value);
  if (path === "api.type") return (t || "none").toLowerCase();
  if (t === "") return null;
  if (path === "launch.port") return /^\d+$/.test(t) ? Number(t) : t;
  return t;
}

/**
 * The PATCH body for `form` = {fields: {path: text}, env: {KEY: typed value}, secret: [KEYs marked secret],
 * reset: [paths]} against `original` (formFrom): a field left as it was is omitted, a field emptied or reset is null
 * (back to what Atrium found), and an environment value is sent only when one was typed ("launch.env.KEY" in `reset`
 * sends KEY: null). Typed keys marked secret - or named like a credential (SECRET_NAME) - go in `launch.secret`: the hub
 * keeps them in its private launch secrets; the others are plain hub-side constants. {} = nothing to save.
 */
export function editBody(original, form) {
  const body = {};
  const reset = new Set(form?.reset || []);
  const marked = new Set(form?.secret || []);
  const put = (path, value) => {
    const [section, name] = path.split(".");
    (body[section] ||= {})[name] = value;
  };
  for (const path of FIELDS) {
    if (reset.has(path)) {
      put(path, null);
      continue;
    }
    const after = normal(path, form?.fields?.[path]);
    if (after !== normal(path, original?.fields?.[path])) put(path, after);
  }
  const env = {};
  for (const [key, value] of Object.entries(form?.env || {})) {
    const k = text(key);
    if (k && typeof value === "string" && value !== "") env[k] = value;
  }
  for (const path of reset) if (path.startsWith("launch.env.")) env[path.slice("launch.env.".length)] = null;
  if (Object.keys(env).length) {
    (body.launch ||= {}).env = env;
    const secret = Object.keys(env).filter((k) => env[k] !== null && (marked.has(k) || SECRET_NAME.test(k)));
    if (secret.length) body.launch.secret = secret;
  }
  return body;
}

function inside(path) {
  const p = path.replace(/\\/g, "/");
  return p === "." || p === "./" || (!p.startsWith("/") && !/^[A-Za-z]:/.test(p) && !p.split("/").some((s) => s === ".."));
}

/** Why `value` is no usable address for `schemes` (null when it is): http(s) (or tcp://host:port), no credentials. */
export function addressError(value, schemes = ["http", "https"]) {
  const t = text(value);
  if (t.length > MAX_URL) return `At most ${MAX_URL} characters`;
  if (/[\s\u0000-\u001f]/.test(t)) return "No spaces or control characters";
  let url;
  try {
    url = new URL(t);
  } catch {
    url = null;
  }
  const scheme = url ? url.protocol.replace(/:$/, "").toLowerCase() : "";
  if (!url || !schemes.includes(scheme) || !url.hostname) return `Starts with ${schemes.map((s) => `${s}://`).join(" or ")} and names a host`;
  if (scheme === "tcp" && (!url.port || (url.pathname && url.pathname !== "/") || url.search)) return "tcp://host:port for a port check";
  const found = [...(url.username || url.password ? ["user info"] : []),
    ...[...url.searchParams.keys()].filter((k) => CREDENTIAL_PARAM.test(k)).map((k) => `query parameter '${k}'`)];
  return found.length ? `No credentials in it (${found.join(", ")}): everyone who can see the tool would read them` : null;
}

function valueError(value) {
  if (/[\r\n\u0000]/.test(value)) return "One line";
  if (value !== value.trim() || /^["']|["']$/.test(value)) return "No quote or blank at the start or the end";
  return null;
}

/**
 * The editor's own checks before sending (the server checks again): {path: message}, empty when all is well. An
 * emptied field is fine (it goes back to what Atrium found); environment keys are checked by name and count.
 */
export function validate(form, original = null) {
  const errors = {};
  const reset = new Set(form?.reset || []);
  const f = form?.fields || {};
  const value = (path) => (reset.has(path) ? "" : text(f[path]));
  const command = value("launch.command");
  if (command) {
    if (command.length > MAX_COMMAND) errors["launch.command"] = `At most ${MAX_COMMAND} characters`;
    else if (/[\r\n\u0000]/.test(String(f["launch.command"]))) errors["launch.command"] = "One line: put several steps in a script in the tool's folder";
    else if (/^todo/i.test(command)) errors["launch.command"] = "A TODO placeholder is no command: give the command that starts the tool";
  }
  const port = value("launch.port");
  if (port && !(/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) errors["launch.port"] = "A whole number from 1 to 65535";
  const cwd = value("launch.cwd");
  if (cwd && !inside(cwd)) errors["launch.cwd"] = "A folder inside the tool's folder (no .., no absolute path)";
  for (const [path, schemes] of [["health.url", ["http", "https", "tcp"]], ["api.base_url", ["http", "https"]], ["ui.url", ["http", "https"]]]) {
    const v = value(path);
    const why = v ? addressError(v, schemes) : null;
    if (why) errors[path] = why;
  }
  const spec = value("api.spec");
  if (spec) {
    const why = /^https?:\/\//i.test(spec) ? addressError(spec) : inside(spec) ? null : "An http(s) address or a path inside the tool's folder";
    if (why) errors["api.spec"] = why;
  }
  const type = value("api.type") || "none";
  if (!API_TYPES.includes(type.toLowerCase())) errors["api.type"] = "rest, graphql, grpc or none";
  const keys = new Set((original?.env || []).map((e) => e.key));
  for (const [rawKey, v] of Object.entries(form?.env || {})) {
    const key = text(rawKey);
    if (typeof v !== "string" || v === "") continue;
    if (!ENV_KEY.test(key)) errors[`launch.env.${key || "?"}`] = "Letters, digits and _, not starting with a digit";
    else {
      const why = valueError(v);
      if (why) errors[`launch.env.${key}`] = why;
    }
    keys.add(key);
  }
  for (const path of reset) if (path.startsWith("launch.env.")) keys.delete(path.slice("launch.env.".length));
  if (keys.size > MAX_ENV) errors["launch.env"] = `At most ${MAX_ENV} environment variables`;
  return errors;
}

/** The toast after a propose pass: "N proposed; M waiting for approval; not proposed: <title>: <reason>", or "No new
 *  patches needed" only when nothing is new, waiting or skipped. */
export function proposeText(result) {
  const made = result?.patches?.length || 0;
  const waiting = result?.pending?.length || 0;
  const skipped = result?.skipped || [];
  if (!made && !waiting && !skipped.length) return "No new patches needed";
  const parts = [`${made} proposed`, `${waiting} waiting for approval`];
  if (skipped.length) parts.push(`not proposed: ${skipped.map((s) => `${s.title}: ${s.reason}`).join("; ")}`);
  return parts.join("; ");
}

/** Whether a propose pass skipped something an administrator can ask for again: a rejected patch, one that failed,
 *  or an AI model's attempt that failed (gapfix.outlook's reasons). */
export function canAskAgain(result) {
  return (result?.skipped || []).some((s) => /^You rejected|failed \d+ times|could not work out|\bask(s)? again\b/i.test(s.reason || ""));
}
