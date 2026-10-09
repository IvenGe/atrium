// API client + live event stream.

// These answer 401 as part of signing in; any other 401 means the session is gone.
const AUTH_PATHS = ["/auth/login", "/auth/setup", "/auth/me"];

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-Hub-Request": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data?.detail;
    const code = data?.code ?? detail?.code;
    const message = Array.isArray(detail) ? detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join("; ")
      : typeof detail === "string" ? detail : detail?.detail || detail?.message;
    if (res.status === 401 && !AUTH_PATHS.includes(path.split("?")[0])) {
      window.dispatchEvent(new CustomEvent("atrium:signed-out"));
    } else if (res.status === 403 && code === "password_change_required") {
      window.dispatchEvent(new CustomEvent("atrium:password-change"));
    }
    const err = new Error(message || `${res.status} ${res.statusText}`);
    err.status = res.status;
    err.code = code;
    throw err;
  }
  return data;
}

export const get = (path) => api(path);
export const post = (path, body = {}) => api(path, { method: "POST", body });
export const patch = (path, body = {}) => api(path, { method: "PATCH", body });
export const put = (path, body = {}) => api(path, { method: "PUT", body });
export const del = (path) => api(path, { method: "DELETE" });

// ---------- live events ----------
const listeners = new Set();
let source = null;

/** Subscribe to event types (array or "*"); returns an unsubscribe function. */
export function onEvent(types, fn) {
  const entry = { types: types === "*" ? null : new Set([].concat(types)), fn };
  listeners.add(entry);
  return () => listeners.delete(entry);
}

/** Opens the event stream (closing any previous one). onStatus(ok, closed): closed means the browser gave up. */
export function connectEvents(onStatus) {
  disconnectEvents();
  const es = new EventSource("/api/events");
  source = es;
  es.onopen = () => onStatus?.(true, false);
  es.onerror = () => { if (source === es) onStatus?.(false, es.readyState === EventSource.CLOSED); };
  es.onmessage = (e) => {
    let event;
    try { event = JSON.parse(e.data); } catch { return; }
    for (const l of listeners) {
      if (!l.types || l.types.has(event.type)) {
        try { l.fn(event); } catch (err) { console.error(err); }
      }
    }
  };
  return es;
}

export function disconnectEvents() {
  source?.close();
  source = null;
}
