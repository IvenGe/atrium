// API client + live event stream.

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: { "Content-Type": "application/json", "X-Hub-Request": "1" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const detail = data?.detail;
    const message = Array.isArray(detail) ? detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join("; ") : detail;
    throw new Error(message || `${res.status} ${res.statusText}`);
  }
  return data;
}

export const get = (path) => api(path);
export const post = (path, body = {}) => api(path, { method: "POST", body });
export const patch = (path, body = {}) => api(path, { method: "PATCH", body });
export const del = (path) => api(path, { method: "DELETE" });

// ---------- live events ----------
const listeners = new Set();

/** Subscribe to event types (array or "*"); returns an unsubscribe function. */
export function onEvent(types, fn) {
  const entry = { types: types === "*" ? null : new Set([].concat(types)), fn };
  listeners.add(entry);
  return () => listeners.delete(entry);
}

export function connectEvents(onStatus) {
  const source = new EventSource("/api/events");
  source.onopen = () => onStatus?.(true);
  source.onerror = () => onStatus?.(false);
  source.onmessage = (e) => {
    let event;
    try { event = JSON.parse(e.data); } catch { return; }
    for (const l of listeners) {
      if (!l.types || l.types.has(event.type)) {
        try { l.fn(event); } catch (err) { console.error(err); }
      }
    }
  };
  return source;
}
