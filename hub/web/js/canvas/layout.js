// The shared arrangement of a map (canvas-design 4.9, 7.3): lane order and, for integration tools, a Sources /
// Destinations override, stored per hub with PATCH /api/layouts/{view} (operator). Local moves apply at once and are
// sent debounced (500 ms); the server merges per id (last write wins) and announces canvas_layout. Undo and redo
// cover the last 20 moves of this session, each saved as a new PATCH. Camera, hidden items and filters are per viewer
// (localStorage) and never shared.
import { del, get, patch } from "../api.js";
import { debounce, toast } from "../ui.js";

const LIMIT = 20;

/** `apply(doc)` hands the merged layout ({id, version, items}) to the canvas after every change. */
export function layoutStore(view, { apply }) {
  let doc = { id: view, version: 0, items: {} };
  let pending = new Map(); // id -> {order, lane?} (lane null = remove the override) | null (forget the id)
  const undo = [];
  const redo = [];

  function merged() {
    const items = { ...doc.items };
    for (const [id, change] of pending) {
      if (change === null) { delete items[id]; continue; }
      const entry = { ...(items[id] || {}), order: change.order };
      if ("lane" in change) { if (change.lane) entry.lane = change.lane; else delete entry.lane; }
      items[id] = entry;
    }
    return { ...doc, items };
  }

  const send = debounce(async () => {
    if (!pending.size) return;
    const items = {}, remove = [];
    for (const [id, change] of pending) if (change === null) remove.push(id); else items[id] = change;
    pending = new Map();
    try {
      const saved = await patch(`/layouts/${encodeURIComponent(view)}`, { items, remove });
      if ((saved.version || 0) >= (doc.version || 0)) doc = saved;
    } catch (err) {
      toast(`The arrangement was not saved: ${err.message}`, "bad");
      doc = await get(`/layouts/${encodeURIComponent(view)}`).catch(() => doc);
    }
    apply(merged());
  }, 500);

  function change(changes) {
    for (const [id, c] of Object.entries(changes)) {
      if (c === null) { pending.set(id, null); continue; }
      const prev = pending.get(id);
      pending.set(id, { ...(prev || {}), ...c });
    }
    apply(merged());
    send();
  }

  /** Changes that restore `before` ({id: stored entry | null}). */
  const restoring = (before) => Object.fromEntries(Object.entries(before).map(([id, entry]) => [id, entry === null ? null : { order: entry.order, lane: entry.lane ?? null }]));

  return {
    get doc() { return merged(); },
    /** Adopt the server's document (first load, or after a canvas_layout event); pending local moves stay on top. */
    set(next) {
      if (next && (next.version || 0) >= (doc.version || 0)) doc = { id: view, version: 0, items: {}, ...next };
      return merged();
    },
    /** A remote change (canvas_layout {version}): fetch it unless this browser already has that version. */
    async remote(version) {
      if (version !== undefined && version <= (doc.version || 0)) return false;
      const next = await get(`/layouts/${encodeURIComponent(view)}`).catch(() => null);
      if (!next) return false;
      this.set(next);
      apply(merged());
      return true;
    },
    /** A move: {id: {order, lane?}}; recorded for undo unless `record` is false. */
    move(changes, { record = true } = {}) {
      const now = merged().items;
      const before = Object.fromEntries(Object.keys(changes).map((id) => [id, now[id] ? { ...now[id] } : null]));
      if (record) {
        undo.push({ before, after: changes });
        undo.splice(0, Math.max(0, undo.length - LIMIT));
        redo.length = 0;
      }
      change(changes);
    },
    undo() {
      const step = undo.pop();
      if (!step) return false;
      redo.push(step);
      change(restoring(step.before));
      return true;
    },
    redo() {
      const step = redo.pop();
      if (!step) return false;
      undo.push(step);
      change(step.after);
      return true;
    },
    /** "Reset arrangement" (the caller confirms first). */
    async reset() {
      pending = new Map();
      undo.length = 0;
      redo.length = 0;
      doc = await del(`/layouts/${encodeURIComponent(view)}`);
      apply(merged());
    },
  };
}
