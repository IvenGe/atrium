// The shared arrangement store (hub/web/js/canvas/layout.js): local merge, one debounced PATCH, undo/redo as new
// PATCHes, remote versions. fetch is replaced by a recorder; no server is involved.
import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { layoutStore } from "../../hub/web/js/canvas/layout.js";

let calls = [];
let server = { id: "integration", version: 0, items: {} };
globalThis.fetch = async (url, { method = "GET", body } = {}) => {
  const data = body ? JSON.parse(body) : null;
  calls.push({ url, method, body: data });
  if (method === "PATCH") {
    for (const id of data.remove || []) delete server.items[id];
    for (const [id, v] of Object.entries(data.items || {})) {
      const entry = { ...(server.items[id] || {}), order: v.order };
      if ("lane" in v) { if (v.lane) entry.lane = v.lane; else delete entry.lane; }
      server.items[id] = entry;
    }
    server = { ...server, version: server.version + 1 };
  } else if (method === "DELETE") server = { ...server, version: server.version + 1, items: {} };
  return { ok: true, status: 200, json: async () => structuredClone(server) };
};
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

beforeEach(() => { calls = []; server = { id: "integration", version: 0, items: {} }; });

test("moves apply at once and are sent as one debounced PATCH", async () => {
  const seen = [];
  const store = layoutStore("integration", { apply: (doc) => seen.push(doc) });
  store.move({ "tool:a": { order: 1, lane: "right" } });
  store.move({ "tool:b": { order: 2 } });
  assert.deepEqual(store.doc.items, { "tool:a": { order: 1, lane: "right" }, "tool:b": { order: 2 } });
  assert.equal(calls.length, 0);
  await wait(650);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].method, "PATCH");
  assert.equal(calls[0].url, "/api/layouts/integration");
  assert.deepEqual(calls[0].body, { items: { "tool:a": { order: 1, lane: "right" }, "tool:b": { order: 2 } }, remove: [] });
  assert.equal(store.doc.version, 1);
  assert.deepEqual(seen.at(-1).items, server.items);
});

test("undo restores the previous entries (removing ids that had none) and redo repeats the move", async () => {
  server.items = { "tool:a": { order: 5 } };
  server.version = 3;
  const store = layoutStore("integration", { apply: () => {} });
  store.set(structuredClone(server));
  store.move({ "tool:a": { order: 1, lane: "left" }, "tool:b": { order: 2 } });
  await wait(650);
  assert.ok(store.undo());
  assert.deepEqual(store.doc.items, { "tool:a": { order: 5 } });
  await wait(650);
  assert.deepEqual(calls.at(-1).body, { items: { "tool:a": { order: 5, lane: null } }, remove: ["tool:b"] });
  assert.deepEqual(server.items, { "tool:a": { order: 5 } });
  assert.ok(store.redo());
  assert.deepEqual(store.doc.items, { "tool:a": { order: 1, lane: "left" }, "tool:b": { order: 2 } });
  assert.equal(store.redo(), false);
  await wait(650);
  assert.equal(store.undo(), true);
  assert.equal(store.undo(), false);
});

test("remote changes: older or equal versions are ignored, newer ones fetched; local pending moves stay on top", async () => {
  server.version = 4;
  server.items = { "tool:x": { order: 9 } };
  const store = layoutStore("integration", { apply: () => {} });
  store.set({ id: "integration", version: 4, items: {} });
  assert.equal(await store.remote(4), false);
  assert.equal(calls.length, 0);
  store.move({ "tool:y": { order: 1 } });
  server.version = 5;
  assert.equal(await store.remote(5), true);
  assert.deepEqual(store.doc.items, { "tool:x": { order: 9 }, "tool:y": { order: 1 } });
  store.set({ id: "integration", version: 2, items: {} }); // an older document never replaces a newer one
  assert.equal(store.doc.version, 5);
  await wait(650);
});

test("reset clears the arrangement and the undo history", async () => {
  const store = layoutStore("integration", { apply: () => {} });
  store.move({ "tool:a": { order: 1 } });
  await store.reset();
  assert.equal(calls.at(-1).method, "DELETE");
  assert.deepEqual(store.doc.items, {});
  assert.equal(store.undo(), false);
  await wait(650);
  assert.ok(!calls.some((c) => c.method === "PATCH"), "a move pending at reset is dropped");
});
