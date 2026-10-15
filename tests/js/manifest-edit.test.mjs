// The manifest editor's pure helpers (hub/web/js/manifest-edit.js): what the editor starts from, the PATCH body it
// sends (unchanged fields left out, null for a reset, environment values only when typed), its own checks (the same
// rules as hub/integration/overrides.py check_edit) and the propose toast's text.
import assert from "node:assert/strict";
import { test } from "node:test";
import { addressError, canAskAgain, editBody, formFrom, proposeText, validate } from "../../hub/web/js/manifest-edit.js";

const TOOL = {
  overridden: ["launch.command", "launch.env.KC_HEALTH_ENABLED", "launch.env_files", "launch.secret_env"],
  manifest: {
    kind: "oss",
    launch: { command: "docker run x", port: 8080, cwd: null, env_keys: ["KC_ADMIN_PASSWORD", "KC_HEALTH_ENABLED", "MODE"],
      secret_env: ["KC_ADMIN_PASSWORD"], env_files: ["launch/secrets.env"] },
    health: { url: null }, api: { type: "rest", base_url: "http://localhost:8080/admin/realms", spec: null }, ui: { url: "" },
  },
};
const form = (fields = {}, extra = {}) => ({ fields: { ...formFrom(TOOL).fields, ...fields }, env: {}, reset: [], ...extra });

test("the editor starts from the tool: values as text, environment names only, what is set hub-side", () => {
  const f = formFrom(TOOL);
  assert.equal(f.fields["launch.command"], "docker run x");
  assert.equal(f.fields["launch.port"], "8080");
  assert.equal(f.fields["launch.cwd"], "");
  assert.equal(f.fields["api.type"], "rest");
  assert.deepEqual(f.env, [
    { key: "KC_ADMIN_PASSWORD", secret: true, overridden: true },
    { key: "KC_HEALTH_ENABLED", secret: false, overridden: true },
    { key: "MODE", secret: false, overridden: false },
  ]);
  assert.ok(f.overridden.has("launch.command") && !f.overridden.has("health.url"));
  assert.equal(formFrom({ manifest: { launch: {}, health: {}, api: {}, ui: {} } }).fields["api.type"], "none");
  assert.deepEqual(formFrom(null).env, []);
});

test("the body holds what changed, null for a reset or an emptied field, and typed environment values only", () => {
  const original = formFrom(TOOL);
  assert.deepEqual(editBody(original, form()), {}); // nothing changed: nothing to send
  assert.deepEqual(editBody(original, form({ "launch.command": "  docker run x  " })), {}); // blanks are no change
  assert.deepEqual(editBody(original, form({ "launch.port": "9090", "health.url": "http://localhost:9000/health/ready" })),
    { launch: { port: 9090 }, health: { url: "http://localhost:9000/health/ready" } });
  assert.deepEqual(editBody(original, form({ "api.base_url": "" })), { api: { base_url: null } }); // emptied: back to the analysis
  assert.deepEqual(editBody(original, form({}, { reset: ["launch.command"] })), { launch: { command: null } });
  assert.deepEqual(editBody(original, form({ "api.type": "GraphQL" })), { api: { type: "graphql" } });
  // values are write-only: an empty value input means "unchanged", a typed one is sent, a reset key sends null
  const env = form({}, { env: { KC_ADMIN_PASSWORD: "", MODE: "prod", NEW_KEY: "s3cret" }, reset: ["launch.env.KC_HEALTH_ENABLED"] });
  assert.deepEqual(editBody(original, env), { launch: { env: { MODE: "prod", NEW_KEY: "s3cret", KC_HEALTH_ENABLED: null } } });
  assert.deepEqual(editBody(original, form({ "launch.cwd": "server" }, { env: { " PAD ": "x" } })),
    { launch: { cwd: "server", env: { PAD: "x" } } });
});

test("typed values marked secret, or named like a credential, go in launch.secret; plain ones are constants", () => {
  // review R1: a plain constant (LOG_LEVEL=info) must not become a hub-wide masked secret
  const original = formFrom(TOOL);
  assert.deepEqual(editBody(original, form({}, { env: { LOG_LEVEL: "info", FLASK_DEBUG: "true" } })),
    { launch: { env: { LOG_LEVEL: "info", FLASK_DEBUG: "true" } } });
  assert.deepEqual(editBody(original, form({}, { env: { MODE: "prod", SIGNING_SEED: "x-1", DB_PASSWORD: "p-2", KC_ADMIN_PASSWORD: "" },
    secret: ["SIGNING_SEED", "KC_ADMIN_PASSWORD"] })),
  { launch: { env: { MODE: "prod", SIGNING_SEED: "x-1", DB_PASSWORD: "p-2" }, secret: ["SIGNING_SEED", "DB_PASSWORD"] } });
  assert.deepEqual(editBody(original, form({}, { secret: ["MODE"], reset: ["launch.env.MODE"] })), { launch: { env: { MODE: null } } });
});

test("validation follows the server's rules", () => {
  const original = formFrom(TOOL);
  assert.deepEqual(validate(form(), original), {});
  const bad = validate(form({
    "launch.command": "TODO: start it", "launch.port": "70000", "launch.cwd": "../up", "health.url": "tcp://db",
    "api.base_url": "ftp://x.example.org", "ui.url": "https://admin:pw@tool.example.org/", "api.spec": "/etc/openapi.yaml",
    "api.type": "soap",
  }), original);
  assert.deepEqual(Object.keys(bad).sort(), ["api.base_url", "api.spec", "api.type", "health.url", "launch.command", "launch.cwd",
    "launch.port", "ui.url"]);
  assert.match(bad["launch.command"], /TODO/);
  assert.match(bad["ui.url"], /No credentials in it \(user info\)/);
  assert.match(validate(form({ "launch.command": "a\nb" }), original)["launch.command"], /One line/);
  assert.match(validate(form({ "launch.command": "x".repeat(501) }), original)["launch.command"], /500/);
  assert.match(validate(form({ "launch.port": "80.5" }), original)["launch.port"], /1 to 65535/);
  assert.deepEqual(validate(form({ "launch.port": "", "launch.command": "", "launch.cwd": "./" }), original), {}); // emptied: fine
  assert.deepEqual(validate(form({ "health.url": "tcp://db:5432", "api.spec": "docs/openapi.yaml" }), original), {});
  assert.deepEqual(validate(form({ "launch.command": "TODO" }, { reset: ["launch.command"] }), original), {}); // a reset sends null
  // environment names and values
  const env = validate(form({}, { env: { "BAD KEY": "x", "1ST": "x", QUOTED: "'x'", MULTI: "a\nb", FINE: "ok", EMPTY: "" } }), original);
  assert.deepEqual(Object.keys(env).sort(), ["launch.env.1ST", "launch.env.BAD KEY", "launch.env.MULTI", "launch.env.QUOTED"]);
  const many = Object.fromEntries(Array.from({ length: 14 }, (_, i) => [`K${i}`, "v"]));
  assert.match(validate(form({}, { env: many }), original)["launch.env"], /At most 16/); // 3 kept + 14 new
  assert.deepEqual(validate(form({}, { env: many, reset: ["launch.env.MODE"] }), original), {});
});

test("addresses: http(s) or tcp://host:port, never with credentials", () => {
  assert.equal(addressError("https://tool.example.org/health"), null);
  assert.equal(addressError("tcp://127.0.0.1:5432", ["http", "https", "tcp"]), null);
  assert.match(addressError("tcp://127.0.0.1:5432"), /http:\/\/ or https:\/\//);
  assert.match(addressError("http://x.example.org/?api_key=1"), /query parameter 'api_key'/);
  assert.match(addressError("javascript:alert(1)"), /names a host/);
  assert.match(addressError("http://a b"), /spaces/);
  assert.match(addressError("localhost:8080/health"), /Starts with/);
});

test("the propose toast says what was proposed, what waits and why the rest was not proposed", () => {
  assert.equal(proposeText({ patches: [], pending: [], skipped: [] }), "No new patches needed");
  assert.equal(proposeText({ patches: ["p1"], pending: [], skipped: [] }), "1 proposed; 0 waiting for approval");
  assert.equal(proposeText({ patches: [], pending: ["p1", "p2"], skipped: [] }), "0 proposed; 2 waiting for approval");
  const skipped = [{ check: "launch", title: "Launchable from the hub", fix: "launch_command", state: "needs_input",
    reason: "Atrium does not know how to start Ledger. An administrator can set the launch command in Integration > Launch > Edit." }];
  assert.equal(proposeText({ patches: [], pending: [], skipped }),
    "0 proposed; 0 waiting for approval; not proposed: Launchable from the hub: Atrium does not know how to start Ledger. "
    + "An administrator can set the launch command in Integration > Launch > Edit.");
  assert.equal(canAskAgain({ skipped }), false);
  for (const reason of [
    "You rejected 'Add a health probe adapter'. It is proposed again when the tool changes, or when an administrator asks again.",
    "'Add a health probe adapter' failed 2 times; last error: boom. Fix the cause and ask again (administrator).",
    "The AI model could not work out how to start Ledger: no README. Set it in Integration > Launch > Edit, or ask again.",
  ]) assert.equal(canAskAgain({ skipped: [{ ...skipped[0], reason }] }), true, reason);
  assert.equal(canAskAgain({ skipped: [{ ...skipped[0], reason: "'X' was applied, but the gap is still open: y" }] }), false);
  assert.equal(canAskAgain(null), false);
});
