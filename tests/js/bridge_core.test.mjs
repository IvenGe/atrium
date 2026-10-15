// The vendored Node bridge core (hub/subsidiary/templates/node) against the contract's vectors
// (hub/subsidiary/contract/vectors.json), on Node's own http server and as Express/Connect middleware, plus the
// "Ask the team" widget (panel.js) in a minimal DOM: answers are text, never HTML. Only 127.0.0.1 is used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const TEMPLATES = path.join(ROOT, 'hub', 'subsidiary', 'templates');
const require = createRequire(import.meta.url);
const core = require(path.join(TEMPLATES, 'node', 'atrium-bridge-core.cjs'));
const VECTORS = JSON.parse(fs.readFileSync(path.join(ROOT, 'hub', 'subsidiary', 'contract', 'vectors.json'), 'utf8'));
const std = (text) => Buffer.from(text, 'base64');
const wire = (text) => Buffer.from(text, 'base64url');
const code = (fn) => {
  try {
    fn();
    return null;
  } catch (e) {
    return e instanceof core.Refused ? e.code : 'error:' + e.message;
  }
};
const quiet = (fn) => async () => {
  const saved = [console.warn, console.error];
  console.warn = () => {};
  console.error = () => {};
  try {
    return await fn();
  } finally {
    [console.warn, console.error] = saved;
  }
};

test('the template JavaScript parses and the ES module exports the same core', async () => {
  for (const file of ['node/atrium-bridge-core.cjs', 'node/atrium-bridge-core.mjs', 'node/glue_skeleton.cjs',
    'node/glue_skeleton.mjs', 'panel/panel.js']) {
    const result = spawnSync(process.execPath, ['--check', path.join(TEMPLATES, file)], { encoding: 'utf8' });
    assert.equal(result.status, 0, file + ': ' + result.stderr);
  }
  const esm = await import(path.join(TEMPLATES, 'node', 'atrium-bridge-core.mjs'));
  assert.equal(esm.default, core);
  for (const name of Object.keys(core)) assert.equal(esm[name], core[name], name);
});

test('the built-ins are the contract\'s', () => {
  const builtins = Object.fromEntries(Object.entries(core.BUILTINS).map(([id, spec]) => [id, spec]));
  assert.deepEqual(Object.keys(builtins).sort(), ['atrium.describe', 'atrium.events.pull', 'atrium.noop_write',
    'atrium.panel.answer', 'atrium.panel.pull', 'atrium.ping', 'atrium.receipt']);
  for (const spec of Object.values(builtins)) assert.ok(core.schemaOk(spec.params));
});

test('unit vectors: base64url, keys, tickets, grants, signing strings and params', () => {
  const u = VECTORS.units;
  for (const c of u.b64u) {
    let out = null;
    try {
      out = core.b64uDecode(c.in).toString('hex');
    } catch (e) { /* refused */ }
    assert.equal(out !== null, c.ok, 'b64u ' + c.in);
    if (c.ok) assert.equal(out, c.hex);
  }
  for (const c of u.keys) {
    let keys = null;
    try {
      keys = core.parseKeys(c.value);
    } catch (e) { /* refused */ }
    assert.equal(keys !== null, c.ok, 'keys ' + c.value);
    if (c.ok) assert.equal(keys.length, c.count);
  }
  for (const [name, prefix, refusal] of [['tickets', 'AT1', 'bad_ticket'], ['grants', 'AG1', 'grant_mismatch']]) {
    const units = u[name];
    const keys = core.parseKeys(units.keys);
    const bridge = Object.create(core.Bridge.prototype);
    Object.assign(bridge, { tool: units.tool, sub: units.sub, grants: new core.MemoryGrants() });
    for (const c of units.cases) {
      let payload = null;
      const got = code(() => {
        payload = core.verifyToken(c.token, prefix, keys, refusal);
        if (name === 'tickets') {
          if (!core.ticketFieldsOk(payload)) throw new core.Refused('bad_ticket');
          bridge.checkTicket(payload, units.now);
        } else {
          if (!core.grantFieldsOk(payload)) throw new core.Refused('grant_mismatch');
          const p = payload;
          const body = std(c.body_b64 || '');
          const expected = core.bodyHash(body);
          if (p.tool !== units.tool || p.sub !== units.sub || p.act !== c.action || p.bh !== expected) {
            throw new core.Refused('grant_mismatch');
          }
          if (p.exp <= units.now - 60) throw new core.Refused('expired');
        }
      });
      if (c.ok) {
        assert.equal(got, null, name + ' ' + c.title);
        assert.deepEqual(payload, c.payload, name + ' ' + c.title);
      } else {
        assert.equal(got, c.code, name + ' ' + c.title);
      }
    }
  }
  for (const c of u.signing) {
    const body = std(c.body_b64);
    const message = core.signingString(c.method, c.path, c.date, c.nonce, body, c.ticket_jti, c.grant_jti, c.on_behalf_of);
    if (c.valid) assert.equal(message.toString('utf8'), c.string, c.title);
    assert.equal(crypto.createHash('sha256').update(body).digest('hex') === c.body_sha256 || !c.valid, true, c.title);
    assert.equal(core.verifySignature(c.cnf, c.signature, message), c.valid, c.title);
  }
  for (const c of u.params.cases) {
    let params = null;
    const got = code(() => {
      params = core.validateParams(u.params.schemas[c.schema], core.parseBody(std(c.body_b64)));
    });
    if (c.ok) {
      assert.equal(got, null, 'params ' + c.title);
      assert.deepEqual(params, c.params, 'params ' + c.title);
    } else {
      assert.equal(got, 'bad_params', 'params ' + c.title);
    }
  }
});

function listen(listener) {
  return new Promise((resolve) => {
    const server = http.createServer(listener);
    server.listen(0, '127.0.0.1', () => resolve(server));
  });
}

async function send(server, step, body, extraHeaders) {
  const { port } = server.address();
  const res = await fetch(`http://127.0.0.1:${port}${step.path}`, {
    method: step.method, headers: Object.assign({}, step.headers, extraHeaders || {}), redirect: 'manual',
    body: step.method === 'GET' ? undefined : body
  });
  return { status: res.status, headers: res.headers, body: Buffer.from(await res.arrayBuffer()) };
}

function dig(value, dotted) {
  for (const part of dotted.split('.')) {
    if (value === null || typeof value !== 'object' || !(part in value)) return undefined;
    value = value[part];
  }
  return value;
}

function check(step, res) {
  const e = step.expect;
  if (res.status !== e.status) return `status ${res.status}, expected ${e.status}: ${res.body}`;
  if (e.sha256 && crypto.createHash('sha256').update(res.body).digest('hex') !== e.sha256) return 'sha256 differs';
  if (e.code === undefined && e.json === undefined) return null;
  const data = JSON.parse(res.body.toString('utf8'));
  if (e.code !== undefined && data.code !== e.code) return `code ${data.code}, expected ${e.code}`;
  for (const [dotted, want] of Object.entries(e.json || {})) {
    if (JSON.stringify(dig(data, dotted)) !== JSON.stringify(want)) return `${dotted} differs: ${res.body}`;
  }
  return null;
}

function conformanceGlue() {
  const c = VECTORS.conformance;
  const manifest = std(c.manifest_b64);
  const actions = Object.fromEntries(JSON.parse(manifest).actions.map((a) => [a.id, () => ({ ok: true })]));
  return {
    actions, manifest, panelJs: std(c.panel_js_b64), panelSha256: c.panel_sha256, env: c.env,
    clock: () => VECTORS.now, currentUser: () => null
  };
}

test('conformance vectors V1-V20 pass on node:http', quiet(async () => {
  const server = await listen(core.handler(conformanceGlue()));
  try {
    for (const vector of VECTORS.conformance.vectors) {
      for (const [i, step] of vector.steps.entries()) {
        const problem = check(step, await send(server, step, wire(step.body_b64)));
        assert.equal(problem, null, `${vector.id} step ${i + 1}`);
      }
    }
  } finally {
    server.close();
  }
}));

function connectApp(...middlewares) {
  return (req, res) => {
    let i = 0;
    const next = (err) => {
      if (err) {
        res.statusCode = 500;
        res.end('error');
        return;
      }
      const mw = middlewares[i++];
      if (!mw) {
        res.statusCode = 200;
        res.end('the tool\'s own page');
        return;
      }
      mw(req, res, next);
    };
    next();
  };
}

test('Express/Connect middleware: the tool keeps its routes, the bridge refuses calls after a body parser', quiet(async () => {
  const glue = conformanceGlue();
  const parser = (req, res, next) => { // like express.json(): consumes the body
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      req._body = true;
      req.body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : {};
      next();
    });
  };
  const good = await listen(connectApp(core.express(glue)));
  const late = await listen(connectApp(parser, core.express(Object.assign({}, glue))));
  try {
    let res = await send(good, { method: 'GET', path: '/tickets', headers: {} });
    assert.equal(res.body.toString(), 'the tool\'s own page');
    res = await send(good, { method: 'GET', path: '/.atrium/v1/health', headers: {} });
    assert.deepEqual(JSON.parse(res.body), { status: 'ok' });
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('access-control-allow-origin'), null);
    res = await send(good, { method: 'GET', path: '/.atrium/v1/unknown', headers: {} });
    assert.equal(res.status, 404);
    const ping = VECTORS.conformance.vectors.find((v) => v.id === 'V19').steps[0];
    res = await send(late, ping, wire(ping.body_b64));
    assert.equal(res.status, 503);
    assert.equal(JSON.parse(res.body).code, 'not_configured');
  } finally {
    good.close();
    late.close();
  }
}));

test('a bridge without keys fails closed but answers /health', quiet(async () => {
  const server = await listen(core.handler({ env: {}, manifest: Buffer.from('{}') }));
  try {
    assert.equal((await send(server, { method: 'GET', path: '/.atrium/v1/health', headers: {} })).status, 200);
    for (const step of [{ method: 'GET', path: '/.atrium/panel.js', headers: {} },
      { method: 'POST', path: '/.atrium/v1/call/atrium.ping', headers: {} }]) {
      const res = await send(server, step, Buffer.from('{"params":{}}'));
      assert.equal(res.status, 503);
      assert.deepEqual(JSON.parse(res.body), { ok: false, code: 'not_configured' });
    }
  } finally {
    server.close();
  }
}));

// ---- a scripted Atrium and sidecar for the stateful behaviour ----

const MANIFEST = Buffer.from(JSON.stringify({
  contract: 'atrium-bridge/1', tool_id: 'helpdesk', stack: 'node-express', core: 'node/1.0.0', panel: { enabled: true },
  events: { names: ['helpdesk.ticket.updated'] }, files: ['atrium-bridge.json'],
  actions: [
    { id: 'tickets.list', title: 'List tickets', risk: 'read', on_behalf_of: true,
      params: { type: 'object', additionalProperties: false, properties: {} } },
    { id: 'tickets.set_priority', title: 'Set a priority', risk: 'write', reversible: true,
      params: { type: 'object', additionalProperties: false, required: ['ticket_id', 'priority'],
        properties: { ticket_id: { type: 'integer' }, priority: { enum: ['low', 'high'] } } } }
  ]
}));
const SUB = 'sub_0123456789ab';
const raw = (key) => key.export({ format: 'der', type: 'spki' }).subarray(12);

class Harness {
  constructor(options = {}) {
    this.atrium = crypto.generateKeyPairSync('ed25519');
    this.probe = crypto.generateKeyPairSync('ed25519');
    if (options.atrium) this.atrium = options.atrium;
    this.now = 1800000000;
    this.n = 0;
    this.glue = {
      manifest: MANIFEST, panelJs: path.join(TEMPLATES, 'panel', 'panel.js'), clock: () => this.now, grants: options.grants,
      env: { ATRIUM_BRIDGE_KEYS: core.b64u(raw(this.atrium.publicKey)), ATRIUM_TOOL_ID: 'helpdesk',
        ATRIUM_SUBSIDIARY_ID: SUB, ATRIUM_BRIDGE_ALLOW: options.allow || '' },
      currentUser: async (req) => (req.headers['x-test-user']
        ? { id: req.headers['x-test-user'], display: 'User', roles: ['agent'] } : null),
      actions: {
        'tickets.list': (params, ctx) => ({ as: ctx.principal, for: ctx.user ? ctx.user.id : null }),
        'tickets.set_priority': async (params) => {
          await new Promise((resolve) => setTimeout(resolve, 5)); // the cause survives an await
          core.emit('helpdesk.ticket.updated', { id: params.ticket_id });
          return { priority: params.priority };
        }
      }
    };
  }

  async start() {
    this.server = await listen(core.handler(this.glue));
    this.bridge = core.createBridge(this.glue);
    return this;
  }

  token(prefix, payload) {
    const signed = prefix + '.' + core.b64u(Buffer.from(JSON.stringify(payload)));
    return signed + '.' + core.b64u(crypto.sign(null, Buffer.from(signed), this.atrium.privateKey));
  }

  async call(action, params, { grant, grantJti, obo } = {}) {
    this.n += 1;
    const jti = 'ticket-' + this.n;
    const ticket = this.token('AT1', {
      v: 1, typ: 'ticket', sub: SUB, tool: 'helpdesk', cv: 1, mode: 'active',
      act: ['atrium.ping', 'atrium.receipt', 'atrium.panel.pull', 'atrium.panel.answer', 'atrium.events.pull',
        'tickets.list', 'tickets.set_priority'],
      cnf: core.b64u(raw(this.probe.publicKey)), rl: { calls_per_min: 100, panel_per_user_hour: 2 },
      iat: this.now, exp: this.now + 600, jti
    });
    const body = Buffer.from(JSON.stringify({ params }));
    const nonce = core.b64u(crypto.randomBytes(16));
    const date = String(this.now);
    const urlPath = '/.atrium/v1/call/' + action;
    const headers = { 'Content-Type': 'application/json', 'Atrium-Ticket': ticket, 'Atrium-Date': date, 'Atrium-Nonce': nonce };
    if (grant) headers['Atrium-Grant'] = grant;
    if (obo) headers['Atrium-On-Behalf-Of'] = obo;
    headers['Atrium-Signature'] = core.b64u(crypto.sign(null,
      core.signingString('POST', urlPath, date, nonce, body, jti, grantJti, obo), this.probe.privateKey));
    const res = await send(this.server, { method: 'POST', path: urlPath, headers }, body);
    return { status: res.status, data: JSON.parse(res.body) };
  }

  grant(action, params, jti) {
    const body = Buffer.from(JSON.stringify({ params }));
    return this.token('AG1', { v: 1, typ: 'grant', sub: SUB, tool: 'helpdesk', cv: 1, act: action, bh: core.bodyHash(body),
      apv: 'ap_1', iat: this.now, exp: this.now + 600, jti });
  }

  async panel(method, urlPath, { user, body, header = true } = {}) {
    const headers = {};
    if (header) headers['X-Atrium-Panel'] = '1';
    if (user) headers['X-Test-User'] = user;
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await send(this.server, { method, path: urlPath, headers }, body === undefined ? undefined : JSON.stringify(body));
    return { status: res.status, data: JSON.parse(res.body) };
  }
}

test('panel questions, on-behalf-of runs and plain-text answers', quiet(async () => {
  const h = await new Harness().start();
  try {
    assert.equal((await h.panel('POST', '/.atrium/v1/panel/ask', { user: 'u1', body: { text: 'hi' }, header: false })).status, 403);
    assert.equal((await h.panel('POST', '/.atrium/v1/panel/ask', { body: { text: 'hi' } })).status, 401);
    let res = await h.panel('GET', '/.atrium/v1/panel/status', { user: 'u1' });
    assert.deepEqual(res.data, { enabled: true, team_online: false });
    res = await h.panel('POST', '/.atrium/v1/panel/ask', { user: 'u1', body: { text: 'why is 42 open?', page: { path: '/t/42', record_id: 'ticket:42' } } });
    const qid = res.data.question_id;
    assert.match(qid, /^q_[A-Za-z0-9_-]{16}$/);
    assert.equal((await h.panel('POST', '/.atrium/v1/panel/ask', { user: 'u1', body: { text: 'x', extra: 1 } })).status, 422);
    assert.equal((await h.panel('GET', '/.atrium/v1/panel/questions/' + qid, { user: 'u2' })).status, 404);
    res = await h.call('atrium.panel.pull', {});
    assert.equal(res.data.result.length, 1);
    assert.deepEqual(res.data.result[0].tool_user, { id: 'u1', display: 'User', roles: ['agent'] });
    assert.deepEqual(res.data.result[0].page, { path: '/t/42', record_id: 'ticket:42' });
    assert.equal((await h.panel('GET', '/.atrium/v1/panel/status', { user: 'u1' })).data.team_online, true);
    res = await h.call('tickets.list', {}, { obo: qid });
    assert.deepEqual(res.data.result, { as: 'atrium-team', for: 'u1' });
    res = await h.call('tickets.list', {}, { obo: 'q_unknown' });
    assert.deepEqual([res.status, res.data.code], [403, 'forbidden_on_behalf']);
    const params = { ticket_id: 42, priority: 'high' };
    res = await h.call('tickets.set_priority', params, { grant: h.grant('tickets.set_priority', params, 'g-obo'), grantJti: 'g-obo', obo: qid });
    assert.deepEqual([res.status, res.data.code], [403, 'forbidden_on_behalf']);
    const answer = '<script>alert(1)</script>\nplain text';
    res = await h.call('atrium.panel.answer', { question_id: qid, text: answer, status: 'answered', by: 'desk' });
    assert.deepEqual(res.data.result, { ok: true });
    res = await h.panel('GET', '/.atrium/v1/panel/questions/' + qid, { user: 'u1' });
    assert.equal(res.data.answer, answer);
    assert.equal(res.data.status, 'answered');
    assert.equal((await h.call('tickets.list', {}, { obo: qid })).status, 403); // answered: no longer open
    await h.panel('POST', '/.atrium/v1/panel/ask', { user: 'u1', body: { text: 'two' } });
    assert.equal((await h.panel('POST', '/.atrium/v1/panel/ask', { user: 'u1', body: { text: 'three' } })).status, 429);
    h.now += 121; // the team has not pulled for two minutes
    res = await h.panel('GET', '/.atrium/v1/panel/status', { user: 'u2' });
    assert.equal(res.data.team_online, false);
  } finally {
    h.server.close();
  }
}));

test('grants are single use across a restart, and granted calls cause their events', quiet(async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'atrium-grants-')), 'grants.json');
  const first = await new Harness({ grants: new core.FileGrants(file) }).start();
  const params = { ticket_id: 7, priority: 'low' };
  const grant = first.grant('tickets.set_priority', params, 'g-1');
  try {
    let res = await first.call('tickets.set_priority', params);
    assert.deepEqual([res.status, res.data.code], [403, 'grant_required']);
    res = await first.call('tickets.set_priority', params, { grant, grantJti: 'g-1' });
    assert.equal(res.status, 200);
    assert.deepEqual(res.data.result, { priority: 'low' });
    assert.equal(res.data.receipt.status, 'executed');
    res = await first.call('tickets.set_priority', { ticket_id: 8, priority: 'low' }, { grant, grantJti: 'g-1' });
    assert.deepEqual([res.status, res.data.code], [403, 'grant_mismatch']);
    res = await first.call('atrium.events.pull', { after: 0 });
    assert.equal(res.data.result.events.length, 1);
    assert.deepEqual(res.data.result.events[0].cause, { jti: 'g-1' });
    assert.equal(first.bridge.emit('helpdesk.undeclared', {}), false);
    assert.equal(first.bridge.emit('helpdesk.ticket.updated', { big: 'x'.repeat(17 * 1024) }), false);
  } finally {
    first.server.close();
  }
  const second = await new Harness({ grants: new core.FileGrants(file), atrium: first.atrium }).start();
  try {
    let res = await second.call('tickets.set_priority', params, { grant, grantJti: 'g-1' });
    assert.deepEqual([res.status, res.data.code], [409, 'grant_used']);
    res = await second.call('atrium.receipt', { jti: 'g-1' });
    assert.equal(res.data.result.status, 'executed');
    res = await second.call('atrium.receipt', { jti: 'g-2' });
    assert.deepEqual(res.data.result, { status: 'unused' });
  } finally {
    second.server.close();
  }
}));

test('marking is the authoritative single-use check, even for calls racing with one grant', quiet(async () => {
  class Racing extends core.MemoryGrants {
    used() {
      return false;
    }
  }
  const h = await new Harness({ grants: new Racing() }).start();
  try {
    const params = { ticket_id: 3, priority: 'high' };
    const grant = h.grant('tickets.set_priority', params, 'g-race');
    const answers = await Promise.all([1, 2, 3].map(() => h.call('tickets.set_priority', params, { grant, grantJti: 'g-race' })));
    assert.deepEqual(answers.map((a) => a.status).sort(), [200, 409, 409]);
  } finally {
    h.server.close();
  }
}));

test('the outbox is bounded and emit never throws', quiet(async () => {
  const h = new Harness();
  const bridge = new core.Bridge(h.glue);
  for (let i = 0; i < 1000; i++) assert.equal(bridge.emit('helpdesk.ticket.updated', { i }), true);
  assert.equal(bridge.emit('helpdesk.ticket.updated', { i: 1000 }), false);
  assert.equal(bridge.drops, 1);
  const circular = {};
  circular.self = circular;
  assert.equal(bridge.emit('helpdesk.ticket.updated', circular), false);
  assert.equal(core.emit('helpdesk.ticket.updated', {}), false); // the module-level default bridge is this full one
}));

test('the source allow list', quiet(async () => {
  const outside = await new Harness({ allow: '10.0.0.0/8' }).start();
  const inside = await new Harness({ allow: '127.0.0.0/8, ::1/128' }).start();
  try {
    const res = await outside.call('atrium.ping', {});
    assert.deepEqual([res.status, res.data.code], [403, 'source_not_allowed']);
    assert.equal((await inside.call('atrium.ping', {})).status, 200);
  } finally {
    outside.server.close();
    inside.server.close();
  }
}));

// ---- the widget in a minimal DOM ----

class FakeNode {
  constructor() {
    this.childNodes = [];
    this.parentNode = null;
    this.listeners = {};
  }

  get firstChild() {
    return this.childNodes[0] || null;
  }

  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  removeChild(child) {
    this.childNodes.splice(this.childNodes.indexOf(child), 1);
    child.parentNode = null;
    return child;
  }

  get textContent() {
    return this.childNodes.map((c) => c.textContent).join('');
  }

  set textContent(value) {
    this.childNodes = [];
    if (value !== '') this.appendChild(new FakeText(String(value)));
  }

  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }

  dispatch(type, init = {}) {
    const event = Object.assign({ type, target: this, stopped: false, preventDefault() {}, stopPropagation() { this.stopped = true; } }, init);
    for (let node = this; node && !event.stopped; node = node.parentNode || node.host) {
      for (const fn of node.listeners[type] || []) fn.call(node, event);
    }
    return event;
  }

  * walk() {
    yield this;
    for (const child of this.childNodes) yield* child.walk();
    if (this.shadowRoot) yield* this.shadowRoot.walk();
  }
}

class FakeText extends FakeNode {
  constructor(data) {
    super();
    this.data = data;
  }

  get textContent() {
    return this.data;
  }

  * walk() {
    yield this;
  }
}

class FakeElement extends FakeNode {
  constructor(tag, doc) {
    super();
    this.tagName = tag.toUpperCase();
    this.attributes = new Map();
    this.doc = doc;
    this.value = '';
  }

  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  hasAttribute(name) { return this.attributes.has(name); }
  removeAttribute(name) { this.attributes.delete(name); }
  focus() { this.doc.activeElement = this; }
  attachShadow() {
    this.shadowRoot = new FakeNode();
    this.shadowRoot.host = this;
    this.shadowRoot.adoptedStyleSheets = [];
    return this.shadowRoot;
  }

  set innerHTML(value) { throw new Error('the widget must never set innerHTML'); }
  get innerHTML() { throw new Error('the widget must never read innerHTML'); }
  insertAdjacentHTML() { throw new Error('the widget must never insert HTML'); }
}

function widget(routes) {
  const doc = { readyState: 'complete', currentScript: { src: 'https://tool.test/app/.atrium/panel.js' }, activeElement: null };
  doc.createElement = (tag) => new FakeElement(tag, doc);
  doc.body = doc.createElement('body');
  doc.addEventListener = () => {};
  doc.querySelector = (selector) => {
    assert.equal(selector, '[data-atrium-context]');
    for (const node of doc.body.walk()) if (node.hasAttribute && node.hasAttribute('data-atrium-context')) return node;
    return null;
  };
  const context = doc.createElement('div');
  context.setAttribute('data-atrium-context', 'ticket:42');
  doc.body.appendChild(context);
  const store = new Map();
  const requests = [];
  const sandbox = {
    document: doc, location: { pathname: '/tickets/42' }, console, setTimeout, clearTimeout,
    sessionStorage: { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)) },
    CSSStyleSheet: class { replaceSync(text) { this.text = text; } },
    fetch: async (url, init) => {
      requests.push({ url, init });
      const [status, data] = routes(url, init);
      return { status, json: async () => data };
    }
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(path.join(TEMPLATES, 'panel', 'panel.js'), 'utf8'), sandbox);
  const shadow = () => doc.body.childNodes.find((n) => n.hasAttribute && n.hasAttribute('data-atrium-team'));
  const find = (predicate) => [...shadow().shadowRoot.walk()].find(predicate);
  return { doc, sandbox, requests, shadow, find };
}

test('the widget renders answers as text, keeps the keyboard and asks with the page context', async () => {
  const html = '<script>alert(1)</script><img src=x onerror=alert(2)>';
  let state = { status: 'waiting' };
  const w = widget((url, init) => {
    if (url.endsWith('/panel/status')) return [200, { enabled: true, team_online: true }];
    if (url.endsWith('/panel/ask')) return [200, { question_id: 'q_1' }];
    if (url.endsWith('/panel/questions/q_1')) return [200, Object.assign({ id: 'q_1', text: 'What is <b>this</b>?' }, state)];
    return [404, {}];
  });
  await w.sandbox.AtriumTeam.ready();
  assert.ok(w.shadow(), 'the button is rendered for a signed-in user');
  assert.ok(w.requests.every((r) => r.url.startsWith('https://tool.test/app/.atrium/v1/panel/')));
  assert.ok(w.requests.every((r) => r.init.headers['X-Atrium-Panel'] === '1' && r.init.credentials === 'same-origin'));
  const button = w.find((n) => n.tagName === 'BUTTON' && n.textContent === 'Ask the team');
  const drawer = w.find((n) => n.tagName === 'SECTION');
  assert.equal(drawer.getAttribute('role'), 'dialog');
  assert.ok(w.find((n) => n.textContent === 'AI team supervised by Atrium. It can look things up and draft; changes need approval in Atrium.'));
  button.dispatch('click');
  assert.equal(drawer.hasAttribute('hidden'), false);
  assert.equal(button.getAttribute('aria-expanded'), 'true');
  assert.equal(w.doc.activeElement.tagName, 'TEXTAREA');
  await w.sandbox.AtriumTeam.ask('What is <b>this</b>?');
  const asked = w.requests.find((r) => r.url.endsWith('/panel/ask'));
  assert.deepEqual(JSON.parse(asked.init.body), { text: 'What is <b>this</b>?', page: { path: '/tickets/42', record_id: 'ticket:42' } });
  state = { status: 'answered', answer: html, by: '<b>desk</b>' };
  await w.sandbox.AtriumTeam.refresh();
  const answer = w.find((n) => n.getAttribute && n.getAttribute('class') === 'answer');
  assert.equal(answer.textContent, html);
  assert.ok(answer.childNodes.every((c) => c instanceof FakeText), 'the answer is a text node, never markup');
  assert.equal(w.find((n) => n.getAttribute && n.getAttribute('class') === 'by').textContent, '- <b>desk</b>');
  assert.equal([...w.shadow().shadowRoot.walk()].filter((n) => n.tagName === 'SCRIPT' || n.tagName === 'IMG').length, 0);
  assert.equal(w.find((n) => n.getAttribute && n.getAttribute('aria-live') === 'polite').textContent, 'Answered');
  w.doc.activeElement.dispatch('keydown', { key: 'Escape' });
  assert.equal(drawer.hasAttribute('hidden'), true);
  assert.equal(w.doc.activeElement, button, 'Esc closes the drawer and returns the focus to the button');
});

test('the widget shows nothing without a session or when the panel is off', async () => {
  for (const status of [[401, { ok: false, code: 'no_session' }], [200, { enabled: false, team_online: false }]]) {
    const w = widget(() => status);
    await w.sandbox.AtriumTeam.ready();
    assert.equal(w.shadow(), undefined);
  }
  const source = fs.readFileSync(path.join(TEMPLATES, 'panel', 'panel.js'), 'utf8');
  for (const banned of ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'eval(', 'new Function', 'href']) {
    assert.equal(source.includes(banned), false, banned);
  }
});
