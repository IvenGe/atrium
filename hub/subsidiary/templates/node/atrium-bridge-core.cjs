/* Atrium bridge core for Node.js >= 16 - contract atrium-bridge/1 (Atrium's docs/SUBSIDIARIES.md has the full text).
 *
 * VENDORED FILE: Atrium adds it byte-identical and checks its SHA-256; do not edit it. Everything tool-specific lives
 * in the glue: the action handlers, currentUser(req) and the service principal. No dependencies (node:crypto).
 *
 * The bridge lets an agent team that runs in a sidecar next to this tool work inside it while Atrium keeps every
 * decision. It holds NO secret: it verifies Atrium's Ed25519 signatures with the public keys in ATRIUM_BRIDGE_KEYS.
 * Every sidecar call carries a short-lived ticket, a signature made with the sidecar's own key and, for changes, a
 * single-use grant Atrium signs after a person approved the exact request.
 *
 * Mount it before any body parser (it needs the raw body bytes) and after the session middleware (the panel needs
 * the signed-in user):
 *     const atriumBridge = require('./atrium/atrium-bridge-core.cjs');   // or import from the .mjs
 *     app.use(atriumBridge.express(glue));                                // Express and Connect
 *     http.createServer(atriumBridge.handler(glue))                       // plain node:http
 * The tool's code queues declared events with atriumBridge.emit(name, payload). */
'use strict';

const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const path = require('path');
const { AsyncLocalStorage } = require('async_hooks');

const CONTRACT = 'atrium-bridge/1';
const CORE_VERSION = 'node/1.0.0';
const PANEL_JS_SHA256 = '169f62fab9b60d01232e02f5f4feb89e81172819c5fe0e3a4042e6a88ef03898';

const HEALTH_PATH = '/.atrium/v1/health';
const CALL_PREFIX = '/.atrium/v1/call/';
const PANEL_JS_PATH = '/.atrium/panel.js';
const PANEL_ASK_PATH = '/.atrium/v1/panel/ask';
const PANEL_QUESTION_PREFIX = '/.atrium/v1/panel/questions/';
const PANEL_STATUS_PATH = '/.atrium/v1/panel/status';

const CLOCK_LEEWAY = 60;
const NONCE_TTL = 180;
const NONCE_CAPACITY = 10000;
const GRANT_JTI_KEEP = 3600;
const MAX_TOKEN_PAYLOAD = 4096;
const MAX_TOKEN = 6144;
const MAX_KEYS = 2;
const MAX_BODY = 64 * 1024;
const MAX_RESPONSE = 1024 * 1024;
const MAX_ACTIONS = 40;
const MAX_PROPERTIES = 20;
const MAX_STRING = 10000;
const MAX_ITEMS = 100;
const MAX_ENUM = 100;
const MAX_SAFE_INT = Number.MAX_SAFE_INTEGER;
const WAIT_MAX = 25;
const DEFAULT_RATE = { calls_per_min: 30, panel_per_user_hour: 10 };
const PANEL_TEXT_MAX = 2000;
const PANEL_PAGE_LIMITS = { path: 300, record_id: 120 };
const PANEL_OPEN_MAX = 200;
const PANEL_EXPIRY = 30 * 60;
const PANEL_ONLINE_WINDOW = 60;
const PANEL_OFFLINE_ANSWER = 120;
const PANEL_PULL_MAX = 20;
const PANEL_UNAVAILABLE = 'The team is not available right now';
const OUTBOX_MAX = 1000;
const OUTBOX_TTL = 24 * 3600;
const EVENT_PAYLOAD_MAX = 16 * 1024;
const EVENTS_PULL_MAX = 100;

const STATUS = {
  bad_ticket: 401, bad_signature: 401, expired: 401, replay: 401,
  action_not_allowed: 403, probation: 403, grant_required: 403, grant_mismatch: 403,
  forbidden_on_behalf: 403, source_not_allowed: 403,
  grant_used: 409, too_large: 413, bad_params: 422, rate_limited: 429,
  not_configured: 503, busy: 503
};
const PANEL_STATUS = {
  no_session: 401, panel_header_required: 403, not_found: 404, too_large: 413,
  bad_params: 422, rate_limited: 429, busy: 503, not_configured: 503
};
const NEEDS_GRANT = ['write', 'admin'];
const RISKS = ['read', 'propose', 'write', 'admin'];

function object(properties, required) {
  return { type: 'object', additionalProperties: false, properties: properties || {}, required: required || [] };
}

const BUILTINS = {
  'atrium.ping': { risk: 'read', params: object() },
  'atrium.describe': { risk: 'read', params: object() },
  'atrium.noop_write': { risk: 'write', params: object({ echo: { type: 'string', maxLength: 64 } }, ['echo']) },
  'atrium.receipt': { risk: 'read', params: object({ jti: { type: 'string', maxLength: 64 } }, ['jti']) },
  'atrium.panel.pull': { risk: 'read', params: object({ wait: { type: 'integer', minimum: 0, maximum: WAIT_MAX } }) },
  'atrium.panel.answer': {
    risk: 'propose',
    params: object({
      question_id: { type: 'string', maxLength: 64 },
      text: { type: 'string', maxLength: 4000 },
      status: { enum: ['answered', 'escalated', 'declined', 'working'] },
      by: { type: 'string', maxLength: 80 }
    }, ['question_id', 'text', 'status'])
  },
  'atrium.events.pull': {
    risk: 'read',
    params: object({
      after: { type: 'integer', minimum: 0, maximum: MAX_SAFE_INT },
      wait: { type: 'integer', minimum: 0, maximum: WAIT_MAX }
    })
  }
};
const PROBATION_BUILTINS = ['atrium.ping', 'atrium.describe', 'atrium.noop_write', 'atrium.receipt'];

const ACTION_ID_RE = /^[a-z][a-z0-9_.]{2,57}$/;
const TOOL_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SUBSIDIARY_ID_RE = /^sub_[0-9a-f]{12}$/;
const PARAM_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
const DATE_RE = /^[0-9]{1,12}$/;
const QUESTION_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const B64U_RE = /^[A-Za-z0-9_-]*$/;
const TEXT_CONTROL = /[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]/g;
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const cause = new AsyncLocalStorage();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const has = (obj, key) => obj !== null && typeof obj === 'object' && Object.prototype.hasOwnProperty.call(obj, key);
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const sha256Hex = (data) => crypto.createHash('sha256').update(data).digest('hex');

class Refused extends Error {
  constructor(code) {
    super(code);
    this.code = code;
    this.status = STATUS[code] || PANEL_STATUS[code];
  }
}

// ---------------------------------------------------------------------------------------------------------------
// encodings, keys, tickets and grants
// ---------------------------------------------------------------------------------------------------------------

function b64u(data) {
  return Buffer.from(data).toString('base64url');
}

function b64uDecode(text) {
  if (typeof text !== 'string' || !B64U_RE.test(text) || text.length % 4 === 1) throw new Error('not base64url');
  const data = Buffer.from(text, 'base64url');
  if (b64u(data) !== text) throw new Error('not canonical base64url');
  return data;
}

function publicKey(text) {
  const raw = b64uDecode(text);
  if (raw.length !== 32) throw new Error('an Ed25519 public key is 32 bytes');
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

function parseKeys(value) {
  const items = String(value || '').split(',').map((k) => k.trim()).filter(Boolean);
  if (items.length < 1 || items.length > MAX_KEYS) throw new Error('ATRIUM_BRIDGE_KEYS holds one or two keys');
  return items.map(publicKey);
}

function verifyWith(key, signature, message) {
  try {
    return crypto.verify(null, message, key, signature);
  } catch (e) {
    return false;
  }
}

function parseJson(bytes) {
  return JSON.parse(decoder.decode(bytes));
}

function verifyToken(token, prefix, keys, code) {
  if (typeof token !== 'string' || token.length > MAX_TOKEN || !keys.length) throw new Refused(code);
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== prefix || !B64U_RE.test(parts[1])) throw new Refused(code);
  let signature;
  try {
    signature = b64uDecode(parts[2]);
  } catch (e) {
    throw new Refused(code);
  }
  const signed = Buffer.from(parts[0] + '.' + parts[1], 'ascii');
  if (!keys.slice(0, MAX_KEYS).some((key) => verifyWith(key, signature, signed))) throw new Refused(code);
  let payload;
  try {
    const raw = b64uDecode(parts[1]);
    if (raw.length > MAX_TOKEN_PAYLOAD) throw new Error('too large');
    payload = parseJson(raw);
  } catch (e) {
    throw new Refused(code);
  }
  if (!isObject(payload) || payload.v !== 1) throw new Refused(code);
  return payload;
}

function ticketFieldsOk(p) {
  const ok = p.typ === 'ticket' && typeof p.sub === 'string' && typeof p.tool === 'string' && isInt(p.cv)
    && (p.mode === 'probation' || p.mode === 'active') && Array.isArray(p.act)
    && p.act.length <= MAX_ACTIONS + Object.keys(BUILTINS).length && p.act.every((a) => typeof a === 'string')
    && typeof p.cnf === 'string' && isInt(p.iat) && isInt(p.exp)
    && typeof p.jti === 'string' && p.jti.length > 0 && p.jti.length <= 64
    && isObject(p.rl) && Object.values(p.rl).every((v) => isInt(v) && v >= 0);
  if (!ok) return false;
  try {
    publicKey(p.cnf);
    return true;
  } catch (e) {
    return false;
  }
}

function grantFieldsOk(p) {
  return p.typ === 'grant' && typeof p.sub === 'string' && typeof p.tool === 'string' && isInt(p.cv)
    && typeof p.act === 'string' && typeof p.bh === 'string' && typeof p.apv === 'string'
    && isInt(p.iat) && isInt(p.exp) && typeof p.jti === 'string' && p.jti.length > 0 && p.jti.length <= 64;
}

function bodyHash(body) {
  return b64u(crypto.createHash('sha256').update(body).digest());
}

function signingString(method, urlPath, date, nonce, body, ticketJti, grantJti, onBehalfOf) {
  return Buffer.from([CONTRACT, method.toUpperCase(), urlPath, date, nonce, sha256Hex(body), ticketJti,
    grantJti || '-', onBehalfOf || '-'].join('\n'), 'utf8');
}

function verifySignature(cnf, signature, message) {
  try {
    return verifyWith(publicKey(cnf), b64uDecode(signature), message);
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// params: the JSON Schema subset
// ---------------------------------------------------------------------------------------------------------------

function kind(prop) {
  if (!isObject(prop)) return null;
  if (has(prop, 'enum')) return 'enum';
  return ['string', 'integer', 'boolean', 'array'].includes(prop.type) ? prop.type : null;
}

function codePoints(text) {
  let n = 0;
  for (const _ of text) n++; // eslint-disable-line no-unused-vars
  return n;
}

const ALLOWED = {
  string: ['type', 'maxLength', 'minLength'], integer: ['type', 'minimum', 'maximum'], boolean: ['type'],
  enum: ['type', 'enum'], array: ['type', 'items', 'maxItems']
};

function propOk(prop, item) {
  const k = kind(prop);
  if (k === null || (item && k === 'array')) return false;
  if (Object.keys(prop).some((key) => key !== 'description' && !ALLOWED[k].includes(key))) return false;
  if (k === 'string') {
    const top = prop.maxLength;
    const low = has(prop, 'minLength') ? prop.minLength : 0;
    return isInt(top) && top >= 1 && top <= MAX_STRING && isInt(low) && low >= 0 && low <= top;
  }
  if (k === 'integer') {
    const lo = has(prop, 'minimum') ? prop.minimum : -MAX_SAFE_INT;
    const hi = has(prop, 'maximum') ? prop.maximum : MAX_SAFE_INT;
    return isInt(lo) && isInt(hi) && -MAX_SAFE_INT <= lo && lo <= hi && hi <= MAX_SAFE_INT;
  }
  if (k === 'enum') {
    const values = prop.enum;
    if (!Array.isArray(values) || values.length < 1 || values.length > MAX_ENUM) return false;
    const strings = values.every((v) => typeof v === 'string');
    const ints = values.every((v) => Number.isSafeInteger(v));
    return (strings || ints) && new Set(values).size === values.length;
  }
  if (k === 'array') return isInt(prop.maxItems) && prop.maxItems >= 1 && prop.maxItems <= MAX_ITEMS && propOk(prop.items, true);
  return true;
}

function schemaOk(schema) {
  if (!isObject(schema) || schema.type !== 'object' || schema.additionalProperties !== false) return false;
  const known = ['type', 'additionalProperties', 'properties', 'required', 'description'];
  if (Object.keys(schema).some((key) => !known.includes(key))) return false;
  const props = has(schema, 'properties') ? schema.properties : {};
  const required = has(schema, 'required') ? schema.required : [];
  if (!isObject(props) || Object.keys(props).length > MAX_PROPERTIES || !Array.isArray(required)) return false;
  if (Object.keys(props).some((n) => !PARAM_NAME_RE.test(n)) || required.some((r) => !has(props, r))) return false;
  return Object.keys(props).every((n) => propOk(props[n], false));
}

function checkValue(prop, value) {
  const k = kind(prop);
  if (k === 'array') {
    if (!Array.isArray(value) || value.length > prop.maxItems) return [false];
    const out = [];
    for (const v of value) {
      const [ok, item] = checkValue(prop.items, v);
      if (!ok) return [false];
      out.push(item);
    }
    return [true, out];
  }
  if (k === 'boolean') return [typeof value === 'boolean', value];
  if (k === 'string') {
    if (typeof value !== 'string') return [false];
    const n = codePoints(value);
    return [n >= (has(prop, 'minLength') ? prop.minLength : 0) && n <= prop.maxLength, value];
  }
  if (k === 'integer') {
    const lo = has(prop, 'minimum') ? prop.minimum : -MAX_SAFE_INT;
    const hi = has(prop, 'maximum') ? prop.maximum : MAX_SAFE_INT;
    return [Number.isSafeInteger(value) && value >= lo && value <= hi, value === 0 ? 0 : value];
  }
  if (k === 'enum') {
    const ok = (typeof value === 'string' || Number.isSafeInteger(value)) && prop.enum.includes(value);
    return [ok, value === 0 ? 0 : value];
  }
  return [false];
}

function validateParams(schema, params) {
  if (!isObject(params)) throw new Refused('bad_params');
  const props = has(schema, 'properties') ? schema.properties : {};
  const required = has(schema, 'required') ? schema.required : [];
  if (Object.keys(params).some((key) => !has(props, key)) || required.some((r) => !has(params, r))) {
    throw new Refused('bad_params');
  }
  const out = {};
  for (const key of Object.keys(params)) {
    const [ok, value] = checkValue(props[key], params[key]);
    if (!ok) throw new Refused('bad_params');
    Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parseBodyJson(body) {
  try {
    return parseJson(body);
  } catch (e) {
    throw new Refused('bad_params');
  }
}

function parseBody(body) {
  const data = parseBodyJson(body);
  const keys = isObject(data) ? Object.keys(data) : [];
  if (keys.length !== 1 || keys[0] !== 'params' || !isObject(data.params)) throw new Refused('bad_params');
  return data.params;
}

// ---------------------------------------------------------------------------------------------------------------
// stores
// ---------------------------------------------------------------------------------------------------------------

class NonceCache {
  constructor(ttl = NONCE_TTL, capacity = NONCE_CAPACITY) {
    this.ttl = ttl;
    this.capacity = capacity;
    this.seen = new Map();
  }

  get size() {
    return this.seen.size;
  }

  add(nonce, now) {
    for (const [first, at] of this.seen) {
      if (at > now - this.ttl) break;
      this.seen.delete(first);
    }
    if (this.seen.has(nonce)) throw new Refused('replay');
    if (this.seen.size >= this.capacity) throw new Refused('busy');
    this.seen.set(nonce, now);
  }
}

/* Used grant jtis and their receipts in memory. A tool with storage persists them (FileGrants, or its own object
 * with the same four methods - they may return Promises), so a restart cannot replay a grant. mark() is the
 * authoritative single-use check: it records the jti and answers true at once, or false when it was already used. */
class MemoryGrants {
  constructor() {
    this.rows = new Map();
  }

  used(jti) {
    return this.rows.has(jti);
  }

  mark(jti, keepUntil, now) {
    for (const [key, row] of this.rows) if (row.keep_until <= now) this.rows.delete(key);
    if (this.rows.has(jti)) return false;
    this.rows.set(jti, { status: 'started', at: now, keep_until: keepUntil });
    return true;
  }

  record(jti, status, at) {
    const row = this.rows.get(jti);
    if (row) Object.assign(row, { status, at });
  }

  receipt(jti) {
    const row = this.rows.get(jti);
    return row ? { status: row.status, at: row.at } : null;
  }
}

class FileGrants extends MemoryGrants {
  constructor(file) {
    super();
    this.file = file;
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      for (const [jti, row] of Object.entries(data)) this.rows.set(jti, row);
    } catch (e) { /* a new store */ }
  }

  save() {
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(this.rows)), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  mark(jti, keepUntil, now) {
    const marked = super.mark(jti, keepUntil, now);
    if (marked) this.save();
    return marked;
  }

  record(jti, status, at) {
    super.record(jti, status, at);
    this.save();
  }
}

// ---------------------------------------------------------------------------------------------------------------
// answers
// ---------------------------------------------------------------------------------------------------------------

function answer(status, value) {
  return {
    status,
    headers: { 'Content-Type': 'application/json', 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store' },
    body: Buffer.from(JSON.stringify(value), 'utf8')
  };
}

function refusal(code) {
  return answer(new Refused(code).status, { ok: false, code });
}

function clean(text) {
  return String(text).replace(TEXT_CONTROL, '');
}

function normalUser(value) {
  if (value === null || value === undefined || typeof value !== 'object') return null;
  const id = value.id;
  if (id === null || id === undefined || typeof id === 'boolean' || String(id).trim() === '') return null;
  let roles = value.roles || [];
  roles = (Array.isArray(roles) ? roles : [roles]).slice(0, 20).map((r) => String(r).slice(0, 60));
  const display = value.display || value.name || id;
  return { id: String(id).slice(0, 120), display: clean(display).slice(0, 120), roles };
}

function readFile(source, name) {
  if (Buffer.isBuffer(source) || source instanceof Uint8Array) return Buffer.from(source);
  if (typeof source === 'string') return fs.readFileSync(source);
  for (const dir of [__dirname, path.dirname(__dirname), path.dirname(path.dirname(__dirname)), process.cwd()]) {
    const file = path.join(dir, name);
    if (fs.existsSync(file)) return fs.readFileSync(file);
  }
  throw new Error(name + ' not found');
}

function v4(address) {
  const text = String(address || '').split('%')[0];
  return /^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(text) ? text.slice(7) : text;
}

function allowList(value) {
  const cidrs = String(value || '').split(',').map((c) => c.trim()).filter(Boolean);
  if (!cidrs.length) return null;
  const list = new net.BlockList();
  for (const cidr of cidrs) {
    const [address, bits] = cidr.split('/');
    const family = net.isIP(address);
    const prefix = bits === undefined ? (family === 4 ? 32 : 128) : Number(bits);
    if (!family || (bits !== undefined && !/^[0-9]{1,3}$/.test(bits)) || prefix > (family === 4 ? 32 : 128)) {
      throw new Error('ATRIUM_BRIDGE_ALLOW: not a CIDR list');
    }
    list.addSubnet(address, prefix, family === 4 ? 'ipv4' : 'ipv6');
  }
  return list;
}

// ---------------------------------------------------------------------------------------------------------------
// the bridge
// ---------------------------------------------------------------------------------------------------------------

const defaults = { bridge: null };
const byGlue = new WeakMap();

class Bridge {
  /* actions: {id: handler(params, ctx)} (sync or async); currentUser(req) -> {id, display, roles} | null (may be
   * async; none disables the panel); manifest / panelJs: a path or the bytes; grants: the used-grant store;
   * env: defaults to process.env; clock: seconds. */
  constructor(options = {}) {
    this.actions = Object.assign(Object.create(null), options.actions || {});
    this.currentUser = typeof options.currentUser === 'function' ? options.currentUser : null;
    const principal = typeof options.servicePrincipal === 'function' ? options.servicePrincipal() : options.servicePrincipal;
    this.principal = String(principal || 'atrium-team');
    this.clock = options.clock || (() => Date.now() / 1000);
    this.grants = options.grants || new MemoryGrants();
    this.maxWait = Math.max(0, Math.min(Number(options.maxWait === undefined ? WAIT_MAX : options.maxWait), WAIT_MAX));
    this.nonces = options.nonces || new NonceCache(); // shared when the tool runs several processes
    this.calls = [];
    this.rate = Object.assign({}, DEFAULT_RATE);
    this.questions = new Map();
    this.asked = new Map();
    this.lastPull = null;
    this.events = [];
    this.seq = 0;
    this.drops = 0;
    this.rejected = 0;
    this.problem = null;
    this.keys = [];
    this.tool = '';
    this.sub = '';
    this.allow = null;
    this.manifest = {};
    this.manifestRaw = Buffer.alloc(0);
    this.panelJs = null;
    this.panelSha = '';
    this.panelOn = false;
    this.panelRoles = [];
    this.configure(options.env || process.env, options.manifest, options.panelJs, options.panelSha256 || PANEL_JS_SHA256);
    defaults.bridge = this;
  }

  configure(env, manifest, panelJs, panelSha256) {
    try {
      this.keys = parseKeys(env.ATRIUM_BRIDGE_KEYS);
      this.tool = String(env.ATRIUM_TOOL_ID || '');
      this.sub = String(env.ATRIUM_SUBSIDIARY_ID || '');
      if (!TOOL_ID_RE.test(this.tool) || !SUBSIDIARY_ID_RE.test(this.sub)) {
        throw new Error('ATRIUM_TOOL_ID or ATRIUM_SUBSIDIARY_ID is missing or malformed');
      }
      this.allow = allowList(env.ATRIUM_BRIDGE_ALLOW);
      this.manifestRaw = readFile(manifest, 'atrium-bridge.json');
      this.manifest = parseJson(this.manifestRaw);
      this.checkManifest();
    } catch (e) {
      this.keys = [];
      this.problem = ('not configured: ' + (e && e.message)).slice(0, 300);
      console.warn('Atrium bridge ' + this.problem);
      return;
    }
    const panelEnv = String(env.ATRIUM_PANEL || '').trim().toLowerCase();
    this.panelRoles = String(env.ATRIUM_PANEL_ROLES || '').split(',').map((r) => r.trim()).filter(Boolean);
    try {
      const raw = readFile(panelJs === undefined || panelJs === null ? path.join(__dirname, 'panel.js') : panelJs, 'panel.js');
      if (sha256Hex(raw) !== panelSha256) throw new Error('panel.js is not the vendored widget (SHA-256 differs)');
      this.panelJs = raw;
      this.panelSha = panelSha256;
    } catch (e) {
      console.warn('Atrium bridge panel off: ' + String(e && e.message).slice(0, 200));
    }
    this.panelOn = panelEnv !== 'off' && this.currentUser !== null && this.panelJs !== null
      && Boolean(isObject(this.manifest.panel) && this.manifest.panel.enabled === true);
  }

  checkManifest() {
    const m = this.manifest;
    if (!isObject(m) || m.contract !== CONTRACT || m.tool_id !== this.tool) {
      throw new Error("atrium-bridge.json is not this tool's atrium-bridge/1 manifest");
    }
    const actions = has(m, 'actions') ? m.actions : [];
    if (!Array.isArray(actions) || actions.length > MAX_ACTIONS) throw new Error('atrium-bridge.json lists too many actions');
    const names = isObject(m.events) && has(m.events, 'names') ? m.events.names : [];
    if (!Array.isArray(names) || !names.every((n) => typeof n === 'string')) {
      throw new Error('atrium-bridge.json events.names is a list of names');
    }
    for (const a of actions) {
      if (!isObject(a) || typeof a.id !== 'string' || !ACTION_ID_RE.test(a.id) || a.id.startsWith('atrium.')
          || !RISKS.includes(a.risk) || !schemaOk(a.params)) {
        throw new Error('atrium-bridge.json action ' + JSON.stringify(String(isObject(a) ? a.id : '').slice(0, 60))
          + ' breaks the contract');
      }
      if (!has(this.actions, a.id)) console.warn('Atrium bridge: the glue has no handler for ' + a.id);
    }
  }

  get ready() {
    return this.keys.length > 0;
  }

  manifestSha256() {
    return sha256Hex(this.manifestRaw);
  }

  spec(action) {
    if (has(BUILTINS, action)) return Object.assign({ id: action }, BUILTINS[action]);
    const found = (this.manifest.actions || []).find((a) => a.id === action);
    return found && has(this.actions, action) ? found : null;
  }

  /* req: {method, path (from "/.atrium/" on), query, headers (lower case), body (Buffer), remote, native, oversize}
   * -> {status, headers, body} */
  async handle(req) {
    try {
      const route = this.route(req);
      if (route !== 'call' && route !== 'panel') return route;
      if (route === 'panel') {
        const user = this.currentUser ? await this.currentUser(req.native) : null;
        return this.panel(req, normalUser(user));
      }
      const call = await this.verify(req);
      const [result, status] = await this.run(call);
      return await this.finish(call, result, status);
    } catch (e) {
      if (e instanceof Refused) return refusal(e.code);
      console.error('Atrium bridge: internal error', e && e.message);
      return answer(500, { ok: false, code: 'failed' });
    }
  }

  route(req) {
    const method = String(req.method || 'GET').toUpperCase();
    const p = req.path;
    if (p === HEALTH_PATH && method === 'GET') return answer(200, { status: 'ok' });
    if (!this.ready) throw new Refused('not_configured');
    if (p === PANEL_JS_PATH && method === 'GET') {
      if (this.panelJs === null) return answer(404, { ok: false, code: 'not_found' });
      const etag = '"' + this.panelSha + '"';
      const headers = {
        'Content-Type': 'application/javascript; charset=utf-8', 'X-Content-Type-Options': 'nosniff',
        ETag: etag, 'Cache-Control': 'no-cache'
      };
      if ((req.headers || {})['if-none-match'] === etag) return { status: 304, headers, body: Buffer.alloc(0) };
      return { status: 200, headers, body: this.panelJs };
    }
    if (method === 'POST' && p.startsWith(CALL_PREFIX)) return 'call';
    if ((method === 'POST' && p === PANEL_ASK_PATH)
        || (method === 'GET' && (p === PANEL_STATUS_PATH || p.startsWith(PANEL_QUESTION_PREFIX)))) return 'panel';
    return answer(404, { ok: false, code: 'not_found' });
  }

  // ---- the verification order (one code path for every call) ----

  async verify(req) {
    const action = req.path.slice(CALL_PREFIX.length);
    const now = Math.floor(this.clock());
    const h = req.headers || {};
    const body = req.body || Buffer.alloc(0);
    if (this.allow && !this.sourceAllowed(req.remote)) throw new Refused('source_not_allowed'); // 1
    if (req.oversize || body.length > MAX_BODY) throw new Refused('too_large');
    const ticket = this.open(h['atrium-ticket'], 'AT1', 'bad_ticket'); // 2
    if (!ticketFieldsOk(ticket)) throw new Refused('bad_ticket');
    this.checkTicket(ticket, now);
    const grantToken = h['atrium-grant']; // 3
    const obo = h['atrium-on-behalf-of'];
    let grant = null;
    if (grantToken !== undefined) {
      grant = this.open(grantToken, 'AG1', 'grant_mismatch');
      if (!grantFieldsOk(grant)) throw new Refused('grant_mismatch');
    }
    const date = h['atrium-date'];
    const nonce = h['atrium-nonce'];
    const signature = h['atrium-signature'];
    if (![date, nonce, signature].every((v) => typeof v === 'string') || !DATE_RE.test(date) || !B64U_RE.test(nonce)
        || nonce.length < 16 || nonce.length > 64 || (obo !== undefined && (typeof obo !== 'string' || !QUESTION_ID_RE.test(obo)))) {
      throw new Refused('bad_signature');
    }
    const urlPath = CALL_PREFIX + action + (req.query ? '?' + req.query : '');
    const message = signingString('POST', urlPath, date, nonce, body, ticket.jti, grant ? grant.jti : null, obo);
    if (!this.signatureOk(ticket.cnf, signature, message)) throw new Refused('bad_signature');
    this.checkDate(date, now);
    this.nonce(nonce, now);
    this.rate = {
      calls_per_min: has(ticket.rl, 'calls_per_min') ? ticket.rl.calls_per_min : DEFAULT_RATE.calls_per_min,
      panel_per_user_hour: has(ticket.rl, 'panel_per_user_hour') ? ticket.rl.panel_per_user_hour : DEFAULT_RATE.panel_per_user_hour
    };
    if (ticket.mode === 'probation' && !PROBATION_BUILTINS.includes(action)) throw new Refused('probation'); // 4
    const spec = this.spec(action);
    if (!ticket.act.includes(action) || spec === null) throw new Refused('action_not_allowed');
    const params = validateParams(spec.params, parseBody(body)); // 5
    if (NEEDS_GRANT.includes(spec.risk)) { // 6
      if (grant === null) this.missingGrant();
      else await this.checkGrant(grant, action, body, now);
    }
    let user = null;
    if (obo !== undefined) user = this.onBehalf(obo, spec); // 7
    while (this.calls.length && this.calls[0] <= now - 60) this.calls.shift(); // 8
    if (this.calls.length >= this.rate.calls_per_min) throw new Refused('rate_limited');
    this.calls.push(now);
    const granted = grant !== null && NEEDS_GRANT.includes(spec.risk) ? grant : null;
    if (granted && !(await this.grants.mark(granted.jti, granted.exp + GRANT_JTI_KEEP, now))) {
      throw new Refused('grant_used'); // single use: marked (atomically) before the handler runs
    }
    const ctx = Object.freeze({
      action, principal: this.principal, user, questionId: obo === undefined ? null : obo,
      grantJti: granted ? granted.jti : null, native: req.native
    });
    return { action, spec, params, ctx, ticket, grant: granted };
  }

  // the steps a broken bridge would get wrong, as methods (the conformance tests break them one at a time)

  open(token, prefix, code) {
    return verifyToken(token, prefix, this.keys, code);
  }

  checkTicket(p, now) {
    if (p.tool !== this.tool || p.sub !== this.sub || p.iat > now + CLOCK_LEEWAY) throw new Refused('bad_ticket');
    if (p.exp <= now - CLOCK_LEEWAY) throw new Refused('expired');
  }

  signatureOk(cnf, signature, message) {
    return verifySignature(cnf, signature, message);
  }

  checkDate(date, now) {
    if (Math.abs(Number(date) - now) > CLOCK_LEEWAY) throw new Refused('expired');
  }

  nonce(nonce, now) {
    this.nonces.add(nonce, now);
  }

  missingGrant() {
    throw new Refused('grant_required');
  }

  async checkGrant(p, action, body, now) {
    const expected = Buffer.from(bodyHash(body));
    const got = Buffer.from(p.bh);
    if (p.tool !== this.tool || p.sub !== this.sub || p.act !== action || got.length !== expected.length
        || !crypto.timingSafeEqual(got, expected)) throw new Refused('grant_mismatch');
    if (p.exp <= now - CLOCK_LEEWAY) throw new Refused('expired');
    if (await this.grants.used(p.jti)) throw new Refused('grant_used');
  }

  onBehalf(questionId, spec) {
    this.sweep(Math.floor(this.clock()));
    const q = this.questions.get(questionId);
    // only read and propose actions act for a tool user, whatever a local manifest says
    if (!q || !isOpen(q) || spec.on_behalf_of !== true || !['read', 'propose'].includes(spec.risk)) {
      throw new Refused('forbidden_on_behalf');
    }
    return Object.assign({}, q.user, { roles: q.user.roles.slice() });
  }

  sourceAllowed(remote) {
    const address = v4(remote);
    const family = net.isIP(address);
    return family !== 0 && this.allow.check(address, family === 4 ? 'ipv4' : 'ipv6');
  }

  // ---- running ----

  async builtin(call) {
    const now = Math.floor(this.clock());
    const params = call.params;
    switch (call.action) {
      case 'atrium.ping':
        return {
          tool: this.tool, contract: CONTRACT, core: CORE_VERSION, manifest_sha256: this.manifestSha256(), time: now,
          drops: this.drops, rejected: this.rejected
        };
      case 'atrium.describe':
        return parseJson(this.manifestRaw);
      case 'atrium.noop_write':
        return { executed: true, echo: params.echo };
      case 'atrium.receipt': {
        const found = await this.grants.receipt(params.jti);
        if (!found) return { status: 'unused' };
        // used, but the bridge stopped before recording the outcome: it may have run - never "unused"
        return { status: found.status === 'started' ? 'unknown' : found.status, at: found.at };
      }
      case 'atrium.panel.pull':
        return this.pullQuestions(now);
      case 'atrium.panel.answer':
        return this.panelAnswer(params, now);
      case 'atrium.events.pull':
        return this.pullEvents(has(params, 'after') ? params.after : 0, now);
      default:
        throw new Error('unknown built-in');
    }
  }

  async run(call) {
    if (has(BUILTINS, call.action)) {
      let result = await this.builtin(call);
      const wait = Math.min(has(call.params, 'wait') ? call.params.wait : 0, this.maxWait);
      const deadline = Date.now() + wait * 1000;
      const empty = (r) => (call.action === 'atrium.panel.pull' ? r.length === 0
        : call.action === 'atrium.events.pull' && r.events.length === 0);
      while (empty(result) && Date.now() < deadline) {
        await sleep(200);
        result = await this.builtin(call);
      }
      return [result, 'executed'];
    }
    try {
      const result = await cause.run(call.ctx.grantJti, () => this.actions[call.action](call.params, call.ctx));
      return [result, 'executed'];
    } catch (e) {
      console.error('Atrium bridge: the handler of ' + call.action + ' failed', e && e.message);
      return [null, 'failed'];
    }
  }

  async finish(call, result, status) {
    const now = Math.floor(this.clock());
    let receipt = null;
    if (call.grant) { // 10
      await this.grants.record(call.grant.jti, status, now);
      receipt = { jti: call.grant.jti, status, at: now };
    }
    if (status === 'failed') return answer(500, { ok: false, code: 'failed', receipt });
    let out;
    try {
      out = answer(200, { ok: true, result: result === undefined ? null : result, receipt });
    } catch (e) {
      return answer(500, { ok: false, code: 'bad_result', receipt });
    }
    if (out.body.length > MAX_RESPONSE) return answer(500, { ok: false, code: 'result_too_large', receipt });
    return out;
  }

  // ---- the panel ----

  panelFor(user) {
    return this.panelOn && user !== null
      && (!this.panelRoles.length || user.roles.some((r) => this.panelRoles.includes(r)));
  }

  panel(req, user) {
    const h = req.headers || {};
    if (h['x-atrium-panel'] !== '1') throw new Refused('panel_header_required');
    if (user === null) throw new Refused('no_session');
    const now = Math.floor(this.clock());
    this.sweep(now);
    const online = this.lastPull !== null && now - this.lastPull < PANEL_ONLINE_WINDOW;
    if (req.path === PANEL_STATUS_PATH) return answer(200, { enabled: this.panelFor(user), team_online: online });
    if (!this.panelFor(user)) throw new Refused('not_found');
    if (req.path.startsWith(PANEL_QUESTION_PREFIX)) {
      const q = this.questions.get(req.path.slice(PANEL_QUESTION_PREFIX.length));
      if (!q || q.user.id !== user.id) throw new Refused('not_found');
      const out = { id: q.id, status: q.status, text: q.text, asked_at: q.askedAt };
      if (q.answer !== null) Object.assign(out, { answer: q.answer, by: q.by });
      return answer(200, out);
    }
    return this.ask(req, user, now);
  }

  ask(req, user, now) {
    const body = req.body || Buffer.alloc(0);
    if (req.oversize || body.length > MAX_BODY) throw new Refused('too_large');
    const data = parseBodyJson(body);
    if (!isObject(data) || Object.keys(data).some((k) => k !== 'text' && k !== 'page')) throw new Refused('bad_params');
    const text = data.text;
    if (typeof text !== 'string' || !text.trim() || codePoints(text) > PANEL_TEXT_MAX) throw new Refused('bad_params');
    let page = has(data, 'page') ? data.page : null;
    if (page !== null) {
      if (!isObject(page) || Object.keys(page).some((k) => !has(PANEL_PAGE_LIMITS, k) || typeof page[k] !== 'string'
          || codePoints(page[k]) > PANEL_PAGE_LIMITS[k])) throw new Refused('bad_params');
      page = Object.fromEntries(Object.keys(page).map((k) => [k, clean(page[k])]));
    }
    const asked = (this.asked.get(user.id) || []).filter((t) => t > now - 3600);
    if (asked.length >= this.rate.panel_per_user_hour) throw new Refused('rate_limited');
    if ([...this.questions.values()].filter(isOpen).length >= PANEL_OPEN_MAX) throw new Refused('busy');
    asked.push(now);
    this.asked.set(user.id, asked);
    const id = 'q_' + crypto.randomBytes(12).toString('base64url');
    this.questions.set(id, {
      id, user, text: clean(text.trim()), page, askedAt: now, status: 'waiting', answer: null, by: null, updatedAt: now
    });
    return answer(200, { question_id: id });
  }

  sweep(now) {
    for (const [id, q] of this.questions) if (q.askedAt + PANEL_EXPIRY <= now) this.questions.delete(id);
    for (const [id, asked] of this.asked) if (!asked.length || asked[asked.length - 1] <= now - 3600) this.asked.delete(id);
    if (this.lastPull !== null && now - this.lastPull < PANEL_OFFLINE_ANSWER) return;
    for (const q of this.questions.values()) {
      if (isOpen(q) && now - Math.max(q.updatedAt, this.lastPull || 0) >= PANEL_OFFLINE_ANSWER) {
        Object.assign(q, { status: 'unavailable', answer: PANEL_UNAVAILABLE, by: 'Atrium', updatedAt: now });
      }
    }
  }

  pullQuestions(now) {
    this.lastPull = now;
    this.sweep(now);
    const out = [];
    for (const q of this.questions.values()) {
      if (q.status === 'waiting' && out.length < PANEL_PULL_MAX) {
        q.status = 'answering';
        q.updatedAt = now;
        out.push({ id: q.id, text: q.text, tool_user: Object.assign({}, q.user), page: q.page, asked_at: q.askedAt });
      }
    }
    return out;
  }

  panelAnswer(params, now) {
    const q = this.questions.get(params.question_id);
    if (!q || !isOpen(q)) return { ok: false };
    q.status = params.status === 'working' ? 'answering' : params.status;
    q.answer = clean(params.text);
    q.by = clean(params.by || '') || null;
    q.updatedAt = now;
    return { ok: true };
  }

  // ---- events ----

  emit(name, payload) {
    try {
      const names = this.ready && isObject(this.manifest.events) && Array.isArray(this.manifest.events.names)
        ? this.manifest.events.names : [];
      const value = payload === undefined || payload === null ? {} : payload;
      const raw = isObject(value) ? JSON.stringify(value) : null;
      if (raw === null || !names.includes(name) || Buffer.byteLength(raw, 'utf8') > EVENT_PAYLOAD_MAX) {
        this.rejected += 1;
        return false;
      }
      const now = Math.floor(this.clock());
      while (this.events.length && this.events[0].at <= now - OUTBOX_TTL) this.events.shift();
      if (this.events.length >= OUTBOX_MAX) {
        this.drops += 1;
        return false;
      }
      this.seq += 1;
      const event = { seq: this.seq, name, payload: JSON.parse(raw), at: now };
      const jti = cause.getStore();
      if (jti) event.cause = { jti };
      this.events.push(event);
      return true;
    } catch (e) {
      this.rejected += 1;
      return false;
    }
  }

  pullEvents(after, now) {
    if (after > this.seq) after = 0; // the bridge restarted since: deliver from the start
    while (this.events.length && (this.events[0].seq <= after || this.events[0].at <= now - OUTBOX_TTL)) this.events.shift();
    const out = this.events.slice(0, EVENTS_PULL_MAX).map((e) => Object.assign({}, e));
    return { events: out, next: out.length ? out[out.length - 1].seq : after };
  }
}

function isOpen(q) {
  return q.status === 'waiting' || q.status === 'answering';
}

/* The bridge of a glue object: built once from its actions, currentUser, servicePrincipal and optional manifest,
 * panelJs, grants, env and clock; a Bridge is returned as it is. */
function createBridge(glue) {
  if (glue instanceof Bridge) return glue;
  if (!glue || typeof glue !== 'object') throw new TypeError('the glue is an object');
  let bridge = byGlue.get(glue);
  if (!bridge) {
    bridge = new Bridge({
      actions: glue.actions, currentUser: glue.currentUser || glue.current_user,
      servicePrincipal: glue.servicePrincipal || glue.service_principal, manifest: glue.manifest,
      panelJs: glue.panelJs, panelSha256: glue.panelSha256, grants: glue.grants, nonces: glue.nonces, env: glue.env,
      clock: glue.clock,
      maxWait: glue.maxWait
    });
    byGlue.set(glue, bridge);
  }
  return bridge;
}

function bridgePath(url) {
  const at = String(url || '').indexOf('/.atrium/');
  return at >= 0 ? String(url).slice(at) : null;
}

function readBody(req) {
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^[0-9]{1,15}$/.test(length) || Number(length) > MAX_BODY)) {
    return Promise.resolve({ body: Buffer.alloc(0), oversize: true });
  }
  if (String(req.method).toUpperCase() !== 'POST') return Promise.resolve({ body: Buffer.alloc(0), oversize: false });
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let done = false;
    const finish = (value) => {
      if (!done) {
        done = true;
        resolve(value);
      }
    };
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        finish({ body: Buffer.alloc(0), oversize: true });
        req.removeAllListeners('data');
        req.resume();
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => finish({ body: Buffer.concat(chunks), oversize: false }));
    req.on('error', () => finish({ body: Buffer.alloc(0), oversize: true }));
  });
}

async function serve(bridge, req, res, url) {
  const full = String(url);
  const q = full.indexOf('?');
  let body = Buffer.alloc(0);
  let oversize = false;
  if (req._body === true || req.readableEnded) {
    // a body parser ran first: the raw bytes are gone. Panel questions still work; calls cannot be verified.
    if (bridgePath(full).startsWith(CALL_PREFIX)) {
      console.error('Atrium bridge: mount it before body parsers - signed calls need the raw body');
      return send(res, refusal('not_configured'));
    }
    body = Buffer.from(JSON.stringify(req.body === undefined ? {} : req.body), 'utf8');
  } else {
    ({ body, oversize } = await readBody(req));
  }
  const out = await bridge.handle({
    method: req.method, path: bridgePath(q >= 0 ? full.slice(0, q) : full), query: q >= 0 ? full.slice(q + 1) : '',
    headers: req.headers, body, remote: req.socket && req.socket.remoteAddress, native: req, oversize
  });
  return send(res, out);
}

function send(res, out) {
  res.statusCode = out.status;
  for (const [name, value] of Object.entries(out.headers)) res.setHeader(name, value);
  res.setHeader('Content-Length', out.body.length);
  res.end(out.body);
}

/* Express / Connect middleware: /.atrium/ requests go to the bridge, everything else to next(). */
function middleware(glue) {
  const bridge = createBridge(glue);
  return function atriumBridge(req, res, next) {
    const url = req.originalUrl || req.url;
    if (!bridgePath(String(url).split('?')[0])) return next();
    serve(bridge, req, res, url).catch((e) => (typeof next === 'function' ? next(e) : res.destroy()));
    return undefined;
  };
}

/* A node:http request listener for the bridge alone (other paths: 404). */
function handler(glue) {
  const bridge = createBridge(glue);
  return function atriumBridge(req, res) {
    if (!bridgePath(String(req.url).split('?')[0])) return send(res, answer(404, { ok: false, code: 'not_found' }));
    serve(bridge, req, res, req.url).catch(() => res.destroy());
    return undefined;
  };
}

/* atriumBridge.emit(name, payload): queue an event declared in atrium-bridge.json for the team. Never blocks, never
 * throws; false when it was not queued (no bridge, undeclared name, too large, outbox full). */
function emit(name, payload) {
  try {
    return defaults.bridge ? defaults.bridge.emit(name, payload) : false;
  } catch (e) {
    return false;
  }
}

module.exports = {
  CONTRACT, CORE_VERSION, PANEL_JS_SHA256, MAX_BODY, MAX_RESPONSE, BUILTINS, PROBATION_BUILTINS, STATUS, PANEL_STATUS,
  Refused, Bridge, NonceCache, MemoryGrants, FileGrants,
  createBridge, middleware, express: middleware, connect: middleware, handler, emit,
  b64u, b64uDecode, parseKeys, verifyToken, ticketFieldsOk, grantFieldsOk, bodyHash, signingString, verifySignature,
  schemaOk, validateParams, parseBody
};
