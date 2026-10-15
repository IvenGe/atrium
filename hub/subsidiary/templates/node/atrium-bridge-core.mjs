/* Atrium bridge core for Node.js >= 16, ES module entry - contract atrium-bridge/1. VENDORED FILE: Atrium adds it
 * byte-identical next to atrium-bridge-core.cjs (the one implementation) and checks its SHA-256; do not edit it.
 *     import * as atriumBridge from './atrium/atrium-bridge-core.mjs';
 *     app.use(atriumBridge.express(glue)); */
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const core = require('./atrium-bridge-core.cjs');

export const {
  CONTRACT, CORE_VERSION, PANEL_JS_SHA256, MAX_BODY, MAX_RESPONSE, BUILTINS, PROBATION_BUILTINS, STATUS, PANEL_STATUS,
  Refused, Bridge, NonceCache, MemoryGrants, FileGrants,
  createBridge, middleware, express, connect, handler, emit,
  b64u, b64uDecode, parseKeys, verifyToken, ticketFieldsOk, grantFieldsOk, bodyHash, signingString, verifySignature,
  schemaOk, validateParams, parseBody
} = core;
export default core;
