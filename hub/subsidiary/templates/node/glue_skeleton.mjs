/* Atrium bridge glue: what the Atrium team may do inside this tool (contract atrium-bridge/1), ES module.
 *
 * This file is the tool-specific part of the bridge; atrium-bridge-core.cjs/.mjs and panel.js next to it are vendored
 * by Atrium and must stay byte-identical. Every action listed in atrium-bridge.json needs a handler here.
 *
 * Rules for handlers (the contract's MUST list):
 * - call the tool's own service layer as the service principal, with the tool's normal authorization: no raw
 *   database access, no generic query endpoint;
 * - parameters never reach eval, new Function, child_process, templates, file paths or SQL strings (they are
 *   validated against the manifest's schema before a handler runs);
 * - results never contain password hashes, tokens, keys or session ids;
 * - in panel runs ctx.user is the tool user who asked: authorize as that user AND the service principal.
 *
 * Mount (before body parsers, after the session middleware):  app.use(atriumBridge.express(glue))
 * Events from the tool's code:  atriumBridge.emit('<tool_id>.<event>', {...}) */

export default {
  servicePrincipal: () => 'atrium-team',

  // The signed-in tool user as {id, display, roles}, or null (the "Ask the team" panel needs it). This template
  // knows Passport-style sessions (req.user); replace it for any other session.
  currentUser(req) {
    const user = req && req.user;
    if (!user || (user.id === undefined && user._id === undefined)) return null;
    const roles = user.roles || (user.role ? [user.role] : []);
    return { id: String(user.id !== undefined ? user.id : user._id), display: String(user.displayName || user.username || user.name || user.id),
      roles: (Array.isArray(roles) ? roles : [roles]).map(String) };
  },

  // Optional: grants: new FileGrants('var/atrium-grants.json') (from the core) keeps used grants across restarts.

  // TODO: one handler per action of atrium-bridge.json, e.g.
  //   'tickets.list': async (params, ctx) => tickets.visible({ principal: ctx.principal, user: ctx.user, status: params.status }),
  actions: {}
};
