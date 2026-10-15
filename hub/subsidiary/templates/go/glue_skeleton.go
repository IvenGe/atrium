// Atrium bridge glue: what the Atrium team may do inside this tool (contract atrium-bridge/1).
//
// This file is the tool-specific part of the bridge; the atriumbridge package (core.go and panel.js) is vendored by
// Atrium and must stay byte-identical. Every action listed in atrium-bridge.json needs a handler here.
//
// Rules for handlers (the contract's MUST list):
//   - call the tool's own service layer as the service principal, with the tool's normal authorization: no raw
//     database access, no generic query endpoint;
//   - parameters never reach exec, a shell, templates, file paths or SQL strings (they are validated against the
//     manifest's schema before a handler runs);
//   - results never contain password hashes, tokens, keys or session ids;
//   - in panel runs ctx.User is the tool user who asked: authorize as that user AND the service principal.
//
// Events: atriumbridge.EmitContext(ctx.Context, "<tool_id>.<event>", map[string]any{...}) from a handler (granted
// calls then set the event's cause), atriumbridge.Emit elsewhere.
package main

import (
	"net/http"

	"__MODULE__/atriumbridge"
)

// atriumBridge builds the bridge. Mount it on the tool's main mux, behind the middleware that identifies the
// signed-in user:  mux.Handle("/.atrium/", atriumBridge())
func atriumBridge() http.Handler {
	return atriumbridge.New(atriumbridge.Glue{
		ServicePrincipal: "atrium-team",
		// CurrentUser: func(r *http.Request) *atriumbridge.User { ... }, // TODO: the panel needs it
		// Grants: atriumbridge.NewFileGrants("var/atrium-grants.json"),   // used grants survive restarts
		Actions: map[string]atriumbridge.Handler{
			// "tickets.list": atriumTicketsList,
		},
	})
}

// TODO: one handler per action of atrium-bridge.json, e.g.
//
//	func atriumTicketsList(params map[string]any, ctx *atriumbridge.Ctx) (any, error) {
//		status, _ := params["status"].(string)
//		return tickets.Visible(ctx.Context, ctx.Principal, ctx.User, status)
//	}
