"""Atrium bridge glue: what the Atrium team may do inside this tool (contract atrium-bridge/1).

This file is the tool-specific part of the bridge; atrium_bridge_core.py, atrium_bridge.py and panel.js next to it
are vendored by Atrium and must stay byte-identical. Every action listed in atrium-bridge.json needs a handler here.

Rules for handlers (the contract's MUST list):
- call the tool's own service layer as the service principal (service_principal() below), with the tool's normal
  authorization: no raw database access, no generic query endpoint;
- parameters never reach eval, exec, a shell, templates, file paths or SQL strings (they are already validated
  against the manifest's schema before a handler runs);
- results never contain password hashes, tokens, keys or session ids;
- in panel runs ctx.user is the tool user who asked: authorize as that user AND the service principal, so the team
  never shows anyone data they cannot see themselves.

The tool's own code queues declared events with:  atrium_bridge.emit("<tool_id>.<event>", {...})
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Optional: where the committed manifest and the widget are (by default the core looks next to itself, then in the
# folders above it). GRANT_STORE persists used grants across restarts, e.g. SqliteGrants("var/atrium-grants.db").
# MANIFEST = Path(__file__).resolve().parent.parent / "atrium-bridge.json"
# GRANT_STORE = SqliteGrants(Path(__file__).resolve().parent.parent / "var" / "atrium-grants.sqlite3")
# NONCE_STORE = SqliteNonces(Path(__file__).resolve().parent.parent / "var" / "atrium-nonces.sqlite3")  # several workers


def service_principal() -> str:
    """The low-privilege in-app account the team acts as (create it with only the rights the actions need)."""
    return "atrium-team"


def current_user(request: Any) -> Optional[Dict[str, Any]]:
    """The signed-in tool user as {"id", "display", "roles"}, or None (the "Ask the team" panel needs it). This
    template knows Flask-Login and Starlette's AuthenticationMiddleware; replace it for any other session."""
    user = None
    try:
        from flask_login import current_user as flask_user  # type: ignore[import-not-found]
        user = flask_user if getattr(flask_user, "is_authenticated", False) else None
    except Exception:
        try:
            candidate = request.user  # Starlette: AuthenticationMiddleware
            user = candidate if getattr(candidate, "is_authenticated", False) else None
        except Exception:
            user = None
    if user is None:
        return None
    uid = getattr(user, "id", None) or getattr(user, "identity", None) \
        or (user.get_id() if callable(getattr(user, "get_id", None)) else None)
    if uid is None:
        return None
    display = getattr(user, "display_name", None) or getattr(user, "username", None) or getattr(user, "name", None)
    roles = getattr(user, "roles", None) or []
    return {"id": str(uid), "display": str(display or uid),
            "roles": [str(getattr(r, "name", r)) for r in (roles if isinstance(roles, (list, tuple, set)) else [roles])]}


# TODO: one handler per action of atrium-bridge.json. A handler gets the validated params and a context with
# ctx.principal (the service principal), ctx.user (panel runs: the tool user who asked) and ctx.grant_jti (writes).
#
# def tickets_list(params, ctx):
#     return [t.public() for t in services.tickets.visible(principal=ctx.principal, user=ctx.user,
#                                                          status=params.get("status"))]

actions: Dict[str, Any] = {
    # "tickets.list": tickets_list,
}
