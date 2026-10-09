"""Who may call what: the role every /api route requires, and the access decision for a principal."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .service import Principal

ROLES = ("viewer", "operator", "admin")
ROLE_RANK = {"viewer": 1, "operator": 2, "admin": 3}

PUBLIC = {
    ("GET", "/api/health"),
    ("GET", "/api/auth/me"),
    ("POST", "/api/auth/login"),
    ("POST", "/api/auth/setup"),
    ("GET", "/api/auth/oidc/login"),
    ("GET", "/api/auth/oidc/callback"),
}
SELF_SERVICE = {
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/password"),
    ("GET", "/api/auth/sessions"),
    ("DELETE", "/api/auth/sessions"),
}
ADMIN_TREES = ("/api/users", "/api/tokens")
# Single routes that need admin: settings (SLA, guardrails), agent definitions (create, configure, remove), the AI
# model providers (they may hold API keys), the identity providers (credentials for sign-in) and tool connections
# (they hold the tools' API credentials).
ADMIN_ROUTES = (
    ("PATCH", re.compile(r"/api/settings")),
    ("PATCH", re.compile(r"/api/settings/guardrails")),
    ("POST", re.compile(r"/api/agents")),
    ("PATCH", re.compile(r"/api/agents/[^/]+")),
    ("DELETE", re.compile(r"/api/agents/[^/]+")),
    ("POST", re.compile(r"/api/llm/providers")),
    ("PATCH", re.compile(r"/api/llm/providers/[^/]+")),
    ("DELETE", re.compile(r"/api/llm/providers/[^/]+")),
    ("POST", re.compile(r"/api/llm/providers/[^/]+/test")),
    ("PUT", re.compile(r"/api/identity-providers/default")),
    ("PATCH", re.compile(r"/api/identity-providers/[^/]+")),
    ("POST", re.compile(r"/api/identity-providers/[^/]+/atrium")),
    ("PUT", re.compile(r"/api/tools/[^/]+/connection")),
    ("DELETE", re.compile(r"/api/tools/[^/]+/connection")),
)
# Reads that act on a tool with its stored credentials, so they need operator.
OPERATOR_READS = (
    ("GET", re.compile(r"/api/tools/[^/]+/connection/options/[^/]+")),
)
INTEGRATION = {("POST", "/api/bus/publish"), ("GET", "/api/health")}
PASSWORD_CHANGE = {("GET", "/api/auth/me"), ("POST", "/api/auth/logout"), ("POST", "/api/auth/password")}


def is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _key(method: str, path: str) -> tuple[str, str]:
    method = method.upper()
    return ("GET" if method == "HEAD" else method), (path.rstrip("/") or "/")


def required_role(method: str, path: str) -> str | None:
    """The minimum role for a request; None means the route is public."""
    method, path = _key(method, path)
    if (method, path) in PUBLIC:
        return None
    if (method, path) in SELF_SERVICE:
        return "viewer"
    if any(_under(path, root) for root in ADMIN_TREES):
        return "admin"
    if any(method == m and rx.fullmatch(path) for m, rx in ADMIN_ROUTES):
        return "admin"
    if any(method == m and rx.fullmatch(path) for m, rx in OPERATOR_READS):
        return "operator"
    if method == "GET":
        return "viewer"
    return "operator"


def role_allows(role: str, required: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK[required]


def authorize(principal: "Principal | None", method: str, path: str) -> tuple[int, dict[str, Any]] | None:
    """None when the request may proceed, else (status code, JSON body) to refuse it with."""
    key = _key(method, path)
    if principal is not None and principal.role == "integration":
        return None if key in INTEGRATION else (403, {"detail": "Integration tokens can only publish events."})
    if principal is not None and principal.must_change_password and key not in PASSWORD_CHANGE:
        return 403, {"detail": "Change your password first.", "code": "password_change_required"}
    required = required_role(method, path)
    if required is None:
        return None
    if principal is None:
        return 401, {"detail": "Sign in required"}
    if not role_allows(principal.role, required):
        return 403, {"detail": f"Your role ({principal.role}) cannot do this."}
    return None
