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
    ("POST", "/api/subsidiary/v1/enroll"),  # a subsidiary's sidecar with its one-time code (throttled)
}
SELF_SERVICE = {
    ("POST", "/api/auth/logout"),
    ("POST", "/api/auth/password"),
    ("GET", "/api/auth/sessions"),
    ("DELETE", "/api/auth/sessions"),
}
ADMIN_TREES = ("/api/users", "/api/tokens")
# Single routes that need admin: settings (SLA, guardrails), agent definitions (create, configure, remove) and their
# settings (model, instructions, tools, budgets, escalation; restoring a version; lifting a budget stop; resuming a
# schedule paused after failed runs; the playground, which spends tokens), the AI model providers (they may hold API
# keys; testing and probing them spends tokens), the suite's model selection and the AI price table, the
# identity providers (credentials for sign-in), tool connections
# (they hold the tools' API credentials), the Sign-in & SSO settings, disabling a person's Atrium account, extensions,
# self-patches, and the shared Home dashboards with the default dashboard.
# Everything else in the People app follows the default: viewers read, operators change people and links.
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
    ("POST", re.compile(r"/api/llm/providers/[^/]+/probe")),  # a few paid tokens per check
    ("PUT", re.compile(r"/api/llm/prices")),  # the price table behind cost estimates (and later budgets)
    ("PATCH", re.compile(r"/api/llm/selection")),  # which model agents use by default (suite, purposes, teams)
    ("PATCH", re.compile(r"/api/agents/[^/]+/settings")),  # an agent's own model, instructions, tools and limits
    ("POST", re.compile(r"/api/agents/[^/]+/settings/restore")),  # bring back an earlier version of them
    ("POST", re.compile(r"/api/agents/[^/]+/playground")),  # spends tokens; may act (approvals apply) when asked
    ("POST", re.compile(r"/api/agents/[^/]+/budget/override")),  # lifts today's budget stop of an agent
    ("POST", re.compile(r"/api/agents/[^/]+/schedule/resume")),  # runs a schedule paused after failed runs again
    ("DELETE", re.compile(r"/api/agents/[^/]+/errors")),  # clears an agent's recorded errors (operators acknowledge)
    ("PUT", re.compile(r"/api/identity-providers/default")),
    ("PATCH", re.compile(r"/api/identity-providers/[^/]+")),
    ("POST", re.compile(r"/api/identity-providers/[^/]+/atrium")),
    ("PUT", re.compile(r"/api/tools/[^/]+/connection")),
    ("DELETE", re.compile(r"/api/tools/[^/]+/connection")),
    # Sign-in & SSO settings (the client secret of Atrium's own sign-in)
    ("GET", re.compile(r"/api/auth/sso")),
    ("PUT", re.compile(r"/api/auth/sso")),
    ("DELETE", re.compile(r"/api/auth/sso")),
    ("POST", re.compile(r"/api/auth/sso/test")),
    # People: disabling someone's Atrium account is account administration
    ("POST", re.compile(r"/api/people/[^/]+/actions/disable_atrium_account")),
    # Extensions and self-patches change Atrium itself: uploading, enabling, rolling back and removing packs, asking
    # the Patch Agent to extend Atrium for a tool, and asking for or applying a change to Atrium's own code. (Deciding
    # their approvals needs admin too - checked by the approvals route, per kind.) Reading them, and the records of
    # extension domains (viewer reads, operator changes), follow the default.
    ("POST", re.compile(r"/api/extensions")),
    ("PATCH", re.compile(r"/api/extensions/[^/]+")),
    ("DELETE", re.compile(r"/api/extensions/[^/]+")),
    ("POST", re.compile(r"/api/extensions/[^/]+/rollback")),
    ("POST", re.compile(r"/api/tools/[^/]+/extend")),
    ("POST", re.compile(r"/api/self-patches")),
    ("POST", re.compile(r"/api/self-patches/[^/]+/apply")),
    # Network app: accepting or removing a device's configuration baseline (it decides what counts as drift),
    # downloading a backup (a device's full configuration, often with password hashes and keys) and the network
    # settings (backup retention). Segmentation: zone roles and the policy decide the compliance verdicts (any zone id,
    # which may contain "/"). Viewers read, operators refresh, back up, acknowledge drift and place assets (default).
    ("POST", re.compile(r"/api/network/devices/[^/]+/baseline")),
    ("DELETE", re.compile(r"/api/network/devices/[^/]+/baseline")),
    ("GET", re.compile(r"/api/network/backups/[^/]+/download")),
    ("PATCH", re.compile(r"/api/network/settings")),
    ("PATCH", re.compile(r"/api/segmentation/zones/.+")),
    ("PUT", re.compile(r"/api/segmentation/policy")),
    # Device changes: operators preview, propose, withdraw and propose reverts / backup restores (the default);
    # applying an approved change at once as an emergency and the maintenance windows are administrators' (deciding
    # a device change needs admin too - checked by the approvals route for kind "firewall").
    ("POST", re.compile(r"/api/segmentation/changes/[^/]+/emergency")),
    ("POST", re.compile(r"/api/network/maintenance-windows")),
    ("PATCH", re.compile(r"/api/network/maintenance-windows/[^/]+")),
    ("DELETE", re.compile(r"/api/network/maintenance-windows/[^/]+")),
    # The integration map (hub/canvas_api.py) follows the default on purpose: viewers read the map, the Connect
    # options and the layouts; operators arrange the shared layouts (PATCH/DELETE /api/layouts/{view}) and create data
    # flows (POST /api/flows, which proposes them for approval unless the hub is autonomous). Nothing there is admin's.
    # Compliance frameworks: viewers read catalogs, assessments and audit packs, operators start and score
    # self-assessments (the default); deleting one removes evidence of past assessments, so it needs admin.
    ("DELETE", re.compile(r"/api/frameworks/[^/]+/assessments/[^/]+")),
    # Home dashboards (hub/dashboards_api.py): shared dashboards and the default are the administrators'; everyone
    # arranges their own (SELF_SERVICE_ROUTES below) and reads the widgets their role allows (the default).
    ("POST", re.compile(r"/api/dashboards/shared")),
    ("PUT", re.compile(r"/api/dashboards/shared/[^/]+")),
    ("DELETE", re.compile(r"/api/dashboards/shared/[^/]+")),
    ("PUT", re.compile(r"/api/dashboards/default")),
    # Subsidiaries (hub/subsidiary/routes.py): viewers read (runs too), operators propose, pause (protective), give
    # tasks (POST .../tasks) and handle reports (the default); the charter, the dedicated credential, enrollment, conformance, signing keys,
    # resume, stop and archive are the administrators' (enrollment, resume and stop signed in as a person; deciding
    # charters, bridge patches and admin-risk in-tool actions needs admin too - checked by the approvals route).
    ("PUT", re.compile(r"/api/subsidiaries/[^/]+/charter")),
    ("PUT", re.compile(r"/api/subsidiaries/[^/]+/credential")),
    ("DELETE", re.compile(r"/api/subsidiaries/[^/]+/credential")),
    ("POST", re.compile(r"/api/subsidiaries/[^/]+/enrollment")),
    ("POST", re.compile(r"/api/subsidiaries/[^/]+/conformance")),
    ("POST", re.compile(r"/api/subsidiaries/[^/]+/rotate-key")),
    ("POST", re.compile(r"/api/subsidiaries/[^/]+/resume")),
    ("POST", re.compile(r"/api/subsidiaries/[^/]+/stop")),
    ("DELETE", re.compile(r"/api/subsidiaries/[^/]+")),
)
# Self-service writes: a signed-in person's own dashboards and dashboard preferences, at any role. The handler scopes
# every write to the caller's user id and refuses API tokens (person_required).
SELF_SERVICE_ROUTES = (
    ("POST", re.compile(r"/api/dashboards/mine")),
    ("PUT", re.compile(r"/api/dashboards/mine/[^/]+")),
    ("DELETE", re.compile(r"/api/dashboards/mine/[^/]+")),
    ("PUT", re.compile(r"/api/dashboards/prefs")),
)
# Reads that act on a tool with its stored credentials, so they need operator - and a person's own conversation with
# an agent (chatting needs operator; the handler returns only the caller's own, DELETE of it follows the default).
OPERATOR_READS = (
    ("GET", re.compile(r"/api/tools/[^/]+/connection/options/[^/]+")),
    ("GET", re.compile(r"/api/agents/[^/]+/conversation")),
)
INTEGRATION = {("POST", "/api/bus/publish"), ("GET", "/api/health")}
# The sidecar API of subsidiaries: only a subsidiary token (role "subsidiary", bound to its subsidiary by the route)
# reaches it - and a subsidiary token reaches nothing else. Enrolling is public (a one-time code, throttled).
SUBSIDIARY_API = "/api/subsidiary/v1/"
PASSWORD_CHANGE = {("GET", "/api/auth/me"), ("POST", "/api/auth/logout"), ("POST", "/api/auth/password")}


def is_api(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root + "/")


def _key(method: str, path: str) -> tuple[str, str]:
    method = method.upper()
    return ("GET" if method == "HEAD" else method), (path.rstrip("/") or "/")


def is_subsidiary_api(path: str) -> bool:
    return path.startswith(SUBSIDIARY_API) and ".." not in path.split("/")


def required_role(method: str, path: str) -> str | None:
    """The minimum role for a request; None means the route is public. "subsidiary": only a subsidiary's sidecar."""
    method, path = _key(method, path)
    if (method, path) in PUBLIC:
        return None
    if _under(path, SUBSIDIARY_API.rstrip("/")):
        return "subsidiary"
    if (method, path) in SELF_SERVICE:
        return "viewer"
    if any(_under(path, root) for root in ADMIN_TREES):
        return "admin"
    if any(method == m and rx.fullmatch(path) for m, rx in ADMIN_ROUTES):
        return "admin"
    if any(method == m and rx.fullmatch(path) for m, rx in OPERATOR_READS):
        return "operator"
    if any(method == m and rx.fullmatch(path) for m, rx in SELF_SERVICE_ROUTES):
        return "viewer"
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
    if principal is not None and principal.role == "subsidiary":
        return None if is_subsidiary_api(path) else (403, {"detail": "Subsidiary tokens can only use the subsidiary API."})
    if principal is not None and principal.must_change_password and key not in PASSWORD_CHANGE:
        return 403, {"detail": "Change your password first.", "code": "password_change_required"}
    required = required_role(method, path)
    if required is None:
        return None
    if principal is None:
        return 401, {"detail": "Sign in required"}
    if required == "subsidiary":
        return 403, {"detail": "Only a subsidiary's sidecar calls this API."}
    if not role_allows(principal.role, required):
        return 403, {"detail": f"Your role ({principal.role}) cannot do this."}
    return None
