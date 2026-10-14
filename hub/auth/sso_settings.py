"""Sign-in & SSO settings: the OpenID Connect sign-in managed from the UI (stored in the database, the client secret
Fernet-encrypted) instead of only HUB_OIDC_* variables. Every field an environment variable sets wins and is shown
read-only. Saving rebuilds hub.auth.oidc - the same OidcClient with every security check - without a restart.

A stored client secret is only sent to the issuer it was entered for: changing the issuer means entering it again.
"""

from __future__ import annotations

import dataclasses
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from ..config import OIDC_ENV, SSO_DEFAULT_ROLES, Settings
from ..connectors.base import endpoint_of
from ..secrets import SecretError
from .oidc import OidcClient

if TYPE_CHECKING:
    from ..core import Hub

DOC = "sso"  # in the "settings" collection
KEYS = {  # API key -> Settings attribute
    "issuer": "oidc_issuer", "client_id": "oidc_client_id", "client_secret": "oidc_client_secret",
    "scopes": "oidc_scopes", "role_claim": "oidc_role_claim", "admin_values": "oidc_admin_values",
    "operator_values": "oidc_operator_values", "viewer_values": "oidc_viewer_values", "default_role": "oidc_default_role",
    "allowed_domains": "oidc_allowed_domains", "label": "oidc_label", "allow_http": "oidc_allow_http",
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
CLAIM_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,100}$")
SCOPE_RE = re.compile(r"^[\w:/.-]{1,100}$")
LOCAL_HOSTS = ("localhost", "127.0.0.1")

PRESETS: list[dict[str, Any]] = [
    {"id": "okta", "name": "Okta", "provider_name": "Okta", "issuer": "https://<your-domain>/oauth2/default",
     "scopes": "openid profile email groups", "role_claim": "groups", "admin_values": ["atrium-admins"],
     "operator_values": ["atrium-operators"],
     "notes": ["Create an OIDC Web Application in Okta with the sign-in redirect URI below.",
               "Issuer: https://<your-domain>/oauth2/default (the default custom authorization server) or "
               "https://<your-domain> (the org authorization server).",
               "Okta does not put groups in the ID token by default: add a groups claim (custom authorization server: "
               "Security > API > Authorization Servers > Claims; org server: the app's Sign On tab), filtered e.g. to "
               "groups starting with atrium-."]},
    {"id": "entra", "name": "Microsoft Entra ID", "provider_name": "Microsoft",
     "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0", "scopes": "openid profile email",
     "role_claim": "roles", "admin_values": ["atrium-admins"], "operator_values": ["atrium-operators"],
     "notes": ["Register an app (Web platform) with the redirect URI below and create a client secret.",
               "Roles: define app roles atrium-admins and atrium-operators and assign them (claim 'roles'), or emit a "
               "groups claim (claim 'groups' - Entra sends group object IDs, so enter those IDs as the values).",
               "Use the tenant ID in the issuer, not 'common'.",
               "In Enterprise applications set 'Assignment required' to Yes and assign the people (or groups) who may "
               "use Atrium: otherwise every member and guest of the tenant can sign in."]},
    {"id": "google", "name": "Google", "provider_name": "Google", "issuer": "https://accounts.google.com",
     "scopes": "openid profile email", "role_claim": "groups", "admin_values": [], "operator_values": [],
     "notes": ["Create an OAuth client ID (Web application) in Google Cloud with the redirect URI below.",
               "Google's ID tokens carry no groups: everyone allowed in gets the default role. Keep a local "
               "administrator account.",
               "With an External consent screen any Google account can authenticate: use an Internal one (Google "
               "Workspace) and list your domains under Allowed domains, then set the default role to viewer."]},
    {"id": "keycloak", "name": "Keycloak", "provider_name": "Keycloak", "issuer": "https://<host>/realms/<realm>",
     "scopes": "openid profile email", "role_claim": "groups", "admin_values": ["atrium-admins"],
     "operator_values": ["atrium-operators"],
     "notes": ["A confidential client with the redirect URI below and a 'groups' mapper (group names, not full path) - "
               "Atrium's generated client registration sets this up."]},
    {"id": "authentik", "name": "authentik", "provider_name": "authentik",
     "issuer": "https://<host>/application/o/<slug>/", "scopes": "openid profile email", "role_claim": "groups",
     "admin_values": ["atrium-admins"], "operator_values": ["atrium-operators"],
     "notes": ["An OAuth2/OpenID provider and application with the redirect URI below; authentik sends groups by "
               "default."]},
    {"id": "generic", "name": "Other OpenID Connect provider", "provider_name": "SSO", "issuer": "",
     "scopes": "openid profile email", "role_claim": "groups", "admin_values": ["atrium-admins"],
     "operator_values": ["atrium-operators"], "notes": ["Any provider with OpenID Connect discovery."]},
]
PRESET_IDS = {p["id"] for p in PRESETS}


# --------------------------------------------------------------------------------------
# what is set where
# --------------------------------------------------------------------------------------


def _defaults() -> dict[str, Any]:
    out = {}
    for f in dataclasses.fields(Settings):
        if f.default is not dataclasses.MISSING:
            out[f.name] = f.default
        elif f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
            out[f.name] = f.default_factory()  # type: ignore[misc]
    return out


def env_keys(settings: Settings) -> set[str]:
    """API keys whose value comes from HUB_OIDC_* variables."""
    if settings.oidc_env is not None:
        attrs = set(settings.oidc_env)
    else:
        defaults = _defaults()
        attrs = {a for a in KEYS.values() if getattr(settings, a) != defaults.get(a)}
    return {k for k, a in KEYS.items() if a in attrs}


def stored(hub: "Hub") -> dict[str, Any] | None:
    return hub.store.get("settings", DOC)


def _secret(hub: "Hub", doc: dict[str, Any], issuer: str | None) -> tuple[str | None, str | None]:
    """(the stored client secret, an error) - only for the issuer it was entered for."""
    token = doc.get("client_secret")
    if not token:
        return None, None
    if endpoint_of(doc.get("secret_endpoint")) != endpoint_of(issuer):
        return None, "The stored client secret was entered for another issuer - enter it again."
    try:
        return hub.secrets.decrypt(token), None
    except SecretError as exc:
        return None, str(exc)


def effective(hub: "Hub", doc: dict[str, Any] | None = None) -> tuple[Settings, dict[str, str], str | None]:
    """(settings with the effective oidc_* values, key -> "environment" | "database" | "default", secret error)."""
    base = hub.settings
    doc = stored(hub) if doc is None else doc
    env = env_keys(base)
    defaults = _defaults()
    values: dict[str, Any] = {}
    origin: dict[str, str] = {}
    for key, attr in KEYS.items():
        if key in env:
            values[attr], origin[key] = getattr(base, attr), "environment"
        elif doc and key not in ("client_secret", "label") and doc.get(key) is not None and doc.get(key) != "":
            values[attr], origin[key] = doc[key], "database"
        elif doc and key == "label" and doc.get("provider_name"):
            values[attr], origin[key] = f"Sign in with {doc['provider_name']}", "database"
        else:
            values[attr], origin[key] = defaults.get(attr), "default"
    error = None
    if "client_secret" not in env and doc:
        secret, error = _secret(hub, doc, values["oidc_issuer"])
        if secret:
            values["oidc_client_secret"], origin["client_secret"] = secret, "database"
    return dataclasses.replace(base, **values), origin, error


def rebuild(hub: "Hub") -> OidcClient:
    """Replace the hub's OIDC client with one for the effective settings (sign-ins already started are dropped)."""
    settings, _, _ = effective(hub)
    hub.auth.oidc = OidcClient(settings, transport=hub.auth.oidc_transport)
    return hub.auth.oidc


# --------------------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------------------


def _url(value: str, allow_http: bool) -> str:
    value = value.strip()
    try:
        parts = urlsplit(value)
        host = parts.hostname
    except ValueError:
        parts, host = None, None
    if not parts or not host or parts.scheme not in ("http", "https"):
        raise ValueError("The issuer must be an https:// URL")
    if "<" in value or ">" in value:
        raise ValueError("Replace the <placeholders> in the issuer URL")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ValueError("The issuer URL has no credentials, query or fragment")
    if parts.scheme == "http" and host not in LOCAL_HOSTS and not allow_http:
        raise ValueError("The issuer uses plain http: use https (or allow http for a lab)")
    return value


def _values(raw: Any, what: str) -> list[str]:
    items = raw if isinstance(raw, list) else [v for v in str(raw or "").split(",")]
    out = [str(v).strip() for v in items if str(v).strip()]
    if len(out) > 50 or any(len(v) > 200 or any(c in v for c in "\r\n") for v in out):
        raise ValueError(f"{what}: at most 50 values of at most 200 characters")
    return list(dict.fromkeys(out))


def clean(body: dict[str, Any], current: dict[str, Any], env: set[str], settings: Settings | None = None) -> dict[str, Any]:
    """The values to store (fields set by the environment are left alone); ValueError with a message for people.
    `settings` holds the environment's values (HUB_OIDC_ALLOW_HTTP decides for the issuer when it is set)."""
    out = {k: v for k, v in current.items() if k not in ("updated_by", "updated_at")}
    preset = body.get("preset") or current.get("preset") or "generic"
    if preset not in PRESET_IDS:
        raise ValueError(f"preset is one of {', '.join(sorted(PRESET_IDS))}")
    out["preset"] = preset
    if "provider_name" in body:
        name = " ".join(str(body.get("provider_name") or "").split())[:40]
        if any(not (c.isprintable()) for c in name):
            raise ValueError("The provider name must be plain text")
        out["provider_name"] = name or None
    if not out.get("provider_name"):
        out["provider_name"] = next(p["provider_name"] for p in PRESETS if p["id"] == preset)
    if "allow_http" in env:  # the environment wins here too
        allow_http = bool(settings.oidc_allow_http) if settings is not None else False
    else:
        allow_http = bool(body["allow_http"]) if "allow_http" in body and body["allow_http"] is not None \
            else bool(current.get("allow_http"))
        out["allow_http"] = allow_http
    if "issuer" in body and "issuer" not in env:
        out["issuer"] = _url(str(body.get("issuer") or ""), allow_http) if body.get("issuer") else None
    if "client_id" in body and "client_id" not in env:
        client_id = str(body.get("client_id") or "").strip()
        if len(client_id) > 255 or any(c.isspace() for c in client_id):
            raise ValueError("The client ID is one word of at most 255 characters")
        out["client_id"] = client_id or None
    if "scopes" in body and "scopes" not in env:
        scopes = str(body.get("scopes") or "").split()
        if any(not SCOPE_RE.match(s) for s in scopes) or len(scopes) > 20:
            raise ValueError("Scopes are up to 20 words separated by spaces")
        out["scopes"] = " ".join(dict.fromkeys(["openid", *scopes]))
    if "role_claim" in body and "role_claim" not in env:
        claim = str(body.get("role_claim") or "").strip()
        if claim and not CLAIM_RE.match(claim):
            raise ValueError("The role claim is a claim name or a dotted path such as realm_access.roles")
        out["role_claim"] = claim or None
    for key, what in (("admin_values", "Admin values"), ("operator_values", "Operator values"),
                      ("viewer_values", "Viewer values")):
        if key in body and key not in env:
            out[key] = _values(body.get(key), what)
    if "allowed_domains" in body and "allowed_domains" not in env:
        domains = [d.lower().lstrip("@") for d in _values(body.get("allowed_domains"), "Allowed domains")]
        if any(not DOMAIN_RE.match(d) for d in domains):
            raise ValueError("Allowed domains are domain names such as example.com")
        out["allowed_domains"] = domains
    if "default_role" in body and "default_role" not in env:
        role = body.get("default_role") or "viewer"
        if role not in SSO_DEFAULT_ROLES:
            raise ValueError(f"The default role is one of {', '.join(SSO_DEFAULT_ROLES)}")
        out["default_role"] = role
    elif not current and "default_role" not in env:  # new settings refuse people outside the Atrium groups (F18)
        out["default_role"] = "none"
    return out


def save(hub: "Hub", body: dict[str, Any], actor: str, *, generated_secret: str | None = None) -> dict[str, Any]:
    """Validate and store the settings, then rebuild the OIDC client. Returns the stored document."""
    env = env_keys(hub.settings)
    current = stored(hub) or {}
    doc = clean(body, current, env, hub.settings)
    issuer = doc.get("issuer") if "issuer" not in env else hub.settings.oidc_issuer
    new_secret = generated_secret or str(body.get("client_secret") or "")
    changed_secret = False
    if "client_secret" not in env:
        if body.get("clear_client_secret"):
            doc.pop("client_secret", None)
            doc.pop("secret_endpoint", None)
            changed_secret = bool(current.get("client_secret"))
        if new_secret:
            if len(new_secret) > 4096:
                raise ValueError("The client secret is at most 4096 characters")
            doc["client_secret"] = hub.secrets.encrypt(new_secret)
            doc["secret_endpoint"] = endpoint_of(issuer)
            changed_secret = True
        elif doc.get("client_secret") and endpoint_of(doc.get("secret_endpoint")) != endpoint_of(issuer):
            raise ValueError("Enter the client secret again: the stored one is only sent to the issuer it was entered for")
    doc.update(id=DOC, updated_by=actor, updated_at=time.time())
    hub.store.put("settings", doc)  # straight to the store: never broadcast
    rebuild(hub)
    shown = [k for k in ("preset", "provider_name", "issuer", "client_id", "scopes", "role_claim", "admin_values",
                         "operator_values", "viewer_values", "default_role", "allowed_domains", "allow_http")
             if doc.get(k) != current.get(k)]
    hub.activity(actor, "warn" if doc.get("allow_http") and not current.get("allow_http") else "info",
                 "Changed the Sign-in & SSO settings" + (f": {', '.join(shown)}" if shown else "")
                 + ("; client secret updated" if changed_secret else ""))
    return doc


def remove(hub: "Hub", actor: str) -> bool:
    removed = hub.store.delete("settings", DOC)
    rebuild(hub)
    if removed:
        hub.activity(actor, "info", "Removed the Sign-in & SSO settings stored in the database")
    return removed


# --------------------------------------------------------------------------------------
# the view
# --------------------------------------------------------------------------------------


def imported_providers(hub: "Hub") -> list[dict[str, Any]]:
    """Identity providers imported into the suite (Keycloak, authentik) as prefilled choices, with whether Atrium's
    generated sign-in client secret exists (Identity > "Use for Atrium sign-in")."""
    from ..integration import identity

    prefs = identity.load_prefs(hub)
    out = []
    for p in identity.list_providers(hub.tools(), prefs.settings):
        if "oidc" not in p.protocols:
            continue
        try:
            has_secret = identity._secret_path(hub.settings.workspace, "atrium", p.tool_id, "client-secret").is_file()
        except ValueError:
            has_secret = False
        out.append({"tool_id": p.tool_id, "name": p.name, "kind": p.kind,
                    "preset": p.kind if p.kind in PRESET_IDS else "generic", "provider_name": p.name,
                    "issuer": p.client_issuer(p.slug), "client_id": "atrium", "scopes": "openid profile email",
                    "role_claim": "groups", "admin_values": [identity.ATRIUM_GROUPS[0]],
                    "operator_values": [identity.ATRIUM_GROUPS[1]], "generated_secret": has_secret})
    return out


def generated_secret(hub: "Hub", provider_id: str) -> str:
    """The client secret Atrium generated for its own sign-in at an imported provider (never shown)."""
    from ..integration import identity

    if not any(p["tool_id"] == provider_id for p in imported_providers(hub)):
        raise ValueError(f"Unknown identity provider '{provider_id}'")
    path = identity._secret_path(hub.settings.workspace, "atrium", provider_id, "client-secret")
    value = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
    if not value:
        raise ValueError("Atrium has no generated sign-in client for this provider yet - generate it under Identity "
                         "('Use for Atrium sign-in') first")
    return value


def view(hub: "Hub") -> dict[str, Any]:
    """GET /api/auth/sso: the effective settings and where each value comes from; the secret only as set / not set."""
    doc = stored(hub)
    settings, origin, error = effective(hub, doc)
    env = env_keys(hub.settings)
    values = {k: getattr(settings, a) for k, a in KEYS.items() if k != "client_secret"}
    return {
        "enabled": hub.auth.oidc.enabled, "label": hub.auth.oidc.label,
        "redirect_uri": f"{hub.settings.public_url}/api/auth/oidc/callback",
        "values": values, "source": origin, "client_secret_set": bool(settings.oidc_client_secret),
        "secret_error": error, "env": sorted(env), "env_vars": {k: OIDC_ENV[a] for k, a in KEYS.items()},
        "stored": {k: doc.get(k) for k in ("preset", "provider_name", "updated_by", "updated_at")} if doc else None,
        "presets": PRESETS, "imported": imported_providers(hub),
    }


def candidate(hub: "Hub", body: dict[str, Any]) -> Settings:
    """Settings as they would be with `body` saved (for the Test button; nothing is stored)."""
    doc = clean(body, stored(hub) or {}, env_keys(hub.settings), hub.settings)
    doc.pop("client_secret", None)  # discovery needs no secret, and none is sent
    settings, _, _ = effective(hub, doc)
    return settings
