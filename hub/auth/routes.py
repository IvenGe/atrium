"""Sign-in, self-service and account administration endpoints (/api/auth, /api/users, /api/tokens)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated, Any, Literal

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from ..models import TokenRole, UserRole, public_token, public_user
from . import sso_settings
from .oidc import OidcClient, OidcError, safe_code
from .service import STATE_COOKIE, AuthError, CurrentPrincipal, Principal, client_ip

if TYPE_CHECKING:
    from ..core import Hub

Password = Annotated[str, Field(max_length=1024)]


class LoginBody(BaseModel):
    username: str = Field(max_length=256)
    password: Password


class SetupBody(BaseModel):
    token: str = Field(max_length=256)
    username: str = Field(max_length=64)
    password: Password
    display_name: str = Field("", max_length=100)
    email: str | None = Field(None, max_length=254)


class PasswordChange(BaseModel):
    current_password: Password
    new_password: Password


class NewUser(BaseModel):
    username: str = Field(max_length=64)
    password: Password
    role: UserRole = "viewer"
    display_name: str = Field("", max_length=100)
    email: str | None = Field(None, max_length=254)
    must_change_password: bool = True


class UserPatch(BaseModel):
    display_name: str | None = Field(None, max_length=100)
    email: str | None = Field(None, max_length=254)
    role: UserRole | None = None
    disabled: bool | None = None


class PasswordReset(BaseModel):
    new_password: Password
    must_change_password: bool = True


class NewToken(BaseModel):
    name: str = Field(max_length=64)
    role: TokenRole
    expires_days: int | None = Field(None, ge=1, le=3650)
    tool_id: str | None = Field(None, max_length=64)  # integration tokens: the tool they publish as (default: the name)


class SsoBody(BaseModel):
    """Sign-in & SSO settings; only the fields sent change (fields set by HUB_OIDC_* variables are left alone)."""

    preset: str | None = Field(None, max_length=20)  # okta | entra | google | keycloak | authentik | generic
    provider_name: str | None = Field(None, max_length=40)  # the sign-in button says "Sign in with <name>"
    issuer: str | None = Field(None, max_length=500)
    client_id: str | None = Field(None, max_length=255)
    client_secret: str | None = Field(None, max_length=4096)  # empty or absent: keep the stored one
    clear_client_secret: bool = False
    generated_secret_from: str | None = Field(None, max_length=64)  # use Atrium's generated client at this provider
    scopes: str | None = Field(None, max_length=500)
    role_claim: str | None = Field(None, max_length=100)
    admin_values: list[str] | None = Field(None, max_length=50)
    operator_values: list[str] | None = Field(None, max_length=50)
    viewer_values: list[str] | None = Field(None, max_length=50)
    default_role: Literal["viewer", "operator", "admin", "none"] | None = None  # "none": refuse everyone else (F18)
    allowed_domains: list[str] | None = Field(None, max_length=50)
    allow_http: bool | None = None


# The error codes of OAuth 2.0 (RFC 6749 4.1.2.1) and OpenID Connect Core (3.1.2.6) an authorization response carries.
PROVIDER_ERRORS = frozenset({
    "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type", "invalid_scope",
    "server_error", "temporarily_unavailable", "interaction_required", "login_required", "account_selection_required",
    "consent_required", "invalid_request_uri", "invalid_request_object", "request_not_supported",
    "request_uri_not_supported", "registration_not_supported",
})
SSO_NOTICE_COOKIE = "atrium_sso_notice"  # why the last single sign-on failed, for this browser's sign-in screen
SSO_NOTICE_TTL = 300


class ProviderRefused(OidcError):
    """The identity provider answered the callback with an error. The callback is public, so anyone can send a browser
    there with any error and error_description: the person sees a fixed sentence (with the code when it is a standard
    one), never the description, and the activity log only the (reduced) code."""

    def __init__(self, error: str, description: str | None):
        code = error if error in PROVIDER_ERRORS else None
        super().__init__(f"The identity provider refused the sign-in ({code})." if code
                         else "The identity provider refused the sign-in.")
        self.logged = f"the identity provider refused the sign-in ({safe_code(error)})"


def build_auth_router(hub: "Hub") -> APIRouter:
    router = APIRouter()
    auth = hub.auth
    # Why a single sign-on failed travels to the sign-in screen in a cookie only this hub process can read or make,
    # never in the URL: a link like /#/login?error=... or a page on another port of the same host (cookies do not
    # isolate ports) cannot make the sign-in screen show its own text (review F32).
    notices = Fernet(Fernet.generate_key())

    async def evaluate_grc(principal: Principal | str) -> None:
        sender = principal if isinstance(principal, str) else principal.bus_id
        await hub.bus.tell(sender, "module:grc", "evaluate")

    def require_person(principal: Principal) -> None:
        if principal.kind != "user":
            raise HTTPException(400, "Only people signed in with an account can do this.")

    def take_sso_notice(request: Request, response: Response) -> str | None:
        sealed = request.cookies.get(SSO_NOTICE_COOKIE)
        if sealed is None:
            return None
        response.delete_cookie(SSO_NOTICE_COOKIE, path="/api/auth", secure=auth.secure_cookies(request), httponly=True,
                               samesite="lax")
        try:
            return notices.decrypt(sealed.encode("ascii"), ttl=SSO_NOTICE_TTL).decode("utf-8")
        except (InvalidToken, UnicodeError):
            return None

    # -- signing in ----------------------------------------------------------------------

    @router.get("/auth/me")
    async def me(request: Request, response: Response) -> dict[str, Any]:
        principal: Principal | None = getattr(request.state, "principal", None)
        user = auth.get_user(principal.id) if principal and principal.kind == "user" else None
        return {
            "authenticated": principal is not None,
            "user": public_user(user) if user else None,
            "setup_required": auth.setup_required,
            "oidc": {"enabled": auth.oidc.enabled, "label": auth.oidc.label},
            "session": {"idle_minutes": hub.settings.session_idle_minutes, "days": hub.settings.session_days},
            # why this browser's last single sign-on failed, shown once on the sign-in screen
            "sso_error": take_sso_notice(request, response),
        }

    @router.post("/auth/login")
    async def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
        user = await auth.login(body.username, body.password, request)
        auth.start_session(user, request, response)
        auth.remember_device(user, request, response)
        return {"user": public_user(user)}

    @router.post("/auth/logout")
    async def logout(principal: CurrentPrincipal, request: Request, response: Response) -> dict[str, Any]:
        if principal.kind == "user" and principal.session_id:
            auth.end_session(principal.session_id)
            hub.activity(principal.actor, "info", "Signed out", ip=client_ip(request))
        auth.clear_session_cookie(request, response)
        return {"ok": True}

    @router.post("/auth/password")
    async def change_password(body: PasswordChange, principal: CurrentPrincipal, request: Request) -> dict[str, Any]:
        await auth.change_password(principal, body.current_password, body.new_password, request)
        return {"ok": True}

    @router.get("/auth/sessions")
    async def my_sessions(principal: CurrentPrincipal) -> list[dict[str, Any]]:
        require_person(principal)
        items = sorted(auth.sessions(principal.id), key=lambda s: -s["last_seen"])
        return [{"id": s["id"][:12], "created_at": s["created_at"], "last_seen": s["last_seen"],
                 "expires_at": s["expires_at"], "ip": s.get("ip"), "user_agent": s.get("user_agent", ""),
                 "current": s["id"] == principal.session_id} for s in items]

    @router.delete("/auth/sessions")
    async def sign_out_others(principal: CurrentPrincipal) -> dict[str, Any]:
        require_person(principal)
        revoked = auth.revoke_sessions(principal.id, keep=principal.session_id)
        if revoked:
            hub.activity(principal.actor, "info", f"Signed out {revoked} other session(s)")
        return {"revoked": revoked}

    @router.post("/auth/setup")
    async def setup(body: SetupBody, request: Request, response: Response) -> dict[str, Any]:
        user = await auth.setup(body.token, body.username, body.password, body.display_name, body.email, request)
        auth.start_session(user, request, response)
        await evaluate_grc(f"user:{user.username}")
        return {"user": public_user(user)}

    # -- single sign-on ------------------------------------------------------------------

    def to_login(message: str, request: Request) -> RedirectResponse:
        response = RedirectResponse("/#/login", status_code=302)
        response.set_cookie(SSO_NOTICE_COOKIE, notices.encrypt(message[:300].encode("utf-8")).decode("ascii"),
                            max_age=SSO_NOTICE_TTL, path="/api/auth", secure=auth.secure_cookies(request),
                            httponly=True, samesite="lax")
        return response

    def require_sso() -> None:
        if not auth.oidc.enabled:
            raise HTTPException(404, "Single sign-on is not configured")

    @router.get("/auth/oidc/login")
    async def oidc_login(request: Request) -> Response:
        require_sso()
        try:
            url, state = await auth.oidc.begin()
        except OidcError as exc:
            auth.log_sso_failure(f"Single sign-on could not start: {exc}", client_ip(request))
            return to_login(str(exc), request)
        response = RedirectResponse(url, status_code=302)
        response.set_cookie(STATE_COOKIE, state, max_age=600, path="/api/auth/oidc", secure=auth.secure_cookies(request),
                            httponly=True, samesite="lax")
        return response

    @router.get("/auth/oidc/callback")
    async def oidc_callback(request: Request, code: str | None = None, state: str | None = None,
                            error: str | None = None, error_description: str | None = None) -> Response:
        require_sso()
        response: Response
        try:
            if error:
                raise ProviderRefused(error, error_description)
            if not code or not state:
                raise OidcError("The identity provider did not return a sign-in code.")
            identity = await auth.oidc.complete(code, state, request.cookies.get(STATE_COOKIE))
            user = auth.provision_oidc(identity, request)
        except (OidcError, AuthError) as exc:
            # anyone can call this route: the log gets the provider's error code, never its free text, and only so
            # many entries (review F15)
            logged = exc.logged if isinstance(exc, ProviderRefused) else str(exc)[:300]
            auth.log_sso_failure(f"Single sign-on failed: {logged}", client_ip(request))
            response = to_login(str(exc), request)
        else:
            response = RedirectResponse("/#/", status_code=302)
            auth.start_session(user, request, response)
            await evaluate_grc(f"user:{user.username}")
        response.delete_cookie(STATE_COOKIE, path="/api/auth/oidc", secure=auth.secure_cookies(request),
                               httponly=True, samesite="lax")
        return response

    # -- Sign-in & SSO settings (admin) --------------------------------------------------

    def sso_fields(body: SsoBody) -> dict[str, Any]:
        return body.model_dump(exclude_unset=True, exclude={"generated_secret_from"})

    @router.get("/auth/sso")
    async def get_sso() -> dict[str, Any]:
        return sso_settings.view(hub)

    @router.put("/auth/sso")
    async def put_sso(body: SsoBody, principal: CurrentPrincipal) -> dict[str, Any]:
        try:
            secret = sso_settings.generated_secret(hub, body.generated_secret_from) if body.generated_secret_from else None
            sso_settings.save(hub, sso_fields(body), principal.actor, generated_secret=secret)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await evaluate_grc(principal)
        return sso_settings.view(hub)

    @router.post("/auth/sso/test")
    async def test_sso(principal: CurrentPrincipal, body: SsoBody | None = None) -> dict[str, Any]:
        """Run discovery (and fetch the signing keys) for the settings as they would be saved - nothing is stored."""
        try:
            settings = sso_settings.candidate(hub, sso_fields(body or SsoBody()))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        client = OidcClient(settings, transport=hub.auth.oidc_transport)
        try:
            found = await client.check()
        except OidcError as exc:
            return {"ok": False, "detail": str(exc), "issuer": settings.oidc_issuer}
        notes = []
        if found["role_claim_advertised"] is False:
            notes.append(f"The provider does not list the '{settings.oidc_role_claim}' claim - add it at the provider, "
                         f"or everyone signs in as {settings.oidc_default_role}.")
        if not found["pkce_s256"]:
            notes.append("The provider does not advertise PKCE (S256); sign-in uses it anyway.")
        hub.activity(principal.actor, "info", f"Tested the single sign-on settings against {found['issuer']}")
        return {"ok": True, "detail": f"Discovery and {found['signing_keys']} signing key(s) found at {found['issuer']}",
                "notes": notes, **found}

    @router.delete("/auth/sso")
    async def delete_sso(principal: CurrentPrincipal) -> dict[str, Any]:
        sso_settings.remove(hub, principal.actor)
        await evaluate_grc(principal)
        return sso_settings.view(hub)

    # -- users (admin) -------------------------------------------------------------------

    @router.get("/users")
    async def list_users() -> list[dict[str, Any]]:
        """Accounts, each with the person (People app) who has the same email, if any."""
        from ..people import all_people, brief, person_for_user

        everyone = all_people(hub)
        return [{**public_user(u), "person": brief(person_for_user(u, everyone))} for u in auth.users()]

    @router.post("/users", status_code=201)
    async def create_user(body: NewUser, principal: CurrentPrincipal) -> dict[str, Any]:
        user = auth.create_user(body.username, body.password, role=body.role, display_name=body.display_name,
                                email=body.email, must_change_password=body.must_change_password, actor=principal.actor)
        await evaluate_grc(principal)
        return public_user(user)

    @router.patch("/users/{user_id}")
    async def update_user(user_id: str, body: UserPatch, principal: CurrentPrincipal) -> dict[str, Any]:
        user = auth.update_user(user_id, body.model_dump(exclude_unset=True), principal)
        await evaluate_grc(principal)
        return public_user(user)

    @router.post("/users/{user_id}/password")
    async def reset_password(user_id: str, body: PasswordReset, principal: CurrentPrincipal) -> dict[str, Any]:
        user = auth.reset_password(user_id, body.new_password, body.must_change_password, principal)
        return public_user(user)

    @router.delete("/users/{user_id}")
    async def delete_user(user_id: str, principal: CurrentPrincipal) -> dict[str, Any]:
        auth.delete_user(user_id, principal)
        await evaluate_grc(principal)
        return {"ok": True}

    # -- API tokens (admin) --------------------------------------------------------------

    @router.get("/tokens")
    async def list_tokens() -> list[dict[str, Any]]:
        return [public_token(t) for t in sorted(auth.tokens(), key=lambda t: -t.created_at)]

    @router.post("/tokens", status_code=201)
    async def create_token(body: NewToken, principal: CurrentPrincipal) -> dict[str, Any]:
        token, secret = auth.create_token(body.name, body.role, body.expires_days, principal, tool_id=body.tool_id)
        return {**public_token(token), "token": secret}

    @router.delete("/tokens/{token_id}")
    async def revoke_token(token_id: str, principal: CurrentPrincipal) -> dict[str, Any]:
        auth.revoke_token(token_id, principal)
        return {"ok": True}

    return router
