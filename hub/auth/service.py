"""Accounts, sessions, API tokens and sign-in throttling: everything the hub needs to know who is calling."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import math
import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Annotated, Any, Literal

from fastapi import Depends, HTTPException, Request, Response

from ..models import ApiToken, User, normalize_username
from .oidc import OidcClient, OidcIdentity
from .passwords import dummy_hash, hash_password, validate_password, verify_password
from .policy import ROLES

if TYPE_CHECKING:
    from ..core import Hub

SESSION_COOKIE = "atrium_session"
STATE_COOKIE = "atrium_oidc_state"
TOKEN_PREFIX = "atr_"
TOUCH_INTERVAL = 60  # seconds between last_seen / last_used writes
THROTTLE_WINDOW = 15 * 60
MAX_USER_FAILURES, MAX_IP_FAILURES = 5, 20
DAY = 24 * 3600


class AuthError(Exception):
    """An auth failure with the HTTP status and message the API answers with."""

    def __init__(self, status: int, detail: str, headers: dict[str, str] | None = None):
        super().__init__(detail)
        self.status, self.detail, self.headers = status, detail, headers


@dataclass
class Principal:
    kind: Literal["user", "token"]
    id: str
    name: str
    role: str
    actor: str  # how the activity log names them
    bus_id: str  # sender id of bus messages sent on their behalf
    session_id: str | None = None
    must_change_password: bool = False


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def bearer_token(request: Request) -> str | None:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def get_principal(request: Request) -> Principal:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(401, "Sign in required")
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def _printable(value: str) -> str:
    return re.sub(r"[^\w.@#-]", "?", value)[:64]


class Throttle:
    """In-memory failed sign-in counters per (username, ip) and per ip, over a sliding window."""

    def __init__(self) -> None:
        self._by_user: dict[tuple[str, str], list[float]] = {}
        self._by_ip: dict[str, list[float]] = {}

    @staticmethod
    def _recent(bucket: dict[Any, list[float]], key: Any) -> list[float]:
        cutoff = time.time() - THROTTLE_WINDOW
        times = [t for t in bucket.get(key, []) if t > cutoff]
        if times:
            bucket[key] = times
        else:
            bucket.pop(key, None)
        return times

    def retry_after(self, username: str, ip: str) -> int | None:
        """Seconds until the next attempt is allowed; None when not locked out."""
        unlock = []
        user = self._recent(self._by_user, (username, ip))
        if len(user) >= MAX_USER_FAILURES:
            unlock.append(user[-MAX_USER_FAILURES] + THROTTLE_WINDOW)
        by_ip = self._recent(self._by_ip, ip)
        if len(by_ip) >= MAX_IP_FAILURES:
            unlock.append(by_ip[-MAX_IP_FAILURES] + THROTTLE_WINDOW)
        return max(1, math.ceil(max(unlock) - time.time())) if unlock else None

    def attempt(self, username: str, ip: str) -> float:
        """Count an attempt as failed up front, so parallel guesses cannot slip past the limit while a password
        is being verified; returns its timestamp for cancel() / succeeded()."""
        if len(self._by_user) > 10_000:  # keep memory bounded under a spray of usernames
            for key in list(self._by_user):
                self._recent(self._by_user, key)
        now = time.time()
        self._by_user.setdefault((username, ip), []).append(now)
        self._by_ip.setdefault(ip, []).append(now)
        return now

    def cancel(self, username: str, ip: str, ts: float) -> None:
        """Take back an attempt that was not a failed guess."""
        for times in (self._by_user.get((username, ip)), self._by_ip.get(ip)):
            if times and ts in times:
                times.remove(ts)

    def succeeded(self, username: str, ip: str, ts: float) -> None:
        self.cancel(username, ip, ts)
        self._by_user.pop((username, ip), None)


class AuthService:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self.settings = hub.settings
        self.store = hub.store
        from . import sso_settings

        self.oidc_transport: Any = None  # tests route the identity provider's HTTP through a mock
        self.oidc = OidcClient(sso_settings.effective(hub)[0])
        self.setup_token: str | None = None
        self.throttle = Throttle()

    # -- first run -------------------------------------------------------------------

    def bootstrap(self) -> None:
        """Create the first administrator from the environment, or arm first-run setup."""
        self.purge_sessions()
        if self.users():
            return
        s = self.settings
        if s.admin_username and s.admin_password:
            try:
                self.create_user(s.admin_username, s.admin_password, role="admin", actor="hub")
            except AuthError as exc:
                raise ValueError(f"HUB_ADMIN_USERNAME/HUB_ADMIN_PASSWORD: {exc.detail}") from exc
            return
        self.setup_token = s.setup_token or secrets.token_urlsafe(24)
        self.hub.activity("hub", "warn", "No accounts yet: create the administrator with the setup link printed at start-up")

    @property
    def setup_required(self) -> bool:
        return not self.store.list("users")

    async def setup(self, token: str, username: str, password: str, display_name: str, email: str | None,
                    request: Request) -> User:
        if not self.setup_required:
            raise AuthError(409, "Setup is already complete. Sign in instead.")
        ip = client_ip(request)
        attempt = self._begin_attempt("#setup", ip)
        if not self.setup_token or not hmac.compare_digest(token.encode(), self.setup_token.encode()):
            self._failed("#setup", ip)
            raise AuthError(403, "The setup token is not valid.")
        self.throttle.succeeded("#setup", ip, attempt)
        actor = _printable(username.strip().lower())
        user = self.create_user(username, password, role="admin", display_name=display_name, email=email, actor=actor)
        user.last_login = time.time()
        self._save_user(user)
        self.hub.activity(user.username, "info", "Signed in", ip=ip, method="setup")
        return user

    # -- users -----------------------------------------------------------------------

    def users(self) -> list[User]:
        return self.hub.all("users", User)

    def get_user(self, user_id: str) -> User | None:
        return self.hub.one("users", user_id, User)

    def find_user(self, username: str) -> User | None:
        name = username.strip().lower()
        return next((u for u in self.users() if u.username == name), None)

    def _require_user(self, user_id: str) -> User:
        user = self.get_user(user_id)
        if user is None:
            raise AuthError(404, "User not found")
        return user

    def _save_user(self, user: User) -> None:
        # Users never go through hub.save: that would broadcast the password hash on the event stream.
        self.store.put("users", user.model_dump(mode="json"))

    @staticmethod
    def _clean_email(email: str | None) -> str | None:
        email = (email or "").strip()
        if email and ("@" not in email or len(email) > 254 or any(c.isspace() for c in email)):
            raise AuthError(400, "Enter a valid email address.")
        return email or None

    def create_user(self, username: str, password: str | None, *, role: str = "viewer", display_name: str = "",
                    email: str | None = None, must_change_password: bool = False, actor: str) -> User:
        try:
            username = normalize_username(username)
            if password is not None:
                validate_password(password, username)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        if role not in ROLES:
            raise AuthError(400, f"Role must be one of {', '.join(ROLES)}.")
        if self.find_user(username):
            raise AuthError(409, "That username is taken.")
        now = time.time()
        user = User(username=username, display_name=display_name.strip(), email=self._clean_email(email),
                    role=role, password_hash=hash_password(password) if password is not None else None,  # type: ignore[arg-type]
                    must_change_password=must_change_password and password is not None,
                    password_changed_at=now if password is not None else None)
        self._save_user(user)
        self.setup_token = None
        self.hub.activity(actor, "info", f"Created {role} account {username}", user_id=user.id)
        return user

    def _guard_last_admin(self, user: User) -> None:
        others = [u for u in self.users() if u.role == "admin" and not u.disabled and u.id != user.id]
        if user.role == "admin" and not user.disabled and not others:
            raise AuthError(400, "At least one enabled administrator must remain.")

    @staticmethod
    def _is_self(user: User, principal: Principal) -> bool:
        return principal.kind == "user" and principal.id == user.id

    def update_user(self, user_id: str, changes: dict[str, Any], principal: Principal) -> User:
        user = self._require_user(user_id)
        role, disabled = changes.get("role"), changes.get("disabled")
        notes = []
        if role is not None and role != user.role:
            if self._is_self(user, principal):
                raise AuthError(400, "You cannot change your own role.")
            if role not in ROLES:
                raise AuthError(400, f"Role must be one of {', '.join(ROLES)}.")
            if role != "admin":
                self._guard_last_admin(user)
            notes.append(f"role {user.role} -> {role}")
            user.role = role
        if disabled is not None and disabled != user.disabled:
            if disabled:
                if self._is_self(user, principal):
                    raise AuthError(400, "You cannot disable your own account.")
                self._guard_last_admin(user)
            notes.append("disabled" if disabled else "enabled")
            user.disabled = disabled
        if changes.get("display_name") is not None:
            user.display_name = changes["display_name"].strip()
            notes.append("display name")
        if "email" in changes:
            user.email = self._clean_email(changes["email"])
            notes.append("email")
        self._save_user(user)
        if user.disabled:
            self.revoke_sessions(user.id)
        if notes:
            self.hub.activity(principal.actor, "info", f"Updated account {user.username}: {', '.join(notes)}", user_id=user.id)
        return user

    def set_password(self, user: User, password: str, *, must_change_password: bool, actor: str) -> User:
        """Set a password on someone's behalf (admin reset, CLI recovery); signs out all their sessions."""
        try:
            validate_password(password, user.username)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        user.password_hash = hash_password(password)
        user.password_changed_at = time.time()
        user.must_change_password = must_change_password
        self._save_user(user)
        revoked = self.revoke_sessions(user.id)
        self.hub.activity(actor, "info", f"Reset the password of {user.username}", user_id=user.id, sessions_revoked=revoked)
        return user

    def reset_password(self, user_id: str, password: str, must_change_password: bool, principal: Principal) -> User:
        user = self._require_user(user_id)
        if self._is_self(user, principal):
            raise AuthError(400, "Use Change password for your own account.")
        if user.auth_source == "oidc":
            raise AuthError(400, "This account signs in through single sign-on.")
        return self.set_password(user, password, must_change_password=must_change_password, actor=principal.actor)

    def delete_user(self, user_id: str, principal: Principal) -> None:
        user = self._require_user(user_id)
        if self._is_self(user, principal):
            raise AuthError(400, "You cannot delete your own account.")
        self._guard_last_admin(user)
        self.revoke_sessions(user.id)
        self.store.delete("users", user.id)
        self.hub.activity(principal.actor, "info", f"Deleted account {user.username}", user_id=user.id)

    # -- signing in ------------------------------------------------------------------

    def _check_throttle(self, username: str, ip: str) -> None:
        wait = self.throttle.retry_after(username, ip)
        if wait is not None:
            minutes = max(1, math.ceil(wait / 60))
            raise AuthError(429, f"Too many failed sign-ins. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
                            {"Retry-After": str(wait)})

    def _begin_attempt(self, username: str, ip: str) -> float:
        self._check_throttle(username, ip)
        return self.throttle.attempt(username, ip)

    def _failed(self, username: str, ip: str) -> None:
        """Log a failed attempt (already counted by _begin_attempt), and the lockout it may start."""
        name = _printable(username)
        what = "first-run setup attempt" if username == "#setup" else f"sign-in for {name}"
        self.hub.activity("auth", "warn", f"Failed {what}", username=name, ip=ip)
        if self.throttle.retry_after(username, ip) is not None:
            self.hub.activity("auth", "warn", f"Locked out {name} from {ip} after repeated failures",
                              username=name, ip=ip, minutes=THROTTLE_WINDOW // 60)

    async def login(self, username: str, password: str, request: Request) -> User:
        ip = client_ip(request)
        name = username.strip().lower()
        key = name[:64]  # bounded throttle key
        attempt = self._begin_attempt(key, ip)
        user = self.find_user(name)
        stored = user.password_hash if user else None
        # Unknown users are verified against a dummy hash so timing does not reveal which usernames exist.
        ok = await asyncio.to_thread(verify_password, password, stored or dummy_hash())
        if user is None or stored is None or not ok:
            self._failed(key, ip)
            raise AuthError(401, "Invalid username or password.")
        if user.disabled:
            self.throttle.cancel(key, ip, attempt)
            raise AuthError(403, "This account is disabled.")
        self.throttle.succeeded(key, ip, attempt)
        user.last_login = time.time()
        self._save_user(user)
        self.hub.activity(user.username, "info", "Signed in", ip=ip, method="password")
        return user

    async def change_password(self, principal: Principal, current: str, new: str, request: Request) -> User:
        user = self.get_user(principal.id) if principal.kind == "user" else None
        if user is None:
            raise AuthError(400, "Only people signed in with an account can change a password.")
        if user.password_hash is None:
            raise AuthError(400, "Your account signs in through single sign-on.")
        ip = client_ip(request)
        attempt = self._begin_attempt(user.username, ip)
        if not await asyncio.to_thread(verify_password, current, user.password_hash):
            self._failed(user.username, ip)
            raise AuthError(400, "Your current password is incorrect.")
        self.throttle.succeeded(user.username, ip, attempt)
        if new == current:
            raise AuthError(400, "Choose a new password that differs from the current one.")
        try:
            validate_password(new, user.username)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        user.password_hash = hash_password(new)
        user.password_changed_at = time.time()
        user.must_change_password = False
        self._save_user(user)
        revoked = self.revoke_sessions(user.id, keep=principal.session_id)
        self.hub.activity(user.username, "info", "Changed their password", sessions_revoked=revoked)
        return user

    def provision_oidc(self, identity: OidcIdentity, request: Request) -> User:
        """Find or create the account behind a single sign-on identity and sync its role."""
        subject = f"{identity.issuer}|{identity.subject}"
        role = identity.role if identity.role in ROLES else self.settings.oidc_default_role
        user = next((u for u in self.users() if u.oidc_subject == subject), None)
        if user is None:
            user = User(username=self._free_username(identity.username or identity.email or "user"),
                        display_name=(identity.name or "").strip(), email=identity.email or None, role=role,  # type: ignore[arg-type]
                        auth_source="oidc", oidc_subject=subject)
            self.hub.activity("auth", "info", f"Created {role} account {user.username} from single sign-on", user_id=user.id)
        elif user.disabled:
            raise AuthError(403, "This account is disabled.")
        elif user.role != role:
            self.hub.activity("auth", "info", f"Role of {user.username} synced from the identity provider: {user.role} -> {role}")
        user.role = role  # type: ignore[assignment]
        user.email = identity.email or user.email
        user.display_name = (identity.name or "").strip() or user.display_name
        user.last_login = time.time()
        self._save_user(user)
        self.hub.activity(user.username, "info", "Signed in", ip=client_ip(request), method="sso")
        return user

    def _free_username(self, raw: str) -> str:
        base = re.sub(r"[^a-z0-9._-]+", "-", raw.strip().lower())
        base = re.sub(r"^[^a-z0-9]+", "", base)[:60].rstrip("-") or "user"
        if len(base) < 2:
            base = f"{base}-user"
        taken = {u.username for u in self.users()}
        candidate, n = base, 1
        while candidate in taken:
            n += 1
            candidate = f"{base}-{n}"
        return candidate

    # -- sessions --------------------------------------------------------------------

    def secure_cookies(self, request: Request) -> bool:
        return request.url.scheme == "https" or self.settings.cookie_secure

    def start_session(self, user: User, request: Request, response: Response) -> str:
        """Create a session for the user and set its cookie; returns the session id."""
        old = request.cookies.get(SESSION_COOKIE)
        if old:
            self.store.delete("sessions", sha256(old))
        raw = secrets.token_urlsafe(32)
        now = time.time()
        lifetime = self.settings.session_days * DAY
        session = {"id": sha256(raw), "user_id": user.id, "created_at": now, "last_seen": now, "expires_at": now + lifetime,
                   "ip": client_ip(request), "user_agent": request.headers.get("user-agent", "")[:200]}
        self.store.put("sessions", session)
        response.set_cookie(SESSION_COOKIE, raw, max_age=lifetime, path="/", secure=self.secure_cookies(request),
                            httponly=True, samesite="lax")
        return session["id"]

    def clear_session_cookie(self, request: Request, response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/", secure=self.secure_cookies(request), httponly=True, samesite="lax")

    def _session_live(self, session: dict[str, Any], now: float) -> bool:
        idle = self.settings.session_idle_minutes * 60
        return now < session["expires_at"] and now - session["last_seen"] < idle

    def session_principal(self, raw: str) -> Principal | None:
        sid = sha256(raw)
        session = self.store.get("sessions", sid)
        if session is None:
            return None
        now = time.time()
        user = self.get_user(session["user_id"])
        if not self._session_live(session, now) or user is None or user.disabled:
            self.store.delete("sessions", sid)
            return None
        if now - session["last_seen"] >= TOUCH_INTERVAL:
            self.store.put("sessions", {**session, "last_seen": now})
        return Principal(kind="user", id=user.id, name=user.username, role=user.role, actor=user.username,
                         bus_id=f"user:{user.username}", session_id=sid, must_change_password=user.must_change_password)

    def sessions(self, user_id: str) -> list[dict[str, Any]]:
        return [s for s in self.store.list("sessions") if s.get("user_id") == user_id]

    def end_session(self, session_id: str) -> None:
        self.store.delete("sessions", session_id)

    def revoke_sessions(self, user_id: str, keep: str | None = None) -> int:
        revoked = 0
        for session in self.sessions(user_id):
            if session["id"] != keep:
                revoked += self.store.delete("sessions", session["id"])
        return revoked

    def purge_sessions(self) -> int:
        now = time.time()
        stale = [s["id"] for s in self.store.list("sessions") if not self._session_live(s, now)]
        for sid in stale:
            self.store.delete("sessions", sid)
        return len(stale)

    # -- API tokens ------------------------------------------------------------------

    def tokens(self) -> list[ApiToken]:
        return self.hub.all("tokens", ApiToken)

    def create_token(self, name: str, role: str, expires_days: int | None, principal: Principal) -> tuple[ApiToken, str]:
        """Returns the token record and its secret; the secret is never stored and cannot be shown again."""
        name = name.strip()
        if not 1 <= len(name) <= 64:
            raise AuthError(400, "Give the token a name of at most 64 characters.")
        if role not in (*ROLES, "integration"):
            raise AuthError(400, "Role must be viewer, operator, admin or integration.")
        if expires_days is not None and not 1 <= expires_days <= 3650:
            raise AuthError(400, "Tokens expire after 1 to 3650 days, or never.")
        if any(t.name == name for t in self.tokens()):
            raise AuthError(409, "A token with that name already exists.")
        secret = secrets.token_urlsafe(32)
        value = TOKEN_PREFIX + secret
        token = ApiToken(name=name, role=role, token_hash=sha256(value), prefix=secret[:8],  # type: ignore[arg-type]
                         created_by=principal.actor,
                         expires_at=time.time() + expires_days * DAY if expires_days else None)
        self.store.put("tokens", token.model_dump(mode="json"))
        self.hub.activity(principal.actor, "info", f"Created API token {name} ({role})", token_id=token.id)
        return token, value

    def revoke_token(self, token_id: str, principal: Principal) -> None:
        token = self.hub.one("tokens", token_id, ApiToken)
        if token is None:
            raise AuthError(404, "Token not found")
        self.store.delete("tokens", token_id)
        self.hub.activity(principal.actor, "info", f"Revoked API token {token.name}", token_id=token_id)

    def token_principal(self, value: str) -> Principal | None:
        if not value.startswith(TOKEN_PREFIX):
            return None
        digest, now = sha256(value), time.time()
        for doc in self.store.list("tokens"):
            if not hmac.compare_digest(str(doc.get("token_hash", "")), digest):
                continue
            token = ApiToken.model_validate(doc)
            if token.expires_at is not None and token.expires_at <= now:
                return None
            if token.last_used is None or now - token.last_used >= TOUCH_INTERVAL:
                token.last_used = now
                self.store.put("tokens", token.model_dump(mode="json"))
            actor = f"token:{token.name}"
            return Principal(kind="token", id=token.id, name=token.name, role=token.role, actor=actor, bus_id=actor)
        return None

    # -- per request -----------------------------------------------------------------

    def resolve(self, request: Request) -> Principal | None:
        """Bearer token if one is sent (the session cookie is then ignored), else the session cookie."""
        value = bearer_token(request)
        if value is not None:
            return self.token_principal(value)
        raw = request.cookies.get(SESSION_COOKIE)
        return self.session_principal(raw) if raw else None

    def still_valid(self, principal: Principal) -> bool:
        """Whether a long-lived connection (the event stream) may keep going; never extends a session."""
        now = time.time()
        if principal.kind == "token":
            doc = self.store.get("tokens", principal.id)
            return doc is not None and (doc.get("expires_at") is None or doc["expires_at"] > now)
        session = self.store.get("sessions", principal.session_id or "")
        user = self.get_user(principal.id)
        return session is not None and self._session_live(session, now) and user is not None and not user.disabled
