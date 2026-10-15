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
from .policy import ROLE_RANK, ROLES

if TYPE_CHECKING:
    from ..core import Hub

SESSION_COOKIE = "atrium_session"
STATE_COOKIE = "atrium_oidc_state"
# Set by a successful password sign-in: that browser's attempts for that username are counted on their own, so failed
# guesses from the same address (everyone behind one proxy) cannot lock its owner out (review F16).
DEVICE_COOKIE = "atrium_device"
DEVICE_DAYS = 180
SSO_LOG_PER_IP, SSO_LOG_TOTAL = 20, 200  # single sign-on failures logged per THROTTLE_WINDOW (review F15)
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
    owner_id: str | None = None  # an API token's owning account (F2)


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

    def retry_after(self, username: str, ip: str, per_ip: bool = True) -> int | None:
        """Seconds until the next attempt is allowed; None when not locked out. `ip` is the client's address, or a
        known browser ("device:<id>") whose attempts do not count towards an address (per_ip False)."""
        unlock = []
        user = self._recent(self._by_user, (username, ip))
        if len(user) >= MAX_USER_FAILURES:
            unlock.append(user[-MAX_USER_FAILURES] + THROTTLE_WINDOW)
        by_ip = self._recent(self._by_ip, ip) if per_ip else []
        if len(by_ip) >= MAX_IP_FAILURES:
            unlock.append(by_ip[-MAX_IP_FAILURES] + THROTTLE_WINDOW)
        return max(1, math.ceil(max(unlock) - time.time())) if unlock else None

    def attempt(self, username: str, ip: str, per_ip: bool = True) -> float:
        """Count an attempt as failed up front, so parallel guesses cannot slip past the limit while a password
        is being verified; returns its timestamp for cancel() / succeeded()."""
        if len(self._by_user) > 10_000:  # keep memory bounded under a spray of usernames
            for key in list(self._by_user):
                self._recent(self._by_user, key)
        now = time.time()
        self._by_user.setdefault((username, ip), []).append(now)
        if per_ip:
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
        self._sso_log: list[tuple[float, str]] = []  # (time, ip) of logged single sign-on failures

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
            tokens = self.revoke_owned_tokens(user)  # F2: a disabled account's tokens end with its sessions
            if tokens:
                notes.append(f"revoked {tokens} API token(s)")
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
        from .. import dashboards

        dashboards.forget_user(self.hub, user.id)  # their personal dashboards and dashboard preferences
        self.hub.llm.memory.forget_user(user.id)  # their conversations with agents
        tokens = self.revoke_owned_tokens(user)
        self.store.delete("users", user.id)
        self.hub.activity(principal.actor, "info", f"Deleted account {user.username}"
                          + (f" and revoked {tokens} API token(s) it owned" if tokens else ""), user_id=user.id)

    # -- signing in ------------------------------------------------------------------

    def _check_throttle(self, username: str, ip: str, per_ip: bool = True) -> None:
        wait = self.throttle.retry_after(username, ip, per_ip)
        if wait is not None:
            minutes = max(1, math.ceil(wait / 60))
            raise AuthError(429, f"Too many failed sign-ins. Try again in {minutes} minute{'s' if minutes != 1 else ''}.",
                            {"Retry-After": str(wait)})

    def _begin_attempt(self, username: str, ip: str, per_ip: bool = True) -> float:
        self._check_throttle(username, ip, per_ip)
        return self.throttle.attempt(username, ip, per_ip)

    def _failed(self, username: str, ip: str, per_ip: bool = True, shown_ip: str | None = None) -> None:
        """Log a failed attempt (already counted by _begin_attempt), and the lockout it may start."""
        name = _printable(username)
        what = "first-run setup attempt" if username == "#setup" else f"sign-in for {name}"
        where = shown_ip or ip
        self.hub.activity("auth", "warn", f"Failed {what}", username=name, ip=where)
        if self.throttle.retry_after(username, ip, per_ip) is not None:
            self.hub.activity("auth", "warn", f"Locked out {name} from {where}"
                              + ("" if per_ip else " (a browser it signed in from before)") + " after repeated failures",
                              username=name, ip=where, minutes=THROTTLE_WINDOW // 60)

    # -- known browsers (review F16) -------------------------------------------------

    def device_of(self, request: Request, username: str) -> str | None:
        """The id of this browser when it signed in as `username` before (its device cookie), else None."""
        raw = request.cookies.get(DEVICE_COOKIE)
        if not raw or len(raw) > 512:
            return None
        try:
            name, _, device = self.hub.secrets.decrypt(raw + "=" * (-len(raw) % 4)).partition("|")
        except Exception:  # not ours, tampered with, or no key: an unknown browser
            return None
        return device if device and hmac.compare_digest(name.encode(), username.encode()) else None

    def remember_device(self, user: User, request: Request, response: Response) -> None:
        try:
            value = self.hub.secrets.encrypt(f"{user.username}|{secrets.token_urlsafe(12)}").rstrip("=")
        except Exception:  # no usable key: sign-in works, the browser is just not remembered
            return
        response.set_cookie(DEVICE_COOKIE, value, max_age=DEVICE_DAYS * DAY, path="/api/auth",
                            secure=self.secure_cookies(request), httponly=True, samesite="strict")

    # -- single sign-on failures in the activity log (review F15) ---------------------

    def log_sso_failure(self, text: str, ip: str) -> None:
        """An activity entry for a failed single sign-on: at most SSO_LOG_PER_IP per address and SSO_LOG_TOTAL in all
        per THROTTLE_WINDOW (the SSO routes are public), then one note that further failures are not logged."""
        now = time.time()
        self._sso_log = [(t, a) for t, a in self._sso_log if t > now - THROTTLE_WINDOW]
        mine = sum(1 for _, a in self._sso_log if a == ip)
        if mine >= SSO_LOG_PER_IP or len(self._sso_log) >= SSO_LOG_TOTAL:
            return
        self._sso_log.append((now, ip))
        self.hub.activity("auth", "warn", text, ip=ip)
        if mine + 1 >= SSO_LOG_PER_IP or len(self._sso_log) >= SSO_LOG_TOTAL:
            whom = f"from {ip}" if mine + 1 >= SSO_LOG_PER_IP else "from anywhere"
            self.hub.activity("auth", "warn", f"Further single sign-on failures {whom} are not logged for "
                                              f"{THROTTLE_WINDOW // 60} minutes", ip=ip)

    async def login(self, username: str, password: str, request: Request) -> User:
        ip = client_ip(request)
        name = username.strip().lower()
        key = name[:64]  # bounded throttle key
        device = self.device_of(request, key)  # a browser this user signed in from before: counted on its own
        where, per_ip = (f"device:{device}", False) if device else (ip, True)
        attempt = self._begin_attempt(key, where, per_ip)
        user = self.find_user(name)
        stored = user.password_hash if user else None
        # Unknown users are verified against a dummy hash so timing does not reveal which usernames exist.
        ok = await asyncio.to_thread(verify_password, password, stored or dummy_hash())
        if user is None or stored is None or not ok:
            self._failed(key, where, per_ip, shown_ip=ip)
            raise AuthError(401, "Invalid username or password.")
        if user.disabled:
            self.throttle.cancel(key, where, attempt)
            raise AuthError(403, "This account is disabled.")
        self.throttle.succeeded(key, where, attempt)
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
        role = identity.role  # OidcClient.role_for: a claim value, else the effective default role (may be "none")
        user = next((u for u in self.users() if u.oidc_subject == subject), None)
        if user is not None and user.disabled:
            raise AuthError(403, "This account is disabled.")
        if role not in ROLES:  # default role "none": not in an Atrium group at the provider (review F18)
            if user is not None:
                revoked = self.revoke_sessions(user.id)
                self.hub.activity("auth", "warn", f"Refused the single sign-on of {user.username}: no Atrium group at "
                                                  "the identity provider any more", user_id=user.id, sessions_revoked=revoked)
            raise AuthError(403, "Your account is not in an Atrium group at the identity provider. Ask an administrator "
                                 "for access.")
        if self.setup_required and role != "admin":  # review F28: setup stays possible until an administrator exists
            raise AuthError(403, "Atrium is not set up yet: its administrator signs in first (the setup link printed at "
                                 "start-up, or single sign-on as an admin).")
        if user is None:
            user = User(username=self._free_username(identity.username or identity.email or "user"),
                        display_name=(identity.name or "").strip(), email=identity.email or None, role=role,  # type: ignore[arg-type]
                        auth_source="oidc", oidc_subject=subject)
            self.hub.activity("auth", "info", f"Created {role} account {user.username} from single sign-on", user_id=user.id)
        elif user.role != role:
            if user.role == "admin" and not [u for u in self.users() if u.role == "admin" and not u.disabled and u.id != user.id]:
                # review F29: the last enabled administrator is never demoted (as update_user and delete_user)
                self.hub.activity("auth", "warn", f"Kept {user.username} as admin although the identity provider gives "
                                                  f"{role}: they are the last enabled administrator - make someone else "
                                                  "an admin first", user_id=user.id)
                role = "admin"
            else:
                self.hub.activity("auth", "info", f"Role of {user.username} synced from the identity provider: {user.role} -> {role}")
        user.role = role  # type: ignore[assignment]
        if identity.email and user.email and identity.email.strip().lower() != user.email.strip().lower():
            # review F17: keep the old address linked (People, leaver checks) and say so
            user.previous_emails = list(dict.fromkeys([*user.previous_emails, user.email]))[-10:]
            self.hub.activity("auth", "warn", f"Email of {user.username} changed at the identity provider: "
                                              f"{user.email} -> {identity.email}", user_id=user.id)
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

    def create_token(self, name: str, role: str, expires_days: int | None, principal: Principal,
                     tool_id: str | None = None) -> tuple[ApiToken, str]:
        """Returns the token record and its secret; the secret is never stored and cannot be shown again. An
        integration token publishes events as `tool_id` only (default: its name)."""
        name = name.strip()
        if not 1 <= len(name) <= 64:
            raise AuthError(400, "Give the token a name of at most 64 characters.")
        if role not in (*ROLES, "integration"):
            raise AuthError(400, "Role must be viewer, operator, admin or integration.")
        if role != "integration" and tool_id:
            raise AuthError(400, "Only integration tokens publish events for a tool.")
        if role == "integration":
            tool_id = (tool_id or name).strip()
            if not re.fullmatch(r"[A-Za-z0-9][\w.-]{0,63}", tool_id):
                raise AuthError(400, "The tool of an integration token is a tool id such as grafana.")
        if expires_days is not None and not 1 <= expires_days <= 3650:
            raise AuthError(400, "Tokens expire after 1 to 3650 days, or never.")
        if any(t.name == name for t in self.tokens()):
            raise AuthError(409, "A token with that name already exists.")
        owner_id = principal.id if principal.kind == "user" else principal.owner_id
        if owner_id is None or self.get_user(owner_id) is None:
            raise AuthError(400, "Only a person's account, or a token that acts for one, can create API tokens.")
        secret = secrets.token_urlsafe(32)
        value = TOKEN_PREFIX + secret
        token = ApiToken(name=name, role=role, token_hash=sha256(value), prefix=secret[:8],  # type: ignore[arg-type]
                         created_by=principal.actor, owner_id=owner_id, tool_id=tool_id if role == "integration" else None,
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

    def token_owner(self, token: ApiToken) -> User | None:
        """The account a token acts for (F2). Tokens stored before owner_id existed are bound once, by following
        created_by (a token created with another token: that token's owner) to an account."""
        if token.owner_id is not None:
            return self.get_user(token.owner_id)
        creator, seen = token.created_by, {token.id}
        tokens = {t.name: t for t in self.tokens()}
        while creator.startswith("token:"):
            parent = tokens.get(creator[6:])
            if parent is None or parent.id in seen:
                return None
            seen.add(parent.id)
            if parent.owner_id is not None:
                owner = self.get_user(parent.owner_id)
                break
            creator = parent.created_by
        else:
            owner = self.find_user(creator.removeprefix("user:")) if creator else None
        if owner is not None:
            token.owner_id = owner.id
            self.store.put("tokens", token.model_dump(mode="json"))
        return owner

    def token_role(self, token: ApiToken) -> str | None:
        """What a token may do now: never more than its owner's current role; None when the owner is gone or
        disabled (the token is refused) or the token expired. Integration tokens keep their own, narrower role."""
        if token.expires_at is not None and token.expires_at <= time.time():
            return None
        owner = self.token_owner(token)
        if owner is None or owner.disabled:
            return None
        if token.role == "integration":
            return "integration"
        if token.role == "subsidiary":  # a sidecar's token: only while its owner is an enabled administrator (F2)
            ok = owner.role == "admin" and bool(token.subsidiary_id) and bool(token.tool_id)
            return "subsidiary" if ok else None
        if token.role not in ROLE_RANK:  # a role this hub does not serve is refused
            return None
        return token.role if ROLE_RANK[token.role] <= ROLE_RANK[owner.role] else owner.role

    def revoke_owned_tokens(self, user: User) -> int:
        """Delete the API tokens that act for `user` (account disabled or deleted)."""
        revoked = 0
        for token in self.tokens():
            owner = self.token_owner(token)
            if owner is not None and owner.id == user.id:
                revoked += self.store.delete("tokens", token.id)
        return revoked

    def publishing_tool(self, principal: Principal, source: str) -> str:
        """The tool an integration token may publish events as (review F31); a token from before tool_id existed is
        bound to the first source it publishes as."""
        doc = self.store.get("tokens", principal.id)
        if doc is None:
            raise AuthError(401, "Sign in required")
        token = ApiToken.model_validate(doc)
        if token.tool_id is None:
            token.tool_id = source
            self.store.put("tokens", token.model_dump(mode="json"))
            self.hub.activity(principal.actor, "info", f"API token {token.name} now publishes events as {source} only",
                              token_id=token.id)
        return token.tool_id

    def sender_role(self, sender: str) -> str | None:
        """The current role of the person ("user:<name>") or API token ("token:<name>") behind a bus sender; None
        for agents, unknown or disabled accounts and refused tokens."""
        if sender.startswith("user:"):
            user = self.find_user(sender[5:])
            return user.role if user is not None and not user.disabled else None
        if sender.startswith("token:"):
            token = next((t for t in self.tokens() if t.name == sender[6:]), None)
            return self.token_role(token) if token is not None else None
        return None

    def token_principal(self, value: str) -> Principal | None:
        if not value.startswith(TOKEN_PREFIX):
            return None
        digest, now = sha256(value), time.time()
        for doc in self.store.list("tokens"):
            if not hmac.compare_digest(str(doc.get("token_hash", "")), digest):
                continue
            token = ApiToken.model_validate(doc)
            role = self.token_role(token)
            if role is None:
                return None
            if token.last_used is None or now - token.last_used >= TOUCH_INTERVAL:
                token.last_used = now
                self.store.put("tokens", token.model_dump(mode="json"))
            # a subsidiary's sidecar is never a person: its actor and bus id name the tool (approvals.person -> None)
            actor = f"subsidiary:{token.tool_id}" if role == "subsidiary" else f"token:{token.name}"
            return Principal(kind="token", id=token.id, name=token.name, role=role, actor=actor, bus_id=actor,
                             owner_id=token.owner_id)
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
            return doc is not None and self.token_role(ApiToken.model_validate(doc)) == principal.role
        session = self.store.get("sessions", principal.session_id or "")
        user = self.get_user(principal.id)
        return session is not None and self._session_live(session, now) and user is not None and not user.disabled
