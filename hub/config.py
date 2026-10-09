"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

AUTONOMY_LEVELS = ("manual", "assisted", "autonomous")
USER_ROLES = ("viewer", "operator", "admin")
DEFAULT_MODEL = "claude-opus-5-5"


def _csv(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").split(",") if v.strip()]


def _flag(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def default_public_url(host: str, port: int) -> str:
    return f"http://[{host}]:{port}" if ":" in host else f"http://{host}:{port}"


def load_dotenv(path: Path) -> None:
    """Read KEY=VALUE lines from a .env file without overriding real environment variables."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.removeprefix("export ").strip(), value.strip().strip("\"'")
        if key and value:
            os.environ.setdefault(key, value)


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path.cwd() / ".hub")
    host: str = "127.0.0.1"
    port: int = 8710
    model: str = DEFAULT_MODEL
    autonomy: str = "assisted"
    health_interval: float = 60.0
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    start_background_tasks: bool = True

    # sign-in and sessions
    session_idle_minutes: int = 720
    session_days: int = 7
    cookie_secure: bool = False  # force the Secure cookie flag (e.g. behind a TLS-terminating proxy)
    public_url: str = ""  # how people reach the hub; defaults to http://{host}:{port}
    admin_username: str | None = None  # first-run administrator, created when there are no users yet
    admin_password: str | None = None
    setup_token: str | None = None  # fixed first-run setup token instead of a random one

    # single sign-on (OpenID Connect)
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_scopes: str = "openid profile email"
    oidc_role_claim: str = "groups"  # dotted paths allowed, e.g. realm_access.roles
    oidc_admin_values: list[str] = field(default_factory=lambda: ["atrium-admins"])
    oidc_operator_values: list[str] = field(default_factory=lambda: ["atrium-operators"])
    oidc_default_role: str = "viewer"
    oidc_label: str = "Sign in with SSO"
    oidc_allow_http: bool = False  # plain-http issuers are otherwise only allowed on localhost

    def __post_init__(self) -> None:
        self.public_url = (self.public_url or default_public_url(self.host, self.port)).rstrip("/")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "hub.db"

    @property
    def workspace(self) -> Path:
        return self.data_dir / "workspace"

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv(Path.cwd() / ".env")
        env = os.environ
        settings = cls(
            data_dir=Path(env.get("HUB_DATA_DIR") or Path.cwd() / ".hub").expanduser().resolve(),
            host=env.get("HUB_HOST", "127.0.0.1"),
            port=int(env.get("HUB_PORT", "8710")),
            model=env.get("HUB_MODEL", DEFAULT_MODEL),
            autonomy=env.get("HUB_AUTONOMY", "assisted"),
            health_interval=float(env.get("HUB_HEALTH_INTERVAL", "60")),
            session_idle_minutes=int(env.get("HUB_SESSION_IDLE_MINUTES") or 720),
            session_days=int(env.get("HUB_SESSION_DAYS") or 7),
            cookie_secure=_flag(env.get("HUB_COOKIE_SECURE")),
            public_url=env.get("HUB_PUBLIC_URL", ""),
            admin_username=env.get("HUB_ADMIN_USERNAME") or None,
            admin_password=env.get("HUB_ADMIN_PASSWORD") or None,
            setup_token=env.get("HUB_SETUP_TOKEN") or None,
            oidc_issuer=env.get("HUB_OIDC_ISSUER") or None,
            oidc_client_id=env.get("HUB_OIDC_CLIENT_ID") or None,
            oidc_client_secret=env.get("HUB_OIDC_CLIENT_SECRET") or None,
            oidc_scopes=env.get("HUB_OIDC_SCOPES") or "openid profile email",
            oidc_role_claim=env.get("HUB_OIDC_ROLE_CLAIM") or "groups",
            oidc_admin_values=_csv(env.get("HUB_OIDC_ADMIN_VALUES", "atrium-admins")),
            oidc_operator_values=_csv(env.get("HUB_OIDC_OPERATOR_VALUES", "atrium-operators")),
            oidc_default_role=env.get("HUB_OIDC_DEFAULT_ROLE") or "viewer",
            oidc_label=env.get("HUB_OIDC_LABEL") or "Sign in with SSO",
            oidc_allow_http=_flag(env.get("HUB_OIDC_ALLOW_HTTP")),
        )
        settings.allowed_hosts += _csv(env.get("HUB_ALLOWED_HOSTS"))
        if settings.autonomy not in AUTONOMY_LEVELS:
            raise ValueError(f"HUB_AUTONOMY must be one of {', '.join(AUTONOMY_LEVELS)}")
        if settings.oidc_default_role not in USER_ROLES:
            raise ValueError(f"HUB_OIDC_DEFAULT_ROLE must be one of {', '.join(USER_ROLES)}")
        if settings.session_idle_minutes < 1 or settings.session_days < 1:
            raise ValueError("HUB_SESSION_IDLE_MINUTES and HUB_SESSION_DAYS must be at least 1")
        return settings
