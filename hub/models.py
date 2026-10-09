"""Domain models shared by the API, the agents and the integration engine."""

from __future__ import annotations

import re
import time
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, field_validator

from .store import new_id


def now() -> float:
    return time.time()


# --------------------------------------------------------------------------------------
# Hub manifest: the integration contract every tool is described by (see docs/MANIFEST.md)
# --------------------------------------------------------------------------------------

ToolKind = Literal["oss", "closed", "saas"]
SsoMode = Literal["oidc", "saml", "ldap", "oauth2", "none", "unknown"]


class Launch(BaseModel):
    setup: str | None = None
    command: str | None = None
    cwd: str | None = None
    port: int | None = None
    env: dict[str, str] = {}


class Health(BaseModel):
    url: str | None = None  # http(s)://... or tcp://host:port
    expect_status: int = 200


class ApiSpec(BaseModel):
    type: Literal["rest", "graphql", "grpc", "none"] = "none"
    spec: str | None = None
    base_url: str | None = None
    endpoints: int = 0


class Auth(BaseModel):
    sso: SsoMode = "unknown"
    notes: str | None = None


class Events(BaseModel):
    emits: list[str] = []
    listens: list[str] = []
    webhook_url: str | None = None  # where the hub delivers events this tool listens to


class PortalUi(BaseModel):
    url: str | None = None
    icon: str | None = None
    color: str | None = None
    embed: bool = False


class Manifest(BaseModel):
    schema_version: str = "1"
    id: str
    name: str
    description: str = ""
    kind: ToolKind = "oss"
    version: str | None = None
    license: str | None = None
    stack: list[str] = []
    launch: Launch = Field(default_factory=Launch)
    health: Health = Field(default_factory=Health)
    api: ApiSpec = Field(default_factory=ApiSpec)
    auth: Auth = Field(default_factory=Auth)
    provides: list[str] = []
    consumes: list[str] = []
    events: Events = Field(default_factory=Events)
    ui: PortalUi = Field(default_factory=PortalUi)
    native: bool = False  # True when the tool ships (or adopted) its own hub manifest


class Check(BaseModel):
    id: str
    title: str
    status: Literal["pass", "warn", "fail"]
    detail: str = ""
    fix: str | None = None  # a patch strategy the Patch Agent understands
    weight: int = 1


class CompatibilityReport(BaseModel):
    score: int
    level: Literal["native", "good", "patchable", "adapter", "incompatible"]
    checks: list[Check]
    generated_at: float = Field(default_factory=now)


class Tool(BaseModel):
    id: str
    name: str
    source_type: Literal["github", "local", "saas"]
    source: str
    path: str | None = None
    openapi_url: str | None = None
    status: Literal["importing", "analyzing", "ready", "needs_patch", "error"] = "importing"
    error: str | None = None
    notes: list[str] = []
    manifest: Manifest | None = None
    report: CompatibilityReport | None = None
    running: bool = False
    health: dict[str, Any] | None = None
    created_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# Operations: hosts, approvals, patches
# --------------------------------------------------------------------------------------


class Host(BaseModel):
    id: str = ""
    name: str
    address: str
    port: int = 22
    username: str
    key_path: str | None = None  # private key file; passwords are never stored
    strict_host_keys: bool = True
    tags: list[str] = []
    created_at: float = Field(default_factory=now)


class Approval(BaseModel):
    id: str
    kind: Literal["command", "patch", "process"]
    title: str
    detail: str = ""
    payload: dict[str, Any] = {}
    requested_by: str
    status: Literal["pending", "approved", "rejected", "done", "failed"] = "pending"
    note: str | None = None
    result: dict[str, Any] | None = None
    created_at: float = Field(default_factory=now)
    decided_at: float | None = None
    decided_by: str | None = None


class FileChange(BaseModel):
    path: str
    content: str


class Patch(BaseModel):
    id: str
    tool_id: str
    title: str
    rationale: str
    strategy: str
    target: Literal["repo", "adapter", "manifest"]
    changes: list[FileChange] = []
    manifest_update: dict[str, Any] = {}
    diff: str = ""
    status: Literal["proposed", "applied", "rejected", "failed"] = "proposed"
    branch: str | None = None
    location: str | None = None
    error: str | None = None
    created_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# Asset management
# --------------------------------------------------------------------------------------

AssetType = Literal["server", "workstation", "network", "software", "saas", "cloud", "data", "other"]


class Asset(BaseModel):
    id: str = ""
    name: str
    type: AssetType = "other"
    owner: str | None = None
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    status: Literal["active", "maintenance", "retired"] = "active"
    source: str = "manual"  # manual | tool:<id> | host:<id>
    facts: dict[str, Any] = {}
    tags: list[str] = []
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# GRC: risks, policies, control states
# --------------------------------------------------------------------------------------


class Risk(BaseModel):
    id: str = ""
    title: str
    description: str = ""
    category: str = "security"
    likelihood: int = Field(3, ge=1, le=5)
    impact: int = Field(3, ge=1, le=5)
    owner: str | None = None
    treatment: Literal["mitigate", "accept", "transfer", "avoid"] = "mitigate"
    status: Literal["open", "in_treatment", "closed"] = "open"
    source: str = "manual"  # manual | auto:<control id>
    asset_ids: list[str] = []
    control_ids: list[str] = []
    reviewed_at: float | None = None
    created_at: float = Field(default_factory=now)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def score(self) -> int:
        return self.likelihood * self.impact


PolicyCategory = Literal["security", "access", "incident", "backup", "acceptable-use", "supplier", "other"]


class Policy(BaseModel):
    id: str = ""
    title: str
    category: PolicyCategory = "security"
    body: str = ""
    version: str = "0.1"
    status: Literal["draft", "approved", "retired"] = "draft"
    owner: str | None = None
    review_due: str | None = None  # ISO date
    updated_at: float = Field(default_factory=now)


class ControlState(BaseModel):
    id: str  # control id
    status: Literal["pass", "partial", "fail", "manual", "na"] = "manual"
    detail: str = ""
    evidence: list[str] = []
    manual: bool = False  # True when a person set the status by hand
    note: str | None = None
    evaluated_at: float | None = None


# --------------------------------------------------------------------------------------
# Hub accounts: people (users) and automation (API tokens)
# --------------------------------------------------------------------------------------

UserRole = Literal["viewer", "operator", "admin"]
TokenRole = Literal["viewer", "operator", "admin", "integration"]
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")


def normalize_username(value: str) -> str:
    username = value.strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError("Usernames are 2-64 characters: letters, digits, dots, dashes and underscores, "
                         "starting with a letter or digit.")
    return username


class User(BaseModel):
    id: str = Field(default_factory=lambda: new_id("u_"))
    username: str
    display_name: str = ""
    email: str | None = None
    role: UserRole = "viewer"
    disabled: bool = False
    password_hash: str | None = None  # None for accounts that only sign in through SSO
    auth_source: Literal["local", "oidc"] = "local"
    oidc_subject: str | None = None  # "<issuer>|<sub>"
    must_change_password: bool = False
    created_at: float = Field(default_factory=now)
    last_login: float | None = None
    password_changed_at: float | None = None

    @field_validator("username")
    @classmethod
    def _username(cls, value: str) -> str:
        return normalize_username(value)


class ApiToken(BaseModel):
    id: str = Field(default_factory=lambda: new_id("tok_"))
    name: str
    role: TokenRole
    token_hash: str  # sha256 hex of the full "atr_..." secret
    prefix: str  # first characters of the secret, for recognising a token
    created_by: str
    created_at: float = Field(default_factory=now)
    last_used: float | None = None
    expires_at: float | None = None


def public_user(user: User) -> dict[str, Any]:
    """What the API may show about an account: everything except the password hash."""
    return {**user.model_dump(mode="json", exclude={"password_hash"}), "has_password": user.password_hash is not None}


def public_token(token: ApiToken) -> dict[str, Any]:
    return token.model_dump(mode="json", exclude={"token_hash"})
