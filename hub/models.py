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
    provider: str | None = None  # tool id of the suite's identity provider this tool signs in through
    env_keys: list[str] = []  # OIDC_* / OAUTH2_* keys its .env example exposes (filled by the generic SSO strategy)


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
    kind: Literal["command", "patch", "process", "flow", "scan", "repair", "agent_team", "extension", "self_patch",
                  "firewall"]
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


class SsoPlan(BaseModel):
    """How an SSO patch connects a tool to the suite's identity provider."""

    provider: str  # identity provider tool id
    provider_name: str
    protocol: Literal["oidc", "saml"]
    client_id: str  # OIDC client id, or the SAML service provider's entity id
    issuer: str | None = None
    redirect_uris: list[str] = []
    steps: list[str] = []  # what a person still has to do
    register_script: str | None = None  # adapter-relative script that registers the client at the provider
    register_command: str | None = None  # set when the patch is applied


class Patch(BaseModel):
    id: str
    tool_id: str
    title: str
    rationale: str
    strategy: str
    target: Literal["repo", "adapter", "manifest"]
    changes: list[FileChange] = []
    adapter_changes: list[FileChange] = []  # hub-side files of a repo patch (e.g. the SSO client registration)
    sso: SsoPlan | None = None
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
    owner: str | None = None  # free text (shown, and kept for back-compat); owner_person_id is the link
    owner_person_id: str | None = None  # the accountable person (People app)
    assigned_person_id: str | None = None  # who uses it (e.g. the laptop's user)
    assigned_source: Literal["auto", "manual"] = "auto"  # auto: linked from the inventory's assigned user
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    status: Literal["active", "maintenance", "retired"] = "active"
    source: str = "manual"  # manual | tool:<id> | host:<id> | sync:<tool id> (pulled by a data flow)
    facts: dict[str, Any] = {}  # facts["addresses"]: IPs / hostnames (scan targets, merge keys)
    tags: list[str] = []
    scan_scope: bool = False  # only assets in scope are ever scanned for vulnerabilities
    last_scanned_at: float | None = None
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# Vulnerabilities and data flows (the integration fabric)
# --------------------------------------------------------------------------------------

Severity = Literal["critical", "high", "medium", "low", "info"]
VulnStatus = Literal["open", "in_progress", "accepted", "false_positive", "fixed"]
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
OPEN_STATES = ("open", "in_progress")


class Vulnerability(BaseModel):
    id: str = ""
    title: str
    severity: Severity = "info"
    cvss: float | None = None
    cves: list[str] = []
    asset_id: str | None = None
    host: str | None = None
    port: str | None = None
    source: str = "manual"  # tool id of the scanner (or the tool it was pulled from)
    external_id: str = ""
    status: VulnStatus = "open"
    first_seen: float = Field(default_factory=now)
    last_seen: float = Field(default_factory=now)
    due_at: float | None = None  # first_seen + the SLA of its severity
    fixed_at: float | None = None
    description: str = ""
    solution: str = ""
    note: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def overdue(self) -> bool:
        return self.status in OPEN_STATES and self.due_at is not None and self.due_at < time.time()


Domain = Literal["assets", "vulnerabilities", "risks", "controls", "people", "accounts", "network", "frameworks",
                 "assessments"]
BUILTIN_DOMAINS: tuple[str, ...] = ("assets", "vulnerabilities", "risks", "controls", "people", "accounts", "network",
                                    "frameworks", "assessments")
EXTENSION_DOMAIN_RE = re.compile(r"^x:[a-z][a-z0-9_]{1,31}$")  # a data type an extension pack adds ("x:alerts")


class Flow(BaseModel):
    """Data moving between a tool and the hub's apps. `source`/`target` are "hub" or "tool:<id>"; a scan flow
    (action "scan") goes from the hub's in-scope assets to a scanner and brings the findings back. `domain` is a
    built-in domain or an extension domain "x:<key>"."""

    id: str
    domain: str
    source: str
    target: str
    action: str | None = None
    title: str = ""
    reason: str = ""  # why the planner proposed it
    schedule_minutes: int = Field(60, ge=0, le=525_600)  # 0 = only when run by hand
    status: Literal["proposed", "enabled", "disabled"] = "proposed"
    strategy: Literal["connector", "generated"] = "connector"
    options: dict[str, Any] = {}
    created_by: str = "supervisor"
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)
    approval_id: str | None = None  # the pending proposal
    running: float | None = None  # set while a run is under way
    last_run: float | None = None
    last_result: dict[str, Any] | None = None  # {ok, counts, error, at, duration, trigger}
    failures: int = 0  # consecutive
    repair: str | None = None  # "requested" or the pending repair approval id
    job: dict[str, Any] | None = None  # scan flows: {status, job_id, started_at, hosts, asset_ids, progress, approval_id}

    @field_validator("domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        if value not in BUILTIN_DOMAINS and not EXTENSION_DOMAIN_RE.match(value):
            raise ValueError(f"Unknown data domain '{value}'")
        return value

    @property
    def tool_id(self) -> str:
        end = self.target if self.target.startswith("tool:") else self.source
        return end.split(":", 1)[1]

    @property
    def direction(self) -> Literal["pull", "push", "scan"]:
        if self.action == "scan":
            return "scan"
        return "pull" if self.target == "hub" else "push"


class SyncLink(BaseModel):
    """A hub record and its counterpart in a tool, with the hash of what was last pushed (unchanged = skipped)."""

    id: str  # "<tool id>|<domain>|<hub id>"
    tool_id: str
    domain: str
    hub_id: str
    external_id: str
    hash: str | None = None
    synced_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# Agent teams: custom agents and the model providers they run on
# --------------------------------------------------------------------------------------

AgentPermission = Literal["read", "tool_api", "commands", "patches", "flows", "assets_write", "grc_write", "agents"]
AGENT_PERMISSIONS: tuple[str, ...] = ("read", "tool_api", "commands", "patches", "flows", "assets_write", "grc_write",
                                      "agents")
AGENT_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
MIN_SCHEDULE = 5  # minutes


class AgentDef(BaseModel):
    """A custom (team) agent people or agents created. Stored in the "agent_defs" collection."""

    id: str  # "agent:<slug>"
    name: str = Field(min_length=1, max_length=80)
    title: str = Field("Team agent", max_length=80)  # its role in the team
    description: str = Field("", max_length=1000)
    instructions: str = Field("", max_length=20_000)
    provider: str = "rules"  # "anthropic" | a local provider id | "rules"
    model: str = Field("", max_length=200)  # empty: the provider's default
    permissions: list[AgentPermission] = ["read"]
    team: str = "hub"  # a tool id, "hub", or a built-in app's agent id ("module:assets", ...)
    parent: str | None = None  # the agent that created it (for agents people create: the lead of its team)
    depth: int = Field(1, ge=1)
    schedule_minutes: int = Field(0, ge=0, le=525_600)  # 0 = no schedule, else at least MIN_SCHEDULE
    task: str = Field("", max_length=4000)  # the standing task it runs on its schedule
    enabled: bool = True
    template: str | None = None  # "<category>:<role>" or "claude" for proposed members
    created_by: str = ""
    created_at: float = Field(default_factory=now)
    updated_by: str = ""
    updated_at: float = Field(default_factory=now)
    running: float | None = None  # set while a run is under way
    last_run: float | None = None
    last_result: dict[str, Any] | None = None  # {ok, reply, trigger, at, duration}

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not value.startswith("agent:") or not AGENT_SLUG_RE.match(value[6:]):
            raise ValueError("Agent ids are 'agent:' followed by 1-48 lowercase letters, digits and dashes")
        return value

    @field_validator("permissions")
    @classmethod
    def _permissions(cls, value: list[str]) -> list[str]:
        return [p for p in AGENT_PERMISSIONS if p in set(value)]

    @field_validator("schedule_minutes")
    @classmethod
    def _schedule(cls, value: int) -> int:
        if 0 < value < MIN_SCHEDULE:
            raise ValueError(f"schedule_minutes is 0 (no schedule) or at least {MIN_SCHEDULE}")
        return value


class LlmProvider(BaseModel):
    """A local model server with an OpenAI-compatible API (Ollama, LM Studio, vLLM, llama.cpp server).
    Stored in "llm_providers"; the API key is Fernet-encrypted and never returned."""

    id: str
    name: str = Field(min_length=1, max_length=80)
    kind: Literal["openai_compatible"] = "openai_compatible"
    base_url: str
    default_model: str = Field("", max_length=200)
    api_key: str | None = None  # Fernet token
    endpoint: str = ""  # scheme://host:port the key was entered for
    tools: bool = True  # send tool definitions (servers without tool calling answer in plain text)
    timeout: float = Field(300, ge=5, le=3600)
    models: list[str] = []  # from the last successful test
    last_test: dict[str, Any] | None = None
    created_by: str = ""
    created_at: float = Field(default_factory=now)
    updated_by: str = ""
    updated_at: float = Field(default_factory=now)


# --------------------------------------------------------------------------------------
# People: the workforce directory and the accounts people hold in tools
# --------------------------------------------------------------------------------------

PersonStatus = Literal["active", "suspended", "terminated"]
PERSON_STATUS_RANK = {"active": 0, "suspended": 1, "terminated": 2}  # the most "left" source status wins


class Person(BaseModel):
    """Someone in the organisation, merged from every directory that knows them (by email, then login). Stored in
    "people"; `sources` maps a tool id (or "manual") to the person's id there."""

    id: str = Field(default_factory=lambda: new_id("p_"))
    display_name: str = Field(min_length=1, max_length=200)
    email: str | None = Field(None, max_length=254)
    login: str | None = Field(None, max_length=254)
    title: str | None = Field(None, max_length=200)
    department: str | None = Field(None, max_length=200)
    manager_id: str | None = None
    status: PersonStatus = "active"
    manual_status: PersonStatus | None = None  # set by a person; a directory saying "left" still wins
    source_status: dict[str, PersonStatus] = {}  # tool id -> status there
    sources: dict[str, str] = {}  # tool id (or "manual") -> external id
    groups: list[str] = []  # every source's groups (plus groups set by hand under "manual")
    source_groups: dict[str, list[str]] = {}
    location: str | None = Field(None, max_length=200)
    phone: str | None = Field(None, max_length=64)
    created_at: float = Field(default_factory=now)
    updated_at: float = Field(default_factory=now)
    terminated_at: float | None = None

    @field_validator("email")
    @classmethod
    def _email(cls, value: str | None) -> str | None:
        value = (value or "").strip()
        if value and ("@" not in value or any(c.isspace() for c in value)):
            raise ValueError("Enter a valid email address")
        return value or None


class Account(BaseModel):
    """A user account in a tool (or, for a directory, the person's entry there). Stored in "accounts" with the id
    "<tool id>|<external id>"; `origin` is the flow domain that brought it (a pull only retires its own)."""

    id: str
    tool_id: str
    external_id: str
    origin: Literal["people", "accounts"] = "accounts"
    login: str | None = None
    email: str | None = None
    display_name: str | None = None
    app: str | None = None  # the application, for directories that list app assignments (Okta app links)
    active: bool = True
    last_login: float | None = None
    person_id: str | None = None
    person_source: Literal["auto", "manual"] = "auto"
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
    owner_person_id: str | None = None
    treatment: Literal["mitigate", "accept", "transfer", "avoid"] = "mitigate"
    status: Literal["open", "in_treatment", "closed"] = "open"
    source: str = "manual"  # manual | auto:<control id> | sync:<tool id> | vuln:<asset id or host>
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
    owner_person_id: str | None = None
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
