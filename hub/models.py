"""Domain models shared by the API, the agents and the integration engine."""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Annotated, Any, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from pydantic import BaseModel, Field, computed_field, field_validator

from .store import new_id


def now() -> float:
    return time.time()


# A query parameter named like one of these carries a credential (?api_key=, ?access_token=, ?sig=...).
CREDENTIAL_PARAM = re.compile(r"(?i)(token|key|secret|passw|pwd|auth|sig|credential|session)")


def url_credentials(url: str | None) -> list[str]:
    """What in a URL looks like a credential: user info (https://user:token@host) and query parameters named like
    one. git SSH addresses (git@host:path) carry no secret."""
    try:
        parts = urlsplit(str(url or "").strip())
    except ValueError:
        return []
    found = ["user info"] if parts.username or parts.password else []
    found += [f"query parameter '{k}'" for k, _ in parse_qsl(parts.query, keep_blank_values=True) if CREDENTIAL_PARAM.search(k)]
    return found


def strip_url_credentials(url: str | None) -> str | None:
    """`url` without user info and with credential-looking query values replaced by "***" (review F3) - for showing a
    URL that may have been stored with a token in it."""
    if not url or not url_credentials(url):
        return url
    parts = urlsplit(url.strip())
    query = "&".join(f"{k}={'***' if CREDENTIAL_PARAM.search(k) else v}" for k, v in parse_qsl(parts.query, keep_blank_values=True))
    return urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], query=query))


# --------------------------------------------------------------------------------------
# Hub manifest: the integration contract every tool is described by (see docs/MANIFEST.md)
# --------------------------------------------------------------------------------------

ToolKind = Literal["oss", "closed", "saas"]
SsoMode = Literal["oidc", "saml", "ldap", "oauth2", "none", "unknown"]
# Set by the hub only: a tool's own hub.manifest.* cannot claim them (the analyzer drops them from the file).
MANIFEST_HUB_KEYS = ("id", "native", "known", "adopted")


class KnownMatch(BaseModel):
    """A well-known product the analyzer recognised (hub/integration/known_tools.py): its profile id, the shape of the
    imported folder (a release folder, a source checkout, a compose folder, a SaaS service), how it was recognised
    (a marker file, the tool's id or name, the SaaS host name, the image of its compose file's main service) and the
    product version when one was found. Hub-only."""

    profile: str = Field(max_length=40)
    shape: Literal["release", "source", "compose", "saas", "other"] = "other"
    by: Literal["marker", "name", "host", "image"] = "name"  # image: the main service of its root compose file
    version: str | None = Field(None, max_length=40)


class Launch(BaseModel):
    setup: str | None = None
    command: str | None = None
    cwd: str | None = None
    port: int | None = None
    env: dict[str, str] = {}
    # adapter-relative files of public KEY=value lines merged into the child environment (e.g. subsidiary/bridge.env)
    env_files: list[str] = Field([], max_length=8)
    test: str | None = Field(None, max_length=500)  # the tool's own test command (bridge patches run it sandboxed)
    # Names of environment variables whose values the hub keeps in adapters/<id>/launch/secrets.env (never here)
    secret_env: list[str] = Field([], max_length=16)

    @field_validator("env_files")
    @classmethod
    def _env_files(cls, value: list[str]) -> list[str]:
        for path in value:
            parts = str(path).replace("\\", "/").split("/")
            if not path or len(path) > 200 or path.startswith("/") or re.match(r"^[A-Za-z]:", path) \
                    or any(p in ("", ".", "..") for p in parts):
                raise ValueError("env_files are adapter-relative paths")
        return value

    @field_validator("secret_env")
    @classmethod
    def _secret_env(cls, value: list[str]) -> list[str]:
        """Names only (the Operator's ENV_KEY rule), each once: the values live in the hub's private secrets file."""
        for name in value:
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$", str(name)):
                raise ValueError("secret_env holds environment variable names (letters, digits and _)")
        return list(dict.fromkeys(value))


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


# A tool's tile colour, from its own manifest: a hex colour and nothing else. The UI puts it in a style attribute, where
# "#7c3aed;position:fixed;inset:0" would add declarations (a full-screen layer over the page) and url(...) would beacon.
HEX_COLOR = re.compile(r"#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})")
ICON_GLYPHS = 2  # a letter, two letters or an emoji - never a sentence posing as a message


def icon_glyphs(text: str) -> int | None:
    """How many characters a tile icon shows, or None when it holds whitespace or control characters. Joiners,
    variation selectors, skin tones, tags and combining marks belong to the character before them, the character after
    a zero-width joiner is part of the same emoji, and two regional indicators make one flag."""
    count, joined, flag_half = 0, False, False
    for ch in text:
        cp = ord(ch)
        if ch == "‍":
            joined = True
            continue
        if 0xFE00 <= cp <= 0xFE0F or 0x1F3FB <= cp <= 0x1F3FF or 0xE0020 <= cp <= 0xE007F or unicodedata.combining(ch):
            continue
        if ch.isspace() or unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zs", "Zl", "Zp"):
            return None
        if 0x1F1E6 <= cp <= 0x1F1FF:
            flag_half = not flag_half
            if not flag_half:  # the second indicator of a flag
                continue
        else:
            flag_half = False
        if not joined:
            count += 1
        joined = False
    return count


class PortalUi(BaseModel):
    url: str | None = None
    icon: str | None = None
    color: str | None = None
    embed: bool = False
    # Dashboard widgets the tool suggests (hub.extensions.pack.WidgetDecl, at most 10; round4-dashboard-spec.md 6.6):
    # untrusted data, only ever offered as gallery suggestions scoped to this tool.
    widgets: list[dict[str, Any]] = Field(default_factory=list, max_length=10)

    @field_validator("widgets")
    @classmethod
    def _widgets(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        from .extensions.pack import WidgetDecl  # the pack module imports this one

        return [WidgetDecl.model_validate(w).model_dump(mode="json") for w in value]

    # Both come from a repository's hub.manifest.yaml: anything else is dropped (the UI then uses its own colour and
    # the tool's first letter) rather than refusing the whole manifest.
    @field_validator("color", mode="before")
    @classmethod
    def _color(cls, value: Any) -> str | None:
        return value.strip() if isinstance(value, str) and HEX_COLOR.fullmatch(value.strip()) else None

    @field_validator("icon", mode="before")
    @classmethod
    def _icon(cls, value: Any) -> str | None:
        if not isinstance(value, str) or len(text := value.strip()) > 16:
            return None
        return text if 1 <= (icon_glyphs(text) or 0) <= ICON_GLYPHS else None


class BridgeSpec(BaseModel):
    """An Atrium bridge in the tool's code (docs/SUBSIDIARIES.md): the contract it implements and the SHA-256 of the
    raw bytes of its committed atrium-bridge.json."""

    contract: str = "atrium-bridge/1"
    stack: str = Field(max_length=40)
    core: str = Field(max_length=60)
    manifest_path: str = "atrium-bridge.json"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


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
    native: bool = False  # True when the tool's folder ships its own hub manifest (recomputed by every analysis)
    bridge: BridgeSpec | None = None  # set when an approved bridge patch is applied
    known: KnownMatch | None = None  # the well-known product the analyzer recognised (hub-only)
    adopted: str | None = None  # where an adopted hub manifest waits: a branch ("hub/add-manifest-...") or a folder

    def public(self) -> dict[str, Any]:
        """The manifest as the API, the bus log and SSE show it (every viewer sees it): whether a webhook URL is set
        (``events.has_webhook``), never the URL - it may carry a token - and the launch environment's key names
        (``launch.env_keys``: its constants and the names of its launch secrets), not their values. The stored
        manifest keeps the constants; launch secret values are never in it."""
        data = self.model_dump(mode="json")
        data["events"]["has_webhook"] = bool(data["events"].pop("webhook_url", None))
        data["launch"]["env_keys"] = sorted(set(data["launch"].pop("env", None) or {}) | set(self.launch.secret_env))
        return data


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
    # Hub-side decisions about the manifest (applied patches and administrators' edits), re-applied after every
    # analysis (hub/integration/overrides.py). Never shown as such: public() lists the paths it sets.
    manifest_overrides: dict[str, Any] = {}
    created_at: float = Field(default_factory=now)

    def public(self) -> dict[str, Any]:
        """The tool for API reads and the ``tool`` SSE event, with ``Manifest.public`` (no webhook URL or env values),
        no credentials in its source or OpenAPI URL (review F3: refused at import, stripped for older tools) and,
        instead of its hub-side overrides, ``overridden``: the dotted paths they set (``launch.env.<KEY>`` names the
        key, never its value)."""
        return {**self.model_dump(mode="json", exclude={"manifest", "manifest_overrides"}),
                "source": strip_url_credentials(self.source), "openapi_url": strip_url_credentials(self.openapi_url),
                "manifest": self.manifest.public() if self.manifest else None,
                "overridden": override_paths(self.manifest_overrides)}


def override_paths(overrides: dict[str, Any], prefix: str = "") -> list[str]:
    """Sorted dotted leaf paths of a nested dict of overrides (an empty dict sets nothing; values are never named)."""
    paths: list[str] = []
    for key, value in overrides.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            paths += override_paths(value, f"{path}.")
        else:
            paths.append(path)
    return sorted(paths)


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
                  "firewall", "agent_escalation", "subsidiary_charter", "subsidiary_action"]
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


class BridgePlan(BaseModel):
    """What a bridge patch (strategy "atrium_bridge", hub/subsidiary) adds to a tool, as Atrium computed it: the
    approval card shows these facts, never a model's own description of them."""

    subsidiary_id: str
    contract: str = "atrium-bridge/1"
    stack: str = Field(max_length=40)
    core: str = Field(max_length=60)  # "<family>/<version>"
    vendored_core: bool = False  # False: a model wrote the core (the conformance vectors gate it)
    designer: Literal["model", "templates"] = "templates"
    manifest_path: str = "atrium-bridge.json"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    actions: list[dict[str, Any]] = []  # the action table: risks at their floors (hub.subsidiary.contract)
    removed: list[dict[str, Any]] = []  # proposed actions left out: {id, rule, reason}
    raised: list[dict[str, Any]] = []  # risks raised to their floors: {id, declared, risk, reason}
    events: list[str] = []
    panel: bool = False
    mounted: bool = True  # False: mount_steps are the lines a person adds
    mount_steps: list[str] = []
    setup_steps: list[str] = []  # the in-app service principal "atrium-team": a migration or a manual step
    checks: list[dict[str, Any]] = []  # static check findings: {rule, file, line, detail}
    checks_ok: bool = False


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
    generated_by: dict[str, str] | None = None  # {provider, model} of the AI model that wrote it (HB-CM-2 evidence)
    bridge: BridgePlan | None = None  # strategy "atrium_bridge"
    tests: dict[str, Any] | None = None  # the tool's own tests at proposal: {ok: true|false|None, status, reason?, ...}
    commit: str | None = None  # the commit an approval binds (patches proposed on a branch)
    fingerprint: str | None = None  # the manifest inputs its plan used (gapfix.fingerprint); None = legacy
    approval_id: str | None = None  # the approval it waits for (PatchAgent._submit)
    # A code patch (target "repo", not a bridge): False once applied while its change waits on its branch (or folder)
    # for a person to merge it into the tool's folder - what it sets in the manifest (a health URL, single sign-on)
    # applies only from the analysis that finds it there (True). None: other patches, and code patches applied before.
    merged: bool | None = None
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
    # Set when its proposal was turned down (the approval id, or "dismissed"): the flow stays as a disabled record that
    # never runs, and enabling it proposes it again - a rejection is never undone by flipping the status.
    rejected: str | None = None
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

AgentPermission = Literal["read", "tool_api", "commands", "patches", "flows", "assets_write", "grc_write", "agents",
                          "tool_actions"]
AGENT_PERMISSIONS: tuple[str, ...] = ("read", "tool_api", "commands", "patches", "flows", "assets_write", "grc_write",
                                      "agents", "tool_actions")
AGENT_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
MIN_SCHEDULE = 5  # minutes


class AgentDef(BaseModel):
    """A custom (team) agent people or agents created. Stored in the "agent_defs" collection."""

    id: str  # "agent:<slug>"
    name: str = Field(min_length=1, max_length=80)
    title: str = Field("Team agent", max_length=80)  # its role in the team
    description: str = Field("", max_length=1000)
    instructions: str = Field("", max_length=20_000)
    provider: str = ""  # "" inherit (the suite's model choice) | "anthropic" | a provider id | "rules"
    model: str = Field("", max_length=200)  # empty: the provider's default
    permissions: list[AgentPermission] = ["read"]
    team: str = "hub"  # a tool id, "hub", or a built-in app's agent id ("module:assets", ...)
    # "sidecar": staff of the team's tool subsidiary, running next to the tool (hub/subsidiary); set at creation,
    # changed only through the subsidiary's charter
    placement: Literal["hub", "sidecar"] = "hub"
    parent: str | None = None  # the agent that created it (for agents people create: the lead of its team)
    depth: int = Field(1, ge=1)
    schedule_minutes: int = Field(0, ge=0, le=525_600)  # 0 = no schedule, else at least MIN_SCHEDULE
    task: str = Field("", max_length=4000)  # the standing task it runs on its schedule
    enabled: bool = True
    template: str | None = None  # "<category>:<role>", or "model" ("claude" before) for members an AI model designed
    config: AgentConfig = Field(default_factory=lambda: AgentConfig())  # per-task models, local only (defined below)
    created_by: str = ""
    created_at: float = Field(default_factory=now)
    updated_by: str = ""
    updated_at: float = Field(default_factory=now)
    running: float | None = None  # set while a run is under way
    last_run: float | None = None
    last_result: dict[str, Any] | None = None  # {ok, reply, trigger, at, duration}
    failures: int = Field(0, ge=0)  # failed runs in a row (a skipped run does not count)
    schedule_paused: bool = False  # paused after config.escalation.failed_runs failures; resumed by an administrator
    inbox: list[dict[str, Any]] = Field([], max_length=10)  # answers to its escalations, for its next model turn

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


LlmKind = Literal["anthropic", "openai", "openai_compatible"]


class ModelCaps(BaseModel):
    """What one model of a provider supports (hub/llm/types.py Caps, stored); None = unknown."""

    tools: bool | None = None
    json_schema: bool | None = None
    json_object: bool | None = None
    temperature: bool | None = None
    effort_levels: list[str] | None = None
    max_output_tokens: int | None = None
    context_window: int | None = None
    lifecycle: str | None = None
    retires_at: str | None = None
    source: Literal["api", "probe", "learned", "admin", "default"] = "default"
    at: float | None = None


class Supplier(BaseModel):
    """Who answers for a cloud AI provider as a supplier, and when its terms / data processing agreement were last
    reviewed (compliance control HB-SC-1)."""

    owner: str = Field("", max_length=200)  # a person from the People app, or free text
    reviewed_at: float | None = None
    notes: str = Field("", max_length=500)


class LlmProvider(BaseModel):
    """An AI model provider: the built-in Claude ("anthropic") and OpenAI ("openai") records, and model servers with
    an OpenAI-compatible API (Ollama, LM Studio, vLLM, llama.cpp server). Stored in "llm_providers"; the API key is
    Fernet-encrypted and never returned."""

    id: str
    name: str = Field(min_length=1, max_length=80)
    kind: LlmKind = "openai_compatible"
    variant: Literal["openai", "azure"] | None = None  # kind "openai"
    base_url: str
    default_model: str = Field("", max_length=200)
    api_key: str | None = None  # Fernet token
    endpoint: str = ""  # scheme://host:port the key was entered for
    enabled: bool = True
    tools: bool = True  # send tool definitions (servers without tool calling answer in plain text)
    structured_output: Literal["auto", "json_schema", "json_object", "prompt"] = "auto"  # openai_compatible
    send_effort: bool = False  # openai_compatible: send reasoning_effort
    location: Literal["self_hosted", "third_party"] = "self_hosted"  # always third_party for anthropic / openai
    location_confirmed: bool = False  # an administrator marked a public host self-hosted
    timeout: float = Field(300, ge=5, le=3600)
    requests_per_minute: int | None = Field(None, ge=1, le=100_000)  # more wait briefly, then fail as rate-limited
    max_concurrency: int = Field(4, ge=1, le=64)  # calls at a time; more wait their turn
    models: list[str] = []  # from the last successful test
    pinned_models: list[str] = []  # shown first in pickers
    capabilities: dict[str, ModelCaps] = {}  # per model id
    supplier: Supplier = Supplier()
    last_test: dict[str, Any] | None = None
    created_by: str = ""
    created_at: float = Field(default_factory=now)
    updated_by: str = ""
    updated_at: float = Field(default_factory=now)


class LlmChoice(BaseModel):
    provider: str = Field("", max_length=64)  # "" inherit | "auto" (suite default only) | "rules" | a provider id
    model: str = Field("", max_length=200)  # "" = the provider's default model


class TeamLlm(LlmChoice):
    local_only: bool = False


class LlmSelection(BaseModel):
    """Which model agents use when they do not choose one (settings doc "llm_selection"; hub/llm/resolve.py)."""

    default: LlmChoice = LlmChoice(provider="auto")
    purposes: dict[Literal["chat", "code", "generate"], LlmChoice] = {}
    fallback: list[str] = Field([], max_length=8)  # provider ids, in order; rules is always last
    teams: dict[str, TeamLlm] = {}
    language: str = "auto"
    version: int = 0
    updated_by: str = ""
    updated_at: float = 0


EFFORT_LEVELS = ("none", "low", "medium", "high", "xhigh", "max")


class ModelParams(BaseModel):
    """How an agent's model calls run; "" / None = each call's own default (hub/llm applies them to every call)."""

    effort: Literal["", "none", "low", "medium", "high", "xhigh", "max"] = ""
    temperature: float | None = Field(None, ge=0, le=2)  # only where the model accepts it
    max_output_tokens: int | None = Field(None, ge=256, le=200_000)  # a cap: a call never asks for more
    max_tool_rounds: int = Field(12, ge=1, le=30)


class Budget(BaseModel):
    """An agent's AI spending limits per UTC day / month (None = no limit). With `hard_stop` off a reached budget is
    only reported."""

    daily_tokens: int | None = Field(None, ge=1_000, le=10_000_000_000)
    daily_cost_usd: float | None = Field(None, ge=0.01, le=100_000)
    monthly_cost_usd: float | None = Field(None, ge=0.01, le=1_000_000)
    hard_stop: bool = True


class RateLimit(BaseModel):
    calls_per_minute: int | None = Field(None, ge=1, le=600)  # model calls
    runs_per_hour: int | None = Field(None, ge=1, le=3_600)  # chat turns and task runs


class MemoryConfig(BaseModel):
    """What an agent remembers of a person's conversation - always per person (hub/llm/memory.py)."""

    mode: Literal["off", "session", "persisted"] = "session"
    max_turns: int = Field(40, ge=2, le=200)  # then the conversation starts afresh (with a notice)
    retention_days: int = Field(30, ge=1, le=365)  # persisted: purged after this many days without a message


class EscalationConfig(BaseModel):
    """How a chat agent asks a person (hub/agents/notify.py): the `escalate` tool (an "agent_escalation" approval
    that operators acknowledge or dismiss, with a note the agent reads in its next turn), the cases it must escalate,
    and - custom agents - pausing its schedule after failed runs in a row (0 = never)."""

    tool: bool = True
    rules: list[Annotated[str, Field(max_length=300)]] = Field([], max_length=20)
    failed_runs: int = Field(3, ge=0, le=20)
    pause_schedule: bool = True
    max_per_day: int = Field(5, ge=1, le=50)  # beyond it the tool says so: the queue cannot be flooded


NotifyEvent = Literal["run_failed", "budget_reached", "escalation", "approval_requested", "run_done"]


class NotifyConfig(BaseModel):
    """Which of an agent's events are notifications (an activity entry with data.notify = the targets, shown in the
    Agents page's "Needs attention" strip) and whether they also go to integrated tools (tool bus hub.agent.<event>)."""

    events: list[NotifyEvent] = Field(["run_failed", "budget_reached", "escalation"], max_length=5)
    targets: list[str] = Field(["role:admin"], max_length=20)  # "role:admin" | "role:operator" | "user:<id>"
    toolbus: bool = False


class AgentConfig(BaseModel):
    """An agent's own settings beyond its definition, the same for core agents (the "agents" document) and custom
    agents (AgentDef.config): per-task model choices (the Patch Agent's code changes and structured generation),
    whether it may only run on self-hosted models, model parameters, instructions added to the built-in ones (core
    agents), its reply language, the tools it may use (None = all its permissions allow), budgets, rate limits,
    memory, escalation and notifications. `version` counts the changes (optimistic concurrency; hub/agents/settings.py keeps the history)."""

    purposes: dict[Literal["code", "generate"], LlmChoice] = {}
    local_only: bool = False
    params: ModelParams = Field(default_factory=ModelParams)
    instructions_mode: Literal["append", "replace"] = "append"  # core agents: "replace" = the `instructions` text
    extra_instructions: str = Field("", max_length=20_000)  # core agents, appended to the built-in instructions
    language: str = Field("", max_length=35)  # "" = the suite default; "auto" = no reply language; else BCP 47
    allowed_tools: list[str] | None = Field(None, max_length=100)
    budget: Budget = Field(default_factory=Budget)
    rate: RateLimit = Field(default_factory=RateLimit)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    escalation: EscalationConfig = Field(default_factory=EscalationConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    version: int = 0


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
# "subsidiary": a subsidiary's sidecar (hub/subsidiary); only issued by its enrollment, never by POST /api/tokens
TokenRole = Literal["viewer", "operator", "admin", "integration", "subsidiary"]
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
    # Emails single sign-on replaced on this account (review F17): it stays linked to the people who had them, so a
    # change at the identity provider never unlinks it from its owner's leaver checks.
    previous_emails: list[str] = []
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
    # The account the token acts for (F2): the id of the person who created it, or of the person behind the token
    # that created it. Never changes; the token works only while that account exists and is enabled, and never with
    # more than that account's role. None only on tokens stored before it existed (bound at their next use).
    owner_id: str | None = None
    # Integration tokens: the tool whose events the token publishes - /api/bus/publish refuses any other source
    # (review F31). Tokens from before are bound to the first source they publish as.
    tool_id: str | None = None
    # Subsidiary tokens: the subsidiary (sub_<12 hex>) whose sidecar API alone the token reaches; tool_id is its tool
    subsidiary_id: str | None = None
    created_at: float = Field(default_factory=now)
    last_used: float | None = None
    expires_at: float | None = None


def public_user(user: User) -> dict[str, Any]:
    """What the API may show about an account: everything except the password hash."""
    return {**user.model_dump(mode="json", exclude={"password_hash"}), "has_password": user.password_hash is not None}


def public_token(token: ApiToken) -> dict[str, Any]:
    hidden = {"token_hash", "owner_id"} | {k for k in ("tool_id", "subsidiary_id") if getattr(token, k) is None}
    return token.model_dump(mode="json", exclude=hidden)
