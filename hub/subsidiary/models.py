"""The subsidiary documents Atrium stores (section 8.1) and the bodies of the sidecar API /api/subsidiary/v1/* (9.2).

Shared with the sidecar: pydantic, contract.py and wire.py only (no hub.models, which pulls in the store). Text a
subsidiary writes is stored after wire.clean and shown as plain text labelled untrusted.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from . import contract, wire
from .wire import WireMsg, WireResult

Status = Literal["proposed", "deploying", "probation", "active", "paused", "stopped", "archived"]
STATUSES: tuple[str, ...] = ("proposed", "deploying", "probation", "active", "paused", "stopped", "archived")
Flag = Literal["offline", "bridge_mismatch", "over_budget", "owner_disabled", "clock_skew", "circuit_open"]
FLAGS: tuple[str, ...] = ("offline", "bridge_mismatch", "over_budget", "owner_disabled", "clock_skew", "circuit_open")
Mode = Literal["bridge", "sidecar_only"]
Risk = Literal["read", "propose", "write", "admin"]
ActionPolicy = Literal["allow", "approval", "auto", "forbidden"]
POLICY_RANK = {"forbidden": 0, "approval": 1, "allow": 2, "auto": 2}  # widening: forbidden < approval < auto
Trigger = Literal["schedule", "manual", "task", "chat", "panel"]
Origin = Literal["observed", "claimed"]

COLLECTIONS = {"subsidiaries": "subsidiaries", "keys": "subsidiary_keys", "grants": "subsidiary_grants",
               "runs": "subsidiary_runs", "usage": "subsidiary_usage", "reports": "subsidiary_reports",
               "inbox": "subsidiary_inbox", "heads": "subsidiary_chain_heads",
               "charters": "subsidiary_charters"}  # every charter version put in force (the charter tab's history)
AUDIT_LOG = "subsidiary_audit"  # store.append stream, never pruned (not in LOG_RETENTION)
OFFLINE_AFTER = 90  # seconds without a heartbeat
HEARTBEAT_SECONDS = 30
INBOX_OPEN_MAX = 500
INBOX_EXPIRY = 15 * 60
ENROLLMENT_MINUTES = 30
TOKEN_DAYS = 30
RUN_WAIT = 15 * 60  # a relayed run waits this long for /replies
CHAT_WAIT = 120


def now() -> float:
    return time.time()


def subsidiary_id() -> str:
    """sub_<12 hex>."""
    return f"sub_{secrets.token_hex(6)}"


def new_id(prefix: str) -> str:
    return f"{prefix}{secrets.token_hex(6)}"


# --------------------------------------------------------------------------------------
# the charter (7.1)
# --------------------------------------------------------------------------------------


class CharterAction(BaseModel):
    id: str
    title: str = Field(max_length=80)
    description: str = Field("", max_length=500)
    risk: Risk  # after floors
    category: str = "other"
    reversible: bool = False
    external_effect: bool = False
    on_behalf_of: bool = False
    params: dict[str, Any]
    policy: ActionPolicy  # allow: read/propose only; auto: write, reversible, no external effect (4.4)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not contract.ACTION_ID_RE.match(value):
            raise ValueError("not an action id")
        return value


class StaffScope(BaseModel):
    actions: list[str] = []  # ids from Charter.actions
    hub_tools: list[str] = []  # a subset of toolkit.SIDECAR_HUB_TOOLS


class Budgets(BaseModel):
    tokens_per_day: int = Field(300_000, ge=0)  # capped by guardrail subsidiary_max_tokens_per_day (thousands)
    model_calls_per_hour: int = Field(120, ge=0)
    approval_requests_per_day: int = Field(20, ge=0)
    max_pending_approvals: int = Field(10, ge=0)
    actions_per_minute: int = Field(30, ge=0)  # -> ticket.rl.calls_per_min (bridge-enforced)
    max_concurrent_runs: int = Field(2, ge=0)
    panel_questions_per_user_hour: int = Field(10, ge=0)  # -> ticket.rl.panel_per_user_hour
    panel_questions_per_day: int = Field(100, ge=0)

    def rate(self) -> dict[str, int]:
        """The ticket's rl."""
        return {"calls_per_min": self.actions_per_minute, "panel_per_user_hour": self.panel_questions_per_user_hour}


class ModelRouting(BaseModel):
    """Which model providers the staff may think with ("anthropic", "openai" or a local provider id)."""

    allowed: list[str] = []
    default: str | None = None


class PanelSettings(BaseModel):
    enabled: bool = False
    desk: str | None = None  # the staff member (agent id) answering "Ask the team"


class EventSettings(BaseModel):
    relay: bool = False


class DataSettings(BaseModel):
    transcripts: bool = False
    report_retention_days: int = Field(180, ge=1, le=3650)


class Charter(BaseModel):
    version: int = Field(0, ge=0)
    mode: Mode
    manifest_sha256: str | None = None  # bridge mode: the manifest the charter was written against
    mandate: str = Field("", max_length=4000)  # the team's purpose, part of every system prompt
    actions: list[CharterAction] = []
    staff: dict[str, StaffScope] = {}  # agent id -> scope (placement sidecar, team = tool id)
    model_routing: ModelRouting = Field(default_factory=ModelRouting)
    budgets: Budgets = Field(default_factory=Budgets)
    panel: PanelSettings = Field(default_factory=PanelSettings)
    events: EventSettings = Field(default_factory=EventSettings)
    data: DataSettings = Field(default_factory=DataSettings)

    def action(self, action_id: str) -> CharterAction | None:
        return next((a for a in self.actions if a.id == action_id), None)

    def sha256(self) -> str:
        """The charter_sha256 an approval binds: SHA-256 of its JSON as Atrium stores it (sorted keys, compact)."""
        raw = json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(raw.encode()).hexdigest()


# --------------------------------------------------------------------------------------
# collections (8.1)
# --------------------------------------------------------------------------------------


class BridgeInfo(BaseModel):
    patch_id: str | None = None
    contract: str = contract.CONTRACT
    stack: str
    core: str
    vendored_core: bool = False
    manifest: dict[str, Any] = {}
    manifest_sha256: str
    files: list[str] = []
    bridge_url: str | None = None  # where the bridge is served (the tool's app); Atrium-run conformance calls it


class ConformanceRow(BaseModel):
    id: str = Field(max_length=8)  # V1..V20, K1..K3
    ok: bool
    status: int | None = None
    code: str | None = Field(None, max_length=40)
    detail: str = Field("", max_length=300)


class Conformance(BaseModel):
    ok: bool
    at: float = Field(default_factory=now)
    by: Literal["atrium", "sidecar"]
    origin: Origin  # atrium-run: observed; sidecar-run: claimed
    manifest_sha256: str | None = None
    rows: list[ConformanceRow] = []


class SidecarInfo(BaseModel):
    public_key: str
    key_fingerprint: str
    enrolled_at: float = Field(default_factory=now)
    last_seen: float | None = None
    version: str = ""
    health: dict[str, Any] = {}
    runtime: dict[str, Any] = {}  # claimed: {uid, container, hostname_hash}
    clock_skew: float = 0.0
    bridge_ping: dict[str, Any] | None = None


class Enrollment(BaseModel):
    code_sha256: str  # the code itself is shown once and never stored
    expires_at: float
    issued_by: str


class StoredCredential(BaseModel):
    """The sidecar-only dedicated (read) credential: each secret value Fernet-encrypted, bound to an endpoint."""

    secrets: dict[str, str] = {}
    endpoint: str = ""
    set_by: str = ""
    set_at: float = Field(default_factory=now)


class Subsidiary(BaseModel):
    id: str  # sub_<12 hex>
    tool_id: str
    mode: Mode
    status: Status = "proposed"
    flags: list[Flag] = []
    charter: Charter | None = None  # the approved, current charter
    charter_version: int = 0
    charter_approved_by: str | None = None
    charter_approved_at: float | None = None
    pending_charter: Charter | None = None
    pending_charter_approval: str | None = None
    # the staff a pending charter would create (teams member specs, placement sidecar): created when it is approved
    pending_members: list[dict[str, Any]] = Field([], max_length=20)
    goals: str = Field("", max_length=2000)
    designer: Literal["auto", "templates", "model"] = "auto"  # who drafts the charter's staff
    bridge: BridgeInfo | None = None
    conformance: Conformance | None = None
    sidecar: SidecarInfo | None = None
    token_id: str | None = None
    enrollment: Enrollment | None = None
    credential: StoredCredential | None = None
    paused_by: str | None = None
    paused_at: float | None = None
    pause_reason: str | None = None
    circuit_reset_at: float | None = None  # the last resume: the circuit breaker counts hits and refusals after it
    stopped_by: str | None = None
    stopped_at: float | None = None
    # reconciliation alarms and broken audit chains ({kind, at, detail}: ids and counts only); HB-AC-8 fails for 90 days
    alarms: list[dict[str, Any]] = Field([], max_length=50)
    created_by: str = ""
    created_at: float = Field(default_factory=now)
    updated_by: str = ""
    updated_at: float = Field(default_factory=now)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not contract.SUBSIDIARY_ID_RE.match(value):
            raise ValueError("subsidiary ids are sub_ and 12 hex digits")
        return value

    def public(self) -> dict[str, Any]:
        """What the API shows: no credential, no enrollment hash, the sidecar's fingerprint but not its key."""
        data = self.model_dump(mode="json", exclude={"credential", "enrollment"})
        if data.get("sidecar"):
            data["sidecar"].pop("public_key", None)
        data["has_credential"] = self.credential is not None
        data["enrollment_pending"] = self.enrollment is not None and self.enrollment.expires_at > now()
        return data


class KeyRecord(BaseModel):
    """subsidiary_keys: one Ed25519 signing key of a subsidiary."""

    id: str  # "<subsidiary id>:<kid>"
    subsidiary_id: str
    kid: str
    private: str = ""  # Fernet (hub.secrets) of the base64url private key; cleared when retired
    public: str
    status: Literal["current", "next", "retired"]
    created_at: float = Field(default_factory=now)
    retired_at: float | None = None

    def public_view(self) -> dict[str, Any]:
        return {"kid": self.kid, "public": self.public, "fingerprint": contract.fingerprint(self.public),
                "status": self.status, "created_at": self.created_at, "retired_at": self.retired_at}


GrantStatus = Literal["issued", "executed", "failed", "unknown", "expired"]


class GrantRecord(BaseModel):
    id: str  # the grant's jti
    subsidiary_id: str
    approval_id: str  # an approval id or "auto"
    action_id: str
    body_sha256: str
    run_id: str | None = None
    agent_id: str | None = None
    issued_at: float = Field(default_factory=now)
    expires_at: float
    status: GrantStatus = "issued"
    result_at: float | None = None
    receipt: dict[str, Any] | None = None
    summary: str = Field("", max_length=2000)  # the sidecar's result summary (wire.clean-ed, untrusted)
    replaced_by: str | None = None  # "expired" because re-granted: the new grant's jti, or "approval:<id>"
    revoked_at: float | None = None  # paused, stopped or switched off while it was still valid


class RunRecord(BaseModel):
    id: str  # run_...
    subsidiary_id: str
    agent_id: str
    trigger: Trigger
    question_id: str | None = None
    person: str | None = None  # whose task or chat started it (the proposer of its approvals)
    started_at: float = Field(default_factory=now)
    ended_at: float | None = None
    outcome: str | None = None
    tainted: bool = False
    taint: list[str] = []  # panel:<qid>, bridge:<action>, connector:<domain>
    injection_flags: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    model_calls: int = 0
    tool_calls: int = 0
    correlation_id: str | None = None  # relayed runs and chats: the /replies key
    reply_ok: bool | None = None
    reply_length: int = 0
    boundary: str = ""  # the run's delimitation boundary: never returned by the API

    def public(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"boundary"})


class UsageDay(BaseModel):
    id: str  # "<subsidiary id>:<UTC date>"
    tokens: int = 0
    model_calls: int = 0
    model_calls_hour: dict[str, int] = {}
    approval_requests: int = 0
    denied: int = 0
    panel_questions: int = 0
    runs: int = 0
    budget_hits: list[float] = []  # for the circuit breaker
    denied_at: list[float] = []  # refused action requests (the circuit breaker: 5 within an hour)
    warned: list[str] = []  # budgets already warned about today (one activity warning per day)
    claimed: int = 0  # claimed audit entries recorded from the sidecar's spool today
    claimed_hour: dict[str, int] = {}  # ... this hour
    claimed_dropped: int = 0  # spool entries over the caps: counted here, not recorded
    claimed_capped: list[str] = []  # hours in which a spool.capped entry was recorded already


class Finding(BaseModel):
    title: str = Field(max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    evidence: str = Field("", max_length=2000)


class Report(BaseModel):
    id: str
    subsidiary_id: str
    agent_id: str
    run_id: str | None = None
    kind: Literal["report", "escalation"]
    severity: Literal["info", "warning", "critical"] = "info"
    title: str = Field(max_length=200)
    text: str = Field("", max_length=8000)  # wire.clean-ed, untrusted
    findings: list[Finding] = Field([], max_length=10)
    status: Literal["open", "promoted", "closed"] = "open"
    created_at: float = Field(default_factory=now)
    handled_by: str | None = None


InboxType = Literal["run", "chat", "grant", "denied", "action_result", "pause", "resume", "stop", "charter_changed",
                    "conformance"]


class InboxMessage(BaseModel):
    id: int  # seq, per subsidiary
    subsidiary_id: str
    type: InboxType
    body: dict[str, Any] = {}
    created_at: float = Field(default_factory=now)
    expires_at: float
    delivered_at: float | None = None
    cancelled: bool = False

    def wire(self) -> dict[str, Any]:
        return {"seq": self.id, "type": self.type, "body": self.body, "created_at": self.created_at,
                "expires_at": self.expires_at}


class ChainHead(BaseModel):
    id: str  # subsidiary id
    seq: int = 0
    hash: str = ""


class AuditEntry(BaseModel):
    """subsidiary_audit: hash = sha256(prev + canonical JSON of the entry without hash)."""

    seq: int
    ts: float = Field(default_factory=now)
    subsidiary_id: str
    origin: Origin
    kind: str = Field(max_length=40)
    agent_id: str | None = None
    run_id: str | None = None
    action_id: str | None = None
    approval_id: str | None = None
    grant_jti: str | None = None
    body_sha256: str | None = None
    outcome: str | None = None
    taint: list[str] | None = None
    detail: dict[str, Any] | None = None
    prev: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        raw = json.dumps(self.model_dump(mode="json", exclude={"hash"}), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False)
        return hashlib.sha256((self.prev + raw).encode()).hexdigest()


# --------------------------------------------------------------------------------------
# the sidecar API (9.2): request and response bodies
# --------------------------------------------------------------------------------------

Health = Literal["ok", "degraded", "failing"]


class EnrollRequest(BaseModel):
    code: str = Field(min_length=20, max_length=100)
    public_key: str = Field(min_length=43, max_length=43)  # base64url of 32 raw bytes
    version: str = Field("", max_length=40)


class EnrollResponse(BaseModel):
    token: str
    subsidiary_id: str
    tool_id: str
    expires_at: float | None = None


class RotateResponse(BaseModel):
    token: str
    expires_at: float | None = None


SPOOL_MAX = 100  # claimed entries per heartbeat (the sidecar ships its spool in batches of this size)


class ClaimedEntry(BaseModel):
    """A spool line the sidecar ships with its heartbeat; recorded in the audit trail as claimed."""

    ts: float
    kind: str = Field(max_length=40)
    agent_id: str | None = Field(None, max_length=60)
    run_id: str | None = Field(None, max_length=60)
    action_id: str | None = Field(None, max_length=60)
    outcome: str | None = Field(None, max_length=40)
    detail: dict[str, Any] | None = None  # hashes and lengths, never tool text


class HeartbeatRequest(BaseModel):
    version: str = Field("", max_length=40)
    health: Health = "ok"
    bridge_ping: dict[str, Any] | None = None  # the atrium.ping result, or {ok: false, error}
    runs: list[str] = Field([], max_length=50)  # run ids under way
    clock: float  # the sidecar's unix time
    runtime: dict[str, Any] = {}  # {uid, container, hostname_hash}
    spool: list[ClaimedEntry] = Field([], max_length=SPOOL_MAX)
    spool_dropped: int = Field(0, ge=0)
    ticket_exp: int | None = None  # the expiry of the ticket the sidecar holds (None: it holds none)


class HeartbeatResponse(BaseModel):
    status: Status
    flags: list[Flag] = []
    ticket: str | None = None
    ticket_exp: int | None = None
    charter_version: int = 0
    server_time: float


class CharterTool(BaseModel):
    """A model-facing tool name of a run kind (the schemas stay in Atrium, which composes every prompt)."""

    name: str
    action_id: str | None = None
    risk: Risk | None = None


class CharterView(BaseModel):
    """GET /charter: what the sidecar needs to run the staff (no instructions: those stay in Atrium)."""

    subsidiary_id: str
    tool_id: str
    mode: Mode
    version: int
    staff: dict[str, dict[str, Any]] = {}  # agent id -> {name, title, actions, hub_tools}
    actions: list[CharterAction] = []
    tools: dict[str, list[CharterTool]] = {}  # run kind (normal, panel) -> tools
    panel: PanelSettings = Field(default_factory=PanelSettings)
    events: EventSettings = Field(default_factory=EventSettings)
    budgets: Budgets = Field(default_factory=Budgets)
    connection: dict[str, Any] | None = None  # sidecar-only: {kind, config} - never secrets


class CredentialResponse(BaseModel):
    kind: str
    config: dict[str, Any] = {}
    secrets: dict[str, str] = {}  # plain values, for the sidecar's memory only


class InboxItem(BaseModel):
    seq: int
    type: InboxType
    body: dict[str, Any] = {}
    created_at: float
    expires_at: float


class InboxResponse(BaseModel):
    messages: list[InboxItem] = []
    cursor: int = 0


class RunMessage(BaseModel):
    """Inbox ``run`` (a scheduled, manual or task run) and ``chat`` bodies: Atrium issued the run id."""

    run_id: str
    agent_id: str
    trigger: Trigger
    correlation_id: str
    text: str = Field("", max_length=8000)  # the task, or the person's chat message
    notes: list[str] = Field([], max_length=20)  # outcomes of earlier action requests


class GrantMessage(BaseModel):
    """Inbox ``grant``: the sidecar sends exactly these body bytes with the grant, without a model call (D5)."""

    approval_id: str
    grant: str
    body_b64: str
    action_id: str
    run_id: str
    agent_id: str


class DeniedMessage(BaseModel):
    """Inbox ``denied``: a request was rejected (or refused by the guard); a note for the agent's next run."""

    approval_id: str
    action_id: str
    run_id: str | None = None
    agent_id: str
    reason: str = Field("", max_length=500)


class ActionResultMessage(BaseModel):
    """Inbox ``action_result``: the outcome of an approved request Atrium carried out itself (sidecar-only writes,
    run by the Tool Supervisor)."""

    approval_id: str
    action_id: str
    run_id: str | None = None
    agent_id: str
    status: Literal["executed", "failed"]
    summary: str = Field("", max_length=2000)


class ControlMessage(BaseModel):
    """Inbox ``pause``, ``resume``, ``stop`` and ``charter_changed``."""

    reason: str = Field("", max_length=500)
    charter_version: int | None = None


class ConformanceMessage(BaseModel):
    """Inbox ``conformance``: vectors (contract.Vector.to_json()) for the sidecar to run; results: POST /conformance."""

    vectors: list[dict[str, Any]] = Field(max_length=40)
    built_at: float


INBOX_BODIES: dict[str, type[BaseModel]] = {
    "run": RunMessage, "chat": RunMessage, "grant": GrantMessage, "denied": DeniedMessage,
    "action_result": ActionResultMessage, "pause": ControlMessage, "resume": ControlMessage, "stop": ControlMessage,
    "charter_changed": ControlMessage, "conformance": ConformanceMessage,
}


class ReplyRequest(BaseModel):
    correlation_id: str = Field(max_length=64)
    reply: str = Field("", max_length=8000)
    ok: bool = True


class RunCreate(BaseModel):
    trigger: Literal["panel"] = "panel"
    question_id: str = Field(max_length=64)
    agent_id: str = Field(max_length=60)


class RunCreated(BaseModel):
    run_id: str
    max_turns: int
    max_tool_calls: int


class RunEnd(BaseModel):
    outcome: Literal["answered", "escalated", "declined", "failed", "budget", "tool_unavailable", "cancelled",
                     "done"]


class ModelRequest(BaseModel):
    """POST /model. Any system prompt or tool list the sidecar adds is ignored: Atrium composes both."""

    run_id: str = Field(max_length=64)
    agent_id: str = Field(max_length=60)
    messages: list[WireMsg] = Field(min_length=1, max_length=wire.MAX_MESSAGES)


ModelResponse = WireResult


class ActionRequest(BaseModel):
    run_id: str = Field(max_length=64)
    agent_id: str = Field(max_length=60)
    action_id: str = Field(max_length=58)
    params: dict[str, Any] = {}
    reason: str = Field("", max_length=2000)


class ActionReply(BaseModel):
    status: Literal["pending_approval", "granted", "denied"]
    approval_id: str | None = None
    grant: str | None = None
    body_b64: str | None = None
    reason: str | None = None


class ActionResult(BaseModel):
    grant_jti: str = Field(max_length=64)
    status: Literal["executed", "failed"]
    receipt: dict[str, Any] | None = None
    result_summary: str = Field("", max_length=2000)


class RegrantRequest(BaseModel):
    """POST /actions/{approval_id}/regrant, answered like a granted ActionReply (status, grant, body_b64)."""

    old_jti: str = Field(max_length=64)
    receipt: dict[str, Any]  # the bridge's atrium.receipt answer: {status: unused}


class HubRequest(BaseModel):
    run_id: str = Field(max_length=64)
    agent_id: str = Field(max_length=60)
    tool: str = Field(max_length=60)
    args: dict[str, Any] = {}


class HubReply(BaseModel):
    ok: bool
    result: Any = None
    error: str | None = None


class ReportRequest(BaseModel):
    run_id: str | None = Field(None, max_length=64)
    agent_id: str = Field(max_length=60)
    kind: Literal["report", "escalation"] = "report"
    title: str = Field(min_length=1, max_length=200)
    text: str = Field("", max_length=8000)
    findings: list[Finding] = Field([], max_length=10)
    severity: Literal["info", "warning", "critical"] = "info"
    question_id: str | None = Field(None, max_length=64)  # an escalation from a panel run


class RelayedEvent(BaseModel):
    name: str = Field(max_length=200)
    payload: dict[str, Any] = {}
    cause: dict[str, str] | None = None  # {"jti": ...} for events caused by a granted action
    at: float | None = None


class EventsRequest(BaseModel):
    events: list[RelayedEvent] = Field(max_length=100)


class ConformanceResults(BaseModel):
    rows: list[ConformanceRow] = Field(max_length=40)
    built_at: float | None = None  # the vectors' build time (they expire VECTOR_TTL seconds later)
