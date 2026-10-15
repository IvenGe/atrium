"""Governance by the parent company (sections 3, 6.3, 7.4-7.8): a subsidiary's status and flags, enrollment and the
sidecar's token, tickets, the dedicated credential, pause, resume, stop and the kill switch, the hold on its staff,
the periodic tick and the facts compliance control HB-AC-8 is evaluated on.

Statuses: proposed -> deploying -> probation -> active <-> paused -> stopped -> archived (at most one subsidiary per
tool is not archived). Flags on the side: offline, bridge_mismatch, over_budget, owner_disabled, clock_skew,
circuit_open. Every change is audited (hash-chained, ``audit.py``), logged in the activity log and published on the
event stream as ``subsidiary`` (the public summary: no credential, enrollment hash or sidecar key).

The kill switch needs no cooperation from the sidecar: without an active status no ticket is issued, so within the
ticket lifetime (guardrail ``subsidiary_ticket_minutes``) the bridge refuses everything; the sidecar API answers 423
at once.
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .. import connectors, guardrails
from ..agents import teams
from ..auth.service import TOKEN_PREFIX
from ..auth.service import sha256 as sha256_text
from ..integration import connections
from ..models import AgentDef, ApiToken, Approval, User
from . import audit, contract, keys, runtime, wire
from .models import (COLLECTIONS, ENROLLMENT_MINUTES, OFFLINE_AFTER, TOKEN_DAYS, BridgeInfo, Charter, CharterTool,
                     CharterView, ClaimedEntry, CredentialResponse, Enrollment, EnrollRequest, EnrollResponse,
                     HeartbeatRequest, HeartbeatResponse, RotateResponse, SidecarInfo, StoredCredential, Subsidiary,
                     UsageDay, subsidiary_id)

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = COLLECTIONS["subsidiaries"]
USAGE = COLLECTIONS["usage"]
LIVE = ("probation", "active", "paused")  # what HB-AC-8 looks at
WORKING = ("deploying", "probation", "active")  # what a pause (and the kill switch) applies to
BLOCKING_FLAGS = ("bridge_mismatch", "circuit_open", "owner_disabled")
ACTOR = "hub"
DAY = 24 * 3600
ALARM_WINDOW = 90 * DAY
CLOCK_SKEW = contract.CLOCK_LEEWAY
CIRCUIT_BUDGET_HITS = 3  # budget refusals within an hour that open the circuit breaker
CIRCUIT_REFUSALS = 5  # refused action requests within an hour that open it
CLAIMED_PER_HOUR = 1000  # claimed (spool) audit entries a subsidiary may add an hour, and a UTC day
CLAIMED_PER_DAY = 10_000
ENROLL_KEY = "subsidiary-enroll"  # the throttle's "username" for enrollment attempts (per client address)
STATUS_TEXT = {"proposed": "proposed", "deploying": "being deployed", "probation": "on probation", "active": "active",
               "paused": "paused", "stopped": "stopped", "archived": "archived"}
FLAG_TEXT = {"offline": "the sidecar is offline", "bridge_mismatch": "the bridge in the tool changed",
             "over_budget": "a budget is exhausted", "owner_disabled": "the sidecar's token no longer works",
             "clock_skew": "the sidecar's clock is off", "circuit_open": "the circuit breaker opened"}
SAFE_RUNTIME = ("uid", "container", "hostname_hash")
SAFE_PING = ("ok", "tool", "contract", "core", "manifest_sha256", "time", "drops")


class GovernanceError(ValueError):
    """A refused request: the HTTP status, a message for people and an optional machine-readable code."""

    def __init__(self, status: int, message: str, code: str | None = None, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.extra = status, code, extra


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def clock(hub: "Hub") -> float:
    return hub.subsidiary_config.clock()


def allowed(hub: "Hub") -> bool:
    """The master switch (guardrail allow_subsidiaries, off by default): off is the global kill switch."""
    return bool(guardrails.value(hub, "allow_subsidiaries"))


def all_subsidiaries(hub: "Hub") -> list[Subsidiary]:
    return [Subsidiary.model_validate(d) for d in hub.store.list(COLLECTION)]


def get(hub: "Hub", sub_id: str) -> Subsidiary | None:
    doc = hub.store.get(COLLECTION, sub_id) if sub_id else None
    return Subsidiary.model_validate(doc) if doc else None


def of_tool(hub: "Hub", tool_id: str, *, archived: bool = False) -> Subsidiary | None:
    """The tool's subsidiary that is not archived; with `archived`, else its newest archived one."""
    subs = sorted((s for s in all_subsidiaries(hub) if s.tool_id == tool_id), key=lambda s: s.created_at, reverse=True)
    return next((s for s in subs if s.status != "archived"), None) or (subs[0] if archived and subs else None)


def tool_name(hub: "Hub", tool_id: str) -> str:
    tool = hub.get_tool(tool_id)
    return tool.name if tool else tool_id


def staff(hub: "Hub", sub: Subsidiary) -> list[AgentDef]:
    """The subsidiary's staff: team agents of its tool placed in the sidecar."""
    return [d for d in teams.defs(hub) if d.team == sub.tool_id and d.placement == "sidecar"]


def utc_day(ts: float) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def usage_day(hub: "Hub", sub_id: str, ts: float) -> UsageDay:
    doc = hub.store.get(USAGE, f"{sub_id}:{utc_day(ts)}")
    return UsageDay.model_validate(doc) if doc else UsageDay(id=f"{sub_id}:{utc_day(ts)}")


def usage_today(hub: "Hub", sub: Subsidiary) -> dict[str, Any]:
    day = usage_day(hub, sub.id, clock(hub))
    budgets = sub.charter.budgets if sub.charter else None
    return {"day": day.id.split(":", 1)[1], "tokens": day.tokens, "model_calls": day.model_calls,
            "approval_requests": day.approval_requests, "denied": day.denied, "panel_questions": day.panel_questions,
            "runs": day.runs, "tokens_per_day": budgets.tokens_per_day if budgets else None,
            "approval_requests_per_day": budgets.approval_requests_per_day if budgets else None}


def pending_approvals(hub: "Hub", sub: Subsidiary) -> list[Approval]:
    return [a for a in (Approval.model_validate(d) for d in hub.store.list_where("approvals", "status", "pending"))
            if (a.payload or {}).get("subsidiary_id") == sub.id]


def open_reports(hub: "Hub", sub: Subsidiary) -> dict[str, int]:
    """Counts of the open reports and escalations (no text): the group dashboard's escalation figures."""
    found = [d for d in hub.store.list_where(COLLECTIONS["reports"], "subsidiary_id", sub.id) if d.get("status") == "open"]
    escalations = [d for d in found if d.get("kind") == "escalation"]
    return {"reports": len(found) - len(escalations), "escalations": len(escalations),
            "critical": sum(1 for d in escalations if d.get("severity") == "critical")}


def summary(hub: "Hub", sub: Subsidiary) -> dict[str, Any]:
    """One subsidiary on the group dashboard (and its ``subsidiary`` event): status and counts, no tool text."""
    conformance = sub.conformance
    return {"id": sub.id, "tool_id": sub.tool_id, "tool_name": tool_name(hub, sub.tool_id), "mode": sub.mode,
            "status": sub.status, "flags": list(sub.flags), "charter_version": sub.charter_version,
            "staff_count": len(sub.charter.staff) if sub.charter else 0,
            "last_seen": sub.sidecar.last_seen if sub.sidecar else None, "enrolled": sub.sidecar is not None,
            "enrollment_pending": sub.enrollment is not None and sub.enrollment.expires_at > clock(hub),
            "has_credential": sub.credential is not None, "pause_reason": sub.pause_reason,
            "conformance": {"ok": conformance.ok, "origin": conformance.origin, "at": conformance.at}
            if conformance else None,
            "usage": usage_today(hub, sub), "pending_approvals": len(pending_approvals(hub, sub)),
            "open": open_reports(hub, sub), "updated_at": sub.updated_at}


def detail(hub: "Hub", sub: Subsidiary) -> dict[str, Any]:
    """The subsidiary page: the public record (no credential, enrollment hash or sidecar key), its staff, today's
    usage, pending approvals, the signing keys' public parts, the deployment bundle, the tool's catalog (the actions a
    charter may hold) and the charter versions put in force."""
    from . import charter as charters

    scopes = sub.charter.staff if sub.charter else {}
    try:
        catalog = charters.catalog_actions(hub, sub)
    except Exception:  # a connection or manifest that no longer reads: the page still shows the charter
        catalog = []
    return {**sub.public(), "tool_name": tool_name(hub, sub.tool_id), "usage": usage_today(hub, sub),
            "staff": [{"id": d.id, "name": d.name, "title": d.title, "enabled": d.enabled, "provider": d.provider,
                       "schedule_minutes": d.schedule_minutes,
                       "scope": scopes[d.id].model_dump(mode="json") if d.id in scopes else None}
                      for d in staff(hub, sub)],
            "pending_approvals": [{"id": a.id, "kind": a.kind, "title": a.title, "created_at": a.created_at,
                                   "agent_id": (a.payload or {}).get("agent_id"), "risk": (a.payload or {}).get("risk")}
                                  for a in pending_approvals(hub, sub)],
            "keys": [r.public_view() for r in keys.records(hub, sub.id)],
            "bridge_keys": keys.bridge_keys(hub, sub.id), "bundle": bundle_info(hub, sub),
            "charter_tools": charter_view(hub, sub).tools, "open": open_reports(hub, sub), "catalog": catalog,
            "charter_history": charters.history(hub, sub.id)}


# --------------------------------------------------------------------------------------
# writing
# --------------------------------------------------------------------------------------


def save(hub: "Hub", sub: Subsidiary, actor: str | None = None) -> Subsidiary:
    sub.updated_at = clock(hub)
    if actor:
        sub.updated_by = actor
    hub.store.put(COLLECTION, sub.model_dump(mode="json"))
    hub.bus.publish("subsidiary", summary(hub, sub))
    return sub


def set_flag(sub: Subsidiary, flag: str, on: bool) -> bool:
    """Set or clear a flag; whether it changed."""
    if on and flag not in sub.flags:
        sub.flags.append(flag)  # type: ignore[arg-type]
        return True
    if not on and flag in sub.flags:
        sub.flags.remove(flag)  # type: ignore[arg-type]
        return True
    return False


def set_status(hub: "Hub", sub: Subsidiary, status: str, actor: str, *, reason: str = "",
               level: str = "info") -> Subsidiary:
    old = sub.status
    if old == status:
        return save(hub, sub, actor)
    sub.status = status  # type: ignore[assignment]
    audit.record(hub, sub.id, f"status.{status}", detail={"from": old, **({"reason": reason[:200]} if reason else {})})
    if old == "active":  # runs exist only while active: those under way end now (none is left counting as busy)
        from . import gateway

        gateway.end_open_runs(hub, sub, f"the subsidiary is {STATUS_TEXT[status]}")
    hub.activity(actor, level, f"The {tool_name(hub, sub.tool_id)} subsidiary is now {STATUS_TEXT[status]}"
                 + (f": {reason}" if reason else ""), subsidiary_id=sub.id, tool_id=sub.tool_id, status=status)
    sub = save(hub, sub, actor)
    if status == "probation" and sub.charter_version == 0 and sub.conformance is not None:
        # resumed (the kill switch withdrew the request) or enrolled after conformance ran: conformance results are
        # in, so the first charter's approval is asked for again (on_conformance skips one still pending)
        from . import charter

        charter.on_conformance(hub, sub)
        return get(hub, sub.id) or sub
    return sub


def _network_device(kind: str) -> bool:
    from ..agents.patcher import network_device

    return network_device(kind)


def choose_mode(hub: "Hub", tool_id: str, mode: str) -> str:
    """5.1: a bridge needs a local checkout of an open-source tool with a known stack; API-only mode a connection
    that is not a network device."""
    tool = hub.get_tool(tool_id)
    conn = connections.get(hub, tool_id)
    bridge_ok = bool(tool and tool.manifest and tool.path and Path(tool.path).is_dir()
                     and tool.manifest.kind == "oss" and tool.manifest.stack)
    sidecar_ok = conn is not None and not _network_device(conn.kind)
    if mode == "bridge" and not bridge_ok:
        raise GovernanceError(400, "A bridge needs the tool's source: a local checkout of an open-source tool whose "
                                   "stack is known.", "no_source")
    if mode == "sidecar_only" and not sidecar_ok:
        raise GovernanceError(400, "API-only mode needs a connection to the tool's API.", "no_connection")
    if mode in ("bridge", "sidecar_only"):
        return mode
    if bridge_ok:
        return "bridge"
    if sidecar_ok:
        return "sidecar_only"
    raise GovernanceError(400, "Connect the tool or import its source first.", "no_source")


def ensure_lead(hub: "Hub", sub: Subsidiary) -> None:
    """The subsidiary's managing director - its tool's Tool Supervisor - exists: it requests the subsidiary's
    approvals and settles their decisions."""
    tool = hub.get_tool(sub.tool_id)
    if tool is not None and hub.agents.get(f"tool:{tool.id}") is None:
        hub.agents.ensure_tool_supervisor(tool)


def propose(hub: "Hub", tool_id: str, mode: str, goals: str, actor: str, designer: str = "auto") -> Subsidiary:
    """Create the tool's subsidiary (status proposed). The Patch Agent then designs its bridge patch; in API-only
    mode the route drafts the charter from the connection's catalog (charter.propose_draft)."""
    if not allowed(hub):
        raise GovernanceError(400, "An administrator must first allow subsidiaries (Settings > Agent guardrails).",
                              "disabled")
    tool = hub.get_tool(tool_id)
    if tool is None:
        raise GovernanceError(404, "Tool not found")
    if tool.manifest is None:
        raise GovernanceError(400, "Analyse the tool first: it has no manifest yet.", "no_manifest")
    conn = connections.get(hub, tool_id)
    if conn is not None and _network_device(conn.kind):
        raise GovernanceError(400, "Network devices never get a subsidiary: their changes go through device change "
                                   "proposals.", "network_device")
    current = of_tool(hub, tool_id)
    if current is not None and current.status != "stopped":
        raise GovernanceError(409, f"{tool.name} already has a subsidiary ({STATUS_TEXT[current.status]}).",
                              "exists")
    chosen = choose_mode(hub, tool_id, mode)
    if current is not None:
        archive(hub, current, actor, reason="replaced by a new subsidiary")
    now = clock(hub)
    sub = Subsidiary(id=subsidiary_id(), tool_id=tool_id, mode=chosen,  # type: ignore[arg-type]
                     goals=wire.clean(goals, 2000), designer="model" if designer == "claude" else designer,  # type: ignore[arg-type]
                     created_by=actor, created_at=now, updated_by=actor, updated_at=now)
    keys.ensure(hub, sub.id)
    ensure_lead(hub, sub)
    audit.record(hub, sub.id, "status.proposed", detail={"mode": chosen})
    kind = "bridge" if chosen == "bridge" else "API only"
    hub.activity(actor, "info", f"Proposed a subsidiary for {tool.name} ({kind})", subsidiary_id=sub.id,
                 tool_id=tool_id)
    return save(hub, sub, actor)


def bridge_applied(hub: "Hub", sub_id: str, bridge: BridgeInfo, actor: str) -> Subsidiary:
    """An administrator approved the bridge patch and it was applied: the tool must now be deployed with the public
    bridge.env and the sidecar enrolled (status deploying)."""
    sub = get(hub, sub_id)
    if sub is None or sub.status != "proposed":
        raise GovernanceError(409, "The subsidiary is no longer waiting for its bridge patch.", "not_proposed")
    sub.bridge = bridge
    audit.record(hub, sub.id, "bridge.applied", detail={"patch_id": bridge.patch_id, "core": bridge.core,
                                                         "vendored_core": bridge.vendored_core,
                                                         "manifest_sha256": bridge.manifest_sha256})
    write_bridge_env(hub, sub)
    sub = set_status(hub, sub, "deploying", actor)
    from . import charter

    return charter.on_bridge_applied(hub, sub)  # the draft follows the approved manifest


def retire_staff(hub: "Hub", sub: Subsidiary, actor: str) -> int:
    """Archive: the staff of a subsidiary whose charter is gone leave the tool's team - they can never work again and
    would otherwise count toward max_team_size for the tool's next subsidiary. The audit trail keeps what they did."""
    gone = staff(hub, sub)
    try:
        asyncio.get_running_loop()
        running = True
    except RuntimeError:  # no event loop (a script): the paused proxies go with the next restart
        running = False
    for defn in gone:
        hub.store.delete(teams.COLLECTION, defn.id)
        if running:
            hub.subsidiaries.background(hub.agents.remove(defn.id))
    if gone:
        audit.record(hub, sub.id, "staff.retire", detail={"agents": [d.id for d in gone][:20]})
        hub.activity(actor, "info", f"Removed the {len(gone)} staff member(s) of the archived "
                                    f"{tool_name(hub, sub.tool_id)} subsidiary from its team", subsidiary_id=sub.id)
    return len(gone)


def archive(hub: "Hub", sub: Subsidiary, actor: str, reason: str = "") -> Subsidiary:
    """Archive a stopped subsidiary (or a proposal that was rejected): kept for the audit trail; its credential, keys,
    inbox and staff go."""
    if sub.status not in ("stopped", "proposed"):
        raise GovernanceError(409, "Only a stopped subsidiary can be archived: stop it first.", "not_stopped")
    if sub.status == "proposed":
        withdraw(hub, sub, None, actor, "Withdrawn: the subsidiary proposal was archived")
        revoke_tokens(hub, sub.id)
    from . import bridgepatch

    bridgepatch.discard(hub, sub.id)  # a bridge patch still waiting: rejected, its worktree and branch removed
    reminder = sub.credential is not None
    sub.credential, sub.enrollment = None, None
    keys.retire_all(hub, sub.id)
    runtime.forget(hub, sub.id)
    hub.subsidiaries.forget(sub.id)
    retire_staff(hub, sub, actor)
    set_status(hub, sub, "archived", actor, reason=reason)
    if reminder:
        hub.activity(actor, "warn", f"Revoke the read-only account the {tool_name(hub, sub.tool_id)} subsidiary "
                                    "used in the tool: Atrium deleted its copy of the credential.", subsidiary_id=sub.id)
    return sub


def withdraw(hub: "Hub", sub: Subsidiary, kinds: tuple[str, ...] | None, actor: str, note: str) -> int:
    """Withdraw the subsidiary's pending approvals of these kinds (None: every kind)."""
    count = 0
    for approval in pending_approvals(hub, sub):
        if kinds is None or approval.kind in kinds:
            count += hub.approvals.withdraw(approval.id, note, actor, verb="Withdrawn") is not None
    return count


# -- the dedicated credential (sidecar-only mode, 6.3) ----------------------------------


def set_credential(hub: "Hub", sub: Subsidiary, values: dict[str, Any], actor: str) -> Subsidiary:
    if sub.mode != "sidecar_only":
        raise GovernanceError(400, "Only API-only subsidiaries use a dedicated credential: a bridge holds no secret.",
                              "bridge_mode")
    if sub.status in ("stopped", "archived"):
        raise GovernanceError(409, f"The subsidiary is {sub.status}.", sub.status)
    conn = connections.get(hub, sub.tool_id)
    if conn is None:
        raise GovernanceError(400, "The tool has no connection: set one up first.", "no_connection")
    if _network_device(conn.kind):
        raise GovernanceError(400, "Network devices never get a subsidiary.", "network_device")
    cls = connectors.connector_class(conn.kind)
    fields = {f.name: f for f in cls.fields if f.kind == "secret"}
    clean: dict[str, str] = {}
    for name, value in (values or {}).items():
        if name not in fields:
            raise GovernanceError(400, f"{cls.title} has no secret '{str(name)[:64]}'", "unknown_field")
        if not isinstance(value, str) or not value or len(value) > connections.MAX_SECRET:
            raise GovernanceError(400, f"{fields[name].label} must be text of 1 to {connections.MAX_SECRET} "
                                       "characters", "bad_value")
        clean[name] = value
    for field in fields.values():
        if field.required and field.name not in clean:
            raise GovernanceError(400, f"Enter the {field.label}", "missing")
    if guardrails.value(hub, "subsidiary_separate_credential"):
        try:
            own = set(connections.decrypt(hub, conn).values())
        except Exception:  # a hub credential that cannot be decrypted cannot be equal either
            own = set()
        if own & set(clean.values()):
            raise GovernanceError(400, "The dedicated credential must differ from the hub's own connection credential: "
                                       "create a separate read-only account in the tool.", "same_credential")
    sub.credential = StoredCredential(secrets={k: hub.secrets.encrypt(v) for k, v in clean.items()},
                                      endpoint=conn.endpoint, set_by=actor, set_at=clock(hub))
    audit.record(hub, sub.id, "credential.set", detail={"fields": sorted(clean)})
    hub.activity(actor, "info", f"Set the dedicated read-only credential of the {tool_name(hub, sub.tool_id)} "
                                "subsidiary", subsidiary_id=sub.id)
    return save(hub, sub, actor)


def clear_credential(hub: "Hub", sub: Subsidiary, actor: str) -> Subsidiary:
    if sub.credential is None:
        raise GovernanceError(404, "No dedicated credential is set.", "no_credential")
    sub.credential = None
    audit.record(hub, sub.id, "credential.clear")
    hub.activity(actor, "warn", f"Cleared the dedicated credential of the {tool_name(hub, sub.tool_id)} subsidiary: "
                                "revoke that read-only account in the tool too.", subsidiary_id=sub.id)
    return save(hub, sub, actor)


def credential_for_sidecar(hub: "Hub", sub: Subsidiary) -> CredentialResponse:
    """GET /credential: the plain values, for the sidecar's memory only - bound to the endpoint they were entered
    for, so a changed tool address never receives them."""
    if sub.mode != "sidecar_only" or sub.credential is None:
        raise GovernanceError(404, "This subsidiary has no dedicated credential.", "no_credential")
    if sub.status not in ("probation", "active"):
        raise GovernanceError(423, f"The subsidiary is {sub.status}.", sub.status)
    conn = connections.get(hub, sub.tool_id)
    if conn is None or conn.endpoint != sub.credential.endpoint:
        raise GovernanceError(409, "The tool's address changed since the credential was entered: an administrator "
                                   "enters it again.", "endpoint_changed")
    cls = connectors.connector_class(conn.kind)
    plain = {f.name for f in cls.fields if f.kind != "secret"}
    audit.record(hub, sub.id, "credential.fetch")
    return CredentialResponse(kind=conn.kind, config={k: v for k, v in conn.config.items() if k in plain},
                              secrets={k: hub.secrets.decrypt(v) for k, v in sub.credential.secrets.items()})


def credential_values(hub: "Hub") -> list[str]:
    """The dedicated credentials' plain values, for masking text that leaves Atrium's control."""
    values = []
    for doc in hub.store.list(COLLECTION):
        for token in ((doc.get("credential") or {}).get("secrets") or {}).values():
            try:
                values.append(hub.secrets.decrypt(token))
            except Exception:  # a value that cannot be decrypted cannot leak either
                continue
    return values


# -- enrollment and the sidecar's token (6.3) -------------------------------------------


def tokens_of(hub: "Hub", sub_id: str) -> list[ApiToken]:
    return [ApiToken.model_validate(d) for d in hub.store.list_where("tokens", "subsidiary_id", sub_id)]


def revoke_tokens(hub: "Hub", sub_id: str, keep: tuple[str, ...] = ()) -> int:
    return sum(hub.store.delete("tokens", t.id) for t in tokens_of(hub, sub_id) if t.id not in keep)


def _new_token(hub: "Hub", sub: Subsidiary, owner: User, now: float) -> tuple[ApiToken, str]:
    """A subsidiary token: it reaches only /api/subsidiary/v1/* for this subsidiary and dies with its owner (F2)."""
    secret = secrets.token_urlsafe(32)
    value = TOKEN_PREFIX + secret
    token = ApiToken(name=f"sidecar-{sub.tool_id}"[:56] + f"-{secrets.token_hex(3)}", role="subsidiary",
                     token_hash=sha256_text(value), prefix=secret[:8], created_by=owner.username, owner_id=owner.id,
                     tool_id=sub.tool_id, subsidiary_id=sub.id, created_at=now, expires_at=now + TOKEN_DAYS * DAY)
    hub.store.put("tokens", token.model_dump(mode="json"))
    return token, value


def token_usable(hub: "Hub", sub: Subsidiary) -> bool:
    """Whether the sidecar's current token still works (not revoked or expired; its owner an enabled administrator)."""
    doc = hub.store.get("tokens", sub.token_id or "")
    return doc is not None and hub.auth.token_role(ApiToken.model_validate(doc)) == "subsidiary"


def issue_enrollment(hub: "Hub", sub: Subsidiary, user: User) -> tuple[str, Enrollment]:
    """A one-time enrollment code (32 random bytes, valid 30 minutes; only its SHA-256 is stored). It revokes the
    current token and forgets the sidecar's key: an active subsidiary goes back to probation and proves conformance
    again."""
    if not allowed(hub):
        raise GovernanceError(409, "Subsidiaries are switched off (allow_subsidiaries).", "disabled")
    if sub.status in ("stopped", "archived"):
        raise GovernanceError(409, f"The subsidiary is {sub.status}.", sub.status)
    if sub.mode == "bridge" and sub.status == "proposed":
        raise GovernanceError(409, "Approve the bridge patch first: the tool runs its bridge before a sidecar enrolls.",
                              "not_deployed")
    if sub.mode == "sidecar_only" and sub.credential is None:
        raise GovernanceError(409, "Enter the dedicated read-only credential first.", "no_credential")
    now = clock(hub)
    code = contract.b64u(secrets.token_bytes(32))
    revoked = revoke_tokens(hub, sub.id)
    sub.token_id, sub.sidecar, sub.conformance = None, None, None
    for flag in ("owner_disabled", "offline", "clock_skew"):
        set_flag(sub, flag, False)
    sub.enrollment = Enrollment(code_sha256=sha256_text(code), expires_at=now + ENROLLMENT_MINUTES * 60,
                                issued_by=user.id)
    hub.subsidiaries.tickets.pop(sub.id, None)
    audit.record(hub, sub.id, "enrollment.issue", detail={"issued_by": user.id, "revoked_tokens": revoked,
                                                          "expires_at": sub.enrollment.expires_at})
    hub.activity(user.username, "info", f"Issued a sidecar enrollment for the {tool_name(hub, sub.tool_id)} subsidiary "
                                        f"(valid {ENROLLMENT_MINUTES} minutes)"
                 + (f"; revoked {revoked} sidecar token(s)" if revoked else ""), subsidiary_id=sub.id)
    target = {"proposed": "deploying", "active": "probation"}.get(sub.status)
    if target:
        set_status(hub, sub, target, user.username, reason="new sidecar enrollment")
    else:
        save(hub, sub, user.username)
    return code, sub.enrollment


def enroll(hub: "Hub", req: EnrollRequest, ip: str) -> EnrollResponse:
    """POST /api/subsidiary/v1/enroll: the first key wins, the code is single use. Failed codes are throttled per
    client address like sign-ins."""
    throttle = hub.subsidiaries.enroll_throttle
    wait = throttle.retry_after(ENROLL_KEY, ip)
    if wait is not None:
        raise GovernanceError(429, f"Too many enrollment attempts. Try again in {max(1, wait // 60)} minutes.",
                              "throttled")
    attempt = throttle.attempt(ENROLL_KEY, ip)
    digest, now = sha256_text(req.code), clock(hub)
    sub = next((s for s in all_subsidiaries(hub)
                if s.enrollment and hmac.compare_digest(s.enrollment.code_sha256, digest)), None)
    if sub is None or sub.enrollment is None or sub.enrollment.expires_at <= now \
            or sub.status in ("stopped", "archived"):
        hub.activity("auth", "warn", f"Refused a subsidiary sidecar enrollment from {ip}: unknown, used or expired "
                                     "code")
        raise GovernanceError(401, "This enrollment code is unknown, used or expired.", "bad_code")
    try:
        contract.public_key(req.public_key)
    except ValueError:
        throttle.cancel(ENROLL_KEY, ip, attempt)
        raise GovernanceError(400, "public_key is the base64url of a 32-byte Ed25519 public key.", "bad_key") from None
    if not allowed(hub):
        throttle.cancel(ENROLL_KEY, ip, attempt)
        raise GovernanceError(423, "Subsidiaries are switched off (allow_subsidiaries).", "disabled")
    owner = hub.auth.get_user(sub.enrollment.issued_by)
    if owner is None or owner.disabled or owner.role != "admin":
        throttle.cancel(ENROLL_KEY, ip, attempt)
        raise GovernanceError(403, "The administrator who issued this enrollment no longer can: another administrator "
                                   "issues a new one.", "owner_disabled")
    throttle.succeeded(ENROLL_KEY, ip, attempt)
    token, value = _new_token(hub, sub, owner, now)
    sub.sidecar = SidecarInfo(public_key=req.public_key, key_fingerprint=contract.fingerprint(req.public_key),
                              enrolled_at=now, version=wire.clean(req.version, 40))
    sub.token_id, sub.enrollment = token.id, None
    for flag in ("owner_disabled", "offline", "clock_skew"):
        set_flag(sub, flag, False)
    audit.record(hub, sub.id, "enroll", detail={"key_fingerprint": sub.sidecar.key_fingerprint, "token": token.id,
                                                "owner": owner.id})
    hub.activity(ACTOR, "info", f"The {tool_name(hub, sub.tool_id)} sidecar enrolled (key "
                                f"{sub.sidecar.key_fingerprint}, token owned by {owner.username})",
                 subsidiary_id=sub.id)
    if sub.status == "deploying":
        set_status(hub, sub, "probation", ACTOR, reason="the sidecar enrolled")
    else:
        save(hub, sub, ACTOR)
    return EnrollResponse(token=value, subsidiary_id=sub.id, tool_id=sub.tool_id, expires_at=token.expires_at)


def token_in_use(hub: "Hub", sub: Subsidiary, token: ApiToken) -> None:
    """The new token's first use after a rotation revokes the older ones."""
    if token.id == sub.token_id:
        revoked = revoke_tokens(hub, sub.id, keep=(token.id,))
        if revoked:
            audit.record(hub, sub.id, "token.retire", detail={"revoked": revoked})


def rotate_token(hub: "Hub", sub: Subsidiary, token: ApiToken) -> RotateResponse:
    """POST /rotate: a new token for the same owner; the calling one keeps working until the new one is used."""
    owner = hub.auth.token_owner(token)
    if owner is None or owner.disabled or owner.role != "admin":
        raise GovernanceError(403, "The token's owner is no longer an enabled administrator.", "owner_disabled")
    new, value = _new_token(hub, sub, owner, clock(hub))
    revoke_tokens(hub, sub.id, keep=(token.id, new.id))
    sub.token_id = new.id
    audit.record(hub, sub.id, "token.rotate", detail={"token": new.id})
    save(hub, sub, ACTOR)
    return RotateResponse(token=value, expires_at=new.expires_at)


# -- conformance, readiness and tickets ---------------------------------------------------


def conformance_required(hub: "Hub") -> bool:
    return bool(guardrails.value(hub, "subsidiary_bridge_requires_conformance"))


def conformance_ok(hub: "Hub", sub: Subsidiary, manifest_sha: str | None = None) -> bool:
    """The latest conformance passed - in bridge mode for the approved manifest (or `manifest_sha`)."""
    c = sub.conformance
    if c is None or not c.ok:
        return False
    if sub.mode == "bridge":
        return c.manifest_sha256 is not None and c.manifest_sha256 == (
            manifest_sha or (sub.bridge.manifest_sha256 if sub.bridge else None))
    return True


def proven(hub: "Hub", sub: Subsidiary) -> bool:
    """Conformance as acting needs it: passed for the approved manifest while subsidiary_bridge_requires_conformance
    is on. Tickets, action requests and their approvals check it too, not only the status."""
    return not conformance_required(hub) or conformance_ok(hub, sub)


def ready_status(hub: "Hub", sub: Subsidiary) -> str:
    """Where a subsidiary stands on its own merits (resume): active with an approved charter and conformance (while
    required), probation once enrolled, else deploying."""
    if sub.sidecar is None:
        return "deploying"
    if sub.charter is not None and sub.charter_version > 0 and proven(hub, sub):
        return "active"
    return "probation"


def after_conformance(hub: "Hub", sub: Subsidiary, actor: str) -> Subsidiary:
    """New conformance results: passing ones for the approved manifest clear bridge_mismatch, and a subsidiary on
    probation with an approved charter becomes active again (a first charter is approved through its own approval);
    failing ones put an active subsidiary on hold while conformance is required (hold_for_conformance)."""
    if conformance_ok(hub, sub):
        set_flag(sub, "bridge_mismatch", False)
        if sub.status == "probation" and ready_status(hub, sub) == "active" and allowed(hub):
            return set_status(hub, sub, "active", actor, reason="conformance passed")
    elif sub.status == "active" and conformance_required(hub):
        return hold_for_conformance(hub, sub, actor)
    sub = save(hub, sub, actor)
    from . import charter

    charter.on_conformance(hub, sub)  # the first charter's approval, once conformance passed
    return get(hub, sub.id) or sub


def hold_for_conformance(hub: "Hub", sub: Subsidiary, actor: str) -> Subsidiary:
    """Failing conformance while it is required (subsidiary_bridge_requires_conformance): an active subsidiary goes
    back to probation - probation tickets only, no actions, model turns or approvals - its pending in-tool requests
    are withdrawn and its grants revoked. The next passing run for the approved manifest makes it active again."""
    from . import actions

    withdrawn = withdraw(hub, sub, ("subsidiary_action",), actor, "Withdrawn: the bridge failed conformance")
    cancelled = runtime.cancel(hub, sub.id, ("grant",))
    revoked = actions.revoke_grants(hub, sub, "conformance failed")
    hub.subsidiaries.tickets.pop(sub.id, None)
    if withdrawn or cancelled or revoked:
        audit.record(hub, sub.id, "conformance.hold", detail={"approvals_withdrawn": withdrawn,
                                                              "messages_cancelled": cancelled,
                                                              "grants_revoked": revoked})
    return set_status(hub, sub, "probation", actor, level="warn",
                      reason="conformance failed (subsidiary_bridge_requires_conformance)")


def ticket_actions(hub: "Hub", sub: Subsidiary, mode: str) -> list[str]:
    charter = sub.charter
    if mode != "active" or charter is None:
        return contract.ticket_actions("probation")
    own = [a.id for a in charter.actions if a.policy != "forbidden" and contract.forbidden(a.model_dump()) is None]
    return contract.ticket_actions("active", own, panel=charter.panel.enabled, events=charter.events.relay)


def ticket_for(hub: "Hub", sub: Subsidiary, held_exp: int | None) -> tuple[str, int] | None:
    """A ticket for the sidecar when one is due: bridge mode, enrolled, probation or active, master switch on, none
    of owner_disabled or circuit_open; renewed at half-life or when what it lists changed. bridge_mismatch, and
    conformance that is not current while it is required, drop an active subsidiary's tickets to probation."""
    if (sub.mode != "bridge" or sub.sidecar is None or sub.status not in ("probation", "active") or not allowed(hub)
            or "owner_disabled" in sub.flags or "circuit_open" in sub.flags):
        return None
    mode = "active" if (sub.status == "active" and "bridge_mismatch" not in sub.flags and sub.charter
                        and proven(hub, sub)) else "probation"
    act = ticket_actions(hub, sub, mode)
    rl = sub.charter.budgets.rate() if mode == "active" and sub.charter else dict(contract.DEFAULT_RATE)
    ttl = int(guardrails.value(hub, "subsidiary_ticket_minutes")) * 60
    key = (mode, sub.charter_version, sub.sidecar.public_key, tuple(act), tuple(sorted(rl.items())))
    now = int(clock(hub))
    last = hub.subsidiaries.tickets.get(sub.id)
    if last is not None and last.key == key and held_exp is not None and held_exp - now > ttl // 2:
        return None
    token, payload = keys.issue_ticket(hub, sub.id, tool=sub.tool_id, cv=sub.charter_version, mode=mode, act=act,
                                       cnf=sub.sidecar.public_key, rl=rl, now=now, ttl=ttl)
    if last is None or last.key != key:
        audit.record(hub, sub.id, "ticket.issue", detail={"mode": mode, "cv": sub.charter_version,
                                                          "actions": len(act), "exp": payload["exp"],
                                                          "renewals_before": last.renewals if last else 0})
        hub.subsidiaries.tickets[sub.id] = runtime.IssuedTicket(key=key, exp=payload["exp"])
    else:
        last.exp, last.renewals = payload["exp"], last.renewals + 1
    return token, payload["exp"]


def _clean_ping(ping: dict[str, Any] | None) -> dict[str, Any] | None:
    if ping is None:
        return None
    out = {k: ping[k] for k in SAFE_PING if isinstance(ping.get(k), (str, int, float, bool))}
    out = {k: (v[:100] if isinstance(v, str) else v) for k, v in out.items()}
    if isinstance(ping.get("error"), str):
        out["error"] = wire.clean(ping["error"], 200)
    return out


def heartbeat(hub: "Hub", sub: Subsidiary, req: HeartbeatRequest) -> tuple[HeartbeatResponse, bool]:
    """POST /heartbeat: what the sidecar reports (claimed), its status and flags, and a ticket when one is due.
    Returns the reply and whether the status or flags changed (compliance is re-evaluated then). Its spool goes
    through admit_spool and is recorded by the route, off the event loop."""
    now = clock(hub)
    info = sub.sidecar
    if info is None:
        raise GovernanceError(409, "The sidecar is not enrolled.", "not_enrolled")
    before = (sub.status, sorted(sub.flags))
    info.last_seen, info.version = now, wire.clean(req.version, 40)
    info.health = {"status": req.health, "runs": len(req.runs)}
    info.runtime = {k: req.runtime[k] for k in SAFE_RUNTIME if isinstance(req.runtime.get(k), (str, int, bool))}
    info.runtime = {k: (v[:80] if isinstance(v, str) else v) for k, v in info.runtime.items()}
    info.clock_skew = round(req.clock - now, 1)
    info.bridge_ping = _clean_ping(req.bridge_ping)
    set_flag(sub, "offline", False)
    set_flag(sub, "clock_skew", abs(info.clock_skew) > CLOCK_SKEW)
    live_sha = (info.bridge_ping or {}).get("manifest_sha256")
    if sub.mode == "bridge" and sub.bridge and isinstance(live_sha, str) and live_sha != sub.bridge.manifest_sha256:
        if set_flag(sub, "bridge_mismatch", True):
            audit.record(hub, sub.id, "bridge.mismatch", detail={"live": live_sha[:64],
                                                                  "approved": sub.bridge.manifest_sha256})
            hub.activity(ACTOR, "warn", f"The bridge in {tool_name(hub, sub.tool_id)} no longer matches the approved "
                                        "one: its tickets drop to probation until the approved bridge is deployed "
                                        "again and passes conformance. A changed bridge needs a new subsidiary: stop "
                                        "this one, then propose a new team.", subsidiary_id=sub.id)
    issued = ticket_for(hub, sub, req.ticket_exp)
    changed = (sub.status, sorted(sub.flags)) != before
    if changed:
        save(hub, sub, ACTOR)
    else:  # every 30 s: stored, not broadcast
        hub.store.put(COLLECTION, sub.model_dump(mode="json"))
    status = sub.status if allowed(hub) else "paused"
    reply = HeartbeatResponse(status=status, flags=list(sub.flags),  # type: ignore[arg-type]
                              ticket=issued[0] if issued else None, ticket_exp=issued[1] if issued else None,
                              charter_version=sub.charter_version, server_time=now)
    return reply, changed


def admit_spool(hub: "Hub", sub: Subsidiary, spool: list[ClaimedEntry], dropped: int) -> tuple[list[ClaimedEntry], int]:
    """The part of a heartbeat's spool that is recorded (and the sidecar's own dropped count, when it fits): at most
    CLAIMED_PER_HOUR and CLAIMED_PER_DAY claimed entries. The rest is only counted (UsageDay.claimed_dropped) and
    noted once an hour as an observed ``spool.capped`` entry - a sidecar cannot flood the never-pruned trail."""
    now = clock(hub)
    day, hour = usage_day(hub, sub.id, now), time.strftime("%H", time.gmtime(now))
    room = max(0, min(CLAIMED_PER_HOUR - day.claimed_hour.get(hour, 0), CLAIMED_PER_DAY - day.claimed))
    take = spool[:room]
    kept = dropped if dropped and room > len(take) else 0
    used = len(take) + (1 if kept else 0)
    over = len(spool) - len(take) + (dropped - kept)
    day.claimed += used
    day.claimed_hour = {hour: day.claimed_hour.get(hour, 0) + used}
    if over:
        day.claimed_dropped += over
        if hour not in day.claimed_capped:
            day.claimed_capped = [*day.claimed_capped, hour][-24:]
            audit.record(hub, sub.id, "spool.capped", detail={"dropped_today": day.claimed_dropped,
                                                               "per_hour": CLAIMED_PER_HOUR,
                                                               "per_day": CLAIMED_PER_DAY})
            if len(day.claimed_capped) == 1:
                hub.activity(ACTOR, "warn", f"The {tool_name(hub, sub.tool_id)} sidecar sent more audit entries than "
                                            "it may: the rest are counted, not recorded", subsidiary_id=sub.id)
    if used or over:
        hub.store.put(USAGE, day.model_dump(mode="json"))
    return take, kept


def charter_view(hub: "Hub", sub: Subsidiary) -> CharterView:
    """GET /charter: the approved charter as the sidecar needs it. Staff instructions stay in Atrium, which composes
    every prompt; in API-only mode the connection's non-secret settings."""
    charter = sub.charter
    view = CharterView(subsidiary_id=sub.id, tool_id=sub.tool_id, mode=sub.mode,
                       version=sub.charter_version if charter else 0)
    if charter is not None:
        defs = {d.id: d for d in staff(hub, sub)}
        view.staff = {aid: {"name": defs[aid].name if aid in defs else aid,
                            "title": defs[aid].title if aid in defs else "",
                            "enabled": aid in defs and defs[aid].enabled,
                            "actions": list(scope.actions), "hub_tools": list(scope.hub_tools)}
                      for aid, scope in charter.staff.items()}
        usable = [a for a in charter.actions if a.policy != "forbidden"]
        view.actions = usable
        act = [CharterTool(name=contract.tool_name(a.id), action_id=a.id, risk=a.risk) for a in usable]
        hub_tools = sorted({t for scope in charter.staff.values() for t in scope.hub_tools})
        view.tools["normal"] = [*act, *(CharterTool(name=contract.hub_tool_name(t)) for t in hub_tools),
                                CharterTool(name=contract.REPORT_TOOL), CharterTool(name=contract.ESCALATE_TOOL)]
        writes = bool(guardrails.value(hub, "subsidiary_panel_actions"))
        view.tools["panel"] = [*(t for t, a in zip(act, usable) if (a.risk == "read" and a.on_behalf_of)
                                 or a.risk == "propose" or (a.risk == "write" and writes)),
                               CharterTool(name=contract.ESCALATE_TOOL)] if charter.panel.enabled else []
        view.panel, view.events, view.budgets = charter.panel, charter.events, charter.budgets
    if sub.mode == "sidecar_only":
        conn = connections.get(hub, sub.tool_id)
        if conn is not None:
            cls = connectors.connector_class(conn.kind)
            plain = {f.name for f in cls.fields if f.kind != "secret"}
            view.connection = {"kind": conn.kind, "config": {k: v for k, v in conn.config.items() if k in plain}}
    return view


# -- pause, resume, stop, kill switch (7.7) -------------------------------------------------


def pause(hub: "Hub", sub: Subsidiary, actor: str, reason: str = "", *, level: str = "warn") -> Subsidiary:
    """Protective, so operators may: no model answers, actions, hub requests or runs from now on, no new ticket;
    pending in-tool action approvals are withdrawn, queued runs and grants cancelled and delivered grants revoked, so
    resuming releases no backlog. The bridge refuses everything once the last ticket expires; until then it still
    accepts a grant the sidecar already holds (up to its expiry plus the clock leeway) - a result showing one ran after
    the pause is a reconciliation alarm."""
    if sub.status not in WORKING:
        raise GovernanceError(409, f"The {tool_name(hub, sub.tool_id)} subsidiary is {STATUS_TEXT[sub.status]}: there "
                                   "is nothing to pause.", "not_running")
    reason = wire.clean(reason, 500).strip()
    sub.paused_by, sub.paused_at, sub.pause_reason = actor, clock(hub), reason or None
    withdrawn = withdraw(hub, sub, ("subsidiary_action",), actor, "Withdrawn: the subsidiary was paused")
    cancelled = runtime.cancel(hub, sub.id, ("run", "chat", "grant"))
    runtime.cancel(hub, sub.id, ("resume",))  # only the latest of pause/resume is delivered
    runtime.post(hub, sub.id, "pause", {"reason": reason})
    hub.subsidiaries.tickets.pop(sub.id, None)
    from . import actions

    revoked = actions.revoke_grants(hub, sub, "paused")  # a delivered grant stays usable at the bridge until exp
    if withdrawn or cancelled or revoked:
        audit.record(hub, sub.id, "pause.backlog", detail={"approvals_withdrawn": withdrawn,
                                                           "messages_cancelled": cancelled, "grants_revoked": revoked})
    return set_status(hub, sub, "paused", actor, reason=reason, level=level)


def pause_all(hub: "Hub", actor: str, reason: str = "") -> list[Subsidiary]:
    return [pause(hub, sub, actor, reason) for sub in all_subsidiaries(hub) if sub.status in WORKING]


def resume(hub: "Hub", sub: Subsidiary, actor: str) -> Subsidiary:
    """An administrator resumes a paused subsidiary: a new ticket at the next heartbeat, circuit_open cleared and the
    circuit breaker counting afresh (the budget hits and refusals before the resume no longer trip it again)."""
    if sub.status != "paused":
        raise GovernanceError(409, f"The subsidiary is {STATUS_TEXT[sub.status]}, not paused.", "not_paused")
    if not allowed(hub):
        raise GovernanceError(409, "Subsidiaries are switched off (allow_subsidiaries): switch them on first.",
                              "disabled")
    set_flag(sub, "circuit_open", False)
    sub.circuit_reset_at = clock(hub)
    sub.paused_by, sub.paused_at, sub.pause_reason = None, None, None
    # a pause the sidecar has not fetched yet would otherwise arrive after this resume and drop the work behind it
    runtime.cancel(hub, sub.id, ("pause",))
    runtime.post(hub, sub.id, "resume", {"charter_version": sub.charter_version})
    return set_status(hub, sub, ready_status(hub, sub), actor, reason="resumed")


def stop(hub: "Hub", sub: Subsidiary, actor: str, confirm: str) -> Subsidiary:
    """Stop for good: the token is revoked, approvals withdrawn, the staff disabled and the signing key replaced
    without staging, so the deployed bridge refuses every new ticket. A new subsidiary must be proposed after it."""
    if sub.status in ("stopped", "archived"):
        raise GovernanceError(409, f"The subsidiary is already {sub.status}.", sub.status)
    name = tool_name(hub, sub.tool_id)
    if confirm.strip() not in (name, sub.tool_id):
        raise GovernanceError(400, f"Type the tool's name ({name}) to confirm.", "confirm")
    revoked = revoke_tokens(hub, sub.id)
    withdrawn = withdraw(hub, sub, None, actor, "Withdrawn: the subsidiary was stopped")
    runtime.cancel(hub, sub.id, ("run", "chat", "grant", "conformance"))
    from . import actions

    actions.revoke_grants(hub, sub, "stopped")
    runtime.post(hub, sub.id, "stop", {"reason": "stopped by Atrium"})
    disabled = 0
    for defn in staff(hub, sub):
        if defn.enabled:
            defn.enabled, defn.updated_by, defn.updated_at = False, actor, clock(hub)
            teams.save_def(hub, defn)
            disabled += 1
    record = keys.rotate_now(hub, sub.id)
    audit.record(hub, sub.id, "key.rotate", detail={"kid": record.kid, "staged": False})
    sub.token_id, sub.enrollment = None, None
    sub.stopped_by, sub.stopped_at = actor, clock(hub)
    write_bridge_env(hub, sub, revoked=True)
    hub.subsidiaries.forget(sub.id)
    audit.record(hub, sub.id, "stop", detail={"tokens_revoked": revoked, "approvals_withdrawn": withdrawn,
                                              "staff_disabled": disabled})
    set_status(hub, sub, "stopped", actor, level="warn")
    if sub.credential is not None:
        hub.activity(actor, "warn", f"Revoke the read-only account the {name} subsidiary used in the tool.",
                     subsidiary_id=sub.id)
    return sub


def forget_tool(hub: "Hub", tool_id: str, actor: str) -> Subsidiary | None:
    """The tool leaves the hub: its subsidiary is stopped (token revoked, key replaced, approvals withdrawn, staff
    disabled) and archived. Its audit trail stays."""
    sub = of_tool(hub, tool_id)
    if sub is None:
        return None
    if sub.status != "proposed":
        stop(hub, sub, actor, confirm=sub.tool_id)
    return archive(hub, sub, actor, reason="the tool was removed from the hub")


def kill_switch(hub: "Hub", actor: str) -> dict[str, int]:
    """allow_subsidiaries switched off: every working subsidiary is paused, their pending approvals withdrawn, and
    the sidecar API answers 423 disabled (heartbeat and inbox excepted) until it is on again and they are resumed."""
    paused = withdrawn = 0
    for sub in all_subsidiaries(hub):
        if sub.status in WORKING:
            pause(hub, sub, actor, "Subsidiaries were switched off (allow_subsidiaries)")
            paused += 1
        if sub.status not in ("stopped", "archived"):
            withdrawn += withdraw(hub, sub, ("subsidiary_charter", "subsidiary_action"), actor,
                                  "Withdrawn: subsidiaries were switched off")
    if paused or withdrawn:
        hub.activity(actor, "warn", f"Subsidiaries switched off: {paused} paused, {withdrawn} approval(s) withdrawn")
    return {"paused": paused, "withdrawn": withdrawn}


# -- staff --------------------------------------------------------------------------------


def is_staff(hub: "Hub", sender: str | None) -> bool:
    """Whether a bus sender is sidecar staff of a subsidiary (their hub-side requests always wait for approval)."""
    if not sender or not str(sender).startswith("agent:"):
        return False
    defn = teams.get_def(hub, str(sender))
    return defn is not None and defn.placement == "sidecar"


def hold(hub: "Hub", defn: AgentDef) -> str | None:
    """Why sidecar staff may not act now (None: they may) - the scheduler, chat and runs refuse them meanwhile."""
    if defn.placement != "sidecar":
        return None
    name = tool_name(hub, defn.team)
    if not allowed(hub):
        return "subsidiaries are switched off by Atrium (allow_subsidiaries)"
    sub = of_tool(hub, defn.team)
    if sub is None:
        return f"{name} has no subsidiary"
    if sub.status != "active":
        return f"the {name} subsidiary is {STATUS_TEXT[sub.status]} by Atrium" if sub.status in ("paused", "stopped") \
            else f"the {name} subsidiary is {STATUS_TEXT[sub.status]}"
    blocking = [FLAG_TEXT[f] for f in BLOCKING_FLAGS if f in sub.flags]
    return f"the {name} subsidiary is held: " + "; ".join(blocking) if blocking else None


# -- alarms, the circuit breaker and the periodic tick (7.5, 7.8) ----------------------------


def add_alarm(hub: "Hub", sub: Subsidiary, kind: str, detail: dict[str, Any] | None = None) -> Subsidiary:
    """A reconciliation alarm or a broken audit chain: kept 90 days for HB-AC-8 (it fails meanwhile)."""
    now = clock(hub)
    sub.alarms = [a for a in sub.alarms if now - float(a.get("at", 0)) < ALARM_WINDOW][-49:]
    sub.alarms.append({"kind": kind, "at": now, "detail": audit.clean_detail(detail or {})})
    audit.record(hub, sub.id, "alarm", outcome=kind, detail=audit.clean_detail(detail or {}))
    hub.activity(ACTOR, "error", f"Alarm on the {tool_name(hub, sub.tool_id)} subsidiary: {kind}", subsidiary_id=sub.id)
    return save(hub, sub, ACTOR)


def open_circuit(hub: "Hub", sub: Subsidiary, reason: str) -> Subsidiary:
    """The circuit breaker: circuit_open is set and the subsidiary paused; an administrator resumes it."""
    set_flag(sub, "circuit_open", True)
    audit.record(hub, sub.id, "circuit.open", detail={"reason": reason[:200]})
    if sub.status in WORKING:
        return pause(hub, sub, ACTOR, f"Circuit breaker: {reason}", level="error")
    hub.activity(ACTOR, "error", f"Circuit breaker of the {tool_name(hub, sub.tool_id)} subsidiary: {reason}",
                 subsidiary_id=sub.id)
    return save(hub, sub, ACTOR)


def tick(hub: "Hub", now: float | None = None) -> list[str]:
    """One pass (from the flow scheduler): offline after 90 s without a heartbeat, owner_disabled when the sidecar's
    token stopped working, expired enrollments and inbox messages, and the circuit breaker on budget hits. Returns the
    ids whose status or flags changed (compliance is re-evaluated then)."""
    now = clock(hub) if now is None else now
    changed = []
    for sub in all_subsidiaries(hub):
        if sub.status == "archived":
            continue
        before = (sub.status, sorted(sub.flags))
        dirty = False
        info = sub.sidecar
        if sub.status not in ("stopped",) and info is not None and info.last_seen is not None \
                and now - info.last_seen > OFFLINE_AFTER and set_flag(sub, "offline", True):
            hub.activity(ACTOR, "warn", f"The {tool_name(hub, sub.tool_id)} sidecar is offline (no heartbeat for "
                                        f"{OFFLINE_AFTER} s)", subsidiary_id=sub.id)
        if sub.token_id:
            usable = token_usable(hub, sub)
            if set_flag(sub, "owner_disabled", not usable) and not usable:
                audit.record(hub, sub.id, "token.unusable")
                hub.activity(ACTOR, "warn", f"The {tool_name(hub, sub.tool_id)} sidecar's token no longer works (its "
                                            "owner was disabled or demoted, or it was revoked): another administrator "
                                            "issues a new enrollment.", subsidiary_id=sub.id)
        if sub.enrollment is not None and sub.enrollment.expires_at <= now:
            sub.enrollment, dirty = None, True
            audit.record(hub, sub.id, "enrollment.expire")
        runtime.prune(hub, sub.id)
        day = usage_day(hub, sub.id, now)
        since = max(now - 3600, sub.circuit_reset_at or 0)  # within the hour, after the last resume
        hits = [h for h in day.budget_hits if h > since]
        refusals = [h for h in day.denied_at if h > since]
        if len(hits) >= CIRCUIT_BUDGET_HITS and "circuit_open" not in sub.flags and sub.status in WORKING:
            open_circuit(hub, sub, f"{len(hits)} budget refusals within an hour")
        elif len(refusals) >= CIRCUIT_REFUSALS and "circuit_open" not in sub.flags and sub.status in WORKING:
            open_circuit(hub, sub, f"{len(refusals)} refused action requests within an hour")
        if sub.status == "active" and not proven(hub, sub):  # e.g. the guardrail was switched on again
            hold_for_conformance(hub, sub, ACTOR)
        if "over_budget" in sub.flags and not day.budget_hits:  # a new UTC day
            set_flag(sub, "over_budget", False)
        from . import actions, gateway

        gateway.expire_runs(hub, sub, now)  # runs left open; reports and transcripts past their retention
        actions.expire_requests(hub, sub, now)
        actions.reconcile(hub, sub, now)  # grants without a result: unknown
        if (sub.status, sorted(sub.flags)) != before:
            save(hub, sub, ACTOR)
            changed.append(sub.id)
        elif dirty:
            save(hub, sub, ACTOR)
    return changed


# -- the approvals Atrium guards (9.4) -------------------------------------------------------


def charter_problems(hub: "Hub", charter: Charter) -> list[str]:
    """The charter invariants that need only the charter and the contract: no forbidden action, no policy looser than
    an action allows, scopes within the actions, budgets above zero and within the guardrail, a mandate, and a panel
    desk among the staff."""
    problems = []
    writes_auto = not guardrails.value(hub, "subsidiary_tool_writes_need_approval")
    for action in charter.actions:
        spec = action.model_dump()
        if hit := contract.forbidden(spec):
            problems.append(f"action '{action.id}' is forbidden ({contract.FORBIDDEN_RULES[hit[0]]})")
        if contract.RISK_RANK[action.risk] < contract.RISK_RANK[contract.risk_floor(spec)]:
            problems.append(f"action '{action.id}' is below its risk floor")
        if action.policy == "allow" and action.risk not in ("read", "propose"):
            problems.append(f"action '{action.id}' changes the tool, so it needs approval")
        if action.policy == "auto" and not (action.risk == "write" and action.reversible and not action.external_effect
                                            and writes_auto):
            problems.append(f"action '{action.id}' cannot run without approval")
    ids = {a.id for a in charter.actions}
    for agent_id, scope in charter.staff.items():
        if outside := sorted(set(scope.actions) - ids):
            problems.append(f"{agent_id} is scoped to actions outside the charter: {', '.join(outside)}")
    budgets = charter.budgets.model_dump()
    if low := [k for k, v in budgets.items() if v <= 0]:
        problems.append(f"budgets must be above zero: {', '.join(low)}")
    cap = int(guardrails.value(hub, "subsidiary_max_tokens_per_day")) * 1000
    if charter.budgets.tokens_per_day > cap:
        problems.append(f"tokens_per_day is above the ceiling of {cap} (guardrail subsidiary_max_tokens_per_day)")
    if not charter.mandate.strip():
        problems.append("the mandate is empty")
    if charter.panel.enabled and charter.panel.desk not in charter.staff:
        problems.append("the panel's front desk is not one of the staff")
    return problems


def check_charter_decision(hub: "Hub", approval: Approval, approve: bool) -> None:
    """Guard of ``subsidiary_charter`` approvals (raising refuses the approval; rejecting is always possible)."""
    if not approve:
        return
    sub = get(hub, str((approval.payload or {}).get("subsidiary_id") or ""))
    if not allowed(hub):
        raise ValueError("Subsidiaries are switched off (allow_subsidiaries): the charter cannot be approved")
    if sub is None or sub.status not in LIVE:
        raise ValueError("The subsidiary is not enrolled, on probation, active or paused any more")
    pending = sub.pending_charter
    if pending is None or sub.pending_charter_approval != approval.id \
            or approval.payload.get("charter_sha256") != pending.sha256():
        raise ValueError("The charter changed since this approval was requested: decide the newer one")
    if conformance_required(hub) and not conformance_ok(hub, sub, pending.manifest_sha256):
        raise ValueError("The bridge has not passed conformance for this charter's manifest "
                         "(guardrail subsidiary_bridge_requires_conformance)")
    if problems := charter_problems(hub, pending):
        raise ValueError("The charter breaks the subsidiary rules: " + "; ".join(problems[:5]))
    from . import charter

    charter.check_decision(hub, sub, approval)  # the version, the staff (scopes, providers, clamp, team room)


def check_action_decision(hub: "Hub", approval: Approval, approve: bool) -> None:
    """Guard of ``subsidiary_action`` approvals: the subsidiary still active and unflagged, the same charter version,
    the request not expired, the action still in it and the approved body still valid against its parameters."""
    if not approve:
        return
    payload = approval.payload or {}
    sub = get(hub, str(payload.get("subsidiary_id") or ""))
    if not allowed(hub):
        raise ValueError("Subsidiaries are switched off (allow_subsidiaries)")
    if sub is None or sub.status != "active":
        raise ValueError("The subsidiary is not active: this action can only be rejected")
    if blocking := [f for f in BLOCKING_FLAGS if f in sub.flags]:
        raise ValueError(f"The subsidiary is held ({', '.join(blocking)}): this action can only be rejected")
    if not proven(hub, sub):
        raise ValueError("The bridge has not passed conformance (guardrail subsidiary_bridge_requires_conformance): "
                         "this action can only be rejected")
    if payload.get("charter_version") != sub.charter_version or sub.charter is None:
        raise ValueError("The charter changed since this action was requested: it can only be rejected")
    expires = payload.get("expires_at")
    if isinstance(expires, (int, float)) and clock(hub) > expires:
        raise ValueError("This request expired: it can only be rejected")
    action = sub.charter.action(str(payload.get("action_id") or ""))
    if action is None or action.policy == "forbidden":
        raise ValueError("The charter no longer allows this action")
    try:
        body = contract.b64u_decode(str(payload.get("body_b64") or ""))
        contract.validate_params(action.params, contract.parse_body(body))
    except (ValueError, contract.Refused):
        raise ValueError("The approved parameters no longer fit the action") from None
    if payload.get("body_sha256") != contract.sha256_hex(body):
        raise ValueError("The approved body does not match its hash")
    agent_id = payload.get("agent_id")
    if agent_id:  # check 2: the staff member still holds this action and may act
        defn = teams.get_def(hub, str(agent_id))
        scope = sub.charter.staff.get(str(agent_id))
        if defn is None or defn.placement != "sidecar" or defn.team != sub.tool_id or scope is None \
                or action.id not in scope.actions:
            raise ValueError("The staff member who asked no longer may: this action can only be rejected")
        if blocked := teams.outside_guardrails(hub, defn):
            raise ValueError(f"{defn.name} may not act: {blocked}")
    run_id = payload.get("run_id")
    if run_id:
        run = hub.store.get(COLLECTIONS["runs"], str(run_id))
        if run is None or run.get("subsidiary_id") != sub.id or (agent_id and run.get("agent_id") != agent_id):
            raise ValueError("The run that asked for this action is not this subsidiary's")


# -- the bridge's public configuration and the sidecar bundle (4.1, 5.3) ---------------------


def adapter_dir(hub: "Hub", sub: Subsidiary) -> Path:
    return hub.settings.workspace / "adapters" / sub.tool_id / "subsidiary"


def bridge_env(hub: "Hub", sub: Subsidiary, *, revoked: bool = False) -> str:
    """The public bridge.env (no secret): the keys bridges accept, the ids and the panel switch. `revoked` leaves the
    keys out, so a bridge started with it refuses every call (fail closed)."""
    panel = bool(sub.bridge and (sub.bridge.manifest.get("panel") or {}).get("enabled"))
    lines = ["# Atrium bridge configuration (public values: no secret). Generated by Atrium.",
             f"{contract.ENV_KEYS}={'' if revoked else keys.bridge_keys(hub, sub.id)}",
             f"{contract.ENV_TOOL}={sub.tool_id}", f"{contract.ENV_SUBSIDIARY}={sub.id}",
             f"{contract.ENV_PANEL}={'on' if panel else 'off'}"]
    return "\n".join(lines) + "\n"


def write_bridge_env(hub: "Hub", sub: Subsidiary, *, revoked: bool = False) -> Path | None:
    """(Re)write adapters/<tool>/subsidiary/bridge.env for a bridge-mode subsidiary (Atrium-launched tools load it
    through launch.env_files)."""
    path = adapter_dir(hub, sub) / "bridge.env"
    if sub.mode != "bridge" or (sub.bridge is None and not path.exists()):
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(bridge_env(hub, sub, revoked=revoked), encoding="utf-8")
    return path


def bundle_info(hub: "Hub", sub: Subsidiary) -> dict[str, Any]:
    root = adapter_dir(hub, sub)
    sidecar = root / "sidecar"
    return {"dir": str(root), "bridge_env": (root / "bridge.env").is_file(), "sidecar_dir": str(sidecar),
            "sidecar_files": sorted(p.name for p in sidecar.iterdir()) if sidecar.is_dir() else []}


# -- compliance facts (HB-AC-8) ----------------------------------------------------------------


def compliance_facts(hub: "Hub") -> dict[str, Any]:
    """What the HB-AC-8 check reads: ids, statuses, flags and counts - never tool data."""
    now = clock(hub)
    subs = all_subsidiaries(hub)
    untested = {p.tool_id for p in hub.patches() if p.strategy == "atrium_bridge" and p.status == "applied"
                and (p.tests or {}).get("status") == "not_run"}
    live = []
    for sub in subs:
        if sub.status not in LIVE:
            continue
        c = sub.conformance
        live.append({"id": sub.id, "tool_id": sub.tool_id, "mode": sub.mode, "status": sub.status,
                     "flags": list(sub.flags), "charter_version": sub.charter_version,
                     "charter_approved": sub.charter is not None and sub.charter_version > 0
                     and bool(sub.charter_approved_by),
                     "conformance": {"ok": c.ok, "origin": c.origin, "current": conformance_ok(hub, sub)}
                     if c else None,
                     "alarms_90d": sum(1 for a in sub.alarms if now - float(a.get("at", 0)) < ALARM_WINDOW),
                     "offline_hours": round((now - sub.sidecar.last_seen) / 3600, 1)
                     if sub.sidecar and sub.sidecar.last_seen and "offline" in sub.flags else 0,
                     "untested_bridge": sub.mode == "bridge" and sub.tool_id in untested})
    counts: dict[str, int] = {}
    for sub in subs:
        counts[sub.status] = counts.get(sub.status, 0) + 1
    return {"live": live, "counts": counts, "audit_entries": audit.count(hub, [s.id for s in subs])}
