"""Guarded network device changes: the FirewallChange lifecycle (docs/research/canvas-design.md 6.6 and 7.7, safety
rules S1-S16) with an Atrium-managed backup before every apply, maintenance windows (``maintenance.py``), approvals
bound to what was reviewed that expire, and the kill switch.

This module holds the model, the validation and the planning (pure: no device access), the binding checks and the
sweeps. The Network Supervisor (``agents/network.py``) drives the device, only through the tool supervisor's
``network.preview`` / ``network.apply`` / ``network.confirm`` / ``network.rollback`` / ``network.restore`` subjects -
each re-loads the change and its approval from the store and checks them again (S8) - never through
``connector.action``.

Lifecycle::

    proposed --approve--> approved --(outside a window)--> scheduled --(window opens / emergency)--+
       |                     |                                 |                                    v
       | reject / withdraw   | expired / stale / blocked / withdrawn / failed (nothing changed)    applying
       v                     v                                                                      |
    rejected / withdrawn   (final)                    verifying (rollback window) <-----------------+
                                                         | checks pass + confirm      | checks fail / no confirm
                                                         v                            v
                                                      applied --"Revert..."-->     rolled_back (re-read proves it)
                                                      new proposal (S10)           failed (device state unknown:
                                                                                   the pre-change backup was restored
                                                                                   or could not be - alert)

Ops: ``allow`` (one pass rule between two zones' networks with explicit services, S13), ``disable_rules`` (pass rules
only - disabling a block rule would open traffic), ``revert`` (the inverse of an applied change: ``netmodel.inverse_ops``)
and ``restore`` (put an Atrium-managed backup back, ``restore_backup``). Every change is a proposal with an approval of
kind ``firewall`` - also in autonomous mode (S3) - decided by an administrator who did not propose it while
``device_changes_need_second_person`` is on (S4; ``Approvals.check_second_person``, the API answers 403
``admin_required`` / ``same_person``). People approve, not API tokens (403 ``person_required``), and a token counts as
the person who created it (``approvals.identities``), so nobody approves their own proposal with a token they made.

Binding (S6/S7): the proposal makes a fresh read of the device; the change keeps ``base_revision`` (the device's
revision), ``base_hash`` (``netmodel.record_hash`` of that read) and ``ops_hash`` (``netmodel.ops_hash``; for a restore
the hash of the backup id and its SHA-256); the approval payload carries them. Before applying, the Network Supervisor
reads the device again: another revision -> ``stale``, nothing applied. Approvals expire ``approval_expiry_hours``
(guardrail, default 24, 1-72) after the proposal -> ``expired``. Switching ``device_changes`` off blocks every approved
or scheduled change at once (S14, ``kill_switch``); a change being verified completes or rolls back as usual.

Collection ``firewall_changes`` (SSE ``firewall_change``: ``public(change)``)::

    {id "chg_...", firewall (tool id), op, request (what was asked), ops (canonical; [] for restore), ops_hash,
     base_revision, base_hash, edge ("zp:<source zone>><target zone>" | None), zones (touched zone ids),
     preview {steps, diff, violations, impact, notes, problems, device_steps, device_notes, rollback, maintenance,
     policy_unknown (a restore the segmentation policy cannot be checked for: S11 treats it as forbidden)},
     status, approval_id, proposed_by, justification, created_at, updated_at, expires_at, decided_by, decided_at,
     self_approved (its proposer approved it: only possible while the second-person guardrail was off), scheduled_for, window {window_id, name, start, end} | None, expires_before_window (the next window opens after
     the approval expired), emergency {by, at, justification} | None,
     backup_id (the Atrium backup taken before applying), rollback {mode, window_s}, rollback_until,
     applied {revision, created, disabled, enabled, notes} | None, verification [{name, ok, detail}],
     result {ok, state, method, detail} | None, applied_at, finished_at, revert_of, reverted_by,
     history [{at, status, actor, note}]}

``device_change_tokens`` keeps the connector's opaque token per change (never returned by the API).

Device text (rule descriptions, zone names) appears only in ``preview`` (diff, steps) and is untrusted: shown as text,
never in approval titles, activity entries or anything agents read (those use ids reduced by ``display_id``).
"""

from __future__ import annotations

import difflib
import hashlib
import time
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .. import connectors, guardrails
from ..connectors.base import ConnectorError
from ..connectors.netmodel import (MAX_SERVICES, canonical_json, display_id, interface_names, marker, ops_diff,
                                   ops_hash, parse_ops, record_lines, rule_line, service_text, targets_device,
                                   untrusted_text)
from ..models import Asset
from ..store import new_id
from . import connections, maintenance, network, segmentation

if TYPE_CHECKING:
    from ..core import Hub
    from ..models import Approval

CHANGES = network.CHANGES
TOKENS = "device_change_tokens"
OPS = ("allow", "disable_rules", "revert", "restore")
STATUSES = ("proposed", "approved", "scheduled", "applying", "verifying", "applied", "rejected", "withdrawn",
            "expired", "stale", "blocked", "failed", "rolled_back")
WAITING = ("proposed", "approved", "scheduled")  # the device was not touched yet
DECIDED = ("approved", "scheduled")
ACTIVE = ("applying", "verifying")
FINAL = ("applied", "rejected", "withdrawn", "expired", "stale", "blocked", "failed", "rolled_back")
FORBIDDEN_JUSTIFICATION = 20  # S11: an administrator's justification for a change that may violate a forbidden rule
RESTRICTED_JUSTIFICATION = 10
EMERGENCY_JUSTIFICATION = 20
HISTORY_LIMIT = 50
CARD_FIELDS = ("id", "firewall", "op", "status", "proposed_by", "created_at", "expires_at", "scheduled_for", "window",
               "expires_before_window", "emergency", "rollback", "rollback_until", "revert_of",
               "edge")  # GET /api/approvals, kind firewall
REVERT_GRACE = 120  # seconds after a device's own rollback deadline before the hub decides it did not revert
SECOND_PERSON = "device_changes_need_second_person"
WINDOW_GUARD = "device_changes_need_maintenance_window"
BACKUP_GUARD = "device_changes_need_backup"


class ChangeRefused(Exception):
    """A request the change path refuses: HTTP `status`, machine `code`, a message a person can act on, extras."""

    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "code": self.code, "message": self.message, **self.extra}


class ServiceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proto: Literal["tcp", "udp", "icmp"]
    ports: str | int | None = None


class ChangeRequest(BaseModel):
    """What a person asks for (preview and create): an allow between two zones of one firewall, or disabling rules."""

    model_config = ConfigDict(extra="forbid")
    firewall: str = Field(min_length=1, max_length=200)
    op: Literal["allow", "disable_rules"]
    source_zone: str | None = Field(None, max_length=400)
    target_zone: str | None = Field(None, max_length=400)
    services: list[ServiceIn] = Field([], max_length=MAX_SERVICES)
    log: bool = True
    description: str = Field("", max_length=120)
    rule_ids: list[str] = Field([], max_length=50)
    edge: str | None = Field(None, max_length=900)
    justification: str | None = Field(None, max_length=2000)
    base_revision: str | None = Field(None, max_length=300)


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def get(hub: "Hub", change_id: str) -> dict[str, Any] | None:
    return hub.store.get(CHANGES, change_id)


def listing(hub: "Hub", firewall: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    items = [c for c in hub.store.list(CHANGES) if (firewall is None or c.get("firewall") == firewall)
             and (status is None or c.get("status") == status)]
    return sorted(items, key=lambda c: (-(c.get("created_at") or 0), c["id"]))


def public(change: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in change.items() if k != "token"}


def save(hub: "Hub", change: dict[str, Any], status: str | None = None, actor: str = "module:network",
         note: str | None = None) -> dict[str, Any]:
    now = time.time()
    if status is not None and status != change.get("status"):
        change["status"] = status
        change["history"] = [*(change.get("history") or []),
                             {"at": now, "status": status, "actor": actor, "note": (note or "")[:300] or None}
                             ][-HISTORY_LIMIT:]
        if status in FINAL:
            change["finished_at"] = now
    change["updated_at"] = now
    hub.store.put(CHANGES, change)
    hub.bus.publish("firewall_change", public(change))
    segmentation.changed(hub, [change["firewall"]])
    return change


def store_token(hub: "Hub", change_id: str, token: str) -> None:
    hub.store.put(TOKENS, {"id": change_id, "token": token, "at": time.time()})


def token(hub: "Hub", change_id: str) -> str | None:
    doc = hub.store.get(TOKENS, change_id)
    return doc["token"] if doc else None


def tool_name(hub: "Hub", tool_id: str) -> str:
    tool = hub.get_tool(tool_id)
    return tool.name if tool else display_id(tool_id)


def summary(change: dict[str, Any]) -> str:
    """A one-line description built from ids only (safe for approval titles, activity and agents)."""
    op = change["op"]
    if op == "allow":
        rule = change["ops"][0]
        return (f"allow {display_id(rule['source']['zone'])} -> {display_id(rule['destination']['zone'])} "
                f"({service_text(rule['services'])})")
    if op == "disable_rules":
        return f"disable {sum(len(o['rules']) for o in change['ops'])} rule(s)"
    if op == "revert":
        return f"revert {display_id(change.get('revert_of'))}"
    return f"restore backup {display_id((change.get('request') or {}).get('backup_id'))}"


# --------------------------------------------------------------------------------------
# what a device allows now (S2) and the guardrails
# --------------------------------------------------------------------------------------


def expiry_hours(hub: "Hub") -> int:
    return int(guardrails.value(hub, "approval_expiry_hours"))


def can_restore(hub: "Hub", tool_id: str) -> bool:
    conn = connections.get(hub, tool_id)
    if conn is None or conn.generated or conn.kind == "generic_rest":
        return False
    try:
        cls = connectors.connector_class(conn.kind)
    except ConnectorError:
        return False
    return cls.implements("restore_backup") and cls.implements("backup")


def write_state(hub: "Hub", tool_id: str, op: str, kinds: list[str] | None = None,
                now: float | None = None) -> dict[str, Any]:
    """``network.write_status`` for one kind of change: `kinds` are the netmodel op names it needs (allow,
    disable_rules, enable_rules). A restore rewrites the whole configuration, so it needs a writable device too (a
    connection set to read only, a connector without a rollback mechanism or a test that narrowed the capability
    away: ``not_capable``) and, instead of rule writes, backup + restore_backup."""
    status = network.write_status(hub, tool_id, now)
    reasons = list(status["reasons"])
    if op == "restore":
        if status["capable"] and not can_restore(hub, tool_id):
            reasons.insert(0, "not_capable")
    elif status["capable"]:
        missing = [k for k in kinds or [op] if k not in status["ops"]]
        if missing:
            reasons.insert(0, "op_not_supported")
    return {**status, "writable": not reasons, "reason": reasons[0] if reasons else None, "reasons": reasons}


REASON_TEXT = {
    "guardrail": "Device changes are switched off (guardrail device_changes; an administrator turns it on in Settings)",
    "not_capable": "This device's connection cannot make this change safely (it is read only, or its connector has no "
                   "write support, no rollback or no backup restore)",
    "op_not_supported": "This device's connection does not offer this kind of change",
    "connection_test": "The device's last connection test did not pass - test the connection first",
    "no_snapshot": "The device has not been read yet - refresh it first",
    "stale_snapshot": "The device's snapshot is older than the freshness limit - refresh it first",
    "change_in_flight": "Another change of this device is approved, scheduled or being applied",
}


def check_writable(state: dict[str, Any]) -> None:
    """ChangeRefused for the first reason a change is not possible now (S1, S2)."""
    reasons = state["reasons"]
    if not reasons:
        return
    first = "guardrail" if "guardrail" in reasons else reasons[0]
    text = REASON_TEXT.get(first, first)
    if first == "guardrail":
        raise ChangeRefused(403, "device_changes_disabled", text, reasons=reasons)
    if first in ("no_snapshot", "stale_snapshot"):
        raise ChangeRefused(409, "stale_snapshot", text, reasons=reasons)
    if first == "change_in_flight":
        raise ChangeRefused(409, "change_in_flight", text, reasons=reasons)
    raise ChangeRefused(403, "not_writable", text, reason=first, reasons=reasons)


# --------------------------------------------------------------------------------------
# planning: from a request to canonical ops, the diff, policy violations, impact (no device access)
# --------------------------------------------------------------------------------------


def _invalid(message: str) -> ChangeRefused:
    return ChangeRefused(422, "invalid", message)


def _zone(topology: segmentation.Topology, zone_id: str | None, side: str) -> dict[str, Any]:
    zone = topology.by_id.get(zone_id or "")
    if zone is None:
        raise _invalid(f"{side} is not a zone of this firewall")
    if zone["id"] == segmentation.INTERNET or not zone.get("subnets") or not zone.get("native_id"):
        raise _invalid(f"{side} must be a zone with networks: a change never opens 'any' (the Internet "
                       "pseudo-zone and zones without subnets cannot be used)")
    return zone


def _rule_of(record: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    for rule in record.get("rules") or []:
        if rule["id"] == ref.get("id") or (ref.get("vendor_ref") and rule.get("vendor_ref") == ref["vendor_ref"]):
            return rule
    return None


def names_device(record: dict[str, Any], endpoint: dict[str, Any]) -> bool:
    """S12: the endpoint names the device itself - "this firewall" or a network holding one of its addresses (an
    'any' destination is left to the connector's management-path guard and the connection check after applying)."""
    if endpoint.get("any") or endpoint.get("negate"):
        return False
    return targets_device(record, endpoint)


def lockout(record: dict[str, Any], ops: list[dict[str, Any]],
            action: str = "disabling it") -> tuple[list[str], list[str]]:
    """(problems, notes) of the hub's anti-lockout check (S12): disabling a pass rule addressed to the device itself
    ("this firewall", or one of its own addresses as a single host) is refused; a rule to a network that merely
    contains a device address is noted - the connector's guard knows the hub's address and management port.
    `action`: how the change turns the rule off, for the message."""
    problems, notes = [], []
    own = set(record.get("self_addresses") or [])
    aliases = {a["name"]: a for a in record.get("aliases") or []}
    for op in ops:
        if op["op"] != "disable_rules":
            continue
        for ref in op["rules"]:
            rule = _rule_of(record, ref)
            if rule is None or rule.get("action") != "pass":
                continue
            destination = rule.get("destination") or {}
            cidrs = [*(destination.get("cidrs") or []),
                     *(c for name in destination.get("aliases") or [] for c in (aliases.get(name) or {}).get("cidrs") or [])]
            hosts = {c.split("/")[0] for c in cidrs if c.endswith(("/32", "/128"))}
            if destination.get("self") or hosts & own:
                problems.append(f"rule {display_id(rule['id'])} lets traffic reach the device itself - {action} "
                                "could cut Atrium off from the device (anti-lockout)")
            elif names_device(record, destination):
                notes.append(f"rule {display_id(rule['id'])} reaches a network that holds one of the device's own "
                             "addresses: the device's connector checks that it does not carry Atrium's management path")
    return problems, notes


def restore_lockout(record: dict[str, Any], backup: dict[str, Any]) -> tuple[list[str], list[str]]:
    """S12 for a restore (review F21): the pass rules enabled now that the backup's configuration has disabled or
    lacks are what restoring it turns off - checked like disabling them."""
    def on(rule: dict[str, Any]) -> bool:
        return rule.get("enabled", True) and rule.get("action") == "pass"

    kept = [r for r in backup.get("rules") or [] if on(r)]
    lost = [{"id": r["id"], "vendor_ref": r.get("vendor_ref")} for r in record.get("rules") or [] if on(r)
            and not any(k["id"] == r["id"] or (r.get("vendor_ref") and k.get("vendor_ref") == r["vendor_ref"])
                        for k in kept)]
    if not lost:
        return [], []
    return lockout(record, [{"op": "disable_rules", "rules": lost}],
                   action="restoring a backup in which it is off or missing")


def _new_rule(record: dict[str, Any], op: dict[str, Any], index: int) -> dict[str, Any]:
    """The pass rule an allow op asks for, in the normalised shape (to evaluate the policy before it exists)."""
    vendor_zones = {z["id"] for z in record.get("zones") or []}
    src, dst = op["source"]["zone"], op["destination"]["zone"]
    zoned = src in vendor_zones
    return {"id": f"atrium-new-{index}", "vendor_ref": f"atrium-new-{index}", "order": 0, "enabled": True,
            "action": "pass", "direction": "in", "interfaces": [] if zoned else [src], "out_interfaces": [],
            "source_zones": [src] if zoned else [], "destination_zones": [dst] if dst in vendor_zones else [],
            "floating": False, "quick": True, "source": {"cidrs": op["source"]["cidrs"]},
            "destination": {"cidrs": op["destination"]["cidrs"]}, "services": op["services"], "log": op["log"],
            "description": f"{op['marker']} {op.get('description') or ''}".strip(), "marker": None}


def _added_rules(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The pass rules a change adds or enables (the ones that can open traffic)."""
    out = []
    for index, op in enumerate(ops):
        if op["op"] == "allow":
            out.append(_new_rule(record, op, index))
        elif op["op"] == "enable_rules":
            for ref in op["rules"]:
                rule = _rule_of(record, ref)
                if rule is not None:
                    out.append({**rule, "enabled": True})
    return out


def _edges(hub: "Hub", tool_id: str, record: dict[str, Any], rules: list[dict[str, Any]]) -> tuple[
        list[dict[str, Any]], dict[str, dict[str, Any]]]:
    """The edges (with their possible policy violations) that only `rules` produce on this firewall."""
    topology = segmentation.Topology(tool_id, {**record, "rules": rules}, segmentation.overrides(hub))
    zones = {z["id"]: z for z in topology.zones}
    edges = segmentation.aggregate(topology)
    policy_rules = segmentation.policy(hub)["rules"]
    for edge in edges:
        edge["violations"] = segmentation.evaluate_policy(edge, zones, policy_rules)
    return edges, zones


def violations_of(hub: "Hub", tool_id: str, record: dict[str, Any], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Possible segmentation-policy violations of the traffic `rules` may allow (roles and ids only)."""
    edges, zones = _edges(hub, tool_id, record, rules)
    out = []
    for edge in edges:
        for v in edge["violations"]:
            out.append({**v, "edge": edge["id"], "source": edge["source"], "target": edge["target"],
                        "from": zones[edge["source"]]["role"], "to": zones[edge["target"]]["role"]})
    return out


def impact(hub: "Hub", tool_id: str, record: dict[str, Any], zones: list[str]) -> dict[str, Any]:
    topology = segmentation.Topology(tool_id, record, segmentation.overrides(hub))
    manual = {d["id"]: d["zone_id"] for d in hub.store.list(segmentation.PLACEMENTS)}
    placed, _ = segmentation.place(topology, hub.all("assets", Asset), manual)
    return {"assets": sum(1 for a in placed if a["zone"] in zones), "zones": zones}


def _allow(hub: "Hub", request: dict[str, Any], change_id: str, record: dict[str, Any],
           topology: segmentation.Topology) -> dict[str, Any]:
    src = _zone(topology, request.get("source_zone"), "source_zone")
    dst = _zone(topology, request.get("target_zone"), "target_zone")
    if src["id"] == dst["id"]:
        raise _invalid("source_zone and target_zone are the same zone - traffic inside a zone does not cross the "
                       "firewall")
    if not request.get("services"):
        raise _invalid("name at least one service (a change never opens 'any')")
    try:
        ops = parse_ops([{"op": "allow", "source": {"zone": src["native_id"], "cidrs": src["subnets"]},
                          "destination": {"zone": dst["native_id"], "cidrs": dst["subnets"]},
                          "services": request["services"], "log": bool(request.get("log", True)),
                          "description": request.get("description") or "", "marker": marker(change_id)}])
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    op = ops[0]
    steps = [{"op": 0, "kind": "add_rule", "position": f"top of {src['name']} rules",
              "rule": {"action": "pass", "source": f"{src['name']} net", "destination": f"{dst['name']} net",
                       "service": service_text(op["services"]), "log": op["log"], "marker": op["marker"]}}]
    return {"ops": ops, "edge": f"zp:{src['id']}>{dst['id']}", "zones": [src["id"], dst["id"]], "steps": steps}


def _rule_ops(hub: "Hub", request: dict[str, Any], record: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    """Steps, edge and zones of disable_rules / enable_rules ops against the record (every rule must exist and be in
    the opposite state)."""
    names = interface_names(record)
    steps, touched = [], []
    for index, op in enumerate(ops):
        enable = op["op"] == "enable_rules"
        for ref in op["rules"]:
            rule = _rule_of(record, ref)
            if rule is None:
                raise _invalid(f"rule {display_id(ref['id'])} is not in the device's current rules - refresh first")
            if bool(rule.get("enabled", True)) == enable:
                raise _invalid(f"rule {display_id(ref['id'])} is already {'enabled' if enable else 'disabled'}")
            steps.append({"op": index, "kind": "enable_rule" if enable else "disable_rule", "position": "in place",
                          "rule": rule_line(rule, names)})
            touched.append({**rule, "enabled": True})
    edges, _ = _edges(hub, request["firewall"], record, touched)
    ids = [e["id"] for e in edges]
    zones = sorted({z for e in edges for z in (e["source"], e["target"])})
    edge = request.get("edge") if request.get("edge") in ids else (ids[0] if ids else None)
    return {"ops": ops, "edge": edge, "zones": zones, "steps": steps}


def _disable(hub: "Hub", request: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    tool_id = request["firewall"]
    refs: list[dict[str, str]] = []
    for raw in request.get("rule_ids") or []:
        native = raw[len(tool_id) + 1:] if raw.startswith(f"{tool_id}:") else raw
        rule = _rule_of(record, {"id": native})
        if rule is None:
            raise _invalid(f"rule {display_id(raw)} is not in the device's current rules - refresh first")
        if rule.get("action") != "pass":
            raise _invalid(f"rule {display_id(rule['id'])} is a {rule.get('action')} rule: only pass rules are disabled "
                           "(disabling a block rule would open traffic)")
        if {"id": rule["id"], "vendor_ref": rule["vendor_ref"]} not in refs:
            refs.append({"id": rule["id"], "vendor_ref": rule["vendor_ref"]})
    if not refs:
        raise _invalid("choose at least one rule to disable")
    try:
        ops = parse_ops([{"op": "disable_rules", "rules": refs}])
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    return _rule_ops(hub, request, record, ops)


def _restore(hub: "Hub", request: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    meta = network.get_backup(hub, str(request.get("backup_id") or ""))
    if meta is None or meta["tool_id"] != request["firewall"]:
        raise _invalid("the backup does not exist (or belongs to another device)")
    taken = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(meta["taken_at"]))
    steps = [{"op": None, "kind": "restore", "position": "whole configuration",
              "rule": f"restore backup {meta['id']} taken {taken} ({meta['reason']}, sha256 {meta['sha256'][:12]})"}]
    # the backup's rules can be shown when a stored snapshot has the backup's revision
    old = next((h for h in network.history(hub, request["firewall"])
                if meta.get("revision") and h.get("revision") == meta["revision"]), None)
    entry = network.history_entry(hub, request["firewall"], old["rev"]) if old else None
    if entry is not None:
        diff = "\n".join(difflib.unified_diff(record_lines(record), record_lines(entry["record"]),
                                              f"current {record.get('revision')}", f"backup {meta['id']}",
                                              lineterm=""))
        restored = [r for r in entry["record"].get("rules") or [] if r.get("enabled", True)
                    and r.get("action") == "pass"]
        current = {(v["edge"], v["policy"]) for v in violations_of(hub, request["firewall"], record, [
            r for r in record.get("rules") or [] if r.get("enabled", True) and r.get("action") == "pass"])}
        found = [v for v in violations_of(hub, request["firewall"], entry["record"], restored)
                 if (v["edge"], v["policy"]) not in current]
        notes = [f"the backup matches snapshot rev {entry['rev']}: its rules are compared with the current ones"]
        problems, lock_notes = restore_lockout(record, entry["record"])
        notes += lock_notes
        unknown = False
    else:
        diff = (f"--- current {record.get('revision')}\n+++ backup {meta['id']} (revision {meta.get('revision') or 'unknown'})"
                "\n! the device's whole configuration is replaced by the backup; no stored snapshot has its revision, "
                "so its rules are not compared here")
        # S11: what the backup allows cannot be checked against the segmentation policy - it may re-open forbidden
        # traffic, so it takes the forbidden path (an administrator, with a justification), never "no violation"
        found, unknown, problems = [], True, []
        notes = ["no stored snapshot has the backup's revision: its rules cannot be compared with the current ones or "
                 "checked against the segmentation policy, so only an administrator can propose it, with a "
                 f"justification of at least {FORBIDDEN_JUSTIFICATION} characters",
                 "the anti-lockout check cannot run either: if the backup turns off the rule that lets Atrium reach "
                 "the device, the restore cuts Atrium off and the device needs console access"]
    return {"ops": [], "edge": None, "zones": [], "steps": steps, "diff": diff, "violations": found, "notes": notes,
            "policy_unknown": unknown, "problems": problems,
            "backup": {k: meta.get(k) for k in ("id", "taken_at", "reason", "sha256", "size", "revision", "format")}}


def plan(hub: "Hub", request: dict[str, Any], change_id: str, record: dict[str, Any]) -> dict[str, Any]:
    """What a change will do against a device record: {"ops" (canonical), "edge", "zones", "steps", "diff",
    "violations", "impact", "notes", "problems" (S12 anti-lockout - refuse)}. ChangeRefused 422 "invalid" when the
    request cannot be built."""
    tool_id = request["firewall"]
    op = request["op"]
    topology = segmentation.Topology(tool_id, record, segmentation.overrides(hub))
    if op == "allow":
        out = _allow(hub, request, change_id, record, topology)
    elif op == "disable_rules":
        out = _disable(hub, request, record)
    elif op == "revert":
        try:
            ops = parse_ops(request.get("ops") or [])
        except ValueError as exc:
            raise _invalid(f"the inverse operations are not valid: {exc}") from exc
        out = _rule_ops(hub, request, record, ops)
    elif op == "restore":
        out = _restore(hub, request, record)
    else:
        raise _invalid(f"op is one of {', '.join(OPS)}")
    out.setdefault("notes", [])
    out.setdefault("policy_unknown", False)
    if op != "restore":
        out["diff"] = ops_diff(record, out["ops"])
        out["violations"] = violations_of(hub, tool_id, record, _added_rules(record, out["ops"]))
    problems, notes = lockout(record, out["ops"])
    out["problems"] = [*out.get("problems", []), *problems]
    out["notes"] = [*out["notes"], *notes]
    out["impact"] = impact(hub, tool_id, record, out["zones"])
    return out


def change_hash(hub: "Hub", op: str, ops: list[dict[str, Any]], request: dict[str, Any]) -> str:
    """What an approval binds to: ``ops_hash(ops)``, or for a restore the backup's id and SHA-256."""
    if op == "restore":
        meta = network.get_backup(hub, str(request.get("backup_id") or "")) or {}
        body = canonical_json({"op": "restore", "backup_id": meta.get("id"), "sha256": meta.get("sha256")})
        return "sha256:" + hashlib.sha256(body.encode()).hexdigest()
    return ops_hash(ops)


def justification_rules(violations: list[dict[str, Any]]) -> dict[str, Any]:
    forbidden = any(v["verdict"] == "forbidden" for v in violations)
    restricted = any(v["verdict"] == "restricted" for v in violations)
    return {"requires_justification": forbidden or restricted,
            "min_justification": FORBIDDEN_JUSTIFICATION if forbidden else RESTRICTED_JUSTIFICATION if restricted else 0,
            "submit_roles": ["admin"] if forbidden else ["operator", "admin"]}


def check_policy(violations: list[dict[str, Any]], role: str, justification: str | None,
                 unknown: bool = False) -> None:
    """S11: a forbidden violation only for administrators with a justification of 20+ characters; a restricted one
    needs a justification (10+) from anyone. `unknown`: the change cannot be checked against the policy (a restore
    whose backup no stored snapshot matches) - treated like a forbidden one."""
    controls = ", ".join(sorted({v.get("control") or v["policy"] for v in violations}))
    text = (justification or "").strip()
    if unknown and not any(v["verdict"] == "forbidden" for v in violations):
        if role != "admin":
            raise ChangeRefused(422, "policy_unknown", "This restore cannot be checked against the segmentation policy "
                                "(no stored snapshot has the backup's revision): only an administrator can propose it, "
                                "with a justification")
        if len(text) < FORBIDDEN_JUSTIFICATION:
            raise ChangeRefused(422, "justification_required", "This restore cannot be checked against the "
                                "segmentation policy: explain why in at least "
                                f"{FORBIDDEN_JUSTIFICATION} characters")
    if any(v["verdict"] == "forbidden" for v in violations):
        if role != "admin":
            raise ChangeRefused(422, "policy_forbidden", f"This change may violate the segmentation policy ({controls}): "
                                "only an administrator can propose it, with a justification", violations=violations)
        if len(text) < FORBIDDEN_JUSTIFICATION:
            raise ChangeRefused(422, "justification_required", f"This change may violate the segmentation policy "
                                f"({controls}): explain why in at least {FORBIDDEN_JUSTIFICATION} characters",
                                violations=violations)
    elif any(v["verdict"] == "restricted" for v in violations) and len(text) < RESTRICTED_JUSTIFICATION:
        raise ChangeRefused(422, "justification_required", f"This change touches a restricted zone pair ({controls}): "
                            f"explain why in at least {RESTRICTED_JUSTIFICATION} characters", violations=violations)


def needed_kinds(op: str, ops: list[dict[str, Any]]) -> list[str]:
    if op in ("allow", "disable_rules"):
        return [op]
    return sorted({o["op"] for o in ops})


def preview(hub: "Hub", request: ChangeRequest, role: str, now: float | None = None) -> dict[str, Any]:
    """POST /api/segmentation/changes/preview: what a change would do against the stored snapshot. No side effects:
    the device is not contacted (the proposal re-reads it and asks its connector to check the change)."""
    now = time.time() if now is None else now
    data = request.model_dump(mode="json")
    tool_id = request.firewall
    if tool_id not in network.device_ids(hub):
        raise ChangeRefused(404, "not_found", "Network device not found")
    snap = network.snapshot(hub, tool_id)
    if snap is None:
        raise ChangeRefused(409, "stale_snapshot", REASON_TEXT["no_snapshot"])
    result = plan(hub, data, "preview", snap["record"])
    state = write_state(hub, tool_id, request.op, needed_kinds(request.op, result["ops"]), now)
    rules = justification_rules(result["violations"])
    if role not in rules["submit_roles"]:
        state = {**state, "writable": False, "reason": state["reason"] or "policy_forbidden"}
    window = maintenance.active(hub, tool_id, now)
    return {
        "firewall": tool_id, "op": request.op, "writable": state["writable"], "reason": state["reason"],
        "reasons": state["reasons"], "base_revision": snap["record"].get("revision"),
        "snapshot": {"rev": snap["rev"], "read_at": snap["read_at"], "age_s": round(now - (snap["read_at"] or now)),
                     "stale": network.stale(hub, snap, now)},
        "ops": result["ops"], "ops_hash": ops_hash(result["ops"]) if result["ops"] else None,
        "steps": result["steps"], "diff": result["diff"], "edge": result["edge"], "violations": result["violations"],
        **rules, "impact": result["impact"], "notes": result["notes"], "problems": result["problems"],
        "rollback": state["rollback"], "expires_in_hours": expiry_hours(hub),
        "maintenance": maintenance_info(hub, tool_id, now, window),
    }


def maintenance_info(hub: "Hub", tool_id: str, now: float, window: dict[str, Any] | None = None,
                     expires_at: float | None = None) -> dict[str, Any]:
    """When a change would be applied: {"required" (the window guardrail), "open" (a window open now), "next" (the
    next one), "expires_at" (the approval's expiry: `expires_at`, else a proposal made now), "expires_before_window"
    (the next window opens only after the approval expired - it could only be applied as an emergency)}."""
    required = bool(guardrails.value(hub, WINDOW_GUARD))
    window = window if window is not None else maintenance.active(hub, tool_id, now)
    upcoming = None if window else maintenance.next_start(hub, tool_id, now)
    expires = float(expires_at) if expires_at is not None else now + expiry_hours(hub) * 3600
    return {"required": required, "open": window, "next": upcoming, "expires_at": expires,
            "expires_before_window": bool(required and upcoming and upcoming["start"] >= expires)}


def revert_request(hub: "Hub", original: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    """The request of a revert proposal (S10): the inverse of an applied change. An allow's rule is found by what
    apply_change reported or, failing that, by its marker in the current record. A restore is reverted by restoring
    the backup taken before it."""
    if original.get("status") != "applied":
        raise ChangeRefused(409, "not_applied", "Only an applied change can be reverted")
    if original.get("reverted_by"):
        raise ChangeRefused(409, "already_reverted", f"This change was already reverted by {original['reverted_by']}")
    base = {"firewall": original["firewall"], "revert_of": original["id"]}
    if original["op"] == "restore":
        if not original.get("backup_id"):
            raise ChangeRefused(409, "no_backup", "No backup was taken before this restore, so it cannot be reverted")
        return {**base, "op": "restore", "backup_id": original["backup_id"]}
    applied = dict(original.get("applied") or {})
    created = list(applied.get("created") or [])
    for index, op in enumerate(original["ops"]):
        if op["op"] == "allow" and not any(c.get("op") == index for c in created):
            found = [r for r in record.get("rules") or [] if r.get("marker") == original["id"]]
            created += [{"op": index, "id": r["id"], "vendor_ref": r["vendor_ref"]} for r in found[:1]]
    try:
        from ..connectors.netmodel import inverse_ops

        ops = inverse_ops(original["ops"], {**applied, "created": created})
    except ValueError as exc:
        raise ChangeRefused(409, "rule_not_found", f"The rule this change created is no longer on the device: {exc}") from exc
    return {**base, "op": "revert", "ops": ops}


# --------------------------------------------------------------------------------------
# creating a proposal (after the Network Supervisor's fresh read and the connector's check)
# --------------------------------------------------------------------------------------


def create(hub: "Hub", *, change_id: str, request: dict[str, Any], record: dict[str, Any], planned: dict[str, Any],
           actor: str, rollback: dict[str, Any] | None, device: dict[str, Any] | None = None) -> dict[str, Any]:
    """Store the proposal and its approval (kind firewall, requested by module:network, payload bound to the revision
    and the ops' hash). Returns the change."""
    from ..connectors.netmodel import record_hash

    now = time.time()
    tool_id = request["firewall"]
    op = request["op"]
    digest = change_hash(hub, op, planned["ops"], request)
    expires_at = now + expiry_hours(hub) * 3600
    device = device or {}
    change = {
        "id": change_id, "firewall": tool_id, "op": op, "request": request, "ops": planned["ops"], "ops_hash": digest,
        "base_revision": record.get("revision"), "base_hash": record_hash(record), "edge": planned["edge"],
        "zones": planned["zones"],
        "preview": {"steps": planned["steps"], "diff": planned["diff"], "violations": planned["violations"],
                    "impact": planned["impact"], "notes": planned["notes"], "problems": planned["problems"],
                    "device_steps": device.get("steps") or [], "device_notes": device.get("notes") or [],
                    "rollback": rollback, "backup": planned.get("backup"),
                    "policy_unknown": bool(planned.get("policy_unknown")),
                    "maintenance": maintenance_info(hub, tool_id, now, expires_at=expires_at)},
        "status": "proposed", "approval_id": None, "proposed_by": actor,
        "justification": (request.get("justification") or "").strip() or None,
        "created_at": now, "updated_at": now, "expires_at": expires_at, "decided_by": None, "decided_at": None,
        "scheduled_for": None, "window": None, "expires_before_window": False, "emergency": None, "backup_id": None,
        "rollback": rollback,
        "rollback_until": None, "applied": None, "verification": [], "result": None, "applied_at": None,
        "finished_at": None, "revert_of": request.get("revert_of"), "reverted_by": None,
        "history": [{"at": now, "status": "proposed", "actor": actor, "note": None}],
    }
    name = tool_name(hub, tool_id)
    title = f"Device change on {name}: {summary(change)}"
    detail = (f"Proposed by {actor}. {len(planned['ops']) or 1} operation(s) on {name}; "
              + (f"rollback: {rollback['mode']} within {rollback['window_s']} s; " if rollback else "")
              + ("an encrypted configuration backup is taken first; " if guardrails.value(hub, BACKUP_GUARD) else "")
              + ("applied in the next maintenance window; " if guardrails.value(hub, WINDOW_GUARD) else "")
              + f"the approval expires {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(expires_at))}.")
    payload = {"change_id": change_id, "firewall": tool_id, "op": op, "diff": planned["diff"],
               "violations": planned["violations"], "base_revision": change["base_revision"], "ops_hash": digest,
               "proposed_by": actor, "justification": change["justification"], "expires_at": expires_at,
               "steps": planned["steps"], "impact": planned["impact"], "rollback": rollback, "edge": planned["edge"],
               "revert_of": change["revert_of"], "backup_id": request.get("backup_id"),
               "policy_unknown": change["preview"]["policy_unknown"], "maintenance": change["preview"]["maintenance"]}
    hub.store.put(CHANGES, change)  # before the approval exists: its guard looks the change up
    approval = hub.approvals.create("firewall", title, detail, payload, "module:network")
    change["approval_id"] = approval.id
    save(hub, change)
    hub.activity(actor, "info", f"Proposed device change {change_id} on {name}: {summary(change)}", change_id=change_id,
                 tool_id=tool_id, approval_id=approval.id)
    return change


# --------------------------------------------------------------------------------------
# binding checks (S6-S8): used by the Network Supervisor before each step and again by the tool supervisor
# --------------------------------------------------------------------------------------


def _role(hub: "Hub", actor: str | None) -> str | None:
    text = str(actor or "")
    if text.startswith("token:"):
        token = next((t for t in hub.auth.tokens() if t.name == text[6:]), None)
        return token.role if token else None
    user = hub.auth.find_user(text.removeprefix("user:")) if text else None
    return user.role if user and not getattr(user, "disabled", False) else None


def principal_role(hub: "Hub", sender: str) -> str | None:
    """The role of the person (or API token) behind a bus sender; None for agents."""
    if sender.startswith(("user:", "token:")):
        return _role(hub, sender)
    return None


def binding_problem(hub: "Hub", change: dict[str, Any], now: float | None = None, *, guardrail: bool = True,
                    expiry: bool = True) -> tuple[str, str] | None:
    """(status to give the change, reason) when it may not go on: its approval is missing, not approved, bound to
    something else, decided against the second-person rule, expired (`expiry`), or device changes are off
    (`guardrail`). None when everything holds."""
    from ..approvals import identities

    now = time.time() if now is None else now
    approval: Approval | None = hub.approvals.get(change.get("approval_id") or "")
    if approval is None or approval.kind != "firewall":
        return "blocked", "its approval is missing"
    if approval.status not in ("approved", "done"):
        return "blocked", f"its approval is {approval.status}"
    payload = approval.payload
    if payload.get("change_id") != change["id"] or payload.get("firewall") != change["firewall"]:
        return "blocked", "the approval belongs to another change"
    if payload.get("ops_hash") != change["ops_hash"] or \
            change_hash(hub, change["op"], change["ops"], change.get("request") or {}) != change["ops_hash"]:
        return "blocked", "the operations differ from what was approved"
    if payload.get("base_revision") != change.get("base_revision"):
        return "blocked", "the approval was given for another device revision"
    if str(approval.decided_by or "").startswith("token:"):  # S4/S5: a person decides, on the Approvals page
        return "blocked", "the approval was given with an API token, not by a person"
    if _role(hub, approval.decided_by) != "admin":  # S4: only administrators decide device changes
        return "blocked", "the approval does not come from an administrator"
    if guardrails.value(hub, SECOND_PERSON):
        # the proposer as recorded with the approval and as resolved now (an API token counts as its creator)
        proposers = hub.approvals.proposers(approval) | identities(hub, change.get("proposed_by"))
        if not proposers or proposers & identities(hub, approval.decided_by):
            return "blocked", "the approval does not come from a second person"
    if expiry and now > float(change.get("expires_at") or 0):
        return "expired", "the approval expired"
    if guardrail and not guardrails.value(hub, "device_changes"):
        return "blocked", "device changes are switched off (guardrail device_changes)"
    return None


def authorize(hub: "Hub", change: dict[str, Any] | None, stage: str, backup_id: str | None = None) -> str | None:
    """Why the tool supervisor must refuse a device call for this change (None: go ahead). Stages: "apply" (rule
    ops), "restore" (an approved restore change), "confirm", "rollback", "recover" (restore the change's own
    pre-change backup after a failed rollback)."""
    if change is None:
        return "unknown change"
    status = change.get("status")
    if stage in ("apply", "restore"):
        if status != "applying":
            return f"the change is {status}, not applying"
        if (stage == "restore") != (change["op"] == "restore"):
            return "wrong operation for this change"
        problem = binding_problem(hub, change)
        return problem[1] if problem else None
    if stage == "confirm":
        if status != "verifying":
            return f"the change is {status}, not verifying"
        problem = binding_problem(hub, change, guardrail=False, expiry=False)  # S14: verifying completes as usual
        return problem[1] if problem else None
    if stage == "rollback":
        return None if status in ACTIVE else f"the change is {status}"
    if stage == "recover":
        if status not in ACTIVE:
            return f"the change is {status}"
        if not backup_id or backup_id != change.get("backup_id"):
            return "only the backup taken before this change can be restored here"
        return None
    return f"unknown stage {stage}"


# --------------------------------------------------------------------------------------
# ending a change, the sweeps, withdrawing, emergencies
# --------------------------------------------------------------------------------------


def finish(hub: "Hub", change: dict[str, Any], status: str, actor: str = "module:network", note: str | None = None,
           result: dict[str, Any] | None = None, level: str | None = None) -> dict[str, Any]:
    """Give a change its final status, settle its approval, log it."""
    if result is not None:
        change["result"] = result
    save(hub, change, status, actor, note)
    approval = hub.approvals.get(change.get("approval_id") or "")
    if approval is not None:
        if approval.status == "pending":
            hub.approvals.withdraw(approval.id, f"Device change {status}" + (f": {note}" if note else ""), actor,
                                   verb=status.replace("_", " ").capitalize())
        elif approval.status == "approved":
            hub.approvals.complete(approval.id, status == "applied", {"status": status, "note": note,
                                                                      **(result or {})})
    name = tool_name(hub, change["firewall"])
    words = {"applied": "applied", "rolled_back": "rolled back", "failed": "failed", "stale": "not applied (stale)",
             "blocked": "blocked", "expired": "expired", "withdrawn": "withdrawn", "rejected": "rejected"}
    level = level or ("info" if status in ("applied", "withdrawn", "rejected", "expired") else
                      "error" if status == "failed" else "warn")
    hub.activity(actor, level, f"Device change {change['id']} on {name} {words.get(status, status)}: {summary(change)}"
                 + (f" - {note}" if note else ""), change_id=change["id"], tool_id=change["firewall"])
    return change


def kill_switch(hub: "Hub", actor: str) -> list[str]:
    """S14: device changes were switched off - approved and scheduled changes are blocked (never applied)."""
    blocked = []
    for change in listing(hub):
        if change.get("status") in DECIDED:
            finish(hub, change, "blocked", actor, "device changes were switched off (guardrail device_changes)")
            blocked.append(change["id"])
    return blocked


def expire(hub: "Hub", now: float | None = None) -> list[str]:
    """S7: proposals whose approval expired (and approved changes not applied in time) become expired."""
    now = time.time() if now is None else now
    out = []
    for change in listing(hub):
        if change.get("status") in WAITING and now > float(change.get("expires_at") or 0):
            finish(hub, change, "expired", "module:network",
                   f"not applied within {expiry_hours(hub)} h of the proposal - propose it again")
            out.append(change["id"])
    return out


def withdraw(hub: "Hub", change_id: str, actor: str, role: str) -> dict[str, Any]:
    """The proposer (or an administrator) withdraws a change that has not touched the device yet."""
    from ..approvals import identities

    change = get(hub, change_id)
    if change is None:
        raise ChangeRefused(404, "not_found", "Change not found")
    if role != "admin" and not identities(hub, actor) & identities(hub, change.get("proposed_by")):
        raise ChangeRefused(403, "not_proposer", "Only the person who proposed a change (or an administrator) can "
                                                 "withdraw it")
    if change["status"] not in WAITING:
        raise ChangeRefused(409, "not_withdrawable", f"The change is {change['status']}: only a proposed, approved or "
                                                     "scheduled change can be withdrawn")
    return finish(hub, change, "withdrawn", actor, f"withdrawn by {actor}")


def mark_emergency(hub: "Hub", change_id: str, actor: str, justification: str) -> dict[str, Any]:
    """An administrator applies an approved change now, outside the maintenance windows (logged; counted as an
    exception by the network change-management control)."""
    change = get(hub, change_id)
    if change is None:
        raise ChangeRefused(404, "not_found", "Change not found")
    if change["status"] not in DECIDED:
        raise ChangeRefused(409, "not_approved", f"The change is {change['status']}: only an approved or scheduled "
                                                 "change can be applied as an emergency")
    text = " ".join((justification or "").split())
    if len(text) < EMERGENCY_JUSTIFICATION:
        raise ChangeRefused(422, "justification_required", f"Explain the emergency in at least "
                                                           f"{EMERGENCY_JUSTIFICATION} characters")
    problem = binding_problem(hub, change)
    if problem:
        raise ChangeRefused(409, problem[0], f"The change cannot be applied: {problem[1]}")
    change["emergency"] = {"by": actor, "at": time.time(), "justification": text[:2000]}
    save(hub, change, actor=actor)
    hub.activity(actor, "warn", f"Emergency: device change {change_id} on {tool_name(hub, change['firewall'])} is "
                                "applied now, outside the maintenance windows", change_id=change_id,
                 tool_id=change["firewall"])
    return change


# --------------------------------------------------------------------------------------
# compliance facts for HB-CM-3 (ids and counts only)
# --------------------------------------------------------------------------------------


def decided_by_proposer(hub: "Hub", change: dict[str, Any], approval: "Approval | None" = None) -> bool:
    """Whether the change was approved by (an identity of) the person who proposed it - possible only while
    ``device_changes_need_second_person`` was off. Recorded on the change when it is approved (``self_approved``),
    so HB-CM-3 still shows it after the guardrail is switched on again."""
    from ..approvals import identities

    approval = approval or hub.approvals.get(change.get("approval_id") or "")
    decider = (approval.decided_by if approval else None) or change.get("decided_by")
    if not decider:
        return False
    proposers = identities(hub, change.get("proposed_by")) | (hub.approvals.proposers(approval) if approval else set())
    return bool(proposers & identities(hub, decider))


def reached_device(change: dict[str, Any]) -> bool:
    """The change was carried out on the device (whatever the outcome), not refused before anything was written. A
    change still applying is left out: its backup is taken in that state."""
    status = change.get("status")
    if status in ("verifying", "applied", "rolled_back"):
        return True
    return status == "failed" and (change.get("result") or {}).get("state") not in (None, "unchanged")


def compliance_facts(hub: "Hub", now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    since = now - 90 * 86400
    recent = [c for c in hub.store.list(CHANGES) if (c.get("finished_at") or c.get("updated_at") or 0) >= since]
    unknown = [c for c in recent if c.get("status") == "failed" and (c.get("result") or {}).get("state") in
               ("unknown", "applied")]
    carried_out = [c for c in recent if reached_device(c)]
    return {
        # exceptions to the second-person and backup guardrails, whatever they are set to now: a change its own
        # proposer approved, and one written to the device without a configuration backup first
        "self_approved_90d": sorted(display_id(c["id"]) for c in carried_out
                                    if (c["self_approved"] if "self_approved" in c else decided_by_proposer(hub, c))),
        "unbacked_90d": sorted(display_id(c["id"]) for c in carried_out if not c.get("backup_id")),
        "device_changes": bool(guardrails.value(hub, "device_changes")),
        "applied_90d": sum(1 for c in recent if c.get("status") == "applied"),
        "rolled_back_90d": sum(1 for c in recent if c.get("status") == "rolled_back"),
        "failed_90d": sum(1 for c in recent if c.get("status") == "failed"),
        "unknown_state": sorted(display_id(c["id"]) for c in unknown),
        "emergency_90d": sorted(display_id(c["id"]) for c in recent if c.get("emergency")
                                and c.get("status") in ("applied", "rolled_back", "failed", "verifying")),
        "open": sum(1 for c in hub.store.list(CHANGES) if c.get("status") in (*WAITING, *ACTIVE)),
    }


def check_decision(hub: "Hub", approval: "Approval", approve: bool) -> None:
    """Approvals guard for kind firewall: only a change that is still a proposal can be decided."""
    change = get(hub, str(approval.payload.get("change_id") or ""))
    if change is None:
        raise ValueError("The device change no longer exists")
    if change["status"] != "proposed":
        raise ValueError(f"The device change is {change['status']}")


def applied_summary(result: dict[str, Any]) -> dict[str, Any]:
    """What a connector's apply_change returned, without its token and with device text reduced to ids and text."""
    from ..connectors.netmodel import device_id_text

    created = []
    for item in list(result.get("created") or [])[:50]:
        if isinstance(item, dict) and item.get("id") not in (None, "") and isinstance(item.get("op"), int):
            created.append({"op": item["op"], "id": device_id_text(item["id"]),
                            "vendor_ref": device_id_text(item.get("vendor_ref") or item["id"], 300)})
    until = result.get("rollback_until")
    return {"rollback_until": float(until) if isinstance(until, (int, float)) and not isinstance(until, bool) else None,
            "revision": device_id_text(result.get("revision"))[:200] or None, "created": created,
            "disabled": [device_id_text(x, 300) for x in list(result.get("disabled") or [])[:100]],
            "enabled": [device_id_text(x, 300) for x in list(result.get("enabled") or [])[:100]],
            "notes": device_text(result.get("notes"))}


def reverted(change: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Problems showing that a re-read still holds part of the change (empty: it is undone). An allow's rule (found by
    its marker) must be gone or disabled, rules it disabled enabled again (and the other way round); a restore must
    have brought back exactly the configuration read before it (``base_hash``)."""
    from ..connectors.netmodel import record_hash

    if change["op"] == "restore":
        return [] if record_hash(after) == change.get("base_hash") else ["the configuration differs from before"]
    problems = []
    for op in change["ops"]:
        if op["op"] == "allow":
            if any(r.get("marker") == change["id"] and r.get("enabled", True) for r in after.get("rules") or []):
                problems.append(f"the rule marked {op['marker']} is still active")
            continue
        was_enabled = op["op"] == "disable_rules"
        for ref in op["rules"]:
            rule = _rule_of(after, ref)
            if rule is None or bool(rule.get("enabled", True)) != was_enabled:
                problems.append(f"rule {display_id(ref['id'])} is not back to its previous state")
    return problems


def device_text(values: Any, limit: int = 20) -> list[str]:
    """Connector-provided strings (steps, notes, problems) made safe to store and show as text."""
    out = []
    for value in list(values or [])[:limit]:
        if isinstance(value, dict):
            value = " ".join(f"{k}: {v}" for k, v in value.items() if k in ("kind", "position", "detail"))
        out.append(untrusted_text(value, 300))
    return out


def new_change_id() -> str:
    return new_id("chg_")
