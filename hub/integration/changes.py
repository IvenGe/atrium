"""Guarded network changes (canvas-design 6.6 / 7.7, review-notes F1-F4).

A change is a proposal. Applying it is a later step that only the Network Supervisor takes, and only after an
approval bound to the device revision and the operations hash. Rollback of an applied change is a new proposal.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING, Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .. import guardrails
from ..connectors.netmodel import management_guard, marker, ops_hash, parse_ops
from ..store import new_id
from . import network, segmentation

if TYPE_CHECKING:
    from ..core import Hub

CHANGES = "firewall_changes"
WINDOWS = "maintenance_windows"
STATUSES = ("proposed", "approved", "scheduled", "applying", "verifying", "applied", "rejected", "withdrawn",
            "expired", "stale", "blocked", "failed", "rolled_back")


class ChangeError(Exception):
    def __init__(self, message: str, code: str = "invalid", status: int = 422):
        super().__init__(message)
        self.message, self.code, self.status = message, code, status

    def body(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message}


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def expiry_seconds(hub: "Hub") -> float:
    return int(guardrails.value(hub, "approval_expiry_hours")) * 3600


def list_changes(hub: "Hub", status: str | None = None, firewall: str | None = None) -> list[dict[str, Any]]:
    items = hub.store.list(CHANGES)
    if status:
        items = [c for c in items if c.get("status") == status]
    if firewall:
        items = [c for c in items if c.get("firewall") == firewall]
    return [public(c) for c in sorted(items, key=lambda c: -c.get("created_at", 0))]


def get(hub: "Hub", change_id: str) -> dict[str, Any] | None:
    return hub.store.get(CHANGES, change_id)


def save(hub: "Hub", change: dict[str, Any]) -> dict[str, Any]:
    hub.store.put(CHANGES, change)
    hub.bus.publish("firewall_change", public(change))
    return change


def public(change: dict[str, Any]) -> dict[str, Any]:
    hidden = {"token", "ops"}
    return {k: v for k, v in change.items() if k not in hidden}


def _zone(hub: "Hub", firewall: str, zid: str) -> dict[str, Any]:
    snap = network.snapshot(hub, firewall)
    if snap is None:
        raise ChangeError("This device has no snapshot. Refresh it first.", "stale_snapshot", 409)
    topology = segmentation.topologies(hub).get(firewall)
    if topology is None or zid not in topology.by_id or zid == segmentation.INTERNET:
        raise ChangeError(f"Unknown zone '{zid}' on this device", "invalid", 422)
    zone = topology.by_id[zid]
    cidrs = [c for c in zone["subnets"] if c not in ("0.0.0.0/0", "::/0")]
    if not cidrs or not zone.get("native_id"):
        raise ChangeError(f"{zone['name']} has no networks Atrium can name in a rule", "invalid", 422)
    return zone


def build_ops(hub: "Hub", body: dict[str, Any], change_id: str) -> list[dict[str, Any]]:
    """Canonical ops for an allow or disable_rules request. The marker is atrium:<change id>."""
    firewall = str(body.get("firewall") or "")
    op = str(body.get("op") or "")
    if op == "allow":
        source = _zone(hub, firewall, str(body.get("source_zone") or ""))
        dest = _zone(hub, firewall, str(body.get("target_zone") or ""))
        if source["id"] == dest["id"]:
            raise ChangeError("The source and destination zones are the same", "invalid", 422)
        services = body.get("services") or []
        if not isinstance(services, list) or not 1 <= len(services) <= 16:
            raise ChangeError("Name 1 to 16 services. A change never opens every port.", "invalid", 422)
        raw = [{"op": "allow", "source": {"zone": source["native_id"], "cidrs": source["subnets"]},
                "destination": {"zone": dest["native_id"], "cidrs": dest["subnets"]},
                "services": services, "log": bool(body.get("log", True)),
                "description": str(body.get("description") or "")[:120], "marker": marker(change_id)}]
    elif op == "disable_rules":
        ids = body.get("rule_ids") or []
        snap = network.snapshot(hub, firewall)
        rules = {r["id"]: r for r in ((snap or {}).get("record") or {}).get("rules") or []}
        refs = []
        for rule_id in ids:
            rule = rules.get(str(rule_id))
            if rule is None:
                raise ChangeError(f"Unknown rule '{rule_id}'", "invalid", 422)
            refs.append({"id": rule["id"], "vendor_ref": rule.get("vendor_ref") or rule["id"]})
        if not refs:
            raise ChangeError("Select at least one rule to disable", "invalid", 422)
        raw = [{"op": "disable_rules", "rules": refs}]
    else:
        raise ChangeError("op is allow or disable_rules", "invalid", 422)
    try:
        return parse_ops(raw)
    except ValueError as exc:
        raise ChangeError(str(exc), "invalid", 422) from exc


def _violations(hub: "Hub", firewall: str, body: dict[str, Any]) -> list[dict[str, Any]]:
    if body.get("op") != "allow":
        return []
    tops = segmentation.topologies(hub)
    topology = tops.get(firewall)
    if topology is None:
        return []
    zones = topology.by_id
    edge = {"source": body.get("source_zone"), "target": body.get("target_zone"), "services": body.get("services") or [],
            "any_service": False, "rules": [], "notes": []}
    return segmentation.evaluate_policy(edge, zones, segmentation.policy(hub)["rules"])


def _justification_needed(violations: list[dict[str, Any]]) -> bool:
    return any(v.get("verdict") in ("forbidden", "restricted") for v in violations)


def preview_view(hub: "Hub", body: dict[str, Any], change_id: str, ops: list[dict[str, Any]],
                 device_preview: dict[str, Any] | None, role: str) -> dict[str, Any]:
    firewall = str(body["firewall"])
    status = network.write_status(hub, firewall)
    snap = network.snapshot(hub, firewall) or {}
    violations = _violations(hub, firewall, body)
    problems = list((device_preview or {}).get("problems") or [])
    problems += management_guard(snap.get("record") or {}, ops)
    forbidden = any(v.get("verdict") == "forbidden" for v in violations)
    if role != "admin" and forbidden:
        submit = []
    elif _justification_needed(violations):
        submit = ["admin"] if forbidden else ["operator", "admin"]
    else:
        submit = ["operator", "admin"] if status["writable"] and not problems else []
    spec = status["rollback"]
    return {
        "writable": bool(status["writable"] and not problems),
        "reason": "invalid" if problems else status["reason"],
        "problems": problems,
        "base_revision": (snap.get("record") or {}).get("revision"),
        "ops_hash": ops_hash(ops),
        "ops": (device_preview or {}).get("steps") or [],
        "ops_canonical": ops,
        "diff": "\n".join((device_preview or {}).get("notes") or []) or _diff_hint(ops),
        "violations": violations,
        "requires_justification": _justification_needed(violations),
        "submit_roles": submit,
        "impact": {"zones": [body.get("source_zone"), body.get("target_zone")]},
        "rollback": spec,
    }


def _diff_hint(ops: list[dict[str, Any]]) -> str:
    lines = []
    for op in ops:
        if op["op"] == "allow":
            ports = ", ".join(f"{s['proto']}/{s.get('ports') or ''}".rstrip("/") for s in op["services"])
            lines.append(f"+ pass from {op['source']['zone']} to {op['destination']['zone']} {ports}")
        else:
            lines.append("- disable " + ", ".join(r["id"] for r in op["rules"]))
    return "\n".join(lines)


def check_submit(hub: "Hub", body: dict[str, Any], preview: dict[str, Any], role: str) -> None:
    status = network.write_status(hub, str(body["firewall"]))
    if "guardrail" in status["reasons"]:
        raise ChangeError("Device changes are off.", "device_changes_disabled", 403)
    if not status["writable"]:
        raise ChangeError(f"This device is not writable ({status['reason']}).", "not_writable", 403)
    if preview["problems"]:
        raise ChangeError("; ".join(preview["problems"]), "invalid", 422)
    text = str(body.get("justification") or "").strip()
    forbidden = any(v.get("verdict") == "forbidden" for v in preview["violations"])
    if forbidden and role != "admin":
        raise ChangeError("This change violates the segmentation policy.", "policy_forbidden", 422)
    if forbidden and len(text) < 20:
        raise ChangeError("An administrator override needs a justification of at least 20 characters.",
                          "justification_required", 422)
    if preview["requires_justification"] and len(text) < 20:
        raise ChangeError("This change needs a justification of at least 20 characters.", "justification_required", 422)


def propose(hub: "Hub", body: dict[str, Any], preview: dict[str, Any], actor: str) -> dict[str, Any]:
    """Store a proposed change and its approval. The approval is requested by module:network; proposed_by is the person."""
    change_id = str(body["change_id"])
    firewall = str(body["firewall"])
    title = f"Network change on {network._name(hub, firewall)}: {body.get('op')}"
    approval = hub.approvals.create(
        "firewall", title, str(preview.get("diff") or title),
        {"change_id": change_id, "firewall": firewall, "op": body.get("op"), "diff": preview.get("diff"),
         "violations": preview.get("violations") or [], "base_revision": preview.get("base_revision"),
         "ops_hash": preview.get("ops_hash"), "proposed_by": actor,
         "justification": str(body.get("justification") or "")[:2000]},
        "module:network")
    change = {
        "id": change_id, "firewall": firewall, "op": body.get("op"), "request": _request(body), "preview": preview,
        "ops": preview.get("ops_canonical") or [], "base_revision": preview.get("base_revision"),
        "ops_hash": preview.get("ops_hash"), "status": "proposed", "approval_id": approval.id, "proposed_by": actor,
        "justification": str(body.get("justification") or "")[:2000], "created_at": time.time(),
        "decided_at": None, "applied_at": None, "rollback_until": None, "result": None, "revert_of": body.get("revert_of"),
        "emergency": False, "backup_id": None, "token": None,
    }
    save(hub, change)
    hub.activity(actor, "warn", f"Proposed a network change on {network._name(hub, firewall)}", tool_id=firewall,
                 change_id=change_id, approval_id=approval.id)
    return {"change": public(change), "approval_id": approval.id}


def _request(body: dict[str, Any]) -> dict[str, Any]:
    keep = ("firewall", "op", "source_zone", "target_zone", "services", "log", "description", "rule_ids",
            "justification", "backup_id")
    return {k: body.get(k) for k in keep if k in body}


def withdraw(hub: "Hub", change_id: str, actor: str, role: str) -> dict[str, Any]:
    change = get(hub, change_id)
    if change is None:
        raise ChangeError("Unknown change", "invalid", 404)
    if change["status"] != "proposed":
        raise ChangeError(f"A {change['status']} change cannot be withdrawn", "invalid", 409)
    if actor != change["proposed_by"] and role != "admin":
        raise ChangeError("Only the proposer or an administrator can withdraw this change", "invalid", 403)
    change["status"] = "withdrawn"
    save(hub, change)
    if change.get("approval_id"):
        hub.approvals.withdraw(change["approval_id"], "Withdrawn by " + actor, actor)
    hub.activity(actor, "info", "Withdrew a network change", tool_id=change["firewall"], change_id=change_id)
    return public(change)


def same_person_blocked(hub: "Hub", kind: str, payload: dict[str, Any], requested_by: str, actor: str) -> str | None:
    """403 code when this person must not decide the approval, else None."""
    proposer = str(payload.get("proposed_by") or requested_by)
    if actor != proposer:
        return None
    if kind == "firewall" and guardrails.value(hub, "device_changes_need_second_person"):
        return "same_person"
    if kind != "firewall" and guardrails.value(hub, "approvals_need_second_person"):
        if kind == "self_patch" or payload.get("proposed_by"):
            return "same_person"
    return None


def approval_expired(hub: "Hub", approval, now: float | None = None) -> bool:
    if approval.kind not in ("firewall", "self_patch"):
        return False
    return _now(now) > approval.created_at + expiry_seconds(hub)


def block_unapproved(hub: "Hub", actor: str) -> list[str]:
    """Kill switch (S14): approved and scheduled changes are not applied once device changes are turned off."""
    blocked = []
    for change in hub.store.list(CHANGES):
        if change.get("status") in ("approved", "scheduled"):
            change["status"] = "blocked"
            change["result"] = {"reason": "device_changes off"}
            save(hub, change)
            blocked.append(change["id"])
            hub.activity(actor, "warn", "Blocked a network change because device changes were turned off",
                         tool_id=change.get("firewall"), change_id=change["id"])
    return blocked


# -- maintenance windows -----------------------------------------------------------------------------


def list_windows(hub: "Hub") -> list[dict[str, Any]]:
    return sorted(hub.store.list(WINDOWS), key=lambda w: w.get("name") or "")


def save_window(hub: "Hub", body: dict[str, Any], actor: str, window_id: str | None = None) -> dict[str, Any]:
    try:
        ZoneInfo(str(body.get("timezone") or "UTC"))
    except ZoneInfoNotFoundError as exc:
        raise ChangeError(f"Unknown timezone '{body.get('timezone')}'", "invalid", 422) from exc
    kind = body.get("kind") or "weekly"
    if kind not in ("weekly", "once"):
        raise ChangeError("kind is weekly or once", "invalid", 422)
    doc = {"id": window_id or new_id("mw_"), "name": str(body.get("name") or "Window")[:80],
           "devices": list(body.get("devices") or ["*"]), "kind": kind,
           "timezone": str(body.get("timezone") or "UTC"), "days": [int(d) for d in body.get("days") or []],
           "start_minute": int(body.get("start_minute") or 0), "end_minute": int(body.get("end_minute") or 0),
           "start_at": body.get("start_at"), "end_at": body.get("end_at"), "updated_by": actor,
           "updated_at": time.time()}
    if not 0 <= doc["start_minute"] < 1440 or not 0 <= doc["end_minute"] < 1440:
        raise ChangeError("start_minute and end_minute are minutes since midnight (0-1439)", "invalid", 422)
    hub.store.put(WINDOWS, doc)
    hub.activity(actor, "info", f"Saved maintenance window '{doc['name']}'", window_id=doc["id"])
    return doc


def delete_window(hub: "Hub", window_id: str, actor: str) -> bool:
    removed = hub.store.delete(WINDOWS, window_id)
    if removed:
        hub.activity(actor, "info", "Removed a maintenance window", window_id=window_id)
    return removed


def in_window(hub: "Hub", firewall: str, now: float | None = None) -> bool:
    now = _now(now)
    for window in list_windows(hub):
        devices = window.get("devices") or ["*"]
        if "*" not in devices and firewall not in devices:
            continue
        if window.get("kind") == "once":
            start, end = window.get("start_at") or 0, window.get("end_at") or 0
            if start <= now < end:
                return True
            continue
        try:
            local = datetime.fromtimestamp(now, ZoneInfo(window.get("timezone") or "UTC"))
        except ZoneInfoNotFoundError:
            continue
        minute = local.hour * 60 + local.minute
        start, end = int(window.get("start_minute") or 0), int(window.get("end_minute") or 0)
        if local.weekday() not in set(window.get("days") or []):
            continue
        if start == end:
            return True
        if start < end and start <= minute < end:
            return True
        if start > end and (minute >= start or minute < end):
            return True
    return False


def may_apply_now(hub: "Hub", change: dict[str, Any], now: float | None = None) -> bool:
    if change.get("emergency"):
        return True
    if not guardrails.value(hub, "device_changes_need_maintenance_window"):
        return True
    return in_window(hub, change["firewall"], now)


# -- apply (called by module:network) ----------------------------------------------------------------


def binding_ok(change: dict[str, Any], approval) -> str | None:
    payload = approval.payload or {}
    if approval.kind != "firewall" or approval.status != "approved":
        return "approval"
    if payload.get("change_id") != change["id"] or payload.get("ops_hash") != change.get("ops_hash"):
        return "binding"
    if payload.get("base_revision") != change.get("base_revision"):
        return "binding"
    return None


async def execute(hub: "Hub", change_id: str, ask_tool, now: float | None = None) -> dict[str, Any]:
    """Apply one approved change. ask_tool(tool_id, subject, body) talks to that device's tool supervisor."""
    change = get(hub, change_id)
    if change is None:
        raise ChangeError("Unknown change", "invalid", 404)
    if change["status"] not in ("approved", "scheduled"):
        return public(change)
    if not guardrails.value(hub, "device_changes"):
        change["status"] = "blocked"
        save(hub, change)
        return public(change)
    approval = hub.approvals.get(change["approval_id"]) if change.get("approval_id") else None
    if approval is None or binding_ok(change, approval):
        change["status"] = "blocked"
        change["result"] = {"reason": "approval"}
        save(hub, change)
        return public(change)
    if approval_expired(hub, approval, now):
        change["status"] = "expired"
        save(hub, change)
        hub.approvals.withdraw(approval.id, "Expired", "module:network")
        hub.activity("module:network", "warn", "A network change expired before it was applied",
                     tool_id=change["firewall"], change_id=change_id)
        return public(change)
    if not may_apply_now(hub, change, now):
        if change["status"] != "scheduled":
            change["status"] = "scheduled"
            save(hub, change)
            hub.activity("module:network", "info", "A network change is waiting for a maintenance window",
                         tool_id=change["firewall"], change_id=change_id)
        return public(change)
    snap = network.snapshot(hub, change["firewall"])
    revision = (snap or {}).get("record", {}).get("revision")
    if revision != change.get("base_revision"):
        change["status"] = "stale"
        change["result"] = {"reason": "revision", "found": revision}
        save(hub, change)
        hub.activity("module:network", "warn", "A network change was not applied: the device revision changed",
                     tool_id=change["firewall"], change_id=change_id)
        return public(change)
    change["status"] = "applying"
    save(hub, change)
    backup_id = None
    if guardrails.value(hub, "device_changes_need_backup"):
        try:
            taken = await ask_tool(change["firewall"], "network.backup",
                                   {"reason": "pre-change", "actor": "module:network", "change_id": change_id})
        except Exception as exc:
            change["status"] = "failed"
            change["result"] = {"reason": "backup", "message": str(exc)[:300]}
            save(hub, change)
            return public(change)
        if taken.get("failure") or not (taken.get("backup") or {}).get("id"):
            change["status"] = "failed"
            change["result"] = {"reason": "backup", "message": (taken.get("failure") or {}).get("message", "backup failed")}
            save(hub, change)
            return public(change)
        backup_id = taken["backup"]["id"]
        change["backup_id"] = backup_id
    applied = await ask_tool(change["firewall"], "network.apply", {
        "change_id": change_id, "ops": change.get("ops") or [], "base_revision": change.get("base_revision"),
        "backup_id": backup_id, "ops_hash": change.get("ops_hash"),
    })
    if applied.get("failure") or applied.get("error"):
        message = (applied.get("failure") or {}).get("message") or applied.get("error") or "apply failed"
        code = (applied.get("failure") or {}).get("code") or "failed"
        change["status"] = "stale" if code == "stale" else "failed"
        change["result"] = {"reason": code, "message": str(message)[:500]}
        save(hub, change)
        hub.activity("module:network", "error", f"A network change failed: {message[:200]}",
                     tool_id=change["firewall"], change_id=change_id)
        return public(change)
    change["status"] = "verifying"
    change["token"] = (applied.get("result") or {}).get("token")
    change["rollback_until"] = (applied.get("result") or {}).get("rollback_until")
    change["result"] = applied.get("result")
    save(hub, change)
    verified = await ask_tool(change["firewall"], "network.verify", {"change_id": change_id})
    if not verified.get("ok"):
        await ask_tool(change["firewall"], "network.rollback",
                       {"change_id": change_id, "token": change.get("token"), "backup_id": backup_id})
        change["status"] = "rolled_back"
        change["result"] = {**(change.get("result") or {}), "verify": verified.get("reason")}
        save(hub, change)
        hub.activity("module:network", "error", "A network change was rolled back: verification failed",
                     tool_id=change["firewall"], change_id=change_id)
        return public(change)
    confirmed = await ask_tool(change["firewall"], "network.confirm",
                               {"change_id": change_id, "token": change.get("token")})
    if confirmed.get("failure"):
        change["status"] = "failed"
        change["result"] = {**(change.get("result") or {}), "confirm": confirmed["failure"].get("message")}
        save(hub, change)
        return public(change)
    change["status"] = "applied"
    change["applied_at"] = _now(now)
    change["token"] = None
    save(hub, change)
    hub.approvals.complete(change["approval_id"], True, {"change_id": change_id, "status": "applied"})
    hub.activity("module:network", "warn", "Applied a network change", tool_id=change["firewall"], change_id=change_id)
    return public(change)


def mark_decided(hub: "Hub", approval, approved: bool, actor: str) -> dict[str, Any] | None:
    change_id = (approval.payload or {}).get("change_id")
    change = get(hub, change_id) if change_id else None
    if change is None or change["status"] != "proposed":
        return None
    change["status"] = "approved" if approved else "rejected"
    change["decided_at"] = time.time()
    save(hub, change)
    verb = "Approved" if approved else "Rejected"
    hub.activity(actor, "info", f"{verb} a network change", tool_id=change["firewall"], change_id=change["id"])
    return change


def emergency(hub: "Hub", change_id: str, actor: str, justification: str) -> dict[str, Any]:
    change = get(hub, change_id)
    if change is None:
        raise ChangeError("Unknown change", "invalid", 404)
    if change["status"] not in ("approved", "scheduled"):
        raise ChangeError("Only an approved change can be marked an emergency", "invalid", 409)
    if len(justification.strip()) < 20:
        raise ChangeError("An emergency apply needs a justification of at least 20 characters.",
                          "justification_required", 422)
    change["emergency"] = True
    change["justification"] = justification.strip()[:2000]
    save(hub, change)
    hub.activity(actor, "warn", "Marked a network change as an emergency (apply outside the maintenance window)",
                 tool_id=change["firewall"], change_id=change_id)
    return public(change)


def sweep(hub: "Hub", now: float | None = None) -> list[str]:
    """Expire proposed approvals and note scheduled changes. Applying them is the Network Supervisor's job."""
    now = _now(now)
    touched = []
    for change in hub.store.list(CHANGES):
        if change.get("status") not in ("proposed", "approved", "scheduled"):
            continue
        approval = hub.approvals.get(change["approval_id"]) if change.get("approval_id") else None
        if approval is not None and approval.status == "pending" and approval_expired(hub, approval, now):
            change["status"] = "expired"
            save(hub, change)
            hub.approvals.withdraw(approval.id, "Expired", "module:network")
            touched.append(change["id"])
    return touched


def change_facts(hub: "Hub") -> dict[str, Any]:
    items = hub.store.list(CHANGES)
    return {
        "second_person": bool(guardrails.value(hub, "device_changes_need_second_person")),
        "maintenance_window": bool(guardrails.value(hub, "device_changes_need_maintenance_window")),
        "backup": bool(guardrails.value(hub, "device_changes_need_backup")),
        "emergencies": sum(1 for c in items if c.get("emergency") and c.get("status") == "applied"),
        "rollbacks": sum(1 for c in items if c.get("status") == "rolled_back"),
        "applied": sum(1 for c in items if c.get("status") == "applied"),
    }
