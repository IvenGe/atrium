"""The Network app's read model: device snapshots and their history, configuration drift, Atrium-managed
configuration backups, what each device lets Atrium change, and the facts the network compliance checks use.

Collections (all keyed by the device's tool id, one connection = one device):

``network_snapshots``         the current snapshot per device: {id, tool_id, rev (Atrium's own counter, +1 per content
                              change), revision (the device's), hash (``netmodel.record_hash``), read_at, stored_at,
                              cause (the change id when the change path stored it), record (normalised), counts,
                              baseline: {rev, matches, deviations} | None}
``network_snapshot_history``  one entry per content change: {id "<tool id>|<rev, 8 digits>", tool_id, rev, revision,
                              hash, read_at, cause, drift (counts per kind), record}; the last ``history_limit`` (50)
                              per device are kept
``network_drift``             what changed between two snapshots: {id, tool_id, detected_at, rev, from_rev, revision,
                              kind (``netmodel.DRIFT_KINDS``), severity (info | warn | critical), subject, before,
                              after (one-line texts, untrusted device text), change_id (the Atrium change that explains
                              it, else None), status (open | attributed | acknowledged), note, acknowledged_by/at}
``network_baselines``         an approved configuration per device (admin "accept current as baseline")
``device_backups``            configuration backups: {id, tool_id, taken_at, reason (pre-change | manual | scheduled),
                              taken_by, change_id, size, sha256, format, device_backup_id, revision, content (Fernet
                              token of the base64 content - never returned, logged or published)}
``settings`` / ``network``    backup_retention (20), backup_interval_hours (24, 0 = no scheduled backups),
                              history_limit (50), stale_after_minutes (15)

Drift attribution: a change Atrium made itself is attributed to its change id, not reported as unexplained. The
change path (collection ``firewall_changes``, R3-NETCHANGE) keeps on every change at least {id, firewall (tool id),
status, op ("allow" | "disable_rules" | "revert" | "restore"), ops (the canonical ops it applies, ``netmodel.parse_ops``
form), updated_at (set on every status change), applied_at}. Only changes that are applying / verifying, or whose
status changed since the previous snapshot was stored, can explain an item (an old change never hides a new edit) -
not a change that ended with nothing changed on the device (result state "unchanged"), and not a finished change
whose own re-read is the previous snapshot (its effects are stored already; review F10): (1) an added rule carrying
the marker "atrium:<change id>" that is exactly what one of the change's allow ops asked for
(``netmodel.rule_matches_allow``; a copied marker on another rule stays unexplained); a removed rule carrying the
marker (a rollback); (2) a rule enabled / disabled that a disable_rules / enable_rules op of the change names; (3)
anything, but only in the re-read the change path stores itself with ``cause_scope="all"`` (after a rollback or a
backup restore, which may put back any part of the configuration) - a later read, or a restore that failed, never
explains an edit it did not make. ``ingest(..., cause=change id)`` checks that change first.

SSE events: ``network_snapshot`` {tool_id, rev, revision, read_at, changed}, ``network_drift`` {tool_id, ids, count,
critical}, ``network_baseline`` {tool_id, rev}, ``device_backup`` (backup metadata), ``network_settings``,
``segmentation`` {firewall_ids, generated_at} (the segmentation map should re-read).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import time
from typing import TYPE_CHECKING, Any

from .. import connectors
from ..connectors.base import Connector, ConnectorError
from ..connectors.netmodel import (CRITICAL_DRIFT, Backup, backup_content, diff_records, display_id, exposes_management,
                                   is_any_any, parse_ops, record_hash, record_lines, rule_matches_allow, rule_ref,
                                   validate_write_spec)
from ..store import new_id
from . import connections, flows

if TYPE_CHECKING:
    from ..core import Hub

SNAPSHOTS = "network_snapshots"
HISTORY = "network_snapshot_history"
DRIFT = "network_drift"
BASELINES = "network_baselines"
BACKUPS = "device_backups"
CHANGES = "firewall_changes"  # owned by the change path (R3-NETCHANGE); read here for attribution and in-flight checks
SETTINGS_ID = "network"
DEFAULT_SETTINGS = {"backup_retention": 20, "backup_interval_hours": 24, "history_limit": 50, "stale_after_minutes": 15}
SETTING_BOUNDS = {"backup_retention": (1, 500), "backup_interval_hours": (0, 720), "history_limit": (5, 500),
                  "stale_after_minutes": (1, 1440)}
MAX_BACKUP = 32 * 1024 * 1024
MAX_DRIFT_PER_DEVICE = 2000
BACKUP_REASONS = ("pre-change", "manual", "scheduled")
OPEN_CHANGES = ("proposed", "approved", "scheduled", "applying", "verifying")  # a backup they name is kept
IN_FLIGHT = ("approved", "scheduled", "applying", "verifying")  # another change of the device waits for these
ATTRIBUTABLE = ("applying", "verifying", "applied", "rolled_back", "failed")
DAY = 86400


# --------------------------------------------------------------------------------------
# settings
# --------------------------------------------------------------------------------------


def settings(hub: "Hub") -> dict[str, Any]:
    stored = hub.store.get("settings", SETTINGS_ID) or {}
    return {k: int(stored.get(k, v)) for k, v in DEFAULT_SETTINGS.items()}


def update_settings(hub: "Hub", actor: str, changes: dict[str, Any]) -> dict[str, Any]:
    """Validated changes (ValueError naming the first bad key), stored and logged with the actor."""
    current = settings(hub)
    clean = {}
    for key, value in (changes or {}).items():
        if key not in DEFAULT_SETTINGS:
            raise ValueError(f"Unknown network setting '{key}'")
        low, high = SETTING_BOUNDS[key]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{key} must be a whole number between {low} and {high}")
        clean[key] = value
    new = {**current, **clean}
    hub.store.put("settings", {"id": SETTINGS_ID, **new})
    moved = [f"{k} {current[k]} -> {v}" for k, v in clean.items() if current[k] != v]
    if moved:
        hub.activity(actor, "info", "Network settings changed: " + ", ".join(moved))
        hub.bus.publish("network_settings", new)
    for tool_id in {d["tool_id"] for d in hub.store.list(BACKUPS)}:
        prune_backups(hub, tool_id)
    return new


# --------------------------------------------------------------------------------------
# snapshots, history and drift
# --------------------------------------------------------------------------------------


def snapshot(hub: "Hub", tool_id: str) -> dict[str, Any] | None:
    return hub.store.get(SNAPSHOTS, tool_id)


def snapshots(hub: "Hub") -> list[dict[str, Any]]:
    return hub.store.list(SNAPSHOTS)


def _history_id(tool_id: str, rev: int) -> str:
    return f"{tool_id}|{rev:08d}"


def history(hub: "Hub", tool_id: str) -> list[dict[str, Any]]:
    """The device's snapshot revisions, newest first, without their records (read by id range, records left in the
    database: review F26 - not every device's full rule bases on every device page)."""
    entries = hub.store.list_prefix(HISTORY, f"{tool_id}|", without="record")
    return sorted((d for d in entries if d.get("tool_id") == tool_id), key=lambda d: -d["rev"])


def history_entry(hub: "Hub", tool_id: str, rev: int) -> dict[str, Any] | None:
    return hub.store.get(HISTORY, _history_id(tool_id, rev))


def counts(record: dict[str, Any]) -> dict[str, int]:
    rules = record.get("rules") or []
    return {"rules": len(rules), "enabled_rules": sum(1 for r in rules if r.get("enabled", True)),
            "pass_rules": sum(1 for r in rules if r.get("enabled", True) and r.get("action") == "pass"),
            "interfaces": len(record.get("interfaces") or []), "zones": len(record.get("zones") or []),
            "aliases": len(record.get("aliases") or []), "errors": len(record.get("errors") or [])}


def _changes(hub: "Hub", tool_id: str) -> list[dict[str, Any]]:
    return [c for c in hub.store.list(CHANGES) if c.get("firewall") == tool_id]


def _op_list(change: dict[str, Any]) -> list[dict[str, Any]]:
    ops = change.get("ops")
    if ops is None:
        ops = (change.get("preview") or {}).get("ops_canonical") or []
    return [o for o in ops if isinstance(o, dict)]


def _touched(change: dict[str, Any]) -> float:
    return max(float(change.get(k) or 0) for k in ("updated_at", "applied_at", "decided_at", "created_at"))


def _explains(change: dict[str, Any], item: dict[str, Any], rule: dict[str, Any] | None,
              record: dict[str, Any] | None) -> bool:
    kind = item["kind"]
    if kind in ("rule_added", "management_exposed", "any_any_introduced"):
        if rule is None or rule.get("marker") != change.get("id"):
            return False
        for op in _op_list(change):
            if op.get("op") != "allow":
                continue
            try:
                if rule_matches_allow(rule, parse_ops([op])[0], record):
                    return True
            except ValueError:
                continue
        return False
    if kind == "rule_removed":
        return rule is not None and rule.get("marker") == change.get("id")
    if kind in ("rule_enabled", "rule_disabled"):
        refs = {item["subject"], *(filter(None, [(rule or {}).get("vendor_ref")]))}
        return any(op.get("op") in ("disable_rules", "enable_rules")
                   and any(refs & {r.get("id"), r.get("vendor_ref")} for r in op.get("rules") or [])
                   for op in _op_list(change))
    return False


def attribute(item: dict[str, Any], changes: list[dict[str, Any]], since: float, cause: str | None = None,
              rule: dict[str, Any] | None = None, cause_scope: str = "ops",
              record: dict[str, Any] | None = None, captured_by: str | None = None) -> str | None:
    """The id of the Atrium change that explains a drift item (see the module docstring), else None. `since`: when
    the previous snapshot was stored; `rule`: the item's rule (the new one, or the removed one); `record`: the new
    snapshot (to resolve the address objects a rule uses); `captured_by`: the change whose own re-read the previous
    snapshot is. Only the change path's own re-read with `cause_scope` "all" explains everything (review F10: a
    restore - applied, or failed with nothing changed - never explains a later out-of-band edit)."""
    by_id = {c.get("id"): c for c in changes}
    if cause and cause_scope == "all" and cause in by_id:
        return cause
    recent = [c for c in changes if c.get("status") in ("applying", "verifying")
              or (c.get("status") in ATTRIBUTABLE and _touched(c) >= since
                  and (c.get("result") or {}).get("state") != "unchanged" and c.get("id") != captured_by)]
    if cause:
        if cause in by_id and by_id[cause] not in recent:
            recent.insert(0, by_id[cause])
        recent.sort(key=lambda c: c.get("id") != cause)
    for change in recent:
        if _explains(change, item, rule, record):
            return change["id"]
    return None


def ingest(hub: "Hub", tool_id: str, record: dict[str, Any], *, cause: str | None = None,
           cause_scope: str = "ops") -> dict[str, Any]:
    """Store a normalised record read from the device as its current snapshot; on a content change add a history
    entry and drift items (attributed to Atrium changes where they explain it). `cause`: the change id when the
    change path stores the re-read it made after applying / rolling back / restoring that change; `cause_scope`
    "all" when everything that changed is that change's doing (after a rollback or a backup restore), else "ops"
    (only what its ops explain). Returns {"changed", "rev", "drift": [new items], "unexplained": n, "critical": n}."""
    now = time.time()
    prev = snapshot(hub, tool_id)
    digest = record_hash(record)
    read_at = record.get("read_at") or now
    if prev is not None and record.get("read_at") and read_at < (prev.get("read_at") or 0):
        # a read that started before the stored snapshot's (a slow pull overtaken by a change's verification read):
        # storing it would show an older device and report Atrium's own change as drift later (review F23)
        return {"changed": False, "rev": prev["rev"], "drift": [], "unexplained": 0, "critical": 0, "stale": True}
    base = {"id": tool_id, "tool_id": tool_id, "revision": record.get("revision"), "hash": digest, "read_at": read_at,
            "stored_at": now, "record": record, "counts": counts(record)}
    if prev is not None and prev.get("hash") == digest:
        doc = {**prev, **base, "rev": prev["rev"], "cause": prev.get("cause")}
        hub.store.put(SNAPSHOTS, doc)
        hub.bus.publish("network_snapshot", {"tool_id": tool_id, "rev": doc["rev"], "revision": doc["revision"],
                                             "read_at": read_at, "changed": False})
        return {"changed": False, "rev": doc["rev"], "drift": [], "unexplained": 0, "critical": 0}
    rev = (prev["rev"] + 1) if prev else 1
    items: list[dict[str, Any]] = []
    if prev is not None:
        changes = _changes(hub, tool_id)
        old_rules = {r["id"]: r for r in prev["record"].get("rules") or []}
        new_rules = {r["id"]: r for r in record.get("rules") or []}
        for item in diff_records(prev["record"], record):
            rule = (old_rules if item["kind"] == "rule_removed" else new_rules).get(item["subject"])
            change_id = attribute(item, changes, prev.get("stored_at") or prev.get("read_at") or 0, cause, rule,
                                  cause_scope, record, captured_by=prev.get("cause"))
            items.append({"id": new_id("dr_"), "tool_id": tool_id, "detected_at": now, "rev": rev,
                          "from_rev": prev["rev"], "revision": record.get("revision"), "kind": item["kind"],
                          "severity": item["severity"], "subject": item["subject"], "before": item["before"],
                          "after": item["after"], "marker": item.get("marker"), "change_id": change_id,
                          "status": "attributed" if change_id else "open", "note": None,
                          "acknowledged_by": None, "acknowledged_at": None})
        for item in items:
            hub.store.put(DRIFT, item)
        _prune_drift(hub, tool_id)
    summary: dict[str, int] = {}
    for item in items:
        summary[item["kind"]] = summary.get(item["kind"], 0) + 1
    hub.store.put(HISTORY, {"id": _history_id(tool_id, rev), "tool_id": tool_id, "rev": rev,
                            "revision": record.get("revision"), "hash": digest, "read_at": read_at, "stored_at": now,
                            "cause": cause, "drift": summary, "record": record})
    _prune_history(hub, tool_id)
    doc = {**base, "rev": rev, "cause": cause}
    baseline = hub.store.get(BASELINES, tool_id)
    doc["baseline"] = _baseline_summary(baseline, doc)
    hub.store.put(SNAPSHOTS, doc)
    unexplained = [i for i in items if i["status"] == "open"]
    critical = [i for i in unexplained if i["kind"] in CRITICAL_DRIFT]
    hub.bus.publish("network_snapshot", {"tool_id": tool_id, "rev": rev, "revision": doc["revision"],
                                         "read_at": read_at, "changed": True})
    if unexplained:
        kinds = sorted({i["kind"].replace("_", " ") for i in unexplained})
        hub.activity("module:network", "error" if critical else "warn",
                     f"Network drift on {_name(hub, tool_id)}: {len(unexplained)} change(s) not made through Atrium "
                     f"({', '.join(kinds[:5])})" + (f"; {len(critical)} critical" if critical else ""),
                     tool_id=tool_id, drift_ids=[i["id"] for i in unexplained[:50]])
        hub.bus.publish("network_drift", {"tool_id": tool_id, "ids": [i["id"] for i in unexplained[:200]],
                                          "count": len(unexplained), "critical": len(critical)})
    return {"changed": True, "rev": rev, "drift": items, "unexplained": len(unexplained), "critical": len(critical)}


def _prune_history(hub: "Hub", tool_id: str) -> None:
    keep = settings(hub)["history_limit"]
    ids = hub.store.ids_prefix(HISTORY, f"{tool_id}|")  # "<tool id>|<rev, 8 digits>": oldest first, nothing parsed
    if len(ids) > keep:
        hub.store.delete_many(HISTORY, ids[:len(ids) - keep])


def _prune_drift(hub: "Hub", tool_id: str) -> None:
    items = hub.store.list_where(DRIFT, "tool_id", tool_id)
    excess = len(items) - MAX_DRIFT_PER_DEVICE
    if excess <= 0:
        return
    closed = sorted((d for d in items if d["status"] != "open"), key=lambda d: d["detected_at"])
    for old in closed[:excess]:
        hub.store.delete(DRIFT, old["id"])


def drift(hub: "Hub", tool_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    """Drift items, newest first; `status`: open | attributed | acknowledged (None: all)."""
    candidates = hub.store.list(DRIFT) if tool_id is None else hub.store.list_where(DRIFT, "tool_id", tool_id)
    items = [d for d in candidates if (tool_id is None or d.get("tool_id") == tool_id)
             and (status is None or d.get("status") == status)]
    return sorted(items, key=lambda d: (-d["detected_at"], d["id"]))


def acknowledge(hub: "Hub", drift_id: str, actor: str, note: str | None = None) -> dict[str, Any]:
    """Mark an open drift item as reviewed (KeyError: unknown; ValueError: not open)."""
    item = hub.store.get(DRIFT, drift_id)
    if item is None:
        raise KeyError(drift_id)
    if item["status"] != "open":
        raise ValueError(f"This drift item is already {item['status']}")
    item.update({"status": "acknowledged", "note": (note or "").strip()[:500] or None, "acknowledged_by": actor,
                 "acknowledged_at": time.time()})
    hub.store.put(DRIFT, item)
    hub.activity(actor, "info", f"Acknowledged network drift on {_name(hub, item['tool_id'])}: "
                                f"{item['kind'].replace('_', ' ')} {display_id(item['subject'])}",
                 tool_id=item["tool_id"], drift_id=drift_id)
    hub.bus.publish("network_drift", {"tool_id": item["tool_id"], "ids": [drift_id], "count": 0, "critical": 0})
    return item


# --------------------------------------------------------------------------------------
# baselines
# --------------------------------------------------------------------------------------


def _baseline_summary(baseline: dict[str, Any] | None, snap: dict[str, Any]) -> dict[str, Any] | None:
    if baseline is None:
        return None
    if baseline["hash"] == snap["hash"]:
        return {"rev": baseline["rev"], "matches": True, "deviations": 0}
    return {"rev": baseline["rev"], "matches": False,
            "deviations": len(diff_records(baseline["record"], snap["record"]))}


def baseline(hub: "Hub", tool_id: str) -> dict[str, Any] | None:
    doc = hub.store.get(BASELINES, tool_id)
    return {k: v for k, v in doc.items() if k != "record"} if doc else None


def baseline_deviations(hub: "Hub", tool_id: str) -> list[dict[str, Any]]:
    doc, snap = hub.store.get(BASELINES, tool_id), snapshot(hub, tool_id)
    if doc is None or snap is None or doc["hash"] == snap["hash"]:
        return []
    return diff_records(doc["record"], snap["record"])


def accept_baseline(hub: "Hub", tool_id: str, actor: str) -> dict[str, Any]:
    """Approve the device's current snapshot as its baseline; its open drift items are acknowledged with it."""
    snap = snapshot(hub, tool_id)
    if snap is None:
        raise KeyError(tool_id)
    now = time.time()
    doc = {"id": tool_id, "tool_id": tool_id, "rev": snap["rev"], "revision": snap["revision"], "hash": snap["hash"],
           "accepted_by": actor, "accepted_at": now, "record": snap["record"]}
    hub.store.put(BASELINES, doc)
    hub.store.put(SNAPSHOTS, {**snap, "baseline": _baseline_summary(doc, snap)})
    open_items = drift(hub, tool_id, "open")
    for item in open_items:
        item.update({"status": "acknowledged", "note": f"accepted as baseline (rev {snap['rev']})",
                     "acknowledged_by": actor, "acknowledged_at": now})
        hub.store.put(DRIFT, item)
    hub.activity(actor, "info", f"Accepted the current configuration of {_name(hub, tool_id)} as its baseline "
                                f"(rev {snap['rev']})" + (f"; {len(open_items)} drift item(s) acknowledged"
                                                          if open_items else ""), tool_id=tool_id)
    hub.bus.publish("network_baseline", {"tool_id": tool_id, "rev": snap["rev"]})
    return {k: v for k, v in doc.items() if k != "record"}


def clear_baseline(hub: "Hub", tool_id: str, actor: str) -> bool:
    removed = hub.store.delete(BASELINES, tool_id)
    snap = snapshot(hub, tool_id)
    if removed:
        if snap is not None:
            hub.store.put(SNAPSHOTS, {**snap, "baseline": None})
        hub.activity(actor, "info", f"Removed the configuration baseline of {_name(hub, tool_id)}", tool_id=tool_id)
        hub.bus.publish("network_baseline", {"tool_id": tool_id, "rev": None})
    return removed


# --------------------------------------------------------------------------------------
# configuration backups (content encrypted at rest, never returned except by the admin download)
# --------------------------------------------------------------------------------------


def public_backup(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k != "content"}


def store_backup(hub: "Hub", tool_id: str, taken: dict[str, Any], *, reason: str, actor: str,
                 change_id: str | None = None) -> dict[str, Any]:
    """Encrypt and store what a connector's backup() returned; returns the metadata (ValueError when it is empty,
    too large or does not match the checksum the connector sent - the message never quotes the content)."""
    if reason not in BACKUP_REASONS:
        raise ValueError(f"reason is one of {', '.join(BACKUP_REASONS)}")
    if not isinstance(taken, dict):
        raise ValueError("backup() must return an object")
    try:
        content = backup_content(taken.get("content"))
    except ConnectorError as exc:
        raise ValueError(exc.message) from exc
    if not content:
        raise ValueError("The device returned an empty configuration")
    if len(content) > MAX_BACKUP:
        raise ValueError(f"The configuration is larger than {MAX_BACKUP // (1024 * 1024)} MB")
    digest = hashlib.sha256(content).hexdigest()
    claimed = str(taken.get("sha256") or "").lower().removeprefix("sha256:")
    if claimed and claimed != digest:
        raise ValueError("The backup does not match the checksum the connector reported")
    doc = {"id": new_id("bk_"), "tool_id": tool_id, "taken_at": time.time(), "reason": reason, "taken_by": actor,
           "change_id": change_id, "size": len(content), "sha256": digest,
           "format": display_id(taken.get("format") or "text", 20),
           "device_backup_id": display_id(taken["device_backup_id"], 120) if taken.get("device_backup_id") else None,
           "revision": display_id(taken["revision"], 200) if taken.get("revision") else None,
           "content": hub.secrets.encrypt(base64.b64encode(content).decode("ascii"))}
    hub.store.put(BACKUPS, doc)
    meta = public_backup(doc)
    prune_backups(hub, tool_id, reason)
    hub.activity(actor, "info", f"Backed up the configuration of {_name(hub, tool_id)} ({reason}, "
                                f"{len(content)} bytes, sha256 {digest[:12]})", tool_id=tool_id, backup_id=doc["id"])
    hub.bus.publish("device_backup", meta)
    return meta


def backups(hub: "Hub", tool_id: str | None = None) -> list[dict[str, Any]]:
    """Backup metadata, newest first."""
    items = [public_backup(d) for d in hub.store.list(BACKUPS) if tool_id is None or d.get("tool_id") == tool_id]
    return sorted(items, key=lambda d: -d["taken_at"])


def get_backup(hub: "Hub", backup_id: str) -> dict[str, Any] | None:
    doc = hub.store.get(BACKUPS, backup_id)
    return public_backup(doc) if doc else None


def backup_bytes(hub: "Hub", backup_id: str) -> tuple[dict[str, Any], bytes]:
    """The decrypted content with its metadata (KeyError unknown; ValueError when it cannot be decrypted or its
    SHA-256 no longer matches)."""
    doc = hub.store.get(BACKUPS, backup_id)
    if doc is None:
        raise KeyError(backup_id)
    try:
        content = base64.b64decode(hub.secrets.decrypt(doc["content"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("The stored backup cannot be decoded") from exc
    except Exception as exc:  # SecretError: the key changed
        raise ValueError(f"The stored backup cannot be decrypted: {exc}") from exc
    if hashlib.sha256(content).hexdigest() != doc["sha256"]:
        raise ValueError("The stored backup no longer matches its SHA-256 - it was altered")
    return public_backup(doc), content


def load_backup(hub: "Hub", backup_id: str) -> Backup:
    """The backup as connectors receive it (apply_change, rollback_change, restore_backup) - verified."""
    meta, content = backup_bytes(hub, backup_id)
    return Backup(backup_id=meta["id"], content=content, sha256=meta["sha256"], taken_at=meta["taken_at"],
                  format=meta["format"], device_backup_id=meta.get("device_backup_id"), revision=meta.get("revision"))


def protected_backups(hub: "Hub") -> set[str]:
    """Backups retention never deletes: the ones an open change names (its pre-change backup, the backup a restore
    puts back), and the pre-change backup of an applied restore that was not reverted - reverting it restores that
    backup (R3-NETCHANGE S10)."""
    out: set[str] = set()
    for change in hub.store.list(CHANGES):
        status = change.get("status")
        if status in OPEN_CHANGES:
            out |= {change.get("backup_id"), (change.get("request") or {}).get("backup_id")}
        elif status == "applied" and change.get("op") == "restore" and not change.get("reverted_by"):
            out.add(change.get("backup_id"))
    return {b for b in out if b}


def prune_backups(hub: "Hub", tool_id: str, reason: str | None = None) -> list[str]:
    """Keep the newest `backup_retention` backups of a device, never the protected ones (``protected_backups``) and
    never the newest. `reason`: what was just taken - a manual backup only pushes out older manual backups, so
    taking backups by hand again and again cannot rotate out the scheduled and pre-change recovery points."""
    keep = settings(hub)["backup_retention"]
    named = protected_backups(hub)
    items = sorted((d for d in hub.store.list(BACKUPS) if d.get("tool_id") == tool_id), key=lambda d: -d["taken_at"])
    excess = len(items) - keep
    removed = []
    for old in reversed(items[1:]):  # oldest first; the newest always stays
        if excess <= 0:
            break
        if old["id"] in named or (reason == "manual" and old.get("reason") != "manual"):
            continue
        hub.store.delete(BACKUPS, old["id"])
        removed.append(old["id"])
        excess -= 1
    return removed


def last_backup(hub: "Hub", tool_id: str) -> dict[str, Any] | None:
    items = backups(hub, tool_id)
    return items[0] if items else None


def can_backup(hub: "Hub", tool_id: str) -> bool:
    cls = _connector_class(hub, tool_id)
    return bool(cls and cls.implements("backup"))


def backup_due(hub: "Hub", tool_id: str, now: float | None = None) -> bool:
    hours = settings(hub)["backup_interval_hours"]
    if not hours or not can_backup(hub, tool_id):
        return False
    last = last_backup(hub, tool_id)
    return last is None or (now or time.time()) - last["taken_at"] >= hours * 3600


# --------------------------------------------------------------------------------------
# write capability and whether a change is possible right now (canvas-design S2)
# --------------------------------------------------------------------------------------


def _connector_class(hub: "Hub", tool_id: str) -> type[Connector] | None:
    conn = connections.get(hub, tool_id)
    if conn is None:
        return None
    try:
        return connectors.connector_class(conn.kind)
    except ConnectorError:
        return None


def narrow_write(connector: Connector, reported: Any = ...) -> dict[str, Any] | None:
    """What a connection may change: the connector's own write_capability(), narrowed by what its test() reported
    (`...` = nothing reported). Reports can only take away: fewer ops, None, never a capability not declared."""
    base = connector.write_capability()
    if base is not None and base["rollback"] == "none":  # no rollback mechanism: never writable (F27)
        return None
    if base is None or reported is ...:
        return base
    try:
        spec = validate_write_spec(reported)
    except (ValueError, TypeError):
        return None
    if spec is None:
        return None
    ops = [o for o in spec["ops"] if o in base["ops"]]
    if not ops or spec["rollback"] == "none":
        return None
    return {"ops": ops, "rollback": spec["rollback"], "window_s": spec["window_s"]}


def write_capability(hub: "Hub", tool_id: str) -> dict[str, Any] | None:
    """The device's write capability: from the last successful connection test, else what the connector declares
    for its settings. Generated / generic connections are never write-capable."""
    conn = connections.get(hub, tool_id)
    cls = _connector_class(hub, tool_id)
    if conn is None or cls is None or conn.generated or conn.kind == "generic_rest":
        return None
    try:
        instance = cls(conn.config, {})
        if conn.last_test and conn.last_test.get("ok") and "network_write" in conn.last_test:
            return narrow_write(instance, conn.last_test["network_write"])
        return narrow_write(instance)
    except Exception:
        return None


def in_flight(hub: "Hub", tool_id: str) -> list[dict[str, Any]]:
    return [c for c in _changes(hub, tool_id) if c.get("status") in IN_FLIGHT]


def stale(hub: "Hub", snap: dict[str, Any] | None, now: float | None = None) -> bool:
    if snap is None:
        return True
    return (now or time.time()) - (snap.get("read_at") or 0) > settings(hub)["stale_after_minutes"] * 60


def write_status(hub: "Hub", tool_id: str, now: float | None = None) -> dict[str, Any]:
    """{"capable", "ops", "rollback": {"mode", "window_s"} | None, "writable", "reason", "reasons"}. Reasons, first
    one wins: not_capable, guardrail (device_changes off), connection_test (the last test did not pass),
    no_snapshot / stale_snapshot (older than stale_after_minutes: refresh first), change_in_flight. The caller's
    role (operator or higher) is checked by the API."""
    spec = write_capability(hub, tool_id)
    conn = connections.get(hub, tool_id)
    snap = snapshot(hub, tool_id)
    reasons = []
    if spec is None:
        reasons.append("not_capable")
    if not hub.prefs["guardrails"].get("device_changes", False):
        reasons.append("guardrail")
    if conn is None or not (conn.last_test or {}).get("ok"):
        reasons.append("connection_test")
    if snap is None:
        reasons.append("no_snapshot")
    elif stale(hub, snap, now):
        reasons.append("stale_snapshot")
    if in_flight(hub, tool_id):
        reasons.append("change_in_flight")
    return {"capable": spec is not None, "ops": spec["ops"] if spec else [],
            "rollback": {"mode": spec["rollback"], "window_s": spec["window_s"]} if spec else None,
            "writable": not reasons, "reason": reasons[0] if reasons else None, "reasons": reasons}


# --------------------------------------------------------------------------------------
# what the Network app shows
# --------------------------------------------------------------------------------------


def _name(hub: "Hub", tool_id: str) -> str:
    tool = hub.get_tool(tool_id)
    return tool.name if tool else tool_id


def device_ids(hub: "Hub") -> list[str]:
    """Tools whose connection reads the network domain, plus devices that still have a snapshot."""
    ids = {c.id for c in connections.all_connections(hub) if "read" in connections.capabilities(c).get("network", [])}
    ids |= {s["tool_id"] for s in snapshots(hub)}
    return sorted(ids)


def network_flow(hub: "Hub", tool_id: str):
    return next((f for f in flows.all_flows(hub, tool_id) if f.domain == "network" and f.direction == "pull"), None)


def device_summary(hub: "Hub", tool_id: str, now: float | None = None) -> dict[str, Any]:
    now = now or time.time()
    conn = connections.get(hub, tool_id)
    snap = snapshot(hub, tool_id)
    record = (snap or {}).get("record") or {}
    device = record.get("device") or {}
    flow = network_flow(hub, tool_id)
    test = (conn.last_test if conn else None) or {}
    open_drift = drift(hub, tool_id, "open")
    last = last_backup(hub, tool_id)
    if conn is None:
        state = "none"
    elif not test:
        state = "untested"
    else:
        state = "ok" if test.get("ok") else "failing"
    failing = bool(flow and flow.last_result and not flow.last_result.get("ok"))
    status = write_status(hub, tool_id, now)
    return {
        "tool_id": tool_id, "name": _name(hub, tool_id), "kind": record.get("kind"),
        "vendor": device.get("vendor"), "model": device.get("model"), "version": device.get("version"),
        "hostname": device.get("hostname"), "management_address": device.get("management_address"),
        "connector": conn.kind if conn else None,
        "connection": {"state": "failing" if failing and state == "ok" else state, "tested_at": test.get("at"),
                       "detail": test.get("detail")},
        "flow": {"id": flow.id, "status": flow.status, "schedule_minutes": flow.schedule_minutes,
                 "last_run": flow.last_run, "ok": (flow.last_result or {}).get("ok"),
                 "error": ((flow.last_result or {}).get("error") or {}).get("message")} if flow else None,
        "snapshot": {"rev": snap["rev"], "revision": snap["revision"], "read_at": snap["read_at"],
                     "age_s": round(now - (snap["read_at"] or now)), "stale": stale(hub, snap, now),
                     "errors": len(record.get("errors") or [])} if snap else None,
        "counts": (snap or {}).get("counts") or counts({}),
        "drift": {"open": len(open_drift), "critical": sum(1 for d in open_drift if d["severity"] == "critical"),
                  "last_at": open_drift[0]["detected_at"] if open_drift else None},
        "backup": {"supported": can_backup(hub, tool_id), "count": len(backups(hub, tool_id)),
                   # its connector can put a backup back (a restore also needs the device writable: status["capable"])
                   "restore": bool(can_backup(hub, tool_id) and (_connector_class(hub, tool_id) or Connector)
                                   .implements("restore_backup")),
                   "last_at": last["taken_at"] if last else None,
                   "age_s": round(now - last["taken_at"]) if last else None},
        "write": status,
        "baseline": {**(baseline(hub, tool_id) or {}), **((snap or {}).get("baseline") or {})} or None,
    }


def devices(hub: "Hub") -> list[dict[str, Any]]:
    now = time.time()
    return [device_summary(hub, tool_id, now) for tool_id in device_ids(hub)]


def device_detail(hub: "Hub", tool_id: str) -> dict[str, Any] | None:
    """The summary plus the snapshot (rules with a one-line text each), the history and the baseline deviations."""
    if tool_id not in device_ids(hub):
        return None
    snap = snapshot(hub, tool_id)
    out = device_summary(hub, tool_id)
    record = (snap or {}).get("record")
    if record is not None:
        from ..connectors.netmodel import interface_names, rule_line

        names = interface_names(record)
        record = {**record, "rules": [{**r, "line": rule_line(r, names)} for r in record.get("rules") or []]}
    out.update({"record": record, "history": history(hub, tool_id),
                "baseline_deviations": baseline_deviations(hub, tool_id)})
    return out


def diff_text(hub: "Hub", tool_id: str, from_rev: int, to_rev: int | None = None) -> str:
    """A unified diff between two snapshot revisions (to_rev None: the current snapshot) - KeyError if unknown."""
    import difflib

    old = history_entry(hub, tool_id, from_rev)
    if to_rev is None:
        snap = snapshot(hub, tool_id)
        new = {"rev": snap["rev"], "record": snap["record"]} if snap else None
    else:
        new = history_entry(hub, tool_id, to_rev)
    if old is None or new is None:
        raise KeyError(f"{tool_id} rev {from_rev}..{to_rev}")
    return "\n".join(difflib.unified_diff(record_lines(old["record"]), record_lines(new["record"]),
                                          f"rev {old['rev']}", f"rev {new['rev']}", lineterm=""))


# --------------------------------------------------------------------------------------
# facts for the network compliance checks (hub/grc/checks.py) - ids only, never device text
# --------------------------------------------------------------------------------------


def compliance_facts(hub: "Hub", now: float | None = None) -> dict[str, Any]:
    from . import changes, segmentation

    now = now or time.time()
    out_devices = []
    for tool_id in device_ids(hub):
        snap = snapshot(hub, tool_id)
        if snap is None:
            continue
        record = snap["record"]
        rules = record.get("rules") or []
        # "pos" (the rule's place in evaluation order) is what control details name - they reach agents; "name" (the
        # device's own rule id, reduced to safe characters) only goes into the evidence lines people read
        refs = [{"pos": f"rule #{n}", "name": rule_ref(r)} for n, r in enumerate(rules, 1)]
        passing = [i for i, r in enumerate(rules) if r.get("enabled", True) and r.get("action") == "pass"]
        last = last_backup(hub, tool_id)
        out_devices.append({
            "tool_id": tool_id, "ref": display_id(tool_id), "kind": record.get("kind"), "read_at": snap["read_at"],
            "stale": stale(hub, snap, now),
            "management_exposed": [refs[i] for i, r in enumerate(rules) if exposes_management(record, r)],
            "any_any": [refs[i] for i, r in enumerate(rules) if is_any_any(r)],
            "pass_rules": len(passing),
            "undocumented_pass": [refs[i] for i in passing if not (rules[i].get("description") or "").strip()],
            "unlogged_pass": sum(1 for i in passing if not rules[i].get("log")),
            "backup_supported": can_backup(hub, tool_id), "last_backup_at": last["taken_at"] if last else None,
        })
    items = drift(hub)
    recent = [d for d in items if d["detected_at"] >= now - 30 * DAY]
    open_items = [d for d in items if d["status"] == "open"]
    return {
        "devices": out_devices,
        "drift": {"open": len(open_items),
                  "open_critical": sum(1 for d in open_items if d["kind"] in CRITICAL_DRIFT),
                  "open_devices": sorted({display_id(d["tool_id"]) for d in open_items}),
                  "oldest_open_at": min((d["detected_at"] for d in open_items), default=None),
                  "detected_30d": len(recent), "attributed_30d": sum(1 for d in recent if d["status"] == "attributed"),
                  "acknowledged_30d": sum(1 for d in recent if d["status"] == "acknowledged")},
        "segmentation": segmentation.compliance(hub),
        "changes": changes.compliance_facts(hub, now),
    }
