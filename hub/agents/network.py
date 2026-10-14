"""Network Supervisor (module:network): the Network app - device snapshots, history, drift, configuration backups,
the segmentation map's data and the network compliance evidence.

It runs the ``network`` pull flows (one per device connection), stores each read through ``integration.network``
(``ingest``), takes scheduled and manual configuration backups through the device's tool supervisor (subject
``network.backup``: the content is encrypted and stored there and never travels on the bus), and re-evaluates
compliance when a configuration changed.

Device changes (``integration/changes.py``, canvas-design 6.6 / 7.7): only this agent changes devices, only for
approved changes, through the tool supervisor's ``network.*`` subjects. Subjects it handles:

``change.propose``    {request} from a person (operator or administrator; the role is looked up, never taken from
                      the message): fresh read, plan, policy (S11), anti-lockout (S12), the connector's own check, then
                      the proposal and its approval -> {change_id, approval_id} | {refused: {status, code, message}}
``approval.decided``  rejected -> "rejected"; approved -> applied now, or "scheduled" for the next maintenance window
``change.advance``    {change_id}: apply an approved / scheduled change when it may go (e.g. after an emergency)
``changes.tick``      every scheduler pass: expiry (S7), the kill switch (S14), scheduled changes whose window opened,
                      and changes left verifying (the device's own rollback timer, a hub restart)

Applying (S6-S9): fresh read (another revision -> "stale"), Atrium's pre-change backup (guardrail
device_changes_need_backup: no backup, no change), apply, then verification over new connections (connection test
and a re-read that shows the change) before confirming within the rollback window; otherwise roll back, prove it with
a re-read, and when that fails restore the pre-change backup and alert.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any

from .. import guardrails
from ..approvals import sender_person
from ..bus import AgentError, Message
from ..connectors.netmodel import ops_applied, untrusted_text
from ..integration import changes, flows, maintenance, network, segmentation
from ..integration.changes import ChangeRefused
from ..models import Flow
from .fabric import FlowFailure, FlowOwner


def safe_device_text(value: Any, limit: int) -> str:
    """Device-provided text in the reduced form agents may read: safe characters only, cut to `limit`."""
    return re.sub(r"[^A-Za-z0-9 .,:;_()/-]+", "_", str(value))[:limit]

TIMED = ("savepoint", "deadman", "commit_confirm")
CONFIRM_MARGIN = 2.0  # seconds: never confirm this close to the device's own rollback deadline
STUCK_APPLYING = 900  # seconds: a change "applying" this long (a hub restart) is settled


class NetworkSupervisor(FlowOwner):
    role = "module-supervisor"
    title = "Network Supervisor"
    description = ("Responsible for the Network app: reads firewalls, routers, switches and host firewalls through "
                   "their connectors, keeps configuration snapshots and their history, reports drift (changes not made "
                   "through Atrium), keeps encrypted configuration backups, and feeds the segmentation map and the "
                   "network compliance controls. It changes devices only for approved changes.")
    flow_domains = ("network",)
    permissions = ("read", "tool_api", "flows", "grc_write")

    def __init__(self, hub):
        super().__init__(hub, "module:network", "Network Supervisor", scope="network")
        self._change_locks: dict[str, asyncio.Lock] = {}
        self._busy: set[str] = set()  # changes this agent is applying or verifying right now

    # -- reading devices ---------------------------------------------------------------

    async def read_device(self, tool_id: str) -> dict[str, Any]:
        """A fresh normalised record of the device (a new connection through its tool supervisor); FlowFailure when
        it cannot be read."""
        try:
            reply = await self.connector(tool_id, "pull", {"domain": "network"})
        except FlowFailure as exc:
            # the failure may quote the device (an error message, the answer's body): agents and models read the flow
            # result, so only a reduced form of the message goes on, without the excerpt (review F22)
            raise FlowFailure(safe_device_text(exc.message, 300), status=exc.status) from exc
        records = list(reply.get("records") or [])
        if not records:
            # validation messages may quote device text: only a reduced form reaches the flow result agents read
            errors = [safe_device_text(e, 160) for e in reply.get("errors") or []][:3]
            raise FlowFailure("No usable device record: " + ("; ".join(errors) or "the connector returned none"))
        return records[0]

    async def store_snapshot(self, tool_id: str, record: dict[str, Any], cause: str | None = None,
                             cause_scope: str = "ops") -> dict[str, Any]:
        """Store a read as the device's snapshot (drift attributed to `cause`, a change id, when given; `cause_scope`
        "all" after a rollback or restore) and tell the segmentation map and the GRC Supervisor."""
        result = network.ingest(self.hub, tool_id, record, cause=cause, cause_scope=cause_scope)
        segmentation.changed(self.hub, [tool_id])
        if result["changed"]:
            await self.tell("module:grc", "evaluate")
        return result

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.direction != "pull":
            raise ValueError("Network flows only read devices")
        async with self._lock(flow.tool_id):  # never between a change's apply and its verification read (F23)
            record = await self.read_device(flow.tool_id)
            result = await self.store_snapshot(flow.tool_id, record)
        snap_counts = network.counts(record)
        counts = {"rules": snap_counts["rules"], "interfaces": snap_counts["interfaces"],
                  "changed": int(result["changed"]), "drift": len(result["drift"]),
                  "unexplained": result["unexplained"], "dropped": snap_counts["errors"]}
        detail = f"Snapshot rev {result['rev']}" + (" (changed)" if result["changed"] else " (unchanged)")
        if network.backup_due(self.hub, flow.tool_id):
            try:
                await self.take_backup(flow.tool_id, "scheduled", self.id)
                counts["backups"] = 1
            except ValueError as exc:  # a failed backup is reported, the read still counts
                self.log("warn", f"Scheduled backup of {self._name(flow.tool_id)} failed: {exc}", tool_id=flow.tool_id)
        return {"counts": counts, "detail": detail}

    # -- backups -------------------------------------------------------------------------

    async def take_backup(self, tool_id: str, reason: str, actor: str, change_id: str | None = None) -> dict[str, Any]:
        """Back the device's configuration up (stored encrypted by its tool supervisor); the metadata, or
        ValueError with a message a person can act on."""
        if not network.can_backup(self.hub, tool_id):
            raise ValueError(f"{self._name(tool_id)} cannot take configuration backups with its connector")
        try:
            reply = await self.ask(f"tool:{tool_id}", "network.backup",
                                   {"reason": reason, "actor": actor, "change_id": change_id}, timeout=900)
        except AgentError as exc:
            raise ValueError(f"The tool's supervisor could not take the backup: {exc}") from exc
        if reply.get("failure"):
            raise ValueError(reply["failure"].get("message") or "The backup failed")
        return reply["backup"]

    async def on_backup_take(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """{tool_id, reason ("manual"), actor} -> {"backup": metadata}."""
        tool_id = str(body.get("tool_id") or "")
        if tool_id not in network.device_ids(self.hub):
            raise ValueError(f"'{tool_id}' is not a network device")
        reason = str(body.get("reason") or "manual")
        if reason not in ("manual", "scheduled"):
            raise ValueError("Backups taken on request are manual or scheduled")
        return {"backup": await self.take_backup(tool_id, reason, str(body.get("actor") or msg.sender))}

    # -- refresh -------------------------------------------------------------------------

    async def on_refresh(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Run the network flows of the given devices now ({tool_ids}: all devices when empty). Flows that are not
        enabled are skipped and listed."""
        wanted = [str(t) for t in body.get("tool_ids") or []] or network.device_ids(self.hub)
        started, skipped, results = [], [], []
        for tool_id in wanted:
            flow = network.network_flow(self.hub, tool_id)
            if flow is None or flow.status != "enabled":
                skipped.append({"tool_id": tool_id, "reason": "no enabled network data flow" if flow is None
                                else f"the network data flow is {flow.status}"})
                continue
            started.append(flow.id)
            results.append(await self.on_flow_run({"flow_id": flow.id, "trigger": "manual"}, msg))
        return {"started": started, "skipped": skipped,
                "results": [{"ok": r.get("ok"), "detail": r.get("detail"), "error": r.get("failure"),
                             "flow_id": (r.get("flow") or {}).get("id")} for r in results]}

    def _name(self, tool_id: str) -> str:
        tool = self.hub.get_tool(tool_id)
        return tool.name if tool else tool_id

    async def on_summary(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Counts only (no device text): what agents may read about the network."""
        devices = network.devices(self.hub)
        return {"devices": len(devices), "stale": sum(1 for d in devices if (d["snapshot"] or {}).get("stale", True)),
                "open_drift": sum(d["drift"]["open"] for d in devices),
                "critical_drift": sum(d["drift"]["critical"] for d in devices),
                "writable": sum(1 for d in devices if d["write"]["writable"]),
                "flows": [f.id for f in flows.all_flows(self.hub) if f.domain == "network"], "at": time.time()}

    # -- device changes: proposals -------------------------------------------------------

    def _lock(self, tool_id: str) -> asyncio.Lock:
        return self._change_locks.setdefault(tool_id, asyncio.Lock())

    async def on_change_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """{request} -> {change_id, approval_id} or {refused: {status, code, message, ...}}. Only people propose
        changes; their role comes from the user store."""
        role = changes.principal_role(self.hub, msg.sender)
        if role not in ("operator", "admin"):
            return {"refused": ChangeRefused(403, "forbidden", "Only operators and administrators propose device "
                                                               "changes").as_dict()}
        try:
            change = await self.propose(dict(body.get("request") or {}), sender_person(msg.sender) or msg.sender, role)
        except ChangeRefused as exc:
            return {"refused": exc.as_dict()}
        return {"change_id": change["id"], "approval_id": change["approval_id"]}

    async def propose(self, request: dict[str, Any], actor: str, role: str) -> dict[str, Any]:
        hub = self.hub
        op = request.get("op")
        original = None
        if op == "restore":
            meta = network.get_backup(hub, str(request.get("backup_id") or ""))
            if meta is None:
                raise ChangeRefused(404, "not_found", "Backup not found")
            request["firewall"] = meta["tool_id"]
        elif op == "revert":
            original = changes.get(hub, str(request.get("revert_of") or ""))
            if original is None:
                raise ChangeRefused(404, "not_found", "Change not found")
            request["firewall"] = original["firewall"]
        elif op not in ("allow", "disable_rules"):
            raise ChangeRefused(422, "invalid", f"op is one of {', '.join(changes.OPS)}")
        tool_id = str(request.get("firewall") or "")
        if tool_id not in network.device_ids(hub):
            raise ChangeRefused(404, "not_found", "Network device not found")
        if not guardrails.value(hub, "device_changes"):
            changes.check_writable({"reasons": ["guardrail"]})
        effective, kinds = op, [op]
        if original is not None:
            effective = "restore" if original["op"] == "restore" else "revert"
            kinds = sorted({"disable_rules" if o["op"] in ("allow", "enable_rules") else "enable_rules"
                            for o in original["ops"]})
        changes.check_writable(changes.write_state(hub, tool_id, effective, kinds))
        async with self._lock(tool_id):
            try:
                record = await self.read_device(tool_id)
            except FlowFailure as exc:
                raise ChangeRefused(502, "device_unreachable", f"The device could not be read: {exc.message}") from exc
            await self.store_snapshot(tool_id, record)
            if request.get("base_revision") and record.get("revision") != request["base_revision"]:
                raise ChangeRefused(409, "stale_snapshot", "The device's rules changed since the preview - preview the "
                                                           "change again")
            if original is not None:
                request = {**request, **changes.revert_request(hub, original, record)}
            change_id = changes.new_change_id()
            planned = changes.plan(hub, request, change_id, record)
            if planned["problems"]:
                raise ChangeRefused(422, "lockout", "; ".join(planned["problems"]), problems=planned["problems"])
            changes.check_policy(planned["violations"], role, request.get("justification"),
                                 unknown=bool(planned.get("policy_unknown")))
            device: dict[str, Any] = {}
            if planned["ops"]:
                reply = await self._device(tool_id, "network.preview", {"ops": planned["ops"]}, timeout=300)
                failure = reply.get("failure")
                if failure:
                    raise ChangeRefused(502, "device_error", f"The device's connector could not check the change: "
                                                             f"{failure.get('message')}")
                if reply.get("problems"):
                    raise ChangeRefused(422, "device_refused", "The device's connector refuses the change: "
                                        + "; ".join(reply["problems"][:5]), problems=reply["problems"])
                device = reply
            state = changes.write_state(hub, tool_id, request["op"], changes.needed_kinds(request["op"], planned["ops"]))
            change = changes.create(hub, change_id=change_id, request=request, record=record, planned=planned,
                                    actor=actor, rollback=state["rollback"] if request["op"] != "restore" else None,
                                    device=device)
        return change

    # -- device changes: decisions, scheduling, applying ---------------------------------

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(str(body.get("approval_id") or ""))
        if approval is None or approval.kind != "firewall":
            return
        change = changes.get(self.hub, str(approval.payload.get("change_id") or ""))
        if change is None or change["status"] != "proposed":
            return
        if approval.status != ("approved" if body.get("approved") else "rejected"):
            return  # only the approval queue's own record counts, never a message claiming a decision
        actor = str(approval.decided_by or msg.sender)
        if not body.get("approved"):
            changes.finish(self.hub, change, "rejected", actor, body.get("note"))
            return
        change.update({"decided_by": approval.decided_by, "decided_at": approval.decided_at,
                       "self_approved": changes.decided_by_proposer(self.hub, change, approval)})
        changes.save(self.hub, change, "approved", actor)
        self.log("info", f"Device change {change['id']} approved by {actor}", change_id=change["id"])
        await self.advance(change["id"])

    async def on_change_advance(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        change = await self.advance(str(body.get("change_id") or ""))
        return {"status": (change or {}).get("status")}

    async def advance(self, change_id: str, now: float | None = None) -> dict[str, Any] | None:
        """Apply an approved or scheduled change when it may go now: still bound to its approval, device changes
        on, inside a maintenance window (unless an emergency) and no other change of the device being applied."""
        change = changes.get(self.hub, change_id)
        if change is None:
            return None
        async with self._lock(change["firewall"]):
            change = changes.get(self.hub, change_id)
            if change is None or change["status"] not in changes.DECIDED:
                return change
            now = time.time() if now is None else now
            problem = changes.binding_problem(self.hub, change, now)
            if problem:
                return changes.finish(self.hub, change, problem[0], note=problem[1])
            if guardrails.value(self.hub, changes.WINDOW_GUARD) and not change.get("emergency"):
                window = maintenance.active(self.hub, change["firewall"], now)
                if window is None:
                    return self._schedule(change, now)
                change["window"] = window
            busy = [c for c in changes.listing(self.hub, change["firewall"])
                    if c["status"] in changes.ACTIVE and c["id"] != change_id]
            if busy:
                return change  # the next scheduler pass tries again
            result = await self._execute(change)
        await self.tell("module:grc", "evaluate")  # HB-CM-3 and the network controls follow the outcome
        return result

    def _schedule(self, change: dict[str, Any], now: float) -> dict[str, Any]:
        upcoming = maintenance.next_start(self.hub, change["firewall"], now)
        start = upcoming["start"] if upcoming else None
        # the next window opens only after the approval expired: it would expire while waiting - say so now
        late = bool(start and start >= float(change.get("expires_at") or 0))
        if change["status"] == "scheduled" and change.get("scheduled_for") == start:
            return change
        change.update({"scheduled_for": start, "window": upcoming, "expires_before_window": late})
        when = (f"the maintenance window '{upcoming['name']}' at "
                f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(start))}" if upcoming
                else "a maintenance window (none covers this device yet - an administrator adds one in Settings)")
        if late:
            when += (" - but the approval expires before that window opens: an administrator applies it now as an "
                     "emergency, or it is proposed again closer to the window")
        changes.save(self.hub, change, "scheduled", note=f"waits for {when}")
        self.log("warn" if late else "info", f"Device change {change['id']} on "
                 f"{changes.tool_name(self.hub, change['firewall'])} waits for {when}", change_id=change["id"])
        return change

    async def _device(self, tool_id: str, subject: str, body: dict[str, Any], timeout: float = 600) -> dict[str, Any]:
        try:
            return await self.ask(f"tool:{tool_id}", subject, body, timeout)
        except AgentError as exc:
            return {"failure": {"message": str(exc), "status": None, "code": "failed", "state": "unknown"}}

    async def _try_read(self, tool_id: str) -> dict[str, Any] | None:
        try:
            return await self.read_device(tool_id)
        except FlowFailure:
            return None

    def _same_base(self, change: dict[str, Any], record: dict[str, Any]) -> bool:
        from ..connectors.netmodel import record_hash

        if change.get("base_revision"):
            return record.get("revision") == change["base_revision"]
        return record_hash(record) == change.get("base_hash")

    async def _execute(self, change: dict[str, Any]) -> dict[str, Any]:
        hub, cid, tool_id = self.hub, change["id"], change["firewall"]
        self._busy.add(cid)
        try:
            record = await self._try_read(tool_id)
            if record is None:
                return changes.finish(hub, change, "failed", note="the device could not be read before applying; "
                                      "nothing was changed", result={"ok": False, "state": "unchanged"})
            await self.store_snapshot(tool_id, record)
            change = changes.get(hub, cid) or change
            if not self._same_base(change, record):  # S6
                return changes.finish(hub, change, "stale", note="the device's rules changed since the proposal; "
                                      "nothing was applied - propose it again", result={"ok": False, "state": "unchanged"})
            problem = changes.binding_problem(hub, change)
            if problem:
                return changes.finish(hub, change, problem[0], note=problem[1])
            emergency = " (emergency)" if change.get("emergency") else ""
            changes.save(hub, change, "applying", note="applying" + emergency)
            if guardrails.value(hub, changes.BACKUP_GUARD):
                try:
                    meta = await self.take_backup(tool_id, "pre-change", self.id, change_id=cid)
                except ValueError as exc:
                    return changes.finish(hub, changes.get(hub, cid) or change, "failed",
                                          note=f"the backup before the change failed, so nothing was changed: {exc}",
                                          result={"ok": False, "state": "unchanged"})
                change = changes.get(hub, cid) or change
                change["backup_id"] = meta["id"]
                changes.save(hub, change)
            restore = change["op"] == "restore"
            reply = await self._device(tool_id, "network.restore" if restore else "network.apply", {"change_id": cid})
            change = changes.get(hub, cid) or change
            failure = reply.get("failure")
            if failure:
                code, state = failure.get("code") or "failed", failure.get("state") or "unknown"
                message = untrusted_text(failure.get("message"), 300)
                if state == "unchanged":
                    return changes.finish(hub, change, "stale" if code == "stale" else "failed",
                                          note=f"the device refused the change ({code}): {message}; nothing was changed",
                                          result={"ok": False, "state": "unchanged", "code": code})
                return await self._undo(change, f"applying failed ({code}): {message}", connector_state=state)
            applied = reply.get("applied") or {"notes": reply.get("notes") or []}
            mode = (change.get("rollback") or {}).get("mode")
            window_s = (change.get("rollback") or {}).get("window_s") or 60
            until = applied.get("rollback_until") or (time.time() + window_s if mode in TIMED else None)
            change.update({"applied": applied, "rollback_until": until})
            changes.save(hub, change, "verifying", note="verifying" + (f" (rollback by the device at "
                                                                         f"{time.strftime('%H:%M:%S', time.gmtime(until))} UTC)"
                                                                         if until else ""))
            checks, after = await self._verify(change)
            change = changes.get(hub, cid) or change
            change["verification"] = checks
            changes.save(hub, change)
            failed = [c for c in checks if not c["ok"]]
            if failed:
                return await self._undo(change, "verification failed: " + "; ".join(f"{c['name']}: {c['detail']}"
                                                                                   for c in failed))
            if until and mode in TIMED and time.time() > until - CONFIRM_MARGIN:
                return await self._undo(change, "the checks ended too close to the device's rollback deadline, so "
                                                "it was not confirmed")
            # a restore has no device-side rollback to confirm: Atrium's pre-change backup is its way back
            reply = {} if restore else await self._device(tool_id, "network.confirm", {"change_id": cid}, timeout=120)
            change = changes.get(hub, cid) or change
            failure = reply.get("failure")
            if failure or not reply.get("confirmed", True):
                state = (failure or {}).get("state") or "unknown"
                return await self._undo(change, "the device did not confirm the change: "
                                        + untrusted_text((failure or {}).get("message"), 300), connector_state=state)
            applied_at = time.time()
            if after is not None:
                await self.store_snapshot(tool_id, after, cause=cid, cause_scope="all" if restore else "ops")
            change = changes.get(hub, cid) or change
            change["applied_at"] = applied_at
            if change.get("revert_of"):
                original = changes.get(hub, change["revert_of"])
                if original is not None:
                    original["reverted_by"] = cid
                    changes.save(hub, original)
            verified = "verified over a new connection" + ("" if restore else " and confirmed")
            result = {"ok": True, "state": "applied", "method": "restored" if restore else "confirmed", "detail": verified}
            return changes.finish(hub, change, "applied", note=verified + emergency, result=result)
        finally:
            self._busy.discard(cid)

    async def _verify(self, change: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        """S9 over new connections: the device still answers (connection test), and a re-read shows the change."""
        tool_id = change["firewall"]
        window_s = (change.get("rollback") or {}).get("window_s") or 60
        checks = []
        try:
            test = await self.ask(f"tool:{tool_id}", "connector.test", {}, timeout=max(30, window_s))
        except AgentError as exc:
            test = {"ok": False, "detail": str(exc)}
        checks.append({"name": "connection", "ok": bool(test.get("ok")),
                       "detail": untrusted_text(test.get("detail"), 300) or ("ok" if test.get("ok") else "failed")})
        if not test.get("ok"):
            return checks, None
        try:
            after = await self.read_device(tool_id)
        except FlowFailure as exc:
            checks.append({"name": "rules", "ok": False, "detail": f"the device could not be read again: {exc.message}"})
            return checks, None
        problems = [] if change["op"] == "restore" else ops_applied(after, change["ops"])
        checks.append({"name": "rules", "ok": not problems,
                       "detail": "; ".join(problems) or ("the device answers with the restored configuration"
                                                        if change["op"] == "restore" else "the re-read shows the change")})
        await self.store_snapshot(tool_id, after, cause=change["id"],
                                  cause_scope="all" if change["op"] == "restore" else "ops")
        return checks, after

    async def _undo(self, change: dict[str, Any], reason: str, connector_state: str | None = None) -> dict[str, Any]:
        """Roll a change back and prove it with a re-read; when the device's own rollback did not revert it, restore
        Atrium's pre-change backup; when even that cannot be proven, wait for a device-side timer or alert."""
        hub, cid, tool_id = self.hub, change["id"], change["firewall"]
        notes, method = [reason], None
        if change["op"] != "restore" and connector_state != "rolled_back":
            reply = await self._device(tool_id, "network.rollback", {"change_id": cid}, timeout=300)
            if reply.get("failure"):
                notes.append("the device's rollback failed: " + untrusted_text(reply["failure"].get("message"), 300))
            else:
                method = reply.get("method")
        after = await self._try_read(tool_id)
        change = changes.get(hub, cid) or change
        if after is not None and not changes.reverted(change, after):
            await self.store_snapshot(tool_id, after, cause=cid, cause_scope="all")
            return changes.finish(hub, changes.get(hub, cid) or change, "rolled_back", note="; ".join(notes),
                                  result={"ok": False, "state": "rolled_back", "method": method or "device",
                                          "detail": "; ".join(notes)})
        if change.get("backup_id"):
            reply = await self._device(tool_id, "network.restore", {"change_id": cid, "recover": True}, timeout=600)
            if reply.get("failure"):
                notes.append("restoring the backup taken before the change failed: "
                             + untrusted_text(reply["failure"].get("message"), 300))
            else:
                after = await self._try_read(tool_id)
                change = changes.get(hub, cid) or change
                if after is not None and not changes.reverted(change, after):
                    await self.store_snapshot(tool_id, after, cause=cid, cause_scope="all")
                    notes.append(f"Atrium restored the backup {change['backup_id']} taken before the change")
                    return changes.finish(hub, change, "rolled_back", note="; ".join(notes),
                                          result={"ok": False, "state": "rolled_back", "method": "backup_restore",
                                                  "detail": "; ".join(notes)}, level="error")
                notes.append("after restoring the backup the device still does not show its previous state")
        change = changes.get(hub, cid) or change
        mode = (change.get("rollback") or {}).get("mode")
        until = change.get("rollback_until")
        if mode in TIMED and until and time.time() < until + changes.REVERT_GRACE:
            change["awaiting_revert"] = True
            change["result"] = {"ok": False, "state": "reverting", "method": mode, "detail": "; ".join(notes)}
            changes.save(hub, change, note="waiting for the device's own rollback timer")
            self.log("warn", f"Device change {cid} on {changes.tool_name(hub, tool_id)} could not be rolled back "
                             f"directly; waiting for the device's own rollback ({mode})", change_id=cid)
            return change
        return changes.finish(hub, change, "failed", note="the device's state is unknown - check it and restore a "
                              "backup if needed: " + "; ".join(notes),
                              result={"ok": False, "state": "unknown", "method": method, "detail": "; ".join(notes)},
                              level="error")

    # -- device changes: the scheduler pass -----------------------------------------------

    async def on_changes_tick(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Expiry, kill switch, scheduled changes whose window opened, changes left verifying. `now` is honoured only
        from the hub itself (the scheduler and tests)."""
        now = float(body["now"]) if msg.sender == "hub" and isinstance(body.get("now"), (int, float)) else time.time()
        expired = changes.expire(self.hub, now)
        blocked = [] if guardrails.value(self.hub, "device_changes") else changes.kill_switch(self.hub, self.id)
        advanced, settled = [], []
        for change in changes.listing(self.hub):
            if change["status"] in changes.DECIDED:
                result = await self.advance(change["id"], now)
                if result is not None and result.get("status") != change["status"]:
                    advanced.append(change["id"])
            elif change["status"] in changes.ACTIVE and change["id"] not in self._busy and self._overdue(change, now):
                await self.settle(change["id"], now)
                settled.append(change["id"])
        return {"expired": expired, "blocked": blocked, "advanced": advanced, "settled": settled}

    @staticmethod
    def _overdue(change: dict[str, Any], now: float) -> bool:
        if change["status"] == "applying":
            return now - float(change.get("updated_at") or 0) > STUCK_APPLYING
        until = change.get("rollback_until")
        if until:
            return now >= until
        window_s = (change.get("rollback") or {}).get("window_s") or 60
        return now - float(change.get("updated_at") or 0) > window_s + changes.REVERT_GRACE

    async def settle(self, change_id: str, now: float | None = None) -> dict[str, Any] | None:
        """A change left applying / verifying (its rollback window passed, or the hub restarted): a re-read decides -
        reverted by the device -> rolled_back; still there unconfirmed -> roll it back; unreachable past the grace
        period -> failed (alert)."""
        now = time.time() if now is None else now
        change = changes.get(self.hub, change_id)
        if change is None:
            return None
        try:
            return await self._settle(change, now)
        finally:
            await self.tell("module:grc", "evaluate")

    async def _settle(self, change: dict[str, Any], now: float) -> dict[str, Any] | None:
        change_id = change["id"]
        async with self._lock(change["firewall"]):
            change = changes.get(self.hub, change_id)
            if change is None or change["status"] not in changes.ACTIVE or change_id in self._busy:
                return change
            self._busy.add(change_id)
            try:
                after = await self._try_read(change["firewall"])
                if after is not None and not changes.reverted(change, after):
                    await self.store_snapshot(change["firewall"], after, cause=change_id, cause_scope="all")
                    return changes.finish(self.hub, change, "rolled_back",
                                          note="the device reverted the unconfirmed change by itself",
                                          result={"ok": False, "state": "rolled_back",
                                                  "method": (change.get("rollback") or {}).get("mode") or "device"})
                if after is None:
                    if now < float(change.get("rollback_until") or 0) + changes.REVERT_GRACE:
                        return change
                    return changes.finish(self.hub, change, "failed", note="the device is still unreachable after its "
                                          "rollback window - check it at the console and restore a backup if needed",
                                          result={"ok": False, "state": "unknown"}, level="error")
                return await self._undo(change, "the change was not confirmed in time")
            finally:
                self._busy.discard(change_id)
