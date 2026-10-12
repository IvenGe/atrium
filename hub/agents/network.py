"""Network Supervisor (module:network): the Network app - device snapshots, history, drift, configuration backups,
the segmentation map's data and the network compliance evidence.

It runs the ``network`` pull flows (one per device connection), stores each read through ``integration.network``
(``ingest``), takes scheduled and manual configuration backups through the device's tool supervisor (subject
``network.backup``: the content is encrypted and stored there and never travels on the bus), and re-evaluates
compliance when a configuration changed. Device changes are made only by this agent, only for approved changes
(R3-NETCHANGE builds on ``read_device``, ``store_snapshot`` and ``take_backup``).
"""

from __future__ import annotations

import time
from typing import Any

from ..bus import AgentError, Message
from ..integration import flows, network, segmentation
from ..models import Flow
from .fabric import FlowFailure, FlowOwner


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

    # -- reading devices ---------------------------------------------------------------

    async def read_device(self, tool_id: str) -> dict[str, Any]:
        """A fresh normalised record of the device (a new connection through its tool supervisor); FlowFailure when
        it cannot be read."""
        reply = await self.connector(tool_id, "pull", {"domain": "network"})
        records = list(reply.get("records") or [])
        if not records:
            detail = "; ".join(reply.get("errors") or []) or "the connector returned no device record"
            raise FlowFailure(f"No usable device record: {detail}")
        return records[0]

    async def store_snapshot(self, tool_id: str, record: dict[str, Any], cause: str | None = None) -> dict[str, Any]:
        """Store a read as the device's snapshot (drift attributed to `cause`, a change id, when given) and tell
        the segmentation map and the GRC Supervisor."""
        result = network.ingest(self.hub, tool_id, record, cause=cause)
        segmentation.changed(self.hub, [tool_id])
        if result["changed"]:
            await self.tell("module:grc", "evaluate")
        return result

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.direction != "pull":
            raise ValueError("Network flows only read devices")
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
