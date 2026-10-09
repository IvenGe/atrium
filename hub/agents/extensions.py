"""Extensions Supervisor: runs the data flows of extension domains ("x:alerts", "x:tickets", ...) and keeps their
records linked to assets and people."""

from __future__ import annotations

from typing import Any

from ..bus import Message
from ..extensions import records, registry
from ..models import Flow
from .fabric import FlowFailure, FlowOwner


class ExtensionSupervisor(FlowOwner):
    role = "module-supervisor"
    title = "Extensions Supervisor"
    description = ("Responsible for the apps extension packs add (alerts, tickets, incidents...): pulls their records "
                   "from the tools and pushes them to tools that take them, types them by the domain's fields, links "
                   "them to assets and people, and feeds their compliance rules.")
    permissions = ("read", "tool_api", "flows", "agents")

    def __init__(self, hub):
        super().__init__(hub, "module:extensions", "Extensions Supervisor", scope="extensions")

    def owns(self, domain: str) -> bool:
        return domain.startswith("x:")

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        key = flow.domain.removeprefix("x:")
        defn = registry.domain(self.hub, key)
        if defn is None:  # the pack was disabled (or extensions switched off): nothing to say about the tool
            raise FlowFailure(f"The extension domain '{key}' is not enabled", count=False)
        if flow.direction == "pull":
            pulled, info = await self.pull_records(flow)
            counts = records.apply_pulled(self.hub, defn, flow.tool_id, pulled, flow.options.get("retire_missing", True))
            counts["dropped"] += info["dropped"]
            await self.tell("module:grc", "evaluate")
            detail = (f"{info['dropped']} record(s) could not be read: {'; '.join(info['errors'][:3])}"
                      if info["dropped"] else "")
            return {"counts": counts, "detail": detail}
        if flow.direction == "push":
            pushed = records.push_records(self.hub, defn)
            return {"counts": await self.push_records(flow, pushed, label=lambda r: r.get("title") or r["hub_id"])}
        raise ValueError(f"The Extensions Supervisor cannot {flow.direction} {flow.domain}")

    async def on_relink(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Re-link the records of every active domain (or of `domain`) to assets and people."""
        wanted = body.get("domain")
        changed = {key: records.relink(self.hub, defn) for key, (defn, _) in registry.active_domains(self.hub).items()
                   if not wanted or key == wanted}
        if any(changed.values()):
            await self.tell("module:grc", "evaluate")
        return {"changed": changed}

    async def on_summary(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        out = {}
        for key, (defn, pack_id) in registry.active_domains(self.hub).items():
            items = records.all_records(self.hub, key)
            out[key] = {"title": defn.title, "extension": pack_id, "records": sum(1 for r in items if not r.stale),
                        "stale": sum(1 for r in items if r.stale),
                        "linked_to_assets": sum(1 for r in items if r.asset_id),
                        "linked_to_people": sum(1 for r in items if r.person_id)}
        return {"domains": out}
