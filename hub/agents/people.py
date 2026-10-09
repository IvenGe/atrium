"""People Supervisor: keeps the People app (the workforce directory) in step with the directories and tools, links
people to their assets and accounts, and reports leavers who still have access or company devices."""

from __future__ import annotations

from typing import Any

from .. import people
from ..bus import Message
from ..models import Flow
from .fabric import FlowOwner


class PeopleSupervisor(FlowOwner):
    role = "module-supervisor"
    title = "People Supervisor"
    description = ("Responsible for the People app: merges people from directories such as Okta, Keycloak or SCIM (by "
                   "email, then login), reads the accounts people hold in tools, links people to the assets they own or "
                   "use, and reports leavers who still have access or company devices - with one-click actions to "
                   "unassign their assets or disable their Atrium account.")
    flow_domains = ("people", "accounts")
    permissions = ("read", "tool_api", "flows", "assets_write", "agents")

    def __init__(self, hub):
        super().__init__(hub, "module:people", "People Supervisor", scope="people")
        self._reported: set[tuple[str, str]] = set()  # (person id, severity) already reported

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.direction != "pull":
            raise ValueError(f"People flows only pull (not {flow.direction})")
        records, info = await self.pull_records(flow)
        retire = flow.options.get("retire_missing", True)
        if flow.domain == "people":
            counts = people.apply_people(self.hub, flow.tool_id, records, retire)
        else:
            counts = people.apply_accounts(self.hub, flow.tool_id, records, retire)
        counts["dropped"] = info["dropped"]
        linked = people.relink(self.hub)
        if linked["assets"]:
            counts["assets_linked"] = linked["assets"]
        await self.check_leavers()
        await self.tell("module:grc", "evaluate")
        detail = f"{info['dropped']} record(s) could not be read: {'; '.join(info['errors'][:3])}" if info["dropped"] else ""
        return {"counts": counts, "detail": detail}

    async def check_leavers(self) -> list[dict[str, Any]]:
        """Report new leaver findings once each (and again when one gets worse)."""
        findings = people.leavers(self.hub)
        current = {(f["person_id"], f["severity"]) for f in findings}
        fresh = [f for f in findings if (f["person_id"], f["severity"]) not in self._reported]
        self._reported = current
        for f in fresh:
            offer = "; ".join(a["title"] for a in f["actions"])
            self.log("warn", f"Leaver: {f['summary']}" + (f" - one-click: {offer}" if offer else "")
                     + (f"; to do in the tools: {'; '.join(f['todo'][:3])}" if f["todo"] else ""),
                     person_id=f["person_id"])
        return findings

    async def on_leavers(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return {"leavers": await self.check_leavers()}

    async def on_relink(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        result = people.relink(self.hub)
        if result["assets"] or result["accounts"]:
            await self.tell("module:grc", "evaluate")
        return result

    async def on_summary(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        everyone = people.all_people(self.hub)
        findings = people.leavers(self.hub)
        return {
            "total": len(everyone),
            "by_status": {s: sum(1 for p in everyone if p.status == s) for s in ("active", "suspended", "terminated")},
            "accounts": len(people.all_accounts(self.hub)),
            "without_email": sum(1 for p in everyone if not p.email),
            "leavers": [f["summary"] for f in findings[:10]],
            "leavers_count": len(findings),
        }
