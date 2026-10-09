"""Asset Supervisor: keeps the asset register in sync with the tools and hosts the hub knows about."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from typing import Any

from ..bus import Message
from ..models import Asset
from ..store import new_id
from .base import BaseAgent
from .operator import DISCOVERY_SCRIPT

LOCAL_SOURCE = "host:local"


def parse_discovery(output: str) -> dict[str, Any]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith("@@"):
            current = line[2:].strip()
            sections[current] = []
        elif current:
            sections[current].append(line.strip())
    facts: dict[str, Any] = {}
    os_release = dict(
        line.split("=", 1) for line in sections.get("os", []) if "=" in line
    )
    if os_release.get("PRETTY_NAME"):
        facts["os"] = os_release["PRETTY_NAME"].strip('"')
    for key in ("kernel", "hostname", "disk_root", "uptime"):
        if sections.get(key) and sections[key][0]:
            facts[key] = sections[key][0]
    for key in ("cpus", "memory_mb"):
        value = (sections.get(key) or [""])[0]
        if value.isdigit():
            facts[key] = int(value)
    return facts


class AssetSupervisor(BaseAgent):
    role = "module-supervisor"
    title = "Asset Supervisor"
    description = ("Responsible for the Assets app: registers every tool, SaaS service and host as an asset, "
                   "discovers host facts over SSH, and retires assets that disappear.")

    def __init__(self, hub):
        super().__init__(hub, "module:assets", "Asset Supervisor", scope="assets")

    def _assets(self) -> list[Asset]:
        return self.hub.all("assets", Asset)

    def _save(self, asset: Asset) -> Asset:
        asset.updated_at = time.time()
        return self.hub.save("assets", asset, "asset")

    async def on_sync(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        assets = self._assets()
        by_source = {a.source: a for a in assets}
        created = updated = retired = 0
        seen = {LOCAL_SOURCE}

        if LOCAL_SOURCE not in by_source:
            self._save(Asset(id=new_id("a_"), name=f"Hub server ({socket.gethostname()})", type="server",
                             criticality="high", source=LOCAL_SOURCE, facts=local_facts(), tags=["hub"]))
            created += 1

        for tool in self.hub.tools():
            source = f"tool:{tool.id}"
            seen.add(source)
            m = tool.manifest
            facts = {"source": tool.source, "kind": m.kind if m else None, "version": m.version if m else None,
                     "license": m.license if m else None, "stack": ", ".join(m.stack) if m else None,
                     "url": m.ui.url if m else None, "integration_score": tool.report.score if tool.report else None}
            facts = {k: v for k, v in facts.items() if v not in (None, "")}
            asset = by_source.get(source)
            if asset is None:
                asset = Asset(id=new_id("a_"), name=tool.name, source=source,
                              type="saas" if tool.source_type == "saas" else "software")
                created += 1
            elif asset.facts == {**asset.facts, **facts} and asset.status != "retired":
                continue
            else:
                updated += 1
            asset.facts = {**asset.facts, **facts}
            if asset.status == "retired":
                asset.status = "active"
            self._save(asset)

        for host in self.hub.hosts():
            source = f"host:{host.id}"
            seen.add(source)
            asset = by_source.get(source)
            facts = {"address": host.address, "ssh": f"{host.username}@{host.address}:{host.port}"}
            if asset is None:
                self._save(Asset(id=new_id("a_"), name=host.name, type="server", source=source, facts=facts, tags=host.tags))
                created += 1
            elif asset.status == "retired" or any(asset.facts.get(k) != v for k, v in facts.items()):
                asset.status, asset.facts = "active", {**asset.facts, **facts}
                self._save(asset)
                updated += 1

        for asset in assets:
            if asset.source.startswith(("tool:", "host:")) and asset.source not in seen and asset.status != "retired":
                asset.status = "retired"
                self._save(asset)
                retired += 1

        if created or updated or retired:
            self.log("info", f"Asset register synced: {created} new, {updated} updated, {retired} retired")
            await self.tell("module:grc", "evaluate")
        return {"created": created, "updated": updated, "retired": retired}

    async def on_discover(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        host_id = body.get("host_id") or "local"
        if host_id == "local":
            asset = next((a for a in self._assets() if a.source == LOCAL_SOURCE), None)
            if asset:
                asset.facts = {**asset.facts, **local_facts()}
                self._save(asset)
            return {"status": "done", "facts": local_facts()}
        host = self.hub.get_host(host_id)
        if host is None:
            raise ValueError(f"Unknown host '{host_id}'")
        result = await self.ask("operator", "run", {
            "target": host.id, "command": DISCOVERY_SCRIPT, "discovery": True, "timeout": 60,
            "reason": f"Read-only discovery of {host.name} for the asset register",
        })
        if result.get("status") != "done":
            return result
        if result.get("exit_code") not in (0, None) and "@@" not in result.get("output", ""):
            raise RuntimeError(result.get("output", "")[-300:] or "discovery failed")
        facts = parse_discovery(result.get("output", ""))
        asset = next((a for a in self._assets() if a.source == f"host:{host.id}"), None)
        if asset:
            asset.facts = {**asset.facts, **facts, "discovered_at": time.time()}
            self._save(asset)
        self.log("info", f"Discovered {host.name}: {facts.get('os', 'unknown OS')}, {facts.get('cpus', '?')} CPUs")
        return {"status": "done", "facts": facts}

    async def on_command_completed(self, body: dict[str, Any], msg: Message) -> None:
        """A discovery that needed approval has now run."""
        output = body.get("output", "")
        target = body.get("target")
        if body.get("status") != "done" or "@@" not in output or not target:
            return await super().on_command_completed(body, msg)
        asset = next((a for a in self._assets() if a.source == f"host:{target}"), None)
        if asset:
            asset.facts = {**asset.facts, **parse_discovery(output), "discovered_at": time.time()}
            self._save(asset)

    async def on_summary(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return summarize(self._assets())


def summarize(assets: list[Asset]) -> dict[str, Any]:
    active = [a for a in assets if a.status != "retired"]
    by_type: dict[str, int] = {}
    for a in active:
        by_type[a.type] = by_type.get(a.type, 0) + 1
    return {
        "total": len(active),
        "retired": len(assets) - len(active),
        "by_type": by_type,
        "without_owner": sum(1 for a in active if not a.owner),
        "critical": sum(1 for a in active if a.criticality == "critical"),
    }


def local_facts() -> dict[str, Any]:
    disk = shutil.disk_usage(os.path.abspath(os.sep))
    return {
        "os": f"{platform.system()} {platform.release()}",
        "kernel": platform.version(),
        "hostname": socket.gethostname(),
        "cpus": os.cpu_count(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "disk_root": f"{disk.free // 2**30} GiB free of {disk.total // 2**30} GiB",
    }
