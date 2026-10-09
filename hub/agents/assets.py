"""Asset Supervisor: keeps the asset register in sync with the tools and hosts the hub knows about, and runs the
asset data flows (pull from inventories such as Snipe-IT, push to tools that keep their own asset list)."""

from __future__ import annotations

import os
import platform
import shutil
import socket
import time
from typing import Any

from .. import people
from ..bus import Message
from ..connectors.base import valid_scan_target
from ..integration import flows
from ..models import Asset, Flow
from ..store import new_id
from .fabric import FlowOwner
from .operator import DISCOVERY_SCRIPT

LOCAL_SOURCE = "host:local"
ADDRESS_FACTS = ("address", "hostname", "fqdn", "ip", "ip_address")
SCALAR = (str, int, float, bool)


def addresses(asset: Asset) -> list[str]:
    """The IPs and hostnames an asset is known by (facts.addresses plus the usual single-address facts)."""
    found: list[str] = []
    listed = asset.facts.get("addresses")
    for value in [*(listed if isinstance(listed, list) else []), *(asset.facts.get(k) for k in ADDRESS_FACTS)]:
        text = str(value).strip().lower().rstrip(".") if isinstance(value, (str, int)) and value != "" else ""
        if text and text not in found:
            found.append(text)
    return found


def scan_targets(asset: Asset) -> list[str]:
    return [a for a in addresses(asset) if valid_scan_target(a)]


def merge_keys(asset_addresses: list[str], facts: dict[str, Any]) -> set[str]:
    keys = {a.lower().rstrip(".") for a in asset_addresses if a}
    for name in ("serial", "mac", "mac_address"):
        if isinstance(facts.get(name), SCALAR) and str(facts[name]).strip():
            keys.add(f"{name.split('_')[0]}:{str(facts[name]).strip().lower()}")
    return keys


def address_index(assets: list[Asset]) -> dict[str, str]:
    """address / serial key -> asset id, over assets that are not retired (first registered wins)."""
    index: dict[str, str] = {}
    for asset in sorted(assets, key=lambda a: a.created_at):
        if asset.status == "retired":
            continue
        for key in merge_keys(addresses(asset), asset.facts):
            index.setdefault(key, asset.id)
    return index


def push_record(asset: Asset) -> dict[str, Any]:
    """A hub asset as a canonical asset record for a tool (scalar facts only)."""
    facts = {k: v for k, v in asset.facts.items() if isinstance(v, SCALAR) and k not in ADDRESS_FACTS}
    return {"hub_id": asset.id, "external_id": None, "name": asset.name, "type": asset.type, "owner": asset.owner,
            "status": asset.status, "addresses": addresses(asset), "facts": facts, "updated_at": asset.updated_at,
            "criticality": asset.criticality}


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


class AssetSupervisor(FlowOwner):
    role = "module-supervisor"
    title = "Asset Supervisor"
    description = ("Responsible for the Assets app: registers every tool, SaaS service and host as an asset, "
                   "discovers host facts over SSH, retires assets that disappear, and runs the asset data flows - "
                   "merging assets pulled from inventories with known ones by address, hostname or serial.")
    flow_domains = ("assets",)

    permissions = ("read", "tool_api", "flows", "assets_write", "agents")

    def __init__(self, hub):
        super().__init__(hub, "module:assets", "Asset Supervisor", scope="assets")

    # -- data flows ------------------------------------------------------------------

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.direction == "pull":
            return await self._pull(flow)
        if flow.direction == "push":
            return await self._push(flow)
        raise ValueError(f"Asset flows cannot {flow.direction}")

    async def _pull(self, flow: Flow) -> dict[str, Any]:
        records, info = await self.pull_records(flow)
        tool_id, source = flow.tool_id, f"sync:{flow.tool_id}"
        known = flows.links(self.hub, tool_id, "assets")
        by_external = {link.external_id: hub_id for hub_id, link in known.items()}
        assets = {a.id: a for a in self._assets()}
        index = address_index(list(assets.values()))
        counts = {"total": len(records), "created": 0, "updated": 0, "merged": 0, "unchanged": 0, "retired": 0,
                  "dropped": info["dropped"]}
        seen: set[str] = set()
        for record in records:
            digest = flows.content_hash(record)
            external = record["external_id"]
            asset = assets.get(by_external.get(external, ""))
            if asset is not None:
                link = known.get(asset.id)
                if link and link.hash == digest and asset.status != "retired":
                    counts["unchanged"] += 1
                    seen.add(asset.id)
                    continue
            else:  # not linked yet: the same machine may already be registered under another source
                match = next((index[k] for k in merge_keys(record["addresses"], record["facts"]) if k in index), None)
                candidate = assets.get(match or "")
                asset = candidate if candidate is not None and candidate.id not in seen else None
            if asset is None:
                asset = Asset(id=new_id("a_"), name=record["name"], source=source)
                counts["created"] += 1
            elif asset.source == source:
                counts["updated"] += 1
            else:
                counts["merged"] += 1
            self._apply_record(asset, record, tool_id, owned=asset.source == source)
            self._save(asset)
            assets[asset.id] = asset
            for key in merge_keys(addresses(asset), asset.facts):
                index.setdefault(key, asset.id)
            flows.put_link(self.hub, tool_id, "assets", asset.id, external, digest)
            seen.add(asset.id)
        if flow.options.get("retire_missing", True):
            for hub_id in set(known) - seen:
                asset = assets.get(hub_id)
                if asset is None or asset.source != source:  # gone, or merged into an asset the hub knew anyway
                    flows.drop_link(self.hub, tool_id, "assets", hub_id)
                elif asset.status != "retired":  # the link stays, so the asset comes back if the record does
                    asset.status = "retired"
                    self._save(asset)
                    counts["retired"] += 1
        linked = people.link_assets(self.hub)  # devices to the people they are checked out to
        if linked:
            counts["people_linked"] = linked
            await self.tell("module:people", "leavers")  # a device checked out to someone who has left
        if counts["created"] or counts["updated"] or counts["merged"] or counts["retired"] or linked:
            await self.tell("module:grc", "evaluate")
        detail = f"{info['dropped']} record(s) could not be read: {'; '.join(info['errors'][:3])}" if info["dropped"] else ""
        return {"counts": counts, "detail": detail}

    @staticmethod
    def _apply_record(asset: Asset, record: dict[str, Any], tool_id: str, owned: bool) -> None:
        """Copy a pulled record onto an asset. Assets this flow created follow the tool; assets the hub already knew
        (merged by address, hostname or serial) keep their name, type and status and gain the tool's facts."""
        merged_addresses = addresses(asset)
        for value in record["addresses"]:
            if value.lower() not in merged_addresses:
                merged_addresses.append(value.lower())
        external_ids = {**(asset.facts.get("external_ids") or {}), tool_id: record["external_id"]}
        kept = {k: v for k, v in asset.facts.items() if k not in people.ASSIGNMENT_FACTS}  # the tool says who has it now
        asset.facts = {**kept, **record["facts"], "addresses": merged_addresses, "external_ids": external_ids}
        if owned:
            asset.name, asset.type, asset.status = record["name"], record["type"], record["status"]  # type: ignore[assignment]
            asset.owner = record["owner"] or asset.owner
        elif not asset.owner and record["owner"]:
            asset.owner = record["owner"]

    async def _push(self, flow: Flow) -> dict[str, Any]:
        types = set(flow.options.get("asset_types") or [])
        records = [push_record(a) for a in self._assets()
                   if a.status != "retired" and a.source != f"sync:{flow.tool_id}" and (not types or a.type in types)]
        return {"counts": await self.push_records(flow, records)}

    async def on_scan_scope(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Put assets in (or take them out of) vulnerability-scan scope."""
        ids, in_scope = set(body.get("asset_ids") or []), bool(body.get("in_scope"))
        changed, unscannable = [], []
        for asset in self._assets():
            if asset.id not in ids or asset.scan_scope == in_scope:
                continue
            asset.scan_scope = in_scope
            self._save(asset)
            changed.append(asset.id)
            if in_scope and not scan_targets(asset):
                unscannable.append(asset.name)
        if changed:
            self.log("info", f"{len(changed)} asset(s) {'added to' if in_scope else 'removed from'} scan scope")
            await self.tell("module:grc", "evaluate")
        return {"changed": changed, "unknown": sorted(ids - {a.id for a in self._assets()}),
                "without_address": unscannable}

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
        "in_scan_scope": sum(1 for a in active if a.scan_scope),
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
