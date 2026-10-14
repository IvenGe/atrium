"""REST routes of the Network app and the segmentation map (added to the main router by ``api.build_router``).

Roles (classified in ``hub/auth/policy.py``): viewers read; operators refresh devices, take backups, acknowledge drift
and place assets; administrators accept baselines, download backups (full device configurations), change the network
settings, zone roles and the segmentation policy. Device text (names, descriptions, rule text) in these payloads is
untrusted: clients render it as text only. Backup content is only ever returned by the admin download.

Network app
  GET    /api/network/devices                               viewer    {generated_at, devices: [summary], settings,
                                                                       device_changes, fake_devices}
  GET    /api/network/devices/{tool_id}                     viewer    summary + record (rules with "line") + history +
                                                                       baseline_deviations + backups + drift (open)
  GET    /api/network/devices/{tool_id}/history/{rev}       viewer    one snapshot revision with its record
  GET    /api/network/devices/{tool_id}/diff?from_rev=&to_rev=  viewer  {tool_id, from_rev, to_rev, diff} (unified
                                                                       diff text; to_rev empty = current snapshot)
  POST   /api/network/devices/{tool_id}/refresh             operator  read the device now (its network data flow)
  POST   /api/network/refresh                               operator  {tool_ids?: [...]} (empty: every device)
  POST   /api/network/devices/{tool_id}/baseline            admin     accept the current snapshot as the baseline
  DELETE /api/network/devices/{tool_id}/baseline            admin     remove the baseline
  GET    /api/network/drift?tool_id=&status=&limit=         viewer    {items, counts}
  POST   /api/network/drift/{drift_id}/ack                  operator  {note?} -> the item
  GET    /api/network/backups?tool_id=                      viewer    {backups: [metadata]}
  POST   /api/network/devices/{tool_id}/backups             operator  take a backup now (201) -> {backup}
  GET    /api/network/backups/{backup_id}/download          admin     the configuration file (logged)
  GET    /api/network/settings                              viewer    backup_retention, backup_interval_hours,
                                                                       history_limit, stale_after_minutes (+ bounds)
  PATCH  /api/network/settings                              admin     any of those keys
  (Restoring a backup is a change proposal: R3-NETCHANGE's change endpoints, never a direct restore.)

Segmentation map (docs/research/canvas-design.md 7.5-7.6)
  GET    /api/segmentation?firewall=                        viewer    the map of one firewall
  POST   /api/segmentation/refresh                          operator  {firewall?} -> {started, skipped, results}
  PATCH  /api/segmentation/zones/{zone_id}                  admin     {role?, label?} (null resets)
  PUT    /api/segmentation/placements/{asset_id}            operator  {zone_id: str | null}
  GET    /api/segmentation/policy                           viewer    the policy (+ defaults, roles)
  PUT    /api/segmentation/policy                           admin     {rules: [...]}

SSE events: network_snapshot, network_drift, network_baseline, device_backup, network_settings, segmentation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import connectors
from .auth.service import CurrentPrincipal, Principal
from .connectors.netmodel import display_id, interface_names, rule_line
from .integration import network, segmentation

if TYPE_CHECKING:
    from .core import Hub

Ask = Callable[..., Awaitable[dict[str, Any]]]
MEDIA = {"xml": "application/xml", "json": "application/json", "text": "text/plain; charset=utf-8"}


class NetworkSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    backup_retention: int | None = None
    backup_interval_hours: int | None = None
    history_limit: int | None = None
    stale_after_minutes: int | None = None


class RefreshBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_ids: list[str] = Field([], max_length=200)


class SegmentationRefresh(BaseModel):
    model_config = ConfigDict(extra="forbid")
    firewall: str | None = Field(None, max_length=200)


class AckBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str | None = Field(None, max_length=500)


class ZonePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: segmentation.Role | None = None
    label: str | None = Field(None, max_length=80)


class PlacementBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    zone_id: str | None = Field(..., max_length=400)


def _with_lines(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    names = interface_names(record)
    return {**record, "rules": [{**r, "line": rule_line(r, names)} for r in record.get("rules") or []]}


def _problems(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, e['loc'])) or 'body'}: {e['msg']}" for e in exc.errors()[:5])


def add_routes(router: APIRouter, hub: "Hub", ask: Ask) -> None:
    def device_or_404(tool_id: str) -> str:
        if tool_id not in network.device_ids(hub):
            raise HTTPException(404, "Network device not found")
        return tool_id

    async def evaluate(p: Principal) -> None:
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")

    # -- devices -------------------------------------------------------------------------

    @router.get("/network/devices")
    async def network_devices() -> dict[str, Any]:
        import time

        return {"generated_at": time.time(), "devices": network.devices(hub), "settings": network.settings(hub),
                "device_changes": bool(hub.prefs["guardrails"].get("device_changes", False)),
                "fake_devices": "fake_firewall" in connectors.REGISTRY}

    @router.get("/network/devices/{tool_id}")
    async def network_device(tool_id: str) -> dict[str, Any]:
        detail = network.device_detail(hub, device_or_404(tool_id))
        if detail is None:
            raise HTTPException(404, "Network device not found")
        detail["backups"] = network.backups(hub, tool_id)
        detail["drift_items"] = network.drift(hub, tool_id, "open")[:200]
        return detail

    @router.get("/network/devices/{tool_id}/history/{rev}")
    async def network_history(tool_id: str, rev: int) -> dict[str, Any]:
        entry = network.history_entry(hub, device_or_404(tool_id), rev)
        if entry is None:
            raise HTTPException(404, "Snapshot revision not found (only the latest revisions are kept)")
        return {**entry, "record": _with_lines(entry.get("record"))}

    @router.get("/network/devices/{tool_id}/diff")
    async def network_diff(tool_id: str, from_rev: int, to_rev: int | None = None) -> dict[str, Any]:
        try:
            text = network.diff_text(hub, device_or_404(tool_id), from_rev, to_rev)
        except KeyError as exc:
            raise HTTPException(404, "Snapshot revision not found (only the latest revisions are kept)") from exc
        return {"tool_id": tool_id, "from_rev": from_rev, "to_rev": to_rev, "diff": text}

    @router.post("/network/devices/{tool_id}/refresh")
    async def network_refresh_device(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "module:network", "refresh", {"tool_ids": [device_or_404(tool_id)]}, timeout=900)

    @router.post("/network/refresh")
    async def network_refresh(body: RefreshBody, p: CurrentPrincipal) -> dict[str, Any]:
        unknown = [t for t in body.tool_ids if t not in network.device_ids(hub)]
        if unknown:
            raise HTTPException(404, f"Not a network device: {display_id(unknown[0])}")
        return await ask(p, "module:network", "refresh", {"tool_ids": body.tool_ids}, timeout=900)

    @router.post("/network/devices/{tool_id}/baseline")
    async def network_accept_baseline(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            result = network.accept_baseline(hub, device_or_404(tool_id), p.actor)
        except KeyError as exc:
            raise HTTPException(400, "The device has no snapshot yet - refresh it first") from exc
        await evaluate(p)
        return result

    @router.delete("/network/devices/{tool_id}/baseline")
    async def network_clear_baseline(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        if not network.clear_baseline(hub, device_or_404(tool_id), p.actor):
            raise HTTPException(404, "The device has no baseline")
        await evaluate(p)
        return {"ok": True}

    # -- drift ---------------------------------------------------------------------------

    @router.get("/network/drift")
    async def network_drift(tool_id: str | None = None, status: str | None = None, limit: int = 500) -> dict[str, Any]:
        if status is not None and status not in ("open", "attributed", "acknowledged"):
            raise HTTPException(400, "status is open, attributed or acknowledged")
        everything = network.drift(hub, tool_id)
        items = [d for d in everything if status is None or d["status"] == status]
        counts = {s: sum(1 for d in everything if d["status"] == s) for s in ("open", "attributed", "acknowledged")}
        counts["critical_open"] = sum(1 for d in everything if d["status"] == "open" and d["severity"] == "critical")
        return {"items": items[:max(1, min(limit, 5000))], "total": len(items), "counts": counts}

    @router.post("/network/drift/{drift_id}/ack")
    async def network_ack(drift_id: str, body: AckBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            item = network.acknowledge(hub, drift_id, p.actor, body.note)
        except KeyError as exc:
            raise HTTPException(404, "Drift item not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        await evaluate(p)
        return item

    # -- backups -------------------------------------------------------------------------

    @router.get("/network/backups")
    async def network_backups(tool_id: str | None = None) -> dict[str, Any]:
        return {"backups": network.backups(hub, tool_id), "settings": network.settings(hub)}

    @router.post("/network/devices/{tool_id}/backups", status_code=201)
    async def network_take_backup(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        device_or_404(tool_id)
        if not network.can_backup(hub, tool_id):
            raise HTTPException(400, "This device's connector cannot take configuration backups")
        result = await ask(p, "module:network", "backup.take", {"tool_id": tool_id, "reason": "manual",
                                                                "actor": p.actor}, timeout=900)
        await evaluate(p)
        return result

    @router.get("/network/backups/{backup_id}/download")
    async def network_download_backup(backup_id: str, p: CurrentPrincipal) -> Response:
        try:
            meta, content = network.backup_bytes(hub, backup_id)
        except KeyError as exc:
            raise HTTPException(404, "Backup not found") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        hub.activity(p.actor, "warn", f"Downloaded configuration backup {meta['id']} of {display_id(meta['tool_id'])} "
                                      f"(sha256 {meta['sha256'][:12]})", tool_id=meta["tool_id"], backup_id=meta["id"])
        extension = {"xml": "xml", "json": "json"}.get(meta.get("format") or "", "txt")
        name = f"{display_id(meta['tool_id'], 40)}-{meta['id']}.{extension}".replace("/", "_").replace(":", "_")
        return Response(content, media_type=MEDIA.get(meta.get("format") or "", "application/octet-stream"),
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
                                 "X-Content-SHA256": meta["sha256"], "X-Content-Type-Options": "nosniff"})

    # -- settings ------------------------------------------------------------------------

    @router.get("/network/settings")
    async def network_settings() -> dict[str, Any]:
        return {**network.settings(hub), "bounds": {k: list(v) for k, v in network.SETTING_BOUNDS.items()}}

    @router.patch("/network/settings")
    async def network_patch_settings(body: NetworkSettingsPatch, p: CurrentPrincipal) -> dict[str, Any]:
        changes = body.model_dump(exclude_none=True)
        if not changes:
            raise HTTPException(400, "Send at least one setting")
        try:
            network.update_settings(hub, p.actor, changes)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return await network_settings()

    # -- segmentation --------------------------------------------------------------------

    @router.get("/segmentation")
    async def segmentation_view(firewall: str | None = None) -> dict[str, Any]:
        try:
            return segmentation.view(hub, firewall)
        except KeyError as exc:
            raise HTTPException(404, "No firewall with that id has a snapshot") from exc

    @router.post("/segmentation/refresh")
    async def segmentation_refresh(body: SegmentationRefresh, p: CurrentPrincipal) -> dict[str, Any]:
        ids = [body.firewall] if body.firewall else [f["tool_id"] for f in segmentation.firewalls(hub)]
        if body.firewall and body.firewall not in network.device_ids(hub):
            raise HTTPException(404, "Not a network device")
        if not ids:
            return {"started": [], "skipped": [], "results": []}
        return await ask(p, "module:network", "refresh", {"tool_ids": ids}, timeout=900)

    @router.patch("/segmentation/zones/{zone_id:path}")
    async def segmentation_zone(zone_id: str, body: ZonePatch, p: CurrentPrincipal) -> dict[str, Any]:
        changes = body.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(400, "Send role and/or label")
        try:
            result = segmentation.set_zone(hub, zone_id, changes, p.actor)
        except KeyError as exc:
            raise HTTPException(404, "Zone not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await evaluate(p)
        return result

    @router.put("/segmentation/placements/{asset_id}")
    async def segmentation_placement(asset_id: str, body: PlacementBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            doc = segmentation.set_placement(hub, asset_id, body.zone_id, p.actor)
        except KeyError as exc:
            raise HTTPException(404, "Asset not found") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return {"asset_id": asset_id, "placement": doc,
                "note": "This only changes where Atrium draws the asset. It does not change the network."}

    @router.get("/segmentation/policy")
    async def segmentation_policy() -> dict[str, Any]:
        return {**segmentation.policy(hub), "defaults": segmentation.DEFAULT_POLICY, "roles": list(segmentation.ROLES)}

    @router.put("/segmentation/policy")
    async def segmentation_put_policy(body: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
        try:
            result = segmentation.put_policy(hub, body, p.actor)
        except ValidationError as exc:
            raise HTTPException(400, f"Invalid policy: {_problems(exc)}") from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await evaluate(p)
        return result
