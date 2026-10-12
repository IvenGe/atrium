"""Network app HTTP API: devices, snapshots, drift, baselines and encrypted configuration backups.

Roles follow the default (viewers read, operators change) except where noted: accepting or clearing a baseline
and downloading a backup are admin. Restore is never a direct call; it is a later approved change.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from .auth.service import CurrentPrincipal, Principal
from .bus import AgentError
from .core import Hub
from .integration import network


class AckBody(BaseModel):
    note: str | None = Field(None, max_length=500)


def add_routes(router: APIRouter, hub: Hub) -> None:
    async def ask(p: Principal, subject: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return await hub.bus.request(p.bus_id, "module:network", subject, body, timeout=900)
        except AgentError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/network/devices")
    async def list_devices() -> dict[str, Any]:
        return {"devices": network.devices(hub)}

    @router.get("/network/devices/{tool_id}")
    async def device(tool_id: str) -> dict[str, Any]:
        detail = network.device_detail(hub, tool_id)
        if detail is None:
            raise HTTPException(404, "Unknown network device")
        return detail

    @router.get("/network/devices/{tool_id}/history/{rev}")
    async def history(tool_id: str, rev: int) -> dict[str, Any]:
        entry = network.history_entry(hub, tool_id, rev)
        if entry is None:
            raise HTTPException(404, "Unknown snapshot revision")
        return entry

    @router.get("/network/devices/{tool_id}/diff")
    async def diff(tool_id: str, from_rev: int, to_rev: int | None = None) -> dict[str, Any]:
        try:
            text = network.diff_text(hub, tool_id, from_rev, to_rev)
        except KeyError:
            raise HTTPException(404, "Unknown snapshot revision") from None
        return {"from_rev": from_rev, "to_rev": to_rev, "diff": text}

    @router.get("/network/drift")
    async def list_drift(tool_id: str | None = None, status: str | None = None) -> dict[str, Any]:
        if status is not None and status not in ("open", "attributed", "acknowledged"):
            raise HTTPException(400, "status is open, attributed or acknowledged")
        return {"drift": network.drift(hub, tool_id, status)}

    @router.post("/network/drift/{drift_id}/ack")
    async def ack_drift(drift_id: str, body: AckBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return network.acknowledge(hub, drift_id, p.actor, body.note)
        except KeyError:
            raise HTTPException(404, "Unknown drift item") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc

    @router.post("/network/devices/{tool_id}/baseline")
    async def accept_baseline(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return network.accept_baseline(hub, tool_id, p.actor)
        except KeyError:
            raise HTTPException(404, "This device has no snapshot to accept") from None

    @router.delete("/network/devices/{tool_id}/baseline")
    async def clear_baseline(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return {"removed": network.clear_baseline(hub, tool_id, p.actor)}

    @router.get("/network/backups")
    async def list_backups(tool_id: str | None = None) -> dict[str, Any]:
        return {"backups": network.backups(hub, tool_id)}

    @router.post("/network/devices/{tool_id}/backups", status_code=201)
    async def take_backup(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            result = await ask(p, "backup.take", {"tool_id": tool_id, "reason": "manual", "actor": p.actor})
        except HTTPException:
            raise
        if result.get("failure"):
            raise HTTPException(400, result["failure"].get("message") or "The backup failed")
        return result

    @router.get("/network/backups/{backup_id}/download")
    async def download_backup(backup_id: str, p: CurrentPrincipal) -> Response:
        try:
            meta, content = network.backup_bytes(hub, backup_id)
        except KeyError:
            raise HTTPException(404, "Unknown backup") from None
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        suffix = meta.get("format") or "bin"
        name = f"atrium-{meta['tool_id']}-{meta['id']}.{suffix}"
        hub.activity(p.actor, "warn", f"Downloaded the configuration backup {meta['id']} of {meta['tool_id']} "
                                      f"({meta['size']} bytes)", tool_id=meta["tool_id"], backup_id=meta["id"])
        return Response(content, media_type="application/octet-stream", headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
        })
