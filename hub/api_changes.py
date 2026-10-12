"""Network changes, maintenance windows and the segmentation map HTTP API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .auth.service import CurrentPrincipal, Principal
from .bus import AgentError
from .core import Hub
from .integration import changes, segmentation


class ChangeBody(BaseModel):
    firewall: str = Field(min_length=1, max_length=80)
    op: str = Field(min_length=1, max_length=32)
    source_zone: str | None = None
    target_zone: str | None = None
    services: list[dict[str, Any]] | None = None
    log: bool = True
    description: str = Field("", max_length=120)
    rule_ids: list[str] | None = None
    justification: str = Field("", max_length=2000)


class EmergencyBody(BaseModel):
    justification: str = Field(min_length=20, max_length=2000)


class WindowBody(BaseModel):
    name: str = Field("Window", max_length=80)
    devices: list[str] = Field(default_factory=lambda: ["*"])
    kind: str = "weekly"
    timezone: str = "UTC"
    days: list[int] = Field(default_factory=list)
    start_minute: int = 0
    end_minute: int = 0
    start_at: float | None = None
    end_at: float | None = None


class ZoneBody(BaseModel):
    role: str | None = None
    label: str | None = None


class PlacementBody(BaseModel):
    zone_id: str | None = None


def add_routes(router: APIRouter, hub: Hub) -> None:
    async def ask(p: Principal, subject: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return await hub.bus.request(p.bus_id, "module:network", subject, body, timeout=900)
        except AgentError as exc:
            raise HTTPException(400, str(exc)) from exc

    def raise_change(result: dict[str, Any]) -> dict[str, Any]:
        if result.get("ok", True):
            return result
        raise HTTPException(int(result.get("http_status") or 400),
                            {"code": result.get("code") or "invalid", "message": result.get("message") or "Refused"})

    @router.get("/segmentation")
    async def segmentation_view(firewall: str | None = None) -> dict[str, Any]:
        return segmentation.view(hub, firewall)

    @router.post("/segmentation/refresh")
    async def segmentation_refresh(p: CurrentPrincipal, firewall: str | None = None) -> dict[str, Any]:
        body = {"tool_ids": [firewall] if firewall else []}
        return await ask(p, "refresh", body)

    @router.patch("/segmentation/zones/{zone_id}")
    async def patch_zone(zone_id: str, body: ZoneBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return segmentation.set_zone(hub, zone_id, body.model_dump(exclude_unset=True), p.actor)
        except KeyError:
            raise HTTPException(404, "Unknown zone") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.put("/segmentation/placements/{asset_id}")
    async def put_placement(asset_id: str, body: PlacementBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            found = segmentation.set_placement(hub, asset_id, body.zone_id, p.actor)
        except KeyError:
            raise HTTPException(404, "Unknown asset") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return found

    @router.get("/segmentation/policy")
    async def get_policy() -> dict[str, Any]:
        return segmentation.policy(hub)

    @router.put("/segmentation/policy")
    async def put_policy(body: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return segmentation.put_policy(hub, body, p.actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.post("/segmentation/changes/preview")
    async def preview_change(body: ChangeBody, p: CurrentPrincipal) -> dict[str, Any]:
        result = await ask(p, "change.preview", {**body.model_dump(), "role": p.role, "actor": p.actor})
        if not result.get("ok", True):
            raise_change(result)
        return result["preview"]

    @router.post("/segmentation/changes", status_code=201)
    async def create_change(body: ChangeBody, p: CurrentPrincipal) -> dict[str, Any]:
        result = await ask(p, "change.propose", {**body.model_dump(), "role": p.role, "actor": p.actor})
        return raise_change(result)

    @router.get("/segmentation/changes")
    async def list_changes(status: str | None = None, firewall: str | None = None) -> dict[str, Any]:
        return {"changes": changes.list_changes(hub, status, firewall)}

    @router.get("/segmentation/changes/{change_id}")
    async def get_change(change_id: str) -> dict[str, Any]:
        change = changes.get(hub, change_id)
        if change is None:
            raise HTTPException(404, "Unknown change")
        return changes.public(change)

    @router.delete("/segmentation/changes/{change_id}")
    async def withdraw_change(change_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return changes.withdraw(hub, change_id, p.actor, p.role)
        except changes.ChangeError as exc:
            raise HTTPException(exc.status, exc.body()) from exc

    @router.post("/segmentation/changes/{change_id}/revert")
    async def revert_change(change_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        change = changes.get(hub, change_id)
        if change is None or change.get("status") != "applied":
            raise HTTPException(409, {"code": "invalid", "message": "Only an applied change can be reverted"})
        body = {"firewall": change["firewall"], "op": "disable_rules", "revert_of": change_id,
                "justification": "Revert the applied change", "role": p.role, "actor": p.actor}
        if change.get("op") == "allow":
            created = (change.get("result") or {}).get("created") or []
            body["rule_ids"] = [c["id"] for c in created if c.get("id")]
            body["op"] = "disable_rules"
        else:
            raise HTTPException(422, {"code": "invalid", "message": "Revert this change from the device page"})
        result = await ask(p, "change.propose", body)
        return raise_change(result)

    @router.post("/segmentation/changes/{change_id}/emergency")
    async def emergency(change_id: str, body: EmergencyBody, p: CurrentPrincipal) -> dict[str, Any]:
        result = await ask(p, "change.emergency", {"change_id": change_id, "justification": body.justification,
                                                   "actor": p.actor})
        return raise_change(result)

    @router.get("/network/windows")
    async def windows() -> dict[str, Any]:
        return {"windows": changes.list_windows(hub)}

    @router.post("/network/windows", status_code=201)
    async def create_window(body: WindowBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return changes.save_window(hub, body.model_dump(), p.actor)
        except changes.ChangeError as exc:
            raise HTTPException(exc.status, exc.body()) from exc

    @router.delete("/network/windows/{window_id}")
    async def remove_window(window_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return {"removed": changes.delete_window(hub, window_id, p.actor)}
