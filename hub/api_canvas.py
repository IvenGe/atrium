"""Integration map, connect options, canvas layouts, and POST /api/flows (canvas-design 7.1-7.4)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .auth.service import CurrentPrincipal, Principal
from .bus import AgentError
from .core import Hub
from .integration import canvas, flows


class FlowCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=80)
    source: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=80)
    action: str | None = Field(None, max_length=16)
    schedule_minutes: int | None = Field(None, ge=0, le=525_600)
    options: dict[str, Any] | None = None


def coded(exc: flows.FlowError) -> HTTPException:
    return HTTPException(exc.status, exc.body())


def add_routes(router: APIRouter, hub: Hub) -> None:
    async def ask(p: Principal, recipient: str, subject: str, body: dict[str, Any] | None = None,
                  timeout: float = 120) -> dict[str, Any]:
        try:
            return await hub.bus.request(p.bus_id, recipient, subject, body or {}, timeout)
        except AgentError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.get("/integration/map")
    async def integration_map() -> dict[str, Any]:
        return canvas.map_payload(hub)

    @router.get("/integration/map/options")
    async def map_options(a: str, b: str) -> dict[str, Any]:
        try:
            return canvas.connect_options(hub, a, b)
        except KeyError:
            raise HTTPException(404, "Unknown map node") from None

    @router.get("/layouts/{view}")
    async def get_layout(view: str) -> dict[str, Any]:
        try:
            return canvas.get_layout(hub, view)
        except KeyError:
            raise HTTPException(404, "Unknown layout") from None

    @router.patch("/layouts/{view}")
    async def patch_layout(view: str, body: canvas.LayoutPatch, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return canvas.patch_layout(hub, view, body, p.actor)
        except KeyError:
            raise HTTPException(404, "Unknown layout") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @router.delete("/layouts/{view}")
    async def delete_layout(view: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return canvas.reset_layout(hub, view, p.actor)
        except KeyError:
            raise HTTPException(404, "Unknown layout") from None

    @router.post("/flows", status_code=201)
    async def create_flow(body: FlowCreate, p: CurrentPrincipal) -> dict[str, Any]:
        result = await ask(p, "supervisor", "flows.create", {
            "domain": body.domain, "source": body.source, "target": body.target, "action": body.action,
            "schedule_minutes": body.schedule_minutes, "options": body.options, "actor": p.actor,
        })
        if not result.get("ok", True):
            raise HTTPException(int(result.get("http_status") or 400), {
                "code": result.get("code") or "invalid",
                "message": result.get("message") or "Could not create the data flow",
                **{k: v for k, v in result.items() if k in ("flow_id",)},
            })
        flow = result["flow"]
        public = flows.public(hub, flow) if not isinstance(flow, dict) else flow
        return {"flow": public, "approval_id": result.get("approval_id")}
