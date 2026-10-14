"""REST routes of the integration map, the Connect panel's options, data flow creation and the canvas layouts
(docs/research/canvas-design.md 7.1-7.4; added to the main router by ``api.build_router``; the read model is in
``hub/integration/canvas.py``, the rules in ``hub/integration/strategies.py``).

Roles (classified in ``hub/auth/policy.py``, all the default): viewers read the map, the options and the layouts;
operators arrange the shared layouts and create data flows. Changing a flow, deciding its approval, single sign-on and
connection tests use the existing routes. Errors carry ``detail = {"code", "message", ...}``.

  GET    /api/integration/map                  viewer    the Integration map (7.1)
  GET    /api/integration/map/options?a=&b=    viewer    what can be connected between two map items (7.2); 404
                                                         unknown item
  POST   /api/flows                            operator  FlowCreate -> 201 {flow, approval_id} (7.4): through the Hub
                                                         Supervisor (flows.create); 400 invalid | no_connection |
                                                         no_capability | system_of_record, 404 not_found, 409
                                                         flow_exists | flow_conflict (with flow_id)
  GET    /api/layouts/{view}                   viewer    the shared arrangement of a map (integration | segmentation)
  PATCH  /api/layouts/{view}                   operator  LayoutPatch -> the layout; 422 for bad ids, order or lane
  DELETE /api/layouts/{view}                   operator  reset the arrangement -> the (empty) layout

SSE events: canvas_layout {view, version, ids, updated_by, reset}.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal

from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, ConfigDict, Field

from .auth.service import CurrentPrincipal
from .integration import canvas, strategies

if TYPE_CHECKING:
    from .core import Hub

Ask = Callable[..., Awaitable[dict[str, Any]]]
View = Path(pattern=r"^(integration|segmentation)$")


class FlowCreate(BaseModel):
    """A data flow between the hub ("hub") and a tool ("tool:<id>"), as the Connect panel's option parts give it."""

    model_config = ConfigDict(extra="forbid")
    domain: str = Field(min_length=1, max_length=40)
    source: str = Field(min_length=1, max_length=80)
    target: str = Field(min_length=1, max_length=80)
    action: Literal["scan"] | None = None
    schedule_minutes: int | None = Field(None, ge=0, le=525_600)  # default: pull and push 60, scan a week
    options: dict[str, Any] = Field(default_factory=dict)  # see flows.validate_options


def add_routes(router: APIRouter, hub: "Hub", ask: Ask) -> None:
    @router.get("/integration/map")
    async def integration_map() -> dict[str, Any]:
        return canvas.integration_map(hub)

    @router.get("/integration/map/options")
    async def map_options(a: str = "", b: str = "") -> dict[str, Any]:
        try:
            return strategies.connect_options(hub, a[:300], b[:300])
        except KeyError as exc:
            raise HTTPException(404, {"code": "not_found", "message": "Unknown map item"}) from exc

    @router.post("/flows", status_code=201)
    async def create_flow(body: FlowCreate, p: CurrentPrincipal) -> dict[str, Any]:
        reply = await ask(p, "supervisor", "flows.create", {**body.model_dump(mode="json"), "actor": p.actor})
        if reply.get("refused"):
            detail = dict(reply["refused"])
            raise HTTPException(int(detail.pop("status", 400)), detail)
        return {"flow": reply["flow"], "approval_id": reply.get("approval_id")}

    @router.get("/layouts/{view}")
    async def get_layout(view: str = View) -> dict[str, Any]:
        return canvas.get_layout(hub, view)

    @router.patch("/layouts/{view}")
    async def patch_layout(body: canvas.LayoutPatch, p: CurrentPrincipal, view: str = View) -> dict[str, Any]:
        try:
            return canvas.patch_layout(hub, view, body, p.actor)
        except ValueError as exc:
            raise HTTPException(422, {"code": "invalid", "message": str(exc)}) from exc

    @router.delete("/layouts/{view}")
    async def reset_layout(p: CurrentPrincipal, view: str = View) -> dict[str, Any]:
        return canvas.reset_layout(hub, view, p.actor)
