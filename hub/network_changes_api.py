"""REST routes of guarded network device changes and maintenance windows (added to the main router by
``api.build_router``; the lifecycle is in ``hub/integration/changes.py`` and ``hub/agents/network.py``).

Roles (classified in ``hub/auth/policy.py``): viewers read; operators preview, propose, withdraw their own proposals
(administrators any) and propose reverts and backup restores - while ``device_changes`` is on and the device is
writable (S2); administrators apply an approved change as an emergency and manage maintenance windows. Approving is
``POST /api/approvals/{id}`` (kind ``firewall``: administrators only, never the proposer while
``device_changes_need_second_person`` is on - 403 ``admin_required`` / ``same_person``). Errors carry
``detail = {"code", "message", ...}``.

Device changes (canvas-design 7.7)
  POST   /api/segmentation/changes/preview              operator  ChangeRequest -> the preview (no side effects)
  POST   /api/segmentation/changes                      operator  ChangeRequest -> 201 {change, approval_id}
  GET    /api/segmentation/changes?firewall=&status=&limit=  viewer  {changes, total, counts}
  GET    /api/segmentation/changes/{change_id}          viewer    the change + {approval}
  DELETE /api/segmentation/changes/{change_id}          operator  withdraw (the proposer or an administrator)
  POST   /api/segmentation/changes/{change_id}/revert   operator  {justification?} -> 201 {change, approval_id} (S10)
  POST   /api/segmentation/changes/{change_id}/emergency  admin   {justification} -> 202 the change (applied now,
                                                                  outside the maintenance windows)
  POST   /api/network/backups/{backup_id}/restore       operator  {justification?} -> 201 {change, approval_id} (a
                                                                  "restore" proposal - never a direct restore)
Maintenance windows
  GET    /api/network/maintenance-windows               viewer    {windows, required}
  POST   /api/network/maintenance-windows               admin     WindowBody -> 201 the window
  PATCH  /api/network/maintenance-windows/{window_id}   admin     WindowPatch -> the window
  DELETE /api/network/maintenance-windows/{window_id}   admin     {ok}

Proposal errors: 403 device_changes_disabled | not_writable | forbidden; 404 not_found; 409 change_in_flight |
stale_snapshot | not_applied | already_reverted | rule_not_found; 422 policy_forbidden | justification_required |
invalid | lockout | device_refused; 502 device_unreachable | device_error.

SSE events: firewall_change (the public change), maintenance_window {id, deleted}.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import guardrails
from .auth.service import CurrentPrincipal, Principal
from .integration import changes, maintenance, network
from .integration.changes import ChangeRefused, ChangeRequest

if TYPE_CHECKING:
    from .core import Hub

Ask = Callable[..., Awaitable[dict[str, Any]]]


class JustificationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    justification: str | None = Field(None, max_length=2000)


class EmergencyBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    justification: str = Field(max_length=2000)


def refused(exc: ChangeRefused) -> HTTPException:
    detail = exc.as_dict()
    return HTTPException(detail.pop("status"), detail)


def _problems(exc: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, e['loc'])) or 'body'}: {e['msg']}" for e in exc.errors()[:5])


def add_routes(router: APIRouter, hub: "Hub", ask: Ask) -> None:
    def with_approval(change: dict[str, Any]) -> dict[str, Any]:
        approval = hub.approvals.get(change.get("approval_id") or "")
        return {**changes.public(change),
                "approval": {"id": approval.id, "status": approval.status, "decided_by": approval.decided_by,
                             "decided_at": approval.decided_at, "note": approval.note} if approval else None}

    def change_or_404(change_id: str) -> dict[str, Any]:
        change = changes.get(hub, change_id)
        if change is None:
            raise HTTPException(404, {"code": "not_found", "message": "Change not found"})
        return change

    async def propose(p: Principal, request: dict[str, Any]) -> dict[str, Any]:
        reply = await ask(p, "module:network", "change.propose", {"request": request}, timeout=900)
        if reply.get("refused"):
            detail = dict(reply["refused"])
            raise HTTPException(int(detail.pop("status", 400)), detail)
        change = changes.get(hub, str(reply.get("change_id")))
        if change is None:
            raise HTTPException(500, {"code": "failed", "message": "The change was not stored"})
        return {"change": with_approval(change), "approval_id": reply.get("approval_id")}

    # -- device changes ------------------------------------------------------------------

    @router.post("/segmentation/changes/preview")
    async def change_preview(body: ChangeRequest, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return changes.preview(hub, body, p.role)
        except ChangeRefused as exc:
            raise refused(exc) from exc

    @router.post("/segmentation/changes", status_code=201)
    async def change_create(body: ChangeRequest, p: CurrentPrincipal) -> dict[str, Any]:
        return await propose(p, body.model_dump(mode="json"))

    @router.get("/segmentation/changes")
    async def change_list(firewall: str | None = None, status: str | None = None, limit: int = 200) -> dict[str, Any]:
        if status is not None and status not in changes.STATUSES:
            raise HTTPException(400, {"code": "invalid", "message": f"status is one of {', '.join(changes.STATUSES)}"})
        everything = changes.listing(hub, firewall)
        items = [c for c in everything if status is None or c["status"] == status]
        counts = {s: sum(1 for c in everything if c["status"] == s) for s in changes.STATUSES}
        return {"changes": [with_approval(c) for c in items[:max(1, min(limit, 1000))]], "total": len(items),
                "counts": counts}

    @router.get("/segmentation/changes/{change_id}")
    async def change_get(change_id: str) -> dict[str, Any]:
        return with_approval(change_or_404(change_id))

    @router.delete("/segmentation/changes/{change_id}")
    async def change_withdraw(change_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return with_approval(changes.withdraw(hub, change_id, p.actor, p.role))
        except ChangeRefused as exc:
            raise refused(exc) from exc

    @router.post("/segmentation/changes/{change_id}/revert", status_code=201)
    async def change_revert(change_id: str, p: CurrentPrincipal, body: JustificationBody | None = None) -> dict[str, Any]:
        change_or_404(change_id)
        return await propose(p, {"op": "revert", "revert_of": change_id,
                                 "justification": body.justification if body else None})

    @router.post("/segmentation/changes/{change_id}/emergency", status_code=202)
    async def change_emergency(change_id: str, body: EmergencyBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            change = changes.mark_emergency(hub, change_id, p.actor, body.justification)
        except ChangeRefused as exc:
            raise refused(exc) from exc
        await hub.bus.tell(p.bus_id, "module:network", "change.advance", {"change_id": change_id})
        return with_approval(change)

    @router.post("/network/backups/{backup_id}/restore", status_code=201)
    async def backup_restore(backup_id: str, p: CurrentPrincipal, body: JustificationBody | None = None) -> dict[str, Any]:
        if network.get_backup(hub, backup_id) is None:
            raise HTTPException(404, {"code": "not_found", "message": "Backup not found"})
        return await propose(p, {"op": "restore", "backup_id": backup_id,
                                 "justification": body.justification if body else None})

    # -- maintenance windows -------------------------------------------------------------

    @router.get("/network/maintenance-windows")
    async def windows_list() -> dict[str, Any]:
        now = time.time()
        return {"windows": [maintenance.public(hub, w, now) for w in maintenance.windows(hub)],
                "required": bool(guardrails.value(hub, changes.WINDOW_GUARD))}

    @router.post("/network/maintenance-windows", status_code=201)
    async def windows_create(body: maintenance.WindowBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return maintenance.public(hub, maintenance.create(hub, body, p.actor))
        except ValueError as exc:
            raise HTTPException(400, {"code": "invalid", "message": str(exc)}) from exc

    @router.patch("/network/maintenance-windows/{window_id}")
    async def windows_update(window_id: str, body: maintenance.WindowPatch, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            return maintenance.public(hub, maintenance.update(hub, window_id, body, p.actor))
        except KeyError as exc:
            raise HTTPException(404, {"code": "not_found", "message": "Maintenance window not found"}) from exc
        except ValidationError as exc:
            raise HTTPException(400, {"code": "invalid", "message": _problems(exc)}) from exc
        except ValueError as exc:
            raise HTTPException(400, {"code": "invalid", "message": str(exc)}) from exc

    @router.delete("/network/maintenance-windows/{window_id}")
    async def windows_delete(window_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        if not maintenance.delete(hub, window_id, p.actor):
            raise HTTPException(404, {"code": "not_found", "message": "Maintenance window not found"})
        return {"ok": True}
