"""Compliance frameworks HTTP API: CyFun catalogs, self-assessments, the audit pack and synced frameworks.

Viewers read. Operators create and score assessments. Deleting an assessment is admin. Requirement text from a
synced GRC tool is the tool's text; the built-in catalogs ship titles only.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from .auth.service import CurrentPrincipal
from .core import Hub
from .grc.frameworks import assessments, audit_pack, sync
from .grc.frameworks import detail as catalog_detail
from .grc.frameworks import get as get_catalog
from .grc.frameworks import summary as catalog_summary


def add_routes(router: APIRouter, hub: Hub) -> None:
    def catalog_or_404(framework_id: str):
        catalog = get_catalog(framework_id)
        if catalog is None:
            raise HTTPException(404, "Unknown compliance framework")
        return catalog

    def assessment_or_404(framework_id: str, aid: str):
        catalog_or_404(framework_id)
        item = assessments.get(hub, framework_id, aid)
        if item is None:
            raise HTTPException(404, "Unknown assessment")
        return item

    def raise_assessment(exc: assessments.AssessmentError) -> None:
        raise HTTPException(exc.status, str(exc)) from exc

    @router.get("/frameworks")
    async def list_frameworks() -> dict[str, Any]:
        builtin = []
        for framework_id in ("cyfun2025", "cyfun2023"):
            catalog = get_catalog(framework_id)
            if catalog is None:
                continue
            builtin.append({**catalog_summary(catalog), "external": sync.cyfun_status(hub, framework_id)})
        return {"frameworks": builtin + sync.external_list(hub), "ciso": sync.status(hub)}

    @router.get("/frameworks/{framework_id}")
    async def framework(framework_id: str) -> dict[str, Any]:
        catalog = get_catalog(framework_id)
        if catalog is not None:
            return {**catalog_detail(catalog), "external": sync.cyfun_status(hub, framework_id)}
        external = sync.external_detail(hub, framework_id)
        if external is None:
            raise HTTPException(404, "Unknown compliance framework")
        return external

    @router.get("/frameworks/{framework_id}/assessments")
    async def list_assessments(framework_id: str) -> dict[str, Any]:
        catalog_or_404(framework_id)
        return {"assessments": [assessments.brief(item) for item in assessments.all_assessments(hub, framework_id)]}

    @router.post("/frameworks/{framework_id}/assessments", status_code=201)
    async def create_assessment(framework_id: str, body: assessments.AssessmentCreate,
                                p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_or_404(framework_id)
        try:
            item = assessments.create(hub, catalog, body, p.actor)
        except assessments.AssessmentError as exc:
            raise_assessment(exc)
        return assessments.detail(hub, item)

    @router.get("/frameworks/{framework_id}/assessments/{aid}")
    async def get_assessment(framework_id: str, aid: str) -> dict[str, Any]:
        return assessments.detail(hub, assessment_or_404(framework_id, aid))

    @router.patch("/frameworks/{framework_id}/assessments/{aid}")
    async def patch_assessment(framework_id: str, aid: str, body: assessments.AssessmentPatch,
                               p: CurrentPrincipal) -> dict[str, Any]:
        item = assessment_or_404(framework_id, aid)
        try:
            item = assessments.update(hub, item, body, p.actor)
        except assessments.AssessmentError as exc:
            raise_assessment(exc)
        return assessments.detail(hub, item)

    @router.patch("/frameworks/{framework_id}/assessments/{aid}/requirements/{ref:path}")
    async def patch_requirement(framework_id: str, aid: str, ref: str, body: assessments.RequirementPatch,
                                p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_or_404(framework_id)
        item = assessment_or_404(framework_id, aid)
        try:
            assessments.update_requirement(hub, catalog, item, ref, body, p.actor)
        except assessments.AssessmentError as exc:
            raise_assessment(exc)
        return assessments.detail(hub, assessments.get(hub, framework_id, aid) or item)

    @router.get("/frameworks/{framework_id}/assessments/{aid}/audit-pack")
    async def audit(framework_id: str, aid: str, p: CurrentPrincipal) -> Response:
        item = assessment_or_404(framework_id, aid)
        content, name = audit_pack.build(hub, item, p.actor)
        hub.activity(p.actor, "info", f"Exported the audit pack of '{item.name}'", assessment_id=item.id)
        return Response(content, media_type="application/zip", headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            "X-Content-Type-Options": "nosniff",
        })

    @router.delete("/frameworks/{framework_id}/assessments/{aid}")
    async def delete_assessment(framework_id: str, aid: str, p: CurrentPrincipal) -> dict[str, Any]:
        item = assessment_or_404(framework_id, aid)
        assessments.delete(hub, item, p.actor)
        return {"ok": True}
