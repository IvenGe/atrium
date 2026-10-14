"""REST routes of the Compliance hub's frameworks (included by hub/api.py under /api).

Roles (hub/auth/policy.py): reading - the catalogs, assessments and the audit pack - is for viewers; starting,
changing and scoring an assessment for operators; deleting one for administrators. Self-assessments exist for the
built-in CyFun catalogs only; frameworks read from CISO Assistant (``ext:<tool>:<id>``) are read-only here.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from ...auth.service import CurrentPrincipal, Principal
from . import CATALOG_IDS, DEFAULT_ID, LEVEL_NAMES, SCALE, Catalog, detail, get, load, summary, sync
from . import assessments as fa
from . import audit_pack

if TYPE_CHECKING:
    from ...core import Hub


def build_router(hub: "Hub") -> APIRouter:
    router = APIRouter()

    def catalog_of(framework_id: str) -> Catalog:
        catalog = get(framework_id)
        if catalog is not None:
            return catalog
        if sync.external_detail(hub, framework_id) is not None:
            raise HTTPException(404, "Self-assessments exist for CyFun 2025 and CyFun 2023 only: frameworks read from "
                                     "CISO Assistant are assessed there")
        raise HTTPException(404, "Framework not found")

    def assessment_of(catalog: Catalog, assessment_id: str) -> fa.FrameworkAssessment:
        assessment = fa.get(hub, catalog.id, assessment_id)
        if assessment is None:
            raise HTTPException(404, "Assessment not found")
        return assessment

    async def reevaluate(p: Principal) -> None:
        """HB-PO-3 (the self-assessment is current) follows the assessments."""
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")

    @router.get("/frameworks")
    async def list_frameworks() -> dict[str, Any]:
        everything = fa.all_assessments(hub)
        items = []
        for framework_id in CATALOG_IDS:
            catalog = load(framework_id)
            mine = [a for a in everything if a.framework == framework_id]
            latest = max(mine, key=lambda a: a.updated_at, default=None)
            items.append({**summary(catalog), "assessments": len(mine),
                          "latest_assessment": fa.brief(latest) if latest else None,
                          "ciso_assistant": sync.cyfun_status(hub, framework_id)})
        items += sync.external_list(hub)
        return {"frameworks": items, "default": DEFAULT_ID, "scale": list(SCALE),
                "levels": [{"id": k, "name": v} for k, v in LEVEL_NAMES.items()], "sync": sync.status(hub)}

    @router.get("/frameworks/{framework_id}")
    async def framework_detail(framework_id: str) -> dict[str, Any]:
        catalog = get(framework_id)
        if catalog is None:
            external = sync.external_detail(hub, framework_id)
            if external is None:
                raise HTTPException(404, "Framework not found")
            return external
        states = fa.control_states(hub)
        return {**detail(catalog), "controls": fa.suggestions(catalog.id, states),
                "assessments": [fa.brief(a) for a in sorted(fa.all_assessments(hub, catalog.id),
                                                            key=lambda a: -a.updated_at)],
                "ciso_assistant": sync.cyfun_status(hub, catalog.id)}

    @router.get("/frameworks/{framework_id}/assessments")
    async def list_assessments(framework_id: str) -> list[dict[str, Any]]:
        catalog = catalog_of(framework_id)
        return [fa.brief(a) for a in sorted(fa.all_assessments(hub, catalog.id), key=lambda a: -a.updated_at)]

    @router.post("/frameworks/{framework_id}/assessments", status_code=201)
    async def create_assessment(framework_id: str, body: fa.AssessmentCreate, p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_of(framework_id)
        try:
            assessment = fa.create(hub, catalog, body, p.actor)
        except fa.AssessmentError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        await reevaluate(p)
        return fa.detail(hub, assessment)

    @router.get("/frameworks/{framework_id}/assessments/{assessment_id}")
    async def assessment_detail(framework_id: str, assessment_id: str) -> dict[str, Any]:
        catalog = catalog_of(framework_id)
        return fa.detail(hub, assessment_of(catalog, assessment_id))

    @router.patch("/frameworks/{framework_id}/assessments/{assessment_id}")
    async def update_assessment(framework_id: str, assessment_id: str, body: fa.AssessmentPatch,
                                p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_of(framework_id)
        try:
            assessment = fa.update(hub, assessment_of(catalog, assessment_id), body, p.actor)
        except fa.AssessmentError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        await reevaluate(p)
        return fa.detail(hub, assessment)

    @router.patch("/frameworks/{framework_id}/assessments/{assessment_id}/requirements/{ref}")
    async def score_requirement(framework_id: str, assessment_id: str, ref: str, body: fa.RequirementPatch,
                                p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_of(framework_id)
        assessment = assessment_of(catalog, assessment_id)
        try:
            fa.update_requirement(hub, catalog, assessment, ref, body, p.actor)
        except fa.AssessmentError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        result = fa.evaluation(assessment)
        # always: any scored requirement can make this the most recently scored assessment, the one HB-PO-3 judges
        await reevaluate(p)
        return {"requirement": fa.requirement_view(hub, catalog, assessment, ref),
                "assessment": fa.brief(assessment, result), "evaluation": result}

    @router.get("/frameworks/{framework_id}/assessments/{assessment_id}/audit-pack")
    async def download_audit_pack(framework_id: str, assessment_id: str, p: CurrentPrincipal) -> Response:
        catalog = catalog_of(framework_id)
        assessment = assessment_of(catalog, assessment_id)
        data, filename = audit_pack.build(hub, assessment, p.actor)
        hub.activity(p.actor, "info", f"Exported the audit pack of the {catalog.short_name} self-assessment "
                                      f"'{assessment.name}'", assessment_id=assessment.id, file=filename,
                     sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        return Response(data, media_type="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                                 "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})

    @router.delete("/frameworks/{framework_id}/assessments/{assessment_id}")
    async def delete_assessment(framework_id: str, assessment_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        catalog = catalog_of(framework_id)
        fa.delete(hub, assessment_of(catalog, assessment_id), p.actor)
        await reevaluate(p)
        return {"ok": True}

    return router
