"""Framework self-assessments (collection ``framework_assessments``): an organisation scores every requirement of a
CyFun edition on two maturity dimensions against a target level. Scores are people's judgement: hub control results
are only ever suggested as evidence, never turned into scores.
"""

from __future__ import annotations

import re
import time
from datetime import date
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ... import people as people_app
from ...models import ControlState, Policy, Risk
from ...store import new_id
from ..baseline import CONTROLS_BY_ID
from . import LEVEL_NAMES, SCALE, Catalog, load, mapping, scoring

if TYPE_CHECKING:
    from ...core import Hub

COLLECTION = "framework_assessments"
EVENT = "framework_assessment"
Level = Literal["B", "I", "E"]
Status = Literal["in_progress", "completed", "archived"]
EvidenceKind = Literal["control", "policy", "risk", "url", "file"]
ITEM_COLLECTIONS = {"policy": "policies", "risk": "risks"}  # evidence kinds that point at a hub record
MAX_EVIDENCE = 25
HISTORY = 20  # changes kept per requirement
STALE_AFTER = 365 * 24 * 3600
URL_RE = re.compile(r"^https?://[^\s/$.?#@][^\s@]*$", re.I)
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _text(value: str, limit: int) -> str:
    return CONTROL_CHARS.sub("", value or "").strip()[:limit]


def _name(value: str) -> str:
    name = _text(value, 200)
    if not name:
        raise AssessmentError("Give the assessment a name")
    return name


class EvidenceLink(BaseModel):
    """Evidence for a requirement: a hub control (its automated result), a policy or a risk of the hub, a URL, or a
    file kept elsewhere (a name or path, e.g. "ISMS share: backup-test-2026.pdf")."""

    model_config = ConfigDict(extra="forbid")
    kind: EvidenceKind
    ref: str = Field(min_length=1, max_length=1000)
    title: str = Field("", max_length=300)
    added_by: str | None = None
    added_at: float | None = None

    @field_validator("ref", "title")
    @classmethod
    def _clean(cls, value: str) -> str:
        return _text(value, 1000)

    @model_validator(mode="after")
    def _check(self) -> "EvidenceLink":
        if self.kind == "url" and not URL_RE.match(self.ref):
            raise ValueError("A URL must start with http:// or https:// and carry no credentials")
        if self.kind == "control" and self.ref not in CONTROLS_BY_ID:
            raise ValueError(f"Unknown hub control '{self.ref}'")
        return self


class Entry(BaseModel):
    """One requirement's assessment."""

    implementation: int | None = Field(None, ge=1, le=5)
    documentation: int | None = Field(None, ge=1, le=5)
    na: bool = False
    na_justification: str = ""
    owner_person_id: str | None = None
    notes: str = ""
    evidence: list[EvidenceLink] = []
    updated_by: str | None = None
    updated_at: float | None = None
    history: list[dict[str, Any]] = []  # newest last: {at, by, changes: {field: [old, new]}}


class FrameworkAssessment(BaseModel):
    id: str = Field(default_factory=lambda: new_id("fa_"))
    framework: Literal["cyfun2025", "cyfun2023"]
    name: str = Field(min_length=1, max_length=200)
    target_level: Level = "B"
    scope: str = Field("", max_length=4000)
    notes: str = Field("", max_length=8000)
    status: Status = "in_progress"
    requirements: dict[str, Entry] = {}
    created_by: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_by: str = ""
    updated_at: float = Field(default_factory=time.time)
    assessed_at: float | None = None  # the last change to a requirement
    completed_at: float | None = None


class AssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    target_level: Level = "B"
    scope: str = Field("", max_length=4000)
    notes: str = Field("", max_length=8000)
    copy_from: str | None = Field(None, max_length=40)  # another assessment of the same edition: its scores carry over


class AssessmentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=200)
    target_level: Level | None = None
    scope: str | None = Field(None, max_length=4000)
    notes: str | None = Field(None, max_length=8000)
    status: Status | None = None


class RequirementPatch(BaseModel):
    """Only the fields sent change; null clears a score or the owner."""

    model_config = ConfigDict(extra="forbid")
    implementation: int | None = Field(None, ge=1, le=5)
    documentation: int | None = Field(None, ge=1, le=5)
    na: bool | None = None
    na_justification: str | None = Field(None, max_length=2000)
    owner_person_id: str | None = Field(None, max_length=40)
    notes: str | None = Field(None, max_length=8000)
    evidence: list[EvidenceLink] | None = Field(None, max_length=MAX_EVIDENCE)


class AssessmentError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


# -- storage ------------------------------------------------------------------------------------------------------


def all_assessments(hub: "Hub", framework_id: str | None = None) -> list[FrameworkAssessment]:
    items = hub.all(COLLECTION, FrameworkAssessment)
    return [a for a in items if framework_id is None or a.framework == framework_id]


def get(hub: "Hub", framework_id: str, assessment_id: str) -> FrameworkAssessment | None:
    item = hub.one(COLLECTION, assessment_id, FrameworkAssessment)
    return item if item is not None and item.framework == framework_id else None


def save(hub: "Hub", assessment: FrameworkAssessment) -> FrameworkAssessment:
    hub.store.put(COLLECTION, assessment.model_dump(mode="json"))
    hub.bus.publish(EVENT, {"id": assessment.id, "framework": assessment.framework, "status": assessment.status,
                            "updated_at": assessment.updated_at, "updated_by": assessment.updated_by})
    return assessment


def create(hub: "Hub", catalog: Catalog, body: AssessmentCreate, actor: str, today: date | None = None) -> FrameworkAssessment:
    window = catalog.transition(today)
    if window and not window["open"]:
        raise AssessmentError(f"{catalog.short_name} can no longer be used for new assessments (allowed until "
                              f"{window['assess_until']}). Use CyFun 2025.")
    name = _name(body.name)
    entries: dict[str, Entry] = {}
    assessed_at = None
    if body.copy_from:
        source = get(hub, catalog.id, body.copy_from)
        if source is None:
            raise AssessmentError(f"No {catalog.short_name} assessment '{body.copy_from}' to copy from")
        entries = {ref: entry.model_copy(update={"history": []}) for ref, entry in source.requirements.items()
                   if ref in catalog.by_ref}
        # copied scores keep their age: the copy counts as assessed again only once a person changes a requirement
        if entries:
            assessed_at = source.assessed_at or max((e.updated_at or 0 for e in entries.values()), default=0) or None
    now = time.time()
    assessment = FrameworkAssessment(framework=catalog.id, name=name, target_level=body.target_level,
                                     scope=_text(body.scope, 4000), notes=_text(body.notes, 8000), requirements=entries,
                                     created_by=actor, created_at=now, updated_by=actor, updated_at=now,
                                     assessed_at=assessed_at)
    save(hub, assessment)
    copied = f", scores copied from '{body.copy_from}'" if body.copy_from else ""
    hub.activity(actor, "info", f"Started the {catalog.short_name} self-assessment '{assessment.name}' (target "
                                f"{LEVEL_NAMES[assessment.target_level]}{copied})", assessment_id=assessment.id)
    return assessment


def update(hub: "Hub", assessment: FrameworkAssessment, body: AssessmentPatch, actor: str) -> FrameworkAssessment:
    changes = {k: v for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    if not changes:
        raise AssessmentError("Nothing to change")
    if "name" in changes:
        changes["name"] = _name(changes["name"])
    for name, limit in (("scope", 4000), ("notes", 8000)):
        if name in changes:
            changes[name] = _text(changes[name], limit)
    edits = [k for k, v in changes.items() if k != "status" and v != getattr(assessment, k)]
    if assessment.status == "archived" and changes.get("status", "archived") == "archived" and edits:
        raise AssessmentError("This assessment is archived: reopen it (status in_progress) before changing its "
                              + ", ".join(k.replace("_", " ") for k in edits), 409)
    before = assessment.model_copy()
    for name, value in changes.items():
        setattr(assessment, name, value)
    if body.status == "completed" and before.status != "completed":
        assessment.completed_at = time.time()
    elif body.status and body.status != "completed":
        assessment.completed_at = None if body.status == "in_progress" else assessment.completed_at
    assessment.updated_by, assessment.updated_at = actor, time.time()
    save(hub, assessment)
    moved = [f"{k} {getattr(before, k)} -> {getattr(assessment, k)}" for k in ("status", "target_level")
             if getattr(before, k) != getattr(assessment, k)]
    if moved or before.name != assessment.name:
        what = "; ".join(moved + ([f"renamed to '{assessment.name}'"] if before.name != assessment.name else []))
        hub.activity(actor, "info", f"Self-assessment '{before.name}': {what}", assessment_id=assessment.id)
    return assessment


def update_requirement(hub: "Hub", catalog: Catalog, assessment: FrameworkAssessment, ref: str,
                       body: RequirementPatch, actor: str) -> Entry:
    if ref not in catalog.by_ref:
        raise AssessmentError(f"{catalog.short_name} has no requirement '{ref}'", 404)
    if assessment.status == "archived":
        raise AssessmentError("This assessment is archived: reopen it (status in_progress) to change scores", 409)
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise AssessmentError("Nothing to change")
    entry = assessment.requirements.get(ref, Entry())
    old = entry.model_dump(exclude={"history", "updated_by", "updated_at"})
    if "owner_person_id" in changes and changes["owner_person_id"]:
        if people_app.get(hub, changes["owner_person_id"]) is None:
            raise AssessmentError(f"Unknown person '{changes['owner_person_id']}' for the owner")
    for name in ("implementation", "documentation", "owner_person_id"):
        if name in changes:
            setattr(entry, name, changes[name] or None)
    for name, limit in (("na_justification", 2000), ("notes", 8000)):
        if name in changes:
            setattr(entry, name, _text(changes[name] or "", limit))
    if changes.get("na") is not None:
        entry.na = bool(changes["na"])
    if body.evidence is not None:
        now = time.time()
        known = {(e.kind, e.ref): e for e in entry.evidence}
        for link in body.evidence:
            if (link.kind, link.ref) not in known and link.kind in ITEM_COLLECTIONS \
                    and hub.store.get(ITEM_COLLECTIONS[link.kind], link.ref) is None:
                raise AssessmentError(f"Unknown {link.kind} '{link.ref}'")
        entry.evidence = [known.get((e.kind, e.ref)) or e.model_copy(update={"added_by": actor, "added_at": now})
                          for e in _unique(body.evidence)]
    if entry.na and len(entry.na_justification) < 3:
        raise AssessmentError("Marking a requirement N/A needs a justification")
    new = entry.model_dump(exclude={"history", "updated_by", "updated_at"})
    diff = {k: [_brief(old[k]), _brief(new[k])] for k in new if old[k] != new[k]}
    if not diff:
        return entry
    now = time.time()
    entry.updated_by, entry.updated_at = actor, now
    entry.history = [*entry.history, {"at": now, "by": actor, "changes": diff}][-HISTORY:]
    assessment.requirements[ref] = entry
    assessment.updated_by, assessment.updated_at, assessment.assessed_at = actor, now, now
    save(hub, assessment)
    return entry


def _unique(links: list[EvidenceLink]) -> list[EvidenceLink]:
    seen, out = set(), []
    for link in links:
        if (link.kind, link.ref) not in seen:
            seen.add((link.kind, link.ref))
            out.append(link)
    return out


def _brief(value: Any) -> Any:
    if isinstance(value, list):
        return [f"{e['kind']}:{e['ref']}" if isinstance(e, dict) else e for e in value]
    if isinstance(value, str) and len(value) > 200:
        return value[:200] + "..."
    return value


def delete(hub: "Hub", assessment: FrameworkAssessment, actor: str) -> None:
    hub.store.delete(COLLECTION, assessment.id)
    hub.bus.publish(f"{EVENT}_removed", {"id": assessment.id, "framework": assessment.framework})
    hub.activity(actor, "warn", f"Deleted the {load(assessment.framework).short_name} self-assessment "
                                f"'{assessment.name}'", assessment_id=assessment.id)


# -- views --------------------------------------------------------------------------------------------------------


def evaluation(assessment: FrameworkAssessment) -> dict[str, Any]:
    return scoring.evaluate(load(assessment.framework), assessment.requirements, assessment.target_level)


def brief(assessment: FrameworkAssessment, result: dict[str, Any] | None = None) -> dict[str, Any]:
    """A list entry: the assessment without its requirement entries, with progress and the verdict per level."""
    result = result or evaluation(assessment)
    catalog = load(assessment.framework)
    return {
        **assessment.model_dump(mode="json", exclude={"requirements"}),
        "framework_name": catalog.short_name, "target_name": LEVEL_NAMES[assessment.target_level],
        "progress": result["progress"], "verdict": result["verdict"],
        "maturity": result["overall"]["maturity"],
        "levels": [{"level": lv["level"], "verdict": lv["verdict"], "targeted": lv["targeted"],
                    "maturity": lv["groups"][lv["level"]]["maturity"]} for lv in result["levels"]],
        "stale": bool(assessment.assessed_at and time.time() - assessment.assessed_at > STALE_AFTER),
    }


def control_states(hub: "Hub") -> dict[str, ControlState]:
    return {s.id: s for s in hub.all("controls", ControlState)}


def suggestions(framework_id: str, states: dict[str, ControlState]) -> dict[str, list[dict[str, Any]]]:
    """Per requirement: the hub controls mapped to it, with their current result (suggested evidence)."""
    out: dict[str, list[dict[str, Any]]] = {}
    for ref, rows in mapping.by_requirement(framework_id).items():
        out[ref] = []
        for row in rows:
            control, state = CONTROLS_BY_ID.get(row["control"]), states.get(row["control"])
            if control is None:
                continue
            out[ref].append({"control": control.id, "title": control.title, "fit": row["fit"],
                             "fit_name": mapping.FITS[row["fit"]], "status": state.status if state else "manual",
                             "detail": state.detail if state else "", "evaluated_at": state.evaluated_at if state else None})
    return out


def evidence_view(hub: "Hub", link: EvidenceLink, states: dict[str, ControlState]) -> dict[str, Any]:
    """A link with what it points at now (metadata only)."""
    out = link.model_dump(mode="json")
    if link.kind == "control":
        control, state = CONTROLS_BY_ID.get(link.ref), states.get(link.ref)
        out.update({"title": link.title or (control.title if control else link.ref),
                    "status": state.status if state else "manual", "detail": state.detail if state else "",
                    "evaluated_at": state.evaluated_at if state else None, "found": control is not None})
    elif link.kind == "policy":
        policy = hub.one("policies", link.ref, Policy)
        out.update({"found": policy is not None, **({"title": link.title or policy.title, "status": policy.status,
                                                     "version": policy.version, "owner": policy.owner,
                                                     "updated_at": policy.updated_at} if policy else {})})
    elif link.kind == "risk":
        risk = hub.one("risks", link.ref, Risk)
        out.update({"found": risk is not None, **({"title": link.title or risk.title, "status": risk.status,
                                                   "score": risk.score, "owner": risk.owner} if risk else {})})
    return out


class _Context:
    """What requirement views share: control states, people and the suggested controls, read once."""

    def __init__(self, hub: "Hub", framework_id: str):
        self.states = control_states(hub)
        self.people = {p.id: p for p in people_app.all_people(hub)}
        self.suggested = suggestions(framework_id, self.states)


def requirement_view(hub: "Hub", catalog: Catalog, assessment: FrameworkAssessment, ref: str,
                     context: _Context | None = None) -> dict[str, Any]:
    """One requirement's entry with its maturity, owner, evidence (with current status) and suggested hub controls."""
    context = context or _Context(hub, catalog.id)
    requirement = catalog.by_ref[ref]
    entry = assessment.requirements.get(ref)
    owner = context.people.get(entry.owner_person_id) if entry and entry.owner_person_id else None
    return {
        **(entry or Entry()).model_dump(mode="json"), "ref_id": ref,
        "maturity": scoring.requirement_maturity(catalog, entry),
        "in_scope": requirement.in_level(assessment.target_level),
        "key_measure": requirement.key_measure(assessment.target_level),
        "owner": {"id": owner.id, "display_name": owner.display_name, "email": owner.email} if owner else None,
        "evidence": [evidence_view(hub, link, context.states) for link in (entry.evidence if entry else [])],
        "suggested": context.suggested.get(ref, []),
    }


def detail(hub: "Hub", assessment: FrameworkAssessment) -> dict[str, Any]:
    catalog = load(assessment.framework)
    result = evaluation(assessment)
    context = _Context(hub, catalog.id)
    requirements = {r.ref_id: requirement_view(hub, catalog, assessment, r.ref_id, context) for r in catalog.requirements}
    return {**brief(assessment, result), "evaluation": result, "requirements": requirements,
            "transition": catalog.transition(), "text_url": catalog.data["text_url"],
            "scale": list(SCALE)}


def control_summaries(hub: "Hub") -> list[dict[str, Any]]:
    """What the compliance control HB-PO-3 checks: the latest non-archived assessment per edition."""
    out = []
    for assessment in all_assessments(hub):
        if assessment.status == "archived":
            continue
        result = evaluation(assessment)
        out.append({"id": assessment.id, "name": assessment.name, "framework": assessment.framework,
                    "framework_name": load(assessment.framework).short_name,
                    "target_level": assessment.target_level, "target_name": LEVEL_NAMES[assessment.target_level],
                    "assessed_at": assessment.assessed_at, "updated_at": assessment.updated_at,
                    "status": assessment.status, "verdict": result["verdict"], "progress": result["progress"],
                    "key_measures_below": [k["ref_id"] for k in result["key_measures"] if not k["ok"]]})
    return out
