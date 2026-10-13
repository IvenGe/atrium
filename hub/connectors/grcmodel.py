"""The ``frameworks`` and ``assessments`` domains: what a GRC connector (CISO Assistant) reads about the compliance
frameworks it has loaded, and what the hub sends it about its own framework self-assessments.

Reading - ``pull("frameworks")`` returns one record per framework::

    {"external_id": "<framework id>", "urn": "urn:intuitem:risk:framework:cra-resolution-annexes", "ref_id": "...",
     "name": "...", "description": "...", "provider": "EU", "library_urn": "urn:intuitem:risk:library:...",
     "min_score": 1, "max_score": 5, "implementation_groups": [{"ref_id": "B", "name": "basic"}],
     "requirements": [{"id": "<node id>", "urn": "...", "ref_id": "Annex I.1", "name": "...", "description": "...",
                       "parent_urn": "...", "depth": 2, "assessable": True, "implementation_groups": ["B"]}],
     "assessments": [{"external_id": "<compliance assessment id>", "name": "...", "ref_id": "", "status": "in_progress",
                      "version": "1.0", "folder": "IT", "selected_implementation_groups": ["I"],
                      "updated_at": "...", "outcomes": ["important_maturity"],
                      "scores": {"implementation": 2.8, "documentation": 2.1, "maturity": 2.45},
                      "results": {"compliant": 12, "not_assessed": 100},
                      "requirements": [{"urn": "...", "ref_id": "...", "result": "compliant", "status": "done",
                                        "score": 3, "documentation_score": 2}]}],
     "mappings": [{"external_id": "...", "name": "...", "source": "<framework urn>", "target": "<framework urn>"}]}

Texts (names, descriptions) are the tool's: untrusted, shown as text only, never handed to agents as instructions. For
the CyFun frameworks Atrium ships itself the connector leaves requirement names and descriptions out (Atrium has its
own catalog and does not store the CCB's text).

Writing - ``push("assessments", records, links)`` receives one record per hub self-assessment::

    {"hub_id": "fa_1", "external_id": "<linked compliance assessment id or None>", "name": "Atrium: 2026 review",
     "framework": "cyfun2025", "framework_urn": "urn:intuitem:risk:framework:ccb-cyfun2025", "level": "I",
     "ref_aliases": {"R.AC-3.4": "PR.AC-3.4"}, "summary": "Verdict ...",
     "requirements": [{"ref_id": "PR.AA-01.1", "result": "compliant", "score": 3, "documentation_score": 3,
                       "observation": "..."}]}

``result`` is not_applicable | compliant | partially_compliant | non_compliant; ``score`` and
``documentation_score`` are the 1-5 maturities (None for N/A). Requirements the hub has not scored are not sent, so a
person's work in the tool is never overwritten with nothing.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_NODES = 5000
MAX_ASSESSMENTS = 200
RESULTS = ("not_assessed", "partially_compliant", "non_compliant", "compliant", "not_applicable")


def text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        value = value.get("str") or value.get("name") or ""
    return CONTROL_CHARS.sub("", str(value)).strip()[:limit]


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if number < 0 else round(number, 4)  # -1: nothing scored


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class Node(_Base):
    id: str = ""
    urn: str
    ref_id: str = ""
    name: str = ""
    description: str = ""
    parent_urn: str | None = None
    depth: int = Field(1, ge=1, le=20)
    assessable: bool = False
    implementation_groups: list[str] = []

    _short = field_validator("id", "urn", "ref_id", mode="before")(lambda cls, v: text(v, 300))
    _parent = field_validator("parent_urn", mode="before")(lambda cls, v: text(v, 300) or None)
    _name = field_validator("name", mode="before")(lambda cls, v: text(v, 500))
    _description = field_validator("description", mode="before")(lambda cls, v: text(v, 4000))

    @field_validator("implementation_groups", mode="before")
    @classmethod
    def _groups(cls, value: Any) -> list[str]:
        return [text(v, 40) for v in (value if isinstance(value, list) else []) if text(v, 40)][:20]


class RequirementResult(_Base):
    urn: str = ""
    ref_id: str = ""
    result: str = "not_assessed"
    status: str = ""
    score: int | None = None
    documentation_score: int | None = None

    @field_validator("status", "urn", "ref_id", mode="before")
    @classmethod
    def _bits(cls, value: Any) -> str:
        return text(value, 200)

    @field_validator("result", mode="before")
    @classmethod
    def _result(cls, value: Any) -> str:
        value = text(value, 40)
        return value if value in RESULTS else "not_assessed"

    @field_validator("score", "documentation_score", mode="before")
    @classmethod
    def _score(cls, value: Any) -> int | None:
        number = _number(value)
        return int(number) if number is not None and number == int(number) else None


class AssessmentState(_Base):
    external_id: str
    name: str = ""
    ref_id: str = ""
    status: str = ""
    version: str = ""
    folder: str = ""
    selected_implementation_groups: list[str] = []
    updated_at: str | None = None
    outcomes: list[str] = []
    scores: dict[str, float | None] = {}
    results: dict[str, int] = {}
    requirements: list[RequirementResult] = []

    _short = field_validator("external_id", "ref_id", "status", "version", "folder", mode="before")(
        lambda cls, v: text(v, 200))
    _name = field_validator("name", mode="before")(lambda cls, v: text(v, 300))

    @field_validator("updated_at", mode="before")
    @classmethod
    def _when(cls, value: Any) -> str | None:
        return text(value, 64) or None

    @field_validator("selected_implementation_groups", "outcomes", mode="before")
    @classmethod
    def _names(cls, value: Any) -> list[str]:
        if isinstance(value, dict):  # outcomes stored as {rule: true/false}
            value = [k for k, v in value.items() if v]
        return [text(v, 80) for v in (value if isinstance(value, list) else []) if text(v, 80)][:100]

    @field_validator("scores", mode="before")
    @classmethod
    def _scores(cls, value: Any) -> dict[str, float | None]:
        value = value if isinstance(value, dict) else {}
        return {k: _number(value.get(k)) for k in ("implementation", "documentation", "maturity")}

    @field_validator("results", mode="before")
    @classmethod
    def _results(cls, value: Any) -> dict[str, int]:
        value = value if isinstance(value, dict) else {}
        return {k: int(v) for k, v in value.items() if k in RESULTS and isinstance(v, int) and not isinstance(v, bool)}

    @field_validator("requirements", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> list[Any]:
        return list(value)[:MAX_NODES] if isinstance(value, list) else []


class Mapping(_Base):
    external_id: str
    name: str = ""
    source: str = ""
    target: str = ""

    _all = field_validator("external_id", "name", "source", "target", mode="before")(lambda cls, v: text(v, 300))


class FrameworkRecord(_Base):
    external_id: str
    urn: str
    ref_id: str = ""
    name: str
    description: str = ""
    provider: str = ""
    library_urn: str = ""
    min_score: int | None = None
    max_score: int | None = None
    implementation_groups: list[dict[str, str]] = []
    requirements: list[Node] = []
    assessments: list[AssessmentState] = []
    mappings: list[Mapping] = []

    _short = field_validator("external_id", "urn", "ref_id", "provider", "library_urn", mode="before")(
        lambda cls, v: text(v, 300))
    _name = field_validator("name", mode="before")(lambda cls, v: text(v, 300) or "Unnamed framework")
    _description = field_validator("description", mode="before")(lambda cls, v: text(v, 4000))

    @field_validator("min_score", "max_score", mode="before")
    @classmethod
    def _bound(cls, value: Any) -> int | None:
        number = _number(value)
        return int(number) if number is not None else None

    @field_validator("implementation_groups", mode="before")
    @classmethod
    def _groups(cls, value: Any) -> list[dict[str, str]]:
        out = []
        for item in value if isinstance(value, list) else []:
            if isinstance(item, dict) and text(item.get("ref_id"), 40):
                out.append({"ref_id": text(item.get("ref_id"), 40), "name": text(item.get("name"), 200)})
        return out[:50]

    @field_validator("requirements", mode="before")
    @classmethod
    def _nodes(cls, value: Any) -> list[Any]:
        return list(value)[:MAX_NODES] if isinstance(value, list) else []

    @field_validator("assessments", mode="before")
    @classmethod
    def _assessments(cls, value: Any) -> list[Any]:
        return list(value)[:MAX_ASSESSMENTS] if isinstance(value, list) else []


def normalize_frameworks(records: list[Any]) -> tuple[list[dict[str, Any]], list[str]]:
    valid, errors = [], []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"record {index}: not an object")
            continue
        try:
            valid.append(FrameworkRecord.model_validate(record).model_dump(mode="json"))
        except ValidationError as exc:
            problem = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:3])
            errors.append(f"record {record.get('external_id', index)}: {problem}")
    return valid, errors


class RequirementPush(_Base):
    ref_id: str
    result: Literal["not_applicable", "compliant", "partially_compliant", "non_compliant"]
    score: int | None = Field(None, ge=1, le=5)
    documentation_score: int | None = Field(None, ge=1, le=5)
    observation: str = ""


class AssessmentPush(_Base):
    hub_id: str
    external_id: str | None = None
    name: str
    framework: str
    framework_urn: str
    level: Literal["B", "I", "E"]
    ref_aliases: dict[str, str] = {}
    summary: str = ""
    requirements: list[RequirementPush] = []
