"""Compliance evidence from extension domains: each "controls" rule of an active pack counts the current records of a
domain that match its conditions and rates a control (pass / partial / fail). The GRC checks combine the result with
the control's own check (hub/grc/checks.py: the worse of the two counts)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from . import records as ext_records
from . import registry
from .pack import SEVERITIES, Condition, ControlRule, DomainItem

if TYPE_CHECKING:
    from ..core import Hub

DAY = 86_400
SEVERITY_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}  # critical 5 ... info 1


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, str) or isinstance(b, str):
        return str(a).strip().lower() == str(b).strip().lower()
    return a == b


def _rank(defn: DomainItem, field: str, value: Any) -> float | None:
    spec = defn.field(field)
    if spec is not None and spec.type == "severity":
        return SEVERITY_RANK.get(str(value).lower()) if value is not None else None
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def condition_holds(defn: DomainItem, cond: Condition, fields: dict[str, Any]) -> bool:
    value = fields.get(cond.field)
    op = cond.op
    if op == "empty":
        return value in (None, "", [])
    if op == "not_empty":
        return value not in (None, "", [])
    if op == "eq":
        return value is not None and _same(value, cond.value)
    if op == "ne":
        return value is None or not _same(value, cond.value)
    if op in ("in", "not_in"):
        inside = value is not None and any(_same(value, v) for v in (cond.value or []))  # type: ignore[union-attr]
        return inside if op == "in" else not inside
    left, right = _rank(defn, cond.field, value), _rank(defn, cond.field, cond.value)
    if left is None or right is None:
        return False
    return left >= right if op == "gte" else left <= right


def rule_matches(defn: DomainItem, rule: ControlRule, record: ext_records.ExtRecord, now: float) -> bool:
    if not all(condition_holds(defn, c, record.fields) for c in rule.where):
        return False
    if rule.older_than_days is not None:
        started = record.fields.get(rule.age_field) if rule.age_field else record.created_at
        if not isinstance(started, (int, float)) or started > now - rule.older_than_days * DAY:
            return False
    return True


def rate(rule: ControlRule, count: int) -> str:
    if rule.fail_above is not None and count > rule.fail_above:
        return "fail"
    if rule.partial_above is not None and count > rule.partial_above:
        return "partial"
    return "pass"


def evaluate(hub: "Hub", now: float | None = None) -> list[dict[str, Any]]:
    """One result per rule of the active packs whose domain has current records:
    {control, extension, domain, title, status, count, detail, examples}."""
    now = now or time.time()
    out = []
    domains = registry.active_domains(hub)
    for pack_id, rule in registry.control_rules(hub):
        found = domains.get(rule.domain)
        if found is None:
            continue
        defn = found[0]
        current = [r for r in ext_records.all_records(hub, rule.domain) if not r.stale]
        if not current:
            continue  # no data yet: the rule says nothing
        matched = [r for r in current if rule_matches(defn, rule, r, now)]
        status = rate(rule, len(matched))
        shown = ", ".join(r.title for r in matched[:3]) + ("..." if len(matched) > 3 else "")
        detail = f"{rule.title}: {len(matched)} of {len(current)} {defn.title.lower()}" + (f" ({shown})" if shown else "")
        out.append({"control": rule.control, "extension": pack_id, "domain": rule.domain, "title": rule.title,
                    "status": status, "count": len(matched), "detail": detail[:500],
                    "examples": [r.id for r in matched[:10]]})
    return out
