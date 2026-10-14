"""CyFun maturity scores and conformity per level - pure functions over a catalog and an assessment's entries.

Source of the rules: the CyFun 2025 library that ships with CISO Assistant (``outcomes_definition``,
``implementation_groups_definition``, ``anchor_na_to_target``, ``score_calculation_method: average_of_averages``),
checked by scripts/build_cyfun_catalog.py on every build. The CCB's own documents (booklets, self-assessment tool)
were unreachable (HTTP 403), so these are the thresholds of the CISO Assistant library copy. UNVERIFIED: against the
CCB originals, including whether the CCB averages the implementation and documentation maturity as CISO Assistant
does. CyFun 2023's library defines no conformity rules: Atrium applies the 2025 rules to it as well
(UNVERIFIED for CyFun 2023).

How a score is computed, as CISO Assistant computes it (backend/core/models.py and core/cel_service.py, main branch,
read 2026-10-09):

- a requirement counts once its implementation maturity is set; its maturity is the average of implementation and
  documentation maturity, a missing documentation maturity counting as 1 (the bottom of the scale);
- a requirement marked N/A counts at the framework target (3.0) in every average and minimum;
- a group's score (all Basic requirements, the Important key measures, ...) is an average of averages over the
  framework tree: requirements are averaged per subcategory, subcategories per category, and the categories carry
  equal weight in the final average. Requirements not scored yet are left out of averages, but count as -1 in a
  group's minimum, so an unscored key measure fails the key-measure rule;
- scores are compared unrounded (noise removed at 9 decimals) and shown with two decimals, half up.

The rules per level (B Basic, I Important, E Essential): the group's maturity is at least the level's threshold; every
key measure of the level reaches its threshold; at most N requirements of the level are N/A and none of its key
measures (and, for Essential, none of its management aspects); for Essential, every category reaches 3.0. Atrium
calls a level "met" only when these rules hold and every requirement of the level is scored or N/A.
"""

from __future__ import annotations

from collections import defaultdict
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Iterable, Mapping

from . import LEVEL_NAMES, LEVELS, Catalog, Requirement

SOURCE_NOTE = ("Thresholds and scoring method from the CyFun 2025 library that ships with CISO Assistant (the CCB "
               "originals were unreachable); not verified against the CCB's own documents.")
SOURCE_NOTE_2023 = ("UNVERIFIED: the CyFun 2023 library defines no conformity rules; Atrium applies the CyFun 2025 "
                    "library's rules (CISO Assistant library copy) to CyFun 2023.")
MISSING = -1.0


def clean(value: float | None) -> float | None:
    """Float noise removed (CISO Assistant's clean_score)."""
    return None if value is None else round(value, 9)


def fmt(value: float | None) -> str:
    """Two decimals, half up, as the CCB tools display scores; "-" when not scored."""
    if value is None or value == MISSING:
        return "-"
    return str(Decimal(repr(clean(value))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def _mean(values: Iterable[float]) -> float | None:
    items = list(values)
    return sum(items) / len(items) if items else None


def _get(entry: Any, name: str) -> Any:
    return entry.get(name) if isinstance(entry, Mapping) else getattr(entry, name, None)


def layers(catalog: Catalog, entry: Any) -> tuple[float, float] | None:
    """(implementation, documentation) as the averages count a requirement; None when it is not scored."""
    if entry is None:
        return None
    if _get(entry, "na"):
        anchor = catalog.na_counts_as
        return anchor, anchor
    implementation = _get(entry, "implementation")
    if implementation is None:
        return None
    documentation = _get(entry, "documentation")
    return float(implementation), float(documentation if documentation is not None else 1)


def requirement_maturity(catalog: Catalog, entry: Any) -> float | None:
    pair = layers(catalog, entry)
    return None if pair is None else clean((pair[0] + pair[1]) / 2)


def tree_average(requirements: Iterable[Requirement], values: Mapping[str, float]) -> float | None:
    """Average of averages: requirements per subcategory, subcategories per category, then the categories."""
    tree: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for requirement in requirements:
        if requirement.ref_id in values:
            tree[requirement.category][requirement.subcategory].append(values[requirement.ref_id])
    categories = [_mean(_mean(items) or 0.0 for items in subs.values()) for subs in tree.values()]
    return clean(_mean(c for c in categories if c is not None))


def subset(catalog: Catalog, requirements: list[Requirement], entries: Mapping[str, Any]) -> dict[str, Any]:
    """Scores of a set of requirements (a group, a function, a category), like CISO Assistant's subset scores."""
    pairs = {r.ref_id: p for r in requirements if (p := layers(catalog, entries.get(r.ref_id))) is not None}
    implementation = tree_average(requirements, {k: v[0] for k, v in pairs.items()})
    documentation = tree_average(requirements, {k: v[1] for k, v in pairs.items()})
    maturity = clean((implementation + documentation) / 2) if implementation is not None and documentation is not None \
        else None
    minimum = min((requirement_maturity(catalog, entries.get(r.ref_id)) or MISSING for r in requirements),
                  default=MISSING)
    return {"implementation": implementation, "documentation": documentation, "maturity": maturity,
            "scored": len(pairs), "total": len(requirements),
            "na": sum(1 for r in requirements if _get(entries.get(r.ref_id), "na")),
            "min_maturity": minimum}


def groups_of(catalog: Catalog) -> tuple[str, ...]:
    management = ("BG", "IG", "EG") if catalog.management_aspects else ()
    return ("B", "I", "E", "BK", "IK", "EK", *management)


def _scored(catalog: Catalog, entry: Any) -> bool:
    return layers(catalog, entry) is not None


def _rule(rule_id: str, label: str, ok: bool, *, value: Any = None, threshold: Any = None,
          reasons: list[str] | None = None, missing_only: bool = False) -> dict[str, Any]:
    return {"id": rule_id, "label": label, "ok": ok, "value": value, "threshold": threshold,
            "reasons": reasons or [], "missing_only": (not ok) and missing_only}


def _listed(items: list[str], limit: int = 12) -> str:
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def evaluate_level(catalog: Catalog, entries: Mapping[str, Any], level: str) -> dict[str, Any]:
    """The library's rules for one level over the requirements tagged with it, with the reasons for each failure."""
    rules_for = catalog.conformity(level)
    in_scope = [r for r in catalog.requirements if r.in_level(level)]
    groups = {g: subset(catalog, [r for r in in_scope if g in r.tags], entries)
              for g in groups_of(catalog) if g in (level, f"{level}K", f"{level}G")}
    unscored = [r.ref_id for r in in_scope if not _scored(catalog, entries.get(r.ref_id))]
    rules: list[dict[str, Any]] = []

    group = groups[level]
    target = rules_for["maturity_min"]
    if group["maturity"] is None:
        rules.append(_rule("maturity", "Overall maturity", False, threshold=target, missing_only=True,
                           reasons=["No requirement of this level is scored yet"]))
    else:
        ok = group["maturity"] >= target
        rules.append(_rule("maturity", "Overall maturity", ok, value=group["maturity"], threshold=target,
                           reasons=[] if ok else [f"Overall maturity {fmt(group['maturity'])} is below {fmt(target)}"]))

    key_min = rules_for["key_measure_min"]
    keys = [r for r in in_scope if r.key_measure(level)]
    low = [(r.ref_id, requirement_maturity(catalog, entries.get(r.ref_id))) for r in keys]
    below = [f"{ref} ({fmt(m)})" for ref, m in low if m is not None and m < key_min]
    not_scored = [ref for ref, m in low if m is None]
    reasons = ([f"Key measures below {fmt(key_min)}: {_listed(below)}"] if below else []) + \
        ([f"Key measures not scored yet: {_listed(not_scored)}"] if not_scored else [])
    rules.append(_rule("key_measures", "Every key measure", not below and not not_scored,
                       value=groups[f"{level}K"]["min_maturity"], threshold=key_min, reasons=reasons,
                       missing_only=not below))

    na_reasons = []
    na_count = groups[level]["na"]
    if na_count > rules_for["na_max"]:
        na_reasons.append(f"{na_count} requirements are N/A; at most {rules_for['na_max']} allowed at this level")
    na_keys = [r.ref_id for r in keys if _get(entries.get(r.ref_id), "na")]
    if len(na_keys) > rules_for["na_max_key"]:
        na_reasons.append(f"Key measures marked N/A (none allowed): {_listed(na_keys)}")
    if rules_for.get("na_max_management") is not None and f"{level}G" in groups:
        na_mgmt = [r.ref_id for r in in_scope if r.management(level) and _get(entries.get(r.ref_id), "na")]
        if len(na_mgmt) > rules_for["na_max_management"]:
            na_reasons.append(f"Management aspects marked N/A (none allowed): {_listed(na_mgmt)}")
    rules.append(_rule("exclusions", "N/A limits", not na_reasons, value=na_count, threshold=rules_for["na_max"],
                       reasons=na_reasons))

    if rules_for.get("category_min") is not None:
        cat_min = rules_for["category_min"]
        titles = catalog.titles("categories")
        below_cats, unscored_cats = [], []
        for cat_id in titles:
            members = [r for r in in_scope if r.category == cat_id]
            if not members:
                continue
            maturity = subset(catalog, members, entries)["maturity"]
            if maturity is None:
                unscored_cats.append(cat_id)
            elif maturity < cat_min:
                below_cats.append(f"{cat_id} ({fmt(maturity)})")
        reasons = ([f"Categories below {fmt(cat_min)}: {_listed(below_cats)}"] if below_cats else []) + \
            ([f"Categories without a score yet: {_listed(unscored_cats)}"] if unscored_cats else [])
        rules.append(_rule("categories", "Every category", not below_cats and not unscored_cats, threshold=cat_min,
                           reasons=reasons, missing_only=not below_cats))

    rules_met = all(r["ok"] for r in rules)
    if rules_met and not unscored:
        verdict = "met"
    elif any(not r["ok"] and not r["missing_only"] for r in rules):
        verdict = "not_met"
    else:
        verdict = "incomplete"
    reasons = [reason for r in rules for reason in r["reasons"]]
    if unscored and verdict != "not_met":
        reasons.append(f"{len(unscored)} of {len(in_scope)} requirements of this level are not scored yet")
    na_total = sum(1 for r in in_scope if _get(entries.get(r.ref_id), "na"))
    return {"level": level, "name": LEVEL_NAMES[level], "verdict": verdict, "rules_met": rules_met, "rules": rules,
            "reasons": reasons, "groups": groups,
            "progress": {"total": len(in_scope), "scored": len(in_scope) - len(unscored) - na_total, "na": na_total,
                         "unscored": len(unscored), "percent": round(100 * (len(in_scope) - len(unscored))
                                                                     / len(in_scope)) if in_scope else 0}}


def _target_for(catalog: Catalog, requirement: Requirement, level: str) -> float:
    """What a requirement should reach at `level`: the key-measure threshold for key measures, else the level's group
    target (B 2.5, I and E 3.0)."""
    if requirement.key_measure(level):
        return float(catalog.conformity(level)["key_measure_min"])
    return catalog.group_target(level)


def evaluate(catalog: Catalog, entries: Mapping[str, Any], target_level: str) -> dict[str, Any]:
    """Everything the assessment workspace, the audit pack and the compliance control show."""
    levels = [{**evaluate_level(catalog, entries, level), "targeted": LEVELS.index(level) <= LEVELS.index(target_level)}
              for level in LEVELS]
    in_scope = [r for r in catalog.requirements if r.in_level(target_level)]
    fn_titles, cat_titles = catalog.titles("functions"), catalog.titles("categories")
    functions = []
    for fn_id, title in fn_titles.items():
        members = [r for r in in_scope if r.function == fn_id]
        if members:
            functions.append({"id": fn_id, "title": title, **subset(catalog, members, entries)})
    categories = []
    target = catalog.group_target(target_level)
    for cat_id, title in cat_titles.items():
        members = [r for r in in_scope if r.category == cat_id]
        if members:
            scores = subset(catalog, members, entries)
            categories.append({"id": cat_id, "function": members[0].function, "title": title, **scores,
                               "target": target, "below": scores["maturity"] is not None and scores["maturity"] < target})
    gaps, unscored, key_measures = [], [], []
    for requirement in in_scope:
        entry = entries.get(requirement.ref_id)
        maturity = requirement_maturity(catalog, entry)
        goal = _target_for(catalog, requirement, target_level)
        if maturity is None:
            unscored.append(requirement.ref_id)
        elif maturity < goal:
            gaps.append({"ref_id": requirement.ref_id, "title": requirement.title, "maturity": maturity, "target": goal,
                         "key_measure": requirement.key_measure(target_level)})
        if requirement.key_measure(target_level):
            key_measures.append({"ref_id": requirement.ref_id, "title": requirement.title, "maturity": maturity,
                                 "threshold": goal, "na": bool(_get(entry, "na")),
                                 "ok": maturity is not None and maturity >= goal and not _get(entry, "na")})
    documentation_missing = [r.ref_id for r in in_scope if not _get(entries.get(r.ref_id), "na")
                             and _get(entries.get(r.ref_id), "implementation") is not None
                             and _get(entries.get(r.ref_id), "documentation") is None]
    targeted = next(level for level in levels if level["level"] == target_level)
    return {
        "target_level": target_level, "target_name": LEVEL_NAMES[target_level], "verdict": targeted["verdict"],
        "progress": {**targeted["progress"], "documentation_missing": len(documentation_missing)},
        "overall": subset(catalog, in_scope, entries),
        "levels": levels, "functions": functions, "categories": categories,
        "gaps": sorted(gaps, key=lambda g: (not g["key_measure"], g["maturity"], g["ref_id"])),
        "unscored": unscored, "key_measures": key_measures, "documentation_missing": documentation_missing,
        "method": {"source": SOURCE_NOTE if catalog.id == "cyfun2025" else SOURCE_NOTE_2023,
                   "na_counts_as": catalog.na_counts_as, "missing_documentation_counts_as": 1,
                   "calculation": "average of averages (requirements per subcategory, subcategories per category, "
                                  "categories equally weighted)",
                   "verified_against_library": catalog.data["conformity"]["verified_against_library"]},
    }
