"""Hub controls -> CyFun requirements: which automated control results are suggested as evidence for a requirement.

CyFun 2025 rows come from docs/research/cyfun-cra-ciso.md section 2 (and 2.1 for network controls). The requirement
ids and their level tags were checked against the CISO Assistant library copy of CyFun 2025; the choice of
requirements per control and the fit are ANALYST JUDGEMENT (unverified, not CCB guidance):

- ``P`` primary evidence, ``S`` supporting / partial, ``W`` weak (the control touches only part of the requirement).

CyFun 2023 refs are derived from the 2025 ones through CISO Assistant's CyFun 2023 <-> 2025 mapping library (aligned
on the CCB transposition table): every 2023 requirement mapped to a 2025 requirement of the control.

A control that lists ``CyFun2025`` in its own ``refs`` (" / "-separated ids, e.g. network controls) is included with
fit ``S``. Suggestions never set a score: maturity stays a person's judgement.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from ..baseline import CONTROLS, Control
from . import load

FITS = {"P": "primary", "S": "supporting", "W": "weak"}
BASIS = "analyst judgement (docs/research/cyfun-cra-ciso.md section 2); ids and levels checked against the library"
BASIS_2023 = "derived through CISO Assistant's CyFun 2023 - 2025 mapping (CCB transposition table)"

CYFUN2025: dict[str, tuple[tuple[str, str], ...]] = {
    "HB-AM-1": (("ID.AM-01.1", "P"), ("ID.AM-02.1", "P"), ("ID.AM-01.2", "S"), ("ID.AM-02.2", "S"),
                ("ID.AM-01.3", "W"), ("ID.AM-02.4", "W")),
    "HB-AM-2": (("ID.AM-05.1", "P"), ("ID.AM-02.3", "P"), ("ID.AM-01.2", "S")),
    "HB-AC-1": (("PR.AA-01.1", "P"), ("PR.AA-05.5", "S"), ("PR.AA-01.2", "S"), ("PR.AA-02.2", "S")),
    "HB-AC-2": (("PR.AA-05.7", "P"), ("PR.AA-05.6", "S"), ("PR.PS-06.2", "S"), ("PR.AA-05.3", "S")),
    "HB-AC-3": (("PR.AA-03.3", "P"), ("ID.AM-08.12", "S"), ("PR.AA-01.4", "S"), ("PR.AA-03.5", "S"),
                ("PR.DS-02.2", "S"), ("PR.AA-03.2", "W")),
    "HB-AC-4": (("PR.AA-01.1", "P"), ("PR.AA-05.1", "P"), ("PR.AA-05.3", "P"), ("PR.AA-05.4", "S"),
                ("PR.AA-03.2", "S")),
    "HB-AC-5": (("PR.AA-01.3", "P"), ("PR.AA-05.1", "S")),
    # the research's proposed "guardrails" control: HB-AC-6 now enforces the agent guardrails
    "HB-AC-6": (("ID.RA-01.5", "P"), ("ID.RA-01.4", "S"), ("PR.AA-05.7", "S")),
    # the research's proposed "leavers" control
    "HB-AC-7": (("GV.RR-04.2", "P"), ("PR.AA-01.1", "P"), ("PR.AA-05.1", "S"), ("GV.SC-02.1", "S")),
    "HB-CM-1": (("PR.PS-01.1", "S"), ("ID.AM-03.2", "S"), ("ID.AM-04.2", "W")),
    "HB-CM-2": (("PR.PS-06.2", "P"), ("PR.PS-06.4", "S"), ("PR.PS-01.5", "S"), ("ID.AM-08.10", "S")),
    "HB-OP-1": (("PR.IR-04.1", "S"), ("DE.CM-09.1", "W"), ("PR.IR-03.1", "W")),
    "HB-OP-2": (("PR.PS-04.1", "P"), ("PR.AA-05.7", "P"), ("PR.PS-04.3", "S"), ("PR.PS-04.2", "S"),
                ("DE.AE-03.1", "S")),
    "HB-VM-1": (("ID.AM-02.1", "P"), ("ID.AM-08.2", "S"), ("PR.PS-02.1", "S")),
    "HB-VM-2": (("ID.RA-01.1", "P"), ("ID.RA-01.2", "P"), ("ID.RA-01.6", "S"), ("ID.RA-01.5", "S"),
                ("ID.IM-03.9", "S")),
    "HB-VM-3": (("ID.AM-08.2", "P"), ("ID.RA-01.3", "P"), ("ID.RA-06.1", "S"), ("ID.RA-08.1", "S"),
                ("ID.RA-08.2", "S")),
    "HB-SC-1": (("ID.AM-04.1", "P"), ("GV.SC-07.2", "P"), ("GV.OC-05.1", "S"), ("GV.SC-07.1", "W")),
    "HB-RM-1": (("ID.RA-05.1", "P"), ("GV.RM-03.2", "P"), ("GV.RM-03.1", "S"), ("ID.RA-05.2", "S"),
                ("ID.RA-06.1", "S"), ("GV.OV-02.1", "W")),
    "HB-PO-1": (("GV.PO-01.1", "P"), ("GV.PO-01.2", "S")),
    "HB-PO-2": (("GV.PO-01.1", "P"), ("PR.AA-05.1", "P"), ("PR.AA-05.2", "S"), ("PR.AA-05.8", "W")),
    # the compliance self-assessment control (Atrium's own choice, not in the research tables)
    "HB-PO-3": (("GV.OV-03.1", "S"), ("GV.OV-02.1", "W")),
    "HB-IR-1": (("RS.MA-01.1", "P"), ("ID.IM-04.1", "P"), ("RS.CO-02.2", "P"), ("DE.AE-08.1", "S"),
                ("RS.CO-02.1", "S"), ("ID.IM-03.1", "S")),
    "HB-BC-1": (("PR.DS-11.1", "P"), ("PR.DS-11.2", "P"), ("PR.DS-11.3", "S"), ("PR.DS-11.4", "S"),
                ("RC.RP-01.1", "S"), ("RC.RP-05.1", "S"), ("GV.OC-04.4", "W")),
}


def _own_refs(control: Control) -> list[str]:
    return [ref.strip() for ref in str(control.refs.get("CyFun2025") or "").split("/") if ref.strip()]


@lru_cache(maxsize=None)
def _reverse_2023() -> dict[str, list[tuple[str, str]]]:
    """CyFun 2025 ref -> [(CyFun 2023 ref, relationship)]."""
    out: dict[str, list[tuple[str, str]]] = {}
    for src, dst, relationship in (load("cyfun2023").data.get("edition_mapping") or {}).get("pairs", []):
        out.setdefault(dst, []).append((src, relationship))
    return out


def control_refs(control: Control) -> dict[str, list[dict[str, Any]]]:
    """{"cyfun2025": [{"ref_id", "fit", "basis"}], "cyfun2023": [...]} for one control (valid ids only)."""
    known = load("cyfun2025").by_ref
    rows: dict[str, str] = {}
    for ref, fit in CYFUN2025.get(control.id, ()):
        rows.setdefault(ref, fit)
    for ref in _own_refs(control):
        rows.setdefault(ref, "S")
    v2025 = [{"ref_id": ref, "fit": fit, "basis": BASIS} for ref, fit in rows.items() if ref in known]
    v2023: dict[str, dict[str, Any]] = {}
    for row in v2025:
        for ref, relationship in _reverse_2023().get(row["ref_id"], []):
            # an "intersect" relationship weakens the fit by one step
            fit = row["fit"] if relationship == "equal" else {"P": "S", "S": "W", "W": "W"}[row["fit"]]
            current = v2023.get(ref)
            if current is None or "PSW".index(fit) < "PSW".index(current["fit"]):
                v2023[ref] = {"ref_id": ref, "fit": fit, "basis": BASIS_2023, "via": row["ref_id"]}
    return {"cyfun2025": v2025, "cyfun2023": sorted(v2023.values(), key=lambda r: r["ref_id"])}


@lru_cache(maxsize=None)
def by_requirement(framework_id: str) -> dict[str, list[dict[str, str]]]:
    """requirement ref -> [{"control", "fit"}], best fit first."""
    out: dict[str, list[dict[str, str]]] = {}
    for control in CONTROLS:
        for row in control_refs(control).get(framework_id, []):
            out.setdefault(row["ref_id"], []).append({"control": control.id, "fit": row["fit"]})
    for rows in out.values():
        rows.sort(key=lambda r: ("PSW".index(r["fit"]), r["control"]))
    return out


def refs_text(control: Control) -> dict[str, str]:
    """The control's CyFun refs as the " / "-separated strings the other frameworks use (primary and supporting)."""
    refs = control_refs(control)
    return {name: " / ".join(r["ref_id"] for r in refs[key] if r["fit"] in ("P", "S"))
            for key, name in (("cyfun2025", "CyFun2025"), ("cyfun2023", "CyFun2023"))
            if any(r["fit"] in ("P", "S") for r in refs[key])}
