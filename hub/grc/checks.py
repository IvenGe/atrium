"""Automated control checks. Pure functions over a snapshot of hub state."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

from ..models import Asset, ControlState, Host, Patch, Policy, Risk, Tool
from .baseline import CONTROLS, FRAMEWORKS, Control

SSO_MODES = {"oidc", "saml", "oauth2", "ldap"}
REVIEW_WINDOW = 90 * 24 * 3600


@dataclass
class Snapshot:
    tools: list[Tool]
    hosts: list[Host]
    assets: list[Asset]
    risks: list[Risk]
    policies: list[Policy]
    patches: list[Patch]
    autonomy: str
    audit_entries: int


Result = tuple[str, str, list[str]]  # status, detail, evidence


def _ratio(ok: int, total: int, what: str, missing: list[str]) -> Result:
    if total == 0:
        return "manual", f"No {what} yet.", []
    if ok == total:
        return "pass", f"All {total} {what} comply.", []
    status = "partial" if ok else "fail"
    shown = ", ".join(missing[:6]) + ("..." if len(missing) > 6 else "")
    return status, f"{ok}/{total} {what} comply. Missing: {shown}", []


def check_assets_inventory(s: Snapshot) -> Result:
    active = {a.source for a in s.assets if a.status != "retired"}
    expected = {f"tool:{t.id}": t.name for t in s.tools} | {f"host:{h.id}": h.name for h in s.hosts}
    if not expected and not s.assets:
        return "fail", "The asset register is empty.", []
    missing = [name for source, name in expected.items() if source not in active]
    if missing:
        return "partial", f"{len(missing)} tools/hosts are not in the asset register: {', '.join(missing[:6])}", []
    return "pass", f"{len(s.assets)} assets registered; every tool and host is covered.", [a.name for a in s.assets[:10]]


def check_assets_owned(s: Snapshot) -> Result:
    active = [a for a in s.assets if a.status != "retired"]
    missing = [a.name for a in active if not a.owner]
    status, detail, _ = _ratio(len(active) - len(missing), len(active), "active assets", missing)
    return status, detail, [f"{a.name}: {a.owner}" for a in active if a.owner][:10]


def check_tools_sso(s: Snapshot) -> Result:
    analysed = [t for t in s.tools if t.manifest]
    missing = [t.name for t in analysed if t.manifest and t.manifest.auth.sso not in SSO_MODES]
    status, detail, _ = _ratio(len(analysed) - len(missing), len(analysed), "tools", missing)
    return status, detail, [f"{t.name}: {t.manifest.auth.sso}" for t in analysed if t.manifest and t.manifest.auth.sso in SSO_MODES]


def check_agent_approvals(s: Snapshot) -> Result:
    if s.autonomy == "autonomous":
        return "fail", "Agents run in autonomous mode - state-changing actions are not reviewed.", []
    return "pass", f"Autonomy is '{s.autonomy}': state-changing agent actions wait in the approval queue.", [f"autonomy={s.autonomy}"]


def check_ssh_hardening(s: Snapshot) -> Result:
    if not s.hosts:
        return "na", "No remote hosts registered.", []
    missing = [h.name for h in s.hosts if not h.strict_host_keys or not h.key_path]
    status, detail, _ = _ratio(len(s.hosts) - len(missing), len(s.hosts), "hosts (key auth + host key check)", missing)
    return status, detail, [h.name for h in s.hosts if h.name not in missing]


def check_tools_manifest(s: Snapshot) -> Result:
    analysed = [t for t in s.tools if t.manifest]
    missing = [t.name for t in analysed if t.manifest and not t.manifest.native]
    status, detail, _ = _ratio(len(analysed) - len(missing), len(analysed), "tools with an adopted manifest", missing)
    return status, detail, [t.name for t in analysed if t.manifest and t.manifest.native]


def check_patch_review(s: Snapshot) -> Result:
    applied = [p for p in s.patches if p.status == "applied"]
    if s.autonomy == "autonomous":
        return "partial", "Patches are reviewed as branches, but autonomous mode applies them without approval.", []
    return "pass", f"Patches go through the approval queue ({len(applied)} applied, "\
        f"{sum(1 for p in s.patches if p.status == 'rejected')} rejected).", [p.title for p in applied[:10]]


def check_tools_health(s: Snapshot) -> Result:
    analysed = [t for t in s.tools if t.manifest]
    missing = [t.name for t in analysed if t.manifest and not t.manifest.health.url]
    status, detail, _ = _ratio(len(analysed) - len(missing), len(analysed), "tools with health checks", missing)
    return status, detail, [f"{t.name}: {t.manifest.health.url}" for t in analysed if t.manifest and t.manifest.health.url][:10]


def check_audit_log(s: Snapshot) -> Result:
    return "pass", f"{s.audit_entries} agent messages and activity entries retained.", ["hub activity log", "agent message log"]


def check_software_versions(s: Snapshot) -> Result:
    analysed = [t for t in s.tools if t.manifest and t.manifest.kind != "saas"]
    missing = [t.name for t in analysed if t.manifest and not t.manifest.version]
    status, detail, _ = _ratio(len(analysed) - len(missing), len(analysed), "self-hosted tools with a known version", missing)
    return status, detail, [f"{t.name} {t.manifest.version}" for t in analysed if t.manifest and t.manifest.version][:10]


def check_saas_inventory(s: Snapshot) -> Result:
    saas = [t for t in s.tools if t.source_type == "saas"]
    if not saas:
        return "na", "No SaaS services imported.", []
    owned = {a.source for a in s.assets if a.owner and a.status != "retired"}
    missing = [t.name for t in saas if f"tool:{t.id}" not in owned]
    status, detail, _ = _ratio(len(saas) - len(missing), len(saas), "SaaS services with an owner", missing)
    return status, detail, [t.name for t in saas if t.name not in missing]


def check_risk_review(s: Snapshot) -> Result:
    if not s.risks:
        return "fail", "The risk register is empty.", []
    cutoff = time.time() - REVIEW_WINDOW
    stale = [r.title for r in s.risks if r.status != "closed" and (r.reviewed_at or r.created_at) < cutoff]
    open_count = sum(1 for r in s.risks if r.status != "closed")
    if stale:
        return "partial", f"{len(stale)} open risks not reviewed in 90 days.", []
    return "pass", f"{len(s.risks)} risks recorded, {open_count} open, all reviewed within 90 days.", [r.title for r in s.risks[:10]]


def check_policy(category: str) -> Callable[[Snapshot], Result]:
    def check(s: Snapshot) -> Result:
        matching = [p for p in s.policies if p.category == category and p.status != "retired"]
        approved = [p for p in matching if p.status == "approved"]
        if approved:
            p = approved[0]
            return "pass", f"'{p.title}' v{p.version} is approved" + (f", owner {p.owner}." if p.owner else "."), [p.title]
        if matching:
            return "partial", f"'{matching[0].title}' exists but is still a draft.", [matching[0].title]
        return "fail", f"No {category} policy. Create one from the template.", []
    return check


CHECKS: dict[str, Callable[[Snapshot], Result]] = {
    "assets_inventory": check_assets_inventory,
    "assets_owned": check_assets_owned,
    "tools_sso": check_tools_sso,
    "agent_approvals": check_agent_approvals,
    "ssh_hardening": check_ssh_hardening,
    "tools_manifest": check_tools_manifest,
    "patch_review": check_patch_review,
    "tools_health": check_tools_health,
    "audit_log": check_audit_log,
    "software_versions": check_software_versions,
    "saas_inventory": check_saas_inventory,
    "risk_review": check_risk_review,
}


def run_check(control: Control, snapshot: Snapshot) -> ControlState:
    now = time.time()
    if not control.check:
        return ControlState(id=control.id, status="manual", detail="Assess manually.", evaluated_at=now)
    fn = check_policy(control.check.split(":", 1)[1]) if control.check.startswith("policy:") else CHECKS[control.check]
    status, detail, evidence = fn(snapshot)
    return ControlState(id=control.id, status=status, detail=detail, evidence=evidence, evaluated_at=now)  # type: ignore[arg-type]


def evaluate_controls(snapshot: Snapshot, overrides: dict[str, ControlState]) -> list[ControlState]:
    states = []
    for control in CONTROLS:
        state = run_check(control, snapshot)
        manual = overrides.get(control.id)
        if manual and manual.manual:
            state = state.model_copy(update={"status": manual.status, "manual": True, "note": manual.note})
        states.append(state)
    return states


POINTS = {"pass": 1.0, "partial": 0.5, "fail": 0.0, "manual": 0.0}


def framework_scores(states: list[ControlState]) -> list[dict]:
    by_id = {s.id: s for s in states}

    def score(controls: list[Control]) -> dict:
        counted = [by_id[c.id] for c in controls if by_id[c.id].status != "na"]
        value = round(100 * sum(POINTS[s.status] for s in counted) / len(counted)) if counted else None
        return {
            "score": value, "controls": len(controls),
            "passing": sum(1 for s in counted if s.status == "pass"),
            "failing": sum(1 for s in counted if s.status == "fail"),
        }

    results = [{"id": "BASELINE", "name": "Hub Security Baseline", **score(CONTROLS)}]
    for key, name in FRAMEWORKS.items():
        results.append({"id": key, "name": name, **score([c for c in CONTROLS if key in c.refs])})
    return results
