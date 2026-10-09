"""Automated control checks. Pure functions over a snapshot of hub state."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import guardrails
from ..models import OPEN_STATES, Account, Asset, ControlState, Host, Patch, Person, Policy, Risk, Tool, User, Vulnerability
from ..people import find_leavers
from .baseline import CONTROLS, FRAMEWORKS, Control

SSO_MODES = {"oidc", "saml", "oauth2", "ldap"}
REVIEW_WINDOW = 90 * 24 * 3600
DORMANT_AFTER = 90 * 24 * 3600
SCAN_WINDOW = 30 * 24 * 3600


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
    users: list[User] = field(default_factory=list)
    oidc_enabled: bool = False
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    guardrails: dict[str, Any] = field(default_factory=guardrails.defaults)
    people: list[Person] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)


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


def _guardrail_findings(s: Snapshot, control: str) -> tuple[list[str], list[str], list[str]]:
    """(titles of relaxed guardrails that fail `control`, findings of those that make it partial, evidence)."""
    g = guardrails.merged(s.guardrails)
    mapped = [x for x in guardrails.REGISTRY.values() if x.control == control]
    keys = [x.key for x in mapped] + [x.requires for x in mapped if x.requires]
    relaxed = guardrails.weakened(g, control)
    # a switch that lets more happen (off by default) names its bound, e.g. nested teams "up to maximum team depth 2"
    loose = [(r.finding or r.title) + (f" (up to {guardrails.REGISTRY[r.requires].title.lower()} {g[r.requires]})"
                                       if r.requires and r.default is False else "")
             for r in relaxed if r.weakens == "partial"]
    return [r.title for r in relaxed if r.weakens == "fail"], loose, [f"{k}={g[k]}" for k in keys]


def check_agent_approvals(s: Snapshot) -> Result:
    if s.autonomy == "autonomous":
        return "fail", "Agents run in autonomous mode - state-changing actions are not reviewed.", []
    off, loose, evidence = _guardrail_findings(s, "HB-AC-2")
    evidence = [f"autonomy={s.autonomy}", *evidence]
    if off:
        return "fail", "Switched off: " + "; ".join(off) + ".", evidence
    if loose:
        return "partial", (f"Autonomy is '{s.autonomy}', but " + " and ".join(loose) + " (guardrails relaxed)."), evidence
    return "pass", f"Autonomy is '{s.autonomy}': state-changing agent actions wait in the approval queue.", evidence


def check_agent_guardrails(s: Snapshot) -> Result:
    g = guardrails.merged(s.guardrails)
    off, loose, evidence = _guardrail_findings(s, "HB-AC-6")
    if off:
        return "fail", "Switched off: " + "; ".join(off) + ".", evidence
    if loose:
        return "partial", "Core guardrails are on, but " + " and ".join(loose) + ".", evidence
    return "pass", (f"Catastrophic commands are blocked, team agents' actions follow the approval policy and never exceed "
                    f"their parent's permissions; teams have at most {g['max_team_size']} agents and do not nest."), evidence


def check_ssh_hardening(s: Snapshot) -> Result:
    if not s.hosts:
        return "na", "No remote hosts registered.", []
    missing = [h.name for h in s.hosts if not h.strict_host_keys or not h.key_path]
    status, detail, _ = _ratio(len(s.hosts) - len(missing), len(s.hosts), "hosts (key auth + host key check)", missing)
    return status, detail, [h.name for h in s.hosts if h.name not in missing]


def check_hub_auth(s: Snapshot) -> Result:
    enabled = [u for u in s.users if not u.disabled]
    if not any(u.role == "admin" for u in enabled):
        return "fail", "No enabled administrator account: finish first-run setup.", []
    roles = ", ".join(f"{sum(1 for u in enabled if u.role == r)} {r}" for r in ("admin", "operator", "viewer"))
    evidence = [f"{len(enabled)} enabled accounts ({roles})", "role checked on every API call"]
    if s.oidc_enabled:
        sso = sum(1 for u in enabled if u.auth_source == "oidc")
        return "pass", f"Single sign-on (OIDC) is enabled; {sso} of {len(enabled)} accounts use it.", evidence
    return "partial", ("Hub accounts use local passwords only - connect the suite's identity provider (OIDC) "
                       "to enforce MFA."), evidence


def check_dormant_accounts(s: Snapshot) -> Result:
    if not s.users:
        return "manual", "No hub accounts yet.", []
    cutoff = time.time() - DORMANT_AFTER
    enabled = [u for u in s.users if not u.disabled]
    dormant = [u.username for u in enabled if (u.last_login or u.created_at) < cutoff]
    if not enabled:
        return "pass", "Every hub account is disabled.", []
    if not dormant:
        return "pass", f"All {len(enabled)} enabled accounts signed in within 90 days.", [u.username for u in enabled[:10]]
    status = "fail" if len(dormant) == len(enabled) else "partial"
    shown = ", ".join(dormant[:6]) + ("..." if len(dormant) > 6 else "")
    return status, f"{len(dormant)}/{len(enabled)} enabled accounts have not signed in for 90 days: {shown}", []


def check_leavers(s: Snapshot) -> Result:
    if not s.people:
        return "na", "No people in the People app yet - connect a directory (Okta, Keycloak, SCIM) or add people.", []
    left = [p for p in s.people if p.status in ("suspended", "terminated")]
    findings = find_leavers(s.people, s.assets, s.users, s.accounts, {t.id: t.name for t in s.tools})
    evidence = [f"{len(s.people)} people, {len(left)} suspended or terminated", f"{len(s.accounts)} tool accounts linked"]
    if not findings:
        return "pass", (f"None of the {len(left)} people who left or are suspended still has access or company assets."
                        if left else f"No leavers among {len(s.people)} people."), evidence
    shown = "; ".join(f["summary"] for f in findings[:4]) + ("..." if len(findings) > 4 else "")
    status = "fail" if any(f["severity"] == "fail" for f in findings) else "partial"
    return status, f"{len(findings)} leaver(s) not cleaned up: {shown}", evidence


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


def check_scan_coverage(s: Snapshot) -> Result:
    in_scope = [a for a in s.assets if a.scan_scope and a.status != "retired"]
    if not in_scope:
        return "manual", "No assets are in vulnerability-scan scope - put the assets to scan in scope.", []
    cutoff = time.time() - SCAN_WINDOW
    missing = [a.name for a in in_scope if not a.last_scanned_at or a.last_scanned_at < cutoff]
    status, detail, _ = _ratio(len(in_scope) - len(missing), len(in_scope), "in-scope assets scanned within 30 days",
                               missing)
    evidence = [f"{a.name}: scanned {time.strftime('%Y-%m-%d', time.gmtime(a.last_scanned_at))}" for a in in_scope
                if a.last_scanned_at and a.last_scanned_at >= cutoff]
    return status, detail, evidence[:10]


def check_vuln_sla(s: Snapshot) -> Result:
    if not s.vulnerabilities and not any(a.scan_scope and a.status != "retired" for a in s.assets):
        return "manual", "No vulnerability data yet - scan in-scope assets or connect a scanner.", []
    now = time.time()
    serious = [v for v in s.vulnerabilities if v.status in OPEN_STATES and v.severity in ("critical", "high")]
    overdue = [v for v in serious if v.due_at is not None and v.due_at < now]
    fixed = sum(1 for v in s.vulnerabilities if v.status == "fixed")
    evidence = [f"{len(serious)} open critical/high finding(s)", f"{fixed} finding(s) fixed"]
    if not overdue:
        return "pass", f"{len(serious)} critical/high finding(s) open, all within their SLA.", evidence
    shown = ", ".join(f"{v.title} ({v.host or 'unknown host'})" for v in overdue[:4]) + ("..." if len(overdue) > 4 else "")
    status = "fail" if any(v.severity == "critical" for v in overdue) else "partial"
    return status, f"{len(overdue)} critical/high finding(s) past their SLA: {shown}", evidence


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
    "agent_guardrails": check_agent_guardrails,
    "ssh_hardening": check_ssh_hardening,
    "hub_auth": check_hub_auth,
    "dormant_accounts": check_dormant_accounts,
    "leavers": check_leavers,
    "tools_manifest": check_tools_manifest,
    "patch_review": check_patch_review,
    "tools_health": check_tools_health,
    "audit_log": check_audit_log,
    "software_versions": check_software_versions,
    "scan_coverage": check_scan_coverage,
    "vuln_sla": check_vuln_sla,
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
