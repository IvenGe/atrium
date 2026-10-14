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
    # results of the active extension packs' control rules (hub/extensions/controls.py), merged into their controls
    extension_results: list[dict[str, Any]] = field(default_factory=list)
    # network facts (hub/integration/network.compliance_facts): devices, drift, segmentation - ids only, no device text
    network: dict[str, Any] = field(default_factory=dict)
    # framework self-assessments that are not archived (hub/grc/frameworks/assessments.control_summaries)
    frameworks: list[dict[str, Any]] = field(default_factory=list)


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
    off, loose, guards = _guardrail_findings(s, "HB-CM-2")  # self-patching and extension guardrails
    evidence = [p.title for p in applied[:10]] + guards
    if off:
        return "fail", "Changes to Atrium's own code are not reviewed - switched off: " + "; ".join(off) + ".", evidence
    if s.autonomy == "autonomous":
        return "partial", "Patches are reviewed as branches, but autonomous mode applies them without approval.", evidence
    if loose:
        return "partial", "Patches go through the approval queue, but " + " and ".join(loose) + ".", evidence
    return "pass", f"Patches go through the approval queue ({len(applied)} applied, "\
        f"{sum(1 for p in s.patches if p.status == 'rejected')} rejected).", evidence


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


# -- network security (HB-NW-*): device text never reaches details or evidence, only ids and counts -----------------

BACKUP_WINDOW = 7 * 24 * 3600
NO_DEVICE = "No firewall or network device is connected"


def _shown(items: list[str], limit: int = 5) -> str:
    return ", ".join(items[:limit]) + (f" and {len(items) - limit} more" if len(items) > limit else "")


def _rule_names(devices: list[dict[str, Any]], key: str, limit: int = 20) -> list[str]:
    """Evidence lines naming the device's own rule ids (details only use positions: they reach agents)."""
    return [f"{d['ref']} {r['pos']}: {r['name']}" for d in devices for r in d.get(key) or []][:limit]


def _stale_note(devices: list[dict[str, Any]]) -> list[str]:
    stale = [d["ref"] for d in devices if d.get("stale")]
    return [f"snapshot not current for {_shown(stale)}"] if stale else []


def check_network_segmentation(s: Snapshot) -> Result:
    facts = s.network.get("segmentation") or {}
    if not facts.get("firewalls"):
        return "manual", "No firewall connected; segmentation is not verified.", []
    evidence = [f"{facts['firewalls']} firewall(s) evaluated (approximate: block rules, rule order and NAT are not "
                "evaluated)", *_stale_note(s.network.get("devices") or [])]
    violations = [v for v in facts.get("violations") or [] if v.get("control") in (None, "HB-NW-1")]
    if violations:
        shown = "; ".join(f"{v['from']} -> {v['to']} on {v['firewall']} ({v['policy']})" for v in violations[:4])
        more = f" and {len(violations) - 4} more" if len(violations) > 4 else ""
        return "partial", f"Possible violation: {shown}{more} (approximate evaluation).", evidence
    problems = []
    if facts.get("unconfirmed_roles"):
        problems.append(f"{len(facts['unconfirmed_roles'])} zone role(s) not confirmed")
    if facts.get("unresolved_aliases"):
        problems.append(f"{len(facts['unresolved_aliases'])} unresolved alias(es)")
    if problems:
        return "partial", "No possible violation found, but " + " and ".join(problems) + ".", evidence
    return "pass", "No possible violation of the segmentation policy; every zone role is confirmed.", evidence


def check_network_drift(s: Snapshot) -> Result:
    devices = s.network.get("devices") or []
    if not devices:
        return "manual", f"{NO_DEVICE}; configuration drift is not monitored.", []
    d = s.network.get("drift") or {}
    evidence = [f"{len(devices)} device(s) monitored",
                f"{d.get('detected_30d', 0)} change(s) in 30 days: {d.get('attributed_30d', 0)} made through Atrium, "
                f"{d.get('acknowledged_30d', 0)} acknowledged", *_stale_note(devices)]
    where = _shown(d.get("open_devices") or [])
    if d.get("open_critical"):
        return "fail", (f"{d['open_critical']} unexplained critical change(s) (any-to-any or management exposure) on "
                        f"{where} - review them in the Network app."), evidence
    if d.get("open"):
        return "partial", f"{d['open']} change(s) not made through Atrium wait for review on {where}.", evidence
    return "pass", "Every configuration change was made through Atrium or has been acknowledged.", evidence


def check_network_management(s: Snapshot) -> Result:
    devices = s.network.get("devices") or []
    if not devices:
        return "manual", f"{NO_DEVICE}; management exposure is not verified.", []
    exposed = [f"{d['ref']} {r['pos']}" for d in devices for r in d.get("management_exposed") or []]
    evidence = [f"{len(devices)} device(s) checked", *_stale_note(devices), *_rule_names(devices, "management_exposed")]
    if exposed:
        return "fail", f"{len(exposed)} rule(s) let traffic from anywhere reach device management: {_shown(exposed)}.", evidence
    return "pass", f"No rule exposes device management to the internet on {len(devices)} device(s).", evidence


def check_network_backups(s: Snapshot) -> Result:
    devices = s.network.get("devices") or []
    if not devices:
        return "manual", f"{NO_DEVICE}; no configuration to back up.", []
    cutoff = time.time() - BACKUP_WINDOW
    fresh = [d for d in devices if d.get("last_backup_at") and d["last_backup_at"] >= cutoff]
    missing = [d["ref"] + ("" if d.get("backup_supported") else " (its connector cannot take backups)")
               for d in devices if d not in fresh]
    status, detail, _ = _ratio(len(fresh), len(devices), "devices backed up within 7 days", missing)
    return status, detail, [f"{d['ref']}: {time.strftime('%Y-%m-%d', time.gmtime(d['last_backup_at']))}" for d in fresh]


def check_network_rules(s: Snapshot) -> Result:
    devices = s.network.get("devices") or []
    if not devices:
        return "manual", f"{NO_DEVICE}; firewall rules are not reviewed.", []
    any_any = [f"{d['ref']} {r['pos']}" for d in devices for r in d.get("any_any") or []]
    undocumented = [f"{d['ref']} {r['pos']}" for d in devices for r in d.get("undocumented_pass") or []]
    total = sum(d.get("pass_rules", 0) for d in devices)
    evidence = [f"{total} enabled pass rule(s) on {len(devices)} device(s)",
                f"{sum(d.get('unlogged_pass', 0) for d in devices)} pass rule(s) without logging", *_stale_note(devices),
                *_rule_names(devices, "any_any"), *_rule_names(devices, "undocumented_pass")]
    if any_any:
        return "fail", f"{len(any_any)} pass rule(s) allow any source to any destination on any service: {_shown(any_any)}.", evidence
    if undocumented:
        return "partial", f"{len(undocumented)} of {total} pass rule(s) have no description: {_shown(undocumented)}.", evidence
    return "pass", f"No any-to-any pass rule; all {total} pass rule(s) are described.", evidence


def check_network_changes(s: Snapshot) -> Result:
    """HB-CM-3: the device-change guardrails (second person and backup -> fail, maintenance window -> partial) and
    the change history: a device left in an unknown state fails it; emergency changes, changes approved by their own
    proposer and changes applied without a backup (made while a guardrail was off) are exceptions (partial) for 90
    days, whatever the guardrails say now."""
    devices = s.network.get("devices") or []
    facts = s.network.get("changes") or {}
    off, loose, evidence = _guardrail_findings(s, "HB-CM-3")
    g = guardrails.merged(s.guardrails)
    evidence = [f"device_changes={g.get('device_changes')}", f"approval_expiry_hours={g.get('approval_expiry_hours')}",
                *evidence]
    self_approved, unbacked = facts.get("self_approved_90d") or [], facts.get("unbacked_90d") or []
    if facts:
        evidence.append(f"in 90 days: {facts.get('applied_90d', 0)} applied, {facts.get('rolled_back_90d', 0)} rolled "
                        f"back, {facts.get('failed_90d', 0)} failed, {len(facts.get('emergency_90d') or [])} emergency, "
                        f"{len(self_approved)} approved by their proposer, {len(unbacked)} without a backup")
    if not devices and not facts.get("applied_90d"):
        return "manual", f"{NO_DEVICE}; no device changes to control.", evidence
    if facts.get("unknown_state"):
        return "fail", (f"{len(facts['unknown_state'])} device change(s) left a device in an unknown state "
                        f"({_shown(facts['unknown_state'])}) - check the device and restore a backup."), evidence
    if off:
        return "fail", "Device changes are not controlled - switched off: " + "; ".join(off) + ".", evidence
    emergencies = facts.get("emergency_90d") or []
    problems = list(loose)
    if emergencies:
        problems.append(f"{len(emergencies)} emergency change(s) bypassed the maintenance windows "
                        f"({_shown(emergencies)}) - review them")
    # exceptions recorded with each change: the guardrails may be on again now, the changes were made without them
    if self_approved:
        problems.append(f"{len(self_approved)} change(s) were approved by the person who proposed them "
                        f"({_shown(self_approved)}) - have a second administrator review them")
    if unbacked:
        problems.append(f"{len(unbacked)} change(s) were applied without a configuration backup "
                        f"({_shown(unbacked)}) - take a backup of the devices and review them")
    if problems:
        return "partial", "Device changes are reviewed and backed up, but " + " and ".join(problems) + ".", evidence
    if not facts.get("device_changes"):
        return "pass", ("Atrium does not change network devices (device changes are off); when they are on, a second "
                        "administrator, a maintenance window and a backup are required."), evidence
    return "pass", ("Device changes need a second administrator, wait for maintenance windows, are backed up first and "
                    "roll back unless verified."), evidence


# -- framework self-assessments (HB-PO-3): scores are people's judgement - only their age and key measures count -----

ASSESSMENT_CURRENT = 365 * 24 * 3600


def _day(ts: float | None) -> str:
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "never"


def check_framework_assessment(s: Snapshot) -> Result:
    if not s.frameworks:
        return "manual", ("No compliance framework self-assessment yet: start one in the Compliance hub "
                          "(Frameworks)."), []
    latest = max(s.frameworks, key=lambda a: (a.get("assessed_at") or 0, a.get("updated_at") or 0))
    evidence = [f"{a['framework_name']} '{a['name']}' (target {a['target_name']}): {a['verdict'].replace('_', ' ')}, "
                f"{a['progress']['percent']}% assessed, last scored {_day(a.get('assessed_at'))}"
                for a in sorted(s.frameworks, key=lambda a: -(a.get("assessed_at") or 0))[:5]]
    which = f"{latest['framework_name']} self-assessment '{latest['name']}'"
    problems = []
    if not latest.get("assessed_at"):
        problems.append("nothing scored yet")
    elif time.time() - latest["assessed_at"] > ASSESSMENT_CURRENT:
        problems.append(f"last scored on {_day(latest['assessed_at'])}, more than 12 months ago")
    below = latest.get("key_measures_below") or []
    if below:
        problems.append(f"{len(below)} key measure(s) of the {latest['target_name']} level below their threshold, N/A "
                        f"or not scored ({', '.join(below[:8])}{' ...' if len(below) > 8 else ''})")
    if problems:
        return "partial", f"The {which}: " + "; ".join(problems) + ".", evidence
    return "pass", (f"The {which} was last scored on {_day(latest['assessed_at'])}; every key measure of the "
                    f"{latest['target_name']} level reaches its threshold."), evidence


CHECKS: dict[str, Callable[[Snapshot], Result]] = {
    "framework_assessment": check_framework_assessment,
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
    "network_segmentation": check_network_segmentation,
    "network_drift": check_network_drift,
    "network_management": check_network_management,
    "network_backups": check_network_backups,
    "network_rules": check_network_rules,
    "network_changes": check_network_changes,
}


RATED = {"pass": 0, "partial": 1, "fail": 2}


def with_extension_evidence(state: ControlState, results: list[dict[str, Any]]) -> ControlState:
    """Combine a control's own check with the extension rules that rate it: the worse status counts (a control the
    hub cannot check itself takes the rules' status only when they find a problem); every rule adds evidence."""
    rated = [r for r in results if r.get("status") in RATED]
    if not rated:
        return state
    worst = max((r["status"] for r in rated), key=RATED.__getitem__)
    if state.status in RATED:
        status = max(state.status, worst, key=RATED.__getitem__)
    else:
        status = worst if worst != "pass" else state.status
    problems = [r["detail"] for r in rated if r["status"] != "pass"]
    detail = state.detail + (f" Extension evidence: {'; '.join(problems)}." if problems else "")
    evidence = [*state.evidence, *(f"{r['extension']}: {r['detail']}" for r in rated)]
    return state.model_copy(update={"status": status, "detail": detail, "evidence": evidence})


def run_check(control: Control, snapshot: Snapshot) -> ControlState:
    now = time.time()
    extra = [r for r in snapshot.extension_results if r.get("control") == control.id]
    if not control.check:
        state = ControlState(id=control.id, status="manual", detail="Assess manually.", evaluated_at=now)
        return with_extension_evidence(state, extra)
    fn = check_policy(control.check.split(":", 1)[1]) if control.check.startswith("policy:") else CHECKS[control.check]
    status, detail, evidence = fn(snapshot)
    state = ControlState(id=control.id, status=status, detail=detail, evidence=evidence, evaluated_at=now)  # type: ignore[arg-type]
    return with_extension_evidence(state, extra)


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
