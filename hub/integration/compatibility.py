"""Scores how well each tool fits the hub, and maps how tools connect to each other."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from ..models import Check, CompatibilityReport, Tool

# Capabilities the hub itself offers to every tool.
BUILTIN_PROVIDES = {"events.bus", "notify.webhook"}
SSO_MODES = {"oidc", "saml", "oauth2", "ldap"}
STATUS_POINTS = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


def evaluate_tool(tool: Tool, others: list[Tool]) -> CompatibilityReport:
    m = tool.manifest
    if m is None:
        return CompatibilityReport(score=0, level="incompatible", checks=[
            Check(id="manifest", title="Hub manifest", status="fail", detail="The tool has not been analysed yet.")
        ])
    adapter_side = m.kind in ("closed", "saas")
    checks: list[Check] = []

    checks.append(Check(
        id="manifest", title="Hub manifest", weight=2,
        status="pass" if m.native else "warn",
        detail="Ships its own hub manifest." if m.native else "Manifest was inferred by the hub; adopt it so it is versioned with the tool.",
        fix=None if m.native else "add_manifest",
    ))

    if m.kind == "saas":
        reachable = bool(m.ui.url or m.api.base_url)
        checks.append(Check(id="launch", title="Reachable", status="pass" if reachable else "fail",
                            detail=m.ui.url or m.api.base_url or "No URL known for this service."))
    else:
        checks.append(Check(
            id="launch", title="Launchable from the hub", status="pass" if m.launch.command else "warn",
            detail=f"`{m.launch.command}`" if m.launch.command else "No launch command found - add one to the manifest.",
            fix=None if m.launch.command else "add_manifest",
        ))

    if m.health.url:
        checks.append(Check(id="health", title="Health check", status="pass", detail=m.health.url))
    else:
        can_code_patch = m.kind == "oss" and bool(tool.path)
        checks.append(Check(
            id="health", title="Health check", status="warn",
            detail="No health endpoint detected.",
            fix="health_endpoint" if can_code_patch else "health_probe",
        ))

    if m.api.type != "none":
        detail = f"{m.api.type.upper()} API" + (f", {m.api.endpoints} operations" if m.api.endpoints else "")
        checks.append(Check(id="api", title="Programmable API", status="pass", detail=detail))
    else:
        checks.append(Check(id="api", title="Programmable API", status="warn",
                            detail="No API detected - other tools cannot automate it.",
                            fix="api_adapter" if adapter_side else None))

    if m.auth.sso in SSO_MODES:
        checks.append(Check(id="sso", title="Single sign-on", status="pass", weight=2, detail=f"Supports {m.auth.sso.upper()}."))
    else:
        checks.append(Check(id="sso", title="Single sign-on", status="fail", weight=2,
                            detail="No SSO support detected - users would need separate accounts.",
                            fix="sso_proxy" if m.kind != "saas" else None))

    if "webhooks" in m.provides or m.events.emits:
        checks.append(Check(id="events", title="Emits events", status="pass",
                            detail=", ".join(m.events.emits) or "webhooks"))
    else:
        checks.append(Check(id="events", title="Emits events", status="warn",
                            detail="Other tools cannot react to changes in this tool.", fix="event_adapter"))

    port = m.launch.port
    clashes = [o.name for o in others if o.manifest and port and o.manifest.launch.port == port and m.kind != "saas"]
    if clashes:
        checks.append(Check(id="ports", title="Port is free", status="fail", detail=f"Port {port} is also used by {', '.join(clashes)}.",
                            fix="reassign_port"))
    elif port:
        checks.append(Check(id="ports", title="Port is free", status="pass", detail=f"Port {port}."))

    available = set(BUILTIN_PROVIDES)
    for other in others:
        if other.manifest:
            available.update(other.manifest.provides)
    unmet = [c for c in m.consumes if c not in available]
    if m.consumes:
        checks.append(Check(
            id="dependencies", title="Dependencies available in the suite",
            status="warn" if unmet else "pass",
            detail=("Missing: " + ", ".join(unmet) + ". Import a tool that provides them, or run them yourself.") if unmet
            else "Everything it needs is provided by the suite.",
        ))

    total = sum(c.weight for c in checks)
    score = round(100 * sum(STATUS_POINTS[c.status] * c.weight for c in checks) / total) if total else 0
    if m.native and score >= 85:
        level = "native"
    elif score >= 75:
        level = "good"
    elif score < 30:
        level = "incompatible"
    elif adapter_side:
        level = "adapter"
    else:
        level = "patchable"
    return CompatibilityReport(score=score, level=level, checks=checks)


def evaluate_suite(tools: list[Tool]) -> dict[str, CompatibilityReport]:
    return {t.id: evaluate_tool(t, [o for o in tools if o.id != t.id]) for t in tools}


def suite_matrix(tools: list[Tool]) -> dict[str, Any]:
    """Nodes and links describing how the imported tools fit together."""
    analysed = [t for t in tools if t.manifest]
    nodes = [{
        "id": t.id, "name": t.name, "kind": t.manifest.kind if t.manifest else None,
        "score": t.report.score if t.report else None, "level": t.report.level if t.report else None,
    } for t in tools]
    links: list[dict[str, Any]] = []
    for a in analysed:
        for b in analysed:
            if a.id == b.id:
                continue
            ma, mb = a.manifest, b.manifest
            assert ma and mb
            for capability in sorted(set(ma.provides) & set(mb.consumes)):
                links.append({"source": a.id, "target": b.id, "type": "capability", "via": capability})
            if ("auth.oidc" in ma.provides or "auth.saml" in ma.provides) and mb.auth.sso in SSO_MODES and "auth.oidc" not in mb.provides:
                links.append({"source": a.id, "target": b.id, "type": "identity", "via": f"SSO ({mb.auth.sso})"})
            for emitted in ma.events.emits:
                for pattern in mb.events.listens:
                    if fnmatch(emitted, pattern) or fnmatch(pattern, emitted):
                        links.append({"source": a.id, "target": b.id, "type": "event", "via": pattern})
    conflicts = []
    by_port: dict[int, list[str]] = {}
    for t in analysed:
        if t.manifest and t.manifest.launch.port and t.manifest.kind != "saas":
            by_port.setdefault(t.manifest.launch.port, []).append(t.name)
    for port, names in by_port.items():
        if len(names) > 1:
            conflicts.append({"port": port, "tools": names})
    provided = set(BUILTIN_PROVIDES).union(*(t.manifest.provides for t in analysed if t.manifest)) if analysed else set(BUILTIN_PROVIDES)
    unmet = {t.id: [c for c in t.manifest.consumes if c not in provided] for t in analysed if t.manifest}
    scores = [t.report.score for t in tools if t.report]
    return {
        "nodes": nodes,
        "links": links,
        "conflicts": conflicts,
        "unmet": {k: v for k, v in unmet.items() if v},
        "suite_score": round(sum(scores) / len(scores)) if scores else None,
    }
