"""Scores how well each tool fits the hub, and maps how tools connect to each other."""

from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from ..models import Check, CompatibilityReport, Tool
from . import identity, sso_catalog
from .identity import IdentityPrefs

# Capabilities the hub itself offers to every tool.
BUILTIN_PROVIDES = {"events.bus", "notify.webhook"}
SSO_MODES = {"oidc", "saml", "oauth2", "ldap"}
STATUS_POINTS = {"pass": 1.0, "warn": 0.5, "fail": 0.0}


def sso_check(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None) -> Check:
    """Single sign-on, and the strategy that closes the gap:

    - no identity provider in the suite: pass when the tool supports SSO, else fail with "sso_proxy";
    - the selected provider and the tool's native OIDC/SAML support (catalog, .env keys, manifest): "sso_connect";
    - source code, no native SSO, Claude available: "sso_code";
    - otherwise "sso_proxy" (SaaS: configure SSO in the vendor's console; no fix)."""
    m = tool.manifest
    assert m is not None
    idp = idp or IdentityPrefs()

    def check(status: str, detail: str, fix: str | None = None) -> Check:
        return Check(id="sso", title="Single sign-on", status=status, weight=2, detail=detail, fix=fix)  # type: ignore[arg-type]

    if identity.is_provider(tool):
        protocols = " and ".join(p.split(".")[1].upper() for p in m.provides if p in ("auth.oidc", "auth.saml"))
        return check("pass", f"Identity provider of the suite ({protocols}).")
    providers = identity.list_providers(others, idp.settings)
    if not providers:
        if m.auth.sso in SSO_MODES:
            return check("pass", f"Supports {m.auth.sso.upper()}.")
        return check("fail", "No SSO support detected - users would need separate accounts. Import an identity provider "
                             "(Keycloak, Authentik, Zitadel or Authelia) and the Patch Agent connects the tool to it natively.",
                     "sso_proxy" if m.kind != "saas" else None)
    if m.auth.sso == "ldap" and not m.auth.provider:
        return check("pass", "Signs in against the directory (LDAP).")
    selected = identity.select(tool, providers, idp)
    provider = selected.provider
    if provider is None:
        names = ", ".join(p.name for p in selected.candidates)
        return check("warn" if m.auth.sso in SSO_MODES else "fail",
                     f"{len(selected.candidates)} identity providers in the suite ({names}). Choose the one {tool.name} "
                     "should use, or a suite default, in Integration hub > Identity.")
    if m.auth.provider == provider.tool_id and m.auth.sso in SSO_MODES:
        return check("pass", f"Signs in through {provider.name} ({m.auth.sso.upper()}).")
    previous = next((p.name for p in providers if p.tool_id == m.auth.provider), None)
    prefix = f"Connected to {previous}, but {provider.name} is selected. " if previous else ""
    how = sso_catalog.native(tool, provider, idp.catalog)
    entry = sso_catalog.match(tool, idp.catalog)
    proxied = "oauth2-proxy" in (m.auth.notes or "")
    capable = how is not None or (m.auth.sso in SSO_MODES and not proxied)
    status = "warn" if capable else "fail"
    if how is not None:
        name = entry.name if entry else tool.name
        return check(status, f"{prefix}{name} supports {how[1].upper()} natively - the Patch Agent configures it and "
                             f"registers it as a client at {provider.name}.", "sso_connect")
    reason = entry.note if entry and entry.note else "No native single sign-on the hub can configure"
    if entry and entry.protocols:
        reason = f"{entry.name} supports {'/'.join(p.upper() for p in entry.protocols)} only, which {provider.name} does not offer"
    if m.kind == "oss" and tool.path and idp.llm and not entry:
        return check(status, f"{prefix}{reason}. The Patch Agent can add OpenID Connect sign-in through {provider.name} "
                             "to the code (with Claude).", "sso_code")
    if m.kind != "saas":
        return check(status, f"{prefix}{reason}. An SSO proxy in front of it signs people in through {provider.name}.",
                     "sso_proxy")
    return check(status, f"{prefix}Configure single sign-on in the service's admin console (if your plan includes it), "
                         f"with {provider.name} as the identity provider.")


def evaluate_tool(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None) -> CompatibilityReport:
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

    checks.append(sso_check(tool, others, idp))

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


def evaluate_suite(tools: list[Tool], idp: IdentityPrefs | None = None) -> dict[str, CompatibilityReport]:
    return {t.id: evaluate_tool(t, [o for o in tools if o.id != t.id], idp) for t in tools}


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
            if mb.auth.provider == a.id and identity.is_provider(a):  # b signs in through a
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
