"""Scores how well each tool fits the hub, and maps how tools connect to each other.

Every open check names the one fix that can close it (``Check.fix``, a patch strategy the Patch Agent understands) or
none, and then its detail says what a person can do instead - never a fix that cannot close its gap, and never a pass
that is not true (a ``TODO`` placeholder is no value, an unmerged adopted manifest is not the tool's own). The known
product profiles (known_tools.py) say how a recognised product starts, where its health check is and what API it
has; ``EvalContext`` adds what the checks cannot see in the manifest: a built-in connector that fits the tool, and one
sentence on the patches tried before (gapfix.history_note). This module never imports strategies or gapfix.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from typing import Any, Callable

from ..models import Check, CompatibilityReport, Tool
from . import identity, known_tools, sso_catalog
from .analyzer import placeholder
from .identity import IdentityPrefs

# Capabilities the hub itself offers to every tool.
BUILTIN_PROVIDES = {"events.bus", "notify.webhook"}
SSO_MODES = {"oidc", "saml", "oauth2", "ldap"}
STATUS_POINTS = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
# Stacks the Patch Agent's code patches handle (a health endpoint added to the source); a "dist" folder holds built
# binaries, not source to patch.
CODE_PATCH_STACKS = frozenset({"python", "node", "go", "ruby", "php", "rust", "java"})
NO_LAUNCH = ("No launch command found. The Patch Agent proposes one (with an AI model), or an administrator sets it in "
             "Integration > Launch > Edit.")
NO_ADDRESS = "No port or address is known yet: set how it starts first."
NO_SAAS_ADDRESS = "No address is known for this service yet: an administrator sets it in Integration > Health > Edit."


@dataclass
class EvalContext:
    """What the checks cannot read from a tool's manifest: `builtin_api` gives the title of a built-in (or saved)
    connector that reaches the tool's API, `note` one sentence on earlier attempts at a check's fix (appended to its
    detail), `waiting` why an applied patch for a check (by id) has no effect yet - a code change on a branch nobody
    merged, an adapter skeleton nothing runs: the open check then says so and offers no fix. The Hub Supervisor fills
    them (strategies.connector_api, gapfix.history_note, gapfix.waiting)."""

    builtin_api: Callable[[Tool], str | None] = lambda t: None
    note: Callable[[Tool, Check], str | None] = lambda t, c: None
    waiting: Callable[[Tool, str], str | None] = lambda t, check_id: None


def _value(value: str | None) -> str | None:
    """A manifest string as a check reads it: a "TODO ..." placeholder is no value."""
    return None if not value or placeholder(value) else value


def sso_check(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None) -> Check:
    """Single sign-on, and the strategy that closes the gap:

    - no identity provider in the suite: pass when the tool supports SSO, else fail with "sso_proxy";
    - the selected provider and the tool's native OIDC/SAML support (catalog, .env keys, manifest): "sso_connect";
    - source code, no native SSO, an AI model available: "sso_code";
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
                             "to the code (with an AI model).", "sso_code")
    if m.kind != "saas":
        return check(status, f"{prefix}{reason}. An SSO proxy in front of it signs people in through {provider.name}.",
                     "sso_proxy")
    return check(status, f"{prefix}Configure single sign-on in the service's admin console (if your plan includes it), "
                         f"with {provider.name} as the identity provider.")


def manifest_check(tool: Tool) -> Check:
    """Hub manifest: the tool's own file (native), else Atrium's built-in profile of the recognised product when it
    says how to run, check or reach it, else an adopted manifest still waiting to be merged, else the add_manifest
    patch. A SaaS service has no folder to ship a manifest in: once adopted, the hub keeps it."""
    m = tool.manifest
    assert m is not None

    def check(status: str, detail: str, fix: str | None = None) -> Check:
        return Check(id="manifest", title="Hub manifest", status=status, weight=2, detail=detail, fix=fix)  # type: ignore[arg-type]

    profile = known_tools.for_manifest(m)
    if m.native:
        return check("pass", "Ships its own hub manifest.")
    if profile is not None and known_tools.describes(m):
        waiting = f" An adopted hub manifest waits unmerged at {m.adopted}." if m.adopted else ""
        return check("pass", f"Described by Atrium's built-in {profile.title} profile; hub-side settings are kept by "
                             f"Atrium.{waiting}")
    if m.adopted and not tool.path:
        return check("pass", f"Adopted: the hub keeps this service's manifest at {m.adopted}.")
    if m.adopted:
        return check("warn", f"Adopted at {m.adopted}, not merged yet: merge it into {tool.path} and Re-analyse.")
    return check("warn", "Manifest was inferred by the hub; adopt it so it is versioned with the tool.", "add_manifest")


def launch_check(tool: Tool) -> Check:
    """Reachable (SaaS), or launchable from the hub: a launch command passes; without one the fix is always the
    launch_command patch (a known product's recipe, else a command the AI model proposes), and the detail says what
    it would run or what is missing - an administrator can also set it in the manifest editor."""
    m = tool.manifest
    assert m is not None
    if m.kind == "saas":
        reachable = _value(m.ui.url) or _value(m.api.base_url)
        return Check(id="launch", title="Reachable", status="pass" if reachable else "fail",
                     detail=reachable or "No URL known for this service.")
    command = _value(m.launch.command)
    if command:
        return Check(id="launch", title="Launchable from the hub", status="pass", detail=f"`{command}`")
    plan = known_tools.launch_plan(m, tool.id)
    profile = known_tools.for_manifest(m)
    if plan is not None and profile is not None:
        needs = f" (needs {plan.requires})" if plan.requires else ""
        detail = f"Atrium can start {profile.title} with {plan.summary}{needs}: approve the launch_command patch."
    elif profile is not None and profile.notes:
        detail = " ".join(profile.notes)
    else:
        detail = NO_LAUNCH
    return Check(id="launch", title="Launchable from the hub", status="warn", detail=detail, fix="launch_command")


def health_check(tool: Tool) -> Check:
    """Health check: a URL passes. Without one, the first rule that applies picks the fix:

    1. the product's health endpoint is switched on through the launch environment, or is always on and its URL is
       known now: health_config;
    2. the launch_command patch would switch it on: launch_command;
    3. a compose folder: a probe once a port is known (the detail says what to add to the compose file), else
       launch_command;
    4. source code the Patch Agent can change (oss, its folder, a stack in CODE_PATCH_STACKS, not a "dist" folder)
       with a known port: health_endpoint - but never for a product whose health endpoint Atrium knows (its profile
       has one: the note says how to switch it on), nor when the launch command runs a container or compose file
       (a change to the source would never run);
    5. a port, portal URL or API URL known: health_probe;
    6. else launch_command (a SaaS service: no fix, an administrator sets its URL)."""
    m = tool.manifest
    assert m is not None
    url = _value(m.health.url)
    if url:
        return Check(id="health", title="Health check", status="pass", detail=url)

    def check(fix: str | None, detail: str) -> Check:
        return Check(id="health", title="Health check", status="warn", detail=detail, fix=fix)

    plan = known_tools.health_plan(m, tool.id)
    port = m.launch.port if m.kind != "saas" else None
    note = f" {plan.note}" if plan and plan.note else ""
    if plan is not None and plan.via == "config":
        return check("health_config", plan.note)
    if plan is not None and plan.via == "builtin" and plan.url:  # e.g. the port became known after the analysis
        profile = known_tools.for_manifest(m)
        return check("health_config", f"{profile.title if profile else tool.name} serves its own health check at "
                                      f"{plan.url}: the health_config patch uses it.")
    if plan is not None and plan.via == "launch" and known_tools.launch_plan(m, tool.id) is not None:
        return check("launch_command", plan.note)
    if plan is not None and plan.via == "compose":
        return check("health_probe" if port else "launch_command", plan.note)
    command = (m.launch.command or "").strip()
    container = bool(known_tools.CONTAINER_RUN_RE.match(command) or known_tools.COMPOSE_CMD_RE.match(command))
    if (m.kind == "oss" and tool.path and CODE_PATCH_STACKS & set(m.stack) and "dist" not in m.stack and port
            and plan is None and not container):
        return check("health_endpoint", f"No health endpoint detected.{note}")
    if port or _value(m.ui.url) or _value(m.api.base_url):
        return check("health_probe", f"No health endpoint detected.{note}")
    if m.kind == "saas":
        return check(None, NO_SAAS_ADDRESS)
    return check("launch_command", f"{NO_ADDRESS}{note}")


def api_check(tool: Tool, ctx: EvalContext) -> Check:
    """Programmable API: a detected API, the recognised product's API (its profile) or a built-in connector that
    reaches it passes, naming it; a closed or SaaS tool without one gets the api_adapter skeleton; open-source code
    gets no fix (an administrator sets the API when it has one)."""
    m = tool.manifest
    assert m is not None

    def check(status: str, detail: str, fix: str | None = None) -> Check:
        return Check(id="api", title="Programmable API", status=status, detail=detail, fix=fix)  # type: ignore[arg-type]

    facts = known_tools.api_info(m)
    connector = ctx.builtin_api(tool)
    via = f"; built-in connector: {connector}" if connector else ""
    if m.api.type != "none":
        label = f" ({facts.label})" if facts and facts.type == m.api.type else ""
        operations = f", {m.api.endpoints} operations" if m.api.endpoints else ""
        return check("pass", f"{m.api.type.upper()} API{label}{operations}{via}")
    if facts is not None:
        return check("pass", f"{facts.type.upper()} API ({facts.label}){via}")
    if connector:
        return check("pass", f"Reached through the built-in connector: {connector}")
    if m.kind in ("closed", "saas"):
        return check("warn", "No API detected - other tools cannot automate it.", "api_adapter")
    return check("warn", "No API detected. If it has one, an administrator sets it in Integration > API > Edit.")


def events_check(tool: Tool) -> Check:
    """Emits events: webhooks, or events the tool itself declares, pass. The "<id>.changed" event of a generated
    poller (an applied event_adapter patch, kept in the hub-side overrides) does not: nothing runs the poller until a
    person starts it. A product whose events need more than a poller says why; otherwise the event_adapter patch once
    an address is known, else launch_command first."""
    m = tool.manifest
    assert m is not None

    def check(status: str, detail: str, fix: str | None = None) -> Check:
        return Check(id="events", title="Emits events", status=status, detail=detail, fix=fix)  # type: ignore[arg-type]

    polled = f"{tool.id}.changed"
    hub_side = ((tool.manifest_overrides or {}).get("events") or {}).get("emits") or []
    own = [e for e in m.events.emits if not (e == polled and e in hub_side)]
    if "webhooks" in m.provides or own:
        return check("pass", ", ".join(m.events.emits) or "webhooks")
    if m.events.emits:  # only the poller's event
        return check("warn", f"An event poller was generated (adapters/{tool.id}/events/adapter.py); it publishes "
                             f"{polled} only while it runs - start it with an integration token (the hub does not run "
                             "it).")
    note = known_tools.events_note(m)
    if note:
        return check("warn", note)
    if (m.launch.port and m.kind != "saas") or _value(m.ui.url) or _value(m.api.base_url):
        return check("warn", "Other tools cannot react to changes in this tool.", "event_adapter")
    if m.kind == "saas":
        return check("warn", "Other tools cannot react to changes in this tool, and no address is known for it.")
    return check("warn", f"Other tools cannot react to changes in this tool. {NO_ADDRESS}", "launch_command")


def evaluate_tool(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None,
                  ctx: EvalContext | None = None) -> CompatibilityReport:
    m = tool.manifest
    if m is None:
        return CompatibilityReport(score=0, level="incompatible", checks=[
            Check(id="manifest", title="Hub manifest", status="fail", detail="The tool has not been analysed yet.")
        ])
    ctx = ctx or EvalContext()
    adapter_side = m.kind in ("closed", "saas")
    checks: list[Check] = [manifest_check(tool), launch_check(tool), health_check(tool), api_check(tool, ctx),
                           sso_check(tool, others, idp), events_check(tool)]

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

    for check in checks:  # an applied patch with no effect yet (unmerged code, a skeleton): a person's next step
        pending = ctx.waiting(tool, check.id) if check.status != "pass" else None
        if pending:
            check.fix, check.detail = None, pending
    for check in checks:  # what happened to the patches tried before (rejected, failed, applied but still open)
        if check.status != "pass" and check.fix:
            note = ctx.note(tool, check)
            if note:
                check.detail = f"{check.detail} {note}".strip()

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


def evaluate_suite(tools: list[Tool], idp: IdentityPrefs | None = None,
                   ctx: EvalContext | None = None) -> dict[str, CompatibilityReport]:
    return {t.id: evaluate_tool(t, [o for o in tools if o.id != t.id], idp, ctx) for t in tools}


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
