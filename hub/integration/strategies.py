"""Integration strategies: the data flows the hub proposes between tools and its built-in apps, and - per tool - how
far each way of integrating it has got (identity, events, data flows, a generated connector, adapters and patches).

Flow rules, from each connection's capabilities (its last successful test, else what the connector declares):

- a scanner (action "scan") -> scan the assets in scan scope and import the findings into Hub Vulnerabilities;
  a tool that only reads vulnerabilities -> pull them into Hub Vulnerabilities;
- writes vulnerabilities -> push the hub's findings to it;
- reads assets, and is the system of record for them or cannot take them -> pull into Hub Assets;
- writes assets and is not their system of record -> push Hub Assets (the hub's list is canonical, so a tool that can
  do both gets the push only and nothing loops back);
- writes controls -> push the hub's controls with their evidence; reads risks -> pull them into the risk register.

Proposals become approvals of kind "flow" (enabled straight away in autonomous mode).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .. import connectors
from ..models import Flow, Tool
from . import connections, flows, identity

if TYPE_CHECKING:
    from ..core import Hub

ADAPTER_STRATEGIES = {"api_adapter", "event_adapter", "health_probe", "health_endpoint", "add_manifest", "reassign_port",
                      "custom"}
BUILTIN_SCORE = 50  # a detected built-in connector at least this sure is offered instead of generating one


def proposals(hub: "Hub") -> list[Flow]:
    """Flows the rules call for that do not exist yet (in any state: a rejected proposal stays rejected)."""
    existing = {flows.key(f) for f in flows.all_flows(hub)}
    out: list[Flow] = []
    for conn in connections.all_connections(hub):
        tool = hub.get_tool(conn.id)
        try:
            cls = connectors.connector_class(conn.kind)
        except connectors.ConnectorError:
            continue
        if tool is None:
            continue
        domains = connections.capabilities(conn)
        end = f"tool:{tool.id}"
        strategy = "generated" if conn.generated else "connector"

        def reads(domain: str) -> bool:
            return "read" in domains.get(domain, [])

        def writes(domain: str) -> bool:
            return "write" in domains.get(domain, [])

        def add(domain: str, source: str, target: str, action: str | None, reason: str) -> None:
            if (domain, source, target, action) not in existing:
                existing.add((domain, source, target, action))
                out.append(flows.make(hub, domain, source, target, action, reason=reason, strategy=strategy))

        name = tool.name
        if "scan" in cls.actions:
            add("vulnerabilities", "hub", end, "scan",
                f"{name} is a vulnerability scanner: it scans the assets in scan scope and its findings land in Hub "
                "Vulnerabilities, where deadlines, risks and compliance follow them.")
        elif reads("vulnerabilities"):
            add("vulnerabilities", end, "hub", None, f"{name} reports vulnerabilities: they are tracked in Hub Vulnerabilities.")
        if writes("vulnerabilities"):
            add("vulnerabilities", "hub", end, None, f"{name} can take vulnerabilities: it receives the hub's findings.")
        sor = "assets" in cls.system_of_record
        if reads("assets") and (sor or not writes("assets")):
            add("assets", end, "hub", None,
                f"{name} keeps an asset inventory" + (" and is its system of record" if sor else "")
                + ": its assets are merged into Hub Assets (matched by address, hostname or serial).")
        if writes("assets") and not sor:
            add("assets", "hub", end, None, f"{name} keeps its own asset list: it receives Hub Assets, the canonical list.")
        if writes("controls"):
            add("controls", "hub", end, None,
                f"{name} manages compliance: it receives the hub's controls with their automated evidence.")
        if reads("risks"):
            add("risks", end, "hub", None, f"{name} keeps risk scenarios: they are pulled into the hub's risk register.")
    return out


def propose(hub: "Hub", requested_by: str = "supervisor") -> list[Flow]:
    """Save new proposals; each waits for approval unless the hub runs autonomously."""
    autonomous = hub.prefs["autonomy"] == "autonomous"
    created = []
    for flow in proposals(hub):
        if autonomous:
            flow.status = "enabled"
            flows.save(hub, flow)
            hub.activity(requested_by, "info", f"Enabled data flow: {flow.title}", flow_id=flow.id)
        else:
            flows.save(hub, flow)
            approval = hub.approvals.create("flow", f"Data flow: {flow.title}", flow.reason,
                                            {"flow_id": flow.id, "tool_id": flow.tool_id, "domain": flow.domain,
                                             "source": flow.source, "target": flow.target, "action": flow.action,
                                             "schedule_minutes": flow.schedule_minutes}, requested_by)
            flow.approval_id = approval.id
            flows.save(hub, flow)
        created.append(flow)
    return created


# --------------------------------------------------------------------------------------
# per-tool overview
# --------------------------------------------------------------------------------------


def _item(id_: str, title: str, state: str, detail: str, action: str | None = None) -> dict[str, Any]:
    """state: active | pending | failing | needs_decision | available | needs_claude | unavailable | not_needed"""
    return {"id": id_, "title": title, "state": state, "detail": detail, "action": action}


def builtin_connector(tool: Tool) -> dict[str, Any] | None:
    best = next((d for d in connectors.detect(tool) if d["kind"] != "generic_rest"), None)
    return best if best and best["score"] >= BUILTIN_SCORE else None


def has_openapi(tool: Tool) -> bool:
    return bool(tool.openapi_url or (tool.manifest and tool.manifest.api.spec))


def tool_strategies(hub: "Hub", tool: Tool, sso_rows: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if sso_rows is None:
        sso_rows = {r["tool_id"]: r for r in identity.overview(hub)["tools"]}
    m = tool.manifest
    checks = {c.id: c for c in (tool.report.checks if tool.report else [])}
    patches = hub.patches(tool.id)
    items = []

    # identity / single sign-on
    if identity.is_provider(tool):
        items.append(_item("identity", "Identity / single sign-on", "active", "Identity provider of the suite."))
    else:
        row = sso_rows.get(tool.id)
        state, action = {"connected": ("active", None), "pending": ("pending", "approve"),
                         "needs_choice": ("needs_decision", "choose_provider"),
                         "not_connected": ("available", "connect_sso"),
                         "no_provider": ("unavailable", "import_provider")}.get(row["status"] if row else "", ("unavailable", None))
        if state == "unavailable" and m and m.auth.sso in ("oidc", "saml", "oauth2", "ldap"):
            state = "available"
        items.append(_item("identity", "Identity / single sign-on", state,
                           (row or {}).get("detail") or (checks["sso"].detail if "sso" in checks else ""), action))

    # events
    events = checks.get("events")
    event_patches = [p for p in patches if p.strategy == "event_adapter"]
    if events and events.status == "pass" or any(p.status == "applied" for p in event_patches):
        state = "active"
    elif any(p.status == "proposed" for p in event_patches):
        state = "pending"
    else:
        state = "available" if m else "unavailable"
    items.append(_item("events", "Events", state, events.detail if events else ""))

    # data flows through a connector
    conn = connections.get(hub, tool.id)
    tool_flows = flows.all_flows(hub, tool.id)
    builtin = builtin_connector(tool)
    if conn is None:
        if builtin:
            items.append(_item("data_flows", "Data flows", "available",
                               f"A built-in {builtin['title']} connector fits: set up the connection to exchange data.",
                               "configure_connection"))
        else:
            items.append(_item("data_flows", "Data flows", "unavailable", "No built-in connector for this tool."))
    else:
        enabled = [f for f in tool_flows if f.status == "enabled"]
        failing = [f for f in enabled if f.failures or (f.last_result and not f.last_result.get("ok"))]
        proposed = [f for f in tool_flows if f.status == "proposed"]
        if failing:
            state, detail = "failing", f"{len(failing)} flow(s) failing: " + ", ".join(f.title for f in failing[:3])
        elif enabled:
            state, detail = "active", f"{len(enabled)} flow(s) enabled: " + ", ".join(f.title for f in enabled[:3])
        elif proposed:
            state, detail = "pending", f"{len(proposed)} flow(s) proposed, waiting for approval."
        else:
            state, detail = "available", "Connected - test the connection, then plan data flows."
        items.append(_item("data_flows", "Data flows", state, detail, "test_connection" if state == "available" else None))

    # a connector Claude generates from the tool's OpenAPI spec
    pending_generated = any(a.kind == "repair" and a.payload.get("tool_id") == tool.id
                            and a.payload.get("diagnosis") == "generated" for a in hub.approvals.list("pending"))
    if conn is not None and conn.generated:
        items.append(_item("generated_connector", "Generated connector", "active",
                           "A generic REST mapping generated from the tool's OpenAPI spec."))
    elif pending_generated:
        items.append(_item("generated_connector", "Generated connector", "pending", "A generated mapping waits for approval."))
    elif builtin or (conn is not None and conn.kind != "generic_rest"):
        items.append(_item("generated_connector", "Generated connector", "not_needed", "A built-in connector fits this tool."))
    elif has_openapi(tool):
        if hub.llm.available:
            items.append(_item("generated_connector", "Generated connector", "available",
                               "Claude can write a connector mapping from the tool's OpenAPI spec.", "generate_connector"))
        else:
            items.append(_item("generated_connector", "Generated connector", "needs_claude",
                               "Generating a connector from the OpenAPI spec needs Claude (ANTHROPIC_API_KEY)."))
    else:
        items.append(_item("generated_connector", "Generated connector", "unavailable",
                           "No OpenAPI spec known for this tool."))

    # adapters and patches (everything that is not single sign-on)
    own = [p for p in patches if p.strategy in ADAPTER_STRATEGIES]
    applied = [p for p in own if p.status == "applied"]
    proposed_patches = [p for p in own if p.status == "proposed"]
    gaps = [c for c in checks.values() if c.status != "pass" and c.fix and c.fix in ADAPTER_STRATEGIES]
    if proposed_patches:
        state, detail = "pending", f"{len(proposed_patches)} patch(es) waiting for approval."
    elif applied and not gaps:
        state, detail = "active", f"{len(applied)} patch(es) applied: " + ", ".join(p.title for p in applied[:3])
    elif gaps:
        state, detail = "available", "Open gaps: " + ", ".join(c.title for c in gaps)
    else:
        state, detail = "not_needed", "No gap needs an adapter or a patch."
    items.append(_item("adapter", "Adapters and patches", state, detail, "propose_patches" if state == "available" else None))
    return items


def overview(hub: "Hub") -> dict[str, Any]:
    sso_rows = {r["tool_id"]: r for r in identity.overview(hub)["tools"]}
    return {"tools": [{"tool_id": t.id, "name": t.name, "strategies": tool_strategies(hub, t, sso_rows)}
                      for t in hub.tools() if t.manifest]}
