"""Integration strategies: the data flows the hub proposes between tools and its built-in apps, and - per tool - how
far each way of integrating it has got (identity, events, data flows, a generated connector, adapters and patches).

Flow rules, from each connection's capabilities (its last successful test, else what the connector declares):

- a scanner (action "scan") -> scan the assets in scan scope and import the findings into Hub Vulnerabilities;
  a tool that only reads vulnerabilities -> pull them into Hub Vulnerabilities;
- writes vulnerabilities -> push the hub's findings to it;
- reads assets, and is the system of record for them or cannot take them -> pull into Hub Assets;
- writes assets and is not their system of record -> push Hub Assets (the hub's list is canonical, so a tool that can
  do both gets the push only and nothing loops back);
- writes controls -> push the hub's controls with their evidence; reads risks -> pull them into the risk register;
- reads people (a directory: Okta, Keycloak, SCIM, HR) -> pull them into the People app; reads accounts -> pull the
  tool's user accounts into the People app (linked to people; leavers with active accounts fail HB-AC-7);
- reads network (a firewall, router, switch or host firewall) -> pull its configuration into the Network app every
  10 minutes (snapshots, drift, segmentation); device changes never go through flows;
- reads frameworks (a GRC tool: CISO Assistant) -> pull its loaded frameworks and assessments into the Compliance hub
  (read-only); writes assessments (an administrator switched it on in the connection) -> push the hub's CyFun
  self-assessment results to it. Two domains, so the pull and the push are not a loop;
- reads an enabled extension domain ("x:alerts") -> pull it into that domain's app; only writes it -> push to it.

The loop rule: a pull and a push of the same domain for the same tool never coexist while either is
enabled or proposed - the planner never proposes both (a tool that reads and writes vulnerabilities without scanning
reports findings, so it gets the pull), and the integration map's Connect panel (``connect_options``), ``POST
/api/flows`` (``create_flow``) and enabling a flow refuse the second one (409 ``flow_conflict``). A scan is not a pull.

``tool_rules`` is the one place these rules live: ``proposals()`` saves what they call for, and ``connect_options()``
marks exactly those options "recommended", with the same reasons, so the planner and the panel cannot disagree.

Proposals become approvals of kind "flow" (enabled straight away in autonomous mode).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable, NamedTuple

from .. import connectors
from ..connectors.base import Connector
from ..models import BUILTIN_DOMAINS, Approval, Flow, Tool
from . import connections, flows, identity

if TYPE_CHECKING:
    from ..core import Hub

ADAPTER_STRATEGIES = {"api_adapter", "event_adapter", "health_probe", "health_endpoint", "add_manifest", "reassign_port",
                      "custom"}
BUILTIN_SCORE = 50  # a detected built-in connector at least this sure is offered instead of generating one
GENERATED_EXCLUDED = ("network", "frameworks", "assessments")  # need a built-in connector's normalised records
LOOP_STATES = ("enabled", "proposed")
TOOL_END = re.compile(r"^tool:[A-Za-z0-9._-]{1,64}$")
# The hub's built-in apps and the domains each takes: the integration map's spine (labels, routes and icons mirror
# APPS in hub/web/js/app.js; the Network app is R3-NETUI's). Extension domains add one app each ("app:x:<key>").
HUB_APPS: tuple[tuple[str, str, tuple[str, ...], str, str], ...] = (
    ("app:assets", "Assets", ("assets",), "#/assets", "box"),
    ("app:vulnerabilities", "Vulnerabilities", ("vulnerabilities",), "#/vulnerabilities", "bug"),
    ("app:compliance", "Compliance hub", ("controls", "risks", "frameworks", "assessments"), "#/compliance", "shield"),
    ("app:people", "People", ("people", "accounts"), "#/people", "contact"),
    ("app:network", "Network", ("network",), "#/network", "server"),
)


class Rule(NamedTuple):
    """One flow the planner's rules call for, and why."""

    domain: str
    source: str
    target: str
    action: str | None
    reason: str

    @property
    def key(self) -> tuple[str, str, str, str | None]:
        return self.domain, self.source, self.target, self.action


def tool_rules(tool: Tool, conn: connections.Connection, cls: type[Connector],
               extension_domains: dict[str, Any]) -> list[Rule]:
    """The flows the rules call for between one connected tool and the hub's apps, from its capabilities alone (which
    flows exist already is the caller's business)."""
    domains = connections.capabilities(conn)
    end = f"tool:{tool.id}"
    out: list[Rule] = []

    def reads(domain: str) -> bool:
        return "read" in domains.get(domain, [])

    def writes(domain: str) -> bool:
        return "write" in domains.get(domain, [])

    def add(domain: str, source: str, target: str, action: str | None, reason: str) -> None:
        out.append(Rule(domain, source, target, action, reason))

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
    if reads("people"):
        add("people", end, "hub", None,
            f"{name} is a directory of people: they are merged into the People app (by email, then login), with "
            "their status, manager and groups, so leavers are noticed.")
    if reads("accounts"):
        add("accounts", end, "hub", None,
            f"{name} has user accounts: they are linked to people in the People app, so leavers who can still "
            "sign in are found.")
    if reads("network") and not conn.generated:
        add("network", end, "hub", None,
            f"{name} is a network device: its interfaces, zones and rules are read into the Network app, where "
            "changes made outside Atrium show up as drift and the segmentation map and compliance checks use them.")
    if reads("frameworks") and not conn.generated:
        add("frameworks", end, "hub", None,
            f"{name} holds compliance frameworks and assessments: they are shown read-only in the Compliance hub "
            "(frameworks, requirement trees, its assessment results), next to Atrium's own CyFun assessments.")
    if writes("assessments") and not conn.generated:
        add("assessments", "hub", end, None,
            f"An administrator allowed sending the hub's CyFun self-assessments to {name}: each one's results and "
            "maturity scores are written into a compliance assessment there.")
    for key, (defn, _) in extension_domains.items():
        domain, what = f"x:{key}", defn.title.lower()
        if reads(domain):
            add(domain, end, "hub", None, f"{name} reports {what}: they are kept in the hub's {defn.title} app (an "
                                          "extension), linked to assets and people.")
        elif writes(domain):
            add(domain, "hub", end, None, f"{name} can take {what}: it receives the hub's {defn.title} records.")
    # the loop rule: a tool that reads and writes vulnerabilities without scanning reports findings - it gets the pull
    pulled = {r.domain for r in out if r.target == "hub"}
    return [r for r in out if not (r.source == "hub" and r.action is None and r.domain in pulled)]


def loop_conflict(items: Iterable[Flow], domain: str, source: str, target: str, action: str | None,
                  exclude: str | None = None, states: tuple[str, ...] = LOOP_STATES) -> Flow | None:
    """The flow that makes this one a loop: the push of the same domain to the same tool for a pull, and the reverse,
    while it is enabled or proposed. Scans are not pulls."""
    if action is not None:
        return None
    other = (domain, target, source, None)
    return next((f for f in items if f.id != exclude and flows.key(f) == other and f.status in states), None)


def loop_message(hub: "Hub", domain: str, source: str, target: str) -> str:
    tool = flows.end_name(hub, target if source == "hub" else source, domain)
    app, what = flows.app_name(hub, domain), domain.removeprefix("x:")
    if target == "hub":
        return f"{app} already sends {what} to {tool}; pulling them back would loop records."
    return f"{tool}'s {what} already come into {app}; sending them back would loop records."


def proposals(hub: "Hub") -> list[Flow]:
    """Flows the rules call for that do not exist yet (in any state: a rejected proposal stays rejected) and would
    not loop with an enabled or proposed flow."""
    from ..extensions import registry

    current = flows.all_flows(hub)
    existing = {flows.key(f) for f in current}
    extension_domains = registry.active_domains(hub)
    out: list[Flow] = []
    for conn in connections.all_connections(hub):
        tool = hub.get_tool(conn.id)
        try:
            cls = connectors.connector_class(conn.kind)
        except connectors.ConnectorError:
            continue
        if tool is None:
            continue
        strategy = "generated" if conn.generated else "connector"
        for rule in tool_rules(tool, conn, cls, extension_domains):
            if rule.key in existing or loop_conflict([*current, *out], *rule.key):
                continue
            existing.add(rule.key)
            out.append(flows.make(hub, *rule.key, reason=rule.reason, strategy=strategy))
    return out


# --------------------------------------------------------------------------------------
# what a person may connect: the integration map's Connect panel and POST /api/flows
# --------------------------------------------------------------------------------------


class FlowRefused(Exception):
    """A data flow a person asked for that the rules refuse: HTTP `status`, `code` and extra fields (``flow_id``)."""

    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.extra = status, code, extra

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "code": self.code, "message": str(self), **self.extra}


@dataclass
class Endpoint:
    """A tool as one end of data flows: its connection, connector class, capabilities and what the rules call for."""

    tool: Tool
    conn: connections.Connection | None = None
    cls: type[Connector] | None = None
    caps: dict[str, list[str]] = field(default_factory=dict)
    rules: dict[tuple[str, str, str, str | None], Rule] = field(default_factory=dict)

    @property
    def end(self) -> str:
        return f"tool:{self.tool.id}"

    @property
    def connected(self) -> bool:
        return self.conn is not None and self.cls is not None


def endpoint(hub: "Hub", tool: Tool, extension_domains: dict[str, Any]) -> Endpoint:
    ep = Endpoint(tool, connections.get(hub, tool.id))
    if ep.conn is not None:
        try:
            ep.cls = connectors.connector_class(ep.conn.kind)
        except connectors.ConnectorError:
            return ep
        ep.caps = connections.capabilities(ep.conn)
        ep.rules = {r.key: r for r in tool_rules(tool, ep.conn, ep.cls, extension_domains)}
    return ep


def assess(hub: "Hub", ep: Endpoint, domain: str, source: str, target: str, action: str | None,
           current: list[Flow]) -> dict[str, Any]:
    """One flow between `ep` and the hub as the Connect panel shows it and POST /api/flows checks it: its title and
    default schedule, the flow that already has this key (``exists``), whether the rules recommend it (with the
    planner's reason), and ``code``/``problem`` when it cannot be created: no_connection | no_capability (not offered)
    | system_of_record | flow_conflict (offered, ``blocked``)."""
    pseudo = flows.make(hub, domain, source, target, action)
    name, what = ep.tool.name, domain.removeprefix("x:")
    part: dict[str, Any] = {
        "domain": domain, "source": source, "target": target, "action": action, "direction": pseudo.direction,
        "title": pseudo.title, "default_schedule": pseudo.schedule_minutes, "exists": None, "recommended": False,
        "reason": "", "blocked": None, "code": None, "problem": None, "conflict_flow_id": None}
    rule = ep.rules.get(flows.key(pseudo))
    if rule is not None:
        part["recommended"], part["reason"] = True, rule.reason
    elif pseudo.direction == "pull" and domain == "vulnerabilities" and ep.cls and "scan" in ep.cls.actions:
        part["reason"] = "Findings already arrive through the scan flow."
    existing = next((f for f in current if flows.key(f) == flows.key(pseudo)), None)
    if existing is not None:
        part["exists"] = {"flow_id": existing.id, "status": existing.status, "approval_id": existing.approval_id}

    def problem(code: str, message: str, blocked: bool = False) -> dict[str, Any]:
        part.update(code=code, problem=message, blocked=message if blocked else None)
        return part

    if not ep.connected or ep.cls is None or ep.conn is None:
        return problem("no_connection", f"{name} has no connection yet - an administrator sets one up in Tool > "
                                        "Connection")
    ops = ep.caps.get(domain, [])
    if ep.conn.generated and domain in GENERATED_EXCLUDED:
        return problem("no_capability", f"{name}'s connection was generated from its OpenAPI spec; {what} need a "
                                        "built-in connector")
    if pseudo.direction == "scan" and "scan" not in ep.cls.actions:
        return problem("no_capability", f"{name} is not a vulnerability scanner")
    if pseudo.direction == "pull" and "read" not in ops:
        return problem("no_capability", f"{name} cannot read {what} through its connection")
    if pseudo.direction == "push" and "write" not in ops:
        return problem("no_capability", f"{name} cannot take {what} through its connection")
    if pseudo.direction == "push" and domain in ep.cls.system_of_record:
        return problem("system_of_record", f"{name} is the system of record for {what}; the hub never pushes {what} "
                                           "to it.", blocked=True)
    conflict = loop_conflict(current, domain, source, target, action)
    if conflict is not None:
        part["conflict_flow_id"] = conflict.id
        return problem("flow_conflict", loop_message(hub, domain, source, target), blocked=True)
    return part


def hub_apps(hub: "Hub", extension_domains: dict[str, Any] | None = None,
             extra_domains: Iterable[str] = ()) -> list[dict[str, Any]]:
    """The spine: the built-in apps, then one app per enabled extension domain (and, marked inactive, per extension
    domain an existing flow still names)."""
    if extension_domains is None:
        from ..extensions import registry

        extension_domains = registry.active_domains(hub)
    out = [{"id": id_, "label": label, "domains": list(domains), "href": href, "icon": icon, "extension": False,
            "active": True} for id_, label, domains, href, icon in HUB_APPS]
    keys = set(extension_domains) | {d[2:] for d in extra_domains if d.startswith("x:")}
    for key in sorted(keys):
        defn = extension_domains[key][0] if key in extension_domains else None
        out.append({"id": f"app:x:{key}", "label": defn.title if defn else key, "domains": [f"x:{key}"],
                    "href": f"#/x/{key}", "icon": defn.icon if defn else "box", "extension": True,
                    "active": defn is not None})
    return out


def connect_options(hub: "Hub", a: str, b: str) -> dict[str, Any]:
    """What can be connected between two items of the integration map (canvas-design 5.6 / 7.2): data flow options
    (tool <-> hub app; tool <-> tool as a chain through the hub app), single sign-on (a tool and an identity provider)
    and the event routes between two tools (information only). KeyError for an unknown item."""
    from ..extensions import registry

    extension_domains = registry.active_domains(hub)
    apps = {x["id"]: x for x in hub_apps(hub, extension_domains) if x["active"]}
    current = flows.all_flows(hub)

    def resolve(node: str) -> Endpoint | dict[str, Any]:
        if node.startswith("tool:") and (tool := hub.get_tool(node[5:])) is not None:
            return endpoint(hub, tool, extension_domains)
        if node in apps:
            return apps[node]
        raise KeyError(node)

    ends = [resolve(a), resolve(b)]
    out: dict[str, Any] = {"a": a, "b": b, "options": [], "sso": None, "events": [], "notes": [],
                           "needs_connection": []}
    tools = [e for e in ends if isinstance(e, Endpoint)]
    if a == b:
        out["notes"].append("Choose two different items.")
        return out
    if not tools:
        out["notes"].append("Hub apps share data internally.")
        return out
    out["needs_connection"] = [e.tool.id for e in tools if not e.connected]
    if out["needs_connection"]:
        out["notes"].append("Set up the connection first: " + ", ".join(e.tool.name for e in tools if not e.connected)
                            + " has no connection yet.")

    def option(kind: str, id_: str, title: str, parts: list[dict[str, Any]], domain: str) -> dict[str, Any]:
        recommended = all(p["recommended"] for p in parts)
        reason = " ".join(p["reason"] for p in parts if p["reason"]) if recommended or len(parts) == 1 else ""
        return {"id": id_, "kind": kind, "domain": domain, "title": title, "recommended": recommended,
                "reason": reason, "blocked": next((p["blocked"] for p in parts if p["blocked"]), None), "parts": parts}

    if len(tools) == 1:  # a tool and a hub app
        ep, app = tools[0], next(e for e in ends if not isinstance(e, Endpoint))
        for domain in app["domains"]:
            kinds = [("hub", ep.end, "scan")] if domain == "vulnerabilities" else []
            kinds += [(ep.end, "hub", None), ("hub", ep.end, None)]
            for source, target, action in kinds:
                part = assess(hub, ep, domain, source, target, action, current)
                if part["code"] not in ("no_connection", "no_capability"):
                    out["options"].append(option(part["direction"], f"{part['direction']}:{domain}", part["title"],
                                                 [part], domain))
        if ep.connected and not out["options"]:
            out["notes"].append(f"{ep.tool.name} cannot exchange {', '.join(app['domains'])} with {app['label']}.")
    else:
        for x, y in ((tools[0], tools[1]), (tools[1], tools[0])):
            if not (x.connected and y.connected):
                continue
            for app in apps.values():
                for domain in app["domains"]:
                    scanner = domain == "vulnerabilities" and x.cls is not None and "scan" in x.cls.actions
                    supply = ("hub", x.end, "scan") if scanner else (x.end, "hub", None)
                    first = assess(hub, x, domain, *supply, current)
                    second = assess(hub, y, domain, "hub", y.end, None, current)
                    if first["code"] in ("no_connection", "no_capability") or second["code"] in (
                            "no_connection", "no_capability", "system_of_record"):
                        continue
                    title = f"{x.tool.name} -> {flows.app_name(hub, domain)} -> {y.tool.name}"
                    out["options"].append(option("chain", f"chain:{x.tool.id}>{y.tool.id}:{domain}", title,
                                                 [first, second], domain))
        if not out["needs_connection"] and not out["options"]:
            out["notes"].append("No data these two can exchange through the hub.")
        providers = [e for e in tools if identity.is_provider(e.tool)]
        if len(providers) == 2:
            out["notes"].append("Identity providers do not sign in through each other.")
        elif len(providers) == 1:
            provider = providers[0].tool
            other = next(e.tool for e in tools if e.tool.id != provider.id)
            row = next((r for r in identity.overview(hub)["tools"] if r["tool_id"] == other.id), None) or {}
            out["sso"] = {"tool_id": other.id, "provider": provider.id, "status": row.get("status", "unknown"),
                          "connected_to": row.get("connected_to"),
                          "pending_provider": (row.get("pending") or {}).get("provider")}
        pair = {tools[0].tool.id, tools[1].tool.id}
        out["events"] = [r for r in event_routes(hub) if {r["from"], r["to"]} == pair]
    out["options"].sort(key=lambda o: not o["recommended"])  # stable: domain order within each group
    return out


def event_routes(hub: "Hub") -> list[dict[str, Any]]:
    """Event routes without webhook URLs (they can carry tokens): whether one is set."""
    seen: dict[str, dict[str, Any]] = {}
    for r in hub.toolbus.public_routes():
        seen.setdefault(f"event:{r['from']}:{r['to']}:{r['event']}", {
            "source": f"tool:{r['from']}", "target": f"tool:{r['to']}", "from": r["from"], "to": r["to"],
            "event": r["event"], "pattern": r["pattern"], "has_webhook": r["has_webhook"]})
    return [{"id": id_, **r} for id_, r in seen.items()]


def create_flow(hub: "Hub", *, domain: str, source: str, target: str, action: str | None = None,
                schedule_minutes: int | None = None, options: dict[str, Any] | None = None,
                actor: str) -> tuple[Flow, Approval | None]:
    """A data flow a person drew (POST /api/flows through the Hub Supervisor): checked like the Connect panel
    (``assess``), then enabled in autonomous mode or proposed for approval - requested by the Hub Supervisor, which
    enables it when approved, with ``proposed_by`` so the second-person guardrail can apply. FlowRefused otherwise."""
    from ..extensions import registry

    extension_domains = registry.active_domains(hub)
    if (source == "hub") == (target == "hub"):
        raise FlowRefused(400, "invalid", 'One end of a data flow is the hub ("hub"), the other a tool ("tool:<id>")')
    end = target if source == "hub" else source
    if not TOOL_END.match(end):
        raise FlowRefused(400, "invalid", 'A tool end is written "tool:<tool id>"')
    if domain not in BUILTIN_DOMAINS and not (domain.startswith("x:") and domain[2:] in extension_domains):
        raise FlowRefused(400, "invalid", f"Unknown data domain '{domain[:40]}'")
    if action not in (None, "scan") or (action == "scan" and (domain != "vulnerabilities" or source != "hub")):
        raise FlowRefused(400, "invalid", 'A scan flow goes from "hub" to a scanner, for vulnerabilities')
    if schedule_minutes is not None and (isinstance(schedule_minutes, bool) or not isinstance(schedule_minutes, int)
                                         or not 0 <= schedule_minutes <= 525_600):
        raise FlowRefused(400, "invalid", "schedule_minutes is 0 (by hand only) to 525600")
    if not isinstance(options or {}, dict):
        raise FlowRefused(400, "invalid", "options is an object")
    tool = hub.get_tool(end[5:])
    if tool is None:
        raise FlowRefused(404, "not_found", "Tool not found")
    ep = endpoint(hub, tool, extension_domains)
    current = flows.all_flows(hub)
    part = assess(hub, ep, domain, source, target, action, current)
    if part["code"] in ("no_connection", "no_capability", "system_of_record"):
        raise FlowRefused(400, part["code"], part["problem"])
    if part["exists"]:
        raise FlowRefused(409, "flow_exists", f"This data flow exists already ({part['exists']['status']})",
                          flow_id=part["exists"]["flow_id"])
    if part["code"] == "flow_conflict":
        raise FlowRefused(409, "flow_conflict", part["problem"], flow_id=part["conflict_flow_id"])
    assert ep.conn is not None
    rule = ep.rules.get((domain, source, target, action))
    flow = flows.make(hub, domain, source, target, action, created_by=actor,
                      reason=rule.reason if rule else f"Drawn on the integration map by {actor}.",
                      strategy="generated" if ep.conn.generated else "connector")
    try:
        flow.options = flows.validate_options(flow, options or {})
    except ValueError as exc:
        raise FlowRefused(400, "invalid", str(exc)) from exc
    if schedule_minutes is not None:
        flow.schedule_minutes = schedule_minutes
    if hub.prefs["autonomy"] == "autonomous":
        flow.status = "enabled"
        flows.save(hub, flow)
        hub.activity(actor, "info", f"Enabled data flow: {flow.title}", flow_id=flow.id)
        return flow, None
    flows.save(hub, flow)
    return flow, _request_approval(hub, flow, actor, "Proposed")


def _request_approval(hub: "Hub", flow: Flow, actor: str, verb: str) -> Approval:
    """A person's proposal of `flow`, requested by the Hub Supervisor (which enables the flow when it is approved),
    with ``proposed_by`` so the second-person guardrail applies."""
    approval = hub.approvals.create(
        "flow", f"Data flow: {flow.title}", f"{flow.reason} {verb} by {actor}.",
        {"flow_id": flow.id, "tool_id": flow.tool_id, "domain": flow.domain, "source": flow.source,
         "target": flow.target, "action": flow.action, "schedule_minutes": flow.schedule_minutes,
         "options": flow.options, "proposed_by": actor}, "supervisor")
    flow.approval_id = approval.id
    flows.save(hub, flow)
    hub.activity(actor, "info", f"{verb} data flow: {flow.title} (awaiting approval)", flow_id=flow.id,
                 approval_id=approval.id)
    return approval


def propose_again(hub: "Hub", flow: Flow, actor: str) -> Approval | None:
    """Enabling a flow whose proposal was turned down (flows.never_approved) proposes it again, exactly like drawing
    it: enabled at once in autonomous mode, otherwise a new approval that `actor` proposes - so the second-person
    rule applies to it, and a rejection is never undone by switching the flow on."""
    for approval in hub.approvals.list("pending"):  # an old proposal of the same flow that is still open
        if approval.payload.get("flow_id") == flow.id:
            hub.approvals.withdraw(approval.id, "Superseded: the data flow was proposed again.", actor)
    flow.rejected = None
    if hub.prefs["autonomy"] == "autonomous":
        flow.status, flow.approval_id = "enabled", None
        flows.save(hub, flow)
        hub.activity(actor, "info", f"Enabled data flow: {flow.title}", flow_id=flow.id)
        return None
    flow.status, flow.approval_id = "proposed", None
    flows.save(hub, flow)
    return _request_approval(hub, flow, actor, "Proposed again")


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
