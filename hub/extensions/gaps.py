"""Hub-side gaps after an import, and the template packs that close the common ones without an AI model.

A gap is something Atrium itself lacks for a tool (not something the tool lacks - that is a patch to the tool):

- ``domain``     the tool's main data has no home in the hub: a SIEM's alerts, a service desk's tickets, a monitoring
                 tool's incidents;
- ``connector``  no built-in connector and no connection (or a generic REST connection that does not map the domain);
                 an extension can map a REST API, anything else (GraphQL, gRPC, no API) needs a change to Atrium's code;
- ``sso``        the tool signs in with OIDC/SAML in a way the SSO catalog does not know (an extension recipe an
                 AI model writes; the generic values work meanwhile).

Templates (no AI model) exist for the three well-known kinds - SIEM alerts, ticketing tickets, monitoring incidents -
with connector mappings for products whose API is documented: Zammad tickets (GET /api/v1/tickets?expand=true,
page/per_page, "Authorization: Token token=..." - checked against docs.zammad.org) and Prometheus Alertmanager
(GET /api/v2/alerts - checked against its OpenAPI document).
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal

from ..integration import connections, identity, sso_catalog, strategies
from ..models import Tool
from . import registry
from .pack import ExtensionPack

if TYPE_CHECKING:
    from ..core import Hub

GapKind = Literal["domain", "connector", "sso"]


@dataclass
class Gap:
    kind: GapKind
    tool_id: str
    title: str
    detail: str
    category: str | None = None  # siem | ticketing | monitoring
    domain: str | None = None  # the extension domain key
    expressible: bool = True  # an extension pack can close it; False: only a change to Atrium's own code can
    needs_model: bool = False  # no template: only a pack an AI model writes closes it

    @property
    def needs_claude(self) -> bool:  # the name before the provider layer
        return self.needs_model

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


KINDS: dict[str, dict[str, Any]] = {
    "siem": {"domain": "alerts", "title": "SIEM / security alerts",
             "capabilities": {"siem", "monitoring.alerts", "logs.search", "security.events"},
             "names": ("wazuh", "ossec", "graylog", "splunk", "security-onion", "security onion", "elastic-siem",
                       "thehive", "opensearch-siem", "suricata", "zeek", "crowdsec", "siem")},
    "ticketing": {"domain": "tickets", "title": "Service desk / ticketing",
                  "capabilities": {"ticketing", "helpdesk"},
                  "names": ("zammad", "osticket", "freescout", "znuny", "otrs", "request-tracker", "request tracker",
                            "helpdesk", "servicedesk", "service-desk", "service desk", "glpi", "trudesk", "uvdesk",
                            "peppermint", "redmine")},
    "monitoring": {"domain": "incidents", "title": "Monitoring / incidents",
                   "capabilities": {"monitoring.uptime", "monitoring.metrics", "monitoring.incidents"},
                   "names": ("alertmanager", "zabbix", "nagios", "icinga", "prometheus", "uptime-kuma", "uptime kuma",
                             "checkmk", "librenms", "gatus", "healthchecks", "netdata", "statping", "cachet",
                             "observium")},
}


def category(tool: Tool) -> str | None:
    """siem, ticketing or monitoring - what the tool's main data is."""
    m = tool.manifest
    provides = set(m.provides) if m else set()
    text = " ".join([tool.id, tool.name, tool.source or "", m.name if m else ""]).lower()
    for key, spec in KINDS.items():
        if provides & spec["capabilities"] or any(n in text for n in spec["names"]):
            return key
    return None


def detect(hub: "Hub", tool: Tool) -> list[Gap]:
    m = tool.manifest
    if m is None:
        return []
    gaps: list[Gap] = []
    kind = category(tool)
    key = KINDS[kind]["domain"] if kind else None
    defined = set(registry.active_domains(hub))
    proposed = {d.key for rec in registry.records(hub) if rec.status == "proposed" for d in rec.pack().domains}
    if key and key not in defined and key not in proposed:
        gaps.append(Gap("domain", tool.id, f"No place for {tool.name}'s {key}",
                        f"{tool.name} is a {KINDS[kind]['title'].lower()} tool, but Atrium has no '{key}' app: its "
                        f"{key} cannot be pulled, linked to assets and people, or used as compliance evidence.",
                        category=kind, domain=key))
    conn = connections.get(hub, tool.id)
    known = template_connector(tool, kind) is not None
    if conn is None and strategies.builtin_connector(tool) is None and (m.api.type != "none" or known):
        rest = m.api.type == "rest" or known
        gaps.append(Gap("connector", tool.id, f"No connector for {tool.name}",
                        f"Atrium has no built-in connector for {tool.name}. " + (
                            "A generic REST mapping can reach its API." if rest else
                            f"Its API is {m.api.type.upper()}, which a generic REST mapping cannot express: it needs a "
                            "connector in Atrium's code."),
                        category=kind, domain=key, expressible=rest,
                        needs_model=rest and not known))
    elif conn is not None and conn.kind == "generic_rest" and key and f"x:{key}" not in (conn.config.get("mapping") or {}):
        gaps.append(Gap("connector", tool.id, f"{tool.name}'s connection does not map its {key}",
                        f"The generic REST connection of {tool.name} has no mapping for x:{key}.", category=kind,
                        domain=key, needs_model=not known))
    if (m.auth.sso in ("oidc", "oauth2", "saml") and not identity.is_provider(tool) and not m.auth.env_keys
            and not m.auth.provider and sso_catalog.match(tool, identity.load_prefs(hub).catalog) is None):
        gaps.append(Gap("sso", tool.id, f"Unknown single sign-on setup for {tool.name}",
                        f"{tool.name} supports {m.auth.sso.upper()}, but Atrium does not know how it is configured: "
                        "people get generic values to enter by hand. An SSO recipe (written by an AI model) can "
                        "configure it.", needs_model=True))
    return gaps


# --------------------------------------------------------------------------------------
# template packs
# --------------------------------------------------------------------------------------


def _field(name: str, label: str, type_: str = "text", values: list[str] | None = None, required: bool = False):
    out: dict[str, Any] = {"name": name, "label": label, "type": type_}
    if values:
        out["values"] = values
    if required:
        out["required"] = True
    return out


DOMAINS: dict[str, dict[str, Any]] = {
    "alerts": {
        "kind": "domain", "key": "alerts", "title": "Alerts", "singular": "Alert", "icon": "bell",
        "description": "Security alerts from SIEM tools, linked to the affected asset and person.",
        "fields": [_field("title", "Title", required=True), _field("severity", "Severity", "severity"),
                   _field("status", "Status", "enum", ["new", "open", "acknowledged", "closed"]),
                   _field("rule", "Rule"), _field("host", "Host"), _field("source_ip", "Source IP"),
                   _field("user", "User"), _field("detected", "Detected", "date"),
                   _field("description", "Description"), _field("link", "Link", "link")],
        "title_field": "title",
        "links": [{"target": "asset", "field": "host"}, {"target": "asset", "field": "source_ip"},
                  {"target": "person", "field": "user"}],
    },
    "tickets": {
        "kind": "domain", "key": "tickets", "title": "Tickets", "singular": "Ticket", "icon": "ticket",
        "description": "Service desk tickets, linked to the requester and the asset they are about.",
        "fields": [_field("title", "Title", required=True), _field("number", "Number"),
                   _field("status", "Status", "enum", ["new", "open", "pending", "closed", "merged"]),
                   _field("priority", "Priority", "enum", ["low", "normal", "high", "urgent"]),
                   _field("requester", "Requester"), _field("assignee", "Assignee"), _field("group", "Group"),
                   _field("asset", "Asset"), _field("created", "Created", "date"), _field("updated", "Updated", "date"),
                   _field("link", "Link", "link")],
        "title_field": "title",
        "links": [{"target": "person", "field": "requester"}, {"target": "asset", "field": "asset"}],
    },
    "incidents": {
        "kind": "domain", "key": "incidents", "title": "Incidents", "singular": "Incident", "icon": "activity",
        "description": "Incidents and firing alerts from monitoring tools, linked to the affected asset.",
        "fields": [_field("title", "Title", required=True), _field("severity", "Severity", "severity"),
                   _field("status", "Status", "enum", ["firing", "active", "acknowledged", "suppressed", "resolved"]),
                   _field("monitor", "Monitor"), _field("host", "Host"), _field("started", "Started", "date"),
                   _field("resolved_at", "Resolved", "date"), _field("description", "Description"),
                   _field("link", "Link", "link")],
        "title_field": "title",
        "links": [{"target": "asset", "field": "host"}],
    },
}

CONTROL_RULES: dict[str, list[dict[str, Any]]] = {
    # untriaged critical security alerts mean the incident process is not working (ISO 27001 A.5.24, SOC 2 CC7.4)
    "alerts": [
        {"control": "HB-IR-1", "domain": "alerts", "title": "Critical alerts open for more than 7 days",
         "where": [{"field": "severity", "op": "eq", "value": "critical"}, {"field": "status", "op": "ne", "value": "closed"}],
         "age_field": "detected", "older_than_days": 7, "fail_above": 0},
        {"control": "HB-IR-1", "domain": "alerts", "title": "High alerts open for more than 7 days",
         "where": [{"field": "severity", "op": "eq", "value": "high"}, {"field": "status", "op": "ne", "value": "closed"}],
         "age_field": "detected", "older_than_days": 7, "partial_above": 0},
    ],
    # incidents left unresolved mean monitoring is not acted on (ISO 27001 A.8.16, SOC 2 CC7.2)
    "incidents": [
        {"control": "HB-OP-1", "domain": "incidents", "title": "Critical incidents unresolved for more than a day",
         "where": [{"field": "severity", "op": "eq", "value": "critical"},
                   {"field": "status", "op": "not_in", "value": ["resolved", "suppressed"]}],
         "age_field": "started", "older_than_days": 1, "fail_above": 0},
        {"control": "HB-OP-1", "domain": "incidents", "title": "Incidents unresolved for more than 7 days",
         "where": [{"field": "status", "op": "not_in", "value": ["resolved", "suppressed"]}],
         "age_field": "started", "older_than_days": 7, "partial_above": 0},
    ],
}

TEAMS: dict[str, dict[str, Any]] = {
    "alerts": {"kind": "team", "category": "siem", "title": "SIEM / monitoring", "roles": [{
        "role": "alert-reviewer", "title": "Alert reviewer",
        "description": "Reviews the alerts {tool} sends to the hub's Alerts app.",
        "instructions": "You review the security alerts {tool} reports, as kept in the hub's Alerts app "
                        "(extension_records with domain 'alerts'). Each run: summarise the open alerts most severe "
                        "first, with the linked asset and person, point out alerts that stay open too long, and record "
                        "lasting problems as risks instead of repeating them. Never change {tool}'s configuration.",
        "permissions": ["read", "grc_write"], "schedule_minutes": 240,
        "task": "Review the open alerts from {tool} in the hub's Alerts app and summarise what needs a person.",
        "rules_ok": False}]},
    "tickets": {"kind": "team", "category": "ticketing", "title": "Service desk",
                "match": {"names": list(KINDS["ticketing"]["names"]), "capabilities": ["ticketing", "helpdesk"]},
                "roles": [{
                    "role": "ticket-triage", "title": "Ticket triage",
                    "description": "Watches the tickets {tool} sends to the hub's Tickets app.",
                    "instructions": "You watch the service desk tickets from {tool}, as kept in the hub's Tickets app "
                                    "(extension_records with domain 'tickets'). Each run: list urgent and high tickets "
                                    "that are still open, the oldest first, with the requester and the linked asset, "
                                    "and say which need a person's attention.",
                    "permissions": ["read"], "schedule_minutes": 1440,
                    "task": "Summarise the urgent and high tickets from {tool} that are still open.", "rules_ok": False}]},
    "incidents": {"kind": "team", "category": "siem", "title": "SIEM / monitoring", "roles": [{
        "role": "incident-watcher", "title": "Incident watcher",
        "description": "Watches the incidents {tool} reports to the hub's Incidents app.",
        "instructions": "You watch the incidents {tool} reports, as kept in the hub's Incidents app (extension_records "
                        "with domain 'incidents'). Each run: summarise unresolved incidents most severe first with the "
                        "affected asset, and record repeated outages of one asset as a risk.",
        "permissions": ["read", "grc_write"], "schedule_minutes": 60,
        "task": "Summarise the unresolved incidents from {tool} and their affected assets.", "rules_ok": False}]},
}


def template_connector(tool: Tool, kind: str | None) -> dict[str, Any] | None:
    """A connector item for products whose API the templates know."""
    text = " ".join([tool.id, tool.name, tool.source or "", tool.manifest.name if tool.manifest else ""]).lower()
    if "zammad" in text:
        # With expand=true, state / priority / customer come as names (customer: the email address) - documented.
        # UNVERIFIED: that owner and group are expanded to names the same way (otherwise they stay empty).
        return {"kind": "connector", "tool": tool.id, "auth": "header", "auth_header": "Authorization",
                "note": "Zammad: enter the API token as 'Token token=<your token>' (an access token from the profile of "
                        "an agent who can read the tickets).",
                "mapping": {"x:tickets": {
                    "list": {"path": "/api/v1/tickets", "items": "", "params": {"expand": "true"},
                             "pagination": {"type": "page", "page_param": "page", "size_param": "per_page",
                                            "page_size": 50, "start": 1}},
                    "fields": {"external_id": "id", "title": "title", "number": "number", "status": "state",
                               "priority": "priority", "requester": "customer", "assignee": "owner", "group": "group",
                               "created": "created_at", "updated": "updated_at"}}}}
    if "alertmanager" in text:
        return {"kind": "connector", "tool": tool.id, "auth": "none",
                "note": "Prometheus Alertmanager: GET /api/v2/alerts (no authentication unless a proxy adds one).",
                "mapping": {"x:incidents": {
                    "list": {"path": "/api/v2/alerts", "items": "", "pagination": {"type": "none"}},
                    "fields": {"external_id": "fingerprint", "title": "labels.alertname", "severity": "labels.severity",
                               "status": "status.state", "monitor": "labels.job", "host": "labels.instance",
                               "started": "startsAt", "description": "annotations.summary", "link": "generatorURL"}}}}
    return None


def template_pack(hub: "Hub", tool: Tool, gaps: list[Gap], actor: str = "patcher") -> ExtensionPack | None:
    """The pack the templates offer for these gaps (None when no template applies)."""
    from .pack import parse

    kind = category(tool)
    if kind is None:
        return None
    key = KINDS[kind]["domain"]
    kinds = {g.kind for g in gaps}
    items: list[dict[str, Any]] = []
    if "domain" in kinds:
        items.append(DOMAINS[key])
        if CONTROL_RULES.get(key):
            items.append({"kind": "controls", "rules": CONTROL_RULES[key]})
        if key in TEAMS:
            items.append(TEAMS[key])
    connector = template_connector(tool, kind)
    if "connector" in kinds and connector is not None and f"x:{key}" in connector["mapping"]:
        items.append(connector)
    if not items:
        return None
    title = DOMAINS[key]["title"]
    what = ", ".join(sorted({i["kind"] for i in items}))
    return parse({
        "id": re.sub(r"[^a-z0-9-]+", "-", f"{tool.id}-{key}".lower())[:48].strip("-"),
        "name": f"{title} from {tool.name}"[:80], "version": "1.0.0",
        "description": (f"Generated from the templates for {KINDS[kind]['title'].lower()} tools after {tool.name} was "
                        f"imported ({what})."),
        "source_tool": tool.id, "created_by": actor, "status": "proposed", "items": items,
    })
