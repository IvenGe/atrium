"""Per-tool and hub-wide suggestions for the widget gallery (round4-dashboard-spec.md 6.5 items 2 and 3).

For every tool with a connection, each domain its connection reads (``connections.capabilities``, narrowed to its last
successful test) gets the presets of ``DEFAULT_PRESETS``, scoped to that tool (``source: "tool:<id>"``) and titled
"<Tool>: <preset>". Extension data types get presets made from their fields. Nothing here knows a product: Snipe-IT,
OpenVAS, Okta, CISO Assistant or a Wazuh pack get their widgets from what their connections read.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from ..models import OPEN_STATES
from . import domains
from .registry import suggester, suggestion
from .resolve import clean

if TYPE_CHECKING:
    from ..core import Hub

OPEN_FINDINGS = [{"field": "status", "op": "in", "value": list(OPEN_STATES)}]
Preset = tuple[str, str, str, dict[str, Any], tuple[int, int] | None]  # title, description, type, config, size


def count(domain: str, group_by: str | None, view: str = "bars", filters: list[dict[str, Any]] | None = None,
          ) -> dict[str, Any]:
    return {"domain": domain, "filters": filters or [], "group_by": group_by, "view": view}


def listing(domain: str, sort: str, order: str, columns: list[str], filters: list[dict[str, Any]] | None = None,
            limit: int = 8) -> dict[str, Any]:
    return {"domain": domain, "filters": filters or [], "sort": sort, "order": order, "limit": limit,
            "columns": columns}


# Presets per domain a tool reads; "source" is added per tool (6.5 table).
DEFAULT_PRESETS: dict[str, Callable[[str], list[Preset]]] = {
    "assets": lambda source: [
        ("assets by type", "Its assets, by type", "domain_count", count("assets", "type"), None),
        ("recently updated assets", "Its assets, the latest changes first", "domain_list",
         listing("assets", "updated_at", "desc", ["name", "type", "status"]), None)],
    "vulnerabilities": lambda source: [
        ("open findings by severity", "Its open findings, by severity", "domain_count",
         count("vulnerabilities", "severity", filters=OPEN_FINDINGS), None),
        ("overdue findings", "Its open findings past their deadline, the oldest deadline first", "domain_list",
         listing("vulnerabilities", "due_at", "asc", ["title", "severity", "host", "due_at"],
                 [{"field": "overdue", "op": "eq", "value": True}]), None),
        ("SLA", "Deadlines of its open findings, by severity", "vuln_sla", {"source": source}, None)],
    "risks": lambda source: [
        ("risk matrix", "Its open risks by likelihood and impact", "risk_matrix",
         {"source": source, "status": ["open", "in_treatment"]}, None),
        ("top risks", "Its risks, the highest score first", "domain_list",
         listing("risks", "score", "desc", ["title", "score", "status", "owner"]), None)],
    "frameworks": lambda source: [
        ("frameworks", "The frameworks it holds and their latest assessment", "compliance_overview",
         {"frameworks": [], "external": source, "cyfun": False}, (6, 3))],
    "controls": lambda source: [
        ("failing controls", "Hub Security Baseline controls that fail or are partial", "controls_status",
         {"status": ["fail", "partial"], "family": None, "limit": 10}, None)],
    "people": lambda source: [
        ("people by status", "Its people, by status", "domain_count", count("people", "status"), None),
        ("suspended or terminated", "Its people who are suspended or have left", "domain_list",
         listing("people", "terminated_at", "desc", ["display_name", "department", "status", "terminated_at"],
                 [{"field": "status", "op": "in", "value": ["suspended", "terminated"]}]), None)],
    "accounts": lambda source: [
        ("active accounts", "Its accounts, active or not", "domain_count", count("accounts", "active"), None),
        ("accounts by last sign-in", "Its accounts, the ones never or least recently used first", "domain_list",
         listing("accounts", "last_login", "asc", ["login", "app", "active", "last_login"]), None)],
    "network": lambda source: [
        ("device status", "Last read, configuration drift and device changes", "network_overview",
         {"tools": [source.removeprefix("tool:")]}, None)],
}


def x_presets(spec: domains.DomainSpec) -> Callable[[str], list[Preset]]:
    """An extension data type's presets: a breakdown by its first severity (else enum) field, and the latest records
    by its first date field."""
    fields = [n for n in spec.group_by if n != "source"]
    by = next((n for n in fields if spec.fields[n].type == "severity"), fields[0] if fields else None)
    when = next((n for n in spec.date_fields if n not in ("created_at", "updated_at")), "updated_at")
    title = spec.label

    def make(source: str) -> list[Preset]:
        out: list[Preset] = []
        if by:
            out.append((f"{title} by {spec.fields[by].label.lower()}", f"Its {spec.noun}, by {spec.fields[by].label.lower()}",
                        "domain_count", count(spec.key, by), None))
        else:
            out.append((title, f"How many {spec.noun} it brings", "domain_count", count(spec.key, None, "number"), (3, 2)))
        if when in spec.sort:
            out.append((f"latest {title}", f"Its {spec.noun}, the newest first", "domain_list",
                        listing(spec.key, when, "desc", list(spec.columns[:4])), None))
        return out

    return make


def scoped(config: dict[str, Any], source: str, type_key: str) -> dict[str, Any]:
    return {**config, "source": source} if type_key in ("domain_count", "domain_list", "domain_timeline") else config


@suggester
def tool_suggestions(hub: "Hub") -> list[dict[str, Any]]:
    """6.5 item 2: the presets of every domain each tool's connection reads."""
    from ..integration import connections

    out = []
    specs = {s.key: s for s in domains.all_specs(hub)}
    for conn in connections.all_connections(hub):
        tool = hub.get_tool(conn.id)
        if tool is None:
            continue
        name = clean(tool.name, 80)
        source = f"tool:{tool.id}"
        reads = sorted(d for d, ops in connections.capabilities(conn).items() if "read" in ops)
        for domain in reads:
            if domain.startswith("x:"):
                if domain not in specs:
                    continue
                make = x_presets(specs[domain])
            else:
                make = DEFAULT_PRESETS.get(domain)
                if make is None:
                    continue
            for title, description, type_key, config, size in make(source):
                out.append(suggestion(f"tool:{tool.id}", type_key, scoped(config, source, type_key),
                                      f"{name}: {title}", description, size=size))
    return [x for x in out if x is not None]


@suggester
def hub_suggestions(hub: "Hub") -> list[dict[str, Any]]:
    """6.5 item 3: one count per active domain from all sources, and the hub-wide compliance, network and people
    widgets."""
    out = [suggestion("hub", "domain_count", {**count(s.key, None, "number"), "source": "all"}, f"{s.label}: all sources",
                      f"How many {s.noun} there are, from every tool and added by hand", size=(3, 2))
           for s in domains.all_specs(hub)]
    out += [
        suggestion("hub", "domain_count", {**count("vulnerabilities", "severity", filters=OPEN_FINDINGS), "source": "all"},
                   "Open findings by severity", "Open findings from every scanner, by severity"),
        suggestion("hub", "domain_timeline", {"domain": "vulnerabilities", "source": "all", "filters": [],
                                              "date_field": "first_seen", "days": 30},
                   "New findings per day", "Findings first seen on each of the last 30 days"),
        suggestion("hub", "vuln_sla", {"source": "all"}, "Vulnerability deadlines",
                   "Open findings past their deadline, fixes and scan coverage"),
        suggestion("hub", "compliance_overview", {"frameworks": "all", "external": "all", "cyfun": True}, "Compliance",
                   "Framework scores, the latest CyFun self-assessment and frameworks from GRC tools"),
        suggestion("hub", "controls_status", {"status": ["fail", "partial"], "family": None, "limit": 10},
                   "Failing controls", "Hub Security Baseline controls that fail or are partial"),
        suggestion("hub", "risk_matrix", {"source": "all", "status": ["open", "in_treatment"]}, "Risk matrix",
                   "Open risks by likelihood and impact"),
        suggestion("hub", "domain_list", {**listing("risks", "score", "desc", ["title", "score", "status", "owner"]),
                                          "source": "all"}, "Top risks", "Risks, the highest score first"),
        suggestion("hub", "network_overview", {"tools": "all"}, "Network devices",
                   "Firewalls and network devices with drift and device changes"),
        suggestion("hub", "leavers", {"limit": 8}, "Leavers",
                   "People who left but still hold assets, accounts or a sign-in"),
    ]
    return [x for x in out if x is not None]
