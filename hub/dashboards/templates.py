"""Dashboard templates and the first-start migration (round4-dashboard-spec.md 5.6).

A template is a list of widgets ``(type, config, w, h, title)``, laid out with the same first-fit algorithm as the
browser's grid (``layout.place``). Entries whose widget type is not registered yet (a later stage adds it), whose
config does not fit, or which name something that does not exist are left out; a template is offered only while the
widget types it ``requires`` are registered. Some entries expand from the hub's state when a dashboard is created
(one count per active extension data type with a severity field).

Migration (idempotent, at hub start): with no ``settings/dashboards`` document and no shared dashboard, the shared
"Overview" dashboard is created from the ``overview`` template - the seven tiles and two cards of the Home page before
dashboards - and made the default.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from . import layout, registry, store
from .models import LIMITS, DashboardSettings, WidgetInstance

if TYPE_CHECKING:
    from ..core import Hub


@dataclass(frozen=True)
class Entry:
    type: str
    config: dict[str, Any]
    w: int
    h: int
    title: str | None = None


@dataclass(frozen=True)
class Template:
    key: str
    title: str
    description: str
    entries: tuple[Entry | Callable[["Hub"], list[Entry]], ...]
    requires: tuple[str, ...] = field(default_factory=tuple)

    def available(self) -> bool:
        return all(registry.get(t) is not None for t in self.requires)

    def view(self) -> dict[str, Any]:
        return {"key": self.key, "title": self.title, "description": self.description}


def metric(key: str, w: int = 3, h: int = 1) -> Entry:
    return Entry("metric", {"metric": key}, w, h)


def _severity_counts(hub: "Hub") -> list[Entry]:
    """One breakdown by severity per active extension data type that has a severity field (e.g. Wazuh alerts)."""
    from ..extensions import registry as ext_registry

    out = []
    for key, (defn, _) in sorted(ext_registry.active_domains(hub).items()):
        sev = next((f for f in defn.fields if f.type == "severity"), None)
        if sev is not None:
            out.append(Entry("domain_count", {"domain": f"x:{key}", "source": "all", "filters": [],
                                              "group_by": sev.name, "view": "bars"}, 4, 3, f"{defn.title} by {sev.label}"))
    return out


OPEN_FINDINGS = [{"field": "status", "op": "in", "value": ["open", "in_progress"]}]

TEMPLATES: dict[str, Template] = {t.key: t for t in (
    Template("overview", "Overview", "The suite at a glance: apps, agents, approvals, assets, people, findings and "
             "compliance, with the apps and the live agent activity.", (
        metric("tools"), metric("agents"), metric("approvals_pending"), metric("assets"),
        metric("people", 4), metric("vulnerabilities_open", 4), metric("compliance_score", 4),
        Entry("tool_health", {"tools": "all", "show_offline_only": False}, 7, 5, "Apps"),
        Entry("agent_activity", {"scope": "all", "min_level": "info", "limit": 40}, 5, 5, "Live agent activity"),
    )),
    Template("security", "Security operations", "Findings, deadlines, configuration drift and the decisions waiting.", (
        metric("vulnerabilities_open"), metric("vulnerabilities_overdue"), metric("drift_open"),
        metric("approvals_pending"),
        Entry("vuln_sla", {"source": "all"}, 4, 3),
        Entry("domain_count", {"domain": "vulnerabilities", "source": "all", "filters": OPEN_FINDINGS,
                               "group_by": "severity", "view": "bars"}, 4, 3, "Open findings by severity"),
        _severity_counts,
        Entry("network_overview", {"tools": "all"}, 6, 3),
        Entry("approvals_queue", {"kinds": [], "limit": 8}, 4, 4),
    )),
    Template("compliance", "Compliance", "Frameworks, failing controls, the risk matrix and the top risks.", (
        Entry("compliance_overview", {"frameworks": "all"}, 6, 3),
        Entry("controls_status", {"status": ["fail", "partial"], "family": None, "limit": 10}, 6, 4),
        Entry("risk_matrix", {"source": "all", "status": ["open", "in_treatment"]}, 4, 4),
        Entry("domain_list", {"domain": "risks", "source": "all", "filters": [], "sort": "score", "order": "desc",
                              "limit": 8, "columns": ["title", "score", "status", "owner"]}, 6, 4, "Top risks"),
        metric("leavers"),
    ), requires=("compliance_overview",)),
    Template("it_people", "IT & people", "Assets, people, leavers and unused accounts.", (
        Entry("domain_count", {"domain": "assets", "source": "all", "filters": [], "group_by": "type",
                               "view": "bars"}, 4, 3, "Assets by type"),
        Entry("domain_count", {"domain": "people", "source": "all", "filters": [], "group_by": "status",
                               "view": "bars"}, 4, 3, "People by status"),
        Entry("leavers", {"limit": 8}, 4, 4),
        Entry("domain_list", {"domain": "accounts", "source": "all", "filters": [], "sort": "last_login",
                              "order": "asc", "limit": 8, "columns": ["login", "app", "active", "last_login"]}, 6, 4,
              "Accounts by last sign-in"),
        Entry("tool_health", {"tools": "all", "show_offline_only": False}, 6, 4, "Apps"),
    ), requires=("domain_count",)),
    Template("settings_ai", "Settings & AI", "Which AI model each agent uses, AI spending, safety settings and agents.", (
        Entry("ai_models", {"show": "all"}, 12, 5),
        metric("llm_spend_today"),
        Entry("safety_settings", {}, 4, 3),
        Entry("tool_health", {"tools": "all", "show_offline_only": False}, 6, 4, "Apps"),
        Entry("agents_status", {"team": "all", "show_provider": True}, 4, 4),
    ), requires=("ai_models",)),
)}


def available() -> list[Template]:
    return [t for t in TEMPLATES.values() if t.available()]


def entries(hub: "Hub", template: Template) -> list[Entry]:
    out: list[Entry] = []
    for item in template.entries:
        out.extend(item(hub) if callable(item) else [item])
    return out


def build(hub: "Hub", key: str, role: str = "admin") -> tuple[list[WidgetInstance], int]:
    """A template's widgets for `role`, placed first-fit; and how many were left out because they need a higher role
    (entries that do not exist yet or do not fit are not counted)."""
    template = TEMPLATES[key]
    sized: list[tuple[Entry, int, int]] = []
    dropped = 0
    for e in entries(hub, template):
        t = registry.get(e.type)
        if t is None:
            continue
        try:
            config = t.parse(e.config)
            t.check(hub, config)
        except Exception:
            continue
        if not registry.allowed(role, t.role(config)):
            dropped += 1
            continue
        w = min(max(e.w, t.size_min[0]), t.size_max[0])
        h = min(max(e.h, t.size_min[1]), t.size_max[1])
        sized.append((e, w, h))
    out = []
    for (e, w, h), spot in zip(sized, layout.place((w, h) for _, w, h in sized)):
        if spot is not None and len(out) < LIMITS["widgets"]:
            out.append(WidgetInstance(id=store.new_widget_id(), type=e.type, x=spot[0], y=spot[1], w=w, h=h,
                                      title=e.title, config=e.config))
    return out, dropped


def migrate(hub: "Hub") -> None:
    """Create the shared Overview dashboard and make it the default, once."""
    if hub.store.get("settings", store.SETTINGS_ID) is not None or hub.store.ids_prefix(store.COLLECTION, "shared:"):
        return
    widgets, _ = build(hub, "overview")
    template = TEMPLATES["overview"]
    d = store.create(hub, scope="shared", owner_id=None, title=template.title, icon="home",
                     description="The suite at a glance.", widgets=widgets, actor="system", template="overview")
    store.put_settings(hub, DashboardSettings(default_id=d.id))
    hub.activity("system", "info", "Created the shared Overview dashboard", dashboard_id=d.id)
