"""The stage-D1 widget types (round4-dashboard-spec.md 6.2): metric, tool_health, tool_overview, agent_activity,
agents_status, approvals_queue, note and links.

Every resolver projects whitelisted fields into its data (no record is dumped whole) and builds its links as internal
hash routes with ids percent-encoded (``route``). Text that comes from tools or people (names, titles, activity) is
cut to bounded lengths here; the UI escapes it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..extensions.pack import _text
from ..models import Approval
from . import metrics
from .registry import FieldSpec, Outcome, Unavailable, WidgetType, options, register, suggester, suggestion
from .resolve import ResolveContext, Snapshot, clean

if TYPE_CHECKING:
    from ..core import Hub
    from ..models import Tool

TOOL_ID = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
INTERNAL_ROUTE = re.compile(r"^#/[A-Za-z0-9/_\-.:%?=&,]{0,200}$")
TOOL_TARGET = re.compile(r"^tool:([A-Za-z0-9][A-Za-z0-9_.-]{0,63})$")
APPROVAL_KINDS = Approval.model_fields["kind"].annotation.__args__  # type: ignore[union-attr]
LEVELS = {"info": 0, "warn": 1, "error": 2}
AGENT_PREFIXES = ("module:", "tool:", "agent:")
ROUTE_ICONS = {"tools": "grid", "integration": "plug", "agents": "bot", "approvals": "checkCircle",
               "operator": "terminal", "network": "network", "assets": "box", "people": "contact",
               "vulnerabilities": "bug", "compliance": "shield", "extensions": "puzzle", "settings": "sliders",
               "users": "users", "x": "puzzle", "portal": "external", "d": "home"}
# Where each built-in domain's records live in the UI (tool_overview; D3's domain specs take over the full list).
DOMAIN_APPS = {"assets": ("Assets", "#/assets"), "vulnerabilities": ("Vulnerabilities", "#/vulnerabilities"),
               "risks": ("Risks", "#/compliance/risks"), "controls": ("Controls", "#/compliance/controls"),
               "people": ("People", "#/people"), "accounts": ("Accounts", "#/people/accounts"),
               "network": ("Network device", "#/network"), "frameworks": ("Frameworks", "#/compliance/frameworks"),
               "assessments": ("Self-assessments", "#/compliance/frameworks")}
DOMAIN_EVENTS = ("asset", "asset_removed", "vulnerability", "risk", "person", "person_removed", "account",
                 "accounts_removed", "x_record", "x_record_removed", "network_snapshot", "extension",
                 "extension_removed")
MAX_TOOL_ROWS = 100


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def route(*parts: str) -> str:
    """An internal hash route with every id percent-encoded (an id never adds a path segment or a query)."""
    return "#/" + "/".join(quote(str(p), safe="") for p in parts)


def check_tool(hub: "Hub", tool_id: str) -> None:
    if hub.get_tool(tool_id) is None:
        raise ValueError("names a tool that does not exist (it may have been removed)")


# -- tools ----------------------------------------------------------------------------------


def tool_row(s: Snapshot, tool: "Tool") -> dict[str, Any]:
    m = tool.manifest
    conn = s.connections.get(tool.id)
    tested = conn.last_test if conn is not None else None
    own = [f for f in s.flows if f.tool_id == tool.id]
    enabled = [f for f in own if f.status == "enabled"]
    runs = [f.last_run for f in own if f.last_run]
    health = tool.health or None
    return {
        "id": tool.id, "name": clean(tool.name, 120), "source_type": tool.source_type,
        "ui": {"icon": m.ui.icon if m else None, "color": m.ui.color if m else None},
        "kind": m.kind if m else None, "status": tool.status, "running": tool.running,
        "health": {"ok": health.get("ok"), "checked_at": health.get("checked_at")} if health else None,
        "connection": {"kind": conn.kind, "tested_ok": bool(tested.get("ok")) if tested else None,
                       "tested_at": tested.get("at") if tested else None} if conn is not None else None,
        "flows": {"enabled": len(enabled), "last_run": max(runs) if runs else None,
                  "failing": sum(1 for f in enabled if (f.last_result or {}).get("ok") is False)},
        "score": tool.report.score if tool.report else None, "level": tool.report.level if tool.report else None,
        "href": route("tools", tool.id), "portal_href": route("portal", tool.id) if m and m.ui.url else None,
    }


def has_problem(row: dict[str, Any]) -> bool:
    """A failed health check, a failed connection test or a failing data flow."""
    return ((row["health"] or {}).get("ok") is False or (row["connection"] or {}).get("tested_ok") is False
            or row["flows"]["failing"] > 0)


class ToolHealthConfig(Strict):
    tools: Literal["all"] | list[str] = Field("all")
    show_offline_only: bool = False

    @field_validator("tools")
    @classmethod
    def _tools(cls, v: Literal["all"] | list[str]) -> Literal["all"] | list[str]:
        if isinstance(v, list):
            if not 1 <= len(v) <= 20:
                raise ValueError("lists 1 to 20 tools (or is \"all\")")
            if any(not re.match(TOOL_ID, x) for x in v):
                raise ValueError("holds an invalid tool id")
            return list(dict.fromkeys(v))
        return v

    def check(self, hub: "Hub") -> None:
        for tool_id in self.tools if isinstance(self.tools, list) else ():
            check_tool(hub, tool_id)


def resolve_tool_health(ctx: ResolveContext, cfg: ToolHealthConfig) -> dict[str, Any] | Outcome:
    s = ctx.snap
    if cfg.tools == "all":
        tools = s.tools
    else:
        tools = [s.tools_by_id[t] for t in cfg.tools if t in s.tools_by_id]
        if not tools:
            raise Unavailable("The tools this widget shows were removed.", "tool_removed")
    rows = [tool_row(s, t) for t in tools]
    total = len(rows)
    if cfg.show_offline_only:
        rows = [r for r in rows if has_problem(r)]
    data = {"rows": rows[:MAX_TOOL_ROWS], "total": total, "shown": len(rows), "href": "#/tools"}
    if not s.tools:
        return Outcome("empty", data, hint={"text": "Import your first tool", "href": "#/tools", "min_role": "operator"})
    return data


class ToolOverviewConfig(Strict):
    tool_id: str = Field(pattern=TOOL_ID)

    def check(self, hub: "Hub") -> None:
        check_tool(hub, self.tool_id)


def records_from(s: Snapshot, domain: str, tool_id: str) -> int | None:
    """How many records of `domain` came from the tool (record provenance, spec section 2); None when unknown."""
    if domain == "assets":
        return sum(1 for a in s.facts("assets", ("status", "source"))
                   if a["status"] != "retired" and a["source"] in (f"sync:{tool_id}", f"tool:{tool_id}"))
    if domain == "vulnerabilities":
        return sum(1 for v in s.facts("vulnerabilities", ("source",)) if v["source"] == tool_id)
    if domain == "risks":
        return sum(1 for r in s.risks if r.source == f"sync:{tool_id}")
    if domain == "people":
        return sum(1 for p in s.people if tool_id in p.sources)
    if domain == "accounts":
        return sum(1 for a in s.accounts if a.tool_id == tool_id)
    if domain.startswith("x:"):
        return sum(1 for r in s.ext_records(domain.removeprefix("x:")) if r.source == tool_id and not r.stale)
    return None


def tool_domains(s: Snapshot, tool_id: str) -> list[dict[str, Any]]:
    """The domains the tool's connection reads or its data flows carry, each with its record count and app link."""
    from ..integration import connections

    conn = s.connections.get(tool_id)
    reads = {d for d, ops in (connections.capabilities(conn) if conn is not None else {}).items() if "read" in ops}
    names = sorted(reads | {f.domain for f in s.flows if f.tool_id == tool_id and f.status == "enabled"})
    out = []
    for domain in names:
        if domain.startswith("x:"):
            found = s.ext_domains.get(domain.removeprefix("x:"))
            if found is None:
                continue
            label, href = clean(found[0].title, 60), route("x", domain.removeprefix("x:"))
        else:
            label, href = DOMAIN_APPS.get(domain, (domain, "#/integration"))
            if domain == "network":
                href = route("network", tool_id)
        out.append({"domain": domain, "label": label, "count": records_from(s, domain, tool_id), "href": href})
    return out


def activity_item(entry: dict[str, Any]) -> dict[str, Any]:
    """An activity entry for a widget: never its ``data``."""
    return {"seq": entry.get("seq"), "ts": entry.get("ts"), "actor": clean(entry.get("actor"), 80),
            "level": entry.get("level") if entry.get("level") in LEVELS else "info", "text": clean(entry.get("text"), 300)}


def resolve_tool_overview(ctx: ResolveContext, cfg: ToolOverviewConfig) -> dict[str, Any]:
    s = ctx.snap
    tool = s.tools_by_id.get(cfg.tool_id)
    if tool is None:
        raise Unavailable(f"{cfg.tool_id} was removed.", "tool_removed")
    own = [f for f in s.flows if f.tool_id == tool.id]
    recent = [e for e in s.activity if e.get("actor") == f"tool:{tool.id}"
              or (isinstance(e.get("data"), dict) and e["data"].get("tool_id") == tool.id)][:5]
    return {
        "tool": tool_row(s, tool),
        "domains": tool_domains(s, tool.id),
        "flows": [{"id": f.id, "title": clean(f.title, 200), "domain": f.domain, "direction": f.direction,
                   "status": f.status, "last_result": {"ok": (f.last_result or {}).get("ok"),
                                                       "at": (f.last_result or {}).get("at")} if f.last_result else None}
                  for f in own],
        "recent": [activity_item(e) for e in recent],
        "href": route("tools", tool.id),
    }


# -- agents and approvals -----------------------------------------------------------------


def is_agent(actor: str, agent_ids: set[str]) -> bool:
    """Activity actors that are agents (or the hub itself); people are user names and API tokens ("token:<name>")."""
    return actor in agent_ids or actor in ("hub", "system") or actor.startswith(AGENT_PREFIXES)


class ActivityConfig(Strict):
    scope: Literal["all", "agents", "people"] = "all"
    min_level: Literal["info", "warn", "error"] = "info"
    actor: str | None = None
    limit: int = Field(20, ge=5, le=50)

    @field_validator("actor")
    @classmethod
    def _actor(cls, v: str | None) -> str | None:
        return (_text(v, 120) or None) if v is not None else None


def resolve_activity(ctx: ResolveContext, cfg: ActivityConfig) -> dict[str, Any]:
    s = ctx.snap
    agent_ids = {a.id for a in s.agents}
    floor = LEVELS[cfg.min_level]
    items = []
    for entry in s.activity:
        actor = str(entry.get("actor") or "")
        if LEVELS.get(entry.get("level"), 0) < floor or (cfg.actor and actor != cfg.actor):
            continue
        if cfg.scope != "all" and is_agent(actor, agent_ids) != (cfg.scope == "agents"):
            continue
        items.append(activity_item(entry))
        if len(items) >= cfg.limit:
            break
    return {"items": items, "href": "#/agents"}


class AgentsConfig(Strict):
    team: str = Field("all", pattern=r"^[A-Za-z0-9][A-Za-z0-9:_.-]{0,63}$")
    show_provider: bool = True

    def check(self, hub: "Hub") -> None:
        if self.team != "all":
            from ..agents import teams

            teams.validate_team(hub, self.team)


def resolve_agents(ctx: ResolveContext, cfg: AgentsConfig) -> dict[str, Any]:
    rows = []
    for r in ctx.snap.agent_records:
        if cfg.team != "all" and r.get("team") != cfg.team:
            continue
        rows.append({"id": r.get("id"), "name": clean(r.get("name"), 120), "title": clean(r.get("title"), 120),
                     "team": r.get("team"), "kind": r.get("kind"), "status": r.get("status"),
                     "paused": bool(r.get("paused")),
                     "provider_label": clean(r.get("provider_label"), 60) if cfg.show_provider else None,
                     "model": clean(r.get("model"), 120) if cfg.show_provider and r.get("uses_llm") else None})
    return {"rows": rows, "total": len(rows), "href": "#/agents"}


def needs_admin(approval: Approval, hub: Any = None) -> bool:
    """Whether only an administrator may approve it (the rules of POST /api/approvals/{id}, read from there; `hub`
    lets runs_on_hub read a patch's stored copy: one that changes how a tool is started is an administrator's)."""
    from ..api import ADMIN_APPROVALS, device_repair, runs_on_hub

    return approval.kind in ADMIN_APPROVALS or approval.kind == "firewall" or runs_on_hub(approval, hub) \
        or device_repair(approval)


class ApprovalsConfig(Strict):
    kinds: list[Literal[APPROVAL_KINDS]] = Field(default_factory=list, max_length=len(APPROVAL_KINDS))  # type: ignore[valid-type]
    limit: int = Field(8, ge=1, le=25)


def resolve_approvals(ctx: ResolveContext, cfg: ApprovalsConfig) -> dict[str, Any]:
    pending = [a for a in ctx.snap.approvals if a.status == "pending" and (not cfg.kinds or a.kind in cfg.kinds)]
    return {"pending": len(pending), "href": "#/approvals",
            "rows": [{"id": a.id, "kind": a.kind, "title": clean(a.title, 200), "requested_by": clean(a.requested_by, 80),
                      "created_at": a.created_at, "needs_admin": needs_admin(a, ctx.hub)} for a in pending[:cfg.limit]]}


# -- metric, note and links -----------------------------------------------------------------


class MetricConfig(Strict):
    metric: str = Field(pattern=r"^[a-z][a-z0-9_]{1,40}$")

    @field_validator("metric")
    @classmethod
    def _known(cls, v: str) -> str:
        if v not in metrics.METRICS:
            raise ValueError("is not a known metric")
        return v


def resolve_metric(ctx: ResolveContext, cfg: MetricConfig) -> dict[str, Any]:
    return metrics.METRICS[cfg.metric].data(ctx.snap)


class NoteConfig(Strict):
    text: str = ""

    _check = field_validator("text")(lambda cls, v: _text(v, 2000, multiline=True))


def resolve_note(ctx: ResolveContext, cfg: NoteConfig) -> dict[str, Any]:
    return {"text": cfg.text}


class LinkItem(Strict):
    label: str
    target: str  # an internal route "#/..." or "tool:<id>" (the tool's portal)

    _label = field_validator("label")(lambda cls, v: _text(v, 60, required=True))

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        if not (INTERNAL_ROUTE.match(v) or TOOL_TARGET.match(v)):
            raise ValueError("must be an Atrium page (#/...) or tool:<tool id>")
        return v


class LinksConfig(Strict):
    items: list[LinkItem] = Field(default_factory=list, max_length=12)

    def check(self, hub: "Hub") -> None:
        for item in self.items:
            found = TOOL_TARGET.match(item.target)
            if found:
                check_tool(hub, found.group(1))


def resolve_links(ctx: ResolveContext, cfg: LinksConfig) -> dict[str, Any]:
    out = []
    for item in cfg.items:
        found = TOOL_TARGET.match(item.target)
        if found:
            tool = ctx.snap.tools_by_id.get(found.group(1))
            out.append({"label": item.label, "href": route("portal", tool.id) if tool else None, "icon": "external",
                        "available": tool is not None, "tool_id": found.group(1)})
        else:
            first = item.target[2:].split("/", 1)[0].split("?", 1)[0]
            out.append({"label": item.label, "href": item.target, "icon": ROUTE_ICONS.get(first, "link"),
                        "available": True, "tool_id": None})
    return {"items": out}


# -- registration ---------------------------------------------------------------------------

LIMIT_FIELD = lambda lo, hi: FieldSpec("limit", "Rows", "number", min=lo, max=hi)  # noqa: E731

register(WidgetType(
    "metric", "Metric", "One number from the hub, such as open vulnerabilities or pending approvals.", "overview",
    MetricConfig, resolve_metric, (2, 1), (3, 1), (4, 2),
    fields=(FieldSpec("metric", "Metric", "select", options="metrics"),),
    events=tuple(sorted({e for m in metrics.METRICS.values() for e in m.events})),
    events_for=lambda c: metrics.METRICS[c.metric].events, ttl=30,
    title_for=lambda c: metrics.METRICS[c.metric].label))
register(WidgetType(
    "tool_health", "Apps", "Every tool (or the ones you pick) with its health, connection and data flows.", "tools",
    ToolHealthConfig, resolve_tool_health, (3, 2), (6, 4), (12, 8),
    fields=(FieldSpec("tools", "Tools", "tools", hint="All tools, or up to 20"),
            FieldSpec("show_offline_only", "Only tools with a problem", "toggle")),
    events=("tool", "tool_removed", "connection", "flow", "flow_removed"), ttl=30, refresh=60,
    title_for=lambda c: "Apps"))
register(WidgetType(
    "tool_overview", "Tool overview", "One tool: its status, the data it brings and its data flows.", "tools",
    ToolOverviewConfig, resolve_tool_overview, (3, 2), (4, 3), (8, 6),
    fields=(FieldSpec("tool_id", "Tool", "tool"),),
    # plus the record events of every domain a tool may bring (which ones it reads is only known when resolving)
    events=("tool", "tool_removed", "connection", "flow", "flow_removed", "activity", *DOMAIN_EVENTS), ttl=30,
    refresh=60, title_for=lambda c: "Tool overview"))
register(WidgetType(
    "agent_activity", "Agent activity", "The live activity log of agents and people.", "agents",
    ActivityConfig, resolve_activity, (3, 2), (5, 5), (12, 8),
    fields=(FieldSpec("scope", "Show", "select", options=options(("all", "Everyone"), ("agents", "Agents only"),
                                                                 ("people", "People only"))),
            FieldSpec("min_level", "At least", "select", options=options(("info", "Everything"),
                                                                         ("warn", "Warnings and errors"),
                                                                         ("error", "Errors only"))),
            FieldSpec("actor", "Only by", "text", hint="An agent id or a user name (optional)"),
            LIMIT_FIELD(5, 50)),
    events=("activity",), ttl=5, refresh=60, title_for=lambda c: "Live agent activity"))
register(WidgetType(
    "agents_status", "Agents", "Agents with their status and the model they use.", "agents",
    AgentsConfig, resolve_agents, (3, 2), (4, 4), (12, 8),
    fields=(FieldSpec("team", "Team", "team", hint="\"all\", hub, a tool id or a built-in app's team"),
            FieldSpec("show_provider", "Show the model", "toggle")),
    # the model each agent runs on changes with the AI settings too (R4-LLM publishes these without an "agent" event)
    events=("agent", "agent_removed", "agent_settings", "llm_selection", "llm_provider", "llm_provider_removed",
            "settings"), ttl=15, title_for=lambda c: "Agents"))
register(WidgetType(
    "approvals_queue", "Approvals", "Decisions waiting for a person (read-only: decide on the Approvals page).",
    "agents", ApprovalsConfig, resolve_approvals, (3, 2), (4, 4), (12, 8),
    fields=(FieldSpec("kinds", "Kinds", "multiselect", options=options(*((k, k) for k in APPROVAL_KINDS)),
                      hint="None selected: every kind"), LIMIT_FIELD(1, 25)),
    events=("approval",), ttl=10, refresh=60, title_for=lambda c: "Awaiting approval"))
register(WidgetType(
    "note", "Note", "Your own text (Markdown).", "notes", NoteConfig, resolve_note, (2, 1), (4, 2), (12, 8),
    fields=(FieldSpec("text", "Text", "textarea", max=2000),), ttl=300, cache=False, title_for=lambda c: "Note"))
register(WidgetType(
    "links", "Links", "Shortcuts to Atrium pages and tools.", "notes", LinksConfig, resolve_links, (2, 1), (3, 2),
    (12, 4), fields=(FieldSpec("items", "Links", "links", max=12),), events=("tool", "tool_removed"), ttl=300,
    cache=False, title_for=lambda c: "Links"))


@suggester
def basic_suggestions(hub: "Hub") -> list[dict[str, Any]]:
    """An overview per tool and the hub-wide widgets of stage D1 (6.5 items 1 and 3; D3 adds per-tool presets)."""
    out = [suggestion(f"tool:{t.id}", "tool_overview", {"tool_id": t.id}, f"{clean(t.name, 80)}: overview",
                      "Its status, the data it brings and its data flows") for t in hub.tools()]
    out += [suggestion("hub", "metric", {"metric": m.key}, m.label, m.description) for m in metrics.METRICS.values()]
    out += [suggestion("hub", "tool_health", {"tools": "all", "show_offline_only": False}, "Apps",
                       "Every tool with its health, connection and data flows"),
            suggestion("hub", "tool_health", {"tools": "all", "show_offline_only": True}, "Apps with a problem",
                       "Tools whose health check, connection test or data flow failed", size=(4, 3)),
            suggestion("hub", "agent_activity", {"scope": "all", "min_level": "info", "limit": 20},
                       "Live agent activity", "What agents and people did, newest first"),
            suggestion("hub", "agent_activity", {"scope": "all", "min_level": "warn", "limit": 20},
                       "Warnings and errors", "Only activity at warning or error level"),
            suggestion("hub", "agents_status", {"team": "all", "show_provider": True}, "Agents",
                       "Every agent with its status and model"),
            suggestion("hub", "approvals_queue", {"kinds": [], "limit": 8}, "Awaiting approval",
                       "Decisions waiting for a person"),
            suggestion("hub", "note", {"text": ""}, "Note", "Your own text"),
            suggestion("hub", "links", {"items": []}, "Links", "Shortcuts to Atrium pages and tools")]
    return [x for x in out if x is not None]
