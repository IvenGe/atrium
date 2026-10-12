"""The integration map: nodes (tools and hub apps), edges (flows, SSO, events, capabilities), connect options
and persisted canvas layouts.

Payloads never carry connection config or secrets, webhook URLs, or toolbus event payloads (review-notes F24).
"""

from __future__ import annotations

import math
import re
import time
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..models import Flow, Tool
from . import connections, flows, identity, strategies

if TYPE_CHECKING:
    from ..core import Hub

LAYOUTS = "canvas_layouts"
VIEWS = ("integration", "segmentation")
NODE_ID = re.compile(r"^(tool|app|z):[A-Za-z0-9._:\-]{1,200}$")
MAX_ITEMS = 5000
KIND_LABEL = {"oss": "Source code", "closed": "Closed source", "saas": "SaaS"}

# Spine apps. Colours match hub/web/js/app.js APPS. Network is included so the later Network UI can sit on the map.
APPS: list[dict[str, Any]] = [
    {"id": "app:assets", "label": "Assets", "icon": "box", "color": "#0d9488", "domains": ["assets"],
     "href": "#/assets", "route": "assets"},
    {"id": "app:vulnerabilities", "label": "Vulnerabilities", "icon": "bug", "color": "#dc2626",
     "domains": ["vulnerabilities"], "href": "#/vulnerabilities", "route": "vulnerabilities"},
    {"id": "app:compliance", "label": "Compliance hub", "icon": "shield", "color": "#16a34a",
     "domains": ["controls", "risks", "frameworks", "assessments"], "href": "#/compliance", "route": "compliance"},
    {"id": "app:people", "label": "People", "icon": "contact", "color": "#e11d48",
     "domains": ["people", "accounts"], "href": "#/people", "route": "people"},
    {"id": "app:network", "label": "Network", "icon": "radar", "color": "#0284c7",
     "domains": ["network"], "href": "#/network", "route": "network"},
]
APPS_BY_ID = {a["id"]: a for a in APPS}
DOMAIN_APP = {d: a["id"] for a in APPS for d in a["domains"]}


class LayoutItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: float | None = None
    lane: Literal["left", "right"] | None = None

    @field_validator("order")
    @classmethod
    def _order(cls, value: float | None) -> float | None:
        if value is None:
            return None
        if not math.isfinite(value) or abs(value) > 1e9:
            raise ValueError("order must be finite and at most 1e9 in absolute value")
        return value


class LayoutPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: dict[str, LayoutItem] | None = None
    remove: list[str] | None = None


class LayoutDoc(BaseModel):
    id: str
    version: int = 0
    updated_at: float | None = None
    updated_by: str | None = None
    items: dict[str, dict[str, Any]] = {}


def empty_layout(view: str) -> dict[str, Any]:
    return {"id": view, "version": 0, "items": {}}


def get_layout(hub: "Hub", view: str) -> dict[str, Any]:
    _view(view)
    doc = hub.store.get(LAYOUTS, view)
    return LayoutDoc.model_validate(doc).model_dump(mode="json") if doc else empty_layout(view)


def patch_layout(hub: "Hub", view: str, body: LayoutPatch, actor: str) -> dict[str, Any]:
    _view(view)
    current = get_layout(hub, view)
    items = dict(current.get("items") or {})
    changed: list[str] = []
    for node_id in body.remove or []:
        _node_id(node_id)
        if node_id in items:
            items.pop(node_id)
            changed.append(node_id)
    for node_id, spec in (body.items or {}).items():
        _node_id(node_id)
        if spec.lane is not None and (not node_id.startswith("tool:") or view != "integration"):
            raise ValueError("lane is only allowed on tool nodes of the integration layout")
        slot = dict(items.get(node_id) or {})
        if spec.order is not None:
            slot["order"] = spec.order
        if spec.lane is not None:
            slot["lane"] = spec.lane
        elif "lane" in slot and spec.model_dump(exclude_unset=True).get("lane", "keep") is None:
            slot.pop("lane", None)
        items[node_id] = slot
        changed.append(node_id)
    if len(items) > MAX_ITEMS:
        raise ValueError(f"A layout can hold at most {MAX_ITEMS} items")
    doc = {"id": view, "version": int(current.get("version") or 0) + 1, "updated_at": time.time(),
           "updated_by": actor, "items": items}
    hub.store.put(LAYOUTS, doc)
    hub.bus.publish("canvas_layout", {"view": view, "version": doc["version"], "ids": changed, "updated_by": actor})
    return doc


def reset_layout(hub: "Hub", view: str, actor: str) -> dict[str, Any]:
    _view(view)
    hub.store.delete(LAYOUTS, view)
    hub.bus.publish("canvas_layout", {"view": view, "version": 0, "ids": [], "updated_by": actor})
    return empty_layout(view)


def _view(view: str) -> str:
    if view not in VIEWS:
        raise KeyError(view)
    return view


def _node_id(value: str) -> str:
    if not NODE_ID.fullmatch(value):
        raise ValueError(f"Invalid layout id '{value}'")
    return value


def parse_node(hub: "Hub", node_id: str) -> dict[str, Any]:
    """Resolve a map node id to {kind: tool|app, id, tool?, app?} or raise KeyError."""
    if node_id in APPS_BY_ID:
        return {"kind": "app", "id": node_id, "app": APPS_BY_ID[node_id]}
    if node_id.startswith("tool:"):
        tool_id = node_id.split(":", 1)[1]
        tool = hub.get_tool(tool_id)
        if tool is None:
            raise KeyError(node_id)
        return {"kind": "tool", "id": node_id, "tool": tool}
    raise KeyError(node_id)


# -- map ----------------------------------------------------------------------------------------------------------


def map_payload(hub: "Hub") -> dict[str, Any]:
    tools = hub.tools()
    conns = {c.id: c for c in connections.all_connections(hub)}
    all_flows = flows.all_flows(hub)
    by_tool: dict[str, list[Flow]] = {}
    for flow in all_flows:
        by_tool.setdefault(flow.tool_id, []).append(flow)
    idp = identity.overview(hub)
    idp_tools = {p["tool_id"] for p in idp["providers"]}
    sso_rows = {r["tool_id"]: r for r in idp["tools"]}
    nodes = [_tool_node(hub, tool, conns.get(tool.id), by_tool.get(tool.id) or [], tool.id in idp_tools)
             for tool in tools]
    return {
        "generated_at": time.time(),
        "autonomy": hub.prefs["autonomy"],
        "guardrails": {"scans_need_approval": hub.prefs["guardrails"].get("scans_need_approval", True)},
        "apps": [{"id": a["id"], "label": a["label"], "icon": a["icon"], "color": a["color"],
                  "domains": a["domains"], "href": a["href"]} for a in APPS],
        "nodes": nodes,
        "flows": [flows.public(hub, f) for f in all_flows],
        "sso": _sso_edges(sso_rows, idp_tools),
        "events": _event_edges(hub),
        "capability_links": _capability_links(tools),
        "identity": idp,
        "layout": get_layout(hub, "integration"),
    }


def _tool_node(hub: "Hub", tool: Tool, conn, tool_flows: list[Flow], is_idp: bool) -> dict[str, Any]:
    m = tool.manifest
    caps: dict[str, list[str]] = connections.capabilities(conn) if conn else {}
    actions: list[str] = []
    sor: list[str] = []
    tested = None
    if conn is not None:
        try:
            from .. import connectors
            cls = connectors.connector_class(conn.kind)
            actions = sorted(cls.actions)
            sor = sorted(cls.system_of_record)
        except Exception:
            pass
        if conn.last_test:
            tested = {"ok": bool(conn.last_test.get("ok")), "at": conn.last_test.get("at") or conn.updated_at}
    ui = {"icon": m.ui.icon if m else None, "color": m.ui.color if m else None}
    kind = (m.kind if m else None) or "oss"
    return {
        "id": f"tool:{tool.id}", "ref": tool.id, "label": tool.name, "kind": kind,
        "ui": ui, "status": tool.status, "running": tool.running,
        "health": tool.health, "score": tool.report.score if tool.report else None,
        "level": tool.report.level if tool.report else None, "is_idp": is_idp,
        "lane_default": _lane(is_idp, conn, tool_flows, caps, actions),
        "connection": None if conn is None else {
            "kind": conn.kind, "generated": conn.generated, "tested": tested,
        },
        "capabilities": caps, "actions": actions, "system_of_record": sor,
    }


def _lane(is_idp: bool, conn, tool_flows: list[Flow], caps: dict[str, list[str]],
          actions: list[str]) -> str:
    if conn is None:
        return "idp" if is_idp else "shelf"
    live = [f for f in tool_flows if f.status in ("enabled", "proposed")]
    if live:
        pulls = sum(1 for f in live if f.direction == "pull")
        pushes = sum(1 for f in live if f.direction in ("push", "scan"))
        return "left" if pulls > pushes else "right"
    writes = any("write" in ops for ops in caps.values()) or "scan" in actions
    return "right" if writes else "left"


def _sso_edges(rows: dict[str, dict[str, Any]], _idp_tools: set[str]) -> list[dict[str, Any]]:
    out = []
    for row in rows.values():
        if row["status"] == "connected" and row.get("connected_to"):
            out.append({"id": f"sso:{row['tool_id']}", "source": f"tool:{row['connected_to']}",
                        "target": f"tool:{row['tool_id']}", "state": "connected"})
        elif row["status"] == "pending" and row.get("pending") and row["pending"].get("provider"):
            out.append({"id": f"sso:{row['tool_id']}", "source": f"tool:{row['pending']['provider']}",
                        "target": f"tool:{row['tool_id']}", "state": "pending"})
    return out


def _event_edges(hub: "Hub") -> list[dict[str, Any]]:
    """Event routes without webhook URLs. last_delivery is ok/ts only, from toolbus.recent (no payloads)."""
    recent = hub.toolbus.recent(50)
    last: dict[tuple[str, str, str], dict[str, Any]] = {}
    for entry in recent:
        source, event = entry.get("source"), entry.get("event")
        for d in entry.get("deliveries") or []:
            if source and event and d.get("to"):
                last[(str(source), str(event), str(d["to"]))] = {"ok": bool(d.get("ok")), "ts": entry.get("ts")}
    edges = []
    for route in hub.toolbus.routes():
        key = (route["from"], route["event"], route["to"])
        edges.append({
            "id": f"event:{route['from']}:{route['to']}:{route['event']}",
            "source": f"tool:{route['from']}", "target": f"tool:{route['to']}",
            "event": route["event"], "pattern": route["pattern"],
            "has_webhook": bool(route.get("webhook")),
            "last_delivery": last.get(key),
        })
    return edges


def _capability_links(tools: list[Tool]) -> list[dict[str, Any]]:
    analysed = [t for t in tools if t.manifest]
    links = []
    for a in analysed:
        for b in analysed:
            if a.id == b.id:
                continue
            ma, mb = a.manifest, b.manifest
            assert ma and mb
            for capability in sorted(set(ma.provides) & set(mb.consumes)):
                links.append({"id": f"cap:{a.id}:{b.id}:{capability}", "source": f"tool:{a.id}",
                              "target": f"tool:{b.id}", "capability": capability})
    return links


# -- connect options (shared planner) -------------------------------------------------------------


def connect_options(hub: "Hub", a: str, b: str) -> dict[str, Any]:
    """What dragging from node a to node b may propose. Options come from strategies.moves() so they cannot
    disagree with proposals()."""
    left, right = parse_node(hub, a), parse_node(hub, b)
    options: list[dict[str, Any]] = []
    sso = None
    events: list[dict[str, Any]] = []
    notes: list[str] = []
    existing = {flows.key(f): f for f in flows.all_flows(hub)}

    tool_node = left if left["kind"] == "tool" else right if right["kind"] == "tool" else None
    app_node = left if left["kind"] == "app" else right if right["kind"] == "app" else None

    if tool_node and app_node:
        tool: Tool = tool_node["tool"]
        domains = set(app_node["app"]["domains"])
        for move in strategies.moves(hub, tool.id):
            if move.domain not in domains:
                continue
            part = _part(hub, move, existing)
            options.append({
                "id": f"{part['direction']}:{move.domain}" + (f":{move.action}" if move.action else ""),
                "recommended": move.recommended and not move.blocked,
                "reason": move.reason if not move.blocked else "",
                "parts": [part],
            })
        if not options:
            notes.append(f"{tool.name} has no data flow with {app_node['app']['label']}.")
    elif left["kind"] == "tool" and right["kind"] == "tool":
        sso = _sso_option(hub, left["tool"], right["tool"])
        events = [e for e in _event_edges(hub)
                  if {e["source"], e["target"]} == {left["id"], right["id"]}]
        if not sso and not events:
            notes.append("Two tools are connected through hub apps, not directly. Drag a tool onto Assets, "
                         "Vulnerabilities, Compliance, People or Network.")
    else:
        notes.append("Hub apps do not exchange data with each other on this map.")

    return {"a": a, "b": b, "options": options, "sso": sso, "events": events, "notes": notes}


def _part(hub: "Hub", move: strategies.Move, existing: dict) -> dict[str, Any]:
    flow = existing.get((move.domain, move.source, move.target, move.action))
    direction = "scan" if move.action == "scan" else ("pull" if move.target == "hub" else "push")
    dummy = flows.make(hub, move.domain, move.source, move.target, move.action, reason=move.reason)
    return {
        "domain": move.domain, "source": move.source, "target": move.target, "action": move.action,
        "direction": direction, "title": dummy.title,
        "default_schedule": dummy.schedule_minutes,
        "exists": None if flow is None else {"flow_id": flow.id, "status": flow.status,
                                             "approval_id": flow.approval_id},
        "blocked": move.blocked,
    }


def _sso_option(hub: "Hub", a: Tool, b: Tool) -> dict[str, Any] | None:
    providers = {p.tool_id: p for p in identity.list_providers(hub.tools(), identity.load_prefs(hub).settings)}
    idp, tool = (a, b) if a.id in providers else ((b, a) if b.id in providers else (None, None))
    if idp is None:
        return None
    overview = identity.overview(hub)
    row = next((r for r in overview["tools"] if r["tool_id"] == tool.id), None)
    return {"tool_id": tool.id, "provider": idp.id, "status": (row or {}).get("status") or "not_connected"}
