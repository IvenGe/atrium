"""The integration map's read model and the shared canvas layouts (docs/research/canvas-design.md 7.1, 7.3).

``integration_map`` is one payload for the Integration map: the hub apps (the spine: Assets, Vulnerabilities, the
Compliance hub, People, Network and one app per extension domain), every tool as a node with a summary of its
connection and its default lane, every data flow exactly as ``GET /api/flows`` shows it, single sign-on edges, event
routes and capability links. It never carries a connection's config or secrets, webhook URLs or toolbus event payloads
(review-notes F24): event routes only say whether a webhook is set.

Layouts (collection ``canvas_layouts``, doc id = the view): only the shared arrangement - the order of items in their
lane and, for integration tools, a Sources/Destinations lane override. Camera, hidden items, collapsed zones and
filters stay in each viewer's browser, so nobody can hide a tool from everyone (F18). Every write bumps ``version``
(reset included, so versions only grow) and publishes ``canvas_layout {view, version, ids, updated_by, reset}``.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .. import connectors, guardrails
from ..connectors.netmodel import CONTROL_CHARS
from ..models import Flow, Tool
from . import connections, flows, identity, strategies
from .compatibility import suite_matrix

if TYPE_CHECKING:
    from ..core import Hub

LAYOUTS = "canvas_layouts"
VIEWS = ("integration", "segmentation")
MAX_ITEMS = 5000
# Tool ids are slugs and app ids fixed; zone ids carry a device's own interface or zone id, which may hold "/" and
# spaces (z:sw1:Gi1/0/1), so they take any printable text - the spec's narrower [A-Za-z0-9._:-] would leave such
# zones unarrangeable.
ITEM_ID = re.compile(r"^(?:(?:tool|app):[A-Za-z0-9._:\-]{1,200}|z:[^\x00-\x1f\x7f]{1,250})$")
LANES = ("left", "right")


# --------------------------------------------------------------------------------------
# the integration map
# --------------------------------------------------------------------------------------


def lane_default(tool: Tool, conn: connections.Connection | None, caps: dict[str, list[str]],
                 actions: list[str], tool_flows: list[Flow]) -> str:
    """idp (an identity provider without a connection), shelf (no connection), else left (mostly brings data into the
    hub) or right (mostly receives or scans); with no flows yet, a tool that only reads goes left."""
    if conn is None:
        return "idp" if identity.is_provider(tool) else "shelf"
    live = [f for f in tool_flows if f.status in strategies.LOOP_STATES]
    if live:
        pulls = sum(1 for f in live if f.direction == "pull")
        return "left" if pulls > len(live) - pulls else "right"
    reads = any("read" in ops for ops in caps.values())
    writes = any("write" in ops for ops in caps.values())
    return "left" if reads and not writes and "scan" not in actions else "right"


def tool_node(tool: Tool, conn: connections.Connection | None, tool_flows: list[Flow]) -> dict[str, Any]:
    m = tool.manifest
    cls = None
    if conn is not None:
        try:
            cls = connectors.connector_class(conn.kind)
        except connectors.ConnectorError:
            cls = None
    caps = connections.capabilities(conn) if conn is not None and cls is not None else {}
    actions = sorted(cls.actions) if cls else []
    tested = conn.last_test if conn is not None else None
    health = tool.health or None
    return {
        "id": f"tool:{tool.id}", "ref": tool.id, "label": tool.name, "kind": m.kind if m else None,
        "source_type": tool.source_type, "ui": {"icon": m.ui.icon if m else None, "color": m.ui.color if m else None},
        "status": tool.status, "running": tool.running,
        "health": {"ok": health.get("ok"), "checked_at": health.get("checked_at")} if health else None,
        "score": tool.report.score if tool.report else None, "level": tool.report.level if tool.report else None,
        "is_idp": identity.is_provider(tool), "lane_default": lane_default(tool, conn, caps, actions, tool_flows),
        "connection": {"kind": conn.kind, "generated": conn.generated, "known": cls is not None,
                       "tested": {"ok": bool(tested.get("ok")), "at": tested.get("at")} if tested else None}
        if conn is not None else None,
        "capabilities": caps, "actions": actions, "system_of_record": sorted(cls.system_of_record) if cls else [],
    }


def sso_edges(overview: dict[str, Any]) -> list[dict[str, Any]]:
    """One edge per tool that signs in through a provider (connected) or will once a patch is approved (pending)."""
    out = []
    for row in overview["tools"]:
        pending = row.get("pending") or {}
        if row["status"] == "connected" and row.get("connected_to"):
            source, state = row["connected_to"], "connected"
        elif row["status"] == "pending" and pending.get("provider"):
            source, state = pending["provider"], "pending"
        else:
            continue
        out.append({"id": f"sso:{row['tool_id']}", "source": f"tool:{source}", "target": f"tool:{row['tool_id']}",
                    "state": state, "protocol": row.get("sso"),
                    "approval_id": pending.get("approval_id") if state == "pending" else None})
    return out


def event_edges(hub: "Hub") -> list[dict[str, Any]]:
    """Event routes from the tools' manifests (not suite_matrix's duplicates), each with its last delivery."""
    last: dict[tuple[Any, Any, Any], dict[str, Any]] = {}
    for entry in hub.toolbus.public_recent(50):  # oldest first: the newest delivery wins
        for d in entry["deliveries"]:
            last[(entry.get("source"), entry.get("event"), d["to"])] = {"ok": d["ok"], "ts": entry["ts"]}
    return [{k: v for k, v in route.items() if k not in ("from", "to")}
            | {"last_delivery": last.get((route["from"], route["event"], route["to"]))}
            for route in strategies.event_routes(hub)]


def integration_map(hub: "Hub") -> dict[str, Any]:
    """GET /api/integration/map (canvas-design 7.1)."""
    from ..extensions import registry

    tools = hub.tools()
    all_flows = flows.all_flows(hub)
    conns = {c.id: c for c in connections.all_connections(hub)}
    by_tool: dict[str, list[Flow]] = defaultdict(list)
    for f in all_flows:
        by_tool[f.tool_id].append(f)
    overview = identity.overview(hub)
    links = suite_matrix(tools)["links"]
    return {
        "generated_at": time.time(),
        "autonomy": hub.prefs["autonomy"],
        "guardrails": {"scans_need_approval": bool(guardrails.value(hub, "scans_need_approval"))},
        "apps": strategies.hub_apps(hub, registry.active_domains(hub), {f.domain for f in all_flows}),
        "nodes": [tool_node(t, conns.get(t.id), by_tool[t.id]) for t in tools],
        "flows": [flows.public(hub, f) for f in all_flows],
        "sso": sso_edges(overview),
        "events": event_edges(hub),
        "capability_links": [{"id": f"cap:{x['source']}:{x['target']}:{x['via']}", "source": f"tool:{x['source']}",
                              "target": f"tool:{x['target']}", "capability": x["via"]}
                             for x in links if x["type"] == "capability"],
        "identity": overview,
        "layout": get_layout(hub, "integration"),
    }


# --------------------------------------------------------------------------------------
# layouts
# --------------------------------------------------------------------------------------


class LayoutItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: float = Field(ge=-1e9, le=1e9, allow_inf_nan=False)
    lane: Literal["left", "right"] | None = None  # integration tools only; null removes the override


class LayoutPatch(BaseModel):
    """PATCH /api/layouts/{view}: per-id merge (last write wins); `remove` drops ids."""

    model_config = ConfigDict(extra="forbid")
    items: dict[str, LayoutItem] = Field(default_factory=dict, max_length=MAX_ITEMS)
    remove: list[str] = Field(default_factory=list, max_length=MAX_ITEMS)

    @field_validator("items")
    @classmethod
    def _item_ids(cls, value: dict[str, LayoutItem]) -> dict[str, LayoutItem]:
        bad = [k for k in value if not valid_id(k)]
        if bad:
            raise ValueError(f"{len(bad)} invalid item id(s): ids are tool:<id>, app:<id> or z:<zone id>")
        return value

    @field_validator("remove")
    @classmethod
    def _remove_ids(cls, value: list[str]) -> list[str]:
        if any(not valid_id(k) for k in value):
            raise ValueError("ids are tool:<id>, app:<id> or z:<zone id>")
        return value


def valid_id(item_id: str) -> bool:
    return bool(ITEM_ID.match(item_id)) and not CONTROL_CHARS.search(item_id)


def get_layout(hub: "Hub", view: str) -> dict[str, Any]:
    return hub.store.get(LAYOUTS, view) or {"id": view, "version": 0, "items": {}}


def _save(hub: "Hub", doc: dict[str, Any], ids: list[str], actor: str, reset: bool = False) -> dict[str, Any]:
    hub.store.put(LAYOUTS, doc)
    hub.bus.publish("canvas_layout", {"view": doc["id"], "version": doc["version"], "ids": ids[:MAX_ITEMS],
                                      "updated_by": actor, "reset": reset})
    return doc


def patch_layout(hub: "Hub", view: str, body: LayoutPatch, actor: str) -> dict[str, Any]:
    """Merge `body` into the view's layout. ValueError (nothing stored) for a lane on anything but an integration
    tool, or more than MAX_ITEMS items after merging."""
    for item_id, item in body.items.items():
        if "lane" in item.model_fields_set and item.lane is not None and not (
                view == "integration" and item_id.startswith("tool:")):
            raise ValueError(f"lane is only set on integration tools ({item_id[:60]})")
    doc = get_layout(hub, view)
    items: dict[str, dict[str, Any]] = {k: dict(v) for k, v in doc.get("items", {}).items()}
    for item_id in body.remove:
        items.pop(item_id, None)
    for item_id, item in body.items.items():
        entry = {**items.get(item_id, {}), "order": item.order}
        if "lane" in item.model_fields_set:
            entry.pop("lane", None)
            if item.lane is not None:
                entry["lane"] = item.lane
        items[item_id] = entry
    if len(items) > MAX_ITEMS:
        raise ValueError(f"A layout holds at most {MAX_ITEMS} items")
    doc = {"id": view, "version": int(doc.get("version", 0)) + 1, "updated_at": time.time(), "updated_by": actor,
           "items": items}
    return _save(hub, doc, [*body.items, *body.remove], actor)


def reset_layout(hub: "Hub", view: str, actor: str) -> dict[str, Any]:
    """"Reset arrangement": every item goes back to its default place (the version keeps counting)."""
    old = get_layout(hub, view)
    doc = {"id": view, "version": int(old.get("version", 0)) + 1, "updated_at": time.time(), "updated_by": actor,
           "items": {}}
    hub.activity(actor, "info", f"Reset the arrangement of the {view} map")
    return _save(hub, doc, list(old.get("items", {})), actor, reset=True)
