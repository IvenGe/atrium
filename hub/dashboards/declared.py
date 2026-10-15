"""Declared widgets (round4-dashboard-spec.md 6.6, stage D3): dashboard widgets that extension packs (``widget`` items)
and tool manifests (``ui.widgets``) declare as data - a ``WidgetDecl`` - and the hub compiles to its own record widgets:
count and metric -> ``domain_count`` (one number), breakdown -> ``domain_count`` (bars), list -> ``domain_list``.

A declaration never carries code, HTML, colours or URLs, and it reads only what the domain spec whitelists. A tool's
declarations are untrusted: they are only suggestions in the gallery ("Suggested by <tool>"), never added to a
dashboard by themselves, always scoped to that tool's records, and only for domains its connection reads now. A
pack's are offered ("From <pack>") while the pack is enabled.

The widget keeps its ``ref`` ("pack:<pack id>/<key>" or "tool:<tool id>/<key>"), so a pack or manifest update applies
to widgets already on dashboards; when the declaration is gone or no longer compiles, the widget is unavailable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, ValidationError

from ..extensions.pack import WidgetDecl, describe_errors
from . import registry
from .domains import QueryError
from .records import ALL_EVENTS
from .registry import Outcome, WidgetType, register, suggester, suggestion
from .resolve import ResolveContext, Snapshot, clean
from .widgets import Strict

if TYPE_CHECKING:
    from ..core import Hub

REF = r"^(pack:[a-z0-9][a-z0-9-]{1,47}|tool:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})/[a-z][a-z0-9_]{1,31}$"
EVENTS = tuple(dict.fromkeys((*ALL_EVENTS, "tool", "tool_removed", "connection", "extension", "extension_removed")))


class DeclaredConfig(Strict):
    ref: str = Field(pattern=REF)

    def check(self, hub: "Hub") -> None:
        build(hub, find(hub, self.ref))


@dataclass
class Found:
    kind: Literal["pack", "tool"]
    id: str
    name: str
    decl: WidgetDecl

    @property
    def source(self) -> str:
        return f"tool:{self.id}" if self.kind == "tool" else "all"

    def declared_by(self) -> dict[str, Any]:
        return {"kind": self.kind, "id": self.id, "name": self.name}


def gone(what: str) -> QueryError:
    return QueryError("ref", f"{what} (it may have been removed or disabled)", "declaration_gone",
                      f"This widget's declaration is gone: {what}.")


def find(hub: "Hub", ref: str, snap: Snapshot | None = None) -> Found:
    """The declaration a ref names: an enabled pack's widget item, or a widget in a tool's manifest."""
    owner, key = ref.rsplit("/", 1)
    kind, owner_id = owner.split(":", 1)
    if kind == "pack":
        from ..extensions import registry as ext_registry

        pack = next((p for p in ext_registry.active(hub) if p.id == owner_id), None)
        if pack is None:
            raise gone("its extension pack is not enabled")
        item = next((w for w in pack.of("widget") if w.key == key), None)
        if item is None:
            raise gone("the pack no longer declares it")
        return Found("pack", pack.id, clean(pack.name, 80), item)
    tool = snap.tools_by_id.get(owner_id) if snap is not None else hub.get_tool(owner_id)
    if tool is None:
        raise gone("the tool that suggested it was removed")
    raw = next((w for w in (tool.manifest.ui.widgets if tool.manifest else []) if w.get("key") == key), None)
    if raw is None:
        raise gone("the tool's manifest no longer declares it")
    try:
        decl = WidgetDecl.model_validate(raw)
    except ValidationError as exc:
        raise QueryError("ref", describe_errors(exc, 3)) from exc
    return Found("tool", tool.id, clean(tool.name, 80), decl)


def compiled(found: Found) -> tuple[str, dict[str, Any]]:
    """(widget type, config) of a declaration."""
    d = found.decl
    base = {"domain": d.domain, "source": found.source,
            "filters": [{"field": c.field, "op": c.op, "value": c.value} for c in d.where]}
    if d.view == "list":
        return "domain_list", {**base, "sort": d.sort, "order": d.order, "limit": d.limit, "columns": d.columns}
    if d.view == "breakdown":
        return "domain_count", {**base, "group_by": d.group_by, "view": "bars"}
    return "domain_count", {**base, "group_by": None, "view": "number"}


def build(hub: "Hub", found: Found, snap: Snapshot | None = None) -> tuple[registry.WidgetType, Any]:
    """The compiled widget type and its validated config; QueryError when the declaration does not fit what the
    domain spec whitelists, or a tool's declaration names data its connection does not read."""
    if found.kind == "tool":
        from ..integration import connections

        conn = (snap.connections.get(found.id) if snap is not None else connections.get(hub, found.id))
        reads = {d for d, ops in (connections.capabilities(conn) if conn is not None else {}).items() if "read" in ops}
        if found.decl.domain not in reads:
            raise QueryError("domain", f"{found.name}'s connection does not read this data", "not_read",
                             f"{found.name}'s connection does not read the data this widget shows.")
    type_key, config = compiled(found)
    t = registry.REGISTRY[type_key]
    try:
        parsed = t.parse(config)
    except ValidationError as exc:
        raise QueryError("ref", describe_errors(exc, 3)) from exc
    t.check(hub, parsed)
    return t, parsed


def resolve_declared(ctx: ResolveContext, cfg: DeclaredConfig) -> dict[str, Any] | Outcome:
    try:
        found = find(ctx.hub, cfg.ref, ctx.snap)
        t, config = build(ctx.hub, found, ctx.snap)
    except QueryError as exc:
        raise exc.unavailable() from exc
    extra = {"compiled": t.key, "declared_by": found.declared_by(), "declared_title": found.decl.title}
    out = t.resolve(ctx, config)
    if isinstance(out, Outcome):
        out.data = {**(out.data or {}), **extra}
        return out
    return {**out, **extra}


register(WidgetType(
    "declared", "Declared widget", "A widget an extension pack or a tool's manifest declares.", "records",
    DeclaredConfig, resolve_declared, (2, 1), (4, 3), (12, 8), events=EVENTS, ttl=30, refresh=60,
    title_for=lambda c: "Suggested widget"))


# -- gallery suggestions (6.5 item 4) -------------------------------------------------------------


def offer(hub: "Hub", group: str, found: Found, ref: str) -> dict[str, Any] | None:
    """A declaration as a suggestion; one that does not compile is offered as invalid, with the reason."""
    try:
        build(hub, found)
        invalid = None
    except QueryError as exc:
        invalid = str(exc)
    d = found.decl
    by = f"Suggested by {found.name}" if found.kind == "tool" else f"From {found.name}"
    extra: dict[str, Any] = {"declared_by": found.declared_by()}
    if invalid:
        extra["invalid"] = invalid
    return suggestion(group, "declared", {"ref": ref}, d.title, d.description or by, size=d.grid_size(), **extra)


@suggester
def declared_suggestions(hub: "Hub") -> list[dict[str, Any]]:
    from ..extensions import registry as ext_registry

    out = []
    for pack, item in ext_registry.widget_items(hub):
        out.append(offer(hub, f"pack:{pack.id}", Found("pack", pack.id, clean(pack.name, 80), item),
                         f"pack:{pack.id}/{item.key}"))
    for tool in hub.tools():
        for raw in (tool.manifest.ui.widgets if tool.manifest else []):
            try:
                decl = WidgetDecl.model_validate(raw)
            except ValidationError:
                continue  # stored before validation tightened: not offered
            out.append(offer(hub, f"tool:{tool.id}", Found("tool", tool.id, clean(tool.name, 80), decl),
                             f"tool:{tool.id}/{decl.key}"))
    return [x for x in out if x is not None]
