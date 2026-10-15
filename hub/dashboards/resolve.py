"""Server-side widget data (round4-dashboard-spec.md 8.1-8.2).

For each requested widget: the role gate (forbidden), the config parse (unavailable when a stored config no longer
fits), the cache, the resolver and the post-processing (strings without control characters and capped, a ``version``
hash of the data). Resolvers get a ``ResolveContext(hub, snap, now)`` - never the principal - and read through ``snap``,
a per-request memo, so a request for 20 widgets reads each collection at most once.

Resolvers build their data from whitelisted fields only (explicit dict projections, never a whole record dumped). A
resolver that raises is reported as ``error`` with a generic message; the log names the widget type and id only, never
config values or record contents.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass
from functools import cached_property
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ..models import Asset, ControlState, Risk, Vulnerability
from . import registry
from .cache import WidgetCache
from .models import canonical

if TYPE_CHECKING:
    from ..core import Hub
    from ..integration.connections import Connection
    from ..models import Approval, Flow, Tool

log = logging.getLogger("hub.dashboards")

# control characters (C0 but tab and newline, DEL, C1) plus zero-width, line/paragraph separators and bidi controls:
# tool text that could disguise itself ("invoice\u202eexe.pdf"). The same class as netmodel.CONTROL_CHARS.
CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
MAX_STRING = 2000  # a generic cap after the resolvers' own (titles and cells 200, notes 2000)
ACTIVITY_WINDOW = 500  # activity entries a request reads (widgets filter and cut them)
PEOPLE_FACTS = ("id", "status")  # counting people and finding who left
ASSET_LINK_FACTS = ("id", "owner_person_id", "assigned_person_id")  # the assets linked to a person


def clean(text: Any, limit: int = 200) -> str:
    """Untrusted text (titles, names, cells) for widget data: no control, bidi or zero-width characters, at most `limit`
    characters."""
    value = CONTROL.sub("", str(text if text is not None else ""))
    return value if len(value) <= limit else value[: limit - 1] + "…"


class Snapshot:
    """What one data request reads, each loaded once on first use."""

    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._ext: dict[str, list[Any]] = {}
        self._facts: dict[tuple[str, tuple[str, ...]], list[dict[str, Any]]] = {}
        self.memo: dict[Any, Any] = {}  # later stages' per-request reads (domain rows, network devices)

    def facts(self, collection: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
        """Only these scalar fields of every record (``Store.project``): counting over a large collection without
        parsing whole records (round4-dashboard-spec.md 8.3)."""
        key = (collection, fields)
        if key not in self._facts:
            self._facts[key] = self.hub.store.project(collection, fields)
        return self._facts[key]

    @cached_property
    def tools(self) -> list["Tool"]:
        return self.hub.tools()

    @cached_property
    def tools_by_id(self) -> dict[str, "Tool"]:
        return {t.id: t for t in self.tools}

    @cached_property
    def connections(self) -> dict[str, "Connection"]:
        from ..integration import connections

        return {c.id: c for c in connections.all_connections(self.hub)}

    @cached_property
    def flows(self) -> list["Flow"]:
        from ..integration import flows

        return flows.all_flows(self.hub)

    @cached_property
    def assets(self) -> list[Asset]:
        return self.hub.all("assets", Asset)

    @cached_property
    def vulnerabilities(self) -> list[Vulnerability]:
        return self.hub.all("vulnerabilities", Vulnerability)

    @cached_property
    def risks(self) -> list[Risk]:
        return self.hub.all("risks", Risk)

    @cached_property
    def controls(self) -> list[ControlState]:
        return self.hub.all("controls", ControlState)

    @cached_property
    def people(self) -> list[Any]:
        from .. import people

        return people.all_people(self.hub)

    @cached_property
    def accounts(self) -> list[Any]:
        from .. import people

        return people.all_accounts(self.hub)

    @cached_property
    def people_count(self) -> int:
        return len(self.facts("people", PEOPLE_FACTS))

    @cached_property
    def leavers(self) -> list[dict[str, Any]]:
        """``people.find_leavers`` over the people who left and only the assets and accounts linked to them: the same
        findings as ``people.leavers(hub)`` without parsing every person and asset of a large directory (8.3)."""
        from .. import people
        from ..models import Person

        left = [r["id"] for r in self.facts(people.COLLECTION, PEOPLE_FACTS) if r["status"] in people.LEFT]
        if not left:
            return []
        ids = set(left)
        persons = [p for p in (self.hub.one(people.COLLECTION, i, Person) for i in left) if p is not None]
        linked = [r["id"] for r in self.facts("assets", ASSET_LINK_FACTS)
                  if r["owner_person_id"] in ids or r["assigned_person_id"] in ids]
        assets = [a for a in (self.hub.one("assets", i, Asset) for i in linked) if a is not None]
        return people.find_leavers(persons, assets, self.hub.auth.users(),
                                   [a for a in self.accounts if a.person_id in ids], {t.id: t.name for t in self.tools})

    @cached_property
    def approvals(self) -> list["Approval"]:
        return self.hub.approvals.list()

    @cached_property
    def agents(self) -> list[Any]:
        return self.hub.agents.all()

    @cached_property
    def agent_records(self) -> list[dict[str, Any]]:
        return [a.record() for a in self.agents]

    @cached_property
    def activity(self) -> list[dict[str, Any]]:
        """The newest activity entries, newest first."""
        return list(reversed(self.hub.store.tail("activity", ACTIVITY_WINDOW)))

    @cached_property
    def extensions(self) -> list[Any]:
        from ..extensions import registry as ext_registry

        return ext_registry.records(self.hub)

    @cached_property
    def ext_domains(self) -> dict[str, Any]:
        from ..extensions import registry as ext_registry

        return ext_registry.active_domains(self.hub)

    def ext_records(self, key: str) -> list[Any]:
        if key not in self._ext:
            from ..extensions import records

            self._ext[key] = records.all_records(self.hub, key)
        return self._ext[key]

    @cached_property
    def drift(self) -> list[dict[str, Any]]:
        from ..integration import network

        return network.drift(self.hub)

    @cached_property
    def device_changes(self) -> list[dict[str, Any]]:
        from ..integration import changes

        return changes.listing(self.hub)


@dataclass
class ResolveContext:
    hub: "Hub"
    snap: Snapshot
    now: float


def _post(value: Any, depth: int = 0) -> Any:
    """Strings without control characters (newlines and tabs stay: notes) and capped; containers walked."""
    if isinstance(value, str):
        value = CONTROL.sub("", value)
        return value if len(value) <= MAX_STRING else value[: MAX_STRING - 1] + "…"
    if depth > 12:
        return None
    if isinstance(value, dict):
        return {str(k): _post(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_post(v, depth + 1) for v in value]
    return value


def result(status: str, data: dict[str, Any] | None = None, *, now: float, ttl: float = 30.0,
           refresh: int | None = None, code: str | None = None, message: str | None = None,
           hint: dict[str, Any] | None = None, events: tuple[str, ...] = ()) -> dict[str, Any]:
    """A WidgetResult (7.2)."""
    body = {"status": status, "data": data, "code": code, "message": message, "hint": hint}
    version = hashlib.sha1(canonical(body).encode()).hexdigest()[:12]
    return {**body, "version": version, "generated_at": now, "stale_after": now + max(ttl, refresh or 0) * 2,
            "refresh": refresh, "events": list(events)}


def _forbidden(needed: str, now: float) -> dict[str, Any]:
    return result("forbidden", now=now, code="role_required", message=f"Needs the {needed} role.")


def compute(t: registry.WidgetType, config: Any, ctx: ResolveContext, widget_id: str = "") -> dict[str, Any]:
    """Run one resolver and wrap its outcome; never raises."""
    events = t.deps(config)
    try:
        out = t.resolve(ctx, config)
    except registry.Unavailable as exc:
        return result("unavailable", now=ctx.now, code=exc.code, message=exc.message, events=events)
    except Exception as exc:  # a resolver bug must not break the dashboard - nor leak what it was computing
        log.warning("Dashboard widget %s (%s) failed: %s", widget_id or "-", t.key, exc.__class__.__name__)
        return result("error", now=ctx.now, code="error", message="Could not compute this widget.", events=events)
    if isinstance(out, registry.Outcome):
        return result(out.status, _post(out.data) if out.data is not None else None, now=ctx.now, ttl=t.ttl,
                      refresh=t.refresh, code=out.code, message=out.message, hint=out.hint, events=events)
    return result("ok", _post(out), now=ctx.now, ttl=t.ttl, refresh=t.refresh, events=events)


async def resolve(ctx: ResolveContext, cache: WidgetCache | None, type_key: str, raw_config: dict[str, Any], role: str,
                  *, widget_id: str = "", fresh: bool = False) -> dict[str, Any]:
    """One widget's WidgetResult for a caller with `role`."""
    t = registry.get(type_key)
    if t is None:
        return result("unavailable", now=ctx.now, code="unknown_type",
                      message="This kind of widget is not available any more.")
    if not registry.allowed(role, t.min_role):
        return _forbidden(t.min_role, ctx.now)
    try:
        config = t.parse(raw_config)
    except ValidationError:
        return result("unavailable", now=ctx.now, code="invalid_config", events=t.events,
                      message="This widget's settings no longer fit; configure it again or remove it.")
    needed = t.role(config)
    if not registry.allowed(role, needed):
        return _forbidden(needed, ctx.now)
    if cache is None or not t.cache:
        return compute(t, config, ctx, widget_id)
    key = (t.key, canonical(config.model_dump(mode="json")))
    return await cache.get(key, t.deps(config), t.ttl, lambda: compute(t, config, ctx, widget_id), fresh=fresh)


async def resolve_many(hub: "Hub", cache: WidgetCache | None, widgets: list[tuple[str, str, dict[str, Any]]],
                       role: str) -> dict[str, dict[str, Any]]:
    """{widget id: WidgetResult} for (id, type, config) triples, over one snapshot."""
    ctx = ResolveContext(hub, Snapshot(hub), time.time())
    return {wid: await resolve(ctx, cache, type_key, config, role, widget_id=wid) for wid, type_key, config in widgets}
