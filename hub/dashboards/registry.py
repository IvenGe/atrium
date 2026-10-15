"""The widget type registry (round4-dashboard-spec.md 6.1) and the gallery's suggestion providers (6.5).

A ``WidgetType`` says what a widget may hold (a strict pydantic config model), how large it may be, who may see it, which
bus events make its data stale, how long its result is cached and how it is computed. Resolvers get a
``ResolveContext`` without the principal (hub/dashboards/resolve.py): the role gate runs before them, so one cached
result serves every viewer (8.2). They return the widget's data as a dict, or an ``Outcome`` for a non-"ok" status, and
raise ``Unavailable`` when what the widget names is gone (a removed tool).

Later stages register more types in their own modules (D3: records and compliance widgets, D4: settings widgets) and
more suggestion providers (``SUGGESTERS``, D3's per-tool presets); ``hub/dashboards/__init__.py`` imports them.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Literal

from pydantic import BaseModel

from ..auth.policy import ROLE_RANK
from .models import canonical

if TYPE_CHECKING:
    from ..core import Hub
    from .resolve import ResolveContext

Role = Literal["viewer", "operator", "admin"]
Category = Literal["overview", "tools", "records", "agents", "compliance", "network", "people", "settings", "embedded",
                   "notes"]
FieldKind = Literal["select", "multiselect", "text", "textarea", "number", "toggle", "tool", "tools", "domain", "field",
                    "filters", "links", "team"]


class Unavailable(Exception):
    """What a widget names is gone (a tool removed, a data type no longer active): the widget shows ``message``."""

    def __init__(self, message: str, code: str = "unavailable"):
        super().__init__(message)
        self.message, self.code = message, code


@dataclass
class Outcome:
    """A resolver's result with a status other than plain "ok": "empty" (with zero-count data and a hint),
    "unavailable" or "disabled"."""

    status: Literal["ok", "empty", "unavailable", "disabled"] = "ok"
    data: dict[str, Any] | None = None
    code: str | None = None
    message: str | None = None
    hint: dict[str, Any] | None = None  # {text, href, min_role}


@dataclass(frozen=True)
class FieldSpec:
    """One field of the configure form the UI builds generically (10.9). ``options`` is a list of {value, label}, or
    the name of a catalog list to take them from: "metrics" (the catalog's metrics) for a select, and for ``field``
    kinds the domain spec list ("group_by", "sort", ...). ``tool``/``tools`` pick one tool or "all"/up to 20 from the
    catalog's tools; ``team`` is "all" or an agent team id. A ``tool`` field with ``depends_on`` (the config's domain
    field) or a fixed ``domain`` is a source: "all", "manual" or "tool:<id>" among the tools that read the domain
    (``options`` then replace "all"/"manual"); ``tools`` with a ``domain`` lists only the tools that read it."""

    name: str
    label: str
    kind: FieldKind
    options: list[dict[str, Any]] | str | None = None
    depends_on: str | None = None
    min: int | None = None
    max: int | None = None
    hint: str | None = None
    domain: str | None = None

    def view(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


def options(*pairs: tuple[Any, str]) -> list[dict[str, Any]]:
    return [{"value": value, "label": label} for value, label in pairs]


@dataclass(frozen=True)
class WidgetType:
    key: str
    title: str
    description: str
    category: Category
    config_model: type[BaseModel]  # extra="forbid"; may define check(hub) raising ValueError(message) (save-time)
    resolve: Callable[["ResolveContext", Any], "dict[str, Any] | Outcome"]
    size_min: tuple[int, int]
    size_default: tuple[int, int]
    size_max: tuple[int, int]
    fields: tuple[FieldSpec, ...] = ()
    min_role: Role = "viewer"
    events: tuple[str, ...] = ()  # bus/SSE types that make the data stale (with events_for: every one it may name)
    events_for: Callable[[Any], tuple[str, ...]] | None = None  # when they depend on the config
    role_for: Callable[[Any], Role] | None = None  # when the role depends on the config (D3: per domain)
    ttl: float = 30.0  # server cache max age, seconds (5..300)
    refresh: int | None = None  # client periodic refresh, seconds (>= 30); None: events only
    cache: bool = True  # False for widgets that read nothing worth caching (note, links)
    title_for: Callable[[Any], str] | None = None  # the generated title (the UI's placeholder and default)

    def deps(self, config: Any) -> tuple[str, ...]:
        return tuple(self.events_for(config)) if self.events_for else self.events

    def role(self, config: Any | None = None) -> Role:
        """The role a config of this type needs (never below the type's own)."""
        if config is None or self.role_for is None:
            return self.min_role
        needed = self.role_for(config)
        return needed if ROLE_RANK[needed] > ROLE_RANK[self.min_role] else self.min_role

    def parse(self, config: dict[str, Any]) -> Any:
        """The validated config; pydantic ValidationError otherwise."""
        return self.config_model.model_validate(config)

    def check(self, hub: "Hub", config: Any) -> None:
        """Save-time whitelist checks (the tool exists, the team is known): ValueError with a readable message."""
        checker = getattr(config, "check", None)
        if checker is not None:
            checker(hub)

    def default_title(self, config: Any) -> str:
        return self.title_for(config) if self.title_for else self.title

    def view(self) -> dict[str, Any]:
        """The catalog entry (7.2)."""
        size = lambda s: {"w": s[0], "h": s[1]}  # noqa: E731
        return {"key": self.key, "title": self.title, "description": self.description, "category": self.category,
                "min_role": self.min_role, "size": {"min": size(self.size_min), "default": size(self.size_default),
                                                    "max": size(self.size_max)},
                "fields": [f.view() for f in self.fields], "refresh": self.refresh, "events": list(self.events)}


REGISTRY: dict[str, WidgetType] = {}


def register(t: WidgetType) -> WidgetType:
    if not 5 <= t.ttl <= 300:
        raise ValueError(f"{t.key}: ttl must be 5..300 seconds")
    if t.refresh is not None and t.refresh < 30:
        raise ValueError(f"{t.key}: refresh must be at least 30 seconds")
    REGISTRY[t.key] = t
    return t


def get(key: str) -> WidgetType | None:
    return REGISTRY.get(key)


def allowed(role: str, needed: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK[needed]


# -- suggestions (6.5) ----------------------------------------------------------------------

Suggester = Callable[["Hub"], list[dict[str, Any]]]
SUGGESTERS: list[Suggester] = []


def suggester(fn: Suggester) -> Suggester:
    SUGGESTERS.append(fn)
    return fn


def suggestion(group: str, type_key: str, config: dict[str, Any], title: str, description: str = "",
               size: tuple[int, int] | None = None, **extra: Any) -> dict[str, Any] | None:
    """A ready-made widget for the gallery, or None when the type is not registered or the config does not fit it."""
    t = REGISTRY.get(type_key)
    if t is None:
        return None
    try:
        t.parse(config)
    except Exception:
        return None
    digest = hashlib.sha1(canonical([group, type_key, config]).encode()).hexdigest()[:12]
    w, h = size or t.size_default
    return {"id": f"sg:{digest}", "group": group, "title": title, "description": description, "type": type_key,
            "config": config, "size": [w, h], **extra}


# What suggestions are made of (tools, their connections, extension data types): the catalog keeps the collected list
# while none of these was published, for at most SUGGESTION_TTL seconds.
SUGGESTION_EVENTS = ("tool", "tool_removed", "connection", "extension", "extension_removed")
SUGGESTION_TTL = 30.0


def collect_suggestions(hub: "Hub") -> list[tuple[dict[str, Any], Role]]:
    """Every provider's suggestions, without duplicates, each with the role it needs."""
    out: dict[str, tuple[dict[str, Any], Role]] = {}
    for provider in SUGGESTERS:
        for item in provider(hub):
            t = REGISTRY.get(item["type"])
            if t is None or item["id"] in out:
                continue
            try:
                out[item["id"]] = (item, t.role(t.parse(item["config"])))
            except Exception:
                continue
    return list(out.values())


def suggestions(hub: "Hub", role: str, collected: list[tuple[dict[str, Any], Role]] | None = None) -> list[dict[str, Any]]:
    """The suggestions the role may add (from `collected` when given)."""
    return [item for item, needed in (collect_suggestions(hub) if collected is None else collected)
            if allowed(role, needed)]


# The catalog's "domains" (D3 registers the domain specs' views here: (hub, role) -> [domain view]).
CATALOG_DOMAINS: list[Callable[["Hub", str], list[dict[str, Any]]]] = []
