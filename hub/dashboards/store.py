"""Dashboards, per-user dashboard preferences and the dashboard settings in the hub's store (round4-dashboard-spec.md
5.1, 5.3, 5.5).

Collections: ``dashboards`` (doc id ``u:<user id>:<dash id>`` for personal dashboards, ``shared:<dash id>`` for shared
ones; the doc is ``{"id": <doc id>, "dashboard": Dashboard}``), ``dashboard_prefs`` (doc id = the user id) and the one
``settings/dashboards`` document. A personal dashboard is always looked up under the caller's own user id, so another
user's id is a 404 by construction.

Every write runs under one lock (read, compare, write): the version must match (409 ``version_conflict``), the layout
must fit the grid without overlaps (422 ``invalid_layout``) and every widget must fit its type (422 ``invalid_widget``,
403 ``role_required``). A widget whose type or config no longer validates (its tool or pack was removed) is kept only
while its content - type, title and config - is unchanged; it may still move, so the rest of the dashboard stays
saveable. Error messages name the widget, never a config value.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING, Any, Iterable

from pydantic import ValidationError

from ..extensions.pack import describe_errors
from ..store import new_id
from . import layout, registry
from .models import LIMITS, Dashboard, DashboardPrefs, DashboardSettings, WidgetInstance, canonical

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "dashboards"
PREFS = "dashboard_prefs"
SETTINGS_ID = "dashboards"
LOCK = threading.Lock()
LAYOUT_MESSAGES = {"duplicate_id": "Two widgets have the same id", "out_of_bounds": "A widget does not fit the grid",
                   "overlap": "Two widgets overlap"}


class DashboardError(Exception):
    """A refused request: HTTP `status`, machine `code`, a message a person can act on, extras (widget_id, ...)."""

    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra

    def detail(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.extra}


def personal_key(user_id: str, dash_id: str) -> str:
    return f"u:{user_id}:{dash_id}"


def shared_key(dash_id: str) -> str:
    return f"shared:{dash_id}"


def doc_key(d: Dashboard) -> str:
    return personal_key(d.owner_id or "", d.id) if d.scope == "personal" else shared_key(d.id)


def _load(doc: dict[str, Any] | None) -> Dashboard | None:
    return Dashboard.model_validate(doc["dashboard"]) if doc else None


def get_personal(hub: "Hub", user_id: str, dash_id: str) -> Dashboard | None:
    return _load(hub.store.get(COLLECTION, personal_key(user_id, dash_id)))


def get_shared(hub: "Hub", dash_id: str) -> Dashboard | None:
    return _load(hub.store.get(COLLECTION, shared_key(dash_id)))


def personal(hub: "Hub", user_id: str) -> list[Dashboard]:
    docs = [_load(d) for d in hub.store.list_prefix(COLLECTION, f"u:{user_id}:")]
    return sorted((d for d in docs if d), key=lambda d: (d.created_at, d.id))


def shared(hub: "Hub") -> list[Dashboard]:
    docs = [_load(d) for d in hub.store.list_prefix(COLLECTION, "shared:")]
    return sorted((d for d in docs if d), key=lambda d: (d.created_at, d.id))


def _put(hub: "Hub", d: Dashboard) -> Dashboard:
    data = d.model_dump(mode="json")
    if len(canonical(data)) > LIMITS["dashboard_bytes"]:
        raise DashboardError(413, "too_large", "The dashboard is larger than 64 KB; remove or shorten some widgets")
    hub.store.put(COLLECTION, {"id": doc_key(d), "dashboard": data})
    return d


def new_widget_id() -> str:
    return new_id("w_")


# -- validation -------------------------------------------------------------------------------


def availability(hub: "Hub", w: WidgetInstance) -> tuple[bool, str | None, str]:
    """(available, reason, min_role) of a stored widget: its type is registered, its config fits and what it names
    still exists."""
    t = registry.get(w.type)
    if t is None:
        return False, "This kind of widget is not available any more.", "viewer"
    try:
        config = t.parse(w.config)
    except ValidationError:
        return False, "This widget's settings no longer fit; configure it again or remove it.", t.min_role
    try:
        t.check(hub, config)
    except ValueError as exc:
        return False, f"{t.title}: {exc}", t.role(config)
    return True, None, t.role(config)


def check_widgets(hub: "Hub", widgets: list[WidgetInstance], previous: Iterable[WidgetInstance], role: str) -> None:
    """The rules of spec 5.3 (2, 3) for a dashboard's widgets; DashboardError for the first problem."""
    if len(widgets) > LIMITS["widgets"]:
        raise DashboardError(422, "invalid_layout", f"A dashboard holds at most {LIMITS['widgets']} widgets")
    problems = layout.validate([w.model_dump() for w in widgets])
    if problems:
        first = problems[0]
        raise DashboardError(422, "invalid_layout", LAYOUT_MESSAGES[first["code"]], widget_id=first["id"],
                             problem=first["code"])
    stored = {w.id: w for w in previous}
    for w in widgets:
        old = stored.get(w.id)
        unchanged = old is not None and old.content() == w.content()
        t = registry.get(w.type)
        if t is None:
            if unchanged:
                continue
            raise DashboardError(422, "invalid_widget", "This kind of widget does not exist", widget_id=w.id)
        try:
            config = t.parse(w.config)
        except ValidationError as exc:
            if unchanged:
                continue
            raise DashboardError(422, "invalid_widget", f"{t.title}: {describe_errors(exc)}", widget_id=w.id) from exc
        # a stored widget keeps its size when its type's bounds change later; a new, retyped or resized one must fit
        resized = old is None or (old.type, old.w, old.h) != (w.type, w.w, w.h)
        if resized and not (t.size_min[0] <= w.w <= t.size_max[0] and t.size_min[1] <= w.h <= t.size_max[1]):
            raise DashboardError(422, "invalid_widget",
                                 f"{t.title} is {t.size_min[0]}x{t.size_min[1]} to {t.size_max[0]}x{t.size_max[1]} cells",
                                 widget_id=w.id)
        if unchanged:
            continue  # kept as it was saved: what it names may be gone, or the caller's role dropped since
        try:
            t.check(hub, config)
        except ValueError as exc:
            raise DashboardError(422, "invalid_widget", f"{t.title}: {exc}", widget_id=w.id) from exc
        needed = t.role(config)
        if not registry.allowed(role, needed):
            raise DashboardError(403, "role_required", f"{t.title} needs the {needed} role", widget_id=w.id)


def usable(hub: "Hub", widgets: Iterable[WidgetInstance], role: str) -> tuple[list[WidgetInstance], int]:
    """The widgets a copy for `role` keeps (5.3 rule 6): not above the role and available now; and how many went."""
    kept: list[WidgetInstance] = []
    dropped = 0
    for w in widgets:
        ok, _, needed = availability(hub, w)
        if ok and registry.allowed(role, needed):
            kept.append(w.model_copy())
        else:
            dropped += 1
    return kept, dropped


# -- dashboards -------------------------------------------------------------------------------


def create(hub: "Hub", *, scope: str, owner_id: str | None, title: str, icon: str, description: str,
           widgets: list[WidgetInstance], actor: str, based_on: str | None = None, based_on_version: int | None = None,
           template: str | None = None) -> Dashboard:
    with LOCK:
        if scope == "personal":
            if len(hub.store.ids_prefix(COLLECTION, f"u:{owner_id}:")) >= LIMITS["personal_dashboards"]:
                raise DashboardError(409, "limit", f"You have {LIMITS['personal_dashboards']} dashboards, the maximum")
        elif len(hub.store.ids_prefix(COLLECTION, "shared:")) >= LIMITS["shared_dashboards"]:
            raise DashboardError(409, "limit", f"There are {LIMITS['shared_dashboards']} shared dashboards, the maximum")
        now = time.time()
        d = Dashboard(id=new_id("p_" if scope == "personal" else "s_"), scope=scope, owner_id=owner_id, title=title,
                      icon=icon, description=description, widgets=widgets, based_on=based_on,
                      based_on_version=based_on_version, template=template, version=1, created_at=now,
                      updated_at=now, updated_by=actor)
        return _put(hub, d)


def update(hub: "Hub", current: Dashboard, *, title: str, icon: str, description: str, widgets: list[WidgetInstance],
           base_version: int, actor: str, role: str, based_on_version: int | None = None) -> Dashboard:
    """Replace a dashboard's title and widgets, against the version the client started from. `based_on_version`: a
    personal copy was reset to that version of the shared dashboard it came from."""
    with LOCK:
        stored = _load(hub.store.get(COLLECTION, doc_key(current)))
        if stored is None:
            raise DashboardError(404, "not_found", "Dashboard not found")
        if base_version != stored.version:
            raise DashboardError(409, "version_conflict", "This dashboard changed in another window", dashboard=stored)
        check_widgets(hub, widgets, stored.widgets, role)
        changes: dict[str, Any] = {"title": title, "icon": icon, "description": description, "widgets": widgets,
                                   "version": stored.version + 1, "updated_at": time.time(), "updated_by": actor}
        if based_on_version is not None:
            source = get_shared(hub, stored.based_on) if stored.based_on else None
            if stored.scope != "personal" or source is None or based_on_version > source.version:
                raise DashboardError(422, "invalid", "This dashboard is not a copy of that version of a shared one")
            changes["based_on_version"] = based_on_version
        d = stored.model_copy(update=changes)
        return _put(hub, Dashboard.model_validate(d.model_dump()))


def delete(hub: "Hub", d: Dashboard) -> bool:
    with LOCK:
        return hub.store.delete(COLLECTION, doc_key(d))


# -- preferences and settings -----------------------------------------------------------------


def prefs(hub: "Hub", user_id: str) -> DashboardPrefs:
    doc = hub.store.get(PREFS, user_id)
    return DashboardPrefs.model_validate({k: v for k, v in doc.items() if k != "id"}) if doc else DashboardPrefs()


def put_prefs(hub: "Hub", user_id: str, value: DashboardPrefs, base_version: int | None = None) -> DashboardPrefs:
    with LOCK:
        current = prefs(hub, user_id)
        if base_version is not None and base_version != current.version:
            raise DashboardError(409, "version_conflict", "Your dashboard tabs changed in another window",
                                 prefs=current.model_dump())
        value = value.model_copy(update={"version": current.version + 1})
        hub.store.put(PREFS, {"id": user_id, **value.model_dump(mode="json")})
        return value


def settings(hub: "Hub") -> DashboardSettings:
    doc = hub.store.get("settings", SETTINGS_ID)
    return DashboardSettings.model_validate({k: v for k, v in doc.items() if k != "id"}) if doc else DashboardSettings()


def put_settings(hub: "Hub", value: DashboardSettings) -> DashboardSettings:
    with LOCK:
        current = settings(hub)
        value = value.model_copy(update={"version": current.version + 1})
        hub.store.put("settings", {"id": SETTINGS_ID, **value.model_dump(mode="json")})
        return value


def forget_user(hub: "Hub", user_id: str) -> int:
    """A deleted account's dashboards and preferences (5.5); returns how many dashboards went."""
    with LOCK:
        removed = hub.store.delete_many(COLLECTION, hub.store.ids_prefix(COLLECTION, f"u:{user_id}:"))
        hub.store.delete(PREFS, user_id)
        return max(removed, 0)
