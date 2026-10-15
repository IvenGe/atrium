"""REST routes of the Home dashboards (round4-dashboard-spec.md 7; added to the main router by ``api.build_router``;
the documents and their rules are in ``hub/dashboards/``).

Roles (classified in ``hub/auth/policy.py``): viewers read every route here and write their own dashboards and
dashboard preferences (``SELF_SERVICE_ROUTES``, marked *: every write is scoped to the caller's user id; API tokens get
403 ``person_required``). Shared dashboards and the default are administrators'. Widget data is computed on the server
from the stored config, per widget role-checked on every request. Errors carry ``detail = {"code", "message", ...}``:
version_conflict (409, with the current ``dashboard`` or ``prefs``), invalid_layout / invalid_widget (422, with
``widget_id``), role_required (403), person_required (403), limit (409), is_default (409), too_large (413), not_found
(404).

  GET    /api/widgets/catalog                     viewer   types, metrics, tools, suggestions, templates, limits
  GET    /api/widgets/preview?type=&config=       viewer   one WidgetResult (the configure dialog; fresh=1)
  GET    /api/widgets/templates/{key}             viewer   a template's widgets for the caller ("Reset to template")
  GET    /api/dashboards                          viewer   the caller's tabs, preferences, default and home
  GET    /api/dashboards/settings                 viewer   the default dashboard
  POST   /api/dashboards/mine                     viewer*  a personal dashboard (blank, template or copy) -> 201
  PUT    /api/dashboards/mine/{dash_id}           viewer*  replace it (base_version; based_on_version after "Reset to
                                                           the shared version")
  DELETE /api/dashboards/mine/{dash_id}           viewer*
  PUT    /api/dashboards/prefs                    viewer*  tab order, hidden shared dashboards, home
  POST   /api/dashboards/shared                   admin    -> 201
  PUT    /api/dashboards/shared/{dash_id}         admin    publish (base_version)
  DELETE /api/dashboards/shared/{dash_id}         admin    409 is_default
  PUT    /api/dashboards/default                  admin    {dashboard_id}
  GET    /api/dashboards/{dash_id}                viewer   one dashboard (a personal one: the caller's own only)
  GET    /api/dashboards/{dash_id}/data?widgets=  viewer   {generated_at, widgets: {id: WidgetResult}}

SSE events: ``dashboard {id, scope: "shared", version, updated_by, removed}`` and ``dashboard_settings {version}``.
Personal dashboards and preferences are never published: the stream reaches every signed-in principal.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import ValidationError

from .auth.service import CurrentPrincipal, Principal
from .dashboards import registry, store, templates
from .dashboards.cache import WidgetCache
from .dashboards.metrics import METRICS
from .dashboards.models import (DASH_ID, LIMITS, PERSONAL_ID, SHARED_ID, TYPE_KEY, Dashboard, DashboardCreate,
                                DashboardPrefs, DashboardPut, DashboardSettings, DefaultPut, PrefsPut,
                                WidgetInstance)
from .dashboards.resolve import ResolveContext, Snapshot, clean, resolve, resolve_many
from .extensions.pack import describe_errors

if TYPE_CHECKING:
    from .core import Hub

AnyId = Path(pattern=DASH_ID)
PersonalId = Path(pattern=PERSONAL_ID)
SharedId = Path(pattern=SHARED_ID)


def add_routes(router: APIRouter, hub: "Hub") -> None:
    cache = WidgetCache(hub.bus)
    suggested: dict[str, Any] = {}  # the collected suggestions, their event generations and expiry (6.5)

    def refuse(status: int, code: str, message: str, **extra: Any) -> HTTPException:
        return HTTPException(status, {"code": code, "message": message, **extra})

    def failed(p: Principal, exc: store.DashboardError) -> HTTPException:
        detail = exc.detail()
        if isinstance(detail.get("dashboard"), Dashboard):
            detail["dashboard"] = view(p, detail["dashboard"])
        return HTTPException(exc.status, detail)

    def person(p: Principal) -> str:
        if p.kind != "user":
            raise refuse(403, "person_required", "Personal dashboards belong to people signed in to Atrium; an API "
                                                 "token has none")
        return p.id

    def lookup(p: Principal, dash_id: str) -> Dashboard:
        d = None
        if dash_id.startswith("s_"):
            d = store.get_shared(hub, dash_id)
        elif p.kind == "user":
            d = store.get_personal(hub, p.id, dash_id)
        if d is None:
            raise refuse(404, "not_found", "Dashboard not found")
        return d

    def publish(d: Dashboard, actor: str, removed: bool = False) -> None:
        hub.bus.publish("dashboard", {"id": d.id, "scope": "shared", "version": d.version, "updated_by": actor,
                                      "removed": removed})

    # -- views ---------------------------------------------------------------------------

    def widget_view(w: WidgetInstance) -> dict[str, Any]:
        ok, reason, needed = store.availability(hub, w)
        t = registry.get(w.type)
        config = t.parse(w.config) if ok and t else None
        return {**w.model_dump(mode="json"), "available": ok, "reason": reason, "min_role": needed,
                "default_title": t.default_title(config) if config is not None else (t.title if t else "Widget"),
                "events": list(t.deps(config) if config is not None else t.events if t else ())}

    def newer(d: Dashboard) -> bool:
        source = store.get_shared(hub, d.based_on) if d.based_on else None
        return source is not None and source.version > (d.based_on_version or 0)

    def view(p: Principal, d: Dashboard, default_id: str | None = None) -> dict[str, Any]:
        """A dashboard for the caller (7.2): a shared one without the widgets above their role (counted only)."""
        default_id = default_id if default_id is not None else store.settings(hub).default_id
        shown, hidden = [], 0
        for w in d.widgets:
            item = widget_view(w)
            if d.scope == "shared" and not registry.allowed(p.role, item["min_role"]):
                hidden += 1
                continue
            shown.append(item)
        return {**d.model_dump(mode="json", exclude={"widgets"}), "widgets": shown, "hidden_widgets": hidden,
                "editable": d.scope == "personal" or p.role == "admin", "is_default": d.id == default_id,
                "based_on_newer": newer(d)}

    def summary(p: Principal, d: Dashboard, default_id: str | None, prefs: DashboardPrefs) -> dict[str, Any]:
        count = len(d.widgets) if d.scope == "personal" else sum(
            1 for w in d.widgets if registry.allowed(p.role, store.availability(hub, w)[2]))
        return {"id": d.id, "scope": d.scope, "title": d.title, "icon": d.icon, "description": d.description,
                "widgets": count, "version": d.version, "updated_at": d.updated_at, "updated_by": d.updated_by,
                "is_default": d.id == default_id, "editable": d.scope == "personal" or p.role == "admin",
                "hidden": d.id in prefs.hidden, "based_on": d.based_on, "based_on_newer": newer(d),
                "template": d.template}

    def source(p: Principal, origin: str | None) -> tuple[list[WidgetInstance], int, Dashboard | None, str | None]:
        """What a new dashboard starts from: (widgets, dropped, the dashboard copied, template key)."""
        if origin is None:
            return [], 0, None, None
        if origin.startswith("template:"):
            key = origin.removeprefix("template:")
            if key not in templates.TEMPLATES or not templates.TEMPLATES[key].available():
                raise refuse(422, "invalid", "There is no such template")
            widgets, dropped = templates.build(hub, key, p.role)
            return widgets, dropped, None, key
        copied = lookup(p, origin)
        widgets, dropped = store.usable(hub, copied.widgets, p.role)
        return widgets, dropped, copied, copied.template

    # -- the widget catalog and previews -------------------------------------------------

    def suggestions(role: str) -> list[dict[str, Any]]:
        deps, now = hub.bus.generations(registry.SUGGESTION_EVENTS), time.time()
        if suggested.get("deps") != deps or suggested.get("expires", 0.0) <= now:
            suggested.update(deps=deps, expires=now + registry.SUGGESTION_TTL,
                             items=registry.collect_suggestions(hub))
        return registry.suggestions(hub, role, suggested["items"])

    @router.get("/widgets/catalog")
    async def widget_catalog(p: CurrentPrincipal) -> dict[str, Any]:
        from .integration import connections

        snap = Snapshot(hub)
        tools = []
        for t in snap.tools:
            conn = snap.connections.get(t.id)
            caps = connections.capabilities(conn) if conn is not None else {}
            tools.append({"id": t.id, "name": clean(t.name, 120),
                          "ui": {"icon": t.manifest.ui.icon if t.manifest else None,
                                 "color": t.manifest.ui.color if t.manifest else None},
                          "reads": sorted(d for d, ops in caps.items() if "read" in ops),
                          "embeddable": False, "embed_reason": None})  # tools' own pages: stage D5, not built
        return {
            "types": [t.view() for t in registry.REGISTRY.values() if registry.allowed(p.role, t.min_role)],
            "domains": [d for provider in registry.CATALOG_DOMAINS for d in provider(hub, p.role)],
            "metrics": [m.view() for m in METRICS.values()],
            "tools": tools,
            "suggestions": suggestions(p.role),
            "templates": [t.view() for t in templates.available()],
            "limits": LIMITS,
            "embed": {"enabled": False, "tools": []},
        }

    @router.get("/widgets/preview")
    async def widget_preview(p: CurrentPrincipal, type_: str = Query(alias="type", pattern=TYPE_KEY),
                             config: str = Query("{}", max_length=4 * LIMITS["config_bytes"]),
                             fresh: bool = False) -> dict[str, Any]:
        t = registry.get(type_)
        if t is None:
            raise refuse(422, "invalid_widget", "This kind of widget does not exist")
        if len(config.encode()) > LIMITS["config_bytes"]:
            raise refuse(422, "invalid_widget", "The widget's settings are larger than 4 KB")
        try:
            raw = json.loads(config)
        except ValueError as exc:
            raise refuse(422, "invalid_widget", "The widget's settings are not valid JSON") from exc
        if not isinstance(raw, dict):
            raise refuse(422, "invalid_widget", "The widget's settings are a JSON object")
        try:
            parsed = t.parse(raw)
            t.check(hub, parsed)
        except ValidationError as exc:
            raise refuse(422, "invalid_widget", f"{t.title}: {describe_errors(exc)}") from exc
        except ValueError as exc:
            raise refuse(422, "invalid_widget", f"{t.title}: {exc}") from exc
        needed = t.role(parsed)
        if not registry.allowed(p.role, needed):
            raise refuse(403, "role_required", f"{t.title} needs the {needed} role")
        ctx = ResolveContext(hub, Snapshot(hub), time.time())
        return await resolve(ctx, cache, t.key, raw, p.role, fresh=fresh)

    @router.get("/widgets/templates/{key}")
    async def widget_template(p: CurrentPrincipal, key: str = Path(pattern=r"^[a-z][a-z0-9_]{1,31}$")) -> dict[str, Any]:
        """A template's widgets as the caller may have them ("Reset to template"; widgets above the role left out)."""
        template = templates.TEMPLATES.get(key)
        if template is None or not template.available():
            raise refuse(404, "not_found", "There is no such template")
        widgets, dropped = templates.build(hub, key, p.role)
        return {**template.view(), "widgets": [w.model_dump(mode="json") for w in widgets], "dropped": dropped}

    # -- dashboards ----------------------------------------------------------------------

    @router.get("/dashboards")
    async def list_dashboards(p: CurrentPrincipal) -> dict[str, Any]:
        default_id = store.settings(hub).default_id
        shared = store.shared(hub)
        mine = store.personal(hub, p.id) if p.kind == "user" else []
        prefs = store.prefs(hub, p.id) if p.kind == "user" else DashboardPrefs()
        ids = {d.id for d in [*shared, *mine]}
        if p.kind == "user" and (set(prefs.order) - ids or set(prefs.hidden) - ids or (prefs.home and prefs.home not in ids)):
            # a dashboard was deleted since: drop it from the preferences (5.5)
            prefs = store.put_prefs(hub, p.id, DashboardPrefs(
                order=[i for i in prefs.order if i in ids], hidden=[i for i in prefs.hidden if i in ids],
                home=prefs.home if prefs.home in ids else None))
        position = {dash_id: n for n, dash_id in enumerate(prefs.order)}
        dashes = sorted([*shared, *mine], key=lambda d: (position.get(d.id, len(position)), d.id != default_id,
                                                         d.scope != "shared", d.created_at))
        visible = [d.id for d in dashes if d.id not in prefs.hidden]
        home = next((x for x in (prefs.home, default_id) if x in visible), visible[0] if visible else None)
        return {"dashboards": [summary(p, d, default_id, prefs) for d in dashes], "prefs": prefs.model_dump(),
                "default_id": default_id, "home_id": home, "can_edit_shared": p.role == "admin", "limits": LIMITS}

    def settings_view(settings: DashboardSettings) -> dict[str, Any]:
        # tools' own pages in widgets are the optional stage D5, which is not built
        return {"default_id": settings.default_id, "version": settings.version, "embed": {"enabled": False, "tools": []}}

    @router.get("/dashboards/settings")
    async def dashboard_settings() -> dict[str, Any]:
        return settings_view(store.settings(hub))

    @router.post("/dashboards/mine", status_code=201)
    async def create_mine(body: DashboardCreate, p: CurrentPrincipal) -> dict[str, Any]:
        user_id = person(p)
        widgets, dropped, copied, template = source(p, body.from_)
        # a copy of a shared dashboard remembers it ("Reset to the shared version"); a copy of a copy keeps its origin
        based_on, based_on_version = ((copied.id, copied.version) if copied.scope == "shared"
                                      else (copied.based_on, copied.based_on_version)) if copied else (None, None)
        try:
            d = store.create(hub, scope="personal", owner_id=user_id, title=body.title, icon=body.icon,
                             description=body.description, widgets=widgets, actor=p.actor, template=template,
                             based_on=based_on, based_on_version=based_on_version)
        except store.DashboardError as exc:
            raise failed(p, exc) from exc
        return {**view(p, d), "dropped": dropped}

    @router.put("/dashboards/mine/{dash_id}")
    async def put_mine(body: DashboardPut, p: CurrentPrincipal, dash_id: str = PersonalId) -> dict[str, Any]:
        person(p)
        current = lookup(p, dash_id)
        try:
            d = store.update(hub, current, title=body.title, icon=body.icon, description=body.description,
                             widgets=body.widgets, base_version=body.base_version, actor=p.actor, role=p.role,
                             based_on_version=body.based_on_version)
        except store.DashboardError as exc:
            raise failed(p, exc) from exc
        return view(p, d)

    @router.delete("/dashboards/mine/{dash_id}")
    async def delete_mine(p: CurrentPrincipal, dash_id: str = PersonalId) -> dict[str, Any]:
        user_id = person(p)
        store.delete(hub, lookup(p, dash_id))
        prefs = store.prefs(hub, user_id)
        if dash_id in prefs.order or prefs.home == dash_id:
            store.put_prefs(hub, user_id, prefs.model_copy(update={
                "order": [i for i in prefs.order if i != dash_id], "home": None if prefs.home == dash_id else prefs.home}))
        return {"ok": True}

    @router.put("/dashboards/prefs")
    async def put_prefs(body: PrefsPut, p: CurrentPrincipal) -> dict[str, Any]:
        user_id = person(p)
        shared_ids = {d.id for d in store.shared(hub)}
        visible = shared_ids | {d.id for d in store.personal(hub, user_id)}
        value = DashboardPrefs(order=[i for i in body.order if i in visible],
                               hidden=[i for i in body.hidden if i in shared_ids],
                               home=body.home if body.home in visible else None)
        try:
            return store.put_prefs(hub, user_id, value, body.base_version).model_dump()
        except store.DashboardError as exc:
            raise failed(p, exc) from exc

    # -- shared dashboards and the default (administrators) ------------------------------

    @router.post("/dashboards/shared", status_code=201)
    async def create_shared(body: DashboardCreate, p: CurrentPrincipal) -> dict[str, Any]:
        widgets, dropped, _, template = source(p, body.from_)
        try:
            d = store.create(hub, scope="shared", owner_id=None, title=body.title, icon=body.icon,
                             description=body.description, widgets=widgets, actor=p.actor, template=template)
        except store.DashboardError as exc:
            raise failed(p, exc) from exc
        hub.activity(p.actor, "info", f"Created the shared dashboard {d.title}", dashboard_id=d.id)
        publish(d, p.actor)
        return {**view(p, d), "dropped": dropped}

    @router.put("/dashboards/shared/{dash_id}")
    async def put_shared(body: DashboardPut, p: CurrentPrincipal, dash_id: str = SharedId) -> dict[str, Any]:
        current = lookup(p, dash_id)
        try:
            d = store.update(hub, current, title=body.title, icon=body.icon, description=body.description,
                             widgets=body.widgets, base_version=body.base_version, actor=p.actor, role=p.role)
        except store.DashboardError as exc:
            raise failed(p, exc) from exc
        hub.activity(p.actor, "info", f"Published the shared dashboard {d.title}", dashboard_id=d.id, version=d.version)
        publish(d, p.actor)
        return view(p, d)

    @router.delete("/dashboards/shared/{dash_id}")
    async def delete_shared(p: CurrentPrincipal, dash_id: str = SharedId) -> dict[str, Any]:
        d = lookup(p, dash_id)
        if store.settings(hub).default_id == d.id:
            raise refuse(409, "is_default", "This is the default dashboard: make another one the default first")
        store.delete(hub, d)
        hub.activity(p.actor, "info", f"Deleted the shared dashboard {d.title}", dashboard_id=d.id)
        publish(d, p.actor, removed=True)
        return {"ok": True}

    @router.put("/dashboards/default")
    async def set_default(body: DefaultPut, p: CurrentPrincipal) -> dict[str, Any]:
        d = lookup(p, body.dashboard_id)
        settings = store.put_settings(hub, store.settings(hub).model_copy(update={"default_id": d.id}))
        hub.activity(p.actor, "info", f"Made {d.title} the default dashboard", dashboard_id=d.id)
        hub.bus.publish("dashboard_settings", {"version": settings.version})
        return settings_view(settings)

    # -- one dashboard and its data (declared after the literal paths above) -------------

    @router.get("/dashboards/{dash_id}")
    async def get_dashboard(p: CurrentPrincipal, dash_id: str = AnyId) -> dict[str, Any]:
        return view(p, lookup(p, dash_id))

    @router.get("/dashboards/{dash_id}/data")
    async def dashboard_data(p: CurrentPrincipal, dash_id: str = AnyId,
                             widgets: str | None = Query(None, max_length=600)) -> dict[str, Any]:
        wanted = [x.strip() for x in (widgets or "").split(",") if x.strip()]
        if len(wanted) > LIMITS["widgets_per_request"]:
            raise refuse(422, "too_many", f"At most {LIMITS['widgets_per_request']} widgets per request")
        d = lookup(p, dash_id)
        chosen = [w for w in d.widgets if not wanted or w.id in wanted]
        results = await resolve_many(hub, cache, [(w.id, w.type, w.config) for w in chosen], p.role)
        return {"generated_at": time.time(), "widgets": results}
