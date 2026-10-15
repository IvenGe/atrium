"""Home dashboards, stage D1 (round4-dashboard-spec.md 5, 7, 8, 13): personal and shared dashboards, the layout and
widget rules, the self-service policy (people only, never another person's dashboards), widget data with its shared
cache, the first-start migration with the Overview template, and what widget data never carries."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import re
import time
from pathlib import Path
from typing import Any

import pytest
from conftest import make_settings
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict
from test_fabric import TOKEN, FakeInventory, FakeScanner, Remote, add_tool, connect
from llm_fakes import use_claude

from hub import connectors, guardrails, llm_providers
from hub.app import create_app
from hub.bus import Bus
from hub.dashboards import cache as cache_module
from hub.dashboards import layout, metrics, registry, store, templates
from hub.dashboards import resolve as resolve_module
from hub.dashboards.cache import WidgetCache
from hub.integration import connections
from hub.models import Asset, Vulnerability
from hub.store import Store

FIXTURES = json.loads((Path(__file__).parent / "data" / "dashboard_layouts.json").read_text())
HREF = re.compile(r"^#/[A-Za-z0-9/_\-.:%?=&,]{0,200}$")
FORBIDDEN_KEYS = {"api_key", "password", "secret", "token", "client_secret", "webhook_url", "env", "config", "secrets",
                  "content", "payload", "facts", "data"}
WEBHOOK = "https://hooks.example.com/in?token=dash-hook-secret-31c9"
ACTIVITY_SECRET = "activity-data-secret-77f0"
PAYLOAD_SECRET = "approval-payload-secret-5b2e"
PROVIDER_KEY = "sk-dash-provider-key-9e44"
OVERVIEW_KEYS = {"tools", "running", "suite_score", "agents", "agents_working", "approvals_pending", "assets",
                 "compliance_score", "risks_open", "vulnerabilities_open", "vulnerabilities_overdue", "flows_enabled",
                 "people", "leavers", "extensions", "extension_domains", "restart_required", "llm", "autonomy"}


# -- helpers ------------------------------------------------------------------------------------


def widget(type_: str, config: dict[str, Any], x: int = 0, y: int = 0, w: int | None = None, h: int | None = None,
           wid: str = "w_00000001", title: str | None = None) -> dict[str, Any]:
    t = registry.REGISTRY[type_] if type_ in registry.REGISTRY else None
    return {"id": wid, "type": type_, "x": x, "y": y, "w": w or (t.size_default[0] if t else 3),
            "h": h or (t.size_default[1] if t else 1), "title": title, "config": config}


def stored(d: dict[str, Any]) -> list[dict[str, Any]]:
    """The widgets of a dashboard view as a PUT sends them back."""
    return [{k: w[k] for k in ("id", "type", "x", "y", "w", "h", "title", "config")} for w in d["widgets"]]


def create(c: TestClient, title: str = "Mine", origin: str | None = None, scope: str = "mine") -> dict[str, Any]:
    body: dict[str, Any] = {"title": title}
    if origin:
        body["from"] = origin
    response = c.post(f"/api/dashboards/{scope}", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def put(c: TestClient, d: dict[str, Any], widgets: list[dict[str, Any]], version: int | None = None,
        title: str | None = None):
    scope = "mine" if d["scope"] == "personal" else "shared"
    return c.put(f"/api/dashboards/{scope}/{d['id']}", json={
        "title": title or d["title"], "icon": d["icon"], "description": d["description"], "widgets": widgets,
        "base_version": d["version"] if version is None else version})


def saved(c: TestClient, d: dict[str, Any], widgets: list[dict[str, Any]]) -> dict[str, Any]:
    response = put(c, d, widgets)
    assert response.status_code == 200, response.text
    return response.json()


def data(c: TestClient, d: dict[str, Any]) -> dict[str, dict[str, Any]]:
    response = c.get(f"/api/dashboards/{d['id']}/data")
    assert response.status_code == 200, response.text
    return response.json()["widgets"]


def overview_dashboard(c: TestClient) -> dict[str, Any]:
    listing = c.get("/api/dashboards").json()
    return c.get(f"/api/dashboards/{listing['default_id']}").json()


def drain(queue: asyncio.Queue) -> list[dict[str, Any]]:
    out = []
    while not queue.empty():
        out.append(queue.get_nowait())
    return out


def walk(value: Any, path: str = "$"):
    if isinstance(value, dict):
        for k, v in value.items():
            yield path, k, v
            yield from walk(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")


class Empty(BaseModel):
    model_config = ConfigDict(extra="forbid")


@pytest.fixture
def admin_type(monkeypatch) -> registry.WidgetType:
    """A widget only administrators may see, with an event of its own (the D4 hub_accounts widget is one too)."""
    t = registry.WidgetType("test_admin_stats", "Admin stats", "Test only.", "settings", Empty,
                            lambda ctx, cfg: {"n": 1}, (2, 1), (3, 1), (4, 2), min_role="admin", events=("test_admin",))
    monkeypatch.setitem(registry.REGISTRY, t.key, t)
    return t


@pytest.fixture
def counted(monkeypatch) -> list[float]:
    """A cached widget type that records each time its resolver runs; it depends on the event "test_event"."""
    calls: list[float] = []

    def resolve(ctx, cfg):
        calls.append(time.time())
        return {"n": len(calls)}

    t = registry.WidgetType("test_counted", "Counted", "Test only.", "notes", Empty, resolve, (2, 1), (3, 1), (4, 2),
                            events=("test_event",), ttl=30)
    monkeypatch.setitem(registry.REGISTRY, t.key, t)
    return calls


@pytest.fixture
def remote(client, monkeypatch) -> Remote:
    state = Remote()
    for cls in (FakeInventory, FakeScanner):
        monkeypatch.setattr(cls, "remote", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    return state


# -- layout math and templates --------------------------------------------------------------------


def test_layout_port_matches_the_shared_fixtures():
    for case in FIXTURES["collides"]:
        assert layout.collides(case["a"], case["b"]) is case["expected"], case
    for case in FIXTURES["sortReading"]:
        assert [i["id"] for i in layout.sort_reading(case["items"])] == case["expected"]
    for case in FIXTURES["compact"]:
        assert layout.compact(case["items"]) == case["expected"], case["name"]
    for case in FIXTURES["firstFit"]:
        spot = layout.first_fit(case["items"], case["w"], case["h"], FIXTURES["cols"], FIXTURES["max_rows"])
        assert (list(spot) if spot else None) == case["expected"], case["name"]
    for case in FIXTURES["place"]:
        spots = layout.place([tuple(s) for s in case["sizes"]], FIXTURES["cols"], FIXTURES["max_rows"])
        assert [list(s) if s else None for s in spots] == case["expected"], case["name"]
    for case in FIXTURES["validate"]:
        assert layout.validate(case["items"], FIXTURES["cols"], FIXTURES["max_rows"]) == case["expected"], case["name"]


def test_layout_functions_never_change_their_arguments():
    items = [{"id": "a", "x": 0, "y": 3, "w": 4, "h": 2}, {"id": "b", "x": 6, "y": 5, "w": 3, "h": 1}]
    before = json.dumps(items)
    layout.compact(items)
    layout.validate(items)
    layout.first_fit(items, 3, 1)
    assert json.dumps(items) == before


def test_fresh_hub_creates_the_shared_overview_once(tmp_path):
    for _ in range(2):  # start the hub twice on the same data directory
        with TestClient(create_app(make_settings(tmp_path)), headers={"X-Hub-Request": "1"}) as c:
            hub = c.app.state.hub
            shared = store.shared(hub)
            assert [d.title for d in shared] == ["Overview"]
            assert store.settings(hub).default_id == shared[0].id
            assert shared[0].updated_by == "system" and shared[0].template == "overview"
            assert layout.validate([w.model_dump() for w in shared[0].widgets]) == []
            created = [e for e in hub.store.tail("activity", 500) if e["text"] == "Created the shared Overview dashboard"]
            assert len(created) == 1


def test_no_overview_when_shared_dashboards_exist_already(tmp_path):
    """The migration runs only on a hub that never had dashboards (an admin who deleted Overview keeps it deleted)."""
    with TestClient(create_app(make_settings(tmp_path))) as c:
        hub = c.app.state.hub
        hub.store.delete("settings", store.SETTINGS_ID)  # settings gone, but a shared dashboard is still there
        templates.migrate(hub)
        assert len(store.shared(hub)) == 1


def test_overview_reproduces_the_home_tiles_and_cards(client):
    hub = client.app.state.hub
    hub.save("vulnerabilities", Vulnerability(id="v_1", title="Old", severity="high", due_at=time.time() - 60),
             "vulnerability")
    d = overview_dashboard(client)
    assert d["is_default"] and d["scope"] == "shared" and d["title"] == "Overview" and d["hidden_widgets"] == 0
    cells = [(w["type"], w["config"].get("metric"), w["x"], w["y"], w["w"], w["h"], w["title"]) for w in d["widgets"]]
    assert cells == [
        ("metric", "tools", 0, 0, 3, 1, None), ("metric", "agents", 3, 0, 3, 1, None),
        ("metric", "approvals_pending", 6, 0, 3, 1, None), ("metric", "assets", 9, 0, 3, 1, None),
        ("metric", "people", 0, 1, 4, 1, None), ("metric", "vulnerabilities_open", 4, 1, 4, 1, None),
        ("metric", "compliance_score", 8, 1, 4, 1, None),
        ("tool_health", None, 0, 2, 7, 5, "Apps"), ("agent_activity", None, 7, 2, 5, 5, "Live agent activity")]
    results = data(client, d)
    ov = client.get("/api/overview").json()
    tiles = {r["data"]["key"]: r["data"] for r in results.values() if r["data"] and "key" in r["data"]}
    # the labels, subtexts and links of the Home page before dashboards (hub/web/js/views/home.js)
    assert {k: (t["label"], t["icon"], t["href"]) for k, t in tiles.items()} == {
        "tools": ("Apps integrated", "grid", "#/tools"), "agents": ("Agents", "bot", "#/agents"),
        "approvals_pending": ("Awaiting approval", "checkCircle", "#/approvals"),
        "assets": ("Assets", "box", "#/assets"), "people": ("People", "contact", "#/people"),
        "vulnerabilities_open": ("Vulnerabilities", "bug", "#/vulnerabilities"),
        "compliance_score": ("Compliance", "shield", "#/compliance")}
    assert tiles["tools"]["sub"] == "import your first tool"
    assert tiles["agents"]["sub"] == f"{ov['agents_working']} working now"
    assert tiles["approvals_pending"]["sub"] == "agent commands & patches"
    assert tiles["assets"]["sub"] == "in the register" and tiles["people"]["sub"] == "in the directory"
    assert tiles["vulnerabilities_open"]["sub"] == "1 past their deadline"
    assert tiles["compliance_score"]["sub"] == f"{ov['risks_open']} open risks" and tiles["compliance_score"]["unit"] == "%"
    for key in ("tools", "agents", "approvals_pending", "assets", "people", "vulnerabilities_open", "compliance_score"):
        assert tiles[key]["value"] == ov[key], key
    cards = {r["data"].get("href"): r for r in results.values() if r["data"] and "key" not in r["data"]}
    assert cards["#/tools"]["status"] == "empty" and cards["#/tools"]["hint"]["min_role"] == "operator"
    assert cards["#/agents"]["status"] == "ok" and cards["#/agents"]["data"]["items"]


def test_overview_response_is_unchanged(client):
    ov = client.get("/api/overview").json()
    assert set(ov) == OVERVIEW_KEYS


def test_templates_offered_and_built_for_a_role(client):
    hub = client.app.state.hub
    # settings_ai is offered since the D4 settings widgets exist
    assert [t.key for t in templates.available()] == ["overview", "security", "compliance", "it_people", "settings_ai"]
    widgets, dropped = templates.build(hub, "security", "viewer")
    assert dropped == 0 and [w.config.get("metric") for w in widgets][:4] == [
        "vulnerabilities_open", "vulnerabilities_overdue", "drift_open", "approvals_pending"]
    assert [w.type for w in widgets][4:] == ["vuln_sla", "domain_count", "network_overview", "approvals_queue"]
    assert layout.validate([w.model_dump() for w in widgets]) == []
    for t in templates.available():  # every entry whose type exists fits it and is built (catches drift with stages)
        registered = [e for e in templates.entries(hub, t) if registry.get(e.type) is not None]
        for e in registered:
            registry.REGISTRY[e.type].check(hub, registry.REGISTRY[e.type].parse(e.config))
        built, dropped = templates.build(hub, t.key, "viewer")
        assert dropped == 0 and len(built) == len(registered), t.key
        assert layout.validate([w.model_dump() for w in built]) == [], t.key


# -- personal dashboards -------------------------------------------------------------------------


@pytest.mark.parametrize("role", ["viewer", "operator", "admin"])
def test_personal_dashboards_for_every_role(client, sign_in, role):
    c = sign_in(role)
    d = create(c, "Work")
    assert d["scope"] == "personal" and d["version"] == 1 and d["widgets"] == [] and d["editable"]
    assert re.fullmatch(r"p_[0-9a-f]{10}", d["id"])
    listing = c.get("/api/dashboards").json()
    assert {x["id"] for x in listing["dashboards"]} == {d["id"], listing["default_id"]}
    note = widget("note", {"text": "Ship **it**"})
    updated = saved(c, d, [note])
    assert updated["version"] == 2 and updated["widgets"][0]["available"] and updated["widgets"][0]["default_title"] == "Note"
    assert data(c, updated)["w_00000001"]["data"] == {"text": "Ship **it**"}
    assert c.delete(f"/api/dashboards/mine/{d['id']}").json() == {"ok": True}
    assert c.get(f"/api/dashboards/{d['id']}").status_code == 404


def test_copies_of_templates_and_shared_dashboards(client, sign_in):
    viewer = sign_in("viewer")
    from_template = create(viewer, "Ops", "template:overview")
    assert from_template["template"] == "overview" and from_template["dropped"] == 0
    assert len(from_template["widgets"]) == 9 and from_template["based_on"] is None
    shared = overview_dashboard(viewer)
    copy = create(viewer, "My overview", shared["id"])
    assert copy["based_on"] == shared["id"] and copy["based_on_version"] == shared["version"]
    assert [w["id"] for w in copy["widgets"]] == [w["id"] for w in shared["widgets"]]
    copy_of_copy = create(viewer, "Again", copy["id"])
    assert copy_of_copy["based_on"] == shared["id"]  # it still resets to the shared version it came from
    assert viewer.post("/api/dashboards/mine", json={"title": "x", "from": "template:nope"}).status_code == 422
    assert viewer.post("/api/dashboards/mine", json={"title": "x", "from": "p_0000000000"}).status_code == 404


def test_api_tokens_have_no_personal_dashboards(client, browser):
    viewer_token = client.post("/api/tokens", json={"name": "wall", "role": "viewer"}).json()["token"]
    integration = client.post("/api/tokens", json={"name": "ci", "role": "integration"}).json()["token"]
    mine = create(client, "Admin's")
    token = browser(headers={"Authorization": f"Bearer {viewer_token}"})
    for method, path, body in (("POST", "/api/dashboards/mine", {"title": "x"}),
                               ("PUT", f"/api/dashboards/mine/{mine['id']}", {"title": "x", "widgets": [],
                                                                              "base_version": 1}),
                               ("DELETE", f"/api/dashboards/mine/{mine['id']}", None),
                               ("PUT", "/api/dashboards/prefs", {"order": []})):
        response = token.request(method, path, json=body)
        assert response.status_code == 403 and response.json()["detail"]["code"] == "person_required", (method, path)
    listing = token.get("/api/dashboards").json()
    assert all(d["scope"] == "shared" for d in listing["dashboards"]) and listing["prefs"]["order"] == []
    assert token.get(f"/api/dashboards/{mine['id']}").status_code == 404
    assert token.get(f"/api/dashboards/{listing['default_id']}/data").status_code == 200
    ci = browser(headers={"Authorization": f"Bearer {integration}"})
    response = ci.post("/api/dashboards/mine", json={"title": "x"})
    assert response.status_code == 403 and response.json() == {"detail": "Integration tokens can only publish events."}


def test_nobody_reaches_another_persons_dashboard(client, sign_in):
    alice, bob = sign_in("operator"), sign_in("admin")
    d = saved(alice, create(alice, "Private"), [widget("note", {"text": "alice only"})])
    for who in (bob, client):  # another operator-or-admin, and the administrator
        assert who.get(f"/api/dashboards/{d['id']}").status_code == 404
        assert who.get(f"/api/dashboards/{d['id']}/data").status_code == 404
        assert put(who, d, []).status_code == 404
        assert who.delete(f"/api/dashboards/mine/{d['id']}").status_code == 404
        assert d["id"] not in {x["id"] for x in who.get("/api/dashboards").json()["dashboards"]}
    assert alice.get(f"/api/dashboards/{d['id']}").json()["widgets"][0]["config"] == {"text": "alice only"}


def test_personal_changes_are_never_published(client, sign_in):
    hub = client.app.state.hub
    viewer = sign_in("viewer")
    queue = hub.bus.subscribe()
    try:
        d = create(viewer, "Secret plans")
        d = saved(viewer, d, [widget("note", {"text": "quiet"})])
        viewer.put("/api/dashboards/prefs", json={"order": [d["id"]], "home": d["id"]})
        viewer.delete(f"/api/dashboards/mine/{d['id']}")
        events = drain(queue)
    finally:
        hub.bus.unsubscribe(queue)
    assert not [e for e in events if e["type"].startswith("dashboard")]
    assert "Secret plans" not in json.dumps(events, default=str) and "quiet" not in json.dumps(events, default=str)


def test_versions_conflict_and_only_grow(client):
    d = create(client)
    first = saved(client, d, [widget("note", {"text": "one"})])
    stale = put(client, d, [widget("note", {"text": "two"})])  # still at version 1
    assert stale.status_code == 409
    detail = stale.json()["detail"]
    assert detail["code"] == "version_conflict" and detail["dashboard"]["version"] == 2
    assert detail["dashboard"]["widgets"][0]["config"] == {"text": "one"}
    second = saved(client, first, [widget("note", {"text": "two"})])
    assert (first["version"], second["version"]) == (2, 3)


# -- validation ------------------------------------------------------------------------------------


@pytest.mark.parametrize("widgets,status,code,secret", [
    ([widget("note", {}, 0, 0, 4, 2), widget("note", {}, 2, 1, 4, 2, "w_00000002")], 422, "invalid_layout", None),
    ([widget("note", {}, 10, 0, 3, 1)], 422, "invalid_layout", None),
    ([widget("note", {}), widget("note", {}, 6, 0)], 422, "invalid_layout", None),
    ([widget("metric", {"metric": "tools"}, w=1)], 422, "invalid_widget", None),
    ([widget("metric", {"metric": "tools"}, w=5)], 422, "invalid_widget", None),
    ([widget("no_such_type", {})], 422, "invalid_widget", None),
    ([widget("metric", {"metric": "tools", "sql": "select-everything-9d1"})], 422, "invalid_widget", "select-everything"),
    ([widget("metric", {"metric": "made_up_metric"})], 422, "invalid_widget", "made_up_metric"),
    ([widget("agent_activity", {"scope": "robots-7f3a"})], 422, "invalid_widget", "robots-7f3a"),
    ([widget("approvals_queue", {"kinds": ["coffee"]})], 422, "invalid_widget", "coffee"),
    ([widget("links", {"items": [{"label": "x", "target": "javascript:alert(1)"}]})], 422, "invalid_widget", "alert"),
    ([widget("links", {"items": [{"label": "x", "target": "https://evil.example"}]})], 422, "invalid_widget", "evil"),
    ([widget("tool_overview", {"tool_id": "ghost-tool-4e1"})], 422, "invalid_widget", "ghost-tool-4e1"),
    ([widget("tool_health", {"tools": ["ghost-tool-4e1"]})], 422, "invalid_widget", "ghost-tool-4e1"),
    ([widget("agents_status", {"team": "nobody-team-8a"})], 422, "invalid_widget", None),
    ([widget("note", {"text": "x" * 2001})], 422, "invalid_widget", None),
])
def test_widget_and_layout_validation(client, widgets, status, code, secret):
    d = create(client)
    response = put(client, d, widgets)
    assert response.status_code == status, response.text
    detail = response.json()["detail"]
    assert detail["code"] == code and detail["widget_id"].startswith("w_")
    if secret:
        assert secret not in response.text  # a config value is never echoed back
    assert client.get(f"/api/dashboards/{d['id']}").json()["version"] == 1  # nothing was stored


def test_a_retyped_widget_must_fit_its_new_type(client):
    d = saved(client, create(client), [widget("note", {"text": "big"}, 0, 0, 12, 8)])
    retyped = stored(d)
    retyped[0].update(type="metric", config={"metric": "tools"}, title=None)  # same id and size, a 4x2 type at most
    response = put(client, d, retyped)
    assert response.status_code == 422 and response.json()["detail"]["code"] == "invalid_widget"


def test_bounds_on_titles_counts_and_sizes(client):
    d = create(client)
    assert put(client, d, [widget("note", {}, title="bad\x07title")]).status_code == 422
    assert put(client, d, [], title="two\nlines").status_code == 422
    assert client.post("/api/dashboards/mine", json={"title": "x", "icon": "<svg>"}).status_code == 422
    assert client.post("/api/dashboards/mine", json={"title": "x", "owner_id": "u_someone"}).status_code == 422
    many = [widget("metric", {"metric": "tools"}, (i % 6) * 2, i // 6, 2, 1, f"w_{i:08d}") for i in range(41)]
    response = put(client, d, many)
    assert response.status_code == 422 and response.json()["detail"]["code"] == "invalid_layout"
    assert saved(client, d, many[:40])["version"] == 2
    d = client.get(f"/api/dashboards/{d['id']}").json()
    big = [widget("note", {"text": "y" * 1990}, (i % 3) * 4, (i // 3) * 2, 4, 2, f"w_{i:08d}") for i in range(40)]
    response = put(client, d, big)
    assert response.status_code == 413 and response.json()["detail"]["code"] == "too_large"
    count = len(store.personal(client.app.state.hub, client.get("/api/auth/me").json()["user"]["id"]))
    for n in range(count, 20):
        create(client, f"Board {n}")
    response = client.post("/api/dashboards/mine", json={"title": "One too many"})
    assert response.status_code == 409 and response.json()["detail"]["code"] == "limit"


def test_unavailable_widget_is_kept_until_it_changes(client):
    add_tool(client, "crm", "CRM")
    d = saved(client, create(client), [widget("tool_overview", {"tool_id": "crm"}),
                                       widget("note", {"text": "n"}, 0, 3, wid="w_00000002")])
    assert data(client, d)["w_00000001"]["status"] == "ok"
    assert client.delete("/api/tools/crm").status_code == 200
    d = client.get(f"/api/dashboards/{d['id']}").json()
    assert d["widgets"][0]["available"] is False and "does not exist" in d["widgets"][0]["reason"]
    result = data(client, d)["w_00000001"]
    assert result["status"] == "unavailable" and result["message"] == "crm was removed."
    moved = stored(d)
    moved[0]["y"] = 5  # it may move (other widgets push it) ...
    d = saved(client, d, moved)
    changed = stored(d)
    changed[0]["config"] = {"tool_id": "crm2"}  # ... but not change
    response = put(client, d, changed)
    assert response.status_code == 422 and response.json()["detail"]["widget_id"] == "w_00000001"


def test_widget_roles_on_save_read_copy_and_demotion(client, sign_in, admin_type):
    viewer, operator = sign_in("viewer"), sign_in("operator")
    response = put(viewer, create(viewer), [widget(admin_type.key, {})])
    assert response.status_code == 403
    assert response.json()["detail"] == {"code": "role_required", "message": "Admin stats needs the admin role",
                                         "widget_id": "w_00000001"}
    shared = saved(client, create(client, "Team", scope="shared"),
                   [widget(admin_type.key, {}), widget("note", {"text": "hello"}, 0, 1, wid="w_00000002")])
    seen = viewer.get(f"/api/dashboards/{shared['id']}").json()
    assert [w["id"] for w in seen["widgets"]] == ["w_00000002"] and seen["hidden_widgets"] == 1
    assert "Admin stats" not in json.dumps(seen)
    summary = next(x for x in viewer.get("/api/dashboards").json()["dashboards"] if x["id"] == shared["id"])
    assert summary["widgets"] == 1 and summary["editable"] is False
    results = data(viewer, shared)
    assert results["w_00000001"]["status"] == "forbidden" and results["w_00000001"]["data"] is None
    assert results["w_00000002"]["status"] == "ok"
    copy = create(operator, "Mine", shared["id"])
    assert copy["dropped"] == 1 and [w["id"] for w in copy["widgets"]] == ["w_00000002"]
    assert saved(operator, copy, stored(copy))["version"] == 2
    # an administrator who keeps the widget on a personal dashboard and is demoted: forbidden, but still saveable
    boss = sign_in("admin", username="boss")
    mine = saved(boss, create(boss), [widget(admin_type.key, {})])
    boss_id = next(u["id"] for u in client.get("/api/users").json() if u["username"] == "boss")
    assert client.patch(f"/api/users/{boss_id}", json={"role": "viewer"}).status_code == 200
    assert data(boss, mine)["w_00000001"]["status"] == "forbidden"
    mine = boss.get(f"/api/dashboards/{mine['id']}").json()
    assert mine["widgets"][0]["min_role"] == "admin"
    assert saved(boss, mine, stored(mine))["version"] == 3


# -- shared dashboards ----------------------------------------------------------------------------


def test_shared_dashboards_are_administrators(client, sign_in):
    hub = client.app.state.hub
    viewer, operator = sign_in("viewer"), sign_in("operator")
    for who in (viewer, operator):
        assert who.post("/api/dashboards/shared", json={"title": "x"}).status_code == 403
        assert who.put("/api/dashboards/default", json={"dashboard_id": "s_0000000000"}).status_code == 403
    default_id = client.get("/api/dashboards").json()["default_id"]
    queue = hub.bus.subscribe()
    try:
        team = create(client, "Security", "template:security", scope="shared")
        assert team["editable"] and re.fullmatch(r"s_[0-9a-f]{10}", team["id"])
        assert operator.delete(f"/api/dashboards/shared/{team['id']}").status_code == 403
        assert put(operator, team, []).status_code == 403
        published = saved(client, team, stored(team)[:2])
        assert published["version"] == 2
        refused = client.delete(f"/api/dashboards/shared/{default_id}")
        assert refused.status_code == 409 and refused.json()["detail"]["code"] == "is_default"
        settings = client.put("/api/dashboards/default", json={"dashboard_id": team["id"]}).json()
        assert settings["default_id"] == team["id"] and client.get("/api/dashboards/settings").json() == settings
        assert viewer.get("/api/dashboards").json()["home_id"] == team["id"]
        assert client.delete(f"/api/dashboards/shared/{default_id}").json() == {"ok": True}
        events = drain(queue)
    finally:
        hub.bus.unsubscribe(queue)
    shared_events = [e["data"] for e in events if e["type"] == "dashboard"]
    assert shared_events == [
        {"id": team["id"], "scope": "shared", "version": 1, "updated_by": "admin", "removed": False},
        {"id": team["id"], "scope": "shared", "version": 2, "updated_by": "admin", "removed": False},
        {"id": default_id, "scope": "shared", "version": 1, "updated_by": "admin", "removed": True}]
    assert [e["data"] for e in events if e["type"] == "dashboard_settings"] == [{"version": 2}]
    texts = [e["text"] for e in hub.store.tail("activity", 100)]
    for text in ("Created the shared dashboard Security", "Published the shared dashboard Security",
                 "Made Security the default dashboard", "Deleted the shared dashboard Overview"):
        assert text in texts


def test_personal_copy_knows_when_the_shared_dashboard_is_newer(client, sign_in):
    viewer = sign_in("viewer")
    shared = overview_dashboard(viewer)
    assert shared["editable"] is False and viewer.get("/api/dashboards").json()["can_edit_shared"] is False
    copy = create(viewer, "Mine", shared["id"])
    assert copy["based_on_newer"] is False
    saved(client, client.get(f"/api/dashboards/{shared['id']}").json(), stored(shared)[:3])
    summary = next(x for x in viewer.get("/api/dashboards").json()["dashboards"] if x["id"] == copy["id"])
    assert summary["based_on_newer"] is True
    # "Reset to the shared version": the shared widgets, and the version they came from
    latest = viewer.get(f"/api/dashboards/{shared['id']}").json()
    too_new = viewer.put(f"/api/dashboards/mine/{copy['id']}", json={
        "title": copy["title"], "widgets": stored(latest), "base_version": copy["version"],
        "based_on_version": latest["version"] + 1})
    assert too_new.status_code == 422 and too_new.json()["detail"]["code"] == "invalid"
    reset = viewer.put(f"/api/dashboards/mine/{copy['id']}", json={
        "title": copy["title"], "widgets": stored(latest), "base_version": copy["version"],
        "based_on_version": latest["version"]}).json()
    assert reset["based_on_newer"] is False and len(reset["widgets"]) == 3
    blank = create(viewer, "Blank")
    assert viewer.put(f"/api/dashboards/mine/{blank['id']}", json={
        "title": "Blank", "widgets": [], "base_version": 1, "based_on_version": 1}).status_code == 422


def test_template_widgets_for_reset(client, sign_in):
    viewer = sign_in("viewer")
    overview = viewer.get("/api/widgets/templates/overview").json()
    assert overview["key"] == "overview" and overview["dropped"] == 0 and len(overview["widgets"]) == 9
    assert layout.validate(overview["widgets"]) == []
    compliance = viewer.get("/api/widgets/templates/compliance").json()  # the D3 widgets
    assert [w["type"] for w in compliance["widgets"]] == ["compliance_overview", "controls_status", "risk_matrix",
                                                          "domain_list", "metric"]
    settings_ai = viewer.get("/api/widgets/templates/settings_ai").json()  # the D4 settings widgets
    assert [(w["type"], w["config"]) for w in settings_ai["widgets"]] == [
        ("ai_models", {"show": "all"}), ("metric", {"metric": "llm_spend_today"}), ("safety_settings", {}),
        ("tool_health", {"tools": "all", "show_offline_only": False}), ("agents_status", {"team": "all", "show_provider": True})]
    assert settings_ai["dropped"] == 0 and layout.validate(settings_ai["widgets"]) == []
    assert viewer.get("/api/widgets/templates/nope").status_code == 404


# -- preferences ------------------------------------------------------------------------------------


def test_preferences_order_hide_and_home(client, sign_in):
    viewer, other = sign_in("viewer"), sign_in("viewer")
    mine, theirs = create(viewer, "Mine"), create(other, "Theirs")
    team = create(client, "Team", scope="shared")
    overview_id = client.get("/api/dashboards").json()["default_id"]
    prefs = viewer.put("/api/dashboards/prefs", json={
        "order": [team["id"], theirs["id"], mine["id"], "s_0000000000", overview_id],
        "hidden": [overview_id, mine["id"]], "home": mine["id"]}).json()
    # another person's dashboard, an unknown one and a personal one in "hidden" are dropped
    assert prefs == {"order": [team["id"], mine["id"], overview_id], "hidden": [overview_id], "home": mine["id"],
                     "version": 1}
    listing = viewer.get("/api/dashboards").json()
    assert [d["id"] for d in listing["dashboards"]] == [team["id"], mine["id"], overview_id]
    assert listing["home_id"] == mine["id"] and [d["hidden"] for d in listing["dashboards"]] == [False, False, True]
    stale = viewer.put("/api/dashboards/prefs", json={"order": [], "base_version": 0})
    assert stale.status_code == 409 and stale.json()["detail"]["prefs"]["version"] == 1
    viewer.delete(f"/api/dashboards/mine/{mine['id']}")
    listing = viewer.get("/api/dashboards").json()
    assert listing["prefs"]["home"] is None and listing["home_id"] == team["id"]  # the default is hidden
    client.delete(f"/api/dashboards/shared/{team['id']}")
    listing = viewer.get("/api/dashboards").json()  # a deleted shared dashboard leaves the preferences lazily
    assert listing["prefs"]["order"] == [overview_id] and listing["home_id"] is None
    assert viewer.put("/api/dashboards/prefs", json={"order": ["not-an-id"]}).status_code == 422


def test_deleting_an_account_forgets_its_dashboards(client, sign_in):
    hub = client.app.state.hub
    leaver = sign_in("viewer", username="leaver")
    d = create(leaver, "Mine")
    leaver.put("/api/dashboards/prefs", json={"order": [d["id"]], "home": d["id"]})
    user_id = hub.auth.find_user("leaver").id
    assert hub.store.ids_prefix(store.COLLECTION, f"u:{user_id}:") and hub.store.get(store.PREFS, user_id)
    assert client.delete(f"/api/users/{user_id}").status_code == 200
    assert hub.store.ids_prefix(store.COLLECTION, f"u:{user_id}:") == [] and hub.store.get(store.PREFS, user_id) is None


def test_mutations_need_the_cross_site_header(client):
    d = create(client)
    response = client.put(f"/api/dashboards/mine/{d['id']}", json={"title": "x", "widgets": [], "base_version": 1},
                          headers={"X-Hub-Request": ""})
    assert response.status_code == 403 and "X-Hub-Request" in response.json()["detail"]


# -- widget data ------------------------------------------------------------------------------------


def seed(client) -> None:
    """Three tools (two connected, one with a failed connection test and a webhook URL with a token), assets and
    findings from them, a pending local command and a warning with secrets in their payloads, and an AI model server
    with an API key."""
    hub = client.app.state.hub
    created = client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "m", "api_key": PROVIDER_KEY})
    assert created.status_code in (200, 201), created.text
    add_tool(client, "inventory", "Inventory")
    add_tool(client, "scanner", "Scanner", events={"emits": [], "listens": [], "webhook_url": WEBHOOK})
    add_tool(client, "notes", "Notes <img src=x onerror=alert(1)>")
    connect(client, "inventory", "fake_inventory")
    connect(client, "scanner", "fake_scanner")
    connections.record_test(hub, "scanner", {"ok": False, "detail": f"401 with {TOKEN}"})
    for n in range(3):
        hub.save("assets", Asset(id=f"a_{n}", name=f"host-{n}", source="sync:inventory"), "asset")
    hub.save("vulnerabilities", Vulnerability(id="v_1", title="Open SSH", severity="high", source="scanner"),
             "vulnerability")
    hub.approvals.create("command", "Run uptime on the hub", "", {"target": "local", "secret": PAYLOAD_SECRET}, "user:x")
    hub.approvals.create("flow", "Pull assets from Inventory", "", {"flow_id": "fl_1"}, "supervisor")
    hub.activity("module:assets", "error", "Inventory sync failed", password=ACTIVITY_SECRET)
    hub.activity("someone", "info", "Changed a risk", detail=ACTIVITY_SECRET)


EVERY_TYPE = [
    ("metric", {"metric": "approvals_pending"}),
    ("tool_health", {"tools": "all"}),
    ("tool_health", {"tools": "all", "show_offline_only": True}),
    ("tool_overview", {"tool_id": "inventory"}),
    ("agent_activity", {"scope": "agents", "min_level": "info", "limit": 50}),
    ("agent_activity", {"scope": "people", "min_level": "info", "limit": 50}),
    ("agent_activity", {"scope": "all", "min_level": "error", "limit": 5}),
    ("agents_status", {"team": "hub", "show_provider": False}),
    ("approvals_queue", {"kinds": ["command"], "limit": 5}),
    ("note", {"text": "**Hi** <b>there</b>"}),
    ("links", {"items": [{"label": "Inventory", "target": "tool:inventory"}, {"label": "Assets", "target": "#/assets"},
                         {"label": "Filtered", "target": "#/vulnerabilities?severity=high"}]}),
    ("agents_status", {"team": "all", "show_provider": True}),
    ("ai_models", {"show": "all"}),  # stage D4: the settings widgets
    ("safety_settings", {}),
    ("hub_accounts", {}),
    ("metric", {"metric": "llm_spend_today"}),
]


def every_widget_dashboard(c: TestClient) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    widgets, y = [], 0
    for n, (type_, config) in enumerate(EVERY_TYPE):
        t = registry.REGISTRY[type_]
        widgets.append(widget(type_, config, 0, y, wid=f"w_{n:08d}"))
        y += t.size_default[1]
    d = saved(c, create(c, "Everything"), widgets)
    results = data(c, d)
    return d, {f"{EVERY_TYPE[int(k[2:])][0]}:{int(k[2:])}": v for k, v in results.items()}


def test_every_widget_type_resolves_with_its_shape(client, remote):
    seed(client)
    hub = client.app.state.hub
    d, r = every_widget_dashboard(client)
    assert all(v["status"] == "ok" for v in r.values()), {k: v["status"] for k, v in r.items()}
    pending = sum(1 for a in hub.approvals.list() if a.status == "pending")  # with the flows the planner proposed
    assert pending >= 2 and r["metric:0"]["data"]["value"] == pending and r["metric:0"]["data"]["tone"] == "warn"
    rows = {row["id"]: row for row in r["tool_health:1"]["data"]["rows"]}
    assert set(rows) == {"inventory", "scanner", "notes"} and r["tool_health:1"]["data"]["total"] == 3
    assert rows["inventory"]["connection"]["kind"] == "fake_inventory" and rows["inventory"]["href"] == "#/tools/inventory"
    assert rows["notes"]["name"] == "Notes <img src=x onerror=alert(1)>"  # data, escaped by the UI
    assert [row["id"] for row in r["tool_health:2"]["data"]["rows"]] == ["scanner"]  # its connection test failed
    overview = r["tool_overview:3"]["data"]
    assert overview["tool"]["id"] == "inventory"
    assert {d["domain"]: (d["count"], d["href"]) for d in overview["domains"]} == {"assets": (3, "#/assets")}
    agents_only = [i["actor"] for i in r["agent_activity:4"]["data"]["items"]]
    people_only = [i["actor"] for i in r["agent_activity:5"]["data"]["items"]]
    assert "module:assets" in agents_only and "someone" not in agents_only
    assert "someone" in people_only and not [a for a in people_only if a.startswith(("module:", "tool:"))]
    errors = r["agent_activity:6"]["data"]["items"]
    assert errors and all(i["level"] == "error" for i in errors) and errors[0]["text"] == "Inventory sync failed"
    assert set(errors[0]) == {"seq", "ts", "actor", "level", "text"}
    team = r["agents_status:7"]["data"]["rows"]
    assert team and all(row["team"] == "hub" and row["provider_label"] is None for row in team)
    assert {row["id"] for row in team} >= {"supervisor"} and "tool:inventory" not in {row["id"] for row in team}
    queue = r["approvals_queue:8"]["data"]
    assert queue["pending"] == 1 and queue["rows"][0]["title"] == "Run uptime on the hub"
    assert queue["rows"][0]["needs_admin"] is True and set(queue["rows"][0]) == {
        "id", "kind", "title", "requested_by", "created_at", "needs_admin"}
    assert r["note:9"]["data"] == {"text": "**Hi** <b>there</b>"}
    assert r["links:10"]["data"]["items"] == [
        {"label": "Inventory", "href": "#/portal/inventory", "icon": "external", "available": True,
         "tool_id": "inventory"},
        {"label": "Assets", "href": "#/assets", "icon": "box", "available": True, "tool_id": None},
        {"label": "Filtered", "href": "#/vulnerabilities?severity=high", "icon": "bug", "available": True,
         "tool_id": None}]
    for result in r.values():  # every link is an internal route
        for path, key, value in walk(result["data"]):
            if key in ("href", "portal_href") and value is not None:
                assert HREF.match(value), (path, value)
    hub.store.delete("tools", "inventory")
    hub.bus.publish("tool_removed", {"id": "inventory"})
    after = data(client, d)
    assert after["w_00000003"]["status"] == "unavailable"  # tool_overview of the removed tool
    assert after["w_00000010"]["data"]["items"][0] == {"label": "Inventory", "href": None, "icon": "external",
                                                       "available": False, "tool_id": "inventory"}


def test_every_metric_resolves_like_the_overview(client):
    ov = client.get("/api/overview").json()
    for key, m in metrics.METRICS.items():
        response = client.get("/api/widgets/preview", params={"type": "metric", "config": json.dumps({"metric": key})})
        result = response.json()
        assert response.status_code == 200 and result["status"] == "ok", key
        assert result["data"]["label"] == m.label and HREF.match(result["data"]["href"]) and result["events"]
        if key in ov:
            assert result["data"]["value"] == ov[key], key


def test_counts_over_projected_fields_match_the_records(client):
    """Metrics count the large collections over a few fields read inside SQLite; they agree with the parsed records."""
    hub = client.app.state.hub
    past, future = time.time() - 60, time.time() + 3600
    for n, (status, due) in enumerate([("open", past), ("in_progress", past), ("fixed", past), ("open", future),
                                       ("open", None), ("accepted", past)]):
        hub.save("vulnerabilities", Vulnerability(id=f"v_{n}", title=f"V{n}", status=status, due_at=due),
                 "vulnerability")
    for n, status in enumerate(["active", "maintenance", "retired"]):
        hub.save("assets", Asset(id=f"a_{n}", name=f"host-{n}", status=status, source="sync:inv"), "asset")
    snap = resolve_module.Snapshot(hub)
    vulns, assets = hub.all("vulnerabilities", Vulnerability), hub.all("assets", Asset)
    assert metrics.vulnerabilities_overdue(snap) == sum(v.overdue for v in vulns) == 2
    assert metrics.vulnerabilities_open(snap) == sum(v.status in ("open", "in_progress") for v in vulns) == 4
    assert metrics.assets(snap) == sum(a.status != "retired" for a in assets) == len(assets) - 1  # the hub's own too
    projected = {r["id"]: r for r in hub.store.project("assets", ("id", "status", "nope"))}
    assert [projected[f"a_{n}"] for n in range(3)] == [{"id": "a_0", "status": "active", "nope": None},
                                                       {"id": "a_1", "status": "maintenance", "nope": None},
                                                       {"id": "a_2", "status": "retired", "nope": None}]


def test_no_secrets_in_widget_data_catalog_or_previews(client, remote):
    seed(client)
    secrets = (TOKEN, WEBHOOK, "dash-hook-secret-31c9", ACTIVITY_SECRET, PAYLOAD_SECRET, PROVIDER_KEY)
    _, results = every_widget_dashboard(client)
    previews = [client.get("/api/widgets/preview", params={"type": t, "config": json.dumps(cfg)}).json()
                for t, cfg in EVERY_TYPE]
    for document in [*results.values(), *previews]:
        text = json.dumps(document)
        assert not [s for s in secrets if s in text]
        for path, key, _ in walk(document["data"]):
            assert key not in FORBIDDEN_KEYS, f"{path}.{key}"
    catalog = client.get("/api/widgets/catalog").json()
    assert not [s for s in secrets if s in json.dumps(catalog)]
    for path, key, _ in walk(catalog):
        assert key not in FORBIDDEN_KEYS or (key == "config" and path.startswith("$.suggestions[")), f"{path}.{key}"


def test_resolver_errors_are_generic_and_logged_without_values(client, monkeypatch, caplog):
    def broken(ctx, cfg):
        raise KeyError("secret-config-value-0c1d")

    t = registry.WidgetType("test_broken", "Broken", "Test only.", "notes", Empty, broken, (2, 1), (3, 1), (4, 2))
    monkeypatch.setitem(registry.REGISTRY, t.key, t)
    d = saved(client, create(client), [widget(t.key, {})])
    with caplog.at_level("WARNING", logger="hub.dashboards"):
        result = data(client, d)["w_00000001"]
    assert result["status"] == "error" and result["message"] == "Could not compute this widget."
    assert "secret-config-value" not in caplog.text and "w_00000001" in caplog.text and "test_broken" in caplog.text


def test_data_requests_are_bounded_and_ignore_unknown_ids(client):
    d = overview_dashboard(client)
    ids = ",".join(f"w_{n:08d}" for n in range(41))
    response = client.get(f"/api/dashboards/{d['id']}/data", params={"widgets": ids})
    assert response.status_code == 422 and response.json()["detail"]["code"] == "too_many"
    first = d["widgets"][0]["id"]
    response = client.get(f"/api/dashboards/{d['id']}/data", params={"widgets": f"{first},w_99999999"}).json()
    assert list(response["widgets"]) == [first]
    assert client.get("/api/dashboards/x_0000000000/data").status_code == 422


def test_preview_validates_its_config(client, sign_in, admin_type):
    def preview(c, type_, config):
        return c.get("/api/widgets/preview", params={"type": type_, "config": config})

    ok = preview(client, "agent_activity", json.dumps({"limit": 5}))
    assert ok.status_code == 200 and ok.json()["status"] == "ok" and ok.json()["refresh"] == 60
    for type_, config in (("agent_activity", "{not json"), ("agent_activity", "[1]"), ("no_such", "{}"),
                          ("note", json.dumps({"text": "x" * 4100})), ("agent_activity", json.dumps({"limit": 999}))):
        response = preview(client, type_, config)
        assert response.status_code == 422 and response.json()["detail"]["code"] == "invalid_widget", (type_, config)
        assert "999" not in response.text
    refused = preview(sign_in("operator"), admin_type.key, "{}")
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "role_required"
    assert preview(client, admin_type.key, "{}").json()["data"] == {"n": 1}


def test_catalog_for_each_role(client, sign_in, remote, admin_type):
    seed(client)
    viewer = sign_in("viewer").get("/api/widgets/catalog").json()
    admin = client.get("/api/widgets/catalog").json()
    assert admin_type.key in {t["key"] for t in admin["types"]} and admin_type.key not in {t["key"] for t in viewer["types"]}
    metric = next(t for t in viewer["types"] if t["key"] == "metric")
    assert metric["size"] == {"min": {"w": 2, "h": 1}, "default": {"w": 3, "h": 1}, "max": {"w": 4, "h": 2}}
    assert metric["fields"] == [{"name": "metric", "label": "Metric", "kind": "select", "options": "metrics"}]
    assert {m["key"] for m in viewer["metrics"]} == set(metrics.METRICS)
    assert [t["key"] for t in viewer["templates"]] == ["overview", "security", "compliance", "it_people", "settings_ai"]
    assert viewer["limits"]["widgets"] == 40 and viewer["embed"] == {"enabled": False, "tools": []}
    tools = {t["id"]: t for t in viewer["tools"]}
    assert tools["inventory"]["reads"] == ["assets"] and tools["notes"]["reads"] == []
    groups = {s["group"] for s in viewer["suggestions"]}
    assert {"tool:inventory", "tool:scanner", "tool:notes", "hub"} <= groups
    assert next(s for s in viewer["suggestions"] if s["group"] == "tool:inventory") == {
        "id": next(s["id"] for s in viewer["suggestions"] if s["group"] == "tool:inventory"), "group": "tool:inventory",
        "title": "Inventory: overview", "description": "Its status, the data it brings and its data flows",
        "type": "tool_overview", "config": {"tool_id": "inventory"}, "size": [4, 3]}
    assert all(re.fullmatch(r"sg:[0-9a-f]{12}", s["id"]) for s in viewer["suggestions"])


def test_catalog_suggestions_are_collected_again_when_tools_change(client, sign_in, monkeypatch, admin_type):
    calls: list[int] = []

    def counting(hub):
        calls.append(1)
        return [registry.suggestion("hub", admin_type.key, {}, "Admin stats"),
                registry.suggestion("hub", "note", {"text": "hi"}, "Hello note")]

    monkeypatch.setattr(registry, "SUGGESTERS", [counting])
    viewer = sign_in("viewer")
    titles = lambda c: [s["title"] for s in c.get("/api/widgets/catalog").json()["suggestions"]]  # noqa: E731
    assert titles(client) == ["Admin stats", "Hello note"] and titles(viewer) == ["Hello note"]  # filtered per role
    assert len(calls) == 1  # one collection serves both
    client.app.state.hub.bus.publish("risk", {})
    titles(viewer)
    assert len(calls) == 1
    add_tool(client, "crm", "CRM")  # a "tool" event
    titles(viewer)
    assert len(calls) == 2


# -- the cache ----------------------------------------------------------------------------------------


def test_cache_reuses_results_until_an_event_or_expiry(client, counted, monkeypatch):
    hub = client.app.state.hub
    d = saved(client, create(client), [widget("test_counted", {})])
    first = data(client, d)["w_00000001"]
    assert data(client, d)["w_00000001"] == first and len(counted) == 1
    assert first["events"] == ["test_event"] and first["stale_after"] == pytest.approx(first["generated_at"] + 60)
    hub.bus.publish("risk", {"id": "r_1"})  # an event it does not depend on
    data(client, d)
    assert len(counted) == 1
    hub.bus.publish("test_event", {})
    assert data(client, d)["w_00000001"]["data"] == {"n": 2} and len(counted) == 2
    later = time.time() + 31  # past the type's ttl
    monkeypatch.setattr(cache_module, "time", type("Clock", (), {"time": staticmethod(lambda: later)}))
    data(client, d)
    assert len(counted) == 3


def test_one_cached_result_serves_viewers_and_administrators(client, sign_in, counted):
    viewer = sign_in("viewer")
    mine = saved(viewer, create(viewer), [widget("test_counted", {}, wid="w_aaaaaaaa")])
    theirs = saved(client, create(client), [widget("test_counted", {}, 3, 0, wid="w_bbbbbbbb")])
    a, b = data(viewer, mine)["w_aaaaaaaa"], data(client, theirs)["w_bbbbbbbb"]
    assert a == b and len(counted) == 1  # same bytes, computed once: results never depend on who asks


def test_agents_widget_is_computed_once_for_viewers_and_administrators(client, sign_in, monkeypatch):
    """A real resolver: the same config asked by a viewer and an administrator is one cache entry with the same bytes
    (agents_status shows statuses and models, nothing that depends on who asks)."""
    calls: list[str] = []
    original = registry.REGISTRY["agents_status"]

    def counting(ctx, cfg):
        calls.append(cfg.team)
        return original.resolve(ctx, cfg)

    monkeypatch.setitem(registry.REGISTRY, "agents_status", dataclasses.replace(original, resolve=counting))
    viewer = sign_in("viewer")
    config = {"team": "all", "show_provider": True}
    mine = saved(viewer, create(viewer), [widget("agents_status", config, wid="w_aaaaaaaa")])
    theirs = saved(client, create(client), [widget("agents_status", config, 4, 0, wid="w_bbbbbbbb")])
    a, b = data(viewer, mine)["w_aaaaaaaa"], data(client, theirs)["w_bbbbbbbb"]
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True) and calls == ["all"]
    assert a["status"] == "ok" and {row["id"] for row in a["data"]["rows"]} >= {"supervisor"}
    assert "llm_provider" in a["events"] and "agent" in a["events"]  # a provider change refreshes the models shown


def test_fresh_previews_recompute_at_most_every_five_seconds(client, counted):
    for _ in range(3):
        client.get("/api/widgets/preview", params={"type": "test_counted", "config": "{}", "fresh": "1"})
    assert len(counted) == 1


def test_cache_computes_once_for_concurrent_requests_and_evicts_old_entries():
    bus = Bus(Store(":memory:"))
    cache = WidgetCache(bus, size=2)
    calls: list[str] = []

    def compute(name: str):
        def run():
            calls.append(name)
            return {"status": "ok", "data": {"name": name}}
        return run

    async def main():
        await asyncio.gather(*(cache.get(("t", "a"), ("e",), 30, compute("a")) for _ in range(10)))
        await cache.get(("t", "b"), ("e",), 30, compute("b"))
        await cache.get(("t", "c"), ("e",), 30, compute("c"))  # evicts "a", the least recently used
        await cache.get(("t", "a"), ("e",), 30, compute("a"))
        failed = await cache.get(("t", "x"), ("e",), 30, lambda: {"status": "error"})
        assert failed == {"status": "error"} and ("t", "x") not in cache._entries  # errors are not cached

    asyncio.run(main())
    assert calls == ["a", "b", "c", "a"] and len(cache) == 2


def test_bus_counts_publishes_per_event_type():
    bus = Bus(Store(":memory:"))
    bus.publish("tool", {})
    bus.publish("tool", {})
    bus.publish("risk", {})
    assert bus.generations(("tool", "risk", "never")) == (2, 1, 0)


# -- the settings event ---------------------------------------------------------------------------------


def test_settings_changes_publish_key_names_only(client):
    hub = client.app.state.hub
    key = next(k for k, g in guardrails.REGISTRY.items() if g.kind == "bool")
    queue = hub.bus.subscribe()
    try:
        assert client.patch("/api/settings", json={"autonomy": "manual", "vuln_sla_days": {"critical": 5}}).status_code == 200
        assert client.patch("/api/settings/guardrails", json={key: guardrails.REGISTRY[key].default}).status_code == 200
        assert client.patch("/api/settings", json={"autonomy": "bogus"}).status_code == 422
        events = [e["data"] for e in drain(queue) if e["type"] == "settings"]
    finally:
        hub.bus.unsubscribe(queue)
    assert events == [{"keys": ["autonomy", "vuln_sla_days"]}, {"keys": ["guardrails"]}]


# -- stage D3: domains, record widgets, compliance/network/people widgets, suggestions, declared widgets ---------


class FakeGrcRead(FakeInventory):
    kind, title = "fake_grc_read", "Fake GRC"
    capabilities = {"risks": {"read"}}


class FakeDirectory(FakeInventory):
    kind, title = "fake_directory", "Fake Directory"
    capabilities = {"people": {"read"}, "accounts": {"read"}}


class FakeSiem(FakeInventory):
    kind, title = "fake_siem", "Fake SIEM"
    capabilities = {"x:alerts": {"read"}}


ALERT_FIELDS = [{"name": "title", "label": "Title"}, {"name": "severity", "label": "Severity", "type": "severity"},
                {"name": "status", "label": "Status", "type": "enum", "values": ["open", "closed"]},
                {"name": "host", "label": "Host"}, {"name": "detected", "label": "Detected", "type": "date"},
                {"name": "link", "label": "Link", "type": "link"}, {"name": "token", "label": "Token"}]


def alerts_pack(**extra) -> dict[str, Any]:
    return {"id": "siem-alerts", "name": "SIEM alerts", "version": "1.0.0", "items": [
        {"kind": "domain", "key": "alerts", "title": "Alerts", "singular": "Alert", "icon": "bell",
         "fields": ALERT_FIELDS, "title_field": "title"},
        {"kind": "widget", "key": "open_alerts", "title": "Open alerts by severity", "view": "breakdown",
         "domain": "x:alerts", "where": [{"field": "status", "op": "eq", "value": "open"}], "group_by": "severity"},
        {"kind": "widget", "key": "critical", "title": "Critical alerts", "view": "list", "domain": "x:alerts",
         "where": [{"field": "severity", "op": "in", "value": ["critical"]}], "columns": ["title", "host", "detected"],
         "sort": "detected", "size": "l"},
        {"kind": "widget", "key": "by_host", "title": "Alerts by host", "view": "breakdown", "domain": "x:alerts",
         "group_by": "host"},  # a text field: breakdowns only group by enum, severity and source fields
    ], **extra}


MANIFEST_WIDGETS = [{"key": "siem_count", "title": "SIEM alert count", "view": "metric", "domain": "x:alerts"},
                    {"key": "siem_assets", "title": "Assets the SIEM sees", "view": "count", "domain": "assets"}]
ALERT_SECRET = "alert-field-secret-4d1a"
DAY = 86400


@pytest.fixture
def d3(client, monkeypatch) -> dict[str, Any]:
    """Tools of every kind with connections that read assets, vulnerabilities, risks, people and accounts and an
    extension data type (x:alerts, from a pack that also declares widgets), records from each of them and by hand,
    and a firewall's snapshot."""
    from hub.connectors.netmodel import normalize_record
    from hub.extensions import pack as ext_pack
    from hub.extensions import records as ext_records
    from hub.extensions import registry as ext_registry
    from hub.integration import network
    from hub.models import Account, Person, Risk

    state = Remote()
    for cls in (FakeInventory, FakeScanner, FakeGrcRead, FakeDirectory, FakeSiem):
        monkeypatch.setattr(cls, "remote", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    hub = client.app.state.hub
    ext_registry.upload(hub, ext_pack.parse(alerts_pack()), "admin", enable=True)
    for tool_id, name, kind, extra in (("inventory", "Inventory", "fake_inventory", {}),
                                       ("scanner", "Scanner", "fake_scanner", {}),
                                       ("grcapp", "GRC App", "fake_grc_read", {}),
                                       ("dir", "Directory", "fake_directory", {}),
                                       ("siem", "SIEM <b>", "fake_siem", {"ui": {"widgets": MANIFEST_WIDGETS}}),
                                       ("notes", "Notes", None, {})):
        add_tool(client, tool_id, name, **extra)
        if kind:
            connect(client, tool_id, kind)
    now = time.time()
    for n, (type_, source) in enumerate([("server", "sync:inventory"), ("server", "sync:inventory"),
                                         ("workstation", "sync:inventory"), ("network", "manual")]):
        hub.save("assets", Asset(id=f"a_{n}", name=f"host-{n}", type=type_, source=source,
                                 criticality=("critical", "low", "high", "medium")[n], scan_scope=n < 2,
                                 last_scanned_at=now - DAY if n == 0 else None, assigned_person_id="p_left" if n == 2 else None,
                                 facts={"secret": TOKEN}), "asset")
    hub.save("assets", Asset(id="a_old", name="retired", type="server", status="retired", source="sync:inventory"), "asset")
    for n, (sev, status, due, first, source) in enumerate([
            ("high", "open", now - DAY, now, "scanner"), ("critical", "in_progress", now + DAY, now - DAY, "scanner"),
            ("low", "open", None, now - 3 * DAY, "scanner"), ("high", "fixed", now - DAY, now - 40 * DAY, "scanner"),
            ("medium", "open", None, now - 2 * DAY, "manual")]):
        hub.save("vulnerabilities", Vulnerability(id=f"v_{n}", title=f"Finding {n}", severity=sev, status=status,
                                                  due_at=due, first_seen=first, source=source, host=f"10.0.0.{n}",
                                                  fixed_at=now - DAY if status == "fixed" else None), "vulnerability")
    hub.save("risks", Risk(id="r_1", title="Ransomware", likelihood=5, impact=4, source="sync:grcapp"), "risk")
    hub.save("risks", Risk(id="r_2", title="Typo", likelihood=1, impact=1), "risk")
    hub.save("risks", Risk(id="r_3", title="Old", likelihood=2, impact=3, status="closed", source="sync:grcapp"), "risk")
    hub.save("people", Person(id="p_ok", display_name="Ada", email="ada@example.com", department="IT",
                              sources={"dir": "1"}), "person")
    hub.save("people", Person(id="p_left", display_name="Bob", email="bob@example.com", status="suspended",
                              department="Sales", sources={"dir": "2", "manual": "x"}), "person")
    for n in range(14):  # more departments than a breakdown shows
        hub.save("people", Person(id=f"p_{n:02d}", display_name=f"Person {n}", department=f"Dept {n:02d}"), "person")
    hub.save("accounts", Account(id="dir|1", tool_id="dir", external_id="1", login="ada", last_login=now - DAY,
                                 person_id="p_ok"), "account")
    hub.save("accounts", Account(id="dir|2", tool_id="dir", external_id="2", login="bob", person_id="p_left"), "account")
    hub.save("accounts", Account(id="dir|3", tool_id="dir", external_id="3", login="old", active=False,
                                 last_login=now - 9 * DAY), "account")
    for n, (sev, status, stale) in enumerate([("critical", "open", False), ("high", "open", False),
                                              ("high", "closed", False), ("critical", "open", True)]):
        ext_records.save(hub, ext_records.ExtRecord(
            id=f"x_{n}", domain="alerts", title=f"Alert {n} <img src=x onerror=alert(1)>", source="siem", stale=stale,
            fields={"title": f"Alert {n}", "severity": sev, "status": status, "host": f"web-{n}",
                    "detected": now - n * DAY, "link": "javascript:alert(1)" if n else "https://siem.example.com/a/0",
                    "token": ALERT_SECRET}))
    network.ingest(hub, "fw", normalize_record({"external_id": "fw", "revision": "1", "kind": "firewall",
                                                "rules": [], "interfaces": []}))
    return {"now": now}


def preview(c: TestClient, type_: str, config: dict[str, Any]) -> dict[str, Any]:
    response = c.get("/api/widgets/preview", params={"type": type_, "config": json.dumps(config), "fresh": "1"})
    assert response.status_code == 200, response.text
    return response.json()


def refused(c: TestClient, type_: str, config: dict[str, Any]):
    return c.get("/api/widgets/preview", params={"type": type_, "config": json.dumps(config)})


def count(domain: str, group_by: str | None = None, source: str = "all", filters: list | None = None,
          view: str = "bars") -> dict[str, Any]:
    return {"domain": domain, "source": source, "filters": filters or [], "group_by": group_by, "view": view}


def groups_of(result: dict[str, Any]) -> list[tuple[Any, str, int]]:
    return [(g["key"], g["label"], g["count"]) for g in result["data"]["groups"]]


def test_catalog_domains_are_whitelists(client, d3, sign_in):
    domains = {d["key"]: d for d in sign_in("viewer").get("/api/widgets/catalog").json()["domains"]}
    assert set(domains) == {"assets", "vulnerabilities", "risks", "controls", "people", "accounts", "network", "x:alerts"}
    assert "facts" not in domains["assets"]["fields"] and "email" not in domains["people"]["fields"]
    assert domains["assets"]["fields"]["criticality"] == {"label": "Criticality", "type": "enum",
                                                          "values": ["critical", "high", "medium", "low"]}
    assert domains["vulnerabilities"]["fields"]["overdue"]["values"] == ["yes", "no"]
    alerts = domains["x:alerts"]
    assert alerts["group_by"] == ["severity", "status", "source"] and alerts["filters"] == ["title", "severity", "status",
                                                                                           "host", "token"]
    assert alerts["sort"] == ["detected", "updated_at"] and alerts["date_fields"] == ["detected", "created_at", "updated_at"]
    assert alerts["fields"]["link"]["type"] == "link" and alerts["app_href"] == "#/x/alerts"
    assert {"manual", "inventory", "siem"} <= set(domains["accounts"]["fields"]["tool"]["values"])
    types = {t["key"]: t for t in sign_in("viewer").get("/api/widgets/catalog").json()["types"]}
    assert {"domain_count", "domain_list", "domain_timeline", "compliance_overview", "controls_status", "risk_matrix",
            "vuln_sla", "network_overview", "leavers", "declared"} <= set(types)
    assert [f["kind"] for f in types["domain_count"]["fields"]] == ["domain", "tool", "filters", "field", "select"]
    assert types["risk_matrix"]["fields"][0] == {"name": "source", "label": "From", "kind": "tool", "domain": "risks"}


def test_domain_counts_group_scope_and_order(client, d3):
    by_type = preview(client, "domain_count", count("assets", "type"))
    # the hub's own server is an asset too (added by hand: "host:local"); the retired asset is not counted
    assert by_type["status"] == "ok" and by_type["data"]["total"] == 5
    assert groups_of(by_type) == [("server", "server", 3), ("network", "network", 1), ("workstation", "workstation", 1)]
    scoped = preview(client, "domain_count", count("assets", "type", "tool:inventory"))["data"]
    assert scoped["total"] == 3 and scoped["source_label"] == "Inventory"
    assert preview(client, "domain_count", count("assets", None, "manual", view="number"))["data"]["total"] == 2
    by_source = preview(client, "domain_count", count("assets", "source"))
    assert groups_of(by_source) == [("inventory", "Inventory", 3), ("manual", "Added by hand", 2)]
    # severities keep their order and their tone; links open the Vulnerabilities page filtered the same way
    open_findings = [{"field": "status", "op": "in", "value": ["open", "in_progress"]}]
    sev = preview(client, "domain_count", count("vulnerabilities", "severity", "tool:scanner", open_findings))["data"]
    assert [(g["key"], g["count"], g["tone"]) for g in sev["groups"]] == [
        ("critical", 1, "sev-critical"), ("high", 1, "sev-high"), ("low", 1, "sev-low")]
    assert sev["ordinal"] is True and sev["groups"][1]["href"] == "#/vulnerabilities?severity=high&status=active&source=scanner"
    assert sev["href"] == "#/vulnerabilities?status=active&source=scanner"
    crit = preview(client, "domain_count", count("assets", "criticality"))["data"]["groups"]
    assert [g["key"] for g in crit] == ["critical", "high", "medium", "low"]
    overdue = preview(client, "domain_count", count("vulnerabilities", "overdue", filters=open_findings))
    assert groups_of(overdue) == [(False, "No", 3), (True, "Yes", 1)]
    # more than 12 groups: the 12 largest, then "Other"; missing values are "Not set"
    depts = preview(client, "domain_count", count("people", "department"))["data"]
    assert len(depts["groups"]) == 12 and depts["other"] == 4 and depts["total"] == 16
    people_by_source = preview(client, "domain_count", count("people", "source"))  # a person counts in each source
    assert groups_of(people_by_source) == [("manual", "Added by hand", 14), ("dir", "Directory", 2)]
    alerts = preview(client, "domain_count", count("x:alerts", "severity", "tool:siem"))["data"]
    assert [(g["key"], g["count"]) for g in alerts["groups"]] == [("critical", 1), ("high", 2)]  # the stale one is out
    assert alerts["source_label"] == "SIEM <b>" and alerts["href"] == "#/x/alerts"
    text_filter = [{"field": "department", "op": "eq", "value": "it"}]  # text compares without case
    assert preview(client, "domain_count", count("people", None, filters=text_filter, view="number"))["data"]["total"] == 1
    ne = [{"field": "status", "op": "ne", "value": "active"}]
    assert preview(client, "domain_count", count("people", None, "tool:dir", ne, "number"))["data"]["total"] == 1


def test_domain_lists_sort_limit_and_project(client, d3):
    risks = preview(client, "domain_list", {"domain": "risks", "source": "tool:grcapp", "sort": "score", "order": "desc",
                                            "limit": 2, "columns": ["title", "score", "level"]})["data"]
    assert risks["total"] == 2 and [r["title"] for r in risks["rows"]] == ["Ransomware", "Old"]
    assert risks["rows"][0]["cells"] == {"title": "Ransomware", "score": 20, "level": "critical"}
    assert risks["rows"][0]["tone"] == "sev-critical" and risks["rows"][0]["href"] == "#/compliance/risks"
    assert risks["columns"] == [{"field": "title", "label": "Title", "type": "text"},
                                {"field": "score", "label": "Score", "type": "number"},
                                {"field": "level", "label": "Level", "type": "enum"}]
    accounts = preview(client, "domain_list", {"domain": "accounts", "sort": "last_login", "order": "asc",
                                               "columns": ["login", "tool", "active", "last_login"]})["data"]
    assert [r["title"] for r in accounts["rows"]] == ["bob", "old", "ada"]  # never used first
    assert accounts["rows"][0]["cells"] == {"login": "bob", "tool": "Directory", "active": True, "last_login": None}
    overdue = preview(client, "domain_list", {"domain": "vulnerabilities", "sort": "due_at", "order": "asc",
                                              "filters": [{"field": "overdue", "op": "eq", "value": True}]})["data"]
    assert [r["id"] for r in overdue["rows"]] == ["v_0"] and set(overdue["rows"][0]["cells"]) == {
        "title", "severity", "host", "status"}  # the default columns: the domain's first four
    alerts = preview(client, "domain_list", {"domain": "x:alerts", "sort": "detected", "order": "desc",
                                             "columns": ["title", "link", "detected"]})["data"]
    assert [r["href"] for r in alerts["rows"]] == ["#/x/alerts/x_0", "#/x/alerts/x_1", "#/x/alerts/x_2"]
    assert alerts["rows"][0]["cells"]["link"] == "https://siem.example.com/a/0"
    assert alerts["rows"][1]["cells"]["link"] is None  # only http(s) links, never javascript:
    assert alerts["rows"][0]["title"] == "Alert 0 <img src=x onerror=alert(1)>"  # data; the UI escapes it
    people = preview(client, "domain_list", {"domain": "people", "sort": "display_name", "order": "asc", "limit": 25,
                                             "columns": ["display_name", "department"]})["data"]
    assert people["rows"][0]["href"] == "#/people/p_ok" and len(people["rows"]) == 16
    for row in people["rows"]:
        assert set(row) == {"id", "title", "href", "tone", "cells"} and set(row["cells"]) == {"display_name", "department"}
    devices = preview(client, "domain_list", {"domain": "network", "sort": "name", "order": "asc"})["data"]
    assert devices["rows"][0]["href"] == "#/network/fw" and devices["rows"][0]["cells"]["open_drift"] == 0


def test_domain_timeline_counts_per_utc_day(client, d3):
    import datetime as dt

    t = preview(client, "domain_timeline", {"domain": "vulnerabilities", "date_field": "first_seen", "days": 7})["data"]
    today = dt.datetime.now(dt.timezone.utc).date()
    assert len(t["buckets"]) == 7 and t["buckets"][-1]["day"] == today.isoformat()
    assert t["total"] == 4 and t["skipped"] == 0  # the finding first seen 40 days ago is outside the window
    fixed = preview(client, "domain_timeline", {"domain": "vulnerabilities", "date_field": "fixed_at", "days": 30})["data"]
    assert fixed["total"] == 1 and fixed["skipped"] == 4 and fixed["date_label"] == "Fixed"


def test_record_widget_configs_are_whitelisted(client, d3):
    def problem(type_, config, setting):
        response = refused(client, type_, config)
        assert response.status_code == 422 and response.json()["detail"]["code"] == "invalid_widget", (config, response.text)
        message = response.json()["detail"]["message"]
        assert setting in message and "zz-secret-value" not in message, message
        return message

    problem("domain_count", count("secrets"), "domain")
    problem("domain_count", count("x:nothing"), "domain")
    problem("domain_count", count("assets", "facts"), "group_by")
    problem("domain_count", count("assets", "name"), "group_by")  # a text field is not a breakdown
    problem("domain_count", count("assets", None), "group_by")  # bars need a field
    problem("domain_count", count("assets", "type", "tool:gone"), "source")
    problem("domain_count", count("assets", "type", filters=[{"field": "facts", "op": "eq", "value": "zz-secret-value"}]),
            "filters")
    problem("domain_count", count("assets", "type", filters=[{"field": "type", "op": "eq", "value": "zz-secret-value"}]),
            "filters")
    problem("domain_count", count("assets", "type", filters=[{"field": "type", "op": "in", "value": "server"}]),
            "filters")
    problem("domain_count", count("assets", "type", filters=[{"field": "type", "op": "eq", "value": "server"}] * 6),
            "filters")
    problem("domain_list", {"domain": "assets", "sort": "facts"}, "sort")
    problem("domain_list", {"domain": "assets", "columns": ["name", "facts"]}, "columns")
    problem("domain_list", {"domain": "assets", "limit": 26}, "limit")
    problem("domain_timeline", {"domain": "assets", "date_field": "name"}, "date_field")
    problem("risk_matrix", {"source": "tool:gone"}, "tool")
    problem("controls_status", {"family": "zz-secret-value"}, "family")


def test_stored_record_widgets_become_unavailable(client, d3):
    from hub.extensions import registry as ext_registry

    hub = client.app.state.hub
    d = saved(client, create(client), [widget("domain_count", count("assets", "type", "tool:inventory")),
                                       widget("domain_count", count("x:alerts", "severity"), y=3, wid="w_00000002"),
                                       widget("risk_matrix", {"source": "tool:grcapp"}, y=6, wid="w_00000003")])
    assert {k: v["status"] for k, v in data(client, d).items()} == {"w_00000001": "ok", "w_00000002": "ok",
                                                                   "w_00000003": "ok"}
    hub.store.delete("tools", "inventory")
    hub.bus.publish("tool_removed", {"id": "inventory"})
    ext_registry.set_status(hub, "siem-alerts", "disabled", "admin")
    hub.store.delete("tools", "grcapp")
    hub.bus.publish("tool_removed", {"id": "grcapp"})
    after = data(client, d)
    assert (after["w_00000001"]["status"], after["w_00000001"]["code"]) == ("unavailable", "tool_removed")
    assert (after["w_00000002"]["status"], after["w_00000002"]["code"]) == ("unavailable", "domain_inactive")
    assert (after["w_00000003"]["status"], after["w_00000003"]["code"]) == ("unavailable", "tool_removed")
    assert saved(client, d, stored(d))  # unchanged, they are kept (5.3)


def test_empty_record_widgets_hint_at_the_next_step(client, d3):
    empty = preview(client, "domain_count", count("assets", "type", "tool:notes"))
    assert empty["status"] == "empty" and empty["data"]["total"] == 0
    assert empty["hint"] == {"text": "Set up a data flow from Notes", "href": "#/tools/notes/connection",
                             "min_role": "admin"}
    filtered = preview(client, "domain_count", count("assets", "type", filters=[
        {"field": "type", "op": "eq", "value": "cloud"}]))
    assert filtered["status"] == "ok" and filtered["data"]["total"] == 0  # records exist, none match: not "empty"


def test_compliance_network_and_people_widgets(client, d3):
    hub = client.app.state.hub
    hub.store.delete_many("controls", [c["id"] for c in hub.store.list("controls")])
    before = preview(client, "controls_status", {})
    assert before["status"] == "empty" and before["hint"]["href"] == "#/compliance/controls"
    assert client.post("/api/grc/evaluate").status_code == 200
    comp = preview(client, "compliance_overview", {"frameworks": ["BASELINE", "NIS2"]})
    assert comp["status"] == "ok" and [f["id"] for f in comp["data"]["frameworks"]] == ["BASELINE", "NIS2"]
    assert set(comp["data"]["frameworks"][0]) == {"id", "name", "score", "passing", "failing", "total", "href"}
    assert comp["data"]["cyfun"] is None and comp["data"]["external"] == []
    controls = preview(client, "controls_status", {"status": ["fail", "partial"], "limit": 3})["data"]
    assert sum(controls["counts"].values()) == len(hub.all("controls", __import__("hub.models").models.ControlState))
    assert len(controls["rows"]) <= 3 and all(r["status"] in ("fail", "partial") for r in controls["rows"])
    assert [r["status"] for r in controls["rows"]] == sorted((r["status"] for r in controls["rows"]),
                                                             key=lambda s: ("fail", "partial").index(s))
    matrix = preview(client, "risk_matrix", {"source": "tool:grcapp"})["data"]
    assert matrix["total"] == 1 and matrix["cells"][4][3] == 1 and matrix["source_label"] == "GRC App"  # not the closed
    assert preview(client, "risk_matrix", {"source": "tool:grcapp", "status": []})["data"]["total"] == 2
    everything = preview(client, "risk_matrix", {"source": "all"})["data"]  # with the risks failing controls raise
    assert everything["cells"][0][0] == 1 and everything["total"] == sum(map(sum, everything["cells"]))
    sla = preview(client, "vuln_sla", {"source": "tool:scanner"})["data"]
    assert (sla["open"], sla["overdue"], sla["fixed_last_30_days"]) == (3, 1, 1)
    assert sla["by_severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "info": 0}
    assert sla["overdue_by_severity"]["high"] == 1 and sla["sla_days"]["critical"] > 0
    assert (sla["in_scope_assets"], sla["scanned_last_30_days"]) == (2, 1)
    assert preview(client, "vuln_sla", {"source": "all"})["data"]["open"] == 4
    net = preview(client, "network_overview", {"tools": "all"})["data"]
    assert [d["tool_id"] for d in net["devices"]] == ["fw"] and net["devices"][0]["href"] == "#/network/fw"
    assert set(net["devices"][0]) == {"tool_id", "name", "product", "snapshot_at", "stale", "writable", "open_drift",
                                      "critical_drift", "connection", "href"}
    assert net["drift"] == {"open": 0, "attributed": 0, "acknowledged": 0, "critical_open": 0}
    assert net["device_changes_on"] is False
    leavers = preview(client, "leavers", {"limit": 5})["data"]
    assert leavers["total"] == 1 and leavers["rows"][0]["display_name"] == "Bob"
    assert leavers["rows"][0]["holds"] == {"assets": 1, "accounts": 1, "atrium_account": False}
    assert "bob@example.com" not in json.dumps(leavers)


def test_tool_suggestions_follow_what_each_connection_reads(client, d3, sign_in):
    suggestions = sign_in("viewer").get("/api/widgets/catalog").json()["suggestions"]
    titles = lambda group: [s["title"] for s in suggestions if s["group"] == group]  # noqa: E731
    assert titles("tool:inventory") == ["Inventory: overview", "Inventory: assets by type",
                                        "Inventory: recently updated assets"]
    assert titles("tool:scanner") == ["Scanner: overview", "Scanner: open findings by severity",
                                      "Scanner: overdue findings", "Scanner: SLA"]
    assert titles("tool:grcapp") == ["GRC App: overview", "GRC App: risk matrix", "GRC App: top risks"]
    assert titles("tool:dir") == ["Directory: overview", "Directory: active accounts",
                                  "Directory: accounts by last sign-in", "Directory: people by status",
                                  "Directory: suspended or terminated"]
    assert titles("tool:siem")[:3] == ["SIEM <b>: overview", "SIEM <b>: Alerts by severity", "SIEM <b>: latest Alerts"]
    assert titles("tool:notes") == ["Notes: overview"]  # no connection: only its overview
    for s in suggestions:
        if s["group"].startswith("tool:") and s["type"] in ("domain_count", "domain_list"):
            assert s["config"]["source"] == s["group"], s
    hub_titles = titles("hub")
    assert {"Assets: all sources", "Alerts: all sources", "Open findings by severity", "Risk matrix", "Leavers",
            "Network devices", "Compliance", "Vulnerability deadlines"} <= set(hub_titles)
    for s in suggestions:  # every suggestion resolves (the gallery adds them without a configure step)
        if s["type"] != "declared" and not s.get("invalid"):
            result = preview(client, s["type"], s["config"])
            assert result["status"] in ("ok", "empty"), (s["title"], result)


def test_declared_widgets_from_packs_and_manifests(client, d3):
    from hub.extensions import registry as ext_registry

    hub = client.app.state.hub
    suggestions = {s["title"]: s for s in client.get("/api/widgets/catalog").json()["suggestions"] if s["type"] == "declared"}
    pack_one = suggestions["Open alerts by severity"]
    assert pack_one["group"] == "pack:siem-alerts" and pack_one["config"] == {"ref": "pack:siem-alerts/open_alerts"}
    assert pack_one["declared_by"] == {"kind": "pack", "id": "siem-alerts", "name": "SIEM alerts"}
    assert pack_one["size"] == [4, 3] and suggestions["Critical alerts"]["size"] == [6, 4] and "invalid" not in pack_one
    # shown with the reason, and it cannot be added
    assert suggestions["Alerts by host"]["invalid"] == "group_by: choose one of the fields of Alerts to group by (bars " \
                                                      "and lists need one)"
    tool_one = suggestions["SIEM alert count"]
    assert tool_one["group"] == "tool:siem" and tool_one["size"] == [3, 2] and "invalid" not in tool_one
    assert tool_one["declared_by"] == {"kind": "tool", "id": "siem", "name": "SIEM <b>"}
    assert "does not read" in suggestions["Assets the SIEM sees"]["invalid"]  # the SIEM's connection reads no assets

    d = create(client)
    bad = put(client, d, [widget("declared", {"ref": "tool:siem/siem_assets"})])
    assert bad.status_code == 422 and "does not read" in bad.json()["detail"]["message"]
    assert put(client, d, [widget("declared", {"ref": "pack:siem-alerts/by_host"})]).status_code == 422
    d = saved(client, d, [widget("declared", {"ref": "pack:siem-alerts/open_alerts"}, w=4, h=3),
                          widget("declared", {"ref": "pack:siem-alerts/critical"}, y=3, w=6, h=4, wid="w_00000002"),
                          widget("declared", {"ref": "tool:siem/siem_count"}, y=7, w=3, h=2, wid="w_00000003")])
    r = data(client, d)
    breakdown, listing, metric = r["w_00000001"]["data"], r["w_00000002"]["data"], r["w_00000003"]["data"]
    assert breakdown["compiled"] == "domain_count" and breakdown["view"] == "bars"
    assert [(g["key"], g["count"]) for g in breakdown["groups"]] == [("critical", 1), ("high", 1)]  # open only
    assert breakdown["declared_by"]["kind"] == "pack" and breakdown["declared_title"] == "Open alerts by severity"
    assert listing["compiled"] == "domain_list" and [row["id"] for row in listing["rows"]] == ["x_0"]
    assert metric["compiled"] == "domain_count" and metric["view"] == "number" and metric["total"] == 3
    assert metric["source"] == "tool:siem"  # a manifest's widget is always scoped to its tool

    ext_registry.set_status(hub, "siem-alerts", "disabled", "admin")
    hub.bus.publish("extension", {"id": "siem-alerts"})
    after = data(client, d)
    assert after["w_00000001"]["status"] == "unavailable" and after["w_00000001"]["code"] == "declaration_gone"
    assert after["w_00000003"]["status"] == "unavailable"  # x:alerts is not active any more either
    gone = {s["title"] for s in client.get("/api/widgets/catalog").json()["suggestions"] if s["type"] == "declared"}
    assert "Open alerts by severity" not in gone


@pytest.mark.parametrize("declaration,problem", [
    ({"title": "<b>Alerts</b>"}, "plain text"),
    ({"title": "Alerts <script>alert(1)</script>"}, "plain text"),
    ({"title": "See https://evil.example.com"}, "plain text"),
    ({"description": "javascript:alert(1)"}, "plain text"),
    ({"color": "#ff0000"}, "Extra inputs"),
    ({"html": "<img>"}, "Extra inputs"),
    ({"source": "tool:other"}, "Extra inputs"),  # never another tool's data
    ({"where": [{"field": "severity", "op": "eq", "value": "high"}] * 100}, "at most 5"),
    ({"where": [{"field": "severity", "op": "gte", "value": "high"}]}, "eq, ne or in"),
    ({"where": [{"field": "nope", "op": "eq", "value": "x"}]}, "not a field"),
    ({"domain": "secrets"}, "domain"),
    ({"limit": 1000}, "limit"),
    ({"group_by": "severity"}, "only a breakdown"),
])
def test_malicious_declarations_are_refused_with_readable_errors(declaration, problem):
    from hub.extensions import pack as ext_pack

    base = {"kind": "widget", "key": "w1", "title": "Alerts", "view": "count", "domain": "x:alerts"}
    data_ = alerts_pack()
    data_["items"] = [data_["items"][0], {**base, **declaration}]
    with pytest.raises(ValueError) as exc:
        ext_pack.parse(data_)
    assert problem in str(exc.value), str(exc.value)
    decls, problems = ext_pack.widget_decls([{k: v for k, v in {**base, **declaration}.items() if k != "kind"}])
    if problem == "not a field":  # a manifest declares no domain: its field names are checked when it is compiled
        assert len(decls) == 1 and problems == []
    else:
        assert decls == [] and problem in problems[0], problems


def test_manifest_widgets_are_kept_one_by_one_by_the_analyzer(tmp_path):
    import yaml

    from hub.integration import analyzer

    (tmp_path / "hub.manifest.yaml").write_text(yaml.safe_dump({"name": "SIEM", "ui": {"widgets": [
        MANIFEST_WIDGETS[0], {**MANIFEST_WIDGETS[1], "title": "<img src=x onerror=alert(1)>"},
        *({**MANIFEST_WIDGETS[0], "key": f"k{n}"} for n in range(12))]}}))
    (tmp_path / "main.py").write_text("print('hi')\n")
    manifest, notes = analyzer.analyze_repo(tmp_path, "siem", "SIEM")
    assert manifest.native and [w["key"] for w in manifest.ui.widgets] == ["siem_count", *(f"k{n}" for n in range(9))]
    assert any("ui.widgets 2: title: must be plain text" in n for n in notes)
    assert any("only the first 10 widgets" in n for n in notes)


def test_record_widgets_depend_on_their_domain_events(client, d3, counted):
    hub = client.app.state.hub
    result = preview(client, "domain_count", count("assets", "type"))
    assert set(result["events"]) == {"asset", "asset_removed", "tool_removed"}
    alerts = preview(client, "domain_count", count("x:alerts", "severity"))
    assert "x_record" in alerts["events"] and "asset" not in alerts["events"]
    d = saved(client, create(client), [widget("domain_count", count("assets", "type"))])
    first = data(client, d)["w_00000001"]
    hub.bus.publish("vulnerability", {})  # unrelated: the cached result stays
    assert data(client, d)["w_00000001"]["generated_at"] == first["generated_at"]
    hub.save("assets", Asset(id="a_new", name="new", type="cloud", source="manual"), "asset")
    again = data(client, d)["w_00000001"]
    assert again["generated_at"] >= first["generated_at"] and again["data"]["total"] == 6


def test_no_secrets_in_d3_widgets_and_suggestions(client, d3):
    client.post("/api/grc/evaluate")
    configs = [("domain_list", {"domain": "x:alerts", "columns": ["title", "host", "link", "detected"]}),
               ("domain_list", {"domain": "assets", "columns": ["name", "type", "owner", "status"]}),
               ("domain_list", {"domain": "people", "columns": ["display_name", "title", "department", "status"]}),
               ("domain_list", {"domain": "accounts"}), ("domain_count", count("x:alerts", "source")),
               ("domain_timeline", {"domain": "x:alerts"}), ("compliance_overview", {}), ("controls_status", {}),
               ("risk_matrix", {}), ("vuln_sla", {}), ("network_overview", {}), ("leavers", {}),
               ("declared", {"ref": "pack:siem-alerts/critical"})]
    secrets = (TOKEN, ALERT_SECRET, "ada@example.com", "bob@example.com")
    for type_, config in configs:
        result = preview(client, type_, config)
        assert result["status"] in ("ok", "empty"), (type_, result)
        text = json.dumps(result)
        assert not [s for s in secrets if s in text], type_
        for path, key, _ in walk(result["data"]):
            assert key not in FORBIDDEN_KEYS, f"{type_}: {path}.{key}"
    catalog = json.dumps(client.get("/api/widgets/catalog").json())
    assert not [s for s in secrets if s in catalog]


# a right-to-left override shows "invoice<RLO>exe.pdf" as "invoicefdp.exe"; zero-width, isolate, separator, BOM and C1
SPOOF = "invoice\u202eexe.pdf\u200b\u2066x\u2069\x85\u061c\u2028\ufeff\u200d"
DISGUISE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")


def test_widget_text_cannot_disguise_itself(client, d3, sign_in):
    """Tool text (record titles, hosts, names, departments, tool names) reaches widget data - previews, breakdown labels
    and the shared cached result every viewer of a shared dashboard gets - without bidi controls, zero-width, separator
    or C1 characters (6.2 Notes, section 11 item 6); a note keeps its line breaks and tabs."""
    from hub.models import Person

    hub = client.app.state.hub
    add_tool(client, "spoof", SPOOF)
    hub.save("vulnerabilities", Vulnerability(id="v_spoof", title=SPOOF, severity="high", host=SPOOF), "vulnerability")
    hub.save("assets", Asset(id="a_spoof", name=SPOOF, type="server", owner=SPOOF), "asset")
    for n in range(2):  # two of them: the department is among the breakdown's top groups
        hub.save("people", Person(id=f"p_spoof{n}", display_name=SPOOF, department=SPOOF, sources={"spoof": str(n)}),
                 "person")
    configs = [("domain_list", {"domain": "vulnerabilities", "columns": ["title", "host"], "limit": 25}),
               ("domain_list", {"domain": "assets", "columns": ["name", "owner"], "limit": 25}),
               ("domain_list", {"domain": "people", "columns": ["display_name", "department"], "limit": 25}),
               ("domain_count", count("people", "department")), ("domain_count", count("people", "source")),
               ("tool_health", {"tools": "all"})]
    viewer = sign_in("viewer")
    shared = saved(client, create(client, "Shared spoof", scope="shared"),
                   [widget(t, c, 0, 4 * n, wid=f"w_{n:08d}") for n, (t, c) in enumerate(configs)])
    cached = data(viewer, shared)
    assert data(sign_in("operator"), shared) == cached  # the second viewer gets the shared cached results
    for n, (type_, config) in enumerate(configs):
        for result in (preview(viewer, type_, config), cached[f"w_{n:08d}"]):
            assert result["status"] == "ok", (type_, result)
            strings = [v for _, _, v in walk(result["data"]) if isinstance(v, str)]
            assert "invoiceexe.pdfx" in strings, (type_, config)
            assert not [s for s in strings if DISGUISE.search(s)], (type_, config)
    labels = {g["label"] for g in preview(viewer, "domain_count", count("people", "department"))["data"]["groups"]}
    assert "invoiceexe.pdfx" in labels
    assert resolve_module.clean(SPOOF) == "invoiceexe.pdfx"
    note = preview(viewer, "note", {"text": "line one\n\tline two \u2066x\u2069"})["data"]
    assert note == {"text": "line one\n\tline two x"}


# -- stage D4: the settings widgets (6.7, 10.16-10.17) -------------------------------------------------


def ready_provider(c: TestClient, name: str = "Ollama", model: str = "qwen3:8b", **extra: Any) -> str:
    """A model server whose last connection test passed (the Agents page offers only those)."""
    created = c.post("/api/llm/providers", json={"name": name, "default_model": model, **extra})
    assert created.status_code == 201, created.text
    hub = c.app.state.hub
    provider = llm_providers.get(hub, created.json()["id"])
    llm_providers.put(hub, provider.model_copy(update={"last_test": {"ok": True, "at": time.time(), "detail": "ok"}}))
    return provider.id


def ai(c: TestClient, show: str = "all") -> dict[str, Any]:
    return preview(c, "ai_models", {"show": show})["data"]


def chip(d: dict[str, Any], agent_id: str) -> dict[str, Any]:
    return next(a for a in d["agents"] if a["id"] == agent_id)


def test_ai_models_lanes_follow_the_model_choice(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = ready_provider(client)
    bare = ready_provider(client, "Bare", "")
    custom = client.post("/api/agents", json={"name": "Triage"}).json()["id"]
    d = ai(client)
    providers = {p["id"]: p for p in d["providers"]}
    assert list(providers)[:2] == ["anthropic", "openai"] and {"rules", ollama, bare} <= set(providers)
    assert all(set(p) == {"id", "kind", "variant", "label", "location", "available", "reason", "default_model", "models"}
               for p in providers.values())
    claude = providers["anthropic"]
    assert claude["available"] and claude["location"] == "third_party" and claude["default_model"].startswith("claude-")
    assert providers["openai"]["available"] is False and providers["openai"]["reason"]  # no API key: drops refused
    assert providers[ollama]["available"] and providers[ollama]["location"] == "self_hosted"
    assert providers[bare]["default_model"] == "" and providers["rules"]["available"]
    agents = {a["id"]: a for a in d["agents"]}
    deterministic = [a.id for a in hub.agents.all() if not (a.uses_llm or a.kind == "custom")]
    assert {"supervisor", "patcher", custom} <= set(agents) and not set(deterministic) & set(agents)
    assert d["deterministic"] == len(deterministic) > 0
    sup = agents["supervisor"]
    assert sup["choice"] == {"provider": "", "model": ""} and sup["kind"] == "core" and sup["local_only"] is False
    assert sup["effective"]["provider"] == "anthropic" and sup["effective"]["source"] == "suite" and sup["effective"]["ready"]
    assert sup["href"] == "#/agents/supervisor/settings" and agents["patcher"]["per_task"] == 0
    assert d["default"] == {"provider": "auto", "model": "", "label": "Automatic", "resolved": {
        "provider": "anthropic", "provider_label": "Claude", "model": claude["default_model"], "ready": True,
        "fallback": False}}
    assert [a["id"] for a in ai(client, "custom")["agents"]] == [custom]
    assert custom not in [a["id"] for a in ai(client, "core")["agents"]] and "supervisor" in [a["id"] for a in ai(client, "core")["agents"]]
    # the Patch Agent's per-task choice is counted, not drawn as a lane
    v = chip(d, "patcher")["settings_version"]
    assert client.patch("/api/agents/patcher/settings", json={"config": {"purposes": {"code": {"provider": ollama}}},
                                                              "version": v}).status_code == 200
    patcher = chip(ai(client), "patcher")
    assert patcher["per_task"] == 1 and patcher["choice"]["provider"] == "" and patcher["settings_version"] == v + 1


def test_ai_models_writes_go_through_the_llm_routes(client, sign_in, monkeypatch):
    """What the widget sends (aimodels.js dropPayload / defaultPayload) against R4-LLM's admin routes."""
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = ready_provider(client)
    operator = sign_in("operator")
    sup = chip(ai(client), "supervisor")
    onto = {"llm": {"provider": ollama, "model": ""}, "version": sup["settings_version"]}
    assert operator.patch("/api/agents/supervisor/settings", json=onto).status_code == 403
    assert client.patch("/api/agents/supervisor/settings", json=onto).status_code == 200
    moved = chip(ai(client), "supervisor")
    assert moved["choice"] == {"provider": ollama, "model": ""} and moved["effective"]["provider"] == ollama
    assert moved["effective"]["source"] == "agent" and moved["settings_version"] == sup["settings_version"] + 1
    stale = client.patch("/api/agents/supervisor/settings", json=onto)  # the version read before the move
    assert stale.status_code == 409 and stale.json()["code"] == "version_conflict"
    inherit = {"llm": {"provider": "", "model": ""}, "version": moved["settings_version"]}  # dropped on "Inherits"
    assert client.patch("/api/agents/supervisor/settings", json=inherit).status_code == 200
    back = chip(ai(client), "supervisor")
    assert back["choice"]["provider"] == "" and back["effective"]["source"] == "suite"
    v = ai(client)["selection_version"]
    default = {"default": {"provider": ollama, "model": ""}, "version": v}  # the default marker onto a lane
    assert operator.patch("/api/llm/selection", json=default).status_code == 403
    assert client.patch("/api/llm/selection", json=default).status_code == 200
    d = ai(client)
    assert d["selection_version"] == v + 1 and d["default"]["provider"] == ollama
    assert d["default"]["resolved"]["provider"] == ollama and chip(d, "supervisor")["effective"]["provider"] == ollama
    assert client.patch("/api/llm/selection", json=default).status_code == 409  # stale
    automatic = {"default": {"provider": "auto", "model": ""}, "version": v + 1}  # "Use automatic"
    assert client.patch("/api/llm/selection", json=automatic).status_code == 200
    assert ai(client)["default"]["provider"] == "auto"


def test_ai_models_shows_local_only_agents_and_blocked_cloud_providers(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ready_provider(client)
    v = chip(ai(client), "supervisor")["settings_version"]
    assert client.patch("/api/agents/supervisor/settings", json={"config": {"local_only": True}, "version": v}).status_code == 200
    sup = chip(ai(client), "supervisor")
    assert sup["local_only"] and sup["local_only_from"] == "agent" and sup["effective"]["location"] == "self_hosted"
    refused = client.patch("/api/agents/supervisor/settings", json={"llm": {"provider": "anthropic"},
                                                                     "version": sup["settings_version"]})
    assert refused.status_code == 400 and "local-only" in refused.json()["detail"]  # as the widget's lanes refuse it
    assert client.patch("/api/settings/guardrails", json={"allow_cloud_llm": False}).status_code == 200
    claude = next(p for p in ai(client)["providers"] if p["id"] == "anthropic")
    assert claude["available"] is False and claude["reason"] == "cloud providers are switched off (guardrail)"


def test_settings_widgets_are_cached_for_everyone_and_follow_their_events(client, sign_in, monkeypatch):
    calls: list[int] = []
    t = registry.REGISTRY["ai_models"]

    def counting(ctx, cfg):
        calls.append(1)
        return t.resolve(ctx, cfg)

    monkeypatch.setitem(registry.REGISTRY, "ai_models", dataclasses.replace(t, resolve=counting))
    hub = client.app.state.hub
    viewer = sign_in("viewer")
    shared = saved(client, create(client, "Settings", scope="shared"), [
        widget("ai_models", {"show": "all"}), widget("agents_status", {"team": "all", "show_provider": True}, 8, 0,
                                                     wid="w_00000002")])
    as_admin, as_viewer = data(client, shared), data(viewer, shared)
    assert json.dumps(as_admin, sort_keys=True) == json.dumps(as_viewer, sort_keys=True) and len(calls) == 1
    first = as_admin["w_00000001"]
    assert "can_edit" not in json.dumps(first) and not {k for a in first["data"]["agents"] for k in a} & {
        "status", "active", "last_active", "paused", "handled", "queued", "errors"}  # no per-viewer, no volatile field
    supervisor = hub.agents.get("supervisor")
    supervisor.active += 1  # "working"
    hub.bus.publish("agent", supervisor.record())  # follows every message an agent handles: not an AI-models event
    assert data(viewer, shared)["w_00000001"] == first and len(calls) == 1
    for n, event in enumerate(("agent_settings", "llm_selection", "settings", "llm_provider", "agent_removed"), 2):
        hub.bus.publish(event, {})
        again = data(viewer, shared)["w_00000001"]
        assert len(calls) == n and again["version"] == first["version"], event  # recomputed; nothing changed


def test_safety_settings_widget(client):
    s = preview(client, "safety_settings", {})["data"]
    assert s == {"autonomy": "assisted", "relaxed": [], "controls_affected": [], "total_guardrails": len(guardrails.REGISTRY),
                 "device_changes_on": False, "cloud_ai": True, "spend_limit": 20, "href": "#/settings"}
    assert client.patch("/api/settings/guardrails", json={"limit_llm_spend": False, "allow_cloud_llm": False}).status_code == 200
    assert client.patch("/api/settings", json={"autonomy": "autonomous"}).status_code == 200
    s = preview(client, "safety_settings", {})["data"]
    assert s["autonomy"] == "autonomous" and s["cloud_ai"] is False and s["spend_limit"] is None
    # blocking cloud providers is the safe side: only the spending cap counts as relaxed
    assert s["relaxed"] == [{"key": "limit_llm_spend", "title": guardrails.REGISTRY["limit_llm_spend"].title,
                             "group": "models", "control": "HB-AC-6"}] and s["controls_affected"] == ["HB-AC-6"]


def test_hub_accounts_widget_is_for_administrators(client, sign_in):
    hub = client.app.state.hub
    viewer, operator = sign_in("viewer"), sign_in("operator")
    sign_in("viewer", "olduser")
    old = time.time() - 120 * 86400
    user = hub.auth.find_user("olduser")
    hub.auth._save_user(user.model_copy(update={"last_login": old, "created_at": old}))
    gone = hub.auth.create_user("gone", None, role="operator", actor="test")
    hub.auth._save_user(gone.model_copy(update={"disabled": True}))
    assert client.post("/api/tokens", json={"name": "ci", "role": "viewer"}).status_code in (200, 201)
    for c in (viewer, operator):
        refused = c.get("/api/widgets/preview", params={"type": "hub_accounts", "config": "{}"})
        assert refused.status_code == 403 and refused.json()["detail"]["code"] == "role_required"
    a = preview(client, "hub_accounts", {})["data"]
    assert a["by_role"] == {"admin": 1, "operator": 1, "viewer": 2} and a["total"] == 5 and a["disabled"] == 1
    assert a["dormant_total"] == 1 and a["dormant_90d"] == [{"username": "olduser", "last_seen": old}]
    assert a["tokens_active"] == 1 and "password" not in json.dumps(a) and "@" not in json.dumps(a)
    mine = create(viewer, "Mine")
    refused = put(viewer, mine, [widget("hub_accounts", {})])
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "role_required"
    shared = saved(client, create(client, "Admins", scope="shared"), [
        widget("hub_accounts", {}), widget("safety_settings", {}, 4, 0, wid="w_00000002")])
    seen = viewer.get(f"/api/dashboards/{shared['id']}").json()
    assert seen["hidden_widgets"] == 1 and [w["type"] for w in seen["widgets"]] == ["safety_settings"]
    copy = operator.post("/api/dashboards/mine", json={"title": "Copy", "from": shared["id"]})
    assert copy.status_code == 201 and copy.json()["dropped"] == 1
    assert put(operator, copy.json(), stored(copy.json())).status_code == 200


def test_llm_spend_today_metric(client):
    hub = client.app.state.hub
    day = time.strftime("%Y-%m-%d", time.gmtime())
    spent = lambda: client.get("/api/llm/usage").json()["suite_budget"]["spent_today"]  # noqa: E731

    def metric(cost: float | None = None) -> dict[str, Any]:
        if cost is not None:
            hub.store.put("llm_usage_daily", {"id": f"{day}|supervisor|anthropic|m", "day": day, "agent_id": "supervisor",
                                              "provider": "anthropic", "model": "m", "calls": 3, "cost_usd": cost})
            hub.bus.publish("llm_usage", {"day": day})
        return preview(client, "metric", {"metric": "llm_spend_today"})["data"]

    first = metric()
    assert first["value"] == spent() == 0 and first["display"] == "$0.00" and first["hint"] == "estimated"
    assert first["sub"] == "of $20 daily limit" and first["tone"] is None and first["href"] == "#/settings/ai"
    warn = metric(16.5)
    assert warn["value"] == spent() == 16.5 and warn["display"] == "$16.50"
    assert warn["tone"] == "warn" and warn["sub"] == "of $20 daily limit - 82% used"
    over = metric(20.0)
    assert over["tone"] == "bad" and over["sub"] == "daily limit of $20 reached - AI calls stop until tomorrow (UTC)"
    assert client.patch("/api/settings/guardrails", json={"limit_llm_spend": False}).status_code == 200
    off = metric()
    assert off["sub"] == "no daily limit" and off["tone"] is None and off["value"] == 20.0
    catalog = client.get("/api/widgets/catalog").json()
    assert "llm_spend_today" in {m["key"] for m in catalog["metrics"]}
    assert ("metric", {"metric": "llm_spend_today"}) in [(s["type"], s["config"]) for s in catalog["suggestions"]]


def test_settings_widget_suggestions_by_role(client, sign_in):
    suggested = lambda c: {(s["type"], json.dumps(s["config"])) for s in c.get("/api/widgets/catalog").json()["suggestions"]}  # noqa: E731
    viewer, admin = suggested(sign_in("viewer")), suggested(client)
    for item in (("ai_models", '{"show": "all"}'), ("ai_models", '{"show": "custom"}'), ("safety_settings", "{}")):
        assert item in viewer and item in admin
    assert ("hub_accounts", "{}") in admin and ("hub_accounts", "{}") not in viewer


def test_add_to_home_through_the_api(client, sign_in):
    """What "Add to Home" (js/dashboard/addhome.js) does for a person without a dashboard of their own: a copy of the
    default becomes "My dashboard" and their home, and the widget goes to the first free place by the normal PUT."""
    viewer = sign_in("viewer")
    listing = viewer.get("/api/dashboards").json()
    assert not [d for d in listing["dashboards"] if d["scope"] == "personal"]
    mine = create(viewer, "My dashboard", listing["default_id"])
    prefs = viewer.put("/api/dashboards/prefs", json={"order": [], "hidden": [], "home": mine["id"],
                                                     "base_version": listing["prefs"]["version"]})
    assert prefs.status_code == 200 and viewer.get("/api/dashboards").json()["home_id"] == mine["id"]
    spot = layout.first_fit(stored(mine), 8, 4)
    added = saved(viewer, mine, [*stored(mine), widget("ai_models", {"show": "all"}, *spot, 8, 4, wid="w_d4added01")])
    assert [w["type"] for w in added["widgets"]][-1] == "ai_models"
    assert data(viewer, added)["w_d4added01"]["status"] == "ok"


# -- stage D6: security walks over every widget type, and what the performance work must not change ----------------

BACKUP_SECRET = "device-backup-secret-6a3f"


def every_type_configs() -> list[tuple[str, dict[str, Any]]]:
    """A valid config of every registered widget type (with the `d3` fixture's tools, pack and records)."""
    return [*EVERY_TYPE,
            ("domain_count", count("x:alerts", "severity")), ("domain_count", count("people", "source")),
            ("domain_list", {"domain": "x:alerts", "columns": ["title", "host", "link", "detected"]}),
            ("domain_list", {"domain": "accounts"}), ("domain_timeline", {"domain": "vulnerabilities"}),
            ("compliance_overview", {}), ("controls_status", {}), ("risk_matrix", {}), ("vuln_sla", {}),
            ("network_overview", {}), ("leavers", {}), ("declared", {"ref": "pack:siem-alerts/critical"}),
            ("declared", {"ref": "tool:siem/siem_count"})]


def test_every_widget_type_is_walked_for_secrets(client, d3, sign_in):
    """Section 11 item 5 over every registered type at once: a dashboard holding each of them, its data, its view, the
    dashboard list and the catalog carry no forbidden key and none of the secrets seeded in the hub - an AI provider's
    API key, a connection token, a webhook URL with a token, a device backup's content, an extension record's
    secret field, people's email addresses, and the data of activity entries and approval payloads."""
    from hub.integration import network

    hub = client.app.state.hub
    assert client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "m",
                                                   "api_key": PROVIDER_KEY}).status_code == 201
    add_tool(client, "hooked", "Hooked", events={"emits": [], "listens": [], "webhook_url": WEBHOOK})
    network.store_backup(hub, "fw", {"content": f"set system password {BACKUP_SECRET}"}, reason="manual", actor="test")
    hub.approvals.create("command", "Run uptime on the hub", "", {"target": "local", "secret": PAYLOAD_SECRET}, "user:x")
    hub.activity("module:assets", "error", "Inventory sync failed", password=ACTIVITY_SECRET)
    client.post("/api/grc/evaluate")
    configs = every_type_configs()
    assert {t for t, _ in configs} == set(registry.REGISTRY), "a widget type is missing from the secret walk"
    widgets, y = [], 0
    for n, (type_, config) in enumerate(configs):
        widgets.append(widget(type_, config, 0, y, wid=f"w_{n:08d}"))
        y += widgets[-1]["h"]
    secrets = (TOKEN, WEBHOOK, "dash-hook-secret-31c9", PROVIDER_KEY, BACKUP_SECRET, ALERT_SECRET, ACTIVITY_SECRET,
               PAYLOAD_SECRET, "ada@example.com", "bob@example.com")
    d = saved(client, create(client, "Everything"), widgets)
    viewer = sign_in("viewer")
    shared = saved(client, create(client, "Shared everything", scope="shared"), widgets)
    for who, board in ((client, d), (client, shared), (viewer, shared)):
        results = data(who, board)
        expected = {f"w_{n:08d}" for n, (t, _) in enumerate(configs)
                    if registry.allowed("admin" if who is client else "viewer", registry.REGISTRY[t].min_role)}
        assert {k for k, r in results.items() if r["status"] in ("ok", "empty")} == expected, {
            k: (r["status"], r["message"]) for k, r in results.items()}
        for document in (results, who.get(f"/api/dashboards/{board['id']}").json(), who.get("/api/dashboards").json()):
            text = json.dumps(document)
            assert not [s for s in secrets if s in text]
        for wid, result in results.items():
            for path, key, _ in walk(result["data"]):
                assert key not in FORBIDDEN_KEYS, f"{wid}: {path}.{key}"
    for who in (client, viewer):
        assert not [s for s in secrets if s in json.dumps(who.get("/api/widgets/catalog").json())]


@pytest.mark.parametrize("method,path,body", [
    ("POST", "/api/dashboards/mine", {"title": "x"}),
    ("PUT", "/api/dashboards/mine/{mine}", {"title": "x", "widgets": [], "base_version": 1}),
    ("DELETE", "/api/dashboards/mine/{mine}", None),
    ("PUT", "/api/dashboards/prefs", {"order": []}),
    ("POST", "/api/dashboards/shared", {"title": "x"}),
    ("PUT", "/api/dashboards/shared/{shared}", {"title": "x", "widgets": [], "base_version": 1}),
    ("DELETE", "/api/dashboards/shared/{shared}", None),
    ("PUT", "/api/dashboards/default", {"dashboard_id": "{shared}"}),
])
def test_every_dashboard_change_needs_the_cross_site_header(client, method, path, body):
    """Section 11 item 8: no dashboard write without X-Hub-Request, whatever the role (an administrator here)."""
    ids = {"mine": create(client)["id"], "shared": create(client, "Team", scope="shared")["id"]}
    body = json.loads(json.dumps(body).replace("{shared}", ids["shared"])) if body else None
    response = client.request(method, path.format(**ids), json=body, headers={"X-Hub-Request": ""})
    assert response.status_code == 403 and "X-Hub-Request" in response.json()["detail"]
    assert client.get(f"/api/dashboards/{ids['mine']}").json()["version"] == 1
    assert client.get(f"/api/dashboards/{ids['shared']}").json()["version"] == 1


def test_only_a_shared_dashboard_can_be_the_default(client, sign_in):
    """An administrator's own dashboard never becomes everyone's Home, and nobody reaches another person's dashboard
    through the default or a copy."""
    mine = create(client, "Admin's own")
    response = client.put("/api/dashboards/default", json={"dashboard_id": mine["id"]})
    assert response.status_code == 422
    viewer = sign_in("viewer")
    theirs = create(viewer, "Viewer's own")
    assert client.post("/api/dashboards/shared", json={"title": "x", "from": theirs["id"]}).status_code == 404
    assert viewer.post("/api/dashboards/mine", json={"title": "x", "from": mine["id"]}).status_code == 404


def test_leavers_from_projections_match_the_people_app(client, sign_in):
    """The dashboards find leavers over the people who left and what links to them only (spec 8.3); the findings are
    exactly the People app's, and the counts on Home are the same as the Overview's."""
    from hub import people
    from hub.models import Account, Person

    hub = client.app.state.hub
    sign_in("viewer", "carol", email="carol@example.com")  # an enabled Atrium account of a leaver
    for pid, name, status, email in (("p_ann", "Ann", "active", "ann@example.com"),
                                     ("p_bob", "Bob", "terminated", "bob@example.com"),
                                     ("p_carol", "Carol", "suspended", "carol@example.com"),
                                     ("p_dan", "Dan", "terminated", "dan@example.com"),
                                     ("p_eve", "Eve", "terminated", "eve@example.com")):
        hub.save("people", Person(id=pid, display_name=name, status=status, email=email), "person")
    for aid, owner, assigned, status in (("a_1", "p_bob", None, "active"), ("a_2", None, "p_bob", "maintenance"),
                                         ("a_3", "p_bob", "p_bob", "retired"), ("a_4", "p_ann", None, "active"),
                                         ("a_5", None, "p_eve", "active")):
        hub.save("assets", Asset(id=aid, name=f"host-{aid}", status=status, owner_person_id=owner,
                                 assigned_person_id=assigned), "asset")
    hub.save("accounts", Account(id="t|1", tool_id="t", external_id="1", login="dan", person_id="p_dan"), "account")
    hub.save("accounts", Account(id="t|2", tool_id="t", external_id="2", login="eve", person_id="p_eve",
                                 active=False), "account")
    found = resolve_module.Snapshot(hub).leavers
    assert found == people.leavers(hub)
    assert [f["person_id"] for f in found] == ["p_carol", "p_dan", "p_bob", "p_eve"]
    assert [a["id"] for a in found[2]["assets"]] == ["a_1", "a_2"]  # not the retired one
    ov = client.get("/api/overview").json()
    assert ov["leavers"] == 4 and ov["people"] == len(people.all_people(hub))
    tile = preview(client, "metric", {"metric": "people"})["data"]
    assert tile["value"] == ov["people"] and tile["href"] == "#/people/leavers"
    assert preview(client, "leavers", {"limit": 10})["data"]["total"] == 4
