"""The integration map's backend (docs/research/canvas-design.md 7.1-7.4, 13/A2-A3): the map read model, the Connect
panel's options, data flows a person draws (POST /api/flows), the loop rule (review-notes F7), the shared canvas layouts
and what viewers never see (F24) - with the in-memory fake connectors of test_fabric."""

from __future__ import annotations

import json
import math
from typing import Any

import pytest
from test_fabric import TOKEN, Fake, FakeGrc, FakeInventory, FakeScanner, Remote, add_tool, connect, flows_of

from hub import connectors, guardrails
from hub.integration import canvas, connections, strategies
from hub.models import Manifest, Patch, SsoPlan, Tool

WEBHOOK = "https://hooks.example.com/in?token=hook-secret-77aa"
PAYLOAD_SECRET = "payload-data-5c1e"


class FakeCmdb(Fake):
    """Reads and writes assets without being their system of record: the planner pushes Hub Assets to it."""

    kind, title = "fake_cmdb", "Fake CMDB"
    capabilities = {"assets": {"read", "write"}}


class FakeTracker(Fake):
    """Reads and writes vulnerabilities and does not scan: the planner pulls (loop rule)."""

    kind, title = "fake_tracker", "Fake Tracker"
    capabilities = {"vulnerabilities": {"read", "write"}}


class FakeDirectory(Fake):
    kind, title = "fake_directory", "Fake Directory"
    capabilities = {"people": {"read"}, "accounts": {"read"}}
    system_of_record = {"people"}


@pytest.fixture
def remote(client, monkeypatch) -> Remote:
    state = Remote()
    for cls in (FakeInventory, FakeGrc, FakeScanner, FakeCmdb, FakeTracker, FakeDirectory):
        monkeypatch.setattr(cls, "remote", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    return state


def walk(value: Any, path: str = "$"):
    """Every (path, key, value) in a JSON document."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield path, k, v
            yield from walk(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from walk(v, f"{path}[{i}]")


def assert_viewer_safe(document: Any) -> None:
    """F24: no connection config or secrets, no webhook URL, no toolbus payload - by key and by value."""
    text = json.dumps(document)
    for secret in (TOKEN, WEBHOOK, "hook-secret-77aa", PAYLOAD_SECRET):
        assert secret not in text
    for path, key, value in walk(document):
        assert key not in ("config", "secrets", "payload", "webhook_url"), f"{path}.{key}"
        if key == "webhook":
            assert isinstance(value, bool), path


def suite(client) -> None:
    """inventory (system of record for assets), grc (takes assets, controls, vulnerabilities; reads risks), scanner,
    an identity provider with one tool signed in through it and one waiting for an SSO patch, and event routes."""
    hub = client.app.state.hub
    add_tool(client, "inventory", "Inventory", events={"emits": ["asset.created"], "listens": []})
    add_tool(client, "grc", "GRC Tool", events={"emits": [], "listens": ["asset.*"], "webhook_url": WEBHOOK})
    add_tool(client, "scanner", "Scanner")
    add_tool(client, "keycloak", "Keycloak", provides=["auth.oidc"])
    add_tool(client, "wiki", "Wiki", auth={"sso": "oidc", "provider": "keycloak"})
    add_tool(client, "crm", "CRM", auth={"sso": "oidc"})
    hub.save_patch(Patch(id="pa_sso", tool_id="crm", title="Sign in through Keycloak", rationale="SSO", strategy="sso_connect",
                         target="adapter", sso=SsoPlan(provider="keycloak", provider_name="Keycloak", protocol="oidc",
                                                       client_id="crm")))
    connect(client, "inventory", "fake_inventory")
    connect(client, "grc", "fake_grc")
    connect(client, "scanner", "fake_scanner")


# -- the map --------------------------------------------------------------------------------------


def test_map_payload_is_complete_and_safe_for_viewers(client, remote, sign_in, wait_for):
    hub = client.app.state.hub
    suite(client)
    client.post("/api/flows/plan")
    hub.store.append("toolbus", {"source": "inventory", "event": "asset.created", "payload": {"note": PAYLOAD_SECRET},
                                 "deliveries": [{"to": "grc", "ok": False, "detail": f"POST {WEBHOOK} failed"}]})
    viewer = sign_in("viewer")
    response = viewer.get("/api/integration/map")
    assert response.status_code == 200, response.text
    data = response.json()
    assert_viewer_safe(data)

    apps = {a["id"]: a for a in data["apps"]}
    assert list(apps)[:5] == ["app:assets", "app:vulnerabilities", "app:compliance", "app:people", "app:network"]
    assert apps["app:compliance"]["domains"] == ["controls", "risks", "frameworks", "assessments"]
    assert apps["app:people"]["domains"] == ["people", "accounts"] and apps["app:network"]["domains"] == ["network"]

    nodes = {n["id"]: n for n in data["nodes"]}
    assert set(nodes) == {f"tool:{t}" for t in ("inventory", "grc", "scanner", "keycloak", "wiki", "crm")}
    inv = nodes["tool:inventory"]
    assert inv["connection"] == {"kind": "fake_inventory", "generated": False, "known": True, "tested": None}
    assert inv["capabilities"] == {"assets": ["read", "write"]} and inv["system_of_record"] == ["assets"]
    assert inv["lane_default"] == "left" and nodes["tool:grc"]["lane_default"] == "right"
    assert nodes["tool:scanner"]["lane_default"] == "right" and nodes["tool:scanner"]["actions"] == ["scan", "scan_status"]
    assert nodes["tool:keycloak"]["is_idp"] and nodes["tool:keycloak"]["lane_default"] == "idp"
    assert nodes["tool:wiki"]["lane_default"] == "shelf" and nodes["tool:wiki"]["connection"] is None

    # flows exactly as GET /api/flows shows them
    assert sorted(f["id"] for f in data["flows"]) == sorted(f["id"] for f in viewer.get("/api/flows").json())
    assert {f["domain"] for f in data["flows"] if f["tool_id"] == "grc"} == {"assets", "controls", "risks", "vulnerabilities"}

    # one SSO edge per connected or pending tool
    sso = {e["id"]: e for e in data["sso"]}
    assert sso == {
        "sso:wiki": {"id": "sso:wiki", "source": "tool:keycloak", "target": "tool:wiki", "state": "connected",
                     "protocol": "oidc", "approval_id": None},
        "sso:crm": {"id": "sso:crm", "source": "tool:keycloak", "target": "tool:crm", "state": "pending",
                    "protocol": "oidc", "approval_id": None}}

    # event edges come from the routes (not suite_matrix's event/identity links), with the last delivery
    [event] = data["events"]
    assert event["id"] == "event:inventory:grc:asset.created" and event["source"] == "tool:inventory"
    assert event["target"] == "tool:grc" and event["pattern"] == "asset.*" and event["has_webhook"] is True
    assert event["last_delivery"]["ok"] is False
    assert all(link["id"].startswith("cap:") for link in data["capability_links"])
    assert data["identity"]["tools"] and data["layout"] == {"id": "integration", "version": 0, "items": {}}
    assert data["guardrails"] == {"scans_need_approval": True} and data["autonomy"] == "assisted"


def test_integration_overview_hides_webhook_urls_and_payloads(client, remote, sign_in):
    hub = client.app.state.hub
    suite(client)
    hub.store.append("toolbus", {"source": "inventory", "event": "asset.created", "payload": {"note": PAYLOAD_SECRET},
                                 "deliveries": [{"to": "grc", "ok": True, "detail": f"HTTP 200 from {WEBHOOK}"}]})
    data = sign_in("viewer").get("/api/integration").json()
    assert_viewer_safe(data)
    [route] = data["routes"]
    assert route["webhook"] is True and route["has_webhook"] is True  # the UI badge still works
    [entry] = data["deliveries"]
    assert entry["event"] == "asset.created" and entry["deliveries"] == [{"to": "grc", "ok": True, "detail": "HTTP 200 from <url>"}]


def test_toolbus_events_on_the_stream_carry_no_payload(client, remote):
    hub = client.app.state.hub
    add_tool(client, "grc", "GRC Tool", events={"listens": ["ping"], "webhook_url": "http://127.0.0.1:9/hook?token=hook-secret-77aa"})
    queue = hub.bus.subscribe()
    try:
        deliveries = client.portal.call(hub.toolbus.publish, "inventory", "ping", {"note": PAYLOAD_SECRET})
        assert deliveries[0]["to"] == "grc" and not deliveries[0]["ok"]
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
    finally:
        hub.bus.unsubscribe(queue)
    [event] = [e for e in events if e["type"] == "toolbus"]
    assert event["data"]["event"] == "ping" and "payload" not in event["data"]
    assert PAYLOAD_SECRET not in json.dumps(events) and "hook-secret-77aa" not in json.dumps(events)
    assert hub.store.tail("toolbus", 1)[0]["payload"] == {"note": PAYLOAD_SECRET}  # the log itself keeps it


def test_tool_reads_events_and_bus_log_carry_no_webhook_url(client, remote, sign_in):
    """F24 beyond the map: GET /api/tools, GET /api/tools/{id}, the `tool` SSE event and the agent bus log (which
    viewers read) say whether a webhook is set, never the URL, and name the launch environment's keys only."""
    hub = client.app.state.hub
    env_secret = "env-secret-9f3b"
    queue = hub.bus.subscribe()
    try:
        add_tool(client, "grc", "GRC Tool", events={"listens": ["asset.*"], "webhook_url": WEBHOOK},
                 launch={"command": "run", "env": {"API_KEY": env_secret, "PORT": "4000"}})
        described = client.portal.call(hub.bus.request, "user:admin", "tool:grc", "describe")
        events = []
        while not queue.empty():
            events.append(queue.get_nowait())
    finally:
        hub.bus.unsubscribe(queue)
    stored = hub.get_tool("grc")
    assert stored.manifest.events.webhook_url == WEBHOOK and stored.manifest.launch.env["API_KEY"] == env_secret

    viewer = sign_in("viewer")
    listed = next(t for t in viewer.get("/api/tools").json() if t["id"] == "grc")
    one = viewer.get("/api/tools/grc").json()
    [tool_event] = [e["data"] for e in events if e["type"] == "tool"]
    messages = viewer.get("/api/messages").json()
    for document in (listed, one, tool_event, described["tool"], events, messages):
        assert_viewer_safe(document)
        assert env_secret not in json.dumps(document)
    for document in (listed, one, tool_event, described["tool"]):
        assert document["manifest"]["events"] == {"emits": [], "listens": ["asset.*"], "has_webhook": True}
        assert document["manifest"]["launch"]["env_keys"] == ["API_KEY", "PORT"]
        assert "env" not in document["manifest"]["launch"]
    assert stored.manifest.public()["events"]["has_webhook"] is True  # also the analyse reply's form
    assert Manifest(id="x", name="X").public()["events"]["has_webhook"] is False


def test_lane_defaults():
    tool = Tool(id="t", name="T", source_type="saas", source="https://t.example.com", manifest=Manifest(id="t", name="T"))
    idp = tool.model_copy(update={"manifest": Manifest(id="t", name="T", provides=["auth.oidc"])})
    conn = connections.Connection(id="t", kind="x")
    from hub.models import Flow

    def flow(direction: str, status: str = "enabled") -> Flow:
        return Flow(id=f"fl_{direction}_{status}", domain="assets", source="tool:t" if direction == "pull" else "hub",
                    target="hub" if direction == "pull" else "tool:t", status=status)  # type: ignore[arg-type]

    assert canvas.lane_default(tool, None, {}, [], []) == "shelf"
    assert canvas.lane_default(idp, None, {}, [], []) == "idp"
    assert canvas.lane_default(idp, conn, {"people": ["read"]}, [], []) == "left"  # an IdP with a data connection
    assert canvas.lane_default(tool, conn, {"assets": ["read"]}, [], []) == "left"
    assert canvas.lane_default(tool, conn, {"assets": ["read", "write"]}, [], []) == "right"
    assert canvas.lane_default(tool, conn, {"vulnerabilities": ["read"]}, ["scan"], []) == "right"
    assert canvas.lane_default(tool, conn, {}, [], [flow("pull"), flow("pull"), flow("push")]) == "left"
    assert canvas.lane_default(tool, conn, {}, [], [flow("pull"), flow("push", "proposed")]) == "right"
    assert canvas.lane_default(tool, conn, {"assets": ["write"]}, [], [flow("pull"), flow("push", "disabled")]) == "left"


def test_map_scales_to_200_tools_and_400_flows(client, remote):
    """canvas-design 7.1 asks to measure the map with 200 tools: it stays one pass over the store."""
    import time

    hub = client.app.state.hub
    for i in range(200):
        hub.save_tool(Tool(id=f"t{i}", name=f"Tool {i}", source_type="saas", source=f"https://t{i}.example.com",
                           status="ready", manifest=Manifest(id=f"t{i}", name=f"Tool {i}", kind="saas")))
        hub.store.put("connections", connections.Connection(id=f"t{i}", kind="fake_cmdb").model_dump(mode="json"))
    from hub.integration import flows as flow_store

    for i in range(200):
        for source, target in ((f"tool:t{i}", "hub"), ("hub", f"tool:t{i}")):
            flow_store.save(hub, flow_store.make(hub, "assets", source, target, status="disabled"))
    started = time.perf_counter()
    data = client.get("/api/integration/map").json()
    elapsed = time.perf_counter() - started
    assert len(data["nodes"]) == 200 and len(data["flows"]) == 400
    assert elapsed < 15, elapsed  # generous: a CI box; measured locally in the report


# -- the Connect panel's options ------------------------------------------------------------------


def options(client, a: str, b: str) -> dict:
    response = client.get(f"/api/integration/map/options?a={a}&b={b}")
    assert response.status_code == 200, response.text
    return response.json()


def test_options_between_a_tool_and_a_hub_app(client, remote, sign_in):
    suite(client)
    viewer = sign_in("viewer")
    inv = options(viewer, "tool:inventory", "app:assets")
    by_id = {o["id"]: o for o in inv["options"]}
    assert set(by_id) == {"pull:assets", "push:assets"} and inv["options"][0]["id"] == "pull:assets"
    pull, push = by_id["pull:assets"], by_id["push:assets"]
    assert pull["recommended"] and "system of record" in pull["reason"] and pull["blocked"] is None
    assert pull["parts"][0] | {"exists": None} == pull["parts"][0]
    part = pull["parts"][0]
    assert (part["source"], part["target"], part["action"], part["direction"]) == ("tool:inventory", "hub", None, "pull")
    assert part["title"] == "Inventory assets -> Hub Assets" and part["default_schedule"] == 60
    assert not push["recommended"] and push["blocked"] == \
        "Inventory is the system of record for assets; the hub never pushes assets to it."

    scan = options(viewer, "app:vulnerabilities", "tool:scanner")  # whichever way the arrow was drawn
    by_id = {o["id"]: o for o in scan["options"]}
    assert set(by_id) == {"scan:vulnerabilities", "pull:vulnerabilities"}
    assert by_id["scan:vulnerabilities"]["recommended"] and by_id["scan:vulnerabilities"]["parts"][0]["default_schedule"] == 7 * 24 * 60
    assert not by_id["pull:vulnerabilities"]["recommended"]
    assert by_id["pull:vulnerabilities"]["reason"] == "Findings already arrive through the scan flow."

    grc = {o["id"]: o for o in options(viewer, "tool:grc", "app:compliance")["options"]}
    assert set(grc) == {"push:controls", "pull:risks"} and all(o["recommended"] for o in grc.values())
    none = options(viewer, "tool:scanner", "app:people")
    assert none["options"] == [] and none["notes"] == ["Scanner cannot exchange people, accounts with People."]
    unconnected = options(viewer, "tool:wiki", "app:assets")
    assert unconnected["options"] == [] and unconnected["needs_connection"] == ["wiki"]
    assert unconnected["notes"][0].startswith("Set up the connection first")
    assert options(viewer, "app:assets", "app:people")["notes"] == ["Hub apps share data internally."]
    assert options(viewer, "tool:grc", "tool:grc")["notes"] == ["Choose two different items."]
    assert viewer.get("/api/integration/map/options?a=tool:nope&b=app:assets").status_code == 404
    assert viewer.get("/api/integration/map/options?a=tool:grc&b=app:nope").status_code == 404
    assert viewer.get("/api/integration/map/options?a=tool:grc").status_code == 404


def test_options_between_two_tools_are_chains_through_the_hub(client, remote):
    suite(client)
    data = options(client, "tool:inventory", "tool:grc")
    assert [o["id"] for o in data["options"]] == ["chain:inventory>grc:assets"]
    [chain] = data["options"]
    assert chain["title"] == "Inventory -> Hub Assets -> GRC Tool" and chain["recommended"]
    assert [(p["source"], p["target"]) for p in chain["parts"]] == [("tool:inventory", "hub"), ("hub", "tool:grc")]
    assert "system of record" in chain["reason"] and "canonical list" in chain["reason"]
    assert data["events"] == [{"id": "event:inventory:grc:asset.created", "source": "tool:inventory", "target": "tool:grc",
                               "from": "inventory", "to": "grc", "event": "asset.created", "pattern": "asset.*",
                               "has_webhook": True}]
    assert_viewer_safe(data)
    scans = options(client, "tool:grc", "tool:scanner")
    [chain] = scans["options"]
    assert chain["id"] == "chain:scanner>grc:vulnerabilities"
    assert [p["direction"] for p in chain["parts"]] == ["scan", "push"] and chain["recommended"]
    assert options(client, "tool:scanner", "tool:inventory")["notes"] == ["No data these two can exchange through the hub."]

    # existing parts are shown, not re-created: approve the planned flows and ask again
    client.post("/api/flows/plan")
    again = options(client, "tool:inventory", "tool:grc")["options"][0]
    assert all(p["exists"] and p["exists"]["status"] == "proposed" for p in again["parts"])


def test_options_for_single_sign_on(client, remote):
    suite(client)
    data = options(client, "tool:keycloak", "tool:wiki")
    assert data["sso"] == {"tool_id": "wiki", "provider": "keycloak", "status": "connected", "connected_to": "keycloak",
                           "pending_provider": None}
    pending = options(client, "tool:crm", "tool:keycloak")["sso"]
    assert pending["status"] == "pending" and pending["pending_provider"] == "keycloak"
    add_tool(client, "authentik", "authentik", provides=["auth.oidc"])
    both = options(client, "tool:keycloak", "tool:authentik")
    assert both["sso"] is None and "Identity providers do not sign in through each other." in both["notes"]


def test_recommended_options_are_exactly_the_planners_proposals(client, remote):
    """The Connect panel and the planner share tool_rules: for every connected tool and hub app, the recommended
    options are the flows the planner proposes, with the same reasons."""
    for tool_id, kind in (("inventory", "fake_inventory"), ("grc", "fake_grc"), ("scanner", "fake_scanner"),
                          ("cmdb", "fake_cmdb"), ("tracker", "fake_tracker"), ("directory", "fake_directory")):
        add_tool(client, tool_id, tool_id.title())
        connect(client, tool_id, kind)
    hub = client.app.state.hub
    planned = {(f.domain, f.source, f.target, f.action): f.reason for f in strategies.proposals(hub)}
    recommended = {}
    for tool_id in ("inventory", "grc", "scanner", "cmdb", "tracker", "directory"):
        for app in strategies.hub_apps(hub):
            for option in options(client, f"tool:{tool_id}", app["id"])["options"]:
                if option["recommended"]:
                    [part] = option["parts"]
                    recommended[(part["domain"], part["source"], part["target"], part["action"])] = option["reason"]
    assert recommended == planned


# -- the planner and the loop rule ----------------------------------------------------------------


def planned(client, kind: str) -> set[tuple]:
    hub = client.app.state.hub
    add_tool(client, "t", "T")
    connect(client, "t", kind)
    return {(f.domain, f.source, f.target, f.action) for f in strategies.proposals(hub)}


@pytest.mark.parametrize("kind,expected", [
    ("fake_inventory", {("assets", "tool:t", "hub", None)}),
    ("fake_grc", {("assets", "hub", "tool:t", None), ("controls", "hub", "tool:t", None), ("risks", "tool:t", "hub", None),
                  ("vulnerabilities", "hub", "tool:t", None)}),
    ("fake_scanner", {("vulnerabilities", "hub", "tool:t", "scan")}),
    ("fake_cmdb", {("assets", "hub", "tool:t", None)}),
    ("fake_directory", {("people", "tool:t", "hub", None), ("accounts", "tool:t", "hub", None)}),
    # a tool that reads and writes vulnerabilities without scanning: the pull only (it never got both)
    ("fake_tracker", {("vulnerabilities", "tool:t", "hub", None)}),
])
def test_planner_proposals_are_unchanged_for_the_fixtures(client, remote, kind, expected):
    assert planned(client, kind) == expected


def test_planner_never_proposes_a_loop_next_to_a_flow_drawn_by_hand(client, remote):
    hub = client.app.state.hub
    add_tool(client, "cmdb", "CMDB")
    connect(client, "cmdb", "fake_cmdb")
    pull = client.post("/api/flows", json={"domain": "assets", "source": "tool:cmdb", "target": "hub"})
    assert pull.status_code == 201, pull.text
    assert strategies.proposals(hub) == []  # the push the rules call for would loop with the proposed pull
    assert client.post("/api/flows/plan").json()["proposed"] == []


# -- POST /api/flows ------------------------------------------------------------------------------


def test_drawn_flow_is_proposed_by_the_supervisor_and_enabled_on_approval(client, remote, sign_in, wait_for):
    hub = client.app.state.hub
    suite(client)
    operator = sign_in("operator", "alice")
    response = operator.post("/api/flows", json={"domain": "assets", "source": "tool:inventory", "target": "hub",
                                                 "schedule_minutes": 30, "options": {"retire_missing": False}})
    assert response.status_code == 201, response.text
    flow, approval_id = response.json()["flow"], response.json()["approval_id"]
    assert flow["status"] == "proposed" and flow["created_by"] == "alice" and flow["approval_id"] == approval_id
    assert flow["schedule_minutes"] == 30 and flow["options"] == {"retire_missing": False}
    assert flow["title"] == "Inventory assets -> Hub Assets" and "system of record" in flow["reason"]
    approval = hub.approvals.get(approval_id)
    assert approval.kind == "flow" and approval.requested_by == "supervisor"
    assert approval.payload["proposed_by"] == "alice" and approval.payload["flow_id"] == flow["id"]
    assert any(e["actor"] == "alice" and e["text"].startswith("Proposed data flow: Inventory assets")
               for e in hub.store.tail("activity", 50))
    # the proposer may approve while approvals_need_second_person is off (the default) ...
    decided = operator.post(f"/api/approvals/{approval_id}", json={"approve": True})
    assert decided.status_code == 200, decided.text
    wait_for(lambda: next(f for f in flows_of(client, "inventory") if f["id"] == flow["id"])["status"] == "enabled")
    wait_for(lambda: hub.approvals.get(approval_id).status == "done")

    # ... and not while it is on (review-notes F1)
    assert client.patch("/api/settings/guardrails", json={"approvals_need_second_person": True}).status_code == 200
    assert guardrails.value(hub, "approvals_need_second_person") is True
    second = operator.post("/api/flows", json={"domain": "controls", "source": "hub", "target": "tool:grc"}).json()
    refused = operator.post(f"/api/approvals/{second['approval_id']}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "same_person"
    # nor by enabling it in the flow list or from the map's inspector (PATCH): refused before anything changes
    flow_id = second["flow"]["id"]
    enabled = operator.patch(f"/api/flows/{flow_id}", json={"status": "enabled", "schedule_minutes": 5})
    assert enabled.status_code == 403 and enabled.json()["detail"]["code"] == "same_person"
    stored = next(f for f in flows_of(client, "grc") if f["id"] == flow_id)
    assert stored["status"] == "proposed" and stored["approval_id"] == second["approval_id"]
    assert stored["schedule_minutes"] == second["flow"]["schedule_minutes"]
    assert hub.approvals.get(second["approval_id"]).status == "pending"
    assert client.post(f"/api/approvals/{second['approval_id']}", json={"approve": True}).status_code == 200


@pytest.mark.parametrize("autonomy", ["manual", "autonomous"])
def test_autonomy_decides_whether_a_drawn_flow_waits(client, remote, autonomy):
    hub = client.app.state.hub
    suite(client)
    client.patch("/api/settings", json={"autonomy": autonomy})
    body = client.post("/api/flows", json={"domain": "vulnerabilities", "source": "hub", "target": "tool:scanner",
                                           "action": "scan"}).json()
    if autonomy == "autonomous":
        assert body["flow"]["status"] == "enabled" and body["approval_id"] is None
    else:  # manual behaves like assisted
        assert body["flow"]["status"] == "proposed" and hub.approvals.get(body["approval_id"]).requested_by == "supervisor"
    assert body["flow"]["direction"] == "scan" and body["flow"]["schedule_minutes"] == 7 * 24 * 60


def test_drawn_flows_are_refused_with_codes(client, remote, sign_in):
    suite(client)

    def create(**body) -> tuple[int, dict]:
        response = client.post("/api/flows", json=body)
        return response.status_code, response.json()

    status, body = create(domain="controls", source="tool:grc", target="hub")
    assert status == 400 and body["detail"]["code"] == "no_capability"
    status, body = create(domain="assets", source="hub", target="tool:inventory")
    assert status == 400 and body["detail"] == {
        "code": "system_of_record", "message": "Inventory is the system of record for assets; the hub never pushes assets to it."}
    status, body = create(domain="assets", source="tool:wiki", target="hub")
    assert status == 400 and body["detail"]["code"] == "no_connection"
    status, body = create(domain="assets", source="tool:nope", target="hub")
    assert status == 404 and body["detail"]["code"] == "not_found"
    for bad in ({"domain": "assets", "source": "hub", "target": "hub"},
                {"domain": "assets", "source": "tool:inventory", "target": "tool:grc"},
                {"domain": "assets", "source": "tool:../x", "target": "hub"},
                {"domain": "spaceships", "source": "tool:inventory", "target": "hub"},
                {"domain": "assets", "source": "hub", "target": "tool:scanner", "action": "scan"},
                {"domain": "vulnerabilities", "source": "tool:scanner", "target": "hub", "action": "scan"},
                {"domain": "assets", "source": "tool:inventory", "target": "hub", "options": {"min_severity": "high"}}):
        status, body = create(**bad)
        assert status == 400 and body["detail"]["code"] == "invalid", bad
    assert create(domain="assets", source="tool:inventory", target="hub", actor="bob")[0] == 422  # never from the body
    assert create(domain="assets", source="tool:inventory", target="hub", schedule_minutes=-1)[0] == 422

    first = create(domain="assets", source="tool:inventory", target="hub")
    assert first[0] == 201
    status, body = create(domain="assets", source="tool:inventory", target="hub")
    assert status == 409 and body["detail"]["code"] == "flow_exists" and body["detail"]["flow_id"] == first[1]["flow"]["id"]
    assert sign_in("viewer").post("/api/flows", json={"domain": "assets", "source": "tool:inventory",
                                                      "target": "hub"}).status_code == 403


def test_the_loop_rule_on_create_enable_and_approval(client, remote, wait_for):
    hub = client.app.state.hub
    add_tool(client, "cmdb", "CMDB")
    connect(client, "cmdb", "fake_cmdb")
    push = client.post("/api/flows", json={"domain": "assets", "source": "hub", "target": "tool:cmdb"}).json()["flow"]
    refused = client.post("/api/flows", json={"domain": "assets", "source": "tool:cmdb", "target": "hub"})
    assert refused.status_code == 409 and refused.json()["detail"] == {
        "code": "flow_conflict", "flow_id": push["id"],
        "message": "Hub Assets already sends assets to CMDB; pulling them back would loop records."}
    blocked = {o["id"]: o for o in options(client, "tool:cmdb", "app:assets")["options"]}["pull:assets"]
    assert blocked["blocked"].startswith("Hub Assets already sends assets to CMDB") and blocked["parts"][0]["code"] == "flow_conflict"

    # once the push is disabled the pull may be drawn; enabling the push again is refused while the pull is live
    assert client.patch(f"/api/flows/{push['id']}", json={"status": "disabled"}).status_code == 200
    pull = client.post("/api/flows", json={"domain": "assets", "source": "tool:cmdb", "target": "hub"})
    assert pull.status_code == 201, pull.text
    enable = client.patch(f"/api/flows/{push['id']}", json={"status": "enabled", "schedule_minutes": 5})
    assert enable.status_code == 409 and enable.json()["detail"]["code"] == "flow_conflict"
    assert enable.json()["detail"]["message"] == "CMDB's assets already come into Hub Assets; sending them back would loop records."
    assert next(f for f in flows_of(client, "cmdb") if f["id"] == push["id"])["schedule_minutes"] == 60  # nothing changed
    assert client.patch(f"/api/flows/{pull.json()['flow']['id']}", json={"status": "enabled"}).status_code == 200

    # an approval cannot enable a loop either (e.g. two proposals left from before this rule)
    from hub.integration import flows as flow_store

    legacy = flow_store.make(hub, "assets", "hub", "tool:cmdb", status="proposed")
    hub.store.delete("flows", push["id"])
    approval = hub.approvals.create("flow", "legacy", "", {"flow_id": legacy.id}, "supervisor")
    legacy.approval_id = approval.id
    flow_store.save(hub, legacy)
    assert client.post(f"/api/approvals/{approval.id}", json={"approve": True}).status_code == 200
    wait_for(lambda: hub.approvals.get(approval.id).status == "failed")
    assert flow_store.get(hub, legacy.id).status == "disabled"
    assert hub.approvals.get(approval.id).result == {"status": "disabled", "error": "flow_conflict",
                                                      "flow_id": pull.json()["flow"]["id"]}


def test_flows_create_takes_the_proposer_from_the_sender(client, remote):
    hub = client.app.state.hub
    suite(client)
    reply = client.portal.call(hub.bus.request, "user:carol", "supervisor", "flows.create",
                               {"domain": "risks", "source": "tool:grc", "target": "hub", "actor": "mallory"})
    assert reply["flow"]["created_by"] == "carol" and hub.approvals.get(reply["approval_id"]).payload["proposed_by"] == "carol"
    refused = client.portal.call(hub.bus.request, "user:carol", "supervisor", "flows.create",
                                 {"domain": "risks", "source": "tool:grc", "target": "hub", "schedule_minutes": "often"})
    assert refused["refused"]["code"] == "invalid"


# -- layouts --------------------------------------------------------------------------------------


def test_layouts_merge_per_id_and_publish(client, sign_in):
    hub = client.app.state.hub
    operator, viewer = sign_in("operator", "olga"), sign_in("viewer")
    assert viewer.get("/api/layouts/integration").json() == {"id": "integration", "version": 0, "items": {}}
    queue = hub.bus.subscribe()
    try:
        first = operator.patch("/api/layouts/integration", json={"items": {
            "tool:snipe-it": {"order": 1.5, "lane": "left"}, "app:assets": {"order": 2}}})
        assert first.status_code == 200, first.text
        assert first.json()["version"] == 1 and first.json()["updated_by"] == "olga"
        second = operator.patch("/api/layouts/integration", json={"items": {"tool:snipe-it": {"order": 0.25}},
                                                                   "remove": ["app:assets"]}).json()
        assert second["version"] == 2 and second["items"] == {"tool:snipe-it": {"order": 0.25, "lane": "left"}}
        third = operator.patch("/api/layouts/integration", json={"items": {"tool:snipe-it": {"order": 3, "lane": None}}}).json()
        assert third["items"] == {"tool:snipe-it": {"order": 3.0}}
        events = [queue.get_nowait() for _ in range(queue.qsize())]
    finally:
        hub.bus.unsubscribe(queue)
    published = [e["data"] for e in events if e["type"] == "canvas_layout"]
    assert published[0] == {"view": "integration", "version": 1, "ids": ["tool:snipe-it", "app:assets"],
                            "updated_by": "olga", "reset": False}
    assert [p["version"] for p in published] == [1, 2, 3]
    assert viewer.get("/api/layouts/integration").json()["version"] == 3

    # segmentation zones may carry device ids with "/" and spaces; the segmentation map shows the same document
    zone = operator.patch("/api/layouts/segmentation", json={"items": {"z:sw1:Gi1/0/1": {"order": 1},
                                                                       "z:fw:LAN zone": {"order": 2}}})
    assert zone.status_code == 200, zone.text
    assert viewer.get("/api/segmentation").json()["layout"]["items"] == zone.json()["items"]

    reset = operator.delete("/api/layouts/integration").json()
    assert reset["version"] == 4 and reset["items"] == {}
    assert any(e["text"] == "Reset the arrangement of the integration map" for e in hub.store.tail("activity", 20))
    assert viewer.patch("/api/layouts/integration", json={"items": {}}).status_code == 403
    assert viewer.delete("/api/layouts/integration").status_code == 403


@pytest.mark.parametrize("body", [
    {"items": {"snipe-it": {"order": 1}}},                         # no prefix
    {"items": {"tool:<script>": {"order": 1}}},                    # not a slug
    {"items": {"z:bad‮id": {"order": 1}}},                    # bidi control in a zone id
    {"items": {"tool:a": {"order": 1e10}}},                        # out of range
    {"items": {"tool:a": {"order": "first"}}},
    {"items": {"tool:a": {"order": 1, "lane": "middle"}}},
    {"items": {"app:assets": {"order": 1, "lane": "left"}}},       # lanes only for tools
    {"items": {"tool:a": {"order": 1, "hidden": True}}},           # no shared hiding (F18)
    {"hidden": ["tool:a"]},
    {"remove": ["nope"]},
])
def test_layout_validation(client, body):
    response = client.patch("/api/layouts/integration", json=body)
    assert response.status_code == 422, (body, response.text)
    assert client.get("/api/layouts/integration").json()["version"] == 0


def test_layout_rejects_non_finite_orders_bad_views_and_too_many_items(client):
    hub = client.app.state.hub
    nan = client.patch("/api/layouts/integration", content='{"items": {"tool:a": {"order": NaN}}}',
                       headers={"Content-Type": "application/json"})
    assert nan.status_code == 422
    assert client.patch("/api/layouts/segmentation", json={"items": {"tool:a": {"order": 1, "lane": "left"}}}).status_code == 422
    assert client.get("/api/layouts/canvas").status_code == 422
    assert client.patch("/api/layouts/other", json={"items": {}}).status_code == 422
    many = {f"tool:t{i}": {"order": i} for i in range(canvas.MAX_ITEMS)}
    assert client.patch("/api/layouts/integration", json={"items": many}).status_code == 200
    over = client.patch("/api/layouts/integration", json={"items": {"tool:one-more": {"order": 1}}})
    assert over.status_code == 422 and "at most 5000" in over.json()["detail"]["message"]
    assert len(hub.store.get("canvas_layouts", "integration")["items"]) == canvas.MAX_ITEMS
    assert client.patch("/api/layouts/integration", json={"items": {"tool:one-more": {"order": 1}},
                                                          "remove": ["tool:t0"]}).status_code == 200
    assert not math.isnan(client.get("/api/layouts/integration").json()["items"]["tool:one-more"]["order"])


class FakeRouter(Fake):
    kind, title = "fake_router", "Fake Router"
    capabilities = {"network": {"read"}}


def test_network_devices_connect_to_the_network_app_but_never_through_a_generated_connection(client, remote, monkeypatch):
    hub = client.app.state.hub
    monkeypatch.setattr(FakeRouter, "remote", remote, raising=False)
    monkeypatch.setitem(connectors.REGISTRY, "fake_router", FakeRouter)
    add_tool(client, "fw", "Edge FW")
    add_tool(client, "gen", "Generated FW")
    hub.store.put("connections", connections.Connection(id="fw", kind="fake_router").model_dump(mode="json"))
    hub.store.put("connections", connections.Connection(id="gen", kind="fake_router", generated=True).model_dump(mode="json"))
    [option] = options(client, "tool:fw", "app:network")["options"]
    assert option["id"] == "pull:network" and option["recommended"] and option["parts"][0]["default_schedule"] == 10
    generated = options(client, "tool:gen", "app:network")
    assert generated["options"] == [] and generated["notes"] == ["Generated FW cannot exchange network with Network."]
    refused = client.post("/api/flows", json={"domain": "network", "source": "tool:gen", "target": "hub"})
    assert refused.status_code == 400 and refused.json()["detail"]["code"] == "no_capability"
    assert "generated from its OpenAPI spec" in refused.json()["detail"]["message"]
    created = client.post("/api/flows", json={"domain": "network", "source": "tool:fw", "target": "hub"})
    assert created.status_code == 201 and created.json()["flow"]["owner"] == "module:network"
    nodes = {n["id"]: n for n in client.get("/api/integration/map").json()["nodes"]}
    assert nodes["tool:fw"]["lane_default"] == "left"


def test_flows_of_a_disabled_extension_keep_an_inactive_app(client):
    hub = client.app.state.hub
    from hub.integration import flows as flow_store

    flow_store.save(hub, flow_store.make(hub, "x:alerts", "tool:siem", "hub", status="disabled"))
    apps = {a["id"]: a for a in client.get("/api/integration/map").json()["apps"]}
    assert apps["app:x:alerts"] == {"id": "app:x:alerts", "label": "alerts", "domains": ["x:alerts"], "href": "#/x/alerts",
                                    "icon": "box", "extension": True, "active": False}
    assert client.get("/api/integration/map/options?a=tool:siem&b=app:x:alerts").status_code == 404
    refused = client.post("/api/flows", json={"domain": "x:alerts", "source": "tool:siem", "target": "hub"})
    assert refused.status_code == 400 and refused.json()["detail"]["code"] == "invalid"
