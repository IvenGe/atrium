"""Integration map, layouts, POST /api/flows, the pull/push loop rule, and viewer redaction (F24)."""

from __future__ import annotations

import pytest

from hub import connectors
from hub.integration import strategies
from test_fabric import FakeGrc, FakeInventory, Remote, add_tool, connect


@pytest.fixture
def remote(client, monkeypatch) -> Remote:
    state = Remote()
    for cls in (FakeInventory, FakeGrc):
        monkeypatch.setattr(cls, "remote", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    return state


def _walk(obj, path="$"):
    if isinstance(obj, dict):
        for key, value in obj.items():
            here = f"{path}.{key}"
            if key == "webhook" and isinstance(value, str) and value.startswith("http"):
                raise AssertionError(f"webhook URL at {here}: {value}")
            if key == "payload" and value not in (None, {}, []):
                raise AssertionError(f"toolbus payload at {here}")
            if key == "config" and isinstance(value, dict) and value and "connection" in path:
                raise AssertionError(f"connection config at {here}")
            _walk(value, here)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            _walk(value, f"{path}[{i}]")


def test_map_nodes_edges_and_options_match_the_planner(client, remote, wait_for):
    add_tool(client, "inventory", "Inventory", provides=["assets.inventory"])
    add_tool(client, "wiki", "Wiki")
    connect(client, "inventory", "fake_inventory")
    client.post("/api/tools/inventory/connection/test")
    wait_for(lambda: client.get("/api/flows?tool_id=inventory").json())

    payload = client.get("/api/integration/map").json()
    ids = {n["id"] for n in payload["nodes"]}
    assert {"tool:inventory", "tool:wiki"} <= ids
    app_ids = {a["id"] for a in payload["apps"]}
    assert {"app:assets", "app:vulnerabilities", "app:compliance", "app:people", "app:network"} <= app_ids
    inv = next(n for n in payload["nodes"] if n["id"] == "tool:inventory")
    assert inv["connection"]["kind"] == "fake_inventory" and "config" not in inv["connection"]
    assert inv["lane_default"] == "left"  # system of record: pull
    wiki = next(n for n in payload["nodes"] if n["id"] == "tool:wiki")
    assert wiki["connection"] is None and wiki["lane_default"] == "shelf"
    assert any(f["domain"] == "assets" and f["source"] == "tool:inventory" for f in payload["flows"])

    options = client.get("/api/integration/map/options",
                         params={"a": "tool:inventory", "b": "app:assets"}).json()
    planned = {(m.domain, m.source, m.target, m.action, bool(m.blocked))
               for m in strategies.moves(client.app.state.hub, "inventory") if m.domain == "assets"}
    shown = {(p["domain"], p["source"], p["target"], p["action"], bool(p["blocked"]))
             for o in options["options"] for p in o["parts"]}
    assert shown == planned
    pull = next(o for o in options["options"] if o["id"] == "pull:assets")
    push = next(o for o in options["options"] if o["id"] == "push:assets")
    assert pull["recommended"] and not pull["parts"][0]["blocked"]
    assert not push["recommended"] and "system of record" in (push["parts"][0]["blocked"] or "")

    missing = client.get("/api/integration/map/options", params={"a": "tool:nope", "b": "app:assets"})
    assert missing.status_code == 404


def test_layouts_save_load_and_sse(client, sign_in):
    empty = client.get("/api/layouts/integration").json()
    assert empty == {"id": "integration", "version": 0, "items": {}}
    saved = client.patch("/api/layouts/integration",
                         json={"items": {"tool:inventory": {"order": 1.5, "lane": "right"}}}).json()
    assert saved["version"] == 1 and saved["items"]["tool:inventory"] == {"order": 1.5, "lane": "right"}
    assert client.get("/api/layouts/integration").json()["version"] == 1
    viewer = sign_in("viewer")
    assert viewer.patch("/api/layouts/integration", json={"items": {}}).status_code == 403
    assert viewer.get("/api/layouts/integration").status_code == 200
    bad = client.patch("/api/layouts/integration", json={"items": {"nope": {"order": 1}}})
    assert bad.status_code == 400
    assert client.patch("/api/layouts/bogus", json={"items": {}}).status_code == 404
    bus = client.app.state.hub.bus
    events = []
    original = bus.publish
    bus.publish = lambda t, d, _orig=original: events.append((t, d)) or _orig(t, d)
    try:
        client.delete("/api/layouts/integration")
    finally:
        bus.publish = original
    assert any(t == "canvas_layout" and d["version"] == 0 for t, d in events)
    assert client.get("/api/layouts/integration").json()["version"] == 0


def test_post_flows_and_loop_conflict(client, remote, wait_for, sign_in):
    add_tool(client, "grc", "GRC Tool")
    connect(client, "grc", "fake_grc")
    created = client.post("/api/flows", json={"domain": "risks", "source": "tool:grc", "target": "hub"})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["flow"]["status"] == "proposed" and body["approval_id"]
    again = client.post("/api/flows", json={"domain": "risks", "source": "tool:grc", "target": "hub"})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "flow_exists"

    # enable the pull, then a push of the same domain is a loop
    client.post(f"/api/approvals/{body['approval_id']}", json={"approve": True})
    wait_for(lambda: client.get("/api/flows").json() and
             any(f["id"] == body["flow"]["id"] and f["status"] == "enabled" for f in client.get("/api/flows").json()))
    loop = client.post("/api/flows", json={"domain": "risks", "source": "hub", "target": "tool:grc"})
    # GRC fake cannot write risks, so this is no_capability rather than a loop unless writes(risks).
    # Assets: GRC writes assets (push) - plan a pull of assets (it cannot read them) -> no_capability.
    # Loop: enable the assets push, try to enable a pull of assets... GRC doesn't read assets.
    # Use inventory instead: SoR pull exists; we still test PATCH enable of a conflicting pair via a tool that
    # both reads and writes a domain that is not SoR — fake_grc writes vulnerabilities and does not read them.
    # Create a pull of controls? GRC writes controls only.
    # Directly insert a pull+push pair through the store and PATCH enable.
    hub = client.app.state.hub
    from hub.integration import flows
    pull = flows.make(hub, "controls", "tool:grc", "hub", None, created_by="test")
    pull.status = "enabled"
    flows.save(hub, pull)
    push = flows.make(hub, "controls", "hub", "tool:grc", None, created_by="test")
    push.status = "disabled"
    flows.save(hub, push)
    conflict = client.patch(f"/api/flows/{push.id}", json={"status": "enabled"})
    assert conflict.status_code == 409 and conflict.json()["detail"]["code"] == "flow_conflict"
    assert conflict.json()["detail"]["flow_id"] == pull.id

    viewer = sign_in("viewer")
    assert viewer.post("/api/flows", json={"domain": "risks", "source": "tool:grc", "target": "hub"}).status_code == 403


def test_viewer_payloads_never_carry_webhooks_config_or_payloads(client, remote, sign_in):
    add_tool(client, "gitea", "Gitea",
             provides=["git.hosting", "webhooks"],
             events={"emits": ["push"], "listens": [], "webhook_url": "https://gitea.example.com/hooks/hub?token=abc"})
    add_tool(client, "ci", "CI",
             provides=["ci"], consumes=["webhooks"],
             events={"emits": [], "listens": ["push*"], "webhook_url": "https://ci.example.com/webhook?secret=xyz"})
    hub = client.app.state.hub
    hub.store.append("toolbus", {"source": "gitea", "event": "push", "payload": {"secret": "should-not-leak"},
                                 "deliveries": [{"to": "ci", "ok": True, "detail": "HTTP 204"}]})

    viewer = sign_in("viewer")
    integration = viewer.get("/api/integration").json()
    _walk(integration)
    assert integration["routes"] and all(r["webhook"] in (True, False) for r in integration["routes"])
    assert all("payload" not in d for d in integration["deliveries"])

    mapped = viewer.get("/api/integration/map").json()
    _walk(mapped)
    assert mapped["events"] and all("webhook" not in e for e in mapped["events"])
    assert all(e.get("has_webhook") in (True, False) for e in mapped["events"])

    operator = sign_in("operator")
    op = operator.get("/api/integration").json()
    assert any(isinstance(r.get("webhook"), str) and r["webhook"].startswith("http") for r in op["routes"])


def test_map_permissions(client, sign_in):
    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.get("/api/integration/map").status_code == 200
    assert operator.get("/api/integration/map").status_code == 200
    assert viewer.post("/api/flows", json={"domain": "assets", "source": "hub", "target": "tool:x"}).status_code == 403
