"""Network and compliance-framework HTTP APIs: roles, snapshots, drift, backups and CyFun assessments."""

from __future__ import annotations

import io
import zipfile

import pytest

from hub import connectors
from hub.connectors.fake_firewall import FakeFirewallConnector, device, reset
from hub.grc.frameworks import get as get_catalog
from hub.integration import network
from hub.models import Manifest, Tool

from test_fabric import add_tool


@pytest.fixture
def fake_fw(monkeypatch):
    reset()
    monkeypatch.setitem(connectors.REGISTRY, "fake_firewall", FakeFirewallConnector)
    yield
    reset()


def test_network_reads_drift_baseline_and_backup_download(client, sign_in, fake_fw):
    hub = client.app.state.hub
    add_tool(client, "edge", "Edge firewall")
    saved = client.put("/api/tools/edge/connection", json={
        "kind": "fake_firewall", "config": {"base_url": "https://fake-firewall.invalid", "device": "fw1"},
        "secrets": {"api_key": "dev-only"},
    })
    assert saved.status_code == 200, saved.text
    network.ingest(hub, "edge", device("fw1").record())

    listed = client.get("/api/network/devices").json()["devices"]
    assert listed[0]["tool_id"] == "edge" and listed[0]["vendor"] == "Atrium"
    detail = client.get("/api/network/devices/edge").json()
    assert detail["record"]["rules"] and detail["history"][0]["rev"] == 1
    assert client.get("/api/network/devices/missing").status_code == 404

    device("fw1").add_rule({"id": "r9", "vendor_ref": "extra", "action": "pass", "interfaces": ["lan"],
                            "source": {"any": True}, "destination": {"any": True}, "description": "out of band"})
    network.ingest(hub, "edge", device("fw1").record())
    open_items = client.get("/api/network/drift?status=open").json()["drift"]
    assert open_items and open_items[0]["tool_id"] == "edge"
    viewer = sign_in("viewer")
    assert viewer.post(f"/api/network/drift/{open_items[0]['id']}/ack", json={}).status_code == 403
    acked = client.post(f"/api/network/drift/{open_items[0]['id']}/ack", json={"note": "reviewed"})
    assert acked.status_code == 200 and acked.json()["status"] == "acknowledged"
    assert client.post(f"/api/network/drift/{open_items[0]['id']}/ack", json={}).status_code == 409

    operator = sign_in("operator")
    assert operator.post("/api/network/devices/edge/baseline").status_code == 403
    baseline = client.post("/api/network/devices/edge/baseline")
    assert baseline.status_code == 200 and baseline.json()["rev"] == 2
    assert client.delete("/api/network/devices/edge/baseline").json()["removed"] is True

    meta = network.store_backup(hub, "edge", {"content": b"<config>secret-marker</config>", "format": "xml"},
                                reason="manual", actor="admin")
    assert "content" not in client.get("/api/network/backups?tool_id=edge").json()["backups"][0]
    assert viewer.get(f"/api/network/backups/{meta['id']}/download").status_code == 403
    downloaded = client.get(f"/api/network/backups/{meta['id']}/download")
    assert downloaded.status_code == 200 and downloaded.content == b"<config>secret-marker</config>"
    assert "attachment" in downloaded.headers["content-disposition"]
    raw = (hub.settings.data_dir / "hub.sqlite").read_bytes() if (hub.settings.data_dir / "hub.sqlite").exists() else b""
    # the store may use a different file name; the encrypted document must not keep the plaintext
    blob = str(hub.store.get("device_backups", meta["id"]))
    assert "secret-marker" not in blob


def test_guarded_network_change_needs_a_second_person(client, sign_in, fake_fw, wait_for):
    hub = client.app.state.hub
    add_tool(client, "edge", "Edge firewall")
    saved = client.put("/api/tools/edge/connection", json={
        "kind": "fake_firewall", "config": {"base_url": "https://fake-firewall.invalid", "device": "fw1"},
        "secrets": {"api_key": "dev-only"},
    })
    assert saved.status_code == 200, saved.text
    network.ingest(hub, "edge", device("fw1").record())
    assert client.post("/api/tools/edge/connection/test").json()["ok"]
    turned = client.patch("/api/settings/guardrails", json={
        "device_changes": True, "device_changes_need_maintenance_window": False,
    })
    assert turned.status_code == 200, turned.text

    body = {"firewall": "edge", "op": "allow", "source_zone": "z:edge:lan", "target_zone": "z:edge:opt1",
            "services": [{"proto": "tcp", "ports": "443"}], "description": "Users to intranet web"}
    preview = client.post("/api/segmentation/changes/preview", json=body)
    assert preview.status_code == 200, preview.text
    assert preview.json()["writable"] is True

    created = client.post("/api/segmentation/changes", json=body)
    assert created.status_code == 201, created.text
    change_id = created.json()["change"]["id"]
    approval_id = created.json()["approval_id"]
    assert client.post(f"/api/approvals/{approval_id}", json={"approve": True}).status_code == 403
    other = sign_in("admin")
    decided = other.post(f"/api/approvals/{approval_id}", json={"approve": True})
    assert decided.status_code == 200, decided.text
    applied = wait_for(lambda: (c := client.get(f"/api/segmentation/changes/{change_id}").json())
                       and c["status"] in ("applied", "failed", "rolled_back", "stale", "blocked") and c)
    assert applied["status"] == "applied", applied
    assert any("atrium:" in (r.get("description") or "") for r in device("fw1").rules())


def test_cyfun_assessment_lifecycle_and_audit_pack(client, sign_in):
    catalog = get_catalog("cyfun2025")
    assert catalog is not None
    ref = catalog.requirements[0].ref_id
    listed = client.get("/api/frameworks").json()
    assert {f["id"] for f in listed["frameworks"] if f.get("kind") == "builtin"} == {"cyfun2025", "cyfun2023"}
    tree = client.get("/api/frameworks/cyfun2025").json()["tree"]
    assert tree and tree[0]["categories"]

    viewer = sign_in("viewer")
    assert viewer.post("/api/frameworks/cyfun2025/assessments", json={"name": "Q4", "target_level": "B"}).status_code == 403
    created = client.post("/api/frameworks/cyfun2025/assessments", json={"name": "Q4 review", "target_level": "B"})
    assert created.status_code == 201, created.text
    aid = created.json()["id"]
    scored = client.patch(f"/api/frameworks/cyfun2025/assessments/{aid}/requirements/{ref}",
                          json={"implementation": 3, "documentation": 3, "notes": "walked the control"})
    assert scored.status_code == 200
    entry = scored.json()["requirements"][ref]
    assert entry["implementation"] == 3 and entry["maturity"] == 3
    pack = viewer.get(f"/api/frameworks/cyfun2025/assessments/{aid}/audit-pack")
    assert pack.status_code == 200 and pack.headers["content-type"].startswith("application/zip")
    with zipfile.ZipFile(io.BytesIO(pack.content)) as archive:
        names = set(archive.namelist())
        assert {"summary.html", "requirements.csv", "assessment.json", "manifest.json", "SHA256SUMS"} <= names
    assert sign_in("operator").delete(f"/api/frameworks/cyfun2025/assessments/{aid}").status_code == 403
    assert client.delete(f"/api/frameworks/cyfun2025/assessments/{aid}").json() == {"ok": True}
    assert client.get(f"/api/frameworks/cyfun2025/assessments/{aid}").status_code == 404
