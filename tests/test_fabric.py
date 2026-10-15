"""The integration fabric end to end: connections, flow planning and approval, the asset / GRC / vulnerability flows,
scans, the scheduler, repairs and generated connectors - with in-memory fake connectors (no network)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest

from hub import connectors, guardrails
from hub.connectors.base import Connector, ConnectorError, ConnectorField, check
from hub.grc.baseline import CONTROLS
from hub.models import Manifest, Tool

TOKEN = "fabric-secret-token-9f8e7d6c"
DAY = 86400


class Remote:
    """What the fake tools hold - shared by every connector instance the hub builds."""

    def __init__(self):
        self.assets: dict[str, dict] = {}
        self.pushed: dict[str, dict[str, dict]] = {}
        self.risks: list[dict] = []
        self.findings: list[dict] = []
        self.scans: list[dict] = []
        self.scan_state = {"status": "Done", "progress": 100, "done": True}
        self.require_api = False  # answer 404 unless the base URL ends with /api
        self.fail: tuple[int | None, str] | None = None
        self.push_calls = 0


class Fake(Connector):
    remote: Remote
    fields = [ConnectorField(name="base_url", label="URL", kind="url", required=True),
              ConnectorField(name="token", label="API token", kind="secret", required=True),
              ConnectorField(name="folder", label="Folder", kind="select", options=True)]

    def guard(self) -> None:
        if self.secrets.get("token") != TOKEN:
            raise ConnectorError(f"{self.title} rejected the credentials (HTTP 401)", status=401)
        if self.remote.require_api and not self.config["base_url"].endswith("/api"):
            raise ConnectorError(f"{self.title} answered 404 Not Found - check the URL and API path", status=404)
        if self.remote.fail:
            status, message = self.remote.fail  # a careless connector that echoes the token
            raise ConnectorError(f"{message} (sent {self.secrets['token']})", status=status, excerpt=f"echo {self.secrets['token']}")

    async def test(self):
        try:
            self.guard()
        except ConnectorError as exc:
            return {"ok": False, "detail": exc.message, "checks": [check("api", False, exc.message)], "domains": {}}
        return {"ok": True, "detail": "Connected.", "checks": [check("api", True, "reachable")], "domains": self.domains()}

    async def options(self, field_name):
        self.guard()
        return [{"value": "f1", "label": "Main folder"}, {"value": 2, "label": "Lab"}]

    async def pull(self, domain, since=None):
        self.guard()
        return {"assets": list(self.remote.assets.values()), "risks": list(self.remote.risks),
                "vulnerabilities": list(self.remote.findings)}[domain]

    async def push(self, domain, records, links):
        self.guard()
        self.remote.push_calls += 1
        store = self.remote.pushed.setdefault(domain, {})
        out = []
        for record in records:
            if "reject-me" in (record.get("name"), record.get("title")):
                out.append({"hub_id": record["hub_id"], "external_id": None, "action": "failed",
                            "error": "name: This name is reserved."})
                continue
            external = links.get(record["hub_id"]) or f"x{len(store) + 1}"
            action = "updated" if external in store else "created"
            store[external] = record
            out.append({"hub_id": record["hub_id"], "external_id": external, "action": action, "error": None})
        return out

    async def action(self, name, params):
        self.guard()
        if name == "scan":
            self.remote.scans.append(params)
            return {"job_id": f"job-{len(self.remote.scans)}"}
        return dict(self.remote.scan_state)


class FakeInventory(Fake):
    kind, title = "fake_inventory", "Fake Inventory"
    capabilities = {"assets": {"read", "write"}}
    system_of_record = {"assets"}

    @classmethod
    def detect(cls, tool):
        return cls.name_score(tool, ("inventory",))


class FakeGrc(Fake):
    kind, title = "fake_grc", "Fake GRC"
    capabilities = {"assets": {"write"}, "controls": {"write"}, "risks": {"read"}, "vulnerabilities": {"write"}}


class FakeScanner(Fake):
    kind, title = "fake_scanner", "Fake Scanner"
    capabilities = {"vulnerabilities": {"read"}}
    actions = {"scan", "scan_status"}


@pytest.fixture
def remote(client, monkeypatch) -> Remote:
    state = Remote()
    for cls in (FakeInventory, FakeGrc, FakeScanner):
        monkeypatch.setattr(cls, "remote", state, raising=False)
        monkeypatch.setitem(connectors.REGISTRY, cls.kind, cls)
    return state


def add_tool(client, tool_id: str, name: str, **manifest) -> Tool:
    hub = client.app.state.hub
    tool = Tool(id=tool_id, name=name, source_type="saas", source=f"https://{tool_id}.example.com", status="ready",
                manifest=Manifest(id=tool_id, name=name, kind="saas", **manifest))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    return tool


def connect(client, tool_id: str, kind: str, base_url: str = "https://tool.example.com", token: str = TOKEN) -> dict:
    response = client.put(f"/api/tools/{tool_id}/connection",
                          json={"kind": kind, "config": {"base_url": base_url}, "secrets": {"token": token}})
    assert response.status_code == 200, response.text
    return response.json()


def flow_approvals(client) -> list[dict]:
    return [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "flow"]


def flows_of(client, tool_id: str) -> list[dict]:
    return client.get(f"/api/flows?tool_id={tool_id}").json()


def plan_and_enable(client, wait_for, tool_id: str, expected: int) -> list[dict]:
    """Test the connection (which plans flows), approve every proposal, and return the tool's flows."""
    assert client.post(f"/api/tools/{tool_id}/connection/test").json()["ok"]
    pending = wait_for(lambda: len(a := [x for x in flow_approvals(client) if x["payload"]["tool_id"] == tool_id]) == expected and a)
    for approval in pending:
        assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    def enabled():
        found = flows_of(client, tool_id)
        return len(found) == expected and all(f["status"] == "enabled" for f in found) and found

    return wait_for(enabled)


def run(client, flow_id: str) -> dict:
    response = client.post(f"/api/flows/{flow_id}/run")
    assert response.status_code == 200, response.text
    return response.json()


def control(client, control_id: str) -> dict:
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


# -- connections -----------------------------------------------------------------------------


def test_connection_secrets_are_encrypted_and_never_shown(client, remote, sign_in, wait_for):
    hub = client.app.state.hub
    add_tool(client, "inventory", "Inventory")
    view = connect(client, "inventory", "fake_inventory", "https://inv.example.com/")
    assert view["kind"] == "fake_inventory" and view["config"]["base_url"] == "https://inv.example.com"
    assert view["secrets"] == {"token": True} and view["detected"][0]["kind"] == "fake_inventory"
    assert view["capabilities"] == {"assets": ["read", "write"]} and view["system_of_record"] == ["assets"]
    stored = hub.store.get("connections", "inventory")["secrets"]["token"]
    assert stored != TOKEN and hub.secrets.decrypt(stored) == TOKEN
    on_disk = b"".join(p.read_bytes() for p in Path(hub.settings.db_path).parent.glob("hub.db*"))  # + the WAL
    assert TOKEN.encode() not in on_disk

    # an empty secret keeps the stored one, as long as the address stays the same
    client.put("/api/tools/inventory/connection", json={"kind": "fake_inventory", "config": {"base_url": "https://inv.example.com/api"},
                                                         "secrets": {"token": ""}})
    assert client.get("/api/tools/inventory/connection").json()["secrets"] == {"token": True}
    moved = client.put("/api/tools/inventory/connection", json={"kind": "fake_inventory",
                                                                 "config": {"base_url": "https://elsewhere.example.com"}})
    assert moved.status_code == 400 and "again" in moved.json()["detail"]
    bad = client.put("/api/tools/inventory/connection", json={"kind": "fake_inventory", "config": {"base_url": "x", "nope": 1}})
    assert bad.status_code == 400
    assert client.put("/api/tools/inventory/connection", json={"kind": "nope"}).status_code == 400

    # roles: admins configure, operators test and list choices, viewers read
    operator, viewer = sign_in("operator"), sign_in("viewer")
    assert operator.put("/api/tools/inventory/connection", json={"kind": "fake_inventory"}).status_code == 403
    assert operator.delete("/api/tools/inventory/connection").status_code == 403
    assert viewer.get("/api/tools/inventory/connection").status_code == 200
    assert viewer.post("/api/tools/inventory/connection/test").status_code == 403
    assert viewer.get("/api/tools/inventory/connection/options/folder").status_code == 403
    assert operator.get("/api/tools/inventory/connection/options/folder").json() == {
        "options": [{"value": "f1", "label": "Main folder"}, {"value": "2", "label": "Lab"}]}
    assert operator.get("/api/tools/inventory/connection/options/base_url").status_code == 400
    result = operator.post("/api/tools/inventory/connection/test").json()
    assert result["ok"] and result["domains"] == {"assets": ["read", "write"]}
    assert client.get("/api/tools/inventory/connection").json()["last_test"]["ok"]

    # a failing tool that echoes the token: the hub masks it everywhere
    remote.fail = (500, "Inventory exploded")
    failed = operator.post("/api/tools/inventory/connection/test").json()
    assert not failed["ok"] and "Inventory exploded" in failed["detail"] and TOKEN not in json.dumps(failed)
    exposed = [client.get(p).text for p in ("/api/tools/inventory/connection", "/api/messages?limit=2000",
                                            "/api/activity?limit=2000", "/api/approvals", "/api/flows", "/api/integration",
                                            "/api/connectors", "/api/tools/inventory")]
    assert all(TOKEN not in text for text in exposed)
    assert client.get("/api/connectors").status_code == 200 and anon_blocked(client)

    assert client.delete("/api/tools/inventory/connection").json()["ok"]
    assert client.get("/api/tools/inventory/connection").json()["kind"] is None


def anon_blocked(client) -> bool:
    from conftest import new_browser

    return new_browser(client).get("/api/tools/inventory/connection").status_code == 401


# -- assets ------------------------------------------------------------------------------------


def test_inventory_assets_are_merged_by_address_and_retired(client, remote, wait_for):
    known = client.post("/api/assets", json={"name": "Web server", "type": "server", "facts": {"addresses": ["10.0.0.5"]}}).json()
    remote.assets = {
        "1": {"external_id": "1", "name": "web-1", "type": "server", "addresses": ["10.0.0.5", "web-1.corp"],
              "facts": {"serial": "S1", "assigned_username": "alice"}},
        "2": {"external_id": "2", "name": "laptop-7", "type": "workstation", "owner": "bob", "addresses": ["10.0.0.7"],
              "facts": {"serial": "S7"}},
    }
    add_tool(client, "inventory", "Inventory", provides=["assets.inventory"])
    connect(client, "inventory", "fake_inventory")
    [flow] = plan_and_enable(client, wait_for, "inventory", 1)
    # the system of record for assets is only read from, never written to
    assert (flow["domain"], flow["source"], flow["target"], flow["direction"]) == ("assets", "tool:inventory", "hub", "pull")
    assert flow["schedule_minutes"] == 60 and flow["owner"] == "module:assets" and flow["next_run"]

    result = run(client, flow["id"])
    assert result["ok"] and result["counts"] | {"total": 2} == {
        "total": 2, "created": 1, "updated": 0, "merged": 1, "unchanged": 0, "retired": 0, "dropped": 0}
    assets = {a["id"]: a for a in client.get("/api/assets").json()}
    merged = assets[known["id"]]
    assert merged["name"] == "Web server" and merged["source"] == "manual"  # the hub's own record keeps its name
    assert merged["facts"]["serial"] == "S1" and set(merged["facts"]["addresses"]) == {"10.0.0.5", "web-1.corp"}
    assert merged["facts"]["external_ids"] == {"inventory": "1"} and merged["facts"]["assigned_username"] == "alice"
    laptop = next(a for a in assets.values() if a["source"] == "sync:inventory")
    assert (laptop["name"], laptop["type"], laptop["owner"]) == ("laptop-7", "workstation", "bob")

    assert run(client, flow["id"])["counts"]["unchanged"] == 2  # nothing changed in the tool
    del remote.assets["2"]
    assert run(client, flow["id"])["counts"]["retired"] == 1
    assert next(a for a in client.get("/api/assets").json() if a["id"] == laptop["id"])["status"] == "retired"
    remote.assets["2"] = {"external_id": "2", "name": "laptop-7b", "type": "workstation", "addresses": ["10.0.0.7"]}
    assert run(client, flow["id"])["counts"]["updated"] == 1
    again = [a for a in client.get("/api/assets").json() if a["source"] == "sync:inventory"]
    assert len(again) == 1 and again[0]["status"] == "active" and again[0]["name"] == "laptop-7b"
    stored = client.get(f"/api/flows?tool_id=inventory").json()[0]
    assert stored["last_result"]["ok"] and stored["failures"] == 0 and stored["last_run"]


# -- GRC tool: assets, findings and controls out, risks in ----------------------------------------


def test_grc_tool_receives_assets_and_controls_and_feeds_risks(client, remote, wait_for):
    client.post("/api/assets", json={"name": "db-1", "type": "server", "facts": {"addresses": ["10.0.0.9"]}})
    add_tool(client, "grc", "GRC Tool")
    connect(client, "grc", "fake_grc")
    planned = {(f["domain"], f["direction"]): f for f in plan_and_enable(client, wait_for, "grc", 4)}
    assert set(planned) == {("assets", "push"), ("controls", "push"), ("risks", "pull"), ("vulnerabilities", "push")}

    assets_flow = planned[("assets", "push")]
    first = run(client, assets_flow["id"])["counts"]
    total = len([a for a in client.get("/api/assets").json() if a["status"] != "retired"])
    assert first["created"] == total and first["failed"] == 0
    calls = remote.push_calls
    assert run(client, assets_flow["id"])["counts"]["skipped"] == total and remote.push_calls == calls  # unchanged: not sent
    db = next(a for a in client.get("/api/assets").json() if a["name"] == "db-1")
    client.patch(f"/api/assets/{db['id']}", json={"owner": "dba-team"})
    changed = run(client, assets_flow["id"])["counts"]
    assert changed["updated"] == 1 and changed["skipped"] == total - 1
    pushed = next(r for r in remote.pushed["assets"].values() if r["hub_id"] == db["id"])
    assert pushed["owner"] == "dba-team" and pushed["addresses"] == ["10.0.0.9"] and pushed["criticality"] == "medium"

    # the tool rejects a record: the run fails with its message, verbatim
    client.post("/api/assets", json={"name": "reject-me", "type": "server"})
    failed = run(client, assets_flow["id"])
    assert not failed["ok"] and "This name is reserved." in failed["error"]["message"]
    assert failed["flow"]["failures"] == 1 and failed["flow"]["last_result"]["counts"]["failed"] == 1

    controls = run(client, planned[("controls", "push")]["id"])
    assert controls["ok"] and controls["counts"]["created"] == len(CONTROLS)
    record = next(r for r in remote.pushed["controls"].values() if r["ref_id"] == "HB-VM-2")
    assert record["external_id"] == "HB-VM-2" and record["refs"]["ISO27001"] == "A.8.8"
    assert isinstance(record["evidence"], list) and record["status"] in ("pass", "partial", "fail", "manual", "na")

    risks_flow = planned[("risks", "pull")]
    remote.risks = [{"external_id": "rs-1", "title": "Ransomware on file servers", "likelihood": 4, "impact": 5,
                     "status": "open", "treatment": "mitigate"},
                    {"external_id": "rs-2", "title": "Supplier outage", "status": "in_treatment", "treatment": "insure it"}]
    assert run(client, risks_flow["id"])["counts"]["created"] == 2
    risks = {r["title"]: r for r in client.get("/api/grc/risks").json() if r["source"] == "sync:grc"}
    assert risks["Ransomware on file servers"]["score"] == 20 and risks["Ransomware on file servers"]["treatment"] == "mitigate"
    assert "Treatment: insure it" in risks["Supplier outage"]["description"]
    remote.risks = remote.risks[:1]
    assert run(client, risks_flow["id"])["counts"]["closed"] == 1
    assert next(r for r in client.get("/api/grc/risks").json() if r["title"] == "Supplier outage")["status"] == "closed"


def test_a_slow_grc_tool_never_holds_up_compliance_evaluation(client, remote, wait_for, monkeypatch):
    """Review finding: the GRC Supervisor had one concurrency slot, shared with its data flows. While a pull from a
    GRC tool waited, POST /api/grc/evaluate and control overrides timed out after 120 s."""
    import asyncio

    hub = client.app.state.hub
    grc = hub.agents.get("module:grc")
    add_tool(client, "grc", "GRC Tool")
    connect(client, "grc", "fake_grc")
    risks_flow = next(f for f in plan_and_enable(client, wait_for, "grc", 4) if f["domain"] == "risks")
    released = {"go": False}

    async def slow_pull(self, domain, since=None):
        while not released["go"]:  # a GRC tool that takes minutes to answer
            await asyncio.sleep(0.02)
        return []

    monkeypatch.setattr(FakeGrc, "pull", slow_pull)
    try:
        for _ in range(grc.max_concurrency + 2):  # every slot taken by runs of the slow flow
            client.portal.call(hub.bus.tell, "user:admin", "module:grc", "flow.run",
                               {"flow_id": risks_flow["id"], "trigger": "manual"})
        wait_for(lambda: grc.active >= grc.max_concurrency)
        started = time.monotonic()
        result = client.portal.call(hub.bus.request, "user:admin", "module:grc", "evaluate", {}, 5)
        assert "error" not in result and result["frameworks"] and time.monotonic() - started < 5
        assert client.post("/api/grc/evaluate").status_code == 200
        override = client.patch("/api/grc/controls/HB-VM-2", json={"status": "pass", "note": "checked by hand"})
        assert override.status_code == 200, override.text
        summary = client.portal.call(hub.bus.request, "user:admin", "module:grc", "summary", {}, 5)
        assert "frameworks" in summary
    finally:
        released["go"] = True
    wait_for(lambda: grc.active == 0)
    assert next(f for f in flows_of(client, "grc") if f["id"] == risks_flow["id"])["last_result"]["ok"]


# -- vulnerabilities and scans ---------------------------------------------------------------------


def finding(oid: str, host: str, title: str, cvss: float, days_ago: float = 0, cves=()) -> dict:
    return {"external_id": f"{oid}|{host}|443/tcp", "title": title, "cvss": cvss, "cves": list(cves), "host": host,
            "port": "443/tcp", "description": f"{title} details", "solution": "Upgrade", "detected_at": time.time() - days_ago * DAY}


def test_scans_cover_only_in_scope_assets_and_track_findings(client, remote, wait_for, sign_in):
    web = client.post("/api/assets", json={"name": "web-1", "type": "server", "facts": {"addresses": ["10.0.0.5"]}}).json()
    other = client.post("/api/assets", json={"name": "printer", "type": "network", "facts": {"address": "10.0.0.99"}}).json()
    assert sign_in("viewer").post("/api/assets/scan-scope", json={"asset_ids": [web["id"]], "in_scope": True}).status_code == 403
    scope = client.post("/api/assets/scan-scope", json={"asset_ids": [web["id"]], "in_scope": True}).json()
    assert scope["changed"] == [web["id"]] and scope["without_address"] == []
    assert control(client, "HB-VM-2")["status"] in ("fail", "partial", "manual")

    add_tool(client, "scanner", "Scanner", provides=["vuln.scanner"])
    connect(client, "scanner", "fake_scanner")
    assert client.post("/api/tools/scanner/connection/test").json()["ok"]
    proposal = wait_for(lambda: [a for a in flow_approvals(client) if a["payload"]["tool_id"] == "scanner"])
    assert proposal[0]["payload"]["action"] == "scan" and proposal[0]["payload"]["schedule_minutes"] == 7 * 24 * 60

    outside = client.post("/api/vulnerabilities/scan", json={"asset_ids": [other["id"]]})
    assert outside.status_code == 400 and "scope" in outside.json()["detail"]
    remote.scan_state = {"status": "Running", "progress": 40, "done": False}
    started = client.post("/api/vulnerabilities/scan", json={}).json()  # a person pressed "Scan now": no approval
    assert started["ok"] and started["pending"] and started["flow"]["job"]["status"] == "running"
    assert remote.scans == [{"hosts": ["10.0.0.5"], "name": remote.scans[0]["name"]}]  # the printer is out of scope
    flow_id = started["flow"]["id"]
    busy = client.post("/api/vulnerabilities/scan", json={}).json()
    assert busy["pending"] and "already" in busy["detail"]

    remote.findings = [finding("1.3.6.1.4.1.25623.1.0.1", "10.0.0.5", "OpenSSL remote code execution", 9.8, 10, ["CVE-2024-0001"]),
                       finding("1.3.6.1.4.1.25623.1.0.2", "10.0.0.5", "Weak TLS ciphers", 5.0),
                       finding("1.3.6.1.4.1.25623.1.0.3", "10.0.0.5", "OS detection", 0.0)]
    assert run(client, flow_id)["pending"]  # still running in the scanner
    remote.scan_state = {"status": "Done", "progress": 100, "done": True}
    done = run(client, flow_id)
    assert done["ok"] and done["counts"]["new"] == 2 and done["counts"]["ignored"] == 1 and done["flow"]["job"] is None

    vulns = client.get("/api/vulnerabilities").json()
    critical = next(v for v in vulns if v["severity"] == "critical")
    assert critical["asset_id"] == web["id"] and critical["cves"] == ["CVE-2024-0001"] and critical["overdue"]
    assert abs(critical["due_at"] - (critical["first_seen"] + 7 * DAY)) < 1
    medium = next(v for v in vulns if v["severity"] == "medium")
    assert not medium["overdue"] and abs(medium["due_at"] - medium["first_seen"] - 90 * DAY) < 1
    assert [v["id"] for v in client.get("/api/vulnerabilities?severity=critical&overdue=true").json()] == [critical["id"]]
    assert client.get("/api/vulnerabilities?q=cve-2024-0001").json()[0]["id"] == critical["id"]
    summary = client.get("/api/vulnerabilities/summary").json()
    assert summary["by_severity"]["critical"] == 1 and summary["overdue"] == 1 and summary["in_scope_assets"] == 1
    assert summary["scanned_last_30_days"] == 1 and summary["scanners"][0]["tool_id"] == "scanner"

    # an overdue critical finding raises a risk, the SLA control fails, the scan coverage control passes
    risk = wait_for(lambda: next((r for r in client.get("/api/grc/risks").json() if r["source"] == f"vuln:{web['id']}"), None))
    assert risk["status"] == "open" and risk["asset_ids"] == [web["id"]] and "OpenSSL" in risk["description"]
    wait_for(lambda: control(client, "HB-VM-3")["status"] == "fail")
    wait_for(lambda: control(client, "HB-VM-2")["status"] == "pass")

    # the rescan no longer finds the critical one: fixed, and the risk closes
    remote.findings = remote.findings[1:2]
    client.post("/api/vulnerabilities/scan", json={"asset_ids": [web["id"]]})
    rescan = run(client, flow_id)
    assert rescan["counts"]["fixed"] == 1 and rescan["counts"]["updated"] == 1
    fixed = client.get(f"/api/vulnerabilities/{critical['id']}").json()
    assert fixed["status"] == "fixed" and fixed["fixed_at"] and "rescan" in fixed["note"]
    wait_for(lambda: next(r for r in client.get("/api/grc/risks").json() if r["id"] == risk["id"])["status"] == "closed")
    wait_for(lambda: control(client, "HB-VM-3")["status"] == "pass")

    # people triage findings
    accepted = client.patch(f"/api/vulnerabilities/{medium['id']}", json={"status": "accepted", "note": "Legacy clients"}).json()
    assert accepted["status"] == "accepted" and accepted["note"] == "Legacy clients"
    assert sign_in("viewer").patch(f"/api/vulnerabilities/{medium['id']}", json={"status": "fixed"}).status_code == 403
    assert client.get("/api/vulnerabilities?status=active").json() == []
    assert client.get("/api/vulnerabilities/nope").status_code == 404


def test_scheduled_scans_wait_for_approval_unless_the_guardrail_is_off(client, remote, wait_for, sign_in):
    hub = client.app.state.hub
    web = client.post("/api/assets", json={"name": "web-1", "type": "server", "facts": {"addresses": ["10.0.0.5"]}}).json()
    client.post("/api/assets/scan-scope", json={"asset_ids": [web["id"]], "in_scope": True})
    add_tool(client, "scanner", "Scanner")
    connect(client, "scanner", "fake_scanner")
    [flow] = plan_and_enable(client, wait_for, "scanner", 1)

    assert client.portal.call(hub.tick_flows)["started"] == [flow["id"]]
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "scan"), None))
    assert approval["payload"]["hosts"] == ["10.0.0.5"] and approval["payload"]["flow_id"] == flow["id"]
    assert client.get(f"/api/flows?tool_id=scanner").json()[0]["job"]["status"] == "awaiting_approval"
    assert client.portal.call(hub.tick_flows)["started"] == []  # not again while it waits
    remote.findings = [finding("1.2.3", "10.0.0.5", "Old SSH", 7.5)]
    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    wait_for(lambda: client.get(f"/api/flows?tool_id=scanner").json()[0]["job"]["status"] == "running")
    assert len(remote.scans) == 1
    assert client.portal.call(hub.tick_flows)["polled"] == [flow["id"]]
    wait_for(lambda: client.get("/api/vulnerabilities").json())
    wait_for(lambda: next(a for a in client.get("/api/approvals").json() if a["id"] == approval["id"])["status"] == "done")
    assert next(a for a in client.get("/api/assets").json() if a["id"] == web["id"])["last_scanned_at"]

    # admins can let scheduled scans run without approval
    assert sign_in("operator").patch("/api/settings", json={"guardrails": {"scans_need_approval": False}}).status_code == 403
    settings = client.patch("/api/settings", json={"guardrails": {"scans_need_approval": False}, "vuln_sla_days": {"high": 14}}).json()
    assert settings["guardrails"] == {**guardrails.defaults(), "scans_need_approval": False}  # only that one changed
    assert settings["vuln_sla_days"] == {"critical": 7, "high": 14, "medium": 90, "low": 180}
    assert client.patch("/api/settings", json={"vuln_sla_days": {"high": 0}}).status_code == 400
    high = client.get("/api/vulnerabilities").json()[0]
    wait_for(lambda: abs(client.get(f"/api/vulnerabilities/{high['id']}").json()["due_at"] - high["first_seen"] - 14 * DAY) < 1)
    client.portal.call(hub.tick_flows, time.time() + 8 * DAY)
    wait_for(lambda: len(remote.scans) == 2)
    assert not [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "scan"]


def test_rejected_scan_and_failed_scan_do_not_count_as_integration_failures(client, remote, wait_for):
    hub = client.app.state.hub
    web = client.post("/api/assets", json={"name": "web-1", "type": "server", "facts": {"addresses": ["10.0.0.5"]}}).json()
    client.post("/api/assets/scan-scope", json={"asset_ids": [web["id"]], "in_scope": True})
    add_tool(client, "scanner", "Scanner")
    connect(client, "scanner", "fake_scanner")
    [flow] = plan_and_enable(client, wait_for, "scanner", 1)
    client.portal.call(hub.tick_flows)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "scan"), None))
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    rejected = wait_for(lambda: (f := flows_of(client, "scanner")[0])["job"] is None and f["last_result"] and f)
    assert rejected["last_result"]["error"]["message"] == "The scan was rejected." and rejected["failures"] == 0
    remote.scan_state = {"status": "Stopped", "progress": 10, "done": False}
    client.post("/api/vulnerabilities/scan", json={})
    stopped = run(client, flow["id"])
    assert not stopped["ok"] and "stopped" in stopped["error"]["message"] and stopped["flow"]["failures"] == 1


# -- planning, editing, scheduling ------------------------------------------------------------------


def test_flow_edits_settle_proposals_and_validate_options(client, remote, wait_for, sign_in):
    hub = client.app.state.hub
    add_tool(client, "grc", "GRC Tool")
    connect(client, "grc", "fake_grc")
    assert client.post("/api/flows/plan").json()["proposed"]  # declared capabilities are enough to plan
    assert client.post("/api/flows/plan").json()["proposed"] == []  # nothing is proposed twice
    flows = flows_of(client, "grc")
    push = next(f for f in flows if f["domain"] == "assets")
    assert client.post(f"/api/flows/{push['id']}/run").status_code == 400  # proposed flows do not run
    viewer = sign_in("viewer")
    assert viewer.get("/api/flows").status_code == 200 and viewer.patch(f"/api/flows/{push['id']}", json={}).status_code == 403
    enabled = client.patch(f"/api/flows/{push['id']}", json={"status": "enabled", "schedule_minutes": 15,
                                                             "options": {"asset_types": ["server"]}}).json()
    assert enabled["status"] == "enabled" and enabled["schedule_minutes"] == 15 and enabled["options"] == {"asset_types": ["server"]}
    wait_for(lambda: next(a for a in client.get("/api/approvals").json() if a["id"] == push["approval_id"])["status"] == "done")
    assert client.patch(f"/api/flows/{push['id']}", json={"options": {"min_severity": "high"}}).status_code == 400
    assert client.patch(f"/api/flows/{push['id']}", json={"options": {"asset_types": ["spaceship"]}}).status_code == 400
    risks = next(f for f in flows if f["domain"] == "risks")
    client.patch(f"/api/flows/{risks['id']}", json={"status": "disabled"})
    wait_for(lambda: next(a for a in client.get("/api/approvals").json() if a["id"] == risks["approval_id"])["status"] == "rejected")

    # the scheduler starts enabled flows that are due, never disabled or manual-only ones
    now = time.time()
    assert client.portal.call(hub.tick_flows, now)["started"] == [push["id"]]
    wait_for(lambda: flows_of(client, "grc") and next(f for f in flows_of(client, "grc") if f["id"] == push["id"])["last_run"])
    assert client.portal.call(hub.tick_flows, now + 60)["started"] == []
    assert client.portal.call(hub.tick_flows, now + 16 * 60)["started"] == [push["id"]]
    client.patch(f"/api/flows/{push['id']}", json={"schedule_minutes": 0})
    assert client.portal.call(hub.tick_flows, now + 99 * DAY)["started"] == []

    integration = client.get("/api/integration").json()
    assert {(l["source"], l["target"], l["type"]) for l in integration["flow_links"]} >= {("hub", "grc", "flow"), ("grc", "hub", "flow")}
    assert client.delete(f"/api/flows/{push['id']}").json()["ok"]
    assert client.delete(f"/api/flows/{push['id']}").status_code == 404
    pending = [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "flow"]
    assert client.delete("/api/tools/grc").json()["ok"]  # the tool's flows, links and connection go with it
    assert flows_of(client, "grc") == [] and hub.store.get("connections", "grc") is None
    assert all(next(a for a in client.get("/api/approvals").json() if a["id"] == p["id"])["status"] == "rejected" for p in pending)


def test_autonomous_mode_enables_flows_and_strategies_show_progress(client, remote, wait_for):
    client.patch("/api/settings", json={"autonomy": "autonomous"})
    add_tool(client, "inventory", "Inventory", provides=["assets.inventory"])
    add_tool(client, "wiki", "Wiki")
    before = {s["id"]: s for s in client.get("/api/tools/inventory/strategies").json()}
    assert before["data_flows"]["state"] == "available" and before["data_flows"]["action"] == "configure_connection"
    assert before["generated_connector"]["state"] == "not_needed"
    wiki = {s["id"]: s for s in client.get("/api/tools/wiki/strategies").json()}
    assert wiki["data_flows"]["state"] == "unavailable" and wiki["generated_connector"]["state"] == "unavailable"
    connect(client, "inventory", "fake_inventory")
    client.post("/api/tools/inventory/connection/test")
    wait_for(lambda: [f for f in flows_of(client, "inventory") if f["status"] == "enabled"])
    assert not flow_approvals(client)
    overview = {t["tool_id"]: {s["id"]: s["state"] for s in t["strategies"]} for t in client.get("/api/integration/strategies").json()["tools"]}
    assert overview["inventory"]["data_flows"] == "active" and set(overview) == {"inventory", "wiki"}
    assert set(overview["wiki"]) == {"identity", "events", "data_flows", "generated_connector", "adapter"}


# -- repairs --------------------------------------------------------------------------------------


def repair_approval(client, wait_for, tool_id: str) -> dict:
    return wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                  if a["kind"] == "repair" and a["payload"]["tool_id"] == tool_id), None))


def test_three_failures_bring_a_base_path_repair(client, remote, wait_for):
    remote.require_api = True
    remote.assets = {"1": {"external_id": "1", "name": "web-1", "addresses": ["10.0.0.5"]}}
    add_tool(client, "inventory", "Inventory")
    connect(client, "inventory", "fake_inventory", "https://inv.example.com")
    assert not client.post("/api/tools/inventory/connection/test").json()["ok"]
    client.post("/api/flows/plan")
    [flow] = flows_of(client, "inventory")
    client.patch(f"/api/flows/{flow['id']}", json={"status": "enabled"})
    for attempt in range(1, 4):
        result = run(client, flow["id"])
        assert not result["ok"] and result["error"]["status"] == 404 and result["flow"]["failures"] == attempt
    approval = repair_approval(client, wait_for, "inventory")
    payload = approval["payload"]
    assert payload["diagnosis"] == "base_path" and payload["flow_id"] == flow["id"]
    assert payload["change"] == {"kind": "fake_inventory", "config": {"base_url": "https://inv.example.com/api"}}
    assert payload["tried"][0]["ok"] and "base_url" in payload["diff"]
    assert flows_of(client, "inventory")[0]["repair"] == approval["id"]
    run(client, flow["id"])  # a fourth failure does not ask for a second repair
    assert len([a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "repair"]) == 1

    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    repaired = wait_for(lambda: (f := flows_of(client, "inventory")[0])["last_result"]["ok"] and f)
    assert repaired["failures"] == 0 and repaired["repair"] is None and repaired["last_result"]["trigger"] == "repair"
    connection = client.get("/api/tools/inventory/connection").json()
    assert connection["config"]["base_url"] == "https://inv.example.com/api" and connection["secrets"] == {"token": True}
    assert next(a for a in client.get("/api/approvals").json() if a["id"] == approval["id"])["status"] == "done"
    assert [a for a in client.get("/api/assets").json() if a["source"] == "sync:inventory"]


def test_repairs_explain_credential_and_validation_failures(client, remote, wait_for):
    remote.fail = (401, "Inventory rejected the credentials (HTTP 401)")
    add_tool(client, "inventory", "Inventory")
    connect(client, "inventory", "fake_inventory")
    client.post("/api/flows/plan")
    [flow] = flows_of(client, "inventory")
    client.patch(f"/api/flows/{flow['id']}", json={"status": "enabled"})
    for _ in range(3):
        run(client, flow["id"])
    approval = repair_approval(client, wait_for, "inventory")
    assert approval["payload"]["diagnosis"] == "credentials" and approval["payload"]["change"] is None
    assert "Connection" in approval["detail"] and TOKEN not in json.dumps(approval)
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    wait_for(lambda: flows_of(client, "inventory")[0]["repair"] is None)
    assert flows_of(client, "inventory")[0]["failures"] == 0  # three new failures bring a new proposal
    run(client, flow["id"])
    asked = client.post(f"/api/flows/{flow['id']}/repair")  # "Repair" in the UI: no need to wait for three failures
    assert asked.status_code == 202 and asked.json()["diagnosis"] == "credentials"
    assert client.post(f"/api/flows/{flow['id']}/repair").json() == {"approval_id": asked.json()["approval_id"], "existing": True}

    remote.fail = None
    add_tool(client, "grc", "GRC Tool")
    connect(client, "grc", "fake_grc")
    client.post("/api/flows/plan")
    push = next(f for f in flows_of(client, "grc") if f["domain"] == "assets")
    client.patch(f"/api/flows/{push['id']}", json={"status": "enabled"})
    client.post("/api/assets", json={"name": "reject-me", "type": "server"})
    for _ in range(3):
        run(client, push["id"])
    validation = repair_approval(client, wait_for, "grc")
    assert validation["payload"]["diagnosis"] == "validation" and "This name is reserved." in validation["detail"]
    sample = next(f for f in flows_of(client, "grc") if f["id"] == push["id"])["last_result"]["sample"]
    assert sample["records"][0]["name"] == "reject-me"
    controls = next(f for f in flows_of(client, "grc") if f["domain"] == "controls")
    assert client.post(f"/api/flows/{controls['id']}/repair").status_code == 400  # it never failed
    assert TOKEN not in client.get("/api/messages?limit=2000").text + client.get("/api/activity?limit=2000").text


def test_claude_repairs_a_generic_rest_mapping_but_never_redirects_secrets(client, wait_for, monkeypatch):
    from llm_fakes import use_claude

    hub = client.app.state.hub
    served = []

    def handler(request: httpx.Request) -> httpx.Response:
        served.append(request.url.path)
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        if request.url.path == "/api/devices":
            return httpx.Response(200, json=[{"id": 9, "hostname": "nas-1", "ip": "10.0.0.20"}])
        return httpx.Response(404, json={"detail": "Not found."})

    hub.connector_transport = httpx.MockTransport(handler)
    mapping = {"assets": {"list": {"path": "/hosts"}, "fields": {"external_id": "id", "name": "hostname", "addresses": ["ip"]}}}
    add_tool(client, "nas", "NAS Manager")
    response = client.put("/api/tools/nas/connection", json={"kind": "generic_rest", "config": {
        "base_url": "https://nas.example.com/api", "auth": "bearer", "mapping": mapping}, "secrets": {"token": TOKEN}})
    assert response.status_code == 200, response.text
    client.post("/api/flows/plan")
    [flow] = flows_of(client, "nas")
    client.patch(f"/api/flows/{flow['id']}", json={"status": "enabled"})

    # the model proposing another host is refused: the rules take over (and find no working base path)
    use_claude(hub, monkeypatch, json_result={"diagnosis": "x", "rationale": "Move it.",
                                              "config_json": json.dumps({"base_url": "https://evil.example/api"})})
    for _ in range(3):
        run(client, flow["id"])
    refused = repair_approval(client, wait_for, "nas")
    assert refused["payload"]["diagnosis"] == "base_path" and refused["payload"]["change"] is None
    assert all(t["value"].startswith("https://nas.example.com") for t in refused["payload"]["tried"])
    client.post(f"/api/approvals/{refused['id']}", json={"approve": False})
    wait_for(lambda: flows_of(client, "nas")[0]["repair"] is None)

    fixed = {"assets": {**mapping["assets"], "list": {"path": "/devices"}}}
    fake = use_claude(hub, monkeypatch, json_result={"diagnosis": "wrong list path", "rationale": "The API lists devices at /devices.",
                                                     "config_json": json.dumps({"mapping": fixed})})
    for _ in range(3):
        run(client, flow["id"])
    approval = repair_approval(client, wait_for, "nas")
    assert approval["payload"]["diagnosis"] == "mapping" and "/devices" in approval["payload"]["diff"]
    assert "lists devices" in approval["detail"]
    prompt = fake.calls[-1]["prompt"]
    assert "/hosts" in prompt and "404" in prompt and TOKEN not in prompt
    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    wait_for(lambda: flows_of(client, "nas")[0]["last_result"]["ok"])
    assert [a["name"] for a in client.get("/api/assets").json() if a["source"] == "sync:nas"] == ["nas-1"]


def test_generated_connector_from_an_openapi_spec(client, wait_for, tmp_path, monkeypatch):
    from llm_fakes import use_claude

    hub = client.app.state.hub
    root = tmp_path / "cmdb"
    root.mkdir()
    (root / "openapi.json").write_text(json.dumps({
        "openapi": "3.0.0", "info": {"title": "CMDB", "version": "1"},
        "paths": {"/api/cis": {"get": {"summary": "List configuration items", "responses": {"200": {"description": "ok"}}}}}}))
    tool = Tool(id="cmdb", name="CMDB", source_type="local", source=str(root), path=str(root), status="ready",
                manifest=Manifest(id="cmdb", name="CMDB", api={"type": "rest", "spec": "openapi.json", "base_url": "http://localhost:9000"}))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    assert client.post("/api/tools/cmdb/connection/generate").status_code == 400  # needs an AI model
    mapping = {"assets": {"list": {"path": "/api/cis", "items": "items"}, "fields": {"external_id": "id", "name": "name"}}}
    fake = use_claude(hub, monkeypatch, json_result={"rationale": "Reads configuration items as assets.", "base_url": "http://evil.example",
                                                     "auth": "token", "auth_header": "", "mapping_json": json.dumps(mapping)})
    assert client.get("/api/tools/cmdb/connection").json()["can_generate"]
    result = client.post("/api/tools/cmdb/connection/generate")
    assert result.status_code == 202, result.text
    approval = next(a for a in client.get("/api/approvals?status=pending").json() if a["id"] == result.json()["approval_id"])
    change = approval["payload"]["change"]
    assert approval["payload"]["diagnosis"] == "generated" and change["kind"] == "generic_rest" and change["generated"]
    assert change["config"]["base_url"] == "http://localhost:9000"  # never a host the hub does not know for the tool
    assert "List configuration items" in fake.calls[0]["prompt"]
    states = {s["id"]: s["state"] for s in client.get("/api/tools/cmdb/strategies").json()}
    assert states["generated_connector"] == "pending"

    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    wait_for(lambda: client.get("/api/tools/cmdb/connection").json()["kind"] == "generic_rest")
    view = client.get("/api/tools/cmdb/connection").json()
    assert view["generated"] and view["config"]["auth"] == "token" and view["secrets"] == {"token": False, "password": False}
    flow = wait_for(lambda: flows_of(client, "cmdb"))[0]
    assert flow["strategy"] == "generated" and flow["domain"] == "assets" and flow["direction"] == "pull"
    assert {s["id"]: s["state"] for s in client.get("/api/tools/cmdb/strategies").json()}["generated_connector"] == "active"


def test_large_bus_bodies_are_logged_as_a_summary(client, remote, wait_for):
    remote.assets = {str(i): {"external_id": str(i), "name": f"host-{i}", "addresses": [f"10.1.{i // 250}.{i % 250}"],
                              "facts": {"note": "x" * 40}} for i in range(600)}
    add_tool(client, "inventory", "Inventory")
    connect(client, "inventory", "fake_inventory")
    client.post("/api/flows/plan")
    [flow] = flows_of(client, "inventory")
    client.patch(f"/api/flows/{flow['id']}", json={"status": "enabled"})
    assert run(client, flow["id"])["counts"]["created"] == 600
    reply = next(m for m in client.get("/api/messages?limit=2000").json()
                 if m["subject"] == "connector.pull" and m["kind"] == "reply")
    assert reply["body"]["records"] == "<600 items>" and "not logged in full" in reply["body"]["_truncated"]
