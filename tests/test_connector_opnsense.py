"""OPNsense connector against a fake REST API (httpx.MockTransport). No device is contacted."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError
from hub.connectors.netmodel import LEAST_PRIVILEGE_NOTE, RESERVED_ACTIONS, TEST_CHECKS, ChangeError, marker, rule_matches_allow
from hub.connectors.opnsense import OpnSenseConnector
from hub.models import Tool

KEY = "opn-key-value-abcd"
SECRET = "opn-secret-value-xyz"
BASE = "https://fw.example"
RULE_UUID = "3f2a9c1e-7b4d-4e8a-9c0f-1a2b3c4d5e6f"
BLOCK_UUID = "22222222-2222-2222-2222-222222222222"
LOCK_UUID = "33333333-3333-3333-3333-333333333333"
NEW_UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
BACKUP_ID = "bk-100"
SAVEPOINT = "1760000000.123"


def run(coro):
    return asyncio.run(coro)


def allow(description: str = "Users to intranet web", change: str = "chg_31") -> dict[str, Any]:
    return {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": "opt1", "cidrs": ["10.0.20.10/32"]},
            "services": [{"proto": "tcp", "ports": "443"}], "log": True,
            "description": description, "marker": marker(change)}


def _rule(**fields: Any) -> dict[str, Any]:
    base = {"enabled": "1", "sequence": "100", "action": "pass", "quick": "1", "interface": "lan",
            "direction": "in", "ipprotocol": "inet", "protocol": "TCP", "source_net": "lan", "source_port": "",
            "destination_net": "web_servers", "destination_port": "443", "log": "1", "description": "",
            "categories": ""}
    return {**base, **fields}


class FakeOpnSense:
    def __init__(self, version: str = "26.1.11"):
        self.version = version
        self.calls: list[httpx.Request] = []
        self.rules = [
            _rule(uuid=RULE_UUID, description="atrium:edge-17 LAN to web"),
            _rule(uuid=BLOCK_UUID, sequence="50", action="block", interface="opt1", protocol="TCP",
                  source_net="10.0.20.0/24", destination_net="10.0.30.0/24", destination_port="25",
                  description="block mail", log="0"),
        ]
        self.snap: list[dict[str, Any]] | None = None
        self.backup_rules = copy.deepcopy(self.rules)
        self.fail_add = False
        self.boom = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        user, _, password = _basic(request)
        if user != KEY or password != SECRET:
            return httpx.Response(401, json={"status": 401, "message": "Authentication Failed"})
        if self.boom:
            return httpx.Response(400, text=f"rejected secret={SECRET}")
        path, method = request.url.path, request.method
        if path == "/api/diagnostics/system/system_information":
            return httpx.Response(200, json={"name": "fw1.example", "versions": [
                f"OPNsense {self.version} (amd64)", "FreeBSD 14.3-RELEASE", "OpenSSL 3.0.15"]})
        if path == "/api/interfaces/overview/interfaces_info":
            return httpx.Response(200, json={
                "wan": {"identifier": "wan", "description": "WAN", "enabled": "1", "ipv4": [{"ipaddr": "203.0.113.2/29"}]},
                "lan": {"identifier": "lan", "description": "LAN", "enabled": "1", "ipv4": [{"ipaddr": "10.0.10.1/24"}]},
                "opt1": {"identifier": "opt1", "description": "SERVERS", "enabled": "1", "vlan_tag": "20",
                         "ipv4": [{"ipaddr": "10.0.20.1/24"}]}})
        if path == "/api/firewall/alias/search_item":
            return httpx.Response(200, json={"total": 1, "rowCount": 1, "current": 1, "rows": [
                {"name": "web_servers", "type": "host", "content": "10.0.20.10", "description": "web"}]})
        if path == "/api/firewall/group/search_item":
            return httpx.Response(200, json={"rows": [{"uuid": "44444444-4444-4444-4444-444444444444",
                                                       "name": "DMZ", "members": "opt1"}]})
        if path == "/api/firewall/filter/search_rule":
            return httpx.Response(200, json={"total": len(self.rules), "rowCount": len(self.rules), "current": 1,
                                             "rows": self.rules})
        if path == "/api/firewall/filter_util/rule_stats":
            return httpx.Response(200, json={"status": "ok", "stats": {RULE_UUID: {
                "evaluations": "10", "packets": "5", "bytes": "100", "states": "1"}}})
        if path == "/api/core/backup/backups/this":
            self.backup_rules = copy.deepcopy(self.rules)
            return httpx.Response(200, json={"items": [{"time": "1760000000", "time_iso": "2026-10-09T00:00:00",
                                                        "description": "admin", "username": "root", "filesize": "20",
                                                        "id": BACKUP_ID}]})
        if path.startswith("/api/core/backup/download/this"):
            return httpx.Response(200, content=b"<opnsense><version>1</version></opnsense>")
        if method == "POST" and path == "/api/firewall/filter/savepoint":
            if _version_ge(self.version, (26, 7)):
                return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
            self.snap = copy.deepcopy(self.rules)
            return httpx.Response(200, json={"status": "ok", "retention": "100", "revision": SAVEPOINT})
        if method == "POST" and path == "/api/firewall/filter/add_rule":
            if self.fail_add:
                return httpx.Response(200, json={"result": "failed", "validations": {
                    "rule.description": f"nope {SECRET}"}})
            rule = json.loads(request.content)["rule"]
            self.rules.append(_rule(uuid=NEW_UUID, sequence="1", interface=rule["interface"], protocol=rule["protocol"],
                                    source_net=rule["source_net"], destination_net=rule["destination_net"],
                                    destination_port=rule.get("destination_port", ""), description=rule["description"],
                                    log=rule.get("log", "0"), action=rule.get("action", "pass")))
            return httpx.Response(200, json={"result": "saved", "uuid": NEW_UUID})
        if method == "POST" and path.startswith("/api/firewall/filter/toggle_rule/"):
            _, uuid, bit = path.rsplit("/", 2)
            for rule in self.rules:
                if rule["uuid"] == uuid:
                    rule["enabled"] = bit
            return httpx.Response(200, json={"result": "Disabled" if bit == "0" else "Enabled", "changed": True})
        if method == "POST" and path.startswith("/api/firewall/filter/move_rule_before/"):
            return httpx.Response(200, json={"status": "ok"})
        if method == "POST" and path.startswith("/api/firewall/filter/apply"):
            return httpx.Response(200, json={"status": "ok"})
        if method == "POST" and path.startswith("/api/firewall/filter/cancelRollback/"):
            # Cancels the timer only. The savepoint copy stays so a later revert can still restore it.
            return httpx.Response(200, json={"status": "ok"})
        if method == "POST" and path.startswith("/api/firewall/filter/revert/"):
            if self.snap is not None:
                self.rules = copy.deepcopy(self.snap)
            return httpx.Response(200, json={"status": "ok"})
        if method == "POST" and path.startswith("/api/core/backup/revert_backup/"):
            self.rules = copy.deepcopy(self.backup_rules)
            return httpx.Response(200, json={"status": "reverted"})
        return httpx.Response(404, json={"errorMessage": "Endpoint not found"})

    def posts(self) -> list[str]:
        return [request.url.path for request in self.calls if request.method == "POST"]


def _basic(request: httpx.Request) -> tuple[str, str, str]:
    header = request.headers.get("authorization", "")
    if not header.startswith("Basic "):
        return "", ":", ""
    import base64
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    user, _, password = decoded.partition(":")
    return user, ":", password


def _version_ge(text: str, cutoff: tuple[int, int]) -> bool:
    major, minor, *_ = [int(part) for part in text.split(".")]
    return (major, minor) >= cutoff


def connector(fake: FakeOpnSense, **config: Any) -> OpnSenseConnector:
    return OpnSenseConnector({"base_url": BASE, **config}, {"api_key": KEY, "api_secret": SECRET},
                             httpx.MockTransport(fake))


def test_registry_and_detect(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "opnsense", OpnSenseConnector)
    assert connectors.connector_class("opnsense") is OpnSenseConnector
    assert not (set(OpnSenseConnector.actions) & RESERVED_ACTIONS)
    tool = Tool(id="edge-fw", name="OPNsense", source_type="local", source="local")
    assert OpnSenseConnector.detect(tool) >= 90
    assert OpnSenseConnector.validate_config({"base_url": "https://fw.example/"})["base_url"] == "https://fw.example"
    with pytest.raises(ConnectorError):
        OpnSenseConnector.validate_config({"base_url": "http://fw.example"})


def test_pull_uses_the_rule_uuid_and_test_checks():
    fake = FakeOpnSense()
    conn = connector(fake)
    result = run(conn.test())
    assert result["ok"] and [item["name"] for item in result["checks"]] == list(TEST_CHECKS)
    assert LEAST_PRIVILEGE_NOTE in next(item["detail"] for item in result["checks"] if item["name"] == "privileges")
    assert result["network_write"]["rollback"] == "savepoint"
    assert "savepoint" in next(item["detail"] for item in result["checks"] if item["name"] == "api_features")
    record = run(conn.pull("network"))[0]
    rule = next(item for item in record["rules"] if item["vendor_ref"] == RULE_UUID)
    assert record["external_id"] == "fw1" and record["revision"] == BACKUP_ID
    assert record["device"]["vendor"] == "OPNsense" and "26.1.11" in record["device"]["version"]
    assert rule["marker"] == "edge-17" and rule["hits"] == 5 and rule["interfaces"] == ["lan"]
    assert rule["source"]["nets"] == ["lan"] and rule["destination"]["aliases"] == ["web_servers"]
    assert rule["services"][0]["proto"] == "tcp" and rule["services"][0]["ports"] == "443"
    lan = next(item for item in record["interfaces"] if item["id"] == "lan")
    assert lan["addresses"] == ["10.0.10.1"] and lan["subnets"] == ["10.0.10.0/24"] and lan["role"] == "lan"
    assert any(zone["id"] == "DMZ" and zone["interfaces"] == ["opt1"] for zone in record["zones"])
    assert any(alias["name"] == "web_servers" and "10.0.20.10/32" in alias["cidrs"] for alias in record["aliases"])
    assert all(request.headers["authorization"].startswith("Basic ") for request in fake.calls)


def test_26_7_reports_backup_restore_and_confirm_does_not_cancel_a_timer():
    fake = FakeOpnSense("26.7.6")
    conn = connector(fake)
    result = run(conn.test())
    assert result["ok"] and result["network_write"]["rollback"] == "backup_restore"
    assert "revert_backup" in next(item["detail"] for item in result["checks"] if item["name"] == "api_features")
    revision = run(conn.pull("network"))[0]["revision"]
    applied = run(conn.apply_change([allow()], revision, None))
    assert not any("savepoint" in path for path in fake.posts())
    assert "/api/firewall/filter/apply" in fake.posts()
    assert not any(path.startswith("/api/firewall/filter/apply/") for path in fake.posts())
    posts_before = len(fake.posts())
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and len(fake.posts()) == posts_before
    run(connector(fake).rollback_change(applied["token"], None))
    assert f"/api/core/backup/revert_backup/{BACKUP_ID}" in fake.posts()
    again = run(conn.pull("network"))[0]
    assert not any(rule["vendor_ref"] == NEW_UUID for rule in again["rules"])


def test_savepoint_apply_confirm_and_rollback():
    fake = FakeOpnSense()
    conn = connector(fake)
    revision = run(conn.pull("network"))[0]["revision"]
    op = allow()
    preview = run(conn.preview_change([op], {}))
    assert preview["problems"] == [] and all(request.method == "GET" for request in fake.calls)
    fake.calls.clear()
    applied = run(conn.apply_change([op], revision, None))
    posts = fake.posts()
    assert posts.index("/api/firewall/filter/savepoint") < posts.index("/api/firewall/filter/add_rule")
    assert any(path == f"/api/firewall/filter/apply/{SAVEPOINT}" for path in posts)
    assert any(path.startswith(f"/api/firewall/filter/move_rule_before/{NEW_UUID}/") for path in posts)
    assert applied["rollback_until"] and applied["created"][0]["vendor_ref"] == NEW_UUID
    record = run(conn.pull("network"))[0]
    created = next(rule for rule in record["rules"] if rule["vendor_ref"] == NEW_UUID)
    assert rule_matches_allow(created, op) and created["interfaces"] == ["lan"]
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and f"/api/firewall/filter/cancelRollback/{SAVEPOINT}" in fake.posts()
    run(connector(fake).rollback_change(applied["token"], None))
    assert f"/api/firewall/filter/revert/{SAVEPOINT}" in fake.posts()
    restored = run(conn.pull("network"))[0]
    assert not any(rule["vendor_ref"] == NEW_UUID for rule in restored["rules"])


def test_http_200_with_result_failed_is_a_failure_and_secrets_stay_out():
    fake = FakeOpnSense()
    fake.fail_add = True
    conn = connector(fake)
    revision = run(conn.pull("network"))[0]["revision"]
    with pytest.raises(ChangeError) as info:
        run(conn.apply_change([allow()], revision, None))
    assert info.value.code == "failed" and info.value.state == "rolled_back"
    assert f"/api/firewall/filter/revert/{SAVEPOINT}" in fake.posts()
    assert SECRET not in json.dumps(info.value.as_dict())
    assert not any(rule["uuid"] == NEW_UUID for rule in fake.rules)


def test_stale_revision_and_lockout_do_not_write():
    fake = FakeOpnSense()
    conn = connector(fake)
    with pytest.raises(ChangeError) as stale:
        run(conn.apply_change([allow()], "old-revision", None))
    assert stale.value.code == "stale" and stale.value.state == "unchanged" and fake.posts() == []
    fake.rules.append(_rule(uuid=LOCK_UUID, sequence="2", destination_net="(self)", destination_port="443",
                            description="anti-lockout", source_net="10.0.99.0/24"))
    fake.calls.clear()
    op = {"op": "disable_rules", "rules": [{"id": LOCK_UUID, "vendor_ref": LOCK_UUID}]}
    with pytest.raises(ChangeError) as locked:
        run(conn.apply_change([op], BACKUP_ID, None))
    assert locked.value.code == "lockout" and fake.posts() == []


def test_disable_rules_and_a_read_only_connection():
    fake = FakeOpnSense()
    conn = connector(fake)
    revision = run(conn.pull("network"))[0]["revision"]
    op = {"op": "disable_rules", "rules": [{"id": BLOCK_UUID, "vendor_ref": BLOCK_UUID}]}
    applied = run(conn.apply_change([op], revision, None))
    assert BLOCK_UUID in applied["disabled"]
    assert next(rule["enabled"] for rule in fake.rules if rule["uuid"] == BLOCK_UUID) == "0"
    readonly = connector(FakeOpnSense(), read_only=True)
    result = run(readonly.test())
    assert result["ok"] and result["network_write"] is None and "read-only" in result["detail"].lower() + " " + result["checks"][3]["detail"]
    fresh = FakeOpnSense()
    with pytest.raises(ChangeError) as info:
        run(connector(fresh, read_only=True).apply_change([allow()], BACKUP_ID, None))
    assert info.value.code == "unsupported" and fresh.calls == []


def test_unknown_zone_preview_backup_and_action_cannot_write():
    fake = FakeOpnSense()
    conn = connector(fake)
    bad = allow()
    bad["source"] = {"zone": "nope", "cidrs": ["10.1.0.0/24"]}
    preview = run(conn.preview_change([bad], {}))
    assert any("nope" in problem for problem in preview["problems"])
    assert all(request.method == "GET" for request in fake.calls)
    saved = run(conn.backup())
    assert saved["format"] == "xml" and saved["device_backup_id"] == BACKUP_ID and saved["content"].startswith(b"<opnsense>")
    before = len(fake.calls)
    for name in ("apply_change", "backup", "preview_change", "confirm_change", "rollback_change", "restore_backup",
                 "allow", "disable_rules"):
        with pytest.raises(ConnectorError):
            run(conn.action(name, {}))
    assert len(fake.calls) == before


def test_a_wrong_key_does_not_echo_the_secret():
    conn = OpnSenseConnector({"base_url": BASE}, {"api_key": KEY, "api_secret": "wrong-secret-value"},
                             httpx.MockTransport(FakeOpnSense()))
    result = run(conn.test())
    assert not result["ok"] and result["checks"][2]["name"] == "authentication"
    assert "wrong-secret-value" not in json.dumps(result) and SECRET not in json.dumps(result)
    fake = FakeOpnSense()
    fake.boom = True
    with pytest.raises(ConnectorError) as info:
        run(connector(fake).pull("network"))
    assert SECRET not in json.dumps(info.value.as_dict())
