"""MikroTik RouterOS connector against a fake REST API (httpx.MockTransport). No router is contacted."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError
from hub.connectors.mikrotik import MikroTikConnector
from hub.connectors.netmodel import LEAST_PRIVILEGE_NOTE, RESERVED_ACTIONS, TEST_CHECKS, ChangeError, marker, rule_matches_allow
from hub.models import Tool

USER = "admin"
PASSWORD = "router-secret-value"
BASE = "https://router.example"
EVIL = "$(/bin/evil)"


def run(coro):
    return asyncio.run(coro)


def allow() -> dict[str, Any]:
    return {"op": "allow", "source": {"zone": "bridge", "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": "ether1", "cidrs": ["10.0.20.0/24"]},
            "services": [{"proto": "tcp", "ports": "443"}], "log": True,
            "description": f"Users {EVIL}", "marker": marker("chg_31")}


class FakeRouter:
    def __init__(self, version: str = "7.26"):
        self.version = version
        self.calls: list[httpx.Request] = []
        self.rules = [
            {".id": "*2", "chain": "input", "action": "accept", "connection-state": "established,related,untracked",
             "comment": "defconf: accept established,related,untracked", "disabled": "false", "dynamic": "false",
             "invalid": "false", "log": "false", "log-prefix": "", "bytes": "1048576", "packets": "9000"},
            {".id": "*7", "chain": "forward", "action": "drop", "in-interface": "ether1", "comment": "drop wan",
             "disabled": "false", "dynamic": "false"},
        ]
        self.schedulers: list[dict[str, str]] = []
        self.export = "# RouterOS export\n/ip firewall filter\n"
        self.export_left = True
        self.boom = False
        self.next_id = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        user, password = _basic(request)
        if user != USER or password != PASSWORD:
            return httpx.Response(401, text=f"bad password={password}")
        if self.boom:
            return httpx.Response(400, text=f"rejected password={PASSWORD}")
        path, method = unquote(request.url.path), request.method
        if path == "/rest/system/resource" and method == "GET":
            return httpx.Response(200, json={"version": self.version, "board-name": "RB5009", "architecture-name": "arm64"})
        if path == "/rest/system/identity":
            return httpx.Response(200, json={"name": "edge"})
        if path == "/rest/system/clock":
            return httpx.Response(200, json={"date": "2026-10-12", "time": "08:00:00"})
        if path == "/rest/ip/address":
            return httpx.Response(200, json=[{".id": "*1", "address": "10.0.10.1/24", "network": "10.0.10.0",
                                              "interface": "bridge", "disabled": "false"}])
        if path == "/rest/interface":
            return httpx.Response(200, json=[
                {".id": "*3", "name": "bridge", "type": "bridge", "running": "true", "disabled": "false"},
                {".id": "*4", "name": "ether1", "type": "ether", "running": "true", "disabled": "false"}])
        if path == "/rest/interface/vlan":
            return httpx.Response(404, json={"detail": "no such command", "error": 404, "message": "Not Found"})
        if path == "/rest/interface/list":
            return httpx.Response(200, json=[{".id": "*5", "name": "LAN"}])
        if path == "/rest/interface/list/member":
            return httpx.Response(200, json=[{".id": "*6", "list": "LAN", "interface": "bridge"}])
        if path == "/rest/ip/firewall/address-list":
            return httpx.Response(200, json=[{".id": "*8", "list": "seg-users", "address": "10.0.10.5"}])
        if path == "/rest/ip/firewall/filter" and method == "GET":
            return httpx.Response(200, json=self.rules)
        if path == "/rest/ip/firewall/filter" and method == "PUT":
            body = json.loads(request.content)
            self.next_id += 1
            created = {**{key: str(value) for key, value in body.items()}, ".id": f"*1{self.next_id}", "disabled": "false",
                       "dynamic": "false"}
            self.rules.append(created)
            return httpx.Response(201, json=created)
        if path.startswith("/rest/ip/firewall/filter/") and method == "PATCH":
            rule_id = path.rsplit("/", 1)[-1]
            body = json.loads(request.content)
            for rule in self.rules:
                if rule[".id"] == rule_id:
                    rule.update({key: str(value) for key, value in body.items()})
                    return httpx.Response(200, json=rule)
            return httpx.Response(404, json={"detail": "no such id", "error": 404, "message": "Not Found"})
        if path.startswith("/rest/ip/firewall/filter/") and method == "DELETE":
            rule_id = path.rsplit("/", 1)[-1]
            self.rules = [rule for rule in self.rules if rule[".id"] != rule_id]
            return httpx.Response(204)
        if path == "/rest/system/scheduler" and method == "PUT":
            body = json.loads(request.content)
            row = {key: str(value) for key, value in body.items()}
            row[".id"] = "*11"
            self.schedulers.append(row)
            return httpx.Response(201, json=row)
        if path.startswith("/rest/system/scheduler/") and method == "DELETE":
            self.schedulers.clear()
            return httpx.Response(204)
        if path == "/rest/export" and method == "POST":
            body = json.loads(request.content)
            assert "show-sensitive" not in body
            return httpx.Response(200, json={})
        if path == "/rest/file/read" and method == "POST":
            data = self.export if self.export_left else ""
            self.export_left = False
            return httpx.Response(200, json={"data": data})
        if path.startswith("/rest/file/") and method == "DELETE":
            return httpx.Response(204)
        return httpx.Response(404, json={"detail": path, "error": 404, "message": "Not Found"})

    def methods(self) -> list[tuple[str, str]]:
        return [(request.method, unquote(request.url.path)) for request in self.calls]


def _basic(request: httpx.Request) -> tuple[str, str]:
    import base64
    header = request.headers.get("authorization", "")
    if not header.startswith("Basic "):
        return "", ""
    decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
    user, _, password = decoded.partition(":")
    return user, password


def connector(fake: FakeRouter, **config: Any) -> MikroTikConnector:
    return MikroTikConnector({"base_url": BASE, "username": USER, **config}, {"password": PASSWORD},
                             httpx.MockTransport(fake))


def test_registry_and_detect(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "mikrotik", MikroTikConnector)
    assert connectors.connector_class("mikrotik") is MikroTikConnector
    assert not (set(MikroTikConnector.actions) & RESERVED_ACTIONS)
    tool = Tool(id="edge", name="MikroTik", source_type="local", source="local")
    assert MikroTikConnector.detect(tool) >= 90
    with pytest.raises(ConnectorError):
        MikroTikConnector.validate_config({"base_url": "http://router.example", "username": USER})


def test_pull_keeps_string_ids_and_test_checks():
    fake = FakeRouter()
    conn = connector(fake)
    result = run(conn.test())
    assert result["ok"] and [item["name"] for item in result["checks"]] == list(TEST_CHECKS)
    assert result["network_write"]["rollback"] == "deadman" and result["network_write"]["window_s"] == 120
    assert LEAST_PRIVILEGE_NOTE in next(item["detail"] for item in result["checks"] if item["name"] == "privileges")
    assert "Safe Mode" in next(item["detail"] for item in result["checks"] if item["name"] == "api_features")
    record = run(conn.pull("network"))[0]
    rule = next(item for item in record["rules"] if item["vendor_ref"] == "*2")
    assert record["external_id"] == "edge" and record["device"]["version"] == "7.26"
    assert record["device"]["model"] == "RB5009" and record["kind"] == "router"
    assert rule["action"] == "pass" and rule["enabled"] is True and rule["hits"] == 9000
    assert rule["destination"]["self"] is True
    assert rule["description"].startswith("defconf:")
    bridge = next(item for item in record["interfaces"] if item["id"] == "bridge")
    assert bridge["addresses"] == ["10.0.10.1"] and bridge["subnets"] == ["10.0.10.0/24"]
    assert any(zone["id"] == "LAN" and zone["interfaces"] == ["bridge"] for zone in record["zones"])
    assert any(alias["name"] == "seg-users" and "10.0.10.5/32" in alias["cidrs"] for alias in record["aliases"])


def test_apply_arms_the_scheduler_before_the_rule_and_confirm_removes_it():
    fake = FakeRouter()
    conn = connector(fake)
    op = allow()
    preview = run(conn.preview_change([op], {}))
    assert preview["problems"] == [] and not any(method == "PUT" for method, _ in fake.methods())
    revision = run(conn.pull("network"))[0]["revision"]
    applied = run(conn.apply_change([op], revision, None))
    puts = [path for method, path in fake.methods() if method == "PUT"]
    assert puts.index("/rest/system/scheduler") < puts.index("/rest/ip/firewall/filter")
    scheduler = fake.schedulers[0]
    rule = next(item for item in fake.rules if item[".id"] == "*11" or "atrium:chg_31" in item.get("comment", ""))
    assert scheduler["interval"] == "0s" and scheduler["start-date"] == "2026-10-12" and scheduler["start-time"] == "08:02:00"
    assert "atrium:chg_31" in scheduler["on-event"] and EVIL not in scheduler["on-event"]
    assert "/ip/firewall/filter/remove" in scheduler["on-event"]
    assert rule["place-before"] == "*7" and rule["chain"] == "forward" and rule["action"] == "accept"
    assert rule["protocol"] == "tcp" and rule["dst-port"] == "443" and rule["in-interface"] == "bridge"
    assert EVIL in rule["comment"]
    record = run(conn.pull("network"))[0]
    created = next(item for item in record["rules"] if item.get("marker") == "chg_31")
    assert created["vendor_ref"] == applied["created"][0]["vendor_ref"] == "*11"
    assert rule_matches_allow(created, op)
    sessions_before = len(fake.calls)
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and fake.schedulers == []
    assert len(fake.calls) > sessions_before
    assert any(item["vendor_ref"] == "*11" for item in run(conn.pull("network"))[0]["rules"])


def test_rollback_removes_the_rule_and_the_scheduler():
    fake = FakeRouter()
    conn = connector(fake)
    revision = run(conn.pull("network"))[0]["revision"]
    applied = run(conn.apply_change([allow()], revision, None))
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["rolled_back"] and rolled["method"] == "inverse_ops"
    assert fake.schedulers == []
    assert not any("atrium:chg_31" in rule.get("comment", "") for rule in fake.rules)


def test_stale_lockout_read_only_and_secrets():
    fake = FakeRouter()
    conn = connector(fake)
    with pytest.raises(ChangeError) as stale:
        run(conn.apply_change([allow()], "h-not-the-revision", None))
    assert stale.value.code == "stale" and not any(method == "PUT" for method, _ in fake.methods())
    op = {"op": "disable_rules", "rules": [{"id": "*2", "vendor_ref": "*2"}]}
    with pytest.raises(ChangeError) as locked:
        run(conn.apply_change([op], run(conn.pull("network"))[0]["revision"], None))
    assert locked.value.code == "lockout" and not any(method in {"PUT", "PATCH"} for method, _ in fake.methods())
    readonly = connector(FakeRouter(), read_only=True)
    result = run(readonly.test())
    assert result["network_write"] is None and "read-only" in result["checks"][3]["detail"]
    old = FakeRouter("6.49")
    assert run(connector(old).test())["ok"] is False
    wrong = MikroTikConnector({"base_url": BASE, "username": USER}, {"password": "other-secret-value"},
                              httpx.MockTransport(FakeRouter()))
    denied = run(wrong.test())
    assert not denied["ok"] and "other-secret-value" not in json.dumps(denied) and PASSWORD not in json.dumps(denied)
    boom = FakeRouter()
    boom.boom = True
    with pytest.raises(ConnectorError) as info:
        run(connector(boom).pull("network"))
    assert PASSWORD not in json.dumps(info.value.as_dict())


def test_backup_action_and_restore():
    fake = FakeRouter()
    conn = connector(fake)
    saved = run(conn.backup())
    assert saved["format"] == "text" and "RouterOS export" in saved["content"]
    assert any(method == "DELETE" and path.startswith("/rest/file/") for method, path in fake.methods())
    with pytest.raises(ChangeError) as info:
        run(conn.restore_backup(type("Backup", (), {"text": lambda self: saved["content"]})()))
    assert info.value.code == "unsupported"
    before = len(fake.calls)
    for name in ("apply_change", "backup", "confirm_change", "rollback_change", "restore_backup", "allow", "disable_rules"):
        with pytest.raises(ConnectorError):
            run(conn.action(name, {}))
    assert len(fake.calls) == before


def test_preview_rejects_an_unknown_interface_without_writing():
    fake = FakeRouter()
    bad = allow()
    bad["source"] = {"zone": "nope", "cidrs": ["10.8.0.0/24"]}
    preview = run(connector(fake).preview_change([bad], {}))
    assert any("nope" in problem for problem in preview["problems"])
    assert not any(method == "PUT" for method, _ in fake.methods())
