"""Cisco IOS-XE connector against a fake RESTCONF server (httpx.MockTransport, no network)."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import unquote

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.cisco_iosxe import CiscoIosXeConnector, frame_netconf, unframe_netconf
from hub.connectors.netmodel import TEST_CHECKS, LEAST_PRIVILEGE_NOTE, Backup, ChangeError

PASSWORD = "ios-secret-password-value-987654"
USER = "atrium"
BASE = "https://sw.example"


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(autouse=True)
def _register(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "cisco_iosxe", CiscoIosXeConnector)


def _errors(message: str, status: int = 401) -> httpx.Response:
    return httpx.Response(status, json={"ietf-restconf:errors": {"error": [
        {"error-type": "protocol", "error-tag": "access-denied", "error-message": message}]}})


class FakeIos:
    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.reject_auth = False
        self.envelope_error = False
        self.advertise = False
        self.fail_rpc = False
        self.hits = 1532

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if PASSWORD in unquote(str(request.url)):
            return _errors("secret in url")
        if self.reject_auth or not _basic_ok(request):
            sent = _password_of(request) or PASSWORD
            return _errors(f"refused {sent}")
        path = unquote(request.url.path)
        if self.envelope_error and path.endswith("device-system-data"):
            return _errors(f"rejected {PASSWORD}", status=200)
        if path.endswith("device-system-data"):
            return httpx.Response(200, json={"Cisco-IOS-XE-device-hardware-oper:device-system-data": {
                "software-version": "17.15.1", "boot-time": "2026-01-01T00:00:00Z"}})
        if path.endswith("/hostname"):
            return httpx.Response(200, json={"Cisco-IOS-XE-native:hostname": "sw1"})
        if path.endswith("interfaces-oper:interfaces"):
            return httpx.Response(200, json={"Cisco-IOS-XE-interfaces-oper:interfaces": {"interface": [
                {"name": "GigabitEthernet1/0/1", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready",
                 "description": "users port"},
                {"name": "Vlan10", "admin-status": "if-state-up", "oper-status": "if-oper-state-ready",
                 "description": "USERS", "ipv4": "10.10.20.1", "ipv4-subnet-mask": "255.255.255.0"},
                {"name": "Vlan99", "admin-status": "if-state-up", "description": "mgmt",
                 "ipv4": "10.0.99.1", "ipv4-subnet-mask": "255.255.255.0"},
            ]}})
        if path.endswith("native/vlan"):
            return httpx.Response(200, json={"Cisco-IOS-XE-vlan:vlan-list": [
                {"id": 10, "name": "USERS\u202eX"}, {"id": 99, "name": "MGMT"}]})
        if path.endswith("vlan-oper:vlans"):
            return httpx.Response(200, json={"Cisco-IOS-XE-vlan-oper:vlans": {"vlan": [
                {"id": 10, "name": "USERS", "ports": [{"interface": "GigabitEthernet1/0/1"}],
                 "vlan-interfaces": ["Vlan10"]}]}})
        if path.endswith("/ip/access-list"):
            return httpx.Response(200, json={"Cisco-IOS-XE-native:access-list": {"Cisco-IOS-XE-acl:extended": [
                {"name": "HUB-IN", "access-list-seq-rule": [
                    {"sequence": "10", "remark": "users web\u202e", "ace-rule": {
                        "action": "permit", "protocol": "tcp", "ipv4-address": "10.10.20.0", "mask": "0.0.0.255",
                        "dst-host-address": "10.10.30.10", "dst-eq": "443", "log": [None]}},
                    {"sequence": "20", "ace-rule": {
                        "action": "deny", "protocol": "ip", "any": [None], "dst-any": [None], "log": [None]}},
                ]}]}})
        if path.endswith("acl-oper:access-lists"):
            count = str(self.hits)
            self.hits += 1
            return httpx.Response(200, json={"Cisco-IOS-XE-acl-oper:access-lists": {"access-list": [
                {"name": "HUB-IN", "access-list-entries": {"access-list-entry": [
                    {"rule-name": 10, "access-list-entries-oper-data": {"match-counter": count}},
                    {"rule-name": 20, "access-list-entries-oper-data": {"match-counter": "4"}},
                ]}}]}})
        if path.endswith("native/interface"):
            # UNVERIFIED access-group shape: type list plus in/acl-name.
            return httpx.Response(200, json={"Cisco-IOS-XE-native:interface": {"Vlan": [
                {"name": "10", "ip": {"access-group": {"in": {"acl-name": "HUB-IN"}}}}]}})
        if path.endswith("/capabilities"):
            if not self.advertise:
                return httpx.Response(404, json={"ietf-restconf:errors": {"error": [{"error-tag": "invalid-value"}]}})
            return httpx.Response(200, json={"ietf-netconf-monitoring:capabilities": {"capability": [
                "urn:ietf:params:netconf:base:1.1",
                "urn:ietf:params:netconf:capability:candidate:1.0",
                "urn:ietf:params:netconf:capability:confirmed-commit:1.1",
            ]}})
        if path.endswith("get-modelled-config-clis"):
            if self.fail_rpc:
                return httpx.Response(404, json={"ietf-restconf:errors": {"error": [{"error-tag": "invalid-value"}]}})
            return httpx.Response(200, json={"Cisco-IOS-XE-cli-rpc:output": {
                "cli": "hostname sw1\ninterface Vlan10\n ip access-group HUB-IN in\n"}})
        if path.endswith("is-syncing"):
            return httpx.Response(404, json={"ietf-restconf:errors": {"error": [{"error-tag": "invalid-value"}]}})
        return httpx.Response(404, json={"ietf-restconf:errors": {"error": [{"error-tag": "invalid-value"}]}})


def _password_of(request: httpx.Request) -> str:
    header = request.headers.get("authorization") or ""
    if not header.startswith("Basic "):
        return ""
    import base64
    try:
        raw = base64.b64decode(header.split(" ", 1)[1]).decode()
    except (ValueError, UnicodeError):
        return ""
    return raw.split(":", 1)[-1]


def _basic_ok(request: httpx.Request) -> bool:
    header = request.headers.get("authorization") or ""
    if not header.startswith("Basic "):
        return False
    import base64
    try:
        user, _, password = base64.b64decode(header.split(" ", 1)[1]).decode().partition(":")
    except (ValueError, UnicodeError):
        return False
    return user == USER and password == PASSWORD


def connector(fake: FakeIos, **config: Any) -> CiscoIosXeConnector:
    cfg = {"base_url": BASE, "username": USER, "verify_tls": True, **config}
    return CiscoIosXeConnector(cfg, {"password": PASSWORD}, httpx.MockTransport(fake))


def _pulled(fake: FakeIos | None = None) -> dict[str, Any]:
    records = run(connector(fake or FakeIos()).pull("network"))
    assert isinstance(records, list) and len(records) == 1
    valid, errors = normalize("network", records)
    assert not errors and len(valid) == 1
    return valid[0]


def test_registry_and_config():
    assert connectors.connector_class("cisco_iosxe") is CiscoIosXeConnector
    described = CiscoIosXeConnector.describe()
    assert described["kind"] == "cisco_iosxe"
    assert described["capabilities"] == {"network": ["read"]}
    assert described["network_write"] is None
    assert CiscoIosXeConnector({"base_url": BASE, "username": USER}, {"password": PASSWORD}).write_capability() is None
    with pytest.raises(ConnectorError, match="https://"):
        CiscoIosXeConnector.validate_config({"base_url": "http://sw.example", "username": USER})
    with pytest.raises(ConnectorError, match="password"):
        CiscoIosXeConnector.validate_config({"base_url": "https://user:secret@sw.example", "username": USER})
    with pytest.raises(ConnectorError, match="username"):
        CiscoIosXeConnector.validate_config({"base_url": BASE, "username": "bad\nname"})
    assert CiscoIosXeConnector.validate_config({"base_url": "http://localhost:443", "username": USER})["base_url"] == \
        "http://localhost:443"


def test_pull_acls_vlans_and_svis():
    fake = FakeIos()
    record = _pulled(fake)
    assert record["external_id"] == "sw1"
    assert record["kind"] == "switch"
    assert record["device"]["vendor"] == "Cisco" and record["device"]["version"] == "17.15.1"
    assert record["device"]["management_address"] == "10.0.99.1"
    svi = next(item for item in record["interfaces"] if item["id"] == "Vlan10")
    assert svi["vlan"] == 10 and svi["role"] == "lan"
    assert svi["subnets"] == ["10.10.20.0/24"] and svi["addresses"] == ["10.10.20.1"]
    mgmt = next(item for item in record["interfaces"] if item["id"] == "Vlan99")
    assert mgmt["role"] == "mgmt" and mgmt["addresses"] == ["10.0.99.1"]
    zone = next(item for item in record["zones"] if item["id"] == "vlan10")
    assert "\u202e" not in zone["name"] and "USERS" in zone["name"]
    assert "GigabitEthernet1/0/1" in zone["interfaces"] and "Vlan10" in zone["interfaces"]
    permit = next(rule for rule in record["rules"] if rule["id"] == "HUB-IN:10")
    assert permit["vendor_ref"] == "HUB-IN:10" and permit["action"] == "pass" and permit["order"] == 10
    assert permit["source"]["cidrs"] == ["10.10.20.0/24"]
    assert permit["destination"]["cidrs"] == ["10.10.30.10/32"]
    assert permit["services"] == [{"proto": "tcp", "ports": "443", "alias": None, "name": ""}]
    assert permit["interfaces"] == ["Vlan10"] and permit["floating"] is False and permit["hits"] == 1532
    assert permit["log"] is True and "\u202e" not in permit["description"]
    deny = next(rule for rule in record["rules"] if rule["order"] == 20)
    assert deny["action"] == "block" and deny["source"]["any"] and deny["destination"]["any"]
    assert deny["services"] is None and deny["interfaces"] == ["Vlan10"]
    assert record["default_policy"]["inbound"] == "block"
    assert "10.10.20.1" in record["self_addresses"] and "10.0.99.1" in record["self_addresses"]
    assert all(call.url.host == "sw.example" for call in fake.calls)
    assert all(PASSWORD not in unquote(str(call.url)) for call in fake.calls)
    assert fake.calls[0].headers["authorization"].startswith("Basic ")
    assert "yang-data+json" in fake.calls[0].headers["accept"]
    again = _pulled(fake)
    assert again["revision"] == record["revision"]
    assert again["rules"][0]["hits"] == 1533


def test_connection_checks_stay_read_only():
    result = run(connector(FakeIos()).test())
    assert result["ok"] is True
    assert [item["name"] for item in result["checks"]] == list(TEST_CHECKS)
    assert all(item["ok"] for item in result["checks"])
    assert result["checks"][3]["detail"] == LEAST_PRIVILEGE_NOTE
    assert "UNVERIFIED" in result["checks"][5]["detail"]
    assert result["network_write"] is None
    assert PASSWORD not in json.dumps(result)

    advertised = FakeIos()
    advertised.advertise = True
    wide = run(connector(advertised).test())
    assert wide["ok"] is True and wide["network_write"] is None
    assert "confirmed-commit" in wide["checks"][5]["detail"]
    assert "UNVERIFIED" in wide["checks"][5]["detail"]


def test_envelope_error_is_a_failure_even_on_http_200():
    fake = FakeIos()
    fake.envelope_error = True
    result = run(connector(fake).test())
    assert result["ok"] is False and result["network_write"] is None
    assert PASSWORD not in result["detail"] and PASSWORD not in json.dumps(result["checks"])
    assert "***" in result["detail"]


def test_auth_and_reachability():
    fake = FakeIos()
    fake.reject_auth = True
    result = run(connector(fake).test())
    assert result["ok"] is False
    assert result["checks"][0]["name"] == "reachability" and result["checks"][0]["ok"]
    assert any(item["name"] == "authentication" and not item["ok"] for item in result["checks"])
    assert PASSWORD not in json.dumps(result)
    assert "***" in json.dumps(result)

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Name or service not known")

    offline = run(CiscoIosXeConnector({"base_url": BASE, "username": USER}, {"password": PASSWORD},
                                      httpx.MockTransport(down)).test())
    assert offline["ok"] is False and offline["checks"][0]["name"] == "reachability" and not offline["checks"][0]["ok"]


def test_backup_and_restore_do_not_write():
    fake = FakeIos()
    taken = run(connector(fake).backup())
    assert taken["sha256"]
    assert b"interface Vlan10" in taken["content"]
    assert PASSWORD.encode() not in taken["content"]
    assert all(call.method in ("GET", "POST") for call in fake.calls)
    assert not any(call.method in ("PUT", "PATCH", "DELETE") for call in fake.calls)

    fake.fail_rpc = True
    snapshot = run(connector(fake).backup())
    assert snapshot["format"] == "json"
    assert b"HUB-IN" in snapshot["content"]
    assert PASSWORD.encode() not in snapshot["content"]

    backup = Backup(backup_id="b1", content=f"super-secret-config-line {PASSWORD}".encode(), sha256="abc", taken_at=0)
    with pytest.raises(ChangeError) as raised:
        run(connector(FakeIos()).restore_backup(backup))
    assert raised.value.code == "unsupported" and raised.value.state == "unchanged"
    assert PASSWORD not in raised.value.message and "super-secret-config-line" not in raised.value.message


def test_apply_is_unsupported():
    with pytest.raises(ChangeError) as raised:
        run(connector(FakeIos()).apply_change([{"op": "allow"}], "rev", None))
    assert raised.value.code == "unsupported" and raised.value.state == "unchanged"


def test_pull_other_domain_raises():
    with pytest.raises(ConnectorError):
        run(connector(FakeIos()).pull("assets"))


def test_netconf_framing_roundtrip():
    sample = b'\n#4\n<rpc\n#18\n message-id="102"\n\n##\n'
    assert unframe_netconf(sample) == b'<rpc message-id="102"\n'
    payload = b'hello\n##\nworld'
    assert unframe_netconf(frame_netconf(payload, chunk_size=4)) == payload
    assert unframe_netconf(frame_netconf(b"")) == b""
    with pytest.raises(ValueError):
        unframe_netconf(b"\n#0\n\n##\n")
    with pytest.raises(ValueError):
        unframe_netconf(b"\n#4\nab")
    with pytest.raises(ValueError):
        unframe_netconf(b"\n#2000001\n" + b"a" * 8)
    with pytest.raises(ValueError):
        frame_netconf(b"abc", chunk_size=0)
