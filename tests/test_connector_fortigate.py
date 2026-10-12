"""FortiGate connector against a fake FortiOS REST API (httpx.MockTransport, no network)."""

from __future__ import annotations

import asyncio
import copy
import json
from typing import Any

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.fortigate import FortiGateConnector
from hub.connectors.netmodel import TEST_CHECKS, Backup, ChangeError, ops_applied, ops_reverted

TOKEN = "fgt-secret-token-value-123456"
BASE = "https://fw.example"


def run(coro):
    return asyncio.run(coro)


def allow(src: str = "port2", dst: str = "port1", marker: str = "atrium:chg_31") -> dict[str, Any]:
    return {"op": "allow", "source": {"zone": src, "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": dst, "cidrs": ["10.0.20.0/24"]},
            "services": [{"proto": "tcp", "ports": "443"}], "log": True,
            "description": "Users to intranet", "marker": marker}


@pytest.fixture(autouse=True)
def _register(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "fortigate", FortiGateConnector)


def _policy(policyid: int, name: str, src: str, dst: str, srcaddr: str, dstaddr: str, **extra: Any) -> dict[str, Any]:
    return {"policyid": policyid, "name": name, "uuid": f"uuid-{policyid}", "status": "enable", "action": "accept",
            "srcintf": [{"name": src}], "dstintf": [{"name": dst}], "srcaddr": [{"name": srcaddr}],
            "dstaddr": [{"name": dstaddr}], "service": [{"name": "HTTPS"}], "schedule": "always",
            "logtraffic": "all", "nat": "disable", "comments": extra.pop("comments", name), **extra}


class FakeFortiGate:
    def __init__(self, version: str = "v7.4.4"):
        self.version = version
        self.revision = 100
        self.cfg_save = "automatic"
        self.central = "disable"
        self.fail_revision = False
        self.fail_inverse = False
        self.envelope_error = False
        self.calls: list[httpx.Request] = []
        self.live = {
            "addresses": {
                "LAN-net": {"name": "LAN-net", "type": "ipmask", "subnet": "10.0.10.0/24"},
                "SERVER": {"name": "SERVER", "type": "ipmask", "subnet": "10.0.20.10/32"},
                "all": {"name": "all", "type": "ipmask", "subnet": "0.0.0.0/0"},
            },
            "services": {"HTTPS": {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"}},
            "policies": [
                _policy(7, "lan-to-web", "port2", "port1", "LAN-net", "all", comments="web\u202eout"),
                _policy(9, "servers-web", "port2", "port1", "LAN-net", "SERVER", comments="servers",
                        logtraffic="disable"),
            ],
        }
        self.staged: dict[str, Any] | None = None
        self.checkpoint: dict[str, Any] | None = None
        self.next_policy = 10

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if TOKEN in str(request.url):
            return httpx.Response(500, json={"status": "error", "http_status": 500, "error": -1})
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"status": "error", "http_status": 401, "cli_error": f"bad {TOKEN}"})
        path = request.url.path
        if self.envelope_error and path.endswith("/monitor/system/status"):
            return httpx.Response(200, json={"status": "success", "http_status": 500, "error": -5,
                                             "cli_error": f"rejected {TOKEN}"})
        tail = path.split("/api/v2/", 1)[-1]
        if tail == "monitor/system/status":
            return self._ok({"model": "FG-VM", "hostname": "fw1"}, version=self.version, serial="FGVMTEST01")
        if tail == "monitor/system/config/backup":
            body = b"#config-version=7.4.4:opmode=0\n# Atrium test configuration\n"
            return httpx.Response(200, content=body, headers={"content-type": "text/plain"})
        if tail == "monitor/system/config-revision/save":
            if self.fail_revision:
                return httpx.Response(200, json={"status": "error", "http_status": 403, "error": -37})
            self.checkpoint = copy.deepcopy(self.live)
            return self._ok({"config_id": self.revision})
        if tail == "monitor/system/config/save":
            return self._ok({})
        if tail == "monitor/system/config/restore":
            if self.checkpoint is not None:
                self.live = copy.deepcopy(self.checkpoint)
                self.staged = None
                self.revision += 1
            return self._ok({})
        if tail == "monitor/firewall/policy":
            return self._ok([{"policyid": 7, "hit_count": 1532}, {"policyid": 9, "hit_count": 4}])
        if tail == "cmdb/system/interface":
            return self._ok([
                {"name": "port2", "ip": "10.0.10.1 255.255.255.0", "vlanid": 0, "allowaccess": "ping https",
                 "status": "up", "role": "lan", "description": "LAN"},
                {"name": "port1", "ip": "203.0.113.2 255.255.255.248", "allowaccess": "ping", "status": "up",
                 "role": "wan"},
                {"name": "vlan20", "ip": "10.0.20.1 255.255.255.0", "vlanid": 20, "interface": "port1",
                 "status": "up", "role": "lan"},
            ])
        if tail == "cmdb/system/zone":
            return self._ok([{"name": "LAN", "interface": [{"interface-name": "port2"}]}])
        if tail == "cmdb/system/global":
            return self._ok([{"cfg-save": self.cfg_save}])
        if tail == "cmdb/system/central-management":
            return self._ok([{"status": self.central}])
        if tail == "cmdb/firewall/addrgrp":
            return self._ok([])
        state = self._state(request)
        if tail == "cmdb/firewall/address":
            return self._address_collection(request, state)
        if tail.startswith("cmdb/firewall/address/"):
            return self._one(state["addresses"], tail.rsplit("/", 1)[-1])
        if tail == "cmdb/firewall.service/custom":
            return self._service_collection(request, state)
        if tail.startswith("cmdb/firewall.service/custom/"):
            return self._one(state["services"], tail.rsplit("/", 1)[-1])
        if tail == "cmdb/firewall/policy":
            return self._policy_collection(request, state)
        if tail.startswith("cmdb/firewall/policy/"):
            return self._policy_write(request, state, tail.rsplit("/", 1)[-1])
        if tail == "cmdb":
            return self._transaction(request)
        return httpx.Response(404, json={"status": "error", "http_status": 404, "error": -3})

    def _state(self, request: httpx.Request) -> dict[str, Any]:
        txn = request.headers.get("X-TRANSACTION-ID")
        if txn and self.staged is not None and str(self.staged["id"]) == txn:
            return self.staged
        return self.live

    def _ok(self, results: Any, **extra: Any) -> httpx.Response:
        return httpx.Response(200, json={"status": "success", "http_status": 200, "revision": str(self.revision),
                                         "results": results, **extra})

    def _body(self, request: httpx.Request) -> dict[str, Any]:
        if not request.content:
            return {}
        data = json.loads(request.content.decode())
        return data if isinstance(data, dict) else {}

    def _one(self, table: dict[str, Any], name: str) -> httpx.Response:
        if name not in table:
            return httpx.Response(404, json={"status": "error", "http_status": 404, "error": -3})
        return self._ok([table[name]])

    def _address_collection(self, request: httpx.Request, state: dict[str, Any]) -> httpx.Response:
        if request.method == "POST":
            body = self._body(request)
            state["addresses"][body["name"]] = body
            return self._ok({"mkey": body["name"]})
        return self._ok(list(state["addresses"].values()))

    def _service_collection(self, request: httpx.Request, state: dict[str, Any]) -> httpx.Response:
        if request.method == "POST":
            body = self._body(request)
            state["services"][body["name"]] = body
            return self._ok({"mkey": body["name"]})
        return self._ok(list(state["services"].values()))

    def _policy_collection(self, request: httpx.Request, state: dict[str, Any]) -> httpx.Response:
        if request.method == "POST":
            body = self._body(request)
            policy = {**body, "policyid": self.next_policy}
            self.next_policy += 1
            state["policies"].append(policy)
            return self._ok({"mkey": policy["policyid"]})
        return self._ok(state["policies"])

    def _policy_write(self, request: httpx.Request, state: dict[str, Any], policy_id: str) -> httpx.Response:
        body = self._body(request)
        if self.fail_inverse and body.get("status"):
            return httpx.Response(200, json={"status": "error", "http_status": 500, "error": -3,
                                             "cli_error": "rejected"})
        policies = state["policies"]
        found = next((p for p in policies if str(p.get("policyid")) == policy_id), None)
        if found is None:
            return httpx.Response(404, json={"status": "error", "http_status": 404})
        if request.url.params.get("action") == "move":
            before = request.url.params.get("before")
            policies.remove(found)
            index = next(i for i, p in enumerate(policies) if str(p.get("policyid")) == before)
            policies.insert(index, found)
            return self._ok({})
        found.update(body)
        return self._ok({})

    def _transaction(self, request: httpx.Request) -> httpx.Response:
        action = request.url.params.get("action")
        if action == "transaction-start":
            self.staged = {"id": "1", **copy.deepcopy({k: v for k, v in self.live.items()})}
            return self._ok({}, **{"transaction-id": 1})
        if action == "transaction-commit":
            if self.staged is None:
                return httpx.Response(200, json={"status": "error", "http_status": 500, "error": -651})
            self.live = {k: v for k, v in self.staged.items() if k != "id"}
            self.staged = None
            self.revision += 1
            return self._ok({})
        if action == "transaction-abort":
            self.staged = None
            return self._ok({})
        return httpx.Response(404, json={"status": "error", "http_status": 404})

    def methods(self) -> list[str]:
        return [f"{r.method} {r.url.path}" for r in self.calls]


def connector(fake: FakeFortiGate, **config: Any) -> FortiGateConnector:
    cfg = {"base_url": BASE, "vdom": "root", "verify_tls": True, "can_write": False, **config}
    return FortiGateConnector(cfg, {"token": TOKEN}, httpx.MockTransport(fake))


def _pulled(fake: FakeFortiGate, **config: Any) -> dict[str, Any]:
    records = run(connector(fake, **config).pull("network"))
    assert isinstance(records, list) and len(records) == 1
    valid, errors = normalize("network", records)
    assert not errors and len(valid) == 1
    return valid[0]


def test_registry_and_config():
    assert connectors.connector_class("fortigate") is FortiGateConnector
    described = FortiGateConnector.describe()
    assert described["kind"] == "fortigate"
    assert described["capabilities"] == {"network": ["read"]}
    assert described["network_write"]["rollback"] == "backup_restore"
    assert FortiGateConnector({"base_url": BASE}, {"token": TOKEN}).write_capability() is None
    with pytest.raises(ConnectorError, match="https://"):
        FortiGateConnector.validate_config({"base_url": "http://fw.example"})
    with pytest.raises(ConnectorError, match="token"):
        FortiGateConnector.validate_config({"base_url": "https://token:x@fw.example"})
    assert FortiGateConnector.validate_config({"base_url": "http://localhost:8443/api/v2"})["base_url"] == \
        "http://localhost:8443"


def test_pull_normalises_policy_zones_and_strips_device_text():
    record = _pulled(FakeFortiGate())
    assert record["external_id"] == "FGVMTEST01"
    assert record["revision"] == "100"
    assert record["device"]["vendor"] == "Fortinet" and record["device"]["version"] == "v7.4.4"
    port2 = next(i for i in record["interfaces"] if i["id"] == "port2")
    assert port2["subnets"] == ["10.0.10.0/24"] and port2["addresses"] == ["10.0.10.1"] and port2["role"] == "lan"
    vlan = next(i for i in record["interfaces"] if i["id"] == "vlan20")
    assert vlan["vlan"] == 20 and vlan["addresses"] == ["10.0.20.1"]
    assert record["zones"][0]["interfaces"] == ["port2"]
    rule = next(r for r in record["rules"] if r["id"] == "7")
    assert rule["vendor_ref"] == "7" and rule["action"] == "pass" and rule["hits"] == 1532
    assert rule["source"]["cidrs"] == ["10.0.10.0/24"] and rule["destination"]["any"] is True
    assert rule["services"] == [{"proto": "tcp", "ports": "443", "alias": None, "name": ""}]
    assert rule["interfaces"] == ["port2"] and rule["out_interfaces"] == ["port1"]
    assert "\u202e" not in rule["description"] and "web" in rule["description"]
    assert "10.0.10.1" in record["self_addresses"]
    assert record["default_policy"]["forward"] == "block"


def test_connection_checks_and_write_gate():
    fake = FakeFortiGate("v7.4.4")
    result = run(connector(fake, can_write=True).test())
    assert result["ok"] is True
    assert [c["name"] for c in result["checks"]] == list(TEST_CHECKS)
    assert all(c["ok"] for c in result["checks"])
    assert "read-only" in result["checks"][3]["detail"]
    assert result["network_write"]["rollback"] == "backup_restore"
    assert result["network_write"]["ops"] == ["allow", "disable_rules", "enable_rules"]
    assert TOKEN not in json.dumps(result)

    read_only = run(connector(FakeFortiGate("v7.4.4"), can_write=False).test())
    assert read_only["ok"] is True and read_only["network_write"] is None
    assert "read-only credential" in read_only["checks"][3]["detail"]

    old = run(connector(FakeFortiGate("v7.2.5"), can_write=True).test())
    assert old["ok"] is True and old["network_write"] is None
    assert "7.4.1" in old["checks"][4]["detail"]

    edge = run(connector(FakeFortiGate("v7.4.1"), can_write=True).test())
    assert edge["network_write"] is not None


def test_envelope_error_is_a_failure_even_on_http_200():
    fake = FakeFortiGate()
    fake.envelope_error = True
    result = run(connector(fake, can_write=True).test())
    assert result["ok"] is False and result["network_write"] is None
    assert TOKEN not in result["detail"] and TOKEN not in json.dumps(result["checks"])
    assert "***" in result["detail"]


def test_auth_and_reachability():
    denied = FakeFortiGate()
    result = run(FortiGateConnector({"base_url": BASE, "verify_tls": True}, {"token": "nope-token-value"},
                                    httpx.MockTransport(denied)).test())
    assert result["ok"] is False
    assert result["checks"][0]["name"] == "reachability" and result["checks"][0]["ok"]
    assert any(c["name"] == "authentication" and not c["ok"] for c in result["checks"])
    assert "nope-token-value" not in json.dumps(result)

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Name or service not known")

    offline = run(connector(FakeFortiGate()).test()) if False else run(
        FortiGateConnector({"base_url": BASE}, {"token": TOKEN}, httpx.MockTransport(down)).test())
    assert offline["ok"] is False and offline["checks"][0]["name"] == "reachability" and not offline["checks"][0]["ok"]


def test_preview_reads_only_and_reports_problems():
    fake = FakeFortiGate()
    preview = run(connector(fake, can_write=True).preview_change([allow()], {}))
    assert preview["problems"] == []
    assert preview["steps"][0]["kind"] == "add_rule" and "atrium:chg_31" in preview["steps"][0]["detail"]
    assert all(call.method == "GET" for call in fake.calls)
    assert fake.revision == 100

    bad = run(connector(FakeFortiGate(), can_write=True).preview_change([allow(src="no-such")], {}))
    assert any("no-such" in problem for problem in bad["problems"])

    locked = run(connector(FakeFortiGate(), can_write=True).preview_change(
        [{"op": "disable_rules", "rules": [{"id": "7", "vendor_ref": "7"}]}], {}))
    assert any("device itself" in problem for problem in locked["problems"])


def test_apply_commits_a_marked_policy_and_rollback_disables_it():
    fake = FakeFortiGate()
    conn = connector(fake, can_write=True)
    before = _pulled(fake, can_write=True)
    applied = run(conn.apply_change([allow()], "100", None))
    assert applied["rollback_until"] is None and applied["revision"] == "101"
    assert applied["created"][0]["vendor_ref"].isdigit()
    assert TOKEN not in applied["token"] and len(applied["token"]) <= 4096
    policy_posts = [c for c in fake.calls if c.method == "POST" and c.url.path.endswith("/firewall/policy")]
    assert policy_posts and policy_posts[0].headers.get("X-TRANSACTION-ID") == "1"
    posted = json.loads(policy_posts[0].content)
    assert posted["comments"].startswith("atrium:chg_31") and posted["action"] == "accept"
    assert posted["nat"] == "disable" and TOKEN not in policy_posts[0].content.decode()
    assert any(c.method == "PUT" and c.url.params.get("before") == "7" for c in fake.calls)
    start = next(i for i, c in enumerate(fake.calls) if c.url.params.get("action") == "transaction-start")
    commit = next(i for i, c in enumerate(fake.calls) if c.url.params.get("action") == "transaction-commit")
    assert start < commit
    after = _pulled(fake, can_write=True)
    assert ops_applied(after, [allow()]) == []
    rolled = run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    assert rolled["rolled_back"] is True and rolled["method"] == "inverse_ops"
    again = _pulled(fake, can_write=True)
    assert ops_reverted(before, again, [allow()]) == []


def test_disable_and_confirm_do_not_save_when_automatic():
    fake = FakeFortiGate()
    conn = connector(fake, can_write=True)
    applied = run(conn.apply_change([{"op": "disable_rules", "rules": [{"id": "9", "vendor_ref": "9"}]}], "100", None))
    assert applied["disabled"] == ["9"]
    disabled = _pulled(fake)
    assert next(r for r in disabled["rules"] if r["id"] == "9")["enabled"] is False
    confirmed = run(connector(fake, can_write=True).confirm_change(applied["token"]))
    assert confirmed["confirmed"] is True
    assert not any(c.url.path.endswith("/config/save") for c in fake.calls)
    run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    restored = _pulled(fake)
    assert next(r for r in restored["rules"] if r["id"] == "9")["enabled"] is True


def test_confirm_saves_when_cfg_save_is_revert():
    fake = FakeFortiGate()
    fake.cfg_save = "revert"
    conn = connector(fake, can_write=True)
    applied = run(conn.apply_change([allow()], "100", None))
    fake.calls.clear()
    result = run(connector(fake, can_write=True).confirm_change(applied["token"]))
    assert result["confirmed"] is True
    assert any(c.method == "POST" and c.url.path.endswith("/monitor/system/config/save") for c in fake.calls)
    assert not any(c.method == "PUT" and "system/global" in c.url.path for c in fake.calls)


def test_stale_lockout_old_version_and_central_management_do_not_write():
    stale = FakeFortiGate()
    with pytest.raises(ChangeError) as exc:
        run(connector(stale, can_write=True).apply_change([allow()], "99", None))
    assert exc.value.code == "stale" and exc.value.state == "unchanged"
    assert not any(c.method == "POST" for c in stale.calls)

    locked = FakeFortiGate()
    with pytest.raises(ChangeError) as exc:
        run(connector(locked, can_write=True).apply_change(
            [{"op": "disable_rules", "rules": [{"id": "7", "vendor_ref": "7"}]}], "100", None))
    assert exc.value.code == "lockout" and exc.value.state == "unchanged"
    assert not any(c.url.params.get("action") == "transaction-start" for c in locked.calls)

    old = FakeFortiGate("v7.2.5")
    with pytest.raises(ChangeError) as exc:
        run(connector(old, can_write=True).apply_change([allow()], "100", None))
    assert exc.value.code == "unsupported" and exc.value.state == "unchanged"
    assert not any(c.url.params.get("action") == "transaction-start" for c in old.calls)

    managed = FakeFortiGate()
    managed.central = "enable"
    tested = run(connector(managed, can_write=True).test())
    assert tested["network_write"] is None
    with pytest.raises(ChangeError) as exc:
        run(connector(managed, can_write=True).apply_change([allow()], "100", None))
    assert exc.value.code == "invalid" and exc.value.state == "unchanged"

    readonly = FakeFortiGate()
    with pytest.raises(ChangeError) as exc:
        run(connector(readonly, can_write=False).apply_change([allow()], "100", None))
    assert exc.value.code == "unsupported"
    assert readonly.calls == []


def test_revision_save_failure_arms_nothing():
    fake = FakeFortiGate()
    fake.fail_revision = True
    with pytest.raises(ChangeError) as exc:
        run(connector(fake, can_write=True).apply_change([allow()], "100", None))
    assert exc.value.code == "failed" and exc.value.state == "unchanged"
    assert not any(c.url.params.get("action") == "transaction-start" for c in fake.calls)
    assert fake.revision == 100


def test_backup_method_switches_at_7_6_and_restore_refuses_snapshots():
    current = FakeFortiGate("v7.4.4")
    backup = run(connector(current, can_write=True).backup())
    assert backup["format"] == "text" and backup["content"].startswith(b"#config-version=")
    assert backup["sha256"] and TOKEN not in backup["content"].decode()
    assert any(c.method == "GET" and c.url.path.endswith("/config/backup") for c in current.calls)
    assert backup["device_backup_id"] == "100"

    newer = FakeFortiGate("v7.6.0")
    run(connector(newer, can_write=True).backup())
    assert any(c.method == "POST" and c.url.path.endswith("/config/backup") for c in newer.calls)

    secret_line = b'{"kind":"fortigate-policy-snapshot","secret":"super-secret-config-line"}'
    with pytest.raises(ChangeError) as exc:
        run(connector(FakeFortiGate(), can_write=True).restore_backup(
            Backup("b1", secret_line, "abc", 0.0, format="json")))
    assert exc.value.code == "unsupported" and exc.value.state == "unchanged"
    assert "super-secret-config-line" not in exc.value.message


def test_inverse_failure_restores_the_saved_revision():
    fake = FakeFortiGate()
    applied = run(connector(fake, can_write=True).apply_change([allow()], "100", None))
    fake.fail_inverse = True
    rolled = run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    assert rolled["method"] == "backup_restore"
    assert any(c.url.path.endswith("/config/restore") for c in fake.calls)
    body = json.loads(next(c for c in fake.calls if c.url.path.endswith("/config/restore")).content)
    assert body["source"] == "revision" and "file_content" not in body
    again = _pulled(fake)
    assert ops_reverted(_pulled(FakeFortiGate()), again, [allow()]) == [] or not any(
        r.get("marker") == "chg_31" and r.get("enabled", True) for r in again["rules"])


def test_requests_stay_on_the_firewall_and_carry_the_vdom():
    fake = FakeFortiGate()
    run(connector(fake, can_write=True).pull("network"))
    assert fake.calls
    for call in fake.calls:
        assert call.url.host == "fw.example"
        assert TOKEN not in str(call.url)
        assert call.url.params.get("vdom") == "root"
    with pytest.raises(ConnectorError):
        run(connector(fake).pull("assets"))
