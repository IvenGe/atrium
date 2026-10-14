"""The FortiGate connector against a fake FortiOS REST API (httpx.MockTransport, no network). The fake follows the
research doc (docs/research/fw-fortigate-panos-cisco.md section 2): the cmdb envelope, Bearer tokens, 401/403/404
answers, policies in evaluation order with policyid != position, zones that own their interfaces, address and service
objects, workspace transactions (start / X-TRANSACTION-ID / show / commit; uncommitted changes invisible), the 7.6
backup method change and the super_admin requirement for backups."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
from typing import Any

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.fortigate import FortigateConnector, parse_version
from hub.connectors.netmodel import (Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops)
from hub.integration.connections import clean_config

TOKEN = "fgt-token-6a5b4c3d2e1f0a9b8c7d"
BASE = "https://fgt.example.net"
PASSWORD_HASH = "ENC SH2nV3fortigate-admin-password-hash-do-not-leak"
TABLES = {"firewall/policy": "policies", "system/interface": "interfaces", "system/zone": "zones",
          "firewall/address": "addresses", "firewall/addrgrp": "addrgrps", "firewall/address6": "addresses6",
          "firewall/addrgrp6": "addrgrps6", "firewall.service/custom": "services",
          "firewall.service/group": "servicegroups", "system/global": "global",
          "system/central-management": "central", "system/vdom": "vdoms", "system/api-user": "api_users",
          "system/accprofile": "profiles"}


def run(coro):
    return asyncio.run(coro)


def members(*names: str) -> list[dict[str, str]]:
    return [{"name": n, "q_origin_key": n} for n in names]


def policy(pid: int, name: str, src: str, dst: str, srcaddr: list[str], dstaddr: list[str], service: list[str],
           action: str = "accept", **extra: Any) -> dict[str, Any]:
    return {"policyid": pid, "q_origin_key": pid, "name": name, "uuid": f"uuid-{pid}", "status": "enable",
            "srcintf": members(src), "dstintf": members(dst), "srcaddr": members(*srcaddr),
            "dstaddr": members(*dstaddr), "service": members(*service), "schedule": "always", "action": action,
            "logtraffic": "all", "nat": "disable", "comments": "", **extra}


def default_state() -> dict[str, Any]:
    return {
        "interfaces": [
            {"name": "port1", "vdom": "root", "type": "physical", "role": "wan", "ip": "203.0.113.2 255.255.255.248",
             "allowaccess": "ping fgfm", "status": "up", "alias": "", "description": ""},
            {"name": "port2", "vdom": "root", "type": "physical", "role": "lan", "ip": "10.0.10.1 255.255.255.0",
             "allowaccess": "ping https ssh", "status": "up", "alias": "LAN"},
            {"name": "port3", "vdom": "root", "type": "physical", "role": "dmz", "ip": "10.0.20.1 255.255.255.0",
             "allowaccess": "ping", "status": "up", "alias": "SERVERS"},
            {"name": "port4", "vdom": "root", "type": "physical", "role": "dmz", "ip": "10.0.40.1 255.255.255.0",
             "allowaccess": "", "status": "down"},
            {"name": "vlan30", "vdom": "root", "type": "vlan", "vlanid": 30, "interface": "port2", "role": "lan",
             "ip": "10.0.30.1 255.255.255.0", "allowaccess": "ping", "status": "up", "alias": "GUEST"},
            {"name": "mgmt", "vdom": "root", "type": "physical", "dedicated-to": "management",
             "ip": "10.0.99.1 255.255.255.0", "allowaccess": "https ssh ping fabric", "status": "up"},
            {"name": "port9", "vdom": "customer-b", "type": "physical", "ip": "192.0.2.1 255.255.255.0",
             "allowaccess": "https", "status": "up"},
        ],
        "zones": [{"name": "dmz", "interface": [{"interface-name": "port3"}, {"interface-name": "port4"}],
                   "intrazone": "deny", "description": ""}],
        "addresses": [
            {"name": "all", "type": "ipmask", "subnet": "0.0.0.0 0.0.0.0"},
            {"name": "LAN-net", "type": "ipmask", "subnet": "10.0.10.0 255.255.255.0"},
            {"name": "SERVERS-net", "type": "ipmask", "subnet": "10.0.20.0 255.255.255.0"},
            {"name": "web-srv", "type": "ipmask", "subnet": "10.0.20.10 255.255.255.255"},
            {"name": "MGMT-net", "type": "ipmask", "subnet": "10.0.99.0 255.255.255.0"},
            {"name": "guest-range", "type": "iprange", "start-ip": "10.0.30.1", "end-ip": "10.0.30.6"},
            {"name": "updates", "type": "fqdn", "fqdn": "updates.example.com"},
            {"name": "geo-XX", "type": "geography", "country": "XX"},
        ],
        "addrgrps": [{"name": "internal-nets", "member": members("LAN-net", "SERVERS-net"), "exclude": "disable"},
                     {"name": "lan-minus", "member": members("LAN-net"), "exclude": "enable",
                      "exclude-member": members("web-srv")}],
        "addresses6": [{"name": "lan6", "type": "ipprefix", "ip6": "2001:db8:10::/64"}],
        "addrgrps6": [],
        "services": [
            {"name": "ALL", "protocol": "IP", "protocol-number": 0},
            {"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"},
            {"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"},
            {"name": "DNS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"},
            {"name": "SSH", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "22"},
            {"name": "ALL_ICMP", "protocol": "ICMP"},
            {"name": "WEB-ALT", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "8000-8080:1024-65535"},
            {"name": "webproxy", "protocol": "HTTP"},
        ],
        "servicegroups": [{"name": "Web Access", "member": members("HTTP", "HTTPS")}],
        "policies": [
            policy(10, "mgmt-in", "mgmt", "port2", ["MGMT-net"], ["LAN-net"], ["SSH"]),
            policy(3, "lan-to-web", "port2", "dmz", ["LAN-net"], ["web-srv"], ["Web Access"]),
            policy(7, "web-from-internet", "port1", "dmz", ["all"], ["web-srv"], ["HTTPS"], logtraffic="utm"),
            policy(5, "guest-block", "vlan30", "any", ["guest-range"], ["internal-nets"], ["ALL"], action="deny"),
            policy(4, "lan-out", "port2", "port1", ["all"], ["all"], ["ALL"], nat="enable",
                   comments="<b>outbound</b>"),
            policy(8, "o365", "port2", "port1", ["LAN-net"], [], [], **{"internet-service": "enable",
                   "internet-service-name": members("Microsoft-Office365"), "status": "disable"}),
            policy(9, "alt-web", "port2", "dmz", ["LAN-net"], ["SERVERS-net"], ["WEB-ALT", "DNS"]),
        ],
        "global": {"cfg-save": "automatic", "admin-sport": 443, "admin-ssh-port": 22, "hostname": "fgt-edge"},
        "central": {"type": "none"},
        "vdoms": [{"name": "root"}, {"name": "customer-b"}],
        "api_users": [{"name": "atrium", "accprofile": "atrium_rw", "vdom": members("root"),
                       "trusthost": [{"id": 1, "type": "ipv4-trusthost",
                                      "ipv4-trusthost": "10.0.99.0 255.255.255.0"}]}],
        "profiles": [{"name": "atrium_rw", "scope": "vdom", "fwgrp": "custom",
                      "fwgrp-permission": {"policy": "read-write", "address": "read-write", "service": "read-write"}},
                     {"name": "atrium_ro", "scope": "vdom", "fwgrp": "read", "netgrp": "read", "sysgrp": "read"}],
    }


KEYS = {"policies": "policyid"}


class FakeFortigate:
    """Just enough of FortiOS's REST API for the connector."""

    def __init__(self, version: str = "v7.4.4"):
        self.version = version
        self.state = default_state()
        self.denied: set[str] = set()
        self.calls: list[tuple[str, str, dict[str, str], Any, str | None]] = []
        self.transactions: dict[int, dict[str, Any]] = {}
        self.next_tid = 1
        self.hits = {"3": 1532, "4": 99120}
        self.unreachable = False
        self.tls_untrusted = False
        self.fail_on: tuple[str, str] | None = None  # (method, path) that answers an error
        self.commit_fails = False
        self.revisions: list[str] = []

    # -- helpers -------------------------------------------------------------------------

    def envelope(self, results: Any, **extra: Any) -> httpx.Response:
        return httpx.Response(200, json={"http_method": "GET", "revision": "c0ffee", "results": results, "vdom": "root",
                                         "status": "success", "http_status": 200, "serial": "FGVM01TM24000001",
                                         "version": self.version, "build": 2662, **extra})

    @staticmethod
    def error(code: int, number: int = -1) -> httpx.Response:
        return httpx.Response(code, json={"status": "error", "http_status": code, "error": number,
                                          "cli_error": "device text <script>x</script>"})

    def table(self, state: dict[str, Any], key: str) -> Any:
        return state[key]

    def find(self, state: dict[str, Any], key: str, mkey: str) -> dict[str, Any] | None:
        field = KEYS.get(key, "name")
        return next((r for r in state[key] if str(r.get(field)) == mkey), None)

    def policy(self, pid: int) -> dict[str, Any] | None:
        return self.find(self.state, "policies", str(pid))

    def objects(self, state: dict[str, Any]) -> set[str]:
        return {r["name"] for k in ("addresses", "addrgrps", "addresses6", "addrgrps6") for r in state[k]}

    def committed_calls(self, method: str, path: str) -> list[tuple]:
        return [c for c in self.calls if c[0] == method and c[1] == path]

    # -- routing ---------------------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectTimeout("timed out", request=request)
        if self.tls_untrusted:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=request)
        assert request.url.path.startswith("/api/v2/"), request.url
        assert "access_token" not in str(request.url)  # tokens never travel in the URL
        if request.headers.get("authorization") != f"Bearer {TOKEN}":
            return self.error(401)
        path = request.url.path[len("/api/v2"):]
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else None
        tid = request.headers.get("x-transaction-id")
        self.calls.append((request.method, path, params, body, tid))
        if self.fail_on == (request.method, path):
            return self.error(500, -5)
        return self.route(request.method, path, params, body, tid)

    def route(self, method: str, path: str, params: dict[str, str], body: Any, tid: str | None) -> httpx.Response:
        if path == "/monitor/system/status":
            return self.envelope({"model_name": "FortiGate", "model_number": "VM64", "hostname": "fgt-edge"})
        if path == "/monitor/firewall/policy":
            if "policies" in self.denied:
                return self.error(403)
            return self.envelope([{"policyid": int(k), "hit_count": v} for k, v in self.hits.items()])
        if path == "/monitor/system/config/backup":
            return self.backup(method, params)
        if path == "/monitor/system/config-revision/save":
            self.revisions.append(body.get("comments"))
            return self.envelope({"config_id": len(self.revisions)})
        if path == "/cmdb":
            return self.transaction(method, params, body)
        if not path.startswith("/cmdb/"):
            return self.error(404)
        rest = path[len("/cmdb/"):].split("/")
        table_path, mkey = "/".join(rest[:2]), "/".join(rest[2:]) or None
        key = TABLES.get(table_path)
        if key is None:
            return self.error(404)
        if key in self.denied or (key in ("api_users", "profiles") and "sys" in self.denied):
            return self.error(403)
        if tid is not None:
            work = self.transactions.get(int(tid))
            if work is None:
                return self.error(500, -651)
            return self.write(work["state"], work["lines"], method, key, mkey, params, body)
        if method == "GET":
            rows = self.table(self.state, key)
            if mkey is not None:
                found = self.find(self.state, key, mkey)
                return self.envelope([copy.deepcopy(found)]) if found else self.error(404, -3)
            return self.envelope(copy.deepcopy(rows))
        return self.write(self.state, [], method, key, mkey, params, body)  # outside a transaction: live at once

    def write(self, state: dict[str, Any], lines: list[str], method: str, key: str, mkey: str | None,
              params: dict[str, str], body: Any) -> httpx.Response:
        rows = state[key]
        field = KEYS.get(key, "name")
        if method == "POST":
            ident = str(body.get(field))
            if any(str(r.get(field)) == ident for r in rows):
                return self.error(500, -5)  # duplicate entry
            if key == "policies":
                problem = self.check_policy(state, body)
                if problem:
                    return self.error(500, problem)
            rows.append(copy.deepcopy(body))
            lines += [f"config {key}", f"edit {ident}", "end"]
            return self.envelope({}, mkey=ident)
        found = self.find(state, key, mkey or "")
        if found is None:
            return self.error(404, -3)
        if method == "PUT" and params.get("action") == "move":
            anchor = self.find(state, key, params.get("before") or params.get("after") or "")
            if anchor is None:
                return self.error(500, -3)
            rows.remove(found)
            index = rows.index(anchor) + (0 if "before" in params else 1)
            rows.insert(index, found)
            lines += [f"move {mkey} before {params.get('before')}"]
            return self.envelope({})
        if method == "PUT":
            found.update(copy.deepcopy(body))  # a partial update: only the given attributes
            lines += [f"edit {mkey}", "end"]
            return self.envelope({})
        if method == "DELETE":
            if key != "policies" and any(mkey in [m["name"] for f in ("srcaddr", "dstaddr", "service")
                                                  for m in p.get(f) or []] for p in state["policies"]):
                return self.error(500, -23)  # still referenced
            rows.remove(found)
            lines += [f"delete {mkey}"]
            return self.envelope({})
        return self.error(405)

    def check_policy(self, state: dict[str, Any], body: dict[str, Any]) -> int | None:
        zones = {z["name"]: [i["interface-name"] for i in z["interface"]] for z in state["zones"]}
        in_zone = {i for members_ in zones.values() for i in members_}
        interfaces = {i["name"] for i in state["interfaces"] if i["vdom"] == "root"}
        for side in ("srcintf", "dstintf"):
            for m in body[side]:
                if m["name"] not in zones and (m["name"] not in interfaces or m["name"] in in_zone):
                    return -3
        objects = self.objects(state)
        services = {s["name"] for k in ("services", "servicegroups") for s in state[k]}
        if any(m["name"] not in objects for f in ("srcaddr", "dstaddr") for m in body[f]):
            return -3
        if any(m["name"] not in services for m in body["service"]):
            return -3
        return None

    def transaction(self, method: str, params: dict[str, str], body: Any) -> httpx.Response:
        action = params.get("action")
        if action == "transaction-start":
            tid = self.next_tid
            self.next_tid += 1
            self.transactions[tid] = {"state": copy.deepcopy(self.state), "lines": []}
            return httpx.Response(200, json={"transaction-id": tid, "status": "success", "http_status": 200})
        if action == "transaction-show":
            work = self.transactions.get(int(params.get("transaction-id") or 0))
            return self.envelope(work["lines"]) if work else self.error(500, -651)
        tid = int((body or {}).get("transaction-id") or 0)
        work = self.transactions.pop(tid, None)
        if work is None:
            return self.error(500, -651)
        if action == "transaction-abort":
            return self.envelope({})
        if action == "transaction-commit":
            if self.commit_fails:
                return self.error(500, -1)
            self.state = work["state"]
            return self.envelope({})
        return self.error(405)

    def backup(self, method: str, params: dict[str, str]) -> httpx.Response:
        if "backup" in self.denied:
            return self.error(403)
        if parse_version(self.version) >= (7, 6, 0) and method != "POST":
            return self.error(405)
        if params.get("scope") != "global":
            return self.error(400)
        content = (f"#config-version=FGVM64-{self.version.lstrip('v')}-FW-build2662:opmode=0:vdom=0\n"
                   f"config system global\n    set hostname \"fgt-edge\"\nend\nconfig system admin\n    edit \"admin\"\n"
                   f"        set password {PASSWORD_HASH}\n    next\nend\n")
        return httpx.Response(200, content=content.encode(), headers={"content-type": "application/octet-stream"})


@pytest.fixture
def fake() -> FakeFortigate:
    return FakeFortigate()


def connector(fake: FakeFortigate, **config: Any) -> FortigateConnector:
    """A new instance (= a new connection), as the hub builds one per call. The hub manages the FortiGate from the
    MGMT network (10.0.99.10)."""
    config = {"hub_address": "10.0.99.10", **config}
    return FortigateConnector(clean_config(FortigateConnector, {"base_url": BASE, **{k: v for k, v in config.items()
                                                                                      if v is not None}}),
                              {"api_token": TOKEN}, httpx.MockTransport(fake))


def snapshot(fake: FakeFortigate, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


ALLOW = parse_ops([{"op": "allow", "source": {"zone": "port2", "cidrs": ["10.0.10.0/24"]},
                    "destination": {"zone": "port3", "cidrs": ["10.0.20.0/24"]},
                    "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Users to intranet",
                    "marker": "atrium:chg_7"}])
ALLOW_NEW = parse_ops([{"op": "allow", "source": {"zone": "vlan30", "cidrs": ["10.0.30.0/24"]},
                        "destination": {"zone": "dmz", "cidrs": ["10.0.40.0/24"]},
                        "services": [{"proto": "tcp", "ports": "8443,9443"}, {"proto": "icmp"}], "log": False,
                        "marker": "atrium:chg_8"}])


def disable(*pids: int) -> list[dict[str, Any]]:
    return parse_ops([{"op": "disable_rules", "rules": [{"id": str(p), "vendor_ref": str(p)} for p in pids]}])


def rule(record: dict[str, Any], rid: str) -> dict[str, Any]:
    return next(r for r in record["rules"] if r["id"] == rid)


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_policies_zones_and_objects_into_the_network_model(fake):
    record = snapshot(fake)
    assert record["external_id"] == "FGVM01TM24000001" and record["kind"] == "firewall"
    assert record["device"] == {"vendor": "Fortinet", "model": "FortiGate VM64", "version": "7.4.4",
                                "hostname": "fgt-edge", "management_address": "fgt.example.net",
                                "serial": "FGVM01TM24000001"}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"port1", "port2", "port3", "port4", "vlan30", "mgmt"}  # port9 is another VDOM's
    assert ifaces["port1"]["role"] == "wan" and ifaces["port1"]["subnets"] == ["203.0.113.0/29"]
    assert ifaces["port2"]["name"] == "LAN" and ifaces["vlan30"]["vlan"] == 30 and ifaces["mgmt"]["role"] == "mgmt"
    assert ifaces["port4"]["enabled"] is False and ifaces["port3"]["role"] == "other"
    assert "10.0.99.1" in record["self_addresses"] and "192.0.2.1" not in record["self_addresses"]
    assert record["zones"] == [{"id": "dmz", "name": "dmz", "description": "", "interfaces": ["port3", "port4"]}]
    assert record["default_policy"] == {"forward": "block", "inbound": "block"}

    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["LAN-net"]["cidrs"] == ["10.0.10.0/24"] and aliases["web-srv"]["kind"] == "host"
    assert aliases["guest-range"]["cidrs"] == ["10.0.30.1/32", "10.0.30.2/31", "10.0.30.4/31", "10.0.30.6/32"]
    assert aliases["internal-nets"]["cidrs"] == ["10.0.10.0/24", "10.0.20.0/24"] and aliases["internal-nets"]["resolved"]
    assert aliases["lan-minus"]["resolved"] is False  # exclude-members cannot be expressed as a list of networks
    assert aliases["updates"]["resolved"] is False and aliases["geo-XX"]["kind"] == "geoip"
    assert aliases["lan6"]["cidrs"] == ["2001:db8:10::/64"]

    policies = [r for r in record["rules"] if not r["id"].startswith("access:")]
    assert [r["id"] for r in policies] == ["10", "3", "7", "5", "4", "8", "9"]  # evaluation order, not policyid order
    assert all(r["vendor_ref"] == r["id"] for r in policies)
    web = rule(record, "3")
    assert web["interfaces"] == ["port2"] and web["destination_zones"] == ["dmz"] and web["out_interfaces"] == []
    assert web["source"]["aliases"] == ["LAN-net"] and web["destination"]["aliases"] == ["web-srv"]
    assert [(s["proto"], s["ports"]) for s in web["services"]] == [("tcp", "80"), ("tcp", "443")]
    assert web["hits"] == 1532 and web["log"] and web["description"] == "lan-to-web"
    assert rule(record, "7")["source"]["any"] and rule(record, "7")["log"] is False  # logtraffic utm
    guest = rule(record, "5")
    assert guest["action"] == "block" and guest["out_interfaces"] == [] and guest["services"] is None
    out = rule(record, "4")
    assert out["source"]["any"] and out["destination"]["any"] and out["services"] is None
    assert out["description"] == "lan-out - <b>outbound</b>"  # device text stays text (never HTML)
    o365 = rule(record, "8")
    assert not o365["enabled"] and o365["destination"]["aliases"] == ["isdb:Microsoft-Office365"]
    alt = rule(record, "9")
    assert [(s["proto"], s["ports"]) for s in alt["services"]] == [("tcp", "8000-8080"), ("tcp", "53"), ("udp", "53")]

    access = {r["id"]: r for r in record["rules"] if r["id"].startswith("access:")}
    assert set(access) == {"access:port1", "access:port2", "access:port3", "access:vlan30", "access:mgmt"}
    assert access["access:mgmt"]["destination"]["self"] and access["access:mgmt"]["interfaces"] == ["mgmt"]
    assert {(s["proto"], s["ports"]) for s in access["access:mgmt"]["services"]} == {("tcp", "443"), ("tcp", "22"),
                                                                                      ("icmp", None)}
    assert {(s["proto"], s["ports"]) for s in access["access:port1"]["services"]} == {("icmp", None), ("tcp", "541")}
    assert any("allowaccess" in n for n in record["notes"]) and any("Internet Service" in n for n in record["notes"])
    assert TOKEN not in json.dumps(record) and "<script>" not in json.dumps(record)


def test_management_exposure_on_the_wan_is_visible(fake):
    from hub.connectors.netmodel import exposes_management

    record = snapshot(fake)
    assert not any(exposes_management(record, r) for r in record["rules"])
    fake.state["interfaces"][0]["allowaccess"] = "ping https ssh"
    fake.state["global"]["admin-sport"] = 8443
    record = snapshot(fake)
    wan = rule(record, "access:port1")
    assert exposes_management(record, wan) and ("tcp", "8443") in {(s["proto"], s["ports"]) for s in wan["services"]}


def test_revision_follows_the_configuration_not_counters(fake):
    first = snapshot(fake)
    fake.hits["3"] = 99999
    assert snapshot(fake)["revision"] == first["revision"]
    fake.policy(3)["comments"] = "edited in the GUI"
    assert snapshot(fake)["revision"] != first["revision"]


def test_versions_before_7_0_are_refused(fake):
    fake.version = "v6.4.15"
    with pytest.raises(Exception, match="not supported"):
        run(connector(fake).pull("network"))
    result = run(connector(fake).test())
    assert result["ok"] is False and result["network_write"] is None
    assert not next(c for c in result["checks"] if c["name"] == "version")["ok"]


def test_missing_optional_permissions_degrade_with_notes(fake):
    fake.denied = {"addresses", "addrgrps", "services", "servicegroups"}
    record = snapshot(fake)
    assert any("Firewall > Address" in n for n in record["notes"])
    web = rule(record, "3")
    assert web["source"]["aliases"] == ["LAN-net"] and web["services"][0]["alias"] == "Web Access"
    fake.denied = {"policies"}
    with pytest.raises(Exception, match="Firewall > Policy"):
        run(connector(fake).pull("network"))


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def names(result: dict[str, Any]) -> list[str]:
    return [c["name"] for c in result["checks"]]


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


def test_test_reports_each_step_and_the_write_capability(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    assert names(result)[:6] == ["reachability", "tls", "authentication", "privileges", "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "backup_restore",
                                       "window_s": 300}
    assert "write access not checked" in detail(result, "privileges")
    assert "super_admin" in detail(result, "privileges")
    assert "configuration transactions: yes" in detail(result, "api_features")
    assert "FortiOS 7.4.4 - supported" in detail(result, "version")
    assert "Connected to FortiOS 7.4.4 (fgt-edge)" in result["detail"]
    assert not [c for c in fake.calls if c[0] != "GET"]  # the test changed nothing

    result = run(connector(fake, api_user="atrium").test())  # the profile can write policies
    assert result["network_write"] and "read-only one is recommended" in detail(result, "privileges")
    assert "atrium_rw" in detail(result, "privileges")
    fake.state["api_users"][0]["accprofile"] = "atrium_ro"
    result = run(connector(fake, api_user="atrium").test())
    assert result["ok"] and result["network_write"] is None and "read-only profile" in detail(result, "privileges")
    fake.state["api_users"][0]["accprofile"] = "super_admin"
    result = run(connector(fake, api_user="atrium").test())
    assert "configuration backups: yes" in detail(result, "privileges")
    fake.state["api_users"][0]["trusthost"][0]["ipv4-trusthost"] = "192.0.2.0 255.255.255.0"
    fake.state["api_users"][0]["accprofile"] = "atrium_rw"
    result = run(connector(fake, api_user="atrium").test())
    assert "not in the API user's trusted hosts" in detail(result, "privileges")


@pytest.mark.parametrize("change, reason", [
    (lambda f: setattr(f, "version", "v7.2.8"), "7.4.1 or later"),
    (lambda f: f.state["global"].update({"cfg-save": "revert"}), "save mode"),
    (lambda f: f.state["central"].update({"type": "fortimanager"}), "FortiManager"),
    (lambda f: f.denied.add("global"), "save mode cannot be read"),
])
def test_write_capability_needs_a_safe_device(fake, change, reason):
    change(fake)
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None, result
    assert reason in detail(result, "privileges")
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"
    assert not fake.transactions and not [c for c in fake.calls if c[1] == "/cmdb"]


def test_test_read_only_setting(fake):
    result = run(connector(fake, read_only=True).test())
    assert result["ok"] and result["network_write"] is None and result["detail"].endswith("(read only)")
    assert connector(fake, read_only=True).write_capability() is None
    result = run(connector(fake, hub_address="10.0.99.10").test())
    assert "10.0.99.10" in detail(result, "management_guard")


def test_test_failures_say_what_to_fix(fake):
    fake.unreachable = True
    result = run(connector(fake).test())
    assert result["ok"] is False and names(result) == ["reachability"] and "did not answer in time" in result["detail"]
    fake.unreachable, fake.tls_untrusted = False, True
    result = run(connector(fake).test())
    assert names(result) == ["reachability", "tls"] and "CA certificate file" in detail(result, "tls")
    fake.tls_untrusted = False
    bad = FortigateConnector({"base_url": BASE}, {"api_token": "wrong-token-value"}, httpx.MockTransport(fake))
    result = run(bad.test())
    assert names(result)[-1] == "authentication" and "trusted hosts" in result["detail"]
    assert "wrong-token-value" not in json.dumps(result) and TOKEN not in json.dumps(result)
    fake.denied = {"policies", "interfaces"}
    result = run(connector(fake).test())
    assert result["ok"] is False and "Firewall > Policy: Read" in detail(result, "privileges")
    fake.denied = set()
    result = run(connector(fake, verify_tls=False).test())
    assert not next(c for c in result["checks"] if c["name"] == "tls")["ok"]


def test_config_validation():
    cfg = clean_config(FortigateConnector, {"base_url": "https://fgt:10443/api/v2/"})
    assert cfg["base_url"] == "https://fgt:10443" and cfg["vdom"] == "root"
    for bad in ("http://fgt", "https://user:pw@fgt", "fgt.example.net", "https://fgt/?access_token=1"):
        with pytest.raises(ValueError):
            clean_config(FortigateConnector, {"base_url": bad})
    with pytest.raises(ValueError, match="VDOM"):
        clean_config(FortigateConnector, {"base_url": BASE, "vdom": "root'; drop"})
    with pytest.raises(ValueError, match="absolute"):
        clean_config(FortigateConnector, {"base_url": BASE, "ca_file": "ca.pem"})
    with pytest.raises(ValueError, match="IP address"):
        clean_config(FortigateConnector, {"base_url": BASE, "hub_address": "hub.local"})
    with pytest.raises(ValueError, match="admin name"):
        clean_config(FortigateConnector, {"base_url": BASE, "api_user": "../x"})
    assert FortigateConnector.endpoint({"base_url": BASE, "verify_tls": False}) != \
        FortigateConnector.endpoint({"base_url": BASE, "verify_tls": True})


def test_vdom_options_and_detection(fake):
    from hub.models import Manifest, Tool

    assert run(connector(fake).options("vdom")) == [{"value": "root", "label": "root"},
                                                    {"value": "customer-b", "label": "customer-b"}]
    tool = Tool(id="fgt1", name="FortiGate edge", source_type="saas", source="https://fortinet.com", status="ready",
                manifest=Manifest(id="fgt1", name="FortiGate edge", kind="saas"))
    assert FortigateConnector.detect(tool) == 90
    other = Tool(id="faz", name="FortiAnalyzer", source_type="saas", source="https://fortinet.com", status="ready",
                 manifest=Manifest(id="faz", name="FortiAnalyzer", kind="saas"))
    assert FortigateConnector.detect(other) == 50  # another Fortinet product: only a weak hint


# --------------------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------------------


def test_apply_reuses_objects_moves_the_policy_and_confirms(fake):
    before = snapshot(fake)
    preview = run(connector(fake).preview_change(ALLOW, before))
    assert preview["problems"] == [], preview
    step = preview["steps"][0]
    assert step["kind"] == "add_rule" and "before policy 3" in step["position"] and "new objects" not in step["detail"]
    assert any("is in zone dmz" in n for n in preview["notes"])
    assert not [c for c in fake.calls if c[0] != "GET"]  # a preview writes nothing

    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert applied["rollback_until"] is None and applied["created"] == [{"op": 0, "id": "11", "vendor_ref": "11"}]
    token = json.loads(applied["token"])
    assert token == {"v": 1, "vdom": "root", "policies": [11], "addresses": [], "services": [], "toggled": {}}
    staged = [c for c in fake.calls if c[4] is not None]
    assert [(m, p) for m, p, *_ in staged] == [("POST", "/cmdb/firewall/policy"), ("PUT", "/cmdb/firewall/policy/11")]
    assert all(c[4] == "1" for c in staged) and staged[1][2] == {"vdom": "root", "action": "move", "before": "3"}
    actions = [c[2].get("action") for c in fake.calls if c[1] == "/cmdb"]
    assert actions == ["transaction-start", "transaction-show", "transaction-commit"]
    created = fake.policy(11)
    assert created["srcintf"] == [{"name": "port2"}] and created["dstintf"] == [{"name": "dmz"}]
    assert created["srcaddr"] == [{"name": "LAN-net"}] and created["dstaddr"] == [{"name": "SERVERS-net"}]
    assert created["service"] == [{"name": "HTTPS"}] and created["comments"] == "atrium:chg_7 Users to intranet"
    assert created["name"] == "atrium-chg_7" and created["logtraffic"] == "all" and created["nat"] == "disable"
    assert fake.revisions == ["before Atrium atrium:chg_7"]

    after = snapshot(fake)  # a new connection
    assert ops_applied(after, ALLOW) == []
    assert rule(after, "11")["order"] < rule(after, "3")["order"] and rule(after, "11")["marker"] == "chg_7"
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]
    revert = inverse_ops(ALLOW, applied)  # a revert is a new change: the created policy is disabled
    again = run(connector(fake).apply_change(revert, after["revision"], None))
    assert again["disabled"] == ["11"] and ops_reverted(before, snapshot(fake), ALLOW) == []


def test_apply_creates_exact_objects_and_rollback_removes_them(fake):
    before = snapshot(fake)
    ops = ALLOW_NEW + disable(9)
    preview = run(connector(fake).preview_change(ops, before))
    assert preview["problems"] == [] and "new objects" in preview["steps"][0]["detail"]
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    token = json.loads(applied["token"])
    assert token["addresses"] == ["atrium-net-10.0.30.0_24", "atrium-net-10.0.40.0_24"]
    assert token["services"] == ["atrium-tcp-8443_9443"] and token["toggled"] == {"9": "enable"}
    svc = next(s for s in fake.state["services"] if s["name"] == "atrium-tcp-8443_9443")
    assert svc["tcp-portrange"] == "8443 9443" and svc["protocol"] == "TCP/UDP/SCTP"
    new = fake.policy(int(applied["created"][0]["id"]))
    assert new["service"] == [{"name": "atrium-tcp-8443_9443"}, {"name": "ALL_ICMP"}] and new["logtraffic"] == "disable"
    assert new["srcintf"] == [{"name": "vlan30"}] and new["dstintf"] == [{"name": "dmz"}]
    after = snapshot(fake)
    assert ops_applied(after, ops) == [] and rule(after, "9")["enabled"] is False
    assert applied["disabled"] == ["9"]

    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled == {"rolled_back": True, "method": "inverse_ops", "notes": []}
    assert fake.policy(int(applied["created"][0]["id"])) is None and fake.policy(9)["status"] == "enable"
    assert "atrium-net-10.0.30.0_24" not in fake.objects(fake.state)
    assert not any(s["name"].startswith("atrium-") for s in fake.state["services"])
    assert ops_reverted(before, snapshot(fake), ops) == []
    again = run(connector(fake).rollback_change(applied["token"], None))  # nothing left to undo
    assert again["rolled_back"] and "no longer held" in again["notes"][0]


def test_a_failed_write_aborts_the_transaction_and_changes_nothing(fake):
    before = snapshot(fake)
    state = copy.deepcopy(fake.state)
    fake.fail_on = ("POST", "/cmdb/firewall/policy")
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW_NEW, before["revision"], None))
    assert caught.value.state == "unchanged" and caught.value.code == "failed"
    assert "error -5" in caught.value.message and "<script>" not in caught.value.message  # device text not quoted
    assert fake.state == state and not fake.transactions
    assert [c[2].get("action") for c in fake.calls if c[1] == "/cmdb"] == ["transaction-start", "transaction-abort"]


def test_a_failed_commit_is_settled_by_a_re_read(fake):
    before = snapshot(fake)
    fake.commit_fails = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "unchanged" and fake.policy(11) is None


def test_stale_lockout_and_refused_ops(fake):
    before = snapshot(fake)
    fake.policy(3)["comments"] = "changed meanwhile"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.code == "stale" and caught.value.state == "unchanged"

    record = snapshot(fake)
    preview = run(connector(fake).preview_change(disable(4), record))  # lan-out carries the hub's traffic
    assert any("cut the hub off" in p for p in preview["problems"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable(4), record["revision"], None))
    assert caught.value.code == "lockout"
    assert run(connector(fake).preview_change(disable(3), record))["problems"] == []

    access = parse_ops([{"op": "disable_rules", "rules": [{"id": "access:mgmt", "vendor_ref": "access:mgmt"}]}])
    assert any("interface settings" in p for p in run(connector(fake).preview_change(access, record))["problems"])
    missing = parse_ops([{"op": "disable_rules", "rules": [{"id": "../../system/admin", "vendor_ref": "77"}]}])
    assert any("not on the FortiGate" in p for p in run(connector(fake).preview_change(missing, record))["problems"])
    six = parse_ops([{"op": "allow", "source": {"zone": "port2", "cidrs": ["2001:db8:10::/64"]},
                      "destination": {"zone": "dmz", "cidrs": ["2001:db8:20::/64"]},
                      "services": [{"proto": "tcp", "ports": "443"}], "marker": "atrium:chg_9"}])
    assert any("IPv6" in p for p in run(connector(fake).preview_change(six, record))["problems"])
    nowhere = parse_ops([{"op": "allow", "source": {"zone": "port9", "cidrs": ["10.9.0.0/24"]},
                          "destination": {"zone": "dmz", "cidrs": ["10.0.20.0/24"]},
                          "services": [{"proto": "udp", "ports": "53"}], "marker": "atrium:chg_10"}])
    assert any("no interface or zone 'port9'" in p for p in run(connector(fake).preview_change(nowhere, record))["problems"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(nowhere, record["revision"], None))
    assert caught.value.code == "invalid"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake, read_only=True).apply_change(ALLOW, record["revision"], None))
    assert caught.value.code == "unsupported"
    assert not [c for c in fake.calls if c[0] != "GET"]


def test_disabling_an_already_disabled_policy_writes_nothing(fake):
    before = snapshot(fake)
    ops = disable(8)
    assert "nothing to write" in run(connector(fake).preview_change(ops, before))["steps"][0]["detail"]
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["disabled"] == [] and not [c for c in fake.calls if c[0] != "GET" and "config-revision" not in c[1]]
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]


def test_confirm_reports_a_change_that_disappeared(fake):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    fake.state["policies"] = [p for p in fake.state["policies"] if p["policyid"] != 11]
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).confirm_change(applied["token"]))
    assert caught.value.state == "rolled_back"


def test_tokens_are_validated(fake):
    for bad in ("{}", "not json", json.dumps({"v": 1, "vdom": "root", "policies": ["1; drop"]}),
                json.dumps({"v": 1, "vdom": "root", "addresses": ["../../system/admin/admin"]}),
                json.dumps({"v": 1, "vdom": "other", "policies": [11]})):
        with pytest.raises(ChangeError) as caught:
            run(connector(fake).rollback_change(bad, None))
        assert caught.value.code == "invalid"


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("version, method", [("v7.4.4", "GET"), ("v7.6.5", "POST")])
def test_backup_uses_the_method_of_the_version(fake, version, method):
    fake.version = version
    taken = run(connector(fake).backup())
    assert taken["format"] == "text" and PASSWORD_HASH.encode() in taken["content"]
    assert [c[0] for c in fake.calls if c[1] == "/monitor/system/config/backup"] == [method]
    assert taken["content"].startswith(b"#config-version")
    assert PASSWORD_HASH not in json.dumps(snapshot(fake))


def test_backup_needs_super_admin_and_restore_is_left_to_the_gui(fake):
    fake.denied = {"backup"}
    with pytest.raises(Exception, match="super_admin"):
        run(connector(fake).backup())
    assert not FortigateConnector.implements("restore_backup")
    content = b"#config-version=x\nconfig system global\nend\n"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk", content, hashlib.sha256(content).hexdigest(), 0.0)))
    assert caught.value.code == "unsupported" and caught.value.state == "unchanged"


def test_errors_never_carry_secrets(fake):
    fake.denied = {"policies"}
    with pytest.raises(Exception) as caught:
        run(connector(fake).pull("network"))
    assert TOKEN not in str(caught.value.as_dict())
    fake.denied = set()
    fake.fail_on = ("POST", "/cmdb/firewall/policy")
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert TOKEN not in json.dumps(caught.value.as_dict())


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeFortigate()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", httpx.MockTransport(fake), raising=False)
    tool = Tool(id="fgt1", name="FortiGate edge", source_type="saas", source="https://fortinet.com", status="ready",
                manifest=Manifest(id="fgt1", name="FortiGate edge", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    catalog = client.get("/api/connectors").json()
    assert any(c["kind"] == "fortigate" and c["network_write"]["rollback"] == "backup_restore" and c["can_backup"]
               for c in catalog)
    response = client.put("/api/tools/fgt1/connection", json={"kind": "fortigate", "config": {"base_url": BASE},
                                                              "secrets": {"api_token": TOKEN}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/fgt1/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "backup_restore", tested
    assert TOKEN not in json.dumps(tested)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "fgt1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=fgt1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/fgt1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/fgt1").json()
    assert device["record"]["device"]["vendor"] == "Fortinet" and len(device["record"]["rules"]) == 12
    assert TOKEN not in json.dumps(device) and PASSWORD_HASH not in json.dumps(device)
    seg = client.get("/api/segmentation?firewall=fgt1").json()
    edges = {(e["source"], e["target"]) for e in seg["edges"]}
    assert ("z:fgt1:port2", "z:fgt1:dmz") in edges and ("z:internet", "z:fgt1:dmz") in edges, edges
    backup = client.post("/api/network/devices/fgt1/backups")
    assert backup.status_code == 201, backup.text
    assert PASSWORD_HASH not in backup.text
