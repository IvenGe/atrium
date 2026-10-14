"""The OPNsense connector against a fake OPNsense API (httpx.MockTransport, no network). The fake follows the
opnsense/core sources: search_rule rows with raw values plus classic/automatic ("legacy") rows, HTTP 200
{"result": "failed"} answers, privileges per URL, "Deny config write", config history entries per save, the 26.1
savepoint timer (60 s) and its removal in 26.7."""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import json
import uuid as uuidlib
from html import escape
from typing import Any

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.netmodel import (Backup, ChangeError, inverse_ops, ops_applied, ops_reverted,
                                     parse_ops)
from hub.connectors.opnsense import OpnsenseConnector, parse_version
from hub.integration.connections import clean_config

KEY, SECRET = "opn-key-8f7e6d5c4b3a2918", "opn-secret-0a1b2c3d4e5f6a7b8c9d"
BASE = "https://fw1.example.net"
PASSWORD_HASH = "$2y$11$opnsense-root-password-hash-do-not-leak"
PRIVILEGE_PATHS = (("/firewall/filter_util/", "stats"), ("/firewall/filter/", "rules"), ("/firewall/alias/", "aliases"),
                   ("/firewall/group/", "groups"), ("/interfaces/overview/", "interfaces"),
                   ("/diagnostics/system/", "version"), ("/core/backup/", "backups"))
U = {name: str(uuidlib.uuid5(uuidlib.NAMESPACE_DNS, name)) for name in ("r1", "r2", "r3", "r4", "r5", "r6")}


def run(coro):
    return asyncio.run(coro)


def mvc(name: str, **fields: Any) -> tuple[str, dict[str, Any]]:
    rule = {"enabled": "1", "sequence": "100", "action": "pass", "quick": "1", "interface": "lan", "interfacenot": "0",
            "direction": "in", "ipprotocol": "inet", "protocol": "any", "source_net": "any", "source_not": "0",
            "source_port": "", "destination_net": "any", "destination_not": "0", "destination_port": "", "log": "0",
            "categories": "", "description": "", "statetype": "keep"}
    rule.update(fields)
    return U[name], rule


class FakeOpnsense:
    """Just enough of OPNsense's API for the connector."""

    def __init__(self, version: str = "26.7.6", *, read_only: bool = False):
        self.version = version
        self.savepoints_supported = parse_version(version) < (26, 7, 0)
        self.read_only = read_only
        self.denied: set[str] = set()
        self.now = [1000.0]
        self.calls: list[tuple[str, str, Any]] = []
        self.unreachable = False
        self.tls_untrusted = False
        self.lockout_after_apply = False
        self.locked = False
        self.fail_add = False
        self.fail_delete = False
        self.interfaces = [
            {"identifier": "wan", "description": "WAN", "device": "igb0", "enabled": True, "status": "up",
             "ipv4": [{"ipaddr": "203.0.113.2/29"}], "ipv6": [{"ipaddr": "fe80::1%igb0/64"}], "vlan_tag": None,
             "gateways": ["203.0.113.1"], "link_type": "dhcp"},
            {"identifier": "lan", "description": "LAN", "device": "igb1", "enabled": True, "status": "up",
             "ipv4": [{"ipaddr": "10.0.10.1/24"}], "ipv6": [], "vlan_tag": None, "gateways": []},
            {"identifier": "opt1", "description": "SERVERS", "device": "vlan0.20", "enabled": True, "status": "up",
             "ipv4": [{"ipaddr": "10.0.20.1/24"}], "vlan_tag": "20", "gateways": []},
            {"identifier": "opt2", "description": "MGMT", "device": "vlan0.99", "enabled": True, "status": "up",
             "ipv4": [{"ipaddr": "10.0.99.1/24"}], "vlan_tag": 99, "gateways": []},
            {"identifier": "", "description": "Unassigned Interface", "device": "igb3", "status": "down"},
        ]
        self.aliases = [
            self.alias("MGMT_NET", "network", "10.0.99.0/24"),
            self.alias("WEB_SERVERS", "host", "10.0.20.10\n10.0.20.11"),
            self.alias("ADMINS", "host", "10.0.10.5\nbastion.example.net"),
            self.alias("INTERNAL_NETS", "networkgroup", "MGMT_NET\nWEB_SERVERS"),
            self.alias("WEB_PORTS", "port", "80\nhttps\n8000:8080"),
            self.alias("BLOCKLIST", "urltable", "https://lists.example.net/drop.txt"),
            self.alias("RANGE", "host", "10.0.30.1-10.0.30.6"),
            self.alias("__lan_network", "internal", ""),
        ]
        self.groups = [{"uuid": str(uuidlib.uuid4()), "ifname": "INTERNAL", "members": "lan,opt1", "nogroup": "0",
                        "sequence": "0", "descr": "internal networks"}]
        self.rules: dict[str, dict[str, Any]] = dict([
            mvc("r1", sequence="100", source_net="lan", description="Allow LAN to any"),
            mvc("r2", sequence="200", interface="wan", protocol="TCP", destination_net="WEB_SERVERS",
                destination_port="WEB_PORTS", log="1", description="Web servers from the internet"),
            mvc("r3", sequence="300", interface="INTERNAL", protocol="TCP", source_net="INTERNAL",
                destination_net="MGMT_NET", destination_port="ssh", description="SSH to management"),
            mvc("r4", sequence="400", interface="lan,opt1", action="block", destination_net="10.66.0.0/16",
                description="Block lab"),
            mvc("r5", sequence="500", interface="opt2", protocol="TCP", source_net="MGMT_NET",
                destination_net="(self)", destination_port="443", description="GUI from MGMT"),
            mvc("r6", sequence="600", interface="wan", interfacenot="1", protocol="ICMP", destination_net="opt2ip",
                enabled="0", description="ping <script>alert(1)</script>"),
        ])
        self.legacy = [
            {"legacy": True, "is_automatic": True, "uuid": "02f4bab031b57d1e30553ce08e0ec131", "enabled": "1",
             "interface": "LAN", "action": "pass", "direction": "in", "ipprotocol": "inet", "protocol": "tcp",
             "source_net": "any", "destination_net": "(self)", "destination_port": "443 80 22",
             "description": "Anti-Lockout Rule", "sort_order": "000005.1000001", "%action": "pass"},
            {"legacy": True, "is_automatic": True, "uuid": "fae559ec2cef8b8a5bd4bc42a2cf5e2f", "enabled": "1",
             "interface": "", "action": "block", "direction": "in", "ipprotocol": "inet46", "protocol": "",
             "source_net": "any", "destination_net": "any", "description": "Default deny / state violation rule",
             "sort_order": "000099.1000002"},
            {"legacy": True, "is_automatic": False, "uuid": "8d1f4c6b2a9e7f3c5d0b1a2e3f4c5d6e", "enabled": "1",
             "interface": "LAN", "action": "pass", "direction": "in", "ipprotocol": "inet", "protocol": "udp",
             "source_net": "lan", "destination_net": "lanip", "destination_port": "53",
             "description": "DNS to the firewall", "sort_order": "400000.1000003"},
        ]
        self.history: list[dict[str, Any]] = []
        self.savepoints: dict[str, dict[str, Any]] = {}
        self.pending: dict[str, Any] | None = None
        self.running = copy.deepcopy(self.rules)
        self.save("initial configuration")

    @staticmethod
    def alias(name: str, kind: str, content: str) -> dict[str, Any]:
        return {"uuid": str(uuidlib.uuid4()), "enabled": "1", "name": name, "type": kind, "%type": kind.title(),
                "proto": "", "content": content, "description": "", "current_items": "2",
                "last_updated": "2026-10-09T10:00:00", "in_pass_p": "12"}

    # -- device behaviour ------------------------------------------------------------------

    def config_xml(self) -> str:
        return (f'<?xml version="1.0"?>\n<opnsense><system><hostname>fw1</hostname><user><name>root</name>'
                f"<password>{PASSWORD_HASH}</password></user></system><OPNsense><Firewall><Filter>"
                f"{escape(json.dumps(self.rules, sort_keys=True))}</Filter></Firewall></OPNsense></opnsense>\n")

    def save(self, description: str) -> None:
        self.now[0] += 0.01
        stamp = f"{self.now[0]:.4f}"
        self.history.append({"time": stamp, "id": f"config-{stamp}.xml", "description": description,
                             "xml": self.config_xml(), "rules": copy.deepcopy(self.rules)})

    def tick(self) -> None:
        if self.pending and self.now[0] >= self.pending["deadline"]:
            self.rules = copy.deepcopy(self.savepoints[self.pending["rev"]])
            self.running = copy.deepcopy(self.rules)
            self.pending, self.locked = None, False
            self.save("rollback")

    def rows(self) -> list[dict[str, Any]]:
        out = []
        for uid, rule in self.rules.items():
            ifaces = [i for i in rule["interface"].split(",") if i]
            prio = 200000 if len(ifaces) != 1 or rule["interfacenot"] == "1" else \
                300000 if ifaces[0] in {g["ifname"] for g in self.groups} else 400000
            out.append({"uuid": uid, **rule, "sort_order": f"{prio}.0{int(rule['sequence']):06d}",
                        "prio_group": str(prio), "%action": rule["action"].title(), "category_colors": [],
                        "alias_meta_source_net": {}})
        if parse_version(self.version) >= (26, 1, 0):
            out += copy.deepcopy(self.legacy)
        else:  # 25.x: without an interface only the floating rules
            out = [r for r in out if r["prio_group"] == "200000"]
        return sorted(out, key=lambda r: float(r["sort_order"]))

    # -- HTTP ------------------------------------------------------------------------------

    @staticmethod
    def grid(rows: list[dict[str, Any]], body: Any) -> dict[str, Any]:
        count = int((body or {}).get("rowCount", -1))
        page = rows if count == -1 else rows[:count]
        return {"total": len(rows), "rowCount": len(page), "current": 1, "rows": page}

    def denied_write(self) -> httpx.Response | None:
        if self.read_only:
            return httpx.Response(500, json={"errorMessage": "User atrium denied for write access "
                                                             "(user-config-readonly set)",
                                             "errorTitle": "General access", "errorLevel": "error"})
        return None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.tick()
        if self.unreachable or self.locked:
            raise httpx.ConnectTimeout("timed out", request=request)
        if self.tls_untrusted:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed "
                                     "certificate (_ssl.c:1006)", request=request)
        expected = "Basic " + base64.b64encode(f"{KEY}:{SECRET}".encode()).decode()
        if request.headers.get("Authorization") != expected:
            return httpx.Response(401, json={"status": 401, "message": "Authentication Failed"})
        assert request.url.path.startswith("/api/"), request.url.path
        path = request.url.path[4:]
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        privilege = next((p for prefix, p in PRIVILEGE_PATHS if path.startswith(prefix)), None)
        if privilege in self.denied:
            return httpx.Response(403, json={"status": 403, "message": "Forbidden"})
        answer = self.route(request.method, path, body)
        if isinstance(answer, httpx.Response):
            return answer
        if answer is None:
            return httpx.Response(404, json={"errorMessage": "Endpoint not found"})
        return httpx.Response(200, json=answer)

    def route(self, method: str, path: str, body: Any) -> Any:
        parts = path.strip("/").split("/")
        if path == "/diagnostics/system/system_information":
            return {"name": "fw1.example.lan", "versions": [f"OPNsense {self.version}-amd64", "FreeBSD 14.3-RELEASE-p4",
                                                            "OpenSSL 3.0.17"], "updates": "Click to check for updates."}
        if path == "/interfaces/overview/interfaces_info":
            return self.grid(self.interfaces, {"rowCount": 9999})
        if path == "/firewall/alias/search_item":
            return self.grid(self.aliases, body)
        if path == "/firewall/group/search_item":
            return self.grid(self.groups, body)
        if path == "/firewall/filter_util/rule_stats":
            return {"status": "ok", "stats": {U["r1"]: {"pf_rules": 1, "evaluations": 99, "packets": 15320,
                                                        "bytes": 1, "states": 3},
                                              "02f4bab031b57d1e30553ce08e0ec131": {"packets": 7}}}
        if path == "/firewall/filter/search_rule":
            return self.grid(self.rows(), body)
        if parts[:2] == ["firewall", "filter"] and len(parts) >= 3:
            return self.filter(method, parts[2], parts[3:], body)
        if parts[:2] == ["core", "backup"]:
            return self.backup(method, parts[2], parts[3:])
        return None

    def filter(self, method: str, action: str, args: list[str], body: Any) -> Any:
        if action == "savepoint":
            if not self.savepoints_supported:
                return None
            if method != "POST":
                return {"status": "error"}
            if denied := self.denied_write():
                return denied
            self.save("savepoint")
            rev = self.history[-1]["time"]
            self.savepoints[rev] = copy.deepcopy(self.rules)
            return {"status": "ok", "retention": "100", "revision": rev}
        if action == "apply":
            if args and not self.savepoints_supported:
                return None  # 26.7: apply takes no revision
            if method != "POST":
                return {"status": "error"}
            self.running = copy.deepcopy(self.rules)
            if args:
                self.pending = {"rev": args[0], "deadline": self.now[0] + 60}
            if self.lockout_after_apply:
                self.locked = True
            return {"status": "OK\n\n"}
        if action == "cancelRollback" and self.savepoints_supported:
            if self.pending and self.pending["rev"] == args[0]:
                self.pending = None
            return {"status": ""}
        if action == "revert" and self.savepoints_supported:
            if args[0] not in self.savepoints:
                return {"status": "unknown (or removed) savepoint"}
            self.rules = copy.deepcopy(self.savepoints[args[0]])
            self.running = copy.deepcopy(self.rules)
            self.locked = False
            self.save("revert")
            return {"status": "ok"}
        if action == "add_rule":
            if self.fail_add or (body["rule"].get("destination_port") or "").count(",") or \
                    body["rule"]["interface"] not in {i["identifier"] for i in self.interfaces}:
                return {"result": "failed", "validations": {"rule.destination_port": "Please specify a valid portnumber"}}
            if denied := self.denied_write():
                return denied
            uid = str(uuidlib.uuid4())
            _, rule = mvc("r1", sequence=str(max(int(r["sequence"]) for r in self.rules.values()) + 100))
            rule.update(body["rule"])
            self.rules[uid] = rule
            self.save("add rule")
            return {"result": "saved", "uuid": uid}
        if action == "toggle_rule":
            rule = self.rules.get(args[0])
            if rule is None:
                return httpx.Response(500, json={"errorMessage": "Unexpected error, check log for details"})
            if rule["enabled"] != args[1]:
                if denied := self.denied_write():
                    return denied
                rule["enabled"] = args[1]
                self.save("toggle rule")
                return {"result": "Enabled" if args[1] == "1" else "Disabled", "changed": True}
            return {"result": "Enabled" if args[1] == "1" else "Disabled", "changed": False}
        if action == "del_rule":
            if self.fail_delete:
                return httpx.Response(500, json={"errorMessage": "Unexpected error, check log for details"})
            if self.rules.pop(args[0], None) is None:
                return {"result": "not found"}
            self.save("delete rule")
            return {"result": "deleted"}
        if action == "move_rule_before":
            target = int(self.rules[args[1]]["sequence"])
            for uid, rule in self.rules.items():
                if uid != args[0] and int(rule["sequence"]) >= target:
                    rule["sequence"] = str(int(rule["sequence"]) + 50)
            self.rules[args[0]]["sequence"] = str(target)
            self.save("move rule")
            return {"status": "ok"}
        return None

    def backup(self, method: str, action: str, args: list[str]) -> Any:
        if action == "backups" and args == ["this"]:
            return {"items": [{"time": h["time"], "time_iso": "2026-10-09T10:00:00+00:00", "description": h["description"],
                               "username": "atrium@10.0.99.10", "filesize": len(h["xml"]), "id": h["id"]}
                              for h in reversed(self.history)]}
        if action == "download" and args[:1] == ["this"]:
            found = [h for h in self.history if len(args) == 1 or h["id"] == args[1]]
            if not found:
                return httpx.Response(200, content=b"")
            return httpx.Response(200, content=found[-1]["xml"].encode(),
                                  headers={"Content-Type": "application/octet-stream"})
        if action == "revert_backup":
            if denied := self.denied_write():
                return denied
            if method != "POST":
                return {"status": "failed"}
            found = next((h for h in self.history if h["id"] == args[0]), None)
            if found is None:
                return {"status": "not_found"}
            self.rules = copy.deepcopy(found["rules"])
            self.save("restored")
            return {"status": "reverted"}
        return None

    def posted(self, action: str) -> list[str]:
        return [path for method, path, _ in self.calls if method == "POST" and action in path]


@pytest.fixture
def fake(monkeypatch):
    device = FakeOpnsense()

    async def sleep(seconds: float) -> None:
        device.now[0] += seconds

    monkeypatch.setattr(OpnsenseConnector, "clock", staticmethod(lambda: device.now[0]))
    monkeypatch.setattr(OpnsenseConnector, "sleep", staticmethod(sleep))
    return device


def connector(fake: FakeOpnsense, **config: Any) -> OpnsenseConnector:
    """A new instance (= a new connection), as the hub builds one per call. The hub manages the firewall from the
    MGMT network (10.0.99.10), so the management-path guard knows which rules carry its traffic."""
    config = {"hub_address": "10.0.99.10", **config}
    return OpnsenseConnector(clean_config(OpnsenseConnector, {"base_url": BASE, **{k: v for k, v in config.items()
                                                                                    if v is not None}}),
                             {"api_key": KEY, "api_secret": SECRET}, httpx.MockTransport(fake))


def snapshot(fake: FakeOpnsense, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


ALLOW = parse_ops([{"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
                    "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
                    "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Users to intranet",
                    "marker": "atrium:chg_7"}])


def disable(*names: str) -> list[dict[str, Any]]:
    return parse_ops([{"op": "disable_rules", "rules": [{"id": U[n], "vendor_ref": U[n]} for n in names]}])


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_every_rule_into_the_network_model(fake):
    record = snapshot(fake)
    assert record["external_id"] == "fw1.example.lan" and record["kind"] == "firewall"
    assert record["device"] == {"vendor": "OPNsense", "model": "", "version": "26.7.6", "hostname": "fw1.example.lan",
                                "management_address": "fw1.example.net", "serial": ""}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"wan", "lan", "opt1", "opt2"}  # unassigned ports are skipped
    assert ifaces["wan"]["role"] == "wan" and ifaces["wan"]["subnets"] == ["203.0.113.0/29"]  # link-local dropped
    assert ifaces["opt1"]["vlan"] == 20 and ifaces["opt2"]["vlan"] == 99 and ifaces["opt1"]["name"] == "SERVERS"
    assert record["self_addresses"] == ["203.0.113.2", "10.0.10.1", "10.0.20.1", "10.0.99.1"]
    assert record["zones"] == [] and record["default_policy"] == {"inbound": "block"}

    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["WEB_SERVERS"]["cidrs"] == ["10.0.20.10/32", "10.0.20.11/32"] and aliases["WEB_SERVERS"]["resolved"]
    assert aliases["ADMINS"]["resolved"] is False  # a host name is resolved by the firewall at run time
    assert aliases["INTERNAL_NETS"]["cidrs"] == ["10.0.99.0/24", "10.0.20.10/32", "10.0.20.11/32"]
    assert aliases["WEB_PORTS"]["ports"] == "80,443,8000-8080" and aliases["WEB_PORTS"]["kind"] == "port"
    assert aliases["BLOCKLIST"] == {"name": "BLOCKLIST", "kind": "url", "cidrs": [], "ports": None, "resolved": False}
    assert aliases["RANGE"]["cidrs"] == ["10.0.30.1/32", "10.0.30.2/31", "10.0.30.4/31", "10.0.30.6/32"]
    assert aliases["__lan_network"]["cidrs"] == ["10.0.10.0/24"]

    rules = record["rules"]
    assert [r["description"] for r in rules][:3] == ["Anti-Lockout Rule", "Default deny / state violation rule",
                                                     "Block lab"]  # evaluation order: automatic, floating, group...
    by = {r["description"]: r for r in rules}
    lan = by["Allow LAN to any"]
    assert lan["id"] == lan["vendor_ref"] == U["r1"] and lan["interfaces"] == ["lan"] and lan["hits"] == 15320
    assert lan["source"]["nets"] == ["lan"] and lan["destination"]["any"] and lan["services"] is None
    web = by["Web servers from the internet"]
    assert web["services"] == [{"proto": "tcp", "ports": "80,443,8000-8080", "alias": None, "name": ""}]
    assert web["destination"]["aliases"] == ["WEB_SERVERS"] and web["log"]
    group = by["SSH to management"]  # a rule on an interface group: its member interfaces
    assert group["interfaces"] == ["lan", "opt1"] and group["source"]["nets"] == ["lan", "opt1"]
    assert group["services"][0]["ports"] == "22"
    assert by["Block lab"]["floating"] and by["Block lab"]["action"] == "block"
    inverted = next(r for r in rules if r["id"] == U["r6"])
    assert inverted["interfaces"] == [] and inverted["floating"] and not inverted["enabled"]
    assert inverted["destination"]["cidrs"] == ["10.0.99.1/32"] and inverted["services"][0]["proto"] == "icmp"
    assert inverted["description"] == "ping <script>alert(1)</script>"  # device text stays text (never HTML)
    lockout = by["Anti-Lockout Rule"]
    assert lockout["id"].startswith("legacy:") and lockout["interfaces"] == ["lan"] and lockout["destination"]["self"]
    assert lockout["services"][0]["ports"] == "443,80,22" and lockout["hits"] == 7
    dns = by["DNS to the firewall"]
    assert dns["source"]["nets"] == ["lan"] and dns["destination"]["cidrs"] == ["10.0.10.1/32"]
    assert by["Default deny / state violation rule"]["floating"] and by["Default deny / state violation rule"]["interfaces"] == []
    assert any("classic or automatic" in n for n in record["notes"])
    assert "denied" not in json.dumps(record) and SECRET not in json.dumps(record) and PASSWORD_HASH not in json.dumps(record)


def test_revision_follows_the_ruleset_not_counters(fake):
    first = snapshot(fake)
    fake.aliases[0]["current_items"] = "9"  # counters and read times move on every read
    fake.now[0] += 500
    assert snapshot(fake)["revision"] == first["revision"]
    fake.rules[U["r1"]]["description"] = "edited in the GUI"
    assert snapshot(fake)["revision"] != first["revision"]


@pytest.mark.parametrize("version", ["25.7.11", "24.7.12"])
def test_versions_before_26_1_are_refused(fake, version):
    fake.version = version
    with pytest.raises(Exception, match="not supported"):
        run(connector(fake).pull("network"))
    result = run(connector(fake).test())
    assert result["ok"] is False and result["network_write"] is None
    assert not next(c for c in result["checks"] if c["name"] == "version")["ok"]


def test_missing_optional_privileges_degrade_with_notes(fake):
    fake.denied = {"aliases", "groups", "stats", "version"}
    record = snapshot(fake)  # the classic/automatic rows prove 26.1+ even without the version
    notes = " ".join(record["notes"])
    assert "Firewall: Aliases" in notes and "hit counts unavailable" in notes and "Lobby: Dashboard" in notes
    group = next(r for r in record["rules"] if r["id"] == U["r3"])
    assert group["interfaces"] == ["INTERNAL"]  # without the groups it cannot expand them
    fake.denied = {"rules"}
    with pytest.raises(Exception, match="Firewall: Rules \\[new\\]"):
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
    assert "read-only one is recommended" in detail(result, "privileges")
    assert "no savepoints" in detail(result, "api_features") and "OPNsense 26.7.6 - supported" in detail(result, "version")
    assert "revert_backup" in " ".join(p for _, p, _ in fake.calls)  # the write probe ...
    assert not fake.posted("revert_backup") and len(fake.history) == 1  # ... changed nothing
    assert "Connected to OPNsense 26.7.6" in result["detail"]

    fake.version, fake.savepoints_supported = "26.1.11_2", True
    result = run(connector(fake).test())
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "savepoint",
                                       "window_s": 60}
    assert not fake.posted("savepoint")  # probed with GET only


def test_test_read_only_key_and_settings(fake):
    fake.read_only = True
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None
    assert "read-only key" in detail(result, "privileges") and result["detail"].endswith("(read only)")
    fake.read_only = False
    fake.denied = {"backups"}
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "write access unknown" in detail(result, "privileges")
    fake.denied = set()
    result = run(connector(fake, read_only=True).test())
    assert result["network_write"] is None and "set to read only" in detail(result, "privileges")
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
    bad = OpnsenseConnector({"base_url": BASE}, {"api_key": KEY, "api_secret": "wrong-secret-value"},
                            httpx.MockTransport(fake))
    result = run(bad.test())
    assert names(result)[-1] == "authentication" and "rejected the API key" in result["detail"]
    assert "wrong-secret-value" not in json.dumps(result) and SECRET not in json.dumps(result)
    fake.denied = {"rules", "interfaces"}
    result = run(connector(fake).test())
    assert result["ok"] is False and "Firewall: Rules [new]" in detail(result, "privileges")
    result = run(connector(fake, verify_tls=False).test())
    assert not next(c for c in result["checks"] if c["name"] == "tls")["ok"]


def test_config_validation():
    assert clean_config(OpnsenseConnector, {"base_url": "https://fw:8443/api/"})["base_url"] == "https://fw:8443"
    for bad in ("http://fw", "https://user:pw@fw", "fw.example.net", "https://fw/?key=1"):
        with pytest.raises(ValueError):
            clean_config(OpnsenseConnector, {"base_url": bad})
    with pytest.raises(ValueError, match="absolute"):
        clean_config(OpnsenseConnector, {"base_url": BASE, "ca_file": "ca.pem"})
    with pytest.raises(ValueError, match="IP address"):
        clean_config(OpnsenseConnector, {"base_url": BASE, "hub_address": "hub.local"})
    assert OpnsenseConnector.endpoint({"base_url": BASE, "verify_tls": False}) != \
        OpnsenseConnector.endpoint({"base_url": BASE, "verify_tls": True})


# --------------------------------------------------------------------------------------
# changes on 26.7 (no device timer: backup_restore)
# --------------------------------------------------------------------------------------


def test_apply_verify_confirm_and_revert_on_26_7(fake):
    before = snapshot(fake)
    preview = run(connector(fake).preview_change(ALLOW, before))
    assert preview["problems"] == [] and preview["steps"][0]["kind"] == "add_rule"
    assert "top of the lan rules [new]" in preview["steps"][0]["position"]
    assert any("no automatic revert" in n for n in preview["notes"])
    assert len(fake.history) == 1  # a preview writes nothing
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert applied["rollback_until"] is None and applied["created"][0]["op"] == 0
    token = json.loads(applied["token"])
    assert token["mode"] == "backup_restore" and token["backup"] == fake.history[0]["id"] and len(applied["token"]) < 4096
    assert [p for _, p, _ in fake.calls if "add_rule" in p or p == "/firewall/filter/apply"] == \
        ["/firewall/filter/add_rule", "/firewall/filter/apply"]
    added = next(b for _, p, b in fake.calls if p == "/firewall/filter/add_rule")["rule"]
    assert added == {"enabled": "1", "action": "pass", "quick": "1", "interface": "lan", "direction": "in",
                     "ipprotocol": "inet", "protocol": "TCP", "source_net": "10.0.10.0/24", "source_not": "0",
                     "destination_net": "10.0.20.0/24", "destination_not": "0", "destination_port": "443",
                     "log": "1", "description": "atrium:chg_7 Users to intranet", "sequence": "99"}
    after = snapshot(fake)  # a new connection
    assert ops_applied(after, ALLOW) == []
    new = next(r for r in after["rules"] if r["marker"] == "chg_7")
    lan = next(r for r in after["rules"] if r["id"] == U["r1"])
    assert new["order"] < lan["order"]  # above the other LAN rules
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]
    revert = inverse_ops(ALLOW, applied)  # a revert is a new change: the created rule is disabled
    again = run(connector(fake).apply_change(revert, after["revision"], None))
    assert again["disabled"] == [applied["created"][0]["vendor_ref"]]
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


def test_rollback_on_26_7_uses_inverse_ops_then_the_config_backup(fake):
    before = snapshot(fake)
    ops = ALLOW + disable("r1")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["disabled"] == [U["r1"]]
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result == {"rolled_back": True, "method": "inverse_ops", "notes": []}
    assert ops_reverted(before, snapshot(fake), ops) == [] and fake.rules[U["r1"]]["enabled"] == "1"

    applied = run(connector(fake).apply_change(ops, snapshot(fake)["revision"], None))
    fake.fail_delete = True  # the inverse fails: the recorded configuration history entry is restored
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result["method"] == "backup_restore" and "rule by rule failed" in result["notes"][0]
    assert ops_reverted(before, snapshot(fake), ops) == []
    restored = next(b for m, p, b in fake.calls if m == "POST" and "revert_backup" in p)
    assert restored is None and fake.history[-1]["description"] == "restored"


def test_rollback_falls_back_to_revert_backup(fake, monkeypatch):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))

    async def stuck(self, client, info):  # the rule-by-rule undo "succeeds" but the firewall keeps the rule
        return None

    monkeypatch.setattr(OpnsenseConnector, "_inverse", stuck)
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result["method"] == "backup_restore" and fake.posted("revert_backup")
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


def test_failed_write_is_undone_before_apply(fake):
    before = snapshot(fake)
    fake.fail_add = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable("r2") + ALLOW, before["revision"], None))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"
    assert "rule.destination_port" in caught.value.message and "Please specify" not in caught.value.message
    assert fake.rules[U["r2"]]["enabled"] == "1" and not fake.posted("/firewall/filter/apply")


def test_stale_lockout_and_unsupported_ops(fake):
    before = snapshot(fake)
    with pytest.raises(ChangeError) as stale:
        run(connector(fake).apply_change(ALLOW, "h-0000000000000000", None))
    assert stale.value.code == "stale" and stale.value.state == "unchanged"

    mgmt = disable("r5")  # the GUI rule on MGMT carries the hub's own API traffic (from 10.0.99.10)
    assert run(connector(fake).preview_change(mgmt, before))["problems"]
    with pytest.raises(ChangeError) as lockout:
        run(connector(fake).apply_change(mgmt, before["revision"], None))
    assert lockout.value.code == "lockout" and len(fake.history) == 1
    # without the hub's address the guard is conservative: any rule that can reach the firewall is protected
    lan = disable("r1")
    assert run(connector(fake, hub_address=None).preview_change(lan, before))["problems"]
    assert run(connector(fake).preview_change(lan, before))["problems"] == []
    assert run(connector(fake, hub_address="198.51.100.7").preview_change(mgmt, before))["problems"] == []

    legacy = next(r for r in before["rules"] if r["description"] == "DNS to the firewall")
    wide = parse_ops([
        {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24", "10.0.11.0/24"]},
         "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
         "services": [{"proto": "tcp", "ports": "80,443"}, {"proto": "udp", "ports": "53"}], "marker": "atrium:chg_8"},
        {"op": "allow", "source": {"zone": "opt9", "cidrs": ["10.0.10.0/24"]},
         "destination": {"zone": "opt1", "cidrs": ["2001:db8::/64"]}, "services": [{"proto": "icmp"}],
         "marker": "atrium:chg_8"},
        {"op": "disable_rules", "rules": [{"id": legacy["id"], "vendor_ref": legacy["vendor_ref"]}]}])
    problems = " | ".join(run(connector(fake).preview_change(wide, before))["problems"])
    for expected in ("one source network", "one protocol", "no interface 'opt9'", "IPv4 and IPv6",
                     "classic or automatic rule"):
        assert expected in problems
    with pytest.raises(ChangeError) as invalid:
        run(connector(fake).apply_change(wide, before["revision"], None))
    assert invalid.value.code == "invalid" and len(fake.history) == 1

    with pytest.raises(ChangeError) as read_only:
        run(connector(fake, read_only=True).apply_change(ALLOW, before["revision"], None))
    assert read_only.value.code == "unsupported"


def test_tcp_udp_pair_and_move_before_the_first_rule(fake):
    fake.rules[U["r1"]]["sequence"] = "1"
    before = snapshot(fake)
    ops = parse_ops([{"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
                      "destination": {"zone": "opt2", "cidrs": ["10.0.99.53/32"]},
                      "services": [{"proto": "tcp", "ports": "53"}, {"proto": "udp", "ports": "53"}],
                      "marker": "atrium:chg_9"}])
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert fake.posted("move_rule_before")
    added = next(b for _, p, b in fake.calls if p == "/firewall/filter/add_rule")["rule"]
    assert added["protocol"] == "TCP/UDP" and "sequence" not in added
    after = snapshot(fake)
    assert ops_applied(after, ops) == []
    uid = applied["created"][0]["id"]
    assert next(r for r in after["rules"] if r["id"] == uid)["order"] < next(r for r in after["rules"]
                                                                              if r["id"] == U["r1"])["order"]


# --------------------------------------------------------------------------------------
# changes on 26.1 (savepoint with a 60 s device timer)
# --------------------------------------------------------------------------------------


@pytest.fixture
def fake261(fake):
    fake.version, fake.savepoints_supported = "26.1.11_2", True
    return fake


def test_savepoint_apply_confirm(fake261):
    fake = fake261
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    token = json.loads(applied["token"])
    assert token["mode"] == "savepoint" and applied["rollback_until"] == pytest.approx(fake.now[0] + 60, abs=1)
    order = [p for m, p, _ in fake.calls if m == "POST" and "search" not in p]
    assert order[:3] == ["/firewall/filter/savepoint", "/firewall/filter/add_rule",
                         f"/firewall/filter/apply/{token['rev']}"]  # armed before writing, timer with the reload
    assert ops_applied(snapshot(fake), ALLOW) == []
    result = run(connector(fake).confirm_change(applied["token"]))
    assert result["confirmed"] and fake.posted("cancelRollback") and fake.pending is None
    fake.now[0] += 300
    assert ops_applied(snapshot(fake), ALLOW) == []  # confirmed: the timer no longer reverts it


def test_savepoint_reverts_by_itself_and_late_confirm_reports_it(fake261):
    fake = fake261
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    fake.now[0] += 61
    assert ops_reverted(before, snapshot(fake), ALLOW) == []
    with pytest.raises(ChangeError) as late:
        run(connector(fake).confirm_change(applied["token"]))
    assert late.value.state == "rolled_back"


def test_confirm_too_close_to_the_timer_waits_for_it(fake261):
    fake = fake261
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    fake.now[0] += 55  # five seconds left: cancelling now could race the device's own revert
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).confirm_change(applied["token"]))
    assert caught.value.state == "rolled_back" and not fake.posted("cancelRollback")


def test_savepoint_rollback_and_lockout(fake261):
    fake = fake261
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW + disable("r2"), before["revision"], None))
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result["method"] == "savepoint" and ops_reverted(before, snapshot(fake), ALLOW + disable("r2")) == []

    fake.lockout_after_apply = True
    applied = run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert run(connector(fake).test())["ok"] is False  # the hub's check over a new connection fails
    with pytest.raises(ChangeError) as unreachable:
        run(connector(fake).rollback_change(applied["token"], None))
    assert unreachable.value.code == "unreachable" and unreachable.value.state == "unknown"
    fake.now[0] += 61  # the device's own timer restores access
    assert run(connector(fake).test())["ok"] and ops_reverted(before, snapshot(fake), ALLOW) == []


def test_tokens_are_validated(fake):
    for token in ("", "{}", json.dumps({"v": 1, "mode": "savepoint", "rev": "1; reboot", "created": []}),
                  json.dumps({"v": 1, "mode": "backup_restore", "backup": "../../etc/passwd", "created": []})):
        with pytest.raises(ChangeError, match="Not a change token"):
            run(connector(fake).rollback_change(token, None))


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


def as_backup(taken: dict[str, Any]) -> Backup:
    content = taken["content"]
    return Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, taken["format"],
                  taken["device_backup_id"], taken["revision"])


def test_backup_and_restore(fake):
    taken = run(connector(fake).backup())
    assert taken["format"] == "xml" and taken["device_backup_id"] == fake.history[-1]["id"]
    assert PASSWORD_HASH.encode() in taken["content"] and taken["sha256"] == hashlib.sha256(taken["content"]).hexdigest()
    before = snapshot(fake)
    run(connector(fake).apply_change(ALLOW, before["revision"], None))
    restored = run(connector(fake).restore_backup(as_backup(taken)))
    assert restored["restored"] and fake.posted("revert_backup") and fake.posted("/firewall/filter/apply")
    assert ops_reverted(before, snapshot(fake), ALLOW) == []

    tampered = Backup("bk_2", b"<opnsense/>", hashlib.sha256(b"<opnsense/>").hexdigest(), 0.0, "xml",
                      taken["device_backup_id"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(tampered))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_3", b"x", "x", 0.0, "xml", None)))
    assert caught.value.code == "unsupported"
    fake.denied = {"backups"}
    with pytest.raises(Exception, match="Configuration History"):
        run(connector(fake).backup())


def test_errors_never_carry_secrets(fake):
    fake.read_only = True
    before = snapshot(fake)
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    text = json.dumps(caught.value.as_dict())
    assert "Deny config write" in text and SECRET not in text and KEY not in text


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeOpnsense()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", httpx.MockTransport(fake), raising=False)
    tool = Tool(id="opn1", name="OPNsense edge", source_type="saas", source="https://opnsense.org", status="ready",
                manifest=Manifest(id="opn1", name="OPNsense edge", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    detected = client.get("/api/connectors").json()
    assert any(c["kind"] == "opnsense" and c["network_write"]["rollback"] == "backup_restore" for c in detected)
    response = client.put("/api/tools/opn1/connection", json={"kind": "opnsense", "config": {"base_url": BASE},
                                                              "secrets": {"api_key": KEY, "api_secret": SECRET}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/opn1/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "backup_restore", tested
    assert SECRET not in json.dumps(tested)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "opn1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=opn1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/opn1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/opn1").json()
    assert device["record"]["device"]["vendor"] == "OPNsense" and len(device["record"]["rules"]) == 9
    assert SECRET not in json.dumps(device) and PASSWORD_HASH not in json.dumps(device)


def test_a_missing_ca_file_is_a_tls_problem():
    conn = OpnsenseConnector({"base_url": BASE, "ca_file": "/nonexistent/opnsense-ca.pem"},
                             {"api_key": KEY, "api_secret": SECRET})
    result = run(conn.test())
    assert result["ok"] is False and result["checks"][0]["name"] == "tls"
    assert "/nonexistent/opnsense-ca.pem" in result["detail"]


def test_device_ids_never_reach_url_paths_unchecked(fake):
    fake.legacy.append({"uuid": "../../core/firmware/poweroff", "enabled": "1", "interface": "lan", "action": "pass",
                        "source_net": "any", "destination_net": "10.1.0.0/16", "description": "odd row",
                        "sort_order": "400000.0000050"})
    record = snapshot(fake)
    odd = next(r for r in record["rules"] if r["description"] == "odd row")
    assert odd["id"].startswith("legacy:")  # read only: never addressed on the device
    ops = parse_ops([{"op": "disable_rules", "rules": [{"id": odd["id"], "vendor_ref": "../../core/firmware/poweroff"}]}])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ops, record["revision"], None))
    assert caught.value.code == "invalid" and not [p for m, p, _ in fake.calls if m == "POST" and "search" not in p]


def test_a_broken_probe_does_not_break_the_test(fake, monkeypatch):
    original = FakeOpnsense.route

    def route(self, method, path, body):
        if path == "/firewall/group/search_item":
            return httpx.Response(500, json={"errorMessage": "Unexpected error, check log for details"})
        return original(self, method, path, body)

    monkeypatch.setattr(FakeOpnsense, "route", route)
    result = run(connector(fake).test())
    assert result["ok"] and "Firewall: Groups" in detail(result, "privileges")
