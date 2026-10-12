"""pfSense connector against a fake SSH transport (and, for pfrest, a fake HTTP API). No device is contacted."""

from __future__ import annotations

import asyncio
import json
import re
import shlex

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError
from hub.connectors.netmodel import LEAST_PRIVILEGE_NOTE, RESERVED_ACTIONS, TEST_CHECKS, ChangeError, marker, rule_matches_allow
from hub.connectors.pfsense import PfSenseConnector
from hub.execution.sshfake import FakeSshTransport
from hub.models import Tool

KEY = "ssh-ed25519 AAAAC3TEST private-key-material-xyz"
PFREST_KEY = "pfrest-api-key-value"
CONFIG = """<?xml version="1.0"?>
<pfsense>
  <version>22.1</version>
  <system><hostname>fw1</hostname></system>
  <revision><time>1760000000</time><description>admin</description><username>root@10.0.0.5</username></revision>
  <interfaces>
    <wan><if>igb0</if><enable></enable><descr>WAN</descr><ipaddr>203.0.113.2</ipaddr><subnet>29</subnet></wan>
    <lan><if>igb1</if><enable></enable><descr>LAN</descr><ipaddr>10.0.10.1</ipaddr><subnet>24</subnet></lan>
    <opt1><if>igb2</if><enable></enable><descr>SERVERS</descr><ipaddr>10.0.20.1</ipaddr><subnet>24</subnet></opt1>
  </interfaces>
  <aliases><alias><name>web_servers</name><type>host</type><address>10.0.20.10</address><descr>web</descr></alias></aliases>
  <filter>
    <rule>
      <tracker>1760000000</tracker>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet</ipprotocol>
      <protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>web_servers</address><port>443</port></destination>
      <log></log>
      <descr><![CDATA[atrium:edge-17 LAN to web]]></descr>
    </rule>
    <rule>
      <tracker>1700000002</tracker>
      <type>pass</type>
      <interface>lan</interface>
      <protocol>tcp</protocol>
      <source><network>lan</network></source>
      <destination><address>10.0.10.1</address><port>443</port></destination>
      <descr>anti-lockout</descr>
    </rule>
  </filter>
</pfsense>
"""
PFCTL = """@0 pass in on lan inet proto tcp
ridentifier 1760000000
  Evaluations: 10 Packets: 5 Bytes: 100 States: 0
"""


def run(coro):
    return asyncio.run(coro)


def allow(description: str = "Users $(touch /tmp/pwned)") -> dict:
    return {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": "opt1", "cidrs": ["10.0.20.10/32"]},
            "services": [{"proto": "tcp", "ports": "443"}], "log": True,
            "description": description, "marker": marker("chg_31")}


class FakePf:
    def __init__(self, version: str = "2.9.0-RELEASE"):
        self.version = version
        self.xml = CONFIG
        self.files: dict[str, str] = {}
        self.transport = FakeSshTransport(self.answer)
        self.php = ""
        self.daemon = ""

    def answer(self, command: str, stdin: str | None, session):
        if command == "cat /etc/version":
            return self.version + "\n"
        if command == "cat /cf/conf/config.xml":
            return self.xml
        if command == "id -u":
            return "0\n"
        if command == "pfctl -vvsr":
            return PFCTL
        if command == "/usr/local/bin/php":
            self.php = stdin or ""
            self._apply_php(self.php)
            return '{"ok": true}\n'
        if command.startswith("daemon "):
            self.daemon = command
            return ""
        parts = shlex.split(command)
        if parts[:2] == ["cp", "/cf/conf/config.xml"] and len(parts) == 3:
            self.files[parts[2]] = self.xml
            return ""
        if parts[:1] == ["touch"] and len(parts) == 2:
            self.files[parts[1]] = "arm"
            return ""
        if parts[:2] == ["cp", "/dev/stdin"]:
            self.xml = stdin or ""
            return ""
        if len(parts) == 3 and parts[0] == "cp" and parts[2] == "/cf/conf/config.xml":
            self.xml = self.files[parts[1]]
            return ""
        if parts[:2] == ["rm", "-f"]:
            for path in parts[2:]:
                self.files.pop(path, None)
            return ""
        if command == "/etc/rc.filter_configure":
            return ""
        return (127, "", f"fake: no answer for {command}")

    def _apply_php(self, script: str) -> None:
        import xml.etree.ElementTree as ET
        match = re.search(r"<<<'ATRIUM_JSON'\n(.*?)\nATRIUM_JSON", script, re.S)
        assert match is not None
        payload = json.loads(match.group(1))
        root = ET.fromstring(self.xml)
        filt = root.find("filter")
        assert filt is not None
        for tracker in payload.get("disable") or []:
            for rule in filt.findall("rule"):
                if (rule.findtext("tracker") or "").strip() == tracker and rule.find("disabled") is None:
                    ET.SubElement(rule, "disabled")
        for tracker in payload.get("enable") or []:
            for rule in filt.findall("rule"):
                if (rule.findtext("tracker") or "").strip() == tracker and rule.find("disabled") is not None:
                    rule.remove(rule.find("disabled"))
        for added in payload.get("add") or []:
            element = ET.Element("rule")
            for key in ("tracker", "type", "interface", "ipprotocol", "protocol", "direction", "descr"):
                if key in added:
                    ET.SubElement(element, key).text = str(added[key])
            for side in ("source", "destination"):
                node = ET.SubElement(element, side)
                for key, value in added[side].items():
                    ET.SubElement(node, key).text = str(value)
            if "log" in added:
                ET.SubElement(element, "log")
            placed = False
            for rule in list(filt.findall("rule")):
                if (rule.findtext("interface") or "").strip() == added["interface"]:
                    filt.insert(list(filt).index(rule), element)
                    placed = True
                    break
            if not placed:
                filt.append(element)
        self.xml = ET.tostring(root, encoding="unicode")

    def commands(self) -> list[str]:
        return [call.command for session in self.transport.sessions for call in session.calls]


def connector(fake: FakePf, **config) -> PfSenseConnector:
    return PfSenseConnector({"host": "fw.example", "username": "root", **config}, {"private_key": KEY}, fake.transport)


def test_registry_and_detect(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "pfsense", PfSenseConnector)
    assert connectors.connector_class("pfsense") is PfSenseConnector
    assert not (set(PfSenseConnector.actions) & RESERVED_ACTIONS)
    tool = Tool(id="edge", name="pfSense", source_type="local", source="local")
    assert PfSenseConnector.detect(tool) >= 90
    with pytest.raises(ConnectorError):
        PfSenseConnector.validate_config({"mode": "ssh", "host": "bad host"})


def test_pull_uses_the_tracker_and_test_checks():
    fake = FakePf()
    conn = connector(fake)
    result = run(conn.test())
    assert result["ok"] and [item["name"] for item in result["checks"]] == list(TEST_CHECKS)
    assert result["network_write"]["rollback"] == "deadman"
    assert LEAST_PRIVILEGE_NOTE in next(item["detail"] for item in result["checks"] if item["name"] == "privileges")
    record = run(conn.pull("network"))[0]
    rule = next(item for item in record["rules"] if item["vendor_ref"] == "1760000000")
    assert record["external_id"] == "fw1" and record["revision"] == "1760000000"
    assert record["device"]["vendor"] == "pfSense" and record["device"]["version"].startswith("2.9.0")
    assert rule["marker"] == "edge-17" and rule["hits"] == 5 and rule["interfaces"] == ["lan"]
    assert rule["source"]["nets"] == ["lan"] and rule["destination"]["aliases"] == ["web_servers"]
    assert rule["services"][0]["proto"] == "tcp" and rule["services"][0]["ports"] == "443"
    assert rule["log"] is True
    lan = next(item for item in record["interfaces"] if item["id"] == "lan")
    assert lan["addresses"] == ["10.0.10.1"] and lan["role"] == "lan"


def test_apply_arms_the_dead_man_before_php_and_keeps_device_text_off_the_command_line():
    fake = FakePf()
    conn = connector(fake)
    op = allow()
    revision = run(conn.pull("network"))[0]["revision"]
    preview = run(conn.preview_change([op], {}))
    assert preview["problems"] == [] and "/usr/local/bin/php" not in fake.commands()
    applied = run(conn.apply_change([op], revision, None))
    commands = fake.commands()
    assert commands.index(next(command for command in commands if command.startswith("daemon "))) < commands.index("/usr/local/bin/php")
    assert all(command == "/usr/local/bin/php" or "touch /tmp/pwned" not in command for command in commands)
    assert "touch /tmp/pwned" in fake.php
    for primitive in ('require_once("config.inc")', 'require_once("filter.inc")', "config_get_path", "config_set_path",
                      "write_config", "filter_configure"):
        assert primitive in fake.php
    assert "atrium-arm-chg_31" in fake.daemon and "touch /tmp/pwned" not in fake.daemon
    assert "sleep 120" in fake.daemon and "/etc/rc.filter_configure" in fake.daemon
    record = run(conn.pull("network"))[0]
    created = next(rule for rule in record["rules"] if rule["marker"] == "chg_31")
    assert created["vendor_ref"] == applied["created"][0]["vendor_ref"]
    assert rule_matches_allow(created, op)
    sessions = len(fake.transport.sessions)
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and len(fake.transport.sessions) == sessions + 1
    assert any(command == "rm -f /tmp/atrium-arm-chg_31" for command in fake.commands())


def test_rollback_restores_the_pre_change_config():
    fake = FakePf()
    conn = connector(fake)
    revision = run(conn.pull("network"))[0]["revision"]
    op = {"op": "disable_rules", "rules": [{"id": "1760000000", "vendor_ref": "1760000000"}]}
    applied = run(conn.apply_change([op], revision, None))
    disabled = run(conn.pull("network"))[0]
    assert next(rule["enabled"] for rule in disabled["rules"] if rule["vendor_ref"] == "1760000000") is False
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["rolled_back"] and rolled["method"] == "deadman"
    restored = run(conn.pull("network"))[0]
    assert next(rule["enabled"] for rule in restored["rules"] if rule["vendor_ref"] == "1760000000") is True


def test_stale_lockout_plus_and_action_cannot_write():
    fake = FakePf()
    conn = connector(fake)
    with pytest.raises(ChangeError) as stale:
        run(conn.apply_change([allow()], "999", None))
    assert stale.value.code == "stale" and "/usr/local/bin/php" not in fake.commands()
    op = {"op": "disable_rules", "rules": [{"id": "1700000002", "vendor_ref": "1700000002"}]}
    with pytest.raises(ChangeError) as locked:
        run(conn.apply_change([op], "1760000000", None))
    assert locked.value.code == "lockout" and locked.value.state == "unchanged"
    plus = FakePf("26.07")
    plus_conn = connector(plus)
    result = run(plus_conn.test())
    assert result["ok"] and result["network_write"] is None and "plus" in result["detail"]
    record = run(plus_conn.pull("network"))[0]
    assert record["rules"]
    with pytest.raises(ChangeError) as denied:
        run(plus_conn.apply_change([allow()], record["revision"], None))
    assert denied.value.code == "unsupported" and "/usr/local/bin/php" not in plus.commands()
    before = len(fake.transport.sessions)
    for name in ("apply_change", "backup", "confirm_change", "rollback_change", "allow", "disable_rules"):
        with pytest.raises(ConnectorError):
            run(conn.action(name, {}))
    assert len(fake.transport.sessions) == before


def test_a_failed_command_does_not_echo_the_private_key():
    class Leaky(FakePf):
        def answer(self, command, stdin, session):
            if command == "cat /cf/conf/config.xml":
                return (1, "", KEY)
            return super().answer(command, stdin, session)

    fake = Leaky()
    with pytest.raises(ChangeError) as info:
        run(connector(fake).pull("network"))
    assert KEY not in str(info.value) and "private-key-material-xyz" not in json.dumps(info.value.as_dict())


def test_preview_rejects_an_unknown_interface_without_writing():
    fake = FakePf()
    conn = connector(fake)
    bad = allow()
    bad["destination"] = {"zone": "nope", "cidrs": ["10.9.0.0/24"]}
    preview = run(conn.preview_change([bad], {}))
    assert any("nope" in problem for problem in preview["problems"])
    assert "/usr/local/bin/php" not in fake.commands()


def test_pfrest_is_unofficial_and_read_only():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.headers.get("X-API-Key") != PFREST_KEY:
            return httpx.Response(401, json={"message": "no"})
        if request.url.path == "/api/v2/firewall/rules":
            return httpx.Response(200, json={"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "",
                                             "data": [{"id": 0, "type": "pass", "interface": ["lan"], "protocol": "tcp",
                                                       "source": "lan", "destination": "10.0.20.10", "destination_port": "443",
                                                       "descr": "atrium:edge-17", "disabled": False, "log": True,
                                                       "tracker": 1760000000}]})
        return httpx.Response(404, json={"message": "no"})

    conn = PfSenseConnector({"mode": "pfrest", "pfrest_url": "https://fw.example"}, {"api_key": PFREST_KEY},
                            httpx.MockTransport(handler))
    result = run(conn.test())
    assert result["ok"] and result["network_write"] is None
    assert any("unofficial" in item["detail"].lower() for item in result["checks"])
    record = run(conn.pull("network"))[0]
    assert record["rules"][0]["vendor_ref"] == "1760000000"
    assert record["rules"][0]["vendor_ref"] != "0"
    with pytest.raises(ChangeError) as info:
        run(conn.apply_change([allow()], record["revision"], None))
    assert info.value.code == "unsupported"
    assert all(request.method == "GET" for request in seen)
