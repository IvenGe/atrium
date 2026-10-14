"""The pfSense connector against a fake pfSense: SSH answers through execution/sshfake (config.xml rendered from a
pfSense-shaped config, /etc/version, ifconfig, pfctl, the dead-man shell scripts) and the connector's own PHP scripts
RUN for real with a local php against stub pfSense includes (config_get_path / config_set_path / write_config /
filter_configure_sync / config_restore). The unofficial REST API package (read only) is faked with
httpx.MockTransport."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.netmodel import (Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops)
from hub.connectors.pfsense import (PHP_APPLY, PfsenseConnector, parse_config_xml, parse_ifconfig, parse_platform)
from hub.execution.sshfake import FakeSshTransport
from hub.integration.connections import clean_config

PHP = shutil.which("php")
needs_php = pytest.mark.skipif(PHP is None, reason="php is not installed")
HASH = "$2y$10$pfsense-admin-bcrypt-hash-do-not-leak"
KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-material-0123456789\n-----END OPENSSH PRIVATE KEY-----"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestsOnly0123456789abcdefgh"
LISTS = {"rule", "alias", "vlan", "ifgroupentry", "user", "separator"}
LOCKED = "10.0.99.1:22: no answer within 10s"
STUB_CONFIG = r"""<?php
function atrium_stub_log($line) { file_put_contents(getenv("ATRIUM_LOG"), $line . "\n", FILE_APPEND); }
$config = json_decode(file_get_contents(getenv("ATRIUM_STATE")), true);
function config_get_path(string $path, $default = null) {
    global $config; $c = $config;
    foreach (explode("/", $path) as $k) { if (!is_array($c) || !array_key_exists($k, $c)) { return $default; } $c = $c[$k]; }
    return $c;
}
function config_set_path(string $path, $value, $default = null) {
    global $config; $ref = &$config;
    foreach (explode("/", $path) as $k) { if (!isset($ref[$k]) || !is_array($ref[$k])) { $ref[$k] = []; } $ref = &$ref[$k]; }
    $ref = $value; return $value;
}
function write_config($desc = "Unknown", $backup = true, $write_config_only = false) {
    global $config; file_put_contents(getenv("ATRIUM_STATE"), json_encode($config)); atrium_stub_log("write_config " . $desc);
}
function make_config_revision_entry($desc = null, $override_user = null) { return ["time" => 1760000000, "username" => $override_user]; }
function config_validate($file) { return @simplexml_load_file($file) !== false; }
function config_restore(string $path, string $descr): bool { atrium_stub_log("config_restore " . $descr); return copy($path, getenv("ATRIUM_RESTORED")); }
"""
STUB_FILTER = r"""<?php
function filter_configure_sync($delete_states_if_needed = true) { atrium_stub_log("filter_configure_sync"); echo "Configuring firewall......done.\n"; }
"""
IFCONFIG = """igb0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tether 00:08:a2:0c:11:01
\tinet 198.51.100.20 netmask 0xffffff00 broadcast 198.51.100.255
\tinet6 fe80::208:a2ff:fe0c:1101%igb0 prefixlen 64 scopeid 0x1
igb1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.0.10.1 netmask 0xffffff00 broadcast 10.0.10.255
igb1.20: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.0.20.1 netmask 0xffffff00 broadcast 10.0.20.255
\tinet6 2001:db8:20::1 prefixlen 64
igb1.99: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.0.99.1 netmask 0xffffff00 broadcast 10.0.99.255
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
"""


def run(coro):
    return asyncio.run(coro)


def rule(tracker: str, **fields: Any) -> dict[str, Any]:
    out = {"tracker": tracker, "type": "pass", "interface": "lan", "ipprotocol": "inet",
           "source": {"any": ""}, "destination": {"any": ""}, "descr": ""}
    out.update(fields)
    return out


def initial_config() -> dict[str, Any]:
    return {
        "version": "23.9",
        "system": {"hostname": "pf1", "domain": "example.lan", "webgui": {"protocol": "https"},
                   "ssh": {"enable": "enabled", "port": "22"}, "user": [{"name": "admin", "bcrypt-hash": HASH}]},
        "interfaces": {
            "wan": {"enable": "", "if": "igb0", "descr": "WAN", "ipaddr": "dhcp"},
            "lan": {"enable": "", "if": "igb1", "descr": "LAN", "ipaddr": "10.0.10.1", "subnet": "24"},
            "opt1": {"enable": "", "if": "igb1.20", "descr": "SERVERS", "ipaddr": "10.0.20.1", "subnet": "24"},
            "opt2": {"enable": "", "if": "igb1.99", "descr": "MGMT", "ipaddr": "10.0.99.1", "subnet": "24"},
        },
        "vlans": {"vlan": [{"if": "igb1", "tag": "20", "vlanif": "igb1.20", "descr": ""},
                           {"if": "igb1", "tag": "99", "vlanif": "igb1.99", "descr": ""}]},
        "ifgroups": {"ifgroupentry": [{"ifname": "INTERNAL", "members": "lan opt1", "descr": "internal"}]},
        "aliases": {"alias": [
            {"name": "web_servers", "type": "host", "address": "10.0.20.10 10.0.20.11", "descr": "", "detail": "a||b"},
            {"name": "web_ports", "type": "port", "address": "80 443 8000:8080", "descr": ""},
            {"name": "mgmt_net", "type": "network", "address": "10.0.99.0/24", "descr": ""},
            {"name": "admins", "type": "host", "address": "10.0.10.5 bastion.example.net", "descr": ""},
            {"name": "blocklist", "type": "urltable", "url": "https://lists.example.net/drop.txt", "address": ""},
        ]},
        "filter": {"rule": [
            rule("1700000001", interface="lan", source={"network": "lan"}, descr="Default allow LAN to any"),
            rule("1700000002", interface="wan", protocol="tcp", destination={"address": "web_servers",
                                                                             "port": "web_ports"},
                 log="", descr="Web servers from the internet"),
            rule("1700000003", interface="INTERNAL", protocol="tcp", source={"network": "INTERNAL"},
                 destination={"address": "mgmt_net", "port": "22"}, descr="SSH to management"),
            rule("1700000004", type="block", interface="lan,opt1", floating="yes", direction="any",
                 destination={"address": "10.66.0.0/16"}, descr="Block lab"),
            rule("1700000005", interface="opt2", protocol="tcp", source={"address": "mgmt_net"},
                 destination={"network": "(self)", "port": "443"}, descr="GUI from MGMT"),
            rule("1700000006", interface="lan", protocol="udp", source={"network": "lan"},
                 destination={"network": "lanip", "port": "53"}, disabled="", descr="DNS <b>to</b> firewall"),
            rule("", type="match", interface="wan", floating="yes", descr="queue"),
        ]},
    }


def to_xml(value: Any, tag: str) -> str:
    if isinstance(value, list):
        return "".join(to_xml(item, tag) for item in value)
    if isinstance(value, dict):
        return f"<{tag}>" + "".join(to_xml(v, k) for k, v in value.items() if v is not None) + f"</{tag}>"
    if value is True or value == "":
        return f"<{tag}></{tag}>"
    return f"<{tag}>{escape(str(value))}</{tag}>"


def from_xml(el) -> Any:
    children = list(el)
    if not children:
        return el.text or ""
    out: dict[str, Any] = {}
    for child in children:
        value = from_xml(child)
        if child.tag in LISTS:
            out.setdefault(child.tag, []).append(value)
        else:
            out[child.tag] = value
    return out


class FakePfsense(FakeSshTransport):
    """A pfSense CE box behind SSH. Its clock is `now`; `tick()` runs the dead-man jobs whose time has come."""

    def __init__(self, tmp: Path, version: str = "2.8.1-RELEASE"):
        super().__init__()
        self.tmp = tmp
        self.version = version
        self.config = initial_config()
        self.running = self.trackers()
        self.now = [1000.0]
        self.uid = "0"
        self.armed: dict[str, dict[str, Any]] = {}
        self.php_runs: list[dict[str, Any]] = []
        self.load_fails = False
        self.php_breaks = False
        self.lockout_after_apply = False
        self.locked = False
        self.on_arm = None
        self.on_php = None
        self.events: list[str] = []
        self.stubs = tmp / "stubs"
        self.stubs.mkdir()
        (self.stubs / "config.inc").write_text(STUB_CONFIG)
        (self.stubs / "filter.inc").write_text(STUB_FILTER)
        self.on("cat /etc/version", lambda c, i, s: f"{self.version}\n")
        self.on("cat /cf/conf/config.xml", lambda c, i, s: (0, self.xml(), "") if self.uid == "0" or self.readable
                else (1, "", "cat: /cf/conf/config.xml: Permission denied"))
        self.on("/sbin/ifconfig -a", IFCONFIG)
        self.on("printenv SSH_CONNECTION", "10.0.99.10 50123 10.0.99.1 22\n")
        self.on("id -u", lambda c, i, s: self.uid + "\n")
        self.on("/sbin/pfctl -sr", lambda c, i, s: "\n".join(
            ["pass in quick on igb1 proto tcp from any to (igb1) port = https ridentifier 10000 keep state"] +
            [f"pass in quick on igb1 all ridentifier {t} keep state label \"USER_RULE\"" for t in self.running]))
        self.on("/etc/rc.filter_configure", lambda c, i, s: self.reload())
        self.on(re.compile(r"^umask 077 && cat > /tmp/atrium-[0-9a-f]{16}\.php && /usr/local/bin/php-cgi -q -f "
                           r"/tmp/atrium-[0-9a-f]{16}\.php; rc=\$\?; rm -f /tmp/atrium-[0-9a-f]{16}\.php; exit \$rc$"),
                lambda c, i, s: self.php(i))
        self.on("/bin/sh -s", lambda c, i, s: self.shell(i))
        self.readable = True

    # -- device state ----------------------------------------------------------------------

    def xml(self) -> str:
        return '<?xml version="1.0"?>\n' + to_xml(self.config, "pfsense") + "\n"

    def trackers(self) -> list[str]:
        return [r["tracker"] for r in self.config["filter"]["rule"] if r.get("tracker") and "disabled" not in r]

    def reload(self) -> str:
        self.running = self.trackers()
        return ""

    def tick(self) -> None:
        for job in self.armed.values():
            if job["state"] == "armed" and self.now[0] >= job["deadline"]:
                job["state"] = "fired"
                self.config = from_xml(__import__("xml.etree.ElementTree", fromlist=["x"]).fromstring(job["pre"]))
                self.reload()
                self.locked = False

    @contextlib.asynccontextmanager
    async def session(self, target):
        self.tick()
        self.fail_connect = LOCKED if self.locked else None if self.fail_connect == LOCKED else self.fail_connect
        async with super().session(target) as session:
            yield session

    # -- PHP (run for real against the stubs) -------------------------------------------------

    def php(self, script: str) -> tuple[int, str, str]:
        match = re.search(r"base64_decode\('([A-Za-z0-9+/=]*)'\)", script)
        payload = json.loads(base64.b64decode(match.group(1)))
        if self.on_php:
            self.on_php(payload)
        xml_file, restored = self.tmp / "config.xml", self.tmp / "restored.xml"
        xml_file.write_text(self.xml())
        restored.unlink(missing_ok=True)
        if "config_path" in payload:
            payload["config_path"] = str(xml_file)
        if "tmp" in payload:
            payload["tmp"] = str(self.tmp / "restore-upload.xml")
        if "daemon" in payload:
            payload["daemon"], payload["sha256"] = "/bin/sh", "/bin/sh"
        self.php_runs.append(payload)
        self.events.append("php:" + (",".join(op["kind"] for op in payload["ops"]) if "ops" in payload else
                                     "restore" if "content" in payload else "probe"))
        if self.php_breaks:
            return 255, "", "PHP Fatal error: something broke"
        script = script.replace(match.group(1), base64.b64encode(json.dumps(payload).encode()).decode())
        (self.tmp / "script.php").write_text(script)
        state, log = self.tmp / "state.json", self.tmp / "php.log"
        state.write_text(json.dumps(self.config))
        log.write_text("")
        done = subprocess.run([PHP, "-d", f"include_path={self.stubs}", "-f", str(self.tmp / "script.php")],
                              capture_output=True, text=True, timeout=60,
                              env={"ATRIUM_STATE": str(state), "ATRIUM_LOG": str(log), "ATRIUM_RESTORED": str(restored),
                                   "PATH": "/usr/bin:/bin"})
        assert done.returncode == 0, done.stderr
        lines = log.read_text().splitlines()
        if any(line.startswith("write_config") for line in lines):
            self.config = json.loads(state.read_text())
        if restored.exists():
            import xml.etree.ElementTree as ET
            self.config = from_xml(ET.fromstring(restored.read_text()))
        if "filter_configure_sync" in lines and not self.load_fails:
            self.reload()
        if self.lockout_after_apply and any(op["kind"] == "add" for op in payload.get("ops") or []):
            self.locked = True
        return 0, done.stdout, done.stderr

    # -- the dead-man shell scripts (Atrium's own templates) -------------------------------------

    def shell(self, script: str) -> tuple[int, str, str]:
        self.tick()
        if "touch /tmp/atrium-arm-" in script:
            cid = re.search(r"touch /tmp/atrium-arm-([0-9a-f]{16})", script).group(1)
            window = int(re.search(r"sleep (\d+);", script).group(1))
            assert "/usr/sbin/daemon -f /bin/sh -c 'sleep" in script and script.index("cp /cf/conf/config.xml") < \
                script.index("touch")
            pre = self.xml()
            self.events.append("arm")
            if self.on_arm:
                self.on_arm()
            self.armed[cid] = {"deadline": self.now[0] + window, "pre": pre, "state": "armed", "window": window}
            return 0, hashlib.sha256(pre.encode()).hexdigest() + "\n", ""
        disarm = re.match(r"^if mv /tmp/atrium-arm-([0-9a-f]{16}) /tmp/atrium-(\w+)-\1", script)
        if disarm:
            job = self.armed.get(disarm.group(1))
            if job and job["state"] == "armed":
                job["state"] = disarm.group(2)
                return 0, disarm.group(2) + "\n", ""
            return 0, ("fired" if job and job["state"] == "fired" else "missing") + "\n", ""
        restore = re.match(r"^\[ -f /root/atrium-pre-([0-9a-f]{16})\.xml \]", script)
        if restore:
            job = self.armed.get(restore.group(1))
            if not job or job.get("cleaned"):
                return 1, "", ""
            import xml.etree.ElementTree as ET
            self.config = from_xml(ET.fromstring(job["pre"]))
            self.reload()
            return 0, "restored\n", ""
        cleanup = re.match(r"^rm -f /root/atrium-pre-([0-9a-f]{16})\.xml", script)
        if cleanup:
            if cleanup.group(1) in self.armed:
                self.armed[cleanup.group(1)]["cleaned"] = True
            return 0, "", ""
        return 127, "", "unexpected script"

    def commands(self) -> list[str]:
        return [c.command for _, c in self.calls]


@pytest.fixture
def fake(tmp_path, monkeypatch):
    device = FakePfsense(tmp_path)
    monkeypatch.setattr(PfsenseConnector, "clock", staticmethod(lambda: device.now[0]))
    return device


def connector(fake: FakePfsense, **config: Any) -> PfsenseConnector:
    """A new instance (= a new SSH connection), as the hub builds one per call."""
    return PfsenseConnector(clean_config(PfsenseConnector, {"host": "10.0.99.1", "host_key": HOST_KEY, **config}),
                            {"private_key": KEY}, fake)


def snapshot(fake: FakePfsense, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


ALLOW = parse_ops([{"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
                    "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
                    "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Users to intranet",
                    "marker": "atrium:chg_7"}])


def disable(*trackers: str) -> list[dict[str, Any]]:
    return parse_ops([{"op": "disable_rules", "rules": [{"id": t, "vendor_ref": t} for t in trackers]}])


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_config_xml_into_the_network_model(fake):
    record = snapshot(fake)
    assert record["external_id"] == "pf1.example.lan"
    assert record["device"] == {"vendor": "pfSense", "model": "CE", "version": "2.8.1-RELEASE",
                                "hostname": "pf1.example.lan", "management_address": "10.0.99.1", "serial": ""}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert ifaces["wan"]["role"] == "wan" and ifaces["wan"]["subnets"] == ["198.51.100.0/24"]  # DHCP: from ifconfig
    assert ifaces["opt1"]["vlan"] == 20 and ifaces["opt1"]["subnets"] == ["10.0.20.0/24", "2001:db8:20::/64"]
    assert ifaces["lan"]["role"] == "lan" and ifaces["opt2"]["name"] == "MGMT"
    assert "198.51.100.20" in record["self_addresses"] and "127.0.0.1" not in record["self_addresses"]
    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["web_servers"]["cidrs"] == ["10.0.20.10/32", "10.0.20.11/32"]
    assert aliases["web_ports"]["ports"] == "80,443,8000-8080"
    assert aliases["admins"]["resolved"] is False and aliases["blocklist"]["kind"] == "url"

    rules = record["rules"]
    assert [r["id"] for r in rules] == ["anti-lockout", "1700000004", "1700000003", "1700000001", "1700000002",
                                        "1700000005", "1700000006"]  # automatic, floating, group, interfaces
    lockout = rules[0]
    assert lockout["interfaces"] == ["lan"] and lockout["destination"]["cidrs"] == ["10.0.10.1/32"]
    assert lockout["services"] == [{"proto": "tcp", "ports": "443,80,22", "alias": None, "name": ""}]
    by = {r["id"]: r for r in rules}
    assert by["1700000003"]["interfaces"] == ["lan", "opt1"] and by["1700000003"]["source"]["nets"] == ["lan", "opt1"]
    assert by["1700000002"]["services"][0]["ports"] == "80,443,8000-8080" and by["1700000002"]["log"]
    assert by["1700000004"]["floating"] and by["1700000004"]["direction"] == "any" and not by["1700000004"]["quick"]
    assert by["1700000005"]["destination"]["self"] and by["1700000005"]["source"]["aliases"] == ["mgmt_net"]
    dns = by["1700000006"]
    assert not dns["enabled"] and dns["destination"]["cidrs"] == ["10.0.10.1/32"]
    assert dns["description"] == "DNS <b>to</b> firewall"  # device text: kept as text, never HTML
    text = json.dumps(record)
    assert HASH not in text and "queue" not in text  # "match" rules neither pass nor block
    assert record["default_policy"] == {"inbound": "block"}
    commands = fake.commands()
    assert set(commands) == {"cat /etc/version", "cat /cf/conf/config.xml", "/sbin/ifconfig -a"}


def test_revision_and_parsing_safety(fake):
    first = snapshot(fake)
    fake.now[0] += 100
    assert snapshot(fake)["revision"] == first["revision"]
    fake.config["filter"]["rule"][0]["descr"] = "edited in the GUI"
    assert snapshot(fake)["revision"] != first["revision"]
    with pytest.raises(ValueError, match="DOCTYPE"):
        parse_config_xml('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><pfsense>&a;</pfsense>')
    with pytest.raises(ValueError, match="not a pfSense"):
        parse_config_xml("<opnsense/>")
    fake.config["system"]["webgui"]["noantilockout"] = ""
    assert all(r["id"] != "anti-lockout" for r in snapshot(fake)["rules"])


def test_small_parsers():
    assert parse_ifconfig(IFCONFIG)["igb1.20"] == ["10.0.20.1/24", "2001:db8:20::1/64"]
    assert parse_ifconfig(IFCONFIG)["lo0"] == []
    assert parse_platform("2.8.1-RELEASE\n")["product"] == "pfSense CE"
    assert parse_platform("25.07.1-RELEASE")["product"] == "pfSense Plus"


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


@needs_php
def test_test_reports_each_step_and_the_write_capability(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    assert [c["name"] for c in result["checks"]][:6] == ["reachability", "tls", "authentication", "privileges",
                                                        "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 120}
    assert "read-only one is recommended" in detail(result, "privileges")
    assert "pinned host key" in detail(result, "tls") and "dead-man revert after 120 s" in detail(result, "api_features")
    assert "10.0.99.10" in detail(result, "management_guard") and "tcp 443,80,22" in detail(result, "anti_lockout")
    assert len(fake.sessions) == 1  # one connection for the whole test
    assert run(connector(fake, rollback_window_s=300).test())["network_write"]["window_s"] == 300
    assert run(connector(fake, read_only=True).test())["network_write"] is None


@needs_php
def test_test_on_plus_non_root_and_failures(fake):
    fake.version = "25.07.1-RELEASE"
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "read only" in detail(result, "version")
    fake.version, fake.uid = "2.8.1-RELEASE", "1001"
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "non-root" in detail(result, "privileges")
    fake.readable = False
    result = run(connector(fake).test())
    assert result["ok"] is False and "Permission denied" in result["detail"]
    for message, failing in (("10.0.99.1:22: the host key is not trusted - pin it", "tls"),
                             ("10.0.99.1:22: authentication failed - check the user and key", "authentication"),
                             ("10.0.99.1:22: cannot connect (ConnectionRefusedError: refused)", "reachability")):
        fake.fail_connect = message
        result = run(connector(fake).test())
        assert result["ok"] is False and result["checks"][-1]["name"] == failing and not result["checks"][-1]["ok"]
    fake.fail_connect = None
    result = run(PfsenseConnector(clean_config(PfsenseConnector, {"host": "10.0.99.1"}), {}, fake).test())
    assert result["checks"][-1]["name"] == "authentication"


def test_config_validation():
    assert clean_config(PfsenseConnector, {"host": "fw.example.net"})["username"] == "admin"
    for bad in ({"host": "-oProxyCommand=x"}, {"host": "fw", "mode": "telnet"}, {"host": "fw", "rollback_window_s": 30},
                {"host": "fw", "ca_file": "ca.pem"}, {"host": "fw", "username": "a b"}):
        with pytest.raises(ValueError):
            clean_config(PfsenseConnector, bad)
    assert PfsenseConnector.endpoint({"host": "fw", "mode": "ssh"}) != PfsenseConnector.endpoint({"host": "fw",
                                                                                                    "mode": "pfrest"})


# --------------------------------------------------------------------------------------
# changes (pfSense CE over SSH): dead-man timer, PHP primitives
# --------------------------------------------------------------------------------------


@needs_php
def test_apply_verify_confirm(fake):
    before = snapshot(fake)
    preview = run(connector(fake).preview_change(ALLOW, before))
    assert preview["problems"] == [] and preview["steps"][0]["kind"] == "add_rule"
    assert any("dead-man" in n for n in preview["notes"]) and fake.php_runs == []
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert fake.events == ["php:probe", "arm", "php:add"]  # the revert job is armed before anything is written
    assert len({n for n, _ in fake.calls[-8:]}) == 1  # read, guard, arm, write and check on ONE connection
    write = fake.php_runs[-1]
    assert write["ops"] == [{"kind": "add", "rule": {
        "type": "pass", "interface": "lan", "ipprotocol": "inet", "protocol": "tcp",
        "source": {"address": "10.0.10.0/24"}, "destination": {"address": "10.0.20.0/24", "port": "443"},
        "descr": "atrium:chg_7 Users to intranet", "log": True}}]
    assert write["expect"] == hashlib.sha256(fake.armed[next(iter(fake.armed))]["pre"].encode()).hexdigest()
    assert applied["rollback_until"] == pytest.approx(fake.now[0] + 120) and "pf runs the new ruleset" in applied["notes"]
    tracker = applied["created"][0]["id"]
    assert tracker == "1000" and tracker in fake.running  # the PHP picked a fresh tracker
    added = next(r for r in fake.config["filter"]["rule"] if r["tracker"] == tracker)
    assert added["created"] == {"time": 1760000000, "username": "Atrium"} and "disabled" not in added
    after = snapshot(fake)  # a new connection
    assert ops_applied(after, ALLOW) == []
    lan = [r["id"] for r in after["rules"] if r["interfaces"] == ["lan"] and r["id"] != "anti-lockout"]
    assert lan[0] == tracker  # top of the LAN rules
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]
    fake.now[0] += 500
    assert ops_applied(snapshot(fake), ALLOW) == []  # confirmed: the timer found nothing to do
    revert = inverse_ops(ALLOW, applied)
    run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


@needs_php
def test_dead_man_reverts_unconfirmed_changes(fake):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW + disable("1700000001"), before["revision"], None))
    assert applied["disabled"] == ["1700000001"]
    fake.now[0] += 121
    assert ops_reverted(before, snapshot(fake), ALLOW + disable("1700000001")) == []
    with pytest.raises(ChangeError) as late:
        run(connector(fake).confirm_change(applied["token"]))
    assert late.value.state == "rolled_back"


@needs_php
def test_rollback_inverse_then_pre_change_file(fake):
    before = snapshot(fake)
    ops = ALLOW + disable("1700000001")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result == {"rolled_back": True, "method": "inverse_ops", "notes": []}
    assert ops_reverted(before, snapshot(fake), ops) == []
    job = next(iter(fake.armed.values()))
    assert job["state"] == "rolled" and job["cleaned"]  # the timer was disarmed and the copy removed
    fake.now[0] += 500
    assert ops_reverted(before, snapshot(fake), ops) == []

    applied = run(connector(fake).apply_change(ops, snapshot(fake)["revision"], None))
    fake.php_breaks = True  # the inverse cannot run: the pre-change config.xml goes back
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result["method"] == "deadman" and "rule by rule failed" in result["notes"][0]
    fake.php_breaks = False
    assert ops_reverted(before, snapshot(fake), ops) == []


@needs_php
def test_stale_guard_and_unsupported(fake):
    before = snapshot(fake)
    with pytest.raises(ChangeError) as stale:
        run(connector(fake).apply_change(ALLOW, "h-0000000000000000", None))
    assert stale.value.code == "stale" and fake.armed == {}

    fake.on_arm = lambda: fake.config["filter"]["rule"][0].update(descr="changed meanwhile")
    with pytest.raises(ChangeError) as moved:  # changed between the read and the copy
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert moved.value.code == "stale" and moved.value.state == "unchanged"
    assert all(job["state"] == "rolled" for job in fake.armed.values())
    fake.on_arm = None
    fake.config["filter"]["rule"][0]["descr"] = "Default allow LAN to any"

    fake.on_php = lambda payload: payload.get("expect") and fake.config["filter"]["rule"][1].update(descr="moved")
    with pytest.raises(ChangeError) as php_stale:  # changed between the copy and the write
        run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert php_stale.value.code == "stale" and php_stale.value.state == "unchanged"
    fake.on_php = None

    # the hub signs in from 10.0.99.10 to SSH port 22 (SSH_CONNECTION): only rules carrying that path are protected
    record = snapshot(fake)
    assert run(connector(fake).preview_change(disable("1700000005"), record))["problems"] == []  # 443 only
    assert run(connector(fake).preview_change(disable("1700000001"), record))["problems"] == []  # from LAN
    fake.config["filter"]["rule"].append(rule("1700000009", interface="opt2", protocol="tcp",
                                              source={"address": "mgmt_net"},
                                              destination={"network": "(self)", "port": "22"}, descr="SSH from MGMT"))
    record = snapshot(fake)
    with pytest.raises(ChangeError) as lockout:
        run(connector(fake).apply_change(disable("1700000009"), record["revision"], None))
    assert lockout.value.code == "lockout"

    wide = parse_ops([
        {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24", "10.0.11.0/24"]},
         "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
         "services": [{"proto": "tcp", "ports": "80,443"}], "marker": "atrium:chg_8"},
        {"op": "allow", "source": {"zone": "INTERNAL", "cidrs": ["10.0.10.0/24"]},
         "destination": {"zone": "opt1", "cidrs": ["2001:db8:20::/64"]}, "services": [{"proto": "icmp"}],
         "marker": "atrium:chg_8"},
        {"op": "disable_rules", "rules": [{"id": "anti-lockout"}, {"id": "index:6"}]}])
    problems = " | ".join(run(connector(fake).preview_change(wide, record))["problems"])
    for expected in ("one source network", "one port or one range", "no interface 'INTERNAL'", "IPv4 and IPv6",
                     "anti-lockout rule cannot be changed", "has no tracker id"):
        assert expected in problems, expected
    fake.version = "25.07.1-RELEASE"
    with pytest.raises(ChangeError) as plus:
        run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert plus.value.code == "invalid" and "Plus" in plus.value.message
    with pytest.raises(ChangeError) as read_only:
        run(connector(fake, read_only=True).apply_change(ALLOW, record["revision"], None))
    assert read_only.value.code == "unsupported"


@needs_php
def test_rules_that_do_not_load_are_rolled_back_at_once(fake):
    before = snapshot(fake)
    fake.load_fails = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "rolled_back" and "did not load" in caught.value.message
    fake.load_fails = False
    assert ops_reverted(before, snapshot(fake), ALLOW) == []


@needs_php
def test_lockout_is_undone_by_the_device_timer(fake):
    before = snapshot(fake)
    fake.lockout_after_apply = True
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert run(connector(fake).test())["ok"] is False  # the hub's check over a new connection fails
    with pytest.raises(ChangeError) as unreachable:
        run(connector(fake).rollback_change(applied["token"], None))
    assert unreachable.value.code == "unreachable" and "console option 15" in unreachable.value.message
    fake.now[0] += 121
    fake.fail_connect = None
    assert run(connector(fake).test())["ok"] and ops_reverted(before, snapshot(fake), ALLOW) == []


@needs_php
def test_the_php_write_script_on_its_own(tmp_path):
    """PHP_APPLY against the stubs: placement before the interface's first rule (floating rules skipped), fresh
    trackers, presence flags, nothing written for an unknown tracker."""
    device = FakePfsense(tmp_path)
    script = PHP_APPLY.replace("@@PAYLOAD@@", base64.b64encode(json.dumps({
        "ops": [{"kind": "add", "rule": {"type": "pass", "interface": "lan", "descr": "a"}},
                {"kind": "add", "rule": {"type": "pass", "interface": "opt9", "descr": "b"}},
                {"kind": "set", "tracker": "1700000001", "disabled": True},
                {"kind": "set", "tracker": "1700000006", "disabled": False}],
        "expect": None, "config_path": "/nonexistent", "now": 1700000004, "user": "Atrium", "desc": "t"}).encode()).decode())
    code, out, _ = device.php(script)
    result = json.loads(out.strip().splitlines()[-1].split("ATRIUM-RESULT:")[1])
    assert result == {"ok": True, "created": ["1700000007", "1700000008"]}
    rules = device.config["filter"]["rule"]
    assert [r["tracker"] for r in rules][:3] == ["1700000007", "1700000001", "1700000002"]
    assert rules[-1]["tracker"] == "1700000008"  # an interface without rules: appended
    assert rules[1]["disabled"] is True and "disabled" not in next(r for r in rules if r["tracker"] == "1700000006")
    before = copy.deepcopy(device.config)
    script = PHP_APPLY.replace("@@PAYLOAD@@", base64.b64encode(json.dumps({
        "ops": [{"kind": "set", "tracker": "42", "disabled": True}], "expect": None, "config_path": "/x", "now": 1,
        "user": "Atrium", "desc": "t"}).encode()).decode())
    _, out, _ = device.php(script)
    assert '"error":"missing"' in out and device.config == before


def test_tokens_are_validated(fake):
    for token in ("", "{}", json.dumps({"v": 1, "cid": "x; rm -rf /", "created": [], "toggled": {}}),
                  json.dumps({"v": 1, "cid": "0123456789abcdef", "created": ["1; reboot"], "toggled": {}})):
        with pytest.raises(ChangeError, match="Not a change token"):
            run(connector(fake).confirm_change(token))


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


@needs_php
def test_backup_and_restore(fake):
    taken = run(connector(fake).backup())
    assert taken["format"] == "xml" and HASH.encode() in taken["content"] and taken["revision"].startswith("h-")
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    content = taken["content"]
    backup = Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, "xml", None, taken["revision"])
    restored = run(connector(fake).restore_backup(backup))
    assert restored["restored"] and restored["revision"] == before["revision"]
    assert ops_reverted(before, snapshot(fake), ALLOW) == [] and "/etc/rc.filter_configure" in fake.commands()
    assert fake.php_runs[-1]["desc"] == "Atrium backup bk_1"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_2", b"<opnsense/>", "x", 0.0)))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"


def test_commands_never_carry_device_text(fake):
    fake.config["filter"]["rule"][0]["descr"] = "$(reboot); `halt` 'x"
    run(connector(fake).pull("network"))
    assert all(c in {"cat /etc/version", "cat /cf/conf/config.xml", "/sbin/ifconfig -a"} for c in fake.commands())


# --------------------------------------------------------------------------------------
# the unofficial REST API package (read only)
# --------------------------------------------------------------------------------------


API_KEY = "pfrest-key-1a2b3c4d5e6f7a8b9c0d"


def rest_answer(data: Any) -> httpx.Response:
    return httpx.Response(200, json={"code": 200, "status": "ok", "response_id": "SUCCESS", "message": "", "data": data})


def fake_rest(request: httpx.Request) -> httpx.Response:
    if request.headers.get("X-API-Key") != API_KEY:
        return httpx.Response(401, json={"code": 401, "status": "unauthorized", "response_id": "AUTH_FAILED",
                                         "message": "Authentication failed", "data": []})
    path = request.url.path
    data = {
        "/api/v2/system/version": {"version": "2.8.1-RELEASE", "base": "2.8.1", "patch": "0", "buildtime": "x"},
        "/api/v2/interfaces": [
            {"id": "wan", "if": "igb0", "enable": True, "descr": "WAN", "typev4": "dhcp", "ipaddr": "dhcp"},
            {"id": "lan", "if": "igb1", "enable": True, "descr": "LAN", "typev4": "static", "ipaddr": "10.0.10.1",
             "subnet": 24},
            {"id": "opt1", "if": "igb1.20", "enable": True, "descr": "SERVERS", "typev4": "static",
             "ipaddr": "10.0.20.1", "subnet": 24}],
        "/api/v2/interface/vlans": [{"id": 0, "if": "igb1", "tag": 20, "vlanif": "igb1.20", "descr": ""}],
        "/api/v2/firewall/aliases": [{"id": 0, "name": "web_servers", "type": "host",
                                      "address": ["10.0.20.10", "10.0.20.11"], "descr": "", "detail": []}],
        "/api/v2/firewall/rules": [
            {"id": 0, "type": "pass", "interface": ["LAN"], "ipprotocol": "inet", "protocol": None, "source": "LAN",
             "source_port": None, "destination": "any", "destination_port": None, "descr": "Default allow LAN",
             "disabled": False, "log": False, "floating": False, "tracker": 1700000001},
            {"id": 1, "type": "pass", "interface": ["SERVERS"], "ipprotocol": "inet", "protocol": "tcp",
             "source": "!SERVERS", "destination": "LAN:ip", "destination_port": "443", "descr": "to the GUI",
             "disabled": True, "log": True, "floating": False, "tracker": 1700000002},
            {"id": 2, "type": "block", "interface": ["LAN", "SERVERS"], "ipprotocol": "inet", "protocol": "udp",
             "source": "any", "destination": "web_servers", "destination_port": "53", "floating": True,
             "quick": True, "direction": "in", "tracker": 1700000003, "descr": ""}],
    }.get(path)
    if path == "/api/v2/interface/groups":
        return httpx.Response(403, json={"code": 403, "status": "forbidden", "response_id": "FORBIDDEN",
                                         "message": "no", "data": []})
    return rest_answer(data) if data is not None else httpx.Response(404, json={"code": 404, "data": []})


def rest_connector(**secrets: str) -> PfsenseConnector:
    return PfsenseConnector(clean_config(PfsenseConnector, {"host": "10.0.99.1", "mode": "pfrest"}),
                            secrets or {"api_key": API_KEY}, httpx.MockTransport(fake_rest))


def test_rest_package_reads_only():
    records, errors = normalize("network", run(rest_connector().pull("network")))
    record = records[0]
    assert errors == [] and record["errors"] == []
    rules = {r["id"]: r for r in record["rules"]}
    assert rules["1700000001"]["interfaces"] == ["lan"] and rules["1700000001"]["source"]["nets"] == ["lan"]
    gui = rules["1700000002"]
    assert gui["source"] == {"any": False, "cidrs": [], "aliases": [], "nets": ["opt1"], "self": False, "negate": True}
    assert gui["destination"]["cidrs"] == ["10.0.10.1/32"] and not gui["enabled"]
    assert rules["1700000003"]["floating"] and rules["1700000003"]["interfaces"] == ["lan", "opt1"]
    assert rules["1700000003"]["order"] < rules["1700000001"]["order"]  # floating rules first
    assert any("unofficial" in n for n in record["notes"]) and any("groups: not readable" in n for n in record["notes"])
    assert next(i for i in record["interfaces"] if i["id"] == "opt1")["vlan"] == 20

    result = run(rest_connector().test())
    assert result["ok"] and result["network_write"] is None
    assert "UNOFFICIAL" in detail(result, "api_features") and result["detail"].endswith("(read only)")
    assert rest_connector().write_capability() is None
    bad = run(rest_connector(api_key="wrong-key-value").test())
    assert bad["ok"] is False and bad["checks"][-1]["name"] == "authentication" and "wrong-key-value" not in json.dumps(bad)
    with pytest.raises(ChangeError) as caught:
        run(rest_connector().apply_change(ALLOW, record["revision"], None))
    assert caught.value.code == "unsupported"


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


@needs_php
def test_through_the_hub(client, monkeypatch, wait_for, tmp_path):
    from hub.models import Manifest, Tool

    fake = FakePfsense(tmp_path)
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="pf1", name="pfSense edge", source_type="saas", source="https://www.pfsense.org", status="ready",
                manifest=Manifest(id="pf1", name="pfSense edge", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    response = client.put("/api/tools/pf1/connection", json={
        "kind": "pfsense", "config": {"host": "10.0.99.1", "host_key": HOST_KEY}, "secrets": {"private_key": KEY}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/pf1/connection/test").json()
    assert tested["ok"], tested
    assert tested["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 120}
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "pf1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=pf1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/pf1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/pf1").json()
    assert device["record"]["device"]["vendor"] == "pfSense" and len(device["record"]["rules"]) == 7
    text = json.dumps(device)
    assert HASH not in text and "fake-key-material" not in text


def test_without_php_cgi_the_firewall_is_still_read(fake):
    fake.on(re.compile(r"php-cgi"), (127, "", "sh: /usr/local/bin/php-cgi: not found"))
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None
    assert "php-cgi" in detail(result, "api_features") and "missing for changes" in detail(result, "api_features")


@needs_php
def test_a_write_without_answer_restores_the_pre_change_file(fake):
    before = snapshot(fake)
    original = fake.php

    def silent(script):  # the write runs, but its answer is lost
        code, out, err = original(script)
        return (code, "", err) if '"kind": "add"' in json.dumps(fake.php_runs[-1]) else (code, out, err)

    fake.on(re.compile(r"php-cgi"), lambda c, i, s: silent(i))
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "rolled_back"
    assert fake.events[-1] == "php:add"  # no rule-by-rule undo with an unknown tracker: the file went back
    assert ops_reverted(before, snapshot(fake), ALLOW) == [] and not any("atrium:" in r.get("descr", "")
                                                                       for r in fake.config["filter"]["rule"])
