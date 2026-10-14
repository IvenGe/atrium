"""Windows Defender Firewall connector (hub/connectors/windows_firewall.py) against a fake Windows host behind SSH.

The fake answers each PowerShell script the connector sends (it reads the script's name and Base64 JSON payload).
When PowerShell is available (``pwsh`` on PATH, or ATRIUM_TEST_PWSH pointing at it) the real scripts also run:
every script must parse, the fixed command must read its script from stdin, and the read / arm / apply / confirm /
revert scripts run against stub cmdlets - the read script's JSON must equal what the fake answers, so the fake
cannot drift from the scripts. The NetSecurity and ScheduledTasks cmdlets themselves only exist on Windows.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
from typing import Any

import pytest

from hub.connectors import windows_firewall as wf
from hub.connectors.base import normalize
from hub.connectors.netmodel import Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops
from hub.connectors.windows_firewall import WindowsFirewallConnector
from hub.execution.sshfake import FakeSshTransport
from hub.integration.connections import clean_config

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-windows-key-material-0123456789\n-----END OPENSSH PRIVATE KEY-----"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestsOnly0123456789abcdefgh"
LOCKED = "10.0.20.7:22: no answer within 10s"
PWSH = os.environ.get("ATRIUM_TEST_PWSH") or shutil.which("pwsh")


def run(coro):
    return asyncio.run(coro)


def rule(name: str, **fields: Any) -> dict[str, Any]:
    base = {"name": name, "display": name, "description": "", "group": "", "enabled": "True", "direction": "Inbound",
            "action": "Allow", "profile": "Any", "status": "OK", "store_type": "Local", "enforcement": ["Full"],
            "protocol": "TCP", "local_port": ["Any"], "remote_port": ["Any"], "local_address": ["Any"],
            "remote_address": ["Any"], "interface": ["Any"]}
    base.update(fields)
    return base


def initial_rules() -> list[dict[str, Any]]:
    return [
        rule("OpenSSH-Server-In-TCP", display="OpenSSH Server (sshd)", local_port=["22"]),
        rule("RemoteDesktop-UserMode-In-TCP", display="Remote Desktop - User Mode (TCP-In)", group="@FirewallAPI.dll,-28752",
             enabled="False", local_port=["3389"]),
        rule("CoreNet-DNS-Out-UDP", display="Core Networking - DNS (UDP-Out)", direction="Outbound", protocol="UDP",
             remote_port=["53"]),
        rule("{8c3a1f6e-0000-4000-8000-000000000001}", display="SQL Server <script>", profile="Domain, Private",
             local_port=["1433", "1434"], remote_address=["10.0.10.0/255.255.255.0", "LocalSubnet"]),
        rule("Block-Guests", display="Block guest network", action="Block", protocol="Any", local_port=[],
             remote_port=[], remote_address=["10.0.30.1-10.0.30.254"]),
        rule("GPO-Web", display="Web (from GPO)", store_type="GroupPolicy", local_port=["80", "443"],
             enforcement=["Full"]),
        rule("ICMP-Echo", display="Ping", protocol="ICMPv4", local_port=["RPC"], interface=["Ethernet 2"]),
        rule("atrium-chg_old-0", display="Atrium chg_old-0", description="atrium:chg_old.0 Postgres from LAN",
             group="Atrium", local_port=["5432"], remote_address=["10.0.10.0/255.255.255.0"],
             local_address=["10.0.20.7"]),
    ]


class FakeWindows(FakeSshTransport):
    """A Windows host behind OpenSSH. Its clock is `now`; `tick()` runs Scheduled Tasks whose time has come."""

    def __init__(self):
        super().__init__(handler=self.handle)
        self.now = [1000.0]
        self.fw_rules = initial_rules()
        self.admin = True
        self.has_tasks = True
        self.ssh = "10.0.20.100 50211 10.0.20.7 22"
        self.peers: list[str] = []
        self.profiles = [{"name": n, "enabled": "True", "inbound": "Block", "outbound": "Allow", "allow_inbound": "True",
                          "allow_local": "True", "log_allowed": "False", "log_blocked": "True"}
                         for n in ("Domain", "Private", "Public")]
        self.ips = [{"alias": "Ethernet", "address": "10.0.20.7", "prefix": 24},
                    {"alias": "Ethernet", "address": "fe80::7", "prefix": 64},
                    {"alias": "Ethernet 2", "address": "203.0.113.20", "prefix": 28},
                    {"alias": "Loopback Pseudo-Interface 1", "address": "127.0.0.1", "prefix": 8}]
        self.adapters = [{"alias": "Ethernet", "status": "Up", "vlan": "20"},
                         {"alias": "Ethernet 2", "status": "Up", "vlan": "0"}]
        self.categories = [{"alias": "Ethernet", "category": "DomainAuthenticated"},
                           {"alias": "Ethernet 2", "category": "Public"}]
        self.registry: dict[str, str] = {}
        self.tasks: dict[str, dict[str, Any]] = {}
        self.events: list[str] = []
        self.locked = False
        self.lockout_after_apply = False
        self.apply_error = False
        self.scripts: list[str] = []

    # -- plumbing --------------------------------------------------------------------------------

    def tick(self) -> None:
        for sid, task in list(self.tasks.items()):
            if self.now[0] >= task["deadline"] and not task.get("ran"):
                task["ran"] = True
                self.revert(task["data"])
                self.locked = False
                self.events.append(f"fired:{sid}")

    @contextlib.asynccontextmanager
    async def session(self, target):
        self.tick()
        self.fail_connect = LOCKED if self.locked else None if self.fail_connect == LOCKED else self.fail_connect
        async with super().session(target) as session:
            yield session

    def reply(self, value: dict[str, Any]) -> str:
        return "noise from a profile script\n" + wf.RESULT + json.dumps(value) + "\n"

    def handle(self, command: str, stdin: str | None, session) -> Any:
        assert command == wf.COMMAND, command  # the command line never changes
        name = re.match(r"# atrium:(\w+)", stdin).group(1)
        data = json.loads(base64.b64decode(re.search(r"FromBase64String\('([A-Za-z0-9+/=]*)'\)", stdin).group(1)))
        self.scripts.append(name)
        return getattr(self, f"do_{name}")(data, stdin)

    # -- the scripts -------------------------------------------------------------------------------

    def read_answer(self, port: int = 22) -> dict[str, Any]:
        return {"ok": True, "rules": copy.deepcopy(self.fw_rules), "joined": len(self.fw_rules), "piped": 0,
                "profiles": copy.deepcopy(self.profiles),
                "ips": copy.deepcopy(self.ips), "adapters": copy.deepcopy(self.adapters),
                "categories": copy.deepcopy(self.categories),
                "routes": ["Ethernet 2"], "listen": [{"address": "0.0.0.0", "port": 22}, {"address": "::", "port": 3389},
                                                     {"address": "127.0.0.1", "port": 5939}],
                "peers": [] if self.ssh else list(self.peers), "ssh": self.ssh, "host": "WIN-APP01", "ps": "5.1.20348.2849",
                "os": {"caption": "Microsoft Windows Server 2022 Standard", "version": "10.0.20348", "build": "20348"},
                "admin": self.admin, "tasks": self.has_tasks}

    def do_read(self, data: dict[str, Any], script: str) -> str:
        return self.reply(self.read_answer(data["port"]))

    def do_arm(self, data: dict[str, Any], script: str) -> str:
        assert re.fullmatch(r"[0-9a-f]{16}", data["sid"]) and 60 <= data["window"] <= 600
        if not self.admin:
            return self.reply({"ok": False, "error": "exception", "fqid": "UnauthorizedAccess", "detail": "Access is denied."})
        revert = base64.b64decode(data["revert"]).decode("utf-16-le")
        assert revert.startswith("# atrium:revert\n") and "Out-Atrium" not in revert
        payload = json.loads(base64.b64decode(re.search(r"FromBase64String\('([A-Za-z0-9+/=]*)'\)", revert).group(1)))
        assert payload["sid"] == data["sid"] and payload["mode"] == "fired"
        self.registry[data["sid"]] = "armed"
        self.tasks[data["sid"]] = {"deadline": self.now[0] + data["window"], "data": payload}
        self.events.append("arm")
        return self.reply({"ok": True, "state": "Ready"})

    def do_apply(self, data: dict[str, Any], script: str) -> str:
        if self.registry.get(data["sid"]) != "armed":
            return self.reply({"ok": False, "error": "not_armed"})
        self.events.append("apply")
        done = []
        for op in data["ops"]:
            by = {r["name"]: r for r in self.fw_rules}
            if self.apply_error and done:
                return self.reply({"ok": False, "error": "exception", "fqid": "HRESULT 0x80070057,New-NetFirewallRule",
                                    "detail": "The parameter is incorrect."})
            if op["kind"] == "add":
                if op["name"] in by:
                    return self.reply({"ok": False, "error": "exists", "done": done})
                profile = op["profile"] or "Any"
                self.fw_rules.append(rule(op["name"], display=op["display"], description=op["description"], group="Atrium",
                                       protocol=op["protocol"], local_port=op["local_port"] or ["Any"],
                                       remote_address=[re.sub(r"/32$", "", a) for a in op["remote_address"]],
                                       local_address=[re.sub(r"/32$", "", a) for a in op["local_address"]],
                                       profile=profile, interface=[op["interface"]] if op["interface"] else ["Any"]))
            else:
                if op["name"] not in by:
                    return self.reply({"ok": False, "error": "missing", "done": done})
                by[op["name"]]["enabled"] = "True" if op["enabled"] else "False"
            done.append(op["name"])
        if self.lockout_after_apply:
            self.locked = True
        return self.reply({"ok": True, "done": done})

    def revert(self, data: dict[str, Any]) -> str:
        state = self.registry.get(data["sid"])
        if state != "armed":
            return state or ""
        self.registry[data["sid"]] = data["mode"]
        self.fw_rules = [r for r in self.fw_rules if r["name"] not in data["created"]]
        for entry in data["toggled"]:
            for r in self.fw_rules:
                if r["name"] == entry["name"]:
                    r["enabled"] = "True" if entry["enabled"] else "False"
        self.events.append(data["mode"])
        return "reverted"

    def do_rollback(self, data: dict[str, Any], script: str) -> str:
        assert data["mode"] == "rolled" and "Unregister-ScheduledTask" in script
        state = self.revert(data)
        self.tasks.pop(data["sid"], None)
        return self.reply({"ok": True, "state": state})

    def do_confirm(self, data: dict[str, Any], script: str) -> str:
        state = self.registry.get(data["sid"], "missing")
        if state == "armed":
            state = self.registry[data["sid"]] = "confirmed"
            self.tasks.pop(data["sid"], None)
            self.events.append("confirm")
        return self.reply({"ok": True, "state": state})

    def do_backup(self, data: dict[str, Any], script: str) -> str:
        if not self.admin:
            return self.reply({"ok": False, "error": "export"})
        content = b"regf-fake-wfw" + json.dumps(self.fw_rules).encode()
        return self.reply({"ok": True, "content": base64.b64encode(content).decode()})

    def do_restore(self, data: dict[str, Any], script: str) -> str:
        content = base64.b64decode(data["content"])
        if hashlib.sha256(content).hexdigest() != data["sha256"]:
            return self.reply({"ok": False, "error": "content"})
        self.fw_rules = json.loads(content[len(b"regf-fake-wfw"):])
        self.events.append("restore")
        return self.reply({"ok": True, "error": None})


@pytest.fixture
def fake(monkeypatch):
    device = FakeWindows()
    monkeypatch.setattr(WindowsFirewallConnector, "clock", staticmethod(lambda: device.now[0]))
    return device


def connector(fake: FakeWindows, **config: Any) -> WindowsFirewallConnector:
    return WindowsFirewallConnector(clean_config(WindowsFirewallConnector, {"host": "10.0.20.7", "host_key": HOST_KEY,
                                                                            **config}), {"private_key": KEY}, fake)


def snapshot(fake: FakeWindows, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


def allow(zone: str = "domain", src: str = "10.0.10.0/24", dst: str = "10.0.20.7/32", ports: str = "443",
          proto: str = "tcp", marker: str = "atrium:chg_7", **extra: Any) -> list[dict[str, Any]]:
    service = {"proto": proto, **({"ports": ports} if proto != "icmp" else {})}
    return parse_ops([{"op": "allow", "source": {"zone": zone, "cidrs": src.split(",")},
                       "destination": {"zone": extra.pop("dst_zone", zone), "cidrs": dst.split(",")},
                       "services": [service], "description": "Users to <intranet>", "marker": marker, **extra}])


def toggle(op: str, *names: str) -> list[dict[str, Any]]:
    return parse_ops([{"op": op, "rules": [{"id": n, "vendor_ref": n} for n in names]}])


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_rules_profiles_and_interfaces(fake):
    record = snapshot(fake)
    assert record["kind"] == "host" and record["external_id"] == "WIN-APP01"
    assert record["device"] == {"vendor": "Microsoft", "model": "Microsoft Windows Server 2022 Standard",
                                "version": "10.0.20348 (build 20348), PowerShell 5.1.20348.2849", "hostname": "WIN-APP01",
                                "management_address": "10.0.20.7", "serial": ""}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"Ethernet", "Ethernet 2"}  # loopback left out
    assert ifaces["Ethernet"]["vlan"] == 20 and ifaces["Ethernet"]["subnets"] == ["10.0.20.0/24"]
    assert ifaces["Ethernet 2"]["role"] == "wan" and ifaces["Ethernet"]["role"] == "lan"
    assert "fe80::7" not in record["self_addresses"]
    zones = {z["id"]: z for z in record["zones"]}
    assert zones["domain"]["interfaces"] == ["Ethernet"] and zones["public"]["interfaces"] == ["Ethernet 2"]
    rules = {r["id"]: r for r in record["rules"]}
    assert record["rules"][0]["action"] == "block"  # no rule order on Windows: block rules shown first
    ssh = rules["OpenSSH-Server-In-TCP"]
    assert ssh["destination"] == {**ssh["destination"], "self": True} and ssh["source"]["any"]
    assert ssh["services"] == [{"proto": "tcp", "ports": "22", "alias": None, "name": ""}]
    assert ssh["description"] == "OpenSSH Server (sshd)"
    assert rules["RemoteDesktop-UserMode-In-TCP"]["enabled"] is False
    dns = rules["CoreNet-DNS-Out-UDP"]
    assert dns["direction"] == "out" and dns["source"]["self"] and dns["services"][0] == {
        "proto": "udp", "ports": "53", "alias": None, "name": ""}
    sql = rules["{8c3a1f6e-0000-4000-8000-000000000001}"]
    assert sql["source_zones"] == ["domain", "private"] and sql["services"][0]["ports"] == "1433,1434"
    assert sql["source"]["cidrs"] == ["10.0.10.0/24", "10.0.20.0/24", "203.0.113.16/28"]  # LocalSubnet resolved
    assert sql["description"] == "SQL Server <script>"  # device text, kept as text
    guests = rules["Block-Guests"]
    assert guests["action"] == "block" and guests["services"] is None and "10.0.30.128/26" in guests["source"]["cidrs"]
    assert rules["GPO-Web"]["description"] == "Web (from GPO) [GroupPolicy]"
    icmp = rules["ICMP-Echo"]
    assert icmp["services"] == [{"proto": "icmp", "ports": None, "alias": None, "name": ""}]
    assert icmp["interfaces"] == ["Ethernet 2"]
    mine = rules["atrium-chg_old-0"]
    assert mine["marker"] == "chg_old" and mine["description"] == "atrium:chg_old.0 Postgres from LAN"
    assert mine["destination"]["cidrs"] == ["10.0.20.7/32"] and mine["source"]["cidrs"] == ["10.0.10.0/24"]
    assert record["default_policy"] == {"inbound": "block", "outbound": "pass"}
    notes = " | ".join(record["notes"])
    assert "no rule order" in notes and "1 rules come from Group Policy" in notes
    assert "listening on every address: tcp/22, tcp/3389" in notes and "logging is per profile" in notes
    fake.profiles[2]["enabled"] = "False"  # the firewall is off on the Public profile, which has an interface
    record = snapshot(fake)
    assert record["default_policy"]["inbound"] == "pass" and any("OFF for the public" in n for n in record["notes"])


def test_revision_follows_the_rules(fake):
    first = snapshot(fake)
    fake.now[0] += 60
    assert snapshot(fake)["revision"] == first["revision"]
    fake.fw_rules[0]["enforcement"] = ["InactiveProfile"]  # runtime state, not configuration
    assert snapshot(fake)["revision"] == first["revision"]
    fake.fw_rules[1]["enabled"] = "True"
    assert snapshot(fake)["revision"] != first["revision"]


def test_small_helpers():
    endpoint, aliases = wf.addresses(["10.0.0.5", "10.1.0.0/255.255.0.0", "Internet", "LocalSubnet4", "junk"], ["10.9.0.0/16"])
    assert endpoint["cidrs"] == ["10.0.0.5/32", "10.1.0.0/16", "10.9.0.0/16"]
    assert aliases == ["keyword:internet", "unreadable:junk"]
    assert wf.addresses(["Any"], [])[0] is None
    assert wf.ports_text(["8080", "80", "8000-8010"]) == ("80,8000-8010,8080", None)
    assert wf.ports_text(["RPC"]) == (None, "RPC") and wf.ports_text(["Any"]) == (None, None)
    assert wf.COMMAND.startswith("powershell.exe -NoProfile -NonInteractive -NoLogo -EncodedCommand ")
    assert base64.b64decode(wf.COMMAND.split()[-1]).decode("utf-16-le") == wf.BOOT


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def test_test_reports_each_step(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    assert [c["name"] for c in result["checks"]][:6] == ["reachability", "tls", "authentication", "privileges",
                                                        "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 180}
    assert "read-only one is recommended" in detail(result, "privileges")
    assert "Windows Server 2022" in detail(result, "version") and "PowerShell 5.1" in detail(result, "version")
    assert "Scheduled Task (SYSTEM) after 180 s" in detail(result, "api_features")
    assert detail(result, "profiles") == "Domain on (inbound block), Private on (inbound block), Public on (inbound block)"
    assert "never disables it" in detail(result, "openssh_rule")
    assert "10.0.20.100" in detail(result, "management_guard")
    assert len(fake.sessions) == 1 and fake.scripts == ["read"]
    assert run(connector(fake, read_only=True).test())["network_write"] is None


def test_test_explains_why_changes_are_off(fake):
    fake.admin = False
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "not elevated" in detail(result, "privileges")
    fake.admin, fake.has_tasks = True, False
    assert "no dead-man timer" in detail(run(connector(fake).test()), "api_features")
    fake.has_tasks = True
    fake.profiles[0]["allow_local"] = "False"
    result = run(connector(fake).test())
    assert result["network_write"] is None and "Group Policy ignores local rules" in detail(result, "api_features")
    fake.profiles[0]["allow_local"] = "True"
    fake.fw_rules = [r for r in fake.fw_rules if r["name"] != "OpenSSH-Server-In-TCP"]
    result = run(connector(fake).test())
    assert not next(c for c in result["checks"] if c["name"] == "openssh_rule")["ok"]
    fake.ssh, fake.peers = "", ["10.0.20.100"]  # no SSH_CONNECTION: the established connection to port 22 tells
    assert "10.0.20.100" in detail(run(connector(fake).test()), "management_guard")
    fake.peers = ["10.0.20.100", "10.0.20.101"]
    assert "address is unknown" in detail(run(connector(fake).test()), "management_guard")
    for message, failing in (("10.0.20.7:22: the host key is not trusted - pin it", "tls"),
                             ("10.0.20.7:22: authentication failed - check the user and key", "authentication"),
                             ("10.0.20.7:22: cannot connect (ConnectionRefusedError: refused)", "reachability")):
        fake.fail_connect = message
        result = run(connector(fake).test())
        assert result["ok"] is False and result["checks"][-1]["name"] == failing


def test_powershell_that_does_not_answer(fake):
    fake.handler = lambda command, stdin, session: (1, "", "'powershell.exe' is not recognized as an internal command")
    result = run(connector(fake).test())
    assert result["ok"] is False and "did not answer the read the firewall script" in result["detail"]
    assert "not recognized" in result["detail"]


def test_config_validation():
    config = clean_config(WindowsFirewallConnector, {"host": "win-app01.corp.example"})
    assert config["username"] == "atrium" and config["rollback_window_s"] == 180
    assert clean_config(WindowsFirewallConnector, {"host": "h", "username": "CORP\\atrium"})["username"] == "CORP\\atrium"
    for bad in ({"host": "-oProxyCommand=x"}, {"host": "h", "rollback_window_s": 9}, {"host": "h", "username": "a b"}):
        with pytest.raises(ValueError):
            clean_config(WindowsFirewallConnector, bad)


# --------------------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------------------


def test_apply_verify_confirm_and_revert(fake):
    before = snapshot(fake)
    ops = allow(ports="80,443")
    preview = run(connector(fake).preview_change(ops, before))
    assert preview["problems"] == [], preview
    assert fake.events == [] and any("Scheduled Task" in n for n in preview["notes"])
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert fake.events == ["arm", "apply"]  # the revert task is registered before anything is written
    sessions = [n for n, c in fake.calls if c.input.startswith(("# atrium:arm", "# atrium:apply"))]
    reads = [n for n, c in fake.calls if c.input.startswith("# atrium:read") and n == sessions[0]]
    assert len(set(sessions)) == 1 and len(reads) == 2  # read, arm, write and re-read on ONE connection
    assert applied["created"] == [{"op": 0, "id": "atrium-chg_7-0", "vendor_ref": "atrium-chg_7-0"}]
    added = next(r for r in fake.fw_rules if r["name"] == "atrium-chg_7-0")
    assert added["profile"] == "Domain" and added["local_port"] == ["80", "443"] and added["group"] == "Atrium"
    assert added["description"] == "atrium:chg_7.0 Users to intranet"  # the marker; "<>" dropped
    task = fake.tasks[json.loads(applied["token"])["sid"]]
    assert task["deadline"] == fake.now[0] + 180 and task["data"]["created"] == ["atrium-chg_7-0"]
    after = snapshot(fake)
    assert ops_applied(after, ops) == []
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"] and not fake.tasks
    fake.now[0] += 500
    assert ops_applied(snapshot(fake), ops) == []
    revert = inverse_ops(ops, applied)  # Windows has a real disabled state
    reverted = run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
    assert reverted["disabled"] == ["atrium-chg_7-0"]
    record = snapshot(fake)
    assert ops_reverted(before, record, ops) == [] and ops_applied(record, revert) == []
    run(connector(fake).confirm_change(reverted["token"]))
    enabled = run(connector(fake).apply_change(toggle("enable_rules", "RemoteDesktop-UserMode-In-TCP"),
                                               snapshot(fake)["revision"], None))
    assert enabled["enabled"] == ["RemoteDesktop-UserMode-In-TCP"]
    assert next(r for r in fake.fw_rules if r["name"] == "RemoteDesktop-UserMode-In-TCP")["enabled"] == "True"


def test_dead_man_reverts_unconfirmed_changes(fake):
    before = snapshot(fake)
    ops = allow(zone="Ethernet", dst_zone="Ethernet") + toggle("disable_rules", "atrium-chg_old-0")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    added = next(r for r in fake.fw_rules if r["name"] == "atrium-chg_7-0")
    assert added["interface"] == ["Ethernet"] and added["profile"] == "Any"
    fake.now[0] += 181
    assert ops_reverted(before, snapshot(fake), ops) == [] and fake.registry[json.loads(applied["token"])["sid"]] == "fired"
    with pytest.raises(ChangeError) as late:
        run(connector(fake).confirm_change(applied["token"]))
    assert late.value.state == "rolled_back"


def test_rollback_lockout_and_failed_steps(fake):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    assert run(connector(fake).rollback_change(applied["token"], None)) == {"rolled_back": True, "method": "deadman",
                                                                           "notes": []}
    assert ops_reverted(before, snapshot(fake), allow()) == [] and not fake.tasks
    fake.lockout_after_apply = True
    applied = run(connector(fake).apply_change(allow(), snapshot(fake)["revision"], None))
    assert run(connector(fake).test())["ok"] is False
    with pytest.raises(ChangeError) as unreachable:
        run(connector(fake).rollback_change(applied["token"], None))
    assert unreachable.value.code == "unreachable" and "Scheduled Task undoes" in unreachable.value.message
    fake.now[0] += 181
    assert run(connector(fake).test())["ok"] and ops_reverted(before, snapshot(fake), allow()) == []
    fake.lockout_after_apply, fake.apply_error = False, True
    ops = allow() + toggle("disable_rules", "atrium-chg_old-0")
    with pytest.raises(ChangeError) as caught:  # the first step went through, the second failed
        run(connector(fake).apply_change(ops, snapshot(fake)["revision"], None))
    assert caught.value.state == "rolled_back" and fake.events[-1] == "rolled"
    assert ops_reverted(before, snapshot(fake), ops) == []
    fake.apply_error, fake.admin = False, False
    with pytest.raises(ChangeError) as unsupported:
        run(connector(fake).apply_change(allow(), snapshot(fake)["revision"], None))
    assert unsupported.value.code == "unsupported" and "elevated" in unsupported.value.message


def test_preview_problems_and_guards(fake):
    record = snapshot(fake)
    cases = [
        (allow(zone="wlan"), "no profile or interface 'wlan'"),
        (allow(ports="443,80"), "ascending order"),
        (parse_ops([{"op": "allow", "source": {"zone": "domain", "cidrs": ["10.0.10.0/24"]},
                     "destination": {"zone": "domain", "cidrs": ["10.0.20.7/32"]},
                     "services": [{"proto": "tcp", "ports": "80"}, {"proto": "udp", "ports": "53"}],
                     "marker": "atrium:chg_7"}]), "one service per Windows rule"),
        (allow(dst="10.0.99.0/24"), "hold none of this host's addresses"),
        (allow(marker="atrium:chg_old"), "already on the host"),
        (toggle("disable_rules", "OpenSSH-Server-In-TCP"), "never disables it"),
        (toggle("disable_rules", "GPO-Web"), "comes from GroupPolicy"),
        (toggle("disable_rules", "Gone-Rule"), "is not on the host"),
        (toggle("enable_rules", "OpenSSH-Server-In-TCP"), "nothing to change"),
    ]
    for ops, expected in cases:
        problems = " | ".join(run(connector(fake).preview_change(ops, record))["problems"])
        assert expected in problems, (expected, problems)
    # an allow rule carrying the hub's SSH path (10.0.20.100 -> 22) is protected by the management-path guard
    fake.fw_rules.append(rule("Admin-SSH", local_port=["22"], remote_address=["10.0.20.0/24"]))
    problems = run(connector(fake).preview_change(toggle("disable_rules", "Admin-SSH"), snapshot(fake)))["problems"]
    assert any("cut the hub off" in p for p in problems)
    # a disabled block rule matching the hub's path is never enabled (block rules always win)
    fake.fw_rules.append(rule("Block-Mgmt", action="Block", enabled="False", local_port=["22", "3389"],
                           remote_address=["10.0.20.0/24"]))
    record = snapshot(fake)
    problems = run(connector(fake).preview_change(toggle("enable_rules", "Block-Mgmt"), record))["problems"]
    assert any("block rules always win" in p for p in problems)
    with pytest.raises(ChangeError) as lockout:
        run(connector(fake).apply_change(toggle("disable_rules", "Admin-SSH"), record["revision"], None))
    assert lockout.value.code == "lockout" and fake.events == []
    with pytest.raises(ChangeError) as stale:
        run(connector(fake).apply_change(allow(), "h-0000000000000000", None))
    assert stale.value.code == "stale" and fake.events == []
    fake.profiles[1]["allow_inbound"] = "False"
    problems = " | ".join(run(connector(fake).preview_change(allow(), snapshot(fake)))["problems"])
    assert "Shields Up" in problems


def test_tokens_are_validated(fake):
    for token in ("", "{}", json.dumps({"v": 1, "sid": "x; reboot"}),
                  json.dumps({"v": 1, "sid": "0123456789abcdef", "created": ["Remove-Everything"]}),
                  json.dumps({"v": 1, "sid": "0123456789abcdef", "toggled": [{"name": "a\nb", "enabled": True}]})):
        with pytest.raises(ChangeError, match="Not a change token"):
            run(connector(fake).confirm_change(token))


def test_device_text_only_travels_as_data(fake):
    fake.fw_rules.append(rule("evil'; Remove-NetFirewallRule -All; '", display="$(Stop-Computer)", local_port=["8080"],
                              remote_address=["10.0.30.0/24"]))
    record = snapshot(fake)
    run(connector(fake).apply_change(toggle("disable_rules", "evil'; Remove-NetFirewallRule -All; '"),
                                     record["revision"], None))
    assert all(c.command == wf.COMMAND for _, c in fake.calls)  # one fixed command line, always
    for _, call in fake.calls:  # in scripts, device text only appears inside the Base64 payloads
        visible = re.sub(r"FromBase64String\('[A-Za-z0-9+/=]*'\)", "", call.input)
        assert "Remove-NetFirewallRule -All" not in visible and "Stop-Computer" not in visible


def test_backup_and_restore(fake):
    taken = run(connector(fake).backup())
    assert taken["format"] == "wfw" and taken["content"].startswith(b"regf-fake-wfw")
    assert taken["sha256"] == hashlib.sha256(taken["content"]).hexdigest()
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    backup = Backup("bk_1", taken["content"], taken["sha256"], 0.0, "wfw", None, taken["revision"])
    restored = run(connector(fake).restore_backup(backup))
    assert restored["restored"] and restored["revision"] == before["revision"] and fake.events[-1] == "restore"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_2", b"<xml/>", "x", 0.0, "xml")))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"
    fake.admin = False
    with pytest.raises(ChangeError):
        run(connector(fake).backup())


# --------------------------------------------------------------------------------------
# the real scripts (PowerShell, when available)
# --------------------------------------------------------------------------------------

needs_pwsh = pytest.mark.skipif(not PWSH, reason="PowerShell (pwsh) is not installed - set ATRIUM_TEST_PWSH")

# Stub cmdlets: functions win over cmdlets of the same name in PowerShell's command lookup.
STUBS = r"""
$global:Reg = @{}; $global:Log = New-Object System.Collections.ArrayList
$global:Fixture = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('@@FIXTURE@@')) | ConvertFrom-Json
$global:Store = @{}
foreach ($r in $global:Fixture.rules) { $global:Store[$r.name] = [pscustomobject]@{ Name = $r.name; DisplayName = $r.display
  Description = $r.description; Group = $r.group; Enabled = $r.enabled; Direction = $r.direction; Action = $r.action
  Profile = $r.profile; PrimaryStatus = $r.status; PolicyStoreSourceType = $r.store_type; EnforcementStatus = @($r.enforcement)
  InstanceID = 'id-' + $r.name; Fixture = $r } }
function Get-NetFirewallRule { param($PolicyStore, [switch]$TracePolicyStore) $global:Store.Values | Sort-Object Name }
function Get-NetFirewallPortFilter { param([switch]$All, $PolicyStore) foreach ($r in $global:Store.Values) {
  [pscustomobject]@{ InstanceID = $r.InstanceID; Protocol = $r.Fixture.protocol; LocalPort = $r.Fixture.local_port; RemotePort = $r.Fixture.remote_port } } }
function Get-NetFirewallAddressFilter { param([switch]$All, $PolicyStore) foreach ($r in $global:Store.Values) {
  [pscustomobject]@{ InstanceID = $r.InstanceID; LocalAddress = $r.Fixture.local_address; RemoteAddress = $r.Fixture.remote_address } } }
function Get-NetFirewallInterfaceFilter { param([switch]$All, $PolicyStore) foreach ($r in $global:Store.Values) {
  [pscustomobject]@{ InstanceID = $r.InstanceID; InterfaceAlias = $r.Fixture.interface } } }
function Get-NetFirewallProfile { param($PolicyStore) foreach ($p in $global:Fixture.profiles) { [pscustomobject]@{ Name = $p.name
  Enabled = $p.enabled; DefaultInboundAction = $p.inbound; DefaultOutboundAction = $p.outbound; AllowInboundRules = $p.allow_inbound
  AllowLocalFirewallRules = $p.allow_local; LogAllowed = $p.log_allowed; LogBlocked = $p.log_blocked } } }
function Get-NetIPAddress { param($ErrorAction) foreach ($i in $global:Fixture.ips) { [pscustomobject]@{ InterfaceAlias = $i.alias; IPAddress = $i.address; PrefixLength = $i.prefix } } }
function Get-NetAdapter { param($ErrorAction) foreach ($a in $global:Fixture.adapters) { [pscustomobject]@{ Name = $a.alias; Status = $a.status; VlanID = $a.vlan } } }
function Get-NetConnectionProfile { param($ErrorAction) foreach ($c in $global:Fixture.categories) { [pscustomobject]@{ InterfaceAlias = $c.alias; NetworkCategory = $c.category } } }
function Get-NetRoute { param($DestinationPrefix, $ErrorAction) foreach ($r in $global:Fixture.routes) { [pscustomobject]@{ InterfaceAlias = $r } } }
function Get-NetTCPConnection { param($State, $LocalPort, $ErrorAction) if ($State -eq 'Listen') { foreach ($l in $global:Fixture.listen) { [pscustomobject]@{ LocalAddress = $l.address; LocalPort = $l.port } } } }
function Get-CimInstance { param($ClassName) [pscustomobject]@{ Caption = $global:Fixture.os.caption; Version = $global:Fixture.os.version; BuildNumber = $global:Fixture.os.build } }
function Test-Path { param($Path) $true }
function New-Item { param($Path, [switch]$Force) }
function Get-ItemProperty { param($Path, $Name, $ErrorAction) if ($global:Reg.ContainsKey($Name)) { [pscustomobject]@{ $Name = $global:Reg[$Name] } } }
function Set-ItemProperty { param($Path, $Name, $Value) $global:Reg[$Name] = $Value }
function New-ItemProperty { param($Path, $Name, $Value, $PropertyType, [switch]$Force) $global:Reg[$Name] = $Value }
function Get-ScheduledTask { param($TaskName, $TaskPath, $ErrorAction) if ($TaskName) { [pscustomobject]@{ TaskName = $TaskName; State = 'Ready' } } }
function Register-ScheduledTask { param($TaskName, $TaskPath, $Action, $Trigger, $Principal, $Settings, [switch]$Force) [void]$global:Log.Add("register $TaskPath$TaskName") }
function Unregister-ScheduledTask { param($TaskName, $TaskPath, $Confirm, $ErrorAction) [void]$global:Log.Add("unregister $TaskName") }
function New-ScheduledTaskAction { param($Execute, $Argument) [void]$global:Log.Add("action $Execute $($Argument.Length)") }
function New-ScheduledTaskTrigger { param([switch]$Once, $At) [void]$global:Log.Add("trigger once") }
function New-ScheduledTaskPrincipal { param($UserId, $LogonType, $RunLevel) [void]$global:Log.Add("principal $UserId $LogonType $RunLevel") }
function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$StartWhenAvailable, $ExecutionTimeLimit) }
function New-NetFirewallRule { param($Name, $DisplayName, $Description, $Group, $Direction, $Action, $Protocol, $RemoteAddress, $LocalAddress, $Enabled, $PolicyStore, $Profile, $LocalPort, $InterfaceAlias)
  [void]$global:Log.Add("new $Name $Direction $Action $Protocol $($LocalPort -join ',') $($RemoteAddress -join ',') $($LocalAddress -join ',') $Profile $InterfaceAlias $Enabled $Description")
  $global:Store[$Name] = [pscustomobject]@{ Name = $Name; Enabled = 'True' } }
function Enable-NetFirewallRule { param([Parameter(ValueFromPipeline = $true)]$InputObject) process { $InputObject.Enabled = 'True'; [void]$global:Log.Add("enable $($InputObject.Name)") } }
function Disable-NetFirewallRule { param([Parameter(ValueFromPipeline = $true)]$InputObject) process { $InputObject.Enabled = 'False'; [void]$global:Log.Add("disable $($InputObject.Name)") } }
function Remove-NetFirewallRule { param([Parameter(ValueFromPipeline = $true)]$InputObject) process { $global:Store.Remove($InputObject.Name); [void]$global:Log.Add("remove $($InputObject.Name)") } }
"""


def pwsh(text: str) -> subprocess.CompletedProcess:
    """Run `text` the way the connector does: the fixed bootstrap command, the script on stdin."""
    return subprocess.run([PWSH, *wf.COMMAND.split()[1:]], input=text, capture_output=True, text=True, timeout=180)


def with_stubs(script: str, fixture: dict[str, Any], tail: str = "") -> str:
    stubs = STUBS.replace("@@FIXTURE@@", base64.b64encode(json.dumps(fixture).encode()).decode())
    return stubs + "\n" + script + "\n" + tail


def result_of(out: subprocess.CompletedProcess) -> dict[str, Any]:
    line = next((l for l in reversed(out.stdout.splitlines()) if l.startswith(wf.RESULT)), None)
    assert line, (out.stdout[-2000:], out.stderr[-2000:])
    return json.loads(line[len(wf.RESULT):])


@needs_pwsh
def test_every_script_parses():
    check = (r"$t = [Console]::In.ReadToEnd(); $e = $null; $null = [System.Management.Automation.Language.Parser]::"
             r"ParseInput($t, [ref]$null, [ref]$e); if ($e.Count) { $e | % { $_.Message } } else { 'ok' }")
    scripts = [wf.script(n, b, {"sid": "0123456789abcdef"}) for n, b in
               (("read", wf.READ), ("arm", wf.ARM), ("apply", wf.APPLY), ("confirm", wf.CONFIRM),
                ("backup", wf.BACKUP), ("restore", wf.RESTORE))]
    scripts += [wf.revert_script("0123456789abcdef", ["atrium-x-0"], [{"name": "a'b", "enabled": True}], m)
                for m in ("fired", "rolled")]
    for text in scripts:
        out = subprocess.run([PWSH, "-NoProfile", "-NonInteractive", "-Command", check], input=text, capture_output=True,
                             text=True, timeout=180)
        assert out.stdout.strip() == "ok", (text.splitlines()[0], out.stdout, out.stderr)


@needs_pwsh
def test_real_read_script_answers_like_the_fake(fake):
    """The read script, run by PowerShell over stub cmdlets fed with the fake's data, prints what the fake prints."""
    data = fake.read_answer()
    fixture = {k: data[k] for k in ("rules", "profiles", "ips", "adapters", "categories", "routes", "listen", "os")}
    script = wf.script("read", wf.READ, {"port": 22})
    out = pwsh(with_stubs(script, fixture))
    real = result_of(out)
    assert real["ok"], real
    expected = json.loads(fake.do_read({"port": 22}, "").split(wf.RESULT)[1])
    for key in ("rules", "profiles", "ips", "adapters", "categories", "routes", "listen", "os"):
        real_value = sorted(real[key], key=json.dumps) if isinstance(real[key], list) else real[key]
        expected_value = sorted(expected[key], key=json.dumps) if isinstance(expected[key], list) else expected[key]
        assert real_value == expected_value, key
    assert real["joined"] == len(fixture["rules"]) and real["piped"] == 0
    assert isinstance(real["admin"], bool) and isinstance(real["tasks"], bool)
    model = wf.read_model(real, "10.0.20.7")  # and the connector reads it
    assert any(r["id"] == "atrium-chg_old-0" for r in model["record"]["rules"])


@needs_pwsh
def test_real_change_scripts_over_stub_cmdlets():
    fixture = {"rules": [rule("Keep-Me"), rule("Toggle-Me", enabled="True"), rule("Odd [name]*", enabled="False")],
               "profiles": [], "ips": [], "adapters": [], "categories": [], "routes": [], "listen": [],
               "os": {"caption": "x", "version": "1", "build": "1"}}
    sid = "0123456789abcdef"
    revert = wf.encoded(wf.revert_script(sid, ["atrium-chg_7-0"], [{"name": "Toggle-Me", "enabled": True},
                                                                   {"name": "Odd [name]*", "enabled": False}], "fired"))
    tail = (r"Out-Atrium @{ ok = $true; log = @($global:Log); reg = $global:Reg; names = @($global:Store.Keys | Sort-Object);"
            r" enabled = @($global:Store.Values | Sort-Object Name | ForEach-Object { $_.Name + '=' + $_.Enabled }) }")
    ops = [{"kind": "add", "name": "atrium-chg_7-0", "display": "Atrium chg_7-0", "description": "atrium:chg_7.0 x",
            "protocol": "TCP", "local_port": ["80", "443"], "remote_address": ["10.0.10.0/24"],
            "local_address": ["10.0.20.7/32"], "profile": None, "interface": "Ethernet [2]"},
           {"kind": "set", "name": "Toggle-Me", "enabled": False}, {"kind": "set", "name": "Odd [name]*", "enabled": True}]
    steps = "\n".join([
        wf.script("arm", wf.ARM, {"sid": sid, "window": 120, "revert": revert}),
        wf.script("apply", wf.APPLY, {"sid": sid, "ops": ops}),
        wf.revert_script(sid, ["atrium-chg_7-0"], [{"name": "Toggle-Me", "enabled": True},
                                                  {"name": "Odd [name]*", "enabled": False}], "rolled"),
        wf.script("confirm", wf.CONFIRM, {"sid": sid})])
    out = pwsh(with_stubs(steps, fixture, wf.OUTPUT + tail))
    results = [json.loads(l[len(wf.RESULT):]) for l in out.stdout.splitlines() if l.startswith(wf.RESULT)]
    assert [r.get("ok") for r in results] == [True, True, True, True, True], (out.stdout[-3000:], out.stderr[-3000:])
    arm, apply, rolled, confirm, final = results
    assert apply["done"] == ["atrium-chg_7-0", "Toggle-Me", "Odd [name]*"]
    assert rolled["state"] == "reverted" and confirm["state"] == "rolled"  # too late to confirm a rolled-back change
    log = final["log"]
    assert "principal SYSTEM ServiceAccount Highest" in log and f"register \\Atrium\\atrium-fw-revert-{sid}" in log
    new = next(l for l in log if l.startswith("new "))
    assert new.startswith("new atrium-chg_7-0 Inbound Allow TCP 80,443 10.0.10.0/24 10.0.20.7/32 Any Ethernet `[2`] True")
    assert log.index("disable Toggle-Me") < log.index("remove atrium-chg_7-0")
    assert "enable Toggle-Me" in log and "disable Odd [name]*" in log  # exact names, never wildcard patterns
    assert final["names"] == ["Keep-Me", "Odd [name]*", "Toggle-Me"]
    assert final["enabled"] == ["Keep-Me=True", "Odd [name]*=False", "Toggle-Me=True"]
    assert final["reg"] == {sid: "rolled"}
    # the task's own revert script (mode fired) runs on its own too: no output needed, nothing armed to undo
    out = pwsh(with_stubs(base64.b64decode(revert).decode("utf-16-le"), fixture, wf.OUTPUT + tail))
    assert result_of(out)["reg"] == {}


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeWindows()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="winapp", name="WIN-APP01 firewall", source_type="saas", source="https://example.invalid",
                status="ready", manifest=Manifest(id="winapp", name="Windows Defender Firewall", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    detected = client.get("/api/tools/winapp").json()
    assert detected["id"] == "winapp"
    response = client.put("/api/tools/winapp/connection", json={
        "kind": "windows_firewall", "config": {"host": "10.0.20.7", "host_key": HOST_KEY}, "secrets": {"private_key": KEY}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/winapp/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "deadman", tested
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "winapp"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=winapp").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/winapp/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/winapp").json()
    assert device["record"]["kind"] == "host" and device["record"]["device"]["vendor"] == "Microsoft"
    assert {z["id"] for z in device["record"]["zones"]} == {"domain", "private", "public"}
    assert "fake-windows-key-material" not in json.dumps(device)
    backup = client.post("/api/network/devices/winapp/backups")
    assert backup.status_code == 201, backup.text
    assert backup.json()["backup"]["format"] == "wfw"


def test_a_change_through_the_hub(client, sign_in, monkeypatch, wait_for):
    """The hub's change path with this connector: proposal, a second administrator's approval, Atrium's backup, the
    Scheduled Task armed before the write, verification over a new connection, confirm (the task is removed)."""
    from hub.models import Manifest, Tool

    fake = FakeWindows()
    fake.ips.append({"alias": "Ethernet 3", "address": "10.0.40.7", "prefix": 24})  # a second internal network
    fake.adapters.append({"alias": "Ethernet 3", "status": "Up", "vlan": "40"})
    fake.categories.append({"alias": "Ethernet 3", "category": "Private"})
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="winapp", name="WIN-APP01", source_type="saas", source="https://example.invalid", status="ready",
                manifest=Manifest(id="winapp", name="Windows Defender Firewall", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    assert client.put("/api/tools/winapp/connection", json={
        "kind": "windows_firewall", "config": {"host": "10.0.20.7", "host_key": HOST_KEY},
        "secrets": {"private_key": KEY}}).status_code == 200
    assert client.post("/api/tools/winapp/connection/test").json()["ok"]
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "winapp"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    assert client.patch("/api/settings/guardrails", json={"device_changes": True,
                                                          "device_changes_need_maintenance_window": False}).status_code == 200
    wait_for(lambda: client.post("/api/network/devices/winapp/refresh").json()["results"][0]["ok"])
    admin2 = sign_in("admin", "admin2")
    body = {"firewall": "winapp", "op": "allow", "source_zone": "z:winapp:domain", "target_zone": "z:winapp:private",
            "services": [{"proto": "tcp", "ports": "8443"}], "log": True, "description": "Admin console"}
    preview = client.post("/api/segmentation/changes/preview", json=body)
    assert preview.status_code == 200 and preview.json()["writable"] and preview.json()["problems"] == [], preview.text
    created = client.post("/api/segmentation/changes", json=body).json()
    assert admin2.post(f"/api/approvals/{created['approval_id']}", json={"approve": True}).status_code == 200
    change_id = created["change"]["id"]
    change = wait_for(lambda: (c := client.get(f"/api/segmentation/changes/{change_id}").json())["status"]
                      in ("applied", "failed", "rolled_back") and c)
    assert change["status"] == "applied", change
    assert fake.events == ["arm", "apply", "confirm"] and not fake.tasks
    added = next(r for r in fake.fw_rules if r["name"] == f"atrium-{change_id}-0")
    assert added["profile"] == "Domain" and added["local_port"] == ["8443"]
    assert added["remote_address"] == ["10.0.20.0/24"] and added["local_address"] == ["10.0.40.0/24"]
    assert hub.store.get("device_backups", change["backup_id"])["format"] == "wfw"
