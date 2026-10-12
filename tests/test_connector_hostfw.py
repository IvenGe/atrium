"""Linux host firewall connector against FakeSshTransport. No SSH, no network."""

from __future__ import annotations

import asyncio
import copy
import json
import shlex

import pytest

from hub import connectors
from hub.connectors import hostfw as fw
from hub.connectors.base import ConnectorError
from hub.connectors.hostfw import HostFirewallConnector
from hub.connectors.netmodel import (
    LEAST_PRIVILEGE_NOTE,
    TEST_CHECKS,
    Backup,
    ChangeError,
    find_marker,
    marker,
    ops_applied,
)
from hub.execution.sshfake import FakeSshTransport

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1lZDI1NTE5AAAAIHostfwTestKey\n-----END OPENSSH PRIVATE KEY-----\n"
PASSPHRASE = "key-pass-phrase-not-sudo"
CONFIG = {"host": "10.0.99.5", "username": "atrium-rw", "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}
SECRETS = {"private_key": KEY, "passphrase": PASSPHRASE}

OS_RELEASE = 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12"\n'
IP_ADDR = [{
    "ifname": "eth0", "flags": ["UP", "LOWER_UP"],
    "addr_info": [{"family": "inet", "local": "10.0.99.5", "prefixlen": 24}],
}]
IP_ROUTE = [{"dst": "default", "dev": "eth0", "gateway": "10.0.99.1"}]
UFW_VERBOSE = (
    "Status: active\nLogging: on (low)\n"
    "Default: deny (incoming), allow (outgoing), disabled (routed)\n"
)
UFW_NUMBERED = """Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    10.20.0.5
[ 2] 443/tcp                    ALLOW IN    10.20.0.0/24               # atrium:r-7f3a
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
"""
UFW_TUPLE = "### tuple ### allow tcp 443 0.0.0.0/0 any 10.20.0.0/24 in comment=atrium:r-7f3a\n"
RICH = ('rule family="ipv4" source address="10.1.1.0/24" destination address="10.2.2.2/32" '
        'port port="443" protocol="tcp" accept')
SAMPLE_NFT = {
    "nftables": [
        {"metainfo": {"json_schema_version": 1, "release_name": "Capital Idea #2", "version": "0.9.6"}},
        {"table": {"family": "inet", "handle": 5, "name": "atrium"}},
        {"set": {"family": "inet", "table": "atrium", "name": "zone_dmz", "handle": 9, "type": "ipv4_addr",
                 "flags": ["interval"], "elem": [{"prefix": {"addr": "10.20.0.0", "len": 24}}]}},
        {"chain": {"family": "inet", "table": "atrium", "name": "input", "handle": 1, "type": "filter",
                   "hook": "input", "prio": 0, "policy": "accept"}},
        {"rule": {"family": "inet", "table": "atrium", "chain": "input", "handle": 7, "comment": "atrium:r-7f3a",
                  "expr": [
                      {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                 "right": "@zone_dmz"}},
                      {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
                      {"counter": {"packets": 8062, "bytes": 37707381}},
                      {"log": {"prefix": "atrium:r-7f3a "}},
                      {"accept": None},
                  ]}},
    ]
}


def run(coro):
    return asyncio.run(coro)


def allow(zone: str = "eth0", description: str = "Users $(touch /tmp/pwned)") -> dict:
    return {"op": "allow", "source": {"zone": zone, "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": zone, "cidrs": ["10.0.20.10/32"]},
            "services": [{"proto": "tcp", "ports": "443"}, {"proto": "tcp", "ports": "80"}],
            "log": True, "description": description, "marker": marker("chg_31")}


def backup_of(content: str) -> Backup:
    return Backup("b1", content.encode(), "sha", 0.0, "json")


def _nft_rule(handle: int, table: str, comment: str, *, accept: bool = True) -> dict:
    expr = [
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "10.1.1.0/24"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "10.2.2.2/32"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
    ]
    if accept:
        expr.append({"accept": None})
    return {"rule": {"family": "inet", "table": table, "chain": "input", "handle": handle, "comment": comment,
                     "expr": expr}}


def default_nft() -> dict:
    return {"nftables": [
        {"metainfo": {"json_schema_version": 1, "release_name": "test", "version": "1.0.7"}},
        {"table": {"family": "inet", "name": "filter", "handle": 1}},
        {"chain": {"family": "inet", "table": "filter", "name": "input", "handle": 2, "type": "filter",
                   "hook": "input", "prio": 0, "policy": "drop"}},
        _nft_rule(3, "filter", "docker"),
    ]}


class LinuxHost:
    """A stateful nftables / ufw / firewalld host. Unmatched commands exit 127."""

    def __init__(self, manager: str = "nftables", *, password: bool = False, sudo: str = "write",
                 nft: dict | None = None, user_rules: str = "", numbered: str = "", rich: list[str] | None = None,
                 version: str = ""):
        self.manager = manager
        self.password = password
        self.sudo = sudo
        self.nft = nft if nft is not None else default_nft()
        self.table_text = ""
        self.user_rules = user_rules
        self.user6 = ""
        self.numbered = numbered
        self.rich = list(rich or [])
        self.disabled: list = []
        self.version = version
        self.handle = 40
        self.verbs: list[str] = []
        self.payloads: list[dict] = []
        self.argvs: list[list[str]] = []
        self.transport = FakeSshTransport(self.answer)

    def answer(self, command: str, stdin: str | None, session):
        argv = shlex.split(command)
        self.argvs.append(argv)
        if argv[:2] == ["sudo", "-n"] and self.password:
            return (1, "", "sudo: a password is required\n")
        if argv[:3] == ["sudo", "-n", fw.WRAPPER] and len(argv) == 4:
            data = json.loads(stdin or "{}")
            self.verbs.append(argv[3])
            self.payloads.append(data)
            if argv[3] == "apply":
                self._mutate(data)
            return json.dumps({"ok": True}) + "\n"
        if argv == fw.SSH_ENV:
            return "10.0.0.5 50000 10.0.99.5 22\n"
        if argv == fw.OS_RELEASE:
            return OS_RELEASE
        if argv == fw.UNAME:
            return "6.1.0-test\n"
        if argv == fw.HOSTNAME:
            return "fw-host\n"
        if argv == fw.FIREWALLD_ACTIVE:
            return "active\n" if self.manager == "firewalld" else "inactive\n"
        if argv == fw.UFW_STATUS_PLAIN:
            if self.manager == "ufw" and not self.password:
                return "Status: active\n"
            return (127, "", "ufw: not available\n")
        if argv == fw.UFW_STATUS:
            return UFW_VERBOSE if self.manager == "ufw" else (127, "", "ufw: not available\n")
        if argv == fw.UFW_NUMBERED:
            return self.numbered
        if argv == fw.UFW_VERSION:
            return (self.version or "ufw 0.36.2") + "\n"
        if argv == fw.UFW_USER:
            return self.user_rules
        if argv == fw.UFW_USER6:
            return self.user6
        if argv == fw.NFT_VERSION:
            if self.manager == "nftables":
                return (self.version or "nftables v1.0.7 (Old MacDonald)") + "\n"
            return (127, "", "nft: not found\n")
        if argv == fw.NFT_LIST:
            return json.dumps(self.nft) + "\n"
        if argv == fw.NFT_TABLE:
            if self.table_text:
                return self.table_text if self.table_text.endswith("\n") else self.table_text + "\n"
            return (1, "", "Error: No such file or directory\n")
        if argv == fw.SUDO_L:
            if self.sudo == "none":
                return (1, "", "atrium-rw is not allowed to run sudo\n")
            listing = "User atrium-rw may run the following commands:\n    (root) NOPASSWD: " + ", ".join(fw.NFT_LIST)
            if self.sudo == "write":
                listing += ", " + fw.WRAPPER
            return listing + "\n"
        if argv == fw.IP_ADDR:
            return json.dumps(IP_ADDR) + "\n"
        if argv == fw.IP_ROUTE:
            return json.dumps(IP_ROUTE) + "\n"
        if argv == fw.FW_VERSION:
            return (self.version or "1.3.3") + "\n"
        if argv == fw.FW_STATE:
            return "running\n"
        if argv in (fw.FW_LIST, fw.FW_LIST_PERM):
            return self._zones_text()
        if argv == fw.FW_DEFAULT:
            return "public\n"
        if argv == fw.FW_DISABLED:
            return json.dumps(self.disabled) + "\n"
        return (127, "", f"fake: no answer for {command}")

    def _zones_text(self) -> str:
        rich = "\n".join(f"        {line}" for line in self.rich)
        body = (
            "public (active)\n  target: default\n  interfaces: eth0\n  sources:\n  services: ssh dhcpv6-client\n"
            "  ports:\n  protocols:\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n"
        )
        return body + (rich + "\n" if rich else "")

    def _mutate(self, data: dict) -> None:
        if self.manager == "nftables":
            self._mutate_nft(data.get("script") or "")
        elif self.manager == "ufw":
            if "user_rules" in data:
                self.user_rules = data["user_rules"] or ""
            if "user6_rules" in data:
                self.user6 = data["user6_rules"] or ""
            for cmd in data.get("commands") or []:
                if cmd and cmd[0] == fw.UFW and "insert" in cmd and "allow" in cmd:
                    self.user_rules = _tuple_line(cmd) + self.user_rules
        else:
            for cmd in data.get("commands") or []:
                zone = next((part.split("=", 1)[1] for part in cmd if str(part).startswith("--zone=")), "public")
                for part in cmd:
                    text = str(part)
                    if text.startswith("--add-rich-rule="):
                        self.rich.append(text.split("=", 1)[1])
                    elif text.startswith("--remove-rich-rule="):
                        line = text.split("=", 1)[1]
                        self.rich = [item for item in self.rich if item != line]
                del zone
            if "disabled_json" in data:
                self.disabled = data["disabled_json"]

    def _mutate_nft(self, script: str) -> None:
        items = self.nft["nftables"]
        for line in script.splitlines():
            if line.startswith("add chain inet atrium"):
                self._ensure_chain()
            elif line.startswith("insert rule inet atrium"):
                self._ensure_chain()
                items.append(self._rule_from_line(line))
            elif line.startswith("replace rule inet atrium"):
                self._replace(line)

    def _ensure_chain(self) -> None:
        items = self.nft["nftables"]
        if any(item.get("chain", {}).get("table") == "atrium" for item in items):
            return
        items.append({"table": {"family": "inet", "name": "atrium", "handle": 5}})
        items.append({"chain": {"family": "inet", "table": "atrium", "name": "input", "handle": 6, "type": "filter",
                                "hook": "input", "prio": 0, "policy": "accept"}})
        self.table_text = "table inet atrium {\n}\n"

    def _rule_from_line(self, line: str) -> dict:
        self.handle += 1
        comment = _quoted(line, "comment")
        expr = []
        source = _braced(line, r"\bip saddr (\{[^}]+\}|\S+)")
        dest = _braced(line, r"\bip daddr (\{[^}]+\}|\S+)")
        port = _braced(line, r"\b(tcp|udp) dport (\{[^}]+\}|\S+)", group=2)
        proto = "tcp"
        found = __import__("re").search(r"\b(tcp|udp) dport", line)
        if found:
            proto = found.group(1)
        if source:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                   "right": _addr_right(source)}})
        if dest:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                                   "right": _addr_right(dest)}})
        if port:
            expr.append({"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}},
                                   "right": _port_right(port)}})
        if "meta l4proto icmpv6" in line:
            expr.append({"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmpv6"}})
        elif "meta l4proto icmp" in line:
            expr.append({"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": "icmp"}})
        if "log prefix" in line:
            expr.append({"log": {"prefix": "atrium"}})
        if "atrium-disabled" not in comment and "accept" in line.split("comment", 1)[0]:
            expr.append({"accept": None})
        return {"rule": {"family": "inet", "table": "atrium", "chain": "input", "handle": self.handle,
                         "comment": comment, "expr": expr}}

    def _replace(self, line: str) -> None:
        import re
        found = re.search(r"handle (\d+)", line)
        if not found:
            return
        handle = int(found.group(1))
        comment = _quoted(line, "comment")
        for item in self.nft["nftables"]:
            rule = item.get("rule")
            if not rule or int(rule.get("handle") or -1) != handle or rule.get("table") != "atrium":
                continue
            rule["comment"] = comment
            expr = [part for part in rule.get("expr") or [] if not any(k in part for k in ("accept", "drop", "reject"))]
            if "atrium-disabled" not in comment:
                expr.append({"accept": None})
            rule["expr"] = expr


def _quoted(line: str, keyword: str) -> str:
    import re
    found = re.search(rf'{keyword} "(.*)"\s*$', line)
    return found.group(1) if found else ""


def _braced(line: str, pattern: str, group: int = 1) -> str:
    import re
    found = re.search(pattern, line)
    return found.group(group) if found else ""


def _split_brace(token: str) -> list[str]:
    if token.startswith("{"):
        return [part.strip() for part in token.strip("{}").split(",") if part.strip()]
    return [token]


def _addr_right(token: str):
    parts = _split_brace(token)
    return parts[0] if len(parts) == 1 else {"set": parts}


def _port_right(token: str):
    parts = [int(part) for part in _split_brace(token)]
    return parts[0] if len(parts) == 1 else {"set": parts}


def _tuple_line(cmd: list[str]) -> str:
    src = cmd[cmd.index("from") + 1]
    dst = cmd[cmd.index("to") + 1]
    if "port" in cmd:
        port = cmd[cmd.index("port") + 1]
        proto = cmd[cmd.index("proto") + 1]
    else:
        port, proto = "any", "icmp"
    comment = cmd[cmd.index("comment") + 1]
    return f"### tuple ### allow {proto} {port} {dst} any {src} in comment={comment}\n"


def connect(host: LinuxHost, **config) -> HostFirewallConnector:
    return HostFirewallConnector({**CONFIG, **config}, SECRETS, host.transport)


def pulled(host: LinuxHost, **config) -> dict:
    return run(connect(host, **config).pull("network"))[0]


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "hostfw", HostFirewallConnector)


def test_sudoers_and_no_password_field():
    text = fw.__doc__ or ""
    for verb in fw.WRAPPER_VERBS:
        assert f"/usr/local/sbin/atrium-fw {verb}" in text
    assert "NOPASSWD" in text
    assert "atrium-ro" in text and "atrium-rw" in text
    assert "AccuracySec=1s" in text
    assert "never stores a sudo password" in text
    assert all(field.name not in {"password", "sudo_password", "sudo_pass"} for field in HostFirewallConnector.fields)
    assert HostFirewallConnector.capabilities == {"network": {"read"}}
    assert HostFirewallConnector.kind == "hostfw"
    spec = HostFirewallConnector(CONFIG, SECRETS, None).write_capability()
    assert spec["rollback"] == "deadman"
    assert spec["ops"] == ["allow", "disable_rules", "enable_rules"]
    with pytest.raises(ConnectorError):
        HostFirewallConnector.validate_config({**CONFIG, "password": "hunter2"})


def test_registry_round_trip():
    assert connectors.connector_class("hostfw") is HostFirewallConnector


def test_password_is_refused_and_not_sent():
    host = LinuxHost()
    conn = HostFirewallConnector(CONFIG, {**SECRETS, "sudo_password": "hunter2"}, host.transport)
    result = run(conn.test())
    assert result["ok"] is False
    assert result["network_write"] is None
    assert "password" in result["detail"]
    assert host.transport.sessions == []


def test_detection_order_and_test_checks():
    firewalld = LinuxHost("firewalld")
    checked = run(connect(firewalld).test())
    assert checked["ok"] is True
    assert [item["name"] for item in checked["checks"]] == list(TEST_CHECKS)
    assert all(item["ok"] for item in checked["checks"])
    assert checked["network_write"]["window_s"] == 180
    assert LEAST_PRIVILEGE_NOTE in checked["checks"][3]["detail"]
    assert "firewalld" in checked["checks"][4]["detail"]
    assert not any("ufw" in part for argv in firewalld.argvs for part in argv)
    assert firewalld.transport.sessions[0].target.password is None
    assert PASSPHRASE not in json.dumps([(a, ) for a in firewalld.argvs])

    ufw = LinuxHost("ufw")
    ufw_result = run(connect(ufw).test())
    assert ufw_result["ok"] is True
    assert "ufw" in ufw_result["checks"][4]["detail"]
    assert fw.NFT_VERSION not in ufw.argvs

    nft = LinuxHost("nftables", version="nftables v0.9.6 (Capital Idea #2)")
    nft_result = run(connect(nft).test())
    assert nft_result["ok"] is True and "nftables" in nft_result["detail"]
    assert "0.9.6" in nft_result["checks"][4]["detail"]

    prompted = LinuxHost("ufw", password=True)
    prompted_result = run(connect(prompted).test())
    assert prompted_result["ok"] is False
    assert prompted_result["network_write"] is None
    assert "unknown" in prompted_result["checks"][4]["detail"]
    assert "nftables" not in prompted_result["checks"][4]["detail"]
    assert fw.NFT_VERSION not in prompted.argvs

    legacy = LinuxHost("iptables")
    legacy_result = run(connect(legacy).test())
    assert legacy_result["ok"] is False
    assert legacy_result["network_write"] is None
    assert legacy_result["checks"][4]["ok"] is False
    record = pulled(legacy)
    assert record["device"]["model"] == "iptables"
    assert any("iptables" in note for note in record["notes"])


def test_test_failures_and_read_only():
    down = LinuxHost()
    down.transport.fail_connect = "timed out waiting for SSH"
    failed = run(connect(down).test())
    assert failed["checks"][0] == {"name": "reachability", "ok": False, "detail": failed["checks"][0]["detail"]}
    assert failed["checks"][0]["ok"] is False
    assert failed["network_write"] is None

    denied = LinuxHost()
    denied.transport.fail_connect = "authentication failed"
    auth = run(connect(denied).test())
    assert auth["checks"][0]["ok"] is True
    assert auth["checks"][1]["name"] == "authentication" and auth["checks"][1]["ok"] is False

    mismatch = LinuxHost()
    mismatch.transport.fail_connect = "host key verification failed"
    keys = run(connect(mismatch).test())
    assert any(item["name"] == "tls" and item["ok"] is False for item in keys["checks"])

    loose = run(connect(LinuxHost(), strict_host_keys=False).test())
    assert loose["ok"] is False
    assert any(item["name"] == "tls" and item["ok"] is False for item in loose["checks"])

    reader = LinuxHost(sudo="read")
    read_result = run(connect(reader).test())
    assert read_result["ok"] is True and read_result["network_write"] is None

    marked = LinuxHost()
    marked_result = run(connect(marked, read_only=True).test())
    assert marked_result["ok"] is True and marked_result["network_write"] is None
    assert "read-only" in marked_result["checks"][3]["detail"]
    assert connect(marked, read_only=True).write_capability() is None


def test_pull_nft_ufw_and_firewalld_samples():
    nft_host = LinuxHost("nftables", nft=copy.deepcopy(SAMPLE_NFT), version="nftables v0.9.6 (Capital Idea #2)")
    first = pulled(nft_host)
    assert first["kind"] == "host"
    assert first["device"]["model"] == "nftables"
    rule = next(item for item in first["rules"] if item["vendor_ref"] == "inet/atrium/input/7")
    assert rule["marker"] == "r-7f3a"
    assert rule["action"] == "pass" and rule["enabled"] is True
    assert rule["destination"].get("self") is True
    assert "zone_dmz" in (rule["source"].get("aliases") or [])
    assert any(alias["name"] == "zone_dmz" and "10.20.0.0/24" in alias["cidrs"] for alias in first["aliases"])
    assert first["interfaces"][0]["id"] == "eth0" and first["interfaces"][0]["role"] == "wan"
    nft_host.nft["nftables"][-1]["rule"]["expr"][2]["counter"]["packets"] = 99999
    second = pulled(nft_host)
    assert second["revision"] == first["revision"]
    assert find_marker(rule["description"]) == "r-7f3a"

    ufw_host = LinuxHost("ufw", user_rules=UFW_TUPLE, numbered=UFW_NUMBERED)
    ufw_record = pulled(ufw_host)
    assert ufw_record["device"]["model"] == "ufw"
    assert len(ufw_record["rules"]) == 1
    assert ufw_record["rules"][0]["marker"] == "r-7f3a"
    assert ufw_record["rules"][0]["source"]["cidrs"] == ["10.20.0.0/24"]
    assert ufw_record["rules"][0]["destination"]["any"] is True
    assert ufw_record["default_policy"]["inbound"] == "block"
    numbered = LinuxHost("ufw", numbered=UFW_NUMBERED)
    numbered_record = pulled(numbered)
    marked = next(item for item in numbered_record["rules"] if item["marker"] == "r-7f3a")
    assert marked["vendor_ref"] == "ufw:4:2"
    assert {(svc["proto"], svc["ports"]) for svc in marked["services"]} == {("tcp", "443")}
    hex_comment = "atrium:r-7f3a".encode().hex()
    parsed = fw.parse_ufw_tuples(
        f"### tuple ### allow tcp 80 10.2.2.2/32 any 10.1.1.0/24 in comment={hex_comment}\n", "4")
    assert parsed[0]["description"].startswith("atrium:r-7f3a")

    firewalld = LinuxHost("firewalld", rich=[
        'rule family="ipv4" source address="10.20.0.0/24" port port="443" protocol="tcp" '
        'log prefix="atrium:r-7f3a " level="info" accept'])
    fw_record = pulled(firewalld)
    assert fw_record["device"]["model"] == "firewalld"
    assert any(zone["id"] == "public" for zone in fw_record["zones"])
    rich = next(item for item in fw_record["rules"] if item.get("marker") == "r-7f3a")
    assert rich["action"] == "pass"
    assert "10.20.0.0/24" in rich["source"]["cidrs"]
    assert {(svc["proto"], svc["ports"]) for svc in rich["services"]} == {("tcp", "443")}
    assert any(item["services"] == [{"proto": "tcp", "ports": "22", "alias": None, "name": ""}]
               or (item["services"] and item["services"][0]["ports"] == "22" and "ssh" in item["description"])
               for item in fw_record["rules"])


def test_nft_allow_disable_and_other_table_untouched():
    host = LinuxHost("nftables")
    conn = connect(host, window_s=90)
    record = run(conn.pull("network"))[0]
    assert any(rule["vendor_ref"] == "inet/filter/input/3" for rule in record["rules"])
    preview = run(conn.preview_change([allow()], {"revision": record["revision"]}))
    assert preview["problems"] == []
    assert host.verbs == []
    assert any("atrium:chg_31" in step["detail"] for step in preview["steps"])

    stale = run(conn.preview_change([allow()], {"revision": "h-stale"}))
    assert any("revision" in problem for problem in stale["problems"])
    assert host.verbs == []

    with pytest.raises(ChangeError) as stale_apply:
        run(conn.apply_change([allow()], "h-stale", None))
    assert stale_apply.value.code == "stale" and stale_apply.value.state == "unchanged"
    assert host.verbs == []

    other = {"op": "disable_rules", "rules": [{"id": "inet/filter/input/3", "vendor_ref": "inet/filter/input/3"}]}
    before = copy.deepcopy(host.nft)
    with pytest.raises(ChangeError) as refused:
        run(conn.apply_change([other], record["revision"], None))
    assert refused.value.code == "invalid" and refused.value.state == "unchanged"
    assert host.nft == before and host.verbs == []

    injected = allow(description="Users $(touch /tmp/pwned)")
    applied = run(conn.apply_change([injected], record["revision"], None))
    assert host.verbs == ["snapshot", "arm-revert", "apply"]
    assert host.payloads[1]["persist"] is False
    timer = host.payloads[1]["timer_argv"]
    assert timer[0] == "/usr/bin/systemd-run"
    assert "--on-active=90" in timer
    assert "--timer-property=AccuracySec=1s" in timer
    assert timer[-2:] == [fw.WRAPPER, "revert-now"]
    assert "flush ruleset" not in host.payloads[1]["revert_script"]
    assert "delete table inet atrium" in host.payloads[1]["revert_script"]
    assert host.payloads[2]["persist"] is False
    script = host.payloads[2]["script"]
    assert "add table inet atrium" in script
    assert "flush ruleset" not in script and "table inet filter" not in script and "table ip " not in script
    assert "$(" not in script
    for argv in host.argvs:
        assert "$(" not in " ".join(argv)
        assert "touch" not in " ".join(argv)
        if argv[:2] == ["sudo", "-n"]:
            assert "-S" not in argv and "-A" not in argv
    assert KEY not in applied["token"] and PASSPHRASE not in applied["token"]
    fresh = pulled(host)
    assert ops_applied(fresh, [injected]) == []
    assert applied["created"][0]["id"] == "atrium:chg_31:0"
    filter_rule = next(item["rule"] for item in host.nft["nftables"]
                       if item.get("rule", {}).get("table") == "filter")
    assert filter_rule["comment"] == "docker"

    sessions = len(host.transport.sessions)
    other_conn = HostFirewallConnector({**CONFIG, "window_s": 90}, SECRETS, host.transport)
    confirmed = run(other_conn.confirm_change(applied["token"]))
    assert confirmed["confirmed"] is True
    assert host.verbs[-1] == "confirm" and host.payloads[-1]["persist"] is True
    assert host.transport.sessions[-1].number != host.transport.sessions[sessions - 1].number
    rolled = run(HostFirewallConnector(CONFIG, SECRETS, host.transport).rollback_change(applied["token"], None))
    assert rolled == {"rolled_back": True, "method": "deadman", "notes": rolled["notes"]}
    assert rolled["method"] == "deadman"
    assert host.verbs[-1] == "revert-now"


def test_nft_lockout_disable_and_enable():
    host = LinuxHost("nftables", nft=copy.deepcopy(SAMPLE_NFT))
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    op = {"op": "disable_rules", "rules": [{"id": "inet/atrium/input/7", "vendor_ref": "inet/atrium/input/7"}]}
    with pytest.raises(ChangeError) as locked:
        run(conn.apply_change([op], record["revision"], None))
    assert locked.value.code == "lockout" and locked.value.state == "unchanged"
    assert host.verbs == []

    owned = _nft_rule(8, "atrium", "$(touch /tmp/pwned)")
    chain = {"chain": {"family": "inet", "table": "atrium", "name": "input", "handle": 6, "type": "filter",
                       "hook": "input", "prio": 0, "policy": "accept"}}
    table = {"table": {"family": "inet", "name": "atrium", "handle": 5}}
    mutable = default_nft()
    mutable["nftables"].extend([table, chain, owned])
    writer = LinuxHost("nftables", nft=mutable, )
    writer.table_text = "table inet atrium {\n}\n"
    conn = connect(writer)
    current = run(conn.pull("network"))[0]
    disable = {"op": "disable_rules", "rules": [{"id": "inet/atrium/input/8", "vendor_ref": "inet/atrium/input/8"}]}
    run(conn.apply_change([disable], current["revision"], None))
    assert "$(" not in writer.payloads[-1]["script"]
    again = pulled(writer)
    found = next(rule for rule in again["rules"] if "inet/atrium/input/8" in rule["vendor_ref"] or rule["id"] == "inet/atrium/input/8")
    assert found["enabled"] is False
    assert any(rule["vendor_ref"] == "inet/filter/input/3" and rule["enabled"] for rule in again["rules"])

    disabled = _nft_rule(11, "atrium", "web atrium-disabled-pass", accept=False)
    doc = default_nft()
    doc["nftables"].extend([table, chain, disabled])
    enabler = LinuxHost("nftables", nft=doc)
    enabler.table_text = "table inet atrium {\n}\n"
    conn = connect(enabler)
    current = run(conn.pull("network"))[0]
    enable = {"op": "enable_rules", "rules": [{"id": "inet/atrium/input/11", "vendor_ref": "inet/atrium/input/11"}]}
    run(conn.apply_change([enable], current["revision"], None))
    enabled = pulled(enabler)
    found = next(rule for rule in enabled["rules"] if rule["vendor_ref"] == "inet/atrium/input/11" or rule["id"] == "inet/atrium/input/11")
    assert found["enabled"] is True


def test_malicious_zone_never_reaches_a_command():
    host = LinuxHost()
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    bad = allow(zone="eth0;reboot")
    with pytest.raises(ChangeError) as exc:
        run(conn.apply_change([bad], record["revision"], None))
    assert exc.value.code == "invalid" and exc.value.state == "unchanged"
    assert host.verbs == []
    blob = json.dumps([(call.command, call.input) for _n, call in host.transport.calls])
    assert "reboot" not in blob and "eth0;reboot" not in blob
    worse = allow()
    worse["source"] = {"zone": "eth0", "cidrs": ["10.0.10.0/24;touch"]}
    with pytest.raises(ChangeError):
        run(conn.apply_change([worse], record["revision"], None))
    assert host.verbs == []


def test_ufw_persists_immediately_and_confirm_only_cancels():
    host = LinuxHost("ufw")
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    op = allow()
    preview = run(conn.preview_change([op], {"revision": record["revision"]}))
    assert any("user.rules" in note for note in preview["notes"])
    assert host.verbs == []
    applied = run(conn.apply_change([op], record["revision"], None))
    assert host.payloads[2]["persist"] is False
    assert "atrium:chg_31" in host.user_rules and "op0" in host.user_rules
    assert ops_applied(pulled(host), [op]) == []
    fresh = HostFirewallConnector(CONFIG, SECRETS, host.transport)
    confirmed = run(fresh.confirm_change(applied["token"]))
    assert host.payloads[-1]["persist"] is False
    assert any("cancelled" in note for note in confirmed["notes"])
    existing = LinuxHost("ufw", user_rules=(
        "### tuple ### allow tcp 443 10.2.2.2/32 any 10.1.1.0/24 in comment=web\n"))
    conn = connect(existing)
    current = run(conn.pull("network"))[0]
    target = next(rule for rule in current["rules"] if rule["vendor_ref"] == "ufw:4:1")
    run(conn.apply_change([{"op": "disable_rules", "rules": [{"id": target["id"], "vendor_ref": target["vendor_ref"]}]}],
                          current["revision"], None))
    assert existing.user_rules.lstrip().startswith("#")
    assert "### tuple ###" in existing.user_rules
    disabled = pulled(existing)
    assert any(rule["vendor_ref"] == "ufw:4:1" and rule["enabled"] is False for rule in disabled["rules"])


def test_firewalld_runtime_until_confirm():
    host = LinuxHost("firewalld", rich=[RICH])
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    op = allow(zone="public")
    assert run(conn.preview_change([op], {"revision": record["revision"]}))["problems"] == []
    assert host.verbs == []
    applied = run(conn.apply_change([op], record["revision"], None))
    assert host.payloads[2]["persist"] is False
    assert ops_applied(pulled(host), [op]) == []
    run(HostFirewallConnector(CONFIG, SECRETS, host.transport).confirm_change(applied["token"]))
    assert host.payloads[-1]["persist"] is True
    rich = next(rule for rule in record["rules"] if rule["vendor_ref"].startswith("fw:") and ":svc:" not in rule["vendor_ref"])
    current = pulled(host)
    # the rich rule is still the one from before the allow; disable it in place
    disable = {"op": "disable_rules", "rules": [{"id": rich["id"], "vendor_ref": rich["vendor_ref"]}]}
    # revision moved because the allow landed; re-read
    current_rev = current["revision"]
    run(connect(host).apply_change([disable], current_rev, None))
    assert RICH not in host.rich
    after = pulled(host)
    assert any(not rule["enabled"] and rich["vendor_ref"] in rule["vendor_ref"] for rule in after["rules"])


def test_backup_restore_refuses_flush_ruleset():
    host = LinuxHost("nftables")
    conn = connect(host)
    saved = run(conn.backup())
    assert saved["format"] == "json"
    assert host.verbs == []
    assert "flush ruleset" not in saved["content"]
    restored = run(conn.restore_backup(backup_of(saved["content"])))
    assert restored["restored"] is True
    assert "confirm" in host.verbs and "arm-revert" in host.verbs
    with pytest.raises(ChangeError) as exc:
        run(conn.restore_backup(backup_of(json.dumps({"manager": "nftables", "table_text": "flush ruleset\n"}))))
    assert exc.value.code == "invalid"
    assert host.verbs.count("confirm") == 1
