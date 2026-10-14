"""Linux host firewall connector (hub/connectors/hostfw.py): a fake host behind SSH (nftables, ufw, firewalld and the
atrium-fw wrapper emulated), the real wrapper script run under /bin/sh with stub tools, and - where this machine
allows it - real nft in a throwaway network namespace.

The nft JSON the fake prints follows what nft 1.0.9 printed for the same rules (checked by
``test_fake_nft_matches_real_nft`` when ``unshare`` and ``nft`` are available). ``ip -j`` / ``ss`` answers are
shaped after the keys documented in iproute2 (research S37); the ufw tuple and firewalld listing formats follow the
upstream sources the connector cites.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from hub.connectors.base import normalize
from hub.connectors.hostfw import (NFT_TABLE_TEMPLATE, WRAPPER_SCRIPT, AtriumTable, HostFirewallConnector, NftRuleset,
                                   nft_rule_line, parse_probe, parse_rich_rule, parse_ss,
                                   parse_ufw_tuples, rich_rule_text)
from hub.connectors.netmodel import Backup, ChangeError, inverse_ops, ops_applied, ops_reverted, parse_ops
from hub.execution.sshfake import FakeSshTransport
from hub.integration.connections import clean_config

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-host-key-material-0123456789\n-----END OPENSSH PRIVATE KEY-----"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTestsOnly0123456789abcdefgh"
NFT, UFW, FWCMD, IP, SS = "/usr/sbin/nft", "/usr/sbin/ufw", "/usr/bin/firewall-cmd", "/usr/bin/ip", "/usr/bin/ss"
WRAP = "/usr/local/sbin/atrium-fw"
LOCKED = "10.0.20.5:22: no answer within 10s"
CAN_UNSHARE = bool(shutil.which("unshare") and shutil.which("nft") and hasattr(os, "geteuid") and os.geteuid() == 0)


def run(coro):
    return asyncio.run(coro)


def netns(script: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["unshare", "-n", "sh", "-c", script], cwd=cwd, capture_output=True, text=True, timeout=60)


@pytest.fixture(scope="module")
def real_nft(tmp_path_factory) -> bool:
    if not CAN_UNSHARE:
        return False
    probe = netns("nft -f - <<'E'\ntable inet t {}\nE\nnft list tables", tmp_path_factory.mktemp("probe"))
    return probe.returncode == 0 and "table inet t" in probe.stdout


# --------------------------------------------------------------------------------------
# a fake nft: ruleset text -> the JSON nft 1.0.9 prints for it
# --------------------------------------------------------------------------------------

TOKENS = re.compile(r'"[^"]*"|!=|[{},]|[^\s{},]+')


def _addr(value: str) -> Any:
    if "/" in value:
        address, length = value.split("/")
        if length == ("128" if ":" in address else "32"):
            return address
        return {"prefix": {"addr": address, "len": int(length)}}
    return value


def _port(value: str) -> Any:
    return {"range": [int(x) for x in value.split("-")]} if "-" in value else int(value)


def nft_expr(line: str) -> tuple[list[dict[str, Any]], str | None]:
    tokens, i, expr, comment = TOKENS.findall(line), 0, [], None

    def take():
        nonlocal i
        if tokens[i] == "{":
            items, i = [], i + 1
            while tokens[i] != "}":
                if tokens[i] != ",":
                    items.append(tokens[i])
                i += 1
            i += 1
            return items
        i += 1
        return tokens[i - 1]

    def match(left, value, convert, op="=="):
        right = {"set": [convert(v) for v in value]} if isinstance(value, list) else convert(value)
        expr.append({"match": {"op": op, "left": left, "right": right}})

    while i < len(tokens):
        token = tokens[i]
        if token in ("iifname", "oifname"):
            i += 1
            match({"meta": {"key": token}}, take(), lambda v: v.strip('"'))
        elif token in ("ip", "ip6") and tokens[i + 1] in ("saddr", "daddr"):
            field, op = tokens[i + 1], "=="
            i += 2
            if tokens[i] == "!=":
                op, i = "!=", i + 1
            match({"payload": {"protocol": token, "field": field}}, take(), lambda v: v if v.startswith("@") else _addr(v), op)
        elif token in ("tcp", "udp") and tokens[i + 1] == "dport":
            i += 2
            match({"payload": {"protocol": token, "field": "dport"}}, take(), lambda v: v if v.startswith("@") else _port(v))
        elif token == "meta" and tokens[i + 1] == "l4proto":
            i += 2
            match({"meta": {"key": "l4proto"}}, take(), str)
        elif token == "ct" and tokens[i + 1] == "state":
            states, i = [tokens[i + 2]], i + 3
            while i < len(tokens) and tokens[i] == ",":
                states.append(tokens[i + 1])
                i += 2
            expr.append({"match": {"op": "in", "left": {"ct": {"key": "state"}},
                                   "right": states if len(states) > 1 else states[0]}})
        elif token == "counter":
            entry, i = {"packets": 0, "bytes": 0}, i + 1
            if i < len(tokens) and tokens[i] == "packets":
                entry, i = {"packets": int(tokens[i + 1]), "bytes": int(tokens[i + 3])}, i + 4
            expr.append({"counter": entry})
        elif token == "log":
            entry, i = {}, i + 1
            if i < len(tokens) and tokens[i] == "prefix":
                entry, i = {"prefix": tokens[i + 1].strip('"')}, i + 2
            expr.append({"log": entry})
        elif token in ("accept", "drop"):
            expr.append({token: None})
            i += 1
        elif token == "reject":
            i += 1
            if tokens[i:i + 3] == ["with", "tcp", "reset"]:
                expr.append({"reject": {"type": "tcp reset"}})
                i += 3
            else:
                expr.append({"reject": None})
        elif token == "jump":
            expr.append({"jump": {"target": tokens[i + 1]}})
            i += 2
        elif token == "comment":
            comment, i = tokens[i + 1].strip('"'), i + 2
        else:
            raise AssertionError(f"the fake nft cannot read {token!r} in {line!r}")
    return expr, comment


def nft_normal(line: str) -> str:
    """How nft lists a rule it was given: host prefixes dropped, counters shown."""
    line = re.sub(r"\b(\d+\.\d+\.\d+\.\d+)/32\b", r"\1", line)
    line = re.sub(r"\b([0-9a-f:]+:[0-9a-f:]*)/128\b", r"\1", line)
    return re.sub(r"\bcounter(?! packets)", "counter packets 0 bytes 0", line)


def table_blocks(text: str) -> list[list[str]]:
    blocks, current = [], None
    for line in text.splitlines():
        if line.startswith("table "):
            current = [line]
            blocks.append(current)
        elif current is not None:
            current.append(line)
            if line == "}":
                current = None
    return blocks


def ruleset_json(text: str) -> dict[str, Any]:
    items: list[dict[str, Any]] = [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3",
                                                 "json_schema_version": 1}}]
    rules = []
    for number, block in enumerate(table_blocks(text), 1):
        _, family, name, _ = block[0].split()
        items.append({"table": {"family": family, "name": name, "handle": number}})
        handle, i = 0, 1
        while i < len(block) - 1:
            line = block[i]
            chain = re.match(r"^\tchain (\S+) \{$", line)
            nset = re.match(r"^\tset (\S+) \{$", line)
            i += 1
            if not (chain or nset):
                continue
            body = []
            while block[i] != "\t}":
                body.append(block[i].strip())
                i += 1
            i += 1
            handle += 1
            if nset:
                obj = {"family": family, "name": nset.group(1), "table": name, "handle": handle}
                for entry in body:
                    if entry.startswith("type "):
                        obj["type"] = entry.split()[1]
                    elif entry.startswith("flags "):
                        obj["flags"] = [f.strip() for f in entry[6:].split(",")]
                    elif entry.startswith("elements = {"):
                        values = [v.strip() for v in entry[len("elements = {"):].rstrip("}").split(",")]
                        obj["elem"] = [int(v) if v.isdigit() else _addr(v) for v in values]
                items.append({"set": obj})
                continue
            obj = {"family": family, "table": name, "name": chain.group(1), "handle": handle}
            if body and body[0].startswith("type "):
                spec = re.match(r"type (\w+) hook (\w+) priority (\S+); policy (\w+);", body.pop(0))
                prio = {"filter": 0, "dstnat": -100, "srcnat": 100}.get(spec.group(3))
                obj.update(type=spec.group(1), hook=spec.group(2), prio=prio if prio is not None else int(spec.group(3)),
                           policy=spec.group(4))
            items.append({"chain": obj})
            for entry in body:
                handle += 1
                expr, comment = nft_expr(entry)
                rule = {"family": family, "table": name, "chain": chain.group(1), "handle": handle, "expr": expr}
                if comment is not None:
                    rule["comment"] = comment
                rules.append({"rule": rule})
    return {"nftables": items + rules}


# --------------------------------------------------------------------------------------
# the fake host
# --------------------------------------------------------------------------------------

IP_ADDR = [
    {"ifindex": 1, "ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"], "mtu": 65536, "operstate": "UNKNOWN",
     "link_type": "loopback", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
    {"ifindex": 2, "ifname": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "mtu": 1500,
     "operstate": "UP", "link_type": "ether",
     "addr_info": [{"family": "inet", "local": "10.0.20.5", "prefixlen": 24, "scope": "global"},
                   {"family": "inet6", "local": "2001:db8:20::5", "prefixlen": 64, "scope": "global"},
                   {"family": "inet6", "local": "fe80::5", "prefixlen": 64, "scope": "link"}]},
    {"ifindex": 3, "ifname": "eth1", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "operstate": "UP",
     "link_type": "ether", "addr_info": [{"family": "inet", "local": "203.0.113.10", "prefixlen": 28, "scope": "global"}]},
    {"ifindex": 4, "ifname": "eth0.30", "link": "eth0", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
     "operstate": "UP", "link_type": "ether", "linkinfo": {"info_kind": "vlan", "info_data": {"protocol": "802.1Q", "id": 30}},
     "addr_info": [{"family": "inet", "local": "10.0.30.5", "prefixlen": 24, "scope": "global"}]},
    {"ifindex": 5, "ifname": "veth12ab", "flags": ["UP"], "operstate": "UP", "link_type": "ether", "addr_info": []},
    {"ifindex": 6, "ifname": "docker0", "flags": ["NO-CARRIER", "BROADCAST", "MULTICAST", "UP"], "operstate": "DOWN",
     "link_type": "ether", "addr_info": [{"family": "inet", "local": "172.17.0.1", "prefixlen": 16, "scope": "global"}]},
]
ROUTES = [{"dst": "default", "gateway": "203.0.113.1", "dev": "eth1", "protocol": "static", "flags": []}]
LISTEN = ("udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*\n"
          "tcp   LISTEN 0      4096         0.0.0.0:22        0.0.0.0:*\n"
          "tcp   LISTEN 0      511             [::]:80           [::]:*\n"
          "tcp   LISTEN 0      244        10.0.20.5:5432      0.0.0.0:*\n")

NFT_RULESET = """table inet atrium {
\tset blocked {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 192.0.2.0/24, 198.51.100.7 }
\t}

\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tct state established,related accept
\t\tct state invalid drop
\t\tiifname "lo" accept
\t\ttcp dport 22 accept comment "ssh"
\t\tip saddr @blocked drop
\t\tiifname "eth0" ip saddr 10.0.10.0/24 ip daddr 10.0.20.5 tcp dport 5432 counter packets 12 bytes 840 accept comment "atrium:chg_old.0 Postgres from LAN"
\t\tip saddr 10.0.10.0/24 jump admin
\t}

\tchain admin {
\t\ttcp dport 9090 accept comment "cockpit <b>from</b> LAN"
\t}

\tchain parked {
\t\tiifname "eth0" ip saddr 10.0.30.0/24 ip daddr 10.0.20.5 tcp dport 80 counter packets 0 bytes 0 accept comment "atrium:chg_park.0 web from guests"
\t}
}
table ip filter {
\tchain INPUT {
\t\ttype filter hook input priority filter; policy accept;
\t\ttcp dport 8080 accept
\t}

\tchain prerouting {
\t\ttype nat hook prerouting priority dstnat; policy accept;
\t}
}
"""


def tuple_line(body: str, comment: str = "") -> str:
    return f"### tuple ### {body}" + (f" comment={comment.encode().hex()}" if comment else "")


def ufw_file(tuples: list[tuple[str, str]]) -> str:
    return "*filter\n:ufw-user-input - [0:0]\n### RULES ###\n\n" + "".join(
        tuple_line(b, c) + "\n-A ufw-user-input -j ACCEPT\n\n" for b, c in tuples) + "### END RULES ###\nCOMMIT\n"


UFW_V4 = [("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in", ""),
          ("allow_log tcp 5432 10.0.20.5 any 10.0.10.0/24 in_eth0", "atrium:chg_old.0 Postgres from LAN"),
          ("limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 in", ""),
          ("deny any any 0.0.0.0/0 any 192.0.2.0/24 in", "block <script>"),
          ("route:allow tcp 443 10.0.20.0/24 any 10.0.10.0/24 in_eth0!out_eth1", ""),
          ("allow udp 53 0.0.0.0/0 any 0.0.0.0/0 out", "")]
UFW_V6 = [("allow tcp 22 ::/0 any ::/0 OpenSSH - in", "")]
UFW_STATUS = ("Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
              "New profiles: skip\n\nTo                         Action      From\n")
UFW_DEFAULTS = 'IPV6=yes\nDEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="DROP"\n'

FW_SERVICES = {"ssh": '<service><short>SSH</short><port protocol="tcp" port="22"/></service>',
               "dhcpv6-client": '<service><port protocol="udp" port="546"/></service>',
               "netbios-ns": '<service><port protocol="udp" port="137"/></service>',
               "samba-client": '<service><include service="netbios-ns"/><port protocol="udp" port="138"/></service>',
               "evil": '<!DOCTYPE x [<!ENTITY a "b">]><service><port protocol="tcp" port="1"/></service>'}


def fw_zone(name: str, **settings: Any) -> dict[str, Any]:
    zone = {"target": "default", "interfaces": [], "sources": [], "services": [], "ports": [], "protocols": [],
            "rich": [], "forward_ports": [], "masquerade": False, "icmp_blocks": []}
    zone.update(settings)
    zone["perm_rich"] = list(zone["rich"])
    return zone


class FakeHost(FakeSshTransport):
    """A Linux host behind SSH running `manager`. Its clock is `now`; `tick()` runs the revert timers whose time has
    come. `sudo_allowed` lists what sudo permits ("read", "wrapper")."""

    def __init__(self, manager: str = "nftables"):
        super().__init__(handler=self.handle)
        self.manager = manager
        self.now = [1000.0]
        self.uid = "1001"
        self.sudo_allowed = {"read", "wrapper"}
        self.wrapper_version = "1"
        self.systemd = True
        self.ssh_connection = "10.0.20.100 50123 10.0.20.5 22"
        self.ip_addr = copy.deepcopy(IP_ADDR)
        self.locked = False
        self.lockout_after_apply = False
        self.apply_breaks = False
        self.events: list[str] = []
        self.jobs: dict[str, dict[str, Any]] = {}
        self.parked: list[str] = []
        self.persisted: str | None = None
        self.nft = NFT_RULESET
        self.ufw = {"v4": list(UFW_V4), "v6": list(UFW_V6)}
        self.ufw_active = True
        self.fw_zones = {
            "public": fw_zone("public", interfaces=["eth1"], services=["ssh", "dhcpv6-client"], ports=["8443/tcp"],
                              rich=['rule family="ipv4" source address="192.0.2.0/24" drop',
                                    'rule priority="-5" family="ipv4" source address="198.51.100.7" reject',
                                    'rule family="ipv4" source ipset="admins" service name="ssh" accept']),
            "internal": fw_zone("internal", interfaces=["eth0", "eth0.30"], services=["ssh", "samba-client", "mystery"],
                                rich=['rule family="ipv4" source address="10.0.10.0/24" destination address='
                                      '"10.0.20.5" port port="5432" protocol="tcp" log prefix="atrium:chg_old.0 " '
                                      'level="info" accept']),
            "trusted": fw_zone("trusted", target="ACCEPT", sources=["10.0.99.0/24"]),
            "drop": fw_zone("drop", target="DROP"),
        }
        self.fw_default = "public"
        self.fw_policies = {"allow-host-ipv6": {"ingress": ["ANY"], "egress": ["HOST"], "priority": -15000,
                                                "target": "CONTINUE", "rich": ['rule family="ipv6" icmp-type name="neighbour-advertisement" accept']}}

    # -- plumbing --------------------------------------------------------------------------------

    def tick(self) -> None:
        for sid, job in self.jobs.items():
            if job["state"] == "armed" and self.now[0] >= job["deadline"]:
                job["state"] = "fired"
                self.restore(job)
                self.locked = False
                self.events.append(f"fired:{sid}")

    @contextlib.asynccontextmanager
    async def session(self, target):
        self.tick()
        self.fail_connect = LOCKED if self.locked else None if self.fail_connect == LOCKED else self.fail_connect
        async with super().session(target) as session:
            yield session

    def commands(self) -> list[str]:
        return [c.command for _, c in self.calls]

    def probe(self) -> str:
        paths = {"nftables": ["nft"], "ufw": ["ufw", "nft"], "firewalld": ["firewall-cmd", "nft"]}[self.manager]
        lines = [f"path.{t}={p}" for t, p in (("nft", NFT), ("ufw", UFW), ("firewall-cmd", FWCMD)) if t in paths]
        lines += [f"path.ip={IP}", f"path.ss={SS}"] + (["path.systemd-run=/usr/bin/systemd-run"] if self.systemd else [])
        lines += [f"uid={self.uid}", "host=web01", "kernel=6.8.0-45-generic", f"ssh={self.ssh_connection}",
                  f"firewalld={'active' if self.manager == 'firewalld' else 'inactive'}",
                  'os.ID=ubuntu', 'os.VERSION_ID="24.04"', 'os.PRETTY_NAME="Ubuntu 24.04.1 LTS"', "docker=yes"]
        if self.manager == "ufw":
            lines.append(f"ufw.ENABLED={'yes' if self.ufw_active else 'no'}")
        return "\n".join(lines) + "\n"

    def handle(self, command: str, stdin: str | None, session) -> Any:
        if command == "/bin/sh -s" and stdin and stdin.startswith("for t in nft"):
            return self.probe()
        if command == "/bin/sh -s" and stdin and "atrium-service" in stdin:
            return "".join(f"### atrium-service {n}.xml\n{x}\n" for n, x in FW_SERVICES.items())
        if command == f"{IP} -j route show default":
            return json.dumps(ROUTES)
        if command == f"{IP} -j -d addr show":
            return json.dumps(self.ip_addr)
        if command == f"{SS} -H -tuln":
            return LISTEN
        if command.startswith("sudo -n "):
            argv = command.split()[2:]
            kind = "wrapper" if argv[0] == WRAP else "read"
            if kind not in self.sudo_allowed:
                return 1, "", "sudo: a password is required\n"
            return self.wrapper(argv[1:], stdin) if kind == "wrapper" else self.root(argv, command)
        if command == "cat /etc/default/ufw":
            return UFW_DEFAULTS
        return 127, "", f"sh: unexpected command {command!r}"

    def root(self, argv: list[str], command: str) -> Any:
        if argv == [NFT, "-j", "list", "ruleset"]:
            return json.dumps(ruleset_json(self.nft))
        if argv == [NFT, "list", "ruleset"]:
            return self.nft
        if argv == [UFW, "status", "verbose"]:
            return UFW_STATUS if self.ufw_active else "Status: inactive\n"
        if argv == [UFW, "version"]:
            return "ufw 0.36.2\nCopyright 2008-2023 Canonical Ltd.\n"
        if argv[:1] == ["cat"] and argv[1] in ("/etc/ufw/user.rules", "/etc/ufw/user6.rules"):
            return ufw_file(self.ufw["v4" if argv[1].endswith("user.rules") else "v6"])
        if argv[:1] == ["cat"] and argv[1].startswith("/etc/ufw/"):
            return f"# {argv[1]}\n*filter\nCOMMIT\n"
        if argv[0] == FWCMD:
            return self.firewall_cmd(argv[1:])
        return 127, "", f"sudo: {argv[0]}: command not found"

    # -- firewalld -----------------------------------------------------------------------------

    def fw_listing(self, permanent: bool = False) -> str:
        out = []
        for name, z in self.fw_zones.items():
            attrs = (["default"] if name == self.fw_default else []) + \
                (["active"] if not permanent and (z["interfaces"] or z["sources"]) else [])
            out.append(name + (f" ({', '.join(attrs)})" if attrs else ""))
            rich = z["perm_rich"] if permanent else z["rich"]
            out += [f"  target: {z['target']}", "  ingress-priority: 0", "  egress-priority: 0",
                    "  icmp-block-inversion: no", f"  interfaces: {' '.join(z['interfaces'])}",
                    f"  sources: {' '.join(z['sources'])}", f"  services: {' '.join(sorted(z['services']))}",
                    f"  ports: {' '.join(z['ports'])}", f"  protocols: {' '.join(z['protocols'])}", "  forward: yes",
                    f"  masquerade: {'yes' if z['masquerade'] else 'no'}", "  forward-ports: ", "  source-ports: ",
                    f"  icmp-blocks: {' '.join(z['icmp_blocks'])}", "  rich rules: " + ("\n\t" if rich else "")
                    + "\n\t".join(rich), ""]
        return "\n".join(out) + "\n"

    def firewall_cmd(self, args: list[str]) -> Any:
        if args == ["--state"]:
            return "running\n"
        if args == ["--version"]:
            return "2.1.1\n"
        if args == ["--list-all-zones"]:
            return self.fw_listing()
        if args == ["--permanent", "--list-all-zones"]:
            return self.fw_listing(permanent=True)
        if args == ["--list-all-policies"]:
            out = []
            for name, p in self.fw_policies.items():
                out += [f"{name} (active)", "  disable: no", f"  priority: {p['priority']}", f"  target: {p['target']}",
                        f"  ingress-zones: {' '.join(p['ingress'])}", f"  egress-zones: {' '.join(p['egress'])}",
                        "  services: ", "  ports: ", "  protocols: ", "  masquerade: no", "  forward-ports: ",
                        "  source-ports: ", "  icmp-blocks: ", "  rich rules: \n\t" + "\n\t".join(p["rich"]), ""]
            return "\n".join(out) + "\n"
        return 2, "", "usage error"

    def fw_rule(self, permanent: bool, zone: str, verb: str, rule: str) -> None:
        rules = self.fw_zones[zone]["perm_rich" if permanent else "rich"]
        if verb == "add" and rule not in rules:
            rules.append(rule)
        elif verb == "remove":
            assert rule in rules, f"remove of a rule that is not there: {rule}"
            rules.remove(rule)

    # -- ufw -----------------------------------------------------------------------------------

    def ufw_cmd(self, verb: str, fields: list[str]) -> None:
        _, iface, log, proto, src, dst, ports, comment = fields
        strip = lambda a: re.sub(r"/(32|128)$", "", a)
        body = f"allow{'_log' if log == '1' else ''} {proto} {ports} {strip(dst)} any {strip(src)} in_{iface}"
        family = "v6" if ":" in src else "v4"
        if verb == "prepend":
            if all(b != body for b, _ in self.ufw[family]):
                self.ufw[family].insert(0, (body, comment))
        else:
            match = [t for t in self.ufw[family] if t == (body, comment)]
            assert match, f"ufw: Could not delete non-existent rule {body}"
            self.ufw[family].remove(match[0])

    # -- the wrapper -----------------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        atrium = next(("\n".join(b) for b in table_blocks(self.nft) if b[0] == "table inet atrium {"), None)
        return {"nft": atrium, "ufw": copy.deepcopy(self.ufw), "parked": list(self.parked)}

    def restore(self, job: dict[str, Any]) -> None:
        pre = job["pre"]
        if job["manager"] == "nftables":
            self.replace_atrium(pre["nft"])
        elif job["manager"] == "ufw":
            self.ufw = copy.deepcopy(pre["ufw"])
        else:  # firewall-cmd --reload: the permanent configuration becomes the runtime one
            for zone in self.fw_zones.values():
                zone["rich"] = list(zone["perm_rich"])
        self.parked = list(pre["parked"])

    def replace_atrium(self, text: str) -> None:
        blocks = ["\n".join(b) for b in table_blocks(self.nft) if b[0] != "table inet atrium {"]
        lines = [nft_normal(l) for l in text.rstrip("\n").split("\n")]
        self.nft = "\n".join(["\n".join(lines)] + blocks) + "\n"

    def wrapper(self, args: list[str], stdin: str | None) -> Any:
        verb = args[0] if args else ""
        job = self.jobs.get(args[1]) if len(args) > 1 else None
        if verb == "version":
            return f"atrium-fw {self.wrapper_version}\n"
        if verb == "check":
            return (f"version={self.wrapper_version}\nsystemd_run={'yes' if self.systemd else 'no'}\nnft=yes\n"
                    f"atrium_table=yes\npersist=yes\nspool=ok\n")
        if verb == "parked":
            return "".join(f"{p}\n" for p in self.parked)
        if verb == "table":
            atrium = self.snapshot()["nft"]
            return (atrium + "\n") if atrium else (1, "", "Error: No such file or directory")
        if verb == "arm":
            sid, window, manager = args[1:]
            assert re.fullmatch(r"[0-9a-f]{16}", sid) and manager == self.manager
            if not self.systemd:
                return 2, "", "atrium-fw: systemd-run is missing: changes need the automatic revert"
            self.jobs[sid] = {"state": "armed", "deadline": self.now[0] + int(window), "manager": manager,
                              "pre": self.snapshot(), "lines": []}
            self.events.append("arm")
            return "armed\n"
        if verb == "apply":
            if job is None or job["state"] != "armed":
                return 2, "", "atrium-fw: not armed: the automatic revert must be armed first"
            self.events.append("apply")
            if self.apply_breaks:
                if self.manager == "ufw":  # the first step went through, then something failed
                    self.ufw_cmd("prepend", stdin.splitlines()[0].split("\t")[1:])
                return 2, "", "atrium-fw: a step failed"
            if self.manager == "nftables":
                assert stdin.startswith("table inet atrium {\n") and stdin.endswith("}\n")
                self.replace_atrium(stdin)
            else:
                for line in stdin.splitlines():
                    fields = line.split("\t")
                    job["lines"].append(fields)
                    if self.manager == "ufw":
                        verb_, key = fields[0], fields[1]
                        self.ufw_cmd("delete" if verb_ == "park" else "prepend", fields[1:])
                        if verb_ == "park":
                            self.parked.append("\t".join(["ufw", *fields[1:]]))
                        elif verb_ == "unpark":
                            self.parked = [p for p in self.parked if p.split("\t")[1] != key]
                    else:
                        verb_, key, zone, rule = fields
                        self.fw_rule(False, zone, "remove" if verb_ == "park" else "add", rule)
                        if verb_ == "park":
                            self.parked.append("\t".join(["firewalld", key, zone, rule]))
                        elif verb_ == "unpark":
                            self.parked = [p for p in self.parked if p.split("\t")[1] != key]
            if self.lockout_after_apply:
                self.locked = True
            return "applied\n"
        if verb == "confirm":
            if job is None:
                return "missing\n"
            if job["state"] != "armed":
                return job["state"] + "\n"
            job["state"] = "confirmed"
            self.events.append("confirm")
            if self.manager == "nftables":
                self.persisted = self.snapshot()["nft"]
            elif self.manager == "firewalld":
                for verb_, key, zone, rule in job["lines"]:
                    self.fw_rule(True, zone, "remove" if verb_ == "park" else "add", rule)
            return "confirmed\npersist=" + ("immediate" if self.manager == "ufw" else "ok") + "\n"
        if verb in ("rollback", "revert-now"):
            if job is None:
                return "missing\n"
            if job["state"] != "armed":
                return job["state"] + "\n"
            job["state"] = "rolled" if verb == "rollback" else "fired"
            self.restore(job)
            self.events.append(verb)
            return "reverted\n"
        if verb == "status":
            return (job or {}).get("state", "missing") + "\n"
        if verb == "restore":  # restore SID SECONDS MANAGER: armed like a change, saved only by confirm
            if len(args) != 4:
                return 2, "", "atrium-fw: usage: restore SID SECONDS MANAGER < content"
            sid, window, manager = args[1:]
            assert re.fullmatch(r"[0-9a-f]{16}", sid) and manager == self.manager
            if manager == "firewalld":
                return 2, "", "atrium-fw: restoring firewalld is not supported"
            if not self.systemd:
                return 2, "", "atrium-fw: systemd-run is missing: changes need the automatic revert"
            self.jobs[sid] = {"state": "armed", "deadline": self.now[0] + int(window), "manager": manager,
                              "pre": self.snapshot(), "lines": []}
            self.events.append(f"restore:{manager}")
            if manager == "nftables":
                assert stdin.startswith("table inet atrium {\n")
                self.replace_atrium(stdin)
            else:
                sections = dict(re.findall(r"### atrium-fw file (\S+)\n(.*?)(?=### atrium-fw|\Z)", stdin, re.S))
                self.ufw = {"v4": [(t["body"], t["comment"]) for t in parse_ufw_tuples(sections["user.rules"], False)],
                            "v6": [(t["body"], t["comment"]) for t in parse_ufw_tuples(sections["user6.rules"], True)]}
            if self.lockout_after_apply:
                self.locked = True
            return "restored\n"
        return 2, "", "atrium-fw: unknown verb"


def connector(fake: FakeHost, **config: Any) -> HostFirewallConnector:
    """A new instance (= a new SSH connection), as the hub builds one per call."""
    return HostFirewallConnector(clean_config(HostFirewallConnector, {"host": "10.0.20.5", "host_key": HOST_KEY,
                                                                      **config}), {"private_key": KEY}, fake)


def snapshot(fake: FakeHost, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


@pytest.fixture
def host(monkeypatch):
    def make(manager: str = "nftables") -> FakeHost:
        fake = FakeHost(manager)
        monkeypatch.setattr(HostFirewallConnector, "clock", staticmethod(lambda: fake.now[0]))
        return fake
    return make


def allow(zone: str = "eth0", src: str = "10.0.10.0/24", dst: str = "10.0.20.5/32", ports: str = "443",
          proto: str = "tcp", marker: str = "atrium:chg_7", **extra: Any) -> list[dict[str, Any]]:
    service = {"proto": proto, **({"ports": ports} if proto != "icmp" else {})}
    return parse_ops([{"op": "allow", "source": {"zone": zone, "cidrs": src.split(",")},
                       "destination": {"zone": extra.pop("dst_zone", zone), "cidrs": dst.split(",")},
                       "services": [service], "description": "Users to intranet", "marker": marker, **extra}])


def toggle(op: str, *keys: str) -> list[dict[str, Any]]:
    return parse_ops([{"op": op, "rules": [{"id": k, "vendor_ref": k} for k in keys]}])


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_small_parsers():
    facts = parse_probe("path.nft=/usr/sbin/nft\npath.ufw=../../evil\nuid=0\nssh=10.0.0.9 5000 10.0.0.1 2222\n"
                        'os.PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nnoise\n')
    assert facts["paths"] == {"nft": "/usr/sbin/nft"} and facts["uid"] == "0"
    assert facts["ssh"] == {"client_ip": "10.0.0.9", "client_port": 5000, "server_ip": "10.0.0.1", "server_port": 2222}
    assert facts["os"]["PRETTY_NAME"] == "Debian GNU/Linux 12 (bookworm)"
    assert parse_ss(LISTEN) == {"all": ["tcp/22", "tcp/80"], "specific": ["tcp/5432"], "local": ["udp/53"]}
    rich = parse_rich_rule('rule priority="-1" family="ipv4" source NOT address="10.0.0.0/8" destination address='
                           '"10.0.20.5" port port="8000-8080" protocol="tcp" log prefix="atrium:x.0 " level="info" '
                           'limit value="1/m" burst=5 accept')
    assert rich["priority"] == -1 and rich["source"] == {"kind": "address", "value": "10.0.0.0/8", "negate": True}
    assert rich["element"] == {"type": "port", "port": "8000-8080", "protocol": "tcp"}
    assert rich["log"]["prefix"] == "atrium:x.0 " and rich["action"] == "accept"
    assert parse_rich_rule('rule family="ipv4" source address="1.2.3.4" bogus accept') is None
    assert parse_rich_rule("not a rule") is None
    tuples = parse_ufw_tuples(tuple_line("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", "héllo") + "\n"
                              "### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 comment=6\n", False)
    assert tuples[0]["comment"] == "héllo" and tuples[1]["comment"] == ""  # odd hex: the last digit dropped (ufw)


def test_reads_nftables(host):
    fake = host("nftables")
    record = snapshot(fake)
    assert record["kind"] == "host" and record["external_id"] == "web01"
    assert record["device"] == {"vendor": "Linux", "model": "Ubuntu 24.04.1 LTS", "version":
                                "nftables 1.0.9, kernel 6.8.0-45-generic", "hostname": "web01",
                                "management_address": "10.0.20.5", "serial": ""}
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"eth0", "eth1", "eth0.30", "docker0"}  # loopback and veth pairs left out
    assert ifaces["eth0"]["subnets"] == ["10.0.20.0/24", "2001:db8:20::/64"] and ifaces["eth0"]["role"] == "lan"
    assert ifaces["eth1"]["role"] == "wan"  # the default route with a public address
    assert ifaces["eth0.30"]["vlan"] == 30 and not ifaces["docker0"]["enabled"]
    assert "fe80::5" not in record["self_addresses"] and "10.0.20.5" in record["self_addresses"]
    rules = {r["id"]: r for r in record["rules"]}
    order = [r["id"] for r in record["rules"]]
    lo = next(r for r in record["rules"] if r["interfaces"] == ["lo"])
    assert lo["id"].startswith("inet/atrium/input/c-") and lo["destination"] == {**lo["destination"], "self": True}
    ssh = next(r for r in record["rules"] if r["description"] == "ssh")
    assert ssh["services"] == [{"proto": "tcp", "ports": "22", "alias": None, "name": ""}] and ssh["source"]["any"]
    blocked = next(r for r in record["rules"] if r["source"]["aliases"])
    assert blocked["action"] == "block" and blocked["source"]["aliases"] == ["inet/atrium/blocked"]
    postgres = rules["atrium:chg_old.0"]  # Atrium's own rule: its key is its id, stable across table replacements
    assert postgres["vendor_ref"] == "atrium:chg_old.0" and postgres["marker"] == "chg_old"
    assert postgres["source"]["cidrs"] == ["10.0.10.0/24"] and postgres["destination"]["cidrs"] == ["10.0.20.5/32"]
    assert postgres["hits"] == 12 and postgres["interfaces"] == ["eth0"]
    cockpit = next(r for r in record["rules"] if "cockpit" in r["description"])  # reached through "jump admin"
    assert cockpit["source"]["cidrs"] == ["10.0.10.0/24"] and cockpit["services"][0]["ports"] == "9090"
    assert cockpit["description"] == "cockpit <b>from</b> LAN"  # device text, kept as text
    assert order.index(cockpit["id"]) > order.index("atrium:chg_old.0")
    parked = rules["atrium:chg_park.0"]
    assert parked["enabled"] is False and parked["source"]["cidrs"] == ["10.0.30.0/24"]
    other = next(r for r in record["rules"] if r["id"].startswith("ip/filter/INPUT/"))
    assert other["services"][0]["ports"] == "8080"
    assert not any(r["description"] == "" and r["action"] == "pass" and r["source"].get("any")
                   and r["destination"].get("any") for r in record["rules"])  # established/related left out
    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["inet/atrium/blocked"]["cidrs"] == ["192.0.2.0/24", "198.51.100.7/32"]
    assert record["default_policy"] == {"inbound": "block", "forward": "pass", "outbound": "pass"}
    notes = " | ".join(record["notes"])
    for expected in ("return-traffic rules", "1 NAT chains", "listening on every address: tcp/22, tcp/80",
                     "specific addresses: tcp/5432", "Docker is installed"):
        assert expected in notes, expected
    assert set(fake.commands()) == {"/bin/sh -s", f"{IP} -j route show default", f"{IP} -j -d addr show",
                                    f"{SS} -H -tuln", f"sudo -n {NFT} -j list ruleset"}


def test_revision_ignores_counters_and_follows_rules(host):
    fake = host("nftables")
    first = snapshot(fake)
    fake.nft = fake.nft.replace("packets 12 bytes 840", "packets 99 bytes 9000")
    assert snapshot(fake)["revision"] == first["revision"]
    fake.nft = fake.nft.replace("tcp dport 9090", "tcp dport 9091")
    assert snapshot(fake)["revision"] != first["revision"]


def test_reads_ufw(host):
    fake = host("ufw")
    fake.parked = ["ufw\tatrium:chg_park.0\teth0\t0\ttcp\t10.0.30.0/24\t10.0.20.5\t80\tatrium:chg_park.0 web"]
    record = snapshot(fake)
    assert record["device"]["version"].startswith("ufw 0.36.2")
    rules = record["rules"]
    assert [r["vendor_ref"].split("|")[0] for r in rules[:7]] == ["1", "2", "3", "4", "5", "6", "7"]
    openssh = rules[0]
    assert openssh["services"] == [{"proto": "tcp", "ports": "22", "alias": None, "name": "OpenSSH"}]
    assert openssh["destination"]["self"] and openssh["description"] == "app OpenSSH"
    by = {r["id"]: r for r in rules}
    postgres = by["atrium:chg_old.0"]
    assert postgres["log"] and postgres["interfaces"] == ["eth0"] and postgres["destination"]["cidrs"] == ["10.0.20.5/32"]
    assert postgres["vendor_ref"] == "2|allow_log tcp 5432 10.0.20.5 any 10.0.10.0/24 in_eth0"
    assert "rate limited" in rules[2]["description"] and rules[2]["action"] == "pass"
    deny = rules[3]
    assert deny["action"] == "block" and deny["services"] is None and deny["description"] == "block <script>"
    route = rules[4]
    assert route["interfaces"] == ["eth0"] and route["out_interfaces"] == ["eth1"] and not route["destination"].get("self")
    out = rules[5]
    assert out["direction"] == "out" and out["source"]["self"]
    assert rules[6]["id"].startswith("ufw/v6/") and rules[6]["vendor_ref"].startswith("7|")
    parked = by["atrium:chg_park.0"]
    assert parked["enabled"] is False and parked["source"]["cidrs"] == ["10.0.30.0/24"]
    assert record["default_policy"] == {"inbound": "block", "outbound": "pass", "forward": "block"}
    assert any("before.rules" in n for n in record["notes"])
    calls = len(fake.calls)
    snapshot(fake, read_only=True)  # a read-only connection never calls the wrapper
    assert not any("atrium-fw" in c.command for _, c in fake.calls[calls:])
    fake.ufw_active = False
    record = snapshot(fake, manager="ufw")
    assert record["default_policy"] == {"inbound": "pass"} and any("not active" in n for n in record["notes"])


def test_reads_firewalld(host):
    fake = host("firewalld")
    for kind in ("rich", "perm_rich"):
        fake.fw_zones["internal"][kind].append('rule family="ipv4" source address="10.0.10.0/24" masquerade')
    record = snapshot(fake)
    assert record["device"]["version"].startswith("firewalld 2.1.1")
    zones = {z["id"]: z for z in record["zones"]}
    assert set(zones) == {"public", "internal", "trusted"}  # "drop" has no interface or source: inactive
    assert zones["internal"]["interfaces"] == ["eth0", "eth0.30"] and zones["public"]["description"] == "default zone"
    rules = record["rules"]
    ids = [r["id"] for r in rules]
    assert ids[0] == "policy/allow-host-ipv6/rich/" + ids[0].split("/")[-1]  # policy with priority < 0 first
    public = [r for r in rules if r["vendor_ref"].startswith("public|")]
    assert public[0]["action"] == "reject" and public[0]["source"]["cidrs"] == ["198.51.100.7/32"]  # priority -5
    assert public[1]["action"] == "block"  # deny rich rules before services
    assert [r["id"] for r in public[2:5]] == ["public/service/dhcpv6-client", "public/service/ssh", "public/port/8443-tcp"]
    assert public[2]["services"] == [{"proto": "udp", "ports": "546", "alias": None, "name": "dhcpv6-client"}]
    assert public[1]["interfaces"] == ["eth1"] and public[1]["destination"]["self"]
    admins = next(r for r in public if r["source"]["aliases"])
    assert admins["source"]["aliases"] == ["ipset:admins"]
    by = {r["id"]: r for r in rules}
    assert by["internal/service/samba-client"]["services"] == [  # includes resolved from the service XML
        {"proto": "udp", "ports": "138", "alias": None, "name": "samba-client"},
        {"proto": "udp", "ports": "137", "alias": None, "name": "samba-client"}]
    assert by["internal/service/mystery"]["services"][0]["alias"] == "service:mystery"
    postgres = by["atrium:chg_old.0"]
    assert postgres["description"] == "atrium:chg_old.0" and postgres["marker"] == "chg_old"
    assert postgres["services"][0]["ports"] == "5432" and postgres["destination"]["cidrs"] == ["10.0.20.5/32"]
    trusted = by["trusted/target"]
    assert trusted["source"]["cidrs"] == ["10.0.99.0/24"] and trusted["services"] is None and trusted["interfaces"] == []
    assert record["default_policy"] == {"inbound": "block"}
    notes = " | ".join(record["notes"])
    assert "zone trusted: target ACCEPT" in notes and "1 inactive zones" in notes and "NAT" in notes
    assert "runtime configuration differs" not in notes
    fake.fw_zones["public"]["rich"].append('rule family="ipv4" source address="10.9.9.9" accept')
    assert "runtime configuration differs" in " | ".join(snapshot(fake)["notes"])


def test_detection_order_and_errors(host):
    fake = host("ufw")
    assert snapshot(fake)["device"]["version"].startswith("ufw")
    fake.ufw_active = False  # ufw installed but off: raw nftables
    assert snapshot(fake)["device"]["version"].startswith("nftables")
    fake = host("nftables")
    with pytest.raises(Exception, match="firewall-cmd was not found"):
        run(connector(fake, manager="firewalld").pull("network"))
    fake.sudo_allowed = {"wrapper"}
    with pytest.raises(Exception, match="sudo -n refused to list the nftables ruleset"):
        run(connector(fake).pull("network"))


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def test_test_reports_each_step(host):
    fake = host("nftables")
    result = run(connector(fake).test())
    assert result["ok"], result
    assert [c["name"] for c in result["checks"]][:6] == ["reachability", "tls", "authentication", "privileges",
                                                        "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 180}
    assert "read-only one is recommended" in detail(result, "privileges")
    assert "Ubuntu 24.04.1 LTS" in detail(result, "version") and "nftables 1.0.9 - supported" in detail(result, "version")
    assert "dead-man revert after 180 s" in detail(result, "api_features")
    assert "present, input policy drop" in detail(result, "atrium_table")
    assert "10.0.20.100" in detail(result, "management_guard") and "port 22" in detail(result, "management_guard")
    assert len(fake.sessions) == 1  # one connection for the whole test
    assert run(connector(fake, rollback_window_s=300).test())["network_write"]["window_s"] == 300
    read_only = run(connector(fake, read_only=True).test())
    assert read_only["network_write"] is None and "never called" in detail(read_only, "privileges")


def test_test_explains_why_changes_are_off(host):
    fake = host("nftables")
    fake.sudo_allowed = {"read"}  # read-only account
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None
    assert "read-only account" in detail(result, "privileges") and "sudo does not allow" in detail(result, "api_features")
    fake.sudo_allowed, fake.systemd = {"read", "wrapper"}, False
    assert "no dead-man timer" in detail(run(connector(fake).test()), "api_features")
    fake.systemd, fake.wrapper_version = True, "0"
    assert "install it again" in detail(run(connector(fake).test()), "api_features")
    fake.wrapper_version = "1"
    fake.nft = fake.nft.replace("policy drop", "policy accept", 1)
    result = run(connector(fake).test())
    assert result["network_write"] is None and "accepts by default" in detail(result, "api_features")
    fake.nft = NFT_RULESET.replace("policy accept;\n\t\ttcp dport 8080", "policy drop;\n\t\ttcp dport 8080")
    result = run(connector(fake).test())
    assert "input also dropped by default in ip filter" in detail(result, "atrium_table")
    fake.nft = NFT_RULESET.split("table ip filter")[0].replace("table inet atrium", "table inet mine")
    result = run(connector(fake).test())
    assert result["network_write"] is None and "missing" in detail(result, "atrium_table")
    fake.uid = "0"
    assert "signed in as root" in detail(run(connector(fake).test()), "privileges")
    fake.sudo_allowed = set()
    result = run(connector(fake).test())
    assert result["ok"] is False and result["checks"][-1]["name"] == "privileges"
    for message, failing in (("10.0.20.5:22: the host key is not trusted - pin it", "tls"),
                             ("10.0.20.5:22: authentication failed - check the user and key", "authentication"),
                             ("10.0.20.5:22: cannot connect (ConnectionRefusedError: refused)", "reachability")):
        fake.fail_connect = message
        result = run(connector(fake).test())
        assert result["ok"] is False and result["checks"][-1]["name"] == failing and not result["checks"][-1]["ok"]


def test_test_on_ufw_and_firewalld(host):
    for manager in ("ufw", "firewalld"):
        fake = host(manager)
        result = run(connector(fake).test())
        assert result["ok"] and result["network_write"]["rollback"] == "deadman", (manager, result)
        assert f"{manager} (detected)" == detail(result, "manager")


def test_config_validation():
    config = clean_config(HostFirewallConnector, {"host": "web01.example.net"})
    assert config["username"] == "atrium" and config["manager"] == "auto" and config["wrapper"] == WRAP
    for bad in ({"host": "-oProxyCommand=x"}, {"host": "h", "manager": "iptables"}, {"host": "h", "rollback_window_s": 30},
                {"host": "h", "wrapper": "atrium-fw"}, {"host": "h", "wrapper": "/usr/../bin/sh"},
                {"host": "h", "username": "a b"}):
        with pytest.raises(ValueError):
            clean_config(HostFirewallConnector, bad)


# --------------------------------------------------------------------------------------
# changes: nftables
# --------------------------------------------------------------------------------------


def test_nftables_apply_verify_confirm_and_revert(host):
    fake = host("nftables")
    before = snapshot(fake)
    ops = allow(ports="80,443")
    preview = run(connector(fake).preview_change(ops, before))
    assert preview["problems"] == [], preview
    assert preview["steps"][0]["position"] == "top of chain input in table inet atrium" and fake.events == []
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert fake.events == ["arm", "apply"]  # the revert timer is armed before anything is written
    sessions = {n for n, c in fake.calls if "atrium-fw arm" in c.command or "atrium-fw apply" in c.command}
    assert len(sessions) == 1  # read, arm, write and re-read on ONE connection
    assert applied["created"] == [{"op": 0, "id": "atrium:chg_7.0", "vendor_ref": "atrium:chg_7.0"}]
    assert applied["rollback_until"] == pytest.approx(fake.now[0] + 180)
    line = next(l for l in fake.nft.splitlines() if "atrium:chg_7.0" in l)
    assert line == ('\t\tiifname "eth0" ip saddr 10.0.10.0/24 ip daddr 10.0.20.5 tcp dport { 80, 443 } counter packets 0 '
                    'bytes 0 log prefix "atrium:chg_7.0 " accept comment "atrium:chg_7.0 Users to intranet"')
    assert fake.nft.split("\n")[9] == line  # top of chain input
    assert "table ip filter" in fake.nft and fake.nft.count("tcp dport 8080") == 1  # other tables untouched
    after = snapshot(fake)  # a new connection
    assert ops_applied(after, ops) == []
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]
    assert "atrium:chg_7.0" in fake.persisted
    fake.now[0] += 500
    assert ops_applied(snapshot(fake), ops) == []  # confirmed: the timer found nothing to do
    revert = inverse_ops(ops, applied)  # a later revert is a new change: the rule is parked, not deleted
    reverted = run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
    assert reverted["disabled"] == ["atrium:chg_7.0"]
    record = snapshot(fake)
    assert ops_reverted(before, record, ops) == [] and ops_applied(record, revert) == []
    assert next(r for r in record["rules"] if r["id"] == "atrium:chg_7.0")["enabled"] is False
    run(connector(fake).confirm_change(reverted["token"]))
    again = run(connector(fake).apply_change(toggle("enable_rules", "atrium:chg_park.0"), snapshot(fake)["revision"], None))
    assert again["enabled"] == ["atrium:chg_park.0"]
    assert next(r for r in snapshot(fake)["rules"] if r["id"] == "atrium:chg_park.0")["enabled"]


def test_dead_man_reverts_unconfirmed_changes(host):
    fake = host("nftables")
    before = snapshot(fake)
    ops = allow() + toggle("disable_rules", "atrium:chg_old.0")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["disabled"] == ["atrium:chg_old.0"]
    fake.now[0] += 181
    assert ops_reverted(before, snapshot(fake), ops) == []
    with pytest.raises(ChangeError) as late:
        run(connector(fake).confirm_change(applied["token"]))
    assert late.value.state == "rolled_back"


def test_rollback_and_lockout(host):
    fake = host("nftables")
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    result = run(connector(fake).rollback_change(applied["token"], None))
    assert result == {"rolled_back": True, "method": "deadman", "notes": []}
    assert ops_reverted(before, snapshot(fake), allow()) == [] and fake.events[-1] == "rollback"
    fake.lockout_after_apply = True
    applied = run(connector(fake).apply_change(allow(), snapshot(fake)["revision"], None))
    assert run(connector(fake).test())["ok"] is False  # the hub's check over a new connection fails
    with pytest.raises(ChangeError) as unreachable:
        run(connector(fake).rollback_change(applied["token"], None))
    assert unreachable.value.code == "unreachable" and "timer restores" in unreachable.value.message
    fake.now[0] += 181
    assert run(connector(fake).test())["ok"] and ops_reverted(before, snapshot(fake), allow()) == []


def test_preview_problems(host):
    fake = host("nftables")
    record = snapshot(fake)
    cases = [
        (allow(src="10.0.10.0/24,10.0.11.0/24"), "keeps these source networks as 10.0.10.0/23"),
        (allow(ports="80,81,8000-8080"), "keeps these ports as 80-81,8000-8080"),
        (allow(ports="443,80"), "ascending order"),
        (parse_ops([{"op": "allow", "source": {"zone": "eth0", "cidrs": ["10.0.10.0/24"]},
                     "destination": {"zone": "eth0", "cidrs": ["10.0.20.5/32"]},
                     "services": [{"proto": "tcp", "ports": "80"}, {"proto": "udp", "ports": "53"}],
                     "marker": "atrium:chg_7"}]), "one service per rule"),
        (allow(zone="wlan9"), "no interface 'wlan9'"),
        (allow(dst="10.0.99.0/24"), "hold none of this host's addresses"),
        (allow(src="2001:db8:10::/64", dst="2001:db8:20::5/128", proto="icmp"), "IPv4 only"),
        (allow(src="2001:db8:10::/64", dst="10.0.20.5/32"), "IPv6 networks are on one side only"),
        (allow(marker="atrium:chg_old"), "already on the host"),
        (toggle("disable_rules", "inet/atrium/input/c-0123456789ab"), "has no disabled state"),
        (toggle("disable_rules", "atrium:chg_gone.0"), "is not on the host"),
        (toggle("enable_rules", "atrium:chg_old.0"), "nothing to change"),
    ]
    for ops, expected in cases:
        problems = " | ".join(run(connector(fake).preview_change(ops, record))["problems"])
        assert expected in problems, (expected, problems)
    fake.nft = NFT_RULESET.replace("policy accept;\n\t\ttcp dport 8080", "policy drop;\n\t\ttcp dport 8080")
    problems = " | ".join(run(connector(fake).preview_change(allow(), snapshot(fake)))["problems"])
    assert "cannot override that" in problems
    fake.sudo_allowed = {"read"}
    problems = " | ".join(run(connector(fake).preview_change(allow(), snapshot(fake)))["problems"])
    assert "changes are unavailable on this host" in problems and "sudo does not allow" in problems


def test_stale_lockout_and_unsupported(host):
    fake = host("nftables")
    before = snapshot(fake)
    with pytest.raises(ChangeError) as stale:
        run(connector(fake).apply_change(allow(), "h-0000000000000000", None))
    assert stale.value.code == "stale" and fake.events == []
    # an Atrium rule that lets the hub (10.0.20.100, SSH_CONNECTION) reach sshd: never disabled
    fake.nft = fake.nft.replace('\t\tip saddr 10.0.10.0/24 jump admin', '\t\tiifname "eth0" ip saddr 10.0.20.0/24 ip daddr '
                                '10.0.20.5 tcp dport 22 counter packets 0 bytes 0 accept comment "atrium:chg_ssh.0"\n'
                                '\t\tip saddr 10.0.10.0/24 jump admin')
    record = snapshot(fake)
    with pytest.raises(ChangeError) as lockout:
        run(connector(fake).apply_change(toggle("disable_rules", "atrium:chg_ssh.0"), record["revision"], None))
    assert lockout.value.code == "lockout" and fake.events == []
    assert run(connector(fake).preview_change(toggle("disable_rules", "atrium:chg_old.0"), record))["problems"] == []
    with pytest.raises(ChangeError) as read_only:
        run(connector(fake, read_only=True).apply_change(allow(), record["revision"], None))
    assert read_only.value.code == "unsupported"
    fake.systemd = False
    with pytest.raises(ChangeError) as no_timer:
        run(connector(fake).apply_change(allow(), record["revision"], None))
    assert no_timer.value.code == "unsupported" and "dead-man" in no_timer.value.message
    assert before["revision"] != record["revision"]


def test_tokens_are_validated(host):
    fake = host("nftables")
    for token in ("", "{}", json.dumps({"v": 1, "sid": "x; reboot", "mgr": "nftables"}),
                  json.dumps({"v": 1, "sid": "0123456789abcdef", "mgr": "iptables"}),
                  json.dumps({"v": 1, "sid": "0123456789abcdef", "mgr": "ufw", "created": ["$(halt)"]})):
        with pytest.raises(ChangeError, match="Not a change token"):
            run(connector(fake).confirm_change(token))


def test_commands_never_carry_device_text(host):
    fake = host("nftables")
    fake.nft = fake.nft.replace('comment "ssh"', 'comment "$(reboot); `halt` \'x"')
    run(connector(fake).pull("network"))
    run(connector(fake).apply_change(allow(), snapshot(fake)["revision"], None))
    allowed = {"/bin/sh -s", f"{IP} -j route show default", f"{IP} -j -d addr show", f"{SS} -H -tuln",
               f"sudo -n {NFT} -j list ruleset"}
    for command in fake.commands():
        assert command in allowed or re.fullmatch(rf"sudo -n {WRAP} (check|table|parked|arm [0-9a-f]{{16}} 180 nftables|"
                                                  r"apply [0-9a-f]{16})", command), command
    stdins = [c.input for _, c in fake.calls if c.input]
    assert all("reboot" not in s or s.startswith("table inet atrium") for s in stdins)  # only as table text, on stdin


# --------------------------------------------------------------------------------------
# changes: ufw and firewalld
# --------------------------------------------------------------------------------------


def test_ufw_changes(host):
    fake = host("ufw")
    before = snapshot(fake)
    ops = allow(ports="80,443")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    sent = next(c.input for _, c in fake.calls if "atrium-fw apply" in c.command)
    assert sent == "add\tatrium:chg_7.0\teth0\t1\ttcp\t10.0.10.0/24\t10.0.20.5/32\t80,443\tatrium:chg_7.0 Users to intranet\n"
    assert fake.ufw["v4"][0] == ("allow_log tcp 80,443 10.0.20.5 any 10.0.10.0/24 in_eth0", "atrium:chg_7.0 Users to intranet")
    after = snapshot(fake)
    assert ops_applied(after, ops) == [] and after["rules"][0]["id"] == "atrium:chg_7.0"
    run(connector(fake).confirm_change(applied["token"]))
    revert = inverse_ops(ops, applied)
    reverted = run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
    park = [c.input for _, c in fake.calls if "atrium-fw apply" in c.command][-1]
    assert park.startswith("park\tatrium:chg_7.0\teth0\t1\ttcp\t10.0.10.0/24\t10.0.20.5\t80,443\t")
    record = snapshot(fake)
    assert ops_reverted(before, record, ops) == [] and ops_applied(record, revert) == []
    assert fake.parked and fake.parked[0].startswith("ufw\tatrium:chg_7.0\t")
    run(connector(fake).rollback_change(reverted["token"], None))  # rolled back: the rule and the registry return
    assert ops_applied(snapshot(fake), ops) == [] and fake.parked == []
    problems = " | ".join(run(connector(fake).preview_change(allow(proto="icmp", marker="atrium:chg_8"),
                                                             snapshot(fake)))["problems"])
    assert "ufw cannot express ICMP" in problems
    problems = " | ".join(run(connector(fake).preview_change(toggle("disable_rules", "atrium:chg_old.0"),
                                                             snapshot(fake)))["problems"])
    assert problems == ""
    fake.ufw["v4"][2] = ("allow_log tcp 5432 10.0.20.5 any 10.0.10.0/24 in_eth0", "atrium:chg_old.0 Postgres; edited")
    problems = " | ".join(run(connector(fake).preview_change(toggle("disable_rules", "atrium:chg_old.0"),
                                                             snapshot(fake)))["problems"])
    assert "not a rule Atrium wrote" in problems


def test_dual_stack_and_several_networks(host):
    """An allow between zones with several networks (dual-stack, secondary subnets) becomes several native rules
    with one key - read back as one rule, verified, parked and restored together."""
    dual = dict(src="10.0.10.0/24,2001:db8:10::/64", dst="10.0.20.5/32,2001:db8:20::5/128")
    for manager, zone, rules in (("nftables", "eth0", 2), ("ufw", "eth0", 2), ("firewalld", "internal", 2)):
        fake = host(manager)
        before = snapshot(fake)
        ops = allow(zone=zone, dst_zone=zone, **dual)
        preview = run(connector(fake).preview_change(ops, before))
        assert preview["problems"] == [] and f"({rules} {manager} rules)" in preview["steps"][0]["detail"], preview
        applied = run(connector(fake).apply_change(ops, before["revision"], None))
        assert json.loads(applied["token"])["parts"] == {"atrium:chg_7.0": rules}
        after = snapshot(fake)
        merged = [r for r in after["rules"] if r["id"] == "atrium:chg_7.0"]
        assert len(merged) == 1 and set(merged[0]["source"]["cidrs"]) == {"10.0.10.0/24", "2001:db8:10::/64"}
        assert ops_applied(after, ops) == [], manager
        run(connector(fake).confirm_change(applied["token"]))
        revert = inverse_ops(ops, applied)
        reverted = run(connector(fake).apply_change(revert, snapshot(fake)["revision"], None))
        record = snapshot(fake)
        assert ops_applied(record, revert) == [] and ops_reverted(before, record, ops) == [], manager
        run(connector(fake).rollback_change(reverted["token"], None))  # both parts come back
        assert ops_applied(snapshot(fake), ops) == [], manager
    fake = host("ufw")  # two source networks on ufw: one rule per pair
    applied = run(connector(fake).apply_change(allow(src="10.0.10.0/24,10.0.30.0/24"), snapshot(fake)["revision"], None))
    assert [b for b, c in fake.ufw["v4"] if c.startswith("atrium:chg_7.0")] == [
        "allow_log tcp 443 10.0.20.5 any 10.0.30.0/24 in_eth0", "allow_log tcp 443 10.0.20.5 any 10.0.10.0/24 in_eth0"]
    # half of an allow parked by hand: it reads as two rules and neither the allow nor its revert looks complete
    fake = host("nftables")
    ops = allow(**dual)
    run(connector(fake).apply_change(ops, snapshot(fake)["revision"], None))
    v6 = next(l for l in fake.nft.splitlines() if "atrium:chg_7.0" in l and "ip6 saddr" in l)
    fake.nft = fake.nft.replace(v6 + "\n", "").replace("\tchain parked {\n", "\tchain parked {\n" + v6 + "\n")
    record = snapshot(fake)
    assert {r["id"] for r in record["rules"] if r["id"].startswith("atrium:chg_7.0")} == {"atrium:chg_7.0",
                                                                                          "atrium:chg_7.0~parked"}
    assert ops_applied(record, ops) != [] and ops_applied(record, inverse_ops(ops, {"created": [
        {"op": 0, "id": "atrium:chg_7.0"}]})) != []
    assert "IPv4 networks are on one side only" in " | ".join(run(connector(fake).preview_change(
        allow(src="10.0.10.0/24,2001:db8:10::/64", dst="2001:db8:20::5/128", marker="atrium:chg_9"), record))["problems"])


def test_ufw_failed_step_is_rolled_back(host):
    fake = host("ufw")
    before = snapshot(fake)
    fake.apply_breaks = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(allow(), before["revision"], None))
    assert caught.value.state == "rolled_back" and fake.events == ["arm", "apply", "rollback"]
    assert ops_reverted(before, snapshot(fake), allow()) == []


def test_firewalld_changes(host):
    fake = host("firewalld")
    before = snapshot(fake)
    ops = allow(zone="internal", dst_zone="internal", ports="8000-8080")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    rule = rich_rule_text(ops[0], "atrium:chg_7.0", "tcp", "8000-8080")
    assert rule == ('rule priority="-1" family="ipv4" source address="10.0.10.0/24" destination address='
                    '"10.0.20.5/32" port port="8000-8080" protocol="tcp" log prefix="atrium:chg_7.0 " level="info" accept')
    assert rule in fake.fw_zones["internal"]["rich"] and rule not in fake.fw_zones["internal"]["perm_rich"]
    after = snapshot(fake)
    assert ops_applied(after, ops) == [] and "runtime configuration differs" in " | ".join(after["notes"])
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert "the change was saved" in confirmed["notes"] and rule in fake.fw_zones["internal"]["perm_rich"]
    applied = run(connector(fake).apply_change(inverse_ops(ops, applied), snapshot(fake)["revision"], None))
    assert rule not in fake.fw_zones["internal"]["rich"] and fake.parked == [f"firewalld\tatrium:chg_7.0\tinternal\t{rule}"]
    record = snapshot(fake)
    assert next(r for r in record["rules"] if r["id"] == "atrium:chg_7.0")["enabled"] is False
    fake.now[0] += 181  # not confirmed: firewall-cmd --reload brings the permanent rule back
    record = snapshot(fake)
    assert ops_applied(record, ops) == [] and fake.parked == []
    problems = " | ".join(run(connector(fake).preview_change(
        allow(zone="internal", ports="80,443", log=False), record))["problems"])
    assert "one port or one range" in problems and "must log" in problems
    problems = " | ".join(run(connector(fake).preview_change(allow(zone="eth0"), record))["problems"])
    assert "no active zone 'eth0'" in problems


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


def as_backup(taken: dict[str, Any]) -> Backup:
    content = taken["content"]
    return Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, taken["format"], None, taken["revision"])


def test_backup_and_restore(host):
    fake = host("nftables")
    taken = run(connector(fake).backup())
    assert taken["format"] == "text" and taken["sha256"] == hashlib.sha256(taken["content"]).hexdigest()
    assert b"### atrium-fw backup v1 manager=nftables" in taken["content"] and b"table ip filter" in taken["content"]
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    restored = run(connector(fake).restore_backup(as_backup(taken)))
    assert restored["restored"] and restored["revision"] == before["revision"]
    assert ops_reverted(before, snapshot(fake), allow()) == [] and fake.events[-2:] == ["restore:nftables", "confirm"]
    sent = next(c.input for _, c in fake.calls if "atrium-fw restore" in c.command)
    assert sent.startswith("table inet atrium {\n") and "table ip filter" not in sent  # only Atrium's own table

    fake = host("ufw")
    taken = run(connector(fake).backup())
    assert b"### atrium-fw file before6.rules" in taken["content"]
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    assert run(connector(fake).restore_backup(as_backup(taken)))["revision"] == before["revision"]

    fake = host("firewalld")
    taken = run(connector(fake).backup())
    assert b"### atrium-fw file permanent-zones" in taken["content"]
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(as_backup(taken)))
    assert caught.value.code == "unsupported"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_2", b"<opnsense/>", "x", 0.0)))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"


# --------------------------------------------------------------------------------------
# helpers and the real wrapper script
# --------------------------------------------------------------------------------------


def test_atrium_table_editing():
    table = AtriumTable(NFT_RULESET.split("table ip filter")[0])
    table.add_top('tcp dport 1 accept comment "atrium:a.0"')
    assert table.move("atrium:chg_old.0", "parked") and table.move("atrium:chg_park.0", "input")
    assert not table.move("atrium:nope.0", "parked")
    lines = table.text().splitlines()
    chain = lines.index("\tchain input {")
    assert lines[chain + 1].startswith("\t\ttype filter")
    assert "atrium:chg_park.0" in lines[chain + 2] and "atrium:a.0" in lines[chain + 3]  # both at the top
    parked = lines.index("\tchain parked {")
    assert "atrium:chg_old.0" in lines[parked + 1] and lines[parked + 2] == "\t}"
    bare = AtriumTable("table inet atrium {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n")
    assert "\tchain parked {\n\t}\n}" in bare.text()
    with pytest.raises(ValueError):
        AtriumTable("table ip filter {\n}\n")


@pytest.fixture
def harness(tmp_path):
    """The real wrapper with its paths moved into tmp_path and stub systemd-run / systemctl / ufw / firewall-cmd."""
    stubs = tmp_path / "bin"
    stubs.mkdir()
    for tool in ("systemd-run", "systemctl", "ufw", "firewall-cmd"):
        (stubs / tool).write_text(f"#!/bin/sh\nprintf '{tool}' >> \"{tmp_path}/log\"\n"
                                  f"for a in \"$@\"; do printf ' [%s]' \"$a\" >> \"{tmp_path}/log\"; done\n"
                                  f"echo >> \"{tmp_path}/log\"\n")
        (stubs / tool).chmod(0o755)
    (tmp_path / "etc" / "ufw").mkdir(parents=True)
    (tmp_path / "etc" / "ufw" / "user.rules").write_text("*filter\n### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\nCOMMIT\n")
    (tmp_path / "etc" / "ufw" / "user6.rules").write_text("*filter\nCOMMIT\n")
    script = WRAPPER_SCRIPT
    for name, value in (("PATH", f"{stubs}:/usr/sbin:/usr/bin:/sbin:/bin"), ("SELF", f"{tmp_path}/atrium-fw"),
                        ("SPOOL", f"{tmp_path}/spool"), ("PERSIST", f"{tmp_path}/etc/atrium/atrium.nft"),
                        ("UFW_DIR", f"{tmp_path}/etc/ufw")):
        script = re.sub(rf"(?m)^{name}=.*$", f"{name}={value}", script, count=1)
    (tmp_path / "atrium-fw").write_text(script)
    (tmp_path / "atrium-fw").chmod(0o755)
    return tmp_path


def wrap(harness: Path, *args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["/bin/sh", str(harness / "atrium-fw"), *args], input=stdin, capture_output=True, text=True,
                          timeout=30)


def test_wrapper_script_syntax_and_template():
    for shell in ("/bin/sh", shutil.which("dash"), shutil.which("bash")):
        if shell:
            assert subprocess.run([shell, "-n"], input=WRAPPER_SCRIPT, text=True).returncode == 0, shell
    assert WRAPPER_SCRIPT.startswith("#!/bin/sh\n# atrium-fw 1 ") and "VERSION=1\n" in WRAPPER_SCRIPT
    assert NFT_TABLE_TEMPLATE.startswith("table inet atrium {") and "policy drop" in NFT_TABLE_TEMPLATE


def test_wrapper_ufw_and_firewalld_steps(harness):
    tab = "\t"
    assert wrap(harness, "version").stdout == "atrium-fw 1\n"
    old = harness / "spool" / "ffffffffffffffff"
    old.mkdir(parents=True)
    os.utime(old, (0, 0))  # a session from long ago: arm prunes it
    refused = wrap(harness, "apply", "0000000000000001", stdin="x\n")
    assert refused.returncode == 2 and "not armed" in refused.stderr
    assert wrap(harness, "arm", "0000000000000001", "120", "ufw").stdout == "armed\n"
    assert not old.exists() and (harness / "spool" / "0000000000000001" / "armed").exists()
    log = (harness / "log").read_text()
    assert "systemd-run [--unit=atrium-fw-revert-0000000000000001] [--on-active=120] [--timer-property=AccuracySec=1s]" in log
    good = tab.join(["add", "atrium:chg_7.0", "eth0", "1", "tcp", "10.0.10.0/24", "10.0.20.5", "80,443",
                     "atrium:chg_7.0 Users to intranet"])
    bad = [good.replace("Users to intranet", "x'y"), good.replace("atrium:chg_7.0 Users", "atrium:chg_8.0 Users"),
           good.replace("eth0", "-oops"), good.replace("10.0.10.0/24", "any"), good.replace("tcp", "icmp"),
           good.replace("add", "delete"), good + tab + "extra", good.replace("80,443", "443;reboot")]
    for line in bad:
        result = wrap(harness, "apply", "0000000000000001", stdin=line + "\n")
        assert result.returncode == 2 and "refused" in result.stderr, line
    assert "ufw [" not in (harness / "log").read_text()  # nothing ran for a refused change
    assert wrap(harness, "apply", "0000000000000001", stdin=good + "\n").stdout == "applied\n"
    assert ("ufw [prepend] [allow] [in] [on] [eth0] [log] [proto] [tcp] [from] [10.0.10.0/24] [to] [10.0.20.5] "
            "[port] [80,443] [comment] [atrium:chg_7.0 Users to intranet]") in (harness / "log").read_text()
    (harness / "etc" / "ufw" / "user.rules").write_text("changed\n")
    assert wrap(harness, "rollback", "0000000000000001").stdout == "reverted\n"
    assert (harness / "etc" / "ufw" / "user.rules").read_text().startswith("*filter")
    assert wrap(harness, "confirm", "0000000000000001").stdout == "rolled\n"

    rule = ('rule priority="-1" family="ipv4" source address="10.0.10.0/24" destination address="10.0.20.5/32" port '
            'port="443" protocol="tcp" log prefix="atrium:chg_7.0 " level="info" accept')
    assert wrap(harness, "arm", "0000000000000002", "120", "firewalld").stdout == "armed\n"
    for text in ('rule family="ipv4" source address="10.0.10.0/24" accept',
                 rule.replace("chg_7.0 ", "chg_9.0 "), rule + ' --panic-on'):
        assert wrap(harness, "apply", "0000000000000002", stdin=f"add{tab}atrium:chg_7.0{tab}public{tab}{text}\n").returncode == 2
    assert wrap(harness, "apply", "0000000000000002", stdin=f"park{tab}atrium:chg_7.0{tab}public{tab}{rule}\n").stdout == "applied\n"
    assert wrap(harness, "parked").stdout == f"firewalld{tab}atrium:chg_7.0{tab}public{tab}{rule}\n"
    confirmed = wrap(harness, "confirm", "0000000000000002").stdout
    assert confirmed == "confirmed\npersist=ok\n"
    log = (harness / "log").read_text()
    assert f"firewall-cmd [--zone=public] [--remove-rich-rule={rule}]" in log
    assert f"firewall-cmd [--permanent] [--zone=public] [--remove-rich-rule={rule}]" in log
    assert "systemctl [stop] [atrium-fw-revert-0000000000000002.timer]" in log
    assert wrap(harness, "revert-now", "0000000000000002").stdout == "confirmed\n"  # the timer found it confirmed
    for args in (("arm", "../etc/passwd0000", "60", "ufw"), ("arm", "0000000000000003", "5", "ufw"),
                 ("arm", "0000000000000003", "60", "iptables"), ("arm", "0000000000000002", "60", "ufw"),
                 ("restore", "firewalld"), ("bogus",)):
        assert wrap(harness, *args).returncode == 2, args


def check_table(harness: Path, text: str) -> subprocess.CompletedProcess:
    """The wrapper's own check_table function, run on `text`."""
    function = re.search(r"(?ms)^check_table\(\) \{.*?^\}\n", WRAPPER_SCRIPT).group(0)
    (harness / "t").write_text(text)
    return subprocess.run(["/bin/sh", "-c", function + 'check_table "$1"', "sh", str(harness / "t")],
                          capture_output=True, text=True, timeout=30)


def test_wrapper_refuses_tables_it_does_not_own(harness):
    """The validator alone: only one "table inet atrium { ... }" block gets through to nft."""
    good = ('table inet atrium {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n'
            '\t\ttcp dport 113 reject with tcp reset\n\t}\n}\n')
    assert check_table(harness, good).returncode == 0
    cases = {"escape on the same line": good.replace("\n}\n", "\n} chain x { }\n"),
             "another table": good.replace("\n}\n", "\n} table ip other { }\n"),
             "escape on the next line": "table inet atrium {\n}\nadd rule ip other input drop\n",
             "include": 'table inet atrium {\n\tinclude "/etc/shadow"\n}\n',
             "define": "table inet atrium {\n\tdefine x = 1\n}\n",
             "comment hiding a brace": "table inet atrium {\n\tchain input { # }\n\t}\n}\n",
             "multi-line string": 'table inet atrium {\n\tchain input {\n\t\taccept comment "x\n}" }\n}\n',
             "backslash": "table inet atrium {\n\tchain input {\n\t\ttcp dport 22 \\\n accept\n\t}\n}\n",
             "variable": "table inet atrium {\n\tchain input {\n\t\ttcp dport $p accept\n\t}\n}\n",
             "control character": "table inet atrium {\n\x01}\n", "wrong table": "table ip filter {\n}\n",
             "incomplete": "table inet atrium {\n\tchain input {\n", "flush": "table inet atrium {\n\tflush ruleset\n}\n"}
    for name, text in cases.items():
        result = check_table(harness, text)
        assert result.returncode != 0 and "atrium-fw:" in result.stderr, name


# -- review F36: "restore" changed the firewall at once, with no armed revert, and took any ufw rules file -------------

# a user.rules as ufw writes it (backend_iptables.py: format_rule, logged and limited rules, logging, rate limiting)
UFW_WRITTEN = """*filter
:ufw-user-input - [0:0]
:ufw-user-output - [0:0]
:ufw-user-forward - [0:0]
:ufw-user-logging-input - [0:0]
:ufw-after-logging-input - [0:0]
:ufw-logging-deny - [0:0]
:ufw-logging-allow - [0:0]
:ufw-user-limit - [0:0]
:ufw-user-limit-accept - [0:0]
### RULES ###

### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 22 -j ACCEPT

### tuple ### allow_log tcp 80,443 10.0.20.5 any 10.0.10.0/24 in_eth0 comment=61747269756d3a6368675f372e30
-A ufw-user-logging-input -i eth0 -p tcp -d 10.0.20.5 -m multiport --dports 80,443 -s 10.0.10.0/24 -m conntrack --ctstate NEW -j LOG --log-prefix "[UFW ALLOW] "
-A ufw-user-input -i eth0 -p tcp -d 10.0.20.5 -m multiport --dports 80,443 -s 10.0.10.0/24 -j ufw-user-logging-input
-A ufw-user-input -i eth0 -p tcp -d 10.0.20.5 -m multiport --dports 80,443 -s 10.0.10.0/24 -j ACCEPT

### tuple ### limit tcp 2222 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in
-A ufw-user-input -p tcp --dport 2222 -m conntrack --ctstate NEW -m recent --set -m comment --comment 'dapp_OpenSSH'
-A ufw-user-input -p tcp --dport 2222 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 -j ufw-user-limit -m comment --comment 'dapp_OpenSSH'
-A ufw-user-input -p tcp --dport 2222 -j ufw-user-limit-accept -m comment --comment 'dapp_OpenSSH'

### tuple ### reject tcp 8000:8080 0.0.0.0/0 any 0.0.0.0/0 in
-A ufw-user-input -p tcp --dport 8000:8080 -j REJECT --reject-with tcp-reset

### tuple ### deny any any 0.0.0.0/0 any 192.0.2.0/24 in
-A ufw-user-input -s 192.0.2.0/24 -j DROP

### END RULES ###

### LOGGING ###
-A ufw-after-logging-input -j LOG --log-prefix "[UFW BLOCK] " -m limit --limit 3/min --limit-burst 10
-I ufw-logging-deny -m conntrack --ctstate INVALID -j RETURN -m limit --limit 3/min --limit-burst 10
-A ufw-logging-allow -j LOG --log-prefix "[UFW ALLOW] " -m limit --limit 3/min --limit-burst 10
### END LOGGING ###

### RATE LIMITING ###
-A ufw-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "
-A ufw-user-limit -j REJECT
-A ufw-user-limit-accept -j ACCEPT
### END RATE LIMITING ###
COMMIT
"""
UFW6_WRITTEN = ("*filter\n:ufw6-user-input - [0:0]\n### RULES ###\n\n"
                "### tuple ### allow udp 53 ::/0 any 2001:db8::/32 in\n"
                "-A ufw6-user-input -p udp --dport 53 -s 2001:db8::/32 -j ACCEPT\n\n### END RULES ###\nCOMMIT\n")


def ufw_restore(user: str = UFW_WRITTEN, user6: str | None = UFW6_WRITTEN) -> str:
    """The restore content as the connector sends it: both rules files, each under its section line."""
    return f"### atrium-fw file user.rules\n{user}" + (f"### atrium-fw file user6.rules\n{user6}" if user6 else "")


def wrapper_log(harness: Path) -> list[str]:
    return (harness / "log").read_text().splitlines() if (harness / "log").exists() else []


def fake_nft(harness: Path, table: str) -> Path:
    """A stub nft for the wrapper: `list table` prints the live table, `-f FILE` makes the file's table live."""
    live = harness / "live.nft"
    live.write_text(table)
    nft = harness / "bin" / "nft"
    nft.write_text(f"#!/bin/sh\nprintf 'nft' >> \"{harness}/log\"\n"
                   f"for a in \"$@\"; do printf ' [%s]' \"$a\" >> \"{harness}/log\"; done\necho >> \"{harness}/log\"\n"
                   f"case \"$1 $2\" in\n  'list table') cat \"{live}\" ;;\n  '-c -f') ;;\n"
                   f"  '-f '*) sed '1,2d' \"$2\" > \"{live}\" ;;\nesac\n")
    nft.chmod(0o755)
    return live


def test_wrapper_restore_writes_only_after_arming_the_revert(harness):
    rules = harness / "etc" / "ufw" / "user.rules"
    before = rules.read_text()
    sid = "00000000000000a1"
    # what the old verb did - "restore ufw" wrote and reloaded at once - and a window too short to arm: refused, and
    # nothing was armed or written
    for args in (("restore", "ufw"), ("restore", sid, "ufw"), ("restore", sid, "5", "ufw")):
        assert wrap(harness, *args, stdin=ufw_restore()).returncode == 2, args
    assert rules.read_text() == before and wrapper_log(harness) == []

    result = wrap(harness, "restore", sid, "120", "ufw", stdin=ufw_restore())
    assert result.stdout == "restored\n", result.stderr
    assert rules.read_text() == UFW_WRITTEN and (harness / "etc" / "ufw" / "user6.rules").read_text() == UFW6_WRITTEN
    log = wrapper_log(harness)
    armed = next(i for i, line in enumerate(log) if line.startswith(
        f"systemd-run [--unit=atrium-fw-revert-{sid}] [--on-active=120] [--timer-property=AccuracySec=1s]"))
    assert log.index("ufw [reload]") > armed  # the timer ran before the restored rules were loaded
    assert (harness / "spool" / sid / "armed").exists()
    # the restored rules cut the hub off, so nothing confirms: the timer puts back the rules from before the restore
    assert wrap(harness, "revert-now", sid).stdout == "reverted\n"
    assert rules.read_text() == before and wrapper_log(harness).count("ufw [reload]") == 2
    assert wrap(harness, "confirm", sid).stdout == "fired\n"  # too late to keep the restore

    sid = "00000000000000a2"  # confirmed in time: kept, the timer stopped, and a late timer changes nothing
    assert wrap(harness, "restore", sid, "120", "ufw", stdin=ufw_restore()).stdout == "restored\n"
    assert wrap(harness, "confirm", sid).stdout == "confirmed\npersist=immediate\n"
    assert f"systemctl [stop] [atrium-fw-revert-{sid}.timer]" in wrapper_log(harness)
    assert wrap(harness, "revert-now", sid).stdout == "confirmed\n" and rules.read_text() == UFW_WRITTEN

    rules.write_text(before)  # no automatic revert, no restore
    stub = harness / "bin" / "systemd-run"
    stub.write_text(stub.read_text() + "exit 1\n")
    refused = wrap(harness, "restore", "00000000000000a3", "120", "ufw", stdin=ufw_restore())
    assert refused.returncode == 2 and "could not arm" in refused.stderr and rules.read_text() == before
    assert not (harness / "spool" / "00000000000000a3").exists()


def test_wrapper_nftables_restore_is_saved_only_once_confirmed(harness):
    old = "table inet atrium {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
    backup = old.replace("policy drop;\n", "policy drop;\n\t\ttcp dport 443 accept\n")
    live = fake_nft(harness, old)
    persist = harness / "etc" / "atrium" / "atrium.nft"
    refused = wrap(harness, "restore", "00000000000000c1", "120", "nftables", stdin="table ip filter {\n}\n")
    assert refused.returncode == 2 and "refused" in refused.stderr
    assert live.read_text() == old and not any(l.startswith("systemd-run") for l in wrapper_log(harness))

    assert wrap(harness, "restore", "00000000000000c1", "120", "nftables", stdin=backup).stdout == "restored\n"
    log = wrapper_log(harness)
    armed = next(i for i, line in enumerate(log)
                 if line.startswith("systemd-run [--unit=atrium-fw-revert-00000000000000c1]"))
    assert next(i for i, line in enumerate(log) if line.startswith("nft [-f]")) > armed
    assert live.read_text() == backup and not persist.exists()  # live, but not saved: a reboot would also undo it
    assert wrap(harness, "revert-now", "00000000000000c1").stdout == "reverted\n"
    assert live.read_text() == old and not persist.exists()

    assert wrap(harness, "restore", "00000000000000c2", "120", "nftables", stdin=backup).stdout == "restored\n"
    assert wrap(harness, "confirm", "00000000000000c2").stdout == "confirmed\npersist=ok\n"
    assert persist.read_text() == backup == live.read_text()


def test_wrapper_restores_only_what_ufw_itself_writes(harness):
    rules = harness / "etc" / "ufw" / "user.rules"
    before = rules.read_text()
    line = "-A ufw-user-input -p tcp --dport 22 -j ACCEPT"
    assert line in UFW_WRITTEN

    def rule(text: str) -> str:
        return UFW_WRITTEN.replace(line, text)

    cases = {
        "a chain of the system": rule("-A INPUT -j DROP"), "a policy": rule("-P INPUT DROP"),
        "flushing a chain": rule("-F ufw-user-input"), "deleting a chain": rule("-X ufw-user-input"),
        "another table": "*nat\n-A PREROUTING -p tcp -j DNAT --to-destination 192.0.2.1\nCOMMIT\n",
        "a second table": UFW_WRITTEN + "*nat\nCOMMIT\n", "no COMMIT": UFW_WRITTEN.replace("COMMIT\n", ""),
        "a system chain declared": UFW_WRITTEN.replace(":ufw-user-input - [0:0]", ":INPUT DROP [0:0]"),
        "a userspace queue": rule("-A ufw-user-input -j NFQUEUE --queue-num 1"),
        "an ipset target": rule("-A ufw-user-input -j SET --add-set x src"),
        "a string match": rule("-A ufw-user-input -m string --algo bm --string x -j ACCEPT"),
        "a bpf match": rule("-A ufw-user-input -m bpf --bytecode 1 -j ACCEPT"),
        "an owner match": rule("-A ufw-user-input -m owner --uid-owner 0 -j ACCEPT"),
        "goto": rule("-A ufw-user-input -g ufw-user-limit"),
        "negation": rule("-A ufw-user-input ! -s 10.0.0.0/8 -j ACCEPT"),
        "a free log prefix": UFW_WRITTEN.replace('"[UFW BLOCK] "', '"x" -j ACCEPT'),
        "an unbalanced quote": UFW_WRITTEN.replace('"[UFW BLOCK] "', '"[UFW BLOCK] '),
        "a free comment": UFW_WRITTEN.replace("'dapp_OpenSSH'", "'x y'", 1),
        "a placeholder": rule("-A ufw-user-input -j LOG --log-prefix @P"),
        "an option without its value": rule("-A ufw-user-input -p tcp --dport"),
        "a bad address": rule("-A ufw-user-input -s 10.0.0.0/8;reboot -j ACCEPT"),
        "a control character": rule(line + "\x07"),
    }
    for name, text in cases.items():
        result = wrap(harness, "restore", "00000000000000b1", "120", "ufw", stdin=ufw_restore(text))
        assert result.returncode == 2 and "not a ufw user rules file" in result.stderr, name
    six = wrap(harness, "restore", "00000000000000b1", "120", "ufw", stdin=ufw_restore(user6=None))
    assert six.returncode == 2 and "user6.rules is missing" in six.stderr
    bad6 = wrap(harness, "restore", "00000000000000b1", "120", "ufw",
                stdin=ufw_restore(user6=UFW6_WRITTEN.replace("-j ACCEPT", "-j TEE --gateway 192.0.2.1")))
    assert bad6.returncode == 2
    # nothing was armed or written, and no work directory is left behind
    assert rules.read_text() == before and wrapper_log(harness) == []
    assert sorted(p.name for p in (harness / "spool").iterdir()) == []


def test_the_connectors_ufw_restore_passes_the_real_wrapper(host, harness):
    """What restore_backup sends for a ufw host is what the wrapper accepts, and a restore that cuts the hub off is
    put back by the host's own timer."""
    fake = host("ufw")
    taken = run(connector(fake).backup())
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(allow(), before["revision"], None))
    run(connector(fake).confirm_change(applied["token"]))
    changed = snapshot(fake)
    fake.lockout_after_apply = True
    with pytest.raises(ChangeError) as cut:
        run(connector(fake).restore_backup(as_backup(taken)))
    assert cut.value.code == "unreachable" and cut.value.state == "unknown" and "automatic revert" in cut.value.message
    fake.lockout_after_apply = False
    fake.now[0] += 181  # nothing confirmed it: the host's timer put back the rules from before the restore
    assert snapshot(fake)["revision"] == changed["revision"]
    sent = next(c.input for _, c in fake.calls if "atrium-fw restore" in c.command)
    assert wrap(harness, "restore", "00000000000000d1", "120", "ufw", stdin=sent).stdout == "restored\n"


@pytest.mark.skipif(not CAN_UNSHARE, reason="needs root, unshare and nft (a throwaway network namespace)")
def test_wrapper_with_real_nft(harness, real_nft):
    if not real_nft:
        pytest.skip("network namespaces are not available here")
    script = f"""set -u
F="{harness}/atrium-fw"
nft -f - <<'E'
{NFT_TABLE_TEMPLATE}table ip other {{
	chain input {{
		type filter hook input priority filter; policy accept;
	}}
}}
E
$F arm 0123456789abcdef 120 nftables
$F table > {harness}/cur.nft
"""
    out = netns(script + f"""
python3 - "{harness}/cur.nft" > "{harness}/new.nft" <<'P'
import sys
lines = open(sys.argv[1]).read().rstrip("\\n").split("\\n")
i = lines.index("\\tchain input {{") + 2
lines.insert(i, '\\t\\tiifname "eth0" ip saddr 10.0.10.0/24 ip daddr 10.0.20.5 tcp dport {{ 80, 443 }} counter log prefix "atrium:chg_7.0 " accept comment "atrium:chg_7.0 x"')
print("\\n".join(lines))
P
$F apply 0123456789abcdef < {harness}/new.nft
nft -j list table inet atrium > {harness}/after.json
$F rollback 0123456789abcdef
nft list table inet atrium | grep -c 'atrium:chg_7.0' || true
nft list table ip other | grep -c 'policy accept'
""", harness)
    assert out.returncode == 0, out.stderr
    assert out.stdout.split() == ["armed", "applied", "reverted", "0", "1"], out.stdout + out.stderr
    data = json.loads((harness / "after.json").read_text())
    rules, _ = NftRuleset(data).read_rules()
    rule = next(r for r in rules if r["id"] == "atrium:chg_7.0")
    assert rule["services"] == [{"proto": "tcp", "ports": "80,443", "alias": None}]
    assert rule["source"]["cidrs"] == ["10.0.10.0/24"] and rule["destination"]["cidrs"] == ["10.0.20.5/32"]


@pytest.mark.skipif(not CAN_UNSHARE, reason="needs root, unshare and nft (a throwaway network namespace)")
def test_fake_nft_matches_real_nft(tmp_path, real_nft):
    """The fake's JSON is what nft 1.0.9 prints - for the starting ruleset and for rules the connector writes."""
    if not real_nft:
        pytest.skip("network namespaces are not available here")
    ops = allow(ports="80,443") + allow(src="10.0.10.0/24,10.0.30.0/24", dst="10.0.20.5/32", ports="8000-8080",
                                        proto="udp", marker="atrium:chg_8")
    lines = [nft_rule_line(op, f"{op['marker']}.{i}", op["services"][0]["proto"], op["services"][0]["ports"])
             for i, op in enumerate(ops)]
    lines.append(nft_rule_line(allow(proto="icmp", marker="atrium:chg_9")[0], "atrium:chg_9.0", "icmp", None))
    lines.append(nft_rule_line(allow(src="2001:db8:10::/64", dst="2001:db8:20::5/128", marker="atrium:chg_10")[0],
                               "atrium:chg_10.0", "tcp", "443"))
    ruleset = NFT_RULESET.replace("\t\tip saddr 10.0.10.0/24 jump admin", "\n".join(f"\t\t{l}" for l in lines)
                                  + "\n\t\tip saddr 10.0.10.0/24 jump admin")
    (tmp_path / "r.nft").write_text(ruleset)
    out = netns("nft -f r.nft && nft -j list ruleset && echo '@@' && nft list ruleset", tmp_path)
    assert out.returncode == 0, out.stderr
    real_json, real_text = out.stdout.split("@@\n")
    real = [i["rule"] for i in json.loads(real_json)["nftables"] if "rule" in i]
    fake = [i["rule"] for i in ruleset_json(ruleset)["nftables"] if "rule" in i]
    assert [(r["chain"], r["expr"], r.get("comment")) for r in real] == [(r["chain"], r["expr"], r.get("comment"))
                                                                         for r in fake]
    for line in lines:
        assert "\t\t" + nft_normal(line) in real_text.splitlines(), line


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakeHost("ufw")
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="web01", name="web01 host firewall", source_type="saas", source="https://example.invalid",
                status="ready", manifest=Manifest(id="web01", name="web01 ufw", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    response = client.put("/api/tools/web01/connection", json={
        "kind": "hostfw", "config": {"host": "10.0.20.5", "host_key": HOST_KEY}, "secrets": {"private_key": KEY}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/web01/connection/test").json()
    assert tested["ok"], tested
    assert tested["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman",
                                       "window_s": 180}
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "web01"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=web01").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/web01/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/web01").json()
    assert device["record"]["kind"] == "host" and device["record"]["device"]["vendor"] == "Linux"
    assert any(r["id"] == "atrium:chg_old.0" for r in device["record"]["rules"])
    devices = client.get("/api/network/devices").json()["devices"]
    entry = next(d for d in devices if d["tool_id"] == "web01")
    assert entry["kind"] == "host" and entry["write"]["capable"] and entry["write"]["rollback"]["mode"] == "deadman"
    assert "fake-host-key-material" not in json.dumps(device) + json.dumps(devices)
    backup = client.post("/api/network/devices/web01/backups")
    assert backup.status_code == 201, backup.text


def test_a_change_through_the_hub(client, sign_in, monkeypatch, wait_for):
    """The hub's own change path with this connector: proposal, a second administrator's approval, Atrium's backup,
    arm + apply, verification over a new connection, confirm - and the new rule attributed, not reported as drift."""
    from hub.models import Manifest, Tool

    fake = FakeHost("nftables")
    fake.ip_addr[1]["addr_info"] = fake.ip_addr[1]["addr_info"][:1]  # eth0: IPv4 only, like eth0.30
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", fake, raising=False)
    tool = Tool(id="web01", name="web01", source_type="saas", source="https://example.invalid", status="ready",
                manifest=Manifest(id="web01", name="web01 nftables", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    assert client.put("/api/tools/web01/connection", json={
        "kind": "hostfw", "config": {"host": "10.0.20.5", "host_key": HOST_KEY},
        "secrets": {"private_key": KEY}}).status_code == 200
    assert client.post("/api/tools/web01/connection/test").json()["ok"]
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "web01"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    assert client.patch("/api/settings/guardrails", json={"device_changes": True,
                                                          "device_changes_need_maintenance_window": False}).status_code == 200
    wait_for(lambda: client.post("/api/network/devices/web01/refresh").json()["results"][0]["ok"])
    admin2 = sign_in("admin", "admin2")
    body = {"firewall": "web01", "op": "allow", "source_zone": "z:web01:eth0.30", "target_zone": "z:web01:eth0",
            "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Guests to the web app"}
    preview = client.post("/api/segmentation/changes/preview", json=body)
    assert preview.status_code == 200 and preview.json()["writable"] and preview.json()["problems"] == [], preview.text
    created = client.post("/api/segmentation/changes", json=body)
    assert created.status_code == 201, created.text
    created = created.json()
    assert admin2.post(f"/api/approvals/{created['approval_id']}", json={"approve": True}).status_code == 200
    change_id = created["change"]["id"]
    change = wait_for(lambda: (c := client.get(f"/api/segmentation/changes/{change_id}").json())["status"]
                      in ("applied", "failed", "rolled_back") and c)
    assert change["status"] == "applied", change
    assert fake.events == ["arm", "apply", "confirm"] and "atrium:" + change_id in fake.persisted
    line = next(l for l in fake.nft.splitlines() if f"atrium:{change_id}.0" in l)
    assert 'iifname "eth0.30" ip saddr 10.0.30.0/24 ip daddr 10.0.20.0/24 tcp dport 443' in line
    assert hub.store.get("device_backups", change["backup_id"])["reason"] == "pre-change"
    client.post("/api/network/devices/web01/refresh")
    drift = client.get("/api/network/drift?tool_id=web01").json()
    assert drift["counts"]["open"] == 0 and any(d["change_id"] == change_id for d in drift["items"])
