"""MikroTik RouterOS v7 connector: reads the router through its REST API into the network model (``netmodel.py``) and
makes guarded rule changes (one accept rule between two interface networks, disabling / re-enabling rules) for the
hub's network change path.

Checked against the RouterOS manual 7.26 (manual.mikrotik.com, October 2026; docs/research/fw-opnsense-pfsense-
mikrotik.md section 3):

- REST: ``https://<router>/rest/<menu>``; GET = print, PUT = add (201 + the record), PATCH = set, DELETE = remove (204),
  POST = any command. HTTP Basic with a RouterOS user whose group has BOTH ``api`` and ``rest-api``; ``read`` to read,
  ``write`` to change, ``ftp`` + ``test`` for configuration exports. Replies encode every value as a string
  ("true"/"false"). Errors: ``{"detail", "error", "message"}``; 401 bad login / no ``rest-api`` / address not allowed,
  500 "not allowed (9)" = no ``api``, 500 "not enough permissions (9)" = a missing policy, 403 = REST off for the
  protocol, 404 = no such item, 400 "Session closed" = the 60 s request limit. Requests of one user run one at a
  time; the login is cached for 10 minutes (group policy changes take up to 10 minutes to apply).
- TLS: ``www-ssl`` has no certificate by default (HTTPS fails until one is assigned); a self-signed CA must be trusted
  through the CA file setting. Plain HTTP is refused here (the password travels in every request).
- Reading: interfaces, VLANs, IPv4/IPv6 addresses, interface lists and members, address lists, the IPv4 and IPv6
  filter tables, resource (version, board), identity, routerboard (serial). A packet no rule matches is accepted
  (help.mikrotik.com "Firewall"): ``default_policy`` is pass everywhere and the map shows explicit accept rules only.
  Interface lists are read as their member interfaces (interfaces are the zones, like OPNsense groups); rules in jump
  chains are read without the conditions of the jump that reaches them (wider); accept rules that only match
  established / related / untracked traffic open no new paths and are left out of the record (counted in notes).
- Revision: RouterOS has no configuration revision, so it is a hash of what was read (static rows only; counters,
  link state and dynamic entries left out).
- Changes: there is no commit step (each request takes effect at once) and no Safe Mode over REST. Rollback mode
  ``deadman``: before writing, a one-shot ``/system/scheduler`` job (``interval=0s``, start = router clock + window) is
  armed whose script undoes exactly this change and removes itself; confirm deletes it, rollback undoes the change
  over REST and deletes it. If Atrium loses the router, the router undoes the change by itself when the window ends.
- Backups: ``/export file=`` + ``/file/read`` (32 KiB chunks) + ``/file/<name>`` DELETE; passwords and keys are left
  out of the export (``show-sensitive`` is never sent). Atrium's backup is JSON holding that export and the filter
  rows it restores from. ``restore_backup`` puts the filter table back only where the difference is what Atrium itself
  changes (its marked rules, enabled/disabled states); anything else is refused before writing (import the export by
  hand) - a full ``/system/backup/load`` reboots the router and is never used.

Verified on the 7.26 reference pages: the properties of /interface/vlan (vlan-id, interface), /interface/list
(include, exclude; built-in all, none, dynamic, static), /interface/list/member (list, interface),
/ip/firewall/address-list (list, address: IP, prefix, range or DNS name; timeout; dynamic), /system/resource (version,
board-name), /system/clock (date YYYY-MM-DD, time HH:MM:SS, gmt-offset) and /system/scheduler (start-date, start-time,
interval 0s = once, on-event as script text, policy defaulting to the adding user's).

UNVERIFIED (no RouterOS device was available; the calls follow the 7.26 manual and are tested against answers shaped
like its examples): /user/group ``policy`` as a comma list with "!"-prefixed denied policies; whether plain GET of the
filter table includes ``bytes``/``packets`` and dynamic rules; stability of ``.id`` across reboots; that ``next-run``
appears in REST output; the scheduler script syntax (``:do {..} on-error={}`` is on the official Scripting page;
``[find comment="..."]`` and ``set *1A ...`` with an internal id are community usage); the ``policy`` multi-value as a
comma string in REST; dates before 7.10 in the "oct/09/2026" style; the encoding of non-ASCII bytes in ``/file/read``
data; a daylight-saving change inside the undo window shifts the job by the DST offset (router local time).
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import secrets as pysecrets
import ssl
import time
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, derived_revision, display_id, find_marker,
                       management_guard, normalise_cidr, normalize_record, parse_ops, parse_ports, untrusted_text)

OPS = ["allow", "disable_rules", "enable_rules"]
MIN_VERSION = (7, 1)  # the REST API exists since 7.1beta4
DEFAULT_WINDOW = 120
WINDOW_RANGE = (60, 900)
CONFIRM_MARGIN = 10  # never delete the undo job this close to its start (it may be running)
SETTLE = 5  # how long to let the undo job finish before reporting what it did
MAX_TOKEN = 4096
CHUNK = 32768
MAX_EXPORT = 16 * 1024 * 1024
MAX_ALIAS_ENTRIES = 2000
TABLES = {"ip": "/ip/firewall/filter", "ipv6": "/ipv6/firewall/filter"}
SCRIPT_MENUS = {"ip": "/ip firewall filter", "ipv6": "/ipv6 firewall filter"}
BASE_CHAINS = ("input", "forward", "output")
BUILTIN_LISTS = ("all", "none", "dynamic", "static")
ACTIONS = {"accept": "pass", "drop": "block", "tarpit": "block", "reject": "reject"}
HARMLESS = ("log", "passthrough", "add-src-to-address-list", "add-dst-to-address-list", "drop", "reject", "tarpit")
ROW_ID_RE = re.compile(r"^\*[0-9A-Fa-f]{1,8}$")
REF_RE = re.compile(r"^(ip|ipv6):(\*[0-9A-Fa-f]{1,8})$")
SCHEDULER_RE = re.compile(r"^atrium-rb-[0-9a-f]{12}$")
EXPORT_RE = re.compile(r"^atrium-bk-[0-9a-f]{12}$")
# what a comment Atrium writes may hold: it is quoted inside the undo job's script, so nothing that a RouterOS string
# treats specially (quotes, backslash, $ variables, ? help, brackets, braces, ;)
UNSAFE_COMMENT = re.compile(r"[^A-Za-z0-9 ._,:/()+@-]")
SAFE_COMMENT_RE = re.compile(r"^atrium:[A-Za-z0-9_-]{1,64}( [A-Za-z0-9 ._,:/()+@-]{0,130})?$")
VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
TRUE = ("true", "yes")
VOLATILE_RULE_KEYS = {"bytes", "packets"}
NOT_NEW = {"established", "related", "untracked", "invalid"}
# the policies that matter for Atrium, and the ones a least-privilege group does not need
NEEDED = ("read", "api", "rest-api")
FOR_CHANGES = ("write",)
FOR_BACKUPS = ("ftp", "test")
EXTRA = ("policy", "sensitive", "password", "reboot", "sniff", "romon", "local", "telnet", "ssh", "winbox", "web")


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value if value is not None else "").strip().lower() in TRUE


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """(7, 16, 2) from "7.16.2 (stable)" or "7.12"."""
    match = VERSION_RE.search(str(text or ""))
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def _split(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple)) else str(value or "").split(",")
    return [text for text in (str(v).strip() for v in items) if text]


def _neg(value: Any) -> tuple[str, bool]:
    """("LAN", True) from "!LAN"; ("", False) for nothing."""
    text = str(value if value is not None else "").strip()
    return (text[1:].strip(), True) if text.startswith("!") else (text, False)


def _query(**params: str) -> str:
    """A query string RouterOS reads: commas in .proplist stay commas, values are percent-encoded."""
    return "?" + "&".join(f"{k.replace('_', '.', 1) if k.startswith('_') else k}={quote(v, safe=',')}"
                          for k, v in params.items())


def safe_comment(op: dict[str, Any]) -> str:
    """The comment an allow's rule gets: the marker, then the description reduced to characters that are safe inside
    the undo job's quoted script string."""
    description = UNSAFE_COMMENT.sub("_", op.get("description") or "")
    return f"{op['marker']} {description}".strip()[:200]


def parse_clock(clock: dict[str, Any]) -> tuple[datetime, str]:
    """(router local time, date style "iso" | "legacy") from /system/clock ("2026-10-09" or "oct/09/2026");
    ValueError when it is neither."""
    date, clock_time = str(clock.get("date") or "").strip(), str(clock.get("time") or "").strip()
    try:
        moment = datetime.strptime(clock_time, "%H:%M:%S").time()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
            return datetime.combine(datetime.strptime(date, "%Y-%m-%d").date(), moment), "iso"
        match = re.fullmatch(r"([a-z]{3})/(\d{2})/(\d{4})", date.lower())
        if match and match.group(1) in MONTHS:  # UNVERIFIED: RouterOS before 7.10
            day = datetime(int(match.group(3)), MONTHS.index(match.group(1)) + 1, int(match.group(2)))
            return datetime.combine(day.date(), moment), "legacy"
    except ValueError:
        pass
    raise ValueError("RouterOS's clock answer is not a date and time Atrium can read")


def format_date(moment: datetime, style: str) -> str:
    if style == "iso":
        return moment.strftime("%Y-%m-%d")
    return f"{MONTHS[moment.month - 1]}/{moment.day:02d}/{moment.year}"


def gmt_offset(value: Any) -> int | None:
    """Seconds from "+02:00" (print) or "7200" (get)."""
    text = str(value or "").strip()
    match = re.fullmatch(r"([+-])(\d{1,2}):(\d{2})", text)
    if match:
        seconds = int(match.group(2)) * 3600 + int(match.group(3)) * 60
        return -seconds if match.group(1) == "-" else seconds
    return int(text) if re.fullmatch(r"-?\d{1,6}", text) else None


class TlsError(ConnectorError):
    """The router answered, but its certificate is not trusted (or it has none)."""


def _rows(answer: Any, what: str) -> list[dict[str, Any]]:
    if isinstance(answer, dict):
        answer = [answer]
    if not isinstance(answer, list):
        raise ConnectorError(f"Unexpected answer from RouterOS ({what}): not a list")
    return [r for r in answer if isinstance(r, dict)]


def _obj(answer: Any) -> dict[str, Any]:
    if isinstance(answer, list):
        answer = answer[0] if answer and isinstance(answer[0], dict) else {}
    return answer if isinstance(answer, dict) else {}


def _stable(row: dict[str, Any], keep: tuple[str, ...] | None = None) -> dict[str, Any]:
    if keep is not None:
        return {k: row.get(k) for k in keep}
    return {k: v for k, v in row.items() if k not in VOLATILE_RULE_KEYS}


def _config(row: dict[str, Any]) -> dict[str, Any]:
    """A rule's settings apart from its on/off state."""
    return {k: v for k, v in row.items() if k not in ("disabled", "invalid")}


def _static(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in rows if not truthy(r.get("dynamic"))]


class Router:
    """What one read of the router returned, and the lookups normalisation needs."""

    def __init__(self, raw: dict[str, Any], wan_list: str = "WAN"):
        self.raw = raw
        self.ifaces = {str(r["name"]): r for r in raw.get("interfaces") or [] if r.get("name")}
        self.vlans = {str(r["name"]): r for r in raw.get("vlans") or [] if r.get("name")}
        self.lists = {str(r["name"]): r for r in raw.get("lists") or [] if r.get("name")}
        self.direct: dict[str, list[str]] = {}
        for member in raw.get("members") or []:
            if not truthy(member.get("disabled")) and member.get("list") and member.get("interface"):
                self.direct.setdefault(str(member["list"]), []).append(str(member["interface"]))
        self.addresses: dict[str, list[Any]] = {}
        for row in [*(raw.get("addresses") or []), *(raw.get("addresses6") or [])]:
            if truthy(row.get("disabled")) or truthy(row.get("invalid")):
                continue
            try:
                found = ipaddress.ip_interface(str(row.get("address") or "").split("%")[0])
            except ValueError:
                continue
            if found.ip.is_link_local:
                continue
            iface = str(row.get("actual-interface") or row.get("interface") or "")
            self.addresses.setdefault(iface, []).append(found)
        wan = next((name for name in self.lists if name.lower() == (wan_list or "WAN").lower()), wan_list)
        self.wan = set(self.members(wan) or [])
        lan = next((name for name in self.lists if name.lower() == "lan"), "LAN")
        self.lan = set(self.members(lan) or [])
        self.self_addresses = list(dict.fromkeys(str(a.ip) for found in self.addresses.values() for a in found))
        self.referenced: set[str] = set()
        self.notes: list[str] = []
        self.skipped: dict[str, int] = {}

    # -- interfaces and lists ----------------------------------------------------------------

    def members(self, name: str, depth: int = 0) -> list[str] | None:
        """Interface names of an interface list; None when it can be any interface (all, dynamic, static, unknown)."""
        if name == "none":
            return []
        if name in BUILTIN_LISTS or name not in self.lists or depth > 8:
            return None
        row = self.lists[name]
        out = list(self.direct.get(name) or [])
        for included in _split(row.get("include")):
            more = self.members(included, depth + 1)
            if more is None:
                return None
            out += more
        for excluded in _split(row.get("exclude")):
            less = self.members(excluded, depth + 1)
            if less is not None:  # excluding "all"/"dynamic"/... cannot be narrowed here: kept wider
                out = [i for i in out if i not in less]
        return list(dict.fromkeys(out))

    def interfaces_of(self, iface: Any, iface_list: Any) -> list[str] | None:
        """Interfaces a rule's in/out matchers name; None = any interface (floating); [] = none matches."""
        name, negated = _neg(iface)
        if name:
            if negated:
                return None  # "every interface but this one": read as floating (wider, never narrower)
            self.referenced.add(name)
            return [name]
        list_name, negated = _neg(iface_list)
        if not list_name:
            return None
        found = self.members(list_name)
        if negated or found is None:
            return None
        self.referenced.update(found)
        return found

    # -- address lists ---------------------------------------------------------------------

    @staticmethod
    def alias_name(table: str, name: str) -> str:
        return name if table == "ip" else f"ipv6:{name}"

    def aliases(self) -> list[dict[str, Any]]:
        out = []
        for table, key in (("ip", "address_lists"), ("ipv6", "address_lists6")):
            grouped: dict[str, dict[str, Any]] = {}
            for row in self.raw.get(key) or []:
                name = str(row.get("list") or "").strip()
                if not name or truthy(row.get("disabled")):
                    continue
                entry = grouped.setdefault(name, {"cidrs": [], "resolved": True, "count": 0})
                entry["count"] += 1
                if truthy(row.get("dynamic")) or str(row.get("timeout") or "").strip():
                    entry["resolved"] = False  # entries added at run time (rules, DNS, timeouts): membership changes
                cidrs = self.cidrs(row.get("address"))
                if cidrs is None:
                    entry["resolved"] = False  # a DNS name, resolved by the router at run time
                else:
                    entry["cidrs"] += cidrs
            for name, entry in grouped.items():
                cidrs = list(dict.fromkeys(entry["cidrs"]))
                big = entry["count"] > MAX_ALIAS_ENTRIES
                hosts = all(ipaddress.ip_network(c).num_addresses == 1 for c in cidrs)
                out.append({"name": self.alias_name(table, name), "kind": "host" if hosts and cidrs else "network",
                            "cidrs": [] if big else cidrs[:MAX_ALIAS_ENTRIES],
                            "resolved": entry["resolved"] and not big and bool(cidrs)})
        return out

    @staticmethod
    def cidrs(value: Any) -> list[str] | None:
        """Networks of an address matcher ("10.0.0.0/24", "10.0.0.5", "10.0.0.1-10.0.0.9"); None if not an address."""
        text = str(value or "").strip()
        cidr = normalise_cidr(text)
        if cidr:
            return [cidr]
        if "-" in text:
            low, _, high = text.partition("-")
            try:
                first, last = ipaddress.ip_address(low.strip()), ipaddress.ip_address(high.strip())
                return [str(n) for n in ipaddress.summarize_address_range(first, last)]
            except (ValueError, TypeError):
                return None
        return None

    # -- rules -----------------------------------------------------------------------------

    def endpoint(self, table: str, address: Any, address_list: Any) -> dict[str, Any]:
        addr, addr_neg = _neg(address)
        lst, lst_neg = _neg(address_list)
        if not addr and not lst:
            return {"any": True}
        cidrs = self.cidrs(addr) if addr else None
        if addr and cidrs is None:
            return {"any": True}
        alias = self.alias_name(table, lst) if lst else None
        if addr and alias:  # both must match: either one alone is wider than both
            if not addr_neg:
                return {"cidrs": cidrs}
            if not lst_neg:
                return {"aliases": [alias]}
            return {"cidrs": cidrs, "aliases": [alias], "negate": True}  # neither A nor B = not (A or B)
        if addr:
            return {"cidrs": cidrs, "negate": addr_neg}
        return {"aliases": [alias], "negate": lst_neg}

    @staticmethod
    def services(protocol: Any, dst_port: Any, port: Any) -> list[dict[str, Any]] | None:
        proto, negated = _neg(protocol)
        proto = proto.lower()
        if not proto or negated:
            return None
        proto = {"ipv6-icmp": "icmpv6", "icmpv6": "icmpv6"}.get(proto, proto)
        ports = None
        if proto in ("tcp", "udp", "udp-lite", "sctp", "dccp"):
            wanted, ports_negated = _neg(dst_port)
            if wanted and not ports_negated and not str(port or "").strip():  # "port" matches either side: any
                try:
                    ports = parse_ports(wanted)
                except ValueError:
                    ports = None
            return [{"proto": proto, "ports": ports}]
        return [{"proto": proto}]

    @staticmethod
    def chain_kinds(rows: list[dict[str, Any]]) -> dict[str, str]:
        """Which base chain each chain behaves like: a jump chain reached only from input is input, only from output
        is output, otherwise forward; chains no enabled rule jumps to are missing (never evaluated)."""
        jumps: dict[str, set[str]] = {}
        for row in rows:
            if str(row.get("action") or "") == "jump" and not truthy(row.get("disabled")) and row.get("jump-target"):
                jumps.setdefault(str(row.get("chain") or ""), set()).add(str(row["jump-target"]))
        reached: dict[str, set[str]] = {}
        for base in BASE_CHAINS:
            stack, seen = [base], set()
            while stack:
                chain = stack.pop()
                if chain in seen:
                    continue
                seen.add(chain)
                reached.setdefault(chain, set()).add(base)
                stack += sorted(jumps.get(chain, ()))
        out = {}
        for chain, bases in reached.items():
            out[chain] = chain if chain in BASE_CHAINS else \
                next(iter(bases)) if len(bases) == 1 and bases <= {"input", "output"} else "forward"
        return out

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def rule(self, row: dict[str, Any], table: str, order: int, kinds: dict[str, str]) -> dict[str, Any] | None:
        rid = str(row.get(".id") or "")
        if not ROW_ID_RE.match(rid):
            self.skip("without an id")
            return None
        action = ACTIONS.get(str(row.get("action") or "accept").strip().lower())
        if action is None:
            self.skip("jump, return, log, passthrough, address-list or fasttrack (no verdict of their own)")
            return None
        kind = kinds.get(str(row.get("chain") or ""))
        if kind is None:
            self.skip("in chains no enabled rule jumps to (never evaluated)")
            return None
        states, negated = _neg(row.get("connection-state"))
        if action == "pass" and states and not negated and not ({s.strip() for s in states.split(",")} - NOT_NEW):
            self.skip("accepting only established, related or untracked traffic (they open no new paths)")
            return None
        if action == "pass" and str(row.get("ipsec-policy") or "").strip().endswith(",ipsec"):
            self.skip("accepting only traffic under an IPsec policy (VPNs are not evaluated)")
            return None
        source = self.endpoint(table, row.get("src-address"), row.get("src-address-list"))
        destination = self.endpoint(table, row.get("dst-address"), row.get("dst-address-list"))
        ingress = egress = None
        if kind == "input":
            dst, dst_neg = _neg(row.get("dst-address"))
            cidrs = self.cidrs(dst) if dst else None
            if cidrs and not dst_neg and not any(ipaddress.ip_address(a) in ipaddress.ip_network(c)
                                                 for c in cidrs for a in self.self_addresses
                                                 if ipaddress.ip_address(a).version == ipaddress.ip_network(c).version):
                self.skip("for loopback, broadcast or multicast addresses of the router itself")
                return None
            destination = {"self": True}
            ingress = self.interfaces_of(row.get("in-interface"), row.get("in-interface-list"))
        elif kind == "output":
            source = {"self": True}
            egress = self.interfaces_of(row.get("out-interface"), row.get("out-interface-list"))
        else:
            ingress = self.interfaces_of(row.get("in-interface"), row.get("in-interface-list"))
            egress = self.interfaces_of(row.get("out-interface"), row.get("out-interface-list"))
        if ingress == [] or egress == []:
            self.skip("bound to the empty interface list 'none' (they match nothing)")
            return None
        packets = row.get("packets")  # UNVERIFIED: whether plain GET carries bytes/packets (else no hit counts)
        # UNVERIFIED: .id stability across reboots (a renumbered rule shows up as drift: removed + added)
        return {
            "id": f"{table}:{rid}", "vendor_ref": f"{table}:{rid}", "order": order,
            "enabled": not truthy(row.get("disabled")) and not truthy(row.get("invalid")), "action": action,
            "interfaces": ingress or [], "out_interfaces": egress or [],
            "floating": ingress is None and egress is None, "direction": "in", "quick": True,
            "source": source, "destination": destination,
            "services": self.services(row.get("protocol"), row.get("dst-port"), row.get("port")),
            "log": truthy(row.get("log")), "description": row.get("comment") or "",
            "hits": packets if str(packets or "").isdigit() else None,
        }


class MikrotikConnector(Connector):
    kind = "mikrotik"
    title = "MikroTik RouterOS"
    description = ("Router / firewall (RouterOS v7 REST API): reads interfaces, VLANs, interface lists, address lists "
                   "and the IPv4/IPv6 filter rules into the Network app; with device changes enabled, adds one accept "
                   "rule or disables rules, with an on-router undo job as the dead-man switch.")
    fields = [
        ConnectorField(name="base_url", label="Router URL", kind="url", required=True,
                       placeholder="https://192.168.88.1",
                       help="The https address of the router (IP > Services > www-ssl, with a certificate assigned)."),
        ConnectorField(name="username", label="User", required=True, default="atrium",
                       help="A dedicated RouterOS user. Its group needs read,api,rest-api (plus write for device "
                            "changes and ftp,test for configuration backups) - nothing else."),
        ConnectorField(name="password", label="Password", kind="secret", required=True),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the password again."),
        ConnectorField(name="ca_file", label="CA certificate file", kind="text",
                       placeholder="/etc/atrium/routeros-ca.pem",
                       help="PEM file on the hub's machine with the CA that signed the router's www-ssl certificate. "
                            "Empty: the system's trusted CAs."),
        ConnectorField(name="hub_address", label="Hub address as the router sees it", kind="text",
                       placeholder="192.168.88.10",
                       help="Optional. The management-path guard then only protects rules that carry the hub's own "
                            "REST traffic; empty, it protects every rule that lets traffic reach the router."),
        ConnectorField(name="wan_list", label="WAN interface list", kind="select", options=True, default="WAN",
                       help="The interface list whose members face the internet (the default configuration's 'WAN')."),
        ConnectorField(name="window_s", label="Undo window (seconds)", kind="number", default=DEFAULT_WINDOW,
                       help="How long a change stays on the router before its undo job reverts it, unless Atrium "
                            "has verified and confirmed it (60-900)."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this router through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "deadman", "window_s": DEFAULT_WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)
    sleep: Callable[[float], Any] = staticmethod(asyncio.sleep)

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("mikrotik", "routeros", "routerboard"))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        # switching certificate checks off would let the stored password go to whoever answers: enter it again
        return super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.hostname:
            raise ConnectorError("The router URL must start with https:// (the password travels in every request)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the user and password in their own fields, not in the URL")
        try:
            parts.port
        except ValueError as exc:
            raise ConnectorError("The router URL has an invalid port") from exc
        config["base_url"] = re.sub(r"(?i)/rest$", "", base)
        user = str(config.get("username") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", user):
            raise ConnectorError("User: 1-64 letters, digits, '.', '_', '-' or '@'")
        config["username"] = user
        ca_file = str(config.get("ca_file") or "").strip()
        if ca_file and not (os.path.isabs(ca_file) or PurePosixPath(ca_file).is_absolute()):
            raise ConnectorError("CA certificate file must be an absolute path on the hub's machine")
        hub_address = str(config.get("hub_address") or "").strip()
        if hub_address:
            try:
                config["hub_address"] = str(ipaddress.ip_address(hub_address))
            except ValueError as exc:
                raise ConnectorError("Hub address must be an IP address") from exc
        wan = str(config.get("wan_list") or "WAN").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", wan):
            raise ConnectorError("WAN interface list: 1-64 letters, digits, '.', '_' or '-'")
        config["wan_list"] = wan
        window = int(config.get("window_s") or DEFAULT_WINDOW)
        if not WINDOW_RANGE[0] <= window <= WINDOW_RANGE[1]:
            raise ConnectorError(f"The undo window is {WINDOW_RANGE[0]}-{WINDOW_RANGE[1]} seconds")
        config["window_s"] = window
        return config

    @property
    def window(self) -> int:
        try:
            window = int(self.config.get("window_s") or DEFAULT_WINDOW)
        except (TypeError, ValueError):
            window = DEFAULT_WINDOW
        return max(WINDOW_RANGE[0], min(WINDOW_RANGE[1], window))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only") or super().write_capability() is None:
            return None
        return {"ops": list(OPS), "rollback": "deadman", "window_s": self.window}

    # -- HTTP ------------------------------------------------------------------------------

    @property
    def host(self) -> str:
        return urlsplit(str(self.config.get("base_url") or "")).hostname or ""

    @property
    def api_port(self) -> int:
        return urlsplit(str(self.config.get("base_url") or "")).port or 443

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise TlsError(f"Cannot load the CA certificate file {ca_file}: "
                           f"{getattr(exc, 'strerror', None) or exc.__class__.__name__}") from exc
        if ca_file:  # a router-made CA is often not RFC 5280-strict; chain and host name are still checked
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        user, password = str(self.config.get("username") or ""), self.secrets.get("password")
        if not user or not password:
            raise self.error("Enter the RouterOS user and password in the connection settings")
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        # 60 s is RouterOS's own limit per request; a little more so its "Session closed" answer arrives
        return self.http(str(self.config.get("base_url") or "").rstrip("/") + "/rest",
                         auth=httpx.BasicAuth(user, password), headers={"Accept": "application/json"},
                         verify=verify, timeout=65.0)

    async def _send(self, client: httpx.AsyncClient, method: str, path: str, *, what: str,
                    body: Any = None) -> httpx.Response:
        where = f"{self.host}:{self.api_port}"
        try:
            if body is None:
                return await client.request(method, path)
            return await client.request(method, path, json=body)
        except httpx.TimeoutException as exc:
            raise self.error(f"RouterOS at {where} did not answer in time ({what})") from exc
        except httpx.ConnectError as exc:
            text = str(exc).lower()
            if "certificate_verify_failed" in text or "certificate verify failed" in text:
                raise TlsError(self.redact("The router's TLS certificate is not trusted - set the CA certificate "
                                           "file (the CA that signed the www-ssl certificate)")) from exc
            if any(s in text for s in ("handshake failure", "no shared cipher", "no_shared_cipher", "alert handshake",
                                       "wrong version number", "unexpected eof")):
                raise TlsError(f"RouterOS at {where} offered no usable TLS certificate - assign a certificate to the "
                               "www-ssl service (IP > Services)") from exc
            raise self.error(f"Cannot reach RouterOS at {where} ({exc.__class__.__name__})") from exc
        except (httpx.ReadError, httpx.RemoteProtocolError) as exc:
            raise self.error(f"RouterOS at {where} closed the connection ({what}) - check that the www-ssl service's "
                             "'available from' includes the hub") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach RouterOS: {exc.__class__.__name__}") from exc

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        """RouterOS's own error detail (device text: shortened, never trusted)."""
        try:
            answer = response.json()
        except ValueError:
            return ""
        if isinstance(answer, dict):
            return untrusted_text(answer.get("detail") or answer.get("message") or "", 160)
        return ""

    async def _call(self, client: httpx.AsyncClient, method: str, path: str, *, what: str, body: Any = None,
                    policy: str = "read") -> Any:
        """The JSON answer of one REST call; a ConnectorError (with the policy to grant) otherwise."""
        response = await self._send(client, method, path, what=what, body=body)
        code = response.status_code
        if code == 401:
            raise self.error("RouterOS rejected the login (HTTP 401) - check the user and password, that the user's "
                             "group has the 'rest-api' policy and that the user's allowed address includes the hub",
                             status=401)
        if code == 403:
            raise self.error("RouterOS refused the REST request (HTTP 403): the REST API is off for HTTPS on this "
                             "router - check IP > Services (www-ssl)", status=403)
        if code in (301, 302, 303, 307, 308):
            raise self.error("RouterOS redirected the request - use the exact https:// address of the router",
                             status=code)
        if code == 404:
            raise self.error(f"RouterOS has no such item ({what})", status=404)
        if code >= 300:
            detail = self._detail(response)
            lowered = detail.lower()
            if "not allowed" in lowered:
                message = "the user's group lacks the 'api' policy (the REST API logs in through the API)"
            elif "not enough permissions" in lowered:
                message = f"the user's group lacks the policy this needs ('{policy}')"
            elif "no such command" in lowered:
                message = "this RouterOS version has no such menu or command"
            elif "session closed" in lowered:
                message = "RouterOS ended the request at its 60 s limit"
            else:
                message = detail or f"HTTP {code}"
            raise self.error(f"RouterOS could not {what} (HTTP {code}): {message}", status=code)
        if code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise self.error(f"RouterOS did not answer with JSON ({what}) - is the URL the router's address?",
                             status=code) from exc

    async def _optional(self, client: httpx.AsyncClient, path: str, *, what: str) -> tuple[Any, str | None]:
        """(answer, None), or (None, a note) when this router or user cannot read it."""
        try:
            return await self._call(client, "GET", path, what=what), None
        except ConnectorError as exc:
            if exc.status in (400, 404, 500):
                return None, f"{what}: not readable ({exc.message.split(': ', 1)[-1]})"
            raise

    # -- reading ---------------------------------------------------------------------------

    async def read(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Everything a snapshot needs, as RouterOS answered it (rows of untrusted device data)."""
        resource = _obj(await self._call(client, "GET", "/system/resource", what="read the version"))
        version = parse_version(resource.get("version"))
        if version is None or version[:2] < MIN_VERSION:
            raise self.error("RouterOS answered without a v7 version - Atrium needs RouterOS 7.1 or later")
        notes: list[str] = []
        identity, _ = await self._optional(client, "/system/identity", what="the router's name")
        board, _ = await self._optional(client, "/system/routerboard", what="the RouterBOARD")
        raw: dict[str, Any] = {"version": version, "resource": resource, "identity": _obj(identity),
                               "routerboard": _obj(board)}
        for key, path, what in (("interfaces", "/interface", "read the interfaces"),
                                ("vlans", "/interface/vlan", "read the VLANs"),
                                ("addresses", "/ip/address", "read the IP addresses"),
                                ("lists", "/interface/list", "read the interface lists"),
                                ("members", "/interface/list/member", "read the interface list members"),
                                ("filter", TABLES["ip"], "read the firewall rules")):
            raw[key] = _rows(await self._call(client, "GET", path, what=what), what)
        # address lists can be huge (block lists): one that cannot be read in RouterOS's 60 s leaves its rules'
        # lists unknown, which the hub reads as "any address" (wider, never narrower)
        for key, path, what in (("address_lists", "/ip/firewall/address-list"
                                 + _query(_proplist="list,address,disabled,dynamic,timeout"), "address lists"),
                                ("addresses6", "/ipv6/address", "IPv6 addresses"),
                                ("filter6", TABLES["ipv6"], "IPv6 firewall rules"),
                                ("address_lists6", "/ipv6/firewall/address-list"
                                 + _query(_proplist="list,address,disabled,dynamic,timeout"), "IPv6 address lists")):
            answer, note = await self._optional(client, path, what=what)
            raw[key] = _rows(answer, what) if answer is not None else []
            if note:
                notes.append(note)
        raw["ipv6"] = not any(n.startswith("IPv6 firewall rules") for n in notes)
        raw["notes"] = notes
        raw["read_at"] = self.clock()
        return raw

    def revision(self, raw: dict[str, Any]) -> str:
        return derived_revision(
            [_stable(r) for r in _static(raw.get("filter") or [])],
            [_stable(r) for r in _static(raw.get("filter6") or [])],
            [_stable(r, ("list", "address", "disabled")) for key in ("address_lists", "address_lists6")
             for r in _static(raw.get(key) or []) if not str(r.get("timeout") or "").strip()],
            [_stable(r, ("name", "type", "disabled", "comment")) for r in raw.get("interfaces") or []],
            [_stable(r, ("name", "vlan-id", "interface", "disabled")) for r in raw.get("vlans") or []],
            [_stable(r, ("name", "include", "exclude")) for r in raw.get("lists") or []],
            [_stable(r, ("list", "interface", "disabled")) for r in _static(raw.get("members") or [])],
            [_stable(r, ("address", "interface", "disabled")) for key in ("addresses", "addresses6")
             for r in _static(raw.get(key) or [])])

    def to_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        """The normalised device record (netmodel) for one read."""
        router = Router(raw, str(self.config.get("wan_list") or "WAN"))
        rules: list[dict[str, Any]] = []
        for table, key, offset in (("ip", "filter", 0), ("ipv6", "filter6", 50_000)):
            rows = raw.get(key) or []
            kinds = router.chain_kinds(rows)
            for index, row in enumerate(rows, start=1):
                rule = router.rule(row, table, offset + index, kinds)
                if rule is not None:
                    rules.append(rule)
        interfaces = []
        for name, row in router.ifaces.items():
            found = router.addresses.get(name) or []
            if not (found or name in router.vlans or name in router.referenced or name in router.wan):
                continue  # bridge ports and unused ports: not zones of their own
            vlan = str((router.vlans.get(name) or {}).get("vlan-id") or "")
            interfaces.append({
                "id": name, "name": name, "description": row.get("comment") or str(row.get("type") or ""),
                "vlan": int(vlan) if vlan.isdigit() and 1 <= int(vlan) <= 4094 else None,
                "subnets": list(dict.fromkeys(str(a.network) for a in found)), "addresses": [str(a.ip) for a in found],
                "role": "wan" if name in router.wan else "lan" if name in router.lan else "other",
                "enabled": not truthy(row.get("disabled")),
            })
        resource, identity, board = raw.get("resource") or {}, raw.get("identity") or {}, raw.get("routerboard") or {}
        version = raw.get("version")
        name = untrusted_text(identity.get("name"), 120)
        serial = untrusted_text(board.get("serial-number"), 120)
        notes = list(raw.get("notes") or [])
        notes.append("interface lists are read as their member interfaces; rules in jump chains are read without the "
                     "conditions of the jump that reaches them")
        notes.append("RouterOS accepts packets no rule drops: the map shows explicit accept rules only, and NAT "
                     "(dst-nat port forwards) is not evaluated")
        for reason, count in sorted(router.skipped.items()):
            notes.append(f"{count} rule(s) not listed: {reason}")
        if not any(str(r.get("packets") or "").isdigit() for r in raw.get("filter") or []):
            notes.append("hit counts are not available")
        if not raw.get("ipv6", True):
            notes.append("the IPv6 firewall was not read")
        return {
            "external_id": serial or name or self.host, "revision": self.revision(raw), "read_at": raw.get("read_at"),
            "kind": "router",
            "device": {"vendor": "MikroTik", "model": untrusted_text(resource.get("board-name"), 120),
                       "version": ".".join(map(str, version)) if version else "", "hostname": name,
                       "management_address": self.host, "serial": serial},
            "interfaces": interfaces, "zones": [], "aliases": router.aliases(),
            "self_addresses": router.self_addresses, "rules": rules,
            "default_policy": {"inbound": "pass", "forward": "pass", "outbound": "pass"},
            "nat_evaluated": False, "notes": notes[:50],
        }

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"RouterOS cannot read {domain}")
        async with self.client() as client:
            return [self.to_record(await self.read(client))]

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name != "wan_list":
            raise self.error(f"RouterOS has no choices for '{field_name}'")
        async with self.client() as client:
            rows = _rows(await self._call(client, "GET", "/interface/list", what="read the interface lists"),
                         "read the interface lists")
        names = [str(r.get("name") or "") for r in rows]
        return [{"value": n, "label": untrusted_text(n, 64)} for n in names
                if re.fullmatch(r"[A-Za-z0-9._-]{1,64}", n) and n not in BUILTIN_LISTS]

    # -- test ------------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def result(ok: bool, detail: str, write: dict[str, Any] | None = None) -> dict[str, Any]:
            return {"ok": ok, "detail": detail, "checks": checks, "domains": self.domains() if ok else {},
                    "network_write": write if ok else None}

        try:
            client = self.client()
        except ConnectorError as exc:
            checks.append(check("tls" if isinstance(exc, TlsError) else "authentication", False, exc.message))
            return result(False, exc.message)
        where = f"{self.host}:{self.api_port}"
        verify = "verification is OFF - anyone on the path could read the password" \
            if not self.config.get("verify_tls", True) else \
            f"certificate verified with {self.config['ca_file']}" if self.config.get("ca_file") else \
            "certificate verified with the system's trusted CAs"
        async with client:
            try:
                resource = _obj(await self._call(client, "GET", "/system/resource", what="read the version"))
            except TlsError as exc:
                checks.append(check("reachability", True, f"{where} answers"))
                checks.append(check("tls", False, exc.message))
                return result(False, exc.message)
            except ConnectorError as exc:
                if exc.status is None:
                    checks.append(check("reachability", False, exc.message))
                    return result(False, exc.message)
                checks.append(check("reachability", True, f"{where} answers"))
                checks.append(check("tls", True, verify))
                checks.append(check("authentication", exc.status not in (401, 403), exc.message if exc.status in
                                    (401, 403) else "logged in, but: " + exc.message))
                if exc.status not in (401, 403):
                    checks.append(check("privileges", False, exc.message))
                return result(False, exc.message)
            checks.append(check("reachability", True, f"{where} answers"))
            checks.append(check("tls", bool(self.config.get("verify_tls", True)), verify))
            checks.append(check("authentication", True, f"logged in as {self.config.get('username')}"))
            version = parse_version(resource.get("version"))
            policies, group = await self._policies(client)
            access = await self._probe(client)
            write = self._write_spec(version, policies, access)
            readable = access["rules"] and access["interfaces"]
            checks.append(check("privileges", readable, self._privilege_detail(group, policies, access, write)))
            supported = version is not None and version[:2] >= MIN_VERSION
            vtext = ".".join(map(str, version)) if version else "unknown"
            board = untrusted_text(resource.get("board-name"), 60)
            checks.append(check("version", supported, f"RouterOS {vtext}" + (f" on {board}" if board else "") + " - "
                                + ("supported" if supported else "not supported: Atrium needs RouterOS 7.1 or later "
                                                                 "(the REST API)")))
            checks.append(check("api_features", True, self._features(access, policies)))
            record = None
            if readable and supported:
                try:
                    record = normalize_record(self.to_record(await self.read(client)))
                    checks.append(check("ruleset", True, f"{len(record['rules'])} rules, {len(record['interfaces'])} "
                                                         f"interfaces, {len(record['aliases'])} address lists read"
                                        + (f"; {len(record['errors'])} entries skipped" if record["errors"] else "")))
                except ConnectorError as exc:
                    checks.append(check("ruleset", False, exc.message))
            checks.append(check("clock", access["clock"] is not None, access["clock_detail"]))
            if access["pending"]:
                checks.append(check("pending_change", False, f"{len(access['pending'])} Atrium undo job(s) are armed "
                                    "on the router: a change is waiting for confirmation (or was left behind)"))
            checks.append(check("management_guard", True,
                                f"protects rules carrying the hub's traffic from {self.config['hub_address']} to port "
                                f"{self.api_port}" if self.config.get("hub_address") else
                                "no hub address set: disabling any rule that lets traffic reach the router is refused "
                                "(set the hub address to narrow this)"))
        ok = bool(readable and supported and record is not None)
        name = untrusted_text(resource.get("board-name"), 60)
        what = f"RouterOS {vtext}" + (f" ({name})" if name else "")
        detail = (f"Connected to {what}: {len(record['rules'])} rules" if record else
                  f"{what}: " + next((c["detail"] for c in checks if not c["ok"] and c["name"] != "tls"),
                                     "cannot read the rules"))
        return result(ok, detail + ("" if write else " (read only)") if ok else detail, write)

    async def _policies(self, client: httpx.AsyncClient) -> tuple[set[str] | None, str]:
        """The policies of this user's group (None when they cannot be read) and the group's name."""
        user = str(self.config.get("username") or "")
        try:
            users = _rows(await self._call(client, "GET", "/user" + _query(name=user, _proplist="name,group"),
                                           what="read the user"), "read the user")
            group = str(next((u.get("group") for u in users if u.get("name") == user), "") or "")
            if not group:
                return None, ""
            groups = _rows(await self._call(client, "GET", "/user/group" + _query(name=group, _proplist="name,policy"),
                                            what="read the user's group"), "read the user's group")
        except ConnectorError as exc:
            if exc.status in (400, 404, 500):
                return None, ""
            raise
        row = next((g for g in groups if g.get("name") == group), None)
        if row is None or row.get("policy") is None:
            return None, group
        # UNVERIFIED: "read,write,api,rest-api,!ftp,..." - denied policies carry "!"
        return {p for p in _split(row.get("policy")) if not p.startswith("!")}, group

    async def _probe(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Which reads work, the router clock and armed Atrium undo jobs - every probe without side effects."""
        out: dict[str, Any] = {}
        for name, path in (("rules", TABLES["ip"] + _query(_proplist=".id")),
                           ("rules6", TABLES["ipv6"] + _query(_proplist=".id")),
                           ("interfaces", "/interface" + _query(_proplist="name")),
                           ("lists", "/interface/list" + _query(_proplist="name")),
                           ("address_lists", "/ip/firewall/address-list" + _query(_proplist="list"))):
            try:
                await self._call(client, "GET", path, what=name)
                out[name] = True
            except ConnectorError as exc:
                if exc.status not in (400, 404, 500):
                    raise
                out[name] = False
        out["clock"], out["clock_detail"] = None, "cannot read the router clock (/system/clock)"
        try:
            clock = _obj(await self._call(client, "GET", "/system/clock", what="read the clock"))
            moment, _ = parse_clock(clock)
            out["clock"] = moment
            offset = gmt_offset(clock.get("gmt-offset"))
            skew = ""
            if offset is not None:
                utc = moment.replace(tzinfo=timezone.utc) - timedelta(seconds=offset)
                drift = abs(utc.timestamp() - self.clock())
                skew = f"; {int(drift)} s from the hub's clock" if drift >= 2 else "; in step with the hub"
            zone = untrusted_text(clock.get("time-zone-name"), 40)
            out["clock_detail"] = (f"router time {moment:%Y-%m-%d %H:%M:%S}" + (f" ({zone})" if zone else "") + skew
                                   + " - the undo job is scheduled in router time")
        except ValueError as exc:
            out["clock_detail"] = str(exc)
        except ConnectorError:
            pass
        try:
            out["pending"] = await self._pending(client)
            out["scheduler"] = True
        except ConnectorError:
            out["pending"], out["scheduler"] = [], False
        return out

    async def _pending(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        """Armed Atrium undo jobs (only names and timing are read: other jobs' scripts are never fetched)."""
        path = "/system/scheduler" + _query(_proplist=".id,name,next-run,disabled")
        rows = _rows(await self._call(client, "GET", path, what="read the scheduler"), "read the scheduler")
        # UNVERIFIED: "next-run" in REST output - a job without the field counts as armed, an empty one as spent
        return [r for r in rows if SCHEDULER_RE.match(str(r.get("name") or "")) and not truthy(r.get("disabled"))
                and str(r.get("next-run", "armed") or "").strip()]

    def _write_spec(self, version: tuple[int, int, int] | None, policies: set[str] | None,
                    access: dict[str, Any]) -> dict[str, Any] | None:
        if self.write_capability() is None or not (access.get("rules") and access.get("interfaces")):
            return None
        if version is None or version[:2] < MIN_VERSION or policies is None or "write" not in policies:
            return None
        if access.get("clock") is None or not access.get("scheduler"):
            return None
        return self.write_capability()

    def _privilege_detail(self, group: str, policies: set[str] | None, access: dict[str, Any],
                          write: dict[str, Any] | None) -> str:
        missing = [k for k in ("rules", "interfaces") if not access.get(k)]
        if missing:
            return "cannot read " + " and ".join("the firewall rules" if k == "rules" else "the interfaces"
                                                for k in missing) + " - the group needs the 'read' policy"
        if policies is None:
            return ("reads rules and interfaces; cannot read the user's group policies (/user, /user/group), so "
                    "device changes are unavailable")
        parts = [f"group {display_id(group)}: " + ",".join(sorted(p for p in policies if p in
                                                                   (*NEEDED, *FOR_CHANGES, *FOR_BACKUPS, *EXTRA)))]
        extra = sorted(p for p in policies if p in EXTRA)
        if extra:
            parts.append("not needed by Atrium: " + ", ".join(extra) + " - a custom group with read,api,rest-api "
                         "(plus write for changes and ftp,test for backups) is enough")
        if "write" not in policies:
            parts.append("read only (no 'write' policy) - recommended until device changes are enabled; changes are "
                         "unavailable")
        elif self.config.get("read_only"):
            parts.append("the user can write, but this connection is set to read only")
        else:
            parts.append(LEAST_PRIVILEGE_NOTE)
        if not set(FOR_BACKUPS) <= policies:
            parts.append("configuration backups need the 'ftp' and 'test' policies (with the backup guardrail on, "
                         "changes need a backup)")
        if write is None and "write" in policies and not self.config.get("read_only"):
            parts.append("changes are unavailable: the clock or the scheduler cannot be read")
        return "; ".join(parts)

    @staticmethod
    def _features(access: dict[str, Any], policies: set[str] | None) -> str:
        parts = ["no commit step: each REST call takes effect at once",
                 "no Safe Mode over REST: Atrium arms a one-shot scheduler job that undoes a change unless it is "
                 "confirmed in time"]
        parts.append("IPv6 firewall: " + ("yes" if access.get("rules6") else "not readable"))
        parts.append("configuration exports: " + ("yes" if policies and set(FOR_BACKUPS) <= policies else
                                                  "no (needs ftp,test)" if policies is not None else "unknown"))
        return "; ".join(parts)

    # -- backups ---------------------------------------------------------------------------

    async def _export(self, client: httpx.AsyncClient) -> str:
        """The router's configuration export (passwords and keys left out), read in chunks and deleted afterwards."""
        name = f"atrium-bk-{pysecrets.token_hex(6)}"
        assert EXPORT_RE.match(name)
        await self._call(client, "POST", "/export", body={"file": name}, what="export the configuration",
                         policy="ftp")
        chunks, size, offset, attempts = [], 0, 0, 0
        try:
            while True:
                try:
                    answer = await self._call(client, "POST", "/file/read", what="read the exported configuration",
                                              body={"file": f"{name}.rsc", "chunk-size": str(CHUNK),
                                                    "offset": str(offset)}, policy="ftp,test")
                except ConnectorError as exc:
                    attempts += 1
                    if offset == 0 and exc.status == 400 and attempts < 4:  # the file may not be listed yet
                        await self.sleep(1)
                        continue
                    raise
                data = str(_obj(answer).get("data") or "")
                if not data:
                    break
                chunk = data.encode("utf-8")  # UNVERIFIED: how /file/read encodes non-ASCII bytes
                chunks.append(chunk)
                size += len(chunk)
                offset += len(chunk)
                if size > MAX_EXPORT:
                    raise self.error("The router's configuration export is larger than 16 MB")
        finally:
            try:
                await self._call(client, "DELETE", f"/file/{name}.rsc", what="delete the exported file", policy="ftp")
            except ConnectorError:
                pass  # a leftover export in the router's files holds no passwords or keys
        text = b"".join(chunks).decode("utf-8", errors="replace")
        if "/" not in text:
            raise self.error("The router's configuration export came back empty")
        return text

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            raw = await self.read(client)
            export = await self._export(client)
        revision = self.revision(raw)
        content = json.dumps({
            "format": "atrium-routeros-backup", "v": 1, "router": self.host,
            "routeros": ".".join(map(str, raw["version"])), "revision": revision,
            "filter": {"ip": [_stable(r) for r in _static(raw.get("filter") or [])],
                       "ipv6": [_stable(r) for r in _static(raw.get("filter6") or [])]},
            "export": export,
            "note": "RouterOS export without passwords and keys; restore it with /import by hand",
        }, sort_keys=True, indent=1).encode("utf-8")
        return {"content": content, "format": "json", "device_backup_id": None, "revision": revision,
                "sha256": hashlib.sha256(content).hexdigest()}

    # -- changes ---------------------------------------------------------------------------

    def _guard(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
        hub = [self.config["hub_address"]] if self.config.get("hub_address") else None
        return management_guard(record, ops, hub_addresses=hub, management_ports=[self.api_port])

    @staticmethod
    def _family(op: dict[str, Any]) -> int | None:
        families = {ipaddress.ip_network(c).version for side in ("source", "destination") for c in op[side]["cidrs"]}
        return families.pop() if len(families) == 1 else None

    @staticmethod
    def _position(raw: dict[str, Any], table: str) -> tuple[str | None, int | None]:
        """(.id to place the new rule before, its position) - the first enabled static rule in the forward chain that
        can drop, reject or jump (a rule matching only invalid packets stays above), else None (append)."""
        for index, row in enumerate(raw.get("filter" if table == "ip" else "filter6") or [], start=1):
            if str(row.get("chain") or "") != "forward" or truthy(row.get("dynamic")) or truthy(row.get("disabled")):
                continue
            if str(row.get("action") or "") not in ("drop", "reject", "tarpit", "jump"):
                continue
            states, negated = _neg(row.get("connection-state"))
            if states and not negated and {s.strip() for s in states.split(",")} == {"invalid"}:
                continue
            rid = str(row.get(".id") or "")
            if ROW_ID_RE.match(rid):
                return rid, index + (0 if table == "ip" else 50_000)
        return None, None

    def _check(self, ops: list[dict[str, Any]], raw: dict[str, Any], record: dict[str, Any]
               ) -> tuple[list[str], list[str], list[dict[str, Any]], list[str]]:
        """(guard problems, other problems, preview steps, notes) for `ops` against what the router holds now."""
        router = Router(raw, str(self.config.get("wan_list") or "WAN"))
        problems, steps = [], []
        notes = ["RouterOS applies each rule as soon as it is written (no commit step)"]
        rows = {"ip": {str(r.get(".id")): r for r in raw.get("filter") or []},
                "ipv6": {str(r.get(".id")): r for r in raw.get("filter6") or []}}
        markers = {find_marker(r.get("comment")) for t in ("filter", "filter6") for r in raw.get(t) or []} - {None}
        for index, op in enumerate(ops):
            n = index + 1
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    row = router.ifaces.get(zone)
                    if row is None:
                        problems.append(f"operation {n}: RouterOS has no interface '{display_id(zone)}'")
                    elif side == "source" and truthy(row.get("disabled")):
                        problems.append(f"operation {n}: interface {display_id(zone)} is disabled")
                    if len(op[side]["cidrs"]) != 1:
                        problems.append(f"operation {n}: a RouterOS rule takes one {side} network - split the change "
                                        "or use one network per side")
                family = self._family(op)
                if family is None:
                    problems.append(f"operation {n}: IPv4 and IPv6 networks cannot share one rule")
                elif family == 6 and not raw.get("ipv6", True):
                    problems.append(f"operation {n}: the IPv6 firewall cannot be read on this router")
                if len(op["services"]) != 1:
                    problems.append(f"operation {n}: a RouterOS rule carries one protocol and one port list - put "
                                    "the ports in one service (e.g. tcp 80,443) or split the change")
                elif op["services"][0]["proto"] == "icmp" and family == 6:
                    problems.append(f"operation {n}: ICMP rules are IPv4 only in this connector")
                if find_marker(op["marker"]) in markers:
                    problems.append(f"operation {n}: a rule marked {op['marker']} is already on the router "
                                    "(re-read it)")
                table = "ipv6" if family == 6 else "ip"
                before, position = self._position(raw, table)
                service = op["services"][0]
                ports = f" {service['ports']}" if service.get("ports") else ""
                steps.append({"op": index, "kind": "add_rule",
                              "position": f"forward chain, before rule #{position}" if before else
                                          "end of the forward chain",
                              "detail": f"accept {service['proto']}{ports} in on {display_id(op['source']['zone'])} "
                                        f"out on {display_id(op['destination']['zone'])}, marked {op['marker']}"})
            else:
                verb = "disable" if op["op"] == "disable_rules" else "enable"
                for ref in op["rules"]:
                    match = REF_RE.match(ref["vendor_ref"]) or REF_RE.match(ref["id"])
                    row = rows[match.group(1)].get(match.group(2)) if match else None
                    if row is None:
                        problems.append(f"rule {display_id(ref['id'])} is not on the router (re-read it first)")
                    elif truthy(row.get("dynamic")):
                        problems.append(f"rule {display_id(ref['id'])} is dynamic (made by a RouterOS service) and "
                                        "cannot be changed")
                    steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place",
                                  "detail": f"{verb} {display_id(ref['vendor_ref'])}"})
        notes.append(f"RouterOS undoes the change by itself {self.window} s after it is written unless Atrium confirms "
                     "it (an on-router scheduler job)")
        return self._guard(record, ops), problems, steps, notes

    async def _state(self, client: httpx.AsyncClient) -> tuple[dict[str, Any], dict[str, Any]]:
        raw = await self.read(client)
        return raw, normalize_record(self.to_record(raw))

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.client() as client:
            raw, record = await self._state(client)
            pending = await self._pending(client)
        guard, problems, steps, notes = self._check(ops, raw, record)
        if self.write_capability() is None:
            problems.append("this connection is set to read only")
        if pending:
            problems.append("another Atrium change is waiting for confirmation on this router")
        if record["revision"] != snapshot.get("revision"):
            notes.append("the router changed since the snapshot: refresh before approving")
        return {"steps": steps, "notes": notes, "problems": guard + problems}

    @staticmethod
    def _token(info: dict[str, Any]) -> str:
        return json.dumps(info, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _parse_token(token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and info.get("mode") == "deadman"
            assert SCHEDULER_RE.match(str(info.get("sched") or ""))
            assert info.get("sched_id") is None or ROW_ID_RE.match(str(info["sched_id"]))
            assert all(REF_RE.match(str(r)) for r in info.get("created") or [])
            assert all(REF_RE.match(str(r)) and s in ("true", "false") for r, s in (info.get("toggled") or {}).items())
            assert all(t in TABLES and SAFE_COMMENT_RE.match(str(c)) for t, c in info.get("comments") or [])
            float(info.get("deadline") or 0)
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this RouterOS connector", code="invalid", state="unknown") from exc
        return info

    @staticmethod
    def _script(info: dict[str, Any]) -> str:
        """The undo job: remove the rules this change adds, put the rules it toggles back, then remove the job itself.
        Every value in it is validated (comments by SAFE_COMMENT_RE, ids by REF_RE, the job name by SCHEDULER_RE);
        each step runs on its own so one missing rule does not stop the others."""
        # UNVERIFIED: [find comment="..."] (exact match) and "set *1A ..." with an internal id are community usage;
        # ":do { } on-error={}" is on the official Scripting page. REST undo does not depend on this script.
        lines = []
        for table, comment in info["comments"]:
            assert table in TABLES and SAFE_COMMENT_RE.match(comment)
            lines.append(f':do {{ {SCRIPT_MENUS[table]} remove [find comment="{comment}"] }} on-error={{}}')
        for ref, previous in info["toggled"].items():
            match = REF_RE.match(ref)
            assert match and previous in ("true", "false")
            value = "yes" if previous == "true" else "no"
            menu = SCRIPT_MENUS[match.group(1)]
            lines.append(f":do {{ {menu} set {match.group(2)} disabled={value} }} on-error={{}}")
        assert SCHEDULER_RE.match(info["sched"])
        lines.append(f'/system scheduler remove [find name="{info["sched"]}"]')
        return "\n".join(lines)

    def _plan(self, ops: list[dict[str, Any]], raw: dict[str, Any]) -> list[dict[str, Any]]:
        """The REST writes for `ops`, in order."""
        plan = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                table = "ipv6" if self._family(op) == 6 else "ip"
                service = op["services"][0]
                body = {"chain": "forward", "action": "accept", "in-interface": op["source"]["zone"],
                        "out-interface": op["destination"]["zone"], "src-address": op["source"]["cidrs"][0],
                        "dst-address": op["destination"]["cidrs"][0], "protocol": service["proto"],
                        "comment": safe_comment(op), "log": bool(op.get("log", True))}
                if service.get("ports"):
                    body["dst-port"] = service["ports"]
                before, _ = self._position(raw, table)
                if before:
                    body["place-before"] = before
                plan.append({"kind": "add", "op": index, "table": table, "body": body})
            else:
                for ref in op["rules"]:
                    match = REF_RE.match(ref["vendor_ref"]) or REF_RE.match(ref["id"])
                    assert match
                    plan.append({"kind": "set", "op": index, "table": match.group(1), "id": match.group(2),
                                 "disabled": "true" if op["op"] == "disable_rules" else "false"})
        return plan

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str,
                           backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This RouterOS connection is set to read only", code="unsupported", state="unchanged")
        try:
            client = self.client()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="invalid", state="unchanged") from exc
        async with client:
            try:
                raw, record = await self._state(client)
                pending = await self._pending(client)
                clock = _obj(await self._call(client, "GET", "/system/clock", what="read the clock"))
                router_now, style = parse_clock(clock)
                armed_at = self.clock()
            except ValueError as exc:
                raise ChangeError(f"{exc} - nothing was changed", code="failed", state="unchanged") from exc
            except ConnectorError as exc:
                raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                  state="unchanged") from exc
            if record["revision"] != base_revision:
                raise ChangeError("The router's configuration changed since the preview - re-read it and preview again",
                                  code="stale", state="unchanged")
            guard, problems, _, _ = self._check(ops, raw, record)
            if guard:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(guard), code="lockout",
                                  state="unchanged")
            if pending:
                problems.append("another Atrium change is waiting for confirmation on this router")
            if problems:
                raise ChangeError("; ".join(problems), code="invalid", state="unchanged")
            plan = self._plan(ops, raw)
            rows = {"ip": {str(r.get(".id")): r for r in raw.get("filter") or []},
                    "ipv6": {str(r.get(".id")): r for r in raw.get("filter6") or []}}
            info: dict[str, Any] = {
                "v": 1, "mode": "deadman", "sched": f"atrium-rb-{pysecrets.token_hex(6)}", "sched_id": None,
                "created": [], "deadline": armed_at + self.window,
                "comments": [[p["table"], p["body"]["comment"]] for p in plan if p["kind"] == "add"],
                "toggled": {f"{p['table']}:{p['id']}": "true" if truthy(rows[p["table"]][p["id"]].get("disabled"))
                            else "false" for p in plan if p["kind"] == "set"},
            }
            longest = {**info, "sched_id": "*FFFFFFFF", "created": ["ipv6:*FFFFFFFF"] * len(plan)}
            if len(self._token(longest)) > MAX_TOKEN:
                raise ChangeError("Too many rules in one change for RouterOS - split it", code="invalid",
                                  state="unchanged")
            await self._arm(client, info, router_now + timedelta(seconds=self.window), style)
            created: list[dict[str, Any]] = []
            disabled, enabled = [], []
            try:
                for step in plan:
                    path = TABLES[step["table"]]
                    if step["kind"] == "add":
                        answer = await self._write(client, "PUT", path, step["body"], "add the rule")
                        rid = str(_obj(answer).get(".id") or "")
                        if not ROW_ID_RE.match(rid):
                            raise ChangeError("RouterOS added the rule but did not answer with its id", code="failed",
                                              state="unknown")
                        ref = f"{step['table']}:{rid}"
                        info["created"].append(ref)
                        created.append({"op": step["op"], "id": ref, "vendor_ref": ref})
                    else:
                        ref = f"{step['table']}:{step['id']}"
                        answer = await self._write(client, "PATCH", f"{path}/{step['id']}",
                                                   {"disabled": step["disabled"] == "true"},
                                                   f"change rule {display_id(ref)}")
                        if _obj(answer) and truthy(_obj(answer).get("disabled")) != (step["disabled"] == "true"):
                            raise ChangeError(f"RouterOS did not change rule {display_id(ref)}", code="failed",
                                              state="unknown")
                        (disabled if step["disabled"] == "true" else enabled).append(ref)
            except ChangeError as exc:
                state = await self._undo(client, info)
                raise ChangeError(exc.message + (" - undone" if state == "unchanged" else
                                                 f" - undoing it failed; the router's undo job reverts it within "
                                                 f"{self.window} s"), code=exc.code, state=state) from exc
        return {"token": self._token(info), "rollback_until": info["deadline"], "revision": None, "created": created,
                "disabled": disabled, "enabled": enabled,
                "notes": [f"undo job {info['sched']} reverts the change at router time "
                          f"{router_now + timedelta(seconds=self.window):%H:%M:%S} unless it is confirmed"]}

    # requests send flags as JSON booleans ("disabled": true is a documented request form); replies are strings
    async def _write(self, client: httpx.AsyncClient, method: str, path: str, body: dict[str, Any], what: str) -> Any:
        try:
            return await self._call(client, method, path, body=body, what=what, policy="write")
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else
                              "invalid" if exc.status == 400 else "failed", state="unknown", status=exc.status) from exc

    async def _arm(self, client: httpx.AsyncClient, info: dict[str, Any], start: datetime, style: str) -> None:
        """Add the undo job and check the router scheduled it - before anything is written."""
        body = {"name": info["sched"], "start-date": format_date(start, style), "start-time": f"{start:%H:%M:%S}",
                "interval": "0s", "policy": "read,write", "on-event": self._script(info)}
        try:
            answer = await self._call(client, "PUT", "/system/scheduler", body=body, what="arm the undo job",
                                      policy="write")
            sched_id = str(_obj(answer).get(".id") or "")
            if not ROW_ID_RE.match(sched_id):
                raise ChangeError("RouterOS added the undo job but did not answer with its id", code="failed",
                                  state="unchanged")
            info["sched_id"] = sched_id
            row = _obj(await self._call(client, "GET", f"/system/scheduler/{sched_id}", what="check the undo job"))
        except ChangeError:
            await self._disarm(client, info)
            raise
        except ConnectorError as exc:
            await self._disarm(client, info)
            raise ChangeError("Could not arm the undo job, so nothing was changed: " + exc.message,
                              code="unreachable" if exc.status is None else "failed", state="unchanged") from exc
        # UNVERIFIED: that REST output carries "next-run"; when it is there it must name a run
        if truthy(row.get("disabled")) or ("next-run" in row and not str(row.get("next-run") or "").strip()):
            await self._disarm(client, info)
            raise ChangeError("RouterOS did not schedule the undo job, so nothing was changed", code="failed",
                              state="unchanged")

    async def _delete_job(self, client: httpx.AsyncClient, info: dict[str, Any]) -> bool:
        """Delete the undo job (by id, else by name): True when it was still there, False when it was gone."""
        rows = _rows(await self._call(client, "GET", "/system/scheduler" + _query(_proplist=".id,name"),
                                      what="read the scheduler"), "read the scheduler")
        ids = [str(r[".id"]) for r in rows
               if r.get("name") == info["sched"] and ROW_ID_RE.match(str(r.get(".id") or ""))]
        found = False
        for sched_id in ids:
            try:
                await self._call(client, "DELETE", f"/system/scheduler/{sched_id}", what="delete the undo job",
                                 policy="write")
                found = True
            except ConnectorError as exc:
                if exc.status != 404:  # 404: it ran (and removed itself) between the read and the delete
                    raise
        return found

    async def _disarm(self, client: httpx.AsyncClient, info: dict[str, Any]) -> bool:
        """Delete the undo job (found by name, so also one whose id was never learned); True when it is gone."""
        try:
            await self._delete_job(client, info)
            return True
        except ConnectorError:
            return False

    async def _inverse(self, client: httpx.AsyncClient, info: dict[str, Any]) -> None:
        """Remove the rules the change added (found by their comment) and put toggled rules back."""
        comments: dict[str, set[str]] = {}
        for table, comment in info.get("comments") or []:
            comments.setdefault(table, set()).add(comment)
        for table, wanted in comments.items():
            rows = _rows(await self._call(client, "GET", TABLES[table] + _query(_proplist=".id,comment"),
                                          what="read the firewall rules"), "read the firewall rules")
            for row in rows:
                rid = str(row.get(".id") or "")
                if row.get("comment") in wanted and ROW_ID_RE.match(rid):
                    try:
                        await self._call(client, "DELETE", f"{TABLES[table]}/{rid}", what="remove the new rule",
                                         policy="write")
                    except ConnectorError as exc:
                        if exc.status != 404:
                            raise
        for ref, previous in (info.get("toggled") or {}).items():
            match = REF_RE.match(ref)
            assert match
            await self._call(client, "PATCH", f"{TABLES[match.group(1)]}/{match.group(2)}",
                             body={"disabled": previous == "true"}, what=f"restore rule {display_id(ref)}",
                             policy="write")

    async def _change_state(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what the router shows of the change now."""
        tables = {t for t, _ in info.get("comments") or []}
        tables |= {REF_RE.match(r).group(1) for r in info.get("toggled") or {}}
        rows: dict[str, list[dict[str, Any]]] = {}
        for table in tables:
            path = TABLES[table] + _query(_proplist=".id,comment,disabled")
            rows[table] = _rows(await self._call(client, "GET", path, what="read the firewall rules"),
                                "read the firewall rules")
        applied, reverted = [], []
        for table, comment in info.get("comments") or []:
            present = any(r.get("comment") == comment and not truthy(r.get("disabled")) for r in rows[table])
            applied.append(present)
            reverted.append(not any(r.get("comment") == comment for r in rows[table]))
        for ref, previous in (info.get("toggled") or {}).items():
            table, rid = REF_RE.match(ref).groups()
            row = next((r for r in rows[table] if r.get(".id") == rid), None)
            now = "true" if row is not None and truthy(row.get("disabled")) else "false"
            applied.append(row is not None and now != previous)
            reverted.append(row is not None and now == previous)
        if all(applied):
            return "applied"
        return "reverted" if all(reverted) else "partial"

    async def _undo(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """Undo a change that failed half-way; "unchanged" when the router is back (and the job deleted), else
        "unknown" (the armed undo job still reverts it)."""
        try:
            await self._inverse(client, info)
            if await self._change_state(client, info) == "reverted" and await self._disarm(client, info):
                return "unchanged"
        except ConnectorError:
            pass
        return "unknown"

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        notes = []
        try:
            async with self.client() as client:
                now = self.clock()
                deadline = float(info["deadline"])
                if now >= deadline - CONFIRM_MARGIN:
                    # too close to the router's own undo job to delete it safely: let it run, then say what it did
                    await self.sleep(max(0.0, min(deadline + SETTLE - now, 30.0)))
                gone = not await self._delete_job(client, info)
                state = await self._change_state(client, info)
                if gone and state == "applied":
                    notes.append("the undo job was no longer on the router")
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        if state == "reverted":
            raise ChangeError("Too late to confirm: the router's undo job already reverted the change", code="failed",
                              state="rolled_back")
        if state == "partial":
            raise ChangeError("The router holds only part of the change", code="failed", state="unknown")
        return {"confirmed": True, "revision": None,
                "notes": notes + ["the undo job was deleted; RouterOS keeps the change (there is no separate save)"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        notes: list[str] = []
        method = None
        try:
            async with self.client() as client:
                state = await self._change_state(client, info)
                armed = any(r.get("name") == info["sched"] for r in await self._pending(client))
                if state == "reverted" and not armed:
                    method = "deadman"
                    await self._disarm(client, info)
                else:
                    try:
                        await self._inverse(client, info)
                        if await self._change_state(client, info) == "reverted":
                            method = "inverse_ops"
                    except ConnectorError as exc:
                        if exc.status is None:
                            raise  # unreachable: the armed undo job is the way back
                        notes.append("undoing the change rule by rule failed")
                    if method is not None:
                        if not await self._disarm(client, info):
                            notes.append("the undo job could not be deleted; it will find nothing left to undo")
                    elif backup is not None:
                        notes.append("putting the filter rules back from Atrium's backup")
                        try:
                            await self._restore(client, backup)
                        except ChangeError as exc:  # the restore changed nothing, so the change is still there
                            raise ChangeError(exc.message, code=exc.code,
                                              state="applied" if exc.state == "unchanged" else exc.state) from exc
                        await self._disarm(client, info)
                        method = "backup_restore"
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message + f" - the router's undo job reverts the change at the end of its window if "
                              "it is still armed", code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        if method is None:
            raise ChangeError("The change is still on the router after undoing it", code="failed", state="applied")
        return {"rolled_back": True, "method": method, "notes": notes}

    # -- restoring Atrium's backup -----------------------------------------------------------

    @staticmethod
    def _backup_rows(backup: Backup) -> dict[str, list[dict[str, Any]]]:
        try:
            saved = json.loads(backup.text())
            assert isinstance(saved, dict) and saved.get("format") == "atrium-routeros-backup" and saved.get("v") == 1
            tables = saved["filter"]
            assert isinstance(tables, dict) and all(isinstance(tables.get(t), list) for t in TABLES)
        except (ValueError, KeyError, AssertionError, UnicodeError, TypeError) as exc:
            raise ChangeError("The backup is not an Atrium RouterOS backup", code="invalid", state="unchanged") from exc
        return {t: [r for r in tables[t] if isinstance(r, dict)] for t in TABLES}

    @staticmethod
    def _restore_plan(current: dict[str, list[dict[str, Any]]], saved: dict[str, list[dict[str, Any]]]
                      ) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]], list[str]]:
        """(rules to remove, rules to toggle (table, id, disabled), differences Atrium cannot restore)."""
        remove, toggle, other = [], [], []
        for table in TABLES:
            now = {str(r.get(".id")): _stable(r) for r in _static(current.get(table) or [])}
            then = {str(r.get(".id")): _stable(r) for r in saved.get(table) or []}
            for rid, row in now.items():
                if rid not in then:
                    if find_marker(row.get("comment")) and ROW_ID_RE.match(rid):
                        remove.append((table, rid))
                    else:
                        other.append(f"{table} rule {display_id(rid)} was added outside Atrium")
            for rid, row in then.items():
                if rid not in now:
                    other.append(f"{table} rule {display_id(rid)} was removed")
                    continue
                if _config(now[rid]) != _config(row):
                    other.append(f"{table} rule {display_id(rid)} was edited")
                elif truthy(now[rid].get("disabled")) != truthy(row.get("disabled")):
                    toggle.append((table, rid, "true" if truthy(row.get("disabled")) else "false"))
            kept = [rid for rid in now if rid in then]
            if kept != [rid for rid in then if rid in now]:
                other.append(f"{table} rules were moved")
        return remove, toggle, other

    async def _restore(self, client: httpx.AsyncClient, backup: Backup) -> None:
        saved = self._backup_rows(backup)
        raw, record = await self._state(client)
        current = {"ip": raw.get("filter") or [], "ipv6": raw.get("filter6") or []}
        remove, toggle, other = self._restore_plan(current, saved)
        if other:
            raise ChangeError(f"The router differs from the backup in {len(other)} way(s) Atrium does not restore over "
                              "the API (" + "; ".join(other[:5]) + ") - import the export in the backup by hand",
                              code="unsupported", state="unchanged")
        modelled = {r["id"] for r in record["rules"]}
        rows = {t: {str(r.get(".id")): r for r in current[t]} for t in TABLES}
        disabling, guard = [], []
        for table, rid, value in toggle:
            if value != "true":
                continue
            if f"{table}:{rid}" in modelled:
                disabling.append({"id": f"{table}:{rid}", "vendor_ref": f"{table}:{rid}"})
            elif str(rows[table][rid].get("action") or "") not in HARMLESS:
                guard.append(f"rule {display_id(table + ':' + rid)} jumps or accepts established traffic - disabling "
                             "it could cut the hub off from the router; restore it by hand")
        for start in range(0, len(disabling), 50):
            guard += self._guard(record, parse_ops([{"op": "disable_rules", "rules": disabling[start:start + 50]}]))
        if guard:
            raise ChangeError("Refused by the management-path guard: " + "; ".join(guard), code="lockout",
                              state="unchanged")
        try:
            for table, rid in remove:
                await self._call(client, "DELETE", f"{TABLES[table]}/{rid}", what="remove a rule Atrium added",
                                 policy="write")
            for table, rid, value in toggle:
                await self._call(client, "PATCH", f"{TABLES[table]}/{rid}", body={"disabled": value == "true"},
                                 what="restore a rule", policy="write")
            raw, _ = await self._state(client)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        left = self._restore_plan({"ip": raw.get("filter") or [], "ipv6": raw.get("filter6") or []}, saved)
        if any(left):
            raise ChangeError("The router's filter rules still differ from the backup after restoring it",
                              code="failed", state="unknown")

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        self._backup_rows(backup)
        try:
            async with self.client() as client:
                await self._restore(client, backup)
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        return {"restored": True, "revision": None,
                "notes": ["the firewall filter rules are back as in the backup (Atrium's rules removed, enabled and "
                          "disabled states restored); other settings are not touched"]}
