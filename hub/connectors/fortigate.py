"""FortiGate (FortiOS 7.x) connector: reads one VDOM's firewall policies, zones, interfaces, address and service
objects through the REST API into the network model (``netmodel.py``) and, on FortiOS 7.4.1 or later, makes
guarded policy changes (one allow policy between two zones or interfaces, disabling / re-enabling policies) for the
hub's network change path.

Source: docs/research/fw-fortigate-panos-cisco.md sections 2, 5 and 6, re-checked October 2026. Labels: [V] official
documentation or Fortinet-maintained code (Ansible collection), [K] Fortinet KB article, [U] unverified.

- Authentication [V]: a REST API administrator's token in ``Authorization: Bearer``; HTTPS only. 401 means a bad
  token or a trusted-host mismatch (before 7.4.1 the hub's address must also be in an administrator's trusted hosts
  [K]). URL-query tokens are never used.
- Requests [V]: ``/api/v2/cmdb/<path>/<name>[/<mkey>]?vdom=<vdom>`` for configuration (GET reads, POST creates, PUT
  updates, DELETE removes, ``PUT ...?action=move&before=<id>`` moves a policy), ``/api/v2/monitor/...`` for state.
  The envelope carries ``status``, ``http_status``, ``results``, ``version``, ``serial``, ``build`` [V].
- Reading:
  - the version from ``monitor/system/status`` (``cmdb/system/status`` was removed in 7.4.4) [K];
  - ``cmdb/firewall/policy`` (list order is evaluation order; ``policyid`` is an id, not the position) - path [U],
    field names [V] (Fortinet's Ansible module), hyphenated wire form [U];
  - ``system/interface``, ``system/zone``, ``firewall/address`` [V], ``firewall/addrgrp``, ``firewall/address6``,
    ``firewall/addrgrp6``, ``firewall.service/custom``, ``firewall.service/group`` (cmdb paths from the Ansible
    collection's path/name pairs; response field names such as ``subnet`` "a.b.c.d m.m.m.m", ``tcp-portrange``
    "80 443 1000-2000:src", ``allowaccess`` are [U]);
  - hit counts from ``monitor/firewall/policy`` (optional, [U] field names);
  - ``system/global`` (``cfg-save``, admin ports) and ``system/central-management`` (FortiManager) [U].
  - Management access: ``allowaccess`` on an interface (https, ssh, ...) is shown as a read-only rule "to this
    device" so the management-exposure checks see it; trusted hosts and local-in policies are not evaluated.
- Revision: a hash of the configuration tables read (FortiOS's own envelope ``revision`` is not documented).
- Changes (only FortiOS 7.4.1+, configuration save mode ``automatic``, not managed by FortiManager):
  - one workspace transaction [V]: ``POST /api/v2/cmdb?action=transaction-start`` ``{"timeout": 60}``, every write
    with the header ``X-TRANSACTION-ID``, ``GET ...?action=transaction-show`` (the staged CLI lines, 7.4.1+), ``POST
    ...?action=transaction-commit`` ``{"transaction-id": n}``. Uncommitted changes are invisible to the firewall and
    discarded after 5 minutes without activity [V], so a failure before the commit leaves the firewall unchanged.
  - the allow policy gets an explicit ``policyid`` (highest + 1), name ``atrium-<change id>``, the marker in
    ``comments``, address objects with exactly the op's networks and custom services with exactly its ports (existing
    ones reused when they hold exactly that, else ``atrium-...`` objects are created), and is moved before the first
    policy for the same interface pair.
  - disable / enable: ``PUT .../firewall/policy/<id>`` ``{"status": "disable" | "enable"}`` (partial update [U]).
  - rollback mode ``backup_restore``: FortiOS has no commit-confirm usable over the API (``cfg-save revert`` is a
    global setting that reboots the unit; Atrium never sets it). Rollback deletes the created policy and puts toggled
    policies back in a new transaction; Atrium-created objects are removed afterwards when unused.
  - configuration backups: ``monitor/system/config/backup?scope=global`` - GET before 7.6.0, POST from 7.6.0; needs a
    ``super_admin`` profile [K]. Restoring is left to the GUI (System > Configuration > Restore): the restore API's
    ``source`` values are not documented and a restore reboots the unit [U], so ``restore_backup`` is not offered.

UNVERIFIED: the cmdb paths and wire field names marked [U] above; the REST action name ``transaction-abort`` (a
failed transaction is otherwise discarded after 5 minutes); the unit of the transaction ``timeout``; where the
transaction id sits in the start answer (top level or in ``results``); that moves and object creations are accepted
inside a transaction; that a PUT with ``status`` alone changes only that field; ``system/api-user`` /
``system/accprofile`` answers used to report the token's access profile.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import time
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import quote, urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, derived_revision, display_id, management_guard,
                       normalise_cidr, normalize_record, parse_ops, parse_ports, untrusted_text)

OPS = ["allow", "disable_rules", "enable_rules"]
MIN_READ = (7, 0, 0)
MIN_WRITE = (7, 4, 1)  # the documented REST transaction flow (transaction-show) starts with 7.4.1 [V]
BACKUP_BY_POST = (7, 6, 0)  # GET answers 405 from 7.6.0 [K]
WINDOW = 300  # backup_restore: how long the hub may take to verify before it rolls back
TRANSACTION_TIMEOUT = 60  # UNVERIFIED: unit not documented (the inactivity limit is 5 minutes either way)
MAX_TOKEN = 4096
MAX_POLICY_ID = 4_294_967_294  # UNVERIFIED upper bound of policyid
VERSION_RE = re.compile(r"v?(\d+)\.(\d+)(?:\.(\d+))?")
VDOM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
POLICY_ID_RE = re.compile(r"^\d{1,10}$")
OBJECT_RE = re.compile(r"^atrium-[A-Za-z0-9_.-]{1,72}$")  # names of objects Atrium creates (they go into URL paths)
USER_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
CHANGE_ID_RE = re.compile(r"atrium:([A-Za-z0-9_-]{1,64})")
TRUE = ("enable", "enabled", "yes", "true", "1")
# what each read needs in the token's admin profile (System > Admin Profiles)
READS: tuple[tuple[str, str, bool, str], ...] = (
    ("policies", "firewall/policy", True, "Firewall > Policy: Read"),
    ("interfaces", "system/interface", True, "Network > Configuration: Read"),
    ("zones", "system/zone", False, "Network > Configuration: Read"),
    ("addresses", "firewall/address", False, "Firewall > Address: Read"),
    ("addrgrps", "firewall/addrgrp", False, "Firewall > Address: Read"),
    ("addresses6", "firewall/address6", False, "Firewall > Address: Read"),
    ("addrgrps6", "firewall/addrgrp6", False, "Firewall > Address: Read"),
    ("services", "firewall.service/custom", False, "Firewall > Service: Read"),
    ("servicegroups", "firewall.service/group", False, "Firewall > Service: Read"),
)
HINTS = {key: hint for key, _, _, hint in READS} | {"global": "System > Configuration: Read",
                                                    "hits": "Firewall > Policy: Read"}
# allowaccess entries that open an administrative service on the interface; the others (fabric, probe-response,
# ftm, ...) are not admin logins and are left out of the management rule
ACCESS = {"https": ("tcp", "admin-sport", 443), "http": ("tcp", "admin-port", 80),
          "ssh": ("tcp", "admin-ssh-port", 22), "telnet": ("tcp", "admin-telnet-port", 23),
          "snmp": ("udp", None, 161), "fgfm": ("tcp", None, 541), "ping": ("icmp", None, None)}


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """(7, 4, 4) from "v7.4.4", "7.4.4" or "FortiGate-VM64 v7.6.5,build3651"."""
    match = VERSION_RE.search(str(text or ""))
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def _names(value: Any, key: str = "name") -> list[str]:
    """Member names from FortiOS lists ([{"name": "port2", "q_origin_key": "port2"}, ...]) or plain strings."""
    items = value if isinstance(value, list) else [value] if value not in (None, "") else []
    out = []
    for item in items:
        text = item.get(key) or item.get("name") or item.get("q_origin_key") if isinstance(item, dict) else item
        text = str(text or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _on(value: Any) -> bool:
    return str(value if value is not None else "").strip().lower() in TRUE


def _interface_address(value: Any) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface | None:
    """"10.0.10.1 255.255.255.0" or "10.0.10.1/24" -> the interface address; None for 0.0.0.0 / empty."""
    text = " ".join(str(value or "").split())
    if not text:
        return None
    try:
        found = ipaddress.ip_interface(text.replace(" ", "/", 1))
    except ValueError:
        return None
    return None if found.ip.is_unspecified or found.ip.is_link_local else found


def _subnet(value: Any) -> str | None:
    """"10.0.0.0 255.255.255.0" / "10.0.0.0/24" / ["10.0.0.0", "255.255.255.0"] -> "10.0.0.0/24"."""
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    text = " ".join(str(value or "").split())
    return normalise_cidr(text.replace(" ", "/", 1)) if text else None


def _ranges(value: Any) -> str | None:
    """A FortiOS port range list "80 443 8000-8080:1024-65535" (destination[:source]) -> "80,443,8000-8080";
    None when empty; ValueError when it is not one. UNVERIFIED: the syntax is the CLI's."""
    parts = [item.split(":", 1)[0] for item in str(value or "").split()]
    return parse_ports(",".join(parts)) if parts else None


class TlsError(ConnectorError):
    """The firewall answered, but its certificate is not trusted."""


class Device:
    """One read of the FortiGate (rows of untrusted device data) and the lookups normalisation needs."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        vdom = raw.get("vdom") or "root"
        self.interfaces = [r for r in raw.get("interfaces") or [] if isinstance(r, dict) and str(r.get("name") or "").strip()
                           and str(r.get("vdom") or vdom) == vdom]
        self.iface_names = {str(r["name"]) for r in self.interfaces}
        self.zones = {str(z["name"]): _names(z.get("interface"), "interface-name")
                      for z in raw.get("zones") or [] if isinstance(z, dict) and z.get("name")}
        self.addr_rows: dict[str, dict[str, Any]] = {}
        for table, key in (("addrgrp6", "addrgrps6"), ("address6", "addresses6"), ("addrgrp", "addrgrps"),
                           ("address", "addresses")):  # the IPv4 address table wins a name clash
            for row in raw.get(key) or []:
                if isinstance(row, dict) and row.get("name"):
                    self.addr_rows[str(row["name"])] = {**row, "_table": table}
        self.svc_rows: dict[str, dict[str, Any]] = {}
        for table, key in (("group", "servicegroups"), ("custom", "services")):
            for row in raw.get(key) or []:
                if isinstance(row, dict) and row.get("name"):
                    self.svc_rows[str(row["name"])] = {**row, "_table": table}
        self.notes: list[str] = []

    # -- objects -------------------------------------------------------------------------

    def alias(self, name: str, depth: int = 0) -> dict[str, Any]:
        """{"name", "kind", "cidrs", "ports", "resolved"} for an address object or group (groups flattened)."""
        out: dict[str, Any] = {"name": name, "kind": "network", "cidrs": [], "ports": None, "resolved": True}
        row = self.addr_rows.get(name)
        if row is None or depth > 8:
            return {**out, "kind": "other", "resolved": False}
        if row["_table"] in ("addrgrp", "addrgrp6"):
            for member in _names(row.get("member")):
                nested = self.alias(member, depth + 1)
                out["cidrs"] += nested["cidrs"]
                out["resolved"] = out["resolved"] and nested["resolved"]
            if _on(row.get("exclude")):  # "members minus exclude-members": not expressible as a list of networks
                out["resolved"] = False
            out["cidrs"] = list(dict.fromkeys(out["cidrs"]))[:2000]
            return out
        kind = str(row.get("type") or ("ipmask" if row["_table"] == "address" else "ipprefix")).lower()
        if kind in ("ipmask", "interface-subnet"):
            cidr = _subnet(row.get("subnet"))
            out["cidrs"] = [cidr] if cidr else []
        elif kind == "ipprefix":
            cidr = normalise_cidr(row.get("ip6"))
            out["cidrs"] = [cidr] if cidr else []
        elif kind == "iprange":
            low, high = (str(row.get(k) or "").strip() for k in ("start-ip", "end-ip"))
            try:
                out["cidrs"] = [str(n) for n in ipaddress.summarize_address_range(ipaddress.ip_address(low),
                                                                                   ipaddress.ip_address(high))]
            except (ValueError, TypeError):
                out["cidrs"] = []
        elif kind == "geography":
            return {**out, "kind": "geoip", "resolved": False}
        else:  # fqdn, wildcard, wildcard-fqdn, dynamic, mac: resolved by the firewall at run time
            return {**out, "kind": "other", "resolved": False}
        if not out["cidrs"]:
            out["resolved"] = False
        elif len(out["cidrs"]) == 1 and ipaddress.ip_network(out["cidrs"][0]).num_addresses == 1:
            out["kind"] = "host"
        return out

    def endpoint(self, names: list[str], negate: bool) -> dict[str, Any]:
        if not names:
            return {"any": True}
        out: dict[str, Any] = {"aliases": [], "negate": negate}
        for name in names:
            found = self.alias(name)
            wide = name.lower() == "all" or (found["resolved"] and any(ipaddress.ip_network(c).prefixlen == 0
                                                                       for c in found["cidrs"]))
            if wide:
                return {"any": True, "negate": negate}
            out["aliases"].append(name)  # unknown names stay as aliases: the hub treats them as "anything"
        return out

    def service(self, name: str, depth: int = 0) -> list[dict[str, Any]] | None:
        """The (proto, ports) entries of a service object or group; None = any service."""
        row = self.svc_rows.get(name)
        if row is None or depth > 8:
            return None if name.upper() == "ALL" else [{"proto": "any", "alias": name, "name": name}]
        if row["_table"] == "group":
            entries: list[dict[str, Any]] = []
            for member in _names(row.get("member")):
                nested = self.service(member, depth + 1)
                if nested is None:
                    return None
                entries += nested
            return entries or [{"proto": "any", "alias": name, "name": name}]
        protocol = str(row.get("protocol") or "TCP/UDP/SCTP").upper()
        if protocol.startswith("TCP/UDP"):
            entries = []
            for proto, key in (("tcp", "tcp-portrange"), ("udp", "udp-portrange"), ("sctp", "sctp-portrange")):
                if not str(row.get(key) or "").strip():
                    continue
                try:
                    entries.append({"proto": proto, "ports": _ranges(row.get(key)), "name": name})
                except ValueError:
                    entries.append({"proto": proto, "alias": name, "name": name})
            return entries or [{"proto": "any", "alias": name, "name": name}]
        if protocol == "ICMP":
            return [{"proto": "icmp", "name": name}]
        if protocol == "ICMP6":
            return [{"proto": "icmpv6", "name": name}]
        if protocol in ("IP", "ALL"):
            number = str(row.get("protocol-number") or "0").strip()
            return None if protocol == "ALL" or number in ("", "0") else [{"proto": number, "name": name}]
        return [{"proto": "any", "alias": name, "name": name}]  # explicit-proxy services (HTTP, FTP, CONNECT, SOCKS)

    def services(self, names: list[str], negate: bool) -> list[dict[str, Any]] | None:
        if negate or not names:
            return None  # "every service but these" is read as any service (wider, never narrower)
        entries: list[dict[str, Any]] = []
        for name in names:
            found = self.service(name)
            if found is None:
                return None
            entries += found
        return entries

    def exact_service(self, name: str) -> tuple[str, str | None] | None:
        """(proto, ports) when a custom service holds exactly one protocol with exactly those ports (reusable)."""
        row = self.svc_rows.get(name)
        if row is None or row["_table"] != "custom":
            return None
        found = self.service(name)
        if not found or len(found) != 1 or found[0].get("alias"):
            return None
        return found[0]["proto"], found[0].get("ports")

    # -- bindings and rules --------------------------------------------------------------

    def bind(self, names: list[str]) -> tuple[list[str], list[str]]:
        """(interfaces, zones) a srcintf / dstintf list names; "any" binds nothing (every interface)."""
        interfaces, zones = [], []
        for name in names:
            if name.lower() == "any":
                return [], []
            (zones if name in self.zones else interfaces).append(name)
        return interfaces, zones

    def rule(self, row: dict[str, Any], order: int, hits: dict[str, Any]) -> dict[str, Any] | None:
        pid = str(row.get("policyid") if row.get("policyid") is not None else "").strip()
        if not POLICY_ID_RE.match(pid):
            return None
        action = {"accept": "pass", "ipsec": "pass", "deny": "block"}.get(str(row.get("action") or "deny").lower())
        if action is None:
            return None
        interfaces, source_zones = self.bind(_names(row.get("srcintf")))
        out_interfaces, destination_zones = self.bind(_names(row.get("dstintf")))
        source = self.endpoint(_names(row.get("srcaddr")) + _names(row.get("srcaddr6")), _on(row.get("srcaddr-negate")))
        destination = self.endpoint(_names(row.get("dstaddr")) + _names(row.get("dstaddr6")),
                                    _on(row.get("dstaddr-negate")))
        services = self.services(_names(row.get("service")), _on(row.get("service-negate")))
        if _on(row.get("internet-service-src")):  # Internet Service Database entries: resolved by the firewall
            source = {"aliases": ["isdb:" + n for n in _names(row.get("internet-service-src-name")) or ["source"]],
                      "negate": _on(row.get("internet-service-src-negate"))}
        if _on(row.get("internet-service")):
            destination = {"aliases": ["isdb:" + n for n in _names(row.get("internet-service-name")) or ["destination"]],
                           "negate": _on(row.get("internet-service-negate"))}
            services = None
        name, comments = str(row.get("name") or "").strip(), str(row.get("comments") or "").strip()
        return {
            "id": pid, "vendor_ref": pid, "order": order, "enabled": str(row.get("status") or "enable") != "disable",
            "action": action, "interfaces": interfaces, "out_interfaces": out_interfaces, "source_zones": source_zones,
            "destination_zones": destination_zones, "direction": "in", "quick": True,
            "source": source, "destination": destination, "services": services,
            "log": str(row.get("logtraffic") or "").lower() == "all",
            "description": " - ".join(filter(None, (name, comments))), "hits": hits.get(pid),
        }

    def management_rules(self) -> list[dict[str, Any]]:
        """Read-only rules "to this device" for each interface's administrative access (allowaccess)."""
        settings = self.raw.get("global") or {}
        rules, other = [], set()
        for row in self.interfaces:
            access = str(row.get("allowaccess") or "").lower().split()
            services = []
            for item in access:
                if item not in ACCESS:
                    other.add(item)
                    continue
                proto, key, default = ACCESS[item]
                port = settings.get(key) if key else None
                port = port if str(port or "").isdigit() and 0 < int(port) < 65536 else default
                services.append({"proto": proto, "ports": str(port) if port else None, "name": item})
            if services:
                name = str(row["name"])
                rules.append({"id": f"access:{name}", "vendor_ref": f"access:{name}", "order": 0, "action": "pass",
                              "interfaces": [name], "source": {"any": True}, "destination": {"self": True},
                              "services": services, "description": "administrative access (allowaccess)"})
        if rules:
            self.notes.append("administrative access (allowaccess) is shown as rules to this device; trusted hosts and "
                              "local-in policies that narrow it are not evaluated")
        if other:
            self.notes.append(f"{len(other)} other access type(s) (e.g. fabric, probe-response) are not shown as rules")
        return rules


class FortigateConnector(Connector):
    kind = "fortigate"
    title = "FortiGate"
    description = ("Firewall (FortiOS 7.x REST API): reads one VDOM's policies, zones, interfaces and objects into the "
                   "Network app; on FortiOS 7.4.1+ with device changes enabled, adds one allow policy or disables "
                   "policies in a configuration transaction under the change safety model.")
    fields = [
        ConnectorField(name="base_url", label="FortiGate URL", kind="url", required=True,
                       placeholder="https://10.0.99.1",
                       help="The https address of the management interface (with the port if the admin HTTPS port "
                            "is not 443)."),
        ConnectorField(name="api_token", label="API token", kind="secret", required=True,
                       help="System > Administrators > Create New > REST API Admin (shown once). Give it a trusted "
                            "host for the hub's address and a read-only profile until device changes are enabled."),
        ConnectorField(name="vdom", label="VDOM", default="root", options=True,
                       help="The virtual domain to read (root on a FortiGate without VDOMs)."),
        ConnectorField(name="api_user", label="REST API admin name", placeholder="atrium",
                       help="Optional. Lets the test read the token's admin profile and say whether it can write and "
                            "take backups."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the token again."),
        ConnectorField(name="ca_file", label="CA certificate file", kind="text",
                       placeholder="/etc/atrium/fortinet-ca.pem",
                       help="PEM file on the hub's machine with the GUI certificate's CA (from 7.2.1 the built-in "
                            "Fortinet_CA_SSL; earlier releases use a self-signed certificate). Empty: the system's CAs."),
        ConnectorField(name="hub_address", label="Hub address as the firewall sees it", kind="text",
                       placeholder="10.0.99.10",
                       help="Optional. The management-path guard then only protects policies that carry the hub's own "
                            "traffic; empty, it protects every policy that can reach the firewall."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this firewall through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "backup_restore", "window_s": WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)

    @classmethod
    def detect(cls, tool) -> int:
        # the vendor name alone (FortiAnalyzer, FortiNAC, ... share it) is only a weak hint
        return max(cls.name_score(tool, ("fortigate", "fortios")), cls.name_score(tool, ("fortinet",), score=50))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        # switching certificate checks off would let the stored token go to whoever answers: enter it again
        return super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.hostname:
            raise ConnectorError("The FortiGate URL must start with https:// (the API token travels in every request)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API token in its own field, not in the URL")
        try:
            parts.port
        except ValueError as exc:
            raise ConnectorError("The FortiGate URL has an invalid port") from exc
        config["base_url"] = re.sub(r"(?i)/api(/v2)?$", "", base)
        vdom = str(config.get("vdom") or "root").strip()
        if not VDOM_RE.match(vdom):
            raise ConnectorError("VDOM: 1-31 letters, digits, '_', '.' or '-'")
        config["vdom"] = vdom
        user = str(config.get("api_user") or "").strip()
        if user and not USER_RE.match(user):
            raise ConnectorError("REST API admin name: letters, digits, '_', '.', '@' or '-'")
        config["api_user"] = user or None
        ca_file = str(config.get("ca_file") or "").strip()
        if ca_file and not (os.path.isabs(ca_file) or PurePosixPath(ca_file).is_absolute()):
            raise ConnectorError("CA certificate file must be an absolute path on the hub's machine")
        hub_address = str(config.get("hub_address") or "").strip()
        if hub_address:
            try:
                config["hub_address"] = str(ipaddress.ip_address(hub_address))
            except ValueError as exc:
                raise ConnectorError("Hub address must be an IP address") from exc
        return config

    def write_capability(self) -> dict[str, Any] | None:
        return None if self.config.get("read_only") else super().write_capability()

    # -- HTTP ------------------------------------------------------------------------------

    @property
    def host(self) -> str:
        return urlsplit(str(self.config.get("base_url") or "")).hostname or ""

    @property
    def api_port(self) -> int:
        return urlsplit(str(self.config.get("base_url") or "")).port or 443

    @property
    def vdom(self) -> str:
        return str(self.config.get("vdom") or "root")

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise TlsError(f"Cannot load the CA certificate file {ca_file}: "
                           f"{getattr(exc, 'strerror', None) or exc.__class__.__name__}") from exc
        if ca_file:  # appliance certificates are often not RFC 5280-strict; chain and host name are still checked
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        token = self.secrets.get("api_token")
        if not token:
            raise self.error("Enter the FortiGate API token in the connection settings")
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        return self.http(str(self.config.get("base_url") or "").rstrip("/") + "/api/v2",
                         headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}, verify=verify)

    async def _send(self, client: httpx.AsyncClient, method: str, path: str, *, what: str,
                    params: dict[str, Any] | None = None, body: Any = None,
                    headers: dict[str, str] | None = None) -> httpx.Response:
        try:
            kwargs: dict[str, Any] = {"params": params, "headers": headers}
            if body is not None:
                kwargs["json"] = body
            return await client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise self.error(f"The FortiGate at {self.host}:{self.api_port} did not answer in time ({what})") from exc
        except httpx.ConnectError as exc:
            text = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text.lower():
                raise TlsError(self.redact("The FortiGate's TLS certificate is not trusted - set the CA certificate "
                                           "file (Fortinet_CA_SSL or your own CA)")) from exc
            raise self.error(f"Cannot reach the FortiGate at {self.host}:{self.api_port} "
                             f"({exc.__class__.__name__})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach the FortiGate: {exc.__class__.__name__}") from exc

    async def _call(self, client: httpx.AsyncClient, method: str, path: str, *, what: str,
                    params: dict[str, Any] | None = None, body: Any = None, hint: str | None = None,
                    tid: int | None = None) -> dict[str, Any]:
        """The JSON envelope of one API call; a ConnectorError (with the profile permission to grant on 403)."""
        headers = {"X-TRANSACTION-ID": str(tid)} if tid is not None else None
        response = await self._send(client, method, path, what=what, params=params, body=body, headers=headers)
        code = response.status_code
        try:
            answer = response.json() if response.content else {}
        except ValueError:
            answer = None
        if code == 401:
            raise self.error("The FortiGate refused the API token (HTTP 401) - check the token and that the hub's "
                             "address is in the REST API admin's trusted hosts (before 7.4.1 also in an "
                             "administrator's trusted hosts)", status=401)
        if code == 403:
            grant = f" - the token's admin profile needs '{hint}'" if hint else " - the token's admin profile lacks it"
            raise self.error(f"The FortiGate refused to {what} (HTTP 403){grant}", status=403)
        if code in (301, 302, 303, 307, 308):
            raise self.error("The FortiGate redirected the request - use the exact https:// address and admin port",
                             status=code)
        if code == 404:
            raise self.error(f"The FortiGate has no API endpoint to {what} (HTTP 404) - check the URL, the VDOM and "
                             "the FortiOS version", status=404)
        if not isinstance(answer, dict):
            if code < 300 and answer is None:
                raise self.error(f"The FortiGate did not answer with JSON ({what}) - is the URL the admin address?",
                                 status=code)
            answer = {"results": answer}
        if code >= 300 or str(answer.get("status") or "success").lower() == "error":
            error = answer.get("error")  # a negative FortiOS error number; cli_error texts are device text: not quoted
            http_status = answer.get("http_status")
            status = http_status if isinstance(http_status, int) and http_status >= 300 else code if code >= 300 else 500
            code_text = f", error {int(error)}" if isinstance(error, (int, float)) and not isinstance(error, bool) else ""
            raise self.error(f"The FortiGate could not {what} (HTTP {status}{code_text})", status=status)
        return answer

    async def _table(self, client: httpx.AsyncClient, path: str, *, what: str, hint: str | None = None,
                     scope: str = "vdom") -> Any:
        params = {"vdom": self.vdom} if scope == "vdom" else None
        answer = await self._call(client, "GET", f"/cmdb/{path}", what=what, params=params, hint=hint)
        results = answer.get("results")
        matched = answer.get("matched_count")
        if isinstance(results, list) and isinstance(matched, int) and matched > len(results):
            raise self.error(f"The FortiGate returned {len(results)} of {matched} entries ({what}) - refusing a "
                             "partial read")
        return results

    # -- reading ---------------------------------------------------------------------------

    async def _status(self, client: httpx.AsyncClient) -> dict[str, Any]:
        answer = await self._call(client, "GET", "/monitor/system/status", what="read the system status")
        results = answer.get("results") if isinstance(answer.get("results"), dict) else {}
        model = " ".join(filter(None, (str(results.get("model_name") or "").strip(),
                                       str(results.get("model_number") or "").strip()))) or results.get("model") or ""
        return {"version": parse_version(answer.get("version") or results.get("version")),
                "build": answer.get("build"), "serial": untrusted_text(answer.get("serial"), 80),
                "hostname": untrusted_text(results.get("hostname"), 120), "model": untrusted_text(model, 120)}

    async def read(self, client: httpx.AsyncClient, *, strict: bool = True) -> dict[str, Any]:
        """Everything a snapshot needs, as the FortiGate answered it (rows of untrusted device data). `strict`
        raises when a required table cannot be read; otherwise `access` says what could be read."""
        status = await self._status(client)
        if status["version"] is not None and status["version"] < MIN_READ and strict:
            raise self.error(f"FortiOS {'.'.join(map(str, status['version']))} is not supported: Atrium reads FortiOS "
                             "7.0 or later")
        raw: dict[str, Any] = {"status": status, "vdom": self.vdom, "notes": [], "access": {}, "errors": []}
        for key, path, required, hint in READS:
            try:
                rows = await self._table(client, path, what=f"read {key}", hint=hint)
                raw[key] = [r for r in rows if isinstance(r, dict)] if isinstance(rows, list) else []
                raw["access"][key] = True
            except TlsError:
                raise
            except ConnectorError as exc:
                if strict and (required or exc.status not in (403, 404)):
                    raise
                raw[key], raw["access"][key] = [], False
                if exc.status not in (403, 404):
                    raw["errors"].append(exc.message)
                elif not required:
                    raw["notes"].append(f"{key}: not readable - grant '{hint}'")
        raw["hits"] = await self._hits(client, raw)
        raw["global"] = await self._optional(client, "system/global", raw, "global", scope="global")
        raw["central"] = await self._optional(client, "system/central-management", raw, "global", scope="global")
        raw["read_at"] = self.clock()
        return raw

    async def _optional(self, client: httpx.AsyncClient, path: str, raw: dict[str, Any], hint: str,
                        scope: str = "vdom") -> dict[str, Any] | None:
        try:
            found = await self._table(client, path, what=f"read {path}", hint=HINTS[hint], scope=scope)
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None or exc.status == 401:
                raise
            raw["notes"].append(f"{path}: not readable - grant '{HINTS[hint]}'")
            return None
        if isinstance(found, list):
            found = found[0] if found and isinstance(found[0], dict) else {}
        return found if isinstance(found, dict) else {}

    async def _hits(self, client: httpx.AsyncClient, raw: dict[str, Any]) -> dict[str, int]:
        try:
            answer = await self._call(client, "GET", "/monitor/firewall/policy", what="read hit counts",
                                      params={"vdom": self.vdom})
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None or exc.status == 401:
                raise
            raw["notes"].append("hit counts are not available")
            return {}
        out = {}
        for row in answer.get("results") or []:  # UNVERIFIED field names: policyid, hit_count
            if isinstance(row, dict) and POLICY_ID_RE.match(str(row.get("policyid"))) \
                    and isinstance(row.get("hit_count"), (int, float)):
                out[str(row["policyid"])] = int(row["hit_count"])
        return out

    def revision(self, raw: dict[str, Any]) -> str:
        return derived_revision(*[raw.get(key) or [] for key, _, _, _ in READS])

    def to_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        """The normalised device record (netmodel) for one read."""
        dev = Device(raw)
        status = raw.get("status") or {}
        notes = list(raw.get("notes") or [])
        interfaces, self_addresses = [], []
        for row in dev.interfaces:
            name = str(row["name"])
            found = [a for a in (_interface_address(row.get("ip")),
                                 _interface_address((row.get("ipv6") or {}).get("ip6-address")
                                                    if isinstance(row.get("ipv6"), dict) else None)) if a]
            self_addresses += [str(a.ip) for a in found]
            role = {"wan": "wan", "lan": "lan"}.get(str(row.get("role") or "").lower(), "other")
            if str(row.get("dedicated-to") or "").lower() == "management" or re.fullmatch(r"mgmt\d?", name):
                role = "mgmt"
            vlan = row.get("vlanid") if str(row.get("type") or "").lower() == "vlan" else None
            interfaces.append({"id": name, "name": row.get("alias") or name, "description": row.get("description") or "",
                               "vlan": vlan if str(vlan or "").isdigit() and 1 <= int(vlan) <= 4094 else None,
                               "subnets": list(dict.fromkeys(str(a.network) for a in found)),
                               "addresses": [str(a.ip) for a in found], "role": role,
                               "enabled": str(row.get("status") or "up").lower() != "down"})
        rules = dev.management_rules()
        skipped = 0
        for order, row in enumerate(raw.get("policies") or [], start=1):
            rule = dev.rule(row, order, raw.get("hits") or {})
            if rule is None:
                skipped += 1
                continue
            rules.append(rule)
        if skipped:
            notes.append(f"{skipped} policy entr(ies) without a usable policy id or action were skipped")
        if any(_on(r.get("internet-service")) or _on(r.get("internet-service-src")) for r in raw.get("policies") or []):
            notes.append("Internet Service Database matches are read as unresolved objects (any address, any service)")
        central = raw.get("central") or {}
        if str(central.get("type") or "").lower() == "fortimanager":
            notes.append("this FortiGate is managed by FortiManager: change policies there")
        notes += dev.notes
        version = status.get("version")
        return {
            "external_id": status.get("serial") or status.get("hostname") or self.host, "revision": self.revision(raw),
            "read_at": raw.get("read_at"), "kind": "firewall",
            "device": {"vendor": "Fortinet", "model": status.get("model") or "FortiGate",
                       "version": ".".join(map(str, version)) if version else "", "hostname": status.get("hostname") or "",
                       "management_address": self.host, "serial": status.get("serial") or ""},
            "interfaces": interfaces,
            "zones": [{"id": name, "name": name, "interfaces": members} for name, members in dev.zones.items()],
            "aliases": [dev.alias(name) for name in dev.addr_rows],
            "self_addresses": list(dict.fromkeys(self_addresses)), "rules": rules,
            "default_policy": {"forward": "block", "inbound": "block"}, "nat_evaluated": False, "notes": notes[:50],
        }

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"The FortiGate connector cannot read {domain}")
        async with self.client() as client:
            return [self.to_record(await self.read(client))]

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name != "vdom":
            return await super().options(field_name)
        async with self.client() as client:
            rows = await self._table(client, "system/vdom", what="list the VDOMs", scope="global")  # UNVERIFIED path
        names = [display_id(r.get("name"), 31) for r in rows or [] if isinstance(r, dict) and r.get("name")]
        return [{"value": n, "label": n} for n in names if VDOM_RE.match(n)]

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
        verify = "verification is OFF - anyone on the path could read the API token" \
            if not self.config.get("verify_tls", True) else \
            f"certificate verified with {self.config['ca_file']}" if self.config.get("ca_file") else \
            "certificate verified with the system's trusted CAs"
        where = f"{self.host}:{self.api_port}"
        async with client:
            try:
                status = await self._status(client)
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
                checks.append(check("authentication", False, exc.message if exc.status == 401 else
                                    "the server answered, but not like FortiOS's REST API: " + exc.message))
                return result(False, exc.message)
            checks.append(check("reachability", True, f"{where} answers"))
            checks.append(check("tls", bool(self.config.get("verify_tls", True)), verify))
            name = display_id(status.get("hostname"), 64) if status.get("hostname") else ""
            checks.append(check("authentication", True, "API token accepted" + (f" by {name}" if name else "")))
            version = status["version"]
            supported = version is not None and version >= MIN_READ
            try:
                raw = await self.read(client, strict=False) if supported else None
                profile = await self._profile(client) if supported and self.config.get("api_user") else None
            except ConnectorError as exc:
                checks.append(check("privileges", False, exc.message))
                return result(False, exc.message)
        access = (raw or {}).get("access") or {}
        readable = bool(access.get("policies") and access.get("interfaces"))
        write = self._write_spec(raw, profile) if raw and readable else None
        checks.append(check("privileges", readable, self._privilege_detail(raw, profile, write)))
        vtext = ".".join(map(str, version)) if version else "unknown"
        checks.append(check("version", supported,
                            f"FortiOS {vtext} - " + ("supported" + ("" if version >= MIN_WRITE else
                                                                    "; device changes need 7.4.1 or later (REST "
                                                                    "configuration transactions)")
                                                     if supported else "not supported: Atrium reads FortiOS 7.0 or later")))
        checks.append(check("api_features", True, self._features(raw, version)))
        record = None
        if raw and readable:
            try:
                record = normalize_record(self.to_record(raw))
                checks.append(check("ruleset", True, f"{len(record['rules'])} rules, {len(record['interfaces'])} "
                                                     f"interfaces, {len(record['zones'])} zones, "
                                                     f"{len(record['aliases'])} address objects read"
                                    + (f"; {len(record['errors'])} entries skipped" if record["errors"] else "")))
            except (ConnectorError, ValueError) as exc:
                checks.append(check("ruleset", False, getattr(exc, "message", None) or str(exc)))
        checks.append(check("management_guard", True,
                            f"protects policies carrying the hub's traffic from {self.config['hub_address']} to port "
                            f"{self.api_port}" if self.config.get("hub_address") else
                            "no hub address set: disabling any policy that lets traffic reach the firewall is refused "
                            "(set the hub address to narrow this)"))
        ok = supported and readable and record is not None
        what = f"FortiOS {vtext}" + (f" ({name})" if name else "")
        detail = (f"Connected to {what}: {len(record['rules'])} rules in VDOM {self.vdom}" if ok and record else
                  f"{what}: " + next((c["detail"] for c in checks if not c["ok"] and c["name"] != "tls"),
                                     "cannot read the policies"))
        return result(ok, detail + ("" if write else " (read only)") if ok else detail, write)

    async def _profile(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """The REST API admin's access profile (UNVERIFIED: system/api-user and system/accprofile answers)."""
        user = str(self.config.get("api_user") or "")
        out: dict[str, Any] = {"user": user, "profile": None, "write": None, "backup": None, "trusted": None}
        try:
            rows = await self._table(client, f"system/api-user/{quote(user, safe='')}", what="read the API user",
                                     hint="System > Administrator Users: Read", scope="global")
            row = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else rows
            if not isinstance(row, dict):
                return out
            out["profile"] = str(row.get("accprofile") or "") or None
            hub = self.config.get("hub_address")
            hosts = [_interface_address(h.get("ipv4-trusthost") or h.get("ipv6-trusthost"))
                     for h in row.get("trusthost") or [] if isinstance(h, dict)]
            if hub and hosts:
                out["trusted"] = any(h is not None and ipaddress.ip_address(hub) in h.network for h in hosts)
            if out["profile"] in ("super_admin", "super_admin_readonly"):
                out["write"] = out["profile"] == "super_admin"
                out["backup"] = out["profile"] == "super_admin"
                return out
            rows = await self._table(client, f"system/accprofile/{quote(out['profile'] or '', safe='')}",
                                     what="read the admin profile", scope="global")
            prof = rows[0] if isinstance(rows, list) and rows and isinstance(rows[0], dict) else rows
            if isinstance(prof, dict):
                fwgrp = str(prof.get("fwgrp") or "none").lower()
                custom = prof.get("fwgrp-permission") if isinstance(prof.get("fwgrp-permission"), dict) else {}
                out["write"] = fwgrp == "read-write" or (fwgrp == "custom"
                                                         and str(custom.get("policy") or "") == "read-write")
                out["backup"] = False  # configuration backups need super_admin (Fortinet KB)
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None or exc.status == 401:
                raise
        return out

    def _write_spec(self, raw: dict[str, Any], profile: dict[str, Any] | None) -> dict[str, Any] | None:
        if self.write_capability() is None or self._write_problems(raw):
            return None
        if profile and profile.get("write") is False:
            return None
        return {"ops": OPS, "rollback": "backup_restore", "window_s": WINDOW}

    def _write_problems(self, raw: dict[str, Any]) -> list[str]:
        """Why this FortiGate cannot take changes through Atrium (empty: it can)."""
        problems = []
        version = (raw.get("status") or {}).get("version")
        if version is None or version < MIN_WRITE:
            problems.append("device changes need FortiOS 7.4.1 or later (REST configuration transactions)")
        settings = raw.get("global")
        if settings is None:
            problems.append("the configuration save mode cannot be read (grant 'System > Configuration: Read')")
        elif str(settings.get("cfg-save") or "automatic").lower() != "automatic":
            problems.append("the configuration save mode is not 'automatic' (in 'revert' mode the FortiGate reverts "
                            "unsaved changes with a reboot) - Atrium only changes FortiGates that save automatically")
        if str((raw.get("central") or {}).get("type") or "").lower() == "fortimanager":
            problems.append("the FortiGate is managed by FortiManager: local changes would be overwritten by the next "
                            "policy package install - change it in FortiManager")
        return problems

    def _privilege_detail(self, raw: dict[str, Any] | None, profile: dict[str, Any] | None,
                          write: dict[str, Any] | None) -> str:
        access = (raw or {}).get("access") or {}
        missing = sorted({HINTS[k] for k in ("policies", "interfaces") if not access.get(k)})
        if raw is None:
            return "not checked (unsupported version)"
        if missing:
            return "cannot read the policies - the token's admin profile needs " + ", ".join(missing) + (
                "; " + "; ".join(raw["errors"][:2]) if raw.get("errors") else "")
        parts = ["reads policies and interfaces"]
        optional = sorted({HINTS[k] for k, _, required, _ in READS if not required and not access.get(k)})
        if optional:
            parts.append("not granted (optional): " + ", ".join(optional))
        if profile and profile.get("profile"):
            parts.append(f"admin profile '{display_id(profile['profile'])}'")
            if profile.get("trusted") is False:
                parts.append(f"the hub address {self.config.get('hub_address')} is not in the API user's trusted hosts")
        if profile and profile.get("write") is False:
            parts.append("read-only profile - recommended until device changes are enabled; changes are unavailable")
        elif profile and profile.get("write"):
            parts.append(LEAST_PRIVILEGE_NOTE if not self.config.get("read_only") else
                         "the token can write, but this connection is set to read only")
        else:
            parts.append("write access not checked (set the REST API admin name to read its profile); a profile with "
                         "read-write on Firewall > Policy can write - a read-only profile is recommended until device "
                         "changes are enabled")
        if profile and profile.get("backup"):
            parts.append("configuration backups: yes (super_admin)")
        else:
            parts.append("configuration backups need a super_admin profile (Fortinet KB) - without it Atrium cannot "
                         "take the backup its change safety model takes before a change")
        if write is None and raw is not None and self.write_capability() is not None:
            problems = self._write_problems(raw)
            if problems:
                parts.append("changes unavailable: " + "; ".join(problems))
        return "; ".join(parts)

    @staticmethod
    def _features(raw: dict[str, Any] | None, version: tuple[int, int, int] | None) -> str:
        if raw is None:
            return "not checked"
        parts = []
        parts.append("configuration transactions: " + ("yes (changes are staged and committed at once)"
                                                       if version and version >= MIN_WRITE else "no (before 7.4.1)"))
        settings = raw.get("global")
        parts.append("configuration save mode: " + (display_id(settings.get("cfg-save") or "automatic")
                                                    if settings is not None else "unknown"))
        central = raw.get("central")
        parts.append("central management: " + (display_id((central or {}).get("type") or "none")
                                               if central is not None else "unknown"))
        parts.append("no commit-confirm over the API: Atrium reverts a change with inverse operations "
                     "(a configuration restore reboots the unit and is left to the GUI)")
        parts.append("hit counts: " + ("yes" if raw.get("hits") else "no"))
        parts.append("backups: " + ("POST" if version and version >= BACKUP_BY_POST else "GET")
                     + " monitor/system/config/backup")
        return "; ".join(parts)

    # -- backups ---------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            status = await self._status(client)
            method = "POST" if status["version"] and status["version"] >= BACKUP_BY_POST else "GET"
            response = await self._send(client, method, "/monitor/system/config/backup", what="take a backup",
                                        params={"scope": "global"})
        if response.status_code == 401:
            raise self.error("The FortiGate refused the API token (HTTP 401)", status=401)
        if response.status_code == 403:
            raise self.error("The FortiGate refused the configuration backup (HTTP 403) - backups need a REST API "
                             "admin with the super_admin profile (Fortinet KB)", status=403)
        if response.status_code >= 300:
            raise self.error(f"The FortiGate could not produce a configuration backup (HTTP {response.status_code})",
                             status=response.status_code)
        content = response.content
        if not (content.lstrip().startswith(b"#config-version") or b"config system global" in content[:200_000]):
            raise self.error("The FortiGate's backup answer is not a configuration file")
        return {"content": content, "format": "text", "device_backup_id": None, "revision": None}

    # -- changes ---------------------------------------------------------------------------

    def _guard(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
        hub = [self.config["hub_address"]] if self.config.get("hub_address") else None
        return management_guard(record, ops, hub_addresses=hub, management_ports=[self.api_port])

    async def _state(self, client: httpx.AsyncClient) -> tuple[dict[str, Any], dict[str, Any]]:
        raw = await self.read(client)
        return raw, normalize_record(self.to_record(raw))

    def _binding(self, dev: Device, zone: str) -> tuple[str | None, str | None]:
        """(the srcintf/dstintf name for an op zone, a note) - an interface inside a FortiOS zone is bound through
        its zone (FortiOS only accepts the zone in policies)."""
        if zone in dev.zones:
            return zone, None
        if zone in dev.iface_names:
            owner = next((z for z, members in dev.zones.items() if zone in members), None)
            return (owner, f"interface {display_id(zone)} is in zone {display_id(owner)}: the policy uses the zone") \
                if owner else (zone, None)
        return None, None

    @staticmethod
    def _anchor(raw: dict[str, Any], src: str, dst: str) -> str | None:
        """The first enabled policy that could match traffic from `src` to `dst` (the new policy goes before it)."""
        for row in raw.get("policies") or []:
            pid = str(row.get("policyid"))
            if not POLICY_ID_RE.match(pid) or str(row.get("status") or "enable") == "disable":
                continue
            ins, outs = _names(row.get("srcintf")), _names(row.get("dstintf"))
            if (src in ins or "any" in ins) and (dst in outs or "any" in outs):
                return pid
        return None

    def _plan(self, ops: list[dict[str, Any]], raw: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
        """Problems, preview steps, notes and the writes for `ops` against what the FortiGate holds now."""
        dev = Device(raw)
        problems, steps, notes = list(self._write_problems(raw)), [], []
        policies = {str(r.get("policyid")): r for r in raw.get("policies") or [] if isinstance(r, dict)}
        names = {str(r.get("name") or "") for r in policies.values()}
        next_id = max([int(p) for p in policies if POLICY_ID_RE.match(p)] or [0]) + 1
        tcpudp = next((str(r.get("protocol")) for r in raw.get("services") or []
                       if isinstance(r, dict) and str(r.get("protocol") or "").upper().startswith("TCP/UDP")),
                      "TCP/UDP/SCTP")
        plan: dict[str, Any] = {"addresses": [], "services": [], "policies": [], "moves": [], "toggles": {}}
        made_addresses: dict[str, str] = {}
        made_services: dict[tuple[str, str | None], str] = {}
        for index, op in enumerate(ops):
            n = index + 1
            if op["op"] != "allow":
                status = "disable" if op["op"] == "disable_rules" else "enable"
                for ref in op["rules"]:
                    pid = ref["vendor_ref"] if POLICY_ID_RE.match(ref["vendor_ref"]) else ref["id"]
                    detail = f"{status} policy {display_id(pid)}"
                    if ref["id"].startswith("access:") or ref["vendor_ref"].startswith("access:"):
                        problems.append(f"rule {display_id(ref['id'])} is administrative access on an interface - "
                                        "Atrium never changes interface settings")
                    elif not POLICY_ID_RE.match(pid) or pid not in policies:
                        problems.append(f"policy {display_id(ref['id'])} is not on the FortiGate (re-read it first)")
                    elif str(policies[pid].get("status") or "enable") == status:
                        detail += f" (already {status}d - nothing to write)"
                    else:
                        plan["toggles"][pid] = status
                    steps.append({"op": index, "kind": f"{status}_rule", "position": "in place", "detail": detail})
                continue
            change_id = CHANGE_ID_RE.fullmatch(op["marker"]).group(1)  # parse_ops checked the marker's form
            name = f"atrium-{change_id}"[:35]  # UNVERIFIED: policy names are at most 35 characters
            if name in names or any(op["marker"] in str(r.get("comments") or "") for r in policies.values()):
                problems.append(f"operation {n}: a policy for {op['marker']} is already on the FortiGate")
            bindings = {}
            for side in ("source", "destination"):
                bound, note = self._binding(dev, op[side]["zone"])
                if bound is None:
                    problems.append(f"operation {n}: the FortiGate has no interface or zone "
                                    f"'{display_id(op[side]['zone'])}' in VDOM {self.vdom}")
                if note:
                    notes.append(note)
                bindings[side] = bound
                if any(ipaddress.ip_network(c).version != 4 for c in op[side]["cidrs"]):
                    problems.append(f"operation {n}: IPv6 networks are not supported by this connector yet")
            members: dict[str, list[str]] = {}
            for side in ("source", "destination"):
                members[side] = []
                for cidr in op[side]["cidrs"]:
                    existing = sorted((a for a, row in dev.addr_rows.items()
                                       if row["_table"] == "address" and str(row.get("type") or "ipmask") == "ipmask"
                                       and _subnet(row.get("subnet")) == cidr and a.lower() != "all"),
                                      key=lambda a: (not a.startswith("atrium-"), a))
                    if existing:
                        members[side].append(existing[0])
                        continue
                    network = ipaddress.ip_network(cidr)
                    object_name = made_addresses.get(cidr) or f"atrium-net-{network.network_address}_{network.prefixlen}"
                    if cidr not in made_addresses:
                        made_addresses[cidr] = object_name
                        plan["addresses"].append({"name": object_name, "type": "ipmask",
                                                  "subnet": f"{network.network_address} {network.netmask}",
                                                  "comment": f"created by Atrium for {op['marker']}"})
                    members[side].append(object_name)
            services = []
            for svc in op["services"]:
                key = (svc["proto"], svc.get("ports"))
                existing = sorted((s for s in dev.svc_rows if dev.exact_service(s) == key),
                                  key=lambda s: (not s.startswith("atrium-"), s))
                if existing:
                    services.append(existing[0])
                    continue
                if key not in made_services:
                    object_name = f"atrium-{svc['proto']}" + (f"-{svc['ports'].replace(',', '_')}" if svc.get("ports")
                                                              else "")
                    made_services[key] = object_name
                    body: dict[str, Any] = {"name": object_name, "comment": f"created by Atrium for {op['marker']}"}
                    if svc["proto"] == "icmp":
                        body["protocol"] = "ICMP"
                    else:
                        body.update({"protocol": tcpudp, f"{svc['proto']}-portrange": svc["ports"].replace(",", " ")})
                    plan["services"].append(body)
                services.append(made_services[key])
            pid = next_id
            next_id += 1
            if pid > MAX_POLICY_ID:
                problems.append(f"operation {n}: no free policy id")
            plan["policies"].append({
                "policyid": pid, "name": name, "srcintf": [{"name": bindings["source"] or ""}],
                "dstintf": [{"name": bindings["destination"] or ""}],
                "srcaddr": [{"name": m} for m in members["source"]], "dstaddr": [{"name": m} for m in members["destination"]],
                "service": [{"name": s} for s in services], "schedule": "always", "action": "accept",
                "logtraffic": "all" if op.get("log", True) else "disable", "status": "enable", "nat": "disable",
                "comments": f"{op['marker']} {op.get('description') or ''}".strip()[:1023],
            })
            plan.setdefault("created", []).append({"op": index, "id": str(pid), "vendor_ref": str(pid)})
            anchor = self._anchor(raw, bindings["source"] or "", bindings["destination"] or "")
            if anchor:
                plan["moves"].append((pid, anchor))
            created = [a["name"] for a in plan["addresses"]] + [s["name"] for s in plan["services"]]
            steps.append({"op": index, "kind": "add_rule",
                          "position": f"before policy {anchor} (the first policy for "
                                      f"{display_id(bindings['source'])} -> {display_id(bindings['destination'])})"
                          if anchor else "at the end of the policy list (above the implicit deny)",
                          "detail": f"policy {pid} '{name}' accepting {', '.join(display_id(s) for s in services)}"
                                    + (f"; new objects: {', '.join(created)}" if created else "")})
        plan["problems"], plan["steps"], plan["notes"] = problems, steps, notes
        plan["guard"] = self._guard(record, ops)
        return plan

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.client() as client:
            raw, record = await self._state(client)
        plan = self._plan(ops, raw, record)
        notes = plan["notes"] + ["FortiOS stages the change in a configuration transaction and commits it at once",
                                 "there is no automatic revert: Atrium reverts with inverse operations (the "
                                 "configuration backup it takes before writing is restored through the GUI)"]
        if self.write_capability() is None:
            plan["problems"].append("this connection is set to read only")
        if record["revision"] != snapshot.get("revision"):
            notes.append("the firewall changed since the snapshot: refresh before approving")
        return {"steps": plan["steps"], "notes": notes, "problems": plan["guard"] + plan["problems"]}

    @staticmethod
    def _token(info: dict[str, Any]) -> str:
        return json.dumps(info, separators=(",", ":"), sort_keys=True)

    def _parse_token(self, token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and info.get("vdom") == self.vdom
            assert all(isinstance(p, int) and 0 < p <= MAX_POLICY_ID for p in info.get("policies") or [])
            assert all(OBJECT_RE.match(str(n)) for n in [*(info.get("addresses") or []), *(info.get("services") or [])])
            assert all(POLICY_ID_RE.match(p) and s in ("enable", "disable") for p, s in (info.get("toggled") or {}).items())
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this FortiGate connection", code="invalid", state="unknown") from exc
        return info

    async def _transaction(self, client: httpx.AsyncClient, writes: list[dict[str, Any]], what: str) -> None:
        """Stage `writes` in one configuration transaction and commit it. A failure before the commit aborts (the
        firewall is unchanged: uncommitted changes are invisible and discarded); a failed commit raises with state
        unknown (the caller re-reads)."""
        try:
            answer = await self._call(client, "POST", "/cmdb", what="start a configuration transaction",
                                      params={"action": "transaction-start", "vdom": self.vdom},
                                      body={"timeout": TRANSACTION_TIMEOUT})
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unchanged", status=exc.status) from exc
        results = answer.get("results") if isinstance(answer.get("results"), dict) else {}
        tid = next((v for v in (answer.get("transaction-id"), results.get("transaction-id"),
                                results.get("transaction_id")) if isinstance(v, int) and not isinstance(v, bool)), None)
        if tid is None:  # UNVERIFIED: the id is documented at the answer's top level
            raise ChangeError("The FortiGate did not answer with a transaction id - nothing was changed",
                              code="failed", state="unchanged")
        try:
            for write in writes:
                await self._call(client, write["method"], write["path"], what=write["what"], body=write.get("body"),
                                 params={"vdom": self.vdom, **(write.get("params") or {})}, tid=tid,
                                 hint=write.get("hint"))
            shown = await self._call(client, "GET", "/cmdb", what="show the staged commands",
                                     params={"action": "transaction-show", "transaction-id": tid})
            if not shown.get("results"):
                raise ConnectorError("The FortiGate staged no commands for the change")
        except ConnectorError as exc:
            await self._abort(client, tid)
            raise ChangeError(f"{exc.message} - the transaction was abandoned, nothing was changed",
                              code="unreachable" if exc.status is None else "failed", state="unchanged",
                              status=exc.status) from exc
        try:
            await self._call(client, "POST", "/cmdb", what=f"commit the transaction ({what})",
                             params={"action": "transaction-commit", "vdom": self.vdom}, body={"transaction-id": tid})
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed", state="unknown",
                              status=exc.status) from exc

    async def _abort(self, client: httpx.AsyncClient, tid: int) -> None:
        try:  # UNVERIFIED action name; without it the transaction is discarded after 5 idle minutes [V]
            await self._call(client, "POST", "/cmdb", what="abort the transaction",
                             params={"action": "transaction-abort", "vdom": self.vdom}, body={"transaction-id": tid})
        except ConnectorError:
            pass

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This FortiGate connection is set to read only", code="unsupported", state="unchanged")
        try:
            client = self.client()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="invalid", state="unchanged") from exc
        async with client:
            try:
                raw, record = await self._state(client)
            except ConnectorError as exc:
                raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                  state="unchanged") from exc
            if record["revision"] != base_revision:
                raise ChangeError("The FortiGate's policies changed since the preview - re-read it and preview again",
                                  code="stale", state="unchanged")
            plan = self._plan(ops, raw, record)
            if plan["guard"]:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(plan["guard"]), code="lockout",
                                  state="unchanged")
            if plan["problems"]:
                raise ChangeError("; ".join(plan["problems"]), code="invalid", state="unchanged")
            policies = {str(r.get("policyid")): r for r in raw.get("policies") or []}
            info: dict[str, Any] = {
                "v": 1, "vdom": self.vdom, "policies": [p["policyid"] for p in plan["policies"]],
                "addresses": [a["name"] for a in plan["addresses"]], "services": [s["name"] for s in plan["services"]],
                "toggled": {pid: "disable" if str(policies[pid].get("status") or "enable") == "disable" else "enable"
                            for pid in plan["toggles"]}}
            if len(self._token(info)) > MAX_TOKEN:
                raise ChangeError("Too many policies in one change for the FortiGate - split it", code="invalid",
                                  state="unchanged")
            notes = await self._save_revision(client, ops)
            writes = [{"method": "POST", "path": "/cmdb/firewall/address", "body": a, "what": "create an address object",
                       "hint": HINTS["addresses"].replace("Read", "Read-Write")} for a in plan["addresses"]]
            writes += [{"method": "POST", "path": "/cmdb/firewall.service/custom", "body": s,
                        "what": "create a service object", "hint": HINTS["services"].replace("Read", "Read-Write")}
                       for s in plan["services"]]
            writes += [{"method": "POST", "path": "/cmdb/firewall/policy", "body": p, "what": "create the policy",
                        "hint": "Firewall > Policy: Read-Write"} for p in plan["policies"]]
            writes += [{"method": "PUT", "path": f"/cmdb/firewall/policy/{pid}", "params": {"action": "move",
                                                                                          "before": anchor},
                        "what": "move the policy", "hint": "Firewall > Policy: Read-Write"}
                       for pid, anchor in plan["moves"]]
            writes += [{"method": "PUT", "path": f"/cmdb/firewall/policy/{pid}", "body": {"status": status},
                        "what": f"{status} policy {pid}", "hint": "Firewall > Policy: Read-Write"}
                       for pid, status in plan["toggles"].items()]
            try:
                if writes:
                    await self._transaction(client, writes, "apply the change")
            except ChangeError as exc:
                if exc.state != "unknown":
                    raise
                state = await self._settled(client, info, exc)
                if state != "applied":
                    raise ChangeError(exc.message, code=exc.code, state=state) from exc
        disabled = [pid for pid, s in plan["toggles"].items() if s == "disable"]
        enabled = [pid for pid, s in plan["toggles"].items() if s == "enable"]
        notes.append("no automatic revert on FortiOS: Atrium rolls back with inverse operations")
        return {"token": self._token(info), "rollback_until": None, "revision": None, "created": plan.get("created", []),
                "disabled": disabled, "enabled": enabled, "notes": notes}

    async def _save_revision(self, client: httpx.AsyncClient, ops: list[dict[str, Any]]) -> list[str]:
        """A configuration revision on the FortiGate before writing - best effort (the hub's backup is the safety
        net; the permission this needs is not documented)."""
        marker = next((op["marker"] for op in ops if op["op"] == "allow"), "a change")
        try:
            await self._call(client, "POST", "/monitor/system/config-revision/save", what="save a config revision",
                             body={"comments": f"before Atrium {marker}"})
            return ["a configuration revision was saved on the FortiGate before writing"]
        except ConnectorError as exc:
            if exc.status is None:
                raise ChangeError(exc.message, code="unreachable", state="unchanged") from exc
            return [f"no configuration revision was saved on the FortiGate (HTTP {exc.status})"]

    async def _change_state(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what the FortiGate's policies show of the change now."""
        rows = await self._table(client, "firewall/policy", what="read the policies", hint=HINTS["policies"])
        by_id = {str(r.get("policyid")): r for r in rows or [] if isinstance(r, dict)}
        applied, reverted = [], []
        for pid in info.get("policies") or []:
            present = str(pid) in by_id and str(by_id[str(pid)].get("status") or "enable") != "disable"
            applied.append(present)
            reverted.append(not present)
        for pid, previous in (info.get("toggled") or {}).items():
            now = str((by_id.get(pid) or {}).get("status") or "enable")
            applied.append(now != previous)
            reverted.append(now == previous)
        if all(applied):
            return "applied"
        return "reverted" if all(reverted) else "partial"

    async def _settled(self, client: httpx.AsyncClient, info: dict[str, Any], exc: ChangeError) -> str:
        """After a failed commit: "applied", "unchanged" or "unknown" from a re-read."""
        try:
            state = await self._change_state(client, info)
        except ConnectorError:
            return "unknown"
        return {"applied": "applied", "reverted": "unchanged"}.get(state, "unknown")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.client() as client:
                state = await self._change_state(client, info)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        if state == "reverted":
            raise ChangeError("The change is no longer on the FortiGate", code="failed", state="rolled_back")
        if state == "partial":
            raise ChangeError("The FortiGate holds only part of the change", code="failed", state="unknown")
        return {"confirmed": True, "revision": None,
                "notes": ["nothing to confirm on FortiOS: the change was saved when the transaction was committed "
                          "(configuration save mode automatic)"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        notes: list[str] = []
        try:
            async with self.client() as client:
                state = await self._change_state(client, info)
                if state != "reverted":
                    rows = await self._table(client, "firewall/policy", what="read the policies", hint=HINTS["policies"])
                    present = {str(r.get("policyid")) for r in rows or [] if isinstance(r, dict)}
                    writes = [{"method": "DELETE", "path": f"/cmdb/firewall/policy/{pid}", "what": "delete the policy",
                               "hint": "Firewall > Policy: Read-Write"}
                              for pid in info.get("policies") or [] if str(pid) in present]
                    writes += [{"method": "PUT", "path": f"/cmdb/firewall/policy/{pid}", "body": {"status": previous},
                                "what": f"restore policy {pid}", "hint": "Firewall > Policy: Read-Write"}
                               for pid, previous in (info.get("toggled") or {}).items() if pid in present]
                    if writes:
                        await self._transaction(client, writes, "roll back the change")
                    if await self._change_state(client, info) != "reverted":
                        raise ChangeError("The change is still on the FortiGate after undoing it", code="failed",
                                          state="applied")
                else:
                    notes.append("the FortiGate no longer held the change")
                notes += await self._cleanup(client, info)
        except ChangeError as exc:
            raise ChangeError(exc.message + " - restore Atrium's backup in System > Configuration > Restore if needed",
                              code=exc.code, state="applied" if exc.state == "unchanged" else exc.state) from exc
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        return {"rolled_back": True, "method": "inverse_ops", "notes": notes}

    async def _cleanup(self, client: httpx.AsyncClient, info: dict[str, Any]) -> list[str]:
        """Remove the objects the change created, when nothing uses them any more (best effort)."""
        kept = []
        for path, names in (("firewall.service/custom", info.get("services") or []),
                            ("firewall/address", info.get("addresses") or [])):
            for name in names:
                try:
                    await self._call(client, "DELETE", f"/cmdb/{path}/{quote(name, safe='')}", what="remove an object",
                                     params={"vdom": self.vdom})
                except ConnectorError as exc:
                    if exc.status is None:
                        raise
                    if exc.status != 404:
                        kept.append(name)
        return [f"kept {len(kept)} object(s) Atrium created (still in use or not removable): {', '.join(kept)}"] \
            if kept else []
