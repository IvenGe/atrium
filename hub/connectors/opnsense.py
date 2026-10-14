"""OPNsense connector: reads the firewall through its REST API into the network model (``netmodel.py``) and makes
guarded rule changes (one allow rule between two interface networks, disabling / re-enabling rules) for the hub's
network change path.

Checked against the opnsense/core sources (stable/24.7, 25.7, 26.1 and master = 26.7) and docs.opnsense.org,
October 2026 (docs/research/fw-opnsense-pfsense-mikrotik.md section 1):

- Authentication: API key + secret as HTTP Basic credentials. 401 = wrong key; 403 = the key's user lacks the
  privilege for that URL. Privileges are URL patterns, with no read / write split. "System: Deny config write"
  (``user-config-readonly``) makes every save fail. The GUI certificate is self-signed by default (set the CA file).
  Redirects are not followed, so the URL must be the https:// address.
- Reading - 26.1 and later only:
  - ``search_rule`` without an ``interface`` returns every rule in evaluation order: Rules [new] (MVC) rows with uuid
    and raw values, plus the classic and automatic rules (``legacy``; their interfaces given by description).
  - 25.x returns only floating rules that way and 24.x only four fields, so older versions are refused rather than
    read partially.
  - Also read: interfaces (``interfaces/overview/interfaces_info``), aliases, interface groups, rule statistics
    (packets per uuid; optional) and the version (``diagnostics/system/system_information``).
  - Interface groups are not zones: a rule on a group is read as a rule on its member interfaces.
- Revision: OPNsense's own config revision changes with every saved setting, so the snapshot revision is a hash of
  what was read (rules, aliases, interfaces, groups). A change is refused when the ruleset moved after the preview.
- Changes:
  - ``add_rule``, ``toggle_rule/{uuid}/{0|1}`` and ``del_rule`` answer HTTP 200 even on failure
    (``{"result": "failed", "validations"}``), so the result is checked.
  - They write config.xml at once, but pf keeps running the old ruleset until ``apply``.
  - 26.1.x (rollback mode ``savepoint``): ``savepoint``, the writes, then ``apply/{revision}`` reloads pf and starts a
    60 s timer. The timer restores the Filter model unless ``cancelRollback/{revision}`` arrives.
    ``revert/{revision}`` rolls back at once.
  - 26.7 and later (``backup_restore``; savepoints were removed by opnsense/core PR #10411): the newest config history
    entry is recorded before writing. Rollback deletes the created rules, toggles the others back and applies. If a
    re-read does not show the old state, ``core/backup/revert_backup/{id}`` restores the whole config.xml and the
    filter is reloaded.
  - Which of the two applies is probed: ``GET .../savepoint`` answers ``{"status": "error"}`` where it exists and 404
    where it was removed.
- Write-privilege probe without side effects: ``GET core/backup/revert_backup/{x}`` checks "Deny config write" before
  the request method. A read-only key therefore gets an error (a UserException: HTTP 500 with ``errorMessage`` "User
  ... denied for write access (user-config-readonly set)"), and a writable one ``{"status": "failed"}``.
- Backups: ``core/backup/download/this/{id}`` returns the raw config.xml. It holds password hashes and keys, so it is
  secret material: never logged or returned.
- Placement: Rules [new] interface rules are evaluated before classic ones. A new rule gets a ``sequence`` below
  every MVC rule on its interface (or is moved before the first one). Floating and group rules still come first.

UNVERIFIED (no OPNsense instance was available; every call above comes from the source code and is tested against
answers shaped like it): the string encoding of values in search_rule rows ("1"/"0"); that the automatic
"__<if>_network" aliases hold the interface's networks; the configd output of ``apply``; the console steps named in
lockout messages.
"""

from __future__ import annotations

import asyncio
import hashlib
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
MIN_VERSION = (26, 1)
SAVEPOINT_WINDOW = 60  # rollback_timer.php: 60 checks one second apart
CONFIRM_MARGIN = 10  # never cancel a savepoint timer this close to its end (it may already be reverting)
SETTLE = 8  # how long to let a savepoint timer finish before reporting what it did
BACKUP_WINDOW = 300  # backup_restore: how long the hub may take to verify before it rolls back
MAX_TOKEN = 4096
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
BACKUP_ID_RE = re.compile(r"^config-[0-9]+(\.[0-9]+)?(_[0-9]+)?\.xml$")
REVISION_RE = re.compile(r"^[0-9]+(\.[0-9]+)?$")
VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
READ_ONLY_RE = re.compile(r"denied for write access|user-config-readonly", re.IGNORECASE)
INTERNAL_NET_RE = re.compile(r"^__(\w+)_network$")
TRUE = ("1", "true", "yes", "on")
# PortField's well-known service names (opnsense/core Base/FieldTypes/PortField.php)
WELL_KNOWN = {
    "afs3-fileserver": 7000, "aol": 5190, "auth": 113, "avt-profile-1": 5004, "cvsup": 5999, "domain": 53,
    "domain-s": 853, "ftp": 21, "hbci": 3000, "http": 80, "https": 443, "igmpv3lite": 465, "imap": 143, "imaps": 993,
    "ipsec-msft": 10000, "ipsec-nat-t": 4500, "isakmp": 500, "l2f": 1701, "ldap": 389, "ldaps": 636,
    "microsoft-ds": 445, "ms-streaming": 1755, "ms-wbt-server": 3389, "msnp": 1863, "nat-stun-port": 3478,
    "netbios-dgm": 138, "netbios-ns": 137, "netbios-ssn": 139, "nntp": 119, "ntp": 123, "openvpn": 1194, "pop3": 110,
    "pop3s": 995, "pptp": 1723, "radius": 1812, "radius-acct": 1813, "rfb": 5900, "sip": 5060, "sip-tls": 5061,
    "smtp": 25, "snmp": 161, "snmptrap": 162, "ssh": 22, "submission": 587, "submissions": 465, "telnet": 23,
    "teredo": 3544, "tftp": 69, "urd": 465, "wins": 1512,
}
# what each read needs (System > Access > Groups > Privileges)
PRIVILEGES = {
    "rules": "Firewall: Rules [new] (page-filter-api)",
    "interfaces": "Status: Interfaces (page-status-interfaces)",
    "aliases": "Firewall: Aliases (page-firewall-aliases)",
    "groups": "Firewall: Groups (page-interfaces-groups-edit)",
    "stats": "Firewall: Rules (page-firewall-rules)",
    "version": "Lobby: Dashboard (page-system-login-logout)",
    "backups": "Diagnostics: Configuration History (page-diagnostics-configurationhistory)",
}
VOLATILE_RULE_KEYS = {"sort_order", "prio_group", "category_colors", "pf_rules", "evaluations", "packets", "bytes",
                      "states", "audit", "is_automatic"}
VOLATILE_ALIAS_KEYS = {"current_items", "last_updated", "eval_nomatch", "eval_match", "in_block_p", "in_block_b",
                       "in_pass_p", "in_pass_b", "out_block_p", "out_block_b", "out_pass_p", "out_pass_b"}


def truthy(value: Any) -> bool:
    # UNVERIFIED: OPNsense's grids encode booleans as "1"/"0" strings; real booleans are accepted too
    if isinstance(value, bool):
        return value
    return str(value if value is not None else "").strip().lower() in TRUE


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """(26, 7, 6) from "OPNsense 26.7.6-amd64", "26.1.11_2" or "26.1"."""
    match = VERSION_RE.search(str(text or ""))
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def _split(value: Any) -> list[str]:
    """"lan,opt1" / "a\\nb" / ["a", "b"] -> ["lan", "opt1"] (OPNsense joins multiple values with "," or newlines)."""
    items = value if isinstance(value, (list, tuple)) else re.split(r"[\n,]+", str(value or ""))
    return [text for text in (str(v).strip() for v in items) if text]


class TlsError(ConnectorError):
    """The firewall answered, but its certificate is not trusted."""


def _rows(answer: Any, what: str) -> list[dict[str, Any]]:
    rows = answer.get("rows") if isinstance(answer, dict) else answer if isinstance(answer, list) else None
    if not isinstance(rows, list):
        raise ConnectorError(f"Unexpected answer from OPNsense ({what}): no 'rows' list")
    return [r for r in rows if isinstance(r, dict)]


def writable_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Rules [new] rows by uuid - only rows whose uuid really is a UUID (it goes into URL paths)."""
    return {str(r["uuid"]): r for r in rows if not truthy(r.get("legacy")) and UUID_RE.match(str(r.get("uuid") or ""))}


def _stable(row: dict[str, Any], drop: set[str]) -> dict[str, Any]:
    """A row without display labels ("%field"), alias metadata and volatile counters - what the revision hashes."""
    return {k: v for k, v in row.items() if not k.startswith(("%", "alias_meta_")) and k not in drop}


class Device:
    """What one read of the firewall returned, and the lookups normalisation needs."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.version: tuple[int, int, int] | None = raw.get("version")
        self.interfaces = [r for r in raw.get("interfaces") or [] if str(r.get("identifier") or "").strip()]
        self.by_id = {str(r["identifier"]): r for r in self.interfaces}
        self.by_descr = {str(r.get("description") or "").strip().lower(): str(r["identifier"])
                         for r in self.interfaces if str(r.get("description") or "").strip()}
        self.groups = {str(g.get("ifname")): [m for m in _split(g.get("members")) if m in self.by_id]
                       for g in raw.get("groups") or [] if g.get("ifname")}
        self.alias_rows = {str(a.get("name")): a for a in raw.get("aliases") or [] if a.get("name")}
        self.notes: list[str] = []

    # -- interfaces ----------------------------------------------------------------------

    def iface(self, token: str, legacy: bool = False) -> str | None:
        """The interface identifier a rule token names (classic rows name interfaces by their description)."""
        if token in self.by_id:
            return token
        return self.by_descr.get(token.strip().lower()) if legacy and token not in self.alias_rows else None

    def members(self, token: str, legacy: bool = False) -> list[str] | None:
        """Interface ids for an interface or interface-group token; None when it is neither."""
        if token in self.groups:
            return self.groups[token]
        found = self.iface(token, legacy)
        return [found] if found else None

    def addresses(self, iface_id: str) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
        row = self.by_id.get(iface_id) or {}
        out = []
        for entry in [*(row.get("ipv4") or []), *(row.get("ipv6") or [])]:
            text = entry.get("ipaddr") if isinstance(entry, dict) else entry
            try:
                found = ipaddress.ip_interface(str(text or "").split("%")[0])
            except ValueError:
                continue
            if not found.ip.is_link_local:
                out.append(found)
        if not out:  # older shapes: addr4 / addr6 as "ip/bits"
            for key in ("addr4", "addr6"):
                try:
                    found = ipaddress.ip_interface(str(row.get(key) or "").split("%")[0])
                except ValueError:
                    continue
                if not found.ip.is_link_local:
                    out.append(found)
        return out

    # -- aliases -------------------------------------------------------------------------

    def alias(self, name: str, depth: int = 0) -> dict[str, Any]:
        """{"name", "kind", "cidrs", "ports", "resolved"} for one alias, nested aliases resolved (8 levels)."""
        row = self.alias_rows.get(name) or {}
        kind_raw = str(row.get("type") or "").lower()
        kind = {"host": "host", "network": "network", "networkgroup": "network", "port": "port", "url": "url",
                "urltable": "url", "urljson": "url", "geoip": "geoip"}.get(kind_raw, "other")
        out: dict[str, Any] = {"name": name, "kind": kind, "cidrs": [], "ports": None, "resolved": True}
        if not row or depth > 8 or not truthy(row.get("enabled", "1")):
            out["resolved"] = False
            return out
        entries = _split(row.get("content"))
        if kind_raw == "internal":
            match = INTERNAL_NET_RE.match(name)  # UNVERIFIED: "__lan_network" holds the interface's networks
            iface = self.iface(match.group(1)) if match else None
            out["kind"] = "network"
            out["cidrs"] = [str(a.network) for a in self.addresses(iface)] if iface else []
            out["resolved"] = bool(out["cidrs"])
            return out
        if kind == "port":
            ports: list[str] = []
            for entry in entries:
                if entry in self.alias_rows:
                    nested = self.alias(entry, depth + 1)
                    if not nested["resolved"] or not nested["ports"]:
                        out["resolved"] = False
                        continue
                    ports.append(nested["ports"])
                    continue
                try:
                    parsed = parse_ports(WELL_KNOWN.get(entry.lower(), entry))
                except ValueError:
                    out["resolved"] = False
                    continue
                if parsed:
                    ports.append(parsed)
            out["ports"] = ",".join(ports) or None
            out["resolved"] = out["resolved"] and bool(ports)
            return out
        if kind not in ("host", "network"):
            out["resolved"] = False
            return out
        cidrs: list[str] = []
        for entry in entries:
            cidr = normalise_cidr(entry)
            if cidr:
                cidrs.append(cidr)
            elif entry in self.alias_rows:
                nested = self.alias(entry, depth + 1)
                cidrs += nested["cidrs"]
                out["resolved"] = out["resolved"] and nested["resolved"]
            elif "-" in entry and all(normalise_cidr(p) for p in entry.split("-", 1)):
                try:
                    low, high = (ipaddress.ip_address(p.strip()) for p in entry.split("-", 1))
                    cidrs += [str(n) for n in ipaddress.summarize_address_range(low, high)]
                except (ValueError, TypeError):
                    out["resolved"] = False
            else:  # a host name (resolved by the firewall at run time), a MAC, ...
                out["resolved"] = False
        out["cidrs"] = list(dict.fromkeys(cidrs))[:2000]
        return out

    def port_alias(self, name: str) -> dict[str, Any] | None:
        row = self.alias_rows.get(name)
        return self.alias(name) if row and str(row.get("type") or "").lower() == "port" else None

    # -- rules ---------------------------------------------------------------------------

    def endpoint(self, value: Any, negate: Any, legacy: bool) -> dict[str, Any]:
        tokens = _split(value)
        if not tokens or "any" in [t.lower() for t in tokens]:
            return {"any": True}
        out: dict[str, Any] = {"cidrs": [], "aliases": [], "nets": [], "self": False, "negate": truthy(negate)}
        for token in tokens:
            if token == "(self)":
                out["self"] = True
            elif token in self.by_id or token in self.groups:  # "lan" = LAN net, a group = its members' nets
                out["nets"] += self.members(token) or []
            elif token in self.alias_rows:
                out["aliases"].append(token)
            elif token.endswith("ip") and token[:-2] in self.by_id:  # "lanip" = the firewall's LAN address
                found = self.addresses(token[:-2])
                if found:
                    out["cidrs"] += [str(ipaddress.ip_network(a.ip)) for a in found]
                else:
                    out["self"] = True  # an interface address that is not known right now (DHCP, down)
            elif normalise_cidr(token):
                out["cidrs"].append(normalise_cidr(token))
            elif legacy and self.iface(token, legacy):
                out["nets"].append(self.iface(token, legacy))
            else:  # an alias the key cannot read: kept by name, the hub treats an unknown alias as "anything"
                out["aliases"].append(token)
        return out

    def services(self, protocol: Any, port: Any) -> list[dict[str, Any]] | None:
        proto = str(protocol or "").strip().lower()
        if proto in ("", "any"):
            return None
        port = str(port or "").strip()
        ports, alias = None, None
        if port and port.lower() != "any":
            resolved = self.port_alias(port)
            if resolved is not None:
                ports, alias = (resolved["ports"], None) if resolved["resolved"] else (None, port)
            else:  # "443", "8000-8080", "https", or a list ("443 80 22" in automatic rules)
                try:
                    ports = parse_ports([WELL_KNOWN.get(p.lower(), p) for p in re.split(r"[\s,]+", port) if p])
                except ValueError:
                    alias = port
        out = []
        for name in proto.split("/"):
            name = name.strip()
            if name in ("tcp", "udp"):
                out.append({"proto": name, "ports": ports, "alias": alias})
            elif name:
                out.append({"proto": name})
        return out or None

    def rule(self, row: dict[str, Any], order: int, stats: dict[str, Any]) -> dict[str, Any] | None:
        uuid = str(row.get("uuid") or "").strip()
        legacy = truthy(row.get("legacy")) or not UUID_RE.match(uuid)  # device text: only real uuids are writable
        action = str(row.get("action") or "pass").strip().lower()
        if action not in ("pass", "block", "reject"):
            return None  # "match" rules neither pass nor block
        tokens = _split(row.get("interface"))
        interfaces: list[str] = []
        for token in tokens:
            interfaces += self.members(token, legacy) or [token]
        negated = truthy(row.get("interfacenot"))
        floating = negated or len(tokens) != 1 or truthy(row.get("floating"))
        if negated:
            interfaces = []  # "every interface but these": read as floating (wider, never narrower)
        hits = (stats.get(uuid) or {}).get("packets") if uuid else None
        return {
            "id": uuid if not legacy else f"legacy:{uuid or order}",
            "vendor_ref": uuid if not legacy else f"legacy:{uuid or order}",
            "order": order, "enabled": truthy(row.get("enabled", "1")), "action": action,
            "interfaces": list(dict.fromkeys(interfaces)), "floating": floating,
            "direction": str(row.get("direction") or "in").strip().lower(),
            "quick": truthy(row.get("quick", "1")) if not truthy(row.get("legacy")) else True,
            "source": self.endpoint(row.get("source_net"), row.get("source_not"), legacy),
            "destination": self.endpoint(row.get("destination_net"), row.get("destination_not"), legacy),
            "services": self.services(row.get("protocol"), row.get("destination_port")),
            "log": truthy(row.get("log")), "description": row.get("description") or "",
            "hits": hits,
        }


class OpnsenseConnector(Connector):
    kind = "opnsense"
    title = "OPNsense"
    description = ("Firewall (REST API, 26.1 or later): reads interfaces, aliases and every rule into the Network app; "
                   "with device changes enabled, adds one allow rule or disables rules under the change safety model.")
    fields = [
        ConnectorField(name="base_url", label="OPNsense URL", kind="url", required=True,
                       placeholder="https://10.0.99.1",
                       help="The https address of the web GUI (with the port if it is not 443)."),
        ConnectorField(name="api_key", label="API key", kind="secret", required=True,
                       help="System > Access > Users > (user) > API keys. Use a dedicated user, one key per "
                            "application."),
        ConnectorField(name="api_secret", label="API secret", kind="secret", required=True),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the key again."),
        ConnectorField(name="ca_file", label="CA certificate file", kind="text",
                       placeholder="/etc/atrium/opnsense-ca.pem",
                       help="PEM file on the hub's machine with the GUI certificate or its CA (OPNsense uses a "
                            "self-signed certificate by default). Empty: the system's trusted CAs."),
        ConnectorField(name="hub_address", label="Hub address as the firewall sees it", kind="text",
                       placeholder="10.0.99.10",
                       help="Optional. The management-path guard then only protects rules that carry the hub's own "
                            "API traffic; empty, it protects every rule that can reach the firewall."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this firewall through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "backup_restore", "window_s": BACKUP_WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)
    sleep: Callable[[float], Any] = staticmethod(asyncio.sleep)

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("opnsense",))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        # switching certificate checks off would let the stored key go to whoever answers: enter it again
        return super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.hostname:
            raise ConnectorError("The OPNsense URL must start with https:// (the API key travels in every request)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API key and secret in their own fields, not in the URL")
        try:
            parts.port
        except ValueError as exc:
            raise ConnectorError("The OPNsense URL has an invalid port") from exc
        config["base_url"] = re.sub(r"(?i)/api$", "", base)
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
        parts = urlsplit(str(self.config.get("base_url") or ""))
        return parts.port or 443

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise TlsError(f"Cannot load the CA certificate file {ca_file}: "
                           f"{getattr(exc, 'strerror', None) or exc.__class__.__name__}") from exc
        if ca_file:  # a self-signed GUI certificate is often not RFC 5280-strict; chain and host name still checked
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        key, secret = self.secrets.get("api_key"), self.secrets.get("api_secret")
        if not key or not secret:
            raise self.error("Enter the OPNsense API key and secret in the connection settings")
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        return self.http(str(self.config.get("base_url") or "").rstrip("/") + "/api", auth=httpx.BasicAuth(key, secret),
                         headers={"Accept": "application/json"}, verify=verify)

    async def _send(self, client: httpx.AsyncClient, method: str, path: str, *, what: str,
                    body: Any = None) -> httpx.Response:
        try:
            if body is None:
                return await client.request(method, path)
            return await client.request(method, path, json=body)
        except httpx.TimeoutException as exc:
            raise self.error(f"OPNsense at {self.host}:{self.api_port} did not answer in time ({what})") from exc
        except httpx.ConnectError as exc:
            text = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text.lower():
                raise TlsError(self.redact("OPNsense's TLS certificate is not trusted - set the CA certificate file "
                                           "(the GUI certificate or its CA)")) from exc
            raise self.error(f"Cannot reach OPNsense at {self.host}:{self.api_port} "
                             f"({exc.__class__.__name__})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach OPNsense: {exc.__class__.__name__}") from exc

    async def _call(self, client: httpx.AsyncClient, method: str, path: str, *, what: str, body: Any = None,
                    privilege: str | None = None) -> Any:
        """The JSON answer of one API call; a ConnectorError (with the privilege to grant on 403) otherwise."""
        response = await self._send(client, method, path, what=what, body=body)
        code = response.status_code
        if code == 401:
            raise self.error("OPNsense rejected the API key and secret (HTTP 401)", status=401)
        if code == 403:
            hint = f" - grant the key's user '{PRIVILEGES[privilege]}'" if privilege else ""
            raise self.error(f"OPNsense refused access to {what} (HTTP 403){hint}", status=403)
        if code == 404:
            raise self.error(f"OPNsense has no API endpoint for {what} (HTTP 404) - check the URL and the version",
                             status=404)
        if code in (301, 302, 303, 307, 308):
            raise self.error("OPNsense redirected the request - use the exact https:// address of the GUI",
                             status=code)
        if code >= 300:
            message = self._error_message(response)
            raise self.error(f"OPNsense could not {what} (HTTP {code}){': ' + message if message else ''}",
                             status=code, excerpt=response.text[:300])
        try:
            return response.json()
        except ValueError as exc:
            raise self.error(f"OPNsense did not answer with JSON ({what}) - is the URL the GUI address?",
                             status=code) from exc

    @staticmethod
    def _error_message(response: httpx.Response) -> str:
        """OPNsense's own error text (device text: shortened, never trusted)."""
        try:
            answer = response.json()
        except ValueError:
            return ""
        if isinstance(answer, dict):
            if READ_ONLY_RE.search(str(answer.get("errorMessage") or answer.get("message") or "")):
                return "the key's user may not change the configuration ('System: Deny config write')"
            return untrusted_text(answer.get("errorMessage") or answer.get("message") or "", 160)
        return ""

    async def _optional(self, client: httpx.AsyncClient, method: str, path: str, *, what: str, privilege: str,
                        body: Any = None) -> tuple[Any, str | None]:
        """(answer, None), or (None, a note) when the key lacks the privilege - for reads the snapshot can do
        without."""
        try:
            return await self._call(client, method, path, what=what, body=body, privilege=privilege), None
        except ConnectorError as exc:
            if exc.status in (403, 404):
                return None, f"{what}: not readable - grant '{PRIVILEGES[privilege]}'"
            if exc.status is None or exc.status == 401 or isinstance(exc, TlsError):
                raise
            return None, f"{what}: not readable (OPNsense answered HTTP {exc.status})"

    # -- reading ---------------------------------------------------------------------------

    async def _version(self, client: httpx.AsyncClient) -> tuple[tuple[int, int, int] | None, str, str | None]:
        """(version, host name, note)."""
        info, note = await self._optional(client, "GET", "/diagnostics/system/system_information",
                                          what="read the version", privilege="version")
        if not isinstance(info, dict):
            return None, "", note
        versions = info.get("versions") if isinstance(info.get("versions"), list) else []
        product = next((v for v in versions if "opnsense" in str(v).lower()), versions[0] if versions else "")
        return parse_version(product), untrusted_text(info.get("name"), 120), None

    async def _rules(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        answer = await self._call(client, "POST", "/firewall/filter/search_rule", what="read the firewall rules",
                                  body={"current": 1, "rowCount": -1, "searchPhrase": ""}, privilege="rules")
        rows = _rows(answer, "read the firewall rules")
        total = answer.get("total") if isinstance(answer, dict) else None
        if isinstance(total, int) and total != len(rows):
            raise self.error(f"OPNsense listed {len(rows)} of {total} rules - refusing a partial read")
        return rows

    async def read(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Everything a snapshot needs, as OPNsense answered it (rows of untrusted device data)."""
        version, name, version_note = await self._version(client)
        interfaces = _rows(await self._call(client, "GET", "/interfaces/overview/interfaces_info",
                                            what="read the interfaces", privilege="interfaces"), "read the interfaces")
        rules = await self._rules(client)
        if version is None and not any(truthy(r.get("legacy")) for r in rules):
            raise self.error("Cannot tell the OPNsense version (grant 'Lobby: Dashboard') and the rule list has no "
                             "classic or automatic rules, so it may be incomplete - Atrium needs OPNsense 26.1 or later")
        if version is not None and version[:2] < MIN_VERSION:
            raise self.error(f"OPNsense {'.'.join(map(str, version))} is not supported: before 26.1 the API does not "
                             "return every rule (upgrade to 26.1 or later)")
        notes = [version_note] if version_note else []
        aliases, note = await self._optional(client, "POST", "/firewall/alias/search_item", what="aliases",
                                             privilege="aliases", body={"current": 1, "rowCount": -1})
        notes += [note] if note else []
        groups, note = await self._optional(client, "POST", "/firewall/group/search_item", what="interface groups",
                                            privilege="groups", body={"current": 1, "rowCount": -1})
        notes += [note] if note else []
        stats, note = await self._optional(client, "GET", "/firewall/filter_util/rule_stats", what="rule statistics",
                                           privilege="stats")
        notes += [note.replace("not readable", "hit counts unavailable")] if note else []
        return {"version": version, "name": name, "interfaces": interfaces, "rules": rules,
                "aliases": _rows(aliases, "aliases") if aliases is not None else [],
                "groups": _rows(groups, "interface groups") if groups is not None else [],
                "stats": (stats or {}).get("stats") if isinstance(stats, dict) and isinstance(stats.get("stats"), dict)
                else {}, "notes": notes, "read_at": self.clock()}

    def revision(self, raw: dict[str, Any]) -> str:
        interfaces = [{k: r.get(k) for k in ("identifier", "description", "enabled", "vlan_tag", "ipv4", "ipv6")}
                      for r in raw.get("interfaces") or []]
        return derived_revision([_stable(r, VOLATILE_RULE_KEYS) for r in raw.get("rules") or []],
                                [_stable(a, VOLATILE_ALIAS_KEYS) for a in raw.get("aliases") or []],
                                interfaces, [_stable(g, set()) for g in raw.get("groups") or []])

    def to_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        """The normalised device record (netmodel) for one read."""
        dev = Device(raw)
        version = raw.get("version")
        notes = list(raw.get("notes") or [])
        interfaces, self_addresses = [], []
        for row in dev.interfaces:
            ident = str(row["identifier"])
            found = dev.addresses(ident)
            self_addresses += [str(a.ip) for a in found]
            role = "wan" if ident == "wan" or row.get("gateways") else "lan" if ident == "lan" else "other"
            vlan = row.get("vlan_tag")
            interfaces.append({"id": ident, "name": row.get("description") or ident.upper(),
                               "description": row.get("device") or "",
                               "vlan": vlan if str(vlan or "").isdigit() and 1 <= int(vlan) <= 4094 else None,
                               "subnets": list(dict.fromkeys(str(a.network) for a in found)),
                               "addresses": [str(a.ip) for a in found], "role": role,
                               "enabled": truthy(row.get("enabled", True))})
        rules, seen = [], set()
        for order, row in enumerate(raw.get("rules") or [], start=1):
            rule = dev.rule(row, order, raw.get("stats") or {})
            if rule is None:
                continue
            while rule["id"] in seen:  # two automatic rules with one label
                rule["id"] = rule["vendor_ref"] = f"{rule['id']}#{order}"
            seen.add(rule["id"])
            rules.append(rule)
        if dev.groups:
            notes.append("rules on interface groups are read as rules on each member interface")
        if any(truthy(r.get("interfacenot")) for r in raw.get("rules") or []):
            notes.append("rules with inverted interfaces are read as floating rules")
        if not raw.get("stats"):
            notes.append("hit counts are not available")
        legacy = sum(1 for r in raw.get("rules") or [] if truthy(r.get("legacy")))
        if legacy:
            notes.append(f"{legacy} classic or automatic rule(s) are read only (OPNsense's API changes Rules [new] only)")
        return {
            "external_id": raw.get("name") or self.host, "revision": self.revision(raw), "read_at": raw.get("read_at"),
            "kind": "firewall",
            "device": {"vendor": "OPNsense", "model": "", "version": ".".join(map(str, version)) if version else "",
                       "hostname": raw.get("name") or "", "management_address": self.host, "serial": ""},
            "interfaces": interfaces, "zones": [],
            "aliases": [dev.alias(name) for name in dev.alias_rows],
            "self_addresses": list(dict.fromkeys(self_addresses)), "rules": rules,
            "default_policy": {"inbound": "block"}, "nat_evaluated": False, "notes": notes[:50],
        }

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"OPNsense cannot read {domain}")
        async with self.client() as client:
            return [self.to_record(await self.read(client))]

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
        verify = "verification is OFF - anyone on the path could read the API key" \
            if not self.config.get("verify_tls", True) else \
            f"certificate verified with {self.config['ca_file']}" if self.config.get("ca_file") else \
            "certificate verified with the system's trusted CAs"
        async with client:
            try:
                version, name, version_note = await self._version(client)
            except TlsError as exc:
                checks.append(check("reachability", True, f"{self.host}:{self.api_port} answers"))
                checks.append(check("tls", False, exc.message))
                return result(False, exc.message)
            except ConnectorError as exc:
                if exc.status is None:
                    checks.append(check("reachability", False, exc.message))
                    return result(False, exc.message)
                checks.append(check("reachability", True, f"{self.host}:{self.api_port} answers"))
                checks.append(check("tls", True, verify))
                checks.append(check("authentication", exc.status != 401, exc.message if exc.status == 401 else
                                    "the server answered, but not like OPNsense's API: " + exc.message))
                return result(False, exc.message)
            checks.append(check("reachability", True, f"{self.host}:{self.api_port} answers"))
            checks.append(check("tls", bool(self.config.get("verify_tls", True)), verify))
            checks.append(check("authentication", True, "API key accepted" + (f" by {name}" if name else "")))
            access = await self._probe_privileges(client)
            write = self._write_spec(version, access)
            readable = access["rules"] and access["interfaces"]
            checks.append(check("privileges", readable, self._privilege_detail(access, write)))
            supported = version is None or version[:2] >= MIN_VERSION
            vtext = ".".join(map(str, version)) if version else "unknown"
            checks.append(check("version", supported,
                                f"OPNsense {vtext} - " + ("supported" if version and supported else
                                                          "not supported: Atrium needs 26.1 or later (older versions "
                                                          "do not return every rule through the API)" if version else
                                                          version_note or "not readable")))
            checks.append(check("api_features", True, self._features(access)))
            record = None
            if readable and supported:
                try:
                    record = normalize_record(self.to_record(await self.read(client)))
                    checks.append(check("ruleset", True, f"{len(record['rules'])} rules, {len(record['interfaces'])} "
                                                         f"interfaces, {len(record['aliases'])} aliases read"
                                        + (f"; {len(record['errors'])} entries skipped" if record["errors"] else "")))
                except ConnectorError as exc:
                    checks.append(check("ruleset", False, exc.message))
            checks.append(check("management_guard", True,
                                f"protects rules carrying the hub's traffic from {self.config['hub_address']} to port "
                                f"{self.api_port}" if self.config.get("hub_address") else
                                "no hub address set: disabling any rule that lets traffic reach the firewall is "
                                "refused (set the hub address to narrow this)"))
        ok = readable and supported and record is not None
        what = f"OPNsense {vtext}" + (f" ({name})" if name else "")
        detail = (f"Connected to {what}: {len(record['rules'])} rules" if record else
                  f"{what}: " + next((c["detail"] for c in checks if not c["ok"]), "cannot read the rules"))
        return result(ok, detail + ("" if write else " (read only)") if ok else detail, write)

    async def _probe_privileges(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Which reads the key may do, whether it may write, and which rollback mechanism the firewall has - every
        probe without side effects."""
        out: dict[str, Any] = {}
        for name, method, path, body in (
                ("rules", "POST", "/firewall/filter/search_rule", {"current": 1, "rowCount": 1, "searchPhrase": ""}),
                ("interfaces", "GET", "/interfaces/overview/interfaces_info", None),
                ("aliases", "POST", "/firewall/alias/search_item", {"current": 1, "rowCount": 1}),
                ("groups", "POST", "/firewall/group/search_item", {"current": 1, "rowCount": 1}),
                ("stats", "GET", "/firewall/filter_util/rule_stats", None),
                ("backups", "GET", "/core/backup/backups/this", None)):
            try:
                await self._call(client, method, path, what=name, body=body, privilege=name)
                out[name] = True
            except ConnectorError as exc:
                out[name] = False
                if exc.status not in (403, 404):
                    out.setdefault("errors", []).append(exc.message)
        out["write"] = None  # unknown without the configuration history privilege
        try:
            if out["backups"]:
                response = await self._send(client, "GET", "/core/backup/revert_backup/atrium-probe",
                                            what="check write access")
                text = response.text[:500]
                if response.status_code == 200 and '"failed"' in text:
                    out["write"] = True
                elif READ_ONLY_RE.search(text):
                    out["write"] = False
            response = await self._send(client, "GET", "/firewall/filter/savepoint", what="look for savepoints")
            out["savepoint"] = response.status_code == 200
        except ConnectorError as exc:
            out["savepoint"] = False
            out.setdefault("errors", []).append(exc.message)
        return out

    def _write_spec(self, version: tuple[int, int, int] | None, access: dict[str, Any]) -> dict[str, Any] | None:
        if self.write_capability() is None or not (access.get("rules") and access.get("interfaces")):
            return None
        if version is None or version[:2] < MIN_VERSION or not access.get("backups") or access.get("write") is not True:
            return None
        if access.get("savepoint"):
            return {"ops": OPS, "rollback": "savepoint", "window_s": SAVEPOINT_WINDOW}
        return {"ops": OPS, "rollback": "backup_restore", "window_s": BACKUP_WINDOW}

    def _privilege_detail(self, access: dict[str, Any], write: dict[str, Any] | None) -> str:
        missing = [PRIVILEGES[k] for k in ("rules", "interfaces") if not access.get(k)]
        if missing:
            return "cannot read the ruleset - grant " + ", ".join(missing) + (
                "; " + "; ".join(access["errors"][:2]) if access.get("errors") else "")
        optional = [PRIVILEGES[k] for k in ("aliases", "groups", "stats", "backups") if not access.get(k)]
        parts = ["reads rules and interfaces"]
        if optional:
            parts.append("not granted (optional): " + ", ".join(optional))
        if access.get("write") is False:
            parts.append("read-only key ('System: Deny config write' is set) - recommended until device changes are "
                         "enabled; changes are unavailable")
        elif access.get("write") is None:
            parts.append("write access unknown (needs 'Diagnostics: Configuration History' to check) - changes are "
                         "unavailable")
        elif self.config.get("read_only"):
            parts.append("the key can write, but this connection is set to read only")
        else:
            parts.append(LEAST_PRIVILEGE_NOTE + "; 'Diagnostics: Configuration History' also lets it revert and "
                         "delete configuration backups")
        if write is None and access.get("write") is True and not self.config.get("read_only"):
            parts.append("changes are unavailable on this version")
        return "; ".join(parts)

    @staticmethod
    def _features(access: dict[str, Any]) -> str:
        parts = ["rules API returns Rules [new], classic and automatic rules"]
        parts.append("savepoints: a change reverts by itself after 60 s unless confirmed" if access.get("savepoint")
                     else "no savepoints (removed in 26.7): Atrium reverts a change with inverse operations or the "
                          "configuration backup it recorded")
        parts.append("hit counts: " + ("yes" if access.get("stats") else "no"))
        parts.append("configuration backups: " + ("yes" if access.get("backups") else "no"))
        return "; ".join(parts)

    # -- backups ---------------------------------------------------------------------------

    async def _latest_backup(self, client: httpx.AsyncClient) -> dict[str, Any]:
        answer = await self._call(client, "GET", "/core/backup/backups/this", what="list configuration backups",
                                  privilege="backups")
        items = answer.get("items") if isinstance(answer, dict) else None
        items = [i for i in items or [] if isinstance(i, dict) and BACKUP_ID_RE.match(str(i.get("id") or ""))]
        if not items:
            raise self.error("OPNsense listed no configuration history entries (System > Configuration > History)")
        return max(items, key=lambda i: float(str(i.get("time") or 0) or 0))

    async def _download(self, client: httpx.AsyncClient, backup_id: str) -> bytes:
        if not BACKUP_ID_RE.match(backup_id):
            raise self.error("Not an OPNsense configuration history id")
        response = await self._send(client, "GET", f"/core/backup/download/this/{quote(backup_id, safe='')}",
                                    what="download the configuration")
        if response.status_code == 403:
            raise self.error(f"OPNsense refused the configuration download (HTTP 403) - grant "
                             f"'{PRIVILEGES['backups']}'", status=403)
        if response.status_code >= 300:
            raise self.error(f"OPNsense could not download the configuration (HTTP {response.status_code})",
                             status=response.status_code)
        content = response.content
        if b"<opnsense" not in content[:4096]:
            raise self.error("OPNsense's configuration download is not a config.xml")
        return content

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            latest = await self._latest_backup(client)
            content = await self._download(client, str(latest["id"]))
        return {"content": content, "format": "xml", "device_backup_id": str(latest["id"]), "revision": None,
                "sha256": hashlib.sha256(content).hexdigest()}

    # -- changes ---------------------------------------------------------------------------

    def _guard(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
        hub = [self.config["hub_address"]] if self.config.get("hub_address") else None
        return management_guard(record, ops, hub_addresses=hub, management_ports=[self.api_port])

    @staticmethod
    def native_service(services: list[dict[str, Any]]) -> tuple[str, str]:
        """(protocol, destination_port) of the one rule the services fit in; ValueError when they need several."""
        protos = sorted({s["proto"] for s in services})
        ports = {s.get("ports") for s in services}
        if protos == ["icmp"] and len(services) == 1:
            return "ICMP", ""
        if len(ports) != 1 or len(services) != len(protos) or not set(protos) <= {"tcp", "udp"}:
            raise ValueError("an OPNsense rule carries one protocol (or TCP/UDP with the same port) - split the "
                             "services into separate changes")
        port = next(iter(ports)) or ""
        if "," in port:
            raise ValueError("an OPNsense rule carries one port or one range - split the ports into separate changes")
        return ("TCP/UDP" if len(protos) == 2 else protos[0].upper()), port

    def _check(self, ops: list[dict[str, Any]], raw: dict[str, Any], record: dict[str, Any]
               ) -> tuple[list[str], list[str], list[dict[str, Any]], list[str]]:
        """(guard problems, other problems, preview steps, notes) for `ops` against what the firewall holds now."""
        dev = Device(raw)
        problems, steps = [], []
        notes = ["Rules [new] interface rules are evaluated before classic rules; floating and group rules come "
                 "first"]
        by_uuid = writable_rows(raw.get("rules") or [])
        legacy_ids = {r["id"] for r in record.get("rules") or [] if r["id"].startswith("legacy:")}
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    row = dev.by_id.get(zone)
                    if row is None:
                        problems.append(f"operation {index + 1}: OPNsense has no interface '{display_id(zone)}'")
                    elif side == "source" and not truthy(row.get("enabled", True)):
                        problems.append(f"operation {index + 1}: interface {display_id(zone)} is disabled")
                    if len(op[side]["cidrs"]) != 1:
                        problems.append(f"operation {index + 1}: an OPNsense rule takes one {side} network - split "
                                        "the change or use one network per side")
                families = {ipaddress.ip_network(c).version for side in ("source", "destination")
                            for c in op[side]["cidrs"]}
                if len(families) > 1:
                    problems.append(f"operation {index + 1}: IPv4 and IPv6 networks cannot share one rule")
                if any(s["proto"] == "icmp" for s in op["services"]) and families == {6}:
                    problems.append(f"operation {index + 1}: ICMP rules are IPv4 only in this connector")
                try:
                    proto, port = self.native_service(op["services"])
                except ValueError as exc:
                    problems.append(f"operation {index + 1}: {exc}")
                    proto, port = "?", ""
                steps.append({"op": index, "kind": "add_rule",
                              "position": f"top of the {display_id(op['source']['zone'])} rules [new] (after floating "
                                          "and group rules)",
                              "detail": f"pass {proto}{' ' + port if port else ''} on {display_id(op['source']['zone'])}, "
                                        f"marked {op['marker']}"})
            else:
                verb = "disable" if op["op"] == "disable_rules" else "enable"
                for ref in op["rules"]:
                    uuid = ref["vendor_ref"] if UUID_RE.match(ref["vendor_ref"]) else ref["id"]
                    if ref["id"] in legacy_ids or ref["vendor_ref"] in legacy_ids or not UUID_RE.match(uuid):
                        problems.append(f"rule {display_id(ref['id'])} is a classic or automatic rule - OPNsense's API "
                                        "only changes Rules [new]")
                    elif uuid not in by_uuid:
                        problems.append(f"rule {display_id(ref['id'])} is not on the firewall (re-read it first)")
                    steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place",
                                  "detail": f"{verb} {display_id(uuid)}"})
        return self._guard(record, ops), problems, steps, notes

    async def _state(self, client: httpx.AsyncClient) -> tuple[dict[str, Any], dict[str, Any]]:
        raw = await self.read(client)
        return raw, normalize_record(self.to_record(raw))

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.client() as client:
            raw, record = await self._state(client)
            mode = "savepoint" if (await self._send(client, "GET", "/firewall/filter/savepoint",
                                                    what="look for savepoints")).status_code == 200 else "backup_restore"
        guard, problems, steps, notes = self._check(ops, raw, record)
        if self.write_capability() is None:
            problems.append("this connection is set to read only")
        if record["revision"] != snapshot.get("revision"):
            notes.append("the firewall changed since the snapshot: refresh before approving")
        notes.append("OPNsense reverts the change by itself unless Atrium confirms it within 60 s" if mode == "savepoint"
                     else "OPNsense 26.7+ has no automatic revert: Atrium reverts with inverse operations or the "
                          "configuration backup it records before writing")
        return {"steps": steps, "notes": notes, "problems": guard + problems}

    def _sequence(self, raw: dict[str, Any], iface: str) -> tuple[int | None, str | None]:
        """(sequence for a new rule at the top of `iface`'s Rules [new], or the uuid to move it before)."""
        mine = [r for r in writable_rows(raw.get("rules") or []).values()
                if _split(r.get("interface")) == [iface] and not truthy(r.get("interfacenot"))]
        sequences = [(int(str(r.get("sequence"))), str(r["uuid"])) for r in mine if str(r.get("sequence") or "").isdigit()]
        if not sequences:
            return None, None
        lowest, uuid = min(sequences)
        return (lowest - 1, None) if lowest > 1 else (None, uuid)

    @staticmethod
    def _saved(answer: Any, what: str, ok: tuple[str, ...]) -> None:
        result = str(answer.get("result") or answer.get("status") or "") if isinstance(answer, dict) else ""
        if result.lower() not in ok:
            fields = sorted((answer.get("validations") or {}).keys()) if isinstance(answer, dict) and \
                isinstance(answer.get("validations"), dict) else []
            raise ChangeError(f"OPNsense refused to {what}" + (f" (invalid: {', '.join(display_id(f) for f in fields[:5])})"
                                                              if fields else ""), code="invalid", state="unknown")

    def _token(self, info: dict[str, Any]) -> str:
        return json.dumps(info, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def _parse_token(token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and info.get("mode") in ("savepoint", "backup_restore")
            assert all(UUID_RE.match(u) for u in info.get("created") or [])
            assert all(UUID_RE.match(u) and s in ("0", "1") for u, s in (info.get("toggled") or {}).items())
            assert info["mode"] != "savepoint" or REVISION_RE.match(str(info.get("rev") or ""))
            assert info["mode"] != "backup_restore" or BACKUP_ID_RE.match(str(info.get("backup") or ""))
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this OPNsense connector", code="invalid", state="unknown") from exc
        return info

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This OPNsense connection is set to read only", code="unsupported", state="unchanged")
        try:
            client = self.client()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="invalid", state="unchanged") from exc
        async with client:
            try:
                raw, record = await self._state(client)
                savepoint = (await self._send(client, "GET", "/firewall/filter/savepoint",
                                              what="look for savepoints")).status_code == 200
                latest = None if savepoint else await self._latest_backup(client)
            except ConnectorError as exc:
                raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                  state="unchanged") from exc
            if record["revision"] != base_revision:
                raise ChangeError("The firewall's ruleset changed since the preview - re-read it and preview again",
                                  code="stale", state="unchanged")
            guard, problems, _, _ = self._check(ops, raw, record)
            if guard:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(guard), code="lockout",
                                  state="unchanged")
            if problems:
                raise ChangeError("; ".join(problems), code="invalid", state="unchanged")
            current = {uuid: "1" if truthy(r.get("enabled", "1")) else "0"
                       for uuid, r in writable_rows(raw["rules"]).items()}
            toggled = {}
            for op in ops:
                for ref in op.get("rules") or []:
                    uuid = ref["vendor_ref"] if UUID_RE.match(ref["vendor_ref"]) else ref["id"]
                    toggled.setdefault(uuid, current[uuid])
            info: dict[str, Any] = {"v": 1, "mode": "savepoint" if savepoint else "backup_restore", "created": [],
                                    "toggled": toggled}
            if len(self._token({**info, "created": ["0" * 36] * len(ops), "rev": "9" * 20, "deadline": 0.0,
                                "backup": "config-" + "9" * 20 + ".xml"})) > MAX_TOKEN:
                raise ChangeError("Too many rules in one change for OPNsense - split it", code="invalid",
                                  state="unchanged")
            if savepoint:
                answer = await self._write_call(client, "POST", "/firewall/filter/savepoint", "set a savepoint",
                                                state="unchanged")
                rev = str((answer or {}).get("revision") or "")
                if (answer or {}).get("status") != "ok" or not REVISION_RE.match(rev):
                    raise ChangeError("OPNsense did not set a savepoint - nothing was changed", code="failed",
                                      state="unchanged")
                info["rev"] = rev
            else:
                info["backup"] = str(latest["id"])
            created: list[dict[str, Any]] = []
            disabled, enabled = [], []
            try:
                for index, op in enumerate(ops):
                    if op["op"] == "allow":
                        uuid = await self._add_rule(client, raw, op)
                        info["created"].append(uuid)
                        created.append({"op": index, "id": uuid, "vendor_ref": uuid})
                    else:
                        want = "0" if op["op"] == "disable_rules" else "1"
                        for ref in op["rules"]:
                            uuid = ref["vendor_ref"] if UUID_RE.match(ref["vendor_ref"]) else ref["id"]
                            answer = await self._write_call(client, "POST", f"/firewall/filter/toggle_rule/{uuid}/{want}",
                                                            f"{'disable' if want == '0' else 'enable'} rule "
                                                            f"{display_id(uuid)}")
                            self._saved(answer, f"change rule {display_id(uuid)}", ("enabled", "disabled"))
                            (disabled if want == "0" else enabled).append(uuid)
            except ChangeError as exc:
                state = await self._undo_unapplied(client, info)
                raise ChangeError(exc.message + ("" if state == "unchanged" else
                                                 " - and undoing the saved part failed: check Firewall > Rules"),
                                  code=exc.code, state=state) from exc
            started = self.clock()
            path = f"/firewall/filter/apply/{info['rev']}" if savepoint else "/firewall/filter/apply"
            try:
                answer = await self._write_call(client, "POST", path, "apply the rules", state="unknown")
            except ChangeError as exc:
                raise ChangeError(exc.message + (" - the 60 s savepoint timer may revert it" if savepoint else ""),
                                  code=exc.code, state="unknown") from exc
            # UNVERIFIED: apply answers the configd output ("OK" on success); "error" is the source's failure answer
            if str((answer or {}).get("status") or "").strip().lower() == "error":
                state = await self._undo_unapplied(client, info)
                raise ChangeError("OPNsense did not apply the rules", code="failed", state=state)
            if savepoint:
                info["deadline"] = started + SAVEPOINT_WINDOW
        token = self._token(info)
        notes = [f"savepoint {info['rev']}: OPNsense reverts the rules by itself 60 s after apply unless confirmed"
                 if savepoint else f"no automatic revert on this version; configuration history entry {info['backup']} "
                                   "was recorded before writing"]
        return {"token": token, "rollback_until": info.get("deadline"), "revision": None, "created": created,
                "disabled": disabled, "enabled": enabled, "notes": notes}

    async def _write_call(self, client: httpx.AsyncClient, method: str, path: str, what: str, *,
                          state: str = "unknown") -> Any:
        try:
            return await self._call(client, method, path, what=what, privilege="rules")
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed", state=state,
                              status=exc.status) from exc

    async def _add_rule(self, client: httpx.AsyncClient, raw: dict[str, Any], op: dict[str, Any]) -> str:
        iface = op["source"]["zone"]
        proto, port = self.native_service(op["services"])
        family = ipaddress.ip_network(op["source"]["cidrs"][0]).version
        rule: dict[str, Any] = {
            "enabled": "1", "action": "pass", "quick": "1", "interface": iface, "direction": "in",
            "ipprotocol": "inet" if family == 4 else "inet6", "protocol": proto,
            "source_net": op["source"]["cidrs"][0], "source_not": "0",
            "destination_net": op["destination"]["cidrs"][0], "destination_not": "0", "destination_port": port,
            "log": "1" if op.get("log", True) else "0",
            "description": f"{op['marker']} {op.get('description') or ''}".strip()[:255],
        }
        sequence, before = self._sequence(raw, iface)
        if sequence is not None:
            rule["sequence"] = str(sequence)
        try:
            answer = await self._call(client, "POST", "/firewall/filter/add_rule", what="add the rule",
                                      body={"rule": rule}, privilege="rules")
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        self._saved(answer, "add the rule", ("saved",))
        uuid = str(answer.get("uuid") or "")
        if not UUID_RE.match(uuid):
            raise ChangeError("OPNsense saved the rule but did not answer with its uuid", code="failed", state="unknown")
        if before:
            answer = await self._write_call(client, "POST", f"/firewall/filter/move_rule_before/{uuid}/{before}",
                                            "move the rule to the top")
            if str((answer or {}).get("status") or "").lower() != "ok":
                raise ChangeError("OPNsense did not move the new rule to the top", code="failed", state="unknown")
        return uuid

    async def _undo_unapplied(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """Undo writes that were saved but not applied (pf still runs the old rules); the state afterwards."""
        try:
            if info.get("rev"):
                answer = await self._call(client, "POST", f"/firewall/filter/revert/{info['rev']}",
                                          what="revert to the savepoint", privilege="rules")
                return "unchanged" if (answer or {}).get("status") == "ok" else "unknown"
            await self._inverse(client, info)
            return "unchanged"
        except ConnectorError:
            return "unknown"

    async def _inverse(self, client: httpx.AsyncClient, info: dict[str, Any]) -> None:
        """Delete the rules the change created and put toggled rules back (saved, not yet applied)."""
        for uuid in info.get("created") or []:
            answer = await self._call(client, "POST", f"/firewall/filter/del_rule/{uuid}", what="delete the new rule",
                                      privilege="rules")
            self._saved(answer, f"delete rule {display_id(uuid)}", ("deleted", "not found"))
        for uuid, previous in (info.get("toggled") or {}).items():
            answer = await self._call(client, "POST", f"/firewall/filter/toggle_rule/{uuid}/{previous}",
                                      what="restore a rule", privilege="rules")
            self._saved(answer, f"restore rule {display_id(uuid)}", ("enabled", "disabled"))

    async def _change_state(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what the firewall's saved rules show of the change now."""
        rows = writable_rows(await self._rules(client))
        applied, reverted = [], []
        for uuid in info.get("created") or []:
            present = uuid in rows and truthy(rows[uuid].get("enabled", "1"))
            applied.append(present)
            reverted.append(not present)
        for uuid, previous in (info.get("toggled") or {}).items():
            now = "1" if truthy((rows.get(uuid) or {}).get("enabled", "1")) else "0"
            applied.append(now != previous)
            reverted.append(now == previous)
        if all(applied):
            return "applied"
        return "reverted" if all(reverted) else "partial"

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.client() as client:
                if info["mode"] == "savepoint":
                    now = self.clock()
                    if now >= float(info.get("deadline") or 0) - CONFIRM_MARGIN:
                        # too close to the firewall's own timer to cancel safely: let it finish, then say what it did
                        await self.sleep(max(0.0, min(float(info.get("deadline") or 0) + SETTLE - now, 30.0)))
                    else:
                        await self._call(client, "POST", f"/firewall/filter/cancelRollback/{info['rev']}",
                                         what="confirm the change", privilege="rules")
                state = await self._change_state(client, info)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        if state == "reverted":
            raise ChangeError("Too late to confirm: OPNsense already reverted the change", code="failed",
                              state="rolled_back")
        if state == "partial":
            raise ChangeError("The firewall holds only part of the change", code="failed", state="unknown")
        return {"confirmed": True, "revision": None,
                "notes": ["the savepoint timer was cancelled" if info["mode"] == "savepoint" else
                          "nothing to confirm on OPNsense 26.7+: the change was saved when it was applied"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        notes: list[str] = []
        try:
            async with self.client() as client:
                method = None
                if info["mode"] == "savepoint":
                    answer = await self._call(client, "POST", f"/firewall/filter/revert/{info['rev']}",
                                              what="revert to the savepoint", privilege="rules")
                    if (answer or {}).get("status") == "ok" and await self._change_state(client, info) == "reverted":
                        method = "savepoint"
                    else:
                        notes.append("the savepoint did not revert the change; undoing it rule by rule")
                if method is None:
                    try:
                        await self._inverse(client, info)
                        await self._call(client, "POST", "/firewall/filter/apply", what="apply the rules",
                                         privilege="rules")
                        if await self._change_state(client, info) == "reverted":
                            method = "inverse_ops"
                    except ConnectorError as exc:
                        if exc.status is None and not isinstance(exc, ChangeError):
                            raise  # unreachable: a backup restore cannot get through either
                        notes.append("undoing the change rule by rule failed")
                if method is None and info.get("backup"):
                    notes.append(f"restoring configuration history entry {info['backup']}")
                    answer = await self._call(client, "POST",
                                              f"/core/backup/revert_backup/{quote(info['backup'], safe='')}",
                                              what="restore the configuration", privilege="backups")
                    if str((answer or {}).get("status") or "") != "reverted":
                        raise ChangeError("OPNsense did not restore the configuration backup", code="failed",
                                          state="applied")
                    await self._call(client, "POST", "/firewall/filter/apply", what="apply the rules", privilege="rules")
                    method = "backup_restore"
        except ConnectorError as exc:
            raise ChangeError(exc.message + " - restore the configuration in System > Configuration > History (or "
                              "at the console) if the firewall is unreachable",
                              code="unreachable" if exc.status is None else "failed", state="unknown") from exc
        if method is None:
            raise ChangeError("The change is still on the firewall after undoing it", code="failed", state="applied")
        return {"rolled_back": True, "method": method, "notes": notes}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        backup_id = str(backup.device_backup_id or "")
        if not BACKUP_ID_RE.match(backup_id):
            raise ChangeError("OPNsense's API cannot upload a configuration: restore Atrium's copy in System > "
                              "Configuration > Backups", code="unsupported", state="unchanged")
        try:
            async with self.client() as client:
                content = await self._download(client, backup_id)
                if hashlib.sha256(content).hexdigest() != backup.sha256:
                    raise ChangeError("The firewall's copy of this configuration differs from Atrium's backup - "
                                      "restore it in System > Configuration > Backups", code="invalid",
                                      state="unchanged")
                answer = await self._call(client, "POST", f"/core/backup/revert_backup/{quote(backup_id, safe='')}",
                                          what="restore the configuration", privilege="backups")
                if str((answer or {}).get("status") or "") != "reverted":
                    raise ChangeError("OPNsense did not restore the configuration", code="failed", state="unchanged")
                await self._call(client, "POST", "/firewall/filter/apply", what="apply the rules", privilege="rules")
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        return {"restored": True, "revision": None,
                "notes": ["OPNsense restored the whole configuration file and Atrium reloaded the firewall rules; other "
                          "services apply the restored settings when they are next reloaded or after a reboot"]}
