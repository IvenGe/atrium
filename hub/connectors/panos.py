"""PAN-OS connector (Palo Alto Networks next-generation firewalls): reads one vsys's security rules, zones,
interfaces, address and service objects through the XML API into the network model (``netmodel.py``) and makes
guarded rule changes (one allow rule between two zones, disabling / re-enabling rules) for the hub's network change
path: candidate configuration, a partial commit of the API admin's own changes, and a configuration snapshot saved on
the firewall before writing.

Source: docs/research/fw-fortigate-panos-cisco.md sections 3, 5 and 6, re-checked October 2026. Labels: [V] official
documentation or Palo Alto-maintained code (pan-os-python), [K] pan.dev tutorial, [U] unverified.

- Authentication [V]: an API key (``type=keygen`` once, by the admin; Atrium stores only the key) in the
  ``X-PAN-KEY`` header; every request is a form-encoded POST to ``/api/`` (keys and xpaths never in URLs).
- Reading [V]: ``type=version``; ``type=config&action=show`` (the running configuration) of
  ``/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='<vsys>']`` + ``/rulebase/security/rules``,
  ``/zone``, ``/address``, ``/address-group`` (``static/member``, ``dynamic/filter``), ``/service``
  (``protocol/{tcp|udp|sctp}/port``), ``/service-group`` (``members/member``); interfaces under ``.../network/
  interface`` (layer3 ``ip`` entries, subinterface ``units`` with ``tag``). Shared objects under ``/config/shared``
  [U]. Rule hit counts with the ``rule-hit-count`` op [K] (optional). Interface management profiles (``.../network/
  profiles/interface-management-profile``: https, ssh, ... and ``permitted-ip``) [U] are shown as read-only rules
  "to this device" so the management-exposure checks see them; the dedicated MGT port is not.
- Revision: a hash of the configuration read (PAN-OS reports none through the API).
- Changes (rollback mode ``backup_restore``: PAN-OS has no commit-confirm or automatic revert [V/U FR 204]):
  1. preflight: ``<check><pending-changes/>`` [V]; uncommitted changes of the API admin itself are discarded with a
     partial revert [V]; changes of other administrators refuse the change (the snapshot would not match what runs);
     ``<show><config-locks/>`` / ``<show><commit-locks/>`` held by someone else refuse it (never force-removed) [V];
     a firewall connected to Panorama is refused (local edits conflict with pushed configuration) [U detection].
  2. ``<save><config><to>atrium-pre-<id>.xml</to></config></save>`` [V] - a snapshot on the firewall.
  3. candidate writes [V]: ``action=set`` of the rule (``from``/``to`` zones, the op's networks as literal members,
     ``application any``, service objects with exactly the op's ports - existing ones reused, else ``atrium-...``
     objects created), ``action=move`` ``where=before`` the first rule for the same zone pair, ``disabled yes|no``.
  4. ``<commit><partial><admin><member>API admin</member></admin></partial></commit>`` [V] and polling ``<show><jobs>``
     until ``status`` FIN, ``result`` OK [V pan-os-python]. A failure before or during the commit is undone with the
     partial revert (the running configuration is unchanged).
  5. rollback: inverse operations (delete the created rule and objects, toggle back) + partial commit; last resort
     ``<load><config><from>atrium-pre-<id>.xml</from></config></load>`` + a full commit (the load replaced the whole
     candidate, discarding other administrators' uncommitted edits).
- Backups: ``type=export&category=configuration`` [V category] - the running configuration [U]. Restore (an
  approved restore change only): ``type=import&category=configuration`` as a multipart ``file`` [V category, I form],
  ``load config from`` that file, full commit.

UNVERIFIED: the xpaths marked [U]; the ``show`` answer wrapping (``<result>`` holding the node); that a missing
``log-end`` means logging at session end (the PAN-OS default); predefined ``service-http`` = tcp 80,8080 and
``service-https`` = tcp 443; the ``pending-changes`` answer text ("yes"/"no"); the Panorama status text ("Connected
: yes"); the role xpath ``/config/mgt-config/users/entry/permissions/role-based``; that export returns the running
configuration; the import form; rule and object name rules (63 characters, letters, digits, space, '.', '_', '-').
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
import uuid
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, UnsafeXml, derived_revision, display_id,
                       management_guard, normalise_cidr, normalize_record, parse_ops, parse_ports, parse_untrusted_xml,
                       untrusted_text)

OPS = ["allow", "disable_rules", "enable_rules"]
MIN_VERSION = (10, 1, 0)  # partial revert of one admin's changes since 10.0 [V]; research covers 10.1+
WINDOW = 300  # backup_restore: how long the hub may take to verify before it rolls back
MAX_TOKEN = 4096
POLL = 2.0
VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
VSYS_RE = re.compile(r"^vsys\d{1,3}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9 _.-]{0,62}$")  # names that may go into an xpath literal
ADMIN_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,63}$")
SNAPSHOT_RE = re.compile(r"^atrium-pre-[A-Za-z0-9_-]{1,52}\.xml$")
CHANGE_ID_RE = re.compile(r"atrium:([A-Za-z0-9_-]{1,64})")
JOB_RE = re.compile(r"jobid\s+(\d+)", re.IGNORECASE)
WAN_ZONE_RE = re.compile(r"untrust|outside|internet|wan|external|isp", re.IGNORECASE)
MGMT_ZONE_RE = re.compile(r"mgmt|management", re.IGNORECASE)
LAN_ZONE_RE = re.compile(r"trust|inside|lan|internal|users", re.IGNORECASE)
DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
PREDEFINED = {"service-http": [("tcp", "80,8080")], "service-https": [("tcp", "443")]}  # UNVERIFIED predefined ports
# interface management profile services that open an administrative service on a dataplane interface
PROFILE_ACCESS = {"https": ("tcp", "443"), "http": ("tcp", "80"), "ssh": ("tcp", "22"), "telnet": ("tcp", "23"),
                  "snmp": ("udp", "161"), "ping": ("icmp", None)}
ACTIONS = {"allow": "pass", "deny": "block", "drop": "block", "reset-client": "reject", "reset-server": "reject",
           "reset-both": "reject"}
XML_CODES = {"1": "unknown command", "6": "bad xpath", "7": "object not present", "8": "object not unique",
             "10": "object referenced elsewhere", "12": "invalid object", "13": "object not found",
             "14": "operation not possible", "15": "operation denied (HA passive peer?)", "16": "the role lacks rights",
             "17": "invalid command", "18": "malformed command", "22": "session timed out", "400": "bad request",
             "403": "forbidden"}
# what the reads need in the admin role (Device > Admin Roles > XML API tab, or a read-only dynamic role)
HINTS = {"config": "XML API: Configuration", "op": "XML API: Operational Requests", "commit": "XML API: Commit",
         "export": "XML API: Export", "import": "XML API: Import"}


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """(11, 1, 4) from "11.1.4-h7" or "10.2.10"."""
    match = VERSION_RE.search(str(text or ""))
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def parse_xml(content: bytes, what: str = "answer") -> ET.Element:
    """An XML document from the firewall (untrusted): no DOCTYPE / entities anywhere (netmodel.parse_untrusted_xml)."""
    try:
        return parse_untrusted_xml(content)
    except UnsafeXml as exc:
        raise ConnectorError(f"The firewall's {what} declares a DOCTYPE or entities - refusing to parse it") from exc
    except ET.ParseError as exc:
        raise ConnectorError(f"The firewall's {what} is not XML ({exc.msg}) - is the URL the firewall's address?") from exc


def _members(node: ET.Element | None, tag: str) -> list[str]:
    if node is None:
        return []
    found = node.findall(f"{tag}/member")
    return [m.text.strip() for m in found if m.text and m.text.strip()]


def _text(node: ET.Element | None, tag: str) -> str:
    found = node.find(tag) if node is not None else None
    return (found.text or "").strip() if found is not None else ""


def _range_cidrs(value: str) -> list[str] | None:
    """"10.0.0.1-10.0.0.9" -> the networks it spans; None when it is not an address range."""
    low, sep, high = value.partition("-")
    if not sep:
        return None
    try:
        return [str(n) for n in ipaddress.summarize_address_range(ipaddress.ip_address(low.strip()),
                                                                  ipaddress.ip_address(high.strip()))]
    except (ValueError, TypeError):
        return None


class TlsError(ConnectorError):
    """The firewall answered, but its certificate is not trusted."""


class XmlApiError(ConnectorError):
    """The XML API answered status="error" (``code`` is PAN-OS's error code)."""

    def __init__(self, message: str, *, code: str = "", status: int | None = None):
        super().__init__(message, status=status)
        self.code = code


class CommitPending(ChangeError):
    """A commit job did not finish in time: it may still complete, so the state is unknown."""


# --------------------------------------------------------------------------------------
# what the firewall answered, as plain data (rows of untrusted device text)
# --------------------------------------------------------------------------------------


def parse_rules(node: ET.Element | None) -> list[dict[str, Any]]:
    out = []
    for entry in node.findall("entry") if node is not None else []:
        name = (entry.get("name") or "").strip()
        if not name:
            continue
        out.append({"name": name, "from": _members(entry, "from"), "to": _members(entry, "to"),
                    "source": _members(entry, "source"), "destination": _members(entry, "destination"),
                    "application": _members(entry, "application"), "service": _members(entry, "service"),
                    "action": _text(entry, "action").lower(), "disabled": _text(entry, "disabled") == "yes",
                    "negate_source": _text(entry, "negate-source") == "yes",
                    "negate_destination": _text(entry, "negate-destination") == "yes",
                    "log_end": _text(entry, "log-end") or None, "description": _text(entry, "description"),
                    "rule_type": _text(entry, "rule-type") or "universal"})
    return out


def parse_zones(node: ET.Element | None) -> list[dict[str, Any]]:
    out = []
    for entry in node.findall("entry") if node is not None else []:
        network = entry.find("network")
        interfaces: list[str] = []
        for mode in ("layer3", "layer2", "virtual-wire", "tap", "tunnel", "external"):
            interfaces += [m.text.strip() for m in (network.findall(f"{mode}/member") if network is not None else [])
                           if m.text and m.text.strip()]
        if entry.get("name"):
            out.append({"name": entry.get("name"), "interfaces": interfaces})
    return out


def parse_addresses(node: ET.Element | None) -> list[dict[str, Any]]:
    out = []
    for entry in node.findall("entry") if node is not None else []:
        kind = next((k for k in ("ip-netmask", "ip-range", "ip-wildcard", "fqdn") if entry.find(k) is not None), "other")
        if entry.get("name"):
            out.append({"name": entry.get("name"), "kind": kind, "value": _text(entry, kind) if kind != "other" else ""})
    return out


def parse_groups(node: ET.Element | None) -> list[dict[str, Any]]:
    return [{"name": e.get("name"), "static": _members(e, "static"),
             "dynamic": _text(e, "dynamic/filter") or (None if e.find("dynamic") is None else "dynamic")}
            for e in (node.findall("entry") if node is not None else []) if e.get("name")]


def parse_services(node: ET.Element | None) -> list[dict[str, Any]]:
    out = []
    for entry in node.findall("entry") if node is not None else []:
        protocol = entry.find("protocol")
        found = {p: _text(protocol, f"{p}/port") for p in ("tcp", "udp", "sctp")
                 if protocol is not None and protocol.find(p) is not None}
        if entry.get("name"):
            out.append({"name": entry.get("name"), "protocols": found})
    return out


def parse_service_groups(node: ET.Element | None) -> list[dict[str, Any]]:
    return [{"name": e.get("name"), "members": _members(e, "members")}
            for e in (node.findall("entry") if node is not None else []) if e.get("name")]


def parse_interfaces(node: ET.Element | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(entry: ET.Element, l3: ET.Element | None, kind: str, name: str | None = None) -> None:
        name = name or (entry.get("name") or "").strip()
        if not name:
            return
        out.append({"name": name, "kind": kind,
                    "ips": [e.get("name") for e in (l3.findall("ip/entry") if l3 is not None else []) if e.get("name")],
                    "tag": _text(entry, "tag"), "profile": _text(l3, "interface-management-profile"),
                    "dhcp": l3 is not None and l3.find("dhcp-client") is not None,
                    "comment": _text(entry, "comment")})

    if node is None:
        return out
    for kind in ("ethernet", "aggregate-ethernet"):
        for entry in node.findall(f"{kind}/entry"):
            l3 = entry.find("layer3")
            add(entry, l3, kind)
            for unit in l3.findall("units/entry") if l3 is not None else []:
                add(unit, unit, kind)
    for kind in ("vlan", "loopback", "tunnel"):
        holder = node.find(kind)
        if holder is None:
            continue
        if holder.find("ip") is not None:
            add(holder, holder, kind, name=kind)
        for unit in holder.findall("units/entry"):
            add(unit, unit, kind)
    return out


def parse_profiles(node: ET.Element | None) -> dict[str, dict[str, Any]]:
    out = {}
    for entry in node.findall("entry") if node is not None else []:
        if entry.get("name"):
            out[entry.get("name")] = {"access": sorted(k for k in PROFILE_ACCESS if _text(entry, k) == "yes"),
                                      "permitted": [e.get("name") for e in entry.findall("permitted-ip/entry")
                                                    if e.get("name")]}
    return out


class Device:
    """One read of the firewall and the lookups normalisation needs."""

    def __init__(self, raw: dict[str, Any], wan_zones: list[str] | None = None):
        self.raw = raw
        self.addresses = {a["name"]: a for a in raw.get("addresses") or []}
        self.groups = {g["name"]: g for g in raw.get("groups") or []}
        self.services_by_name = {s["name"]: s for s in raw.get("services") or []}
        self.service_groups = {g["name"]: g for g in raw.get("service_groups") or []}
        self.zones = {z["name"]: z["interfaces"] for z in raw.get("zones") or []}
        self.zone_of = {i: z for z, members in self.zones.items() for i in members}
        self.wan_zones = wan_zones
        self.notes: list[str] = []

    def alias(self, name: str, depth: int = 0) -> dict[str, Any]:
        out: dict[str, Any] = {"name": name, "kind": "network", "cidrs": [], "ports": None, "resolved": True}
        if depth > 8:
            return {**out, "kind": "other", "resolved": False}
        if name in self.groups:
            group = self.groups[name]
            if group["dynamic"] is not None:
                return {**out, "resolved": False}  # dynamic address groups are filled at run time
            for member in group["static"]:
                nested = self.alias(member, depth + 1)
                out["cidrs"] += nested["cidrs"]
                out["resolved"] = out["resolved"] and nested["resolved"]
            out["cidrs"] = list(dict.fromkeys(out["cidrs"]))[:2000]
            return out
        row = self.addresses.get(name)
        if row is None:
            return {**out, "kind": "other", "resolved": False}
        if row["kind"] == "ip-netmask":
            cidr = normalise_cidr(row["value"])
            out["cidrs"] = [cidr] if cidr else []
        elif row["kind"] == "ip-range":
            out["cidrs"] = _range_cidrs(row["value"]) or []
        else:  # fqdn, ip-wildcard: resolved by the firewall / not a list of networks
            return {**out, "kind": "other", "resolved": False}
        if not out["cidrs"]:
            out["resolved"] = False
        elif len(out["cidrs"]) == 1 and ipaddress.ip_network(out["cidrs"][0]).num_addresses == 1:
            out["kind"] = "host"
        return out

    def address_cidrs(self, value: str) -> list[str]:
        """An interface ip entry: a literal "10.0.0.1/24" or an ip-netmask address object."""
        cidr = value if normalise_cidr(value) else (self.addresses.get(value) or {}).get("value")
        try:
            found = ipaddress.ip_interface(str(cidr or ""))
        except ValueError:
            return []
        return [str(found)]

    def endpoint(self, members: list[str], negate: bool) -> dict[str, Any]:
        if not members or "any" in members:
            return {"any": True, "negate": negate}
        out: dict[str, Any] = {"cidrs": [], "aliases": [], "negate": negate}
        for member in members:
            if member in self.addresses or member in self.groups:
                out["aliases"].append(member)
            elif normalise_cidr(member):
                out["cidrs"].append(normalise_cidr(member))
            elif _range_cidrs(member):
                out["cidrs"] += _range_cidrs(member) or []
            else:  # an external dynamic list, a region, a tag-based object: the hub treats it as "anything"
                out["aliases"].append(member)
        return out

    def service(self, name: str, depth: int = 0) -> list[dict[str, Any]] | None:
        if name == "any":
            return None
        if depth > 8:
            return [{"proto": "any", "alias": name, "name": name}]
        if name in self.service_groups:
            entries: list[dict[str, Any]] = []
            for member in self.service_groups[name]["members"]:
                nested = self.service(member, depth + 1)
                if nested is None:
                    return None
                entries += nested
            return entries or [{"proto": "any", "alias": name, "name": name}]
        row = self.services_by_name.get(name)
        if row is None:
            if name in PREDEFINED:
                return [{"proto": p, "ports": ports, "name": name} for p, ports in PREDEFINED[name]]
            return [{"proto": "any", "alias": name, "name": name}]
        entries = []
        for proto, ports in row["protocols"].items():
            try:
                entries.append({"proto": proto, "ports": parse_ports(ports), "name": name})
            except ValueError:
                entries.append({"proto": proto, "alias": name, "name": name})
        return entries or [{"proto": "any", "alias": name, "name": name}]

    def exact_service(self, name: str) -> tuple[str, str | None] | None:
        """(proto, ports) when a configured service object holds exactly one protocol with exactly those ports."""
        if name not in self.services_by_name:
            return None
        found = self.service(name)
        if not found or len(found) != 1 or found[0].get("alias"):
            return None
        return found[0]["proto"], found[0].get("ports")

    def services(self, service: list[str], applications: list[str]) -> list[dict[str, Any]] | None:
        apps = [a for a in applications if a != "any"]
        app_text = ", ".join(apps)[:80]
        if not service or "any" in service or "application-default" in service:
            if not apps:
                return None  # any application on any (or its default) port
            alias = "application-default" if "application-default" in service else "app-id"
            return [{"proto": "any", "alias": alias, "name": app_text}]  # App-ID: ports not evaluated
        entries: list[dict[str, Any]] = []
        for name in service:
            found = self.service(name)
            if found is None:
                return None
            entries += found
        return entries

    def role(self, interface: str) -> str:
        zone = self.zone_of.get(interface, "")
        if self.wan_zones is not None:
            return "wan" if zone in self.wan_zones else "mgmt" if MGMT_ZONE_RE.search(zone) else \
                "lan" if zone and LAN_ZONE_RE.search(zone) else "other"
        if zone and WAN_ZONE_RE.search(zone):
            return "wan"
        if zone and MGMT_ZONE_RE.search(zone):
            return "mgmt"
        return "lan" if zone and LAN_ZONE_RE.search(zone) else "other"

    def rule(self, row: dict[str, Any], order: int, hits: dict[str, int]) -> dict[str, Any] | None:
        action = ACTIONS.get(row["action"])
        if action is None:
            return None
        log = row["log_end"] != "no"  # UNVERIFIED: logging at session end is the default when the element is absent
        return {
            "id": row["name"], "vendor_ref": row["name"], "order": order, "enabled": not row["disabled"],
            "action": action, "source_zones": [] if "any" in row["from"] else row["from"],
            "destination_zones": [] if "any" in row["to"] else row["to"], "direction": "in", "quick": True,
            "source": self.endpoint(row["source"], row["negate_source"]),
            "destination": self.endpoint(row["destination"], row["negate_destination"]),
            "services": self.services(row["service"], row["application"]), "log": log,
            "description": row["description"], "hits": hits.get(row["name"]),
        }

    def management_rules(self) -> list[dict[str, Any]]:
        profiles = self.raw.get("profiles") or {}
        rules = []
        for iface in self.raw.get("interfaces") or []:
            profile = profiles.get(iface.get("profile") or "")
            if not profile or not profile["access"]:
                continue
            permitted = [c for c in (normalise_cidr(p) for p in profile["permitted"]) if c]
            services = [{"proto": PROFILE_ACCESS[a][0], "ports": PROFILE_ACCESS[a][1], "name": a}
                        for a in profile["access"]]
            rules.append({"id": f"mgmt-profile:{iface['name']}", "vendor_ref": f"mgmt-profile:{iface['name']}",
                          "order": 0, "action": "pass", "interfaces": [iface["name"]],
                          "source": {"cidrs": permitted} if permitted else {"any": True},
                          "destination": {"self": True}, "services": services,
                          "description": "interface management profile"})
        if rules:
            self.notes.append("interface management profiles are shown as rules to this device; the dedicated "
                              "management port is not")
        return rules


class PanosConnector(Connector):
    kind = "panos"
    title = "PAN-OS (Palo Alto Networks)"
    description = ("Firewall (PAN-OS 10.1+ XML API): reads one vsys's security rules, zones, interfaces and objects "
                   "into the Network app; with device changes enabled, adds one allow rule or disables rules in the "
                   "candidate configuration and commits only the API admin's changes, under the change safety model.")
    fields = [
        ConnectorField(name="base_url", label="Firewall URL", kind="url", required=True,
                       placeholder="https://10.0.99.1",
                       help="The https address of the management interface (MGT port or a dataplane interface "
                            "with a management profile)."),
        ConnectorField(name="api_key", label="API key", kind="secret", required=True,
                       help="Generate it once for a dedicated admin account (type=keygen); generating a new key ends "
                            "that account's sessions. Use Superuser (readonly) or Device admin (readonly) until "
                            "device changes are enabled."),
        ConnectorField(name="api_admin", label="API admin account", placeholder="atrium-api",
                       help="The account the key belongs to. Needed for changes: Atrium commits and reverts only "
                            "this account's changes (partial commit)."),
        ConnectorField(name="vsys", label="Virtual system", default="vsys1", options=True),
        ConnectorField(name="wan_zones", label="Internet-facing zones", placeholder="untrust, outside",
                       help="Optional, comma separated. Empty: zones named like untrust, outside, internet, wan or "
                            "external are treated as internet-facing."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the key again."),
        ConnectorField(name="ca_file", label="CA certificate file", kind="text",
                       placeholder="/etc/atrium/panos-ca.pem",
                       help="PEM file on the hub's machine with the management certificate or its CA (PAN-OS uses a "
                            "self-signed certificate by default). Empty: the system's trusted CAs."),
        ConnectorField(name="hub_address", label="Hub address as the firewall sees it", kind="text",
                       placeholder="10.0.99.10",
                       help="Optional. The management-path guard then only protects rules that carry the hub's own "
                            "traffic; empty, it protects every rule that can reach the firewall."),
        ConnectorField(name="commit_timeout", label="Commit timeout (seconds)", kind="number", default=300,
                       help="How long Atrium waits for a commit job (30-1800)."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this firewall through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "backup_restore", "window_s": WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)
    sleep: Callable[[float], Any] = staticmethod(asyncio.sleep)

    @classmethod
    def detect(cls, tool) -> int:
        # the vendor name alone (Prisma, Cortex, ... share it) is only a weak hint
        return max(cls.name_score(tool, ("pan-os", "panos", "pa-vm", "pa-series")),
                   cls.name_score(tool, ("palo alto", "paloalto"), score=50))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        return super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.hostname:
            raise ConnectorError("The firewall URL must start with https:// (the API key travels in every request)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API key in its own field, not in the URL")
        try:
            parts.port
        except ValueError as exc:
            raise ConnectorError("The firewall URL has an invalid port") from exc
        config["base_url"] = re.sub(r"(?i)/(api|restapi)/?$", "", base)
        vsys = str(config.get("vsys") or "vsys1").strip()
        if not VSYS_RE.match(vsys):
            raise ConnectorError("Virtual system: vsys1, vsys2, ...")
        config["vsys"] = vsys
        admin = str(config.get("api_admin") or "").strip()
        if admin and not ADMIN_RE.match(admin):
            raise ConnectorError("API admin account: letters, digits, '_', '.', '@' or '-'")
        config["api_admin"] = admin or None
        zones = [z.strip() for z in str(config.get("wan_zones") or "").split(",") if z.strip()]
        if any(not SAFE_NAME.match(z) for z in zones):
            raise ConnectorError("Internet-facing zones: zone names separated by commas")
        config["wan_zones"] = ", ".join(zones) or None
        timeout = int(config.get("commit_timeout") or 300)
        if not 30 <= timeout <= 1800:
            raise ConnectorError("The commit timeout is 30-1800 seconds")
        config["commit_timeout"] = timeout
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
        if self.config.get("read_only") or not self.config.get("api_admin"):
            return None
        return super().write_capability()

    # -- HTTP ------------------------------------------------------------------------------

    @property
    def host(self) -> str:
        return urlsplit(str(self.config.get("base_url") or "")).hostname or ""

    @property
    def api_port(self) -> int:
        return urlsplit(str(self.config.get("base_url") or "")).port or 443

    @property
    def vsys(self) -> str:
        return str(self.config.get("vsys") or "vsys1")

    @property
    def base(self) -> str:
        return f"{DEVICE}/vsys/entry[@name='{self.vsys}']"

    @property
    def admin(self) -> str:
        return str(self.config.get("api_admin") or "")

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise TlsError(f"Cannot load the CA certificate file {ca_file}: "
                           f"{getattr(exc, 'strerror', None) or exc.__class__.__name__}") from exc
        if ca_file:
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        key = self.secrets.get("api_key")
        if not key:
            raise self.error("Enter the PAN-OS API key in the connection settings")
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        return self.http(str(self.config.get("base_url") or "").rstrip("/"), headers={"X-PAN-KEY": key},
                         verify=verify, timeout=60.0)

    async def _post(self, client: httpx.AsyncClient, data: dict[str, str], *, what: str,
                    files: dict[str, Any] | None = None) -> httpx.Response:
        try:
            return await client.post("/api/", data=data, files=files)
        except httpx.TimeoutException as exc:
            raise self.error(f"The firewall at {self.host}:{self.api_port} did not answer in time ({what})") from exc
        except httpx.ConnectError as exc:
            text = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text.lower():
                raise TlsError(self.redact("The firewall's TLS certificate is not trusted - set the CA certificate "
                                           "file (the management certificate or its CA)")) from exc
            raise self.error(f"Cannot reach the firewall at {self.host}:{self.api_port} "
                             f"({exc.__class__.__name__})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach the firewall: {exc.__class__.__name__}") from exc

    def _check_http(self, response: httpx.Response, what: str) -> None:
        code = response.status_code
        if code in (301, 302, 303, 307, 308):
            raise self.error("The firewall redirected the request - use the exact https:// management address",
                             status=code)
        if code == 403 or code == 401:
            raise XmlApiError("The firewall refused the API key (HTTP 403) - check the key (it ends when the "
                              "account's password changes or a new key is generated)", code="403", status=403)
        if code >= 400:
            raise self.error(f"The firewall could not {what} (HTTP {code})", status=code)

    async def _api(self, client: httpx.AsyncClient, data: dict[str, str], *, what: str, hint: str = "config",
                   files: dict[str, Any] | None = None) -> ET.Element:
        """The <response> of one XML API call (status success); XmlApiError otherwise."""
        response = await self._post(client, data, what=what, files=files)
        self._check_http(response, what)
        try:
            root = parse_xml(response.content, "answer")
        except ConnectorError as exc:  # an HTML login page, a proxy's error page, ...
            raise self.error(f"The firewall did not answer with an XML API response ({what}) - is the URL the "
                             "firewall's management address?", status=response.status_code) from exc
        if root.tag != "response":
            raise self.error(f"The firewall's answer ({what}) is not an XML API response - is the URL the firewall?",
                             status=response.status_code)
        if root.get("status") != "success":
            code = root.get("code") or ""
            if code == "403":
                raise XmlApiError("The firewall refused the API key (code 403) - check the key", code=code, status=403)
            if code == "16":
                raise XmlApiError(f"The firewall refused to {what}: the admin role lacks '{HINTS[hint]}'", code=code,
                                  status=403)
            meaning = XML_CODES.get(code, "error")
            raise XmlApiError(f"The firewall could not {what} (code {code or '?'}: {meaning})", code=code, status=400)
        return root

    async def _show(self, client: httpx.AsyncClient, xpath: str, tag: str, *, what: str) -> ET.Element | None:
        """The running configuration node at `xpath` (its element named `tag`), None when it does not exist."""
        try:
            root = await self._api(client, {"type": "config", "action": "show", "xpath": xpath}, what=what)
        except XmlApiError as exc:
            if exc.code in ("7", "13"):
                return None
            raise
        result = root.find("result")
        if result is None:
            return None
        return result.find(tag) if result.find(tag) is not None else (result if len(result) else None)

    async def _op(self, client: httpx.AsyncClient, cmd: str, *, what: str) -> ET.Element:
        return await self._api(client, {"type": "op", "cmd": cmd}, what=what, hint="op")

    # -- reading ---------------------------------------------------------------------------

    async def _version(self, client: httpx.AsyncClient) -> dict[str, Any]:
        root = await self._api(client, {"type": "version"}, what="read the version")
        result = root.find("result")
        return {"version": parse_version(_text(result, "sw-version")), "model": untrusted_text(_text(result, "model"), 80),
                "serial": untrusted_text(_text(result, "serial"), 80),
                "multi_vsys": _text(result, "multi-vsys") == "on"}

    async def read(self, client: httpx.AsyncClient, *, strict: bool = True) -> dict[str, Any]:
        """Everything a snapshot needs, as plain data. `strict` raises when the rules cannot be read."""
        info = await self._version(client)
        if strict and info["version"] is not None and info["version"] < MIN_VERSION:
            raise self.error(f"PAN-OS {'.'.join(map(str, info['version']))} is not supported: Atrium needs PAN-OS 10.1 "
                             "or later")
        raw: dict[str, Any] = {"info": info, "vsys": self.vsys, "notes": [], "access": {}, "errors": []}
        reads = (
            ("rules", f"{self.base}/rulebase/security/rules", "rules", parse_rules, True),
            ("zones", f"{self.base}/zone", "zone", parse_zones, True),
            ("interfaces", f"{DEVICE}/network/interface", "interface", parse_interfaces, False),
            ("addresses", f"{self.base}/address", "address", parse_addresses, False),
            ("groups", f"{self.base}/address-group", "address-group", parse_groups, False),
            ("services", f"{self.base}/service", "service", parse_services, False),
            ("service_groups", f"{self.base}/service-group", "service-group", parse_service_groups, False),
            ("shared_addresses", "/config/shared/address", "address", parse_addresses, False),
            ("shared_groups", "/config/shared/address-group", "address-group", parse_groups, False),
            ("shared_services", "/config/shared/service", "service", parse_services, False),
            ("shared_service_groups", "/config/shared/service-group", "service-group", parse_service_groups, False),
            ("profiles", f"{DEVICE}/network/profiles/interface-management-profile", "interface-management-profile",
             parse_profiles, False),
        )
        for key, xpath, tag, parser, required in reads:
            try:
                raw[key] = parser(await self._show(client, xpath, tag, what=f"read {key.replace('_', ' ')}"))
                raw["access"][key] = True
            except TlsError:
                raise
            except ConnectorError as exc:
                key_refused = isinstance(exc, XmlApiError) and exc.code == "403"
                if (strict and required) or exc.status is None or key_refused:
                    raise
                raw[key] = {} if key == "profiles" else []
                raw["access"][key] = False
                raw["notes"].append(f"{key.replace('_', ' ')}: not readable ({exc.message})")
        for key in ("addresses", "groups", "services", "service_groups"):  # vsys objects win over shared ones
            names = {r["name"] for r in raw[key]}
            raw[key] = raw[key] + [r for r in raw.pop(f"shared_{key}") if r["name"] not in names]
        raw["hits"] = await self._hits(client, raw)
        raw["read_at"] = self.clock()
        return raw

    async def _hits(self, client: httpx.AsyncClient, raw: dict[str, Any]) -> dict[str, int]:
        cmd = (f"<show><rule-hit-count><vsys><vsys-name><entry name='{self.vsys}'><rule-base><entry name='security'>"
               "<rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>")
        try:
            root = await self._op(client, cmd, what="read rule hit counts")
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None:
                raise
            raw["notes"].append("hit counts are not available")
            return {}
        out = {}
        for entry in root.iter("entry"):
            count = _text(entry, "hit-count")
            if entry.get("name") and count.isdigit():
                out[entry.get("name")] = int(count)
        return out

    def _wan_zones(self) -> list[str] | None:
        zones = [z.strip() for z in str(self.config.get("wan_zones") or "").split(",") if z.strip()]
        return zones or None

    def revision(self, raw: dict[str, Any]) -> str:
        return derived_revision(*[raw.get(k) for k in ("rules", "zones", "interfaces", "addresses", "groups",
                                                       "services", "service_groups", "profiles")])

    def to_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        dev = Device(raw, self._wan_zones())
        info = raw.get("info") or {}
        notes = list(raw.get("notes") or [])
        interfaces, self_addresses = [], []
        for row in raw.get("interfaces") or []:
            found = [ipaddress.ip_interface(c) for value in row["ips"] for c in dev.address_cidrs(value)]
            self_addresses += [str(a.ip) for a in found]
            tag = row.get("tag") or ""
            interfaces.append({"id": row["name"], "name": row["name"], "description": row.get("comment") or "",
                               "vlan": int(tag) if tag.isdigit() and 1 <= int(tag) <= 4094 else None,
                               "subnets": list(dict.fromkeys(str(a.network) for a in found)),
                               "addresses": [str(a.ip) for a in found], "role": dev.role(row["name"])})
        rules = dev.management_rules()
        skipped = 0
        for order, row in enumerate(raw.get("rules") or [], start=1):
            rule = dev.rule(row, order, raw.get("hits") or {})
            if rule is None:
                skipped += 1
                continue
            rules.append(rule)
        if skipped:
            notes.append(f"{skipped} rule(s) with an unknown action were skipped")
        if self._wan_zones() is None and any(i["role"] == "wan" for i in interfaces):
            notes.append("internet-facing interfaces were recognised by their zone names (set the internet-facing "
                         "zones to be exact)")
        notes.append("App-ID based rules are read with 'application-default' or 'app-id' services: ports not evaluated")
        notes.append("intrazone traffic is allowed and interzone traffic denied by PAN-OS's default rules (not listed)")
        if raw.get("panorama"):
            notes.append("this firewall is connected to Panorama: rules pushed from Panorama are not read")
        notes += dev.notes
        version = info.get("version")
        addresses = {r["name"] for r in raw.get("addresses") or []} | {g["name"] for g in raw.get("groups") or []}
        return {
            "external_id": info.get("serial") or self.host, "revision": self.revision(raw), "read_at": raw.get("read_at"),
            "kind": "firewall",
            "device": {"vendor": "Palo Alto Networks", "model": info.get("model") or "",
                       "version": ".".join(map(str, version)) if version else "", "hostname": "",
                       "management_address": self.host, "serial": info.get("serial") or ""},
            "interfaces": interfaces,
            "zones": [{"id": name, "name": name, "interfaces": members} for name, members in dev.zones.items()],
            "aliases": [dev.alias(name) for name in sorted(addresses)],
            "self_addresses": list(dict.fromkeys(self_addresses)), "rules": rules,
            "default_policy": {"forward": "block"}, "nat_evaluated": False, "notes": notes[:50],
        }

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"The PAN-OS connector cannot read {domain}")
        async with self.client() as client:
            raw = await self.read(client)
            raw["panorama"] = await self._panorama(client)
            return [self.to_record(raw)]

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name != "vsys":
            return await super().options(field_name)
        async with self.client() as client:
            node = await self._show(client, f"{DEVICE}/vsys", "vsys", what="list the virtual systems")
        names = [e.get("name") for e in (node.findall("entry") if node is not None else []) if e.get("name")]
        return [{"value": n, "label": n} for n in names if VSYS_RE.match(n)]

    # -- device state used by test() and the change path ----------------------------------

    async def _panorama(self, client: httpx.AsyncClient) -> bool | None:
        """True when the firewall reports a connected Panorama; None when it cannot tell (UNVERIFIED text)."""
        try:
            root = await self._op(client, "<show><panorama-status></panorama-status></show>", what="read Panorama status")
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None:
                raise
            return None
        text = " ".join("".join(root.itertext()).split()).lower()
        return bool(re.search(r"connected\s*:\s*yes", text))

    async def _pending(self, client: httpx.AsyncClient) -> bool:
        root = await self._op(client, "<check><pending-changes></pending-changes></check>", what="check pending changes")
        return (root.findtext("result") or "").strip().lower() == "yes"

    async def _locks(self, client: httpx.AsyncClient) -> list[str]:
        """Holders of config or commit locks other than the API admin (display-safe names)."""
        holders = []
        for kind in ("config-locks", "commit-locks"):
            root = await self._op(client, f"<show><{kind}></{kind}></show>", what=f"read {kind}")
            for entry in (root.find("result") if root.find("result") is not None else root).iter("entry"):
                name = entry.get("name") or ""
                if name != self.admin:
                    holders.append(display_id(name or "unknown", 40))
        return holders

    async def _role(self, client: httpx.AsyncClient) -> str | None:
        """The API admin's role (UNVERIFIED xpath): superuser, superreader, deviceadmin, devicereader, vsysadmin,
        vsysreader or custom:<profile>; None when it cannot be read."""
        if not self.admin:
            return None
        try:
            node = await self._show(client, f"/config/mgt-config/users/entry[@name='{self.admin}']/permissions/role-based",
                                    "role-based", what="read the admin role")
        except TlsError:
            raise
        except ConnectorError as exc:
            if exc.status is None:
                raise
            return None
        child = next(iter(node), None) if node is not None else None
        if child is None:
            return None
        if child.tag == "custom":
            return "custom:" + display_id(_text(child, "profile") or "?", 40)
        return child.tag

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
        where = f"{self.host}:{self.api_port}"
        state: dict[str, Any] = {}
        async with client:
            try:
                info = await self._version(client)
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
                message = exc.message if exc.status == 403 else \
                    "the server answered, but not like PAN-OS's XML API: " + exc.message
                checks.append(check("authentication", False, message))
                return result(False, message)
            checks.append(check("reachability", True, f"{where} answers"))
            checks.append(check("tls", bool(self.config.get("verify_tls", True)), verify))
            checks.append(check("authentication", True, "API key accepted"))
            version = info["version"]
            supported = version is not None and version >= MIN_VERSION
            try:
                raw = await self.read(client, strict=False) if supported else None
                if raw is not None:
                    state["panorama"] = raw["panorama"] = await self._panorama(client)
                    state["role"] = await self._role(client)
                    try:
                        state["pending"] = await self._pending(client)
                        state["locks"] = await self._locks(client)
                        state["op"] = True
                    except XmlApiError:
                        state["op"] = False
            except ConnectorError as exc:
                checks.append(check("privileges", False, exc.message))
                return result(False, exc.message)
        access = (raw or {}).get("access") or {}
        readable = bool(access.get("rules") and access.get("zones"))
        write = self._write_spec(raw, state) if raw and readable else None
        checks.append(check("privileges", readable, self._privilege_detail(raw, state, write)))
        vtext = ".".join(map(str, version)) if version else "unknown"
        checks.append(check("version", supported, f"PAN-OS {vtext} {display_id(info.get('model'), 40)} - " +
                            ("supported" if supported else "not supported: Atrium needs PAN-OS 10.1 or later")))
        checks.append(check("api_features", True, self._features(raw, state)))
        record = None
        if raw and readable:
            try:
                record = normalize_record(self.to_record(raw))
                checks.append(check("ruleset", True, f"{len(record['rules'])} rules, {len(record['zones'])} zones, "
                                                     f"{len(record['interfaces'])} interfaces, "
                                                     f"{len(record['aliases'])} address objects read"
                                    + (f"; {len(record['errors'])} entries skipped" if record["errors"] else "")))
            except (ConnectorError, ValueError) as exc:
                checks.append(check("ruleset", False, getattr(exc, "message", None) or str(exc)))
        checks.append(check("management_guard", True,
                            f"protects rules carrying the hub's traffic from {self.config['hub_address']} to port "
                            f"{self.api_port}" if self.config.get("hub_address") else
                            "no hub address set: disabling any rule that lets traffic reach the firewall is refused "
                            "(set the hub address to narrow this)"))
        ok = supported and readable and record is not None
        what = f"PAN-OS {vtext}"
        detail = (f"Connected to {what}: {len(record['rules'])} rules in {self.vsys}" if ok and record else
                  f"{what}: " + next((c["detail"] for c in checks if not c["ok"] and c["name"] != "tls"),
                                     "cannot read the rules"))
        return result(ok, detail + ("" if write else " (read only)") if ok else detail, write)

    def _write_problems(self, raw: dict[str, Any], state: dict[str, Any]) -> list[str]:
        problems = []
        version = (raw.get("info") or {}).get("version")
        if version is None or version < MIN_VERSION:
            problems.append("device changes need PAN-OS 10.1 or later")
        if not self.admin:
            problems.append("set the API admin account: Atrium commits and reverts only that account's changes")
        if state.get("panorama"):
            problems.append("the firewall is connected to Panorama: change its rules in Panorama (local edits "
                            "conflict with pushed configuration)")
        if state.get("op") is False:
            problems.append(f"the admin role lacks '{HINTS['op']}' (needed to check pending changes and locks)")
        if str(state.get("role") or "") in ("superreader", "devicereader", "vsysreader"):
            problems.append(f"the admin role is read-only ({state['role']})")
        return problems

    def _write_spec(self, raw: dict[str, Any], state: dict[str, Any]) -> dict[str, Any] | None:
        if self.write_capability() is None or self._write_problems(raw, state):
            return None
        return {"ops": OPS, "rollback": "backup_restore", "window_s": WINDOW}

    def _privilege_detail(self, raw: dict[str, Any] | None, state: dict[str, Any], write: dict[str, Any] | None) -> str:
        if raw is None:
            return "not checked (unsupported version)"
        access = raw.get("access") or {}
        if not (access.get("rules") and access.get("zones")):
            return (f"cannot read the security rules and zones - the admin role needs '{HINTS['config']}' (or a "
                    "read-only dynamic role)" + ("; " + "; ".join(raw["notes"][:2]) if raw.get("notes") else ""))
        parts = ["reads rules, zones and objects"]
        missing = [k.replace("_", " ") for k in ("interfaces", "addresses", "services", "profiles") if not access.get(k)]
        if missing:
            parts.append("not readable (optional): " + ", ".join(missing))
        role = state.get("role")
        if role:
            parts.append(f"role {role}")
        if role in ("superreader", "devicereader", "vsysreader"):
            parts.append("read-only role - recommended until device changes are enabled; changes are unavailable")
        elif role in ("superuser", "deviceadmin", "vsysadmin"):
            parts.append(LEAST_PRIVILEGE_NOTE if not self.config.get("read_only") else
                         "the key can write, but this connection is set to read only")
        elif role:
            parts.append("custom role: Atrium cannot tell whether it may commit (XML API: Configuration, Operational "
                         "Requests and Commit are needed for changes); a read-only role is recommended until device "
                         "changes are enabled")
        else:
            parts.append("the admin role could not be read (set the API admin account; superusers can read it) - "
                         "a read-only role is recommended until device changes are enabled")
        if state.get("op") is False:
            parts.append(f"no '{HINTS['op']}': hit counts, pending changes and locks cannot be checked")
        if write is None and self.write_capability() is not None:
            problems = self._write_problems(raw, state)
            if problems:
                parts.append("changes unavailable: " + "; ".join(problems))
        elif not self.admin:
            parts.append("changes unavailable: set the API admin account")
        return "; ".join(parts)

    def _features(self, raw: dict[str, Any] | None, state: dict[str, Any]) -> str:
        if raw is None:
            return "not checked"
        parts = ["candidate configuration with partial commits of the API admin's own changes",
                 "no commit-confirm: Atrium reverts with inverse operations, then the snapshot it saves on the "
                 "firewall before writing"]
        panorama = state.get("panorama")
        parts.append("Panorama: " + ("connected" if panorama else "not connected" if panorama is False else "unknown"))
        if state.get("op"):
            parts.append("uncommitted changes: " + ("yes" if state.get("pending") else "none"))
            if state.get("locks"):
                parts.append("locks held by: " + ", ".join(state["locks"][:5]))
        parts.append("hit counts: " + ("yes" if raw.get("hits") else "no"))
        return "; ".join(parts)

    # -- backups ---------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            response = await self._post(client, {"type": "export", "category": "configuration"},
                                        what="export the configuration")
        self._check_http(response, "export the configuration")
        content = response.content
        head = content[:4096].lstrip()
        if head.startswith(b"<response"):
            root = parse_xml(content, "export answer")
            code = root.get("code") or ""
            raise self.error(f"The firewall could not export the configuration (code {code or '?'}: "
                             f"{XML_CODES.get(code, 'error')}) - the admin role needs '{HINTS['export']}'",
                             status=403 if code in ("16", "403") else 400)
        if b"<config" not in head:
            raise self.error("The firewall's export is not a configuration file")
        parse_xml(content, "configuration export")  # well-formed, no entities
        return {"content": content, "format": "xml", "device_backup_id": None, "revision": None}

    # -- changes ---------------------------------------------------------------------------

    def _guard(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
        hub = [self.config["hub_address"]] if self.config.get("hub_address") else None
        return management_guard(record, ops, hub_addresses=hub, management_ports=[self.api_port])

    def _rule_xpath(self, name: str) -> str:
        if not SAFE_NAME.match(name):
            raise ChangeError("This rule name cannot be addressed safely", code="invalid", state="unchanged")
        return f"{self.base}/rulebase/security/rules/entry[@name='{name}']"

    @staticmethod
    def _anchor(raw: dict[str, Any], src: str, dst: str) -> str | None:
        for row in raw.get("rules") or []:
            if row["disabled"] or not SAFE_NAME.match(row["name"]):
                continue
            if (src in row["from"] or "any" in row["from"]) and (dst in row["to"] or "any" in row["to"]):
                return row["name"]
        return None

    @staticmethod
    def _service_name(proto: str, ports: str) -> str:
        name = f"atrium-{proto}-{ports.replace(',', '_')}"
        return name if len(name) <= 63 else f"atrium-{proto}-{hashlib.sha256(ports.encode()).hexdigest()[:12]}"

    def _plan(self, ops: list[dict[str, Any]], raw: dict[str, Any], record: dict[str, Any],
              state: dict[str, Any]) -> dict[str, Any]:
        dev = Device(raw, self._wan_zones())
        problems, steps, notes = list(self._write_problems(raw, state)), [], []
        rules = {r["name"]: r for r in raw.get("rules") or []}
        plan: dict[str, Any] = {"services": [], "rules": [], "moves": [], "toggles": {}, "created": []}
        made: dict[tuple[str, str], str] = {}
        for index, op in enumerate(ops):
            n = index + 1
            if op["op"] != "allow":
                want = "yes" if op["op"] == "disable_rules" else "no"
                verb = "disable" if want == "yes" else "enable"
                for ref in op["rules"]:
                    name = ref["vendor_ref"] if ref["vendor_ref"] in rules else ref["id"]
                    detail = f"{verb} rule {display_id(name)}"
                    if name.startswith("mgmt-profile:"):
                        problems.append(f"rule {display_id(ref['id'])} is an interface management profile - Atrium "
                                        "never changes interface settings")
                    elif name not in rules:
                        problems.append(f"rule {display_id(ref['id'])} is not on the firewall (re-read it first)")
                    elif not SAFE_NAME.match(name):
                        problems.append(f"rule {display_id(ref['id'])} has a name Atrium cannot address safely "
                                        "(quotes or other special characters) - change it on the firewall")
                    elif ("yes" if rules[name]["disabled"] else "no") == want:
                        detail += f" (already {verb}d - nothing to write)"
                    else:
                        plan["toggles"][name] = want
                    steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place", "detail": detail})
                continue
            change_id = CHANGE_ID_RE.fullmatch(op["marker"]).group(1)  # parse_ops checked the marker's form
            name = f"atrium-{change_id}"[:63]
            if name in rules or any(op["marker"] in r["description"] for r in rules.values()):
                problems.append(f"operation {n}: a rule for {op['marker']} is already on the firewall")
            for side in ("source", "destination"):
                if op[side]["zone"] not in dev.zones:
                    problems.append(f"operation {n}: {self.vsys} has no zone '{display_id(op[side]['zone'])}'")
            services = []
            for svc in op["services"]:
                if svc["proto"] == "icmp":
                    problems.append(f"operation {n}: ICMP needs an App-ID rule (application icmp/ping) - not supported "
                                    "by this connector; use TCP or UDP ports")
                    continue
                key = (svc["proto"], svc["ports"])
                existing = sorted((s for s in dev.services_by_name if dev.exact_service(s) == key and SAFE_NAME.match(s)),
                                  key=lambda s: (not s.startswith("atrium-"), s))
                if existing:
                    services.append(existing[0])
                    continue
                if key not in made:
                    made[key] = self._service_name(*key)
                    plan["services"].append({"name": made[key], "proto": svc["proto"], "ports": svc["ports"],
                                             "description": f"created by Atrium for {op['marker']}"})
                services.append(made[key])
            plan["rules"].append({"name": name, "from": op["source"]["zone"], "to": op["destination"]["zone"],
                                  "source": op["source"]["cidrs"], "destination": op["destination"]["cidrs"],
                                  "services": services, "log": op.get("log", True),
                                  "description": f"{op['marker']} {op.get('description') or ''}".strip()[:1023]})
            plan["created"].append({"op": index, "id": name, "vendor_ref": name})
            anchor = self._anchor(raw, op["source"]["zone"], op["destination"]["zone"])
            if anchor:
                plan["moves"].append((name, anchor))
            new = [s["name"] for s in plan["services"]]
            steps.append({"op": index, "kind": "add_rule",
                          "position": f"before rule {display_id(anchor)} (the first rule for "
                                      f"{display_id(op['source']['zone'])} -> {display_id(op['destination']['zone'])})"
                          if anchor else "at the end of the rulebase (before the default rules)",
                          "detail": f"rule '{name}' allowing {', '.join(display_id(s) for s in services)}"
                                    + (f"; new service objects: {', '.join(new)}" if new else "")})
        plan["problems"], plan["steps"], plan["notes"] = problems, steps, notes
        plan["guard"] = self._guard(record, ops)
        return plan

    async def _state(self, client: httpx.AsyncClient) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        raw = await self.read(client)
        state = {"panorama": await self._panorama(client), "op": True}
        raw["panorama"] = state["panorama"]
        return raw, normalize_record(self.to_record(raw)), state

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self.client() as client:
            raw, record, state = await self._state(client)
            try:
                pending, locks = await self._pending(client), await self._locks(client)
            except XmlApiError:
                pending, locks, state["op"] = None, [], False
        plan = self._plan(ops, raw, record, state)
        notes = plan["notes"] + ["PAN-OS validates the candidate configuration when Atrium commits it (a partial "
                                 "commit of the API admin's changes only)",
                                 "there is no automatic revert: Atrium reverts with inverse operations, then the "
                                 "snapshot it saves on the firewall before writing"]
        if pending:
            notes.append("the firewall has uncommitted changes: the API admin's own are discarded before writing; "
                         "other administrators' must be committed or reverted first")
        if locks:
            plan["problems"].append("configuration or commit locks are held by " + ", ".join(locks[:5]))
        if self.write_capability() is None:
            plan["problems"].append("this connection is read only (or the API admin account is not set)")
        if record["revision"] != snapshot.get("revision"):
            notes.append("the firewall changed since the snapshot: refresh before approving")
        return {"steps": plan["steps"], "notes": notes, "problems": plan["guard"] + plan["problems"]}

    @staticmethod
    def _token(info: dict[str, Any]) -> str:
        return json.dumps(info, separators=(",", ":"), sort_keys=True)

    def _parse_token(self, token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and info.get("vsys") == self.vsys
            assert info.get("admin") == self.admin and SNAPSHOT_RE.match(str(info.get("snapshot") or ""))
            assert all(isinstance(n, str) and SAFE_NAME.match(n) for n in [*(info.get("rules") or []),
                                                                            *(info.get("services") or [])])
            assert all(SAFE_NAME.match(n) and v in ("yes", "no") for n, v in (info.get("toggled") or {}).items())
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this PAN-OS connection", code="invalid", state="unknown") from exc
        return info

    def _rule_element(self, rule: dict[str, Any]) -> str:
        parts = []
        for tag, values in (("from", [rule["from"]]), ("to", [rule["to"]]), ("source", rule["source"]),
                            ("destination", rule["destination"]), ("source-user", ["any"]), ("category", ["any"]),
                            ("application", ["any"]), ("service", rule["services"])):
            node = ET.Element(tag)
            for value in values:
                ET.SubElement(node, "member").text = value
            parts.append(node)
        for tag, value in (("action", "allow"), ("log-end", "yes" if rule["log"] else "no"),
                           ("description", rule["description"])):
            node = ET.Element(tag)
            node.text = value
            parts.append(node)
        return "".join(ET.tostring(p, encoding="unicode") for p in parts)

    def _service_element(self, service: dict[str, Any]) -> str:
        protocol = ET.Element("protocol")
        ET.SubElement(ET.SubElement(protocol, service["proto"]), "port").text = service["ports"]
        description = ET.Element("description")
        description.text = service["description"]
        return ET.tostring(protocol, encoding="unicode") + ET.tostring(description, encoding="unicode")

    async def _write(self, client: httpx.AsyncClient, data: dict[str, str], what: str) -> None:
        await self._api(client, {"type": "config", **data}, what=what)

    async def _revert_own(self, client: httpx.AsyncClient) -> None:
        """Discard the API admin's uncommitted candidate changes (partial revert, PAN-OS 10.0+)."""
        cmd = ET.Element("revert")
        ET.SubElement(ET.SubElement(ET.SubElement(ET.SubElement(cmd, "config"), "partial"), "admin"),
                      "member").text = self.admin
        await self._op(client, ET.tostring(cmd, encoding="unicode"), what="discard the API admin's uncommitted changes")

    async def _commit(self, client: httpx.AsyncClient, *, partial: bool, what: str) -> str:
        """Commit and wait for the job: "ok", or "nothing" when there was nothing to commit; ChangeError (state
        unknown) when the job failed or did not finish in time."""
        cmd = ET.Element("commit")
        if partial:
            ET.SubElement(ET.SubElement(ET.SubElement(cmd, "partial"), "admin"), "member").text = self.admin
        data = {"type": "commit", "cmd": ET.tostring(cmd, encoding="unicode")}
        if partial:
            data["action"] = "partial"
        root = await self._api(client, data, what=what, hint="commit")
        job = (root.findtext("result/job") or "").strip()
        if not job.isdigit():
            text = " ".join("".join(root.itertext()).split())
            match = JOB_RE.search(text)
            if match is None:
                if "no changes to commit" in text.lower():
                    return "nothing"
                raise ChangeError(f"The firewall did not start a commit job ({what})", code="failed", state="unknown")
            job = match.group(1)
        deadline = self.clock() + int(self.config.get("commit_timeout") or 300)
        while True:
            answer = await self._op(client, f"<show><jobs><id>{job}</id></jobs></show>", what="poll the commit job")
            status = (answer.findtext("result/job/status") or "").strip().upper()
            outcome = (answer.findtext("result/job/result") or "").strip().upper()
            if status == "FIN":
                if outcome == "OK":
                    return "ok"
                raise ChangeError(f"The commit job {job} failed ({what})", code="failed", state="unknown")
            if self.clock() >= deadline:
                raise CommitPending(f"The commit job {job} did not finish in time ({what}) - it may still complete",
                                    code="failed", state="unknown")
            await self.sleep(POLL)

    async def _preflight(self, client: httpx.AsyncClient) -> list[str]:
        """Make the candidate match the running configuration (discarding only the API admin's own uncommitted
        changes); ChangeError (unchanged) when other administrators' changes or locks are in the way."""
        notes = []
        locks = await self._locks(client)
        if locks:
            raise ChangeError("Configuration or commit locks are held by another administrator - Atrium never removes "
                              "them; try again when they are released", code="failed", state="unchanged")
        if await self._pending(client):
            await self._revert_own(client)
            notes.append("uncommitted changes of the API admin were discarded before writing")
            if await self._pending(client):
                raise ChangeError("The firewall has uncommitted changes of other administrators - commit or revert "
                                  "them first (Atrium's snapshot must match the running configuration)",
                                  code="failed", state="unchanged")
        return notes

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This PAN-OS connection is read only (or the API admin account is not set)",
                              code="unsupported", state="unchanged")
        try:
            client = self.client()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="invalid", state="unchanged") from exc
        async with client:
            try:
                raw, record, state = await self._state(client)
            except ConnectorError as exc:
                raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                  state="unchanged") from exc
            if record["revision"] != base_revision:
                raise ChangeError("The firewall's rules changed since the preview - re-read it and preview again",
                                  code="stale", state="unchanged")
            plan = self._plan(ops, raw, record, state)
            if plan["guard"]:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(plan["guard"]), code="lockout",
                                  state="unchanged")
            if plan["problems"]:
                raise ChangeError("; ".join(plan["problems"]), code="invalid", state="unchanged")
            change_id = next((c["id"][len("atrium-"):] for c in plan["created"]), uuid.uuid4().hex[:12])
            info: dict[str, Any] = {
                "v": 1, "vsys": self.vsys, "admin": self.admin, "snapshot": f"atrium-pre-{change_id[:52]}.xml",
                "rules": [r["name"] for r in plan["rules"]], "services": [s["name"] for s in plan["services"]],
                "toggled": {n: "no" if want == "yes" else "yes" for n, want in plan["toggles"].items()}}
            if len(self._token(info)) > MAX_TOKEN:
                raise ChangeError("Too many rules in one change for PAN-OS - split it", code="invalid",
                                  state="unchanged")
            try:
                notes = await self._preflight(client)
                cmd = ET.Element("save")
                ET.SubElement(ET.SubElement(cmd, "config"), "to").text = info["snapshot"]
                await self._op(client, ET.tostring(cmd, encoding="unicode"), what="save a configuration snapshot")
            except ChangeError:
                raise
            except ConnectorError as exc:
                raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                  state="unchanged") from exc
            notes.append(f"snapshot {info['snapshot']} saved on the firewall before writing")
            try:
                for service in plan["services"]:
                    await self._write(client, {"action": "set", "xpath": f"{self.base}/service/entry[@name='"
                                                                         f"{service['name']}']",
                                               "element": self._service_element(service)}, "create a service object")
                for rule in plan["rules"]:
                    await self._write(client, {"action": "set", "xpath": self._rule_xpath(rule["name"]),
                                               "element": self._rule_element(rule)}, "add the rule")
                for name, anchor in plan["moves"]:
                    await self._write(client, {"action": "move", "xpath": self._rule_xpath(name), "where": "before",
                                               "dst": anchor}, "move the rule")
                for name, want in plan["toggles"].items():
                    await self._write(client, {"action": "set", "xpath": self._rule_xpath(name),
                                               "element": f"<disabled>{want}</disabled>"}, "change a rule")
                outcome = await self._commit(client, partial=True, what="apply the change") \
                    if plan["services"] or plan["rules"] or plan["toggles"] else "nothing"
            except CommitPending:
                raise  # the job may still complete: never claim the firewall is unchanged
            except ConnectorError as exc:
                state_after = await self._undo_candidate(client, info)
                code = exc.code if isinstance(exc, ChangeError) else "unreachable" if exc.status is None else "failed"
                raise ChangeError(exc.message + (" - the API admin's candidate changes were discarded"
                                                 if state_after == "unchanged" else ""), code=code,
                                  state=state_after) from exc
            if outcome == "nothing" and (plan["rules"] or plan["toggles"]):
                state_after = await self._undo_candidate(client, info)
                if state_after != "applied":
                    raise ChangeError("The firewall found nothing to commit", code="failed", state=state_after)
        disabled = [n for n, want in plan["toggles"].items() if want == "yes"]
        enabled = [n for n, want in plan["toggles"].items() if want == "no"]
        notes.append("no automatic revert on PAN-OS: Atrium rolls back with inverse operations")
        return {"token": self._token(info), "rollback_until": None, "revision": None, "created": plan["created"],
                "disabled": disabled, "enabled": enabled, "notes": notes}

    async def _undo_candidate(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """After a failed write or commit: discard the API admin's candidate changes, then say what runs."""
        try:
            await self._revert_own(client)
            state = await self._change_state(client, info)
        except ConnectorError:
            return "unknown"
        return {"reverted": "unchanged", "applied": "applied"}.get(state, "unknown")

    async def _change_state(self, client: httpx.AsyncClient, info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what the running configuration shows of the change."""
        rules = {r["name"]: r for r in parse_rules(await self._show(client, f"{self.base}/rulebase/security/rules",
                                                                    "rules", what="read the rules"))}
        applied, reverted = [], []
        for name in info.get("rules") or []:
            present = name in rules and not rules[name]["disabled"]
            applied.append(present)
            reverted.append(not present)
        for name, previous in (info.get("toggled") or {}).items():
            now = "yes" if (rules.get(name) or {}).get("disabled") else "no"
            applied.append(now != previous)
            reverted.append(now == previous)
        if all(applied):
            return "applied"
        return "reverted" if all(reverted) else "partial"

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.client() as client:
                state = await self._change_state(client, info)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        if state == "reverted":
            raise ChangeError("The change is no longer on the firewall", code="failed", state="rolled_back")
        if state == "partial":
            raise ChangeError("The firewall runs only part of the change", code="failed", state="unknown")
        return {"confirmed": True, "revision": None,
                "notes": ["nothing to confirm on PAN-OS: the commit made the change persistent",
                          f"the snapshot {info['snapshot']} stays on the firewall (Device > Setup > Operations)"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        notes: list[str] = []
        try:
            async with self.client() as client:
                if await self._change_state(client, info) == "reverted":
                    return {"rolled_back": True, "method": "inverse_ops",
                            "notes": ["the firewall no longer runs the change"]}
                method = None
                try:
                    await self._revert_own(client)
                    rules = {r["name"]: r for r in parse_rules(await self._show(
                        client, f"{self.base}/rulebase/security/rules", "rules", what="read the rules"))}
                    for name in info.get("rules") or []:
                        if name in rules:
                            await self._write(client, {"action": "delete", "xpath": self._rule_xpath(name)},
                                              "delete the rule")
                    for name, previous in (info.get("toggled") or {}).items():
                        if name in rules:
                            await self._write(client, {"action": "set", "xpath": self._rule_xpath(name),
                                                       "element": f"<disabled>{previous}</disabled>"}, "restore a rule")
                    for name in info.get("services") or []:
                        await self._write(client, {"action": "delete",
                                                   "xpath": f"{self.base}/service/entry[@name='{name}']"},
                                          "delete a service object")
                    await self._commit(client, partial=True, what="roll back the change")
                    if await self._change_state(client, info) == "reverted":
                        method = "inverse_ops"
                except ConnectorError as exc:
                    if exc.status is None and not isinstance(exc, ChangeError):
                        raise
                    notes.append("undoing the change rule by rule failed")
                if method is None:
                    notes.append(f"loading the snapshot {info['snapshot']} and committing it (other administrators' "
                                 "uncommitted edits were discarded)")
                    cmd = ET.Element("load")
                    ET.SubElement(ET.SubElement(cmd, "config"), "from").text = info["snapshot"]
                    await self._op(client, ET.tostring(cmd, encoding="unicode"), what="load the snapshot")
                    await self._commit(client, partial=False, what="commit the snapshot")
                    if await self._change_state(client, info) != "reverted":
                        raise ChangeError("The change is still on the firewall after loading the snapshot",
                                          code="failed", state="applied")
                    method = "backup_restore"
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        return {"rolled_back": True, "method": method, "notes": notes}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        head = backup.content[:4096].lstrip()
        if backup.format != "xml" or b"<config" not in head or head.startswith(b"<response"):
            raise ChangeError("This backup is not a PAN-OS configuration file", code="invalid", state="unchanged")
        name = f"atrium-restore-{re.sub(r'[^A-Za-z0-9_-]', '', backup.backup_id)[:40] or 'backup'}.xml"
        try:
            async with self.client() as client:
                try:
                    await self._preflight(client)
                    parse_xml(backup.content, "backup")
                    # UNVERIFIED: the multipart form of type=import&category=configuration (field "file")
                    await self._api(client, {"type": "import", "category": "configuration"}, what="upload the backup",
                                    hint="import", files={"file": (name, backup.content, "application/xml")})
                    cmd = ET.Element("load")
                    ET.SubElement(ET.SubElement(cmd, "config"), "from").text = name
                    await self._op(client, ET.tostring(cmd, encoding="unicode"), what="load the backup")
                except ChangeError:
                    raise
                except ConnectorError as exc:  # nothing was loaded (a failed load leaves the candidate as it was)
                    raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                                      state="unchanged") from exc
                try:
                    await self._commit(client, partial=False, what="commit the restored configuration")
                except ChangeError:
                    await self._discard_load(client)
                    raise
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if exc.status is None else "failed",
                              state="unknown") from exc
        return {"restored": True, "revision": None,
                "notes": [f"the backup was uploaded as {name}, loaded and committed (a full commit: the load "
                          "replaced the whole candidate configuration)"]}

    async def _discard_load(self, client: httpx.AsyncClient) -> None:
        """Put the candidate back to the running configuration after a failed restore (pan-os-python's
        revert_to_running_configuration)."""
        try:
            await self._op(client, "<load><config><from>running-config.xml</from></config></load>",
                           what="discard the loaded configuration")
        except ConnectorError:
            pass
