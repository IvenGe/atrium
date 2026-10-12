"""Cisco IOS-XE connector: RESTCONF reads of ACLs, VLANs, SVIs and interfaces.

Follows ``docs/research/fw-fortigate-panos-cisco.md`` section 4. Privilege 15 is required, and no read-only
RESTCONF role is documented. Writes would need NETCONF candidate plus a confirmed commit on a session that stays
open. IOS-XE support for ``<persist>`` (so a new connection could confirm) is unverified, and this process has no
tested NETCONF subsystem. Writes are therefore unavailable: ``network_write`` stays None even when the device
advertises candidate and confirmed-commit. ``frame_netconf`` / ``unframe_netconf`` implement RFC 6242 chunked
framing for a future client; nothing here sends them.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import LEAST_PRIVILEGE_NOTE, Backup, ChangeError, derived_revision, parse_ports

# RFC 6242 chunked framing. A chunk larger than this is rejected rather than buffered.
_MAX_CHUNK = 2_000_000
_USER = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")

VERSION_PATH = ("/restconf/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data"
                "/device-hardware/device-system-data")
INTERFACES_PATH = "/restconf/data/Cisco-IOS-XE-interfaces-oper:interfaces"
VLAN_PATH = "/restconf/data/Cisco-IOS-XE-native:native/vlan"
VLAN_OPER_PATH = "/restconf/data/Cisco-IOS-XE-vlan-oper:vlans"
ACL_PATH = "/restconf/data/Cisco-IOS-XE-native:native/ip/access-list"
HITS_PATH = "/restconf/data/Cisco-IOS-XE-acl-oper:access-lists"
# UNVERIFIED: the native interface tree (per-type lists) and the ip access-group leaves are not in the guides read.
NATIVE_IF_PATH = "/restconf/data/Cisco-IOS-XE-native:native/interface"
# UNVERIFIED: hostname is a common native leaf; the hardware-oper page lists software-version, not hostname.
HOSTNAME_PATH = "/restconf/data/Cisco-IOS-XE-native:native/hostname"
# UNVERIFIED: exposing ietf-netconf-monitoring capabilities through RESTCONF is not documented for IOS-XE.
CAPS_PATH = "/restconf/data/ietf-netconf-monitoring:netconf-state/capabilities"
CLI_RPC = "/restconf/operations/Cisco-IOS-XE-cli-rpc:get-modelled-config-clis"
# UNVERIFIED: the is-syncing output leaf names are taken from the YANG description, not a captured reply.
SYNC_RPC = "/restconf/operations/cisco-ia:is-syncing"

_WRITE_NOTE = (
    "Writes stay off. NETCONF confirmed commit reverts if its session drops, and IOS-XE support for <persist> "
    "is UNVERIFIED, so a later connection cannot confirm. This connector does not open a NETCONF session."
)


def frame_netconf(message: bytes | str, chunk_size: int = 4096) -> bytes:
    """RFC 6242 chunked framing: ``\\n#<size>\\n<data>`` chunks and an ``\\n##\\n`` end marker."""
    data = message.encode("utf-8") if isinstance(message, str) else bytes(message)
    if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size < 1 or chunk_size > _MAX_CHUNK:
        raise ValueError("NETCONF chunk size must be 1 to 2000000 octets")
    parts: list[bytes] = []
    for offset in range(0, len(data), chunk_size):
        piece = data[offset:offset + chunk_size]
        parts.append(b"\n#" + str(len(piece)).encode("ascii") + b"\n" + piece)
    parts.append(b"\n##\n")
    return b"".join(parts)


def unframe_netconf(data: bytes) -> bytes:
    """Decode one RFC 6242 chunked frame. Raises ValueError on a zero, oversized or truncated chunk."""
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("a NETCONF frame is bytes")
    raw = bytes(data)
    out = bytearray()
    index = 0
    while True:
        if not raw.startswith(b"\n#", index):
            raise ValueError("truncated or malformed NETCONF frame")
        if raw.startswith(b"\n##\n", index):
            return bytes(out)
        end = raw.find(b"\n", index + 2)
        if end < 0:
            raise ValueError("truncated NETCONF chunk size")
        token = raw[index + 2:end]
        if not token.isdigit():
            raise ValueError("NETCONF chunk size is not a decimal length")
        size = int(token)
        if size < 1 or size > _MAX_CHUNK or len(out) + size > _MAX_CHUNK:
            raise ValueError("NETCONF chunk size is outside 1 to 2000000 octets")
        start = end + 1
        if start + size > len(raw):
            raise ValueError("truncated NETCONF chunk")
        out.extend(raw[start:start + size])
        index = start + size


def _local(name: str) -> str:
    return str(name).rsplit(":", 1)[-1]


def _dicts_named(node: Any, name: str) -> list[dict[str, Any]]:
    """Dict values stored under a key with this local name. Matched values are not walked again."""
    found: list[dict[str, Any]] = []

    def walk(current: Any) -> None:
        if isinstance(current, dict):
            for key, value in current.items():
                if _local(key) == name:
                    items = value if isinstance(value, list) else [value]
                    found.extend(item for item in items if isinstance(item, dict))
                else:
                    walk(value)
        elif isinstance(current, list):
            for item in current:
                walk(item)

    walk(node)
    return found


def _child(node: Any, name: str) -> Any:
    """A direct child whose local name matches. Does not search deeper."""
    if isinstance(node, dict):
        for key, value in node.items():
            if _local(key) == name:
                return value
    return None


def _first(node: Any, name: str) -> Any:
    if isinstance(node, dict):
        for key, value in node.items():
            if _local(key) == name:
                return value
            found = _first(value, name)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _first(item, name)
            if found is not None:
                return found
    return None


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return ""


def _present(value: Any) -> bool:
    return value not in (None, False, "", [])


def _hostname_text(document: Any) -> str:
    if isinstance(document, str):
        return document.strip()
    if isinstance(document, dict) and len(document) == 1:
        value = next(iter(document.values()))
        if isinstance(value, str):
            return value.strip()
        found = _first(value, "hostname")
        if isinstance(found, str):
            return found.strip()
    found = _first(document, "hostname")
    return found.strip() if isinstance(found, str) else ""


def _wildcard_cidr(address: str, wildcard: str) -> str | None:
    try:
        addr = ipaddress.IPv4Address(address)
        wild = ipaddress.IPv4Address(wildcard)
    except ValueError:
        return None
    mask = (~int(wild)) & 0xFFFFFFFF
    if mask == 0:
        return None
    prefix = bin(mask).count("1")
    if mask != ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF):
        return None
    return str(ipaddress.IPv4Network((int(addr) & mask, prefix), strict=False))


def _subnet(address: str, mask: str) -> tuple[str | None, str | None]:
    try:
        ip = ipaddress.IPv4Address(address)
    except ValueError:
        return None, None
    if not mask:
        return f"{ip}/32", str(ip)
    try:
        network = ipaddress.IPv4Network((str(ip), mask), strict=False)
    except ValueError:
        return None, None
    return str(network), str(ip)


def _vlan_number(name: str) -> int | None:
    match = re.fullmatch(r"vlan(\d{1,4})", name.replace(" ", ""), flags=re.IGNORECASE)
    if not match:
        return None
    vlan = int(match.group(1))
    return vlan if 1 <= vlan <= 4094 else None


def _iface_id(kind: str, name: str) -> str:
    if name.lower().startswith(kind.lower()):
        return name
    return f"{kind}{name}"


def _acl_names(node: Any) -> list[str]:
    names: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if _local(key) in ("acl-name", "aclname") and isinstance(value, str) and value.strip():
                names.append(value.strip())
            else:
                names.extend(_acl_names(value))
    elif isinstance(node, list):
        for item in node:
            names.extend(_acl_names(item))
    return names


def _group_entries(node: Any) -> list[tuple[str, str]]:
    if isinstance(node, list):
        return [pair for item in node for pair in _group_entries(item)]
    if not isinstance(node, dict):
        return []
    pairs: list[tuple[str, str]] = []
    for key, value in node.items():
        local = _local(key)
        if local in ("in", "out"):
            pairs.extend((local, acl) for acl in _acl_names(value))
    if pairs:
        return pairs
    direction = "out" if isinstance(node.get("direction"), str) and "out" in node["direction"].lower() else "in"
    return [(direction, acl) for acl in _acl_names(node)]


def _access_groups(node: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []

    def walk(current: Any) -> None:
        if isinstance(current, dict):
            for key, value in current.items():
                if _local(key) == "access-group":
                    found.extend(_group_entries(value))
                else:
                    walk(value)
        elif isinstance(current, list):
            for item in current:
                walk(item)

    walk(node)
    return found


def _bindings(document: Any) -> dict[str, dict[str, list[str]]]:
    """ACL name -> inbound and outbound interface ids. The encoding is UNVERIFIED."""
    node = document
    if isinstance(document, dict) and len(document) == 1:
        only = next(iter(document.values()))
        if isinstance(only, dict):
            node = only
    found: dict[str, dict[str, list[str]]] = {}
    if not isinstance(node, dict):
        return found
    for type_name, entries in node.items():
        items = entries if isinstance(entries, list) else [entries] if isinstance(entries, dict) else []
        for entry in items:
            if not isinstance(entry, dict) or entry.get("name") in (None, ""):
                continue
            iface = _iface_id(_local(type_name), str(entry["name"]))
            for direction, acl in _access_groups(entry):
                slot = found.setdefault(acl, {"in": [], "out": []})
                if iface not in slot[direction]:
                    slot[direction].append(iface)
    return found


def _endpoint(ace: dict[str, Any], *, dest: bool) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    any_key = "dst-any" if dest else "any"
    host_keys = ("dst-host-address", "dst-host") if dest else ("host-address", "host")
    addr_key = "dest-ipv4-address" if dest else "ipv4-address"
    mask_key = "dest-mask" if dest else "mask"
    group_keys = ("dst-object-group",) if dest else ("object-group", "object-group-str")
    if _present(ace.get(any_key)):
        return {"any": True}, []
    for key in host_keys:
        host = _text(ace.get(key))
        if host:
            cidr = f"{host}/32" if "/" not in host else host
            try:
                return {"cidrs": [str(ipaddress.ip_network(cidr, strict=False))]}, []
            except ValueError:
                alias = f"ace-{host}"
                return {"aliases": [alias]}, [{"name": alias, "kind": "network", "resolved": False}]
    address, wildcard = _text(ace.get(addr_key)), _text(ace.get(mask_key))
    if address and wildcard:
        cidr = _wildcard_cidr(address, wildcard)
        if cidr:
            return {"cidrs": [cidr]}, []
        alias = f"ace-{address}-{wildcard}"
        return {"aliases": [alias]}, [{"name": alias, "kind": "network", "resolved": False}]
    if address and not wildcard:
        return {"cidrs": [f"{address}/32"]}, []
    for key in group_keys:
        group = _text(ace.get(key))
        if group:
            return {"aliases": [group]}, [{"name": group, "kind": "network", "resolved": False}]
    return {"any": True}, []


def _service(ace: dict[str, Any]) -> list[dict[str, Any]] | None:
    proto = _text(ace.get("protocol")).lower() or "any"
    if proto in ("ip", "any", "ipv4"):
        return None
    ports = None
    if proto in ("tcp", "udp"):
        if ace.get("dst-range1") not in (None, "") and ace.get("dst-range2") not in (None, ""):
            ports = f"{ace.get('dst-range1')}-{ace.get('dst-range2')}"
        elif ace.get("dst-range") not in (None, ""):
            ports = ace.get("dst-range")
        elif ace.get("dst-eq") not in (None, ""):
            ports = ace.get("dst-eq")
        try:
            ports = parse_ports(ports)
        except ValueError:
            return [{"proto": proto, "alias": "unparsed-ports", "name": ""}]
    mapped = {"6": "tcp", "17": "udp", "1": "icmp"}.get(proto, proto)
    if mapped == "icmp":
        return [{"proto": "icmp"}]
    return [{"proto": mapped, "ports": ports}]


def _capability_flags(document: Any) -> set[str]:
    flags: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, str):
            if "capability:candidate" in node:
                flags.add("candidate")
            if "confirmed-commit" in node:
                flags.add("confirmed-commit")
        elif isinstance(node, dict):
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(document)
    return flags


class CiscoIosXeConnector(Connector):
    kind = "cisco_iosxe"
    title = "Cisco IOS-XE"
    description = ("RESTCONF reads of extended ACLs, VLANs, SVIs and interfaces. "
                   "Privilege 15 is required. Rule changes are not offered: a safe write needs a NETCONF "
                   "confirmed commit, and that path is not available from a fresh connection.")
    fields = [
        ConnectorField(name="base_url", label="Device URL", kind="url", required=True,
                       placeholder="https://switch.example",
                       help="HTTPS RESTCONF address. The password is sent only here, as HTTP Basic."),
        ConnectorField(name="username", label="Username", required=True,
                       help="A dedicated privilege-15 account. IOS-XE has no documented read-only RESTCONF role."),
        ConnectorField(name="password", label="Password", kind="secret", required=True),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="IOS-XE presents a self-signed certificate unless a trustpoint is configured. "
                            "Pin it with the CA file field."),
        ConnectorField(name="ca_file", label="CA certificate file", placeholder="/etc/atrium/iosxe-ca.pem"),
    ]
    capabilities = {"network": {"read"}}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("ios-xe", "ios xe", "iosxe", "catalyst", "cisco ios"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        local = parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
        if not (parts.scheme == "https" or local) or not parts.hostname:
            raise ConnectorError("The device URL must start with https:// (the password must not travel in clear text)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the username and password in their own fields, not in the URL")
        username = str(config.get("username") or "").strip()
        if not _USER.fullmatch(username):
            raise ConnectorError("The username is 1-64 letters, digits, '.', '_', '@' and '-'")
        ca = str(config.get("ca_file") or "").strip()
        if ca and not ca.startswith("/"):
            raise ConnectorError("The CA certificate file must be an absolute path")
        return {**config, "base_url": base, "username": username, "ca_file": ca}

    def write_capability(self) -> dict[str, Any] | None:
        return None

    def _verify(self) -> bool | str:
        ca = str(self.config.get("ca_file") or "").strip()
        return ca or bool(self.config.get("verify_tls", True))

    def client(self):
        username = str(self.config.get("username") or "")
        password = self.secrets.get("password")
        if not username or not password:
            raise self.error("Enter the IOS-XE username and password in the connection settings")
        return self.http(str(self.config.get("base_url") or "").rstrip("/"),
                         headers={"Accept": "application/yang-data+json",
                                  "Content-Type": "application/yang-data+json"},
                         auth=httpx.BasicAuth(username, password), verify=self._verify())

    def _change(self, message: str, *, code: str = "failed", state: str = "unknown",
                status: int | None = None, excerpt: str | None = None) -> ChangeError:
        err = self.error(message, status=status, excerpt=excerpt)
        return ChangeError(err.message, code=code, state=state, status=err.status, excerpt=err.excerpt)

    async def _request(self, client, method: str, path: str, *, what: str, optional: bool = False,
                       body: dict[str, Any] | None = None) -> Any:
        try:
            response = await client.request(method, path, json=body)
        except httpx.TimeoutException as exc:
            raise self.error(f"{self.title} did not answer in time ({what})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach {self.title}: {exc.__class__.__name__}") from exc
        if optional and response.status_code == 404:
            return None
        if response.status_code == 401:
            raise self.error(f"{self.title} rejected the credentials (HTTP 401): {response.text[:300]}",
                             status=401, excerpt=response.text)
        self.raise_for_status(response, what)
        if response.status_code == 204 or not response.content:
            return None
        try:
            data = response.json()
        except ValueError as exc:
            raise self.error(f"{self.title} did not answer with JSON ({what})", status=response.status_code,
                             excerpt=response.text) from exc
        self._restconf_errors(data, what, response.status_code)
        return data

    def _restconf_errors(self, data: Any, what: str, status: int) -> None:
        """A RESTCONF error document is a failure even when HTTP is 200."""
        if not isinstance(data, dict):
            return
        errors = None
        for key, value in data.items():
            if _local(key) == "errors":
                errors = value
                break
        if not isinstance(errors, dict):
            return
        items = errors.get("error")
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list) or not items:
            return
        messages = []
        for item in items:
            if isinstance(item, dict):
                text = _text(item.get("error-message") or item.get("error-tag"))
                if text:
                    messages.append(text)
        detail = "; ".join(messages)[:300]
        raise self.error(f"{self.title} reported a RESTCONF error ({what})" + (f": {detail}" if detail else ""),
                         status=status, excerpt=json.dumps(data, default=str)[:500])

    async def _read(self, client) -> dict[str, Any]:
        version_doc = await self._request(client, "GET", VERSION_PATH, what="reading the software version")
        interfaces_doc = await self._request(client, "GET", INTERFACES_PATH, what="reading interfaces", optional=True)
        vlan_doc = await self._request(client, "GET", VLAN_PATH, what="reading VLANs", optional=True)
        vlan_oper = await self._request(client, "GET", VLAN_OPER_PATH, what="reading VLAN state", optional=True)
        acl_doc = await self._request(client, "GET", ACL_PATH, what="reading access lists", optional=True)
        hits_doc = await self._request(client, "GET", HITS_PATH, what="reading ACL counters", optional=True)
        native_if = await self._request(client, "GET", NATIVE_IF_PATH, what="reading interface configuration",
                                        optional=True)
        hostname_doc = await self._request(client, "GET", HOSTNAME_PATH, what="reading the hostname", optional=True)
        syncing = await self._syncing(client)
        return self._record(version_doc, interfaces_doc, vlan_doc, vlan_oper, acl_doc, hits_doc, native_if,
                            hostname_doc, syncing)

    async def _syncing(self, client) -> bool:
        try:
            data = await self._request(client, "POST", SYNC_RPC, what="checking whether the model is syncing",
                                       optional=True, body={"cisco-ia:input": {}})
        except ConnectorError:
            return False
        flag = _first(data, "syncing") if data else None
        return flag is True or (isinstance(flag, str) and flag.lower() == "true")

    def _record(self, version_doc, interfaces_doc, vlan_doc, vlan_oper, acl_doc, hits_doc, native_if,
                hostname_doc, syncing: bool) -> dict[str, Any]:
        version = _text(_first(version_doc, "software-version"))
        hostname = _hostname_text(hostname_doc) or urlsplit(str(self.config.get("base_url") or "")).hostname or ""
        interfaces, self_addresses, mgmt = self._interfaces(interfaces_doc)
        zones = self._zones(vlan_doc, vlan_oper, interfaces)
        bindings = _bindings(native_if)
        rules, aliases, notes = self._rules(acl_doc, hits_doc, bindings)
        if acl_doc and not bindings:
            notes.append("No interface ACL binding was found. The access-group encoding is UNVERIFIED.")
        if syncing:
            notes.append("The device reported that its model data is still syncing.")
        notes.append("Extended ACLs end with an implicit deny that is not listed as a rule.")
        notes.append(_WRITE_NOTE)
        kind = "switch" if zones else "router"
        revision = derived_revision(
            [{"id": rule["id"], "action": rule["action"], "source": rule["source"],
              "destination": rule["destination"], "services": rule["services"],
              "interfaces": rule["interfaces"], "out": rule["out_interfaces"]} for rule in rules],
            [{"id": item["id"], "subnets": item["subnets"], "addresses": item["addresses"], "vlan": item["vlan"]}
             for item in interfaces],
            [{"id": zone["id"], "interfaces": zone["interfaces"]} for zone in zones],
        )
        external = hostname or "ios-xe"
        return {"external_id": external, "revision": revision, "read_at": time.time(), "kind": kind,
                "device": {"vendor": "Cisco", "model": "", "version": version, "hostname": hostname,
                           "management_address": mgmt, "serial": ""},
                "interfaces": interfaces, "zones": zones, "aliases": aliases, "self_addresses": self_addresses,
                "rules": rules, "default_policy": {"inbound": "block"} if rules else {},
                "nat_evaluated": False, "notes": notes, "_version": version}

    def _interfaces(self, document: Any) -> tuple[list[dict[str, Any]], list[str], str]:
        interfaces = []
        addresses: list[str] = []
        mgmt = ""
        for row in _dicts_named(document, "interface"):
            name = _text(row.get("name"))
            if not name:
                continue
            ip_value = row.get("ipv4")
            mask = _text(row.get("ipv4-subnet-mask"))
            # UNVERIFIED: some releases return ipv4 as an object rather than the string leaf in the oper model.
            if isinstance(ip_value, dict):
                mask = mask or _text(ip_value.get("mask") or ip_value.get("ipv4-subnet-mask"))
                ip_value = ip_value.get("address") or ip_value.get("ip") or ip_value.get("ipv4")
            subnet, address = _subnet(_text(ip_value), mask) if _text(ip_value) else (None, None)
            description = row.get("description") if isinstance(row.get("description"), str) else ""
            role = "other"
            blob = f"{name} {description}".lower()
            if "mgmt" in blob or "management" in blob:
                role = "mgmt"
            elif name.lower().startswith("vlan"):
                role = "lan"
            admin = _text(row.get("admin-status")).lower()
            item = {"id": name, "name": name, "description": description, "vlan": _vlan_number(name),
                    "subnets": [subnet] if subnet else [], "addresses": [address] if address else [],
                    "role": role, "enabled": "down" not in admin}
            interfaces.append(item)
            if address and address not in addresses:
                addresses.append(address)
            if role == "mgmt" and address and not mgmt:
                mgmt = address
        return interfaces, addresses, mgmt

    def _zones(self, config_doc: Any, oper_doc: Any, interfaces: list[dict[str, Any]]) -> list[dict[str, Any]]:
        by_id: dict[str, dict[str, Any]] = {}
        for row in _dicts_named(config_doc, "vlan-list"):
            vlan = row.get("id")
            try:
                number = int(vlan)
            except (TypeError, ValueError):
                continue
            if not 1 <= number <= 4094:
                continue
            by_id[str(number)] = {"id": f"vlan{number}", "name": _text(row.get("name")) or f"VLAN {number}",
                                  "description": "", "interfaces": []}
        for row in _dicts_named(oper_doc, "vlan"):
            try:
                number = int(row.get("id"))
            except (TypeError, ValueError):
                continue
            zone = by_id.setdefault(str(number), {"id": f"vlan{number}", "name": _text(row.get("name")) or f"VLAN {number}",
                                                  "description": "", "interfaces": []})
            if not zone["name"] or zone["name"] == f"VLAN {number}":
                zone["name"] = _text(row.get("name")) or zone["name"]
            members: list[str] = []
            ports = row.get("ports") or []
            if isinstance(ports, dict):
                ports = [ports]
            for port in ports if isinstance(ports, list) else []:
                if isinstance(port, str) and port:
                    members.append(port)
                elif isinstance(port, dict):
                    member = port.get("interface")
                    if isinstance(member, str) and member:
                        members.append(member)
            vlan_ifs = row.get("vlan-interfaces") or []
            if isinstance(vlan_ifs, str):
                vlan_ifs = [vlan_ifs]
            if isinstance(vlan_ifs, list):
                members.extend(str(item) for item in vlan_ifs if item)
            for member in members:
                if member not in zone["interfaces"]:
                    zone["interfaces"].append(member)
        known = {item["id"] for item in interfaces}
        for zone in by_id.values():
            svi = "Vlan" + zone["id"].removeprefix("vlan")
            if svi in known and svi not in zone["interfaces"]:
                zone["interfaces"].append(svi)
        return [by_id[key] for key in sorted(by_id, key=lambda item: int(item))]

    def _rules(self, acl_doc: Any, hits_doc: Any, bindings: dict[str, dict[str, list[str]]]) -> tuple[
            list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        counters = self._counters(hits_doc)
        rules: list[dict[str, Any]] = []
        aliases: list[dict[str, Any]] = []
        notes: list[str] = []
        seen_alias: set[str] = set()
        for acl in _dicts_named(acl_doc, "extended"):
            name = _text(_child(acl, "name"))
            if not name:
                continue
            sequences = _child(acl, "access-list-seq-rule") or []
            if isinstance(sequences, dict):
                sequences = [sequences]
            bound = bindings.get(name) or {"in": [], "out": []}
            for seq in sequences if isinstance(sequences, list) else []:
                if not isinstance(seq, dict):
                    continue
                ace = _child(seq, "ace-rule")
                if not isinstance(ace, dict):
                    continue
                ace = {_local(key): value for key, value in ace.items()}
                sequence = _text(_child(seq, "sequence"))
                if not sequence.isdigit():
                    notes.append(f"Skipped an entry in {name} whose sequence was not a number.")
                    continue
                source, source_aliases = _endpoint(ace, dest=False)
                dest, dest_aliases = _endpoint(ace, dest=True)
                for alias in source_aliases + dest_aliases:
                    if alias["name"] not in seen_alias:
                        seen_alias.add(alias["name"])
                        aliases.append(alias)
                try:
                    services = _service(ace)
                except ValueError:
                    notes.append(f"Skipped {name} sequence {sequence}: the ports could not be read.")
                    continue
                rule_id = f"{name}:{int(sequence)}"
                rules.append({
                    "id": rule_id, "vendor_ref": rule_id, "order": int(sequence), "enabled": True,
                    "action": _text(ace.get("action")) or "deny",
                    "interfaces": list(bound["in"]), "out_interfaces": list(bound["out"]),
                    "direction": "out" if bound["out"] and not bound["in"] else "in",
                    "source": source, "destination": dest, "services": services,
                    "log": _present(_child(ace, "log")) or _present(_child(ace, "log-input")),
                    "description": _child(seq, "remark") if isinstance(_child(seq, "remark"), str) else "",
                    "hits": counters.get((name, str(int(sequence)))),
                })
        return rules, aliases, notes

    def _counters(self, document: Any) -> dict[tuple[str, str], int]:
        found: dict[tuple[str, str], int] = {}
        for acl in _dicts_named(document, "access-list"):
            name = _text(acl.get("name"))
            if not name:
                continue
            for entry in _dicts_named(acl, "access-list-entry"):
                seq = _text(entry.get("rule-name") if "rule-name" in entry else _first(entry, "rule-name"))
                counter = _first(entry, "match-counter")
                if not seq or counter in (None, ""):
                    continue
                try:
                    found[(name, str(int(float(seq))))] = max(0, int(float(counter)))
                except (TypeError, ValueError):
                    continue
        return found

    def _public(self, record: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in record.items() if not str(key).startswith("_")}

    async def test(self) -> dict[str, Any]:
        tls_on = bool(self.config.get("verify_tls", True) or self.config.get("ca_file"))
        try:
            async with self.client() as client:
                record = await self._read(client)
                caps = await self._request(client, "GET", CAPS_PATH, what="reading NETCONF capabilities", optional=True)
        except ConnectorError as exc:
            return self._test_failed(exc, tls_on)
        flags = _capability_flags(caps)
        checks = [
            check("reachability", True, f"{self.config.get('base_url')} answers"),
            check("tls", tls_on, "certificate verification is on" if tls_on else
                  "TLS certificate verification is turned off in the connection"),
            check("authentication", True, "HTTP Basic credentials accepted"),
            check("privileges", True, LEAST_PRIVILEGE_NOTE),
        ]
        version = record.get("_version") or ""
        checks.append(check("version", bool(version), f"IOS-XE {version}" if version else
                            "software-version was not in the RESTCONF reply"))
        features = ("RESTCONF reads ACLs, VLANs, SVIs and interfaces. " + _WRITE_NOTE)
        if {"candidate", "confirmed-commit"} <= flags:
            features += " The device advertises candidate and confirmed-commit; writes still stay off."
        elif caps is None:
            features += " NETCONF capability discovery over RESTCONF returned nothing (UNVERIFIED path)."
        checks.append(check("api_features", True, features))
        ok = all(item["ok"] for item in checks)
        return {"ok": ok, "detail": f"Connected to Cisco IOS-XE {record.get('external_id')}.", "checks": checks,
                "domains": self.domains() if ok else {}, "network_write": None}

    def _test_failed(self, exc: ConnectorError, tls_on: bool) -> dict[str, Any]:
        text = exc.message
        checks = []
        if "Cannot reach" in text or "did not answer in time" in text:
            checks.append(check("reachability", False, text))
        else:
            checks.append(check("reachability", True, f"{self.config.get('base_url')} answers"))
            checks.append(check("tls", tls_on, "certificate verification is on" if tls_on else
                                "TLS certificate verification is turned off in the connection"))
            if exc.status in (401, 403):
                checks.append(check("authentication", False, text))
            else:
                checks.append(check("authentication", True, "HTTP Basic credentials accepted"))
                checks.append(check("version", False, text))
        return {"ok": False, "detail": text, "checks": checks, "domains": {}, "network_write": None}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self.client() as client:
            return [self._public(await self._read(client))]

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            content, fmt = await self._backup_bytes(client)
        return {"content": content, "format": fmt, "device_backup_id": None, "revision": None,
                "sha256": hashlib.sha256(content).hexdigest()}

    async def _backup_bytes(self, client) -> tuple[bytes, str]:
        try:
            data = await self._request(client, "POST", CLI_RPC, what="reading the modelled configuration",
                                       body={"Cisco-IOS-XE-cli-rpc:input": {"datastore": "running"}})
        except ConnectorError as exc:
            if exc.status not in (400, 404, 405, 501):
                raise self._change(exc.message, code="failed", state="unchanged", status=exc.status,
                                   excerpt=exc.excerpt) from exc
            data = None
        text = _modelled_cli(data)
        if text:
            return text.encode("utf-8"), "text"
        record = self._public(await self._read(client))
        payload = {"kind": "cisco-iosxe-restconf-snapshot", "record": record}
        return json.dumps(payload, sort_keys=True).encode("utf-8"), "json"

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        raise self._change("Cisco IOS-XE configuration restore is unavailable. " + _WRITE_NOTE,
                           code="unsupported", state="unchanged")


def _modelled_cli(data: Any) -> str:
    """UNVERIFIED: the get-modelled-config-clis output leaf name is not in a captured reply."""
    if not isinstance(data, dict):
        return ""
    for name in ("cli", "result", "config", "config-clis"):
        value = _first(data, name)
        if isinstance(value, str) and value.strip():
            return value
    return ""
