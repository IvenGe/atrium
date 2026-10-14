"""pfSense connector. Two modes:

- SSH: pfSense CE and Plus; reads config.xml. On CE it also makes guarded rule changes (one allow rule between two
  interface networks, disabling / re-enabling rules).
- REST: read only, through the UNOFFICIAL pfSense REST API package (pfrest).

pfSense CE has no official API, and the official Plus API (Netgate Nexus) is not documented well enough to use (see
docs/research/fw-opnsense-pfsense-mikrotik.md section 2). Checked against the pfsense/pfsense sources (master =
2.9.0-dev, October 2026), Netgate's documentation and the pfrest sources:

- SSH:
  - The root/admin login shell (``/etc/rc.initial``) runs ``ssh <fw> <command>`` as ``/bin/sh -c "<command>"``.
  - Reads: ``cat /cf/conf/config.xml`` (Netgate's remote backup example), ``/etc/version`` and ``/etc/platform``, and
    ``/sbin/ifconfig -a`` for addresses learnt by DHCP.
- config.xml:
  - Interfaces live under ``interfaces/<wan|lan|optN>`` (``if``, ``enable``, ``descr``, ``ipaddr``/``subnet``,
    ``ipaddrv6``/``subnetv6``, ``gateway``). Also read: ``vlans/vlan``, ``ifgroups/ifgroupentry`` (members
    space-separated) and ``aliases/alias`` (``address`` space-separated).
  - ``filter/rule``: ``disabled``, ``log`` and ``not`` mean true when present (``isset`` in filter.inc). Ranges look
    like "8000-8080". Endpoints are ``any``, ``network`` (an interface = its subnet, ``<if>ip`` = its address,
    ``(self)``) or ``address`` (an IP, a CIDR or an alias).
  - Evaluation order (``get_filter_rules_map``): floating rules, then interface-group rules, then interface rules,
    each in config order.
  - Automatic rules (filter.inc): the anti-lockout rule (unless ``system/webgui/noantilockout``) passes TCP to the LAN
    address (or WAN with a single interface) on the GUI port, port 80 when HTTP redirects, and the SSH port when SSH
    is on. A default deny comes last.
  - Interface groups are not zones: rules on a group are read as rules on its member interfaces.
- Changes (CE over SSH):
  - The write uses the official PHP primitives ``config_get_path`` / ``config_set_path`` / ``write_config`` /
    ``filter_configure_sync``, run by ``/usr/local/bin/php-cgi -f``, the binary pfSense's own scripts use.
  - The PHP script refuses to write when config.xml changed since the hub read it (SHA-256 of the file).
  - pfSense has no commit-confirm, so a dead-man timer is armed BEFORE writing. ``daemon(8)`` runs a job that copies
    the pre-change config.xml back and reloads the filter after ``window_s`` unless Atrium renames its arm file first.
    The rename is atomic, so the confirm and the timer cannot both win.
  - Rollback is the inverse in PHP (remove the created rule by its tracker, put toggled rules back), then the
    pre-change file if a re-read still shows the change.
  - ``pfctl -sr`` must list the new rule's ``ridentifier`` (the tracker) once a rule that was already enabled
    shows its own.
  - A restored Atrium backup goes through ``config_restore()``, the official restore that keeps a history entry.
- Plus: read only. Its PHP internals are not public, so writes stay off (UNVERIFIED that they match CE).
- pfrest (unofficial; "not affiliated or supported by Netgate"; removed by every pfSense upgrade): read only.
  - The ``X-API-Key`` header. ``GET /api/v2/system/version``, ``/interfaces``, ``/interface/vlans``,
    ``/interface/groups``, ``/firewall/aliases`` and ``/firewall/rules`` (all records when no limit is given).
  - Interfaces are represented by description, id or device (the package's "represent interfaces as" setting).
  - Addresses are "any", "!x" (negated), an interface, "<if>:ip", "(self)", an alias, an IP or a CIDR.

UNVERIFIED (no pfSense device was available; tested against recorded config.xml / command answers and against the
PHP scripts run with stub pfSense includes): that pfSense Plus uses the same config.xml layout (reads only); that
``pfctl -sr`` prints ``ridentifier`` on every pfSense version (the check is skipped when it does not); ``/sbin/sha256
-q`` and ``/usr/sbin/daemon`` on every version (test() checks both); GUI separators shifting by one row on the
interface that gets the new rule (cosmetic); that a non-root shell account can read config.xml.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets as secrets_module
import ssl
import time
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, AsyncIterator, Callable

import httpx

from ..execution.runner import SshError, SshResult, parse_ssh_connection
from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, Backup, ChangeError, UnsafeXml, derived_revision, display_id,
                       management_guard, normalise_cidr, normalize_record, parse_ops, parse_ports, parse_untrusted_xml,
                       ssh_fields, ssh_target, untrusted_text, validate_ssh_config)

OPS = ["allow", "disable_rules", "enable_rules"]
WINDOW = 120
WINDOW_BOUNDS = (60, 600)
CONFIG_PATH = "/cf/conf/config.xml"
PHP_BIN = "/usr/local/bin/php-cgi"
DAEMON = "/usr/sbin/daemon"  # UNVERIFIED: FreeBSD base paths, assumed on every pfSense version (test() checks both)
SHA256 = "/sbin/sha256"
RESULT = "ATRIUM-RESULT:"
CID_RE = re.compile(r"^[0-9a-f]{16}$")
TRACKER_RE = re.compile(r"^[0-9]{1,20}$")
IFACE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
PLATFORM_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
VPN_NETWORKS = ("pppoe", "l2tp")  # the client networks of pfSense's own VPN servers: read as "any"
REST_PRIVILEGE = "REST API - {path} GET"

# PHP run on the firewall by php-cgi. Only data goes in (base64 JSON in @@PAYLOAD@@); output is the last line
# "ATRIUM-RESULT:<json>" (pfSense includes may print, so everything before it is discarded).
PHP_HEAD = r"""<?php
ob_start();
require_once("config.inc");
require_once("filter.inc");
function atrium_result(array $data): void {
    while (ob_get_level() > 0) { ob_end_clean(); }
    echo "\nATRIUM-RESULT:" . json_encode($data) . "\n";
    exit(0);
}
$p = json_decode(base64_decode('@@PAYLOAD@@'), true);
if (!is_array($p)) { atrium_result(["ok" => false, "error" => "payload"]); }
"""
PHP_PROBE = PHP_HEAD + r"""
$out = ["ok" => true];
foreach (["config_get_path", "config_set_path", "write_config", "filter_configure_sync", "config_restore",
          "config_validate"] as $f) { $out[$f] = function_exists($f); }
$out["daemon"] = is_executable($p["daemon"]);
$out["sha256"] = is_executable($p["sha256"]);
atrium_result($out);
"""
PHP_APPLY = PHP_HEAD + r"""
foreach (["config_get_path", "config_set_path", "write_config", "filter_configure_sync"] as $f) {
    if (!function_exists($f)) { atrium_result(["ok" => false, "error" => "unsupported", "detail" => $f]); }
}
if (!empty($p["expect"]) && hash_file("sha256", $p["config_path"]) !== $p["expect"]) {
    atrium_result(["ok" => false, "error" => "stale"]);
}
$rules = config_get_path("filter/rule", []);
$rules = is_array($rules) ? array_values($rules) : [];
$trackers = [];
foreach ($rules as $r) { if (is_array($r) && isset($r["tracker"])) { $trackers[(string)$r["tracker"]] = true; } }
$stamp = function_exists("make_config_revision_entry") ? make_config_revision_entry(null, $p["user"])
    : ["time" => time(), "username" => $p["user"]];
$created = [];
foreach ($p["ops"] as $op) {
    if ($op["kind"] === "add") {
        $tracker = (int)$p["now"];
        while (isset($trackers[(string)$tracker])) { $tracker++; }
        $trackers[(string)$tracker] = true;
        $rule = $op["rule"];
        $rule["tracker"] = (string)$tracker;
        $rule["created"] = $stamp;
        $position = count($rules);
        foreach ($rules as $i => $r) {
            if (is_array($r) && !isset($r["floating"]) && ($r["interface"] ?? "") === $rule["interface"]) {
                $position = $i;
                break;
            }
        }
        array_splice($rules, $position, 0, [$rule]);
        $created[] = (string)$tracker;
        continue;
    }
    $found = false;
    foreach ($rules as $i => $r) {
        if (!is_array($r) || (string)($r["tracker"] ?? "") !== (string)$op["tracker"]) { continue; }
        $found = true;
        if ($op["kind"] === "remove") { unset($rules[$i]); break; }
        if ($op["disabled"]) { $rules[$i]["disabled"] = true; } else { unset($rules[$i]["disabled"]); }
        $rules[$i]["updated"] = $stamp;
    }
    if (!$found && $op["kind"] !== "remove") {
        atrium_result(["ok" => false, "error" => "missing", "tracker" => (string)$op["tracker"]]);
    }
}
config_set_path("filter/rule", array_values($rules));
write_config($p["desc"]);
filter_configure_sync();
atrium_result(["ok" => true, "created" => $created]);
"""
PHP_RESTORE = PHP_HEAD + r"""
$data = base64_decode($p["content"], true);
if ($data === false || hash("sha256", $data) !== $p["sha256"] || strpos(substr($data, 0, 4096), "<pfsense") === false) {
    atrium_result(["ok" => false, "error" => "content"]);
}
if (file_put_contents($p["tmp"], $data) === false) { atrium_result(["ok" => false, "error" => "write"]); }
chmod($p["tmp"], 0600);
if (function_exists("config_validate") && !config_validate($p["tmp"])) {
    @unlink($p["tmp"]);
    atrium_result(["ok" => false, "error" => "invalid"]);
}
if (function_exists("config_restore")) {
    $ok = config_restore($p["tmp"], $p["desc"]);
} else {
    $ok = copy($p["tmp"], $p["config_path"]);
    @unlink("/tmp/config.cache");
}
@unlink($p["tmp"]);
atrium_result(["ok" => (bool)$ok, "error" => $ok ? null : "restore"]);
"""

# Shell scripts (``/bin/sh -s``) of the dead-man timer: only the change id (16 hex characters) and the window
# (an integer) are filled in, both made by Atrium.
ARM = """set -e
umask 077
cp {config} /root/atrium-pre-{cid}.xml
touch /tmp/atrium-arm-{cid}
{daemon} -f /bin/sh -c 'sleep {window}; if mv /tmp/atrium-arm-{cid} /tmp/atrium-fired-{cid} 2>/dev/null; then cp /root/atrium-pre-{cid}.xml {config} && rm -f /tmp/config.cache && /etc/rc.filter_configure; fi'
{sha256} -q /root/atrium-pre-{cid}.xml
"""
DISARM = ("if mv /tmp/atrium-arm-{cid} /tmp/atrium-{to}-{cid} 2>/dev/null; then echo {to}; "
          "elif [ -e /tmp/atrium-fired-{cid} ]; then echo fired; else echo missing; fi")
CONFIRM = DISARM + "\nrm -f /tmp/atrium-done-{cid}\n[ -e /tmp/atrium-fired-{cid} ] || rm -f /root/atrium-pre-{cid}.xml"
RESTORE_PRE = ("[ -f /root/atrium-pre-{cid}.xml ] && cp /root/atrium-pre-{cid}.xml {config} && rm -f /tmp/config.cache "
               "&& /etc/rc.filter_configure && echo restored")
CLEANUP = "rm -f /root/atrium-pre-{cid}.xml /tmp/atrium-rolled-{cid} /tmp/atrium-fired-{cid} /tmp/atrium-done-{cid}"


class SshUnavailable(ConnectorError):
    """The SSH connection could not be opened or broke off."""


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value if value is not None else "").strip().lower() in ("1", "true", "yes", "on", "enabled")


def _words(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [w for w in re.split(r"[\s,]+", str(value or "")) if w]


# --------------------------------------------------------------------------------------
# config.xml and command output (untrusted device data)
# --------------------------------------------------------------------------------------


def _text(el: ET.Element | None, tag: str) -> str:
    return (el.findtext(tag) or "").strip() if el is not None else ""


def _present(el: ET.Element | None, tag: str) -> bool:
    return el is not None and el.find(tag) is not None


def _endpoint_xml(rule: ET.Element, tag: str) -> dict[str, Any]:
    el = rule.find(tag)
    if el is None or _present(el, "any"):
        return {"any": True, "not": _present(el, "not")}
    return {"any": False, "network": _text(el, "network"), "address": _text(el, "address"), "not": _present(el, "not")}


def parse_config_xml(content: str | bytes) -> dict[str, Any]:
    """The parts of a pfSense config.xml the network model needs (ValueError when it is not one)."""
    raw = content.encode("utf-8") if isinstance(content, str) else content
    try:
        root = parse_untrusted_xml(raw)
    except UnsafeXml as exc:
        raise ValueError("config.xml declares a DOCTYPE or entities - refusing to parse it") from exc
    except ET.ParseError as exc:
        raise ValueError(f"config.xml is not valid XML ({exc.msg})") from exc
    if root.tag != "pfsense":
        raise ValueError("this is not a pfSense config.xml")
    system = root.find("system")
    interfaces = []
    for el in list(root.find("interfaces") if root.find("interfaces") is not None else []):
        interfaces.append({"id": el.tag, "if": _text(el, "if"), "descr": _text(el, "descr"),
                           "enabled": _present(el, "enable"), "ipaddr": _text(el, "ipaddr"),
                           "subnet": _text(el, "subnet"), "ipaddrv6": _text(el, "ipaddrv6"),
                           "subnetv6": _text(el, "subnetv6"), "gateway": _text(el, "gateway")})
    rules = []
    for el in root.findall("filter/rule"):
        floating = _text(el, "floating") == "yes"
        rules.append({
            "tracker": _text(el, "tracker"), "type": _text(el, "type") or "pass",
            "interface": _words(_text(el, "interface")) if floating else [_text(el, "interface")],
            "floating": floating, "quick": True if not floating else _present(el, "quick"),
            "direction": (_text(el, "direction") or "any") if floating else "in",
            "ipprotocol": _text(el, "ipprotocol") or "inet", "protocol": _text(el, "protocol"),
            "source": _endpoint_xml(el, "source"), "source_port": _text(el.find("source"), "port"),
            "destination": _endpoint_xml(el, "destination"),
            "destination_port": _text(el.find("destination"), "port"),
            "disabled": _present(el, "disabled"), "log": _present(el, "log"), "descr": _text(el, "descr"),
        })
    webgui = system.find("webgui") if system is not None else None
    ssh = system.find("ssh") if system is not None else None
    antilockout = None
    if not _present(webgui, "noantilockout"):
        protocol = _text(webgui, "protocol") or "https"
        port = _text(webgui, "port") or ("443" if protocol == "https" else "80")
        ports = [port]
        if protocol == "https" and not _present(webgui, "disablehttpredirect") and port != "80":
            ports.append("80")
        if _present(ssh, "enable"):
            ports.append(_text(ssh, "port") or "22")
        keys = [i["id"] for i in interfaces]
        where = "lan" if len(keys) > 1 and "lan" in keys else "wan" if len(keys) == 1 else None
        antilockout = {"interface": where, "ports": ports} if where else None
    hostname = ".".join(filter(None, (_text(system, "hostname"), _text(system, "domain"))))
    return {
        "hostname": hostname, "config_version": _text(root, "version"), "interfaces": interfaces,
        "vlans": {_text(v, "vlanif"): _text(v, "tag") for v in root.findall("vlans/vlan") if _text(v, "vlanif")},
        "groups": {_text(g, "ifname"): _words(_text(g, "members")) for g in root.findall("ifgroups/ifgroupentry")
                   if _text(g, "ifname")},
        "aliases": {_text(a, "name"): {"type": _text(a, "type"), "address": _words(_text(a, "address"))}
                    for a in root.findall("aliases/alias") if _text(a, "name")},
        "rules": rules, "antilockout": antilockout,
    }


def parse_ifconfig(text: str) -> dict[str, list[str]]:
    """FreeBSD ``ifconfig -a`` -> {device: ["10.0.0.1/24", "2001:db8::1/64"]} (link-local addresses left out)."""
    out: dict[str, list[str]] = {}
    device = None
    for line in (text or "").splitlines():
        head = re.match(r"^([A-Za-z0-9_.]+): flags=", line)
        if head:
            device = head.group(1)
            out.setdefault(device, [])
            continue
        if device is None:
            continue
        inet = re.match(r"^\s+inet (\S+) netmask (0x[0-9a-fA-F]{8})", line)
        inet6 = re.match(r"^\s+inet6 ([0-9a-fA-F:]+)(?:%\S+)? prefixlen (\d+)", line)
        try:
            if inet:
                prefix = bin(int(inet.group(2), 16)).count("1")
                found = ipaddress.ip_interface(f"{inet.group(1)}/{prefix}")
            elif inet6:
                found = ipaddress.ip_interface(f"{inet6.group(1)}/{inet6.group(2)}")
            else:
                continue
        except ValueError:
            continue
        if not found.ip.is_link_local and not found.ip.is_loopback:
            out[device].append(str(found))
    return out


def parse_platform(version_text: str) -> dict[str, Any]:
    """{"product": "pfSense CE" | "pfSense Plus", "version": "2.8.1-RELEASE", "major": 2}: Plus numbers its releases
    by year and month (25.07), CE by 2.x."""
    # UNVERIFIED: telling Plus from CE by the release number (inferred from Netgate's release lists)
    version = untrusted_text((version_text or "").splitlines()[0] if version_text else "", 60)
    match = PLATFORM_RE.search(version)
    major = int(match.group(1)) if match else None
    product = "pfSense Plus" if major and major >= 20 else "pfSense CE" if major else "pfSense"
    return {"product": product, "version": version, "major": major,
            "numbers": tuple(int(x or 0) for x in match.groups()) if match else None}


# --------------------------------------------------------------------------------------
# the shared model -> the normalised record
# --------------------------------------------------------------------------------------


class Device:
    """One read of the firewall (from config.xml or from pfrest) and the lookups normalisation needs."""

    def __init__(self, model: dict[str, Any]):
        self.model = model
        self.interfaces = {i["id"]: i for i in model.get("interfaces") or [] if i.get("id")}
        self.groups = {name: [m for m in members if m in self.interfaces]
                       for name, members in (model.get("groups") or {}).items()}
        self.aliases = model.get("aliases") or {}
        self.live = model.get("live") or {}

    def addresses(self, iface: str) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
        row = self.interfaces.get(iface) or {}
        out = []
        for address, bits in ((row.get("ipaddr"), row.get("subnet")), (row.get("ipaddrv6"), row.get("subnetv6"))):
            try:
                out.append(ipaddress.ip_interface(f"{address}/{bits}"))
            except ValueError:
                continue
        for text in self.live.get(row.get("if") or "", []):
            found = ipaddress.ip_interface(text)
            if found not in out:
                out.append(found)
        return [a for a in out if not a.ip.is_link_local]

    def role(self, iface: dict[str, Any]) -> str:
        if iface["id"] == "wan" or iface.get("gateway") or iface.get("ipaddr") in ("dhcp", "pppoe", "pptp", "l2tp"):
            return "wan"
        return "lan" if iface["id"] == "lan" else "other"

    def members(self, token: str) -> list[str] | None:
        if token in self.groups:
            return self.groups[token]
        return [token] if token in self.interfaces else None

    def alias(self, name: str, depth: int = 0) -> dict[str, Any]:
        entry = self.aliases.get(name) or {}
        kind_raw = str(entry.get("type") or "").lower()
        kind = {"host": "host", "network": "network", "port": "port", "url": "url", "urltable": "url",
                "url_ports": "url", "urltable_ports": "url"}.get(kind_raw, "other")
        out: dict[str, Any] = {"name": name, "kind": kind, "cidrs": [], "ports": None, "resolved": True}
        if not entry or depth > 8 or kind not in ("host", "network", "port"):
            out["resolved"] = False
            return out
        if kind == "port":
            ports = []
            for item in entry.get("address") or []:
                if item in self.aliases:
                    nested = self.alias(item, depth + 1)
                    out["resolved"] = out["resolved"] and nested["resolved"]
                    ports += [nested["ports"]] if nested["ports"] else []
                    continue
                try:
                    parsed = parse_ports(item)
                except ValueError:
                    out["resolved"] = False
                    continue
                ports += [parsed] if parsed else []
            out["ports"] = ",".join(ports) or None
            out["resolved"] = out["resolved"] and bool(ports)
            return out
        cidrs: list[str] = []
        for item in entry.get("address") or []:
            cidr = normalise_cidr(item)
            if cidr:
                cidrs.append(cidr)
            elif item in self.aliases:
                nested = self.alias(item, depth + 1)
                cidrs += nested["cidrs"]
                out["resolved"] = out["resolved"] and nested["resolved"]
            elif "-" in item and all(normalise_cidr(p) for p in item.split("-", 1)):
                try:
                    low, high = (ipaddress.ip_address(p.strip()) for p in item.split("-", 1))
                    cidrs += [str(n) for n in ipaddress.summarize_address_range(low, high)]
                except (ValueError, TypeError):
                    out["resolved"] = False
            else:  # a host name, resolved by the firewall at run time
                out["resolved"] = False
        out["cidrs"] = list(dict.fromkeys(cidrs))[:2000]
        return out

    def endpoint(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        if endpoint.get("any"):
            return {"any": True}
        out: dict[str, Any] = {"cidrs": [], "aliases": [], "nets": [], "self": False, "negate": bool(endpoint.get("not"))}
        network, address = str(endpoint.get("network") or ""), str(endpoint.get("address") or "")
        if network:
            members = self.members(network)
            if network == "(self)":
                out["self"] = True
            elif members is not None:
                out["nets"] += members
            elif network.endswith("ip") and network[:-2] in self.interfaces:
                found = self.addresses(network[:-2])
                if found:
                    out["cidrs"] += [str(ipaddress.ip_network(a.ip)) for a in found]
                else:
                    out["self"] = True  # an interface address unknown right now (DHCP, down)
            else:  # pppoe / l2tp server clients and anything unknown: any (wider, never narrower)
                return {"any": True}
        elif address:
            cidr = normalise_cidr(address)
            if cidr:
                out["cidrs"].append(cidr)
            else:
                out["aliases"].append(address)
        else:
            return {"any": True}
        return out

    def services(self, protocol: str, port: str) -> list[dict[str, Any]] | None:
        proto = (protocol or "").strip().lower()
        if proto in ("", "any"):
            return None
        ports, alias = None, None
        if port and port.lower() != "any":
            if port in self.aliases:
                resolved = self.alias(port)
                ports, alias = (resolved["ports"], None) if resolved["resolved"] else (None, port)
            else:
                try:
                    ports = parse_ports(port)
                except ValueError:
                    alias = port
        out = []
        for name in proto.split("/"):
            if name in ("tcp", "udp"):
                out.append({"proto": name, "ports": ports, "alias": alias})
            elif name:
                out.append({"proto": name})
        return out or None

    def rule(self, raw: dict[str, Any], index: int) -> dict[str, Any] | None:
        action = str(raw.get("type") or "pass").lower()
        if action not in ("pass", "block", "reject"):
            return None  # floating "match" rules neither pass nor block
        interfaces: list[str] = []
        for token in raw.get("interface") or []:
            if token and token != "any":
                interfaces += self.members(token) or [token]
        tracker = str(raw.get("tracker") or "")
        ident = tracker if TRACKER_RE.match(tracker) else f"index:{index}"
        return {"id": ident, "vendor_ref": ident, "enabled": not raw.get("disabled"), "action": action,
                "interfaces": list(dict.fromkeys(interfaces)), "floating": bool(raw.get("floating")),
                "direction": raw.get("direction") or "in", "quick": bool(raw.get("quick", True)),
                "source": self.endpoint(raw.get("source") or {}), "destination": self.endpoint(raw.get("destination") or {}),
                "services": self.services(str(raw.get("protocol") or ""), str(raw.get("destination_port") or "")),
                "log": bool(raw.get("log")), "description": raw.get("descr") or ""}

    def rank(self, raw: dict[str, Any]) -> int:
        """pfSense's evaluation order: floating, interface groups, interfaces (get_filter_rules_map)."""
        if raw.get("floating"):
            return 1
        return 2 if (raw.get("interface") or [""])[0] in self.groups else 3


def revision(model: dict[str, Any]) -> str:
    return derived_revision({k: model.get(k) for k in ("interfaces", "vlans", "groups", "aliases", "rules",
                                                         "antilockout")})


def to_record(model: dict[str, Any], management_address: str) -> dict[str, Any]:
    """The normalised device record (netmodel) of one read."""
    dev = Device(model)
    interfaces, self_addresses = [], []
    for iface in dev.interfaces.values():
        found = dev.addresses(iface["id"])
        self_addresses += [str(a.ip) for a in found]
        vlan = str((model.get("vlans") or {}).get(iface.get("if") or "") or "")
        interfaces.append({"id": iface["id"], "name": iface.get("descr") or iface["id"].upper(),
                           "description": iface.get("if") or "", "vlan": int(vlan) if vlan.isdigit() else None,
                           "subnets": list(dict.fromkeys(str(a.network) for a in found)),
                           "addresses": [str(a.ip) for a in found], "role": dev.role(iface),
                           "enabled": bool(iface.get("enabled"))})
    ranked = sorted(enumerate(model.get("rules") or []), key=lambda pair: (dev.rank(pair[1]), pair[0]))
    rules, seen = [], set()
    lockout = model.get("antilockout")
    if lockout and lockout.get("interface") in dev.interfaces:
        found = dev.addresses(lockout["interface"])
        rules.append({"id": "anti-lockout", "vendor_ref": "anti-lockout", "order": 0, "enabled": True,
                      "action": "pass", "interfaces": [lockout["interface"]], "direction": "in", "quick": True,
                      "source": {"any": True},
                      "destination": {"cidrs": [str(ipaddress.ip_network(a.ip)) for a in found]} if found
                      else {"self": True},
                      "services": [{"proto": "tcp", "ports": ",".join(lockout["ports"])}],
                      "description": "Anti-Lockout Rule (automatic)"})
    for order, (index, raw) in enumerate(ranked, start=1):
        rule = dev.rule(raw, index)
        if rule is None or rule["id"] in seen:
            continue
        seen.add(rule["id"])
        rules.append({**rule, "order": order})
    notes = list(model.get("notes") or [])
    if dev.groups:
        notes.append("rules on interface groups are read as rules on each member interface")
    if any(r["id"].startswith("index:") for r in rules):
        notes.append("some rules have no tracker id: they are named by position and cannot be changed by Atrium")
    notes += ["hit counts are not read", "the automatic anti-lockout and default deny rules are shown as pfSense "
              "generates them"]
    return {
        "external_id": model.get("hostname") or management_address, "revision": revision(model),
        "read_at": model.get("read_at"), "kind": "firewall",
        "device": {"vendor": "pfSense", "model": str(model.get("product") or "").replace("pfSense", "").strip(),
                   "version": model.get("version") or "",
                   "hostname": model.get("hostname") or "", "management_address": management_address, "serial": ""},
        "interfaces": interfaces, "zones": [], "aliases": [dev.alias(name) for name in dev.aliases],
        "self_addresses": list(dict.fromkeys(self_addresses)), "rules": rules,
        "default_policy": {"inbound": "block"}, "nat_evaluated": False, "notes": notes[:50],
    }


# --------------------------------------------------------------------------------------
# pfrest (unofficial REST API package) -> the shared model
# --------------------------------------------------------------------------------------


def model_from_rest(data: dict[str, Any]) -> dict[str, Any]:
    """The shared model from pfrest's answers (``data`` of each endpoint)."""
    interfaces = []
    for row in data.get("interfaces") or []:
        if not isinstance(row, dict) or not row.get("id"):
            continue
        interfaces.append({"id": str(row["id"]), "if": str(row.get("if") or ""), "descr": str(row.get("descr") or ""),
                           "enabled": truthy(row.get("enable")), "ipaddr": str(row.get("ipaddr") or ""),
                           "subnet": str(row.get("subnet") or ""), "ipaddrv6": str(row.get("ipaddrv6") or ""),
                           "subnetv6": str(row.get("subnetv6") or ""), "gateway": str(row.get("gateway") or "")})
    names: dict[str, str] = {}
    for iface in interfaces:  # rule fields name interfaces by description, id or device (a package setting)
        for key in (iface["descr"].lower(), iface["if"].lower(), iface["id"].lower()):
            if key:
                names.setdefault(key, iface["id"])
    groups = {str(g.get("ifname")): [names.get(str(m).lower(), str(m)) for m in _words(g.get("members"))]
              for g in data.get("groups") or [] if isinstance(g, dict) and g.get("ifname")}

    def iface(token: str) -> str:
        return token if token in groups else names.get(token.lower(), token)

    def endpoint(value: Any) -> dict[str, Any]:
        text = str(value or "").strip()
        negate = text.startswith("!")
        text = text[1:] if negate else text
        if not text or text == "any":
            return {"any": True, "not": negate}
        if text == "(self)":
            return {"any": False, "network": "(self)", "address": "", "not": negate}
        if text.endswith(":ip"):
            return {"any": False, "network": iface(text[:-3]) + "ip", "address": "", "not": negate}
        if text.lower() in names or text in groups or text in VPN_NETWORKS:
            return {"any": False, "network": iface(text), "address": "", "not": negate}
        return {"any": False, "network": "", "address": text, "not": negate}

    rules = []
    for row in data.get("rules") or []:
        if not isinstance(row, dict):
            continue
        floating = truthy(row.get("floating"))
        tokens = [iface(t) for t in _words(row.get("interface"))]
        rules.append({"tracker": str(row.get("tracker") or ""), "type": str(row.get("type") or "pass"),
                      "interface": tokens, "floating": floating,
                      "quick": truthy(row.get("quick")) if floating else True,
                      "direction": (str(row.get("direction") or "any") if floating else "in"),
                      "ipprotocol": str(row.get("ipprotocol") or "inet"), "protocol": str(row.get("protocol") or ""),
                      "source": endpoint(row.get("source")), "source_port": str(row.get("source_port") or ""),
                      "destination": endpoint(row.get("destination")),
                      "destination_port": str(row.get("destination_port") or ""),
                      "disabled": truthy(row.get("disabled")), "log": truthy(row.get("log")),
                      "descr": str(row.get("descr") or "")})
    version = data.get("version") if isinstance(data.get("version"), dict) else {}
    platform = parse_platform(str(version.get("version") or ""))
    return {"hostname": "", "product": platform["product"], "version": platform["version"],
            "interfaces": interfaces,
            "vlans": {str(v.get("vlanif")): str(v.get("tag")) for v in data.get("vlans") or []
                      if isinstance(v, dict) and v.get("vlanif")},
            "groups": groups,
            "aliases": {str(a.get("name")): {"type": str(a.get("type") or ""), "address": _words(a.get("address"))}
                        for a in data.get("aliases") or [] if isinstance(a, dict) and a.get("name")},
            "rules": rules, "antilockout": None,
            "notes": ["read through the unofficial pfSense REST API package (read only)",
                      "the automatic anti-lockout rule is not visible through the REST API"]}


# --------------------------------------------------------------------------------------
# the connector
# --------------------------------------------------------------------------------------


class PfsenseConnector(Connector):
    kind = "pfsense"
    title = "pfSense"
    description = ("Firewall: reads interfaces, aliases and rules into the Network app over SSH (pfSense CE and Plus) "
                   "or, read only, through the unofficial REST API package. On CE over SSH, with device changes "
                   "enabled, adds one allow rule or disables rules under the change safety model.")
    fields = [
        ConnectorField(name="mode", label="Connect with", kind="select", default="ssh", choices=[
            {"value": "ssh", "label": "SSH (config.xml; changes on pfSense CE)"},
            {"value": "pfrest", "label": "REST API package - unofficial, read only"}],
            help="pfSense CE has no official API. The REST API package (pfrest) is not supported by Netgate and is "
                 "removed by every pfSense upgrade."),
        *ssh_fields(default_user="admin"),
        ConnectorField(name="rollback_window_s", label="Automatic revert after (seconds)", kind="number",
                       default=WINDOW, help="SSH: a change reverts by itself unless Atrium confirms it in time "
                                            "(60-600)."),
        ConnectorField(name="api_port", label="REST API port", kind="number", default=443),
        ConnectorField(name="api_key", label="REST API key", kind="secret",
                       help="REST API package only: System > REST API > Keys, for a user with only the GET "
                            "privileges of the firewall, interface and alias endpoints."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate (REST)", kind="bool", default=True),
        ConnectorField(name="ca_file", label="CA certificate file (REST)", kind="text",
                       placeholder="/etc/atrium/pfsense-ca.pem",
                       help="PEM file on the hub's machine with the GUI certificate or its CA. Empty: the system's "
                            "trusted CAs."),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this firewall through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "deadman", "window_s": WINDOW}
    clock: Callable[[], float] = staticmethod(time.time)

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("pfsense", "netgate"))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        return (super().endpoint(config) + f"|mode={config.get('mode') or 'ssh'}|api_port={config.get('api_port') or 443}"
                f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}")

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        mode = str(config.get("mode") or "ssh")
        if mode not in ("ssh", "pfrest"):
            raise ConnectorError("Connect with: ssh or pfrest")
        try:
            config = validate_ssh_config({**config, "mode": mode})
        except ValueError as exc:
            raise ConnectorError(str(exc)) from exc
        window = int(config.get("rollback_window_s") or WINDOW)
        if not WINDOW_BOUNDS[0] <= window <= WINDOW_BOUNDS[1]:
            raise ConnectorError(f"The automatic revert window is {WINDOW_BOUNDS[0]}-{WINDOW_BOUNDS[1]} seconds")
        port = int(config.get("api_port") or 443)
        if not 1 <= port <= 65535:
            raise ConnectorError("The REST API port is 1-65535")
        ca_file = str(config.get("ca_file") or "").strip()
        if ca_file and not (os.path.isabs(ca_file) or PurePosixPath(ca_file).is_absolute()):
            raise ConnectorError("CA certificate file must be an absolute path on the hub's machine")
        return {**config, "rollback_window_s": window, "api_port": port}

    @property
    def rest(self) -> bool:
        return self.config.get("mode") == "pfrest"

    @property
    def window(self) -> int:
        return int(self.config.get("rollback_window_s") or WINDOW)

    def write_capability(self) -> dict[str, Any] | None:
        if self.rest or self.config.get("read_only"):
            return None
        spec = super().write_capability()
        return {**spec, "window_s": self.window} if spec else None

    # -- SSH ---------------------------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def session(self) -> AsyncIterator[Any]:
        try:
            target = ssh_target(self.config, self.secrets)
        except ConnectorError as exc:
            raise self.error(exc.message) from exc
        try:
            async with self.ssh(target) as session:
                yield session
        except SshError as exc:
            raise SshUnavailable(self.redact(f"pfSense over SSH: {exc}")) from exc

    async def _run(self, session: Any, command: str, *, what: str, input: str | None = None,
                   ok_codes: tuple[int, ...] = (0,)) -> SshResult:
        try:
            result = await session.run(command, input=input)
        except SshError as exc:
            raise SshUnavailable(self.redact(f"pfSense over SSH ({what}): {exc}")) from exc
        if result.truncated:
            raise self.error(f"pfSense's answer was larger than the read limit ({what}) - refusing a partial read")
        if result.timed_out or result.exit_status not in ok_codes:
            raise self.error(f"pfSense could not {what} (exit status {result.exit_status}"
                             + (", timed out" if result.timed_out else "") + ")"
                             + (f": {untrusted_text(result.stderr, 160)}" if result.stderr.strip() else ""))
        return result

    async def _php(self, session: Any, template: str, payload: dict[str, Any], *, what: str) -> dict[str, Any]:
        """Run one of the PHP templates with `payload` on the firewall; its ATRIUM-RESULT object."""
        name = secrets_module.token_hex(8)
        script = template.replace("@@PAYLOAD@@", base64.b64encode(json.dumps(payload).encode()).decode("ascii"))
        command = (f"umask 077 && cat > /tmp/atrium-{name}.php && {PHP_BIN} -q -f /tmp/atrium-{name}.php; "
                   f"rc=$?; rm -f /tmp/atrium-{name}.php; exit $rc")
        result = await self._run(session, command, what=what, input=script)
        line = next((l for l in reversed(result.stdout.splitlines()) if l.startswith(RESULT)), None)
        try:
            answer = json.loads(line[len(RESULT):]) if line else None
        except ValueError:
            answer = None
        if not isinstance(answer, dict):
            raise self.error(f"pfSense did not answer the {what} script (is {PHP_BIN} there?)")
        return answer

    async def read_ssh(self, session: Any) -> tuple[dict[str, Any], str]:
        """(the shared model, the config.xml text) of one read over SSH."""
        platform = parse_platform((await self._run(session, "cat /etc/version", what="read the version")).stdout)
        config = (await self._run(session, f"cat {CONFIG_PATH}", what="read config.xml")).stdout
        try:
            model = parse_config_xml(config)
        except ValueError as exc:
            raise self.error(f"pfSense's config.xml cannot be read: {exc}") from exc
        notes = []
        try:
            live = parse_ifconfig((await session.run("/sbin/ifconfig -a")).stdout)
        except SshError:
            live = {}
        if not live:
            notes.append("interface addresses learnt by DHCP are unknown (ifconfig did not answer)")
        model.update({"product": platform["product"], "version": platform["version"], "live": live,
                      "notes": notes, "read_at": self.clock()})
        if platform["product"] == "pfSense Plus":
            model["notes"].append("pfSense Plus is read only in Atrium")
        return model, config

    # -- REST (pfrest, read only) --------------------------------------------------------------

    def ssl_context(self) -> ssl.SSLContext:
        ca_file = str(self.config.get("ca_file") or "").strip()
        try:
            context = ssl.create_default_context(cafile=ca_file or None)
        except (OSError, ssl.SSLError) as exc:
            raise self.error(f"Cannot load the CA certificate file {ca_file}") from exc
        if ca_file:
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        key = self.secrets.get("api_key")
        if not key:
            raise self.error("Enter the REST API key in the connection settings")
        host = str(self.config["host"])
        host = f"[{host}]" if ":" in host else host
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        return self.http(f"https://{host}:{self.config.get('api_port') or 443}/api/v2",
                         headers={"X-API-Key": key, "Accept": "application/json"}, verify=verify)

    async def _rest(self, client: httpx.AsyncClient, path: str, *, what: str) -> Any:
        try:
            response = await client.get(path)
        except httpx.TimeoutException as exc:
            raise self.error(f"pfSense's REST API did not answer in time ({what})") from exc
        except httpx.HTTPError as exc:
            reason = "its TLS certificate is not trusted - set the CA file" if "CERTIFICATE_VERIFY_FAILED" in str(exc) \
                else exc.__class__.__name__
            raise self.error(f"Cannot reach pfSense's REST API: {reason}") from exc
        code = response.status_code
        if code == 401:
            raise self.error("pfSense's REST API rejected the API key (HTTP 401)", status=401)
        if code == 403:
            raise self.error(f"pfSense's REST API refused {what} (HTTP 403) - grant the key's user "
                             f"'{REST_PRIVILEGE.format(path='/api/v2' + path)}'", status=403)
        if code == 404:
            raise self.error("pfSense answered 404 - is the REST API package installed? (pfSense upgrades remove it)",
                             status=404)
        if code >= 300:
            raise self.error(f"pfSense's REST API could not {what} (HTTP {code})", status=code)
        try:
            answer = response.json()
        except ValueError as exc:
            raise self.error(f"pfSense's REST API did not answer with JSON ({what})") from exc
        if not isinstance(answer, dict) or "data" not in answer:
            raise self.error(f"Unexpected answer from pfSense's REST API ({what}): no 'data'")
        return answer["data"]

    async def read_rest(self, client: httpx.AsyncClient) -> dict[str, Any]:
        data = {"version": await self._rest(client, "/system/version", what="read the version")}
        for key, path in (("interfaces", "/interfaces"), ("rules", "/firewall/rules"),
                          ("aliases", "/firewall/aliases")):
            data[key] = await self._rest(client, path, what=f"read {key}")
        notes = []
        for key, path in (("vlans", "/interface/vlans"), ("groups", "/interface/groups")):
            try:
                data[key] = await self._rest(client, path, what=f"read {key}")
            except ConnectorError as exc:
                if exc.status not in (403, 404):
                    raise
                data[key] = []
                notes.append(f"{key}: not readable ({exc.message})")
        model = model_from_rest(data)
        model["notes"] += notes
        model["read_at"] = self.clock()
        return model

    # -- reading ---------------------------------------------------------------------------

    async def read(self) -> tuple[dict[str, Any], str | None]:
        if self.rest:
            async with self.client() as client:
                return await self.read_rest(client), None
        async with self.session() as session:
            return await self.read_ssh(session)

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"pfSense cannot read {domain}")
        model, _ = await self.read()
        return [to_record(model, str(self.config.get("host") or ""))]

    # -- test ------------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        return await (self._test_rest() if self.rest else self._test_ssh())

    def _result(self, checks: list[dict[str, Any]], ok: bool, detail: str, write: dict[str, Any] | None = None
                ) -> dict[str, Any]:
        return {"ok": ok, "detail": detail, "checks": checks, "domains": self.domains() if ok else {},
                "network_write": write if ok else None}

    async def _test_ssh(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        where = f"{self.config.get('host')}:{self.config.get('port') or 22}"
        pinned = "pinned host key" if self.config.get("host_key") else \
            f"host key in {self.config.get('known_hosts') or '~/.ssh/known_hosts'}"
        try:
            async with self.session() as session:
                checks += [check("reachability", True, f"SSH answers on {where}"),
                           check("tls", True, f"SSH {pinned} verified"),
                           check("authentication", True, f"signed in as {self.config.get('username')}")]
                return await self._test_ssh_session(session, checks)
        except ConnectorError as exc:
            if checks:  # failed after signing in
                checks.append(check("ruleset", False, exc.message))
                return self._result(checks, False, exc.message)
            text = exc.message.lower()
            if "host key" in text or "known_hosts" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", False, exc.message)]
            elif "authentication" in text or "private key" in text or "password" in text:
                checks += [check("reachability", True, f"SSH answers on {where}"), check("tls", True, pinned),
                           check("authentication", False, exc.message + " (repeated failures make sshguard block "
                                                                        "the hub for a while)")]
            else:
                checks.append(check("reachability", False, exc.message))
            return self._result(checks, False, exc.message)

    async def _test_ssh_session(self, session: Any, checks: list[dict[str, Any]]) -> dict[str, Any]:
        uid = (await self._run(session, "id -u", what="read the account")).stdout.strip()
        root = uid == "0"
        connection = parse_ssh_connection((await session.run("printenv SSH_CONNECTION")).stdout)
        model, _ = await self.read_ssh(session)
        record = normalize_record(to_record(model, str(self.config.get("host"))))
        plus = model["product"] == "pfSense Plus"
        probe: dict[str, Any] = {}
        if root and not plus:
            try:
                probe = await self._php(session, PHP_PROBE, {"daemon": DAEMON, "sha256": SHA256}, what="feature check")
            except SshUnavailable:
                raise
            except ConnectorError as exc:  # reading works without it; changes do not
                probe = {"php": False, "detail": exc.message}
        if probe.get("php") is False:
            missing = [f"{PHP_BIN} ({probe['detail']})"]
        else:
            missing = [name for name in ("config_get_path", "config_set_path", "write_config", "filter_configure_sync",
                                         "daemon", "sha256") if probe and not probe.get(name)]
        write = None
        if root and not plus and probe and not missing and self.write_capability() is not None:
            write = {"ops": OPS, "rollback": "deadman", "window_s": self.window}
        if not root:
            privilege = (f"non-root account (uid {display_id(uid)}): config.xml is readable, changes are unavailable "
                         "(pfSense needs root/admin to write the configuration)")
        elif self.config.get("read_only"):
            privilege = "root/admin account; this connection is set to read only"
        else:
            privilege = (f"root/admin account - {LEAST_PRIVILEGE_NOTE}. pfSense has no read-only SSH role: use a key "
                         "(System > Advanced > Admin Access: Public Key Only) and keep device changes off until "
                         "needed")
        checks.append(check("privileges", True, privilege))
        numbers = parse_platform(model["version"])["numbers"]
        checks.append(check("version", True, f"{model['product']} {model['version'] or 'unknown'} - "
                            + ("read only (Plus' internals are not public)" if plus else "supported")))
        features = ["config.xml readable", f"{len(record['rules'])} rules read"]
        if probe:
            features.append(("missing for changes: " + ", ".join(missing)) if missing else
                            f"config_set_path / write_config / filter_configure_sync present; dead-man revert after "
                            f"{self.window} s via daemon(8)")
        elif root and plus:
            features.append("changes are off on pfSense Plus")
        checks.append(check("api_features", True, "; ".join(features)
                            + ("" if numbers is None or numbers >= (2, 7, 0) or plus else
                               " (pfSense CE before 2.7 lacks config_set_path: read only)")))
        lockout = next((r for r in record["rules"] if r["id"] == "anti-lockout"), None)
        checks.append(check("anti_lockout", True, f"automatic anti-lockout rule on {lockout['interfaces'][0]} "
                                                  f"(tcp {lockout['services'][0]['ports']})" if lockout else
                            "the automatic anti-lockout rule is disabled: make sure a rule lets the hub reach SSH"))
        checks.append(check("management_guard", True,
                            f"the hub reaches the firewall from {connection['client_ip']} to SSH port "
                            f"{connection['server_port']}: rules carrying that path are never disabled"
                            if connection else "the hub's address is unknown (SSH_CONNECTION not set): every rule "
                                               "that can reach the firewall is protected"))
        if record["errors"]:
            checks.append(check("ruleset", True, f"{len(record['errors'])} entries could not be read and were skipped"))
        detail = (f"Connected to {model['product']} {model['version']} ({model.get('hostname') or self.config['host']}): "
                  f"{len(record['rules'])} rules" + ("" if write else " (read only)"))
        return self._result(checks, True, detail, write)

    async def _test_rest(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        where = f"{self.config.get('host')}:{self.config.get('api_port') or 443}"
        try:
            client = self.client()
        except ConnectorError as exc:
            checks.append(check("authentication", False, exc.message))
            return self._result(checks, False, exc.message)
        async with client:
            try:
                version = await self._rest(client, "/system/version", what="read the version")
            except ConnectorError as exc:
                if exc.status is None:
                    name = "tls" if "certificate" in exc.message else "reachability"
                    if name == "tls":
                        checks.append(check("reachability", True, f"{where} answers"))
                    checks.append(check(name, False, exc.message))
                else:
                    checks += [check("reachability", True, f"{where} answers"),
                               check("tls", bool(self.config.get("verify_tls", True)), "certificate checked"),
                               check("authentication" if exc.status == 401 else "api_features", False, exc.message)]
                return self._result(checks, False, exc.message)
            checks += [check("reachability", True, f"{where} answers"),
                       check("tls", bool(self.config.get("verify_tls", True)),
                             "certificate verified" if self.config.get("verify_tls", True) else
                             "verification is OFF - anyone on the path could read the API key"),
                       check("authentication", True, "API key accepted")]
            try:
                model = await self.read_rest(client)
                record = normalize_record(to_record(model, str(self.config.get("host"))))
            except ConnectorError as exc:
                checks.append(check("privileges", False, exc.message))
                return self._result(checks, False, exc.message)
        checks.append(check("privileges", True, "reads rules, interfaces and aliases; changes are never made through "
                                                "the REST API package (a key limited to GET privileges is enough)"))
        checks.append(check("version", True, f"{model['product']} {untrusted_text((version or {}).get('version'), 60)}"
                                             " - read only through the REST API package"))
        checks.append(check("api_features", True, "UNOFFICIAL REST API package (not supported by Netgate; removed by "
                                                  "pfSense upgrades - Atrium then reports 404)"))
        return self._result(checks, True, f"Connected to {model['product']} through the REST API package: "
                                          f"{len(record['rules'])} rules (read only)")

    # -- backups ---------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        if self.rest:
            raise ChangeError("Backups need the SSH connection mode", code="unsupported", state="unchanged")
        async with self.session() as session:
            model, config = await self.read_ssh(session)
        content = config.encode("utf-8")
        return {"content": content, "format": "xml", "device_backup_id": None, "revision": revision(model),
                "sha256": hashlib.sha256(content).hexdigest()}

    # -- changes ---------------------------------------------------------------------------

    @staticmethod
    def native_service(services: list[dict[str, Any]]) -> tuple[str, str]:
        """(protocol, port) of the one pfSense rule the services fit in; ValueError when they need several."""
        protos = sorted({s["proto"] for s in services})
        ports = {s.get("ports") for s in services}
        if protos == ["icmp"] and len(services) == 1:
            return "icmp", ""
        if len(ports) != 1 or len(services) != len(protos) or not set(protos) <= {"tcp", "udp"}:
            raise ValueError("a pfSense rule carries one protocol (or TCP/UDP with the same port) - split the "
                             "services into separate changes")
        port = next(iter(ports)) or ""
        if "," in port:
            raise ValueError("a pfSense rule carries one port or one range - split the ports into separate changes")
        return "/".join(protos), port

    def _check(self, ops: list[dict[str, Any]], model: dict[str, Any], record: dict[str, Any],
               connection: dict[str, Any] | None) -> tuple[list[str], list[str], list[dict[str, Any]]]:
        """(guard problems, other problems, preview steps) for `ops` against what the firewall holds now."""
        dev = Device(model)
        trackers = {str(r.get("tracker")) for r in model.get("rules") or [] if TRACKER_RE.match(str(r.get("tracker") or ""))}
        problems, steps = [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    iface = dev.interfaces.get(zone)
                    if iface is None or not IFACE_KEY_RE.match(zone):
                        problems.append(f"operation {index + 1}: pfSense has no interface '{display_id(zone)}'")
                    elif side == "source" and not iface.get("enabled"):
                        problems.append(f"operation {index + 1}: interface {display_id(zone)} is disabled")
                    if len(op[side]["cidrs"]) != 1:
                        problems.append(f"operation {index + 1}: a pfSense rule takes one {side} network - split the "
                                        "change or use one network per side")
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
                              "position": f"top of the {display_id(op['source']['zone'])} rules (after floating and "
                                          "interface-group rules)",
                              "detail": f"pass {proto}{' ' + port if port else ''} on "
                                        f"{display_id(op['source']['zone'])}, marked {op['marker']}"})
            else:
                verb = "disable" if op["op"] == "disable_rules" else "enable"
                for ref in op["rules"]:
                    tracker = ref["vendor_ref"] if TRACKER_RE.match(ref["vendor_ref"]) else ref["id"]
                    if ref["id"] == "anti-lockout" or ref["vendor_ref"] == "anti-lockout":
                        problems.append("the automatic anti-lockout rule cannot be changed by Atrium")
                    elif not TRACKER_RE.match(tracker):
                        problems.append(f"rule {display_id(ref['id'])} has no tracker id - save it once in the pfSense "
                                        "GUI so it gets one")
                    elif tracker not in trackers:
                        problems.append(f"rule {display_id(ref['id'])} is not on the firewall (re-read it first)")
                    steps.append({"op": index, "kind": f"{verb}_rule", "position": "in place",
                                  "detail": f"{verb} tracker {display_id(tracker)}"})
        guard = management_guard(record, ops,
                                 hub_addresses=[connection["client_ip"]] if connection else None,
                                 management_ports=[connection["server_port"] if connection
                                                   else int(self.config.get("port") or 22)])
        return guard, problems, steps

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            model, _ = await self.read()
            record = normalize_record(to_record(model, str(self.config.get("host"))))
            guard, problems, steps = self._check(ops, model, record, None)
            return {"steps": steps, "notes": [], "problems": guard + problems + [
                "changes need the SSH mode on pfSense CE" if self.rest else "this connection is set to read only"]}
        async with self.session() as session:
            connection = parse_ssh_connection((await session.run("printenv SSH_CONNECTION")).stdout)
            model, _ = await self.read_ssh(session)
        record = normalize_record(to_record(model, str(self.config.get("host"))))
        guard, problems, steps = self._check(ops, model, record, connection)
        if model["product"] == "pfSense Plus":
            problems.append("pfSense Plus is read only in Atrium")
        notes = [f"pfSense has no commit-confirm: a dead-man job restores the previous config.xml {self.window} s "
                 "after the change unless Atrium confirms it",
                 "GUI separators on that interface may shift by one row"]
        if record["revision"] != snapshot.get("revision"):
            notes.append("the firewall changed since the snapshot: refresh before approving")
        return {"steps": steps, "notes": notes, "problems": guard + problems}

    @staticmethod
    def _parse_token(token: str) -> dict[str, Any]:
        try:
            info = json.loads(token)
            assert isinstance(info, dict) and info.get("v") == 1 and CID_RE.match(str(info.get("cid") or ""))
            assert all(TRACKER_RE.match(t) for t in info.get("created") or [])
            assert all(TRACKER_RE.match(t) and v in ("0", "1") for t, v in (info.get("toggled") or {}).items())
            assert isinstance(info.get("adds", 0), int) and re.fullmatch(r"[0-9a-f]{64}", str(info.get("pre") or "0" * 64))
        except (ValueError, AssertionError, AttributeError, TypeError) as exc:
            raise ChangeError("Not a change token of this pfSense connector", code="invalid", state="unknown") from exc
        return info

    @staticmethod
    def _state(model: dict[str, Any], info: dict[str, Any]) -> str:
        """"applied", "reverted" or "partial": what config.xml shows of the change now ("partial" also when the
        tracker of a rule the change added is unknown)."""
        if len(info.get("created") or []) < int(info.get("adds") or 0):
            return "partial"
        rules = {str(r.get("tracker")): r for r in model.get("rules") or []}
        applied, reverted = [], []
        for tracker in info.get("created") or []:
            present = tracker in rules and not rules[tracker].get("disabled")
            applied.append(present)
            reverted.append(not present)
        for tracker, previous in (info.get("toggled") or {}).items():
            now = "1" if (rules.get(tracker) or {}).get("disabled") else "0"
            applied.append(now != previous)
            reverted.append(now == previous)
        if not applied:
            return "partial"
        return "applied" if all(applied) else "reverted" if all(reverted) else "partial"

    def _rule(self, op: dict[str, Any]) -> dict[str, Any]:
        proto, port = self.native_service(op["services"])
        destination: dict[str, Any] = {"address": op["destination"]["cidrs"][0]}
        if port:
            destination["port"] = port
        rule = {"type": "pass", "interface": op["source"]["zone"],
                "ipprotocol": "inet" if ipaddress.ip_network(op["source"]["cidrs"][0]).version == 4 else "inet6",
                "protocol": proto, "source": {"address": op["source"]["cidrs"][0]}, "destination": destination,
                "descr": f"{op['marker']} {op.get('description') or ''}".strip()}
        if op.get("log", True):
            rule["log"] = True
        return rule

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            raise ChangeError("This pfSense connection cannot change the firewall (read only or REST mode)",
                              code="unsupported", state="unchanged")
        progress = {"armed": False}
        try:
            async with self.session() as session:
                return await self._apply(session, ops, base_revision, progress)
        except ChangeError:
            raise
        except ConnectorError as exc:  # before arming nothing changed; after it the device's timer reverts
            raise ChangeError(exc.message + (f" - the automatic revert restores the previous configuration within "
                                             f"{self.window} s" if progress["armed"] else ""),
                              code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown" if progress["armed"] else "unchanged") from exc

    async def _apply(self, session: Any, ops: list[dict[str, Any]], base_revision: str,
                     progress: dict[str, bool]) -> dict[str, Any]:
        connection = parse_ssh_connection((await session.run("printenv SSH_CONNECTION")).stdout)
        model, config = await self.read_ssh(session)
        probe = await self._php(session, PHP_PROBE, {"daemon": DAEMON, "sha256": SHA256}, what="feature check")
        record = normalize_record(to_record(model, str(self.config.get("host"))))
        if record["revision"] != base_revision:
            raise ChangeError("The firewall's ruleset changed since the preview - re-read it and preview again",
                              code="stale", state="unchanged")
        guard, problems, _ = self._check(ops, model, record, connection)
        if guard:
            raise ChangeError("Refused by the management-path guard: " + "; ".join(guard), code="lockout",
                              state="unchanged")
        if model["product"] == "pfSense Plus":
            problems.append("pfSense Plus is read only in Atrium")
        missing = [n for n in ("config_set_path", "write_config", "filter_configure_sync", "daemon", "sha256")
                   if not probe.get(n)]
        if missing:
            problems.append("this pfSense lacks " + ", ".join(missing))
        if problems:
            raise ChangeError("; ".join(problems), code="invalid" if not missing else "unsupported", state="unchanged")
        current = {str(r["tracker"]): "1" if r.get("disabled") else "0" for r in model["rules"]
                   if TRACKER_RE.match(str(r.get("tracker") or ""))}
        php_ops, toggled = [], {}
        for op in ops:
            if op["op"] == "allow":
                php_ops.append({"kind": "add", "rule": self._rule(op)})
                continue
            for ref in op["rules"]:
                tracker = ref["vendor_ref"] if TRACKER_RE.match(ref["vendor_ref"]) else ref["id"]
                toggled.setdefault(tracker, current[tracker])
                php_ops.append({"kind": "set", "tracker": tracker, "disabled": op["op"] == "disable_rules"})
        cid = secrets_module.token_hex(8)
        info: dict[str, Any] = {"v": 1, "cid": cid, "created": [], "toggled": toggled,
                                "adds": sum(1 for op in ops if op["op"] == "allow")}
        if len(json.dumps(info)) + 25 * len(ops) > 4000:
            raise ChangeError("Too many rules in one change for pfSense - split it", code="invalid", state="unchanged")
        # 1. arm the dead-man timer BEFORE writing: it restores this exact file unless confirmed
        armed_at = self.clock()
        arm = await session.run("/bin/sh -s", input=ARM.format(cid=cid, window=self.window, config=CONFIG_PATH,
                                                                   daemon=DAEMON, sha256=SHA256))
        expected = hashlib.sha256(config.encode("utf-8")).hexdigest()
        if not arm.ok or arm.stdout.strip().splitlines()[-1:] != [expected]:
            await self._disarm(session, cid)
            if arm.ok:
                raise ChangeError("config.xml changed while the change was being prepared - re-read and preview again",
                                  code="stale", state="unchanged")
            raise ChangeError("pfSense could not arm the automatic revert - nothing was changed", code="failed",
                              state="unchanged")
        info["deadline"], info["pre"] = armed_at + self.window, expected
        progress["armed"] = True
        # 2. write and reload with the official primitives (refused if config.xml moved since the read)
        try:
            answer = await self._php(session, PHP_APPLY, {
                "ops": php_ops, "expect": expected, "config_path": CONFIG_PATH, "now": int(self.clock()),
                "user": "Atrium", "desc": f"Atrium change {cid}"}, what="change")
        except SshUnavailable:
            raise
        except ConnectorError as exc:  # no answer from the script: it may have written part of the change
            raise await self._undone(session, info, exc.message) from exc
        if not answer.get("ok"):
            await self._disarm(session, cid)
            error = str(answer.get("error") or "")
            raise ChangeError({"stale": "config.xml changed while the change was being prepared - re-read and preview "
                                        "again",
                               "missing": f"rule {display_id(answer.get('tracker'))} is not on the firewall",
                               "unsupported": "this pfSense lacks the PHP configuration functions Atrium needs"}
                              .get(error, f"pfSense refused the change ({display_id(error)})"),
                              code="stale" if error == "stale" else "invalid", state="unchanged")
        created = [str(t) for t in answer.get("created") or [] if TRACKER_RE.match(str(t))]
        if len(created) != sum(1 for op in ops if op["op"] == "allow"):
            raise await self._undone(session, info, "pfSense did not report the new rules")
        info["created"] = created
        notes = [f"dead-man revert armed for {self.window} s (change {cid})"]
        try:
            notes += await self._loaded(session, model, info)
        except ChangeError as exc:
            raise await self._undone(session, info, exc.message) from exc
        result_created, index = [], 0
        for position, op in enumerate(ops):
            if op["op"] == "allow":
                result_created.append({"op": position, "id": created[index], "vendor_ref": created[index]})
                index += 1
        return {"token": json.dumps(info, separators=(",", ":"), sort_keys=True), "rollback_until": info["deadline"],
                "revision": None, "created": result_created,
                "disabled": [t for op in php_ops if op["kind"] == "set" and op["disabled"] for t in [op["tracker"]]],
                "enabled": [t for op in php_ops if op["kind"] == "set" and not op["disabled"] for t in [op["tracker"]]],
                "notes": notes}

    async def _loaded(self, session: Any, model: dict[str, Any], info: dict[str, Any]) -> list[str]:
        """Check that pf runs the new rules (``ridentifier <tracker>`` in ``pfctl -sr``); notes for the result."""
        try:
            shown = await session.run("/sbin/pfctl -sr")
        except SshError:
            return ["pfctl did not answer: the running ruleset was not checked"]
        # UNVERIFIED: pfctl -sr printing "ridentifier <tracker>"; when no enabled rule shows one the check is skipped
        loaded = set(re.findall(r"ridentifier (\d+)", shown.stdout))
        known = [str(r["tracker"]) for r in model.get("rules") or [] if not r.get("disabled")
                 and TRACKER_RE.match(str(r.get("tracker") or "")) and str(r["tracker"]) not in info["toggled"]]
        if not shown.ok or not any(t in loaded for t in known):
            return ["pfctl does not list rule trackers here: the running ruleset was not checked"]
        missing = [t for t in info["created"] if t not in loaded]
        missing += [t for t, previous in info["toggled"].items() if previous == "1" and t not in loaded]
        stale = [t for t, previous in info["toggled"].items() if previous == "0" and t in loaded]
        if missing or stale:
            raise ChangeError("pfSense saved the change but the running ruleset does not show it (the rules did not "
                              "load)", code="failed", state="unknown")
        return ["pf runs the new ruleset"]

    async def _disarm(self, session: Any, cid: str) -> str:
        try:
            answer = await session.run("/bin/sh -s", input=DISARM.format(cid=cid, to="rolled"))
            await session.run("/bin/sh -s", input=CLEANUP.format(cid=cid))
            return answer.stdout.strip()
        except SshError:
            return "unknown"

    async def _undone(self, session: Any, info: dict[str, Any], message: str) -> ChangeError:
        """Undo a change that failed after the timer was armed, at once; the error to raise."""
        try:
            method, _ = await self._undo(session, info)
        except ConnectorError:
            method = None
        if method:
            return ChangeError(message + " - Atrium rolled the change back", code="failed", state="rolled_back")
        return ChangeError(message + f" - the automatic revert restores the previous configuration within "
                           f"{self.window} s", code="failed", state="unknown")

    async def _undo(self, session: Any, info: dict[str, Any]) -> tuple[str | None, list[str]]:
        """Stop the timer, undo the change rule by rule, else put the pre-change config.xml back; (method, notes)."""
        cid, notes = info["cid"], []
        timer = (await self._run(session, "/bin/sh -s", input=DISARM.format(cid=cid, to="rolled"),
                                 what="stop the automatic revert")).stdout.strip()
        if timer == "fired":
            notes.append("the automatic revert had already run")
        ops = [{"kind": "remove", "tracker": t} for t in info.get("created") or []]
        ops += [{"kind": "set", "tracker": t, "disabled": previous == "1"} for t, previous in info["toggled"].items()]
        method, answer = None, {}
        if len(info.get("created") or []) >= int(info.get("adds") or 0):  # else a new rule's tracker is unknown
            try:
                answer = await self._php(session, PHP_APPLY, {"ops": ops, "expect": None, "config_path": CONFIG_PATH,
                                                              "now": int(self.clock()), "user": "Atrium",
                                                              "desc": f"Atrium roll back of change {cid}"},
                                         what="roll back")
            except SshUnavailable:
                raise
            except ConnectorError:
                answer = {}
        model, _ = await self.read_ssh(session)
        if answer.get("ok") and self._state(model, info) == "reverted":
            method = "inverse_ops"
        else:
            notes.append("undoing the change rule by rule failed; restoring the pre-change config.xml")
            restored = await session.run("/bin/sh -s", input=RESTORE_PRE.format(cid=cid, config=CONFIG_PATH))
            model, config = await self.read_ssh(session)
            same = hashlib.sha256(config.encode("utf-8")).hexdigest() == info.get("pre")
            if restored.ok and (same or self._state(model, info) == "reverted"):
                method = "deadman"
        await session.run("/bin/sh -s", input=CLEANUP.format(cid=cid))
        return method, notes

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                answer = (await self._run(session, "/bin/sh -s", input=CONFIRM.format(cid=info["cid"], to="done"),
                                          what="confirm the change")).stdout.strip().splitlines()
                model, _ = await self.read_ssh(session)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        state = self._state(model, info)
        if answer[:1] == ["done"] and state == "applied":
            return {"confirmed": True, "revision": None, "notes": ["the dead-man revert was disarmed"]}
        if answer[:1] == ["fired"] or state == "reverted":
            raise ChangeError("Too late to confirm: pfSense restored the previous configuration", code="failed",
                              state="rolled_back" if state == "reverted" else "unknown")
        raise ChangeError("No armed change with this id on the firewall", code="failed", state="unknown")

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.session() as session:
                method, notes = await self._undo(session, info)
        except ConnectorError as exc:
            raise ChangeError(exc.message + " - if the firewall is unreachable, use console option 15 (Restore Recent "
                              "Configuration)", code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        if method is None:
            raise ChangeError("The change is still on the firewall after undoing it", code="failed", state="applied")
        return {"rolled_back": True, "method": method, "notes": notes}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        if self.rest:
            raise ChangeError("Restoring needs the SSH connection mode", code="unsupported", state="unchanged")
        try:
            parse_config_xml(backup.content)
        except ValueError as exc:
            raise ChangeError(f"The backup is not a pfSense configuration: {exc}", code="invalid",
                              state="unchanged") from exc
        rid = secrets_module.token_hex(8)
        try:
            async with self.session() as session:
                answer = await self._php(session, PHP_RESTORE, {
                    "content": base64.b64encode(backup.content).decode("ascii"),
                    "sha256": hashlib.sha256(backup.content).hexdigest(), "tmp": f"/tmp/atrium-restore-{rid}.xml",
                    "config_path": CONFIG_PATH, "desc": f"Atrium backup {display_id(backup.backup_id)}"}, what="restore")
                if not answer.get("ok"):
                    raise ChangeError(f"pfSense refused the configuration ({display_id(answer.get('error'))})",
                                      code="invalid", state="unchanged")
                await self._run(session, "/etc/rc.filter_configure", what="reload the firewall rules")
                model, _ = await self.read_ssh(session)
        except ChangeError:
            raise
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable" if isinstance(exc, SshUnavailable) else "failed",
                              state="unknown") from exc
        return {"restored": True, "revision": revision(model),
                "notes": ["pfSense restored the configuration (a Config History entry was kept) and reloaded the "
                          "firewall rules; other services apply the restored settings when they are next reloaded or "
                          "after a reboot"]}
