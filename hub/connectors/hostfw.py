"""Linux host firewall over SSH: nftables, ufw or firewalld (``kind`` ``hostfw``).

The hub opens one SSH session per call (``Connector.ssh``). Detection order is firewalld, then ufw, then
raw nftables, then legacy iptables (read-only), per docs/research/fw-hosts-linux-windows.md section 0.3.
Writes go through one root wrapper, ``/usr/local/sbin/atrium-fw``, with the fixed verbs ``snapshot``,
``arm-revert``, ``apply``, ``confirm`` and ``revert-now``. The verb is the only argument. The change body is
JSON on stdin. The wrapper, not the SSH user, is what runs ``nft``, ``ufw``, ``firewall-cmd`` and
``systemd-run``. This connector never stores a sudo password and never passes one: every privileged command
is ``sudo -n``, so a missing sudoers rule fails instead of prompting.

nftables writes touch only ``table inet atrium``. Other tables (filter, Docker, firewalld, iptables-nft) are
read and left alone. ``apply`` does not persist: nftables and firewalld stay runtime-only until
``confirm_change``; the host timer restores the snapshot if confirm never arrives. ufw has no runtime-only
mode: it rewrites ``user.rules`` immediately, and the timer copies the saved files back until confirm.

Sudoers (exact argv; ``NOPASSWD`` so ``sudo -n`` works; no wildcards, no shell, no ``nft -f`` of a user path).
Confirm each path with ``command -v`` on the host before installing — the paths below are the ones this
connector executes.

::

    # Read-only identity. A sudo password is never stored and never sent.
    Cmnd_Alias ATRIUM_FW_READ = \\
        /usr/sbin/nft -j list ruleset, \\
        /usr/sbin/nft list table inet atrium, \\
        /usr/bin/env LC_ALL=C /usr/sbin/ufw status verbose, \\
        /usr/bin/env LC_ALL=C /usr/sbin/ufw status numbered, \\
        /usr/bin/env LC_ALL=C /usr/sbin/ufw version, \\
        /usr/bin/cat /etc/ufw/user.rules, \\
        /usr/bin/cat /etc/ufw/user6.rules, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --state, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --version, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --get-default-zone, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --get-active-zones, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --list-all-zones, \\
        /usr/bin/env LC_ALL=C /usr/bin/firewall-cmd --permanent --list-all-zones, \\
        /usr/bin/cat /var/lib/atrium/fw/disabled.json
    atrium-ro ALL=(root) NOPASSWD: ATRIUM_FW_READ

    # Write identity. Verbs only; the body is stdin. Do not grant a shell or nft -f.
    Cmnd_Alias ATRIUM_FW_WRITE = \\
        /usr/local/sbin/atrium-fw snapshot, \\
        /usr/local/sbin/atrium-fw arm-revert, \\
        /usr/local/sbin/atrium-fw apply, \\
        /usr/local/sbin/atrium-fw confirm, \\
        /usr/local/sbin/atrium-fw revert-now
    atrium-rw ALL=(root) NOPASSWD: ATRIUM_FW_READ, ATRIUM_FW_WRITE

The wrapper's ``arm-revert`` starts ``systemd-run --on-active=<window> --timer-property=AccuracySec=1s``
(AccuracySec defaults to one minute) running ``/usr/local/sbin/atrium-fw revert-now``. ``confirm`` stops
unit ``atrium-fw-revert`` and, for nftables and firewalld, persists. ``revert-now`` restores the spool.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from ..execution.runner import SshError, SshTarget, parse_ssh_connection, posix_command
from .base import HOSTNAME_RE, Connector, ConnectorError, ConnectorField, check
from .netmodel import (
    LEAST_PRIVILEGE_NOTE,
    Backup,
    ChangeError,
    derived_revision,
    find_marker,
    management_guard,
    normalize_record,
    parse_ops,
    untrusted_text,
    validate_write_spec,
)

WRAPPER = "/usr/local/sbin/atrium-fw"
WRAPPER_VERBS = ("snapshot", "arm-revert", "apply", "confirm", "revert-now")
NFT = "/usr/sbin/nft"
UFW = "/usr/sbin/ufw"
FIREWALL_CMD = "/usr/bin/firewall-cmd"
IP = "/usr/sbin/ip"
ENV = "/usr/bin/env"
CAT = "/usr/bin/cat"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
DISABLED_JSON = "/var/lib/atrium/fw/disabled.json"
PENDING_UNIT = "atrium-fw-revert"
# UNVERIFIED: these absolute paths; confirm with command -v (fw-hosts 1.1, 2.1, 3.1).
_SAFE_ARG = re.compile(r"^[A-Za-z0-9_.:/=@+,*-]{1,240}$")
_ZONE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CHANGE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_PASSWORD_KEYS = {"password", "sudo_password", "sudo_pass", "root_password"}
_OS_RELEASE = "/etc/os-release"
_WINDOW = 180

# nft payload field names saddr/daddr are not in the verified JSON examples.
# UNVERIFIED: payload field names saddr and daddr (fw-hosts 1.2).
_NFT_ADDR = {"saddr": "source", "daddr": "destination"}
_NFT_VERDICT = {"accept": "pass", "drop": "block", "reject": "reject"}
_ACTION_VERDICT = {"pass": "accept", "block": "drop", "reject": "reject"}
# UNVERIFIED: firewalld service name to ports, except ssh/tcp/22 (OpenSSH, fw-hosts 4.7).
_FW_SERVICES = {
    "ssh": [("tcp", "22")],
    "http": [("tcp", "80")],
    "https": [("tcp", "443")],
    "dns": [("tcp", "53"), ("udp", "53")],
    "dhcpv6-client": [("udp", "546")],
}
_UFW_ACTION = {"allow": "pass", "deny": "block", "reject": "reject", "limit": "pass"}
_POLICY = {"deny": "block", "drop": "block", "allow": "pass", "accept": "pass", "reject": "reject",
           "disabled": "unknown"}


def _argv(*args: str) -> list[str]:
    bad = [a for a in args if not _SAFE_ARG.fullmatch(a)]
    if bad:
        raise ConnectorError("Refusing a command argument that is not a fixed token")
    return list(args)


def sudo(*args: str) -> list[str]:
    """``sudo -n`` plus a fixed argv. No password, no shell."""
    return _argv("sudo", "-n", *args)


def command(args: list[str]) -> str:
    return posix_command(_argv(*args))


def env_sudo(tool: str, *args: str) -> list[str]:
    """``sudo -n /usr/bin/env LC_ALL=C <tool> ...`` so gettext cannot translate ufw/firewalld text."""
    return sudo(ENV, "LC_ALL=C", tool, *args)


NFT_LIST = sudo(NFT, "-j", "list", "ruleset")
NFT_TABLE = sudo(NFT, "list", "table", "inet", "atrium")
NFT_VERSION = _argv(NFT, "--version")
UFW_STATUS = env_sudo(UFW, "status", "verbose")
UFW_STATUS_PLAIN = _argv(UFW, "status")  # detection without sudo; verbose read still uses sudo
UFW_NUMBERED = env_sudo(UFW, "status", "numbered")
UFW_VERSION = env_sudo(UFW, "version")
UFW_USER = sudo(CAT, "/etc/ufw/user.rules")
UFW_USER6 = sudo(CAT, "/etc/ufw/user6.rules")
FW_STATE = env_sudo(FIREWALL_CMD, "--state")
FW_VERSION = env_sudo(FIREWALL_CMD, "--version")
FW_DEFAULT = env_sudo(FIREWALL_CMD, "--get-default-zone")
FW_ACTIVE = env_sudo(FIREWALL_CMD, "--get-active-zones")
FW_LIST = env_sudo(FIREWALL_CMD, "--list-all-zones")
FW_LIST_PERM = env_sudo(FIREWALL_CMD, "--permanent", "--list-all-zones")
FW_DISABLED = sudo(CAT, DISABLED_JSON)
SUDO_L = sudo("-l")
IP_ADDR = _argv(IP, "-j", "addr", "show")
IP_ROUTE = _argv(IP, "-j", "route", "show")
OS_RELEASE = _argv(CAT, _OS_RELEASE)
HOSTNAME = _argv("hostname")
UNAME = _argv("uname", "-r")
SSH_ENV = _argv("printenv", "SSH_CONNECTION")
FIREWALLD_ACTIVE = _argv(SYSTEMCTL, "is-active", "firewalld")


def wrapper(verb: str) -> list[str]:
    if verb not in WRAPPER_VERBS:
        raise ConnectorError(f"unknown wrapper verb {verb!r}")
    return sudo(WRAPPER, verb)


def _sudo_needs_password(stdout: str, stderr: str) -> bool:
    text = f"{stderr}\n{stdout}".lower()
    return "password is required" in text or "a password is required" in text


def _excerpt(stdout: str, stderr: str, limit: int = 240) -> str:
    text = " ".join((stderr or stdout or "").split())
    return text[:limit]


def _nft_string(text: str) -> str:
    """A double-quoted nft token. Device text is reduced to a safe subset before it is quoted."""
    safe = "".join(ch if ch.isalnum() or ch in " _.:/=+-" else " " for ch in text)
    return '"' + " ".join(safe.split())[:120] + '"'


def _cidrs_of(value: Any) -> list[str]:
    """Addresses and prefixes from one nft JSON 'right' value."""
    out: list[str] = []

    def add(item: Any) -> None:
        if isinstance(item, str):
            if item.startswith("@"):
                return
            text = item if "/" in item else f"{item}/32" if ":" not in item else f"{item}/128"
            try:
                out.append(str(ipaddress.ip_network(text, strict=False)))
            except ValueError:
                return
        elif isinstance(item, dict):
            if "prefix" in item:
                prefix = item["prefix"]
                addr, length = prefix.get("addr"), prefix.get("len")
                try:
                    out.append(str(ipaddress.ip_network(f"{addr}/{length}", strict=False)))
                except ValueError:
                    return
            elif "set" in item:
                for part in item["set"] or []:
                    add(part)
            else:
                add(item.get("addr"))

    if isinstance(value, list):
        for part in value:
            add(part)
    else:
        add(value)
    return list(dict.fromkeys(out))


def _alias_of(value: Any) -> list[str]:
    found: list[str] = []
    if isinstance(value, str) and value.startswith("@"):
        found.append(value[1:])
    elif isinstance(value, dict) and isinstance(value.get("set"), list):
        for part in value["set"]:
            found.extend(_alias_of(part))
    return found


def _ports_of(value: Any) -> str | None:
    numbers: list[str] = []

    def add(item: Any) -> None:
        if isinstance(item, bool) or item is None:
            return
        if isinstance(item, int):
            numbers.append(str(item))
        elif isinstance(item, str) and item.isdigit():
            numbers.append(item)
        elif isinstance(item, dict):
            if "range" in item and isinstance(item["range"], list) and len(item["range"]) == 2:
                numbers.append(f"{item['range'][0]}-{item['range'][1]}")
            elif "set" in item:
                for part in item["set"] or []:
                    add(part)

    add(value)
    if not numbers:
        return None
    return ",".join(numbers)


def _os_release(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def _ip_interfaces(addr_doc: Any, routes: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Interfaces from ``ip -j addr`` plus ``ip -j route``.

    # UNVERIFIED: the ``ifname`` key (fw-hosts 5.1). ``dst`` == ``default`` is also unverified.
    """
    wan: set[str] = set()
    if isinstance(routes, list):
        for route in routes:
            if not isinstance(route, dict):
                continue
            dst = str(route.get("dst") or "")
            if dst in {"default", "0.0.0.0/0", "::/0"} and route.get("dev"):
                wan.add(str(route["dev"]))
    interfaces: list[dict[str, Any]] = []
    addresses: list[str] = []
    if not isinstance(addr_doc, list):
        return interfaces, addresses
    for link in addr_doc:
        if not isinstance(link, dict):
            continue
        name = str(link.get("ifname") or link.get("name") or "")
        if not name or not _ZONE_RE.fullmatch(name):
            continue
        flags = {str(f).upper() for f in link.get("flags") or []}
        vlan = None
        info = (link.get("linkinfo") or {}) if isinstance(link.get("linkinfo"), dict) else {}
        if info.get("info_kind") == "vlan":
            data = info.get("info_data") if isinstance(info.get("info_data"), dict) else {}
            try:
                vlan = int(data.get("id"))
            except (TypeError, ValueError):
                vlan = None
        subnets, locals = [], []
        for item in link.get("addr_info") or []:
            if not isinstance(item, dict) or not item.get("local"):
                continue
            local = str(item["local"]).split("%", 1)[0]
            try:
                ipaddress.ip_address(local)
            except ValueError:
                continue
            prefix = item.get("prefixlen")
            try:
                network = str(ipaddress.ip_network(f"{local}/{prefix}", strict=False))
            except (TypeError, ValueError):
                network = None
            if local not in locals:
                locals.append(local)
            if network and network not in subnets:
                subnets.append(network)
            if local not in addresses:
                addresses.append(local)
        loopback = "LOOPBACK" in flags or name == "lo"
        role = "other" if loopback else "wan" if name in wan else "lan"
        interfaces.append({"id": name, "name": name, "role": role, "subnets": subnets, "addresses": locals,
                           "enabled": "UP" in flags or not flags, **({"vlan": vlan} if vlan else {})})
    return interfaces, addresses


def _endpoint(cidrs: list[str] | None = None, aliases: list[str] | None = None, self_: bool = False,
              any_: bool = False) -> dict[str, Any]:
    if any_ or not (cidrs or aliases or self_):
        return {"any": True}
    out: dict[str, Any] = {}
    if cidrs:
        out["cidrs"] = cidrs
    if aliases:
        out["aliases"] = aliases
    if self_:
        out["self"] = True
    return out


def _service(proto: str, ports: str | None) -> dict[str, Any]:
    item: dict[str, Any] = {"proto": proto}
    if ports:
        item["ports"] = ports
    return item


def parse_nft(document: Any) -> dict[str, Any]:
    """A normalised view of ``nft -j list ruleset``. Rules outside ``inet atrium`` are visible and not writable."""
    items = document.get("nftables") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise ConnectorError("nft did not return a ruleset (expected {\"nftables\": [...]})")
    version = ""
    chains: dict[tuple[str, str, str], dict[str, Any]] = {}
    aliases: list[dict[str, Any]] = []
    rules: list[dict[str, Any]] = []
    nat = False
    order = 0
    for item in items:
        if not isinstance(item, dict):
            continue
        if "metainfo" in item and isinstance(item["metainfo"], dict):
            version = str(item["metainfo"].get("version") or version)
        elif "chain" in item and isinstance(item["chain"], dict):
            chain = item["chain"]
            key = (str(chain.get("family") or ""), str(chain.get("table") or ""), str(chain.get("name") or ""))
            chains[key] = chain
            if str(chain.get("type") or "") == "nat":
                nat = True
        elif "set" in item and isinstance(item["set"], dict):
            aliases.append(_nft_set(item["set"]))
        elif "rule" in item and isinstance(item["rule"], dict):
            order += 1
            parsed = _nft_rule(item["rule"], chains, order)
            if parsed:
                rules.append(parsed)
    policies: dict[str, str] = {}
    notes: list[str] = []
    for hook, key in (("input", "inbound"), ("output", "outbound"), ("forward", "forward")):
        relevant = [c for c in chains.values() if c.get("hook") == hook and c.get("policy")]
        if not relevant:
            continue
        actions = {_POLICY.get(str(c.get("policy")), "unknown") for c in relevant}
        if "block" in actions:
            policies[key] = "block"
        elif "reject" in actions:
            policies[key] = "reject"
        elif "pass" in actions:
            policies[key] = "pass"
        else:
            policies[key] = "unknown"
        if len(relevant) > 1:
            notes.append(f"several base chains share the {hook} hook; a drop in another table is final and an "
                         "Atrium accept cannot override it")
    if nat:
        notes.append("NAT chains were seen and not turned into rules")
    return {"version": version, "rules": rules, "aliases": [a for a in aliases if a], "default_policy": policies,
            "notes": notes, "chains": chains}


def _nft_set(body: dict[str, Any]) -> dict[str, Any] | None:
    name = str(body.get("name") or "")
    if not name:
        return None
    kind = "port" if body.get("type") == "inet_service" else "network"
    cidrs = _cidrs_of(body.get("elem"))
    ports = _ports_of(body.get("elem")) if kind == "port" else None
    alias: dict[str, Any] = {"name": name, "kind": kind, "cidrs": cidrs, "resolved": True}
    if ports:
        alias["ports"] = ports
    return alias


def _nft_rule(body: dict[str, Any], chains: dict[tuple[str, str, str], dict[str, Any]], order: int) -> dict[str, Any] | None:
    family, table, chain = str(body.get("family") or ""), str(body.get("table") or ""), str(body.get("chain") or "")
    handle = body.get("handle")
    if handle is None:
        return None
    ref = f"{family}/{table}/{chain}/{handle}"
    hook = str((chains.get((family, table, chain)) or {}).get("hook") or "")
    source: dict[str, list[str]] = {"cidrs": [], "aliases": []}
    dest: dict[str, list[str]] = {"cidrs": [], "aliases": []}
    ifaces: list[str] = []
    out_ifaces: list[str] = []
    services: list[dict[str, Any]] = []
    action = ""
    log = False
    hits = None
    l4 = ""
    for expr in body.get("expr") or []:
        if not isinstance(expr, dict):
            continue
        if "match" in expr and isinstance(expr["match"], dict):
            match = expr["match"]
            left, right = match.get("left") or {}, match.get("right")
            if isinstance(left, dict) and "meta" in left:
                key = str((left.get("meta") or {}).get("key") or "")
                # UNVERIFIED: JSON shape of a meta iifname/oifname match (fw-hosts 1.2 lists the key only).
                if key == "iifname" and isinstance(right, str) and _ZONE_RE.fullmatch(right):
                    ifaces.append(right)
                elif key == "oifname" and isinstance(right, str) and _ZONE_RE.fullmatch(right):
                    out_ifaces.append(right)
                elif key == "l4proto" and isinstance(right, str):
                    l4 = right
            elif isinstance(left, dict) and "payload" in left:
                payload = left["payload"] if isinstance(left["payload"], dict) else {}
                field = str(payload.get("field") or "")
                proto = str(payload.get("protocol") or "")
                if field in _NFT_ADDR:
                    bucket = source if _NFT_ADDR[field] == "source" else dest
                    bucket["cidrs"].extend(_cidrs_of(right))
                    bucket["aliases"].extend(_alias_of(right))
                elif field == "dport":
                    ports = _ports_of(right)
                    services.append(_service(proto or "tcp", ports))
        elif "accept" in expr or "drop" in expr or "reject" in expr:
            action = next(name for name in ("accept", "drop", "reject") if name in expr)
        elif "log" in expr:
            log = True
        elif "counter" in expr and isinstance(expr["counter"], dict):
            try:
                hits = int(expr["counter"].get("packets") or 0)
            except (TypeError, ValueError):
                hits = None
    comment = str(body.get("comment") or "")
    disabled = "atrium-disabled" in comment
    if not action:
        tagged = re.search(r"atrium-disabled-(pass|block|reject)", comment)
        action = {"pass": "accept", "block": "drop", "reject": "reject"}.get(tagged.group(1) if tagged else "", "")
    if l4 in {"icmp", "icmpv6"} and not services:
        services.append(_service("icmp" if l4 == "icmp" else "icmpv6", None))
    self_dest = hook == "input" and not dest["cidrs"] and not dest["aliases"]
    self_src = hook == "output" and not source["cidrs"] and not source["aliases"]
    direction = {"input": "in", "output": "out"}.get(hook, "in")
    rule: dict[str, Any] = {
        "id": ref, "vendor_ref": ref, "order": order, "enabled": not disabled,
        "action": _NFT_VERDICT.get(action, "pass"), "direction": direction, "log": log,
        "description": untrusted_text(comment),
        "source": _endpoint(source["cidrs"], source["aliases"], self_=self_src),
        "destination": _endpoint(dest["cidrs"], dest["aliases"], self_=self_dest),
        "services": services or None,
    }
    if ifaces:
        rule["interfaces"] = ifaces
    if out_ifaces:
        rule["out_interfaces"] = out_ifaces
    if hits is not None:
        rule["hits"] = hits
    return rule


def _ufw_comment(value: str) -> str:
    # UNVERIFIED: ufw tuple comments may be hex-encoded (fw-hosts 2.2). Decode only even-length hex.
    value = (value or "").strip()
    if re.fullmatch(r"[0-9A-Fa-f]{2,}", value) and len(value) % 2 == 0:
        try:
            raw = bytes.fromhex(value).decode("utf-8")
        except (ValueError, UnicodeError):
            return value
        if raw.isprintable():
            return raw
    return value


def parse_ufw_status(text: str) -> dict[str, str]:
    """Default policy from ``ufw status verbose`` (``Default: %(in)s (incoming), ...``)."""
    policy: dict[str, str] = {}
    for line in (text or "").splitlines():
        match = re.match(r"Default:\s*(\S+)\s*\(incoming\),\s*(\S+)\s*\(outgoing\),\s*(\S+)\s*\(routed\)", line.strip())
        if match:
            policy = {"inbound": _POLICY.get(match.group(1).lower(), "unknown"),
                      "outbound": _POLICY.get(match.group(2).lower(), "unknown"),
                      "forward": _POLICY.get(match.group(3).lower(), "unknown")}
    return policy


def _ufw_endpoint(token: str) -> dict[str, Any]:
    text = token.strip()
    if text.lower() in {"any", "anywhere", "0.0.0.0/0", "::/0"}:
        return {"any": True}
    try:
        return {"cidrs": [str(ipaddress.ip_network(text, strict=False))]}
    except ValueError:
        return {"any": True}


def parse_ufw_tuples(text: str, family: str) -> list[dict[str, Any]]:
    """``### tuple ###`` lines in user.rules / user6.rules. A leading ``#`` (but not the tuple marker) means disabled.

    # UNVERIFIED: commenting the tuple line is how a rule is kept in the file without being loaded.
    """
    rules = []
    index = 0
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        disabled = stripped.startswith("#") and not stripped.startswith("###")
        body = stripped[1:].strip() if disabled else stripped
        if not body.startswith("### tuple ###"):
            continue
        index += 1
        rest = body[len("### tuple ###"):].strip()
        comment = ""
        if " comment=" in rest:
            rest, _, comment = rest.partition(" comment=")
        tokens = rest.split()
        if len(tokens) < 6:
            continue
        action, proto, dport, dst, _sport, src = tokens[:6]
        direction = tokens[6] if len(tokens) > 6 else "in"
        iface = tokens[7] if len(tokens) > 7 else ""
        services = None if proto in {"any", "all"} else [_service(proto, None if dport in {"any", "0"} else dport)]
        rule: dict[str, Any] = {
            "id": f"ufw:{family}:{index}", "vendor_ref": f"ufw:{family}:{index}", "order": index,
            "enabled": not disabled, "action": _UFW_ACTION.get(action, "pass"),
            "direction": {"in": "in", "out": "out"}.get(direction, "any"),
            "source": _ufw_endpoint(src), "destination": _ufw_endpoint(dst), "services": services,
            "description": untrusted_text(_ufw_comment(comment)), "log": action == "limit",
        }
        if iface and _ZONE_RE.fullmatch(iface):
            rule["interfaces"] = [iface]
        rules.append(rule)
    return rules


def parse_ufw_numbered(text: str) -> list[dict[str, Any]]:
    """``ufw status numbered``. Used when the tuple files have no UI rules."""
    rules = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line.startswith("["):
            continue
        comment = ""
        if "#" in line:
            line, _, comment = line.partition("#")
        match = re.match(r"^\[\s*(\d+)\]\s+(.*)$", line.strip())
        if not match:
            continue
        number, rest = match.group(1), match.group(2)
        v6 = "(v6)" in rest
        rest = rest.replace("(v6)", " ")
        found = re.search(r"\b(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\b", rest)
        if not found:
            continue
        to_part, from_part = rest[:found.start()].strip(), rest[found.end():].strip()
        proto, ports = "tcp", None
        port_match = re.match(r"^(\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*)/(tcp|udp)$", to_part.split()[0] if to_part else "")
        if port_match:
            ports, proto = port_match.group(1), port_match.group(2)
        services = [_service(proto, ports)] if ports else None
        family = "6" if v6 else "4"
        rules.append({
            "id": f"ufw:{family}:{number}", "vendor_ref": f"ufw:{family}:{number}", "order": int(number),
            "enabled": True, "action": _UFW_ACTION.get(found.group(1).lower(), "pass"),
            "direction": {"IN": "in", "OUT": "out"}.get(found.group(2), "any"),
            "source": _ufw_endpoint(from_part.split()[0] if from_part else "any"),
            "destination": {"any": True} if not port_match else {"any": True},
            "services": services, "description": untrusted_text(comment.strip()),
        })
    return rules


def parse_firewalld_zones(text: str) -> list[dict[str, Any]]:
    """``firewall-cmd --list-all-zones`` / ``--info-zone`` text. Rich rules and services become rules."""
    zones: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section = ""
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        if raw[:1].isspace():
            if current is None:
                continue
            line = raw.strip()
            if line.startswith("rule "):
                current["rich"].append(line)
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                section = key.strip().lower()
                current[section] = value.split()
            elif section:
                current.setdefault(section, []).append(line)
            continue
        name = raw.strip().split()[0]
        current = {"name": name, "active": "active" in raw, "rich": []}
        zones.append(current)
        section = ""
    return zones


def _rich_rule(zone: str, line: str, order: int) -> dict[str, Any] | None:
    def grab(pattern: str) -> str | None:
        found = re.search(pattern, line)
        return found.group(1) if found else None

    action = None
    for name in ("accept", "reject", "drop", "mark"):
        if re.search(rf"\b{name}\s*$", line):
            action = name
            break
    if action is None:
        return None
    source = grab(r'source\s+address="([^"]+)"')
    dest = grab(r'destination\s+address="([^"]+)"')
    port = grab(r'port\s+port="([^"]+)"')
    proto = grab(r'protocol="([^"]+)"') or grab(r'protocol\s+value="([^"]+)"')
    prefix = grab(r'log\s+prefix="([^"]*)"') or ""
    # UNVERIFIED: the ``port port= protocol=`` rich-rule element (fw-hosts 3.3).
    services = None
    if proto in {"tcp", "udp", "icmp"}:
        services = [_service(proto, port if proto != "icmp" else None)]
    disabled = "atrium-disabled" in prefix
    mapped = {"accept": "pass", "reject": "reject", "drop": "block", "mark": "pass"}[action]
    rule: dict[str, Any] = {
        "id": f"fw:{zone}:{order}", "vendor_ref": f"fw:{zone}:{order}", "order": order, "enabled": not disabled,
        "action": mapped, "direction": "in", "source_zones": [zone], "log": bool(prefix),
        "description": untrusted_text(prefix),
        "source": _endpoint(_cidrs_of(source) if source else None, any_=not source),
        "destination": _endpoint(_cidrs_of(dest) if dest else None, self_=not dest),
        "services": services,
    }
    rule["_rich"] = line  # stripped by _public_rule before the record is returned
    return rule


def firewalld_rules(zones: list[dict[str, Any]], disabled: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, str]]:
    """Rules, zone records and a default-policy guess from parsed zones plus the disabled spool."""
    out_zones, rules = [], []
    order = 0
    default_zone = ""
    targets: dict[str, str] = {}
    for zone in zones:
        name = str(zone.get("name") or "")
        if not name:
            continue
        if zone.get("active") and not default_zone:
            default_zone = name
        target = (zone.get("target") or ["default"])[0] if isinstance(zone.get("target"), list) else "default"
        targets[name] = target
        out_zones.append({"id": name, "name": name, "interfaces": list(zone.get("interfaces") or []),
                          "description": f"target {target}"})
        for service in zone.get("services") or []:
            for proto, ports in _FW_SERVICES.get(service, []):
                order += 1
                rules.append({
                    "id": f"fw:{name}:svc:{service}:{proto}", "vendor_ref": f"fw:{name}:svc:{service}:{proto}",
                    "order": order, "enabled": True, "action": "pass", "direction": "in", "source_zones": [name],
                    "source": {"any": True}, "destination": {"self": True},
                    "services": [_service(proto, ports)], "description": f"service {service}",
                })
        for port in zone.get("ports") or []:
            if "/" not in str(port):
                continue
            number, _, proto = str(port).partition("/")
            order += 1
            rules.append({
                "id": f"fw:{name}:port:{order}", "vendor_ref": f"fw:{name}:port:{order}", "order": order,
                "enabled": True, "action": "pass", "direction": "in", "source_zones": [name],
                "source": {"any": True}, "destination": {"self": True},
                "services": [_service(proto or "tcp", number)], "description": "",
            })
        for line in zone.get("rich") or []:
            order += 1
            parsed = _rich_rule(name, line, order)
            if parsed:
                # Positional numbers shift when a rich rule is removed, so the id is a hash of the rule text.
                digest = hashlib.sha256(f"{name}\n{line}".encode()).hexdigest()[:12]
                parsed["id"] = f"fw:{name}:rich:{digest}"
                parsed["vendor_ref"] = parsed["id"]
                rules.append(parsed)
    for item in disabled:
        if isinstance(item, dict) and item.get("id"):
            rules.append({**item, "enabled": False})
    # UNVERIFIED: firewalld's builtin zone target "default" means REJECT.
    policy = _POLICY.get(str(targets.get(default_zone, "default")).lower(), "reject")
    return rules, out_zones, {"inbound": policy}


def _op_group(description: str) -> str | None:
    found = re.search(r"\bop(\d+)\b", description or "")
    return found.group(1) if found else None


def _union_endpoint(keep: dict[str, Any], extra: dict[str, Any], field: str) -> None:
    left, right = keep.get(field) or {}, extra.get(field) or {}
    if left.get("any") or right.get("any"):
        keep[field] = {"any": True}
        return
    cidrs = list(dict.fromkeys([*(left.get("cidrs") or []), *(right.get("cidrs") or [])]))
    aliases = list(dict.fromkeys([*(left.get("aliases") or []), *(right.get("aliases") or [])]))
    endpoint: dict[str, Any] = {}
    if cidrs:
        endpoint["cidrs"] = cidrs
    if aliases:
        endpoint["aliases"] = aliases
    if left.get("self") or right.get("self"):
        endpoint["self"] = True
    keep[field] = endpoint or {"any": True}


def merge_by_marker(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Slices of one allow (same marker and ``opN`` tag, or the same endpoints) become one rule.

    A change can carry several allows with one marker. The ``opN`` tag this connector writes keeps them apart
    while still folding per-port and per-address slices of a single allow back into the rule the hub asked for.
    """
    merged: list[dict[str, Any]] = []
    index: dict[tuple[Any, ...], int] = {}
    for rule in rules:
        public = {k: v for k, v in rule.items() if not str(k).startswith("_")}
        mid = find_marker(public.get("description"))
        group = _op_group(str(public.get("description") or ""))
        if not mid:
            key = None
        elif group is not None:
            key = ("op", mid, group)
        else:
            key = ("ep", mid, json.dumps(public.get("source"), sort_keys=True),
                   json.dumps(public.get("destination"), sort_keys=True))
        if key is None or key not in index:
            if mid and group is not None:
                public["id"] = f"atrium:{mid}:{group}"
            elif mid:
                public["id"] = f"atrium:{mid}"
            if key is not None:
                index[key] = len(merged)
            merged.append(public)
            continue
        keep = merged[index[key]]
        _union_endpoint(keep, public, "source")
        _union_endpoint(keep, public, "destination")
        services = list(keep.get("services") or [])
        for service in public.get("services") or []:
            if service not in services:
                services.append(service)
        keep["services"] = services or None
        if public["vendor_ref"] not in str(keep["vendor_ref"]).split(","):
            keep["vendor_ref"] = keep["vendor_ref"] + "," + public["vendor_ref"]
        keep["enabled"] = bool(keep.get("enabled", True) or public.get("enabled", True))
        keep["log"] = bool(keep.get("log") or public.get("log"))
    return merged


def _family_cidrs(cidrs: list[str]) -> tuple[list[str], list[str]]:
    v4, v6 = [], []
    for cidr in cidrs:
        (v6 if ":" in cidr else v4).append(cidr)
    return v4, v6


def _nft_addr_match(keyword: str, cidrs: list[str]) -> str:
    if len(cidrs) == 1:
        return f"{keyword} {cidrs[0]}"
    inner = ", ".join(cidrs)
    return f"{keyword} {{ {inner} }}"


def _nft_port_match(proto: str, ports: str | None) -> str:
    if proto == "icmp":
        # UNVERIFIED: ``meta l4proto icmp`` / ``icmpv6`` as the icmp service match.
        return "meta l4proto icmp"
    if not ports:
        raise ChangeError(f"{proto} needs ports", code="invalid", state="unchanged")
    if "," in ports:
        return f"{proto} dport {{ {', '.join(ports.split(','))} }}"
    return f"{proto} dport {ports}"


def _mark_text(op: dict[str, Any], index: int) -> str:
    """Marker plus an op index so slices of one allow can be folded back together."""
    return f"{op['marker']} op{index} {op.get('description') or ''}".strip()


def render_nft_allow(op: dict[str, Any], ifaces: set[str], index: int) -> list[str]:
    """One ``insert rule inet atrium`` line per service slice. No other table is named."""
    if not _ZONE_RE.fullmatch(op["source"]["zone"]) or not _ZONE_RE.fullmatch(op["destination"]["zone"]):
        raise ChangeError("a zone id must be letters, digits and _.:- so it can be named in a rule",
                          code="invalid", state="unchanged")
    comment = _nft_string(_mark_text(op, index))
    prefix = _nft_string(op["marker"] + " ")
    lines = []
    v4s, v6s = _family_cidrs(op["source"]["cidrs"])
    v4d, v6d = _family_cidrs(op["destination"]["cidrs"])
    pairs = [("ip", v4s, v4d, "icmp"), ("ip6", v6s, v6d, "icmpv6")]
    iif = f"iifname {_nft_string(op['source']['zone'])} " if op["source"]["zone"] in ifaces else ""
    for keyword, sources, dests, icmp_name in pairs:
        if not sources or not dests:
            continue
        for service in op["services"]:
            proto = icmp_name if service["proto"] == "icmp" and keyword == "ip6" else service["proto"]
            port = _nft_port_match("icmp" if service["proto"] == "icmp" else service["proto"], service.get("ports"))
            if service["proto"] == "icmp" and keyword == "ip6":
                port = "meta l4proto icmpv6"
            log = f"log prefix {prefix} " if op.get("log", True) else ""
            lines.append(
                f"insert rule inet atrium input {iif}{_nft_addr_match(keyword + ' saddr', sources)} "
                f"{_nft_addr_match(keyword + ' daddr', dests)} {port} counter {log}accept comment {comment}"
            )
    if not lines:
        raise ChangeError("the allow has no address family in common on both sides", code="invalid", state="unchanged")
    return lines


def render_nft_replace(rule: dict[str, Any], *, enable: bool) -> str:
    """Replace one atrium handle in place. Disable keeps the matches and drops the verdict."""
    ref = str(rule.get("vendor_ref") or "")
    match = re.fullmatch(r"inet/atrium/([A-Za-z0-9_-]+)/(\d+)", ref)
    if not match:
        raise ChangeError("only rules in table inet atrium can be changed; other tables are left alone",
                          code="invalid", state="unchanged")
    chain, handle = match.group(1), match.group(2)
    action = rule.get("action") or "pass"
    parts = [f"replace rule inet atrium {chain} handle {handle}"]
    ifaces = rule.get("interfaces") or []
    if ifaces and _ZONE_RE.fullmatch(str(ifaces[0])):
        parts.append(f"iifname {_nft_string(str(ifaces[0]))}")
    for keyword, side, field in (("ip", "source", "saddr"), ("ip", "destination", "daddr")):
        cidrs = [c for c in (rule.get(side) or {}).get("cidrs") or [] if ":" not in c]
        v6 = [c for c in (rule.get(side) or {}).get("cidrs") or [] if ":" in c]
        token = "ip6" if v6 and not cidrs else keyword
        use = v6 or cidrs
        if use:
            parts.append(_nft_addr_match(f"{token} {field}", use))
    services = rule.get("services") or []
    if services:
        service = services[0]
        proto = service.get("proto") or "tcp"
        if proto == "icmpv6":
            parts.append("meta l4proto icmpv6")
        else:
            parts.append(_nft_port_match(proto, service.get("ports")))
    parts.append("counter")
    if enable:
        parts.append(_ACTION_VERDICT.get(action, "accept"))
    base = untrusted_text(rule.get("description") or "")
    base = re.sub(r"\s*atrium-disabled-(?:pass|block|reject)\s*", " ", base).strip()
    comment = base if enable else f"{base} atrium-disabled-{action}".strip()
    parts.append(f"comment {_nft_string(comment)}")
    return " ".join(parts)


def _chain_header() -> list[str]:
    return ["add table inet atrium",
            "add chain inet atrium input { type filter hook input priority 0 ; policy accept ; }"]


def _timer_argv(window: int) -> list[str]:
    return [SYSTEMD_RUN, f"--unit={PENDING_UNIT}", f"--on-active={window}", "--timer-property=AccuracySec=1s",
            WRAPPER, "revert-now"]


def _safe_zone(op: dict[str, Any]) -> None:
    for side in ("source", "destination"):
        if op["op"] == "allow" and not _ZONE_RE.fullmatch(op[side]["zone"]):
            raise ChangeError("a zone id must be letters, digits and _.:-", code="invalid", state="unchanged")


class HostFirewallConnector(Connector):
    kind = "hostfw"
    title = "Linux host firewall"
    description = ("nftables, ufw or firewalld on a Linux host, over SSH. Reads the running firewall. "
                   "Changes go through sudo -n and /usr/local/sbin/atrium-fw (fixed verbs, no sudo password) "
                   "and revert on the host unless confirmed.")
    fields = [
        ConnectorField(name="host", label="Host", required=True, placeholder="10.0.99.5"),
        ConnectorField(name="port", label="SSH port", kind="number", default=22),
        ConnectorField(name="username", label="SSH user", required=True, placeholder="atrium-rw"),
        ConnectorField(name="private_key", label="Private key", kind="secret", required=True,
                       help="OpenSSH private key. A key passphrase is not a sudo password."),
        ConnectorField(name="passphrase", label="Key passphrase", kind="secret",
                       help="Passphrase for the private key only. A sudo password is never accepted."),
        ConnectorField(name="host_key", label="Pinned host key", placeholder="ssh-ed25519 AAAA..."),
        ConnectorField(name="strict_host_keys", label="Strict host key checking", kind="bool", default=True),
        ConnectorField(name="window_s", label="Revert window (seconds)", kind="number", default=_WINDOW),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False,
                       help="When on, device changes are not offered even if sudo allows the wrapper."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        host = str(config.get("host") or "").strip()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not HOSTNAME_RE.match(host):
                raise ConnectorError("The host must be an IP address or a hostname")
        user = str(config.get("username") or "").strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,31}", user):
            raise ConnectorError("The SSH user is 1-32 letters, digits, '.', '_' and '-'")
        try:
            port = int(config.get("port") or 22)
            window = int(config.get("window_s") or _WINDOW)
        except (TypeError, ValueError) as exc:
            raise ConnectorError("The SSH port and the revert window must be numbers") from exc
        if not 1 <= port <= 65535:
            raise ConnectorError("The SSH port is 1-65535")
        if not 10 <= window <= 3600:
            raise ConnectorError("The revert window is 10-3600 seconds")
        if config.get("password") or config.get("sudo_password"):
            raise ConnectorError("A sudo password is not accepted. Use NOPASSWD sudoers and sudo -n")
        pinned = str(config.get("host_key") or "").strip()
        if pinned and not re.match(r"^ssh-(ed25519|rsa|ecdsa)(\s+\S+){1,2}$", pinned):
            raise ConnectorError("The pinned host key must look like 'ssh-ed25519 AAAA...'")
        return {**config, "host": host, "username": user, "port": port, "window_s": window,
                "host_key": pinned or None}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("host firewall", "hostfw", "nftables", "ufw", "firewalld", "linux firewall"))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        return validate_write_spec({**self.network_write, "window_s": int(self.config.get("window_s") or _WINDOW)})

    def _refuse_password(self) -> None:
        found = [key for key in self.secrets if key.lower() in _PASSWORD_KEYS]
        if found or self.config.get("password") or self.config.get("sudo_password"):
            raise ConnectorError("This connector never accepts a sudo or account password. "
                                 "Use an SSH key and NOPASSWD sudoers; calls use sudo -n")

    def _target(self) -> SshTarget:
        self._refuse_password()
        key = self.secrets.get("private_key")
        if not key:
            raise ConnectorError("The SSH private key is missing")
        host = str(self.config.get("host") or "").strip()
        user = str(self.config.get("username") or "").strip()
        if not host or not user:
            raise ConnectorError("Host and SSH user are required")
        return SshTarget(host=host, username=user, port=int(self.config.get("port") or 22), private_key=key,
                         passphrase=self.secrets.get("passphrase"),
                         strict_host_keys=bool(self.config.get("strict_host_keys", True)),
                         host_key=(self.config.get("host_key") or None))

    @asynccontextmanager
    async def _connect(self) -> AsyncIterator[Any]:
        target = self._target()
        try:
            async with self.ssh(target) as session:
                yield session
        except SshError as exc:
            raise ConnectorError(str(exc)) from exc

    async def _run(self, session: Any, args: list[str], *, stdin: str | None = None, check: bool = True) -> Any:
        result = await session.run(command(args), input=stdin)
        if result.truncated:
            raise ConnectorError("The command output was truncated; refusing to parse a partial result")
        if check and not result.ok:
            if _sudo_needs_password(result.stdout, result.stderr):
                raise ConnectorError("sudo -n would prompt for a password, and this connector will not send one")
            raise ConnectorError(f"{args[-1]} failed ({result.exit_status}): {_excerpt(result.stdout, result.stderr)}")
        return result

    async def _wrapper(self, session: Any, verb: str, payload: dict[str, Any], *, state: str) -> dict[str, Any]:
        body = json.dumps({"verb": verb, **payload}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        try:
            result = await self._run(session, wrapper(verb), stdin=body, check=False)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="failed", state=state) from exc
        if _sudo_needs_password(result.stdout, result.stderr):
            raise ChangeError("sudo -n would prompt for a password; none is stored", code="unsupported", state=state)
        if result.truncated or not result.ok:
            raise ChangeError(f"atrium-fw {verb} failed ({result.exit_status}): {_excerpt(result.stdout, result.stderr)}",
                              code="failed", state=state)
        try:
            data = json.loads(result.stdout or "{}")
        except ValueError as exc:
            raise ChangeError(f"atrium-fw {verb} did not return JSON", code="failed", state=state) from exc
        if not isinstance(data, dict) or not data.get("ok"):
            message = data.get("error") if isinstance(data, dict) else ""
            raise ChangeError(str(message or f"atrium-fw {verb} refused the change"), code="failed", state=state)
        return data

    async def _text(self, session: Any, args: list[str], *, check: bool = False) -> tuple[int, str, str]:
        result = await self._run(session, args, check=False)
        if check and not result.ok and not _sudo_needs_password(result.stdout, result.stderr):
            raise ConnectorError(f"{args[-1]} failed ({result.exit_status}): {_excerpt(result.stdout, result.stderr)}")
        return result.exit_status, result.stdout, result.stderr

    async def _probe(self, session: Any) -> dict[str, Any]:
        """Manager, OS and the hub's address as the host sees them. No wrapper calls."""
        _, ssh_text, _ = await self._text(session, SSH_ENV)
        _, release, _ = await self._text(session, OS_RELEASE)
        _, kernel, _ = await self._text(session, UNAME)
        status, hostname, _ = await self._text(session, HOSTNAME)
        _, active, _ = await self._text(session, FIREWALLD_ACTIVE)
        os_info = _os_release(release)
        facts: dict[str, Any] = {
            "os": os_info, "kernel": kernel.strip(),
            "hostname": hostname.strip() if status == 0 else "",
            "ssh": parse_ssh_connection(ssh_text.strip()),
            "sudo_password": False, "version": "",
        }
        if active.strip() == "active":
            facts["manager"] = "firewalld"
            _code, version, err = await self._text(session, FW_VERSION)
            facts["sudo_password"] = _sudo_needs_password(version, err)
            facts["version"] = version.strip()
            return facts
        # ufw before nft: a ufw host also has the nft binary. A sudo password on the probe must not
        # make us call that host "nftables".
        plain_code, plain_text, _plain_err = await self._text(session, UFW_STATUS_PLAIN)
        plain_first = next((line.strip() for line in plain_text.splitlines() if line.strip()), "")
        if plain_code == 0 and plain_first == "Status: active":
            return await self._ufw_facts(session, facts, plain_text)
        if plain_code != 0 and plain_first != "Status: inactive":
            code, ufw_text, ufw_err = await self._text(session, UFW_STATUS)
            first = next((line.strip() for line in ufw_text.splitlines() if line.strip()), "")
            if _sudo_needs_password(ufw_text, ufw_err):
                facts["sudo_password"] = True
                facts["manager"] = "unknown"
                return facts
            if code == 0 and first == "Status: active":
                return await self._ufw_facts(session, facts, ufw_text)
        code, nft_ver, _nft_err = await self._text(session, NFT_VERSION)
        if code == 0 and nft_ver.strip():
            facts["manager"] = "nftables"
            facts["version"] = nft_ver.strip().splitlines()[0]
            return facts
        facts["manager"] = "iptables"
        return facts

    async def _ufw_facts(self, session: Any, facts: dict[str, Any], status_text: str) -> dict[str, Any]:
        facts["manager"] = "ufw"
        _code, version, err = await self._text(session, UFW_VERSION)
        facts["sudo_password"] = facts.get("sudo_password") or _sudo_needs_password(version, err)
        facts["version"] = version.strip().splitlines()[0] if version.strip() else ""
        if "Default:" in status_text and status_text.lstrip().startswith("Status:"):
            facts["ufw_status"] = status_text
        return facts

    async def _privileges(self, session: Any) -> dict[str, Any]:
        # UNVERIFIED: sudo -n -l exits 0 without a prompt when the account has any NOPASSWD command.
        result = await self._run(session, SUDO_L, check=False)
        if _sudo_needs_password(result.stdout, result.stderr):
            return {"sudo": False, "write": False,
                    "detail": "sudo -n would prompt for a password; none is stored, so the host cannot be read or changed"}
        if not result.ok:
            return {"sudo": False, "write": False,
                    "detail": "sudo -n -l failed: " + _excerpt(result.stdout, result.stderr)}
        write = WRAPPER in result.stdout
        return {"sudo": True, "write": write, "listing": result.stdout,
                "detail": LEAST_PRIVILEGE_NOTE if write else
                "sudo can run the read commands but not /usr/local/sbin/atrium-fw; device changes are unavailable"}

    async def _load(self, session: Any, facts: dict[str, Any]) -> dict[str, Any]:
        manager = facts.get("manager") or "iptables"
        status, addr_text, _ = await self._text(session, IP_ADDR)
        _, route_text, _ = await self._text(session, IP_ROUTE)
        interfaces, addresses = [], []
        if status == 0 and addr_text.strip():
            try:
                interfaces, addresses = _ip_interfaces(json.loads(addr_text), json.loads(route_text or "[]"))
            except ValueError:
                interfaces, addresses = [], []
        ssh = facts.get("ssh") or {}
        server = ssh.get("server_ip")
        if server and server not in addresses:
            addresses.append(server)
        extra: dict[str, Any] = {"interfaces": interfaces, "addresses": addresses, "raw": {}, "nft_table_text": "",
                                 "user_rules": "", "user6_rules": "", "disabled": [], "zones_runtime": "",
                                 "zones_permanent": "", "ufw_status": facts.get("ufw_status") or ""}
        notes = list(facts.get("notes") or [])
        if manager == "iptables":
            record = self._assemble(facts, [], [], {}, notes + [
                "legacy iptables only: this connector does not write iptables rules"])
            return {"record": record, **extra}
        if manager == "unknown":
            raise ConnectorError("sudo -n would prompt for a password, so the firewall manager could not be read")
        if manager == "nftables":
            code, text, err = await self._text(session, NFT_LIST, check=True)
            if _sudo_needs_password(text, err):
                raise ConnectorError("sudo -n would prompt for a password; the nftables ruleset was not read")
            try:
                parsed = parse_nft(json.loads(text))
            except ValueError as exc:
                raise ConnectorError("nft -j list ruleset did not return JSON") from exc
            _, table_text, _ = await self._text(session, NFT_TABLE)
            if "flush ruleset" in table_text:
                raise ConnectorError("nft list table inet atrium included flush ruleset; refusing to keep it")
            extra["nft_table_text"] = table_text
            extra["raw"] = {rule["vendor_ref"]: rule for rule in parsed["rules"]}
            rules = merge_by_marker(parsed["rules"])
            if not facts.get("version"):
                facts["version"] = parsed.get("version") or ""
            notes = notes + parsed["notes"] + [
                "writes replace nothing outside table inet atrium"]
            record = self._assemble(facts, rules, parsed["aliases"], parsed["default_policy"], notes, interfaces, addresses)
            return {"record": record, **extra}
        if manager == "ufw":
            if "ufw_status" not in facts or not facts.get("ufw_status"):
                _, status_text, err = await self._text(session, UFW_STATUS, check=True)
                if _sudo_needs_password(status_text, err):
                    raise ConnectorError("sudo -n would prompt for a password; ufw status was not read")
                extra["ufw_status"] = status_text
            _, user, _ = await self._text(session, UFW_USER, check=True)
            _, user6, _ = await self._text(session, UFW_USER6)
            _, numbered, _ = await self._text(session, UFW_NUMBERED)
            extra["user_rules"], extra["user6_rules"] = user, user6
            tuples = parse_ufw_tuples(user, "4") + parse_ufw_tuples(user6, "6")
            rules = tuples or parse_ufw_numbered(numbered)
            extra["raw"] = {rule["vendor_ref"]: rule for rule in rules}
            notes = notes + ["ufw persists every change immediately; the revert timer restores the saved user.rules",
                             "Docker published ports bypass ufw"]
            record = self._assemble(facts, merge_by_marker(rules), [], parse_ufw_status(extra["ufw_status"]), notes,
                                    interfaces, addresses)
            return {"record": record, **extra}
        _, state, err = await self._text(session, FW_STATE)
        if _sudo_needs_password(state, err):
            raise ConnectorError("sudo -n would prompt for a password; firewalld was not read")
        _, zones_text, _ = await self._text(session, FW_LIST, check=True)
        _, permanent, _ = await self._text(session, FW_LIST_PERM)
        _, default_zone, _ = await self._text(session, FW_DEFAULT)
        _, disabled_text, _ = await self._text(session, FW_DISABLED)
        extra["zones_runtime"], extra["zones_permanent"] = zones_text, permanent
        disabled: list[Any] = []
        if disabled_text.strip():
            try:
                loaded = json.loads(disabled_text)
                disabled = loaded if isinstance(loaded, list) else []
            except ValueError:
                disabled = []
        extra["disabled"] = disabled
        zones = parse_firewalld_zones(zones_text)
        rules, zone_recs, policy = firewalld_rules(zones, [item for item in disabled if isinstance(item, dict)])
        extra["raw"] = {rule["vendor_ref"]: rule for rule in rules}
        if zones_text.strip() != permanent.strip() and permanent.strip():
            notes.append("firewalld runtime and permanent configuration differ")
        if state.strip() and state.strip() != "running":
            notes.append(f"firewall-cmd --state returned {untrusted_text(state, 40)}")
        if default_zone.strip():
            notes.append(f"default zone {untrusted_text(default_zone, 60)}")
        notes.append("firewalld rich rules have no disabled flag; disabled rules are kept in "
                     "/var/lib/atrium/fw/disabled.json and removed from the runtime")
        # zone records from firewalld win; ip interfaces still fill addresses
        record = self._assemble(facts, merge_by_marker(rules), [], policy, notes, interfaces, addresses, zone_recs)
        return {"record": record, **extra}

    def _assemble(self, facts: dict[str, Any], rules: list[dict[str, Any]], aliases: list[dict[str, Any]],
                  policy: dict[str, str], notes: list[str], interfaces: list[dict[str, Any]] | None = None,
                  addresses: list[str] | None = None, zones: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        interfaces = interfaces if interfaces is not None else []
        addresses = addresses if addresses is not None else []
        os_info = facts.get("os") or {}
        hostname = facts.get("hostname") or str(self.config.get("host") or "host")
        manager = facts.get("manager") or "iptables"
        public_rules = []
        for rule in rules:
            public_rules.append({k: v for k, v in rule.items() if not str(k).startswith("_")})
        body_rules = [{k: v for k, v in rule.items() if k != "hits"} for rule in public_rules]
        revision = derived_revision(manager, body_rules, interfaces, zones or [], aliases, policy, hostname)
        ssh = facts.get("ssh") or {}
        return {
            "external_id": hostname, "revision": revision, "read_at": time.time(), "kind": "host",
            "device": {"vendor": os_info.get("ID") or "linux", "model": manager,
                       "version": facts.get("version") or os_info.get("VERSION_ID") or "",
                       "hostname": hostname, "management_address": ssh.get("server_ip") or "", "serial": ""},
            "interfaces": interfaces, "zones": zones or [], "aliases": aliases, "self_addresses": addresses,
            "rules": public_rules, "default_policy": policy, "nat_evaluated": False,
            "notes": [untrusted_text(note, 300) for note in notes if note][:50],
        }

    def _zone_ids(self, record: dict[str, Any]) -> set[str]:
        return {z["id"] for z in record.get("zones") or []} | {i["id"] for i in record.get("interfaces") or []}

    def _problems(self, record: dict[str, Any], ops: list[dict[str, Any]], loaded: dict[str, Any]) -> list[str]:
        problems = list(management_guard(record, ops))
        zones = self._zone_ids(record)
        fw_zones = {z["id"] for z in record.get("zones") or []}
        manager = record.get("device", {}).get("model")
        raw = loaded.get("raw") or {}
        for op in ops:
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    if not _ZONE_RE.fullmatch(zone):
                        problems.append(f"zone {untrusted_text(zone, 40)!r} cannot be named safely in a rule")
                    elif manager == "firewalld" and fw_zones and zone not in fw_zones:
                        problems.append(f"the device has no firewalld zone '{zone}'")
                    elif manager != "firewalld" and zones and zone not in zones:
                        problems.append(f"the device has no interface or zone '{zone}'")
                continue
            for ref in op["rules"]:
                vendor = ref.get("vendor_ref") or ref.get("id") or ""
                parts = [part for part in str(vendor).split(",") if part]
                for part in parts:
                    rule = raw.get(part) or next((item for item in raw.values()
                                                  if item.get("id") == ref.get("id") or item.get("vendor_ref") == part), None)
                    if manager == "nftables" and not part.startswith("inet/atrium/"):
                        problems.append(f"rule {part} is not in table inet atrium; other tables are not rewritten")
                    elif rule is None and manager == "nftables":
                        problems.append(f"rule {part} is not on the device (re-read it first)")
        return list(dict.fromkeys(problems))

    def _change_id(self, ops: list[dict[str, Any]]) -> str:
        for op in ops:
            if op["op"] == "allow":
                found = find_marker(op["marker"])
                if found:
                    return found
        digest = derived_revision(ops)[2:]
        return "dis-" + digest[:16]

    def _render(self, loaded: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
        record = loaded["record"]
        manager = record["device"]["model"]
        ifaces = {i["id"] for i in record.get("interfaces") or []}
        has_chain = bool((loaded.get("nft_table_text") or "").strip()) or any(
            str(ref).startswith("inet/atrium/") for ref in (loaded.get("raw") or {}))
        if manager == "nftables":
            lines: list[str] = []
            if not has_chain:
                lines.extend(_chain_header())
            for index, op in enumerate(ops):
                if op["op"] == "allow":
                    lines.extend(render_nft_allow(op, ifaces, index))
                else:
                    enable = op["op"] == "enable_rules"
                    for ref in op["rules"]:
                        for part in str(ref.get("vendor_ref") or ref["id"]).split(","):
                            raw = (loaded.get("raw") or {}).get(part)
                            if raw is None:
                                raise ChangeError(f"rule {part} is not on the device", code="invalid", state="unchanged")
                            lines.append(render_nft_replace(raw, enable=enable))
            script = "\n".join(lines) + "\n"
            if "flush ruleset" in script or "table ip " in script or "table inet filter" in script:
                raise ChangeError("the rendered ruleset touched a table other than inet atrium", code="failed",
                                  state="unchanged")
            return {"script": script, "commands": []}
        if manager == "ufw":
            commands: list[list[str]] = []
            user, user6 = loaded.get("user_rules") or "", loaded.get("user6_rules") or ""
            for index, op in enumerate(ops):
                if op["op"] == "allow":
                    _safe_zone(op)
                    comment = "".join(ch if ch.isalnum() or ch in " _.:/=+-" else " " for ch in _mark_text(op, index))
                    for service in op["services"]:
                        for src in op["source"]["cidrs"]:
                            for dst in op["destination"]["cidrs"]:
                                argv = [UFW, "insert", "1", "allow", "from", src, "to", dst]
                                if service["proto"] == "icmp":
                                    argv += ["proto", "icmp"]
                                else:
                                    argv += ["port", str(service["ports"]), "proto", service["proto"]]
                                if op.get("log", True):
                                    argv.append("log")
                                argv += ["comment", " ".join(comment.split())]
                                commands.append(argv)
                else:
                    enable = op["op"] == "enable_rules"
                    user = _rewrite_ufw(user, "4", op, loaded, enable=enable)
                    user6 = _rewrite_ufw(user6, "6", op, loaded, enable=enable)
            return {"script": "", "commands": commands, "user_rules": user, "user6_rules": user6}
        commands = []
        disabled = [item for item in loaded.get("disabled") or [] if isinstance(item, dict)]
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                _safe_zone(op)
                for service in op["services"]:
                    for src in op["source"]["cidrs"]:
                        for dst in op["destination"]["cidrs"]:
                            family = "ipv6" if ":" in src or ":" in dst else "ipv4"
                            rule = _rich(family, src, dst, service, _mark_text(op, index), op.get("log", True), False)
                            commands.append([FIREWALL_CMD, f"--zone={op['source']['zone']}", f"--add-rich-rule={rule}"])
            else:
                enable = op["op"] == "enable_rules"
                parts = []
                for ref in op["rules"]:
                    parts.extend(part for part in str(ref.get("vendor_ref") or ref["id"]).split(",") if part)
                for part in parts:
                    raw = (loaded.get("raw") or {}).get(part)
                    if raw is None:
                        raise ChangeError(f"rule {part} is not on the device", code="invalid", state="unchanged")
                    line = raw.get("_rich")
                    zone = (raw.get("source_zones") or ["public"])[0]
                    if not _ZONE_RE.fullmatch(str(zone)):
                        raise ChangeError("the firewalld zone name is not a safe token", code="invalid", state="unchanged")
                    if not line:
                        raise ChangeError("only firewalld rich rules can be enabled or disabled here", code="invalid",
                                          state="unchanged")
                    if enable:
                        commands.append([FIREWALL_CMD, f"--zone={zone}", f"--add-rich-rule={line}"])
                        disabled = [item for item in disabled if item.get("vendor_ref") != raw["vendor_ref"]]
                    else:
                        commands.append([FIREWALL_CMD, f"--zone={zone}", f"--remove-rich-rule={line}"])
                        disabled.append({k: v for k, v in raw.items() if not str(k).startswith("_")} | {"enabled": False})
        return {"script": "", "commands": commands, "disabled_json": disabled}

    def _revert_body(self, loaded: dict[str, Any], change_id: str, window: int) -> dict[str, Any]:
        record = loaded["record"]
        manager = record["device"]["model"]
        body: dict[str, Any] = {
            "change_id": change_id, "manager": manager, "window_s": window, "unit": PENDING_UNIT,
            "timer_argv": _timer_argv(window), "persist": False,
        }
        if manager == "nftables":
            table = loaded.get("nft_table_text") or ""
            if "flush ruleset" in table:
                raise ChangeError("refusing a revert script that contains flush ruleset", code="failed", state="unchanged")
            script = "table inet atrium {}\ndelete table inet atrium\n"
            if table.strip():
                script += table if table.endswith("\n") else table + "\n"
            body["revert_script"] = script
            body["revert_argv"] = [NFT, "-f", "/var/lib/atrium/fw/pending/revert.nft"]
        elif manager == "ufw":
            body["revert_files"] = {"/etc/ufw/user.rules": loaded.get("user_rules") or "",
                                    "/etc/ufw/user6.rules": loaded.get("user6_rules") or ""}
            body["revert_argv"] = [UFW, "reload"]
        else:
            body["revert_argv"] = [FIREWALL_CMD, "--reload"]
            body["revert_note"] = "firewall-cmd --reload drops runtime-only changes"
        return body

    async def _read_pair(self, session: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        facts = await self._probe(session)
        loaded = await self._load(session, facts)
        record = normalize_record(loaded["record"])
        loaded["record"] = record
        return facts, loaded

    def _spec(self) -> dict[str, Any]:
        return validate_write_spec({**self.network_write, "window_s": int(self.config.get("window_s") or _WINDOW)}) or {}

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        try:
            target = self._target()
        except ConnectorError as exc:
            return {"ok": False, "detail": exc.message, "checks": [check("reachability", False, exc.message)],
                    "domains": {}, "network_write": None}
        try:
            async with self.ssh(target) as session:
                return await self._test_in(session, checks)
        except SshError as exc:
            message = str(exc)
            if "authentication failed" in message:
                checks.append(check("reachability", True, "the host answered SSH"))
                checks.append(check("authentication", False, message))
            elif "host key" in message:
                checks.append(check("reachability", True, "the host answered SSH"))
                checks.append(check("tls", False, message))
                checks.append(check("authentication", False, "the host key was not accepted"))
            else:
                checks.append(check("reachability", False, message))
            return {"ok": False, "detail": message, "checks": checks, "domains": {}, "network_write": None}

    async def _test_in(self, session: Any, checks: list[dict[str, Any]]) -> dict[str, Any]:
        checks.append(check("reachability", True, f"{self.config['host']} answered SSH"))
        strict = bool(self.config.get("strict_host_keys", True))
        checks.append(check("tls", strict, "SSH host-key checking is on (SSH is the transport; there is no TLS)"
                            if strict else "strict host-key checking is off"))
        checks.append(check("authentication", True, f"SSH key accepted for {self.config['username']}@{self.config['host']}"))
        try:
            facts = await self._probe(session)
            priv = await self._privileges(session)
        except ConnectorError as exc:
            checks.append(check("privileges", False, exc.message))
            return {"ok": False, "detail": exc.message, "checks": checks, "domains": {}, "network_write": None}
        writable = bool(priv.get("write")) and not self.config.get("read_only") and facts.get("manager") not in {
            "iptables", "unknown"} and not facts.get("sudo_password")
        detail = priv["detail"]
        if facts.get("sudo_password"):
            detail = "sudo -n would prompt for a password; none is stored"
            writable = False
        elif self.config.get("read_only") and priv.get("write"):
            detail = LEAST_PRIVILEGE_NOTE + "; this connection is marked read-only"
            writable = False
        elif facts.get("manager") == "iptables":
            detail = "legacy iptables only; device changes are unavailable"
            writable = False
        checks.append(check("privileges", bool(priv.get("sudo")) and not facts.get("sudo_password"), detail))
        manager = facts.get("manager") or "unknown"
        version = facts.get("version") or "unknown version"
        pretty = (facts.get("os") or {}).get("PRETTY_NAME") or (facts.get("os") or {}).get("ID") or "Linux"
        supported = manager in {"nftables", "ufw", "firewalld"}
        checks.append(check("version", supported, f"{manager} {version} on {pretty} kernel {facts.get('kernel') or '?'} "
                       + ("(supported)" if supported else "(read-only)")))
        spec = self._spec() if writable else None
        feature = (f"manager {manager}; deadman via systemd-run; wrapper {WRAPPER}; window {spec['window_s']}s"
                   if spec else f"manager {manager}; writes off")
        checks.append(check("api_features", supported and not facts.get("sudo_password"), feature))
        ok = supported and bool(priv.get("sudo")) and not facts.get("sudo_password") and strict
        # A readable firewall with host-key checking off is still a failed test: the transport is not authenticated.
        if supported and priv.get("sudo") and not facts.get("sudo_password") and not strict:
            ok = False
        return {"ok": ok, "detail": f"{manager} on {facts.get('hostname') or self.config['host']}",
                "checks": checks, "domains": self.domains() if ok else {}, "network_write": spec}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self._connect() as session:
            _facts, loaded = await self._read_pair(session)
        return [loaded["record"]]

    async def backup(self) -> dict[str, Any]:
        async with self._connect() as session:
            facts = await self._probe(session)
            loaded = await self._load(session, facts)
        record = loaded["record"]
        if facts.get("manager") == "nftables":
            content, fmt = loaded.get("nft_table_text") or "", "text"
            # The full JSON ruleset is the backup; the table text is what revert reapplies. Keep both.
            code_text = json.dumps({"manager": "nftables", "table_text": loaded.get("nft_table_text") or "",
                                    "record": {k: v for k, v in record.items() if k != "read_at"}},
                                   sort_keys=True)
            content, fmt = code_text, "json"
        elif facts.get("manager") == "ufw":
            content = json.dumps({"manager": "ufw", "user.rules": loaded.get("user_rules") or "",
                                  "user6.rules": loaded.get("user6_rules") or "",
                                  "status": loaded.get("ufw_status") or ""}, sort_keys=True)
            fmt = "json"
        elif facts.get("manager") == "firewalld":
            content = json.dumps({"manager": "firewalld", "runtime": loaded.get("zones_runtime") or "",
                                  "permanent": loaded.get("zones_permanent") or "",
                                  "disabled": loaded.get("disabled") or []}, sort_keys=True)
            fmt = "json"
        else:
            content, fmt = json.dumps({"manager": facts.get("manager"), "record": record}, sort_keys=True), "json"
        return {"content": content, "format": fmt, "device_backup_id": None, "revision": record["revision"]}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed = parse_ops(ops)
        except ValueError as exc:
            return {"steps": [], "notes": [], "problems": [str(exc)]}
        async with self._connect() as session:
            facts = await self._probe(session)
            loaded = await self._load(session, facts)
            record = normalize_record(loaded["record"])
            loaded["record"] = record
        problems = self._problems(record, parsed, loaded)
        if snapshot and snapshot.get("revision") and snapshot.get("revision") != record["revision"]:
            problems.append("the device revision moved since this snapshot; re-read it and preview again")
        steps = []
        manager = facts.get("manager")
        for index, op in enumerate(parsed):
            if op["op"] == "allow":
                where = {"nftables": "inserted at the top of table inet atrium chain input "
                                      "(an accept here does not override a drop in another table)",
                         "ufw": "inserted at position 1 (first match wins)",
                         "firewalld": f"runtime rich rule on zone {op['source']['zone']}, persisted only on confirm"
                         }.get(manager, "not applied")
                steps.append({"op": index, "kind": "add_rule", "position": where,
                              "detail": "one pass rule, marked " + op["marker"]})
            else:
                kind = "disable_rule" if op["op"] == "disable_rules" else "enable_rule"
                steps.extend({"op": index, "kind": kind, "position": "in place",
                              "detail": f"{op['op'].replace('_', ' ')} {ref['vendor_ref']}"} for ref in op["rules"])
        notes = [f"manager {manager}", "dead-man timer is systemd-run; persist happens on confirm"]
        if manager == "ufw":
            notes.append("ufw writes user.rules immediately; the timer restores the saved copy until confirm")
        return {"steps": steps, "notes": notes, "problems": problems}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        try:
            parsed = parse_ops(ops)
        except ValueError as exc:
            raise ChangeError(str(exc), code="invalid", state="unchanged") from exc
        try:
            target = self._target()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unsupported", state="unchanged") from exc
        try:
            async with self.ssh(target) as session:
                return await self._apply_in(session, parsed, base_revision)
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unchanged") from exc

    async def _apply_in(self, session: Any, ops: list[dict[str, Any]], base_revision: str) -> dict[str, Any]:
        facts = await self._probe(session)
        manager = facts.get("manager")
        if manager in {"iptables", "unknown", None}:
            raise ChangeError("this host has no supported writable firewall (nftables, ufw or firewalld)",
                              code="unsupported", state="unchanged")
        if self.config.get("read_only"):
            raise ChangeError("this connection is read-only", code="unsupported", state="unchanged")
        priv = await self._privileges(session)
        if not priv.get("write"):
            raise ChangeError(priv.get("detail") or "the SSH user cannot run the atrium-fw wrapper",
                              code="unsupported", state="unchanged")
        try:
            loaded = await self._load(session, facts)
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="failed", state="unchanged") from exc
        record = normalize_record(loaded["record"])
        loaded["record"] = record
        if record["revision"] != base_revision:
            raise ChangeError(f"the device is at revision {record['revision']}, not {base_revision}: re-read it and "
                              "preview again", code="stale", state="unchanged")
        problems = self._problems(record, ops, loaded)
        if problems:
            code = "lockout" if any("could cut the hub" in item for item in problems) else "invalid"
            raise ChangeError("Refused: " + "; ".join(problems), code=code, state="unchanged")
        for op in ops:
            if op["op"] == "allow" and any(find_marker(rule.get("description")) == find_marker(op["marker"])
                                           for rule in record.get("rules") or []):
                raise ChangeError(f"a rule marked {op['marker']} is already on the device", code="failed",
                                  state="unchanged")
        change_id = self._change_id(ops)
        if not _CHANGE_RE.fullmatch(change_id):
            raise ChangeError("the change id is not safe to put in a unit name", code="invalid", state="unchanged")
        window = int(self.config.get("window_s") or _WINDOW)
        rendered = self._render(loaded, ops)
        await self._wrapper(session, "snapshot", {"change_id": change_id, "manager": manager}, state="unchanged")
        revert = self._revert_body(loaded, change_id, window)
        await self._wrapper(session, "arm-revert", revert, state="unchanged")
        try:
            await self._wrapper(session, "apply", {"change_id": change_id, "manager": manager, "persist": False,
                                                   **rendered}, state="unknown")
            fresh = await self._load(session, facts)
            after = normalize_record(fresh["record"])
            self._assert_applied(after, ops, fresh)
        except (ChangeError, ConnectorError, SshError) as exc:
            reverted = await self._try_revert(session, change_id, manager)
            message = exc.message if isinstance(exc, ConnectorError) else str(exc)
            raise ChangeError(message, code="failed", state="rolled_back" if reverted else "unknown") from exc
        created, disabled = self._created(after, ops)
        token = json.dumps({"v": 1, "host": self.config["host"], "port": int(self.config.get("port") or 22),
                            "manager": manager, "change_id": change_id, "revision": after["revision"]},
                           separators=(",", ":"))
        if len(token) > 4096:
            raise ChangeError("the change token is too large", code="failed", state="unknown")
        notes = ["deadman armed via systemd-run", "persist is deferred until confirm"]
        if manager == "ufw":
            notes.append("ufw has already rewritten user.rules; confirm only cancels the timer")
        return {"token": token, "rollback_until": time.time() + window, "revision": after["revision"],
                "created": created, "disabled": disabled, "notes": notes}

    def _assert_applied(self, record: dict[str, Any], ops: list[dict[str, Any]], loaded: dict[str, Any]) -> None:
        from .netmodel import rule_matches_allow

        for op in ops:
            if op["op"] == "allow":
                mid = find_marker(op["marker"])
                found = [rule for rule in record.get("rules") or [] if rule.get("marker") == mid]
                if not any(rule_matches_allow(rule, op) for rule in found):
                    raise ChangeError(f"the rule marked {op['marker']} is not on the device as proposed",
                                      code="failed", state="unknown")
            else:
                want = op["op"] == "enable_rules"
                for ref in op["rules"]:
                    rule = _find(record, ref)
                    if rule is None or bool(rule.get("enabled", True)) != want:
                        raise ChangeError(f"rule {ref.get('id')} is not {'enabled' if want else 'disabled'}",
                                          code="failed", state="unknown")

    def _created(self, record: dict[str, Any], ops: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
        created, disabled = [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                mid = find_marker(op["marker"])
                rule = next((rule for rule in record.get("rules") or [] if rule.get("marker") == mid), None)
                if rule is None:
                    raise ChangeError(f"the rule marked {op['marker']} is not on the device after the write",
                                      code="failed", state="unknown")
                created.append({"op": index, "id": rule["id"], "vendor_ref": rule["vendor_ref"]})
            elif op["op"] == "disable_rules":
                disabled.extend(str(ref.get("vendor_ref") or ref["id"]) for ref in op["rules"])
        return created, disabled

    async def _try_revert(self, session: Any, change_id: str, manager: str) -> bool:
        try:
            await self._wrapper(session, "revert-now", {"change_id": change_id, "manager": manager}, state="unknown")
        except (ChangeError, ConnectorError, SshError):
            return False
        return True

    def _token(self, token: str) -> dict[str, Any]:
        try:
            data = json.loads(token)
        except ValueError as exc:
            raise ChangeError("the change token is not valid", code="invalid", state="unknown") from exc
        if not isinstance(data, dict):
            raise ChangeError("the change token is not valid", code="invalid", state="unknown")
        if data.get("host") != self.config.get("host") or int(data.get("port") or 0) != int(self.config.get("port") or 22):
            raise ChangeError("the change token is for a different host", code="invalid", state="unknown")
        if data.get("manager") not in {"nftables", "ufw", "firewalld"}:
            raise ChangeError("the change token names an unknown manager", code="invalid", state="unknown")
        if not _CHANGE_RE.fullmatch(str(data.get("change_id") or "")):
            raise ChangeError("the change token has no change id", code="invalid", state="unknown")
        return data

    async def confirm_change(self, token: str) -> dict[str, Any]:
        data = self._token(token)
        persist = data["manager"] != "ufw"
        try:
            target = self._target()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unsupported", state="unknown") from exc
        try:
            async with self.ssh(target) as session:
                result = await self._wrapper(session, "confirm",
                                             {"change_id": data["change_id"], "manager": data["manager"],
                                              "persist": persist, "cancel_timer": True}, state="unknown")
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unknown") from exc
        notes = ["revert timer cancelled"]
        notes.append("ufw had already persisted; confirm only cancelled the timer" if data["manager"] == "ufw"
                     else "change persisted")
        return {"confirmed": True, "revision": result.get("revision"), "notes": notes}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        data = self._token(token)
        try:
            target = self._target()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unsupported", state="unknown") from exc
        try:
            async with self.ssh(target) as session:
                await self._wrapper(session, "revert-now",
                                    {"change_id": data["change_id"], "manager": data["manager"]}, state="unknown")
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unknown") from exc
        return {"rolled_back": True, "method": "deadman", "notes": ["revert-now restored the host snapshot"]}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        try:
            saved = json.loads(backup.text())
        except (ValueError, UnicodeError) as exc:
            raise ChangeError("the backup is not a host-firewall configuration", code="invalid", state="unchanged") from exc
        if not isinstance(saved, dict) or saved.get("manager") not in {"nftables", "ufw", "firewalld"}:
            raise ChangeError("the backup is not a host-firewall configuration", code="invalid", state="unchanged")
        if "flush ruleset" in json.dumps(saved):
            raise ChangeError("the backup contains flush ruleset and was refused", code="invalid", state="unchanged")
        change_id = "restore-" + derived_revision(saved.get("manager"))[2:10]
        try:
            target = self._target()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unsupported", state="unchanged") from exc
        try:
            async with self.ssh(target) as session:
                return await self._restore_in(session, saved, change_id)
        except SshError as exc:
            raise ChangeError(str(exc), code="unreachable", state="unchanged") from exc

    async def _restore_in(self, session: Any, saved: dict[str, Any], change_id: str) -> dict[str, Any]:
        facts = await self._probe(session)
        if facts.get("manager") != saved.get("manager"):
            raise ChangeError(f"the host is {facts.get('manager')}, not {saved.get('manager')}", code="invalid",
                              state="unchanged")
        loaded = await self._load(session, facts)
        window = int(self.config.get("window_s") or _WINDOW)
        await self._wrapper(session, "snapshot", {"change_id": change_id, "manager": facts["manager"]}, state="unchanged")
        await self._wrapper(session, "arm-revert", self._revert_body(loaded, change_id, window), state="unchanged")
        payload = self._restore_payload(saved, change_id)
        try:
            await self._wrapper(session, "apply", payload, state="unknown")
            await self._wrapper(session, "confirm", {"change_id": change_id, "manager": facts["manager"],
                                                    "persist": facts["manager"] != "ufw", "cancel_timer": True},
                               state="unknown")
        except (ChangeError, ConnectorError) as exc:
            reverted = await self._try_revert(session, change_id, facts["manager"])
            raise ChangeError(exc.message, code="failed", state="rolled_back" if reverted else "unknown") from exc
        fresh = await self._load(session, facts)
        return {"restored": True, "revision": normalize_record(fresh["record"])["revision"],
                "notes": [f"restored the {facts['manager']} configuration this connector manages"]}

    def _restore_payload(self, saved: dict[str, Any], change_id: str) -> dict[str, Any]:
        manager = saved["manager"]
        if manager == "nftables":
            script = saved.get("table_text") or ""
            if script and "flush ruleset" in script:
                raise ChangeError("refusing to restore a table dump that contains flush ruleset", code="invalid",
                                  state="unchanged")
            text = "table inet atrium {}\ndelete table inet atrium\n" + (script or "")
            return {"change_id": change_id, "manager": manager, "persist": False, "script": text, "commands": []}
        if manager == "ufw":
            return {"change_id": change_id, "manager": manager, "persist": False, "script": "", "commands": [],
                    "user_rules": saved.get("user.rules") or "", "user6_rules": saved.get("user6.rules") or ""}
        return {"change_id": change_id, "manager": manager, "persist": False, "script": "",
                "commands": [], "zones_text": saved.get("runtime") or "", "disabled_json": saved.get("disabled") or []}


def _find(record: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    wanted = set(str(ref.get("vendor_ref") or ref.get("id") or "").split(","))
    wanted.add(str(ref.get("id") or ""))
    for rule in record.get("rules") or []:
        refs = set(str(rule.get("vendor_ref") or "").split(","))
        refs.add(rule.get("id"))
        if wanted & refs:
            return rule
    return None


def _rewrite_ufw(text: str, family: str, op: dict[str, Any], loaded: dict[str, Any], *, enable: bool) -> str:
    """Comment or uncomment tuple lines that this operation names. The file is data for the wrapper, not a shell."""
    lines = text.splitlines()
    index = 0
    wanted: set[str] = set()
    for ref in op["rules"]:
        wanted.update(part for part in str(ref.get("vendor_ref") or "").split(",") if part)
        if ref.get("id"):
            wanted.add(str(ref["id"]))
    for number, line in enumerate(lines):
        stripped = line.strip()
        body = stripped[1:].strip() if stripped.startswith("#") and not stripped.startswith("###") else stripped
        if not body.startswith("### tuple ###"):
            continue
        index += 1
        ref = f"ufw:{family}:{index}"
        if ref not in wanted:
            continue
        if enable:
            lines[number] = body
        elif not stripped.startswith("# ") and not (stripped.startswith("#") and not stripped.startswith("###")):
            lines[number] = "# " + line
    return "\n".join(lines) + ("\n" if text.endswith("\n") or lines else "")


def _rich(family: str, src: str, dst: str, service: dict[str, Any], marker_text: str, log: bool, disabled: bool) -> str:
    prefix = f"atrium-disabled {marker_text} " if disabled else f"{marker_text} "
    parts = [f'rule family="{family}"', 'priority="-10"', f'source address="{src}"', f'destination address="{dst}"']
    proto = service.get("proto")
    if proto in {"tcp", "udp"}:
        parts.append(f'port port="{service.get("ports")}" protocol="{proto}"')
    elif proto == "icmp":
        parts.append('protocol value="icmp"')
    if log or disabled:
        safe = "".join(ch if ch.isalnum() or ch in " _.:/=+-" else " " for ch in prefix)
        parts.append(f'log prefix="{" ".join(safe.split())}" level="info"')
    parts.append("accept" if not disabled else "mark")
    return " ".join(parts)
