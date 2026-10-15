"""Cisco IOS-XE connector (Catalyst switches, ISR / ASR / Catalyst 8000 routers): reads interfaces, VLANs / SVIs and
the IPv4 access lists bound to them over RESTCONF into the network model (``netmodel.py``) and - only on a device whose
NETCONF server offers a candidate datastore with confirmed commit 1.1 - adds one permit entry to an interface ACL
under the change safety model.

Sources: docs/research/fw-fortigate-panos-cisco.md sections 4-6, and Cisco's published YANG models for 17.15.1
(YangModels/yang vendor/cisco/xe/17151, revision 2024-07-01), re-read for this connector in October 2026; RFC 8040
(RESTCONF), RFC 7951 (JSON encoding), RFC 6241 (NETCONF) and RFC 6242 (NETCONF over SSH). Labels: [V] official model /
documentation / RFC, [U] unverified.

- Credential [V]: RESTCONF and NETCONF need a privilege-15 AAA user; there is no read-only API role (NACM groups
  PRIV00-PRIV15 exist, but read-only enforcement for a priv-15 user is not documented). ``test()`` says so: use a
  dedicated account, restrict its sources (``ip http access-class``) and keep device changes off until needed.
- Reading (RESTCONF, ``Accept: application/yang-data+json``), paths from the 17.15.1 models [V]:
  - ``Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data`` (software-version)
    and ``.../device-inventory`` (chassis part-number, serial-number);
  - ``Cisco-IOS-XE-native:native/hostname``, ``.../interface`` (per-type lists keyed by ``name``: ``ip/address/
    primary|secondary`` address + netmask, ``vrf/forwarding``, ``shutdown``, ``ip/access-group/in|out/acl/acl-name``,
    ``Cisco-IOS-XE-zone:zone-member``), ``.../vlan`` (``Cisco-IOS-XE-vlan:vlan-list`` id + name);
  - ``.../ip/access-list`` (``Cisco-IOS-XE-acl:extended`` / ``standard`` lists, ``access-list-seq-rule`` keyed by
    ``sequence`` (uint64, a JSON string), ``remark`` (1-100 characters) as its own entry, ``ace-rule`` with
    ``action``, ``protocol``, ``ipv4-address`` + wildcard ``mask`` / ``any`` / ``host-address`` / ``object-group``,
    the ``dest-``/``dst-`` equivalents, ``dst-eq`` .. ``dst-eq-port10`` / ``dst-gt`` / ``dst-lt`` / ``dst-neq..`` /
    ``dst-range1`` + ``dst-range2`` (port numbers or names: the model's ``acl-port-type`` values), ``log``,
    ``log-input``, ``established``, ``time-range``; standard entries ``permit|deny/std-ace``);
  - ``.../object-group`` (``Cisco-IOS-XE-object-group:network``: ``network_address`` address + netmask, ``host``,
    ``addr-ranges``, ``group-objects``), ``.../line`` (``vty``: ``access-class/acccess-list`` - the model's own
    spelling - and ``transport/input``), ``.../ip/http`` (``Cisco-IOS-XE-http:http``: ``access-class-group``,
    ``server``, ``secure-server``, ``secure-port``);
  - optional: ``Cisco-IOS-XE-interfaces-oper:interfaces`` (DHCP addresses, ``input-security-acl`` /
    ``output-security-acl``) and ``Cisco-IOS-XE-acl-oper:access-lists`` (``match-counter`` per entry = hit counts).
- The record: routed interfaces and SVIs are the segments (an SVI is named after its VLAN); an ACL bound ``in`` on an
  interface gives rules on that interface, ``out`` gives rules with direction ``out``; each binding ends with its
  implicit deny; ACLs bound to nothing filter nothing and are left out (counted in the notes). VTY ``access-class``
  and the HTTP server's access class are read as rules to the device itself; without one, an implicit "any source"
  rule shows that management access is not restricted by an ACL. A packet on an interface without an ACL is
  forwarded, so ``default_policy`` is pass and such interfaces are listed in the notes. Remarks before an entry are its
  description (Atrium's marker lives there). Non-contiguous wildcard masks, FQDN / geo groups and unresolvable object
  groups become unresolved aliases (treated as any). Source-port conditions, ``established``, ICMP types and time
  ranges are not modelled (the rule is shown wider). Zone-based firewall policies and IPv6 ACLs are not read (noted).
- Revision: IOS-XE reports no configuration revision; it is a hash of the configuration read (oper data and
  counters left out).
- Changes - rollback mode ``commit_confirm``, over NETCONF (SSH port 830, subsystem ``netconf``; RFC 6242 framing,
  end-of-message for 1.0 and chunked for 1.1, implemented here over asyncssh):
  - required capabilities, checked in every session: ``:candidate:1.0`` (``netconf-yang feature
    candidate-datastore``) [V] and ``:confirmed-commit:1.1`` - RFC 6241 defines ``<persist>``, ``<persist-id>`` and
    ``<cancel-commit>`` for 1.1 [V], which let a confirmed commit outlive the session that issued it (Atrium verifies
    over a NEW connection). With 1.0 only, a confirmed commit is undone when its session closes [V], so the device
    stays read only.
  - apply: ``<lock>`` candidate, ``<discard-changes>``, re-read over RESTCONF (revision and the guard checked under
    the lock), ``<edit-config>`` with ``default-operation none`` and ``operation="create"`` on two new entries (a
    remark ``atrium:<change id> <description>`` and the permit entry right after it), ``<validate>`` when offered,
    ``<commit><confirmed/><confirm-timeout>N</confirm-timeout><persist>id</persist>``, ``<unlock>``. The device
    reverts by itself after N seconds unless confirmed.
  - confirm: ``<commit><persist-id>`` (in a locked, discarded candidate), then ``cisco-ia:save-config`` over RESTCONF
    (running to startup) [V] - only now. Rollback: ``<cancel-commit><persist-id>``; after a confirm, the two entries
    Atrium created are deleted (when they still carry its marker).
  - allow only: an IOS ACE has no disabled state, so ``disable_rules`` / ``enable_rules`` are not offered. The entry
    goes into the extended ACL bound inbound on the source interface (never a new ACL or binding), before the first
    entry that could block (deny / evaluate) - after the permits, so the order of what was there stays. One entry
    per change: one source and one destination network, one protocol, up to 10 single ports or one range.
  - management path (never written): ACLs bound to the VTY lines or the HTTP server, ACLs on management-VRF
    interfaces (Mgmt-vrf, Mgmt-intf) and on interfaces holding the device's management address or the hub's address.
- Backups: ``Cisco-IOS-XE-cli-rpc:get-modelled-config-clis`` (the modelled running configuration as CLI text; wireless,
  app-hosting and telemetry are not included) is the hub's copy [V], and ``Cisco-IOS-XE-rpc:copy`` running-config to
  ``<filesystem>atrium-<hash>.cfg`` keeps the full configuration on the device [V]. ``restore_backup`` replaces the
  running configuration with that file through ``cisco-ia:rollback`` (``configure replace``, ``revert-on-error``) [V];
  it has no confirm timer (no API equivalent of ``configure confirm`` exists [V]).

UNVERIFIED: that IOS-XE advertises ``:confirmed-commit:1.1`` and honours ``<persist>`` / ``<cancel-commit>`` (Cisco's
guide documents confirmed commit and its 600 s default, not persist); that ``<discard-changes>`` is accepted while a
confirmed commit is pending; that remarks are written as their own numbered entries and eq ports keep their meaning
when read back as names (``www``); RESTCONF answering 404 (or 204) for an empty container; that the ``copy`` RPC
overwrites an existing file; how ``cisco-ia:rollback`` behaves with the candidate datastore enabled; default values
(``ip http server`` true) being left out of answers (with-defaults "explicit"); the shapes of hit counters on releases
before 17.15.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import secrets as pysecrets
import ssl
import time
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath
from typing import Any, AsyncIterator, Callable
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, MARKER_RE, Backup, ChangeError, UnsafeXml, derived_revision, display_id,
                       find_marker, normalize_record, parse_ops, parse_untrusted_xml, ssh_target, untrusted_text,
                       validate_ssh_config)

OPS = ["allow"]
DEFAULT_CONFIRM = 120
CONFIRM_RANGE = (60, 600)
MIN_MAJOR = 16  # the native models this connector reads came with IOS XE 16
TOKEN_PREFIX = "iosxe1:"
MAX_TOKEN = 4096
MAX_MESSAGE = 16 * 1024 * 1024  # one NETCONF message
RPC_TIMEOUT = 60.0
ROLLBACK_TIMEOUT = 300.0  # configure replace can take minutes

NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
ACL_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-acl"
CAP_BASE11 = "urn:ietf:params:netconf:base:1.1"
CAP_CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
CAP_CONFIRMED = "urn:ietf:params:netconf:capability:confirmed-commit:"
CAP_VALIDATE = "urn:ietf:params:netconf:capability:validate:"
EOM = b"]]>]]>"
CHUNK_RE = re.compile(rb"\n#([1-9][0-9]{0,9})\n")
HELLO = (f'<?xml version="1.0" encoding="UTF-8"?><hello xmlns="{NC}"><capabilities>'
         f"<capability>urn:ietf:params:netconf:base:1.0</capability><capability>{CAP_BASE11}</capability>"
         "</capabilities></hello>")

REST = "/restconf"
SYSTEM = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data"
INVENTORY = "/data/Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-inventory"
HOSTNAME = "/data/Cisco-IOS-XE-native:native/hostname"
INTERFACES = "/data/Cisco-IOS-XE-native:native/interface"
OPER = "/data/Cisco-IOS-XE-interfaces-oper:interfaces"
OPER_FIELDS = "interface(name;admin-status;oper-status;ipv4;ipv4-subnet-mask;vrf;input-security-acl;output-security-acl)"
VLANS = "/data/Cisco-IOS-XE-native:native/vlan"
ACLS = "/data/Cisco-IOS-XE-native:native/ip/access-list"
OBJECT_GROUPS = "/data/Cisco-IOS-XE-native:native/object-group"
LINES = "/data/Cisco-IOS-XE-native:native/line"
HTTP_SERVER = "/data/Cisco-IOS-XE-native:native/ip/http"
COUNTERS = "/data/Cisco-IOS-XE-acl-oper:access-lists"
IS_SYNCING = "/operations/cisco-ia:is-syncing"
SAVE_CONFIG = "/operations/cisco-ia:save-config"
ROLLBACK = "/operations/cisco-ia:rollback"
COPY = "/operations/Cisco-IOS-XE-rpc:copy"
DELETE = "/operations/Cisco-IOS-XE-rpc:delete"
CLI_CONFIG = "/operations/Cisco-IOS-XE-cli-rpc:get-modelled-config-clis"

MGMT_VRFS = ("mgmt-vrf", "mgmt-intf")
FILESYSTEMS = ("bootflash:", "flash:", "harddisk:")
SKIP_TYPES = ("Loopback", "Null")
ACL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")  # what Atrium writes into (and accepts in a token)
IFACE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z-]*[0-9][0-9/.:]*$")
FILE_RE = re.compile(r"^(bootflash|flash|harddisk):atrium-[0-9a-f]{16}\.cfg$")
VERSION_RE = re.compile(r"Version\s+(\d+)\.(\d+)(?:\.(\d+))?([A-Za-z0-9]*)")
PERSIST_RE = re.compile(r"^[0-9a-f]{32}$")
# acl-port-type (Cisco-IOS-XE-acl.yang 17.15.1): the names a port may be given in, with their numbers [V]; exec,
# login and cmd have no value in the model - 512, 513, 514 are their IANA tcp ports
PORT_NAMES = {
    "bgp": 179, "chargen": 19, "daytime": 13, "discard": 9, "domain": 53, "echo": 7, "finger": 79, "ftp": 21,
    "ftp-data": 20, "gopher": 70, "hostname": 101, "ident": 113, "irc": 194, "klogin": 543, "kshell": 544, "lpd": 515,
    "msrpc": 135, "nntp": 119, "pim-auto-rp": 496, "pop2": 109, "pop3": 110, "smtp": 25, "sunrpc": 111, "tacacs": 49,
    "talk": 517, "telnet": 23, "time": 37, "uucp": 540, "whois": 43, "www": 80, "biff": 512, "bootpc": 68,
    "bootps": 67, "dnsix": 195, "isakmp": 500, "mobile-ip": 434, "nameserver": 42, "netbios-dgm": 138,
    "netbios-ns": 137, "netbios-ss": 139, "non500-isakmp": 4500, "ntp": 123, "rip": 520, "ripv6": 521, "snmp": 161,
    "snmptrap": 162, "syslog": 514, "tftp": 69, "who": 513, "xdmcp": 177, "onep-plain": 15001, "onep-tls": 15002,
    "exec": 512, "login": 513, "cmd": 514,
}
PROTOCOL_NAMES = {"ahp": "ah"}


def member(data: Any, name: str) -> Any:
    """`data[name]` whether the member is module-qualified ("Cisco-IOS-XE-acl:extended") or not (RFC 7951 qualifies
    a member only where its module changes)."""
    if not isinstance(data, dict):
        return None
    if name in data:
        return data[name]
    return next((v for k, v in data.items() if isinstance(k, str) and k.rpartition(":")[2] == name), None)


def items(value: Any) -> list[dict[str, Any]]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else [value] if isinstance(value, dict) else []


def is_set(value: Any) -> bool:
    """An ``empty`` leaf is [null] in JSON (RFC 7951); a boolean is a boolean."""
    return value is not None and value is not False


def parse_version(text: Any) -> tuple[int, int, int] | None:
    """(17, 15, 1) from "Cisco IOS XE Software, Version 17.15.01 ..." or "17.9.4a"."""
    match = VERSION_RE.search(str(text or "")) or re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)) if match else None


def wildcard_cidr(address: Any, wildcard: Any) -> str | None:
    """'10.0.10.0' + '0.0.0.255' -> '10.0.10.0/24'; None for a non-contiguous wildcard or a non-address."""
    try:
        addr = int(ipaddress.IPv4Address(str(address).strip()))
        wild = int(ipaddress.IPv4Address(str(wildcard).strip()))
    except ValueError:
        return None
    if (wild + 1) & wild:
        return None
    prefix = 32 - wild.bit_length()
    return str(ipaddress.IPv4Network((addr & ~wild & 0xFFFFFFFF, prefix)))


def netmask_cidr(address: Any, mask: Any) -> str | None:
    try:
        return str(ipaddress.IPv4Network(f"{str(address).strip()}/{str(mask).strip()}", strict=False))
    except ValueError:
        return None


def to_wildcard(cidr: str) -> tuple[str, str]:
    net = ipaddress.IPv4Network(cidr)
    return str(net.network_address), str(net.hostmask)


def port_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 < value <= 65535 else None
    text = str(value or "").strip().lower()
    if text.isdigit():
        number = int(text)
        return number if 0 < number <= 65535 else None
    return PORT_NAMES.get(text)


def _complement(ports: list[int]) -> str | None:
    """'neq 80 443' -> '1-79,81-442,444-65535'."""
    out, low = [], 1
    for port in sorted(set(ports)):
        if port > low:
            out.append(f"{low}-{port - 1}" if port - 1 > low else str(low))
        low = port + 1
    if low <= 65535:
        out.append(f"{low}-65535" if low < 65535 else "65535")
    return ",".join(out) or None


class TlsError(ConnectorError):
    """The device answered, but its certificate is not trusted."""


class NetconfError(ConnectorError):
    """A NETCONF problem: an <rpc-error> (``tag`` set, e.g. in-use, data-exists) or a broken session. The message
    holds the device's error text shortened and stripped (untrusted, never a secret of ours)."""

    def __init__(self, message: str, *, tag: str | None = None):
        super().__init__(message)
        self.tag = tag


# --------------------------------------------------------------------------------------
# NETCONF (RFC 6241) over SSH with RFC 6242 framing
# --------------------------------------------------------------------------------------


def parse_xml(raw: bytes, what: str = "NETCONF message") -> ET.Element:
    """A device XML document (untrusted): no DOCTYPE or entity declarations (netmodel.parse_untrusted_xml)."""
    try:
        return parse_untrusted_xml(raw)
    except UnsafeXml as exc:
        raise NetconfError(f"The device's {what} declares a DOCTYPE or entities - refusing to parse it") from exc
    except ET.ParseError as exc:
        raise NetconfError(f"The device sent a {what} that is not well-formed XML") from exc


def _local(tag: str) -> str:
    return tag.rpartition("}")[2]


def _child_text(element: ET.Element, name: str) -> str:
    found = next((c for c in element if _local(c.tag) == name), None)
    return (found.text or "").strip() if found is not None else ""


class NetconfSession:
    """One NETCONF session over a byte stream: ``reader.read(n)`` -> bytes (b"" at the end) and ``writer.write`` /
    ``drain``. ``hello()`` exchanges capabilities (end-of-message framing), then chunked framing is used when both
    sides speak base:1.1. ``rpc(body)`` returns the <rpc-reply> element or raises NetconfError."""

    def __init__(self, reader: Any, writer: Any, *, label: str = "device", timeout: float = RPC_TIMEOUT,
                 max_message: int = MAX_MESSAGE):
        self.reader, self.writer, self.label = reader, writer, label
        self.timeout, self.max_message = timeout, max_message
        self.capabilities: set[str] = set()
        self.session_id: str | None = None
        self.chunked = False
        self._buffer = b""
        self._next_id = 0
        self.closed = False

    def has(self, capability: str) -> bool:
        """Whether the server announced `capability` (parameters after '?' are ignored)."""
        return any(c.split("?")[0] == capability for c in self.capabilities)

    def has_prefix(self, prefix: str) -> list[str]:
        return sorted(c.split("?")[0][len(prefix):] for c in self.capabilities if c.startswith(prefix))

    async def _fill(self) -> None:
        chunk = await self.reader.read(65536)
        if not chunk:
            self.closed = True
            raise NetconfError(f"{self.label} closed the NETCONF session")
        self._buffer += chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8")
        if len(self._buffer) > self.max_message + 64:
            raise NetconfError(f"{self.label} sent a NETCONF message larger than {self.max_message} bytes")

    async def _read_eom(self) -> bytes:
        while EOM not in self._buffer:
            await self._fill()
        message, _, self._buffer = self._buffer.partition(EOM)
        return message

    async def _read_chunked(self) -> bytes:
        parts, size = [], 0
        while True:
            while len(self._buffer) < 4:
                await self._fill()
            if self._buffer.startswith(b"\n##\n"):
                self._buffer = self._buffer[4:]
                if not parts:
                    raise NetconfError(f"{self.label} sent an empty NETCONF message")
                return b"".join(parts)
            while b"\n" not in self._buffer[1:16] and len(self._buffer) < 16:
                await self._fill()
            match = CHUNK_RE.match(self._buffer)
            if not match:
                raise NetconfError(f"{self.label} broke the NETCONF chunked framing (RFC 6242)")
            length = int(match.group(1))
            size += length
            if size > self.max_message:
                raise NetconfError(f"{self.label} sent a NETCONF message larger than {self.max_message} bytes")
            start = match.end()
            while len(self._buffer) < start + length:
                await self._fill()
            parts.append(self._buffer[start:start + length])
            self._buffer = self._buffer[start + length:]

    async def receive(self, timeout: float | None = None) -> bytes:
        try:
            return await asyncio.wait_for(self._read_chunked() if self.chunked else self._read_eom(),
                                          timeout or self.timeout)
        except asyncio.TimeoutError as exc:
            self.closed = True  # the message stream is out of step: never reuse the session
            raise NetconfError(f"{self.label} did not answer over NETCONF within {timeout or self.timeout:.0f}s") from exc
        except NetconfError:
            self.closed = True
            raise

    async def send(self, text: str) -> None:
        if self.closed:
            raise NetconfError(f"{self.label}: the NETCONF session is closed")
        data = text.encode("utf-8")
        framed = b"\n#%d\n%s\n##\n" % (len(data), data) if self.chunked else data + EOM
        try:
            self.writer.write(framed)
            await self.writer.drain()
        except Exception as exc:  # OSError, BrokenPipeError, asyncssh's own channel errors
            self.closed = True
            raise NetconfError(f"{self.label}: the NETCONF session broke ({exc.__class__.__name__})") from exc

    async def hello(self) -> None:
        await self.send(HELLO)
        root = parse_xml(await self.receive(), "hello")
        if _local(root.tag) != "hello":
            raise NetconfError(f"{self.label} did not start with a NETCONF <hello>")
        self.capabilities = {(c.text or "").strip() for c in root.iter() if _local(c.tag) == "capability" and c.text}
        self.session_id = _child_text(root, "session-id") or None
        self.chunked = self.has(CAP_BASE11)

    async def rpc(self, body: str, *, timeout: float | None = None) -> ET.Element:
        self._next_id += 1
        message_id = str(self._next_id)
        await self.send(f'<rpc message-id="{message_id}" xmlns="{NC}">{body}</rpc>')
        while True:
            root = parse_xml(await self.receive(timeout), "reply")
            if _local(root.tag) == "rpc-reply" and root.get("message-id") == message_id:
                break  # anything else (a notification) is skipped
        errors = [e for e in root if _local(e.tag) == "rpc-error" and _child_text(e, "error-severity") != "warning"]
        if errors:
            first = errors[0]
            tag = _child_text(first, "error-tag") or "error"
            text = untrusted_text(_child_text(first, "error-message"), 200)
            path = untrusted_text(_child_text(first, "error-path"), 120)
            raise NetconfError(f"{tag}" + (f": {text}" if text else "") + (f" (at {path})" if path else ""), tag=tag)
        return root

    async def close(self) -> None:
        if self.closed:
            return
        with contextlib.suppress(Exception):
            await self.rpc("<close-session/>", timeout=5)
        self.closed = True


class AsyncsshNetconf:
    """The real NETCONF transport: SSH (asyncssh, strict host keys as ``execution.runner``) to the ``netconf``
    subsystem."""

    @contextlib.asynccontextmanager
    async def session(self, target: Any) -> AsyncIterator[NetconfSession]:
        from ..execution import runner

        try:
            import asyncssh
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise NetconfError("NETCONF needs asyncssh: pip install 'atrium[ssh]'") from exc
        try:
            options = runner.AsyncsshTransport.options(target)
        except runner.SshError as exc:
            raise NetconfError(str(exc)) from exc
        try:
            conn = await asyncio.wait_for(asyncssh.connect(**options), target.connect_timeout + 20)
        except asyncssh.HostKeyNotVerifiable as exc:
            raise NetconfError(f"{target.label}: the host key is not trusted - pin it in the connection (strict "
                               "host-key checking is on)") from exc
        except asyncssh.PermissionDenied as exc:
            raise NetconfError(f"{target.label}: NETCONF authentication failed - check the user and password") from exc
        except asyncio.TimeoutError as exc:
            raise NetconfError(f"{target.label}: no answer within {target.connect_timeout:.0f}s") from exc
        except (OSError, asyncssh.Error) as exc:
            reason = exc.strerror if isinstance(exc, OSError) else getattr(exc, "reason", "")
            raise NetconfError(f"{target.label}: cannot connect to NETCONF ({exc.__class__.__name__}: "
                               f"{reason or 'no reason given'})") from exc
        process = None
        try:
            try:
                process = await conn.create_process(subsystem="netconf", encoding=None)
            except Exception as exc:
                raise NetconfError(f"{target.label}: the device refused the NETCONF subsystem - is 'netconf-yang' "
                                   f"configured? ({exc.__class__.__name__})") from exc
            session = NetconfSession(process.stdout, process.stdin, label=target.label)
            await session.hello()
            try:
                yield session
            finally:
                await session.close()
        finally:
            if process is not None:
                process.close()
            conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.wait_closed(), 5)


NETCONF = AsyncsshNetconf()


def _x(value: Any) -> str:
    return escape(str(value))


LOCK = "<lock><target><candidate/></target></lock>"
UNLOCK = "<unlock><target><candidate/></target></unlock>"
DISCARD = "<discard-changes/>"
VALIDATE = "<validate><source><candidate/></source></validate>"


async def lock_candidate(session: NetconfSession) -> None:
    """Lock the candidate datastore and start from the running configuration. RFC 6241 8.3.5.1: a candidate holding
    uncommitted changes cannot be locked - such leftovers (of a session that ended) are discarded first, which the
    device refuses while another session holds the lock."""
    try:
        await session.rpc(LOCK)
    except NetconfError as first:
        if first.tag is None:
            raise
        try:
            await session.rpc(DISCARD)
            await session.rpc(LOCK)
        except NetconfError:
            raise first from None
    await session.rpc(DISCARD)


def acl_edit(acl: str, entries: str) -> str:
    """An <edit-config> of the candidate touching only the given entries of one extended ACL (default operation
    none: an ACL that does not exist is an error, never created)."""
    return ("<edit-config><target><candidate/></target><default-operation>none</default-operation><config>"
            f'<native xmlns="{NATIVE_NS}"><ip><access-list><extended xmlns="{ACL_NS}"><name>{_x(acl)}</name>'
            f"{entries}</extended></access-list></ip></native></config></edit-config>")


def entry_xml(sequence: int, operation: str, inner: str = "") -> str:
    return (f'<access-list-seq-rule xmlns:nc="{NC}" nc:operation="{operation}"><sequence>{int(sequence)}</sequence>'
            f"{inner}</access-list-seq-rule>")


def ace_xml(ace: dict[str, Any]) -> str:
    return "<ace-rule>" + "".join("<log/>" if key == "log" else f"<{key}>{_x(value)}</{key}>"
                                  for key, value in ace.items()) + "</ace-rule>"


# --------------------------------------------------------------------------------------
# reading: from RESTCONF answers to the normalised record
# --------------------------------------------------------------------------------------


class Device:
    """One read of the device (RESTCONF answers, untrusted) and the lookups normalisation needs."""

    def __init__(self, raw: dict[str, Any], config: dict[str, Any], host: str):
        self.raw, self.config, self.host = raw, config, host
        self.notes: list[str] = list(raw.get("notes") or [])
        self.aliases: dict[str, dict[str, Any]] = {}
        self.vlan_names = {int(v["id"]): str(v.get("name") or "") for v in
                           items(member(member(raw.get("vlans"), "vlan"), "vlan-list"))
                           if str(v.get("id", "")).isdigit()}
        self.oper = {str(i.get("name")): i for i in items(member(member(raw.get("oper"), "interfaces"), "interface"))}
        self.ifaces = self._interfaces()
        acl_root = member(raw.get("acls"), "access-list") or {}
        self.extended = {str(a.get("name")): a for a in items(member(acl_root, "extended")) if a.get("name") is not None}
        self.standard = {str(a.get("name")): a for a in items(member(acl_root, "standard")) if a.get("name") is not None}
        self.groups = {str(g.get("name")): g for g in
                       items(member(member(raw.get("object_groups"), "object-group"), "network")) if g.get("name")}
        self.counters = self._counters()

    # -- interfaces ----------------------------------------------------------------------

    def _interfaces(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        root = member(self.raw.get("interfaces"), "interface") or {}

        def walk(kind: str, entries: Any) -> None:
            for entry in items(entries):
                if entry.get("name") is None:
                    continue
                ident = f"{kind}{entry['name']}"
                if not IFACE_ID_RE.match(ident):
                    continue
                out[ident] = self._interface(ident, kind, entry)

        for kind, value in (root.items() if isinstance(root, dict) else []):
            kind = str(kind).rpartition(":")[2]
            if isinstance(value, dict):  # e.g. Port-channel-subinterface: {"Port-channel": [...]}
                for inner, entries in value.items():
                    walk(str(inner).rpartition(":")[2], entries)
            else:
                walk(kind, value)
        return out

    def _interface(self, ident: str, kind: str, entry: dict[str, Any]) -> dict[str, Any]:
        ip = member(entry, "ip") or {}
        address = member(ip, "address") or {}
        found = []
        primary = member(address, "primary") or {}
        for item in [primary, *items(member(address, "secondary"))]:
            try:
                found.append(ipaddress.IPv4Interface(f"{item.get('address')}/{item.get('mask')}"))
            except (ValueError, TypeError, AttributeError):
                continue
        oper = self.oper.get(ident) or {}
        if not found and oper.get("ipv4") not in (None, "", "0.0.0.0"):  # a DHCP address
            with contextlib.suppress(ValueError):
                found.append(ipaddress.IPv4Interface(f"{oper['ipv4']}/{oper.get('ipv4-subnet-mask') or '32'}"))
        groups = member(ip, "access-group") or {}

        def bound(direction: str) -> str | None:
            side = member(groups, direction) or {}
            acl = member(side, "acl") or member(side, "common-acl") or {}
            name = acl.get("acl-name") if isinstance(acl, dict) else None
            if name is None:
                name = oper.get("input-security-acl" if direction == "in" else "output-security-acl") or None
            return str(name) if name not in (None, "") else None

        vrf = member(member(entry, "vrf"), "forwarding") or oper.get("vrf") or ""
        vlan = int(entry["name"]) if kind == "Vlan" and str(entry["name"]).isdigit() else None
        return {"id": ident, "kind": kind, "description": entry.get("description") or "", "addresses": found,
                "vrf": str(vrf), "shutdown": is_set(entry.get("shutdown")), "acl_in": bound("in"),
                "acl_out": bound("out"), "vlan": vlan, "zone": member(entry, "zone-member") is not None}

    def segments(self) -> list[dict[str, Any]]:
        """Interfaces that are segments: routed interfaces with an address, SVIs and interfaces with an ACL."""
        return [i for i in self.ifaces.values() if i["kind"] not in SKIP_TYPES
                and (i["addresses"] or i["kind"] == "Vlan" or i["acl_in"] or i["acl_out"])]

    def management(self, iface: dict[str, Any]) -> bool:
        return iface["vrf"].strip().lower() in MGMT_VRFS

    def holds(self, iface: dict[str, Any], address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in a.network for a in iface["addresses"])

    def role(self, iface: dict[str, Any]) -> str:
        if self.management(iface):
            return "mgmt"
        if iface["id"] == (self.config.get("wan_interface") or ""):
            return "wan"
        return "other"

    def self_addresses(self) -> list[str]:
        out = [str(a.ip) for i in self.ifaces.values() for a in i["addresses"]]
        with contextlib.suppress(ValueError):
            out.append(str(ipaddress.ip_address(self.host)))
        return list(dict.fromkeys(out))

    # -- addresses, aliases, services ---------------------------------------------------

    def alias(self, name: str, kind: str = "network", cidrs: list[str] | None = None, resolved: bool = False,
              ports: str | None = None) -> str:
        self.aliases.setdefault(name, {"name": name, "kind": kind, "cidrs": cidrs or [], "ports": ports,
                                       "resolved": resolved})
        return name

    def group_cidrs(self, name: str, depth: int = 0) -> list[str] | None:
        group = self.groups.get(name)
        if group is None or depth > 4:
            return None
        body = member(group, "obj-Mode-config-network-group") or {}
        cidrs: list[str] = []
        for entry in items(member(body, "network_address")):
            cidr = netmask_cidr(entry.get("ipv4_addr"), entry.get("ipv4_mask"))
            if cidr is None:
                return None
            cidrs.append(cidr)
        for entry in items(member(body, "host")):
            try:
                cidrs.append(f"{ipaddress.IPv4Address(str(entry.get('ipv4-host')))}/32")
            except ValueError:
                return None  # a host name: resolved by the device, not here
        for entry in items(member(body, "addr-ranges")):
            try:
                first = ipaddress.IPv4Address(str(entry.get("addr-range-start")))
                last = ipaddress.IPv4Address(str(entry.get("addr-range-end")))
                cidrs += [str(n) for n in ipaddress.summarize_address_range(first, last)]
            except (ValueError, TypeError):
                return None
        for entry in items(member(body, "group-objects")):
            nested = self.group_cidrs(str(entry.get("network-group") or ""), depth + 1)
            if nested is None:
                return None
            cidrs += nested
        return list(dict.fromkeys(cidrs))

    def group_alias(self, name: Any) -> str:
        name = str(name)
        cidrs = self.group_cidrs(name)
        return self.alias(name, "network", cidrs or [], cidrs is not None)

    def endpoint(self, ace: dict[str, Any], side: str) -> dict[str, Any]:
        """Source or destination of an extended entry (``side`` "src" / "dst")."""
        src = side == "src"
        if is_set(ace.get("any" if src else "dst-any")):
            return {"any": True}
        host = ace.get("host-address" if src else "dst-host-address") or ace.get("host" if src else "dst-host")
        if host is not None:
            try:
                return {"cidrs": [f"{ipaddress.IPv4Address(str(host).strip())}/32"]}
            except ValueError:
                return {"aliases": [self.alias(f"host {untrusted_text(host, 60)}", "host")]}
        address = ace.get("ipv4-address" if src else "dest-ipv4-address")
        if address is not None:
            mask = ace.get("mask" if src else "dest-mask") or "0.0.0.0"
            cidr = wildcard_cidr(address, mask)
            if cidr:
                return {"cidrs": [cidr]}
            return {"aliases": [self.alias(f"{untrusted_text(address, 40)} wildcard {untrusted_text(mask, 40)}",
                                           "other")]}
        group = ace.get("object-group" if src else "dst-object-group")
        if group is not None:
            return {"aliases": [self.group_alias(group)]}
        for key, kind in (("fqdn-group", "other"), ("geo-group", "geoip")):
            value = ace.get(f"{side}-{key}")
            if value is not None:
                return {"aliases": [self.alias(f"{key} {untrusted_text(value, 60)}", kind)]}
        return {"any": True}

    def std_endpoint(self, std: dict[str, Any]) -> dict[str, Any]:
        if is_set(std.get("any")):
            return {"any": True}
        host = std.get("host-address") or std.get("host")
        if host is not None:
            try:
                return {"cidrs": [f"{ipaddress.IPv4Address(str(host).strip())}/32"]}
            except ValueError:
                return {"aliases": [self.alias(f"host {untrusted_text(host, 60)}", "host")]}
        address = std.get("ipv4-address-prefix") or std.get("ipv4-prefix")
        if address is not None:
            mask = std.get("mask") or "0.0.0.0"
            cidr = wildcard_cidr(address, mask)
            return {"cidrs": [cidr]} if cidr else {"aliases": [self.alias(
                f"{untrusted_text(address, 40)} wildcard {untrusted_text(mask, 40)}", "other")]}
        return {"any": True}

    def services(self, ace: dict[str, Any], flags: set[str]) -> list[dict[str, Any]] | None:
        proto = str(ace.get("protocol") if ace.get("protocol") is not None else "ip").strip().lower()
        proto = PROTOCOL_NAMES.get(proto, proto)
        if proto == "object-group":
            name = str(ace.get("object-group-str") or "service group")
            self.alias(name, "port", [], False)
            return [{"proto": "any", "alias": name}]
        if proto in ("ip", "0"):
            return None
        if any(k.startswith("src-") and not k.endswith(("fqdn-group", "geo-group")) for k in ace):
            flags.add("source ports")
        if any(k in ace for k in ("established", "ack", "fin", "psh", "rst", "syn", "urg", "match-all", "match-any")):
            flags.add("tcp flags")
        if any(k in ace for k in ("dscp", "fragments", "option", "precedence", "tos", "ttl")):
            flags.add("other conditions")
        if proto in ("icmp", "1") and any(k in ace for k in ("msg-type", "msg-code", "named-msg-type")):
            flags.add("icmp types")
        if proto not in ("tcp", "udp", "6", "17"):
            return [{"proto": proto}]
        proto = {"6": "tcp", "17": "udp"}.get(proto, proto)
        values = [ace[k] for k in ["dst-eq", *(f"dst-eq-port{n}" for n in range(2, 11))] if ace.get(k) is not None]
        if values:
            out = []
            for value in values:
                number = port_number(value)
                out.append({"proto": proto, "ports": str(number)} if number else
                           {"proto": proto, "alias": f"port {untrusted_text(value, 30)}"})
            return out
        if ace.get("dst-range1") is not None:
            low, high = port_number(ace.get("dst-range1")), port_number(ace.get("dst-range2"))
            if low and high and low <= high:
                return [{"proto": proto, "ports": f"{low}-{high}" if low < high else str(low)}]
            return [{"proto": proto, "alias": "port range"}]
        if ace.get("dst-gt") is not None:
            number = port_number(ace["dst-gt"])
            return [{"proto": proto, "ports": f"{number + 1}-65535"}] if number and number < 65535 else \
                [{"proto": proto, "alias": "port gt"}]
        if ace.get("dst-lt") is not None:
            number = port_number(ace["dst-lt"])
            return [{"proto": proto, "ports": f"1-{number - 1}" if number - 1 > 1 else "1"}] if number and number > 1 \
                else [{"proto": proto, "alias": "port lt"}]
        neq = [ace[k] for k in ["dst-neq", *(f"dst-neq-port{n}" for n in range(2, 11))] if ace.get(k) is not None]
        if neq:
            numbers = [port_number(v) for v in neq]
            ports = _complement([n for n in numbers if n]) if all(numbers) else None
            return [{"proto": proto, "ports": ports}] if ports else [{"proto": proto, "alias": "port neq"}]
        return [{"proto": proto}]

    # -- access lists ------------------------------------------------------------------------

    def _counters(self) -> dict[tuple[str, str], int]:
        out = {}
        for acl in items(member(member(self.raw.get("counters"), "access-lists"), "access-list")):
            name = str(acl.get("access-control-list-name") or "")
            for entry in items(member(member(acl, "access-list-entries"), "access-list-entry")):
                data = member(entry, "access-list-entries-oper-data") or {}
                try:
                    out[(name, str(int(str(entry.get("rule-name")))))] = int(str(data.get("match-counter")))
                except (TypeError, ValueError):
                    continue
        return out

    def entries(self, name: str) -> tuple[str, list[dict[str, Any]]]:
        """("extended" | "standard" | "missing", entries sorted by sequence)."""
        for kind, table in (("extended", self.extended), ("standard", self.standard)):
            if name in table:
                rows = [e for e in items(member(table[name], "access-list-seq-rule"))
                        if str(e.get("sequence", "")).isdigit()]
                return kind, sorted(rows, key=lambda e: int(str(e["sequence"])))
        return "missing", []

    def acl_rules(self, name: str, kind: str, rows: list[dict[str, Any]], flags: set[str]) -> list[dict[str, Any]]:
        """The entries of one ACL as rules (without binding), each with "seq"; remarks become descriptions."""
        out, remarks = [], []
        for row in rows:
            seq = str(int(str(row["sequence"])))
            remark = row.get("remark")
            if kind == "extended":
                ace = member(row, "ace-rule")
                if not isinstance(ace, dict) or ace.get("action") not in ("permit", "deny"):
                    if row.get("evaluate") is not None:
                        flags.add("reflexive")
                    if remark is not None:
                        remarks.append(str(remark))
                    continue
                if ace.get("time-range") is not None:
                    flags.add("time ranges")
                rule = {"action": ace["action"], "source": self.endpoint(ace, "src"),
                        "destination": self.endpoint(ace, "dst"), "services": self.services(ace, flags),
                        "log": is_set(ace.get("log")) or is_set(ace.get("log-input"))}
            else:
                action = "permit" if isinstance(member(row, "permit"), dict) else \
                    "deny" if isinstance(member(row, "deny"), dict) else None
                if action is None:
                    if remark is not None:
                        remarks.append(str(remark))
                    continue
                std = member(member(row, action), "std-ace") or {}
                rule = {"action": action, "source": self.std_endpoint(std), "destination": {"any": True},
                        "services": None, "log": is_set(std.get("log"))}
            if remark is not None:
                remarks.append(str(remark))
            rule.update({"seq": seq, "description": " ".join(remarks), "hits": self.counters.get((name, seq))})
            remarks = []
            out.append(rule)
        return out

    def vty(self) -> tuple[list[str], list[str], bool, list[dict[str, Any]]]:
        """(ACLs bound inbound on VTY lines, management services, readable, lines without an access class)."""
        lines = items(member(member(self.raw.get("lines"), "line"), "vty"))
        acls, ports, open_lines = [], set(), []
        for line in lines:
            transport = member(member(line, "transport"), "input") or {}
            if is_set(transport.get("none")):
                continue
            if is_set(transport.get("all")):
                ports |= {22, 23}
            elif isinstance(transport.get("input"), list):
                ports |= {22 if p == "ssh" else 23 for p in transport["input"] if p in ("ssh", "telnet")}
            elif transport.get("ssh") is not False:
                ports.add(22)
            classes = member(line, "access-class") or {}
            found = [str(c.get("access-list")) for c in items(member(classes, "acccess-list") or
                                                               member(classes, "access-list"))
                     if c.get("direction") == "in" and c.get("access-list") is not None]
            if found:
                acls += [a for a in found if a not in acls]
            else:
                open_lines.append(line)
        services = [{"proto": "tcp", "ports": str(p)} for p in sorted(ports)]
        return acls, services, self.raw.get("lines") is not None, open_lines

    def http(self) -> tuple[str | None, list[dict[str, Any]], bool]:
        """(the HTTP server's access-class ACL, its services, readable)."""
        http = member(self.raw.get("http"), "http")
        if not isinstance(http, dict):
            return None, [{"proto": "tcp", "ports": "443"}], False
        group = member(http, "access-class-group") or {}
        ipv4 = member(group, "ipv4") or {}
        acl = group.get("access-list-number") or ipv4.get("ipv4-access-list-number") or ipv4.get("word") \
            or http.get("access-class")
        ports = []
        if http.get("secure-server") is not False:
            ports.append(str(port_number(http.get("secure-port")) or 443))
        if http.get("server") is not False:
            ports.append("80")
        return (str(acl) if acl is not None else None), [{"proto": "tcp", "ports": p} for p in ports], True

    def protected(self) -> dict[str, str]:
        """ACL name -> why Atrium never writes it (the management path)."""
        out: dict[str, str] = {}
        vty_acls = self.vty()[0]
        for name in vty_acls:
            out.setdefault(name, "it filters the VTY (SSH) lines")
        http_acl = self.http()[0]
        if http_acl:
            out.setdefault(http_acl, "it filters the HTTPS server (RESTCONF)")
        hub = str(self.config.get("hub_address") or "")
        for iface in self.ifaces.values():
            reason = ("it is on a management-VRF interface" if self.management(iface) else
                      "it is on the interface holding the device's management address" if self.holds(iface, self.host)
                      else "it is on the interface holding the hub's address" if hub and self.holds(iface, hub) else None)
            for acl in (iface["acl_in"], iface["acl_out"]):
                if reason and acl:
                    out.setdefault(acl, reason)
        return out


# --------------------------------------------------------------------------------------
# the connector
# --------------------------------------------------------------------------------------


class CiscoIosXeConnector(Connector):
    kind = "cisco_iosxe"
    title = "Cisco IOS-XE"
    description = ("Switch or router (RESTCONF): reads interfaces, VLANs / SVIs and the access lists bound to them "
                   "into the Network app; with device changes enabled and a NETCONF candidate datastore with "
                   "confirmed commit, adds one permit entry to an interface ACL under the change safety model.")
    fields = [
        ConnectorField(name="base_url", label="RESTCONF URL", kind="url", required=True, placeholder="https://10.0.99.2",
                       help="The device's https address ('ip http secure-server' and 'restconf' configured)."),
        ConnectorField(name="username", label="User", required=True, default="atrium",
                       help="A dedicated privilege-15 account (RESTCONF and NETCONF have no read-only role)."),
        ConnectorField(name="password", label="Password", kind="secret", required=True),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="Switch off only in a lab. Changing it means entering the password again."),
        ConnectorField(name="ca_file", label="CA certificate file", placeholder="/etc/atrium/iosxe-ca.pem",
                       help="PEM file on the hub with the device certificate or its CA (IOS-XE uses a self-signed "
                            "TP-self-signed certificate unless 'ip http secure-trustpoint' names a CA trustpoint)."),
        ConnectorField(name="device_kind", label="Device type", kind="select", default="auto",
                       choices=[{"value": "auto", "label": "Detect (switch when it has VLANs)"},
                                {"value": "switch", "label": "Switch"}, {"value": "router", "label": "Router"}]),
        ConnectorField(name="wan_interface", label="Internet-facing interface", kind="select", options=True,
                       help="Optional: the routed interface towards the internet (shown as the internet zone)."),
        ConnectorField(name="hub_address", label="Hub address as the device sees it", placeholder="10.0.99.10",
                       help="Optional. ACLs on the interface holding this address are never changed."),
        ConnectorField(name="netconf_port", label="NETCONF port", kind="number", default=830,
                       help="Device changes go over NETCONF (SSH, 'netconf-yang'), never over RESTCONF."),
        ConnectorField(name="host_key", label="NETCONF host key", placeholder="ssh-rsa AAAA...",
                       help="The device's SSH public host key (pinned). Empty: the hub user's known_hosts must hold it."),
        ConnectorField(name="known_hosts", label="known_hosts file", placeholder="~/.ssh/known_hosts",
                       help="Optional: a known_hosts file on the hub to verify the NETCONF host key with."),
        ConnectorField(name="confirm_timeout", label="Confirm window (seconds)", kind="number", default=DEFAULT_CONFIRM,
                       help="How long a change stays on the device before it reverts by itself, unless Atrium has "
                            "verified and confirmed it (60-600)."),
        ConnectorField(name="backup_filesystem", label="Backup file system", kind="select", default="bootflash:",
                       choices=[{"value": f, "label": f} for f in FILESYSTEMS],
                       help="Where 'copy running-config' keeps Atrium's backups on the device (atrium-<hash>.cfg)."),
        ConnectorField(name="save_config", label="Save to startup-config after a confirmed change", kind="bool",
                       default=True),
        ConnectorField(name="read_only", label="Read only", kind="bool", default=False,
                       help="Never change this device through this connection, even with device changes on."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "commit_confirm", "window_s": DEFAULT_CONFIRM}
    clock: Callable[[], float] = staticmethod(time.time)

    @classmethod
    def detect(cls, tool) -> int:
        return max(cls.name_score(tool, ("ios-xe", "iosxe", "ios xe"), score=90),
                   cls.name_score(tool, ("catalyst", "cisco"), score=60))

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        # where the password goes: the RESTCONF address and certificate checks, and the NETCONF host and host key
        return (super().endpoint(config) + f"|verify_tls={str(bool(config.get('verify_tls', True))).lower()}"
                f"|netconf_port={config.get('netconf_port') or 830}|host_key={config.get('host_key') or ''}"
                f"|known_hosts={config.get('known_hosts') or ''}")

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        config = dict(config)
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme != "https" or not parts.hostname:
            raise ConnectorError("The RESTCONF URL must start with https:// (the password travels in every request)")
        if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/restconf"):
            raise ConnectorError("The RESTCONF URL is the device address only (https://host[:port]); put the "
                                 "credentials in their own fields")
        try:
            parts.port
        except ValueError as exc:
            raise ConnectorError("The RESTCONF URL has an invalid port") from exc
        config["base_url"] = f"https://{parts.netloc}"
        ca_file = str(config.get("ca_file") or "").strip()
        if ca_file and not (os.path.isabs(ca_file) or PurePosixPath(ca_file).is_absolute()):
            raise ConnectorError("CA certificate file must be an absolute path on the hub's machine")
        hub_address = str(config.get("hub_address") or "").strip()
        if hub_address:
            try:
                config["hub_address"] = str(ipaddress.ip_address(hub_address))
            except ValueError as exc:
                raise ConnectorError("Hub address must be an IP address") from exc
        wan = str(config.get("wan_interface") or "").strip()
        if wan and not IFACE_ID_RE.match(wan):
            raise ConnectorError("Internet-facing interface must be an interface name such as GigabitEthernet0/0/0")
        config["wan_interface"] = wan or None
        timeout = int(config.get("confirm_timeout") or DEFAULT_CONFIRM)
        if not CONFIRM_RANGE[0] <= timeout <= CONFIRM_RANGE[1]:
            raise ConnectorError(f"The confirm window is {CONFIRM_RANGE[0]}-{CONFIRM_RANGE[1]} seconds")
        config["confirm_timeout"] = timeout
        if (config.get("backup_filesystem") or "bootflash:") not in FILESYSTEMS:
            raise ConnectorError(f"Backup file system is one of {', '.join(FILESYSTEMS)}")
        if (config.get("device_kind") or "auto") not in ("auto", "switch", "router"):
            raise ConnectorError("Device type is auto, switch or router")
        try:
            ssh = validate_ssh_config({"host": parts.hostname, "port": config.get("netconf_port") or 830,
                                       "username": config.get("username") or "", "host_key": config.get("host_key")})
        except ValueError as exc:
            raise ConnectorError(str(exc).replace("The SSH port", "The NETCONF port")) from exc
        config.update({"netconf_port": ssh["port"], "username": ssh["username"], "host_key": ssh["host_key"]})
        return config

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        spec = super().write_capability()
        return {**spec, "window_s": self.confirm_timeout} if spec else None

    @property
    def confirm_timeout(self) -> int:
        return int(self.config.get("confirm_timeout") or DEFAULT_CONFIRM)

    # -- RESTCONF ----------------------------------------------------------------------------

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
        if ca_file:  # self-signed device certificates are often not RFC 5280-strict; chain and host name still checked
            context.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        if not self.config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def client(self) -> httpx.AsyncClient:
        user, password = str(self.config.get("username") or ""), self.secrets.get("password")
        if not user or not password:
            raise self.error("Enter the IOS-XE user and password in the connection settings")
        verify: Any = True if isinstance(self.transport, httpx.AsyncBaseTransport) else self.ssl_context()
        return self.http(str(self.config.get("base_url") or "").rstrip("/") + REST,
                         auth=httpx.BasicAuth(user, password), verify=verify,
                         headers={"Accept": "application/yang-data+json"})

    async def _send(self, client: httpx.AsyncClient, method: str, path: str, *, what: str, body: Any = None,
                    params: dict[str, str] | None = None, timeout: float | None = None) -> httpx.Response:
        kwargs: dict[str, Any] = {"params": params}
        if body is not None:
            kwargs.update(content=json.dumps(body), headers={"Content-Type": "application/yang-data+json"})
        if timeout:
            kwargs["timeout"] = timeout
        try:
            return await client.request(method, path, **kwargs)
        except httpx.TimeoutException as exc:
            raise self.error(f"IOS-XE at {self.host}:{self.api_port} did not answer in time ({what})") from exc
        except httpx.ConnectError as exc:
            text = str(exc)
            if "CERTIFICATE_VERIFY_FAILED" in text or "certificate verify failed" in text.lower():
                raise TlsError(self.redact("The device's TLS certificate is not trusted - set the CA certificate "
                                           "file (the device certificate or its CA)")) from exc
            raise self.error(f"Cannot reach IOS-XE RESTCONF at {self.host}:{self.api_port} "
                             f"({exc.__class__.__name__})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach IOS-XE RESTCONF: {exc.__class__.__name__}") from exc

    @staticmethod
    def _error_text(response: httpx.Response) -> str:
        """The RFC 8040 error (tag and message) the device returned - device text, shortened."""
        try:
            answer = response.json()
        except ValueError:
            return ""
        errors = member(member(answer, "errors"), "error") if isinstance(answer, dict) else None
        first = items(errors)[0] if items(errors) else {}
        tag, message = first.get("error-tag"), first.get("error-message")
        return untrusted_text(" - ".join(str(p) for p in (tag, message) if p), 200)

    async def _call(self, client: httpx.AsyncClient, method: str, path: str, *, what: str, body: Any = None,
                    params: dict[str, str] | None = None, missing_ok: bool = False,
                    timeout: float | None = None) -> Any:
        """The JSON answer (None for 204, or for 404 with missing_ok: RESTCONF's "no such data"); ConnectorError
        otherwise."""
        response = await self._send(client, method, path, what=what, body=body, params=params, timeout=timeout)
        code = response.status_code
        if code == 401:
            raise self.error("IOS-XE rejected the user and password (HTTP 401)", status=401)
        if code == 403:
            raise self.error(f"IOS-XE refused access to {what} (HTTP 403) - RESTCONF needs a privilege-15 account "
                             "(NACM rules may also deny it)", status=403)
        if code == 404 and missing_ok:
            return None
        if code == 404:
            raise self.error(f"IOS-XE has no RESTCONF resource for {what} (HTTP 404) - is 'restconf' configured, and "
                             "does this release have the model?", status=404)
        if code in (301, 302, 303, 307, 308):
            raise self.error("IOS-XE redirected the request - use the device's https:// address", status=code)
        if code >= 300:
            message = self._error_text(response)
            raise self.error(f"IOS-XE could not {what} (HTTP {code}){': ' + message if message else ''}",
                             status=code, excerpt=response.text[:300])
        if code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise self.error(f"IOS-XE did not answer with JSON ({what}) - is the URL the RESTCONF device address?",
                             status=code) from exc

    async def _optional(self, client: httpx.AsyncClient, path: str, *, what: str,
                        params: dict[str, str] | None = None) -> tuple[Any, str | None]:
        """(answer, None) or (None, a note): for reads the snapshot can do without."""
        try:
            return await self._call(client, "GET", path, what=what, params=params, missing_ok=True), None
        except ConnectorError as exc:
            if exc.status is None or exc.status == 401 or isinstance(exc, TlsError):
                raise
            return None, f"{what}: not readable (HTTP {exc.status})"

    async def _operation(self, client: httpx.AsyncClient, path: str, what: str, body: dict[str, Any] | None = None,
                         timeout: float | None = None) -> dict[str, Any]:
        module = path.rsplit("/", 1)[1].split(":")[0]
        answer = await self._call(client, "POST", path, what=what, body={f"{module}:input": body or {}},
                                  timeout=timeout)
        output = member(answer, "output") if isinstance(answer, dict) else None
        return output if isinstance(output, dict) else {}

    # -- reading ---------------------------------------------------------------------------

    async def read(self, client: httpx.AsyncClient) -> dict[str, Any]:
        """Everything a snapshot needs, as the device answered it (untrusted)."""
        system = await self._call(client, "GET", SYSTEM, what="read the software version")
        version_text = member(member(system, "device-system-data"), "software-version") if system else None
        version = parse_version(version_text)
        if version is not None and version[0] < MIN_MAJOR:
            raise self.error(f"IOS XE {'.'.join(map(str, version))} is not supported: the YANG models Atrium reads "
                             f"came with IOS XE {MIN_MAJOR} (upgrade, or read the device another way)")
        notes = [] if version else ["the software version could not be read"]
        interfaces = await self._call(client, "GET", INTERFACES, what="read the interface configuration")
        acls = await self._call(client, "GET", ACLS, what="read the access lists", missing_ok=True)
        raw: dict[str, Any] = {"version": version, "version_text": untrusted_text(version_text, 300),
                               "interfaces": interfaces, "acls": acls, "notes": notes, "read_at": self.clock()}
        for key, path, what, params in (
                ("inventory", INVENTORY, "the chassis inventory", None),
                ("hostname", HOSTNAME, "the host name", None),
                ("vlans", VLANS, "VLANs", None),
                ("object_groups", OBJECT_GROUPS, "object groups", None),
                ("lines", LINES, "the VTY lines", None),
                ("http", HTTP_SERVER, "the HTTP server settings", None),
                ("counters", COUNTERS, "ACL hit counters", None)):
            raw[key], note = await self._optional(client, path, what=what, params=params)
            if note:
                notes.append(note)
        try:
            raw["oper"] = await self._call(client, "GET", OPER, what="interface state", params={"fields": OPER_FIELDS},
                                           missing_ok=True)
        except ConnectorError as exc:
            if exc.status is None or exc.status == 401 or isinstance(exc, TlsError):
                raise
            raw["oper"], note = await self._optional(client, OPER, what="interface state")
            if note:
                notes.append(note)
        return raw

    def revision(self, raw: dict[str, Any]) -> str:
        return derived_revision(raw.get("interfaces"), raw.get("acls"), raw.get("vlans"), raw.get("object_groups"),
                                raw.get("lines"), raw.get("http"), raw.get("hostname"))

    def to_record(self, raw: dict[str, Any]) -> dict[str, Any]:
        """The normalised device record (netmodel) for one read."""
        dev = Device(raw, self.config, self.host)
        notes, flags = dev.notes, set()
        segments = dev.segments()
        interfaces = []
        for iface in segments:
            vlan_name = dev.vlan_names.get(iface["vlan"] or 0, "")
            interfaces.append({"id": iface["id"], "name": vlan_name or iface["id"], "description": iface["description"],
                               "vlan": iface["vlan"], "subnets": list(dict.fromkeys(str(a.network) for a in iface["addresses"])),
                               "addresses": [str(a.ip) for a in iface["addresses"]], "role": dev.role(iface),
                               "enabled": not iface["shutdown"]})
        bindings: dict[str, dict[str, list[str]]] = {}
        for iface in segments:
            for direction in ("in", "out"):
                acl = iface[f"acl_{direction}"]
                if acl:
                    bindings.setdefault(acl, {"in": [], "out": []})[direction].append(iface["id"])
        vty_acls, vty_services, vty_read, open_lines = dev.vty()
        http_acl, http_services, http_read = dev.http()
        rules: list[dict[str, Any]] = []
        names = sorted(set(bindings) | set(vty_acls) | ({http_acl} if http_acl else set()))
        for index, name in enumerate(names):
            kind, rows = dev.entries(name)
            if kind == "missing":
                notes.append(f"an ACL bound on the device is not defined (it filters nothing): {untrusted_text(name, 64)}")
                continue
            base = dev.acl_rules(name, kind, rows, flags)
            uses = [("in", bindings.get(name, {}).get("in") or []), ("out", bindings.get(name, {}).get("out") or []),
                    ("vty", [] if name not in vty_acls else ["vty"]), ("http", ["http"] if name == http_acl else [])]
            primary = next((u for u, ifs in uses if ifs), None)
            for slot, (use, where) in enumerate(uses):
                if not where or (use == "vty" and not vty_services) or (use == "http" and not http_services):
                    continue  # nothing to bind to, or management access switched off (transport input none)
                suffix = "" if use == primary else f"@{use}"
                mgmt = use in ("vty", "http")
                order = (index * 4 + slot) * 100_000
                for position, entry in enumerate(base, start=1):
                    rule = {k: v for k, v in entry.items() if k != "seq"}
                    rule.update({"id": f"{name}:{entry['seq']}{suffix}", "vendor_ref": f"{name}:{entry['seq']}",
                                 "order": order + position, "enabled": True,
                                 "interfaces": [] if mgmt else where, "direction": "out" if use == "out" else "in"})
                    if mgmt:
                        rule["destination"] = {"self": True}
                        rule["services"] = vty_services if use == "vty" else http_services
                        if suffix:
                            rule["hits"] = None
                    elif suffix:
                        rule["hits"] = None  # the counter is per entry, shown once
                    rules.append(rule)
                rules.append({"id": f"{name}:implicit-deny{suffix}", "vendor_ref": f"{name}:implicit-deny",
                              "order": order + 99_999, "action": "block", "interfaces": [] if mgmt else where,
                              "direction": "out" if use == "out" else "in", "source": {"any": True},
                              "destination": {"self": True} if mgmt else {"any": True},
                              "services": (vty_services if use == "vty" else http_services) if mgmt else None,
                              "description": "implicit deny at the end of the access list"})
        base_order = (len(names) * 4 + 1) * 100_000
        if vty_read and open_lines and vty_services:
            rules.append({"id": "vty:no-access-class", "vendor_ref": "vty:no-access-class", "order": base_order + 1,
                          "action": "pass", "source": {"any": True}, "destination": {"self": True},
                          "services": vty_services,
                          "description": "implicit: VTY lines without an access-class accept SSH from any address"})
        if http_read and not http_acl and http_services:
            rules.append({"id": "http:no-access-class", "vendor_ref": "http:no-access-class", "order": base_order + 2,
                          "action": "pass", "source": {"any": True}, "destination": {"self": True},
                          "services": http_services,
                          "description": "implicit: the HTTP(S) server has no access-class and accepts any address"})
        if not vty_read:
            notes.append("VTY access classes not read: management access over SSH is not shown")
        unbound = [n for n in (*dev.extended, *dev.standard) if n not in names]
        if unbound:
            notes.append(f"{len(unbound)} access list(s) are not bound to an interface, the VTY lines or the HTTP "
                         "server and filter nothing (not shown)")
        open_ifs = [i["id"] for i in segments if not i["acl_in"] and not dev.management(i)]
        if open_ifs:
            notes.append(f"{len(open_ifs)} interface(s) have no inbound ACL: traffic entering them is forwarded "
                         "unfiltered by this device (the map shows ACL entries only)")
        layer2 = sorted(set(dev.vlan_names) - {i["vlan"] for i in segments if i["vlan"]})
        if layer2:
            notes.append(f"{len(layer2)} VLAN(s) have no SVI on this device (layer 2 only, not shown as segments)")
        if any(i["zone"] for i in dev.ifaces.values()):
            notes.append("zone-based firewall is configured: its zone-pair policies are not read (ACLs only)")
        for flag, text in (("source ports", "source-port conditions are not modelled (those entries are shown wider)"),
                           ("tcp flags", "TCP flag conditions ('established', syn, ...) are not modelled: those "
                                         "entries are shown as matching new connections too"),
                           ("other conditions", "dscp / precedence / ttl / fragment conditions are not modelled"),
                           ("icmp types", "ICMP type conditions are not modelled"),
                           ("time ranges", "time-based entries are shown as always active"),
                           ("reflexive", "reflexive (evaluate) entries are not read")):
            if flag in flags:
                notes.append(text)
        if not dev.counters:
            notes.append("hit counts are not available")
        notes.append("IPv6 access lists are not read")
        version = raw.get("version")
        inventory = next((i for i in items(member(raw.get("inventory"), "device-inventory"))
                          if i.get("hw-type") == "hw-type-chassis"), {})
        hostname = member(raw.get("hostname"), "hostname") if isinstance(raw.get("hostname"), dict) else None
        kind = self.config.get("device_kind") or "auto"
        if kind == "auto":
            kind = "switch" if dev.vlan_names or any(i["kind"] == "Vlan" for i in dev.ifaces.values()) else "router"
        return {
            "external_id": untrusted_text(hostname, 120) or self.host, "revision": self.revision(raw),
            "read_at": raw.get("read_at"), "kind": kind,
            "device": {"vendor": "Cisco", "model": untrusted_text(inventory.get("part-number"), 80),
                       "version": ".".join(map(str, version)) if version else "",
                       "hostname": untrusted_text(hostname, 120), "management_address": self.host,
                       "serial": untrusted_text(inventory.get("serial-number"), 80)},
            "interfaces": interfaces, "zones": [], "aliases": list(dev.aliases.values()),
            "self_addresses": dev.self_addresses(), "rules": rules,
            "default_policy": {"inbound": "pass", "forward": "pass", "outbound": "pass"},
            "nat_evaluated": False, "notes": notes[:50],
        }

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise self.error(f"IOS-XE cannot read {domain}")
        async with self.client() as client:
            return [self.to_record(await self.read(client))]

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name != "wan_interface":
            raise self.error(f"IOS-XE has no choices for '{field_name}'")
        async with self.client() as client:
            raw = {"interfaces": await self._call(client, "GET", INTERFACES, what="read the interface configuration")}
        dev = Device(raw, self.config, self.host)
        return [{"value": i["id"], "label": i["id"]} for i in dev.segments() if i["addresses"] and i["kind"] != "Vlan"]

    # -- NETCONF -----------------------------------------------------------------------------

    def netconf(self) -> Any:
        """A NETCONF session to the device (an async context manager), on the transport tests pass (``netconf``
        attribute) or the real one."""
        transport = getattr(self.transport, "netconf", None) or NETCONF
        target = ssh_target({"host": self.host, "port": self.config.get("netconf_port") or 830,
                             "username": self.config.get("username"), "host_key": self.config.get("host_key"),
                             "known_hosts": self.config.get("known_hosts")},
                            {"password": self.secrets.get("password", ""),
                             "private_key": ""}, command_timeout=RPC_TIMEOUT)
        return transport.session(target)

    @staticmethod
    def netconf_problem(session: NetconfSession) -> str | None:
        """Why this NETCONF server cannot take Atrium's changes, or None."""
        confirmed = session.has_prefix(CAP_CONFIRMED)
        if not session.has(CAP_CANDIDATE):
            return ("no candidate datastore: enable it with 'netconf-yang feature candidate-datastore' in a "
                    "maintenance window (it restarts NETCONF and RESTCONF)")
        if "1.1" not in confirmed:
            return ("confirmed commit 1.1 (persist) is not offered" + (f" (only {', '.join(confirmed)})" if confirmed
                                                                        else "") +
                    ": a confirmed commit would be undone when its session closes, and Atrium verifies over a new "
                    "connection")
        return None

    async def _netconf_features(self) -> tuple[dict[str, Any] | None, str]:
        """(write spec or None, a description) from the NETCONF hello."""
        try:
            async with self.netconf() as session:
                problem = self.netconf_problem(session)
                validate = session.has_prefix(CAP_VALIDATE)
        except (NetconfError, ConnectorError) as exc:
            return None, f"NETCONF on port {self.config.get('netconf_port') or 830}: {self.redact(exc.message)}"
        if problem:
            return None, "NETCONF: " + problem
        spec = {"ops": OPS, "rollback": "commit_confirm", "window_s": self.confirm_timeout}
        return spec, ("NETCONF: candidate datastore and confirmed commit 1.1 - a change reverts by itself after "
                      f"{self.confirm_timeout} s unless confirmed" + ("; validate" if validate else ""))

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
        verify = "verification is OFF - anyone on the path could read the password" \
            if not self.config.get("verify_tls", True) else \
            f"certificate verified with {self.config['ca_file']}" if self.config.get("ca_file") else \
            "certificate verified with the system's trusted CAs"
        where = f"{self.host}:{self.api_port}"
        async with client:
            try:
                system = await self._call(client, "GET", SYSTEM, what="read the software version")
            except TlsError as exc:
                checks += [check("reachability", True, f"{where} answers"), check("tls", False, exc.message)]
                return result(False, exc.message)
            except ConnectorError as exc:
                if exc.status is None:
                    checks.append(check("reachability", False, exc.message))
                    return result(False, exc.message)
                checks += [check("reachability", True, f"{where} answers"), check("tls", True, verify),
                           check("authentication", exc.status != 401, exc.message if exc.status == 401 else
                                 "the server answered, but not like IOS-XE RESTCONF: " + exc.message)]
                return result(False, exc.message)
            checks += [check("reachability", True, f"{where} answers RESTCONF"),
                       check("tls", bool(self.config.get("verify_tls", True)), verify),
                       check("authentication", True, f"user {self.config.get('username')} accepted")]
            version_text = member(member(system, "device-system-data"), "software-version") if system else None
            version = parse_version(version_text)
            record, read_error = None, None
            try:
                raw = await self.read(client)
                record = normalize_record(self.to_record(raw))
            except ConnectorError as exc:
                read_error = exc
            privileged = read_error is None or read_error.status not in (401, 403)
            checks.append(check("privileges", privileged, (
                f"reads the configuration; {LEAST_PRIVILEGE_NOTE}, but IOS-XE has none: RESTCONF and NETCONF require "
                "privilege 15 - keep the account dedicated, restrict its source addresses (ip http access-class) and "
                "keep device changes off until needed" if privileged else read_error.message)))
            supported = version is None or version[0] >= MIN_MAJOR
            vtext = ".".join(map(str, version)) if version else "unknown"
            checks.append(check("version", supported, f"IOS XE {vtext} - " + (
                "supported (paths checked against the 17.15 YANG models; older releases may lack some fields)"
                if version and supported else f"not supported: Atrium needs IOS XE {MIN_MAJOR} or later" if version
                else "the version string was not recognised")))
            write, features = None, "NETCONF not checked: this connection is read only"
            if self.write_capability() is not None:
                write, features = await self._netconf_features()
            sync_note = await self._sync_note(client)
            has_counters = record is not None and any(r.get("hits") is not None for r in record["rules"])
            checks.append(check("api_features", True, "RESTCONF reads; hit counters: " +
                                ("yes" if has_counters else "no") + "; " + features + (f"; {sync_note}" if sync_note
                                                                                       else "")))
            if record is not None:
                acls = len({r["vendor_ref"].rsplit(":", 1)[0] for r in record["rules"] if ":" in r["vendor_ref"]
                            and not r["vendor_ref"].startswith(("vty:", "http:"))})
                checks.append(check("ruleset", True, f"{len(record['rules'])} rules from {acls} bound access list(s), "
                                                     f"{len(record['interfaces'])} interfaces read"
                                    + (f"; {len(record['errors'])} entries skipped" if record["errors"] else "")))
                protected = Device(raw, self.config, self.host).protected()
                hints = [] if self.config.get("hub_address") else ["set the hub address to protect its interface too"]
                try:
                    ipaddress.ip_address(self.host)
                except ValueError:
                    hints.append("the RESTCONF address is a DNS name, so the interface holding it is not recognised")
                checks.append(check("management_guard", True,
                                    f"{len(protected)} access list(s) on the management path are never changed (VTY "
                                    "lines, HTTP server, management VRF, interfaces holding the device's management "
                                    "address or the hub's address)" + "".join(f"; {h}" for h in hints)))
            elif read_error is not None:
                checks.append(check("ruleset", False, read_error.message))
        ok = record is not None and supported
        what = f"IOS XE {vtext}" + (f" ({record['device']['hostname']})" if record and record["device"]["hostname"]
                                     else "")
        if ok:
            detail = f"Connected to {what}: {len(record['rules'])} rules" + ("" if write else " (read only)")
        else:
            detail = f"{what}: " + next((c["detail"] for c in checks if not c["ok"]), "cannot read the configuration")
        return result(ok, detail, write)

    async def _sync_note(self, client: httpx.AsyncClient) -> str | None:
        try:
            state = await self._operation(client, IS_SYNCING, "check the configuration sync")
        except ConnectorError:
            return None
        if state.get("syncing") or state.get("syncs-pending"):
            return "the device is syncing CLI changes into its configuration database (changes wait for it)"
        if state.get("candidate-datastore-dirty"):
            return "the candidate datastore holds uncommitted changes from another session"
        return "configuration database in sync"

    # -- backups -----------------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self.client() as client:
            raw = await self.read(client)
            output = await self._operation(client, CLI_CONFIG, "read the running configuration",
                                           {"datastore": "running"}, timeout=ROLLBACK_TIMEOUT)
            text = output.get("result")
            if not isinstance(text, str) or not text.strip():
                message = untrusted_text(output.get("error-message"), 160)
                raise self.error("IOS-XE returned no configuration text" + (f": {message}" if message else ""))
            name = f"{self.config.get('backup_filesystem') or 'bootflash:'}atrium-" \
                   f"{hashlib.sha256(text.encode('utf-8')).hexdigest()[:16]}.cfg"
            copy = {"source-drop-node-name": "running-config", "destination-drop-node-name": name}
            try:
                await self._operation(client, COPY, "copy the running configuration to a file", copy,
                                      timeout=ROLLBACK_TIMEOUT)
            except ConnectorError as first:
                # UNVERIFIED: whether copy overwrites an existing file; the name holds the content's hash, so the
                # file there is an earlier copy of the same configuration - replace it once
                try:
                    await self._operation(client, DELETE, "delete the old backup file",
                                          {"filename-drop-node-name": name})
                    await self._operation(client, COPY, "copy the running configuration to a file", copy,
                                          timeout=ROLLBACK_TIMEOUT)
                except ConnectorError:
                    raise self.error(f"IOS-XE could not keep the full configuration in {name} (is the file system "
                                     f"full?): {first.message}") from first
        return {"content": text, "format": "text", "device_backup_id": name, "revision": self.revision(raw)}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        if self.write_capability() is None:
            raise self._fail("This connection is read only", code="unsupported", state="unchanged")
        target = str(backup.device_backup_id or "")
        if not FILE_RE.match(target):
            raise self._fail("This backup has no configuration file on the device to replace the running "
                             "configuration with - restore it by hand", code="unsupported", state="unchanged")
        try:
            async with self.client() as client:
                output = await self._operation(client, ROLLBACK, "replace the running configuration",
                                               {"target-url": target, "revert-on-error": [None]},
                                               timeout=ROLLBACK_TIMEOUT)
        except ConnectorError as exc:
            state = "unchanged" if exc.status and exc.status < 500 else "unknown"
            raise self._fail(f"The configuration replace failed: {exc.message}", code="failed", state=state) from exc
        notes = [f"replaced the running configuration with {target} (configure replace, revert on error)",
                 "not saved to startup-config: a reload returns to the saved configuration"]
        result = untrusted_text(output.get("result"), 160)
        if result:
            notes.append(f"device: {result}")
        return {"restored": True, "revision": None, "notes": notes}

    # -- changes -----------------------------------------------------------------------------

    def _plan(self, ops: list[dict[str, Any]], raw: dict[str, Any]
              ) -> tuple[list[dict[str, Any]], list[str], list[str], bool]:
        """(entries to write, problems, notes, whether the management-path guard refused) for allow ops against one
        read of the device."""
        dev = Device(raw, self.config, self.host)
        segments = {i["id"]: i for i in dev.segments()}
        protected = dev.protected()
        plan, problems, notes, guarded = [], [], [], False
        taken: dict[str, set[int]] = {}
        for index, op in enumerate(ops):
            n = index + 1
            if op["op"] not in OPS:
                problems.append(f"operation {n}: IOS-XE access list entries cannot be disabled or enabled (there is "
                                "no disabled state) - only 'allow' is offered")
                continue
            source, destination = segments.get(op["source"]["zone"]), segments.get(op["destination"]["zone"])
            for side, found in (("source", source), ("destination", destination)):
                if found is None:
                    problems.append(f"operation {n}: the device has no routed interface or SVI "
                                    f"'{display_id(op[side]['zone'])}'")
            if source is None or destination is None:
                continue
            if dev.management(source):
                guarded = True
                problems.append(f"operation {n}: {source['id']} is a management-VRF interface (the management path) "
                                "- Atrium never changes it")
                continue
            acl = source["acl_in"]
            if not acl:
                problems.append(f"operation {n}: {source['id']} has no inbound ACL - traffic entering it is not "
                                "filtered here, and Atrium never creates or binds access lists")
                continue
            kind, rows = dev.entries(acl)
            if kind != "extended":
                problems.append(f"operation {n}: the inbound ACL of {source['id']} is "
                                + ("not defined" if kind == "missing" else "a standard ACL (source only)")
                                + " - Atrium adds entries to extended ACLs only")
                continue
            if not ACL_NAME_RE.match(acl):
                problems.append(f"operation {n}: the ACL name has characters Atrium does not write")
                continue
            if acl in protected:
                guarded = True
                problems.append(f"operation {n}: the ACL of {source['id']} is on the management path "
                                f"({protected[acl]}) - Atrium never changes it")
                continue
            ace, why = self._ace(op)
            if ace is None:
                problems.append(f"operation {n}: {why}")
                continue
            used = taken.setdefault(acl, {int(str(r["sequence"])) for r in rows})
            sequences = self._position(rows, used)
            if sequences is None:
                problems.append(f"operation {n}: no free sequence numbers before the first deny entry of the ACL on "
                                f"{source['id']} - resequence it on the device ('ip access-list resequence')")
                continue
            used.update(sequences)
            remark = f"{op['marker']} {op.get('description') or ''}".strip()[:100]
            plan.append({"op": index, "acl": acl, "remark_seq": sequences[0], "seq": sequences[1], "ace": ace,
                         "remark": remark, "interface": source["id"]})
            others = [i for i in segments.values() if i["id"] != source["id"] and acl in (i["acl_in"], i["acl_out"])]
            if others:
                notes.append(f"operation {n}: the ACL is also bound to {', '.join(i['id'] for i in others)} - the "
                             "entry applies there too")
            if destination["acl_out"]:
                notes.append(f"operation {n}: {destination['id']} also filters outbound traffic - the traffic may "
                             "still be blocked there")
            subnets = [a.network for a in source["addresses"]]
            if subnets and not all(any(ipaddress.ip_network(c).subnet_of(s) for s in subnets
                                       if ipaddress.ip_network(c).version == s.version) for c in op["source"]["cidrs"]):
                notes.append(f"operation {n}: the source network is not one of {source['id']}'s own subnets")
        return plan, problems, notes, guarded

    @staticmethod
    def _ace(op: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """The ace-rule leaves for an allow op (one entry), or (None, why not)."""
        if len(op["source"]["cidrs"]) != 1 or len(op["destination"]["cidrs"]) != 1:
            return None, "one source and one destination network per change on IOS-XE (an ACL entry has one each)"
        cidrs = [op["source"]["cidrs"][0], op["destination"]["cidrs"][0]]
        if any(ipaddress.ip_network(c).version != 4 for c in cidrs):
            return None, "IPv4 networks only (IPv6 access lists are not read or changed)"
        protocols = {s["proto"] for s in op["services"]}
        if len(protocols) != 1:
            return None, "one protocol per change on IOS-XE (an ACL entry matches one protocol)"
        proto = protocols.pop()
        ace: dict[str, Any] = {"action": "permit", "protocol": proto}
        for key, cidr in (("src", cidrs[0]), ("dst", cidrs[1])):
            address, wildcard = to_wildcard(cidr)
            if ipaddress.ip_network(cidr).prefixlen == 32:
                ace["host-address" if key == "src" else "dst-host-address"] = address
            else:
                ace.update({"ipv4-address": address, "mask": wildcard} if key == "src" else
                           {"dest-ipv4-address": address, "dest-mask": wildcard})
        if proto in ("tcp", "udp"):
            ports = [s["ports"] for s in op["services"]]
            if len(ports) == 1 and "-" in ports[0] and "," not in ports[0]:
                low, high = ports[0].split("-")
                ace.update({"dst-range1": int(low), "dst-range2": int(high)})
            elif all(p.isdigit() for p in ports) and len(set(ports)) == len(ports) <= 10:
                for i, port in enumerate(sorted(ports, key=int)):
                    ace["dst-eq" if i == 0 else f"dst-eq-port{i + 1}"] = int(port)
            else:
                return None, ("ports: up to 10 single ports as separate services, or one range (an ACL entry cannot "
                              "hold a list of ranges)")
        elif len(op["services"]) != 1:
            return None, "one ICMP service per change"
        if op.get("log", True):
            ace["log"] = [None]
        return ace, ""

    @staticmethod
    def _position(rows: list[dict[str, Any]], used: set[int]) -> tuple[int, int] | None:
        """Two free sequence numbers (remark, entry) right after the leading permit entries: before the first entry
        that could block (deny, evaluate) and before the remarks that describe it. `used` holds the numbers taken,
        including entries planned earlier in the same change."""

        def plain_remark(row: dict[str, Any]) -> bool:
            return not isinstance(member(row, "ace-rule"), dict) and row.get("remark") is not None \
                and row.get("evaluate") is None

        def permit(row: dict[str, Any]) -> bool:
            ace = member(row, "ace-rule")
            return isinstance(ace, dict) and ace.get("action") == "permit"

        target = next((i for i, row in enumerate(rows) if not (permit(row) or plain_remark(row))), len(rows))
        while target > 0 and plain_remark(rows[target - 1]):
            target -= 1
        lower = int(str(rows[target - 1]["sequence"])) if target else 0
        upper = int(str(rows[target]["sequence"])) if target < len(rows) else 2147483648
        lower = max([lower, *(s for s in used if lower < s < upper)])
        first = lower + 1 if lower or rows else 10
        if first + 1 >= upper or {first, first + 1} & used:
            return None
        return first, first + 1

    def _token(self, info: dict[str, Any]) -> str:
        token = TOKEN_PREFIX + base64.urlsafe_b64encode(json.dumps(info, separators=(",", ":")).encode()).decode()
        if len(token) > MAX_TOKEN:
            raise self._fail("The change is too large to track", code="invalid", state="unchanged")
        return token

    def _parse_token(self, token: str) -> dict[str, Any]:
        try:
            if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > MAX_TOKEN:
                raise ValueError
            info = json.loads(base64.urlsafe_b64decode(token[len(TOKEN_PREFIX):].encode()))
            assert isinstance(info, dict) and PERSIST_RE.match(str(info.get("persist")))
            assert isinstance(info.get("until"), (int, float))
            entries = info.get("entries")
            assert isinstance(entries, list) and 1 <= len(entries) <= 20
            for acl, remark_seq, seq, marker_id in entries:
                assert ACL_NAME_RE.match(str(acl)) and MARKER_RE.fullmatch(f"atrium:{marker_id}")
                assert all(isinstance(s, int) and 1 <= s <= 2147483647 for s in (remark_seq, seq))
        except (ValueError, TypeError, AssertionError, UnicodeError):
            raise self._fail("Not a change token of this connector", code="invalid", state="unknown") from None
        return info

    def _fail(self, message: str, *, code: str, state: str) -> ChangeError:
        """A ChangeError whose message (which may quote the device's own error text) has this connection's secrets
        masked."""
        return ChangeError(self.redact(message), code=code, state=state)

    def _writable(self) -> None:
        if self.write_capability() is None:
            raise self._fail("This connection is read only", code="unsupported", state="unchanged")

    async def _session_ready(self, session: NetconfSession) -> None:
        problem = self.netconf_problem(session)
        if problem:
            raise self._fail(f"IOS-XE cannot take guarded changes: {problem}", code="unsupported", state="unchanged")

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        problems, notes = [], []
        if self.write_capability() is None:
            problems.append("this connection is read only")
        async with self.client() as client:
            raw = await self.read(client)
        record = normalize_record(self.to_record(raw))
        plan, found, more, _ = self._plan(ops, raw)
        problems += found
        notes += more
        if record["revision"] != (snapshot or {}).get("revision"):
            notes.append("the device changed since the snapshot this preview was made from - refresh before approving")
        if self.write_capability() is not None:
            write, features = await self._netconf_features()
            if write is None:
                problems.append(features)
        notes.append(f"the device reverts the change by itself after {self.confirm_timeout} s unless Atrium confirms "
                     "it (NETCONF confirmed commit)")
        steps = [{"op": p["op"], "kind": "add_rule",
                  "position": f"ACL on {p['interface']} (inbound), sequence {p['seq']} after the leading permits",
                  "detail": f"remark {p['remark_seq']} '{p['remark']}', then {self._ace_text(p['ace'])}"} for p in plan]
        return {"steps": steps, "notes": notes, "problems": problems}

    @staticmethod
    def _ace_text(ace: dict[str, Any]) -> str:
        def side(prefix: str) -> str:
            host = ace.get("host-address" if prefix == "src" else "dst-host-address")
            if host:
                return f"host {host}"
            return f"{ace['ipv4-address']} {ace['mask']}" if prefix == "src" else \
                f"{ace['dest-ipv4-address']} {ace['dest-mask']}"

        ports = [str(ace[k]) for k in ["dst-eq", *(f"dst-eq-port{n}" for n in range(2, 11))] if k in ace]
        port_text = f" eq {' '.join(ports)}" if ports else \
            f" range {ace['dst-range1']} {ace['dst-range2']}" if "dst-range1" in ace else ""
        return f"permit {ace['protocol']} {side('src')} {side('dst')}{port_text}" + (" log" if "log" in ace else "")

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        ops = parse_ops(ops)
        self._writable()
        timeout = self.confirm_timeout
        try:
            client = self.client()
        except ConnectorError as exc:
            raise self._fail(exc.message, code="unreachable", state="unchanged") from exc
        try:
            async with client, self.netconf() as session:
                return await self._apply(client, session, ops, base_revision, timeout)
        except ChangeError:
            raise
        except (NetconfError, ConnectorError) as exc:  # before the commit: _apply turns every later failure into one
            raise self._fail(f"Cannot change the device: {self.redact(exc.message)}", code="unreachable",
                             state="unchanged") from exc

    async def _apply(self, client: httpx.AsyncClient, session: NetconfSession, ops: list[dict[str, Any]],
                     base_revision: str, timeout: int) -> dict[str, Any]:
        await self._session_ready(session)
        committed = locked = False
        try:
            try:
                await lock_candidate(session)
            except NetconfError as exc:
                raise self._fail(f"The candidate datastore is locked by another session ({exc.message}) - try again "
                                 "later", code="failed", state="unchanged") from exc
            locked = True
            try:
                raw = await self.read(client)
            except ConnectorError as exc:
                raise self._fail(exc.message, code="failed" if isinstance(exc, NetconfError) else "unreachable",
                                 state="unchanged") from exc
            record = normalize_record(self.to_record(raw))
            if record["revision"] != base_revision:
                raise self._fail("The device's configuration changed since the change was approved - re-read it and "
                                 "preview again", code="stale", state="unchanged")
            plan, problems, _, guarded = self._plan(ops, raw)
            if problems:
                raise self._fail("Refused: " + "; ".join(problems), code="lockout" if guarded else "invalid",
                                 state="unchanged")
            if len(plan) != len(ops):
                raise self._fail("Refused: not every operation could be planned", code="invalid", state="unchanged")
            state = await self._operation_or_none(client, IS_SYNCING)
            if state and (state.get("syncing") or state.get("syncs-pending")):
                raise self._fail("The device is syncing CLI changes into its configuration database - try again in "
                                 "a minute", code="failed", state="unchanged")
            by_acl: dict[str, list[dict[str, Any]]] = {}
            for item in plan:
                by_acl.setdefault(item["acl"], []).append(item)
            try:
                for acl, entries in by_acl.items():
                    body = "".join(entry_xml(e["remark_seq"], "create", f"<remark>{_x(e['remark'])}</remark>") +
                                   entry_xml(e["seq"], "create", ace_xml(e["ace"])) for e in entries)
                    await session.rpc(acl_edit(acl, body))
                if session.has_prefix(CAP_VALIDATE):
                    await session.rpc(VALIDATE)
            except NetconfError as exc:
                raise self._fail(f"The device refused the change: {exc.message}", code="failed",
                                 state="unchanged") from exc
            persist = pysecrets.token_hex(16)
            started = self.clock()
            try:
                await session.rpc(f"<commit><confirmed/><confirm-timeout>{timeout}</confirm-timeout>"
                                  f"<persist>{persist}</persist></commit>", timeout=RPC_TIMEOUT + 30)
            except NetconfError as exc:
                if exc.tag is None:  # the session broke: the commit may or may not have happened
                    raise self._fail(f"The NETCONF session broke during the commit ({exc.message}); if the device "
                                     f"committed, it reverts by itself within {timeout} s", code="failed",
                                     state="unknown") from exc
                raise self._fail(f"The device refused the commit: {exc.message}", code="failed",
                                 state="unchanged") from exc
            committed = True
        finally:
            if locked and not committed:
                with contextlib.suppress(Exception):
                    await session.rpc(DISCARD, timeout=10)
            if locked:
                with contextlib.suppress(Exception):
                    await session.rpc(UNLOCK, timeout=10)
        until = started + timeout
        info = {"persist": persist, "until": until,
                "entries": [[p["acl"], p["remark_seq"], p["seq"], find_marker(p["remark"])] for p in plan]}
        created = [{"op": p["op"], "id": f"{p['acl']}:{p['seq']}", "vendor_ref": f"{p['acl']}:{p['seq']}"}
                   for p in plan]
        return {"token": self._token(info), "rollback_until": until, "revision": None, "created": created,
                "disabled": [], "enabled": [],
                "notes": [f"confirmed commit: the device reverts by itself after {timeout} s unless confirmed"]}

    async def _operation_or_none(self, client: httpx.AsyncClient, path: str) -> dict[str, Any] | None:
        try:
            return await self._operation(client, path, "check the configuration sync")
        except ConnectorError:
            return None

    async def confirm_change(self, token: str) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.netconf() as session:
                try:
                    await lock_candidate(session)
                except NetconfError as exc:
                    raise self._fail(f"The candidate datastore is locked by another session ({exc.message}); the "
                                     "device reverts the change by itself when the window ends", code="failed",
                                     state="unknown") from exc
                try:
                    await session.rpc(f"<commit><persist-id>{info['persist']}</persist-id></commit>")
                except NetconfError as exc:
                    passed = self.clock() >= info["until"]
                    raise self._fail(
                        "Nothing to confirm: the confirm window passed and the device reverted the change" if passed
                        else f"The device refused the confirming commit ({exc.message}); it reverts the change by "
                             "itself when the window ends", code="failed",
                        state="rolled_back" if passed else "unknown") from exc
                finally:
                    with contextlib.suppress(Exception):
                        await session.rpc(UNLOCK, timeout=10)
        except (NetconfError, ConnectorError) as exc:
            if isinstance(exc, ChangeError):
                raise
            raise self._fail(f"Cannot confirm over NETCONF: {self.redact(exc.message)}; the device reverts the change "
                             "by itself when the window ends", code="unreachable", state="unknown") from exc
        notes = []
        if self.config.get("save_config", True):
            try:
                async with self.client() as client:
                    await self._operation(client, SAVE_CONFIG, "save the configuration", timeout=ROLLBACK_TIMEOUT)
                notes.append("saved to startup-config")
            except ConnectorError as exc:
                notes.append(f"confirmed, but not saved to startup-config ({exc.message}) - a reload would lose it")
        else:
            notes.append("not saved to startup-config (the connection's setting)")
        return {"confirmed": True, "revision": None, "notes": notes}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        info = self._parse_token(token)
        try:
            async with self.netconf() as session:
                try:
                    await session.rpc(f"<cancel-commit><persist-id>{info['persist']}</persist-id></cancel-commit>")
                    return {"rolled_back": True, "method": "commit_confirm", "notes": ["the confirmed commit was "
                                                                                       "cancelled"]}
                except NetconfError:
                    pass  # nothing pending: the window passed (reverted) or the change was confirmed
                async with self.client() as client:
                    raw = await self.read(client)
                dev = Device(raw, self.config, self.host)
                present = []
                for acl, remark_seq, seq, change_id in info["entries"]:
                    rows = {int(str(r["sequence"])): r for r in dev.entries(acl)[1]}
                    remark = rows.get(remark_seq, {}).get("remark")
                    if seq in rows or remark_seq in rows:
                        if find_marker(remark) != change_id:
                            raise self._fail("The entries Atrium created no longer carry its marker - not removing "
                                             "them", code="failed", state="applied")
                        present.append((acl, remark_seq, seq))
                if not present:
                    return {"rolled_back": True, "method": "commit_confirm",
                            "notes": ["the device had already reverted the change"]}
                await self._remove(session, present)
                return {"rolled_back": True, "method": "inverse_ops",
                        "notes": ["the change was already confirmed; the entries Atrium created were removed"]}
        except ChangeError:
            raise
        except (NetconfError, ConnectorError) as exc:
            raise self._fail(f"Cannot roll back over NETCONF: {self.redact(exc.message)}", code="unreachable",
                             state="unknown") from exc

    async def _remove(self, session: NetconfSession, present: list[tuple[str, int, int]]) -> None:
        problem = self.netconf_problem(session)
        if problem:
            raise self._fail(f"IOS-XE cannot remove the entries: {problem}", code="unsupported", state="applied")
        try:
            await lock_candidate(session)
        except NetconfError as exc:
            raise self._fail(f"The candidate datastore is locked by another session ({exc.message})", code="failed",
                             state="applied") from exc
        committed = False
        try:
            by_acl: dict[str, list[int]] = {}
            for acl, remark_seq, seq in present:
                by_acl.setdefault(acl, []).extend([remark_seq, seq])
            for acl, sequences in by_acl.items():
                await session.rpc(acl_edit(acl, "".join(entry_xml(s, "remove") for s in sequences)))
            await session.rpc("<commit/>")
            committed = True
        except NetconfError as exc:
            raise self._fail(f"The device refused removing the entries: {exc.message}", code="failed",
                             state="applied") from exc
        finally:
            if not committed:
                with contextlib.suppress(Exception):
                    await session.rpc(DISCARD, timeout=10)
            with contextlib.suppress(Exception):
                await session.rpc(UNLOCK, timeout=10)


__all__ = ["CiscoIosXeConnector", "NetconfSession", "NetconfError", "AsyncsshNetconf", "Device", "parse_version",
           "wildcard_cidr"]
