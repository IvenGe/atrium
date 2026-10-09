"""The ``network`` domain: what network connectors read (the normalised device record) and what write-capable ones
receive (change operations), plus helpers shared by connectors and the hub. ``base.py`` documents the connector
methods; this module holds the shapes. Connectors import from here::

    from .netmodel import ChangeError, NetworkRecord, parse_ops, marker, rule_line, management_guard

Reading - ``pull("network")`` returns a list with exactly ONE record: the device the connection reaches (one
connection per device; the hub keeps only the first record of a longer list and says so in the snapshot's errors).
Every key below is validated by ``NetworkRecord`` when the hub normalises the pull (unknown keys are dropped, bad
entries are dropped with a message, strings are cut to length and stripped of control characters). Text read from a
device (names, descriptions, comments, alias names) is UNTRUSTED: the hub never renders it as HTML, never builds
commands from it and never hands it to agent/LLM tools; connectors must not either (quote or validate anything
device-provided before it goes near a shell or an API path).

::

    {"external_id": "fw1",                      # stable device id (serial, hostname); the hub's device id is the
                                                #   tool id of the connection
     "revision": "r-5521",                      # opaque config/ruleset revision as the device reports it (or a hash
                                                #   of what was read); changes bind to it (apply_change base_revision)
     "read_at": 1760000000.0,
     "kind": "firewall",                        # firewall | router | switch | host
     "device": {"vendor": "OPNsense", "model": "", "version": "26.7.6", "hostname": "fw1",
                "management_address": "10.0.99.1", "serial": ""},
     "interfaces": [{"id": "lan", "name": "LAN", "description": "", "vlan": None, "subnets": ["10.0.10.0/24"],
                     "addresses": ["10.0.10.1"], "role": "lan", "enabled": True}],   # role: lan | wan | mgmt | other
     "zones": [{"id": "trusted", "name": "Trusted", "interfaces": ["lan", "opt1"], "description": ""}],
                                                # vendor zones; empty: every interface acts as a zone
     "aliases": [{"name": "MGMT_NET", "kind": "network", "cidrs": ["10.0.99.0/24"], "ports": None,
                  "resolved": True}],           # kind: network | host | port | url | geoip | other; unresolved
                                                #   (URL tables, GeoIP, nested beyond reach): resolved False
     "self_addresses": ["10.0.10.1", "203.0.113.4"],   # addresses that reach the device itself
     "rules": [{"id": "7c1d", "vendor_ref": "7c1d-...-uuid", "order": 12, "enabled": True, "action": "pass",
                "interfaces": ["wan"], "out_interfaces": [], "source_zones": [], "destination_zones": [],
                "floating": False, "direction": "in", "quick": True,
                "source": {"any": True},
                "destination": {"cidrs": ["10.0.99.0/24"], "aliases": ["MGMT_NET"]},
                "services": [{"proto": "tcp", "ports": "443"}], "log": False,
                "description": "vCenter from outside", "hits": 1532}],
     "default_policy": {"inbound": "block"},    # what happens without a matching rule, per chain/direction:
                                                #   inbound | outbound | forward -> pass | block | reject | unknown
     "nat_evaluated": False,
     "notes": ["hit counts are not available on this version"]}

Rules:
- ``id`` is unique within the record and stable across reads; ``vendor_ref`` is the stable NATIVE id used to address
  the rule on the device (OPNsense uuid, FortiGate policyid, PAN-OS rule name, IOS-XE "<ACL name>:<sequence>", nft
  handle, ufw "<number>|<tuple>", firewalld "<zone>|<rich rule>", Windows rule Name). Defaults to ``id``.
- ``order`` is the global evaluation order (lower first). ``interfaces`` are ingress interfaces (pf "on <if>",
  FortiGate srcintf, an ACL bound inbound); ``out_interfaces`` egress ones (FortiGate dstintf, nft oifname);
  ``source_zones`` / ``destination_zones`` vendor zone ids (PAN-OS from/to). A rule bound to nothing is floating.
  ``direction`` (pf): in | out | any; for ``out`` the interfaces constrain the destination.
- Endpoints: ``any``; ``cidrs`` (networks or single addresses, normalised); ``aliases`` (names from ``aliases``);
  ``nets`` (interface ids: "the network of this interface", pf "LAN net"); ``self`` (the device itself, pf "This
  Firewall", an nft input chain); ``negate``. An endpoint with nothing set means any.
- ``services``: None = any service. Each ``{"proto", "ports", "alias", "name"}``: proto ``tcp``, ``udp``, ``icmp``,
  ``icmpv6`` or another IP protocol name (``tcp/udp`` is split in two); ports ``"443"``, ``"8000-8080"``,
  ``"80,443"`` or None (any port); ``alias`` names a port alias that could not be resolved (treated as any port).
- ``description`` is the device's text. Rules Atrium creates carry ``marker(change_id)`` ("atrium:<change id>") in
  it; the hub reads the marker back (``rule["marker"]``) to attribute drift to its own changes.

Writing - a write-capable connector declares ``network_write = {"ops": [...], "rollback": <mode>, "window_s": int}``
(``WRITE_OPS``, ``ROLLBACK_MODES``) and implements the methods in ``base.Connector``. They receive operations
validated by ``parse_ops`` (canonical dicts, see ``AllowOp`` / ``DisableRulesOp``)::

    {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
     "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
     "services": [{"proto": "tcp", "ports": "443"}], "log": True,
     "description": "Users to intranet web", "marker": "atrium:chg_31"}
    {"op": "disable_rules", "rules": [{"id": "7c1d", "vendor_ref": "7c1d-...-uuid"}]}

``zone`` is the native zone or interface id the rule binds to (the hub's zone id without "z:<device id>:"). An allow
never uses "any": both sides are explicit networks and every service is explicit (at most 16). Approvals bind to
``ops_hash(ops)``, so connectors must not reinterpret ops (no widening, no merging). The rule an allow creates is a
pass rule bound inbound to the source zone's interface(s) (or, for zone-based products, from the source zone to the
destination zone), placed before the rules that could block it (connectors say where in ``preview_change``), with
the op's ``marker`` (plus its description) as the rule's description/comment.

Helpers for both sides: ``ops_diff`` (the diff text a preview shows), ``ops_applied`` / ``ops_reverted`` (did a
re-read show the change / its undo - what the hub verifies before confirming), ``record_hash`` (what history and
drift compare: hit counters and read times excluded), ``management_guard`` (anti-lockout), ``rule_ref`` (a rule's
id safe for logs, compliance details and agent-visible text).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError, field_validator, model_validator

from .base import ConnectorError

DEVICE_KINDS = ("firewall", "router", "switch", "host")
INTERFACE_ROLES = ("lan", "wan", "mgmt", "other")
RULE_ACTIONS = ("pass", "block", "reject")
DIRECTIONS = ("in", "out", "any")
ALIAS_KINDS = ("network", "host", "port", "url", "geoip", "other")
POLICY_KEYS = ("inbound", "outbound", "forward")
POLICY_VALUES = ("pass", "block", "reject", "unknown")
WRITE_OPS = ("allow", "disable_rules")
ROLLBACK_MODES = ("savepoint", "backup_restore", "deadman", "commit_confirm", "none")
CHANGE_PROTOCOLS = ("tcp", "udp", "icmp")  # what an allow may open
MAX_SERVICES = 16
MAX_RULES = 20_000
MAX_TEXT = 500
MAX_ID = 200
MARKER_PREFIX = "atrium:"
MARKER_RE = re.compile(r"atrium:([A-Za-z0-9_-]{1,64})")
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
PROTO_RE = re.compile(r"^[a-z0-9][a-z0-9.+-]{0,23}$")
# control characters plus zero-width, line/paragraph separators and bidi overrides (text that could disguise itself)
CONTROL_CHARS = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
# The method names of the write contract (and the op names): never connector actions, so the generic
# connector.action path can never reach them (base.Connector refuses such actions at class creation).
RESERVED_ACTIONS = frozenset({"backup", "preview_change", "apply_change", "confirm_change", "rollback_change",
                              "restore_backup", "write_capability", "allow", "disable_rules", "restore", "revert",
                              "apply", "confirm", "rollback"})
MANAGEMENT_PORTS = (22, 23, 80, 443, 830, 8080, 8443, 8728, 8729, 4444, 3389, 5985, 5986)


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------


def untrusted_text(value: Any, limit: int = MAX_TEXT) -> str:
    """Device-provided text made safe to store and show as TEXT: control and bidi-override characters removed,
    whitespace collapsed, cut to `limit`. It is still untrusted (never HTML, never a command, never LLM input)."""
    if value is None:
        return ""
    text = CONTROL_CHARS.sub(" ", str(value))
    return " ".join(text.split())[:limit]


def device_id_text(value: Any, limit: int = MAX_ID) -> str:
    """An id read from a device: control characters removed, kept verbatim otherwise (ids may contain "/", spaces)."""
    return CONTROL_CHARS.sub("", str(value if value is not None else "")).strip()[:limit]


def display_id(value: Any, limit: int = 64) -> str:
    """An id reduced to [A-Za-z0-9._:/-] - safe inside log lines and compliance details read by agents."""
    return re.sub(r"[^A-Za-z0-9._:/-]+", "_", str(value or ""))[:limit] or "_"


def normalise_cidr(value: Any) -> str | None:
    """'10.0.0.5' -> '10.0.0.5/32', '10.0.0.0/24' -> '10.0.0.0/24', '10.0.0.7/24' -> '10.0.0.0/24'; None if not an
    address or network."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def parse_ports(value: Any) -> str | None:
    """'443', '8000-8080', '80,443', 443, [80, 443] -> canonical text; None for any/empty; ValueError if invalid."""
    if value is None or value == "" or (isinstance(value, str) and value.strip().lower() in ("any", "*")):
        return None
    if isinstance(value, (list, tuple)):
        value = ",".join(str(v) for v in value)
    text = re.sub(r"\s+", "", str(value)).replace(":", "-")
    if not PORTS_RE.match(text):
        raise ValueError(f"ports must look like 443, 8000-8080 or 80,443 (got {untrusted_text(value, 40)!r})")
    parts = []
    for part in text.split(","):
        low, _, high = part.partition("-")
        lo, hi = int(low), int(high or low)
        if not (0 < lo <= 65535 and 0 < hi <= 65535 and lo <= hi):
            raise ValueError(f"port {part} is out of range (1-65535)")
        parts.append(str(lo) if lo == hi else f"{lo}-{hi}")
    return ",".join(parts)


def port_ranges(ports: str | None) -> list[tuple[int, int]]:
    """'80,8000-8080' -> [(80, 80), (8000, 8080)]; None (any port) -> [(1, 65535)]."""
    if not ports:
        return [(1, 65535)]
    out = []
    for part in ports.split(","):
        low, _, high = part.partition("-")
        out.append((int(low), int(high or low)))
    return out


def marker(change_id: str) -> str:
    """The text Atrium puts in the description of every rule it creates: "atrium:<change id>"."""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", change_id or ""):
        raise ValueError("change ids are 1-64 letters, digits, '_' and '-'")
    return f"{MARKER_PREFIX}{change_id}"


def find_marker(text: Any) -> str | None:
    """The change id of an "atrium:<change id>" marker in a rule description, else None."""
    match = MARKER_RE.search(str(text or ""))
    return match.group(1) if match else None


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def ops_hash(ops: list[dict[str, Any]]) -> str:
    """"sha256:<hex>" of the canonical JSON of validated ops - what an approval binds to."""
    return "sha256:" + hashlib.sha256(canonical_json(parse_ops(ops)).encode()).hexdigest()


# --------------------------------------------------------------------------------------
# the normalised record
# --------------------------------------------------------------------------------------


def _id(value: Any) -> str:
    text = device_id_text(value)
    if not text:
        raise ValueError("an id is required")
    return text


def _ids(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple, set)) else [value] if value not in (None, "") else []
    return list(dict.fromkeys(t for t in (device_id_text(v) for v in items) if t))[:500]


def _cidrs(value: Any, what: str = "address") -> list[str]:
    items = value if isinstance(value, (list, tuple, set)) else [value] if value not in (None, "") else []
    out: list[str] = []
    for item in list(items)[:2000]:
        cidr = normalise_cidr(item)
        if cidr is None:
            raise ValueError(f"not an IP {what}: {untrusted_text(item, 60)!r}")
        if cidr not in out:
            out.append(cidr)
    return out


def _addresses(value: Any) -> list[str]:
    items = value if isinstance(value, (list, tuple, set)) else [value] if value not in (None, "") else []
    out: list[str] = []
    for item in list(items)[:2000]:
        text = str(item or "").strip().split("/")[0]
        try:
            address = str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise ValueError(f"not an IP address: {untrusted_text(item, 60)!r}") from exc
        if address not in out:
            out.append(address)
    return out


class _Model(BaseModel):
    model_config = ConfigDict(extra="ignore")


class DeviceInfo(_Model):
    vendor: str = ""
    model: str = ""
    version: str = ""
    hostname: str = ""
    management_address: str = ""
    serial: str = ""

    @field_validator("vendor", "model", "version", "hostname", "management_address", "serial", mode="before")
    @classmethod
    def _text(cls, value: Any) -> str:
        return untrusted_text(value, 120)


class Interface(_Model):
    id: str
    name: str = ""
    description: str = ""
    vlan: int | None = None
    subnets: list[str] = []
    addresses: list[str] = []
    role: Literal["lan", "wan", "mgmt", "other"] = "other"
    enabled: bool = True

    _id = field_validator("id", mode="before")(lambda cls, v: _id(v))
    _subnets = field_validator("subnets", mode="before")(lambda cls, v: _cidrs(v, "network"))
    _addresses = field_validator("addresses", mode="before")(lambda cls, v: _addresses(v))

    @field_validator("name", "description", mode="before")
    @classmethod
    def _text(cls, value: Any) -> str:
        return untrusted_text(value, 200)

    @field_validator("vlan", mode="before")
    @classmethod
    def _vlan(cls, value: Any) -> int | None:
        if value in (None, "", 0, "0"):
            return None
        vlan = int(value)
        if not 1 <= vlan <= 4094:
            raise ValueError("vlan must be 1-4094")
        return vlan

    @field_validator("role", mode="before")
    @classmethod
    def _role(cls, value: Any) -> str:
        text = str(value or "other").strip().lower()
        return text if text in INTERFACE_ROLES else "other"

    @model_validator(mode="after")
    def _name_default(self) -> "Interface":
        self.name = self.name or self.id
        return self


class Zone(_Model):
    id: str
    name: str = ""
    description: str = ""
    interfaces: list[str] = []

    _id = field_validator("id", mode="before")(lambda cls, v: _id(v))
    _interfaces = field_validator("interfaces", mode="before")(lambda cls, v: _ids(v))

    @field_validator("name", "description", mode="before")
    @classmethod
    def _text(cls, value: Any) -> str:
        return untrusted_text(value, 200)

    @model_validator(mode="after")
    def _name_default(self) -> "Zone":
        self.name = self.name or self.id
        return self


class Alias(_Model):
    name: str
    kind: str = "network"
    cidrs: list[str] = []
    ports: str | None = None
    resolved: bool = True

    _name = field_validator("name", mode="before")(lambda cls, v: _id(v))
    _cidrs = field_validator("cidrs", mode="before")(lambda cls, v: _cidrs(v))

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, value: Any) -> str:
        text = str(value or "network").strip().lower()
        return text if text in ALIAS_KINDS else "other"

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> str | None:
        return parse_ports(value)


class Endpoint(_Model):
    any: bool = False
    cidrs: list[str] = []
    aliases: list[str] = []
    nets: list[str] = []
    self: bool = False
    negate: bool = False

    _cidrs = field_validator("cidrs", mode="before")(lambda cls, v: _cidrs(v))
    _aliases = field_validator("aliases", "nets", mode="before")(lambda cls, v: _ids(v))

    @model_validator(mode="after")
    def _empty_is_any(self) -> "Endpoint":
        if not (self.cidrs or self.aliases or self.nets or self.self):
            self.any = True
        if self.any:
            self.cidrs, self.aliases, self.nets, self.self = [], [], [], False
        return self


class Service(_Model):
    proto: str = "any"
    ports: str | None = None
    alias: str | None = None
    name: str = ""

    @field_validator("proto", mode="before")
    @classmethod
    def _proto(cls, value: Any) -> str:
        text = str(value if value not in (None, "") else "any").strip().lower()
        text = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6", "ip": "any", "*": "any", "all": "any"}.get(text, text)
        if not PROTO_RE.match(text):
            raise ValueError(f"unknown protocol {untrusted_text(value, 30)!r}")
        return text

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> str | None:
        return parse_ports(value)

    @field_validator("alias", mode="before")
    @classmethod
    def _alias(cls, value: Any) -> str | None:
        return device_id_text(value) or None

    @field_validator("name", mode="before")
    @classmethod
    def _name(cls, value: Any) -> str:
        return untrusted_text(value, 80)


def _services(value: Any) -> list[dict[str, Any]] | None:
    """None/'any' -> None; 'tcp/udp' entries split in two; an 'any' protocol without ports makes the whole list any."""
    if value is None or value == "any":
        return None
    items = value if isinstance(value, (list, tuple)) else [value]
    out: list[dict[str, Any]] = []
    for item in items[:500]:
        if isinstance(item, str):  # "tcp/443", "443/tcp", "tcp", "443" (tcp)
            left, _, right = item.strip().lower().partition("/")
            if right and not left[:1].isdigit():
                proto, ports = left, right
            elif right:
                proto, ports = right, left
            else:
                proto, ports = (left, "") if not left[:1].isdigit() else ("tcp", left)
            item = {"proto": proto, "ports": ports or None}
        if not isinstance(item, dict):
            raise ValueError("a service is an object {proto, ports}")
        protos = str(item.get("proto") or "any").lower().split("/")
        for proto in protos:
            out.append({**item, "proto": proto})
    services = [Service.model_validate(s) for s in out]
    if any(s.proto == "any" and not s.ports and not s.alias for s in services):
        return None
    return [s.model_dump() for s in services]


class Rule(_Model):
    id: str
    vendor_ref: str = ""
    order: int = 0
    enabled: bool = True
    action: Literal["pass", "block", "reject"] = "pass"
    interfaces: list[str] = []
    out_interfaces: list[str] = []
    source_zones: list[str] = []
    destination_zones: list[str] = []
    floating: bool = False
    direction: Literal["in", "out", "any"] = "in"
    quick: bool = True
    source: Endpoint = Field(default_factory=Endpoint)
    destination: Endpoint = Field(default_factory=Endpoint)
    services: list[Service] | None = None
    log: bool = False
    description: str = ""
    hits: int | None = None
    marker: str | None = None  # set by the hub from the description

    _id = field_validator("id", mode="before")(lambda cls, v: _id(v))
    _lists = field_validator("interfaces", "out_interfaces", "source_zones", "destination_zones",
                             mode="before")(lambda cls, v: _ids(v))
    _services = field_validator("services", mode="before")(lambda cls, v: _services(v))

    @field_validator("vendor_ref", mode="before")
    @classmethod
    def _ref(cls, value: Any) -> str:
        return device_id_text(value, 300)

    @field_validator("action", mode="before")
    @classmethod
    def _action(cls, value: Any) -> str:
        text = str(value or "pass").strip().lower()
        text = {"accept": "pass", "allow": "pass", "permit": "pass", "drop": "block", "deny": "block"}.get(text, text)
        if text not in RULE_ACTIONS:
            raise ValueError(f"unknown action {untrusted_text(value, 30)!r}")
        return text

    @field_validator("direction", mode="before")
    @classmethod
    def _direction(cls, value: Any) -> str:
        text = str(value or "in").strip().lower()
        return {"inbound": "in", "outbound": "out", "both": "any"}.get(text, text)

    @field_validator("description", mode="before")
    @classmethod
    def _description(cls, value: Any) -> str:
        return untrusted_text(value)

    @field_validator("hits", mode="before")
    @classmethod
    def _hits(cls, value: Any) -> int | None:
        if value in (None, ""):
            return None
        try:
            return max(0, int(float(value)))
        except (TypeError, ValueError):
            return None

    @model_validator(mode="after")
    def _derived(self) -> "Rule":
        self.vendor_ref = self.vendor_ref or self.id
        self.marker = find_marker(self.description)
        if not (self.interfaces or self.out_interfaces or self.source_zones or self.destination_zones):
            self.floating = True
        return self


class NetworkRecord(_Model):
    external_id: str
    revision: str
    read_at: float | None = None
    kind: Literal["firewall", "router", "switch", "host"] = "firewall"
    device: DeviceInfo = Field(default_factory=DeviceInfo)
    interfaces: list[Interface] = []
    zones: list[Zone] = []
    aliases: list[Alias] = []
    self_addresses: list[str] = []
    rules: list[Rule] = []
    default_policy: dict[str, str] = {}
    nat_evaluated: bool = False
    notes: list[str] = []
    errors: list[str] = []  # entries the hub dropped while normalising (set by the hub)

    _external_id = field_validator("external_id", mode="before")(lambda cls, v: _id(v))
    _self = field_validator("self_addresses", mode="before")(lambda cls, v: _addresses(v))

    @field_validator("revision", mode="before")
    @classmethod
    def _revision(cls, value: Any) -> str:
        text = device_id_text(value, 200)
        if not text:
            raise ValueError("revision is required (the device's revision or a hash of what was read)")
        return text

    @field_validator("kind", mode="before")
    @classmethod
    def _kind(cls, value: Any) -> str:
        text = str(value or "firewall").strip().lower()
        if text not in DEVICE_KINDS:
            raise ValueError(f"kind is one of {', '.join(DEVICE_KINDS)}")
        return text

    @field_validator("default_policy", mode="before")
    @classmethod
    def _policy(cls, value: Any) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        out = {}
        for key, action in value.items():
            key, action = str(key).lower(), str(action or "unknown").lower()
            action = {"accept": "pass", "allow": "pass", "drop": "block", "deny": "block"}.get(action, action)
            if key in POLICY_KEYS:
                out[key] = action if action in POLICY_VALUES else "unknown"
        return out

    @field_validator("notes", mode="before")
    @classmethod
    def _notes(cls, value: Any) -> list[str]:
        items = value if isinstance(value, (list, tuple)) else [value] if value else []
        return [untrusted_text(v, 300) for v in items[:50] if v]

    @field_validator("interfaces", "zones", "aliases", "rules", mode="before")
    @classmethod
    def _lists(cls, value: Any) -> list[Any]:
        if value is None:
            return []
        if not isinstance(value, (list, tuple)):
            raise ValueError("must be a list")
        return list(value)[:MAX_RULES]


def _keep_valid(model: type[BaseModel], items: list[Any], what: str, errors: list[str]) -> list[dict[str, Any]]:
    """Valid entries of a list (an entry that does not validate is dropped with a message); duplicate ids dropped."""
    out, seen = [], set()
    for index, item in enumerate(items):
        try:
            entry = model.model_validate(item).model_dump(mode="json")
        except ValidationError as exc:
            ref = untrusted_text((item or {}).get("id") or (item or {}).get("name") if isinstance(item, dict) else index, 60)
            problem = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:2])
            errors.append(f"{what} {ref or index}: {problem}")
            continue
        key = entry.get("id") or entry.get("name")
        if key in seen:
            errors.append(f"{what} {untrusted_text(key, 60)}: duplicate id dropped")
            continue
        seen.add(key)
        out.append(entry)
    return out


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    """One device record in canonical form. Entries that do not validate (a rule with a bad address, ...) are
    dropped and listed in "errors"; a record without external_id or revision raises ValueError."""
    if not isinstance(record, dict):
        raise ValueError("not an object")
    errors: list[str] = []
    lists = {}
    for key, model in (("interfaces", Interface), ("zones", Zone), ("aliases", Alias), ("rules", Rule)):
        raw = record.get(key) or []
        if not isinstance(raw, (list, tuple)):
            raise ValueError(f"{key} must be a list")
        lists[key] = _keep_valid(model, list(raw)[:MAX_RULES], key[:-1], errors)
    try:
        base = NetworkRecord.model_validate({**{k: v for k, v in record.items() if k not in lists}, "interfaces": [],
                                             "zones": [], "aliases": [], "rules": []})
    except ValidationError as exc:
        raise ValueError("; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:3])) from exc
    out = base.model_dump(mode="json")
    out.update(lists)
    out["rules"] = sorted(out["rules"], key=lambda r: r["order"])
    out["errors"] = errors[:100]
    return out


# --------------------------------------------------------------------------------------
# change operations (what write-capable connectors receive)
# --------------------------------------------------------------------------------------


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=False)


class OpEndpoint(_Strict):
    zone: str = Field(min_length=1, max_length=MAX_ID)
    cidrs: list[str] = Field(min_length=1, max_length=64)

    @field_validator("zone", mode="before")
    @classmethod
    def _zone(cls, value: Any) -> str:
        text = device_id_text(value)
        if not text:
            raise ValueError("zone is required")
        return text

    @field_validator("cidrs", mode="before")
    @classmethod
    def _cidrs(cls, value: Any) -> list[str]:
        cidrs = _cidrs(value, "network")
        if any(ipaddress.ip_network(c).prefixlen == 0 for c in cidrs):
            raise ValueError("a change never opens 'any' (0.0.0.0/0 or ::/0): name the zone's networks")
        return cidrs


class OpService(_Strict):
    proto: Literal["tcp", "udp", "icmp"]
    ports: str | None = None

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> str | None:
        return parse_ports(value)

    @model_validator(mode="after")
    def _explicit(self) -> "OpService":
        if self.proto in ("tcp", "udp") and not self.ports:
            raise ValueError(f"{self.proto} needs explicit ports (no 'any')")
        if self.proto == "icmp" and self.ports:
            raise ValueError("icmp has no ports")
        return self


class AllowOp(_Strict):
    """Add one pass rule from the source zone's networks to the destination zone's networks."""

    op: Literal["allow"]
    source: OpEndpoint
    destination: OpEndpoint
    services: list[OpService] = Field(min_length=1, max_length=MAX_SERVICES)
    log: bool = True
    description: str = Field("", max_length=120)
    marker: str

    @field_validator("description", mode="before")
    @classmethod
    def _description(cls, value: Any) -> str:
        return untrusted_text(value, 120)

    @field_validator("marker")
    @classmethod
    def _marker(cls, value: str) -> str:
        if not MARKER_RE.fullmatch(value):
            raise ValueError("marker is 'atrium:<change id>'")
        return value


class RuleRef(_Strict):
    id: str = Field(min_length=1, max_length=MAX_ID)
    vendor_ref: str = Field("", max_length=300)

    @model_validator(mode="after")
    def _ref(self) -> "RuleRef":
        self.id, self.vendor_ref = device_id_text(self.id), device_id_text(self.vendor_ref, 300) or device_id_text(self.id)
        return self


class DisableRulesOp(_Strict):
    """Disable existing rules (never delete them)."""

    op: Literal["disable_rules"]
    rules: list[RuleRef] = Field(min_length=1, max_length=50)


ChangeOp = Annotated[Union[AllowOp, DisableRulesOp], Field(discriminator="op")]
_OPS = TypeAdapter(list[ChangeOp])


def parse_ops(ops: Any) -> list[dict[str, Any]]:
    """Validated canonical ops (ValueError with the first problems). 1-20 ops per change."""
    if not isinstance(ops, list) or not 1 <= len(ops) <= 20:
        raise ValueError("a change has 1-20 operations")
    try:
        parsed = _OPS.validate_python(ops)
    except ValidationError as exc:
        raise ValueError("; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:3])) from exc
    return [op.model_dump(mode="json") for op in parsed]


def validate_write_spec(spec: Any) -> dict[str, Any] | None:
    """A connector's network_write declaration (or what test() reports), checked; None when not writable."""
    if not spec:
        return None
    if not isinstance(spec, dict):
        raise ValueError("network_write must be a dict")
    ops = [o for o in spec.get("ops") or [] if o in WRITE_OPS]
    rollback = spec.get("rollback", "none")
    if rollback not in ROLLBACK_MODES:
        raise ValueError(f"network_write rollback must be one of {', '.join(ROLLBACK_MODES)}")
    window = int(spec.get("window_s") or 0)
    if rollback != "none" and not 10 <= window <= 3600:
        raise ValueError("network_write window_s must be 10-3600 seconds")
    if not ops:
        return None
    return {"ops": ops, "rollback": rollback, "window_s": window}


# --------------------------------------------------------------------------------------
# results and errors of the write contract
# --------------------------------------------------------------------------------------


class ChangeError(ConnectorError):
    """A write that did not go through. `code`: stale (the revision moved), lockout (the management-path guard
    refused it), unsupported, invalid, unreachable or failed. `state` - what the device holds now: unchanged,
    rolled_back (the connector's own rollback ran and a re-read proved it), applied, or unknown (say so: the hub then
    restores its own backup and alerts)."""

    def __init__(self, message: str, *, code: str = "failed", state: str = "unknown", status: int | None = None,
                 excerpt: str | None = None):
        super().__init__(message, status=status, excerpt=excerpt)
        self.code = code if code in ("stale", "lockout", "unsupported", "invalid", "unreachable", "failed") else "failed"
        self.state = state if state in ("unchanged", "rolled_back", "applied", "unknown") else "unknown"

    def as_dict(self) -> dict[str, Any]:
        return {**super().as_dict(), "code": self.code, "state": self.state}


@dataclass(frozen=True)
class Backup:
    """A device configuration backup as the hub hands it to apply_change / rollback_change / restore_backup.
    `content` is the exact bytes the connector's backup() returned (the hub verified `sha256` before handing it
    over). It is secret material: never log it, put it in an error message or return it."""

    backup_id: str
    content: bytes = field(repr=False)
    sha256: str
    taken_at: float
    format: str = "text"
    device_backup_id: str | None = None  # the device's own reference, if the connector returned one
    revision: str | None = None

    def text(self) -> str:
        return self.content.decode("utf-8")


def backup_content(value: Any) -> bytes:
    """What a connector's backup() returned under "content", as bytes (str is UTF-8 encoded)."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ConnectorError("backup() must return the configuration as bytes or text under 'content'")


# --------------------------------------------------------------------------------------
# reading rules: one-line text, management exposure, the anti-lockout guard
# --------------------------------------------------------------------------------------


def endpoint_text(endpoint: dict[str, Any], interfaces: dict[str, str] | None = None) -> str:
    """'any', 'LAN net', 'MGMT_NET', '10.0.0.0/24', 'this device', joined with ', '; '!' when negated."""
    if endpoint.get("any"):
        return "any"
    names = interfaces or {}
    parts = [*(f"{names.get(n, n)} net" for n in endpoint.get("nets") or []), *(endpoint.get("aliases") or []),
             *(endpoint.get("cidrs") or [])]
    if endpoint.get("self"):
        parts.append("this device")
    return ("!" if endpoint.get("negate") else "") + (", ".join(parts) or "any")


def service_text(services: list[dict[str, Any]] | None) -> str:
    if not services:
        return "any"
    return ", ".join(f"{s['proto']}/{s['ports']}" if s.get("ports") else
                     f"{s['proto']}/{s['alias']}" if s.get("alias") else s["proto"] for s in services)


def rule_line(rule: dict[str, Any], interfaces: dict[str, str] | None = None) -> str:
    """A rule as one line of text (history, diffs, previews), e.g.
    "pass in on lan from LAN net to MGMT_NET tcp/443 log  # vCenter from outside [disabled]"."""
    where = []
    if rule.get("interfaces"):
        where.append("on " + ",".join(rule["interfaces"]))
    if rule.get("out_interfaces"):
        where.append("out " + ",".join(rule["out_interfaces"]))
    if rule.get("source_zones") or rule.get("destination_zones"):
        where.append(f"zones {','.join(rule.get('source_zones') or ['any'])}>{','.join(rule.get('destination_zones') or ['any'])}")
    if rule.get("floating") and not where:
        where.append("floating")
    line = " ".join([rule.get("action", "pass"), rule.get("direction", "in"), *where,
                     "from", endpoint_text(rule.get("source") or {}, interfaces),
                     "to", endpoint_text(rule.get("destination") or {}, interfaces),
                     service_text(rule.get("services"))])
    if rule.get("log"):
        line += " log"
    if rule.get("description"):
        line += f"  # {rule['description']}"
    if not rule.get("enabled", True):
        line += " [disabled]"
    return line


def record_lines(record: dict[str, Any]) -> list[str]:
    """A snapshot as stable lines of text (what the history diff compares)."""
    names = {i["id"]: i.get("name") or i["id"] for i in record.get("interfaces") or []}
    lines = [f"device {record.get('kind', 'firewall')} {record.get('device', {}).get('vendor', '')} "
             f"{record.get('device', {}).get('version', '')}".rstrip()]
    for i in record.get("interfaces") or []:
        vlan = f" vlan {i['vlan']}" if i.get("vlan") else ""
        state = "" if i.get("enabled", True) else " [down]"
        lines.append(f"interface {i['id']} ({i.get('name')}) role {i.get('role')}{vlan} "
                     f"{' '.join(i.get('subnets') or []) or '-'}{state}")
    for z in record.get("zones") or []:
        lines.append(f"zone {z['id']} ({z.get('name')}): {', '.join(z.get('interfaces') or []) or '-'}")
    for a in record.get("aliases") or []:
        value = " ".join(a.get("cidrs") or []) or a.get("ports") or "-"
        lines.append(f"alias {a['name']} {a.get('kind')}{'' if a.get('resolved', True) else ' (unresolved)'}: {value}")
    for key, value in sorted((record.get("default_policy") or {}).items()):
        lines.append(f"default {key} {value}")
    for r in record.get("rules") or []:
        lines.append(f"rule {r['vendor_ref']} #{r.get('order')}: {rule_line(r, names)}")
    return lines


def _covers(cidrs: list[str], address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip.version == (net := ipaddress.ip_network(c)).version and ip in net for c in cidrs)


def targets_device(record: dict[str, Any], endpoint: dict[str, Any]) -> bool:
    """Whether an endpoint can match the device itself (this firewall, any, or a network holding a self address)."""
    if endpoint.get("negate"):
        return True  # "not X" usually includes the device: be conservative
    if endpoint.get("any") or endpoint.get("self"):
        return True
    cidrs = list(endpoint.get("cidrs") or [])
    aliases = {a["name"]: a for a in record.get("aliases") or []}
    for name in endpoint.get("aliases") or []:
        alias = aliases.get(name)
        if alias is None or not alias.get("resolved", True):
            return True  # unknown content: assume it may
        cidrs += alias.get("cidrs") or []
    nets = {i["id"]: i for i in record.get("interfaces") or []}
    for net in endpoint.get("nets") or []:
        cidrs += (nets.get(net) or {}).get("subnets") or []
    return any(_covers(cidrs, a) for a in record.get("self_addresses") or [])


def management_guard(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    """Anti-lockout (S12): problems with `ops` against the device's current record. disable_rules is refused for any
    pass rule whose destination can be the device itself (this firewall, any, or a network holding one of its
    self_addresses) - those rules may carry the hub's management path. An unknown rule is a problem too (the
    snapshot is stale). Connectors add their own vendor checks (the hub's source address, the management port)."""
    rules = {r["id"]: r for r in record.get("rules") or []}
    by_ref = {r["vendor_ref"]: r for r in record.get("rules") or []}
    problems = []
    for op in ops:
        if op.get("op") != "disable_rules":
            continue
        for ref in op.get("rules") or []:
            rule = rules.get(ref.get("id")) or by_ref.get(ref.get("vendor_ref"))
            if rule is None:
                problems.append(f"rule {display_id(ref.get('id'))} is not on the device (re-read it first)")
            elif rule.get("action") == "pass" and targets_device(record, rule.get("destination") or {}):
                problems.append(f"rule {display_id(rule['id'])} lets traffic reach the device itself - disabling it "
                                "could cut the hub off from the device")
    return problems


def from_untrusted(record: dict[str, Any], rule: dict[str, Any]) -> bool:
    """Whether a rule's traffic can come from anywhere: source any (or negated) and ingress on a WAN interface, from a
    vendor zone holding a WAN interface, or floating (bound to nothing)."""
    source = rule.get("source") or {}
    if not (source.get("any") or source.get("negate")):
        return False
    wan = {i["id"] for i in record.get("interfaces") or [] if i.get("role") == "wan"}
    if rule.get("interfaces"):
        return bool(wan & set(rule["interfaces"]))
    if rule.get("source_zones"):
        zones = {z["id"]: set(z.get("interfaces") or []) for z in record.get("zones") or []}
        return any(wan & zones.get(z, set()) for z in rule["source_zones"])
    return True


def exposes_management(record: dict[str, Any], rule: dict[str, Any]) -> bool:
    """An enabled pass rule from anywhere (see ``from_untrusted``) that can reach the device itself (this device, any,
    or a network holding one of its self addresses) on a management port (or any port)."""
    if not rule.get("enabled", True) or rule.get("action") != "pass" or not from_untrusted(record, rule):
        return False
    if not targets_device(record, rule.get("destination") or {}):
        return False
    services = rule.get("services")
    if not services:
        return True
    return any(s.get("proto") in ("tcp", "udp", "any") and any(lo <= p <= hi for p in MANAGEMENT_PORTS
                                                                for lo, hi in port_ranges(s.get("ports")))
               for s in services)


def is_any_any(rule: dict[str, Any]) -> bool:
    """An enabled pass rule from any to any for any service."""
    return (rule.get("enabled", True) and rule.get("action") == "pass" and (rule.get("source") or {}).get("any")
            and (rule.get("destination") or {}).get("any") and not rule.get("services"))


# --------------------------------------------------------------------------------------
# comparing records: history, drift, previews and verification
# --------------------------------------------------------------------------------------

RULE_FIELDS = ("enabled", "action", "interfaces", "out_interfaces", "source_zones", "destination_zones", "floating",
               "direction", "quick", "source", "destination", "services", "log", "description")
DRIFT_KINDS = ("rule_added", "rule_removed", "rule_changed", "rule_enabled", "rule_disabled", "rules_reordered",
               "interface_added", "interface_removed", "interface_changed", "zone_added", "zone_removed", "zone_changed",
               "alias_added", "alias_removed", "alias_changed", "default_policy_changed", "device_changed",
               "any_any_introduced", "management_exposed")
CRITICAL_DRIFT = ("any_any_introduced", "management_exposed")
INFO_DRIFT = ("rules_reordered", "alias_added", "alias_removed", "alias_changed", "device_changed")


def record_hash(record: dict[str, Any]) -> str:
    """"sha256:<hex>" of what a record says about the device's configuration: read time, revision, notes, errors and
    rule hit counters are left out, so a re-read of an unchanged device hashes the same."""
    body = {k: v for k, v in record.items() if k not in ("read_at", "revision", "notes", "errors")}
    body["rules"] = [{k: v for k, v in r.items() if k not in ("hits", "marker")} for r in record.get("rules") or []]
    return "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()


def rule_ref(rule: dict[str, Any]) -> str:
    """A rule's native id reduced to safe characters - for activity, compliance details and anything agents read."""
    return display_id(rule.get("vendor_ref") or rule.get("id"), 80)


def interface_names(record: dict[str, Any]) -> dict[str, str]:
    return {i["id"]: i.get("name") or i["id"] for i in record.get("interfaces") or []}


def _same(a: dict[str, Any], b: dict[str, Any], fields: tuple[str, ...]) -> bool:
    return all(canonical_json(a.get(f)) == canonical_json(b.get(f)) for f in fields)


def diff_records(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    """What changed between two normalised records of one device, as drift items
    {"kind", "severity" (info | warn | critical), "subject" (rule / interface / zone / alias id), "before", "after"
    (one-line texts, device text included - untrusted), "marker" (the change id of an "atrium:<id>" marker on the rule,
    else None)}. Rules are matched by ``id``; a moved rule is reported once as "rules_reordered"."""
    items: list[dict[str, Any]] = []
    old_names, new_names = interface_names(old), interface_names(new)

    def add(kind: str, subject: str, before: str | None, after: str | None, marker_id: str | None = None) -> None:
        severity = "critical" if kind in CRITICAL_DRIFT else "info" if kind in INFO_DRIFT else "warn"
        items.append({"kind": kind, "severity": severity, "subject": subject, "before": before, "after": after,
                      "marker": marker_id})

    old_rules = {r["id"]: r for r in old.get("rules") or []}
    new_rules = {r["id"]: r for r in new.get("rules") or []}
    for rid, rule in new_rules.items():
        before = old_rules.get(rid)
        if before is None:
            add("rule_added", rid, None, rule_line(rule, new_names), rule.get("marker"))
        elif not _same(before, rule, RULE_FIELDS):
            only_state = _same({**before, "enabled": rule.get("enabled")}, rule, RULE_FIELDS)
            kind = ("rule_enabled" if rule.get("enabled", True) else "rule_disabled") if only_state else "rule_changed"
            add(kind, rid, rule_line(before, old_names), rule_line(rule, new_names), rule.get("marker") or before.get("marker"))
    for rid, rule in old_rules.items():
        if rid not in new_rules:
            add("rule_removed", rid, rule_line(rule, old_names), None, rule.get("marker"))
    common_old = [r["id"] for r in old.get("rules") or [] if r["id"] in new_rules]
    common_new = [r["id"] for r in new.get("rules") or [] if r["id"] in old_rules]
    if common_old != common_new:
        add("rules_reordered", "rules", f"{len(common_old)} rules in the previous order",
            f"{sum(1 for a, b in zip(common_old, common_new) if a != b)} position(s) changed")

    for key, kind, fields in (("interfaces", "interface", ("name", "description", "vlan", "subnets", "addresses", "role",
                                                           "enabled")),
                              ("zones", "zone", ("name", "description", "interfaces")),
                              ("aliases", "alias", ("kind", "cidrs", "ports", "resolved"))):
        ident = "name" if key == "aliases" else "id"
        before_map = {x[ident]: x for x in old.get(key) or []}
        after_map = {x[ident]: x for x in new.get(key) or []}
        line = {"interfaces": lambda x: record_lines({"interfaces": [x]})[1],
                "zones": lambda x: record_lines({"zones": [x]})[1],
                "aliases": lambda x: record_lines({"aliases": [x]})[1]}[key]
        for name, item in after_map.items():
            if name not in before_map:
                add(f"{kind}_added", name, None, line(item))
            elif not _same(before_map[name], item, fields):
                add(f"{kind}_changed", name, line(before_map[name]), line(item))
        for name, item in before_map.items():
            if name not in after_map:
                add(f"{kind}_removed", name, line(item), None)

    if canonical_json(old.get("default_policy") or {}) != canonical_json(new.get("default_policy") or {}):
        add("default_policy_changed", "default_policy",
            ", ".join(f"{k} {v}" for k, v in sorted((old.get("default_policy") or {}).items())) or "-",
            ", ".join(f"{k} {v}" for k, v in sorted((new.get("default_policy") or {}).items())) or "-")
    old_device, new_device = old.get("device") or {}, new.get("device") or {}
    if (old_device.get("vendor"), old_device.get("version"), old_device.get("model")) != \
            (new_device.get("vendor"), new_device.get("version"), new_device.get("model")):
        add("device_changed", "device", " ".join(filter(None, (old_device.get("vendor"), old_device.get("model"),
                                                               old_device.get("version")))) or "-",
            " ".join(filter(None, (new_device.get("vendor"), new_device.get("model"), new_device.get("version")))) or "-")

    exposed_before = {r["id"] for r in old.get("rules") or [] if exposes_management(old, r)}
    any_before = {r["id"] for r in old.get("rules") or [] if is_any_any(r)}
    for rule in new.get("rules") or []:
        if exposes_management(new, rule) and rule["id"] not in exposed_before:
            add("management_exposed", rule["id"], None, rule_line(rule, new_names), rule.get("marker"))
        if is_any_any(rule) and rule["id"] not in any_before:
            add("any_any_introduced", rule["id"], None, rule_line(rule, new_names), rule.get("marker"))
    return items


def _op_rule(op: dict[str, Any]) -> dict[str, Any]:
    """The rule an allow op asks for, in the normalised shape (for previews and diffs)."""
    return {"id": op["marker"], "action": "pass", "direction": "in", "interfaces": [op["source"]["zone"]],
            "source": {"cidrs": op["source"]["cidrs"]}, "destination": {"cidrs": op["destination"]["cidrs"]},
            "services": op["services"], "log": op.get("log", True), "enabled": True,
            "description": f"{op['marker']} {op.get('description') or ''}".strip()}


def ops_diff(record: dict[str, Any], ops: list[dict[str, Any]]) -> str:
    """A unified-diff style text of what `ops` change in `record` ("+" added, "-" removed lines) - what previews and
    approval cards show (device text included: untrusted, display as text only)."""
    names = interface_names(record)
    rules = {r["id"]: r for r in record.get("rules") or []}
    by_ref = {r["vendor_ref"]: r for r in record.get("rules") or []}
    lines = [f"--- {record.get('revision', 'current')}", "+++ proposed"]
    for op in parse_ops(ops):
        if op["op"] == "allow":
            lines.append("+ " + rule_line(_op_rule(op), names))
        else:
            for ref in op["rules"]:
                rule = rules.get(ref["id"]) or by_ref.get(ref["vendor_ref"])
                if rule is None:
                    lines.append(f"? rule {display_id(ref['id'])} is not in the snapshot")
                    continue
                lines.append("- " + rule_line(rule, names))
                lines.append("+ " + rule_line({**rule, "enabled": False}, names))
    return "\n".join(lines)


def _find_rule(record: dict[str, Any], ref: dict[str, Any]) -> dict[str, Any] | None:
    for rule in record.get("rules") or []:
        if rule["id"] == ref.get("id") or (ref.get("vendor_ref") and rule["vendor_ref"] == ref["vendor_ref"]):
            return rule
    return None


def ops_applied(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    """Problems showing that a re-read `record` does NOT hold the change (empty = applied): every allow's rule (found
    by its marker) is there, enabled, a pass rule with the op's networks and services; every rule disable_rules named
    is there and disabled."""
    problems = []
    for op in parse_ops(ops):
        if op["op"] == "allow":
            change_id = find_marker(op["marker"])
            found = [r for r in record.get("rules") or [] if r.get("marker") == change_id]
            match = [r for r in found if r.get("enabled", True) and r.get("action") == "pass"
                     and set(op["source"]["cidrs"]) <= set((r.get("source") or {}).get("cidrs") or [])
                     and set(op["destination"]["cidrs"]) <= set((r.get("destination") or {}).get("cidrs") or [])
                     and {(s["proto"], s.get("ports")) for s in op["services"]}
                     <= {(s["proto"], s.get("ports")) for s in r.get("services") or []}]
            if not match:
                problems.append(f"the rule marked {op['marker']} is " + ("not as proposed" if found else "missing"))
        else:
            for ref in op["rules"]:
                rule = _find_rule(record, ref)
                if rule is None:
                    problems.append(f"rule {display_id(ref['id'])} is missing")
                elif rule.get("enabled", True):
                    problems.append(f"rule {display_id(ref['id'])} is still enabled")
    return problems


def ops_reverted(before: dict[str, Any], after: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    """Problems showing that `after` (a re-read) still holds part of the change compared with `before` (the record
    the change was made against); empty = fully reverted."""
    problems = []
    for op in parse_ops(ops):
        if op["op"] == "allow":
            change_id = find_marker(op["marker"])
            if any(r.get("marker") == change_id for r in after.get("rules") or []):
                problems.append(f"the rule marked {op['marker']} is still on the device")
        else:
            for ref in op["rules"]:
                old, new = _find_rule(before, ref), _find_rule(after, ref)
                if old is not None and (new is None or new.get("enabled", True) != old.get("enabled", True)):
                    problems.append(f"rule {display_id(ref['id'])} is not back to its previous state")
    return problems
