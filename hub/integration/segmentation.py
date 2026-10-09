"""The segmentation read model (canvas-design 6.2-6.5, 7.5-7.6): a firewall's zones, where the hub's assets sit in
them, which traffic its rules may allow between zones, the segmentation policy, and overlays (open vulnerabilities,
possible policy violations). Pure computation over the network snapshots (``network.py``) plus three small
collections:

``segmentation_zones``       admin overrides per zone id: {id, role, label, updated_by, updated_at}
``segmentation_placements``  manual asset placements (operator): {id (asset id), zone_id, updated_by, updated_at}
``settings`` / ``segmentation_policy``  the policy (admin): {id, version, rules, updated_by, updated_at}

Zones: ``z:<tool id>:<native id>`` - vendor zones when the device has them, otherwise interfaces / VLANs (one
level). WAN-role interfaces (and vendor zones made only of them) are the pseudo-zone ``z:internet``, which also holds
every address outside the firewall's internal subnets. Roles come from an admin override (manual), else from the
name (heuristic, "role not confirmed"), else unknown.

Allowed traffic is an OVER-APPROXIMATION ("may allow"): every enabled pass rule adds an edge from each zone its
traffic can enter through (its ingress interfaces / source zones, all zones for floating rules) whose networks the
source matches, to each zone the destination matches (restricted to its egress interfaces / destination zones);
traffic within one zone is not an edge. Block and reject rules, rule order, NAT, VPNs and implicit vendor rules are
not evaluated, so an edge may not be reachable. Unresolved aliases and negated endpoints count as "any" (noted on the
edge). Rule and zone text from devices is untrusted (data, never HTML or agent input).

Policy rules ({id, from: [roles], to: [roles], verdict, control, except_services} or {id, match:
"any_source_any_destination_any_service", verdict, control}) are evaluated per edge in order: every matching
"forbidden" / "restricted" rule is a possible violation (restricted passes when all the edge's services are in
except_services), unless an earlier "allowed" rule matched the same pair (an exception). Violations are always
"possible" while the evaluation is approximate.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..connectors.netmodel import display_id, endpoint_text, interface_names, is_any_any, parse_ports, port_ranges, service_text
from ..models import OPEN_STATES, SEVERITY_ORDER, Asset, Vulnerability
from . import network

if TYPE_CHECKING:
    from ..core import Hub

ZONE_OVERRIDES = "segmentation_zones"
PLACEMENTS = "segmentation_placements"
POLICY_ID = "segmentation_policy"
INTERNET = "z:internet"
FIREWALL_KINDS = ("firewall", "router", "switch")
ROLES = ("internet", "dmz", "management", "servers", "users", "guest", "iot", "ot", "dev", "backup", "remote", "unknown")
Role = Literal["internet", "dmz", "management", "servers", "users", "guest", "iot", "ot", "dev", "backup", "remote",
               "unknown"]
LANES = {"internet": "internet", "dmz": "edge", "remote": "edge", "guest": "edge", "iot": "edge", "users": "users",
         "servers": "servers", "dev": "servers", "management": "core", "backup": "core", "ot": "core",
         "unknown": "unclassified"}
# most specific first: "GUEST_LAN" is guest, not users
HEURISTICS: tuple[tuple[tuple[str, ...], str], ...] = (
    (("wan", "internet", "outside", "untrust"), "internet"), (("dmz",), "dmz"),
    (("mgmt", "management", "admin", "oob", "ipmi", "bmc"), "management"), (("guest",), "guest"),
    (("iot", "cam", "camera", "printer"), "iot"), (("ot", "scada", "ics"), "ot"), (("backup",), "backup"),
    (("vpn",), "remote"), (("dev", "test", "staging", "lab"), "dev"), (("srv", "server", "prod"), "servers"),
    (("lan", "office", "corp", "staff", "users", "trust"), "users"),
)
WELL_KNOWN = {("tcp", "443"): "HTTPS", ("tcp", "80"): "HTTP", ("tcp", "22"): "SSH", ("tcp", "3389"): "RDP",
              ("udp", "53"): "DNS", ("tcp", "53"): "DNS", ("icmp", None): "ICMP", ("tcp", "25"): "SMTP",
              ("tcp", "445"): "SMB", ("udp", "123"): "NTP", ("udp", "161"): "SNMP", ("tcp", "3306"): "MySQL",
              ("tcp", "5432"): "PostgreSQL", ("tcp", "8443"): "HTTPS (8443)", ("tcp", "8080"): "HTTP (8080)"}
EVALUATION_NOTE = ("Approximate: block rules, rule order and NAT are not evaluated, so some edges may not be "
                   "reachable.")
EXPOSING_ROLES = ("internet", "guest", "iot")
UNCONFIRMED = "role not confirmed"


# --------------------------------------------------------------------------------------
# policy
# --------------------------------------------------------------------------------------


class ServiceSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proto: Literal["tcp", "udp", "icmp"]
    ports: str | None = None

    @field_validator("ports", mode="before")
    @classmethod
    def _ports(cls, value: Any) -> str | None:
        return parse_ports(value)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    from_: list[Role] = Field([], alias="from", max_length=len(ROLES))
    to: list[Role] = Field([], max_length=len(ROLES))
    match: Literal["any_source_any_destination_any_service"] | None = None
    verdict: Literal["allowed", "restricted", "forbidden"]
    control: str | None = Field(None, pattern=r"^HB-[A-Z]{2,4}-\d{1,3}$")
    except_services: list[ServiceSpec] = Field([], max_length=32)
    description: str = Field("", max_length=300)

    @model_validator(mode="after")
    def _shape(self) -> "PolicyRule":
        if self.match is None and not (self.from_ and self.to):
            raise ValueError("a policy rule needs 'from' and 'to' roles (or 'match')")
        if self.match is not None and (self.from_ or self.to):
            raise ValueError("a 'match' rule has no 'from' / 'to'")
        if self.except_services and self.verdict != "restricted":
            raise ValueError("except_services only applies to restricted rules")
        return self


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rules: list[PolicyRule] = Field(max_length=100)

    @model_validator(mode="after")
    def _unique(self) -> "Policy":
        ids = [r.id for r in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("policy rule ids must be unique")
        return self


DEFAULT_POLICY: list[dict[str, Any]] = [
    {"id": "untrusted-to-management", "from": ["internet", "guest", "iot", "users"], "to": ["management"],
     "verdict": "forbidden", "control": "HB-NW-1"},
    {"id": "internet-must-hit-dmz", "from": ["internet"],
     "to": ["servers", "users", "dev", "backup", "ot", "management"], "verdict": "forbidden", "control": "HB-NW-1"},
    {"id": "guest-iot-isolated", "from": ["guest", "iot"],
     "to": ["users", "servers", "backup", "ot", "dev", "management"], "verdict": "forbidden", "control": "HB-NW-1"},
    {"id": "prod-dev-separated", "from": ["dev"], "to": ["servers"], "verdict": "restricted", "control": "HB-NW-1",
     "except_services": []},
    {"id": "no-any-any", "match": "any_source_any_destination_any_service", "verdict": "forbidden",
     "control": "HB-NW-5"},
]


def policy(hub: "Hub") -> dict[str, Any]:
    doc = hub.store.get("settings", POLICY_ID)
    if doc is None:
        return {"id": POLICY_ID, "version": 0, "rules": DEFAULT_POLICY, "default": True, "updated_by": None,
                "updated_at": None}
    return {**doc, "default": False}


def put_policy(hub: "Hub", body: dict[str, Any], actor: str) -> dict[str, Any]:
    """Replace the policy (ValueError / pydantic ValidationError on a bad one); the version increments."""
    parsed = Policy.model_validate(body)
    current = policy(hub)
    doc = {"id": POLICY_ID, "version": int(current["version"]) + 1,
           "rules": [r.model_dump(mode="json", by_alias=True, exclude_none=True) for r in parsed.rules],
           "updated_by": actor, "updated_at": time.time()}
    hub.store.put("settings", doc)
    hub.activity(actor, "warn", f"Segmentation policy changed (version {doc['version']}, {len(doc['rules'])} rules)")
    changed(hub, [])
    return {**doc, "default": False}


def changed(hub: "Hub", firewall_ids: list[str]) -> None:
    hub.bus.publish("segmentation", {"firewall_ids": firewall_ids, "generated_at": time.time()})


# --------------------------------------------------------------------------------------
# zones
# --------------------------------------------------------------------------------------


def _tokens(*texts: str) -> list[str]:
    out = []
    for text in texts:
        out += [t for t in re.split(r"[^a-z]+", (text or "").lower()) if t]
    return out


def heuristic_role(*names: str) -> str:
    tokens = _tokens(*names)
    for patterns, role in HEURISTICS:
        if any(t == p or (len(p) >= 3 and t.startswith(p)) for t in tokens for p in patterns):
            return role
    return "unknown"


def zone_id(tool_id: str, native: str) -> str:
    return f"z:{tool_id}:{native}"


def internet_zone() -> dict[str, Any]:
    return {"id": INTERNET, "kind": "pseudo", "name": "Internet", "label": None, "role": "internet",
            "role_source": "builtin", "lane": "internet", "badges": [], "subnets": [], "interfaces": [], "vlan": None,
            "native_id": None, "firewall": None, "parent": None, "same_subnet_as": []}


class Topology:
    """A firewall's zones and how its interfaces, vendor zones and addresses map onto them."""

    def __init__(self, tool_id: str, record: dict[str, Any], overrides: dict[str, dict[str, Any]]):
        self.tool_id, self.record = tool_id, record
        self.interfaces = {i["id"]: i for i in record.get("interfaces") or []}
        self.aliases = {a["name"]: a for a in record.get("aliases") or []}
        self.iface_zone: dict[str, str] = {}
        self.vendor_zone: dict[str, str] = {}
        self.zones: list[dict[str, Any]] = [internet_zone()]
        self.wan_subnets: list[Any] = []
        for zone in record.get("zones") or []:
            members = [self.interfaces[i] for i in zone.get("interfaces") or [] if i in self.interfaces]
            if members and all(m.get("role") == "wan" for m in members):
                self.vendor_zone[zone["id"]] = INTERNET
                for m in members:
                    self.iface_zone[m["id"]] = INTERNET
                    self.wan_subnets += [ipaddress.ip_network(s) for s in m.get("subnets") or []]
                continue
            zid = zone_id(tool_id, zone["id"])
            vlans = [m["vlan"] for m in members if m.get("vlan")]
            self._add(zid, "zone", zone.get("name") or zone["id"], zone["id"], members,
                      vlans[0] if len(vlans) == 1 else None, overrides, zone.get("description") or "")
            self.vendor_zone[zone["id"]] = zid
            for m in members:
                self.iface_zone.setdefault(m["id"], zid)
        for iface in self.interfaces.values():
            if iface["id"] in self.iface_zone:
                continue
            if iface.get("role") == "wan":
                self.iface_zone[iface["id"]] = INTERNET
                self.wan_subnets += [ipaddress.ip_network(s) for s in iface.get("subnets") or []]
                continue
            if not iface.get("enabled", True) and not iface.get("subnets"):
                continue
            zid = zone_id(tool_id, iface["id"])
            self._add(zid, "vlan" if iface.get("vlan") else "interface", iface.get("name") or iface["id"], iface["id"],
                      [iface], iface.get("vlan"), overrides, iface.get("description") or "", iface.get("role"))
            self.iface_zone[iface["id"]] = zid
        self.by_id = {z["id"]: z for z in self.zones}
        self.internal = [(ipaddress.ip_network(s), z["id"]) for z in self.zones if z["id"] != INTERNET
                         for s in z["subnets"]]

    def _add(self, zid: str, kind: str, name: str, native: str, members: list[dict[str, Any]], vlan: int | None,
             overrides: dict[str, dict[str, Any]], description: str, iface_role: str | None = None) -> None:
        subnets = list(dict.fromkeys(s for m in members for s in m.get("subnets") or []))
        override = overrides.get(zid) or {}
        guess = heuristic_role(name, native, description)
        if guess == "unknown" and iface_role == "mgmt":
            guess = "management"
        role = override.get("role") or guess
        source = "manual" if override.get("role") else "heuristic"
        badges = [] if source == "manual" else [UNCONFIRMED]
        self.zones.append({"id": zid, "kind": kind, "name": name, "label": override.get("label"), "role": role,
                           "role_source": source, "lane": LANES[role], "badges": badges, "subnets": subnets,
                           "interfaces": [m["id"] for m in members], "vlan": vlan, "native_id": native,
                           "firewall": self.tool_id, "parent": None, "same_subnet_as": []})

    # -- matching ----------------------------------------------------------------------

    def zone_of_network(self, net: Any) -> str | None:
        """The internal zone whose subnet holds `net`, longest prefix first; None when none does."""
        best = None
        for subnet, zid in self.internal:
            if subnet.version == net.version and net.subnet_of(subnet):
                if best is None or subnet.prefixlen > best[0].prefixlen:
                    best = (subnet, zid)
        return best[1] if best else None

    def is_external(self, net: Any) -> bool:
        return any(net.version == w.version and net.subnet_of(w) for w in self.wan_subnets) or net.is_global

    def all_zone_ids(self) -> set[str]:
        return set(self.by_id)

    def endpoint_zones(self, endpoint: dict[str, Any], notes: list[str]) -> set[str]:
        """The zones an endpoint can match (over-approximated); the device itself is not a zone."""
        if endpoint.get("any") or endpoint.get("negate"):
            if endpoint.get("negate"):
                notes.append("negated address treated as any")
            return self.all_zone_ids()
        out: set[str] = set()
        cidrs = list(endpoint.get("cidrs") or [])
        for name in endpoint.get("aliases") or []:
            alias = self.aliases.get(name)
            if alias is None or not alias.get("resolved", True):
                notes.append(f"unresolved alias {display_id(name)}")
                return self.all_zone_ids()
            cidrs += alias.get("cidrs") or []
        for net_id in endpoint.get("nets") or []:
            zid = self.iface_zone.get(net_id)
            if zid:
                out.add(zid)
        for cidr in cidrs:
            net = ipaddress.ip_network(cidr)
            covered = False
            for subnet, zid in self.internal:
                if subnet.version == net.version and net.overlaps(subnet):
                    out.add(zid)
                    covered = covered or net.subnet_of(subnet)
            if not covered:
                out.add(INTERNET)
        return out

    def interface_zones(self, ids: list[str]) -> set[str]:
        return {self.iface_zone[i] for i in ids if i in self.iface_zone}


def overrides(hub: "Hub") -> dict[str, dict[str, Any]]:
    return {d["id"]: d for d in hub.store.list(ZONE_OVERRIDES)}


def topologies(hub: "Hub") -> dict[str, Topology]:
    """One topology per firewall (router, switch) with a snapshot."""
    over = overrides(hub)
    out = {}
    for snap in sorted(network.snapshots(hub), key=lambda s: s["tool_id"]):
        if (snap.get("record") or {}).get("kind") in FIREWALL_KINDS:
            out[snap["tool_id"]] = Topology(snap["tool_id"], snap["record"], over)
    return out


def all_zone_ids(hub: "Hub") -> set[str]:
    return {INTERNET} | {z for t in topologies(hub).values() for z in t.by_id}


def set_zone(hub: "Hub", zid: str, changes: dict[str, Any], actor: str) -> dict[str, Any]:
    """Admin override of a zone's role and label (None resets to the heuristic / the device's name). KeyError when
    no firewall has the zone; ValueError for a bad role or label."""
    if zid == INTERNET or zid not in all_zone_ids(hub):
        raise KeyError(zid)
    current = hub.store.get(ZONE_OVERRIDES, zid) or {"id": zid}
    if "role" in changes:
        role = changes["role"]
        if role is not None and role not in ROLES:
            raise ValueError(f"role is one of {', '.join(ROLES)}")
        current["role"] = role
    if "label" in changes:
        label = changes["label"]
        if label is not None and (not isinstance(label, str) or len(label.strip()) > 80):
            raise ValueError("label is at most 80 characters")
        current["label"] = (label.strip() or None) if isinstance(label, str) else None
    current.update({"updated_by": actor, "updated_at": time.time()})
    hub.store.put(ZONE_OVERRIDES, current)
    hub.activity(actor, "info", f"Zone {display_id(zid, 120)}: role {current.get('role') or 'from its name'}"
                                + (f", label {current['label']!r}" if current.get("label") else ""), zone_id=zid)
    changed(hub, [zid.split(":")[1]])
    return current


def set_placement(hub: "Hub", asset_id: str, zid: str | None, actor: str) -> dict[str, Any] | None:
    """Pin an asset to a zone (None removes the pin). Only where Atrium draws it - the network is not changed."""
    asset = hub.store.get("assets", asset_id)
    if asset is None:
        raise KeyError(asset_id)
    if zid is None:
        hub.store.delete(PLACEMENTS, asset_id)
        hub.activity(actor, "info", f"Asset {asset.get('name')}: placed by its addresses again", asset_id=asset_id)
        changed(hub, [])
        return None
    if zid not in all_zone_ids(hub):
        raise ValueError(f"Unknown zone {display_id(zid, 120)}")
    doc = {"id": asset_id, "zone_id": zid, "updated_by": actor, "updated_at": time.time()}
    hub.store.put(PLACEMENTS, doc)
    hub.activity(actor, "info", f"Asset {asset.get('name')}: drawn in zone {display_id(zid, 120)} (manual placement)",
                 asset_id=asset_id)
    changed(hub, [])
    return doc


# --------------------------------------------------------------------------------------
# assets in zones
# --------------------------------------------------------------------------------------


def _network(text: str) -> Any:
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def place(topology: Topology, assets: list[Asset], manual: dict[str, str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(placed assets, unplaced assets) for one firewall. Longest-prefix match per address; the first address that
    matches decides the zone, others make the asset multi-homed; a public address outside every zone is
    "external" (z:internet); a private address outside every zone or a hostname is unplaced (no DNS lookups).
    A manual placement wins, with a warning when the addresses point elsewhere."""
    from ..agents.assets import addresses

    placed, unplaced = [], []
    for asset in assets:
        if asset.status == "retired":
            continue
        found: list[str] = []
        external, unmatched, literal = False, [], False
        addrs = addresses(asset)
        for text in addrs:
            net = _network(text)
            if net is None:
                continue
            literal = True
            zid = topology.zone_of_network(net)
            if zid:
                found.append(zid)
            elif topology.is_external(net):
                external = True
                found.append(INTERNET)
            else:
                unmatched.append(text)
        found = list(dict.fromkeys(found))
        zone, how, warning = (found[0], "external" if found[0] == INTERNET else "subnet", None) if found else (None, None, None)
        pinned = manual.get(asset.id)
        if pinned and pinned in topology.by_id:
            if found and pinned not in found:
                names = ", ".join(topology.by_id[z]["name"] for z in found[:3])
                warning = f"its addresses point to {names}"
            zone, how = pinned, "manual"
        if zone is None:
            reason = ("no address" if not addrs else "hostname only" if not literal
                      else f"no zone contains {', '.join(unmatched[:3])}")
            unplaced.append({"id": asset.id, "name": asset.name, "type": asset.type, "reason": reason})
            continue
        badges = []
        if len(found) > 1:
            badges.append("multi-homed")
        if how == "external" or (how == "manual" and zone == INTERNET) or (external and zone == INTERNET):
            badges.append("external")
        if how == "manual":
            badges.append("manual")
        placed.append({"id": asset.id, "name": asset.name, "type": asset.type, "criticality": asset.criticality,
                       "zone": zone, "zones": found if zone in found else [zone, *found], "addresses": addrs[:20],
                       "placement": how, "badges": badges, "warning": warning})
    return placed, unplaced


# --------------------------------------------------------------------------------------
# allowed traffic between zones
# --------------------------------------------------------------------------------------


def service_label(proto: str, ports: str | None) -> str:
    return WELL_KNOWN.get((proto, ports)) or (f"{proto}/{ports}" if ports else proto)


def aggregate(topology: Topology) -> list[dict[str, Any]]:
    """Edges {source zone, target zone} of what the enabled pass rules may allow (see the module docstring)."""
    record, tool_id = topology.record, topology.tool_id
    names = interface_names(record)
    everything = topology.all_zone_ids()
    edges: dict[tuple[str, str], dict[str, Any]] = {}
    for rule in record.get("rules") or []:
        if not rule.get("enabled", True) or rule.get("action") != "pass":
            continue
        notes: list[str] = []
        restrict: set[str] | None = None
        if rule.get("direction") == "out":
            ingress = set(everything)
            restrict = topology.interface_zones(rule.get("interfaces") or [])
        elif rule.get("interfaces"):
            ingress = topology.interface_zones(rule["interfaces"])
        elif rule.get("source_zones"):
            ingress = {topology.vendor_zone[z] for z in rule["source_zones"] if z in topology.vendor_zone}
        else:
            ingress = set(everything)
        egress = topology.interface_zones(rule.get("out_interfaces") or []) | {
            topology.vendor_zone[z] for z in rule.get("destination_zones") or [] if z in topology.vendor_zone}
        if rule.get("out_interfaces") or rule.get("destination_zones"):
            restrict = egress if restrict is None else restrict & egress
        sources = ingress & topology.endpoint_zones(rule.get("source") or {}, notes)
        targets = topology.endpoint_zones(rule.get("destination") or {}, notes)
        if restrict is not None:
            targets &= restrict
        if not sources or not targets:
            continue
        ref = f"{tool_id}:{rule['id']}"
        entry = {"id": ref, "order": rule.get("order"), "action": "pass", "enabled": True,
                 "interfaces": rule.get("interfaces") or [], "floating": bool(rule.get("floating")),
                 "source": endpoint_text(rule.get("source") or {}, names),
                 "destination": endpoint_text(rule.get("destination") or {}, names),
                 "service": service_text(rule.get("services")), "log": bool(rule.get("log")),
                 "description": rule.get("description") or "", "hits": rule.get("hits"),
                 "any_any": bool(is_any_any(rule)), "marker": rule.get("marker")}
        for s in sorted(sources):
            for d in sorted(targets):
                if s == d:
                    continue
                edge = edges.setdefault((s, d), {
                    "id": f"zp:{s}>{d}", "source": s, "target": d, "services": [], "any_service": False,
                    "rule_count": 0, "hits": None, "bidirectional": False, "approximate": True, "notes": [],
                    "rules": [], "violations": [], "exposure": None, "pending_changes": [], "evaluable": True})
                edge["rule_count"] += 1
                edge["rules"].append(entry)
                if rule.get("hits") is not None:
                    edge["hits"] = (edge["hits"] or 0) + rule["hits"]
                for note in notes:
                    if note not in edge["notes"]:
                        edge["notes"].append(note)
                if rule.get("services") is None:
                    edge["any_service"] = True
                    continue
                for svc in rule["services"]:
                    key = (svc["proto"], svc.get("ports") or svc.get("alias"))
                    existing = next((x for x in edge["services"] if (x["proto"], x["ports"]) == key), None)
                    if existing is None:
                        existing = {"proto": svc["proto"], "ports": key[1], "label": service_label(*key), "rule_ids": []}
                        edge["services"].append(existing)
                    if ref not in existing["rule_ids"]:
                        existing["rule_ids"].append(ref)
    for (s, d), edge in edges.items():
        edge["bidirectional"] = (d, s) in edges
    return sorted(edges.values(), key=lambda e: e["id"])


def _within(services: list[dict[str, Any]], allowed: list[dict[str, Any]]) -> bool:
    """Every edge service is covered by one of the allowed services (same protocol, ports inside)."""
    for svc in services:
        ranges = port_ranges(svc.get("ports")) if svc["proto"] in ("tcp", "udp") else [(0, 0)]
        ok = any(a["proto"] == svc["proto"] and (svc["proto"] not in ("tcp", "udp") or all(
            any(lo2 <= lo and hi <= hi2 for lo2, hi2 in port_ranges(a.get("ports"))) for lo, hi in ranges))
            for a in allowed)
        if not ok:
            return False
    return True


def evaluate_policy(edge: dict[str, Any], zones: dict[str, dict[str, Any]], rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Possible violations of an edge (see the module docstring); marks edges between unclassified zones."""
    src, dst = zones.get(edge["source"]) or {}, zones.get(edge["target"]) or {}
    roles = (src.get("role", "unknown"), dst.get("role", "unknown"))
    if "unknown" in roles:
        edge["evaluable"] = False
        if "cannot evaluate: unclassified zone" not in edge["notes"]:
            edge["notes"].append("cannot evaluate: unclassified zone")
    violations, allowed = [], False
    for rule in rules:
        if rule.get("match") == "any_source_any_destination_any_service":
            if rule["verdict"] != "allowed" and any(r.get("any_any") for r in edge["rules"]):
                violations.append({"policy": rule["id"], "verdict": rule["verdict"], "control": rule.get("control"),
                                   "possible": True})
            continue
        if roles[0] not in rule.get("from", []) or roles[1] not in rule.get("to", []):
            continue
        if rule["verdict"] == "allowed":
            allowed = True
            continue
        if allowed:
            continue
        if rule["verdict"] == "restricted" and not edge["any_service"] and edge["services"] and \
                _within(edge["services"], rule.get("except_services") or []):
            continue
        violations.append({"policy": rule["id"], "verdict": rule["verdict"], "control": rule.get("control"),
                           "possible": True})
    return violations


# --------------------------------------------------------------------------------------
# overlays
# --------------------------------------------------------------------------------------


def _port(value: str | None) -> tuple[int | None, str | None]:
    """'443/tcp', '443', 'general/tcp' -> (port, proto)."""
    text = (value or "").strip().lower()
    number, _, proto = text.partition("/")
    return (int(number) if number.isdigit() else None), (proto or None)


def _on_services(vuln: Vulnerability, edge: dict[str, Any]) -> bool:
    if edge["any_service"]:
        return True
    port, proto = _port(vuln.port)
    if port is None:
        return False
    return any((proto is None or s["proto"] == proto) and s["proto"] in ("tcp", "udp")
               and any(lo <= port <= hi for lo, hi in port_ranges(s["ports"] if s["ports"] and s["ports"][0].isdigit()
                                                                      else None))
               for s in edge["services"])


def overlays(topology: Topology, zones: list[dict[str, Any]], placed: list[dict[str, Any]], edges: list[dict[str, Any]],
             vulns: list[Vulnerability]) -> None:
    """Add open-vulnerability counts to zones and assets, and exposure counts to edges coming from untrusted zones."""
    open_vulns = [v for v in vulns if v.status in OPEN_STATES]
    by_asset: dict[str, list[Vulnerability]] = {}
    for v in open_vulns:
        if v.asset_id:
            by_asset.setdefault(v.asset_id, []).append(v)
    zone_vulns: dict[str, list[Vulnerability]] = {z["id"]: [] for z in zones}
    for asset in placed:
        mine = by_asset.get(asset["id"], [])
        asset["vuln"] = {"critical": sum(1 for v in mine if v.severity == "critical"),
                         "high": sum(1 for v in mine if v.severity == "high"),
                         "overdue": sum(1 for v in mine if v.overdue)}
        zone_vulns.setdefault(asset["zone"], []).extend(mine)
    for v in open_vulns:  # findings without an asset, by the host's address
        if v.asset_id or not v.host:
            continue
        net = _network(v.host)
        zid = topology.zone_of_network(net) if net is not None else None
        if zid:
            zone_vulns[zid].append(v)
    counts = {z: {**{s: sum(1 for v in vs if v.severity == s) for s in SEVERITY_ORDER},
                  "overdue": sum(1 for v in vs if v.overdue)} for z, vs in zone_vulns.items()}
    for zone in zones:
        zone["vuln"] = counts.get(zone["id"]) or {**{s: 0 for s in SEVERITY_ORDER}, "overdue": 0}
        zone["asset_count"] = sum(1 for a in placed if a["zone"] == zone["id"])
    roles = {z["id"]: z["role"] for z in zones}
    for edge in edges:
        if edge["source"] != INTERNET and roles.get(edge["source"]) not in EXPOSING_ROLES:
            continue
        serious = [v for v in zone_vulns.get(edge["target"], []) if v.severity in ("critical", "high")]
        on = [v for v in serious if _on_services(v, edge)]
        off = [v for v in serious if v not in on]
        edge["exposure"] = {"critical": sum(1 for v in on if v.severity == "critical"),
                            "high": sum(1 for v in on if v.severity == "high"),
                            "not_on_allowed_ports": {"critical": sum(1 for v in off if v.severity == "critical"),
                                                     "high": sum(1 for v in off if v.severity == "high")}}


# --------------------------------------------------------------------------------------
# the model
# --------------------------------------------------------------------------------------

CHANGE_OPEN = ("proposed", "approved", "scheduled", "applying", "verifying")


def firewalls(hub: "Hub", now: float | None = None) -> list[dict[str, Any]]:
    now = now or time.time()
    out = []
    for snap in sorted(network.snapshots(hub), key=lambda s: s["tool_id"]):
        record = snap.get("record") or {}
        if record.get("kind") not in FIREWALL_KINDS:
            continue
        status = network.write_status(hub, snap["tool_id"], now)
        tool = hub.get_tool(snap["tool_id"])
        out.append({"tool_id": snap["tool_id"], "name": tool.name if tool else snap["tool_id"], "kind": record["kind"],
                    "snapshot": {"rev": snap["rev"], "revision": snap["revision"], "read_at": snap["read_at"],
                                 "age_s": round(now - (snap["read_at"] or now)),
                                 "stale": network.stale(hub, snap, now)},
                    "write": {"capable": status["capable"], "ops": status["ops"], "rollback": status["rollback"]},
                    "writable": status["writable"], "reason": status["reason"]})
    return out


def model(hub: "Hub", topology: Topology) -> dict[str, Any]:
    """Zones, placed and unplaced assets, and edges (with violations and exposure) of one firewall."""
    assets = hub.all("assets", Asset)
    manual = {d["id"]: d["zone_id"] for d in hub.store.list(PLACEMENTS)}
    placed, unplaced = place(topology, assets, manual)
    zones = [dict(z) for z in topology.zones]
    edges = aggregate(topology)
    by_id = {z["id"]: z for z in zones}
    rules = policy(hub)["rules"]
    for edge in edges:
        edge["violations"] = evaluate_policy(edge, by_id, rules)
    overlays(topology, zones, placed, edges, hub.all("vulnerabilities", Vulnerability))
    return {"zones": zones, "assets": placed, "unplaced": unplaced, "edges": edges}


def _same_subnets(hub: "Hub", selected: Topology, tops: dict[str, Topology]) -> None:
    for zone in selected.zones:
        if not zone["subnets"]:
            continue
        mine = set(zone["subnets"])
        zone["same_subnet_as"] = sorted(z["id"] for tool_id, t in tops.items() if tool_id != selected.tool_id
                                        for z in t.zones if mine & set(z["subnets"]))


def view(hub: "Hub", firewall: str | None = None) -> dict[str, Any]:
    """GET /api/segmentation (canvas-design 7.5). `firewall`: the tool id to show (default: the first one)."""
    now = time.time()
    tops = topologies(hub)
    guards = hub.prefs["guardrails"]
    layout = hub.store.get("canvas_layouts", "segmentation") or {"id": "segmentation", "version": 0, "items": {}}
    out: dict[str, Any] = {
        "generated_at": now, "firewalls": firewalls(hub, now), "selected": None,
        "evaluation": {"mode": "approximate", "notes": [EVALUATION_NOTE]},
        "zones": [], "assets": [], "unplaced": [], "edges": [], "changes": [],
        "guardrails": {"device_changes": bool(guards.get("device_changes", False)),
                       "device_changes_need_second_person": bool(guards.get("device_changes_need_second_person", True))},
        "policy_version": policy(hub)["version"], "layout": layout,
    }
    if not tops:
        return out
    if firewall is not None and firewall not in tops:
        raise KeyError(firewall)
    selected = tops[firewall or next(iter(tops))]
    _same_subnets(hub, selected, tops)
    out.update(model(hub, selected))
    out["selected"] = selected.tool_id
    changes = [c for c in hub.store.list(network.CHANGES)
               if c.get("firewall") == selected.tool_id and c.get("status") in CHANGE_OPEN]
    edges = {e["id"]: e for e in out["edges"]}
    for change in sorted(changes, key=lambda c: c.get("created_at") or 0):
        out["changes"].append({k: change.get(k) for k in ("id", "status", "op", "edge", "approval_id",
                                                          "rollback_until", "proposed_by", "created_at")})
        if change.get("edge") in edges:
            edges[change["edge"]]["pending_changes"].append(change["id"])
    return out


def compliance(hub: "Hub") -> dict[str, Any]:
    """What HB-NW-1 / HB-NW-5 evaluate, over every firewall: possible violations (as roles and ids, never device
    text), zones whose role is not confirmed, unresolved aliases."""
    tops = topologies(hub)
    violations, unconfirmed, unresolved = [], [], []
    for tool_id, topology in tops.items():
        result = model(hub, topology)
        roles = {z["id"]: z["role"] for z in result["zones"]}
        for edge in result["edges"]:
            for v in edge["violations"]:
                violations.append({"firewall": display_id(tool_id), "from": roles[edge["source"]],
                                   "to": roles[edge["target"]], "policy": v["policy"], "verdict": v["verdict"],
                                   "control": v.get("control")})
        unconfirmed += [f"{display_id(tool_id)}:{z['role']}" for z in result["zones"] if z["role_source"] == "heuristic"]
        unresolved += [f"{display_id(tool_id)}:{display_id(a['name'])}" for a in topology.aliases.values()
                       if not a.get("resolved", True)]
    return {"firewalls": len(tops), "violations": violations, "unconfirmed_roles": unconfirmed,
            "unresolved_aliases": unresolved}
