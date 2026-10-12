"""FortiGate (FortiOS) connector: REST API reads, writes only with workspace transactions.

Follows ``docs/research/fw-fortigate-panos-cisco.md`` section 2. Verified there: Bearer token, the JSON
envelope (``status`` / ``http_status`` / ``revision`` / ``results``), ``firewall/address``, transaction
start/show/commit with ``X-TRANSACTION-ID`` (7.4.1+), backup method switch at 7.6.0, and policy attribute
names. Many cmdb paths are not in the public REST reference; those are marked ``UNVERIFIED``.

Writes are inverse-op rollback (``backup_restore``): a config revision is saved before the transaction, the
batch is committed only if it stages cleanly, and rollback disables what an allow created (it does not delete).
A full config restore reboots the unit and is only the last resort. FortiOS has no per-change commit-confirm;
``cfg-save revert`` is an operator setting this connector never toggles.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from typing import Any
from urllib.parse import urlsplit

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (
    LEAST_PRIVILEGE_NOTE,
    Backup,
    ChangeError,
    derived_revision,
    management_guard,
    marker,
    normalize_record,
    parse_ops,
    untrusted_text,
)

API = "/api/v2"
WINDOW_S = 120
# Workspace transactions (transaction-show) exist from 7.4.1. Backup GET returns 405 from 7.6.0.
TRANSACTIONS_FROM = (7, 4, 1)
BACKUP_POST_FROM = (7, 6, 0)
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:/-]{1,64}$")
VDOM_RE = re.compile(r"^[A-Za-z0-9_.-]{1,31}$")
# UNVERIFIED: predefined service names are not in the FortiOS REST reference we could read. Custom objects win.
PREDEFINED: dict[str, list[dict[str, Any]]] = {
    "ALL": [],
    "HTTP": [{"proto": "tcp", "ports": "80"}],
    "HTTPS": [{"proto": "tcp", "ports": "443"}],
    "DNS": [{"proto": "udp", "ports": "53"}, {"proto": "tcp", "ports": "53"}],
    "PING": [{"proto": "icmp"}],
    "SSH": [{"proto": "tcp", "ports": "22"}],
}
PAGE = 500


def parse_version(value: Any) -> tuple[int, int, int] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", str(value or ""))
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def transactions_supported(version: tuple[int, int, int] | None) -> bool:
    return version is not None and version >= TRANSACTIONS_FROM


def _safe_name(value: Any, what: str) -> str:
    text = str(value or "").strip()
    if not SAFE_NAME.fullmatch(text):
        raise ChangeError(f"{what} {untrusted_text(value, 40)!r} cannot be sent to the device",
                          code="invalid", state="unchanged")
    return text


def _policy_id(value: Any) -> str:
    text = str(value if value is not None else "").strip()
    if not text.isdigit() or int(text) < 1:
        raise ChangeError(f"policy id {untrusted_text(value, 40)!r} is not a FortiGate policyid",
                          code="invalid", state="unchanged")
    return str(int(text))


def _names(value: Any) -> list[str]:
    items = value if isinstance(value, list) else []
    out = []
    for item in items:
        if isinstance(item, dict):
            name = item.get("name") or item.get("interface-name") or item.get("q_origin_key")
        else:
            name = item
        text = str(name or "").strip()
        if text and text not in out:
            out.append(text)
    return out


def _subnet(value: Any) -> str | None:
    text = str(value or "").strip()
    parts = text.split()
    if len(parts) == 2:  # UNVERIFIED: "address netmask" form seen in interface/address examples, not the REST reference
        try:
            return str(ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_network(text, strict=False)) if text else None
    except ValueError:
        return None


def _interface_net(value: Any) -> tuple[list[str], list[str]]:
    network = _subnet(value)
    if not network:
        return [], []
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return [], []
    if parsed.prefixlen == 0:
        return [], []
    address = str(parsed.network_address) if parsed.prefixlen == parsed.max_prefixlen else None
    # A host address with a mask ("10.0.10.1 255.255.255.0") is the interface address, not the network address.
    parts = str(value or "").split()
    if parts:
        try:
            address = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            address = None
    if address in (None, "0.0.0.0", "::"):
        return [], []
    return [network], [address]


def _object_name(kind: str, key: str) -> str:
    return f"atr-{kind}-{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _service_specs(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """UNVERIFIED: ``tcp-portrange`` / ``udp-portrange`` / ``protocol`` ICMP on firewall.service/custom."""
    protocol = str(obj.get("protocol") or "")
    if protocol.upper() == "ICMP" or obj.get("protocol") == "ICMP":
        return [{"proto": "icmp"}]
    out: list[dict[str, Any]] = []
    for proto, field in (("tcp", "tcp-portrange"), ("udp", "udp-portrange")):
        raw = obj.get(field)
        if not raw:
            continue
        ports = str(raw).replace(" ", ",")
        try:
            from .netmodel import parse_ports

            parsed = parse_ports(ports)
        except ValueError:
            continue
        if parsed:
            out.append({"proto": proto, "ports": parsed})
    return out


class FortiGateConnector(Connector):
    kind = "fortigate"
    title = "FortiGate"
    description = ("FortiOS REST API: reads firewall policy, zones, interfaces and address objects. "
                   "Rule changes need FortiOS 7.4.1 or newer (workspace transactions) and a token whose "
                   "profile can edit policy; rollback is inverse operations. Older versions are read-only.")
    fields = [
        ConnectorField(name="base_url", label="FortiGate URL", kind="url", required=True,
                       placeholder="https://firewall.example", help="HTTPS address of the FortiGate. The API token "
                       "is sent only here."),
        ConnectorField(name="token", label="REST API token", kind="secret", required=True,
                       help="System > Administrators > REST API Admin. A read-only profile "
                            "(super_admin_readonly, or fwgrp/netgrp/sysgrp read) is enough until device changes "
                            "are enabled. Backups of the full configuration need super_admin."),
        ConnectorField(name="vdom", label="VDOM", default="root",
                       help="Virtual domain to read and, when writes are on, to change."),
        ConnectorField(name="can_write", label="Token can edit firewall policy", kind="bool", default=False,
                       help="Turn on only when this token's accprofile has firewall policy, address and service "
                            "read-write. Leave off for a read-only token."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="FortiOS 7.2.1+ presents a certificate signed by the built-in Fortinet_CA_SSL unless you "
                            "installed your own. Pin that CA in the CA file field."),
        ConnectorField(name="ca_file", label="CA certificate file", placeholder="/etc/atrium/fortinet-ca.pem",
                       help="Optional PEM file used to verify the FortiGate certificate."),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "backup_restore",
                     "window_s": WINDOW_S}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("fortigate", "fortios", "fortinet"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        local = parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
        if not (parts.scheme == "https" or local) or not parts.hostname:
            raise ConnectorError("The FortiGate URL must start with https:// (the API token must not travel in clear text)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API token in its own field, not in the URL")
        base = re.sub(r"(?i)/api/v2$", "", base)
        vdom = str(config.get("vdom") or "root").strip()
        if not VDOM_RE.fullmatch(vdom):
            raise ConnectorError("The VDOM name is 1-31 letters, digits, '.', '_' and '-'")
        ca = str(config.get("ca_file") or "").strip()
        if ca and not ca.startswith("/"):
            raise ConnectorError("The CA certificate file must be an absolute path")
        return {**config, "base_url": base, "vdom": vdom, "ca_file": ca}

    def write_capability(self) -> dict[str, Any] | None:
        if not self.config.get("can_write"):
            return None
        return super().write_capability()

    def _verify(self) -> bool | str:
        ca = str(self.config.get("ca_file") or "").strip()
        if ca:
            return ca
        return bool(self.config.get("verify_tls", True))

    def client(self):
        token = self.secrets.get("token")
        if not token:
            raise self.error("Enter the FortiGate REST API token in the connection settings")
        # Bearer is the documented header. URL-query tokens are disabled by default from 7.4.5 and are never used.
        return self.http(f"{str(self.config.get('base_url') or '').rstrip('/')}{API}",
                         headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
                         verify=self._verify())

    def _change(self, message: str, *, code: str = "failed", state: str = "unknown",
                status: int | None = None, excerpt: str | None = None) -> ChangeError:
        err = self.error(message, status=status, excerpt=excerpt)
        return ChangeError(err.message, code=code, state=state, status=err.status, excerpt=err.excerpt)

    def _from_connector(self, exc: ConnectorError, *, code: str, state: str) -> ChangeError:
        if isinstance(exc, ChangeError):
            return exc
        return ChangeError(exc.message, code=code, state=state, status=exc.status, excerpt=exc.excerpt)

    async def _call(self, client, method: str, path: str, *, what: str, params: dict[str, Any] | None = None,
                    body: dict[str, Any] | None = None, txn: str | None = None) -> dict[str, Any]:
        headers = {"X-TRANSACTION-ID": txn} if txn else None
        query = {"vdom": self.config.get("vdom") or "root", **(params or {})}
        try:
            response = await client.request(method, path, params=query, json=body, headers=headers)
        except Exception as exc:  # request_json maps these; keep the same wording
            if isinstance(exc, ConnectorError):
                raise
            from httpx import HTTPError, TimeoutException

            name = self.title
            if isinstance(exc, TimeoutException):
                raise self.error(f"{name} did not answer in time ({what})") from exc
            if isinstance(exc, HTTPError):
                raise self.error(f"Cannot reach {name}: {exc.__class__.__name__}") from exc
            raise
        self.raise_for_status(response, what)
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError as exc:
            raise self.error(f"{self.title} did not answer with JSON ({what})", status=response.status_code,
                             excerpt=response.text) from exc
        if not isinstance(data, dict):
            raise self.error(f"{self.title} returned an unexpected JSON document ({what})", status=response.status_code)
        self._envelope(data, what)
        return data

    def _envelope(self, data: dict[str, Any], what: str) -> None:
        """A FortiOS error envelope is a failure even when the HTTP status is 200."""
        status = str(data.get("status") or "").lower()
        raw = data.get("http_status")
        try:
            http_status = int(raw) if raw not in (None, "") else None
        except (TypeError, ValueError):
            http_status = None
        if status == "error" or (http_status is not None and http_status >= 400):
            code = data.get("error")
            detail = untrusted_text(data.get("cli_error"), 180)
            message = (f"{self.title} rejected {what} (status {status or 'error'}, HTTP {http_status if http_status is not None else '?'}"
                       + (f", error {code}" if code not in (None, "") else "")
                       + (f": {detail}" if detail else "") + ")")
            excerpt = json.dumps({k: data.get(k) for k in ("status", "http_status", "error", "cli_error")
                                  if k in data}, default=str)
            raise self.error(message, status=http_status, excerpt=excerpt)

    async def _table(self, client, path: str, what: str, *, txn: str | None = None) -> tuple[list[dict[str, Any]], str]:
        """UNVERIFIED: cmdb tables honour ``start``/``count`` the way monitor calls do. Paging stops on a short page."""
        rows: list[dict[str, Any]] = []
        revision = ""
        start = 0
        for _ in range(40):
            data = await self._call(client, "GET", path, what=what, params={"start": start, "count": PAGE}, txn=txn)
            revision = str(data.get("revision") or revision)
            chunk = data.get("results")
            if isinstance(chunk, dict):
                chunk = [chunk]
            if not isinstance(chunk, list):
                break
            rows.extend(item for item in chunk if isinstance(item, dict))
            if len(chunk) < PAGE:
                break
            start += PAGE
        return rows, revision

    async def _optional_table(self, client, path: str, what: str) -> list[dict[str, Any]]:
        try:
            rows, _revision = await self._table(client, path, what)
            return rows
        except ConnectorError:
            return []

    # -- reading -----------------------------------------------------------------------

    def _index_addresses(self, rows: list[dict[str, Any]]) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
        cidrs: dict[str, list[str]] = {}
        aliases = []
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name or name.lower() in ("all", "none"):
                continue
            network = _subnet(row.get("subnet") or row.get("ip") or row.get("start-ip"))
            if network and ipaddress.ip_network(network).prefixlen != 0:
                cidrs[name] = [network]
                aliases.append({"name": name, "kind": "network", "cidrs": [network], "resolved": True})
            elif row.get("fqdn"):
                aliases.append({"name": name, "kind": "other", "resolved": False})
            else:
                aliases.append({"name": name, "kind": "network", "resolved": False})
        return cidrs, aliases

    def _index_groups(self, rows: list[dict[str, Any]], cidrs: dict[str, list[str]]) -> dict[str, dict[str, Any]]:
        groups = {}
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            members = _names(row.get("member"))
            resolved = [c for member in members for c in cidrs.get(member, [])]
            if members and all(member in cidrs for member in members):
                groups[name] = {"name": name, "kind": "network", "cidrs": resolved, "resolved": True}
            else:
                groups[name] = {"name": name, "kind": "network", "resolved": False}
        return groups

    def _index_services(self, rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
        found: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            specs = _service_specs(row)
            if specs:
                found[name] = specs
        return found

    def _endpoint(self, members: list[str], cidrs: dict[str, list[str]], groups: dict[str, dict[str, Any]],
                  negate: bool) -> dict[str, Any]:
        if any(name.lower() == "all" for name in members):
            return {"any": True, "negate": negate}
        out_cidrs: list[str] = []
        aliases: list[str] = []
        for name in members:
            if name in groups:
                aliases.append(name)
            elif name in cidrs:
                out_cidrs.extend(cidrs[name])
            else:
                aliases.append(name)
        endpoint: dict[str, Any] = {}
        if out_cidrs:
            endpoint["cidrs"] = out_cidrs
        if aliases:
            endpoint["aliases"] = aliases
        if negate:
            endpoint["negate"] = True
        return endpoint or {"any": True}

    def _rule_services(self, members: list[str], services: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
        if not members or any(name.upper() == "ALL" for name in members):
            return None
        out: list[dict[str, Any]] = []
        for name in members:
            specs = services.get(name)
            if specs is None and name.upper() in PREDEFINED:
                specs = PREDEFINED[name.upper()]
            if specs is None:
                out.append({"proto": "tcp", "alias": name, "name": name})
            else:
                out.extend(specs)
        return out or None

    def _interfaces(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # UNVERIFIED: system/interface field names (ip, vlanid, allowaccess, role, status).
        out = []
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            subnets, addresses = _interface_net(row.get("ip"))
            role = str(row.get("role") or "").strip().lower()
            if role not in ("lan", "wan", "mgmt", "other"):
                access = str(row.get("allowaccess") or "").lower()
                role = "mgmt" if any(flag in access.split() for flag in ("https", "ssh", "http")) else "other"
            vlan = row.get("vlanid")
            item: dict[str, Any] = {"id": name, "name": name, "role": role, "subnets": subnets,
                                    "addresses": addresses, "enabled": str(row.get("status") or "up").lower() != "down",
                                    "description": row.get("description") or ""}
            if vlan not in (None, "", 0, "0"):
                item["vlan"] = vlan
            out.append(item)
        return out

    def _zones(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # UNVERIFIED: system/zone member list (interface-name versus name).
        out = []
        for row in rows:
            name = str(row.get("name") or "").strip()
            if not name:
                continue
            members = _names(row.get("interface") or row.get("member"))
            out.append({"id": name, "name": name, "interfaces": members, "description": row.get("description") or ""})
        return out

    def _rules(self, rows: list[dict[str, Any]], cidrs: dict[str, list[str]], groups: dict[str, dict[str, Any]],
               services: dict[str, list[dict[str, Any]]], hits: dict[str, int], zone_ids: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
        rules, notes = [], []
        skipped = 0
        for order, row in enumerate(rows, start=1):
            action = str(row.get("action") or "").lower()
            if action in ("ipsec", "ipsec-dia"):  # not a pass/block/reject filter rule
                skipped += 1
                continue
            policy_id = row.get("policyid")
            if policy_id in (None, ""):
                continue
            src = _names(row.get("srcintf"))
            dst = _names(row.get("dstintf"))
            rule: dict[str, Any] = {
                "id": str(policy_id), "vendor_ref": str(policy_id), "order": order,
                "enabled": str(row.get("status") or "enable").lower() == "enable",
                "action": action or "accept", "direction": "in",
                "interfaces": src, "out_interfaces": dst,
                "source_zones": [name for name in src if name in zone_ids],
                "destination_zones": [name for name in dst if name in zone_ids],
                "source": self._endpoint(_names(row.get("srcaddr")), cidrs, groups,
                                         str(row.get("srcaddr-negate") or "").lower() == "enable"),
                "destination": self._endpoint(_names(row.get("dstaddr")), cidrs, groups,
                                              str(row.get("dstaddr-negate") or "").lower() == "enable"),
                "services": self._rule_services(_names(row.get("service")), services),
                "log": str(row.get("logtraffic") or "").lower() in ("all", "utm"),
                "description": row.get("comments") or "",
            }
            hit = hits.get(str(policy_id))
            if hit is not None:
                rule["hits"] = hit
            rules.append(rule)
        if skipped:
            notes.append(f"{skipped} IPsec policies are not firewall filter rules and were left out")
        return rules, notes

    async def _read(self, client) -> dict[str, Any]:
        status = await self._call(client, "GET", "/monitor/system/status", what="reading system status")
        version = str(status.get("version") or "")
        results = status.get("results") if isinstance(status.get("results"), dict) else {}
        interfaces = self._interfaces(await self._optional_table(client, "/cmdb/system/interface", "reading interfaces"))
        zones = self._zones(await self._optional_table(client, "/cmdb/system/zone", "reading zones"))
        address_rows = await self._optional_table(client, "/cmdb/firewall/address", "reading addresses")
        cidrs, aliases = self._index_addresses(address_rows)
        groups = self._index_groups(await self._optional_table(client, "/cmdb/firewall/addrgrp", "reading address groups"), cidrs)
        services = self._index_services(await self._optional_table(client, "/cmdb/firewall.service/custom", "reading services"))
        policies, revision = await self._table(client, "/cmdb/firewall/policy", "reading firewall policy")
        hits: dict[str, int] = {}
        notes: list[str] = []
        try:
            hit_rows, _rev = await self._table(client, "/monitor/firewall/policy", "reading policy hit counts")
            for row in hit_rows:  # UNVERIFIED: hit_count field name on the monitor policy selector
                if row.get("policyid") is not None and row.get("hit_count") is not None:
                    hits[str(row["policyid"])] = row["hit_count"]
        except ConnectorError:
            notes.append("hit counts are not available with this token or FortiOS version")
        zone_ids = {z["id"] for z in zones}
        rules, rule_notes = self._rules(policies, cidrs, groups, services, hits, zone_ids)
        notes.extend(rule_notes)
        global_rows = await self._optional_table(client, "/cmdb/system/global", "reading system global")
        cfg_save = str((global_rows[0] if global_rows else {}).get("cfg-save") or "")
        if cfg_save and cfg_save != "automatic":
            notes.append(f"cfg-save is {untrusted_text(cfg_save, 40)}; unsaved changes follow that mode")
        if await self._centrally_managed(client):
            notes.append("this FortiGate reports central management; local policy writes are refused")
        if not revision:
            revision = str(status.get("revision") or "") or derived_revision(policies)
        serial = str(status.get("serial") or results.get("serial") or "")
        hostname = str(results.get("hostname") or "")
        external = serial or hostname or urlsplit(str(self.config.get("base_url") or "")).hostname or "fortigate"
        self_addresses = [addr for iface in interfaces for addr in iface.get("addresses") or []]
        host = urlsplit(str(self.config.get("base_url") or "")).hostname or ""
        return {
            "external_id": external, "revision": revision, "read_at": time.time(), "kind": "firewall",
            "device": {"vendor": "Fortinet", "model": results.get("model") or "", "version": version,
                       "hostname": hostname, "management_address": host, "serial": serial},
            "interfaces": interfaces, "zones": zones,
            "aliases": aliases + [g for g in groups.values() if g["name"] not in {a["name"] for a in aliases}],
            "self_addresses": self_addresses, "rules": rules,
            "default_policy": {"forward": "block"}, "nat_evaluated": False,
            "notes": notes + ["NAT and local-in policy are not part of this ruleset"],
            "_cfg_save": cfg_save, "_version": version,
        }

    async def _centrally_managed(self, client) -> bool:
        # UNVERIFIED: cmdb/system/central-management status enable means FortiManager.
        try:
            rows, _rev = await self._table(client, "/cmdb/system/central-management", "reading central management")
        except ConnectorError:
            return False
        for row in rows:
            if str(row.get("status") or "").lower() in ("enable", "enabled"):
                return True
        return False

    def _public(self, record: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in record.items() if not k.startswith("_")}

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        tls_on = bool(self.config.get("verify_tls", True) or self.config.get("ca_file"))
        try:
            async with self.client() as client:
                record = await self._read(client)
        except ConnectorError as exc:
            return self._test_failed(exc, checks, tls_on)
        checks.append(check("reachability", True, f"{self.config.get('base_url')} answers"))
        if self.config.get("ca_file"):
            checks.append(check("tls", True, "certificate verified with the configured CA file"))
        elif self.config.get("verify_tls", True):
            checks.append(check("tls", True, "certificate verification is on"))
        else:
            checks.append(check("tls", False, "TLS certificate verification is turned off in the connection"))
        checks.append(check("authentication", True, "REST API token accepted"))
        version = parse_version(record.get("_version"))
        writable = transactions_supported(version) and self.write_capability() is not None
        managed = any("central management" in note for note in record.get("notes") or [])
        if managed:
            writable = False
        if self.config.get("can_write"):
            privilege = LEAST_PRIVILEGE_NOTE
        else:
            privilege = "read-only credential: device changes are unavailable"
        checks.append(check("privileges", True, privilege))
        shown = record.get("_version") or "unknown"
        if version is None:
            checks.append(check("version", True, f"FortiOS {shown} (version string was not recognised; writes stay off)"))
            writable = False
        elif transactions_supported(version):
            checks.append(check("version", True, f"FortiOS {shown} (workspace transactions supported)"))
        else:
            checks.append(check("version", True, f"FortiOS {shown} is supported for read; writes need 7.4.1 or newer"))
        features = "firewall policy, interfaces, zones, addresses"
        if writable:
            features += f"; writes via workspace transaction, rollback inverse ops, window {WINDOW_S}s"
        elif managed:
            features += "; local writes refused because central management is enabled"
        else:
            features += "; writes off"
        cfg_save = record.get("_cfg_save") or "automatic"
        if cfg_save != "automatic":
            features += f"; cfg-save={untrusted_text(cfg_save, 40)} (not changed by Atrium)"
        checks.append(check("api_features", True, features))
        ok = all(item["ok"] for item in checks)
        write = self.write_capability() if writable and ok else None
        return {"ok": ok, "detail": f"Connected to FortiGate {record.get('external_id')} ({record.get('revision')}).",
                "checks": checks, "domains": self.domains() if ok else {}, "network_write": write}

    def _test_failed(self, exc: ConnectorError, checks: list[dict[str, Any]], tls_on: bool) -> dict[str, Any]:
        text = exc.message
        if "Cannot reach" in text or "did not answer in time" in text:
            if "certificate" in text.lower() or "tls" in text.lower():
                checks.append(check("reachability", True, "the host answered"))
                checks.append(check("tls", False, text))
            else:
                checks.append(check("reachability", False, text))
        else:
            checks.append(check("reachability", True, f"{self.config.get('base_url')} answers"))
            checks.append(check("tls", tls_on, "certificate verification is on" if tls_on else
                                "TLS certificate verification is turned off in the connection"))
            if exc.status == 401:
                checks.append(check("authentication", False, "the API token was refused (HTTP 401) or the source "
                                "address is not a trusted host"))
            elif exc.status == 403:
                checks.append(check("authentication", True, "token accepted"))
                checks.append(check("privileges", False, "the token cannot read firewall policy (HTTP 403)"))
            else:
                checks.append(check("authentication", False, text))
        return {"ok": False, "detail": text, "checks": checks, "domains": {}, "network_write": None}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self.client() as client:
            return [self._public(await self._read(client))]

    # -- backups -----------------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        try:
            async with self.client() as client:
                status = await self._call(client, "GET", "/monitor/system/status", what="reading system status")
                version = parse_version(status.get("version"))
                content, revision_id = await self._backup(client, version)
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed", state="unchanged") from exc
        digest = hashlib.sha256(content).hexdigest()
        return {"content": content, "format": "json" if content.startswith(b"{") else "text",
                "device_backup_id": revision_id, "revision": str(status.get("revision") or "") or None,
                "sha256": digest}

    async def _backup(self, client, version: tuple[int, int, int] | None) -> tuple[bytes, str | None]:
        method = "POST" if version is not None and version >= BACKUP_POST_FROM else "GET"
        response = await client.request(method, "/monitor/system/config/backup", params={"scope": "global"})
        # A read-only profile is not allowed to download the full configuration (super_admin). Keep a policy
        # snapshot instead of failing the hub's backup step closed.
        if response.status_code in (401, 403):
            return await self._policy_snapshot(client), await self._save_revision(client, "atrium backup")
        if response.status_code >= 300:
            self.raise_for_status(response, "taking a configuration backup")
        raw = response.content or b""
        if raw[:1] in (b"{", b"["):
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeError, ValueError):
                data = None
            if isinstance(data, dict):
                try:
                    self._envelope(data, "taking a configuration backup")
                except ConnectorError as exc:
                    if exc.status in (401, 403):
                        return await self._policy_snapshot(client), await self._save_revision(client, "atrium backup")
                    raise
                if "results" in data:
                    return await self._policy_snapshot(client), await self._save_revision(client, "atrium backup")
        if not raw:
            raise self._change("FortiGate returned an empty configuration backup", code="failed", state="unchanged")
        return raw, await self._save_revision(client, "atrium backup")

    async def _policy_snapshot(self, client) -> bytes:
        policies, revision = await self._table(client, "/cmdb/firewall/policy", "reading firewall policy")
        payload = {"kind": "fortigate-policy-snapshot", "revision": revision, "policies": policies}
        return json.dumps(payload, sort_keys=True).encode("utf-8")

    async def _save_revision(self, client, comment: str) -> str | None:
        # comments text is ours (a fixed phrase or an atrium marker), never device text.
        try:
            data = await self._call(client, "POST", "/monitor/system/config-revision/save",
                                    what="saving a config revision", body={"comments": comment})
        except ConnectorError:
            return None
        results = data.get("results")
        if isinstance(results, dict):
            for key in ("config_id", "id", "mkey"):
                if results.get(key) not in (None, ""):
                    return str(results[key])
        return None

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        try:
            raw = backup.content
        except Exception as exc:
            raise self._change("The backup could not be read", code="invalid", state="unchanged") from exc
        if raw[:1] in (b"{", b"["):
            raise self._change("This backup is a policy snapshot, not a full FortiOS configuration. "
                               "Roll the change back with inverse operations; a full restore reboots the unit "
                               "and needs the configuration file from a super_admin backup.",
                               code="unsupported", state="unchanged")
        # UNVERIFIED: restore ``source`` values are not documented. ``upload`` matches the file_content parameter.
        try:
            text = raw.decode("utf-8")
        except UnicodeError as exc:
            raise self._change("The backup is not a text configuration", code="invalid", state="unchanged") from exc
        try:
            async with self.client() as client:
                await self._call(client, "POST", "/monitor/system/config/restore", what="restoring the configuration",
                                 body={"source": "upload", "scope": "global", "file_content": text})
                status = await self._call(client, "GET", "/monitor/system/status", what="reading system status")
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed", state="unknown") from exc
        return {"restored": True, "revision": str(status.get("revision") or "") or None,
                "notes": ["a configuration restore reboots the FortiGate; treat it as a last resort"]}

    # -- changes -----------------------------------------------------------------------

    def _zones_of(self, record: dict[str, Any]) -> set[str]:
        return {i["id"] for i in record.get("interfaces") or []} | {z["id"] for z in record.get("zones") or []}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        try:
            ops = parse_ops(ops)
        except ValueError as exc:
            raise self._change(str(exc), code="invalid", state="unchanged") from exc
        try:
            async with self.client() as client:
                record = self._public(await self._read(client))
        except ConnectorError as exc:
            raise self._from_connector(exc, code="unreachable", state="unchanged") from exc
        try:
            normalised = normalize_record(record)
        except ValueError as exc:
            raise self._change(str(exc), code="invalid", state="unchanged") from exc
        problems = management_guard(normalised, ops)
        zones = self._zones_of(record)
        steps = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    zone = op[side]["zone"]
                    if zone not in zones:
                        problems.append(f"the device has no interface or zone {untrusted_text(zone, 40)!r}")
                steps.append({"op": index, "kind": "add_rule",
                              "position": f"before the first policy on {op['source']['zone']}",
                              "detail": "one accept policy, marked " + op["marker"]})
            else:
                kind = "disable_rule" if op["op"] == "disable_rules" else "enable_rule"
                steps.extend({"op": index, "kind": kind, "position": "in place",
                              "detail": f"{op['op']} {ref['vendor_ref']}"} for ref in op["rules"])
        version = parse_version((record.get("device") or {}).get("version"))
        notes = ["rollback is inverse operations (disable the created policy); there is no commit-confirm timer"]
        if not transactions_supported(version):
            problems.append("this FortiOS version has no workspace transactions (need 7.4.1); the change cannot be applied")
        if any("central management" in note for note in record.get("notes") or []):
            problems.append("this FortiGate is centrally managed; local policy writes are refused")
        if self.write_capability() is None:
            problems.append("this connection is read-only")
        return {"steps": steps, "notes": notes, "problems": problems}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        if self.write_capability() is None:
            raise self._change("This connection is read-only", code="unsupported", state="unchanged")
        try:
            ops = parse_ops(ops)
        except ValueError as exc:
            raise self._change(str(exc), code="invalid", state="unchanged") from exc
        try:
            async with self.client() as client:
                record = await self._read(client)
                version = parse_version(record.get("_version"))
                if not transactions_supported(version):
                    raise self._change("This FortiOS version has no workspace transactions (need 7.4.1). "
                                       "The connector will not write live policy one call at a time.",
                                       code="unsupported", state="unchanged")
                if await self._centrally_managed(client):
                    raise self._change("This FortiGate is centrally managed. Refusing a local policy write.",
                                       code="invalid", state="unchanged")
                if str(record.get("revision") or "") != str(base_revision):
                    raise self._change(f"The device is at revision {record.get('revision')}, not {base_revision}: "
                                       "re-read it and preview again", code="stale", state="unchanged")
                public = self._public(record)
                try:
                    normalised = normalize_record(public)
                except ValueError as exc:
                    raise self._change(str(exc), code="invalid", state="unchanged") from exc
                problems = management_guard(normalised, ops)
                zones = self._zones_of(public)
                extra = []
                for op in ops:
                    if op["op"] != "allow":
                        continue
                    for side in ("source", "destination"):
                        zone = op[side]["zone"]
                        if zone not in zones:
                            extra.append(f"the device has no interface or zone {untrusted_text(zone, 40)!r}")
                        else:
                            _safe_name(zone, "interface or zone")
                if problems or extra:
                    raise self._change("Refused: " + "; ".join(problems + extra),
                                       code="lockout" if problems else "invalid", state="unchanged")
                change_id = next((op["marker"].split(":", 1)[1] for op in ops if op["op"] == "allow"), "rules")
                # Arm rollback before any policy write. A failed save means we have not changed the device.
                snapshot = await self._save_revision(client, f"atrium change {change_id}"[:120])
                if snapshot is None:
                    raise self._change("Could not save a config revision before writing, so nothing was changed. "
                                       "The token needs permission to save a configuration revision.",
                                       code="failed", state="unchanged")
                return await self._transact(client, ops, snapshot, str(record.get("revision") or ""))
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed" if exc.status not in (None, 401) else "unreachable",
                                       state="unchanged") from exc

    async def _transact(self, client, ops: list[dict[str, Any]], snapshot: str, previous: str) -> dict[str, Any]:
        # UNVERIFIED: the unit of {"timeout": N}. The documented example sends 60. Abort's REST name is not documented.
        started = False
        txn = ""
        try:
            opened = await self._call(client, "POST", "/cmdb", what="starting a workspace transaction",
                                      params={"action": "transaction-start"}, body={"timeout": 60})
            txn = str(self._txn_id(opened))
            started = True
            created, disabled = [], []
            for index, op in enumerate(ops):
                if op["op"] == "allow":
                    created.append(await self._allow(client, txn, index, op))
                else:
                    enable = op["op"] == "enable_rules"
                    for ref in op["rules"]:
                        policy = _policy_id(ref.get("vendor_ref") or ref.get("id"))
                        await self._call(client, "PUT", f"/cmdb/firewall/policy/{policy}",
                                         what="updating a firewall policy", txn=txn,
                                         body={"status": "enable" if enable else "disable"})
                        disabled.append(policy)
            await self._call(client, "POST", "/cmdb", what="committing a workspace transaction",
                             params={"action": "transaction-commit"}, body={"transaction-id": int(txn)}, txn=txn)
            started = False
        except ConnectorError as exc:
            state = "unchanged"
            if started:
                state = "unchanged" if await self._abort(client, txn) else "unknown"
            raise self._from_connector(exc, code="failed", state=state) from exc
        policies, revision = await self._table(client, "/cmdb/firewall/policy", "reading firewall policy")
        token = json.dumps({"v": 1, "vdom": self.config.get("vdom") or "root", "snapshot": snapshot,
                            "previous": previous, "created": created, "disabled": disabled,
                            "marker": next((op["marker"] for op in ops if op["op"] == "allow"), "")},
                           separators=(",", ":"))
        if len(token) > 4096:
            raise self._change("The change was committed but its token does not fit the hub limit; roll it back "
                               "from the config revision that was saved first", code="failed", state="applied")
        return {"token": token, "rollback_until": None, "revision": revision or None, "created": created,
                "disabled": disabled, "notes": ["workspace transaction committed; rollback is inverse operations"]}

    def _txn_id(self, data: dict[str, Any]) -> int:
        raw = data.get("transaction-id")
        results = data.get("results")
        if raw in (None, "") and isinstance(results, dict):
            raw = results.get("transaction-id")
        try:
            txn = int(raw)
        except (TypeError, ValueError) as exc:
            raise self.error("FortiGate did not return a transaction id") from exc
        if txn < 1:
            raise self.error("FortiGate returned an invalid transaction id")
        return txn

    async def _abort(self, client, txn: str) -> bool:
        # UNVERIFIED: REST action name transaction-abort (the CLI is `execute config-transaction abort`).
        try:
            await self._call(client, "POST", "/cmdb", what="aborting a workspace transaction",
                             params={"action": "transaction-abort"}, body={"transaction-id": int(txn)}, txn=txn)
            return True
        except ConnectorError:
            return False

    async def _allow(self, client, txn: str, index: int, op: dict[str, Any]) -> dict[str, Any]:
        src = _safe_name(op["source"]["zone"], "interface or zone")
        dst = _safe_name(op["destination"]["zone"], "interface or zone")
        src_addrs = [await self._address(client, txn, cidr, op["marker"]) for cidr in op["source"]["cidrs"]]
        dst_addrs = [await self._address(client, txn, cidr, op["marker"]) for cidr in op["destination"]["cidrs"]]
        service_names = [await self._service(client, txn, spec, op["marker"]) for spec in op["services"]]
        name = _object_name("p", f"{op['marker']}:{index}")[:35]
        comment = f"{marker(op['marker'].split(':', 1)[1])} {op.get('description') or ''}".strip()
        body = {"policyid": 0, "name": name, "srcintf": [{"name": src}], "dstintf": [{"name": dst}],
                "srcaddr": [{"name": addr} for addr in src_addrs], "dstaddr": [{"name": addr} for addr in dst_addrs],
                "service": [{"name": svc} for svc in service_names], "schedule": "always", "action": "accept",
                "status": "enable", "logtraffic": "all" if op.get("log", True) else "disable",
                "nat": "disable", "comments": comment}
        # UNVERIFIED: POST /cmdb/firewall/policy and the mkey it returns. policyid 0 means "next free id".
        await self._call(client, "POST", "/cmdb/firewall/policy", what="creating a firewall policy", body=body, txn=txn)
        policy = await self._policy_by_name(client, txn, name)
        await self._move_before_first(client, txn, policy)
        return {"op": index, "id": policy, "vendor_ref": policy}

    async def _policy_by_name(self, client, txn: str, name: str) -> str:
        rows, _rev = await self._table(client, "/cmdb/firewall/policy", "reading the new firewall policy", txn=txn)
        for row in rows:
            if str(row.get("name") or "") == name and row.get("policyid") not in (None, ""):
                return _policy_id(row["policyid"])
        raise self.error("FortiGate did not return the new policy id")

    async def _move_before_first(self, client, txn: str, policy: str) -> None:
        rows, _rev = await self._table(client, "/cmdb/firewall/policy", "reading firewall policy order", txn=txn)
        for row in rows:
            other = row.get("policyid")
            if other in (None, "") or str(other) == policy:
                continue
            other_id = _policy_id(other)
            await self._call(client, "PUT", f"/cmdb/firewall/policy/{policy}", what="moving a firewall policy",
                             params={"action": "move", "before": other_id}, txn=txn)
            return

    async def _address(self, client, txn: str, cidr: str, mark: str) -> str:
        name = _object_name("n", cidr)
        existing = await self._optional_one(client, f"/cmdb/firewall/address/{name}", "reading an address", txn=txn)
        if existing is not None:
            return name
        # UNVERIFIED: firewall/address create body (type ipmask, subnet CIDR, singular comment).
        await self._call(client, "POST", "/cmdb/firewall/address", what="creating an address", txn=txn,
                         body={"name": name, "type": "ipmask", "subnet": cidr, "comment": mark})
        return name

    async def _service(self, client, txn: str, spec: dict[str, Any], mark: str) -> str:
        proto, ports = spec["proto"], spec.get("ports") or ""
        name = _object_name("s", f"{proto}/{ports}")
        existing = await self._optional_one(client, f"/cmdb/firewall.service/custom/{name}", "reading a service", txn=txn)
        if existing is not None:
            return name
        body: dict[str, Any] = {"name": name, "comment": mark}
        # UNVERIFIED: firewall.service/custom create body.
        if proto == "icmp":
            body["protocol"] = "ICMP"
        elif proto == "tcp":
            body["protocol"] = "TCP/UDP/SCTP"
            body["tcp-portrange"] = str(ports).replace(",", " ")
        elif proto == "udp":
            body["protocol"] = "TCP/UDP/SCTP"
            body["udp-portrange"] = str(ports).replace(",", " ")
        else:
            raise self._change(f"cannot express protocol {proto} on FortiGate", code="invalid", state="unchanged")
        await self._call(client, "POST", "/cmdb/firewall.service/custom", what="creating a service", body=body, txn=txn)
        return name

    async def _optional_one(self, client, path: str, what: str, *, txn: str | None = None) -> dict[str, Any] | None:
        try:
            data = await self._call(client, "GET", path, what=what, txn=txn)
        except ConnectorError as exc:
            if exc.status == 404:
                return None
            raise
        results = data.get("results")
        if isinstance(results, list):
            return results[0] if results else None
        if isinstance(results, dict):
            return results
        return None

    async def confirm_change(self, token: str) -> dict[str, Any]:
        self._parse_token(token)
        try:
            async with self.client() as client:
                rows = await self._optional_table(client, "/cmdb/system/global", "reading system global")
                cfg_save = str((rows[0] if rows else {}).get("cfg-save") or "automatic")
                notes = []
                if cfg_save in ("manual", "revert"):
                    # Do not toggle cfg-save. Persist only at confirm, and only when the device is not already automatic.
                    await self._call(client, "POST", "/monitor/system/config/save", what="saving the configuration",
                                     body={})
                    notes.append(f"cfg-save is {untrusted_text(cfg_save, 40)}; configuration save was called")
                else:
                    notes.append("cfg-save is automatic; the committed policy is already saved")
                _policies, revision = await self._table(client, "/cmdb/firewall/policy", "reading firewall policy")
        except ConnectorError as exc:
            raise self._from_connector(exc, code="unreachable" if exc.status in (None, 401) else "failed",
                                       state="unknown") from exc
        return {"confirmed": True, "revision": revision or None, "notes": notes}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        data = self._parse_token(token)
        try:
            async with self.client() as client:
                await self._inverse(client, data)
                return {"rolled_back": True, "method": "inverse_ops",
                        "notes": ["created policies were disabled; disabled policies were enabled again"]}
        except ChangeError as exc:
            if exc.state == "unchanged":
                raise
            restored = await self._restore_last_resort(data, backup)
            if restored:
                return restored
            raise ChangeError(exc.message, code=exc.code, state="unknown", status=exc.status, excerpt=exc.excerpt) from exc

    async def _inverse(self, client, data: dict[str, Any]) -> None:
        try:
            opened = await self._call(client, "POST", "/cmdb", what="starting a rollback transaction",
                                      params={"action": "transaction-start"}, body={"timeout": 60})
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed", state="applied") from exc
        txn = str(self._txn_id(opened))
        try:
            for item in data.get("created") or []:
                if isinstance(item, dict):
                    policy = _policy_id(item.get("vendor_ref") or item.get("id"))
                    await self._call(client, "PUT", f"/cmdb/firewall/policy/{policy}", what="disabling a created policy",
                                     txn=txn, body={"status": "disable"})
            for policy in data.get("disabled") or []:
                await self._call(client, "PUT", f"/cmdb/firewall/policy/{_policy_id(policy)}",
                                 what="re-enabling a policy", txn=txn, body={"status": "enable"})
            await self._call(client, "POST", "/cmdb", what="committing a rollback transaction",
                             params={"action": "transaction-commit"}, body={"transaction-id": int(txn)}, txn=txn)
        except ConnectorError as exc:
            # Abort discards the inverse batch only. The original change is still on the device.
            aborted = await self._abort(client, txn)
            raise self._from_connector(exc, code="failed", state="applied" if aborted else "unknown") from exc

    async def _restore_last_resort(self, data: dict[str, Any], backup: Backup | None) -> dict[str, Any] | None:
        snapshot = str(data.get("snapshot") or "")
        try:
            async with self.client() as client:
                if snapshot.isdigit():
                    # UNVERIFIED: source=revision. A restore reboots the unit.
                    await self._call(client, "POST", "/monitor/system/config/restore",
                                     what="restoring a config revision",
                                     body={"source": "revision", "scope": "global", "config_id": int(snapshot)})
                    return {"rolled_back": True, "method": "backup_restore",
                            "notes": ["inverse operations failed; restored the config revision saved before the change "
                                      "(the unit reboots)"]}
                if backup is not None and not backup.content[:1] in (b"{", b"["):
                    text = backup.content.decode("utf-8")
                    await self._call(client, "POST", "/monitor/system/config/restore",
                                     what="restoring a configuration backup",
                                     body={"source": "upload", "scope": "global", "file_content": text})
                    return {"rolled_back": True, "method": "backup_restore",
                            "notes": ["inverse operations failed; restored the configuration backup (the unit reboots)"]}
        except (ConnectorError, UnicodeError):
            return None
        return None

    def _parse_token(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise self._change("The change token is not one this connector issued", code="invalid", state="unchanged")
        try:
            data = json.loads(token)
        except ValueError as exc:
            raise self._change("The change token is not one this connector issued", code="invalid",
                               state="unchanged") from exc
        if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("created"), list):
            raise self._change("The change token is not one this connector issued", code="invalid", state="unchanged")
        if str(data.get("vdom") or "") != str(self.config.get("vdom") or "root"):
            raise self._change("The change token is for a different VDOM", code="invalid", state="unchanged")
        return data
