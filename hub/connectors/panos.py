"""Palo Alto PAN-OS connector: XML API reads, candidate edits, partial commit.

Follows ``docs/research/fw-fortigate-panos-cisco.md`` section 3. Verified there: API key in ``X-PAN-KEY``,
``type=config`` show/set/move, partial commit for one admin, ``save config to`` / ``load config from``, and
security-rule element names. PAN-OS has no commit-confirm. Rollback disables what an allow created and, if that
commit fails, loads ``atrium-pre-<id>.xml`` and commits. That load is the last resort: it replaces the candidate.

The key is never put in the query string. XML ``status="error"`` is a failure even when HTTP is 200.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
import xml.etree.ElementTree as ET
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

WINDOW_S = 120
SAFE = re.compile(r"^[A-Za-z0-9_.:/-]{1,63}$")
USER = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
DEVICE = "/config/devices/entry[@name='localhost.localdomain']"
# UNVERIFIED: FIN / OK / FAIL are the job values operators see; the guide example only shows ACT / PEND.
JOB_OK = {"OK"}
JOB_FAIL = {"FAIL"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ET.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    return element.text.strip()


def _members(entry: ET.Element, tag: str) -> list[str]:
    return [(_text(member)) for member in entry.findall(tag + "/member") if _text(member)]


def _leaf(root: ET.Element, names: set[str]) -> str:
    for element in root.iter():
        if _local(element.tag) in names and element.text and element.text.strip():
            return element.text.strip()
    return ""


def _object_name(kind: str, key: str) -> str:
    return f"atr-{kind}-{hashlib.sha256(key.encode()).hexdigest()[:12]}"


def _xml_children(parent: ET.Element) -> str:
    return "".join(ET.tostring(child, encoding="unicode") for child in list(parent))


def _members_el(parent: ET.Element, tag: str, values: list[str]) -> None:
    node = ET.SubElement(parent, tag)
    for value in values:
        ET.SubElement(node, "member").text = value


class PanOsConnector(Connector):
    kind = "panos"
    title = "PAN-OS"
    description = ("Palo Alto XML API: reads security policy, zones, interfaces and address objects. "
                   "Rule changes are written to the candidate, committed for this admin only, and rolled back "
                   "by inverse operations or by loading the atrium-pre snapshot. There is no commit-confirm timer.")
    fields = [
        ConnectorField(name="base_url", label="Firewall URL", kind="url", required=True,
                       placeholder="https://firewall.example",
                       help="HTTPS address of the firewall. The API key is sent only here, in the X-PAN-KEY header."),
        ConnectorField(name="api_key", label="API key", kind="secret", required=True,
                       help="Generate the key once for a dedicated admin (type=keygen) and store it here. "
                            "Do not generate it again: that ends the admin's sessions. A read-only role "
                            "(Device admin or Superuser, readonly) is enough until device changes are enabled."),
        ConnectorField(name="api_user", label="API admin user",
                       help="The admin the key belongs to. Partial commits include only this admin's changes. "
                            "Required when the key can change policy."),
        ConnectorField(name="vsys", label="Virtual system", default="vsys1"),
        ConnectorField(name="can_write", label="Key can change security policy", kind="bool", default=False,
                       help="Turn on only for a role that may edit policy, commit and save a named config. "
                            "Leave off for a read-only role."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True,
                       help="PAN-OS presents a self-signed certificate unless you installed a CA-issued one. "
                            "Pin it with the CA file field."),
        ConnectorField(name="ca_file", label="CA certificate file", placeholder="/etc/atrium/panos-ca.pem"),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "backup_restore",
                     "window_s": WINDOW_S}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("pan-os", "panos", "palo alto", "paloalto"))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        local = parts.scheme == "http" and parts.hostname in ("localhost", "127.0.0.1")
        if not (parts.scheme == "https" or local) or not parts.hostname:
            raise ConnectorError("The firewall URL must start with https:// (the API key must not travel in clear text)")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API key in its own field, not in the URL")
        vsys = str(config.get("vsys") or "vsys1").strip()
        user = str(config.get("api_user") or "").strip()
        if not USER.fullmatch(vsys):
            raise ConnectorError("The virtual system name is 1-63 letters, digits, '.', '_' and '-'")
        if user and not USER.fullmatch(user):
            raise ConnectorError("The API admin user is 1-63 letters, digits, '.', '_' and '-'")
        if config.get("can_write") and not user:
            raise ConnectorError("Name the API admin user when this key can change policy (partial commits need it)")
        ca = str(config.get("ca_file") or "").strip()
        if ca and not ca.startswith("/"):
            raise ConnectorError("The CA certificate file must be an absolute path")
        return {**config, "base_url": base, "vsys": vsys, "api_user": user, "ca_file": ca}

    def write_capability(self) -> dict[str, Any] | None:
        if not self.config.get("can_write") or not str(self.config.get("api_user") or "").strip():
            return None
        return super().write_capability()

    def _verify(self) -> bool | str:
        ca = str(self.config.get("ca_file") or "").strip()
        return ca or bool(self.config.get("verify_tls", True))

    def client(self):
        key = self.secrets.get("api_key")
        if not key:
            raise self.error("Enter the PAN-OS API key in the connection settings")
        return self.http(str(self.config.get("base_url") or "").rstrip("/"),
                         headers={"X-PAN-KEY": key}, verify=self._verify())

    def _base(self) -> str:
        return f"{DEVICE}/vsys/entry[@name='{self.config.get('vsys') or 'vsys1'}']"

    def _change(self, message: str, *, code: str = "failed", state: str = "unknown",
                status: int | None = None, excerpt: str | None = None) -> ChangeError:
        err = self.error(message, status=status, excerpt=excerpt)
        return ChangeError(err.message, code=code, state=state, status=err.status, excerpt=err.excerpt)

    def _from_connector(self, exc: ConnectorError, *, code: str, state: str) -> ChangeError:
        if isinstance(exc, ChangeError):
            return exc
        return ChangeError(exc.message, code=code, state=state, status=exc.status, excerpt=exc.excerpt)

    async def _post(self, client, form: dict[str, str], what: str) -> ET.Element:
        try:
            response = await client.post("/api/", data=form)
        except Exception as exc:
            from httpx import HTTPError, TimeoutException

            if isinstance(exc, TimeoutException):
                raise self.error(f"{self.title} did not answer in time ({what})") from exc
            if isinstance(exc, HTTPError):
                raise self.error(f"Cannot reach {self.title}: {exc.__class__.__name__}") from exc
            raise
        self.raise_for_status(response, what)
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            raise self.error(f"{self.title} did not answer with XML ({what})", status=response.status_code,
                             excerpt=response.text) from exc
        self._xml_status(root, what)
        return root

    def _xml_status(self, root: ET.Element, what: str) -> None:
        """XML ``status="error"`` is a failure even when the HTTP status is 200."""
        if _local(root.tag) != "response":
            return
        status = (root.get("status") or "").lower()
        if status == "success":
            return
        code = str(root.get("code") or "")
        detail = untrusted_text(" ".join(root.itertext()), 300)
        http = 403 if code == "403" else (401 if code in ("401", "22") else None)
        raise self.error(f"{self.title} rejected {what} (code {code or 'error'}): {detail}", status=http, excerpt=detail)

    async def _show(self, client, xpath: str, what: str) -> ET.Element:
        return await self._post(client, {"type": "config", "action": "show", "xpath": xpath}, what)

    async def _op(self, client, cmd: str, what: str) -> ET.Element:
        return await self._post(client, {"type": "op", "cmd": cmd}, what)

    async def _set(self, client, xpath: str, element: str, what: str) -> None:
        await self._post(client, {"type": "config", "action": "set", "xpath": xpath, "element": element}, what)

    # -- reading -----------------------------------------------------------------------

    def _interfaces(self, root: ET.Element, zone_of: dict[str, str]) -> list[dict[str, Any]]:
        # Layer3 ip entries and subinterface tag are the documented shape; walking every entry is UNVERIFIED
        # for aggregate/loopback variants.
        found: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in root.findall(".//entry"):
            name = entry.get("name") or ""
            if not name or name in seen:
                continue
            ips = [ip.get("name") or "" for ip in entry.findall("./layer3/ip/entry")]
            ips += [ip.get("name") or "" for ip in entry.findall("./ip/entry")]
            if not ips and entry.find("tag") is None and entry.find("layer3") is None:
                continue
            if entry.find("layer3") is None and entry.find("ip") is None and entry.find("tag") is None:
                continue
            seen.add(name)
            subnets, addresses = [], []
            for raw in ips:
                try:
                    network = ipaddress.ip_network(raw, strict=False)
                except ValueError:
                    continue
                if network.prefixlen == 0:
                    continue
                subnets.append(str(network))
                host = raw.split("/")[0]
                try:
                    addresses.append(str(ipaddress.ip_address(host)))
                except ValueError:
                    pass
            zone = zone_of.get(name, "")
            if "mgmt" in name.lower() or zone.lower() in ("mgmt", "management"):
                role = "mgmt"
            elif zone.lower() in ("untrust", "wan", "outside", "internet"):
                role = "wan"
            elif addresses:
                role = "lan"
            else:
                role = "other"
            item: dict[str, Any] = {"id": name, "name": name, "role": role, "subnets": subnets,
                                    "addresses": addresses, "enabled": True}
            tag = _text(entry.find("tag"))
            if tag.isdigit() and tag != "0":
                item["vlan"] = int(tag)
            found.append(item)
        return found

    def _zones(self, root: ET.Element) -> list[dict[str, Any]]:
        zones = []
        for entry in root.findall(".//entry"):
            name = entry.get("name") or ""
            members = [m.text.strip() for m in entry.findall(".//member") if m.text and m.text.strip()]
            if not name or not members:
                continue
            # Address and rule entries also have members; zones carry them under network/.
            if entry.find("network") is None and entry.find("from") is not None:
                continue
            if entry.find("network") is None and entry.find("ip-netmask") is not None:
                continue
            if entry.find("network") is None:
                continue
            zones.append({"id": name, "name": name, "interfaces": members})
        return zones

    def _addresses(self, root: ET.Element) -> tuple[dict[str, str], list[dict[str, Any]]]:
        cidrs, aliases = {}, []
        for entry in root.findall(".//entry"):
            name = entry.get("name") or ""
            if not name or name.lower() == "any":
                continue
            raw = _text(entry.find("ip-netmask"))
            network = None
            if raw:
                try:
                    parsed = ipaddress.ip_network(raw, strict=False)
                    network = None if parsed.prefixlen == 0 else str(parsed)
                except ValueError:
                    network = None
            if network:
                cidrs[name] = network
                aliases.append({"name": name, "kind": "network", "cidrs": [network], "resolved": True})
            elif _text(entry.find("fqdn")):
                aliases.append({"name": name, "kind": "other", "resolved": False})
        return cidrs, aliases

    def _services(self, root: ET.Element) -> dict[str, list[dict[str, Any]]]:
        # UNVERIFIED: service/protocol/tcp/port XML. The REST service schema was not in the fetched pages.
        found: dict[str, list[dict[str, Any]]] = {}
        for entry in root.findall(".//entry"):
            name = entry.get("name") or ""
            protocol = entry.find("protocol")
            if not name or protocol is None:
                continue
            specs = []
            for proto in ("tcp", "udp"):
                port = _text(protocol.find(f"{proto}/port"))
                if not port:
                    continue
                try:
                    from .netmodel import parse_ports

                    parsed = parse_ports(port.replace(" ", ","))
                except ValueError:
                    continue
                if parsed:
                    specs.append({"proto": proto, "ports": parsed})
            if protocol.find("icmp") is not None and not specs:
                specs.append({"proto": "icmp"})
            if specs:
                found[name] = specs
        return found

    def _endpoint(self, members: list[str], cidrs: dict[str, str]) -> dict[str, Any]:
        if any(member.lower() == "any" for member in members):
            return {"any": True}
        out_cidrs, aliases = [], []
        for member in members:
            if member in cidrs:
                out_cidrs.append(cidrs[member])
            else:
                aliases.append(member)
        endpoint: dict[str, Any] = {}
        if out_cidrs:
            endpoint["cidrs"] = out_cidrs
        if aliases:
            endpoint["aliases"] = aliases
        return endpoint or {"any": True}

    def _rule_services(self, members: list[str], services: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]] | None:
        if not members or any(member.lower() == "any" for member in members):
            return None
        out: list[dict[str, Any]] = []
        for member in members:
            if member == "application-default":
                out.append({"proto": "tcp", "alias": member, "name": member})
                continue
            specs = services.get(member)
            if specs is None:
                out.append({"proto": "tcp", "alias": member, "name": member})
            else:
                out.extend(specs)
        return out or None

    def _rules(self, root: ET.Element, cidrs: dict[str, str], services: dict[str, list[dict[str, Any]]],
               hits: dict[str, Any]) -> list[dict[str, Any]]:
        rules = []
        entries = [entry for entry in root.findall(".//entry") if entry.find("from") is not None and entry.find("action") is not None]
        for order, entry in enumerate(entries, start=1):
            name = entry.get("name") or ""
            if not name:
                continue
            disabled = _text(entry.find("disabled")).lower()
            action = _text(entry.find("action")).lower() or "allow"
            rule: dict[str, Any] = {
                "id": name, "vendor_ref": name, "order": order,
                "enabled": disabled not in ("yes", "true"),
                "action": {"allow": "allow", "deny": "deny", "drop": "drop", "reset-client": "reject",
                           "reset-server": "reject", "reset-both": "reject"}.get(action, action),
                "direction": "in",
                "source_zones": _members(entry, "from"), "destination_zones": _members(entry, "to"),
                "source": self._endpoint(_members(entry, "source"), cidrs),
                "destination": self._endpoint(_members(entry, "destination"), cidrs),
                "services": self._rule_services(_members(entry, "service"), services),
                "log": _text(entry.find("log-end")).lower() == "yes" or _text(entry.find("log-start")).lower() == "yes",
                "description": _text(entry.find("description")),
            }
            if name in hits:
                rule["hits"] = hits[name]
            rules.append(rule)
        return rules

    def _hits(self, root: ET.Element) -> dict[str, Any]:
        hits = {}
        for entry in root.findall(".//entry"):
            count = entry.find("hit-count")
            name = entry.get("name")
            if name and count is not None and count.text:
                hits[name] = count.text.strip()
        return hits

    def _fingerprint(self, rules: list[dict[str, Any]]) -> str:
        body = [{k: rule.get(k) for k in ("id", "enabled", "action", "source_zones", "destination_zones",
                                           "source", "destination", "services", "description")} for rule in rules]
        return derived_revision(body)

    async def _panorama(self, client) -> bool:
        # UNVERIFIED: deviceconfig/system/panorama-server is not in the fetched API pages.
        xpath = f"{DEVICE}/deviceconfig/system/panorama-server"
        try:
            root = await self._show(client, xpath, "reading Panorama management")
        except ConnectorError:
            return False
        text = " ".join(part.strip() for part in root.itertext() if part and part.strip())
        return bool(text) and text.lower() not in ("none", "0.0.0.0")

    async def _read(self, client) -> dict[str, Any]:
        version_xml = await self._post(client, {"type": "version"}, "reading the PAN-OS version")
        # UNVERIFIED: sw-version / model / serial / hostname element names are not in the fetched type=version page.
        version = _leaf(version_xml, {"sw-version", "sw_version"})
        model = _leaf(version_xml, {"model"})
        serial = _leaf(version_xml, {"serial"})
        hostname = _leaf(version_xml, {"hostname", "devicename"})
        notes = ["PAN-OS has no commit-confirm; interzone default is deny and intrazone default is allow"]
        if any(rule_note == "application-default" for rule_note in ()):
            notes.append("application-default services are not expanded to ports")
        zones = self._zones(await self._show(client, self._base() + "/zone", "reading zones"))
        zone_of = {iface: zone["id"] for zone in zones for iface in zone.get("interfaces") or []}
        interfaces = self._interfaces(await self._show(client, f"{DEVICE}/network/interface", "reading interfaces"), zone_of)
        cidrs, aliases = self._addresses(await self._show(client, self._base() + "/address", "reading addresses"))
        services = self._services(await self._show(client, self._base() + "/service", "reading services"))
        rules_xml = await self._show(client, self._base() + "/rulebase/security/rules", "reading security rules")
        hits: dict[str, Any] = {}
        try:
            # Rule names are not interpolated: the command asks for every security rule in this vsys.
            vsys = self.config.get("vsys") or "vsys1"
            cmd = ("<show><rule-hit-count><vsys><vsys-name><entry name='" + vsys + "'><rule-base>"
                   "<entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys>"
                   "</rule-hit-count></show>")
            hits = self._hits(await self._op(client, cmd, "reading rule hit counts"))
        except ConnectorError:
            notes.append("hit counts are not available with this key or PAN-OS version")
        rules = self._rules(rules_xml, cidrs, services, hits)
        if any((rule.get("services") or []) and any(s.get("alias") == "application-default" for s in rule["services"])
               for rule in rules):
            notes.append("application-default services are not expanded to ports")
        if await self._panorama(client):
            notes.append("this firewall reports a Panorama server; local policy writes are refused")
        if not hostname:
            host = urlsplit(str(self.config.get("base_url") or "")).hostname or ""
            hostname = host
        external = serial or hostname or "panos"
        self_addresses = [addr for iface in interfaces for addr in iface.get("addresses") or []]
        revision = self._fingerprint(rules)
        return {"external_id": external, "revision": revision, "read_at": time.time(), "kind": "firewall",
                "device": {"vendor": "Palo Alto Networks", "model": model, "version": version, "hostname": hostname,
                           "management_address": urlsplit(str(self.config.get("base_url") or "")).hostname or "",
                           "serial": serial},
                "interfaces": interfaces, "zones": zones, "aliases": aliases, "self_addresses": self_addresses,
                "rules": rules, "default_policy": {"forward": "block"}, "nat_evaluated": False, "notes": notes,
                "_version": version}

    def _public(self, record: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in record.items() if not str(k).startswith("_")}

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
        checks.append(check("authentication", True, "API key accepted"))
        writable = self.write_capability() is not None and bool(record.get("_version"))
        managed = any("Panorama" in note for note in record.get("notes") or [])
        if managed:
            writable = False
        if self.config.get("can_write"):
            privilege = LEAST_PRIVILEGE_NOTE
        else:
            privilege = "read-only credential: device changes are unavailable"
        checks.append(check("privileges", True, privilege))
        shown = record.get("_version") or "unknown"
        if record.get("_version"):
            checks.append(check("version", True, f"PAN-OS {shown} (read supported; no native commit-confirm)"))
        else:
            checks.append(check("version", True, "PAN-OS version was not in the reply; writes stay off"))
            writable = False
        features = "security rules, zones, interfaces, addresses"
        if writable:
            features += f"; candidate config, partial commit for {self.config.get('api_user')}, rollback inverse ops then snapshot load, window {WINDOW_S}s"
        elif managed:
            features += "; local writes refused because Panorama manages this firewall"
        else:
            features += "; writes off"
        checks.append(check("api_features", True, features))
        ok = all(item["ok"] for item in checks)
        return {"ok": ok, "detail": f"Connected to PAN-OS {record.get('external_id')}.", "checks": checks,
                "domains": self.domains() if ok else {}, "network_write": self.write_capability() if writable and ok else None}

    def _test_failed(self, exc: ConnectorError, checks: list[dict[str, Any]], tls_on: bool) -> dict[str, Any]:
        text = exc.message
        if "Cannot reach" in text or "did not answer in time" in text:
            checks.append(check("reachability", False, text))
        else:
            checks.append(check("reachability", True, f"{self.config.get('base_url')} answers"))
            checks.append(check("tls", tls_on, "certificate verification is on" if tls_on else
                                "TLS certificate verification is turned off in the connection"))
            if exc.status in (401, 403) or "code 403" in text:
                checks.append(check("authentication", False, "the API key was refused"))
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
                record = await self._read(client)
                name = "atrium-hub-" + record["revision"] + ".xml"
                if not SAFE.fullmatch(name.replace(".xml", "")) and not re.fullmatch(r"atrium-hub-[A-Za-z0-9_-]+\.xml", name):
                    name = "atrium-hub-backup.xml"
                await self._op(client, f"<save><config><to>{name}</to></config></save>", "saving a named configuration")
                response = await client.post("/api/", data={"type": "export", "category": "configuration"})
                self.raise_for_status(response, "exporting the configuration")
                content = self._export_bytes(response.content)
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed", state="unchanged") from exc
        return {"content": content, "format": "xml", "device_backup_id": name, "revision": record["revision"],
                "sha256": hashlib.sha256(content).hexdigest()}

    def _export_bytes(self, raw: bytes) -> bytes:
        if not raw:
            raise self._change("PAN-OS returned an empty configuration export", code="failed", state="unchanged")
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise self._change("PAN-OS did not return an XML configuration", code="failed", state="unchanged") from exc
        if _local(root.tag) == "response":
            self._xml_status(root, "exporting the configuration")
        return raw

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        name = str(backup.device_backup_id or "")
        if not re.fullmatch(r"atrium-[A-Za-z0-9_.-]{1,80}", name):
            raise self._change("This backup has no PAN-OS snapshot name to load. Refusing to push the file "
                               "(the import form is not used).", code="unsupported", state="unchanged")
        try:
            async with self.client() as client:
                await self._op(client, f"<load><config><from>{name}</from></config></load>", "loading a saved configuration")
                await self._commit(client, full=True)
                record = await self._read(client)
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed", state="unknown") from exc
        return {"restored": True, "revision": record.get("revision"), "notes": [f"loaded {name} and committed"]}

    # -- changes -----------------------------------------------------------------------

    def _names(self, value: Any, what: str) -> str:
        text = str(value or "").strip()
        if not SAFE.fullmatch(text):
            raise self._change(f"{what} {untrusted_text(value, 40)!r} cannot be sent to the device",
                               code="invalid", state="unchanged")
        return text

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
        zones = {z["id"] for z in record.get("zones") or []} | {i["id"] for i in record.get("interfaces") or []}
        steps = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    if op[side]["zone"] not in zones:
                        problems.append(f"the device has no zone {untrusted_text(op[side]['zone'], 40)!r}")
                steps.append({"op": index, "kind": "add_rule", "position": "before the first security rule",
                              "detail": "one allow rule in the candidate, marked " + op["marker"]})
            else:
                kind = "disable_rule" if op["op"] == "disable_rules" else "enable_rule"
                steps.extend({"op": index, "kind": kind, "position": "in place",
                              "detail": f"{op['op']} {ref['vendor_ref']}"} for ref in op["rules"])
        notes = ["candidate config and a partial commit; rollback is inverse operations, then load atrium-pre-<id>.xml"]
        if any("Panorama" in note for note in record.get("notes") or []):
            problems.append("this firewall is Panorama-managed; local policy writes are refused")
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
                if await self._panorama(client):
                    raise self._change("This firewall is Panorama-managed. Refusing a local policy write.",
                                       code="invalid", state="unchanged")
                if record["revision"] != str(base_revision):
                    raise self._change(f"The device revision changed ({record['revision']}): re-read it and preview again",
                                       code="stale", state="unchanged")
                public = self._public(record)
                try:
                    normalised = normalize_record(public)
                except ValueError as exc:
                    raise self._change(str(exc), code="invalid", state="unchanged") from exc
                problems = management_guard(normalised, ops)
                zones = {z["id"] for z in public.get("zones") or []} | {i["id"] for i in public.get("interfaces") or []}
                extra = []
                for op in ops:
                    if op["op"] != "allow":
                        continue
                    for side in ("source", "destination"):
                        zone = op[side]["zone"]
                        if zone not in zones:
                            extra.append(f"the device has no zone {untrusted_text(zone, 40)!r}")
                        else:
                            self._names(zone, "zone")
                if problems or extra:
                    raise self._change("Refused: " + "; ".join(problems + extra),
                                       code="lockout" if problems else "invalid", state="unchanged")
                if await self._locked_by_other(client):
                    raise self._change("Another admin holds a config lock. Nothing was changed.",
                                       code="failed", state="unchanged")
                change_id = next((op["marker"].split(":", 1)[1] for op in ops if op["op"] == "allow"), "rules")
                snap = self._snapshot_name(change_id)
                # Arm the snapshot before any candidate edit.
                await self._op(client, f"<save><config><to>{snap}</to></config></save>", "saving the pre-change snapshot")
                await self._discard_own_pending(client)
                created, disabled, enabled = await self._stage(client, ops, public)
                committed = False
                try:
                    await self._commit(client, full=False)
                    committed = True
                    fresh = await self._read(client)
                except ConnectorError as exc:
                    if not committed:
                        await self._revert_own(client)
                    raise self._from_connector(exc, code="failed", state="applied" if committed else "unchanged") from exc
        except ConnectorError as exc:
            raise self._from_connector(exc, code="failed" if exc.status not in (None, 401, 403) else "unreachable",
                                       state=exc.state if isinstance(exc, ChangeError) else "unchanged") from exc
        token = json.dumps({"v": 1, "vsys": self.config.get("vsys") or "vsys1",
                                          "admin": self.config.get("api_user"), "snapshot": snap,
                                          "created": created, "disabled": disabled, "enabled": enabled},
                                         separators=(",", ":"))
        if len(token) > 4096:
            raise self._change("The change was committed but its token does not fit the hub limit; load "
                               f"{snap} to roll it back", code="failed", state="applied")
        return {"token": token, "rollback_until": None, "revision": fresh.get("revision"), "created": created,
                "disabled": disabled, "notes": [f"partial commit done; snapshot {snap}"]}

    def _snapshot_name(self, change_id: str) -> str:
        safe = re.sub(r"[^A-Za-z0-9_-]", "", change_id)[:40] or "rules"
        return f"atrium-pre-{safe}.xml"

    async def _locked_by_other(self, client) -> bool:
        try:
            root = await self._op(client, "<show><config-locks/></show>", "reading config locks")
        except ConnectorError:
            return False
        if root.find(".//entry") is not None:
            return True
        text = " ".join(part.strip() for part in root.itertext() if part and part.strip())
        return bool(text)

    async def _discard_own_pending(self, client) -> None:
        # Drop this admin's uncommitted candidate edits so the partial commit cannot include leftovers.
        user = self.config.get("api_user") or ""
        try:
            root = await self._op(client, "<check><pending-changes/></check>", "reading pending changes")
        except ConnectorError:
            return
        admins = [_text(member) for member in root.findall(".//member")]
        if user in admins:
            await self._revert_own(client)

    async def _revert_own(self, client) -> None:
        user = self.config.get("api_user") or ""
        cmd = f"<revert><config><partial><admin><member>{user}</member></admin></partial></config></revert>"
        try:
            await self._op(client, cmd, "reverting this admin's candidate")
        except ConnectorError:
            return

    async def _stage(self, client, ops: list[dict[str, Any]], record: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        created, disabled, enabled = [], [], []
        anchor = next((rule["vendor_ref"] for rule in record.get("rules") or [] if SAFE.fullmatch(rule["vendor_ref"])), "")
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                created.append(await self._allow(client, index, op, anchor))
            else:
                turn_on = op["op"] == "enable_rules"
                for ref in op["rules"]:
                    name = self._names(ref.get("vendor_ref") or ref.get("id"), "rule")
                    await self._set(client, f"{self._base()}/rulebase/security/rules/entry[@name='{name}']",
                                    f"<disabled>{'no' if turn_on else 'yes'}</disabled>", "updating a security rule")
                    (enabled if turn_on else disabled).append(name)
        return created, disabled, enabled

    async def _allow(self, client, index: int, op: dict[str, Any], anchor: str) -> dict[str, Any]:
        src_zone = self._names(op["source"]["zone"], "zone")
        dst_zone = self._names(op["destination"]["zone"], "zone")
        src = [await self._address(client, cidr) for cidr in op["source"]["cidrs"]]
        dst = [await self._address(client, cidr) for cidr in op["destination"]["cidrs"]]
        services = [await self._service(client, spec) for spec in op["services"]]
        name = _object_name("r", f"{op['marker']}:{index}")
        parent = ET.Element("rule")
        _members_el(parent, "from", [src_zone])
        _members_el(parent, "to", [dst_zone])
        _members_el(parent, "source", src)
        _members_el(parent, "destination", dst)
        _members_el(parent, "source-user", ["any"])
        _members_el(parent, "application", ["any"])
        _members_el(parent, "service", services)
        _members_el(parent, "category", ["any"])
        ET.SubElement(parent, "action").text = "allow"
        ET.SubElement(parent, "disabled").text = "no"
        ET.SubElement(parent, "log-end").text = "yes" if op.get("log", True) else "no"
        ET.SubElement(parent, "description").text = f"{marker(op['marker'].split(':', 1)[1])} {op.get('description') or ''}".strip()
        xpath = f"{self._base()}/rulebase/security/rules/entry[@name='{name}']"
        await self._set(client, xpath, _xml_children(parent), "creating a security rule")
        if anchor and anchor != name:
            try:
                await self._post(client, {"type": "config", "action": "move", "xpath": xpath, "where": "before",
                                           "dst": anchor}, "moving a security rule")
            except ConnectorError as exc:
                if "code 14" not in exc.message:
                    raise
        return {"op": index, "id": name, "vendor_ref": name}

    async def _address(self, client, cidr: str) -> str:
        name = _object_name("n", cidr)
        # ip-netmask matches the documented address field. Creating it with config set is the XML form of that object.
        await self._set(client, f"{self._base()}/address/entry[@name='{name}']", f"<ip-netmask>{cidr}</ip-netmask>",
                        "creating an address")
        return name

    async def _service(self, client, spec: dict[str, Any]) -> str:
        proto, ports = spec["proto"], spec.get("ports") or ""
        name = _object_name("s", f"{proto}/{ports}")
        if proto == "icmp":
            # UNVERIFIED: icmp service element.
            element = "<protocol><icmp/></protocol>"
        elif proto in ("tcp", "udp"):
            # UNVERIFIED: protocol/tcp/port (and udp) element names.
            element = f"<protocol><{proto}><port>{ports}</port></{proto}></protocol>"
        else:
            raise self._change(f"cannot express protocol {proto} on PAN-OS", code="invalid", state="unchanged")
        await self._set(client, f"{self._base()}/service/entry[@name='{name}']", element, "creating a service")
        return name

    async def _commit(self, client, *, full: bool) -> None:
        user = self.config.get("api_user") or ""
        if full:
            cmd = "<commit></commit>"
            what = "committing"
        else:
            cmd = f"<commit><partial><admin><member>{user}</member></admin></partial></commit>"
            what = "committing this admin's changes"
        root = await self._post(client, {"type": "commit", "cmd": cmd, **({"action": "partial"} if not full else {})}, what)
        job = _leaf(root, {"job"})
        if not job:
            blob = " ".join(root.itertext())
            if "no changes" in blob.lower():
                return
            found = re.search(r"jobid\s+(\d+)", blob, re.IGNORECASE)
            job = found.group(1) if found else ""
        if not job:
            raise self._change("PAN-OS did not return a commit job id", code="failed", state="unknown")
        if not job.isdigit():
            raise self._change("PAN-OS returned an unexpected commit job id", code="failed", state="unknown")
        for _ in range(8):
            polled = await self._op(client, f"<show><jobs><id>{job}</id></jobs></show>", "reading the commit job")
            node = next((el for el in polled.findall(".//job")), None)
            status = (_text(node.find("status")) if node is not None else "").upper()
            result = (_text(node.find("result")) if node is not None else "").upper()
            if result in JOB_FAIL or status in JOB_FAIL:
                raise self._change(f"PAN-OS commit job {job} failed", code="failed", state="unchanged")
            if result in JOB_OK or status == "FIN":
                return
        raise self._change(f"PAN-OS commit job {job} did not finish", code="failed", state="unknown")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        self._parse_token(token)
        try:
            async with self.client() as client:
                record = await self._read(client)
        except ConnectorError as exc:
            raise self._from_connector(exc, code="unreachable" if exc.status in (None, 401, 403) else "failed",
                                       state="unknown") from exc
        return {"confirmed": True, "revision": record.get("revision"),
                "notes": ["the partial commit already activated the change; there is no confirm timer to cancel"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        data = self._parse_token(token)
        try:
            async with self.client() as client:
                await self._inverse(client, data)
            return {"rolled_back": True, "method": "inverse_ops",
                    "notes": ["created rules were disabled and previously disabled rules enabled, then committed"]}
        except ChangeError as exc:
            if exc.code == "invalid":
                raise
            try:
                async with self.client() as client:
                    snap = str(data.get("snapshot") or "")
                    if not re.fullmatch(r"atrium-pre-[A-Za-z0-9_-]{1,40}\.xml", snap):
                        raise self._change("The snapshot name in the token is not usable", code="failed", state="applied")
                    await self._op(client, f"<load><config><from>{snap}</from></config></load>", "loading the pre-change snapshot")
                    await self._commit(client, full=True)
                return {"rolled_back": True, "method": "backup_restore",
                        "notes": [f"inverse commit failed; loaded {snap} and committed"]}
            except ConnectorError as second:
                raise self._from_connector(second, code="failed", state="applied" if exc.state != "unknown" else "unknown") from second

    async def _inverse(self, client, data: dict[str, Any]) -> None:
        base = f"{DEVICE}/vsys/entry[@name='{data.get('vsys') or 'vsys1'}']"
        try:
            for item in data.get("created") or []:
                if isinstance(item, dict):
                    name = self._names(item.get("vendor_ref") or item.get("id"), "rule")
                    await self._set(client, f"{base}/rulebase/security/rules/entry[@name='{name}']",
                                    "<disabled>yes</disabled>", "disabling a created rule")
            for name in data.get("disabled") or []:
                safe = self._names(name, "rule")
                await self._set(client, f"{base}/rulebase/security/rules/entry[@name='{safe}']",
                                "<disabled>no</disabled>", "re-enabling a rule")
            for name in data.get("enabled") or []:
                safe = self._names(name, "rule")
                await self._set(client, f"{base}/rulebase/security/rules/entry[@name='{safe}']",
                                "<disabled>yes</disabled>", "disabling a rule")
            await self._commit(client, full=False)
        except ConnectorError as exc:
            await self._revert_own(client)
            raise self._from_connector(exc, code="failed", state="unchanged" if not isinstance(exc, ChangeError) or exc.state == "unchanged" else exc.state) from exc

    def _parse_token(self, token: str) -> dict[str, Any]:
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise self._change("The change token is not one this connector issued", code="invalid", state="unchanged")
        try:
            data = json.loads(token)
        except ValueError as exc:
            raise self._change("The change token is not one this connector issued", code="invalid", state="unchanged") from exc
        if not isinstance(data, dict) or data.get("v") != 1 or not isinstance(data.get("created"), list):
            raise self._change("The change token is not one this connector issued", code="invalid", state="unchanged")
        if str(data.get("vsys") or "") != str(self.config.get("vsys") or "vsys1"):
            raise self._change("The change token is for a different virtual system", code="invalid", state="unchanged")
        return data
