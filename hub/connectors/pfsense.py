"""pfSense connector.

CE is read and written over SSH. The live file is ``/cf/conf/config.xml``. A change is a PHP script on stdin
that uses the official primitives ``config_get_path``, ``config_set_path``, ``write_config`` and
``filter_configure``. Before the script runs, a dead-man timer is armed (``daemon`` + a 120s sleep) so a lost
session restores the pre-change copy. Confirm removes the arm file.

Plus (Nexus / MIM) is read-only: the API base path, security scheme, login call and rule schema were not in
the parts of the OpenAPI file the research could read. The unofficial pfrest package is an optional read-only
mode and is never used for writes.

Device text is never placed on a shell command line. The PHP program is the command's stdin; every path this
connector builds is a fixed string or a change id restricted to letters, digits, '_' and '-'.

UNVERIFIED: ``/usr/local/bin/php`` as the interpreter path, ``daemon(8)`` on the appliance, presence-only
``disabled`` / ``log`` elements, NAT and interface-group tags, and the exact ``pfctl -vvsr`` text layout.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import shlex
import time
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..execution.runner import SshError, SshTarget, posix_command
from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (
    LEAST_PRIVILEGE_NOTE,
    Backup,
    ChangeError,
    derived_revision,
    management_guard,
    normalize_record,
    parse_ops,
    parse_ports,
    port_ranges,
)

# UNVERIFIED: the PHP binary path is the usual FreeBSD location, not a Netgate-documented path.
_PHP = "/usr/local/bin/php"
_CONFIG = "/cf/conf/config.xml"
_VERSION_FILE = "/etc/version"
_FILTER_RELOAD = "/etc/rc.filter_configure"
_WINDOW = 120
_CHANGE_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST = re.compile(r"^[A-Za-z0-9._:-]{1,253}$")
_USER = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_TRACKER = re.compile(r"^[0-9]{1,20}$")
# UNVERIFIED: Plus versions look like 26.07 / 25.11; CE looks like 2.9.0-RELEASE.
_PLUS_VERSION = re.compile(r"^(?:2[4-9]|[3-9]\d)\.\d{2}(?:\.\d+)?")
_CE_VERSION = re.compile(r"^2\.\d+\.\d+")
_MGMT_PORTS = (22, 80, 443)


def _change_id(ops: list[dict[str, Any]]) -> str:
    for op in ops:
        if op["op"] == "allow":
            text = op["marker"].split(":", 1)[-1]
            if _CHANGE_ID.match(text):
                return text
    digest = hashlib.sha256(json.dumps(ops, sort_keys=True).encode()).hexdigest()[:16]
    return digest


def _local(tag: ET.Element, name: str) -> str:
    child = tag.find(name)
    return (child.text or "").strip() if child is not None and child.text else ""


def _flag_present(tag: ET.Element, name: str) -> bool:
    """UNVERIFIED: pfSense treats the presence of <disabled> and <log>, including empty elements, as true."""
    return tag.find(name) is not None


class PfSenseConnector(Connector):
    kind = "pfsense"
    title = "pfSense"
    description = ("pfSense CE over SSH (config.xml and the official PHP config primitives, with a dead-man "
                   "restore). pfSense Plus stays read-only: the Nexus API was not verified far enough to write. "
                   "The unofficial pfrest package is an optional read-only mode.")
    fields = [
        ConnectorField(name="mode", label="Access", kind="select", default="ssh",
                       choices=[{"value": "ssh", "label": "SSH (CE)"}, {"value": "pfrest", "label": "pfrest (unofficial, read-only)"}]),
        ConnectorField(name="edition", label="Edition", kind="select", default="auto",
                       choices=[{"value": "auto", "label": "Detect"}, {"value": "ce", "label": "CE"},
                                {"value": "plus", "label": "Plus (read-only)"}]),
        ConnectorField(name="host", label="Host", placeholder="firewall.example"),
        ConnectorField(name="port", label="SSH port", kind="number", default=22),
        ConnectorField(name="username", label="SSH user", default="root",
                       help="Writes need root. Netgate's own backup examples use root."),
        ConnectorField(name="strict_host_keys", label="Strict host keys", kind="bool", default=True),
        ConnectorField(name="host_key", label="Pinned host key", help="One public key line, ssh-ed25519 AAAA..."),
        ConnectorField(name="known_hosts", label="known_hosts file"),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False),
        ConnectorField(name="pfrest_url", label="pfrest URL", kind="url",
                       help="Unofficial pfSense REST API package. Read-only. Not a Netgate product."),
        ConnectorField(name="private_key", label="SSH private key", kind="secret"),
        ConnectorField(name="password", label="SSH password", kind="secret", help="A key is preferred."),
        ConnectorField(name="api_key", label="pfrest API key", kind="secret"),
    ]
    capabilities = {"network": {"read"}}
    timeout = 60.0
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        mode = str(config.get("mode") or "ssh")
        if mode not in {"ssh", "pfrest"}:
            raise ConnectorError("Access must be ssh or pfrest")
        edition = str(config.get("edition") or "auto")
        if edition not in {"auto", "ce", "plus"}:
            raise ConnectorError("Edition must be auto, ce or plus")
        port = int(config.get("port") or 22)
        if not 1 <= port <= 65535:
            raise ConnectorError("SSH port must be 1-65535")
        cleaned = {**config, "mode": mode, "edition": edition, "port": port}
        if mode == "ssh":
            host = str(config.get("host") or "").strip()
            user = str(config.get("username") or "root").strip()
            if not _HOST.match(host):
                raise ConnectorError("Host must be a hostname or an IP address")
            if not _USER.match(user):
                raise ConnectorError("SSH user must be letters, digits, '.', '_' and '-'")
            cleaned["host"] = host
            cleaned["username"] = user
        else:
            url = str(config.get("pfrest_url") or "").strip().rstrip("/")
            parts = urlsplit(url)
            if parts.scheme != "https" or not parts.hostname:
                raise ConnectorError("pfrest URL must start with https://")
            if parts.username or parts.password:
                raise ConnectorError("pfrest URL must not contain credentials")
            cleaned["pfrest_url"] = url
        return cleaned

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("pfsense", "pf sense"))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only") or self.config.get("mode") == "pfrest" or self.config.get("edition") == "plus":
            return None
        return super().write_capability()

    def _target(self) -> SshTarget:
        return SshTarget(host=str(self.config.get("host") or ""), port=int(self.config.get("port") or 22),
                         username=str(self.config.get("username") or "root"),
                         private_key=self.secrets.get("private_key"), password=self.secrets.get("password"),
                         strict_host_keys=bool(self.config.get("strict_host_keys", True)),
                         host_key=(self.config.get("host_key") or None), known_hosts=(self.config.get("known_hosts") or None))

    async def _run(self, session: Any, command: str, *, stdin: str | None = None, what: str = "") -> Any:
        result = await session.run(command, input=stdin)
        if result.truncated:
            raise ChangeError("pfSense output was truncated; refusing to use a partial read", code="failed", state="unknown")
        if not result.ok:
            detail = self.redact((result.stderr or result.stdout or "").strip())[:300]
            raise ChangeError(f"pfSense command failed ({what or 'ssh'}, exit {result.exit_status}): {detail}",
                              code="failed", state="unknown")
        return result

    # -- test / pull ------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        if self.config.get("mode") == "pfrest":
            return await self._test_pfrest()
        checks: list[dict[str, Any]] = []
        try:
            async with self.ssh(self._target()) as session:
                try:
                    version_run = await session.run(f"cat {_VERSION_FILE}")
                except Exception as exc:  # SshError or a transport failure: the host did not give us a session
                    checks.append(check("reachability", False, self.redact(exc.__class__.__name__)))
                    return _test_result(False, "The firewall could not be reached over SSH", checks, None)
                checks.append(check("reachability", True, f"SSH session to {self._target().label}"))
                strict = bool(self.config.get("strict_host_keys", True))
                pinned = " A host key is pinned." if self.config.get("host_key") else ""
                checks.append(check("tls", strict, ("SSH with strict host-key checking." + pinned
                                                    + " The GUI certificate is not used by this connector.")
                                    if strict else "host-key checking is off"))
                if not version_run.ok:
                    checks.append(check("authentication", False, "the SSH command was refused"))
                    return _test_result(False, "SSH authentication failed", checks, None)
                checks.append(check("authentication", True, "SSH key accepted" if self.secrets.get("private_key")
                                    else "SSH session accepted"))
                identity = await session.run("id -u")
                uid = (identity.stdout or "").strip()
                edition, version = _edition(version_run.stdout, str(self.config.get("edition") or "auto"))
                writable = uid == "0" and edition == "ce" and not self.config.get("read_only") and strict
                if uid != "0":
                    privilege = "the SSH user is not root. Writes need root; reading config.xml as another user is unverified."
                elif edition == "plus":
                    privilege = "pfSense Plus is read-only here: the Nexus API base path and rule schema are not verified."
                elif self.config.get("read_only"):
                    privilege = "this connection is marked read-only. root can still write on the device; there is no general SSH read-only mode."
                else:
                    privilege = LEAST_PRIVILEGE_NOTE + " (CE writes need root; Deny Config Write is a GUI privilege only)"
                checks.append(check("privileges", True, privilege))
                supported = edition == "ce" and version is not None
                checks.append(check("version", supported or edition == "plus",
                                    f"pfSense {edition} {version or version_run.stdout.strip() or 'unknown'}"))
                features = ("CE: config.xml over SSH, PHP config_get_path / config_set_path / write_config / "
                            "filter_configure, dead-man restore after 120s. No official REST API.")
                if edition == "plus":
                    features = ("Plus detected. Nexus/MIM writes are not implemented (base path, login and rule "
                                "schema unverified). Config.xml is still read over SSH.")
                checks.append(check("api_features", True, features))
                spec = self._write_spec() if writable else None
                detail = f"Connected to pfSense {edition} {version or ''}.".strip()
                return _test_result(True, detail, checks, spec)
        except (ChangeError, SshError, OSError) as exc:
            message = self.redact(getattr(exc, "message", str(exc))[:300])
            if not any(item["name"] == "reachability" for item in checks):
                checks.append(check("reachability", False, message))
            return _test_result(False, message, checks, None)

    def _write_spec(self) -> dict[str, Any]:
        return {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        if self.config.get("mode") == "pfrest":
            return [await self._pull_pfrest()]
        async with self.ssh(self._target()) as session:
            version = await self._run(session, f"cat {_VERSION_FILE}", what="version")
            config = await self._run(session, f"cat {_CONFIG}", what="config")
            counters = await session.run("pfctl -vvsr")
        hits: dict[str, int] = {}
        notes = ["pfSense has no zone objects; each interface is a zone",
                 "NAT tags are not read"]
        if counters.ok and not counters.truncated:
            hits = _pfctl_hits(counters.stdout)
        else:
            notes.append("hit counts are not available (pfctl -vvsr did not succeed)")
        edition, version_text = _edition(version.stdout, str(self.config.get("edition") or "auto"))
        try:
            return [normalize_record(_from_xml(config.stdout, version_text or version.stdout.strip(), edition, hits, notes,
                                               self.config.get("host") or ""))]
        except (ValueError, ET.ParseError) as exc:
            raise ConnectorError(f"config.xml could not be read ({exc.__class__.__name__})") from exc

    # -- backups and changes -----------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        if self.config.get("mode") == "pfrest":
            raise ChangeError("pfrest is unofficial and is not used for backups", code="unsupported", state="unchanged")
        async with self.ssh(self._target()) as session:
            result = await self._run(session, f"cat {_CONFIG}", what="config")
        content = result.stdout
        revision = _revision_of(content)
        return {"content": content, "format": "xml", "device_backup_id": revision, "revision": revision,
                "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        if self.write_capability() is None:
            return {"steps": [], "notes": ["this connection cannot write"], "problems": ["device changes are not available on this connection"]}
        record = (await self.pull("network"))[0]
        steps = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                steps.append({"op": index, "kind": "add_rule", "position": f"top of {op['source']['zone']} rules",
                              "detail": "one pass rule, marked " + op["marker"]})
            else:
                steps.extend({"op": index, "kind": "disable_rule" if op["op"] == "disable_rules" else "enable_rule",
                              "position": "in place", "detail": f"{op['op']} {ref['vendor_ref']}"} for ref in op["rules"])
        return {"steps": steps, "notes": ["dead-man restores the pre-change config.xml after 120s unless confirm removes the arm file",
                                          "one address and one port per rule"], "problems": _problems(record, ops)}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        if self.write_capability() is None:
            raise ChangeError("This connection cannot change pfSense (read-only, Plus, or the unofficial API)",
                              code="unsupported", state="unchanged")
        ops = parse_ops(ops)
        change = _change_id(ops)
        arm = f"/tmp/atrium-arm-{change}"
        copy = f"/root/atrium-pre-{change}.xml"
        async with self.ssh(self._target()) as session:
            version = await self._run(session, f"cat {_VERSION_FILE}", what="version")
            edition, _ = _edition(version.stdout, str(self.config.get("edition") or "auto"))
            if edition != "ce":
                raise ChangeError("pfSense Plus writes are not implemented: the Nexus API was not verified",
                                  code="unsupported", state="unchanged")
            config = await self._run(session, f"cat {_CONFIG}", what="config")
            if _revision_of(config.stdout) != str(base_revision):
                raise ChangeError(f"The firewall revision changed (now {_revision_of(config.stdout)}): re-read it and preview again",
                                  code="stale", state="unchanged")
            record = normalize_record(_from_xml(config.stdout, version.stdout.strip(), edition, {}, [], self.config.get("host") or ""))
            problems = _problems(record, ops)
            if problems:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(problems), code="lockout", state="unchanged")
            payload, created, disabled = _payload(ops, record, change)
            # Arm before the write. The copy and the arm path use only the validated change id.
            await self._run(session, posix_command(["cp", _CONFIG, copy]), what="backup")
            await self._run(session, posix_command(["touch", arm]), what="arm")
            script = (f"sleep {_WINDOW}; [ -f {shlex.quote(arm)} ] && cp {shlex.quote(copy)} {_CONFIG} && "
                      f"rm -f /tmp/config.cache && {_FILTER_RELOAD}")
            await self._run(session, posix_command(["daemon", "-f", "sh", "-c", script]), what="dead-man")
            try:
                await self._php(session, payload)
            except ChangeError:
                await self._restore_copy(session, copy, arm)
                raise
        token = _token({"v": 1, "mode": "deadman", "change_id": change, "arm": arm, "backup_path": copy,
                        "created": created, "disabled": disabled})
        return {"token": token, "rollback_until": int(time.time()) + _WINDOW, "revision": None,
                "created": created, "disabled": disabled, "notes": ["dead-man armed for 120s"]}

    async def _php(self, session: Any, payload: dict[str, Any]) -> None:
        result = await self._run(session, _PHP, stdin=_php(payload), what="php")
        try:
            body = json.loads(result.stdout[result.stdout.find("{"):result.stdout.rfind("}") + 1])
        except ValueError as exc:
            raise ChangeError("the filter script did not return JSON", code="failed", state="unknown") from exc
        if not isinstance(body, dict) or body.get("ok") is not True:
            raise ChangeError("the filter script did not confirm the change", code="failed", state="unknown")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        payload = _loads(token)
        arm = _path_id(str(payload.get("arm") or ""), "/tmp/atrium-arm-")
        async with self.ssh(self._target()) as session:
            await self._run(session, posix_command(["rm", "-f", arm]), what="disarm")
        return {"confirmed": True, "revision": payload.get("change_id"), "notes": ["dead-man disarmed"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        payload = _loads(token)
        copy = _path_id(str(payload.get("backup_path") or ""), "/root/atrium-pre-", suffix=".xml")
        arm = _path_id(str(payload.get("arm") or ""), "/tmp/atrium-arm-")
        async with self.ssh(self._target()) as session:
            await self._restore_copy(session, copy, arm)
        return {"rolled_back": True, "method": "deadman", "notes": ["pre-change config.xml restored and the filter reloaded"]}

    async def _restore_copy(self, session: Any, copy: str, arm: str) -> None:
        await self._run(session, posix_command(["cp", copy, _CONFIG]), what="restore")
        await self._run(session, posix_command(["rm", "-f", "/tmp/config.cache", arm]), what="clear cache")
        await self._run(session, _FILTER_RELOAD, what="filter reload")

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        text = backup.text()
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ChangeError("the backup is not a plain pfSense configuration", code="invalid", state="unchanged")
        if "<pfsense" not in text and "<filter" not in text:
            raise ChangeError("the backup is not a pfSense configuration", code="invalid", state="unchanged")
        async with self.ssh(self._target()) as session:
            # The document travels on stdin. The command line is fixed.
            await self._run(session, posix_command(["cp", "/dev/stdin", _CONFIG]), stdin=text, what="restore")
            await self._run(session, posix_command(["rm", "-f", "/tmp/config.cache"]), what="clear cache")
            await self._run(session, _FILTER_RELOAD, what="filter reload")
        return {"restored": True, "revision": _revision_of(text), "notes": ["config.xml replaced from the backup and the filter reloaded"]}

    # -- unofficial pfrest (read-only) ------------------------------------------------------

    def _pfrest(self) -> httpx.AsyncClient:
        # Labelled unofficial. Writes are not implemented. The API key is a header, never a URL.
        return self.http(str(self.config.get("pfrest_url") or ""), headers={
            "X-API-Key": self.secrets.get("api_key", ""), "Accept": "application/json"})

    async def _test_pfrest(self) -> dict[str, Any]:
        checks = [check("reachability", False, "")]
        try:
            async with self._pfrest() as client:
                response = await client.get("/api/v2/firewall/rules", params={"limit": 1, "offset": 0})
        except httpx.TimeoutException:
            checks[0] = check("reachability", False, "pfrest did not answer in time")
            return _test_result(False, "pfrest did not answer", checks, None)
        except httpx.HTTPError:
            checks[0] = check("reachability", False, "pfrest could not be reached")
            return _test_result(False, "pfrest could not be reached", checks, None)
        checks[0] = check("reachability", True, "pfrest answered")
        checks.append(check("tls", str(self.config.get("pfrest_url") or "").startswith("https://"),
                            "HTTPS to the unofficial pfrest package"))
        if response.status_code == 401:
            checks.append(check("authentication", False, "the API key was refused (HTTP 401)"))
            return _test_result(False, "pfrest authentication failed", checks, None)
        self.raise_for_status(response, "pfrest rules")
        checks.append(check("authentication", True, "pfrest API key accepted"))
        checks.append(check("privileges", True, "unofficial pfrest, read-only. Atrium does not send writes to this package."))
        checks.append(check("version", True, "product version is read from /etc/version over SSH, not from pfrest"))
        checks.append(check("api_features", True, "unofficial read of /api/v2/firewall/rules. Not affiliated with Netgate. Writes are disabled."))
        return _test_result(True, "Connected to unofficial pfrest (read-only).", checks, None)

    async def _pull_pfrest(self) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        offset = 0
        async with self._pfrest() as client:
            while True:
                body = await self.request_json(client, "GET", "/api/v2/firewall/rules", what="pfrest rules",
                                               params={"limit": 50, "offset": offset})
                data = body.get("data") if isinstance(body, dict) else None
                if not isinstance(data, list):
                    raise ConnectorError("pfrest did not return a rules list")
                rows.extend(row for row in data if isinstance(row, dict))
                if len(data) < 50:
                    break
                offset += 50
                if offset > 20_000:
                    break
        rules = [_pfrest_rule(row, index) for index, row in enumerate(rows)]
        host = urlsplit(str(self.config.get("pfrest_url") or "")).hostname or "pfsense"
        raw = {"external_id": host, "revision": derived_revision([row.get("tracker") for row in rows]),
               "read_at": time.time(), "kind": "firewall",
               "device": {"vendor": "pfSense", "version": "", "hostname": host, "management_address": host},
               "interfaces": [], "zones": [], "aliases": [], "self_addresses": [], "rules": rules,
               "default_policy": {"inbound": "block"}, "nat_evaluated": False,
               "notes": ["unofficial pfrest read. Interface and alias paths were not verified, so they are not queried.",
                         "pfrest ids are array indexes and are not used as vendor_ref; tracker is."]}
        try:
            return normalize_record(raw)
        except ValueError as exc:
            raise ConnectorError(f"pfrest rules could not be read ({exc})") from exc


def _edition(text: str, configured: str) -> tuple[str, str]:
    raw = (text or "").strip().splitlines()[0] if text else ""
    if configured == "plus":
        return "plus", raw
    if configured == "ce":
        return "ce", raw
    if _PLUS_VERSION.match(raw):
        return "plus", raw
    if _CE_VERSION.match(raw) or raw:
        return "ce", raw
    return "ce", raw


def _revision_of(xml_text: str) -> str:
    try:
        root = ET.fromstring(_strip_doctype(xml_text))
    except ET.ParseError:
        return derived_revision(xml_text[:2000])
    revision = root.find("revision")
    stamp = _local(revision if revision is not None else ET.Element("revision"), "time")
    if stamp:
        return stamp
    trackers = [(_local(rule, "tracker"), _local(rule, "descr")) for rule in root.findall("./filter/rule")]
    return derived_revision(trackers)


def _strip_doctype(xml_text: str) -> str:
    if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
        raise ChangeError("config.xml contains a doctype and was refused", code="invalid", state="unchanged")
    return xml_text


def _from_xml(xml_text: str, version: str, edition: str, hits: dict[str, int], notes: list[str], host: str) -> dict[str, Any]:
    root = ET.fromstring(_strip_doctype(xml_text))
    interfaces = []
    vlans = {}
    for vlan in root.findall("./vlans/vlan"):
        tag = _local(vlan, "tag")
        parent = _local(vlan, "if")
        vlanif = _local(vlan, "vlanif")
        if tag.isdigit():
            vlans[vlanif or parent] = int(tag)
            vlans[parent] = int(tag)
    interfaces_el = root.find("interfaces")
    for element in list(interfaces_el if interfaces_el is not None else []):
        ident = element.tag
        address, subnet = _interface_address(element)
        # UNVERIFIED: role is inferred from the interface key (lan/wan), not a vendor field.
        role = "wan" if ident == "wan" else "lan" if ident == "lan" else "other"
        interfaces.append({"id": ident, "name": _local(element, "descr") or ident, "description": _local(element, "descr"),
                           "vlan": vlans.get(_local(element, "if")), "addresses": [address] if address else [],
                           "subnets": [subnet] if subnet else [], "role": role, "enabled": _flag_present(element, "enable")})
    aliases = []
    for alias in root.findall("./aliases/alias"):
        name = _local(alias, "name")
        if not name:
            continue
        kind = (_local(alias, "type") or "network").lower()
        values = _local(alias, "address").split()
        item: dict[str, Any] = {"name": name, "kind": kind if kind in {"network", "host", "port", "url", "geoip"} else "other"}
        if kind == "port":
            item["ports"] = ",".join(values)
        elif kind in {"url", "urltable", "geoip"}:
            item["resolved"] = False
        else:
            cidrs = []
            for value in values:
                try:
                    cidrs.append(str(ipaddress.ip_network(value, strict=False)))
                except ValueError:
                    continue
            item["cidrs"] = cidrs
        aliases.append(item)
    alias_names = {item["name"] for item in aliases}
    iface_ids = {item["id"] for item in interfaces}
    rules = []
    for index, rule in enumerate(root.findall("./filter/rule")):
        tracker = _local(rule, "tracker") or f"index:{index}"
        rules.append(_xml_rule(rule, index, tracker, iface_ids, alias_names, hits.get(tracker)))
    system = root.find("system")
    hostname = _local(system if system is not None else ET.Element("system"), "hostname")
    try:
        ipaddress.ip_address(host)
        management = host
    except ValueError:
        management = ""
    return {"external_id": hostname or host or "pfsense", "revision": _revision_of(xml_text), "read_at": time.time(),
            "kind": "firewall", "device": {"vendor": "pfSense", "model": edition, "version": version.strip()[:120],
                                           "hostname": hostname, "management_address": management},
            "interfaces": interfaces, "zones": [], "aliases": aliases,
            "self_addresses": [addr for item in interfaces for addr in item.get("addresses") or []],
            "rules": rules, "default_policy": {"inbound": "block"}, "nat_evaluated": False, "notes": notes}


def _interface_address(element: ET.Element) -> tuple[str, str]:
    ipaddr = _local(element, "ipaddr")
    bits = _local(element, "subnet")
    # UNVERIFIED: ipaddr "dhcp" means no static address.
    if not ipaddr or ipaddr.lower() in {"dhcp", "pppoe"}:
        return "", ""
    try:
        ipaddress.ip_address(ipaddr)
    except ValueError:
        return "", ""
    if bits.isdigit():
        network = ipaddress.ip_network(f"{ipaddr}/{bits}", strict=False)
        return ipaddr, str(network)
    return ipaddr, f"{ipaddr}/32"


def _endpoint_xml(element: ET.Element | None, interfaces: set[str], aliases: set[str]) -> dict[str, Any]:
    if element is None or element.find("any") is not None:
        return {"any": True}
    endpoint: dict[str, Any] = {}
    network = _local(element, "network")
    address = _local(element, "address")
    if network:
        if network in interfaces:
            endpoint["nets"] = [network]
        else:
            try:
                endpoint["cidrs"] = [str(ipaddress.ip_network(network, strict=False))]
            except ValueError:
                endpoint["aliases"] = [network]
    if address:
        try:
            endpoint.setdefault("cidrs", []).append(str(ipaddress.ip_network(address, strict=False)))
        except ValueError:
            if address in aliases or address not in {"any"}:
                endpoint.setdefault("aliases", []).append(address)
    if element.find("not") is not None:
        endpoint["negate"] = True
    return endpoint or {"any": True}


def _xml_rule(rule: ET.Element, index: int, tracker: str, interfaces: set[str], aliases: set[str],
              hits: int | None) -> dict[str, Any]:
    proto = (_local(rule, "protocol") or "any").lower()
    dest = rule.find("destination")
    port = _local(dest, "port") if dest is not None else ""
    services: Any
    if proto in {"", "any"} and not port:
        services = None
    else:
        service: dict[str, Any] = {"proto": proto or "any"}
        if port:
            try:
                service["ports"] = parse_ports(port.replace(":", "-"))
            except ValueError:
                service["alias"] = port
        services = [service]
    ifaces = [part for part in (_local(rule, "interface") or "").split(",") if part]
    floating = _local(rule, "floating").lower() in {"yes", "1", "on"} or (_flag_present(rule, "floating") and not ifaces)
    return {"id": tracker, "vendor_ref": tracker, "order": index, "enabled": not _flag_present(rule, "disabled"),
            "action": _local(rule, "type") or "pass", "interfaces": ifaces, "floating": floating,
            "direction": _local(rule, "direction") or "in", "quick": _local(rule, "quick").lower() not in {"0", "no"},
            "source": _endpoint_xml(rule.find("source"), interfaces, aliases),
            "destination": _endpoint_xml(dest, interfaces, aliases), "services": services,
            "log": _flag_present(rule, "log"), "description": _local(rule, "descr"), "hits": hits}


def _pfctl_hits(text: str) -> dict[str, int]:
    """UNVERIFIED: pfctl -vvsr layout. ridentifier comes from the tracker; Packets: is the counter used as hits."""
    found: dict[str, int] = {}
    current = None
    for line in text.splitlines():
        ident = re.search(r"ridentifier\s+(\d+)", line)
        if ident:
            current = ident.group(1)
        packets = re.search(r"Packets:\s*(\d+)", line, re.IGNORECASE)
        if current and packets:
            found[current] = int(packets.group(1))
            current = None
    return found


def _problems(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    problems = management_guard(record, ops)
    known = {item["id"] for item in record.get("interfaces") or []} | {item["id"] for item in record.get("zones") or []}
    addresses = record.get("self_addresses") or []
    for op in ops:
        if op["op"] != "allow":
            continue
        for side in ("source", "destination"):
            if op[side]["zone"] not in known:
                problems.append(f"the device has no interface '{op[side]['zone']}'")
            if len(op[side]["cidrs"]) != 1:
                problems.append("pfSense filter rules take one address on each side; split the change")
        protos = {svc["proto"] for svc in op["services"]}
        ports = [svc.get("ports") or "" for svc in op["services"]]
        if len(protos) != 1 or any("," in port or "-" in port for port in ports):
            problems.append("this connector writes one protocol and one port (a list or range needs a port alias)")
        if _covers(op["destination"]["cidrs"], addresses) and _mgmt(op["services"]):
            problems.append("the allow would open a management port toward an address of this firewall")
    return problems


def _covers(cidrs: list[str], addresses: list[str]) -> bool:
    for address in addresses:
        ip = ipaddress.ip_address(address)
        for cidr in cidrs:
            network = ipaddress.ip_network(cidr)
            if ip.version == network.version and ip in network:
                return True
    return False


def _mgmt(services: list[dict[str, Any]]) -> bool:
    for service in services:
        for low, high in port_ranges(service.get("ports")):
            if any(low <= port <= high for port in _MGMT_PORTS):
                return True
    return False


def _payload(ops: list[dict[str, Any]], record: dict[str, Any], change: str) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    existing = {str(rule.get("vendor_ref")) for rule in record.get("rules") or []}
    tracker = max([int(value) for value in existing if value.isdigit()] + [int(time.time())])
    created, disabled = [], []
    adds, disables, enables = [], [], []
    for index, op in enumerate(ops):
        if op["op"] == "allow":
            tracker += 1
            while str(tracker) in existing:
                tracker += 1
            ref = str(tracker)
            existing.add(ref)
            adds.append(_php_rule(op, ref))
            created.append({"op": index, "id": ref, "vendor_ref": ref})
        else:
            enable = op["op"] == "enable_rules"
            for ref in op["rules"]:
                token = str(ref.get("vendor_ref") or ref["id"])
                if not _TRACKER.match(token):
                    raise ChangeError("pfSense rules are addressed by their numeric tracker", code="invalid", state="unchanged")
                (enables if enable else disables).append(token)
                disabled.append(token)
    reason = f"Atrium: {change}"
    return {"reason": reason, "add": adds, "disable": disables, "enable": enables}, created, disabled


def _php_rule(op: dict[str, Any], tracker: str) -> dict[str, Any]:
    proto = op["services"][0]["proto"]
    versions = {ipaddress.ip_network(cidr).version for side in ("source", "destination") for cidr in op[side]["cidrs"]}
    rule: dict[str, Any] = {
        "tracker": tracker, "type": "pass", "interface": op["source"]["zone"],
        "ipprotocol": "inet" if versions == {4} else "inet6" if versions == {6} else "inet46",
        "protocol": proto, "direction": "in",
        "source": {"address": op["source"]["cidrs"][0]},
        "destination": {"address": op["destination"]["cidrs"][0]},
        "descr": f"{op['marker']} {op.get('description') or ''}".strip(),
    }
    if proto != "icmp":
        rule["destination"]["port"] = op["services"][0]["ports"]
    if op.get("log", True):
        rule["log"] = ""
    return rule


def _php(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, ensure_ascii=True)
    # nowdoc, one JSON line: device text stays inside the JSON string, never on the command line.
    return f"""<?php
require_once("config.inc");
require_once("filter.inc");
$req = json_decode(<<<'ATRIUM_JSON'
{blob}
ATRIUM_JSON, true);
if (!is_array($req)) {{ fwrite(STDERR, "Atrium payload was not JSON\\n"); exit(2); }}
$rules = config_get_path('filter/rule', array());
if (!is_array($rules)) {{ $rules = array(); }}
if ($rules !== array() && array_keys($rules) !== range(0, count($rules) - 1)) {{
    // UNVERIFIED: a single rule can come back as one associative array rather than a list.
    $rules = array($rules);
}}
foreach (($req["disable"] ?? array()) as $tracker) {{
    $found = false;
    foreach ($rules as &$rule) {{
        if ((string)($rule["tracker"] ?? "") === (string)$tracker) {{ $rule["disabled"] = ""; $found = true; }}
    }}
    unset($rule);
    if (!$found) {{ fwrite(STDERR, "tracker not found\\n"); exit(3); }}
}}
foreach (($req["enable"] ?? array()) as $tracker) {{
    foreach ($rules as &$rule) {{
        if ((string)($rule["tracker"] ?? "") === (string)$tracker) {{ unset($rule["disabled"]); }}
    }}
    unset($rule);
}}
foreach (($req["add"] ?? array()) as $rule) {{
    $iface = (string)($rule["interface"] ?? "");
    $at = count($rules);
    foreach ($rules as $index => $existing) {{
        if ((string)($existing["interface"] ?? "") === $iface) {{ $at = $index; break; }}
    }}
    array_splice($rules, $at, 0, array($rule));
}}
config_set_path('filter/rule', $rules);
write_config((string)($req["reason"] ?? "Atrium"));
filter_configure();
echo json_encode(array("ok" => true));
"""


def _pfrest_rule(row: dict[str, Any], index: int) -> dict[str, Any]:
    tracker = str(row.get("tracker") or f"index:{index}")
    interfaces = row.get("interface") or []
    if isinstance(interfaces, str):
        interfaces = [interfaces]
    proto = str(row.get("protocol") or "any").lower()
    port = row.get("destination_port")
    services = None if proto in {"", "any"} and not port else [{"proto": proto or "any", "ports": port}]
    return {"id": tracker, "vendor_ref": tracker, "order": index, "enabled": not bool(row.get("disabled")),
            "action": row.get("type") or "pass", "interfaces": interfaces, "direction": row.get("direction") or "in",
            "source": _pfrest_endpoint(row.get("source")), "destination": _pfrest_endpoint(row.get("destination")),
            "services": services, "log": bool(row.get("log")), "description": row.get("descr") or ""}


def _pfrest_endpoint(value: Any) -> dict[str, Any]:
    if value in (None, "", "any"):
        return {"any": True}
    text = str(value)
    try:
        return {"cidrs": [str(ipaddress.ip_network(text, strict=False))]}
    except ValueError:
        return {"aliases": [text]}


def _test_result(ok: bool, detail: str, checks: list[dict[str, Any]], spec: dict[str, Any] | None) -> dict[str, Any]:
    return {"ok": ok, "detail": detail, "checks": checks, "domains": {"network": ["read"]} if ok else {},
            "network_write": spec}


def _token(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    if len(raw) > 4096:
        raise ChangeError("the change token is too large", code="failed", state="unknown")
    return raw


def _loads(token: str) -> dict[str, Any]:
    try:
        payload = json.loads(token)
    except ValueError as exc:
        raise ChangeError("the change token is not valid", code="invalid", state="unknown") from exc
    if not isinstance(payload, dict):
        raise ChangeError("the change token is not valid", code="invalid", state="unknown")
    return payload


def _path_id(path: str, prefix: str, suffix: str = "") -> str:
    if not path.startswith(prefix) or (suffix and not path.endswith(suffix)):
        raise ChangeError("the change token has an unexpected path", code="invalid", state="unknown")
    ident = path[len(prefix):-len(suffix)] if suffix else path[len(prefix):]
    if not _CHANGE_ID.match(ident):
        raise ChangeError("the change token has an unexpected path", code="invalid", state="unknown")
    return path
