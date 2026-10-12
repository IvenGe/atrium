"""MikroTik RouterOS v7 connector (REST).

Every value the router returns is a string. Rules are ``/rest/ip/firewall/filter``; ``.id`` is the native
reference. There is no commit step and no documented way to enter Safe Mode over REST, so a change arms a
one-shot scheduler 120 seconds ahead (the inverse of the change) before it writes. Confirm deletes that
scheduler. Rollback performs the inverse immediately and deletes the scheduler.

The scheduler script is built only from the Atrium marker (a change id) and from ``.id`` values that match
``*`` plus hexadecimal digits. Device comments and descriptions are not copied into the script.

UNVERIFIED: ``/rest/system/clock`` and ``/rest/system/identity`` paths, interface-list and address-list field
names, VLAN menu field names, whether a plain GET includes bytes/packets, ``.id`` stability across reboots,
and that a full ``.rsc`` import is not used (it duplicates objects; binary backup load reboots).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (
    LEAST_PRIVILEGE_NOTE,
    Backup,
    ChangeError,
    derived_revision,
    management_guard,
    normalize_record,
    parse_ops,
    port_ranges,
)

_WINDOW = 120
_ID = re.compile(r"^\*[0-9A-Fa-f]+$")
_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CHANGE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_MGMT_PORTS = (22, 80, 443, 8291, 8728, 8729)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _truthy(value: Any) -> bool:
    return _text(value).lower() in {"true", "yes", "1", "on"}


def _rows(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if isinstance(body, dict):
        return [body]
    return []


def _version(text: str) -> tuple[int, int, int] | None:
    match = _VERSION.search(text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _safe_id(value: str) -> str:
    if not _ID.match(value or ""):
        raise ChangeError("refusing a RouterOS id that is not an internal *id", code="invalid", state="unchanged")
    return value


class MikroTikConnector(Connector):
    kind = "mikrotik"
    title = "MikroTik RouterOS"
    description = ("RouterOS v7 REST API. Values are strings. Changes apply immediately, so a one-shot "
                   "scheduler undoes them after 120 seconds unless the change is confirmed. Safe Mode is not used.")
    fields = [
        ConnectorField(name="base_url", label="Router URL", kind="url", required=True,
                       placeholder="https://router.example",
                       help="HTTPS on www-ssl. The router has no certificate until one is assigned."),
        ConnectorField(name="username", label="User", default="admin",
                       help="The group needs both api and rest-api. Writes also need write."),
        ConnectorField(name="ca_file", label="CA certificate file",
                       help="PEM file of the certificate assigned to www-ssl. Empty uses the system trust store."),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False,
                       help="Atrium will not offer device changes. Prefer a group with only read,api,rest-api."),
        ConnectorField(name="password", label="Password", kind="secret", required=True),
    ]
    capabilities = {"network": {"read"}}
    timeout = 60.0
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        url = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConnectorError("Router URL must start with https://")
        if parts.username or parts.password:
            raise ConnectorError("Router URL must not contain credentials")
        if parts.scheme != "https" and parts.hostname not in {"localhost", "127.0.0.1"}:
            raise ConnectorError("Router URL must be https:// so the password does not travel in clear text")
        user = str(config.get("username") or "admin").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
            raise ConnectorError("User must be letters, digits, '.', '_' and '-'")
        return {**config, "base_url": url, "username": user, "ca_file": str(config.get("ca_file") or "").strip()}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("mikrotik", "routeros", "router os"))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        return super().write_capability()

    def _client(self) -> httpx.AsyncClient:
        verify: bool | str = self.config.get("ca_file") or True
        return self.http(self.config.get("base_url") or "", auth=httpx.BasicAuth(
            str(self.config.get("username") or "admin"), self.secrets.get("password", "")), verify=verify,
            headers={"Accept": "application/json", "Content-Type": "application/json"})

    async def _json(self, client: httpx.AsyncClient, method: str, url: str, *, what: str = "", **kwargs: Any) -> Any:
        body = await self.request_json(client, method, url, what=what, **kwargs)
        if isinstance(body, dict) and body.get("error") and body.get("detail"):
            raise self.error(f"RouterOS rejected the request ({what or url}): {body.get('detail')}",
                             status=int(body.get("error") or 400))
        return body

    async def _optional(self, client: httpx.AsyncClient, url: str) -> Any:
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        if response.status_code in {400, 401, 403, 404, 500}:
            return None
        self.raise_for_status(response, url)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return None

    # -- test / pull ------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        try:
            async with self._client() as client:
                try:
                    response = await client.get("/rest/system/resource")
                except httpx.TimeoutException:
                    checks.append(check("reachability", False, "the router did not answer in time"))
                    return _result(False, "The router did not answer in time", checks, None)
                except httpx.HTTPError as exc:
                    if any(word in exc.__class__.__name__.lower() or word in str(exc).lower()
                           for word in ("ssl", "tls", "certificate")):
                        checks.append(check("reachability", True, "the host answered"))
                        checks.append(check("tls", False, "the certificate was not accepted"))
                        return _result(False, "TLS certificate was not accepted", checks, None)
                    checks.append(check("reachability", False, "the router could not be reached"))
                    return _result(False, "The router could not be reached", checks, None)
                checks.append(check("reachability", True, "the router answered"))
                https = str(self.config.get("base_url") or "").startswith("https://")
                if self.config.get("ca_file"):
                    tls_detail = "HTTPS; the certificate is checked against the configured CA file"
                elif https:
                    tls_detail = "HTTPS; the certificate is checked with the system trust store (www-ssl has no certificate until one is assigned)"
                else:
                    tls_detail = "the URL is not HTTPS"
                checks.append(check("tls", https, tls_detail))
                if response.status_code == 401:
                    checks.append(check("authentication", False, "the user was refused (HTTP 401). The group needs rest-api, and the address must match."))
                    return _result(False, "Authentication failed", checks, None)
                if response.status_code >= 300:
                    detail = _permission_detail(response)
                    if detail:
                        checks.append(check("authentication", True, "HTTP Basic accepted"))
                        checks.append(check("privileges", False, detail))
                        return _result(False, "The user cannot use the REST API", checks, None)
                    self.raise_for_status(response, "system resource")
                checks.append(check("authentication", True, "HTTP Basic accepted"))
                resource = response.json()
                version_text = _resource_version(resource)
                parsed = _version(version_text)
                if parsed is None:
                    checks.append(check("privileges", False, "version is unknown, so firewall access was not checked"))
                    checks.append(check("version", False, "system/resource did not include a version string"))
                    checks.append(check("api_features", False, "RouterOS version is unknown"))
                    return _result(False, "RouterOS version unknown", checks, None)
                supported = parsed[0] >= 7
                version_detail = f"RouterOS {version_text}" + ("" if supported else " (REST needs v7)")
                if not supported:
                    checks.append(check("privileges", False, "RouterOS v6 has no REST API this connector can use"))
                    checks.append(check("version", False, version_detail))
                    checks.append(check("api_features", False, "REST needs RouterOS v7"))
                    return _result(False, "RouterOS v6 has no REST API this connector can use", checks, None)
                rules = await client.get("/rest/ip/firewall/filter")
                if rules.status_code in {401, 403, 500} and _permission_detail(rules):
                    checks.append(check("privileges", False, _permission_detail(rules)))
                    checks.append(check("version", True, version_detail))
                    checks.append(check("api_features", False, "firewall filter is not readable"))
                    return _result(False, "The user cannot read firewall rules", checks, None)
                self.raise_for_status(rules, "firewall filter")
                if self.config.get("read_only"):
                    privilege = "this connection is marked read-only. A group with only read,api,rest-api cannot write."
                    spec = None
                else:
                    privilege = LEAST_PRIVILEGE_NOTE + " (rule writes need the write policy as well as api and rest-api)"
                    spec = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "deadman", "window_s": _WINDOW}
                checks.append(check("privileges", True, privilege))
                checks.append(check("version", True, version_detail))
                checks.append(check("api_features", True,
                                    "REST filter rules apply immediately. Rollback is a one-shot scheduler 120s ahead. "
                                    "Safe Mode has no documented REST entry and is not used."))
                return _result(True, f"Connected to RouterOS {version_text}.", checks, spec)
        except ConnectorError as exc:
            checks.append(check("reachability", False, exc.message))
            return _result(False, exc.message, checks, None)

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self._client() as client:
            resource = await self._json(client, "GET", "/rest/system/resource", what="system resource")
            identity = await self._optional(client, "/rest/system/identity")  # UNVERIFIED path
            addresses = await self._json(client, "GET", "/rest/ip/address", what="addresses")
            interfaces = await self._json(client, "GET", "/rest/interface", what="interfaces")
            vlans = await self._optional(client, "/rest/interface/vlan")  # UNVERIFIED menu
            lists = await self._optional(client, "/rest/interface/list")  # UNVERIFIED field names
            members = await self._optional(client, "/rest/interface/list/member")
            addr_lists = await self._optional(client, "/rest/ip/firewall/address-list")
            rules = await self._json(client, "GET", "/rest/ip/firewall/filter", what="filter")
        return [self._record(resource, identity, addresses, interfaces, vlans, lists, members, addr_lists, rules)]

    def _record(self, resource: Any, identity: Any, addresses: Any, interfaces: Any, vlans: Any, lists: Any,
                members: Any, addr_lists: Any, rules: Any) -> dict[str, Any]:
        notes = ["RouterOS has no commit; this read is the running configuration",
                 "interface lists stand in for zones",
                 "bytes/packets on a plain GET are unverified; they are used when the router sends them"]
        vlan_of = {}
        for row in _rows(vlans):
            name = _text(row.get("name"))
            tag = _text(row.get("vlan-id"))
            if name and tag.isdigit():
                vlan_of[name] = int(tag)
        by_iface: dict[str, dict[str, list[str]]] = {}
        for row in _rows(addresses):
            if _truthy(row.get("disabled")):
                continue
            iface = _text(row.get("interface") or row.get("actual-interface"))
            text = _text(row.get("address"))
            bucket = by_iface.setdefault(iface, {"addresses": [], "subnets": []})
            _take_address(text, bucket["addresses"], bucket["subnets"])
        iface_rows = []
        for row in _rows(interfaces):
            name = _text(row.get("name"))
            if not name:
                continue
            kind = _text(row.get("type")).lower()
            # UNVERIFIED: WAN/LAN role is not a RouterOS field. ether on the WAN list is left as other.
            role = "lan" if name.lower() in {"bridge", "lan"} else "other"
            addrs = by_iface.get(name) or {"addresses": [], "subnets": []}
            iface_rows.append({"id": name, "name": name, "description": _text(row.get("comment")),
                               "vlan": vlan_of.get(name), "addresses": addrs["addresses"], "subnets": addrs["subnets"],
                               "role": role, "enabled": not _truthy(row.get("disabled"))})
        zones = []
        grouped: dict[str, list[str]] = {}
        for row in _rows(members):
            # UNVERIFIED: member objects use "list" and "interface".
            name = _text(row.get("list") or row.get("name"))
            iface = _text(row.get("interface"))
            if name and iface:
                grouped.setdefault(name, []).append(iface)
        for row in _rows(lists):
            name = _text(row.get("name"))
            if name and name not in grouped:
                grouped.setdefault(name, [])
        for name, ifaces in grouped.items():
            zones.append({"id": name, "name": name, "interfaces": ifaces})
        aliases: dict[str, list[str]] = {}
        for row in _rows(addr_lists):
            # UNVERIFIED: address-list entries use "list" (or "name") and "address".
            name = _text(row.get("list") or row.get("name"))
            address = _text(row.get("address"))
            if not name or not address:
                continue
            try:
                aliases.setdefault(name, []).append(str(ipaddress.ip_network(address, strict=False)))
            except ValueError:
                continue
        alias_rows = [{"name": name, "kind": "network", "cidrs": cidrs} for name, cidrs in aliases.items()]
        known_ifaces = {row["id"] for row in iface_rows}
        known_aliases = set(aliases)
        rule_rows = []
        for index, row in enumerate(_rows(rules)):
            if _truthy(row.get("dynamic")):
                continue
            rule_rows.append(_rule(row, index, known_ifaces, known_aliases))
        version_text = _resource_version(resource)
        board = ""
        if isinstance(resource, dict):
            board = _text(resource.get("board-name"))
        elif isinstance(resource, list) and resource:
            board = _text(resource[0].get("board-name"))
        hostname = ""
        if isinstance(identity, dict):
            hostname = _text(identity.get("name"))
        host = urlsplit(str(self.config.get("base_url") or "")).hostname or ""
        try:
            ipaddress.ip_address(host)
            management = host
        except ValueError:
            management = ""
        stable = [{key: value for key, value in row.items() if key not in {"bytes", "packets"}} for row in _rows(rules)]
        raw = {"external_id": hostname or board or host or "mikrotik", "revision": derived_revision(stable),
               "read_at": time.time(), "kind": "router",
               "device": {"vendor": "MikroTik", "model": board, "version": version_text, "hostname": hostname,
                          "management_address": management},
               "interfaces": iface_rows, "zones": zones, "aliases": alias_rows,
               "self_addresses": [addr for row in iface_rows for addr in row.get("addresses") or []],
               "rules": rule_rows, "default_policy": {"inbound": "unknown", "forward": "unknown"},
               "nat_evaluated": False, "notes": notes}
        try:
            return normalize_record(raw)
        except ValueError as exc:
            raise ConnectorError(f"RouterOS returned a device record that could not be read ({exc})") from exc

    # -- backups and changes -----------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        name = "atrium-bk-" + hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        file_name = name + ".rsc"
        async with self._client() as client:
            await self._json(client, "POST", "/rest/export", what="export", json={"file": name})
            chunks: list[str] = []
            offset = 0
            while True:
                # UNVERIFIED: the file/read JSON uses "data" and the offset is a byte count.
                body = await self._json(client, "POST", "/rest/file/read", what="read export",
                                        json={"file": file_name, "chunk-size": "32768", "offset": str(offset)})
                data = body.get("data") if isinstance(body, dict) else ""
                if not data:
                    break
                chunks.append(str(data))
                offset += len(str(data).encode("utf-8"))
                if offset > 32_000_000:
                    break
            await self._delete(client, "/rest/file/" + quote(file_name, safe=""))
        content = "".join(chunks)
        return {"content": content, "format": "text", "device_backup_id": None,
                "revision": None, "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest()}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        record = (await self.pull("network"))[0]
        steps = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                steps.append({"op": index, "kind": "add_rule", "position": "top of the forward chain (place-before)",
                              "detail": "one accept rule, marked " + op["marker"]})
            else:
                steps.extend({"op": index, "kind": "disable_rule" if op["op"] == "disable_rules" else "enable_rule",
                              "position": "in place", "detail": f"{op['op']} {ref['vendor_ref']}"} for ref in op["rules"])
        return {"steps": steps, "notes": ["scheduler dead-man, 120s, because Safe Mode is not available over REST",
                                          "one address per side; the rule is placed before the first forward rule"],
                "problems": _problems(record, ops)}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        if self.write_capability() is None:
            raise ChangeError("This connection is read-only", code="unsupported", state="unchanged")
        ops = parse_ops(ops)
        async with self._client() as client:
            record = (await self.pull("network"))[0]
            if str(record["revision"]) != str(base_revision):
                raise ChangeError(f"The router is at revision {record['revision']}, not {base_revision}: re-read it and preview again",
                                  code="stale", state="unchanged")
            problems = _problems(record, ops)
            if problems:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(problems), code="lockout", state="unchanged")
            clock = await self._json(client, "GET", "/rest/system/clock", what="clock")
            start_date, start_time = _ahead(clock, _WINDOW)
            name = "atrium-rb-" + hashlib.sha256(json.dumps(ops, sort_keys=True).encode()).hexdigest()[:20]
            on_event = _on_event(ops, name)
            # Arm before any filter write. The script does not contain device-provided descriptions.
            scheduler = await self._json(client, "PUT", "/rest/system/scheduler", what="scheduler", json={
                "name": name, "start-date": start_date, "start-time": start_time, "interval": "0s", "on-event": on_event})
            scheduler_id = _safe_id(_text((scheduler or {}).get(".id")))
            try:
                created, disabled, enabled = await self._write(client, ops, record)
            except (ConnectorError, ChangeError) as exc:
                await self._delete(client, "/rest/system/scheduler/" + quote(scheduler_id, safe="*"))
                code = exc.code if isinstance(exc, ChangeError) else "failed"
                raise ChangeError(self.redact(exc.message), code=code, state="unchanged") from exc
        token = _token({"v": 1, "mode": "deadman", "scheduler_id": scheduler_id, "scheduler_name": name,
                        "created": created, "disabled": disabled, "enabled": enabled})
        return {"token": token, "rollback_until": int(time.time()) + _WINDOW, "revision": None,
                "created": created, "disabled": disabled, "notes": ["scheduler dead-man armed for 120s"]}

    async def _write(self, client: httpx.AsyncClient, ops: list[dict[str, Any]], record: dict[str, Any]
                     ) -> tuple[list[dict[str, Any]], list[str], list[str]]:
        created, disabled, enabled = [], [], []
        fresh = await self._json(client, "GET", "/rest/ip/firewall/filter", what="filter")
        rows = _rows(fresh)
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                comment = f"{op['marker']} {op.get('description') or ''}".strip()
                existing = next((row for row in rows if op["marker"] in _text(row.get("comment"))), None)
                if existing:
                    rule_id = _safe_id(_text(existing.get(".id")))
                else:
                    rule_id = await self._add(client, op, comment, rows)
                created.append({"op": index, "id": rule_id, "vendor_ref": rule_id})
            else:
                enable = op["op"] == "enable_rules"
                for ref in op["rules"]:
                    rule_id = _safe_id(_text(ref.get("vendor_ref") or ref["id"]))
                    await self._json(client, "PATCH", "/rest/ip/firewall/filter/" + quote(rule_id, safe="*"),
                                    what="toggle rule", json={"disabled": "false" if enable else "true"})
                    (enabled if enable else disabled).append(rule_id)
        return created, disabled, enabled

    async def _add(self, client: httpx.AsyncClient, op: dict[str, Any], comment: str, rows: list[dict[str, Any]]) -> str:
        proto = op["services"][0]["proto"]
        ports = [str(svc["ports"]) for svc in op["services"] if svc.get("ports")]
        body: dict[str, str] = {
            "chain": "forward", "action": "accept", "src-address": op["source"]["cidrs"][0],
            "dst-address": op["destination"]["cidrs"][0], "protocol": proto, "comment": comment,
            "log": "true" if op.get("log", True) else "false",
        }
        if proto != "icmp" and ports:
            body["dst-port"] = ",".join(ports)
        zone = op["source"]["zone"]
        if _NAME.match(zone):
            body["in-interface"] = zone
        anchor = next((_text(row.get(".id")) for row in rows if _text(row.get("chain")) == "forward" and _ID.match(_text(row.get(".id")))), "")
        if anchor:
            body["place-before"] = anchor
        created = await self._json(client, "PUT", "/rest/ip/firewall/filter", what="add rule", json=body)
        return _safe_id(_text((created or {}).get(".id")))

    async def confirm_change(self, token: str) -> dict[str, Any]:
        payload = _loads(token)
        scheduler_id = _safe_id(str(payload.get("scheduler_id") or ""))
        async with self._client() as client:
            await self._delete(client, "/rest/system/scheduler/" + quote(scheduler_id, safe="*"))
        return {"confirmed": True, "revision": payload.get("scheduler_name"), "notes": ["dead-man scheduler removed"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        payload = _loads(token)
        scheduler_id = _safe_id(str(payload.get("scheduler_id") or ""))
        async with self._client() as client:
            for item in payload.get("created") or []:
                if isinstance(item, dict) and _ID.match(str(item.get("id") or "")):
                    await self._delete(client, "/rest/ip/firewall/filter/" + quote(str(item["id"]), safe="*"))
            for rule_id in payload.get("disabled") or []:
                if _ID.match(str(rule_id)):
                    await self._json(client, "PATCH", "/rest/ip/firewall/filter/" + quote(str(rule_id), safe="*"),
                                    what="re-enable rule", json={"disabled": "false"})
            for rule_id in payload.get("enabled") or []:
                if _ID.match(str(rule_id)):
                    await self._json(client, "PATCH", "/rest/ip/firewall/filter/" + quote(str(rule_id), safe="*"),
                                    what="re-disable rule", json={"disabled": "true"})
            await self._delete(client, "/rest/system/scheduler/" + quote(scheduler_id, safe="*"))
        return {"rolled_back": True, "method": "inverse_ops", "notes": ["created rules removed, disabled rules enabled, scheduler deleted"]}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        # A full .rsc import duplicates live objects, and /system/backup/load reboots. Neither is a safe restore.
        raise ChangeError("RouterOS REST has no verified way to put an export back without duplicating objects or "
                          "rebooting. Roll back the change, or restore a binary backup at the console.",
                          code="unsupported", state="unchanged")

    async def _delete(self, client: httpx.AsyncClient, url: str) -> None:
        try:
            response = await client.delete(url)
        except httpx.HTTPError as exc:
            raise self.error(f"RouterOS delete failed: {exc.__class__.__name__}") from exc
        if response.status_code in {200, 204, 404}:
            return
        self.raise_for_status(response, url)


def _resource_version(body: Any) -> str:
    """``version`` on /system/resource is UNVERIFIED; board-name is documented."""
    row = body[0] if isinstance(body, list) and body else body
    if not isinstance(row, dict):
        return ""
    return _text(row.get("version"))


def _permission_detail(response: httpx.Response) -> str:
    text = response.text or ""
    if "not enough permissions" in text or "not allowed" in text:
        return "the group is missing a policy (api, rest-api, or read)"
    if response.status_code == 403:
        return "REST is disabled on the router (HTTP 403)"
    return ""


def _take_address(text: str, addresses: list[str], subnets: list[str]) -> None:
    if not text:
        return
    try:
        network = ipaddress.ip_network(text, strict=False)
        host = str(ipaddress.ip_interface(text).ip) if "/" in text else text
    except ValueError:
        return
    if host not in addresses:
        addresses.append(host)
    rendered = str(network)
    if rendered not in subnets:
        subnets.append(rendered)


def _endpoint_address(value: str, interfaces: set[str], aliases: set[str]) -> dict[str, Any]:
    if not value:
        return {}
    try:
        return {"cidrs": [str(ipaddress.ip_network(value, strict=False))]}
    except ValueError:
        if value in aliases:
            return {"aliases": [value]}
        return {"aliases": [value]} if _NAME.match(value) else {"any": True}


def _rule(row: dict[str, Any], index: int, interfaces: set[str], aliases: set[str]) -> dict[str, Any]:
    rule_id = _text(row.get(".id")) or f"row-{index}"
    chain = _text(row.get("chain")).lower()
    direction = {"input": "in", "output": "out"}.get(chain, "in")
    source = _endpoint_address(_text(row.get("src-address")), interfaces, aliases)
    destination = _endpoint_address(_text(row.get("dst-address")), interfaces, aliases)
    if _text(row.get("src-address-list")):
        source = {"aliases": [_text(row.get("src-address-list"))]}
    if _text(row.get("dst-address-list")):
        destination = {"aliases": [_text(row.get("dst-address-list"))]}
    if chain == "input" and not destination:
        destination = {"self": True}
    proto = _text(row.get("protocol")).lower()
    port = _text(row.get("dst-port"))
    services = None
    if proto or port:
        service: dict[str, Any] = {"proto": proto or "tcp"}
        if port:
            service["ports"] = port.replace(":", "-")
        services = [service]
    in_iface = _text(row.get("in-interface"))
    out_iface = _text(row.get("out-interface"))
    hits = row.get("packets")
    return {"id": rule_id, "vendor_ref": rule_id, "order": index, "enabled": not _truthy(row.get("disabled")),
            "action": _text(row.get("action")) or "accept",
            "interfaces": [in_iface] if in_iface else [], "out_interfaces": [out_iface] if out_iface else [],
            "source_zones": [_text(row.get("in-interface-list"))] if _text(row.get("in-interface-list")) else [],
            "destination_zones": [_text(row.get("out-interface-list"))] if _text(row.get("out-interface-list")) else [],
            "direction": direction, "source": source or {"any": True}, "destination": destination or {"any": True},
            "services": services, "log": _truthy(row.get("log")), "description": _text(row.get("comment")),
            "hits": hits or None}


def _problems(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    problems = management_guard(record, ops)
    known = {item["id"] for item in record.get("interfaces") or []} | {item["id"] for item in record.get("zones") or []}
    addresses = record.get("self_addresses") or []
    for op in ops:
        if op["op"] != "allow":
            continue
        for side in ("source", "destination"):
            if op[side]["zone"] not in known:
                problems.append(f"the router has no interface or interface list '{op[side]['zone']}'")
            if len(op[side]["cidrs"]) != 1:
                problems.append("a RouterOS filter rule takes one address on each side; split the change")
        protos = {svc["proto"] for svc in op["services"]}
        if len(protos) != 1:
            problems.append("a RouterOS filter rule takes one protocol; split the change")
        if _covers(op["destination"]["cidrs"], addresses) and _mgmt(op["services"]):
            problems.append("the allow would open a management port toward an address of this router")
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
        if service.get("proto") not in {"tcp", "udp"}:
            continue
        for low, high in port_ranges(service.get("ports")):
            if any(low <= port <= high for port in _MGMT_PORTS):
                return True
    return False


def _ahead(clock: Any, seconds: int) -> tuple[str, str]:
    """UNVERIFIED: /rest/system/clock returns date (YYYY-MM-DD or mon/dd/yyyy) and time (HH:MM:SS)."""
    row = clock[0] if isinstance(clock, list) and clock else clock
    if not isinstance(row, dict):
        raise ChangeError("the router clock could not be read, so the dead-man cannot be armed", code="failed", state="unchanged")
    date_text, time_text = _text(row.get("date")), _text(row.get("time"))
    parsed = None
    for date_fmt in ("%Y-%m-%d", "%b/%d/%Y"):
        try:
            parsed = datetime.strptime(f"{date_text} {time_text}", f"{date_fmt} %H:%M:%S")
            break
        except ValueError:
            continue
    if parsed is None:
        raise ChangeError("the router clock format was not recognised, so the dead-man cannot be armed",
                          code="failed", state="unchanged")
    later = parsed + timedelta(seconds=seconds)
    return later.strftime("%Y-%m-%d"), later.strftime("%H:%M:%S")


def _on_event(ops: list[dict[str, Any]], scheduler_name: str) -> str:
    parts = []
    for op in ops:
        if op["op"] == "allow":
            marker = op["marker"].split(":", 1)[-1]
            if not _CHANGE.match(marker):
                raise ChangeError("the change marker is not safe to place in a scheduler script", code="invalid", state="unchanged")
            # comment~ is a RouterOS find match. The marker alphabet has no regex metacharacters. UNVERIFIED operator.
            parts.append(f'/ip/firewall/filter/remove [find comment~"atrium:{marker}"]')
        else:
            enable = op["op"] == "enable_rules"
            for ref in op["rules"]:
                rule_id = _safe_id(_text(ref.get("vendor_ref") or ref["id"]))
                # CLI yes/no. UNVERIFIED inside a scheduler script; REST itself uses "true"/"false".
                parts.append(f"/ip/firewall/filter/set {rule_id} disabled={'yes' if enable else 'no'}")
    if not _CHANGE.match(scheduler_name.removeprefix("atrium-rb-")):
        raise ChangeError("the scheduler name is not safe", code="invalid", state="unchanged")
    parts.append(f'/system/scheduler/remove [find name="{scheduler_name}"]')
    return "; ".join(parts)


def _result(ok: bool, detail: str, checks: list[dict[str, Any]], spec: dict[str, Any] | None) -> dict[str, Any]:
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
