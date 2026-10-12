"""OPNsense firewall connector (REST, API key + secret over HTTP Basic).

Reads one ``network`` record and, where the firmware has a safe mechanism, applies an allow (one pass rule)
or disables rules. Rollback follows the firmware, not a single class default:

- 24.1 through 26.1.x: ``POST /api/firewall/filter/savepoint``, ``apply/<revision>``, then
  ``cancelRollback/<revision>`` within 60 seconds (verified in the 26.1 source). The class declaration uses
  this mode; ``test()`` narrows a 26.7+ device to backup-restore.
- 26.7 and later: savepoint was removed. The pre-change backup id is recorded and ``revert_backup/<id>``
  undoes the change. There is no device-side timer.

HTTP 200 with ``{"result":"failed"}`` is a failure. The API key and secret never appear in errors.

UNVERIFIED (see the research notes): the exact ``system_information`` / ``interfaces_info`` JSON shapes, the
string encoding of booleans, the 25.7 snake_case cut-over, ``(self)`` as the this-firewall token, and that
``revert`` reloads the running ruleset (``apply`` is repeated after it).
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import time
from typing import Any
from urllib.parse import urlsplit

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

# cancelRollback keeps the camelCase action name from the 26.1 controller [V-src].
_SAVEPOINT_CUTOFF = (26, 7, 0)
# UNVERIFIED: community reports say endpoints moved to snake_case in 25.7. The router accepts both
# casings; the ACL does not. camelCase is used only when a parsed version is older than 25.7.
_SNAKE_CASE_FROM = (25, 7, 0)
_CAMEL = {
    "search_rule": "searchRule", "add_rule": "addRule", "toggle_rule": "toggleRule",
    "move_rule_before": "moveRuleBefore", "search_item": "searchItem", "interfaces_info": "interfacesInfo",
    "system_information": "systemInformation", "rule_stats": "ruleStats", "revert_backup": "revertBackup",
}
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_REVISION = re.compile(r"^[0-9.]+$")
_BACKUP_ID = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_MGMT_PORTS = (22, 80, 443)


def _version_tuple(text: str) -> tuple[int, int, int] | None:
    match = _VERSION.search(text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)


def _flag(value: Any, default: bool = False) -> bool:
    """OPNsense often encodes booleans as '1'/'0' (the example values are unverified)."""
    if isinstance(value, bool):
        return value
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "enabled"}


def _csv(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        items = value
    else:
        items = re.split(r"[, \n]+", str(value))
    return [str(item).strip() for item in items if str(item).strip()]


def _rows(body: Any) -> list[dict[str, Any]]:
    """A search grid (``rows``) or a dict of objects. The interfaces_info envelope is UNVERIFIED."""
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if not isinstance(body, dict):
        return []
    for key in ("rows", "interfaces", "items"):
        if isinstance(body.get(key), list):
            return [row for row in body[key] if isinstance(row, dict)]
    values = [value for value in body.values() if isinstance(value, dict)]
    if values and any(key in value for value in values for key in ("identifier", "uuid", "name", "device")):
        return values
    return []


def _version_text(body: Any) -> str:
    """Product version from diagnostics/system/system_information. The JSON layout is UNVERIFIED."""
    if not isinstance(body, dict):
        return ""
    for key in ("product_version", "version"):
        if body.get(key):
            return str(body[key])
    versions = body.get("versions") or []
    parts: list[str] = []
    for item in versions if isinstance(versions, list) else [versions]:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict):
            parts.append(" ".join(str(item.get(k) or "") for k in ("product", "name", "version", "product_version")))
    named = next((part for part in parts if "opnsense" in part.lower()), "")
    return named or " ".join(parts)


def _endpoint(token: str, interfaces: set[str], aliases: set[str]) -> dict[str, Any]:
    parts = _csv(token)
    if not parts or any(part.lower() in {"any", "*", "(any)"} for part in parts):
        return {"any": True}
    cidrs, nets, names, self_device = [], [], [], False
    for part in parts:
        lowered = part.lower()
        # UNVERIFIED: OPNsense shows this firewall as "(self)" in the rules UI.
        if lowered in {"(self)", "self", "this firewall"}:
            self_device = True
            continue
        cidr = None
        try:
            cidr = str(ipaddress.ip_network(part, strict=False))
        except ValueError:
            cidr = None
        if cidr:
            cidrs.append(cidr)
        elif part in interfaces:
            nets.append(part)
        elif part in aliases or _SAFE_NAME.match(part):
            names.append(part)
    endpoint: dict[str, Any] = {}
    if cidrs:
        endpoint["cidrs"] = cidrs
    if nets:
        endpoint["nets"] = nets
    if names:
        endpoint["aliases"] = names
    if self_device:
        endpoint["self"] = True
    return endpoint or {"any": True}


def _safe_id(value: str, pattern: re.Pattern[str], what: str) -> str:
    text = str(value or "").strip()
    if not pattern.match(text):
        raise ChangeError(f"refusing an unsafe {what}", code="invalid", state="unchanged")
    return text


class OpnSenseConnector(Connector):
    kind = "opnsense"
    title = "OPNsense"
    description = ("OPNsense firewall over the core REST API (API key and secret, HTTP Basic). "
                   "Rules [new] only. Savepoint rollback on 26.1 and older; backup restore on 26.7 and later.")
    fields = [
        ConnectorField(name="base_url", label="Firewall URL", kind="url", required=True,
                       placeholder="https://firewall.example", help="HTTPS address of the firewall. Redirects are not followed."),
        ConnectorField(name="ca_file", label="CA certificate file",
                       help="PEM file pinning the firewall's CA or certificate. Empty uses the system trust store."),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False,
                       help="Atrium will not offer device changes. The key can still write unless the user has user-config-readonly."),
        ConnectorField(name="api_key", label="API key", kind="secret", required=True),
        ConnectorField(name="api_secret", label="API secret", kind="secret", required=True),
    ]
    capabilities = {"network": {"read"}}
    timeout = 60.0
    network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "savepoint", "window_s": 60}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        url = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ConnectorError("Firewall URL must start with https://")
        if parts.username or parts.password:
            raise ConnectorError("Firewall URL must not contain credentials")
        if parts.scheme != "https" and parts.hostname not in {"localhost", "127.0.0.1"}:
            raise ConnectorError("Firewall URL must be https:// so the API key does not travel in clear text")
        ca_file = str(config.get("ca_file") or "").strip()
        return {**config, "base_url": url, "ca_file": ca_file}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("opnsense", "opn sense"))

    def write_capability(self) -> dict[str, Any] | None:
        if self.config.get("read_only"):
            return None
        return super().write_capability()

    # -- HTTP -------------------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        verify: bool | str = self.config.get("ca_file") or True
        return self.http(self.config.get("base_url") or "", auth=httpx.BasicAuth(
            self.secrets.get("api_key", ""), self.secrets.get("api_secret", "")), verify=verify,
            headers={"Accept": "application/json"})

    def _path(self, *parts: str, version: tuple[int, int, int] | None = None) -> str:
        """``/api/<module>/<controller>/<command>``. Pre-25.7 camelCase is UNVERIFIED."""
        use_camel = version is not None and version < _SNAKE_CASE_FROM
        mapped = []
        for part in parts:
            if use_camel and part in _CAMEL:
                mapped.append(_CAMEL[part])
            else:
                mapped.append(part)
        return "/api/" + "/".join(mapped)

    async def _send(self, client: httpx.AsyncClient, method: str, url: str, *, what: str = "",
                    **kwargs: Any) -> Any:
        body = await self.request_json(client, method, url, what=what, **kwargs)
        failed = _result_problem(body)
        if failed:
            raise self.error(f"OPNsense rejected the request ({what or url}): {failed}", status=200)
        return body

    def _tls_check(self) -> dict[str, Any]:
        if str(self.config.get("base_url") or "").startswith("https://"):
            if self.config.get("ca_file"):
                return check("tls", True, "HTTPS; the certificate is checked against the configured CA file")
            return check("tls", True, "HTTPS; the certificate is checked with the system trust store")
        return check("tls", False, "the URL is not HTTPS")

    def _write_spec(self, version: tuple[int, int, int] | None) -> dict[str, Any] | None:
        if self.config.get("read_only") or version is None:
            return None
        if version >= _SAVEPOINT_CUTOFF:
            return {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "backup_restore", "window_s": 120}
        return {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "savepoint", "window_s": 60}

    # -- test / pull ------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        try:
            async with self._client() as client:
                try:
                    response = await client.get(self._path("diagnostics", "system", "system_information"))
                except httpx.TimeoutException:
                    checks.append(check("reachability", False, "the firewall did not answer in time"))
                    return _test_result(False, "The firewall did not answer in time", checks, None)
                except httpx.HTTPError as exc:
                    return _transport_failure(checks, exc)
                checks.append(check("reachability", True, "the firewall answered"))
                checks.append(self._tls_check())
                if response.status_code == 401:
                    checks.append(check("authentication", False, "the API key was refused (HTTP 401)"))
                    return _test_result(False, "Authentication failed", checks, None)
                if response.status_code >= 300:
                    self.raise_for_status(response, "system information")
                info = response.json()
                checks.append(check("authentication", True, "API key accepted"))
                text = _version_text(info)
                version = _version_tuple(text)
                label = text.strip() or (".".join(str(part) for part in version) if version else "")
                shown = label if label.lower().startswith("opnsense") else f"OPNsense {label}".strip()
                if version is None:
                    checks.append(check("privileges", False, "version is unknown, so rule access was not checked"))
                    checks.append(check("version", False, "the firmware did not report an OPNsense version"))
                    checks.append(check("api_features", False, "the firmware version is unknown"))
                    return _test_result(False, "Version unknown", checks, None)
                supported = version >= (24, 1, 0)
                version_detail = shown + ("" if supported else " (before 24.1, no core rules API)")
                if not supported:
                    checks.append(check("privileges", False, "this version has no core rules API to check"))
                    checks.append(check("version", False, version_detail))
                    checks.append(check("api_features", False, "no core rules API before 24.1"))
                    return _test_result(False, "This OPNsense version has no core rules API", checks, None)
                rules = await client.get(self._path("firewall", "filter", "search_rule", version=version),
                                         params={"current": 1, "rowCount": 1, "searchPhrase": ""})
                if rules.status_code == 403:
                    checks.append(check("privileges", False, "the key cannot read firewall rules (needs Firewall: Rules [new])"))
                    checks.append(check("version", True, version_detail))
                    checks.append(check("api_features", False, "filter API is not permitted for this key"))
                    return _test_result(False, "The API key cannot read firewall rules", checks, None)
                self.raise_for_status(rules, "firewall rules")
                spec = self._write_spec(version)
                if self.config.get("read_only"):
                    privilege = ("marked read-only on this connection, so device changes stay off. "
                                 "page-filter-api itself grants read and write; user-config-readonly on the user is what blocks writes")
                    spec = None
                elif spec:
                    privilege = LEAST_PRIVILEGE_NOTE + " (page-filter-api has no method distinction; a read-only key needs user-config-readonly)"
                else:
                    privilege = "rules are readable"
                checks.append(check("privileges", True, privilege))
                checks.append(check("version", True, version_detail))
                history = await client.get(self._path("core", "backup", "backups", "this"))
                history_ok = history.status_code == 200
                if version >= _SAVEPOINT_CUTOFF:
                    feature = ("26.7 or later: savepoint was removed. Rollback stores the current backup id and "
                               "calls revert_backup. There is no automatic timer.")
                    if not history_ok:
                        feature += " This key cannot read config history, so rollback is unavailable."
                        spec = None
                        checks.append(check("api_features", False, feature))
                        return _test_result(False, "Rollback needs config history", checks, None)
                else:
                    feature = "24.1-26.1: native savepoint, apply/<revision>, cancelRollback within 60 seconds."
                    if not history_ok:
                        feature += " Config history is not readable; the savepoint path does not need it."
                checks.append(check("api_features", True, feature))
                return _test_result(True, f"Connected to {shown}.", checks, spec)
        except ConnectorError as exc:
            checks.append(check("reachability", False, exc.message))
            return _test_result(False, exc.message, checks, None)

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        async with self._client() as client:
            info = await self._send(client, "GET", self._path("diagnostics", "system", "system_information"),
                                    what="system information")
            version_text = _version_text(info)
            version = _version_tuple(version_text)
            interfaces_body = await self._send(client, "GET", self._path("interfaces", "overview", "interfaces_info", version=version),
                                               what="interfaces")
            aliases_body = await self._optional(client, self._path("firewall", "alias", "search_item", version=version))
            groups_body = await self._optional(client, self._path("firewall", "group", "search_item", version=version))
            rules_body = await self._send(client, "GET", self._path("firewall", "filter", "search_rule", version=version),
                                          what="firewall rules", params={"current": 1, "rowCount": -1, "searchPhrase": ""})
            stats_body = await self._optional(client, self._path("firewall", "filter_util", "rule_stats", version=version))
            backups = await self._optional(client, self._path("core", "backup", "backups", "this"))
        return [self._record(info, version_text, interfaces_body, aliases_body, groups_body, rules_body, stats_body, backups)]

    async def _optional(self, client: httpx.AsyncClient, url: str) -> Any:
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            return None
        if response.status_code in {401, 403, 404}:
            return None
        self.raise_for_status(response, url)
        if not response.content:
            return None
        try:
            body = response.json()
        except ValueError:
            return None
        if _result_problem(body):
            return None
        return body

    def _record(self, info: Any, version_text: str, interfaces_body: Any, aliases_body: Any, groups_body: Any,
                rules_body: Any, stats_body: Any, backups: Any) -> dict[str, Any]:
        notes = ["classic (non-MVC) rules may appear without a uuid and cannot be changed through this API",
                 "interface groups stand in for zones; OPNsense has no zone objects"]
        interfaces = _interfaces(interfaces_body)
        aliases = _aliases(aliases_body)
        zones = _groups(groups_body)
        iface_ids = {item["id"] for item in interfaces}
        alias_names = {item["name"] for item in aliases}
        stats = _stats(stats_body)
        if not stats:
            notes.append("hit counts are not available to this key")
        rules = []
        for index, row in enumerate(_rows(rules_body)):
            if str(row.get("legacy") or "").strip():
                notes.append("legacy rules are included but are not writable through the MVC API")
            rules.append(_rule(row, index, iface_ids, alias_names, stats))
        hostname = ""
        if isinstance(info, dict):
            hostname = str(info.get("name") or info.get("hostname") or "").split(".")[0]
        items = _rows(backups) if not isinstance(backups, dict) else (backups.get("items") or [])
        if isinstance(backups, dict) and isinstance(backups.get("items"), list):
            items = backups["items"]
        newest = items[0] if items and isinstance(items[0], dict) else {}
        revision = str(newest.get("id") or newest.get("time") or "") or derived_revision(
            [row.get("uuid") or row.get("sequence") for row in _rows(rules_body)])
        host = urlsplit(str(self.config.get("base_url") or "")).hostname or ""
        try:
            ipaddress.ip_address(host)
            management = host
        except ValueError:
            management = ""
        raw = {
            "external_id": hostname or host or "opnsense",
            "revision": revision,
            "read_at": time.time(),
            "kind": "firewall",
            "device": {"vendor": "OPNsense", "version": version_text.strip()[:120], "hostname": hostname,
                       "management_address": management},
            "interfaces": interfaces, "zones": zones, "aliases": aliases,
            "self_addresses": [addr for item in interfaces for addr in item.get("addresses") or []],
            "rules": rules,
            "default_policy": {"inbound": "block"},
            "nat_evaluated": False,
            "notes": notes,
        }
        try:
            return normalize_record(raw)
        except ValueError as exc:
            raise ConnectorError(f"OPNsense returned a device record that could not be read ({exc})") from exc

    # -- backups and changes -----------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        async with self._client() as client:
            meta = await self._send(client, "GET", self._path("core", "backup", "backups", "this"), what="config history")
            items = meta.get("items") if isinstance(meta, dict) else None
            newest = items[0] if isinstance(items, list) and items else {}
            backup_id = str((newest or {}).get("id") or "")
            path = self._path("core", "backup", "download", "this")
            if backup_id and _BACKUP_ID.match(backup_id):
                path += "/" + backup_id
            response = await client.get(path)
            self.raise_for_status(response, "configuration download")
            content = response.content
        if not content:
            raise ConnectorError("OPNsense returned an empty configuration backup")
        return {"content": content, "format": "xml", "device_backup_id": backup_id or None,
                "revision": backup_id or None, "sha256": hashlib.sha256(content).hexdigest()}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        ops = parse_ops(ops)
        async with self._client() as client:
            record = (await self.pull("network"))[0]
        problems = _problems(record, ops)
        steps = []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                steps.append({"op": index, "kind": "add_rule", "position": f"top of {op['source']['zone']} rules",
                              "detail": "one pass rule, marked " + op["marker"]})
            else:
                kind = "disable_rule" if op["op"] == "disable_rules" else "enable_rule"
                steps.extend({"op": index, "kind": kind, "position": "in place",
                              "detail": f"{op['op']} {ref['vendor_ref']}"} for ref in op["rules"])
        mode = "savepoint (60s) on 26.1 and older; backup id + revert_backup on 26.7+"
        return {"steps": steps, "notes": [mode, "MVC rules are evaluated before legacy interface rules"], "problems": problems}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        if self.write_capability() is None:
            raise ChangeError("This connection is read-only", code="unsupported", state="unchanged")
        ops = parse_ops(ops)
        async with self._client() as client:
            info = await self._send(client, "GET", self._path("diagnostics", "system", "system_information"),
                                    what="system information")
            version = _version_tuple(_version_text(info))
            if version is None:
                raise ChangeError("Cannot read the OPNsense version, so the rollback mechanism is unknown",
                                  code="failed", state="unchanged")
            current = str((await self.pull("network"))[0]["revision"])
            if current != str(base_revision):
                raise ChangeError(f"The firewall is at revision {current}, not {base_revision}: re-read it and preview again",
                                  code="stale", state="unchanged")
            record = (await self.pull("network"))[0]
            problems = _problems(record, ops)
            if problems:
                raise ChangeError("Refused by the management-path guard: " + "; ".join(problems),
                                  code="lockout", state="unchanged")
            use_savepoint = version < _SAVEPOINT_CUTOFF
            armed: dict[str, Any] = {}
            try:
                if use_savepoint:
                    armed = await self._arm_savepoint(client, version)
                else:
                    armed = await self._arm_backup(client)
                created, disabled = await self._write_ops(client, ops, record, version)
                revision = armed.get("revision")
                apply_path = self._path("firewall", "filter", "apply", version=version)
                if use_savepoint and revision:
                    apply_path += "/" + revision
                await self._send(client, "POST", apply_path, what="filter apply")
            except (ConnectorError, ChangeError) as exc:
                state = await self._undo_arm(client, armed, version)
                code = exc.code if isinstance(exc, ChangeError) else "failed"
                raise ChangeError(self.redact(exc.message), code=code, state=state) from exc
        token = _token({"v": 1, "mode": armed["mode"], "revision": armed.get("revision"),
                        "backup_id": armed.get("backup_id"), "created": created, "disabled": disabled})
        return {"token": token, "rollback_until": armed.get("rollback_until"), "revision": armed.get("backup_id") or current,
                "created": created, "disabled": disabled, "notes": [armed["mode"]]}

    async def _arm_savepoint(self, client: httpx.AsyncClient, version: tuple[int, int, int]) -> dict[str, Any]:
        try:
            body = await self._send(client, "POST", self._path("firewall", "filter", "savepoint", version=version),
                                    what="savepoint")
        except ConnectorError as exc:
            if exc.status == 404:
                return await self._arm_backup(client)
            raise
        revision = str((body or {}).get("revision") or "")
        revision = _safe_id(revision, _REVISION, "savepoint revision")
        return {"mode": "savepoint", "revision": revision, "rollback_until": int(time.time()) + 60}

    async def _arm_backup(self, client: httpx.AsyncClient) -> dict[str, Any]:
        body = await self._send(client, "GET", self._path("core", "backup", "backups", "this"), what="config history")
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list) or not items or not isinstance(items[0], dict):
            raise ChangeError("OPNsense did not return a config history id, so a 26.7 change cannot be rolled back",
                              code="failed", state="unchanged")
        backup_id = _safe_id(str(items[0].get("id") or ""), _BACKUP_ID, "backup id")
        return {"mode": "backup_restore", "backup_id": backup_id, "rollback_until": None}

    async def _undo_arm(self, client: httpx.AsyncClient, armed: dict[str, Any],
                        version: tuple[int, int, int]) -> str:
        try:
            if armed.get("mode") == "savepoint" and armed.get("revision"):
                await self._send(client, "POST", self._path("firewall", "filter", "revert", version=version)
                                 + "/" + armed["revision"], what="revert savepoint")
                return "rolled_back"
            if armed.get("mode") == "backup_restore" and armed.get("backup_id"):
                await self._revert_backup(client, armed["backup_id"])
                return "rolled_back"
        except ConnectorError:
            return "unknown"
        return "unchanged"

    async def _write_ops(self, client: httpx.AsyncClient, ops: list[dict[str, Any]], record: dict[str, Any],
                         version: tuple[int, int, int]) -> tuple[list[dict[str, Any]], list[str]]:
        existing = {str(rule.get("description") or ""): rule for rule in record.get("rules") or []}
        created, disabled = [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                marker_text = op["marker"]
                found = next((rule for text, rule in existing.items() if marker_text in text), None)
                if found:
                    uuid = str(found["vendor_ref"])
                else:
                    uuid = await self._add_rule(client, op, record, version)
                created.append({"op": index, "id": uuid, "vendor_ref": uuid})
            else:
                enable = op["op"] == "enable_rules"
                for ref in op["rules"]:
                    uuid = _safe_id(str(ref.get("vendor_ref") or ref["id"]), _UUID, "rule uuid")
                    await self._send(client, "POST", self._path("firewall", "filter", "toggle_rule", version=version)
                                     + f"/{uuid}/" + ("1" if enable else "0"), what="toggle rule")
                    disabled.append(uuid)
        return created, disabled

    async def _add_rule(self, client: httpx.AsyncClient, op: dict[str, Any], record: dict[str, Any],
                        version: tuple[int, int, int]) -> str:
        zone = op["source"]["zone"]
        if not _SAFE_NAME.match(zone):
            raise ChangeError("the source zone is not a safe interface name", code="invalid", state="unchanged")
        protos = {svc["proto"] for svc in op["services"]}
        if len(protos) != 1:
            raise ChangeError("an OPNsense filter rule takes one protocol; split the change", code="invalid",
                              state="unchanged")
        proto = next(iter(protos))
        ports = [svc.get("ports") for svc in op["services"] if svc.get("ports")]
        rule: dict[str, Any] = {
            "enabled": "1", "action": "pass", "quick": "1", "direction": "in",
            "interface": zone, "ipprotocol": _ipproto(op), "protocol": proto.upper(),
            "source_net": ",".join(op["source"]["cidrs"]), "destination_net": ",".join(op["destination"]["cidrs"]),
            "log": "1" if op.get("log", True) else "0",
            "description": f"{op['marker']} {op.get('description') or ''}".strip(),
        }
        if proto != "icmp":
            rule["destination_port"] = ",".join(ports)
        body = await self._send(client, "POST", self._path("firewall", "filter", "add_rule", version=version),
                                what="add rule", json={"rule": rule})
        uuid = str((body or {}).get("uuid") or "")
        uuid = _safe_id(uuid, _UUID, "new rule uuid")
        target = _first_on_interface(record, zone, skip=uuid)
        if target:
            await self._send(client, "POST", self._path("firewall", "filter", "move_rule_before", version=version)
                             + f"/{uuid}/{target}", what="move rule")
        return uuid

    async def confirm_change(self, token: str) -> dict[str, Any]:
        payload = _loads(token)
        if payload.get("mode") != "savepoint":
            return {"confirmed": True, "revision": payload.get("backup_id"),
                    "notes": ["26.7 has no savepoint timer; the change stays until an explicit rollback"]}
        revision = _safe_id(str(payload.get("revision") or ""), _REVISION, "savepoint revision")
        async with self._client() as client:
            body = await self._send(client, "POST", "/api/firewall/filter/cancelRollback/" + revision,
                                    what="cancel rollback")
        status = str((body or {}).get("status") or "")
        if "unknown" in status.lower():
            raise ChangeError("The savepoint is gone; the firewall may already have reverted the change",
                              code="failed", state="rolled_back")
        return {"confirmed": True, "revision": revision, "notes": ["savepoint rollback cancelled"]}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        payload = _loads(token)
        async with self._client() as client:
            if payload.get("mode") == "savepoint":
                revision = _safe_id(str(payload.get("revision") or ""), _REVISION, "savepoint revision")
                await self._send(client, "POST", "/api/firewall/filter/revert/" + revision, what="revert savepoint")
                # UNVERIFIED: whether revert reloads pf. The 26.1 timer reloads after rollback, so apply again.
                await self._send(client, "POST", "/api/firewall/filter/apply", what="filter apply after revert")
                return {"rolled_back": True, "method": "savepoint", "notes": ["filter model restored to the savepoint"]}
            backup_id = str(payload.get("backup_id") or (backup.device_backup_id if backup else "") or "")
            backup_id = _safe_id(backup_id, _BACKUP_ID, "backup id")
            await self._revert_backup(client, backup_id)
        return {"rolled_back": True, "method": "backup_restore", "notes": [f"config history {backup_id} restored"]}

    async def _revert_backup(self, client: httpx.AsyncClient, backup_id: str) -> None:
        await self._send(client, "POST", "/api/core/backup/revert_backup/" + backup_id, what="revert backup")
        await self._send(client, "POST", "/api/firewall/filter/apply", what="filter apply after restore")

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        backup_id = str(backup.device_backup_id or "")
        if not backup_id:
            raise ChangeError("This backup has no OPNsense history id. The verified API restores a history id, "
                              "not an uploaded XML file.", code="unsupported", state="unchanged")
        backup_id = _safe_id(backup_id, _BACKUP_ID, "backup id")
        async with self._client() as client:
            await self._revert_backup(client, backup_id)
        return {"restored": True, "revision": backup_id, "notes": ["restored the device history entry, then reloaded the filter"]}


def _result_problem(body: Any) -> str:
    """HTTP 200 with result failed is still a failure [V-src]."""
    if not isinstance(body, dict) or str(body.get("result", "")).lower() != "failed":
        return ""
    validations = body.get("validations")
    if isinstance(validations, dict) and validations:
        return ", ".join(f"{key}: {value}" for key, value in list(validations.items())[:6])
    return "result failed"


def _test_result(ok: bool, detail: str, checks: list[dict[str, Any]], spec: dict[str, Any] | None) -> dict[str, Any]:
    return {"ok": ok, "detail": detail, "checks": checks, "domains": {"network": ["read"]} if ok else {},
            "network_write": spec}


def _transport_failure(checks: list[dict[str, Any]], exc: httpx.HTTPError) -> dict[str, Any]:
    text = exc.__class__.__name__
    if any(word in text.lower() or word in str(exc).lower() for word in ("ssl", "tls", "certificate")):
        checks.append(check("reachability", True, "the host answered"))
        checks.append(check("tls", False, "the certificate was not accepted"))
        return _test_result(False, "TLS certificate was not accepted", checks, None)
    checks.append(check("reachability", False, "the firewall could not be reached"))
    return _test_result(False, "The firewall could not be reached", checks, None)


def _interfaces(body: Any) -> list[dict[str, Any]]:
    out = []
    for row in _rows(body):
        ident = str(row.get("identifier") or row.get("id") or row.get("device") or "").strip()
        if not ident:
            continue
        addresses, subnets = [], []
        for family in ("ipv4", "ipv6"):
            entries = row.get(family) or []
            if isinstance(entries, dict):
                entries = [entries]
            for entry in entries if isinstance(entries, list) else []:
                text = str((entry or {}).get("ipaddr") or "") if isinstance(entry, dict) else str(entry)
                _take_address(text, addresses, subnets)
        for key in ("addr4", "addr6"):
            if row.get(key) and not addresses:
                _take_address(str(row[key]), addresses, subnets)
        role = "wan" if ident == "wan" else "lan" if ident == "lan" else "other"
        # UNVERIFIED: role is inferred from the interface identifier, not from a vendor field.
        out.append({"id": ident, "name": str(row.get("description") or ident), "description": str(row.get("description") or ""),
                    "vlan": row.get("vlan_tag") or None, "addresses": addresses, "subnets": subnets, "role": role,
                    "enabled": _flag(row.get("enabled"), True)})
    return out


def _take_address(text: str, addresses: list[str], subnets: list[str]) -> None:
    text = text.strip()
    if not text or text.lower() in {"dhcp", "none"}:
        return
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return
    host = text.split("/")[0]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return
    if host not in addresses:
        addresses.append(host)
    rendered = str(network)
    if rendered not in subnets:
        subnets.append(rendered)


def _aliases(body: Any) -> list[dict[str, Any]]:
    out = []
    for row in _rows(body):
        name = str(row.get("name") or "").strip()
        if not name:
            continue
        kind = str(row.get("type") or "network").lower()
        content = _csv(str(row.get("content") or "").replace("\n", ","))
        item: dict[str, Any] = {"name": name, "kind": kind if kind in {"network", "host", "port", "url", "geoip"} else "other"}
        if kind == "port":
            item["ports"] = ",".join(content)
        elif kind in {"url", "urltable", "geoip"}:
            item["resolved"] = False
        else:
            cidrs = []
            for value in content:
                try:
                    cidrs.append(str(ipaddress.ip_network(value, strict=False)))
                except ValueError:
                    continue
            item["cidrs"] = cidrs
        out.append(item)
    return out


def _groups(body: Any) -> list[dict[str, Any]]:
    """Interface groups. Member field names are UNVERIFIED beyond the search grid."""
    out = []
    for row in _rows(body):
        name = str(row.get("name") or row.get("ifname") or "").strip()
        if not name:
            continue
        members = _csv(row.get("members") or row.get("interfaces") or row.get("ifname"))
        out.append({"id": name, "name": name, "description": str(row.get("description") or ""), "interfaces": members})
    return out


def _stats(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    stats = body.get("stats")
    return stats if isinstance(stats, dict) else {}


def _rule(row: dict[str, Any], index: int, interfaces: set[str], aliases: set[str], stats: dict[str, Any]) -> dict[str, Any]:
    uuid = str(row.get("uuid") or "").strip()
    ident = uuid or f"legacy-{row.get('sequence') or index}"
    iface = [part for part in _csv(row.get("interface")) if part]
    proto = str(row.get("protocol") or "any").lower()
    port = str(row.get("destination_port") or "").strip()
    services: Any
    if proto in {"", "any"} and not port:
        services = None
    else:
        services = [{"proto": proto or "any", "ports": port or None}]
    source = _endpoint(str(row.get("source_net") or ""), interfaces, aliases)
    destination = _endpoint(str(row.get("destination_net") or ""), interfaces, aliases)
    if _flag(row.get("source_not")):
        source["negate"] = True
    if _flag(row.get("destination_not")):
        destination["negate"] = True
    hits = None
    counters = stats.get(uuid) if uuid else None
    if isinstance(counters, dict):
        hits = counters.get("packets", counters.get("evaluations"))
    return {
        "id": ident, "vendor_ref": uuid or ident, "order": int(float(row.get("sequence") or index)),
        "enabled": _flag(row.get("enabled"), True), "action": row.get("action") or "pass",
        "interfaces": iface, "direction": row.get("direction") or "in", "quick": _flag(row.get("quick"), True),
        "source": source, "destination": destination, "services": services, "log": _flag(row.get("log")),
        "description": row.get("description") or "", "hits": hits,
    }


def _first_on_interface(record: dict[str, Any], zone: str, skip: str) -> str | None:
    ranked = [rule for rule in record.get("rules") or [] if zone in (rule.get("interfaces") or []) and rule.get("vendor_ref") != skip]
    ranked.sort(key=lambda rule: rule.get("order") or 0)
    for rule in ranked:
        ref = str(rule.get("vendor_ref") or "")
        if _UUID.match(ref):
            return ref
    return None


def _ipproto(op: dict[str, Any]) -> str:
    versions = set()
    for side in ("source", "destination"):
        for cidr in op[side]["cidrs"]:
            versions.add(ipaddress.ip_network(cidr).version)
    if versions == {4}:
        return "inet"
    if versions == {6}:
        return "inet6"
    return "inet46"


def _problems(record: dict[str, Any], ops: list[dict[str, Any]]) -> list[str]:
    problems = management_guard(record, ops)
    known = {item["id"] for item in record.get("interfaces") or []} | {item["id"] for item in record.get("zones") or []}
    self_addrs = record.get("self_addresses") or []
    for op in ops:
        if op["op"] != "allow":
            continue
        for side in ("source", "destination"):
            zone = op[side]["zone"]
            if zone not in known:
                problems.append(f"the device has no interface or group '{zone}'")
        if _covers_self(op["destination"]["cidrs"], self_addrs) and _mgmt_service(op["services"]):
            problems.append("the allow would open a management port toward an address of this firewall")
    return problems


def _covers_self(cidrs: list[str], addresses: list[str]) -> bool:
    for address in addresses:
        ip = ipaddress.ip_address(address)
        for cidr in cidrs:
            network = ipaddress.ip_network(cidr)
            if ip.version == network.version and ip in network:
                return True
    return False


def _mgmt_service(services: list[dict[str, Any]]) -> bool:
    for service in services:
        if service.get("proto") not in {"tcp", "udp"}:
            continue
        for low, high in port_ranges(service.get("ports")):
            if any(low <= port <= high for port in _MGMT_PORTS):
                return True
    return False


def _token(payload: dict[str, Any]) -> str:
    import json
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    if len(raw) > 4096:
        raise ChangeError("the change token is too large", code="failed", state="unknown")
    return raw


def _loads(token: str) -> dict[str, Any]:
    import json
    try:
        payload = json.loads(token)
    except ValueError as exc:
        raise ChangeError("the change token is not valid", code="invalid", state="unknown") from exc
    if not isinstance(payload, dict):
        raise ChangeError("the change token is not valid", code="invalid", state="unknown")
    return payload
