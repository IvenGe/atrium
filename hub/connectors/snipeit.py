"""Snipe-IT connector (REST API v1): hardware is read into Hub Assets and can be created or updated from them.

Checked against the Snipe-IT sources (grokability/snipe-it: routes/api.php, Api/AssetsController, the API
transformers, the CustomField model) and its API docs, October 2026:

- every call sends "Authorization: Bearer <token>" and "Accept: application/json" (without it Snipe-IT redirects to
  its login page); the API throttles (120 requests a minute by default) with HTTP 429 + Retry-After, honoured here;
- lists answer {"total", "rows"} and page with limit/offset; MAX_RESULTS caps a page (500 by default), so the offset
  advances by the rows actually received. Archived hardware is left out unless the instance shows it in lists (the
  hub then retires it). Snipe-IT cannot filter hardware by change time: every pull reads all hardware and the hub
  skips unchanged records;
- writes and look-ups answer {"status": "success" | "error", "messages", "payload"}; validation errors come as HTTP
  200 with "status": "error" and are surfaced verbatim. Updating a deleted asset answers 404 (older versions: an
  error envelope saying it does not exist) - the record is then created again;
- text in answers is HTML-escaped (Laravel e()), so it is unescaped here;
- there is no built-in IP or hostname field: addresses come from custom fields with an IP format (IP / IPV4 / IPV6)
  or a name such as "IP address", "Hostname", "FQDN" or "DNS name", from the custom field chosen in the settings
  (which pushes write as well), and from primary_ip of newer sync adapters. MACs come from MAC-format fields, fields
  named "MAC ..." and primary_mac.

Assumptions (not verifiable without an instance): GET /api/v1/users/me answers the user object itself (a "payload"
wrapper is accepted too); an older update-of-a-deleted-asset answer is recognised by its English message.
"""

from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

import httpx

from .base import HOSTNAME_RE, Connector, ConnectorError, ConnectorField, check

API = "/api/v1"
PAGE = 500  # Snipe-IT's default MAX_RESULTS
SAMPLE = 50  # assets test() inspects
MAX_RECORDS = 50_000  # more is refused, never truncated: a partial pull would retire the rest
RETRIES = 3
COLUMN_RE = re.compile(r"^_snipeit_[a-z0-9_]{1,200}$")
IP_FORMATS = {"IP", "IPV4", "IPV6"}
ADDRESS_WORDS = {"ip", "ipv4", "ipv6", "ipaddress", "hostname", "hostnames", "fqdn", "dns", "dnsname"}
PLACEHOLDERS = {"none", "n/a", "na", "tbd", "unknown", "null", "dhcp", "encrypted", "-", "?"}
GONE_RE = re.compile(r"does not exist|not found", re.IGNORECASE)
TYPE_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("network", ("switch", "router", "firewall", "access point", "wireless", "wifi", "network", "gateway", "modem",
                 "load balancer")),
    ("server", ("server", "virtual machine", "vm", "hypervisor", "host", "nas", "san", "storage", "appliance")),
    ("workstation", ("laptop", "notebook", "desktop", "workstation", "computer", "pc", "macbook", "imac", "tablet",
                     "thin client", "phone", "smartphone", "mobile")),
    ("cloud", ("cloud",)),
    ("software", ("software", "license", "licence")),
)


def _text(value: Any) -> str | None:
    """Plain text of a Snipe-IT value (HTML-unescaped; {"id", "name"} objects give their name)."""
    if isinstance(value, dict):
        value = value.get("name")
    if value is None or isinstance(value, (dict, list)):
        return None
    text = html.unescape(str(value)).strip()
    return text or None


def _date(value: Any) -> str | None:
    """A {"date" | "datetime", "formatted"} object as its machine-readable value."""
    if isinstance(value, dict):
        value = value.get("date") or value.get("datetime")
    return _text(value)


def _words(label: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", label.lower())


def asset_type(category: str | None) -> str:
    """The hub asset type a Snipe-IT category name suggests ("Laptops" -> workstation), else "other"."""
    words = _words(category or "")
    joined = " ".join(words)
    for kind, keys in TYPE_WORDS:
        for key in keys:
            if (" " in key and key in joined) or any(w in (key, key + "s", key + "es") for w in words):
                return kind
    return "other"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def split_addresses(value: Any) -> list[str]:
    """IPs and hostnames in a field value ("10.0.0.5, web-1.example.com"); URLs give their host, placeholders such
    as "DHCP" or "n/a" and anything else are dropped."""
    out: list[str] = []
    for part in re.split(r"[,;\s]+", _text(value) or ""):
        if "://" in part:
            try:
                part = urlsplit(part).hostname or ""
            except ValueError:
                continue
        if part.count(":") == 1:  # host:port (an IPv6 address has more colons)
            part = part.split(":")[0]
        part = part.strip("[]").lower().rstrip(".")
        if not part or part in PLACEHOLDERS or "/" in part:
            continue
        if not _is_ip(part) and (not HOSTNAME_RE.match(part) or part.replace(".", "").isdigit()):
            continue
        if part not in out:
            out.append(part)
    return out


def split_macs(value: Any) -> list[str]:
    out: list[str] = []
    for part in re.split(r"[,;\s]+", _text(value) or ""):
        digits = re.sub(r"[:\-.]", "", part.lower())
        if re.fullmatch(r"[0-9a-f]{12}", digits) and re.fullmatch(r"[0-9a-fA-F:\-.]+", part):
            mac = ":".join(digits[i:i + 2] for i in range(0, 12, 2))
            if mac not in out:
                out.append(mac)
    return out


def messages(value: Any) -> str:
    """Snipe-IT's "messages": a string, a list or {field: [messages]}, as one line."""
    if isinstance(value, dict):
        return "; ".join(f"{field}: {messages(text)}" for field, text in value.items()) or "no reason given"
    if isinstance(value, list):
        return " ".join(messages(v) for v in value)
    return _text(value) or "no reason given"


class SnipeItConnector(Connector):
    kind = "snipeit"
    title = "Snipe-IT"
    description = "Asset inventory: reads hardware into Hub Assets and can create or update hardware."
    fields = [
        ConnectorField(name="base_url", label="Snipe-IT URL", kind="url", required=True,
                       placeholder="https://snipeit.example.com",
                       help="The address Snipe-IT opens at (a pasted /api/v1 is removed)."),
        ConnectorField(name="token", label="API token", kind="secret", required=True,
                       help="A personal access token (Snipe-IT: your name > Manage API keys) of an account that may "
                            "view hardware - and create and edit it, if the hub should write."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
        ConnectorField(name="address_field", label="Custom field with the IP address or hostname", kind="select",
                       options=True,
                       help="Read into the asset's addresses (vulnerability scans target them) and written when the "
                            "hub pushes assets. Empty: fields with an IP format or named like IP, hostname, FQDN or "
                            "DNS name are read."),
        ConnectorField(name="model_id", label="Model for new hardware", kind="select", options=True,
                       help="Only needed for creating hardware from hub assets."),
        ConnectorField(name="status_id", label="Status label for new hardware", kind="select", options=True,
                       help="Only needed for creating hardware from hub assets."),
        ConnectorField(name="asset_tags", label="Asset tags of new hardware", kind="select", default="hub", choices=[
            {"value": "hub", "label": "The hub asset id"},
            {"value": "auto", "label": "Snipe-IT's auto-increment (turn it on in Snipe-IT's settings)"}]),
    ]
    capabilities = {"assets": {"read", "write"}}
    system_of_record = {"assets"}
    retry_cap: ClassVar[float] = 30.0  # longest wait for a rate limit to clear, per retry

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("snipe-it", "snipeit"), ("assets.inventory",))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The Snipe-IT URL must start with http:// or https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API token in its own field, not in the URL (no user:password@, query or #)")
        out = {**config, "base_url": re.sub(r"(?i)/api(?:/v1)?$", "", base)}
        for key, label in (("model_id", "model"), ("status_id", "status label")):
            value = config.get(key)
            if value is None or (isinstance(value, str) and not value.strip()):
                out.pop(key, None)
                continue
            if isinstance(value, bool) or not str(value).strip().isdigit() or int(str(value).strip()) < 1:
                raise ConnectorError(f"The {label} for new hardware must be a Snipe-IT id - choose it from the list")
            out[key] = int(str(value).strip())
        field = str(config.get("address_field") or "").strip()
        if field and (len(field) > 191 or re.search(r"[<>\"'\\\x00-\x1f]", field)):
            raise ConnectorError("The address custom field must be a field name or column from the list")
        if config.get("asset_tags", "hub") not in ("hub", "auto"):
            raise ConnectorError("Asset tags of new hardware must be 'hub' or 'auto'")
        return out

    # -- HTTP ----------------------------------------------------------------------

    def client(self) -> httpx.AsyncClient:
        token = self.secrets.get("token")
        if not token:
            raise self.error("Enter the Snipe-IT API token in the connection settings")
        return self.http(f"{str(self.config.get('base_url') or '').rstrip('/')}{API}",
                         headers={"Accept": "application/json", "Authorization": f"Bearer {token}"},
                         verify=bool(self.config.get("verify_tls", True)))

    def _wait(self, response: httpx.Response, attempt: int) -> float:
        header = response.headers.get("retry-after", "").strip()
        wait = float(header) if header.isdigit() else 2.0 * (attempt + 1)
        return max(0.0, min(wait, self.retry_cap))

    async def _call(self, client: httpx.AsyncClient, method: str, path: str, *, what: str,
                    params: dict[str, Any] | None = None, body: dict[str, Any] | None = None) -> Any:
        """The JSON answer of one API call; a ConnectorError for every failure, including Snipe-IT's HTTP 200
        {"status": "error"} answers (with their messages verbatim, minus secrets)."""
        response: httpx.Response | None = None
        for attempt in range(RETRIES + 1):
            try:
                response = await client.request(method, path, params=params, json=body)
            except httpx.TimeoutException as exc:
                raise self.error(f"Snipe-IT did not answer in time ({what})") from exc
            except httpx.HTTPError as exc:
                raise self.error(f"Cannot reach Snipe-IT: {exc.__class__.__name__}: {exc}") from exc
            if response.status_code != 429 or attempt == RETRIES:
                break
            await asyncio.sleep(self._wait(response, attempt))
        assert response is not None
        self.raise_for_status(response, what)
        try:
            answer = response.json()
        except ValueError as exc:
            raise self.error(f"Snipe-IT did not answer with JSON ({what}) - is the URL the address Snipe-IT opens at?",
                             status=response.status_code, excerpt=response.text) from exc
        if isinstance(answer, dict) and answer.get("status") == "error":
            raise self.error(f"Snipe-IT could not {what}: {messages(answer.get('messages'))}",
                             status=response.status_code, excerpt=response.text)
        return answer

    async def _list(self, client: httpx.AsyncClient, path: str, params: dict[str, Any], *, what: str,
                    limit: int | None = None, pages: int | None = None) -> tuple[list[dict[str, Any]], int]:
        """Rows of a list endpoint (all of them, or `pages` pages) and the total Snipe-IT reports."""
        limit = limit or PAGE
        rows: list[dict[str, Any]] = []
        offset, fetched = 0, 0
        while True:
            answer = await self._call(client, "GET", path, params={**params, "limit": limit, "offset": offset}, what=what)
            page = answer.get("rows") if isinstance(answer, dict) else None
            if not isinstance(page, list):
                raise self.error(f"Unexpected answer from Snipe-IT ({what}): no 'rows' list",
                                 excerpt=json.dumps(answer, default=str)[:300])
            rows.extend(r for r in page if isinstance(r, dict))
            offset, fetched = offset + len(page), fetched + 1
            try:
                total = int(answer.get("total"))
            except (TypeError, ValueError):  # nothing to page against: complete only when the page was not full
                if len(page) < limit or pages is not None:
                    return rows, len(rows)
                raise self.error(f"Snipe-IT's answer has no total ({what}), so the hub cannot tell whether it read "
                                 "every item") from None
            if len(rows) > MAX_RECORDS:
                raise self.error(f"Snipe-IT lists {total} items ({what}); the hub reads at most {MAX_RECORDS}")
            if not page or offset >= total or (pages is not None and fetched >= pages):
                return rows, total

    # -- records -------------------------------------------------------------------

    def _chosen(self, label: str, entry: dict[str, Any]) -> bool:
        chosen = str(self.config.get("address_field") or "").strip().lower()
        return bool(chosen) and chosen in (label.strip().lower(), str(entry.get("field") or "").lower())

    def _field_kind(self, label: str, entry: dict[str, Any]) -> str | None:
        """"address", "mac" or None for one entry of an asset's custom_fields."""
        if self._chosen(label, entry):
            return "address"
        words = set(_words(label))
        fmt = str(entry.get("field_format") or "").upper()
        if fmt == "MAC" or "mac" in words:
            return "mac"
        if fmt in IP_FORMATS or words & ADDRESS_WORDS or {"host", "name"} <= words:
            return "address"
        return None

    @staticmethod
    def _custom(row: dict[str, Any]) -> dict[str, dict[str, Any]]:
        custom = row.get("custom_fields")
        return {str(k): v for k, v in custom.items() if isinstance(v, dict)} if isinstance(custom, dict) else {}

    def _addresses(self, row: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
        """(addresses, MACs, labels of the fields the addresses came from)."""
        addresses, macs, sources = [], [], []
        for label, entry in self._custom(row).items():
            kind = self._field_kind(label, entry)
            if kind == "address":
                found = split_addresses(entry.get("value"))
                addresses += found
                if found:
                    sources.append(_text(label) or label)
            elif kind == "mac":
                macs += split_macs(entry.get("value"))
        primary = split_addresses(row.get("primary_ip"))
        if primary:
            addresses += primary
            sources.append("primary_ip")
        macs += split_macs(row.get("primary_mac"))
        return list(dict.fromkeys(addresses)), list(dict.fromkeys(macs)), sources

    def to_record(self, row: dict[str, Any]) -> dict[str, Any]:
        """One hardware row as a canonical asset record."""
        addresses, macs, _ = self._addresses(row)
        status = row.get("status") if isinstance(row.get("status"), dict) else row.get("status_label")
        status = status if isinstance(status, dict) else {}
        assigned = row.get("assigned_to") if isinstance(row.get("assigned_to"), dict) else {}
        person = assigned.get("type") == "user"
        model, serial, tag = _text(row.get("model")), _text(row.get("serial")), _text(row.get("asset_tag"))
        state = (_text(status.get("status_type")) or _text(status.get("status_meta")) or "").lower()
        os_name = " ".join(filter(None, (_text(row.get("external_os")), _text(row.get("external_os_version")))))
        facts = {
            "snipeit_id": row.get("id"), "asset_tag": tag, "serial": serial, "model": model,
            "model_number": _text(row.get("model_number")), "manufacturer": _text(row.get("manufacturer")),
            "category": _text(row.get("category")), "company": _text(row.get("company")),
            "location": _text(row.get("location")) or _text(row.get("rtd_location")),
            "status_label": _text(status), "mac": macs[0] if macs else None, "macs": macs if len(macs) > 1 else None,
            "os": os_name or None, "assigned_type": _text(assigned.get("type")), "assigned_name": _text(assigned.get("name")),
            # kept so people can be linked to their devices later (only present when the token may view the user)
            "assigned_username": _text(assigned.get("username")) if person else None,
            "assigned_email": _text(assigned.get("email")) if person else None,
            "assigned_employee_number": _text(assigned.get("employee_number")) if person else None,
            "purchase_date": _date(row.get("purchase_date")), "warranty_expires": _date(row.get("warranty_expires")),
        }
        return {
            "external_id": str(row.get("id")),
            "name": _text(row.get("name")) or tag or " ".join(filter(None, (model, serial))) or f"Snipe-IT asset {row.get('id')}",
            "type": asset_type(_text(row.get("category"))),
            "owner": (_text(assigned.get("name")) or _text(assigned.get("username"))) if person else None,
            "status": "retired" if row.get("deleted_at") else
                      {"archived": "retired", "undeployable": "maintenance", "pending": "maintenance"}.get(state, "active"),
            "addresses": addresses,
            "facts": {k: v for k, v in facts.items() if v not in (None, "", [])},
            "updated_at": row.get("updated_at") if isinstance(row.get("updated_at"), (dict, str, int, float)) else None,
        }

    def _check_domain(self, domain: str, op: str) -> None:
        if domain != "assets":
            raise self.error(f"Snipe-IT cannot {op} {domain} (only assets)")

    # -- operations ----------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        domains: dict[str, list[str]] = {}
        facts: dict[str, Any] = {}
        try:
            client = self.client()
        except ConnectorError as exc:
            return self._result([check("API token", False, exc.message)], domains, facts)
        async with client:
            try:  # reachable, the right product, the token accepted
                answer = await self._call(client, "GET", "/version", what="read its version")
                version = _text(answer.get("version") or answer.get("full_version")) if isinstance(answer, dict) else None
                facts["version"] = version
                checks.append(check("Connection", True, f"Snipe-IT {version}" if version else "Snipe-IT answered"))
            except ConnectorError as exc:
                if exc.status != 404:  # unreachable, TLS, a redirect, not Snipe-IT, the token: nothing else can work
                    name = "API token" if exc.status in (401, 403) else "Connection"
                    return self._result(checks + [check(name, False, exc.message)], domains, facts)
                checks.append(check("Connection", True, "reachable (this Snipe-IT version does not report its version)"))
            try:
                me = await self._call(client, "GET", "/users/me", what="read the signed-in account")
                me = me.get("payload") if isinstance(me, dict) and isinstance(me.get("payload"), dict) else me
                who = (_text(me.get("username")) or _text(me.get("name"))) if isinstance(me, dict) else None
                checks.append(check("API token", True, f"accepted - signed in as {who}" if who else "accepted"))
            except ConnectorError as exc:
                if exc.status not in (403, 404):
                    return self._result(checks + [check("API token", False, exc.message)], domains, facts)
                checks.append(check("API token", True, "accepted (the account cannot view its own profile)"))
            try:
                rows, total = await self._list(client, "/hardware", {"sort": "id", "order": "asc"},
                                               what="list hardware", limit=SAMPLE, pages=1)
                facts["total"] = total
                checks.append(check("Read hardware", True, f"{total} asset(s) visible to this account" if total else
                                    "no hardware visible to this account - check its permissions (and company, "
                                    "with full multiple companies support)"))
                checks.append(self._address_check(rows))
                domains["assets"] = ["read"]
            except ConnectorError as exc:
                checks.append(check("Read hardware", False, exc.message))
            writable = await self._write_check(client, checks)
            if writable:
                domains.setdefault("assets", []).append("write")
        return self._result(checks, domains, facts)

    def _address_check(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if not rows:
            return check("Addresses", True, "no hardware to inspect yet")
        chosen = str(self.config.get("address_field") or "").strip()
        if chosen and not any(self._chosen(label, entry) for row in rows for label, entry in self._custom(row).items()):
            return check("Addresses", False, f"None of the first {len(rows)} assets has the custom field '{chosen}' - "
                                             "choose another field, or add it to the models' fieldsets")
        found = [self._addresses(row) for row in rows]
        with_address = sum(1 for addresses, _, _ in found if addresses)
        sources = sorted({s for _, _, labels in found for s in labels})
        if not with_address:
            return check("Addresses", True, f"None of the first {len(rows)} assets has an IP address or hostname, so "
                                            "vulnerability scans cannot target them: add an IP custom field to the "
                                            "models' fieldsets, or choose the field that holds it")
        macs = sum(1 for _, found_macs, _ in found if found_macs)
        return check("Addresses", True, f"{with_address} of the first {len(rows)} assets have an IP address or "
                                        f"hostname (from {', '.join(sources)}); {macs} have a MAC address")

    async def _write_check(self, client: httpx.AsyncClient, checks: list[dict[str, Any]]) -> bool:
        """Whether the settings let the hub create hardware (updates need no settings); adds its check."""
        model_id, status_id = self.config.get("model_id"), self.config.get("status_id")
        if not model_id or not status_id:
            checks.append(check("Create hardware", True, "not set up - the hub only reads (choose a model and a status "
                                                         "label for new hardware to let it create hardware)"))
            return False
        parts = []
        try:
            model = await self._call(client, "GET", f"/models/{int(model_id)}", what=f"find model {model_id}")
            status = await self._call(client, "GET", f"/statuslabels/{int(status_id)}", what=f"find status label {status_id}")
            if self.config.get("address_field"):
                parts.append(f"addresses go to {await self._address_column(client)}")
        except ConnectorError as exc:
            checks.append(check("Create hardware", False, exc.message))
            return False
        tags = "hub asset ids" if self.config.get("asset_tags", "hub") == "hub" else "Snipe-IT's auto-increment"
        parts.insert(0, f"new hardware gets model '{_text(model) or model_id}' and status '{_text(status) or status_id}', "
                        f"asset tags from {tags}")
        checks.append(check("Create hardware", True, "; ".join(parts) + " (not exercised by the test)"))
        return True

    @staticmethod
    def _result(checks: list[dict[str, Any]], domains: dict[str, list[str]], facts: dict[str, Any]) -> dict[str, Any]:
        failed = [c for c in checks if not c["ok"]]
        if failed:
            detail = f"{failed[0]['name']}: {failed[0]['detail']}"
        else:
            version = f" {facts['version']}" if facts.get("version") else ""
            seen = f", {facts['total']} asset(s)" if "total" in facts else ""
            detail = f"Connected to Snipe-IT{version}{seen}" + ("" if "write" in domains.get("assets", []) else " (read only)")
        return {"ok": bool(checks) and not failed, "detail": detail, "checks": checks, "domains": domains}

    async def options(self, field_name: str) -> list[dict[str, str]]:
        if field_name not in ("model_id", "status_id", "address_field"):
            raise self.error(f"Snipe-IT has no choices for '{field_name}'")
        async with self.client() as client:
            if field_name == "model_id":
                rows, _ = await self._list(client, "/models", {"sort": "name", "order": "asc"}, what="list models")
                return [{"value": str(r["id"]), "label": " - ".join(filter(None, (
                    _text(r.get("name")), _text(r.get("manufacturer")), _text(r.get("model_number"))))) or str(r["id"])}
                        for r in rows if r.get("id") is not None]
            if field_name == "status_id":
                rows, _ = await self._list(client, "/statuslabels", {"sort": "name", "order": "asc"},
                                           what="list status labels")
                return [{"value": str(r["id"]), "label": f"{_text(r.get('name')) or r['id']}"
                                                         + (f" ({_text(r.get('type'))})" if _text(r.get("type")) else "")}
                        for r in rows if r.get("id") is not None]
            rows, _ = await self._list(client, "/fields", {}, what="list custom fields")
            fields = []
            for r in rows:
                column, name = str(r.get("db_column_name") or ""), _text(r.get("name")) or ""
                if COLUMN_RE.match(column):
                    likely = self._field_kind(name, {"field": column, "field_format": r.get("format")}) == "address"
                    fields.append((not likely, name.lower(), {"value": column, "label": f"{name} ({_text(r.get('format')) or 'ANY'})"}))
            return [option for *_, option in sorted(fields, key=lambda f: (f[0], f[1]))]

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        self._check_domain(domain, "read")
        async with self.client() as client:
            rows, _ = await self._list(client, "/hardware", {"sort": "id", "order": "asc"}, what="list hardware")
        return [self.to_record(row) for row in rows if row.get("id") is not None]

    async def push(self, domain: str, records: list[dict[str, Any]], links: dict[str, str]) -> list[dict[str, Any]]:
        self._check_domain(domain, "write")
        results = []
        async with self.client() as client:
            column = await self._address_column(client)
            for record in records:
                hub_id = record.get("hub_id")
                external = str(links.get(hub_id or "") or record.get("external_id") or "") or None
                try:
                    results.append(await self._push_one(client, record, external, column))
                except ConnectorError as exc:
                    if exc.status in (None, 401, 403, 429):  # unreachable, not allowed, throttled: all would fail alike
                        raise
                    results.append({"hub_id": hub_id, "external_id": external, "action": "failed", "error": exc.message})
        return results

    # -- writing -------------------------------------------------------------------

    async def _address_column(self, client: httpx.AsyncClient) -> str | None:
        """The database column of the chosen address field (a field chosen by name is looked up)."""
        chosen = str(self.config.get("address_field") or "").strip()
        if not chosen or COLUMN_RE.match(chosen):
            return chosen or None
        rows, _ = await self._list(client, "/fields", {}, what="list custom fields")
        for row in rows:
            column = str(row.get("db_column_name") or "")
            if (_text(row.get("name")) or "").lower() == chosen.lower() and COLUMN_RE.match(column):
                return column
        raise self.error(f"Snipe-IT has no custom field '{chosen}' - choose the address field from the list")

    @staticmethod
    def _body(record: dict[str, Any], column: str | None) -> dict[str, Any]:
        """Fields the hub owns on a Snipe-IT asset: its name, serial and (with a chosen field) its address."""
        facts = record.get("facts") or {}
        body: dict[str, Any] = {"name": str(record.get("name") or "")[:255]}
        serial = facts.get("serial")
        if isinstance(serial, (str, int)) and not isinstance(serial, bool) and str(serial).strip():
            body["serial"] = str(serial).strip()[:255]
        addresses = [str(a) for a in record.get("addresses") or [] if a]
        if column and addresses:  # an IP field gets an IP, a hostname field a name, when the asset has one
            wants_name = any(word in column for word in ("host", "fqdn", "dns", "name"))
            body[column] = next((a for a in addresses if _is_ip(a) != wants_name), addresses[0])
        return body

    def _asset_tag(self, record: dict[str, Any]) -> str | None:
        tag = (record.get("facts") or {}).get("asset_tag")
        if isinstance(tag, (str, int)) and not isinstance(tag, bool) and str(tag).strip():
            return str(tag).strip()[:255]
        return str(record["hub_id"]) if self.config.get("asset_tags", "hub") == "hub" and record.get("hub_id") else None

    async def _by_tag(self, client: httpx.AsyncClient, tag: str) -> str | None:
        """The id of the asset with this tag, if any (a create whose answer was lost is not repeated)."""
        try:
            answer = await self._call(client, "GET", f"/hardware/bytag/{quote(tag, safe='')}", what="look up an asset tag")
        except ConnectorError as exc:
            if exc.status in (200, 404):  # "Asset does not exist"
                return None
            raise
        if isinstance(answer, dict) and answer.get("id") is not None:
            return str(answer["id"])
        rows = answer.get("rows") if isinstance(answer, dict) else None
        found = [r for r in rows or [] if isinstance(r, dict) and r.get("id") is not None and not r.get("deleted_at")]
        return str(found[0]["id"]) if len(found) == 1 else None

    async def _update(self, client: httpx.AsyncClient, external: str, body: dict[str, Any]) -> bool:
        """False when the asset no longer exists in Snipe-IT."""
        try:
            await self._call(client, "PATCH", f"/hardware/{external}", body=body, what=f"update asset {external}")
        except ConnectorError as exc:
            if exc.status == 404 or (exc.status == 200 and GONE_RE.search(exc.message)):
                return False
            raise
        return True

    async def _push_one(self, client: httpx.AsyncClient, record: dict[str, Any], external: str | None,
                        column: str | None) -> dict[str, Any]:
        hub_id = record.get("hub_id")
        body = self._body(record, column)

        def result(action: str, external_id: str | None, error: str | None = None) -> dict[str, Any]:
            return {"hub_id": hub_id, "external_id": external_id, "action": action, "error": error}

        if external:
            if not external.isdigit():
                return result("failed", external, f"'{external}' is not a Snipe-IT asset id")
            if await self._update(client, external, body):
                return result("updated", external)
            # deleted in Snipe-IT since the last push: created again below
        model_id, status_id = self.config.get("model_id"), self.config.get("status_id")
        if not model_id or not status_id:
            return result("failed", None, "Choose a model and a status label for new hardware in the Snipe-IT "
                                          "connection settings to let the hub create hardware")
        tag = self._asset_tag(record)
        if tag:
            existing = await self._by_tag(client, tag)
            if existing and await self._update(client, existing, body):
                return result("updated", existing)
        created = await self._call(client, "POST", "/hardware", what="create hardware", body={
            **body, "model_id": int(model_id), "status_id": int(status_id), **({"asset_tag": tag} if tag else {}),
            "notes": f"Created by Atrium from hub asset {hub_id}"})
        payload = created.get("payload") if isinstance(created, dict) else None
        new_id = payload.get("id") if isinstance(payload, dict) else None
        if new_id in (None, ""):
            return result("failed", None, "Snipe-IT created the hardware but did not answer with its id")
        return result("created", str(new_id))
