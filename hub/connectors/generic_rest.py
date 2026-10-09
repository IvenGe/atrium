"""Generic REST connector: any JSON API, described by a declarative mapping per domain.

    {
      "assets": {
        "list": {
          "path": "/items",                     # relative to base_url, starts with "/"
          "items": "data.rows",                 # dotted path to the list in the answer; "" = the answer is the list
          "params": {"status": "all"},          # extra query parameters
          "since_param": "updated_since",       # optional: incremental pulls send the last run's time (ISO 8601)
          "pagination": {"type": "none"}
                      | {"type": "offset", "limit_param": "limit", "offset_param": "offset", "page_size": 100,
                         "total": "total"}      # dotted path to the total count (optional)
                      | {"type": "page", "page_param": "page", "size_param": "per_page", "page_size": 100, "start": 1}
                      | {"type": "next", "next": "next"}   # dotted path to the next page's URL; "" = Link header
        },
        "fields": {"external_id": "id", "name": "name", "addresses": ["ip", "fqdn"], "facts": {"serial": "serial"}},
        "defaults": {"type": "server"},
        "create": {"path": "/items", "method": "POST", "body": {"name": "{name}"}, "id": "data.id"},
        "update": {"path": "/items/{external_id}", "method": "PATCH"}
      }
    }

"fields" maps canonical fields (base.py) to dotted paths in a remote item: a string, a list of paths (collected into a
list) or an object (e.g. facts). Body templates: a string that is exactly "{field}" inserts the record's value with
its type, other strings interpolate; dotted record paths work ("{facts.serial}"). Without a body the record is mapped
back through "fields". Every path is relative to base_url: a mapping can never send the credentials to another
scheme, host or port, and pagination links pointing elsewhere are refused.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, AsyncIterator
from urllib.parse import quote, urlsplit

import httpx

from .base import DOMAINS, Connector, ConnectorError, ConnectorField, check, dotted, endpoint_of

AUTH_TYPES = ("bearer", "token", "header", "basic", "none")
PAGINATION = ("none", "offset", "page", "next")
WRITE_METHODS = ("POST", "PUT", "PATCH")
MAX_PAGES = 200
MAX_RECORDS = 10_000
DOTTED_RE = re.compile(r"^[\w\-.@$ ]{0,200}$")
HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
PARAM_RE = re.compile(r"^[\w\-.\[\]]{1,100}$")
PLACEHOLDER = re.compile(r"\{([\w.\-]+)\}")


def _fail(message: str) -> ConnectorError:
    return ConnectorError(f"Invalid mapping: {message}")


def check_path(path: Any, where: str) -> str:
    """A path relative to the API root: starts with one "/", no scheme, host, "..", query, fragment or backslash."""
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise _fail(f"{where} must be a path starting with '/', relative to the base URL")
    if "://" in path or "\\" in path or "?" in path or "#" in path or any(ch.isspace() for ch in path) \
            or ".." in path.split("/") or len(path) > 500:
        raise _fail(f"{where} must be a plain path relative to the base URL (no scheme, host, '..', query or spaces)")
    return path


def _check_dotted(value: Any, where: str) -> None:
    if not isinstance(value, str) or not DOTTED_RE.match(value):
        raise _fail(f"{where} must be a dotted path such as 'data.items'")


def _check_fields(fields: Any, where: str) -> None:
    if not isinstance(fields, dict):
        raise _fail(f"{where} must be an object of canonical field -> remote path")
    for name, path in fields.items():
        if isinstance(path, str):
            _check_dotted(path, f"{where}.{name}")
        elif isinstance(path, list):
            for item in path:
                _check_dotted(item, f"{where}.{name}")
        elif isinstance(path, dict):
            _check_fields(path, f"{where}.{name}")
        else:
            raise _fail(f"{where}.{name} must be a path, a list of paths or an object")


def _int(value: Any, where: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise _fail(f"{where} must be a whole number from {low} to {high}")
    return value


def validate_mapping(mapping: Any) -> dict[str, Any]:
    if isinstance(mapping, str):
        try:
            mapping = json.loads(mapping)
        except ValueError as exc:
            raise _fail(f"not valid JSON ({exc})") from exc
    if not isinstance(mapping, dict) or not mapping:
        raise _fail("expected an object with at least one domain (assets, vulnerabilities, risks, controls)")
    for domain, spec in mapping.items():
        if domain not in DOMAINS:
            raise _fail(f"unknown domain '{domain}' (use {', '.join(DOMAINS)})")
        if not isinstance(spec, dict) or not any(spec.get(k) for k in ("list", "create", "update")):
            raise _fail(f"{domain} needs 'list' (read) and/or 'create' / 'update' (write)")
        _check_fields(spec.get("fields") or {}, f"{domain}.fields")
        if spec.get("defaults") is not None and not isinstance(spec["defaults"], dict):
            raise _fail(f"{domain}.defaults must be an object")
        listing = spec.get("list")
        if listing:
            if not isinstance(listing, dict):
                raise _fail(f"{domain}.list must be an object")
            check_path(listing.get("path"), f"{domain}.list.path")
            _check_dotted(listing.get("items", ""), f"{domain}.list.items")
            if "external_id" not in (spec.get("fields") or {}):
                raise _fail(f"{domain}.fields needs external_id (the remote id of an item)")
            params = listing.get("params") or {}
            if not isinstance(params, dict) or any(not PARAM_RE.match(str(k)) for k in params):
                raise _fail(f"{domain}.list.params must be an object of query parameters")
            if listing.get("since_param") and not PARAM_RE.match(str(listing["since_param"])):
                raise _fail(f"{domain}.list.since_param is not a valid parameter name")
            paging = listing.get("pagination") or {"type": "none"}
            if not isinstance(paging, dict) or paging.get("type", "none") not in PAGINATION:
                raise _fail(f"{domain}.list.pagination.type must be one of {', '.join(PAGINATION)}")
            for key in ("limit_param", "offset_param", "page_param", "size_param"):
                if paging.get(key) is not None and not PARAM_RE.match(str(paging[key])):
                    raise _fail(f"{domain}.list.pagination.{key} is not a valid parameter name")
            if paging.get("page_size") is not None:
                _int(paging["page_size"], f"{domain}.list.pagination.page_size", 1, 1000)
            if paging.get("start") is not None:
                _int(paging["start"], f"{domain}.list.pagination.start", 0, 1)
            for key in ("total", "next"):
                if paging.get(key):
                    _check_dotted(paging[key], f"{domain}.list.pagination.{key}")
        for op in ("create", "update"):
            write = spec.get(op)
            if not write:
                continue
            if not isinstance(write, dict):
                raise _fail(f"{domain}.{op} must be an object")
            check_path(write.get("path"), f"{domain}.{op}.path")
            method = str(write.get("method") or ("POST" if op == "create" else "PATCH")).upper()
            if method not in WRITE_METHODS:
                raise _fail(f"{domain}.{op}.method must be POST, PUT or PATCH")
            write["method"] = method
            if write.get("body") is not None and not isinstance(write["body"], (dict, list)):
                raise _fail(f"{domain}.{op}.body must be a JSON object or array")
            if write.get("id"):
                _check_dotted(write["id"], f"{domain}.{op}.id")
        if spec.get("update") and "{" not in spec["update"]["path"] and not (spec["update"].get("body")):
            raise _fail(f"{domain}.update.path should contain {{external_id}}")
    return mapping


def render(template: Any, record: dict[str, Any]) -> Any:
    if isinstance(template, dict):
        return {k: render(v, record) for k, v in template.items()}
    if isinstance(template, list):
        return [render(v, record) for v in template]
    if isinstance(template, str):
        whole = PLACEHOLDER.fullmatch(template)
        if whole:
            return dotted(record, whole.group(1))
        return PLACEHOLDER.sub(lambda m: "" if dotted(record, m.group(1)) is None else str(dotted(record, m.group(1))), template)
    return template


def _set(target: dict[str, Any], path: str, value: Any) -> None:
    parts = [p for p in path.split(".") if p]
    if not parts or value is None:
        return
    for part in parts[:-1]:
        target = target.setdefault(part, {})
        if not isinstance(target, dict):
            return
    target[parts[-1]] = value


def _extract(item: Any, path: Any) -> Any:
    if isinstance(path, str):
        return dotted(item, path)
    if isinstance(path, list):
        values = []
        for p in path:
            value = dotted(item, p)
            for v in value if isinstance(value, list) else [value]:
                if v not in (None, "") and v not in values:
                    values.append(v)
        return values
    if isinstance(path, dict):
        return {k: _extract(item, p) for k, p in path.items()}
    return None


class GenericRestConnector(Connector):
    kind = "generic_rest"
    title = "Generic REST API"
    description = "Any JSON REST API, described by a mapping per data domain (written by hand or generated by Claude)."
    fields = [
        ConnectorField(name="base_url", label="API base URL", kind="url", required=True,
                       placeholder="https://tool.example.com/api", help="Every mapping path is relative to this URL."),
        ConnectorField(name="auth", label="Authentication", kind="select", default="bearer", choices=[
            {"value": "bearer", "label": "Authorization: Bearer <token>"},
            {"value": "token", "label": "Authorization: Token <token>"},
            {"value": "header", "label": "Custom header"},
            {"value": "basic", "label": "Username and password (basic)"},
            {"value": "none", "label": "None"}]),
        ConnectorField(name="auth_header", label="Header name", kind="text", default="X-API-Key",
                       help="For custom-header authentication."),
        ConnectorField(name="username", label="Username", kind="text", help="For basic authentication."),
        ConnectorField(name="token", label="API token", kind="secret"),
        ConnectorField(name="password", label="Password", kind="secret", help="For basic authentication."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
        ConnectorField(name="mapping", label="Mapping", kind="json", required=True,
                       help="Per domain: list (path, items, pagination), fields, create / update. See the docs."),
    ]
    capabilities = {d: {"read", "write"} for d in DOMAINS}  # narrowed by the mapping, see domains()

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The API base URL must start with http:// or https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put credentials in the secret fields, not in the URL (no user:password@, query or #)")
        auth = config.get("auth") or "bearer"
        if auth not in AUTH_TYPES:
            raise ConnectorError(f"Authentication must be one of {', '.join(AUTH_TYPES)}")
        if auth == "header" and not HEADER_RE.match(str(config.get("auth_header") or "")):
            raise ConnectorError("The header name may contain letters, digits and dashes only")
        return {**config, "base_url": base, "auth": auth, "mapping": validate_mapping(config.get("mapping"))}

    @classmethod
    def detect(cls, tool) -> int:
        m = tool.manifest
        if tool.openapi_url or (m and m.api.spec):
            return 15
        return 10 if m and m.api.type == "rest" else 0

    @property
    def mapping(self) -> dict[str, Any]:
        mapping = self.config.get("mapping") or {}
        return json.loads(mapping) if isinstance(mapping, str) else mapping

    def domains(self) -> dict[str, list[str]]:
        out = {}
        for domain, spec in self.mapping.items():
            ops = (["read"] if spec.get("list") else []) + (["write"] if spec.get("create") or spec.get("update") else [])
            if domain in DOMAINS and ops:
                out[domain] = ops
        return out

    # -- HTTP ----------------------------------------------------------------------

    @property
    def base(self) -> str:
        return str(self.config.get("base_url") or "").rstrip("/")

    def url(self, path: str, record: dict[str, Any] | None = None) -> str:
        path = check_path(path, "path")
        if record is not None:
            path = PLACEHOLDER.sub(lambda m: quote(str(dotted(record, m.group(1)) or ""), safe=""), path)
        return self._same_origin(self.base + path)

    def _same_origin(self, url: str) -> str:
        if endpoint_of(url) != endpoint_of(self.base):
            raise self.error("Refusing to send the credentials to another host than the configured base URL")
        return url

    def client(self) -> httpx.AsyncClient:
        headers = {"Accept": "application/json"}
        auth_type, token = self.config.get("auth") or "bearer", self.secrets.get("token", "")
        auth = None
        if auth_type == "bearer" and token:
            headers["Authorization"] = f"Bearer {token}"
        elif auth_type == "token" and token:
            headers["Authorization"] = f"Token {token}"
        elif auth_type == "header" and token:
            headers[str(self.config.get("auth_header") or "X-API-Key")] = token
        elif auth_type == "basic":
            auth = httpx.BasicAuth(str(self.config.get("username") or ""), self.secrets.get("password", ""))
        return self.http(headers=headers, auth=auth, verify=bool(self.config.get("verify_tls", True)))

    def _spec(self, domain: str, op: str) -> dict[str, Any]:
        spec = self.mapping.get(domain) or {}
        if not spec.get(op):
            raise self.error(f"The mapping has no '{op}' for {domain}")
        return spec

    @staticmethod
    def _items(answer: Any, path: str, where: str) -> list[Any]:
        items = dotted(answer, path)
        if items is None and not path and isinstance(answer, dict):
            items = answer.get("results") or answer.get("items") or answer.get("data")
        if not isinstance(items, list):
            raise ConnectorError(f"{where}: no list at '{path or '(root)'}' in the answer - check list.items",
                                 excerpt=json.dumps(answer, default=str)[:300])
        return items

    async def _pages(self, client: httpx.AsyncClient, listing: dict[str, Any], since: float | None) -> AsyncIterator[list[Any]]:
        paging = listing.get("pagination") or {"type": "none"}
        kind = paging.get("type", "none")
        size = int(paging.get("page_size") or 100)
        params = {str(k): v for k, v in (listing.get("params") or {}).items()}
        if since is not None and listing.get("since_param"):
            params[listing["since_param"]] = datetime.fromtimestamp(since, timezone.utc).isoformat()
        url = self.url(listing["path"])
        where = listing["path"]
        offset, page = 0, int(paging.get("start", 1))
        total = 0
        for _ in range(MAX_PAGES):
            query = dict(params)
            if kind == "offset":
                query[paging.get("limit_param") or "limit"] = size
                query[paging.get("offset_param") or "offset"] = offset
            elif kind == "page":
                query[paging.get("page_param") or "page"] = page
                if paging.get("size_param"):
                    query[paging["size_param"]] = size
            response = await self._get(client, url, query, where)
            items = self._items(response.json(), listing.get("items", ""), where)
            yield items
            total += len(items)
            if not items or total >= MAX_RECORDS or kind == "none":
                return
            if kind == "next":
                nxt = dotted(response.json(), paging["next"]) if paging.get("next") else response.links.get("next", {}).get("url")
                if not nxt:
                    return
                url, params = self._same_origin(str(httpx.URL(url).join(str(nxt)))), {}
                continue
            if len(items) < size:
                return
            if kind == "offset":
                offset += len(items)
                known = dotted(response.json(), paging["total"]) if paging.get("total") else None
                if isinstance(known, (int, float)) and offset >= known:
                    return
            else:
                page += 1

    async def _get(self, client: httpx.AsyncClient, url: str, params: dict[str, Any], where: str) -> httpx.Response:
        try:  # params=None: httpx replaces a URL's own query (a next-page link's) with an empty params dict
            response = await client.get(url, params=params or None)
        except httpx.TimeoutException as exc:
            raise self.error(f"The API did not answer in time ({where})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach the API: {exc.__class__.__name__}: {exc}") from exc
        self.raise_for_status(response, where)
        try:
            response.json()
        except ValueError as exc:
            raise self.error(f"The API did not answer with JSON ({where}) - is the base URL the API root?",
                             status=response.status_code, excerpt=response.text) from exc
        return response

    def to_record(self, spec: dict[str, Any], item: Any) -> dict[str, Any]:
        record = {k: v for k, v in (spec.get("defaults") or {}).items()}
        for name, path in (spec.get("fields") or {}).items():
            value = _extract(item, path)
            if value not in (None, "", []):
                record[name] = value
        return record

    def to_remote(self, spec: dict[str, Any], record: dict[str, Any], op: str) -> Any:
        body = spec[op].get("body")
        if body is not None:
            return render(body, record)
        remote: dict[str, Any] = {}
        for name, path in (spec.get("fields") or {}).items():
            if name in ("external_id", "updated_at", "detected_at"):
                continue
            value = record.get(name)
            if isinstance(path, str):
                _set(remote, path, value)
            elif isinstance(path, list) and isinstance(value, list):
                for p, v in zip(path, value):
                    _set(remote, p, v)
            elif isinstance(path, dict) and isinstance(value, dict):
                for key, p in path.items():
                    if isinstance(p, str):
                        _set(remote, p, value.get(key))
        return remote

    # -- operations ----------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks, domains = [], {}
        async with self.client() as client:
            for domain, spec in self.mapping.items():
                ops = []
                if spec.get("list"):
                    try:
                        listing = {**spec["list"], "pagination": {**(spec["list"].get("pagination") or {}), "type": "none"}}
                        async for items in self._pages(client, listing, None):
                            checks.append(check(f"{domain}: read", True, f"{len(items)} item(s) on the first page"))
                            break
                        ops.append("read")
                    except ConnectorError as exc:
                        checks.append(check(f"{domain}: read", False, exc.message))
                if spec.get("create") or spec.get("update"):
                    checks.append(check(f"{domain}: write", True, "mapped (not exercised by the test)"))
                    ops.append("write")
                if ops:
                    domains[domain] = ops
        ok = bool(checks) and all(c["ok"] for c in checks)
        failed = [c["name"] for c in checks if not c["ok"]]
        return {"ok": ok, "detail": "Connected." if ok else f"Failed: {', '.join(failed) or 'nothing mapped'}",
                "checks": checks, "domains": domains}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        spec = self._spec(domain, "list")
        records: list[dict[str, Any]] = []
        async with self.client() as client:
            async for items in self._pages(client, spec["list"], since):
                records.extend(self.to_record(spec, item) for item in items)
        return records[:MAX_RECORDS]

    async def push(self, domain: str, records: list[dict[str, Any]], links: dict[str, str]) -> list[dict[str, Any]]:
        spec = self.mapping.get(domain) or {}
        if not (spec.get("create") or spec.get("update")):
            raise self.error(f"The mapping has no create or update for {domain}")
        results = []
        async with self.client() as client:
            for record in records:
                hub_id = record.get("hub_id")
                external = links.get(hub_id or "")
                op = "update" if external else "create"
                if not spec.get(op):
                    results.append({"hub_id": hub_id, "external_id": external, "action": "skipped",
                                    "error": f"no {op} in the mapping"})
                    continue
                values = {**record, "external_id": external}
                write = spec[op]
                try:
                    answer = await self.request_json(client, write["method"], self.url(write["path"], values),
                                                     json=self.to_remote(spec, values, op), what=f"{op} {domain}")
                except ConnectorError as exc:
                    if exc.status in (None, 401, 403):  # unreachable or not allowed: every other record fails alike
                        raise
                    results.append({"hub_id": hub_id, "external_id": external, "action": "failed", "error": exc.message})
                    continue
                if op == "create":
                    new_id = dotted(answer, write.get("id") or "id")
                    if new_id in (None, ""):
                        results.append({"hub_id": hub_id, "external_id": None, "action": "failed",
                                        "error": f"created, but the answer has no id at '{write.get('id') or 'id'}' "
                                                 "(set create.id in the mapping)"})
                        continue
                    external = str(new_id)
                results.append({"hub_id": hub_id, "external_id": external, "action": "created" if op == "create" else "updated",
                                "error": None})
        return results
