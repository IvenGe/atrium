"""Connector SDK: how the hub reads from and writes to a tool's own API.

A connector is built for one call with the tool's connection: ``config`` (non-secret settings, with field defaults
applied) and ``secrets`` (decrypted by the tool's supervisor, never stored or logged by the connector). Tests pass an
``httpx`` transport (e.g. ``httpx.MockTransport``) so no network is needed; ``self.http()`` honours it.

Domains and canonical records - ``pull`` returns, and ``push`` receives, one dict per item in these shapes (the hub
normalises them with ``normalize``; unknown keys are dropped, timestamps are POSIX seconds or ISO 8601 strings):

``assets``           external_id, name, type (server|workstation|network|software|saas|cloud|data|other), owner,
                     status (active|maintenance|retired), addresses (IPs / hostnames), facts (dict), updated_at
``vulnerabilities``  external_id, title, severity (critical|high|medium|low|info), cvss, cves, host, port,
                     description, solution, detected_at, scanner
``risks``            external_id, title, description, likelihood 1-5, impact 1-5, status (open|in_treatment|closed),
                     treatment
``controls``         external_id (the hub control id), ref_id, name, description, status (pass|partial|fail|manual|na),
                     evidence (list), refs (dict: framework -> reference)

Records the hub pushes carry ``hub_id`` as well; ``links`` maps hub ids to the external ids of records synced before
(create when a hub id has no link, update when it has one; ``external_id`` of a pushed record is that link or None,
except for controls, where it is the hub control id). Records the hub did not change since the last successful push
are not sent again. Pushed records may carry extra keys a connector can use:

``assets``           criticality (low|medium|high|critical)
``vulnerabilities``  status (open|in_progress|accepted|false_positive|fixed), asset (asset name), due_at, first_seen
``controls``         family, detail (the latest check result), evaluated_at; ``evidence`` is a list of strings
                     (check results and evidence items), ``refs`` maps ISO27001 / SOC2 / NIS2 to clause ids

``pull(domain, since)`` gets ``since`` as POSIX seconds (or None for everything); after a scan the hub pulls
``vulnerabilities`` with ``since`` = the scan's start time and treats the answer as that scan's results: a finding of
a scanned host that is missing from it is marked fixed.

Scanners implement the actions ``scan`` (params: ``hosts`` - IPs, CIDRs or hostnames, ``name``) -> {"job_id"} and
``scan_status`` (params: ``job_id``) -> {"status", "progress" 0-100, "done": bool}; ``status`` "failed", "stopped"
or "interrupted" marks the scan failed.

Errors: raise ``ConnectorError`` with a message a person can act on; ``self.error()`` / ``self.raise_for_status()``
build one with the HTTP status and a response excerpt, both with every secret value masked.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

if TYPE_CHECKING:
    from ..models import Tool

Domain = Literal["assets", "vulnerabilities", "risks", "controls"]
DOMAINS: tuple[str, ...] = ("assets", "vulnerabilities", "risks", "controls")
FieldKind = Literal["text", "url", "secret", "select", "number", "bool", "json"]
FAILED_SCAN_STATES = {"failed", "stopped", "interrupted"}
EXCERPT = 500
MASK = "***"
# key=value / "key": "value" pairs whose value is a credential, masked in anything shown to people
SECRET_PAIR = re.compile(r"(?i)((?:authorization|x-api-key|api[_-]?key|access[_-]?token|token|password|passwd|secret)"
                         r"[\"']?\s*[:=]\s*[\"']?(?:bearer\s+|token\s+|basic\s+)?)([^\s\"',;}&]+)")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.(?!-)[A-Za-z0-9-]{1,63})*\.?$")


class ConnectorError(Exception):
    """A failure to show to people: `message` must be safe (no secrets); `status` and `excerpt` describe the
    tool's HTTP answer when there was one."""

    def __init__(self, message: str, *, status: int | None = None, excerpt: str | None = None):
        super().__init__(message)
        self.message = message
        self.status = status
        self.excerpt = excerpt[:EXCERPT] if excerpt else None

    def as_dict(self) -> dict[str, Any]:
        return {"message": self.message, "status": self.status, "excerpt": self.excerpt}


def redact(text: Any, secrets: dict[str, str] | list[str] | None = None) -> str:
    """`text` with every secret value and credential-looking key=value pair masked."""
    out = str(text) if text is not None else ""
    values = secrets.values() if isinstance(secrets, dict) else (secrets or [])
    for value in sorted((v for v in values if isinstance(v, str) and len(v) >= 4), key=len, reverse=True):
        out = out.replace(value, MASK)
    return SECRET_PAIR.sub(lambda m: m.group(1) + MASK, out)


def dotted(obj: Any, path: str | None) -> Any:
    """`obj` at a dotted path ("a.b.0.c"); an empty path is `obj` itself; None when any step is missing."""
    if not path:
        return obj
    current = obj
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.lstrip("-").isdigit():
            index = int(part)
            current = current[index] if -len(current) <= index < len(current) else None
        else:
            return None
        if current is None:
            return None
    return current


def to_timestamp(value: Any) -> float | None:
    """POSIX seconds from a number, an ISO 8601 string or a {"datetime": ...} object (Snipe-IT style)."""
    if value is None or value == "":
        return None
    if isinstance(value, dict):
        value = value.get("datetime") or value.get("date") or value.get("value")
        if value is None:
            return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) / (1000 if value > 1e11 else 1)  # milliseconds
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).timestamp()


def severity_from_score(score: float | None) -> str:
    """CVSS-style score -> severity: critical >= 9, high >= 7, medium >= 4, low > 0, info 0."""
    if score is None:
        return "info"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low" if score > 0 else "info"


def valid_scan_target(value: str) -> bool:
    """An IP address, a CIDR network or a hostname - nothing that could smuggle options or markup."""
    value = value.strip()
    if not value or len(value) > 253:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(value))


# --------------------------------------------------------------------------------------
# canonical records
# --------------------------------------------------------------------------------------


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):  # {"name": ...} / {"value": ...} objects as returned by many APIs
        value = value.get("name") or value.get("username") or value.get("value") or value.get("label")
        if value is None:
            return None
    text = str(value).strip()
    return text or None


def _strings(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    items = value if isinstance(value, (list, tuple, set)) else re.split(r"[,\s]+", str(value))
    out: list[str] = []
    for item in items:
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return out


class _Record(BaseModel):
    model_config = ConfigDict(extra="ignore")
    external_id: str
    hub_id: str | None = None

    @field_validator("external_id", mode="before")
    @classmethod
    def _external_id(cls, value: Any) -> str:
        text = _text(value)
        if not text:
            raise ValueError("external_id is required")
        return text[:500]


ASSET_TYPES = ("server", "workstation", "network", "software", "saas", "cloud", "data", "other")


class AssetRecord(_Record):
    name: str
    type: str = "other"
    owner: str | None = None
    status: str = "active"
    addresses: list[str] = []
    facts: dict[str, Any] = {}
    updated_at: float | None = None

    @field_validator("name", mode="before")
    @classmethod
    def _name(cls, value: Any) -> str:
        return (_text(value) or "unnamed")[:200]

    @field_validator("type", mode="before")
    @classmethod
    def _type(cls, value: Any) -> str:
        text = (_text(value) or "other").lower()
        return text if text in ASSET_TYPES else "other"

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value: Any) -> str:
        text = (_text(value) or "active").lower()
        return text if text in ("active", "maintenance", "retired") else "active"

    @field_validator("owner", mode="before")
    @classmethod
    def _owner(cls, value: Any) -> str | None:
        return _text(value)

    _addresses = field_validator("addresses", mode="before")(lambda cls, v: _strings(v))
    _updated = field_validator("updated_at", mode="before")(lambda cls, v: to_timestamp(v))

    @field_validator("facts", mode="before")
    @classmethod
    def _facts(cls, value: Any) -> dict[str, Any]:
        return {str(k): v for k, v in value.items() if v not in (None, "", [], {})} if isinstance(value, dict) else {}


SEVERITIES = ("critical", "high", "medium", "low", "info")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class VulnerabilityRecord(_Record):
    title: str
    severity: str = ""
    cvss: float | None = None
    cves: list[str] = []
    host: str | None = None
    port: str | None = None
    description: str = ""
    solution: str = ""
    detected_at: float | None = None
    scanner: str | None = None

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, value: Any) -> str:
        return (_text(value) or "Untitled finding")[:300]

    @field_validator("cvss", mode="before")
    @classmethod
    def _cvss(cls, value: Any) -> float | None:
        try:
            return max(0.0, min(10.0, float(value))) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    @field_validator("cves", mode="before")
    @classmethod
    def _cves(cls, value: Any) -> list[str]:
        return sorted({m.upper() for item in _strings(value) for m in CVE_RE.findall(item)})

    @field_validator("host", "port", "scanner", mode="before")
    @classmethod
    def _short(cls, value: Any) -> str | None:
        text = _text(value)
        return text[:255] if text else None

    @field_validator("description", "solution", mode="before")
    @classmethod
    def _long(cls, value: Any) -> str:
        return (_text(value) or "")[:20000]

    _detected = field_validator("detected_at", mode="before")(lambda cls, v: to_timestamp(v))

    def model_post_init(self, _context: Any) -> None:
        severity = (self.severity or "").strip().lower()
        severity = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low",
                    "info": "info", "informational": "info", "log": "info", "none": "info"}.get(severity, "")
        self.severity = severity or severity_from_score(self.cvss)


class RiskRecord(_Record):
    title: str
    description: str = ""
    likelihood: int = 3
    impact: int = 3
    status: str = "open"
    treatment: str | None = None

    @field_validator("title", mode="before")
    @classmethod
    def _title(cls, value: Any) -> str:
        return (_text(value) or "Untitled risk")[:300]

    @field_validator("description", mode="before")
    @classmethod
    def _description(cls, value: Any) -> str:
        return (_text(value) or "")[:20000]

    @field_validator("likelihood", "impact", mode="before")
    @classmethod
    def _scale(cls, value: Any) -> int:
        try:
            return max(1, min(5, round(float(value))))
        except (TypeError, ValueError):
            return 3

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value: Any) -> str:
        text = (_text(value) or "open").lower().replace(" ", "_").replace("-", "_")
        return text if text in ("open", "in_treatment", "closed") else "open"

    @field_validator("treatment", mode="before")
    @classmethod
    def _treatment(cls, value: Any) -> str | None:
        return _text(value)


class ControlRecord(_Record):
    ref_id: str
    name: str
    description: str = ""
    status: Literal["pass", "partial", "fail", "manual", "na"] = "manual"
    evidence: list[Any] = []
    refs: dict[str, str] = {}


RECORD_MODELS: dict[str, type[_Record]] = {
    "assets": AssetRecord, "vulnerabilities": VulnerabilityRecord, "risks": RiskRecord, "controls": ControlRecord,
}


def normalize(domain: str, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Canonical records of `domain`, plus one message per record that had to be dropped."""
    model = RECORD_MODELS.get(domain)
    if model is None:
        raise ConnectorError(f"Unknown data domain '{domain}'")
    valid: list[dict[str, Any]] = []
    errors: list[str] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            errors.append(f"record {index}: not an object")
            continue
        try:
            valid.append(model.model_validate(record).model_dump(mode="json", exclude_none=False))
        except ValidationError as exc:
            problem = "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:3])
            errors.append(f"record {record.get('external_id', index)}: {problem}")
    return valid, errors


# --------------------------------------------------------------------------------------
# connectors
# --------------------------------------------------------------------------------------


class ConnectorField(BaseModel):
    """One connection setting, rendered as a form field. Secrets are encrypted at rest and never shown again."""

    name: str
    label: str
    kind: FieldKind = "text"
    required: bool = False
    default: Any = None
    help: str = ""
    placeholder: str = ""
    options: bool = False  # the choices come from Connector.options(name) - the tool's own data
    choices: list[dict[str, str]] = []  # fixed choices of a "select": [{"value", "label"}]


def check(name: str, ok: bool, detail: str = "") -> dict[str, Any]:
    """One line of a test() result."""
    return {"name": name, "ok": ok, "detail": detail}


def endpoint_of(value: Any) -> str:
    """scheme://host:port of a URL (what decides where a secret is sent), else the value itself."""
    text = str(value or "").strip()
    try:
        parts = urlsplit(text)
    except ValueError:
        return text.lower()
    if parts.scheme and parts.hostname:
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme.lower())
        return f"{parts.scheme.lower()}://{parts.hostname.lower()}:{port}"
    return text.lower()


ENDPOINT_FIELDS = ("host", "hostname", "port", "server", "address", "socket", "socket_path", "connection_type",
                   "transport", "ca_file")


class Connector:
    """Base class of every connector. Subclasses set the class attributes and implement what they support."""

    kind: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    fields: ClassVar[list[ConnectorField]] = []
    capabilities: ClassVar[dict[str, set[str]]] = {}  # domain -> {"read", "write"}
    actions: ClassVar[set[str]] = set()  # e.g. {"scan", "scan_status"}
    system_of_record: ClassVar[set[str]] = set()  # domains this product is authoritative for (never pushed to)
    timeout: ClassVar[float] = 30.0

    def __init__(self, config: dict[str, Any], secrets: dict[str, str], transport: httpx.AsyncBaseTransport | None = None):
        self.config = {**self.defaults(), **{k: v for k, v in (config or {}).items() if v is not None}}
        self.secrets = {k: v for k, v in (secrets or {}).items() if v}
        self.transport = transport

    # -- description ---------------------------------------------------------------

    @classmethod
    def defaults(cls) -> dict[str, Any]:
        return {f.name: f.default for f in cls.fields if f.kind != "secret" and f.default is not None}

    @classmethod
    def describe(cls) -> dict[str, Any]:
        return {
            "kind": cls.kind, "title": cls.title, "description": cls.description,
            "fields": [f.model_dump(mode="json") for f in cls.fields],
            "capabilities": {d: sorted(ops) for d, ops in cls.capabilities.items()},
            "actions": sorted(cls.actions), "system_of_record": sorted(cls.system_of_record),
        }

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        """Connector-specific validation of non-secret settings; return the (normalised) config or raise
        ConnectorError / ValueError with a message for the person saving the connection."""
        return config

    @classmethod
    def endpoint(cls, config: dict[str, Any]) -> str:
        """Where this connection sends its secrets. Stored secrets are only reused while this stays the same, so a
        changed server address needs the secrets entered again (and repairs can never redirect them)."""
        keys = [f.name for f in cls.fields if f.kind == "url" or f.name in ENDPOINT_FIELDS]
        return "|".join(f"{k}={endpoint_of(config.get(k))}" for k in sorted(keys))

    @classmethod
    def detect(cls, tool: "Tool") -> int:
        """0..100: how likely this connector fits `tool`."""
        return 0

    def domains(self) -> dict[str, list[str]]:
        """Domains and operations this connection supports (a connector may narrow them by its config)."""
        return {d: sorted(ops) for d, ops in self.capabilities.items() if ops}

    # -- operations ----------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        """{"ok", "detail", "checks": [{"name", "ok", "detail"}], "domains": {domain: [ops]}}"""
        raise ConnectorError(f"{self.title or self.kind}: test is not implemented")

    async def options(self, field_name: str) -> list[dict[str, str]]:
        raise ConnectorError(f"{self.title or self.kind} has no choices for '{field_name}'")

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        raise ConnectorError(f"{self.title or self.kind} cannot read {domain}")

    async def push(self, domain: str, records: list[dict[str, Any]], links: dict[str, str]) -> list[dict[str, Any]]:
        """One result per record: {"hub_id", "external_id", "action": created|updated|skipped|failed, "error"}"""
        raise ConnectorError(f"{self.title or self.kind} cannot write {domain}")

    async def action(self, name: str, params: dict[str, Any]) -> dict[str, Any]:
        raise ConnectorError(f"{self.title or self.kind} has no action '{name}'")

    # -- helpers for subclasses ----------------------------------------------------

    def redact(self, text: Any) -> str:
        return redact(text, self.secrets)

    def error(self, message: str, *, status: int | None = None, excerpt: str | None = None) -> ConnectorError:
        return ConnectorError(self.redact(message), status=status, excerpt=self.redact(excerpt)[:EXCERPT] if excerpt else None)

    def http(self, base_url: str = "", *, headers: dict[str, str] | None = None, auth: httpx.Auth | None = None,
             verify: bool | str = True, timeout: float | None = None) -> httpx.AsyncClient:
        """An HTTP client for the tool's API. Redirects are not followed (they could carry credentials elsewhere)."""
        kwargs: dict[str, Any] = {"base_url": base_url, "headers": headers or {}, "auth": auth,
                                  "timeout": timeout or self.timeout, "follow_redirects": False}
        if self.transport is not None:
            kwargs["transport"] = self.transport
        else:
            kwargs["verify"] = verify
        return httpx.AsyncClient(**kwargs)

    def raise_for_status(self, response: httpx.Response, what: str = "") -> None:
        """ConnectorError for a 3xx/4xx/5xx answer, with the tool's own (validation) message kept verbatim."""
        code = response.status_code
        if code < 300:
            return
        name = self.title or self.kind
        where = f" ({what})" if what else ""
        excerpt = response.text[:EXCERPT]
        if code in (301, 302, 303, 307, 308):
            message = f"{name} redirected to {response.headers.get('location', 'another address')}{where} - check the URL"
        elif code == 401:
            message = f"{name} rejected the credentials (HTTP 401){where} - check the API token"
        elif code == 403:
            message = f"{name} refused access (HTTP 403){where} - the account lacks permission"
        elif code == 404:
            message = f"{name} answered 404 Not Found{where} - check the URL and API path"
        elif code in (400, 409, 422):
            message = f"{name} rejected the request (HTTP {code}){where}: {excerpt[:300]}"
        elif code == 429:
            message = f"{name} is rate limiting (HTTP 429){where} - try again later"
        else:
            message = f"{name} answered HTTP {code}{where}"
        raise self.error(message, status=code, excerpt=excerpt)

    async def request_json(self, client: httpx.AsyncClient, method: str, url: str, *, what: str = "",
                           **kwargs: Any) -> Any:
        """Send a request and return its JSON body, turning every failure into a ConnectorError."""
        name = self.title or self.kind
        try:
            response = await client.request(method, url, **kwargs)
        except httpx.TimeoutException as exc:
            raise self.error(f"{name} did not answer in time ({what or url})") from exc
        except httpx.HTTPError as exc:
            raise self.error(f"Cannot reach {name}: {exc.__class__.__name__}: {exc}") from exc
        self.raise_for_status(response, what)
        if response.status_code == 204 or not response.content:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise self.error(f"{name} did not answer with JSON ({what or url}) - is the URL the API root?",
                             status=response.status_code, excerpt=response.text) from exc

    @staticmethod
    def name_score(tool: "Tool", names: tuple[str, ...], capabilities: tuple[str, ...] = (), score: int = 90) -> int:
        """A detect() helper: `score` when the tool's id, name, source or manifest name contains one of `names`,
        else 30 when its manifest provides one of `capabilities`, else 0."""
        manifest = tool.manifest
        haystack = " ".join([tool.id, tool.name, tool.source or "", manifest.name if manifest else ""]).lower()
        squashed = re.sub(r"[^a-z0-9]", "", haystack)
        if any(n.lower() in haystack or re.sub(r"[^a-z0-9]", "", n.lower()) in squashed for n in names):
            return score
        if manifest and any(c in manifest.provides for c in capabilities):
            return 30
        return 0
