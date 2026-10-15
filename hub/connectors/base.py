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
``people``           external_id, display_name, email, login, title, department, manager_external_id (the manager's
                     external_id in the same tool), status (active|suspended|terminated), groups (names), location,
                     phone - a directory's (Okta, Keycloak, SCIM, HR) people; the hub merges them into persons by
                     email, then login
``accounts``         external_id, login, email, display_name, active (bool), last_login, app (the application, for a
                     directory that lists app assignments) - user accounts in a tool; linked to persons by email/login
``network``          read only: ONE record describing the device the connection reaches - firewall, router, switch or
                     host firewall (device facts, interfaces, zones, aliases, rules, default policy). The shape, its
                     validation and the helpers are in ``netmodel.py``; text in it is untrusted device text
``frameworks``       read only: one record per compliance framework a GRC tool has loaded, with its requirement tree,
                     the tool's assessments of it (results and scores per requirement) and its mapping sets. The shape
                     and its validation are in ``grcmodel.py``; requirement text in it is the tool's (untrusted) text
``assessments``      write only: the hub's framework self-assessments (CyFun), one record per assessment with the
                     result and both maturity scores per requirement (shape in ``grcmodel.py``)
``x:<key>``          a data type an enabled extension pack adds (hub/extensions, e.g. ``x:alerts``): external_id plus
                     the domain's fields by name (scalars or lists of scalars); the hub types them against the
                     domain's field definitions

An asset record's ``facts`` may carry ``assigned_email`` / ``assigned_username`` (the user the device is checked out
to): the hub links the asset to that person (``assigned_person_id``).

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

Actions that change something (start a scan, ...) are listed in ``side_effect_actions`` with the approval kind that
governs them (``{"scan": "scan"}``). The tool's supervisor runs such an action only for a person, or for the agent
that owns that approval path (``tool_supervisor.ACTION_ROUTES``: kind "scan" -> ``module:vulns``, which applies the
scan approval policy) - never for team agents or other modules, so none of them can bypass that approval. Actions not listed there must be
read-only (``scan_status``).

Errors: raise ``ConnectorError`` with a message a person can act on; ``self.error()`` / ``self.raise_for_status()``
build one with the HTTP status and a response excerpt, both with every secret value masked.

Network devices (firewalls, routers, switches, host firewalls) - the device connector contract
---------------------------------------------------------------------------------------------
The record shape, the change operations, their validation and the shared helpers are in ``netmodel.py`` (read its
docstring first); ``fake_firewall.py`` implements the whole contract and is the reference. One connection = one device.

Reading: declare ``capabilities = {"network": {"read"}}`` and return ``[record]`` from ``pull("network")``.
``detect(tool)`` scores the product as usual (``name_score``). ``test()`` must be useful to a person checking a real
device: one check per step, named as in ``netmodel.TEST_CHECKS`` - ``reachability``, ``tls`` (certificate verified, or
the configured CA file), ``authentication``, ``privileges`` (the role found; when the credential can WRITE say
``netmodel.LEAST_PRIVILEGE_NOTE``), ``version`` (product and version, and whether this connector supports it),
``api_features`` (what it relies on: savepoints, transactions, confirmed commit, ...) - then vendor checks. ``ok`` is
true when the device can be read. ``test()`` may add ``"network_write": {...} | None``: what this device and
credential actually allow. It can only NARROW ``write_capability()`` (fewer ops; None for a read-only key or a
version without a safe rollback mechanism); the hub keeps it with the test result (``integration.network``).

Writing (only where the product has a safe mechanism): declare the class attribute
``network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": <mode>, "window_s": <seconds>}``
(``window_s`` 10-3600) and implement the six methods below; ``write_capability()`` narrows it by the connection's
settings (e.g. a "read only" setting -> None) and returns None unless every method but ``restore_backup`` is
implemented. Rollback modes (``netmodel.ROLLBACK_MODES``): ``savepoint`` (the device reverts by itself unless
confirmed within window_s), ``commit_confirm`` (a confirmed commit that reverts by itself), ``deadman`` (a revert job
the connector arms on the device before writing and disarms on confirm), ``backup_restore`` (no device-side timer:
rollback_change undoes the change with ``netmodel.inverse_ops`` or by restoring the backup), ``none`` (not
writable). These methods are NEVER connector actions: a class whose ``actions`` names one of them (or another name in
``netmodel.RESERVED_ACTIONS``) is refused when it is defined, and ``connector.action`` refuses them, so they are only
reached through the hub's change path. Generated / generic connectors are never write-capable. Every call opens its
own connection: the hub builds a NEW connector instance per call (so verification runs over a new connection, and a
token must work in a new instance - even after a hub restart).

How the hub drives a change (``module:network``; the connector never decides any of it):
1. proposal: a fresh ``pull("network")``, then ``preview_change(ops, snapshot)``; ``problems`` refuse the change.
2. after the approval (bound to the snapshot revision and ``netmodel.ops_hash(ops)``): ``backup()`` - stored
   encrypted by the hub - unless the backup guardrail is off; a failed backup refuses the apply while it is on.
3. ``apply_change(ops, base_revision, backup)``.
4. verification through new instances: ``test()`` ok and a re-read where ``netmodel.ops_applied`` finds no problem.
5. ``confirm_change(token)`` within the window; otherwise ``rollback_change(token, backup)``, a re-read must pass
   ``netmodel.ops_reverted``, else the hub calls ``restore_backup(pre-change backup)`` and alerts.
6. an approved "restore" change: ``restore_backup(backup)``.

``backup()`` -> ``{"content": bytes | str (the full configuration), "format": "xml" | "json" | "text" | ...,
    "device_backup_id": the device's own reference or None, "revision": the config revision it holds or None,
    "sha256": optional hex digest of content (verified when given)}``. The hub encrypts the content
    (``hub/secrets.py``), stores it in ``device_backups`` with its SHA-256, size and revision, returns only metadata
    ``{id, taken_at, size, sha256, ...}`` and hands the content back only as ``netmodel.Backup`` (and to an admin
    download). Never log it, return it elsewhere or put it in an error.
``preview_change(ops, snapshot)`` -> ``{"steps": [{"op": index, "kind": "add_rule" | "disable_rule" | "enable_rule",
    "position": "top of LAN rules", "detail": "..."}], "notes": [...], "problems": [...]}``. No side effects (it may
    read the device). ``ops`` are ``netmodel.parse_ops`` canonical dicts, ``snapshot`` the hub's current normalised
    record; ``problems`` (``netmodel.management_guard``, a zone the device does not have, ...) refuse the change.
``apply_change(ops, base_revision, backup)`` -> ``{"token": str (opaque, JSON-safe, no secrets, <= 4096 chars),
    "rollback_until": epoch seconds when the device reverts by itself (None for backup_restore), "revision": the new
    revision or None, "created": [{"op": index, "id", "vendor_ref"}] (the rule each allow made, as the next pull will
    report it), "disabled": [vendor_ref, ...], "enabled": [vendor_ref, ...], "notes": [...]}``. It must: re-read and
    compare the revision with ``base_revision`` (``ChangeError(code="stale", state="unchanged")`` on a mismatch), run
    the management-path guard (``code="lockout"``), arm the rollback mechanism BEFORE writing, write exactly the ops
    (one rule per allow, its description/comment starting with ``op["marker"]``), and apply. ``backup`` is the hub's
    pre-change backup (``netmodel.Backup``, or None when the backup guardrail is off) - backup_restore needs it.
``confirm_change(token)`` -> ``{"confirmed": True, "revision": ..., "notes": [...]}``: cancel the timer / confirm the
    commit / persist (only now, where the product separates running and persisted config).
``rollback_change(token, backup)`` -> ``{"rolled_back": True, "method": "savepoint" | "commit_confirm" | "deadman" |
    "inverse_ops" | "backup_restore", "notes": [...]}``: undo now. The hub re-reads the device to prove it.
``restore_backup(backup)`` -> ``{"restored": True, "revision": ..., "notes": [...]}``: put an Atrium-managed backup
    back (only for an approved "restore" change, or after a failed rollback - the hub never restores on its own). A
    restore change is a write: the hub proposes and runs one only while the connection's write capability (narrowed
    by its settings and last test) is not None; recovering a change's own pre-change backup is not refused.

Failures raise ``netmodel.ChangeError(message, code=..., state=...)``: ``code`` stale | lockout | unsupported |
invalid | unreachable | failed; ``state`` what the device holds now - unchanged, rolled_back, applied or unknown
(the hub then restores its own backup and alerts). Messages must not quote device text or secrets.

SSH-based connectors (host firewalls, CLI-only devices) use ``netmodel.SSH_FIELDS`` / ``validate_ssh_config`` /
``ssh_target`` and ``self.ssh(target)`` - one connection per session, stdout / stderr / exit status kept apart,
scripts on stdin, no silent truncation, strict host keys (see ``execution/runner.py``); tests pass a fake SSH
transport (``execution/sshfake.FakeSshTransport``) as the connector's ``transport`` (or ``hub.connector_transport``).
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

Domain = Literal["assets", "vulnerabilities", "risks", "controls", "people", "accounts", "network", "frameworks",
                 "assessments"]
DOMAINS: tuple[str, ...] = ("assets", "vulnerabilities", "risks", "controls", "people", "accounts", "network",
                            "frameworks", "assessments")
WRITE_METHODS = ("backup", "preview_change", "apply_change", "confirm_change", "rollback_change", "restore_backup")
EXTENSION_DOMAIN = re.compile(r"^x:[a-z][a-z0-9_]{1,31}$")  # a data type an extension pack adds, e.g. "x:alerts"
FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
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


PERSON_STATES = {
    "active": "active", "enabled": "active", "true": "active", "provisioned": "active", "staged": "active",
    "recovery": "active", "password_expired": "active", "locked_out": "active",
    "suspended": "suspended", "locked": "suspended", "disabled": "suspended", "inactive": "suspended", "false": "suspended",
    "terminated": "terminated", "deprovisioned": "terminated", "deleted": "terminated", "deactivated": "terminated",
    "left": "terminated", "leaver": "terminated",
}


def _email(value: Any) -> str | None:
    text = _text(value)
    if not text or "@" not in text or any(c.isspace() for c in text) or len(text) > 254:
        return None
    return text.lower()


class PersonRecord(_Record):
    display_name: str
    email: str | None = None
    login: str | None = None
    title: str | None = None
    department: str | None = None
    manager_external_id: str | None = None
    status: str = "active"
    groups: list[str] = []
    location: str | None = None
    phone: str | None = None

    @field_validator("display_name", mode="before")
    @classmethod
    def _name(cls, value: Any) -> str:
        return (_text(value) or "Unnamed")[:200]

    _email = field_validator("email", mode="before")(lambda cls, v: _email(v))

    @field_validator("login", "title", "department", "manager_external_id", "location", "phone", mode="before")
    @classmethod
    def _short(cls, value: Any) -> str | None:
        text = _text(value)
        return text[:200] if text else None

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value: Any) -> str:
        if isinstance(value, bool):
            return "active" if value else "suspended"
        text = (_text(value) or "active").lower().replace(" ", "_").replace("-", "_")
        return PERSON_STATES.get(text, "active")

    @field_validator("groups", mode="before")
    @classmethod
    def _groups(cls, value: Any) -> list[str]:
        items = value if isinstance(value, (list, tuple, set)) else [value] if value else []
        return list(dict.fromkeys(t[:200] for t in (_text(i) for i in items) if t))[:500]


class AccountRecord(_Record):
    login: str | None = None
    email: str | None = None
    display_name: str | None = None
    active: bool = True
    last_login: float | None = None
    app: str | None = None

    _email = field_validator("email", mode="before")(lambda cls, v: _email(v))
    _last = field_validator("last_login", mode="before")(lambda cls, v: to_timestamp(v))

    @field_validator("login", "display_name", "app", mode="before")
    @classmethod
    def _short(cls, value: Any) -> str | None:
        text = _text(value)
        return text[:200] if text else None

    @field_validator("active", mode="before")
    @classmethod
    def _active(cls, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if value is None or value == "":
            return True
        return PERSON_STATES.get(str(value).strip().lower(), "active") == "active" and str(value).strip() not in ("0",)


RECORD_MODELS: dict[str, type[_Record]] = {
    "assets": AssetRecord, "vulnerabilities": VulnerabilityRecord, "risks": RiskRecord, "controls": ControlRecord,
    "people": PersonRecord, "accounts": AccountRecord,
}
EXT_FIELDS = 60
EXT_TEXT = 4000


def is_domain(name: str) -> bool:
    """A built-in domain or an extension domain ("x:<key>")."""
    return name in DOMAINS or bool(EXTENSION_DOMAIN.match(name or ""))


def _ext_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, dict):  # {"name": ...} objects collapse to their name, like the canonical records
        return _text(value)
    if isinstance(value, (list, tuple)):
        return [v for v in (_ext_value(x) for x in list(value)[:50]) if v is not None and not isinstance(v, list)]
    return str(value)[:EXT_TEXT]


def extension_record(record: dict[str, Any]) -> dict[str, Any]:
    """An extension domain's record: external_id plus flat values (scalars or lists of scalars) under field-like
    names. The hub types them against the domain's field definitions when it stores them."""
    external_id = _text(record.get("external_id"))
    if not external_id:
        raise ValueError("external_id is required")
    out: dict[str, Any] = {"external_id": external_id[:500]}
    if record.get("hub_id") is not None:
        out["hub_id"] = str(record["hub_id"])
    for name, value in record.items():
        if name in ("external_id", "hub_id") or not FIELD_NAME.match(str(name)) or len(out) > EXT_FIELDS:
            continue
        out[name] = _ext_value(value)
    return out


def normalize(domain: str, records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    """Canonical records of `domain`, plus one message per record that had to be dropped."""
    if EXTENSION_DOMAIN.match(domain or ""):
        valid, errors = [], []
        for index, record in enumerate(records):
            try:
                if not isinstance(record, dict):
                    raise ValueError("not an object")
                valid.append(extension_record(record))
            except ValueError as exc:
                errors.append(f"record {record.get('external_id', index) if isinstance(record, dict) else index}: {exc}")
        return valid, errors
    if domain == "frameworks":
        from .grcmodel import normalize_frameworks

        return normalize_frameworks(records)
    if domain == "network":
        from .netmodel import normalize_record

        valid, errors = [], []
        for index, record in enumerate(records[:1]):  # one device per connection
            try:
                valid.append(normalize_record(record))
            except ValueError as exc:
                errors.append(f"record {index}: {exc}")
        if len(records) > 1:
            errors.append(f"the connection returned {len(records)} device records; only the first is used "
                          "(one connection per device)")
        return valid, errors
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


# Settings that decide who receives a connection's secrets: changing one needs the secrets entered again. An SSH
# connection's pinned host key and known_hosts file are among them (review F22): with another key the password
# would go to whichever host presents it.
ENDPOINT_FIELDS = ("host", "hostname", "port", "server", "address", "socket", "socket_path", "connection_type",
                   "transport", "ca_file", "host_key", "known_hosts")


class Connector:
    """Base class of every connector. Subclasses set the class attributes and implement what they support."""

    kind: ClassVar[str] = ""
    title: ClassVar[str] = ""
    description: ClassVar[str] = ""
    fields: ClassVar[list[ConnectorField]] = []
    capabilities: ClassVar[dict[str, set[str]]] = {}  # domain -> {"read", "write"}
    actions: ClassVar[set[str]] = set()  # e.g. {"scan", "scan_status"}
    # actions that change something -> the approval kind whose path alone may run them (see the module docstring)
    side_effect_actions: ClassVar[dict[str, str]] = {}
    system_of_record: ClassVar[set[str]] = set()  # domains this product is authoritative for (never pushed to)
    timeout: ClassVar[float] = 30.0
    # device changes (see the module docstring): {"ops": [...], "rollback": mode, "window_s": seconds}; None = read-only
    network_write: ClassVar[dict[str, Any] | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        from .netmodel import RESERVED_ACTIONS, validate_write_spec

        reserved = sorted(set(cls.actions) & RESERVED_ACTIONS)
        if reserved:
            raise TypeError(f"{cls.__name__}: {', '.join(reserved)} cannot be connector actions - device changes go "
                            "through the network change path only")
        validate_write_spec(cls.network_write)  # a bad declaration fails at import, not during a change
        unknown = sorted(set(cls.side_effect_actions) - set(cls.actions))
        if unknown:
            raise TypeError(f"{cls.__name__}: side_effect_actions names unknown actions: {', '.join(unknown)}")

    def __init__(self, config: dict[str, Any], secrets: dict[str, str], transport: Any = None):
        self.config = {**self.defaults(), **{k: v for k, v in (config or {}).items() if v is not None}}
        self.secrets = {k: v for k, v in (secrets or {}).items() if v}
        self.transport = transport

    # -- description ---------------------------------------------------------------

    @classmethod
    def defaults(cls) -> dict[str, Any]:
        return {f.name: f.default for f in cls.fields if f.kind != "secret" and f.default is not None}

    @classmethod
    def describe(cls) -> dict[str, Any]:
        from .netmodel import validate_write_spec

        return {
            "kind": cls.kind, "title": cls.title, "description": cls.description,
            "fields": [f.model_dump(mode="json") for f in cls.fields],
            "capabilities": {d: sorted(ops) for d, ops in cls.capabilities.items()},
            "actions": sorted(cls.actions), "system_of_record": sorted(cls.system_of_record),
            "network_write": validate_write_spec(cls.network_write), "can_backup": cls.implements("backup"),
        }

    @classmethod
    def implements(cls, method: str) -> bool:
        """Whether this connector overrides one of the device methods (``WRITE_METHODS``)."""
        return method in WRITE_METHODS and getattr(cls, method) is not getattr(Connector, method)

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

    # -- network devices: backups and guarded changes (never actions; see the module docstring) --------------

    def write_capability(self) -> dict[str, Any] | None:
        """This connection's write capability: the class declaration, narrowed by the settings (a connector with a
        "read only" setting returns None). The hub narrows it further by what test() reported."""
        from .netmodel import validate_write_spec

        if not all(self.implements(m) for m in WRITE_METHODS if m != "restore_backup"):
            return None
        return validate_write_spec(self.network_write)

    async def backup(self) -> dict[str, Any]:
        raise self._unsupported("take configuration backups")

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        raise self._unsupported("change rules")

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Any) -> dict[str, Any]:
        raise self._unsupported("change rules")

    async def confirm_change(self, token: str) -> dict[str, Any]:
        raise self._unsupported("change rules")

    async def rollback_change(self, token: str, backup: Any) -> dict[str, Any]:
        raise self._unsupported("change rules")

    async def restore_backup(self, backup: Any) -> dict[str, Any]:
        raise self._unsupported("restore backups")

    def _unsupported(self, what: str) -> ConnectorError:
        from .netmodel import ChangeError

        return ChangeError(f"{self.title or self.kind} cannot {what}", code="unsupported", state="unchanged")

    def ssh(self, target: Any):
        """An SSH session to `target` (``execution.runner.SshTarget``), as an async context manager: one connection
        for the whole session. Uses ``self.transport`` when it is an SSH transport (tests pass
        ``execution.sshfake.FakeSshTransport``), else the real one (asyncssh)."""
        from ..execution import runner

        transport = self.transport if hasattr(self.transport, "session") else runner.SSH
        return transport.session(target)

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
        if isinstance(self.transport, httpx.AsyncBaseTransport):
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
        """A detect() helper: `score` when the tool's id, name, source or manifest name contains one of `names`, or
        the id of the product the analyzer recognised (``manifest.known.profile``) holds one, else 30 when its manifest
        provides one of `capabilities`, else 0. Of the source only its own name counts - a SaaS host, the last part of
        a folder path or repository - never the folders it sits in (".../keycloak-lab/ledger" is no Keycloak)."""
        manifest = tool.manifest
        source = (tool.source or "").strip()
        if tool.source_type == "saas" or "://" in source:
            parts = urlsplit(source)
            source = (parts.hostname or "") if tool.source_type == "saas" else (parts.path or source)
        if tool.source_type != "saas":
            source = re.split(r"[\\/:]", source.rstrip("/\\"))[-1].removesuffix(".git")
        haystack = " ".join([tool.id, tool.name, source, manifest.name if manifest else ""]).lower()
        squashed = re.sub(r"[^a-z0-9]", "", haystack)
        if any(n.lower() in haystack or re.sub(r"[^a-z0-9]", "", n.lower()) in squashed for n in names):
            return score
        known = re.sub(r"[^a-z0-9]", "", manifest.known.profile.lower()) if manifest and manifest.known else ""
        if known and any((name := re.sub(r"[^a-z0-9]", "", n.lower())) and name in known for n in names):
            return score
        if manifest and any(c in manifest.provides for c in capabilities):
            return 30
        return 0
