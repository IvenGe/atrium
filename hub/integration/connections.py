"""Connections: how the hub reaches a tool's own API - a connector kind, its settings and encrypted credentials.

Stored in the ``connections`` collection keyed by tool id. Secrets are Fernet-encrypted (``hub.secrets``), decrypted
only by the tool's supervisor when it builds the connector, and never returned, logged or broadcast. A stored secret
is only ever sent to the endpoint (scheme, host and port) it was entered for: changing the server address, or the
connector kind, means entering the secrets again - so neither a person editing settings nor an agent repairing a
flow can redirect them.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, Field

from .. import connectors
from ..connectors.base import Connector, ConnectorError, ConnectorField, redact
from ..models import Tool

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "connections"
MAX_SECRET = 4096
MAX_TEXT = 2000
MAX_JSON = 200_000


class Connection(BaseModel):
    id: str  # tool id
    kind: str
    config: dict[str, Any] = {}
    secrets: dict[str, str] = {}  # field name -> Fernet token
    endpoint: str = ""  # Connector.endpoint(config) the secrets were entered for
    generated: bool = False  # a generic_rest mapping Claude generated from the tool's OpenAPI spec
    created_by: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_by: str = ""
    updated_at: float = Field(default_factory=time.time)
    last_test: dict[str, Any] | None = None


def get(hub: "Hub", tool_id: str) -> Connection | None:
    doc = hub.store.get(COLLECTION, tool_id)
    return Connection.model_validate(doc) if doc else None


def all_connections(hub: "Hub") -> list[Connection]:
    return [Connection.model_validate(d) for d in hub.store.list(COLLECTION)]


def _put(hub: "Hub", conn: Connection) -> Connection:
    """Written straight to the store: the event stream only ever carries the public view."""
    hub.store.put(COLLECTION, conn.model_dump(mode="json"))
    hub.bus.publish("connection", {"tool_id": conn.id, "kind": conn.kind, "updated_at": conn.updated_at})
    return conn


def delete(hub: "Hub", tool_id: str) -> bool:
    removed = hub.store.delete(COLLECTION, tool_id)
    if removed:
        hub.bus.publish("connection", {"tool_id": tool_id, "kind": None})
    return removed


# --------------------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------------------


def _coerce(field: ConnectorField, value: Any) -> Any:
    """One non-secret setting in the type its field declares; ValueError with a message for people."""
    label = field.label
    if field.kind == "bool":
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        raise ValueError(f"{label} must be true or false")
    if field.kind == "number":
        if isinstance(value, bool):
            raise ValueError(f"{label} must be a number")
        try:
            number = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{label} must be a number") from exc
        return int(number) if number.is_integer() else number
    if field.kind == "json":
        if isinstance(value, str):
            if len(value) > MAX_JSON:
                raise ValueError(f"{label} is too large")
            try:
                value = json.loads(value)
            except ValueError as exc:
                raise ValueError(f"{label} is not valid JSON: {exc}") from exc
        if not isinstance(value, (dict, list)):
            raise ValueError(f"{label} must be a JSON object")
        return value
    if isinstance(value, (dict, list)):
        raise ValueError(f"{label} must be text")
    if field.kind == "select" and isinstance(value, int) and not isinstance(value, bool):
        return value  # e.g. a numeric id chosen from options()
    text = str(value).strip()
    if len(text) > MAX_TEXT:
        raise ValueError(f"{label} is too long")
    if field.kind == "url":
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"{label} must start with http:// or https://")
        if parts.username or parts.password:
            raise ValueError(f"{label} must not contain credentials - use the secret fields")
        return text.rstrip("/")
    if field.kind == "select" and field.choices and text not in {c["value"] for c in field.choices}:
        raise ValueError(f"{label} must be one of {', '.join(c['value'] for c in field.choices)}")
    return text


def clean_config(cls: type[Connector], raw: dict[str, Any]) -> dict[str, Any]:
    """Validated non-secret settings (unset values fall back to the field defaults when the connector is built)."""
    fields = {f.name: f for f in cls.fields}
    config: dict[str, Any] = {}
    for name, value in (raw or {}).items():
        field = fields.get(name)
        if field is None:
            raise ValueError(f"{cls.title} has no setting '{name}'")
        if field.kind == "secret":
            raise ValueError(f"{field.label} is a secret: send it under 'secrets'")
        if value is None or (isinstance(value, str) and not value.strip()):
            continue
        config[name] = _coerce(field, value)
    missing = [f.label for f in cls.fields if f.required and f.kind != "secret" and f.name not in config
               and f.default is None]
    if missing:
        raise ValueError(f"Required: {', '.join(missing)}")
    try:
        return cls.validate_config({**cls.defaults(), **config})
    except ConnectorError as exc:
        raise ValueError(exc.message) from exc


def endpoint(cls: type[Connector], config: dict[str, Any]) -> str:
    return cls.endpoint({**cls.defaults(), **config})


# --------------------------------------------------------------------------------------
# saving
# --------------------------------------------------------------------------------------


def save(hub: "Hub", tool_id: str, kind: str, config: dict[str, Any], secrets: dict[str, str | None],
         actor: str, *, generated: bool | None = None) -> tuple[Connection, list[str]]:
    """Create or replace a tool's connection. An empty secret keeps the stored one - as long as the kind and the
    endpoint stay the same. Returns the connection and the names of the secrets that were changed."""
    cls = connectors.connector_class(kind)
    config = clean_config(cls, config)
    fields = {f.name: f for f in cls.fields}
    current = get(hub, tool_id)
    target = endpoint(cls, config)
    reusable = current is not None and current.kind == kind and current.endpoint == target
    stored: dict[str, str] = {}
    changed: list[str] = []
    for name, value in (secrets or {}).items():
        field = fields.get(name)
        if field is None or field.kind != "secret":
            raise ValueError(f"{cls.title} has no secret '{name}'")
        if value is None or value == "":
            continue
        if not isinstance(value, str) or len(value) > MAX_SECRET:
            raise ValueError(f"{field.label} must be text of at most {MAX_SECRET} characters")
        stored[name] = hub.secrets.encrypt(value)
        changed.append(name)
    for field in cls.fields:
        if field.kind != "secret" or field.name in stored:
            continue
        if reusable and current and field.name in current.secrets:
            stored[field.name] = current.secrets[field.name]
        elif field.required:
            moved = current is not None and field.name in current.secrets
            raise ValueError(f"Enter the {field.label}" + (
                " again: the stored one is only sent to the address it was entered for" if moved else ""))
    now = time.time()
    conn = Connection(
        id=tool_id, kind=kind, config=config, secrets=stored, endpoint=target,
        generated=(current.generated if current and current.kind == kind else False) if generated is None else generated,
        created_by=current.created_by if current else actor, created_at=current.created_at if current else now,
        updated_by=actor, updated_at=now,
        last_test=current.last_test if current and current.kind == kind and current.endpoint == target else None,
    )
    return _put(hub, conn), changed


def update_config(hub: "Hub", tool_id: str, changes: dict[str, Any], actor: str, *, kind: str | None = None,
                  generated: bool | None = None) -> Connection:
    """Apply an agent-proposed change (a repair or a generated mapping) to the non-secret settings. The endpoint must
    not change while secrets are stored, so a change can never send them anywhere else."""
    current = get(hub, tool_id)
    kind = kind or (current.kind if current else None)
    if not kind:
        raise ValueError("The tool has no connection to change")
    cls = connectors.connector_class(kind)
    same = current if current is not None and current.kind == kind else None  # another kind starts without secrets
    config = clean_config(cls, {**(same.config if same else {}), **changes})
    target = endpoint(cls, config)
    if same and same.secrets and target != same.endpoint:
        raise ValueError("Refusing a change that would send the stored credentials to another address")
    now = time.time()
    conn = Connection(
        id=tool_id, kind=kind, config=config, secrets=same.secrets if same else {}, endpoint=target,
        generated=(same.generated if same else False) if generated is None else generated,
        created_by=current.created_by if current else actor, created_at=current.created_at if current else now,
        updated_by=actor, updated_at=now,
    )
    return _put(hub, conn)


def drop_mapping(hub: "Hub", tool_id: str, actor: str) -> Connection | None:
    """Take every domain out of a generic REST connection (an extension that mapped the last ones was disabled): the
    connection and its credentials stay, and it reads nothing until someone maps a domain again. The "at least one
    domain" rule of a saved mapping does not apply here."""
    conn = get(hub, tool_id)
    if conn is None or "mapping" not in conn.config:
        return conn
    return _put(hub, conn.model_copy(update={"config": {k: v for k, v in conn.config.items() if k != "mapping"},
                                             "last_test": None, "updated_by": actor, "updated_at": time.time()}))


def record_test(hub: "Hub", tool_id: str, result: dict[str, Any]) -> None:
    conn = get(hub, tool_id)
    if conn is None:
        return
    conn.last_test = {k: result.get(k) for k in ("ok", "detail", "checks", "domains")} | {"at": time.time()}
    _put(hub, conn)


# --------------------------------------------------------------------------------------
# using a connection
# --------------------------------------------------------------------------------------


def decrypt(hub: "Hub", conn: Connection) -> dict[str, str]:
    return {name: hub.secrets.decrypt(token) for name, token in conn.secrets.items()}


def build(hub: "Hub", tool_id: str, config_override: dict[str, Any] | None = None,
          transport: httpx.AsyncBaseTransport | None = None) -> tuple[Connector, dict[str, str]]:
    """The tool's connector with its decrypted secrets (and the secrets, for redacting what it answers).
    `config_override` (a repair trying a variant) must keep the endpoint the secrets were entered for."""
    conn = get(hub, tool_id)
    if conn is None:
        raise ConnectorError("This tool has no connection yet - an administrator sets one up in Tool > Connection")
    cls = connectors.connector_class(conn.kind)
    config = dict(conn.config)
    if config_override:
        try:
            config = clean_config(cls, {**config, **config_override})
        except ValueError as exc:
            raise ConnectorError(str(exc)) from exc
        if conn.secrets and endpoint(cls, config) != conn.endpoint:
            raise ConnectorError("Refusing to send the stored credentials to another address")
    secrets = decrypt(hub, conn) if conn.secrets else {}
    return cls(config, secrets, transport or getattr(hub, "connector_transport", None)), secrets


def capabilities(conn: Connection) -> dict[str, list[str]]:
    """Domains and operations of a connection: what its last successful test reported, else what the connector
    declares for these settings."""
    if conn.last_test and conn.last_test.get("ok") and conn.last_test.get("domains"):
        return {d: sorted(ops) for d, ops in conn.last_test["domains"].items() if ops}
    try:
        cls = connectors.connector_class(conn.kind)
        return cls(conn.config, {}).domains()
    except Exception:
        return {}


def public(hub: "Hub", tool: Tool, conn: Connection | None) -> dict[str, Any]:
    """What GET /api/tools/{id}/connection shows: never a secret, only whether each one is set."""
    detected = connectors.detect(tool)
    out: dict[str, Any] = {"tool_id": tool.id, "detected": detected, "kind": None, "config": {}, "secrets": {},
                           "capabilities": {}, "actions": [], "system_of_record": [], "last_test": None,
                           "generated": False, "updated_at": None, "updated_by": None, "connector": None}
    if conn is None:
        return out
    try:
        cls = connectors.connector_class(conn.kind)
        described = cls.describe()
    except ConnectorError as exc:
        return {**out, "kind": conn.kind, "error": exc.message}
    out.update({
        "kind": conn.kind, "connector": described,
        "config": {k: v for k, v in conn.config.items() if k in {f.name for f in cls.fields if f.kind != "secret"}},
        "secrets": {f.name: f.name in conn.secrets for f in cls.fields if f.kind == "secret"},
        "capabilities": capabilities(conn), "actions": described["actions"],
        "system_of_record": described["system_of_record"], "last_test": conn.last_test, "generated": conn.generated,
        "updated_at": conn.updated_at, "updated_by": conn.updated_by,
    })
    return out


def safe_failure(exc: BaseException, secrets: dict[str, str] | None = None) -> dict[str, Any]:
    """{"message", "status", "excerpt"} of a failed connector call, with every secret masked."""
    if isinstance(exc, ConnectorError):
        return {"message": redact(exc.message, secrets), "status": exc.status,
                "excerpt": redact(exc.excerpt, secrets) if exc.excerpt else None}
    return {"message": redact(f"{exc.__class__.__name__}: {exc}", secrets), "status": None, "excerpt": None}
