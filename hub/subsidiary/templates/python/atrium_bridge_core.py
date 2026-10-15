"""Atrium bridge core for Python - contract atrium-bridge/1 (Atrium's docs/SUBSIDIARIES.md has the full text).

VENDORED FILE: Atrium adds it byte-identical and checks its SHA-256; do not edit it. Everything tool-specific lives in
the glue (glue.py): the action handlers, the current-user hook and the service principal.

The bridge lets an agent team (a "subsidiary") that runs in a sidecar next to this tool work inside it, while Atrium
(the parent) keeps every decision. It holds NO secret: it verifies Atrium's Ed25519 signatures with the public keys in
ATRIUM_BRIDGE_KEYS. Every sidecar call carries a short-lived ticket (the actions it may call), a signature made with
the sidecar's own key, and - for changes - a single-use grant Atrium signs after a person approved the exact request.

Routes (mounted on the tool's own application by adapters.py):
    GET  /.atrium/v1/health              anyone        {"status": "ok"}
    POST /.atrium/v1/call/{action_id}    the sidecar   ticket + request signature (+ grant)
    GET  /.atrium/panel.js               browsers      the "Ask the team" widget
    POST /.atrium/v1/panel/ask           tool users    the tool's session + header X-Atrium-Panel: 1
    GET  /.atrium/v1/panel/questions/ID  tool users    only the user who asked
    GET  /.atrium/v1/panel/status        tool users    {enabled, team_online}

Fail closed: without valid configuration every route but /health answers 503 not_configured and the tool works
unchanged. Never blocks the tool: long-polls only hold the sidecar's own requests, emit() never waits.

Requires Python 3.8+ and the "cryptography" package; nothing else.
"""

from __future__ import annotations

import asyncio
import base64
import contextvars
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

CONTRACT = "atrium-bridge/1"
CORE_VERSION = "python/1.0.0"
PANEL_JS_SHA256 = "169f62fab9b60d01232e02f5f4feb89e81172819c5fe0e3a4042e6a88ef03898"  # the vendored widget

API_PREFIX = "/.atrium/v1"
HEALTH_PATH = "/.atrium/v1/health"
CALL_PREFIX = "/.atrium/v1/call/"
PANEL_JS_PATH = "/.atrium/panel.js"
PANEL_ASK_PATH = "/.atrium/v1/panel/ask"
PANEL_QUESTION_PREFIX = "/.atrium/v1/panel/questions/"
PANEL_STATUS_PATH = "/.atrium/v1/panel/status"
PANEL_HEADER = "x-atrium-panel"

CLOCK_LEEWAY = 60
NONCE_TTL = 180
NONCE_CAPACITY = 10_000
GRANT_JTI_KEEP = 3600
MAX_TOKEN_PAYLOAD = 4096
MAX_TOKEN = 6144
MAX_KEYS = 2
MAX_BODY = 64 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_ACTIONS = 40
MAX_PROPERTIES = 20
MAX_STRING = 10_000
MAX_ITEMS = 100
MAX_ENUM = 100
MAX_SAFE_INT = 2 ** 53 - 1
WAIT_MAX = 25
DEFAULT_RATE = {"calls_per_min": 30, "panel_per_user_hour": 10}
PANEL_TEXT_MAX, PANEL_PAGE_PATH_MAX, PANEL_RECORD_MAX = 2000, 300, 120
PANEL_ANSWER_MAX, PANEL_BY_MAX = 4000, 80
PANEL_OPEN_MAX = 200
PANEL_EXPIRY = 30 * 60
PANEL_ONLINE_WINDOW = 60
PANEL_OFFLINE_ANSWER = 120
PANEL_PULL_MAX = 20
PANEL_UNAVAILABLE = "The team is not available right now"
OUTBOX_MAX = 1000
OUTBOX_TTL = 24 * 3600
EVENT_PAYLOAD_MAX = 16 * 1024
EVENTS_PULL_MAX = 100

STATUS = {
    "bad_ticket": 401, "bad_signature": 401, "expired": 401, "replay": 401,
    "action_not_allowed": 403, "probation": 403, "grant_required": 403, "grant_mismatch": 403,
    "forbidden_on_behalf": 403, "source_not_allowed": 403,
    "grant_used": 409, "too_large": 413, "bad_params": 422, "rate_limited": 429,
    "not_configured": 503, "busy": 503,
}
PANEL_STATUS = {"no_session": 401, "panel_header_required": 403, "not_found": 404, "too_large": 413,
                "bad_params": 422, "rate_limited": 429, "busy": 503, "not_configured": 503}
NEEDS_GRANT = ("write", "admin")
RISKS = ("read", "propose", "write", "admin")


def _object(properties: Optional[Dict[str, Any]] = None, required: Tuple[str, ...] = ()) -> Dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "properties": dict(properties or {}),
            "required": list(required)}


BUILTINS: Dict[str, Dict[str, Any]] = {
    "atrium.ping": {"risk": "read", "params": _object()},
    "atrium.describe": {"risk": "read", "params": _object()},
    "atrium.noop_write": {"risk": "write", "params": _object({"echo": {"type": "string", "maxLength": 64}}, ("echo",))},
    "atrium.receipt": {"risk": "read", "params": _object({"jti": {"type": "string", "maxLength": 64}}, ("jti",))},
    "atrium.panel.pull": {"risk": "read",
                          "params": _object({"wait": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX}})},
    "atrium.panel.answer": {"risk": "propose", "params": _object({
        "question_id": {"type": "string", "maxLength": 64},
        "text": {"type": "string", "maxLength": PANEL_ANSWER_MAX},
        "status": {"enum": ["answered", "escalated", "declined", "working"]},
        "by": {"type": "string", "maxLength": PANEL_BY_MAX}}, ("question_id", "text", "status"))},
    "atrium.events.pull": {"risk": "read", "params": _object({
        "after": {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INT},
        "wait": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX}})},
}
PROBATION_BUILTINS = ("atrium.ping", "atrium.describe", "atrium.noop_write", "atrium.receipt")

ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9_.]{2,57}$")
TOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SUBSIDIARY_ID_RE = re.compile(r"^sub_[0-9a-f]{12}$")
PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
DATE_RE = re.compile(r"^[0-9]{1,12}$")
QUESTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
TEXT_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f‪-‮⁦-⁩]")

log = logging.getLogger("atrium_bridge")
_CAUSE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("atrium_bridge_cause", default=None)


class Refused(Exception):
    """A refusal: its answer is {"ok": false, "code": code} and never echoes request content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
        self.status = STATUS.get(code) or PANEL_STATUS[code]


# --------------------------------------------------------------------------------------
# encodings, keys, tickets and grants
# --------------------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: Any) -> bytes:
    """Strict base64url without padding: the alphabet only, canonical."""
    if not isinstance(text, str) or not B64U_RE.match(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(data) != text:
        raise ValueError("not canonical base64url")
    return data


def public_key(text: Any) -> Ed25519PublicKey:
    raw = b64u_decode(text)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_keys(value: Optional[str]) -> List[Ed25519PublicKey]:
    """ATRIUM_BRIDGE_KEYS: one or two base64url public keys, comma-separated (ValueError otherwise)."""
    items = [k.strip() for k in str(value or "").split(",") if k.strip()]
    if not 1 <= len(items) <= MAX_KEYS:
        raise ValueError("ATRIUM_BRIDGE_KEYS holds one or two keys")
    return [public_key(k) for k in items]


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def verify_token(token: Any, prefix: str, keys: List[Ed25519PublicKey], code: str) -> Dict[str, Any]:
    """Verify the signature over the received "<prefix>.<payload>" bytes with each key, THEN decode and parse."""
    if not isinstance(token, str) or len(token) > MAX_TOKEN or not keys:
        raise Refused(code)
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != prefix or not B64U_RE.match(parts[1]):
        raise Refused(code)
    try:
        signature = b64u_decode(parts[2])
    except ValueError:
        raise Refused(code) from None
    signed = (parts[0] + "." + parts[1]).encode("ascii")
    for key in keys[:MAX_KEYS]:
        try:
            key.verify(signature, signed)
            break
        except InvalidSignature:
            continue
    else:
        raise Refused(code)
    return parse_payload(parts[1], code)


def parse_payload(payload_b64: str, code: str) -> Dict[str, Any]:
    try:
        raw = b64u_decode(payload_b64)
        if len(raw) > MAX_TOKEN_PAYLOAD:
            raise ValueError("too large")
        payload = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused(code) from None
    if not isinstance(payload, dict) or not _int(payload.get("v")) or payload["v"] != 1:
        raise Refused(code)
    return payload


def ticket_fields_ok(p: Mapping[str, Any]) -> bool:
    rl = p.get("rl")
    ok = (p.get("typ") == "ticket" and isinstance(p.get("sub"), str) and isinstance(p.get("tool"), str)
          and _int(p.get("cv")) and p.get("mode") in ("probation", "active") and isinstance(p.get("act"), list)
          and len(p["act"]) <= MAX_ACTIONS + len(BUILTINS) and all(isinstance(a, str) for a in p["act"])
          and isinstance(p.get("cnf"), str) and _int(p.get("iat")) and _int(p.get("exp"))
          and isinstance(p.get("jti"), str) and 0 < len(p["jti"]) <= 64
          and isinstance(rl, dict) and all(_int(v) and v >= 0 for v in rl.values()))
    if not ok:
        return False
    try:
        public_key(p["cnf"])
    except ValueError:
        return False
    return True


def grant_fields_ok(p: Mapping[str, Any]) -> bool:
    return (p.get("typ") == "grant" and isinstance(p.get("sub"), str) and isinstance(p.get("tool"), str)
            and _int(p.get("cv")) and isinstance(p.get("act"), str) and isinstance(p.get("bh"), str)
            and isinstance(p.get("apv"), str) and _int(p.get("iat")) and _int(p.get("exp"))
            and isinstance(p.get("jti"), str) and 0 < len(p["jti"]) <= 64)


def body_hash(body: bytes) -> str:
    return b64u(hashlib.sha256(body).digest())


def signing_string(method: str, path: str, date: str, nonce: str, body: bytes, ticket_jti: str,
                   grant_jti: Optional[str], on_behalf_of: Optional[str]) -> bytes:
    lines = [CONTRACT, method.upper(), path, date, nonce, hashlib.sha256(body).hexdigest(), ticket_jti,
             grant_jti or "-", on_behalf_of or "-"]
    return "\n".join(lines).encode("utf-8")


def verify_signature(cnf: str, signature: Any, message: bytes) -> bool:
    try:
        public_key(cnf).verify(b64u_decode(signature), message)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


# --------------------------------------------------------------------------------------
# params: the JSON Schema subset
# --------------------------------------------------------------------------------------


def _kind(prop: Any) -> Optional[str]:
    if not isinstance(prop, dict):
        return None
    if "enum" in prop:
        return "enum"
    return prop.get("type") if prop.get("type") in ("string", "integer", "boolean", "array") else None


def _prop_ok(prop: Any, item: bool = False) -> bool:
    kind = _kind(prop)
    if kind is None or (item and kind == "array"):
        return False
    allowed = {"description"} | {"string": {"type", "maxLength", "minLength"}, "integer": {"type", "minimum", "maximum"},
                                 "boolean": {"type"}, "enum": {"type", "enum"}, "array": {"type", "items", "maxItems"}
                                 }[kind]
    if set(prop) - allowed:
        return False
    if kind == "string":
        top, low = prop.get("maxLength"), prop.get("minLength", 0)
        return _int(top) and 1 <= top <= MAX_STRING and _int(low) and 0 <= low <= top
    if kind == "integer":
        lo, hi = prop.get("minimum", -MAX_SAFE_INT), prop.get("maximum", MAX_SAFE_INT)
        return _int(lo) and _int(hi) and -MAX_SAFE_INT <= lo <= hi <= MAX_SAFE_INT
    if kind == "enum":
        values = prop["enum"]
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_ENUM:
            return False
        strings = all(isinstance(v, str) for v in values)
        ints = all(_int(v) and abs(v) <= MAX_SAFE_INT for v in values)
        return (strings or ints) and len(set(values)) == len(values)
    if kind == "array":
        top = prop.get("maxItems")
        return _int(top) and 1 <= top <= MAX_ITEMS and _prop_ok(prop.get("items"), item=True)
    return True


def schema_ok(schema: Any) -> bool:
    """An action's params schema is the contract's subset (a manifest that breaks it fails closed)."""
    if not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        return False
    if set(schema) - {"type", "additionalProperties", "properties", "required", "description"}:
        return False
    props, required = schema.get("properties", {}), schema.get("required", [])
    if not isinstance(props, dict) or len(props) > MAX_PROPERTIES or not isinstance(required, list):
        return False
    if any(not PARAM_NAME_RE.match(n) for n in props) or any(r not in props for r in required):
        return False
    return all(_prop_ok(p) for p in props.values())


def _value(prop: Dict[str, Any], value: Any) -> Tuple[bool, Any]:
    kind = _kind(prop)
    if kind == "array":
        if not isinstance(value, list) or len(value) > prop["maxItems"]:
            return False, None
        out = []
        for v in value:
            ok, v = _value(prop["items"], v)
            if not ok:
                return False, None
            out.append(v)
        return True, out
    if kind == "boolean":
        return isinstance(value, bool), value
    if kind == "string":
        return isinstance(value, str) and prop.get("minLength", 0) <= len(value) <= prop["maxLength"], value
    if isinstance(value, float) and value.is_integer():
        value = int(value)  # 2.0 and 1e1 are integers, as in every bridge language
    if kind == "integer":
        ok = _int(value) and prop.get("minimum", -MAX_SAFE_INT) <= value <= prop.get("maximum", MAX_SAFE_INT)
        return ok and abs(value) <= MAX_SAFE_INT, value
    if kind == "enum":
        return (isinstance(value, str) or (_int(value) and abs(value) <= MAX_SAFE_INT)) and value in prop["enum"], value
    return False, None


def validate_params(schema: Mapping[str, Any], params: Any) -> Dict[str, Any]:
    """`params` against an action's schema: 422 bad_params on any problem; integral numbers become integers."""
    if not isinstance(params, dict):
        raise Refused("bad_params")
    props = schema.get("properties", {})
    if any(k not in props for k in params) or any(r not in params for r in schema.get("required", [])):
        raise Refused("bad_params")
    out: Dict[str, Any] = {}
    for key, value in params.items():
        ok, out[key] = _value(props[key], value)
        if not ok:
            raise Refused("bad_params")
    return out


def parse_json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("bad_params") from None


def parse_body(body: bytes) -> Dict[str, Any]:
    """The params of a call body: a JSON object whose only member is "params", an object."""
    data = parse_json(body)
    if not isinstance(data, dict) or set(data) != {"params"} or not isinstance(data["params"], dict):
        raise Refused("bad_params")
    return data["params"]


# --------------------------------------------------------------------------------------
# stores
# --------------------------------------------------------------------------------------


class NonceCache:
    """Seen nonces for NONCE_TTL seconds; a full cache refuses (503 busy) rather than forget a live nonce."""

    def __init__(self, ttl: int = NONCE_TTL, capacity: int = NONCE_CAPACITY):
        self.ttl, self.capacity = ttl, capacity
        self._seen: "OrderedDict[str, float]" = OrderedDict()
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._seen)

    def add(self, nonce: str, now: float) -> None:
        with self._lock:
            while self._seen:
                first, at = next(iter(self._seen.items()))
                if at > now - self.ttl:
                    break
                self._seen.popitem(last=False)
            if nonce in self._seen:
                raise Refused("replay")
            if len(self._seen) >= self.capacity:
                raise Refused("busy")
            self._seen[nonce] = now


class SqliteNonces(NonceCache):
    """Seen nonces in a SQLite file, for tools served by several processes (gunicorn workers): a request replayed to
    another worker is refused too. Check and insert are one transaction across processes."""

    def __init__(self, path: Any, ttl: int = NONCE_TTL, capacity: int = NONCE_CAPACITY):
        super().__init__(ttl, capacity)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=5)
        self._db.execute("CREATE TABLE IF NOT EXISTS atrium_nonces (nonce TEXT PRIMARY KEY, at INTEGER NOT NULL)")

    def __len__(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM atrium_nonces").fetchone()[0]

    def add(self, nonce: str, now: float) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM atrium_nonces WHERE at <= ?", (int(now) - self.ttl,))
                if self._db.execute("SELECT 1 FROM atrium_nonces WHERE nonce = ?", (nonce,)).fetchone():
                    raise Refused("replay")
                if self._db.execute("SELECT COUNT(*) FROM atrium_nonces").fetchone()[0] >= self.capacity:
                    raise Refused("busy")
                self._db.execute("INSERT INTO atrium_nonces VALUES (?, ?)", (nonce, int(now)))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise


class MemoryGrants:
    """Used grant jtis and their receipts, in memory. A tool with storage persists them (SqliteGrants, or its own
    object with the same four methods), so a restart cannot replay a grant. mark() is the authoritative single-use
    check: it must record the jti and answer True atomically, or answer False when the jti was already used."""

    def __init__(self) -> None:
        self._rows: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def used(self, jti: str) -> bool:
        with self._lock:
            return jti in self._rows

    def mark(self, jti: str, keep_until: int, now: int) -> bool:
        """Called BEFORE the handler runs: from here on the jti is used whatever happens. False: already used."""
        with self._lock:
            self._rows = {j: r for j, r in self._rows.items() if r["keep_until"] > now}
            if jti in self._rows:
                return False
            self._rows[jti] = {"status": "started", "at": now, "keep_until": keep_until}
            return True

    def record(self, jti: str, status: str, at: int) -> None:
        with self._lock:
            if jti in self._rows:
                self._rows[jti].update(status=status, at=at)

    def receipt(self, jti: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._rows.get(jti)
            return {"status": row["status"], "at": row["at"]} if row else None


class SqliteGrants(MemoryGrants):
    """Used grant jtis and receipts in a SQLite file (standard library only)."""

    def __init__(self, path: Any) -> None:
        super().__init__()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None, timeout=5)
        self._db.execute("CREATE TABLE IF NOT EXISTS atrium_grants (jti TEXT PRIMARY KEY, status TEXT NOT NULL, "
                         "at INTEGER NOT NULL, keep_until INTEGER NOT NULL)")

    def used(self, jti: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM atrium_grants WHERE jti = ?", (jti,)).fetchone() is not None

    def mark(self, jti: str, keep_until: int, now: int) -> bool:
        with self._lock:
            self._db.execute("DELETE FROM atrium_grants WHERE keep_until <= ?", (now,))
            cursor = self._db.execute("INSERT OR IGNORE INTO atrium_grants VALUES (?, 'started', ?, ?)",
                                      (jti, now, keep_until))
            return cursor.rowcount == 1

    def record(self, jti: str, status: str, at: int) -> None:
        with self._lock:
            self._db.execute("UPDATE atrium_grants SET status = ?, at = ? WHERE jti = ?", (status, at, jti))

    def receipt(self, jti: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._db.execute("SELECT status, at FROM atrium_grants WHERE jti = ?", (jti,)).fetchone()
        return {"status": row[0], "at": row[1]} if row else None


# --------------------------------------------------------------------------------------
# requests, answers and the handlers' context
# --------------------------------------------------------------------------------------


@dataclass
class Request:
    """A request as the adapters hand it over. `path` starts at "/.atrium/" (any prefix the tool is served under is
    stripped), `query` is the raw query string, header names are lower case, `body` is the raw body (adapters stop
    reading past MAX_BODY and set `oversize`), `native` is the framework's own request (for the current-user hook)."""

    method: str
    path: str
    query: str = ""
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""
    remote: Optional[str] = None
    native: Any = None
    oversize: bool = False


@dataclass
class Response:
    status: int
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Context:
    """What a handler gets besides its params. `user` is set in panel runs: the tool user who asked, taken from the
    bridge's own question store (never from the sidecar) - authorize as that user AND the service principal."""

    action: str
    principal: str
    user: Optional[Dict[str, Any]] = None
    question_id: Optional[str] = None
    grant_jti: Optional[str] = None
    native: Any = None


def _answer(status: int, value: Any) -> Response:
    body = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return Response(status, body, {"Content-Type": "application/json", "X-Content-Type-Options": "nosniff",
                                   "Cache-Control": "no-store"})


def _refusal(code: str) -> Response:
    return _answer(Refused(code).status, {"ok": False, "code": code})


def _user(value: Any) -> Optional[Dict[str, Any]]:
    """The current-user hook's answer as {id, display, roles}, or None."""
    if value is None:
        return None
    get = value.get if isinstance(value, Mapping) else (lambda k, d=None: getattr(value, k, d))
    uid = get("id")
    if uid is None or isinstance(uid, bool) or str(uid).strip() == "":
        return None
    roles = get("roles") or []
    roles = [str(r)[:60] for r in (roles if isinstance(roles, (list, tuple, set)) else [roles])][:20]
    display = get("display") or get("name") or uid
    return {"id": str(uid)[:120], "display": TEXT_CONTROL.sub("", str(display))[:120], "roles": roles}


@dataclass
class _Question:
    id: str
    user: Dict[str, Any]
    text: str
    page: Optional[Dict[str, str]]
    asked_at: int
    status: str = "waiting"
    answer: Optional[str] = None
    by: Optional[str] = None
    updated_at: int = 0

    def open(self) -> bool:
        return self.status in ("waiting", "answering")


@dataclass
class _Call:
    action: str
    spec: Dict[str, Any]
    params: Dict[str, Any]
    ctx: Context
    ticket: Dict[str, Any]
    grant: Optional[Dict[str, Any]]


# --------------------------------------------------------------------------------------
# the bridge
# --------------------------------------------------------------------------------------


_DEFAULT: List["Bridge"] = []
_BY_GLUE: Dict[int, Tuple[Any, "Bridge"]] = {}
_GLUE_LOCK = threading.Lock()


class Bridge:
    """One bridge per tool process. `actions`: action id -> handler(params, ctx) (sync or async) for the manifest's
    actions; `current_user(request)` -> {id, display, roles} | None (sync or async; None disables the panel);
    `manifest`/`panel_js`: a path or the bytes; `grants` and `nonces`: the used-grant and seen-nonce stores (share
    them, e.g. SqliteGrants and SqliteNonces, when the tool runs several processes); `env`: defaults to os.environ.
    `sync_wait` caps long-polls in sync servers (WSGI), where a waiting request holds one of the tool's workers."""

    def __init__(self, *, actions: Optional[Mapping[str, Callable[..., Any]]] = None,
                 current_user: Optional[Callable[[Any], Any]] = None, service_principal: Any = "atrium-team",
                 manifest: Any = None, panel_js: Any = None, panel_sha256: str = PANEL_JS_SHA256,
                 env: Optional[Mapping[str, str]] = None, clock: Callable[[], float] = time.time,
                 grants: Optional[MemoryGrants] = None, nonces: Optional[NonceCache] = None, sync_wait: int = 0,
                 max_wait: int = WAIT_MAX):
        self.actions = dict(actions or {})
        self.current_user = current_user
        principal = service_principal() if callable(service_principal) else service_principal
        self.principal = str(principal or "atrium-team")
        self.clock, self.grants = clock, grants if grants is not None else MemoryGrants()
        self.sync_wait, self.max_wait = max(0, min(int(sync_wait), WAIT_MAX)), max(0, min(int(max_wait), WAIT_MAX))
        self.nonces = nonces if nonces is not None else NonceCache()
        self._lock = threading.RLock()
        self._calls: "deque[float]" = deque()
        self._rate = dict(DEFAULT_RATE)
        self._questions: "OrderedDict[str, _Question]" = OrderedDict()
        self._asked: Dict[str, "deque[int]"] = {}
        self._last_pull: Optional[int] = None
        self._events: "deque[Dict[str, Any]]" = deque()
        self._seq = 0
        self.drops = 0
        self.rejected = 0
        self.problem: Optional[str] = None
        self.keys: List[Ed25519PublicKey] = []
        self.tool, self.sub, self.allow, self.panel_on, self.panel_roles = "", "", [], False, []
        self.manifest: Dict[str, Any] = {}
        self.manifest_raw = b""
        self.panel_js: Optional[bytes] = None
        self.panel_sha = ""
        self._configure(env if env is not None else os.environ, manifest, panel_js, panel_sha256)
        _DEFAULT[:] = [self]

    # ---- configuration (fail closed) ----

    def _configure(self, env: Mapping[str, str], manifest: Any, panel_js: Any, panel_sha256: str) -> None:
        try:
            self.keys = parse_keys(env.get("ATRIUM_BRIDGE_KEYS"))
            self.tool = env.get("ATRIUM_TOOL_ID", "")
            self.sub = env.get("ATRIUM_SUBSIDIARY_ID", "")
            if not TOOL_ID_RE.match(self.tool) or not SUBSIDIARY_ID_RE.match(self.sub):
                raise ValueError("ATRIUM_TOOL_ID or ATRIUM_SUBSIDIARY_ID is missing or malformed")
            self.allow = [ipaddress.ip_network(c.strip(), strict=False)
                          for c in str(env.get("ATRIUM_BRIDGE_ALLOW") or "").split(",") if c.strip()]
            self.manifest_raw = _read(manifest, "atrium-bridge.json")
            self.manifest = json.loads(self.manifest_raw.decode("utf-8"), parse_constant=_no_constant)
            self._check_manifest()
        except Exception as exc:  # any configuration problem: every route but /health answers 503
            self.keys, self.problem = [], f"not configured: {exc}"[:300]
            log.warning("Atrium bridge %s", self.problem)
            return
        panel_env = str(env.get("ATRIUM_PANEL") or "").strip().lower()
        self.panel_roles = [r.strip() for r in str(env.get("ATRIUM_PANEL_ROLES") or "").split(",") if r.strip()]
        try:
            raw = _read(panel_js, "panel.js")
            if hashlib.sha256(raw).hexdigest() != panel_sha256:
                raise ValueError("panel.js is not the vendored widget (SHA-256 differs)")
            self.panel_js, self.panel_sha = raw, panel_sha256
        except Exception as exc:
            log.warning("Atrium bridge panel off: %s", str(exc)[:200])
        self.panel_on = (panel_env != "off" and self.current_user is not None and self.panel_js is not None
                         and bool((self.manifest.get("panel") or {}).get("enabled")))

    def _check_manifest(self) -> None:
        m = self.manifest
        if not isinstance(m, dict) or m.get("contract") != CONTRACT or m.get("tool_id") != self.tool:
            raise ValueError("atrium-bridge.json is not this tool's atrium-bridge/1 manifest")
        actions = m.get("actions", [])
        if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
            raise ValueError("atrium-bridge.json lists too many actions")
        names = (m.get("events") or {}).get("names", [])
        if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
            raise ValueError("atrium-bridge.json events.names is a list of names")
        for a in actions:
            if not isinstance(a, dict) or not ACTION_ID_RE.match(str(a.get("id"))) or a["id"].startswith("atrium.") \
                    or a.get("risk") not in RISKS or not schema_ok(a.get("params")):
                raise ValueError(f"atrium-bridge.json action {str((a or {}).get('id'))[:60]!r} breaks the contract")
            if a["id"] not in self.actions:
                log.warning("Atrium bridge: the glue has no handler for %s", a["id"])

    @property
    def ready(self) -> bool:
        return bool(self.keys)

    def manifest_sha256(self) -> str:
        return hashlib.sha256(self.manifest_raw).hexdigest()

    def spec(self, action: str) -> Optional[Dict[str, Any]]:
        if action in BUILTINS:
            return {"id": action, **BUILTINS[action]}
        found = next((a for a in self.manifest.get("actions", []) if a.get("id") == action), None)
        return found if found is not None and action in self.actions else None

    # ---- entry points ----

    def handle(self, req: Request) -> Response:
        """Synchronous servers (WSGI). Long-polls wait at most `sync_wait` seconds; async handlers are refused."""
        try:
            route = self._route(req)
            if isinstance(route, Response):
                return route
            if route == "panel":
                user = self._resolve_user_sync(req)
                return self._panel(req, user)
            call = self._verify(req)
            result, status = self._run_sync(call)
            return self._finish(call, result, status)
        except Refused as exc:
            return _refusal(exc.code)
        except Exception:
            log.exception("Atrium bridge: internal error")
            return _answer(500, {"ok": False, "code": "failed"})

    async def ahandle(self, req: Request) -> Response:
        """Asynchronous servers (ASGI): long-polls wait up to 25 s without blocking anything else; sync handlers run
        in a worker thread."""
        try:
            route = self._route(req)
            if isinstance(route, Response):
                return route
            if route == "panel":
                user = self.current_user(req.native) if self.current_user else None
                if inspect.isawaitable(user):
                    user = await user
                return self._panel(req, _user(user))
            call = self._verify(req)
            result, status = await self._run_async(call)
            return self._finish(call, result, status)
        except Refused as exc:
            return _refusal(exc.code)
        except Exception:
            log.exception("Atrium bridge: internal error")
            return _answer(500, {"ok": False, "code": "failed"})

    def _route(self, req: Request) -> Any:
        method, path = req.method.upper(), req.path
        if path == HEALTH_PATH and method == "GET":
            return _answer(200, {"status": "ok"})
        if not self.ready:
            raise Refused("not_configured")
        if path == PANEL_JS_PATH and method == "GET":
            if self.panel_js is None:
                return _answer(404, {"ok": False, "code": "not_found"})
            etag = f'"{self.panel_sha}"'
            headers = {"Content-Type": "application/javascript; charset=utf-8", "X-Content-Type-Options": "nosniff",
                       "ETag": etag, "Cache-Control": "no-cache"}
            if req.headers.get("if-none-match") == etag:
                return Response(304, b"", headers)
            return Response(200, self.panel_js, headers)
        if method == "POST" and path.startswith(CALL_PREFIX):
            return "call"
        if (method == "POST" and path == PANEL_ASK_PATH) or (method == "GET" and (
                path == PANEL_STATUS_PATH or path.startswith(PANEL_QUESTION_PREFIX))):
            return "panel"
        return _answer(404, {"ok": False, "code": "not_found"})

    # ---- the verification order (one code path for every call) ----

    def _verify(self, req: Request) -> _Call:
        action = req.path[len(CALL_PREFIX):]
        now = int(self.clock())
        h = req.headers
        if self.allow and not self._source_allowed(req.remote):  # 1
            raise Refused("source_not_allowed")
        if req.oversize or len(req.body) > MAX_BODY:
            raise Refused("too_large")
        ticket = self._open(h.get("atrium-ticket"), "AT1", "bad_ticket")  # 2
        if not ticket_fields_ok(ticket):
            raise Refused("bad_ticket")
        self._check_ticket(ticket, now)
        grant_token, obo = h.get("atrium-grant"), h.get("atrium-on-behalf-of")  # 3
        grant = None
        if grant_token is not None:
            grant = self._open(grant_token, "AG1", "grant_mismatch")
            if not grant_fields_ok(grant):
                raise Refused("grant_mismatch")
        date, nonce, signature = h.get("atrium-date"), h.get("atrium-nonce"), h.get("atrium-signature")
        if not all(isinstance(v, str) for v in (date, nonce, signature)) or not DATE_RE.match(date or "") \
                or not B64U_RE.match(nonce or "") or not 16 <= len(nonce or "") <= 64 \
                or (obo is not None and not QUESTION_ID_RE.match(obo)):
            raise Refused("bad_signature")
        path = CALL_PREFIX + action + ("?" + req.query if req.query else "")
        message = signing_string("POST", path, str(date), str(nonce), req.body, ticket["jti"],
                                 grant["jti"] if grant else None, obo)
        if not self._signature_ok(ticket["cnf"], signature, message):
            raise Refused("bad_signature")
        self._check_date(str(date), now)
        self._nonce(str(nonce), now)
        with self._lock:
            self._rate = {**DEFAULT_RATE, **ticket["rl"]}
        if ticket["mode"] == "probation" and action not in PROBATION_BUILTINS:  # 4
            raise Refused("probation")
        spec = self.spec(action)
        if action not in ticket["act"] or spec is None:
            raise Refused("action_not_allowed")
        params = validate_params(spec["params"], parse_body(req.body))  # 5
        if spec["risk"] in NEEDS_GRANT:  # 6
            if grant is None:
                self._missing_grant()
            else:
                self._check_grant(grant, action, req.body, now)
        user = None
        if obo is not None:  # 7
            user = self._on_behalf(obo, spec)
        with self._lock:  # 8
            while self._calls and self._calls[0] <= now - 60:
                self._calls.popleft()
            if len(self._calls) >= int(ticket["rl"].get("calls_per_min", DEFAULT_RATE["calls_per_min"])):
                raise Refused("rate_limited")
            self._calls.append(now)
        granted = grant if grant is not None and spec["risk"] in NEEDS_GRANT else None
        if granted is not None and not self.grants.mark(granted["jti"], granted["exp"] + GRANT_JTI_KEEP, now):
            raise Refused("grant_used")  # single use: marked (atomically) before the handler runs
        ctx = Context(action=action, principal=self.principal, user=user, question_id=obo,
                      grant_jti=granted["jti"] if granted else None, native=req.native)
        return _Call(action, spec, params, ctx, ticket, granted)

    # the steps a broken bridge would get wrong, as methods (the conformance tests break them one at a time)

    def _open(self, token: Any, prefix: str, code: str) -> Dict[str, Any]:
        return verify_token(token, prefix, self.keys, code)

    def _check_ticket(self, p: Mapping[str, Any], now: int) -> None:
        if p["tool"] != self.tool or p["sub"] != self.sub or p["iat"] > now + CLOCK_LEEWAY:
            raise Refused("bad_ticket")
        if p["exp"] <= now - CLOCK_LEEWAY:
            raise Refused("expired")

    def _signature_ok(self, cnf: str, signature: Any, message: bytes) -> bool:
        return verify_signature(cnf, signature, message)

    def _check_date(self, date: str, now: int) -> None:
        if abs(int(date) - now) > CLOCK_LEEWAY:
            raise Refused("expired")

    def _nonce(self, nonce: str, now: int) -> None:
        self.nonces.add(nonce, now)

    def _missing_grant(self) -> None:
        raise Refused("grant_required")

    def _check_grant(self, p: Mapping[str, Any], action: str, body: bytes, now: int) -> None:
        if p["tool"] != self.tool or p["sub"] != self.sub or p["act"] != action \
                or not hmac.compare_digest(p["bh"].encode(), body_hash(body).encode()):
            raise Refused("grant_mismatch")
        if p["exp"] <= now - CLOCK_LEEWAY:
            raise Refused("expired")
        if self.grants.used(p["jti"]):
            raise Refused("grant_used")

    def _on_behalf(self, question_id: str, spec: Mapping[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._sweep(int(self.clock()))
            q = self._questions.get(question_id)
            # only read and propose actions act for a tool user, whatever a local manifest says
            if q is None or not q.open() or spec.get("on_behalf_of") is not True \
                    or spec.get("risk") not in ("read", "propose"):
                raise Refused("forbidden_on_behalf")
            return dict(q.user)

    def _source_allowed(self, remote: Optional[str]) -> bool:
        try:
            address = ipaddress.ip_address(str(remote or "").split("%")[0])
        except ValueError:
            return False
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address.version == net.version and address in net for net in self.allow)

    # ---- running ----

    def _builtin(self, call: _Call) -> Any:
        action, params, now = call.action, call.params, int(self.clock())
        if action == "atrium.ping":
            return {"tool": self.tool, "contract": CONTRACT, "core": CORE_VERSION,
                    "manifest_sha256": self.manifest_sha256(), "time": now, "drops": self.drops,
                    "rejected": self.rejected}
        if action == "atrium.describe":
            return json.loads(self.manifest_raw.decode("utf-8"))
        if action == "atrium.noop_write":
            return {"executed": True, "echo": params["echo"]}
        if action == "atrium.receipt":
            found = self.grants.receipt(params["jti"])
            if found is None:
                return {"status": "unused"}
            # used, but the bridge stopped before recording the outcome: it may have run - never "unused"
            return {"status": "unknown" if found["status"] == "started" else found["status"], "at": found["at"]}
        if action == "atrium.panel.pull":
            return self._pull_questions(now)
        if action == "atrium.panel.answer":
            return self._panel_answer(params, now)
        if action == "atrium.events.pull":
            return self._pull_events(params.get("after", 0), now)
        raise KeyError(action)

    def _is_empty(self, call: _Call, result: Any) -> bool:
        if call.action == "atrium.panel.pull":
            return not result
        return call.action == "atrium.events.pull" and not result["events"]

    def _run_sync(self, call: _Call) -> Tuple[Any, str]:
        if call.action in BUILTINS:
            result = self._builtin(call)
            deadline = time.monotonic() + min(call.params.get("wait", 0), self.sync_wait, self.max_wait)
            while self._is_empty(call, result) and time.monotonic() < deadline:
                time.sleep(0.2)
                result = self._builtin(call)
            return result, "executed"
        token = _CAUSE.set(call.ctx.grant_jti)
        try:
            result = self.actions[call.action](call.params, call.ctx)
            if inspect.isawaitable(result):
                getattr(result, "close", lambda: None)()
                raise TypeError("an async handler in a synchronous server")
            return result, "executed"
        except Exception:
            log.exception("Atrium bridge: the handler of %s failed", call.action)
            return None, "failed"
        finally:
            _CAUSE.reset(token)

    async def _run_async(self, call: _Call) -> Tuple[Any, str]:
        if call.action in BUILTINS:
            result = self._builtin(call)
            deadline = time.monotonic() + min(call.params.get("wait", 0), self.max_wait)
            while self._is_empty(call, result) and time.monotonic() < deadline:
                await asyncio.sleep(0.2)
                result = self._builtin(call)
            return result, "executed"
        handler = self.actions[call.action]
        token = _CAUSE.set(call.ctx.grant_jti)
        try:
            if inspect.iscoroutinefunction(handler) or inspect.iscoroutinefunction(getattr(handler, "__call__", None)):
                result = await handler(call.params, call.ctx)
            else:
                ctx = contextvars.copy_context()
                result = await asyncio.get_running_loop().run_in_executor(None, ctx.run, handler, call.params, call.ctx)
                if inspect.isawaitable(result):
                    result = await result
            return result, "executed"
        except Exception:
            log.exception("Atrium bridge: the handler of %s failed", call.action)
            return None, "failed"
        finally:
            _CAUSE.reset(token)

    def _finish(self, call: _Call, result: Any, status: str) -> Response:
        now = int(self.clock())
        receipt = None
        if call.grant is not None:  # 10
            self.grants.record(call.grant["jti"], status, now)
            receipt = {"jti": call.grant["jti"], "status": status, "at": now}
        if status == "failed":
            return _answer(500, {"ok": False, "code": "failed", "receipt": receipt})
        try:
            answer = _answer(200, {"ok": True, "result": result, "receipt": receipt})
        except (TypeError, ValueError, RecursionError):
            log.error("Atrium bridge: the result of %s is not JSON", call.action)
            return _answer(500, {"ok": False, "code": "bad_result", "receipt": receipt})
        if len(answer.body) > MAX_RESPONSE:
            return _answer(500, {"ok": False, "code": "result_too_large", "receipt": receipt})
        return answer

    # ---- the panel ----

    def _resolve_user_sync(self, req: Request) -> Optional[Dict[str, Any]]:
        if self.current_user is None:
            return None
        value = self.current_user(req.native)
        if inspect.isawaitable(value):
            getattr(value, "close", lambda: None)()
            log.error("Atrium bridge: an async current_user hook in a synchronous server")
            return None
        return _user(value)

    def _panel_for(self, user: Optional[Dict[str, Any]]) -> bool:
        return self.panel_on and user is not None and (
            not self.panel_roles or any(r in self.panel_roles for r in user["roles"]))

    def _panel(self, req: Request, user: Optional[Dict[str, Any]]) -> Response:
        if req.headers.get(PANEL_HEADER) != "1":
            raise Refused("panel_header_required")
        if user is None:
            raise Refused("no_session")
        now = int(self.clock())
        with self._lock:
            self._sweep(now)
            online = self._last_pull is not None and now - self._last_pull < PANEL_ONLINE_WINDOW
        if req.path == PANEL_STATUS_PATH:
            return _answer(200, {"enabled": self._panel_for(user), "team_online": bool(online)})
        if not self._panel_for(user):
            raise Refused("not_found")
        if req.path.startswith(PANEL_QUESTION_PREFIX):
            with self._lock:
                q = self._questions.get(req.path[len(PANEL_QUESTION_PREFIX):])
                if q is None or q.user["id"] != user["id"]:
                    raise Refused("not_found")
                out = {"id": q.id, "status": q.status, "text": q.text, "asked_at": q.asked_at}
                if q.answer is not None:
                    out.update(answer=q.answer, by=q.by)
            return _answer(200, out)
        return self._ask(req, user, now)

    def _ask(self, req: Request, user: Dict[str, Any], now: int) -> Response:
        if req.oversize or len(req.body) > MAX_BODY:
            raise Refused("too_large")
        data = parse_json(req.body)
        if not isinstance(data, dict) or set(data) - {"text", "page"}:
            raise Refused("bad_params")
        text = data.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > PANEL_TEXT_MAX:
            raise Refused("bad_params")
        page = data.get("page")
        if page is not None:
            limits = {"path": PANEL_PAGE_PATH_MAX, "record_id": PANEL_RECORD_MAX}
            if not isinstance(page, dict) or set(page) - set(limits) \
                    or any(not isinstance(v, str) or len(v) > limits[k] for k, v in page.items()):
                raise Refused("bad_params")
            page = {k: TEXT_CONTROL.sub("", v) for k, v in page.items()}
        with self._lock:
            asked = self._asked.setdefault(user["id"], deque())
            while asked and asked[0] <= now - 3600:
                asked.popleft()
            if len(asked) >= int(self._rate.get("panel_per_user_hour", DEFAULT_RATE["panel_per_user_hour"])):
                raise Refused("rate_limited")
            if sum(1 for q in self._questions.values() if q.open()) >= PANEL_OPEN_MAX:
                raise Refused("busy")
            asked.append(now)
            qid = "q_" + secrets.token_urlsafe(12)
            self._questions[qid] = _Question(qid, dict(user), TEXT_CONTROL.sub("", text.strip()), page, now,
                                             updated_at=now)
        return _answer(200, {"question_id": qid})

    def _sweep(self, now: int) -> None:
        """Expire old questions; when the team has not pulled for 2 minutes, answer the open ones "unavailable"."""
        for qid in [q.id for q in self._questions.values() if q.asked_at + PANEL_EXPIRY <= now]:
            del self._questions[qid]
        for user_id in [u for u, asked in self._asked.items() if not asked or asked[-1] <= now - 3600]:
            del self._asked[user_id]
        if self._last_pull is not None and now - self._last_pull < PANEL_OFFLINE_ANSWER:
            return
        for q in self._questions.values():
            if q.open() and now - max(q.updated_at, self._last_pull or 0) >= PANEL_OFFLINE_ANSWER:
                q.status, q.answer, q.by, q.updated_at = "unavailable", PANEL_UNAVAILABLE, "Atrium", now

    def _pull_questions(self, now: int) -> List[Dict[str, Any]]:
        with self._lock:
            self._last_pull = now
            self._sweep(now)
            out = []
            for q in self._questions.values():
                if q.status == "waiting" and len(out) < PANEL_PULL_MAX:
                    q.status, q.updated_at = "answering", now
                    out.append({"id": q.id, "text": q.text, "tool_user": dict(q.user), "page": q.page,
                                "asked_at": q.asked_at})
            return out

    def _panel_answer(self, params: Mapping[str, Any], now: int) -> Dict[str, Any]:
        with self._lock:
            q = self._questions.get(params["question_id"])
            if q is None or not q.open():
                return {"ok": False}
            q.status = "answering" if params["status"] == "working" else params["status"]
            q.answer, q.updated_at = TEXT_CONTROL.sub("", params["text"]), now
            q.by = TEXT_CONTROL.sub("", params.get("by") or "") or None
            return {"ok": True}

    # ---- events ----

    def emit(self, name: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """Queue a declared event for the team; never blocks and never raises. False when it was not queued: an
        undeclared name, a payload that is not a JSON object of at most 16 KiB, or a full outbox (counted in drops)."""
        try:
            names = (self.manifest.get("events") or {}).get("names", []) if self.ready else []
            raw = json.dumps(dict(payload or {}), ensure_ascii=False, allow_nan=False)
            if name not in names or len(raw.encode("utf-8")) > EVENT_PAYLOAD_MAX:
                self.rejected += 1
                return False
            now = int(self.clock())
            event: Dict[str, Any] = {"name": name, "payload": json.loads(raw), "at": now}
            if _CAUSE.get():
                event["cause"] = {"jti": _CAUSE.get()}
            with self._lock:
                while self._events and self._events[0]["at"] <= now - OUTBOX_TTL:
                    self._events.popleft()
                if len(self._events) >= OUTBOX_MAX:
                    self.drops += 1
                    return False
                self._seq += 1
                self._events.append({"seq": self._seq, **event})
            return True
        except Exception:
            self.rejected += 1
            return False

    def _pull_events(self, after: int, now: int) -> Dict[str, Any]:
        with self._lock:
            if after > self._seq:  # the bridge restarted since: deliver from the start
                after = 0
            while self._events and (self._events[0]["seq"] <= after or self._events[0]["at"] <= now - OUTBOX_TTL):
                self._events.popleft()
            out = [dict(e) for e in list(self._events)[:EVENTS_PULL_MAX]]
            return {"events": out, "next": out[-1]["seq"] if out else after}


def _read(source: Any, name: str) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    if source is not None:
        return Path(source).read_bytes()
    here = Path(__file__).resolve().parent
    for folder in (here, here.parent, here.parent.parent, Path.cwd()):
        if (folder / name).is_file():
            return (folder / name).read_bytes()
    raise FileNotFoundError(name)


def bridge_for(glue: Any) -> Bridge:
    """The bridge of a glue module (or object): built once from its `actions`, `current_user`, `service_principal`
    and optional MANIFEST, PANEL_JS and GRANT_STORE; a Bridge is returned as it is."""
    if isinstance(glue, Bridge):
        return glue
    with _GLUE_LOCK:
        found = _BY_GLUE.get(id(glue))
        if found is not None and found[0] is glue:
            return found[1]
        bridge = Bridge(actions=getattr(glue, "actions", None) or getattr(glue, "ACTIONS", None),
                        current_user=getattr(glue, "current_user", None),
                        service_principal=getattr(glue, "service_principal", "atrium-team"),
                        manifest=getattr(glue, "MANIFEST", None), panel_js=getattr(glue, "PANEL_JS", None),
                        grants=getattr(glue, "GRANT_STORE", None), nonces=getattr(glue, "NONCE_STORE", None),
                        sync_wait=getattr(glue, "SYNC_WAIT", 0))
        _BY_GLUE[id(glue)] = (glue, bridge)
        return bridge


def emit(name: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
    """atrium_bridge.emit(name, payload): queue an event declared in atrium-bridge.json for the team. Never blocks,
    never raises; False when it was not queued (no bridge configured, undeclared name, too large, outbox full)."""
    try:
        return _DEFAULT[0].emit(name, payload) if _DEFAULT else False
    except Exception:
        return False
