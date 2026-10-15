"""The bridge contract ``atrium-bridge/1`` - the Python reference implementation (contract/SPEC.md is the normative
text, contract/vectors.json the cross-language test vectors, built by scripts/build_bridge_vectors.py).

A bridge (in the tool's own code) holds only Atrium's public Ed25519 keys. Atrium signs short-lived **tickets** (the
actions a sidecar may call, bound to the sidecar's key) and single-use **grants** (one approved write, bound to the exact
request body). Every sidecar call carries a request signature made with the sidecar's own key (proof of possession),
so a stolen ticket or a sniffed request is useless.

Shared by Atrium and the sidecar: dependency-free apart from ``cryptography`` (no hub imports).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import random
import re
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

CONTRACT = "atrium-bridge/1"
TICKET_PREFIX = "AT1"
GRANT_PREFIX = "AG1"

# routes, relative to the tool's main application (4.1, 4.2)
API_PREFIX = "/.atrium/v1"
HEALTH_PATH = "/.atrium/v1/health"
CALL_PREFIX = "/.atrium/v1/call/"
PANEL_JS_PATH = "/.atrium/panel.js"
PANEL_ASK_PATH = "/.atrium/v1/panel/ask"
PANEL_QUESTION_PREFIX = "/.atrium/v1/panel/questions/"
PANEL_STATUS_PATH = "/.atrium/v1/panel/status"
PANEL_HEADER = "X-Atrium-Panel"

# the bridge's environment (4.1): every value is public
ENV_KEYS, ENV_TOOL, ENV_SUBSIDIARY = "ATRIUM_BRIDGE_KEYS", "ATRIUM_TOOL_ID", "ATRIUM_SUBSIDIARY_ID"
ENV_PANEL, ENV_PANEL_ROLES, ENV_ALLOW = "ATRIUM_PANEL", "ATRIUM_PANEL_ROLES", "ATRIUM_BRIDGE_ALLOW"

# request headers (4.6)
H_TICKET, H_DATE, H_NONCE = "Atrium-Ticket", "Atrium-Date", "Atrium-Nonce"
H_GRANT, H_ON_BEHALF, H_SIGNATURE = "Atrium-Grant", "Atrium-On-Behalf-Of", "Atrium-Signature"

# limits (seconds, bytes, counts)
CLOCK_LEEWAY = 60  # tickets, grants and Atrium-Date are accepted within +-60 s
NONCE_TTL = 180
NONCE_CAPACITY = 10_000
GRANT_TTL = 600
GRANT_JTI_KEEP = 3600  # a used grant jti is kept until exp + 1 h
TICKET_MINUTES = 10  # default ticket lifetime (guardrail subsidiary_ticket_minutes, 1-60)
MAX_TOKEN_PAYLOAD = 4096
MAX_TOKEN = 6144  # characters of a ticket or grant header
MAX_KEYS = 2
MAX_BODY = 64 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_MANIFEST = 128 * 1024
MAX_ACTIONS = 40
MAX_PROPOSED_ACTIONS = 12  # what Claude may propose in a survey
MAX_PROPERTIES = 20
MAX_STRING = 10_000
MAX_ITEMS = 100
MAX_ENUM = 100
MAX_EVENTS = 30
MAX_FILES = 64
MAX_SAFE_INT = 2**53 - 1  # integers stay exact in every bridge language (JavaScript numbers)
WAIT_MAX = 25  # long-poll seconds
VECTOR_TTL = 60  # conformance vectors expire 60 s after they are built
DEFAULT_RATE = {"calls_per_min": 30, "panel_per_user_hour": 10}
CONFORMANCE_RATE = {"calls_per_min": 120, "panel_per_user_hour": 10}

# the panel and the events outbox (4.10, 4.11)
PANEL_TEXT_MAX, PANEL_PAGE_PATH_MAX, PANEL_RECORD_MAX = 2000, 300, 120
PANEL_ANSWER_MAX, PANEL_BY_MAX = 4000, 80
PANEL_OPEN_MAX = 200
PANEL_EXPIRY = 30 * 60
PANEL_ONLINE_WINDOW = 60  # team_online: a ticketed atrium.panel.pull less than 60 s ago
PANEL_OFFLINE_ANSWER = 120  # queued questions are answered "unavailable" after 2 minutes without the team
PANEL_UNAVAILABLE = "The team is not available right now"
PANEL_BANNER = "AI team supervised by Atrium. It can look things up and draft; changes need approval in Atrium."
PANEL_STATUSES = ("waiting", "answering", "answered", "escalated", "declined", "unavailable")
OUTBOX_MAX = 1000
OUTBOX_TTL = 24 * 3600
EVENT_PAYLOAD_MAX = 16 * 1024

# answers of a refused call (4.8): {"ok": false, "code": <code>} with this HTTP status
STATUS = {
    "bad_ticket": 401, "bad_signature": 401, "expired": 401, "replay": 401,
    "action_not_allowed": 403, "probation": 403, "grant_required": 403, "grant_mismatch": 403,
    "forbidden_on_behalf": 403, "source_not_allowed": 403,
    "grant_used": 409, "too_large": 413, "bad_params": 422, "rate_limited": 429,
    "not_configured": 503, "busy": 503,
}
# the panel routes' own refusals (a tool user's browser, never the sidecar)
PANEL_STATUS = {"no_session": 401, "panel_header_required": 403, "not_found": 404, "too_large": 413,
                "bad_params": 422, "rate_limited": 429, "busy": 503, "not_configured": 503}

RISKS = ("read", "propose", "write", "admin")
RISK_RANK = {r: n for n, r in enumerate(RISKS)}
CATEGORIES = ("data", "content", "workflow", "config", "notify", "other")
MODES = ("probation", "active")
NEEDS_GRANT = ("write", "admin")

ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9_.]{2,57}$")
TOOL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SUBSIDIARY_ID_RE = re.compile(r"^sub_[0-9a-f]{12}$")
PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
PRINCIPAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,79}$")
CORE_RE = re.compile(r"^[a-z][a-z0-9-]{0,19}/[0-9][0-9A-Za-z.+-]{0,31}$")
DATE_RE = re.compile(r"^[0-9]{1,12}$")
QUESTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")
TEXT_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")

# stacks (5.2); the ones with a vendored core map to its family
STACKS = ("python-fastapi", "python-starlette", "python-flask", "python-wsgi", "python-asgi", "node-express",
          "node-connect", "go-nethttp", "php", "java")
OTHER_STACK_RE = re.compile(r"^other:[a-z0-9+#.-]{1,20}$")
CORE_FAMILIES = {"python": ("python-fastapi", "python-starlette", "python-flask", "python-wsgi", "python-asgi"),
                 "node": ("node-express", "node-connect"), "go": ("go-nethttp",)}

# built-in actions (4.9): every bridge has them; ids under "atrium." are reserved for them


def _object(properties: dict[str, Any] | None = None, required: Iterable[str] = ()) -> dict[str, Any]:
    return {"type": "object", "additionalProperties": False, "properties": dict(properties or {}),
            "required": list(required)}


BUILTINS: dict[str, dict[str, Any]] = {
    "atrium.ping": {"risk": "read", "params": _object()},
    "atrium.describe": {"risk": "read", "params": _object()},
    "atrium.noop_write": {"risk": "write", "params": _object({"echo": {"type": "string", "maxLength": 64}}, ["echo"])},
    "atrium.receipt": {"risk": "read", "params": _object({"jti": {"type": "string", "maxLength": 64}}, ["jti"])},
    "atrium.panel.pull": {"risk": "read",
                          "params": _object({"wait": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX}})},
    "atrium.panel.answer": {"risk": "propose", "params": _object({
        "question_id": {"type": "string", "maxLength": 64},
        "text": {"type": "string", "maxLength": PANEL_ANSWER_MAX},
        "status": {"enum": ["answered", "escalated", "declined", "working"]},
        "by": {"type": "string", "maxLength": PANEL_BY_MAX}}, ["question_id", "text", "status"])},
    "atrium.events.pull": {"risk": "read", "params": _object({
        "after": {"type": "integer", "minimum": 0, "maximum": MAX_SAFE_INT},
        "wait": {"type": "integer", "minimum": 0, "maximum": WAIT_MAX}})},
}
PROBATION_BUILTINS = ("atrium.ping", "atrium.describe", "atrium.noop_write", "atrium.receipt")
PANEL_BUILTINS = ("atrium.panel.pull", "atrium.panel.answer")
EVENTS_BUILTINS = ("atrium.events.pull",)

# model-facing tool names (6.5): act__<action id with "." as "-"> (ids have no "-", so the mapping is reversible)
ACT_PREFIX = "act__"
HUB_TOOL_PREFIX = "atrium__"
REPORT_TOOL = "atrium__report"
ESCALATE_TOOL = "atrium__escalate"
TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# risk floors (4.4). A keyword matches a word (words(): ids and titles split at anything but letters and digits) that
# starts with it, also after one of COMPOUND ("unpublish", "softdelete", "email", "runscript"); "eval$" only whole
# ("eval", "evals") so "evaluation" stays allowed.
COMPOUND = ("un", "re", "e", "soft", "hard", "force", "auto", "bulk", "mass", "batch", "run", "raw", "db")
ADMIN_WORDS = ("delete", "remove", "purge", "drop", "destroy", "config", "setting", "send", "email", "mail", "notify",
               "publish", "invite", "pay", "refund", "transfer", "webhook")
WRITE_WORDS = ("create", "update", "set", "assign", "close", "open", "move", "merge", "archive", "import")
ADMIN_CATEGORIES = ("config", "notify")

# forbidden actions (4.4), by rule
CODE_WORDS = ("exec", "eval$", "shell", "script", "sql", "plugin")
CODE_PHRASES = (("query", "raw"), ("template", "render"))
BULK_WORDS = ("export", "backup", "dump", "bulk")
BULK_PHRASES = (("download", "all"),)
SECRET_RESOURCES = frozenset({"sessions", "session", "tokens", "token", "apikeys", "apikey", "api_keys", "api_key",
                              "secrets", "secret", "passwords", "password", "credentials", "credential"})
IDENTITY_RESOURCES = frozenset({"users", "user", "roles", "role", "permissions", "permission", "sso", "mfa", "auth"})
SECURITY_RESOURCES = frozenset({"audit_log", "audit_logs", "audit", "audits", "logging", "security", "integrations",
                                "integration", "webhooks", "webhook", "bridge", "bridges", "atrium"})
FREE_FORM_PARAMS = frozenset({"cmd", "command", "shell", "script", "code", "sql", "query", "eval", "exec",
                              "expression", "template", "url", "uri", "path", "file", "filename", "host"})
# in string parameters these (and their plurals) are refused anywhere in the name too ("file_path", "callback_url",
# "hostnames"); "code" and "query" only as the whole name ("zip_code" is fine)
_FREE_WORDS = (FREE_FORM_PARAMS - {"code", "query"}) | {"hostname", "filepath"}
FREE_FORM_WORDS = frozenset(_FREE_WORDS | {w + "s" for w in _FREE_WORDS})
FORBIDDEN_RULES = {
    "code_execution": "code execution",
    "bulk_data": "bulk data",
    "secrets": "secrets",
    "identity": "changes to who can do what",
    "security": "security and integration settings",
    "free_form_param": "a free-form parameter",
}


# --------------------------------------------------------------------------------------
# errors
# --------------------------------------------------------------------------------------


class Refused(Exception):
    """A bridge refusal: ``code`` from STATUS. Its answer never echoes request content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code
        self.status = STATUS.get(code) or PANEL_STATUS[code]

    def body(self) -> dict[str, Any]:
        return {"ok": False, "code": self.code}


class ManifestError(ValueError):
    """A bridge manifest or catalog that breaks the contract; ``problems`` name the action and the rule."""

    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


# --------------------------------------------------------------------------------------
# encodings and keys
# --------------------------------------------------------------------------------------


def b64u(data: bytes) -> str:
    """base64url without padding (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    """Strict base64url without padding: only the alphabet, canonical (the unused trailing bits are zero)."""
    if not isinstance(text, str) or not B64U_RE.match(text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if b64u(data) != text:
        raise ValueError("not canonical base64url")
    return data


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_key(seed: bytes | None = None) -> Ed25519PrivateKey:
    """A new Ed25519 key; from a 32-byte seed when given (tests and vectors only)."""
    return Ed25519PrivateKey.from_private_bytes(seed) if seed is not None else Ed25519PrivateKey.generate()


def private_b64(key: Ed25519PrivateKey) -> str:
    return b64u(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption()))


def private_key(text: str) -> Ed25519PrivateKey:
    raw = b64u_decode(text)
    if len(raw) != 32:
        raise ValueError("an Ed25519 private key is 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_b64(key: Ed25519PrivateKey | Ed25519PublicKey) -> str:
    pub = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return b64u(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def public_key(text: str) -> Ed25519PublicKey:
    raw = b64u_decode(text)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_keys(value: str | None) -> list[Ed25519PublicKey]:
    """ATRIUM_BRIDGE_KEYS: one or two base64url public keys (current, next), comma-separated. ValueError when missing
    or unparseable - the bridge then fails closed (503 not_configured)."""
    items = [k.strip() for k in str(value or "").split(",") if k.strip()]
    if not 1 <= len(items) <= MAX_KEYS:
        raise ValueError(f"{ENV_KEYS} holds one or two keys")
    return [public_key(k) for k in items]


def fingerprint(public: str) -> str:
    """How people recognise a public key: "SHA256:" and the base64 SHA-256 of its raw bytes, as OpenSSH shows keys."""
    raw = b64u_decode(public)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def new_jti(rng: random.Random | None = None) -> str:
    return b64u(rng.randbytes(16) if rng is not None else secrets.token_bytes(16))


new_nonce = new_jti


# --------------------------------------------------------------------------------------
# tickets and grants (4.5, 4.7)
# --------------------------------------------------------------------------------------


def _int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _sign_token(prefix: str, payload: dict[str, Any], key: Ed25519PrivateKey) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(raw) > MAX_TOKEN_PAYLOAD:
        raise ValueError(f"a {prefix} payload is at most {MAX_TOKEN_PAYLOAD} bytes")
    signed = f"{prefix}.{b64u(raw)}"
    return f"{signed}.{b64u(key.sign(signed.encode('ascii')))}"


def _open(token: Any, prefix: str, keys: list[Ed25519PublicKey], code: str) -> dict[str, Any]:
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
    signed = f"{parts[0]}.{parts[1]}".encode("ascii")
    for key in keys[:MAX_KEYS]:
        try:
            key.verify(signature, signed)
            break
        except InvalidSignature:
            continue
    else:
        raise Refused(code)
    try:
        raw = b64u_decode(parts[1])
        if len(raw) > MAX_TOKEN_PAYLOAD:
            raise ValueError("too large")
        payload = json.loads(raw.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused(code) from None
    if not isinstance(payload, dict) or not _int(payload.get("v")) or payload["v"] != 1:
        raise Refused(code)
    return payload


def make_ticket(key: Ed25519PrivateKey, *, sub: str, tool: str, cv: int, mode: str, act: Iterable[str], cnf: str,
                rl: Mapping[str, int] | None = None, now: int | None = None, ttl: int = TICKET_MINUTES * 60,
                jti: str | None = None) -> tuple[str, dict[str, Any]]:
    """A ticket (AT1) and its payload: the actions a sidecar holding the key `cnf` may call until exp."""
    if mode not in MODES:
        raise ValueError(f"mode is one of {MODES}")
    iat = int(time.time() if now is None else now)
    payload = {"v": 1, "typ": "ticket", "sub": sub, "tool": tool, "cv": int(cv), "mode": mode,
               "act": list(dict.fromkeys(act)), "cnf": cnf, "rl": dict(rl or DEFAULT_RATE), "iat": iat,
               "exp": iat + int(ttl), "jti": jti or new_jti()}
    return _sign_token(TICKET_PREFIX, payload, key), payload


def open_ticket(token: Any, keys: list[Ed25519PublicKey]) -> dict[str, Any]:
    """The ticket's payload once its signature verifies under a configured key and its fields are well formed
    (401 bad_ticket otherwise). Not yet checked against the bridge's tool, subsidiary or clock: check_ticket."""
    p = _open(token, TICKET_PREFIX, keys, "bad_ticket")
    rl = p.get("rl")
    ok = (p.get("typ") == "ticket" and isinstance(p.get("sub"), str) and isinstance(p.get("tool"), str)
          and _int(p.get("cv")) and p.get("mode") in MODES and isinstance(p.get("act"), list)
          and len(p["act"]) <= MAX_ACTIONS + len(BUILTINS) and all(isinstance(a, str) for a in p["act"])
          and isinstance(p.get("cnf"), str) and _int(p.get("iat")) and _int(p.get("exp"))
          and isinstance(p.get("jti"), str) and 0 < len(p["jti"]) <= 64
          and isinstance(rl, dict) and all(_int(v) and v >= 0 for v in rl.values()))
    if not ok:
        raise Refused("bad_ticket")
    try:
        public_key(p["cnf"])
    except ValueError:
        raise Refused("bad_ticket") from None
    return p


def check_ticket(p: Mapping[str, Any], *, tool: str, sub: str, now: int) -> None:
    if p["tool"] != tool or p["sub"] != sub or p["iat"] > now + CLOCK_LEEWAY:
        raise Refused("bad_ticket")
    if p["exp"] <= now - CLOCK_LEEWAY:
        raise Refused("expired")


def verify_ticket(token: Any, keys: list[Ed25519PublicKey], *, tool: str, sub: str,
                  now: int | None = None) -> dict[str, Any]:
    p = open_ticket(token, keys)
    check_ticket(p, tool=tool, sub=sub, now=int(time.time() if now is None else now))
    return p


def body_hash(body: bytes) -> str:
    """The grant's ``bh``: base64url SHA-256 of the exact request body bytes."""
    return b64u(hashlib.sha256(body).digest())


def make_grant(key: Ed25519PrivateKey, *, sub: str, tool: str, cv: int, act: str, body: bytes, apv: str,
               now: int | None = None, ttl: int = GRANT_TTL, jti: str | None = None) -> tuple[str, dict[str, Any]]:
    """A grant (AG1) and its payload: one call of `act` with exactly `body`, approved by `apv` (an approval id or
    "auto"), until exp; single use."""
    iat = int(time.time() if now is None else now)
    payload = {"v": 1, "typ": "grant", "sub": sub, "tool": tool, "cv": int(cv), "act": act, "bh": body_hash(body),
               "apv": apv, "iat": iat, "exp": iat + int(ttl), "jti": jti or new_jti()}
    return _sign_token(GRANT_PREFIX, payload, key), payload


def open_grant(token: Any, keys: list[Ed25519PublicKey]) -> dict[str, Any]:
    """The grant's payload once its signature verifies (403 grant_mismatch otherwise). The bridge opens a grant while
    building the signing string (it needs the jti); check_grant does the rest of step 6."""
    p = _open(token, GRANT_PREFIX, keys, "grant_mismatch")
    ok = (p.get("typ") == "grant" and isinstance(p.get("sub"), str) and isinstance(p.get("tool"), str)
          and _int(p.get("cv")) and isinstance(p.get("act"), str) and isinstance(p.get("bh"), str)
          and isinstance(p.get("apv"), str) and _int(p.get("iat")) and _int(p.get("exp"))
          and isinstance(p.get("jti"), str) and 0 < len(p["jti"]) <= 64)
    if not ok:
        raise Refused("grant_mismatch")
    return p


def check_grant(p: Mapping[str, Any], *, tool: str, sub: str, action: str, body: bytes, now: int,
                used: Callable[[str], bool] | None = None) -> None:
    if p["tool"] != tool or p["sub"] != sub or p["act"] != action \
            or not hmac.compare_digest(p["bh"].encode(), body_hash(body).encode()):
        raise Refused("grant_mismatch")
    if p["exp"] <= now - CLOCK_LEEWAY:
        raise Refused("expired")
    if used is not None and used(p["jti"]):
        raise Refused("grant_used")


def verify_grant(token: Any, keys: list[Ed25519PublicKey], *, tool: str, sub: str, action: str, body: bytes,
                 now: int | None = None, used: Callable[[str], bool] | None = None) -> dict[str, Any]:
    p = open_grant(token, keys)
    check_grant(p, tool=tool, sub=sub, action=action, body=body, now=int(time.time() if now is None else now),
                used=used)
    return p


def ticket_actions(mode: str, actions: Iterable[str] = (), *, panel: bool = False, events: bool = False) -> list[str]:
    """What a ticket lists (4.5): probation - the four probation built-ins; active - the charter's actions (never a
    forbidden or reserved id), those built-ins, and the panel and events built-ins when the charter enables them."""
    if mode == "probation":
        return list(PROBATION_BUILTINS)
    own = [a for a in actions if ACTION_ID_RE.match(a) and not a.startswith("atrium.")]
    return list(dict.fromkeys([*own, *PROBATION_BUILTINS, *(PANEL_BUILTINS if panel else ()),
                               *(EVENTS_BUILTINS if events else ())]))


# --------------------------------------------------------------------------------------
# request signatures (4.6) and the replay window
# --------------------------------------------------------------------------------------


def call_path(action_id: str, query: str = "") -> str:
    """The path a call is signed over: the contract path, whatever prefix the tool is served under."""
    return f"{CALL_PREFIX}{action_id}" + (f"?{query}" if query else "")


def signing_string(method: str, path: str, date: str | int, nonce: str, body: bytes, ticket_jti: str,
                   grant_jti: str | None = None, on_behalf_of: str | None = None) -> bytes:
    """The nine lines a request signature covers, joined by "\\n" (no trailing newline), UTF-8."""
    lines = [CONTRACT, method.upper(), path, str(date), nonce, sha256_hex(body), ticket_jti, grant_jti or "-",
             on_behalf_of or "-"]
    if any("\n" in line or "\r" in line for line in lines):
        raise ValueError("signing string fields are single lines")
    return "\n".join(lines).encode("utf-8")


def sign(key: Ed25519PrivateKey, message: bytes) -> str:
    return b64u(key.sign(message))


def verify_signature(cnf: str, signature: Any, message: bytes) -> bool:
    try:
        public_key(cnf).verify(b64u_decode(signature), message)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def call_headers(key: Ed25519PrivateKey, *, ticket: str, ticket_jti: str, path: str, body: bytes,
                 date: int | None = None, nonce: str | None = None, grant: str | None = None,
                 grant_jti: str | None = None, on_behalf_of: str | None = None, method: str = "POST") -> dict[str, str]:
    """The headers of a signed call (the sidecar's side); `key` is the private key matching the ticket's cnf."""
    date = int(time.time()) if date is None else int(date)
    nonce = nonce or new_nonce()
    headers = {"Content-Type": "application/json", H_TICKET: ticket, H_DATE: str(date), H_NONCE: nonce}
    if grant:
        headers[H_GRANT] = grant
    if on_behalf_of:
        headers[H_ON_BEHALF] = on_behalf_of
    headers[H_SIGNATURE] = sign(key, signing_string(method, path, date, nonce, body, ticket_jti, grant_jti,
                                                    on_behalf_of))
    return headers


def check_date(date: Any, now: int) -> None:
    """Atrium-Date: decimal unix seconds within +-60 s (401 expired outside it, bad_signature when malformed)."""
    if not isinstance(date, str) or not DATE_RE.match(date):
        raise Refused("bad_signature")
    if abs(int(date) - now) > CLOCK_LEEWAY:
        raise Refused("expired")


class NonceCache:
    """Seen nonces for NONCE_TTL seconds, at most `capacity` of them: a full cache refuses (503 busy) rather than
    forget a nonce that could still be replayed."""

    def __init__(self, ttl: int = NONCE_TTL, capacity: int = NONCE_CAPACITY):
        self.ttl, self.capacity = ttl, capacity
        self._seen: OrderedDict[str, float] = OrderedDict()

    def __len__(self) -> int:
        return len(self._seen)

    def add(self, nonce: str, now: float) -> None:
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


class UsedGrants:
    """The used-grant store interface, in memory (bridges persist it where the tool has storage)."""

    def __init__(self) -> None:
        self._until: dict[str, int] = {}

    def used(self, jti: str) -> bool:
        return jti in self._until

    def mark(self, jti: str, exp: int, now: int) -> None:
        self._until = {j: t for j, t in self._until.items() if t > now}
        self._until[jti] = exp + GRANT_JTI_KEEP


# --------------------------------------------------------------------------------------
# params: the JSON Schema subset (4.3) and the call body
# --------------------------------------------------------------------------------------


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _schema_kind(prop: Any) -> str | None:
    if not isinstance(prop, dict):
        return None
    if "enum" in prop:
        return "enum"
    return prop.get("type") if prop.get("type") in ("string", "integer", "boolean", "array") else None


def _scalar_problems(name: str, prop: Any, *, item: bool = False) -> list[str]:
    kind = _schema_kind(prop)
    where = f"{name}[]" if item else name
    if kind is None or (item and kind == "array"):
        return [f"{where}: types are string, integer, boolean, enum{'' if item else ' or array'} (no objects, "
                "floats or $ref)"]
    allowed = {"description"} | {"string": {"type", "maxLength", "minLength"}, "integer": {"type", "minimum", "maximum"},
                                 "boolean": {"type"}, "enum": {"type", "enum"}, "array": {"type", "items", "maxItems"}
                                 }[kind]
    extra = sorted(set(prop) - allowed)
    if extra:
        return [f"{where}: {', '.join(extra)} not allowed"]
    if not isinstance(prop.get("description", ""), str) or len(prop.get("description", "")) > 500:
        return [f"{where}: description is text of at most 500 characters"]
    if kind == "string":
        top, low = prop.get("maxLength"), prop.get("minLength", 0)
        if not _int(top) or not 1 <= top <= MAX_STRING or not _int(low) or not 0 <= low <= top:
            return [f"{where}: strings need maxLength 1-{MAX_STRING} (and minLength <= maxLength)"]
    elif kind == "integer":
        lo, hi = prop.get("minimum", -MAX_SAFE_INT), prop.get("maximum", MAX_SAFE_INT)
        if not _int(lo) or not _int(hi) or not -MAX_SAFE_INT <= lo <= hi <= MAX_SAFE_INT:
            return [f"{where}: minimum and maximum are integers within +-(2^53-1), minimum <= maximum"]
    elif kind == "enum":
        values = prop["enum"]
        strings = isinstance(values, list) and values and all(isinstance(v, str) and len(v) <= 200 for v in values)
        ints = isinstance(values, list) and values and all(_int(v) and abs(v) <= MAX_SAFE_INT for v in values)
        if not (strings or ints) or len(values) > MAX_ENUM or len(set(values)) != len(values):
            return [f"{where}: enum is 1-{MAX_ENUM} distinct strings or integers"]
        if "type" in prop and prop["type"] != ("string" if strings else "integer"):
            return [f"{where}: enum type does not match its values"]
    elif kind == "array":
        top = prop.get("maxItems")
        if not _int(top) or not 1 <= top <= MAX_ITEMS:
            return [f"{where}: arrays need maxItems 1-{MAX_ITEMS}"]
        return _scalar_problems(name, prop.get("items"), item=True)
    return []


def schema_problems(schema: Any) -> list[str]:
    """What breaks the params subset: an object with additionalProperties false, at most 20 properties, each a string
    (maxLength), integer, boolean, enum, or an array of those (maxItems)."""
    if not isinstance(schema, dict) or schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        return ["params must be {type: object, additionalProperties: false, properties: {...}}"]
    extra = sorted(set(schema) - {"type", "additionalProperties", "properties", "required", "description"})
    if extra:
        return [f"params: {', '.join(extra)} not allowed"]
    props, required = schema.get("properties", {}), schema.get("required", [])
    if not isinstance(props, dict) or len(props) > MAX_PROPERTIES:
        return [f"params: at most {MAX_PROPERTIES} properties"]
    problems = [f"parameter name '{n}' is not allowed" for n in props if not isinstance(n, str) or not PARAM_NAME_RE.match(n)]
    if not isinstance(required, list) or any(r not in props for r in required) or len(set(required)) != len(required):
        problems.append("params: required lists properties, once each")
    for name, prop in props.items():
        problems += _scalar_problems(str(name), prop)
    return problems


def _value(prop: dict[str, Any], value: Any) -> tuple[bool, Any]:
    kind = _schema_kind(prop)
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
        value = int(value)  # 1.0 and 1e2 are integers: JavaScript cannot tell them apart
    if kind == "integer":
        ok = _int(value) and prop.get("minimum", -MAX_SAFE_INT) <= value <= prop.get("maximum", MAX_SAFE_INT)
        return ok and abs(value) <= MAX_SAFE_INT, value
    if kind == "enum":
        return (isinstance(value, str) or (_int(value) and abs(value) <= MAX_SAFE_INT)) and value in prop["enum"], value
    return False, None


def validate_params(schema: Mapping[str, Any], params: Any) -> dict[str, Any]:
    """`params` checked against an action's schema (422 bad_params on any problem), with integral numbers as integers.
    String lengths count Unicode code points; null is never a value."""
    if not isinstance(params, dict):
        raise Refused("bad_params")
    props = schema.get("properties", {})
    if any(k not in props for k in params) or any(r not in params for r in schema.get("required", [])):
        raise Refused("bad_params")
    out: dict[str, Any] = {}
    for key, value in params.items():
        ok, out[key] = _value(props[key], value)
        if not ok:
            raise Refused("bad_params")
    return out


def body_bytes(params: Mapping[str, Any]) -> bytes:
    """The one serialization of a call body (Atrium serializes once, nobody re-serializes it)."""
    return json.dumps({"params": dict(params)}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_body(body: bytes) -> dict[str, Any]:
    """The params of a call body: UTF-8 JSON whose only member is "params", an object (422 bad_params otherwise)."""
    if len(body) > MAX_BODY:
        raise Refused("too_large")
    try:
        data = json.loads(body.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("bad_params") from None
    if not isinstance(data, dict) or set(data) != {"params"} or not isinstance(data["params"], dict):
        raise Refused("bad_params")
    return data["params"]


# --------------------------------------------------------------------------------------
# the manifest (4.3), floors and forbidden actions (4.4)
# --------------------------------------------------------------------------------------


def words(text: Any) -> list[str]:
    """Lowercase words of an id or a title: split at anything but letters and digits, and at lower-to-upper changes."""
    return re.findall(r"[a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or "")).lower())


def _match(word: str, keyword: str) -> bool:
    whole, key = keyword.endswith("$"), keyword.rstrip("$")
    for prefix in ("", *COMPOUND):
        if word.startswith(prefix):
            rest = word[len(prefix):]
            if rest and (rest in (key, key + "s") if whole else rest.startswith(key)):
                return True
    return False


def _hit(found: list[str], keywords: Iterable[str]) -> str | None:
    return next((k.rstrip("$") for w in found for k in keywords if _match(w, k)), None)


def _phrase(found: list[str], phrases: Iterable[tuple[str, ...]]) -> str | None:
    for phrase in phrases:
        n = len(phrase)
        if any(tuple(found[i:i + n]) == phrase for i in range(len(found) - n + 1)):
            return "_".join(phrase)
    return None


def floor_reason(action: Mapping[str, Any]) -> tuple[str, str | None]:
    """The heuristic floor of an action and why: admin for deletes, configuration, outbound messages, payments and
    anything with an external effect; write for changes."""
    found = words(action.get("id")) + words(action.get("title"))
    if action.get("external_effect"):
        return "admin", "it has an external effect"
    if action.get("category") in ADMIN_CATEGORIES:
        return "admin", f"its category is {action['category']}"
    if k := _hit(found, ADMIN_WORDS):
        return "admin", f"its id or title says '{k}'"
    if k := _hit(found, WRITE_WORDS):
        return "write", f"its id or title says '{k}'"
    return "read", None


def risk_floor(action: Mapping[str, Any]) -> str:
    """max(declared risk, heuristic floor): a bridge can never lower a floor."""
    declared = action.get("risk") if action.get("risk") in RISK_RANK else "admin"
    floor = floor_reason(action)[0]
    return max(declared, floor, key=RISK_RANK.__getitem__)


def forbidden(action: Mapping[str, Any]) -> tuple[str, str] | None:
    """(rule, reason) when an action may never be in a manifest or a charter, whatever its risk; None otherwise."""
    action_id = str(action.get("id") or "")
    resource = action_id.split(".")[0]
    found = words(action_id) + words(action.get("title"))
    if k := (_hit(found, CODE_WORDS) or _phrase(found, CODE_PHRASES)):
        return "code_execution", f"'{action_id}' says '{k}': no code execution"
    if k := (_hit(found, BULK_WORDS) or _phrase(found, BULK_PHRASES)):
        return "bulk_data", f"'{action_id}' says '{k}': no bulk data"
    if resource in SECRET_RESOURCES:
        return "secrets", f"'{action_id}' works on {resource}: secrets are never reachable"
    if resource in IDENTITY_RESOURCES and risk_floor(action) != "read":
        return "identity", f"'{action_id}' changes {resource}: reading is allowed, changing who can do what is not"
    if resource in SECURITY_RESOURCES:
        return "security", f"'{action_id}' works on {resource}: security and integration settings are off limits"
    props = (action.get("params") or {}).get("properties") or {}
    for name, prop in props.items() if isinstance(props, dict) else ():
        snake = "_".join(words(name))
        stringy = _schema_kind(prop) == "string" or (_schema_kind(prop) == "array"
                                                     and _schema_kind((prop or {}).get("items")) == "string")
        if snake in FREE_FORM_PARAMS or str(name).lower() in FREE_FORM_PARAMS \
                or (stringy and any(w in FREE_FORM_WORDS for w in words(name))):
            return "free_form_param", f"'{action_id}' has a parameter '{name}': no free-form escape hatches"
    return None


ACTION_KEYS = {"id", "title", "description", "risk", "category", "reversible", "external_effect", "on_behalf_of",
               "params"}


def _text_ok(value: Any, limit: int, *, empty: bool = False) -> bool:
    return isinstance(value, str) and (empty or value.strip() != "") and len(value) <= limit \
        and not TEXT_CONTROL.search(value)


def action_problems(action: Any) -> list[str]:
    """Structure only (no floors, no forbidden rules): what a manifest action must look like."""
    if not isinstance(action, dict):
        return ["an action is an object"]
    aid = action.get("id")
    where = f"action '{aid}'" if isinstance(aid, str) else "an action"
    problems = []
    if not isinstance(aid, str) or not ACTION_ID_RE.match(aid):
        problems.append(f"{where}: ids are 3-58 characters: a-z first, then a-z, 0-9, '_' and '.'")
    elif aid.startswith("atrium."):
        problems.append(f"{where}: ids under 'atrium.' are reserved for the built-ins")
    if extra := sorted(set(action) - ACTION_KEYS):
        problems.append(f"{where}: unknown fields {', '.join(extra)}")
    if not _text_ok(action.get("title"), 80):
        problems.append(f"{where}: a title of 1-80 characters (plain text)")
    if not _text_ok(action.get("description", ""), 500, empty=True):
        problems.append(f"{where}: a description of at most 500 characters (plain text)")
    if action.get("risk") not in RISKS:
        problems.append(f"{where}: risk is one of {', '.join(RISKS)}")
    if action.get("category", "other") not in CATEGORIES:
        problems.append(f"{where}: category is one of {', '.join(CATEGORIES)}")
    for flag in ("reversible", "external_effect", "on_behalf_of"):
        if not isinstance(action.get(flag, False), bool):
            problems.append(f"{where}: {flag} is true or false")
    problems += [f"{where}: {p}" for p in schema_problems(action.get("params"))]
    return problems


def normalized_action(action: Mapping[str, Any]) -> dict[str, Any]:
    return {"id": action["id"], "title": action["title"].strip(), "description": action.get("description", "").strip(),
            "risk": action["risk"], "category": action.get("category", "other"),
            "reversible": action.get("reversible", False), "external_effect": action.get("external_effect", False),
            "on_behalf_of": action.get("on_behalf_of", False),
            "params": {"required": [], **action["params"]}}


@dataclass
class Catalog:
    """A proposed action catalog after Atrium's checks: the actions kept (risks at their floors), the ones removed
    (forbidden, invalid, duplicate or over the limit) and the risks raised."""

    actions: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)  # {id, rule, reason}
    raised: list[dict[str, Any]] = field(default_factory=list)  # {id, declared, risk, reason}


def check_catalog(actions: Any, *, limit: int = MAX_PROPOSED_ACTIONS) -> Catalog:
    """Validate a proposed catalog (5.2): forbidden actions are removed and reported, risks are raised to their floors
    (on-behalf-of is dropped from an action raised above propose)."""
    out = Catalog()
    seen: set[str] = set()
    for raw in actions if isinstance(actions, list) else []:
        aid = raw.get("id") if isinstance(raw, dict) else None
        if problems := action_problems(raw):
            out.removed.append({"id": aid if isinstance(aid, str) else None, "rule": "invalid", "reason": problems[0]})
            continue
        if aid in seen:
            out.removed.append({"id": aid, "rule": "duplicate", "reason": f"'{aid}' is listed twice"})
            continue
        if hit := forbidden(raw):
            out.removed.append({"id": aid, "rule": hit[0], "reason": hit[1]})
            continue
        if len(out.actions) >= limit:
            out.removed.append({"id": aid, "rule": "limit", "reason": f"at most {limit} actions"})
            continue
        action = normalized_action(raw)
        risk = risk_floor(action)
        if risk != action["risk"]:
            out.raised.append({"id": aid, "declared": action["risk"], "risk": risk,
                               "reason": floor_reason(action)[1] or ""})
            action["risk"] = risk
        if RISK_RANK[risk] > RISK_RANK["propose"]:
            action["on_behalf_of"] = False
        seen.add(aid)
        out.actions.append(action)
    return out


MANIFEST_KEYS = {"contract", "tool_id", "stack", "core", "service_principal", "panel", "events", "files", "actions"}


def safe_relative(path: Any) -> bool:
    """A repository-relative file path without "..", absolute parts, backslashes or control characters."""
    if not isinstance(path, str) or not path or len(path) > 300 or path.startswith("/") or "\\" in path \
            or TEXT_CONTROL.search(path) or re.match(r"^[A-Za-z]:", path):
        return False
    return all(part not in ("", ".", "..") for part in path.split("/"))


def load_manifest(raw: bytes | str | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(data) > MAX_MANIFEST:
        raise ManifestError([f"the manifest is larger than {MAX_MANIFEST} bytes"])
    try:
        value = json.loads(data.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ManifestError([f"atrium-bridge.json is not JSON ({type(exc).__name__})"]) from None
    if not isinstance(value, dict):
        raise ManifestError(["atrium-bridge.json is a JSON object"])
    return value


def validate_manifest(raw: bytes | str | Mapping[str, Any], *, tool_id: str | None = None) -> dict[str, Any]:
    """The bridge manifest (atrium-bridge.json) checked against every rule of 4.3 and 4.4: a forbidden action, or a
    declared risk below its floor, refuses the manifest (and therefore the patch). Returns it with defaults filled."""
    m = load_manifest(raw)
    problems: list[str] = []
    if extra := sorted(set(m) - MANIFEST_KEYS):
        problems.append(f"unknown fields {', '.join(extra)}")
    if m.get("contract") != CONTRACT:
        problems.append(f"contract must be '{CONTRACT}'")
    tid = m.get("tool_id")
    if not isinstance(tid, str) or not TOOL_ID_RE.match(tid) or (tool_id is not None and tid != tool_id):
        problems.append(f"tool_id must be '{tool_id}'" if tool_id else "tool_id is a tool id")
        tid = tool_id or ""
    stack = m.get("stack")
    if not (stack in STACKS or (isinstance(stack, str) and OTHER_STACK_RE.match(stack))):
        problems.append(f"stack is one of {', '.join(STACKS)} or other:<language>")
    if not isinstance(m.get("core"), str) or not CORE_RE.match(m["core"]):
        problems.append("core is <family>/<version>, e.g. python/1.0.0")
    if not isinstance(m.get("service_principal", "atrium-team"), str) \
            or not PRINCIPAL_RE.match(m.get("service_principal", "atrium-team")):
        problems.append("service_principal is the in-app user the bridge acts as")
    panel = m.get("panel", {"enabled": False})
    if not isinstance(panel, dict) or set(panel) - {"enabled"} or not isinstance(panel.get("enabled", False), bool):
        problems.append("panel is {enabled: true|false}")
    events = m.get("events", {"names": []})
    names = events.get("names", []) if isinstance(events, dict) else None
    event_re = re.compile(rf"^{re.escape(tid)}\.[a-z0-9_.-]{{1,60}}$")
    if not isinstance(names, list) or set(events) - {"names"} or len(names) > MAX_EVENTS \
            or len(set(map(str, names))) != len(names) \
            or not all(isinstance(n, str) and event_re.match(n) for n in names):
        problems.append(f"events.names: at most {MAX_EVENTS} distinct names '<tool_id>.<event>' "
                        "(a-z, 0-9, '_', '.', '-')")
    files = m.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_FILES or not all(safe_relative(f) for f in files) \
            or "atrium-bridge.json" not in files:
        problems.append(f"files lists 1-{MAX_FILES} relative paths the bridge adds or owns, atrium-bridge.json "
                        "included")
    actions = m.get("actions", [])
    if not isinstance(actions, list) or len(actions) > MAX_ACTIONS:
        problems.append(f"actions: at most {MAX_ACTIONS}")
        actions = []
    seen: set[str] = set()
    normalized = []
    for action in actions:
        if found := action_problems(action):
            problems += found
            continue
        aid = action["id"]
        if aid in seen:
            problems.append(f"action '{aid}' is listed twice")
        seen.add(aid)
        if hit := forbidden(action):
            problems.append(f"action '{aid}' is forbidden ({FORBIDDEN_RULES[hit[0]]}): {hit[1]}")
        floor, why = floor_reason(action)
        if RISK_RANK[action["risk"]] < RISK_RANK[floor]:
            problems.append(f"action '{aid}': risk {action['risk']} is below its floor {floor} ({why})")
        if action.get("on_behalf_of") and RISK_RANK[risk_floor(action)] > RISK_RANK["propose"]:
            problems.append(f"action '{aid}': only read and propose actions act on behalf of a tool user")
        normalized.append(normalized_action(action))
    if problems:
        raise ManifestError(problems)
    return {"contract": CONTRACT, "tool_id": m["tool_id"], "stack": stack, "core": m["core"],
            "service_principal": m.get("service_principal", "atrium-team"), "panel": {"enabled": panel.get("enabled", False)},
            "events": {"names": list(names)}, "files": list(files), "actions": normalized}


def manifest_sha256(raw: bytes) -> str:
    """The SHA-256 (hex) of the raw bytes of atrium-bridge.json - there is no canonical JSON in the contract."""
    return sha256_hex(raw)


def action_spec(manifest: Mapping[str, Any], action_id: str) -> dict[str, Any] | None:
    """A built-in's or the manifest's definition of an action (risk, params, ...)."""
    if action_id in BUILTINS:
        return {"id": action_id, **BUILTINS[action_id]}
    return next((a for a in manifest.get("actions", []) if a.get("id") == action_id), None)


def core_family(stack: str) -> str | None:
    """The vendored core a stack uses (python, node, go), or None: Claude writes the core, conformance gates it."""
    return next((family for family, stacks in CORE_FAMILIES.items() if stack in stacks), None)


# --------------------------------------------------------------------------------------
# model-facing tool names (6.5)
# --------------------------------------------------------------------------------------


def tool_name(action_id: str) -> str:
    """act__<id> with "." as "-" (at most 63 characters)."""
    return ACT_PREFIX + action_id.replace(".", "-")


def action_of(name: str) -> str | None:
    """The action id of an act__ tool name, or None."""
    if not isinstance(name, str) or not name.startswith(ACT_PREFIX):
        return None
    aid = name[len(ACT_PREFIX):].replace("-", ".")
    return aid if ACTION_ID_RE.match(aid) and not aid.startswith("atrium.") else None


def hub_tool_name(tool: str) -> str:
    return HUB_TOOL_PREFIX + tool


def hub_tool_of(name: str) -> str | None:
    """The hub tool of an atrium__<tool> name (not report or escalate), or None."""
    if not isinstance(name, str) or not name.startswith(HUB_TOOL_PREFIX) or name in (REPORT_TOOL, ESCALATE_TOOL):
        return None
    tool = name[len(HUB_TOOL_PREFIX):]
    return tool if re.fullmatch(r"[a-z][a-z0-9_]{0,55}", tool) else None


# --------------------------------------------------------------------------------------
# conformance vectors (4.14)
# --------------------------------------------------------------------------------------


@dataclass
class Step:
    """One pre-signed HTTP request and the answer it must get. `path` is relative to the bridge's base URL."""

    method: str
    path: str
    headers: dict[str, str]
    body: bytes
    status: int
    code: str | None = None
    json: dict[str, Any] | None = None  # dotted paths into the answer -> expected values
    sha256: str | None = None  # of the answer body

    def to_json(self) -> dict[str, Any]:
        expect: dict[str, Any] = {"status": self.status}
        for key in ("code", "json", "sha256"):
            if getattr(self, key) is not None:
                expect[key] = getattr(self, key)
        return {"method": self.method, "path": self.path, "headers": dict(self.headers), "body_b64": b64u(self.body),
                "expect": expect}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "Step":
        e = data["expect"]
        return cls(method=data["method"], path=data["path"], headers=dict(data["headers"]),
                   body=b64u_decode(data["body_b64"]), status=e["status"], code=e.get("code"), json=e.get("json"),
                   sha256=e.get("sha256"))


@dataclass
class Vector:
    id: str
    title: str
    steps: list[Step]

    def to_json(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "steps": [s.to_json() for s in self.steps]}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "Vector":
        return cls(id=data["id"], title=data["title"], steps=[Step.from_json(s) for s in data["steps"]])


def _dig(value: Any, dotted: str) -> Any:
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return _MISSING
        value = value[part]
    return value


_MISSING = object()


def check_answer(step: Step, status: int, body: bytes) -> tuple[bool, str]:
    """Whether an answer meets a step's expectation, and a short detail (no answer content beyond the code)."""
    if status != step.status:
        return False, f"status {status}, expected {step.status}"
    if step.sha256 is not None and sha256_hex(body) != step.sha256:
        return False, "the body's SHA-256 differs"
    if step.code is None and step.json is None:
        return True, "ok"
    try:
        data = json.loads(body.decode("utf-8")) if len(body) <= MAX_RESPONSE else None
    except (ValueError, UnicodeError):
        data = None
    if not isinstance(data, dict):
        return False, "the answer is not a JSON object"
    if step.code is not None and data.get("code") != step.code:
        code = data.get("code")
        return False, f"code {code if isinstance(code, str) and re.fullmatch(r'[a-z_]{1,40}', code) else '?'}, " \
                      f"expected {step.code}"
    for dotted, expected in (step.json or {}).items():
        if _dig(data, dotted) != expected:
            return False, f"{dotted} is not {expected!r}"
    return True, "ok"


def sample_params(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Params valid for an action's schema that name nothing likely to exist: its required properties only, integers
    at their maximum, strings and enums at their first allowed value, arrays empty, booleans false."""
    out: dict[str, Any] = {}
    for name in schema.get("required", []):
        prop = (schema.get("properties") or {})[name]
        kind = _schema_kind(prop)
        if kind == "enum":
            out[name] = prop["enum"][0]
        elif kind == "integer":
            out[name] = prop.get("maximum", MAX_SAFE_INT)
        elif kind == "string":
            text = "atrium-conformance"
            out[name] = (text * (1 + prop.get("minLength", 0) // len(text)))[:prop["maxLength"]]
        else:
            out[name] = [] if kind == "array" else False
    return out


GUARD_RATE = {"calls_per_min": 0, "panel_per_user_hour": CONFORMANCE_RATE["panel_per_user_hour"]}
GUARD_QUESTION = "atrium-conformance-probe"  # an on-behalf-of question no bridge has


def build_vectors(key: Ed25519PrivateKey, *, tool: str, sub: str, manifest: Mapping[str, Any], manifest_sha: str,
                  panel_sha: str | None, now: int | None = None, rng: random.Random | None = None,
                  cv: int = 0) -> list[Vector]:
    """V1-V20: complete pre-signed requests, in order (the replay and single-use vectors depend on it). Tickets are
    probation tickets signed with the subsidiary's `key` (or a random key where a vector needs one) for an ephemeral
    probe key, so nobody else can use them; they expire VECTOR_TTL seconds after `now`. `rng` makes the keys, nonces
    and jtis reproducible (scripts/build_bridge_vectors.py); by default they are random.

    V12 and V13 also probe every write and admin action of the manifest with an active ticket that lists only that
    action: without a grant, and with a grant for another body. Each such request names an on-behalf-of question no
    bridge has and its ticket allows no call a minute, so a core that skips the grant check (step 6) still refuses
    it (steps 7 and 8, with another code) instead of running the write."""
    rng = rng or random.SystemRandom()
    now = int(time.time() if now is None else now)
    probe, stranger = new_key(rng.randbytes(32)), new_key(rng.randbytes(32))
    cnf = public_b64(probe)

    def ticket(*, signer: Ed25519PrivateKey = key, act: Iterable[str] = PROBATION_BUILTINS, tool_: str = tool,
               sub_: str = sub, iat: int = now, ttl: int = VECTOR_TTL, mode: str = "probation",
               rl: Mapping[str, int] = CONFORMANCE_RATE) -> tuple[str, str]:
        token, p = make_ticket(signer, sub=sub_, tool=tool_, cv=cv, mode=mode, act=act, cnf=cnf, rl=rl, now=iat,
                               ttl=ttl, jti=new_jti(rng))
        return token, p["jti"]

    def call(action: str, params: Mapping[str, Any] | None = None, *, tk: tuple[str, str] | None = None,
             body: bytes | None = None, signed_body: bytes | None = None, date: int | None = None,
             signer: Ed25519PrivateKey = probe, grant: tuple[str, str] | None = None, status: int = 200,
             code: str | None = None, expect: dict[str, Any] | None = None, on_behalf_of: str | None = None) -> Step:
        token, tjti = tk or ticket()
        body = body_bytes(params or {}) if body is None else body
        path = call_path(action)
        headers = call_headers(signer, ticket=token, ticket_jti=tjti, path=path,
                               body=body if signed_body is None else signed_body, date=now if date is None else date,
                               nonce=new_nonce(rng), grant=grant[0] if grant else None,
                               grant_jti=grant[1] if grant else None, on_behalf_of=on_behalf_of)
        return Step("POST", path, headers, body, status, code, expect)

    def guarded(action: Mapping[str, Any], code: str, *, mismatched: bool = False) -> Step:
        """A manifest write or admin action a correct core refuses at step 6 (see above)."""
        body = body_bytes(sample_params(action.get("params") or {}))
        return call(action["id"], body=body, tk=ticket(act=[action["id"]], mode="active", rl=GUARD_RATE),
                    grant=grant(action["id"], body + b" ") if mismatched else None, on_behalf_of=GUARD_QUESTION,
                    status=STATUS[code], code=code)

    def grant(action: str = "atrium.noop_write", body: bytes = b"", *, tool_: str = tool) -> tuple[str, str]:
        token, p = make_grant(key, sub=sub, tool=tool_, cv=cv, act=action, body=body, apv="conformance", now=now,
                              ttl=VECTOR_TTL, jti=new_jti(rng))
        return token, p["jti"]

    echo = body_bytes({"echo": "conformance"})
    other = body_bytes({"echo": "something else"})
    first = next((a["id"] for a in manifest.get("actions", [])), "atrium.events.pull")
    writes = [a for a in manifest.get("actions", []) if a.get("risk") in NEEDS_GRANT]
    jose = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + b64u(json.dumps(
        {"v": 1, "typ": "ticket", "sub": sub, "tool": tool, "mode": "active"}).encode()) + "."
    no_ticket = Step("POST", call_path("atrium.ping"), {"Content-Type": "application/json"}, body_bytes({}), 401,
                     "bad_ticket")
    replayed = call("atrium.ping")
    granted = grant(body=echo)
    big = b'{"params":{"echo":"' + b"x" * (70 * 1024) + b'"}}'
    return [
        Vector("V1", "GET /health answers without authentication",
               [Step("GET", HEALTH_PATH, {}, b"", 200, None, {"status": "ok"})]),
        Vector("V2", "a call without a ticket is refused", [no_ticket]),
        Vector("V3", "a ticket signed with another key is refused",
               [call("atrium.ping", tk=ticket(signer=stranger), status=401, code="bad_ticket")]),
        Vector("V4", "a ticket for another tool, then for another subsidiary, is refused",
               [call("atrium.ping", tk=ticket(tool_=f"{tool}-other"), status=401, code="bad_ticket"),
                call("atrium.ping", tk=ticket(sub_="sub_000000000000" if sub != "sub_000000000000"
                                              else "sub_111111111111"), status=401, code="bad_ticket")]),
        Vector("V5", "an expired ticket is refused",
               [call("atrium.ping", tk=ticket(iat=now - 15 * 60, ttl=10 * 60), status=401, code="expired")]),
        Vector("V6", "a request signed with a key other than the ticket's cnf is refused",
               [call("atrium.ping", signer=stranger, status=401, code="bad_signature")]),
        Vector("V7", "a body changed after signing is refused",
               [call("atrium.receipt", body=body_bytes({"jti": "changed"}), signed_body=body_bytes({"jti": "signed"}),
                     status=401, code="bad_signature")]),
        Vector("V8", "the same request twice: the second is a replay",
               [replayed, Step(replayed.method, replayed.path, dict(replayed.headers), replayed.body, 401, "replay")]),
        Vector("V9", "a request dated 5 minutes ago is refused",
               [call("atrium.ping", date=now - 300, status=401, code="expired")]),
        Vector("V10", "a probation ticket cannot call a manifest action",
               [call(first, tk=ticket(act=[*PROBATION_BUILTINS, first]), status=403, code="probation")]),
        Vector("V11", "an action the ticket does not list is refused",
               [call("atrium.describe", tk=ticket(act=["atrium.ping"]), status=403, code="action_not_allowed")]),
        Vector("V12", "a write without a grant is refused (atrium.noop_write and each manifest write or admin action)",
               [call("atrium.noop_write", body=echo, status=403, code="grant_required"),
                *(guarded(a, "grant_required") for a in writes)]),
        Vector("V13", "a grant for another body is refused (atrium.noop_write and each manifest write or admin action)",
               [call("atrium.noop_write", body=echo, grant=grant(body=other), status=403, code="grant_mismatch"),
                *(guarded(a, "grant_mismatch", mismatched=True) for a in writes)]),
        Vector("V14", "a grant for another tool, then for another action, is refused",
               [call("atrium.noop_write", body=echo, grant=grant(body=echo, tool_=f"{tool}-other"), status=403,
                     code="grant_mismatch"),
                call("atrium.noop_write", body=echo, grant=grant("atrium.receipt", echo), status=403,
                     code="grant_mismatch")]),
        Vector("V15", "a valid grant is used once",
               [call("atrium.noop_write", body=echo, grant=granted,
                     expect={"ok": True, "result.executed": True, "result.echo": "conformance"}),
                call("atrium.noop_write", body=echo, grant=granted, status=409, code="grant_used")]),
        Vector("V16", "an unknown parameter is refused before anything runs",
               [call("atrium.receipt", {"jti": "x", "extra": 1}, status=422, code="bad_params")]),
        Vector("V17", "a 70 KiB body is refused", [call("atrium.ping", body=big, status=413, code="too_large")]),
        Vector("V18", "a JOSE-style ticket (alg none) is refused",
               [call("atrium.ping", tk=(jose, "jose"), status=401, code="bad_ticket")]),
        Vector("V19", "ping and describe answer with the approved manifest",
               [call("atrium.ping", expect={"ok": True, "result.contract": CONTRACT, "result.tool": tool,
                                            "result.manifest_sha256": manifest_sha}),
                call("atrium.describe", expect={"ok": True, "result.contract": CONTRACT, "result.tool_id": tool})]),
        Vector("V20", "panel.js is served byte-identical to the vendored widget",
               [Step("GET", PANEL_JS_PATH, {}, b"", 200, sha256=panel_sha)]),
    ]


# --------------------------------------------------------------------------------------
# the verification order as a reference (4.8): tests and vector self-checks; real bridges use the vendored cores
# --------------------------------------------------------------------------------------


class ReferenceBridge:
    """Steps 1-10 of 4.8 for /.atrium/v1/* calls, /health and /panel.js, in memory. `handlers`: action id ->
    handler(params, ctx) for the manifest's actions; `questions`: open panel question ids (on-behalf-of)."""

    def __init__(self, *, keys: str | None, tool: str, sub: str, manifest: bytes, panel_js: bytes | None = None,
                 handlers: Mapping[str, Callable[[dict[str, Any], dict[str, Any]], Any]] | None = None,
                 clock: Callable[[], float] = time.time):
        try:
            self.keys: list[Ed25519PublicKey] | None = parse_keys(keys)
        except ValueError:
            self.keys = None  # fail closed: every route but /health answers 503 not_configured
        self.tool, self.sub, self.manifest_raw, self.panel_js = tool, sub, manifest, panel_js
        self.manifest = json.loads(manifest.decode("utf-8"))
        self.handlers, self.clock = dict(handlers or {}), clock
        self.nonces, self.grants = NonceCache(), UsedGrants()
        self.receipts: dict[str, dict[str, Any]] = {}
        self.questions: set[str] = set()
        self.calls: list[float] = []
        self.drops = 0

    def handle(self, method: str, path: str, headers: Mapping[str, str], body: bytes) -> tuple[int, Any]:
        """(status, answer): a dict for JSON answers, bytes for panel.js."""
        try:
            return self._handle(method.upper(), path, {k.lower(): v for k, v in headers.items()}, body)
        except Refused as exc:
            return exc.status, exc.body()

    def _handle(self, method: str, path: str, h: dict[str, str], body: bytes) -> tuple[int, Any]:
        if method == "GET" and path == HEALTH_PATH:
            return 200, {"status": "ok"}
        if self.keys is None:
            raise Refused("not_configured")
        if method == "GET" and path == PANEL_JS_PATH and self.panel_js is not None:
            return 200, self.panel_js
        route, _, query = path.partition("?")
        if method != "POST" or not route.startswith(CALL_PREFIX):
            return 404, {"ok": False, "code": "not_found"}
        action = route[len(CALL_PREFIX):]
        now = int(self.clock())
        if len(body) > MAX_BODY:  # 1
            raise Refused("too_large")
        ticket = open_ticket(h.get(H_TICKET.lower()), self.keys)  # 2
        check_ticket(ticket, tool=self.tool, sub=self.sub, now=now)
        grant_token, obo = h.get(H_GRANT.lower()), h.get(H_ON_BEHALF.lower())  # 3
        grant = open_grant(grant_token, self.keys) if grant_token else None
        date, nonce, signature = h.get(H_DATE.lower()), h.get(H_NONCE.lower()), h.get(H_SIGNATURE.lower())
        if not all(isinstance(v, str) for v in (date, nonce, signature)) or not DATE_RE.match(date or "") \
                or not B64U_RE.match(nonce or "") or not 16 <= len(nonce or "") <= 64 \
                or (obo is not None and not QUESTION_ID_RE.match(obo)):
            raise Refused("bad_signature")
        message = signing_string("POST", call_path(action, query), date, nonce, body, ticket["jti"],
                                 grant["jti"] if grant else None, obo)
        if not verify_signature(ticket["cnf"], signature, message):
            raise Refused("bad_signature")
        check_date(date, now)
        self.nonces.add(nonce, now)
        if ticket["mode"] == "probation" and action not in PROBATION_BUILTINS:  # 4
            raise Refused("probation")
        spec = action_spec(self.manifest, action)
        if action not in ticket["act"] or spec is None:
            raise Refused("action_not_allowed")
        params = validate_params(spec["params"], parse_body(body))  # 5
        if spec["risk"] in NEEDS_GRANT:  # 6
            if grant is None:
                raise Refused("grant_required")
            check_grant(grant, tool=self.tool, sub=self.sub, action=action, body=body, now=now, used=self.grants.used)
        if obo is not None and (obo not in self.questions or not spec.get("on_behalf_of")):  # 7
            raise Refused("forbidden_on_behalf")
        self.calls = [t for t in self.calls if t > now - 60]  # 8
        if len(self.calls) >= int(ticket["rl"].get("calls_per_min", DEFAULT_RATE["calls_per_min"])):
            raise Refused("rate_limited")
        self.calls.append(now)
        if grant is not None and spec["risk"] in NEEDS_GRANT:  # single use: marked before the handler runs
            self.grants.mark(grant["jti"], grant["exp"], now)
        try:  # 9
            result = self._run(action, params, {"principal": self.manifest.get("service_principal", "atrium-team"),
                                                "on_behalf_of": obo, "grant_jti": grant["jti"] if grant else None})
            status = "executed"
        except Exception:
            result, status = None, "failed"
        receipt = None
        if grant is not None and spec["risk"] in NEEDS_GRANT:  # 10
            receipt = self.receipts[grant["jti"]] = {"jti": grant["jti"], "status": status, "at": now}
        if status == "failed":
            return 500, {"ok": False, "code": "failed", "receipt": receipt}
        return 200, {"ok": True, "result": result, "receipt": receipt}

    def _run(self, action: str, params: dict[str, Any], ctx: dict[str, Any]) -> Any:
        if action == "atrium.ping":
            return {"tool": self.tool, "contract": CONTRACT, "core": self.manifest.get("core"),
                    "manifest_sha256": manifest_sha256(self.manifest_raw), "time": int(self.clock()),
                    "drops": self.drops}
        if action == "atrium.describe":
            return self.manifest
        if action == "atrium.noop_write":
            return {"executed": True, "echo": params["echo"]}
        if action == "atrium.receipt":
            found = self.receipts.get(params["jti"])
            return {"status": found["status"], "at": found["at"]} if found else {"status": "unused"}
        if action in ("atrium.panel.pull", "atrium.events.pull"):
            return [] if action == "atrium.panel.pull" else {"events": [], "next": params.get("after", 0)}
        if action == "atrium.panel.answer":
            return {"ok": True}
        return self.handlers[action](params, ctx)
