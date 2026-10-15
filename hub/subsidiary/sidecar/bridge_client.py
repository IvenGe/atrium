"""Calls from the sidecar to the bridge in the tool (contract atrium-bridge/1, sections 4.5 to 4.9).

Every call carries the current ticket and a request signature made with the sidecar's own key (proof of possession).
Read and propose actions are called with params the sidecar serializes; a granted write is sent with EXACTLY the
body bytes Atrium returned with the grant (D5) - nobody re-serializes them. No redirects, 30 s timeout, answers of at
most 1 MiB, and the tool's network is not routed through an HTTP proxy.

The sidecar reads its own ticket's payload (jti, exp, actions) without verifying the signature: it got the ticket
from Atrium over verified TLS, and the bridge verifies it anyway.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import contract

TIMEOUT = 30.0
MAX_ANSWER = contract.MAX_RESPONSE


class BridgeError(Exception):
    """The bridge could not be called: no valid ticket, an action the ticket does not list, or no answer."""

    def __init__(self, code: str, message: str = ""):
        super().__init__(message or code)
        self.code = code


def token_payload(token: str, prefix: str) -> dict[str, Any]:
    """A ticket's or grant's payload, read without checking the signature (ValueError when malformed)."""
    parts = token.split(".") if isinstance(token, str) else []
    if len(parts) != 3 or parts[0] != prefix:
        raise ValueError(f"not an {prefix} token")
    payload = json.loads(contract.b64u_decode(parts[1]).decode("utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("jti"), str) \
            or not isinstance(payload.get("exp"), int):
        raise ValueError(f"not an {prefix} token")
    return payload


@dataclass
class Ticket:
    token: str
    jti: str
    exp: int
    mode: str
    act: tuple[str, ...]

    @classmethod
    def of(cls, token: str) -> "Ticket":
        p = token_payload(token, contract.TICKET_PREFIX)
        act = p.get("act")
        if not isinstance(act, list) or p.get("mode") not in contract.MODES:
            raise ValueError("not a ticket")
        return cls(token, p["jti"], p["exp"], p["mode"], tuple(a for a in act if isinstance(a, str)))


@dataclass
class Answer:
    """A bridge answer: its HTTP status and the JSON it sent (``ok``, ``result`` or ``code``, ``receipt``)."""

    status: int
    data: dict[str, Any]

    @property
    def ok(self) -> bool:
        return self.status == 200 and self.data.get("ok") is True

    @property
    def code(self) -> str | None:
        code = self.data.get("code")
        return code if isinstance(code, str) and code.isidentifier() and len(code) <= 40 else None

    @property
    def result(self) -> Any:
        return self.data.get("result")

    @property
    def receipt(self) -> dict[str, Any] | None:
        receipt = self.data.get("receipt")
        return receipt if isinstance(receipt, dict) else None

    def refusal(self) -> str:
        return f"the tool's bridge refused the call ({self.status} {self.code or 'error'})"


class BridgeClient:
    def __init__(self, url: str, key: Ed25519PrivateKey, *, transport: httpx.AsyncBaseTransport | None = None,
                 clock: Callable[[], float] = time.time):
        self.url, self.key, self.clock = url, key, clock
        self.http = httpx.AsyncClient(base_url=url.rstrip("/"), transport=transport, follow_redirects=False,
                                      timeout=TIMEOUT, trust_env=False)
        self.ticket: Ticket | None = None

    async def aclose(self) -> None:
        await self.http.aclose()

    def set_ticket(self, token: str) -> Ticket:
        self.ticket = Ticket.of(token)
        return self.ticket

    def valid(self) -> bool:
        return self.ticket is not None and self.ticket.exp > self.clock()

    def allows(self, action: str) -> bool:
        return self.valid() and action in self.ticket.act  # type: ignore[union-attr]

    async def _send(self, method: str, path: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        try:
            async with self.http.stream(method, path, headers=headers, content=body or None) as answer:
                data = b""
                async for chunk in answer.aiter_bytes():
                    data += chunk
                    if len(data) > MAX_ANSWER:
                        raise BridgeError("too_large", "the bridge's answer is larger than 1 MiB")
                return answer.status_code, data
        except httpx.HTTPError as exc:
            raise BridgeError("unreachable", f"the tool's bridge is unreachable ({exc.__class__.__name__})") from None

    async def send(self, action: str, body: bytes, *, grant: str | None = None,
                   on_behalf_of: str | None = None) -> Answer:
        """One signed call of `action` with these exact body bytes."""
        if not self.valid():
            raise BridgeError("no_ticket", "the sidecar holds no valid ticket (Atrium has not issued one)")
        if action not in self.ticket.act:  # type: ignore[union-attr]
            raise BridgeError("action_not_allowed", f"the ticket does not list {action}")
        grant_jti = token_payload(grant, contract.GRANT_PREFIX)["jti"] if grant else None
        path = contract.call_path(action)
        headers = contract.call_headers(self.key, ticket=self.ticket.token, ticket_jti=self.ticket.jti,  # type: ignore
                                        path=path, body=body, date=int(self.clock()), grant=grant,
                                        grant_jti=grant_jti, on_behalf_of=on_behalf_of)
        status, raw = await self._send("POST", path, headers, body)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeError):
            data = None
        if not isinstance(data, dict):
            data = {"ok": False, "code": "bad_answer"}
        return Answer(status, data)

    async def call(self, action: str, params: dict[str, Any] | None = None, *,
                   on_behalf_of: str | None = None) -> Answer:
        return await self.send(action, contract.body_bytes(params or {}), on_behalf_of=on_behalf_of)

    async def health(self) -> bool:
        try:
            status, _ = await self._send("GET", contract.HEALTH_PATH, {}, b"")
        except BridgeError:
            return False
        return status == 200

    async def step(self, step: contract.Step) -> tuple[int, bytes]:
        """A conformance step, sent verbatim (method, path, headers, body)."""
        return await self._send(step.method, step.path, dict(step.headers), step.body)
