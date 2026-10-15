"""The sidecar's HTTPS client for Atrium's sidecar API (/api/subsidiary/v1/*, section 9.2).

- TLS verification is on (an optional CA file), with an optional pin of Atrium's certificate (``atrium_cert_sha256``):
  the pin is checked right after the TLS handshake, before a byte of the request - the token - is sent.
- No redirects; timeouts of 35 s for long-polls, 15 s otherwise and 5 minutes for a model turn; answers are capped
  (4 MiB from /model, 1 MiB otherwise).
- ``Authorization: Bearer`` once enrolled; enrolling sends ``X-Hub-Request: 1`` like any request without a token.
- Five 401s in a row end the process with exit code 3 (the token was revoked or expired, or its owner disabled);
  423 ``stopped`` ends it with 4.
- Requests that do work send ``Atrium-Charter-Version``, so Atrium answers 409 when the charter moved on.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
from typing import Any, Callable

import httpcore
import httpx

from .config import SidecarConfig

LONG_POLL_TIMEOUT = 35.0
TIMEOUT = 15.0
MODEL_TIMEOUT = 300.0
MAX_ANSWER = 1024 * 1024
MAX_MODEL_ANSWER = 4 * 1024 * 1024
UNAUTHORIZED_LIMIT = 5
H_CHARTER = "Atrium-Charter-Version"
EXIT_TOKEN, EXIT_STOPPED = 3, 4


class Exit(Exception):
    """End the sidecar with this exit code (3: the token no longer works; 4: Atrium stopped the subsidiary).
    `remember`: Atrium said so - the next start exits at once instead of asking again (runtime.py)."""

    def __init__(self, code: int, reason: str, *, remember: bool = False):
        super().__init__(reason)
        self.code, self.remember = code, remember


class AtriumError(Exception):
    """Atrium refused a request: its HTTP status, machine-readable code (when it gave one) and message."""

    def __init__(self, status: int, code: str | None, message: str = ""):
        super().__init__(message or code or f"HTTP {status}")
        self.status, self.code, self.message = status, code, message


class Unavailable(Exception):
    """Atrium could not be reached, or answered 5xx: try again later (with backoff)."""


class Backoff:
    """1 s doubling to 60 s, with jitter (each delay is 50 to 100 % of the step); reset after a success."""

    def __init__(self, first: float = 1.0, cap: float = 60.0, rng: random.Random | None = None):
        self.first, self.cap, self.rng, self.step = first, cap, rng or random.Random(), 0.0

    def next(self) -> float:
        self.step = self.first if self.step == 0 else min(self.cap, self.step * 2)
        return self.step * (0.5 + self.rng.random() / 2)

    def reset(self) -> None:
        self.step = 0.0


# --------------------------------------------------------------------------------------
# certificate pinning: checked in the TLS handshake, before the request is written
# --------------------------------------------------------------------------------------


def peer_matches(stream: Any, pin: str) -> bool:
    ssl_object = stream.get_extra_info("ssl_object")
    der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
    return bool(der) and hmac.compare_digest(hashlib.sha256(der).hexdigest(), pin)


class PinnedStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner: httpcore.AsyncNetworkStream, pin: str, host: str):
        self.inner, self.pin, self.host = inner, pin, host

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self.inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        await self.inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self.inner.aclose()

    async def start_tls(self, ssl_context: Any, server_hostname: str | None = None,
                        timeout: float | None = None) -> httpcore.AsyncNetworkStream:
        stream = await self.inner.start_tls(ssl_context, server_hostname, timeout)
        if server_hostname == self.host and not peer_matches(stream, self.pin):  # Atrium, not a proxy on the way
            await stream.aclose()
            raise httpcore.ConnectError("Atrium's certificate does not match atrium_cert_sha256")
        return PinnedStream(stream, self.pin, self.host)

    def get_extra_info(self, info: str) -> Any:
        return self.inner.get_extra_info(info)


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, inner: httpcore.AsyncNetworkBackend, pin: str, host: str):
        self.inner, self.pin, self.host = inner, pin, host

    async def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                          socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        stream = await self.inner.connect_tcp(host, port, timeout, local_address, socket_options)
        return PinnedStream(stream, self.pin, self.host)

    async def connect_unix_socket(self, path: str, timeout: float | None = None,
                                  socket_options: Any = None) -> httpcore.AsyncNetworkStream:
        return PinnedStream(await self.inner.connect_unix_socket(path, timeout, socket_options), self.pin, self.host)

    async def sleep(self, seconds: float) -> None:
        await self.inner.sleep(seconds)


def atrium_transport(config: SidecarConfig) -> httpx.AsyncHTTPTransport:
    """The real transport to Atrium: verified TLS (the CA file when set), pinned when configured."""
    transport = httpx.AsyncHTTPTransport(verify=config.ca_file or True)
    if config.atrium_cert_sha256:
        pool = getattr(transport, "_pool", None)
        if pool is None or not hasattr(pool, "_network_backend"):  # fail closed rather than skip the pin
            raise RuntimeError("this httpx version cannot pin certificates: remove atrium_cert_sha256 or upgrade")
        pool._network_backend = PinnedBackend(pool._network_backend, config.atrium_cert_sha256, config.atrium_host)
    return transport


# --------------------------------------------------------------------------------------
# the client
# --------------------------------------------------------------------------------------


def error_of(status: int, body: bytes) -> AtriumError:
    """An AtriumError from a refusal: FastAPI's {"detail": {"code", "message"} | "text" | [problems]}."""
    try:
        detail = json.loads(body.decode("utf-8")).get("detail")
    except (ValueError, UnicodeError, AttributeError):
        detail = None
    code = message = None
    if isinstance(detail, dict):
        code = detail.get("code") if isinstance(detail.get("code"), str) else None
        message = detail.get("message") if isinstance(detail.get("message"), str) else None
    elif isinstance(detail, str):
        message = detail
    elif isinstance(detail, list):
        message = "the request was not valid"
    return AtriumError(status, (code or "")[:40] or None, (message or "")[:300])


async def read_capped(answer: httpx.Response, limit: int) -> bytes:
    body = b""
    async for chunk in answer.aiter_bytes():
        body += chunk
        if len(body) > limit:
            raise Unavailable(f"the answer is larger than {limit} bytes")
    return body


class AtriumClient:
    def __init__(self, config: SidecarConfig, *, transport: httpx.AsyncBaseTransport | None = None,
                 token: str | None = None, charter_version: Callable[[], int | None] = lambda: None):
        self.config, self.token, self.charter_version = config, token, charter_version
        self.http = httpx.AsyncClient(base_url=config.api, transport=transport or atrium_transport(config),
                                      follow_redirects=False, timeout=TIMEOUT)
        self.unauthorized = 0
        self.on_exit: Callable[[Exit], None] | None = None  # the runtime ends its loops

    async def aclose(self) -> None:
        await self.http.aclose()

    def headers(self, *, cv: bool) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        else:
            headers["X-Hub-Request"] = "1"
        version = self.charter_version() if cv else None
        if version is not None:
            headers[H_CHARTER] = str(version)
        return headers

    async def call(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None,
                   timeout: float = TIMEOUT, limit: int = MAX_ANSWER, cv: bool = False,
                   extra_headers: dict[str, str] | None = None) -> tuple[int, Any, httpx.Headers]:
        """(status, parsed JSON or None, headers) for a 2xx or 304 answer; AtriumError for a refusal, Unavailable when
        Atrium cannot be reached or fails, Exit after five 401s in a row or on 423 stopped."""
        headers = {**self.headers(cv=cv), **(extra_headers or {})}
        content = None
        if json_body is not None:
            content = json.dumps(json_body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["Content-Type"] = "application/json"
        try:
            async with self.http.stream(method, path, content=content, params=params, headers=headers,
                                        timeout=timeout) as answer:
                body = await read_capped(answer, limit)
                status, answer_headers = answer.status_code, answer.headers
        except httpx.HTTPError as exc:
            raise Unavailable(f"Atrium is unreachable ({exc.__class__.__name__})") from None
        if status == 401:
            self.unauthorized += 1
            if self.unauthorized >= UNAUTHORIZED_LIMIT:
                raise self.exiting(Exit(EXIT_TOKEN, "Atrium refused the sidecar's token five times in a row: it was "
                                                    "revoked (a new enrollment, or Atrium stopped the subsidiary) or "
                                                    "expired, or its owner is no longer an administrator.",
                                        remember=True))
            raise error_of(status, body)
        self.unauthorized = 0
        if status >= 500:
            raise Unavailable(f"Atrium answered {status}")
        if status >= 400:
            error = error_of(status, body)
            if status == 423 and error.code == "stopped":
                raise self.exiting(Exit(EXIT_STOPPED, "Atrium stopped the subsidiary.", remember=True))
            raise error
        if 300 <= status < 400 and status != 304:  # redirects are never followed (the token stays with Atrium)
            raise AtriumError(status, "redirect", "Atrium answered with a redirect, which the sidecar does not follow")
        if status == 304 or not body:
            return status, None, answer_headers
        try:
            return status, json.loads(body.decode("utf-8")), answer_headers
        except (ValueError, UnicodeError):
            raise Unavailable("Atrium's answer is not JSON") from None

    def exiting(self, exc: Exit) -> Exit:
        if self.on_exit is not None:
            self.on_exit(exc)
        return exc

    async def post(self, path: str, body: Any = None, **kw: Any) -> Any:
        return (await self.call("POST", path, json_body=body if body is not None else {}, **kw))[1]

    async def get(self, path: str, **kw: Any) -> Any:
        return (await self.call("GET", path, **kw))[1]

