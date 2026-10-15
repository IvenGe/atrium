"""HTTP for the adapters that call a provider's REST API directly (OpenAI, Azure OpenAI, local model servers).

Redirects are refused (they could carry the API key to another address), every error becomes a safe text with the
key redacted, and - for the cloud providers - a rate limit or an overloaded server (HTTP 429, 503, 529) is retried
twice: after 1 s and 4 s, or after the server's `Retry-After` when it sends one (UNVERIFIED that OpenAI always does;
honoured when present), never waiting longer than 30 s.
"""

from __future__ import annotations

import asyncio
import json
import time
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any

import httpx

from ...connectors.base import redact
from ..types import ProviderError

if TYPE_CHECKING:
    from ...core import Hub

RETRY_STATUS = frozenset({429, 503, 529})
BACKOFF = (1.0, 4.0)
MAX_WAIT = 30.0
sleep = asyncio.sleep  # tests replace it


def error_text(response: httpx.Response) -> str:
    """The provider's own error message (and the request field it names, when it does), at most 300 characters."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        error = body.get("error", body.get("detail", body.get("message")))
        param = error.get("param") if isinstance(error, dict) else None
        if isinstance(error, dict):
            error = error.get("message") or json.dumps(error)[:300]
        if error:
            return (str(error)[:300] + (f" (param: {param})" if isinstance(param, str) and param else ""))[:360]
    return response.text[:300]


def retry_after(response: httpx.Response) -> float | None:
    """Seconds the server asked to wait (Retry-After: seconds or an HTTP date), if it said."""
    value = (response.headers.get("retry-after") or "").strip()
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        return max(0.0, parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


async def request(hub: "Hub", *, name: str, base_url: str, headers: dict[str, str], timeout: float, method: str,
                  path: str, body: dict[str, Any] | None = None, secret: str | None = None, retries: int = 0,
                  hints: dict[int, str] | None = None, redirect_hint: str = "",
                  not_json_hint: str = "") -> Any:
    """One API call (with up to `retries` retries on 429/503/529); the parsed JSON answer, or a ProviderError."""
    kwargs: dict[str, Any] = {"base_url": base_url, "timeout": timeout, "headers": headers, "follow_redirects": False}
    transport = getattr(hub, "llm_transport", None)
    if transport is not None:
        kwargs["transport"] = transport
    secrets = [secret] if secret else None
    attempt = 0
    while True:
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                response = await client.request(method, path.lstrip("/"), json=body)
        except httpx.TimeoutException as exc:
            raise ProviderError(f"{name} did not answer within {timeout:.0f}s", kind="timeout") from exc
        except httpx.HTTPError as exc:
            raise ProviderError(redact(f"{name} is unreachable at {base_url}: {exc.__class__.__name__}: {exc}",
                                       secrets), kind="unreachable") from exc
        if response.status_code in RETRY_STATUS and attempt < retries:
            wait = retry_after(response)
            await sleep(min(MAX_WAIT, wait if wait is not None else BACKOFF[min(attempt, len(BACKOFF) - 1)]))
            attempt += 1
            continue
        break
    if response.status_code in (301, 302, 303, 307, 308):
        raise ProviderError(f"{name} redirected the request (HTTP {response.status_code}){redirect_hint}",
                            kind="redirect", status=response.status_code)
    if response.status_code >= 400:
        hint = (hints or {}).get(response.status_code, "")
        raise ProviderError(redact(f"{name} answered HTTP {response.status_code}: {error_text(response)}{hint}",
                                   secrets), kind=f"http_{response.status_code}", status=response.status_code)
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError(f"{name} did not answer with JSON{not_json_hint}", kind="not_json") from exc
