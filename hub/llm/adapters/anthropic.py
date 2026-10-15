"""Claude through the Anthropic SDK (optional dependency: pip install "atrium[ai]").

Credentials: the environment wins (ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile:
ANTHROPIC_PROFILE / ~/.config/anthropic), resolved by the SDK as before; otherwise the key an administrator stored on
the built-in provider record "anthropic" (Fernet-encrypted), which is only ever sent to the fixed API address.
Facts (checked 2026-10-14 against platform.claude.com/docs): `output_config.effort` takes low..max and
`output_config.format` a json_schema; temperature is rejected on current models (never sent); usage reports
cache reads and writes, thinking tokens and `inference_geo`; `metadata.user_id` is an opaque id (a salted hash here).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from ...connectors.base import redact
from ...secrets import SecretError
from ..types import Caps, ProviderError, Request, Result, ToolCall, Usage
from . import cloud_off, estimate_tokens, safety_id

try:
    import anthropic
except ImportError:  # pragma: no cover - optional dependency
    anthropic = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from ...core import Hub
    from ...models import LlmProvider

PROVIDER_ID = "anthropic"
BASE_URL = "https://api.anthropic.com"
# Server-side refusal fallback: if a request is declined, the API re-runs it on a fallback model.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
# Claude rejects a request with more than this many tools marked strict (HTTP 400: "Too many strict tools").
STRICT_TOOL_LIMIT = 20
EFFORTS = ("low", "medium", "high", "xhigh", "max")
ENV_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
STOP = {"end_turn": "end", "stop_sequence": "end", "tool_use": "tool_calls", "max_tokens": "max_tokens",
        "pause_turn": "pause", "refusal": "refusal", "model_context_window_exceeded": "context_exceeded"}


def _tools_for_api(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Claude accepts at most STRICT_TOOL_LIMIT tools marked strict. Above that, send them unstrict: the hub checks
    every tool's arguments itself (toolkit.validate_args) before it runs."""
    if sum(1 for tool in tools if tool.get("strict")) <= STRICT_TOOL_LIMIT:
        return tools
    return [{**tool, "strict": False} if tool.get("strict") else tool for tool in tools]


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def env_source() -> str | None:
    """Credentials the SDK reads itself: "env" (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN) or "profile" (an
    `ant auth login` profile)."""
    if any(os.environ.get(k) for k in ENV_KEYS):
        return "env"
    if os.environ.get("ANTHROPIC_PROFILE") or (Path.home() / ".config" / "anthropic").is_dir():
        return "profile"
    return None


def caps_from_info(info: dict[str, Any]) -> Caps:
    """Caps from a models-list entry: structured outputs, effort levels, output and context sizes."""
    capabilities = info.get("capabilities") or {}
    effort = capabilities.get("effort") or {}
    levels = [e for e in EFFORTS if (effort.get(e) or {}).get("supported")] if effort.get("supported") else []
    structured = (capabilities.get("structured_outputs") or {}).get("supported")
    return Caps(tools=True, json_schema=structured if isinstance(structured, bool) else None, temperature=False,
                effort_levels=levels or None, max_output_tokens=info.get("max_tokens"),
                context_window=info.get("max_input_tokens"), source="api", at=time.time())


class AnthropicAdapter:
    kind = "anthropic"

    def __init__(self, hub: "Hub"):
        self.hub = hub
        # Builds the SDK client: anthropic.AsyncAnthropic(**kwargs) - tests inject a fake one
        self.client_factory: Callable[..., Any] | None = None
        self._client: Any = None
        self._client_for: tuple[Any, ...] | None = None
        self.last_error: str | None = None

    def record(self) -> "LlmProvider | None":
        from ... import llm_providers

        return llm_providers.get(self.hub, PROVIDER_ID)

    def location(self) -> str:
        return "third_party"

    @staticmethod
    def installed() -> bool:
        return anthropic is not None

    def key_source(self) -> str | None:
        """Where the credentials come from: "env" and "profile" (the SDK reads them) win over "stored"."""
        source = env_source()
        if source is not None:
            return source
        record = self.record()
        return "stored" if record is not None and record.api_key else None

    def available(self) -> tuple[bool, str | None]:
        if cloud_off():
            return False, "HUB_LLM=off"
        if anthropic is None and self.client_factory is None:
            return False, "the anthropic package is not installed (pip install atrium[ai])"
        record = self.record()
        if record is not None and not record.enabled:
            return False, "switched off"
        if self.key_source() is None:
            return False, "no API key - set ANTHROPIC_API_KEY or store a key for Claude"
        return True, None

    def default_model(self) -> str:
        record = self.record()
        return (record.default_model if record else "") or self.hub.settings.model

    def caps(self, model: str) -> Caps:
        record = self.record()
        stored = record.capabilities.get(model) if record else None
        caps = Caps.model_validate(stored.model_dump()) if stored is not None else Caps(tools=True)
        caps.temperature = False  # rejected by every current Claude model (other than 1.0)
        return caps

    def reset(self) -> None:
        self._client, self._client_for = None, None

    def client(self) -> Any:
        source = self.key_source()
        record = self.record()
        token = record.api_key if source == "stored" and record else None
        fingerprint = (source, token, id(self.client_factory))
        if self._client is None or self._client_for != fingerprint:
            kwargs: dict[str, Any] = {}
            if source == "stored":
                try:
                    kwargs = {"api_key": self.hub.secrets.decrypt(token), "base_url": BASE_URL}
                except SecretError as exc:
                    raise ProviderError("The stored Claude API key cannot be decrypted - enter it again",
                                        kind="key") from exc
            factory = self.client_factory or (anthropic.AsyncAnthropic if anthropic else None)
            if factory is None:
                raise ProviderError("The anthropic package is not installed (pip install atrium[ai])", kind="install")
            self._client, self._client_for = factory(**kwargs), fingerprint
        return self._client

    def _secrets(self) -> list[str]:
        values = [os.environ.get(k) or "" for k in ENV_KEYS]
        record = self.record()
        if record is not None and record.api_key:
            try:
                values.append(self.hub.secrets.decrypt(record.api_key))
            except SecretError:
                pass
        return [v for v in values if v]

    def _error(self, exc: Exception) -> ProviderError:
        status = getattr(exc, "status_code", None)
        if anthropic is not None and isinstance(exc, anthropic.APITimeoutError):
            error = ProviderError("Claude did not answer in time", kind="timeout")
        elif anthropic is not None and isinstance(exc, anthropic.APIConnectionError):
            error = ProviderError("Claude is unreachable", kind="unreachable")
        elif isinstance(status, int):
            message = str(getattr(exc, "message", "") or exc)[:300]
            error = ProviderError(redact(f"Claude answered HTTP {status}: {message}", self._secrets()),
                                  kind=f"http_{status}", status=status)
        else:
            error = ProviderError(f"Claude failed ({exc.__class__.__name__})", kind=exc.__class__.__name__)
        self.last_error = str(error)
        return error

    # -- one model turn -----------------------------------------------------------------

    def _messages(self, req: Request) -> list[dict[str, Any]]:
        """Neutral history in the Messages API shape: the results of one round's tool calls go back together in one
        user message; an assistant turn from this provider and model is replayed as it came (thinking signatures)."""
        out: list[dict[str, Any]] = []
        results: list[dict[str, Any]] = []
        for m in req.messages:
            if m.role == "tool":
                block: dict[str, Any] = {"type": "tool_result", "tool_use_id": m.call_id, "content": m.text}
                if m.is_error:
                    block["is_error"] = True
                results.append(block)
                continue
            if results:
                out.append({"role": "user", "content": results})
                results = []
            if m.role == "user":
                out.append({"role": "user", "content": m.text})
            elif m.raw is not None and (m.provider, m.model) == (PROVIDER_ID, req.model):
                out.append({"role": "assistant", "content": m.raw})
            else:
                content: list[dict[str, Any]] = [{"type": "text", "text": m.text}] if m.text else []
                content += [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments} for c in m.tool_calls]
                out.append({"role": "assistant", "content": content or [{"type": "text", "text": "(no answer)"}]})
        if results:
            out.append({"role": "user", "content": results})
        return out

    async def complete(self, req: Request) -> Result:
        caps = self.caps(req.model)
        kwargs: dict[str, Any] = {
            "model": req.model,
            "max_tokens": min(req.max_output_tokens, caps.max_output_tokens or req.max_output_tokens),
            "system": req.system,
            "messages": self._messages(req),
            "cache_control": {"type": "ephemeral"},
        }
        output_config: dict[str, Any] = {}
        if req.effort in EFFORTS and (caps.effort_levels is None or req.effort in caps.effort_levels):
            output_config["effort"] = req.effort
        if req.json_schema is not None and req.json_mode == "native":
            output_config["format"] = {"type": "json_schema", "schema": req.json_schema}
        if output_config:
            kwargs["output_config"] = output_config
        if req.tools:
            kwargs["tools"] = _tools_for_api(req.tools)
        if req.model in FALLBACK_MODELS:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        user_id = safety_id(self.hub, req.person)
        if user_id:
            kwargs["metadata"] = {"user_id": user_id}
        try:
            response = await self.client().beta.messages.create(**kwargs)
        except ProviderError:
            raise
        except Exception as exc:  # the SDK's errors, and anything a client raises: a safe text, never the key
            raise self._error(exc) from exc
        self.last_error = None
        content = list(_get(response, "content") or [])
        text = "\n".join(_get(b, "text") or "" for b in content if _get(b, "type") == "text").strip()
        calls = [ToolCall(id=str(_get(b, "id")), name=str(_get(b, "name")), arguments=dict(_get(b, "input") or {}))
                 for b in content if _get(b, "type") == "tool_use"]
        reason = _get(response, "stop_reason")
        stop = STOP.get(reason or "", "end")
        refusal = None
        if stop == "refusal":
            refusal = str(_get(_get(response, "stop_details"), "category") or "refused")
        return Result(text=text, tool_calls=calls, stop=stop, usage=self._usage(response, req, text), raw=content,
                      served_model=str(_get(response, "model") or req.model), refusal=refusal)

    @staticmethod
    def _usage(response: Any, req: Request, text: str) -> Usage:
        usage = _get(response, "usage")
        if usage is None or not isinstance(_get(usage, "input_tokens"), int):
            sent = req.system + "".join(m.text for m in req.messages)
            return Usage(input_tokens=estimate_tokens(sent), output_tokens=estimate_tokens(text), estimated=True)
        details = _get(usage, "output_tokens_details")
        geo = _get(usage, "inference_geo")
        return Usage(input_tokens=_get(usage, "input_tokens") or 0,
                     cached_input_tokens=_get(usage, "cache_read_input_tokens") or 0,
                     cache_write_tokens=_get(usage, "cache_creation_input_tokens") or 0,
                     output_tokens=_get(usage, "output_tokens") or 0,
                     reasoning_tokens=(_get(details, "thinking_tokens") or 0) if details is not None else 0,
                     inference_geo=geo if isinstance(geo, str) else None)

    async def list_models(self) -> list[dict[str, Any]]:
        """The account's models (active and deprecated), with their capabilities."""
        ok, reason = self.available()
        if not ok:
            raise ProviderError(f"Claude is not available: {reason}", kind="unavailable")
        out = []
        try:
            async for item in self.client().models.list(limit=1000, lifecycle=["active", "deprecated"]):
                info = item.model_dump() if hasattr(item, "model_dump") else dict(item)
                if info.get("lifecycle") == "retired":
                    continue
                out.append({"id": str(info["id"]), "label": info.get("display_name"), "caps": caps_from_info(info),
                            "lifecycle": info.get("lifecycle"), "retires_at": str(info["retires_at"])
                            if info.get("retires_at") else None})
        except ProviderError:
            raise
        except Exception as exc:
            raise self._error(exc) from exc
        return out
