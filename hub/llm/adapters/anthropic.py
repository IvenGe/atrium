"""Claude through the Anthropic SDK (optional dependency: pip install "atrium[ai]").

Credentials: the environment wins (ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN, or an `ant auth login` profile:
ANTHROPIC_PROFILE / ~/.config/anthropic), resolved by the SDK as before; otherwise the key an administrator stored on
the built-in provider record "anthropic" (Fernet-encrypted), which is only ever sent to the fixed API address.
Facts (checked 2026-10-15 against platform.claude.com/docs - effort, structured outputs, prompt caching, errors,
the models overview and the model pages): `output_config.effort` takes low..max on the models in KNOWN_MODELS that list
levels and is refused with HTTP 400 by the others (Claude Haiku 4.5, Sonnet 4.5 and older; the wording of that 400 is
not documented - UNVERIFIED, so hub.llm learns from any of the wordings in registry.UNSUPPORTED);
`output_config.format` takes a json_schema; at most 20 tools per request may be `strict` (STRICT_TOOLS, with at most
24 optional and 16 union-typed parameters across the strict schemas - "Schema is too complex for compilation" when
the compiled grammar is too large); top-level automatic
`cache_control` works on every active model (on the legacy Bedrock integration only explicit breakpoints - not used
here); temperature is rejected on current models (never sent); no thinking is configured (models that think by
default think adaptively; Haiku 4.5 would need budget_tokens, which is not used); usage reports cache reads and writes,
thinking tokens and `inference_geo`; `metadata.user_id` is an opaque id (a salted hash here). A 400 carries
{type: "error", error: {type, message}}: the message is what people see (masked, capped), never the request. The
SDK refuses a non-streaming request it expects to run over 10 minutes: larger answers are streamed (`streamed`).
"""

from __future__ import annotations

import ast
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from ...connectors.base import redact
from ...secrets import SecretError
from .. import structured
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
EFFORTS = ("low", "medium", "high", "xhigh", "max")
ENV_KEYS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
# Structured outputs limits per request, across every strict tool schema and the output_config.format schema
STRICT_TOOLS, STRICT_OPTIONAL, STRICT_UNIONS = 20, 24, 16
MESSAGE_LIMIT = 200  # characters of the API's own error message kept in a ProviderError
# The SDK refuses a non-streaming request it expects to run over 10 minutes (an hour per 128,000 output tokens, and
# 8,192 tokens on Claude Opus 4 / 4.1): larger answers are streamed (and read whole, as one message).
NONSTREAMING_TOKENS = 21_333
NONSTREAMING_OLD = ("claude-opus-4", "claude-opus-4-0", "claude-opus-4-1"), 8_192

_ALL = list(EFFORTS)
_NO_XHIGH = ["low", "medium", "high", "max"]  # xhigh arrived with Opus 4.7
_CURRENT = {"json_schema": True, "max_output_tokens": 128_000, "context_window": 1_000_000}
_LEGACY = {"max_output_tokens": 64_000, "context_window": 200_000}
# What the Claude API reference says per model (2026-10-15): the effort levels it takes ([]: output_config.effort is
# refused with HTTP 400), structured outputs (output_config.format and strict tools), max output and context window.
# Used for what the provider record does not know about a model (no models list fetched yet, nothing learned or set);
# what the Models API, a probe, learning or an administrator found wins. Matched by family (known_caps): dated
# snapshots and the Bedrock / Google Cloud spellings of these ids match too; a model not listed (a newer one) stays
# unknown and is learned from its answers.
KNOWN_MODELS: dict[str, dict[str, Any]] = {
    **{m: {"effort_levels": _ALL, **_CURRENT} for m in (
        "claude-fable-5-1", "claude-mythos-5-1", "claude-fable-5", "claude-mythos-5", "claude-opus-5-5",
        "claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-sonnet-5-5", "claude-sonnet-5",
        "claude-haiku-5-5")},
    "claude-mythos-preview": {"effort_levels": _NO_XHIGH, "json_schema": True},
    "claude-opus-4-6": {"effort_levels": _NO_XHIGH, **_CURRENT},
    "claude-sonnet-4-6": {"effort_levels": _NO_XHIGH, **_CURRENT},
    "claude-opus-4-5": {"effort_levels": ["low", "medium", "high"], "json_schema": True, **_LEGACY},
    "claude-sonnet-4-5": {"effort_levels": [], "json_schema": True, **_LEGACY},
    "claude-haiku-4-5": {"effort_levels": [], "json_schema": True, **_LEGACY},
    # Retired or retiring; no effort parameter. UNVERIFIED (no current page): structured outputs, and max output
    # 32K (Opus 4.1, Opus 4) / 64K (Sonnet 4) as the model pages said before.
    "claude-opus-4-1": {"effort_levels": [], "max_output_tokens": 32_000, "context_window": 200_000},
    "claude-opus-4-0": {"effort_levels": [], "max_output_tokens": 32_000, "context_window": 200_000},
    "claude-opus-4": {"effort_levels": [], "max_output_tokens": 32_000, "context_window": 200_000},
    "claude-sonnet-4-0": {"effort_levels": [], **_LEGACY},
    "claude-sonnet-4": {"effort_levels": [], **_LEGACY},
}
_DATE = re.compile(r"-\d{8}$")
_PLATFORM = re.compile(r"^(?:(?:us|eu|apac|au|jp|global)\.)?anthropic\.")  # Bedrock: [region.]anthropic.<id>
_VERSION = re.compile(r"^\d{1,2}(?:-|$)")
STOP = {"end_turn": "end", "stop_sequence": "end", "tool_use": "tool_calls", "max_tokens": "max_tokens",
        "pause_turn": "pause", "refusal": "refusal", "model_context_window_exceeded": "context_exceeded"}


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


def family(model: str) -> str | None:
    """The KNOWN_MODELS entry `model` belongs to: the id itself, a dated snapshot of it (claude-haiku-4-5-20251001), a
    Bedrock or Google Cloud spelling (anthropic.claude-haiku-4-5-20251001-v1:0, claude-haiku-4-5@20251001) or a
    variant with a suffix word - never a newer version (claude-opus-5 is not claude-opus-5-5). None: unknown."""
    name = _PLATFORM.sub("", (model or "").strip().lower()).split("[", 1)[0]
    name = re.sub(r"-v\d+(?::\d+)?$", "", name.replace("@", "-"))
    name = _DATE.sub("", name)
    best = None
    for key in KNOWN_MODELS:
        if name == key or (name.startswith(key + "-") and not _VERSION.match(name[len(key) + 1:])):
            best = key if best is None or len(key) > len(best) else best
    return best


def known_caps(model: str) -> dict[str, Any] | None:
    """What the API reference says about `model` (KNOWN_MODELS), or None for a model it does not list."""
    key = family(model)
    return {"tools": True, **KNOWN_MODELS[key]} if key else None


def streamed(model: str, max_tokens: int) -> bool:
    """Whether a request is sent streaming (the SDK refuses it otherwise: NONSTREAMING_TOKENS)."""
    old, limit = NONSTREAMING_OLD
    return max_tokens > NONSTREAMING_TOKENS or (family(model) in old and max_tokens > limit)


def caps_from_info(info: dict[str, Any]) -> Caps:
    """Caps from a models-list entry: structured outputs, effort levels, output and context sizes. Effort the entry
    says is not supported is no effort levels ([]); effort it says nothing about stays unknown (None)."""
    capabilities = info.get("capabilities") or {}
    effort = capabilities.get("effort")
    levels: list[str] | None = None
    if isinstance(effort, dict) and isinstance(effort.get("supported"), bool):
        listed = [e for e in EFFORTS if isinstance(effort.get(e), dict) and "supported" in effort[e]]
        if not effort["supported"]:
            levels = []
        elif listed:  # levels the entry does not mention stay possible only when it mentions none
            levels = [e for e in EFFORTS if (effort.get(e) or {}).get("supported")]
    structured_ok = (capabilities.get("structured_outputs") or {}).get("supported")
    return Caps(tools=True, json_schema=structured_ok if isinstance(structured_ok, bool) else None, temperature=False,
                effort_levels=levels, max_output_tokens=info.get("max_tokens"),
                context_window=info.get("max_input_tokens"), source="api", at=time.time())


def api_message(exc: Exception) -> str:
    """The API's own error message: body {type: "error", error: {type, message}} (the SDK keeps it as `body`; its
    text is "Error code: 400 - {...}"), else the exception's text."""
    body = getattr(exc, "body", None)
    text = str(getattr(exc, "message", "") or exc)
    if not isinstance(body, dict):
        found = re.match(r"Error code: \d+ - (\{.*\})\s*$", text, re.DOTALL)
        if found:
            try:
                body = ast.literal_eval(found.group(1))
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                body = None
    if isinstance(body, dict):
        error = body.get("error")
        message = error.get("message") if isinstance(error, dict) else None
        if isinstance(message, str) and message.strip():
            return message.strip()
    return text.strip()


def strict_fits(tools: list[dict[str, Any]], schema: dict[str, Any] | None) -> bool:
    """Whether the strict tool schemas (and a native JSON output schema) stay within the structured outputs limits."""
    strict = [t for t in tools if t.get("strict")]
    if len(strict) > STRICT_TOOLS:
        return False
    optional = unions = 0
    for item in [*(t.get("input_schema") or {} for t in strict), *([schema] if schema else [])]:
        o, u = structured.schema_load(item)
        optional, unions = optional + o, unions + u
    return optional <= STRICT_OPTIONAL and unions <= STRICT_UNIONS


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
        """What the API reference says about the model (KNOWN_MODELS), overridden by what the provider record knows
        (the models list, a probe, learning, an administrator)."""
        known = known_caps(model)
        caps = Caps(**known) if known else Caps(tools=True)
        record = self.record()
        stored = record.capabilities.get(model) if record else None
        if stored is not None:
            found = Caps.model_validate(stored.model_dump(include=set(Caps.model_fields)))
            caps = caps.model_copy(update={k: v for k, v in found.model_dump().items() if v is not None})
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
            message = " ".join(redact(api_message(exc), self._secrets()).split())
            if len(message) > MESSAGE_LIMIT:
                message = message[:MESSAGE_LIMIT - 1] + "…"
            error = ProviderError(f"Claude answered HTTP {status}: {message}", kind=f"http_{status}", status=status)
        else:
            error = ProviderError(f"Claude failed ({exc.__class__.__name__})", kind=exc.__class__.__name__)
        # LLM.status() shows it to every signed-in account (GET /api/overview, /api/llm/providers): the status only -
        # the provider's own message may quote the request (a person's chat), and goes to the call's agent error
        self.last_error = f"Claude answered HTTP {error.status}" if error.status else str(error)
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
            "messages": self._messages(req),
            "cache_control": {"type": "ephemeral"},  # automatic caching: every active model, nothing to opt out of
        }
        if req.system:
            kwargs["system"] = req.system
        output_config: dict[str, Any] = {}
        if req.effort in EFFORTS and (caps.effort_levels is None or req.effort in caps.effort_levels):
            output_config["effort"] = req.effort  # never to a model that refuses it (Haiku 4.5, Sonnet 4.5...)
        native = req.json_schema is not None and req.json_mode == "native"
        if native:
            output_config["format"] = {"type": "json_schema", "schema": req.json_schema}
        if output_config:
            kwargs["output_config"] = output_config
        if req.tools:
            # strict tools only within the structured outputs limits and on a model that has them; otherwise plain
            # tools (the toolkit validates every call's arguments itself)
            strict = caps.json_schema is not False and strict_fits(req.tools, req.json_schema if native else None)
            kwargs["tools"] = req.tools if strict else [{k: v for k, v in t.items() if k != "strict"}
                                                        for t in req.tools]
        if req.model in FALLBACK_MODELS:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        user_id = safety_id(self.hub, req.person)
        if user_id:
            kwargs["metadata"] = {"user_id": user_id}
        try:
            messages = self.client().beta.messages
            if streamed(req.model, kwargs["max_tokens"]):
                async with messages.stream(**kwargs) as stream:
                    response = await stream.get_final_message()
            else:
                response = await messages.create(**kwargs)
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
