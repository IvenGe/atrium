"""OpenAI ("ChatGPT models") and Azure OpenAI over the Responses API (provider kind "openai", variants "openai" and
"azure"), with plain HTTP (httpx) - no SDK.

Facts (checked 2026-10-14 against developers.openai.com and learn.microsoft.com):
- OpenAI recommends the Responses API for new projects; on the current models function calling with reasoning needs
  it (Chat Completions supports function calling on gpt-6-luna only with reasoning_effort none).
- A request has `instructions` (the system message), `input` items, flat function tools {type, name, description,
  parameters, strict}, `text.format` {type: json_schema, name, schema, strict}, `reasoning.effort` (none, minimal,
  low, medium, high, xhigh, max - per model), `max_output_tokens` (reasoning tokens count toward it), `store`
  (defaults to true: always sent false here), `include` (reasoning.encrypted_content keeps reasoning across tool rounds
  without storing anything at OpenAI) and `safety_identifier` (a salted hash here, never a name or email).
- The answer's `output` holds `message` items (content `output_text` or `refusal`), `function_call` items whose
  `arguments` is a JSON string, and `reasoning` items; reasoning items must be passed back with the tool results, so
  an assistant turn is replayed as it came (`raw`) to the same provider and model. A tool result goes back as
  {type: function_call_output, call_id, output}. `status` is completed, failed, in_progress, cancelled, queued or
  incomplete (`incomplete_details.reason` max_output_tokens or content_filter, among others).
- Usage: input_tokens, input_tokens_details.cached_tokens, output_tokens, output_tokens_details.reasoning_tokens.
  UNVERIFIED: that cached_tokens are part of input_tokens (assumed, as in Chat Completions - see `uncached`).
- GET /models lists the account's models without capabilities (they are probed or learned).
- Azure OpenAI v1: base URL https://<resource>.openai.azure.com/openai/v1/ (or .services.ai.azure.com), no
  api-version, the key in an `api-key` header, `model` = the deployment name. UNVERIFIED: whether GET /models lists
  deployments - administrators type the deployment names.
- UNVERIFIED: the minimum of max_output_tokens (16 is used for the smallest call).

The key: OPENAI_API_KEY in the environment wins for the built-in provider, else the key an administrator stored
(Fernet). The address is fixed (https://api.openai.com/v1; OPENAI_BASE_URL is ignored on purpose, so a stray
environment variable cannot redirect the key) or, for Azure, bound to an Azure OpenAI address.
"""

from __future__ import annotations

import json
import os
import re
from typing import TYPE_CHECKING, Any

from ...connectors.base import redact
from ...secrets import SecretError
from .. import structured
from ..types import Caps, ProviderError, Request, Result, ToolCall, Usage
from . import cloud_off, estimate_tokens, http, safety_id
from .compat import arguments

if TYPE_CHECKING:
    from ...core import Hub
    from ...models import LlmProvider

BASE_URL = "https://api.openai.com/v1"
ENV_KEY = "OPENAI_API_KEY"
AZURE_URL = re.compile(r"^https://[a-z0-9-]+\.(openai\.azure\.com|services\.ai\.azure\.com)/openai/v1/?$")
EFFORTS = ("none", "minimal", "low", "medium", "high", "xhigh", "max")
# Not text-generation models: hidden from the model pickers (a heuristic on the id; typing any name still works)
NON_TEXT = re.compile(r"embedding|tts|whisper|dall-e|image|audio|realtime|transcribe|moderation", re.IGNORECASE)
KNOWN_MODELS = ("gpt-6-astra", "gpt-6.1-sol", "gpt-6-luna")  # current flagships: suggested when the account has them
# What OpenAI's models pages say (2026-10-14); anything else is unknown until probed or learned
DEFAULT_CAPS: dict[str, dict[str, Any]] = {
    "gpt-6-luna": {"tools": True, "json_schema": True, "effort_levels": ["none", "low", "medium", "high", "xhigh", "max"],
                   "max_output_tokens": 128_000, "context_window": 1_050_000},
    "gpt-6-astra": {"tools": True, "effort_levels": ["low", "medium", "high", "xhigh", "max"]},
    "gpt-6.1-sol": {"tools": True, "effort_levels": ["low", "medium", "high", "xhigh", "max"]},
}
SMALLEST_OUTPUT = 16
RETRIES = 2
NAME_RE = re.compile(r"[^A-Za-z0-9_-]")


def azure_url_ok(url: str) -> bool:
    return bool(AZURE_URL.match((url or "").strip()))


def uncached(input_tokens: int, cached: int) -> int:
    """Input tokens not served from the cache. UNVERIFIED: OpenAI counts cached tokens inside input_tokens (as Chat
    Completions does), so they are subtracted here - the one place that assumption lives."""
    return max(0, input_tokens - cached)


def sort_models(ids: list[str]) -> list[str]:
    """The known flagships first (in the order of KNOWN_MODELS), then the rest by name."""
    known = [m for m in KNOWN_MODELS if m in ids]
    return known + sorted(m for m in set(ids) if m not in known)


class OpenAIAdapter:
    kind = "openai"

    def __init__(self, hub: "Hub", provider: "LlmProvider"):
        self.hub = hub
        self.provider = provider
        self.variant = provider.variant or "openai"

    @property
    def builtin(self) -> bool:
        return self.variant == "openai"

    @property
    def label(self) -> str:
        return self.provider.name

    def location(self) -> str:
        return "third_party"

    # -- credentials and availability ----------------------------------------------------

    def key_source(self) -> str | None:
        if self.builtin and os.environ.get(ENV_KEY):
            return "env"
        return "stored" if self.provider.api_key else None

    def enabled(self) -> bool:
        """The built-in record is seeded off; it counts as on once a key is stored (an administrator switches it on
        with the key) or OPENAI_API_KEY is set and nobody has changed the record since."""
        p = self.provider
        return p.enabled or (self.builtin and self.key_source() == "env" and p.updated_by == "hub")

    def available(self) -> tuple[bool, str | None]:
        if cloud_off():
            return False, "HUB_LLM=off"
        if not self.builtin and not azure_url_ok(self.provider.base_url):
            return False, "the base URL is not an Azure OpenAI address"
        if not self.enabled():
            return False, "switched off"
        if self.key_source() is None:
            return False, ("no API key - set OPENAI_API_KEY or store a key for OpenAI" if self.builtin
                           else "no API key - store the Azure OpenAI key")
        return True, None

    def _key(self) -> str:
        source = self.key_source()
        if source == "env":
            return os.environ[ENV_KEY]
        if source is None:
            raise ProviderError(f"{self.label} has no API key", kind="key")
        try:
            return self.hub.secrets.decrypt(self.provider.api_key)
        except SecretError as exc:
            raise ProviderError(f"The stored {self.label} API key cannot be decrypted - enter it again",
                                kind="key") from exc

    def base_url(self) -> str:
        if self.builtin:
            return BASE_URL
        url = self.provider.base_url.strip()
        if not azure_url_ok(url):
            raise ProviderError(f"{self.label}: the base URL is not an Azure OpenAI address", kind="config")
        return url.rstrip("/")

    def caps(self, model: str) -> Caps:
        """What the models pages say, overridden by what was learned, probed or set for this model."""
        known = DEFAULT_CAPS.get(model) if self.builtin else None
        caps = Caps(**known) if known else Caps()
        stored = self.provider.capabilities.get(model)
        if stored is not None:
            found = Caps.model_validate(stored.model_dump())
            caps = caps.model_copy(update={k: v for k, v in found.model_dump().items() if v is not None})
        return caps

    # -- HTTP ----------------------------------------------------------------------------

    async def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        key = self._key()
        headers = {"Authorization": f"Bearer {key}"} if self.builtin else {"api-key": key}
        return await http.request(
            self.hub, name=self.label, base_url=self.base_url(), headers=headers, timeout=self.provider.timeout,
            method=method, path=path, body=body, secret=key, retries=RETRIES,
            hints={401: " - check the API key", 403: " - check the API key and the account's access",
                   404: " - check the model or deployment name"},
            redirect_hint=" - redirects are not followed", not_json_hint="")

    async def list_models(self) -> list[dict[str, Any]]:
        """The account's models; ids that are clearly not text models are marked `hidden`. Azure: when the list
        fails or is empty, the deployment names typed on the provider."""
        typed = [m for m in dict.fromkeys([self.provider.default_model, *self.provider.pinned_models]) if m]
        try:
            data = await self.call("GET", "/models")
            items = data.get("data") if isinstance(data, dict) else data
            if not isinstance(items, list):
                raise ProviderError(f"{self.label} answered /models without a model list", kind="bad_answer")
        except ProviderError:
            if self.builtin or not typed:
                raise
            items = []
        found: dict[str, dict[str, Any]] = {}
        for item in items:
            model_id = str(item.get("id") or "") if isinstance(item, dict) else str(item)
            if not model_id:
                continue
            shutdown = item.get("shutdown_date") if isinstance(item, dict) else None
            found[model_id] = {"id": model_id, "hidden": bool(NON_TEXT.search(model_id)),
                               **({"lifecycle": "deprecated", "retires_at": str(shutdown)} if shutdown else {})}
        if not self.builtin and not found:
            found = {m: {"id": m, "hidden": False} for m in typed}
        return [found[m] for m in sort_models(list(found))]

    # -- one model turn ------------------------------------------------------------------

    def _input(self, req: Request) -> list[dict[str, Any]]:
        """Neutral history as Responses input items. An assistant turn from this provider and model is replayed as
        it came (its reasoning items must go back with the tool results); from elsewhere it is rebuilt as text plus
        function_call items."""
        items: list[dict[str, Any]] = []
        for m in req.messages:
            if m.role == "user":
                items.append({"role": "user", "content": m.text})
            elif m.role == "tool":
                items.append({"type": "function_call_output", "call_id": m.call_id, "output": m.text})
            elif isinstance(m.raw, list) and (m.provider, m.model) == (self.provider.id, req.model):
                items.extend(m.raw)
            else:
                if m.text or not m.tool_calls:
                    items.append({"role": "assistant", "content": m.text or "(no answer)"})
                items += [{"type": "function_call", "call_id": c.id, "name": c.name,
                           "arguments": json.dumps(c.arguments)} for c in m.tool_calls]
        return items

    def body(self, req: Request) -> dict[str, Any]:
        caps = self.caps(req.model)
        body: dict[str, Any] = {
            "model": req.model,
            "input": self._input(req),
            "max_output_tokens": min(req.max_output_tokens, caps.max_output_tokens or req.max_output_tokens),
            "store": False,  # OpenAI keeps nothing (store defaults to true)
            "include": ["reasoning.encrypted_content"],
        }
        if req.system:
            body["instructions"] = req.system
        if req.tools:  # explicit strict false: the arguments are validated locally (toolkit.validate_args)
            body["tools"] = [{"type": "function", "name": t["name"], "description": t.get("description", ""),
                              "parameters": t["input_schema"], "strict": False} for t in req.tools]
        if req.json_schema is not None and req.json_mode == "native":
            strict = structured.strictify(req.json_schema)
            body["text"] = {"format": {"type": "json_schema", "name": NAME_RE.sub("_", req.schema_name)[:64] or "result",
                                       "schema": strict if strict is not None else req.json_schema,
                                       "strict": strict is not None}}
        if req.effort in EFFORTS and (caps.effort_levels is None or req.effort in caps.effort_levels):
            body["reasoning"] = {"effort": req.effort}
        # temperature only without reasoning (OpenAI: remove it when the effort is not "none")
        if req.temperature is not None and req.effort == "none" and caps.temperature is not False:
            body["temperature"] = req.temperature
        user_id = safety_id(self.hub, req.person)
        if user_id:
            body["safety_identifier"] = user_id
        return body

    async def complete(self, req: Request) -> Result:
        data = await self.call("POST", "/responses", self.body(req))
        if not isinstance(data, dict):
            raise ProviderError(f"{self.label} answered without a response object", kind="bad_answer")
        status = data.get("status")
        if status == "failed":
            error = data.get("error") if isinstance(data.get("error"), dict) else {}
            message = redact(str(error.get("message") or "failed")[:300], [self._key()])  # hub.llm masks the rest
            raise ProviderError(f"{self.label} could not answer: {message}", kind="failed")
        if status not in (None, "completed", "incomplete"):
            raise ProviderError(f"{self.label} answered with status {status}", kind="status")
        output = data.get("output") if isinstance(data.get("output"), list) else []
        texts, calls, refusal = [], [], None
        for item in output:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "message":
                parts = [p for p in item.get("content") or [] if isinstance(p, dict)]
                text = "".join(str(p.get("text") or "") for p in parts if p.get("type") == "output_text")
                if text:
                    texts.append(text)
                refusal = refusal or next((str(p.get("refusal") or "refused") for p in parts
                                           if p.get("type") == "refusal"), None)
            elif item.get("type") == "function_call":
                try:
                    args, error = arguments(item.get("arguments")), None
                except ValueError as exc:
                    args, error = {}, str(exc)
                calls.append(ToolCall(id=str(item.get("call_id") or item.get("id") or f"call_{len(calls)}"),
                                      name=str(item.get("name")), arguments=args, error=error))
        reason = (data.get("incomplete_details") or {}).get("reason") if isinstance(data.get("incomplete_details"),
                                                                                  dict) else None
        if reason == "content_filter":
            refusal = refusal or "content_filter"
        stop = "tool_calls" if calls else "refusal" if refusal else \
            "max_tokens" if status == "incomplete" and reason == "max_output_tokens" else "end"
        text = "\n".join(texts).strip()
        return Result(text=text, tool_calls=calls, stop=stop, usage=self._usage(data, req, text), raw=output,  # type: ignore[arg-type]
                      served_model=str(data.get("model") or req.model), refusal=refusal)

    @staticmethod
    def _usage(data: dict[str, Any], req: Request, text: str) -> Usage:
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        if not usage or not isinstance(usage.get("input_tokens"), int):
            sent = req.system + "".join(m.text for m in req.messages)
            return Usage(input_tokens=estimate_tokens(sent), output_tokens=estimate_tokens(text), estimated=True)
        details = usage.get("input_tokens_details") if isinstance(usage.get("input_tokens_details"), dict) else {}
        out_details = usage.get("output_tokens_details") if isinstance(usage.get("output_tokens_details"), dict) else {}
        cached = int(details.get("cached_tokens") or 0)
        return Usage(input_tokens=uncached(usage["input_tokens"], cached), cached_input_tokens=cached,
                     output_tokens=int(usage.get("output_tokens") or 0),
                     reasoning_tokens=int(out_details.get("reasoning_tokens") or 0))
