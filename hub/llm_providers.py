"""Model providers with an OpenAI-compatible API that custom agents can run on instead of Claude.

Local servers: Ollama, LM Studio, vLLM, llama.cpp's server. Hosted presets: ChatGPT (OpenAI) and Grok (xAI).

The hub calls GET {base_url}/models to list models and POST {base_url}/chat/completions with "tools" for the agent
loop. Checked against the vendors' documentation (October 2026): Ollama serves this API at http://localhost:11434/v1,
ignores the API key and does not support `tool_choice` (so the hub never sends it); LM Studio (localhost:1234/v1),
vLLM (localhost:8000/v1; tool calls need --enable-auto-tool-choice and a --tool-call-parser) and llama.cpp's server
(tool calls with --jinja) return `tool_calls[].function.arguments` as a JSON string. Assumption, handled defensively:
some servers send `arguments` as an object, or no tool call id - both are accepted. A server or model without tool
calling answers HTTP 400 or ignores the tools: switch the provider's `tools` option off and its agents answer in text.

Stored in the "llm_providers" collection. The optional API key is Fernet-encrypted with the hub's secret key, never
returned, logged or broadcast, and only sent to the endpoint (scheme, host and port) it was entered for.
"""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx

from .connectors.base import endpoint_of, redact
from .models import LlmProvider

if TYPE_CHECKING:
    from .core import Hub

COLLECTION = "llm_providers"
DEFAULT_BASE_URL = "http://localhost:11434/v1"
RESERVED = {"anthropic", "rules", "claude", "local"}
# Hosted presets. Checked against the vendors' docs in October 2026: both still serve
# POST /v1/chat/completions and GET /v1/models. The default model is a current flagship; Test lists
# whatever the key can actually call, and the admin can pick another.
PRESETS: tuple[dict[str, Any], ...] = (
    {
        "id": "chatgpt",
        "name": "ChatGPT",
        "vendor": "OpenAI",
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-5.6-terra",
        "suggested_models": ["gpt-5.6-terra", "gpt-5.6-sol", "gpt-4o"],
        "requires_key": True,
        "tools": True,
        "note": "OpenAI Chat Completions. Create a key at platform.openai.com.",
    },
    {
        "id": "grok",
        "name": "Grok",
        "vendor": "xAI",
        "base_url": "https://api.x.ai/v1",
        "default_model": "grok-4.7",
        "suggested_models": ["grok-4.7", "grok-4.6", "grok-4.5"],
        "requires_key": True,
        "tools": True,
        "note": "xAI Chat Completions. Create a key in the xAI console.",
    },
)
MAX_TURNS = 12
MAX_RESULT = 20_000
ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")


class ProviderError(RuntimeError):
    """A provider problem with a message safe to show (secrets masked)."""


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def get(hub: "Hub", provider_id: str) -> LlmProvider | None:
    doc = hub.store.get(COLLECTION, provider_id)
    return LlmProvider.model_validate(doc) if doc else None


def all_providers(hub: "Hub") -> list[LlmProvider]:
    return [LlmProvider.model_validate(d) for d in hub.store.list(COLLECTION)]


def public(provider: LlmProvider) -> dict[str, Any]:
    """What the API shows: everything but the key, and whether one is set."""
    return {**provider.model_dump(mode="json", exclude={"api_key", "endpoint"}), "api_key_set": bool(provider.api_key)}


def _put(hub: "Hub", provider: LlmProvider) -> LlmProvider:
    """Written straight to the store; the event stream only carries the public view."""
    hub.store.put(COLLECTION, provider.model_dump(mode="json"))
    hub.bus.publish("llm_provider", public(provider))
    return provider


def clean_base_url(value: str) -> str:
    text = (value or "").strip().rstrip("/")
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("The base URL must start with http:// or https://, e.g. " + DEFAULT_BASE_URL)
    if parts.username or parts.password:
        raise ValueError("The base URL must not contain credentials - use the API key field")
    if parts.query or parts.fragment:
        raise ValueError("The base URL must not have a query or fragment")
    return text


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "local"


def preset_by_id(preset_id: str | None) -> dict[str, Any] | None:
    if not preset_id:
        return None
    return next((p for p in PRESETS if p["id"] == preset_id), None)


def public_presets() -> list[dict[str, Any]]:
    return [dict(p) for p in PRESETS]


def save(hub: "Hub", provider_id: str | None, values: dict[str, Any], actor: str) -> tuple[LlmProvider, bool]:
    """Create (provider_id None) or update a provider. `api_key`: a value sets it, None or "" keeps the stored one
    - while the endpoint stays the same; `clear_api_key` removes it. Returns the provider and whether the key changed."""
    current = get(hub, provider_id) if provider_id else None
    if provider_id and current is None:
        raise KeyError(provider_id)
    data = current.model_dump() if current else {}
    preset = preset_by_id(values.get("preset"))
    if values.get("preset") and preset is None:
        raise ValueError(f"Unknown preset '{values.get('preset')}'. Use one of: "
                         + ", ".join(p["id"] for p in PRESETS))
    for key in ("name", "default_model", "tools", "timeout"):
        if values.get(key) is not None:
            data[key] = values[key].strip() if isinstance(values[key], str) else values[key]
    if current is None and preset is not None:
        data["preset"] = preset["id"]
        if not (data.get("name") or "").strip():
            data["name"] = preset["name"]
        if not (data.get("default_model") or "").strip():
            data["default_model"] = preset["default_model"]
        if values.get("tools") is None:
            data["tools"] = preset["tools"]
        if preset["requires_key"] and not values.get("api_key"):
            raise ValueError(f"{preset['name']} needs an API key")
    if not (data.get("name") or "").strip():
        raise ValueError("Give the provider a name")
    if values.get("base_url") or (current is None and not data.get("base_url")):
        fallback = preset["base_url"] if preset is not None else DEFAULT_BASE_URL
        data["base_url"] = clean_base_url(values.get("base_url") or data.get("base_url") or fallback)
    if current is None:
        wanted = _slug(values.get("id") or data.get("name") or "local")
        if not ID_RE.match(wanted) or wanted in RESERVED:
            raise ValueError(f"'{wanted}' cannot be a provider id")
        data["id"], n = wanted, 2
        while get(hub, data["id"]) is not None:
            if values.get("id"):
                raise ValueError(f"A provider '{wanted}' already exists")
            data["id"], n = f"{wanted}-{n}", n + 1
        data["created_by"] = actor
    target = endpoint_of(data["base_url"])
    key, changed = values.get("api_key"), False
    if values.get("clear_api_key"):
        data["api_key"], changed = None, bool(current and current.api_key)
    elif key:
        if len(key) > 4096:
            raise ValueError("The API key is too long")
        data["api_key"], changed = hub.secrets.encrypt(key), True
    elif current and current.api_key and current.endpoint != target:
        raise ValueError("Enter the API key again (or remove it): a stored key is only sent to the address it was "
                         "entered for")
    if current is None or current.endpoint != target:
        data["models"], data["last_test"] = [], None
    data["endpoint"], data["updated_by"], data["updated_at"] = target, actor, time.time()
    return _put(hub, LlmProvider.model_validate(data)), changed


def delete(hub: "Hub", provider_id: str) -> bool:
    removed = hub.store.delete(COLLECTION, provider_id)
    if removed:
        hub.bus.publish("llm_provider_removed", {"id": provider_id})
    return removed


# --------------------------------------------------------------------------------------
# talking to the server
# --------------------------------------------------------------------------------------


def _key(hub: "Hub", provider: LlmProvider) -> str | None:
    return hub.secrets.decrypt(provider.api_key) if provider.api_key else None


def _client(hub: "Hub", provider: LlmProvider, key: str | None) -> httpx.AsyncClient:
    """Redirects are not followed: they could carry the key to another address."""
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    kwargs: dict[str, Any] = {"base_url": provider.base_url, "headers": headers, "timeout": provider.timeout,
                              "follow_redirects": False}
    transport = getattr(hub, "llm_transport", None)
    if transport is not None:
        kwargs["transport"] = transport
    return httpx.AsyncClient(**kwargs)


def _error_text(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:300]
    if isinstance(body, dict):
        error = body.get("error", body.get("detail", body.get("message")))
        if isinstance(error, dict):
            error = error.get("message") or json.dumps(error)[:300]
        if error:
            return str(error)[:300]
    return response.text[:300]


async def _call(hub: "Hub", provider: LlmProvider, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    key = _key(hub, provider)
    try:
        async with _client(hub, provider, key) as client:
            response = await client.request(method, path.lstrip("/"), json=body)
    except httpx.TimeoutException as exc:
        raise ProviderError(f"{provider.name} did not answer within {provider.timeout:.0f}s") from exc
    except httpx.HTTPError as exc:
        raise ProviderError(redact(f"{provider.name} is unreachable at {provider.base_url}: "
                                   f"{exc.__class__.__name__}: {exc}", [key] if key else None)) from exc
    if response.status_code in (301, 302, 303, 307, 308):
        raise ProviderError(f"{provider.name} redirected the request (HTTP {response.status_code}); check the base URL "
                            "(it usually ends in /v1)")
    if response.status_code >= 400:
        hint = {401: " - check the API key", 403: " - check the API key", 404: " - check the base URL (usually .../v1) "
                "and the model name"}.get(response.status_code, "")
        raise ProviderError(redact(f"{provider.name} answered HTTP {response.status_code}: {_error_text(response)}{hint}",
                                   [key] if key else None))
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError(f"{provider.name} did not answer with JSON - is {provider.base_url} an OpenAI-compatible "
                            "API?") from exc


async def list_models(hub: "Hub", provider: LlmProvider) -> list[str]:
    data = await _call(hub, provider, "GET", "/models")
    items = data.get("data", data.get("models")) if isinstance(data, dict) else data
    if not isinstance(items, list):
        raise ProviderError(f"{provider.name} answered /models without a model list")
    names = [str(m.get("id") or m.get("name") or m.get("model")) if isinstance(m, dict) else str(m) for m in items]
    return sorted({n for n in names if n and n != "None"})


async def test(hub: "Hub", provider: LlmProvider) -> dict[str, Any]:
    """List the provider's models; the result (and the model list) is stored with the provider."""
    try:
        models = await list_models(hub, provider)
        result = {"ok": True, "detail": f"Connected: {len(models)} model(s).", "models": models}
    except ProviderError as exc:
        result = {"ok": False, "detail": str(exc), "models": []}
    current = get(hub, provider.id) or provider
    if result["ok"]:
        current.models = result["models"]
        if not current.default_model and len(result["models"]) == 1:
            current.default_model = result["models"][0]
    current.last_test = {"ok": result["ok"], "detail": result["detail"], "at": time.time()}
    _put(hub, current)
    return {**result, "provider": public(current)}


def openai_tools(definitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Toolkit definitions ({name, description, input_schema}) in the OpenAI function-calling format."""
    return [{"type": "function", "function": {"name": d["name"], "description": d["description"],
                                              "parameters": d["input_schema"]}} for d in definitions]


def _arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"the tool arguments are not valid JSON: {str(raw)[:200]}") from exc
    return value if isinstance(value, dict) else {}


async def chat_loop(hub: "Hub", provider: LlmProvider, *, model: str, system: str, history: list[dict[str, Any]],
                    tools: list[dict[str, Any]], execute: Callable[[str, dict[str, Any]], Awaitable[Any]],
                    max_turns: int = MAX_TURNS) -> str:
    """Run the conversation in `history` (OpenAI message format, without the system message; appended to in place)
    until the model answers without calling a tool. `execute(name, arguments)` runs one tool call."""
    model = model or provider.default_model
    if not model:
        raise ProviderError(f"Choose a model for this agent, or a default model for {provider.name} (testing the "
                            "provider lists its models)")
    offered = openai_tools(tools) if provider.tools and tools else []
    text = ""
    for _ in range(max_turns):
        body: dict[str, Any] = {"model": model, "messages": [{"role": "system", "content": system}, *history]}
        if offered:
            body["tools"] = offered
        data = await _call(hub, provider, "POST", "/chat/completions", body)
        try:
            choice = data["choices"][0]
            message = choice.get("message") or {}
        except (KeyError, IndexError, TypeError) as exc:
            raise ProviderError(f"{provider.name} answered without a choice: {json.dumps(data)[:200]}") from exc
        text = str(message.get("content") or "").strip()
        calls = [c for c in message.get("tool_calls") or [] if isinstance(c, dict)] if offered else []
        for n, call in enumerate(calls):
            call.setdefault("id", f"call_{len(history)}_{n}")
            call.setdefault("type", "function")
        history.append({"role": "assistant", "content": text, **({"tool_calls": calls} if calls else {})})
        if not calls:
            if choice.get("finish_reason") == "length":
                text += "\n\n(Reply cut off - ask me to continue.)"
            return text or "Done."
        for call in calls:
            function = call.get("function") or {}
            try:
                result: Any = await execute(str(function.get("name")), _arguments(function.get("arguments")))
                content = json.dumps(result, default=str)[:MAX_RESULT]
            except Exception as exc:
                content = f"Error: {exc}"
            history.append({"role": "tool", "tool_call_id": call["id"], "content": content})
    return (text + "\n\n" if text else "") + f"(Stopped after {max_turns} tool rounds.)"
