"""Local model servers with an OpenAI-compatible API - Ollama, LM Studio, vLLM, llama.cpp's server - over Chat
Completions (provider kind "openai_compatible").

The hub calls GET {base_url}/models to list models and POST {base_url}/chat/completions with "tools". Checked
against the vendors' documentation (October 2026): Ollama serves this API at http://localhost:11434/v1, ignores the
API key and does not support `tool_choice` (so the hub never sends it); LM Studio (localhost:1234/v1), vLLM
(localhost:8000/v1; tool calls need --enable-auto-tool-choice and a --tool-call-parser) and llama.cpp's server (tool
calls with --jinja) return `tool_calls[].function.arguments` as a JSON string. Assumption, handled defensively: some
servers send `arguments` as an object, or no tool call id - both are accepted. A server or model without tool calling
answers HTTP 400 or ignores the tools: switch the provider's `tools` option off and its agents answer in text.
UNVERIFIED: whether a server reports `usage` (counted from characters when it does not) and accepts
`response_format` json_schema (the structured ladder learns it from a refusal).

The API key is only sent to the endpoint (scheme, host and port) it was entered for, and redirects are refused.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from ...models import LlmProvider
from ..types import Caps, ProviderError, Request, Result, ToolCall, Usage
from . import estimate_tokens, http

if TYPE_CHECKING:
    from ...core import Hub


def openai_tools(definitions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Toolkit definitions ({name, description, input_schema}) in the Chat Completions function-calling format."""
    return [{"type": "function", "function": {"name": d["name"], "description": d["description"],
                                              "parameters": d["input_schema"]}} for d in definitions]


def arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"the tool arguments are not valid JSON: {str(raw)[:200]}") from exc
    return value if isinstance(value, dict) else {}


class CompatAdapter:
    kind = "openai_compatible"

    def __init__(self, hub: "Hub", provider: LlmProvider):
        self.hub = hub
        self.provider = provider

    def location(self) -> str:
        return self.provider.location

    def available(self) -> tuple[bool, str | None]:
        return (True, None) if self.provider.enabled else (False, "switched off")

    def caps(self, model: str) -> Caps:
        stored = self.provider.capabilities.get(model)
        caps = Caps.model_validate(stored.model_dump()) if stored is not None else Caps()
        if not self.provider.tools:
            caps.tools = False
        return caps

    # -- HTTP -----------------------------------------------------------------------

    def _key(self) -> str | None:
        return self.hub.secrets.decrypt(self.provider.api_key) if self.provider.api_key else None

    async def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        p, key = self.provider, self._key()
        return await http.request(
            self.hub, name=p.name, base_url=p.base_url, headers={"Authorization": f"Bearer {key}"} if key else {},
            timeout=p.timeout, method=method, path=path, body=body, secret=key,
            hints={401: " - check the API key", 403: " - check the API key",
                   404: " - check the base URL (usually .../v1) and the model name"},
            redirect_hint="; check the base URL (it usually ends in /v1)",
            not_json_hint=f" - is {p.base_url} an OpenAI-compatible API?")

    async def list_models(self) -> list[dict[str, Any]]:
        data = await self.call("GET", "/models")
        items = data.get("data", data.get("models")) if isinstance(data, dict) else data
        if not isinstance(items, list):
            raise ProviderError(f"{self.provider.name} answered /models without a model list", kind="bad_answer")
        names = [str(m.get("id") or m.get("name") or m.get("model")) if isinstance(m, dict) else str(m) for m in items]
        return [{"id": n} for n in sorted({n for n in names if n and n != "None"})]

    # -- one model turn -----------------------------------------------------------------

    def _messages(self, req: Request) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = [{"role": "system", "content": req.system}]
        for m in req.messages:
            if m.role == "user":
                out.append({"role": "user", "content": m.text})
            elif m.role == "tool":
                out.append({"role": "tool", "tool_call_id": m.call_id, "content": m.text})
            elif isinstance(m.raw, dict) and (m.provider, m.model) == (self.provider.id, req.model):
                out.append(m.raw)  # the server's own message, as it sent it
            else:
                entry: dict[str, Any] = {"role": "assistant", "content": m.text}
                if m.tool_calls:
                    entry["tool_calls"] = [{"id": c.id, "type": "function", "function": {
                        "name": c.name, "arguments": json.dumps(c.arguments)}} for c in m.tool_calls]
                out.append(entry)
        return out

    async def complete(self, req: Request) -> Result:
        body: dict[str, Any] = {"model": req.model, "messages": self._messages(req)}
        offered = openai_tools(req.tools) if self.provider.tools and req.tools else []
        if offered:
            body["tools"] = offered  # never tool_choice: Ollama does not support it
        if req.json_schema is not None and req.json_mode == "native":
            body["response_format"] = {"type": "json_schema", "json_schema": {
                "name": req.schema_name, "schema": req.json_schema, "strict": True}}
        elif req.json_schema is not None and req.json_mode == "json_object":
            body["response_format"] = {"type": "json_object"}
        if req.effort and self.provider.send_effort:
            body["reasoning_effort"] = req.effort
        if req.temperature is not None:
            body["temperature"] = req.temperature
        data = await self.call("POST", "/chat/completions", body)
        try:
            choice = data["choices"][0]
            message = choice.get("message") or {}
        except (KeyError, IndexError, TypeError, AttributeError) as exc:
            # never the answer itself in the message: a gateway may echo the request (the key, the prompt)
            raise ProviderError(f"{self.provider.name} answered without a choice", kind="bad_answer") from exc
        text = str(message.get("content") or "").strip()
        calls = [c for c in message.get("tool_calls") or [] if isinstance(c, dict)] if offered else []
        tool_calls = []
        for n, call in enumerate(calls):
            call.setdefault("id", f"call_{len(req.messages)}_{n}")
            call.setdefault("type", "function")
            function = call.get("function") or {}
            try:
                args, error = arguments(function.get("arguments")), None
            except ValueError as exc:
                args, error = {}, str(exc)
            tool_calls.append(ToolCall(id=str(call["id"]), name=str(function.get("name")), arguments=args, error=error))
        raw = {"role": "assistant", "content": text, **({"tool_calls": calls} if calls else {})}
        stop = "tool_calls" if tool_calls else "max_tokens" if choice.get("finish_reason") == "length" else "end"
        return Result(text=text, tool_calls=tool_calls, stop=stop, usage=self._usage(data, req, text), raw=raw,
                      served_model=str(data.get("model") or req.model))

    @staticmethod
    def _usage(data: dict[str, Any], req: Request, text: str) -> Usage:
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else None
        if usage and isinstance(usage.get("prompt_tokens"), int):
            cached = ((usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0) \
                if isinstance(usage.get("prompt_tokens_details"), dict) else 0
            return Usage(input_tokens=max(0, usage["prompt_tokens"] - cached), cached_input_tokens=cached,
                         output_tokens=int(usage.get("completion_tokens") or 0))
        sent = req.system + "".join(m.text + json.dumps([c.arguments for c in m.tool_calls]) for m in req.messages)
        return Usage(input_tokens=estimate_tokens(sent), output_tokens=estimate_tokens(text), estimated=True)
