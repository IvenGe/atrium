"""Fakes for the provider layer (hub/llm): no test ever calls a real model provider.

- FakeClaude: an Anthropic SDK client (client.beta.messages.create, client.models.list) with scripted Messages API
  responses; `use_claude` plugs it into the real gateway as the Anthropic adapter's client and switches HUB_LLM back
  on for the test (there is no production flag that bypasses HUB_LLM=off).
- ScriptedClaude: a FakeClaude answering each turn by a function of the call; `submits(result)` scripts a model that
  submits `result` through a read-before-write conversation's submit tool (code patches, launch proposals);
  `tool_turn(...)` builds a turn of tool calls.
- chat_transport: an httpx.MockTransport for an OpenAI-compatible server's Chat Completions (hub.llm_transport).
- FakeProvider: an Adapter for resolution and loop tests.
"""

from __future__ import annotations

import itertools
import json
from types import SimpleNamespace
from typing import Any, Callable

import httpx

from hub.llm.types import Caps, ProviderError, Request, Result, Usage

FAKE_KEY = "sk-ant-fake-test-key-0123456789"


def block(type_: str, **fields: Any) -> SimpleNamespace:
    """A Messages API content block (text, tool_use...)."""
    return SimpleNamespace(type=type_, **fields)


def message(stop_reason: str = "end_turn", content: list | None = None, usage: dict | None = None, **extra: Any):
    """A Messages API response: `content` blocks, a stop reason and (optionally) usage counts."""
    return SimpleNamespace(stop_reason=stop_reason, content=content or [], model=extra.pop("model", None),
                           usage=SimpleNamespace(**usage) if usage else None, **extra)


class FakeClaude:
    """`responses`: one scripted response per conversation turn (popped in order); `json_result`: the answer to every
    structured call (output_config.format). `calls` records each call's keyword arguments with the messages as they
    were then, plus "prompt" (the first user message) and "schema" (a structured call's JSON schema)."""

    def __init__(self, responses: list | None = None, json_result: Any = None):
        self.responses = list(responses or [])
        self.json_result = json_result
        self.calls: list[dict[str, Any]] = []
        self.models_listed: list[dict[str, Any]] = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create, stream=self.stream))
        self.models = SimpleNamespace(list=self._list_models)

    def _record(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        messages = list(kwargs.get("messages") or [])
        call = {**kwargs, "messages": messages}
        first = messages[0]["content"] if messages else ""
        call["prompt"] = first if isinstance(first, str) else ""
        fmt = (kwargs.get("output_config") or {}).get("format")
        if fmt:
            call["schema"] = fmt["schema"]
        self.calls.append(call)
        return call

    async def create(self, **kwargs: Any) -> Any:
        call = self._record(kwargs)
        if "schema" in call:
            return message(content=[block("text", text=json.dumps(self.json_result))])
        if not self.responses:
            raise AssertionError("FakeClaude has no scripted response left")
        return self.responses.pop(0)

    def stream(self, **kwargs: Any) -> Any:
        """client.beta.messages.stream(...): an async context manager whose get_final_message() is the answer
        create() would give (the call is recorded with "stream": True)."""
        fake = self

        class Stream:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *exc: Any) -> None:
                return None

            async def get_final_message(self) -> Any:
                return await fake.create(**kwargs, stream=True)
        return Stream()

    def _list_models(self, **kwargs: Any) -> Any:
        self.calls.append({"models.list": kwargs})
        items = [SimpleNamespace(model_dump=lambda m=m: m) for m in self.models_listed]

        class Page:
            def __aiter__(self):
                async def gen():
                    for item in items:
                        yield item
                return gen()
        return Page()


_TOOL_IDS = itertools.count(1)


def tool_turn(*calls: tuple, text: str = "") -> SimpleNamespace:
    """An assistant turn calling tools: each call is (name, input) or (name, input, id) - a tool_use block each."""
    blocks = [block("text", text=text)] if text else []
    for name, args, *rest in calls:
        blocks.append(block("tool_use", id=rest[0] if rest else f"tu_{next(_TOOL_IDS)}", name=name, input=args))
    return message("tool_use", blocks)


def tool_results(call: dict[str, Any]) -> list[dict[str, Any]]:
    """The tool_result blocks a recorded call carried in its last user message (what the model got back)."""
    for msg in reversed(call.get("messages") or []):
        if msg.get("role") == "user":
            content = msg.get("content")
            return [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"] \
                if isinstance(content, list) else []
    return []


def turns(call: dict[str, Any]) -> int:
    """How many assistant turns came before this call in its conversation."""
    return sum(1 for m in call.get("messages") or [] if m.get("role") == "assistant")


class ScriptedClaude(FakeClaude):
    """A FakeClaude that answers each conversation turn with `script(call)` (the recorded call: messages, tools,
    system, prompt), so several conversations in one pass - two code patches of one propose - are scripted by their
    content rather than by their order. A structured call gets `json_result` (when it is not None) or script(call);
    a dict or list the script returns for it is sent as the JSON answer."""

    def __init__(self, script: Callable[[dict[str, Any]], Any], json_result: Any = None):
        super().__init__(json_result=json_result)
        self.script = script

    async def create(self, **kwargs: Any) -> Any:
        call = self._record(kwargs)
        if "schema" in call and self.json_result is not None:
            return message(content=[block("text", text=json.dumps(self.json_result))])
        answer = self.script(call)
        if isinstance(answer, (dict, list)):
            return message(content=[block("text", text=json.dumps(answer))])
        return answer


_SAME = object()


def submits(result: dict[str, Any], *, json_result: Any = _SAME) -> ScriptedClaude:
    """A model that answers a read-before-write conversation (hub/agents/reader.py) by calling its submit tool once
    with `fake.submission` (= `result`, changeable later), then ends after any tool answer - accepted or refused. A
    structured call (a text-only path, the enrichment...) gets `json_result`, by default the same `result`, as a
    FakeClaude(json_result=result) answered every call before code patches read files."""

    def script(call: dict[str, Any]) -> Any:
        names = [t.get("name") for t in call.get("tools") or []]
        submit = next((n for n in names if str(n).startswith("submit_")), None)
        if submit is None or tool_results(call):
            return message(content=[block("text", text="Done.")])
        return tool_turn((submit, fake.submission))

    fake = ScriptedClaude(script, json_result=result if json_result is _SAME else json_result)
    fake.submission = result
    return fake


def use_claude(hub: Any, monkeypatch: Any, fake: FakeClaude | None = None, **kwargs: Any) -> FakeClaude:
    """Make `fake` the Anthropic client of `hub`'s gateway (credentials from the environment, HUB_LLM on)."""
    fake = fake or FakeClaude(**kwargs)
    monkeypatch.delenv("HUB_LLM", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    hub.llm.adapters["anthropic"].client_factory = lambda **_: fake
    hub.llm.invalidate()
    return fake


def chat_transport(handler: Callable[[dict[str, Any]], dict[str, Any] | httpx.Response]) -> tuple[httpx.MockTransport, list]:
    """A Chat Completions server: `handler(body)` answers each POST /chat/completions (a dict is sent as JSON);
    GET /models lists one model. Returns the transport and the recorded requests (method, path, headers, body)."""
    seen: list[tuple[str, str, dict, dict]] = []

    def serve(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        seen.append((request.method, request.url.path, dict(request.headers), body))
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"object": "list", "data": [{"id": "m1", "object": "model"}]})
        answer = handler(body)
        return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)

    return httpx.MockTransport(serve), seen


def completion(content: str | None = "", tool_calls: list | None = None, finish: str = "stop",
               usage: dict | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"choices": [{"finish_reason": finish, "message": {
        "role": "assistant", "content": content, **({"tool_calls": tool_calls} if tool_calls else {})}}]}
    if usage is not None:
        out["usage"] = usage
    return out


OPENAI_KEY = "sk-proj-fake-openai-key-0123456789"


def responses_transport(handler: Callable[[dict[str, Any]], dict[str, Any] | httpx.Response],
                        models: list[str] | None = None) -> tuple[httpx.MockTransport, list]:
    """An OpenAI (or Azure OpenAI) Responses API: `handler(body)` answers each POST .../responses (a dict is sent as
    JSON); GET .../models lists `models`. Returns the transport and the recorded requests (method, URL, headers,
    body); a redirect or error can be returned as an httpx.Response."""
    seen: list[tuple[str, str, dict, dict]] = []

    def serve(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        seen.append((request.method, str(request.url), dict(request.headers), body))
        if request.url.path.endswith("/models"):
            return httpx.Response(200, json={"object": "list", "data": [
                {"id": m, "object": "model", "created": 1, "owned_by": "openai"} for m in (models or ["gpt-6-luna"])]})
        answer = handler(body)
        return answer if isinstance(answer, httpx.Response) else httpx.Response(200, json=answer)

    return httpx.MockTransport(serve), seen


def response(*items: dict[str, Any], status: str = "completed", usage: dict | None = None,
             incomplete: str | None = None, model: str = "gpt-6-luna") -> dict[str, Any]:
    """A Responses API response object with these output items."""
    out: dict[str, Any] = {"id": "resp_1", "object": "response", "status": status, "model": model, "output": list(items)}
    if incomplete:
        out["incomplete_details"] = {"reason": incomplete}
    if usage is not None:
        out["usage"] = usage
    return out


def said(text: str, item_id: str = "msg_1") -> dict[str, Any]:
    """A `message` output item with one output_text part."""
    return {"type": "message", "id": item_id, "role": "assistant", "status": "completed",
            "content": [{"type": "output_text", "text": text, "annotations": []}]}


def function_call(name: str, arguments: str | dict, call_id: str = "call_1") -> dict[str, Any]:
    return {"type": "function_call", "id": f"fc_{call_id}", "call_id": call_id, "name": name,
            "arguments": arguments if isinstance(arguments, str) else json.dumps(arguments), "status": "completed"}


def reasoning(item_id: str = "rs_1") -> dict[str, Any]:
    return {"type": "reasoning", "id": item_id, "summary": [], "encrypted_content": "gAAAA-opaque"}


def use_openai(client: Any, monkeypatch: Any, handler: Callable, *, models: list[str] | None = None,
               default_model: str = "gpt-6-luna", env: bool = False) -> list:
    """Configure the built-in OpenAI provider against a fake Responses API (stored key, or OPENAI_API_KEY with
    `env`), switch HUB_LLM back on for the test, and return the recorded requests."""
    hub = client.app.state.hub
    transport, seen = responses_transport(handler, models)
    hub.llm_transport = transport
    monkeypatch.delenv("HUB_LLM", raising=False)
    body: dict[str, Any] = {"default_model": default_model}
    if env:
        monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)
        body["enabled"] = True
    else:
        body["api_key"] = OPENAI_KEY
    assert client.patch("/api/llm/providers/openai", json=body).status_code == 200
    hub.llm.invalidate()
    return seen


class FakeProvider:
    """An Adapter answering scripted Results (or raising ProviderErrors); records each Request it got."""

    kind = "openai_compatible"

    def __init__(self, results: list | None = None, *, ok: bool = True, reason: str | None = None,
                 caps: Caps | None = None, location: str = "self_hosted"):
        self.results = list(results or [])
        self.ok, self.reason, self._caps, self._location = ok, reason, caps or Caps(), location
        self.requests: list[Request] = []

    def location(self) -> str:
        return self._location

    def available(self) -> tuple[bool, str | None]:
        return self.ok, self.reason

    def caps(self, model: str) -> Caps:
        return self._caps

    async def list_models(self) -> list[dict[str, Any]]:
        return [{"id": "fake-model"}]

    async def complete(self, req: Request) -> Result:
        self.requests.append(req)
        item = self.results.pop(0) if self.results else Result(text="Done.", usage=Usage(input_tokens=1))
        if isinstance(item, Exception):
            raise item
        if isinstance(item, str):
            return Result(text=item, usage=Usage(input_tokens=10, output_tokens=5))
        return item


def failing(message: str = "boom", status: int | None = 500) -> ProviderError:
    return ProviderError(message, kind=f"http_{status}" if status else "unreachable", status=status)
