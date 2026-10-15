"""The Anthropic adapter: credentials (the environment wins over a stored key), the request it builds, how it reads
the answer (stop reasons, usage, thinking blocks replayed), the cost estimate, and errors without the key."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from llm_fakes import FAKE_KEY, FakeClaude, block, message, use_claude

from hub import llm_providers
from hub.llm import LLMUnavailable, Msg
from hub.llm import usage as llm_usage
from hub.llm.adapters import anthropic as claude_adapter
from hub.llm.types import ProviderError, Request, Usage

STORED_KEY = "sk-ant-stored-key-abcdef0123456789"


def adapter(hub):
    return hub.llm.adapters["anthropic"]


def ask(client, hub, **kwargs):
    history = kwargs.pop("history", None) or [Msg(role="user", text="hello")]
    return client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="You help.", history=history,
                                                       tools=kwargs.pop("tools", []), run=kwargs.pop("run", None),
                                                       person=kwargs.pop("person", None)))


def test_credentials_the_environment_wins_over_a_stored_key(client, monkeypatch, tmp_path):
    hub = client.app.state.hub
    monkeypatch.setenv("HOME", str(tmp_path))  # ~/.config/anthropic would count as a profile
    monkeypatch.delenv("HUB_LLM")
    claude = adapter(hub)
    ok, reason = claude.available()
    assert claude.key_source() is None and not ok and "no API key" in reason
    made = []
    fake = FakeClaude([message("end_turn", [block("text", text="Hi.")])] * 2)
    claude.client_factory = lambda **kwargs: made.append(kwargs) or fake
    assert client.patch("/api/llm/providers/anthropic", json={"api_key": STORED_KEY}).status_code == 200
    assert claude.key_source() == "stored" and hub.llm.ready("supervisor", "chat")
    ask(client, hub)
    assert made[-1] == {"api_key": STORED_KEY, "base_url": "https://api.anthropic.com"}  # only to the fixed address
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    ask(client, hub)
    assert claude.key_source() == "env" and made[-1] == {}  # the SDK reads the environment, as before
    view = client.get("/api/llm/providers").json()
    assert next(p for p in view["builtin"] if p["id"] == "anthropic")["api_key_set"]
    assert view["llm"]["providers"][0]["key_source"] == "env"
    exposed = [client.get(p).text for p in ("/api/llm/providers", "/api/settings", "/api/agents", "/api/activity",
                                            "/api/overview")]
    assert all(STORED_KEY not in text and FAKE_KEY not in text for text in exposed)
    assert client.delete("/api/llm/providers/anthropic").status_code == 409  # built in: remove the key instead
    assert client.patch("/api/llm/providers/anthropic", json={"base_url": "https://evil.example"}).json()["base_url"] \
        == "https://api.anthropic.com"


def test_without_the_sdk_claude_is_unavailable_even_with_a_stored_key(client, monkeypatch):
    hub = client.app.state.hub
    monkeypatch.delenv("HUB_LLM")
    llm_providers.save(hub, "anthropic", {"api_key": STORED_KEY}, "test")
    monkeypatch.setattr(claude_adapter, "anthropic", None)
    ok, reason = adapter(hub).available()
    assert not ok and reason == "the anthropic package is not installed (pip install atrium[ai])"
    assert not hub.llm.ready("supervisor", "chat")
    assert client.get("/api/settings").json()["llm"]["installed"] is False


def test_the_request_it_builds(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="Hi.")])], json_result={})
    ask(client, hub, person="user:u_1", tools=[{"name": "t", "description": "d", "input_schema": {"type": "object"}}])
    call = fake.calls[0]
    assert call["output_config"] == {"effort": "medium"} and "temperature" not in call
    assert call["cache_control"] == {"type": "ephemeral"} and call["max_tokens"] == 16000
    assert call["betas"] and call["fallbacks"] == "default"  # the server-side refusal fallback, as before
    assert call["tools"][0]["name"] == "t" and call["tools"][0].get("strict") is not False
    assert call["system"] == "You help."
    user_id = call["metadata"]["user_id"]
    assert len(user_id) == 32 and "u_1" not in user_id  # a salted hash, never the person's id or name
    result, meta = client.portal.call(lambda: hub.llm.json("patcher", "code", system="s", prompt="p",
                                                           schema={"type": "object", "properties": {}}, effort="high"))
    assert fake.calls[1]["output_config"] == {"effort": "high", "format": {"type": "json_schema", "schema": {
        "type": "object", "properties": {}}}}
    assert meta.provider == "anthropic" and meta.model == "claude-opus-5-5"
    many = [{"name": f"t{i}", "description": "d", "strict": True, "input_schema": {"type": "object"}}
            for i in range(claude_adapter.STRICT_TOOL_LIMIT + 1)]
    wider = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="Hi.")])])
    ask(client, hub, tools=many)
    sent = wider.calls[0]["tools"]
    assert len(sent) == len(many) and all(tool["strict"] is False for tool in sent)
    assert many[0]["strict"] is True  # the caller's definitions stay strict


def test_stop_reasons_usage_and_thinking_blocks(client, monkeypatch):
    hub = client.app.state.hub
    thinking = block("thinking", thinking="...", signature="sig-1")
    usage = {"input_tokens": 100, "cache_read_input_tokens": 50, "cache_creation_input_tokens": 10, "output_tokens": 20,
             "output_tokens_details": SimpleNamespace(thinking_tokens=7), "inference_geo": "global"}
    fake = use_claude(hub, monkeypatch, responses=[
        message("pause_turn", [thinking], usage=usage),
        message("tool_use", [block("tool_use", id="tu_1", name="echo", input={"x": 1})], usage=usage),
        message("end_turn", [block("text", text="Done it.")], usage=usage),
    ])

    async def run(name, args):
        return {"echoed": args}

    reply, meta = ask(client, hub, run=run, tools=[{"name": "echo", "description": "d", "input_schema": {"type": "object"}}])
    assert reply == "Done it." and len(fake.calls) == 3
    assert fake.calls[1]["messages"][1]["content"][0] is thinking  # replayed as it came, signature and all
    assert fake.calls[2]["messages"][-1]["content"][0] == {"type": "tool_result", "tool_use_id": "tu_1",
                                                          "content": json.dumps({"echoed": {"x": 1}})}
    assert (meta.usage.input_tokens, meta.usage.cached_input_tokens, meta.usage.cache_write_tokens,
            meta.usage.output_tokens, meta.usage.reasoning_tokens) == (300, 150, 30, 60, 21)
    # Opus 5.5: $4 input, $5 cache write, $0.20 cache hit, $20 output per 1M tokens
    assert meta.cost_usd == pytest.approx(3 * (100 * 4 + 10 * 5 + 50 * 0.2 + 20 * 20) / 1e6)

    use_claude(hub, monkeypatch, responses=[message("refusal", [], stop_details=SimpleNamespace(category="cyber"))])
    assert ask(client, hub)[0] == "I can't help with that request."
    use_claude(hub, monkeypatch, responses=[message("max_tokens", [block("text", text="Partial")])])
    reply = ask(client, hub)[0]
    assert reply.startswith("Partial") and "cut off" in reply
    use_claude(hub, monkeypatch, responses=[message("model_context_window_exceeded", [block("text", text="Too long")])])
    assert ask(client, hub)[0] == "Too long"
    adapter(hub).client_factory = lambda **_: SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(
        create=_answer(message("refusal", [])))))
    with pytest.raises(LLMUnavailable, match="declined"):
        client.portal.call(lambda: hub.llm.json("patcher", "code", system="s", prompt="p", schema={"type": "object"}))


def _answer(response):
    async def create(**kwargs):
        return response
    return create


def test_the_cost_estimate_tiers_and_us_only_inference():
    haiku = llm_usage.default_prices()["anthropic:claude-haiku-5-5"]
    small = Usage(input_tokens=50_000, cached_input_tokens=40_000, cache_write_tokens=10_000, output_tokens=1_000)
    assert llm_usage.cost(haiku, small) == pytest.approx((50_000 * 0.1 + 40_000 * 0.01 + 10_000 * 0.125 + 1_000 * 0.5) / 1e6)
    big = small.model_copy(update={"cache_write_tokens": 10_001})  # input + cache reads + writes above 100 000
    assert llm_usage.cost(haiku, big) == pytest.approx((50_000 * 0.5 + 40_000 * 0.05 + 10_001 * 0.625 + 1_000 * 2.5) / 1e6)
    us = small.model_copy(update={"inference_geo": "us"})
    assert llm_usage.cost(haiku, us) == pytest.approx(llm_usage.cost(haiku, small) * 1.1)
    assert llm_usage.cost(None, small) is None  # no price: no cost (token counts still recorded)
    shipped = llm_usage.default_prices()
    assert all(p["source"].startswith("https://platform.claude.com/") and p["as_of"] for k, p in shipped.items()
               if k.startswith("anthropic:"))
    assert all(p["source"].startswith("https://") and p["as_of"] == "2026-10-14" for p in shipped.values())


def test_errors_never_carry_the_key(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)

    class Refused(Exception):
        status_code = 401
        message = f"invalid x-api-key {FAKE_KEY}"

    claude = adapter(hub)
    claude.client_factory = lambda **_: SimpleNamespace(beta=SimpleNamespace(messages=SimpleNamespace(create=_raise(Refused()))))
    with pytest.raises(ProviderError) as caught:
        client.portal.call(claude.complete, Request(purpose="chat", agent_id="supervisor", model="claude-opus-5-5"))
    assert FAKE_KEY not in str(caught.value) and caught.value.status == 401 and "HTTP 401" in str(caught.value)
    assert FAKE_KEY not in (claude.last_error or "") and FAKE_KEY not in json.dumps(hub.llm.status())


def _raise(exc):
    async def create(**kwargs):
        raise exc
    return create


def test_the_model_list_and_its_capabilities(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch)
    fake.models_listed = [
        {"id": "claude-opus-5-5", "display_name": "Claude Opus 5.5", "lifecycle": "active", "max_tokens": 128_000,
         "max_input_tokens": 1_000_000, "capabilities": {"structured_outputs": {"supported": True}, "effort": {
             "supported": True, "low": {"supported": True}, "medium": {"supported": True}, "max": {"supported": False}}}},
        {"id": "claude-old", "lifecycle": "retired"},
        {"id": "claude-sonnet-5", "lifecycle": "deprecated", "retires_at": "2027-01-01T00:00:00Z", "capabilities": None},
    ]
    tested = client.post("/api/llm/providers/anthropic/test").json()
    assert tested["ok"] and tested["models"] == ["claude-opus-5-5", "claude-sonnet-5"]  # retired models are left out
    assert next(c for c in fake.calls if "models.list" in c)["models.list"]["lifecycle"] == ["active", "deprecated"]
    models = client.portal.call(adapter(hub).list_models)
    opus = models[0]["caps"]
    assert (opus.json_schema, opus.effort_levels, opus.max_output_tokens, opus.temperature) == (True, ["low", "medium"],
                                                                                              128_000, False)
    assert models[1]["lifecycle"] == "deprecated" and models[1]["retires_at"]
