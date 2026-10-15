"""OpenAI and Azure OpenAI over the Responses API behind the provider layer: the request the adapter builds, how it
reads answers (text, tool calls, refusals, cut-offs, usage), the tool loop, learning what a model refuses, retries,
keys that never leak or travel elsewhere, Azure's address and deployments, the model list, the capability probe and
the price table. Every call goes to an httpx.MockTransport (tests/llm_fakes.py)."""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from llm_fakes import (OPENAI_KEY, function_call, reasoning, response, responses_transport, said, use_openai)

from hub import llm_providers
from hub.llm import LLMUnavailable, Msg
from hub.llm.adapters import http as llm_http
from hub.llm.adapters.openai import azure_url_ok, sort_models

AZURE_KEY = "azure-fake-key-abcdef0123456789"
AZURE_URL = "https://contoso-ai.openai.azure.com/openai/v1"
SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}, "note": {"type": "string"}},
          "required": ["answer"], "additionalProperties": False}


def activity(client, text: str) -> list[dict]:
    return [e for e in client.get("/api/activity?limit=500").json() if text in e["text"]]


def posts(seen):
    return [body for method, url, _, body in seen if method == "POST" and url.endswith("/responses")]


def ask(client, hub, history=None, tools=None, run=None, person=None):
    return client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="You help.", tools=tools or [],
                                                       history=history or [Msg(role="user", text="hello")], run=run,
                                                       person=person))


@pytest.fixture
def no_wait(monkeypatch):
    waits: list[float] = []

    async def sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr(llm_http, "sleep", sleep)
    return waits


def test_the_request_body(client, monkeypatch):
    hub = client.app.state.hub
    seen = use_openai(client, monkeypatch, lambda body: response(said("Hi.")))
    tools = [{"name": "list_tools", "description": "List tools.", "strict": True,
              "input_schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False}}]
    reply, meta = ask(client, hub, tools=tools, person="user:u_1")
    assert reply == "Hi." and (meta.provider, meta.model, meta.mode) == ("openai", "gpt-6-luna", "llm")
    method, url, headers, body = seen[-1]
    assert url == "https://api.openai.com/v1/responses" and headers["authorization"] == f"Bearer {OPENAI_KEY}"
    assert body["instructions"] == "You help." and body["input"] == [{"role": "user", "content": "hello"}]
    assert body["tools"] == [{"type": "function", "name": "list_tools", "description": "List tools.",
                              "parameters": tools[0]["input_schema"], "strict": False}]  # validated locally instead
    assert body["store"] is False and body["include"] == ["reasoning.encrypted_content"]
    assert body["reasoning"] == {"effort": "medium"} and body["max_output_tokens"] == 16_000
    assert "temperature" not in body and "text" not in body
    install = hub.store.get("settings", "llm_install_id")["value"]
    assert body["safety_identifier"] == hashlib.sha256(f"{install}|user:u_1".encode()).hexdigest()[:32]
    assert "u_1" not in body["safety_identifier"]


def test_reading_answers(client, monkeypatch):
    hub = client.app.state.hub
    answers = iter([
        response(reasoning(), said("Part one."), said("Part two.", "msg_2"),
                 usage={"input_tokens": 1000, "input_tokens_details": {"cached_tokens": 400}, "output_tokens": 300,
                        "output_tokens_details": {"reasoning_tokens": 120}, "total_tokens": 1300}),
        response({"type": "message", "id": "m", "role": "assistant", "content": [
            {"type": "refusal", "refusal": "I can't help with that."}]}),
        response(said("Half an ans"), status="incomplete", incomplete="max_output_tokens"),
        response(status="incomplete", incomplete="content_filter"),
        {"id": "r", "status": "failed", "error": {"code": "server_error", "message": "The model failed"}, "output": []},
        response(said("No usage here.")),
    ])
    use_openai(client, monkeypatch, lambda body: next(answers))
    reply, meta = ask(client, hub)
    assert reply == "Part one.\nPart two."  # every message item, in order
    usage = meta.usage
    assert (usage.input_tokens, usage.cached_input_tokens, usage.output_tokens, usage.reasoning_tokens) == (600, 400, 300, 120)
    assert meta.cost_usd == pytest.approx((600 * 0.1 + 400 * 0.01 + 300 * 0.5) / 1e6)  # gpt-6-luna's price
    assert ask(client, hub)[0] == "I can't help with that request."  # a refusal item
    assert ask(client, hub)[0].startswith("Half an ans\n\n(Reply cut off")
    assert ask(client, hub)[0] == "I can't help with that request."  # content_filter
    with pytest.raises(LLMUnavailable, match="The model failed"):
        ask(client, hub)
    assert ask(client, hub)[1].usage.estimated  # no usage reported: counted from characters


def test_the_tool_loop_replays_reasoning_and_returns_results_by_call_id(client, monkeypatch):
    calls = iter([response(reasoning(), function_call("list_tools", "{}", "call_7"), function_call(
                      "list_approvals", {"status": "pending"}, "call_8")),
                  response(said("The suite is empty."))])
    seen = use_openai(client, monkeypatch, lambda body: next(calls))
    reply = client.post("/api/chat", json={"text": "how is the suite doing?"}).json()
    meta = reply.pop("meta")  # which model answered (shown under the reply)
    assert reply.pop("thread").startswith("m_")  # the conversation on the agent bus
    assert reply == {"reply": "The suite is empty.", "mode": "llm"} and meta["provider"] == "openai"
    first, second = posts(seen)
    assert {t["name"] for t in first["tools"]} >= {"list_tools", "list_approvals"}
    replayed = second["input"]
    assert [i.get("type") or i.get("role") for i in replayed] == ["user", "reasoning", "function_call", "function_call",
                                                                    "function_call_output", "function_call_output"]
    assert replayed[1]["encrypted_content"] == "gAAAA-opaque"  # the reasoning goes back as it came
    outputs = {i["call_id"]: i["output"] for i in replayed if i.get("type") == "function_call_output"}
    assert set(outputs) == {"call_7", "call_8"} and all(isinstance(o, str) for o in outputs.values())
    assert not outputs["call_7"].startswith("Error")


def test_history_from_another_provider_is_rebuilt(client, monkeypatch):
    hub = client.app.state.hub
    seen = use_openai(client, monkeypatch, lambda body: response(said("Sure.")))
    from hub.llm.types import ToolCall

    history = [Msg(role="user", text="hi"),
               Msg(role="assistant", text="Looking.", tool_calls=[ToolCall(id="tu_1", name="list_tools", arguments={})],
                   raw=[{"type": "thinking", "signature": "claude-only"}], provider="anthropic", model="claude-opus-5-5"),
               Msg(role="tool", call_id="tu_1", text="[]"), Msg(role="user", text="and now?")]
    ask(client, hub, history=history)
    items = posts(seen)[-1]["input"]
    assert items[1] == {"role": "assistant", "content": "Looking."}
    assert items[2] == {"type": "function_call", "call_id": "tu_1", "name": "list_tools", "arguments": "{}"}
    assert items[3] == {"type": "function_call_output", "call_id": "tu_1", "output": "[]"}
    assert "claude-only" not in json.dumps(items)  # another provider's raw blocks never travel


def test_structured_answers_use_strict_schemas_and_drop_the_extra_nulls(client, monkeypatch):
    hub = client.app.state.hub
    seen = use_openai(client, monkeypatch, lambda body: response(said('{"answer": "42", "note": null}')))
    value, meta = client.portal.call(lambda: hub.llm.json("patcher", "generate", system="Write JSON.", prompt="Go",
                                                          schema=SCHEMA, schema_name="team design"))
    assert value == {"answer": "42"} and meta.provider == "openai"
    fmt = posts(seen)[-1]["text"]["format"]
    assert fmt["type"] == "json_schema" and fmt["strict"] is True and fmt["name"] == "team_design"
    assert fmt["schema"]["required"] == ["answer", "note"] and fmt["schema"]["properties"]["note"]["type"] == ["string", "null"]


def test_a_refused_strict_schema_falls_back_to_the_prompt(client, monkeypatch):
    hub = client.app.state.hub

    def serve(body):
        if "text" in body:
            return httpx.Response(400, json={"error": {"message": "Invalid schema for response_format 'result'",
                                                       "type": "invalid_request_error", "param": "text.format"}})
        return response(said('Here: {"answer": "ok"}'))

    seen = use_openai(client, monkeypatch, serve)
    value, _ = client.portal.call(lambda: hub.llm.json("patcher", "generate", system="s", prompt="Go", schema=SCHEMA))
    assert value == {"answer": "ok"} and "Answer with one JSON object only" in posts(seen)[-1]["instructions"]
    assert llm_providers.get(hub, "openai").capabilities["gpt-6-luna"].json_schema is False


def test_a_refused_temperature_is_dropped_learned_and_logged_once(client, monkeypatch):
    hub = client.app.state.hub

    def serve(body):
        if "temperature" in body:
            return httpx.Response(400, json={"error": {"message": "Unsupported parameter: 'temperature' is not "
                                                       "supported with this model.", "param": "temperature",
                                                       "code": "unsupported_parameter"}})
        return response(said("Fine."))

    seen = use_openai(client, monkeypatch, serve, default_model="gpt-6-astra")
    from hub.llm.types import Request

    req = Request(purpose="chat", agent_id="supervisor", system="s", messages=[Msg(role="user", text="hi")],
                  model="gpt-6-astra", effort="none", temperature=0.2)
    result, _, _ = client.portal.call(lambda: hub.llm.complete("openai", req))
    assert result.text == "Fine." and [("temperature" in b) for b in posts(seen)] == [True, False]
    assert llm_providers.get(hub, "openai").capabilities["gpt-6-astra"].temperature is False
    caps = hub.llm.caps("openai", "gpt-6-astra")  # what OpenAI documents stays known next to what was learned
    assert caps.temperature is False and caps.tools is True and caps.effort_levels[0] == "low"
    client.portal.call(lambda: hub.llm.complete("openai", req))
    assert "temperature" not in posts(seen)[-1]  # learned: not sent again
    logged = activity(client, "temperature")
    assert len(logged) == 1 and "gpt-6-astra" in logged[0]["text"]
    # without reasoning effort "none" the temperature is never sent (OpenAI: remove it when reasoning)
    req.effort, req.model = "low", "gpt-6-luna"
    client.portal.call(lambda: hub.llm.complete("openai", req))
    assert "temperature" not in posts(seen)[-1]


def test_a_refused_effort_is_learned(client, monkeypatch):
    hub = client.app.state.hub

    def serve(body):
        if (body.get("reasoning") or {}).get("effort") == "medium":
            return httpx.Response(400, json={"error": {"message": "Unsupported value: 'reasoning.effort' does not "
                                                       "support 'medium' with this model. Supported values are: "
                                                       "'low' and 'high'.", "param": "reasoning.effort"}})
        return response(said("ok"))

    seen = use_openai(client, monkeypatch, serve, default_model="o-small")
    assert ask(client, hub)[0] == "ok"
    assert "reasoning" not in posts(seen)[-1]
    assert llm_providers.get(hub, "openai").capabilities["o-small"].effort_levels == ["low", "high"]


def test_rate_limits_are_retried_then_reported(client, monkeypatch, no_wait):
    hub = client.app.state.hub
    replies = iter([httpx.Response(429, headers={"retry-after": "2"}, json={"error": {"message": "Rate limit"}}),
                    httpx.Response(503, json={"error": {"message": "Overloaded"}}),
                    response(said("Made it."))])
    use_openai(client, monkeypatch, lambda body: next(replies))
    assert ask(client, hub)[0] == "Made it." and no_wait == [2.0, 4.0]  # Retry-After, then the backoff
    no_wait.clear()
    use_openai(client, monkeypatch, lambda body: httpx.Response(429, headers={"retry-after": "120"},
                                                                json={"error": {"message": "Slow down"}}))
    with pytest.raises(LLMUnavailable, match="HTTP 429"):
        ask(client, hub)
    assert no_wait == [30.0, 30.0]  # at most 30 s per wait, two retries


def test_errors_and_redirects_never_carry_the_key(client, monkeypatch):
    hub = client.app.state.hub
    seen = use_openai(client, monkeypatch, lambda body: httpx.Response(
        401, json={"error": {"message": f"Incorrect API key provided: {OPENAI_KEY}"}}))
    with pytest.raises(LLMUnavailable) as failed:
        ask(client, hub)
    assert OPENAI_KEY not in str(failed.value) and "HTTP 401" in str(failed.value) and "check the API key" in str(failed.value)
    seen.clear()
    use_openai(client, monkeypatch, lambda body: httpx.Response(307, headers={"location": "https://evil.example/v1/responses"}))
    with pytest.raises(LLMUnavailable, match="redirected"):
        ask(client, hub)
    assert all(url.startswith("https://api.openai.com/") for _, url, _, _ in seen)  # never followed
    exposed = [client.get(p).text for p in ("/api/llm/providers", "/api/settings", "/api/agents", "/api/activity",
                                            "/api/overview", "/api/llm/prices")]
    exposed += [json.dumps(hub.store.tail("llm_usage", 100)), json.dumps(hub.store.list("llm_usage_daily"))]
    assert all(OPENAI_KEY not in text for text in exposed)
    stored = hub.store.get("llm_providers", "openai")["api_key"]
    assert stored != OPENAI_KEY and hub.secrets.decrypt(stored) == OPENAI_KEY


def test_the_key_never_reaches_the_event_stream(client, monkeypatch):
    hub = client.app.state.hub
    events = []
    hub.bus.listen(lambda type_, data: events.append((type_, json.dumps(data, default=str))))
    use_openai(client, monkeypatch, lambda body: response(said("Hi.")))
    client.post("/api/chat", json={"text": "hi"})
    client.post("/api/llm/providers/openai/test")
    assert any(t == "llm_provider" for t, _ in events)
    assert all(OPENAI_KEY not in data for _, data in events)


def test_the_address_is_fixed_and_the_environment_cannot_redirect_it(client, monkeypatch):
    hub = client.app.state.hub
    monkeypatch.setenv("OPENAI_BASE_URL", "https://proxy.example/v1")
    seen = use_openai(client, monkeypatch, lambda body: response(said("Hi.")))
    changed = client.patch("/api/llm/providers/openai", json={"base_url": "https://evil.example/v1", "name": "Mine"})
    assert changed.json()["base_url"] == "https://api.openai.com/v1" and changed.json()["name"] == "OpenAI"
    ask(client, hub)
    assert seen[-1][1] == "https://api.openai.com/v1/responses"
    assert client.delete("/api/llm/providers/openai").status_code == 409  # built in: remove the key instead
    assert client.post("/api/llm/providers", json={"kind": "openai", "variant": None, "name": "Second OpenAI",
                                                   "base_url": "https://api.openai.com/v1"}).status_code in (400, 422)


def test_openai_is_seeded_off_and_switched_on_by_a_key_or_the_environment(client, monkeypatch):
    hub = client.app.state.hub
    monkeypatch.delenv("HUB_LLM")
    record = client.get("/api/llm/providers").json()["records"][1]
    assert (record["id"], record["enabled"], record["api_key_set"], record["key_source"]) == ("openai", False, False, None)
    assert hub.llm.blocked_reason("openai") == "switched off"
    monkeypatch.setenv("OPENAI_API_KEY", OPENAI_KEY)  # an untouched record runs on the environment's key
    assert hub.llm.blocked_reason("openai") is None
    assert client.patch("/api/llm/providers/openai", json={"default_model": "gpt-6-luna"}).json()["enabled"]  # stays on
    assert hub.llm.ready("supervisor", "chat") and hub.llm.resolve("supervisor", "chat").provider == "openai"
    off = client.patch("/api/llm/providers/openai", json={"enabled": False}).json()
    assert not off["enabled"] and hub.llm.blocked_reason("openai") == "switched off"
    assert client.patch("/api/llm/providers/openai", json={"default_model": "gpt-6.1-sol"}).json()["enabled"] is False
    warned = activity(client, "on/off")
    assert warned and warned[0]["level"] == "warn"
    monkeypatch.delenv("OPENAI_API_KEY")
    on = client.patch("/api/llm/providers/openai", json={"api_key": OPENAI_KEY}).json()  # a stored key switches it on
    assert on["enabled"] and on["key_source"] == "stored" and OPENAI_KEY not in json.dumps(on)
    assert activity(client, "API key set")
    monkeypatch.setenv("HUB_LLM", "off")
    assert hub.llm.blocked_reason("openai") == "HUB_LLM=off"


def test_automatic_prefers_claude_then_openai(client, monkeypatch):
    from llm_fakes import use_claude

    hub = client.app.state.hub
    use_openai(client, monkeypatch, lambda body: response(said("Hi.")))
    assert hub.llm.resolve("supervisor", "chat").provider == "openai"
    use_claude(hub, monkeypatch, responses=[])
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"


def test_the_model_list_hides_what_is_not_a_text_model(client, monkeypatch):
    models = ["text-embedding-3-large", "gpt-6-luna", "whisper-1", "tts-1", "gpt-image-2", "omni-moderation-latest",
              "gpt-realtime", "my-fine-tune", "gpt-6-astra", "gpt-audio"]
    use_openai(client, monkeypatch, lambda body: response(said("Hi.")), models=models)
    tested = client.post("/api/llm/providers/openai/test").json()
    assert tested["ok"] and tested["models"] == ["gpt-6-astra", "gpt-6-luna", "my-fine-tune"]  # flagships first
    assert "7 other model(s)" in tested["detail"]
    assert tested["capabilities"] == {}  # OpenAI's list carries no capabilities
    view = client.get("/api/llm/providers").json()
    assert view["known_models"]["openai"] == ["gpt-6-astra", "gpt-6.1-sol", "gpt-6-luna"]
    choice = next(c for c in view["choices"] if c["id"] == "openai")
    assert choice["available"] and choice["kind"] == "openai" and choice["location"] == "third_party"
    assert sort_models(["b", "gpt-6-luna", "a", "gpt-6-astra"]) == ["gpt-6-astra", "gpt-6-luna", "a", "b"]


def test_an_agent_can_chat_with_tools_on_openai(client, monkeypatch):
    calls = iter([response(function_call("list_tools", "{}")), response(said("Nothing is imported yet."))])
    seen = use_openai(client, monkeypatch, lambda body: next(calls))
    created = client.post("/api/agents", json={"name": "Helper", "team": "hub", "provider": "openai",
                                               "permissions": ["read"]}).json()
    assert created["provider"] == "openai" and created["provider_label"] == "OpenAI" and created["model"] == "gpt-6-luna"
    reply = client.post(f"/api/agents/{created['id']}/chat", json={"text": "What tools are there?"}).json()
    assert reply["reply"] == "Nothing is imported yet." and reply["mode"] == "llm"
    first = posts(seen)[0]
    assert "list_tools" in {t["name"] for t in first["tools"]} and "run_command" not in {t["name"] for t in first["tools"]}
    assert client.delete("/api/llm/providers/openai").status_code == 409


def test_azure_openai(client, monkeypatch):
    hub = client.app.state.hub
    transport, seen = responses_transport(lambda body: response(said("pong"), model=body["model"]))
    hub.llm_transport = transport
    monkeypatch.delenv("HUB_LLM")
    bad = client.post("/api/llm/providers", json={"kind": "openai", "variant": "azure", "name": "Azure",
                                                  "base_url": "https://evil.example.com/openai/v1"})
    assert bad.status_code == 400 and "openai.azure.com" in bad.json()["detail"]
    created = client.post("/api/llm/providers", json={
        "kind": "openai", "variant": "azure", "name": "Azure prod", "base_url": AZURE_URL + "/", "api_key": AZURE_KEY,
        "default_model": "prod-gpt", "pinned_models": ["prod-gpt", "prod-gpt", "batch-gpt"]})
    assert created.status_code == 201, created.text
    azure = created.json()
    assert (azure["id"], azure["kind"], azure["variant"], azure["location"]) == ("azure-prod", "openai", "azure", "third_party")
    assert azure["base_url"] == AZURE_URL and azure["pinned_models"] == ["prod-gpt", "batch-gpt"] and azure["enabled"]
    assert AZURE_KEY not in created.text and azure["key_source"] == "stored"
    tested = client.post("/api/llm/providers/azure-prod/test").json()
    assert tested["ok"] and "prod-gpt answered" in tested["detail"]
    ping = posts(seen)[-1]
    assert ping["model"] == "prod-gpt" and ping["max_output_tokens"] == 16
    assert seen[-1][1] == f"{AZURE_URL}/responses" and seen[-1][2]["api-key"] == AZURE_KEY
    assert "authorization" not in seen[-1][2]
    # the deployments the list shows (the fake lists gpt-6-luna) or, when it is empty, the typed ones
    assert tested["models"] == ["gpt-6-luna"]
    assert client.patch("/api/llm/providers/azure-prod", json={"base_url": "https://other.services.ai.azure.com/openai/v1"}
                        ).status_code == 400  # the key is bound to the address it was entered for
    moved = client.patch("/api/llm/providers/azure-prod", json={
        "base_url": "https://other.services.ai.azure.com/openai/v1", "api_key": AZURE_KEY})
    assert moved.status_code == 200 and moved.json()["base_url"] == "https://other.services.ai.azure.com/openai/v1"
    assert client.patch("/api/llm/providers/azure-prod", json={"base_url": "http://other.openai.azure.com/openai/v1"}
                        ).status_code == 400
    # an agent on it, and Azure is never part of the automatic choice
    record = client.post("/api/agents", json={"name": "Az", "team": "hub", "provider": "azure-prod"}).json()
    assert record["provider"] == "azure-prod" and record["model"] == "prod-gpt"
    assert client.post(f"/api/agents/{record['id']}/chat", json={"text": "hi"}).json()["reply"] == "pong"
    assert hub.llm.resolve("supervisor", "chat").provider == "rules"


def test_azure_without_a_deployment_list(client, monkeypatch):
    hub = client.app.state.hub

    def serve(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/models"):
            return httpx.Response(404, json={"error": {"message": "Not found"}})
        return httpx.Response(200, json=response(said("pong")))

    hub.llm_transport = httpx.MockTransport(serve)
    monkeypatch.delenv("HUB_LLM")
    client.post("/api/llm/providers", json={"kind": "openai", "variant": "azure", "name": "Az", "base_url": AZURE_URL,
                                            "api_key": AZURE_KEY, "pinned_models": ["dep-a", "dep-b"]})
    untested = client.post("/api/llm/providers/az/test").json()
    assert not untested["ok"] and "deployment name" in untested["detail"]
    client.patch("/api/llm/providers/az", json={"default_model": "dep-a"})
    tested = client.post("/api/llm/providers/az/test").json()
    assert tested["ok"] and tested["models"] == ["dep-a", "dep-b"]


@pytest.mark.parametrize("url, ok", [
    ("https://contoso.openai.azure.com/openai/v1", True), ("https://contoso.openai.azure.com/openai/v1/", True),
    ("https://my-res-2.services.ai.azure.com/openai/v1", True),
    ("http://contoso.openai.azure.com/openai/v1", False), ("https://contoso.openai.azure.com.evil.io/openai/v1", False),
    ("https://contoso.openai.azure.com/openai/v1/deployments", False), ("https://evil.io/x.openai.azure.com/openai/v1", False),
    ("https://user@contoso.openai.azure.com/openai/v1", False), ("https://CONTOSO.openai.azure.com/openai/v1", False),
])
def test_azure_addresses(url, ok):
    assert azure_url_ok(url) is ok


def test_the_probe_checks_tools_and_json(client, monkeypatch):
    hub = client.app.state.hub

    def serve(body):
        if body.get("tools"):
            return response(function_call("report_ok", {"ok": True}), usage={"input_tokens": 40, "output_tokens": 9})
        assert body["text"]["format"]["strict"] is True and body["max_output_tokens"] == 256
        return response(said('{"ok": true}'), usage={"input_tokens": 30, "output_tokens": 5})

    use_openai(client, monkeypatch, serve)
    probed = client.post("/api/llm/providers/openai/probe", json={"model": "my-fine-tune"})
    assert probed.status_code == 200, probed.text
    result = probed.json()
    assert result["caps"]["tools"] is True and result["caps"]["json_schema"] is True and result["tokens"] == 84
    assert result["caps"]["source"] == "probe"
    caps = llm_providers.get(hub, "openai").capabilities["my-fine-tune"]
    assert (caps.tools, caps.json_schema, caps.source) == (True, True, "probe")
    logged = activity(client, "Checked my-fine-tune")[-1]
    assert "84 tokens" in logged["text"] and "tools yes, JSON yes" in logged["text"] and logged["level"] == "info"
    assert {r["agent_id"] for r in hub.store.tail("llm_usage", 10)} == {"hub"}  # metered


def test_the_probe_records_what_a_model_refuses(client, monkeypatch):
    def serve(body):
        if body.get("tools"):
            return httpx.Response(400, json={"error": {"message": "tools is not supported with this model"}})
        return response(said("Sure, ok is true!"))

    hub = client.app.state.hub
    use_openai(client, monkeypatch, serve)
    caps = client.post("/api/llm/providers/openai/probe", json={"model": "old-model"}).json()["caps"]
    assert caps["tools"] is False and caps["json_schema"] is False
    assert hub.llm.caps("openai", "old-model").tools is False
    off = client.patch("/api/llm/providers/openai", json={"enabled": False})
    assert off.status_code == 200
    assert client.post("/api/llm/providers/openai/probe", json={"model": "x"}).status_code == 409
    assert client.post("/api/llm/providers/nope/probe", json={"model": "x"}).status_code == 404


def test_prices_can_be_read_and_overridden(client, sign_in):
    hub = client.app.state.hub
    view = client.get("/api/llm/prices").json()
    luna = view["defaults"]["openai:gpt-6-luna"]
    assert (luna["input"], luna["cached_input"], luna["output"]) == (0.1, 0.01, 0.5)
    assert luna["as_of"] == "2026-10-14" and luna["source"].startswith("https://developers.openai.com/")
    assert sign_in("viewer").get("/api/llm/prices").status_code == 200
    assert sign_in("operator").put("/api/llm/prices", json={"overrides": {}}).status_code == 403
    changed = client.put("/api/llm/prices", json={"overrides": {"openai:gpt-6-astra": {"input": 1.25, "output": 10}}})
    assert changed.status_code == 200
    assert changed.json()["effective"]["openai:gpt-6-astra"]["input"] == 1.25
    assert activity(client, "AI prices changed: openai:gpt-6-astra input 0 -> 1.25")
    from hub.llm import usage as llm_usage
    from hub.llm.types import Usage

    price = llm_usage.price_for(hub, "openai", "gpt-6-astra")
    assert llm_usage.cost(price, Usage(input_tokens=1_000_000, output_tokens=100_000)) == pytest.approx(2.25)
    back = client.put("/api/llm/prices", json={"overrides": {"openai:gpt-6-astra": None}}).json()
    assert "openai:gpt-6-astra" not in back["effective"] and back["overrides"] == {}
    for bad in ({"nope:model": {"input": 1}}, {"openai:": {"input": 1}}, {"openai:x": {"input": -1}},
                {"openai:x": {"input": 10_001}}, {"openai:x": {"tiers": [{"above_input_tokens": 0}]}}):
        assert client.put("/api/llm/prices", json={"overrides": bad}).status_code in (400, 422), bad
