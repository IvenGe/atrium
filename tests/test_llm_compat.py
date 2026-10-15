"""Local model servers (OpenAI-compatible Chat Completions) behind the provider layer: only they count as "local"
next to the built-in records, the structured-output ladder learns what a server refuses, usage is estimated when a
server reports none, and where a provider runs is computed from its address."""

from __future__ import annotations

import json

import httpx
import pytest
from llm_fakes import chat_transport, completion

from hub import llm_providers
from hub.agents import teams
from hub.llm import LLMUnavailable, Msg
from hub.llm.registry import location_of

SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"],
          "additionalProperties": False}


def provider(client, **values) -> str:
    created = client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "qwen3:8b", **values})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def json_call(client, hub, agent="patcher", purpose="generate"):
    return client.portal.call(lambda: hub.llm.json(agent, purpose, system="Write JSON.", prompt="Go", schema=SCHEMA))


def test_only_the_model_servers_people_add_count_as_local(client):
    hub = client.app.state.hub
    assert {p.id for p in llm_providers.all_providers(hub)} == {"anthropic", "openai"}  # the seeded built-ins
    assert llm_providers.local(hub) == [] and teams.default_provider(hub) == "rules"  # never the seeded Claude record
    assert [c["id"] for c in teams.provider_choices(hub)] == ["anthropic", "openai", "rules"]
    assert [c["kind"] for c in teams.provider_choices(hub)] == ["anthropic", "openai", "rules"]  # none counts as local
    ollama = provider(client)
    assert [c["id"] for c in teams.provider_choices(hub)] == ["anthropic", "openai", "rules", ollama]
    assert [c["id"] for c in teams.provider_choices(hub) if c["kind"] == "local"] == [ollama]
    assert teams.default_provider(hub) == ollama
    assert [p["id"] for p in client.get("/api/llm/providers").json()["providers"]] == [ollama]


def test_the_structured_ladder_learns_what_a_server_refuses(client):
    hub = client.app.state.hub

    def serve(body):
        mode = (body.get("response_format") or {}).get("type")
        if mode in ("json_schema", "json_object"):
            return httpx.Response(400, json={"error": {"message": f"response_format {mode} is not supported"}})
        assert "Answer with one JSON object only" in body["messages"][0]["content"]
        return completion('Sure:\n```json\n{"answer": "42"}\n```')

    transport, seen = chat_transport(serve)
    hub.llm_transport = transport
    ollama = provider(client)
    value, meta = json_call(client, hub)
    assert value == {"answer": "42"} and meta.provider == ollama and meta.mode == "local"
    modes = [(b.get("response_format") or {}).get("type") for _, path, _, b in seen if path.endswith("/chat/completions")]
    assert modes == ["json_schema", "json_object", None]
    caps = llm_providers.get(hub, ollama).capabilities["qwen3:8b"]
    assert (caps.json_schema, caps.json_object, caps.source) == (False, False, "learned")
    learned = [e for e in client.get("/api/activity").json() if "structured-output mode" in e["text"]]
    assert len(learned) == 2  # once per mode
    seen.clear()
    json_call(client, hub)  # the next call starts with the mode that works
    assert [(b.get("response_format") or {}).get("type") for _, _, _, b in seen] == [None]


def test_a_wrong_answer_gets_one_repair_round(client):
    hub = client.app.state.hub
    answers = iter([completion('{"answer": 42}'), completion('{"answer": "42"}'),
                    completion('{"answer": 1}'), completion('{"nope": true}')])
    transport, seen = chat_transport(lambda body: next(answers))
    hub.llm_transport = transport
    provider(client, structured_output="json_schema")
    assert json_call(client, hub)[0] == {"answer": "42"}
    repair = seen[1][3]["messages"]
    assert repair[-1]["role"] == "user" and "$.answer must be string" in repair[-1]["content"]
    with pytest.raises(LLMUnavailable, match="unusable"):
        json_call(client, hub)


def test_usage_is_estimated_when_the_server_reports_none_and_effort_is_opt_in(client):
    hub = client.app.state.hub
    answers = iter([completion("Hi there.", usage={"prompt_tokens": 120, "completion_tokens": 7,
                                                  "prompt_tokens_details": {"cached_tokens": 20}}),
                    completion("Hello again.")])
    transport, seen = chat_transport(lambda body: next(answers))
    hub.llm_transport = transport
    ollama = provider(client)
    run = lambda: hub.llm.converse("supervisor", "chat", system="s", history=[Msg(role="user", text="hi")], tools=[],  # noqa: E731
                                   run=None)
    _, meta = client.portal.call(run)
    assert (meta.usage.input_tokens, meta.usage.cached_input_tokens, meta.usage.output_tokens) == (100, 20, 7)
    assert meta.cost_usd == 0.0 and not meta.usage.estimated  # own hardware: no price unless an admin sets one
    _, meta = client.portal.call(run)
    assert meta.usage.estimated and meta.usage.input_tokens > 0
    assert "reasoning_effort" not in seen[0][3]
    record = llm_providers.get(hub, ollama)
    record.send_effort = True
    llm_providers.put(hub, record)
    answers = iter([completion("ok")])
    client.portal.call(run)
    assert seen[-1][3]["reasoning_effort"] == "medium"


def test_tool_arguments_that_are_not_json_come_back_as_a_failed_call(client):
    hub = client.app.state.hub
    calls = iter([completion(None, tool_calls=[{"id": "c1", "type": "function", "function": {
        "name": "list_tools", "arguments": "{not json"}}], finish="tool_calls"), completion("Sorry.")])
    transport, seen = chat_transport(lambda body: next(calls))
    hub.llm_transport = transport
    provider(client)
    ran = []

    async def run(name, args):
        ran.append(name)

    tools = [{"name": "list_tools", "description": "d", "input_schema": {"type": "object", "properties": {}}}]
    reply, _ = client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", tools=tools, run=run,
                                                           history=[Msg(role="user", text="hi")]))
    assert reply == "Sorry." and ran == []
    tool_message = seen[1][3]["messages"][-1]
    assert tool_message["role"] == "tool" and "not valid JSON" in tool_message["content"]


@pytest.mark.parametrize("url, where", [
    ("http://localhost:11434/v1", "self_hosted"), ("http://127.0.0.1:8000/v1", "self_hosted"),
    ("http://10.1.2.3/v1", "self_hosted"), ("http://192.168.1.20:1234/v1", "self_hosted"),
    ("http://[fd00::5]:8000/v1", "self_hosted"), ("http://gpu-box:11434/v1", "self_hosted"),
    ("http://ollama.local/v1", "self_hosted"), ("https://llm.example.com/v1", "third_party"),
    ("https://8.8.8.8/v1", "third_party"), ("http://gpu-box.lan:11434/v1", "third_party"),
])
def test_where_a_provider_runs(url, where):
    assert location_of(url) == where


def test_a_new_provider_records_where_it_runs(client):
    hub = client.app.state.hub
    ollama = provider(client)
    remote = provider(client, name="Hosted", base_url="https://llm.example.com/v1")
    assert llm_providers.get(hub, ollama).location == "self_hosted"
    assert llm_providers.get(hub, remote).location == "third_party"
    assert json.loads(client.get("/api/llm/providers").text)["providers"][1]["location"] == "third_party"


def test_a_public_address_needs_https_unless_an_administrator_confirms_it_is_their_own(client):
    hub = client.app.state.hub
    plain = client.post("/api/llm/providers", json={"name": "Remote", "base_url": "http://llm.example.com/v1"})
    assert plain.status_code == 400 and "https" in plain.json()["detail"]
    ours = client.post("/api/llm/providers", json={"name": "Ours", "base_url": "http://gpu.example.com/v1",
                                                   "confirm_self_hosted": True})
    assert ours.status_code == 201, ours.text
    assert (ours.json()["location"], ours.json()["location_confirmed"]) == ("self_hosted", True)
    marked = [e for e in client.get("/api/activity?limit=500").json() if "as self-hosted" in e["text"]]
    assert len(marked) == 1 and marked[0]["level"] == "warn" and "gpu.example.com" in marked[0]["text"]
    renamed = client.patch(f"/api/llm/providers/{ours.json()['id']}", json={"name": "Ours 2",
                                                                            "base_url": "http://gpu.example.com/v1"})
    assert renamed.json()["location_confirmed"]  # the same host keeps its confirmation (and logs no new warning)
    assert len([e for e in client.get("/api/activity?limit=500").json() if "as self-hosted" in e["text"]]) == 1
    undone = client.patch(f"/api/llm/providers/{ours.json()['id']}", json={"confirm_self_hosted": False})
    assert undone.status_code == 400  # back to a third party: plain http is refused
    # a proxy on this machine that forwards to a cloud service can be marked a third party
    proxy = client.post("/api/llm/providers", json={"name": "Proxy", "base_url": "http://127.0.0.1:4000/v1",
                                                    "location": "third_party"}).json()
    assert proxy["location"] == "third_party" and hub.llm.location(proxy["id"]) == "third_party"
    assert client.patch(f"/api/llm/providers/{proxy['id']}", json={"timeout": 60}).json()["location"] == "third_party"
    hosted = client.post("/api/llm/providers", json={"name": "Hosted", "base_url": "https://llm.example.com/v1",
                                                     "structured_output": "json_object", "send_effort": True}).json()
    assert (hosted["location"], hosted["structured_output"], hosted["send_effort"]) == ("third_party", "json_object", True)
