"""Every known hub secret is masked in what is sent to a model - system prompt, messages, tool results and tool-call
arguments - for Claude and for local providers, and new secrets are masked at once."""

from __future__ import annotations

import json

from llm_fakes import FakeClaude, block, chat_transport, completion, message, use_claude

from hub import llm_providers
from hub.llm import Msg
from hub.llm.types import ToolCall

CONNECTION_SECRET = "conn-secret-token-9f8e7d6c5b"
PROVIDER_KEY = "local-provider-key-1a2b3c4d5e"
SSO_SECRET = "sso-client-secret-5f6g7h8i9j"
ENV_SECRET = "env-service-api-key-0z9y8x7w"


def leaky_history() -> list[Msg]:
    return [Msg(role="user", text=f"use {CONNECTION_SECRET}"),
            Msg(role="assistant", text="", tool_calls=[ToolCall(id="c1", name="t", arguments={"token": PROVIDER_KEY})]),
            Msg(role="tool", call_id="c1", text=f"result {SSO_SECRET} and {ENV_SECRET}")]


def store_secrets(client, hub, monkeypatch) -> None:
    monkeypatch.setenv("SOME_SERVICE_API_KEY", ENV_SECRET)
    client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "m", "api_key": PROVIDER_KEY})
    hub.store.put("tools", {"id": "wazuh", "name": "Wazuh", "source_type": "saas", "source": "https://wazuh.example.com"})
    from hub.integration import connections

    connections.save(hub, "wazuh", "generic_rest", {"base_url": "https://wazuh.example.com/api", "auth": "bearer",
                                                    "mapping": {"assets": {"list": {"path": "/agents"}, "fields": {
                                                        "external_id": "id"}}}}, {"token": CONNECTION_SECRET}, "test")
    hub.store.put("settings", {"id": "sso", "client_secret": hub.secrets.encrypt(SSO_SECRET)})
    hub.llm.secrets_changed()


def test_secrets_are_masked_for_claude(client, monkeypatch):
    hub = client.app.state.hub
    store_secrets(client, hub, monkeypatch)
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")])])
    client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system=f"key {PROVIDER_KEY}", history=leaky_history(),
                                                tools=[], run=None))
    sent = json.dumps(fake.calls[0], default=str)
    for secret in (CONNECTION_SECRET, PROVIDER_KEY, SSO_SECRET, ENV_SECRET):
        assert secret not in sent
    assert sent.count("***") >= 5


def test_secrets_are_masked_for_local_providers(client, monkeypatch):
    hub = client.app.state.hub
    transport, seen = chat_transport(lambda body: completion("ok"))
    hub.llm_transport = transport
    store_secrets(client, hub, monkeypatch)
    client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system=f"key {SSO_SECRET}", history=leaky_history(),
                                                tools=[], run=None))
    body = json.dumps(seen[-1][3])
    for secret in (CONNECTION_SECRET, PROVIDER_KEY, SSO_SECRET, ENV_SECRET):
        assert secret not in body
    assert seen[-1][2]["authorization"] == f"Bearer {PROVIDER_KEY}"  # the key itself still authenticates


def test_a_new_secret_is_masked_at_once(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, FakeClaude([message("end_turn", [block("text", text="ok")])] * 2))
    ask = lambda text: client.portal.call(lambda: hub.llm.converse(  # noqa: E731
        "supervisor", "chat", system="s", history=[Msg(role="user", text=text)], tools=[], run=None))
    ask("warm the cache")
    llm_providers.save(hub, None, {"name": "Later", "api_key": "brand-new-key-123456789"}, "test")  # an event refreshes it
    ask("leak brand-new-key-123456789")
    assert "brand-new-key-123456789" not in json.dumps(fake.calls[-1], default=str)


def test_secrets_are_masked_for_openai(client, monkeypatch):
    from llm_fakes import OPENAI_KEY, response, said, use_openai

    hub = client.app.state.hub
    store_secrets(client, hub, monkeypatch)
    seen = use_openai(client, monkeypatch, lambda body: response(said("ok")))
    client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system=f"key {CONNECTION_SECRET}",
                                                history=leaky_history(), tools=[], run=None))
    body = json.dumps(seen[-1][3])
    for secret in (CONNECTION_SECRET, PROVIDER_KEY, SSO_SECRET, ENV_SECRET, OPENAI_KEY):
        assert secret not in body
    assert seen[-1][2]["authorization"] == f"Bearer {OPENAI_KEY}"  # only in the header that authenticates


# -- secrets spelled differently by JSON, cut in half, or quoted in a provider's error --------------------------------

ODD_SECRET = 'Pässwörd"with\\quote-2026-xyz'  # non-ASCII, a quote and a backslash: JSON escapes all three
CUT_SECRET = "trunc-secret-value-0123456789abcdef"


def connection_secrets(client, hub, *values: str) -> None:
    hub.store.put("tools", {"id": "hr", "name": "HR", "source_type": "saas", "source": "https://hr.example.com"})
    from hub.integration import connections

    connections.save(hub, "hr", "generic_rest", {"base_url": "https://hr.example.com/api", "auth": "bearer",
                                                 "mapping": {"assets": {"list": {"path": "/a"}, "fields": {
                                                     "external_id": "id"}}}},
                     dict(zip(("token", "password"), values)), "test")
    hub.llm.secrets_changed()


def test_a_secret_in_a_tool_result_is_masked_before_json_escapes_or_cuts_it(client, monkeypatch):
    from hub.agents.loops import MAX_RESULT

    hub = client.app.state.hub
    connection_secrets(client, hub, ODD_SECRET, CUT_SECRET)
    fake = use_claude(hub, monkeypatch, FakeClaude([
        message("tool_use", [block("tool_use", id="c1", name="read_tool_records", input={"tool_id": "hr"}),
                             block("tool_use", id="c2", name="read_tool_records", input={"tool_id": "hr2"})]),
        message("end_turn", [block("text", text="done")])]))
    # the second result is cut at MAX_RESULT characters 12 characters into the secret
    pad = MAX_RESULT - 12 - len('{"pad": "') - len('", "password": "')

    async def run(name, args):
        if args["tool_id"] == "hr":
            return {"records": [{"service_account": "svc", "password": ODD_SECRET}], "tags": ("a", ODD_SECRET)}
        return {"pad": "x" * pad, "password": CUT_SECRET}

    tools = [{"name": "read_tool_records", "description": "d", "input_schema": {"type": "object", "properties": {}}}]
    client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", tools=tools, run=run,
                                                history=[Msg(role="user", text="list")]))
    first, second = (b["content"] for b in fake.calls[1]["messages"][-1]["content"])
    decoded = json.loads(first)
    assert decoded == {"records": [{"service_account": "svc", "password": "***"}], "tags": ["a", "***"]}
    assert second.endswith('"password": "***"}') and CUT_SECRET[:12] not in second  # unmasked, the cut kept 12


def test_every_json_spelling_of_a_secret_is_masked(client):
    """Text that already is JSON (a sidecar's tool result through the subsidiary gateway, playground previews)."""
    hub = client.app.state.hub
    connection_secrets(client, hub, ODD_SECRET)
    mask = hub.llm.mask
    for text in (json.dumps({"p": ODD_SECRET}), json.dumps({"p": ODD_SECRET}, ensure_ascii=False),
                 json.dumps({"body": json.dumps({"p": ODD_SECRET})}), f"raw {ODD_SECRET}"):
        masked = mask.text(text)
        assert ODD_SECRET not in masked and ODD_SECRET not in str(json.loads(masked) if masked[0] == "{" else masked)
        assert "***" in masked
    assert mask.value({"k": [ODD_SECRET, (1, ODD_SECRET)], ODD_SECRET: None, "n": 3}) == {
        "k": ["***", [1, "***"]], "***": None, "n": 3}


def test_a_provider_answer_quoted_in_an_error_never_carries_a_secret(client, sign_in):
    """A misconfigured gateway answers 200 with a debug echo of the request: the chat error and the activity log
    (which every viewer reads) never carry its key, nor another hub secret."""
    hub = client.app.state.hub
    key = "sk-local-gateway-key-77aa88bb99cc"
    connection_secrets(client, hub, CONNECTION_SECRET)
    transport, _ = chat_transport(lambda body: {"request_headers": {"authorization": f"Bearer {key}"},
                                                "detail": f"upstream {CONNECTION_SECRET} not configured"})
    hub.llm_transport = transport
    provider = client.post("/api/llm/providers", json={"name": "Gateway", "default_model": "m1", "api_key": key,
                                                       "base_url": "http://localhost:4000/v1"}).json()["id"]
    agent = client.post("/api/agents", json={"name": "Helper", "provider": provider}).json()["id"]
    reply = client.post(f"/api/agents/{agent}/chat", json={"text": "hello"})
    feed = sign_in("viewer").get("/api/activity?limit=100").text
    assert "Gateway answered without a choice" in reply.text + feed
    for secret in (key, CONNECTION_SECRET):
        assert secret not in reply.text and secret not in feed


def test_an_openai_failure_message_never_carries_a_secret(client, monkeypatch):
    from llm_fakes import OPENAI_KEY, response, use_openai

    hub = client.app.state.hub
    connection_secrets(client, hub, CONNECTION_SECRET)
    use_openai(client, monkeypatch, lambda body: {**response(status="failed"), "error": {
        "message": f"echo: Authorization: Bearer {OPENAI_KEY}; {CONNECTION_SECRET}; password=hunter2-local"}})
    client.patch("/api/llm/selection", json={"default": {"provider": "openai"}})
    from hub.llm import LLMUnavailable

    try:
        client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", tools=[], run=None,
                                                    history=[Msg(role="user", text="hi")]))
    except LLMUnavailable as exc:
        text = str(exc)
    else:
        raise AssertionError("the failed response was not an error")
    assert text.startswith("OpenAI could not answer: echo:")
    for secret in (OPENAI_KEY, CONNECTION_SECRET, "hunter2-local"):
        assert secret not in text
