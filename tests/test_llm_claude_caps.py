"""What Claude models take, and what happens when one refuses a request: the Models API capabilities (effort refused
is "no levels", not "unknown"), the built-in defaults per model family (KNOWN_MODELS) for models nothing is stored
about, the request sent to Claude Haiku 4.5 (no effort), learning from an HTTP 400 and calling again once without the
feature, the structured-output ladder on a 400, and the provider's own message (masked, capped) in the chat, the
activity log (once) and the agent's errors."""

from __future__ import annotations

import anthropic
import httpx2
import pytest
from llm_fakes import FAKE_KEY, FakeClaude, block, message, use_claude

from hub import llm_providers
from hub.agents.supervisor import fallback_note
from hub.llm import Msg, registry, structured
from hub.llm.adapters import anthropic as claude_adapter
from hub.llm.adapters.anthropic import caps_from_info, family, known_caps
from hub.llm.types import ProviderError, Request
from hub.models import ModelCaps

HAIKU = "claude-haiku-4-5"
TOOL = {"name": "t", "description": "d", "input_schema": {"type": "object", "properties": {}, "required": [],
                                                          "additionalProperties": False}, "strict": True}


def bad_request(text: str, status: int = 400) -> anthropic.APIStatusError:
    """The SDK's own error for an HTTP 4xx: body {type: "error", error: {type, message}}, text "Error code: ..."."""
    body = {"type": "error", "error": {"type": "invalid_request_error", "message": text},
            "request_id": "req_011CTest"}
    response = httpx2.Response(status, request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))
    cls = anthropic.BadRequestError if status == 400 else anthropic.APIStatusError
    return cls(f"Error code: {status} - {body}", response=response, body=body)


class Refusing(FakeClaude):
    """A Claude that answers HTTP 400 with `text` whenever `refuses(kwargs)` holds, and like FakeClaude otherwise."""

    def __init__(self, refuses, text: str, **kwargs):
        super().__init__(**kwargs)
        self.refuses, self.text, self.refused = refuses, text, 0

    async def create(self, **kwargs):
        if self.refuses(kwargs):
            self.calls.append({**kwargs, "refused": True})
            self.refused += 1
            raise bad_request(self.text)
        return await super().create(**kwargs)


def on_haiku(client) -> None:
    """The suite default model is Claude Haiku 4.5 (Settings > AI defaults)."""
    sel = client.patch("/api/llm/selection", json={"default": {"provider": "anthropic", "model": HAIKU}})
    assert sel.status_code == 200, sel.text
    assert client.app.state.hub.llm.resolve("supervisor", "chat").model == HAIKU


def store_caps(hub, model: str, **caps) -> None:
    record = llm_providers.get(hub, "anthropic")
    record.capabilities[model] = ModelCaps(**caps)
    llm_providers.put(hub, record)
    hub.llm.invalidate()


def activity(client, words: str) -> list[dict]:
    return [e for e in client.get("/api/activity?limit=500").json() if words in e["text"]]


# -- what a model takes ---------------------------------------------------------------------------


def test_caps_from_the_models_api_tell_refused_effort_from_unknown():
    haiku = caps_from_info({"id": HAIKU, "max_tokens": 64_000, "max_input_tokens": 200_000, "capabilities": {
        "structured_outputs": {"supported": True}, "effort": {
            "supported": False, "low": {"supported": False}, "medium": {"supported": False},
            "high": {"supported": False}, "xhigh": {"supported": False}, "max": {"supported": False}}}})
    assert haiku.effort_levels == [] and haiku.json_schema is True  # no effort parameter at all: never sent
    assert (haiku.max_output_tokens, haiku.context_window, haiku.source) == (64_000, 200_000, "api")
    opus = caps_from_info({"capabilities": {"effort": {"supported": True, "low": {"supported": True},
                                                       "medium": {"supported": True}, "high": {"supported": True},
                                                       "xhigh": {"supported": False}, "max": {"supported": True}}}})
    assert opus.effort_levels == ["low", "medium", "high", "max"]
    assert caps_from_info({"capabilities": {"effort": {"supported": False}}}).effort_levels == []
    for unknown in ({}, {"capabilities": None}, {"capabilities": {"effort": {}}},
                    {"capabilities": {"effort": {"supported": True}}}):  # supported, levels not said: all may work
        assert caps_from_info(unknown).effort_levels is None
    assert caps_from_info({"capabilities": {"structured_outputs": {"supported": False}}}).json_schema is False


def test_known_model_families_give_defaults_without_a_models_list(client):
    assert known_caps(HAIKU)["effort_levels"] == [] and known_caps(HAIKU)["max_output_tokens"] == 64_000
    for spelling in ("claude-haiku-4-5-20251001", "anthropic.claude-haiku-4-5-20251001-v1:0",
                     "us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5@20251001", "CLAUDE-HAIKU-4-5"):
        assert family(spelling) == HAIKU, spelling  # snapshots, Bedrock and Google Cloud ids
    assert known_caps("claude-sonnet-4-5")["effort_levels"] == []
    assert known_caps("claude-opus-4-5-20251101")["effort_levels"] == ["low", "medium", "high"]
    assert known_caps("claude-opus-4-6")["effort_levels"] == ["low", "medium", "high", "max"]  # no xhigh before 4.7
    assert known_caps("claude-sonnet-4-6")["effort_levels"] == ["low", "medium", "high", "max"]
    for current in ("claude-opus-4-7", "claude-opus-4-8", "claude-opus-5", "claude-opus-5-5", "claude-sonnet-5-5",
                    "claude-haiku-5-5", "claude-fable-5-1"):
        assert known_caps(current)["effort_levels"] == ["low", "medium", "high", "xhigh", "max"], current
    assert family("claude-opus-4-20250514") == "claude-opus-4" and family("claude-opus-4-5") == "claude-opus-4-5"
    assert family("claude-opus-5-5") == "claude-opus-5-5" and family("claude-opus-5-6") is None  # never a newer one
    assert known_caps("claude-opus-9") is None and known_caps("") is None

    hub = client.app.state.hub
    claude = hub.llm.adapters["anthropic"]
    caps = claude.caps(HAIKU)  # nothing stored about it
    assert (caps.effort_levels, caps.max_output_tokens, caps.tools, caps.temperature) == ([], 64_000, True, False)
    assert claude.caps("claude-opus-9").effort_levels is None  # a model the table does not list: learned later
    store_caps(hub, HAIKU, source="api")  # a models-list entry that said nothing about effort keeps the default
    assert claude.caps(HAIKU).effort_levels == []
    store_caps(hub, "claude-opus-9", effort_levels=["low", "high"], source="api")  # what the API said wins
    assert claude.caps("claude-opus-9").effort_levels == ["low", "high"]


# -- the request Claude Haiku 4.5 gets -----------------------------------------------------------------


def test_no_effort_is_sent_to_claude_haiku_4_5(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="All good.")])],
                      json_result={"ok": True})
    on_haiku(client)
    reply = client.post("/api/chat", json={"text": "how is the suite doing?"}).json()
    assert reply["reply"] == "All good." and reply["mode"] == "llm" and reply["meta"]["model"] == HAIKU
    call = fake.calls[0]
    assert call["model"] == HAIKU and "output_config" not in call and "temperature" not in call
    assert "thinking" not in call and "betas" not in call and "fallbacks" not in call  # no server-side fallback
    assert call["max_tokens"] <= 64_000 and call["cache_control"] == {"type": "ephemeral"}  # automatic caching
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
              "additionalProperties": False}
    client.patch("/api/llm/selection", json={"purposes": {"generate": {"provider": "anthropic", "model": HAIKU}}})
    value, meta = client.portal.call(lambda: hub.llm.json("patcher", "generate", system="s", prompt="p",
                                                          schema=schema, effort="high"))
    assert value == {"ok": True} and meta.model == HAIKU
    assert fake.calls[-1]["output_config"] == {"format": {"type": "json_schema", "schema": schema}}  # no effort


def test_strict_tools_only_within_the_structured_outputs_limits(client, monkeypatch):
    hub = client.app.state.hub
    claude = hub.llm.adapters["anthropic"]
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")])] * 3)
    request = Request(purpose="chat", agent_id="supervisor", model=HAIKU, messages=[Msg(role="user", text="hi")])
    client.portal.call(claude.complete, request.model_copy(update={"tools": [TOOL]}))
    assert fake.calls[-1]["tools"][0]["strict"] is True
    many = [{**TOOL, "name": f"t{n}"} for n in range(claude_adapter.STRICT_TOOLS + 1)]  # 21 strict tools: a 400
    client.portal.call(claude.complete, request.model_copy(update={"tools": many}))
    assert not any("strict" in t for t in fake.calls[-1]["tools"]) and len(fake.calls[-1]["tools"]) == 21
    optional = {**TOOL, "input_schema": {"type": "object", "properties": {f"p{n}": {"type": "string"} for n in range(25)},
                                         "additionalProperties": False}}  # 25 optional parameters (limit 24)
    client.portal.call(claude.complete, request.model_copy(update={"tools": [optional]}))
    assert "strict" not in fake.calls[-1]["tools"][0]


def test_large_answers_are_streamed(client, monkeypatch):
    """The SDK refuses a non-streaming request it expects to take over 10 minutes (about 21,333 output tokens)."""
    hub = client.app.state.hub
    claude = hub.llm.adapters["anthropic"]
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")])] * 4)
    request = Request(purpose="code", agent_id="patcher", model="claude-opus-5-5", messages=[Msg(role="user", text="hi")])
    client.portal.call(claude.complete, request)  # 16,000
    assert "stream" not in fake.calls[-1]
    result = client.portal.call(claude.complete, request.model_copy(update={"max_output_tokens": 32_000}))
    assert result.text == "ok" and fake.calls[-1]["stream"] is True and fake.calls[-1]["max_tokens"] == 32_000
    client.portal.call(claude.complete, request.model_copy(update={"max_output_tokens": 200_000}))
    assert fake.calls[-1]["max_tokens"] == 128_000  # never above the model's output limit
    client.portal.call(claude.complete, request.model_copy(update={"model": "claude-opus-4-1-20250805"}))
    assert fake.calls[-1]["stream"] is True  # 8,192 tokens at most without streaming on Opus 4 and 4.1
    assert claude_adapter.streamed("claude-opus-5-5", 21_333) is False


# -- a 400: learn, call again once without the feature ---------------------------------------------------


def test_a_refused_effort_is_learned_and_the_call_made_again_without_it(client, monkeypatch):
    hub = client.app.state.hub
    text = "output_config.effort: Extra inputs are not permitted"
    fake = use_claude(hub, monkeypatch, Refusing(lambda kw: "effort" in (kw.get("output_config") or {}), text,
                                                 responses=[message("end_turn", [block("text", text="Hi.")])] * 2))
    on_haiku(client)
    store_caps(hub, HAIKU, effort_levels=["low", "medium", "high"], source="admin")  # what someone set, wrongly
    reply = client.post("/api/chat", json={"text": "hello"}).json()
    assert reply["reply"] == "Hi." and reply["mode"] == "llm"  # the person never sees the refused call
    first, second = fake.calls
    assert first["refused"] and first["output_config"] == {"effort": "medium"}
    assert "output_config" not in second and second["messages"] == first["messages"]
    caps = llm_providers.get(hub, "anthropic").capabilities[HAIKU]
    assert caps.effort_levels == [] and caps.source == "learned"
    assert len(activity(client, f"does not support the reasoning effort 'medium' for {HAIKU}")) == 1
    client.post("/api/chat", json={"text": "hello again"})
    assert len(fake.calls) == 3 and "output_config" not in fake.calls[2] and fake.refused == 1  # it starts right
    outcomes = [u.get("outcome") for u in hub.store.tail("llm_usage", 10)]
    assert outcomes.count("error") == 1 and outcomes.count("ok") == 2  # the refused call is metered too


@pytest.mark.parametrize("text, learned", [
    ("output_config.effort: Input should be 'low', 'medium' or 'high'", ["low", "medium", "high"]),
    ("This model does not support the effort parameter.", []),
    ("output_config.effort 'xhigh' is not supported on this model.", ["low", "medium", "high", "max"]),
])
def test_what_a_refused_effort_teaches(client, monkeypatch, text, learned):
    hub = client.app.state.hub
    sent = "medium" if "Input should be" not in text else "xhigh"
    sent = "xhigh" if "'xhigh'" in text else sent
    fake = use_claude(hub, monkeypatch, Refusing(lambda kw: (kw.get("output_config") or {}).get("effort") == sent, text,
                                                 responses=[message("end_turn", [block("text", text="ok")])]))
    store_caps(hub, "claude-opus-9", effort_levels=["low", "medium", "high", "xhigh", "max"], source="api")
    request = Request(purpose="chat", agent_id="supervisor", model="claude-opus-9", effort=sent,
                      messages=[Msg(role="user", text="hi")])
    result, _, _ = client.portal.call(hub.llm.complete, "anthropic", request)
    assert result.text == "ok" and len(fake.calls) == 2 and "output_config" not in fake.calls[1]
    assert llm_providers.get(hub, "anthropic").capabilities["claude-opus-9"].effort_levels == learned


def test_a_refused_strict_tool_schema_is_dropped(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, Refusing(lambda kw: any(t.get("strict") for t in kw.get("tools") or []),
                                                 "tools.0.custom.strict: Extra inputs are not permitted",
                                                 responses=[message("end_turn", [block("text", text="ok")])] * 2))
    request = Request(purpose="chat", agent_id="supervisor", model="claude-opus-9", tools=[TOOL],
                      messages=[Msg(role="user", text="hi")])
    client.portal.call(hub.llm.complete, "anthropic", request)
    assert fake.calls[0]["refused"] and "strict" not in fake.calls[1]["tools"][0]
    assert llm_providers.get(hub, "anthropic").capabilities["claude-opus-9"].json_schema is False  # one capability
    client.portal.call(hub.llm.complete, "anthropic", request)
    assert len(fake.calls) == 3 and "strict" not in fake.calls[2]["tools"][0] and fake.refused == 1
    complex_ = use_claude(hub, monkeypatch, Refusing(lambda kw: any(t.get("strict") for t in kw.get("tools") or []),
                                                     "Schema is too complex for compilation.",
                                                     responses=[message("end_turn", [block("text", text="ok")])]))
    client.portal.call(hub.llm.complete, "anthropic", request.model_copy(update={"model": "claude-opus-8"}))
    assert "strict" not in complex_.calls[1]["tools"][0]  # this schema set: the model learns nothing
    assert "claude-opus-8" not in llm_providers.get(hub, "anthropic").capabilities


def test_the_structured_output_ladder_degrades_on_a_400(client, monkeypatch):
    hub = client.app.state.hub
    schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
    answer = message("end_turn", [block("text", text='{"ok": true}')])
    fake = use_claude(hub, monkeypatch, Refusing(lambda kw: "format" in (kw.get("output_config") or {}),
                                                 "output_config.format: Extra inputs are not permitted",
                                                 responses=[answer]))
    client.patch("/api/llm/selection", json={"purposes": {"generate": {"provider": "anthropic",
                                                                       "model": "claude-opus-9"}}})
    value, _ = client.portal.call(lambda: hub.llm.json("patcher", "generate", system="s", prompt="p", schema=schema))
    assert value == {"ok": True} and fake.calls[0]["refused"] and "output_config" not in fake.calls[1]
    assert "JSON" in fake.calls[1]["system"]  # the schema in the prompt instead
    assert llm_providers.get(hub, "anthropic").capabilities["claude-opus-9"].json_schema is False
    too_big = use_claude(hub, monkeypatch, Refusing(lambda kw: "format" in (kw.get("output_config") or {}),
                                                    "Schema is too complex for compilation.", responses=[answer]))
    client.patch("/api/llm/selection", json={"purposes": {"generate": {"provider": "anthropic",
                                                                       "model": "claude-opus-8"}}})
    value, _ = client.portal.call(lambda: hub.llm.json("patcher", "generate", system="s", prompt="p", schema=schema))
    assert value == {"ok": True} and too_big.calls[0]["refused"]
    assert "claude-opus-8" not in llm_providers.get(hub, "anthropic").capabilities  # another schema may pass


@pytest.mark.parametrize("text, feature", [
    ("output_config.effort: Extra inputs are not permitted", "effort"),
    ("This model does not support the effort parameter.", "effort"),
    ("output_config.effort: Input should be 'low', 'medium' or 'high'", "effort"),
    ("output_config.effort requires a model that supports per-turn effort; this model does not", "effort"),
    ("output_config: Extra inputs are not permitted", "effort"),
    ("temperature: Extra inputs are not permitted", "temperature"),
    ("`temperature` is deprecated for this model.", "temperature"),
    ("tools: Extra inputs are not permitted", "tools"),
    ("tools.0.custom.strict: Extra inputs are not permitted", "strict"),
    ("output_config.format: Extra inputs are not permitted", None),  # the structured-output ladder's
    ("Schema is too complex for compilation.", None),
    ("messages: roles must alternate between \"user\" and \"assistant\"", None),
    ("max_tokens: 200000 > 64000, which is the maximum allowed number of output tokens for claude-haiku-4-5", None),
    # OpenAI and OpenAI-compatible servers
    ("Unsupported parameter: 'temperature' is not supported with this model.", "temperature"),
    ("Unsupported value: 'reasoning.effort' does not support 'medium' with this model. Supported values are: 'low' "
     "and 'high'.", "effort"),
    ("Unknown parameter: 'reasoning'.", "effort"),
    ("Unrecognized request argument supplied: tools", "tools"),
    ("This model does not support tools", "tools"),
])
def test_how_providers_word_a_refused_feature(text, feature):
    assert registry.refused_feature(text) == feature


def test_structured_mode_refusals_name_the_mode_not_the_effort():
    assert structured.names_mode("output_config.format: Extra inputs are not permitted", "native")
    assert not structured.names_mode("output_config.effort: Extra inputs are not permitted", "native")
    assert structured.names_mode("Schema is too complex for compilation.", "native")
    assert structured.schema_refused("Schema is too complex for compilation.")
    assert structured.schema_refused("output_config.format.schema: For 'string' type, 'format' is not supported")
    assert not structured.schema_refused("output_config.format: Extra inputs are not permitted")


# -- readable errors ------------------------------------------------------------------------------------


def test_the_api_message_is_read_from_the_sdk_error():
    assert claude_adapter.api_message(bad_request("output_config.effort: Extra inputs are not permitted")) == \
        "output_config.effort: Extra inputs are not permitted"
    plain = bad_request("x")
    plain.body = None  # only the SDK's text: "Error code: 400 - {...}"
    assert claude_adapter.api_message(plain) == "x"
    assert claude_adapter.api_message(RuntimeError("something else")) == "something else"


def test_the_chat_shows_the_providers_message_masked_and_capped(client, monkeypatch):
    hub = client.app.state.hub
    long_tail = " ".join(["detail"] * 80)
    text = (f"max_tokens: 200000 > 64000, which is the maximum allowed number of output tokens for {HAIKU} "
            f"(key {FAKE_KEY}, password=hunter2) {long_tail}")
    fake = use_claude(hub, monkeypatch, Refusing(lambda kw: True, text))
    on_haiku(client)
    reply = client.post("/api/chat", json={"text": "status"}).json()
    assert reply["mode"] == "rules" and fake.refused == 1  # not a learnable refusal: no second call
    note = reply["reply"].split("\n\n", 1)[0]
    assert note.startswith("(Claude answered HTTP 400: max_tokens: 200000 > 64000, which is the maximum allowed")
    assert note.endswith("Falling back to built-in commands.)") and "http_400" not in note
    assert FAKE_KEY not in reply["reply"] and "hunter2" not in reply["reply"]
    assert len(note) < 320 and "…" in note  # the API's message is capped (about 200 characters)
    logged = activity(client, "model call failed")
    assert len(logged) == 1 and f"({HAIKU}): Claude answered HTTP 400: max_tokens" in logged[0]["text"]
    assert FAKE_KEY not in logged[0]["text"] and logged[0]["level"] == "warn"
    client.post("/api/chat", json={"text": "status"})
    assert len(activity(client, "model call failed")) == 1  # once, not on every chat
    errors = hub.agent_errors.for_agent("supervisor")
    assert len(errors) == 2 and errors[0]["code"] == "llm_http_400" and errors[0]["kind"] == "llm"
    assert all(FAKE_KEY not in (e.get("error") or "") for e in errors)

    use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="Back.")])])
    assert client.post("/api/chat", json={"text": "status"}).json()["reply"] == "Back."
    use_claude(hub, monkeypatch, Refusing(lambda kw: True, text))
    client.post("/api/chat", json={"text": "status"})
    assert len(activity(client, "model call failed")) == 2  # failing again after it worked: logged again


def test_the_providers_message_is_not_in_the_status_everyone_reads(client, sign_in, monkeypatch):
    """A 400 may quote the request (a person's chat): the chat's person reads it, the agent error keeps it private,
    and the status every signed-in account reads (GET /api/overview, /api/llm/providers) says the HTTP status only."""
    hub = client.app.state.hub
    marker = "Sebastien-Dupont-9x7"
    use_claude(hub, monkeypatch, Refusing(lambda kw: True, f"messages.0.content.0.text: unexpected value "
                                                           f"'Confidential: please onboard {marker} today'"))
    alice, carol = sign_in("operator", "alice"), sign_in("viewer", "carol")
    reply = alice.post("/api/chat", json={"text": f"Confidential: please onboard {marker} today"}).json()
    assert reply["reply"].startswith("(Claude answered HTTP 400: messages.0.content.0.text") and marker in reply["reply"]
    assert hub.llm.status()["last_error"] == "Claude answered HTTP 400"
    for path in ("/api/overview", "/api/llm/providers", "/api/agents/supervisor/errors", "/api/activity?limit=500"):
        assert marker not in carol.get(path).text, path
    assert carol.get("/api/overview").json()["llm"]["last_error"] == "Claude answered HTTP 400"


def test_the_fallback_note():
    assert fallback_note("Claude", "Claude answered HTTP 400: output_config.effort: not supported.") == \
        "Claude answered HTTP 400: output_config.effort: not supported. Falling back to built-in commands."
    assert fallback_note("Claude", "KeyError") == "Claude unavailable: KeyError. Falling back to built-in commands."


def test_explain_shows_model_layer_failures_only(client):
    llm = client.app.state.hub.llm
    error = ProviderError("Claude answered HTTP 400: bad request", kind="http_400", status=400)
    try:
        try:
            raise error
        except ProviderError as exc:
            raise ValueError("wrapped") from exc
    except ValueError as wrapped:
        assert llm.explain(wrapped) == "Claude answered HTTP 400: bad request"  # also as the cause
    assert llm.explain(KeyError("secret internals")) == "KeyError"  # any other error: its class only
    assert llm.explain(ProviderError("x" * 1000), limit=50) == "x" * 49 + "…"
    assert llm.explain(ProviderError("token=abc123def456 refused")) == "token=*** refused"  # credential pairs masked
