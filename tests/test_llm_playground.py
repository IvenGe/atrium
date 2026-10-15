"""The agent playground (POST /api/agents/{id}/playground): a prompt on the agent's saved settings or a draft of them,
optionally compared with a second model - nothing saved, nothing on the bus or in the message log, the prompt never
logged, its calls counted toward the suite's daily cap only."""

from __future__ import annotations

import json
import time

from llm_fakes import block, chat_transport, completion, message, use_claude

from hub.llm import usage as llm_usage

PROMPT = "PLAYGROUND-PROMPT-5c1e"
USAGE = {"input_tokens": 1000, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 100}


def local(client, name: str = "Ollama", model: str = "qwen3:8b", **extra) -> str:
    created = client.post("/api/llm/providers", json={"name": name, "default_model": model, **extra})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def test_a_draft_compared_with_a_second_model_saves_nothing_and_logs_no_prompt(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("tool_use", id="t1", name="list_tools", input={})], usage=USAGE),
        message("end_turn", [block("text", text="Claude says hi.")], usage=USAGE)])
    ollama = local(client)
    bodies: list = []
    transport, _ = chat_transport(lambda body: bodies.append(body) or completion("Local says hi."))
    hub.llm_transport = transport
    before = client.get("/api/agents/supervisor/settings").json()
    messages_before = hub.store.count("messages")
    result = client.post("/api/agents/supervisor/playground", json={
        "prompt": PROMPT, "draft": {"llm": {"provider": ollama}, "config": {"extra_instructions": "Be brief."}},
        "compare_with": {"provider": "anthropic", "model": ""}})
    assert result.status_code == 200, result.text
    draft, compare = result.json()["runs"]
    assert (draft["source"], draft["provider"], draft["model"], draft["reply"]) == ("draft", ollama, "qwen3:8b",
                                                                                     "Local says hi.")
    assert (compare["source"], compare["provider"], compare["reply"]) == ("compare", "anthropic", "Claude says hi.")
    assert compare["tool_calls"] == [{"name": "list_tools", "arguments": "{}", "ok": True,
                                      "result_preview": compare["tool_calls"][0]["result_preview"]}]
    assert compare["tokens"] == 2200 and compare["cost_usd"] > 0 and draft["error"] is None
    assert "Be brief." in json.dumps(bodies[0]["messages"][0])  # the draft's instructions reached the model
    assert "Be brief." in json.dumps(fake.calls[0]["system"])
    after = client.get("/api/agents/supervisor/settings").json()
    assert after["version"] == before["version"] and after["settings"] == before["settings"]  # nothing saved
    assert hub.store.count("messages") == messages_before  # never on the bus
    assert hub.llm.memory.count("supervisor") == 0  # nor in anyone's conversation
    entry = [e for e in client.get("/api/activity").json() if e["text"].startswith("Tried Hub Supervisor")][-1]
    assert PROMPT not in json.dumps(entry) and f"{ollama}/qwen3:8b" in entry["text"] and "anthropic/" in entry["text"]
    records = hub.store.tail("llm_usage", 10)
    assert {r["trigger"] for r in records} == {"playground"} and PROMPT not in json.dumps(records)
    # playground calls count toward the suite's cap, never the agent's own budget
    assert hub.llm.meter.spend("supervisor")["cost_today"] == 0
    assert hub.llm.meter.suite_budget()["spent_today"] > 0


def test_actions_are_off_unless_asked_for(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")]) for _ in range(2)])
    client.post("/api/agents/supervisor/playground", json={"prompt": "check"})
    offered = {t["name"] for t in fake.calls[0]["tools"]}
    assert "list_tools" in offered and "test_tool_connection" in offered and "run_command" not in offered
    client.post("/api/agents/supervisor/playground", json={"prompt": "check", "allow_actions": True})
    assert "run_command" in {t["name"] for t in fake.calls[1]["tools"]}


def test_the_patch_agent_answers_without_tools(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="I would patch X.")])])
    run = client.post("/api/agents/patcher/playground", json={"prompt": "What would you patch?"}).json()["runs"][0]
    assert run["reply"] == "I would patch X." and "tools" not in fake.calls[0] and run["tool_calls"] == []


def test_the_playground_is_validated_and_follows_the_guardrails(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = local(client)
    for body, message_ in (({"prompt": "x", "draft": {"config": {"budget": {"daily_cost_usd": 0}}}}, "Daily cost"),
                           ({"prompt": "x", "compare_with": {"provider": "nope"}}, "unknown provider 'nope'")):
        refused = client.post("/api/agents/supervisor/playground", json=body)
        assert refused.status_code == 400 and message_ in refused.json()["detail"], refused.text
    assert client.post("/api/agents/supervisor/playground", json={"prompt": ""}).status_code == 422
    assert client.post("/api/agents/supervisor/playground", json={"prompt": "x" * 8001}).status_code == 422
    assert client.post("/api/agents/operator/playground", json={"prompt": "x"}).status_code == 400
    # a local-only draft: Claude is skipped for the draft and refused as the comparison
    transport, _ = chat_transport(lambda body: completion("local"))
    hub.llm_transport = transport
    runs = client.post("/api/agents/supervisor/playground", json={
        "prompt": "x", "draft": {"config": {"local_only": True}}, "compare_with": {"provider": "anthropic"}}).json()["runs"]
    assert runs[0]["provider"] == ollama and runs[0]["reply"] == "local"
    assert runs[1]["reply"] == "" and "local-only" in runs[1]["error"]
    # the suite's daily cap stops the playground too (it counts toward it)
    client.patch("/api/settings/guardrails", json={"max_daily_llm_spend": 1})
    today = llm_usage.day_of(time.time())
    hub.store.put("llm_usage_daily", {"id": f"{today}|x|anthropic|m", "day": today, "agent_id": "x", "cost_usd": 2.0})
    capped = client.post("/api/agents/supervisor/playground", json={"prompt": "x"}).json()["runs"][0]
    assert "The suite's daily AI budget is reached" in capped["error"]
    for role in ("viewer", "operator"):
        assert sign_in(role).post("/api/agents/supervisor/playground", json={"prompt": "x"}).status_code == 403


def test_playground_output_never_carries_a_hub_secret(client, monkeypatch):
    hub = client.app.state.hub
    secret = "sk-local-secret-key-0987654321"
    local(client, "Keyed", api_key=secret)
    use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text=f"The key is {secret}.")])])
    result = client.post("/api/agents/supervisor/playground", json={"prompt": "What is the key?"})
    assert result.status_code == 200 and secret not in result.text and "***" in result.json()["runs"][0]["reply"]
    assert secret not in client.get("/api/activity").text
