"""Governance of AI model use: the guardrail allow_cloud_llm (on by default, off is safe, effective at once), the local-
only rule of agents and teams, supplier records of cloud providers and compliance control HB-SC-1."""

from __future__ import annotations

import time

import pytest
from llm_fakes import FakeProvider, failing, use_claude

from hub import guardrails
from hub.llm import LLMUnavailable, Msg
from hub.llm import loop
from hub.llm.loop import CLOUD_STOPPED
from hub.llm.resolve import Candidate
from hub.llm.types import Result, ToolCall, Usage

from test_teams import add_tool


def local(client, name: str = "Ollama", model: str = "qwen3:8b", **extra) -> str:
    created = client.post("/api/llm/providers", json={"name": name, "default_model": model, **extra})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def control(client, wait_for, control_id: str, status: str | None = None) -> dict:
    def found():
        client.post("/api/grc/evaluate")
        c = next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == control_id)
        return c if status is None or c["status"] == status else None
    return wait_for(found)


def test_the_cloud_guardrail_is_in_the_catalog_with_its_safe_side(client):
    catalog = {g["key"]: g for g in client.get("/api/settings").json()["guardrail_catalog"]}
    g = catalog["allow_cloud_llm"]
    assert (g["group"], g["default"], g["value"], g["safe"], g["relaxed"]) == ("models", True, True, False, False)
    assert "process the data under their terms" in g["risk"]
    assert catalog["block_catastrophic_commands"]["safe"] is True and catalog["allow_extensions"]["safe"] is False
    # a default-on switch is never "weakened": its compliance effect goes through the HB-SC-1 supplier records
    assert not any(x.key == "allow_cloud_llm" for c in ("HB-AC-6", "HB-SC-1", "HB-AC-2")
                   for x in guardrails.weakened({"allow_cloud_llm": True}, c))


def test_switching_cloud_providers_off_moves_agents_to_local_models_at_once(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    hosted = local(client, "Hosted", "m1", base_url="https://llm.example.com/v1")
    member = client.post("/api/agents", json={"name": "Member", "provider": hosted}).json()["id"]
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"  # cached from here on
    assert hub.llm.resolve(member, "chat").provider == hosted
    assert client.patch("/api/settings/guardrails", json={"allow_cloud_llm": False}).status_code == 200
    res = hub.llm.resolve("supervisor", "chat")  # no bus event needed: the guardrail write clears the cache
    assert res.provider == "rules" and "cloud providers are switched off (guardrail)" in res.blocked[0].reason
    blocked = hub.llm.resolve(member, "chat").blocked
    assert ("agent", hosted, "cloud providers are switched off (guardrail)") in [(b.level, b.provider, b.reason) for b in blocked]
    ollama = local(client)
    assert hub.llm.resolve("supervisor", "chat").provider == ollama and hub.llm.resolve(member, "chat").provider == ollama
    rows = {r["id"]: r for r in client.get("/api/llm/providers").json()["llm"]["providers"]}
    assert rows["anthropic"]["reason"] == "cloud providers are switched off (guardrail)" and rows[ollama]["available"]
    assert client.patch("/api/settings/guardrails", json={"allow_cloud_llm": True}).status_code == 200
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"
    entries = [(e["level"], e["text"]) for e in client.get("/api/activity").json()]
    on, off = "Guardrail 'Agents may send data to cloud AI providers'", "on -> off"
    assert ("info", f"{on} changed: {off}") in entries and ("warn", f"{on} relaxed: off -> on") in entries


def test_a_running_loop_stops_before_its_next_round_when_cloud_goes_off(client):
    hub = client.app.state.hub
    hosted = local(client, "Hosted", "m1", base_url="https://llm.example.com/v1")
    calls = Result(text="Looking.", tool_calls=[ToolCall(id="c1", name="lookup", arguments={})], stop="tool_calls",
                   usage=Usage(input_tokens=5))
    fake = hub.llm.adapters[hosted] = FakeProvider([calls, "Never sent."], location="third_party")

    async def run(name, args):  # the administrator switches cloud providers off while a tool runs
        guardrails.update(hub, "admin", {"allow_cloud_llm": False})
        return {"ok": True}

    reply, _ = client.portal.call(lambda: hub.llm.converse(
        "supervisor", "chat", system="s", history=[Msg(role="user", text="hi")],
        tools=[{"name": "lookup", "description": "d", "input_schema": {"type": "object"}}], run=run))
    assert reply.endswith(CLOUD_STOPPED) and len(fake.requests) == 1


def test_local_only_teams_and_agents_skip_cloud_providers(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    add_tool(client, "wazuh", "Wazuh")
    member = client.post("/api/agents", json={"name": "Member", "team": "wazuh"}).json()["id"]
    grc_member = client.post("/api/agents", json={"name": "Auditor", "team": "module:grc"}).json()["id"]
    sel = client.patch("/api/llm/selection", json={"teams": {"wazuh": {"local_only": True},
                                                             "module:grc": {"local_only": True}}})
    assert sel.status_code == 200, sel.text
    for agent_id in (member, "tool:wazuh", grc_member):  # members and a tool team's lead; no local model: rules
        res = hub.llm.resolve(agent_id, "chat" if agent_id != "tool:wazuh" else "generate")
        assert res.provider == "rules" and res.local_only and res.local_only_from == "team", agent_id
        assert "local-only" in res.blocked[-1].reason
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"  # the Hub Supervisor is not in a team
    ollama = local(client)
    assert hub.llm.resolve(member, "chat").provider == ollama
    # an explicit suite default and an empty fallback chain: a local-only agent goes to rules - unless a local
    # provider is in the fallback chain
    client.patch("/api/llm/selection", json={"default": {"provider": "anthropic"}})
    assert client.patch(f"/api/agents/{member}/settings", json={"config": {"local_only": True}}).status_code == 200
    client.patch("/api/llm/selection", json={"teams": {"wazuh": None}})
    res = hub.llm.resolve(member, "chat")
    assert (res.provider, res.local_only_from) == ("rules", "agent")
    assert ("suite", "anthropic", "agent is local-only") in [(b.level, b.provider, b.reason) for b in res.blocked]
    client.patch("/api/llm/selection", json={"fallback": [ollama]})
    res = hub.llm.resolve(member, "chat")
    assert (res.provider, res.source, res.fallback) == (ollama, "fallback", True)
    record = next(a for a in client.get("/api/agents").json() if a["id"] == member)
    assert record["llm"]["local_only"] is True and record["llm"]["purposes"]["chat"]["source_label"] == "Fallback"


def test_the_resolution_chain_names_every_level(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = local(client)
    add_tool(client, "wazuh", "Wazuh")
    member = client.post("/api/agents", json={"name": "Member", "team": "wazuh"}).json()["id"]
    client.patch("/api/llm/selection", json={"purposes": {"chat": {"provider": ollama}}})
    chain = client.get(f"/api/agents/{member}/settings").json()["chain"]["chat"]
    assert [(r["title"], r["status"]) for r in chain] == [
        ("This agent", "not set"), ("Wazuh team", "not set"), ("Chat and agent tasks default", "used"),
        ("Suite default", "not reached"), ("Rules", "not reached")]
    client.patch(f"/api/agents/{member}/settings", json={"llm": {"provider": "openai"}})  # OpenAI has no key
    chain = client.get(f"/api/agents/{member}/settings").json()["chain"]["chat"]
    assert (chain[0]["status"], chain[0]["provider_label"]) == ("blocked", "OpenAI") and chain[0]["reason"]
    assert chain[2]["status"] == "used" and chain[2]["model"] == "qwen3:8b"
    client.patch("/api/llm/selection", json={"purposes": {"chat": None}})
    client.patch(f"/api/agents/{member}/settings", json={"llm": {"provider": ""}})
    chain = client.get(f"/api/agents/{member}/settings").json()["chain"]["chat"]
    assert (chain[3]["title"], chain[3]["status"], chain[3]["provider_label"]) == (
        "Suite default (automatic)", "used", "Claude")
    assert client.get("/api/agents/operator/settings").json()["chain"] == {}  # deterministic: no model


def test_cloud_providers_in_use_need_a_supplier_owner_and_a_terms_review(client, monkeypatch, wait_for):
    hub = client.app.state.hub
    assert hub.llm.in_use() == []
    state = control(client, wait_for, "HB-SC-1")
    assert state["status"] == "na"
    use_claude(hub, monkeypatch)  # the automatic choice resolves to Claude: Claude is in use
    assert hub.llm.in_use() == ["anthropic"]
    state = control(client, wait_for, "HB-SC-1", "fail")
    assert "AI provider Claude has no supplier owner and its terms were never reviewed" in state["detail"]
    reviewed = time.time() - 3 * 86400
    saved = client.patch("/api/llm/providers/anthropic", json={"supplier": {"owner": "j.doe", "reviewed_at": reviewed,
                                                                            "notes": "DPA signed"}})
    assert saved.status_code == 200 and saved.json()["supplier"]["owner"] == "j.doe"
    day = time.strftime("%Y-%m-%d", time.gmtime(reviewed))
    assert any(e["text"] == f"Changed the AI provider Claude: supplier owner j.doe, terms reviewed {day}"
               for e in client.get("/api/activity").json())
    state = control(client, wait_for, "HB-SC-1", "pass")
    assert f"AI provider: Claude - owner j.doe, terms reviewed {day}" in state["evidence"]
    future = client.patch("/api/llm/providers/anthropic", json={"supplier": {"owner": "x", "reviewed_at": time.time() + 9e6}})
    assert future.status_code == 400
    # switched off: cloud providers are blocked, so they are not "in use"
    client.patch("/api/settings/guardrails", json={"allow_cloud_llm": False})
    assert hub.llm.in_use() == []
    control(client, wait_for, "HB-SC-1", "na")
    # usage in the last 30 days counts too, also for a provider nobody chooses any more
    client.patch("/api/settings/guardrails", json={"allow_cloud_llm": True})
    hosted = local(client, "Hosted", "m1", base_url="https://llm.example.com/v1")
    hub.store.put("llm_usage_daily", {"id": f"{time.strftime('%Y-%m-%d', time.gmtime())}|supervisor|{hosted}|m1",
                                      "day": time.strftime("%Y-%m-%d", time.gmtime()), "agent_id": "supervisor",
                                      "provider": hosted, "model": "m1", "calls": 1})
    assert hub.llm.in_use() == ["anthropic", hosted]


def test_the_automatic_choice_prefers_self_hosted_servers_and_replies_name_their_model(client):
    hub = client.app.state.hub
    hosted = local(client, "A hosted cloud", "big", base_url="https://llm.example.com/v1")  # sorts first by name
    ollama = local(client, "Ollama")
    assert hub.llm.resolve("supervisor", "chat").provider == ollama  # self-hosted before an OpenAI-compatible cloud
    hub.store.delete("llm_providers", ollama)
    hub.llm.invalidate()
    assert hub.llm.resolve("supervisor", "chat").provider == hosted
    hub.llm.adapters[hosted] = FakeProvider(["Hi there."], location="third_party")
    reply = client.post("/api/chat", json={"text": "hello"}).json()
    assert reply["reply"] == "Hi there." and reply["mode"] == "local"  # an OpenAI-compatible server
    assert (reply["meta"]["provider"], reply["meta"]["model"], reply["meta"]["source"]) == (hosted, "big", "suite")
    logged = [m for m in client.get("/api/messages").json() if m["subject"] == "chat" and m["kind"] == "reply"][-1]
    assert logged["body"].get("meta") == {"model": "big", "provider": hosted} and "Hi there." not in str(logged)


def test_the_spending_cap_guardrails(client):
    catalog = {g["key"]: g for g in client.get("/api/settings").json()["guardrail_catalog"]}
    cap, limit = catalog["limit_llm_spend"], catalog["max_daily_llm_spend"]
    assert (cap["group"], cap["default"], cap["safe"], cap["control"], cap["requires"]) == (
        "models", True, True, "HB-AC-6", "max_daily_llm_spend")
    assert (limit["group"], limit["default"], limit["min"], limit["max"]) == ("models", 20, 1, 100_000)
    assert client.patch("/api/settings/guardrails", json={"max_daily_llm_spend": 100_001}).status_code == 400
    assert client.patch("/api/settings/guardrails", json={"max_daily_llm_spend": 100_000}).status_code == 200
    texts = [(e["level"], e["text"]) for e in client.get("/api/activity").json()]
    assert ("warn", "Guardrail 'Maximum AI spending per day (USD)' relaxed: 20 -> 100000") in texts
    assert [g.key for g in guardrails.weakened({"limit_llm_spend": False}, "HB-AC-6")] == ["limit_llm_spend"]


def test_spending_without_a_cap_makes_the_guardrail_control_partial():
    from hub.grc.checks import Snapshot, evaluate_controls

    def control(**values):
        snapshot = Snapshot(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[], autonomy="assisted",
                            audit_entries=1, guardrails={**guardrails.defaults(), **values})
        return {s.id: s for s in evaluate_controls(snapshot, {})}["HB-AC-6"]

    on = control()
    assert on.status == "pass" and on.detail.endswith("; AI spending is capped at $20 per day.")
    assert "max_daily_llm_spend=20" in on.evidence
    off = control(limit_llm_spend=False)
    assert off.status == "partial" and "agents' AI model spending has no daily limit" in off.detail


def test_the_upgrade_announces_the_new_spending_cap_once(client):
    hub = client.app.state.hub
    from hub.llm import registry

    fresh = [e for e in client.get("/api/activity").json() if e["text"].startswith("AI spending is now capped")]
    assert fresh == []  # a new install never ran without the cap
    hub.store.put("settings", {"id": "llm_migration", "version": 1, "at": time.time()})  # ran stage 1-3 only
    assert registry.migrate(hub)
    [entry] = [e for e in client.get("/api/activity").json() if e["text"].startswith("AI spending is now capped")]
    assert entry["text"] == ("AI spending is now capped at $20 per day (Settings > Agent guardrails > AI models and "
                             "spending)") and entry["actor"] == "hub"
    assert not registry.migrate(hub)


PRIVATE = "Jane Doe salary 85k, SSN 123-45-6789"
SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}


def cloud_calls(fake) -> list:
    return [c for c in fake.calls if "messages" in c]


def test_a_local_only_agent_never_falls_back_to_a_cloud_provider(client, monkeypatch):
    """The fallback chain keeps the local-only rule: a local server that is down, or that refuses a request (one made
    too long on purpose, say), never moves the conversation to Claude - a self-hosted fallback may take over."""
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch)
    ollama, backup = local(client), local(client, "LM Studio", "m2", base_url="http://localhost:1234/v1")
    agent = client.post("/api/agents", json={"name": "HR helper", "provider": ollama}).json()["id"]
    assert client.patch(f"/api/agents/{agent}/settings", json={"config": {"local_only": True}}).status_code == 200
    assert client.patch("/api/llm/selection", json={"fallback": ["anthropic", backup]}).status_code == 200
    res = hub.llm.resolve(agent, "chat")
    assert (res.provider, res.local_only, [c.provider for c in res.fallbacks]) == (ollama, True, [backup])

    def converse():
        return client.portal.call(lambda: hub.llm.converse(agent, "chat", system="s", tools=[], run=None,
                                                           history=[Msg(role="user", text=PRIVATE)]))

    hub.llm.adapters[ollama] = FakeProvider([failing("connection refused", None)])
    hub.llm.adapters[backup] = FakeProvider(["From the backup."])
    reply, meta = converse()  # down: the self-hosted fallback answers, Claude is skipped
    assert (reply, meta.provider, meta.fallback_from) == ("From the backup.", backup, ollama)

    assert client.patch("/api/llm/selection", json={"fallback": ["anthropic"]}).status_code == 200
    assert hub.llm.resolve(agent, "chat").fallbacks == []
    for error in (failing("Ollama restarting", 503), failing("This model's maximum context length is 8192 tokens", 400)):
        hub.llm.adapters[ollama] = FakeProvider([error])
        with pytest.raises(LLMUnavailable):
            converse()
        hub.llm.adapters[ollama] = FakeProvider([error])
        client.post(f"/api/agents/{agent}/chat", json={"text": PRIVATE})  # the chat path: the same
    assert cloud_calls(fake) == [] and PRIVATE not in str(fake.calls)


def test_a_local_only_team_never_falls_back_to_a_cloud_provider(client, monkeypatch):
    """Structured calls of a local-only team (a Tool Supervisor enriching tool data, team designs) keep the rule."""
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, json_result={"ok": True})
    ollama = local(client)
    add_tool(client, "hr", "HR")
    assert client.patch("/api/llm/selection", json={"teams": {"hr": {"provider": ollama, "local_only": True}},
                                                     "fallback": ["anthropic"]}).status_code == 200
    res = hub.llm.resolve("tool:hr", "generate")
    assert (res.provider, res.local_only_from, res.fallbacks) == (ollama, "team", [])
    hub.llm.adapters[ollama] = FakeProvider([failing("down", 503)])
    with pytest.raises(LLMUnavailable):
        client.portal.call(lambda: hub.llm.json("tool:hr", "generate", system="s", schema=SCHEMA,
                                                prompt="employee records: jane@corp.example"))
    assert cloud_calls(fake) == []


def test_a_local_only_playground_draft_never_falls_back_to_a_cloud_provider(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch)
    ollama = local(client)
    assert client.patch("/api/llm/selection", json={"fallback": ["anthropic"]}).status_code == 200
    hub.llm.adapters[ollama] = FakeProvider([failing("down", 503)])
    result = client.post("/api/agents/supervisor/playground", json={
        "prompt": PRIVATE, "draft": {"llm": {"provider": ollama}, "config": {"local_only": True}}})
    assert result.status_code == 200, result.text
    [run] = result.json()["runs"]
    assert run["provider"] == ollama and run["error"] and run["reply"] == ""
    assert cloud_calls(fake) == []


def test_the_loop_itself_refuses_a_cloud_fallback_for_a_local_only_turn(client, monkeypatch):
    """Defence in depth for every caller that builds a turn (the playground, the subsidiaries' model gateway)."""
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = local(client)
    chain = [Candidate(level="fallback", provider="anthropic")]
    assert loop.next_fallback(hub.llm, loop.Turn(ollama, "qwen3:8b", list(chain), local_only=True)) is None
    assert loop.next_fallback(hub.llm, loop.Turn(ollama, "qwen3:8b", list(chain))) == ("anthropic", "claude-opus-5-5")
