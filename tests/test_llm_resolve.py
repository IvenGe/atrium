"""Which provider and model a call runs on (hub/llm/resolve.py): the levels in order, the automatic suite default,
what blocks a level, the circuit breaker, and that every writer clears the cached resolutions."""

from __future__ import annotations

import pytest
from llm_fakes import FakeProvider, failing, use_claude

from hub import llm_providers
from hub.llm import LLMUnavailable, Msg
from hub.llm import registry
from hub.llm.registry import FAILURES, OPEN_FOR

from test_teams import add_tool


def local(client, name: str = "Ollama", model: str = "qwen3:8b", **extra) -> str:
    created = client.post("/api/llm/providers", json={"name": name, "default_model": model, **extra})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def select(hub, **values) -> None:
    doc = hub.store.get("settings", "llm_selection")
    hub.store.put("settings", {**doc, **values})
    hub.llm.invalidate()


def test_the_automatic_suite_default(client, monkeypatch):
    hub = client.app.state.hub
    res = hub.llm.resolve("supervisor", "chat")  # HUB_LLM=off and no local model: rules
    assert (res.provider, res.source, res.ready) == ("rules", "rules", False)
    assert res.blocked and res.blocked[0].provider == "auto" and "HUB_LLM=off" in res.blocked[0].reason
    assert hub.llm.resolve("operator", "chat").source == "deterministic"  # an agent without a model

    ollama = local(client)  # Claude is off (HUB_LLM=off): the automatic choice goes on to a local model
    res = hub.llm.resolve("supervisor", "chat")
    assert (res.provider, res.model, res.source, res.provider_kind, res.location) == (
        ollama, "qwen3:8b", "suite", "local", "self_hosted")
    assert res.source_label == "Suite default (automatic)"

    use_claude(hub, monkeypatch)  # Claude first when it is configured (as before)
    res = hub.llm.resolve("supervisor", "chat")
    assert (res.provider, res.model, res.provider_label) == ("anthropic", "claude-opus-5-5", "Claude")
    assert hub.llm.status()["default"]["provider"] == "anthropic" and hub.llm.available


def test_the_levels_in_order(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama, studio = local(client), local(client, "LM Studio", "m2", base_url="http://localhost:1234/v1")
    add_tool(client, "wazuh", "Wazuh")
    member = client.post("/api/agents", json={"name": "Member", "team": "wazuh"}).json()["id"]
    hub_member = client.post("/api/agents", json={"name": "Hub member", "team": "hub"}).json()["id"]

    def source(agent: str, purpose: str = "chat") -> tuple[str, str]:
        res = hub.llm.resolve(agent, purpose)
        return res.source, res.provider

    assert source(member) == ("suite", "anthropic")
    select(hub, purposes={"code": {"provider": ollama, "model": ""}})  # code changes run locally
    assert source("patcher", "code") == ("purpose", ollama) and source("patcher", "generate") == ("suite", "anthropic")
    select(hub, teams={"wazuh": {"provider": studio, "model": "", "local_only": False}})
    assert source(member) == ("team", studio) and source("tool:wazuh", "generate") == ("team", studio)
    assert source(hub_member) == ("suite", "anthropic") and source("supervisor") == ("suite", "anthropic")
    assert source("module:grc") == ("deterministic", "rules")  # module leads keep their own (no model)
    assert hub.llm.resolve(member, "chat").source_label == "Wazuh team default"
    client.patch(f"/api/agents/{member}", json={"provider": ollama})  # the agent's own choice beats its team's
    assert source(member) == ("agent", ollama)
    doc = hub.store.get("agents", "patcher") or {"id": "patcher"}
    hub.store.put("agents", {**doc, "config": {"purposes": {"code": {"provider": studio, "model": "m9"}}}})
    hub.llm.invalidate()
    res = hub.llm.resolve("patcher", "code")
    assert (res.source, res.provider, res.model) == ("agent_purpose", studio, "m9")
    client.patch("/api/agents/patcher", json={"model": "claude-sonnet-5-5"})  # a legacy model override: Claude
    assert source("patcher", "generate") == ("agent", "anthropic")
    assert hub.llm.resolve("patcher", "generate").model == "claude-sonnet-5-5"
    client.patch(f"/api/agents/{member}", json={"provider": "rules"})
    assert source(member) == ("agent", "rules")


def test_what_blocks_a_level(client, monkeypatch):
    hub = client.app.state.hub
    ollama = local(client, model="")
    agent = client.post("/api/agents", json={"name": "Local", "provider": ollama}).json()["id"]
    res = hub.llm.resolve(agent, "chat")  # no model on the provider: the next level (the suite: nothing usable)
    assert res.provider == "rules" and [(b.level, b.reason) for b in res.blocked][0] == ("agent", "no model chosen")
    assert res.intended is not None and res.intended.provider == ollama  # what the record shows as chosen
    provider = llm_providers.get(hub, ollama)
    provider.pinned_models = ["pinned:1b"]
    llm_providers.put(hub, provider)
    assert hub.llm.resolve(agent, "chat").model == "pinned:1b"  # the first pinned model
    llm_providers.save(hub, ollama, {"default_model": "qwen3:8b"}, "test")
    assert hub.llm.resolve(agent, "chat").model == "qwen3:8b"  # the provider's default model wins
    provider = llm_providers.get(hub, ollama)
    provider.enabled = False
    llm_providers.put(hub, provider)
    res = hub.llm.resolve(agent, "chat")
    assert res.provider == "rules" and ("agent", "switched off") in [(b.level, b.reason) for b in res.blocked]
    hub.store.delete("llm_providers", ollama)  # removed behind the API's back
    hub.llm.invalidate()
    assert ("agent", "provider removed") in [(b.level, b.reason) for b in hub.llm.resolve(agent, "chat").blocked]
    record = next(a for a in client.get("/api/agents").json() if a["id"] == agent)
    assert record["llm"]["purposes"]["chat"]["blocked"][0]["reason"] == "provider removed"


def test_the_circuit_breaker_opens_after_failures_and_closes_again(client):
    hub = client.app.state.hub
    ollama = local(client)
    now = [1000.0]
    hub.llm.breaker.clock = lambda: now[0]
    hub.llm.adapters[ollama] = FakeProvider([failing() for _ in range(FAILURES)])
    for _ in range(FAILURES):
        with pytest.raises(LLMUnavailable):
            client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", history=[Msg(role="user", text="x")],
                                                        tools=[], run=None))
    res = hub.llm.resolve("supervisor", "chat")
    assert res.provider == "rules" and "failing - retry in" in res.blocked[0].reason
    now[0] += OPEN_FOR + 1
    assert hub.llm.resolve("supervisor", "chat").provider == ollama


def test_a_failing_provider_hands_over_to_the_fallback_chain(client):
    hub = client.app.state.hub
    first, second = local(client, "A server"), local(client, "B server", "b1", base_url="http://localhost:1234/v1")
    select(hub, default={"provider": first, "model": ""}, fallback=[second, "rules"])
    hub.llm.adapters[first] = FakeProvider([failing("down", 503)])
    hub.llm.adapters[second] = FakeProvider(["From B."])
    history = [Msg(role="user", text="hi")]
    reply, meta = client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", history=history,
                                                              tools=[], run=None))
    assert reply == "From B." and (meta.provider, meta.fallback_from, meta.model) == (second, first, "b1")
    usage = hub.store.tail("llm_usage", 5)
    assert [(u["provider"], u["outcome"]) for u in usage[-2:]] == [(first, "error"), (second, "fallback")]


def test_every_writer_clears_the_cached_resolution(client, monkeypatch):
    hub = client.app.state.hub
    assert hub.llm.resolve("supervisor", "chat").provider == "rules"
    ollama = local(client)  # a provider saved
    assert hub.llm.resolve("supervisor", "chat").provider == ollama
    agent = client.post("/api/agents", json={"name": "A"}).json()["id"]
    assert hub.llm.resolve(agent, "chat").provider == ollama
    client.patch(f"/api/agents/{agent}", json={"provider": "rules"})  # an agent's choice
    assert hub.llm.resolve(agent, "chat").provider == "rules"
    client.patch("/api/agents/supervisor", json={"model": "claude-x"})  # a core agent's override
    assert hub.llm.resolve("supervisor", "chat").intended.model == "claude-x"
    use_claude(hub, monkeypatch)  # the environment changes (no explicit invalidation needed)
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"
    monkeypatch.setenv("HUB_LLM", "off")
    assert hub.llm.resolve("supervisor", "chat").provider == ollama
    monkeypatch.delenv("HUB_LLM")
    assert hub.llm.resolve("supervisor", "chat").provider == "anthropic"


def test_removing_a_tool_drops_its_team_model_choice(client):
    hub = client.app.state.hub
    ollama = local(client)
    add_tool(client, "wazuh", "Wazuh")
    select(hub, teams={"wazuh": {"provider": ollama, "model": "", "local_only": False}})
    assert client.delete("/api/tools/wazuh").status_code == 200
    assert "wazuh" not in hub.store.get("settings", "llm_selection")["teams"]
    assert any("removed tool's team" in e["text"] for e in client.get("/api/activity").json())


def test_the_migration_seeds_the_built_in_providers_once(client):
    hub = client.app.state.hub
    anthropic, openai = llm_providers.get(hub, "anthropic"), llm_providers.get(hub, "openai")
    assert (anthropic.kind, anthropic.location, anthropic.default_model) == ("anthropic", "third_party", "")
    assert (openai.kind, openai.variant, openai.enabled) == ("openai", "openai", False)
    assert hub.store.get("settings", "llm_selection")["default"] == {"provider": "auto", "model": ""}
    assert client.delete("/api/llm/providers/anthropic").status_code == 409
    assert {p["id"] for p in client.get("/api/llm/providers").json()["providers"]} == set()  # local servers only
    hub.store.put("agents", {"id": "operator", "paused": False, "model": "claude-x", "instructions": "Mine."})
    hub.store.put("llm_providers", {"id": "old", "name": "Old", "base_url": "https://llm.example.com/v1"})
    hub.store.delete("settings", "llm_migration")
    hub.llm.migrate()
    doc = hub.store.get("agents", "operator")
    assert doc["provider"] == "anthropic" and doc["config"]["instructions_mode"] == "replace"
    assert llm_providers.get(hub, "old").location == "third_party"
    assert not registry.migrate(hub)  # idempotent: once


def test_the_settings_model_is_claudes_default_model(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    assert client.get("/api/settings").json()["model"] == "claude-opus-5-5"  # HUB_MODEL while none is chosen
    assert client.patch("/api/settings", json={"model": "claude-sonnet-5-5"}).status_code == 200
    assert llm_providers.get(hub, "anthropic").default_model == "claude-sonnet-5-5"
    assert client.get("/api/settings").json()["model"] == "claude-sonnet-5-5"
    assert hub.llm.resolve("supervisor", "chat").model == "claude-sonnet-5-5"
    assert any(e["text"] == "Changed the AI provider Claude: default model" for e in client.get("/api/activity").json())
