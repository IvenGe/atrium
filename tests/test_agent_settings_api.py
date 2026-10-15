"""Per-agent model settings (GET/PATCH /api/agents/{id}/settings) and the suite's model choice
(GET/PATCH /api/llm/selection): inherit is provider "", the version guards against lost updates, what is not
available yet is refused, every change is logged and announced with `agent_settings` / `llm_selection`."""

from __future__ import annotations

import json

from llm_fakes import block, chat_transport, completion, message, use_claude

from test_teams import add_tool


def local(client, name: str = "Ollama", model: str = "qwen3:8b", **extra) -> str:
    created = client.post("/api/llm/providers", json={"name": name, "default_model": model, **extra})
    assert created.status_code == 201, created.text
    return created.json()["id"]


def cloud(client, name: str = "Hosted", model: str = "m1") -> str:
    return local(client, name, model, base_url="https://llm.example.com/v1")


def last(client, prefix: str) -> dict:
    """The newest activity entry whose text starts with `prefix`."""
    return [e for e in client.get("/api/activity").json() if e["text"].startswith(prefix)][-1]


def events(hub) -> list:
    seen: list = []
    hub.bus.listen(lambda type_, data: seen.append((type_, data)))
    return seen


def test_core_and_custom_agents_choose_or_inherit_a_model(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = local(client)
    member = client.post("/api/agents", json={"name": "Triage"}).json()["id"]
    seen = events(hub)
    for agent_id in ("supervisor", member):
        view = client.get(f"/api/agents/{agent_id}/settings").json()
        assert view["settings"]["llm"] == {"provider": "", "model": ""} and view["version"] == 0
        assert view["effective"]["purposes"]["chat"]["source"] == "suite" and view["uses_model"]
        saved = client.patch(f"/api/agents/{agent_id}/settings", json={"llm": {"provider": ollama, "model": ""},
                                                                       "version": 0})
        assert saved.status_code == 200, saved.text
        body = saved.json()
        assert body["version"] == 1 and body["settings"]["llm"]["provider"] == ollama
        chat = body["effective"]["purposes"]["chat"]
        assert (chat["provider"], chat["model"], chat["source"]) == (ollama, "qwen3:8b", "agent")
        assert hub.llm.resolve(agent_id, "chat").provider == ollama
        assert ("agent_settings", {"id": agent_id, "version": 1}) in seen
        record = next(a for a in client.get("/api/agents").json() if a["id"] == agent_id)
        assert record["llm"]["settings_version"] == 1 and record["llm"]["choice"]["provider"] == ollama
        back = client.patch(f"/api/agents/{agent_id}/settings", json={"llm": {"provider": "", "model": ""}}).json()
        assert back["settings"]["llm"]["provider"] == "" and back["effective"]["purposes"]["chat"]["provider"] == "anthropic"
    entries = [e["text"] for e in client.get("/api/activity").json()]
    assert f"Configured Hub Supervisor: model inherit -> {ollama} (default model)" in entries
    assert any(t.startswith("Configured Triage: model ") and t.endswith("-> inherit") for t in entries)


def test_a_stale_version_is_refused_with_the_current_settings(client):
    ollama = local(client)
    assert client.patch("/api/agents/supervisor/settings", json={"llm": {"provider": ollama}, "version": 0}).status_code == 200
    stale = client.patch("/api/agents/supervisor/settings", json={"llm": {"provider": "rules"}, "version": 0})
    assert stale.status_code == 409
    body = stale.json()
    assert body["code"] == "version_conflict" and body["version"] == 1
    assert body["settings"]["settings"]["llm"]["provider"] == ollama
    # an older route that changes the model choice moves the version too, so the page cannot overwrite it unseen
    assert client.patch("/api/agents/supervisor", json={"model": "claude-x"}).status_code == 200
    assert client.get("/api/agents/supervisor/settings").json()["version"] == 2
    assert client.patch("/api/agents/supervisor/settings", json={"llm": {"provider": "rules"}, "version": 1}).status_code == 409


def test_the_settings_are_validated(client):
    ollama = local(client)
    hosted = cloud(client)
    member = client.post("/api/agents", json={"name": "Triage"}).json()["id"]
    cases = [
        ("supervisor", {"name": "x"}, "is a core agent: its name cannot be changed"),
        ("supervisor", {"colour": "red"}, "Unknown setting: colour"),
        ("supervisor", {"config": {"budgets": {}}}, "Unknown setting: config.budgets"),
        ("supervisor", {"config": {"budget": {"daily_usd": 5}}}, "Unknown setting: config.budget.daily_usd"),
        ("supervisor", {"config": {"budget": {"daily_cost_usd": 0}}}, "Daily cost: "),
        ("supervisor", {"config": {"params": {"max_tool_rounds": 31}}}, "Max tool rounds: "),
        ("supervisor", {"config": {"params": {"effort": "extreme"}}}, "Effort: "),
        ("supervisor", {"config": {"allowed_tools": ["list_tools", "fly"]}}, "Allowed tools: unknown tool 'fly'"),
        ("supervisor", {"config": {"language": "not a code!"}}, "Language: 'not a code!' is not a language code"),
        ("patcher", {"config": {"memory": {"mode": "off"}}}, "Memory: Patch Agent does not chat"),
        ("patcher", {"config": {"allowed_tools": []}}, "Allowed tools: Patch Agent does not chat"),
        (member, {"config": {"extra_instructions": "more"}}, "Additional instructions: a custom agent's instructions"),
        (member, {"config": {"instructions_mode": "replace"}}, "nothing to replace"),
        (member, {"team": "nope"}, "Unknown team"),
        ("operator", {"instructions": "x"}, "works without an AI model"),
        ("operator", {"llm": {"provider": ollama}}, "works without an AI model"),
        ("supervisor", {"llm": {"model": "m"}}, "a model needs a provider"),
        ("supervisor", {"llm": {"provider": "nope"}}, "unknown provider 'nope'"),
        ("supervisor", {"llm": {"provider": "auto"}}, "only for the suite default"),
        ("supervisor", {"config": {"purposes": {"code": {"provider": ollama}}}}, "has no separate model for 'code'"),
        ("patcher", {"config": {"purposes": {"chat": {"provider": ollama}}}}, "has no separate model for 'chat'"),
        ("supervisor", {"llm": {"provider": hosted}, "config": {"local_only": True}}, "is a cloud provider"),
    ]
    for agent_id, body, expected in cases:
        response = client.patch(f"/api/agents/{agent_id}/settings", json=body)
        assert response.status_code == 400 and expected in response.json()["detail"], (body, response.text)
    assert client.patch("/api/agents/nobody/settings", json={}).status_code == 404
    assert client.get("/api/agents/operator/settings").json()["uses_model"] is False


def test_the_patch_agent_chooses_a_model_per_task(client):
    hub = client.app.state.hub
    ollama, studio = local(client), local(client, "LM Studio", "m2", base_url="http://localhost:1234/v1")
    view = client.get("/api/agents/patcher/settings").json()
    assert view["per_task"] == ["code", "generate"] and set(view["chain"]) == {"code", "generate"}
    saved = client.patch("/api/agents/patcher/settings", json={
        "llm": {"provider": ollama}, "config": {"purposes": {"code": {"provider": studio, "model": "m9"}}}}).json()
    assert saved["effective"]["purposes"]["code"]["source"] == "agent_purpose"
    assert (hub.llm.resolve("patcher", "code").model, hub.llm.resolve("patcher", "generate").provider) == ("m9", ollama)
    chain = [(row["level"], row["status"]) for row in saved["chain"]["code"]]
    assert chain[:2] == [("agent_purpose", "used"), ("agent", "not reached")] and chain[-1] == ("rules", "not reached")
    cleared = client.patch("/api/agents/patcher/settings", json={"config": {"purposes": {"code": None}}}).json()
    assert cleared["settings"]["config"]["purposes"] == {} and cleared["effective"]["purposes"]["code"]["source"] == "agent"
    assert any("code changes model" in e["text"] for e in client.get("/api/activity").json())


def test_local_only_skips_cloud_providers_and_switching_it_off_is_a_warning(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama = local(client)
    saved = client.patch("/api/agents/supervisor/settings", json={"config": {"local_only": True}}).json()
    chat = saved["effective"]["purposes"]["chat"]
    assert chat["provider"] == ollama and saved["effective"]["local_only"] is True  # automatic: past Claude to a local one
    off = client.patch("/api/agents/supervisor/settings", json={"config": {"local_only": False}})
    assert off.status_code == 200 and hub.llm.resolve("supervisor", "chat").provider == "anthropic"
    entry = last(client, "Configured Hub Supervisor")
    assert entry["level"] == "warn" and entry["text"] == "Configured Hub Supervisor: local only off"


def test_the_suite_selection_api(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    ollama, hosted = local(client), cloud(client)
    add_tool(client, "wazuh", "Wazuh")
    seen = events(hub)
    view = client.get("/api/llm/selection").json()
    assert view["selection"]["default"] == {"provider": "auto", "model": ""} and view["selection"]["version"] == 0
    assert view["suite"]["provider"] == "anthropic" and any(a["agent_id"] == "patcher" for a in view["effective"])
    assert view["deterministic"] >= 1 and not any(a["agent_id"] == "operator" for a in view["effective"])
    saved = client.patch("/api/llm/selection", json={
        "default": {"provider": ollama, "model": ""}, "purposes": {"code": {"provider": "anthropic", "model": "claude-x"}},
        "teams": {"wazuh": {"provider": "", "model": "", "local_only": True}}, "fallback": [hosted], "version": 0})
    assert saved.status_code == 200, saved.text
    sel = saved.json()["selection"]
    assert sel["version"] == 1 and sel["teams"]["wazuh"]["local_only"] and sel["fallback"] == [hosted]
    assert hub.llm.resolve("supervisor", "chat").provider == ollama
    assert hub.llm.resolve("patcher", "code").model == "claude-x"
    assert hub.llm.resolve("tool:wazuh", "generate").local_only  # the team's local-only rule reaches its lead
    assert any(t == "llm_selection" for t, _ in seen)
    entry = last(client, "AI model selection")
    assert entry["text"].startswith(f"AI model selection: suite default automatic -> {ollama} (default model); "
                                    "code changes default set to anthropic/claude-x; Wazuh team: local-only on")
    stale = client.patch("/api/llm/selection", json={"default": {"provider": "auto"}, "version": 0})
    assert stale.status_code == 409 and stale.json()["code"] == "version_conflict"
    assert stale.json()["selection"]["version"] == 1
    off = client.patch("/api/llm/selection", json={"teams": {"wazuh": None}, "purposes": {"code": None}, "version": 1})
    assert off.status_code == 200 and off.json()["selection"]["teams"] == {} and off.json()["selection"]["purposes"] == {}
    assert last(client, "AI model selection")["level"] == "warn"  # a team lost its local-only rule
    unchanged = client.patch("/api/llm/selection", json={"teams": {}}).json()["selection"]
    assert unchanged["version"] == 2  # nothing changed: no new version, no entry


def test_the_selection_is_validated(client):
    ollama, hosted = local(client), cloud(client)
    add_tool(client, "wazuh", "Wazuh")
    cases = [
        ({"default": {"provider": "", "model": "m"}}, "a model needs a provider"),
        ({"default": {"provider": "nope"}}, "unknown provider 'nope'"),
        ({"purposes": {"code": {"provider": "auto"}}}, "only for the suite default"),
        ({"purposes": {"writing": {"provider": ollama}}}, "Unknown purpose 'writing'"),
        ({"teams": {"nope": {"provider": ollama}}}, "Unknown team 'nope'"),
        ({"teams": {"wazuh": {"provider": hosted, "local_only": True}}}, "cloud provider"),
        ({"fallback": [ollama, ollama]}, "only once"),
        ({"fallback": ["rules"]}, "rules always come last"),
        ({"fallback": ["ghost"]}, "unknown provider 'ghost'"),
        ({"default": {"provider": "rules", "model": "x"}}, "rules have no model"),
        ({"language": "not a code!"}, "is not a language code"),
    ]
    for body, expected in cases:
        response = client.patch("/api/llm/selection", json=body)
        assert response.status_code == 400 and expected in response.json()["detail"], (body, response.text)
    assert client.patch("/api/llm/selection", json={"fallback": ["a"] * 9}).status_code == 422
    assert client.get("/api/llm/selection").json()["selection"]["version"] == 0  # nothing stored


def test_a_provider_in_use_at_any_level_cannot_be_removed(client):
    ollama = local(client)
    add_tool(client, "wazuh", "Wazuh")
    for body in ({"default": {"provider": ollama}}, {"purposes": {"code": {"provider": ollama}}},
                 {"teams": {"wazuh": {"provider": ollama}}}, {"fallback": [ollama]}):
        assert client.patch("/api/llm/selection", json=body).status_code == 200
        refused = client.delete(f"/api/llm/providers/{ollama}")
        assert refused.status_code == 409, body
        reset = {"default": {"provider": "auto"}, "purposes": {"code": None}, "teams": {"wazuh": None}, "fallback": []}
        assert client.patch("/api/llm/selection", json=reset).status_code == 200
    assert client.patch("/api/agents/patcher/settings", json={"config": {"purposes": {"code": {"provider": ollama}}}}).status_code == 200
    assert "Patch Agent" in client.delete(f"/api/llm/providers/{ollama}").json()["detail"]
    client.patch("/api/agents/patcher/settings", json={"config": {"purposes": {"code": None}}})
    assert client.delete(f"/api/llm/providers/{ollama}").status_code == 200


def test_viewers_read_the_model_settings_and_only_admins_change_them(client, sign_in):
    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.get("/api/llm/selection").status_code == 200
    assert viewer.get("/api/agents/supervisor/settings").status_code == 200
    for caller in (viewer, operator):
        assert caller.patch("/api/llm/selection", json={"default": {"provider": "rules"}}).status_code == 403
        assert caller.patch("/api/agents/supervisor/settings", json={"llm": {"provider": "rules"}}).status_code == 403


def test_creating_an_agent_announces_its_settings(client):
    hub = client.app.state.hub
    seen = events(hub)
    created = client.post("/api/agents", json={"name": "Watcher"}).json()
    assert ("agent_settings", {"id": created["id"], "version": 0}) in seen
    # a plain status change (an agent handled a message) is an `agent` event, not a settings change
    seen.clear()
    client.post("/api/chat", json={"text": "status"})
    assert any(t == "agent" for t, _ in seen) and not any(t == "agent_settings" for t, _ in seen)


def test_model_settings_never_carry_a_key(client):
    secret = "sk-local-secret-key-1234567890"
    provider = local(client, api_key=secret)
    client.patch("/api/llm/selection", json={"default": {"provider": provider}})
    client.patch("/api/agents/patcher/settings", json={"llm": {"provider": provider}})
    for path in ("/api/llm/selection", "/api/agents/patcher/settings", "/api/agents/supervisor/settings", "/api/agents",
                 "/api/agents/teams", "/api/llm/providers", "/api/activity"):
        assert secret not in client.get(path).text, path


# -- stage 4: every setting, the history, instructions, tools ---------------------------------------------------------

def test_every_setting_is_saved_logged_kept_and_applied_to_the_model_calls(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="Klaar.")])])
    secret_rule = "Always cite the ids you looked up."
    saved = client.patch("/api/agents/supervisor/settings", json={"version": 0, "config": {
        "params": {"effort": "high", "max_output_tokens": 4000, "max_tool_rounds": 3},
        "extra_instructions": secret_rule, "language": "nl", "allowed_tools": ["list_tools", "list_approvals"],
        "budget": {"daily_cost_usd": 5}, "rate": {"calls_per_minute": 10},
        "memory": {"mode": "persisted", "retention_days": 7}}})
    assert saved.status_code == 200, saved.text
    view = saved.json()
    config = view["settings"]["config"]
    assert view["version"] == 1 and config["params"]["effort"] == "high" and config["budget"]["hard_stop"] is True
    assert config["memory"] == {"mode": "persisted", "max_turns": 40, "retention_days": 7}
    assert view["language"]["effective"] == "nl" and view["budget_state"]["limit"] == 5
    catalog = {t["name"]: t for t in view["tools_catalog"]}
    assert catalog["list_tools"]["allowed"] and not catalog["run_command"]["allowed"] and catalog["run_command"]["granted"]
    entry = last(client, "Configured Hub Supervisor")
    assert entry["level"] == "info" and secret_rule not in json.dumps(entry)  # instructions as length and hash only
    assert f"additional instructions changed ({len(secret_rule)} chars, sha256 " in entry["text"]
    assert "effort none -> high" in entry["text"] and "budget daily_cost_usd none -> 5.0" in entry["text"]
    assert "language suite default -> nl" in entry["text"] and "memory session -> persisted" in entry["text"]

    reply = client.post("/api/chat", json={"text": "status?"}).json()
    assert reply["reply"] == "Klaar."
    call = fake.calls[0]
    system = json.dumps(call["system"])
    assert "Additional instructions from an administrator" in system and secret_rule in system
    assert "Answer in Dutch" in system
    assert call["output_config"]["effort"] == "high" and call["max_tokens"] == 4000
    assert {t["name"] for t in call["tools"]} == {"list_tools", "list_approvals"}

    history = client.get("/api/agents/supervisor/settings/history").json()
    assert [h["version"] for h in history] == [1, 0] and history[0]["actor"] == "admin"
    assert "config.params" in history[0]["changed"] and "config.memory" in history[0]["changed"]
    restored = client.post("/api/agents/supervisor/settings/restore", json={"version": 0})
    assert restored.status_code == 200, restored.text
    back = restored.json()
    assert back["version"] == 2 and back["settings"]["config"]["params"]["effort"] == ""
    assert back["settings"]["config"]["allowed_tools"] is None and back["settings"]["config"]["extra_instructions"] == ""
    entry = last(client, "Restored Hub Supervisor settings to version 0")
    assert entry["level"] == "warn"  # it widened the allowed tools again
    assert client.post("/api/agents/supervisor/settings/restore", json={"version": 9}).status_code == 404
    assert client.post("/api/agents/supervisor/settings/restore",
                       json={"version": 1, "base_version": 1}).status_code == 409
    assert [h["version"] for h in client.get("/api/agents/supervisor/settings/history").json()][:2] == [2, 1]


def test_widening_changes_are_warnings_and_tightening_ones_are_not(client):
    tight = client.patch("/api/agents/supervisor/settings", json={"config": {
        "allowed_tools": ["list_tools"], "budget": {"daily_cost_usd": 2}}}).json()
    assert last(client, "Configured Hub Supervisor")["level"] == "info"
    for change in ({"config": {"allowed_tools": ["list_tools", "run_command"]}}, {"config": {"allowed_tools": None}},
                   {"config": {"budget": {"hard_stop": False}}}, {"config": {"budget": {"daily_cost_usd": 3}}}):
        assert client.patch("/api/agents/supervisor/settings", json=change).status_code == 200
        assert last(client, "Configured Hub Supervisor")["level"] == "warn", change
    assert tight["version"] == 1


def test_core_agent_instructions_append_or_replace(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")]) for _ in range(3)])
    view = client.get("/api/agents/supervisor/settings").json()
    assert "Hub Supervisor" in view["builtin_instructions"] and view["settings"]["instructions"] == ""
    replaced = client.patch("/api/agents/supervisor/settings", json={
        "config": {"instructions_mode": "replace"}, "instructions": "You are terse."}).json()
    assert replaced["settings"]["instructions"] == "You are terse."
    record = next(a for a in client.get("/api/agents").json() if a["id"] == "supervisor")
    assert record["instructions"] == "You are terse." and record["custom_instructions"]
    client.post("/api/chat", json={"text": "hi"})
    assert json.dumps(fake.calls[0]["system"]).startswith('"You are terse.') or "You are terse." in json.dumps(fake.calls[0]["system"])
    assert "Hub Supervisor, the orchestrating agent" not in json.dumps(fake.calls[0]["system"])
    entry = last(client, "Configured Hub Supervisor")
    assert "instructions append -> replace" in entry["text"] and "You are terse." not in entry["text"]
    # back to the built-in instructions: the replacement goes (the history keeps it)
    appended = client.patch("/api/agents/supervisor/settings", json={"config": {"instructions_mode": "append"}}).json()
    assert appended["settings"]["instructions"] == ""
    assert hub.agents.get("supervisor").instructions == hub.agents.get("supervisor").default_instructions
    # the older route replaces them too, and moves the version
    version = appended["version"]
    assert client.patch("/api/agents/supervisor", json={"instructions": "Older route."}).status_code == 200
    after = client.get("/api/agents/supervisor/settings").json()
    assert after["version"] == version + 1 and after["settings"]["config"]["instructions_mode"] == "replace"
    assert hub.agents.get("supervisor").instructions == "Older route."


def test_a_custom_agents_definition_is_part_of_its_settings(client):
    hub = client.app.state.hub
    member = client.post("/api/agents", json={"name": "Triage", "permissions": ["read"]}).json()["id"]
    saved = client.patch(f"/api/agents/{member}/settings", json={
        "name": "Triage lead", "description": "Sorts alerts", "task": "Summarize the state", "schedule_minutes": 60,
        "instructions": "Be brief.", "version": 0})
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["settings"]["name"] == "Triage lead" and body["settings"]["schedule_minutes"] == 60
    defn = hub.store.get("agent_defs", member)
    assert (defn["name"], defn["task"], defn["instructions"]) == ("Triage lead", "Summarize the state", "Be brief.")
    entry = last(client, "Configured Triage lead")
    assert "name Triage -> Triage lead" in entry["text"] and "schedule none -> 60 minutes" in entry["text"]
    assert "Be brief." not in entry["text"] and entry["level"] == "info"
    wider = client.patch(f"/api/agents/{member}/settings", json={"permissions": ["read", "flows"]})
    assert wider.status_code == 200 and last(client, "Configured Triage lead")["level"] == "warn"
    restored = client.post(f"/api/agents/{member}/settings/restore", json={"version": 0}).json()
    assert restored["settings"]["name"] == "Triage" and restored["settings"]["permissions"] == ["read"]
    assert hub.store.get("agent_defs", member)["task"] == ""
    # the older route moves the version (and keeps a history entry) for any change of its definition
    version = restored["version"]
    client.patch(f"/api/agents/{member}", json={"description": "changed elsewhere"})
    assert client.get(f"/api/agents/{member}/settings").json()["version"] == version + 1


def test_temperature_only_where_the_model_takes_it(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch)
    refused = client.patch("/api/agents/supervisor/settings", json={"config": {"params": {"temperature": 0.3}}})
    assert refused.status_code == 400 and refused.json()["detail"].startswith("Temperature: Claude claude-opus-5-5")
    ollama = local(client)
    seen_bodies: list = []
    transport, _ = chat_transport(lambda body: seen_bodies.append(body) or completion("Done."))
    hub.llm_transport = transport
    ok = client.patch("/api/agents/supervisor/settings", json={"llm": {"provider": ollama},
                                                               "config": {"params": {"temperature": 0.3}}})
    assert ok.status_code == 200, ok.text
    assert client.post("/api/chat", json={"text": "hi"}).json()["reply"] == "Done."
    assert seen_bodies[-1]["temperature"] == 0.3
    view = ok.json()
    assert view["models"]["chat"]["provider"] == ollama and view["call_tokens"] == {"chat": 16000}
