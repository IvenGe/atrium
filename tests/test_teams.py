"""Agent teams: custom agent definitions, permission clamping, team size and depth, the guardrails (and their GRC
control), the command policy switch, the shared toolkit, local models through an OpenAI-compatible API, team
proposals and their approval, and the agent scheduler. No network: local model servers are httpx mock transports."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from test_llm_paths import FakeLLM, block

from hub import guardrails
from hub.agents import teams, toolkit
from hub.execution.policy import classify, decide
from hub.grc.baseline import CONTROLS_BY_ID
from hub.grc.checks import Snapshot, evaluate_controls
from hub.models import AgentDef, Manifest, Tool

KEY = "sk-local-model-key-5e4d3c2b1a"
COMMAND = f'"{sys.executable}" -c "print(6*7)"'  # harmless, but not on the read-only list: a state change


def add_tool(client, tool_id: str, name: str, **manifest) -> Tool:
    hub = client.app.state.hub
    tool = Tool(id=tool_id, name=name, source_type="saas", source=f"https://{tool_id}.example.com", status="ready",
                manifest=Manifest(id=tool_id, name=name, kind="saas", **manifest))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    return tool


def agent(client, agent_id: str) -> dict:
    return next(a for a in client.get("/api/agents").json() if a["id"] == agent_id)


def ask(client, sender: str, recipient: str, subject: str, body: dict | None = None) -> dict:
    hub = client.app.state.hub
    return client.portal.call(hub.bus.request, sender, recipient, subject, body or {}, 60)


def pending(client, kind: str) -> list[dict]:
    return [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == kind]


def set_guardrails(client, **values) -> dict:
    response = client.patch("/api/settings/guardrails", json=values)
    assert response.status_code == 200, response.text
    return response.json()


def activity(client) -> list[dict]:
    return client.get("/api/activity?limit=2000").json()


# -- definitions ---------------------------------------------------------------------------------


def test_admins_create_edit_and_remove_custom_agents(client, sign_in, wait_for):
    add_tool(client, "wazuh", "Wazuh")
    operator = sign_in("operator")
    body = {"name": "Night watch", "title": "Health watcher", "team": "wazuh", "permissions": ["read", "commands"],
            "schedule_minutes": 30, "task": "Check the health of Wazuh and summarize its state."}
    assert operator.post("/api/agents", json=body).status_code == 403
    created = client.post("/api/agents", json=body)
    assert created.status_code == 201, created.text
    record = created.json()
    assert record["id"] == "agent:wazuh-night-watch" and record["kind"] == "custom" and record["clamped"] == []
    assert (record["team"], record["parent"], record["depth"]) == ("wazuh", "tool:wazuh", 1)
    assert record["provider"] == "rules" and record["provider_label"] == "Rules"  # no Claude, no local model
    assert record["effective_permissions"] == ["read", "commands"] and record["next_run"] > time.time()
    assert ("admin", "Created agent Night watch (Health watcher) in the Wazuh team") in [
        (e["actor"], e["text"]) for e in activity(client)]

    # every field of a custom agent can change; the core agents keep their limits
    changed = client.patch("/api/agents/agent:wazuh-night-watch",
                           json={"title": "Watcher", "schedule_minutes": 60, "enabled": False}).json()
    assert changed["title"] == "Watcher" and changed["schedule_minutes"] == 60 and changed["status"] == "paused"
    assert client.patch("/api/agents/agent:wazuh-night-watch", json={"paused": False}).json()["enabled"] is True
    assert client.patch("/api/agents/agent:wazuh-night-watch", json={"schedule_minutes": 3}).status_code == 400
    assert client.patch("/api/agents/agent:wazuh-night-watch", json={"provider": "nope"}).status_code == 400
    assert client.patch("/api/agents/patcher", json={"title": "x"}).status_code == 400
    assert client.patch("/api/agents/patcher", json={"model": "claude-sonnet-5-5"}).json()["model"] == "claude-sonnet-5-5"
    assert client.delete("/api/agents/patcher").status_code == 400
    assert client.delete("/api/agents/tool:wazuh").status_code == 400
    assert operator.delete("/api/agents/agent:wazuh-night-watch").status_code == 403
    assert client.post("/api/agents", json={**body, "team": "nope"}).status_code == 400
    assert client.post("/api/agents", json={**body, "provider": "nope"}).status_code == 400
    assert client.post("/api/agents", json={**body, "id": "wazuh-night-watch"}).status_code == 400  # taken

    teams_view = client.get("/api/agents/teams").json()
    wazuh = next(t for t in teams_view["teams"] if t["team"] == "wazuh")
    assert wazuh["lead"]["id"] == "tool:wazuh" and [m["id"] for m in wazuh["members"]] == ["agent:wazuh-night-watch"]
    assert wazuh["category"] == "siem" and wazuh["suggested"] == ["Alert triage analyst", "Health watcher", "Maintainer"]
    assert {p["id"] for p in teams_view["permissions"]} >= {"read", "agents"}
    assert [p["id"] for p in teams_view["providers"]][:2] == ["anthropic", "rules"]

    # removed agents are gone after a restart too
    assert client.delete("/api/agents/agent:wazuh-night-watch").json() == {"ok": True}
    assert all(a["id"] != "agent:wazuh-night-watch" for a in client.get("/api/agents").json())
    assert client.app.state.hub.store.get("agent_defs", "agent:wazuh-night-watch") is None


def test_core_agents_declare_permissions_and_teams(client):
    agents = {a["id"]: a for a in client.get("/api/agents").json()}
    assert agents["supervisor"]["permissions"] == list(teams.PERMISSION_INFO) and agents["supervisor"]["team"] == "hub"
    assert agents["operator"]["permissions"] == ["read", "commands"] and agents["patcher"]["permissions"] == ["read", "patches"]
    assert agents["module:grc"]["team"] == "module:grc" and "grc_write" in agents["module:grc"]["permissions"]
    assert all(a["kind"] == "core" and a["depth"] == 0 for a in agents.values())


# -- permissions, size and depth ------------------------------------------------------------------


def test_members_never_exceed_their_parents_permissions(client):
    hub = client.app.state.hub
    lead = client.post("/api/agents", json={"name": "Lead", "team": "module:grc", "permissions": ["read", "grc_write", "agents"]}).json()
    assert lead["parent"] == "module:grc" and lead["effective_permissions"] == ["read", "grc_write", "agents"]
    # module:grc cannot run commands, so neither can a member of its team
    capped = client.post("/api/agents", json={"name": "Capped", "team": "module:grc", "permissions": ["read", "commands"]}).json()
    assert capped["effective_permissions"] == ["read"] and capped["clamped"] == ["commands"]

    set_guardrails(client, allow_nested_teams=True, max_team_depth=2)
    sub = client.post("/api/agents", json={"name": "Sub", "team": "module:grc", "parent": lead["id"],
                                           "permissions": ["read", "grc_write", "flows", "patches"]}).json()
    assert sub["depth"] == 2 and sub["effective_permissions"] == ["read", "grc_write"]
    # the clamp follows the parent: narrowing the parent narrows the member at once
    client.patch(f"/api/agents/{lead['id']}", json={"permissions": ["read"]})
    assert agent(client, sub["id"])["effective_permissions"] == ["read"]
    defn = teams.get_def(hub, sub["id"])
    assert toolkit.definitions(set(teams.effective_permissions(hub, defn))) == toolkit.definitions({"read"})

    # with the guardrail off, members keep what they were given
    state = set_guardrails(client, limit_to_parent_permissions=False)
    assert state["guardrails"]["limit_to_parent_permissions"] is False
    assert agent(client, sub["id"])["effective_permissions"] == ["read", "patches", "flows", "grc_write"]
    assert agent(client, capped["id"])["effective_permissions"] == ["read", "commands"]

    # switching nested teams off again stops the nested agent from acting (it stays, so it can be moved or removed)
    assert agent(client, sub["id"])["outside_guardrails"] is None
    set_guardrails(client, allow_nested_teams=False)
    assert "allow_nested_teams" in agent(client, sub["id"])["outside_guardrails"]
    refused = client.post(f"/api/agents/{sub['id']}/chat", json={"text": "report the state"})
    assert refused.status_code == 400 and "may not act" in refused.json()["detail"]
    assert client.post(f"/api/agents/{lead['id']}/chat", json={"text": "report the state"}).status_code == 200


def test_team_size_and_depth_limits(client):
    add_tool(client, "snipe-it", "Snipe-IT")
    set_guardrails(client, max_team_size=2)
    first = client.post("/api/agents", json={"name": "One", "team": "snipe-it", "permissions": ["read", "agents"]}).json()
    client.post("/api/agents", json={"name": "Two", "team": "snipe-it"})
    full = client.post("/api/agents", json={"name": "Three", "team": "snipe-it"})
    assert full.status_code == 400 and "max_team_size" in full.json()["detail"]
    set_guardrails(client, limit_team_size=False)
    assert client.post("/api/agents", json={"name": "Three", "team": "snipe-it"}).status_code == 201

    # a tighter limit later stops the newest members from acting (and from running on a schedule) - they stay
    hub = client.app.state.hub
    set_guardrails(client, limit_team_size=True)
    newest = agent(client, "agent:snipe-it-three")
    assert "max_team_size" in newest["outside_guardrails"] and agent(client, first["id"])["outside_guardrails"] is None
    client.patch(f"/api/agents/{newest['id']}", json={"schedule_minutes": 5, "task": "Summarize the state."})
    assert client.portal.call(hub.tick_agents, time.time() + 600) == []
    assert client.post(f"/api/agents/{newest['id']}/chat", json={"text": "status"}).status_code == 400
    set_guardrails(client, limit_team_size=False)
    assert client.portal.call(hub.tick_agents, time.time() + 600) == [newest["id"]]

    # nested teams are off by default; when on, the depth is bounded
    nested = client.post("/api/agents", json={"name": "Sub", "team": "snipe-it", "parent": first["id"]})
    assert nested.status_code == 400 and "allow_nested_teams" in nested.json()["detail"]
    set_guardrails(client, allow_nested_teams=True)
    too_deep = client.post("/api/agents", json={"name": "Sub", "team": "snipe-it", "parent": first["id"]})
    assert too_deep.status_code == 400 and "max_team_depth" in too_deep.json()["detail"]
    set_guardrails(client, max_team_depth=2)
    sub = client.post("/api/agents", json={"name": "Sub", "team": "snipe-it", "parent": first["id"], "permissions": ["read", "agents"]}).json()
    assert sub["depth"] == 2
    deeper = client.post("/api/agents", json={"name": "Deeper", "team": "snipe-it", "parent": sub["id"]})
    assert deeper.status_code == 400 and "max_team_depth" in deeper.json()["detail"]
    other_team = client.post("/api/agents", json={"name": "Elsewhere", "team": "hub", "parent": first["id"]})
    assert other_team.status_code == 400  # a parent must belong to the same team

    # an agent with the "agents" permission proposes members of its own (nested) team through the toolkit
    hub = client.app.state.hub
    custom = hub.agents.get(first["id"])
    ctx = custom.context()
    result = client.portal.call(toolkit.execute, ctx, "create_team_member", {
        "name": "Helper", "title": "Helper", "description": "", "instructions": "", "permissions": ["read", "commands"],
        "task": "", "schedule_minutes": 0})
    assert result["approval_id"] and result["members"][0]["clamped"] == ["commands"]  # its parent has no commands
    approval = pending(client, "agent_team")[0]
    assert approval["requested_by"] == first["id"] and approval["payload"]["parent"] == first["id"]
    assert approval["payload"]["depth"] == 2

    # removing an agent hands its members to its parent and withdraws what it proposed
    client.delete(f"/api/agents/{first['id']}")
    moved = agent(client, sub["id"])
    assert (moved["parent"], moved["depth"]) == ("tool:snipe-it", 1)
    withdrawn = next(a for a in client.get("/api/approvals").json() if a["id"] == approval["id"])
    assert withdrawn["status"] == "rejected" and "was removed" in withdrawn["note"]


# -- guardrails and their control ----------------------------------------------------------------


def test_guardrail_settings_are_admin_only_validated_and_logged(client, sign_in, wait_for):
    settings = client.get("/api/settings").json()
    assert settings["guardrails"] == guardrails.defaults()
    assert settings["guardrails"] == {
        "limit_to_parent_permissions": True, "allow_nested_teams": False, "max_team_depth": 1, "limit_team_size": True,
        "max_team_size": 5, "team_actions_need_approval": True, "block_catastrophic_commands": True,
        "scans_need_approval": True, "team_requires_approval": True,
        # extensions and self-patching (EXTEND_SPEC)
        "allow_extensions": True, "extensions_need_approval": True, "allow_self_patching": True,
        "self_patch_requires_tests": True, "self_patch_requires_approval": True, "self_patch_via_pull_request": True,
        "device_changes": False, "device_changes_need_second_person": True,
        "device_changes_need_maintenance_window": True, "device_changes_need_backup": True,
        "approval_expiry_hours": 24, "approvals_need_second_person": False}
    catalog = {g["key"]: g for g in settings["guardrail_catalog"]}
    assert catalog["block_catastrophic_commands"]["risk"] and catalog["max_team_size"]["max"] == 50
    assert not any(g["relaxed"] for g in catalog.values())

    assert sign_in("operator").patch("/api/settings/guardrails", json={"max_team_size": 3}).status_code == 403
    for bad in ({"nope": True}, {"max_team_size": 0}, {"max_team_size": True}, {"limit_team_size": 1}, {}):
        assert client.patch("/api/settings/guardrails", json=bad).status_code == 400, bad
    assert client.get("/api/settings").json()["guardrails"] == guardrails.defaults()  # nothing stored

    after = set_guardrails(client, block_catastrophic_commands=False, max_team_size=3)
    assert after["guardrails"]["block_catastrophic_commands"] is False and after["guardrails"]["max_team_size"] == 3
    assert {g["key"] for g in after["guardrail_catalog"] if g["relaxed"]} == {"block_catastrophic_commands"}
    entries = [(e["actor"], e["level"], e["text"]) for e in activity(client)]
    assert ("admin", "warn", "Guardrail 'Block catastrophic commands' relaxed: on -> off") in entries
    assert ("admin", "info", "Guardrail 'Maximum team size' changed: 5 -> 3") in entries
    # the older settings route takes guardrails too, with the same validation
    assert client.patch("/api/settings", json={"guardrails": {"max_team_depth": 9}}).status_code == 400
    assert client.patch("/api/settings", json={"guardrails": {"allow_nested_teams": True}}).json()["guardrails"]["allow_nested_teams"]

    # HB-AC-6 fails while a core guardrail is off, and raises its risk
    control = wait_for(lambda: (c := next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == "HB-AC-6"))["status"] == "fail" and c)
    assert "Block catastrophic commands" in control["detail"]
    wait_for(lambda: any(r["title"] == "AI agents operate without guardrails" and r["status"] == "open"
                         for r in client.get("/api/grc/risks").json()))
    set_guardrails(client, block_catastrophic_commands=True)
    wait_for(lambda: next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == "HB-AC-6")["status"] == "partial")


def test_agent_guardrails_control():
    def status(**values):
        return {s.id: s for s in evaluate_controls(Snapshot(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[],
                                                             autonomy="assisted", audit_entries=1,
                                                             guardrails={**guardrails.defaults(), **values}), {})}["HB-AC-6"]

    assert status().status == "pass"
    for key in ("block_catastrophic_commands", "team_actions_need_approval", "limit_to_parent_permissions"):
        assert status(**{key: False}).status == "fail", key
    assert status(limit_team_size=False).status == "partial"
    assert status(allow_nested_teams=True).status == "partial"
    assert status(scans_need_approval=False, team_requires_approval=False).status == "pass"
    control = CONTROLS_BY_ID["HB-AC-6"]
    assert control.title == "AI agent guardrails are enforced"
    assert control.refs == {"ISO27001": "A.8.2 / A.8.32", "SOC2": "CC6.1 / CC8.1", "NIS2": "21(2)(i)",
                            "CyFun2025": "ID.RA-01.5 / ID.RA-01.4 / PR.AA-05.7",
                            "CyFun2023": "DE.CM-8.1 / ID.RA-1.3 / PR.AC-4.7"}
    assert control.risk == ("AI agents operate without guardrails", 3, 5)


def test_relaxed_approval_guardrails_make_the_approval_control_partial_and_new_keys_map_to_controls():
    def states(**values):
        snapshot = Snapshot(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[], autonomy="assisted",
                            audit_entries=1, guardrails={**guardrails.defaults(), **values})
        return {s.id: s for s in evaluate_controls(snapshot, {})}

    assert states()["HB-AC-2"].status == "pass"
    for key in ("scans_need_approval", "team_requires_approval"):
        state = states(**{key: False})["HB-AC-2"]
        assert state.status == "partial" and "without approval" in state.detail, key
    assert "up to maximum team depth 3" in states(allow_nested_teams=True, max_team_depth=3)["HB-AC-6"].detail
    assert {g["key"]: g["control"] for g in guardrails.catalog({})}["block_catastrophic_commands"] == "HB-AC-6"

    # a guardrail a later feature registers is reflected in its control without changing the checks
    later = guardrails.register(guardrails.Guardrail(
        "extensions_need_review", "Extensions need review", "test", True, "test", control="HB-AC-6", weakens="fail"))
    try:
        assert states()["HB-AC-6"].status == "pass"
        state = states(extensions_need_review=False)["HB-AC-6"]
        assert state.status == "fail" and "Extensions need review" in state.detail
        assert guardrails.validate({"extensions_need_review": False}) == {"extensions_need_review": False}
    finally:
        guardrails.REGISTRY.pop(later.key)


def test_blocked_commands_become_changes_when_the_guardrail_is_off():
    assert classify("rm -rf /")[0] == "blocked"
    risk, why = classify("rm -rf /", block_catastrophic=False)
    assert risk == "change" and "guardrail is off" in why
    assert decide("shutdown -h now", "assisted", from_person=False, block_catastrophic=False).action == "approve"
    assert decide("shutdown -h now", "assisted", from_person=False).action == "deny"
    assert classify("", block_catastrophic=False)[0] == "blocked"  # an empty command is never a command


def test_operator_applies_the_command_guardrails(client):
    hub = client.app.state.hub
    # (never executed: an agent's state-changing command waits for approval, and the approval is rejected)
    assert ask(client, "supervisor", "operator", "run", {"command": "mkfs.ext4 /dev/sdz9"})["status"] == "denied"
    set_guardrails(client, block_catastrophic_commands=False)
    queued = ask(client, "supervisor", "operator", "run", {"command": "mkfs.ext4 /dev/sdz9"})
    assert queued["status"] == "pending_approval" and queued["risk"] == "change"
    client.post(f"/api/approvals/{queued['approval_id']}", json={"approve": False})

    # team agents follow the autonomy level ...
    queued = ask(client, "agent:helper", "operator", "run", {"command": COMMAND})
    assert queued["status"] == "pending_approval"
    assert next(a for a in client.get("/api/approvals").json() if a["id"] == queued["approval_id"])["payload"]["origin"] == "agent:helper"
    # ... unless an admin lets them act without approval (other agents still follow it)
    set_guardrails(client, team_actions_need_approval=False)
    assert guardrails.effective_autonomy(hub, "agent:helper") == "autonomous"
    assert guardrails.effective_autonomy(hub, "supervisor") == "assisted"
    done = ask(client, "agent:helper", "operator", "run", {"command": COMMAND})
    assert done["status"] == "done" and done["output"].strip() == "42"
    assert ask(client, "supervisor", "operator", "run", {"command": COMMAND})["status"] == "pending_approval"


def test_a_queued_command_the_guardrail_blocks_again_never_runs(client, monkeypatch, wait_for):
    hub = client.app.state.hub
    ran = []

    async def fake_execute(request):
        ran.append(request["command"])
        return {"exit_code": 0, "output": "", "duration": 0.0}

    monkeypatch.setattr(hub.agents.get("operator"), "execute", fake_execute)  # nothing below may run for real
    set_guardrails(client, block_catastrophic_commands=False)
    queued = ask(client, "agent:helper", "operator", "run", {"command": "mkfs.ext4 /dev/sdz9"})
    assert queued["status"] == "pending_approval"
    set_guardrails(client, block_catastrophic_commands=True)
    assert client.post(f"/api/approvals/{queued['approval_id']}", json={"approve": True}).status_code == 200
    decided = wait_for(lambda: (a := next(x for x in client.get("/api/approvals").json()
                                          if x["id"] == queued["approval_id"]))["status"] != "approved" and a)
    assert decided["status"] == "failed" and "block_catastrophic_commands" in decided["result"]["error"]
    assert ran == [] and any(e["text"].startswith("Refused approved command from agent:helper") for e in activity(client))

    # an approved command the guardrail still allows runs as before
    queued = ask(client, "agent:helper", "operator", "run", {"command": COMMAND})
    client.post(f"/api/approvals/{queued['approval_id']}", json={"approve": True})
    wait_for(lambda: ran == [COMMAND])


def test_stopping_a_tool_follows_the_autonomy_level(client, wait_for):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    sleeper = f'"{sys.executable}" -c "import time; time.sleep(60)"'
    running = lambda: hub.processes.status("wazuh")["running"]  # noqa: E731
    client.patch("/api/settings", json={"autonomy": "manual"})
    watcher = client.post("/api/agents", json={"name": "Watcher", "team": "wazuh", "permissions": ["read", "commands"]}).json()
    ctx = hub.agents.get(watcher["id"]).context()
    try:
        assert client.portal.call(toolkit.execute, ctx, "stop_tool", {"tool_id": "wazuh"})["status"] == "not_running"
        client.portal.call(hub.processes.start, "wazuh", sleeper)
        queued = client.portal.call(toolkit.execute, ctx, "stop_tool", {"tool_id": "wazuh"})
        assert queued["status"] == "pending_approval" and running()
        approval = next(a for a in pending(client, "process") if a["id"] == queued["approval_id"])
        assert approval["title"] == "Stop Wazuh" and approval["payload"] == {
            "tool_id": "wazuh", "origin": watcher["id"], "action": "stop"}
        # core agents and API tokens follow the autonomy level too
        assert ask(client, "supervisor", "operator", "stop_tool", {"tool_id": "wazuh"})["status"] == "pending_approval"
        assert ask(client, "token:ci", "operator", "stop_tool", {"tool_id": "wazuh"})["status"] == "pending_approval"
        assert running()
        assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
        done = wait_for(lambda: (a := next(x for x in client.get("/api/approvals").json() if x["id"] == approval["id"]))["status"] == "done" and a)
        assert done["result"] == {"stopped": True}
        wait_for(lambda: not running())

        # without the team guardrail the team agent stops it at once; a person always does
        set_guardrails(client, team_actions_need_approval=False)
        client.portal.call(hub.processes.start, "wazuh", sleeper)
        assert client.portal.call(toolkit.execute, ctx, "stop_tool", {"tool_id": "wazuh"}) == {"status": "stopped", "stopped": True}
        wait_for(lambda: not running())
        client.portal.call(hub.processes.start, "wazuh", sleeper)
        assert client.post("/api/tools/wazuh/stop").json() == {"status": "stopped", "stopped": True}
        wait_for(lambda: not running())
    finally:
        client.portal.call(hub.processes.stop_all)


# -- the toolkit -----------------------------------------------------------------------------------


def test_toolkit_tools_are_filtered_by_permission_and_scoped_to_the_team_tool(client):
    hub = client.app.state.hub
    by_permission = {}
    for spec in toolkit.TOOLS.values():
        by_permission.setdefault(spec.permission, set()).add(spec.name)
    assert {"run_command", "start_tool"} <= by_permission["commands"] and "read_tool_records" in by_permission["tool_api"]
    names = {d["name"] for d in toolkit.definitions({"read"})}
    assert "list_tools" in names and not names & (by_permission["commands"] | by_permission["patches"])
    assert {d["name"] for d in toolkit.definitions(set(teams.PERMISSION_INFO))} == set(toolkit.TOOLS)
    assert all(d["strict"] and d["input_schema"]["required"] == list(d["input_schema"]["properties"])
               for d in toolkit.definitions(set(teams.PERMISSION_INFO)))

    add_tool(client, "wazuh", "Wazuh")
    add_tool(client, "grafana", "Grafana")
    record = client.post("/api/agents", json={"name": "Reader", "team": "wazuh", "permissions": ["read"]}).json()
    ctx = hub.agents.get(record["id"]).context()
    assert ctx.tool_scope == "wazuh" and ctx.permissions == frozenset({"read"})
    with pytest.raises(PermissionError, match="commands"):
        client.portal.call(toolkit.execute, ctx, "run_command", {"target": "local", "command": "echo", "reason": ""})
    with pytest.raises(PermissionError, match="wazuh team"):
        client.portal.call(toolkit.execute, ctx, "tool_health", {"tool_id": "grafana"})
    assert client.portal.call(toolkit.execute, ctx, "tool_health", {"tool_id": "wazuh"})["ok"] is None
    assert [t["id"] for t in client.portal.call(toolkit.execute, ctx, "list_tools", {})] == ["wazuh", "grafana"]


def test_supervisor_chat_offers_every_tool(client):
    fake = FakeLLM([SimpleNamespace(stop_reason="end_turn", content=[block("text", text="Hi.")])])
    client.app.state.hub.llm = fake
    assert client.post("/api/agents/supervisor/chat", json={"text": "hello"}).json() == {
        "reply": "Hi.", "mode": "llm", "agent_id": "supervisor"}
    assert {t["name"] for t in fake.calls[0]["tools"]} == set(toolkit.TOOLS)
    assert "run" in client.post("/api/agents/operator/chat", json={"text": "hi"}).json()["reply"].lower()
    assert client.post("/api/agents/nope/chat", json={"text": "hi"}).status_code == 404


# -- running team agents ---------------------------------------------------------------------------


def test_team_agent_on_claude_uses_its_tools_through_the_operator(client, wait_for):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    fake = FakeLLM([
        SimpleNamespace(stop_reason="tool_use", content=[
            block("tool_use", id="tu_1", name="run_command", input={"target": "local", "command": COMMAND, "reason": "check"}),
            block("tool_use", id="tu_2", name="request_code_patch", input={"tool_id": "wazuh", "goal": "x"})]),
        SimpleNamespace(stop_reason="end_turn", content=[block("text", text="Asked for approval.")]),
    ])
    hub.llm = fake
    record = client.post("/api/agents", json={"name": "Ops", "team": "wazuh", "provider": "anthropic",
                                               "permissions": ["read", "commands"], "instructions": "Be careful."}).json()
    assert record["provider_label"] == "Claude" and record["llm_active"] and record["model"] == "claude-opus-5-5"
    reply = client.post(f"/api/agents/{record['id']}/chat", json={"text": "check the box"}).json()
    assert reply == {"reply": "Asked for approval.", "mode": "llm", "agent_id": record["id"]}
    offered = {t["name"] for t in fake.calls[0]["tools"]}
    assert "run_command" in offered and "request_code_patch" not in offered and "Be careful." in fake.calls[0]["system"]
    results = {r["tool_use_id"]: r for r in fake.calls[1]["messages"][2]["content"]}
    assert json.loads(results["tu_1"]["content"])["status"] == "pending_approval"
    assert results["tu_2"]["is_error"] and "patches" in results["tu_2"]["content"]  # not its permission
    command = pending(client, "command")[0]
    assert command["payload"]["origin"] == record["id"]
    # a disabled agent does not chat or run
    client.patch(f"/api/agents/{record['id']}", json={"enabled": False})
    assert client.post(f"/api/agents/{record['id']}/chat", json={"text": "hi"}).status_code == 409
    assert client.post(f"/api/agents/{record['id']}/run").status_code == 409


def test_rules_agents_run_template_actions_and_say_when_a_task_needs_a_model(client):
    add_tool(client, "wazuh", "Wazuh")
    record = client.post("/api/agents", json={"name": "Watch", "team": "wazuh", "permissions": ["read"],
                                               "task": "Check the health of Wazuh and summarize its state."}).json()
    ran = client.post(f"/api/agents/{record['id']}/run").json()
    assert ran["ok"] and ran["mode"] == "rules" and ran["trigger"] == "manual"
    assert "Health of Wazuh" in ran["reply"] and "**Wazuh:**" in ran["reply"]
    assert agent(client, record["id"])["last_result"]["ok"]
    flows_reply = client.post(f"/api/agents/{record['id']}/run", json={"task": "Run the data flows"}).json()
    assert "lack the 'flows' permission" in flows_reply["reply"]
    needs_model = client.post(f"/api/agents/{record['id']}/chat", json={"text": "Write a poem about alerts"}).json()
    assert needs_model["mode"] == "rules" and "needs a language model" in needs_model["reply"]
    mixed = client.post(f"/api/agents/{record['id']}/chat", json={"text": "Triage alerts and report the state"}).json()
    assert "**Wazuh:**" in mixed["reply"] and "need a language model" in mixed["reply"]
    assert client.post("/api/agents/patcher/run").status_code == 400
    no_task = client.post("/api/agents", json={"name": "Idle", "team": "hub"}).json()
    assert client.post(f"/api/agents/{no_task['id']}/run").status_code == 400


# -- local models (OpenAI-compatible) ----------------------------------------------------------


class FakeLocalServer:
    """An Ollama-like /v1 API: lists models and answers with one tool call, then text."""

    def __init__(self):
        self.requests: list[tuple[str, str, dict, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.requests.append((request.method, request.url.path, dict(request.headers), body))
        if request.url.path == "/v1/models":
            return httpx.Response(200, json={"object": "list", "data": [{"id": "llama3.2:latest", "object": "model"},
                                                                         {"id": "qwen3:8b", "object": "model"}]})
        if request.url.path == "/v1/chat/completions":
            if body["model"] == "missing":
                return httpx.Response(404, json={"error": {"message": "model 'missing' not found"}})
            if not any(m["role"] == "tool" for m in body["messages"]):
                return httpx.Response(200, json={"choices": [{"finish_reason": "tool_calls", "message": {
                    "role": "assistant", "content": None, "tool_calls": [{"id": "call_1", "type": "function", "function": {
                        "name": "list_tools", "arguments": "{}"}}]}}]})
            tool_result = next(m for m in body["messages"] if m["role"] == "tool")
            names = [t["name"] for t in json.loads(tool_result["content"])]
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
                "role": "assistant", "content": f"The suite has: {', '.join(names)}."}}]})
        return httpx.Response(404, json={"error": "not found"})


def test_you_can_talk_to_an_agent_and_it_reports_to_the_supervisor(client):
    tool = add_tool(client, "flask", "Flask")
    tool.status = "error"
    tool.error = "connection refused"
    client.app.state.hub.save_tool(tool)
    reply = client.post("/api/agents/patcher/chat", json={"text": "patch the error on Flask"}).json()
    assert "Flask" in reply["reply"] and "1 patch" in reply["reply"]
    patches = client.get("/api/tools/flask").json()["patches"]
    repair = next(p for p in patches if p["strategy"] == "error_repair")
    assert "connection refused" in repair["rationale"]
    reports = [m for m in client.get("/api/messages?limit=100").json()
               if m["subject"] == "team.report" and m["recipient"] == "supervisor"]
    assert reports and reports[-1]["body"]["agent"] == "Patch Agent"
    status = client.post("/api/agents/module:assets/chat", json={"text": "status"}).json()
    assert "total" in status["reply"]
    idle = client.post("/api/agents/patcher/chat/stop").json()
    assert idle["ok"] is True and idle["stopped"] is False
    again = client.post("/api/agents/patcher/chat", json={"text": "help"}).json()
    assert again.get("cancelled") is not True and "Patch Agent" in again["reply"]
    early = client.post("/api/agents/operator/chat/stop", json={"client_id": "chat-early-1"}).json()
    assert early["stopped"] is True
    stopped = client.post("/api/agents/operator/chat", json={"text": "help", "client_id": "chat-early-1"}).json()
    assert stopped["cancelled"] is True and "Stopped" in stopped["reply"]
    nxt = client.post("/api/agents/operator/chat", json={"text": "help", "client_id": "chat-early-2"}).json()
    assert nxt.get("cancelled") is not True and "run" in nxt["reply"].lower()


def test_a_running_chat_can_be_stopped_and_restarted(client):
    import asyncio

    hub = client.app.state.hub
    agent = hub.agents.get("operator")
    started = asyncio.Event()
    release = asyncio.Event()
    original = agent.direct_chat

    async def slow(text, msg):
        started.set()
        await release.wait()
        return {"reply": "finished", "mode": "rules"}

    agent.direct_chat = slow

    async def run():
        chat = asyncio.create_task(hub.bus.request("user:admin", "operator", "chat", {"text": "wait please"}, 30))
        await asyncio.wait_for(started.wait(), 5)
        assert agent.cancel_chat() is True
        body = await asyncio.wait_for(chat, 5)
        assert body["cancelled"] is True and "Stopped" in body["reply"]
        reset = await hub.bus.request("user:admin", "operator", "chat.reset", {}, 10)
        assert reset["ok"] is True
        agent.direct_chat = original
        again = await hub.bus.request("user:admin", "operator", "chat", {"text": "help"}, 10)
        assert "run" in again["reply"].lower() and again.get("cancelled") is not True

    client.portal.call(run)


def test_stopping_a_command_kills_it_and_the_next_chat_still_runs(client):
    import asyncio
    import subprocess

    hub = client.app.state.hub

    async def run():
        chat = asyncio.create_task(hub.bus.request("user:admin", "operator", "chat", {"text": "run sleep 30"}, 20))
        await asyncio.sleep(0.5)
        assert hub.agents.get("operator").cancel_chat() is True
        body = await asyncio.wait_for(chat, 8)
        assert body["cancelled"] is True and "Stopped" in body["reply"]
        reset = await hub.bus.request("user:admin", "operator", "chat.reset", {}, 10)
        assert reset["ok"] is True
        again = await hub.bus.request("user:admin", "operator", "chat", {"text": "help"}, 10)
        assert "run" in again["reply"].lower() and again.get("cancelled") is not True

    client.portal.call(run)
    procs = subprocess.run(["ps", "-eo", "args"], check=False, capture_output=True, text=True).stdout
    assert not any(line.strip() == "sleep 30" for line in procs.splitlines())


def test_the_supervisor_asks_for_a_patch_when_a_tool_errors(client):
    tool = add_tool(client, "flask", "Flask")
    tool.status = "error"
    tool.error = "connection refused"
    client.app.state.hub.save_tool(tool)
    reply = client.post("/api/chat", json={"text": "flask has an error"}).json()
    assert reply["mode"] == "team"
    assert "Patch Agent" in reply["reply"] and "Flask Supervisor" in reply["reply"]
    patches = client.get("/api/tools/flask").json()["patches"]
    repair = next(p for p in patches if p["strategy"] == "error_repair")
    assert "connection refused" in repair["rationale"]
    direct = client.post("/api/agents/tool:flask/chat", json={"text": "fix the error"}).json()
    assert "Patch Agent" in direct["reply"]
    reports = [m for m in client.get("/api/messages?limit=100").json()
               if m["subject"] == "team.report" and m["body"].get("agent_id") == "tool:flask"]
    assert reports


def _health_script(path: Path) -> None:
    path.write_text(
        "import json, os\n"
        "from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        body = json.dumps({'status': 'ok'}).encode()\n"
        "        self.send_response(200)\n"
        "        self.send_header('Content-Type', 'application/json')\n"
        "        self.send_header('Content-Length', str(len(body)))\n"
        "        self.end_headers()\n"
        "        self.wfile.write(body)\n"
        "    def log_message(self, fmt, *args):\n"
        "        return\n"
        "ThreadingHTTPServer(('127.0.0.1', int(os.environ['PORT'])), Handler).serve_forever()\n",
        encoding="utf-8",
    )


def _down_tool(client, folder: Path, tool_id: str, name: str) -> Tool:
    import socket

    folder.mkdir(parents=True, exist_ok=True)
    script = folder / f"{tool_id}.py"
    _health_script(script)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    tool = add_tool(client, tool_id, name)
    tool.source_type = "local"
    tool.path = str(folder)
    tool.status = "error"
    tool.error = "connection refused"
    tool.manifest.kind = "oss"
    tool.manifest.launch.command = f'"{sys.executable}" "{script}"'
    tool.manifest.launch.port = port
    tool.manifest.launch.env = {"PORT": str(port)}
    tool.manifest.health.url = f"http://127.0.0.1:{port}/healthz"
    client.app.state.hub.save_tool(tool)
    return tool


def _stop(client, *tool_ids: str) -> None:
    hub = client.app.state.hub
    for tool_id in tool_ids:
        client.portal.call(hub.processes.stop, tool_id)


def test_a_down_tool_is_started_and_its_error_cleared(client, tmp_path):
    folder = tmp_path / "scripts"
    try:
        _down_tool(client, folder, "lamp", "Lamp")
        reply = client.post("/api/agents/patcher/chat", json={"text": "fix the error on Lamp"}).json()
        assert "fixed" in reply["reply"].lower()
        assert "no new patch" not in reply["reply"].lower()
        assert "waiting in approvals" not in reply["reply"].lower()
        saved = client.get("/api/tools/lamp").json()
        assert saved["error"] is None and saved["status"] == "ready"
        assert saved["health"]["ok"] is True and saved["process"]["running"] is True

        _down_tool(client, folder, "bell", "Bell")
        team = client.post("/api/chat", json={"text": "bell has an error"}).json()
        assert team["mode"] == "team" and "fixed" in team["reply"].lower()
        assert "Bell Supervisor" in team["reply"] and "Patch Agent" in team["reply"]
        saved = client.get("/api/tools/bell").json()
        assert saved["error"] is None and saved["status"] == "ready" and saved["health"]["ok"] is True
        again = client.post("/api/agents/patcher/chat", json={"text": "fix the error on Lamp"}).json()
        assert "no error to fix" in again["reply"].lower()
        assert "no new patch" not in again["reply"].lower()
    finally:
        _stop(client, "lamp", "bell")


def test_a_python_project_without_a_launch_command_is_started_without_editing_it(client, tmp_path):
    from hub.execution.policy import HUB_PRIVATE

    project = tmp_path / "project"
    package = project / "src" / "demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("VERSION = '1'\n", encoding="utf-8")
    (project / "pyproject.toml").write_text("[project]\nname = 'demo'\nversion = '0.0.1'\n", encoding="utf-8")
    before = sorted(path.relative_to(project).as_posix() for path in project.rglob("*") if path.is_file())
    tool = add_tool(client, "demo", "Demo")
    tool.source_type = "local"
    tool.path = str(project)
    tool.status = "error"
    tool.error = "connection refused"
    tool.manifest.kind = "oss"
    tool.manifest.stack = ["python"]
    client.app.state.hub.save_tool(tool)
    try:
        reply = client.post("/api/agents/patcher/chat", json={"text": "fix the error on Demo"}).json()
        assert "fixed" in reply["reply"].lower()
        assert "no new patch" not in reply["reply"].lower()
        assert "stand-in" in reply["reply"].lower()
        saved = client.get("/api/tools/demo").json()
        assert saved["error"] is None and saved["status"] == "ready" and saved["health"]["ok"] is True
        command = saved["manifest"]["launch"]["command"]
        assert HUB_PRIVATE.search(command) is None
        assert str(project) not in command
        after = sorted(path.relative_to(project).as_posix() for path in project.rglob("*") if path.is_file())
        assert after == before
    finally:
        _stop(client, "demo")


def test_the_supervisor_hands_a_fix_to_the_patch_agent(client):
    tool = add_tool(client, "flask", "Flask")
    tool.status = "needs_patch"
    client.app.state.hub.save_tool(tool)
    reply = client.post("/api/chat", json={"text": "fix bugs"}).json()
    assert reply["mode"] == "team"
    assert "Patch Agent" in reply["reply"] and "Flask" in reply["reply"]
    assert "Flask Supervisor" in reply["reply"]
    assert reply["delegated"] == ["tool:flask", "patcher:flask"]
    supervisor = agent(client, "supervisor")
    assert supervisor["provider_label"] == "Rules" and supervisor["model"] == ""


def test_the_supervisor_plans_a_cycle_with_the_selected_model(client):
    hub = client.app.state.hub
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/v1/chat/completions":
            return httpx.Response(200, json={"object": "list", "data": [{"id": "gpt-5.6-terra"}, {"id": "gpt-3.5-turbo"}]})
        body = json.loads(request.content)
        seen.append(body)
        system = body["messages"][0]["content"]
        if "Reply with JSON only" in system and body["model"] == "gpt-3.5-turbo":
            return httpx.Response(404, json={"error": {"message": "model not found"}})
        if "Reply with JSON only" in system:
            facts = json.loads(body["messages"][-1]["content"])
            items = [{"id": item["id"], "priority": 1 if item["id"] == "grc" else 2,
                      "goal": "Cycle goal for " + item["id"]} for item in facts["work"]]
            content = json.dumps({"items": items})
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": content}}]})
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": "From ChatGPT."}}]})

    hub.llm_transport = httpx.MockTransport(handler)
    client.post("/api/llm/providers", json={"preset": "chatgpt", "name": "ChatGPT", "api_key": "sk-test"})
    saved = client.patch("/api/settings", json={"model_provider": "chatgpt", "model": "gpt-3.5-turbo",
                                                "autonomy": "autonomous"}).json()
    assert saved["model_provider"] == "chatgpt" and saved["model"] == "gpt-3.5-turbo"

    hello = client.post("/api/chat", json={"text": "hello there"}).json()
    assert hello["mode"] == "local" and hello["reply"] == "From ChatGPT."
    assert not hello.get("steps")

    tool = add_tool(client, "flask", "Flask")
    tool.status = "error"
    tool.error = "connection refused"
    hub.save_tool(tool)
    repair = client.post("/api/chat", json={"text": "flask has an error"}).json()
    assert repair["mode"] == "local"
    assert repair["delegated"] == ["tool:flask", "patcher:flask"]
    assert "Nothing is waiting" not in repair["reply"]
    assert "Cycle goal for health:flask" in repair["reply"] and "Cycle goal for repair:flask" in repair["reply"]
    assert "Dispatching 2 work item(s)" in repair["reply"]
    assert "Supervisor hands off to Flask Supervisor" in repair["reply"]
    assert "Supervisor hands off to Patch Agent" in repair["reply"]
    assert any(step.get("handoff") and step["text"] == "Supervisor hands off to Patch Agent" for step in repair["steps"])
    assert any(step["who"] == "Patch Agent" for step in repair["steps"])
    patches = client.get("/api/tools/flask").json()["patches"]
    filed = next(p for p in patches if p["strategy"] == "error_repair")
    assert "connection refused" in filed["rationale"]
    assert not [t for t in client.get("/api/agents/teams").json()["teams"] if t["team"] == "flask" and t["size"]]

    cycle = client.post("/api/chat", json={
        "text": "Plan this maintenance cycle. Assemble an AI team for the installed software."}).json()
    assert cycle["mode"] == "local"
    assert "Nothing is waiting" not in cycle["reply"]
    assert "Cycle goal for grc" in cycle["reply"] and "Cycle goal for team:flask" in cycle["reply"]
    assert "Dispatching 3 work item(s)" in cycle["reply"]
    assert "Supervisor hands off to GRC Supervisor" in cycle["reply"]
    assert any(step["who"] == "GRC Supervisor" and "Frameworks:" in step["text"] for step in cycle["steps"])
    assert any(step["who"] == "Flask Supervisor" and "Created" in step["text"] for step in cycle["steps"])
    flask_team = next(t for t in client.get("/api/agents/teams").json()["teams"] if t["team"] == "flask")
    assert flask_team["size"] == 1 and flask_team["members"][0]["title"] == "Maintainer"

    plan_calls = [body for body in seen if "Reply with JSON only" in body["messages"][0]["content"]]
    assert [body["model"] for body in plan_calls] == ["gpt-3.5-turbo", "gpt-5.6-terra", "gpt-3.5-turbo", "gpt-5.6-terra"]
    assert all("tools" not in body for body in plan_calls)
    assert seen[0]["model"] == "gpt-3.5-turbo" and seen[0]["messages"][-1]["content"] == "hello there"


def test_a_cycle_repairs_a_down_tool_and_not_a_healthy_gap(client):
    from hub.agents.cycle import _catalog
    from hub.models import Check, CompatibilityReport

    gap = add_tool(client, "flask", "Flask")
    gap.status = "ready"
    gap.report = CompatibilityReport(score=50, level="patchable", checks=[
        Check(id="sso", title="Single sign-on", status="fail", fix="sso_proxy")])
    client.app.state.hub.save_tool(gap)
    down = add_tool(client, "bell", "Bell")
    down.status = "error"
    down.error = "connection refused"
    client.app.state.hub.save_tool(down)
    items, _left = _catalog(client.app.state.hub.agents.get("supervisor"),
                            "Fix all the issues if needed and assemble an AI team for the installed software.")
    kinds = {(item["kind"], item.get("tool_id")) for item in items}
    assert ("repair", "bell") in kinds and ("health", "bell") in kinds
    assert ("repair", "flask") not in kinds and ("health", "flask") not in kinds
    assert ("team", "flask") in kinds
    assert any(item["kind"] == "grc" for item in items)


def test_chatgpt_and_grok_presets(client):
    view = client.get("/api/llm/providers").json()
    presets = {p["id"]: p for p in view["presets"]}
    assert presets["chatgpt"]["base_url"] == "https://api.openai.com/v1"
    assert presets["chatgpt"]["default_model"] == "gpt-5.6-terra" and presets["chatgpt"]["requires_key"]
    assert presets["grok"]["base_url"] == "https://api.x.ai/v1" and presets["grok"]["default_model"] == "grok-4.7"

    missing = client.post("/api/llm/providers", json={"preset": "chatgpt", "name": "ChatGPT"})
    assert missing.status_code == 400 and "API key" in missing.json()["detail"]
    assert client.post("/api/llm/providers", json={"preset": "nope", "name": "Nope", "api_key": "x"}).status_code == 400

    created = client.post("/api/llm/providers", json={"preset": "chatgpt", "name": "ChatGPT", "api_key": "sk-test"})
    assert created.status_code == 201, created.text
    chatgpt = created.json()
    assert chatgpt["id"] == "chatgpt" and chatgpt["name"] == "ChatGPT" and chatgpt["preset"] == "chatgpt"
    assert chatgpt["base_url"] == "https://api.openai.com/v1" and chatgpt["default_model"] == "gpt-5.6-terra"
    assert chatgpt["api_key_set"] and "api_key" not in chatgpt and "sk-test" not in json.dumps(chatgpt)
    grok = client.post("/api/llm/providers", json={"preset": "grok", "name": "Grok", "api_key": "xai-test",
                                                   "default_model": ""}).json()
    assert grok["id"] == "grok" and grok["base_url"] == "https://api.x.ai/v1" and grok["default_model"] == "grok-4.7"
    again = client.post("/api/llm/providers", json={"preset": "chatgpt", "name": "ChatGPT", "api_key": "sk-other"})
    assert again.status_code == 201 and again.json()["id"] == "chatgpt-2"

    choices = {c["id"]: c for c in client.get("/api/llm/providers").json()["choices"]}
    assert choices["chatgpt"]["kind"] == "hosted" and choices["grok"]["kind"] == "hosted"
    record = client.post("/api/agents", json={"name": "Writer", "provider": "chatgpt", "model": "gpt-4o"}).json()
    assert record["provider_label"] == "ChatGPT" and record["provider_kind"] == "local" and record["model"] == "gpt-4o"


def test_the_default_model_can_be_chatgpt_grok_or_a_local_server(client):
    hub = client.app.state.hub
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/chat/completions":
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {"content": "From Grok."}}]})
        return httpx.Response(200, json={"object": "list", "data": [{"id": "grok-4.7"}]})

    hub.llm_transport = httpx.MockTransport(handler)
    assert client.patch("/api/settings", json={"model_provider": "grok", "model": "grok-4.7"}).status_code == 400
    client.post("/api/llm/providers", json={"preset": "grok", "name": "Grok", "api_key": "xai-test"})
    saved = client.patch("/api/settings", json={"model_provider": "grok", "model": "grok-4.7"}).json()
    assert saved["model_provider"] == "grok" and saved["model"] == "grok-4.7"
    assert client.patch("/api/settings", json={"model_provider": "anthropic", "model": " "}).status_code == 400

    record = client.post("/api/agents", json={"name": "Defaulted"}).json()
    assert record["provider"] == "grok" and record["model"] == "grok-4.7"
    reply = client.post("/api/chat", json={"text": "hello there"}).json()
    assert reply["mode"] == "local" and reply["reply"] == "From Grok."
    assert seen[-1]["model"] == "grok-4.7" and seen[-1]["messages"][1]["content"] == "hello there"

    client.post("/api/llm/providers", json={"name": "Ollama", "base_url": "http://localhost:11434/v1",
                                            "default_model": "qwen3:8b"})
    local = client.patch("/api/settings", json={"model_provider": "ollama", "model": "qwen3:8b"}).json()
    assert local["model_provider"] == "ollama"
    assert client.post("/api/agents", json={"name": "On box"}).json()["provider"] == "ollama"


def test_local_provider_and_the_openai_compatible_tool_loop(client, sign_in):
    hub = client.app.state.hub
    server = FakeLocalServer()
    hub.llm_transport = httpx.MockTransport(server)
    add_tool(client, "wazuh", "Wazuh")

    assert sign_in("operator").post("/api/llm/providers", json={"name": "Ollama"}).status_code == 403
    created = client.post("/api/llm/providers", json={"name": "Ollama", "api_key": KEY})
    assert created.status_code == 201, created.text
    provider = created.json()
    assert provider["id"] == "ollama" and provider["base_url"] == "http://localhost:11434/v1" and provider["api_key_set"]
    assert "api_key" not in provider and KEY not in json.dumps(provider)
    stored = hub.store.get("llm_providers", "ollama")["api_key"]
    assert stored != KEY and hub.secrets.decrypt(stored) == KEY

    tested = client.post("/api/llm/providers/ollama/test").json()
    assert tested["ok"] and tested["models"] == ["llama3.2:latest", "qwen3:8b"]
    assert server.requests[-1][2]["authorization"] == f"Bearer {KEY}"
    client.patch("/api/llm/providers/ollama", json={"default_model": "qwen3:8b"})
    choices = {c["id"]: c for c in client.get("/api/llm/providers").json()["choices"]}
    assert choices["ollama"]["kind"] == "local" and choices["ollama"]["available"] and choices["ollama"]["models"]

    record = client.post("/api/agents", json={"name": "Local", "team": "wazuh", "provider": "ollama",
                                               "permissions": ["read"]}).json()
    assert record["provider_label"] == "Ollama" and record["provider_kind"] == "local" and record["model"] == "qwen3:8b"
    reply = client.post(f"/api/agents/{record['id']}/chat", json={"text": "What tools are there?"}).json()
    assert reply == {"reply": "The suite has: Wazuh.", "mode": "local", "agent_id": record["id"]}
    calls = [r for r in server.requests if r[1] == "/v1/chat/completions"]
    first, second = calls[0][3], calls[1][3]
    assert first["model"] == "qwen3:8b" and first["messages"][0]["role"] == "system" and "tool_choice" not in first
    offered = {t["function"]["name"] for t in first["tools"]}
    assert "list_tools" in offered and "run_command" not in offered and first["tools"][0]["type"] == "function"
    assert [m["role"] for m in second["messages"]] == ["system", "user", "assistant", "tool"]
    assert second["messages"][2]["tool_calls"][0]["id"] == "call_1" and second["messages"][3]["tool_call_id"] == "call_1"

    # the conversation continues; a provider error is shown without the key
    client.patch(f"/api/agents/{record['id']}", json={"model": "missing"})
    failed = client.post(f"/api/agents/{record['id']}/chat", json={"text": "again"})
    assert failed.status_code == 400 and "HTTP 404" in failed.json()["detail"] and "missing" in failed.json()["detail"]

    # the key only goes to the address it was entered for
    moved = client.patch("/api/llm/providers/ollama", json={"base_url": "http://gpu-box.lan:11434/v1"})
    assert moved.status_code == 400 and "again" in moved.json()["detail"]
    assert client.patch("/api/llm/providers/ollama", json={"base_url": "ftp://x"}).status_code == 400
    assert client.delete("/api/llm/providers/ollama").status_code == 409  # still used by an agent
    exposed = [client.get(p).text for p in ("/api/llm/providers", "/api/agents", "/api/agents/teams", "/api/settings",
                                            "/api/messages?limit=2000", "/api/activity?limit=2000", "/api/approvals")]
    assert all(KEY not in text for text in exposed)
    assert KEY.encode() not in Path(hub.settings.db_path).read_bytes()
    client.delete(f"/api/agents/{record['id']}")
    assert client.delete("/api/llm/providers/ollama").json() == {"ok": True}


def test_local_providers_without_tool_calling(client):
    hub = client.app.state.hub
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"choices": [{"finish_reason": "length", "message": {"content": "Partial"}}]})

    hub.llm_transport = httpx.MockTransport(handler)
    client.post("/api/llm/providers", json={"name": "LM Studio", "base_url": "http://localhost:1234/v1/",
                                            "tools": False, "default_model": "m"})
    record = client.post("/api/agents", json={"name": "Plain", "provider": "lm-studio"}).json()
    reply = client.post(f"/api/agents/{record['id']}/chat", json={"text": "hi"}).json()
    assert reply["reply"].startswith("Partial") and "cut off" in reply["reply"] and "tools" not in seen[0]


# -- team proposals --------------------------------------------------------------------------------


def test_tool_supervisor_proposes_a_team_from_templates_and_approval_creates_it(client, wait_for, sign_in):
    add_tool(client, "wazuh", "Wazuh")
    assert sign_in("viewer").post("/api/tools/wazuh/team").status_code == 403
    operator = sign_in("operator")
    proposal = operator.post("/api/tools/wazuh/team").json()
    assert proposal["proposed"] and proposal["designer"] == "templates" and proposal["category"] == "siem"
    approval = next(a for a in pending(client, "agent_team") if a["id"] == proposal["approval_id"])
    assert approval["requested_by"] == "tool:wazuh" and approval["payload"]["team"] == "wazuh"
    members = {m["title"]: m for m in approval["payload"]["members"]}
    assert set(members) == {"Alert triage analyst", "Health watcher", "Maintainer"}
    assert members["Health watcher"]["permissions"] == ["read", "commands"] and members["Health watcher"]["schedule_minutes"] == 15
    assert members["Alert triage analyst"]["provider"] == "rules" and members["Alert triage analyst"]["schedule_minutes"] == 0
    assert "Alert triage analyst for Wazuh" in approval["detail"]
    again = client.post("/api/tools/wazuh/team").json()
    assert not again["proposed"] and again["approval_id"] == approval["id"]  # one proposal at a time
    assert client.get("/api/agents/teams").json()["teams"][1]["pending_approval"] == approval["id"]

    # operators may ask for a team, but approving it creates agent definitions: only administrators decide it
    refused = operator.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    assert refused.status_code == 403 and "administrators" in refused.json()["detail"]
    assert operator.post(f"/api/approvals/{approval['id']}", json={"approve": False}).status_code == 403
    assert pending(client, "agent_team")[0]["id"] == approval["id"] and not teams.defs(client.app.state.hub)
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    done = wait_for(lambda: (a := next(x for x in client.get("/api/approvals").json() if x["id"] == approval["id"]))["status"] == "done" and a)
    assert sorted(done["result"]["created"]) == ["agent:wazuh-alert-triage", "agent:wazuh-health-watcher", "agent:wazuh-maintainer"]
    watcher = agent(client, "agent:wazuh-health-watcher")
    assert (watcher["team"], watcher["parent"], watcher["depth"], watcher["created_by"]) == ("wazuh", "tool:wazuh", 1, "tool:wazuh")
    assert watcher["template"] == "siem:health-watcher"
    nothing = client.post("/api/tools/wazuh/team").json()
    assert not nothing["proposed"] and {s["reason"] for s in nothing["skipped"]} == {"already in the team"}

    # removing the tool removes its team
    client.delete("/api/tools/wazuh")
    assert not [a for a in client.get("/api/agents").json() if a.get("team") == "wazuh"]
    assert not teams.defs(client.app.state.hub)


def test_team_proposals_follow_the_guardrails(client, wait_for):
    add_tool(client, "openvas", "Greenbone", provides=["vuln.scanner"])
    add_tool(client, "ciso", "CISO Assistant", provides=["grc.compliance"])
    set_guardrails(client, max_team_size=1)
    proposal = client.post("/api/tools/ciso/team", json={"designer": "templates"}).json()
    assert [m["title"] for m in proposal["members"]] == ["Compliance analyst"]
    assert [s["reason"] for s in proposal["skipped"]] == ["team size limit (guardrail max_team_size)"] * 2

    # without the approval guardrail, the team is created straight away
    set_guardrails(client, team_requires_approval=False, max_team_size=5)
    created = client.post("/api/tools/openvas/team").json()
    assert created["approval_id"] is None and sorted(created["created"]) == ["agent:openvas-maintainer", "agent:openvas-vuln-triage"]
    assert agent(client, "agent:openvas-vuln-triage")["effective_permissions"] == ["read", "flows", "grc_write"]
    assert client.post("/api/tools/openvas/team", json={"designer": "claude"}).status_code == 400  # needs Claude
    assert client.post("/api/tools/nope/team").status_code == 404


def test_a_paused_tool_supervisor_is_not_asked_for_a_team(client):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    asker = client.post("/api/agents", json={"name": "Asker", "team": "hub", "permissions": ["read", "agents"]}).json()
    assert client.patch("/api/agents/tool:wazuh", json={"paused": True}).status_code == 200
    started = time.monotonic()
    refused = client.post("/api/tools/wazuh/team")
    assert refused.status_code == 409 and "paused" in refused.json()["detail"]
    with pytest.raises(RuntimeError, match="paused"):  # a team agent's request fails at once too
        client.portal.call(toolkit.execute, hub.agents.get(asker["id"]).context(), "propose_team", {"tool_id": "wazuh"})
    assert time.monotonic() - started < 10 and not pending(client, "agent_team")
    client.patch("/api/agents/tool:wazuh", json={"paused": False})
    assert client.post("/api/tools/wazuh/team").json()["proposed"]


def test_validation_errors_never_echo_what_was_sent(client):
    refused = client.post("/api/llm/providers", json={"api_key": KEY, "timeout": 1})
    assert refused.status_code == 422 and KEY not in refused.text
    detail = refused.json()["detail"]
    assert {tuple(d["loc"]) for d in detail} == {("body", "name"), ("body", "timeout")}
    assert all(set(d) == {"loc", "msg", "type"} and d["msg"] for d in detail)
    add_tool(client, "wazuh", "Wazuh")
    for response in (client.put("/api/tools/wazuh/connection", json={"config": {}, "secrets": {"token": KEY}}),
                     client.patch("/api/llm/providers/nope", json={"api_key": KEY, "timeout": "soon"})):
        assert response.status_code == 422 and KEY not in response.text


def test_a_team_agent_cannot_get_a_stronger_team_through_its_lead(client):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    asker = client.post("/api/agents", json={"name": "Asker", "team": "hub", "permissions": ["read", "agents"]}).json()
    ctx = hub.agents.get(asker["id"]).context()
    result = client.portal.call(toolkit.execute, ctx, "propose_team", {"tool_id": "wazuh"})
    approval = next(a for a in pending(client, "agent_team") if a["id"] == result["approval_id"])
    assert approval["requested_by"] == "tool:wazuh" and approval["payload"]["on_behalf_of"] == asker["id"]
    members = {m["title"]: m for m in approval["payload"]["members"]}
    assert members["Health watcher"]["permissions"] == ["read"] and members["Health watcher"]["clamped"] == ["commands"]
    assert all(set(m["permissions"]) <= {"read", "agents"} for m in members.values())
    assert "Requested by Asker" in approval["detail"]

    # with the guardrail off, the lead's templates apply as they are
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    set_guardrails(client, limit_to_parent_permissions=False)
    add_tool(client, "grafana", "Grafana", provides=["monitoring.dashboards"])
    again = client.portal.call(toolkit.execute, ctx, "propose_team", {"tool_id": "grafana"})
    watcher = next(m for m in again["members"] if m["title"] == "Health watcher")
    assert watcher["permissions"] == ["read", "commands"] and watcher["clamped"] == []


def test_claude_designs_a_team_when_available(client):
    hub = client.app.state.hub
    add_tool(client, "netbox", "NetBox")
    hub.llm = FakeLLM(json_result={"rationale": "NetBox is the source of truth for the network.", "members": [
        {"role": "ipam-auditor", "title": "IPAM auditor", "description": "Audits address assignments.",
         "instructions": "You audit IPAM.", "permissions": ["read", "tool_api", "commands"], "schedule_minutes": 2,
         "task": "Audit the IP address plan."},
        {"role": "maintainer", "title": "Maintainer", "description": "", "instructions": "", "permissions": ["read"],
         "schedule_minutes": 0, "task": ""}]})
    proposal = client.post("/api/tools/netbox/team").json()
    assert proposal["designer"] == "claude" and proposal["category"] == "inventory"
    auditor = proposal["members"][0]
    assert auditor["id"] == "agent:netbox-ipam-auditor" and auditor["schedule_minutes"] == 5 and auditor["provider"] == "anthropic"
    approval = next(a for a in pending(client, "agent_team") if a["id"] == proposal["approval_id"])
    assert approval["payload"]["designer"] == "claude" and approval["detail"].startswith("NetBox is the source of truth")
    # an unusable answer falls back to the templates
    hub.llm = FakeLLM(json_result={"rationale": "", "members": []})
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    fallback = client.post("/api/tools/netbox/team").json()
    assert fallback["designer"] == "templates" and [m["title"] for m in fallback["members"]] == ["Inventory reconciler", "Maintainer"]


def test_known_complex_tools_get_a_team_proposal_once(client, wait_for):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    ask(client, "user:admin", "supervisor", "tool.imported", {"tool_id": "wazuh"})
    [approval] = wait_for(lambda: pending(client, "agent_team"))
    assert approval["payload"]["team"] == "wazuh" and approval["payload"]["designer"] == "templates"
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    ask(client, "user:admin", "supervisor", "tool.imported", {"tool_id": "wazuh"})
    result = ask(client, "supervisor", "tool:wazuh", "team.propose", {"auto": True})
    assert not result["proposed"] and not pending(client, "agent_team")  # a rejected proposal is not repeated
    add_tool(client, "notes", "Notes")
    ask(client, "user:admin", "supervisor", "tool.imported", {"tool_id": "notes"})
    assert teams.classify(hub, hub.get_tool("notes")) is None and not pending(client, "agent_team")


def test_a_connected_tool_gets_a_team_proposal_and_autonomous_hubs_create_it(client, wait_for):
    add_tool(client, "nas", "NAS Manager")
    mapping = {"assets": {"list": {"path": "/hosts"}, "fields": {"external_id": "id", "name": "hostname"}}}
    saved = client.put("/api/tools/nas/connection", json={"kind": "generic_rest", "config": {
        "base_url": "https://nas.example.com/api", "auth": "bearer", "mapping": mapping}, "secrets": {"token": "t0ken-xyz"}})
    assert saved.status_code == 200, saved.text
    [approval] = wait_for(lambda: pending(client, "agent_team"))
    assert [m["title"] for m in approval["payload"]["members"]] == ["Maintainer"]  # no specialised template fits
    client.post("/api/flows/plan")  # planning flows does not propose a second team
    assert len([a for a in client.get("/api/approvals").json() if a["kind"] == "agent_team"]) == 1

    client.patch("/api/settings", json={"autonomy": "autonomous"})
    add_tool(client, "grafana", "Grafana")
    result = ask(client, "supervisor", "tool:grafana", "team.propose", {"auto": True})
    assert result["approval_id"] is None and sorted(result["created"]) == [
        "agent:grafana-alert-triage", "agent:grafana-health-watcher", "agent:grafana-maintainer"]
    assert any(e["text"].startswith("Created 3 agent(s) in the Grafana team") for e in activity(client))


# -- the scheduler ------------------------------------------------------------------------------------


def test_scheduler_due_logic():
    now = time.time()
    defn = AgentDef(id="agent:x", name="X", schedule_minutes=10, task="Check health", created_at=now - 300)
    assert teams.next_run(defn) == pytest.approx(now + 300) and not teams.is_due(defn, now)
    assert teams.is_due(defn, now + 301)
    assert not teams.is_due(defn.model_copy(update={"running": now}), now + 301)  # already running
    assert teams.is_due(defn.model_copy(update={"running": now - 3600}), now + 301)  # a stale marker
    assert teams.is_due(defn.model_copy(update={"last_run": now - 601}), now)
    for off in ({"enabled": False}, {"schedule_minutes": 0}, {"task": " "}):
        assert teams.next_run(defn.model_copy(update=off)) is None
    with pytest.raises(ValueError):
        AgentDef(id="agent:x", name="X", schedule_minutes=4)
    with pytest.raises(ValueError):
        AgentDef(id="not-an-agent", name="X")


def test_scheduler_runs_due_agents(client, wait_for):
    hub = client.app.state.hub
    add_tool(client, "wazuh", "Wazuh")
    due = client.post("/api/agents", json={"name": "Watch", "team": "wazuh", "schedule_minutes": 5,
                                            "task": "Check the health of Wazuh."}).json()
    client.post("/api/agents", json={"name": "Off", "team": "wazuh", "schedule_minutes": 5, "task": "Check health.",
                                     "enabled": False})
    assert client.portal.call(hub.tick_agents) == []  # not due yet
    assert client.portal.call(hub.tick_agents, time.time() + 301) == [due["id"]]
    result = wait_for(lambda: agent(client, due["id"])["last_result"])
    assert result["ok"] and result["trigger"] == "schedule" and "Health of Wazuh" in result["reply"]
    assert agent(client, due["id"])["running"] is None
    assert client.portal.call(hub.tick_agents) == []  # the next run is a schedule interval after this one
    assert client.portal.call(hub.tick_agents, time.time() + 301) == [due["id"]]
    wait_for(lambda: agent(client, due["id"])["last_result"]["at"] > result["at"])
