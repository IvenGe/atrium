"""The subsidiaries' hard rules (round4-spec 7.4), checked with the hub as permissive as it gets - autonomy
"autonomous" and team_actions_need_approval off: sidecar staff are clamped to read, tool_actions and patches, their
hub-side requests always wait for a person, the hub-request relay reaches only the allowed tools of their own tool,
and their placement changes only through a charter. No tool, model or network is used."""

from __future__ import annotations

from pathlib import Path

import pytest
from llm_fakes import submits, use_claude
from subsidiary_support import TOOL, activate, local_model, relayed_run, staff_ids

from hub import guardrails
from hub.agents import teams
from hub.models import AGENT_PERMISSIONS, AgentDef
from hub.subsidiary import governance


@pytest.fixture
def permissive(client):
    client.app.state.hub.prefs["autonomy"] = "autonomous"
    assert client.patch("/api/settings/guardrails", json={"team_actions_need_approval": False}).status_code == 200
    return client


def hub_request(sidecar, run_id: str, agent_id: str, tool: str, args: dict | None = None):
    return sidecar.post("hub-request", {"run_id": run_id, "agent_id": agent_id, "tool": tool, "args": args or {}})


def test_sidecar_staff_are_clamped_and_always_wait_for_a_person(permissive, tmp_path, wait_for, sign_in):
    client = permissive
    local_model(client)
    activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = teams.get_def(hub, staff_ids(hub)["clerk"])
    everything = clerk.model_copy(update={"permissions": list(AGENT_PERMISSIONS)})
    assert teams.effective_permissions(hub, everything) == ["read", "patches", "tool_actions"]
    for dropped in ("commands", "agents", "flows", "assets_write", "grc_write", "tool_api"):
        assert dropped not in teams.effective_permissions(hub, everything)
    assert guardrails.effective_autonomy(hub, clerk.id) == "manual"
    hub_member = AgentDef(id="agent:plain", name="Plain", team=TOOL, parent=f"tool:{TOOL}")
    hub.store.put("agent_defs", hub_member.model_dump(mode="json"))
    assert guardrails.effective_autonomy(hub, "agent:plain") == "autonomous"  # an ordinary team agent: as asked
    # sidecar placement comes only from a charter: not created directly, not moved, not changed back
    with pytest.raises(ValueError, match="charter"):
        teams.create(hub, {"name": "Sneaky", "team": TOOL, "placement": "sidecar"}, "admin")
    with pytest.raises(ValueError, match="charter"):
        teams.update(hub, clerk.id, {"team": "hub"}, "admin")
    with pytest.raises(ValueError, match="placement"):
        teams.update(hub, clerk.id, {"placement": "hub"}, "admin")
    moved = client.patch(f"/api/agents/{clerk.id}", json={"team": "hub"})
    assert moved.status_code in (400, 409, 422) and teams.get_def(hub, clerk.id).team == TOOL
    # the subsidiary roles are offered for a charter only, never for an ordinary team
    assert "Front desk" not in [r.title for r in teams.roles_for("siem", hub)]
    assert "tool_actions" in teams.PERMISSION_INFO


def test_the_hub_request_relay_reaches_only_the_allowed_tools_of_the_own_tool(permissive, tmp_path, wait_for,
                                                                             sign_in):
    client = permissive
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    hub.store.put("tools", {"id": "crm", "name": "CRM", "source_type": "saas", "source": "https://crm.example.com"})
    staff = staff_ids(hub)
    clerk = staff["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    for tool in ("run_command", "run_flow", "request_scan", "create_team_member", "list_approvals", "list_tools",
                 "propose_patches"):  # not in the clerk's scope (or never reachable)
        answer = hub_request(sidecar, run_id, clerk, tool, {"command": "id", "tool_id": TOOL})
        assert answer.status_code == 200 and answer.json() == {
            "ok": False, "result": None, "error": f"{tool} is not one of your hub tools"}, tool
    other = hub_request(sidecar, run_id, clerk, "get_tool", {"tool_id": "crm"}).json()
    assert other["ok"] is False and "Helpdesk only" in other["error"]
    own = hub_request(sidecar, run_id, clerk, "get_tool").json()
    assert own["ok"] and own["result"]["tool"]["id"] == TOOL  # forced to the team's own tool
    # a panel run has no hub tools at all
    panel = sidecar.post("runs", {"question_id": "q_1", "agent_id": staff["desk"]}).json()["run_id"]
    assert hub_request(sidecar, panel, staff["desk"], "get_tool").json()["error"].startswith("a question asked")


def test_a_staff_code_patch_request_still_waits_for_approval(permissive, tmp_path, wait_for, sign_in, plain_repo: Path,
                                                             monkeypatch):
    client = permissive
    provider, _ = local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    # the charter gains a developer that may ask for code patches (widening: an administrator approves it)
    sub = governance.of_tool(hub, TOOL)
    staff = {k: v.model_dump() for k, v in sub.charter.staff.items()}
    staff["agent:helpdesk-dev"] = {"actions": [], "hub_tools": ["request_code_patch"]}
    member = {"id": "agent:helpdesk-dev", "name": "Developer", "title": "Developer", "provider": provider,
              "permissions": ["read", "tool_actions", "patches", "commands"], "instructions": "Fix small bugs."}
    amended = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"staff": staff, "members": [member]}).json()
    assert amended["widening"] == ["staff member agent:helpdesk-dev added"]
    assert ada.post(f"/api/approvals/{amended['approval_id']}", json={"approve": True}).status_code == 200
    dev = wait_for(lambda: teams.get_def(hub, "agent:helpdesk-dev"))
    assert dev.permissions == ["read", "patches", "tool_actions"] and dev.placement == "sidecar"  # commands dropped
    # the tool's source is the plain repository; the Patch Agent writes the patch with a (fake) model
    tool = hub.get_tool(TOOL)
    hub.store.put("tools", {**tool.model_dump(mode="json"), "path": str(plain_repo)})
    new_app = (plain_repo / "app.py").read_text() + "\n\n@app.get('/healthz')\ndef healthz():\n    return 'ok'\n"
    use_claude(hub, monkeypatch, submits({"title": "Add /healthz", "rationale": "Health checks.",  # read-before-write
                                          "health_path": "/healthz", "changes": [{"path": "app.py", "content": new_app}]}))
    sidecar.heartbeat()
    run_id = relayed_run(client, sidecar, dev.id, "Add a health route")
    answer = hub_request(sidecar, run_id, dev.id, "request_code_patch", {"goal": "Add a health route"}).json()
    assert answer["ok"], answer
    patch = wait_for(lambda: next((p for p in hub.patches(TOOL) if p.strategy == "custom"), None))
    assert patch.status == "proposed"  # autonomous, yet never applied: the staff's requests wait for a person
    pending = [a for a in hub.approvals.list("pending") if a.kind == "patch"]
    assert len(pending) == 1 and "/healthz" not in (plain_repo / "app.py").read_text()
    assert governance.usage_day(hub, sub.id, clock()).approval_requests >= 1
