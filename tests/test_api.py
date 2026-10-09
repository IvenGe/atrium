"""End-to-end: the API, the agents talking on the bus, approvals and the modules."""

import sys
from pathlib import Path


def test_mutations_need_the_hub_header(client):
    response = client.post("/api/commands", json={"command": "echo hi"}, headers={"X-Hub-Request": ""})
    assert response.status_code == 403


def test_unknown_host_header_is_rejected(client):
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400


def test_core_agents_are_running(client):
    agents = {a["id"]: a for a in client.get("/api/agents").json()}
    assert {"supervisor", "patcher", "operator", "module:assets", "module:grc"} <= set(agents)
    assert all(a["status"] in ("idle", "working") for a in agents.values())


def test_import_local_project_end_to_end(client, wait_for, plain_repo: Path):
    response = client.post("/api/tools/import", json={"source_type": "local", "source": str(plain_repo)})
    assert response.status_code == 202
    tool_id = response.json()["id"]

    tool = wait_for(lambda: (t := client.get(f"/api/tools/{tool_id}").json())["status"] in ("ready", "needs_patch") and t["report"] and t)
    assert tool["manifest"]["launch"]["port"] == 5000
    assert tool["status"] == "needs_patch"

    # a dedicated supervisor agent was assigned to the tool
    agents = {a["id"] for a in client.get("/api/agents").json()}
    assert f"tool:{tool_id}" in agents

    # the Patch Agent proposed patches, each waiting for approval
    approvals = wait_for(lambda: [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "patch"])
    titles = {a["patch"]["strategy"] for a in approvals}
    assert {"sso_proxy", "health_probe", "event_adapter", "add_manifest"} <= titles

    # approving the health probe applies it and the tool is re-scored
    score_before = tool["report"]["score"]
    health = next(a for a in approvals if a["patch"]["strategy"] == "health_probe")
    assert client.post(f"/api/approvals/{health['id']}", json={"approve": True}).status_code == 200
    tool = wait_for(lambda: (t := client.get(f"/api/tools/{tool_id}").json())["manifest"]["health"]["url"] and t)
    assert tool["manifest"]["health"]["url"] == "tcp://127.0.0.1:5000"
    wait_for(lambda: client.get(f"/api/tools/{tool_id}").json()["report"]["score"] > score_before)

    # rejecting another one marks the patch rejected
    sso = next(a for a in approvals if a["patch"]["strategy"] == "sso_proxy")
    client.post(f"/api/approvals/{sso['id']}", json={"approve": False})
    wait_for(lambda: any(p["strategy"] == "sso_proxy" and p["status"] == "rejected"
                         for p in client.get(f"/api/tools/{tool_id}").json()["patches"]))

    # the agents talked to each other on the bus
    subjects = {(m["sender"], m["recipient"], m["subject"]) for m in client.get("/api/messages").json()}
    assert ("supervisor", f"tool:{tool_id}", "analyze") in subjects
    assert ("supervisor", "patcher", "propose") in subjects

    # the Asset Supervisor registered it and the GRC Supervisor evaluated controls
    assets = wait_for(lambda: [a for a in client.get("/api/assets").json() if a["source"] == f"tool:{tool_id}"])
    assert assets[0]["type"] == "software"
    grc = client.get("/api/grc").json()
    sso_control = next(c for c in grc["controls"] if c["id"] == "HB-AC-1")
    assert sso_control["status"] == "fail"
    risks = wait_for(lambda: [r for r in client.get("/api/grc/risks").json() if r["source"] == "auto:HB-AC-1"])
    assert risks[0]["status"] == "open"

    # removing the tool retires its asset
    assert client.delete(f"/api/tools/{tool_id}").json()["ok"]
    wait_for(lambda: next(a for a in client.get("/api/assets").json() if a["source"] == f"tool:{tool_id}")["status"] == "retired")


def test_person_runs_commands_directly(client):
    result = client.post("/api/commands", json={"command": f'"{sys.executable}" -c "print(6*7)"'}).json()
    assert result["status"] == "done"
    assert result["exit_code"] == 0 and "42" in result["output"]
    assert client.get("/api/commands").json()[-1]["origin"] == "user"


def test_blocked_command_is_refused_even_for_people(client):
    result = client.post("/api/commands", json={"command": "rm -rf /"}).json()
    assert result["status"] == "denied"


def test_agent_commands_wait_for_approval(client, wait_for):
    reply = client.post("/api/chat", json={"text": f'run "{sys.executable}" -c "print(1)"'}).json()
    assert "approval" in reply["reply"].lower()
    pending = wait_for(lambda: [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == "command"])
    client.post(f"/api/approvals/{pending[0]['id']}", json={"approve": True})
    done = wait_for(lambda: (a := next(x for x in client.get("/api/approvals").json() if x["id"] == pending[0]["id"]))["status"] in ("done", "failed") and a)
    assert done["status"] == "done"


def test_rules_chat_without_llm(client):
    reply = client.post("/api/chat", json={"text": "help"}).json()
    assert reply["mode"] == "rules" and "import" in reply["reply"]
    assert "No tools" in client.post("/api/chat", json={"text": "status"}).json()["reply"]


def test_hosts_become_assets(client, wait_for):
    host = client.post("/api/hosts", json={"name": "web-1", "address": "10.0.0.5", "username": "ops",
                                           "key_path": "~/.ssh/id_ed25519"}).json()
    assets = wait_for(lambda: [a for a in client.get("/api/assets").json() if a["source"] == f"host:{host['id']}"])
    assert assets[0]["type"] == "server"
    local = [a for a in client.get("/api/assets").json() if a["source"] == "host:local"]
    assert local and local[0]["facts"]["cpus"]


def test_policy_from_template_passes_control(client, wait_for):
    template = client.get("/api/grc/policy-templates").json()["security"]
    policy = client.post("/api/grc/policies", json={**template, "category": "security", "status": "approved", "owner": "CISO"}).json()
    assert policy["id"].startswith("pol_")
    wait_for(lambda: next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-PO-1")["status"] == "pass")


def test_settings_and_agent_configuration(client):
    assert client.patch("/api/settings", json={"autonomy": "manual"}).json()["autonomy"] == "manual"
    assert client.patch("/api/settings", json={"autonomy": "yolo"}).status_code == 422
    record = client.patch("/api/agents/patcher", json={"paused": True, "model": "claude-sonnet-5-5"}).json()
    assert record["paused"] and record["model"] == "claude-sonnet-5-5" and record["status"] == "paused"
    assert client.patch("/api/agents/patcher", json={"paused": False}).json()["status"] == "idle"
