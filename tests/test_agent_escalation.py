"""Escalation and notifications (round4-agents-spec.md 9): the escalate tool asks a person through an
"agent_escalation" approval that operators decide, its answer reaches the agent's next turn; failed runs pause a
custom agent's schedule until an administrator resumes it; agent events are notifications (activity data.notify, the
tool bus) and the Agents page's "Needs attention" strip lists what needs a person. No network: local model servers
are httpx mock transports, the tool bus delivers to a closed local port."""

from __future__ import annotations

import json
import time

from llm_fakes import chat_transport, completion

from hub.agents import notify, toolkit
from hub.llm import BudgetExceeded
from test_teams import add_tool

KEY = "local-provider-key-esc-7c6b5a4d3e"


def local_model(client, handler) -> list:
    """A local provider (with a key, so the mask knows a secret) answering through `handler`; the requests it got."""
    hub = client.app.state.hub
    transport, seen = chat_transport(handler)
    hub.llm_transport = transport
    created = client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "qwen3:8b", "api_key": KEY})
    assert created.status_code == 201, created.text
    hub.llm.invalidate()
    return seen


def escalation_call(summary: str, severity: str = "critical", needs: str = "decision") -> dict:
    return completion(None, finish="tool_calls", tool_calls=[{"id": "e1", "type": "function", "function": {
        "name": "escalate", "arguments": json.dumps({"summary": summary, "severity": severity, "needs": needs})}}])


def script(*answers):
    """A handler answering the chat completions in order (then "Done.")."""
    queue = list(answers)
    return lambda body: queue.pop(0) if queue else completion("Done.")


def system_of(request) -> str:
    return request[3]["messages"][0]["content"]


def activity(client, prefix: str) -> list[dict]:
    return [e for e in client.get("/api/activity?limit=500").json() if e["text"].startswith(prefix)]


def escalations(client, status: str | None = None) -> list[dict]:
    query = f"?status={status}" if status else ""
    return [a for a in client.get(f"/api/approvals{query}").json() if a["kind"] == "agent_escalation"]


def test_the_escalate_tool_asks_a_person_and_the_answer_reaches_the_next_turn(client, sign_in, wait_for):
    hub = client.app.state.hub
    seen = local_model(client, script(escalation_call(f"Open port 22 to the world?\nThe key {KEY} was in a log."),
                                      completion("I escalated it to a person.")))
    member = client.post("/api/agents", json={"name": "Triage", "title": "Analyst"}).json()["id"]
    reply = client.post(f"/api/agents/{member}/chat", json={"text": "Should we open port 22?"})
    assert reply.status_code == 200, reply.text
    assert reply.json()["reply"] == "I escalated it to a person."
    offered = {t["function"]["name"] for t in seen[0][3]["tools"]}
    assert "escalate" in offered and "call the escalate tool" not in system_of(seen[0])  # no rules: the short block
    assert "Also escalate (the escalate tool) when you are blocked" in system_of(seen[0])

    [esc] = escalations(client, "pending")
    assert esc["title"] == "Triage: Open port 22 to the world?" and esc["requested_by"] == member
    assert KEY not in json.dumps(esc) and "***" in esc["detail"]  # the summary is masked
    assert esc["payload"] == {"agent_id": member, "agent_name": "Triage", "severity": "critical", "needs": "decision"}
    [entry] = activity(client, "Awaiting approval: Triage")
    assert entry["level"] == "warn" and entry["data"]["event"] == "escalation"
    assert entry["data"]["severity"] == "critical" and entry["data"]["notify"] == ["role:admin"]
    assert entry["data"]["agent_id"] == member and KEY not in json.dumps(entry)

    # operators decide escalations (viewers cannot); "Acknowledge" with a note
    assert sign_in("viewer").post(f"/api/approvals/{esc['id']}", json={"approve": True}).status_code == 403
    operator = sign_in("operator")
    decided = operator.post(f"/api/approvals/{esc['id']}", json={"approve": True, "note": "Not yet - ticket 4242"})
    assert decided.status_code == 200, decided.text
    wait_for(lambda: notify.inbox(hub, member))
    assert wait_for(lambda: client.get("/api/approvals?status=done").json())[0]["id"] == esc["id"]
    view = client.get(f"/api/agents/{member}/settings").json()
    assert view["escalation"] == {"pending": 0, "today": 1, "limit": 5, "answers_waiting": 1}

    # the next turn - here a run - reads the answer, then it is gone
    ran = client.post(f"/api/agents/{member}/run", json={"task": "Check the port request again."})
    assert ran.status_code == 200 and ran.json()["ok"], ran.text
    assert 'A person answered your escalation "Triage: Open port 22 to the world?" (acknowledged): Not yet - ticket 4242' \
        in system_of(seen[-1])
    assert notify.inbox(hub, member) == []
    client.post(f"/api/agents/{member}/chat", json={"text": "Again?"})
    assert "ticket 4242" not in system_of(seen[-1])


def test_the_hub_supervisor_escalates_and_a_dismissal_reaches_it_too(client, wait_for):
    hub = client.app.state.hub
    seen = local_model(client, script(escalation_call("Restart the SIEM?", severity="warning", needs="information"),
                                      completion("Asked.")))
    assert client.post("/api/chat", json={"text": "restart it"}).json()["reply"] == "Asked."
    [esc] = escalations(client, "pending")
    assert esc["requested_by"] == "supervisor" and esc["title"] == "Hub Supervisor: Restart the SIEM?"
    assert client.post(f"/api/approvals/{esc['id']}", json={"approve": False}).status_code == 200  # "Dismiss"
    wait_for(lambda: notify.inbox(hub, "supervisor"))
    assert escalations(client)[0]["status"] == "rejected"
    client.post("/api/chat", json={"text": "next"})
    assert "(dismissed): no note." in system_of(seen[-1])
    assert notify.inbox(hub, "supervisor") == []


def test_escalations_are_limited_per_day_and_the_tool_can_be_switched_off(client):
    hub = client.app.state.hub
    seen = local_model(client, script(escalation_call("First"), completion("ok"), escalation_call("Second"),
                                      completion("ok"), escalation_call("Third"), completion("ok")))
    member = client.post("/api/agents", json={"name": "Noisy"}).json()["id"]
    saved = client.patch(f"/api/agents/{member}/settings", json={"config": {"escalation": {
        "max_per_day": 1, "rules": ["  A firewall   rule changes ", "Personal data leaves the hub", ""]}}})
    assert saved.status_code == 200, saved.text
    assert saved.json()["settings"]["config"]["escalation"]["rules"] == ["A firewall rule changes",
                                                                         "Personal data leaves the hub"]
    for text in ("one", "two", "three"):
        client.post(f"/api/agents/{member}/chat", json={"text": text})
    assert len(escalations(client)) == 1
    refused = seen[3][3]["messages"][-1]  # the tool result of the second escalation
    assert refused["role"] == "tool" and notify.LIMIT_REACHED in refused["content"]
    assert len(activity(client, "Noisy reached its limit of 1 escalations today")) == 1  # logged once a day
    system = system_of(seen[0])
    assert "call the escalate tool instead of deciding yourself:\n- A firewall rule changes\n- Personal data" in system

    # switched off: not offered, no escalation instructions, and a call to it is refused
    client.patch(f"/api/agents/{member}/settings", json={"config": {"escalation": {"tool": False}}})
    hub.llm_transport, seen = chat_transport(script(escalation_call("Fourth"), completion("ok")))
    client.post(f"/api/agents/{member}/chat", json={"text": "four"})
    assert "escalate" not in {t["function"]["name"] for t in seen[0][3]["tools"]}
    assert "escalate tool" not in system_of(seen[0])
    assert "not among the tools" in seen[1][3]["messages"][-1]["content"] and len(escalations(client)) == 1
    # narrowing the allowed tools narrows it too
    client.patch(f"/api/agents/{member}/settings", json={"config": {"escalation": {"tool": True},
                                                                    "allowed_tools": ["list_tools"]}})
    hub.llm_transport, seen = chat_transport(script(completion("ok")))
    client.post(f"/api/agents/{member}/chat", json={"text": "five"})
    assert {t["function"]["name"] for t in seen[0][3]["tools"]} == {"list_tools"}


def test_the_playground_offers_the_escalate_tool_only_with_actions(client):
    hub = client.app.state.hub
    seen = local_model(client, script(completion("a"), completion("b")))
    for allow in (False, True):
        run = client.post("/api/agents/supervisor/playground", json={"prompt": "hi", "allow_actions": allow})
        assert run.status_code == 200, run.text
    without, with_actions = ({t["function"]["name"] for t in s[3]["tools"]} for s in seen[-2:])
    assert "escalate" not in without and "escalate" in with_actions and "list_tools" in without
    assert hub.approvals.list() == []


def failing_runs(hub, agent_id: str, monkeypatch, outcomes: list) -> None:
    """Make the agent's runs end as `outcomes` says: "fail", "ok" or "skip" (a reached budget)."""
    agent = hub.agents.get(agent_id)
    queue = list(outcomes)

    async def converse(text, history, requested_by=None, **kwargs):
        what = queue.pop(0)
        if what == "fail":
            raise RuntimeError(f"tool down ({KEY})")
        if what == "skip":
            raise BudgetExceeded("Its daily budget is reached")
        return "All fine.", "rules"

    monkeypatch.setattr(agent, "converse", converse)


def run(client, agent_id: str) -> dict:
    response = client.post(f"/api/agents/{agent_id}/run", json={})
    assert response.status_code == 200, response.text
    return response.json()


def test_failed_runs_pause_the_schedule_until_an_administrator_resumes_it(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    member = client.post("/api/agents", json={"name": "Watch"}).json()["id"]
    client.patch(f"/api/agents/{member}", json={"schedule_minutes": 5, "task": "Check the health."})
    failing_runs(hub, member, monkeypatch, ["fail", "ok", "fail", "skip", "fail", "fail", "fail", "ok"])
    assert run(client, member)["agent"]["failures"] == 1
    assert run(client, member)["agent"]["failures"] == 0  # a success starts the count again
    run(client, member)
    skipped = run(client, member)
    assert skipped["skipped"] and skipped["agent"]["failures"] == 1  # a reached budget is not a failure
    run(client, member)
    paused = run(client, member)["agent"]
    assert paused["failures"] == 3 and paused["schedule_paused"] and paused["next_run"] is None
    entry = activity(client, "Watch ran its task (manual): failed - its schedule is paused after 3 failed runs")[-1]
    assert entry["level"] == "warn" and entry["data"]["event"] == "run_failed" and entry["data"]["paused"]
    assert entry["data"]["notify"] == ["role:admin"] and entry["data"]["failures"] == 3
    assert client.portal.call(hub.tick_agents, time.time() + 3600) == []  # the scheduler leaves it alone
    assert run(client, member)["agent"]["failures"] == 4  # a person can still run it by hand

    assert sign_in("operator").post(f"/api/agents/{member}/schedule/resume").status_code == 403
    assert client.post("/api/agents/supervisor/schedule/resume").status_code == 400
    assert client.post("/api/agents/agent:nobody/schedule/resume").status_code == 404
    resumed = client.post(f"/api/agents/{member}/schedule/resume")
    assert resumed.status_code == 200, resumed.text
    assert not resumed.json()["schedule_paused"] and resumed.json()["failures"] == 0 and resumed.json()["next_run"]
    assert activity(client, "Resumed Watch's schedule (it was paused after 4 failed runs in a row)")
    assert client.portal.call(hub.tick_agents, time.time() + 3600) == [member]


def test_pausing_follows_the_agents_escalation_settings(client, monkeypatch):
    hub = client.app.state.hub
    member = client.post("/api/agents", json={"name": "Watch"}).json()["id"]
    client.patch(f"/api/agents/{member}", json={"schedule_minutes": 5, "task": "Check the health."})
    off = client.patch(f"/api/agents/{member}/settings", json={"config": {"escalation": {"pause_schedule": False}}})
    assert off.status_code == 200 and activity(client, "Configured Watch: pause the schedule")[-1]["level"] == "warn"
    failing_runs(hub, member, monkeypatch, ["fail"] * 5)
    for _ in range(4):
        result = run(client, member)
    assert result["agent"]["failures"] == 4 and not result["agent"]["schedule_paused"]
    client.patch(f"/api/agents/{member}/settings", json={"config": {"escalation": {"pause_schedule": True,
                                                                                   "failed_runs": 0}}})
    assert not run(client, member)["agent"]["schedule_paused"]  # 0 = never pause


def test_notifications_reach_listening_tools_on_the_tool_bus_masked(client, wait_for, monkeypatch):
    hub = client.app.state.hub
    local_model(client, script())  # its key is a secret the mask knows
    add_tool(client, "itsm", "ITSM", events={"listens": ["hub.agent.*"], "webhook_url": "http://127.0.0.1:9/hook"})
    member = client.post("/api/agents", json={"name": "Watch", "task": "Check the health."}).json()["id"]
    view = client.get(f"/api/agents/{member}/settings").json()
    assert view["toolbus_listeners"] == [{"id": "itsm", "name": "ITSM"}]
    assert [e["id"] for e in view["notify_events"]] == list(notify.EVENTS)
    saved = client.patch(f"/api/agents/{member}/settings", json={"config": {"notify": {"toolbus": True}}})
    assert saved.status_code == 200
    assert activity(client, "Configured Watch: tool bus notifications on")[-1]["level"] == "warn"
    failing_runs(hub, member, monkeypatch, ["fail", "ok"])
    run(client, member)
    entry = wait_for(lambda: next((e for e in hub.store.tail("toolbus", 20) if e["event"] == "hub.agent.run_failed"), None))
    payload = entry["payload"]
    assert entry["source"] == "hub" and entry["by"] == member and entry["deliveries"][0]["to"] == "itsm"
    assert payload["agent_id"] == member and payload["event"] == "run_failed" and payload["severity"] == "warning"
    assert payload["link"].endswith("/#/agents/agent%3Awatch/settings") and KEY not in json.dumps(entry)
    assert "RuntimeError: tool down" in payload["summary"]
    run(client, member)  # run_done is not among its events: no tool bus event
    time.sleep(0.3)
    assert not [e for e in hub.store.tail("toolbus", 20) if e["event"] == "hub.agent.run_done"]


def test_a_reached_budget_is_a_notification_of_the_agent(client):
    hub = client.app.state.hub
    hub.llm.meter._warn(time.time(), "supervisor", "stopped", "Hub Supervisor reached its daily budget",
                        agent_id="supervisor")
    [entry] = activity(client, "Hub Supervisor reached its daily budget")
    assert entry["actor"] == "hub" and entry["data"]["event"] == "budget_reached"
    assert entry["data"]["notify"] == ["role:admin"] and entry["data"]["agent_id"] == "supervisor"
    hub.llm.meter._warn(time.time(), "suite", "cap", "AI spending reached the daily cap")
    assert "notify" not in activity(client, "AI spending reached the daily cap")[0]["data"]


def test_notification_settings_are_checked_logged_and_kept(client, sign_in):
    hub = client.app.state.hub
    operator_id = hub.auth.find_user("admin").id
    member = client.post("/api/agents", json={"name": "Watch"}).json()["id"]
    bad = [({"notify": {"targets": ["user:u_nobody"]}}, "Notification targets: no account"),
           ({"notify": {"targets": ["role:root"]}}, "Notification targets: 'role:root'"),
           ({"notify": {"events": ["coffee"]}}, "Notification events:"),
           ({"escalation": {"rules": ["x" * 301]}}, "Escalation rules:"),
           ({"escalation": {"max_per_day": 0}}, "Escalations per day:"),
           ({"escalation": {"failed_runs": 21}}, "Failed runs before pausing:")]
    for config, message in bad:
        response = client.patch(f"/api/agents/{member}/settings", json={"config": config})
        assert response.status_code == 400 and response.json()["detail"].startswith(message), (config, response.text)
    saved = client.patch(f"/api/agents/{member}/settings", json={"config": {"notify": {
        "events": ["escalation", "run_failed", "run_failed"], "targets": ["role:operator", f"user:{operator_id}",
                                                                          "role:operator"]}}})
    assert saved.status_code == 200, saved.text
    config = saved.json()["settings"]["config"]["notify"]
    assert config["events"] == ["run_failed", "escalation"]
    assert config["targets"] == ["role:operator", f"user:{operator_id}"]
    assert saved.json()["notify_targets"] == [{"id": "role:operator", "label": "Operators (and administrators)"},
                                              {"id": f"user:{operator_id}", "label": "admin"}]
    entry = activity(client, "Configured Watch: notifications: run_failed, escalation")[-1]
    assert entry["level"] == "info" and f"notification targets: role:operator, user:{operator_id}" in entry["text"]
    assert "config.notify" in client.get(f"/api/agents/{member}/settings/history").json()[0]["changed"]

    # escalation is for chat agents; agents without a model only have notifications
    patcher = client.patch("/api/agents/patcher/settings", json={"config": {"escalation": {"max_per_day": 9}}})
    assert patcher.status_code == 400 and patcher.json()["detail"].startswith("Escalation: Patch Agent does not chat")
    view = client.get("/api/agents/operator/settings").json()
    assert view["tabs"] == ["overview", "escalation", "history"] and [e["id"] for e in view["notify_events"]] == [
        "approval_requested"]
    assert client.patch("/api/agents/operator/settings", json={"llm": {"provider": "rules"}}).status_code == 400
    refused = client.patch("/api/agents/operator/settings", json={"config": {"budget": {"daily_tokens": 5000}}})
    assert refused.status_code == 400 and "only its notifications" in refused.json()["detail"]
    ok = client.patch("/api/agents/operator/settings", json={"config": {"notify": {"events": ["approval_requested"]}},
                                                             "version": 0})
    assert ok.status_code == 200, ok.text
    assert client.post("/api/agents/operator/settings/restore", json={"version": 0}).status_code == 200
    assert client.get("/api/agents/operator/settings").json()["settings"]["config"]["notify"]["events"] == [
        "run_failed", "budget_reached", "escalation"]
    # a viewer reads them, only administrators change them
    viewer = sign_in("viewer")
    assert viewer.get(f"/api/agents/{member}/settings").json()["settings"]["config"]["notify"]["toolbus"] is False
    assert viewer.patch(f"/api/agents/{member}/settings", json={"config": {"notify": {}}}).status_code == 403


def test_approval_requests_of_an_agent_are_notifications_when_it_asks_for_them(client):
    hub = client.app.state.hub
    client.patch("/api/agents/operator/settings", json={"config": {"notify": {
        "events": ["approval_requested"], "targets": ["role:operator"]}}})
    approval = hub.approvals.create("command", "Run uptime", "", {"target": "local", "command": "uptime"}, "operator")
    [entry] = activity(client, "Awaiting approval: Run uptime")
    assert entry["data"] == {"event": "approval_requested", "severity": "info", "notify": ["role:operator"],
                             "agent_id": "operator", "approval_id": approval.id}
    hub.approvals.create("command", "By a person", "", {}, "alice")
    assert activity(client, "Awaiting approval: By a person")[0]["data"] == {"event": "approval_requested",
                                                                             "approval_id": hub.approvals.list()[0].id}


def test_the_needs_attention_strip(client, sign_in, monkeypatch, wait_for):
    hub = client.app.state.hub
    local_model(client, script(escalation_call("Is this alert real?", severity="warning"), completion("Asked.")))
    member = client.post("/api/agents", json={"name": "Triage"}).json()["id"]
    client.patch(f"/api/agents/{member}", json={"schedule_minutes": 5, "task": "Triage alerts."})
    client.post(f"/api/agents/{member}/chat", json={"text": "look"})
    watcher = client.post("/api/agents", json={"name": "Watch"}).json()["id"]
    client.patch(f"/api/agents/{watcher}", json={"schedule_minutes": 5, "task": "Check the health."})
    client.patch(f"/api/agents/{watcher}/settings", json={"config": {"notify": {"targets": ["role:operator"]}}})
    failing_runs(hub, watcher, monkeypatch, ["fail"] * 3)
    for _ in range(3):
        run(client, watcher)
    selection = client.get("/api/llm/selection").json()["selection"]  # a suite default that cannot run (no key)
    assert client.patch("/api/llm/selection", json={"default": {"provider": "openai", "model": "gpt-6-luna"},
                                                    "version": selection["version"]}).status_code == 200

    items = client.get("/api/agents/attention").json()["items"]
    kinds = [i["kind"] for i in items]
    assert kinds == ["escalation", "paused", "blocked"], items
    esc, paused, blocked = items
    assert esc["agent_id"] == member and esc["title"] == "Triage: Is this alert real?" and esc["for_you"]
    assert esc["severity"] == "warning" and esc["approval_id"]
    assert paused["agent_id"] == watcher and paused["failures"] == 3 and paused["for_you"]  # role:operator: admins too
    assert {"id": "supervisor", "name": "Hub Supervisor"} in blocked["agents"] and blocked["reason"].startswith("OpenAI:")
    assert {"id": member, "name": "Triage"} in blocked["agents"] and not blocked["for_you"]
    operator_items = {i["kind"]: i for i in sign_in("operator").get("/api/agents/attention").json()["items"]}
    assert not operator_items["escalation"]["for_you"] and operator_items["paused"]["for_you"]
    viewer = sign_in("viewer").get("/api/agents/attention")
    assert viewer.status_code == 200 and not any(i["for_you"] for i in viewer.json()["items"])
    assert KEY not in json.dumps(viewer.json())


def test_the_deprecated_wrappers_are_gone(client):
    hub = client.app.state.hub
    assert not hasattr(toolkit, "claude_loop") and not hasattr(toolkit, "local_loop")
    assert not hasattr(hub.llm, "create")
