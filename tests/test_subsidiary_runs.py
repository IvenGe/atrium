"""Runs of a subsidiary's staff (round4-spec 6.5, 7.2, 7.5, 7.7): the scheduler and chat relayed to the sidecar, the
replies, the staff's hold while the subsidiary is paused, the budgets (tokens, calls, approvals, concurrency) with
their daily reset, and amendments that narrow the charter at once. A scripted local model and a fake sidecar; no
tool, model or network is used."""

from __future__ import annotations

import threading

from subsidiary_support import TOOL, activate, local_model, relayed_run, staff_ids

from hub.agents import teams
from hub.llm.types import Result, Usage
from hub.subsidiary import audit, contract as c, gateway, governance, runtime


def user(text: str) -> dict:
    return {"role": "user", "text": text}


def test_the_scheduler_runs_staff_in_the_sidecar_and_records_the_reply(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = teams.get_def(hub, staff_ids(hub)["clerk"])
    assert clerk.schedule_minutes == 240 and clerk.task == "Keep tickets tidy"
    started = client.portal.call(hub.tick_agents, clerk.created_at + 241 * 60)
    assert clerk.id in started
    message = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "run"), None))
    body = message["body"]
    assert body["agent_id"] == clerk.id and body["trigger"] == "schedule" and body["text"] == "Keep tickets tidy"
    replied = sidecar.post("replies", {"correlation_id": body["correlation_id"], "reply": "Two tickets\x07 tidied.",
                                       "ok": True})
    assert replied.status_code == 200
    result = wait_for(lambda: (teams.get_def(hub, clerk.id).last_result or {}).get("run_id") and
                      teams.get_def(hub, clerk.id).last_result)
    assert result["ok"] and result["reply"] == "Two tickets tidied." and result["untrusted"].startswith("Written by")
    assert result["trigger"] == "schedule" and teams.get_def(hub, clerk.id).running is None
    assert sidecar.post("replies", {"correlation_id": body["correlation_id"], "reply": "again"}).status_code == 409
    assert sidecar.post("replies", {"correlation_id": "c_nope", "reply": "x"}).status_code == 404
    assert sidecar.post(f"runs/{body['run_id']}/end", {"outcome": "done"}).json() == {"ok": True, "outcome": "done"}
    assert gateway.get_run(hub, body["run_id"]).outcome == "done"


def test_a_chat_is_relayed_and_an_offline_sidecar_answers_503(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    desk = staff_ids(hub)["desk"]
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(client.post(f"/api/agents/{desk}/chat",
                                                                        json={"text": "Who are you?"})))
    thread.start()
    message = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "chat"), None))
    assert message["body"]["text"] == "Who are you?" and message["body"]["trigger"] == "chat"
    sidecar.post("replies", {"correlation_id": message["body"]["correlation_id"], "reply": "The front desk."})
    thread.join(10)
    reply = answers[0].json()
    assert reply["reply"] == "The front desk." and reply["untrusted"].startswith("Written by the subsidiary")
    clock.advance(governance.OFFLINE_AFTER + 1)
    governance.tick(hub)
    offline = client.post(f"/api/agents/{desk}/chat", json={"text": "Still there?"})
    assert offline.status_code == 503 and offline.json()["detail"]["code"] == "offline"


def test_runs_are_skipped_not_failed_while_the_sidecar_is_offline(client, tmp_path, wait_for, sign_in):
    """Review (medium): only chat looked at `offline`. A scheduled run opened a run, queued an inbox message, held a
    concurrency slot for 15 minutes and then counted as failed toward the schedule's auto-pause. It is skipped now,
    and a task is refused 503 offline, with nothing queued for the sidecar."""
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = teams.get_def(hub, staff_ids(hub)["clerk"])
    sidecar.inbox()  # what is queued so far
    clock.advance(governance.OFFLINE_AFTER + 1)
    governance.tick(hub)
    sub = governance.of_tool(hub, TOOL)
    assert "offline" in sub.flags
    assert clerk.id in client.portal.call(hub.tick_agents, clerk.created_at + 241 * 60)
    result = wait_for(lambda: (teams.get_def(hub, clerk.id).last_result or {}).get("skipped") and
                      teams.get_def(hub, clerk.id).last_result)
    assert result["ok"] is False and result["run_id"] is None and "offline" in result["reply"]
    assert teams.get_def(hub, clerk.id).failures == 0 and gateway.runs_of(hub, sub.id, open_only=True) == []
    task = client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk.id, "text": "Go"})
    assert task.status_code == 503 and task.json()["detail"]["code"] == "offline"
    assert [m for m in sidecar.inbox() if m["type"] in ("run", "chat")] == []
    sidecar.heartbeat()  # back online: work is relayed again
    assert client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk.id, "text": "Go"}).status_code == 202


def test_a_pause_holds_the_staff_and_stops_the_work_at_once(client, tmp_path, wait_for, sign_in):
    local_model(client, [Result(text="Fine.", usage=Usage(input_tokens=5))])
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    pending = sidecar.post("actions/request", {"run_id": run_id, "agent_id": clerk, "action_id": "tickets.set_priority",
                                               "params": {"ticket_id": 1, "priority": "low"}}).json()["approval_id"]
    assert sign_in("operator").post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "Audit"}).status_code == 200
    assert hub.approvals.get(pending).status == "rejected"  # withdrawn: resuming releases no backlog
    for path, body in (("model", {"run_id": run_id, "agent_id": clerk, "messages": [user("x")]}),
                       ("actions/request", {"run_id": run_id, "agent_id": clerk, "action_id": "tickets.list"}),
                       ("hub-request", {"run_id": run_id, "agent_id": clerk, "tool": "get_tool"}),
                       ("runs", {"question_id": "q_1", "agent_id": clerk})):
        refused = sidecar.post(path, body)
        assert refused.status_code == 423 and refused.json()["detail"]["code"] == "paused", path
    assert sidecar.heartbeat().json()["ticket"] is None
    # what already happened is still reported: the run's end
    assert sidecar.post(f"runs/{run_id}/end", {"outcome": "cancelled"}).status_code == 200
    held = teams.outside_guardrails(hub, teams.get_def(hub, clerk))
    assert held == "the Helpdesk subsidiary is paused by Atrium"
    assert client.portal.call(hub.tick_agents, teams.get_def(hub, clerk).created_at + 241 * 60) == []
    refused = client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "Go"})
    assert refused.status_code == 409
    assert ada.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 200
    assert teams.outside_guardrails(hub, teams.get_def(hub, clerk)) is None
    assert client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "Go"}).status_code == 202


def test_a_pause_ends_the_runs_under_way_so_the_resumed_team_is_not_busy(client, tmp_path, wait_for, sign_in):
    """Review (medium): runs queued or under way at a pause stayed open (up to RUN_STALE), so the resumed team was
    "busy" and refused new work with 429, and a proxy waiting for such a run's reply waited 15 minutes and recorded a
    failed run. Leaving active ends them "cancelled" and answers the waiting proxy "skipped" at once."""
    local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    relayed_run(client, sidecar, clerk, "first")
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(client.post(f"/api/agents/{clerk}/run")))
    thread.start()  # "Run now": the proxy waits for the sidecar's reply
    wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "run"), None))
    sub = governance.of_tool(hub, TOOL)
    assert gateway.busy(hub, sub.id) == 2
    assert sign_in("operator").post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "x"}).status_code == 200
    thread.join(10)
    result = answers[0].json()
    assert result["skipped"] is True and result["ok"] is False and "paused" in result["reply"]
    assert teams.get_def(hub, clerk).failures == 0  # skipped, not failed: no step toward the schedule's auto-pause
    runs = gateway.runs_of(hub, sub.id)
    assert len(runs) == 2 and {r.outcome for r in runs} == {"cancelled"} and gateway.busy(hub, sub.id) == 0
    assert ada.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 200
    again = client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "third"})
    assert again.status_code == 202, again.text
    late = sidecar.post(f"runs/{runs[0].id}/end", {"outcome": "cancelled"})  # the sidecar's own end: harmless
    assert late.status_code == 200 and late.json()["outcome"] == "cancelled"


def test_budgets_stop_the_work_and_start_over_the_next_utc_day(client, tmp_path, wait_for, sign_in):
    local_model(client, [Result(text="A long answer.", usage=Usage(input_tokens=900, output_tokens=200))
                         for _ in range(4)])
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    clerk = staff_ids(hub)["clerk"]
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"budgets": {
        **sub.charter.budgets.model_dump(), "tokens_per_day": 1000, "max_concurrent_runs": 1}})
    assert narrowed.json()["applied"] is True
    assert any(m["type"] == "charter_changed" for m in sidecar.inbox())
    run_id = relayed_run(client, sidecar, clerk)
    busy = client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "Another"})
    assert busy.status_code == 429 and busy.json()["detail"]["code"] == "busy"  # one run at a time
    assert sidecar.model(run_id, clerk, [user("Go")]).status_code == 200  # 1100 tokens: over the day's budget now
    over = sidecar.model(run_id, clerk, [user("Go")])
    assert over.status_code == 429 and over.json()["detail"]["which"] == "tokens_per_day"
    assert gateway.get_run(hub, run_id).outcome == "budget" and "over_budget" in governance.of_tool(hub, TOOL).flags
    warnings = [e for e in hub.store.tail("activity", 30) if "used up its tokens per day budget" in e["text"]]
    assert len(warnings) == 1  # one warning a day, not one per refusal
    clock.advance(24 * 3600)  # the next UTC day: counters start over
    governance.tick(hub)
    assert "over_budget" not in governance.of_tool(hub, TOOL).flags
    sidecar.heartbeat()
    fresh = relayed_run(client, sidecar, clerk)
    assert sidecar.model(fresh, clerk, [user("Go")]).status_code == 200
    assert {"budget", "model.call"} <= {e.kind for e in audit.all_entries(hub, sub.id)}


def test_narrowing_applies_at_once_and_widening_waits_for_an_administrator(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    staff = staff_ids(hub)
    before = sidecar.ticket
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={
        "staff": {staff["clerk"]: {"actions": ["tickets.list"], "hub_tools": []}}, "panel": {"enabled": False}})
    assert narrowed.status_code == 200 and narrowed.json()["applied"] is True, narrowed.text
    sub = governance.of_tool(hub, TOOL)
    assert sub.charter_version == 2 and list(sub.charter.staff) == [staff["clerk"]]
    assert teams.get_def(hub, staff["desk"]).enabled is False  # removed staff are disabled, not deleted
    assert sub.charter_approved_by == "ada"  # narrowing keeps the approval it narrows
    sidecar.ticket_exp = None
    sidecar.heartbeat()
    assert sidecar.ticket != before
    act = __import__("json").loads(c.b64u_decode(sidecar.ticket.split(".")[1]))["act"]
    assert "atrium.panel.pull" not in act
    # widening back needs an approval; until then the narrowed charter stays in force
    widened = client.put(f"/api/subsidiaries/{TOOL}/charter", json={
        "staff": {staff["clerk"]: {"actions": ["tickets.list", "tickets.set_priority"], "hub_tools": []}}}).json()
    assert widened["applied"] is False and widened["widening"] == [f"{staff['clerk']} may use tickets.set_priority"]
    assert governance.of_tool(hub, TOOL).charter.staff[staff["clerk"]].actions == ["tickets.list"]
    assert ada.post(f"/api/approvals/{widened['approval_id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: governance.of_tool(hub, TOOL).charter_version == 3)
    unchanged = client.put(f"/api/subsidiaries/{TOOL}/charter", json={})
    assert unchanged.json()["changed"] is False
    bad = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"actions": [{"id": "tickets.purge", "policy": "allow"}]})
    assert bad.status_code == 400 and "not in the tool's catalog" in bad.json()["detail"]["message"]
    assert sign_in("operator").put(f"/api/subsidiaries/{TOOL}/charter", json={}).status_code == 403
    assert runtime.pending(hub, sub.id, 0) is not None


def test_parallel_model_calls_are_reserved_capped_and_turn_limited(client, tmp_path, wait_for, sign_in):
    """Review (medium): the gateway checked the budgets before the provider call and booked after it, so a compromised
    sidecar firing many /model calls at once passed the check with each. Calls in flight are now capped per
    subsidiary and counted at their estimate until booked, and a run stops at its turn limit."""
    import asyncio

    from llm_fakes import FakeProvider
    from hub.subsidiary.models import ModelRequest

    class Slow(FakeProvider):
        async def complete(self, req):
            self.requests.append(req)
            await asyncio.sleep(0.05)
            return Result(text="ok", usage=Usage(input_tokens=60_000, output_tokens=100))

    provider, _ = local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    hub.llm.adapters[provider] = slow = Slow()
    hub.llm.invalidate()
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    req = ModelRequest(run_id=run_id, agent_id=clerk, messages=[user("Tidy the tickets")])

    async def burst(n: int):
        sub = governance.of_tool(hub, TOOL)
        return await asyncio.gather(*(gateway.model(hub, sub, req) for _ in range(n)), return_exceptions=True)

    results = client.portal.call(burst, 40)
    sub = governance.of_tool(hub, TOOL)
    cap = sub.charter.budgets.max_concurrent_runs * gateway.INFLIGHT_PER_RUN
    refused = [r for r in results if isinstance(r, governance.GovernanceError)]
    assert len(slow.requests) == cap == 40 - len(refused) and {r.code for r in refused} == {"busy"}
    day = governance.usage_day(hub, sub.id, governance.clock(hub))
    assert day.tokens <= sub.charter.budgets.tokens_per_day and not hub.subsidiaries.flights[sub.id]
    # reserved at their estimate: a call that could go over the budget with the calls under way waits
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"budgets": {
        **sub.charter.budgets.model_dump(), "tokens_per_day": day.tokens + 2 * gateway.MAX_OUTPUT + 6000}})
    assert narrowed.json()["applied"] is True
    sidecar.heartbeat()
    fresh = relayed_run(client, sidecar, clerk)
    slow.requests.clear()
    req = ModelRequest(run_id=fresh, agent_id=clerk, messages=[user("Tidy the tickets")])
    results = client.portal.call(burst, cap)  # each reserved at its prompt plus MAX_OUTPUT
    assert len(slow.requests) == 2 and sum(isinstance(r, governance.GovernanceError) for r in results) == cap - 2
    # a run gets its turn limit (and a little slack for lost answers), however its calls are timed
    hub.llm.adapters[provider] = FakeProvider()
    hub.llm.invalidate()
    clock.advance(24 * 3600)  # a new day: the token budget starts over
    governance.tick(hub)
    sidecar.heartbeat()
    last = relayed_run(client, sidecar, clerk)
    limit = gateway.loops.MAX_TURNS + gateway.TURN_SLACK
    answers = [sidecar.model(last, clerk, [user("Go")]).status_code for _ in range(limit + 1)]
    assert answers[:limit] == [200] * limit and answers[-1] == 429
    assert sidecar.model(last, clerk, [user("Go")]).json()["detail"]["code"] == "max_turns"
