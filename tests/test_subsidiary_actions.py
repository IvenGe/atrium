"""In-tool actions of a subsidiary's staff (round4-spec 7.1, 7.3, 4.7, 7.8): the charter's approval and its staff, the
decision table, grants bound to the exact approved bytes, results, regrants, the auto policy, reconciliation alarms
and API-only writes carried out by the Tool Supervisor. A fake tool runs the reference bridge, a scripted fake
sidecar stands in for the sidecar and a scripted local model for the AI. No tool, model or network is used."""

from __future__ import annotations

import json

import httpx
from subsidiary_support import (HUB_SECRET, OWN_SECRET, TOOL, activate, charter_approval, enrolled,
                                local_model, relayed_run, setup, sidecar_only_subsidiary, staff_ids)

from hub.agents import teams
from hub.subsidiary import actions, audit, contract as c, gateway, governance, runtime
from hub.subsidiary.agent import SubsidiaryAgent


def control(client, control_id: str) -> dict:
    return next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == control_id)


def evaluate(client) -> None:
    client.portal.call(client.app.state.hub.bus.request, "user:admin", "module:grc", "evaluate", {}, 60)


def request(sidecar, run_id: str, agent_id: str, action: str = "tickets.set_priority", params=None, **extra):
    return sidecar.post("actions/request", {"run_id": run_id, "agent_id": agent_id, "action_id": action,
                                            "params": params if params is not None else
                                            {"ticket_id": 7, "priority": "high"}, **extra})


def grant_message(hub, wait_for, sub_id: str) -> dict:
    found = wait_for(lambda: next((m for m in runtime.pending(hub, sub_id, 0) if m.type == "grant"), None))
    return found.body


# -- the charter's approval -------------------------------------------------------------------------------------------


def test_conformance_brings_the_drafted_charter_to_an_administrator_and_its_approval_creates_the_staff(
        client, tmp_path, wait_for, sign_in):
    provider, _ = local_model(client)
    activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "active" and sub.charter_version == 1 and sub.charter_approved_by == "ada"
    staff = staff_ids(hub)
    desk, clerk = teams.get_def(hub, staff["desk"]), teams.get_def(hub, staff["clerk"])
    assert desk.placement == clerk.placement == "sidecar" and desk.provider == clerk.provider == provider
    assert isinstance(hub.agents.get(clerk.id), SubsidiaryAgent) and clerk.parent == f"tool:{TOOL}"
    assert sub.charter.staff[desk.id].actions == ["tickets.list"]  # the front desk reads and drafts only
    assert sub.charter.staff[clerk.id].actions == ["tickets.list", "tickets.set_priority"]
    assert {a.id: a.policy for a in sub.charter.actions} == {"tickets.list": "allow", "tickets.set_priority": "approval"}
    assert sub.charter.model_routing.allowed == [provider] and sub.pending_charter is None
    kinds = [e.kind for e in audit.all_entries(hub, sub.id)]
    assert {"charter.draft", "charter.request", "charter.approve", "status.active"} <= set(kinds)


def test_the_charter_waits_for_conformance_and_its_proposer_never_approves_it(client, tmp_path, wait_for, sign_in):
    from subsidiary_support import MANIFEST_RAW, FakeBridge, bridge_subsidiary

    clock = setup(client)
    local_model(client)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    broken = MANIFEST_RAW.replace(b"Open tickets", b"All tickets")  # V19 fails
    hub.subsidiary_config.bridge_transport = FakeBridge(client, clock, manifest=broken).transport()
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    wait_for(lambda: governance.of_tool(hub, TOOL).conformance)
    assert charter_approval(hub) is None  # no charter before conformance passed
    sub = governance.of_tool(hub, TOOL)
    assert sub.pending_charter is not None and sub.pending_charter.version == 1  # drafted when the bridge applied
    hub.subsidiary_config.bridge_transport = FakeBridge(client, clock).transport()
    assert client.post(f"/api/subsidiaries/{TOOL}/conformance").json()["conformance"]["ok"] is True
    approval = wait_for(lambda: charter_approval(hub))
    assert approval.requested_by == f"tool:{TOOL}" and approval.payload["proposed_by"] == "admin"
    assert approval.payload["charter_sha256"] == governance.of_tool(hub, TOOL).pending_charter.sha256()
    assert "the first charter of this subsidiary" in approval.detail and len(approval.payload["members"]) == 2
    own = client.post(f"/api/approvals/{approval.id}", json={"approve": True})
    assert own.status_code == 403 and own.json()["detail"]["code"] == "same_person"  # the proposer: never
    assert sign_in("operator").post(f"/api/approvals/{approval.id}", json={"approve": True}).status_code == 403
    # a charter changed after the request cannot be approved with it
    sub = governance.of_tool(hub, TOOL)
    sub.pending_charter = sub.pending_charter.model_copy(update={"mandate": "Something else entirely."})
    governance.save(hub, sub)
    ada = sign_in("admin", "ada")
    stale = ada.post(f"/api/approvals/{approval.id}", json={"approve": True})
    assert stale.status_code == 409 and "charter changed" in stale.json()["detail"]
    assert governance.of_tool(hub, TOOL).status == "probation" and not governance.staff(hub, sub)


def test_a_first_charter_is_asked_for_again_once_the_subsidiary_is_back_on_probation(
        client, tmp_path, wait_for, sign_in):
    """Review (medium): the first charter's approval was asked for only right after conformance results on probation.
    Withdrawn by the kill switch (then resumed), or with conformance run while the subsidiary was still deploying,
    nothing asked again and the subsidiary stayed on probation for good."""
    from subsidiary_support import FakeBridge, FakeSidecar, bridge_subsidiary

    local_model(client)
    clock = setup(client)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    hub.subsidiary_config.bridge_transport = FakeBridge(client, clock).transport()
    # conformance run by an administrator while the subsidiary is still being deployed, before the sidecar enrolls
    code = client.post(f"/api/subsidiaries/{TOOL}/enrollment").json()["code"]
    assert client.post(f"/api/subsidiaries/{TOOL}/conformance").json()["conformance"]["ok"] is True
    assert governance.of_tool(hub, TOOL).status == "deploying" and charter_approval(hub) is None
    sidecar = FakeSidecar(client, clock)
    assert sidecar.enroll(code).status_code == 200  # on probation now: the charter is asked for
    first = charter_approval(hub)
    assert first is not None and governance.of_tool(hub, TOOL).status == "probation"
    # the kill switch withdraws it; switched on and resumed, it is asked for again
    assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": False}).status_code == 200
    assert hub.approvals.get(first.id).status == "rejected"
    assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": True}).status_code == 200
    resumed = client.post(f"/api/subsidiaries/{TOOL}/resume")
    assert resumed.status_code == 200 and resumed.json()["status"] == "probation"
    again = charter_approval(hub)
    assert again is not None and again.id != first.id
    assert sign_in("admin", "ada").post(f"/api/approvals/{again.id}", json={"approve": True}).status_code == 200
    wait_for(lambda: governance.of_tool(hub, TOOL).status == "active")
    # HB-AC-8 is evaluated again once the charter is in force (review, low): not left describing probation
    wait_for(lambda: "1 active" in control(client, "HB-AC-8")["detail"])


def test_an_archived_subsidiarys_staff_leave_the_team_so_the_next_one_has_room(client, tmp_path, wait_for, sign_in):
    """Review (low): stop disabled the staff and archive kept them, and the team size counts every member, enabled
    or not: each stop and new proposal left staff behind until no new charter fitted max_team_size."""
    from subsidiary_support import FakeBridge, bridge_subsidiary

    local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    old = list(staff_ids(hub).values())
    assert client.patch("/api/settings/guardrails", json={"max_team_size": 2}).status_code == 200
    assert client.post(f"/api/subsidiaries/{TOOL}/stop", json={"confirm": TOOL}).status_code == 200
    assert [teams.get_def(hub, a).enabled for a in old] == [False, False]  # stopped: disabled, still listed
    bridge_subsidiary(client, tmp_path)  # a new team for the tool: the stopped subsidiary is archived first
    assert [teams.get_def(hub, a) for a in old] == [None, None] and teams.room(hub, TOOL) == 2
    wait_for(lambda: all(hub.agents.get(a) is None for a in old))
    hub.subsidiary_config.bridge_transport = FakeBridge(client, clock).transport()
    enrolled(client, clock).heartbeat()
    approval = wait_for(lambda: charter_approval(hub))
    assert ada.post(f"/api/approvals/{approval.id}", json={"approve": True}).status_code == 200
    wait_for(lambda: governance.of_tool(hub, TOOL).status == "active")
    assert len(staff_ids(hub)) == 2


def test_a_write_runs_once_with_exactly_the_approved_bytes(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    # without a grant the bridge refuses the write
    assert sidecar.call(bridge, "tickets.set_priority", {"ticket_id": 7, "priority": "high"}) == (
        403, {"ok": False, "code": "grant_required"})
    asked = request(sidecar, run_id, clerk, reason="Ticket 7 is urgent")
    assert asked.status_code == 200 and asked.json()["status"] == "pending_approval"
    approval = hub.approvals.get(asked.json()["approval_id"])
    payload = approval.payload
    assert payload["params"] == {"ticket_id": 7, "priority": "high"} and payload["proposed_by"] == "user:admin"
    assert payload["trigger"] == "task" and not payload["user_steered"] and payload["risk"] == "write"
    assert c.b64u_decode(payload["body_b64"]) == c.body_bytes({"ticket_id": 7, "priority": "high"})
    assert "Reason written by the subsidiary (untrusted):\nTicket 7 is urgent" in approval.detail
    # the person who gave the task never approves the request it led to; an operator does
    assert client.post(f"/api/approvals/{approval.id}", json={"approve": True}).json()["detail"]["code"] == \
        "same_person"
    assert sign_in("operator").post(f"/api/approvals/{approval.id}", json={"approve": True}).status_code == 200
    message = grant_message(hub, wait_for, sub.id)
    body = c.b64u_decode(message["body_b64"])
    assert body == c.body_bytes({"ticket_id": 7, "priority": "high"}) and message["run_id"] == run_id
    grant = json.loads(c.b64u_decode(message["grant"].split(".")[1]))
    assert grant["act"] == "tickets.set_priority" and grant["apv"] == approval.id and grant["bh"] == c.body_hash(body)
    # the model may say anything next: only the approved bytes run, once
    other = c.body_bytes({"ticket_id": 8, "priority": "low"})
    assert sidecar.call(bridge, "tickets.set_priority", grant=message["grant"], body=other)[1]["code"] == \
        "grant_mismatch"
    status, answer = sidecar.call(bridge, "tickets.set_priority", grant=message["grant"], body=body)
    assert status == 200 and answer["ok"] and answer["receipt"]["jti"] == grant["jti"]
    assert sidecar.call(bridge, "tickets.set_priority", grant=message["grant"], body=body)[0] == 409  # grant_used
    result = {"grant_jti": grant["jti"], "status": "executed", "receipt": answer["receipt"],
              "result_summary": "Priority set"}
    posted = sidecar.post(f"actions/{approval.id}/result", result)
    assert posted.status_code == 200 and hub.approvals.get(approval.id).status == "done"
    assert sidecar.post(f"actions/{approval.id}/result", result).status_code == 200  # the same result again
    assert sidecar.post(f"actions/{approval.id}/result", {**result, "status": "failed"}).status_code == 409
    record = actions.grants_of(hub, sub.id)[0]
    assert record.status == "executed" and record.summary == "Priority set"
    kinds = [e.kind for e in audit.all_entries(hub, sub.id)]
    for kind in ("action.request", "action.decision", "grant.issue", "grant.result"):
        assert kind in kinds
    assert audit.verify(hub, sub.id)["ok"]


def test_the_decision_table_refuses_in_order(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    staff = staff_ids(hub)
    run_id = relayed_run(client, sidecar, staff["clerk"])

    def denied(**kw) -> str:
        answer = request(sidecar, **{"run_id": run_id, "agent_id": staff["clerk"], **kw})
        assert answer.status_code == 200 and answer.json()["status"] == "denied", answer.text
        return answer.json()["reason"]

    assert "No such run" in denied(run_id="run_000000000000")
    assert "another staff member" in denied(agent_id=staff["desk"])
    assert "not one of your actions" in denied(action="tickets.delete")
    assert "only reads or drafts" in denied(action="tickets.list", params={})
    assert "do not fit" in denied(params={"ticket_id": 7, "priority": "urgent"})
    assert "do not fit" in denied(params={"ticket_id": 7, "priority": "high", "note": "x"})
    sub = governance.of_tool(hub, TOOL)
    assert governance.usage_day(hub, sub.id, clock()).denied == 6
    # the charter narrows budgets at once: one approval request a day
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"budgets": {
        **sub.charter.budgets.model_dump(), "approval_requests_per_day": 1}})
    assert narrowed.status_code == 200 and narrowed.json()["applied"] is True and narrowed.json()["widening"] == []
    sidecar.heartbeat()
    assert request(sidecar, run_id, staff["clerk"]).json()["status"] == "pending_approval"
    over = request(sidecar, run_id, staff["clerk"])
    assert over.status_code == 429 and over.json()["detail"] | {"message": ""} == {
        "code": "budget", "which": "approval_requests_per_day", "message": ""}
    assert "over_budget" in governance.of_tool(hub, TOOL).flags
    # five refused requests within an hour open the circuit breaker (the tick): the subsidiary pauses
    governance.tick(hub)
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "paused" and "circuit_open" in sub.flags
    assert request(sidecar, run_id, staff["clerk"]).status_code == 423


def test_a_resume_is_not_undone_by_the_refusals_from_before_it(client, tmp_path, wait_for, sign_in):
    """Review (medium): resume cleared circuit_open, but the next tick counted the same refusals of the past hour and
    paused the subsidiary again at once. The breaker counts afresh from the resume - and new refusals still trip it."""
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]

    def refuse_enough() -> None:
        run_id = relayed_run(client, sidecar, clerk)
        for _ in range(governance.CIRCUIT_REFUSALS):
            assert request(sidecar, run_id, clerk, action="tickets.nope", params={}).json()["status"] == "denied"

    refuse_enough()
    governance.tick(hub)
    assert "circuit_open" in governance.of_tool(hub, TOOL).flags
    clock.advance(60)
    resumed = client.post(f"/api/subsidiaries/{TOOL}/resume")
    assert resumed.status_code == 200 and resumed.json()["status"] == "active"
    clock.advance(30)
    governance.tick(hub)
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "active" and "circuit_open" not in sub.flags
    refuse_enough()
    governance.tick(hub)
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "paused" and "circuit_open" in sub.flags


def test_auto_needs_the_guardrail_relaxed_and_never_runs_from_the_panel(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    staff = staff_ids(hub)
    auto = [{"id": "tickets.list", "policy": "allow"}, {"id": "tickets.set_priority", "policy": "auto"}]
    refused = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"actions": auto})
    assert refused.status_code == 400 and "cannot run without approval" in refused.json()["detail"]["message"]
    client.patch("/api/settings/guardrails", json={"subsidiary_tool_writes_need_approval": False})
    widened = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"actions": auto}).json()
    assert widened["applied"] is False and widened["widening"] == [
        "action tickets.set_priority loosened from approval to auto"]
    assert ada.post(f"/api/approvals/{widened['approval_id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: governance.of_tool(hub, TOOL).charter_version == 2)
    sidecar.heartbeat()
    run_id = relayed_run(client, sidecar, staff["clerk"])
    granted = request(sidecar, run_id, staff["clerk"]).json()
    assert granted["status"] == "granted" and granted["approval_id"] == "auto"
    assert c.b64u_decode(granted["body_b64"]) == c.body_bytes({"ticket_id": 7, "priority": "high"})
    assert sidecar.call(bridge, "tickets.set_priority", grant=granted["grant"],
                        body=c.b64u_decode(granted["body_b64"]))[0] == 200
    assert any("without approval" in e["text"] for e in hub.store.tail("activity", 30) if e["level"] == "warn")
    evaluate(client)
    assert control(client, "HB-AC-2")["status"] == "partial"
    # a run started from the panel never gets an auto grant: off, refused; on, always an approval (user-steered)
    sub = governance.of_tool(hub, TOOL)
    panel = gateway.create_run(hub, sub, staff["clerk"], "panel", question_id="q_7")
    from hub.subsidiary.models import ActionRequest

    ask = ActionRequest(run_id=panel.id, agent_id=staff["clerk"], action_id="tickets.set_priority",
                        params={"ticket_id": 7, "priority": "low"})
    assert actions.request_action(hub, sub, ask).status == "denied"
    client.patch("/api/settings/guardrails", json={"subsidiary_panel_actions": True})
    steered = actions.request_action(hub, sub, ask)
    assert steered.status == "pending_approval"
    payload = hub.approvals.get(steered.approval_id).payload
    assert payload["user_steered"] and payload["taint"] == ["panel:q_7"] and "proposed_by" not in payload


def test_auto_grants_count_against_the_daily_requests_and_trip_the_circuit_breaker(
        client, tmp_path, wait_for, sign_in):
    """Review (medium): auto grants skipped the budget step (7.3 step 6 comes before step 7), so a compromised or
    steered sidecar could get unlimited grant-backed writes a day with no circuit breaker."""
    local_model(client)
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    client.patch("/api/settings/guardrails", json={"subsidiary_tool_writes_need_approval": False})
    auto = [{"id": "tickets.list", "policy": "allow"}, {"id": "tickets.set_priority", "policy": "auto"}]
    widened = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"actions": auto}).json()
    assert ada.post(f"/api/approvals/{widened['approval_id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: governance.of_tool(hub, TOOL).charter_version == 2)
    budgets = governance.of_tool(hub, TOOL).charter.budgets.model_dump()
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"budgets": {**budgets,
                                                                                "approval_requests_per_day": 2}})
    assert narrowed.json()["applied"] is True
    sidecar.heartbeat()
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    answers = [request(sidecar, run_id, clerk) for _ in range(6)]
    assert [a.json().get("status") for a in answers[:2]] == ["granted", "granted"]
    assert {(a.status_code, a.json()["detail"]["which"]) for a in answers[2:]} == {(429, "approval_requests_per_day")}
    sub = governance.of_tool(hub, TOOL)
    assert governance.usage_day(hub, sub.id, governance.clock(hub)).approval_requests == 2
    assert len([g for g in actions.grants_of(hub, sub.id) if g.approval_id == "auto"]) == 2
    governance.tick(hub)
    assert "circuit_open" in governance.of_tool(hub, TOOL).flags


def test_a_grant_is_replaced_only_after_it_expired_unused(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    clerk = staff_ids(hub)["clerk"]
    approval_id = request(sidecar, relayed_run(client, sidecar, clerk), clerk).json()["approval_id"]
    sign_in("operator").post(f"/api/approvals/{approval_id}", json={"approve": True})
    old = json.loads(c.b64u_decode(grant_message(hub, wait_for, sub.id)["grant"].split(".")[1]))["jti"]
    unused = {"old_jti": old, "receipt": {"jti": old, "status": "unused"}}
    assert sidecar.post(f"actions/{approval_id}/regrant", unused).json()["detail"]["code"] == "grant_valid"
    clock.advance(c.GRANT_TTL + 1)  # expired, but the bridge still accepts it for the clock leeway
    assert sidecar.post(f"actions/{approval_id}/regrant", unused).json()["detail"]["code"] == "grant_valid"
    clock.advance(c.CLOCK_LEEWAY)
    used = sidecar.post(f"actions/{approval_id}/regrant", {"old_jti": old, "receipt": {"status": "executed"}})
    assert used.status_code == 409 and used.json()["detail"]["code"] == "used"
    again = sidecar.post(f"actions/{approval_id}/regrant", unused)
    assert again.status_code == 200 and again.json()["status"] == "granted"
    new = json.loads(c.b64u_decode(again.json()["grant"].split(".")[1]))["jti"]
    statuses = {g.id: g.status for g in actions.grants_of(hub, sub.id)}
    assert new != old and statuses == {old: "expired", new: "issued"}
    # an issued grant with no result five minutes after it expired: unknown, and its approval failed
    clock.advance(c.GRANT_TTL + actions.UNKNOWN_AFTER + 1)
    governance.tick(hub)
    assert {g.id: g.status for g in actions.grants_of(hub, sub.id)}[new] == "unknown"
    assert hub.approvals.get(approval_id).status == "failed"
    assert hub.approvals.get(approval_id).result["error"] == "not executed in time"


def jti_of(token: str) -> str:
    return json.loads(c.b64u_decode(token.split(".")[1]))["jti"]


def approved_grant(client, sign_in, wait_for, sidecar) -> tuple[str, dict]:
    """One write a person approved: its approval id and the inbox grant message (grant and exact body)."""
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    approval_id = request(sidecar, relayed_run(client, sidecar, clerk), clerk).json()["approval_id"]
    assert sign_in("operator").post(f"/api/approvals/{approval_id}", json={"approve": True}).status_code == 200
    sub_id = governance.of_tool(hub, TOOL).id
    return approval_id, wait_for(lambda: next((m.body for m in runtime.pending(hub, sub_id, 0) if m.type == "grant"
                                               and m.body["approval_id"] == approval_id), None))


def claim_unused(sidecar, approval_id: str, grant: str):
    return sidecar.post(f"actions/{approval_id}/regrant",
                        {"old_jti": jti_of(grant), "receipt": {"jti": jti_of(grant), "status": "unused"}})


def test_a_sidecar_claiming_a_used_grant_unused_gets_no_second_grant(client, tmp_path, wait_for, sign_in):
    """Review (high): one approval, many writes - the sidecar runs grant N, claims it unused once it expired and
    gets grant N+1 for the same body. Atrium now asks the bridge itself: the lie is an alarm, the write ran once."""
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    executed: list[dict] = []
    bridge.bridge.handlers["tickets.set_priority"] = lambda params, ctx: executed.append(params) or {"ok": True}
    approval_id, msg = approved_grant(client, sign_in, wait_for, sidecar)
    status, answer = sidecar.call(bridge, "tickets.set_priority", grant=msg["grant"],
                                  body=c.b64u_decode(msg["body_b64"]))
    assert status == 200 and answer["ok"]  # ... and the sidecar never posts the result
    clock.advance(c.GRANT_TTL + c.CLOCK_LEEWAY + 1)
    governance.tick(hub)
    sidecar.ticket_exp = None
    sidecar.heartbeat()
    lied = claim_unused(sidecar, approval_id, msg["grant"])
    assert lied.status_code == 409 and lied.json()["detail"]["code"] == "used"
    sub = governance.of_tool(hub, TOOL)
    assert sub.alarms[-1]["kind"] == "receipt_mismatch" and "circuit_open" in sub.flags and sub.status == "paused"
    assert len(executed) == 1 and [g.status for g in actions.grants_of(hub, sub.id)] == ["issued"]
    observed = [e for e in audit.all_entries(hub, sub.id) if e.kind == "grant.receipt"]
    assert observed[-1].origin == "observed" and observed[-1].outcome == "executed"


def test_an_approval_is_regranted_once_while_valid_and_after_the_bridge_clock_let_go(
        client, tmp_path, wait_for, sign_in):
    from subsidiary_support import FakeBridge

    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    approval_id, msg = approved_grant(client, sign_in, wait_for, sidecar)
    # a bridge whose clock is 30 s behind still accepts the old grant after Atrium's leeway: wait
    hub.subsidiary_config.bridge_transport = FakeBridge(client, lambda: clock() - 30).transport()
    clock.advance(c.GRANT_TTL + c.CLOCK_LEEWAY + 1)
    late = claim_unused(sidecar, approval_id, msg["grant"])
    assert late.status_code == 409 and late.json()["detail"]["code"] == "grant_valid"
    hub.subsidiary_config.bridge_transport = bridge.transport()
    first = claim_unused(sidecar, approval_id, msg["grant"])
    assert first.status_code == 200 and first.json()["status"] == "granted"
    clock.advance(c.GRANT_TTL + c.CLOCK_LEEWAY + 1)  # the new grant expired unused too: no third one
    again = claim_unused(sidecar, approval_id, first.json()["grant"])
    assert again.status_code == 409 and again.json()["detail"]["code"] == "regrant_limit"
    # and a grant whose approval lapsed meanwhile is never replaced
    approval_id, msg = approved_grant(client, sign_in, wait_for, sidecar)
    approval = hub.approvals.get(approval_id)
    approval.payload["expires_at"] = clock() + c.GRANT_TTL
    hub.store.put("approvals", approval.model_dump(mode="json"))
    clock.advance(c.GRANT_TTL + c.CLOCK_LEEWAY + 1)
    expired = claim_unused(sidecar, approval_id, msg["grant"])
    assert expired.status_code == 409 and expired.json()["detail"]["code"] == "no_longer_valid"
    assert "expired" in expired.json()["detail"]["message"]


def test_an_unverifiable_regrant_goes_back_to_a_person_and_the_old_grant_is_dead(client, tmp_path, wait_for, sign_in):
    from subsidiary_support import unreachable

    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    approval_id, msg = approved_grant(client, sign_in, wait_for, sidecar)
    hub.subsidiary_config.bridge_transport = httpx.MockTransport(unreachable)  # Atrium cannot ask the bridge
    clock.advance(c.GRANT_TTL + c.CLOCK_LEEWAY + 1)
    asked = claim_unused(sidecar, approval_id, msg["grant"])
    assert asked.status_code == 200 and asked.json()["status"] == "pending_approval"
    again = hub.approvals.get(asked.json()["approval_id"])
    assert again.status == "pending" and again.payload["regrant_of"] == approval_id
    assert again.payload["body_b64"] == msg["body_b64"] and "runs it a second time" in again.detail
    old = hub.approvals.get(approval_id)
    assert old.status == "failed" and old.result["asked_again"] == again.id
    # a result for the replaced grant shows its receipt was wrong: the alarm
    late = sidecar.post(f"actions/{approval_id}/result", {"grant_jti": jti_of(msg["grant"]), "status": "executed"})
    assert late.status_code == 409 and late.json()["detail"]["code"] == "superseded"
    assert governance.of_tool(hub, TOOL).alarms[-1]["kind"] == "superseded_grant"


def test_a_write_that_ran_after_a_pause_with_an_already_delivered_grant_is_an_alarm(
        client, tmp_path, wait_for, sign_in):
    """Review (low): pause and the kill switch cannot recall a grant the sidecar already fetched (the bridge accepts it
    until it expires). Atrium revokes it, never re-grants it, and a result showing it ran later is surfaced."""
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub_id = governance.of_tool(hub, TOOL).id
    before_id, before = approved_grant(client, sign_in, wait_for, sidecar)
    after_id, after = approved_grant(client, sign_in, wait_for, sidecar)
    ran = sidecar.call(bridge, "tickets.set_priority", grant=before["grant"], body=c.b64u_decode(before["body_b64"]))
    assert ran[0] == 200  # carried out just before the pause; its result arrives after it
    assert client.post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "check"}).status_code == 200
    assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": False}).status_code == 200
    grants = {g.approval_id: g for g in actions.grants_of(hub, sub_id)}
    assert grants[before_id].revoked_at is not None and grants[after_id].revoked_at is not None
    in_time = sidecar.post(f"actions/{before_id}/result", {"grant_jti": jti_of(before["grant"]), "status": "executed",
                                                           "receipt": ran[1]["receipt"]})
    assert in_time.status_code == 200 and not governance.of_tool(hub, TOOL).alarms
    clock.advance(120)
    late = sidecar.call(bridge, "tickets.set_priority", grant=after["grant"], body=c.b64u_decode(after["body_b64"]))
    assert late[0] == 200  # the bridge cannot be told before the grant expires
    posted = sidecar.post(f"actions/{after_id}/result", {"grant_jti": jti_of(after["grant"]), "status": "executed",
                                                         "receipt": late[1]["receipt"]})
    assert posted.status_code == 200 and hub.approvals.get(after_id).status == "done"
    sub = governance.of_tool(hub, TOOL)
    assert [a["kind"] for a in sub.alarms] == ["write_after_revoke"] and "circuit_open" in sub.flags
    assert any(e.kind == "grant.revoke" for e in audit.all_entries(hub, sub_id))


def test_failing_conformance_puts_an_active_subsidiary_on_hold_until_it_passes_again(
        client, tmp_path, wait_for, sign_in):
    """Review (medium): the bridge is redeployed with a core that ignores grants; Atrium re-runs the vectors and sees
    them fail. While subsidiary_bridge_requires_conformance is on, that subsidiary may no longer act."""
    from subsidiary_support import FakeBridge

    class NoGrants(FakeBridge):
        def handle(self, request):
            saved, c.NEEDS_GRANT = c.NEEDS_GRANT, ()
            try:
                return super().handle(request)
            finally:
                c.NEEDS_GRANT = saved

    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    waiting = request(sidecar, run_id, clerk).json()["approval_id"]
    hub.subsidiary_config.bridge_transport = NoGrants(client, clock).transport()
    rerun = client.post(f"/api/subsidiaries/{TOOL}/conformance").json()
    assert rerun["conformance"]["ok"] is False and rerun["conformance"]["origin"] == "observed"
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "probation" and hub.approvals.get(waiting).status == "rejected"
    sidecar.ticket_exp = None
    ticket = json.loads(c.b64u_decode(sidecar.heartbeat().json()["ticket"].split(".")[1]))
    assert ticket["mode"] == "probation" and "tickets.set_priority" not in ticket["act"]
    refused = request(sidecar, run_id, clerk)
    assert refused.status_code == 200 and refused.json()["status"] == "denied"
    hub.subsidiary_config.bridge_transport = bridge.transport()  # the fixed bridge passes again: active again
    assert client.post(f"/api/subsidiaries/{TOOL}/conformance").json()["conformance"]["ok"] is True
    assert governance.of_tool(hub, TOOL).status == "active"


def test_conformance_that_is_not_current_stops_tickets_requests_and_approvals_even_while_active(
        client, tmp_path, wait_for, sign_in):
    """Review (high, correctness): only the status decided whether a subsidiary could act. An active one whose last
    conformance failed (re-run while the guardrail was off, then switched on again) gets probation tickets, its action
    requests are denied and a waiting one cannot be approved at once; the next tick puts it on probation."""
    from subsidiary_support import FakeBridge

    class NoGrants(FakeBridge):
        def handle(self, request):
            saved, c.NEEDS_GRANT = c.NEEDS_GRANT, ()
            try:
                return super().handle(request)
            finally:
                c.NEEDS_GRANT = saved

    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk)
    guard = "subsidiary_bridge_requires_conformance"
    assert client.patch("/api/settings/guardrails", json={guard: False}).status_code == 200
    hub.subsidiary_config.bridge_transport = NoGrants(client, clock).transport()
    assert client.post(f"/api/subsidiaries/{TOOL}/conformance").json()["conformance"]["ok"] is False
    assert governance.of_tool(hub, TOOL).status == "active"  # not required: shown (HB-AC-8), not enforced
    waiting = request(sidecar, run_id, clerk).json()["approval_id"]
    assert client.patch("/api/settings/guardrails", json={guard: True}).status_code == 200
    sidecar.ticket_exp = None
    ticket = json.loads(c.b64u_decode(sidecar.heartbeat().json()["ticket"].split(".")[1]))
    assert ticket["mode"] == "probation" and "tickets.set_priority" not in ticket["act"]
    denied = request(sidecar, run_id, clerk).json()
    assert denied["status"] == "denied" and "conformance" in denied["reason"]
    decided = sign_in("operator").post(f"/api/approvals/{waiting}", json={"approve": True})
    assert decided.status_code >= 400 and "conformance" in decided.text
    assert not [g for g in actions.grants_of(hub, governance.of_tool(hub, TOOL).id) if g.approval_id == waiting]
    governance.tick(hub)
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "probation" and hub.approvals.get(waiting).status == "rejected"


def test_a_result_for_a_grant_atrium_never_issued_raises_the_alarm(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    forged = sidecar.post("actions/ap_0123456789ab/result", {"grant_jti": "forged-jti", "status": "executed"})
    assert forged.status_code == 404 and forged.json()["detail"]["code"] == "unknown_grant"
    sub = governance.of_tool(hub, TOOL)
    assert sub.status == "paused" and "circuit_open" in sub.flags and sub.alarms[0]["kind"] == "unknown_grant"
    evaluate(client)
    state = control(client, "HB-AC-8")
    assert state["status"] == "fail"


def test_a_rejected_request_reaches_the_staff_member_at_its_next_run(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    clerk = staff_ids(hub)["clerk"]
    approval_id = request(sidecar, relayed_run(client, sidecar, clerk), clerk).json()["approval_id"]
    sign_in("operator").post(f"/api/approvals/{approval_id}", json={"approve": False, "note": "Not now"})
    denied = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "denied"), None))
    assert denied["body"] == {"approval_id": approval_id, "action_id": "tickets.set_priority",
                              "run_id": denied["body"]["run_id"], "agent_id": clerk, "reason": "Not now"}
    client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "Again"})
    run = next(m for m in sidecar.inbox() if m["type"] == "run")
    assert run["body"]["notes"] == [f"Your request {approval_id} (tickets.set_priority) was not approved."]


def test_api_only_writes_run_in_atrium_with_the_hub_credential(client, wait_for, sign_in):
    clock = setup(client)
    hub = client.app.state.hub
    local_model(client)
    sidecar_only_subsidiary(client)
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    message = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "conformance"), None))
    sidecar.post("conformance", {"rows": [{"id": "K1", "ok": True}], "built_at": message["body"]["built_at"]})
    approval = wait_for(lambda: charter_approval(hub))
    ids = [a["id"] for a in governance.of_tool(hub, TOOL).pending_charter.model_dump()["actions"]]
    assert ids == ["records.assets.list", "records.assets.upsert"]
    sign_in("admin", "ada").post(f"/api/approvals/{approval.id}", json={"approve": True})
    wait_for(lambda: governance.of_tool(hub, TOOL).status == "active")
    seen: list[httpx.Request] = []

    def snipeit(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"status": "success", "payload": {"id": 7}})

    hub.connector_transport = httpx.MockTransport(snipeit)
    clerk = next(iter(governance.of_tool(hub, TOOL).charter.staff))
    run_id = relayed_run(client, sidecar, clerk)
    asked = request(sidecar, run_id, clerk, action="records.assets.upsert",
                    params={"external_id": "7", "name": "Laptop 7"}).json()
    assert asked["status"] == "pending_approval"
    assert sign_in("operator").post(f"/api/approvals/{asked['approval_id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: hub.approvals.get(asked["approval_id"]).status == "done")
    assert [(r.method, r.url.path) for r in seen] == [("PATCH", "/api/v1/hardware/7")]
    assert seen[0].headers["authorization"] == f"Bearer {HUB_SECRET}" and OWN_SECRET not in str(seen[0].headers)
    assert json.loads(seen[0].content) == {"name": "Laptop 7"}
    result = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "action_result"), None))
    assert result["body"]["status"] == "executed" and result["body"]["approval_id"] == asked["approval_id"]
