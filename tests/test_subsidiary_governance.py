"""Governance of subsidiaries by Atrium (round4-spec 3, 4.14, 7.4-7.8, 10): the lifecycle to active, tickets,
conformance (Atrium-run and sidecar-run), pause, resume, stop, the kill switch within the ticket lifetime, the tick,
the staff's hold, the audit chain and compliance control HB-AC-8. A fake tool runs the reference bridge; a scripted
fake sidecar stands in for the sidecar. No tool, model or network is used."""

from __future__ import annotations

import json

import pytest
from subsidiary_support import (MANIFEST_RAW, OWN_SECRET, TOOL, FakeBridge, approve_charter, bridge_subsidiary,
                                charter, enrolled, setup, sidecar_only_subsidiary)

from hub import guardrails
from hub.grc.checks import Snapshot, evaluate_controls
from hub.models import AgentDef
from hub.subsidiary import audit, conformance, contract as c, governance, keys, runtime


def control(client, control_id: str) -> dict:
    return next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == control_id)


def evaluate(client) -> None:
    client.portal.call(client.app.state.hub.bus.request, "user:admin", "module:grc", "evaluate", {}, 60)


def wait_conformance(client, hub, wait_for, tool_id=TOOL):
    return wait_for(lambda: governance.of_tool(hub, tool_id).conformance)


def ticket_payload(hub, token: str) -> dict:
    sub = governance.of_tool(hub, TOOL)
    return c.verify_ticket(token, [c.public_key(k) for k in keys.public_keys(hub, sub.id)], tool=TOOL, sub=sub.id,
                           now=int(hub.subsidiary_config.clock()))


# -- the lifecycle -----------------------------------------------------------------------------------------------------


def test_a_bridge_subsidiary_goes_from_proposal_to_active_with_tickets(client, tmp_path, wait_for):
    clock = setup(client)
    hub = client.app.state.hub
    sub_id = bridge_subsidiary(client, tmp_path)
    bridge = FakeBridge(client, clock)
    hub.subsidiary_config.bridge_transport = bridge.transport()
    env = (hub.settings.workspace / "adapters" / TOOL / "subsidiary" / "bridge.env").read_text()
    assert f"ATRIUM_BRIDGE_KEYS={keys.bridge_keys(hub, sub_id)}" in env and f"ATRIUM_SUBSIDIARY_ID={sub_id}" in env
    assert governance.of_tool(hub, TOOL).status == "deploying"
    sidecar = enrolled(client, clock)
    assert governance.of_tool(hub, TOOL).status == "probation"
    beat = sidecar.heartbeat().json()
    assert beat["status"] == "probation" and beat["ticket"] and beat["charter_version"] == 0
    probation = ticket_payload(hub, beat["ticket"])
    assert probation["mode"] == "probation" and probation["act"] == list(c.PROBATION_BUILTINS)
    assert probation["cnf"] == sidecar.public and probation["exp"] - probation["iat"] == 600
    # the heartbeat started Atrium-run conformance: observed, passed, against the approved manifest
    result = wait_conformance(client, hub, wait_for)
    assert result.ok and result.origin == "observed" and result.by == "atrium"
    assert [r.id for r in result.rows] == [f"V{n}" for n in range(1, 21)]
    assert result.manifest_sha256 == c.manifest_sha256(MANIFEST_RAW) and "/.atrium/v1/health" in bridge.calls
    assert governance.of_tool(hub, TOOL).status == "probation"  # a charter still has to be approved
    # the charter approval activates it; the next ticket lists the charter's actions
    approve_charter(client)
    assert governance.of_tool(hub, TOOL).status == "active"
    sidecar.ticket_exp = None
    active = ticket_payload(hub, sidecar.heartbeat().json()["ticket"])
    assert active["mode"] == "active" and active["cv"] == 1 and active["rl"] == {"calls_per_min": 30,
                                                                                   "panel_per_user_hour": 10}
    assert active["act"] == ["tickets.list", "tickets.set_priority", *c.PROBATION_BUILTINS]
    status, answer = sidecar.call(bridge, "tickets.list")
    assert status == 200 and answer["result"] == [{"id": 1}]
    # renewed at half-life only
    assert sidecar.heartbeat().json()["ticket"] is None
    clock.advance(301)
    assert sidecar.heartbeat().json()["ticket"]
    kinds = [e["kind"] for e in client.get(f"/api/subsidiaries/{TOOL}/audit").json()["entries"]]
    assert kinds.count("ticket.issue") == 2 and "conformance" in kinds and "status.active" in kinds


def test_a_failing_bridge_stays_on_probation(client, tmp_path, wait_for):
    clock = setup(client)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    other_manifest = MANIFEST_RAW.replace(b"Open tickets", b"All tickets")  # not the approved bytes: V19 fails
    hub.subsidiary_config.bridge_transport = FakeBridge(client, clock, manifest=other_manifest).transport()
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    result = wait_conformance(client, hub, wait_for)
    assert not result.ok and [r.id for r in result.rows if not r.ok] == ["V19"]
    approve_charter(client)
    assert governance.of_tool(hub, TOOL).status == "probation"
    assert ticket_payload(hub, sidecar.heartbeat().json()["ticket"])["mode"] == "probation"


def test_the_sidecar_runs_conformance_when_atrium_cannot_reach_the_bridge(client, tmp_path, wait_for):
    clock = setup(client)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    bridge = FakeBridge(client, clock)  # Atrium cannot reach it (setup's transport): the sidecar can
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    message = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "conformance"), None))
    assert len(message["body"]["vectors"]) == 20
    rows = bridge.run(message["body"]["vectors"])
    posted = sidecar.post("conformance", {"rows": rows, "built_at": message["body"]["built_at"]})
    assert posted.status_code == 200 and posted.json() == {"ok": True, "status": "probation"}
    recorded = governance.of_tool(hub, TOOL).conformance
    assert recorded.ok and recorded.origin == "claimed" and recorded.by == "sidecar"
    # results cannot be posted twice
    assert sidecar.post("conformance", {"rows": rows, "built_at": message["body"]["built_at"]}).status_code == 409
    approve_charter(client)
    assert governance.of_tool(hub, TOOL).status == "active"
    evaluate(client)
    state = control(client, "HB-AC-8")
    assert state["status"] == "partial" and "only claimed by its sidecar" in state["detail"]


def test_an_api_only_subsidiary_proves_k1_to_k3(client, wait_for):
    clock = setup(client)
    hub = client.app.state.hub
    sidecar_only_subsidiary(client)
    sidecar = enrolled(client, clock)
    assert sidecar.heartbeat().json()["ticket"] is None  # no bridge, no tickets
    message = wait_for(lambda: next((m for m in sidecar.inbox() if m["type"] == "conformance"), None))
    assert [v["id"] for v in message["body"]["vectors"]] == ["K1"]
    posted = sidecar.post("conformance", {"rows": [{"id": "K1", "ok": True, "detail": "connector test passed"}],
                                          "built_at": message["body"]["built_at"]})
    assert posted.json()["ok"] is True
    rows = {r.id: r.ok for r in governance.of_tool(hub, TOOL).conformance.rows}
    assert rows == {"K1": True, "K2": True, "K3": True}
    approve_charter(client, chart=charter("sidecar_only"))
    assert governance.of_tool(hub, TOOL).status == "active"
    # K3 fails once the dedicated credential equals the hub's (only possible with the guardrail off)
    from subsidiary_support import HUB_SECRET

    client.patch("/api/settings/guardrails", json={"subsidiary_separate_credential": False})
    client.put(f"/api/subsidiaries/{TOOL}/credential", json={"secrets": {"token": HUB_SECRET}})
    client.patch("/api/settings/guardrails", json={"subsidiary_separate_credential": True})
    assert {r.id: r.ok for r in conformance.atrium_rows(hub, governance.of_tool(hub, TOOL))} == {"K2": True,
                                                                                                "K3": False}


# -- pause, resume, stop -----------------------------------------------------------------------------------------------


def active_bridge(client, tmp_path, wait_for):
    clock = setup(client)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    bridge = FakeBridge(client, clock)
    hub.subsidiary_config.bridge_transport = bridge.transport()
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    wait_conformance(client, hub, wait_for)
    approve_charter(client)
    sidecar.ticket_exp = None
    sidecar.heartbeat()
    assert governance.of_tool(hub, TOOL).status == "active"
    return clock, hub, bridge, sidecar


def test_pause_stops_work_at_once_and_resuming_releases_no_backlog(client, tmp_path, sign_in, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    runtime.post(hub, sub.id, "run", {"run_id": "run_1", "agent_id": "agent:clerk", "trigger": "schedule",
                                      "correlation_id": "co_1"})
    waiting = hub.approvals.create("subsidiary_action", "Change a priority", "", {"subsidiary_id": sub.id},
                                   f"tool:{TOOL}")
    operator = sign_in("operator")
    paused = operator.post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "Investigating"})
    assert paused.status_code == 200 and paused.json()["status"] == "paused"
    assert hub.approvals.get(waiting.id).status == "rejected"
    assert [m["type"] for m in sidecar.inbox()] == ["pause"]  # the queued run was cancelled
    beat = sidecar.heartbeat().json()
    assert beat["status"] == "paused" and beat["ticket"] is None
    held = sidecar.get("charter")
    assert held.status_code == 423 and held.json()["detail"]["code"] == "paused"
    assert governance.hold(hub, governance.staff(hub, sub)[0]) == "the Helpdesk subsidiary is paused by Atrium"
    # within the ticket lifetime the bridge still answers reads, after it nothing
    assert sidecar.call(bridge, "tickets.list")[0] == 200
    clock.advance(11 * 60)
    assert sidecar.call(bridge, "tickets.list") == (401, {"ok": False, "code": "expired"})
    # operators pause, administrators resume - signed in as a person
    assert operator.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 403
    token = client.post("/api/tokens", json={"name": "ops", "role": "admin"}).json()["token"]
    as_token = client.post(f"/api/subsidiaries/{TOOL}/resume", headers={"Authorization": f"Bearer {token}"})
    assert as_token.status_code == 403 and as_token.json()["detail"]["code"] == "person_required"
    resumed = client.post(f"/api/subsidiaries/{TOOL}/resume")
    assert resumed.status_code == 200 and resumed.json()["status"] == "active"
    assert [m["type"] for m in sidecar.inbox()] == ["resume"]
    sidecar.ticket_exp = None
    assert ticket_payload(hub, sidecar.heartbeat().json()["ticket"])["mode"] == "active"
    assert governance.hold(hub, governance.staff(hub, governance.of_tool(hub, TOOL))[0]) is None


def test_a_pause_the_sidecar_never_fetched_is_not_delivered_after_the_resume(client, tmp_path, sign_in, wait_for):
    """Paused and resumed between two polls: the sidecar gets the resume and the work queued after it, never the stale
    pause (which would idle it again and drop that work until its next heartbeat)."""
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    assert sign_in("operator").post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "a minute"}).status_code == 200
    assert client.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 200
    runtime.post(hub, sub.id, "run", {"run_id": "run_1", "agent_id": "agent:clerk", "trigger": "task",
                                      "correlation_id": "co_1"})
    assert [m["type"] for m in sidecar.inbox()] == ["resume", "run"]
    for step in ("pause", "resume", "pause"):  # only the latest of them reaches a sidecar that did not poll meanwhile
        assert client.post(f"/api/subsidiaries/{TOOL}/{step}", json={}).status_code == 200
    assert [m["type"] for m in sidecar.inbox()] == ["pause"]


def test_stop_revokes_the_token_rotates_the_key_and_disables_the_staff(client, tmp_path, sign_in, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    old_keys = keys.bridge_keys(hub, sub.id)
    assert sign_in("operator").post(f"/api/subsidiaries/{TOOL}/stop", json={"confirm": "Helpdesk"}).status_code == 403
    wrong = client.post(f"/api/subsidiaries/{TOOL}/stop", json={"confirm": "helpdesk2"})
    assert wrong.status_code == 400 and wrong.json()["detail"]["code"] == "confirm"
    assert client.post(f"/api/subsidiaries/{TOOL}/stop", json={"confirm": "Helpdesk"}).json()["status"] == "stopped"
    assert sidecar.heartbeat().status_code == 401  # the token is revoked
    assert not any(d.enabled for d in governance.staff(hub, sub))
    assert keys.bridge_keys(hub, sub.id) != old_keys
    env = (hub.settings.workspace / "adapters" / TOOL / "subsidiary" / "bridge.env").read_text()
    assert "ATRIUM_BRIDGE_KEYS=\n" in env  # the adapter's copy no longer lets a bridge start
    # the deployed bridge (old keys) refuses a ticket signed with the new key (V3 behaviour)
    forged, _ = keys.issue_ticket(hub, sub.id, tool=TOOL, cv=1, mode="active", act=["tickets.list"],
                                  cnf=sidecar.public, now=int(clock()))
    sidecar.ticket = forged
    assert sidecar.call(bridge, "tickets.list") == (401, {"ok": False, "code": "bad_ticket"})
    # a stopped subsidiary is archived, and the tool may get a new one
    assert client.post(f"/api/tools/{TOOL}/subsidiary", json={"mode": "bridge"}).status_code == 201
    assert governance.get(hub, sub.id).status == "archived"
    assert client.get(f"/api/subsidiaries/{TOOL}").json()["id"] != sub.id


def test_archive_needs_a_stopped_subsidiary(client):
    setup(client)
    sidecar_only_subsidiary(client)
    assert client.delete(f"/api/subsidiaries/{TOOL}").status_code == 409
    client.post(f"/api/subsidiaries/{TOOL}/stop", json={"confirm": TOOL})
    archived = client.delete(f"/api/subsidiaries/{TOOL}")
    assert archived.status_code == 200 and archived.json()["status"] == "archived"
    sub = governance.of_tool(client.app.state.hub, TOOL, archived=True)
    assert sub.credential is None and all(r.status == "retired" for r in keys.records(client.app.state.hub, sub.id))
    assert client.get("/api/subsidiaries").json()["subsidiaries"] == []


def test_the_kill_switch_pauses_every_subsidiary(client, tmp_path, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    charter_approval = hub.approvals.create("subsidiary_charter", "Charter v2", "", {"subsidiary_id": sub.id},
                                            f"tool:{TOOL}")
    assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": False}).status_code == 200
    assert governance.of_tool(hub, TOOL).status == "paused"
    assert hub.approvals.get(charter_approval.id).status == "rejected"
    disabled = sidecar.get("charter")
    assert disabled.status_code == 423 and disabled.json()["detail"]["code"] == "disabled"
    beat = sidecar.heartbeat()
    assert beat.status_code == 200 and beat.json()["status"] == "paused" and beat.json()["ticket"] is None
    texts = [(e["level"], e["text"]) for e in client.get("/api/activity").json()]
    assert any(level == "warn" and "Subsidiaries switched off: 1 paused" in text for level, text in texts)
    # on again is logged as relaxing; nothing resumes on its own
    client.patch("/api/settings/guardrails", json={"allow_subsidiaries": True})
    assert any(e["level"] == "warn" and "relaxed" in e["text"] and e["data"].get("guardrail") == "allow_subsidiaries"
               for e in client.get("/api/activity").json())
    assert governance.of_tool(hub, TOOL).status == "paused"
    assert client.post(f"/api/subsidiaries/{TOOL}/resume").json()["status"] == "active"
    clock.advance(1)
    assert sidecar.call(bridge, "tickets.list")[0] == 200


# -- the tick, the hold, effective autonomy ----------------------------------------------------------------------------


def test_the_tick_flags_offline_sidecars_and_expired_enrollments(client, sign_in):
    clock = setup(client)
    hub = client.app.state.hub
    sidecar_only_subsidiary(client)
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    clock.advance(governance.OFFLINE_AFTER + 1)
    assert governance.tick(hub) == [governance.of_tool(hub, TOOL).id]
    assert governance.of_tool(hub, TOOL).flags == ["offline"]
    assert sidecar.heartbeat().json()["flags"] == []
    client.post(f"/api/subsidiaries/{TOOL}/enrollment")
    clock.advance(31 * 60)
    governance.tick(hub)
    assert governance.of_tool(hub, TOOL).enrollment is None
    # a skewed clock is flagged
    assert sidecar.heartbeat(clock=clock() + 300).status_code == 401  # the new enrollment revoked the token


def test_clock_skew_and_bridge_mismatch(client, tmp_path, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    assert "clock_skew" in sidecar.heartbeat(clock=clock() + 300).json()["flags"]
    beat = sidecar.heartbeat(bridge_ping={"ok": True, "manifest_sha256": "f" * 64, "contract": c.CONTRACT,
                                          "secret": "never stored"}).json()
    assert "bridge_mismatch" in beat["flags"]
    sub = governance.of_tool(hub, TOOL)
    assert sub.sidecar.bridge_ping == {"ok": True, "manifest_sha256": "f" * 64, "contract": c.CONTRACT}
    sidecar.ticket_exp = None
    assert ticket_payload(hub, sidecar.heartbeat().json()["ticket"])["mode"] == "probation"
    assert "the bridge in the tool changed" in governance.hold(hub, governance.staff(hub, sub)[0])
    rerun = client.post(f"/api/subsidiaries/{TOOL}/conformance")
    assert rerun.status_code == 200 and rerun.json()["by"] == "atrium" and rerun.json()["conformance"]["ok"]
    assert "bridge_mismatch" not in governance.of_tool(hub, TOOL).flags


def test_sidecar_staff_always_wait_for_approval(client):
    setup(client)
    hub = client.app.state.hub
    client.patch("/api/settings", json={"autonomy": "autonomous"})
    client.patch("/api/settings/guardrails", json={"team_actions_need_approval": False})
    hub.store.put("agent_defs", AgentDef(id="agent:desk", name="Desk", team=TOOL, placement="sidecar",
                                         permissions=["read"], parent=f"tool:{TOOL}").model_dump(mode="json"))
    hub.store.put("agent_defs", AgentDef(id="agent:helper", name="Helper", team=TOOL,
                                         permissions=["read"], parent=f"tool:{TOOL}").model_dump(mode="json"))
    assert governance.is_staff(hub, "agent:desk") and not governance.is_staff(hub, "agent:helper")
    assert guardrails.effective_autonomy(hub, "agent:desk") == "manual"
    assert guardrails.effective_autonomy(hub, "agent:helper") == "autonomous"
    helper, desk = (AgentDef.model_validate(hub.store.get("agent_defs", a)) for a in ("agent:helper", "agent:desk"))
    assert governance.hold(hub, helper) is None and governance.hold(hub, desk) == f"{TOOL} has no subsidiary"
    client.patch("/api/settings/guardrails", json={"allow_subsidiaries": False})
    assert "switched off" in governance.hold(hub, desk)


def test_rotating_the_signing_key_is_staged(client, tmp_path, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    staged = client.post(f"/api/subsidiaries/{TOOL}/rotate-key").json()
    assert [k["status"] for k in staged["keys"]] == ["current", "next"] and staged["bridge_keys"].count(",") == 1
    assert "private" not in json.dumps(staged)
    env = (hub.settings.workspace / "adapters" / TOOL / "subsidiary" / "bridge.env").read_text()
    assert staged["bridge_keys"] in env
    finished = client.post(f"/api/subsidiaries/{TOOL}/rotate-key?finish=1").json()
    assert [k["status"] for k in finished["keys"]] == ["retired", "current"] and "," not in finished["bridge_keys"]
    assert client.post(f"/api/subsidiaries/{TOOL}/rotate-key?finish=1").status_code == 409
    assert keys.records(hub, sub.id)[0].private == ""


# -- the audit trail ---------------------------------------------------------------------------------------------------


def test_a_sidecar_cannot_flood_the_audit_trail_or_block_the_hub(client, wait_for, tmp_path, monkeypatch):
    """Review (medium): every heartbeat wrote up to 500 claimed entries into the never-pruned chain, on the event
    loop. Now: at most SPOOL_MAX a heartbeat, per-hour and per-day caps (the rest counted, noted once an hour), and
    the writes run off the event loop."""
    import threading

    from hub.subsidiary.models import SPOOL_MAX

    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    monkeypatch.setattr(governance, "CLAIMED_PER_HOUR", 150)
    monkeypatch.setattr(governance, "CLAIMED_PER_DAY", 250)
    writers: set[int] = set()
    original = audit.claimed

    def claimed(*args, **kw):
        writers.add(threading.get_ident())
        return original(*args, **kw)
    monkeypatch.setattr(audit, "claimed", claimed)

    async def loop_thread() -> int:
        return threading.get_ident()

    def beat(n: int = SPOOL_MAX, dropped: int = 0):
        lines = [{"ts": clock(), "kind": "bridge.read", "action_id": "tickets.list"} for _ in range(n)]
        answer = sidecar.heartbeat(spool=lines, spool_dropped=dropped)
        assert answer.status_code == 200, answer.text
    assert sidecar.heartbeat(spool=[{"ts": clock(), "kind": "x"}] * (SPOOL_MAX + 1)).status_code == 422
    beat(), beat(), beat(dropped=7)  # 100 recorded, then 50, then none: the hour's cap
    clock.advance(3600)
    beat(), beat()  # a new hour: 100 more, then the day's cap
    entries = audit.all_entries(hub, sub.id)
    assert sum(1 for e in entries if e.origin == "claimed") == 250
    assert [e.origin for e in entries if e.kind == "spool.capped"] == ["observed", "observed"]
    assert governance.usage_day(hub, sub.id, clock()).claimed_dropped == 50 + 107 + 100
    assert writers and client.portal.call(loop_thread) not in writers  # recorded off the event loop
    assert audit.verify(hub, sub.id)["ok"]


def test_the_audit_chain_verifies_and_detects_tampering(client, sign_in, wait_for, tmp_path):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    sidecar.heartbeat(spool=[{"ts": clock(), "kind": "bridge.read", "action_id": "tickets.list",
                              "detail": {"sha256": "ab" * 32, "length": 120, "Text": "a whole ticket"}}])
    viewer = sign_in("viewer")
    trail = viewer.get(f"/api/subsidiaries/{TOOL}/audit").json()
    claimed = next(e for e in trail["entries"] if e["origin"] == "claimed")
    assert claimed["kind"] == "bridge.read" and "detail" not in claimed
    assert viewer.get(f"/api/subsidiaries/{TOOL}/audit?detail=1").status_code == 403
    detailed = client.get(f"/api/subsidiaries/{TOOL}/audit?detail=1").json()["entries"]
    assert next(e for e in detailed if e["origin"] == "claimed")["detail"] == {
        "claimed_at": clock(), "sha256": "ab" * 32, "length": 120}  # keys outside the simple form are dropped
    assert sign_in("operator").post(f"/api/subsidiaries/{TOOL}/audit/verify").json()["ok"] is True
    evaluate(client)
    assert control(client, "HB-AC-8")["status"] == "pass"
    # someone edits an entry in the database: the chain no longer verifies, an alarm is raised, HB-AC-8 fails
    with hub.store._lock, hub.store._db:
        seq, data = hub.store._db.execute("SELECT seq, data FROM log WHERE stream = ? ORDER BY seq LIMIT 1 OFFSET 2",
                                          (audit.stream(sub.id),)).fetchone()
        row = json.loads(data)
        row["entry"]["outcome"] = "edited"
        hub.store._db.execute("UPDATE log SET data = ? WHERE seq = ?", (json.dumps(row), seq))
    result = client.post(f"/api/subsidiaries/{TOOL}/audit/verify").json()
    assert result["ok"] is False and result["problems"][0]["seq"] == 3
    assert governance.of_tool(hub, TOOL).alarms[0]["kind"] == "audit_chain"
    evaluate(client)
    state = control(client, "HB-AC-8")
    assert state["status"] == "fail" and "alarm" in state["detail"]


# -- HB-AC-8 and the guardrails --------------------------------------------------------------------------------------


def snapshot(live=(), **guards) -> Snapshot:
    return Snapshot(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[], autonomy="assisted",
                    audit_entries=1, guardrails={**guardrails.defaults(), **guards},
                    subsidiaries={"live": list(live), "counts": {}, "audit_entries": 5})


def fact(**fields) -> dict:
    return {"id": "sub_0123456789ab", "tool_id": TOOL, "mode": "bridge", "status": "active", "flags": [],
            "charter_version": 1, "charter_approved": True,
            "conformance": {"ok": True, "origin": "observed", "current": True}, "alarms_90d": 0, "offline_hours": 0,
            "untested_bridge": False, **fields}


def hb_ac_8(live=(), **guards):
    return {s.id: s for s in evaluate_controls(snapshot(live, **guards), {})}["HB-AC-8"]


def test_hb_ac_8_follows_the_subsidiaries_and_their_guardrails():
    assert hb_ac_8().status == "na"
    assert hb_ac_8([fact()]).status == "pass" and hb_ac_8([fact(status="probation", charter_approved=False,
                                                               conformance=None)]).status == "pass"
    for guards, text in (({"subsidiary_panel_actions": True}, "tool users can steer subsidiary write requests"),
                         ({"subsidiary_separate_credential": False}, "use the hub's own tool credential"),
                         ({"subsidiary_ticket_minutes": 30}, "kill switch takes up to 30 minutes")):
        state = hb_ac_8([fact()], **guards)
        assert state.status == "partial" and text in state.detail, guards
    for extra, text in (({"flags": ["bridge_mismatch"]}, "changed since it was approved"),
                        ({"offline_hours": 30}, "offline for 30 hours"),
                        ({"conformance": {"ok": True, "origin": "claimed", "current": True}}, "only claimed"),
                        ({"untested_bridge": True}, "without the tool's tests")):
        state = hb_ac_8([fact(**extra)])
        assert state.status == "partial" and text in state.detail, extra
    for extra, text in (({"charter_approved": False}, "without an approved charter"),
                        ({"conformance": None}, "without passing conformance"),
                        ({"flags": ["owner_disabled"]}, "no longer has an enabled administrator"),
                        ({"alarms_90d": 1}, "alarm")):
        state = hb_ac_8([fact(**extra)])
        assert state.status == "fail" and text in state.detail, extra
    relaxed = hb_ac_8([fact()], subsidiary_bridge_requires_conformance=False)
    assert relaxed.status == "fail" and "Bridges must pass conformance" in relaxed.detail
    assert hb_ac_8([fact(conformance=None)], subsidiary_bridge_requires_conformance=False).status == "fail"
    assert "HB-AC-8" in {s.id for s in evaluate_controls(snapshot(), {})}


def test_the_subsidiary_guardrails_map_to_their_controls():
    catalog = {g["key"]: g for g in guardrails.catalog({})}
    assert {k for k, g in catalog.items() if g["group"] == "subsidiaries"} == {
        "allow_subsidiaries", "subsidiary_tool_writes_need_approval", "subsidiary_panel_actions",
        "subsidiary_bridge_requires_tests", "subsidiary_bridge_requires_conformance",
        "subsidiary_separate_credential", "subsidiary_ticket_minutes", "subsidiary_max_tokens_per_day"}
    assert catalog["allow_subsidiaries"]["value"] is False and catalog["subsidiary_ticket_minutes"]["max"] == 60
    assert not any(g["relaxed"] for g in catalog.values())
    state = {s.id: s for s in evaluate_controls(snapshot(subsidiary_tool_writes_need_approval=False), {})}
    assert state["HB-AC-2"].status == "partial" and "reversible in-tool writes" in state["HB-AC-2"].detail
    state = {s.id: s for s in evaluate_controls(snapshot(subsidiary_bridge_requires_tests=False), {})}
    assert state["HB-CM-2"].status == "fail" and "Bridge patches must pass" in state["HB-CM-2"].detail
    assert "5 subsidiary audit entries" in " ".join(state["HB-OP-2"].evidence)


def test_relaxing_a_subsidiary_guardrail_is_logged(client):
    client.patch("/api/settings/guardrails", json={"subsidiary_ticket_minutes": 20})
    entry = next(e for e in client.get("/api/activity").json() if e["data"].get("guardrail") ==
                 "subsidiary_ticket_minutes")
    assert entry["level"] == "warn" and "relaxed" in entry["text"]


@pytest.mark.parametrize("value", [0, 61])
def test_the_ticket_lifetime_is_bounded(client, value):
    assert client.patch("/api/settings/guardrails", json={"subsidiary_ticket_minutes": value}).status_code == 400


def test_the_dedicated_credential_never_reaches_the_activity_log(client):
    setup(client)
    sidecar_only_subsidiary(client)
    assert OWN_SECRET not in json.dumps(client.get("/api/activity").json())


def test_removing_the_tool_stops_and_archives_its_subsidiary(client, tmp_path, wait_for):
    clock, hub, bridge, sidecar = active_bridge(client, tmp_path, wait_for)
    sub = governance.of_tool(hub, TOOL)
    assert client.delete(f"/api/tools/{TOOL}").status_code == 200
    gone = governance.get(hub, sub.id)
    assert gone.status == "archived" and gone.stopped_by == "admin"
    assert sidecar.heartbeat().status_code == 401
    assert all(r.status == "retired" for r in keys.records(hub, sub.id))
    assert audit.verify(hub, sub.id)["ok"]  # the audit trail stays
