"""Guarded network device changes end to end with the fake firewall (docs/research/canvas-design.md 13/B4): the
guardrails, previews without side effects, proposals that always need an approval, the second-person rule, approvals
bound to the device revision that expire, the kill switch, maintenance windows and emergencies, Atrium's backup
before every apply, verification with rollback (and the backup restored when the device's own rollback fails),
reverts and backup restores as new proposals, the network change-management control, the same binding, expiry and
second-person rules for self-patches, and side-effecting connector actions only through their approval path."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import new_browser
from test_network import API_KEY, fw, refresh  # noqa: F401 - the fixture is used by name
from test_selfpatch import approval_of, configure, git, repo  # noqa: F401 - the fixture is used by name
from test_selfpatch import propose as propose_patch

from hub import connectors
from hub.bus import AgentError
from hub.connectors.base import Connector, ConnectorError, check
from hub.connectors.fake_firewall import FakeFirewallConnector
from hub.extensions import selfpatch
from hub.integration import changes, network
from hub.models import Manifest, Tool

ALLOW = {"firewall": "fw1", "op": "allow", "source_zone": "z:fw1:lan", "target_zone": "z:fw1:opt1",
         "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Users to intranet web"}
FINAL = set(changes.FINAL)


def set_guards(client, **values) -> None:
    response = client.patch("/api/settings/guardrails", json=values)
    assert response.status_code == 200, response.text


def enable(client, window: bool = False) -> None:
    set_guards(client, device_changes=True, device_changes_need_maintenance_window=window)


def get_change(client, change_id: str) -> dict:
    response = client.get(f"/api/segmentation/changes/{change_id}")
    assert response.status_code == 200, response.text
    return response.json()


def wait_status(client, wait_for, change_id: str, statuses=FINAL) -> dict:
    return wait_for(lambda: (c := get_change(client, change_id))["status"] in statuses and c)


def propose(caller, body: dict | None = None, status: int = 201) -> dict:
    response = caller.post("/api/segmentation/changes", json=body or ALLOW)
    assert response.status_code == status, response.text
    return response.json()


def approve(caller, approval_id: str, status: int = 200, approve: bool = True):
    response = caller.post(f"/api/approvals/{approval_id}", json={"approve": approve})
    assert response.status_code == status, response.text
    return response.json()


def tick(client, now: float | None = None) -> dict:
    hub = client.app.state.hub
    return client.portal.call(hub.bus.request, "hub", "module:network", "changes.tick",
                              {"now": now} if now is not None else {})


@pytest.fixture
def admins(sign_in):
    """A second administrator and an operator (the client is the administrator "admin")."""
    return sign_in("admin", "admin2"), sign_in("operator", "op1")


# -- the guardrails and previews ---------------------------------------------------------------------------------


def test_guardrails_are_registered_off_by_default_and_logged(client, fw):
    catalog = {g["key"]: g for g in client.get("/api/settings").json()["guardrail_catalog"]}
    assert catalog["device_changes"]["value"] is False and catalog["device_changes"]["group"] == "network"
    assert catalog["device_changes_need_second_person"]["value"] is True
    assert catalog["device_changes_need_maintenance_window"]["value"] is True
    assert catalog["device_changes_need_backup"]["value"] is True
    assert catalog["approval_expiry_hours"]["value"] == 24 and catalog["approval_expiry_hours"]["max"] == 72
    assert catalog["approvals_need_second_person"]["value"] is False
    assert client.patch("/api/settings/guardrails", json={"approval_expiry_hours": 73}).status_code == 400
    set_guards(client, device_changes=True)
    entry = next(e for e in client.get("/api/activity").json() if "Allow device changes" in e["text"])
    assert entry["level"] == "warn" and "relaxed" in entry["text"] and entry["actor"] == "admin"
    assert next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-CM-3")


def test_guardrail_off_refuses_and_preview_has_no_side_effects(client, fw, admins):
    hub = client.app.state.hub
    refresh(client)
    _, operator = admins
    calls, rev = list(fw.calls), client.get("/api/network/devices/fw1").json()["snapshot"]["rev"]
    preview = operator.post("/api/segmentation/changes/preview", json=ALLOW)
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert body["writable"] is False and body["reason"] == "guardrail"
    assert body["ops"][0]["op"] == "allow" and body["ops"][0]["source"] == {"zone": "lan", "cidrs": ["10.0.10.0/24"]}
    assert body["ops"][0]["services"] == [{"proto": "tcp", "ports": "443"}]
    assert body["diff"].splitlines()[-1].startswith("+ pass in on lan from 10.0.10.0/24 to 10.0.20.0/24 tcp/443 log")
    assert body["violations"] == [] and body["submit_roles"] == ["operator", "admin"]
    assert body["rollback"] == {"mode": "savepoint", "window_s": 60} and body["edge"] == "zp:z:fw1:lan>z:fw1:opt1"
    assert body["impact"]["zones"] == ["z:fw1:lan", "z:fw1:opt1"] and body["steps"][0]["kind"] == "add_rule"
    # no side effects: the device was not contacted, no snapshot, no change, no approval
    assert fw.calls == calls and client.get("/api/network/devices/fw1").json()["snapshot"]["rev"] == rev
    assert hub.store.list(network.CHANGES) == [] and not [a for a in hub.approvals.list() if a.kind == "firewall"]

    refused = operator.post("/api/segmentation/changes", json=ALLOW)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "device_changes_disabled"
    bad = operator.post("/api/segmentation/changes/preview", json={**ALLOW, "services": [{"proto": "tcp"}]})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "invalid"
    anyzone = operator.post("/api/segmentation/changes/preview", json={**ALLOW, "source_zone": "z:internet"})
    assert anyzone.status_code == 422 and "never opens 'any'" in anyzone.json()["detail"]["message"]
    assert operator.post("/api/segmentation/changes/preview", json={**ALLOW, "services": [
        {"proto": "tcp", "ports": str(p)} for p in range(1, 18)]}).status_code == 422  # at most 16 services


def test_proposal_needs_approval_even_when_autonomous_and_the_proposer_cannot_approve(client, fw, admins, wait_for):
    admin2, operator = admins
    assert client.patch("/api/settings", json={"autonomy": "autonomous"}).status_code == 200
    refresh(client)
    enable(client)
    assert operator.post("/api/segmentation/changes/preview", json=ALLOW).json()["writable"] is True
    created = propose(operator)
    change = created["change"]
    assert change["status"] == "proposed" and change["approval"]["status"] == "pending"  # S3
    assert change["proposed_by"] == "op1" and change["base_revision"] == fw.rev and "token" not in change
    approval = next(a for a in client.get("/api/approvals?status=pending").json() if a["id"] == created["approval_id"])
    assert approval["kind"] == "firewall" and approval["requested_by"] == "module:network"
    payload = approval["payload"]
    assert payload["change_id"] == change["id"] and payload["ops_hash"] == change["ops_hash"]
    assert payload["base_revision"] == fw.rev and payload["proposed_by"] == "op1" and payload["diff"].startswith("---")
    assert abs(payload["expires_at"] - change["created_at"] - 24 * 3600) < 5
    assert approval["title"] == "Device change on Edge firewall: allow lan -> opt1 (tcp/443)"
    assert "Users to intranet" not in approval["title"] + approval["detail"]  # no device or free text in titles
    assert "preview_change" in fw.calls and "apply_change" not in fw.calls
    approve(admin2, created["approval_id"])
    assert wait_status(client, wait_for, change["id"])["status"] == "applied"


def test_four_eyes_apply_backup_verify_and_attribution(client, fw, admins, wait_for):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client)
    created = propose(client)  # the administrator "admin" proposes
    same = client.post(f"/api/approvals/{created['approval_id']}", json={"approve": True})
    assert same.status_code == 403 and same.json()["detail"]["code"] == "same_person"
    approve(admin2, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "applied", change
    assert change["decided_by"] == "admin2" and change["result"]["state"] == "applied"
    assert change["applied_at"] >= change["decided_at"] and change["finished_at"] >= change["applied_at"]
    assert [c["name"] for c in change["verification"]] == ["connection", "rules"]
    assert all(c["ok"] for c in change["verification"])
    assert [h["status"] for h in change["history"]] == ["proposed", "approved", "applying", "verifying", "applied"]
    # the order the contract promises: backup before apply, then (after verifying) confirm
    assert fw.calls.index("preview_change") < fw.calls.index("backup", fw.calls.index("preview_change")) \
        < fw.calls.index("apply_change") < fw.calls.index("confirm_change")
    created_rule = next(r for r in fw.rules() if r["description"].startswith(f"atrium:{change['id']}"))
    assert created_rule["source"] == {"cidrs": ["10.0.10.0/24"]} and created_rule["services"] == ALLOW["services"]
    backup = hub.store.get(network.BACKUPS, change["backup_id"])
    assert backup["reason"] == "pre-change" and backup["change_id"] == change["id"]
    assert change["approval"]["status"] == "done"
    # Atrium's own change is attributed, not reported as drift
    refresh(client)
    drift = client.get("/api/network/drift?tool_id=fw1").json()
    assert drift["counts"]["open"] == 0
    assert any(d["change_id"] == change["id"] and d["status"] == "attributed" for d in drift["items"])
    texts = [e["text"] for e in client.get("/api/activity").json()]
    assert any(f"Proposed device change {change['id']}" in t for t in texts)
    assert any(f"Device change {change['id']} on Edge firewall applied" in t for t in texts)
    # the device is writable again (no change in flight) and the segmentation map lists nothing pending
    assert client.get("/api/network/devices").json()["devices"][0]["write"]["writable"] is True


def test_operator_proposals_wait_for_an_admin_and_one_change_at_a_time(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client, window=True)  # no maintenance window: an approved change waits
    created = propose(operator)
    denied = operator.post(f"/api/approvals/{created['approval_id']}", json={"approve": True})
    assert denied.status_code == 403 and denied.json()["detail"]["code"] == "admin_required"
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"], {"scheduled"})
    assert change["scheduled_for"] is None and change["window"] is None
    busy = operator.post("/api/segmentation/changes", json={**ALLOW, "services": [{"proto": "tcp", "ports": "22"}]})
    assert busy.status_code == 409 and busy.json()["detail"]["code"] == "change_in_flight"
    view = client.get("/api/segmentation").json()
    assert view["changes"][0]["id"] == change["id"] and view["changes"][0]["status"] == "scheduled"
    edge = next(e for e in view["edges"] if e["id"] == "zp:z:fw1:lan>z:fw1:opt1")
    assert change["id"] in edge["pending_changes"]


# -- binding, expiry, kill switch --------------------------------------------------------------------------------


def test_revision_changed_before_apply_is_stale_and_nothing_is_applied(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client)
    created = propose(operator)
    fw.change(lambda s: s["rules"][3].update(description="edited on the device"))  # someone else, meanwhile
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "stale" and change["result"]["state"] == "unchanged"
    assert "apply_change" not in fw.calls and change["backup_id"] is None
    assert change["approval"]["status"] == "failed"
    stale = operator.post("/api/segmentation/changes", json={**ALLOW, "base_revision": "r1"})
    assert stale.status_code == 409 and stale.json()["detail"]["code"] == "stale_snapshot"


def test_proposals_expire_and_expired_approvals_cannot_be_approved(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client)
    set_guards(client, approval_expiry_hours=1)
    created = propose(operator)
    change = created["change"]
    assert abs(change["expires_at"] - change["created_at"] - 3600) < 5
    hub = client.app.state.hub
    approval = hub.approvals.get(created["approval_id"])
    hub.store.put("approvals", {**approval.model_dump(mode="json"),
                                "payload": {**approval.payload, "expires_at": time.time() - 1}})
    late = client.post(f"/api/approvals/{created['approval_id']}", json={"approve": True})
    assert late.status_code == 409 and "expired" in late.json()["detail"]
    result = tick(client, now=change["expires_at"] + 1)
    assert result["expired"] == [change["id"]]
    expired = get_change(client, change["id"])
    assert expired["status"] == "expired" and expired["approval"]["status"] == "rejected"
    assert "apply_change" not in fw.calls


def test_guardrail_turned_off_after_approval_blocks_the_change(client, fw, admins, wait_for):
    refresh(client)
    enable(client, window=True)
    created = propose(admins[1])
    approve(client, created["approval_id"])
    wait_status(client, wait_for, created["change"]["id"], {"scheduled"})
    set_guards(client, device_changes=False)  # the kill switch
    change = get_change(client, created["change"]["id"])
    assert change["status"] == "blocked" and change["approval"]["status"] == "failed"
    set_guards(client, device_changes=True, device_changes_need_maintenance_window=False)
    tick(client)
    assert get_change(client, created["change"]["id"])["status"] == "blocked" and "apply_change" not in fw.calls


def test_a_message_claiming_a_decision_changes_nothing(client, fw, admins):
    hub = client.app.state.hub
    refresh(client)
    enable(client)
    created = propose(admins[1])
    for sender in ("agent:helper", "supervisor"):
        client.portal.call(hub.bus.request, sender, "module:network", "approval.decided",
                           {"approval_id": created["approval_id"], "approved": True, "decided_by": "admin2"})
    change = get_change(client, created["change"]["id"])
    assert change["status"] == "proposed" and change["approval"]["status"] == "pending"
    assert "apply_change" not in fw.calls
    # nor can another agent ask for a proposal (only people propose; their role comes from the user store)
    reply = client.portal.call(hub.bus.request, "agent:helper", "module:network", "change.propose", {"request": ALLOW})
    assert reply["refused"]["code"] == "forbidden"


def test_tampered_binding_blocks_the_apply(client, fw, admins, wait_for):
    hub = client.app.state.hub
    refresh(client)
    enable(client, window=True)
    created = propose(admins[1])
    approve(client, created["approval_id"])
    wait_status(client, wait_for, created["change"]["id"], {"scheduled"})
    doc = hub.store.get(network.CHANGES, created["change"]["id"])
    doc["ops"][0]["destination"]["cidrs"] = ["10.0.99.0/24"]  # someone edits the stored ops after the approval
    hub.store.put(network.CHANGES, doc)
    set_guards(client, device_changes_need_maintenance_window=False)
    tick(client)
    change = get_change(client, created["change"]["id"])
    assert change["status"] == "blocked" and "differ from what was approved" in change["history"][-1]["note"]
    assert "apply_change" not in fw.calls
    # the tool supervisor refuses device calls for it too (S8), and anyone but the Network Supervisor
    reply = client.portal.call(hub.bus.request, "module:network", "tool:fw1", "network.apply",
                               {"change_id": change["id"]})
    assert reply["failure"]["state"] == "unchanged" and "Refused" in reply["failure"]["message"]
    for sender in ("agent:helper", "user:admin", "module:vulns"):
        for subject in ("network.apply", "network.confirm", "network.rollback", "network.restore", "network.preview"):
            with pytest.raises(AgentError, match="Network Supervisor"):
                client.portal.call(hub.bus.request, sender, "tool:fw1", subject, {"change_id": change["id"]})
    assert "apply_change" not in fw.calls


# -- verification and rollback ---------------------------------------------------------------------------------


def test_verification_failure_rolls_back_without_confirming(client, fw, admins, wait_for):
    refresh(client)
    enable(client)
    created = propose(admins[1])
    fw.simulate = "verify_fail"  # the device answers success but the rule is not there
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "rolled_back", change
    assert "confirm_change" not in fw.calls and "rollback_change" in fw.calls
    assert change["result"]["state"] == "rolled_back" and "verification failed" in change["history"][-1]["note"]
    assert not [r for r in fw.rules() if (r.get("description") or "").startswith("atrium:")]


def test_failed_device_rollback_restores_atriums_backup(client, fw, admins, wait_for, monkeypatch):
    refresh(client)
    enable(client)
    created = propose(admins[1])
    real_test = FakeFirewallConnector.test

    async def failing_test(self):
        result = await real_test(self)
        if "apply_change" in self.dev.calls:  # after the change, the hub can no longer manage the device
            return {**result, "ok": False, "detail": "management API answers 503"}
        return result

    monkeypatch.setattr(FakeFirewallConnector, "test", failing_test)
    fw.simulate = "rollback_fails"
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "rolled_back", change
    assert change["result"]["method"] == "backup_restore"
    assert fw.calls.index("backup") < fw.calls.index("apply_change") < fw.calls.index("rollback_change") \
        < fw.calls.index("restore_backup")
    assert "confirm_change" not in fw.calls
    assert not [r for r in fw.rules() if (r.get("description") or "").startswith("atrium:")]
    assert any(e["level"] == "error" and change["id"] in e["text"] for e in client.get("/api/activity").json())


def test_failed_backup_refuses_the_apply(client, fw, admins, wait_for, monkeypatch):
    refresh(client)
    enable(client)
    created = propose(admins[1])

    async def broken_backup(self):
        raise ConnectorError("The device refused to export its configuration")

    monkeypatch.setattr(FakeFirewallConnector, "backup", broken_backup)
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "failed" and change["result"]["state"] == "unchanged"
    assert "backup before the change failed" in change["history"][-1]["note"]
    assert "apply_change" not in fw.calls


def test_lockout_waits_for_the_devices_own_rollback(client, fw, admins, wait_for):
    refresh(client)
    enable(client)
    created = propose(admins[1])
    fw.simulate = "lockout"  # after the change the device stops answering until its savepoint timer reverts it
    approve(client, created["approval_id"])
    change = wait_for(lambda: (c := get_change(client, created["change"]["id"])).get("awaiting_revert") and c)
    assert change["status"] == "verifying" and change["result"]["state"] == "reverting"
    assert "confirm_change" not in fw.calls
    later = change["rollback_until"] + 1
    fw.clock = lambda: time.time() + 3600  # the device's own timer has run out
    tick(client, now=later)
    change = get_change(client, change["id"])
    assert change["status"] == "rolled_back" and change["result"]["state"] == "rolled_back"
    assert not [r for r in fw.rules() if (r.get("description") or "").startswith("atrium:")]


# -- policy and anti-lockout -------------------------------------------------------------------------------------


def test_anti_lockout_and_policy_rules(client, fw, admins):
    admin2, operator = admins
    refresh(client)
    enable(client)
    lock = operator.post("/api/segmentation/changes/preview", json={"firewall": "fw1", "op": "disable_rules",
                                                                     "rule_ids": ["fw1:r1"]})
    assert lock.status_code == 200 and lock.json()["problems"] and "anti-lockout" in lock.json()["problems"][0]
    refused = operator.post("/api/segmentation/changes", json={"firewall": "fw1", "op": "disable_rules",
                                                                "rule_ids": ["fw1:r1"]})
    assert refused.status_code == 422 and refused.json()["detail"]["code"] == "lockout"
    block = operator.post("/api/segmentation/changes/preview", json={"firewall": "fw1", "op": "disable_rules",
                                                                      "rule_ids": ["r5"]})
    assert block.status_code == 422 and "only pass rules" in block.json()["detail"]["message"]

    to_mgmt = {**ALLOW, "target_zone": "z:fw1:opt2", "services": [{"proto": "tcp", "ports": "22"}]}
    preview = operator.post("/api/segmentation/changes/preview", json=to_mgmt).json()
    assert preview["violations"][0]["verdict"] == "forbidden" and preview["violations"][0]["control"] == "HB-NW-1"
    assert preview["submit_roles"] == ["admin"] and preview["writable"] is False
    forbidden = operator.post("/api/segmentation/changes", json=to_mgmt)
    assert forbidden.status_code == 422 and forbidden.json()["detail"]["code"] == "policy_forbidden"
    short = client.post("/api/segmentation/changes", json={**to_mgmt, "justification": "because"})
    assert short.status_code == 422 and short.json()["detail"]["code"] == "justification_required"
    created = propose(client, {**to_mgmt, "justification": "Jump host needs SSH to the switches for the migration"})
    assert created["change"]["preview"]["violations"][0]["policy"] == "untrusted-to-management"
    approval = client.app.state.hub.approvals.get(created["approval_id"])
    assert approval.payload["violations"] and approval.payload["justification"].startswith("Jump host")

    disable = operator.post("/api/segmentation/changes/preview", json={"firewall": "fw1", "op": "disable_rules",
                                                                        "rule_ids": ["fw1:r4"], "edge": "nope"}).json()
    assert disable["ops"] == [{"op": "disable_rules", "rules": [{"id": "r4", "vendor_ref": "3b4c-guest-web"}]}]
    assert disable["violations"] == [] and disable["problems"] == [] and disable["edge"].startswith("zp:z:fw1:opt3>")


# -- maintenance windows and emergencies -------------------------------------------------------------------------


def test_maintenance_window_schedules_then_applies_at_its_start(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client, window=True)
    start = time.time() + 3600
    body = {"name": "Night", "devices": ["fw1"], "recurrence": "once", "timezone": "UTC",
            "start": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "end": datetime.fromtimestamp(start + 3600, timezone.utc).isoformat()}
    assert operator.post("/api/network/maintenance-windows", json=body).status_code == 403
    window = client.post("/api/network/maintenance-windows", json=body)
    assert window.status_code == 201, window.text
    window = window.json()
    assert window["next"]["start"] == pytest.approx(start, abs=1) and window["open_now"] is False
    created = propose(operator)
    preview = created["change"]["preview"]["maintenance"]
    assert preview["required"] is True and preview["next"]["window_id"] == window["id"]
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"], {"scheduled"})
    assert change["scheduled_for"] == pytest.approx(start, abs=1) and change["window"]["name"] == "Night"
    assert "apply_change" not in fw.calls
    assert tick(client, now=start - 60)["advanced"] == []  # not yet
    assert get_change(client, change["id"])["status"] == "scheduled"
    tick(client, now=start + 10)
    change = get_change(client, change["id"])
    assert change["status"] == "applied", change
    listing = client.get("/api/network/maintenance-windows").json()
    assert listing["required"] is True and listing["windows"][0]["id"] == window["id"]

    weekly = client.post("/api/network/maintenance-windows", json={
        "name": "Weekend", "recurrence": "weekly", "days": ["sat", "sun"], "start_time": "22:00", "end_time": "02:00",
        "timezone": "Europe/Brussels"})
    assert weekly.status_code == 201, weekly.text
    assert 3 * 3600 <= weekly.json()["next"]["end"] - weekly.json()["next"]["start"] <= 5 * 3600  # 4 h, DST aside
    bad = client.post("/api/network/maintenance-windows", json={**body, "timezone": "Mars/Olympus"})
    assert bad.status_code == 422
    patched = client.patch(f"/api/network/maintenance-windows/{weekly.json()['id']}", json={"enabled": False})
    assert patched.status_code == 200 and patched.json()["enabled"] is False
    assert client.patch("/api/network/maintenance-windows/mw_none", json={"enabled": False}).status_code == 404
    assert client.delete(f"/api/network/maintenance-windows/{window['id']}").status_code == 200
    assert client.delete(f"/api/network/maintenance-windows/{window['id']}").status_code == 404
    unknown = client.post("/api/network/maintenance-windows", json={**body, "devices": ["nope"]})
    assert unknown.status_code == 400


def test_approval_card_shows_maintenance_windows_as_of_now(client, fw, admins):
    """The Approvals card's 'Applied' line: a window an administrator adds after the proposal counts (the payload keeps
    the proposal-time copy); decided approvals carry no live copy."""
    _, operator = admins
    refresh(client)
    enable(client, window=True)
    created = propose(operator)

    def card() -> dict:
        return next(a for a in client.get("/api/approvals").json() if a["id"] == created["approval_id"])

    before = card()
    assert before["payload"]["maintenance"]["open"] is None and before["payload"]["maintenance"]["next"] is None
    assert before["firewall_change"]["maintenance"]["open"] is None and before["firewall_change"]["maintenance"]["required"]
    now = time.time()
    window = client.post("/api/network/maintenance-windows", json={
        "name": "Open now", "devices": ["fw1"], "recurrence": "once", "timezone": "UTC",
        "start": datetime.fromtimestamp(now - 60, timezone.utc).isoformat(),
        "end": datetime.fromtimestamp(now + 3600, timezone.utc).isoformat()})
    assert window.status_code == 201, window.text
    after = card()
    assert after["payload"]["maintenance"]["open"] is None  # what the proposer saw
    live = after["firewall_change"]["maintenance"]
    assert live["open"]["name"] == "Open now" and live["expires_at"] == pytest.approx(after["payload"]["expires_at"])
    approve(client, created["approval_id"], approve=False)
    assert "maintenance" not in card()["firewall_change"]


def test_emergency_apply_outside_the_window(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client, window=True)
    created = propose(operator)
    approve(client, created["approval_id"])
    change_id = wait_status(client, wait_for, created["change"]["id"], {"scheduled"})["id"]
    assert operator.post(f"/api/segmentation/changes/{change_id}/emergency",
                         json={"justification": "x" * 30}).status_code == 403
    short = client.post(f"/api/segmentation/changes/{change_id}/emergency", json={"justification": "now"})
    assert short.status_code == 422 and short.json()["detail"]["code"] == "justification_required"
    response = client.post(f"/api/segmentation/changes/{change_id}/emergency",
                           json={"justification": "Payment outage: the API servers must reach the gateway"})
    assert response.status_code == 202 and response.json()["emergency"]["by"] == "admin"
    change = wait_status(client, wait_for, change_id)
    assert change["status"] == "applied" and "(emergency)" in change["history"][-1]["note"]
    assert any("Emergency" in e["text"] and e["level"] == "warn" for e in client.get("/api/activity").json())
    client.post("/api/grc/evaluate")
    cm3 = next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-CM-3")
    assert cm3["status"] == "partial" and "emergency" in cm3["detail"]
    again = client.post(f"/api/segmentation/changes/{change_id}/emergency", json={"justification": "x" * 30})
    assert again.status_code == 409


# -- reverts, restores, withdrawals ------------------------------------------------------------------------------


def test_revert_is_a_new_approved_change(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client)
    created = propose(operator)
    approve(client, created["approval_id"])
    original = wait_status(client, wait_for, created["change"]["id"])
    assert original["status"] == "applied"
    rule = next(r for r in fw.rules() if (r.get("description") or "").startswith(f"atrium:{original['id']}"))
    revert = operator.post(f"/api/segmentation/changes/{original['id']}/revert", json={})
    assert revert.status_code == 201, revert.text
    proposal = revert.json()["change"]
    assert proposal["op"] == "revert" and proposal["revert_of"] == original["id"] and proposal["status"] == "proposed"
    assert proposal["ops"] == [{"op": "disable_rules", "rules": [{"id": rule["id"], "vendor_ref": rule["vendor_ref"]}]}]
    assert rule.get("enabled", True) is True  # nothing happens without approval (F4)
    approve(client, revert.json()["approval_id"])
    done = wait_status(client, wait_for, proposal["id"])
    assert done["status"] == "applied" and fw.rule(rule["id"])["enabled"] is False
    assert get_change(client, original["id"])["reverted_by"] == proposal["id"]
    twice = operator.post(f"/api/segmentation/changes/{original['id']}/revert", json={})
    assert twice.status_code == 409 and twice.json()["detail"]["code"] == "already_reverted"
    assert operator.post("/api/segmentation/changes/chg_missing/revert", json={}).status_code == 404
    not_applied = operator.post(f"/api/segmentation/changes/{proposal['id']}/revert", json={})
    assert not_applied.status_code == 201  # the revert itself can be reverted (it enables the rule again)


def test_restoring_a_backup_is_a_proposal(client, fw, admins, wait_for):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    taken = operator.post("/api/network/devices/fw1/backups").json()["backup"]
    fw.add_rule({"id": "r9", "action": "pass", "interfaces": ["opt3"], "source": {"nets": ["opt3"]},
                 "destination": {"cidrs": ["10.0.20.0/24"]}, "description": "guest to servers"})
    refresh(client)
    disabled = operator.post(f"/api/network/backups/{taken['id']}/restore", json={})
    assert disabled.status_code == 403 and disabled.json()["detail"]["code"] == "device_changes_disabled"
    enable(client)
    created = operator.post(f"/api/network/backups/{taken['id']}/restore", json={"justification": "undo r9"})
    assert created.status_code == 201, created.text
    change = created.json()["change"]
    assert change["op"] == "restore" and change["request"]["backup_id"] == taken["id"] and change["ops"] == []
    assert "\n-rule r9 #8:" in change["preview"]["diff"]  # the backup matches the stored snapshot of its revision
    assert "restore_backup" not in fw.calls
    approve(client, created.json()["approval_id"])
    done = wait_status(client, wait_for, change["id"])
    assert done["status"] == "applied", done
    assert "restore_backup" in fw.calls and not any(r["id"] == "r9" for r in fw.rules())
    assert hub.store.get(network.BACKUPS, done["backup_id"])["reason"] == "pre-change"
    refresh(client)
    drift = client.get("/api/network/drift?tool_id=fw1").json()["items"]
    assert [(d["kind"], d["status"]) for d in drift if d["subject"] == "r9"] == [
        ("rule_removed", "attributed"), ("rule_added", "open")]  # the restore is Atrium's; r9 was someone's
    assert next(d for d in drift if d["kind"] == "rule_removed")["change_id"] == done["id"]
    assert client.post("/api/network/backups/bk_missing/restore", json={}).status_code == 404


def test_withdrawing(client, fw, admins, sign_in):
    admin2, operator = admins
    other = sign_in("operator", "op2")
    refresh(client)
    enable(client)
    created = propose(operator)
    change_id = created["change"]["id"]
    assert other.delete(f"/api/segmentation/changes/{change_id}").json()["detail"]["code"] == "not_proposer"
    withdrawn = operator.delete(f"/api/segmentation/changes/{change_id}")
    assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawn"
    assert withdrawn.json()["approval"]["status"] == "rejected"
    assert operator.delete(f"/api/segmentation/changes/{change_id}").status_code == 409
    second = propose(operator)
    assert client.delete(f"/api/segmentation/changes/{second['change']['id']}").status_code == 200  # an admin may
    listing = client.get("/api/segmentation/changes?firewall=fw1").json()
    assert listing["counts"]["withdrawn"] == 2 and listing["total"] == 2
    assert client.get("/api/segmentation/changes?status=bogus").status_code == 400


# -- payloads, compliance --------------------------------------------------------------------------------------


def test_no_secrets_or_tokens_in_change_payloads_and_events(client, fw, admins, wait_for):
    hub = client.app.state.hub
    events = hub.bus.subscribe(maxsize=5000)
    refresh(client)
    enable(client)
    created = propose(admins[1])
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    token = changes.token(hub, change["id"])
    assert token
    texts = [json.dumps(client.get(path).json()) for path in (
        f"/api/segmentation/changes/{change['id']}", "/api/segmentation/changes", "/api/approvals", "/api/activity",
        "/api/messages", "/api/segmentation")]
    seen = []
    while not events.empty():
        seen.append(events.get_nowait())
    hub.bus.unsubscribe(events)
    texts.append(json.dumps(seen))
    secret = fw.state["secrets"]["admin_password_hash"]
    for text in texts:
        assert API_KEY not in text and token not in text and secret not in text
    assert any(e["type"] == "firewall_change" for e in seen)


def test_network_change_management_control(client, fw):
    def cm3():
        client.post("/api/grc/evaluate")
        return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-CM-3")

    first = cm3()
    assert first["refs"]["ISO27001"] == "A.8.32" and "CyFun2025" in first["refs"]
    refresh(client)
    assert cm3()["status"] == "pass"
    set_guards(client, device_changes_need_maintenance_window=False)
    assert cm3()["status"] == "partial"
    set_guards(client, device_changes_need_second_person=False)
    assert cm3()["status"] == "fail" and "second administrator" in cm3()["detail"]
    set_guards(client, device_changes_need_second_person=True, device_changes_need_backup=False)
    assert cm3()["status"] == "fail"


def test_change_management_remembers_changes_made_while_a_guardrail_was_off(client, fw, admins, wait_for):
    """Review finding: HB-CM-3 read only the guardrails' current values. An administrator could switch the
    second-person rule off, approve their own change, switch it on again and the control passed at once."""
    from hub.connectors.netmodel import display_id

    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client)

    def cm3():  # judged with every guardrail on (the changes below are applied without maintenance windows)
        set_guards(client, device_changes_need_maintenance_window=True)
        client.post("/api/grc/evaluate")
        control = next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-CM-3")
        set_guards(client, device_changes_need_maintenance_window=False)
        return control

    reviewed = propose(client)  # reviewed by a second administrator, backed up: nothing to report
    approve(admin2, reviewed["approval_id"])
    assert wait_status(client, wait_for, reviewed["change"]["id"])["self_approved"] is False
    assert cm3()["status"] == "pass"

    refresh(client)
    set_guards(client, device_changes_need_second_person=False)
    own = propose(client, {**ALLOW, "services": [{"proto": "tcp", "ports": "8443"}]})
    approve(client, own["approval_id"])  # the proposer approves it
    own_id = own["change"]["id"]
    change = wait_status(client, wait_for, own_id)
    assert change["status"] == "applied" and change["self_approved"] is True and change["backup_id"]
    set_guards(client, device_changes_need_second_person=True)
    control = cm3()
    assert control["status"] == "partial" and "approved by the person who proposed them" in control["detail"]
    assert own_id in control["detail"] and reviewed["change"]["id"] not in control["detail"]
    assert any("1 approved by their proposer, 0 without a backup" in e for e in control["evidence"])

    refresh(client)
    set_guards(client, device_changes_need_backup=False)
    bare = propose(operator, {**ALLOW, "services": [{"proto": "tcp", "ports": "9443"}]})
    approve(admin2, bare["approval_id"])
    assert wait_status(client, wait_for, bare["change"]["id"])["backup_id"] is None
    set_guards(client, device_changes_need_backup=True)
    control = cm3()
    assert control["status"] == "partial" and "without a configuration backup" in control["detail"]
    assert bare["change"]["id"] in control["detail"] and own_id in control["detail"]

    # changes recorded before the flag existed are judged from their approval
    stored = hub.store.get(changes.CHANGES, own_id)
    stored.pop("self_approved")
    hub.store.put(changes.CHANGES, stored)
    facts = changes.compliance_facts(hub)
    assert facts["self_approved_90d"] == [display_id(own_id)] and facts["unbacked_90d"] == [display_id(bare["change"]["id"])]


# -- second person, binding and expiry (self-patches), side-effecting connector actions ----------------------------


def test_second_person_rule_for_other_approvals(client, sign_in):
    hub = client.app.state.hub
    flow = hub.approvals.create("flow", "Proposed flow", "", {"flow_id": "fl_x", "proposed_by": "admin"}, "supervisor")
    patch = hub.approvals.create("self_patch", "Change Atrium", "", {"self_patch_id": "sp_x", "proposed_by": "admin"},
                                 "patcher")
    set_guards(client, approvals_need_second_person=True)
    for approval in (flow, patch):
        refused = client.post(f"/api/approvals/{approval.id}", json={"approve": True})
        assert refused.status_code == 403 and refused.json()["detail"]["code"] == "same_person", approval.kind
    assert client.post(f"/api/approvals/{flow.id}", json={"approve": False}).status_code == 200  # rejecting is fine
    other = sign_in("admin", "admin2")
    assert other.post(f"/api/approvals/{patch.id}", json={"approve": True}).status_code == 409  # its guard: no patch
    set_guards(client, approvals_need_second_person=False)
    third = hub.approvals.create("flow", "Proposed flow", "", {"flow_id": "fl_y", "proposed_by": "admin"}, "supervisor")
    assert client.post(f"/api/approvals/{third.id}", json={"approve": True}).status_code == 200
    expired = hub.approvals.create("flow", "Old", "", {"flow_id": "fl_z", "expires_at": time.time() - 5}, "supervisor")
    assert client.post(f"/api/approvals/{expired.id}", json={"approve": True}).status_code == 409


class ScanConnector(Connector):
    kind = "fake_scanner"
    title = "Fake scanner"
    actions = {"scan", "scan_status"}
    side_effect_actions = {"scan": "scan"}
    capabilities = {"vulnerabilities": {"read"}}
    started: list[dict] = []

    async def test(self):
        return {"ok": True, "detail": "ok", "checks": [check("api", True)], "domains": self.domains()}

    async def action(self, name, params):
        if name == "scan":
            ScanConnector.started.append(params)
            return {"job_id": "j1"}
        return {"status": "running", "progress": 10, "done": False}


def test_side_effecting_connector_actions_need_their_approval_path(client, monkeypatch):
    hub = client.app.state.hub
    monkeypatch.setitem(connectors.REGISTRY, "fake_scanner", ScanConnector)
    ScanConnector.started = []
    tool = Tool(id="scanner", name="Scanner", source_type="saas", source="https://scanner.example.net", status="ready",
                manifest=Manifest(id="scanner", name="Scanner", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    assert client.put("/api/tools/scanner/connection", json={"kind": "fake_scanner", "config": {},
                                                             "secrets": {}}).status_code == 200

    def action(sender: str, name: str, **extra) -> dict:
        return client.portal.call(hub.bus.request, sender, "tool:scanner", "connector.action",
                                  {"name": name, "params": {"hosts": ["10.0.0.5"]}, **extra})

    for sender in ("agent:helper", "module:network", "module:assets", "supervisor"):
        reply = action(sender, "scan")
        assert "Refused" in reply["failure"]["message"] and "scan approval path" in reply["failure"]["message"], sender
    assert ScanConnector.started == []
    assert action("agent:helper", "scan_status")["result"]["status"] == "running"  # read-only stays open
    for name in ("apply_change", "allow", "restore", "backup"):  # device writes are never connector actions
        assert "not a connector action" in action("user:admin", name)["failure"]["message"]
    assert action("module:vulns", "scan")["result"]["job_id"] == "j1"  # the scan path (it applies the scan policy)
    assert action("user:admin", "scan")["result"]["job_id"] == "j1"  # a person decides themselves
    wrong = hub.approvals.create("flow", "x", "", {"tool_id": "scanner"}, "supervisor")
    reply = action("module:vulns", "scan", approval_id=wrong.id)
    assert "does not cover" in reply["failure"]["message"] and len(ScanConnector.started) == 2
    with pytest.raises(TypeError, match="unknown actions"):
        type("Broken", (Connector,), {"actions": {"a"}, "side_effect_actions": {"b": "scan"}})


def test_self_patch_approval_is_bound_to_its_commit_and_expires(client, repo, wait_for):
    hub = client.app.state.hub
    configure(client, repo)
    patch = propose_patch(client)
    approval = hub.approvals.get(patch.approval_id)
    assert approval.payload["commit"] == patch.commit and len(patch.commit) == 40
    assert abs(approval.payload["expires_at"] - approval.created_at - 24 * 3600) < 5
    # the branch moved after the tests ran: the worktree is no longer at the approved commit - nothing is merged
    git(Path(patch.worktree), "commit", "-q", "--allow-empty", "-m", "sneaked in")
    client.post(f"/api/approvals/{patch.approval_id}", json={"approve": True})
    failed = wait_for(lambda: (a := approval_of(client, patch.approval_id))["status"] == "failed" and a)
    assert "approved commit" in failed["result"]["detail"]
    assert not (repo / "hub" / "hello.py").exists() and git(repo, "log", "-1", "--pretty=%s") == "initial"

    second = propose_patch(client, title="Add hello again")
    stored = selfpatch.get(hub, second.id)
    stored.commit = "0" * 40  # the record no longer matches what the approval was requested for
    selfpatch.save(hub, stored)
    moved = client.post(f"/api/approvals/{second.approval_id}", json={"approve": True})
    assert moved.status_code == 409 and "moved" in moved.json()["detail"]
    third = propose_patch(client, title="Add hello once more")
    late = hub.approvals.get(third.approval_id)
    hub.store.put("approvals", {**late.model_dump(mode="json"), "payload": {**late.payload, "expires_at": time.time() - 1}})
    expired = client.post(f"/api/approvals/{third.approval_id}", json={"approve": True})
    assert expired.status_code == 409 and "expired" in expired.json()["detail"]


def test_without_the_backup_guardrail_no_backup_is_taken(client, fw, admins, wait_for):
    refresh(client)
    enable(client)
    set_guards(client, device_changes_need_backup=False)
    created = propose(admins[1])
    calls = len(fw.calls)
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "applied" and change["backup_id"] is None and "backup" not in fw.calls[calls:]
    card = next(a for a in client.get("/api/approvals").json() if a["id"] == created["approval_id"])
    assert card["firewall_change"]["status"] == "applied" and card["firewall_change"]["id"] == change["id"]
    assert "token" not in card["firewall_change"]


def test_a_device_without_a_rollback_mechanism_is_not_writable(client, fw, admins, monkeypatch):
    hub = client.app.state.hub
    refresh(client)
    enable(client)

    class NoRollback(FakeFirewallConnector):
        network_write = {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "none", "window_s": 0}

        def write_capability(self):
            return Connector.write_capability(self)

    monkeypatch.setitem(connectors.REGISTRY, "fake_firewall", NoRollback)
    assert network.write_capability(hub, "fw1") is None
    summary = client.get("/api/network/devices").json()["devices"][0]["write"]
    assert summary["capable"] is False and summary["writable"] is False and summary["reason"] == "not_capable"
    refused = admins[1].post("/api/segmentation/changes", json=ALLOW)
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "not_writable"


# -- review fixes: restores need a writable device; tokens, look-alike user names and side decisions under the
# -- second-person rule; restores the policy cannot check; retention of revert points; windows after the expiry -------


def reconnect(client, **config) -> None:
    """The fw1 connection saved again with other settings (the stored API key is kept), then tested."""
    response = client.put("/api/tools/fw1/connection", json={"kind": "fake_firewall", "secrets": {},
                                                             "config": {"device": "fw1", **config}})
    assert response.status_code == 200, response.text
    assert client.post("/api/tools/fw1/connection/test").json()["ok"]


def test_restore_needs_a_writable_device(client, fw, admins, wait_for):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client)
    taken = operator.post("/api/network/devices/fw1/backups").json()["backup"]
    for config in ({"read_only": True}, {"rollback": "none"}):  # "never change this firewall", no rollback mechanism
        reconnect(client, **config)
        summary = client.get("/api/network/devices/fw1").json()
        assert summary["write"]["capable"] is False and summary["write"]["reason"] == "not_capable", config
        assert summary["backup"]["supported"] is True and summary["backup"]["restore"] is True
        refused = operator.post(f"/api/network/backups/{taken['id']}/restore", json={"justification": "go back"})
        assert refused.status_code == 403 and refused.json()["detail"]["code"] == "not_writable", config
        assert refused.json()["detail"]["reason"] == "not_capable"
    assert hub.store.list(network.CHANGES) == [] and "restore_backup" not in fw.calls

    # writable when proposed and approved, read only by the time it is applied: the tool supervisor refuses it (S8)
    reconnect(client)
    enable(client, window=True)
    created = operator.post(f"/api/network/backups/{taken['id']}/restore", json={})
    assert created.status_code == 201, created.text
    change_id = created.json()["change"]["id"]
    approve(admin2, created.json()["approval_id"])
    wait_status(client, wait_for, change_id, {"scheduled"})
    reconnect(client, read_only=True)
    assert client.post(f"/api/segmentation/changes/{change_id}/emergency",
                       json={"justification": "Restore the known good configuration now"}).status_code == 202
    change = wait_status(client, wait_for, change_id)
    assert change["status"] == "failed" and change["result"]["state"] == "unchanged", change
    assert "read only" in change["history"][-1]["note"] and "restore_backup" not in fw.calls


def test_an_api_token_counts_as_the_person_who_created_it(client, fw, admins, wait_for):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client, window=True)
    created = propose(client)  # the administrator "admin", in a session
    made = client.post("/api/tokens", json={"name": "admin-ci", "role": "admin"})
    assert made.status_code == 201, made.text
    bot = new_browser(client, headers={"Authorization": f"Bearer {made.json()['token']}", "X-Hub-Request": "1"})
    # device changes are approved by people on the Approvals page, never with a token (S4, S5)
    refused = bot.post(f"/api/approvals/{created['approval_id']}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "person_required"
    assert hub.approvals.get(created["approval_id"]).status == "pending" and "apply_change" not in fw.calls
    assert bot.post(f"/api/approvals/{created['approval_id']}", json={"approve": False}).status_code == 200  # rejecting

    # a proposal made with the admin's token is the admin's own: they cannot approve it, another administrator can
    by_token = propose(bot)
    assert by_token["change"]["proposed_by"] == "token:admin-ci"
    payload = hub.approvals.get(by_token["approval_id"]).payload
    assert payload["proposer_ids"] == ["admin", "token:admin-ci"]
    same = client.post(f"/api/approvals/{by_token['approval_id']}", json={"approve": True})
    assert same.status_code == 403 and same.json()["detail"]["code"] == "same_person"
    # ... also once the token is revoked (who proposed it was recorded with the approval)
    token_id = next(t["id"] for t in client.get("/api/tokens").json() if t["name"] == "admin-ci")
    assert client.delete(f"/api/tokens/{token_id}").status_code == 200
    again = client.post(f"/api/approvals/{by_token['approval_id']}", json={"approve": True})
    assert again.status_code == 403 and again.json()["detail"]["code"] == "same_person"

    # the Network Supervisor checks it again before applying: an approval recorded around the API is blocked
    for decided_by, why in (("admin", "second person"), ("token:admin-ci", "API token")):
        approval = hub.approvals.get(by_token["approval_id"])
        hub.store.put("approvals", {**approval.model_dump(mode="json"), "status": "approved", "decided_by": decided_by,
                                    "decided_at": time.time()})
        doc = hub.store.get(network.CHANGES, by_token["change"]["id"])
        problem = changes.binding_problem(hub, {**doc, "status": "approved"})
        assert problem is not None and problem[0] == "blocked" and why in problem[1], decided_by
    hub.store.put(network.CHANGES, {**hub.store.get(network.CHANGES, by_token["change"]["id"]), "status": "approved"})
    set_guards(client, device_changes_need_maintenance_window=False)
    tick(client)
    blocked = get_change(client, by_token["change"]["id"])
    assert blocked["status"] == "blocked" and "API token" in blocked["history"][-1]["note"]
    assert "apply_change" not in fw.calls

    # the general rule (approvals_need_second_person) resolves tokens the same way
    set_guards(client, approvals_need_second_person=True)
    made = client.post("/api/tokens", json={"name": "admin-ci-2", "role": "admin"}).json()["token"]
    bot2 = new_browser(client, headers={"Authorization": f"Bearer {made}", "X-Hub-Request": "1"})
    flow = hub.approvals.create("flow", "Proposed flow", "", {"flow_id": "fl_t", "proposed_by": "admin"}, "supervisor")
    refused = bot2.post(f"/api/approvals/{flow.id}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "same_person"
    assert admin2.post(f"/api/approvals/{flow.id}", json={"approve": True}).status_code == 200


def test_user_names_that_look_like_agent_ids_are_people(client, fw, sign_in, wait_for):
    from hub.approvals import identities, person, sender_person

    hub = client.app.state.hub
    assert person("operator") == "operator" and person("user:system") == "system" and person("module:network") is None
    assert sender_person("operator") is None and sender_person("user:operator") == "operator"
    assert sender_person("token:ci") == "token:ci" and identities(hub, "agent:x") == set()
    refresh(client)
    enable(client)
    as_operator, as_system, as_hub = sign_in("admin", "operator"), sign_in("admin", "system"), sign_in("admin", "hub")
    created = propose(as_operator)
    assert created["change"]["proposed_by"] == "operator"
    same = as_operator.post(f"/api/approvals/{created['approval_id']}", json={"approve": True})
    assert same.status_code == 403 and same.json()["detail"]["code"] == "same_person"
    approve(as_system, created["approval_id"])  # four eyes between two such administrators works
    assert wait_status(client, wait_for, created["change"]["id"])["status"] == "applied"
    second = propose(as_system, {**ALLOW, "services": [{"proto": "tcp", "ports": "8443"}]})
    approve(as_hub, second["approval_id"])
    assert wait_status(client, wait_for, second["change"]["id"])["status"] == "applied"

    set_guards(client, approvals_need_second_person=True)  # the general rule holds for them too
    flow = hub.approvals.create("flow", "Proposed flow", "", {"flow_id": "fl_s", "proposed_by": "system"}, "supervisor")
    refused = as_system.post(f"/api/approvals/{flow.id}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "same_person"


def test_enabling_a_proposed_flow_in_its_list_follows_the_second_person_rule(client, fw, sign_in):
    from hub.integration import flows

    hub = client.app.state.hub
    set_guards(client, approvals_need_second_person=True)
    proposer, other = sign_in("operator", "op9"), sign_in("operator", "op10")
    flow = next(f for f in flows.all_flows(hub) if f.domain == "network")
    approval = hub.approvals.create("flow", "Data flow: fw1", "", {"flow_id": flow.id, "tool_id": "fw1",
                                                                   "proposed_by": "op9"}, "supervisor")
    flow.status, flow.approval_id = "proposed", approval.id
    flows.save(hub, flow)
    refused = proposer.patch(f"/api/flows/{flow.id}", json={"status": "enabled", "schedule_minutes": 5})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "same_person"
    # nothing changed: the flow is still a proposal (schedule included) and its approval still waits
    stored = flows.get(hub, flow.id)
    assert stored.status == "proposed" and stored.schedule_minutes == flow.schedule_minutes
    assert hub.approvals.get(approval.id).status == "pending"
    enabled = other.patch(f"/api/flows/{flow.id}", json={"status": "enabled"})
    assert enabled.status_code == 200 and enabled.json()["status"] == "enabled"
    decided = hub.approvals.get(approval.id)
    assert decided.status in ("approved", "done") and decided.decided_by == "op10"


def test_a_restore_the_policy_cannot_check_takes_the_forbidden_path(client, fw, admins):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client)
    taken = operator.post("/api/network/devices/fw1/backups").json()["backup"]
    doc = hub.store.get(network.BACKUPS, taken["id"])
    hub.store.put(network.BACKUPS, {**doc, "revision": "r-from-before-atrium"})  # no stored snapshot has it
    refused = operator.post(f"/api/network/backups/{taken['id']}/restore", json={"justification": "x" * 30})
    assert refused.status_code == 422 and refused.json()["detail"]["code"] == "policy_unknown"
    short = client.post(f"/api/network/backups/{taken['id']}/restore", json={"justification": "go back"})
    assert short.status_code == 422 and short.json()["detail"]["code"] == "justification_required"
    created = client.post(f"/api/network/backups/{taken['id']}/restore",
                          json={"justification": "Back to the configuration from before the migration"})
    assert created.status_code == 201, created.text
    change = created.json()["change"]
    assert change["preview"]["policy_unknown"] is True and change["preview"]["violations"] == []
    assert hub.approvals.get(created.json()["approval_id"]).payload["policy_unknown"] is True
    assert any("segmentation policy" in n for n in change["preview"]["notes"])


def test_revert_points_and_recovery_points_survive_manual_backups(client, fw, admins, wait_for):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)  # takes the scheduled backup
    assert client.patch("/api/network/settings", json={"backup_retention": 3}).status_code == 200
    taken = operator.post("/api/network/devices/fw1/backups").json()["backup"]
    fw.add_rule({"id": "r9", "action": "pass", "interfaces": ["opt3"], "source": {"nets": ["opt3"]},
                 "destination": {"cidrs": ["10.0.20.0/24"]}, "description": "guest to servers"})
    refresh(client)
    enable(client)
    created = operator.post(f"/api/network/backups/{taken['id']}/restore", json={}).json()
    approve(admin2, created["approval_id"])
    done = wait_status(client, wait_for, created["change"]["id"])
    assert done["status"] == "applied" and done["backup_id"]
    for _ in range(6):  # "take backup now" again and again
        assert operator.post("/api/network/devices/fw1/backups").status_code == 201
    kept = client.get("/api/network/backups?tool_id=fw1").json()["backups"]
    assert done["backup_id"] in {b["id"] for b in kept}  # the applied restore's revert point
    assert {b["reason"] for b in kept} >= {"scheduled", "pre-change", "manual"}  # manual ones only push out manual ones
    assert sum(1 for b in kept if b["reason"] == "manual") == 1
    revert = operator.post(f"/api/segmentation/changes/{done['id']}/revert", json={})
    assert revert.status_code == 201, revert.text
    assert revert.json()["change"]["request"]["backup_id"] == done["backup_id"]


def test_a_window_that_opens_after_the_approval_expires_is_flagged(client, fw, admins, wait_for):
    admin2, operator = admins
    refresh(client)
    enable(client, window=True)
    start = time.time() + 3 * 86400  # the approval expires after 24 h
    body = {"name": "Far away", "devices": ["fw1"], "recurrence": "once", "timezone": "UTC",
            "start": datetime.fromtimestamp(start, timezone.utc).isoformat(),
            "end": datetime.fromtimestamp(start + 3600, timezone.utc).isoformat()}
    assert client.post("/api/network/maintenance-windows", json=body).status_code == 201
    preview = operator.post("/api/segmentation/changes/preview", json=ALLOW).json()["maintenance"]
    assert preview["expires_before_window"] is True and preview["next"]["start"] == pytest.approx(start, abs=1)
    created = propose(operator)
    assert created["change"]["preview"]["maintenance"]["expires_before_window"] is True
    approve(client, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"], {"scheduled"})
    assert change["expires_before_window"] is True and "expires before that window opens" in change["history"][-1]["note"]
    card = next(a for a in client.get("/api/approvals").json() if a["id"] == created["approval_id"])
    assert card["firewall_change"]["expires_before_window"] is True
    assert tick(client, now=change["expires_at"] + 1)["expired"] == [change["id"]]
    assert "apply_change" not in fw.calls
    # a window inside the approval's lifetime is not flagged
    soon = time.time() + 3600
    assert client.post("/api/network/maintenance-windows", json={
        **body, "name": "Soon", "start": datetime.fromtimestamp(soon, timezone.utc).isoformat(),
        "end": datetime.fromtimestamp(soon + 3600, timezone.utc).isoformat()}).status_code == 201
    assert operator.post("/api/segmentation/changes/preview", json=ALLOW).json()["maintenance"]["expires_before_window"] is False
