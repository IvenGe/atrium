"""Regression tests for the security-core review's core findings (F23, F24, F25, F26, F38): races, a paused agent's
backlog, the network history cost and log growth - each plays the scenario of the finding."""

from __future__ import annotations

import asyncio
import threading
import time

from test_fabric import FakeInventory, add_tool, connect, flows_of, plan_and_enable, remote  # noqa: F401
from test_network import fw, refresh  # noqa: F401
from test_network_changes import admins, approve, enable, propose, wait_status  # noqa: F401
from test_selfpatch import configure, git, repo  # noqa: F401
from test_selfpatch import propose as propose_self_patch

from hub.connectors.fake_firewall import FakeFirewallConnector
from hub.extensions import selfpatch
from hub.integration import network


# -- F23: a slow pull that read the device before a change never overwrites the post-change snapshot --------------------


def test_slow_pull_cannot_overwrite_the_snapshot_a_change_verified(client, fw, admins, wait_for, monkeypatch):
    hub = client.app.state.hub
    admin2, operator = admins
    refresh(client)
    enable(client)
    gate = {"armed": False, "event": None, "held": False}
    original = FakeFirewallConnector.pull

    async def pull(self, domain, since=None):
        records = await original(self, domain, since)  # reads the device now ...
        if gate["armed"]:
            gate["armed"], gate["held"], gate["event"] = False, True, asyncio.Event()
            await gate["event"].wait()  # ... and delivers late (a slow device, a big rule base)
        return records

    monkeypatch.setattr(FakeFirewallConnector, "pull", pull)
    flow = next(f for f in client.get("/api/flows?tool_id=fw1").json() if f["domain"] == "network")
    gate["armed"] = True
    client.portal.call(hub.bus.tell, "hub", "module:network", "flow.run", {"flow_id": flow["id"], "trigger": "schedule"})
    wait_for(lambda: gate["held"])
    # a change proposed meanwhile waits for the device: the pull holds it until its read is stored
    threading.Timer(1.0, lambda: client.portal.call(gate["event"].set)).start()
    created = propose(operator)
    approve(admin2, created["approval_id"])
    change = wait_status(client, wait_for, created["change"]["id"])
    assert change["status"] == "applied", change
    stored = hub.store.get("network_snapshots", "fw1")
    assert [r for r in stored["record"]["rules"] if r.get("marker") == change["id"]]  # the snapshot has the new rule
    refresh(client)  # and the next pull reports no drift "not made through Atrium"
    drift = client.get("/api/network/drift?tool_id=fw1").json()
    assert drift["counts"]["open"] == 0, drift


def test_a_read_older_than_the_stored_snapshot_is_not_stored(client, fw):
    hub = client.app.state.hub
    refresh(client)
    before = hub.store.get("network_snapshots", "fw1")
    stale = {**before["record"], "rules": [], "read_at": before["read_at"] - 60}
    result = network.ingest(hub, "fw1", stale)
    assert result["stale"] and not result["changed"]
    after = hub.store.get("network_snapshots", "fw1")
    assert after["rev"] == before["rev"] and after["record"]["rules"] == before["record"]["rules"]


# -- F24: "Apply again" while the approval's own apply runs ---------------------------------------------------------------


def test_apply_again_during_the_approved_apply_is_refused_and_the_merge_stands(client, repo, wait_for):
    hub = client.app.state.hub
    state = {"slowed": False, "in_merge": False, "done": None}

    async def slow_git(args, cwd, timeout, env=None):
        if "merge" in args and "--no-ff" in args and not state["slowed"]:
            state["slowed"] = state["in_merge"] = True
            await asyncio.sleep(1.5)  # a merge that takes a moment
            state["done"] = await selfpatch.default_runner(args, cwd, timeout, env)
            return state["done"]
        return await selfpatch.default_runner(args, cwd, timeout, env)

    configure(client, repo, git_runner=slow_git)
    patch = propose_self_patch(client)
    assert client.post(f"/api/approvals/{patch.approval_id}", json={"approve": True}).status_code == 200
    wait_for(lambda: state["in_merge"])
    listed = next(p for p in client.get("/api/self-patches").json()["patches"] if p["id"] == patch.id)
    assert listed["status"] == "approved" and not listed["error"]  # the UI offers "Apply again" only after a failure
    again = client.post(f"/api/self-patches/{patch.id}/apply")
    assert again.status_code == 409
    wait_for(lambda: state["done"] is not None, timeout=20)
    final = wait_for(lambda: (p := selfpatch.get(hub, patch.id)) and p.status == "merged" and p)
    assert final.merge_commit and not final.error
    assert git(repo, "log", "-1", "--pretty=%s").startswith("Merge Atrium self-patch")
    assert wait_for(lambda: hub.approvals.get(patch.approval_id).status == "done")
    # a finished approval stays done, whatever a later attempt reports
    hub.approvals.complete(patch.approval_id, False, {"error": "late"})
    assert hub.approvals.get(patch.approval_id).status == "done"
    assert client.post(f"/api/self-patches/{patch.id}/apply").status_code == 400  # merged: nothing to apply


# -- F25: a paused agent gets no backlog, and a disabled flow is not run automatically -------------------------------------


def test_paused_owner_gets_no_backlog_and_disabled_flows_do_not_run(client, remote, wait_for, monkeypatch):
    hub = client.app.state.hub
    pulls = []
    original = FakeInventory.pull

    async def counting_pull(self, domain, since=None):
        pulls.append(time.time())
        return await original(self, domain, since)

    monkeypatch.setattr(FakeInventory, "pull", counting_pull)
    remote.assets = {"1": {"external_id": "1", "name": "web-1", "type": "server", "addresses": ["10.0.0.5"]}}
    add_tool(client, "inventory", "Inventory", provides=["assets.inventory"])
    connect(client, "inventory", "fake_inventory")
    [flow] = plan_and_enable(client, wait_for, "inventory", 1)
    assert client.patch("/api/agents/module:assets", json={"paused": True}).json()["paused"]
    agent = hub.agents.get("module:assets")
    now = time.time()
    started = sum(len(client.portal.call(hub.tick_flows, now + i * 31 * 60)["started"]) for i in range(6))
    assert started == 0 and agent.inbox.qsize() == 0  # nothing queues up for a paused agent
    network_agent = hub.agents.get("module:network")
    client.patch("/api/agents/module:network", json={"paused": True})
    for i in range(20):
        client.portal.call(hub.tick_flows, now + i * 30)
    assert network_agent.inbox.qsize() == 0
    client.patch("/api/agents/module:network", json={"paused": False})

    # a run asked for before the flow was disabled does not pull once the flow is off; a person can still run it
    client.patch("/api/agents/module:assets", json={"paused": False})
    client.patch(f"/api/flows/{flow['id']}", json={"status": "disabled"})
    before = len(pulls)
    result = client.portal.call(hub.bus.request, "hub", "module:assets", "flow.run",
                                {"flow_id": flow["id"], "trigger": "schedule"})
    assert result["skipped"] and len(pulls) == before
    assert not next(f for f in flows_of(client, "inventory") if f["id"] == flow["id"])["running"]
    manual = client.post(f"/api/flows/{flow['id']}/run").json()
    assert manual["ok"] and len(pulls) == before + 1


# -- F26: a device page reads that device's history only, without the records -----------------------------------------------


def test_history_reads_one_device_and_no_records(client):
    hub = client.app.state.hub
    record = {"rules": [{"id": f"r{i}", "description": "x" * 200} for i in range(200)]}
    for tool in ("dev-a", "dev-ab", "dev-b"):
        for rev in range(1, 6):
            hub.store.put(network.HISTORY, {"id": network._history_id(tool, rev), "tool_id": tool, "rev": rev,
                                            "hash": str(rev), "record": record})
    calls = []
    original = hub.store.list
    hub.store.list = lambda collection: calls.append(collection) or original(collection)
    try:
        entries = network.history(hub, "dev-a")
    finally:
        hub.store.list = original
    assert network.HISTORY not in calls  # never every device's full history
    assert [e["rev"] for e in entries] == [5, 4, 3, 2, 1] and all("record" not in e for e in entries)
    assert {e["tool_id"] for e in entries} == {"dev-a"}
    hub.store.put("settings", {"id": network.SETTINGS_ID, **network.settings(hub), "history_limit": 2})
    network._prune_history(hub, "dev-a")
    assert [e["rev"] for e in network.history(hub, "dev-a")] == [5, 4]
    assert len(network.history(hub, "dev-ab")) == 5 and len(network.history(hub, "dev-b")) == 5


# -- F38: routine pings are not logged and the operational logs are bounded -----------------------------------------------------


def test_idle_scheduler_does_not_grow_the_message_log_and_logs_are_pruned(client, monkeypatch):
    from hub import core
    hub = client.app.state.hub
    before = hub.store.count("messages")
    for i in range(50):
        client.portal.call(hub.tick_flows, time.time() + i * 30)
        client.portal.call(hub.bus.tell, "hub", "supervisor", "health.sweep")
    assert hub.store.count("messages") - before <= 2  # e.g. one hourly SLA check, never the 30-second ticks
    activity_before = hub.store.count("activity")
    for i in range(120):
        hub.store.append("messages", {"subject": f"m{i}"})
        hub.store.append("toolbus", {"event": f"e{i}"})
    monkeypatch.setattr(core, "LOG_RETENTION", {"messages": 100, "toolbus": 30})
    hub._pruned = 0.0
    client.portal.call(hub.tick_flows)
    assert hub.store.count("messages") == 100 and hub.store.count("toolbus") == 30
    assert hub.store.tail("messages", 1)[0]["subject"] == "m119"  # the newest stay
    assert hub.store.count("activity") >= activity_before  # the audit trail is kept
