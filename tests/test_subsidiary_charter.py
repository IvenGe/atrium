"""A subsidiary's charter beyond its approval (round4-spec 5.4, 7.1, 7.6, 9.2): the API-only catalog derived from the
connector, staff designed by an AI model within the catalog, model routing that keeps personal data on a local model,
the event relay to the tool bus and transcripts (off by default, encrypted when on). No tool, model or network is
used."""

from __future__ import annotations

import json

from llm_fakes import use_claude
from subsidiary_support import TOOL, activate, add_tool, local_model, relayed_run, setup, staff_ids

from hub.integration import connections
from hub.llm.types import Result, Usage
from hub.subsidiary import catalog, charter, contract as c, governance
from hub.subsidiary.gateway import TRANSCRIPTS


def test_the_api_only_catalog_comes_from_the_connector(client):
    setup(client)
    hub = client.app.state.hub
    add_tool(client, connection="snipeit")
    actions = catalog.build(hub, TOOL)
    assert [(a["id"], a["risk"]) for a in actions] == [("records.assets.list", "read"),
                                                        ("records.assets.upsert", "write")]
    upsert = actions[1]
    assert upsert["params"]["required"] == ["external_id", "name"] and not upsert["reversible"]
    assert all(c.forbidden(a) is None and not c.action_problems(a) for a in actions)
    connections.update_config(hub, TOOL, {"read_accounts": True}, "test")
    ids = [a["id"] for a in catalog.build(hub, TOOL)]
    assert "records.accounts.list" in ids and "records.accounts.upsert" not in ids  # identity data: read only
    assert catalog.parse("records.assets.upsert") == ("assets", "upsert") and catalog.parse("records.x.drop") is None


def test_an_ai_model_designs_the_staff_within_the_catalog(client, wait_for):
    design = {"mandate": "Keep the asset register exact.", "rationale": "One clerk is enough.", "members": [
        {"role": "front-desk", "title": "Desk", "instructions": "Answer.", "actions": ["records.assets.list"],
         "schedule_minutes": 0, "task": ""},
        {"role": "clerk", "title": "Inventory clerk", "instructions": "You keep assets exact.",
         "actions": ["records.assets.list", "records.assets.upsert", "records.secrets.dump"], "schedule_minutes": 30,
         "task": "Check the assets"}]}
    setup(client)
    hub = client.app.state.hub
    provider, fake = local_model(client, [Result(text=json.dumps(design), usage=Usage(input_tokens=10))])
    add_tool(client, connection="snipeit")
    made = client.post(f"/api/tools/{TOOL}/subsidiary", json={"mode": "sidecar_only", "designer": "claude"})
    assert made.status_code == 201
    sub = governance.of_tool(hub, TOOL)
    draft = sub.pending_charter
    assert sub.designer == "model" and draft.mandate == "Keep the asset register exact."
    assert len(sub.pending_members) == 1 and not draft.panel.enabled  # no panel without a bridge: no front desk
    member = sub.pending_members[0]
    assert member["title"] == "Inventory clerk" and member["template"] == "model:clerk"
    assert member["schedule_minutes"] == 60 and member["provider"] == provider  # at least an hour; the local model
    assert draft.staff[member["id"]].actions == ["records.assets.list", "records.assets.upsert"]  # catalog only
    assert "<catalog>" in fake.requests[0].messages[0].text and "data describing" in fake.requests[0].system


def test_tools_holding_personal_data_default_to_a_local_model(client, monkeypatch):
    setup(client)
    hub = client.app.state.hub
    add_tool(client, connection="snipeit")
    client.post(f"/api/tools/{TOOL}/subsidiary", json={"mode": "sidecar_only", "designer": "templates"})
    sub = governance.of_tool(hub, TOOL)
    actions = catalog.build(hub, TOOL)
    routing, warning = charter.default_routing(hub, sub, actions)
    assert routing.allowed == [] and "No AI model is available" in warning
    use_claude(hub, monkeypatch)
    routing, warning = charter.default_routing(hub, sub, actions)
    assert routing.allowed == ["anthropic"] and warning == "Tool data is sent to Claude, a third-party provider."
    connections.update_config(hub, TOOL, {"read_accounts": True}, "test")  # now it reads people's accounts
    actions = catalog.build(hub, TOOL)
    routing, warning = charter.default_routing(hub, sub, actions)
    assert routing.allowed == ["anthropic"] and "holds personal data and no local model" in warning
    provider, _ = local_model(client)
    routing, warning = charter.default_routing(hub, sub, actions)
    assert routing.allowed == [provider] and routing.default == provider and warning is None  # Claude stays out


def test_declared_tool_events_are_relayed_to_the_tool_bus(client, tmp_path, wait_for, sign_in):
    local_model(client)
    clock, bridge, sidecar, _ = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    assert governance.of_tool(hub, TOOL).charter.events.relay is True  # the manifest declares an event
    batch = {"events": [{"name": "helpdesk.ticket.created", "payload": {"id": 7, "api_token": "s3cret"},
                         "cause": {"jti": "j1"}},
                        {"name": "helpdesk.ticket.deleted", "payload": {}},
                        {"name": "crm.deal.won", "payload": {}}]}
    answer = sidecar.post("events", batch)
    assert answer.json() == {"ok": True, "accepted": 1, "refused": 2}
    entry = wait_for(lambda: next((e for e in hub.store.tail("toolbus", 10) if e["event"] == "helpdesk.ticket.created"),
                                  None))
    assert entry["by"] == "subsidiary:helpdesk" and entry["source"] == TOOL
    assert entry["payload"] == {"id": 7, "api_token": "***", "atrium_cause": {"jti": "j1"}}
    narrowed = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"events": {"relay": False}})
    assert narrowed.json()["applied"] is True
    assert sidecar.post("events", batch).json()["detail"]["code"] == "relay_off"


def test_transcripts_are_off_by_default_and_encrypted_when_kept(client, tmp_path, wait_for, sign_in):
    provider, fake = local_model(client, [Result(text="Done once.", usage=Usage(input_tokens=5)),
                                          Result(text="Done twice.", usage=Usage(input_tokens=5))])
    clock, bridge, sidecar, ada = activate(client, tmp_path, wait_for, sign_in)
    hub = client.app.state.hub
    sub = governance.of_tool(hub, TOOL)
    clerk = staff_ids(hub)["clerk"]
    run_id = relayed_run(client, sidecar, clerk, "Secret task wording")
    assert sidecar.model(run_id, clerk, [{"role": "user", "text": "Secret task wording"}]).status_code == 200
    assert hub.store.list(TRANSCRIPTS) == []
    widened = client.put(f"/api/subsidiaries/{TOOL}/charter", json={"data": {"transcripts": True}}).json()
    assert widened["widening"] == ["transcripts turned on"]
    ada.post(f"/api/approvals/{widened['approval_id']}", json={"approve": True})
    wait_for(lambda: governance.of_tool(hub, TOOL).charter.data.transcripts)
    assert sidecar.model(run_id, clerk, [{"role": "user", "text": "Secret task wording"}]).status_code == 200
    stored = hub.store.list(TRANSCRIPTS)
    assert len(stored) == 1 and "Secret task wording" not in json.dumps(stored)
    plain = json.loads(hub.secrets.decrypt(stored[0]["data"]))
    assert plain["reply"] == "Done twice." and plain["messages"][0]["text"] == "Secret task wording"
    assert stored[0]["subsidiary_id"] == sub.id
