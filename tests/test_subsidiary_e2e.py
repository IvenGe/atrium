"""End to end (round4-spec 14.2 #15): one agent team inside a tool, from an operator's request to the kill switch.
Everything is real except the tool, the model and the network:

- the real Atrium app: routes, approvals, the Patch Agent, the Tool Supervisor, the model gateway, governance;
- the Patch Agent's real bridge patch for a git checkout of the tool, designed by a fake Claude;
- the fake Helpdesk (tests/fakes/subsidiary_tool.py) "deployed" with the REAL vendored Python bridge core and
  configured only from what the approved patch produced: the committed atrium-bridge.json and the public bridge.env;
- the REAL sidecar runtime (hub.subsidiary.sidecar), one --once step at a time on the app's event loop.

The story: propose -> bridge patch (an administrator approves; the operator who asked cannot) -> deploy -> enroll ->
conformance observed by Atrium -> charter approved -> a tool user's panel question answered on her behalf -> a
scheduled clerk run reads poisoned tickets (delimited, flagged) and requests a write -> an operator approves -> a grant
-> the exact approved bytes run once in the tool -> the result completes the approval -> the tool's event reaches the
tool bus -> pause (the bridge refuses once the last ticket expires) -> resume -> kill switch -> the audit chain
verifies, and the enrollment code, the sidecar's token and its key never leaked. The hub runs autonomously
throughout: no step is approved by the autonomy level."""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import subsidiary_support as support
from cryptography.hazmat.primitives import serialization
from fakes import subsidiary_tool as fake
from fakes.sidecar_harness import BRIDGE_URL, SidecarHarness
from fastapi.testclient import TestClient
from llm_fakes import FakeClaude, block, message, use_claude

from hub import guardrails
from hub.agents import teams
from hub.integration.analyzer import parse_env_file
from hub.subsidiary import actions, governance, runtime
from hub.subsidiary import contract as c
from hub.subsidiary.sidecar.bridge_client import Ticket
from hub.subsidiary.sidecar.client import AtriumError

TOOL = fake.TOOL
GOALS = "Keep urgent tickets visible and help requesters find their tickets."
SERVICE = '''"""The Helpdesk's service layer: tickets, and who may see them."""

TICKETS = {}


def visible(user_id, roles):
    if "admin" in roles or "agent" in roles or "service" in roles:
        return list(TICKETS.values())
    return [t for t in TICKETS.values() if t["requester"] == user_id]


def set_priority(ticket_id, priority):
    TICKETS[ticket_id]["priority"] = priority
    return TICKETS[ticket_id]
'''
MAIN = '''from fastapi import FastAPI, Request

import helpdesk

app = FastAPI()


@app.get("/api/tickets")
def tickets(request: Request):
    return helpdesk.visible(request.cookies.get("helpdesk_session"), [])
'''
GLUE = '''"""Atrium bridge glue for the Helpdesk (written for the tool)."""

from typing import Any, Dict, Optional

import helpdesk


def service_principal() -> str:
    return "atrium-team"


def current_user(request: Any) -> Optional[Dict[str, Any]]:
    return None


def tickets_list(params, ctx):
    return helpdesk.visible(ctx.principal, ["service"])


def tickets_set_priority(params, ctx):
    return helpdesk.set_priority(params["ticket_id"], params["priority"])


actions = {"tickets.list": tickets_list, "tickets.set_priority": tickets_set_priority}
'''
REPO = {"requirements.txt": "fastapi\n", "helpdesk.py": SERVICE, "main.py": MAIN, "README.md": "# Helpdesk\n"}
EVENTS = [f"{TOOL}.ticket.created", f"{TOOL}.ticket.updated"]
SURVEY = {"framework": "FastAPI: app = FastAPI() in main.py", "entry_file": "main.py",
          "current_user": "the helpdesk_session cookie", "service_layer": "helpdesk.visible, helpdesk.set_priority",
          "files_to_read": ["helpdesk.py"], "layout_file": "", "rationale": "Reads, drafts and priority changes.",
          "catalog_json": json.dumps(fake.MANIFEST["actions"]),
          "events": [{"name": EVENTS[0], "where": "main.tickets"}, {"name": EVENTS[1], "where": "set_priority"}]}
DESIGN = {"mandate": "The Helpdesk team keeps urgent tickets visible and helps requesters find their tickets.",
          "rationale": "A front desk for questions, a clerk for the priorities.",
          "members": [{"role": "front-desk", "title": "Front desk", "instructions": "Answer questions about tickets.",
                       "actions": ["tickets.list", "tickets.draft_reply"], "schedule_minutes": 0, "task": ""},
                      {"role": "clerk", "title": "Clerk", "instructions": "Raise what is urgent.",
                       "actions": ["tickets.list", "tickets.set_priority"], "schedule_minutes": 240,
                       "task": "Raise tickets about fires to high priority."}]}


def write_answer() -> dict[str, Any]:
    validated = c.check_catalog(fake.MANIFEST["actions"]).actions
    return {"title": "Atrium bridge for the Helpdesk", "rationale": "Lists, drafts and re-prioritises tickets.",
            "changes": [{"path": "atrium/glue.py", "content": GLUE}],
            "service_principal_setup": "Create the account atrium-team that may read tickets and set priorities.",
            "manifest_json": json.dumps({"actions": validated, "events": {"names": EVENTS},
                                         "panel": {"enabled": True}}),
            "mount_steps": []}


def turn(*blocks: Any) -> Any:
    return message("tool_use" if any(b.type == "tool_use" for b in blocks) else "end_turn", list(blocks))


def call(call_id: str, action: str, params: dict[str, Any]) -> Any:
    return block("tool_use", id=call_id, name=c.tool_name(action), input=params)


PANEL_ANSWER = "Your ticket 1, Printer on fire, is open."
TURNS = [
    # the front desk answers Rita's panel question (a panel run)
    turn(call("tu_1", "tickets.list", {})),
    turn(block("text", text=PANEL_ANSWER)),
    # the clerk's scheduled run: it reads every ticket, then asks for a change
    turn(call("tu_2", "tickets.list", {"status": "open"})),
    turn(block("text", text="Ticket 1 is about a fire."), call("tu_3", "tickets.set_priority",
                                                               {"ticket_id": 1, "priority": "high"})),
    turn(block("text", text="Asked Atrium to raise ticket 1 to high.")),
    # a task from an operator, waiting when the master switch goes off
    turn(block("text", text="Payday is known."), call("tu_4", "tickets.set_priority",
                                                      {"ticket_id": 2, "priority": "low"})),
    turn(block("text", text="Waiting for approval.")),
]


class TeamClaude(FakeClaude):
    """The fake Claude of the whole story: structured calls are answered by their schema (the bridge survey, the
    bridge's files, the staff design); conversation turns come from TURNS, in order."""

    def __init__(self) -> None:
        super().__init__(responses=TURNS)
        self.answers = {"catalog_json": SURVEY, "manifest_json": write_answer(), "members": DESIGN}

    async def create(self, **kwargs: Any) -> Any:
        schema = ((kwargs.get("output_config") or {}).get("format") or {}).get("schema") or {}
        self.json_result = next((v for k, v in self.answers.items() if k in (schema.get("properties") or {})), None)
        return await super().create(**kwargs)

    def turns(self) -> list[dict[str, Any]]:
        return [call for call in self.calls if "messages" in call and "schema" not in call]


@pytest.fixture(autouse=True)
def git_identity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = tmp_path / "gitconfig"
    config.write_text("[user]\n\tname = Test\n\temail = test@example.com\n[init]\n\tdefaultBranch = main\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def make_repo(root: Path) -> Path:
    root.mkdir()
    for name, content in REPO.items():
        (root / name).write_text(content)
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(root), "commit", "-q", "-m", "initial"], check=True)
    return root


def pending(hub: Any, kind: str) -> list[Any]:
    return [a for a in hub.approvals.list("pending") if a.kind == kind]


def control(client: TestClient, control_id: str) -> dict[str, Any]:
    client.portal.call(client.app.state.hub.bus.request, "user:admin", "module:grc", "evaluate", {}, 60)
    return next(x for x in client.get("/api/grc").json()["controls"] if x["id"] == control_id)


def browser(tool: fake.FakeTool, username: str) -> TestClient:
    """A tool user's browser, signed in to the Helpdesk: the panel shares the tool's own session."""
    http = TestClient(tool.app, base_url=BRIDGE_URL)
    assert http.post("/login", json={"username": username}).status_code == 200
    return http


def signed_call(tool: fake.FakeTool, side: SidecarHarness, ticket: Ticket) -> httpx.Response:
    """A read a sidecar that ignores Atrium could still send: its own key and a ticket it kept."""
    body = c.body_bytes({})
    path = c.call_path("tickets.list")
    headers = c.call_headers(side.rt.bridge.key, ticket=ticket.token, ticket_jti=ticket.jti, path=path, body=body,
                             date=int(side.rt.bridge.clock()))
    return TestClient(tool.app, base_url=BRIDGE_URL).post(path, content=body, headers=headers)


def refusal(side: SidecarHarness) -> tuple[int, str | None]:
    """What Atrium answers the sidecar on a work route."""
    with pytest.raises(AtriumError) as refused:
        side.run(lambda: side.rt.atrium.post("runs", {"trigger": "panel", "question_id": "q_x", "agent_id": "x"}))
    return refused.value.status, refused.value.code


def test_a_team_inside_the_helpdesk_from_the_request_to_the_kill_switch(client, sign_in, wait_for, tmp_path,
                                                                        monkeypatch):
    hub = client.app.state.hub
    clock = support.setup(client, support.Clock(time.time()))  # subsidiaries allowed; a clock the test can advance
    claude = use_claude(hub, monkeypatch, TeamClaude())
    hub.prefs["autonomy"] = "autonomous"
    support.add_tool(client, TOOL, repo=make_repo(tmp_path / "helpdesk"))
    olive = sign_in("operator", "olive")
    ttl = int(guardrails.value(hub, "subsidiary_ticket_minutes")) * 60

    # -- 1. an operator asks for a team; the Patch Agent's bridge patch waits for an administrator -----------------
    made = olive.post(f"/api/tools/{TOOL}/subsidiary", json={"mode": "bridge", "designer": "auto", "goals": GOALS})
    assert made.status_code == 201, made.text
    sub_id = made.json()["id"]
    patch_approval = wait_for(lambda: next((a for a in pending(hub, "patch")
                                            if a.payload.get("strategy") == "atrium_bridge"), None))
    patch = hub.get_patch(patch_approval.payload["patch_id"])
    assert patch.bridge.vendored_core and patch.bridge.checks_ok and patch.bridge.panel
    assert [a["id"] for a in patch.bridge.actions] == [a["id"] for a in fake.MANIFEST["actions"]]
    assert patch_approval.payload["tests"]["status"] == "not_run" and "DID NOT RUN" in patch_approval.detail
    refused = olive.post(f"/api/approvals/{patch_approval.id}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "admin_required"
    assert client.post(f"/api/approvals/{patch_approval.id}", json={"approve": True}).status_code == 200
    wait_for(lambda: hub.approvals.get(patch_approval.id).status == "done")
    sub = governance.get(hub, sub_id)
    assert sub.status == "deploying" and sub.pending_charter is not None

    # -- 2. deployed: the tool runs the vendored core with the committed manifest and the public bridge.env --------
    manifest_raw = (Path(patch.location) / "atrium-bridge.json").read_bytes()
    assert c.manifest_sha256(manifest_raw) == sub.bridge.manifest_sha256
    env = parse_env_file((governance.adapter_dir(hub, sub) / "bridge.env").read_text())
    assert env[c.ENV_SUBSIDIARY] == sub_id and env[c.ENV_TOOL] == TOOL and env[c.ENV_PANEL] == "on"
    tool = fake.helpdesk_app(keys=env[c.ENV_KEYS], sub=sub_id, manifest=manifest_raw, env=env, clock=clock,
                             max_wait=0)
    hub.subsidiary_config.bridge_transport = httpx.ASGITransport(app=tool.app)  # Atrium reaches the bridge

    # -- 3. an administrator enrolls the sidecar; Atrium observes conformance; another person approves the charter --
    issued = client.post(f"/api/subsidiaries/{TOOL}/enrollment")
    assert issued.status_code == 200, issued.text
    code = issued.json()["code"]
    side = SidecarHarness(tmp_path / "sidecar-state", clock, atrium=httpx.ASGITransport(app=client.app), tool=tool,
                          atrium_url="http://testserver", sub=sub_id, code=code, portal=client.portal)
    try:
        side.enroll()
        reply = side.heartbeat_once()
        assert reply.status == "probation" and set(side.rt.bridge.ticket.act) == set(c.PROBATION_BUILTINS)
        charter_approval = wait_for(lambda: support.charter_approval(hub))
        done = governance.get(hub, sub_id).conformance
        assert done.ok and done.origin == "observed" and [r.id for r in done.rows] == [f"V{n}" for n in range(1, 21)]
        assert "Claude" in charter_approval.detail  # the routing warning: tool data goes to a third party
        refused = olive.post(f"/api/approvals/{charter_approval.id}", json={"approve": True})
        assert refused.status_code == 403 and refused.json()["detail"]["code"] == "admin_required"
        assert client.post(f"/api/approvals/{charter_approval.id}", json={"approve": True}).status_code == 200
        wait_for(lambda: governance.get(hub, sub_id).status == "active")
        staff = support.staff_ids(hub)
        desk, clerk = staff["desk"], staff["clerk"]
        reply = side.heartbeat_once()
        assert reply.status == "active" and side.rt.bridge.ticket.mode == "active" and side.rt.working()
        assert {"tickets.list", "tickets.set_priority", "atrium.panel.pull", "atrium.events.pull"} \
            <= set(side.rt.bridge.ticket.act)
        assert side.rt.charter.version == 1 and side.rt.charter.panel.desk == desk
        hb = control(client, "HB-AC-8")
        assert hb["status"] == "partial" and "without the tool's tests" in hb["detail"]

        # -- 4. a tool user asks the team; the front desk reads on her behalf and answers in plain text -----------
        rita = browser(tool, "requester")
        asked = rita.post(c.PANEL_ASK_PATH, json={"text": "Which of my tickets are still open?"},
                          headers={c.PANEL_HEADER: "1"})
        assert asked.status_code == 200, asked.text
        side.panel_once()
        answered = rita.get(c.PANEL_QUESTION_PREFIX + asked.json()["question_id"], headers={c.PANEL_HEADER: "1"})
        assert answered.json()["status"] == "answered" and answered.json()["answer"] == PANEL_ANSWER
        first, second = claude.turns()[:2]
        assert "governed by Atrium" in str(first["system"]) and DESIGN["mandate"] in str(first["system"])
        assert {t["name"] for t in first["tools"]} == {"act__tickets-list", "act__tickets-draft_reply",
                                                       "atrium__escalate"}
        seen = json.dumps(second["messages"], default=str)
        assert '<tool_data source=\\"bridge:tickets.list\\"' in seen and "Printer on fire" in seen
        assert "Payroll question" not in seen  # as Rita: only her own ticket

        # -- 5. the clerk's scheduled run reads poisoned tickets and asks for a change; nothing runs yet ----------
        defn = teams.get_def(hub, clerk)
        assert defn.placement == "sidecar" and defn.schedule_minutes == 240
        assert clerk in client.portal.call(hub.tick_agents, defn.created_at + 241 * 60)
        wait_for(lambda: any(m.type == "run" for m in runtime.pending(hub, sub_id, 0)))
        side.inbox_once()
        request = wait_for(lambda: next(iter(pending(hub, "subsidiary_action")), None))
        p = request.payload
        assert request.requested_by == f"tool:{TOOL}" and not p.get("proposed_by")
        assert p["action_id"] == "tickets.set_priority" and p["trigger"] == "schedule" and not p["user_steered"]
        assert c.b64u_decode(p["body_b64"]) == c.body_bytes({"ticket_id": 1, "priority": "high"})
        assert "bridge:tickets.list" in p["taint"] and p["injection_flags"] >= 1
        assert p["reason_untrusted"] == "Ticket 1 is about a fire."
        read = json.dumps(claude.turns()[3]["messages"], default=str)
        assert "Ignore your previous instructions" in read and '<tool_data source=\\"bridge:tickets.list\\"' in read
        assert tool.desk.tickets[1].priority == "normal" and ("tickets.set_priority", {"ticket_id": 1, "priority":
                                                                                      "high"}) not in tool.desk.calls
        result = wait_for(lambda: (teams.get_def(hub, clerk).last_result or {}).get("run_id")
                          and teams.get_def(hub, clerk).last_result)
        assert result["ok"] and result["trigger"] == "schedule" and result["reply"] == TURNS[4].content[0].text

        # -- 6. an operator approves; the grant runs exactly the approved bytes, once ----------------------------
        assert sign_in("viewer").post(f"/api/approvals/{request.id}", json={"approve": True}).status_code == 403
        assert olive.post(f"/api/approvals/{request.id}", json={"approve": True}).status_code == 200
        wait_for(lambda: any(m.type == "grant" for m in runtime.pending(hub, sub_id, 0)))
        side.inbox_once()
        assert tool.desk.tickets[1].priority == "high"
        assert [x for x in tool.desk.calls if x[0] == "tickets.set_priority"] == [
            ("tickets.set_priority", {"ticket_id": 1, "priority": "high"})]
        settled = wait_for(lambda: hub.approvals.get(request.id).status == "done" and hub.approvals.get(request.id))
        assert settled.result["status"] == "executed"
        grant = next(g for g in actions.grants_of(hub, sub_id) if g.approval_id == request.id)
        assert grant.status == "executed" and grant.body_sha256 == p["body_sha256"]

        # -- 7. the tool's event, caused by the grant, reaches the tool bus from subsidiary:helpdesk -------------
        assert side.events_once() >= 1
        event = wait_for(lambda: next((e for e in hub.store.tail("toolbus", 20) if e["event"] == EVENTS[1]), None))
        assert event["by"] == f"subsidiary:{TOOL}" and event["source"] == TOOL
        assert event["payload"] == {"id": 1, "priority": "high", "atrium_cause": {"jti": grant.id}}

        # -- 8. an operator pauses: no work, no ticket; the bridge refuses once the last ticket expired ----------
        held = side.rt.bridge.ticket
        assert olive.post(f"/api/subsidiaries/{TOOL}/pause", json={"reason": "Quarterly review"}).status_code == 200
        reply = side.heartbeat_once()
        assert reply.status == "paused" and reply.ticket is None and not side.rt.working()
        assert refusal(side) == (423, "paused")
        assert signed_call(tool, side, held).status_code == 200  # reads end with the ticket's lifetime (documented)
        clock.advance(ttl + 120)
        late = signed_call(tool, side, held)
        assert late.status_code == 401 and late.json()["code"] == "expired"
        assert olive.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 403  # resuming is for administrators
        assert client.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 200
        reply = side.heartbeat_once()
        assert reply.status == "active" and reply.ticket and side.rt.working()

        # -- 9. a task from the operator waits for someone else; then the master switch goes off -----------------
        given = olive.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": clerk, "text": "Payday is known."})
        assert given.status_code == 202, given.text
        side.inbox_once()  # the pause it never fetched is not delivered after the resume
        mine = wait_for(lambda: next(iter(pending(hub, "subsidiary_action")), None))
        assert mine.payload["trigger"] == "task"
        same = olive.post(f"/api/approvals/{mine.id}", json={"approve": True})
        assert same.status_code == 403 and same.json()["detail"]["code"] == "same_person"
        held = side.rt.bridge.ticket
        assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": False}).status_code == 200
        assert governance.get(hub, sub_id).status == "paused"
        assert hub.approvals.get(mine.id).status == "rejected"  # withdrawn: switching on again releases no backlog
        reply = side.heartbeat_once()
        assert reply.status == "paused" and reply.ticket is None and not side.rt.working()
        assert refusal(side) == (423, "disabled")
        assert teams.outside_guardrails(hub, teams.get_def(hub, clerk)).startswith("subsidiaries are switched off")
        assert any(e["text"].startswith("Subsidiaries switched off: 1 paused") for e in hub.store.tail("activity", 80))
        clock.advance(ttl + 120)  # without the sidecar's cooperation: its last ticket simply runs out
        assert signed_call(tool, side, held).json()["code"] == "expired"
        refused = client.post(f"/api/subsidiaries/{TOOL}/resume")
        assert refused.status_code == 409 and refused.json()["detail"]["code"] == "disabled"
        assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": True}).status_code == 200
        assert client.post(f"/api/subsidiaries/{TOOL}/resume").status_code == 200  # each one, by an administrator
        assert side.heartbeat_once().status == "active"
        assert tool.desk.tickets[2].priority == "high"  # the withdrawn request never ran

        # -- 10. the audit trail verifies, and no secret reached Atrium's records, its API or the model -----------
        verified = olive.post(f"/api/subsidiaries/{TOOL}/audit/verify")
        assert verified.status_code == 200 and verified.json()["ok"], verified.text
        trail = olive.get(f"/api/subsidiaries/{TOOL}/audit", params={"detail": 1, "limit": 1000}).json()
        kinds = {e["kind"] for e in trail["entries"]}
        assert {"enroll", "conformance", "model.call", "action.request", "action.decision", "grant.issue",
                "grant.result", "events.batch"} <= kinds, kinds
        assert {e["origin"] for e in trail["entries"]} == {"observed", "claimed"}
        token = side.rt.atrium.token
        key = c.b64u(side.rt.bridge.key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                      serialization.NoEncryption()))
        records = [client.get(f"/api/subsidiaries/{TOOL}").json(), client.get("/api/subsidiaries").json(), trail,
                   client.get("/api/approvals").json(), client.get("/api/messages").json(),
                   hub.store.tail("activity", 500), hub.store.tail("toolbus", 50), claude.calls]
        text = json.dumps(records, default=str)
        for secret in (code, token, key):
            assert secret and secret not in text
    finally:
        side.close()
