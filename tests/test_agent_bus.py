"""The agent bus as conversations: threads through ask chains, recorded agent errors, the Agent bus API (filters,
paging, roles) and its privacy - a person's chat text stays theirs, also when an agent quotes it to another one."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from llm_fakes import block, message, use_claude

from hub.agents import teams
from hub.agents.base import BaseAgent
from hub.bus import PRIVATE_TEXT, QUOTE_SCAN, AgentError, Message, Quotes, Trace, conversation, thread_key
from hub.llm import LLMUnavailable
from hub.llm.types import ProviderError
from hub.models import Manifest, Tool

MARKER = "MARKER-alice-7f3a9c"


class Probe(BaseAgent):
    """A test agent: echoes, fails, answers with an error, relays a request, or never answers."""

    async def on_echo(self, body, msg):
        return {"echo": body.get("text"), "kind": body.get("kind")}

    async def on_fail(self, body, msg):
        raise ValueError(f"could not work on {body.get('note')}")

    async def on_refuse(self, body, msg):
        return {"error": "refused on purpose", "code": "refused"}

    async def on_relay(self, body, msg):
        return await self.ask(body["to"], body["subject"], body.get("body") or {}, timeout=body.get("timeout", 30))

    async def on_hang(self, body, msg):
        await asyncio.sleep(3600)

    async def on_slowfail(self, body, msg):
        await asyncio.sleep(body.get("after", 0.6))
        raise ValueError("the real cause: database locked")

    async def on_think(self, body, msg):  # what hub.llm.converse does when the model call fails
        exc = ProviderError("the provider is down", kind="http_503", status=503)
        self.hub.llm.failed(self.id, exc, "chat")
        raise LLMUnavailable(str(exc)) from exc


def probe(client, agent_id: str) -> Probe:
    hub = client.app.state.hub
    return client.portal.call(hub.agents.add, Probe(hub, agent_id, agent_id.split(":")[1].title()))


def ask(client, recipient: str, subject: str, body: dict | None = None, sender: str = "hub", timeout: float = 30):
    return client.portal.call(client.app.state.hub.bus.request, sender, recipient, subject, body or {}, timeout)


def logged(client, **match) -> list[dict]:
    return [m for m in client.app.state.hub.store.tail("messages", 2000) if all(m.get(k) == v for k, v in match.items())]


def drain(client, queue) -> list[dict]:
    async def take():
        out = []
        while not queue.empty():
            out.append(queue.get_nowait())
        return out
    return client.portal.call(take)


def conversation_of(c, thread_id: str) -> dict:
    response = c.get(f"/api/bus/threads/{thread_id}")
    assert response.status_code == 200, response.text
    return response.json()


def add_tool(client, tool_id: str) -> None:
    hub = client.app.state.hub
    tool = Tool(id=tool_id, name=tool_id.upper(), source_type="saas", source=f"https://{tool_id}.example.com",
                status="ready", manifest=Manifest(id=tool_id, name=tool_id.upper(), kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)


# -- conversations (threads) --------------------------------------------------------------------------------------------


def test_a_chat_and_everything_it_causes_is_one_conversation(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    add_tool(client, "crm")
    patcher = hub.agents.get("patcher")

    async def propose(body, msg):  # the Patch Agent asks the tool's supervisor before it answers
        await patcher.ask("tool:crm", "describe")
        return {"patches": []}

    monkeypatch.setattr(patcher, "on_propose", propose)
    alice, bob = sign_in("operator", "alice"), sign_in("operator", "bob")
    events = hub.bus.subscribe(maxsize=5000)
    response = alice.post("/api/chat", json={"text": "patch crm"})
    assert response.status_code == 200, response.text
    root = response.json()["thread"]
    assert root and response.headers["x-atrium-thread"] == root
    published = [e["data"] for e in drain(client, events) if e["type"] == "message"]
    hub.bus.unsubscribe(events)
    assert len(published) == 6 and {m["thread"] for m in published} == {root}  # the live event names it too

    view = conversation_of(alice, root)
    msgs = view["messages"]
    assert [(m["sender"], m["recipient"], m["subject"], m["kind"]) for m in msgs] == [
        ("user:alice", "supervisor", "chat", "request"), ("supervisor", "patcher", "propose", "request"),
        ("patcher", "tool:crm", "describe", "request"), ("tool:crm", "patcher", "describe", "reply"),
        ("patcher", "supervisor", "propose", "reply"), ("supervisor", "user:alice", "chat", "reply")]
    ids = [m["id"] for m in msgs]
    assert ids[0] == root and {m["thread"] for m in msgs} == {root} and {m["origin"] for m in msgs} == {"user:alice"}
    assert [m["parent"] for m in msgs] == [None, root, ids[1], ids[2], ids[1], root]  # what caused each message
    assert [m["reply_to"] for m in msgs] == [None, None, None, ids[2], ids[1], root]  # replies keep their request's
    assert msgs[0]["reply_id"] == ids[5] and msgs[0]["duration"] >= msgs[1]["duration"] >= 0 and not msgs[0]["pending"]
    assert msgs[3]["duration"] == msgs[2]["duration"]
    summary = view["thread"]
    assert summary["status"] == "answered" and summary["count"] == 6 and summary["errors"] == 0
    assert summary["initiator"] == {"id": "user:alice", "kind": "person"} and summary["private"] and summary["mine"]
    assert summary["participants"] == ["user:alice", "supervisor", "patcher", "tool:crm"]
    assert summary["title"] == "patch crm"  # the person's own words, for them
    assert msgs[0]["body"] == {"text": "patch crm"} and msgs[0]["mine"] and msgs[1]["body"] == {"tool_id": "crm"}

    others = conversation_of(bob, root)
    assert others["thread"]["title"] == "chat" and not others["thread"]["mine"]
    assert others["messages"][0]["body_hidden"] == "private" and others["messages"][0]["body"]["redacted"] == "chat"
    assert others["messages"][1]["body"] == {"tool_id": "crm"}  # the agents' own messages stay readable
    # the existing message log and its event carry the conversation too
    assert {m["thread"] for m in alice.get("/api/messages?limit=2000").json() if m["id"] in ids} == {root}


def test_requests_and_replies_inherit_the_conversation_they_are_sent_in(client):
    hub = client.app.state.hub
    probe(client, "test:a"), probe(client, "test:b")
    assert ask(client, "test:a", "relay", {"to": "test:b", "subject": "echo", "body": {"text": "hi"}}) == {
        "echo": "hi", "kind": None}
    relay = logged(client, subject="relay", kind="request")[-1]
    rows = [m for m in hub.store.tail("messages", 200) if m.get("thread") == relay["id"]]
    assert [(m["sender"], m["subject"], m["kind"], m["parent"]) for m in rows] == [
        ("hub", "relay", "request", None), ("test:a", "echo", "request", relay["id"]),
        ("test:b", "echo", "reply", rows[1]["id"]), ("test:a", "relay", "reply", relay["id"])]
    # a second request outside any conversation is a conversation of its own
    ask(client, "test:b", "echo", {"text": "again"})
    again = logged(client, subject="echo", kind="request", sender="hub")[-1]
    assert again["thread"] == again["id"] != relay["id"] and again["origin"] == "hub"

    async def inside():  # code running for a message: what it sends joins that message's conversation
        msg = Message(sender="x", recipient="test:a", subject="something", thread="m_outer", origin="user:z")
        with conversation(Trace(thread="m_outer", parent=msg.id, origin="user:z", message=msg)):
            await hub.bus.tell("test:a", "test:b", "echo", {"text": "inner"})

    client.portal.call(inside)
    inner = logged(client, subject="echo", kind="event")[-1]
    assert (inner["thread"], inner["origin"]) == ("m_outer", "user:z")


def test_scheduled_work_starts_its_own_conversation(client, wait_for):
    hub = client.app.state.hub
    record = client.post("/api/agents", json={"name": "Night watch", "provider": "rules", "schedule_minutes": 5,
                                              "task": "summarize the state"}).json()

    async def tick_inside_a_conversation():  # even when the scheduler runs inside someone's conversation
        with conversation(Trace(thread="m_elsewhere", parent="m_elsewhere", origin="user:x")):
            agents = await hub.tick_agents(time.time() + 3600)
            flows = await hub.tick_flows(time.time() + 7200)
        return agents, flows

    started, _ = client.portal.call(tick_inside_a_conversation)
    assert started == [record["id"]]
    wait_for(lambda: (teams.get_def(hub, record["id"]).last_run or 0) > 0)
    run = logged(client, subject="run", recipient=record["id"], kind="event")[-1]
    assert run["thread"] == run["id"] and run["origin"] == "hub" and run["parent"] is None
    sla = logged(client, subject="sla.check")[-1]
    assert sla["thread"] == sla["id"] != run["thread"]  # every scheduled message its own conversation
    summary = client.get(f"/api/bus/threads/{run['id']}").json()["thread"]
    assert summary["initiator"] == {"id": "hub", "kind": "schedule"} and summary["subject"] == "run"
    caused = [m for m in hub.store.tail("messages", 2000) if m.get("parent") == run["id"]]
    assert all(m["thread"] == run["id"] for m in caused)


def test_rows_from_before_conversations_group_a_reply_with_its_request(client):
    hub = client.app.state.hub
    hub.store.append("messages", {"id": "m_old1", "sender": "supervisor", "recipient": "patcher", "subject": "propose",
                                  "body": {"tool_id": "x"}, "kind": "request", "reply_to": None})
    hub.store.append("messages", {"id": "m_old2", "sender": "patcher", "recipient": "supervisor", "subject": "propose",
                                  "body": {"error": "boom"}, "kind": "reply", "reply_to": "m_old1"})
    hub.store.append("messages", {"sender": "hub", "recipient": "module:grc", "subject": "evaluate", "body": {},
                                  "kind": "event", "reply_to": None})
    view = client.get("/api/bus/threads/m_old1").json()
    assert [m["id"] for m in view["messages"]] == ["m_old1", "m_old2"] and view["thread"]["status"] == "failed"
    assert view["messages"][1]["error"] == "boom" and view["thread"]["errors"] == 1
    no_id = hub.store.tail("messages", 1)[0]
    assert thread_key(no_id) == f"seq:{no_id['seq']}" and client.get(f"/api/bus/threads/seq:{no_id['seq']}").status_code == 200
    assert client.get("/api/bus/threads/m_nothing").status_code == 404
    assert {m["thread"] for m in client.get("/api/messages?limit=5").json()} >= {"m_old1", f"seq:{no_id['seq']}"}


def test_a_failure_in_an_unlogged_routine_ping_still_has_its_conversation(client):
    hub = client.app.state.hub

    async def tick():  # the scheduler's routine pings are not logged, their failures are recorded
        msg = Message(sender="hub", recipient="module:network", subject="changes.tick")
        hub.bus.stamp(msg)
        hub.agent_errors.record("module:network", subject=msg.subject, sender=msg.sender, message=msg.id,
                                thread=msg.thread, text="device unreachable", error_class="ConnectorError")
        return msg.thread

    thread_id = client.portal.call(tick)
    view = client.get(f"/api/bus/threads/{thread_id}").json()
    assert view["messages"] == [] and [e["error"] for e in view["errors"]] == ["device unreachable"]
    assert view["thread"]["status"] == "failed" and view["thread"]["initiator"] == {"id": "hub", "kind": "schedule"}
    assert view["thread"]["participants"] == ["hub", "module:network"]


# -- agent errors ---------------------------------------------------------------------------------------------------------


def test_failures_are_recorded_acknowledged_and_cleared(client, sign_in):
    hub = client.app.state.hub
    probe(client, "test:a"), probe(client, "test:b")
    events = hub.bus.subscribe(maxsize=5000)
    with pytest.raises(AgentError, match="could not work on the report"):  # an exception in a handler
        ask(client, "test:b", "fail", {"note": "the report"})
    with pytest.raises(AgentError, match="refused on purpose"):  # an error reply
        ask(client, "test:b", "refuse")
    with pytest.raises(AgentError, match="did not answer 'hang'"):  # a request nobody answers in time
        ask(client, "test:a", "relay", {"to": "test:b", "subject": "hang", "timeout": 0.2})
    with pytest.raises(AgentError, match="No agent named"):
        ask(client, "test:nobody", "echo")

    page = client.get("/api/agents/test:b/errors").json()
    assert [(e["kind"], e["subject"], e["error_class"], e["code"], e["sender"]) for e in page["errors"]] == [
        ("timeout", "hang", "Timeout", "timeout", "test:a"), ("reply", "refuse", "ErrorReply", "refused", "hub"),
        ("exception", "fail", "ValueError", None, "hub")]  # newest first; the exception's own error reply is not twice
    assert page["total"] == page["unacknowledged"] == page["since_start"] == 3
    fail = page["errors"][2]
    assert fail["error"] == "could not work on the report" and fail["thread"] == fail["message"]
    assert fail["acknowledged_at"] is None
    relay = logged(client, subject="relay", kind="request")[-1]
    assert page["errors"][0]["thread"] == relay["id"]  # the timeout is in the relay's conversation
    relayed = client.get("/api/agents/test:a/errors").json()["errors"]
    assert [(e["kind"], e["error_class"], e["code"]) for e in relayed] == [("exception", "AgentError", "timeout")]
    assert client.get("/api/agents/test:nobody/errors").json()["errors"][0]["code"] == "unreachable"
    view = client.get(f"/api/bus/threads/{relay['id']}").json()
    assert [e["kind"] for e in view["errors"]] == ["timeout", "exception"] and view["thread"]["errors"] == 2
    record = next(a for a in client.get("/api/agents").json() if a["id"] == "test:b")
    assert record["errors"] == 3 and record["errors_unacknowledged"] == 3 and record["last_error_at"]
    published = [e for e in drain(client, events) if e["type"] == "agent_error"]
    assert {e["data"]["agent"] for e in published} == {"test:a", "test:b", "test:nobody"}
    hub.bus.unsubscribe(events)

    viewer, operator = sign_in("viewer"), sign_in("operator", "olga")
    assert viewer.get("/api/agents/test:b/errors").json()["total"] == 3  # viewers read the error texts
    assert viewer.post(f"/api/agents/test:b/errors/{fail['id']}/ack").status_code == 403
    acked = operator.post(f"/api/agents/test:b/errors/{fail['id']}/ack").json()
    assert acked["acknowledged_by"] == "olga" and acked["acknowledged_at"]
    assert operator.post("/api/agents/test:a/errors/" + fail["id"] + "/ack").status_code == 404  # another agent's
    assert len(client.get("/api/agents/test:b/errors?unacknowledged=true").json()["errors"]) == 2
    hub.agent_errors.invalidate()  # the counts come from the store (they survive a restart)
    assert next(a for a in client.get("/api/agents").json() if a["id"] == "test:b")["errors_unacknowledged"] == 2
    assert operator.post("/api/agents/test:b/errors/ack").json() == {"acknowledged": 2, "unacknowledged": 0}
    assert client.get("/api/agents/test:b/errors").json()["unacknowledged"] == 0

    assert operator.delete("/api/agents/test:b/errors").status_code == 403  # clearing is an administrator's
    assert client.delete("/api/agents/test:b/errors").json() == {"cleared": 3}
    after = client.get("/api/agents/test:b/errors").json()
    assert after["errors"] == [] and after["since_start"] == 0
    assert client.get("/api/agents/test:none/errors").status_code == 404


def test_error_records_are_bounded(client, monkeypatch):
    from hub import agent_errors

    hub = client.app.state.hub
    monkeypatch.setattr(agent_errors, "KEEP_PER_AGENT", 3)
    for n in range(30):
        hub.agent_errors.record("test:x", subject="s", sender="hub", message=f"m_{n}", thread=f"m_{n}",
                                text=f"failure {n}", error_class="ValueError")
    assert hub.agent_errors.stored("test:x") <= 3 + 20
    old = hub.store.list_where("agent_errors", "agent", "test:x")[0]
    hub.store.put("agent_errors", {**old, "ts": time.time() - 40 * 86400})
    hub.agent_errors.prune()
    kept = hub.agent_errors.for_agent("test:x")
    assert [d["error"] for d in kept] == ["failure 29", "failure 28", "failure 27"]
    assert "agent_errors" in hub.prune_logs()


def test_error_counts_stay_right_when_the_cache_was_dropped(client):
    hub = client.app.state.hub
    hub.agent_errors.invalidate()  # start-up, an hourly prune, a trim, acknowledging all: the counts are read again
    with pytest.raises(AgentError):
        ask(client, "test:nobody", "echo")
    page = client.get("/api/agents/test:nobody/errors").json()
    assert page["total"] == page["unacknowledged"] == 1  # not counted twice

    agent = probe(client, "test:h")
    for _ in range(2):
        with pytest.raises(AgentError):
            ask(client, "test:h", "hang", timeout=0.2)
    first = client.get("/api/agents/test:h/errors").json()["errors"][0]
    hub.agent_errors.invalidate()
    client.post(f"/api/agents/test:h/errors/{first['id']}/ack")
    page = client.get("/api/agents/test:h/errors").json()
    assert page["total"] == 2 and page["unacknowledged"] == 1  # not subtracted twice
    assert [e["acknowledged_at"] is None for e in page["errors"]] == [False, True]
    assert agent.record()["errors_unacknowledged"] == 1


def test_a_timeout_does_not_hide_the_failure_that_follows_it(client, wait_for):
    agent = probe(client, "test:slow")
    with pytest.raises(AgentError, match=r"did not answer 'slowfail' within 0.2s"):
        ask(client, "test:slow", "slowfail", {"after": 0.6}, timeout=0.2)
    errors = wait_for(lambda: len(e := client.get("/api/agents/test:slow/errors").json()["errors"]) == 2 and e)
    assert [(e["kind"], e["error"]) for e in errors] == [
        ("exception", "the real cause: database locked"), ("timeout", "test:slow did not answer 'slowfail' within 0.2s")]
    assert errors[0]["message"] == errors[1]["message"] and agent.errors == 2  # the same request, two failures
    client.portal.call(asyncio.sleep, 0.2)
    assert len(client.get("/api/agents/test:slow/errors").json()["errors"]) == 2  # its error reply is not a third


def test_a_failed_model_call_is_one_error_and_a_failed_fallback_another(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    probe(client, "test:t")
    with pytest.raises(AgentError, match="the provider is down"):  # the failure the handler ends with: the model's
        ask(client, "test:t", "think")
    assert [(e["kind"], e["code"]) for e in client.get("/api/agents/test:t/errors").json()["errors"]] == [
        ("llm", "llm_http_503")]

    async def broken(**kwargs):
        raise ProviderError("the provider is down", kind="http_503", status=503)

    async def rules(text, person=None):  # the rules the supervisor falls back to fail too
        raise ValueError("the rules crashed")

    fake = use_claude(hub, monkeypatch, responses=[])
    monkeypatch.setattr(fake, "create", broken)
    fake.beta.messages.create = broken
    monkeypatch.setattr(hub.agents.get("supervisor"), "_rules_chat", rules)
    alice = sign_in("operator", "alice")
    assert alice.post("/api/chat", json={"text": "status"}).status_code >= 400
    errors = alice.get("/api/agents/supervisor/errors").json()["errors"]
    assert [(e["kind"], e["error_class"]) for e in errors] == [("exception", "ValueError"), ("llm", "ProviderError")]
    assert errors[0]["error"] == "the rules crashed" and errors[0]["message"] == errors[1]["message"]


def test_a_failed_model_call_is_an_agent_error(client, sign_in, monkeypatch):
    from hub.llm.types import ProviderError

    hub = client.app.state.hub

    async def broken(**kwargs):
        raise ProviderError("the provider is down", kind="http_503", status=503)

    fake = use_claude(hub, monkeypatch, responses=[])
    monkeypatch.setattr(fake, "create", broken)
    fake.beta.messages.create = broken
    alice = sign_in("operator", "alice")
    reply = alice.post("/api/chat", json={"text": "status"}).json()
    assert reply["mode"] == "rules"  # the supervisor fell back to its built-in commands
    errors = client.get("/api/agents/supervisor/errors").json()["errors"]
    assert errors and errors[0]["kind"] == "llm" and errors[0]["code"].startswith("llm_")
    assert errors[0]["thread"] == reply["thread"] and errors[0]["subject"] == "chat"
    assert errors[0]["error"] is None and errors[0]["error_hidden"] == "private"  # a chat's failure: its person's
    assert alice.get("/api/agents/supervisor/errors").json()["errors"][0]["error"]  # alice reads it


# -- the API: filters and paging --------------------------------------------------------------------------------------------


def test_conversations_can_be_filtered_searched_and_paged(client, sign_in):
    probe(client, "test:a"), probe(client, "test:b")
    for n in range(5):
        ask(client, "test:a", "echo", {"text": f"note {n}"})
    ask(client, "test:b", "echo", {"text": "needle-in-a-body"})
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": "x"})
    alice, viewer = sign_in("operator", "alice"), sign_in("viewer")
    alice.post("/api/chat", json={"text": "status"})

    first = client.get("/api/bus/threads?agent=test:a&limit=2").json()
    assert first["total"] == 5 and len(first["threads"]) == 2 and first["next_before"]
    seen = [t["id"] for t in first["threads"]]
    cursor = first["next_before"]
    while cursor:
        page = client.get(f"/api/bus/threads?agent=test:a&limit=2&before={cursor}").json()
        seen += [t["id"] for t in page["threads"]]
        cursor = page["next_before"]
    assert len(seen) == len(set(seen)) == 5
    lasts = [t["last"] for t in first["threads"]]
    assert lasts == sorted(lasts, reverse=True)  # the latest activity first
    item = first["threads"][0]
    assert item["subject"] == "echo" and item["count"] == 2 and item["status"] == "answered"
    assert item["initiator"] == {"id": "hub", "kind": "schedule"} and item["participants"] == ["hub", "test:a"]

    failing = client.get("/api/bus/threads?agent=test:b&errors_only=true").json()["threads"]
    assert [(t["subject"], t["status"], t["errors"]) for t in failing] == [("fail", "failed", 1)]
    assert client.get("/api/bus/threads?agent=test:b&status=failed").json()["total"] == 1
    assert client.get("/api/bus/threads?agent=test:b&status=answered").json()["total"] == 1
    assert client.get("/api/bus/threads?subject=echo").json()["total"] == 6

    mine = alice.get("/api/bus/threads?person_only=true").json()["threads"]
    assert [(t["title"], t["initiator"]["id"]) for t in mine] == [("status", "user:alice")]
    assert client.get("/api/bus/threads?person_only=true").json()["total"] == 0  # the admin started none

    assert client.get("/api/bus/threads?q=needle").json()["total"] == 1  # bodies, for roles that read them
    assert viewer.get("/api/bus/threads?q=needle").json()["total"] == 0
    assert viewer.get("/api/bus/threads?q=TEST:B").json()["total"] == 2  # participants and subjects for everyone
    assert client.get("/api/bus/threads?limit=0").status_code == 422
    assert client.get("/api/bus/threads?status=lost").status_code == 422


def test_viewers_read_routing_status_and_errors_but_not_bodies(client, sign_in):
    probe(client, "test:b")
    ask(client, "test:b", "echo", {"text": "a body"})
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": "y"})
    viewer = sign_in("viewer")
    echo = viewer.get("/api/bus/threads?subject=echo").json()["threads"][0]
    view = conversation_of(viewer, echo["id"])
    assert [(m["body"], m["body_hidden"]) for m in view["messages"]] == [(None, "role"), (None, "role")]
    assert view["messages"][0]["subject"] == "echo" and view["thread"]["status"] == "answered"
    failed = conversation_of(viewer, viewer.get("/api/bus/threads?subject=fail").json()["threads"][0]["id"])
    assert failed["messages"][1]["error"] == "could not work on y" and failed["messages"][1]["body"] is None
    assert failed["errors"][0]["error"] == "could not work on y"
    assert conversation_of(client, echo["id"])["messages"][1]["body"] == {"echo": "a body", "kind": None}


# -- privacy ----------------------------------------------------------------------------------------------------------------


def test_quotes_of_a_chat_are_recognised():
    quotes = Quotes([f"please file {MARKER} for me, password Hunter2! at 10.0.0.5"])
    assert quotes(MARKER) and quotes(f"filed: {MARKER.upper()}") and quotes("hunter2") and quotes("10.0.0.5")
    assert quotes("please   FILE it")  # inside the text (case and spacing ignored)
    assert quotes("the text said: file marker-alice")  # ten characters in a row
    assert not quotes("local") and not quotes("tool_id") and not quotes("") and not Quotes([])("anything")
    body = {"command": f"echo {MARKER}", "target": "local", "args": ["x", MARKER], "n": 3, "flag": True}
    assert quotes.scrub(body) == {"command": PRIVATE_TEXT, "target": "local", "args": ["x", PRIVATE_TEXT], "n": 3,
                                  "flag": True}


def test_quotes_of_short_texts_names_numbers_and_keys_are_recognised():
    short = Quotes(["fire Jan"])  # shorter than a run: the whole text, and the name in it
    assert short.scrub({"task": "The person asked: fire Jan", "who": "Jan", "amount": 5000}) == {
        "task": PRIVATE_TEXT, "who": PRIVATE_TEXT, "amount": 5000}
    for text, name in (("sack Ann", "Ann"), ("hire Tim!", "Tim")):
        assert Quotes([text])(f"The person asked: {text}") and Quotes([text])(f"notify HR about {name}")
    assert Quotes(["fire jan"])("asked to fire jan today") and Quotes(["Jan"])("fire jan now")
    assert not Quotes(["patch crm"])("crm")  # a plain short word is the agents' vocabulary too (a tool's id)
    hire = Quotes(["Confidential: the new hire is Sebastien-Dupont-9x7, salary 85,000"])
    body = {"command": "echo welcome sebastien-dupont-9x7", "salary": 85000, "as_float": 85000.0, "n": 3,
            "flag": True, "Sebastien-Dupont-9x7": "a key", "text": "a key too", "target": "local"}
    assert hire.scrub(body) == {"command": PRIVATE_TEXT, "salary": PRIVATE_TEXT, "as_float": PRIVATE_TEXT, "n": 3,
                                "flag": True, f"{PRIVATE_TEXT} 6": "a key", "text": "a key too", "target": "local"}
    assert hire("the new hire") and not hire("an unrelated note about local tools")  # a part of it, as before


def test_a_huge_chat_text_cannot_stall_the_quote_check(client, sign_in):
    alice = sign_in("operator", "alice")
    assert alice.post("/api/chat", json={"text": "x" * 20_001}).status_code == 422
    huge = Quotes([" ".join(f"a{n}b" for n in range(200_000))])  # 1.7 MB of distinctive words
    assert len(huge.runs) <= QUOTE_SCAN
    body = {f"k{n}": f"an ordinary agent string about tools and flows, number {n}" for n in range(50)}
    started = time.monotonic()
    assert huge.scrub(body) == body
    assert time.monotonic() - started < 0.5  # it took 2.5 s when every word was looked for in every string


def test_a_quote_of_an_earlier_turn_is_redacted_for_everyone_else(client, sign_in, monkeypatch):
    """The model reads the person's earlier turns (agent memory): quoting them is as private as quoting this one."""
    hub = client.app.state.hub
    marker = "Sebastien-Dupont-9x7"
    fake = use_claude(hub, monkeypatch, responses=[
        message("end_turn", [block("text", text="Noted.")]),
        message("tool_use", [block("tool_use", id="tu_1", name="run_command", input={
            "target": "local", "command": f"echo welcome {marker}", "reason": "asked in chat"})]),
        message("end_turn", [block("text", text="It waits for an administrator's approval.")])])
    alice, bob, carol = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    alice.post("/api/chat", json={"text": f"Confidential: the new hire is {marker}, salary 85000"})
    events = hub.bus.subscribe(maxsize=5000)
    root = alice.post("/api/chat", json={"text": "now greet him on the server"}).json()["thread"]
    assert marker in json.dumps(fake.calls[1]["messages"], default=str)  # the model did read turn 1
    published = [e for e in drain(client, events) if e["type"] == "message"]
    hub.bus.unsubscribe(events)
    assert published and marker not in json.dumps(published)
    for other in (bob, carol):
        for path in (f"/api/bus/threads/{root}", "/api/messages?limit=2000", "/api/agents/operator/messages"):
            assert marker not in other.get(path).text, path
    run = next(m for m in conversation_of(bob, root)["messages"] if m["subject"] == "run" and m["kind"] == "request")
    assert run["body"]["command"] == PRIVATE_TEXT and run["body"]["target"] == "local"
    mine = next(m for m in conversation_of(alice, root)["messages"] if m["subject"] == "run" and m["kind"] == "request")
    assert mine["body"]["command"] == f"echo welcome {marker}"


def test_a_quote_of_a_stored_earlier_turn_is_redacted_after_a_restart(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    marker = "Zq7Secret-Proj9"
    saved = client.patch("/api/agents/supervisor/settings", json={"config": {"memory": {"mode": "persisted"}}})
    assert saved.status_code == 200, saved.text
    use_claude(hub, monkeypatch, responses=[
        message("end_turn", [block("text", text="Noted. Say go when ready.")]),
        message("tool_use", [block("tool_use", id="tu_1", name="run_command", input={
            "target": "local", "command": f"echo {marker}", "reason": "asked in chat"})]),
        message("end_turn", [block("text", text="It waits for approval.")])])
    alice, bob = sign_in("operator", "alice"), sign_in("operator", "bob")
    alice.post("/api/chat", json={"text": f"remember the project code {marker}"})
    hub.llm.memory._conversations.clear()  # as after a restart: turn 1 is read from the store
    root = alice.post("/api/chat", json={"text": "go, run the echo now"}).json()["thread"]
    assert marker not in bob.get(f"/api/bus/threads/{root}").text
    assert marker not in bob.get("/api/messages?limit=2000").text


def test_the_message_log_shows_bodies_to_operators_only_with_secrets_masked(client, sign_in):
    hub = client.app.state.hub
    probe(client, "test:b")
    hub.secrets.encrypt("warm up")  # the key file exists
    key = (hub.settings.data_dir / "secret.key").read_text().strip()
    hub.llm.mask.invalidate()
    events = hub.bus.subscribe(maxsize=5000)
    client.portal.call(hub.bus.tell, "hub", "module:grc", "note", {"text": f"the key is {key}"})
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": "z"})
    published = [e for e in drain(client, events) if e["type"] == "message"]
    hub.bus.unsubscribe(events)
    assert key not in json.dumps(hub.store.tail("messages", 50))  # masked when it was written
    assert key not in json.dumps(published)

    viewer, operator = sign_in("viewer", "carol"), sign_in("operator", "olga")
    for path in ("/api/messages?limit=50", "/api/agents/module:grc/messages", "/api/agents/test:b/messages"):
        assert key not in viewer.get(path).text and key not in operator.get(path).text, path
    note = next(m for m in viewer.get("/api/messages?limit=50").json() if m["subject"] == "note")
    assert note["body"] == {"redacted": "role"} and note["thread"] == note["id"]  # routing, no body
    failed = next(m for m in viewer.get("/api/agents/test:b/messages").json() if m["kind"] == "reply")
    assert failed["body"] == {"redacted": "role", "failed": True, "error": "could not work on z"}  # errors: everyone
    note = next(m for m in operator.get("/api/messages?limit=50").json() if m["subject"] == "note")
    assert note["body"]["text"] == "the key is ***"
    request = next(m for m in operator.get("/api/agents/test:b/messages").json() if m["kind"] == "request")
    assert request["body"] == {"note": "z"}
    # the live event: as GET /api/messages shows it to each role
    live = [hub.conversations.event(e, False)["data"]["body"] for e in published]
    assert {json.dumps(b, sort_keys=True) for b in live} <= {
        '{"redacted": "role"}', '{"error": "could not work on z", "failed": true, "redacted": "role"}'}
    assert hub.conversations.event(published[0], True) == published[0]


def test_a_persons_chat_stays_theirs_when_agents_pass_it_on(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    probe(client, "test:b")
    supervisor = hub.agents.get("supervisor")

    async def rules(text, person=None):  # the Hub Supervisor hands the person's words to other agents
        await supervisor.ask("test:b", "echo", {"text": text, "kind": "note"})
        try:
            await supervisor.ask("test:b", "fail", {"note": text})
        except AgentError:
            pass
        return f"Filed: {text}"

    monkeypatch.setattr(supervisor, "_rules_chat", rules)
    alice, bob, carol = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    events = hub.bus.subscribe(maxsize=5000)
    text = f"please file {MARKER} for me"
    reply = alice.post("/api/chat", json={"text": text}).json()
    assert reply["reply"] == f"Filed: {text}"
    root = reply["thread"]
    published = drain(client, events)
    hub.bus.unsubscribe(events)
    assert MARKER not in json.dumps(published)  # the event stream every signed-in account reads

    for other in (bob, carol, client):
        for path in (f"/api/bus/threads/{root}", "/api/bus/threads", f"/api/bus/threads?q={MARKER}",
                     "/api/bus/threads?q=please", "/api/messages?limit=2000", "/api/agents/test:b/messages",
                     "/api/agents/supervisor/messages", "/api/agents/test:b/errors", "/api/activity?limit=2000"):
            assert MARKER not in other.get(path).text, path
        assert other.get(f"/api/bus/threads?q={MARKER}").json()["total"] == 0
    view = conversation_of(bob, root)
    echo, fail_reply = view["messages"][1], view["messages"][4]
    assert echo["body"] == {"text": PRIVATE_TEXT, "kind": "note"}  # the agents' message, less the person's words
    assert view["messages"][2]["body"] == {"echo": PRIVATE_TEXT, "kind": "note"}
    assert fail_reply["failed"] and fail_reply["error"] == PRIVATE_TEXT
    assert view["errors"][0]["error"] == PRIVATE_TEXT and view["thread"]["title"] == "chat"
    assert [m["private"] for m in view["messages"]] == [True] * 6

    own = conversation_of(alice, root)  # the person reads it all
    assert own["thread"]["title"] == text and own["messages"][0]["body"] == {"text": text}
    assert own["messages"][1]["body"] == {"text": text, "kind": "note"} and own["messages"][1]["mine"]
    assert own["messages"][4]["error"] == f"could not work on {text}"
    assert own["errors"][0]["error"] == f"could not work on {text}" and own["errors"][0]["mine"]
    assert own["messages"][5]["body"]["reply"] == f"Filed: {text}"
    assert alice.get(f"/api/bus/threads?q={MARKER}").json()["total"] == 1  # her own words find her chat
    on_disk = b"".join(p.read_bytes() for p in hub.settings.db_path.parent.glob("hub.db*"))
    assert MARKER.encode() not in on_disk  # kept for her encrypted only

    user_id = hub.auth.find_user("alice").id
    assert hub.store.list_where("bus_private", "user_id", user_id)
    assert client.delete(f"/api/users/{user_id}").status_code == 200
    assert hub.store.list_where("bus_private", "user_id", user_id) == []  # only while her account exists
    assert MARKER not in conversation_of(client, root)["messages"][0]["body"].__repr__()


def test_the_supervisors_model_quoting_a_chat_is_redacted_for_everyone_else(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("tool_use", id="tu_1", name="run_command",
                                   input={"target": "local", "command": f"echo {MARKER}", "reason": "asked in chat"})]),
        message("end_turn", [block("text", text="It waits for an administrator's approval.")])])
    alice, bob, carol = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    root = alice.post("/api/chat", json={"text": f"run echo {MARKER} please"}).json()["thread"]
    for other in (bob, carol):
        for path in (f"/api/bus/threads/{root}", "/api/bus/threads", "/api/agents/operator/messages"):
            assert MARKER not in other.get(path).text, path
    run = next(m for m in conversation_of(bob, root)["messages"] if m["subject"] == "run" and m["kind"] == "request")
    assert run["sender"] == "supervisor" and run["recipient"] == "operator" and run["parent"] == root
    assert run["body"]["command"] == PRIVATE_TEXT and run["body"]["target"] == "local"
    mine = next(m for m in conversation_of(alice, root)["messages"] if m["subject"] == "run" and m["kind"] == "request")
    assert mine["body"]["command"] == f"echo {MARKER}"


def test_secrets_are_masked_in_conversation_bodies_and_errors(client):
    hub = client.app.state.hub
    probe(client, "test:b")
    hub.secrets.encrypt("warm up")  # the key file exists
    key = (hub.settings.data_dir / "secret.key").read_text().strip()
    hub.llm.mask.invalidate()
    ask(client, "test:b", "echo", {"text": f"the key is {key}"})
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": key})
    echo = client.get("/api/bus/threads?subject=echo").json()["threads"][0]["id"]
    fail = client.get("/api/bus/threads?subject=fail").json()["threads"][0]["id"]
    for thread_id in (echo, fail):
        assert key not in client.get(f"/api/bus/threads/{thread_id}").text
    assert "***" in conversation_of(client, echo)["messages"][0]["body"]["text"]
    assert key not in client.get("/api/agents/test:b/errors").text
    assert client.get(f"/api/bus/threads?q={key[:12]}").json()["total"] == 0  # a search cannot probe for it


# -- privacy beyond the message log: the activity log, the command history, deferred work, status --------------------


def other_views(c, root: str) -> dict[str, str]:
    """What another account reads of a conversation and of the logs everyone reads."""
    paths = ("/api/messages?limit=2000", "/api/activity?limit=2000", "/api/commands?limit=500", "/api/bus/threads",
             f"/api/bus/threads/{root}", "/api/agents/operator/messages", "/api/agents/supervisor/messages",
             "/api/agents/operator/errors", "/api/agents/supervisor/errors")
    return {p: c.get(p).text for p in paths}


def test_the_activity_log_and_command_history_keep_a_chat_private(client, sign_in, monkeypatch):
    """A read-only command a chat asks for runs at once: its activity line, its command record and their live events
    are everyone's, so they carry no quote of the chat - its person reads the originals."""
    hub = client.app.state.hub
    marker = "Sebastien-Dupont-9x7"
    alice, bob, carol = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    events = hub.bus.subscribe(maxsize=5000)
    reply = alice.post("/api/chat", json={"text": f"run ls /tmp/{marker}"})
    assert reply.status_code == 200 and "cannot access" in reply.json()["reply"]
    root = reply.json()["thread"]
    published = drain(client, events)
    hub.bus.unsubscribe(events)
    assert {"activity", "command"} <= {e["type"] for e in published}
    assert marker not in json.dumps(published, default=str)  # the live events every signed-in account reads
    for other in (bob, carol):
        for path, text in other_views(other, root).items():
            assert marker not in text, path
    ran = next(e for e in carol.get("/api/activity?limit=200").json() if e["actor"] == "operator")
    assert ran["text"] == PRIVATE_TEXT and ran["private"] and "mine" not in ran
    record = carol.get("/api/commands").json()[-1]
    assert record["command"] == PRIVATE_TEXT and record["output"] == PRIVATE_TEXT and record["exit_code"] != 0
    assert record["target"] == "local" and record["private"]

    mine = next(e for e in alice.get("/api/activity?limit=200").json() if e["actor"] == "operator")
    assert mine["text"].startswith(f"Ran on local: ls /tmp/{marker} (exit ") and mine["mine"]
    own = alice.get("/api/commands").json()[-1]
    assert own["command"] == f"ls /tmp/{marker}" and marker in own["output"] and own["mine"]
    on_disk = b"".join(p.read_bytes() for p in hub.settings.db_path.parent.glob("hub.db*"))
    assert marker.encode() not in on_disk  # kept for her encrypted only

    # what an agent's tools write in a chat thread: a risk recorded on a chat's behalf
    use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("tool_use", id="tu_1", name="create_risk", input={
            "title": f"Salary data of {marker} exposed", "description": "from chat", "likelihood": 3, "impact": 4})]),
        message("end_turn", [block("text", text="Recorded.")])])
    admin = sign_in("admin", "ada")
    risk = admin.post("/api/chat", json={"text": f"Record a risk: the salary data of {marker} was exposed"})
    assert risk.status_code == 200 and hub.store.list("risks")
    lines = [e["text"] for e in carol.get("/api/activity?limit=500").json()]
    assert marker not in json.dumps(lines) and PRIVATE_TEXT in lines


def test_secrets_never_reach_the_activity_log(client, sign_in):
    """The activity log is everyone's: an agent's failure, or any other entry, carries no hub secret and no
    credential-looking pair (the agent's error record of the same failure was masked already)."""
    hub = client.app.state.hub
    probe(client, "test:b")
    hub.secrets.encrypt("warm up")  # the key file exists
    key = (hub.settings.data_dir / "secret.key").read_text().strip()
    hub.llm.mask.invalidate()
    events = hub.bus.subscribe(maxsize=5000)
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": f"key {key}"})
    with pytest.raises(AgentError):
        ask(client, "test:b", "fail", {"note": "Authorization: Bearer sk-not-a-hub-secret-0123456789"})
    hub.activity("hub", "info", f"a writer that forgot to mask {key}", detail={"pair": "password=hunter2", "key": key})
    published = [e for e in drain(client, events) if e["type"] == "activity"]
    hub.bus.unsubscribe(events)
    carol = sign_in("viewer", "carol")
    shown = carol.get("/api/activity?limit=200").text
    assert len(published) == 3
    for secret in (key, "sk-not-a-hub-secret-0123456789", "hunter2"):
        assert secret not in shown and secret not in json.dumps(published, default=str), secret
    assert key not in carol.get("/api/agents/test:b/errors").text
    failed = [e["text"] for e in carol.get("/api/activity?limit=200").json() if e["text"].startswith("'fail' failed")]
    assert failed == ["'fail' failed: could not work on key ***",
                      "'fail' failed: could not work on Authorization: Bearer ***"]


def test_an_approval_decided_later_stays_in_the_chat_thread(client, sign_in, monkeypatch, wait_for):
    """A command a chat asked for waits for an administrator. Its approval, and what the agents do once it is decided
    (run it, tell who asked), belong to the person's private thread: no quote of the chat for anyone else."""
    hub = client.app.state.hub
    marker = "Sebastien-Dupont-9x7"
    use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("tool_use", id="tu_1", name="run_command", input={
            "target": "local", "command": f"echo welcome {marker}", "reason": "asked in chat"})]),
        message("end_turn", [block("text", text="It waits for an administrator's approval.")])])
    alice, bob, carol = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    root = alice.post("/api/chat", json={"text": f"Please greet {marker} on the server"}).json()["thread"]
    pending = next(a for a in client.get("/api/approvals").json() if a["kind"] == "command")
    assert pending["status"] == "pending"
    for other in (bob, carol):  # "Awaiting approval: ..." in the activity log
        for path, text in other_views(other, root).items():
            assert marker not in text, path

    kept = hub.store.get("bus_private", f"p:{pending['id']}")  # what resuming the thread needs, encrypted

    events = hub.bus.subscribe(maxsize=5000)
    assert client.post(f"/api/approvals/{pending['id']}", json={"approve": True, "note": "ok"}).status_code == 200
    wait_for(lambda: logged(client, subject="command.completed"))
    wait_for(lambda: hub.approvals.get(pending["id"]).status == "done")
    published = drain(client, events)
    hub.bus.unsubscribe(events)
    for reader in (True, False):  # the live events as operators and as viewers get them
        live = [hub.conversations.event(e, reader) for e in published if e["type"] != "approval"]
        assert marker not in json.dumps(live, default=str)
    for other in (bob, carol):
        for path, text in other_views(other, root).items():
            assert marker not in text, path
        assert other.get(f"/api/bus/threads?q={marker}").json()["total"] == 0
    done = logged(client, subject="command.completed")[0]
    assert done["thread"] == root and done["private"] and done["body"]["command"] == PRIVATE_TEXT
    decided = logged(client, subject="approval.decided")[0]
    assert decided["thread"] == root and decided["sender"] == "user:admin" and decided["parent"]
    assert kept and marker not in json.dumps(kept)
    assert hub.store.get("bus_private", f"p:{pending['id']}") is None  # kept only until it was decided

    view = conversation_of(alice, root)  # the person reads it all, in her conversation
    own = next(m for m in view["messages"] if m["subject"] == "command.completed")
    assert own["mine"] and own["body"]["command"] == f"echo welcome {marker}" and own["body"]["exit_code"] == 0
    assert any(e.get("mine") and marker in e["text"] for e in alice.get("/api/activity?limit=500").json())


def test_quotes_of_every_remembered_turn_are_recognised():
    """The model reads the person's whole memory: a distinctive word of an old turn is recognised however much was
    said since (only the 10-character runs are limited to the newest QUOTE_SCAN characters)."""
    marker = "Sebastien-Dupont-9x7"
    filler = ("lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor " * 300)[:19_990]
    turns = [f"Confidential: the new hire is {marker}, salary 85000.", *[f"log {n}: {filler}" for n in range(30)],
             "now greet him on the server"]
    assert sum(map(len, turns[1:])) > QUOTE_SCAN * 5
    quotes = Quotes(turns)
    assert quotes(f"echo welcome {marker}") and quotes("dupont-9x7") and quotes.scrub({"pay": 85000}) == {
        "pay": PRIVATE_TEXT}
    assert not quotes("echo welcome") and len(quotes.runs) <= QUOTE_SCAN + 20


def test_names_that_open_a_sentence_are_recognised():
    dana = Quotes(["Dana is leaving on Friday. Revoke her VPN access quietly."])
    for agent_string in ("id dana", "disable the account of Dana", "notify HR about dana", "Dana"):
        assert dana(agent_string), agent_string
    jan = Quotes(["Jan gets fired tomorrow, keep it quiet"])
    assert jan("Jan") and jan("notify payroll about Jan") and Quotes(["Sack Dana's manager"])("id dana")
    # a usual sentence opener is not taken for a name: the agents' own strings stay readable
    assert not dana("revoke all sessions now") and not Quotes(["Please check the disk"])("checks: please wait")
    assert not Quotes(["Run uptime on the web server"])("running services: 12")


def test_numbers_are_recognised_in_any_thousands_format():
    comma = Quotes(["Confidential: Dana's pay will be 85,000 from May"])
    assert comma("payroll update 85000") and comma("payroll update 85.000") and comma.key("85000 eur")
    plain = Quotes(["Dana's pay will be 85000 from May"])
    assert plain("payroll update 85,000") and plain("payroll update 85.000") and plain("total 85000.50")
    assert plain.scrub({"note": "payroll update 85'000", "n": 85000}) == {"note": PRIVATE_TEXT, "n": PRIVATE_TEXT}
    assert not plain("payroll update 86,000") and not plain("version 8.5")
