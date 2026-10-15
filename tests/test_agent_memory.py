"""Chat privacy (review D7): a person's conversation with an agent is theirs - never part of another person's
conversation, never in the message log or the event stream other accounts read."""

from __future__ import annotations

import json
import time

from llm_fakes import block, message, use_claude

MARKER = "MARKER-alice-7f3a9c"


def drain(client, queue) -> list[dict]:
    async def take():
        out = []
        while not queue.empty():
            out.append(queue.get_nowait())
        return out
    return client.portal.call(take)


def turn(text: str):
    return message("end_turn", [block("text", text=text)])


def test_one_persons_chat_history_is_never_sent_with_anothers(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice, bob = sign_in("operator", "alice"), sign_in("operator", "bob")
    fake = use_claude(hub, monkeypatch, responses=[turn(f"Noted, {MARKER}."), turn("Hello Bob."), turn("Still here.")])
    assert alice.post("/api/chat", json={"text": f"remember {MARKER}"}).json()["reply"] == f"Noted, {MARKER}."
    assert bob.post("/api/chat", json={"text": "hi"}).json()["reply"] == "Hello Bob."
    sent_for_bob = json.dumps(fake.calls[1]["messages"], default=str)
    assert MARKER not in sent_for_bob and [m["role"] for m in fake.calls[1]["messages"]] == ["user"]
    # alice's own conversation goes on
    alice.post("/api/chat", json={"text": "and now?"})
    assert MARKER in json.dumps(fake.calls[2]["messages"], default=str) and len(fake.calls[2]["messages"]) == 3
    # a new conversation for bob leaves alice's alone
    bob.post("/api/chat/reset")
    assert hub.llm.memory.count("supervisor") == 1

    # the same for a team agent
    record = client.post("/api/agents", json={"name": "Helper", "provider": "anthropic"}).json()
    fake = use_claude(hub, monkeypatch, responses=[turn("A1"), turn("B1")])
    alice.post(f"/api/agents/{record['id']}/chat", json={"text": f"note {MARKER}"})
    bob.post(f"/api/agents/{record['id']}/chat", json={"text": "hello"})
    assert MARKER not in json.dumps(fake.calls[1]["messages"], default=str)


def test_chat_text_never_reaches_other_accounts(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice, viewer = sign_in("operator", "alice"), sign_in("viewer", "carol")
    events = hub.bus.subscribe(maxsize=5000)
    use_claude(hub, monkeypatch, responses=[turn(f"Your secret plan {MARKER} is safe.")])
    reply = alice.post("/api/chat", json={"text": f"my plan is {MARKER}"}).json()
    assert MARKER in reply["reply"]  # the person who asked gets the answer
    for path in ("/api/messages?limit=2000", "/api/agents/supervisor/messages?limit=2000"):
        rows = viewer.get(path).json()
        assert MARKER not in json.dumps(rows)
        chat = [r for r in rows if r["subject"] == "chat"]
        assert {(r["sender"], r["recipient"], r["kind"]) for r in chat} == {
            ("user:alice", "supervisor", "request"), ("supervisor", "user:alice", "reply")}  # the routing stays
        request = next(r for r in chat if r["kind"] == "request")
        assert request["body"] == {"redacted": "chat", "chars": len(f"my plan is {MARKER}")}
        assert next(r for r in chat if r["kind"] == "reply")["body"]["mode"] == "llm"
    published = [e for e in drain(client, events) if e["type"] == "message"]
    assert published and MARKER not in json.dumps(published)
    hub.bus.unsubscribe(events)
    on_disk = b"".join(p.read_bytes() for p in hub.settings.db_path.parent.glob("hub.db*"))
    assert MARKER.encode() not in on_disk  # nor in the store

    # a chat row written before the fix is redacted on the way out
    hub.store.append("messages", {"sender": "user:alice", "recipient": "agent:x", "subject": "chat",
                                  "body": {"text": "OLD-CHAT-TEXT"}, "kind": "request", "reply_to": None})
    hub.store.append("messages", {"sender": "agent:x", "recipient": "user:alice", "subject": "chat",
                                  "body": {"reply": "OLD-REPLY-TEXT", "mode": "rules"}, "kind": "reply"})
    for path in ("/api/messages", "/api/agents/agent:x/messages"):
        text = viewer.get(path).text
        assert "OLD-CHAT-TEXT" not in text and "OLD-REPLY-TEXT" not in text and '"redacted":"chat"' in text.replace(" ", "")


def test_other_subjects_keep_their_bodies(client):
    hub = client.app.state.hub
    client.portal.call(hub.bus.tell, "hub", "module:grc", "evaluate", {"reason": "visible"})
    row = next(m for m in reversed(client.get("/api/messages").json()) if m["subject"] == "evaluate")
    assert row["body"] == {"reason": "visible"}


def test_rules_chat_is_redacted_too_and_errors_carry_no_text(client, sign_in):
    alice = sign_in("operator", "alice")
    alice.post("/api/chat", json={"text": f"status {MARKER}"})
    assert MARKER not in client.get("/api/messages").text
    record = client.post("/api/agents", json={"name": "Quiet", "provider": "rules"}).json()
    client.patch(f"/api/agents/{record['id']}", json={"enabled": False})
    rows = client.get(f"/api/agents/{record['id']}/messages").json()
    assert all(MARKER not in json.dumps(r) for r in rows)


def test_deleting_an_account_drops_its_conversations(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice = sign_in("operator", "alice")
    use_claude(hub, monkeypatch, responses=[turn("ok")])
    alice.post("/api/chat", json={"text": "hello"})
    user_id = hub.auth.find_user("alice").id
    assert hub.llm.memory.count("supervisor") == 1
    assert client.delete(f"/api/users/{user_id}").status_code == 200
    assert hub.llm.memory.count() == 0


def test_a_conversation_is_bound_to_its_provider_and_model(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice = sign_in("operator", "alice")
    fake = use_claude(hub, monkeypatch, responses=[turn("one"), turn("two")])
    alice.post("/api/chat", json={"text": f"first {MARKER}"})
    client.patch("/api/agents/supervisor", json={"model": "claude-sonnet-5-5"})  # another model: a fresh start
    alice.post("/api/chat", json={"text": "second"})
    assert fake.calls[1]["model"] == "claude-sonnet-5-5" and MARKER not in json.dumps(fake.calls[1]["messages"], default=str)


def test_api_tokens_share_their_owners_conversation(client):
    hub = client.app.state.hub
    memory = hub.llm.memory
    admin = hub.auth.find_user("admin")
    token = client.post("/api/tokens", json={"name": "ci", "role": "operator"}).json()
    assert token["token"]
    assert memory.person_of("user:admin") == f"user:{admin.id}" == memory.person_of("token:ci")
    assert memory.person_of("agent:x") == "agent:x" and memory.person_of("token:missing") == "token:missing"


# -- memory modes (stage 4): off, session, persisted (encrypted, retention), max turns, self-only reads ------------------

def memory(client, agent_id: str, **settings) -> dict:
    saved = client.patch(f"/api/agents/{agent_id}/settings", json={"config": {"memory": settings}})
    assert saved.status_code == 200, saved.text
    return saved.json()


def test_memory_off_sends_one_message_each_time(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice = sign_in("operator", "alice")
    fake = use_claude(hub, monkeypatch, responses=[turn("one"), turn("two")])
    memory(client, "supervisor", mode="off")
    alice.post("/api/chat", json={"text": f"first {MARKER}"})
    alice.post("/api/chat", json={"text": "second"})
    assert [m["role"] for m in fake.calls[1]["messages"]] == ["user"] and MARKER not in json.dumps(fake.calls[1]["messages"])
    assert hub.llm.memory.count("supervisor") == 0
    assert alice.get("/api/agents/supervisor/conversation").json()["memory"]["mode"] == "off"


def test_a_long_conversation_starts_afresh_with_a_notice(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice = sign_in("operator", "alice")
    fake = use_claude(hub, monkeypatch, responses=[turn("a"), turn("b"), turn("c")])
    memory(client, "supervisor", max_turns=2)
    assert alice.post("/api/chat", json={"text": "1"}).json()["reply"] == "a"
    assert alice.post("/api/chat", json={"text": "2"}).json()["reply"] == "b"
    third = alice.post("/api/chat", json={"text": "3"}).json()["reply"]
    assert third.startswith("(Started a new conversation: the earlier one reached this agent's memory limit.)")
    assert third.endswith("c") and [m["role"] for m in fake.calls[2]["messages"]] == ["user"]


def test_persisted_memory_survives_a_restart_encrypted_and_is_purged_after_retention(tmp_path, monkeypatch):
    from conftest import ADMIN_PASSWORD, make_settings
    from fastapi.testclient import TestClient

    from hub.app import create_app

    settings = make_settings(tmp_path)

    def started():
        c = TestClient(create_app(settings), headers={"X-Hub-Request": "1"})
        c.__enter__()
        return c

    first = started()
    hub = first.app.state.hub
    hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
    assert first.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    use_claude(hub, monkeypatch, responses=[turn(f"Noted {MARKER}.")])
    memory(first, "supervisor", mode="persisted", retention_days=3)
    first.post("/api/chat", json={"text": f"remember {MARKER}"})
    [stored] = hub.store.list("agent_conversations")
    admin_id = hub.auth.find_user("admin").id
    assert (stored["agent_id"], stored["user_id"], stored["turns"]) == ("supervisor", admin_id, 1)
    on_disk = b"".join(p.read_bytes() for p in settings.db_path.parent.glob("hub.db*"))
    assert MARKER.encode() not in on_disk  # encrypted at rest (the WAL too)
    assert MARKER in json.dumps(first.get("/api/agents/supervisor/conversation").json())  # the person reads their own
    first.__exit__(None, None, None)

    second = started()
    hub = second.app.state.hub
    assert second.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    fake = use_claude(hub, monkeypatch, responses=[turn("Still here.")])
    view = second.get("/api/agents/supervisor/conversation").json()
    assert view["turns"] == 1 and [m["role"] for m in view["messages"]] == ["user", "assistant"]
    second.post("/api/chat", json={"text": "what did I say?"})
    assert MARKER in json.dumps(fake.calls[0]["messages"], default=str) and len(fake.calls[0]["messages"]) == 3
    doc = hub.store.get("agent_conversations", f"supervisor|user:{admin_id}")
    hub.store.put("agent_conversations", {**doc, "updated_at": time.time() - 4 * 86400})
    assert hub.prune_logs()["agent_conversations"] == 1
    assert hub.store.list("agent_conversations") == [] and hub.llm.memory.count("supervisor") == 0
    second.__exit__(None, None, None)


def test_conversations_are_read_by_their_own_person_only(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice, bob, viewer = sign_in("operator", "alice"), sign_in("operator", "bob"), sign_in("viewer", "carol")
    use_claude(hub, monkeypatch, responses=[turn(f"Hi Alice {MARKER}"), turn("Hi Bob")])
    memory(client, "supervisor", mode="persisted")
    alice.post("/api/chat", json={"text": f"hello {MARKER}"})
    bob.post("/api/chat", json={"text": "hello"})
    assert MARKER in json.dumps(alice.get("/api/agents/supervisor/conversation").json())
    assert MARKER not in json.dumps(bob.get("/api/agents/supervisor/conversation").json())
    assert MARKER not in json.dumps(client.get("/api/agents/supervisor/conversation").json())  # admins see counts only
    assert client.get("/api/agents/supervisor/settings").json()["memory"] == {"sessions": 2, "stored": 2}
    assert viewer.get("/api/agents/supervisor/conversation").status_code == 403
    alice_id = hub.auth.find_user("alice").id
    assert bob.delete(f"/api/agents/supervisor/conversation?user_id={alice_id}").status_code == 403
    assert client.delete(f"/api/agents/supervisor/conversation?user_id={alice_id}").status_code == 200
    assert alice.get("/api/agents/supervisor/conversation").json()["turns"] == 0
    assert any("Deleted a conversation with Hub Supervisor" in e["text"] for e in client.get("/api/activity").json())
    assert bob.delete("/api/agents/supervisor/conversation").json() == {"ok": True}  # "New conversation": their own
    assert hub.store.list("agent_conversations") == []
    assert client.get("/api/agents/operator/conversation").status_code == 400  # it does not chat


def test_switching_persisted_memory_off_deletes_the_stored_conversations(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    alice = sign_in("operator", "alice")
    use_claude(hub, monkeypatch, responses=[turn("ok"), turn("ok")])
    memory(client, "supervisor", mode="persisted")
    alice.post("/api/chat", json={"text": "hello"})
    assert len(hub.store.list("agent_conversations")) == 1
    memory(client, "supervisor", mode="session")
    assert hub.store.list("agent_conversations") == []
    entry = [e for e in client.get("/api/activity").json() if e["text"].startswith("Configured Hub Supervisor")][-1]
    assert "memory persisted -> session" in entry["text"] and "1 stored conversation(s) deleted" in entry["text"]
    # deleting an account drops its stored conversations too
    memory(client, "supervisor", mode="persisted")
    alice.post("/api/chat", json={"text": "again"})
    assert client.delete(f"/api/users/{hub.auth.find_user('alice').id}").status_code == 200
    assert hub.store.list("agent_conversations") == []
