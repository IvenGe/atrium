"""The model-powered paths, exercised with a fake Claude client behind the real provider layer (no network)."""

from pathlib import Path

from llm_fakes import FakeClaude, block, message, submits, use_claude


def test_supervisor_chat_uses_tools_then_answers(client, monkeypatch):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("text", text="Let me look."), block("tool_use", id="tu_1", name="list_tools", input={}),
                             block("tool_use", id="tu_2", name="list_approvals", input={})]),
        message("end_turn", [block("text", text="The suite is empty.")]),
    ])
    reply = client.post("/api/chat", json={"text": "how is the suite doing?"}).json()
    meta = reply.pop("meta")  # which model answered (shown under the reply)
    assert reply.pop("thread").startswith("m_")  # the conversation on the agent bus
    assert reply == {"reply": "The suite is empty.", "mode": "llm"}
    assert (meta["provider"], meta["model"], meta["source"]) == ("anthropic", "claude-opus-5-5", "suite")
    second = fake.calls[1]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "user"]
    results = second[2]["content"]
    assert {r["tool_use_id"] for r in results} == {"tu_1", "tu_2"}  # all results in one user message
    assert all(not r.get("is_error") for r in results)
    assert fake.calls[0]["tools"] and fake.calls[0]["system"]
    assert fake.calls[0]["output_config"] == {"effort": "medium"} and fake.calls[0]["model"] == "claude-opus-5-5"


def test_supervisor_chat_falls_back_to_rules_on_api_failure(client, monkeypatch):
    class Broken(FakeClaude):
        async def create(self, **kwargs):
            raise RuntimeError("network down")

    use_claude(client.app.state.hub, monkeypatch, Broken())
    reply = client.post("/api/chat", json={"text": "help"}).json()
    assert reply["mode"] == "rules" and "(Claude failed (RuntimeError). Falling back" in reply["reply"]
    assert "network down" not in reply["reply"]  # not an API answer: the error class, never an exception's text


def test_patch_agent_code_patch_is_validated(client, wait_for, plain_repo: Path, monkeypatch):
    new_app = (plain_repo / "app.py").read_text() + "\n\n@app.get('/healthz')\ndef healthz():\n    return {'status': 'ok'}\n"
    # the model submits through the read-before-write conversation (hub/agents/reader.py): app.py is an entry hint,
    # shown in full up front, so it may be rewritten without another read
    use_claude(client.app.state.hub, monkeypatch, submits({
        "title": "Add /healthz", "rationale": "Lets the hub monitor the app.", "health_path": "/healthz",
        "changes": [{"path": "app.py", "content": new_app}],
    }))
    tool_id = client.post("/api/tools/import", json={"source_type": "local", "source": str(plain_repo)}).json()["id"]
    patches = wait_for(lambda: client.get(f"/api/tools/{tool_id}").json()["patches"])
    code = next(p for p in patches if p["strategy"] == "health_endpoint")
    assert code["target"] == "repo" and "+@app.get('/healthz')" in code["diff"]
    assert code["manifest_update"] == {"health": {"url": "http://localhost:5000/healthz"}}
    assert code["generated_by"] == {"provider": "anthropic", "model": "claude-opus-5-5"}  # HB-CM-2 evidence
    assert "health_probe" not in {p["strategy"] for p in patches}


def test_patch_agent_refuses_blind_rewrites(client, wait_for, plain_repo: Path, monkeypatch):
    (plain_repo / "secret_module.py").write_text("x = 1\n")
    fake = use_claude(client.app.state.hub, monkeypatch, submits({
        "title": "x", "rationale": "y", "health_path": "", "changes": [{"path": "secret_module.py", "content": "hacked"}]}))
    tool_id = client.post("/api/tools/import", json={"source_type": "local", "source": str(plain_repo)}).json()["id"]
    # the submission is refused (the model never read that file) and the model gives up; the agent falls back to a
    # probe adapter
    patches = wait_for(lambda: [p for p in client.get(f"/api/tools/{tool_id}").json()["patches"] if p["strategy"].startswith("health")])
    assert {p["strategy"] for p in patches} == {"health_probe"}
    assert (plain_repo / "secret_module.py").read_text() == "x = 1\n"
    refused = next(r for c in fake.calls for r in c["messages"][-1]["content"] if isinstance(c["messages"][-1]["content"], list)
                   and r.get("type") == "tool_result" and r.get("is_error"))
    assert "You have not read secret_module.py in full" in refused["content"]
