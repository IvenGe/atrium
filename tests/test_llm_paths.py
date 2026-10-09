"""The Claude-powered paths, exercised with a fake model (no network)."""

from pathlib import Path
from types import SimpleNamespace


class FakeLLM:
    available = True

    def __init__(self, responses=None, json_result=None):
        self.responses = list(responses or [])
        self.json_result = json_result
        self.calls = []

    def status(self):
        return {"available": True, "installed": True, "configured": True, "model": "fake", "last_error": None}

    async def create(self, **kwargs):
        self.calls.append({**kwargs, "messages": list(kwargs["messages"])})  # snapshot: history keeps growing
        return self.responses.pop(0)

    async def json(self, **kwargs):
        self.calls.append(kwargs)
        return self.json_result


def block(type_, **fields):
    return SimpleNamespace(type=type_, **fields)


def test_supervisor_chat_uses_tools_then_answers(client):
    hub = client.app.state.hub
    fake = FakeLLM([
        SimpleNamespace(stop_reason="tool_use", content=[block("text", text="Let me look."),
                                                          block("tool_use", id="tu_1", name="list_tools", input={}),
                                                          block("tool_use", id="tu_2", name="list_approvals", input={})]),
        SimpleNamespace(stop_reason="end_turn", content=[block("text", text="The suite is empty.")]),
    ])
    hub.llm = fake
    reply = client.post("/api/chat", json={"text": "how is the suite doing?"}).json()
    assert reply == {"reply": "The suite is empty.", "mode": "llm"}
    second = fake.calls[1]["messages"]
    assert [m["role"] for m in second] == ["user", "assistant", "user"]
    results = second[2]["content"]
    assert {r["tool_use_id"] for r in results} == {"tu_1", "tu_2"}  # all results in one user message
    assert all(not r.get("is_error") for r in results)
    assert fake.calls[0]["tools"] and fake.calls[0]["system"]


def test_supervisor_chat_falls_back_to_rules_on_api_failure(client):
    class Broken(FakeLLM):
        async def create(self, **kwargs):
            raise RuntimeError("network down")

    client.app.state.hub.llm = Broken()
    reply = client.post("/api/chat", json={"text": "help"}).json()
    assert reply["mode"] == "rules" and "Claude unavailable" in reply["reply"]


def test_patch_agent_code_patch_is_validated(client, wait_for, plain_repo: Path):
    new_app = (plain_repo / "app.py").read_text() + "\n\n@app.get('/healthz')\ndef healthz():\n    return {'status': 'ok'}\n"
    client.app.state.hub.llm = FakeLLM(json_result={
        "title": "Add /healthz", "rationale": "Lets the hub monitor the app.", "health_path": "/healthz",
        "changes": [{"path": "app.py", "content": new_app}],
    })
    tool_id = client.post("/api/tools/import", json={"source_type": "local", "source": str(plain_repo)}).json()["id"]
    patches = wait_for(lambda: client.get(f"/api/tools/{tool_id}").json()["patches"])
    code = next(p for p in patches if p["strategy"] == "health_endpoint")
    assert code["target"] == "repo" and "+@app.get('/healthz')" in code["diff"]
    assert code["manifest_update"] == {"health": {"url": "http://localhost:5000/healthz"}}
    assert "health_probe" not in {p["strategy"] for p in patches}


def test_patch_agent_refuses_blind_rewrites(client, wait_for, plain_repo: Path):
    (plain_repo / "secret_module.py").write_text("x = 1\n")
    client.app.state.hub.llm = FakeLLM(json_result={"title": "x", "rationale": "y", "health_path": "",
                                                    "changes": [{"path": "secret_module.py", "content": "hacked"}]})
    tool_id = client.post("/api/tools/import", json={"source_type": "local", "source": str(plain_repo)}).json()["id"]
    # the code patch is rejected (Claude never saw that file); the agent falls back to a probe adapter
    patches = wait_for(lambda: [p for p in client.get(f"/api/tools/{tool_id}").json()["patches"] if p["strategy"].startswith("health")])
    assert {p["strategy"] for p in patches} == {"health_probe"}
    assert (plain_repo / "secret_module.py").read_text() == "x = 1\n"
