"""Fakes for subsidiary tests (round4-spec 14.1): a fake clock, a fake tool with the reference bridge
(hub.subsidiary.contract.ReferenceBridge) behind an httpx transport, and a scripted fake sidecar that speaks the sidecar
API through the TestClient. No real tool, model or network."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from conftest import new_browser
from hub.integration import connections
from hub.models import AgentDef
from hub.subsidiary import contract as c
from hub.subsidiary import conformance, governance, keys
from hub.subsidiary.models import BridgeInfo, Charter, CharterAction, StaffScope

TOOL = "helpdesk"
NOW = 1_800_000_000.0
LIST_PARAMS = {"type": "object", "additionalProperties": False,
               "properties": {"q": {"type": "string", "maxLength": 200}}, "required": []}
PRIORITY_PARAMS = {"type": "object", "additionalProperties": False, "required": ["ticket_id", "priority"],
                   "properties": {"ticket_id": {"type": "integer", "minimum": 1},
                                  "priority": {"enum": ["low", "normal", "high"]}}}
MANIFEST = {"contract": c.CONTRACT, "tool_id": TOOL, "stack": "python-fastapi", "core": "python/1.0.0",
            "service_principal": "atrium-team", "panel": {"enabled": True},
            "events": {"names": [f"{TOOL}.ticket.created"]},
            "files": ["atrium/glue.py", "atrium-bridge.json"],
            "actions": [
                {"id": "tickets.list", "title": "List tickets", "description": "Open tickets", "risk": "read",
                 "category": "data", "on_behalf_of": True, "params": LIST_PARAMS},
                {"id": "tickets.set_priority", "title": "Change a ticket's priority", "risk": "write",
                 "category": "workflow", "reversible": True, "params": PRIORITY_PARAMS}]}
MANIFEST_RAW = json.dumps(MANIFEST, indent=2).encode()
PANEL_JS = b"/* a stand-in for the vendored panel widget, while this hub ships none */\n"
HUB_SECRET = "hub-connection-token-0001"
OWN_SECRET = "sidecar-read-only-token-0002"


class Clock:
    def __init__(self, now: float = NOW):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def unreachable(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("no route to the tool", request=request)


def setup(client: TestClient, clock: Clock | None = None, *, allow: bool = True) -> Clock:
    """The hub on a fake clock (the subsidiaries' one), with subsidiaries allowed."""
    clock = clock or Clock()
    client.app.state.hub.subsidiary_config.clock = clock
    client.app.state.hub.subsidiary_config.bridge_transport = httpx.MockTransport(unreachable)  # no real network
    if allow:
        assert client.patch("/api/settings/guardrails", json={"allow_subsidiaries": True}).status_code == 200
    return clock


def add_tool(client: TestClient, tool_id: str = TOOL, *, repo: Path | None = None, connection: str | None = None,
             name: str = "Helpdesk") -> None:
    """A tool with a manifest: an open-source checkout at `repo` (bridge mode), and/or a connection of kind
    `connection` (snipeit for API-only mode, opnsense for a network device)."""
    hub = client.app.state.hub
    hub.store.put("tools", {"id": tool_id, "name": name, "source_type": "local" if repo else "saas",
                            "source": str(repo) if repo else f"https://{tool_id}.example.com",
                            "path": str(repo) if repo else None, "status": "ready",
                            "manifest": {"id": tool_id, "name": name, "kind": "oss" if repo else "saas",
                                         "stack": ["python", "fastapi"] if repo else [],
                                         "ui": {"url": f"http://{tool_id}.internal"}}})
    if connection == "snipeit":
        connections.save(hub, tool_id, "snipeit", {"base_url": f"https://{tool_id}.example.com"},
                         {"token": HUB_SECRET}, "test")
    elif connection == "opnsense":
        connections.save(hub, tool_id, "opnsense", {"base_url": f"https://{tool_id}.example.com"},
                         {"api_key": "key-0001", "api_secret": "secret-0001"}, "test")


def bridge_subsidiary(client: TestClient, tmp_path: Path, tool_id: str = TOOL) -> str:
    """A bridge-mode subsidiary whose bridge patch was applied (the tool now runs the reference bridge). It is proposed
    the way the route does it, without the Patch Agent's bridge patch (test_subsidiary_bridgegen.py covers that)."""
    repo = tmp_path / f"{tool_id}-repo"
    repo.mkdir(exist_ok=True)
    add_tool(client, tool_id, repo=repo)
    sub_id = client.portal.call(governance.propose, client.app.state.hub, tool_id, "bridge", "Keep tickets tidy",
                                "admin").id  # on the hub's loop: it starts the Tool Supervisor
    manifest = c.validate_manifest(MANIFEST_RAW, tool_id=tool_id)
    info = BridgeInfo(patch_id="p_1", stack="python-fastapi", core="python/1.0.0", vendored_core=True,
                      manifest=manifest, manifest_sha256=c.manifest_sha256(MANIFEST_RAW), files=manifest["files"])
    governance.bridge_applied(client.app.state.hub, sub_id, info, "test")
    return sub_id


def sidecar_only_subsidiary(client: TestClient, tool_id: str = TOOL) -> str:
    add_tool(client, tool_id, connection="snipeit")
    made = client.post(f"/api/tools/{tool_id}/subsidiary", json={"mode": "sidecar_only"})
    assert made.status_code == 201, made.text
    saved = client.put(f"/api/subsidiaries/{tool_id}/credential", json={"secrets": {"token": OWN_SECRET}})
    assert saved.status_code == 200, saved.text
    return made.json()["id"]


def charter(mode: str = "bridge", *, staff: str = "agent:clerk", **fields: Any) -> Charter:
    return Charter(version=1, mode=mode, manifest_sha256=c.manifest_sha256(MANIFEST_RAW) if mode == "bridge" else None,
                   mandate="Keep the helpdesk tidy.", actions=[
                       CharterAction(id="tickets.list", title="List tickets", risk="read", category="data",
                                     on_behalf_of=True, params=LIST_PARAMS, policy="allow"),
                       CharterAction(id="tickets.set_priority", title="Change a ticket's priority", risk="write",
                                     category="workflow", reversible=True, params=PRIORITY_PARAMS, policy="approval")],
                   staff={staff: StaffScope(actions=["tickets.list", "tickets.set_priority"])}, **fields)


def approve_charter(client: TestClient, tool_id: str = TOOL, chart: Charter | None = None) -> None:
    """What the charter approval does when it is settled: staff created, charter v1 in force, the subsidiary active
    once conformance passed (governance.after_conformance)."""
    hub = client.app.state.hub
    sub = governance.of_tool(hub, tool_id)
    chart = chart or charter(sub.mode)
    staff_id = next(iter(chart.staff))
    hub.store.put("agent_defs", AgentDef(id=staff_id, name="Clerk", title="Clerk", team=tool_id, placement="sidecar",
                                         permissions=["read", "tool_actions"], parent=f"tool:{tool_id}",
                                         depth=1).model_dump(mode="json"))
    sub.charter, sub.charter_version, sub.charter_approved_by = chart, chart.version, "admin"
    governance.after_conformance(hub, sub, "admin")


class FakeBridge:
    """The tool with the reference bridge: Atrium (bridge_transport) and the fake sidecar reach it through this."""

    def __init__(self, client: TestClient, clock: Clock, tool_id: str = TOOL, *, manifest: bytes = MANIFEST_RAW,
                 keys_value: str | None = None):
        hub = client.app.state.hub
        sub = governance.of_tool(hub, tool_id)
        self.calls: list[str] = []
        self.bridge = c.ReferenceBridge(keys=keys_value if keys_value is not None else keys.bridge_keys(hub, sub.id),
                                        tool=tool_id, sub=sub.id, manifest=manifest,
                                        panel_js=conformance.vendored_panel() or PANEL_JS, clock=clock,
                                        handlers={"tickets.list": lambda params, ctx: [{"id": 1}],
                                                  "tickets.set_priority": lambda params, ctx: {"ok": True}})

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        self.calls.append(path)
        status, answer = self.bridge.handle(request.method, path, dict(request.headers), request.content)
        if isinstance(answer, bytes):
            return httpx.Response(status, content=answer, headers={"content-type": "text/javascript"})
        return httpx.Response(status, json=answer)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def run(self, vectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """What a sidecar does with an inbox ``conformance`` message: run each vector, report rows."""
        rows = []
        for raw in vectors:
            vector = c.Vector.from_json(raw)
            ok, detail, status = True, "ok", None
            for step in vector.steps:
                status, answer = self.bridge.handle(step.method, step.path, step.headers, step.body)
                body = answer if isinstance(answer, bytes) else json.dumps(answer).encode()
                ok, detail = c.check_answer(step, status, body)
                if not ok:
                    break
            rows.append({"id": vector.id, "ok": ok, "status": status, "detail": detail})
        return rows


class FakeSidecar:
    """A scripted sidecar: its own Ed25519 key and token, and one call per sidecar API route."""

    def __init__(self, client: TestClient, clock: Clock):
        self.client, self.clock = client, clock
        self.key = c.new_key()
        self.public = c.public_b64(self.key)
        self.token: str | None = None
        self.http = new_browser(client)
        self.ticket: str | None = None
        self.ticket_exp: int | None = None
        self.cursor = 0

    def use(self, token: str) -> None:
        self.token = token
        self.http.headers["Authorization"] = f"Bearer {token}"

    def enroll(self, code: str, **extra: Any) -> httpx.Response:
        answer = new_browser(self.client).post("/api/subsidiary/v1/enroll",
                                               json={"code": code, "public_key": self.public, "version": "0.1",
                                                     **extra})
        if answer.status_code == 200:
            self.use(answer.json()["token"])
        return answer

    def heartbeat(self, **fields: Any) -> httpx.Response:
        body = {"version": "0.1", "health": "ok", "clock": self.clock(), "ticket_exp": self.ticket_exp, **fields}
        answer = self.http.post("/api/subsidiary/v1/heartbeat", json=body)
        if answer.status_code == 200 and answer.json().get("ticket"):
            self.ticket, self.ticket_exp = answer.json()["ticket"], answer.json()["ticket_exp"]
        return answer

    def inbox(self, wait: int = 0) -> list[dict[str, Any]]:
        answer = self.http.get("/api/subsidiary/v1/inbox", params={"cursor": self.cursor, "wait": wait})
        assert answer.status_code == 200, answer.text
        self.cursor = answer.json()["cursor"]
        return answer.json()["messages"]

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.http.get(f"/api/subsidiary/v1/{path}", **kw)

    def post(self, path: str, body: dict[str, Any] | None = None, **kw: Any) -> httpx.Response:
        return self.http.post(f"/api/subsidiary/v1/{path}", json=body or {}, **kw)

    def call(self, bridge: FakeBridge, action: str, params: dict[str, Any] | None = None, *, grant: str | None = None,
             body: bytes | None = None) -> tuple[int, Any]:
        """A signed bridge call with the current ticket (what the sidecar does for read actions) - with a grant and
        its exact body bytes for a write."""
        jti = json.loads(c.b64u_decode(self.ticket.split(".")[1]))["jti"]  # the sidecar trusts its own ticket
        body = c.body_bytes(params or {}) if body is None else body
        grant_jti = json.loads(c.b64u_decode(grant.split(".")[1]))["jti"] if grant else None
        path = c.call_path(action)
        headers = c.call_headers(self.key, ticket=self.ticket, ticket_jti=jti, path=path, body=body,
                                 date=int(self.clock()), grant=grant, grant_jti=grant_jti)
        return bridge.bridge.handle("POST", path, headers, body)

    def model(self, run_id: str, agent_id: str, messages: list[dict[str, Any]], **extra: Any) -> httpx.Response:
        return self.post("model", {"run_id": run_id, "agent_id": agent_id, "messages": messages, **extra})


def enrolled(client: TestClient, clock: Clock, tool_id: str = TOOL) -> FakeSidecar:
    """An enrollment issued by the signed-in administrator, used by a new fake sidecar."""
    issued = client.post(f"/api/subsidiaries/{tool_id}/enrollment")
    assert issued.status_code == 200, issued.text
    sidecar = FakeSidecar(client, clock)
    assert sidecar.enroll(issued.json()["code"]).status_code == 200
    return sidecar


# -- the work: a scripted model, the real charter approval -------------------------------------------------------------


def local_model(client: TestClient, results: list[Any] | None = None) -> tuple[str, Any]:
    """A local model server whose answers the test scripts (llm_fakes.FakeProvider): with cloud providers off
    (HUB_LLM=off in tests) it is the suite's automatic choice, so new charters route to it."""
    from llm_fakes import FakeProvider

    hub = client.app.state.hub
    created = client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "qwen3:8b"})
    assert created.status_code == 201, created.text
    provider = created.json()["id"]
    fake = FakeProvider(list(results or []))
    hub.llm.adapters[provider] = fake
    hub.llm.invalidate()
    return provider, fake


def charter_approval(hub: Any, tool_id: str = TOOL) -> Any:
    sub = governance.of_tool(hub, tool_id)
    return next((a for a in hub.approvals.list("pending") if a.kind == "subsidiary_charter"
                 and a.payload.get("subsidiary_id") == sub.id), None)


def activate(client: TestClient, tmp_path: Path, wait_for: Any, sign_in: Any, clock: Clock | None = None
             ) -> tuple[Clock, FakeBridge, FakeSidecar, TestClient]:
    """A bridge-mode subsidiary made active the real way: bridge applied, sidecar enrolled, conformance observed by
    Atrium, the drafted charter approved by a second administrator (the first proposed the team). Returns the clock,
    the fake bridge, the fake sidecar (holding an active ticket) and the approving administrator."""
    clock = setup(client, clock)
    hub = client.app.state.hub
    bridge_subsidiary(client, tmp_path)
    bridge = FakeBridge(client, clock)
    hub.subsidiary_config.bridge_transport = bridge.transport()
    sidecar = enrolled(client, clock)
    sidecar.heartbeat()
    approval = wait_for(lambda: charter_approval(hub))
    ada = sign_in("admin", "ada")
    decided = ada.post(f"/api/approvals/{approval.id}", json={"approve": True})
    assert decided.status_code == 200, decided.text
    wait_for(lambda: governance.of_tool(hub, TOOL).status == "active")
    sidecar.ticket_exp = None
    assert sidecar.heartbeat().json()["ticket"]
    return clock, bridge, sidecar, ada


def staff_ids(hub: Any, tool_id: str = TOOL) -> dict[str, str]:
    """{"desk": ..., "clerk": ...} of the subsidiary's charter in force."""
    sub = governance.of_tool(hub, tool_id)
    desk = sub.charter.panel.desk
    clerk = next(a for a in sub.charter.staff if a != desk)
    return {"desk": desk, "clerk": clerk}


def relayed_run(client: TestClient, sidecar: FakeSidecar, agent_id: str, text: str = "Tidy the tickets") -> str:
    """A task from the signed-in person, as the sidecar sees it in its inbox: the run id Atrium issued."""
    given = client.post(f"/api/subsidiaries/{TOOL}/tasks", json={"agent_id": agent_id, "text": text})
    assert given.status_code == 202, given.text
    message = next(m for m in sidecar.inbox() if m["type"] == "run")
    assert message["body"]["run_id"] == given.json()["run_id"]
    return message["body"]["run_id"]
