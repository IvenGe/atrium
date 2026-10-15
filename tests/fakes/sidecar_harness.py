"""The sidecar under test (round4-spec 14.1): the REAL runtime (hub.subsidiary.sidecar.Runtime) wired to

- a scripted fake Atrium (FakeAtrium): the sidecar API of section 9.2 on an httpx.MockTransport, signing tickets and
  grants with its own key, answering the model gateway from a script - or the real app through
  httpx.ASGITransport(app=client.app);
- the fake Helpdesk with the REAL vendored bridge core (tests/fakes/subsidiary_tool.py) through
  httpx.ASGITransport(app=tool.app).

Every step runs on one event loop: the harness's own, or the TestClient's portal for the real app, so the hub and the
sidecar share it. No real tool, model or network.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx

from hub.subsidiary import contract as c
from hub.subsidiary.models import (ActionReply, ActionRequest, Budgets, CharterAction, CharterTool, CharterView,
                                   ConformanceResults, EventsRequest, EventSettings, ModelRequest, PanelSettings,
                                   ReplyRequest, ReportRequest, RunCreated)
from hub.subsidiary.sidecar.config import ALLOW_HTTP_ENV, ENROLL_ENV, parse
from hub.subsidiary.sidecar.runtime import Runtime
from hub.subsidiary.wire import WireResult, WireToolCall

from . import subsidiary_tool as fake

ATRIUM_URL = "http://atrium.test"
BRIDGE_URL = "http://helpdesk.test"
CODE = "one-time-enrollment-code-0123456789abcdef"
DESK, CLERK = "agent:desk", "agent:clerk"
PREFIX = "/api/subsidiary/v1/"


def say(text: str) -> WireResult:
    return WireResult(text=text, stop="end")


def use(name: str, arguments: dict[str, Any] | None = None, *, text: str = "", call_id: str = "call_1") -> WireResult:
    return WireResult(text=text, stop="tool_calls",
                      tool_calls=[WireToolCall(id=call_id, name=name, arguments=arguments or {})])


def charter_actions() -> list[CharterAction]:
    policy = {"read": "allow", "propose": "allow", "write": "approval", "admin": "approval"}
    return [CharterAction(**{k: v for k, v in a.items() if k in CharterAction.model_fields},
                          policy=policy[a["risk"]]) for a in fake.MANIFEST["actions"]]


def helpdesk_charter(version: int = 1, *, panel: bool = True, events: bool = True) -> CharterView:
    """The charter view of the fake Helpdesk's team: a front desk (reads and drafts) and a clerk (reads, priority
    changes, one hub tool)."""
    actions = charter_actions()
    act = [CharterTool(name=c.tool_name(a.id), action_id=a.id, risk=a.risk) for a in actions]
    panel_tools = [t for t, a in zip(act, actions) if (a.risk == "read" and a.on_behalf_of) or a.risk == "propose"]
    return CharterView(
        subsidiary_id=fake.SUB, tool_id=fake.TOOL, mode="bridge", version=version,
        staff={DESK: {"name": "Front desk", "title": "Front desk", "enabled": True,
                      "actions": ["tickets.list", "tickets.draft_reply"], "hub_tools": []},
               CLERK: {"name": "Clerk", "title": "Clerk", "enabled": True,
                       "actions": ["tickets.list", "tickets.set_priority", "tickets.delete"],
                       "hub_tools": ["get_tool"]}},
        actions=actions,
        tools={"normal": [*act, CharterTool(name=c.hub_tool_name("get_tool")), CharterTool(name=c.REPORT_TOOL),
                          CharterTool(name=c.ESCALATE_TOOL)],
               "panel": [*panel_tools, CharterTool(name=c.ESCALATE_TOOL)] if panel else []},
        panel=PanelSettings(enabled=panel, desk=DESK if panel else None), events=EventSettings(relay=events),
        budgets=Budgets())


class FakeAtrium:
    """A scripted Atrium: what it was sent is recorded, what it answers is set by the test."""

    def __init__(self, clock: Callable[[], float], *, mode: str = "bridge", charter: CharterView | None = None,
                 status: str = "active"):
        self.clock, self.mode = clock, mode
        self.key = c.new_key(bytes([42]) * 32)
        self.bridge_keys = c.public_b64(self.key)
        self.tool, self.sub = fake.TOOL, fake.SUB
        self.status, self.flags = status, []
        self.charter = charter or helpdesk_charter()
        self.ticket_mode: str | None = None  # None: from the status
        self.tokens: set[str] = set()
        self.revoked = False
        self.sidecar_key: str | None = None
        self.inbox: list[dict[str, Any]] = []
        self.seq = 0
        self.calls: list[tuple[str, str]] = []
        self.bodies: dict[str, list[Any]] = {}
        self.model: list[WireResult | Callable[[ModelRequest], Any]] = []
        self.decide: Callable[[ActionRequest], ActionReply] = lambda req: ActionReply(
            status="pending_approval", approval_id="ap_1")
        self.regrant: Callable[[str, dict[str, Any]], ActionReply] | None = None
        self.hub_reply: dict[str, Any] = {"ok": True, "result": {"id": fake.TOOL, "name": "Helpdesk"}}
        self.runs_refused: int | None = None
        self.credential: dict[str, Any] | None = None
        self.turns = 0
        self.fail_next = 0  # answer 503 this many times

    # -- what tests script ------------------------------------------------------------------------

    def post(self, type_: str, body: dict[str, Any]) -> int:
        self.seq += 1
        self.inbox.append({"seq": self.seq, "type": type_, "body": body, "created_at": self.clock(),
                           "expires_at": self.clock() + 900})
        return self.seq

    def grant(self, action_id: str, params: dict[str, Any], *, approval_id: str = "ap_1", run_id: str = "run_1",
              agent_id: str = CLERK, ttl: int = c.GRANT_TTL, body: bytes | None = None) -> dict[str, Any]:
        """A grant message for exactly these params (or `body`), as Atrium posts it after an approval."""
        raw = c.body_bytes(params)
        token, _ = c.make_grant(self.key, sub=self.sub, tool=self.tool, cv=self.charter.version, act=action_id,
                                body=raw, apv=approval_id, now=int(self.clock()), ttl=ttl)
        return {"approval_id": approval_id, "grant": token, "body_b64": c.b64u(raw if body is None else body),
                "action_id": action_id, "run_id": run_id, "agent_id": agent_id}

    def sent(self, path: str) -> list[Any]:
        return self.bodies.get(path, [])

    # -- the API --------------------------------------------------------------------------------------

    def _ticket(self) -> tuple[str, int] | None:
        if self.mode != "bridge" or self.sidecar_key is None or self.status not in ("probation", "active"):
            return None
        mode = self.ticket_mode or ("active" if self.status == "active" else "probation")
        act = c.ticket_actions(mode, [a.id for a in self.charter.actions], panel=self.charter.panel.enabled,
                               events=self.charter.events.relay)
        token, payload = c.make_ticket(self.key, sub=self.sub, tool=self.tool, cv=self.charter.version, mode=mode,
                                       act=act, cnf=self.sidecar_key, rl={"calls_per_min": 600,
                                                                          "panel_per_user_hour": 10},
                                       now=int(self.clock()))
        return token, payload["exp"]

    @staticmethod
    def answer(status: int, body: Any = None, headers: dict[str, str] | None = None) -> httpx.Response:
        return httpx.Response(status, json=body, headers=headers)

    def refuse(self, status: int, code: str, message: str = "") -> httpx.Response:
        return self.answer(status, {"detail": {"code": code, "message": message or code}})

    async def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        assert path.startswith(PREFIX), path
        route = path[len(PREFIX):]
        self.calls.append((request.method, route))
        raw = request.content
        data = json.loads(raw) if raw else None
        self.bodies.setdefault(route, []).append(data)
        if self.fail_next:
            self.fail_next -= 1
            return self.answer(503, {"detail": "unavailable"})
        if route == "enroll":
            if request.headers.get("x-hub-request") != "1" or "authorization" in request.headers:
                return self.answer(403, {"detail": "Missing X-Hub-Request header"})
            if data["code"] != CODE or self.sidecar_key is not None:
                return self.refuse(401, "bad_code", "This enrollment code is unknown, used or expired.")
            self.sidecar_key = data["public_key"]
            token = f"hubtok_sidecar{len(self.tokens)}_" + "t" * 30
            self.tokens.add(token)
            return self.answer(200, {"token": token, "subsidiary_id": self.sub, "tool_id": self.tool,
                                     "expires_at": self.clock() + 30 * 86400})
        bearer = request.headers.get("authorization", "")
        if self.revoked or not bearer.startswith("Bearer ") or bearer[7:] not in self.tokens:
            return self.answer(401, {"detail": "Sign in required"})
        if self.status in ("stopped", "archived"):
            return self.refuse(423, "stopped", "The subsidiary was stopped.")
        exempt = route in ("heartbeat", "inbox", "rotate")
        if not exempt:
            if self.status == "paused":
                return self.refuse(423, "paused", "The subsidiary is paused by Atrium.")
            version = request.headers.get("atrium-charter-version")
            if version is not None and version != str(self.charter.version):
                return self.refuse(409, "charter_changed")
        return await self.route(request, route, data)

    async def route(self, request: httpx.Request, route: str, data: Any) -> httpx.Response:
        if route == "rotate":
            token = f"hubtok_rotated{len(self.tokens)}_" + "r" * 30
            self.tokens.add(token)
            return self.answer(200, {"token": token, "expires_at": self.clock() + 30 * 86400})
        if route == "heartbeat":
            issued = self._ticket() if data.get("ticket_exp") is None or data["ticket_exp"] - self.clock() < 300 \
                else None
            return self.answer(200, {"status": self.status, "flags": self.flags, "ticket": issued and issued[0],
                                     "ticket_exp": issued and issued[1], "charter_version": self.charter.version,
                                     "server_time": self.clock()})
        if route == "charter":
            body = self.charter.model_dump(mode="json")
            etag = f'"v{self.charter.version}"'
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304, headers={"ETag": etag})
            return self.answer(200, body, {"ETag": etag})
        if route == "credential":
            return self.answer(200, self.credential) if self.credential else self.refuse(404, "no_credential")
        if route == "inbox":
            cursor = int(request.url.params.get("cursor", 0))
            self.inbox = [m for m in self.inbox if m["seq"] > cursor]
            return self.answer(200, {"messages": list(self.inbox),
                                     "cursor": max([cursor, *(m["seq"] for m in self.inbox)])})
        if route == "replies":
            ReplyRequest.model_validate(data)
            return self.answer(200, {"ok": True})
        if route == "runs":
            if self.runs_refused:
                return self.refuse(self.runs_refused, "budget")
            return self.answer(201, RunCreated(run_id=f"run_p{len(self.sent('runs'))}", max_turns=6,
                                               max_tool_calls=20).model_dump())
        if route.startswith("runs/") and route.endswith("/end"):
            return self.answer(200, {"ok": True})
        if route == "model":
            req = ModelRequest.model_validate(data)
            assert self.model, "the model was asked more often than the test scripted"
            step = self.model.pop(0)
            result = step(req) if callable(step) else step
            if inspect.isawaitable(result):  # a step that waits (a run under way while the test pauses it)
                result = await result
            self.turns += 1
            return self.answer(200, result.model_copy(update={"ref": f"t{self.turns}"}).model_dump(mode="json"))
        if route == "actions/request":
            return self.answer(200, self.decide(ActionRequest.model_validate(data)).model_dump(mode="json"))
        if route.startswith("actions/") and route.endswith("/regrant"):
            assert self.regrant is not None
            return self.answer(200, self.regrant(route.split("/")[1], data).model_dump(mode="json"))
        if route.startswith("actions/") and route.endswith("/result"):
            return self.answer(200, {"ok": True})
        if route == "hub-request":
            return self.answer(200, self.hub_reply)
        if route == "reports":
            ReportRequest.model_validate(data)
            return self.answer(201, {"id": f"rep_{len(self.sent('reports'))}"})
        if route == "events":
            EventsRequest.model_validate(data)
            return self.answer(200, {"ok": True, "accepted": len(data["events"])})
        if route == "conformance":
            ConformanceResults.model_validate(data)
            return self.answer(200, {"ok": all(r["ok"] for r in data["rows"]), "status": self.status})
        return self.answer(404, {"detail": "Not Found"})

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)


class Sleeps:
    """An injected sleep: records each delay and returns at once."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
        await asyncio.sleep(0)


class SidecarHarness:
    """The real sidecar runtime with injected transports, clock and sleep; `--once` steps as methods."""

    def __init__(self, state_dir: Path, clock: Callable[[], float], *, atrium: httpx.AsyncBaseTransport,
                 tool: Any = None, mode: str = "bridge", atrium_url: str = ATRIUM_URL, sub: str = fake.SUB,
                 tool_id: str = fake.TOOL, code: str | None = CODE,
                 connector_transport: httpx.AsyncBaseTransport | None = None,
                 portal: Any = None, config: dict[str, Any] | None = None):
        env = {ALLOW_HTTP_ENV: "1", **({ENROLL_ENV: code} if code else {})}
        self.config = parse({"atrium_url": atrium_url, "subsidiary_id": sub, "tool_id": tool_id, "mode": mode,
                             **({"bridge_url": BRIDGE_URL} if mode == "bridge" else {}),
                             "state_dir": str(state_dir), **(config or {})}, env)
        self.sleeps = Sleeps()
        self.tool = tool
        bridge = httpx.ASGITransport(app=tool.app) if tool is not None else None
        self.rt = Runtime(self.config, atrium_transport=atrium, bridge_transport=bridge,
                          connector_transport=connector_transport, clock=clock, sleep=self.sleeps, env=env)
        self.portal = portal
        self.loop = asyncio.new_event_loop() if portal is None else None

    def run(self, work: Callable[[], Awaitable[Any]]) -> Any:
        if self.portal is not None:
            return self.portal.call(work)
        return self.loop.run_until_complete(work())  # type: ignore[union-attr]

    def close(self) -> None:
        self.run(self.rt.aclose)
        if self.loop is not None:
            self.loop.close()

    # -- the --once steps -------------------------------------------------------------------------

    def enroll(self) -> None:
        self.run(self.rt.enroll)

    def heartbeat_once(self) -> Any:
        return self.run(self.rt.heartbeat_once)

    def start(self) -> Any:
        return self.run(self.rt.start)

    def inbox_once(self) -> list[Any]:
        """One inbox poll, waiting for the work it started (runs, grants, conformance)."""
        async def go() -> list[Any]:
            started = await self.rt.inbox_once(wait=0)
            return list(await asyncio.gather(*started, return_exceptions=True))
        return self.run(go)

    def panel_once(self) -> list[Any]:
        async def go() -> list[Any]:
            started = await self.rt.panel.once(wait=0)
            return list(await asyncio.gather(*started, return_exceptions=True))
        return self.run(go)

    def events_once(self) -> int:
        return self.run(lambda: self.rt.events.once(wait=0))

    def run_conformance(self, message: dict[str, Any]) -> Any:
        from hub.subsidiary.models import ConformanceMessage
        return self.run(lambda: self.rt.run_conformance(ConformanceMessage.model_validate(message)))
