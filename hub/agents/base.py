"""Base class for every agent: an inbox, concurrent handlers, and helpers to talk on the bus."""

from __future__ import annotations

import asyncio
import contextlib
import time
from typing import TYPE_CHECKING, Any

from ..bus import AgentError, Message

if TYPE_CHECKING:
    from ..core import Hub


class BaseAgent:
    role = "agent"
    kind = "core"  # core agents are built in; "custom" agents are defined by people or other agents
    title = "Agent"
    description = ""
    default_instructions = ""
    uses_llm = False
    max_concurrency = 4
    # Subjects handled outside the max_concurrency slots: quick, local work that must not wait behind slow handlers
    # (e.g. the GRC Supervisor's evaluation behind a data flow that waits minutes for a tool).
    unthrottled_subjects: frozenset[str] = frozenset()
    # What the agent may do through the shared toolkit, and the most a member of its team may get while the
    # limit_to_parent_permissions guardrail is on (see agents/teams.py).
    permissions: tuple[str, ...] = ("read",)

    def __init__(self, hub: "Hub", agent_id: str, name: str, scope: str | None = None):
        self.hub = hub
        self.id = agent_id
        self.name = name
        self.scope = scope
        self.inbox: asyncio.Queue[Message] = asyncio.Queue()
        self.paused = False
        self.model_override: str | None = None
        self.instructions_override: str | None = None
        self.handled = 0
        self.errors = 0
        self.active = 0
        self.last_active: float | None = None
        self._resume = asyncio.Event()
        self._resume.set()
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._loop_task: asyncio.Task[None] | None = None
        self._tasks: set[asyncio.Task[None]] = set()

    # -- configuration ---------------------------------------------------------------

    @property
    def model(self) -> str:
        return self.model_override or self.hub.prefs["model"]

    @property
    def instructions(self) -> str:
        return self.instructions_override or self.default_instructions

    @property
    def team(self) -> str:
        """The team the agent leads or belongs to: "hub", a tool id or a built-in app's agent id."""
        return "hub"

    @property
    def status(self) -> str:
        if self.paused:
            return "paused"
        return "working" if self.active else "idle"

    def set_paused(self, paused: bool) -> None:
        self.paused = paused
        if paused:
            self._resume.clear()
        else:
            self._resume.set()
        self._publish()

    def record(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "title": self.title,
            "description": self.description,
            "scope": self.scope,
            "status": self.status,
            "paused": self.paused,
            "model": self.model,
            "model_override": self.model_override,
            "instructions": self.instructions,
            "custom_instructions": self.instructions_override is not None,
            "uses_llm": self.uses_llm,
            "llm_active": self.uses_llm and self.hub.llm.available,
            "kind": self.kind,
            "provider": "anthropic" if self.uses_llm else "rules",
            "provider_kind": "anthropic" if self.uses_llm else "rules",
            "provider_label": "Claude" if self.uses_llm else "Rules",
            "permissions": list(self.permissions),
            "effective_permissions": list(self.permissions),
            "team": self.team,
            "parent": None,
            "depth": 0,
            "enabled": not self.paused,
            "handled": self.handled,
            "errors": self.errors,
            "active": self.active,
            "queued": self.inbox.qsize(),
            "last_active": self.last_active,
        }

    # -- lifecycle -------------------------------------------------------------------

    def start(self) -> None:
        self.hub.bus.attach(self.id, self.inbox)
        self._loop_task = asyncio.create_task(self._loop(), name=f"agent:{self.id}")
        self.setup()

    def setup(self) -> None:
        """Hook for subclasses."""

    async def stop(self) -> None:
        self.hub.bus.detach(self.id)
        tasks = [t for t in (self._loop_task, *self._tasks) if t]
        for task in tasks:
            task.cancel()
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    async def _loop(self) -> None:
        while True:
            msg = await self.inbox.get()
            await self._resume.wait()
            task = asyncio.create_task(self._process(msg))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _process(self, msg: Message) -> None:
        if msg.subject in self.unthrottled_subjects:
            await self._handle(msg)
            return
        async with self._sem:
            await self._handle(msg)

    async def _handle(self, msg: Message) -> None:
        self.active += 1
        self.last_active = time.time()
        self._publish()
        try:
            handler = getattr(self, "on_" + msg.subject.replace(".", "_").replace("-", "_"), None)
            if handler is None:
                raise AgentError(f"{self.name} does not handle '{msg.subject}'")
            result = await handler(msg.body, msg)
            if msg.kind == "request":
                await self.hub.bus.reply(msg, self.id, result or {})
        except Exception as exc:  # an agent must survive any single failure
            self.errors += 1
            self.log("error", f"'{msg.subject}' failed: {exc}")
            if msg.kind == "request":
                await self.hub.bus.reply(msg, self.id, {"error": str(exc) or exc.__class__.__name__})
        finally:
            self.active -= 1
            self.handled += 1
            self._publish()

    # -- talking ---------------------------------------------------------------------

    async def ask(self, recipient: str, subject: str, body: dict[str, Any] | None = None, timeout: float = 300) -> dict[str, Any]:
        return await self.hub.bus.request(self.id, recipient, subject, body or {}, timeout)

    async def tell(self, recipient: str, subject: str, body: dict[str, Any] | None = None) -> None:
        await self.hub.bus.tell(self.id, recipient, subject, body or {})

    def log(self, level: str, text: str, **data: Any) -> None:
        self.hub.activity(self.id, level, text, **data)

    def _publish(self) -> None:
        self.hub.bus.publish("agent", self.record())

    # Notifications every agent understands --------------------------------------------

    async def on_command_completed(self, body: dict[str, Any], msg: Message) -> None:
        status = body.get("status")
        self.log("info" if status == "done" and body.get("exit_code") == 0 else "warn",
                 f"Command finished ({status}): {body.get('command')}", exit_code=body.get("exit_code"))
