"""Base class for every agent: an inbox, concurrent handlers, and helpers to talk on the bus."""

from __future__ import annotations

import asyncio
import contextlib
import re
import time
from typing import TYPE_CHECKING, Any

from ..bus import AgentError, Message

if TYPE_CHECKING:
    from ..core import Hub


_CLIENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
STOPPED_TEXT = "Stopped. Send another message, or start a new conversation."


def _client_id(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _CLIENT_ID.fullmatch(text) else None


def _format_summary(summary: Any) -> str:
    if not isinstance(summary, dict):
        return str(summary)
    lines = [f"- **{key.replace('_', ' ')}**: {value}" for key, value in summary.items()
             if isinstance(value, (str, int, float)) and not isinstance(value, bool)]
    return "\n".join(lines) or "Nothing to report."


class BaseAgent:
    role = "agent"
    kind = "core"  # core agents are built in; "custom" agents are defined by people or other agents
    title = "Agent"
    description = ""
    default_instructions = ""
    uses_llm = False
    max_concurrency = 4
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
        self._chat_tasks: dict[str, asyncio.Task[None]] = {}
        # Client ids of chats the person stopped before this agent picked them up.
        self._stopped_ids: dict[str, None] = {}

    # -- configuration ---------------------------------------------------------------

    @property
    def model(self) -> str:
        if self.model_override:
            return self.model_override
        from . import teams
        return teams.claude_model(self.hub)

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
        data = {
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
            "chats": True,
            "handled": self.handled,
            "errors": self.errors,
            "active": self.active,
            "queued": self.inbox.qsize(),
            "last_active": self.last_active,
        }
        if self.kind != "custom" and self.uses_llm and not self.hub.llm.available:
            data.update(provider="rules", provider_kind="rules", provider_label="Rules", llm_active=False)
            if not self.model_override:
                data["model"] = ""
        return data

    def cancel_chat(self, client_id: str | None = None) -> bool:
        """Stop the chat in progress. A client id also stops the matching request that has not started yet,
        and does not affect the next message."""
        pending = False
        key = _client_id(client_id)
        if key:
            self._stopped_ids[key] = None
            pending = True
            while len(self._stopped_ids) > 40:
                self._stopped_ids.pop(next(iter(self._stopped_ids)))
        tasks = [task for task in self._chat_tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        return bool(tasks) or pending

    def take_stop(self, body: dict[str, Any]) -> bool:
        """True when this chat was stopped before the handler started. The id is consumed once."""
        key = _client_id(body.get("client_id"))
        if key and key in self._stopped_ids:
            self._stopped_ids.pop(key, None)
            return True
        return False

    def stopped_reply(self) -> dict[str, Any]:
        return {"reply": STOPPED_TEXT, "mode": "stopped", "cancelled": True, "agent_id": self.id}

    async def cancel_chat_wait(self, client_id: str | None = None) -> bool:
        """Cancel like `cancel_chat` and wait until the in-flight chat has actually stopped."""
        tasks = [task for task in self._chat_tasks.values() if not task.done()]
        stopped = self.cancel_chat(client_id)
        pending = [task for task in tasks if not task.done()]
        if pending:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), 8)
        return stopped

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
        task = asyncio.current_task()
        if msg.subject == "chat" and task is not None:
            self._chat_tasks[msg.id] = task
        try:
            async with self._sem:
                self.active += 1
                self.last_active = time.time()
                self._publish()
                try:
                    handler = getattr(self, "on_" + msg.subject.replace(".", "_").replace("-", "_"), None)
                    if handler is None:
                        raise AgentError(f"{self.name} does not handle '{msg.subject}'")
                    if msg.subject == "chat" and self.take_stop(msg.body):
                        result = self.stopped_reply()
                    else:
                        result = await handler(msg.body, msg)
                    if msg.kind == "request":
                        await self.hub.bus.reply(msg, self.id, result or {})
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # an agent must survive any single failure
                    self.errors += 1
                    self.log("error", f"'{msg.subject}' failed: {exc}")
                    if msg.kind == "request":
                        await self.hub.bus.reply(msg, self.id, {"error": str(exc) or exc.__class__.__name__})
                finally:
                    self.active -= 1
                    self.handled += 1
                    self._publish()
        except asyncio.CancelledError:
            if msg.subject == "chat" and msg.kind == "request":
                await self._reply_stopped(msg)
            else:
                raise
        finally:
            self._chat_tasks.pop(msg.id, None)

    async def _reply_stopped(self, msg: Message) -> None:
        current = asyncio.current_task()
        if current is not None:
            while current.uncancel():
                pass
        with contextlib.suppress(Exception):
            await self.hub.bus.reply(msg, self.id, self.stopped_reply())

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

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Talk to this agent directly. Specialists do the work and report it to the Hub Supervisor."""
        text = str(body.get("text") or "").strip()
        if not text:
            raise ValueError("Say something")
        result = await self.direct_chat(text, msg)
        if not isinstance(result, dict):
            result = {"reply": str(result), "mode": "rules"}
        result.setdefault("mode", "rules")
        result["agent_id"] = self.id
        if result.get("cancelled"):
            return result
        if self.id != "supervisor" and msg.sender != "supervisor":
            await self.tell("supervisor", "team.report", {
                "agent_id": self.id, "agent": self.name, "text": text[:500],
                "reply": str(result.get("reply") or "")[:2000], "mode": result.get("mode"),
            })
        return result

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return {"ok": True}

    async def direct_chat(self, text: str, msg: Message) -> dict[str, Any]:
        low = text.lower().strip()
        if not low or low in ("help", "?", "hi", "hello"):
            return {"reply": self.chat_help(), "mode": "rules"}
        if any(word in low for word in ("status", "summary", "report", "overview")) and hasattr(self, "on_summary"):
            summary = await self.on_summary({}, msg)
            return {"reply": _format_summary(summary), "mode": "rules"}
        return {"reply": self.chat_help(), "mode": "rules"}

    def chat_help(self) -> str:
        return (f"I am **{self.name}**. Say `status` and I will report it to the Hub Supervisor. "
                "The supervisor can also send me the work.")

    async def on_command_completed(self, body: dict[str, Any], msg: Message) -> None:
        status = body.get("status")
        self.log("info" if status == "done" and body.get("exit_code") == 0 else "warn",
                 f"Command finished ({status}): {body.get('command')}", exit_code=body.get("exit_code"))
