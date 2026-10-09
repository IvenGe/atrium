"""The agent bus: how agents talk to each other, and how the UI watches them do it.

Every message is persisted to the ``messages`` stream and fanned out to UI
subscribers (Server-Sent Events), so the conversation between agents is always
visible and auditable. Bodies larger than ``LOG_BODY_LIMIT`` (e.g. records a data
flow pulls from a tool) reach their recipient in full but are logged as a summary.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from .store import Store, new_id

LOG_BODY_LIMIT = 32_000


def loggable(record: dict[str, Any]) -> dict[str, Any]:
    """`record` (a dumped Message) with an oversized body replaced by a summary of it."""
    size = len(json.dumps(record.get("body"), default=str))
    if size <= LOG_BODY_LIMIT:
        return record
    summary: dict[str, Any] = {}
    for key, value in (record.get("body") or {}).items():
        if isinstance(value, list):
            summary[key] = f"<{len(value)} items>"
        else:
            summary[key] = value if len(json.dumps(value, default=str)) <= 2000 else "<omitted>"
    return {**record, "body": {**summary, "_truncated": f"{size} bytes, not logged in full"}}


class Message(BaseModel):
    id: str = Field(default_factory=lambda: new_id("m_"))
    sender: str
    recipient: str
    subject: str
    body: dict[str, Any] = {}
    kind: Literal["request", "reply", "event"] = "event"
    reply_to: str | None = None
    ts: float = Field(default_factory=time.time)


class AgentError(RuntimeError):
    """Raised when an agent cannot be reached or answers a request with an error."""


class Bus:
    def __init__(self, store: Store):
        self.store = store
        self._inboxes: dict[str, asyncio.Queue[Message]] = {}
        self._pending: dict[str, asyncio.Future[Message]] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()

    # -- agents ----------------------------------------------------------------------

    def attach(self, agent_id: str, inbox: asyncio.Queue[Message]) -> None:
        self._inboxes[agent_id] = inbox

    def detach(self, agent_id: str) -> None:
        self._inboxes.pop(agent_id, None)

    async def send(self, msg: Message) -> None:
        record = self.store.append("messages", loggable(msg.model_dump(mode="json")))
        self.publish("message", record)
        if msg.kind == "reply":
            fut = self._pending.get(msg.reply_to or "")
            if fut and not fut.done():
                fut.set_result(msg)
            return
        inbox = self._inboxes.get(msg.recipient)
        if inbox is None:
            fut = self._pending.get(msg.id)
            if fut and not fut.done():
                fut.set_exception(AgentError(f"No agent named '{msg.recipient}'"))
            return
        inbox.put_nowait(msg)

    async def request(
        self, sender: str, recipient: str, subject: str, body: dict[str, Any] | None = None, timeout: float = 300.0
    ) -> dict[str, Any]:
        """Send a request and wait for the recipient's reply."""
        msg = Message(sender=sender, recipient=recipient, subject=subject, body=body or {}, kind="request")
        fut: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._pending[msg.id] = fut
        try:
            await self.send(msg)
            reply = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            raise AgentError(f"{recipient} did not answer '{subject}' within {timeout:.0f}s") from exc
        finally:
            self._pending.pop(msg.id, None)
        if "error" in reply.body:
            raise AgentError(str(reply.body["error"]))
        return reply.body

    async def tell(self, sender: str, recipient: str, subject: str, body: dict[str, Any] | None = None) -> None:
        """Fire-and-forget notification."""
        await self.send(Message(sender=sender, recipient=recipient, subject=subject, body=body or {}))

    async def reply(self, request: Message, sender: str, body: dict[str, Any]) -> None:
        await self.send(
            Message(
                sender=sender,
                recipient=request.sender,
                subject=request.subject,
                body=body,
                kind="reply",
                reply_to=request.id,
            )
        )

    # -- UI fan-out ------------------------------------------------------------------

    def publish(self, type_: str, data: Any) -> None:
        event = {"type": type_, "data": data}
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # a slow browser tab must never stall the agents

    def subscribe(self, maxsize: int = 500) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)
