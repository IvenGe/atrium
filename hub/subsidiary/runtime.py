"""In-process state of the subsidiaries (``hub.subsidiaries``), their injectable settings
(``hub.subsidiary_config``) and the persistent inbox each sidecar long-polls (8.1, ``subsidiary_inbox``).

The runtime assumes one hub process, like the rest of Atrium: inbox wake-ups, reply futures, per-subsidiary locks,
per-token request counters and the last ticket issued to each sidecar live in memory. A restart loses only those: the
sidecar's next heartbeat gets a new ticket, its next poll the messages still stored.

Inbox messages are stored as ``<subsidiary id>:<12-digit seq>``; the counter is ``<subsidiary id>#seq`` (outside the
message prefix). A message expires (15 minutes, a grant with its grant); a poll's cursor acknowledges every message up
to it, which deletes them.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

import httpx

from ..auth.service import Throttle
from .models import COLLECTIONS, INBOX_BODIES, INBOX_EXPIRY, INBOX_OPEN_MAX, InboxItem, InboxMessage

if TYPE_CHECKING:
    from ..core import Hub

INBOX = COLLECTIONS["inbox"]
CALLS_PER_MINUTE = 120  # per sidecar token, every /api/subsidiary/v1 route
OPEN_POLLS = 2  # long-polls one token may hold open at once
CONTROL_TYPES = ("pause", "resume", "stop", "charter_changed")
_seq_lock = threading.Lock()


@dataclass
class SubsidiaryConfig:
    """What tests (and operations) inject: the clock, the HTTP transport to bridges for Atrium-run conformance, how
    long an inbox poll waits at most, and the bridge patches' test runner (``bridgepatch.BridgeTestConfig``)."""

    clock: Callable[[], float] = time.time
    bridge_transport: httpx.AsyncBaseTransport | None = None
    bridge_timeout: float = 10.0
    poll_wait: float = 25.0
    bridge_test: Any = None


@dataclass
class IssuedTicket:
    """The last ticket issued to a subsidiary's sidecar: a heartbeat renews it at half-life or when what it lists
    changed (status, charter, key)."""

    key: tuple[Any, ...]
    exp: int
    renewals: int = 0


@dataclass
class SubsidiaryRuntime:
    hub: "Hub"
    locks: dict[str, asyncio.Lock] = field(default_factory=dict)
    replies: dict[str, asyncio.Future[Any]] = field(default_factory=dict)  # correlation id -> a relayed run's reply
    tickets: dict[str, IssuedTicket] = field(default_factory=dict)
    conformance: dict[str, float] = field(default_factory=dict)  # sub id -> built_at of vectors a sidecar runs
    tasks: dict[str, asyncio.Task[Any]] = field(default_factory=dict)  # sub id -> a running Atrium-run conformance
    polls: dict[str, int] = field(default_factory=dict)  # token id -> open inbox polls
    # run id -> the gateway's assistant turns by ref (with the provider-native output, re-attached when the sidecar
    # sends a turn back; a turn Atrium did not return is refused)
    turns: dict[str, dict[str, Any]] = field(default_factory=dict)
    # sub id -> the gateway's model calls in flight: (run id, reserved tokens), counted against the budgets until booked
    flights: dict[str, list[tuple[str, int]]] = field(default_factory=dict)
    enroll_throttle: Throttle = field(default_factory=Throttle)
    _background: set[asyncio.Task[Any]] = field(default_factory=set)
    _calls: dict[str, deque[float]] = field(default_factory=dict)
    _waiters: dict[str, set[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = field(default_factory=dict)

    def lock(self, sub_id: str) -> asyncio.Lock:
        return self.locks.setdefault(sub_id, asyncio.Lock())

    def background(self, work: Any) -> asyncio.Task[Any]:
        """Run a coroutine after the answer (event deliveries), keeping it referenced until it is done."""
        task = asyncio.get_running_loop().create_task(work)
        self._background.add(task)
        task.add_done_callback(self._background.discard)
        return task

    def allow_call(self, token_id: str, now: float) -> bool:
        """The per-token rate limit (CALLS_PER_MINUTE over a sliding minute)."""
        calls = self._calls.setdefault(token_id, deque())
        while calls and calls[0] <= now - 60:
            calls.popleft()
        if len(calls) >= CALLS_PER_MINUTE:
            return False
        calls.append(now)
        return True

    def settle(self, correlation_id: str, answer: dict[str, Any]) -> bool:
        """Give the proxy waiting for a relayed run's reply this answer now (safe from any thread); whether one
        waited."""
        future = self.replies.pop(correlation_id, None)
        if future is None or future.done():
            return False

        def deliver() -> None:
            if not future.done():
                future.set_result(answer)
        try:
            future.get_loop().call_soon_threadsafe(deliver)
        except RuntimeError:  # that loop is closed
            return False
        return True

    def notify(self, sub_id: str) -> None:
        """Wake the inbox polls of a subsidiary (safe from any thread)."""
        for loop, event in list(self._waiters.get(sub_id, ())):
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:  # that loop is closed
                self._waiters.get(sub_id, set()).discard((loop, event))

    async def wait(self, sub_id: str, timeout: float) -> None:
        """Until a message is posted for the subsidiary, or `timeout` seconds."""
        waiter = (asyncio.get_running_loop(), asyncio.Event())
        self._waiters.setdefault(sub_id, set()).add(waiter)
        try:
            await asyncio.wait_for(waiter[1].wait(), timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            self._waiters.get(sub_id, set()).discard(waiter)

    def forget(self, sub_id: str) -> None:
        """Drop what the runtime holds for a stopped subsidiary."""
        self.tickets.pop(sub_id, None)
        self.conformance.pop(sub_id, None)
        task = self.tasks.pop(sub_id, None)
        if task is not None and not task.done():
            task.cancel()
        self.notify(sub_id)


# --------------------------------------------------------------------------------------
# the inbox (persistent)
# --------------------------------------------------------------------------------------


def _doc_id(sub_id: str, seq: int) -> str:
    return f"{sub_id}:{seq:012d}"


def _load(doc: dict[str, Any]) -> InboxMessage:
    return InboxMessage.model_validate({**doc, "id": doc["seq"]})


def stored(hub: "Hub", sub_id: str) -> list[InboxMessage]:
    return [_load(d) for d in hub.store.list_prefix(INBOX, f"{sub_id}:")]


def _put(hub: "Hub", msg: InboxMessage) -> None:
    hub.store.put(INBOX, {**msg.model_dump(mode="json"), "id": _doc_id(msg.subsidiary_id, msg.id), "seq": msg.id})


def post(hub: "Hub", sub_id: str, type_: str, body: dict[str, Any], *, expires_at: float | None = None) -> InboxMessage:
    """Queue a message for the sidecar (the body is checked against its model in models.INBOX_BODIES). At most
    INBOX_OPEN_MAX open messages: beyond that the oldest work message is cancelled - control messages always go."""
    body = INBOX_BODIES[type_].model_validate(body).model_dump(mode="json")
    now = hub.subsidiary_config.clock()
    with _seq_lock:
        counter = hub.store.get(INBOX, f"{sub_id}#seq") or {"id": f"{sub_id}#seq", "seq": 0}
        counter["seq"] += 1
        hub.store.put(INBOX, counter)
        msg = InboxMessage(id=counter["seq"], subsidiary_id=sub_id, type=type_, body=body,  # type: ignore[arg-type]
                           created_at=now, expires_at=expires_at or now + INBOX_EXPIRY)
        _put(hub, msg)
    open_msgs = [m for m in stored(hub, sub_id) if not m.cancelled and m.expires_at > now]
    excess = len(open_msgs) - INBOX_OPEN_MAX
    for old in [m for m in open_msgs if m.type not in CONTROL_TYPES][:max(0, excess)]:
        old.cancelled = True
        _put(hub, old)
    hub.subsidiaries.notify(sub_id)
    return msg


def pending(hub: "Hub", sub_id: str, cursor: int) -> list[InboxMessage]:
    """Messages after `cursor` that are neither cancelled nor expired, oldest first."""
    now = hub.subsidiary_config.clock()
    return [m for m in stored(hub, sub_id) if m.id > cursor and not m.cancelled and m.expires_at > now]


def acknowledge(hub: "Hub", sub_id: str, cursor: int) -> int:
    """The sidecar handled everything up to `cursor`: those messages go."""
    ids = [_doc_id(sub_id, m.id) for m in stored(hub, sub_id) if m.id <= cursor]
    return hub.store.delete_many(INBOX, ids) if ids else 0


def delivered(hub: "Hub", messages: list[InboxMessage]) -> list[InboxItem]:
    now = hub.subsidiary_config.clock()
    out = []
    for msg in messages:
        if msg.delivered_at is None:
            msg.delivered_at = now
            _put(hub, msg)
        out.append(InboxItem.model_validate(msg.wire()))
    return out


def cancel(hub: "Hub", sub_id: str, types: tuple[str, ...]) -> int:
    """Cancel queued messages of these types (pause: no backlog of runs or grants is released on resume)."""
    count = 0
    for msg in stored(hub, sub_id):
        if msg.type in types and not msg.cancelled:
            msg.cancelled = True
            _put(hub, msg)
            count += 1
    return count


def prune(hub: "Hub", sub_id: str) -> int:
    """Delete expired and cancelled messages."""
    now = hub.subsidiary_config.clock()
    ids = [_doc_id(sub_id, m.id) for m in stored(hub, sub_id) if m.cancelled or m.expires_at <= now]
    return hub.store.delete_many(INBOX, ids) if ids else 0


def forget(hub: "Hub", sub_id: str) -> int:
    """Every message of an archived subsidiary (the counter too)."""
    ids = [_doc_id(sub_id, m.id) for m in stored(hub, sub_id)]
    removed = hub.store.delete_many(INBOX, ids) if ids else 0
    hub.store.delete(INBOX, f"{sub_id}#seq")
    return removed
