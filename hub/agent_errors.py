"""Agent errors: every failure of an agent, kept so people can see what went wrong, for whom and in which conversation.

A failure is recorded (collection ``agent_errors``) when an agent's handler raises (BaseAgent._handle), when an
agent answers a request with an error (Bus.send), when a request gets no answer in time or reaches no agent
(Bus.request / Bus.send), and when an AI model call fails (hub.llm). One failure is one record: the error reply an
exception or a failed model call causes is not recorded again, nor the exception a failed model call raises (it is
marked, ``mark``); different failures of one message - a timeout, then the handler's own exception; a model call that
failed, then the rules it fell back to - are each recorded. Each record: id, agent, subject, sender (who asked),
message (the message that failed), thread, error (the text: secrets masked, credential-looking pairs masked, at most
TEXT_LIMIT characters), error_class, code, kind (exception | reply | timeout | unreachable | llm), ts,
acknowledged_by / acknowledged_at.

In a person's private chat thread (hub/bus.py) the text is stored as others may read it - quotes of the person's chat
removed, and for the chat itself (PRIVATE_SUBJECTS) no text at all (``error_hidden: "private"``); what was removed is
kept for the person alone (hub/conversations.py).

At most KEEP_PER_AGENT records per agent are kept, none older than MAX_AGE_DAYS. Operators acknowledge them, an
administrator clears an agent's. The agent's record shows its errors since start and the unacknowledged ones.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from .bus import PRIVATE_SUBJECTS, Private
from .connectors.base import redact
from .store import new_id

if TYPE_CHECKING:
    from .conversations import Viewer
    from .core import Hub

COLLECTION = "agent_errors"
KEEP_PER_AGENT = 200
MAX_AGE_DAYS = 30
TEXT_LIMIT = 2000
RECENT = 2000  # (agent, message) pairs remembered with the kinds of failure recorded for them
CAUSES = {"exception", "llm"}  # a failure whose error reply is the same failure
MARK = "_atrium_agent_error"  # set on an exception that is recorded already
FIELDS = ("id", "agent", "subject", "sender", "message", "thread", "error", "error_hidden", "error_class", "code",
          "kind", "ts", "acknowledged_by", "acknowledged_at", "private")


def mark(exc: BaseException) -> None:
    """Note that `exc` was recorded (hub.llm records a failed model call before it raises)."""
    try:
        setattr(exc, MARK, True)
    except Exception:  # an exception that takes no attributes: recorded again at worst
        pass


def recorded(exc: BaseException | None) -> bool:
    """`exc`, or an exception it was raised from (``raise ... from``), was recorded already. An exception raised while
    another was handled (e.g. the rules a chat fell back to after its model failed) is a failure of its own."""
    seen = 0
    while exc is not None and seen < 20:
        if getattr(exc, MARK, False):
            return True
        exc, seen = exc.__cause__, seen + 1
    return False


class ErrorLog:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._stats: dict[str, list[int]] | None = None  # agent -> [stored, unacknowledged]
        self._threads: dict[str, list[str | None]] | None = None  # thread -> the failed messages' ids
        self._recent: dict[tuple[str, str], set[str]] = {}  # (agent, message) -> the kinds recorded for it

    # -- recording ---------------------------------------------------------------------

    def clean(self, text: Any) -> str:
        """Error text as it may be stored and shown: every hub secret and credential-looking pair masked, capped."""
        out = str(text or "")
        try:
            out = self.hub.llm.mask.text(out)
        except Exception:  # the mask cannot load the secrets (e.g. no key): the pairs are still masked below
            pass
        out = redact(out)
        return out if len(out) <= TEXT_LIMIT else out[:TEXT_LIMIT - 1] + "…"

    def record(self, agent: str, *, subject: str, sender: str | None, message: str | None, thread: str | None,
               text: Any, error_class: str, code: str | None = None, kind: str = "exception",
               private: Private | None = None) -> dict[str, Any] | None:
        """Record one failure (None: the same failure was recorded already - an exception and its error reply - or
        it could not be recorded: recording never adds a failure of its own to the agent's)."""
        try:
            return self._record(agent, subject=subject, sender=sender, message=message, thread=thread, text=text,
                                error_class=error_class, code=code, kind=kind, private=private)
        except Exception:
            return None

    def _record(self, agent: str, *, subject: str, sender: str | None, message: str | None, thread: str | None,
                text: Any, error_class: str, code: str | None, kind: str,
                private: Private | None) -> dict[str, Any] | None:
        if message:
            kinds = self._recent.setdefault((agent, message), set())
            if kind in kinds or kind == "reply" and kinds & CAUSES:  # the same failure, or the error reply it caused
                return None
            kinds.add(kind)
            while len(self._recent) > RECENT:
                self._recent.pop(next(iter(self._recent)))
        stats, threads = self._load()  # before the record is stored: a reload would count it, and then again below
        full = self.clean(text) or error_class
        hidden = subject in PRIVATE_SUBJECTS  # a chat's failure may say anything about it: only the person reads it
        shown = None if hidden else private.quotes.scrub(full) if private is not None else full
        doc = {"id": new_id("ae_"), "agent": agent, "subject": subject, "sender": sender, "message": message,
               "thread": thread, "error": shown, "error_hidden": "private" if hidden else None,
               "error_class": error_class, "code": code, "kind": kind, "ts": time.time(), "acknowledged_by": None,
               "acknowledged_at": None, "private": private is not None}
        self.hub.store.put(COLLECTION, doc)
        if private is not None and shown != full:
            self.hub.conversations.copies.keep(f"e:{doc['id']}", private.owner, thread, {"error": full})
        entry = stats.setdefault(agent, [0, 0])
        entry[0] += 1
        entry[1] += 1
        if thread:
            threads.setdefault(thread, []).append(message)
        if entry[0] > KEEP_PER_AGENT + 20:  # trimmed in batches, not on every record
            self._trim(agent)
        live = self.hub.agents.get(agent)
        if live is not None:
            live.errors += 1
            live.last_error_at = doc["ts"]
        self._changed(agent)
        self.hub.bus.publish("agent_error", self.public(doc))
        return doc

    # -- reading -------------------------------------------------------------------------

    def _load(self) -> tuple[dict[str, list[int]], dict[str, list[str | None]]]:
        if self._stats is None or self._threads is None:
            stats: dict[str, list[int]] = {}
            threads: dict[str, list[str | None]] = {}
            for row in self.hub.store.project(COLLECTION, ("agent", "acknowledged_at", "thread", "message")):
                entry = stats.setdefault(str(row["agent"]), [0, 0])
                entry[0] += 1
                entry[1] += row["acknowledged_at"] is None
                if row["thread"]:
                    threads.setdefault(str(row["thread"]), []).append(row["message"])
            self._stats, self._threads = stats, threads
        return self._stats, self._threads

    def invalidate(self) -> None:
        self._stats = self._threads = None

    def unacknowledged(self, agent: str) -> int:
        return self._load()[0].get(agent, [0, 0])[1]

    def stored(self, agent: str) -> int:
        return self._load()[0].get(agent, [0, 0])[0]

    def in_thread(self, thread: str) -> list[str | None]:
        """The ids of the messages that failed in a conversation (one per recorded failure)."""
        return self._load()[1].get(thread, [])

    def get(self, agent: str, error_id: str) -> dict[str, Any] | None:
        doc = self.hub.store.get(COLLECTION, error_id)
        return doc if doc and doc.get("agent") == agent else None

    def for_agent(self, agent: str) -> list[dict[str, Any]]:
        """An agent's records, newest first."""
        return sorted(self.hub.store.list_where(COLLECTION, "agent", agent), key=lambda d: -float(d.get("ts") or 0))

    def for_thread(self, thread: str) -> list[dict[str, Any]]:
        if not self.in_thread(thread):
            return []
        return sorted(self.hub.store.list_where(COLLECTION, "thread", thread), key=lambda d: float(d.get("ts") or 0))

    def public(self, doc: dict[str, Any]) -> dict[str, Any]:
        """A record as anyone who reads errors sees it (the event stream, other people)."""
        return {k: doc.get(k) for k in FIELDS}

    def view(self, doc: dict[str, Any], viewer: "Viewer | None") -> dict[str, Any]:
        """A record for `viewer`: the person whose private chat it failed in reads its full text."""
        out = {**self.public(doc), "mine": False}
        if doc.get("private") and viewer is not None and viewer.bodies:
            own = self.hub.conversations.copies.read(f"e:{doc['id']}", viewer.key)
            if isinstance(own, dict):
                out.update(error=own.get("error"), error_hidden=None, mine=True)
        if isinstance(out.get("error"), str):
            out["error"] = self.clean(out["error"])  # secrets added since it was recorded
        return out

    # -- acknowledging and clearing --------------------------------------------------------

    def acknowledge(self, agent: str, error_id: str, actor: str) -> dict[str, Any] | None:
        doc = self.get(agent, error_id)
        if doc is None:
            return None
        if doc.get("acknowledged_at") is None:
            entry = self._load()[0].get(agent)  # before the change is stored: a reload would already leave it out
            doc.update(acknowledged_by=actor, acknowledged_at=time.time())
            self.hub.store.put(COLLECTION, doc)
            if entry:
                entry[1] = max(0, entry[1] - 1)
            self._changed(agent)
            self.hub.bus.publish("agent_error", self.public(doc))
        return doc

    def acknowledge_all(self, agent: str, actor: str) -> int:
        now, done = time.time(), 0
        for doc in self.for_agent(agent):
            if doc.get("acknowledged_at") is None:
                doc.update(acknowledged_by=actor, acknowledged_at=now)
                self.hub.store.put(COLLECTION, doc)
                done += 1
        if done:
            self.invalidate()
            self._changed(agent)
            self.hub.bus.publish("agent_errors_acknowledged", {"agent": agent, "count": done, "by": actor})
        return done

    def clear(self, agent: str) -> int:
        """Delete every record of an agent (and reset its errors since start)."""
        ids = [d["id"] for d in self.hub.store.list_where(COLLECTION, "agent", agent)]
        self._delete(ids)
        live = self.hub.agents.get(agent)
        if live is not None:
            live.errors, live.last_error_at = 0, None
        self._changed(agent)
        self.hub.bus.publish("agent_errors_cleared", {"agent": agent, "count": len(ids)})
        return len(ids)

    def prune(self, now: float | None = None) -> int:
        """Delete records older than MAX_AGE_DAYS and each agent's beyond KEEP_PER_AGENT (hourly, with the logs)."""
        cutoff = (now or time.time()) - MAX_AGE_DAYS * 86400
        rows = self.hub.store.project(COLLECTION, ("id", "agent", "ts"))
        old = [str(r["id"]) for r in rows if float(r["ts"] or 0) < cutoff]
        by_agent: dict[str, list[tuple[float, str]]] = {}
        for r in rows:
            if float(r["ts"] or 0) >= cutoff:
                by_agent.setdefault(str(r["agent"]), []).append((float(r["ts"] or 0), str(r["id"])))
        for items in by_agent.values():
            old += [i for _, i in sorted(items, reverse=True)[KEEP_PER_AGENT:]]
        self._delete(old)
        return len(old)

    def _trim(self, agent: str) -> None:
        docs = self.hub.store.list_where(COLLECTION, "agent", agent)
        items = sorted(((float(d.get("ts") or 0), d["id"]) for d in docs), reverse=True)
        self._delete([i for _, i in items[KEEP_PER_AGENT:]])

    def _delete(self, ids: list[str]) -> None:
        if not ids:
            return
        self.hub.store.delete_many(COLLECTION, ids)
        self.hub.conversations.copies.drop([f"e:{i}" for i in ids])
        self.invalidate()

    def _changed(self, agent: str) -> None:
        live = self.hub.agents.get(agent)
        if live is not None:
            live._publish()  # the Agents page shows the new counts
