"""Conversations on the agent bus: the threads of the "messages" log as the Agent bus page shows them.

The index (Conversations) reads only the routing of the log's rows (SQLite extracts the fields, bodies stay unparsed)
and catches up with new rows on every read; pruning the log rebuilds it. A thread's key is its root message's id
(``bus.thread_key``: rows from before threads existed group a reply with its request). Status: "open" while a request
of it waits for its reply or an agent works on one of its messages, else "failed" when its root request got an error
or no answer (a thread started by a notification: when anything in it failed), else "answered".

Who reads what (``Viewer``):
- everyone: routing, subjects, status, error texts (secrets masked);
- operators and administrators: bodies too, secrets masked (hub.llm.mask) - over LOG_BODY_LIMIT as the log keeps them;
- a person's private chat thread (hub/bus.py): its chat messages show their size only, and strings quoting the
  person's text were replaced when they were logged; the person reads the originals, kept encrypted for them alone
  (PrivateCopies) while their account exists.
The plain message log (GET /api/messages, GET /api/agents/{id}/messages, the "message" event) follows the same rules
(``log_row``).
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .bus import PRIVATE_SUBJECTS, Message, failed, is_person, loggable, redacted, thread_key

if TYPE_CHECKING:
    from .core import Hub

COPIES = "bus_private"
TITLE_CHARS = 80
SEARCH_ROWS = 2000  # log rows whose text matched a search that are checked against what the viewer may read
CHUNK = 2000  # log rows read into the index at a time (ready() lets the agents run in between)
DETAIL_LIMIT = 500
FIELDS = ("id", "thread", "reply_to", "kind", "sender", "recipient", "subject", "origin", "private", "body.error",
          "body.failed")


@dataclass
class Viewer:
    """Who reads: their memory key ("user:<user id>", hub.llm.memory.person_of) and whether their role reads bodies."""

    key: str
    bodies: bool


def initiator(origin: str) -> str:
    """Who started a conversation: a "person" (an account or its API token), the hub's "schedule" (scheduled and
    background work) or an "agent"."""
    return "person" if is_person(origin) else "schedule" if origin == "hub" else "agent"


def first_words(text: str, limit: int = TITLE_CHARS) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit].rsplit(" ", 1)[0].rstrip(",.;:") + "…"


class PrivateCopies:
    """What only the person of a private chat thread reads - their chat text, the agent's answer, the strings of other
    messages that quoted them, error texts, activity entries and commands that quoted them - Fernet-encrypted
    (hub.secrets) in the collection "bus_private" under their user id ("m:<message id>", "e:<error id>",
    "a:<activity seq>", "c:<command seq>"), and what an approval asked for in their thread needs to resume there
    ("p:<approval id>", hub/approvals.py; until it is decided). Deleted with their account (forget_user), a message's
    pruned with the log; never stored in plain text (an encryption failure keeps nothing)."""

    def __init__(self, hub: "Hub"):
        self.hub = hub

    def keep(self, key: str, owner: str, thread: str | None, value: dict[str, Any], whole: bool = False) -> None:
        """Keep `value` for `owner` (an oversized one summarised as the log keeps it, unless `whole`)."""
        try:
            enc = self.hub.secrets.encrypt(json.dumps(value if whole else loggable({"body": value})["body"],
                                                      default=str))
        except Exception:
            return
        user_id = owner[5:] if owner.startswith("user:") else owner
        self.hub.store.put(COPIES, {"id": key, "owner": owner, "user_id": user_id, "thread": thread,
                                    "ts": time.time(), "enc": enc})

    def read(self, key: str, viewer: str) -> Any:
        """The original for its owner; None for anyone else (or when it is gone)."""
        doc = self.hub.store.get(COPIES, key)
        if not doc or doc.get("owner") != viewer:
            return None
        try:
            return json.loads(self.hub.secrets.decrypt(str(doc.get("enc") or "")))
        except Exception:
            return None

    def load(self, key: str) -> tuple[str, str | None, Any] | None:
        """(owner, thread, value) of a copy, for the hub itself (resuming work in a private thread); None when it is
        gone or cannot be read."""
        doc = self.hub.store.get(COPIES, key)
        if not doc:
            return None
        try:
            return str(doc.get("owner")), doc.get("thread"), json.loads(self.hub.secrets.decrypt(str(doc.get("enc") or "")))
        except Exception:
            return None

    def drop(self, keys: list[str]) -> int:
        return self.hub.store.delete_many(COPIES, keys) if keys else 0

    def forget_user(self, user_id: str) -> int:
        return self.drop([d["id"] for d in self.hub.store.list_where(COPIES, "user_id", user_id)])

    def prune(self, before: float) -> int:
        """Drop the copies of messages older than `before` (the oldest message the log still holds)."""
        rows = self.hub.store.project(COPIES, ("id", "ts"))
        return self.drop([str(r["id"]) for r in rows if str(r["id"]).startswith("m:") and float(r["ts"] or 0) < before])


@dataclass
class Thread:
    key: str
    origin: str
    subject: str
    first_ts: float
    last_ts: float = 0.0
    last_seq: int = 0
    root: str | None = None
    root_kind: str | None = None
    root_reply: str | None = None  # "ok" | "error": how the root request was answered
    count: int = 0
    error_replies: int = 0
    private: bool = False
    parties: dict[str, None] = field(default_factory=dict)  # ordered sets
    subjects: dict[str, None] = field(default_factory=dict)
    seqs: list[int] = field(default_factory=list)


class Conversations:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self.copies = PrivateCopies(hub)
        self._threads: dict[str, Thread] = {}
        self._seq_key: dict[int, str] = {}  # log row -> its conversation
        self._last = 0
        self._valid = False

    # -- the index -----------------------------------------------------------------------------

    def invalidate(self) -> None:
        self._valid = False

    def _catch_up(self) -> bool:
        """Read the next rows of the log into the index: True when there may be more."""
        if not self._valid:
            self._threads, self._seq_key, self._last, self._valid = {}, {}, 0, True
        rows = self.hub.store.project_stream("messages", FIELDS, after=self._last, limit=CHUNK)
        for row in rows:
            self._add(row)
        return len(rows) == CHUNK

    def sync(self) -> None:
        while self._catch_up():
            pass

    async def ready(self) -> None:
        """Catch up with the log a chunk at a time: reading a long log (after a start or a prune) never holds up the
        agents for long."""
        while self._catch_up():
            await asyncio.sleep(0)

    def _add(self, row: dict[str, Any]) -> None:
        self._last = row["seq"]
        key = thread_key(row)
        sender, kind = str(row.get("sender") or ""), row.get("kind")
        t = self._threads.get(key)
        if t is None:
            t = self._threads[key] = Thread(key, origin=str(row.get("origin") or sender),
                                            subject=str(row.get("subject")), first_ts=float(row["ts"]))
        if row.get("id") == key:
            t.root, t.root_kind, t.subject = key, kind, str(row.get("subject"))
            t.origin = str(row.get("origin") or sender)
        bad = kind == "reply" and (row.get("body.error") is not None or bool(row.get("body.failed")))
        if kind == "reply" and row.get("reply_to") == key:
            t.root_reply = "error" if bad else "ok"
        t.count += 1
        t.error_replies += bad
        t.last_ts, t.last_seq = float(row["ts"]), row["seq"]
        t.private = t.private or bool(row.get("private")) or row.get("subject") in PRIVATE_SUBJECTS
        for party in (sender, row.get("recipient")):
            if party:
                t.parties[str(party)] = None
        t.subjects[str(row.get("subject"))] = None
        t.seqs.append(row["seq"])
        self._seq_key[row["seq"]] = key

    # -- summaries -----------------------------------------------------------------------------

    def errors(self, t: Thread) -> int:
        return max(t.error_replies, len(self.hub.agent_errors.in_thread(t.key)))

    def status(self, t: Thread, errors: int) -> str:
        if t.key in self.hub.bus.busy:
            return "open"
        if t.root_kind == "request":
            return "answered" if t.root_reply == "ok" else "failed"
        return "failed" if errors else "answered"

    def _mine(self, t: Thread, viewer: Viewer, people: dict[str, str]) -> bool:
        if not is_person(t.origin):
            return False
        if t.origin not in people:
            people[t.origin] = self.hub.llm.memory.person_of(t.origin)
        return people[t.origin] == viewer.key

    def _own_text(self, t: Thread, viewer: Viewer) -> str | None:
        """The person's own words that started their private chat thread (for its title and search)."""
        if not (t.private and t.root and viewer.bodies):
            return None
        own = self.copies.read(f"m:{t.root}", viewer.key)
        text = own.get("text") if isinstance(own, dict) else None
        return text if isinstance(text, str) and text.strip() else None

    def summary(self, t: Thread, viewer: Viewer, people: dict[str, str] | None = None) -> dict[str, Any]:
        errors = self.errors(t)
        own = self._own_text(t, viewer)
        return {"id": t.key, "root": t.root, "subject": t.subject, "title": first_words(own) if own else t.subject,
                "initiator": {"id": t.origin, "kind": initiator(t.origin)}, "participants": list(t.parties),
                "subjects": list(t.subjects)[:20], "count": t.count, "started": t.first_ts, "last": t.last_ts,
                "last_seq": t.last_seq, "status": self.status(t, errors), "errors": errors, "private": t.private,
                "mine": self._mine(t, viewer, people if people is not None else {})}

    # -- listing ---------------------------------------------------------------------------------

    def threads(self, viewer: Viewer, *, agent: str | None = None, subject: str | None = None,
                errors_only: bool = False, person_only: bool = False, status: str | None = None, q: str = "",
                limit: int = 50, before: int | None = None) -> dict[str, Any]:
        """Conversations, the latest activity first: {threads, total (all that match), next_before (pass it as
        `before` for the next page; None on the last)}. `q` searches subjects, participants, the viewer's own chat
        words and - for roles that read bodies - bodies as the viewer would read them."""
        self.sync()
        query = q.strip().lower()
        people: dict[str, str] = {}
        found: list[Thread] = []
        for t in sorted(self._threads.values(), key=lambda x: -x.last_seq):
            if agent and agent not in t.parties or subject and subject not in t.subjects:
                continue
            if person_only and not self._mine(t, viewer, people):
                continue
            if errors_only or status:
                errors = self.errors(t)
                if errors_only and not errors or status and self.status(t, errors) != status:
                    continue
            found.append(t)
        if query:
            hits = {t.key for t in found if self._matches(t, query, viewer, people)}
            if viewer.bodies:  # bodies only of the conversations that matched nothing else yet
                hits |= self._search_bodies(q.strip(), viewer, {t.key for t in found} - hits)
            found = [t for t in found if t.key in hits]
        page = [t for t in found if before is None or t.last_seq < before][:limit + 1]
        return {"threads": [self.summary(t, viewer, people) for t in page[:limit]], "total": len(found),
                "next_before": page[limit - 1].last_seq if len(page) > limit else None}

    def _matches(self, t: Thread, query: str, viewer: Viewer, people: dict[str, str]) -> bool:
        if query == t.key.lower() or query in t.origin.lower():
            return True
        if any(query in s.lower() for s in t.subjects) or any(query in p.lower() for p in t.parties):
            return True
        own = self._own_text(t, viewer) if t.private and self._mine(t, viewer, people) else None
        return bool(own and query in own.lower())

    def _search_bodies(self, q: str, viewer: Viewer, keys: set[str]) -> set[str]:
        """Of the conversations `keys`, those with a message whose body - as `viewer` reads it, secrets masked -
        contains `q`."""
        needle = json.dumps(q)[1:-1]  # as the log stores text (JSON, non-ASCII escaped)
        found: set[str] = set()
        seqs = [s for s in self.hub.store.search_stream("messages", needle) if self._seq_key.get(s) in keys]
        for row in self.hub.store.entries("messages", seqs[:SEARCH_ROWS]):
            body, _, _ = self._body(row, viewer)
            text = json.dumps(body, default=str).lower()
            if needle.lower() in text:
                found.add(thread_key(row))
        return found

    # -- one conversation ------------------------------------------------------------------------

    def _mask(self, value: Any) -> Any:
        return self.hub.llm.mask.value(value)

    def log_row(self, row: dict[str, Any], bodies: bool) -> dict[str, Any]:
        """A row of the message log as GET /api/messages, GET /api/agents/{id}/messages and the live "message" event
        show it, with its conversation (`thread`): a chat's text never; for roles that read bodies (`bodies`) the body
        with the hub's secrets masked; for the others only what everyone reads - a chat's size, and whether a reply
        failed with its error text."""
        out = {**redacted(row), "thread": thread_key(row)}
        body = out.get("body") or {}
        if row.get("subject") in PRIVATE_SUBJECTS:
            return out  # its text was left out already: size, mode and model only
        if bodies:
            try:
                return {**out, "body": self._mask(body)}
            except Exception:  # the secrets cannot be read: nothing to show safely
                return {**out, "body": {"redacted": "unavailable"}}
        hidden: dict[str, Any] = {"redacted": "role"}
        if row.get("kind") == "reply" and failed(body):
            hidden["failed"] = True
            if "error" in body:
                hidden["error"] = self.hub.agent_errors.clean(body["error"])
        return {**out, "body": hidden}

    def event(self, event: dict[str, Any], bodies: bool) -> dict[str, Any]:
        """A live event (GET /api/events) as its reader may see it: a "message" event's row as log_row shows it to
        roles that read no bodies (the others get the row as logged - secrets masked when it was written)."""
        if event.get("type") == "message" and not bodies and isinstance(event.get("data"), dict):
            return {**event, "data": self.log_row(event["data"], False)}
        return event

    def _body(self, row: dict[str, Any], viewer: Viewer) -> tuple[Any, str | None, bool]:
        """(body as `viewer` reads it, secrets masked; why it is hidden: "role" | "private" | "unavailable" | None;
        whether it is the viewer's own private original)."""
        if not viewer.bodies:
            return None, "role", False
        own = self.copies.read(f"m:{row['id']}", viewer.key) if row.get("private") and row.get("id") else None
        body = own if own is not None else redacted(row).get("body") or {}  # a chat row logged before review D7 too
        try:
            masked = self._mask(body)
        except Exception:  # the secrets cannot be read: nothing to show safely
            return None, "unavailable", False
        if own is not None:
            return masked, None, True
        return masked, "private" if row.get("subject") in PRIVATE_SUBJECTS else None, False

    def message(self, row: dict[str, Any], viewer: Viewer, by_id: dict[str, dict[str, Any]],
                replies: dict[str, dict[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {k: row.get(k) for k in ("id", "seq", "ts", "sender", "recipient", "subject", "kind",
                                                       "reply_to", "parent", "origin")}
        out["thread"] = thread_key(row)
        out["private"] = bool(row.get("private")) or row.get("subject") in PRIVATE_SUBJECTS
        body, hidden, own = self._body(row, viewer)
        out.update(body=body, body_hidden=hidden, mine=own)
        logged = redacted(row).get("body") or {}
        out["failed"] = row.get("kind") == "reply" and failed(logged)
        error = None
        if out["failed"]:  # error text: everyone reads it, except a private chat's (its person does)
            source = body if own and isinstance(body, dict) else logged
            if "error" in source and (own or row.get("subject") not in PRIVATE_SUBJECTS):
                error = self.hub.agent_errors.clean(source["error"])
        out["error"] = error
        if row.get("kind") == "request":
            reply = replies.get(str(row.get("id")))
            out["reply_id"] = reply.get("id") if reply else None
            out["duration"] = round(float(reply["ts"]) - float(row["ts"]), 3) if reply else None
            out["pending"] = self.hub.bus.pending(str(row.get("id")))
        elif row.get("kind") == "reply":
            request = by_id.get(str(row.get("reply_to")))
            out["duration"] = round(float(row["ts"]) - float(request["ts"]), 3) if request else None
        return out

    def thread(self, key: str, viewer: Viewer, limit: int = DETAIL_LIMIT) -> dict[str, Any] | None:
        """One conversation: {thread (its summary), messages (oldest first, the last `limit`), errors (the recorded
        failures, oldest first), truncated}; None when nothing is known of it."""
        self.sync()
        t = self._threads.get(key)
        errors = self.hub.agent_errors.for_thread(key)
        if t is None and not errors:
            return None
        rows = self.hub.store.entries("messages", t.seqs[-limit:]) if t else []
        by_id = {str(r.get("id")): r for r in rows}
        replies = {str(r.get("reply_to")): r for r in rows if r.get("kind") == "reply" and r.get("reply_to")}
        if t is not None:
            summary = self.summary(t, viewer)
        else:  # a conversation whose messages are not logged (a routine ping) but whose handling failed
            first = errors[0]
            parties = (str(x) for e in errors for x in (e.get("sender"), e.get("agent")) if x)
            summary = {"id": key, "root": None, "subject": first.get("subject"), "title": first.get("subject"),
                       "initiator": {"id": first.get("sender"), "kind": initiator(str(first.get("sender") or ""))},
                       "participants": list(dict.fromkeys(parties)),
                       "subjects": list(dict.fromkeys(str(e.get("subject")) for e in errors)), "count": 0,
                       "started": first.get("ts"), "last": errors[-1].get("ts"), "last_seq": None,
                       "status": "open" if key in self.hub.bus.busy else "failed", "errors": len(errors),
                       "private": any(e.get("private") for e in errors), "mine": False}
        return {"thread": summary, "messages": [self.message(r, viewer, by_id, replies) for r in rows],
                "errors": [self.hub.agent_errors.view(e, viewer) for e in errors],
                "truncated": t is not None and len(t.seqs) > limit}

    # -- privacy and housekeeping ----------------------------------------------------------------

    def own_entries(self, entries: list[dict[str, Any]], viewer: str, prefix: str) -> list[dict[str, Any]]:
        """Entries of a log everyone reads (Hub.shared_append: "a" the activity log, "c" the command history) as
        `viewer` (a memory key) reads them: the entries written in their own private chat thread with the original
        fields ("mine": true), everyone else's as they were stored."""
        out = []
        for entry in entries:
            own = self.copies.read(f"{prefix}:{entry.get('seq')}", viewer) if entry.get("private") else None
            out.append({**entry, **own, "mine": True} if isinstance(own, dict) else entry)
        return out

    def keep_message(self, msg: Message, body: dict[str, Any]) -> None:
        """Bus.keep_private: the original body of a message of a private chat thread, for its person."""
        if msg.private is not None:
            self.copies.keep(f"m:{msg.id}", msg.private.owner, msg.thread, body)

    def forget_user(self, user_id: str) -> int:
        return self.copies.forget_user(user_id)

    def prune(self) -> int:
        """After the log was pruned: rebuild the index; drop the private copies of messages it no longer holds."""
        self.invalidate()
        oldest = self.hub.store.oldest("messages")
        return self.copies.prune(oldest[1] if oldest else time.time())
