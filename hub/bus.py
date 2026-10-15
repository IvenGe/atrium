"""The agent bus: how agents talk to each other, and how the UI watches them do it.

Every message is persisted to the ``messages`` stream and fanned out to UI
subscribers (Server-Sent Events), so the conversation between agents is always
visible and auditable. Bodies larger than ``LOG_BODY_LIMIT`` (e.g. records a data
flow pulls from a tool) reach their recipient in full but are logged as a summary;
a person's chat with an agent (``PRIVATE_SUBJECTS``) is logged without its text.

Conversations (threads): every message carries ``thread`` (the id of the message that started the conversation, its
root) and ``parent`` (the message whose handling sent it). ``TRACE`` holds the conversation of the code that runs now:
an agent handling a message (BaseAgent._handle), an API request on behalf of a person (hub/app.py) - so whatever it
asks, tells or answers belongs to the same conversation. A message sent outside one (the hub's scheduler, start-up)
starts a new conversation; a reply always keeps its request's. ``origin`` is who started it (the root's sender).

A person's chat thread is private (review D7): the chat text never reaches the log, and every other message of the
thread is logged with the strings that quote the person's text replaced by ``PRIVATE_TEXT`` (``Quotes`` has the rule).
"The person's text" is everything of theirs the agent can see: this turn's chat text and - with the agent's memory -
their earlier turns (``Private.learn``, called by hub/llm/memory.py when a turn starts). What was removed is kept for
the person alone, encrypted (hub/conversations.py). Every logged body has the hub's secrets masked (``Bus.mask``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import re
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Literal

from pydantic import BaseModel, Field, PrivateAttr

from .store import Store, new_id

LOG_BODY_LIMIT = 32_000
# The scheduler's routine pings (every 30-60 seconds, all day long) reach their agent but are not logged: they would
# be most of the message log (review F38).
ROUTINE = {("hub", "changes.tick"), ("hub", "health.sweep")}
# A person's chat with an agent is theirs: the log and the event stream every signed-in account reads keep its
# routing, never its text (review D7). Bus.reply copies the subject, so requests and replies both carry it.
PRIVATE_SUBJECTS = {"chat", "chat.reset"}
PRIVATE_TEXT = "[private: quotes a person's chat]"
QUOTE_RUN = 10  # characters in a row shared with a person's chat text make a string a quote of it
QUOTE_SCAN = 100_000  # characters of the person's texts (the newest first) looked at for shared runs
QUOTE_TEXTS = 1_000_000  # characters of the person's texts (the newest first) a string is looked for in
QUOTE_WORDS = 300_000  # characters of distinctive words and numbers (the newest first) indexed from those texts
QUOTE_SHORT = 3  # a string this short (or shorter) is a quote only as a name, or a whole text, of the person's
EDGE = ".,;:!?'\"()[]{}<>`*"
SENTENCE_END = (".", "!", "?", ":", ";")
NUMBER_MARKS = re.compile(r"(?<=\d)[,._'\u00a0\u202f](?=\d)")
DIGIT_GROUP = re.compile(r"\d(?:[\d,._'\u00a0\u202f]*\d)?")  # a number, with thousands separators or decimals
NOT_DIGITS_AT_ENDS = re.compile(r"^\D+|\D+$")  # "$85,000", "85,000\u20ac", "INV-85000": the number in the word
POSSESSIVE = re.compile(r"['\u2019]s$")
DIGIT_OR_SYMBOL = re.compile(r"[\d_]|[^\w']")  # a digit, or a symbol other than an apostrophe
# Capitalised words that open a sentence without being a name: not taken for one there (inside a sentence a
# capitalised word is always taken for a name).
OPENERS = frozenset("""
a an the this that these those it its i we you he she they me my our your his her their them us one someone
please pls kindly can could would should will shall may might must do does did is are was were be been am have has
had what when where why how who whom whose which whether if then than so and but or nor yet also too just now still
again hi hello hey dear thanks thank ok okay yes no not all any some every each both either neither there here for
from with without about after before during since until while because although though as at by in into of on onto to
up down out over under via per let lets new old next last first today tomorrow tonight yesterday
run check show list find get set make add remove delete create update install uninstall upgrade deploy open close
start stop restart reboot shutdown kill scan patch fix review report summarize summarise explain describe compare
look see read write send tell ask give keep note record log notify inform email message call contact remind revoke
disable enable grant block allow deny approve reject sync import export backup restore ping test verify monitor
watch investigate assess evaluate track assign schedule plan prepare draft rotate reset change move copy rename
onboard offboard greet welcome help use try go wait cancel retry continue confirm clear connect disconnect
""".split())


def redacted(record: dict[str, Any]) -> dict[str, Any]:
    """`record` (a dumped Message) as the log and the event stream keep it: a private subject's body becomes its
    size and the non-text facts of a reply (mode, model, provider)."""
    if record.get("subject") not in PRIVATE_SUBJECTS:
        return record
    body = record.get("body") or {}
    if body.get("redacted"):
        return record
    text = body.get("text", body.get("reply", ""))
    out: dict[str, Any] = {"redacted": "chat", "chars": len(text) if isinstance(text, str) else 0}
    if isinstance(body.get("mode"), str):
        out["mode"] = body["mode"]
    meta = body.get("meta")
    if isinstance(meta, dict):
        out["meta"] = {k: meta[k] for k in ("model", "provider") if k in meta}
    if "error" in body:
        out["failed"] = True
    return {**record, "body": out}


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


def is_person(sender: str | None) -> bool:
    """A bus sender that is a person: a signed-in account ("user:<name>") or an API token ("token:<name>")."""
    return str(sender or "").startswith(("user:", "token:"))


def thread_key(record: dict[str, Any]) -> str:
    """The conversation a logged message belongs to. Rows from before conversations existed: a reply goes with its
    request, anything else is a conversation of its own."""
    return str(record.get("thread") or (record.get("reply_to") if record.get("kind") == "reply" else None)
               or record.get("id") or f"seq:{record.get('seq')}")


def _norm(text: str) -> str:
    return " ".join(text.casefold().split())


def _distinctive(word: str) -> bool:
    """A word of a chat text that is evidence of a quote on its own: an identifier, a number, an address, a path, a
    password - letters and digits or symbols mixed, or capitals after the first letter."""
    if len(word) < 4:
        return False
    return DIGIT_OR_SYMBOL.search(word) is not None or word[1:].lower() != word[1:]


def _name(word: str, opens: bool) -> str | None:
    """`word` (or the word of a possessive: "Dana's") when it is a name: capitalised, letters only, QUOTE_SHORT
    letters or more - also when it opens a sentence (`opens`; "Dana is leaving"), unless it is a usual sentence
    opener there ("Please", "The", "Revoke")."""
    if not word[:1].isupper():
        return None
    base = POSSESSIVE.sub("", word)
    if len(base) < QUOTE_SHORT or not base.isalpha():
        return None
    return None if opens and base.casefold() in OPENERS else base


def _numbers(text: str) -> Iterator[str]:
    """The numbers of 4+ digits in `text`, without thousands separators or leading zeros ("85,000", "85.000" and
    "85000" are all "85000"), and the 4+ digit runs inside a longer number ("85000.50": also "85000")."""
    for match in DIGIT_GROUP.finditer(text):
        group = match.group()
        digits = NUMBER_MARKS.sub("", group)
        candidates = {digits} if digits.isdigit() else set()
        if digits != group or not digits.isdigit():
            candidates.update(re.findall(r"\d+", group))
        for found in candidates:
            if len(found) >= 4:
                yield found.lstrip("0") or "0"


def _windows(text: str, size: int) -> Iterator[str]:
    return (text[i:i + size] for i in range(len(text) - size + 1))


class Quotes:
    """Recognises strings that quote any of `texts` (a person's chat messages), erring on the side of a quote - case
    and spacing ignored - when the string (4+ characters) is inside a text, a whole text is inside the string, it
    shares QUOTE_RUN characters in a row with a text, or it contains a distinctive word of a text (an identifier, a
    number, an address, a password, a name: a capitalised word, also one that opens a sentence unless it is a usual
    opener such as "Please" - ``OPENERS``) or a 4+ digit number of a text in any thousands format. A string of up to
    QUOTE_SHORT characters is a quote only when it is such a word or a whole text: a plain short word the person used
    ("crm" in "patch crm") is also the agents' own vocabulary, e.g. a tool's id. scrub() also replaces numbers that
    are a 4+ digit number of a text, and dictionary keys that contain a distinctive word, a run, a number or a whole
    text. Paraphrases are not recognised.

    Every check is linear in the length of the string looked at (set lookups of its windows), and the texts are read up
    to QUOTE_TEXTS characters, the newest first - runs of the newest QUOTE_SCAN, distinctive words, names and numbers
    of all of them (QUOTE_WORDS characters at most): a huge chat text cannot stall the hub."""

    def __init__(self, texts: tuple[str, ...] | list[str]):
        given = [t for t in texts if isinstance(t, str) and t.strip()]
        self.texts: list[str] = []  # normalised, the newest first, at most QUOTE_TEXTS characters in all
        budget = QUOTE_TEXTS
        for t in reversed(given):
            if budget <= 0:
                break
            norm = _norm(t)[:budget]
            self.texts.append(norm)
            budget -= len(norm)
        self.joined = "\0".join(self.texts)
        self.runs: set[str] = set()
        self.words: set[str] = set()  # distinctive words and names shorter than QUOTE_RUN (longer ones are in runs)
        self.numbers: set[str] = set()  # numbers of 4+ digits, without thousands separators
        # Runs of the newest QUOTE_SCAN characters; distinctive words, names and numbers of every text read above
        # (all a model may be handed from the person's memory), up to QUOTE_WORDS characters of them.
        scan, words, budget = QUOTE_SCAN, QUOTE_WORDS, QUOTE_TEXTS
        for t in reversed(given):
            if budget <= 0 or scan <= 0 and words <= 0:
                break
            raw = t[:budget]
            budget -= len(raw)
            if scan > 0:
                self.runs.update(_windows(_norm(raw[:scan]), QUOTE_RUN))
                scan -= len(raw[:scan])
            if words > 0:
                words -= self._index(raw, words)
        self.lengths = sorted({len(w) for w in self.words})
        self.whole = [t for t in self.texts if len(t) > QUOTE_SHORT]
        self.short = {t.strip(EDGE) for t in self.texts if len(t) <= QUOTE_SHORT}  # a text of one short word

    def _index(self, raw: str, budget: int) -> int:
        """Index the distinctive words, names and numbers of `raw` (one text), at most `budget` characters of them;
        returns how many characters it indexed."""
        used, previous = 0, ""
        for w in raw.split():
            if used >= budget:
                break
            word = w.strip(EDGE)
            name = _name(word, opens=not previous or previous.endswith(SENTENCE_END))
            found = _norm(name) if name else _norm(word) if _distinctive(word) else ""
            if found:
                if len(found) < QUOTE_RUN:
                    self.words.add(found)
                else:
                    self.runs.update(_windows(found, QUOTE_RUN))
                used += len(found)
            digits = NUMBER_MARKS.sub("", NOT_DIGITS_AT_ENDS.sub("", word)) if found else ""  # 4+ digits: distinctive
            if len(digits) >= 4 and digits.isdigit():
                self.numbers.add(digits.lstrip("0") or "0")
                used += len(digits)
            previous = w
        return used

    def _shares(self, v: str) -> bool:
        """`v` (normalised) holds a whole text, a run, a distinctive word or a 4+ digit number of the texts (a number
        in any thousands format: "85000", "85,000", "85.000")."""
        if any(t in v for t in self.whole) or self.short and any(w.strip(EDGE) in self.short for w in v.split()):
            return True
        if not self.runs.isdisjoint(_windows(v, QUOTE_RUN)):
            return True
        if any(not self.words.isdisjoint(_windows(v, n)) for n in self.lengths):
            return True
        return bool(self.numbers) and any(n in self.numbers for n in _numbers(v))

    def __call__(self, value: str) -> bool:
        if not self.texts:
            return False
        v = _norm(value)
        if len(v) <= QUOTE_SHORT:
            w = v.strip(EDGE)
            return bool(w) and (w in self.words or w in self.short)
        return v in self.joined or self._shares(v)

    def number(self, value: int | float) -> bool:
        if isinstance(value, float):
            if not value.is_integer():
                return False
            value = int(value)
        return (str(abs(value)).lstrip("0") or "0") in self.numbers

    def key(self, value: str) -> bool:
        """A dictionary key that quotes the texts (the keys of a body are its structure: a key is only a quote when it
        carries a distinctive word, a run or a whole text, not when it is merely a word of the text)."""
        return bool(self.texts) and self._shares(_norm(value))

    def scrub(self, value: Any) -> Any:
        """`value` (a message body, an error text) with every string, number and dictionary key that quotes the texts
        replaced by PRIVATE_TEXT (keys numbered, so none is lost)."""
        if isinstance(value, str):
            return PRIVATE_TEXT if self(value) else value
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return PRIVATE_TEXT if self.texts and self.number(value) else value
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            for k, v in value.items():
                if isinstance(k, str) and self.key(k):
                    k = f"{PRIVATE_TEXT} {len(out) + 1}"
                out[k] = self.scrub(v)
            return out
        if isinstance(value, (list, tuple)):
            return [self.scrub(v) for v in value]
        return value


@dataclass
class Private:
    """A person's chat thread: whose it is (their memory key, "user:<user id>") and what they wrote that its agents can
    see (the oldest first) - in memory only, to recognise quotes of it; never logged."""

    owner: str
    texts: tuple[str, ...] = ()
    _quotes: Quotes | None = field(default=None, repr=False, compare=False)

    @property
    def quotes(self) -> Quotes:
        if self._quotes is None:
            self._quotes = Quotes(self.texts)
        return self._quotes

    def learn(self, texts: Iterable[Any]) -> None:
        """Also recognise quotes of `texts` (the person's earlier turns an agent remembers, the oldest first): every
        message of the thread that refers to this Private sees them from now on."""
        known = set(self.texts)
        new = tuple(dict.fromkeys(t for t in texts if isinstance(t, str) and t.strip() and t not in known))
        if new:
            self.texts, self._quotes = (*new, *self.texts), None

    def material(self) -> list[str]:
        """The texts as Quotes reads them (the newest QUOTE_TEXTS characters), the oldest first: what recognising quotes
        of them needs when work of the thread resumes later (hub/approvals.py)."""
        out, budget = [], QUOTE_TEXTS
        for t in reversed(self.texts):
            if budget <= 0:
                break
            out.append(t[:budget])
            budget -= len(out[-1])
        return out[::-1]


class Message(BaseModel):
    id: str = Field(default_factory=lambda: new_id("m_"))
    sender: str
    recipient: str
    subject: str
    body: dict[str, Any] = {}
    kind: Literal["request", "reply", "event"] = "event"
    reply_to: str | None = None
    thread: str | None = None  # the conversation: its first message's id (set by Bus.stamp)
    parent: str | None = None  # the message whose handling sent this one (None: a root or a person's request)
    origin: str | None = None  # who started the conversation
    ts: float = Field(default_factory=time.time)
    _private: Private | None = PrivateAttr(default=None)  # in a person's chat thread: never serialised

    @property
    def private(self) -> Private | None:
        return self._private


@dataclass
class Trace:
    """The conversation the running code belongs to: messages it sends join `thread` (None: the next one starts a
    conversation, and the trace keeps it for the ones after) with `parent` as the cause."""

    thread: str | None = None
    parent: str | None = None
    origin: str | None = None
    private: Private | None = None
    message: Message | None = None  # the message being handled


TRACE: ContextVar[Trace | None] = ContextVar("atrium_bus_trace", default=None)


@contextlib.contextmanager
def conversation(trace: Trace | None) -> Iterator[Trace | None]:
    """Run the block in `trace`'s conversation; None: outside any, so every message sent starts its own (scheduled
    work, agent loops)."""
    token = TRACE.set(trace)
    try:
        yield trace
    finally:
        TRACE.reset(token)


def handling(msg: Message) -> Trace:
    """The trace of an agent's handler for `msg`: what it sends joins msg's conversation, caused by msg."""
    return Trace(thread=msg.thread or msg.id, parent=msg.id, origin=msg.origin or msg.sender, private=msg.private,
                 message=msg)


def failed(body: Any) -> bool:
    """A reply body that reports a failure (an error reply; a chat reply whose text the log dropped says so)."""
    return isinstance(body, dict) and ("error" in body or body.get("failed") is True)


class AgentError(RuntimeError):
    """Raised when an agent cannot be reached or answers a request with an error. `code` / `retry_after`: what the
    agent's error reply carried (a reached AI budget or rate limit: "budget_exceeded" / "rate_limited")."""

    def __init__(self, message: str, *, code: str | None = None, retry_after: int | None = None):
        super().__init__(message)
        self.code, self.retry_after = code, retry_after


class Bus:
    def __init__(self, store: Store):
        self.store = store
        self._inboxes: dict[str, asyncio.Queue[Message]] = {}
        self._pending: dict[str, asyncio.Future[Message]] = {}
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.generation: dict[str, int] = {}  # per event type, +1 on every publish (dashboard widget cache)
        self._listeners: list[Callable[[str, Any], None]] = []
        self.busy: dict[str, int] = {}  # conversation -> requests waiting for their reply and handlers at work
        # Set by the Hub (hub/core.py): the memory key of a person sender, where the private originals of a person's
        # chat thread go (hub/conversations.py), and where failures are recorded (hub/agent_errors.py).
        self.person_of: Callable[[str], str] = lambda sender: sender
        self.keep_private: Callable[[Message, dict[str, Any]], None] | None = None
        self.on_failure: Callable[..., Any] | None = None
        self.mask: Callable[[Any], Any] | None = None  # a body with the hub's secrets masked (hub.llm.mask.value)

    # -- agents ----------------------------------------------------------------------

    def attach(self, agent_id: str, inbox: asyncio.Queue[Message]) -> None:
        self._inboxes[agent_id] = inbox

    def detach(self, agent_id: str) -> None:
        self._inboxes.pop(agent_id, None)

    def stamp(self, msg: Message) -> Message:
        """Give a message its conversation (from TRACE, see the module docstring) and, for a person's chat request,
        make the conversation private to them."""
        trace = TRACE.get()
        if msg.thread is None:
            if trace is not None and trace.thread:
                msg.thread, msg.parent, msg.origin = trace.thread, trace.parent, trace.origin
                msg._private = msg._private or trace.private
            else:
                msg.thread, msg.origin = msg.id, msg.sender
                if trace is not None:  # the first message of a person's request: the others join it
                    trace.thread, trace.origin = msg.id, msg.sender
        if msg.kind == "request" and msg.subject in PRIVATE_SUBJECTS and is_person(msg.sender):
            owner = self.person_of(msg.sender)
            known = msg._private.texts if msg._private is not None and msg._private.owner == owner else ()
            text = msg.body.get("text")
            msg._private = Private(owner, (*known, text) if isinstance(text, str) and text.strip() else known)
            if trace is not None and trace.thread == msg.thread:
                trace.private = msg._private
        return msg

    def _masked(self, body: Any) -> Any:
        if self.mask is None:
            return body
        try:
            return self.mask(body)
        except Exception:  # the secrets cannot be read: the readers mask again (hub/conversations.py)
            return body

    def _log(self, msg: Message) -> dict[str, Any]:
        """Persist `msg` as the log keeps it - a chat's text left out, an oversized body summarised, the hub's secrets
        masked, quotes of a person's private chat replaced - and return the stored row (what the "message" event
        carries)."""
        record = msg.model_dump(mode="json")
        shown = loggable(redacted(record))
        shown = {**shown, "body": self._masked(shown.get("body") or {})}
        private = msg.private
        if private is not None:
            shown = {**shown, "body": private.quotes.scrub(shown["body"]), "private": True}
            original = self._masked(loggable(record)["body"])
            if shown["body"] != original and original and self.keep_private is not None:
                self.keep_private(msg, original)  # the person still reads what they wrote, and the answer
        return self.store.append("messages", shown)

    async def send(self, msg: Message) -> None:
        self.stamp(msg)
        if msg.kind != "event" or (msg.sender, msg.subject) not in ROUTINE:
            self.publish("message", self._log(msg))
        if msg.kind == "reply":
            if "error" in msg.body:
                self._failure(msg.sender, msg, str(msg.body["error"]), "ErrorReply", msg.body.get("code"), "reply")
            fut = self._pending.get(msg.reply_to or "")
            if fut and not fut.done():
                fut.set_result(msg)
            return
        inbox = self._inboxes.get(msg.recipient)
        if inbox is None:
            fut = self._pending.get(msg.id)
            if fut and not fut.done():
                error = AgentError(f"No agent named '{msg.recipient}'")
                self._failure(msg.recipient, msg, str(error), "AgentError", "unreachable", "unreachable")
                fut.set_exception(error)
            return
        inbox.put_nowait(msg)

    def _failure(self, agent: str, msg: Message, text: str, error_class: str, code: Any, kind: str) -> None:
        """Record a failure (an error reply, a request nobody answered or could receive) with on_failure; a reply
        stands for its request."""
        if self.on_failure is None:
            return
        reply = msg.kind == "reply"
        try:
            self.on_failure(agent, subject=msg.subject, sender=msg.recipient if reply else msg.sender,
                            message=msg.reply_to if reply else msg.id, thread=msg.thread, text=text,
                            error_class=error_class, code=code if isinstance(code, str) else None, kind=kind,
                            private=msg.private)
        except Exception:  # recording a failure never breaks the conversation
            pass

    def enter(self, thread: str | None) -> None:
        if thread:
            self.busy[thread] = self.busy.get(thread, 0) + 1

    def leave(self, thread: str | None) -> None:
        if thread and thread in self.busy:
            self.busy[thread] -= 1
            if self.busy[thread] <= 0:
                del self.busy[thread]

    async def request(
        self, sender: str, recipient: str, subject: str, body: dict[str, Any] | None = None, timeout: float = 300.0
    ) -> dict[str, Any]:
        """Send a request and wait for the recipient's reply."""
        msg = self.stamp(Message(sender=sender, recipient=recipient, subject=subject, body=body or {}, kind="request"))
        fut: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._pending[msg.id] = fut
        self.enter(msg.thread)
        try:
            await self.send(msg)
            reply = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError as exc:
            text = f"{recipient} did not answer '{subject}' within {timeout:g}s"
            self._failure(recipient, msg, text, "Timeout", "timeout", "timeout")
            raise AgentError(text, code="timeout") from exc
        finally:
            self._pending.pop(msg.id, None)
            self.leave(msg.thread)
        if "error" in reply.body:
            raise AgentError(str(reply.body["error"]), code=reply.body.get("code"),
                             retry_after=reply.body.get("retry_after"))
        return reply.body

    def pending(self, message_id: str) -> bool:
        """A request still waiting for its reply."""
        return message_id in self._pending

    async def tell(self, sender: str, recipient: str, subject: str, body: dict[str, Any] | None = None) -> None:
        """Fire-and-forget notification."""
        await self.send(Message(sender=sender, recipient=recipient, subject=subject, body=body or {}))

    async def reply(self, request: Message, sender: str, body: dict[str, Any]) -> None:
        msg = Message(sender=sender, recipient=request.sender, subject=request.subject, body=body, kind="reply",
                      reply_to=request.id, thread=request.thread or request.id, parent=request.id,
                      origin=request.origin or request.sender)
        msg._private = request.private
        await self.send(msg)

    # -- UI fan-out ------------------------------------------------------------------

    def listen(self, fn: Callable[[str, Any], None]) -> None:
        """Call `fn(type, data)` for every published event, in process (e.g. to refresh a cache); it must be quick."""
        self._listeners.append(fn)

    def publish(self, type_: str, data: Any) -> None:
        self.generation[type_] = self.generation.get(type_, 0) + 1
        event = {"type": type_, "data": data}
        for fn in list(self._listeners):
            try:
                fn(type_, data)
            except Exception:  # a listener never stops the event
                pass
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # a slow browser tab must never stall the agents

    def generations(self, types: tuple[str, ...] | list[str]) -> tuple[int, ...]:
        """How often each event type was published: a cached result that depends on them is current while these stay
        the same."""
        return tuple(self.generation.get(t, 0) for t in types)

    def subscribe(self, maxsize: int = 500) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._subscribers.discard(queue)
