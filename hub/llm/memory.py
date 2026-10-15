"""Chat memory per (agent, person): a person's conversation with an agent is never part of anyone else's (review D7).

Each agent's memory setting (AgentConfig.memory) decides how long a conversation lasts:
- "off": every message starts afresh - the agent remembers nothing;
- "session" (the default): kept in this process, lost on restart;
- "persisted": also stored, Fernet-encrypted (hub.secrets), in the collection "agent_conversations" (doc id
  "<agent id>|<person>"), without the providers' raw output blobs; purged after `retention_days` without a message.
A conversation longer than `max_turns` messages from the person starts afresh, with a notice in the reply.

A conversation is bound to the provider and model it ran on; when that changes, the next message starts a fresh
conversation (a model never sees another provider's raw output). The person is the account's user id, or for an API
token the account that owns it - so renaming an account keeps its conversations and deleting it
(AuthService.delete_user -> forget_user) drops them, also the stored ones.

A turn of a person's private chat thread (hub/bus.py) tells the thread the person's earlier turns the model reads
(Private.learn), so the agents' messages that quote them are logged without them, like quotes of this turn."""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, AsyncIterator

from ..bus import TRACE
from ..models import MemoryConfig
from .types import Msg

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "agent_conversations"
MAX_MESSAGES = 600  # a backstop besides max_turns: tool rounds add messages too
LIMIT_NOTICE = "(Started a new conversation: the earlier one reached this agent's memory limit.)"


@dataclass
class Conversation:
    agent_id: str
    person: str
    provider: str | None = None
    model: str | None = None
    messages: list[Msg] = field(default_factory=list)
    updated_at: float = field(default_factory=time.time)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    loaded: bool = False  # the stored conversation was read (persisted mode)

    def bind(self, provider: str, model: str) -> bool:
        """Use this conversation with `provider`/`model`: True (and an empty history) when that starts a new one."""
        fresh = (self.provider, self.model) != (provider, model)
        if fresh:
            self.messages, self.provider, self.model = [], provider, model
        return fresh

    @property
    def turns(self) -> int:
        """Messages from the person (tool results are not turns)."""
        return sum(1 for m in self.messages if m.role == "user")


@dataclass
class Turn:
    """What one chat turn works on: the conversation and the notice to add to the reply (or None)."""

    conversation: Conversation
    notice: str | None = None

    @property
    def messages(self) -> list[Msg]:
        return self.conversation.messages


def doc_id(agent_id: str, person: str) -> str:
    return f"{agent_id}|{person}"


class Memory:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._conversations: dict[tuple[str, str], Conversation] = {}

    def person_of(self, sender: str | None) -> str:
        """The key a bus sender's conversations are kept under: "user:<user id>" for an account (also for its API
        tokens), else the sender itself (an agent, or a token without an owner)."""
        text = str(sender or "")
        auth = self.hub.auth
        if text.startswith("user:"):
            user = auth.find_user(text[5:])
            return f"user:{user.id}" if user is not None else text
        if text.startswith("token:"):
            token = next((t for t in auth.tokens() if t.name == text[6:]), None)
            if token is not None:
                return f"user:{token.owner_id}" if token.owner_id else f"token:{token.id}"
        return text or "anonymous"

    def conversation(self, agent_id: str, person: str) -> Conversation:
        key = (agent_id, person)
        found = self._conversations.get(key)
        if found is None:
            found = self._conversations[key] = Conversation(agent_id, person)
        return found

    @contextlib.asynccontextmanager
    async def turn(self, agent_id: str, person: str, provider: str, model: str,
                   config: MemoryConfig | None = None) -> AsyncIterator[Turn]:
        """One chat turn of `person` with the agent, one at a time per conversation: the history to append to, as
        the agent's memory setting has it. A failed turn leaves nothing behind; a finished one is kept (session),
        stored (persisted) or dropped (off)."""
        config = config or MemoryConfig()
        conv = self.conversation(agent_id, person)
        async with conv.lock:
            if config.mode == "persisted" and not conv.loaded:
                self._load(conv)
            if config.mode == "off":
                conv.messages = []
            conv.bind(provider, model)
            notice = None
            if config.mode != "off" and (conv.turns >= config.max_turns or len(conv.messages) > MAX_MESSAGES):
                conv.messages, notice = [], LIMIT_NOTICE
            trace = TRACE.get()
            if trace is not None and trace.private is not None and trace.private.owner == person:
                # the model reads the person's earlier turns too: a quote of them is as private as one of this turn
                trace.private.learn(m.text for m in conv.messages if m.role == "user")
            before = len(conv.messages)
            try:
                yield Turn(conv, notice)
            except BaseException:
                del conv.messages[before:]  # never keep half a turn
                raise
            conv.updated_at = time.time()
            if config.mode == "off":
                conv.messages = []
            elif config.mode == "persisted":
                self._save(conv)

    # -- stored conversations (persisted mode) ------------------------------------------------

    def _load(self, conv: Conversation) -> None:
        conv.loaded = True
        doc = self.hub.store.get(COLLECTION, doc_id(conv.agent_id, conv.person))
        if not doc or conv.messages:
            return
        try:
            data = json.loads(self.hub.secrets.decrypt(str(doc.get("messages_enc") or "")))
            conv.messages = [Msg.model_validate(m) for m in data]
        except Exception:  # unreadable (another key, damaged): start afresh rather than fail every message
            conv.messages = []
            return
        conv.provider, conv.model = doc.get("provider"), doc.get("model")
        conv.updated_at = float(doc.get("updated_at") or time.time())

    def _save(self, conv: Conversation) -> None:
        plain = [m.model_dump(mode="json", exclude={"raw"}) for m in conv.messages]  # raw blobs stay in memory only
        user_id = conv.person[5:] if conv.person.startswith("user:") else conv.person
        self.hub.store.put(COLLECTION, {
            "id": doc_id(conv.agent_id, conv.person), "agent_id": conv.agent_id, "user_id": user_id,
            "person": conv.person, "provider": conv.provider, "model": conv.model, "updated_at": conv.updated_at,
            "turns": conv.turns, "messages_enc": self.hub.secrets.encrypt(json.dumps(plain))})

    def stored(self, agent_id: str | None = None) -> list[dict[str, Any]]:
        """The stored conversations without their text (counts for administrators)."""
        docs = self.hub.store.list_where(COLLECTION, "agent_id", agent_id) if agent_id else self.hub.store.list(COLLECTION)
        return [{k: d.get(k) for k in ("agent_id", "user_id", "provider", "model", "updated_at", "turns")} for d in docs]

    def view(self, agent_id: str, person: str, config: MemoryConfig | None = None) -> dict[str, Any]:
        """A person's own conversation with the agent: {turns, messages: [{role, text}], provider, model,
        updated_at} - the text of their messages and the agent's answers, not tool results."""
        conv = self._conversations.get((agent_id, person))
        if conv is None and (config or MemoryConfig()).mode == "persisted":
            conv = self.conversation(agent_id, person)
            self._load(conv)
        if conv is None:
            return {"turns": 0, "messages": [], "provider": None, "model": None, "updated_at": None}
        shown = [{"role": m.role, "text": m.text} for m in conv.messages
                 if m.role == "user" or (m.role == "assistant" and m.text and not m.tool_calls)]
        return {"turns": conv.turns, "messages": shown, "provider": conv.provider, "model": conv.model,
                "updated_at": conv.updated_at if conv.messages else None}

    # -- forgetting ----------------------------------------------------------------------------

    def reset(self, agent_id: str, person: str) -> None:
        """A new conversation: the old one is gone, also from the store."""
        conv = self._conversations.get((agent_id, person))
        if conv is not None:
            conv.messages, conv.provider, conv.model = [], None, None
        self.hub.store.delete(COLLECTION, doc_id(agent_id, person))

    def forget_user(self, user_id: str) -> int:
        """Drop every conversation of a deleted account (in memory and stored)."""
        person = f"user:{user_id}"
        gone = [k for k in self._conversations if k[1] == person]
        for key in gone:
            del self._conversations[key]
        stored = [d["id"] for d in self.hub.store.list_where(COLLECTION, "person", person)]
        if stored:
            self.hub.store.delete_many(COLLECTION, stored)
        return len(gone) + len(stored)

    def forget_agent(self, agent_id: str, *, keep_stored: bool = False) -> int:
        """Drop an agent's conversations (removed, or its memory switched off / to session)."""
        gone = [k for k in self._conversations if k[0] == agent_id]
        for key in gone:
            del self._conversations[key]
        stored = [] if keep_stored else [d["id"] for d in self.hub.store.list_where(COLLECTION, "agent_id", agent_id)]
        if stored:
            self.hub.store.delete_many(COLLECTION, stored)
        return len(gone) + len(stored)

    def drop_stored(self, agent_id: str) -> int:
        """Delete an agent's stored conversations (its memory is no longer "persisted"); session copies stay."""
        stored = [d["id"] for d in self.hub.store.list_where(COLLECTION, "agent_id", agent_id)]
        for key, conv in self._conversations.items():
            if key[0] == agent_id:
                conv.loaded = False
        return self.hub.store.delete_many(COLLECTION, stored) if stored else 0

    def prune(self, now: float | None = None) -> int:
        """Purge stored conversations older than their agent's retention (the prune loop calls this hourly)."""
        from .resolve import own_settings

        now = now or time.time()
        old = []
        retention: dict[str, int] = {}
        for doc in self.hub.store.list(COLLECTION):
            agent_id = str(doc.get("agent_id") or "")
            if agent_id not in retention:
                retention[agent_id] = own_settings(self.hub.llm, agent_id)[1].memory.retention_days
            if now - float(doc.get("updated_at") or 0) > retention[agent_id] * 86400:
                old.append(doc["id"])
        for doc_key in old:
            agent_id, _, person = doc_key.partition("|")
            conv = self._conversations.pop((agent_id, person), None)
            if conv is not None:
                conv.messages = []
        return self.hub.store.delete_many(COLLECTION, old) if old else 0

    def count(self, agent_id: str | None = None) -> int:
        return sum(1 for k, c in self._conversations.items() if c.messages and (agent_id is None or k[0] == agent_id))
