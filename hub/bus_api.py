"""The Agent bus page's API: conversations on the agent bus (hub/conversations.py) and agents' errors
(hub/agent_errors.py). Viewers read routing, status and error texts; operators and administrators read bodies too;
a person's private chat text only that person (see hub/conversations.py)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from fastapi import APIRouter, HTTPException, Query

from .auth.policy import role_allows
from .auth.service import CurrentPrincipal, Principal
from .conversations import Viewer

if TYPE_CHECKING:
    from .core import Hub


def add_routes(router: APIRouter, hub: "Hub") -> None:
    def viewer(p: Principal) -> Viewer:
        return Viewer(key=hub.llm.memory.person_of(p.bus_id), bodies=role_allows(p.role, "operator"))

    @router.get("/bus/threads")
    async def bus_threads(p: CurrentPrincipal, agent: str | None = Query(None, max_length=200),
                          subject: str | None = Query(None, max_length=200), errors_only: bool = False,
                          person_only: bool = False, status: Literal["open", "answered", "failed"] | None = None,
                          q: str = Query("", max_length=200), limit: int = Query(50, ge=1, le=200),
                          before: int | None = Query(None, ge=1)) -> dict[str, Any]:
        """Conversations, latest activity first: {threads, total, next_before}. `person_only`: the ones the caller
        started ("my chats"); `before`: the previous page's next_before."""
        await hub.conversations.ready()
        return hub.conversations.threads(viewer(p), agent=agent or None, subject=subject or None,
                                         errors_only=errors_only, person_only=person_only, status=status, q=q,
                                         limit=limit, before=before)

    @router.get("/bus/threads/{thread_id}")
    async def bus_thread(thread_id: str, p: CurrentPrincipal, limit: int = Query(500, ge=1, le=2000)) -> dict[str, Any]:
        """One conversation: {thread, messages (oldest first), errors, truncated}."""
        await hub.conversations.ready()
        found = hub.conversations.thread(thread_id, viewer(p), limit)
        if found is None:
            raise HTTPException(404, "Conversation not found")
        return found

    def known(agent_id: str) -> None:
        """An agent, or one removed whose errors are still kept."""
        if hub.agents.get(agent_id) is None and not hub.agent_errors.stored(agent_id):
            raise HTTPException(404, "Agent not found")

    def name(agent_id: str) -> str:
        agent = hub.agents.get(agent_id)
        return agent.name if agent is not None else agent_id

    @router.get("/agents/{agent_id}/errors")
    async def agent_errors(agent_id: str, p: CurrentPrincipal, unacknowledged: bool = False,
                           limit: int = Query(100, ge=1, le=500), before: float | None = None) -> dict[str, Any]:
        """An agent's recorded failures, newest first: {agent, errors, total, unacknowledged, since_start,
        next_before}."""
        known(agent_id)
        docs = hub.agent_errors.for_agent(agent_id)
        if unacknowledged:
            docs = [d for d in docs if d.get("acknowledged_at") is None]
        total = len(docs)
        if before is not None:
            docs = [d for d in docs if float(d.get("ts") or 0) < before]
        page = docs[:limit]
        who = viewer(p)
        live = hub.agents.get(agent_id)
        return {"agent": agent_id, "errors": [hub.agent_errors.view(d, who) for d in page], "total": total,
                "unacknowledged": hub.agent_errors.unacknowledged(agent_id), "since_start": live.errors if live else 0,
                "next_before": page[-1]["ts"] if len(docs) > limit else None}

    @router.post("/agents/{agent_id}/errors/ack")
    async def acknowledge_all_errors(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        known(agent_id)
        done = hub.agent_errors.acknowledge_all(agent_id, p.actor)
        if done:
            hub.activity(p.actor, "info", f"Acknowledged {done} error(s) of {name(agent_id)}", agent_id=agent_id)
        return {"acknowledged": done, "unacknowledged": hub.agent_errors.unacknowledged(agent_id)}

    @router.post("/agents/{agent_id}/errors/{error_id}/ack")
    async def acknowledge_error(agent_id: str, error_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        doc = hub.agent_errors.acknowledge(agent_id, error_id, p.actor)
        if doc is None:
            raise HTTPException(404, "Error not found")
        return hub.agent_errors.view(doc, viewer(p))

    @router.delete("/agents/{agent_id}/errors")
    async def clear_errors(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        known(agent_id)
        cleared = hub.agent_errors.clear(agent_id)
        hub.activity(p.actor, "info", f"Cleared {cleared} error(s) of {name(agent_id)}", agent_id=agent_id)
        return {"cleared": cleared}
