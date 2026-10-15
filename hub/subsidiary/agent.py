"""Sidecar staff in Atrium (7.2): ``SubsidiaryAgent`` is the hub-side proxy of a staff member who thinks and works in
its subsidiary's sidecar. ``AgentRegistry.add_custom`` picks it for an ``AgentDef`` with ``placement="sidecar"``.

- ``on_run`` (the scheduler, "Run now", a task): skipped unless the subsidiary is active, its sidecar online and the
  member may act; it creates the run, posts an inbox ``run`` and waits for ``POST /replies`` (15 minutes at most); the
  result is recorded like any agent's run - as text written by the subsidiary (untrusted). A pause answers the wait
  at once (skipped).
- ``on_chat`` relays the person's message as an inbox ``chat`` and waits two minutes; after that the reply lands in
  the run log. It answers ``offline`` (HTTP 503) while the sidecar is offline.
- Nothing runs locally: the member never calls a model in Atrium (the gateway serves the sidecar instead).
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING, Any

from ..agents import notify, teams
from ..agents.custom import CustomAgent
from ..bus import Message
from ..models import AgentDef
from . import actions, audit, gateway, governance, runtime, wire
from .governance import GovernanceError
from .models import CHAT_WAIT, RUN_WAIT, ReplyRequest, RunMessage, RunRecord, Subsidiary, new_id

if TYPE_CHECKING:
    from ..core import Hub

UNTRUSTED = "Written by the subsidiary team (untrusted)"


def start(hub: "Hub", sub: Subsidiary, defn: AgentDef, trigger: str, text: str, person: str | None) -> RunRecord:
    """A relayed run (scheduled, manual, a task or a chat): the run id Atrium issues and the inbox message carrying
    it, with the outcomes of the member's earlier requests as notes. Refused while the sidecar is offline: nothing is
    queued for it, and a scheduled run is skipped rather than failed (it would wait RUN_WAIT and count as busy)."""
    gateway.staff_member(hub, sub, defn.id)
    assert sub.charter is not None
    if "offline" in sub.flags or sub.sidecar is None:
        raise GovernanceError(503, f"The {governance.tool_name(hub, sub.tool_id)} team's sidecar is offline.",
                              "offline")
    if gateway.busy(hub, sub.id) >= sub.charter.budgets.max_concurrent_runs:
        raise GovernanceError(429, "The team is running as many runs as it may at once.", "busy")
    correlation = new_id("c_")
    run = gateway.create_run(hub, sub, defn.id, trigger, person=person, correlation_id=correlation)
    notes = actions.notes_for(hub, sub, defn.id, since=defn.last_run or 0)
    message = RunMessage(run_id=run.id, agent_id=defn.id, trigger=trigger,  # type: ignore[arg-type]
                         correlation_id=correlation, text=text[:8000], notes=notes)
    runtime.post(hub, sub.id, "chat" if trigger == "chat" else "run", message.model_dump(mode="json"))
    return run


def record_result(hub: "Hub", defn_id: str, result: dict[str, Any], *, ran: bool = True) -> None:
    """The member's last result; `ran` (not a chat): it also counts as its last run (its schedule's clock)."""
    current = teams.get_def(hub, defn_id)
    if current is None:
        return
    current.running = None
    current.last_result = result
    if ran:
        current.last_run = result["at"]
    teams.save_def(hub, current)


def reply(hub: "Hub", sub: Subsidiary, req: ReplyRequest) -> RunRecord:
    """POST /replies: the answer of a relayed run or chat. A waiting proxy gets it; otherwise (a task, a timed-out
    wait) it is recorded as the member's last result."""
    run = next((RunRecord.model_validate(d) for d in hub.store.list_where(gateway.RUNS, "correlation_id",
                                                                           req.correlation_id)
                if d.get("subsidiary_id") == sub.id), None)
    if run is None:
        raise GovernanceError(404, "No relayed run of this subsidiary has that correlation id.", "unknown_run")
    if run.reply_ok is not None:
        raise GovernanceError(409, "This run was answered already.", "answered")
    text = wire.clean(req.reply, 8000)
    run.reply_ok, run.reply_length = req.ok, len(text)
    gateway.save_run(hub, run)
    audit.record(hub, sub.id, "run.reply", agent_id=run.agent_id, run_id=run.id, outcome="ok" if req.ok else "failed",
                 detail={"length": len(text)})
    answer = {"ok": req.ok, "reply": text}
    future = hub.subsidiaries.replies.pop(req.correlation_id, None)
    if future is not None and not future.done():
        future.set_result(answer)
    else:  # agents keep wall-clock bookkeeping (their schedules run on it)
        record_result(hub, run.agent_id, {"ok": req.ok, "reply": text[:4000], "mode": "sidecar", "trigger": run.trigger,
                                          "at": time.time(), "duration": round(governance.clock(hub) - run.started_at, 2),
                                          "run_id": run.id, "untrusted": UNTRUSTED}, ran=run.trigger != "chat")
    return run


class SubsidiaryAgent(CustomAgent):
    role = "subsidiary-staff"
    max_concurrency = 2

    def _subsidiary(self) -> Subsidiary | None:
        return governance.of_tool(self.hub, self.defn.team)

    def record(self) -> dict[str, Any]:
        sub = self._subsidiary()
        return {**super().record(), "placement": "sidecar", "uses_llm": True,
                "subsidiary": {"id": sub.id, "status": sub.status, "flags": list(sub.flags)} if sub else None,
                "works_inside": self.defn.team}

    async def _wait(self, sub: Subsidiary, defn: AgentDef, trigger: str, text: str, person: str | None,
                    timeout: float) -> tuple[RunRecord, dict[str, Any] | None]:
        future: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
        run = start(self.hub, sub, defn, trigger, text, person)
        if run.correlation_id:
            self.hub.subsidiaries.replies[run.correlation_id] = future
        try:
            return run, await asyncio.wait_for(asyncio.shield(future), timeout)
        except asyncio.TimeoutError:
            return run, None
        finally:
            if run.correlation_id and self.hub.subsidiaries.replies.get(run.correlation_id) is future:
                self.hub.subsidiaries.replies.pop(run.correlation_id, None)

    async def on_run(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """The standing task (or the given one), run in the sidecar; the reply is recorded as the result."""
        task = str(body.get("task") or self.defn.task).strip()
        trigger = str(body.get("trigger") or "manual")
        trigger = trigger if trigger in ("schedule", "manual", "task") else "manual"
        person = msg.sender if msg.sender.startswith(("user:", "token:")) else None
        started = time.time()
        sub = self._subsidiary()
        if not task or sub is None:
            self._finish(None)
            raise ValueError(f"{self.name} has no standing task - give it one, or send a task" if not task
                             else f"{self.name} has no subsidiary")
        skipped = False
        try:
            run, answer = await self._wait(sub, self.defn, trigger, task, person, RUN_WAIT)
            if answer is None:
                ok, reply = False, "No reply from the team's sidecar within 15 minutes (it may still answer)."
            else:  # skipped: Atrium paused or stopped the subsidiary while the run was under way
                ok, reply, skipped = bool(answer["ok"]), str(answer["reply"]), bool(answer.get("skipped"))
            run_id: str | None = run.id
        except GovernanceError as exc:  # paused, held, busy: skipped, not failed
            ok, reply, skipped, run_id = False, f"Skipped: {exc}", True, None
        now = time.time()
        result = {"ok": ok, "reply": reply[:4000], "mode": "sidecar", "trigger": trigger, "at": now,
                  "duration": round(now - started, 2), "run_id": run_id, "untrusted": UNTRUSTED,
                  **({"skipped": True} if skipped else {})}
        self._finish(result)
        failures, paused = notify.run_finished(self.hub, self.id, ok, skipped)
        self.log("info" if ok or skipped else "warn", f"{self.name} ran its task in the sidecar ({trigger}): "
                 + ("skipped" if skipped else "done" if ok else "failed")
                 + (f" - its schedule is paused after {failures} failed runs" if paused else ""), agent_id=self.id)
        return {**result, "agent": self.record()}

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        text = str(body.get("text", "")).strip()
        if not text:
            raise ValueError("Say something")
        sub = self._subsidiary()
        if sub is None:
            raise ValueError(f"{self.name} has no subsidiary")
        if "offline" in sub.flags or sub.sidecar is None:
            return {"error": f"The {governance.tool_name(self.hub, sub.tool_id)} team's sidecar is offline.",
                    "code": "offline"}
        person = msg.sender if msg.sender.startswith(("user:", "token:")) else None
        try:
            run, answer = await self._wait(sub, self.defn, "chat", text, person, CHAT_WAIT)
        except GovernanceError as exc:
            raise ValueError(str(exc)) from exc
        if answer is None:
            return {"reply": "Queued: the team is working on it; the reply will appear in the run log.",
                    "mode": "sidecar", "queued": True, "run_id": run.id, "agent_id": self.id}
        if answer.get("skipped"):
            return {"error": str(answer["reply"]), "code": "cancelled", "run_id": run.id}
        return {"reply": str(answer["reply"]), "mode": "sidecar", "untrusted": UNTRUSTED, "run_id": run.id,
                "agent_id": self.id}

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return {"ok": True}  # the sidecar keeps no conversation between runs

    async def turn(self, *args: Any, **kwargs: Any) -> tuple[str, str, Any]:
        raise ValueError(f"{self.name} works in its subsidiary's sidecar, not in Atrium")
