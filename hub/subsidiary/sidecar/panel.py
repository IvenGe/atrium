"""The "Ask the team" panel (4.10, 6.5): questions tool users ask inside the tool, answered by the front desk.

While the charter enables the panel and the ticket lists ``atrium.panel.pull``, the sidecar long-polls the bridge for
open questions. Each question becomes a panel run: Atrium issues its id (``POST /runs``, after checking status,
budgets and the per-user limits), the question is answered ``working`` at once, then the front desk runs with the panel
tools only (reads on behalf of the asking user, drafts, escalation) and at most 6 turns. The answer is plain text of
at most 4000 characters; an escalation answers ``escalated``. Atrium treats every panel run as user-steered and
tainted; the question text reaches the model only inside Atrium's delimitation.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, ValidationError

from ...agents import loops
from .. import contract, wire
from ..models import RunCreated
from ..wire import WireMsg
from .bridge_client import BridgeError
from .client import AtriumError, Unavailable
from .spool import digest
from .tools import RunContext, names_for

if TYPE_CHECKING:
    from .runtime import Runtime

WORKING = "Working on it..."
BUSY = "The team cannot take more questions right now. Please try again later."
FAILED = "The team could not answer this question. Please try again later or ask a colleague."
ESCALATED = "The team passed your question on to the people who supervise it."
PAUSED = "The team was paused. Please ask again later."
PULL_MAX = 20  # questions one pull returns at most (the cores' PANEL_PULL_MAX)


class Question(BaseModel):
    """One open question from atrium.panel.pull (the bridge resolved the tool user; nothing here is verified)."""

    id: str = Field(pattern=contract.QUESTION_ID_RE.pattern)
    text: str = Field(max_length=contract.PANEL_TEXT_MAX)
    tool_user: dict[str, Any] = {}
    page: dict[str, Any] | None = None
    asked_at: int | None = None


class Panel:
    def __init__(self, rt: "Runtime"):
        self.rt = rt
        self.tasks: dict[str, asyncio.Task[Any]] = {}  # question id -> its run
        self.runs: dict[str, str] = {}  # question id -> the run id Atrium issued

    def running(self) -> list[str]:
        return [run_id for qid, run_id in self.runs.items() if qid in self.tasks and not self.tasks[qid].done()]

    def enabled(self) -> bool:
        charter, bridge = self.rt.charter, self.rt.bridge
        return (self.rt.working() and charter is not None and charter.panel.enabled and bool(charter.panel.desk)
                and bridge is not None and bridge.allows("atrium.panel.pull"))

    async def once(self, wait: int = contract.WAIT_MAX) -> list[asyncio.Task[Any]]:
        """One pull; each question starts a run (returned, so --once can wait for them)."""
        if not self.enabled():
            return []
        try:
            answer = await self.rt.bridge.call("atrium.panel.pull", {"wait": max(0, min(wait, contract.WAIT_MAX))})
        except BridgeError as exc:
            self.rt.log.info("The panel pull failed: %s", exc)
            return []
        if not answer.ok or not isinstance(answer.result, list):
            self.rt.log.info("The bridge refused the panel pull: %s", answer.refusal())
            return []
        started = []
        for raw in answer.result[:PULL_MAX]:
            try:
                question = Question.model_validate(raw)
            except ValidationError:
                continue
            if question.id in self.tasks and not self.tasks[question.id].done():
                continue
            task = asyncio.get_running_loop().create_task(self.handle(question))
            self.tasks[question.id] = task
            task.add_done_callback(lambda t, q=question.id: self.tasks.pop(q, None) if self.tasks.get(q) is t else None)
            started.append(task)
        return started

    async def answer(self, question_id: str, text: str, status: str) -> bool:
        desk = self.rt.charter.panel.desk if self.rt.charter else None
        staff = (self.rt.charter.staff.get(desk) or {}) if self.rt.charter and desk else {}
        by = wire.clean(staff.get("name") or "The team", contract.PANEL_BY_MAX).strip() or "The team"
        params = {"question_id": question_id, "text": wire.clean(text, contract.PANEL_ANSWER_MAX).strip() or FAILED,
                  "status": status, "by": by}
        try:
            reply = await self.rt.bridge.call("atrium.panel.answer", params)  # type: ignore[union-attr]
        except BridgeError as exc:
            self.rt.log.info("The panel answer failed: %s", exc)
            return False
        return reply.ok and isinstance(reply.result, dict) and reply.result.get("ok") is True

    async def handle(self, question: Question) -> None:
        desk = self.rt.charter.panel.desk if self.rt.charter else None
        if not desk:
            return
        try:
            data = await self.rt.atrium.post("runs", {"trigger": "panel", "question_id": question.id,
                                                      "agent_id": desk}, cv=True)
            created = RunCreated.model_validate(data)
        except (AtriumError, Unavailable, ValidationError):  # paused, a budget or a per-user limit, unreachable
            await self.answer(question.id, BUSY, "declined")
            self.record(question, "declined", None, 0)
            return
        self.runs[question.id] = created.run_id
        await self.answer(question.id, WORKING, "working")
        ctx = RunContext(created.run_id, desk, "panel", question_id=question.id,
                         tools=names_for(self.rt, desk, "panel"))
        outcome, status, text = "failed", "declined", FAILED
        try:
            async with self.rt.runner.slots():
                outcome, reply = await self.rt.runner.execute(
                    ctx, WireMsg(role="user", text=question.text),
                    max_turns=min(loops.PANEL_MAX_TURNS, created.max_turns),
                    max_tool_calls=min(loops.MAX_TOOL_CALLS, created.max_tool_calls))
            if ctx.escalated:
                outcome, status, text = "escalated", "escalated", reply if outcome == "done" else ESCALATED
            elif outcome == "done":
                outcome, status, text = "answered", "answered", reply
        except asyncio.CancelledError:
            await asyncio.shield(self._cancelled(question, created.run_id))
            raise
        finally:
            self.runs.pop(question.id, None)
        await self.answer(question.id, text, status)
        self.record(question, status, created.run_id, len(text))
        await self.rt.runner.end(created.run_id, outcome)

    async def _cancelled(self, question: Question, run_id: str) -> None:
        await self.answer(question.id, PAUSED, "declined")
        self.record(question, "declined", run_id, 0)
        await self.rt.runner.end(run_id, "cancelled")

    def record(self, question: Question, status: str, run_id: str | None, length: int) -> None:
        """The claimed audit entry: hashes and lengths, never the question, the answer or who asked."""
        self.rt.spool.add("panel.answer", agent_id=self.rt.charter.panel.desk if self.rt.charter else None,
                          run_id=run_id, outcome=status,
                          detail={"question": question.id, "question_sha256": digest(question.text),
                                  "question_length": len(question.text), "answer_length": length,
                                  "tool_user_sha256": digest(question.tool_user.get("id", ""))})
