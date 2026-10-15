"""Staff runs and granted actions.

Runs. Atrium issues every run id: an inbox ``run`` or ``chat`` carries one (a scheduled run, a task or a chat started
in Atrium), and a panel question gets one from ``POST /runs`` (panel.py). The sidecar has no scheduler of its own. A
run is ``loops.tool_loop`` over Atrium's gateway (at most 12 turns, 6 for panel runs, and 20 tool calls), at most
``budgets.max_concurrent_runs`` at a time. A relayed run ends with ``POST /replies {correlation_id, reply, ok}``;
every run ends with ``POST /runs/{id}/end {outcome}``. Pausing cancels the runs under way.

Grants (D5). A granted action - inbox ``grant`` after a person approved, or an auto grant in the request's answer -
is carried out outside the model loop: the bridge call carries exactly the body bytes Atrium returned, after the
sidecar checked that they are the bytes the grant names. The result goes to ``POST /actions/{approval}/result``. Each
grant is kept in the state directory until its result is recorded, so a crash in between is recovered with
``atrium.receipt``; a grant that expired before it could be sent is re-granted (4.7) once the bridge confirms it was
never used. Outcomes reach the staff member as a note at the start of its next run.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ...agents import loops
from .. import contract, wire
from ..models import ActionReply, ActionResultMessage, DeniedMessage, GrantMessage, RunMessage
from ..wire import WireMsg
from .bridge_client import BridgeError, token_payload
from .client import AtriumError, Unavailable
from .tools import GatewayModel, RunAbort, RunContext, RunOutcome, RunTools, names_for

if TYPE_CHECKING:
    from .runtime import Runtime

GRANTS_FILE = "grants.json"
REPLY_MAX = 8000
NOTES_MAX = 20


@dataclass
class Notes:
    """Outcomes of a staff member's earlier action requests, for the start of its next run."""

    by_agent: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # agent -> [(approval id, text)]

    def add(self, agent_id: str, approval_id: str, text: str) -> None:
        items = self.by_agent.setdefault(agent_id, [])
        items.append((approval_id, wire.clean(text, 500)))
        del items[:-NOTES_MAX]

    def take(self, agent_id: str, from_atrium: list[str]) -> list[str]:
        """Atrium's notes, then the sidecar's own that Atrium did not already mention."""
        mine = self.by_agent.pop(agent_id, [])
        return [*from_atrium, *(text for approval, text in mine if not any(approval in n for n in from_atrium))]


def first_message(text: str, notes: list[str]) -> WireMsg:
    parts = []
    if notes:
        parts.append("Outcomes of your earlier requests:\n" + "\n".join(f"- {wire.clean(n, 500)}" for n in notes))
    parts.append(text or "Do your standing task.")
    return WireMsg(role="user", text="\n\n".join(parts))


class Runner:
    def __init__(self, rt: "Runtime"):
        self.rt = rt
        self.tasks: dict[str, asyncio.Task[Any]] = {}
        self.notes = Notes()
        self._limit = 0
        self._slots: asyncio.Semaphore | None = None

    def running(self) -> list[str]:
        return [run_id for run_id, task in self.tasks.items() if not task.done()]

    def slots(self) -> asyncio.Semaphore:
        limit = max(1, self.rt.charter.budgets.max_concurrent_runs if self.rt.charter else 1)
        if self._slots is None or limit != self._limit:
            self._limit, self._slots = limit, asyncio.Semaphore(limit)
        return self._slots

    def start(self, run_id: str, work: Any) -> asyncio.Task[Any]:
        task = asyncio.get_running_loop().create_task(work)
        self.tasks[run_id] = task
        task.add_done_callback(lambda t, rid=run_id: self.tasks.pop(rid, None) if self.tasks.get(rid) is t else None)
        return task

    async def cancel_all(self) -> int:
        """Pause or stop: every run under way is cancelled (Atrium refuses their next step anyway)."""
        tasks = [t for t in self.tasks.values() if not t.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return len(tasks)

    # -- one run ---------------------------------------------------------------------------

    async def execute(self, ctx: RunContext, first: WireMsg, *, max_turns: int,
                      max_tool_calls: int) -> tuple[RunOutcome, str]:
        """Run the loop; (outcome, reply text). Never raises but on cancellation."""
        model = GatewayModel(self.rt, ctx)
        self.rt.spool.add("run.start", agent_id=ctx.agent_id, run_id=ctx.run_id, detail={"trigger": ctx.trigger})
        outcome: RunOutcome = "done"
        try:
            result = await loops.tool_loop(model, [first], RunTools(self.rt, ctx, model), max_turns=max_turns,
                                           max_tool_calls=max_tool_calls)
            reply = result.reply
        except RunAbort as exc:
            outcome, reply = exc.outcome, str(exc)
        except asyncio.CancelledError:
            self.rt.spool.add("run.end", agent_id=ctx.agent_id, run_id=ctx.run_id, outcome="cancelled",
                              detail={"turns": model.turns, "tool_calls": ctx.tool_calls})
            raise
        self.rt.spool.add("run.end", agent_id=ctx.agent_id, run_id=ctx.run_id, outcome=outcome,
                          detail={"turns": model.turns, "tool_calls": ctx.tool_calls, "reads": len(ctx.reads),
                                  "tokens_in": model.tokens["input"], "tokens_out": model.tokens["output"]})
        return outcome, reply

    async def end(self, run_id: str, outcome: str) -> None:
        try:
            await self.rt.atrium.post(f"runs/{run_id}/end", {"outcome": outcome})
        except (AtriumError, Unavailable) as exc:
            self.rt.log.info("Atrium did not record the end of run %s: %s", run_id, exc)

    async def relayed(self, msg: RunMessage) -> None:
        """An inbox run or chat: run it and reply. Cancelled (a pause): Atrium still learns that the run ended."""
        try:
            async with self.slots():
                ok, outcome, reply = await self._relayed(msg)
        except asyncio.CancelledError:
            await asyncio.shield(self.end(msg.run_id, "cancelled"))
            raise
        try:
            await self.rt.atrium.post("replies", {"correlation_id": msg.correlation_id, "ok": ok,
                                                  "reply": reply[:REPLY_MAX]})
        except (AtriumError, Unavailable) as exc:
            self.rt.log.warning("Atrium did not take the reply of run %s: %s", msg.run_id, exc)
        await self.end(msg.run_id, outcome)

    async def _relayed(self, msg: RunMessage) -> tuple[bool, str, str]:
        if not self.rt.working():
            return False, "cancelled", "The team is not working right now (paused by Atrium)."
        tools = names_for(self.rt, msg.agent_id, "normal")
        if self.rt.charter is None or msg.agent_id not in self.rt.charter.staff:
            return False, "failed", "This staff member is not in the team's charter."
        ctx = RunContext(msg.run_id, msg.agent_id, msg.trigger, tools=tools)
        first = first_message(msg.text, self.notes.take(msg.agent_id, list(msg.notes)))
        outcome, reply = await self.execute(ctx, first, max_turns=loops.MAX_TURNS,
                                            max_tool_calls=loops.MAX_TOOL_CALLS)
        return outcome == "done", outcome, reply


# --------------------------------------------------------------------------------------
# grants (D5)
# --------------------------------------------------------------------------------------


def decode_body(body_b64: str) -> bytes:
    """The approved body: base64url without padding (the contract's encoding), or standard base64."""
    try:
        return contract.b64u_decode(body_b64)
    except ValueError:
        pass
    try:
        return base64.b64decode(body_b64, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("body_b64 is not base64") from None


class Grants:
    """Grants in flight, kept in the state directory (0600) until their result is recorded in Atrium."""

    def __init__(self, rt: "Runtime"):
        self.rt = rt
        data = rt.state.read_json(GRANTS_FILE)
        self.items: dict[str, dict[str, Any]] = data if isinstance(data, dict) else {}
        self.lock = asyncio.Lock()
        rt.secrets.add(*(g.get("grant") for g in self.items.values()))

    def save(self) -> None:
        """Write the grants in flight; a done grant keeps only its jti (duplicates are recognised) until exp + 1 h."""
        now = self.rt.clock()
        self.items = {j: g for j, g in self.items.items()
                      if g["state"] != "done" or g["exp"] + contract.GRANT_JTI_KEEP > now}
        for g in self.items.values():
            if g["state"] == "done":
                g["grant"] = g["body_b64"] = ""
        self.rt.state.write_json(GRANTS_FILE, self.items)

    async def execute(self, msg: GrantMessage, *, note: bool = True) -> tuple[str, Any]:
        """Carry out a grant: (status, result). status: executed, failed, refused (not sent: the grant does not fit),
        pending (the bridge could not be reached; retried), done (carried out earlier)."""
        async with self.lock:
            try:
                payload = token_payload(msg.grant, contract.GRANT_PREFIX)
                body = decode_body(msg.body_b64)
            except ValueError:
                return await self._refuse(msg, None, "the grant or its body could not be read")
            jti = payload["jti"]
            known = self.items.get(jti)
            if known is not None and known["state"] in ("sent", "done"):
                return "done", None  # a duplicate message: never sent twice
            self.rt.secrets.add(msg.grant)
            if payload.get("act") != msg.action_id or payload.get("bh") != contract.body_hash(body):
                return await self._refuse(msg, jti, "the approved body does not match the grant")
            self.items[jti] = {"jti": jti, "approval_id": msg.approval_id, "action_id": msg.action_id,
                               "run_id": msg.run_id, "agent_id": msg.agent_id, "grant": msg.grant,
                               "body_b64": msg.body_b64, "exp": int(payload["exp"]), "state": "pending",
                               "note": note}
            self.save()
            return await self._send(jti)

    async def _refuse(self, msg: GrantMessage, jti: str | None, why: str) -> tuple[str, Any]:
        self.rt.log.warning("Refused to carry out grant for %s: %s", msg.action_id, why)
        self.rt.spool.add("grant.refused", agent_id=msg.agent_id, run_id=msg.run_id, action_id=msg.action_id,
                          outcome="refused")
        if jti is not None:
            await self._result(msg.approval_id, jti, "failed", None, f"not sent by the sidecar: {why}")
        return "refused", None

    async def _send(self, jti: str) -> tuple[str, Any]:
        g = self.items[jti]
        bridge = self.rt.bridge
        if bridge is None:
            return "pending", None
        g["state"] = "sent"
        self.save()
        try:
            answer = await bridge.send(g["action_id"], decode_body(g["body_b64"]), grant=g["grant"])
        except BridgeError as exc:
            if exc.code in ("no_ticket", "action_not_allowed"):  # nothing left the sidecar: send it later
                g["state"] = "pending"
                self.save()
            # otherwise it may have reached the tool (a timeout, an oversized answer): the receipt tells, later
            return "pending", None
        if answer.status == 409 and answer.code == "grant_used":  # sent before (a crash): what happened then?
            status, receipt = await self._receipt(jti)
            await self._finish(jti, status, receipt, None)
            return status, None
        status = "executed" if answer.ok else "failed"
        await self._finish(jti, status, answer.receipt, answer.result if answer.ok else answer.refusal())
        return status, answer.result if answer.ok else None

    async def _receipt(self, jti: str) -> tuple[str, dict[str, Any] | None]:
        try:
            answer = await self.rt.bridge.call("atrium.receipt", {"jti": jti})  # type: ignore[union-attr]
        except BridgeError:
            return "unknown", None
        status = (answer.result or {}).get("status") if answer.ok and isinstance(answer.result, dict) else None
        status = status if status in ("unused", "executed", "failed") else "unknown"
        return status, {"jti": jti, "status": status, **({"at": answer.result["at"]}
                                                          if isinstance(answer.result, dict) and "at" in answer.result
                                                          else {})}

    async def _finish(self, jti: str, status: str, receipt: dict[str, Any] | None, result: Any) -> None:
        g = self.items[jti]
        final = status if status in ("executed", "failed") else "failed"
        summary = wire.clean(wire.text_of(result), 2000) if result is not None else status
        recorded = await self._result(g["approval_id"], jti, final, receipt, summary)
        g["state"] = "done" if recorded else "sent"
        self.save()
        self.rt.spool.add("grant.result", agent_id=g["agent_id"], run_id=g["run_id"], action_id=g["action_id"],
                          outcome=status, detail={"grant": jti, "recorded": recorded})
        if g.get("note", True) and not g.get("noted"):
            g["noted"] = True
            done = "was carried out" if status == "executed" else f"did not go through in the tool ({status})"
            self.rt.runner.notes.add(g["agent_id"], g["approval_id"],
                                     f"Your request {g['approval_id']} ({g['action_id']}) {done}.")

    async def _result(self, approval_id: str, jti: str, status: str, receipt: dict[str, Any] | None,
                      summary: str) -> bool:
        body = {"grant_jti": jti, "status": status, "receipt": receipt, "result_summary": summary[:2000]}
        try:
            await self.rt.atrium.post(f"actions/{approval_id}/result", body)
            return True
        except AtriumError as exc:
            self.rt.log.warning("Atrium refused the result of grant %s: %s", jti, exc)
            return exc.status in (400, 404, 409, 422)  # Atrium will not take it: stop retrying
        except Unavailable:
            return False

    async def retry(self) -> None:
        """Every heartbeat: grants not yet sent are sent while valid; expired unused ones are re-granted; results
        Atrium did not take yet are posted again; sent-but-unrecorded ones (a crash) are recovered by receipt."""
        regranted: list[tuple[GrantMessage, bool]] = []
        async with self.lock:
            now = self.rt.clock()
            for jti, g in list(self.items.items()):
                if g["state"] == "done" or self.rt.bridge is None or not self.rt.bridge.valid():
                    continue
                if g["state"] == "sent":
                    status, receipt = await self._receipt(jti)
                    if status in ("executed", "failed"):
                        await self._finish(jti, status, receipt, None)
                        continue
                    if status == "unknown":  # the bridge cannot tell: Atrium's reconciliation reports it
                        if now > g["exp"] + contract.GRANT_JTI_KEEP:
                            g["state"] = "done"
                            self.save()
                        continue
                    g["state"] = "pending"  # unused: it never reached the handler
                if g["exp"] - contract.CLOCK_LEEWAY > now:
                    await self._send(jti)
                elif g["approval_id"] != "auto":
                    if now < g["exp"] + contract.CLOCK_LEEWAY:  # the bridge may still take it: Atrium waits too
                        continue
                    msg = await self._regrant(jti)
                    if msg is not None:
                        regranted.append((msg, g.get("note", True)))
                else:
                    g["state"] = "done"
                    self.save()
        for msg, note in regranted:
            await self.execute(msg, note=note)

    async def _regrant(self, jti: str) -> GrantMessage | None:
        """4.7: a new grant for an approval whose grant expired unused (the bridge's receipt says so)."""
        g = self.items[jti]
        status, receipt = await self._receipt(jti)
        if status != "unused":
            if status in ("executed", "failed"):
                await self._finish(jti, status, receipt, None)
            return None
        try:
            reply = ActionReply.model_validate(await self.rt.atrium.post(
                f"actions/{g['approval_id']}/regrant", {"old_jti": jti, "receipt": receipt}))
        except (AtriumError, Unavailable, ValidationError) as exc:
            self.rt.log.info("No new grant for %s: %s", g["approval_id"], exc)
            if isinstance(exc, AtriumError) and exc.status in (403, 404, 409, 410, 422) and exc.code != "grant_valid":
                g["state"] = "done"
                self.save()
            return None
        g["state"] = "done"
        self.save()
        if reply.status == "pending_approval":  # Atrium could not check the receipt: a person decides again
            self.rt.log.info("A person decides %s again (as %s)", g["approval_id"], reply.approval_id)
        if reply.status != "granted" or not reply.grant or not reply.body_b64:
            return None
        return GrantMessage(approval_id=g["approval_id"], grant=reply.grant, body_b64=reply.body_b64,
                            action_id=g["action_id"], run_id=g["run_id"], agent_id=g["agent_id"])

    async def drop_pending(self, why: str) -> int:
        """Pause: grants not yet sent are not carried out (resuming releases no backlog); Atrium learns why."""
        async with self.lock:
            dropped = [j for j, g in self.items.items() if g["state"] == "pending"]
            for jti in dropped:
                g = self.items[jti]
                g["state"] = "done"
                self.save()
                await self._result(g["approval_id"], jti, "failed", None, f"not sent: {why}")
                self.rt.spool.add("grant.dropped", agent_id=g["agent_id"], run_id=g["run_id"],
                                  action_id=g["action_id"], outcome="dropped")
            return len(dropped)

    async def refuse_paused(self, msg: GrantMessage) -> None:
        """A grant that arrives while the team is not working is not carried out."""
        try:
            jti = token_payload(msg.grant, contract.GRANT_PREFIX)["jti"]
        except ValueError:
            return
        if jti not in self.items:
            await self._refuse(msg, jti, "the team is not working (paused by Atrium)")

    # -- inbox notes ---------------------------------------------------------------------------

    def denied(self, msg: DeniedMessage) -> None:
        self.rt.spool.add("action.denied", agent_id=msg.agent_id, run_id=msg.run_id, action_id=msg.action_id,
                          outcome="denied")
        reason = f": {msg.reason}" if msg.reason else ""
        self.rt.runner.notes.add(msg.agent_id, msg.approval_id,
                                 f"Your request {msg.approval_id} ({msg.action_id}) was not approved{reason}.")

    def action_result(self, msg: ActionResultMessage) -> None:
        self.rt.spool.add("action.result", agent_id=msg.agent_id, run_id=msg.run_id, action_id=msg.action_id,
                          outcome=msg.status)
        done = "was carried out by Atrium" if msg.status == "executed" else "failed when Atrium carried it out"
        self.rt.runner.notes.add(msg.agent_id, msg.approval_id,
                                 f"Your request {msg.approval_id} ({msg.action_id}) {done}.")

