"""A staff run's model and tools (6.5).

The model is Atrium's gateway: ``POST /model {run_id, agent_id, messages}``. Atrium composes the system prompt and the
tool list itself, delimits tool data, and books the budgets; the sidecar only keeps the conversation.

The tools the model may call (the run kind's names from ``GET /charter``, narrowed to the staff member's scope):

- ``act__<action>`` with risk read or propose: a signed bridge call with the ticket, on behalf of the asking tool user
  in panel runs. In API-only mode, ``records.<domain>.list`` runs here through the connector.
- ``act__<action>`` with risk write or admin: ``POST /actions/request``. Atrium decides (7.3): pending approval, denied,
  or granted at once (auto). A grant is carried out deterministically with the exact approved bytes (D5), never with
  what the model says next.
- ``atrium__<hub tool>``: ``POST /hub-request``, run in Atrium within the staff member's hub reach.
- ``atrium__report`` and ``atrium__escalate``: ``POST /reports``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, ValidationError

from .. import contract, wire
from ..models import ActionReply, Finding, GrantMessage, HubReply
from ..wire import WireMsg, WireResult
from .client import MODEL_TIMEOUT, AtriumError, MAX_MODEL_ANSWER, Unavailable
from .spool import digest

if TYPE_CHECKING:
    from .runtime import Runtime

RunOutcome = Literal["answered", "escalated", "declined", "failed", "budget", "tool_unavailable", "cancelled", "done"]


class RunAbort(Exception):
    """The run cannot go on: Atrium refused the model call (budget, pause, a changed charter) or is unreachable."""

    def __init__(self, outcome: RunOutcome, message: str):
        super().__init__(message)
        self.outcome = outcome


class ToolError(Exception):
    """A tool call failed or was refused; the model reads the message."""


@dataclass
class RunContext:
    run_id: str
    agent_id: str
    trigger: str
    question_id: str | None = None  # panel runs: the question asked in the tool
    tools: frozenset[str] = frozenset()
    escalated: bool = False
    tool_calls: int = 0
    reads: list[str] = field(default_factory=list)  # bridge reads (action ids), for the spool
    abort: "RunAbort | None" = None  # set by a tool when Atrium stopped the run: the next turn is not asked for

    @property
    def panel(self) -> bool:
        return self.trigger == "panel"


def abort_of(exc: AtriumError) -> RunAbort:
    if exc.status == 429:
        return RunAbort("budget", "Atrium refused the run: a budget of the team is used up.")
    if exc.status in (409, 423):
        return RunAbort("cancelled", "Atrium stopped the run: the team was paused or its charter changed.")
    return RunAbort("failed", f"Atrium refused the run ({exc.status}).")


class GatewayModel:
    """loops.Model over Atrium's gateway; remembers the latest assistant text (an action request's reason)."""

    def __init__(self, rt: "Runtime", ctx: RunContext):
        self.rt, self.ctx = rt, ctx
        self.last_text = ""
        self.turns = 0
        self.tokens = {"input": 0, "output": 0}

    async def complete(self, messages: list[WireMsg]) -> WireResult:
        if self.ctx.abort is not None:
            raise self.ctx.abort
        body = {"run_id": self.ctx.run_id, "agent_id": self.ctx.agent_id,
                "messages": [m.model_dump(mode="json", exclude_none=True) for m in messages]}
        try:
            data = await self.rt.atrium.post("model", body, timeout=MODEL_TIMEOUT, limit=MAX_MODEL_ANSWER, cv=True)
        except AtriumError as exc:
            raise abort_of(exc) from None
        except Unavailable as exc:
            raise RunAbort("failed", str(exc)) from None
        try:
            result = WireResult.model_validate(data)
        except ValidationError:
            raise RunAbort("failed", "Atrium's model answer was not understood.") from None
        self.turns += 1
        self.tokens["input"] += result.usage.input_tokens
        self.tokens["output"] += result.usage.output_tokens
        self.last_text = result.text
        return result


class ReportArgs(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    text: str = Field("", max_length=8000)
    findings: list[Finding] = Field([], max_length=10)


class EscalateArgs(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    text: str = Field("", max_length=8000)
    severity: Literal["info", "warning", "critical"] = "warning"


def names_for(rt: "Runtime", agent_id: str, kind: str) -> frozenset[str]:
    """The tools a run of `kind` (normal, panel) may call: the charter's names for the run kind, narrowed to the
    staff member's scope (Atrium composes the same list for the model)."""
    charter = rt.charter
    if charter is None or agent_id not in charter.staff:
        return frozenset()
    scope = charter.staff[agent_id]
    actions, hub_tools = set(scope.get("actions") or []), set(scope.get("hub_tools") or [])
    out = set()
    for tool in charter.tools.get(kind, []):
        if tool.action_id is not None:
            if tool.action_id in actions:
                out.add(tool.name)
        elif contract.hub_tool_of(tool.name) is not None:
            if contract.hub_tool_of(tool.name) in hub_tools:
                out.add(tool.name)
        elif tool.name in (contract.REPORT_TOOL, contract.ESCALATE_TOOL):
            out.add(tool.name)
    return frozenset(out)


class RunTools:
    """loops.Run for one run: executes the model's tool calls."""

    def __init__(self, rt: "Runtime", ctx: RunContext, model: GatewayModel):
        self.rt, self.ctx, self.model = rt, ctx, model

    async def __call__(self, name: str, args: dict[str, Any]) -> Any:
        self.ctx.tool_calls += 1
        if name not in self.ctx.tools:
            raise ToolError(f"{name} is not one of this run's tools")
        action_id = contract.action_of(name)
        if action_id is not None:
            return await self.action(action_id, args)
        if name == contract.REPORT_TOOL:
            return await self.report(args)
        if name == contract.ESCALATE_TOOL:
            return await self.escalate(args)
        tool = contract.hub_tool_of(name)
        if tool is not None:
            return await self.hub_request(tool, args)
        raise ToolError(f"{name} is not a tool")

    # -- in-tool actions ----------------------------------------------------------------

    async def action(self, action_id: str, args: dict[str, Any]) -> Any:
        charter = self.rt.charter
        action = next((a for a in charter.actions if a.id == action_id), None) if charter else None
        if action is None or action.policy == "forbidden":
            raise ToolError(f"{action_id} is not in the team's charter")
        try:
            params = contract.validate_params(action.params, args)
        except contract.Refused:
            raise ToolError(f"the parameters do not fit {action_id}'s schema") from None
        if action.risk in contract.NEEDS_GRANT:
            return await self.request(action_id, params)
        if self.rt.config.mode == "sidecar_only":
            return await self.connector_read(action_id, params)
        return await self.bridge_read(action_id, params, action.on_behalf_of)

    async def bridge_read(self, action_id: str, params: dict[str, Any], on_behalf_of: bool) -> Any:
        from .bridge_client import BridgeError

        if self.rt.bridge is None:
            raise ToolError("the tool's bridge is not configured")
        obo = self.ctx.question_id if self.ctx.panel and on_behalf_of else None
        try:
            answer = await self.rt.bridge.call(action_id, params, on_behalf_of=obo)
        except BridgeError as exc:
            self.rt.spool.add("bridge.read", agent_id=self.ctx.agent_id, run_id=self.ctx.run_id, action_id=action_id,
                              outcome=exc.code)
            raise ToolError(str(exc)) from None
        size = len(wire.text_of(answer.result)) if answer.ok else 0
        self.rt.spool.add("bridge.read", agent_id=self.ctx.agent_id, run_id=self.ctx.run_id, action_id=action_id,
                          outcome="ok" if answer.ok else (answer.code or "refused"),
                          detail={"status": answer.status, "length": size, "on_behalf_of": obo is not None,
                                  "sha256": digest(wire.text_of(answer.result)) if answer.ok else None})
        if not answer.ok:
            raise ToolError(answer.refusal())
        self.ctx.reads.append(action_id)
        return answer.result

    async def connector_read(self, action_id: str, params: dict[str, Any]) -> Any:
        backend = self.rt.connector
        if backend is None:
            raise ToolError("the sidecar has no credential for the tool's API yet")
        try:
            result = await backend.list(action_id, params)
        except Exception as exc:
            self.rt.spool.add("connector.read", agent_id=self.ctx.agent_id, run_id=self.ctx.run_id,
                              action_id=action_id, outcome="failed")
            raise ToolError(self.rt.secrets.mask(f"the tool's API failed: {exc}")[:300]) from None
        self.rt.spool.add("connector.read", agent_id=self.ctx.agent_id, run_id=self.ctx.run_id, action_id=action_id,
                          outcome="ok", detail={"records": len(result["records"]), "count": result["count"]})
        self.ctx.reads.append(action_id)
        return result

    async def request(self, action_id: str, params: dict[str, Any]) -> Any:
        body = {"run_id": self.ctx.run_id, "agent_id": self.ctx.agent_id, "action_id": action_id, "params": params,
                "reason": wire.clean(self.model.last_text, 2000)}
        try:
            reply = ActionReply.model_validate(await self.rt.atrium.post("actions/request", body, cv=True))
        except AtriumError as exc:
            raise self.refused(exc) from None
        except (Unavailable, ValidationError):
            raise ToolError("Atrium could not take the request now") from None
        self.rt.spool.add("action.request", agent_id=self.ctx.agent_id, run_id=self.ctx.run_id, action_id=action_id,
                          outcome=reply.status)
        if reply.status == "denied":
            raise ToolError(f"refused by Atrium: {wire.clean(reply.reason or 'no reason given', 500)}")
        if reply.status == "pending_approval":
            return {"status": "pending_approval", "approval_id": reply.approval_id,
                    "note": "A person decides in Atrium. If it is approved, Atrium carries it out exactly as requested; "
                            "the outcome reaches you at the start of your next run."}
        if not reply.grant or not reply.body_b64:
            raise ToolError("Atrium granted the request without a grant")
        grant = GrantMessage(approval_id=reply.approval_id or "auto", grant=reply.grant, body_b64=reply.body_b64,
                             action_id=action_id, run_id=self.ctx.run_id, agent_id=self.ctx.agent_id)
        status, result = await self.rt.grants.execute(grant, note=False)
        if status != "executed":
            raise ToolError(f"the tool did not carry out the granted request ({status})")
        return {"status": "executed", "result": result}

    def refused(self, exc: AtriumError) -> ToolError:
        if exc.status in (409, 423):  # paused or a changed charter: the run ends after this tool call
            self.ctx.abort = abort_of(exc)
            return ToolError(str(self.ctx.abort))
        return ToolError(f"Atrium refused the request: {exc.message or exc.code or exc.status}")

    # -- reports, escalations, hub requests -------------------------------------------------

    async def report(self, args: dict[str, Any]) -> Any:
        try:
            parsed = ReportArgs.model_validate(args)
        except ValidationError:
            raise ToolError("a report has a title (at most 200 characters), a text and at most 10 findings") from None
        return await self._report({"kind": "report", **parsed.model_dump(mode="json")})

    async def escalate(self, args: dict[str, Any]) -> Any:
        try:
            parsed = EscalateArgs.model_validate(args)
        except ValidationError:
            raise ToolError("an escalation has a title (at most 200 characters), a text and a severity "
                            "(info, warning, critical)") from None
        answer = await self._report({"kind": "escalation", **parsed.model_dump(mode="json"),
                                     "question_id": self.ctx.question_id if self.ctx.panel else None})
        self.ctx.escalated = True
        return answer

    async def _report(self, fields: dict[str, Any]) -> Any:
        body = {"run_id": self.ctx.run_id, "agent_id": self.ctx.agent_id,
                **{k: v for k, v in fields.items() if v is not None}}
        try:
            answer = await self.rt.atrium.post("reports", body)
        except AtriumError as exc:
            raise ToolError(f"Atrium refused the {fields['kind']}: {exc.message or exc.code or exc.status}") from None
        except Unavailable:
            raise ToolError("Atrium could not take it now") from None
        self.rt.spool.add(fields["kind"], agent_id=self.ctx.agent_id, run_id=self.ctx.run_id,
                          detail={"title_sha256": digest(fields["title"]), "length": len(fields.get("text") or "")})
        return {"ok": True, "id": answer.get("id") if isinstance(answer, dict) else None}

    async def hub_request(self, tool: str, args: dict[str, Any]) -> Any:
        body = {"run_id": self.ctx.run_id, "agent_id": self.ctx.agent_id, "tool": tool, "args": args}
        try:
            reply = HubReply.model_validate(await self.rt.atrium.post("hub-request", body, cv=True))
        except AtriumError as exc:
            raise self.refused(exc) from None
        except (Unavailable, ValidationError):
            raise ToolError("Atrium could not take the request now") from None
        if not reply.ok:
            raise ToolError(reply.error or "Atrium refused the request")
        return reply.result
