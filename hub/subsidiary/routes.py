"""REST routes of subsidiaries (added to the main router by ``api.build_router``; roles in ``hub/auth/policy.py``).

For people (9.1). Viewers read; operators propose, pause (protective) and handle reports; administrators - signed in
as a person where noted - change the credential, enroll the sidecar, rotate keys, re-run conformance, resume, stop
and archive. Text a subsidiary wrote is untrusted: clients render it as plain text.

  GET    /api/subsidiaries                                  viewer    the group dashboard: one summary per subsidiary
  GET    /api/subsidiaries/{tool_id}                        viewer    detail (no credential, enrollment hash or key)
  POST   /api/tools/{tool_id}/subsidiary                    operator  {mode, designer, goals}: propose (5.1)
  PUT    /api/subsidiaries/{tool_id}/credential             admin     {secrets}: API-only mode's read credential
  DELETE /api/subsidiaries/{tool_id}/credential             admin
  POST   /api/subsidiaries/{tool_id}/enrollment             admin*    a one-time code, shown once, and the bundle
  POST   /api/subsidiaries/{tool_id}/conformance            admin     run the conformance vectors again
  POST   /api/subsidiaries/{tool_id}/rotate-key[?finish=1]  admin     stage the next signing key / retire the old one
  POST   /api/subsidiaries/{tool_id}/pause                  operator  {reason}
  POST   /api/subsidiaries/pause-all                        operator  {reason}
  POST   /api/subsidiaries/{tool_id}/resume                 admin*
  POST   /api/subsidiaries/{tool_id}/stop                   admin*    {confirm: the tool's name}
  DELETE /api/subsidiaries/{tool_id}                        admin     archive a stopped subsidiary
  GET    /api/subsidiaries/{tool_id}/audit[?detail=1]       viewer    metadata; operators may ask for the detail
  POST   /api/subsidiaries/{tool_id}/audit/verify           operator  recompute the hash chain
  GET    /api/subsidiaries/{tool_id}/reports                viewer    titles; operators also read the text
  POST   /api/subsidiaries/{tool_id}/reports/{id}/close     operator
  POST   /api/subsidiaries/{tool_id}/reports/{id}/promote   operator  a person creates a risk from it
  PUT    /api/subsidiaries/{tool_id}/charter                admin     amend: narrowing applies, widening is approved
  POST   /api/subsidiaries/{tool_id}/tasks                  operator  {agent_id?, text}: a task for a staff member
  GET    /api/subsidiaries/{tool_id}/runs                   viewer    the staff's runs (counts, taint sources)
  (* a person: API tokens are refused with 403 person_required)

For the sidecar (9.2): only a principal with role ``subsidiary`` reaches /api/subsidiary/v1/*, bound to its own
subsidiary (enroll excepted: public, throttled). Every body is at most 64 KiB, each token makes at most 120 requests a
minute and holds at most 2 open long-polls. Paused, stopped or switched-off subsidiaries get 423 {code: paused |
stopped | disabled} - except heartbeat, inbox and rotate, so the sidecar learns its status. A sidecar that sends
``Atrium-Charter-Version`` gets 409 {code: charter_changed} when the charter moved on.

  POST /api/subsidiary/v1/enroll         {code, public_key, version} -> {token, subsidiary_id, tool_id, expires_at}
  POST /api/subsidiary/v1/rotate         -> {token, expires_at}; the old token works until the new one is used
  POST /api/subsidiary/v1/heartbeat      -> {status, flags, ticket?, ticket_exp?, charter_version, server_time}
  GET  /api/subsidiary/v1/charter        the charter as the sidecar needs it (ETag / If-None-Match)
  GET  /api/subsidiary/v1/credential     API-only mode, probation or active: the dedicated credential
  GET  /api/subsidiary/v1/inbox?cursor&wait   messages after cursor (acknowledging those up to it), long-poll
  POST /api/subsidiary/v1/conformance    {rows, built_at}: results of vectors Atrium asked the sidecar to run
  POST /api/subsidiary/v1/model          {run_id, agent_id, messages} -> one model turn (gateway.py; 4 MiB)
  POST /api/subsidiary/v1/runs           {trigger: panel, question_id, agent_id} -> {run_id, max_turns, ...}
  POST /api/subsidiary/v1/runs/{id}/end  {outcome}
  POST /api/subsidiary/v1/replies        {correlation_id, reply, ok}: the answer of a relayed run or chat
  POST /api/subsidiary/v1/actions/request            the decision table (actions.py)
  POST /api/subsidiary/v1/actions/{approval}/result  {grant_jti, status, receipt, result_summary}
  POST /api/subsidiary/v1/actions/{approval}/regrant {old_jti, receipt}: once, on the bridge's receipt as Atrium
                                                     observes it (else a person decides again: pending_approval)
  POST /api/subsidiary/v1/hub-request    {run_id, agent_id, tool, args} (hubrequest.py)
  POST /api/subsidiary/v1/reports        reports and escalations
  POST /api/subsidiary/v1/events         {events}: declared tool events, republished on the tool bus
Replies, run ends and results are recorded whatever the status (they report what already happened).

SSE events: subsidiary (summary), subsidiary_report (ids and severity, no text).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Literal, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..agents import teams
from ..auth.policy import ROLE_RANK
from ..auth.service import CurrentPrincipal, Principal, client_ip
from ..integration import flows
from ..models import ApiToken, Risk
from ..store import new_id
from . import (actions, agent, audit, bridgepatch, conformance, contract, gateway, governance, hubrequest, keys,
               runtime, wire)
from . import charter as charters
from .models import (COLLECTIONS, ActionRequest, ActionResult, Budgets, ConformanceResults, DataSettings,
                     EnrollRequest, EventSettings, EventsRequest, HeartbeatRequest, HubRequest, InboxResponse,
                     ModelRequest, ModelRouting, PanelSettings, RegrantRequest, ReplyRequest, Report, ReportRequest,
                     RunCreate, RunEnd, StaffScope, Subsidiary)

if TYPE_CHECKING:
    from ..core import Hub

Ask = Callable[..., Awaitable[dict[str, Any]]]
M = TypeVar("M", bound=BaseModel)
H_CHARTER = "Atrium-Charter-Version"
ENROLL_BODY = 4096
MODEL_BODY = 4 * 1024 * 1024
REPORTS = COLLECTIONS["reports"]
OPEN_REPORTS = 200  # open reports a subsidiary may have at once
EXEMPT = ("heartbeat", "inbox", "rotate", "replies", "runs/{id}/end", "actions/{id}/result")  # whatever the status


class ProposeBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["auto", "bridge", "sidecar_only"] = "auto"
    designer: Literal["auto", "templates", "model", "claude"] = "auto"
    goals: str = Field("", max_length=2000)


class CredentialBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    secrets: dict[str, str] = Field(default_factory=dict, max_length=20)


class ReasonBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field("", max_length=500)


class StopBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: str = Field(max_length=200)


class TaskBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_id: str | None = Field(None, max_length=60)
    text: str = Field(min_length=1, max_length=4000)


class CharterBody(BaseModel):
    """An amendment: the fields given replace the charter's; actions come from the tool's catalog (only their policy
    is chosen here); new staff are described in `members`."""

    model_config = ConfigDict(extra="forbid")
    mandate: str | None = Field(None, max_length=4000)
    actions: list[dict[str, Any]] | None = Field(None, max_length=contract.MAX_ACTIONS)
    staff: dict[str, StaffScope] | None = Field(None, max_length=charters.MAX_STAFF)
    model_routing: ModelRouting | None = None
    budgets: Budgets | None = None
    panel: PanelSettings | None = None
    events: EventSettings | None = None
    data: DataSettings | None = None
    members: list[dict[str, Any]] = Field([], max_length=charters.MAX_STAFF)


@dataclass
class Caller:
    """A sidecar's request: its subsidiary, its token and the body it sent (read once, size-capped)."""

    sub: Subsidiary
    token: ApiToken
    principal: Principal
    body: bytes


def refused(exc: governance.GovernanceError) -> HTTPException:
    return HTTPException(exc.status, {"code": exc.code, "message": str(exc), **exc.extra} if exc.code else str(exc))


def problems(exc: ValidationError) -> list[dict[str, Any]]:
    """Where and why a body is invalid - never the input itself (it may hold secrets)."""
    return [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", "")), "type": str(e.get("type", ""))}
            for e in exc.errors()[:10]]


def parse(model: type[M], body: bytes) -> M:
    try:
        return model.model_validate_json(body or b"{}")
    except ValidationError as exc:
        raise HTTPException(422, problems(exc)) from None


async def read_body(request: Request, limit: int) -> bytes:
    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > limit:
        raise HTTPException(413, {"code": "too_large", "message": f"Bodies are at most {limit} bytes."})
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise HTTPException(413, {"code": "too_large", "message": f"Bodies are at most {limit} bytes."})
        chunks.append(chunk)
    return b"".join(chunks)


def add_routes(router: APIRouter, hub: "Hub", ask: Ask) -> None:
    def current(tool_id: str) -> Subsidiary:
        sub = governance.of_tool(hub, tool_id, archived=True)
        if sub is None:
            raise HTTPException(404, "Subsidiary not found")
        return sub

    def person(p: Principal) -> None:
        if p.kind != "user":
            raise HTTPException(403, {"code": "person_required",
                                      "message": "An administrator does this signed in, not with an API token."})

    async def evaluate(by: str) -> None:
        await hub.bus.tell(by, "module:grc", "evaluate")

    # -- the group and one subsidiary ------------------------------------------------------

    @router.get("/subsidiaries")
    async def list_subsidiaries() -> dict[str, Any]:
        subs = [s for s in governance.all_subsidiaries(hub) if s.status != "archived"]
        items = sorted((governance.summary(hub, s) for s in subs), key=lambda s: s["tool_name"].lower())
        return {"subsidiaries": items, "allowed": governance.allowed(hub),
                "pending_approvals": sum(i["pending_approvals"] for i in items),
                "archived": sum(1 for s in governance.all_subsidiaries(hub) if s.status == "archived")}

    @router.get("/subsidiaries/{tool_id}")
    async def get_subsidiary(tool_id: str) -> dict[str, Any]:
        return governance.detail(hub, current(tool_id))

    @router.post("/tools/{tool_id}/subsidiary", status_code=201)
    async def propose(tool_id: str, body: ProposeBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            sub = governance.propose(hub, tool_id, body.mode, body.goals, p.actor, body.designer)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        if sub.mode == "sidecar_only":  # no patch: the charter is drafted from the connection's catalog at once
            sub = await charters.propose_draft(hub, sub, p.actor)
        else:
            patcher = hub.agents.get("patcher")
            if callable(getattr(patcher, "on_subsidiary_propose", None)):  # the bridge patch (and its draft)
                await hub.bus.tell(p.bus_id, "patcher", "subsidiary.propose", {
                    "tool_id": tool_id, "subsidiary_id": sub.id, "mode": sub.mode, "designer": sub.designer,
                    "goals": sub.goals})
        return governance.detail(hub, sub)

    # -- the dedicated credential, enrollment, conformance, keys (administrators) ------------

    @router.put("/subsidiaries/{tool_id}/credential")
    async def set_credential(tool_id: str, body: CredentialBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            sub = governance.set_credential(hub, current(tool_id), body.secrets, p.actor)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        return governance.detail(hub, sub)

    @router.delete("/subsidiaries/{tool_id}/credential")
    async def clear_credential(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            sub = governance.clear_credential(hub, current(tool_id), p.actor)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        return governance.detail(hub, sub)

    @router.post("/subsidiaries/{tool_id}/enrollment")
    async def enrollment(tool_id: str, p: CurrentPrincipal, response: Response) -> dict[str, Any]:
        person(p)
        user = hub.auth.get_user(p.id)
        if user is None:
            raise HTTPException(403, "Sign in again.")
        try:
            code, issued = governance.issue_enrollment(hub, current(tool_id), user)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        if current(tool_id).mode == "sidecar_only":  # its bundle (a bridge patch wrote the bridge mode's one)
            bridgepatch.write_bundle(hub, current(tool_id))
        response.headers["Cache-Control"] = "no-store"
        await evaluate(p.bus_id)
        sub = current(tool_id)
        return {"code": code, "expires_at": issued.expires_at, "subsidiary_id": sub.id, "tool_id": sub.tool_id,
                "atrium_path": "/api/subsidiary/v1/", "bundle": governance.bundle_info(hub, sub),
                "note": "Shown once: the sidecar enrolls with it within 30 minutes."}

    @router.post("/subsidiaries/{tool_id}/conformance")
    async def rerun_conformance(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            result = await conformance.run(hub, current(tool_id), p.actor)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(p.bus_id)
        done = result["conformance"]
        return {"by": result["by"], "conformance": done.model_dump(mode="json") if done else None,
                "subsidiary": governance.summary(hub, current(tool_id))}

    @router.post("/subsidiaries/{tool_id}/rotate-key")
    async def rotate_key(tool_id: str, p: CurrentPrincipal, finish: bool = False) -> dict[str, Any]:
        sub = current(tool_id)
        if sub.status in ("stopped", "archived"):
            raise HTTPException(409, f"The subsidiary is {sub.status}.")
        try:
            record = keys.finish(hub, sub.id) if finish else keys.stage(hub, sub.id)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        audit.record(hub, sub.id, "key.rotate", detail={"kid": record.kid, "staged": not finish})
        governance.write_bridge_env(hub, sub)
        hub.activity(p.actor, "info", f"{'Finished rotating' if finish else 'Staged a new'} signing key of the "
                                      f"{governance.tool_name(hub, tool_id)} subsidiary"
                     + ("" if finish else ": deploy the new bridge.env (it lists both keys), then finish"),
                     subsidiary_id=sub.id)
        hub.subsidiaries.tickets.pop(sub.id, None)  # the next ticket is signed with the current key
        return {"keys": [r.public_view() for r in keys.records(hub, sub.id)],
                "bridge_keys": keys.bridge_keys(hub, sub.id), "bridge_env": governance.bridge_env(hub, sub)}

    # -- pause, resume, stop, archive -------------------------------------------------------

    @router.post("/subsidiaries/pause-all")
    async def pause_all(body: ReasonBody, p: CurrentPrincipal) -> dict[str, Any]:
        paused = governance.pause_all(hub, p.actor, body.reason)
        if paused:
            await evaluate(p.bus_id)
        return {"paused": [s.tool_id for s in paused]}

    @router.post("/subsidiaries/{tool_id}/pause")
    async def pause(tool_id: str, body: ReasonBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            sub = governance.pause(hub, current(tool_id), p.actor, body.reason)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(p.bus_id)
        return governance.summary(hub, sub)

    @router.post("/subsidiaries/{tool_id}/resume")
    async def resume(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        person(p)
        try:
            sub = governance.resume(hub, current(tool_id), p.actor)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(p.bus_id)
        return governance.summary(hub, sub)

    @router.post("/subsidiaries/{tool_id}/stop")
    async def stop(tool_id: str, body: StopBody, p: CurrentPrincipal) -> dict[str, Any]:
        person(p)
        try:
            sub = governance.stop(hub, current(tool_id), p.actor, body.confirm)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(p.bus_id)
        return governance.summary(hub, sub)

    @router.delete("/subsidiaries/{tool_id}")
    async def archive(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        sub = current(tool_id)
        if sub.status == "archived":
            raise HTTPException(409, "The subsidiary is already archived.")
        if sub.status != "stopped":
            raise HTTPException(409, "Only a stopped subsidiary can be archived: stop it first.")
        governance.archive(hub, sub, p.actor)
        await evaluate(p.bus_id)
        return governance.summary(hub, sub)

    # -- the audit trail ----------------------------------------------------------------------

    @router.get("/subsidiaries/{tool_id}/audit")
    async def audit_trail(tool_id: str, p: CurrentPrincipal, detail: bool = False, limit: int = 200,
                          before: int | None = None) -> dict[str, Any]:
        if detail and ROLE_RANK.get(p.role, 0) < ROLE_RANK["operator"]:
            raise HTTPException(403, "Viewers see the audit trail's metadata; its detail is for operators.")
        sub = current(tool_id)
        items, cursor = audit.entries(hub, sub.id, max(1, min(limit, 1000)), before)
        return {"subsidiary_id": sub.id, "entries": [audit.public(e, detail) for e in items], "before": cursor,
                "head": audit.head(hub, sub.id).model_dump(mode="json")}

    @router.post("/subsidiaries/{tool_id}/audit/verify")
    async def verify_audit(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        sub = current(tool_id)
        result = audit.verify(hub, sub.id)
        if not result["ok"]:
            governance.add_alarm(hub, sub, "audit_chain", {"problems": len(result["problems"])})
            await evaluate(p.bus_id)
        hub.activity(p.actor, "info" if result["ok"] else "error",
                     f"Verified the audit trail of the {governance.tool_name(hub, tool_id)} subsidiary: "
                     + ("intact" if result["ok"] else f"{len(result['problems'])} problem(s)"), subsidiary_id=sub.id)
        return result

    # -- reports and escalations ------------------------------------------------------------------

    def reports_of(sub: Subsidiary) -> list[Report]:
        return sorted((Report.model_validate(d) for d in hub.store.list_where(REPORTS, "subsidiary_id", sub.id)),
                      key=lambda r: r.created_at, reverse=True)

    def report_or_404(sub: Subsidiary, report_id: str) -> Report:
        doc = hub.store.get(REPORTS, report_id)
        if doc is None or doc.get("subsidiary_id") != sub.id:
            raise HTTPException(404, "Report not found")
        return Report.model_validate(doc)

    @router.get("/subsidiaries/{tool_id}/reports")
    async def reports(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        texts = ROLE_RANK.get(p.role, 0) >= ROLE_RANK["operator"]
        items = [r.model_dump(mode="json", exclude=None if texts else {"text", "findings"})
                 for r in reports_of(current(tool_id))]
        return {"reports": items, "untrusted": "Written by the subsidiary team (untrusted)", "texts": texts}

    @router.post("/subsidiaries/{tool_id}/reports/{report_id}/close")
    async def close_report(tool_id: str, report_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        sub = current(tool_id)
        report = report_or_404(sub, report_id)
        report.status, report.handled_by = "closed", p.actor
        hub.store.put(REPORTS, report.model_dump(mode="json"))
        audit.record(hub, sub.id, "report.close", detail={"report": report.id})
        hub.bus.publish("subsidiary_report", {"id": report.id, "subsidiary_id": sub.id, "status": report.status})
        return report.model_dump(mode="json")

    @router.post("/subsidiaries/{tool_id}/reports/{report_id}/promote", status_code=201)
    async def promote_report(tool_id: str, report_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        sub = current(tool_id)
        report = report_or_404(sub, report_id)
        if report.status == "promoted":
            raise HTTPException(409, "This report was promoted to a risk already.")
        severity = {"critical": 5, "warning": 4}.get(report.severity, 3)
        risk = Risk(id=new_id("r_"), title=wire.clean(report.title, 200), category="security", impact=severity,
                    description="Written by the subsidiary team (untrusted):\n" + wire.clean(report.text, 8000),
                    source=f"subsidiary:{sub.tool_id}", reviewed_at=governance.clock(hub))
        hub.save("risks", risk, "risk")
        report.status, report.handled_by = "promoted", p.actor
        hub.store.put(REPORTS, report.model_dump(mode="json"))
        audit.record(hub, sub.id, "report.promote", detail={"report": report.id, "risk": risk.id})
        hub.activity(p.actor, "info", f"Promoted a report of the {governance.tool_name(hub, tool_id)} subsidiary to "
                                      f"risk {risk.id}", subsidiary_id=sub.id, risk_id=risk.id)
        await evaluate(p.bus_id)
        return {"report": report.model_dump(mode="json"), "risk": risk.model_dump(mode="json")}

    # -- the charter, tasks and runs ---------------------------------------------------------------

    @router.put("/subsidiaries/{tool_id}/charter")
    async def amend_charter(tool_id: str, body: CharterBody, p: CurrentPrincipal) -> dict[str, Any]:
        fields = body.model_dump(mode="json", exclude_unset=True, exclude={"members"})
        try:
            result = charters.amend(hub, current(tool_id), fields, body.members, p.actor)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(p.bus_id)
        return {**result, "subsidiary": governance.detail(hub, current(tool_id))}

    @router.post("/subsidiaries/{tool_id}/tasks", status_code=202)
    async def give_task(tool_id: str, body: TaskBody, p: CurrentPrincipal) -> dict[str, Any]:
        sub = current(tool_id)
        if not governance.allowed(hub) or sub.status != "active" or sub.charter is None:
            raise HTTPException(409, {"code": "not_active",
                                      "message": f"The subsidiary is {governance.STATUS_TEXT[sub.status]}."})
        staff_ids = list(sub.charter.staff)
        agent_id = body.agent_id or next((a for a in staff_ids if a != sub.charter.panel.desk), None) \
            or (staff_ids[0] if staff_ids else None)
        defn = teams.get_def(hub, agent_id) if agent_id and agent_id in staff_ids else None
        if defn is None:
            raise HTTPException(404, "No such staff member in the charter.")
        try:
            run = agent.start(hub, sub, defn, "task", body.text, p.bus_id)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        hub.activity(p.actor, "info", f"Gave {defn.name} a task in the {governance.tool_name(hub, tool_id)} subsidiary",
                     subsidiary_id=sub.id, agent_id=defn.id, run_id=run.id)
        return {"run_id": run.id, "agent_id": defn.id, "status": "queued"}

    @router.get("/subsidiaries/{tool_id}/runs")
    async def list_runs(tool_id: str, limit: int = 50) -> dict[str, Any]:
        sub = current(tool_id)
        return {"runs": [r.public() for r in gateway.runs_of(hub, sub.id)[:max(1, min(limit, 500))]]}

    # -- the sidecar API (/api/subsidiary/v1/*) ---------------------------------------------------

    def sidecar(*, working: bool, limit: int = contract.MAX_BODY) -> Callable[[Request], Awaitable[Caller]]:
        async def dependency(request: Request) -> Caller:
            p = getattr(request.state, "principal", None)
            if p is None or p.role != "subsidiary":
                raise HTTPException(403, "Only a subsidiary's sidecar calls this API.")
            if not hub.subsidiaries.allow_call(p.id, governance.clock(hub)):
                raise HTTPException(429, {"code": "rate_limited", "message": "At most 120 requests a minute."})
            body = await read_body(request, limit)  # first: nothing below waits, so the subsidiary read is current
            doc = hub.store.get("tokens", p.id)
            token = ApiToken.model_validate(doc) if doc else None
            sub = governance.get(hub, token.subsidiary_id or "") if token else None
            if token is None or sub is None or sub.tool_id != token.tool_id:
                raise HTTPException(403, "This token belongs to no subsidiary.")
            if sub.status in ("stopped", "archived"):
                raise HTTPException(423, {"code": "stopped", "message": "The subsidiary was stopped."})
            governance.token_in_use(hub, sub, token)
            if working:
                if not governance.allowed(hub):
                    raise HTTPException(423, {"code": "disabled", "message": "Subsidiaries are switched off."})
                if sub.status == "paused":
                    raise HTTPException(423, {"code": "paused", "message": "The subsidiary is paused by Atrium."})
                version = request.headers.get(H_CHARTER)
                if version is not None and version != str(sub.charter_version):
                    raise HTTPException(409, {"code": "charter_changed", "charter_version": sub.charter_version})
            return Caller(sub, token, p, body)
        return dependency

    working, exempt = Depends(sidecar(working=True)), Depends(sidecar(working=False))
    thinking = Depends(sidecar(working=True, limit=MODEL_BODY))

    @router.post("/subsidiary/v1/enroll")
    async def enroll(request: Request) -> dict[str, Any]:
        req = parse(EnrollRequest, await read_body(request, ENROLL_BODY))
        try:
            answer = governance.enroll(hub, req, client_ip(request))
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(governance.ACTOR)
        return answer.model_dump(mode="json")

    @router.post("/subsidiary/v1/rotate")
    async def rotate(caller: Caller = exempt) -> dict[str, Any]:
        try:
            return governance.rotate_token(hub, caller.sub, caller.token).model_dump(mode="json")
        except governance.GovernanceError as exc:
            raise refused(exc) from exc

    @router.post("/subsidiary/v1/heartbeat")
    async def heartbeat(caller: Caller = exempt) -> dict[str, Any]:
        req = parse(HeartbeatRequest, caller.body)
        try:
            reply, changed = governance.heartbeat(hub, caller.sub, req)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        spool, dropped = governance.admit_spool(hub, caller.sub, req.spool, req.spool_dropped)
        if spool or dropped:  # hash-chained writes, one per entry: off the event loop
            await asyncio.to_thread(audit.claimed, hub, caller.sub.id, spool, dropped)
        sub = governance.get(hub, caller.sub.id) or caller.sub
        if governance.allowed(hub) and conformance.due(hub, sub):
            conformance.launch(hub, sub)
        if changed:
            await evaluate(governance.ACTOR)
        return reply.model_dump(mode="json")

    @router.get("/subsidiary/v1/charter")
    async def charter(request: Request, response: Response, caller: Caller = working) -> Any:
        data = governance.charter_view(hub, caller.sub).model_dump(mode="json")
        etag = '"' + hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:32] + '"'
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers={"ETag": etag})
        response.headers["ETag"] = etag
        return data

    @router.get("/subsidiary/v1/credential")
    async def credential(response: Response, caller: Caller = working) -> dict[str, Any]:
        try:
            answer = governance.credential_for_sidecar(hub, caller.sub)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        response.headers["Cache-Control"] = "no-store"
        return answer.model_dump(mode="json")

    @router.get("/subsidiary/v1/inbox")
    async def inbox(caller: Caller = exempt, cursor: int = 0, wait: int = 0) -> dict[str, Any]:
        rt, token_id = hub.subsidiaries, caller.token.id
        if cursor > 0:
            runtime.acknowledge(hub, caller.sub.id, cursor)
        messages = runtime.pending(hub, caller.sub.id, cursor)
        if not messages and wait > 0:
            if rt.polls.get(token_id, 0) >= runtime.OPEN_POLLS:
                raise HTTPException(429, {"code": "too_many_polls", "message": "At most 2 open polls per token."})
            rt.polls[token_id] = rt.polls.get(token_id, 0) + 1
            try:
                await rt.wait(caller.sub.id, min(float(wait), contract.WAIT_MAX, hub.subsidiary_config.poll_wait))
            finally:
                rt.polls[token_id] -= 1
            messages = runtime.pending(hub, caller.sub.id, cursor)
        items = runtime.delivered(hub, messages)
        return InboxResponse(messages=items, cursor=max([cursor, *(m.seq for m in items)])).model_dump(mode="json")

    @router.post("/subsidiary/v1/conformance")
    async def conformance_results(caller: Caller = working) -> dict[str, Any]:
        results = parse(ConformanceResults, caller.body)
        try:
            recorded = conformance.from_sidecar(hub, caller.sub, results)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        await evaluate(governance.ACTOR)
        return {"ok": recorded.ok, "status": (governance.get(hub, caller.sub.id) or caller.sub).status}

    # -- the work: model turns, runs, replies, action requests, hub requests, reports, events ----------

    @router.post("/subsidiary/v1/model")
    async def model_turn(caller: Caller = thinking) -> dict[str, Any]:
        req = parse(ModelRequest, caller.body)
        try:
            result = await gateway.model(hub, caller.sub, req)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        return result.model_dump(mode="json")

    @router.post("/subsidiary/v1/runs", status_code=201)
    async def create_run(caller: Caller = working) -> dict[str, Any]:
        req = parse(RunCreate, caller.body)
        try:
            return (await gateway.panel_run(hub, caller.sub, req)).model_dump(mode="json")
        except governance.GovernanceError as exc:
            raise refused(exc) from exc

    @router.post("/subsidiary/v1/runs/{run_id}/end")
    async def end_run(run_id: str, caller: Caller = exempt) -> dict[str, Any]:
        req = parse(RunEnd, caller.body)
        run = gateway.get_run(hub, run_id)
        if run is None or run.subsidiary_id != caller.sub.id:
            raise HTTPException(404, {"code": "unknown_run", "message": "No such run of this subsidiary."})
        run = gateway.end_run(hub, caller.sub, run, req.outcome, origin="claimed")
        return {"ok": True, "outcome": run.outcome}

    @router.post("/subsidiary/v1/replies")
    async def replies(caller: Caller = exempt) -> dict[str, Any]:
        req = parse(ReplyRequest, caller.body)
        try:
            run = agent.reply(hub, caller.sub, req)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        return {"ok": True, "run_id": run.id}

    @router.post("/subsidiary/v1/actions/request")
    async def request_action(caller: Caller = working) -> dict[str, Any]:
        req = parse(ActionRequest, caller.body)
        try:
            async with hub.subsidiaries.lock(caller.sub.id):
                answer = actions.request_action(hub, caller.sub, req)
        except governance.GovernanceError as exc:
            raise refused(exc) from exc
        return answer.model_dump(mode="json")

    @router.post("/subsidiary/v1/actions/{approval_id}/result")
    async def action_result(approval_id: str, caller: Caller = exempt) -> dict[str, Any]:
        req = parse(ActionResult, caller.body)
        try:
            grant = actions.record_result(hub, caller.sub, approval_id, req)
        except governance.GovernanceError as exc:
            await evaluate(governance.ACTOR)  # a reconciliation alarm fails HB-AC-8
            raise refused(exc) from exc
        if (governance.get(hub, caller.sub.id) or caller.sub).alarms[-1:] != caller.sub.alarms[-1:]:
            await evaluate(governance.ACTOR)  # recorded, but it ran after a pause: an alarm
        return {"ok": True, "status": grant.status}

    @router.post("/subsidiary/v1/actions/{approval_id}/regrant")
    async def regrant(approval_id: str, caller: Caller = working) -> dict[str, Any]:
        req = parse(RegrantRequest, caller.body)
        try:
            return (await actions.regrant(hub, caller.sub, approval_id, req)).model_dump(mode="json")
        except governance.GovernanceError as exc:
            if exc.code == "used":  # the bridge may have said the grant ran: a reconciliation alarm
                await evaluate(governance.ACTOR)
            raise refused(exc) from exc

    @router.post("/subsidiary/v1/hub-request")
    async def hub_request(caller: Caller = working) -> dict[str, Any]:
        req = parse(HubRequest, caller.body)
        try:
            return (await hubrequest.relay(hub, caller.sub, req)).model_dump(mode="json")
        except governance.GovernanceError as exc:
            raise refused(exc) from exc

    @router.post("/subsidiary/v1/reports", status_code=201)
    async def file_report(caller: Caller = working) -> dict[str, Any]:
        req = parse(ReportRequest, caller.body)
        sub = caller.sub
        if sub.charter is None or req.agent_id not in sub.charter.staff:
            raise HTTPException(403, {"code": "not_staff", "message": "Reports come from the charter's staff."})
        if req.run_id:
            run = gateway.get_run(hub, req.run_id)
            if run is None or run.subsidiary_id != sub.id or run.agent_id != req.agent_id:
                raise HTTPException(404, {"code": "unknown_run", "message": "No such run of this staff member."})
        if sum(1 for d in hub.store.list_where(REPORTS, "subsidiary_id", sub.id) if d.get("status") == "open") \
                >= OPEN_REPORTS:
            raise HTTPException(429, {"code": "too_many_reports",
                                      "message": f"At most {OPEN_REPORTS} open reports: people close them first."})
        findings = [f.model_copy(update={"title": wire.clean(f.title, 200), "evidence": wire.clean(f.evidence, 2000)})
                    for f in req.findings]
        report = Report(id=new_id("rp_"), subsidiary_id=sub.id, agent_id=req.agent_id, run_id=req.run_id,
                        kind=req.kind, severity=req.severity, title=wire.clean(req.title, 200).strip() or "Untitled",
                        text=wire.clean(req.text, 8000), findings=findings, created_at=governance.clock(hub))
        hub.store.put(REPORTS, report.model_dump(mode="json"))
        audit.record(hub, sub.id, req.kind, agent_id=req.agent_id, run_id=req.run_id, outcome=req.severity,
                     detail={"report": report.id, "findings": len(findings), "length": len(report.text)})
        hub.bus.publish("subsidiary_report", {"id": report.id, "subsidiary_id": sub.id, "kind": report.kind,
                                              "severity": report.severity, "status": report.status})
        if report.kind == "escalation":
            await hub.bus.tell(f"subsidiary:{sub.tool_id}", f"tool:{sub.tool_id}", "subsidiary.escalation",
                               {"report_id": report.id, "subsidiary_id": sub.id, "severity": report.severity})
        return {"id": report.id}

    @router.post("/subsidiary/v1/events")
    async def relay_events(caller: Caller = working) -> dict[str, Any]:
        req = parse(EventsRequest, caller.body)
        sub = caller.sub
        if sub.charter is None or not sub.charter.events.relay or sub.bridge is None:
            raise HTTPException(403, {"code": "relay_off", "message": "The charter does not relay tool events."})
        declared = set((sub.bridge.manifest.get("events") or {}).get("names") or [])
        accepted = [e for e in req.events if e.name.startswith(f"{sub.tool_id}.") and e.name in declared]
        counts: dict[str, int] = {}
        for event in accepted:
            counts[event.name] = counts.get(event.name, 0) + 1
        audit.record(hub, sub.id, "events.batch", detail={"names": dict(list(counts.items())[:20]),
                                                          "refused": len(req.events) - len(accepted)})

        async def publish() -> None:  # deliveries may wait for slow webhooks: never the sidecar
            for event in accepted:
                payload = flows.sanitize(event.payload)
                if event.cause:
                    payload = {**payload, "atrium_cause": {"jti": str(event.cause.get("jti", ""))[:64]}}
                try:
                    await hub.toolbus.publish(sub.tool_id, event.name, payload, by=f"subsidiary:{sub.tool_id}")
                except Exception as exc:  # one failed delivery must not stop the rest
                    hub.activity(governance.ACTOR, "warn", f"A tool event of the {sub.tool_id} subsidiary was not "
                                                           f"delivered ({exc.__class__.__name__})", subsidiary_id=sub.id)

        if accepted:
            hub.subsidiaries.background(publish())
        return {"ok": True, "accepted": len(accepted), "refused": len(req.events) - len(accepted)}
