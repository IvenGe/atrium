"""In-tool actions of sidecar staff (7.3, 4.7, 7.8): the decision table, grants, their results, regrants and the
reconciliation of what was granted with what was reported.

``request_action`` runs the decision table in order; the first failing check refuses with a message the model reads:

1. subsidiaries allowed, the subsidiary active and not held (bridge_mismatch, circuit_open, owner_disabled);
2. the run is this subsidiary's and open, its staff member asked, and may act (``gateway.check_run``);
3. the action is in the charter and the member's scope, not forbidden, and changes the tool (write or admin);
4. the parameters validate against its schema in Atrium; the body bytes are serialized once, here;
5. panel runs (user-steered): never admin risk; write only while ``subsidiary_panel_actions`` is on, and then always
   an approval;
6. budgets: approval requests a day (an auto grant counts as one) and pending approvals (429, counted for the
   circuit breaker);
7. ``auto``: a reversible write without external effect whose policy is auto, while
   ``subsidiary_tool_writes_need_approval`` is off and not from the panel - granted at once, logged as a warning;
8. otherwise an approval of kind ``subsidiary_action``, proposed by the person whose task or chat started the run (so
   they never approve it), with Atrium-computed facts: the exact params, the trigger, the taint and injection flags.

On approval the Tool Supervisor calls ``decided``: in bridge mode a grant bound to the exact approved body goes to the
sidecar's inbox; in API-only mode the Tool Supervisor carries the upsert out itself with the connection. Results come
back through ``record_result``; a result for a grant Atrium never issued is an alarm (circuit breaker, HB-AC-8 fails
for 90 days). A grant without a result five minutes after it expired becomes ``unknown`` and fails its approval.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .. import guardrails
from ..agents import teams
from ..models import Approval
from . import audit, catalog, conformance, contract, gateway, governance, keys, runtime, wire
from .governance import GovernanceError
from .models import (COLLECTIONS, ActionReply, ActionRequest, ActionResult, ActionResultMessage, DeniedMessage,
                     GrantMessage, GrantRecord, RegrantRequest, RunRecord, Subsidiary)

if TYPE_CHECKING:
    from ..core import Hub

KIND = "subsidiary_action"
GRANTS = COLLECTIONS["grants"]
UNKNOWN_AFTER = 300  # seconds after a grant's expiry without a result: "unknown"
REGRANTS = 1  # new grants an approval may get after its first one expired unused
TRIGGER_TEXT = {"schedule": "a scheduled run", "manual": "a run started by {person}", "task": "a task from {person}",
                "chat": "an Atrium chat with {person}", "panel": "a question inside the tool (user-steered)"}


def _person_name(person: str | None) -> str:
    text = str(person or "")
    return text.split(":", 1)[1] if text.startswith(("user:", "token:")) else (text or "someone")


def trigger_text(run: RunRecord) -> str:
    return TRIGGER_TEXT.get(run.trigger, run.trigger).format(person=_person_name(run.person))


def provenance(run: RunRecord) -> str:
    """What a run read before it asked (for the approval card): its taint sources in words."""
    parts = []
    for source in run.taint:
        kind, _, name = source.partition(":")
        parts.append(f"panel question {name} by a tool user (not verified by Atrium)" if kind == "panel" else name)
    return "; ".join(parts) or "nothing from the tool"


def _deny(hub: "Hub", sub: Subsidiary, req: ActionRequest, reason: str) -> ActionReply:
    gateway.book(hub, sub, denied=1)
    audit.record(hub, sub.id, "action.request", agent_id=req.agent_id[:60], run_id=req.run_id[:64],
                 action_id=req.action_id[:58], outcome="denied", detail={"reason": reason[:200]})
    return ActionReply(status="denied", reason=reason)


def grants_of(hub: "Hub", sub_id: str) -> list[GrantRecord]:
    return [GrantRecord.model_validate(d) for d in hub.store.list_where(GRANTS, "subsidiary_id", sub_id)]


def pending_actions(hub: "Hub", sub: Subsidiary) -> list[Approval]:
    return [a for a in governance.pending_approvals(hub, sub) if a.kind == KIND]


def request_action(hub: "Hub", sub: Subsidiary, req: ActionRequest) -> ActionReply:
    """The decision table (see the module docstring). 429 GovernanceError when a budget is used up."""
    if not governance.allowed(hub) or sub.status != "active" or sub.charter is None:
        return _deny(hub, sub, req, f"the subsidiary is {governance.STATUS_TEXT[sub.status]}, not active")
    if blocking := [f for f in governance.BLOCKING_FLAGS if f in sub.flags]:
        return _deny(hub, sub, req, f"the subsidiary is held: {', '.join(blocking)}")
    if not governance.proven(hub, sub):
        return _deny(hub, sub, req, "the bridge has not passed conformance")
    try:
        run, defn = gateway.check_run(hub, sub, req.run_id, req.agent_id)
    except GovernanceError as exc:
        return _deny(hub, sub, req, str(exc))
    action = sub.charter.action(req.action_id)
    scope = sub.charter.staff.get(defn.id)
    if action is None or action.policy == "forbidden" or scope is None or action.id not in scope.actions:
        return _deny(hub, sub, req, f"{req.action_id} is not one of your actions in the charter")
    if action.risk not in contract.NEEDS_GRANT:
        return _deny(hub, sub, req, f"{action.id} only reads or drafts: call it through the bridge, no request needed")
    try:
        params = contract.validate_params(action.params, req.params)
    except contract.Refused:
        return _deny(hub, sub, req, f"the parameters do not fit {action.id}'s schema")
    body = contract.body_bytes(params)
    panel = run.trigger == "panel"
    if panel and action.risk == "admin":
        return _deny(hub, sub, req, "a question asked inside the tool never leads to a high-risk change")
    if panel and not guardrails.value(hub, "subsidiary_panel_actions"):
        return _deny(hub, sub, req, "a question asked inside the tool cannot lead to a change")
    budgets = sub.charter.budgets
    day = governance.usage_day(hub, sub.id, governance.clock(hub))  # 6: before auto, which counts the same way
    if day.approval_requests >= budgets.approval_requests_per_day:
        raise gateway.over_budget(hub, sub, "approval_requests_per_day")
    if len(pending_actions(hub, sub)) >= budgets.max_pending_approvals:
        raise gateway.over_budget(hub, sub, "max_pending_approvals")
    auto = (action.risk == "write" and action.policy == "auto" and action.reversible and not action.external_effect
            and not guardrails.value(hub, "subsidiary_tool_writes_need_approval") and not panel)
    if auto:
        gateway.book(hub, sub, approval_requests=1)
        token, record = issue_grant(hub, sub, "auto", action.id, body, run_id=run.id, agent_id=defn.id)
        audit.record(hub, sub.id, "action.request", agent_id=defn.id, run_id=run.id, action_id=action.id,
                     approval_id="auto", grant_jti=record.id, body_sha256=record.body_sha256, outcome="auto",
                     taint=run.taint or None)
        hub.activity(governance.ACTOR, "warn", f"{defn.name} changed {governance.tool_name(hub, sub.tool_id)} without "
                                               f"approval ({action.id}): the charter allows it while "
                                               "subsidiary_tool_writes_need_approval is off", subsidiary_id=sub.id,
                     action_id=action.id)
        return ActionReply(status="granted", approval_id="auto", grant=token, body_b64=contract.b64u(body))
    approval = create_approval(hub, sub, run, defn.name, action, params, body, wire.clean(req.reason, 2000))
    gateway.book(hub, sub, approval_requests=1)
    return ActionReply(status="pending_approval", approval_id=approval.id)


def create_approval(hub: "Hub", sub: Subsidiary, run: RunRecord, staff_name: str, action: Any,
                    params: dict[str, Any], body: bytes, reason: str, *, notice: str = "",
                    extra: dict[str, Any] | None = None) -> Approval:
    name = governance.tool_name(hub, sub.tool_id)
    hours = float(guardrails.value(hub, "approval_expiry_hours"))
    expires = governance.clock(hub) + hours * 3600
    steered = run.trigger == "panel"
    payload: dict[str, Any] = {
        "subsidiary_id": sub.id, "tool_id": sub.tool_id, "action_id": action.id, "title": action.title,
        "risk": action.risk, "external_effect": action.external_effect, "reversible": action.reversible,
        "params": params, "body_b64": contract.b64u(body), "body_sha256": contract.sha256_hex(body),
        "agent_id": run.agent_id, "run_id": run.id, "trigger": run.trigger, "user_steered": steered,
        "taint": list(run.taint), "injection_flags": run.injection_flags, "reason_untrusted": reason,
        "charter_version": sub.charter_version, "expires_at": expires, "mode": sub.mode, **(extra or {})}
    if run.person and run.trigger in ("task", "chat", "manual"):
        payload["proposed_by"] = run.person  # whose task or chat it is: someone else approves (second person)
    lines = [f"{staff_name} wants to {action.title[:1].lower()}{action.title[1:]} in {name} ({action.id}, "
             f"{action.risk} risk{', with an external effect' if action.external_effect else ''}).", "",
             "Exact parameters (they run exactly like this, once):"]
    lines += [f"- {k}: {wire.text_of(v)[:300]}" for k, v in params.items()] or ["- (none)"]
    lines += ["", f"Asked in {trigger_text(run)}" + (" - USER-STEERED" if steered else "") + ".",
              f"The run read: {provenance(run)}."]
    if run.injection_flags:
        lines.append(f"Injection heuristics flagged {run.injection_flags} passage(s) the run read.")
    if notice:
        lines += ["", notice]
    if reason:
        lines += ["", "Reason written by the subsidiary (untrusted):", reason]
    approval = hub.approvals.create(KIND, f"{staff_name} wants to {action.title[:1].lower()}{action.title[1:]} in "
                                          f"{name}", "\n".join(lines), payload, f"tool:{sub.tool_id}")
    audit.record(hub, sub.id, "action.request", agent_id=run.agent_id, run_id=run.id, action_id=action.id,
                 approval_id=approval.id, body_sha256=payload["body_sha256"], outcome="pending",
                 taint=run.taint or None, detail={"risk": action.risk, "user_steered": steered,
                                                  "injection_flags": run.injection_flags})
    return approval


# --------------------------------------------------------------------------------------
# grants
# --------------------------------------------------------------------------------------


def issue_grant(hub: "Hub", sub: Subsidiary, approval_id: str, action_id: str, body: bytes, *, run_id: str | None,
                agent_id: str | None) -> tuple[str, GrantRecord]:
    """A single-use grant for exactly `body`, signed with the subsidiary's current key (never a second one while an
    earlier grant of the same approval is unexpired)."""
    now = int(governance.clock(hub))
    if approval_id != "auto" and any(g.approval_id == approval_id and g.status == "issued" and g.expires_at > now
                                     for g in grants_of(hub, sub.id)):
        raise GovernanceError(409, "A grant for this approval is still valid.", "grant_valid")
    token, payload = keys.issue_grant(hub, sub.id, tool=sub.tool_id, cv=sub.charter_version, act=action_id, body=body,
                                      apv=approval_id, now=now, ttl=contract.GRANT_TTL)
    record = GrantRecord(id=payload["jti"], subsidiary_id=sub.id, approval_id=approval_id, action_id=action_id,
                         body_sha256=contract.sha256_hex(body), issued_at=now, expires_at=payload["exp"],
                         run_id=run_id, agent_id=agent_id)
    hub.store.put(GRANTS, record.model_dump(mode="json"))
    audit.record(hub, sub.id, "grant.issue", agent_id=agent_id, run_id=run_id, action_id=action_id,
                 approval_id=approval_id, grant_jti=record.id, body_sha256=record.body_sha256,
                 detail={"exp": record.expires_at})
    return token, record


def _body(approval: Approval) -> bytes:
    return contract.b64u_decode(str(approval.payload.get("body_b64") or ""))


async def decided(hub: "Hub", approval: Approval, approved: bool, supervisor: Any) -> None:
    """A person decided a ``subsidiary_action`` (the Tool Supervisor relays it): a grant to the sidecar (bridge
    mode), the upsert carried out by the Tool Supervisor (API-only mode), or a ``denied`` note."""
    payload = approval.payload or {}
    sub = governance.get(hub, str(payload.get("subsidiary_id") or ""))
    if sub is None:
        return
    action_id, agent_id, run_id = str(payload.get("action_id") or ""), str(payload.get("agent_id") or ""), \
        payload.get("run_id")
    if not approved:
        audit.record(hub, sub.id, "action.decision", approval_id=approval.id, action_id=action_id, outcome="rejected")
        if sub.status not in ("stopped", "archived"):
            runtime.post(hub, sub.id, "denied", DeniedMessage(approval_id=approval.id, action_id=action_id,
                                                              run_id=run_id, agent_id=agent_id,
                                                              reason=wire.clean(approval.note or "", 500))
                         .model_dump(mode="json"))
        return
    audit.record(hub, sub.id, "action.decision", approval_id=approval.id, action_id=action_id, outcome="approved",
                 detail={"by": str(approval.decided_by or "")[:80]})
    if sub.status != "active" or not governance.allowed(hub) or any(f in sub.flags for f in governance.BLOCKING_FLAGS):
        hub.approvals.complete(approval.id, False, {"error": "the subsidiary stopped working before it could run"})
        return
    try:
        body = _body(approval)
    except ValueError:
        hub.approvals.complete(approval.id, False, {"error": "the approved body could not be read"})
        return
    if sub.mode == "bridge":
        try:
            token, record = issue_grant(hub, sub, approval.id, action_id, body, run_id=run_id, agent_id=agent_id)
        except GovernanceError as exc:
            hub.approvals.complete(approval.id, False, {"error": str(exc)})
            return
        runtime.post(hub, sub.id, "grant", GrantMessage(approval_id=approval.id, grant=token,
                                                        body_b64=contract.b64u(body), action_id=action_id,
                                                        run_id=run_id or "", agent_id=agent_id)
                     .model_dump(mode="json"), expires_at=record.expires_at)
        return
    await run_upsert(hub, sub, approval, action_id, body, supervisor)


async def run_upsert(hub: "Hub", sub: Subsidiary, approval: Approval, action_id: str, body: bytes,
                     supervisor: Any) -> None:
    """API-only mode: the Tool Supervisor carries out an approved ``records.<domain>.upsert`` with the hub's own
    connection (the sidecar never writes); the outcome reaches the staff member as an inbox ``action_result``."""
    parsed = catalog.parse(action_id)
    payload = approval.payload or {}
    ok, summary = False, "not an upsert of the catalog"
    if parsed is not None and parsed[1] == "upsert":
        record = contract.parse_body(body)
        answer = await supervisor.push_record(parsed[0], record)
        if answer.get("failure"):
            summary = f"the tool's API failed: {answer['failure'].get('message', '')}"[:500]
        else:
            ok = answer.get("action") in ("created", "updated", "skipped")
            summary = f"{answer.get('action', 'failed')}" + (f": {answer['error']}" if answer.get("error") else "")
    audit.record(hub, sub.id, "action.result", approval_id=approval.id, action_id=action_id,
                 body_sha256=contract.sha256_hex(body), outcome="executed" if ok else "failed",
                 detail={"by": f"tool:{sub.tool_id}"})
    hub.approvals.complete(approval.id, ok, {"status": "executed" if ok else "failed", "summary": summary[:500]})
    runtime.post(hub, sub.id, "action_result", ActionResultMessage(
        approval_id=approval.id, action_id=action_id, run_id=payload.get("run_id"),
        agent_id=str(payload.get("agent_id") or ""), status="executed" if ok else "failed",
        summary=wire.clean(summary, 2000)).model_dump(mode="json"))


def record_result(hub: "Hub", sub: Subsidiary, approval_id: str, res: ActionResult) -> GrantRecord:
    """POST /actions/{approval}/result. A result for a grant Atrium never issued (or for another approval, or with a
    receipt for another grant) is a reconciliation alarm: the circuit breaker opens."""
    doc = hub.store.get(GRANTS, res.grant_jti)
    grant = GrantRecord.model_validate(doc) if doc else None
    receipt_jti = (res.receipt or {}).get("jti")
    if grant is None or grant.subsidiary_id != sub.id or grant.approval_id != approval_id \
            or (receipt_jti is not None and receipt_jti != res.grant_jti):
        why = "unknown_grant" if grant is None or grant.subsidiary_id != sub.id else "grant_mismatch"
        alarm(hub, sub, why, {"grant": res.grant_jti[:64], "approval": approval_id[:64]})
        raise GovernanceError(404 if why == "unknown_grant" else 409, "Atrium issued no such grant for this approval.",
                              why)
    if grant.status in ("executed", "failed"):
        if grant.status == res.status:
            return grant  # the same result again (a retry after a lost answer)
        raise GovernanceError(409, "A different result was recorded for this grant already.", "recorded")
    if grant.status == "expired":  # replaced as unused: the receipt that said so was wrong
        alarm(hub, sub, "superseded_grant", {"grant": grant.id, "approval": approval_id,
                                             "replaced_by": str(grant.replaced_by or "")[:80]})
        raise GovernanceError(409, "That grant was replaced because it was reported unused.", "superseded")
    late = grant.revoked_at is not None and res.status == "executed" and not ran_before(res.receipt, grant.revoked_at)
    grant.status, grant.result_at = res.status, governance.clock(hub)
    grant.receipt = audit.clean_detail(res.receipt) if res.receipt else None
    grant.summary = wire.clean(res.result_summary, 2000)
    hub.store.put(GRANTS, grant.model_dump(mode="json"))
    audit.record(hub, sub.id, "grant.result", agent_id=grant.agent_id, run_id=grant.run_id, action_id=grant.action_id,
                 approval_id=approval_id, grant_jti=grant.id, body_sha256=grant.body_sha256, outcome=res.status,
                 detail={"receipt": grant.receipt})
    if approval_id != "auto":
        hub.approvals.complete(approval_id, res.status == "executed",
                               {"status": res.status, "grant_jti": grant.id, "summary": grant.summary,
                                "written_by": "the subsidiary (untrusted)"})
    if late:  # the pause, stop or kill switch did not stop this write: surfaced as an alarm
        alarm(hub, sub, "write_after_revoke", {"grant": grant.id, "approval": approval_id})
    return grant


def ran_before(receipt: dict[str, Any] | None, revoked_at: float) -> bool:
    """Whether the bridge's receipt (as the sidecar relays it) dates the write before the revocation (with the clock
    leeway: a call already under way when the subsidiary was paused)."""
    at = (receipt or {}).get("at")
    return isinstance(at, (int, float)) and not isinstance(at, bool) and at <= revoked_at + contract.CLOCK_LEEWAY


def revoke_grants(hub: "Hub", sub: Subsidiary, why: str) -> int:
    """Pause, stop or the kill switch: grants still usable at the bridge are revoked in Atrium. The bridge cannot be
    told (it accepts them until they expire), so a result showing one ran later is an alarm; none is re-granted."""
    now, count = governance.clock(hub), 0
    for grant in grants_of(hub, sub.id):
        if grant.status == "issued" and grant.revoked_at is None and grant.expires_at + contract.CLOCK_LEEWAY > now:
            grant.revoked_at = now
            hub.store.put(GRANTS, grant.model_dump(mode="json"))
            count += 1
    if count:
        audit.record(hub, sub.id, "grant.revoke", detail={"grants": count, "why": why[:100]})
    return count


def _regrantable(hub: "Hub", sub: Subsidiary, approval_id: str, req: RegrantRequest) -> tuple[Approval, GrantRecord]:
    """The checks of 4.7 that need nobody's word: the approval still approved, valid and not yet re-granted, the old
    grant issued, unrevoked and past the bridge's acceptance (exp + leeway), but not yet reconciled as unknown."""
    approval = hub.approvals.get(approval_id)
    if approval is None or approval.kind != KIND or (approval.payload or {}).get("subsidiary_id") != sub.id:
        raise GovernanceError(404, "No such request of this subsidiary.", "unknown_approval")
    if approval.status != "approved":
        raise GovernanceError(409, f"The request is {approval.status}.", "not_approved")
    doc = hub.store.get(GRANTS, req.old_jti)
    old = GrantRecord.model_validate(doc) if doc else None
    now = governance.clock(hub)
    if old is None or old.subsidiary_id != sub.id or old.approval_id != approval_id or old.status != "issued" \
            or old.revoked_at is not None or now > old.expires_at + UNKNOWN_AFTER:
        raise GovernanceError(409, "That grant cannot be replaced.", "not_regrantable")
    if now < old.expires_at + contract.CLOCK_LEEWAY:  # the bridge accepts it until exp + leeway
        raise GovernanceError(409, "That grant may still be used: send it, or ask again once it expired.",
                              "grant_valid")
    if (req.receipt or {}).get("status") != "unused":
        raise GovernanceError(409, "Only a grant the bridge reports unused is replaced.", "used")
    if sum(1 for g in grants_of(hub, sub.id) if g.approval_id == approval_id) > REGRANTS:
        raise GovernanceError(409, "This approval was re-granted already: the staff member asks again.",
                              "regrant_limit")
    try:
        governance.check_action_decision(hub, approval, True)  # also the approval's own expiry
    except ValueError as exc:
        raise GovernanceError(409, str(exc), "no_longer_valid") from None
    return approval, old


def _supersede(hub: "Hub", old: GrantRecord, by: str) -> None:
    old.status, old.replaced_by = "expired", by
    hub.store.put(GRANTS, old.model_dump(mode="json"))


async def regrant(hub: "Hub", sub: Subsidiary, approval_id: str, req: RegrantRequest) -> ActionReply:
    """4.7: a new grant for an approved request whose grant expired unused, once per approval. The sidecar's receipt
    is only its word: Atrium asks the bridge itself (observed). A bridge that says the grant ran is a reconciliation
    alarm; when Atrium cannot reach the bridge, a person decides again (a new approval with the same body)."""
    _regrantable(hub, sub, approval_id, req)
    observed = await conformance.bridge_receipt(hub, sub, req.old_jti)
    async with hub.subsidiaries.lock(sub.id):
        approval, old = _regrantable(hub, sub, approval_id, req)  # nothing replaced it while the bridge answered
        if observed is None:
            return reapprove(hub, sub, approval, old)
        status, bridge_now = observed
        audit.record(hub, sub.id, "grant.receipt", approval_id=approval_id, grant_jti=old.id, outcome=status,
                     detail={"bridge_time": bridge_now})
        if status != "unused":  # it ran (an alarm: the sidecar said otherwise) or may have run
            if status != "unknown":
                alarm(hub, sub, "receipt_mismatch", {"grant": old.id, "approval": approval_id, "bridge": status})
            raise GovernanceError(409, "The bridge says this grant was used.", "used")
        if bridge_now is None or bridge_now < old.expires_at + contract.CLOCK_LEEWAY:
            raise GovernanceError(409, "The bridge's clock still accepts that grant: ask again once it expired.",
                                  "grant_valid")
        body = _body(approval)
        token, record = issue_grant(hub, sub, approval_id, old.action_id, body, run_id=old.run_id,
                                    agent_id=old.agent_id)
        _supersede(hub, old, record.id)
        audit.record(hub, sub.id, "grant.regrant", approval_id=approval_id, grant_jti=record.id,
                     detail={"replaces": old.id, "receipt": "observed"})
        return ActionReply(status="granted", approval_id=approval_id, grant=token, body_b64=contract.b64u(body))


def reapprove(hub: "Hub", sub: Subsidiary, approval: Approval, old: GrantRecord) -> ActionReply:
    """A regrant Atrium cannot check with the bridge: the old approval fails and a person decides the same body again,
    told that it may have run already."""
    payload = approval.payload or {}
    assert sub.charter is not None  # check_action_decision: active, with the charter the approval was asked under
    action = sub.charter.action(old.action_id)
    run = gateway.get_run(hub, str(payload.get("run_id") or ""))
    defn = teams.get_def(hub, str(payload.get("agent_id") or ""))
    if action is None or run is None or defn is None:
        raise GovernanceError(409, "The request can no longer be asked again.", "no_longer_valid")
    note = (f"Asked again: the grant of approval {approval.id} expired. The subsidiary says it was never used, which "
            "Atrium could not check with the tool. If it did run, approving this runs it a second time.")
    again = create_approval(hub, sub, run, defn.name, action, dict(payload.get("params") or {}), _body(approval), "",
                            notice=note, extra={"regrant_of": approval.id, "replaces_grant": old.id})
    _supersede(hub, old, f"approval:{again.id}")
    hub.approvals.complete(approval.id, False, {"error": "not executed in time: asked again", "grant_jti": old.id,
                                                "asked_again": again.id})
    audit.record(hub, sub.id, "grant.reapprove", approval_id=approval.id, grant_jti=old.id,
                 detail={"approval": again.id, "receipt": "claimed"})
    return ActionReply(status="pending_approval", approval_id=again.id,
                       reason="Atrium could not check the grant with the tool: a person decides again")


# --------------------------------------------------------------------------------------
# the tick: reconciliation and expiry
# --------------------------------------------------------------------------------------


def alarm(hub: "Hub", sub: Subsidiary, kind: str, detail: dict[str, Any]) -> None:
    """A reconciliation alarm: kept 90 days (HB-AC-8 fails), a critical escalation, the circuit breaker."""
    sub = governance.add_alarm(hub, sub, kind, detail)
    hub.activity(governance.ACTOR, "error", f"Critical: the {governance.tool_name(hub, sub.tool_id)} sidecar reported "
                                            f"a result Atrium cannot match ({kind})", subsidiary_id=sub.id)
    if "circuit_open" not in sub.flags:
        governance.open_circuit(hub, sub, f"reconciliation alarm ({kind})")


def reconcile(hub: "Hub", sub: Subsidiary, now: float) -> int:
    """Grants with no result five minutes after they expired become unknown (a warning); their approvals fail:
    not executed in time."""
    count = 0
    for grant in grants_of(hub, sub.id):
        if grant.status != "issued" or now <= grant.expires_at + UNKNOWN_AFTER:
            continue
        grant.status = "unknown"
        hub.store.put(GRANTS, grant.model_dump(mode="json"))
        audit.record(hub, sub.id, "grant.expire", approval_id=grant.approval_id, grant_jti=grant.id,
                     action_id=grant.action_id, outcome="unknown")
        hub.activity(governance.ACTOR, "warn", f"A grant of the {governance.tool_name(hub, sub.tool_id)} subsidiary "
                                               f"({grant.action_id}) expired without a result", subsidiary_id=sub.id)
        approval = hub.approvals.get(grant.approval_id) if grant.approval_id != "auto" else None
        if approval is not None and approval.status == "approved":
            hub.approvals.complete(grant.approval_id, False, {"error": "not executed in time", "grant_jti": grant.id})
        count += 1
    return count


def expire_requests(hub: "Hub", sub: Subsidiary, now: float) -> int:
    """Pending in-tool requests past their expiry are withdrawn (they free the pending-approvals budget)."""
    count = 0
    for approval in pending_actions(hub, sub):
        expires = (approval.payload or {}).get("expires_at")
        if isinstance(expires, (int, float)) and now > expires:
            count += hub.approvals.withdraw(approval.id, "Expired: nobody decided it in time", governance.ACTOR,
                                            verb="Expired") is not None
    return count


def notes_for(hub: "Hub", sub: Subsidiary, agent_id: str, since: float) -> list[str]:
    """Outcomes of a staff member's requests decided since its last run, for the start of its next one."""
    notes = []
    for approval in hub.approvals.list():
        payload = approval.payload or {}
        if approval.kind != KIND or payload.get("subsidiary_id") != sub.id or payload.get("agent_id") != agent_id \
                or approval.status == "pending" or (approval.decided_at or 0) <= since:
            continue
        outcome = {"approved": "was approved and is being carried out", "rejected": "was not approved",
                   "done": "was approved and carried out", "failed": "was approved but failed in the tool"}
        notes.append(f"Your request {approval.id} ({payload.get('action_id')}) {outcome[approval.status]}.")
    return notes[-10:]
