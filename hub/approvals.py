"""The approval queue: where agents park actions that need a human decision.

Two rules hold for every decision:
- Second person: an approval whose payload records ``proposed_by`` (the person who proposed it), and every self-patch
  and device change, cannot be APPROVED by that same person while the second-person guardrail for it is on -
  ``device_changes_need_second_person`` (default on) for kind ``firewall``, ``approvals_need_second_person`` (default
  off) for everything else - and always for a subsidiary's charters, in-tool actions and bridge patches. Refused
  with ``DecisionRefused`` (code ``same_person``; the API answers 403). Rejecting
  one's own proposal stays possible. An API token counts as the person who created it (``identities``), so an
  administrator cannot approve their own proposal with a token they made; device changes are approved by people
  only (the API answers 403 ``person_required`` to a token).
- Expiry: an approval whose payload carries ``expires_at`` can no longer be approved after that time (ValueError).
  Device changes and self-patches set it (guardrail ``approval_expiry_hours``); their owners also bind the approval
  to what was reviewed (the device revision and the operations' hash, the self-patch's commit) and check it again
  before acting.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable

from .models import Approval
from .store import new_id

if TYPE_CHECKING:
    from .core import Hub


class DecisionRefused(ValueError):
    """A decision this person may not make (``code``: same_person); the API answers 403. Routes that settle an
    approval on the side (enabling a proposed flow or extension in its list) run ``precheck`` before they change
    anything, so a refused decision never leaves the proposal enabled with its approval still pending."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


TOKEN_CHAIN = 5  # how many "token created by token" links identities() follows


def person(actor: str | None) -> str | None:
    """The person (or API token) a stored actor name stands for: "user:alice" and "alice" are the person alice,
    "token:ci" is the API token ci (``identities`` adds whoever created it); other prefixed ids ("module:network",
    "agent:x", "tool:y") are agents - nobody. A bare name is always a person: "operator" or "system" are valid user
    names, so agents' bare bus ids are never recorded as a proposer or decider - read bus senders with
    ``sender_person``."""
    text = str(actor or "").strip()
    if text.startswith("user:"):
        return text[5:] or None
    if text.startswith("token:"):
        return text if text[6:] else None
    return None if not text or ":" in text else text


def sender_person(sender: str | None) -> str | None:
    """The person behind a bus sender: only "user:<name>" and "token:<name>" are people; every other sender
    ("supervisor", "operator", "module:network", "agent:x") is an agent (None)."""
    text = str(sender or "").strip()
    return person(text) if text.startswith(("user:", "token:")) else None


def identities(hub: "Hub", actor: str | None) -> set[str]:
    """Everyone an actor stands for in the second-person rule: the person, and for an API token also whoever created
    it (``ApiToken.created_by``; a token created with another token is followed back to a person) - a token an
    administrator created acts for that administrator (S4)."""
    out: set[str] = set()
    current = person(actor)
    tokens: dict[str, Any] | None = None
    while current and current not in out and len(out) < TOKEN_CHAIN:
        out.add(current)
        if not current.startswith("token:"):
            break
        tokens = tokens if tokens is not None else {t.name: t for t in hub.auth.tokens()}
        token = tokens.get(current[6:])
        owner = hub.auth.get_user(token.owner_id) if token is not None and token.owner_id else None
        if owner is not None:  # the account the token acts for (F2), even when the creating token was revoked
            out.add(owner.username)
        current = person(token.created_by) if token is not None else None
    return out


class Approvals:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        # kind -> check run before a decision is recorded; raising ValueError refuses it (e.g. a self-patch whose
        # tests failed cannot be approved)
        self.guards: dict[str, Callable[[Approval, bool], None]] = {}

    def create(self, kind: str, title: str, detail: str, payload: dict[str, Any], requested_by: str) -> Approval:
        if payload.get("proposed_by"):  # who that is as of now (still counts when their API token is revoked later)
            payload = {**payload, "proposer_ids": sorted(identities(self.hub, payload["proposed_by"]))}
        approval = Approval(id=new_id("ap_"), kind=kind, title=title, detail=detail, payload=payload,  # type: ignore[arg-type]
                            requested_by=requested_by)
        self._save(approval)
        from .agents import notify  # "Awaiting approval: ..." - a notification when the agent that asks wants one

        notify.approval_requested(self.hub, approval)
        return approval

    def get(self, approval_id: str) -> Approval | None:
        doc = self.hub.store.get("approvals", approval_id)
        return Approval.model_validate(doc) if doc else None

    def list(self, status: str | None = None) -> list[Approval]:
        items = [Approval.model_validate(d) for d in self.hub.store.list("approvals")]
        if status:
            items = [a for a in items if a.status == status]
        return sorted(items, key=lambda a: a.created_at, reverse=True)

    def pending_count(self) -> int:
        return sum(1 for a in self.list() if a.status == "pending")

    async def decide(self, approval_id: str, approve: bool, note: str | None, actor: str,
                     sender: str | None = None) -> Approval:
        """Record a person's (or token's) decision; `sender` is their bus id, defaulting to the actor."""
        approval = self.get(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        self.precheck(approval, approve, actor)
        guard = self.guards.get(approval.kind)
        if guard is not None:
            guard(approval, approve)
        approval.status = "approved" if approve else "rejected"
        approval.note = note
        approval.decided_at = time.time()
        approval.decided_by = actor
        self._save(approval)
        verb = "Approved" if approve else "Rejected"
        self.hub.activity(actor, "info", f"{verb}: {approval.title}", approval_id=approval.id)
        await self.hub.bus.tell(sender or actor, approval.requested_by, "approval.decided",
                                {"approval_id": approval.id, "approved": approve, "note": note, "decided_by": actor})
        return approval

    def second_person_required(self, approval: Approval) -> bool:
        from . import guardrails

        if approval.kind == "firewall":
            return bool(guardrails.value(self.hub, "device_changes_need_second_person"))
        if approval.kind in ("subsidiary_charter", "subsidiary_action") or (
                approval.kind == "patch" and (approval.payload or {}).get("strategy") == "atrium_bridge"):
            return True  # a subsidiary's proposer never approves their own request (whatever the guardrail says)
        if approval.kind == "self_patch" or approval.payload.get("proposed_by"):
            return bool(guardrails.value(self.hub, "approvals_need_second_person"))
        return False

    def precheck(self, approval: Approval, approve: bool, actor: str) -> None:
        """What ``decide`` checks before recording anything (also for callers that change the proposed object first,
        such as enabling a proposed flow in its list): still pending, the second-person rule, not expired."""
        if approval.status != "pending":
            raise ValueError(f"Approval is already {approval.status}")
        if approve:
            self.check_second_person(approval, actor)
            expires = approval.payload.get("expires_at")
            if isinstance(expires, (int, float)) and time.time() > expires:
                raise ValueError("This approval expired at " + time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(expires))
                                 + " - it can only be rejected; propose the change again")

    def proposers(self, approval: Approval) -> set[str]:
        """Who proposed it: recorded when it was created, and resolved again now (``identities``)."""
        recorded = {str(i) for i in approval.payload.get("proposer_ids") or [] if person(str(i))}
        return recorded | identities(self.hub, approval.payload.get("proposed_by"))

    def check_second_person(self, approval: Approval, actor: str) -> None:
        """DecisionRefused when `actor` - or the person behind their API token - proposed this approval and a second
        person must decide it."""
        if self.second_person_required(approval) and self.proposers(approval) & identities(self.hub, actor):
            raise DecisionRefused("same_person", "You proposed this, so someone else must approve it (second-person "
                                                 "rule; an API token you created counts as you) - you can still "
                                                 "reject it")

    def approve_automatically(self, approval_id: str, actor: str, note: str) -> Approval | None:
        """Record an approval a guardrail lets an agent skip (logged as a warning with the reason)."""
        approval = self.get(approval_id)
        if approval is None or approval.status != "pending":
            return None
        approval.status, approval.note = "approved", note
        approval.decided_at, approval.decided_by = time.time(), actor
        self._save(approval)
        self.hub.activity(actor, "warn", f"Approved automatically: {approval.title} - {note}", approval_id=approval.id)
        return approval

    def withdraw(self, approval_id: str, note: str, actor: str, verb: str = "Superseded") -> Approval | None:
        """Reject a pending approval on the requester's side because a newer request replaces it (or, with another
        `verb`, because it was withdrawn or expired)."""
        approval = self.get(approval_id)
        if approval is None or approval.status != "pending":
            return None
        approval.status, approval.note = "rejected", note
        approval.decided_at, approval.decided_by = time.time(), actor
        self._save(approval)
        self.hub.activity(actor, "info", f"{verb}: {approval.title}", approval_id=approval.id)
        return approval

    def complete(self, approval_id: str, ok: bool, result: dict[str, Any]) -> None:
        """Record what carrying out an approved action did: "done" or "failed". "done" is final - a later or
        concurrent attempt (e.g. applying a merged self-patch again) never turns it into a failure (review F24)."""
        approval = self.get(approval_id)
        if approval is None or approval.status == "done":
            return
        approval.status = "done" if ok else "failed"
        approval.result = result
        self._save(approval)

    def _save(self, approval: Approval) -> None:
        data = approval.model_dump(mode="json")
        self.hub.store.put("approvals", data)
        self.hub.bus.publish("approval", data)
