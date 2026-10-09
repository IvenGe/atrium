"""The approval queue: where agents park actions that need a human decision."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Callable

from .models import Approval
from .store import new_id

if TYPE_CHECKING:
    from .core import Hub


class Approvals:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        # kind -> check run before a decision is recorded; raising ValueError refuses it (e.g. a self-patch whose
        # tests failed cannot be approved)
        self.guards: dict[str, Callable[[Approval, bool], None]] = {}

    def create(self, kind: str, title: str, detail: str, payload: dict[str, Any], requested_by: str) -> Approval:
        approval = Approval(id=new_id("ap_"), kind=kind, title=title, detail=detail, payload=payload,  # type: ignore[arg-type]
                            requested_by=requested_by)
        self._save(approval)
        self.hub.activity(requested_by, "warn", f"Awaiting approval: {title}", approval_id=approval.id)
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
        if approval.status != "pending":
            raise ValueError(f"Approval is already {approval.status}")
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

    def withdraw(self, approval_id: str, note: str, actor: str) -> Approval | None:
        """Reject a pending approval on the requester's side because a newer request replaces it."""
        approval = self.get(approval_id)
        if approval is None or approval.status != "pending":
            return None
        approval.status, approval.note = "rejected", note
        approval.decided_at, approval.decided_by = time.time(), actor
        self._save(approval)
        self.hub.activity(actor, "info", f"Superseded: {approval.title}", approval_id=approval.id)
        return approval

    def complete(self, approval_id: str, ok: bool, result: dict[str, Any]) -> None:
        approval = self.get(approval_id)
        if approval is None:
            return
        approval.status = "done" if ok else "failed"
        approval.result = result
        self._save(approval)

    def _save(self, approval: Approval) -> None:
        data = approval.model_dump(mode="json")
        self.hub.store.put("approvals", data)
        self.hub.bus.publish("approval", data)
