"""The approval queue: where agents park actions that need a human decision."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from .models import Approval
from .store import new_id

if TYPE_CHECKING:
    from .core import Hub


class Approvals:
    def __init__(self, hub: "Hub"):
        self.hub = hub

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

    async def decide(self, approval_id: str, approve: bool, note: str | None = None) -> Approval:
        approval = self.get(approval_id)
        if approval is None:
            raise KeyError(approval_id)
        if approval.status != "pending":
            raise ValueError(f"Approval is already {approval.status}")
        approval.status = "approved" if approve else "rejected"
        approval.note = note
        approval.decided_at = time.time()
        self._save(approval)
        verb = "Approved" if approve else "Rejected"
        self.hub.activity("user", "info", f"{verb}: {approval.title}", approval_id=approval.id)
        await self.hub.bus.tell("user", approval.requested_by, "approval.decided",
                                {"approval_id": approval.id, "approved": approve, "note": note})
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
