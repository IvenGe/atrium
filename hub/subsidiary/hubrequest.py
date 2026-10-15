"""Hub requests of sidecar staff (7.2): ``POST /api/subsidiary/v1/hub-request {run_id, agent_id, tool, args}``.

A staff member reaches the hub only through ``toolkit.SIDECAR_HUB_TOOLS`` (get_tool, tool_health, data_flows,
propose_patches, request_code_patch) that its charter scope also lists - never from a panel run. The relay forces
``tool_id`` to the subsidiary's own tool and refuses any other value, and runs the tool in Atrium as the staff member
(``agent:<slug>``) with its clamped permissions, so ``guardrails.effective_autonomy`` answers "manual" for it: every
patch it asks for waits for a person's approval. Approvals it causes count against ``approval_requests_per_day``.

A tool that takes longer than a few seconds (a patch the Patch Agent designs) goes on in the background; the answer
says so, and its approval appears in Approvals.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

from ..agents import teams, toolkit
from . import audit, gateway, governance, wire
from .governance import GovernanceError
from .models import HubReply, HubRequest, Subsidiary

if TYPE_CHECKING:
    from ..core import Hub

WAIT = 10.0  # seconds a hub request is answered within; longer ones continue in the background
APPROVING = frozenset({"propose_patches", "request_code_patch"})  # tools whose requests become approvals


def _book_new(hub: "Hub", sub: Subsidiary, before: set[str], agent_id: str) -> int:
    """Approvals the request caused (asked by the staff member, or about the subsidiary's tool) count against the
    subsidiary's daily approval requests."""
    new = [a for a in hub.approvals.list() if a.id not in before
           and (a.requested_by == agent_id or (a.payload or {}).get("tool_id") == sub.tool_id)]
    if new:
        gateway.book(hub, sub, approval_requests=len(new))
    return len(new)


async def relay(hub: "Hub", sub: Subsidiary, req: HubRequest) -> HubReply:
    run, defn = gateway.check_run(hub, sub, req.run_id, req.agent_id)
    assert sub.charter is not None
    scope = sub.charter.staff[defn.id]
    if run.trigger == "panel":
        return HubReply(ok=False, error="a question asked inside the tool has no hub tools")
    if req.tool not in toolkit.SIDECAR_HUB_TOOLS or req.tool not in scope.hub_tools:
        audit.record(hub, sub.id, "hub.request", agent_id=defn.id, run_id=run.id, outcome="refused",
                     detail={"tool": req.tool[:60]})
        return HubReply(ok=False, error=f"{req.tool[:60]} is not one of your hub tools")
    spec = toolkit.TOOLS[req.tool]
    args: dict[str, Any] = dict(req.args)
    asked = str(args.get("tool_id") or "")
    if asked and asked != sub.tool_id:
        return HubReply(ok=False, error=f"you work for {governance.tool_name(hub, sub.tool_id)} only")
    if "tool_id" in spec.properties:
        args["tool_id"] = sub.tool_id  # forced: get_tool does not scope itself
    args = {k: v for k, v in args.items() if k in spec.properties}
    if req.tool in APPROVING:
        budgets = sub.charter.budgets
        if governance.usage_day(hub, sub.id, governance.clock(hub)).approval_requests >= \
                budgets.approval_requests_per_day:
            raise gateway.over_budget(hub, sub, "approval_requests_per_day")
        if len(governance.pending_approvals(hub, sub)) >= budgets.max_pending_approvals:
            raise gateway.over_budget(hub, sub, "max_pending_approvals")
    agent = hub.agents.get(defn.id)
    if agent is None:
        raise GovernanceError(409, f"{defn.name} is not running in Atrium.", "not_running")
    ctx = toolkit.ToolContext(hub, agent, frozenset(teams.effective_permissions(hub, defn)), sub.tool_id, None)
    before = {a.id for a in hub.approvals.list()}
    task = asyncio.get_running_loop().create_task(toolkit.execute(ctx, req.tool, args))
    done, _ = await asyncio.wait({task}, timeout=WAIT)
    if not done:
        task.add_done_callback(lambda _t: _book_new(hub, sub, before, defn.id))
        audit.record(hub, sub.id, "hub.request", agent_id=defn.id, run_id=run.id, outcome="working",
                     detail={"tool": req.tool})
        return HubReply(ok=True, result={"status": "working", "note": "The request continues in Atrium; anything that "
                                         "needs approval appears in Approvals there."})
    approvals = _book_new(hub, sub, before, defn.id)
    try:
        result = task.result()
    except Exception as exc:  # the model reads why; nothing of the hub's state leaks beyond the message
        audit.record(hub, sub.id, "hub.request", agent_id=defn.id, run_id=run.id, outcome="failed",
                     detail={"tool": req.tool, "approvals": approvals})
        return HubReply(ok=False, error=wire.clean(str(exc) or exc.__class__.__name__, 500))
    audit.record(hub, sub.id, "hub.request", agent_id=defn.id, run_id=run.id, outcome="ok",
                 detail={"tool": req.tool, "approvals": approvals})
    return HubReply(ok=True, result=result)
