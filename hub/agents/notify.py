"""Escalations and notifications of agents (round4-agents-spec.md 9).

Escalation: a chat agent (the Hub Supervisor, custom agents) with its `escalate` tool switched on
(AgentConfig.escalation.tool) asks a person instead of deciding itself. That creates an approval of kind
"agent_escalation", which operators decide: Approve = "Acknowledge", Reject = "Dismiss", each with an optional note.
The note waits in the agent's inbox (a custom agent's definition, a core agent's "agents" document; the last
INBOX_KEEP) and is added to the context of its next chat turn or run, then cleared. At most
`escalation.max_per_day` escalations per agent and UTC day: beyond that the tool says so, so injected text cannot
flood the approval queue.

Notifications: an event of an agent (run_failed, budget_reached, escalation, approval_requested, run_done) is an
activity entry - the existing one of that event - with `data.event`, `data.severity` and, when the agent's
`notify.events` include it, `data.notify` = its targets ("role:admin", "role:operator", "user:<id>"). The targets only
decide whom the Agents page's "Needs attention" strip highlights: the activity log reaches every signed-in person, so
a notification carries the agent id, the event, a severity and a masked summary - nothing a viewer may not read. With
`notify.toolbus` on it is also published on the tool bus as "hub.agent.<event>" to the integrated tools that listen.

A custom agent whose runs fail `escalation.failed_runs` times in a row gets its schedule paused (with
`escalation.pause_schedule`); an administrator resumes it (POST /api/agents/{id}/schedule/resume). A run skipped for
a budget or rate limit is not a failure.
"""

from __future__ import annotations

import asyncio
import time
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from ..bus import TRACE
from ..llm.usage import day_of
from ..models import AgentConfig, Approval
from . import teams

if TYPE_CHECKING:
    from ..auth.service import Principal
    from ..core import Hub
    from .base import BaseAgent

KIND = "agent_escalation"
INBOX_KEEP = 10
SUMMARY_MAX, TITLE_MAX, TOOLBUS_SUMMARY = 2000, 120, 500
SEVERITIES = ("info", "warning", "critical")
NEEDS = ("decision", "information")
EVENTS = {
    "run_failed": "A run failed",
    "budget_reached": "A budget is reached",
    "escalation": "It escalates to a person",
    "approval_requested": "It asks for an approval",
    "run_done": "A run finished",
}
SEVERITY = {"run_failed": "warning", "budget_reached": "warning", "escalation": "warning",
            "approval_requested": "info", "run_done": "info"}
ROLE_TARGETS = {"role:admin": "Administrators", "role:operator": "Operators (and administrators)"}
LIMIT_REACHED = "escalation limit reached - put it in your reply instead"
_tasks: set[asyncio.Task[Any]] = set()  # tool bus deliveries in flight
_limit_logged: set[tuple[str, str]] = set()  # (day, agent id): "limit reached" is logged once a day


def chats(agent: "BaseAgent") -> bool:
    return agent.id == "supervisor" or agent.kind == "custom"


def events_for(agent: "BaseAgent") -> list[str]:
    """The events an agent can have: custom agents all; the Hub Supervisor no runs; the other model-using agents
    budgets and approvals; agents without a model only the approvals they ask for."""
    if agent.kind == "custom":
        return list(EVENTS)
    if agent.id == "supervisor":
        return ["escalation", "budget_reached", "approval_requested"]
    if agent.uses_llm:
        return ["budget_reached", "approval_requested"]
    return ["approval_requested"]


def config_of(hub: "Hub", agent_id: str) -> AgentConfig | None:
    """The agent's settings, or None when `agent_id` is no agent (a person, "hub")."""
    if not agent_id or getattr(hub, "agents", None) is None or hub.agents.get(agent_id) is None:
        return None
    return hub.llm.config(agent_id)


def check_targets(hub: "Hub", targets: list[str]) -> list[str]:
    """The notification targets, checked and without duplicates; ValueError names the first unknown one."""
    out: list[str] = []
    for raw in targets:
        target = str(raw).strip()
        if target in ROLE_TARGETS:
            pass
        elif target.startswith("user:") and hub.auth.get_user(target[5:]) is not None:
            pass
        elif target.startswith("user:"):
            raise ValueError(f"Notification targets: no account with the id '{target[5:][:60]}'")
        else:
            raise ValueError(f"Notification targets: '{target[:60]}' is not role:admin, role:operator or user:<id>")
        if target not in out:
            out.append(target)
    return out


def target_labels(hub: "Hub", targets: list[str]) -> list[dict[str, str]]:
    """[{id, label}] of targets: role names, account names ("(removed account)" when it is gone)."""
    out = []
    for target in targets:
        if target in ROLE_TARGETS:
            out.append({"id": target, "label": ROLE_TARGETS[target]})
        elif target.startswith("user:"):
            user = hub.auth.get_user(target[5:])
            out.append({"id": target, "label": user.username if user else "(removed account)"})
    return out


def for_principal(targets: list[str] | None, principal: "Principal") -> bool:
    """Whether a notification's targets name this person: their account, or a role they hold (administrators are
    operators too)."""
    if not targets:
        return False
    user_id = principal.id if principal.kind == "user" else principal.owner_id
    roles = {"role:admin"} if principal.role == "admin" else set()
    if principal.role in ("admin", "operator"):
        roles.add("role:operator")
    return any(t in roles or (user_id and t == f"user:{user_id}") for t in targets)


def fields(hub: "Hub", agent_id: str, event: str, severity: str | None = None) -> dict[str, Any]:
    """The data an activity entry of an agent event carries: the event, its severity and - when the agent's
    notifications include it - the targets. {} for anything that is not an agent."""
    config = config_of(hub, agent_id)
    if config is None:
        return {}
    out: dict[str, Any] = {"event": event, "severity": severity or SEVERITY.get(event, "info")}
    if event in config.notify.events:
        out["notify"] = list(config.notify.targets)
    return out


def emit(hub: "Hub", agent_id: str, event: str, /, *, level: str, text: str, actor: str | None = None,
         severity: str | None = None, summary: str | None = None, **data: Any) -> dict[str, Any]:
    """Write the activity entry of an agent event (actor: the agent, unless given) as a notification when the agent
    asks for one, and publish it on the tool bus when that is switched on for the agent."""
    extra = fields(hub, agent_id, event, severity)
    if extra:  # an agent's event (a person's approval request carries no agent id)
        data = {"agent_id": agent_id, **data}
    entry = hub.activity(actor or agent_id, level, text, **(extra or {"event": event}), **data)
    config = config_of(hub, agent_id)
    if config is not None and config.notify.toolbus and "notify" in extra:
        relay(hub, agent_id, event, extra["severity"], summary if summary is not None else text)
    return entry


def toolbus_payload(hub: "Hub", agent_id: str, event: str, severity: str, summary: str) -> dict[str, Any]:
    agent = hub.agents.get(agent_id)
    text = hub.llm.mask.text(str(summary or ""))
    trace = TRACE.get()
    if trace is not None and trace.private is not None:  # asked in a person's private chat: no quote of it leaves
        text = trace.private.quotes.scrub(text)
    return {"agent_id": agent_id, "agent_name": agent.name if agent else agent_id, "event": event,
            "severity": severity, "summary": text[:TOOLBUS_SUMMARY],
            "link": f"{hub.settings.public_url}/#/agents/{quote(agent_id, safe='')}/settings", "at": time.time()}


def relay(hub: "Hub", agent_id: str, event: str, severity: str, summary: str) -> None:
    """Publish "hub.agent.<event>" on the tool bus in the background (a slow tool never holds up the agent)."""
    payload = toolbus_payload(hub, agent_id, event, severity, summary)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:  # no event loop (a synchronous caller): nothing to deliver with
        return
    task = loop.create_task(hub.toolbus.publish("hub", f"hub.agent.{event}", payload, by=agent_id))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def listeners(hub: "Hub") -> list[dict[str, str]]:
    """The integrated tools that listen for agent events (their names, never their webhook URLs)."""
    out = []
    for tool in hub.tools():
        listens = tool.manifest.events.listens if tool.manifest else []
        if any(fnmatch(f"hub.agent.{e}", p) for e in EVENTS for p in listens):
            out.append({"id": tool.id, "name": tool.name})
    return out


# -- approvals the agents ask for ----------------------------------------------------------------


def approval_requested(hub: "Hub", approval: Approval) -> dict[str, Any]:
    """The activity entry of a new approval ("Awaiting approval: <title>"), as a notification of the agent that asked
    for it (an escalation is the agent's "escalation" event)."""
    escalation = approval.kind == KIND
    event = "escalation" if escalation else "approval_requested"
    severity = str(approval.payload.get("severity") or "warning") if escalation else None
    return emit(hub, approval.requested_by, event, level="warn", text=f"Awaiting approval: {approval.title}",
                actor=approval.requested_by, severity=severity,
                summary=approval.detail if escalation else approval.title, approval_id=approval.id)


# -- escalations ---------------------------------------------------------------------------------


def escalations(hub: "Hub", agent_id: str | None = None, status: str | None = None) -> list[Approval]:
    return [a for a in hub.approvals.list(status) if a.kind == KIND
            and (agent_id is None or a.payload.get("agent_id") == agent_id)]


def today(hub: "Hub", agent_id: str, now: float | None = None) -> int:
    """How many escalations the agent made this UTC day."""
    day = day_of(now or time.time())
    return sum(1 for a in escalations(hub, agent_id) if day_of(a.created_at) == day)


def escalate(hub: "Hub", agent: "BaseAgent", *, summary: str, severity: str, needs: str) -> dict[str, Any]:
    """The `escalate` tool: an "agent_escalation" approval with the masked summary (the tool result says what
    happened; the limit per day is answered, not raised)."""
    config = hub.llm.config(agent.id)
    if not config.escalation.tool:
        raise PermissionError(f"Escalation is switched off for {agent.name}")
    text = hub.llm.mask.text(str(summary or "").strip())[:SUMMARY_MAX].strip()
    if not text:
        raise ValueError("escalate.summary: say what happened and what you need")
    severity = severity if severity in SEVERITIES else "warning"
    needs = needs if needs in NEEDS else "decision"
    limit = config.escalation.max_per_day
    if today(hub, agent.id) >= limit:
        key = (day_of(time.time()), agent.id)
        if key not in _limit_logged:
            _limit_logged.add(key)
            hub.activity(agent.id, "warn", f"{agent.name} reached its limit of {limit} escalations today: further "
                         "ones are refused until 00:00 UTC", agent_id=agent.id, event="escalation", severity="warning")
        return {"ok": False, "detail": LIMIT_REACHED}
    first = next((line.strip() for line in text.splitlines() if line.strip()), "needs a person")
    title = f"{agent.name}: {first[:TITLE_MAX]}" + ("..." if len(first) > TITLE_MAX else "")
    approval = hub.approvals.create(KIND, title, text, {"agent_id": agent.id, "agent_name": agent.name,
                                                       "severity": severity, "needs": needs}, agent.id)
    return {"ok": True, "approval_id": approval.id,
            "detail": "A person sees it in Approvals; their answer reaches you in a later turn. Tell the person "
                      "you are talking to (if any) that you escalated it."}


def _inbox_owner(hub: "Hub", agent_id: str) -> tuple[Any, list[dict[str, Any]]]:
    defn = teams.get_def(hub, agent_id)
    if defn is not None:
        return defn, list(defn.inbox)
    doc = hub.store.get("agents", agent_id) or {"id": agent_id, "paused": False}
    return doc, list(doc.get("inbox") or [])


def _save_inbox(hub: "Hub", agent_id: str, owner: Any, items: list[dict[str, Any]]) -> None:
    items = items[-INBOX_KEEP:]
    if isinstance(owner, dict):
        hub.store.put("agents", {**owner, "id": agent_id, "inbox": items})
    else:
        current = teams.get_def(hub, agent_id) or owner  # re-read: a run may have saved it meanwhile
        teams.save_def(hub, current.model_copy(update={"inbox": items}))


def answered(hub: "Hub", agent_id: str, body: dict[str, Any]) -> bool:
    """A person decided one of the agent's escalations (the agent's approval.decided handler): the note goes to its
    inbox, an acknowledged one is done. False when the approval is not an escalation of this agent."""
    approval = hub.approvals.get(str(body.get("approval_id") or ""))
    if approval is None or approval.kind != KIND or approval.payload.get("agent_id") != agent_id:
        return False
    approved = bool(body.get("approved"))
    owner, items = _inbox_owner(hub, agent_id)
    items.append({"approval_id": approval.id, "title": approval.title, "approved": approved,
                  "note": str(body.get("note") or "")[:2000], "decided_by": str(body.get("decided_by") or ""),
                  "at": time.time()})
    _save_inbox(hub, agent_id, owner, items)
    if approved:
        hub.approvals.complete(approval.id, True, {"status": "answer delivered"})
    return True


def inbox(hub: "Hub", agent_id: str) -> list[dict[str, Any]]:
    return _inbox_owner(hub, agent_id)[1]


def answers_prompt(items: list[dict[str, Any]]) -> str:
    """The context a model turn gets for the answers waiting in the inbox."""
    lines = []
    for item in items:
        verb = "acknowledged" if item.get("approved") else "dismissed"
        note = str(item.get("note") or "").strip()
        lines.append(f'- A person answered your escalation "{item.get("title")}" ({verb}): '
                     + (note if note else "no note."))
    return "Answers to your earlier escalations (through Approvals):\n" + "\n".join(lines)


def with_answers(hub: "Hub", agent_id: str, system: str) -> tuple[str, list[str]]:
    """`system` plus the waiting answers, and their approval ids (clear them once the turn worked)."""
    items = inbox(hub, agent_id)
    if not items:
        return system, []
    return f"{system}\n\n{answers_prompt(items)}", [str(i.get("approval_id")) for i in items]


def clear_answers(hub: "Hub", agent_id: str, ids: list[str]) -> None:
    if not ids:
        return
    owner, items = _inbox_owner(hub, agent_id)
    kept = [i for i in items if str(i.get("approval_id")) not in set(ids)]
    if len(kept) != len(items):
        _save_inbox(hub, agent_id, owner, kept)


# -- failed runs ---------------------------------------------------------------------------------


def run_finished(hub: "Hub", agent_id: str, ok: bool, skipped: bool) -> tuple[int, bool]:
    """Count a custom agent's failed runs in a row (a success resets it, a skipped run leaves it) and pause its
    schedule at the threshold. (failures in a row, whether this run paused the schedule)."""
    defn = teams.get_def(hub, agent_id)
    if defn is None or skipped:
        return (defn.failures if defn else 0), False
    if ok:
        if defn.failures:
            teams.save_def(hub, defn.model_copy(update={"failures": 0}))
        return 0, False
    failures = defn.failures + 1
    esc = defn.config.escalation
    pause = (not defn.schedule_paused and esc.pause_schedule and esc.failed_runs > 0 and failures >= esc.failed_runs
             and bool(defn.schedule_minutes and defn.task.strip()))
    teams.save_def(hub, defn.model_copy(update={"failures": failures, "schedule_paused": defn.schedule_paused or pause}))
    return failures, pause


def resume(hub: "Hub", agent_id: str, actor: str) -> bool:
    """An administrator resumes a paused schedule (the failure count starts again). False when nothing was paused."""
    defn = teams.get_def(hub, agent_id)
    if defn is None or not (defn.schedule_paused or defn.failures):
        return False
    was = defn.schedule_paused
    teams.save_def(hub, defn.model_copy(update={"schedule_paused": False, "failures": 0}))
    if was:
        hub.activity(actor, "info", f"Resumed {defn.name}'s schedule (it was paused after {defn.failures} failed "
                     "runs in a row)", agent_id=agent_id)
    return True


# -- what needs attention ------------------------------------------------------------------------


def attention(hub: "Hub", principal: "Principal") -> list[dict[str, Any]]:
    """What the Agents page's "Needs attention" strip shows: pending escalations, budgets reached, paused schedules,
    agents held by the guardrails, and agents whose chosen model cannot run - `for_you` when the agent's
    notifications target this person."""
    items: list[dict[str, Any]] = []

    def mine(agent_id: str, event: str | None) -> bool:
        config = config_of(hub, agent_id)
        return bool(event and config is not None and event in config.notify.events
                    and for_principal(config.notify.targets, principal))

    for a in escalations(hub, status="pending"):
        agent_id = str(a.payload.get("agent_id") or a.requested_by)
        items.append({"kind": "escalation", "agent_id": agent_id,
                      "agent_name": str(a.payload.get("agent_name") or agent_id), "title": a.title,
                      "severity": a.payload.get("severity") or "warning", "approval_id": a.id, "at": a.created_at,
                      "for_you": mine(agent_id, "escalation")})
    blocked: dict[str, list[dict[str, str]]] = {}
    for agent in hub.agents.all():
        record = agent.record()
        llm = record.get("llm") or {}
        if llm.get("budget_reached"):
            state = hub.llm.meter.state(agent.id)
            items.append({"kind": "budget", "agent_id": agent.id, "agent_name": agent.name,
                          "stopped": bool(state.get("stopped")), "for_you": mine(agent.id, "budget_reached")})
        if record.get("schedule_paused"):
            items.append({"kind": "paused", "agent_id": agent.id, "agent_name": agent.name,
                          "failures": record.get("failures") or 0, "for_you": mine(agent.id, "run_failed")})
        if record.get("outside_guardrails") and record.get("enabled"):
            items.append({"kind": "held", "agent_id": agent.id, "agent_name": agent.name,
                          "reason": record["outside_guardrails"], "for_you": False})
        primary = llm.get("primary")
        if primary and not llm.get("ready") and not agent.paused:
            res = hub.llm.resolve(agent.id, primary)
            if res.intended is not None and res.intended.provider != "rules" and res.blocked:  # a choice that cannot run
                why = next((b for b in res.blocked if b.provider == res.intended.provider), res.blocked[0])
                reason = f"{hub.llm.label(why.provider)}: {why.reason}"
                blocked.setdefault(reason, []).append({"id": agent.id, "name": agent.name})
    for reason, agents in blocked.items():
        items.append({"kind": "blocked", "reason": reason, "agents": agents, "for_you": False})
    order = {"escalation": 0, "budget": 1, "paused": 2, "held": 3, "blocked": 4}
    return sorted(items, key=lambda i: (order[i["kind"]], not i["for_you"], -(i.get("at") or 0)))
