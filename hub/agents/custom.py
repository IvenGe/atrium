"""Custom (team) agents: agents people or other agents create, each defined by an AgentDef (collection "agent_defs").

They chat and run their standing task on the AI model the provider layer resolves for them (hub/llm: their own
choice, or the suite's - Claude, a local model with an OpenAI-compatible API), or on rules - deterministic template
actions only (health check, data flows, summary of the state). Everything they do goes through
the shared toolkit with their effective permissions, and through the Operator, the Patch Agent and the Vulnerability
Supervisor as themselves ("agent:<slug>"), so the command policy, the approval flows and the guardrails apply.
"""

from __future__ import annotations

import time
from typing import Any

from ..agent_errors import recorded
from ..approvals import sender_person
from ..bus import Message
from ..integration import flows
from ..llm import Limited, LLMUnavailable, Msg
from ..models import OPEN_STATES, SEVERITY_ORDER, AgentDef, ControlState, Risk, Vulnerability
from . import notify, teams, toolkit
from . import settings as agent_settings
from .base import BaseAgent

HEALTH_WORDS = ("health", "alive", "outage", "uptime", "reachable", "is up", "down")
FLOW_WORDS = ("flow", "sync", "pull", "push", "evidence", "reconcil", "import")
SUMMARY_WORDS = ("summar", "status", "report", "overview", "state", "review")
MODEL_WORDS = ("triage", "analy", "prioriti", "propose", "investigat", "recommend", "explain", "why", "write",
               "remediat", "design", "group duplicates")
RULES_ONLY = ("I run on rules, so I can only check health, run data flows and summarize the state. This task needs a "
              "language model: an administrator can give me an AI model (Claude or a local model).")


class CustomAgent(BaseAgent):
    role = "team-agent"
    kind = "custom"
    purposes = ("chat",)
    max_concurrency = 2

    def __init__(self, hub, defn: AgentDef):
        super().__init__(hub, defn.id, defn.name, scope=defn.team)
        self.defn = defn

    # -- definition ------------------------------------------------------------------

    @property
    def defn(self) -> AgentDef:
        return self._defn

    @defn.setter
    def defn(self, defn: AgentDef) -> None:
        self._defn = defn
        self.name, self.title, self.description, self.scope = defn.name, defn.title, defn.description, defn.team
        self.uses_llm = defn.provider != "rules"

    @property
    def permissions(self) -> tuple[str, ...]:  # type: ignore[override]
        return tuple(teams.effective_permissions(self.hub, self.defn))

    @property
    def team(self) -> str:  # type: ignore[override]
        return self.defn.team

    @property
    def instructions(self) -> str:
        return self.defn.instructions or f"You are {self.defn.name}, {self.defn.title}. {self.defn.description}".strip()

    def record(self) -> dict[str, Any]:
        d = self.defn
        return {
            **super().record(),  # provider, provider_label, model and llm: what the provider layer resolves for it
            "kind": "custom", "provider_override": d.provider or None, "model_override": d.model or None,
            "custom_instructions": bool(d.instructions),
            "permissions": list(d.permissions), "effective_permissions": list(self.permissions),
            "team": d.team, "team_name": teams.team_name(self.hub, d.team), "parent": d.parent, "depth": d.depth,
            "schedule_minutes": d.schedule_minutes, "task": d.task, "enabled": d.enabled, "template": d.template,
            "created_by": d.created_by, "created_at": d.created_at, "updated_by": d.updated_by,
            "updated_at": d.updated_at, "last_run": d.last_run, "last_result": d.last_result,
            "next_run": teams.next_run(d), "running": d.running,
            "failures": d.failures, "schedule_paused": d.schedule_paused,  # paused after failed runs in a row
            "outside_guardrails": teams.outside_guardrails(self.hub, d),  # why it may not act now, or None
        }

    # -- requests --------------------------------------------------------------------

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        text = str(body.get("text", "")).strip()
        if not text:
            raise ValueError("Say something")
        if not self.defn.enabled:
            raise ValueError(f"{self.name} is disabled")
        memory = self.hub.llm.memory
        key = memory.person_of(msg.sender)  # each person has their own conversation with the agent (review D7)
        person = sender_person(msg.sender) and msg.sender
        config = self.defn.config
        res = self.hub.llm.resolve(self.id, "chat")
        if res.ready:
            self.hub.llm.start_run(self.id, config)  # its chats and runs per hour (RateLimited: HTTP 429)
        # another model starts a fresh conversation; how long one lasts is the agent's memory setting
        async with memory.turn(self.id, key, res.provider, res.model, config.memory) as conv:
            reply, mode, meta = await self.turn(text, conv.messages, person, trigger="chat",
                                                person=key if person else None)
        return {"reply": f"{conv.notice}\n\n{reply}" if conv.notice else reply, "mode": mode, "agent_id": self.id,
                **({"meta": meta.model_dump(mode="json")} if meta is not None else {})}

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        memory = self.hub.llm.memory
        memory.reset(self.id, memory.person_of(msg.sender))
        return {"ok": True}

    async def on_run(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Run the standing task (or the given one) once, in a fresh conversation, and record the result."""
        task = str(body.get("task") or self.defn.task).strip()
        trigger = str(body.get("trigger") or ("manual" if msg.sender.startswith(("user:", "token:")) else "agent"))
        if not task:
            self._finish(None)
            raise ValueError(f"{self.name} has no standing task - give it one, or send a task")
        started = time.time()
        person = sender_person(msg.sender) and msg.sender
        skipped = False
        try:
            if self.hub.llm.ready(self.id, "chat"):
                self.hub.llm.start_run(self.id, self.defn.config)  # its chats and runs per hour
            reply, mode = await self.converse(task, [], person, trigger="schedule" if trigger == "schedule" else "run",
                                              person=self.hub.llm.memory.person_of(msg.sender) if person else None)
            ok = True
        except Limited as exc:  # a reached budget or rate limit: skipped, not failed (it runs again when due)
            reply, ok, skipped = f"Skipped: {exc}", False, True
            mode = self.hub.llm.mode(self.hub.llm.resolve(self.id, "chat").provider)
        except Exception as exc:  # recorded like any result; the scheduler must not stop
            reply = str(exc) if isinstance(exc, ValueError) else f"{exc.__class__.__name__}: {exc}"
            mode, ok = self.hub.llm.mode(self.hub.llm.resolve(self.id, "chat").provider), False
            if not isinstance(exc, LLMUnavailable) and not recorded(exc):  # a model's failure: recorded by hub.llm
                self.hub.agent_errors.record(self.id, subject=msg.subject, sender=msg.sender, message=msg.id,
                                             thread=msg.thread, text=reply, error_class=exc.__class__.__name__,
                                             kind="exception", private=msg.private)
        now = time.time()
        result = {"ok": ok, "reply": reply[:4000], "mode": mode, "trigger": trigger, "at": now,
                  "duration": round(now - started, 2), **({"skipped": True} if skipped else {})}
        self._finish(result)
        failures, paused = notify.run_finished(self.hub, self.id, ok, skipped)  # pauses the schedule at the threshold
        text = f"{self.name} ran its task ({trigger}): " + (
            "skipped - a budget or rate limit is reached" if skipped else "done" if ok else "failed")
        if paused:
            text += (f" - its schedule is paused after {failures} failed runs in a row (an administrator can resume "
                     "it on the Agents page)")
        if skipped:
            self.log("info", text, agent_id=self.id)
        else:  # run_done / run_failed: a notification when the agent's settings ask for one
            notify.emit(self.hub, self.id, "run_done" if ok else "run_failed", level="info" if ok else "warn",
                        text=text, summary=reply[:500], failures=failures, **({"paused": True} if paused else {}))
        return {**result, "agent": self.record()}

    def _finish(self, result: dict[str, Any] | None) -> None:
        current = teams.get_def(self.hub, self.id)
        if current is None:  # removed while it ran
            return
        current.running = None
        if result is not None:
            current.last_run, current.last_result = result["at"], result
        teams.save_def(self.hub, current)

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        if notify.answered(self.hub, self.id, body):  # a person answered its escalation: for its next turn
            return
        teams.settle(self.hub, str(body.get("approval_id")), bool(body.get("approved")))

    # -- thinking ----------------------------------------------------------------------

    def context(self, requested_by: str | None = None) -> toolkit.ToolContext:
        """`requested_by`: the person whose chat message or manual run this is (commands on the hub machine and tool
        starts are judged by their role, F1); None for scheduled runs."""
        scope = self.defn.team if teams.team_kind(self.defn.team) == "tool" else None
        return toolkit.ToolContext(self.hub, self, frozenset(self.permissions), scope, requested_by or None)

    def system_prompt(self, instructions: str | None = None) -> str:
        """Its instructions (or, in the playground, a draft of them) and the fixed part no setting removes."""
        d = self.defn
        perms = ", ".join(self.permissions) or "none"
        base = (instructions or "").strip() or self.instructions
        return (f"{base}\n\nYou are {d.name}, the {d.title} in the {teams.team_name(self.hub, d.team)} team "
                f"of Atrium, an integration hub. You act only through your tools (your permissions: {perms}). "
                "Commands, patches and scans you ask for go through the hub's policies and may wait for a person's "
                "approval - say so when they do. Never invent ids or results: look them up. Answer concisely: what "
                "you found, what you did, and what needs a person.")

    async def converse(self, text: str, history: list[Msg], requested_by: str | None = None, *,
                       trigger: str = "chat", person: str | None = None) -> tuple[str, str]:
        """One turn: (reply, mode) with mode "llm" (a cloud model), "local" or "rules". `history` (appended to in
        place) is the person's conversation, or empty for a run; `requested_by`: see ``context``; `person`: the
        memory key of who asked (metering)."""
        reply, mode, _ = await self.turn(text, history, requested_by, trigger=trigger, person=person)
        return reply, mode

    async def turn(self, text: str, history: list[Msg], requested_by: str | None = None, *,
                   trigger: str = "chat", person: str | None = None) -> tuple[str, str, Any]:
        """converse, plus what the model reported (ReplyMeta: provider, model, source, tokens; None for rules)."""
        blocked = teams.outside_guardrails(self.hub, self.defn)
        if blocked:
            raise ValueError(f"{self.name} may not act: {blocked}")
        ctx = self.context(requested_by)
        res = self.hub.llm.resolve(self.id, "chat")
        if not res.ready:
            return await self.rules(text, ctx), "rules", None

        config = self.defn.config
        tools, allowed = agent_settings.allowed_definitions(self, ctx.permissions, config)

        async def run(name: str, args: dict[str, Any]) -> Any:
            agent_settings.check_allowed(self, name, ctx.permissions, allowed)
            return await toolkit.execute(ctx, name, args)

        history.append(Msg(role="user", text=text))
        system, answers = notify.with_answers(self.hub, self.id, self.system_prompt())  # answers to its escalations
        try:
            found = await self.hub.llm.converse(self.id, "chat", system=system, history=history,
                                                tools=tools, run=run, trigger=trigger, person=person, resolved=res,
                                                config=config, context=lambda: self._summary(ctx))
        except Limited:
            raise  # chat: HTTP 429; a run: skipped
        except LLMUnavailable as exc:
            raise ValueError(str(exc)) from exc
        if found is None:
            return await self.rules(text, ctx), "rules", None
        notify.clear_answers(self.hub, self.id, answers)  # the model read them
        reply, meta = found
        return reply, self.hub.llm.mode(meta.provider), meta

    # -- rules: deterministic template actions -------------------------------------------

    async def rules(self, text: str, ctx: toolkit.ToolContext) -> str:
        low = text.lower()
        parts: list[str] = []
        if any(w in low for w in HEALTH_WORDS):
            parts.append(await self._health(ctx))
        if any(w in low for w in FLOW_WORDS):
            parts.append(await self._flows(ctx))
        if any(w in low for w in SUMMARY_WORDS):
            parts.append(await self._summary(ctx))
        if not parts:
            return RULES_ONLY
        if any(w in low for w in MODEL_WORDS):
            parts.append("Parts of this task need a language model, which I don't have (I run on rules): an "
                         "administrator can give me an AI model (Claude or a local model).")
        return "\n\n".join(parts)

    def _team_tool(self) -> str | None:
        return self.defn.team if teams.team_kind(self.defn.team) == "tool" else None

    async def _health(self, ctx: toolkit.ToolContext) -> str:
        if "read" not in ctx.permissions:
            return "Health: I lack the 'read' permission."
        tool_id = self._team_tool()
        if tool_id:
            result = await toolkit.execute(ctx, "tool_health", {"tool_id": tool_id})
            state = "no health check defined" if result.get("ok") is None else "OK" if result.get("ok") else "DOWN"
            return f"**Health of {teams.team_name(self.hub, tool_id)}:** {state}" + (
                f" - {result['detail']}" if result.get("detail") and result.get("ok") is not None else "")
        if self.defn.team != "hub":
            return "Health: my team has no tool to check."
        result = await ctx.ask("supervisor", "health.sweep", timeout=120)
        lines = [f"- {k}: {'OK' if v.get('ok') else 'DOWN'} - {v.get('detail')}" for k, v in result["results"].items()]
        return "**Health:** " + ("\n" + "\n".join(lines) if lines else "no running tools with a health check.")

    async def _flows(self, ctx: toolkit.ToolContext) -> str:
        if "flows" not in ctx.permissions:
            return "Data flows: I lack the 'flows' permission to run them."
        tool_id, team = self._team_tool(), self.defn.team
        items = [f for f in flows.all_flows(self.hub, tool_id) if f.status == "enabled"
                 and (team not in teams.MODULE_TEAMS or flows.owner(f) == team)]
        if not items:
            return f"**Data flows:** none enabled for the {teams.team_name(self.hub, team)} team."
        lines = []
        for flow in items:
            try:
                result = await toolkit.execute(ctx, "run_flow", {"flow_id": flow.id})
            except Exception as exc:
                lines.append(f"- {flow.title}: could not run ({exc})")
                continue
            if result.get("pending"):
                lines.append(f"- {flow.title}: {result.get('detail') or 'continues in the background'}")
            elif result.get("ok"):
                moved = ", ".join(f"{v} {k}" for k, v in (result.get("counts") or {}).items() if v and k != "total")
                lines.append(f"- {flow.title}: ok ({moved or 'nothing changed'})")
            else:
                lines.append(f"- {flow.title}: failed - {(result.get('failure') or {}).get('message', 'unknown error')}")
        return "**Data flows:**\n" + "\n".join(lines)

    async def _summary(self, ctx: toolkit.ToolContext) -> str:
        if "read" not in ctx.permissions:
            return "Summary: I lack the 'read' permission."
        hub = self.hub
        tool_id = self._team_tool()
        pending = hub.approvals.list("pending")
        vulns = [v for v in hub.all("vulnerabilities", Vulnerability) if v.status in OPEN_STATES]
        if tool_id:
            tool = hub.get_tool(tool_id)
            if tool is None:
                return "Summary: my tool is no longer in the hub."
            tool_flows = flows.all_flows(hub, tool_id)
            failing = [f for f in tool_flows if f.status == "enabled" and f.failures]
            mine = [v for v in vulns if v.source == tool_id]
            health = (tool.health or {}).get("ok")
            lines = [
                f"- Status: {tool.status}" + (f", score {tool.report.score} ({tool.report.level})" if tool.report else ""),
                f"- Health: {'OK' if health else 'DOWN' if health is False else 'not checked'}"
                + (", running" if tool.running else ""),
                f"- Patches waiting: {sum(1 for p in hub.patches(tool_id) if p.status == 'proposed')}",
                f"- Data flows: {sum(1 for f in tool_flows if f.status == 'enabled')} enabled, {len(failing)} failing",
                f"- Open findings from it: {len(mine)}" + (" (" + ", ".join(
                    f"{n} {s}" for s in SEVERITY_ORDER if (n := sum(1 for v in mine if v.severity == s))) + ")" if mine else ""),
                f"- Approvals waiting for it: {sum(1 for a in pending if a.payload.get('tool_id') == tool_id)}",
            ]
            return f"**{tool.name}:**\n" + "\n".join(lines)
        team = self.defn.team
        if team == "module:assets":
            s = await ctx.ask("module:assets", "summary")
            return (f"**Assets:** {s['total']} active, {s['without_owner']} without an owner; "
                    + ", ".join(f"{v} {k}" for k, v in s["by_type"].items()))
        if team == "module:people":
            s = await ctx.ask("module:people", "summary")
            return (f"**People:** {s['total']} ({', '.join(f'{v} {k}' for k, v in s['by_status'].items())}), "
                    f"{s['accounts']} accounts; {s['leavers_count']} leaver(s) still holding access or assets"
                    + ("".join(f"\n- {line}" for line in s["leavers"]) if s["leavers"] else ""))
        if team == "module:network":  # counts only: device text never reaches an agent
            s = await ctx.ask("module:network", "summary")
            return (f"**Network:** {s['devices']} device(s), {s['stale']} without a current snapshot; "
                    f"{s['open_drift']} unexplained change(s) ({s['critical_drift']} critical); "
                    f"{s['writable']} writable now")
        if team == "module:grc":
            s = await ctx.ask("module:grc", "summary")
            return "**Compliance:**\n" + "\n".join(f"- {f['name']}: {f['score']}%" for f in s["frameworks"]) + (
                "\n\nFailing or partial:\n" + "\n".join(f"- {c}" for c in s["failing_controls"][:8]) if s["failing_controls"] else "")
        failing = [s for s in hub.all("controls", ControlState) if s.status in ("fail", "partial")]
        tools = hub.tools()
        scores = [t.report.score for t in tools if t.report]
        return "**Hub:**\n" + "\n".join([
            f"- Tools: {len(tools)}" + (f", suite score {round(sum(scores) / len(scores))}" if scores else ""),
            f"- Approvals waiting: {len(pending)}",
            f"- Open findings: {len(vulns)}, overdue {sum(1 for v in vulns if v.overdue)}",
            f"- Open risks: {sum(1 for r in hub.all('risks', Risk) if r.status != 'closed')}",
            f"- Failing or partial controls: {len(failing)}",
        ])
