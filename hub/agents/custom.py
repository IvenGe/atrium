"""Custom (team) agents: agents people or other agents create, each defined by an AgentDef (collection "agent_defs").

They chat and run their standing task on Claude, on a local model with an OpenAI-compatible API, or on rules -
deterministic template actions only (health check, data flows, summary of the state). Everything they do goes through
the shared toolkit with their effective permissions, and through the Operator, the Patch Agent and the Vulnerability
Supervisor as themselves ("agent:<slug>"), so the command policy, the approval flows and the guardrails apply.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .. import llm_providers
from ..bus import Message
from ..integration import flows
from ..models import OPEN_STATES, SEVERITY_ORDER, AgentDef, ControlState, Risk, Vulnerability
from . import teams, toolkit
from .base import BaseAgent

MAX_HISTORY = 80
HEALTH_WORDS = ("health", "alive", "outage", "uptime", "reachable", "is up", "down")
FLOW_WORDS = ("flow", "sync", "pull", "push", "evidence", "reconcil", "import")
SUMMARY_WORDS = ("summar", "status", "report", "overview", "state", "review")
MODEL_WORDS = ("triage", "analy", "prioriti", "propose", "investigat", "recommend", "explain", "why", "write",
               "remediat", "design", "group duplicates")
RULES_ONLY = ("I run on rules, so I can only check health, run data flows and summarize the state. This task needs a "
              "language model: an administrator can switch me to Claude or a local model.")


class CustomAgent(BaseAgent):
    role = "team-agent"
    kind = "custom"
    max_concurrency = 2

    def __init__(self, hub, defn: AgentDef):
        super().__init__(hub, defn.id, defn.name, scope=defn.team)
        self.defn = defn
        self._history: list[dict[str, Any]] = []
        self._history_key: tuple[str, str] | None = None
        self._chat_lock = asyncio.Lock()

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
    def model(self) -> str:
        return teams.model_of(self.hub, self.defn)

    @property
    def instructions(self) -> str:
        return self.defn.instructions or f"You are {self.defn.name}, {self.defn.title}. {self.defn.description}".strip()

    def record(self) -> dict[str, Any]:
        d = self.defn
        kind = teams.provider_kind(d.provider)
        local = llm_providers.get(self.hub, d.provider) if kind == "local" else None
        active = self.hub.llm.available if kind == "anthropic" else local is not None
        return {
            **super().record(),
            "kind": "custom", "provider": d.provider, "provider_kind": kind,
            "provider_label": local.name if local else teams.PROVIDER_LABELS[kind], "model_override": d.model or None,
            "custom_instructions": bool(d.instructions), "llm_active": bool(active) and kind != "rules",
            "permissions": list(d.permissions), "effective_permissions": list(self.permissions),
            "team": d.team, "team_name": teams.team_name(self.hub, d.team), "parent": d.parent, "depth": d.depth,
            "schedule_minutes": d.schedule_minutes, "task": d.task, "enabled": d.enabled, "template": d.template,
            "created_by": d.created_by, "created_at": d.created_at, "updated_by": d.updated_by,
            "updated_at": d.updated_at, "last_run": d.last_run, "last_result": d.last_result,
            "next_run": teams.next_run(d), "running": d.running,
            "outside_guardrails": teams.outside_guardrails(self.hub, d),  # why it may not act now, or None
        }

    # -- requests --------------------------------------------------------------------

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        text = str(body.get("text", "")).strip()
        if not text:
            raise ValueError("Say something")
        if not self.defn.enabled:
            raise ValueError(f"{self.name} is disabled")
        async with self._chat_lock:
            key = (self.defn.provider, self.model)
            if self._history_key != key or len(self._history) > MAX_HISTORY:
                self._history, self._history_key = [], key  # another model: start a fresh conversation
            before = len(self._history)
            try:
                reply, mode = await self.converse(text, self._history)
            except Exception:
                del self._history[before:]  # never keep half a turn
                raise
        return {"reply": reply, "mode": mode, "agent_id": self.id}

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        async with self._chat_lock:
            self._history = []
        return {"ok": True}

    async def on_run(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Run the standing task (or the given one) once, in a fresh conversation, and record the result."""
        task = str(body.get("task") or self.defn.task).strip()
        trigger = str(body.get("trigger") or ("manual" if msg.sender.startswith(("user:", "token:")) else "agent"))
        if not task:
            self._finish(None)
            raise ValueError(f"{self.name} has no standing task - give it one, or send a task")
        started = time.time()
        try:
            reply, mode = await self.converse(task, [])
            ok = True
        except Exception as exc:  # recorded like any result; the scheduler must not stop
            reply = str(exc) if isinstance(exc, ValueError) else f"{exc.__class__.__name__}: {exc}"
            mode, ok = teams.provider_kind(self.defn.provider), False
        now = time.time()
        result = {"ok": ok, "reply": reply[:4000], "mode": mode, "trigger": trigger, "at": now,
                  "duration": round(now - started, 2)}
        self._finish(result)
        self.log("info" if ok else "warn", f"{self.name} ran its task ({trigger}): {'done' if ok else 'failed'}",
                 agent_id=self.id)
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
        teams.settle(self.hub, str(body.get("approval_id")), bool(body.get("approved")))

    # -- thinking ----------------------------------------------------------------------

    def context(self) -> toolkit.ToolContext:
        scope = self.defn.team if teams.team_kind(self.defn.team) == "tool" else None
        return toolkit.ToolContext(self.hub, self, frozenset(self.permissions), scope)

    def system_prompt(self) -> str:
        d = self.defn
        perms = ", ".join(self.permissions) or "none"
        return (f"{self.instructions}\n\nYou are {d.name}, the {d.title} in the {teams.team_name(self.hub, d.team)} team "
                f"of Atrium, an integration hub. You act only through your tools (your permissions: {perms}). "
                "Commands, patches and scans you ask for go through the hub's policies and may wait for a person's "
                "approval - say so when they do. Never invent ids or results: look them up. Answer concisely: what "
                "you found, what you did, and what needs a person.")

    async def converse(self, text: str, history: list[dict[str, Any]]) -> tuple[str, str]:
        """One turn: (reply, mode) with mode "llm" (Claude), "local" or "rules"."""
        blocked = teams.outside_guardrails(self.hub, self.defn)
        if blocked:
            raise ValueError(f"{self.name} may not act: {blocked}")
        ctx = self.context()
        provider = self.defn.provider
        if provider == "rules":
            return await self.rules(text, ctx), "rules"
        tools = toolkit.definitions(ctx.permissions)

        async def run(name: str, args: dict[str, Any]) -> Any:
            return await toolkit.execute(ctx, name, args)

        history.append({"role": "user", "content": text})
        if provider == "anthropic":
            if not self.hub.llm.available:
                raise ValueError(f"{self.name} runs on Claude, which is not available - set ANTHROPIC_API_KEY, or "
                                 "switch the agent to a local model or rules")
            return await toolkit.claude_loop(self.hub, history, system=self.system_prompt(), tools=tools,
                                              model=self.model, run=run), "llm"
        local = llm_providers.get(self.hub, provider)
        if local is None:
            raise ValueError(f"{self.name} runs on the local provider '{provider}', which no longer exists")
        try:
            return await toolkit.local_loop(self.hub, local, history, system=self.system_prompt(), tools=tools,
                                            model=self.model, run=run), "local"
        except llm_providers.ProviderError as exc:
            raise ValueError(str(exc)) from exc

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
                         "administrator can switch me to Claude or a local model.")
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
