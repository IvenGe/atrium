"""Hub Supervisor: the orchestrator. It talks to every other agent and keeps the suite integrated."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

from ..approvals import sender_person
from ..bus import Message
from ..extensions import gaps as extension_gaps
from ..extensions import registry as extension_registry
from ..integration import connections, flows, identity, importer, strategies
from ..integration.compatibility import evaluate_suite, suite_matrix
from ..integration.identity import SSO_STRATEGIES
from ..models import AGENT_PERMISSIONS, strip_url_credentials
from . import teams, toolkit
from .base import BaseAgent

HELP = (
    "I coordinate the agents in this hub. Things I understand without an LLM:\n"
    "- `status` - suite overview\n"
    "- `import <github url | owner/repo | folder | https://saas.example.com>`\n"
    "- `analyze <tool>` / `patch <tool>` / `start <tool>` / `stop <tool>`\n"
    "- `run <command>` or `run on <host>: <command>`\n"
    "- `health`, `assets`, `compliance`\n"
    "With ANTHROPIC_API_KEY set I also understand plain language and can plan multi-step work."
)

SYSTEM = """You are the Hub Supervisor, the orchestrating agent of an integration hub - an "office suite" that brings
open-source projects, closed-source applications and SaaS services together and keeps them working as one.

Your team:
- One Tool Supervisor per imported tool (agent id "tool:<tool id>") - responsible for that application.
- Patch Agent - fixes integration gaps with code patches on git branches, or adapters for closed/SaaS tools, and
  repairs failing data flows.
- Operator Agent - runs commands on this machine or on registered SSH hosts, under a command policy.
- Asset Supervisor - the asset register. GRC Supervisor - controls, evidence, risks and policies.
  Vulnerability Supervisor - scans of in-scope assets, findings and their remediation deadlines.
- Data flows move assets, vulnerabilities, controls and risks between tools (through their connectors) and the
  hub's apps; you propose them, the module supervisors run them.
- Agent teams: a Tool Supervisor can lead a team of custom agents for its tool (propose_team); team agents act
  through the same policies and approvals, within the guardrails an administrator sets.

How to work:
- Use the tools to look at real state before answering; do not guess tool ids, host ids or scores.
- Prefer read-only investigation. State-changing commands and every patch go to the human approval queue
  (unless the hub is in autonomous mode); tell the person when something is waiting for their approval.
- Never try to run destructive commands; the policy refuses them anyway.
- Answer concisely in plain language, with short lists where they help."""


class HubSupervisor(BaseAgent):
    role = "supervisor"
    title = "Hub Supervisor"
    uses_llm = True
    max_concurrency = 16  # imports can take minutes; chat must stay responsive
    permissions = AGENT_PERMISSIONS  # its chat gets every tool of the shared toolkit
    description = ("Orchestrates the hub. Imports tools, assigns a supervisor to each, scores how well the suite "
                   "fits together, sends gaps to the Patch Agent, and plans multi-step work from chat.")
    default_instructions = SYSTEM

    def __init__(self, hub):
        super().__init__(hub, "supervisor", "Hub Supervisor")
        self._history: list[dict[str, Any]] = []
        self._chat_lock = asyncio.Lock()

    # -- tool lifecycle ----------------------------------------------------------------

    async def on_tool_import(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self.hub.get_tool(body["tool_id"])
        if tool is None:
            raise ValueError("Unknown tool")
        self.log("info", f"Importing {tool.name} from {tool.source_type}: {strip_url_credentials(tool.source)}")
        tool = await importer.materialize(self.hub, tool, body.get("branch"))
        if tool.status == "error":
            self.log("error", f"Import of {tool.name} failed: {tool.error}")
            return {"status": "error", "error": tool.error}
        self.hub.agents.ensure_tool_supervisor(tool)
        return await self.on_tool_imported({"tool_id": tool.id}, msg)

    async def on_tool_imported(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool_id = body["tool_id"]
        try:
            await self.ask(f"tool:{tool_id}", "analyze", timeout=900)
        except Exception as exc:
            tool = self.hub.get_tool(tool_id)
            if tool:
                tool.status, tool.error = "error", str(exc)
                self.hub.save_tool(tool)
            raise
        self.reevaluate()
        tool = self.hub.get_tool(tool_id)
        assert tool and tool.report
        gaps = [c for c in tool.report.checks if c.status != "pass" and c.fix]
        if gaps:
            tool.status = "needs_patch"
            self.hub.save_tool(tool)
            await self.tell("patcher", "propose", {"tool_id": tool_id, "fixes": [c.fix for c in gaps]})
        self.log("info", f"{tool.name} is in the suite: score {tool.report.score} ({tool.report.level}), "
                         f"{len(gaps)} gap(s) sent to the Patch Agent")
        if identity.is_provider(tool):  # every other tool can now sign in through it
            await self._sso_sweep(exclude=tool_id)
        if teams.classify(self.hub, tool):  # a known complex tool (SIEM, GRC, inventory, scanner) gets a team proposal
            await self.tell(f"tool:{tool_id}", "team.propose", {"auto": True})
        await self.extend_for(tool)
        await self.tell("module:assets", "sync")
        await self.tell("module:grc", "evaluate")
        return {"tool_id": tool_id, "score": tool.report.score, "level": tool.report.level, "gaps": len(gaps)}

    async def extend_for(self, tool) -> list[dict[str, Any]]:
        """Hub-side gaps (a data domain Atrium does not model, no connector, unknown SSO) go to the Patch Agent, which
        extends Atrium - once per tool (see PatchAgent.on_extension_propose)."""
        if not extension_registry.allowed(self.hub) or extension_registry.covers_tool(self.hub, tool.id):
            return []
        gaps = [g.as_dict() for g in extension_gaps.detect(self.hub, tool)]
        if gaps:
            self.log("info", f"Atrium lacks {len(gaps)} thing(s) for {tool.name}: " + "; ".join(g["title"] for g in gaps)
                     + " - asking the Patch Agent to extend Atrium", tool_id=tool.id)
            await self.tell("patcher", "extension.propose", {"tool_id": tool.id, "auto": True})
        return gaps

    async def on_tool_patched(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self.reevaluate()
        tool = self.hub.get_tool(body["tool_id"])
        if tool and tool.report:
            open_patches = [p for p in self.hub.patches(tool.id) if p.status == "proposed"]
            if tool.status == "needs_patch" and not open_patches:
                tool.status = "ready"
                self.hub.save_tool(tool)
            self.log("info", f"{tool.name} re-scored after patch: {tool.report.score} ({tool.report.level})")
        await self.tell("module:assets", "sync")
        await self.tell("module:grc", "evaluate")
        return {}

    async def on_tool_removed(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self.reevaluate()
        if body.get("was_provider"):
            await self._sso_sweep()
        await self.tell("module:assets", "sync")
        await self.tell("module:grc", "evaluate")
        return {}

    async def on_reevaluate(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self.reevaluate()
        await self.tell("module:grc", "evaluate")
        return suite_matrix(self.hub.tools())

    async def on_identity_changed(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """The suite default, a provider's settings or the providers changed: re-score and re-plan single sign-on."""
        planned = await self._sso_sweep()
        await self.tell("module:grc", "evaluate")
        return {"replanned": planned}

    async def _sso_sweep(self, exclude: str | None = None) -> list[str]:
        """Ask the Patch Agent to (re)plan SSO for every tool whose single sign-on is not settled."""
        self.reevaluate()
        planned = []
        for tool in self.hub.tools():
            check = next((c for c in (tool.report.checks if tool.report else []) if c.id == "sso"), None)
            stale = any(p.strategy in SSO_STRATEGIES and p.status == "proposed" for p in self.hub.patches(tool.id))
            if tool.id != exclude and check and check.status != "pass" and (check.fix in SSO_STRATEGIES or stale):
                await self.tell("patcher", "sso.plan", {"tool_id": tool.id, "rescore": False})
                planned.append(tool.id)
        return planned

    # -- data flows --------------------------------------------------------------------

    async def on_flows_plan(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Propose the data flows the connections make possible (see integration/strategies.py)."""
        created = strategies.propose(self.hub, self.id)
        if created:
            verb = "Enabled" if self.hub.prefs["autonomy"] == "autonomous" else "Proposed"
            self.log("info", f"{verb} {len(created)} data flow(s): " + "; ".join(f.title for f in created))
        await self.propose_teams()
        return {"proposed": [flows.public(self.hub, f) for f in created]}

    async def on_flows_create(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """A data flow a person drew on the integration map (POST /api/flows): the planner's rules decide whether it
        may exist (strategies.create_flow); a proposal is requested by this agent, so approving it enables the flow
        here. The proposer is the sender when a person sent it - never a name in the body."""
        actor = sender_person(msg.sender) or msg.sender
        try:
            flow, approval = strategies.create_flow(
                self.hub, domain=str(body.get("domain") or ""), source=str(body.get("source") or ""),
                target=str(body.get("target") or ""), action=body.get("action"),
                schedule_minutes=body.get("schedule_minutes"), options=body.get("options") or {}, actor=actor)
        except strategies.FlowRefused as exc:
            return {"refused": exc.as_dict()}
        return {"flow": flows.public(self.hub, flow), "approval_id": approval.id if approval else None}

    async def propose_teams(self) -> list[str]:
        """Tools with a connection get an agent team proposal - once (see ToolSupervisor.on_team_propose)."""
        asked = []
        for conn in connections.all_connections(self.hub):
            if self.hub.get_tool(conn.id) and not teams.has_team_or_proposal(self.hub, conn.id):
                await self.tell(f"tool:{conn.id}", "team.propose", {"auto": True})
                asked.append(conn.id)
        return asked

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(body["approval_id"])
        if approval is not None and approval.kind == "agent_team":  # members it proposed from chat
            teams.settle(self.hub, approval.id, bool(body.get("approved")))
            return
        if approval is None or approval.kind != "flow":
            return
        flow = flows.get(self.hub, approval.payload.get("flow_id", ""))
        conflict = None
        if flow is not None and flow.status == "proposed":
            # the loop rule: never enable a pull next to an enabled push of the same domain for a tool (or the reverse)
            conflict = strategies.loop_conflict(flows.all_flows(self.hub), *flows.key(flow), exclude=flow.id,
                                                states=("enabled",)) if body.get("approved") else None
            flow.status = "enabled" if body.get("approved") and conflict is None else "disabled"
            flow.approval_id = None
            flows.save(self.hub, flow)
            if conflict is not None:
                self.log("warn", f"Data flow not enabled: {flow.title} - "
                         + strategies.loop_message(self.hub, flow.domain, flow.source, flow.target), flow_id=flow.id)
            else:
                self.log("info", f"Data flow {flow.status}: {flow.title}", flow_id=flow.id)
        if body.get("approved"):  # a rejected proposal stays "rejected"; the flow stays as a disabled record
            result: dict[str, Any] = {"status": flow.status if flow else "removed"}
            if conflict is not None:
                result.update(error="flow_conflict", flow_id=conflict.id)
            self.hub.approvals.complete(approval.id, flow is not None and conflict is None, result)

    async def on_flow_failed(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """A flow failed again: after REPAIR_AFTER consecutive failures, ask the Patch Agent for a repair (once - until
        the repair is decided)."""
        flow = flows.get(self.hub, str(body.get("flow_id")))
        if flow is None or flow.failures < flows.REPAIR_AFTER or flow.repair:
            return {"repair": False}
        flow.repair = "requested"
        flows.save(self.hub, flow)
        self.log("warn", f"Data flow failed {flow.failures} times in a row, asking the Patch Agent for a repair: {flow.title}",
                 flow_id=flow.id)
        await self.tell("patcher", "integration.repair", {
            "flow_id": flow.id, "tool_id": flow.tool_id, "error": body.get("error") or (flow.last_result or {}).get("error"),
            "sample": flows.sanitize(body.get("sample")), "failures": flow.failures})
        return {"repair": True}

    async def on_health_sweep(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tools = [t for t in self.hub.tools() if t.manifest and t.manifest.health.url and (t.running or t.manifest.kind == "saas")]

        async def check(tool_id: str) -> tuple[str, Any]:
            try:
                return tool_id, await self.ask(f"tool:{tool_id}", "health", timeout=30)
            except Exception as exc:
                return tool_id, {"ok": False, "detail": str(exc)}

        results = dict(await asyncio.gather(*(check(t.id) for t in tools)))
        return {"checked": len(results), "results": results}

    def reevaluate(self) -> None:
        tools = self.hub.tools()
        for tool_id, report in evaluate_suite(tools, identity.load_prefs(self.hub)).items():
            tool = self.hub.get_tool(tool_id)
            if tool and tool.manifest:
                tool.report = report
                self.hub.save_tool(tool)

    # -- chat --------------------------------------------------------------------------

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        text = str(body.get("text", "")).strip()
        person = msg.sender if sender_person(msg.sender) else None  # commands asked for in chat are judged by them (F1)
        if self.hub.llm.available:
            try:
                return {"reply": await self._llm_chat(text, person), "mode": "llm"}
            except Exception as exc:  # fall back to rules on any API failure
                note = f"(Claude unavailable: {exc.__class__.__name__}. Falling back to built-in commands.)\n\n"
                return {"reply": note + await self._rules_chat(text, person), "mode": "rules"}
        return {"reply": await self._rules_chat(text, person), "mode": "rules"}

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        async with self._chat_lock:
            self._history = []
        return {"ok": True}

    async def _llm_chat(self, text: str, person: str | None = None) -> str:
        async with self._chat_lock:
            if len(self._history) > 80:  # start a fresh conversation instead of editing history
                self._history = []
            self._history.append({"role": "user", "content": text})
            ctx = toolkit.ToolContext(self.hub, self, frozenset(self.permissions), requested_by=person)

            async def run(name: str, args: dict[str, Any]) -> Any:
                return await toolkit.execute(ctx, name, args)

            return await toolkit.claude_loop(self.hub, self._history, system=self.instructions,
                                             tools=toolkit.definitions(ctx.permissions), model=self.model, run=run)

    async def _rules_chat(self, text: str, person: str | None = None) -> str:
        low = text.lower().strip()
        if not low or low in ("help", "?", "hi", "hello"):
            return HELP
        if low in ("status", "overview", "report"):
            tools = self.hub.tools()
            if not tools:
                return "No tools imported yet. Try `import owner/repo`."
            lines = [f"- **{t.name}** - {t.status}, score {t.report.score if t.report else '-'}"
                     f" ({t.report.level if t.report else 'not analysed'})" for t in tools]
            pending = self.hub.approvals.pending_count()
            return "\n".join(lines) + (f"\n\n{pending} action(s) await your approval." if pending else "")
        match = re.match(r"^import\s+(\S+)$", text.strip(), re.IGNORECASE)
        if match:
            source = match.group(1)
            if Path(source).expanduser().is_dir():
                kind = "local"
            elif "github.com" in source or source.startswith("git@") or importer.SHORTHAND.match(source):
                kind = "github"
            else:
                kind = "saas"
            tool = importer.create_tool(self.hub, importer.ImportRequest(source_type=kind, source=source))
            await self.tell("supervisor", "tool.import", {"tool_id": tool.id})
            return f"Importing **{tool.name}** ({kind}). Its supervisor will analyse it and I will score the integration."
        match = re.match(r"^(analy[sz]e|patch|start|stop)\s+(.+)$", text.strip(), re.IGNORECASE)
        if match:
            verb, name = match.group(1).lower(), match.group(2).strip().lower()
            tool = next((t for t in self.hub.tools() if name in (t.id, t.name.lower())), None)
            if tool is None:
                return f"I don't know a tool called '{name}'."
            if verb.startswith("analy"):
                result = await self.on_tool_imported({"tool_id": tool.id}, Message(sender="user", recipient=self.id, subject="analyze"))
                return f"{tool.name}: score {result['score']} ({result['level']}), {result['gaps']} gap(s)."
            if verb == "patch":
                result = await self.ask("patcher", "propose", {"tool_id": tool.id}, timeout=600)
                return f"The Patch Agent proposed {len(result['patches'])} patch(es) for {tool.name}; see Approvals."
            result = await self.ask(f"tool:{tool.id}", verb, {"requested_by": person}, timeout=60)
            return f"{verb.capitalize()} {tool.name}: {result.get('status', result)}"
        match = re.match(r"^(?:run|exec)\s+(?:on\s+([\w.-]+)\s*:\s*)?(.+)$", text.strip(), re.IGNORECASE | re.DOTALL)
        if match:
            host_name, command = match.group(1), match.group(2).strip()
            target = "local"
            if host_name:
                host = next((h for h in self.hub.hosts() if host_name.lower() in (h.id.lower(), h.name.lower())), None)
                if host is None:
                    return f"I don't know a host called '{host_name}'."
                target = host.id
            result = await self.ask("operator", "run", {"target": target, "command": command, "reason": "Requested in chat",
                                                        "requested_by": person}, timeout=900)
            if result["status"] == "done":
                return f"Exit code {result['exit_code']}:\n```\n{result['output'][-3000:]}\n```"
            return f"{result['status'].replace('_', ' ').capitalize()}: {result.get('reason', '')}"
        if low == "health":
            result = await self.on_health_sweep({}, Message(sender="user", recipient=self.id, subject="health"))
            if not result["checked"]:
                return "No running tools with a health check."
            return "\n".join(f"- {k}: {'OK' if v.get('ok') else 'DOWN'} - {v.get('detail')}" for k, v in result["results"].items())
        if low in ("assets", "asset summary"):
            s = await self.ask("module:assets", "summary")
            types = ", ".join(f"{v} {k}" for k, v in s["by_type"].items()) or "none"
            return f"{s['total']} active assets ({types}); {s['without_owner']} without an owner."
        if low in ("compliance", "grc", "risks"):
            s = await self.ask("module:grc", "summary")
            frameworks = "\n".join(f"- {f['name']}: {f['score']}%" for f in s["frameworks"])
            failing = "\n".join(f"- {c}" for c in s["failing_controls"][:6]) or "- none"
            return f"{frameworks}\n\nFailing or partial controls:\n{failing}"
        return "I'm running without an LLM, so I only understand a few commands.\n\n" + HELP
