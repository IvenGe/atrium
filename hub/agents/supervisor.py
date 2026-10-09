"""Hub Supervisor: the orchestrator. It talks to every other agent and keeps the suite integrated."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any

from ..bus import Message
from ..integration import importer
from ..integration.compatibility import evaluate_suite, suite_matrix
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
- Patch Agent - fixes integration gaps with code patches on git branches, or adapters for closed/SaaS tools.
- Operator Agent - runs commands on this machine or on registered SSH hosts, under a command policy.
- Asset Supervisor - the asset register. GRC Supervisor - controls, evidence, risks and policies.

How to work:
- Use the tools to look at real state before answering; do not guess tool ids, host ids or scores.
- Prefer read-only investigation. State-changing commands and every patch go to the human approval queue
  (unless the hub is in autonomous mode); tell the person when something is waiting for their approval.
- Never try to run destructive commands; the policy refuses them anyway.
- Answer concisely in plain language, with short lists where they help."""


def _tool(name: str, description: str, properties: dict[str, Any] | None = None) -> dict[str, Any]:
    properties = properties or {}
    return {
        "name": name,
        "description": description,
        "strict": True,
        "input_schema": {"type": "object", "properties": properties, "required": list(properties),
                         "additionalProperties": False},
    }


STR = {"type": "string"}
CHAT_TOOLS = [
    _tool("list_tools", "List imported tools with kind, status, integration score and level."),
    _tool("get_tool", "Full manifest, compatibility checks and patches of one tool.", {"tool_id": STR}),
    _tool("integration_overview", "How tools connect: capability, identity and event links, port conflicts, unmet dependencies."),
    _tool("import_tool", "Import a tool. source_type is github (URL or owner/repo), local (folder path) or saas (https URL).",
          {"source_type": {"type": "string", "enum": ["github", "local", "saas"]}, "source": STR}),
    _tool("reanalyze_tool", "Ask a tool's supervisor to re-analyse it and re-score the suite.", {"tool_id": STR}),
    _tool("propose_patches", "Ask the Patch Agent to propose patches for every open integration gap of a tool.", {"tool_id": STR}),
    _tool("request_code_patch", "Ask the Patch Agent for a custom source-code patch to a tool with source code.",
          {"tool_id": STR, "goal": STR}),
    _tool("run_command", "Run a shell command through the Operator Agent. target is 'local' or a host id from list_hosts.",
          {"target": STR, "command": STR, "reason": STR}),
    _tool("list_hosts", "List registered SSH hosts."),
    _tool("tool_health", "Check the health of one tool now.", {"tool_id": STR}),
    _tool("asset_summary", "Summary of the asset register."),
    _tool("compliance_summary", "Framework scores, failing controls and top risks."),
    _tool("list_approvals", "Actions waiting for human approval."),
]


class HubSupervisor(BaseAgent):
    role = "supervisor"
    title = "Hub Supervisor"
    uses_llm = True
    max_concurrency = 16  # imports can take minutes; chat must stay responsive
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
        self.log("info", f"Importing {tool.name} from {tool.source_type}: {tool.source}")
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
        await self.tell("module:assets", "sync")
        await self.tell("module:grc", "evaluate")
        return {"tool_id": tool_id, "score": tool.report.score, "level": tool.report.level, "gaps": len(gaps)}

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
        await self.tell("module:assets", "sync")
        await self.tell("module:grc", "evaluate")
        return {}

    async def on_reevaluate(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self.reevaluate()
        await self.tell("module:grc", "evaluate")
        return suite_matrix(self.hub.tools())

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
        for tool_id, report in evaluate_suite(tools).items():
            tool = self.hub.get_tool(tool_id)
            if tool and tool.manifest:
                tool.report = report
                self.hub.save_tool(tool)

    # -- chat --------------------------------------------------------------------------

    async def on_chat(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        text = str(body.get("text", "")).strip()
        if self.hub.llm.available:
            try:
                return {"reply": await self._llm_chat(text), "mode": "llm"}
            except Exception as exc:  # fall back to rules on any API failure
                note = f"(Claude unavailable: {exc.__class__.__name__}. Falling back to built-in commands.)\n\n"
                return {"reply": note + await self._rules_chat(text), "mode": "rules"}
        return {"reply": await self._rules_chat(text), "mode": "rules"}

    async def on_chat_reset(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        async with self._chat_lock:
            self._history = []
        return {"ok": True}

    async def _llm_chat(self, text: str) -> str:
        async with self._chat_lock:
            if len(self._history) > 80:  # start a fresh conversation instead of editing history
                self._history = []
            self._history.append({"role": "user", "content": text})
            response = None
            for _ in range(12):
                response = await self.hub.llm.create(system=self.instructions, messages=self._history,
                                                     tools=CHAT_TOOLS, model=self.model, effort="medium")
                self._history.append({"role": "assistant", "content": response.content})
                if response.stop_reason == "refusal":
                    return "I can't help with that request."
                if response.stop_reason == "pause_turn":
                    continue
                if response.stop_reason != "tool_use":
                    break
                calls = [b for b in response.content if b.type == "tool_use"]
                results = await asyncio.gather(*(self._run_chat_tool(b) for b in calls))
                self._history.append({"role": "user", "content": list(results)})
            reply = "\n".join(b.text for b in (response.content if response else []) if b.type == "text").strip()
            if response is not None and response.stop_reason == "max_tokens":
                reply += "\n\n(Reply cut off - ask me to continue.)"
            return reply or "Done."

    async def _run_chat_tool(self, block: Any) -> dict[str, Any]:
        try:
            result = await self._chat_tool(block.name, dict(block.input or {}))
            content = json.dumps(result, default=str)[:20000]
            return {"type": "tool_result", "tool_use_id": block.id, "content": content}
        except Exception as exc:
            return {"type": "tool_result", "tool_use_id": block.id, "content": f"Error: {exc}", "is_error": True}

    async def _chat_tool(self, name: str, args: dict[str, Any]) -> Any:
        hub = self.hub
        if name == "list_tools":
            return [{"id": t.id, "name": t.name, "kind": t.manifest.kind if t.manifest else None, "status": t.status,
                     "score": t.report.score if t.report else None, "level": t.report.level if t.report else None,
                     "running": t.running} for t in hub.tools()]
        if name == "get_tool":
            tool = hub.get_tool(args["tool_id"])
            if tool is None:
                raise ValueError("Unknown tool id")
            return {"tool": tool.model_dump(mode="json"),
                    "patches": [{"id": p.id, "title": p.title, "status": p.status} for p in hub.patches(tool.id)]}
        if name == "integration_overview":
            return suite_matrix(hub.tools())
        if name == "import_tool":
            tool = importer.create_tool(hub, importer.ImportRequest(source_type=args["source_type"], source=args["source"]))
            await self.tell("supervisor", "tool.import", {"tool_id": tool.id})
            return {"tool_id": tool.id, "status": "importing in the background"}
        if name == "reanalyze_tool":
            return await self.on_tool_imported({"tool_id": args["tool_id"]}, Message(sender="supervisor", recipient="supervisor", subject="reanalyze"))
        if name == "propose_patches":
            return await self.ask("patcher", "propose", {"tool_id": args["tool_id"]}, timeout=600)
        if name == "request_code_patch":
            return await self.ask("patcher", "custom", {"tool_id": args["tool_id"], "goal": args["goal"]}, timeout=900)
        if name == "run_command":
            return await self.ask("operator", "run", {"target": args["target"], "command": args["command"],
                                                      "reason": args["reason"]}, timeout=900)
        if name == "list_hosts":
            return [{"id": h.id, "name": h.name, "address": h.address, "user": h.username} for h in hub.hosts()]
        if name == "tool_health":
            return await self.ask(f"tool:{args['tool_id']}", "health", timeout=30)
        if name == "asset_summary":
            return await self.ask("module:assets", "summary")
        if name == "compliance_summary":
            return await self.ask("module:grc", "summary")
        if name == "list_approvals":
            return [{"id": a.id, "title": a.title, "kind": a.kind} for a in hub.approvals.list("pending")]
        raise ValueError(f"Unknown tool {name}")

    async def _rules_chat(self, text: str) -> str:
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
            result = await self.ask(f"tool:{tool.id}", verb, timeout=60)
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
            result = await self.ask("operator", "run", {"target": target, "command": command, "reason": "Requested in chat"}, timeout=900)
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
