"""The Hub runtime: shared state every agent and API route works through."""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from . import guardrails
from .agents import teams
from .approvals import Approvals
from .auth.service import AuthService
from .bus import Bus
from .config import AUTONOMY_LEVELS, Settings
from .execution.processes import ProcessManager
from .extensions import selfpatch
from .integration import changes as device_changes
from .integration import flows
from .integration.toolbus import ToolBus
from .llm import LLM
from .llm import usage as llm_usage
from .models import Host, Patch, Tool
from .secrets import SecretBox
from .store import Store

M = TypeVar("M", bound=BaseModel)


def private_dir(path: Path) -> None:
    """Create `path` readable by this account only, and tighten it when it already exists (review F14)."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:  # best effort (Windows ACLs are not mode bits; a folder someone else owns)
        pass

# Service-level targets for fixing vulnerabilities, in days from first seen (Settings > Vulnerabilities).
DEFAULT_SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180}
SLA_CHECK_INTERVAL = 3600.0
# How many entries of the operational logs are kept (review F38); the activity log and the command history are the
# audit trail and are kept.
LOG_RETENTION = {"messages": 50_000, "toolbus": 20_000, "llm_usage": 200_000}
PRUNE_INTERVAL = 3600.0


class Hub:
    def __init__(self, settings: Settings):
        from .agents.registry import AgentRegistry

        self.settings = settings
        for folder in (settings.data_dir, settings.workspace):  # owner-only: the database, key and secrets (F14)
            private_dir(folder)
        self.store = Store(settings.db_path)
        self.bus = Bus(self.store)
        self.secrets = SecretBox.for_settings(settings)
        self.auth = AuthService(self)
        self.llm = LLM(self)
        self.approvals = Approvals(self)
        self.processes = ProcessManager(self)
        self.toolbus = ToolBus(self)
        self.agents = AgentRegistry(self)
        self.connector_transport: httpx.AsyncBaseTransport | None = None  # tests route connector HTTP through a mock
        self.llm_transport: httpx.AsyncBaseTransport | None = None  # ... and local model servers' HTTP
        # Atrium's own repository, test command and git / gh runners for self-patches (tests inject fakes)
        self.self_patch = selfpatch.SelfPatchConfig()
        self.restart_required: dict[str, Any] | None = None  # set when a self-patch was merged; a restart clears it
        self.approvals.guards["self_patch"] = lambda approval, approve: selfpatch.check_decision(self, approval, approve)
        self.approvals.guards["firewall"] = lambda approval, approve: device_changes.check_decision(self, approval, approve)
        # subsidiaries (hub/subsidiary): in-process state, injectable clock and transports, and their approvals' guards
        from .subsidiary import governance as subsidiaries
        from .subsidiary import runtime as subsidiary_runtime

        self.subsidiary_config = subsidiary_runtime.SubsidiaryConfig()
        self.subsidiaries = subsidiary_runtime.SubsidiaryRuntime(self)
        self.approvals.guards["subsidiary_charter"] = lambda a, ok: subsidiaries.check_charter_decision(self, a, ok)
        self.approvals.guards["subsidiary_action"] = lambda a, ok: subsidiaries.check_action_decision(self, a, ok)
        from .subsidiary import bridgepatch  # bridge patches (strategy atrium_bridge); other patches pass

        self.approvals.guards["patch"] = lambda a, ok: bridgepatch.check_decision(self, a, ok)
        self._background: list[asyncio.Task[None]] = []
        self._sla_checked = 0.0
        self._pruned = 0.0

    # -- lifecycle -------------------------------------------------------------------

    async def start(self) -> None:
        self.llm.migrate()  # the built-in AI providers, the model selection (hub/llm/registry.py)
        self.agents.start_core()
        for tool in self.tools():
            self.agents.ensure_tool_supervisor(tool)
        self.agents.start_custom()
        flows.reset_running(self)
        teams.reset_running(self)
        from . import dashboards

        dashboards.migrate(self)  # the shared Overview dashboard, once (R4-DASH 5.6)
        if self.settings.start_background_tasks:
            self._background.append(asyncio.create_task(self._health_loop()))
            self._background.append(asyncio.create_task(self._flow_loop()))
        await self.bus.tell("hub", "module:assets", "sync")
        await self.bus.tell("hub", "module:grc", "evaluate")
        self.activity("hub", "info", "Hub started", llm=self.llm.available, autonomy=self.prefs["autonomy"])

    async def stop(self) -> None:
        for task in self._background:
            task.cancel()
        for task in self._background:
            with contextlib.suppress(asyncio.CancelledError):
                await task
        await self.processes.stop_all()
        await self.agents.stop_all()
        self.store.close()

    def _paused(self, agent_id: str) -> bool:
        """A paused agent gets no scheduled work: it would only queue up and run all at once on resume (F25)."""
        agent = self.agents.get(agent_id)
        return agent is not None and agent.paused

    async def _health_loop(self) -> None:
        await asyncio.sleep(5)
        while True:
            if not self._paused("supervisor"):
                await self.bus.tell("hub", "supervisor", "health.sweep")
            await asyncio.sleep(self.settings.health_interval)

    async def _flow_loop(self) -> None:
        await asyncio.sleep(min(10.0, self.settings.flow_interval))
        while True:
            try:
                await self.tick_flows()
            except Exception as exc:  # the scheduler must outlive any single problem
                self.activity("hub", "error", f"Flow scheduler: {exc.__class__.__name__}: {exc}")
            try:
                await self.tick_agents()
            except Exception as exc:
                self.activity("hub", "error", f"Agent scheduler: {exc.__class__.__name__}: {exc}")
            await asyncio.sleep(self.settings.flow_interval)

    async def tick_agents(self, now: float | None = None) -> list[str]:
        """One scheduler pass for team agents: each enabled agent with a schedule and a standing task runs it when due
        (a message to the agent, so a slow model never blocks the loop)."""
        now = now or time.time()
        started = []
        for defn in teams.defs(self):
            if (teams.is_due(defn, now) and self.agents.get(defn.id) is not None
                    and teams.outside_guardrails(self, defn) is None):
                defn.running = now  # the next pass must not start it again while it works
                teams.save_def(self, defn)
                await self.bus.tell("hub", defn.id, "run", {"trigger": "schedule"})
                started.append(defn.id)
        return started

    async def tick_flows(self, now: float | None = None) -> dict[str, list[str]]:
        """One scheduler pass: start enabled flows that are due, poll running scans, and check the vulnerability
        SLA every hour. Runs are messages to the owning module agents, so a slow tool never blocks the loop."""
        now = now or time.time()
        started, polled = [], []
        for flow in flows.all_flows(self):
            if flow.job and flow.job.get("status") == "running":
                if not self._paused("module:vulns"):
                    await self.bus.tell("hub", "module:vulns", "scan.poll", {"flow_id": flow.id})
                    polled.append(flow.id)
            elif flows.is_due(flow, now) and not self._paused(flows.owner(flow)):
                flow.running = now  # the next pass must not start it again while the owner works on it
                flows.save(self, flow)
                await self.bus.tell("hub", flows.owner(flow), "flow.run", {"flow_id": flow.id, "trigger": "schedule"})
                started.append(flow.id)
        # the SLA check re-evaluates compliance too, so controls that depend on time alone follow within the hour
        # (HB-PO-3: a self-assessment last scored more than 12 months ago)
        if now - self._sla_checked >= SLA_CHECK_INTERVAL and not self._paused("module:vulns"):
            self._sla_checked = now
            await self.bus.tell("hub", "module:vulns", "sla.check")
        # device changes: expiry, scheduled changes whose maintenance window opened, changes left verifying
        if not self._paused("module:network"):
            await self.bus.tell("hub", "module:network", "changes.tick")
        # subsidiaries: offline sidecars, unusable tokens, expired enrollments and inbox messages, the circuit breaker
        from .subsidiary import governance as subsidiaries

        if subsidiaries.tick(self):
            await self.bus.tell("hub", "module:grc", "evaluate")
        if now - self._pruned >= PRUNE_INTERVAL:
            self._pruned = now
            self.prune_logs()
        return {"started": started, "polled": polled}

    def prune_logs(self) -> dict[str, int]:
        """Keep the agent message and tool event logs to their LOG_RETENTION size (the activity log and the command
        history are never pruned)."""
        pruned = {stream: self.store.prune(stream, keep) for stream, keep in LOG_RETENTION.items()}
        pruned["llm_usage_daily"] = llm_usage.prune_daily(self)
        pruned["agent_conversations"] = self.llm.memory.prune()  # stored chats past their agent's retention
        return pruned

    # -- preferences -----------------------------------------------------------------

    @property
    def prefs(self) -> dict[str, Any]:
        stored = (self.store.get("settings", "prefs") or {}).get("values", {})
        prefs = {"autonomy": self.settings.autonomy, "model": self.settings.model, **stored}
        prefs["vuln_sla_days"] = {**DEFAULT_SLA_DAYS, **(stored.get("vuln_sla_days") or {})}
        prefs["guardrails"] = guardrails.merged(stored.get("guardrails"))
        return prefs

    def update_prefs(self, actor: str, **values: Any) -> dict[str, Any]:
        values = {k: v for k, v in values.items() if v is not None}
        if "autonomy" in values and values["autonomy"] not in AUTONOMY_LEVELS:
            raise ValueError(f"autonomy must be one of {', '.join(AUTONOMY_LEVELS)}")
        stored = (self.store.get("settings", "prefs") or {}).get("values", {})
        self.store.put("settings", {"id": "prefs", "values": {**stored, **values}})
        self.llm.invalidate()  # resolved models may depend on preferences
        self.activity(actor, "info", "Settings changed: " + ", ".join(f"{k}={v}" for k, v in values.items()))
        return self.prefs

    def put_pref(self, key: str, value: Any) -> None:
        """Store (or with None, remove) one preference; callers log their own activity entry."""
        stored = dict((self.store.get("settings", "prefs") or {}).get("values", {}))
        if value is None:
            stored.pop(key, None)
        else:
            stored[key] = value
        self.store.put("settings", {"id": "prefs", "values": stored})

    # -- activity log ----------------------------------------------------------------

    def activity(self, actor: str, level: str, text: str, **data: Any) -> dict[str, Any]:
        entry = self.store.append("activity", {"actor": actor, "level": level, "text": text, "data": data})
        self.bus.publish("activity", entry)
        return entry

    # -- typed collections -----------------------------------------------------------

    def all(self, collection: str, model: type[M]) -> list[M]:
        return [model.model_validate(d) for d in self.store.list(collection)]

    def one(self, collection: str, doc_id: str, model: type[M]) -> M | None:
        doc = self.store.get(collection, doc_id)
        return model.model_validate(doc) if doc else None

    def save(self, collection: str, item: M, event: str | None = None) -> M:
        data = item.model_dump(mode="json")
        self.store.put(collection, data)
        self.bus.publish(event or collection, data)
        return item

    def tools(self) -> list[Tool]:
        return self.all("tools", Tool)

    def get_tool(self, tool_id: str) -> Tool | None:
        return self.one("tools", tool_id, Tool)

    def save_tool(self, tool: Tool) -> Tool:
        self.store.put("tools", tool.model_dump(mode="json"))
        self.bus.publish("tool", tool.public())  # every signed-in viewer gets it: no webhook URL (it may carry a token)
        return tool

    def hosts(self) -> list[Host]:
        return self.all("hosts", Host)

    def get_host(self, host_id: str) -> Host | None:
        return self.one("hosts", host_id, Host)

    def patches(self, tool_id: str | None = None) -> list[Patch]:
        items = self.all("patches", Patch)
        return [p for p in items if p.tool_id == tool_id] if tool_id else items

    def get_patch(self, patch_id: str) -> Patch | None:
        return self.one("patches", patch_id, Patch)

    def save_patch(self, patch: Patch) -> Patch:
        return self.save("patches", patch, "patch")
