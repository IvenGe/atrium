"""The Hub runtime: shared state every agent and API route works through."""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, TypeVar

from pydantic import BaseModel

from .approvals import Approvals
from .bus import Bus
from .config import AUTONOMY_LEVELS, Settings
from .execution.processes import ProcessManager
from .integration.toolbus import ToolBus
from .llm import LLM
from .models import Host, Patch, Tool
from .store import Store

M = TypeVar("M", bound=BaseModel)


class Hub:
    def __init__(self, settings: Settings):
        from .agents.registry import AgentRegistry

        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        settings.workspace.mkdir(parents=True, exist_ok=True)
        self.store = Store(settings.db_path)
        self.bus = Bus(self.store)
        self.llm = LLM(self)
        self.approvals = Approvals(self)
        self.processes = ProcessManager(self)
        self.toolbus = ToolBus(self)
        self.agents = AgentRegistry(self)
        self._background: list[asyncio.Task[None]] = []

    # -- lifecycle -------------------------------------------------------------------

    async def start(self) -> None:
        self.agents.start_core()
        for tool in self.tools():
            self.agents.ensure_tool_supervisor(tool)
        if self.settings.start_background_tasks:
            self._background.append(asyncio.create_task(self._health_loop()))
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

    async def _health_loop(self) -> None:
        await asyncio.sleep(5)
        while True:
            await self.bus.tell("hub", "supervisor", "health.sweep")
            await asyncio.sleep(self.settings.health_interval)

    # -- preferences -----------------------------------------------------------------

    @property
    def prefs(self) -> dict[str, Any]:
        stored = (self.store.get("settings", "prefs") or {}).get("values", {})
        return {"autonomy": self.settings.autonomy, "model": self.settings.model, **stored}

    def update_prefs(self, **values: Any) -> dict[str, Any]:
        values = {k: v for k, v in values.items() if v is not None}
        if "autonomy" in values and values["autonomy"] not in AUTONOMY_LEVELS:
            raise ValueError(f"autonomy must be one of {', '.join(AUTONOMY_LEVELS)}")
        stored = (self.store.get("settings", "prefs") or {}).get("values", {})
        self.store.put("settings", {"id": "prefs", "values": {**stored, **values}})
        self.activity("user", "info", "Settings changed: " + ", ".join(f"{k}={v}" for k, v in values.items()))
        return self.prefs

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
        return self.save("tools", tool, "tool")

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
