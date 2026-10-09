"""Creates, configures and tracks every agent in the hub."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .base import BaseAgent

if TYPE_CHECKING:
    from ..core import Hub
    from ..models import AgentDef, Tool


class AgentRegistry:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._agents: dict[str, BaseAgent] = {}

    def start_core(self) -> None:
        from .assets import AssetSupervisor
        from .extensions import ExtensionSupervisor
        from .grc import GrcSupervisor
        from .network import NetworkSupervisor
        from .operator import OperatorAgent
        from .patcher import PatchAgent
        from .people import PeopleSupervisor
        from .supervisor import HubSupervisor
        from .vulns import VulnerabilitySupervisor

        for agent in (HubSupervisor(self.hub), PatchAgent(self.hub), OperatorAgent(self.hub),
                      AssetSupervisor(self.hub), GrcSupervisor(self.hub), VulnerabilitySupervisor(self.hub),
                      PeopleSupervisor(self.hub), ExtensionSupervisor(self.hub), NetworkSupervisor(self.hub)):
            self.add(agent)

    def start_custom(self) -> None:
        """Start every custom (team) agent people or agents defined (collection "agent_defs")."""
        from . import teams

        for defn in teams.defs(self.hub):
            if defn.id not in self._agents:
                self.add_custom(defn)

    def add_custom(self, defn: "AgentDef") -> BaseAgent:
        from .custom import CustomAgent

        return self.add(CustomAgent(self.hub, defn))

    def add(self, agent: BaseAgent) -> BaseAgent:
        defn = getattr(agent, "defn", None)
        if defn is not None:  # a custom agent: its definition holds everything; disabled = paused
            paused = not defn.enabled
        else:
            saved = self.hub.store.get("agents", agent.id) or {}
            agent.model_override = saved.get("model")
            agent.instructions_override = saved.get("instructions")
            paused = bool(saved.get("paused"))
        agent.paused = paused
        if paused:
            agent.set_paused(True)
        self._agents[agent.id] = agent
        agent.start()
        self.hub.bus.publish("agent", agent.record())
        return agent

    def ensure_tool_supervisor(self, tool: "Tool") -> BaseAgent:
        from .tool_supervisor import ToolSupervisor

        agent_id = f"tool:{tool.id}"
        existing = self._agents.get(agent_id)
        if existing:
            return existing
        agent = self.add(ToolSupervisor(self.hub, tool.id, tool.name))
        self.hub.activity("supervisor", "info", f"Assigned {agent.name} to {tool.name}")
        return agent

    def get(self, agent_id: str) -> BaseAgent | None:
        return self._agents.get(agent_id)

    def all(self) -> list[BaseAgent]:
        return list(self._agents.values())

    def configure(self, agent_id: str, *, paused: bool | None = None, model: str | None = None,
                  instructions: str | None = None) -> dict[str, Any]:
        agent = self._agents.get(agent_id)
        if agent is None:
            raise KeyError(agent_id)
        if getattr(agent, "defn", None) is not None:  # custom agents keep their settings in their definition
            from . import teams

            changes = {"enabled": None if paused is None else not paused, "model": model, "instructions": instructions}
            teams.update(self.hub, agent_id, changes, "system")
            return agent.record()
        if paused is not None:
            agent.set_paused(paused)
        if model is not None:
            agent.model_override = model.strip() or None
        if instructions is not None:
            agent.instructions_override = instructions.strip() or None
        self.hub.store.put("agents", {
            "id": agent.id, "paused": agent.paused, "model": agent.model_override,
            "instructions": agent.instructions_override,
        })
        record = agent.record()
        self.hub.bus.publish("agent", record)
        return record

    async def remove(self, agent_id: str) -> None:
        agent = self._agents.pop(agent_id, None)
        if agent:
            await agent.stop()
            self.hub.store.delete("agents", agent_id)
            self.hub.bus.publish("agent_removed", {"id": agent_id})

    async def stop_all(self) -> None:
        for agent in list(self._agents.values()):
            await agent.stop()
        self._agents.clear()
