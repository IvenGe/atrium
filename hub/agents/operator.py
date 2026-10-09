"""Operator Agent: runs commands on this machine or on remote hosts over SSH."""

from __future__ import annotations

from typing import Any

from .. import guardrails
from ..bus import Message
from ..execution import policy
from ..execution.runner import CommandResult, run_local, run_ssh
from .base import BaseAgent

# Built-in, read-only host discovery script used by the Asset Supervisor.
DISCOVERY_SCRIPT = (
    'echo "@@os"; cat /etc/os-release 2>/dev/null; '
    'echo "@@kernel"; uname -srm; '
    'echo "@@hostname"; hostname; '
    'echo "@@cpus"; nproc 2>/dev/null; '
    "echo \"@@memory_mb\"; free -m 2>/dev/null | awk '/Mem:/{print $2}'; "
    'echo "@@disk_root"; df -h / 2>/dev/null | tail -1; '
    'echo "@@uptime"; uptime -p 2>/dev/null || uptime'
)


def from_person(sender: str) -> bool:
    """A command comes from a person when a signed-in user sent it; tokens and agents are automation."""
    return sender.startswith("user:")


class OperatorAgent(BaseAgent):
    role = "operator"
    title = "Operator Agent"
    description = ("Runs commands on this machine or on registered hosts over SSH. Enforces the command policy: "
                   "blocked commands are refused, and state-changing commands wait for approval.")
    permissions = ("read", "commands")

    def __init__(self, hub):
        super().__init__(hub, "operator", "Operator Agent")

    # -- requests --------------------------------------------------------------------

    async def on_run(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Run a shell command. The sender decides the policy: "user:<name>" means a person typed it;
        API tokens ("token:<name>") are automation and follow the autonomy policy like agents."""
        command = str(body.get("command", "")).strip()
        target = body.get("target") or "local"
        trusted = bool(body.get("discovery")) and command == DISCOVERY_SCRIPT
        decision = self._decide(command, msg.sender, trusted)
        request = {"command": command, "target": target, "cwd": body.get("cwd"), "timeout": body.get("timeout", 120),
                   "reason": body.get("reason", ""), "origin": msg.sender}
        if decision.action == "deny":
            self.log("warn", f"Refused command from {msg.sender}: {command}", reason=decision.reason)
            return {"status": "denied", "reason": decision.reason, "risk": decision.risk}
        if decision.action == "approve":
            where = "this machine" if target == "local" else self._host_label(target)
            approval = self.hub.approvals.create(
                "command", f"Run on {where}: {command}",
                (request["reason"] + "\n" if request["reason"] else "") + decision.reason,
                request, requested_by=self.id,
            )
            return {"status": "pending_approval", "approval_id": approval.id, "reason": decision.reason, "risk": decision.risk}
        result = await self.execute(request)
        return {"status": "done", **result}

    async def on_launch(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Start a tool's long-running process."""
        tool = self.hub.get_tool(str(body.get("tool_id")))
        if tool is None or tool.manifest is None or not tool.manifest.launch.command:
            raise ValueError("This tool has no launch command in its manifest")
        command = tool.manifest.launch.command
        decision = self._decide(command, msg.sender)
        if decision.action == "deny":
            return {"status": "denied", "reason": decision.reason}
        payload = {"tool_id": tool.id, "origin": msg.sender}
        if decision.action == "approve":
            approval = self.hub.approvals.create("process", f"Start {tool.name}: {command}", decision.reason, payload, self.id)
            return {"status": "pending_approval", "approval_id": approval.id}
        return {"status": "started", **(await self._launch(tool.id))}

    async def on_stop_tool(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Stop a tool's process. Stopping changes state, so anyone but a person follows the autonomy level (team
        agents: unless team_actions_need_approval is off), like starting it."""
        tool_id = str(body.get("tool_id"))
        if not self.hub.processes.status(tool_id)["running"]:
            return {"status": "not_running", "stopped": False}
        autonomy = guardrails.effective_autonomy(self.hub, msg.sender)
        if not from_person(msg.sender) and autonomy != "autonomous":
            tool = self.hub.get_tool(tool_id)
            approval = self.hub.approvals.create(
                "process", f"Stop {tool.name if tool else tool_id}",
                f"Needs approval: stopping a tool's process changes state ({autonomy} mode).",
                {"tool_id": tool_id, "origin": msg.sender, "action": "stop"}, self.id)
            return {"status": "pending_approval", "approval_id": approval.id}
        return {"status": "stopped", "stopped": await self.hub.processes.stop(tool_id)}

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(body["approval_id"])
        if approval is None:
            return
        origin = approval.payload.get("origin", "supervisor")
        if not body.get("approved"):
            if not from_person(origin):
                await self.tell(origin, "command.completed", {"status": "rejected", "command": approval.payload.get("command")})
            return
        try:
            if approval.kind == "process":
                if approval.payload.get("action") == "stop":
                    result: dict[str, Any] = {"stopped": await self.hub.processes.stop(approval.payload["tool_id"])}
                else:
                    tool = self.hub.get_tool(approval.payload["tool_id"])
                    blocked = self._now_blocked((tool.manifest.launch.command or "") if tool and tool.manifest else "")
                    if blocked:
                        self.hub.approvals.complete(approval.id, False, {"error": blocked})
                        return
                    result = await self._launch(approval.payload["tool_id"])
                self.hub.approvals.complete(approval.id, True, result)
                return
            # the guardrail may have been switched back on since the request: a command it blocks never runs
            blocked = self._now_blocked(approval.payload["command"])
            if blocked:
                self.hub.approvals.complete(approval.id, False, {"error": blocked})
                self.log("warn", f"Refused approved command from {origin}: {approval.payload['command']}", reason=blocked)
                if not from_person(origin):
                    await self.tell(origin, "command.completed", {"status": "denied", "reason": blocked,
                                                                  "command": approval.payload["command"]})
                return
            result = await self.execute(approval.payload)
            self.hub.approvals.complete(approval.id, result["exit_code"] == 0, result)
            if not from_person(origin):
                await self.tell(origin, "command.completed", {"status": "done", **result})
        except Exception as exc:
            self.hub.approvals.complete(approval.id, False, {"error": str(exc)})
            raise

    # -- execution -------------------------------------------------------------------

    def _decide(self, command: str, sender: str, trusted: bool = False) -> policy.Decision:
        """The command policy for `sender`, with the guardrails: team agents ("agent:<slug>") follow the autonomy
        level unless team_actions_need_approval is off, and blocked patterns stay refused while
        block_catastrophic_commands is on."""
        return policy.decide(command, guardrails.effective_autonomy(self.hub, sender), from_person=from_person(sender),
                             trusted=trusted, block_catastrophic=bool(guardrails.value(self.hub, "block_catastrophic_commands")))

    def _now_blocked(self, command: str) -> str | None:
        """Why an approved command is refused after all - the block_catastrophic_commands guardrail as it is now (it
        may have been switched back on while the approval waited) - or None."""
        if not command.strip():
            return None
        risk, why = policy.classify(command, block_catastrophic=bool(guardrails.value(self.hub, "block_catastrophic_commands")))
        return f"Blocked by the block_catastrophic_commands guardrail: {why}" if risk == "blocked" else None

    async def execute(self, request: dict[str, Any]) -> dict[str, Any]:
        target = request.get("target") or "local"
        command = request["command"]
        timeout = float(request.get("timeout") or 120)
        if target == "local":
            result = await run_local(command, cwd=request.get("cwd"), timeout=timeout)
        else:
            host = self.hub.get_host(target)
            if host is None:
                raise ValueError(f"Unknown host '{target}'")
            try:
                result = await run_ssh(host, command, timeout=timeout)
            except Exception as exc:  # connection, auth and host-key errors
                result = CommandResult(-1, f"SSH error: {exc}", 0.0)
        record = {"target": target, "command": command, "origin": request.get("origin"), **result.as_dict()}
        entry = self.hub.store.append("commands", {**record, "output": result.output[-4000:]})
        self.hub.bus.publish("command", entry)
        level = "info" if result.exit_code == 0 else "warn"
        self.log(level, f"Ran on {target}: {command} (exit {result.exit_code}, {result.duration:.1f}s)")
        return record

    async def _launch(self, tool_id: str) -> dict[str, Any]:
        tool = self.hub.get_tool(tool_id)
        if tool is None or tool.manifest is None or not tool.manifest.launch.command:
            raise ValueError("This tool has no launch command")
        launch = tool.manifest.launch
        cwd = tool.path
        if cwd and launch.cwd and launch.cwd != ".":
            cwd = f"{cwd}/{launch.cwd}"
        env = dict(launch.env)
        if launch.port:
            env.setdefault("PORT", str(launch.port))
        return await self.hub.processes.start(tool.id, launch.command, cwd=cwd, env=env)

    def _host_label(self, host_id: str) -> str:
        host = self.hub.get_host(host_id)
        return f"{host.name} ({host.username}@{host.address})" if host else host_id
