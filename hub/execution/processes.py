"""Long-running tool processes started from the hub (the "open the app" button)."""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .runner import kill_tree, new_group_kwargs

if TYPE_CHECKING:
    from ..core import Hub


@dataclass
class ManagedProcess:
    tool_id: str
    command: str
    cwd: str | None
    proc: asyncio.subprocess.Process
    started_at: float = field(default_factory=time.time)
    lines: deque[str] = field(default_factory=lambda: deque(maxlen=2000))
    exit_code: int | None = None
    reader: asyncio.Task[None] | None = None


class ProcessManager:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._procs: dict[str, ManagedProcess] = {}

    def status(self, tool_id: str) -> dict[str, Any]:
        mp = self._procs.get(tool_id)
        if not mp:
            return {"running": False}
        return {
            "running": mp.exit_code is None,
            "pid": mp.proc.pid,
            "command": mp.command,
            "started_at": mp.started_at,
            "exit_code": mp.exit_code,
        }

    def logs(self, tool_id: str, lines: int = 200) -> list[str]:
        mp = self._procs.get(tool_id)
        return list(mp.lines)[-lines:] if mp else []

    async def start(self, tool_id: str, command: str, cwd: str | None = None, env: dict[str, str] | None = None) -> dict[str, Any]:
        current = self._procs.get(tool_id)
        if current and current.exit_code is None:
            return self.status(tool_id)
        proc = await asyncio.create_subprocess_shell(
            command,
            cwd=cwd or None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env={**os.environ, **(env or {})},
            **new_group_kwargs(),
        )
        mp = ManagedProcess(tool_id=tool_id, command=command, cwd=cwd, proc=proc)
        mp.reader = asyncio.create_task(self._pump(mp))
        self._procs[tool_id] = mp
        self._set_running(tool_id, True)
        self.hub.activity(f"tool:{tool_id}", "info", f"Started: {command}", pid=proc.pid)
        return self.status(tool_id)

    async def stop(self, tool_id: str) -> bool:
        mp = self._procs.get(tool_id)
        if not mp or mp.exit_code is not None:
            return False
        await kill_tree(mp.proc.pid)
        try:
            await asyncio.wait_for(mp.proc.wait(), 10)
        except asyncio.TimeoutError:
            mp.proc.kill()
        return True

    async def stop_all(self) -> None:
        for tool_id in list(self._procs):
            await self.stop(tool_id)

    async def _pump(self, mp: ManagedProcess) -> None:
        assert mp.proc.stdout is not None
        while True:
            line = await mp.proc.stdout.readline()
            if not line:
                break
            mp.lines.append(line.decode("utf-8", errors="replace").rstrip())
        mp.exit_code = await mp.proc.wait()
        self._set_running(mp.tool_id, False)
        self.hub.activity(f"tool:{mp.tool_id}", "info", f"Process exited with code {mp.exit_code}")

    def _set_running(self, tool_id: str, running: bool) -> None:
        tool = self.hub.get_tool(tool_id)
        if tool:
            tool.running = running
            self.hub.save_tool(tool)
