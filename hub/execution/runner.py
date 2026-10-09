"""Low-level command execution: local shell, argv exec (no shell) and SSH."""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ..models import Host

MAX_OUTPUT = 64_000
IS_WINDOWS = sys.platform == "win32"


@dataclass
class CommandResult:
    exit_code: int
    output: str
    duration: float
    timed_out: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    return text[-MAX_OUTPUT:]


def new_group_kwargs() -> dict[str, Any]:
    """Start children in their own process group so the whole tree can be stopped."""
    if IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _kill_tree_sync(pid: int) -> None:
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


async def kill_tree(pid: int) -> None:
    await asyncio.to_thread(_kill_tree_sync, pid)


async def run_local(
    command: str, cwd: str | None = None, timeout: float = 120, env: dict[str, str] | None = None
) -> CommandResult:
    started = time.monotonic()
    proc = await asyncio.create_subprocess_shell(
        command,
        cwd=cwd or None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, **(env or {})},
        **new_group_kwargs(),
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        await kill_tree(proc.pid)
        await proc.wait()
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)
    return CommandResult(proc.returncode or 0, _decode(out), time.monotonic() - started)


async def run_exec(args: list[str], cwd: str | Path | None = None, timeout: float = 600) -> CommandResult:
    """Run a program with an argv list - no shell, so arguments cannot inject commands."""
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        await kill_tree(proc.pid)
        await proc.wait()
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)
    return CommandResult(proc.returncode or 0, _decode(out), time.monotonic() - started)


async def run_ssh(host: Host, command: str, timeout: float = 120) -> CommandResult:
    try:
        import asyncssh
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("SSH support needs asyncssh: pip install 'atrium[ssh]'") from exc

    options: dict[str, Any] = {"host": host.address, "port": host.port, "username": host.username}
    if host.key_path:
        options["client_keys"] = [os.path.expanduser(host.key_path)]
    if not host.strict_host_keys:
        options["known_hosts"] = None

    started = time.monotonic()

    async def _run() -> CommandResult:
        async with asyncssh.connect(**options) as conn:
            res = await conn.run(command, check=False)
            output = _decode(res.stdout) + _decode(res.stderr)
            code = res.exit_status if res.exit_status is not None else -1
            return CommandResult(code, output[-MAX_OUTPUT:], time.monotonic() - started)

    try:
        return await asyncio.wait_for(_run(), timeout)
    except asyncio.TimeoutError:
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)
