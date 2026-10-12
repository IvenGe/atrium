"""Whether this machine can run a tool's launch command."""

from __future__ import annotations

import shutil
from pathlib import Path


def runtime_problem(command: str | None) -> str | None:
    """Why `command` cannot even be started here, or None when it can be tried."""
    program = _program(command)
    if program == "docker" and shutil.which("docker") is None:
        return ("Docker is not installed on this machine, so this app cannot be started here. "
                "Connect the portal to a server where it is already running.")
    return None


def _program(command: str | None) -> str:
    token = (command or "").strip().split(None, 1)[0] if (command or "").strip() else ""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        token = token[1:-1]
    return Path(token).name
