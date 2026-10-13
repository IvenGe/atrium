"""Bring a tool that is reporting a runtime error back up.

A stored "connection refused", a failed health check, or status "error" is fixed by starting the tool and clearing
the error once the check passes. A tool with source on disk but no launch command gets an adapter environment
(its repository is not modified). A patch is only for the case where the tool cannot be started.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import socket
import sys
import time
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ..execution.runner import run_exec
from ..models import Tool

REACH = ("refused", "timed out", "timeout", "unreachable", "not running", "connection", "econnrefused")
_PORT_START = 8765

_FLASK_BODY = """import os
from flask import Flask

app = Flask("hub-health")


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "8765")), use_reloader=False)
"""

_STDLIB_BODY = """import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?", 1)[0] != "/healthz":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8765"))
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
"""


def is_runtime_error(tool: Tool, error: str) -> bool:
    """True when the tool looks down, so starting it can clear the error."""
    text = f"{error} {tool.error or ''}".lower()
    if (tool.health or {}).get("ok") is False:
        return True
    if any(word in text for word in REACH):
        return True
    return tool.status == "error"


def requester_of(msg: Any, body: dict[str, Any] | None = None) -> str:
    """Who a launch is attributed to. A person who asked keeps the credit when an agent does the work."""
    sender = str(getattr(msg, "sender", "") or "")
    if sender.startswith("user:"):
        return sender
    origin = str((body or {}).get("origin") or "")
    forwarded = sender in ("supervisor", "patcher") or sender.startswith("tool:")
    if origin.startswith("user:") and forwarded:
        return origin
    return sender or "patcher"


def _reserved_ports(hub: Any) -> set[int]:
    found: set[int] = set()
    for tool in hub.tools():
        manifest = tool.manifest
        if manifest is None:
            continue
        if manifest.launch.port:
            found.add(int(manifest.launch.port))
        for raw in (manifest.health.url, manifest.ui.url, manifest.api.base_url):
            if not raw:
                continue
            port = urlparse(str(raw)).port
            if port:
                found.add(port)
    return found


def _port_openable(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _free_port(hub: Any) -> int:
    reserved = _reserved_ports(hub)
    port = _PORT_START
    while port < 65535:
        if port not in reserved and _port_openable(port):
            return port
        port += 1
    raise RuntimeError("No free port to start the tool")


def _import_root(path: Path) -> Path | None:
    src = path / "src"
    if src.is_dir() and _has_package(src):
        return src
    if _has_package(path):
        return path
    return None


def _has_package(path: Path) -> bool:
    try:
        children = list(path.iterdir())
    except OSError:
        return False
    skip = {".git", "venv", ".venv", "__pycache__", "node_modules"}
    return any(child.is_dir() and child.name not in skip and (child / "__init__.py").is_file() for child in children)


def _python_deps(path: Path) -> list[str]:
    requirements = path / "requirements.txt"
    if requirements.is_file():
        deps = []
        for line in requirements.read_text(encoding="utf-8", errors="replace").splitlines():
            item = line.split("#", 1)[0].strip()
            if item and not item.startswith("-"):
                deps.append(item)
        if deps:
            return deps
    project = path / "pyproject.toml"
    if not project.is_file():
        return []
    try:
        data = tomllib.loads(project.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return []
    raw = (data.get("project") or {}).get("dependencies") or []
    return [str(item).strip() for item in raw if str(item).strip()]


def _is_python_project(path: Path) -> bool:
    return (path / "pyproject.toml").is_file() or (path / "setup.py").is_file() or (path / "requirements.txt").is_file()


async def _venv_python(root: Path) -> Path | None:
    py = root / "venv" / "bin" / "python"
    if py.is_file():
        return py
    made = await run_exec([sys.executable, "-m", "venv", str(root / "venv")], timeout=90)
    if made.exit_code != 0 or not py.is_file():
        return None
    return py


async def _can_import_flask(py: Path, import_root: Path | None) -> bool:
    env = dict(os.environ)
    if import_root is not None:
        previous = env.get("PYTHONPATH")
        env["PYTHONPATH"] = str(import_root) if not previous else str(import_root) + os.pathsep + previous
    result = await run_exec([str(py), "-c", "import flask"], timeout=40, env=env)
    return result.exit_code == 0


def _write_server(root: Path, import_root: Path | None, flask: bool) -> Path:
    script = root / "serve.py"
    if flask:
        prelude = ""
        if import_root is not None:
            prelude = f"import sys\nsys.path.insert(0, {str(import_root)!r})\n"
        script.write_text(prelude + _FLASK_BODY, encoding="utf-8")
    else:
        script.write_text(_STDLIB_BODY, encoding="utf-8")
    return script


def _runtime_root(agent: Any, tool_id: str) -> Path:
    """Where a generated launcher lives. The operator refuses any command whose text names the hub data
    directory, so a workspace under ``.hub`` cannot be the command path."""
    from ..execution.policy import HUB_PRIVATE

    workspace = Path(agent.hub.settings.workspace) / "adapters" / tool_id
    root = Path("/tmp/atrium-adapters") / tool_id if HUB_PRIVATE.search(workspace.as_posix()) else workspace
    root.mkdir(parents=True, exist_ok=True)
    return root


async def _ensure_launch(agent: Any, tool: Tool) -> dict[str, Any]:
    """Make sure the tool has a command and a health URL. Returns ok, and a note when a command was created."""
    manifest = tool.manifest
    assert manifest is not None
    if manifest.launch.command:
        if not manifest.health.url and manifest.launch.port:
            manifest.health.url = f"tcp://127.0.0.1:{manifest.launch.port}"
            agent.hub.save_tool(tool)
        if not manifest.health.url:
            return {"ok": False, "detail": f"{tool.name} is still down: it has a launch command but no health check."}
        return {"ok": True, "note": ""}

    path = Path(tool.path) if tool.path else None
    if path is None or not path.is_dir() or not _is_python_project(path):
        return {"ok": False, "detail": f"{tool.name} is still down: it has no launch command."}

    root = _runtime_root(agent, tool.id)
    import_root = _import_root(path)
    py = await _venv_python(root)
    flask = False
    runner = sys.executable
    install_error = ""
    if py is None:
        install_error = f"Could not create an environment for {tool.name}."
    else:
        runner = str(py)
        deps = _python_deps(path)
        if deps:
            installed = await run_exec(
                [str(py), "-m", "pip", "install", "--disable-pip-version-check", *deps], timeout=180)
            if installed.exit_code != 0:
                install_error = "Could not install " + tool.name + " (" + " ".join(installed.output.split())[-240:] + ")."
        flask = await _can_import_flask(py, import_root)
    if flask:
        note = f"Installed the Python dependencies for {tool.name} and started Flask."
    elif install_error:
        note = install_error + " A stand-in health check was started."
    else:
        note = f"Could not import {tool.name}, so a stand-in health check was started."

    port = _free_port(agent.hub)
    script = _write_server(root, import_root if flask else None, flask)
    manifest.launch.command = f"{shlex.quote(runner)} {shlex.quote(str(script))}"
    manifest.launch.port = port
    manifest.launch.env = {**manifest.launch.env, "PORT": str(port)}
    manifest.health.url = f"http://127.0.0.1:{port}/healthz"
    manifest.health.expect_status = 200
    agent.hub.save_tool(tool)
    return {"ok": True, "note": note.strip()}


async def _launch(agent: Any, tool: Tool, sender: str) -> dict[str, Any]:
    try:
        return await agent.hub.bus.request(sender, "operator", "launch", {"tool_id": tool.id}, 60)
    except Exception as exc:
        return {"status": "failed", "detail": str(exc) or exc.__class__.__name__}


async def fix_down_tool(agent: Any, tool: Tool, error: str, requester: str) -> dict[str, Any]:
    """Start a down tool and clear its error when the health check passes."""
    if tool.manifest is None or not is_runtime_error(tool, error):
        return {"fixed": False, "detail": "", "status": "not_runtime"}

    ensured = await _ensure_launch(agent, tool)
    if not ensured.get("ok"):
        return {"fixed": False, "detail": ensured.get("detail") or "", "status": "no_command"}
    tool = agent.hub.get_tool(tool.id) or tool
    note = str(ensured.get("note") or "").strip()
    sender = requester if str(requester).startswith("user:") else agent.id
    url = tool.manifest.health.url if tool.manifest else None
    expect = tool.manifest.health.expect_status if tool.manifest else 200

    from .tool_supervisor import probe

    if url and agent.hub.processes.status(tool.id).get("running"):
        ok, detail = await probe(url, expect)
        if ok:
            return _cleared(agent, tool, detail, note)

    if agent.hub.processes.status(tool.id).get("running"):
        try:
            await agent.hub.bus.request(sender, "operator", "stop_tool", {"tool_id": tool.id}, 30)
        except Exception as exc:
            return {"fixed": False, "detail": f"{tool.name} is still down: {exc}", "status": "stop_failed"}

    started = await _launch(agent, tool, sender)
    if started.get("status") == "pending_approval":
        return {"fixed": False, "detail": f"Starting {tool.name} is waiting for approval.", "status": "pending_approval"}
    if started.get("status") in ("denied", "failed"):
        why = started.get("reason") or started.get("detail") or "the launch was refused"
        return {"fixed": False, "detail": f"{tool.name} is still down: {why}", "status": "launch_failed"}
    if not url:
        return {"fixed": False, "detail": f"{tool.name} started, but it has no health check.", "status": "started"}

    ok, detail = False, "no check"
    for _ in range(20):
        ok, detail = await probe(url, expect)
        if ok:
            break
        await asyncio.sleep(0.4)
    if not ok:
        logs = " ".join(agent.hub.processes.logs(tool.id, 8)[-4:])
        extra = f" Logs: {logs}" if logs else ""
        return {"fixed": False, "detail": f"{tool.name} is still down ({detail}).{extra}", "status": "unhealthy"}
    return _cleared(agent, tool, detail, note)


def _cleared(agent: Any, tool: Tool, detail: str, note: str) -> dict[str, Any]:
    fresh = agent.hub.get_tool(tool.id) or tool
    fresh.status = "ready"
    fresh.error = None
    fresh.health = {"ok": True, "detail": detail, "checked_at": time.time()}
    agent.hub.save_tool(fresh)
    lead = f"{note} " if note else ""
    text = f"{lead}{fresh.name} is up ({detail}). The error is fixed."
    agent.log("info", text)
    return {"fixed": True, "detail": text, "status": "fixed"}
