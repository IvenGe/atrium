"""Bringing tools into the hub: GitHub repositories, local folders and SaaS services."""

from __future__ import annotations

import re
import shutil
import stat
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse

from pydantic import BaseModel

from ..execution.runner import run_exec
from ..models import Tool

if TYPE_CHECKING:
    from ..core import Hub

SHORTHAND = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
GIT_URL = re.compile(r"^(https://[^\s]+|git@[\w.-]+:[\w./-]+)$")


class ImportRequest(BaseModel):
    source_type: Literal["github", "local", "saas"]
    source: str
    name: str | None = None
    openapi_url: str | None = None
    branch: str | None = None


def normalize_git_url(source: str) -> str:
    value = source.strip()
    if SHORTHAND.match(value):
        return f"https://github.com/{value.removesuffix('.git')}.git"
    if value.startswith("-") or not GIT_URL.match(value):
        raise ValueError("Expected a git URL such as https://github.com/owner/repo or the shorthand owner/repo")
    return value


def normalize_saas_url(source: str) -> str:
    parsed = urlparse(source.strip())
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Expected the service URL, e.g. https://app.example.com")
    return source.strip().rstrip("/")


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug[:40] or "tool"


def derive_name(req: ImportRequest) -> str:
    if req.name:
        return req.name.strip()
    if req.source_type == "github":
        tail = req.source.rstrip("/").split("/")[-1].split(":")[-1]
        return tail.removesuffix(".git") or "repository"
    if req.source_type == "local":
        return Path(req.source).expanduser().name or "local project"
    host = urlparse(req.source).hostname or "service"
    parts = host.split(".")
    core = parts[-2] if len(parts) >= 2 else parts[0]
    return core.capitalize()


def validate(req: ImportRequest) -> ImportRequest:
    if req.source_type == "github":
        req.source = normalize_git_url(req.source)
    elif req.source_type == "saas":
        req.source = normalize_saas_url(req.source)
        if req.openapi_url:
            normalize_saas_url(req.openapi_url)
    else:
        path = Path(req.source.strip()).expanduser()
        if not path.is_dir():
            raise ValueError(f"Folder not found: {path}")
        req.source = str(path.resolve())
    if req.branch and (req.branch.startswith("-") or not re.match(r"^[\w./-]+$", req.branch)):
        raise ValueError("Invalid branch name")
    return req


def create_tool(hub: "Hub", req: ImportRequest) -> Tool:
    req = validate(req)
    name = derive_name(req)
    base = slugify(name)
    tool_id, n = base, 2
    while hub.get_tool(tool_id):
        tool_id, n = f"{base}-{n}", n + 1
    tool = Tool(id=tool_id, name=name, source_type=req.source_type, source=req.source, openapi_url=req.openapi_url)
    return hub.save_tool(tool)


def _force_remove(func, path, _exc) -> None:  # git marks pack files read-only on Windows
    Path(path).chmod(stat.S_IWRITE)
    func(path)


def remove_tree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, onexc=_force_remove)


async def materialize(hub: "Hub", tool: Tool, branch: str | None = None) -> Tool:
    """Make the tool's files available to the hub (clone, or point at the local folder)."""
    if tool.source_type == "github":
        dest = hub.settings.workspace / "tools" / tool.id
        remove_tree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        args = ["git", "clone", "--depth", "1"]
        if branch:
            args += ["--branch", branch]
        args += ["--", tool.source, str(dest)]
        result = await run_exec(args, timeout=900)
        if result.exit_code != 0:
            tool.status, tool.error = "error", f"git clone failed: {result.output.strip()[-600:]}"
            return hub.save_tool(tool)
        tool.path = str(dest)
    elif tool.source_type == "local":
        tool.path = tool.source
    tool.status = "analyzing"
    return hub.save_tool(tool)
