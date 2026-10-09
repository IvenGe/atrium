"""Tool Supervisor: one per imported application, responsible for that application."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..bus import Message
from ..integration.analyzer import analyze_repo, analyze_saas, list_files, readme_summary
from ..models import Manifest, Tool
from .base import BaseAgent

ENRICH_SCHEMA = {
    "type": "object",
    "properties": {
        "description": {"type": "string"},
        "provides": {"type": "array", "items": {"type": "string"}},
        "consumes": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["description", "provides", "consumes"],
    "additionalProperties": False,
}


class ToolSupervisor(BaseAgent):
    role = "tool-supervisor"
    title = "Tool Supervisor"
    uses_llm = True
    description = ("Responsible for one application: understands it, keeps its manifest current, watches its health, "
                   "starts and stops it, and reports integration problems to the Hub Supervisor.")
    default_instructions = (
        "You are the supervisor of a single application inside an integration hub. Describe what the application does "
        "in one or two plain sentences, and list the capabilities it provides to other tools and consumes from them, "
        "using dotted names such as auth.oidc, api.rest, webhooks, db.postgres, cache.redis, notify.email, storage.s3, "
        "chat, ticketing, docs.wiki, monitoring.metrics. Only list capabilities the evidence supports."
    )

    def __init__(self, hub, tool_id: str, tool_name: str):
        super().__init__(hub, f"tool:{tool_id}", f"{tool_name} Supervisor", scope=tool_id)
        self.tool_id = tool_id

    def _tool(self) -> Tool:
        tool = self.hub.get_tool(self.tool_id)
        if tool is None:
            raise ValueError(f"Tool {self.tool_id} no longer exists")
        return tool

    # -- requests --------------------------------------------------------------------

    async def on_analyze(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool()
        tool.status = "analyzing"
        self.hub.save_tool(tool)
        if tool.source_type == "saas":
            manifest, notes = await analyze_saas(tool.id, tool.name, tool.source, tool.openapi_url)
        else:
            if not tool.path or not Path(tool.path).is_dir():
                raise ValueError("The tool's files are not available")
            manifest, notes = await asyncio.to_thread(analyze_repo, Path(tool.path), tool.id, tool.name)
        if tool.manifest:  # keep hub-side decisions (applied patches, adopted manifest) across re-analysis
            manifest = self._carry_over(tool.manifest, manifest)
        if self.hub.llm.available and not manifest.native and tool.path:
            try:
                manifest = await self._enrich(manifest, Path(tool.path))
                notes.append("Description and capabilities refined with Claude.")
            except Exception as exc:
                notes.append(f"LLM enrichment skipped: {exc}")
        tool = self._tool()
        tool.manifest, tool.notes, tool.status, tool.error = manifest, notes, "ready", None
        if manifest.native and manifest.name:
            tool.name = manifest.name  # a tool that names itself in its manifest wins
        self.hub.save_tool(tool)
        self.log("info", f"Analysed {tool.name}: {manifest.kind}, stack {', '.join(manifest.stack) or 'unknown'}, "
                         f"SSO {manifest.auth.sso}, provides {', '.join(manifest.provides) or 'nothing detected'}")
        return {"manifest": manifest.model_dump(mode="json"), "notes": notes}

    async def on_describe(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool()
        return {"tool": tool.model_dump(mode="json"), "process": self.hub.processes.status(tool.id)}

    async def on_health(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool()
        url = tool.manifest.health.url if tool.manifest else None
        if not url:
            return {"ok": None, "detail": "No health check defined"}
        expect = tool.manifest.health.expect_status if tool.manifest else 200
        ok, detail = await probe(url, expect)
        previous = (tool.health or {}).get("ok")
        tool.health = {"ok": ok, "detail": detail, "checked_at": time.time()}
        self.hub.save_tool(tool)
        if previous is not None and previous != ok:
            self.log("info" if ok else "error", f"{tool.name} is {'healthy again' if ok else 'DOWN'}: {detail}")
        return tool.health

    async def on_start(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return await self.ask("operator", "launch", {"tool_id": self.tool_id})

    async def on_stop(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return await self.ask("operator", "stop_tool", {"tool_id": self.tool_id})

    # -- internals -------------------------------------------------------------------

    @staticmethod
    def _carry_over(old: Manifest, new: Manifest) -> Manifest:
        if old.native:
            new.native = True
        if old.health.url and not new.health.url:
            new.health = old.health
        if old.auth.notes and "adapter" in old.auth.notes:
            new.auth = old.auth
        if old.launch.port and old.launch.env.get("PORT") == str(old.launch.port):
            new.launch.port, new.launch.env, new.ui.url = old.launch.port, old.launch.env, old.ui.url
        new.events.emits = sorted(set(new.events.emits) | set(old.events.emits))
        return new

    async def _enrich(self, manifest: Manifest, root: Path) -> Manifest:
        files = "\n".join(f.as_posix() for f in list_files(root, 300))
        readme = ""
        for name in ("README.md", "readme.md", "README.rst", "README"):
            if (root / name).is_file():
                readme = (root / name).read_text(encoding="utf-8", errors="replace")[:8000]
                break
        prompt = (
            f"<inferred_manifest>\n{manifest.model_dump_json(include={'name', 'stack', 'provides', 'consumes', 'auth'})}\n"
            f"</inferred_manifest>\n<readme>\n{readme or readme_summary(root)}\n</readme>\n<files>\n{files}\n</files>"
        )
        result = await self.hub.llm.json(system=self.instructions, prompt=prompt, schema=ENRICH_SCHEMA,
                                         model=self.model, effort="low", max_tokens=4000)
        manifest.description = result["description"][:400] or manifest.description
        manifest.provides = sorted(set(manifest.provides) | {c for c in result["provides"] if c and len(c) < 40})
        manifest.consumes = sorted(set(manifest.consumes) | {c for c in result["consumes"] if c and len(c) < 40})
        return manifest


async def probe(url: str, expect_status: int = 200) -> tuple[bool, str]:
    parsed = urlparse(url)
    if parsed.scheme == "tcp":
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(parsed.hostname, parsed.port), 5)
            writer.close()
            return True, f"TCP {parsed.hostname}:{parsed.port} open"
        except (OSError, asyncio.TimeoutError) as exc:
            return False, f"TCP {parsed.hostname}:{parsed.port} closed ({exc.__class__.__name__})"
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            response = await client.get(url)
        ok = response.status_code == expect_status or (expect_status == 200 and response.status_code < 400)
        return ok, f"HTTP {response.status_code}"
    except httpx.HTTPError as exc:
        return False, str(exc) or exc.__class__.__name__
