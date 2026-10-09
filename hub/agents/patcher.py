"""Patch Agent: makes tools that do not fit the hub fit, with code patches and adapters."""

from __future__ import annotations

import difflib
from pathlib import Path
from typing import Any

from ..bus import Message
from ..integration.analyzer import list_files
from ..integration.patches import apply_patch, plan_patch, safe_relative
from ..models import FileChange, Patch, Tool
from ..store import new_id
from .base import BaseAgent

HEALTH_GOAL = (
    "Add a lightweight HTTP health endpoint at GET /healthz that returns status 200 with the JSON body "
    '{"status": "ok"} without authentication, using the framework the project already uses.'
)
ENTRY_HINTS = (
    "main.py", "app.py", "server.py", "asgi.py", "wsgi.py", "urls.py", "app/main.py", "src/main.py",
    "index.js", "server.js", "app.js", "src/index.js", "src/server.js", "src/app.js",
    "src/index.ts", "src/server.ts", "src/app.ts", "src/main.ts", "main.go", "cmd/server/main.go",
    "config/routes.rb", "routes/web.php", "src/main.rs", "package.json", "pyproject.toml",
)
PATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "rationale": {"type": "string"},
        "changes": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
        "health_path": {"type": "string"},
    },
    "required": ["title", "rationale", "changes", "health_path"],
    "additionalProperties": False,
}


class PatchAgent(BaseAgent):
    role = "patcher"
    title = "Patch Agent"
    uses_llm = True
    description = ("Closes integration gaps. Writes code patches on a separate git branch for tools with source code, "
                   "and adapters (health probes, SSO proxy, event pollers, API wrappers) for closed-source and SaaS tools.")
    default_instructions = (
        "You are the Patch Agent of an integration hub. You change other people's software, so be conservative: "
        "make the smallest change that achieves the goal, follow the project's existing style and framework, never "
        "remove functionality, never add secrets, and never touch files you were not shown unless you create them. "
        "Each change contains the complete new content of one file. Set health_path to the HTTP path of the health "
        "endpoint if the change adds one, otherwise to an empty string."
    )

    def __init__(self, hub):
        super().__init__(hub, "patcher", "Patch Agent")

    @property
    def hub_url(self) -> str:
        return f"http://{self.hub.settings.host}:{self.hub.settings.port}"

    # -- requests --------------------------------------------------------------------

    async def on_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool(body.get("tool_id"))
        fixes = body.get("fixes") or [c.fix for c in (tool.report.checks if tool.report else []) if c.fix and c.status != "pass"]
        others = [t for t in self.hub.tools() if t.id != tool.id]
        existing = {p.strategy for p in self.hub.patches(tool.id) if p.status in ("proposed", "applied")}
        created: list[Patch] = []
        for fix in dict.fromkeys(fixes):
            if fix in existing or (fix == "health_endpoint" and "health_probe" in existing):
                continue
            patch = None
            if fix == "health_endpoint" and self.hub.llm.available:
                try:
                    patch = await self.code_patch(tool, HEALTH_GOAL, strategy="health_endpoint")
                except Exception as exc:
                    self.log("warn", f"Code patch for {tool.name} failed, falling back to a probe adapter: {exc}")
            if patch is None:
                patch = plan_patch(tool, others, fix, self.hub_url)
            if patch is not None:
                created.append(await self._submit(tool, patch))
        if created:
            self.log("info", f"Proposed {len(created)} patch(es) for {tool.name}: " + "; ".join(p.title for p in created))
        return {"patches": [p.id for p in created]}

    async def on_custom(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Free-form patch request, e.g. from the Hub Supervisor chat. Needs Claude."""
        tool = self._tool(body.get("tool_id"))
        goal = str(body.get("goal") or "").strip()
        if not goal:
            raise ValueError("Describe what the patch should achieve")
        if not self.hub.llm.available:
            raise ValueError("Custom code patches need Claude - set ANTHROPIC_API_KEY")
        patch = await self.code_patch(tool, goal, strategy="custom")
        patch = await self._submit(tool, patch)
        return {"patch_id": patch.id, "title": patch.title, "status": patch.status}

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(body["approval_id"])
        patch = self.hub.get_patch(approval.payload.get("patch_id", "")) if approval else None
        if approval is None or patch is None:
            return
        if not body.get("approved"):
            patch.status = "rejected"
            self.hub.save_patch(patch)
            return
        await self._apply(patch, approval.id)

    # -- internals -------------------------------------------------------------------

    def _tool(self, tool_id: Any) -> Tool:
        tool = self.hub.get_tool(str(tool_id))
        if tool is None or tool.manifest is None:
            raise ValueError(f"Unknown or unanalysed tool '{tool_id}'")
        return tool

    async def _submit(self, tool: Tool, patch: Patch) -> Patch:
        patch.diff = render_diff(tool, patch)
        self.hub.save_patch(patch)
        if self.hub.prefs["autonomy"] == "autonomous":
            await self._apply(patch, None)
        else:
            self.hub.approvals.create("patch", f"Patch {tool.name}: {patch.title}", patch.rationale,
                                      {"patch_id": patch.id, "tool_id": tool.id}, self.id)
        return patch

    async def _apply(self, patch: Patch, approval_id: str | None) -> None:
        try:
            patch = await apply_patch(self.hub, patch)
        except Exception as exc:
            patch.status, patch.error = "failed", str(exc)
            self.hub.save_patch(patch)
            if approval_id:
                self.hub.approvals.complete(approval_id, False, {"error": str(exc)})
            raise
        where = f"branch {patch.branch}" if patch.branch else (patch.location or "hub manifest")
        self.log("info", f"Applied '{patch.title}' ({where})")
        if approval_id:
            self.hub.approvals.complete(approval_id, True, {"branch": patch.branch, "location": patch.location})
        await self.tell("supervisor", "tool.patched", {"tool_id": patch.tool_id, "patch_id": patch.id})

    async def code_patch(self, tool: Tool, goal: str, strategy: str) -> Patch:
        """Ask Claude for a source patch. Existing files may only be changed if Claude was shown them."""
        if not tool.path or tool.manifest is None or tool.manifest.kind != "oss":
            raise ValueError("Code patches need a tool with source code on disk")
        root = Path(tool.path)
        files = list_files(root, 2000)
        names = {f.as_posix() for f in files}
        context = [n for n in ENTRY_HINTS if n in names][:6]
        tree = "\n".join(sorted(names)[:400])
        shown = "\n\n".join(
            f'<file path="{n}">\n{(root / n).read_text(encoding="utf-8", errors="replace")[:15000]}\n</file>' for n in context
        )
        m = tool.manifest
        prompt = (
            f"<goal>{goal}</goal>\n\n"
            f"<tool name=\"{m.name}\" stack=\"{', '.join(m.stack)}\" port=\"{m.launch.port}\" "
            f"launch=\"{m.launch.command}\" />\n\n<file_tree>\n{tree}\n</file_tree>\n\n{shown}"
        )
        result = await self.hub.llm.json(system=self.instructions, prompt=prompt, schema=PATCH_SCHEMA,
                                         model=self.model, effort="high")
        changes: list[FileChange] = []
        for change in result.get("changes", [])[:10]:
            rel = safe_relative(change["path"]).as_posix()
            if rel in names and rel not in context:
                raise ValueError(f"Claude tried to rewrite {rel} without having seen it")
            if len(change["content"]) > 200_000:
                raise ValueError(f"Patch for {rel} is too large")
            changes.append(FileChange(path=rel, content=change["content"]))
        if not changes:
            raise ValueError("Claude proposed no changes")
        update: dict[str, Any] = {}
        health_path = (result.get("health_path") or "").strip()
        if health_path.startswith("/") and m.launch.port:
            update["health"] = {"url": f"http://localhost:{m.launch.port}{health_path}"}
        return Patch(id=new_id("p_"), tool_id=tool.id, title=result["title"][:120], rationale=result["rationale"],
                     strategy=strategy, target="repo", changes=changes, manifest_update=update)


def render_diff(tool: Tool, patch: Patch) -> str:
    chunks = []
    for change in patch.changes:
        old = ""
        if patch.target == "repo" and tool.path:
            existing = Path(tool.path) / change.path
            if existing.is_file():
                old = existing.read_text(encoding="utf-8", errors="replace")
        diff = difflib.unified_diff(
            old.splitlines(keepends=True), change.content.splitlines(keepends=True),
            fromfile=f"a/{change.path}" if old else "/dev/null", tofile=f"b/{change.path}",
        )
        chunks.append("".join(diff))
    return "\n".join(chunks)[:200_000]
