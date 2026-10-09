"""Tool Supervisor: one per imported application, responsible for that application."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..bus import Message
from ..connectors.base import ConnectorError, check, normalize, redact
from ..integration import connections
from ..integration.analyzer import analyze_repo, analyze_saas, list_files, readme_summary
from ..models import AGENT_PERMISSIONS, Manifest, Tool
from . import teams
from .base import BaseAgent

PUSH_ACTIONS = ("created", "updated", "skipped", "failed")

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

    permissions = AGENT_PERMISSIONS  # it leads its tool's agent team

    def __init__(self, hub, tool_id: str, tool_name: str):
        super().__init__(hub, f"tool:{tool_id}", f"{tool_name} Supervisor", scope=tool_id)
        self.tool_id = tool_id

    @property
    def team(self) -> str:
        return self.tool_id

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

    # -- the tool's agent team ------------------------------------------------------------

    async def on_team_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Propose an AI agent team for this tool, from the templates for what the tool is or designed by Claude.
        `designer`: "auto" (Claude when available, else the templates), "templates" or "claude". Proposals the hub
        makes by itself (`auto`) happen once per tool and always use the templates: no model cost behind a background
        trigger."""
        tool = self._tool()
        auto = bool(body.get("auto"))
        if auto and teams.has_team_or_proposal(self.hub, tool.id):
            return {"proposed": False, "approval_id": None, "created": [], "members": [], "skipped": [],
                    "detail": f"{tool.name} already has an agent team or a team proposal."}
        pending = teams.pending_proposal(self.hub, tool.id)
        if pending:
            return {"proposed": False, "approval_id": pending, "created": [], "members": [], "skipped": [],
                    "detail": f"A team proposal for {tool.name} is already waiting for approval."}
        designer = "templates" if auto else str(body.get("designer") or "auto")
        if designer not in ("auto", "templates", "claude"):
            raise ValueError("designer is auto, templates or claude")
        if designer == "claude" and not self.hub.llm.available:
            raise ValueError("Designing a team with Claude needs ANTHROPIC_API_KEY; use the templates instead")
        category = teams.classify(self.hub, tool)
        space = teams.room(self.hub, tool.id)
        members, rationale, used = None, "", "templates"
        if designer != "templates" and self.hub.llm.available and space != 0:
            try:
                members, rationale = await teams.design_with_claude(self.hub, tool, category, self.model,
                                                                     8 if space is None else space)
                used = "claude"
            except Exception as exc:  # the templates always work
                self.log("warn", f"Claude could not design a team for {tool.name}, using the templates: {exc}")
        if members is None:
            members = teams.template_members(self.hub, tool, category)
            roles = ", ".join(m["title"].lower() for m in members)
            rationale = (f"{tool.name} looks like a {teams.CATEGORIES[category].lower()} tool, so its team gets: {roles}."
                         if category else f"No specialised template fits {tool.name}; every tool gets a maintainer.")
        result = teams.propose_members(self.hub, requested_by=self.id, parent=self.id, members=members, designer=used,
                                       rationale=rationale, tool_id=tool.id, category=category)
        if result["proposed"]:
            self.log("info", result["detail"], tool_id=tool.id)
        return result

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        teams.settle(self.hub, str(body.get("approval_id")), bool(body.get("approved")))

    # -- the tool's own API (connector) ------------------------------------------------
    # Only this agent decrypts the tool's credentials. Failures come back as {"failure": {message, status, excerpt}}
    # with every secret masked, so the module agents can record them and the repair loop can diagnose them.

    async def _connector(self, op: str, run, config_override: dict[str, Any] | None = None) -> dict[str, Any]:
        secrets: dict[str, str] = {}
        try:
            connector, secrets = connections.build(self.hub, self.tool_id, config_override)
            return await run(connector)
        except Exception as exc:  # a connector bug must not take the agent down or leak a secret
            failure = connections.safe_failure(exc, secrets)
            if not isinstance(exc, ConnectorError):
                self.log("warn", f"Connector {op} for {self.tool_id} failed unexpectedly: {failure['message']}")
            return {"failure": failure}

    async def on_connector_test(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        async def run(connector):
            result = await connector.test()
            checks = [check(str(c.get("name", "")), bool(c.get("ok")), redact(c.get("detail", ""), connector.secrets))
                      for c in result.get("checks") or [] if isinstance(c, dict)]
            domains = {str(d): sorted({str(o) for o in ops if o in ("read", "write")})
                       for d, ops in (result.get("domains") or {}).items() if isinstance(ops, (list, set, tuple))}
            return {"ok": bool(result.get("ok")), "detail": redact(result.get("detail", ""), connector.secrets),
                    "checks": checks, "domains": {d: ops for d, ops in domains.items() if ops}}

        result = await self._connector("test", run, body.get("config"))
        if "failure" in result:
            failure = result["failure"]
            return {"ok": False, "detail": failure["message"], "checks": [check("connection", False, failure["message"])],
                    "domains": {}, "failure": failure}
        return result

    async def on_connector_options(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        field = str(body.get("field", ""))

        async def run(connector):
            if field not in {f.name for f in connector.fields if f.options}:
                raise ConnectorError(f"{connector.title} has no choices for '{field}'")
            options = await connector.options(field)
            return {"options": [{"value": str(o.get("value")), "label": str(o.get("label") or o.get("value"))}
                                for o in options if isinstance(o, dict) and o.get("value") not in (None, "")][:1000]}

        return await self._connector("options", run)

    async def on_connector_pull(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        domain, since = str(body.get("domain")), body.get("since")

        async def run(connector):
            if "read" not in connector.domains().get(domain, []):
                raise ConnectorError(f"{connector.title} cannot read {domain}")
            records, errors = normalize(domain, await connector.pull(domain, since))
            return {"records": records, "errors": [redact(e, connector.secrets) for e in errors[:50]],
                    "dropped": len(errors)}

        return await self._connector("pull", run)

    async def on_connector_push(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        domain, records, links = str(body.get("domain")), list(body.get("records") or []), dict(body.get("links") or {})

        async def run(connector):
            if "write" not in connector.domains().get(domain, []):
                raise ConnectorError(f"{connector.title} cannot write {domain}")
            results = []
            for item in await connector.push(domain, records, links):
                if not isinstance(item, dict):
                    continue
                action = item.get("action") if item.get("action") in PUSH_ACTIONS else "failed"
                results.append({"hub_id": item.get("hub_id"), "external_id": item.get("external_id"), "action": action,
                                "error": redact(item["error"], connector.secrets)[:1000] if item.get("error") else None})
            return {"results": results}

        return await self._connector("push", run)

    async def on_connector_action(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        name, params = str(body.get("name")), dict(body.get("params") or {})

        async def run(connector):
            if name not in connector.actions:
                raise ConnectorError(f"{connector.title} has no action '{name}'")
            result = await connector.action(name, params)
            return {"result": result if isinstance(result, dict) else {"value": result}}

        return await self._connector("action", run)

    # -- internals -------------------------------------------------------------------

    @staticmethod
    def _carry_over(old: Manifest, new: Manifest) -> Manifest:
        if old.native:
            new.native = True
        if old.health.url and not new.health.url:
            new.health = old.health
        if old.auth.provider or (old.auth.notes and "adapter" in old.auth.notes):  # connected by an SSO patch
            new.auth = old.auth.model_copy(update={"env_keys": new.auth.env_keys})
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
