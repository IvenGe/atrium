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
from ..connectors.netmodel import RESERVED_ACTIONS
from ..integration import connections, network
from ..integration.analyzer import analyze_repo, analyze_saas, list_files, readme_summary
from ..models import AGENT_PERMISSIONS, Manifest, Tool
from . import teams
from .base import BaseAgent
from .patcher import describe_patches

PUSH_ACTIONS = ("created", "updated", "skipped", "failed")


def _side_effect_allowed(sender: str, name: str) -> bool:
    """A person may start a side-effecting action. A scan is started only by the Vulnerability Supervisor,
    which is the scan approval path. Every other agent is refused."""
    if sender.startswith("user:"):
        return True
    return name == "scan" and sender == "module:vulns"


def guardrails_on(hub) -> bool:
    return bool(hub.prefs["guardrails"].get("device_changes", False))


def _change_visible(change: dict[str, Any], record: dict[str, Any]) -> bool:
    rules = record.get("rules") or []
    if change.get("op") == "allow":
        mark = f"atrium:{change['id']}"
        return any(mark in str(r.get("description") or "") for r in rules)
    wanted = {ref.get("id") for op in change.get("ops") or [] for ref in op.get("rules") or []}
    found = [r for r in rules if r.get("id") in wanted]
    return bool(found) and all(r.get("enabled", True) is False for r in found)

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

    async def direct_chat(self, text: str, msg: Message) -> dict[str, Any]:
        """A person talking to this tool's supervisor. Changes go to the Operator or the Patch Agent, then up."""
        tool = self._tool()
        low = text.lower().strip()
        if not low or low in ("help", "?", "hi", "hello"):
            return {"reply": (f"I am the supervisor of **{tool.name}**. Say `health`, `status`, `start`, `stop`, or `fix`. "
                              "I report what I find to the Hub Supervisor."), "mode": "rules"}
        if low in ("status", "describe", "report", "overview"):
            error = tool.error
            return {"reply": f"**{tool.name}** is {tool.status}." + (f" Error: {error}" if error else " No error."),
                    "mode": "rules"}
        if low == "health":
            health = await self.on_health({}, msg)
            detail = health.get("detail") or "checked"
            reply = f"**{tool.name}**: {detail}"
            if health.get("ok") is False or tool.error:
                asked = await self._ask_patcher(tool, str(tool.error or detail), msg)
                reply += "\n\n" + asked
            return {"reply": reply, "mode": "team" if health.get("ok") is False or tool.error else "rules",
                    "delegated": [f"patcher:{tool.id}"] if health.get("ok") is False or tool.error else []}
        if low in ("start", "stop"):
            result = await (self.on_start if low == "start" else self.on_stop)({}, msg)
            return {"reply": f"{low.capitalize()} **{tool.name}**: {result.get('status', result)}", "mode": "rules",
                    "delegated": ["operator"]}
        if any(word in low for word in ("fix", "error", "patch", "repair", "broken", "bug")):
            note = tool.error or (str((tool.health or {}).get("detail")) if (tool.health or {}).get("ok") is False else "")
            return {"reply": await self._ask_patcher(tool, note, msg), "mode": "team",
                    "delegated": [f"patcher:{tool.id}"]}
        return {"reply": f"Say `health`, `status`, `start`, `stop`, or `fix` for **{tool.name}**.", "mode": "rules"}

    async def _ask_patcher(self, tool: Tool, error: str, msg: Message) -> str:
        result = await self.ask("patcher", "propose", {"tool_id": tool.id, "error": error}, timeout=90)
        outcome = describe_patches(self.hub, result.get("patches") or [])
        if outcome.startswith("no new patch"):
            return f"The Patch Agent has nothing new for **{tool.name}**. One may already be waiting in Approvals."
        return f"I asked the Patch Agent to patch **{tool.name}**: {outcome}"

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
            rationale = (f"{tool.name} looks like a {(teams.category_title(self.hub, category) or category).lower()} tool, "
                         f"so its team gets: {roles}."
                         if category else f"No specialised template fits {tool.name}; every tool gets a maintainer.")
        asker = teams.get_def(self.hub, msg.sender)  # a team agent asked: the members get no more than it has
        if asker is not None:
            rationale += f" Requested by {asker.name}."
        result = teams.propose_members(self.hub, requested_by=self.id, parent=self.id, members=members, designer=used,
                                       rationale=rationale, tool_id=tool.id, category=category,
                                       on_behalf_of=asker.id if asker else None)
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
            out = {"ok": bool(result.get("ok")), "detail": redact(result.get("detail", ""), connector.secrets),
                   "checks": checks, "domains": {d: ops for d, ops in domains.items() if ops}}
            if "network" in out["domains"]:  # what this device and credential allow (never more than declared)
                out["network_write"] = network.narrow_write(connector, result.get("network_write", ...))
            return out

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
            if name in RESERVED_ACTIONS:  # device changes and backups only go through the network change path
                raise ConnectorError(f"'{name}' is not a connector action: device changes need an approved change")
            if name not in connector.actions:
                raise ConnectorError(f"{connector.title} has no action '{name}'")
            if name in connector.side_effects and not _side_effect_allowed(msg.sender, name):
                raise ConnectorError(f"'{name}' changes the tool. A person starts it, or it goes through its "
                                     "approval (scans are started by the Vulnerability Supervisor).")
            result = await connector.action(name, params)
            return {"result": result if isinstance(result, dict) else {"value": result}}

        return await self._connector("action", run)

    # -- network devices: configuration backups (device changes: see hub/integration/network.py) ---------------

    async def on_network_backup(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Take a configuration backup and store it encrypted (collection device_backups). Only the Network
        Supervisor asks; the reply carries the backup's metadata - the content never travels on the bus."""
        if msg.sender != "module:network":
            raise ValueError("Device backups are taken by the Network Supervisor")

        async def run(connector):
            if not connector.implements("backup"):
                raise ConnectorError(f"{connector.title} cannot take configuration backups")
            taken = await connector.backup()
            meta = network.store_backup(self.hub, self.tool_id, taken, reason=str(body.get("reason") or "manual"),
                                        actor=str(body.get("actor") or msg.sender), change_id=body.get("change_id"))
            return {"backup": meta}

        return await self._connector("backup", run)

    def _only_network(self, msg: Message) -> None:
        if msg.sender != "module:network":
            raise ValueError("Device changes are applied by the Network Supervisor")

    def _bound_change(self, body: dict[str, Any]):
        from ..integration import changes

        change = changes.get(self.hub, str(body.get("change_id") or ""))
        if change is None or change.get("firewall") != self.tool_id:
            raise ValueError("Unknown network change for this device")
        approval = self.hub.approvals.get(change.get("approval_id") or "")
        if approval is None or changes.binding_ok(change, approval):
            raise ValueError("This change is not bound to an approved revision")
        if changes.approval_expired(self.hub, approval):
            raise ValueError("This change's approval has expired")
        if not guardrails_on(self.hub):
            raise ValueError("Device changes are off")
        return change

    async def on_network_preview(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._only_network(msg)
        ops = body.get("ops") or []

        async def run(connector):
            if not connector.implements("preview_change"):
                return {"steps": [], "notes": ["this connector cannot preview a change"], "problems": []}
            snap = network.snapshot(self.hub, self.tool_id) or {}
            return await connector.preview_change(ops, snap.get("record") or {})

        return await self._connector("preview", run)

    async def on_network_apply(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._only_network(msg)
        change = self._bound_change(body)

        async def run(connector):
            backup = network.load_backup(self.hub, body["backup_id"]) if body.get("backup_id") else None
            result = await connector.apply_change(change.get("ops") or [], str(change.get("base_revision") or ""), backup)
            return {"result": result}

        return await self._connector("apply", run)

    async def on_network_verify(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """A new connection: the hub can still authenticate, and the change is visible on a fresh read."""
        self._only_network(msg)
        change = self._bound_change(body)

        async def run(connector):
            tested = await connector.test()
            if not tested.get("ok"):
                return {"ok": False, "reason": "the hub can no longer reach the device"}
            records = await connector.pull("network")
            record = records[0] if isinstance(records, list) and records else {}
            if not _change_visible(change, record):
                return {"ok": False, "reason": "a fresh read does not show the change"}
            network.ingest(self.hub, self.tool_id, record, cause=change["id"])
            return {"ok": True}

        return await self._connector("verify", run)

    async def on_network_confirm(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._only_network(msg)
        self._bound_change(body)

        async def run(connector):
            result = await connector.confirm_change(str(body.get("token") or ""))
            return {"result": result}

        return await self._connector("confirm", run)

    async def on_network_rollback(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._only_network(msg)

        async def run(connector):
            backup = network.load_backup(self.hub, body["backup_id"]) if body.get("backup_id") else None
            result = await connector.rollback_change(str(body.get("token") or ""), backup)
            return {"result": result}

        return await self._connector("rollback", run)

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
