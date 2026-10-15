"""Tool Supervisor: one per imported application, responsible for that application."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from ..approvals import sender_person
from ..bus import Message
from ..connectors.base import ConnectorError, check, normalize, redact
from ..connectors.netmodel import RESERVED_ACTIONS, ChangeError, parse_ops
from ..integration import changes, connections, network
from ..integration.analyzer import analyze_repo, analyze_saas, list_files, read_repo_file, readme_summary
from ..models import AGENT_PERMISSIONS, Manifest, Tool
from . import teams
from .base import BaseAgent

PUSH_ACTIONS = ("created", "updated", "skipped", "failed")
# approval kind of a side-effecting connector action -> the only agent that may ask for it (it applies that kind's
# approval policy), so team agents and other modules cannot bypass it; people may run them directly
ACTION_ROUTES = {"scan": "module:vulns"}

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
    purposes = ("generate",)
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
        if self.hub.llm.ready(self.id, "generate") and not manifest.native and tool.path:
            try:
                manifest, label = await self._enrich(manifest, Path(tool.path))
                notes.append(f"Description and capabilities refined with {label}.")
            except Exception as exc:
                notes.append(f"AI model enrichment skipped: {exc}")
        tool = self._tool()
        tool.manifest, tool.notes, tool.status, tool.error = manifest, notes, "ready", None
        if manifest.native and manifest.name:
            tool.name = manifest.name  # a tool that names itself in its manifest wins
        self.hub.save_tool(tool)
        self.log("info", f"Analysed {tool.name}: {manifest.kind}, stack {', '.join(manifest.stack) or 'unknown'}, "
                         f"SSO {manifest.auth.sso}, provides {', '.join(manifest.provides) or 'nothing detected'}")
        return {"manifest": manifest.public(), "notes": notes}  # the bus log is readable by viewers (F24)

    async def on_describe(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool()
        return {"tool": tool.public(), "process": self.hub.processes.status(tool.id)}

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
        # whoever asked: a person directly, or the person an agent relays (chat) - the Operator Agent judges by them (F1)
        person = msg.sender if sender_person(msg.sender) else body.get("requested_by")
        return await self.ask("operator", "launch", {"tool_id": self.tool_id, "requested_by": person})

    async def on_stop(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        return await self.ask("operator", "stop_tool", {"tool_id": self.tool_id})

    # -- the tool's agent team ------------------------------------------------------------

    async def on_team_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Propose an AI agent team for this tool, from the templates for what the tool is or designed by the AI model.
        `designer`: "auto" (the AI model when one is available, else the templates), "templates" or "model" ("claude"
        is accepted for it). Proposals the hub makes by itself (`auto`) happen once per tool and always use the
        templates: no model cost behind a background trigger."""
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
        designer = "model" if designer == "claude" else designer
        if designer not in ("auto", "templates", "model"):
            raise ValueError("designer is auto, templates or model")
        ready = self.hub.llm.ready(self.id, "generate")
        if designer == "model" and not ready:
            raise ValueError("Designing a team needs an AI model (Settings > AI providers); use the templates instead")
        category = teams.classify(self.hub, tool)
        space = teams.room(self.hub, tool.id)
        members, rationale, used, generated_by = None, "", "templates", None
        if designer != "templates" and ready and space != 0:
            try:
                members, rationale, generated_by = await teams.design_with_model(
                    self.hub, tool, category, 8 if space is None else space, self.id)
                used = "model"
            except Exception as exc:  # the templates always work
                self.log("warn", f"The AI model could not design a team for {tool.name}, using the templates: {exc}")
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
                                       on_behalf_of=asker.id if asker else None, generated_by=generated_by)
        if result["proposed"]:
            self.log("info", result["detail"], tool_id=tool.id)
        return result

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval_id, approved = str(body.get("approval_id")), bool(body.get("approved"))
        approval = self.hub.approvals.get(approval_id)
        kind = approval.kind if approval is not None else None
        if kind == "subsidiary_charter":  # it leads the tool's subsidiary: the charter comes into force
            from ..subsidiary import charter

            if approved:
                await charter.settle(self.hub, approval_id)
            else:
                charter.rejected(self.hub, approval_id)
            return
        if kind == "subsidiary_action" and approval is not None:  # a grant, or (API-only) the write itself
            from ..subsidiary import actions

            await actions.decided(self.hub, approval, approved, self)
            return
        teams.settle(self.hub, approval_id, approved)

    async def push_record(self, domain: str, record: dict[str, Any]) -> dict[str, Any]:
        """An approved in-tool write of the tool's API-only subsidiary: one record pushed with the connection's own
        credential (the subsidiary's sidecar only reads). {action, external_id, error} or {failure}."""
        async def run(connector):
            if "write" not in connector.domains().get(domain, []):
                raise ConnectorError(f"{connector.title} cannot write {domain}")
            items = [i for i in await connector.push(domain, [record], {}) if isinstance(i, dict)]
            item = items[0] if items else {"action": "failed", "error": "the connector returned nothing"}
            action = item.get("action") if item.get("action") in PUSH_ACTIONS else "failed"
            return {"action": action, "external_id": item.get("external_id"),
                    "error": redact(item["error"], connector.secrets)[:1000] if item.get("error") else None}

        return await self._connector("push", run)

    async def on_subsidiary_escalation(self, body: dict[str, Any], msg: Message) -> None:
        """An escalation from the tool's subsidiary (its text stays in its report: untrusted, never in a prompt)."""
        if msg.sender not in (f"subsidiary:{self.tool_id}", "hub"):
            return
        severity = str(body.get("severity") or "warning")
        self.log("error" if severity == "critical" else "warn",
                 f"The {self._tool().name} subsidiary escalated a matter ({severity}): see its reports",
                 report_id=str(body.get("report_id") or ""), subsidiary_id=str(body.get("subsidiary_id") or ""))

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
            if domain == "network" and msg.sender != "module:network":  # untrusted device text: never to other agents
                raise ConnectorError("Device configuration is read by the Network Supervisor only")
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

    def _action_refusal(self, name: str, kind: str, body: dict[str, Any], msg: Message) -> str | None:
        """Why a side-effecting action may not run for this sender (None: it may)."""
        if msg.sender.startswith(("user:", "token:")):
            return None
        route = ACTION_ROUTES.get(kind)
        if msg.sender != route:
            return (f"'{name}' changes something, so it only runs through the {kind} approval path "
                    f"({route or 'none'}), not for {msg.sender}")
        approval_id = body.get("approval_id")
        if approval_id:
            approval = self.hub.approvals.get(str(approval_id))
            if (approval is None or approval.kind != kind or approval.status not in ("approved", "done")
                    or approval.payload.get("tool_id") not in (None, self.tool_id)):
                return f"the approval given for '{name}' does not cover it"
        return None

    async def on_connector_action(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        name, params = str(body.get("name")), dict(body.get("params") or {})

        async def run(connector):
            if name in RESERVED_ACTIONS:  # device changes and backups only go through the network change path
                raise ConnectorError(f"'{name}' is not a connector action: device changes need an approved change")
            if name not in connector.actions:
                raise ConnectorError(f"{connector.title} has no action '{name}'")
            kind = connector.side_effect_actions.get(name)
            refusal = self._action_refusal(name, kind, body, msg) if kind else None
            if refusal:
                raise ConnectorError(f"Refused: {refusal}")
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
            try:
                meta = network.store_backup(self.hub, self.tool_id, taken, reason=str(body.get("reason") or "manual"),
                                            actor=str(body.get("actor") or msg.sender), change_id=body.get("change_id"))
            except ValueError as exc:  # empty, too large or a checksum mismatch: the message never quotes content
                raise ConnectorError(f"The backup of {connector.title} was not stored: {exc}") from exc
            return {"backup": meta}

        return await self._connector("backup", run)

    # -- network devices: guarded changes (only for the Network Supervisor; see hub/integration/changes.py) ------
    # Each call builds a new connector instance (a new connection), re-loads the change and its approval from the
    # store and checks them again (S8) before touching the device. Replies carry no token, backup or secret.

    @staticmethod
    def _from_network(msg: Message) -> None:
        if msg.sender != "module:network":
            raise ValueError("Device changes are made only by the Network Supervisor, for approved changes")

    async def _change_call(self, op: str, call) -> dict[str, Any]:
        async def run(connector):
            try:
                return await call(connector)
            except ChangeError as exc:  # what the device holds now travels with the failure
                return {"failure": {"message": connector.redact(exc.message), "status": exc.status, "excerpt": None,
                                    "code": exc.code, "state": exc.state}}

        return await self._connector(op, run)

    def _load_backup(self, backup_id: str | None):
        if not backup_id:
            return None
        try:
            return network.load_backup(self.hub, backup_id)
        except (KeyError, ValueError) as exc:
            raise ChangeError(f"The Atrium backup {backup_id} cannot be used: {exc}", code="invalid",
                              state="unchanged") from exc

    def _change(self, body: dict[str, Any], stage: str, backup_id: str | None = None) -> dict[str, Any]:
        change = changes.get(self.hub, str(body.get("change_id") or ""))
        problem = changes.authorize(self.hub, change, stage, backup_id)
        if problem or change is None or change["firewall"] != self.tool_id:
            raise ValueError(f"Refused: {problem or 'the change is for another device'}")
        return change

    @staticmethod
    def _refused(exc: ValueError) -> dict[str, Any]:
        """A refused apply / restore: nothing was sent to the device."""
        return {"failure": {"message": str(exc), "status": None, "excerpt": None, "code": "failed",
                            "state": "unchanged"}}

    async def on_network_preview(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """{ops} -> {steps, notes, problems}: the connector checks a proposed change against the device (no side
        effects); the snapshot is the hub's current one (the Network Supervisor just re-read the device)."""
        self._from_network(msg)
        ops = parse_ops(body.get("ops"))
        snap = network.snapshot(self.hub, self.tool_id)
        if snap is None:
            raise ValueError("The device has no snapshot")

        async def call(connector):
            result = await connector.preview_change(ops, snap["record"])
            return {"steps": texts(connector, result.get("steps"), 100), "notes": texts(connector, result.get("notes")),
                    "problems": texts(connector, result.get("problems"))}

        return await self._change_call("preview", call)

    async def on_network_apply(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """{change_id} -> {applied: {rollback_until, revision, created, disabled, enabled, notes}}; the token is kept
        in the store for confirm / rollback."""
        self._from_network(msg)
        try:
            change = self._change(body, "apply")
        except ValueError as exc:
            return self._refused(exc)
        kinds = changes.needed_kinds(change["op"], change["ops"])

        async def call(connector):
            spec = network.write_capability(self.hub, self.tool_id)
            if spec is None or spec["rollback"] == "none" or any(k not in spec["ops"] for k in kinds):
                raise ChangeError(f"{connector.title} cannot make this change on this connection", code="unsupported",
                                  state="unchanged")
            backup = self._load_backup(change.get("backup_id"))
            result = await connector.apply_change(change["ops"], change["base_revision"], backup)
            if not isinstance(result, dict):
                raise ChangeError("apply_change answered no result", code="failed", state="unknown")
            if result.get("token"):
                changes.store_token(self.hub, change["id"], str(result["token"])[:4096])
            applied = changes.applied_summary(result)
            applied["notes"] = [connector.redact(n) for n in applied["notes"]]
            return {"applied": applied}

        return await self._change_call("apply", call)

    async def on_network_confirm(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._from_network(msg)
        change = self._change(body, "confirm")
        token = changes.token(self.hub, change["id"])

        async def call(connector):
            if not token:
                raise ChangeError("There is no token to confirm", code="failed", state="unknown")
            result = await connector.confirm_change(token)
            return {"confirmed": bool((result or {}).get("confirmed")), "notes": texts(connector, (result or {}).get("notes"))}

        return await self._change_call("confirm", call)

    async def on_network_rollback(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        self._from_network(msg)
        change = self._change(body, "rollback")
        token = changes.token(self.hub, change["id"])

        async def call(connector):
            if not token:
                raise ChangeError("The device never acknowledged the change: there is nothing to roll back with",
                                  code="failed", state="unknown")
            try:
                backup = self._load_backup(change.get("backup_id"))
            except ChangeError:
                backup = None
            result = await connector.rollback_change(token, backup)
            return {"rolled_back": bool((result or {}).get("rolled_back")),
                    "method": texts(connector, [(result or {}).get("method") or ""])[0] or None,
                    "notes": texts(connector, (result or {}).get("notes"))}

        return await self._change_call("rollback", call)

    async def on_network_restore(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """{change_id, recover?: bool}: an approved restore change puts its backup back; with `recover`, the change's
        own pre-change backup is restored after its rollback did not revert the device."""
        self._from_network(msg)
        recover = bool(body.get("recover"))
        if recover:
            current = changes.get(self.hub, str(body.get("change_id") or "")) or {}
            backup_id = current.get("backup_id")
            change = self._change(body, "recover", backup_id)
        else:
            try:
                change = self._change(body, "restore")
            except ValueError as exc:
                return self._refused(exc)
            backup_id = (change.get("request") or {}).get("backup_id")

        async def call(connector):
            # a restore change is a write: never on a connection that is read only, has no rollback mechanism or whose
            # test narrowed the capability away (S2). Recovering a change's own pre-change backup stays possible.
            if not recover and (network.write_capability(self.hub, self.tool_id) is None
                                or connector.write_capability() is None):
                raise ChangeError(f"{connector.title} cannot restore a configuration on this connection (it is read "
                                  "only or cannot make changes safely)", code="unsupported", state="unchanged")
            backup = self._load_backup(backup_id)
            if backup is None:
                raise ChangeError("No backup to restore", code="invalid", state="unchanged")
            result = await connector.restore_backup(backup)
            return {"restored": bool((result or {}).get("restored")), "notes": texts(connector, (result or {}).get("notes"))}

        return await self._change_call("restore", call)

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

    async def _enrich(self, manifest: Manifest, root: Path) -> tuple[Manifest, str]:
        """The manifest with a description and capabilities the AI model read from the repository, and the model's
        label."""
        files = "\n".join(f.as_posix() for f in list_files(root, 300))
        readme = ""
        for name in ("README.md", "readme.md", "README.rst", "README"):
            text = read_repo_file(root, name, 32_000)  # never through a symbolic link out of the repository
            if text is not None:
                readme = text[:8000]
                break
        prompt = (
            f"<inferred_manifest>\n{manifest.model_dump_json(include={'name', 'stack', 'provides', 'consumes', 'auth'})}\n"
            f"</inferred_manifest>\n<readme>\n{readme or readme_summary(root)}\n</readme>\n<files>\n{files}\n</files>"
        )
        result, meta = await self.hub.llm.json(self.id, "generate", system=self.instructions, prompt=prompt,
                                               schema=ENRICH_SCHEMA, effort="low", max_output_tokens=4000)
        manifest.description = result["description"][:400] or manifest.description
        manifest.provides = sorted(set(manifest.provides) | {c for c in result["provides"] if c and len(c) < 40})
        manifest.consumes = sorted(set(manifest.consumes) | {c for c in result["consumes"] if c and len(c) < 40})
        return manifest, meta.provider_label


def texts(connector: Any, values: Any, limit: int = 20) -> list[str]:
    """Connector-provided strings for a change's record: made safe as text (``changes.device_text``), secrets masked."""
    return [connector.redact(t) for t in changes.device_text(values, limit)]


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
