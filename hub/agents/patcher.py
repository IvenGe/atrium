"""Patch Agent: makes tools that do not fit the hub fit, with code patches and adapters."""

from __future__ import annotations

import asyncio
import difflib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
import yaml

from .. import connectors, guardrails
from ..approvals import sender_person
from ..bus import Message
from ..connectors import base as connector_sdk
from ..connectors import generic_rest
from ..connectors.base import ConnectorError, endpoint_of
from ..extensions import gaps as ext_gaps
from ..extensions import generate as ext_generate
from ..extensions import registry as ext_registry
from ..extensions import selfpatch
from ..integration import connections, flows, identity
from ..integration.analyzer import list_files
from ..integration.identity import SSO_STRATEGIES
from ..integration.patches import apply_patch, attach_sso, plan_patch, safe_relative, selected_provider, sso_code_goal
from ..models import FileChange, Flow, Patch, Tool
from ..store import new_id
from .base import BaseAgent

MAX_SPEC = 5_000_000
SPEC_PROMPT_CHARS = 60_000
# Settings a flow repair never changes (review F22): what keeps a connection safe - Read only, TLS and SSH host
# verification, the hub address the management-path guard uses, the root wrapper a host firewall runs - and the
# switches that let the hub write to a tool are an administrator's decision (PUT /api/tools/{id}/connection).
REPAIR_LOCKED = frozenset({"read_only", "verify_tls", "ca_file", "host_key", "known_hosts", "hub_address", "wrapper",
                           "push_assessments", "read_accounts", "save_config"})


def network_device(kind: str) -> bool:
    """Whether connections of this connector kind manage a network device (a firewall)."""
    try:
        return "network" in connectors.connector_class(kind).capabilities
    except ConnectorError:
        return False


def repairable(kind: str) -> set[str]:
    """The settings a repair may change: for a network device's connection only its URLs (their path - the address
    stays, connections.update_config checks it); otherwise every setting except the secrets and REPAIR_LOCKED."""
    cls = connectors.connector_class(kind)
    if network_device(kind):
        return {f.name for f in cls.fields if f.kind == "url"}
    return {f.name for f in cls.fields if f.kind != "secret" and f.name not in REPAIR_LOCKED}

REPAIR_SCHEMA = {
    "type": "object",
    "properties": {"diagnosis": {"type": "string"}, "rationale": {"type": "string"}, "config_json": {"type": "string"}},
    "required": ["diagnosis", "rationale", "config_json"],
    "additionalProperties": False,
}
GENERATE_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string"},
        "base_url": {"type": "string"},
        "auth": {"type": "string", "enum": list(generic_rest.AUTH_TYPES)},
        "auth_header": {"type": "string"},
        "mapping_json": {"type": "string"},
    },
    "required": ["rationale", "base_url", "auth", "auth_header", "mapping_json"],
    "additionalProperties": False,
}
REPAIR_INSTRUCTIONS = (
    "You repair data flows between an integration hub and a tool's REST API. You are given the connector's settings "
    "(never its secrets), the failing flow, the tool's error and a sanitized sample. Propose the smallest change to "
    "the non-secret settings that fixes the failure, as a JSON object of setting name -> new value in config_json "
    "('{}' when no setting change can fix it, e.g. rejected credentials or data the tool refuses). Never change the "
    "scheme, host or port of a URL setting. In rationale, explain the cause and the fix in two or three sentences "
    "for an operator; quote the tool's own error message."
)
GENERATE_INSTRUCTIONS = (
    "You write declarative connector mappings that let an integration hub exchange data with a tool's REST API. "
    "Use only operations that exist in the OpenAPI document you are given. Map as many of the hub's data domains "
    "(assets, vulnerabilities, risks, controls) as the API really supports - none is fine - and never invent paths "
    "or fields. Return the mapping as JSON in mapping_json, the API root in base_url, and the authentication scheme "
    "the API documents. In rationale, list what each mapped domain reads or writes and what you left out."
)

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
    permissions = ("read", "patches")
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
        self._locks: dict[str, asyncio.Lock] = {}

    @property
    def hub_url(self) -> str:
        return f"http://{self.hub.settings.host}:{self.hub.settings.port}"

    def _lock(self, tool_id: str) -> asyncio.Lock:
        """One planning pass per tool at a time, so concurrent requests cannot propose the same patch twice."""
        return self._locks.setdefault(tool_id, asyncio.Lock())

    # -- requests --------------------------------------------------------------------

    async def on_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        tool = self._tool(body.get("tool_id"))
        async with self._lock(tool.id):
            tool = self._tool(tool.id)
            fixes = body.get("fixes") or [c.fix for c in (tool.report.checks if tool.report else []) if c.fix and c.status != "pass"]
            others = [t for t in self.hub.tools() if t.id != tool.id]
            existing = {p.strategy for p in self.hub.patches(tool.id) if p.status in ("proposed", "applied")}
            created: list[Patch] = []
            for fix in dict.fromkeys(fixes):
                if fix in SSO_STRATEGIES:
                    patch = await self._sso_patch(tool, others, fix)
                elif fix in existing or (fix == "health_endpoint" and "health_probe" in existing):
                    continue
                else:
                    patch = None
                    if fix == "health_endpoint" and self.hub.llm.available:
                        try:
                            patch = await self.code_patch(tool, HEALTH_GOAL, strategy="health_endpoint")
                        except Exception as exc:
                            self.log("warn", f"Code patch for {tool.name} failed, falling back to a probe adapter: {exc}")
                    if patch is None:
                        patch = plan_patch(tool, others, fix, self.hub_url)
                if patch is not None:
                    created.append(await self._submit(tool, patch, msg.sender))
        if created:
            self.log("info", f"Proposed {len(created)} patch(es) for {tool.name}: " + "; ".join(p.title for p in created))
        return {"patches": [p.id for p in created]}

    async def on_sso_plan(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """(Re)plan single sign-on for one tool after its provider choice, the suite default or the providers changed.
        A pending SSO patch is superseded (its approval rejected with a note) when another provider is now selected or
        its provider left the suite; while someone still has to choose between providers, it stays."""
        if body.get("rescore", True):
            await self.ask("supervisor", "reevaluate", timeout=120)
        tool = self._tool(body.get("tool_id"))
        actor = str(body.get("actor") or self.id)
        async with self._lock(tool.id):
            tool = self._tool(tool.id)
            others = [t for t in self.hub.tools() if t.id != tool.id]
            prefs = identity.load_prefs(self.hub)
            ids = {p.tool_id for p in identity.list_providers(others, prefs.settings)}
            provider = selected_provider(tool, others, prefs)
            target = provider.tool_id if provider else None
            superseded = []
            for patch in self.hub.patches(tool.id):
                current = patch.sso.provider if patch.sso else None
                if patch.strategy not in SSO_STRATEGIES or patch.status != "proposed":
                    continue
                if (target is not None and current != target) or (current is not None and current not in ids):
                    note = (f"Superseded: {tool.name} now signs in through {provider.name}." if provider
                            else "Superseded: its identity provider left the suite.")
                    superseded += self._supersede(patch, note, actor)
            check = next((c for c in (tool.report.checks if tool.report else []) if c.id == "sso"), None)
            created = None
            if provider and check and check.status != "pass" and check.fix in SSO_STRATEGIES:
                patch = await self._sso_patch(tool, others, check.fix)
                created = await self._submit(tool, patch) if patch else None
        if created:
            self.log("info", f"Proposed '{created.title}' for {tool.name}")
        pending = next((p for p in self.hub.patches(tool.id) if p.strategy in SSO_STRATEGIES and p.status == "proposed"), None)
        return {"provider": target, "strategy": check.fix if check else None, "superseded": superseded,
                "patches": [created.id] if created else [], "pending": pending.id if pending else None}

    async def on_custom(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Free-form patch request, e.g. from the Hub Supervisor chat. Needs Claude."""
        tool = self._tool(body.get("tool_id"))
        goal = str(body.get("goal") or "").strip()
        if not goal:
            raise ValueError("Describe what the patch should achieve")
        if not self.hub.llm.available:
            raise ValueError("Custom code patches need Claude - set ANTHROPIC_API_KEY")
        patch = await self.code_patch(tool, goal, strategy="custom")
        patch = await self._submit(tool, patch, msg.sender)
        return {"patch_id": patch.id, "title": patch.title, "status": patch.status}

    # -- data flow repairs and generated connectors -----------------------------------

    async def on_integration_repair(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """A flow failed REPAIR_AFTER times in a row: diagnose it and propose a fix (approval kind "repair")."""
        flow = flows.get(self.hub, str(body.get("flow_id")))
        tool = self.hub.get_tool(str(body.get("tool_id")))
        conn = connections.get(self.hub, tool.id) if tool else None
        if flow is None or tool is None or conn is None:
            if flow is not None:  # nothing to repair through: let a later failure ask again
                flow.repair = None
                flows.save(self.hub, flow)
            return {"approval_id": None, "diagnosis": None, "applied": False}
        error = body.get("error") or {}
        sample = flows.sanitize(body.get("sample"))
        proposal = None
        # a network device's error text is the device's own words: it never reaches a model (review F22), so its
        # repairs are the rules-based diagnosis
        if self.hub.llm.available and not network_device(conn.kind):
            try:
                proposal = await self._claude_repair(flow, tool, conn, error, sample)
            except Exception as exc:  # fall back to the rules
                self.log("warn", f"Claude could not propose a repair for '{flow.title}': {exc}")
        if proposal is None:
            proposal = await self._heuristic_repair(flow, tool, conn, error)
        return await self._submit_repair(tool, proposal, flow, error)

    async def on_connector_generate(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """With Claude: a generic_rest mapping from the tool's OpenAPI spec, proposed as a "repair" approval."""
        tool = self._tool(body.get("tool_id"))
        if not self.hub.llm.available:
            raise ValueError("Generating a connector needs Claude - set ANTHROPIC_API_KEY")
        spec, known_base = await load_openapi(tool)
        prompt = (
            f"<tool name=\"{tool.name}\" known_api_base=\"{known_base or ''}\" />\n"
            f"<canonical_records>\n{connector_sdk.__doc__}\n</canonical_records>\n"
            f"<mapping_format>\n{generic_rest.__doc__}\n</mapping_format>\n"
            f"<openapi>\n{spec}\n</openapi>"
        )
        result = await self.hub.llm.json(system=GENERATE_INSTRUCTIONS, prompt=prompt, schema=GENERATE_SCHEMA,
                                         model=self.model, effort="high")
        base = str(result.get("base_url") or "").strip().rstrip("/")
        if known_base and endpoint_of(base) != endpoint_of(known_base):
            base = known_base.rstrip("/")  # the mapping may pick the API root's path, never another host
        try:
            mapping = json.loads(result.get("mapping_json") or "{}")
            config = generic_rest.GenericRestConnector.validate_config({
                "base_url": base, "auth": result.get("auth") or "bearer",
                "auth_header": (result.get("auth_header") or "X-API-Key").strip() or "X-API-Key",
                "mapping": mapping, "verify_tls": True})
        except (ValueError, ConnectorError) as exc:
            raise ValueError(f"Claude's mapping is not usable: {getattr(exc, 'message', exc)}") from exc
        domains = generic_rest.GenericRestConnector(config, {}).domains()
        summary = ", ".join(f"{d} ({'/'.join(ops)})" for d, ops in domains.items())
        proposal = {
            "diagnosis": "generated", "title": f"Generated connector for {tool.name}",
            "detail": f"{str(result.get('rationale') or '').strip()}\n\nMapped: {summary}. After approval an administrator "
                      f"enters the API credentials in {tool.name} > Connection.",
            "change": {"kind": "generic_rest", "config": config, "generated": True},
        }
        return await self._submit_repair(tool, proposal, None, {})

    async def _claude_repair(self, flow: Flow, tool: Tool, conn: connections.Connection, error: dict[str, Any],
                             sample: Any) -> dict[str, Any] | None:
        cls = connectors.connector_class(conn.kind)
        allowed = repairable(conn.kind)
        fields = [f.model_dump(include={"name", "label", "kind", "help", "choices"}) for f in cls.fields if f.name in allowed]
        spec = ""
        if conn.kind == "generic_rest":
            try:
                spec = (await load_openapi(tool))[0]
            except ValueError:
                spec = ""
        prompt = (
            f"<tool name=\"{tool.name}\" connector=\"{cls.title}\" />\n"
            f"<flow domain=\"{flow.domain}\" direction=\"{flow.direction}\" failures=\"{flow.failures}\" />\n"
            f"<settings_fields>\n{json.dumps(fields)}\n</settings_fields>\n"
            f"<current_settings>\n{json.dumps(conn.config, default=str)[:30000]}\n</current_settings>\n"
            f"<error status=\"{error.get('status')}\">\n{error.get('message', '')}\n{error.get('excerpt') or ''}\n</error>\n"
            f"<sample>\n{json.dumps(sample, default=str)[:8000]}\n</sample>\n"
            + (f"<mapping_format>\n{generic_rest.__doc__}\n</mapping_format>\n" if conn.kind == "generic_rest" else "")
            + (f"<openapi>\n{spec[:SPEC_PROMPT_CHARS // 2]}\n</openapi>\n" if spec else "")
        )
        result = await self.hub.llm.json(system=REPAIR_INSTRUCTIONS, prompt=prompt, schema=REPAIR_SCHEMA,
                                         model=self.model, effort="medium", max_tokens=16000)
        changes = json.loads(result.get("config_json") or "{}")
        if not isinstance(changes, dict):
            raise ValueError("config_json is not an object")
        changes = {k: v for k, v in changes.items() if k in allowed and conn.config.get(k) != v}
        rationale = str(result.get("rationale") or "").strip()
        diagnosis = "mapping" if conn.kind == "generic_rest" and "mapping" in changes else ("config" if changes else "manual")
        if changes:
            merged = connections.clean_config(cls, {**conn.config, **changes})  # ValueError: not a usable change
            if conn.secrets and connections.endpoint(cls, merged) != conn.endpoint:
                raise ValueError("the change would send the credentials to another address")
        return {"diagnosis": diagnosis, "title": f"Repair: {flow.title}",
                "detail": rationale or str(result.get("diagnosis") or ""),
                "change": {"kind": conn.kind, "config": changes} if changes else None}

    async def _heuristic_repair(self, flow: Flow, tool: Tool, conn: connections.Connection,
                                error: dict[str, Any]) -> dict[str, Any]:
        status, message = error.get("status"), str(error.get("message") or "the flow failed")
        excerpt = error.get("excerpt") or ""
        title = f"Repair: {flow.title}"
        if status in (401, 403):
            return {"diagnosis": "credentials", "title": title, "change": None, "detail": (
                f"{tool.name} refused the hub's credentials ({message}). An administrator should check the API token "
                f"and the account's permissions in {tool.name} > Connection. Approve to run the flow again once that is done.")}
        if status == 404:
            cls = connectors.connector_class(conn.kind)
            tried = []
            for field in (f for f in cls.fields if f.kind == "url" and conn.config.get(f.name)):
                for variant in base_path_variants(str(conn.config[field.name])):
                    result = await self.ask(f"tool:{tool.id}", "connector.test", {"config": {field.name: variant}}, timeout=180)
                    tried.append({"field": field.name, "value": variant, "ok": bool(result.get("ok")),
                                  "detail": str(result.get("detail") or "")[:300]})
                    if result.get("ok"):
                        return {"diagnosis": "base_path", "title": title, "tried": tried,
                                "change": {"kind": conn.kind, "config": {field.name: variant}},
                                "detail": f"{tool.name} answered 404 Not Found: the API is not at "
                                          f"{conn.config[field.name]}. A connection test succeeds with {variant}; approve "
                                          "to use it and run the flow again."}
            shown = ", ".join(t["value"] for t in tried) or "none"
            return {"diagnosis": "base_path", "title": title, "tried": tried, "change": None,
                    "detail": f"{tool.name} answered 404 Not Found ({message}). No variant of the base path worked "
                              f"(tried: {shown}); check the URL in {tool.name} > Connection, then approve to retry."}
        if status in (400, 409, 422) or "rejected" in message:
            return {"diagnosis": "validation", "title": title, "change": None, "detail": (
                f"{tool.name} rejected the data: {message}" + (f"\n\n{tool.name} answered: {excerpt}" if excerpt else "")
                + "\n\nFix the records (or the fields the tool requires) and approve to run the flow again.")}
        if status is None:
            return {"diagnosis": "unreachable", "title": title, "change": None, "detail": (
                f"The hub could not complete the flow: {message}. Check that {tool.name} is running and reachable at "
                "the configured address, then approve to retry.")}
        return {"diagnosis": "unknown", "title": title, "change": None,
                "detail": f"{tool.name} answered: {message}" + (f"\n\n{excerpt}" if excerpt else "")}

    async def _submit_repair(self, tool: Tool, proposal: dict[str, Any], flow: Flow | None,
                             error: dict[str, Any]) -> dict[str, Any]:
        conn = connections.get(self.hub, tool.id)
        change = proposal.get("change")
        if change and not change.get("generated"):  # only the settings a repair may change (review F22)
            allowed = repairable(change["kind"])
            change = {**change, "config": {k: v for k, v in change["config"].items() if k in allowed}}
            if not change["config"]:
                change = None
        # a repair of a network device's connection: an administrator approves it, never the agent alone
        device = network_device(conn.kind if conn else (change or {}).get("kind") or "")
        payload = {"flow_id": flow.id if flow else None, "tool_id": tool.id, "diagnosis": proposal["diagnosis"],
                   "change": change, "diff": config_diff(conn.config if conn and change and conn.kind == change["kind"] else {},
                                                         change["config"]) if change else "",
                   "tried": proposal.get("tried", []), "error": {"message": error.get("message"), "status": error.get("status")}}
        if device:
            payload["device"] = True
        if change and self.hub.prefs["autonomy"] == "autonomous" and not device:
            approval = self.hub.approvals.create("repair", proposal["title"], proposal["detail"], payload, self.id)
            await self._decide_repair(approval.id, True, self.id)
            return {"approval_id": approval.id, "diagnosis": proposal["diagnosis"], "applied": True}
        approval = self.hub.approvals.create("repair", proposal["title"], proposal["detail"], payload, self.id)
        if flow is not None:
            current = flows.get(self.hub, flow.id)
            if current:
                current.repair = approval.id
                flows.save(self.hub, current)
        self.log("info", f"Proposed '{proposal['title']}' ({proposal['diagnosis']})")
        return {"approval_id": approval.id, "diagnosis": proposal["diagnosis"], "applied": False}

    async def _decide_repair(self, approval_id: str, approved: bool, actor: str) -> None:
        approval = self.hub.approvals.get(approval_id)
        if approval is None:
            return
        payload = approval.payload
        flow = flows.get(self.hub, payload.get("flow_id") or "")
        change = payload.get("change")
        if approved and change:
            try:
                connections.update_config(self.hub, payload["tool_id"], change["config"], f"{actor} (repair)",
                                          kind=change["kind"], generated=change.get("generated"))
            except (ValueError, ConnectorError) as exc:
                self.hub.approvals.complete(approval.id, False, {"error": getattr(exc, "message", None) or str(exc)})
                self.log("warn", f"Could not apply '{approval.title}': {exc}")
                approved = False  # nothing changed: the flow keeps its state, and a later repair may be proposed
        if approved:
            self.hub.approvals.complete(approval.id, True, {"applied": bool(change)})
        if flow is not None:
            flow.repair, flow.failures = None, 0
            flows.save(self.hub, flow)
            if approved:
                await self.tell(flows.owner(flow), "flow.run", {"flow_id": flow.id, "trigger": "repair"})
        if approved and payload.get("diagnosis") == "generated":
            await self.tell("supervisor", "flows.plan")
        if approved and change:
            self.log("info", f"Applied '{approval.title}'")

    # -- extending Atrium itself -------------------------------------------------------

    async def on_extension_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """Close a tool's hub-side gaps (extensions/gaps.py): a pack written by Claude (when available, unless
        `designer` is "templates") or from the templates, proposed as an approval of kind "extension" - enabled at once
        while the extensions_need_approval guardrail is off. When only a change to Atrium's code can close a gap and
        Claude is available, a self-patch is requested as well. `auto`: the hub asked by itself (once per tool)."""
        tool = self._tool(body.get("tool_id"))
        designer = str(body.get("designer") or "auto")
        if designer not in ("auto", "templates", "claude"):
            raise ValueError("designer is auto, templates or claude")
        if designer == "claude" and not self.hub.llm.available:
            raise ValueError("Writing an extension with Claude needs ANTHROPIC_API_KEY; use the templates instead")
        result: dict[str, Any] = {"tool_id": tool.id, "gaps": [], "proposed": False, "approval_id": None,
                                  "extension_id": None, "enabled": False, "self_patch": None, "designer": None,
                                  "detail": ""}
        if not ext_registry.allowed(self.hub):
            return {**result, "detail": "Extensions are switched off (guardrail allow_extensions)"}
        async with self._lock(f"extend:{tool.id}"):
            if body.get("auto") and ext_registry.covers_tool(self.hub, tool.id):
                return {**result, "detail": f"{tool.name} already has an extension or a proposal"}
            pending = next((r for r in ext_registry.records(self.hub) if r.source_tool == tool.id and r.status == "proposed"), None)
            if pending is not None:
                return {**result, "approval_id": pending.approval_id, "extension_id": pending.id,
                        "detail": f"An extension for {tool.name} is already waiting for approval"}
            gaps = ext_gaps.detect(self.hub, tool)
            result["gaps"] = [g.as_dict() for g in gaps]
            if not gaps:
                return {**result, "detail": f"Atrium has no gap to close for {tool.name}"}
            pack, rationale, needs_code, goal = None, "", False, ""
            if designer != "templates" and self.hub.llm.available:
                try:
                    pack, rationale, needs_code, goal = await ext_generate.claude_pack(self.hub, tool, gaps, self.model)
                    result["designer"] = "claude"
                except Exception as exc:  # the templates always work
                    self.log("warn", f"Claude could not write an extension for {tool.name}, using the templates: {exc}")
            if pack is None:
                pack = ext_gaps.template_pack(self.hub, tool, gaps, self.id)
                if pack is not None:
                    result["designer"] = "templates"
                    kind = ext_gaps.category(tool)
                    rationale = rationale or (f"{tool.name} is a {ext_gaps.KINDS[kind]['title'].lower()} tool"
                                              if kind else tool.name) + ": " + "; ".join(g.title for g in gaps) + "."
            if pack is not None:
                result.update(await self._submit_extension(tool, pack, rationale, result["designer"], gaps, msg.sender))
            code_gaps = [g for g in gaps if not g.expressible]
            if (needs_code or code_gaps) and self._may_self_patch(tool.id):
                goal = goal or " ".join(f"{g.title}: {g.detail}" for g in code_gaps)
                await self.tell(self.id, "self_patch.propose", {"goal": goal, "tool_id": tool.id})
                result["self_patch"] = "requested"
            if not result["detail"]:
                missing = [g.title for g in gaps if g.needs_claude and not self.hub.llm.available]
                result["detail"] = (f"No template fits {tool.name}'s gaps" + (f" ({'; '.join(missing)} need Claude)"
                                                                             if missing else ""))
        return result

    def _may_self_patch(self, tool_id: str) -> bool:
        return (self.hub.llm.available and bool(guardrails.value(self.hub, "allow_self_patching"))
                and selfpatch.config(self.hub).root() is not None
                and not any(p.tool_id == tool_id for p in selfpatch.all_patches(self.hub)))

    async def _submit_extension(self, tool: Tool, pack: Any, rationale: str, designer: str | None,
                                gaps: list[Any], origin: str) -> dict[str, Any]:
        rec = ext_registry.propose(self.hub, pack, self.id)
        summary = pack.summary()
        lines = [f"- {kind}: {count}" for kind, count in summary["kinds"].items()]
        detail = (rationale + "\n\n" if rationale else "") + f"{pack.name} {pack.version} adds:\n" + "\n".join(lines)
        if not guardrails.value(self.hub, "extensions_need_approval"):
            try:
                ext_registry.set_status(self.hub, rec.id, "enabled", f"{self.id} (extensions_need_approval off)")
            except ValueError as exc:
                ext_registry.set_status(self.hub, rec.id, "disabled", self.id)
                return {"proposed": True, "extension_id": rec.id, "enabled": False,
                        "detail": f"Generated {pack.name}, but it cannot be enabled: {exc}"}
            self.log("warn", f"Enabled the extension {pack.name} without approval (guardrail extensions_need_approval "
                             "is off)", extension_id=rec.id)
            await ext_registry.changed(self.hub, self.id)
            return {"proposed": True, "extension_id": rec.id, "enabled": True, "detail": f"Enabled {pack.name}."}
        payload = {"extension_id": rec.id, "version": pack.version, "tool_id": tool.id, "designer": designer,
                   "summary": summary, "gaps": [g.as_dict() for g in gaps], "pack": pack.model_dump(mode="json")}
        approval = self.hub.approvals.create("extension", f"Extend Atrium for {tool.name}: {pack.name}", detail, payload,
                                             self.id)
        rec = ext_registry.get(self.hub, rec.id) or rec
        rec.approval_id = approval.id
        ext_registry.save(self.hub, rec)
        self.log("info", f"Proposed the extension {pack.name} for {tool.name}", extension_id=rec.id)
        return {"proposed": True, "approval_id": approval.id, "extension_id": rec.id, "enabled": False,
                "detail": f"Proposed {pack.name}; waiting for approval."}

    async def _decide_extension(self, approval_id: str, approved: bool, actor: str) -> None:
        approval = self.hub.approvals.get(approval_id)
        if approval is None:
            return
        rec = ext_registry.get(self.hub, str(approval.payload.get("extension_id")))
        if rec is None:
            if approved:
                self.hub.approvals.complete(approval_id, False, {"error": "The extension was removed"})
            return
        if not approved:
            if rec.status == "proposed":
                rec.status, rec.approval_id = "disabled", None
                rec.log(actor, "rejected")
                ext_registry.save(self.hub, rec, actor)
            return
        if rec.status == "proposed":
            try:
                rec = ext_registry.set_status(self.hub, rec.id, "enabled", actor)
            except ValueError as exc:
                rec.status, rec.approval_id = "disabled", None
                rec.notes = [*rec.notes, f"Not enabled: {exc}"]
                ext_registry.save(self.hub, rec, actor)
                self.hub.approvals.complete(approval_id, False, {"error": str(exc)})
                return
            await ext_registry.changed(self.hub, self.id)
        self.hub.approvals.complete(approval_id, True, {"enabled": rec.status == "enabled", "notes": rec.notes})

    async def on_self_patch_propose(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """With Claude: a change to Atrium's own repository for `goal`, tested in a worktree and proposed as an approval
        of kind "self_patch" (see extensions/selfpatch.py)."""
        goal = str(body.get("goal") or "").strip()
        if not goal:
            raise ValueError("Describe what the change to Atrium should achieve")
        if not self.hub.llm.available:
            raise ValueError("Self-patches need Claude - set ANTHROPIC_API_KEY")
        tool = self.hub.get_tool(str(body.get("tool_id"))) if body.get("tool_id") else None
        title, rationale, changes = await ext_generate.claude_self_patch(self.hub, goal, tool, self.model)
        patch = await selfpatch.propose(self.hub, title=title, rationale=rationale, changes=changes, goal=goal,
                                        tool_id=tool.id if tool else None, requested_by=self.id)
        patch.proposed_by = sender_person(msg.sender)  # the person who asked: approving it needs a second person (F1)
        patch = await selfpatch.submit(self.hub, patch, self.id)
        self.log("info", f"Proposed the self-patch '{patch.title}' ({'tests passed' if patch.tests and patch.tests.get('ok') else 'tests failed'})",
                 self_patch_id=patch.id)
        return {"self_patch_id": patch.id, "approval_id": patch.approval_id, "status": patch.status,
                "tests_passed": bool(patch.tests and patch.tests.get("ok"))}

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(body["approval_id"])
        actor = str(body.get("decided_by") or msg.sender)
        if approval is not None and approval.kind == "repair":
            await self._decide_repair(approval.id, bool(body.get("approved")), actor)
            return
        if approval is not None and approval.kind == "extension":
            await self._decide_extension(approval.id, bool(body.get("approved")), actor)
            return
        if approval is not None and approval.kind == "self_patch":
            await selfpatch.decided(self.hub, approval.id, bool(body.get("approved")), actor)
            return
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

    async def _sso_patch(self, tool: Tool, others: list[Tool], fix: str) -> Patch | None:
        """The SSO patch for the provider selected for `tool`, unless one is already pending or applied for it."""
        prefs = identity.load_prefs(self.hub)
        provider = selected_provider(tool, others, prefs)
        target = provider.tool_id if provider else None
        for patch in self.hub.patches(tool.id):
            if patch.strategy not in SSO_STRATEGIES:
                continue
            if patch.status == "proposed" or (patch.status == "applied" and (patch.sso.provider if patch.sso else None) == target):
                return None
        if fix == "sso_code" and provider and self.hub.llm.available:
            try:
                return attach_sso(tool, provider, await self.code_patch(tool, sso_code_goal(tool, provider), strategy="sso_code"))
            except Exception as exc:
                self.log("warn", f"OIDC code patch for {tool.name} failed, falling back to an SSO proxy: {exc}")
        return plan_patch(tool, others, "sso_proxy" if fix == "sso_code" else fix, self.hub_url, prefs)

    def _supersede(self, patch: Patch, note: str, actor: str) -> list[str]:
        patch.status = "rejected"
        self.hub.save_patch(patch)
        withdrawn = []
        for approval in self.hub.approvals.list("pending"):
            if approval.kind == "patch" and approval.payload.get("patch_id") == patch.id:
                self.hub.approvals.withdraw(approval.id, note, actor)
                withdrawn.append(approval.id)
        return withdrawn

    async def _submit(self, tool: Tool, patch: Patch, origin: str = "") -> Patch:
        """Save the patch and queue it for approval - or apply it in autonomous mode. Patches team agents asked for
        ("agent:<slug>") skip approval only while the team_actions_need_approval guardrail is off."""
        patch.diff = render_diff(tool, patch)
        self.hub.save_patch(patch)
        if guardrails.effective_autonomy(self.hub, origin) == "autonomous":
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


def base_path_variants(url: str) -> list[str]:
    """The same API root with "/api" (or "/api/v1") added or removed - the usual reason for a 404."""
    parts = urlsplit(url.rstrip("/"))
    path = parts.path.rstrip("/")
    if path.endswith("/api/v1"):
        paths = [path[:-3], path[:-7]]
    elif path.endswith("/api"):
        paths = [path[:-4], path + "/v1"]
    else:
        paths = [path + "/api", path + "/api/v1"]
    out = []
    for candidate in paths:
        variant = urlunsplit((parts.scheme, parts.netloc, candidate, "", "")).rstrip("/")
        if variant != url.rstrip("/") and variant not in out:
            out.append(variant)
    return out


def config_diff(old: dict[str, Any], changes: dict[str, Any]) -> str:
    """A readable diff of a settings change (JSON values are compared line by line)."""
    chunks = []
    for name, value in changes.items():
        before = old.get(name)
        if isinstance(value, (dict, list)) or isinstance(before, (dict, list)):
            a = json.dumps(before, indent=2, sort_keys=True, default=str).splitlines(keepends=True) if before is not None else []
            b = json.dumps(value, indent=2, sort_keys=True, default=str).splitlines(keepends=True)
            chunks.append("".join(difflib.unified_diff(a, b, fromfile=f"a/{name}", tofile=f"b/{name}")))
        else:
            chunks.append(f"{name}: {before!r} -> {value!r}\n")
    return "".join(chunks)[:100_000]


def _condense(spec: dict[str, Any]) -> dict[str, Any]:
    """The parts of an OpenAPI document a mapping needs: operations with their parameters and schemas."""
    methods = ("get", "post", "put", "patch")
    paths = {}
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        ops = {}
        for method in methods:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            responses = op.get("responses") or {}
            ok = next((responses[c] for c in responses if str(c).startswith("2")), {})
            ops[method] = {
                "summary": str(op.get("summary") or op.get("operationId") or "")[:120],
                "parameters": [f"{p.get('name')} ({p.get('in')})" for p in op.get("parameters") or [] if isinstance(p, dict)][:15],
                "body": (((op.get("requestBody") or {}).get("content") or {}).get("application/json") or {}).get("schema"),
                "response": ((ok.get("content") or {}).get("application/json") or {}).get("schema") if isinstance(ok, dict)
                else None,
            }
        if ops:
            paths[path] = ops
    components = spec.get("components") or {}
    schemas = components.get("schemas") or spec.get("definitions") or {}
    return {"info": {k: (spec.get("info") or {}).get(k) for k in ("title", "version")}, "servers": spec.get("servers"),
            "basePath": spec.get("basePath"), "security": components.get("securitySchemes") or spec.get("securityDefinitions"),
            "paths": paths,
            "schemas": {name: {"required": s.get("required"), "properties": {k: v.get("type") or v.get("$ref")
                                                                              for k, v in (s.get("properties") or {}).items()
                                                                              if isinstance(v, dict)}}
                        for name, s in schemas.items() if isinstance(s, dict)}}


async def load_openapi(tool: Tool) -> tuple[str, str | None]:
    """The tool's OpenAPI document, condensed for a prompt, and the API root the hub already knows (if any)."""
    m = tool.manifest
    location = tool.openapi_url or (m.api.spec if m else None)
    if not location:
        raise ValueError(f"{tool.name} has no OpenAPI spec - add one at import (SaaS) or to the repository")
    if location.startswith(("http://", "https://")):
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                response = await client.get(location)
                response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ValueError(f"Cannot read the OpenAPI spec of {tool.name}: {exc}") from exc
        text = response.text[:MAX_SPEC]
    else:
        if not tool.path:
            raise ValueError(f"The files of {tool.name} are not available")
        path = Path(tool.path) / safe_relative(location)
        if not path.is_file():
            raise ValueError(f"{location} is missing from {tool.name}")
        text = path.read_text(encoding="utf-8", errors="replace")[:MAX_SPEC]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f"The OpenAPI spec of {tool.name} cannot be parsed: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"The OpenAPI spec of {tool.name} is not an object")
    servers = [s.get("url") for s in doc.get("servers") or [] if isinstance(s, dict) and str(s.get("url", "")).startswith("http")]
    known = (m.api.base_url if m and m.api.base_url else None) or (servers[0] if servers else None) \
        or (tool.source if tool.source_type == "saas" else None)
    return json.dumps(_condense(doc), default=str)[:SPEC_PROMPT_CHARS], known


def render_diff(tool: Tool, patch: Patch) -> str:
    """Unified diff of the patch. Secrets only ever appear as placeholders: they are generated when it is applied."""
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
    for change in patch.adapter_changes:  # kept by the hub, not committed
        chunks.append("".join(difflib.unified_diff([], change.content.splitlines(keepends=True),
                                                   fromfile="/dev/null", tofile=f"hub-adapter/{change.path}")))
    return "\n".join(chunks)[:200_000]
