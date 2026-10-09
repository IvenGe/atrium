"""REST + Server-Sent Events API used by the web UI (and by tools publishing events)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import connectors, guardrails, llm_providers
from . import people as people_app
from .agents import teams
from .agents import vulns as vuln_app
from .agents.grc import control_catalog
from .auth.service import CurrentPrincipal, Principal
from .bus import AgentError
from .connectors.base import ConnectorError
from .core import Hub
from .grc.baseline import POLICY_TEMPLATES
from .grc.checks import framework_scores
from .integration import connections, flows, identity, importer, strategies
from .integration.compatibility import suite_matrix
from .integration.identity import SSO_STRATEGIES
from .models import (OPEN_STATES, SEVERITY_ORDER, AgentPermission, Asset, ControlState, Host, PersonStatus, Policy, Risk,
                     Vulnerability)
from .secrets import SecretError
from .store import new_id

SlaDays = dict[Literal["critical", "high", "medium", "low"], int]


class DecisionBody(BaseModel):
    approve: bool
    note: str | None = None


class CommandBody(BaseModel):
    command: str
    target: str = "local"
    cwd: str | None = None
    timeout: float = Field(120, gt=0, le=3600)


class ChatBody(BaseModel):
    text: str


class AgentPatch(BaseModel):
    """Core agents: paused, model, instructions. Custom agents: every field (paused = not enabled)."""

    paused: bool | None = None
    model: str | None = Field(None, max_length=200)
    instructions: str | None = Field(None, max_length=20_000)
    name: str | None = Field(None, min_length=1, max_length=80)
    title: str | None = Field(None, max_length=80)
    description: str | None = Field(None, max_length=1000)
    provider: str | None = Field(None, max_length=64)
    permissions: list[AgentPermission] | None = None
    team: str | None = Field(None, max_length=64)
    parent: str | None = Field(None, max_length=80)
    schedule_minutes: int | None = Field(None, ge=0, le=525_600)
    task: str | None = Field(None, max_length=4000)
    enabled: bool | None = None


CORE_AGENT_FIELDS = {"paused", "model", "instructions"}


class AgentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    id: str | None = Field(None, max_length=60)  # "agent:<slug>" or "<slug>"; default: from the team and name
    title: str = Field("Team agent", max_length=80)
    description: str = Field("", max_length=1000)
    instructions: str = Field("", max_length=20_000)
    provider: str | None = Field(None, max_length=64)  # default: Claude if available, else a local provider, else rules
    model: str = Field("", max_length=200)
    permissions: list[AgentPermission] = ["read"]
    team: str = Field("hub", max_length=64)
    parent: str | None = Field(None, max_length=80)  # default: the team's lead
    schedule_minutes: int = Field(0, ge=0, le=525_600)
    task: str = Field("", max_length=4000)
    enabled: bool = True


class AgentRun(BaseModel):
    task: str | None = Field(None, max_length=4000)


class TeamRequest(BaseModel):
    designer: Literal["auto", "templates", "claude"] = "auto"


class ProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    id: str | None = Field(None, max_length=40)
    base_url: str = Field(llm_providers.DEFAULT_BASE_URL, max_length=500)
    default_model: str = Field("", max_length=200)
    api_key: str | None = Field(None, max_length=4096)
    tools: bool = True
    timeout: float = Field(300, ge=5, le=3600)


class ProviderPatch(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    base_url: str | None = Field(None, max_length=500)
    default_model: str | None = Field(None, max_length=200)
    api_key: str | None = Field(None, max_length=4096)  # empty or absent: keep the stored key
    clear_api_key: bool = False
    tools: bool | None = None
    timeout: float | None = Field(None, ge=5, le=3600)


class SettingsPatch(BaseModel):
    autonomy: Literal["manual", "assisted", "autonomous"] | None = None
    model: str | None = None
    vuln_sla_days: SlaDays | None = None  # days to fix a finding, per severity (merged into the current values)
    guardrails: dict[str, bool | int] | None = None  # see hub/guardrails.py (also PATCH /api/settings/guardrails)


class ConnectionBody(BaseModel):
    kind: str = Field(max_length=64)
    config: dict[str, Any] = {}
    secrets: dict[str, str | None] = {}  # an empty value keeps the stored secret


class FlowPatch(BaseModel):
    status: Literal["enabled", "disabled"] | None = None
    schedule_minutes: int | None = Field(None, ge=0, le=525_600)
    options: dict[str, Any] | None = None


class VulnPatch(BaseModel):
    status: Literal["open", "in_progress", "accepted", "false_positive", "fixed"] | None = None
    note: str | None = Field(None, max_length=4000)


class ScanRequest(BaseModel):
    scanner_tool_id: str | None = Field(None, max_length=64)
    asset_ids: list[str] = Field(default_factory=list, max_length=5000)


class ScanScope(BaseModel):
    asset_ids: list[str] = Field(max_length=10_000)
    in_scope: bool


class ControlOverride(BaseModel):
    status: Literal["pass", "partial", "fail", "manual", "na"] | None = None
    note: str | None = None
    clear: bool = False


class PersonBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=200)
    email: str | None = Field(None, max_length=254)
    login: str | None = Field(None, max_length=254)
    title: str | None = Field(None, max_length=200)
    department: str | None = Field(None, max_length=200)
    manager_id: str | None = Field(None, max_length=64)
    status: PersonStatus | None = None  # set by hand; a directory saying the person left still wins
    groups: list[str] = Field(default_factory=list, max_length=200)
    location: str | None = Field(None, max_length=200)
    phone: str | None = Field(None, max_length=64)


class PersonPatch(BaseModel):
    """Only the fields sent change; "status": null clears a status set by hand."""

    display_name: str | None = Field(None, min_length=1, max_length=200)
    email: str | None = Field(None, max_length=254)
    login: str | None = Field(None, max_length=254)
    title: str | None = Field(None, max_length=200)
    department: str | None = Field(None, max_length=200)
    manager_id: str | None = Field(None, max_length=64)
    status: PersonStatus | None = None
    groups: list[str] | None = Field(None, max_length=200)
    location: str | None = Field(None, max_length=200)
    phone: str | None = Field(None, max_length=64)


class PersonAction(BaseModel):
    asset_ids: list[str] | None = Field(None, max_length=5000)  # unassign_assets: only these (default: all)


class AccountLink(BaseModel):
    person_id: str | None = Field(None, max_length=64)  # null: unlinked by hand
    auto: bool = False  # true: link automatically again (by email, then login)


class PublishBody(BaseModel):
    source: str
    event: str
    payload: dict[str, Any] = {}


class SsoChoice(BaseModel):
    provider: str = Field(max_length=64)


class DefaultProvider(BaseModel):
    tool_id: str | None = Field(None, max_length=64)


class ProviderSettings(BaseModel):
    """Per-provider settings, flat or under "settings"; an empty string clears one."""

    realm: str | None = Field(None, max_length=64)
    slug: str | None = Field(None, max_length=50)
    base_url: str | None = Field(None, max_length=500)
    settings: dict[str, str | None] | None = None


class AtriumClientRequest(BaseModel):
    run_registration: bool = False


def build_router(hub: Hub) -> APIRouter:
    router = APIRouter()

    # Bus messages sent for a request carry the caller's bus id ("user:<name>" or "token:<name>"), so agents
    # can tell a person from automation; the activity log names them by their actor.
    async def ask(p: Principal, recipient: str, subject: str, body: dict[str, Any] | None = None,
                  timeout: float = 120) -> dict[str, Any]:
        try:
            return await hub.bus.request(p.bus_id, recipient, subject, body or {}, timeout)
        except AgentError as exc:
            raise HTTPException(400, str(exc)) from exc

    def not_found(what: str) -> HTTPException:
        return HTTPException(404, f"{what} not found")

    # -- overview ------------------------------------------------------------------------

    @router.get("/health")
    async def health() -> dict[str, Any]:
        return {"ok": True}

    @router.get("/overview")
    async def overview() -> dict[str, Any]:
        tools = hub.tools()
        scores = [t.report.score for t in tools if t.report]
        agents = hub.agents.all()
        states = hub.all("controls", ControlState)
        baseline = framework_scores(states)[0]["score"] if states else None
        assets = hub.all("assets", Asset)
        vulns = hub.all("vulnerabilities", Vulnerability)
        return {
            "tools": len(tools),
            "running": sum(1 for t in tools if t.running),
            "suite_score": round(sum(scores) / len(scores)) if scores else None,
            "agents": len(agents),
            "agents_working": sum(1 for a in agents if a.status == "working"),
            "approvals_pending": hub.approvals.pending_count(),
            "assets": sum(1 for a in assets if a.status != "retired"),
            "compliance_score": baseline,
            "risks_open": sum(1 for r in hub.all("risks", Risk) if r.status != "closed"),
            "vulnerabilities_open": sum(1 for v in vulns if v.status in OPEN_STATES),
            "vulnerabilities_overdue": sum(1 for v in vulns if v.overdue),
            "flows_enabled": sum(1 for f in flows.all_flows(hub) if f.status == "enabled"),
            "people": len(people_app.all_people(hub)),
            "leavers": len(people_app.leavers(hub)),
            "llm": hub.llm.status(),
            "autonomy": hub.prefs["autonomy"],
        }

    # -- tools ---------------------------------------------------------------------------

    @router.get("/tools")
    async def list_tools() -> list[dict[str, Any]]:
        return [t.model_dump(mode="json") for t in hub.tools()]

    @router.post("/tools/import", status_code=202)
    async def import_tool(req: importer.ImportRequest, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            tool = importer.create_tool(hub, req)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await hub.bus.tell(p.bus_id, "supervisor", "tool.import", {"tool_id": tool.id, "branch": req.branch})
        return tool.model_dump(mode="json")

    @router.get("/tools/{tool_id}")
    async def get_tool(tool_id: str) -> dict[str, Any]:
        tool = hub.get_tool(tool_id)
        if tool is None:
            raise not_found("Tool")
        return {
            **tool.model_dump(mode="json"),
            "patches": [p.model_dump(mode="json") for p in sorted(hub.patches(tool_id), key=lambda p: -p.created_at)],
            "process": hub.processes.status(tool_id),
        }

    @router.delete("/tools/{tool_id}")
    async def delete_tool(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        tool = hub.get_tool(tool_id)
        if tool is None:
            raise not_found("Tool")
        await hub.processes.stop(tool_id)
        await hub.agents.remove(f"tool:{tool_id}")
        for patch in hub.patches(tool_id):
            hub.store.delete("patches", patch.id)
        hub.store.delete("tools", tool_id)
        identity.forget_tool(hub, tool_id)
        flows.forget_tool(hub, tool_id, p.actor)
        people_app.forget_tool(hub, tool_id)
        await teams.forget_tool(hub, tool_id, p.actor)
        if tool.source_type == "github" and tool.path:
            await asyncio.to_thread(importer.remove_tree, hub.settings.workspace / "tools" / tool_id)
        hub.bus.publish("tool_removed", {"id": tool_id})
        hub.activity(p.actor, "info", f"Removed {tool.name} from the hub")
        await hub.bus.tell(p.bus_id, "supervisor", "tool.removed",
                           {"tool_id": tool_id, "was_provider": identity.is_provider(tool)})
        return {"ok": True}

    @router.post("/tools/{tool_id}/analyze", status_code=202)
    async def analyze_tool(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        if hub.get_tool(tool_id) is None:
            raise not_found("Tool")
        await hub.bus.tell(p.bus_id, "supervisor", "tool.imported", {"tool_id": tool_id})
        return {"status": "analysing"}

    @router.post("/tools/{tool_id}/patches", status_code=202)
    async def propose_patches(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "patcher", "propose", {"tool_id": tool_id}, timeout=900)

    @router.post("/tools/{tool_id}/start")
    async def start_tool(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "operator", "launch", {"tool_id": tool_id})

    @router.post("/tools/{tool_id}/stop")
    async def stop_tool(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "operator", "stop_tool", {"tool_id": tool_id})

    @router.post("/tools/{tool_id}/health")
    async def tool_health(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, f"tool:{tool_id}", "health", timeout=30)

    @router.get("/tools/{tool_id}/logs")
    async def tool_logs(tool_id: str, lines: int = 300) -> dict[str, Any]:
        return {"lines": hub.processes.logs(tool_id, lines), "process": hub.processes.status(tool_id)}

    @router.post("/tools/{tool_id}/team")
    async def propose_team(tool_id: str, p: CurrentPrincipal, body: TeamRequest | None = None) -> dict[str, Any]:
        """Ask the tool's supervisor to propose an AI agent team (an "agent_team" approval, or created directly)."""
        tool = hub.get_tool(tool_id)
        if tool is None or tool.manifest is None or hub.agents.get(f"tool:{tool_id}") is None:
            raise not_found("Tool")
        return await ask(p, f"tool:{tool_id}", "team.propose", {"designer": (body or TeamRequest()).designer}, timeout=600)

    @router.get("/tools/{tool_id}/strategies")
    async def tool_strategies(tool_id: str) -> list[dict[str, Any]]:
        """How far each way of integrating the tool has got: identity, events, data flows, generated connector, adapters."""
        tool = hub.get_tool(tool_id)
        if tool is None or tool.manifest is None:
            raise not_found("Tool")
        return strategies.tool_strategies(hub, tool)

    # -- connectors and connections (the tool's own API) ---------------------------------

    def tool_or_404(tool_id: str):
        tool = hub.get_tool(tool_id)
        if tool is None:
            raise not_found("Tool")
        return tool

    def connection_view(tool) -> dict[str, Any]:
        builtin = strategies.builtin_connector(tool)
        return {**connections.public(hub, tool, connections.get(hub, tool.id)),
                "flows": [flows.public(hub, f) for f in flows.all_flows(hub, tool.id)],
                "can_generate": hub.llm.available and strategies.has_openapi(tool) and builtin is None,
                "has_openapi": strategies.has_openapi(tool)}

    @router.get("/connectors")
    async def connector_catalog() -> list[dict[str, Any]]:
        return connectors.catalog()

    @router.get("/tools/{tool_id}/connection")
    async def get_connection(tool_id: str) -> dict[str, Any]:
        return connection_view(tool_or_404(tool_id))

    @router.put("/tools/{tool_id}/connection")
    async def put_connection(tool_id: str, body: ConnectionBody, p: CurrentPrincipal) -> dict[str, Any]:
        tool = tool_or_404(tool_id)
        try:
            conn, changed = connections.save(hub, tool_id, body.kind, body.config, body.secrets, p.actor)
        except (ValueError, ConnectorError, SecretError) as exc:
            raise HTTPException(400, getattr(exc, "message", None) or str(exc)) from exc
        what = f"; updated secret(s): {', '.join(changed)}" if changed else ""
        hub.activity(p.actor, "info", f"Saved the {conn.kind} connection of {tool.name}{what}", tool_id=tool_id)
        if not teams.has_team_or_proposal(hub, tool_id):  # a connected tool gets an agent team proposal (once)
            await hub.bus.tell(p.bus_id, f"tool:{tool_id}", "team.propose", {"auto": True})
        return connection_view(tool)

    @router.delete("/tools/{tool_id}/connection")
    async def delete_connection(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        tool = tool_or_404(tool_id)
        if connections.get(hub, tool_id) is None:
            raise not_found("Connection")
        flows.forget_tool(hub, tool_id, p.actor)  # its flows and sync links go with it
        hub.activity(p.actor, "info", f"Removed the connection of {tool.name} and its data flows", tool_id=tool_id)
        return {"ok": True}

    @router.post("/tools/{tool_id}/connection/test")
    async def test_connection(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        tool = tool_or_404(tool_id)
        if connections.get(hub, tool_id) is None:
            raise HTTPException(400, f"{tool.name} has no connection yet")
        result = await ask(p, f"tool:{tool_id}", "connector.test", timeout=180)
        result.pop("failure", None)
        connections.record_test(hub, tool_id, result)
        hub.activity(p.actor, "info" if result.get("ok") else "warn",
                     f"Connection test of {tool.name}: {'ok' if result.get('ok') else 'failed'}", tool_id=tool_id)
        if result.get("ok"):
            await hub.bus.tell(p.bus_id, "supervisor", "flows.plan")
        return {**result, "connection": connection_view(tool)}

    @router.get("/tools/{tool_id}/connection/options/{field}")
    async def connection_options(tool_id: str, field: str, p: CurrentPrincipal) -> dict[str, Any]:
        tool_or_404(tool_id)
        if connections.get(hub, tool_id) is None:
            raise HTTPException(400, "Save the connection first")
        result = await ask(p, f"tool:{tool_id}", "connector.options", {"field": field}, timeout=120)
        if "failure" in result:
            raise HTTPException(400, result["failure"]["message"])
        return result

    @router.post("/tools/{tool_id}/connection/generate", status_code=202)
    async def generate_connector(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        tool_or_404(tool_id)
        return await ask(p, "patcher", "connector.generate", {"tool_id": tool_id}, timeout=900)

    # -- single sign-on ------------------------------------------------------------------

    def provider_or_404(provider_id: str) -> identity.IdentityProvider:
        prefs = identity.load_prefs(hub)
        provider = next((x for x in identity.list_providers(hub.tools(), prefs.settings) if x.tool_id == provider_id), None)
        if provider is None:
            raise not_found("Identity provider")
        return provider

    async def identity_changed(p: Principal) -> dict[str, Any]:
        await ask(p, "supervisor", "identity.changed", timeout=300)
        return identity.overview(hub)

    @router.post("/tools/{tool_id}/sso")
    async def choose_sso_provider(tool_id: str, body: SsoChoice, p: CurrentPrincipal) -> dict[str, Any]:
        """Use `provider` for this tool's single sign-on: a pending SSO patch for another provider is superseded."""
        tool = hub.get_tool(tool_id)
        if tool is None or tool.manifest is None:
            raise not_found("Tool")
        provider = provider_or_404(body.provider)
        if provider.tool_id == tool_id:
            raise HTTPException(400, "A tool cannot sign in through itself")
        identity.set_choice(hub, tool_id, provider.tool_id)
        hub.activity(p.actor, "info", f"{tool.name} signs in through {provider.name}")
        return await ask(p, "patcher", "sso.plan", {"tool_id": tool_id, "actor": p.actor}, timeout=900)

    @router.post("/tools/{tool_id}/sso/register")
    async def register_sso_client(tool_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        """Ask the Operator Agent to run the provider registration script of the tool's applied SSO patch."""
        tool = hub.get_tool(tool_id)
        if tool is None:
            raise not_found("Tool")
        applied = sorted((x for x in hub.patches(tool_id) if x.strategy in SSO_STRATEGIES and x.status == "applied"
                          and x.sso and x.sso.register_command), key=lambda x: -x.created_at)
        if not applied:
            raise HTTPException(400, f"{tool.name} has no applied single sign-on patch with a provider registration script")
        sso = applied[0].sso
        assert sso and sso.register_command
        return await ask(p, "operator", "run", {
            "target": "local", "command": sso.register_command, "cwd": str(hub.settings.workspace / "adapters" / tool_id),
            "reason": f"Register {tool.name} as {sso.protocol.upper()} client {sso.client_id} at {sso.provider_name}",
            "timeout": 300}, timeout=400)

    @router.get("/identity-providers")
    async def identity_providers() -> dict[str, Any]:
        return identity.overview(hub)

    @router.put("/identity-providers/default")
    async def set_default_provider(body: DefaultProvider, p: CurrentPrincipal) -> dict[str, Any]:
        name = provider_or_404(body.tool_id).name if body.tool_id else None
        identity.set_default(hub, body.tool_id)
        hub.activity(p.actor, "info", f"Default identity provider: {name}" if name else "Cleared the default identity provider")
        return await identity_changed(p)

    @router.patch("/identity-providers/{tool_id}")
    async def configure_provider(tool_id: str, body: ProviderSettings, p: CurrentPrincipal) -> dict[str, Any]:
        provider = provider_or_404(tool_id)
        allowed = identity.SETTING_KEYS.get(provider.kind, ("base_url",))
        requested = body.model_dump(exclude_unset=True)
        requested.update(requested.pop("settings", None) or {})
        values: dict[str, str | None] = {}
        for key, value in requested.items():
            if key not in allowed:
                raise HTTPException(400, f"{provider.name} has no setting '{key}'")
            if value is not None and len(value) > 500:
                raise HTTPException(400, f"The value of '{key}' is too long")
            try:
                values[key] = identity.validate_setting(key, value) if value else None
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        settings = identity.set_settings(hub, tool_id, values)
        hub.activity(p.actor, "info", f"Identity provider {provider.name}: " + (", ".join(f"{k}={v}" for k, v in settings.items()) or "defaults"))
        return await identity_changed(p)

    @router.post("/identity-providers/{tool_id}/atrium")
    async def atrium_sign_in_client(tool_id: str, p: CurrentPrincipal, body: AtriumClientRequest | None = None) -> dict[str, Any]:
        """Generate the client Atrium itself signs in with at this provider (the secret stays in the workspace)."""
        provider_or_404(tool_id)
        body = body or AtriumClientRequest()
        try:
            client = await asyncio.to_thread(identity.atrium_client, hub, tool_id)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        hub.activity(p.actor, "info", f"Generated Atrium's sign-in client at {client.provider_name} ({client.location})")
        result = client.public()
        if body.run_registration:
            if not client.register_command:
                raise HTTPException(400, f"There is no registration script for {client.provider_name}; register the client by hand")
            result["registration"] = await ask(p, "operator", "run", {
                "target": "local", "command": client.register_command, "cwd": client.location, "timeout": 300,
                "reason": f"Register Atrium as client {client.client_id} at {client.provider_name}"}, timeout=400)
        return result

    # -- integration ---------------------------------------------------------------------

    @router.get("/integration")
    async def integration() -> dict[str, Any]:
        all_flows = [flows.public(hub, f) for f in flows.all_flows(hub)]
        flow_links = [{"source": "hub" if f["source"] == "hub" else f["source"].split(":", 1)[1],
                       "target": "hub" if f["target"] == "hub" else f["target"].split(":", 1)[1],
                       "type": "flow", "via": f["domain"] + (f" ({f['action']})" if f["action"] else ""),
                       "flow_id": f["id"], "status": f["status"], "failing": bool(f["failures"])} for f in all_flows]
        return {**suite_matrix(hub.tools()), "routes": hub.toolbus.routes(), "deliveries": hub.toolbus.recent(30),
                "flows": all_flows, "flow_links": flow_links}

    @router.post("/integration/evaluate")
    async def reevaluate(p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "supervisor", "reevaluate")

    @router.get("/integration/strategies")
    async def integration_strategies() -> dict[str, Any]:
        return strategies.overview(hub)

    # -- data flows ----------------------------------------------------------------------

    def run_result(result: dict[str, Any]) -> dict[str, Any]:
        """A flow run's reply for the UI: {ok, pending?, detail?, counts?, error?: {message, status, excerpt}, flow}."""
        if "failure" in result:
            result["error"] = result.pop("failure")
        return result

    def flow_or_404(flow_id: str):
        flow = flows.get(hub, flow_id)
        if flow is None:
            raise not_found("Flow")
        return flow

    @router.get("/flows")
    async def list_flows(tool_id: str | None = None, domain: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        items = flows.all_flows(hub, tool_id)
        items = [f for f in items if (not domain or f.domain == domain) and (not status or f.status == status)]
        return [flows.public(hub, f) for f in sorted(items, key=lambda f: (f.status != "enabled", f.title))]

    @router.post("/flows/plan")
    async def plan_flows(p: CurrentPrincipal) -> dict[str, Any]:
        result = await ask(p, "supervisor", "flows.plan", timeout=120)
        return {**result, "flows": [flows.public(hub, f) for f in flows.all_flows(hub)]}

    @router.patch("/flows/{flow_id}")
    async def update_flow(flow_id: str, body: FlowPatch, p: CurrentPrincipal) -> dict[str, Any]:
        flow = flow_or_404(flow_id)
        changes = []
        if body.options is not None:
            try:
                flow.options = flows.validate_options(flow, body.options)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            changes.append("options")
        if body.schedule_minutes is not None:
            flow.schedule_minutes = body.schedule_minutes
            changes.append(f"every {body.schedule_minutes} min" if body.schedule_minutes else "manual only")
        pending = flow.approval_id if flow.status == "proposed" else None
        if body.status and body.status != flow.status:
            flow.status, flow.approval_id = body.status, None
            changes.append(body.status)
        flows.save(hub, flow)
        if pending and body.status:  # deciding here also settles the proposal in the approval queue
            try:
                await hub.approvals.decide(pending, body.status == "enabled", f"{body.status.capitalize()} in the flow list",
                                           p.actor, sender=p.bus_id)
            except (KeyError, ValueError):
                pass
        if changes:
            hub.activity(p.actor, "info", f"Data flow {flow.title}: {', '.join(changes)}", flow_id=flow_id)
        return flows.public(hub, flows.get(hub, flow_id) or flow)

    @router.post("/flows/{flow_id}/run")
    async def run_flow(flow_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        flow = flow_or_404(flow_id)
        if flow.status == "proposed" and not flow.job:  # a scan started by hand on a proposed flow can still be polled
            raise HTTPException(400, "Approve or enable this proposed flow first")
        return run_result(await ask(p, flows.owner(flow), "flow.run", {"flow_id": flow_id, "trigger": "manual"}, timeout=900))

    @router.post("/flows/{flow_id}/repair", status_code=202)
    async def repair_flow(flow_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        """Ask the Patch Agent to diagnose the flow's last failure now (it does so by itself after 3 in a row)."""
        flow = flow_or_404(flow_id)
        if flow.repair and flow.repair != "requested":
            return {"approval_id": flow.repair, "existing": True}
        last = flow.last_result or {}
        if last.get("ok") is not False or not last.get("error"):
            raise HTTPException(400, "This flow has not failed - there is nothing to repair")
        flow.repair = "requested"
        flows.save(hub, flow)
        try:
            return await ask(p, "patcher", "integration.repair", {"flow_id": flow.id, "tool_id": flow.tool_id,
                                                                  "error": last["error"], "sample": last.get("sample")}, timeout=600)
        except HTTPException:
            current = flows.get(hub, flow_id)
            if current is not None and current.repair == "requested":
                current.repair = None
                flows.save(hub, current)
            raise

    @router.delete("/flows/{flow_id}")
    async def delete_flow(flow_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        flow = flows.remove(hub, flow_or_404(flow_id).id, p.actor)
        hub.activity(p.actor, "info", f"Removed data flow {flow.title if flow else flow_id}", flow_id=flow_id)
        return {"ok": True}

    @router.post("/bus/publish")
    async def bus_publish(body: PublishBody) -> dict[str, Any]:
        return {"deliveries": await hub.toolbus.publish(body.source, body.event, body.payload)}

    # -- agents & chat -------------------------------------------------------------------

    def agent_or_404(agent_id: str):
        agent = hub.agents.get(agent_id)
        if agent is None:
            raise not_found("Agent")
        return agent

    def custom_or_400(agent_id: str):
        agent = agent_or_404(agent_id)
        if agent.kind != "custom":
            raise HTTPException(400, f"{agent.name} is a core agent: it has no standing task to run")
        return agent

    @router.get("/agents")
    async def list_agents() -> list[dict[str, Any]]:
        return [a.record() for a in hub.agents.all()]

    @router.get("/agents/teams")
    async def agent_teams() -> dict[str, Any]:
        """Teams with their lead and members, what a proposal would contain per tool, permissions and providers."""
        return teams.overview(hub)

    @router.post("/agents", status_code=201)
    async def create_agent(body: AgentCreate, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            defn = teams.create(hub, body.model_dump(), p.actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        record = agent_or_404(defn.id).record()
        return {**record, "clamped": [x for x in defn.permissions if x not in record["effective_permissions"]]}

    @router.patch("/agents/{agent_id}")
    async def configure_agent(agent_id: str, body: AgentPatch, p: CurrentPrincipal) -> dict[str, Any]:
        agent = agent_or_404(agent_id)
        given = body.model_dump(exclude_unset=True)
        if agent.kind == "custom":
            if given.get("paused") is not None and given.get("enabled") is None:
                given["enabled"] = not given["paused"]
            try:
                defn = teams.update(hub, agent_id, {k: v for k, v in given.items() if k != "paused"}, p.actor)
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
            record = agent_or_404(defn.id).record()
            return {**record, "clamped": [x for x in defn.permissions if x not in record["effective_permissions"]]}
        extra = sorted(k for k in given if k not in CORE_AGENT_FIELDS)
        if extra:
            raise HTTPException(400, f"{agent.name} is a core agent: only paused, model and instructions can be changed "
                                     f"(not {', '.join(extra)})")
        record = hub.agents.configure(agent_id, **{k: given.get(k) for k in CORE_AGENT_FIELDS})
        changed = ", ".join(k for k, v in given.items() if v is not None)
        if changed:
            hub.activity(p.actor, "info", f"Configured {record['name']}: {changed}", agent_id=agent_id)
        return record

    @router.delete("/agents/{agent_id}")
    async def delete_agent(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        agent = agent_or_404(agent_id)
        if agent.kind != "custom":
            raise HTTPException(400, f"{agent.name} is a core agent: it cannot be removed (pause it instead)")
        await teams.remove(hub, agent_id, p.actor)
        return {"ok": True}

    @router.post("/agents/{agent_id}/chat")
    async def chat_with_agent(agent_id: str, body: ChatBody, p: CurrentPrincipal) -> dict[str, Any]:
        """Chat with the Hub Supervisor or any team agent (Claude, a local model, or rules)."""
        agent = agent_or_404(agent_id)
        if agent_id != "supervisor" and agent.kind != "custom":
            raise HTTPException(400, f"{agent.name} does not chat - chat with the Hub Supervisor or a team agent")
        if agent.paused:
            raise HTTPException(409, f"{agent.name} is {'disabled' if agent.kind == 'custom' else 'paused'}")
        if not body.text.strip():
            raise HTTPException(400, "Say something")
        return {**await ask(p, agent_id, "chat", {"text": body.text}, timeout=900), "agent_id": agent_id}

    @router.post("/agents/{agent_id}/chat/reset")
    async def reset_agent_chat(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        agent = agent_or_404(agent_id)
        if agent_id != "supervisor" and agent.kind != "custom":
            raise HTTPException(400, f"{agent.name} does not chat")
        if agent.paused:
            raise HTTPException(409, f"{agent.name} is {'disabled' if agent.kind == 'custom' else 'paused'}")
        return await ask(p, agent_id, "chat.reset")

    @router.post("/agents/{agent_id}/run")
    async def run_agent(agent_id: str, p: CurrentPrincipal, body: AgentRun | None = None) -> dict[str, Any]:
        """Run a team agent's standing task now (or the given task, once)."""
        agent = custom_or_400(agent_id)
        if agent.paused:
            raise HTTPException(409, f"{agent.name} is disabled")
        payload: dict[str, Any] = {"trigger": "manual"}
        if body and body.task and body.task.strip():
            payload["task"] = body.task.strip()
        return await ask(p, agent_id, "run", payload, timeout=900)

    @router.get("/agents/{agent_id}/messages")
    async def agent_messages(agent_id: str, limit: int = 100) -> list[dict[str, Any]]:
        recent = hub.store.tail("messages", 2000)
        return [m for m in recent if agent_id in (m["sender"], m["recipient"])][-limit:]

    @router.get("/messages")
    async def messages(limit: int = 200) -> list[dict[str, Any]]:
        return hub.store.tail("messages", min(limit, 2000))

    @router.get("/activity")
    async def activity(limit: int = 100) -> list[dict[str, Any]]:
        return hub.store.tail("activity", min(limit, 2000))

    @router.post("/chat")
    async def chat(body: ChatBody, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "supervisor", "chat", {"text": body.text}, timeout=900)

    @router.post("/chat/reset")
    async def chat_reset(p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "supervisor", "chat.reset")

    # -- approvals -----------------------------------------------------------------------

    @router.get("/approvals")
    async def approvals(status: str | None = None) -> list[dict[str, Any]]:
        out = []
        for a in hub.approvals.list(status):
            item = a.model_dump(mode="json")
            if a.kind == "patch":
                patch = hub.get_patch(a.payload.get("patch_id", ""))
                item["patch"] = patch.model_dump(mode="json", exclude={"changes", "adapter_changes"}) if patch else None
            out.append(item)
        return out

    @router.post("/approvals/{approval_id}")
    async def decide(approval_id: str, body: DecisionBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            approval = await hub.approvals.decide(approval_id, body.approve, body.note, p.actor, sender=p.bus_id)
        except KeyError as exc:
            raise not_found("Approval") from exc
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return approval.model_dump(mode="json")

    @router.get("/patches/{patch_id}")
    async def get_patch(patch_id: str) -> dict[str, Any]:
        patch = hub.get_patch(patch_id)
        if patch is None:
            raise not_found("Patch")
        return patch.model_dump(mode="json")

    # -- operator: hosts & commands ------------------------------------------------------

    @router.get("/hosts")
    async def hosts() -> list[dict[str, Any]]:
        return [h.model_dump(mode="json") for h in hub.hosts()]

    @router.post("/hosts", status_code=201)
    async def add_host(host: Host, p: CurrentPrincipal) -> dict[str, Any]:
        host.id = host.id or importer.slugify(host.name)
        if hub.get_host(host.id) or host.id == "local":
            host.id = f"{host.id}-{new_id()[:4]}"
        hub.save("hosts", host, "host")
        hub.activity(p.actor, "info", f"Registered host {host.name} ({host.username}@{host.address})")
        await hub.bus.tell(p.bus_id, "module:assets", "sync")
        return host.model_dump(mode="json")

    @router.delete("/hosts/{host_id}")
    async def delete_host(host_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        host = hub.get_host(host_id)
        if host is None or not hub.store.delete("hosts", host_id):
            raise not_found("Host")
        hub.bus.publish("host_removed", {"id": host_id})
        hub.activity(p.actor, "info", f"Removed host {host.name}")
        await hub.bus.tell(p.bus_id, "module:assets", "sync")
        return {"ok": True}

    @router.post("/hosts/{host_id}/discover")
    async def discover_host(host_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "module:assets", "discover", {"host_id": host_id}, timeout=180)

    @router.post("/commands")
    async def run_command(body: CommandBody, p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "operator", "run", body.model_dump(), timeout=body.timeout + 30)

    @router.get("/commands")
    async def command_history(limit: int = 50) -> list[dict[str, Any]]:
        return hub.store.tail("commands", min(limit, 500))

    # -- assets --------------------------------------------------------------------------

    @router.get("/assets")
    async def assets() -> list[dict[str, Any]]:
        return [a.model_dump(mode="json") for a in hub.all("assets", Asset)]

    def person_or_400(person_id: str | None, what: str):
        if not person_id:
            return None
        person = people_app.get(hub, person_id)
        if person is None:
            raise HTTPException(400, f"Unknown person for {what}: '{person_id}'")
        return person

    def link_people(data: dict[str, Any], changes: dict[str, Any]) -> dict[str, Any]:
        """Validate person links in an asset change; a person picked as owner also fills the free-text owner."""
        owner = person_or_400(changes.get("owner_person_id"), "the owner")
        if owner is not None and not changes.get("owner"):
            data["owner"] = owner.display_name
        if "assigned_person_id" in changes:
            person_or_400(changes.get("assigned_person_id"), "the assigned user")
            data["assigned_source"] = "manual"
        if changes.get("assigned_source") == "auto":
            data["assigned_source"] = "auto"
            data["assigned_person_id"] = people_app.assigned_person(Asset.model_validate(data),
                                                                    people_app.Index.of(people_app.all_people(hub)))
        return data

    @router.post("/assets", status_code=201)
    async def create_asset(asset: Asset, p: CurrentPrincipal) -> dict[str, Any]:
        asset.id = new_id("a_")
        given = asset.model_dump(exclude_unset=True)
        asset = Asset.model_validate(link_people(asset.model_dump(), given))
        hub.save("assets", asset, "asset")
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return asset.model_dump(mode="json")

    @router.patch("/assets/{asset_id}")
    async def update_asset(asset_id: str, changes: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
        current = hub.one("assets", asset_id, Asset)
        if current is None:
            raise not_found("Asset")
        allowed = {"name", "type", "owner", "criticality", "status", "tags", "facts", "scan_scope", "owner_person_id",
                   "assigned_person_id", "assigned_source"}
        given = {k: v for k, v in changes.items() if k in allowed}
        merged = Asset.model_validate(link_people({**current.model_dump(), **given, "updated_at": time.time()}, given))
        hub.save("assets", merged, "asset")
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return merged.model_dump(mode="json")

    @router.delete("/assets/{asset_id}")
    async def delete_asset(asset_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        if not hub.store.delete("assets", asset_id):
            raise not_found("Asset")
        hub.bus.publish("asset_removed", {"id": asset_id})
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return {"ok": True}

    @router.post("/assets/sync")
    async def sync_assets(p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "module:assets", "sync")

    @router.post("/assets/scan-scope")
    async def set_scan_scope(body: ScanScope, p: CurrentPrincipal) -> dict[str, Any]:
        """Put assets in (or take them out of) vulnerability-scan scope; only in-scope assets are ever scanned."""
        result = await ask(p, "module:assets", "scan.scope", body.model_dump())
        if result["changed"]:
            hub.activity(p.actor, "info", f"{len(result['changed'])} asset(s) {'put in' if body.in_scope else 'taken out of'} "
                                          "vulnerability-scan scope")
        return result

    # -- people --------------------------------------------------------------------------

    def person_or_404(person_id: str):
        person = people_app.get(hub, person_id)
        if person is None:
            raise not_found("Person")
        return person

    async def people_changed(p: Principal) -> None:
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")

    @router.get("/people")
    async def list_people(q: str = "", status: str = "", department: str = "", source: str = "") -> dict[str, Any]:
        """Filters: q (name, email, login, title, department, groups), status (comma-separated), department, source
        (a tool id or "manual")."""
        return people_app.listing(hub, q=q[:200], status=status[:100], department=department[:200], source=source[:64])

    @router.get("/people/leavers")
    async def list_leavers() -> dict[str, Any]:
        return {"leavers": people_app.leavers(hub),
                "actions": [{"id": k, **v} for k, v in people_app.ACTIONS.items()]}

    @router.get("/people/{person_id}")
    async def get_person(person_id: str) -> dict[str, Any]:
        return people_app.detail(hub, person_or_404(person_id))

    @router.post("/people", status_code=201)
    async def create_person(body: PersonBody, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            person = people_app.create(hub, body.model_dump(), p.actor)
        except LookupError as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc).removeprefix("Value error, ")) from exc
        await people_changed(p)
        return people_app.detail(hub, person)

    @router.patch("/people/{person_id}")
    async def update_person(person_id: str, body: PersonPatch, p: CurrentPrincipal) -> dict[str, Any]:
        person = person_or_404(person_id)
        changes = body.model_dump(exclude_unset=True)
        if "display_name" in changes and not changes["display_name"]:
            raise HTTPException(400, "A person needs a name")
        try:
            person = people_app.update(hub, person, changes, p.actor)
        except LookupError as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await people_changed(p)
        return people_app.detail(hub, person)

    @router.delete("/people/{person_id}")
    async def delete_person(person_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        people_app.delete(hub, person_or_404(person_id), p.actor)
        await people_changed(p)
        return {"ok": True}

    @router.post("/people/{person_id}/actions/{action}")
    async def person_action(person_id: str, action: str, p: CurrentPrincipal,
                            body: PersonAction | None = None) -> dict[str, Any]:
        """unassign_assets (operator) or disable_atrium_account (admin; the role is checked by the policy)."""
        person = person_or_404(person_id)
        if action == "unassign_assets":
            result = people_app.unassign_assets(hub, person, p.actor, (body or PersonAction()).asset_ids)
        elif action == "disable_atrium_account":
            result = people_app.disable_atrium_account(hub, person, p)
        else:
            raise HTTPException(404, f"Unknown action '{action}': use {', '.join(people_app.ACTIONS)}")
        await people_changed(p)
        return {**result, "person": people_app.detail(hub, person)}

    @router.get("/accounts")
    async def list_accounts(tool_id: str | None = None, person_id: str | None = None,
                            unlinked: bool = False) -> list[dict[str, Any]]:
        """User accounts in the tools (and directory entries), with the person each is linked to."""
        by_id = {x.id: x for x in people_app.all_people(hub)}
        names = people_app.source_names(hub)
        out = []
        for account in people_app.all_accounts(hub, tool_id):
            if person_id and account.person_id != person_id or unlinked and account.person_id:
                continue
            out.append({**account.model_dump(mode="json"), "tool": names.get(account.tool_id, account.tool_id),
                        "person": people_app.brief(by_id.get(account.person_id or ""))})
        return sorted(out, key=lambda a: (a["tool"].lower(), (a["login"] or a["email"] or "").lower()))

    @router.patch("/accounts/{account_id:path}")
    async def link_account(account_id: str, body: AccountLink, p: CurrentPrincipal) -> dict[str, Any]:
        account = hub.one(people_app.ACCOUNTS, account_id, people_app.Account)
        if account is None:
            raise not_found("Account")
        if body.auto:
            account.person_source = "auto"
            account.person_id = people_app.Index.of(people_app.all_people(hub)).match(account.email, account.login)
        else:
            person = person_or_400(body.person_id, "the account") if body.person_id else None
            account.person_id, account.person_source = (person.id if person else None), "manual"
        people_app.save_account(hub, account)
        hub.activity(p.actor, "info", f"Account {account.login or account.external_id} in {account.tool_id}: "
                                      + (f"linked to {account.person_id}" if account.person_id else "not linked"),
                     person_id=account.person_id)
        await people_changed(p)
        return account.model_dump(mode="json")

    # -- vulnerabilities -----------------------------------------------------------------

    def vuln_or_404(vuln_id: str) -> Vulnerability:
        vuln = hub.one("vulnerabilities", vuln_id, Vulnerability)
        if vuln is None:
            raise not_found("Vulnerability")
        return vuln

    @router.get("/vulnerabilities")
    async def list_vulnerabilities(status: str | None = None, severity: str | None = None, asset_id: str | None = None,
                                   source: str | None = None, q: str | None = None, overdue: bool | None = None,
                                   limit: int = 2000) -> list[dict[str, Any]]:
        """Filters: status and severity take comma-separated values ("active" = open + in_progress); q searches the
        title, host, CVEs and description."""
        statuses = {s for part in (status or "").split(",") if (s := part.strip())}
        if "active" in statuses:
            statuses = (statuses - {"active"}) | set(OPEN_STATES)
        severities = {s.strip() for s in (severity or "").split(",") if s.strip()}
        needle = (q or "").strip().lower()
        items = []
        for v in hub.all("vulnerabilities", Vulnerability):
            if statuses and v.status not in statuses or severities and v.severity not in severities:
                continue
            if asset_id and v.asset_id != asset_id or source and v.source != source:
                continue
            if overdue is not None and v.overdue != overdue:
                continue
            if needle and needle not in " ".join([v.title, v.host or "", *v.cves, v.description[:2000]]).lower():
                continue
            items.append(v)
        items.sort(key=lambda v: (v.status not in OPEN_STATES, SEVERITY_ORDER.index(v.severity), v.due_at or float("inf")))
        return [v.model_dump(mode="json") for v in items[:max(1, min(limit, 10_000))]]

    @router.get("/vulnerabilities/summary")
    async def vulnerability_summary() -> dict[str, Any]:
        return vuln_app.summary(hub)

    @router.get("/vulnerabilities/{vuln_id}")
    async def get_vulnerability(vuln_id: str) -> dict[str, Any]:
        return vuln_or_404(vuln_id).model_dump(mode="json")

    @router.patch("/vulnerabilities/{vuln_id}")
    async def update_vulnerability(vuln_id: str, body: VulnPatch, p: CurrentPrincipal) -> dict[str, Any]:
        vuln = vuln_or_404(vuln_id)
        if body.status and body.status != vuln.status:
            vuln.status = body.status
            vuln.fixed_at = time.time() if body.status == "fixed" else None
            hub.activity(p.actor, "info", f"Vulnerability '{vuln.title}' ({vuln.host or 'no host'}) set to {body.status}",
                         vulnerability_id=vuln_id)
        if body.note is not None:
            vuln.note = body.note.strip() or None
        hub.save("vulnerabilities", vuln, "vulnerability")
        await hub.bus.tell(p.bus_id, "module:vulns", "reconcile")
        return vuln.model_dump(mode="json")

    @router.post("/vulnerabilities/scan")
    async def scan_now(body: ScanRequest, p: CurrentPrincipal) -> dict[str, Any]:
        """Scan the given in-scope assets (default: all in scope) with the chosen scanner (default: the only one)."""
        return run_result(await ask(p, "module:vulns", "scan.request", body.model_dump(), timeout=600))

    # -- GRC -----------------------------------------------------------------------------

    @router.get("/grc")
    async def grc() -> dict[str, Any]:
        states = hub.all("controls", ControlState)
        return {"frameworks": framework_scores(states) if states else [], "controls": control_catalog(states)}

    @router.post("/grc/evaluate")
    async def grc_evaluate(p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "module:grc", "evaluate")

    @router.patch("/grc/controls/{control_id}")
    async def override_control(control_id: str, body: ControlOverride, p: CurrentPrincipal) -> dict[str, Any]:
        state = hub.one("controls", control_id, ControlState) or ControlState(id=control_id)
        if body.clear:
            state.manual, state.note = False, None
        else:
            state.manual = True
            state.status = body.status or state.status
            state.note = body.note
        hub.store.put("controls", state.model_dump(mode="json"))
        hub.activity(p.actor, "info", f"Control {control_id} " + ("set back to automatic" if body.clear else f"set to {state.status} by hand"))
        return await ask(p, "module:grc", "evaluate")

    def crud(collection: str, model: type[Risk] | type[Policy], event: str, prefix: str) -> None:
        @router.get(f"/grc/{collection}", name=f"list_{collection}")
        async def list_items() -> list[dict[str, Any]]:
            return [i.model_dump(mode="json") for i in hub.all(collection, model)]

        @router.post(f"/grc/{collection}", status_code=201, name=f"create_{collection}")
        async def create_item(data: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
            owner = person_or_400(data.get("owner_person_id"), "the owner")
            if owner is not None and not data.get("owner"):
                data = {**data, "owner": owner.display_name}
            item = model.model_validate({**data, "id": new_id(prefix)})
            if isinstance(item, Risk):
                item.reviewed_at = time.time()
            hub.save(collection, item, event)
            await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
            return item.model_dump(mode="json")

        @router.patch(f"/grc/{collection}/{{item_id}}", name=f"update_{collection}")
        async def update_item(item_id: str, changes: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
            current = hub.one(collection, item_id, model)
            if current is None:
                raise not_found(event.capitalize())
            data = {**current.model_dump(), **{k: v for k, v in changes.items() if k not in ("id", "score")}}
            owner = person_or_400(changes.get("owner_person_id"), "the owner")
            if owner is not None and not changes.get("owner"):
                data["owner"] = owner.display_name
            if isinstance(current, Risk):
                data["reviewed_at"] = time.time()
            if isinstance(current, Policy):
                data["updated_at"] = time.time()
            item = model.model_validate(data)
            hub.save(collection, item, event)
            await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
            return item.model_dump(mode="json")

        @router.delete(f"/grc/{collection}/{{item_id}}", name=f"delete_{collection}")
        async def delete_item(item_id: str, p: CurrentPrincipal) -> dict[str, Any]:
            if not hub.store.delete(collection, item_id):
                raise not_found(event.capitalize())
            hub.bus.publish(f"{event}_removed", {"id": item_id})
            await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
            return {"ok": True}

    crud("risks", Risk, "risk", "r_")
    crud("policies", Policy, "policy", "pol_")

    @router.get("/grc/policy-templates")
    async def policy_templates() -> dict[str, Any]:
        return POLICY_TEMPLATES

    # -- settings ------------------------------------------------------------------------

    @router.get("/settings")
    async def get_settings() -> dict[str, Any]:
        prefs = hub.prefs
        return {**prefs, "guardrail_catalog": guardrails.catalog(prefs["guardrails"]), "llm": hub.llm.status(),
                "data_dir": str(hub.settings.data_dir), "version": __import__("hub").__version__}

    @router.patch("/settings")
    async def patch_settings(body: SettingsPatch, p: CurrentPrincipal) -> dict[str, Any]:
        values = body.model_dump(exclude={"vuln_sla_days", "guardrails"})
        if body.vuln_sla_days:
            if any(not 1 <= days <= 3650 for days in body.vuln_sla_days.values()):
                raise HTTPException(400, "SLA days must be between 1 and 3650")
            values["vuln_sla_days"] = {**hub.prefs["vuln_sla_days"], **body.vuln_sla_days}
        try:
            if body.guardrails:
                guardrails.validate(body.guardrails)  # nothing is stored when any value is invalid
            if any(v is not None for v in values.values()):
                hub.update_prefs(p.actor, **values)
            if body.guardrails:
                guardrails.update(hub, p.actor, body.guardrails)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if body.vuln_sla_days:
            await hub.bus.tell(p.bus_id, "module:vulns", "sla.recompute")
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return await get_settings()

    @router.patch("/settings/guardrails")
    async def patch_guardrails(body: dict[str, bool | int], p: CurrentPrincipal) -> dict[str, Any]:
        """Change guardrails ({key: value}); each change is logged with the actor, relaxations as warnings."""
        if not body:
            raise HTTPException(400, "Send at least one guardrail")
        try:
            guardrails.update(hub, p.actor, body)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return await get_settings()

    # -- AI model providers --------------------------------------------------------------

    def provider_or_404_llm(provider_id: str):
        provider = llm_providers.get(hub, provider_id)
        if provider is None:
            raise not_found("Provider")
        return provider

    def providers_view() -> dict[str, Any]:
        return {"providers": [llm_providers.public(x) for x in llm_providers.all_providers(hub)],
                "choices": teams.provider_choices(hub), "anthropic": hub.llm.status(),
                "default_base_url": llm_providers.DEFAULT_BASE_URL, "kinds": ["openai_compatible"]}

    @router.get("/llm/providers")
    async def list_llm_providers() -> dict[str, Any]:
        return providers_view()

    @router.post("/llm/providers", status_code=201)
    async def create_llm_provider(body: ProviderCreate, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            provider, _ = llm_providers.save(hub, None, body.model_dump(), p.actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        key = "; API key set" if provider.api_key else ""
        hub.activity(p.actor, "info", f"Added the local model provider {provider.name} ({provider.base_url}){key}",
                     provider_id=provider.id)
        return llm_providers.public(provider)

    @router.patch("/llm/providers/{provider_id}")
    async def update_llm_provider(provider_id: str, body: ProviderPatch, p: CurrentPrincipal) -> dict[str, Any]:
        provider_or_404_llm(provider_id)
        try:
            provider, key_changed = llm_providers.save(hub, provider_id, body.model_dump(), p.actor)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        changed = [k for k, v in body.model_dump(exclude={"api_key", "clear_api_key"}).items() if v is not None]
        what = ", ".join(changed + (["API key"] if key_changed else []))
        hub.activity(p.actor, "info", f"Changed the local model provider {provider.name}" + (f": {what}" if what else ""),
                     provider_id=provider.id)
        return llm_providers.public(provider)

    @router.delete("/llm/providers/{provider_id}")
    async def delete_llm_provider(provider_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        provider = provider_or_404_llm(provider_id)
        users = [d.name for d in teams.defs(hub) if d.provider == provider_id]
        if users:
            raise HTTPException(409, f"{provider.name} is used by {', '.join(users[:5])}"
                                     f"{' and more' if len(users) > 5 else ''} - move them to another provider first")
        llm_providers.delete(hub, provider_id)
        hub.activity(p.actor, "info", f"Removed the local model provider {provider.name}", provider_id=provider_id)
        return {"ok": True}

    @router.post("/llm/providers/{provider_id}/test")
    async def test_llm_provider(provider_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        result = await llm_providers.test(hub, provider_or_404_llm(provider_id))
        hub.activity(p.actor, "info" if result["ok"] else "warn",
                     f"Tested the local model provider {result['provider']['name']}: {result['detail']}",
                     provider_id=provider_id)
        return result

    # -- live events (SSE) ---------------------------------------------------------------

    @router.get("/events")
    async def events(request: Request, p: CurrentPrincipal) -> StreamingResponse:
        queue = hub.bus.subscribe()

        async def stream():
            checked = time.monotonic()
            try:
                yield "retry: 3000\n\n"
                while not await request.is_disconnected():
                    if time.monotonic() - checked >= 15:  # end the stream once the session or token is revoked
                        if not hub.auth.still_valid(p):
                            break
                        checked = time.monotonic()
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
                        continue
                    yield f"data: {json.dumps(event, default=str)}\n\n"
            finally:
                hub.bus.unsubscribe(queue)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return router
