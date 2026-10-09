"""REST + Server-Sent Events API used by the web UI (and by tools publishing events)."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from .agents.grc import control_catalog
from .auth.service import CurrentPrincipal, Principal
from .bus import AgentError
from .core import Hub
from .grc.baseline import POLICY_TEMPLATES
from .grc.checks import framework_scores
from .integration import importer
from .integration.compatibility import suite_matrix
from .models import Asset, ControlState, Host, Policy, Risk
from .store import new_id


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
    paused: bool | None = None
    model: str | None = None
    instructions: str | None = None


class SettingsPatch(BaseModel):
    autonomy: Literal["manual", "assisted", "autonomous"] | None = None
    model: str | None = None


class ControlOverride(BaseModel):
    status: Literal["pass", "partial", "fail", "manual", "na"] | None = None
    note: str | None = None
    clear: bool = False


class PublishBody(BaseModel):
    source: str
    event: str
    payload: dict[str, Any] = {}


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
        if tool.source_type == "github" and tool.path:
            await asyncio.to_thread(importer.remove_tree, hub.settings.workspace / "tools" / tool_id)
        hub.bus.publish("tool_removed", {"id": tool_id})
        hub.activity(p.actor, "info", f"Removed {tool.name} from the hub")
        await hub.bus.tell(p.bus_id, "supervisor", "tool.removed", {"tool_id": tool_id})
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

    # -- integration ---------------------------------------------------------------------

    @router.get("/integration")
    async def integration() -> dict[str, Any]:
        return {**suite_matrix(hub.tools()), "routes": hub.toolbus.routes(), "deliveries": hub.toolbus.recent(30)}

    @router.post("/integration/evaluate")
    async def reevaluate(p: CurrentPrincipal) -> dict[str, Any]:
        return await ask(p, "supervisor", "reevaluate")

    @router.post("/bus/publish")
    async def bus_publish(body: PublishBody) -> dict[str, Any]:
        return {"deliveries": await hub.toolbus.publish(body.source, body.event, body.payload)}

    # -- agents & chat -------------------------------------------------------------------

    @router.get("/agents")
    async def list_agents() -> list[dict[str, Any]]:
        return [a.record() for a in hub.agents.all()]

    @router.patch("/agents/{agent_id}")
    async def configure_agent(agent_id: str, body: AgentPatch, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            record = hub.agents.configure(agent_id, **body.model_dump())
        except KeyError as exc:
            raise not_found("Agent") from exc
        changed = ", ".join(k for k, v in body.model_dump().items() if v is not None)
        if changed:
            hub.activity(p.actor, "info", f"Configured {record['name']}: {changed}", agent_id=agent_id)
        return record

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
                item["patch"] = patch.model_dump(mode="json", exclude={"changes"}) if patch else None
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

    @router.post("/assets", status_code=201)
    async def create_asset(asset: Asset, p: CurrentPrincipal) -> dict[str, Any]:
        asset.id = new_id("a_")
        hub.save("assets", asset, "asset")
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return asset.model_dump(mode="json")

    @router.patch("/assets/{asset_id}")
    async def update_asset(asset_id: str, changes: dict[str, Any], p: CurrentPrincipal) -> dict[str, Any]:
        current = hub.one("assets", asset_id, Asset)
        if current is None:
            raise not_found("Asset")
        allowed = {"name", "type", "owner", "criticality", "status", "tags", "facts"}
        merged = Asset.model_validate({**current.model_dump(), **{k: v for k, v in changes.items() if k in allowed},
                                       "updated_at": time.time()})
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
        return {**hub.prefs, "llm": hub.llm.status(), "data_dir": str(hub.settings.data_dir),
                "version": __import__("hub").__version__}

    @router.patch("/settings")
    async def patch_settings(body: SettingsPatch, p: CurrentPrincipal) -> dict[str, Any]:
        try:
            hub.update_prefs(p.actor, **body.model_dump())
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        await hub.bus.tell(p.bus_id, "module:grc", "evaluate")
        return await get_settings()

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
