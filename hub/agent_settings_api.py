"""REST routes of agent settings beyond the model choice (round4-agents-spec.md 10, 13; added to the main router by
``api.build_router``; GET/PATCH /api/agents/{id}/settings stay in api.py). Roles are classified in
``hub/auth/policy.py``:

  GET    /api/agents/{id}/settings/history   viewer    [{version, actor, at, changed, restored_from}], newest first
  POST   /api/agents/{id}/settings/restore   admin     {version, base_version?} -> the settings view (a new version)
  POST   /api/agents/{id}/playground         admin     {prompt, draft?, compare_with?, allow_actions?} -> {runs}
  POST   /api/agents/{id}/budget/override    admin     {reason, extra_usd?, extra_tokens?} -> budget state
  GET    /api/agents/{id}/usage?days=        viewer    per-day calls, tokens and estimated cost
  GET    /api/agents/{id}/conversation       operator  the caller's own conversation with the agent
  DELETE /api/agents/{id}/conversation       operator  the caller's own (?user_id=: an administrator, anyone's)
  GET    /api/llm/usage?days=&group=&agent_id=  viewer  totals and rows by agent / provider / model / day, the cap
  POST   /api/agents/{id}/schedule/resume    admin     a custom agent's schedule paused after failed runs runs again
  GET    /api/agents/attention               viewer    the Agents page's "Needs attention" strip (for_you per item)

The playground never uses the bus: the prompt and the reply never reach the message log or the event stream (review
D7). Its calls count toward the suite's daily cap only. Nothing in it is stored; the activity log names the models and
token counts, never the prompt.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import TYPE_CHECKING, Any, Literal

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .agents import notify, toolkit
from .agents import settings as agent_settings
from .auth.service import CurrentPrincipal
from .llm import Limited, LLMUnavailable, Msg, ProviderError
from .llm import resolve as resolution
from .llm import usage as llm_usage
from .llm.resolve import Resolution
from .models import LlmChoice

if TYPE_CHECKING:
    from .agents.base import BaseAgent
    from .core import Hub

PLAYGROUND_TIMEOUT = 300.0
READ_ONLY_TOOLS = {"test_tool_connection", "read_tool_records"}  # tool_api tools that change nothing
ACTION_TOOLS = {"escalate"}  # "read" tools that still create something (an approval): with allow_actions only
PREVIEW_ARGS, PREVIEW_RESULT = 500, 300


class RestoreBody(BaseModel):
    version: int = Field(ge=0)
    base_version: int | None = None  # the version the caller saw: refused (409) when the settings moved since


class PlaygroundBody(BaseModel):
    prompt: str = Field(min_length=1, max_length=8000)
    draft: dict[str, Any] | None = None  # a partial AgentSettings, checked like PATCH /settings, never stored
    compare_with: LlmChoice | None = None
    allow_actions: bool = False


class BudgetOverride(BaseModel):
    reason: str = Field(min_length=5, max_length=500)
    extra_usd: float | None = Field(None, ge=0.01, le=100_000)
    extra_tokens: int | None = Field(None, ge=1, le=10_000_000_000)


def add_routes(router: APIRouter, hub: "Hub") -> None:
    def agent_or_404(agent_id: str) -> "BaseAgent":
        agent = hub.agents.get(agent_id)
        if agent is None:
            raise HTTPException(404, "Agent not found")
        return agent

    def model_agent(agent_id: str) -> "BaseAgent":
        agent = agent_or_404(agent_id)
        if not agent_settings.uses_model(agent):
            raise HTTPException(400, f"{agent.name} works without an AI model")
        return agent

    def chat_agent(agent_id: str) -> "BaseAgent":
        agent = agent_or_404(agent_id)
        if not agent_settings.chats(agent):
            raise HTTPException(400, f"{agent.name} does not chat - chat with the Hub Supervisor or a team agent")
        return agent

    # -- history ---------------------------------------------------------------------------

    @router.get("/agents/{agent_id}/settings/history")
    async def settings_history(agent_id: str) -> list[dict[str, Any]]:
        return agent_settings.history(hub, agent_or_404(agent_id).id)

    @router.post("/agents/{agent_id}/settings/restore")
    async def restore_settings(agent_id: str, body: RestoreBody, p: CurrentPrincipal) -> Any:
        agent = agent_or_404(agent_id)
        try:
            view, lines, loosened = agent_settings.restore(hub, agent, body.version, p.actor, body.base_version)
        except KeyError as exc:
            raise HTTPException(404, f"Version {body.version} of {agent.name}'s settings is not kept") from exc
        except agent_settings.Conflict as exc:
            return JSONResponse(status_code=409, content={"detail": str(exc), "code": "version_conflict",
                                                          "settings": exc.view, "version": exc.view["version"]})
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if lines:
            hub.activity(p.actor, "warn" if loosened else "info",
                         f"Restored {agent.name} settings to version {body.version}: " + "; ".join(lines[1:] or lines),
                         agent_id=agent.id, version=view["version"], restored_from=body.version)
            await hub.bus.tell(p.bus_id, "module:grc", "evaluate")  # HB-SC-1: which cloud providers are in use
        return view

    # -- budgets and usage -----------------------------------------------------------------

    @router.post("/agents/{agent_id}/budget/override")
    async def budget_override(agent_id: str, body: BudgetOverride, p: CurrentPrincipal) -> dict[str, Any]:
        agent = model_agent(agent_id)
        reason = " ".join(body.reason.split())
        if len(reason) < 5:
            raise HTTPException(400, "Give a reason (at least 5 characters)")
        hub.llm.meter.lift(agent.id, reason=reason, actor=p.actor, extra_usd=body.extra_usd,
                           extra_tokens=body.extra_tokens)
        what = ", ".join(x for x in (f"+${body.extra_usd:.2f}" if body.extra_usd else "",
                                     f"+{body.extra_tokens:,} tokens" if body.extra_tokens else "") if x) \
            or "no budget stop for the rest of the day"
        hub.activity(p.actor, "warn", f"Lifted today's budget stop for {agent.name} ({what}): {reason}",
                     agent_id=agent.id, extra_usd=body.extra_usd, extra_tokens=body.extra_tokens)
        agent_settings.published(hub, agent.id)
        return hub.llm.meter.state(agent.id)

    @router.get("/agents/{agent_id}/usage")
    async def agent_usage(agent_id: str, days: int = Query(30, ge=1, le=400)) -> dict[str, Any]:
        agent = agent_or_404(agent_id)
        return {**agent_settings.usage(hub, agent.id, days), "budget_state": hub.llm.meter.state(agent.id)}

    @router.get("/llm/usage")
    async def llm_usage_report(days: int = Query(30, ge=1, le=400),
                               group: Literal["agent", "provider", "model", "day"] = "agent",
                               agent_id: str | None = Query(None, max_length=120)) -> dict[str, Any]:
        """AI model use and estimated cost (counts only, never text) and the suite's daily cap."""
        return llm_usage.usage_report(hub, days=days, group=group, agent_id=agent_id or None)

    # -- escalation and notifications ------------------------------------------------------

    @router.get("/agents/attention")
    async def needs_attention(p: CurrentPrincipal) -> dict[str, Any]:
        """Pending escalations, budgets reached, paused schedules, held agents and agents whose chosen model cannot
        run - each `for_you` when the agent's notifications target the caller."""
        return {"items": notify.attention(hub, p)}

    @router.post("/agents/{agent_id}/schedule/resume")
    async def resume_schedule(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        agent = agent_or_404(agent_id)
        if agent.kind != "custom":
            raise HTTPException(400, f"{agent.name} is a core agent: it has no schedule to resume")
        notify.resume(hub, agent.id, p.actor)
        return agent.record()

    # -- conversations (memory) ------------------------------------------------------------

    @router.get("/agents/{agent_id}/conversation")
    async def own_conversation(agent_id: str, p: CurrentPrincipal) -> dict[str, Any]:
        """The caller's own conversation with the agent - never anyone else's (administrators see counts only)."""
        agent = chat_agent(agent_id)
        memory = hub.llm.memory
        config = hub.llm.config(agent.id)
        return {**memory.view(agent.id, memory.person_of(p.bus_id), config.memory),
                "memory": agent_settings.memory_note(config, False)}

    @router.delete("/agents/{agent_id}/conversation")
    async def forget_conversation(agent_id: str, p: CurrentPrincipal,
                                  user_id: str | None = Query(None, max_length=120)) -> dict[str, Any]:
        agent = chat_agent(agent_id)
        memory = hub.llm.memory
        own = memory.person_of(p.bus_id)
        if user_id and f"user:{user_id}" != own:
            if p.role != "admin":
                raise HTTPException(403, "Only administrators can delete another person's conversation")
            if hub.auth.get_user(user_id) is None and not hub.store.list_where("agent_conversations", "user_id", user_id):
                raise HTTPException(404, "No such account")
            memory.reset(agent.id, f"user:{user_id}")
            hub.activity(p.actor, "info", f"Deleted a conversation with {agent.name} (account {user_id})",
                         agent_id=agent.id)
            return {"ok": True}
        memory.reset(agent.id, own)
        return {"ok": True}

    # -- playground --------------------------------------------------------------------------

    @router.post("/agents/{agent_id}/playground")
    async def playground(agent_id: str, body: PlaygroundBody, p: CurrentPrincipal) -> dict[str, Any]:
        """Try the agent on a prompt with its saved settings or a draft (and optionally a second model), without
        saving anything and without the bus."""
        agent = model_agent(agent_id)
        try:
            draft = agent_settings.draft(hub, agent, {k: v for k, v in (body.draft or {}).items() if k != "version"})
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        purpose = agent.purposes[0] if agent.purposes else "chat"
        targets = [("draft", resolution.resolve(hub.llm, agent.id, purpose, (draft.choice, draft.config)))]
        if body.compare_with is not None and body.compare_with.provider:
            try:
                targets.append(("compare", compare_resolution(agent, draft, purpose, body.compare_with)))
            except ValueError as exc:
                raise HTTPException(400, str(exc)) from exc
        runs = list(await asyncio.gather(*(run_once(agent, draft, res, purpose, body, p.bus_id, source)
                                           for source, res in targets)))
        summary = "; ".join(f"{r['provider']}/{r['model'] or '-'} ({r['tokens']:,} tokens"
                            + (f", ~${r['cost_usd']:.4f}" if r.get("cost_usd") else "") + ")" for r in runs)
        hub.activity(p.actor, "info", f"Tried {agent.name} in the playground: {summary}", agent_id=agent.id,
                     allow_actions=body.allow_actions)
        return {"runs": runs}

    def compare_resolution(agent: "BaseAgent", draft: agent_settings.Draft, purpose: str,
                           choice: LlmChoice) -> Resolution:
        provider = choice.provider.strip()
        if provider in ("auto", "rules") or hub.llm.record(provider) is None:
            raise ValueError(f"Compare with: unknown provider '{provider}'")
        res = Resolution(agent_id=agent.id, purpose=purpose, provider=provider,
                         model=choice.model.strip() or hub.llm.default_model(provider),
                         provider_label=hub.llm.label(provider), provider_kind=hub.llm.kind_of(provider),
                         location=hub.llm.location(provider), source="explicit", source_label="Compared")
        bound = resolution.local_only(hub.llm, agent.id, draft.config)
        reason = hub.llm.blocked_reason(provider)
        if bound and res.location == "third_party":
            reason = "this agent is local-only"
        if reason is None and not res.model:
            reason = "no model chosen"
        if reason is not None:  # the card says why; nothing runs
            res.provider, res.blocked = "rules", [resolution.Blocked(level="compare", provider=provider, reason=reason)]
        return res

    async def run_once(agent: "BaseAgent", draft: agent_settings.Draft, res: Resolution, purpose: str,
                       body: PlaygroundBody, requested_by: str, source: str) -> dict[str, Any]:
        out: dict[str, Any] = {"source": source, "provider": res.provider, "provider_label": res.provider_label,
                               "model": res.model, "reply": "", "mode": "rules", "usage": None, "cost_usd": None,
                               "latency_ms": 0, "tokens": 0, "tool_calls": [], "error": None}
        if not res.ready:
            reason = "; ".join(f"{b.provider}: {b.reason}" for b in res.blocked[:3])
            out.update(provider=(res.blocked[0].provider if res.blocked else "rules"),
                       error="No AI model can run this" + (f" ({reason})" if reason else ""))
            return out
        mask = hub.llm.mask.text

        def preview(value: Any, size: int) -> str:  # masked before it is JSON (escaped) and cut (half a secret)
            return json.dumps(hub.llm.mask.value(value), default=str)[:size]

        trace: list[dict[str, Any]] = out["tool_calls"]
        tools: list[dict[str, Any]] = []
        allowed: set[str] = set()
        system = playground_system(agent, draft)
        ctx = None
        if agent_settings.chats(agent):
            ctx = agent.context(requested_by) if agent.kind == "custom" else \
                toolkit.ToolContext(hub, agent, frozenset(agent.permissions), requested_by=requested_by)
            tools, allowed = agent_settings.allowed_definitions(agent, ctx.permissions, draft.config)
            if not body.allow_actions:  # reading only: no commands, patches, flows or writes
                allowed = {n for n in allowed if (toolkit.TOOLS[n].permission == "read" or n in READ_ONLY_TOOLS)
                           and n not in ACTION_TOOLS}
                tools = [t for t in tools if t["name"] in allowed]

        async def run(name: str, args: dict[str, Any]) -> Any:
            entry = {"name": name, "arguments": preview(args, PREVIEW_ARGS), "ok": False,
                     "result_preview": ""}
            trace.append(entry)
            if name not in allowed or ctx is None:
                entry["result_preview"] = "not allowed in this playground run"
                raise PermissionError(f"{name} is not allowed here")
            result = await toolkit.execute(ctx, name, args)
            entry.update(ok=True, result_preview=preview(result, PREVIEW_RESULT))
            return result

        started = time.monotonic()
        try:
            found = await asyncio.wait_for(hub.llm.converse(
                agent.id, purpose, system=system, history=[Msg(role="user", text=body.prompt)], tools=tools, run=run,
                trigger="playground", person=hub.llm.memory.person_of(requested_by), resolved=res,
                config=draft.config), PLAYGROUND_TIMEOUT)
        except asyncio.TimeoutError:
            out["error"] = f"No answer within {int(PLAYGROUND_TIMEOUT)} seconds"
            return out
        except (Limited, LLMUnavailable, ProviderError) as exc:
            out["error"] = mask(str(exc))
            return out
        out["latency_ms"] = int((time.monotonic() - started) * 1000)
        if found is None:
            out["error"] = "This agent runs on rules with these settings"
            return out
        reply, meta = found
        usage = meta.usage
        out.update(reply=mask(reply), mode=meta.mode, provider=meta.provider, provider_label=meta.provider_label,
                   model=meta.model, usage=usage.model_dump(), cost_usd=meta.cost_usd, latency_ms=meta.latency_ms,
                   tokens=llm_usage.tokens_of(usage.model_dump()), fallback_from=meta.fallback_from)
        return out

    def playground_system(agent: "BaseAgent", draft: agent_settings.Draft) -> str:
        """The agent's effective instructions with the draft applied (hub.llm adds the rest of the draft)."""
        if agent.kind == "custom":
            return agent.system_prompt(draft.instructions)  # type: ignore[attr-defined]
        if draft.config.instructions_mode == "replace":
            text = draft.instructions if draft.instructions is not None else agent.instructions_override
            if text and text.strip():
                return text
        return agent.default_instructions

