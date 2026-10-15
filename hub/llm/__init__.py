"""The model layer: every model call of every agent goes through the gateway `hub.llm` - the Hub Supervisor's chat,
team agents, the Patch Agent (code patches, connectors, extension packs, self-patches), the Tool Supervisors
(enrichment, team designs).

Providers: Claude (Anthropic SDK, optional dependency), OpenAI and Azure OpenAI (Responses API), model servers with an
OpenAI-compatible API (local providers), and rules - the deterministic fallback every agent has. Which one a call runs on is resolved per agent
and purpose (resolve.py). Every call is masked (no hub secret leaves in a prompt, masking.py), metered (counts, never
text, usage.py) and guarded by a circuit breaker (registry.py). Chat memory is per agent and person (memory.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from typing import TYPE_CHECKING, Any, AsyncIterator, Awaitable, Callable, Collection

from .. import agent_errors, llm_providers
from ..bus import TRACE
from ..connectors.base import redact
from ..models import AgentConfig, LlmProvider, ModelCaps
from . import loop, prompting, registry, resolve as resolution, structured, usage
from .adapters import cloud_off
from .adapters.anthropic import AnthropicAdapter
from .adapters.compat import CompatAdapter
from .adapters.openai import OpenAIAdapter
from .masking import SecretMask
from .memory import Memory
from .resolve import Resolution
from .types import (BudgetExceeded, Caps, Limited, LLMUnavailable, Msg, ProviderError, RateLimited, ReplyMeta,
                    Request, Result, Usage)
from .usage import Limiter, Meter

if TYPE_CHECKING:
    from ..core import Hub

__all__ = ["LLM", "LLMUnavailable", "Limited", "BudgetExceeded", "RateLimited", "ProviderError", "Msg", "ReplyMeta",
           "Resolution"]

PURPOSE_NAMES = {"chat": "chat", "code": "code changes", "generate": "structured generation"}
CLOUD_OFF = "cloud providers are switched off (guardrail)"
# The capability check (POST /api/llm/providers/{id}/probe): one tool call and one JSON answer, a few tokens each.
# 256 output tokens, not fewer: reasoning models count their reasoning toward the limit.
PROBE_TOKENS = 256
PROBE_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
                "additionalProperties": False}
PROBE_TOOL = {"name": "report_ok", "description": "Report that this check worked.", "input_schema": PROBE_SCHEMA}
EXPLAIN_LIMIT = 260  # characters of a failure people read (a provider's message is capped at about 200 by its adapter)


class LLM:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self.adapters: dict[str, Any] = {"anthropic": AnthropicAdapter(hub)}  # the built-in providers' adapters
        self.breaker = registry.Breaker()
        self.mask = SecretMask(hub)
        self.meter = Meter(hub)
        self.limits = Limiter()
        self.memory = Memory(hub)
        self._slots: dict[str, tuple[int, asyncio.Semaphore]] = {}  # per provider: max_concurrency calls at a time
        self._cache: dict[tuple[str, str], tuple[tuple[Any, ...], Resolution]] = {}
        self._reported: dict[tuple[str, str], str] = {}  # (provider, model) -> the failure logged last (failed)
        hub.bus.listen(self.mask.on_event)

    # -- providers ------------------------------------------------------------------------

    def migrate(self) -> None:
        registry.migrate(self.hub)
        self.invalidate()

    def providers(self) -> list[LlmProvider]:
        return llm_providers.all_providers(self.hub)

    def record(self, provider_id: str) -> LlmProvider | None:
        return llm_providers.get(self.hub, provider_id) if provider_id and provider_id != "rules" else None

    def adapter(self, provider_id: str) -> Any:
        if provider_id in self.adapters:
            return self.adapters[provider_id]
        record = self.record(provider_id)
        if record is not None and record.kind == "openai_compatible":
            return CompatAdapter(self.hub, record)
        if record is not None and record.kind == "openai":
            return OpenAIAdapter(self.hub, record)
        return None

    def blocked_reason(self, provider_id: str) -> str | None:
        """Why `provider_id` cannot take a call now (None: it can). No network."""
        record = self.record(provider_id)
        if record is None and provider_id not in self.adapters:
            return "provider removed"
        adapter = self.adapter(provider_id)
        if adapter is None:
            return f"{self.label(provider_id)} is not supported by this version of Atrium yet"
        if self.location(provider_id) == "third_party" and not self.cloud_allowed():
            return CLOUD_OFF
        ok, reason = adapter.available()
        if not ok:
            return reason or "not available"
        wait = self.breaker.remaining(provider_id)
        return f"failing - retry in {int(wait) + 1}s" if wait > 0 else None

    def cloud_allowed(self) -> bool:
        """The guardrail allow_cloud_llm: may agents send data to third-party (cloud) AI providers?"""
        from .. import guardrails

        return bool(guardrails.value(self.hub, "allow_cloud_llm"))

    def default_model(self, provider_id: str) -> str:
        if provider_id == "anthropic":
            return self.adapters["anthropic"].default_model()
        record = self.record(provider_id)
        if record is None:
            return ""
        return record.default_model or (record.pinned_models[0] if record.pinned_models else "")

    def label(self, provider_id: str) -> str:
        if provider_id in ("rules", ""):
            return "Rules"
        record = self.record(provider_id)
        return record.name if record else registry.BUILTINS.get(provider_id, {}).get("name", provider_id)

    def kind_of(self, provider_id: str) -> str:
        """anthropic | openai | local | rules (how the UI groups providers)."""
        if provider_id in ("rules", ""):
            return "rules"
        record = self.record(provider_id)
        kind = record.kind if record else registry.BUILTINS.get(provider_id, {}).get("kind", "openai_compatible")
        return resolution.KIND_LABELS.get(kind, kind)

    def location(self, provider_id: str) -> str | None:
        if provider_id in ("rules", ""):
            return None
        record = self.record(provider_id)
        if provider_id in registry.BUILTINS or (record is not None and record.kind != "openai_compatible"):
            return "third_party"
        return record.location if record else None

    def mode(self, provider_id: str) -> str:
        """The reply mode the UI shows: "llm" (a cloud provider), "local" or "rules"."""
        kind = self.kind_of(provider_id)
        return "rules" if kind == "rules" else "local" if kind == "local" else "llm"

    def caps(self, provider_id: str, model: str) -> Caps:
        adapter = self.adapter(provider_id)
        return adapter.caps(model) if adapter is not None else Caps()

    def usable(self) -> list[str]:
        ids = ["anthropic", "openai", *(p.id for p in self.providers())]
        return [p for p in dict.fromkeys(ids) if self.blocked_reason(p) is None and self.default_model(p)]

    def in_use(self, days: int = 30) -> list[str]:
        """The third-party (cloud) providers agents use: chosen at any level, what an agent resolves to now, or
        called in the last `days` days. None while the guardrail allow_cloud_llm is off (they are blocked)."""
        from ..agents import teams

        if not self.cloud_allowed():
            return []
        sel = resolution.selection(self)
        ids = {sel.default.provider, *(c.provider for c in sel.purposes.values()),
               *(t.provider for t in sel.teams.values()), *sel.fallback, *(d.provider for d in teams.defs(self.hub))}
        for doc in self.hub.store.list("agents"):
            ids.add(str(doc.get("provider") or ""))
            ids.update(str((c or {}).get("provider") or "") for c in ((doc.get("config") or {}).get("purposes") or {}).values())
        for agent in self.hub.agents.all():
            ids.update(self.resolve(agent.id, p).provider for p in getattr(agent, "purposes", ()))
        now = time.time()
        for n in range(days):
            ids.update(str(d.get("provider") or "") for d in self.hub.store.list_prefix(
                "llm_usage_daily", time.strftime("%Y-%m-%d|", time.gmtime(now - n * 86400))) if d.get("calls"))
        return sorted(p for p in ids if p and self.record(p) is not None and self.location(p) == "third_party")

    def suppliers(self) -> list[dict[str, Any]]:
        """The cloud providers in use with their supplier record (compliance control HB-SC-1)."""
        out = []
        for provider_id in self.in_use():
            record = self.record(provider_id)
            if record is not None:
                out.append({"id": record.id, "name": record.name, "owner": record.supplier.owner,
                            "reviewed_at": record.supplier.reviewed_at, "allow_cloud": True})
        return out

    def secrets_changed(self) -> None:
        """A stored secret was added or changed outside the bus events the mask listens to."""
        self.mask.invalidate()

    # -- resolution ------------------------------------------------------------------------

    def invalidate(self) -> None:
        """Called by every writer of what resolution reads: providers, agent choices, the model selection, prefs."""
        self._cache.clear()

    def _environment(self) -> tuple[Any, ...]:
        """What resolution depends on besides the stored records: the environment and the open circuits."""
        return (cloud_off(), *(bool(os.environ.get(k)) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                                                                  "ANTHROPIC_PROFILE", "OPENAI_API_KEY")),
                self.breaker.open_now())

    def resolve(self, agent_id: str, purpose: str) -> Resolution:
        key, env = (agent_id, purpose), self._environment()
        cached = self._cache.get(key)
        if cached is not None and cached[0] == env:
            return cached[1]
        res = resolution.resolve(self, agent_id, purpose)
        self._cache[key] = (env, res)
        return res

    def ready(self, agent_id: str, purpose: str) -> bool:
        return self.resolve(agent_id, purpose).ready

    @property
    def available(self) -> bool:
        """Some model provider is usable (kept for compatibility; agents ask `ready(agent_id, purpose)`)."""
        return bool(self.usable())

    def block(self, agent: Any) -> dict[str, Any]:
        """The `llm` block of an agent record: the effective model per purpose and where it comes from."""
        purposes = list(getattr(agent, "purposes", ())) if agent.uses_llm or agent.kind == "custom" else []
        views = {p: self.resolve(agent.id, p).view() for p in purposes}
        primary = purposes[0] if purposes else None
        choice, config = resolution.own_settings(self, agent.id)
        budget = config.budget  # "budget reached" on the agent's card, only for an agent with a budget
        limited = primary is not None and any(v is not None for v in (budget.daily_tokens, budget.daily_cost_usd,
                                                                       budget.monthly_cost_usd))
        return {"purposes": views, "primary": primary,
                "local_only": bool(primary and self.resolve(agent.id, primary).local_only),
                "local_only_from": self.resolve(agent.id, primary).local_only_from if primary else None,
                "ready": bool(primary and self.resolve(agent.id, primary).ready),
                "choice": choice.model_dump(), "per_task": len(config.purposes), "settings_version": config.version,
                "budget_reached": bool(limited and self.meter.state(agent.id, budget)["reached"])}

    def chain(self, agent_id: str, purpose: str) -> list[dict[str, Any]]:
        """Every level that could decide the agent's model for `purpose`, with what happened to it (resolve.chain)."""
        return resolution.chain(self, agent_id, purpose)

    def effective(self, agent: Any) -> dict[str, Any]:
        """provider, provider_kind, provider_label and model of an agent record (its primary purpose)."""
        purposes = list(getattr(agent, "purposes", ()))
        if not agent.uses_llm or not purposes:
            return {"provider": "rules", "provider_kind": "rules", "provider_label": "Rules", "model": ""}
        return resolution.effective(self.resolve(agent.id, purposes[0]), self)

    # -- settings and limits ---------------------------------------------------------------

    def config(self, agent_id: str) -> AgentConfig:
        """An agent's own settings (model parameters, instructions, budgets, limits, memory); defaults for "hub"."""
        return resolution.own_settings(self, agent_id)[1] if agent_id else AgentConfig()

    def start_run(self, agent_id: str, config: AgentConfig | None = None) -> None:
        """A chat turn or a task run of the agent starts: RateLimited when its runs per hour are used up."""
        config = config or self.config(agent_id)
        n = config.rate.runs_per_hour
        self.limits.take(("runs", agent_id), n, 3600, f"{self.meter.name(agent_id)} reached its limit of {n} chats "
                         "and runs per hour")

    async def _admit(self, provider_id: str, req: Request, config: AgentConfig | None) -> None:
        """Before a call: the agent's calls per minute, the budgets, the provider's requests per minute. A refused
        call is metered (no tokens) and raises Limited."""
        try:
            if req.trigger != "playground" and req.agent_id:
                config = config or self.config(req.agent_id)
                n = config.rate.calls_per_minute
                self.limits.take(("calls", req.agent_id), n, 60,
                                 f"{self.meter.name(req.agent_id)} reached its limit of {n} model calls per minute")
            self.meter.check(req, config.budget if config is not None and req.trigger != "playground" else None)
            record = self.record(provider_id)
            if record is not None and record.requests_per_minute:
                await self.limits.acquire(("provider", provider_id), record.requests_per_minute, 60,
                                          f"{record.name} reached its limit of {record.requests_per_minute} requests "
                                          "per minute")
        except Limited as exc:
            self.meter.record(req, provider=provider_id, model=req.model, result=None, latency_ms=0,
                              outcome="budget_stopped" if isinstance(exc, BudgetExceeded) else "rate_limited",
                              error_kind=exc.code)
            raise

    @contextlib.asynccontextmanager
    async def _slot(self, provider_id: str) -> AsyncIterator[None]:
        """At most the provider's max_concurrency calls at a time (more wait their turn)."""
        record = self.record(provider_id)
        size = record.max_concurrency if record is not None else 4
        slot = self._slots.get(provider_id)
        if slot is None or slot[0] != size:
            slot = self._slots[provider_id] = (size, asyncio.Semaphore(size))
        async with slot[1]:
            yield

    # -- calls ------------------------------------------------------------------------------

    async def complete(self, provider_id: str, req: Request, *, fallback_from: str | None = None,
                       learn: Collection[str] = registry.LEARNABLE, config: AgentConfig | None = None
                       ) -> tuple[Result, float | None, int]:
        """One model call: rate-limited, within budget, masked, metered, guarded by the circuit breaker. (result,
        cost in USD or None, latency). Raises Limited (BudgetExceeded, RateLimited) before the call when a limit is
        reached. A model that refuses an optional feature (HTTP 400 naming temperature, reasoning effort or tools -
        the ones in `learn`) gets the call again without it, and the provider record remembers that (logged once)."""
        if config is None and req.trigger != "playground" and req.agent_id:
            config = self.config(req.agent_id)
        await self._admit(provider_id, req, config)
        hold = await self._reserve(provider_id, req, config)
        try:
            async with self._slot(provider_id):
                while True:
                    try:
                        return await self._complete(provider_id, req, fallback_from)
                    except ProviderError as exc:
                        lighter = self._without_refused(provider_id, req, exc, learn)
                        if lighter is None:
                            exc.provider, exc.model = exc.provider or provider_id, exc.model or req.model
                            raise
                        req = lighter
        finally:
            self.meter.release(hold)  # metered by now (_complete records every attempt)

    async def _reserve(self, provider_id: str, req: Request, config: AgentConfig | None) -> usage.Hold:
        """After the rate limits: count the call toward the budgets while it runs (usage.Meter.reserve)."""
        try:
            return await self.meter.reserve(req, config.budget if config is not None and req.trigger != "playground"
                                            else None, provider_id=provider_id,
                                            self_hosted=self.location(provider_id) == "self_hosted")
        except BudgetExceeded as exc:
            self.meter.record(req, provider=provider_id, model=req.model, result=None, latency_ms=0,
                              outcome="budget_stopped", error_kind=exc.code)
            raise

    def _without_refused(self, provider_id: str, req: Request, exc: ProviderError,
                         learn: Collection[str]) -> Request | None:
        """The request again without the optional feature a provider's HTTP 400 refused (None: not such a refusal,
        or nothing left to drop - the error stands). The model's record learns it, so the next call starts right."""
        if exc.status != 400:
            return None
        message = str(exc)
        strict = [t for t in req.tools if t.get("strict")]
        if strict and req.json_mode != "native" and structured.schema_refused(message):
            return req.model_copy(update={"tools": loop.plain_tools(req.tools)})  # this schema set, not the model
        feature = registry.refused_feature(message)
        if feature not in learn:
            return None
        if feature == "temperature" and req.temperature is not None:
            self.learn(provider_id, req.model, "a temperature setting", temperature=False)
            return req.model_copy(update={"temperature": None})
        if feature == "effort" and req.effort:
            known = self.caps(provider_id, req.model).effort_levels
            self.learn(provider_id, req.model, f"the reasoning effort '{req.effort}'",
                       effort_levels=registry.efforts_after_refusal(message, req.effort, known))
            return req.model_copy(update={"effort": None})  # the model's own default
        if feature == "strict" and strict:
            if self.kind_of(provider_id) == "anthropic":  # strict tools are part of Claude's structured outputs
                self.learn(provider_id, req.model, "strict tool schemas", "its tools are sent without them",
                           json_schema=False)
            return req.model_copy(update={"tools": loop.plain_tools(req.tools)})
        if feature == "tools" and req.tools:
            self.learn(provider_id, req.model, "tool calling", "it answers without tools", tools=False)
            return req.model_copy(update={"tools": [], "system": f"{req.system}\n\n{loop.TEXT_ONLY}"})
        return None

    async def _complete(self, provider_id: str, req: Request, fallback_from: str | None
                        ) -> tuple[Result, float | None, int]:
        adapter = self.adapter(provider_id)
        if adapter is None:
            raise ProviderError(f"{self.label(provider_id)} is not available", kind="unavailable")
        masked = self.mask.request(req)
        started = time.monotonic()
        try:
            result = await adapter.complete(masked)
        except Exception as exc:
            error = self.mask.error(exc if isinstance(exc, ProviderError) else ProviderError(
                f"{self.label(provider_id)} failed ({exc.__class__.__name__})", kind=exc.__class__.__name__))
            if error.status is None or error.status == 429 or error.status >= 500:  # an outage, not a refused request
                self.breaker.failure(provider_id)
            self.meter.record(req, provider=provider_id, model=req.model, result=None,
                              latency_ms=int((time.monotonic() - started) * 1000), outcome="error",
                              error_kind=error.kind, fallback_from=fallback_from)
            raise error from exc
        latency = int((time.monotonic() - started) * 1000)
        self.breaker.success(provider_id)
        self._reported.pop((provider_id, req.model), None)  # working again: its next failure is logged
        cost = self.meter.call_cost(provider_id, req.model, result.usage, self.location(provider_id) == "self_hosted")
        self.meter.record(req, provider=provider_id, model=req.model, result=result, latency_ms=latency,
                          outcome="refused" if result.stop == "refusal" else "fallback" if fallback_from else "ok",
                          cost_usd=cost, fallback_from=fallback_from)
        return result, cost, latency

    def failed(self, agent_id: str, exc: ProviderError, trigger: str) -> None:
        """A model call of an agent failed (after its fallbacks): an agent error in the conversation it worked on
        (hub/agent_errors.py), and the provider's own message in the activity log once per provider, model and
        message (again after a call there worked) - not for the playground, where an administrator watches the call."""
        if not agent_id or trigger == "playground":
            return
        trace = TRACE.get()
        msg = trace.message if trace is not None else None
        self._report(agent_id, exc, trace.private if trace is not None else None)
        self.hub.agent_errors.record(agent_id, subject=msg.subject if msg else trigger, sender=msg.sender if msg else None,
                                     message=msg.id if msg else None, thread=trace.thread if trace else None,
                                     text=str(exc), error_class=exc.__class__.__name__, code=f"llm_{exc.kind or 'error'}",
                                     kind="llm", private=trace.private if trace else None)
        agent_errors.mark(exc)  # the handler that this failure ends is not recorded again (hub/agent_errors.py)

    def _report(self, agent_id: str, exc: ProviderError, private: Any) -> None:
        provider = exc.provider or ""
        key, text = (provider, exc.model or ""), self.explain(exc)
        if self._reported.get(key) == text:
            return
        self._reported[key] = text
        while len(self._reported) > 200:
            self._reported.pop(next(iter(self._reported)))
        if private is not None:  # the activity log is shared: no quote of a person's private chat
            text = private.quotes.scrub(text)
        where = f" ({exc.model})" if exc.model else ""
        self.hub.activity("hub", "warn", f"{self.meter.name(agent_id)}'s model call failed{where}: {text}",
                          provider_id=provider or None, model=exc.model, error_kind=exc.kind, agent_id=agent_id)

    def explain(self, exc: BaseException, limit: int = EXPLAIN_LIMIT) -> str:
        """Why a model call failed, as people may read it: the provider's own message (e.g. "Claude answered HTTP
        400: output_config.effort: Extra inputs are not permitted") with every hub secret and credential-looking pair
        masked, at most `limit` characters - for a failure of the model layer (ProviderError, LLMUnavailable, also
        as the cause of another error); any other error by its class name only."""
        found: BaseException | None = exc
        while found is not None and not isinstance(found, (ProviderError, LLMUnavailable)):
            found = found.__cause__
        if found is None:
            return exc.__class__.__name__
        text = str(found)
        try:
            text = self.mask.text(text)
        except Exception:  # the mask cannot load the secrets: the provider texts are masked already, pairs below
            pass
        text = " ".join(redact(text).split()) or found.__class__.__name__
        return text if len(text) <= limit else text[:limit - 1] + "…"

    async def converse(self, agent_id: str, purpose: str, *, system: str, history: list[Msg],
                       tools: list[dict[str, Any]], run: loop.Run, trigger: str = "chat", person: str | None = None,
                       effort: str = "medium", max_output_tokens: int = 16_000,
                       context: Callable[[], Awaitable[str]] | None = None,
                       resolved: Resolution | None = None, config: AgentConfig | None = None
                       ) -> tuple[str, ReplyMeta] | None:
        """One turn of a conversation with tools on the agent's model; None when it resolves to rules (the caller
        runs its rules). The agent's settings (`config`: a playground draft, else the stored ones) add to the system
        prompt and set the effort, temperature, output cap and tool rounds. Raises LLMUnavailable when the provider
        fails (and no fallback can take over), Limited when a budget or rate limit stops the first call."""
        res = resolved or self.resolve(agent_id, purpose)
        if not res.ready:
            return None
        config = config or self.config(agent_id)
        params = config.params
        system = prompting.assemble(system, config, language=prompting.reply_language(self, config), purpose=purpose,
                                    escalate=any(t.get("name") == "escalate" for t in tools))
        try:
            return await loop.converse(self, res, system=system, history=history, tools=tools, run=run,
                                       trigger=trigger, person=person, effort=params.effort or effort,
                                       temperature=params.temperature, config=config,
                                       max_output_tokens=min(max_output_tokens, params.max_output_tokens or max_output_tokens),
                                       max_rounds=params.max_tool_rounds, context=context)
        except ProviderError as exc:
            self.failed(agent_id, exc, trigger)
            raise LLMUnavailable(str(exc)) from exc

    async def converse_on(self, provider_id: str, model: str, *, agent_id: str, purpose: str = "chat",
                          **kwargs: Any) -> tuple[str, ReplyMeta]:
        """The same on a given provider and model, past the agent's resolution (the provider must be usable)."""
        reason = self.blocked_reason(provider_id)
        bound = resolution.local_only(self, agent_id) if agent_id else None
        if reason is None and bound and self.location(provider_id) != "self_hosted":
            reason = "this agent is local-only"
        if reason is not None:
            raise LLMUnavailable(f"{self.label(provider_id)}: {reason}")
        res = Resolution(agent_id=agent_id, purpose=purpose, provider=provider_id, model=model or
                         self.default_model(provider_id), provider_label=self.label(provider_id),
                         provider_kind=self.kind_of(provider_id), source="explicit", source_label="Chosen for this call",
                         local_only=bound is not None, local_only_from=bound)
        found = await self.converse(agent_id, purpose, resolved=res, **kwargs)
        assert found is not None
        return found

    async def json(self, agent_id: str, purpose: str, *, system: str, prompt: str, schema: dict[str, Any],
                   effort: str | None = None, max_output_tokens: int = 16_000, trigger: str = "system",
                   person: str | None = None, schema_name: str = "result") -> tuple[dict[str, Any], ReplyMeta]:
        """A structured answer validated against `schema` (structured.py), on the agent's model for `purpose`, with
        its settings (additional instructions, effort, temperature, output cap). Raises LLMUnavailable when no model
        can give one (callers fall back to templates or rules; a reached budget says so in its message)."""
        res = self.resolve(agent_id, purpose)
        if not res.ready:
            reason = "; ".join(f"{b.provider}: {b.reason}" for b in res.blocked[:2])
            raise LLMUnavailable(f"No AI model is available for {PURPOSE_NAMES.get(purpose, purpose)}"
                                 + (f" ({reason})" if reason else ""))
        config = self.config(agent_id)
        params = config.params
        system = prompting.assemble(system, config, language=None, purpose=purpose)
        effort = params.effort or effort
        max_output_tokens = min(max_output_tokens, params.max_output_tokens or max_output_tokens)
        turn = loop.Turn.of(res, config)
        record = self.record(turn.provider)
        caps = self.caps(turn.provider, turn.model)
        modes = structured.mode_order(record.kind if record else "anthropic", caps.json_schema, caps.json_object,
                                      record.structured_output if record else "auto")
        for n, mode in enumerate(modes):
            messages = [Msg(role="user", text=prompt)]
            request = Request(purpose=purpose, agent_id=agent_id, trigger=trigger, person=person,  # type: ignore[arg-type]
                              system=system + (structured.schema_prompt(schema) if mode != "native" else ""),
                              messages=messages, json_schema=schema, schema_name=schema_name, json_mode=mode,
                              model=turn.model, effort=effort, temperature=params.temperature,
                              max_output_tokens=max_output_tokens)
            try:
                result = await loop.complete(self, turn, request)
                value, errors = self._parse(result, schema)
                if errors:  # one repair round with what was wrong
                    messages += [Msg(role="assistant", text=result.text, raw=result.raw, provider=turn.provider,
                                     model=turn.model), Msg(role="user", text=structured.repair_prompt(errors))]
                    result = await loop.complete(self, turn, request.model_copy(update={"messages": messages}))
                    value, errors = self._parse(result, schema)
                    if errors:
                        raise LLMUnavailable("The model's structured answer was unusable: " + "; ".join(errors[:3]))
            except ProviderError as exc:
                if exc.status == 400 and structured.names_mode(str(exc), mode) and n + 1 < len(modes):
                    native = mode == "native"
                    if not structured.schema_refused(str(exc)):  # the mode itself, not this one schema
                        self.learn(turn.provider, turn.model, "JSON schema output" if native else "JSON output",
                                   "using the next structured-output mode",
                                   **{"json_schema" if native else "json_object": False})
                    continue
                self.failed(agent_id, exc, trigger)
                raise LLMUnavailable(str(exc)) from exc
            meta = ReplyMeta(provider=turn.provider, provider_label=self.label(turn.provider), model=turn.model,
                             mode=self.mode(turn.provider), source=res.source, fallback_from=turn.fallback_from,  # type: ignore[arg-type]
                             usage=turn.usage, cost_usd=turn.cost, latency_ms=turn.latency_ms)
            return value, meta
        raise LLMUnavailable("No structured-output mode worked")  # pragma: no cover - the last mode raises

    @staticmethod
    def _parse(result: Result, schema: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
        if result.stop == "refusal":
            raise LLMUnavailable("The model declined this request.")
        if result.stop == "max_tokens":
            raise LLMUnavailable("The response was cut off (max_tokens).")
        try:
            value = structured.extract(result.text)
        except ValueError as exc:
            return {}, [str(exc)]
        if not isinstance(value, dict):
            return {}, ["$ must be a JSON object"]
        value = structured.strip_nulls(schema, value)  # the nulls a strict schema allowed for optional properties
        return value, structured.check(schema, value)

    def learn(self, provider_id: str, model: str, refused: str, then: str = "calls continue without it",
              **found: Any) -> None:
        """Remember what a provider's model refused on its record, so the next call starts right; logged once."""
        record = self.record(provider_id)
        if record is None:
            return
        caps = record.capabilities.get(model) or ModelCaps()
        if all(getattr(caps, k) == v for k, v in found.items()):
            return
        record.capabilities[model] = caps.model_copy(update={**found, "source": "learned", "at": time.time()})
        llm_providers.put(self.hub, record)
        self.hub.activity("hub", "info", f"{record.name} does not support {refused} for {model}: {then}",
                          provider_id=provider_id)

    async def probe(self, provider_id: str, model: str, *, person: str | None = None) -> tuple[Caps, Usage]:
        """Check what a model supports with two tiny calls - one tool call, one JSON-schema answer - and store the
        result on the provider (source "probe"). Raises LLMUnavailable when the provider cannot be reached."""
        record = self.record(provider_id)
        adapter = self.adapter(provider_id)
        if record is None or adapter is None:
            raise LLMUnavailable(f"{self.label(provider_id)} cannot be checked")
        ok, reason = adapter.available()
        if not ok:
            raise LLMUnavailable(f"{record.name}: {reason}")
        levels = self.caps(provider_id, model).effort_levels or []
        base = Request(purpose="chat", agent_id="hub", trigger="system", person=person, model=model,
                       system="This is an automatic capability check. Follow the instruction exactly.",
                       effort="none" if "none" in levels else "low", max_output_tokens=PROBE_TOKENS)
        checks = {"tools": base.model_copy(update={"tools": [PROBE_TOOL], "messages": [
                      Msg(role="user", text="Call the report_ok tool once with ok set to true.")]}),
                  "json_schema": base.model_copy(update={"json_schema": PROBE_SCHEMA, "schema_name": "probe",
                                                         "json_mode": "native", "messages": [
                      Msg(role="user", text="Answer with ok set to true.")]})}
        found: dict[str, Any] = {}
        used = Usage()
        for field, request in checks.items():
            try:
                result, _, _ = await self.complete(provider_id, request, learn=("temperature", "effort"))
            except ProviderError as exc:
                if exc.status != 400:
                    raise LLMUnavailable(str(exc)) from exc
                found[field] = False  # the model refused the feature itself
                continue
            used = loop.add_usage(used, result.usage)
            if result.stop == "max_tokens":
                continue  # cut off: still unknown
            if field == "tools":
                found["tools"] = any(c.name == PROBE_TOOL["name"] for c in result.tool_calls)
            else:
                try:
                    found["json_schema"] = not structured.check(PROBE_SCHEMA, structured.extract(result.text))
                except ValueError:
                    found["json_schema"] = False
        record = self.record(provider_id) or record  # learning may have updated it
        caps = (record.capabilities.get(model) or ModelCaps()).model_copy(
            update={**found, "source": "probe", "at": time.time()})
        record.capabilities[model] = caps
        llm_providers.put(self.hub, record)
        return Caps.model_validate(caps.model_dump(include=set(Caps.model_fields))), used

    # -- reporting -----------------------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        claude: AnthropicAdapter = self.adapters["anthropic"]
        rows = []
        for provider_id in ["anthropic", *(p.id for p in self.providers() if p.id != "anthropic")]:
            reason = self.blocked_reason(provider_id)
            adapter = self.adapter(provider_id)
            rows.append({"id": provider_id, "label": self.label(provider_id), "kind": self.kind_of(provider_id),
                         "location": self.location(provider_id), "available": reason is None, "reason": reason,
                         "default_model": self.default_model(provider_id),
                         **({"key_source": adapter.key_source()} if hasattr(adapter, "key_source") else {})})
        default = self.resolve("", "chat")
        return {
            "available": self.available,
            "installed": claude.installed(),
            "configured": not cloud_off() and claude.key_source() is not None,
            "model": claude.default_model(),
            "last_error": claude.last_error,
            "providers": rows,
            "default": {"provider": default.provider, "provider_label": default.provider_label,
                        "model": default.model, "source_label": default.source_label},
        }
