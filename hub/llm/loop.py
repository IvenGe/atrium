"""The provider-neutral tool loop: one conversation turn of an agent, with tool calls, on whatever provider the
resolution picked (Claude, a local model, later OpenAI). The history is a list of neutral Msgs, appended to in place;
tools run concurrently each round, and a provider that fails mid-turn hands over to the next entry of the fallback
chain (when one is configured) - never to a third-party provider for a local-only agent or team. A budget or rate
limit reached after the first round ends the turn with what the model said so far and a notice; reached before it, it
is raised (chat answers HTTP 429)."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Collection

from ..agents import loops
from .types import Limited, Msg, ProviderError, ReplyMeta, Request, Result, ToolCall, Usage

if TYPE_CHECKING:
    from ..models import AgentConfig
    from . import LLM
    from .resolve import Candidate, Resolution

MAX_ROUNDS = 12
MAX_RESULT = loops.MAX_RESULT
REFUSED = "I can't help with that request."
TEXT_ONLY = "You cannot call tools in this setup; answer from the context below."
CLOUD_STOPPED = "(Stopped: an administrator switched cloud AI providers off while I was working.)"

Run = Callable[[str, dict[str, Any]], Awaitable[Any]]


def plain_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Tool definitions without `strict` (the toolkit validates every call's arguments itself)."""
    return [{k: v for k, v in t.items() if k != "strict"} for t in tools]


def add_usage(a: Usage, b: Usage) -> Usage:
    return Usage(input_tokens=a.input_tokens + b.input_tokens,
                 cached_input_tokens=a.cached_input_tokens + b.cached_input_tokens,
                 cache_write_tokens=a.cache_write_tokens + b.cache_write_tokens,
                 output_tokens=a.output_tokens + b.output_tokens, reasoning_tokens=a.reasoning_tokens + b.reasoning_tokens,
                 estimated=a.estimated or b.estimated, inference_geo=b.inference_geo or a.inference_geo)


@dataclass
class Turn:
    """The provider and model a turn runs on now (a fallback may change it), and what it used so far."""

    provider: str
    model: str
    fallbacks: list["Candidate"]
    fallback_from: str | None = None
    config: "AgentConfig | None" = None  # the agent's settings (its rate limit and budget), read once per turn
    local_only: bool = False  # the agent or its team is local-only: a fallback is never a third-party provider
    usage: Usage = field(default_factory=Usage)
    cost: float | None = 0.0
    latency_ms: int = 0

    @classmethod
    def of(cls, res: "Resolution", config: "AgentConfig | None" = None,
           allowed: Collection[str] | None = None) -> "Turn":
        """A turn on what `res` resolved to, with its fallbacks (only the providers in `allowed`, when given) and its
        local-only rule."""
        return cls(res.provider, res.model, [c for c in res.fallbacks if allowed is None or c.provider in allowed],
                   config=config, local_only=res.local_only)

    def account(self, result: Result, cost: float | None, latency_ms: int) -> None:
        self.usage = add_usage(self.usage, result.usage)
        self.cost = None if cost is None or self.cost is None else round(self.cost + cost, 9)
        self.latency_ms += latency_ms


async def complete(gw: "LLM", turn: Turn, req: Request) -> Result:
    """One model call on the turn's provider; on a provider failure, the next usable fallback-chain entry."""
    while True:
        try:
            result, cost, latency = await gw.complete(turn.provider, req.model_copy(update={"model": turn.model}),
                                                      fallback_from=turn.fallback_from, config=turn.config)
        except ProviderError:
            nxt = next_fallback(gw, turn)
            if nxt is None:
                raise
            turn.fallback_from = turn.fallback_from or turn.provider
            turn.provider, turn.model = nxt
            continue
        turn.account(result, cost, latency)
        return result


def next_fallback(gw: "LLM", turn: Turn) -> tuple[str, str] | None:
    """The next usable fallback-chain entry: available now, and self-hosted when the turn is local-only."""
    while turn.fallbacks:
        c = turn.fallbacks.pop(0)
        if c.provider == turn.provider or gw.blocked_reason(c.provider) is not None:
            continue
        if turn.local_only and gw.location(c.provider) != "self_hosted":
            continue
        model = c.model or gw.default_model(c.provider)
        if model:
            return c.provider, model
    return None


async def _tool(gw: "LLM", run: Run, call: ToolCall) -> Msg:
    async def masked(name: str, args: dict[str, Any]) -> Any:
        return gw.mask.value(await run(name, args))  # before it is JSON (secrets escaped) and cut (half a secret)

    text, is_error = await loops.call_tool(masked, call)  # the same tool message as the sidecar's loop
    return Msg(role="tool", call_id=call.id, text=text, is_error=is_error)


async def converse(gw: "LLM", res: "Resolution", *, system: str, history: list[Msg], tools: list[dict[str, Any]],
                   run: Run, trigger: str, person: str | None, effort: str = "medium", max_output_tokens: int = 16_000,
                   max_rounds: int = MAX_ROUNDS, temperature: float | None = None, config: "AgentConfig | None" = None,
                   context: Callable[[], Awaitable[str]] | None = None) -> tuple[str, ReplyMeta]:
    """Run the conversation in `history` (ending with the person's message) until the model answers without a tool
    call. `context`: read-only facts given to a model that cannot call tools (tools switched off for its provider)."""
    turn = Turn.of(res, config)
    offered = tools if tools and gw.caps(turn.provider, turn.model).tools is not False else []
    text_only = bool(tools) and not offered
    if text_only:
        system = f"{system}\n\n{TEXT_ONLY}"
        if context is not None:
            try:
                system += "\n\n" + await context()
            except Exception:  # the context is a courtesy: the model still answers without it
                pass
    result: Result | None = None
    reply = ""
    for n in range(max_rounds):
        if n and gw.location(turn.provider) == "third_party" and not gw.cloud_allowed():
            text = result.text if result else ""  # switched off mid-turn: no further round goes to the cloud
            reply = (text + "\n\n" if text else "") + CLOUD_STOPPED
            break
        req = Request(purpose=res.purpose, agent_id=res.agent_id, trigger=trigger, person=person,  # type: ignore[arg-type]
                      system=system, messages=history, tools=offered, model=turn.model, effort=effort,
                      temperature=temperature, max_output_tokens=max_output_tokens)
        try:
            result = await complete(gw, turn, req)
        except Limited as exc:
            if not n:
                raise  # nothing happened yet: the caller says why (HTTP 429 in chat)
            text = result.text if result else ""
            reply = (text + "\n\n" if text else "") + f"(Stopped: {exc}.)"
            break
        history.append(Msg(role="assistant", text=result.text, tool_calls=result.tool_calls, raw=result.raw,
                           provider=turn.provider, model=turn.model))
        if result.stop == "refusal":
            reply = REFUSED
            break
        if result.stop == "pause":
            continue
        if not result.tool_calls:
            reply = result.text + ("\n\n(Reply cut off - ask me to continue.)" if result.stop == "max_tokens" else "")
            break
        history.extend(await asyncio.gather(*(_tool(gw, run, c) for c in result.tool_calls)))
    else:
        text = result.text if result else ""
        reply = (text + "\n\n" if text else "") + f"(Stopped after {max_rounds} tool rounds.)"
    meta = ReplyMeta(provider=turn.provider, provider_label=gw.label(turn.provider), model=turn.model,
                     mode="text-only" if text_only else gw.mode(turn.provider), source=res.source,
                     fallback_from=turn.fallback_from, usage=turn.usage, cost_usd=turn.cost,
                     latency_ms=turn.latency_ms)
    return reply.strip() or "Done.", meta
