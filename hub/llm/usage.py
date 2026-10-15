"""Metering: one usage record per model call - counts only, never prompt or reply text - plus a daily aggregate per
(UTC day, agent, provider, model), and the estimated cost from a price table (hub/llm/prices.json, overridden by an
administrator in settings/llm_prices). Cost is an estimate: Atrium does not read the providers' billing.

Budgets act on the aggregates before every model call (Meter.check): each agent's own daily tokens, daily and monthly
cost (AgentConfig.budget, with "lift today's stop" overrides that expire at the end of the UTC day) and the suite's
daily cap (guardrails limit_llm_spend / max_daily_llm_spend). A reached budget stops new calls - a call already running
finishes. Calls in flight count at an upper estimate until they are metered (Meter.reserve): while they could reach a
budget, a new call waits for them, so calls running at the same time cannot pass it together and the overshoot stays
bounded by one call. Playground calls count toward the suite cap only. Rate limits (Limiter) count model calls per
agent per minute, chat turns and task runs per agent per hour, and a provider's requests per minute (waited for,
briefly)."""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from pydantic import BaseModel, Field

from .types import BudgetExceeded, RateLimited, Request, Result, Usage

if TYPE_CHECKING:
    from ..core import Hub
    from ..models import Budget

STREAM = "llm_usage"
DAILY = "llm_usage_daily"
PRICES_DOC = "llm_prices"
OVERRIDES = "llm_budget_overrides"  # doc id "<UTC day>|<agent id>": today's lifts of an agent's budget stop
KEEP_DAYS = 400
EVENT_EVERY = 5.0  # seconds between llm_usage bus events
TOKEN_KINDS = ("input", "cached_input", "cache_write", "output")
US_ONLY = 1.1  # Anthropic: US-only inference costs 1.1x on every token category (pricing page, 2026-10-14)
COUNTERS = ("calls", "errors", "input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens",
            "reasoning_tokens", "estimated_calls", "stopped", "playground_tokens")
STOPPED = ("budget_stopped", "rate_limited")  # outcomes of calls a limit refused (no tokens, not counted as calls)


def day_of(ts: float) -> str:
    """The UTC day (budgets and aggregates count UTC days)."""
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


def seconds_to_day_end(ts: float) -> int:
    """Seconds until the next UTC midnight, when daily budgets start over."""
    at = datetime.fromtimestamp(ts, timezone.utc)
    end = datetime(at.year, at.month, at.day, tzinfo=timezone.utc) + timedelta(days=1)
    return max(1, int((end - at).total_seconds()))


def tokens_of(doc: dict[str, Any]) -> int:
    """Every token a call counted - input (also cached and cache writes) and output (reasoning included)."""
    return sum(int(doc.get(k) or 0) for k in ("input_tokens", "cached_input_tokens", "cache_write_tokens",
                                               "output_tokens"))


@lru_cache(maxsize=1)
def default_prices() -> dict[str, dict[str, Any]]:
    data = json.loads((Path(__file__).with_name("prices.json")).read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


class Tier(BaseModel):
    above_input_tokens: int = Field(ge=1, le=100_000_000)
    input: float = Field(0, ge=0, le=10_000)
    cached_input: float = Field(0, ge=0, le=10_000)
    cache_write: float = Field(0, ge=0, le=10_000)
    output: float = Field(0, ge=0, le=10_000)


class Price(BaseModel):
    """USD per 1M tokens of one provider's model (an administrator's override of the shipped table)."""

    input: float = Field(0, ge=0, le=10_000)
    cached_input: float = Field(0, ge=0, le=10_000)
    cache_write: float = Field(0, ge=0, le=10_000)
    output: float = Field(0, ge=0, le=10_000)
    tiers: list[Tier] = Field([], max_length=5)


def overrides(hub: "Hub") -> dict[str, dict[str, Any]]:
    return dict((hub.store.get("settings", PRICES_DOC) or {}).get("overrides") or {})


def prices(hub: "Hub") -> dict[str, dict[str, Any]]:
    """Defaults with the administrator's overrides applied (an override of None removes a default)."""
    merged = dict(default_prices())
    for key, value in overrides(hub).items():
        if value is None:
            merged.pop(key, None)
        else:
            merged[key] = value
    return merged


def set_overrides(hub: "Hub", changes: dict[str, Price | None], actor: str) -> list[str]:
    """Set (a Price) or drop (None: back to the shipped price, if any) administrators' prices, keyed
    "<provider id>:<model>". Returns what changed, as readable lines ("openai:gpt-6-astra input 0 -> 1.25")."""
    from .. import llm_providers

    current = overrides(hub)
    lines: list[str] = []
    for key, price in changes.items():
        provider_id, _, model = key.partition(":")
        if not model or len(model) > 200 or llm_providers.get(hub, provider_id) is None:
            raise ValueError(f"'{key}' is not '<provider id>:<model>' of a configured provider")
        before = current.get(key) or default_prices().get(key) or {}
        if price is None:
            if current.pop(key, None) is not None:
                lines.append(f"{key} back to the default price")
            continue
        value = {**price.model_dump(), "as_of": day_of(time.time()), "source": f"set by {actor}"}
        diffs = [f"{k} {before.get(k, 0)} -> {value[k]}" for k in TOKEN_KINDS if float(before.get(k) or 0) != value[k]]
        if (before.get("tiers") or []) != value["tiers"]:
            diffs.append("tiers changed")
        current[key] = value
        if diffs:
            lines.append(f"{key} " + ", ".join(diffs))
    if len(current) > 500:
        raise ValueError("At most 500 price overrides")
    hub.store.put("settings", {"id": PRICES_DOC, "overrides": current, "updated_by": actor, "updated_at": time.time()})
    return lines


def price_view(hub: "Hub") -> dict[str, Any]:
    """The shipped prices (with as_of and source), the administrators' overrides and what applies."""
    return {"defaults": default_prices(), "overrides": overrides(hub), "effective": prices(hub)}


def price_for(hub: "Hub", provider_id: str, model: str) -> dict[str, Any] | None:
    return prices(hub).get(f"{provider_id}:{model}")


def cost(price: dict[str, Any] | None, usage: Usage) -> float | None:
    """USD for one call: tokens x price / 1M per token kind, at the tier the call's total input reaches."""
    if price is None:
        return None
    rates = price
    for tier in sorted(price.get("tiers") or [], key=lambda t: t.get("above_input_tokens", 0)):
        if usage.total_input > int(tier.get("above_input_tokens", 0)):
            rates = {**price, **tier}
    counts = {"input": usage.input_tokens, "cached_input": usage.cached_input_tokens,
              "cache_write": usage.cache_write_tokens, "output": usage.output_tokens}
    total = sum(counts[k] * float(rates.get(k) or 0) for k in TOKEN_KINDS) / 1_000_000
    if usage.inference_geo and usage.inference_geo != "global":
        total *= US_ONLY
    return round(total, 9)


@dataclass(eq=False)
class Hold:
    """A call admitted and not metered yet, with what it may use at most (estimate()): its input plus its whole output
    cap, at the model's price."""

    agent_id: str | None  # None: the suite cap only (playground calls)
    usd: float
    tokens: int


class Meter:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._published = 0.0
        self._warned: set[tuple[str, str, str]] = set()  # (day, agent id or "suite", what): logged once a day
        self._holds: list[Hold] = []  # the calls in flight (this process)
        self._released = asyncio.Event()  # set (and replaced) whenever one of them is metered

    def call_cost(self, provider_id: str, model: str, usage: Usage, self_hosted: bool) -> float | None:
        price = price_for(self.hub, provider_id, model)
        if price is None and self_hosted:
            return 0.0  # own hardware: no per-token price unless an administrator sets one
        return cost(price, usage)

    def record(self, req: Request, *, provider: str, model: str, result: Result | None, latency_ms: int,
               outcome: str, cost_usd: float | None = None, error_kind: str | None = None,
               fallback_from: str | None = None) -> dict[str, Any]:
        usage = result.usage if result is not None else Usage()
        entry = {
            "agent_id": req.agent_id, "purpose": req.purpose, "trigger": req.trigger, "person": req.person,
            "provider": provider, "model": model, "served_model": result.served_model if result else None,
            "input_tokens": usage.input_tokens, "cached_input_tokens": usage.cached_input_tokens,
            "cache_write_tokens": usage.cache_write_tokens, "output_tokens": usage.output_tokens,
            "reasoning_tokens": usage.reasoning_tokens, "estimated": usage.estimated, "cost_usd": cost_usd,
            "latency_ms": latency_ms, "outcome": outcome, "error_kind": error_kind, "fallback_from": fallback_from,
            "inference_geo": usage.inference_geo,
        }
        stored = self.hub.store.append(STREAM, entry)
        self._aggregate(stored["ts"], entry, usage)
        return stored

    def _aggregate(self, ts: float, entry: dict[str, Any], usage: Usage) -> None:
        day = day_of(ts)
        doc_id = f"{day}|{entry['agent_id']}|{entry['provider']}|{entry['model']}"
        doc = self.hub.store.get(DAILY, doc_id) or {
            "id": doc_id, "day": day, "agent_id": entry["agent_id"], "provider": entry["provider"],
            "model": entry["model"], **{k: 0 for k in COUNTERS}, "cost_usd": 0.0, "playground_cost_usd": 0.0}
        for key in COUNTERS:
            doc.setdefault(key, 0)
        if entry["outcome"] in STOPPED:  # refused by a limit before it started: no call, no tokens
            doc["stopped"] += 1
        else:
            doc["calls"] += 1
            doc["errors"] += 0 if entry["outcome"] in ("ok", "fallback") else 1
            for kind in ("input_tokens", "cached_input_tokens", "cache_write_tokens", "output_tokens",
                         "reasoning_tokens"):
                doc[kind] += getattr(usage, kind)
            doc["estimated_calls"] += 1 if usage.estimated else 0
            doc["cost_usd"] = round(float(doc.get("cost_usd") or 0) + float(entry["cost_usd"] or 0), 9)
            if entry["trigger"] == "playground":  # counts toward the suite cap only, never an agent's budget
                doc["playground_tokens"] += tokens_of(entry)
                doc["playground_cost_usd"] = round(float(doc.get("playground_cost_usd") or 0)
                                                   + float(entry["cost_usd"] or 0), 9)
        doc["updated_at"] = ts
        self.hub.store.put(DAILY, doc)
        if ts - self._published >= EVENT_EVERY:  # counts only, at most every few seconds
            self._published = ts
            self.hub.bus.publish("llm_usage", {"day": day, "agent_id": entry["agent_id"], "cost_usd": doc["cost_usd"],
                                               "tokens": doc["input_tokens"] + doc["output_tokens"]})

    def daily(self, day: str | None = None) -> list[dict[str, Any]]:
        day = day or day_of(time.time())
        return self.hub.store.list_prefix(DAILY, f"{day}|")

    # -- budgets ----------------------------------------------------------------------------

    def spend(self, agent_id: str, now: float | None = None, *, month: bool = False) -> dict[str, Any]:
        """What an agent spent today (UTC) and, with `month`, this month - playground calls not counted."""
        now = now or time.time()
        today = self.hub.store.list_prefix(DAILY, f"{day_of(now)}|{agent_id}|")
        out: dict[str, Any] = {
            "cost_today": round(sum(float(d.get("cost_usd") or 0) - float(d.get("playground_cost_usd") or 0)
                                    for d in today), 6),
            "tokens_today": sum(tokens_of(d) - int(d.get("playground_tokens") or 0) for d in today)}
        if month:
            rows = [d for d in self.hub.store.list_prefix(DAILY, day_of(now)[:8]) if d.get("agent_id") == agent_id]
            out["cost_month"] = round(sum(float(d.get("cost_usd") or 0) - float(d.get("playground_cost_usd") or 0)
                                          for d in rows), 6)
        return out

    def suite_budget(self, now: float | None = None) -> dict[str, Any]:
        """The suite's daily cap (guardrails limit_llm_spend / max_daily_llm_spend) and today's estimated spend of
        every agent and the playground: {enabled, limit, spent_today, stopped}."""
        from .. import guardrails

        now = now or time.time()
        spent = round(sum(float(d.get("cost_usd") or 0) for d in self.daily(day_of(now))), 6)
        enabled = bool(guardrails.value(self.hub, "limit_llm_spend"))
        limit = int(guardrails.value(self.hub, "max_daily_llm_spend")) if enabled else None
        return {"enabled": enabled, "limit": limit, "spent_today": spent,
                "stopped": limit is not None and spent >= limit}

    def override(self, agent_id: str, now: float | None = None) -> dict[str, Any] | None:
        """Today's lifts of the agent's budget stop (they expire at the end of the UTC day)."""
        return self.hub.store.get(OVERRIDES, f"{day_of(now or time.time())}|{agent_id}")

    def lift(self, agent_id: str, *, reason: str, actor: str, extra_usd: float | None = None,
             extra_tokens: int | None = None) -> dict[str, Any]:
        """Raise today's limits of an agent (by `extra_usd` / `extra_tokens`; neither: no budget stop for the rest of
        the day). Adds to earlier lifts of the same day."""
        now = time.time()
        doc = self.override(agent_id, now) or {"id": f"{day_of(now)}|{agent_id}", "day": day_of(now),
                                               "agent_id": agent_id, "extra_usd": 0.0, "extra_tokens": 0,
                                               "lifted": False, "entries": []}
        if extra_usd is None and extra_tokens is None:
            doc["lifted"] = True
        doc["extra_usd"] = round(float(doc.get("extra_usd") or 0) + float(extra_usd or 0), 6)
        doc["extra_tokens"] = int(doc.get("extra_tokens") or 0) + int(extra_tokens or 0)
        doc["entries"] = [*doc.get("entries", []), {"actor": actor, "at": now, "reason": reason,
                                                     "extra_usd": extra_usd, "extra_tokens": extra_tokens}][-20:]
        self.hub.store.put(OVERRIDES, doc)
        self._warned = {w for w in self._warned if w[1] != agent_id}  # a new stop is reported again
        return doc

    def state(self, agent_id: str, budget: "Budget | None" = None, now: float | None = None) -> dict[str, Any]:
        """The agent's budgets against what it spent: limits (with today's lifts), what is reached, whether new calls
        are stopped."""
        if budget is None:
            from .resolve import own_settings

            budget = own_settings(self.hub.llm, agent_id)[1].budget
        now = now or time.time()
        ov = self.override(agent_id, now) or {}
        extra_usd, extra_tokens = float(ov.get("extra_usd") or 0), int(ov.get("extra_tokens") or 0)
        spend = self.spend(agent_id, now, month=budget.monthly_cost_usd is not None)
        limit = round(budget.daily_cost_usd + extra_usd, 6) if budget.daily_cost_usd is not None else None
        token_limit = budget.daily_tokens + extra_tokens if budget.daily_tokens is not None else None
        monthly = round(budget.monthly_cost_usd + extra_usd, 6) if budget.monthly_cost_usd is not None else None
        reached: list[str] = []
        if not ov.get("lifted"):
            if limit is not None and spend["cost_today"] >= limit:
                reached.append("daily_cost")
            if token_limit is not None and spend["tokens_today"] >= token_limit:
                reached.append("daily_tokens")
            if monthly is not None and spend.get("cost_month", 0) >= monthly:
                reached.append("monthly_cost")
        return {"spent_today": spend["cost_today"], "tokens_today": spend["tokens_today"],
                "spent_month": spend.get("cost_month"), "limit": limit, "token_limit": token_limit,
                "monthly_limit": monthly, "hard_stop": budget.hard_stop, "reached": reached,
                "stopped": bool(reached) and budget.hard_stop,
                "override": {k: ov.get(k) for k in ("extra_usd", "extra_tokens", "lifted", "entries")} if ov else None,
                "resets_in": seconds_to_day_end(now)}

    def check(self, req: Request, budget: "Budget | None" = None) -> None:
        """Before a model call: BudgetExceeded when the suite's daily cap or (not for the playground) the agent's own
        budget (`budget`, else its stored one) with its hard stop is reached. A reached budget is logged once a day."""
        now = time.time()
        suite = self.suite_budget(now)
        if suite["stopped"]:
            self._warn(now, "suite", "cap", f"AI spending reached the daily cap (${suite['spent_today']:.2f} of "
                       f"${suite['limit']}): new model calls are stopped until 00:00 UTC (Settings > Agent guardrails)")
            raise BudgetExceeded(f"The suite's daily AI budget is reached (${suite['spent_today']:.2f} of "
                                 f"${suite['limit']}) - an administrator can raise it under Settings > Agent guardrails",
                                 retry_after=seconds_to_day_end(now))
        if req.trigger == "playground" or not req.agent_id:
            return
        if budget is None:
            from .resolve import own_settings

            budget = own_settings(self.hub.llm, req.agent_id)[1].budget
        if budget.daily_cost_usd is None and budget.daily_tokens is None and budget.monthly_cost_usd is None:
            return
        state = self.state(req.agent_id, budget, now)
        if not state["reached"]:
            return
        name, what = self.name(req.agent_id), budget_words(state)
        monthly = state["reached"] == ["monthly_cost"]
        if not state["hard_stop"]:
            self._warn(now, req.agent_id, "over", f"{name} went over its {what}: it keeps running (the hard stop is "
                       "off)", agent_id=req.agent_id)
            return
        self._warn(now, req.agent_id, "stopped", f"{name} reached its {what}: its new model calls are stopped until "
                   + ("the month ends" if monthly else "00:00 UTC"), agent_id=req.agent_id)
        raise BudgetExceeded(f"{name}'s {what} is reached - an administrator can raise it or lift today's stop",
                             retry_after=None if monthly else seconds_to_day_end(now))

    def estimate(self, req: Request, provider_id: str, self_hosted: bool) -> Hold:
        """On the high side: ~3 characters a token, the input priced as a cache write when that costs more."""
        sent = req.system + "".join(m.text + json.dumps([c.arguments for c in m.tool_calls], default=str)
                                    for m in req.messages) + (json.dumps(req.tools, default=str) if req.tools else "")
        n, out = len(sent) // 3 + 1, req.max_output_tokens
        costs = [self.call_cost(provider_id, req.model, usage, self_hosted) or 0.0
                 for usage in (Usage(input_tokens=n, output_tokens=out), Usage(cache_write_tokens=n, output_tokens=out))]
        return Hold(agent_id=req.agent_id if req.trigger != "playground" and req.agent_id else None,
                    usd=max(costs), tokens=n + out)

    async def reserve(self, req: Request, budget: "Budget | None", *, provider_id: str, self_hosted: bool) -> Hold:
        """Admit a call (check) and count it at its estimate until release(): while the calls in flight could reach
        the suite cap or the agent's budget, wait for them to be metered first. BudgetExceeded when one is reached."""
        hold = self.estimate(req, provider_id, self_hosted)
        while True:
            released = self._released
            self.check(req, budget)
            if not self._crowded(hold, budget):
                self._holds.append(hold)
                return hold
            await released.wait()

    def release(self, hold: Hold) -> None:
        """The call is metered (or never started)."""
        if hold in self._holds:
            self._holds.remove(hold)
        released, self._released = self._released, asyncio.Event()
        released.set()

    def _crowded(self, hold: Hold, budget: "Budget | None") -> bool:
        """Could this call, with the calls in flight, go past the suite cap or the agent's (hard-stop) budget?"""
        if not self._holds:
            return False  # alone: it may go over by itself (bounded by one call)
        suite, flying = self.suite_budget(), sum(h.usd for h in self._holds)
        if suite["limit"] is not None and suite["spent_today"] + flying + hold.usd > suite["limit"]:
            return True
        mine = [h for h in self._holds if hold.agent_id is not None and h.agent_id == hold.agent_id]
        if not mine or budget is None or not budget.hard_stop:
            return False
        state = self.state(hold.agent_id or "", budget)
        if (state["override"] or {}).get("lifted"):
            return False
        usd, tokens = hold.usd + sum(h.usd for h in mine), hold.tokens + sum(h.tokens for h in mine)
        return any(limit is not None and spent + extra > limit for spent, extra, limit in (
            (state["spent_today"], usd, state["limit"]), (state["tokens_today"], tokens, state["token_limit"]),
            (state["spent_month"] or 0, usd, state["monthly_limit"])))

    def name(self, agent_id: str) -> str:
        agent = self.hub.agents.get(agent_id) if getattr(self.hub, "agents", None) is not None else None
        return agent.name if agent is not None else agent_id

    def _warn(self, now: float, who: str, what: str, text: str, **data: Any) -> None:
        key = (day_of(now), who, what)
        if key in self._warned:
            return
        self._warned.add(key)
        if who == "suite":
            self.hub.activity("hub", "warn", text, event="budget_reached", **data)
            return
        from ..agents import notify  # the agent's budget_reached notification (activity, tool bus)

        notify.emit(self.hub, who, "budget_reached", level="warn", text=text, actor="hub", **data)


def budget_words(state: dict[str, Any]) -> str:
    """What a reached budget is, for messages: "daily AI budget ($5.00 of $5.00)"."""
    reached = state["reached"]
    if "daily_cost" in reached:
        return f"daily AI budget (${state['spent_today']:.2f} of ${state['limit']:.2f})"
    if "daily_tokens" in reached:
        return f"daily AI budget ({state['tokens_today']:,} of {state['token_limit']:,} tokens)"
    return f"monthly AI budget (${state['spent_month'] or 0:.2f} of ${state['monthly_limit']:.2f})"


class Limiter:
    """Sliding-window rate limits in this process: per agent (model calls per minute, chat turns and runs per hour)
    and per provider (requests per minute, waited for briefly)."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self._hits: dict[tuple[str, ...], deque[float]] = {}

    def wait_time(self, key: tuple[str, ...], limit: int, window: float) -> float:
        now = self.clock()
        hits = self._hits.setdefault(key, deque())
        while hits and now - hits[0] >= window:
            hits.popleft()
        return 0.0 if len(hits) < limit else window - (now - hits[0])

    def take(self, key: tuple[str, ...], limit: int | None, window: float, message: str) -> None:
        """Count one more; RateLimited (with the seconds to wait) when `limit` are already in the window."""
        if not limit:
            return
        wait = self.wait_time(key, limit, window)
        if wait > 0:
            seconds = max(1, int(wait + 0.999))
            raise RateLimited(f"{message} - try again in {seconds}s", retry_after=seconds)
        self._hits[key].append(self.clock())

    async def acquire(self, key: tuple[str, ...], limit: int | None, window: float, message: str,
                      max_wait: float = 30.0) -> None:
        """The same, but wait up to `max_wait` seconds for a free slot first."""
        while limit:
            wait = self.wait_time(key, limit, window)
            if wait <= 0:
                self._hits[key].append(self.clock())
                return
            if wait > max_wait:
                seconds = max(1, int(wait + 0.999))
                raise RateLimited(f"{message} - try again in {seconds}s", retry_after=seconds)
            await asyncio.sleep(wait)


def prune_daily(hub: "Hub", now: float | None = None) -> int:
    """Drop daily aggregates older than KEEP_DAYS and budget lifts of past days (the prune loop calls this hourly)."""
    now = now or time.time()
    cutoff = day_of(now - KEEP_DAYS * 86400)
    old = [d["id"] for d in hub.store.list(DAILY) if str(d.get("day", "")) < cutoff]
    lifts = [d["id"] for d in hub.store.list(OVERRIDES) if str(d.get("day", "")) < day_of(now)]
    if lifts:
        hub.store.delete_many(OVERRIDES, lifts)
    return hub.store.delete_many(DAILY, old) if old else 0


def usage_report(hub: "Hub", *, days: int = 30, group: str = "agent", agent_id: str | None = None,
                 now: float | None = None) -> dict[str, Any]:
    """GET /api/llm/usage: totals and rows grouped by agent, provider, model or day over the last `days` UTC days
    (counts and estimated cost only), plus the suite's daily cap."""
    now = now or time.time()
    first = day_of(now - (days - 1) * 86400)
    docs = [d for d in hub.store.list(DAILY) if str(d.get("day", "")) >= first
            and (agent_id is None or d.get("agent_id") == agent_id)]
    keys = {"agent": "agent_id", "provider": "provider", "model": "model", "day": "day"}
    fields = ("calls", "errors", "stopped", "input_tokens", "cached_input_tokens", "cache_write_tokens",
              "output_tokens", "reasoning_tokens", "estimated_calls")
    rows: dict[str, dict[str, Any]] = {}
    unpriced: set[str] = set()
    for d in docs:
        key = str(d.get(keys[group]) or "")
        row = rows.setdefault(key, {"key": key, **{f: 0 for f in fields}, "cost_usd": 0.0})
        for f in fields:
            row[f] += int(d.get(f) or 0)
        row["cost_usd"] = round(row["cost_usd"] + float(d.get("cost_usd") or 0), 6)
        if group == "agent":
            row.setdefault("models", set()).add(f"{d.get('provider')}:{d.get('model')}")
        if d.get("calls") and price_for(hub, str(d.get("provider")), str(d.get("model"))) is None:
            unpriced.add(f"{d.get('provider')}:{d.get('model')}")
    out_rows = []
    for row in rows.values():
        if "models" in row:
            row["models"] = sorted(row["models"])
            agent = hub.agents.get(row["key"])
            row["name"] = agent.name if agent is not None else row["key"]
        out_rows.append(row)
    out_rows.sort(key=lambda r: (r["key"] if group == "day" else -r["cost_usd"], r["key"]))
    totals = {f: sum(r[f] for r in out_rows) for f in fields}
    totals["cost_usd"] = round(sum(r["cost_usd"] for r in out_rows), 6)
    as_of = sorted({str(v.get("as_of")) for v in default_prices().values() if v.get("as_of")})
    return {"from": first, "to": day_of(now), "days": days, "group": group, "totals": totals, "rows": out_rows,
            "suite_budget": hub.llm.meter.suite_budget(now),
            "unpriced": sorted(unpriced), "prices_as_of": as_of[-1] if as_of else None}
