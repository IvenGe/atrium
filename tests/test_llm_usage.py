"""Metering (hub/llm/usage.py): one record per model call with counts and never text, daily aggregates per UTC day,
agent, provider and model, the estimated cost, and the prune of old aggregates."""

from __future__ import annotations

import asyncio
import json
import time

import pytest
from llm_fakes import FakeClaude, block, message, use_claude

from hub.llm import BudgetExceeded, Msg, RateLimited
from hub.llm import usage as llm_usage

SECRET_TEXT = "PROMPT-TEXT-never-metered"


def test_a_usage_record_per_call_and_a_daily_aggregate(client, monkeypatch):
    hub = client.app.state.hub
    usage = {"input_tokens": 1000, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 100}
    use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text=f"Reply {SECRET_TEXT}")], usage=usage),
                                            message("end_turn", [block("text", text="Again")], usage=usage)])
    events = hub.bus.subscribe()
    for _ in range(2):
        client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system=SECRET_TEXT, trigger="chat",
                                                    history=[Msg(role="user", text=SECRET_TEXT)], tools=[], run=None,
                                                    person="user:u_1"))
    records = hub.store.tail("llm_usage", 10)
    assert len(records) == 2 and SECRET_TEXT not in json.dumps(records)  # counts only
    first = records[0]
    assert (first["agent_id"], first["purpose"], first["trigger"], first["person"], first["provider"], first["model"],
            first["outcome"]) == ("supervisor", "chat", "chat", "user:u_1", "anthropic", "claude-opus-5-5", "ok")
    assert (first["input_tokens"], first["output_tokens"]) == (1000, 100)
    assert first["cost_usd"] == pytest.approx((1000 * 4 + 100 * 20) / 1e6)
    [daily] = hub.llm.meter.daily()
    assert daily["id"] == f"{llm_usage.day_of(time.time())}|supervisor|anthropic|claude-opus-5-5"
    assert (daily["calls"], daily["errors"], daily["input_tokens"], daily["output_tokens"]) == (2, 0, 2000, 200)
    assert daily["cost_usd"] == pytest.approx(2 * (1000 * 4 + 100 * 20) / 1e6)
    published = [e for e in [events.get_nowait() for _ in range(events.qsize())] if e["type"] == "llm_usage"]
    assert len(published) == 1 and set(published[0]["data"]) == {"day", "agent_id", "cost_usd", "tokens"}  # throttled
    hub.bus.unsubscribe(events)


def test_no_price_no_cost_and_failed_calls_are_counted(client, monkeypatch):
    hub = client.app.state.hub
    client.patch("/api/agents/supervisor", json={"model": "claude-unpriced"})

    class Failing:
        beta = None

    fake = use_claude(hub, monkeypatch, responses=[message("end_turn", [block("text", text="ok")])])
    client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", history=[Msg(role="user", text="x")],
                                                tools=[], run=None))
    record = hub.store.tail("llm_usage", 1)[0]
    assert record["model"] == "claude-unpriced" and record["cost_usd"] is None and record["estimated"]
    hub.llm.adapters["anthropic"].client_factory = lambda **_: Failing()
    with pytest.raises(Exception):
        client.portal.call(lambda: hub.llm.converse("supervisor", "chat", system="s", tools=[], run=None,
                                                    history=[Msg(role="user", text="x")]))
    failed = hub.store.tail("llm_usage", 1)[0]
    assert failed["outcome"] == "error" and failed["error_kind"] == "AttributeError"
    assert hub.llm.meter.daily()[0]["errors"] == 1 and fake.calls


def test_old_daily_aggregates_are_pruned(client):
    hub = client.app.state.hub
    hub.store.put("llm_usage_daily", {"id": "2020-01-01|a|p|m", "day": "2020-01-01", "calls": 1})
    hub.store.put("llm_usage_daily", {"id": f"{llm_usage.day_of(time.time())}|a|p|m", "day": llm_usage.day_of(time.time())})
    assert hub.prune_logs()["llm_usage_daily"] == 1
    assert [d["day"] for d in hub.store.list("llm_usage_daily")] == [llm_usage.day_of(time.time())]


def test_an_administrators_price_overrides_the_default(client):
    hub = client.app.state.hub
    hub.store.put("settings", {"id": "llm_prices", "overrides": {"anthropic:claude-opus-5-5": {"input": 1.0, "output": 1.0},
                                                                 "anthropic:claude-fable-5-1": None}})
    assert llm_usage.price_for(hub, "anthropic", "claude-opus-5-5") == {"input": 1.0, "output": 1.0}
    assert llm_usage.price_for(hub, "anthropic", "claude-fable-5-1") is None
    assert llm_usage.price_for(hub, "anthropic", "claude-sonnet-5-5")["input"] == 2.0


# -- budgets, the hard stop, lifting it, the suite cap and rate limits (stage 4) ------------------------------------

USAGE = {"input_tokens": 1000, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 100}


def said(text: str, usage: dict | None = None):
    return message("end_turn", [block("text", text=text)], usage=usage or USAGE)


def activity(client, words: str) -> list[dict]:
    return [e for e in client.get("/api/activity?limit=500").json() if words in e["text"]]


def test_an_agents_daily_budget_stops_new_calls_and_chat_says_why(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[said("one"), said("two"), said("three")])  # $0.006 each
    assert client.patch("/api/agents/supervisor/settings", json={"config": {"budget": {"daily_cost_usd": 0.01}}}).status_code == 200
    assert [client.post("/api/chat", json={"text": "hi"}).json()["reply"] for _ in range(2)] == ["one", "two"]
    stopped = client.post("/api/chat", json={"text": "again"})
    assert stopped.status_code == 429, stopped.text  # not a rules answer: the person sees why
    body = stopped.json()
    assert body["code"] == "budget_exceeded" and body["retry_after"] > 0 and int(stopped.headers["retry-after"]) > 0
    assert body["detail"].startswith("Hub Supervisor's daily AI budget ($0.01 of $0.01) is reached")
    assert client.post("/api/chat", json={"text": "and again"}).status_code == 429
    [warned] = activity(client, "reached its daily AI budget")  # once a day
    assert warned["level"] == "warn" and warned["actor"] == "hub" and warned["data"]["event"] == "budget_reached"
    assert hub.store.tail("llm_usage", 1)[0]["outcome"] == "budget_stopped"
    [daily] = hub.llm.meter.daily()
    assert (daily["calls"], daily["stopped"]) == (2, 2)
    state = client.get("/api/agents/supervisor/settings").json()["budget_state"]
    assert state["stopped"] and state["reached"] == ["daily_cost"] and state["spent_today"] == pytest.approx(0.012)

    assert client.post("/api/agents/supervisor/budget/override", json={"reason": "x"}).status_code == 422
    lifted = client.post("/api/agents/supervisor/budget/override", json={"reason": "incident 42", "extra_usd": 1})
    assert lifted.status_code == 200 and lifted.json()["limit"] == pytest.approx(1.01) and not lifted.json()["stopped"]
    [entry] = activity(client, "Lifted today's budget stop")
    assert entry["text"] == "Lifted today's budget stop for Hub Supervisor (+$1.00): incident 42" and entry["level"] == "warn"
    assert client.post("/api/chat", json={"text": "now?"}).json()["reply"] == "three"
    tomorrow = hub.llm.meter.state("supervisor", now=time.time() + 86400)  # a lift ends with the UTC day
    assert tomorrow["override"] is None and tomorrow["limit"] == 0.01 and tomorrow["spent_today"] == 0


def test_a_budget_reached_mid_turn_ends_it_with_what_the_model_said(client, monkeypatch):
    hub = client.app.state.hub
    big = {"input_tokens": 900, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 200}
    fake = use_claude(hub, monkeypatch, responses=[
        message("tool_use", [block("text", text="Looking."), block("tool_use", id="t1", name="list_tools", input={})],
                usage=big), said("never sent")])
    client.patch("/api/agents/supervisor/settings", json={"config": {"budget": {"daily_tokens": 1000}}})
    reply = client.post("/api/chat", json={"text": "what is there?"})
    assert reply.status_code == 200 and len(fake.calls) == 1
    assert reply.json()["reply"] == ("Looking.\n\n(Stopped: Hub Supervisor's daily AI budget (1,100 of 1,000 tokens) is "
                                     "reached - an administrator can raise it or lift today's stop.)")


def test_without_the_hard_stop_a_budget_only_warns(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[said("a"), said("b"), said("c")])
    saved = client.patch("/api/agents/supervisor/settings", json={"config": {"budget": {
        "daily_cost_usd": 0.01, "hard_stop": False}}})
    assert saved.status_code == 200 and activity(client, "hard stop off")[0]["level"] == "warn"
    assert [client.post("/api/chat", json={"text": "x"}).status_code for _ in range(3)] == [200, 200, 200]
    [warned] = activity(client, "went over its daily AI budget")
    assert "keeps running (the hard stop is off)" in warned["text"]


def test_the_suite_cap_stops_every_agent_and_runs_are_skipped(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[said("after the cap")])
    assert client.patch("/api/settings/guardrails", json={"max_daily_llm_spend": 1}).status_code == 200
    today = llm_usage.day_of(time.time())
    hub.store.put("llm_usage_daily", {"id": f"{today}|x|anthropic|m", "day": today, "agent_id": "x",
                                      "provider": "anthropic", "model": "m", "calls": 3, "cost_usd": 1.5})
    assert client.get("/api/llm/usage?days=1").json()["suite_budget"] == {
        "enabled": True, "limit": 1, "spent_today": 1.5, "stopped": True}
    refused = client.post("/api/chat", json={"text": "hi"})
    assert refused.status_code == 429 and refused.json()["detail"].startswith(
        "The suite's daily AI budget is reached ($1.50 of $1)")
    with pytest.raises(BudgetExceeded):  # structured calls: their callers fall back to templates with this reason
        client.portal.call(lambda: hub.llm.json("patcher", "code", system="s", prompt="p", schema={"type": "object"}))
    member = client.post("/api/agents", json={"name": "Night shift", "task": "Summarize the state"}).json()["id"]
    run = client.post(f"/api/agents/{member}/run").json()
    assert run["ok"] is False and run["skipped"] and run["reply"].startswith("Skipped: The suite's daily AI budget")
    assert activity(client, "Night shift ran its task (manual): skipped")
    [capped] = activity(client, "AI spending reached the daily cap")
    assert capped["level"] == "warn"
    assert client.patch("/api/settings/guardrails", json={"limit_llm_spend": False}).status_code == 200
    assert activity(client, "Guardrail 'Cap the AI model spending per day' relaxed: on -> off")[0]["level"] == "warn"
    assert client.post("/api/chat", json={"text": "hi"}).json()["reply"] == "after the cap"


class SlowClaude(FakeClaude):
    """A model call takes a moment (calls overlap) and uses its whole output cap (16,000 tokens on Opus 5.5: $0.32)."""

    async def create(self, **kwargs):
        assert kwargs["max_tokens"] == 16_000
        await asyncio.sleep(0.05)
        return await super().create(**kwargs)


FULL = {"input_tokens": 10, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0, "output_tokens": 16_000}
ONE_CALL = (10 * 4 + 16_000 * 20) / 1e6


def at_once(hub, client, agent_id: str, n: int) -> list:
    async def many():
        return await asyncio.gather(*(hub.llm.converse(agent_id, "chat", system="s", tools=[], run=None,
                                                       history=[Msg(role="user", text=f"q{k}")]) for k in range(n)),
                                    return_exceptions=True)
    return client.portal.call(many)


def test_calls_running_at_the_same_time_cannot_pass_the_suite_cap_together(client, monkeypatch):
    """The calls in flight count toward the cap: eight parallel chats on a $1 cap run until it is reached (one call
    over at most), the rest are stopped - not all eight at $0.32 each."""
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, SlowClaude([said(f"answer {n}", FULL) for n in range(8)]))
    assert client.patch("/api/settings/guardrails", json={"max_daily_llm_spend": 1}).status_code == 200
    results = at_once(hub, client, "supervisor", 8)
    stopped = [r for r in results if isinstance(r, BaseException)]
    assert stopped and all(isinstance(r, BudgetExceeded) for r in stopped), results
    spent = hub.llm.meter.suite_budget()["spent_today"]
    assert 1 <= spent <= 1 + ONE_CALL and len(results) - len(stopped) == round(spent / ONE_CALL)
    assert hub.llm.meter._holds == []  # every admitted call was released
    assert {r["outcome"] for r in hub.store.tail("llm_usage", 20)} == {"ok", "budget_stopped"}


def test_calls_running_at_the_same_time_cannot_pass_an_agents_budget_together(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, SlowClaude([said(f"answer {n}", FULL) for n in range(4)]))
    assert client.patch("/api/agents/supervisor/settings", json={"config": {"budget": {"daily_cost_usd": 0.5}}}).status_code == 200
    results = at_once(hub, client, "supervisor", 4)
    assert sum(isinstance(r, BudgetExceeded) for r in results) == 2, results
    assert hub.llm.meter.spend("supervisor")["cost_today"] == pytest.approx(2 * ONE_CALL)  # 0.5 + less than one call
    lifted = client.post("/api/agents/supervisor/budget/override", json={"reason": "incident 42"})
    assert lifted.status_code == 200 and not lifted.json()["stopped"]


def test_rate_limits_per_agent(client, monkeypatch):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[said("one"), said("two"), said("three")])
    client.patch("/api/agents/supervisor/settings", json={"config": {"rate": {"calls_per_minute": 1}}})
    assert client.post("/api/chat", json={"text": "hi"}).status_code == 200
    limited = client.post("/api/chat", json={"text": "hi"})
    assert limited.status_code == 429 and limited.json()["code"] == "rate_limited"
    assert 1 <= limited.json()["retry_after"] <= 60
    assert "reached its limit of 1 model calls per minute - try again in" in limited.json()["detail"]
    assert hub.store.tail("llm_usage", 1)[0]["outcome"] == "rate_limited"
    member = client.post("/api/agents", json={"name": "Helper", "provider": "anthropic"}).json()["id"]
    client.patch(f"/api/agents/{member}/settings", json={"config": {"rate": {"runs_per_hour": 1}}})
    assert client.post(f"/api/agents/{member}/chat", json={"text": "hi"}).status_code == 200
    again = client.post(f"/api/agents/{member}/chat", json={"text": "hi"})
    assert again.status_code == 429 and "1 chats and runs per hour" in again.json()["detail"]


def test_the_limiter_and_a_providers_own_limits():
    clock = [0.0]
    limiter = llm_usage.Limiter(clock=lambda: clock[0])
    limiter.take(("calls", "a"), 2, 60, "a")
    limiter.take(("calls", "a"), 2, 60, "a")
    with pytest.raises(RateLimited) as caught:
        limiter.take(("calls", "a"), 2, 60, "a is busy")
    assert caught.value.retry_after == 60 and str(caught.value) == "a is busy - try again in 60s"
    limiter.take(("calls", "a"), None, 60, "no limit")  # None: never limited
    clock[0] = 61
    limiter.take(("calls", "a"), 2, 60, "a")
    asyncio.run(limiter.acquire(("provider", "p"), 1, 60, "p"))  # a free slot: taken at once
    with pytest.raises(RateLimited):  # a provider's requests per minute: waited for briefly (max_wait), not a minute
        asyncio.run(limiter.acquire(("provider", "p"), 1, 60, "Ollama is busy", max_wait=30))


def test_a_providers_requests_per_minute_and_concurrency(client):
    hub = client.app.state.hub
    created = client.post("/api/llm/providers", json={"name": "Ollama", "default_model": "m", "max_concurrency": 1,
                                                      "requests_per_minute": 30}).json()
    record = hub.llm.record(created["id"])
    assert (record.max_concurrency, record.requests_per_minute) == (1, 30)
    assert client.patch(f"/api/llm/providers/{created['id']}", json={"requests_per_minute": 0}).status_code == 200
    assert hub.llm.record(created["id"]).requests_per_minute is None  # 0: no limit
    order: list[str] = []

    async def both():
        async def one(name: str):
            async with hub.llm._slot(created["id"]):
                order.append(f"{name} in")
                await asyncio.sleep(0.05)
                order.append(f"{name} out")
        await asyncio.gather(one("a"), one("b"))
    client.portal.call(both)
    assert order == ["a in", "a out", "b in", "b out"]  # one call at a time


def test_the_usage_report(client, monkeypatch, sign_in):
    hub = client.app.state.hub
    use_claude(hub, monkeypatch, responses=[said("one"), said("two")])
    client.post("/api/chat", json={"text": "a"})
    client.post("/api/chat", json={"text": "b"})
    viewer = sign_in("viewer")
    report = viewer.get("/api/llm/usage?days=1").json()
    [row] = report["rows"]
    assert (row["key"], row["name"], row["calls"], row["input_tokens"]) == ("supervisor", "Hub Supervisor", 2, 2000)
    assert row["cost_usd"] == pytest.approx(0.012) and report["totals"]["calls"] == 2
    assert report["suite_budget"]["limit"] == 20 and report["prices_as_of"] == "2026-10-14"
    assert report["from"] == report["to"] == llm_usage.day_of(time.time())
    assert viewer.get("/api/llm/usage?group=provider").json()["rows"][0]["key"] == "anthropic"
    assert viewer.get("/api/llm/usage?group=day").json()["rows"][0]["key"] == llm_usage.day_of(time.time())
    assert viewer.get("/api/llm/usage?group=nope").status_code == 422
    assert viewer.get("/api/llm/usage?days=0").status_code == 422
    agent = viewer.get("/api/agents/supervisor/usage?days=7").json()
    assert len(agent["days"]) == 7 and agent["today"]["calls"] == 2 and agent["budget_state"]["limit"] is None
    assert SECRET_TEXT not in json.dumps(report)
