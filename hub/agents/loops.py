"""A dependency-free tool loop for an agent whose model sits behind a gateway it reaches over the network: the
subsidiary sidecar (hub/subsidiary/sidecar) runs its staff with it over Atrium's model gateway, which composes the
system prompt and the tool list itself. Atrium's own agents use hub.llm.loop.converse, which adds provider fallbacks,
cloud switches and metering; both turn a tool's result into the model's tool message the same way (call_tool).

Imports only the standard library and hub.subsidiary.wire (pydantic): never hub.core, hub.store, FastAPI or a model SDK.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Literal, Protocol

from ..subsidiary.wire import WireMsg, WireResult

MAX_TURNS = 12
PANEL_MAX_TURNS = 6
MAX_TOOL_CALLS = 20
MAX_RESULT = 20_000
REFUSED = "I can't help with that request."

Run = Callable[[str, dict[str, Any]], Awaitable[Any]]


class Model(Protocol):
    async def complete(self, messages: list[WireMsg]) -> WireResult: ...


def result_text(result: Any) -> str:
    """A tool's result as the model reads it: JSON, cut to MAX_RESULT characters."""
    return json.dumps(result, default=str)[:MAX_RESULT]


async def call_tool(run: Run, call: Any) -> tuple[str, bool]:
    """Run one tool call (anything with .name, .arguments and .error) -> (text for the model, is_error)."""
    if call.error:
        return f"Error: {call.error}", True
    try:
        return result_text(await run(call.name, dict(call.arguments))), False
    except Exception as exc:
        return f"Error: {exc}", True


@dataclass
class Outcome:
    reply: str
    stop: Literal["end", "refusal", "max_tokens", "max_turns", "max_tool_calls"]
    turns: int = 0
    tool_calls: int = 0


async def tool_loop(model: Model, messages: list[WireMsg], run: Run, *, max_turns: int = MAX_TURNS,
                    max_tool_calls: int = MAX_TOOL_CALLS) -> Outcome:
    """Run the conversation in `messages` (ending with the task or question) until the model answers without a tool
    call, at most `max_turns` model turns and `max_tool_calls` tool calls. `messages` is appended to in place; the
    model's errors (the gateway refusing, a budget) propagate to the caller."""
    calls = 0
    text = ""
    for turn in range(1, max_turns + 1):
        result = await model.complete(messages)
        messages.append(result.message())
        text = result.text
        if result.stop == "refusal":
            return Outcome(REFUSED, "refusal", turn, calls)
        if result.stop == "pause":
            continue
        if not result.tool_calls:
            if result.stop == "max_tokens":
                return Outcome((text + "\n\n(Reply cut off.)").strip(), "max_tokens", turn, calls)
            return Outcome(text.strip() or "Done.", "end", turn, calls)
        if calls + len(result.tool_calls) > max_tool_calls:
            note = f"(Stopped: the run reached its limit of {max_tool_calls} tool calls.)"
            return Outcome((text + "\n\n" + note).strip(), "max_tool_calls", turn, calls)
        calls += len(result.tool_calls)
        answers = await asyncio.gather(*(call_tool(run, c) for c in result.tool_calls))
        messages.extend(WireMsg(role="tool", call_id=c.id, text=t, is_error=e)
                        for c, (t, e) in zip(result.tool_calls, answers))
    note = f"(Stopped after {max_turns} model turns.)"
    return Outcome((text + "\n\n" + note).strip(), "max_turns", max_turns, calls)
