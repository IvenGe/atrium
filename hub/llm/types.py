"""Provider-neutral types of the model layer: what agents send (Request, Msg, ToolSpec), what a provider answers
(Result, Usage) and what an adapter is. Provider-native shapes (Anthropic content blocks, Chat Completions messages)
live only in hub/llm/adapters/."""

from __future__ import annotations

from typing import Any, Literal, Protocol, TypedDict

from pydantic import BaseModel, Field

Purpose = Literal["chat", "code", "generate"]
PURPOSES: tuple[str, ...] = ("chat", "code", "generate")
Stop = Literal["end", "tool_calls", "max_tokens", "refusal", "pause", "context_exceeded"]
Trigger = Literal["chat", "run", "schedule", "playground", "system"]
Location = Literal["self_hosted", "third_party"]


class ProviderError(RuntimeError):
    """A provider problem with a message safe to show (secrets masked). `kind`: a short machine-readable cause
    (the exception class it came from, "http_<status>", "timeout"...); `status`: the HTTP status, when there was one."""

    def __init__(self, message: str, *, kind: str = "provider_error", status: int | None = None):
        super().__init__(message)
        self.kind, self.status = kind, status


class LLMUnavailable(RuntimeError):
    """No model can answer this call (none configured, the provider failed, or its answer was unusable). Callers
    fall back to rules or templates."""


class Limited(LLMUnavailable):
    """A budget or rate limit stops new model calls (usage.py). `code` is what a chat answer's HTTP 429 carries;
    `retry_after`: seconds until a call may start again (None: not today)."""

    code = "limited"

    def __init__(self, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class BudgetExceeded(Limited):
    """An agent's or the suite's AI budget is used up for today (or this month)."""

    code = "budget_exceeded"


class RateLimited(Limited):
    """Too many model calls or runs in a short time."""

    code = "rate_limited"


class ToolSpec(TypedDict, total=False):
    name: str
    description: str
    input_schema: dict[str, Any]
    strict: bool  # Anthropic strict tool use (the toolkit's schemas are strict-shaped for it)


class ToolCall(BaseModel):
    id: str
    name: str
    arguments: dict[str, Any] = {}
    error: str | None = None  # the arguments could not be read (e.g. invalid JSON): answered as a failed call


class Msg(BaseModel):
    """One conversation entry. `raw` keeps an assistant turn's provider-native output (Anthropic content blocks with
    thinking signatures, a Chat Completions message) and is replayed verbatim to the SAME provider and model only."""

    role: Literal["user", "assistant", "tool"]
    text: str = ""
    tool_calls: list[ToolCall] = []  # assistant
    call_id: str | None = None  # tool
    is_error: bool = False  # tool
    raw: Any = None
    provider: str | None = None
    model: str | None = None


class Usage(BaseModel):
    input_tokens: int = 0  # not counting cached or cache-write tokens
    cached_input_tokens: int = 0
    cache_write_tokens: int = 0
    output_tokens: int = 0
    reasoning_tokens: int = 0
    estimated: bool = False  # counted from characters: the provider did not report usage
    inference_geo: str | None = None

    @property
    def total_input(self) -> int:
        return self.input_tokens + self.cached_input_tokens + self.cache_write_tokens


class Request(BaseModel):
    purpose: Purpose
    agent_id: str
    trigger: Trigger = "system"
    person: str | None = None  # whoever asked ("user:<id>"), for metering and hashed safety ids
    system: str = ""
    messages: list[Msg] = []
    tools: list[dict[str, Any]] = []  # ToolSpec
    json_schema: dict[str, Any] | None = None
    schema_name: str = "result"
    json_mode: Literal["native", "json_object", "prompt"] | None = None  # set by structured.py with json_schema
    model: str
    effort: str | None = None
    temperature: float | None = None
    max_output_tokens: int = 16_000


class Result(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = []
    stop: Stop = "end"
    usage: Usage = Usage()
    served_model: str = ""
    raw: Any = None
    refusal: str | None = None
    parsed: dict[str, Any] | None = None  # the validated JSON of a json_schema call


class Caps(BaseModel):
    """What a provider's model supports, merged from its API, a probe, learning from errors, an admin or defaults.
    None = unknown (try, and learn from the answer)."""

    tools: bool | None = None
    json_schema: bool | None = None
    json_object: bool | None = None
    temperature: bool | None = None
    effort_levels: list[str] | None = None
    max_output_tokens: int | None = None
    context_window: int | None = None
    source: Literal["api", "probe", "learned", "admin", "default"] = "default"
    at: float | None = None


class ReplyMeta(BaseModel):
    """What a model call ran on - never prompt or reply text."""

    provider: str
    provider_label: str
    model: str
    mode: Literal["llm", "local", "rules", "text-only"] = "llm"
    source: str = "suite"
    fallback_from: str | None = None
    usage: Usage = Field(default_factory=Usage)
    cost_usd: float | None = None
    latency_ms: int = 0


class Adapter(Protocol):
    """One provider: turns a neutral Request into its API's request and its answer into a neutral Result."""

    kind: str

    def location(self) -> Location: ...

    def available(self) -> tuple[bool, str | None]: ...  # (ok, reason) without network

    async def list_models(self) -> list[dict[str, Any]]: ...  # [{id, label?, caps?: Caps, lifecycle?, retires_at?}]

    def caps(self, model: str) -> Caps: ...

    async def complete(self, req: Request) -> Result: ...  # one model turn; raises ProviderError (safe text)
