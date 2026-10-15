"""What crosses between Atrium and a sidecar besides the bridge contract: the delimitation of tool data (6.6) and the
model gateway's message format (6.5). Shared with the sidecar: pydantic and the standard library only.

Delimitation. Content written by others (a bridge result, a panel question, connector records) reaches a model only
inside a delimited block whose boundary is 128 random bits per run; the boundary is removed from the content, control
and bidi characters are stripped (newlines kept), look-alike tags are defused and each value is cut to 20 000
characters. The gateway delimits on the server - the sidecar's own copy (for its local logs) is a convenience.

Messages. The gateway speaks the provider-neutral shape of hub.llm.types (Msg, ToolCall, Result) without the
provider-native part: an assistant turn the gateway returned carries ``ref``, and Atrium re-attaches the native output
it kept (thinking signatures, ...) when the sidecar sends the turn back - the sidecar never sees or sends native blocks.
"""

from __future__ import annotations

import json
import re
import secrets
from typing import Any, Literal

from pydantic import BaseModel, Field

MAX_VALUE = 20_000
MAX_TEXT = 100_000  # any one text field of a gateway message
MAX_MESSAGES = 200  # of one gateway request (a run: the task, 12 turns, 20 tool results, notes)
MAX_TOOL_CALLS = 20
BOUNDARY_RE = re.compile(r"^[0-9a-f]{32}$")
# control characters (newline kept), zero-width, line/paragraph separators and bidi overrides, as netmodel.CONTROL_CHARS
CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]")
TAG = re.compile(r"(?i)<(\s*/?\s*)(tool_data|untrusted|system)")
SOURCE = re.compile(r"[^A-Za-z0-9:._-]+")
TAINT_KINDS = ("bridge", "panel", "connector")

# Injection heuristics: they flag, they never decide (a person sees the flags on the approval card).
INJECTION = {
    "ignore_instructions": re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|earlier|your|all)\b"
                                      r".{0,20}\b(instructions?|prompts?|rules?|directions?)\b"),
    "role_change": re.compile(r"(?i)\byou are now\b|\bact as (an?|the)\b|\bnew instructions\b"),
    "system_prompt": re.compile(r"(?i)\bsystem prompt\b|<\s*/?\s*system\s*>"),
    "tool_call": re.compile(r"(?i)\btool_use\b|\bfunction_call\b|\"tool_calls\"|\bact__[a-z0-9_-]+|\batrium__[a-z0-9_]+"
                            r"|<\s*/?\s*tool_data"),
    "base64_blob": re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}"),
}


def boundary() -> str:
    """128 random bits, hex: one per run."""
    return secrets.token_hex(16)


def text_of(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def clean(value: Any, limit: int = MAX_VALUE) -> str:
    """Text written by others made safe to store and show as TEXT: control and bidi characters removed (newlines kept,
    tabs as spaces), cut to `limit`. Still untrusted: never HTML, never a command, never an instruction."""
    text = text_of(value).replace("\r\n", "\n").replace("\t", " ")
    return CONTROL.sub("", text)[:limit]


def source_name(kind: str, name: Any) -> str:
    """A taint source / delimited-block source: "bridge:<action>", "panel:<question id>", "connector:<domain>"."""
    if kind not in TAINT_KINDS:
        raise ValueError(f"taint kinds are {TAINT_KINDS}")
    return f"{kind}:{SOURCE.sub('_', str(name))[:100]}"


def delimit(source: str, value: Any, run_boundary: str, limit: int = MAX_VALUE) -> str:
    """`value` inside <tool_data source="..." boundary="..."> ... </tool_data boundary="...">."""
    if not BOUNDARY_RE.match(run_boundary):
        raise ValueError("a boundary is 32 lowercase hex characters")
    text = clean(value, limit)
    pattern = re.compile(re.escape(run_boundary), re.IGNORECASE)
    while pattern.search(text):  # removing one occurrence may join two halves into another
        text = pattern.sub("", text)
    text = TAG.sub(lambda m: "[" + m.group(1) + m.group(2), text)
    src = SOURCE.sub("_", source)[:120]
    return f'<tool_data source="{src}" boundary="{run_boundary}">\n{text}\n</tool_data boundary="{run_boundary}">'


def injection_flags(value: Any) -> list[str]:
    """Names of the injection heuristics `value` trips (an empty list when none)."""
    text = text_of(value)
    return [name for name, pattern in INJECTION.items() if pattern.search(text)]


# --------------------------------------------------------------------------------------
# the model gateway's messages (POST /api/subsidiary/v1/model)
# --------------------------------------------------------------------------------------

Stop = Literal["end", "tool_calls", "max_tokens", "refusal", "pause", "context_exceeded"]


class WireToolCall(BaseModel):
    id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = {}
    error: str | None = Field(None, max_length=2000)  # the model's arguments could not be read


class WireMsg(BaseModel):
    """One conversation entry (hub.llm.types.Msg without the provider-native part)."""

    role: Literal["user", "assistant", "tool"]
    text: str = Field("", max_length=MAX_TEXT)
    tool_calls: list[WireToolCall] = Field([], max_length=MAX_TOOL_CALLS)  # assistant
    call_id: str | None = Field(None, max_length=128)  # tool
    is_error: bool = False  # tool
    ref: str | None = Field(None, max_length=64)  # assistant: the gateway's id of a turn it returned


class WireUsage(BaseModel):
    input_tokens: int = Field(0, ge=0)
    output_tokens: int = Field(0, ge=0)


class WireResult(BaseModel):
    """One model turn as the gateway answers it (hub.llm.types.Result without the native part)."""

    text: str = Field("", max_length=MAX_TEXT)
    tool_calls: list[WireToolCall] = Field([], max_length=MAX_TOOL_CALLS)
    stop: Stop = "end"
    usage: WireUsage = Field(default_factory=WireUsage)
    ref: str | None = Field(None, max_length=64)

    def message(self) -> WireMsg:
        """The assistant entry to append to the history (and send back unchanged)."""
        return WireMsg(role="assistant", text=self.text, tool_calls=self.tool_calls, ref=self.ref)
