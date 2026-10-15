"""Every known hub secret is masked in all content sent to a model - system prompt, messages, tool results and
tool-call arguments - for every provider, local ones included (local servers often log prompts). A secret is masked
as it is and as JSON spells it inside a string (escaped quotes, backslashes, control and non-ASCII characters - once
or twice), and a tool's result is masked before it is serialised and cut (value()). Provider error texts, which can
quote a provider's answer, are masked too (error())."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING, Any

from ..connectors.base import redact
from ..extensions.selfpatch import mask_known
from .types import Msg, ProviderError, Request, ToolCall

if TYPE_CHECKING:
    from ..core import Hub

REFRESH = 60.0  # seconds; changes that add a secret refresh it at once (REFRESH_EVENTS)
REFRESH_EVENTS = {"llm_provider", "llm_provider_removed", "connection", "connection_removed", "sso_settings"}


def spellings(secret: str) -> set[str]:
    """The secret as text may carry it: as it is, and inside a JSON string once or twice (with or without
    ensure_ascii)."""
    out = {secret}
    for _ in range(2):
        out |= {json.dumps(v, ensure_ascii=ascii_only)[1:-1] for v in out for ascii_only in (True, False)}
    return out


class SecretMask:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._values: list[str] | None = None
        self._at = 0.0

    def invalidate(self) -> None:
        self._values = None

    def on_event(self, type_: str, data: Any) -> None:
        if type_ in REFRESH_EVENTS:
            self.invalidate()

    def values(self) -> list[str]:
        if self._values is None or time.monotonic() - self._at >= REFRESH:
            from ..secrets import hub_secret_values

            self._values = sorted({v for secret in hub_secret_values(self.hub) for v in spellings(secret)},
                                  key=len, reverse=True)
            self._at = time.monotonic()
        return self._values

    def text(self, value: str) -> str:
        return mask_known(value, self.values()) if value else value

    def value(self, value: Any) -> Any:
        """`value` (a tool's result, tool-call arguments) with every string in it masked, before it becomes JSON text:
        what json.dumps(value, default=str) would write, less the secrets."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, (list, tuple)):
            return [self.value(v) for v in value]
        if isinstance(value, dict):
            return {self.text(k) if isinstance(k, str) else k: self.value(v) for k, v in value.items()}
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self.text(str(value))  # json.dumps(default=str) writes str(value)

    def error(self, exc: ProviderError) -> ProviderError:
        """A provider error whose text carries no hub secret and no credential-looking pair."""
        text = redact(self.text(str(exc)))
        return exc if text == str(exc) else ProviderError(text, kind=exc.kind, status=exc.status)

    def message(self, msg: Msg) -> Msg:
        """A copy with every text masked. `raw` (a provider's own earlier output, replayed to it) is left as it is:
        the model wrote it from content that was masked already."""
        return msg.model_copy(update={
            "text": self.text(msg.text),
            "tool_calls": [ToolCall(id=c.id, name=c.name, arguments=self.value(c.arguments)) for c in msg.tool_calls],
        })

    def request(self, req: Request) -> Request:
        return req.model_copy(update={"system": self.text(req.system),
                                      "messages": [self.message(m) for m in req.messages]})
