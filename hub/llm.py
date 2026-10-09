"""Optional Claude integration.

Every agent works without an LLM using deterministic rules. With Claude
available, the Hub Supervisor plans in natural language and the Patch Agent
writes real code patches. Credentials are resolved by the Anthropic SDK
(ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login` profile).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

try:
    import anthropic
except ImportError:  # pragma: no cover - optional dependency
    anthropic = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from .core import Hub

# Server-side refusal fallback: if a request is declined, the API re-runs it on a fallback model.
FALLBACK_BETA = "server-side-fallback-2026-07-01"
FALLBACK_MODELS = {"claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}


class LLMUnavailable(RuntimeError):
    pass


class LLM:
    def __init__(self, hub: "Hub"):
        self.hub = hub
        self._client: Any = None
        self.last_error: str | None = None

    @property
    def installed(self) -> bool:
        return anthropic is not None

    @property
    def configured(self) -> bool:
        if os.environ.get("HUB_LLM", "").lower() == "off":
            return False
        if any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE")):
            return True
        return (Path.home() / ".config" / "anthropic").is_dir()

    @property
    def available(self) -> bool:
        return self.installed and self.configured

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "installed": self.installed,
            "configured": self.configured,
            "model": self.hub.prefs["model"],
            "last_error": self.last_error,
        }

    def client(self) -> Any:
        if not self.available:
            raise LLMUnavailable("No Claude credentials found (set ANTHROPIC_API_KEY or run `ant auth login`).")
        if self._client is None:
            self._client = anthropic.AsyncAnthropic()
        return self._client

    async def create(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        effort: str = "medium",
        max_tokens: int = 16000,
        json_schema: dict[str, Any] | None = None,
    ) -> Any:
        model = model or self.hub.prefs["model"]
        output_config: dict[str, Any] = {"effort": effort}
        if json_schema:
            output_config["format"] = {"type": "json_schema", "schema": json_schema}
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": messages,
            "output_config": output_config,
            "cache_control": {"type": "ephemeral"},
        }
        if tools:
            kwargs["tools"] = tools
        if model in FALLBACK_MODELS:
            kwargs["betas"] = [FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        try:
            response = await self.client().beta.messages.create(**kwargs)
        except anthropic.APIError as exc:
            self.last_error = f"{exc.__class__.__name__}: {exc}"
            raise
        self.last_error = None
        return response

    async def json(self, *, system: str, prompt: str, schema: dict[str, Any], model: str | None = None,
                   effort: str = "medium", max_tokens: int = 16000) -> dict[str, Any]:
        """One structured-output call; returns the parsed JSON object."""
        response = await self.create(
            system=system, messages=[{"role": "user", "content": prompt}], json_schema=schema,
            model=model, effort=effort, max_tokens=max_tokens,
        )
        if response.stop_reason == "refusal":
            raise LLMUnavailable("The model declined this request.")
        if response.stop_reason == "max_tokens":
            raise LLMUnavailable("The response was cut off (max_tokens).")
        text = "".join(block.text for block in response.content if block.type == "text")
        return json.loads(text)
