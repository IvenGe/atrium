"""Provider records -> adapters: the built-in providers (Claude, OpenAI), where a provider runs (location), the
circuit breaker, and the one-time migration from the Claude-only layer."""

from __future__ import annotations

import ipaddress
import re
import time
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import urlsplit

from ..connectors.base import endpoint_of

if TYPE_CHECKING:
    from ..core import Hub

MIGRATION_DOC = "llm_migration"
MIGRATION_VERSION = 2  # 1: the provider layer (R4-LLM stage 1); 2: the daily AI spending cap (stage 4)
BUILTINS: dict[str, dict[str, Any]] = {
    "anthropic": {"id": "anthropic", "name": "Claude", "kind": "anthropic", "base_url": "https://api.anthropic.com",
                  "location": "third_party"},
    "openai": {"id": "openai", "name": "OpenAI", "kind": "openai", "variant": "openai",
               "base_url": "https://api.openai.com/v1", "location": "third_party", "enabled": False},
}
# 5 failed calls (unreachable, timed out, HTTP 429 or 5xx) in 5 minutes open the circuit for 60 seconds
FAILURES, WINDOW, OPEN_FOR = 5, 300.0, 60.0
UNSUPPORTED = ("unsupported", "not supported", "does not support", "not available for", "not allowed")
LEARNABLE = frozenset({"temperature", "effort", "tools"})


def refused_feature(message: str) -> str | None:
    """The optional request feature a provider's HTTP 400 says the model does not support: "temperature", "effort"
    (reasoning effort) or "tools" - None when the refusal is about something else."""
    low = (message or "").lower()
    if not any(w in low for w in UNSUPPORTED):
        return None
    if "temperature" in low:
        return "temperature"
    if "reasoning" in low or "effort" in low:
        return "effort"
    if re.search(r"\btools?\b|function call", low):
        return "tools"
    return None


def supported_efforts(message: str) -> list[str]:
    """The effort levels a refusal lists as supported ("Supported values are: 'low', 'medium' and 'high'"), if any."""
    from .adapters.openai import EFFORTS

    tail = re.split(r"supported values (?:are|include)", message or "", flags=re.IGNORECASE)
    return [e for e in re.findall(r"'([a-z]+)'", tail[1]) if e in EFFORTS] if len(tail) > 1 else []


def location_of(base_url: str) -> str:
    """self_hosted for loopback, private (RFC 1918 / RFC 4193) and link-local addresses, *.local and single-label
    host names; anything else is a third party (a cloud service)."""
    host = (urlsplit(base_url or "").hostname or "").lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        return "self_hosted" if ip.is_loopback or ip.is_private or ip.is_link_local else "third_party"
    if host == "localhost" or host.endswith((".local", ".localhost")) or (host and "." not in host):
        return "self_hosted"
    return "third_party"


class Breaker:
    """Per provider: FAILURES failed calls within WINDOW seconds stop new calls for OPEN_FOR seconds."""

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self.clock = clock
        self._failures: dict[str, list[float]] = {}
        self._open_until: dict[str, float] = {}

    def failure(self, provider: str) -> None:
        now = self.clock()
        recent = [t for t in self._failures.get(provider, []) if now - t < WINDOW] + [now]
        if len(recent) >= FAILURES:
            self._open_until[provider], recent = now + OPEN_FOR, []
        self._failures[provider] = recent

    def success(self, provider: str) -> None:
        self._failures.pop(provider, None)

    def remaining(self, provider: str) -> float:
        return max(0.0, self._open_until.get(provider, 0.0) - self.clock())

    def open_now(self) -> frozenset[str]:
        now = self.clock()
        return frozenset(p for p, until in self._open_until.items() if until > now)


def ensure_builtins(hub: "Hub") -> None:
    """The built-in provider records exist (Claude takes over the default model chosen in Settings before)."""
    from .. import llm_providers

    for provider_id, values in BUILTINS.items():
        if hub.store.get(llm_providers.COLLECTION, provider_id) is not None:
            continue
        doc = {**values, "endpoint": endpoint_of(values["base_url"]), "created_by": "hub", "updated_by": "hub",
               "created_at": time.time(), "updated_at": time.time()}
        if provider_id == "anthropic":  # "" = HUB_MODEL (settings.model), as before
            doc["default_model"] = str(((hub.store.get("settings", "prefs") or {}).get("values") or {}).get("model") or "")
        hub.store.put(llm_providers.COLLECTION, doc)


def migrate(hub: "Hub") -> bool:
    """Run once per version (settings/llm_migration): the suite default "auto", legacy core model overrides as Claude
    choices, replaced built-in instructions marked as such, and a location for local providers (1); a notice that AI
    spending is now capped, on installs that ran without the cap (2). Idempotent."""
    ensure_builtins(hub)
    marker = hub.store.get("settings", MIGRATION_DOC) or {}
    done = int(marker.get("version") or 0)
    if done >= MIGRATION_VERSION:
        return False
    ran_before = done >= 1 or bool(hub.auth.users())  # a new install has no accounts at its first start
    if done < 1:
        _migrate_v1(hub)
    if ran_before:
        from .. import guardrails

        if guardrails.value(hub, "limit_llm_spend"):
            hub.activity("hub", "info", f"AI spending is now capped at ${guardrails.value(hub, 'max_daily_llm_spend')} "
                         "per day (Settings > Agent guardrails > AI models and spending)", guardrail="limit_llm_spend")
    hub.store.put("settings", {"id": MIGRATION_DOC, "version": MIGRATION_VERSION, "at": time.time()})
    return True


def _migrate_v1(hub: "Hub") -> None:
    from .. import llm_providers
    from .resolve import SELECTION_DOC

    if hub.store.get("settings", SELECTION_DOC) is None:
        hub.store.put("settings", {"id": SELECTION_DOC, "default": {"provider": "auto", "model": ""}, "purposes": {},
                                   "fallback": [], "teams": {}, "language": "auto", "version": 0, "updated_by": "hub",
                                   "updated_at": time.time()})
    for doc in hub.store.list("agents"):
        changed = dict(doc)
        if doc.get("model") and not doc.get("provider"):
            changed["provider"] = "anthropic"
        if doc.get("instructions"):
            changed["config"] = {**(doc.get("config") or {}), "instructions_mode": "replace"}
        if changed != doc:
            hub.store.put("agents", changed)
    for doc in hub.store.list(llm_providers.COLLECTION):
        if doc.get("kind", "openai_compatible") == "openai_compatible" and "location" not in doc:
            hub.store.put(llm_providers.COLLECTION, {**doc, "location": location_of(doc.get("base_url", ""))})
