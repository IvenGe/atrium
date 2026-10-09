"""The tool event bus: how integrated tools notify each other at runtime.

A tool (or its adapter) publishes ``{source, event, payload}`` to the hub. The
hub delivers it to every tool whose manifest ``events.listens`` matches, by
POSTing to that tool's ``events.webhook_url``.
"""

from __future__ import annotations

import time
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from ..core import Hub


class ToolBus:
    def __init__(self, hub: "Hub"):
        self.hub = hub

    def routes(self) -> list[dict[str, Any]]:
        routes = []
        tools = [t for t in self.hub.tools() if t.manifest]
        for source in tools:
            for emitted in source.manifest.events.emits:  # type: ignore[union-attr]
                for target in tools:
                    if target.id == source.id:
                        continue
                    for pattern in target.manifest.events.listens:  # type: ignore[union-attr]
                        if fnmatch(emitted, pattern) or fnmatch(pattern, emitted):
                            routes.append({
                                "from": source.id, "event": emitted, "to": target.id, "pattern": pattern,
                                "webhook": target.manifest.events.webhook_url,  # type: ignore[union-attr]
                            })
        return routes

    async def publish(self, source: str, event: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
        deliveries: list[dict[str, Any]] = []
        envelope = {"source": source, "event": event, "payload": payload, "ts": time.time()}
        targets = [
            t for t in self.hub.tools()
            if t.id != source and t.manifest and any(fnmatch(event, p) for p in t.manifest.events.listens)
        ]
        async with httpx.AsyncClient(timeout=10) as client:
            for target in targets:
                url = target.manifest.events.webhook_url if target.manifest else None
                if not url:
                    deliveries.append({"to": target.id, "ok": False, "detail": "listens, but has no webhook_url"})
                    continue
                try:
                    response = await client.post(url, json=envelope)
                    deliveries.append({"to": target.id, "ok": response.status_code < 400, "detail": f"HTTP {response.status_code}"})
                except httpx.HTTPError as exc:
                    deliveries.append({"to": target.id, "ok": False, "detail": str(exc) or exc.__class__.__name__})
        entry = self.hub.store.append("toolbus", {**envelope, "deliveries": deliveries})
        self.hub.bus.publish("toolbus", entry)
        return deliveries

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.hub.store.tail("toolbus", limit)
