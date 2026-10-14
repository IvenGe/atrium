"""The tool event bus: how integrated tools notify each other at runtime.

A tool (or its adapter) publishes ``{source, event, payload}`` to the hub. The
hub delivers it to every tool whose manifest ``events.listens`` matches, by
POSTing to that tool's ``events.webhook_url``.

Webhook URLs can carry tokens and payloads are the tools' data, so what viewers
see (``public_routes``, ``public_recent`` and the ``toolbus`` event) says only
whether a webhook is set and how each delivery went (review-notes F24).
"""

from __future__ import annotations

import re
import time
from fnmatch import fnmatch
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from ..core import Hub

URL = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://\S+")


def public_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """A delivery log entry without the event payload, URLs removed from the delivery details."""
    return {"seq": entry.get("seq"), "ts": entry.get("ts"), "source": entry.get("source"), "event": entry.get("event"),
            "by": entry.get("by"),
            "deliveries": [{"to": d.get("to"), "ok": bool(d.get("ok")),
                            "detail": URL.sub("<url>", str(d.get("detail") or ""))[:300]}
                           for d in entry.get("deliveries") or []]}


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

    async def publish(self, source: str, event: str, payload: dict[str, Any], by: str | None = None) -> list[dict[str, Any]]:
        """Deliver an event to the tools listening for it; `by` (who published it - an API token or a person) is
        recorded with the delivery log (review F31)."""
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
        entry = self.hub.store.append("toolbus", {**envelope, "deliveries": deliveries, "by": by})
        self.hub.bus.publish("toolbus", public_entry(entry))
        return deliveries

    def recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return self.hub.store.tail("toolbus", limit)

    def public_routes(self) -> list[dict[str, Any]]:
        """routes() for viewers: ``webhook`` and ``has_webhook`` say whether one is set, never where."""
        return [{**{k: v for k, v in r.items() if k != "webhook"}, "webhook": bool(r["webhook"]),
                 "has_webhook": bool(r["webhook"])} for r in self.routes()]

    def public_recent(self, limit: int = 50) -> list[dict[str, Any]]:
        return [public_entry(e) for e in self.recent(limit)]
