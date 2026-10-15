"""The event relay (4.11, 9.2): events the tool emits through its bridge, republished by Atrium on the tool bus.

While the charter relays events and the ticket lists ``atrium.events.pull``, the sidecar long-polls the bridge's outbox
and posts what it gets to ``POST /events`` in batches of at most 100. Atrium accepts only names the approved manifest
declares under ``<tool_id>.``; the sidecar drops anything else before sending it. Events never start runs. The pull
cursor is kept in the state directory, so a restart does not relay the same events twice.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .. import contract
from .bridge_client import BridgeError
from .client import AtriumError, Unavailable

if TYPE_CHECKING:
    from .runtime import Runtime

CURSOR_FILE = "events.json"
BATCH = 100


class Events:
    def __init__(self, rt: "Runtime"):
        self.rt = rt
        data = rt.state.read_json(CURSOR_FILE)
        self.after = int(data.get("after", 0)) if isinstance(data, dict) else 0
        self.relayed = self.dropped = 0

    def enabled(self) -> bool:
        charter, bridge = self.rt.charter, self.rt.bridge
        return (self.rt.working() and charter is not None and charter.events.relay and bridge is not None
                and bridge.allows("atrium.events.pull"))

    def keep(self, event: Any) -> dict[str, Any] | None:
        """An event as Atrium takes it, or None (a foreign name, a payload that is not a small JSON object)."""
        if not isinstance(event, dict):
            return None
        name, payload = event.get("name"), event.get("payload")
        if not isinstance(name, str) or not name.startswith(f"{self.rt.config.tool_id}.") or len(name) > 200:
            return None
        if not isinstance(payload, dict) or len(json.dumps(payload, default=str)) > contract.EVENT_PAYLOAD_MAX:
            return None
        out: dict[str, Any] = {"name": name, "payload": payload}
        cause = event.get("cause")
        if isinstance(cause, dict) and isinstance(cause.get("jti"), str) and len(cause["jti"]) <= 64:
            out["cause"] = {"jti": cause["jti"]}
        if isinstance(event.get("at"), (int, float)) and not isinstance(event.get("at"), bool):
            out["at"] = event["at"]
        return out

    async def once(self, wait: int = contract.WAIT_MAX) -> int:
        """One pull and its relay; the number of events relayed."""
        if not self.enabled():
            return 0
        try:
            answer = await self.rt.bridge.call("atrium.events.pull",  # type: ignore[union-attr]
                                               {"after": self.after, "wait": max(0, min(wait, contract.WAIT_MAX))})
        except BridgeError as exc:
            self.rt.log.info("The events pull failed: %s", exc)
            return 0
        result = answer.result if answer.ok and isinstance(answer.result, dict) else None
        if result is None or not isinstance(result.get("events"), list):
            self.rt.log.info("The bridge refused the events pull: %s", answer.refusal())
            return 0
        events = [e for e in (self.keep(raw) for raw in result["events"]) if e is not None]
        self.dropped += len(result["events"]) - len(events)
        for start in range(0, len(events), BATCH):
            try:
                await self.rt.atrium.post("events", {"events": events[start:start + BATCH]})
            except (AtriumError, Unavailable) as exc:
                self.rt.log.warning("Atrium did not take %d tool event(s): %s", len(events[start:start + BATCH]), exc)
                if isinstance(exc, Unavailable):
                    return self.relayed  # the cursor stays: the bridge hands them out again
        following = result.get("next")
        if isinstance(following, int) and not isinstance(following, bool) and following >= 0:
            self.after = following
            self.rt.state.write_json(CURSOR_FILE, {"after": self.after})
        self.relayed += len(events)
        if events:
            self.rt.spool.add("events.relay", outcome="ok", detail={"events": len(events)})
        return len(events)
