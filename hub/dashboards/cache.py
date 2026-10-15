"""The widget result cache (round4-dashboard-spec.md 8.2).

In-process LRU of 512 entries keyed by ``(type, canonical config)``. An entry holds the result and the bus generation
counters of the events the widget depends on (``Bus.generations``); it is valid while it has not expired (``ttl``) and
none of those events was published since. Results never depend on who asks (resolvers get no principal), so the cache
is shared by every viewer. Each key has an ``asyncio.Lock``: dashboards refreshing together compute a widget once.
``fresh`` (the configure dialog's preview) recomputes at most once per key per ``FRESH_EVERY`` seconds.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from ..bus import Bus

SIZE = 512
FRESH_EVERY = 5.0
Key = tuple[str, str]


@dataclass
class Entry:
    result: dict[str, Any]
    deps: tuple[int, ...]
    expires: float


class WidgetCache:
    def __init__(self, bus: "Bus", size: int = SIZE):
        self.bus = bus
        self.size = size
        self._entries: OrderedDict[Key, Entry] = OrderedDict()
        self._locks: dict[Key, asyncio.Lock] = {}
        self._fresh: dict[Key, float] = {}

    def __len__(self) -> int:
        return len(self._entries)

    def _lock(self, key: Key) -> asyncio.Lock:
        if len(self._locks) > 2 * self.size:  # forget idle locks of evicted keys
            for k in [k for k, lock in self._locks.items() if not lock.locked() and k not in self._entries]:
                del self._locks[k]
        return self._locks.setdefault(key, asyncio.Lock())

    def valid(self, key: Key, events: tuple[str, ...], now: float) -> dict[str, Any] | None:
        entry = self._entries.get(key)
        if entry is None or entry.expires <= now or entry.deps != self.bus.generations(events):
            return None
        self._entries.move_to_end(key)
        return entry.result

    async def get(self, key: Key, events: tuple[str, ...], ttl: float, compute: Callable[[], dict[str, Any]],
                  fresh: bool = False) -> dict[str, Any]:
        async with self._lock(key):
            now = time.time()
            if fresh and now - self._fresh.get(key, 0.0) >= FRESH_EVERY:
                self._fresh[key] = now
                if len(self._fresh) > 2 * self.size:
                    self._fresh = {k: t for k, t in self._fresh.items() if now - t < FRESH_EVERY}
            else:
                cached = self.valid(key, events, now)
                if cached is not None:
                    return cached
            deps = self.bus.generations(events)  # before computing: an event during it leaves the entry stale
            result = compute()
            if result.get("status") in ("ok", "empty"):
                self._entries[key] = Entry(result, deps, now + ttl)
                self._entries.move_to_end(key)
                while len(self._entries) > self.size:
                    self._entries.popitem(last=False)
            return result

    def clear(self) -> None:
        self._entries.clear()
