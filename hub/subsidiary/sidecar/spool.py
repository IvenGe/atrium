"""The claimed-audit spool and secret masking.

What the sidecar did that Atrium did not see itself - bridge reads, panel questions answered, runs started and ended,
grants executed - is appended to ``spool.jsonl`` in the state directory and shipped with the next heartbeats, where
Atrium records it as *claimed* (7.8). Entries hold ids, outcomes, hashes and lengths, never tool text. The file is at
most 10 MB: beyond that the oldest entries are dropped and counted (the count is shipped too).

``Secrets`` masks every secret the sidecar holds (its token, the enrollment code, the dedicated credential's values,
tickets and grants) in what leaves the process: the spool and the log.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Callable

from ..models import SPOOL_MAX, ClaimedEntry
from .config import State

SPOOL_FILE, SPOOL_META = "spool.jsonl", "spool.json"
MAX_BYTES = 10 * 1024 * 1024
SHIP_MAX = SPOOL_MAX  # entries per heartbeat (HeartbeatRequest.spool)
MASK = "***"
DETAIL_KEY = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
MIN_SECRET = 6  # shorter values are not masked (they would mask ordinary words)


def digest(text: Any) -> str:
    """How the spool refers to text it must not hold: the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(str(text).encode("utf-8")).hexdigest()[:16]


class Secrets:
    """The secret values this sidecar holds, to mask wherever text leaves it."""

    def __init__(self) -> None:
        self.values: set[str] = set()

    def add(self, *values: Any) -> None:
        for value in values:
            if isinstance(value, str) and len(value) >= MIN_SECRET:
                self.values.add(value)

    def mask(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in sorted(self.values, key=len, reverse=True):
                if secret in value:
                    value = value.replace(secret, MASK)
            return value
        if isinstance(value, dict):
            return {k: self.mask(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.mask(v) for v in value]
        return value


class MaskFilter(logging.Filter):
    """Masks the sidecar's secrets in every log record it formats."""

    def __init__(self, secrets: Secrets):
        super().__init__()
        self.secrets = secrets

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        record.msg, record.args = self.secrets.mask(message), None
        return True


def small(detail: Any, depth: int = 0) -> Any:
    """A detail kept to small scalars under simple keys (what Atrium keeps of a claimed entry anyway)."""
    if detail is None or isinstance(detail, (bool, int, float)):
        return detail
    if isinstance(detail, str):
        return detail[:200]
    if isinstance(detail, dict) and depth < 2:
        return {k: small(v, depth + 1) for k, v in list(detail.items())[:20] if isinstance(k, str) and DETAIL_KEY.match(k)}
    if isinstance(detail, (list, tuple)) and depth < 2:
        return [small(v, depth + 1) for v in list(detail)[:20]]
    return None


class Spool:
    def __init__(self, state: State, *, clock: Callable[[], float], secrets: Secrets, max_bytes: int = MAX_BYTES):
        self.state, self.clock, self.secrets, self.max_bytes = state, clock, secrets, max_bytes
        meta = state.read_json(SPOOL_META) or {}
        self.dropped = int(meta.get("dropped", 0)) if isinstance(meta, dict) else 0

    @property
    def path(self) -> Any:
        return self.state.path(SPOOL_FILE)

    def _lines(self) -> list[bytes]:
        raw = self.state.read(SPOOL_FILE) or b""
        return [line for line in raw.split(b"\n") if line.strip()]

    def _save(self, lines: list[bytes]) -> None:
        self.state.write(SPOOL_FILE, b"".join(line + b"\n" for line in lines))
        self.state.write_json(SPOOL_META, {"dropped": self.dropped})

    def add(self, kind: str, *, agent_id: str | None = None, run_id: str | None = None, action_id: str | None = None,
            outcome: str | None = None, detail: dict[str, Any] | None = None) -> None:
        entry = ClaimedEntry(ts=self.clock(), kind=kind[:40], agent_id=agent_id and agent_id[:60],
                             run_id=run_id and run_id[:60], action_id=action_id and action_id[:60],
                             outcome=outcome and outcome[:40], detail=small(self.secrets.mask(detail)))
        line = json.dumps(self.secrets.mask(entry.model_dump(mode="json", exclude_none=True)),
                          separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        size = self.path.stat().st_size if self.path.exists() else 0
        if size == 0:
            self._save([line])  # created 0600 by State.write
            return
        if size + len(line) + 1 <= self.max_bytes:
            with open(self.path, "ab") as out:  # appends keep the file's mode
                out.write(line + b"\n")
            return
        lines = self._lines() + [line]
        total = sum(len(item) + 1 for item in lines)
        while lines and total > self.max_bytes * 0.9:  # drop the oldest, leaving room to grow
            total -= len(lines.pop(0)) + 1
            self.dropped += 1
        self._save(lines)

    def batch(self, limit: int = SHIP_MAX) -> tuple[list[dict[str, Any]], int]:
        """The oldest entries to ship with a heartbeat, and the dropped count."""
        out = []
        for line in self._lines()[:limit]:
            try:
                out.append(ClaimedEntry.model_validate_json(line).model_dump(mode="json"))
            except ValueError:
                continue
        return out, self.dropped

    def shipped(self, count: int, dropped: int) -> None:
        """Atrium recorded the first `count` entries (and the dropped count it was sent)."""
        lines = self._lines()
        self.dropped = max(0, self.dropped - dropped)
        self._save(lines[count:])

    def __len__(self) -> int:
        return len(self._lines())
