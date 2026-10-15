"""The subsidiaries' audit trail (7.8): one append-only, hash-chained log per subsidiary, never pruned.

Each subsidiary has its own log stream ``subsidiary_audit:<subsidiary id>`` (not in core.LOG_RETENTION). An entry's
``hash`` is the SHA-256 of the previous entry's hash and the entry's canonical JSON (models.AuditEntry.compute_hash);
the newest ``seq`` and ``hash`` are kept in ``subsidiary_chain_heads``, so a deleted, changed or reordered entry - or a
truncated tail - shows when the chain is recomputed (``verify``).

``observed`` entries are what Atrium saw itself; ``claimed`` entries come from the sidecar's spool (bridge reads, panel
answers as hashes and lengths, runs). Entries hold ids, hashes and counts: never tool text, prompts or secrets.
"""

from __future__ import annotations

import re
import threading
from typing import TYPE_CHECKING, Any, Iterable

from .models import AUDIT_LOG, COLLECTIONS, AuditEntry, ChainHead, ClaimedEntry, Origin

if TYPE_CHECKING:
    from ..core import Hub

HEADS = COLLECTIONS["heads"]
PAGE = 5000
DETAIL_KEYS = 20
KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_lock = threading.Lock()  # read head, append, move head: one writer at a time (the API loop and tests' threads)


def stream(sub_id: str) -> str:
    return f"{AUDIT_LOG}:{sub_id}"


def head(hub: "Hub", sub_id: str) -> ChainHead:
    doc = hub.store.get(HEADS, sub_id)
    return ChainHead.model_validate(doc) if doc else ChainHead(id=sub_id)


def clean_detail(detail: Any, depth: int = 0) -> Any:
    """A claimed detail kept to small scalars under simple keys (hashes, lengths, counts, ids): never tool text."""
    if isinstance(detail, bool) or detail is None or isinstance(detail, (int, float)):
        return detail
    if isinstance(detail, str):
        return detail[:200]
    if isinstance(detail, dict) and depth < 2:
        return {k: clean_detail(v, depth + 1) for k, v in list(detail.items())[:DETAIL_KEYS]
                if isinstance(k, str) and KEY_RE.match(k)}
    if isinstance(detail, list) and depth < 2:
        return [clean_detail(v, depth + 1) for v in detail[:DETAIL_KEYS]]
    return None


def record(hub: "Hub", sub_id: str, kind: str, *, origin: Origin = "observed", ts: float | None = None,
           **fields: Any) -> AuditEntry:
    """Append an entry to the subsidiary's chain (fields: agent_id, run_id, action_id, approval_id, grant_jti,
    body_sha256, outcome, taint, detail)."""
    with _lock:
        current = head(hub, sub_id)
        entry = AuditEntry(seq=current.seq + 1, subsidiary_id=sub_id, origin=origin, kind=kind[:40],
                           prev=current.hash, **({"ts": ts} if ts is not None else {}), **fields)
        entry.hash = entry.compute_hash()
        hub.store.append(stream(sub_id), {"ts": entry.ts, "entry": entry.model_dump(mode="json")})
        hub.store.put(HEADS, ChainHead(id=sub_id, seq=entry.seq, hash=entry.hash).model_dump(mode="json"))
    return entry


def claimed(hub: "Hub", sub_id: str, spool: Iterable[ClaimedEntry], dropped: int = 0) -> int:
    """Record the sidecar's spool lines as claimed entries (and how many it dropped, when any)."""
    count = 0
    for line in spool:
        record(hub, sub_id, line.kind, origin="claimed", agent_id=line.agent_id, run_id=line.run_id,
               action_id=line.action_id, outcome=line.outcome, detail={"claimed_at": line.ts,
                                                                        **(clean_detail(line.detail) or {})})
        count += 1
    if dropped:
        record(hub, sub_id, "spool.dropped", origin="claimed", detail={"dropped": int(dropped)})
    return count


def _rows(hub: "Hub", sub_id: str, limit: int, before: int | None = None) -> list[dict[str, Any]]:
    return hub.store.tail(stream(sub_id), limit, before)


def entries(hub: "Hub", sub_id: str, limit: int = 200,
            before: int | None = None) -> tuple[list[AuditEntry], int | None]:
    """The newest `limit` entries (oldest first) before the cursor `before`, and the cursor of the page before them."""
    rows = _rows(hub, sub_id, limit, before)
    cursor = rows[0]["seq"] if rows and len(rows) == limit else None
    return [AuditEntry.model_validate(r["entry"]) for r in rows], cursor


def all_entries(hub: "Hub", sub_id: str) -> list[AuditEntry]:
    out: list[AuditEntry] = []
    before: int | None = None
    while True:
        rows = _rows(hub, sub_id, PAGE, before)
        out[:0] = [AuditEntry.model_validate(r["entry"]) for r in rows]
        if len(rows) < PAGE:
            return out
        before = rows[0]["seq"]


def public(entry: AuditEntry, detail: bool) -> dict[str, Any]:
    """Viewers see the metadata; operators (``detail``) also the detail and the taint sources."""
    return entry.model_dump(mode="json", exclude=None if detail else {"detail", "taint"})


def verify(hub: "Hub", sub_id: str) -> dict[str, Any]:
    """Recompute the chain: {ok, entries, head_seq, problems: [{seq, problem}]} (at most 20 problems listed)."""
    items = all_entries(hub, sub_id)
    problems: list[dict[str, Any]] = []
    prev, expected = "", 1
    for entry in items:
        if entry.seq != expected:
            problems.append({"seq": entry.seq, "problem": f"expected entry {expected}"})
        if entry.prev != prev:
            problems.append({"seq": entry.seq, "problem": "does not link to the entry before it"})
        if entry.compute_hash() != entry.hash:
            problems.append({"seq": entry.seq, "problem": "its content changed after it was written"})
        prev, expected = entry.hash, entry.seq + 1
    top = head(hub, sub_id)
    if top.seq != len(items) or top.hash != prev:
        problems.append({"seq": top.seq, "problem": "the chain head does not match the last entry (entries missing)"})
    return {"ok": not problems, "entries": len(items), "head_seq": top.seq, "problems": problems[:20]}


def count(hub: "Hub", sub_ids: Iterable[str]) -> int:
    return sum(hub.store.count(stream(s)) for s in sub_ids)
