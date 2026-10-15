"""A tiny JSON document store on top of SQLite.

Documents live in named collections and are plain dicts with an ``id``.
Append-only streams (agent messages, activity, command history) live in ``log``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS docs (
    collection TEXT NOT NULL,
    id TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY (collection, id)
);
CREATE TABLE IF NOT EXISTS log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    stream TEXT NOT NULL,
    ts REAL NOT NULL,
    data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS log_stream ON log (stream, seq);
"""


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def _field(name: str) -> str:
    """A top-level JSON field name for the queries above (internal constants; refused otherwise)."""
    if not name or not name.replace("_", "").isalnum():
        raise ValueError(f"Not a field name: {name!r}")
    return name


def private_db(path: Path) -> None:
    """hub.db holds password hashes, rule bases and tools' launch environments: owner-only (review F14). SQLite gives
    its -wal and -shm files the database file's permissions, so the file is created 0600 before SQLite opens it; files
    from before are tightened."""
    try:
        os.close(os.open(path, os.O_RDWR | os.O_CREAT, 0o600))
    except OSError:
        return
    for name in (path, Path(f"{path}-wal"), Path(f"{path}-shm")):
        try:
            if name.exists():
                name.chmod(0o600)
        except OSError:  # best effort (Windows ACLs are not mode bits)
            pass


class Store:
    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        if str(path) != ":memory:":
            private_db(Path(path))
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        with self._lock:
            if str(path) != ":memory:":
                self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(SCHEMA)

    # -- documents -----------------------------------------------------------------

    def put(self, collection: str, doc: dict[str, Any]) -> dict[str, Any]:
        if not doc.get("id"):
            raise ValueError("document needs an id")
        data = json.dumps(doc, default=str)
        with self._lock, self._db:
            self._db.execute(
                "INSERT INTO docs (collection, id, data, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(collection, id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at",
                (collection, doc["id"], data, time.time()),
            )
        return doc

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._db.execute(
                "SELECT data FROM docs WHERE collection = ? AND id = ?", (collection, doc_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, collection: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT data FROM docs WHERE collection = ? ORDER BY rowid", (collection,)
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    @staticmethod
    def _after(prefix: str) -> str:
        """The smallest string greater than every string starting with `prefix` (for id range queries)."""
        return prefix[:-1] + chr(ord(prefix[-1]) + 1)

    def list_prefix(self, collection: str, prefix: str, without: str | None = None) -> list[dict[str, Any]]:
        """Documents whose id starts with `prefix`, read through the primary key - only those rows are read and parsed;
        `without`: a top-level field left out inside SQLite (e.g. a large record), in id order."""
        column = f"json_remove(data, '$.{_field(without)}')" if without else "data"
        with self._lock:
            rows = self._db.execute(
                f"SELECT {column} FROM docs WHERE collection = ? AND id >= ? AND id < ? ORDER BY id",
                (collection, prefix, self._after(prefix)),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def ids_prefix(self, collection: str, prefix: str) -> list[str]:
        """The ids starting with `prefix`, sorted (nothing parsed)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM docs WHERE collection = ? AND id >= ? AND id < ? ORDER BY id",
                (collection, prefix, self._after(prefix)),
            ).fetchall()
        return [r[0] for r in rows]

    def list_where(self, collection: str, field: str, value: Any) -> list[dict[str, Any]]:
        """Documents whose top-level `field` equals `value`, filtered inside SQLite: only the matching ones are
        parsed here."""
        with self._lock:
            rows = self._db.execute(
                f"SELECT data FROM docs WHERE collection = ? AND json_extract(data, '$.{_field(field)}') = ? ORDER BY rowid",
                (collection, value),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    def project(self, collection: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
        """Only these fields of every document, read inside SQLite - several times cheaper than list() for counting
        over a large collection. A dotted name reads inside an object ("fields.severity"). Scalars only: SQLite gives
        booleans as 1/0, objects and arrays as JSON text; a missing field is None."""
        columns = ", ".join(f"json_extract(data, '$.{'.'.join(_field(p) for p in f.split('.'))}')" for f in fields)
        with self._lock:
            rows = self._db.execute(f"SELECT {columns} FROM docs WHERE collection = ? ORDER BY rowid",
                                    (collection,)).fetchall()
        return [dict(zip(fields, r)) for r in rows]

    def delete_many(self, collection: str, doc_ids: list[str]) -> int:
        with self._lock, self._db:
            cur = self._db.executemany("DELETE FROM docs WHERE collection = ? AND id = ?",
                                       [(collection, doc_id) for doc_id in doc_ids])
        return cur.rowcount

    def delete(self, collection: str, doc_id: str) -> bool:
        with self._lock, self._db:
            cur = self._db.execute("DELETE FROM docs WHERE collection = ? AND id = ?", (collection, doc_id))
        return cur.rowcount > 0

    # -- append-only streams -------------------------------------------------------

    def append(self, stream: str, data: dict[str, Any]) -> dict[str, Any]:
        ts = data.get("ts") or time.time()
        entry = {**data, "ts": ts}
        with self._lock, self._db:
            cur = self._db.execute(
                "INSERT INTO log (stream, ts, data) VALUES (?, ?, ?)",
                (stream, ts, json.dumps(entry, default=str)),
            )
        entry["seq"] = cur.lastrowid
        return entry

    def tail(self, stream: str, limit: int = 100, before: int | None = None) -> list[dict[str, Any]]:
        """The last `limit` entries of a stream, oldest first; with `before`, the last ones before that seq (paging)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, data FROM log WHERE stream = ? AND seq < ? ORDER BY seq DESC LIMIT ?",
                (stream, before if before is not None else 2**63 - 1, limit)
            ).fetchall()
        return [{**json.loads(data), "seq": seq} for seq, data in reversed(rows)]

    def prune(self, stream: str, keep: int) -> int:
        """Delete all but the newest `keep` entries of a stream; returns how many went."""
        with self._lock, self._db:
            cur = self._db.execute(
                "DELETE FROM log WHERE stream = ? AND seq < "
                "(SELECT seq FROM log WHERE stream = ? ORDER BY seq DESC LIMIT 1 OFFSET ?)",
                (stream, stream, max(keep, 1) - 1),
            )
        return cur.rowcount

    def count(self, stream: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM log WHERE stream = ?", (stream,)).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()
