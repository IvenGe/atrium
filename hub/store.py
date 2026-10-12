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


class Store:
    def __init__(self, path: Path | str):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        if str(path) != ":memory:":
            for suffix in ("", "-wal", "-shm"):
                file = Path(str(path) + suffix)
                if file.exists():
                    os.chmod(file, 0o600)
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

    def tail(self, stream: str, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, data FROM log WHERE stream = ? ORDER BY seq DESC LIMIT ?", (stream, limit)
            ).fetchall()
        return [{**json.loads(data), "seq": seq} for seq, data in reversed(rows)]

    def count(self, stream: str) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM log WHERE stream = ?", (stream,)).fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._db.close()
