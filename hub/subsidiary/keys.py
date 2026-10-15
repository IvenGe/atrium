"""Each subsidiary's Ed25519 signing keys - they sign its tickets and grants - in the "subsidiary_keys" collection.

The private key is encrypted with the hub's secret key (hub.secrets, Fernet), never returned by the API, never logged,
and masked wherever hub secrets are (secrets.hub_secret_values). The bridge holds only the public keys, published in
the public bridge.env as ATRIUM_BRIDGE_KEYS ("current" first, then "next").

Rotation is staged: stage() adds a "next" key that bridge.env lists after the current one; once the tool runs with that
file, finish() makes it current and retires the old one (its private part is erased). rotate_now() - when a
subsidiary is stopped - replaces both at once, so the deployed bridge.env no longer matches and the bridge refuses
every new ticket.
"""

from __future__ import annotations

import hashlib
import time
from typing import TYPE_CHECKING, Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..secrets import SecretError
from . import contract
from .models import COLLECTIONS, KeyRecord

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = COLLECTIONS["keys"]


def kid_of(public: str) -> str:
    """A key's id: the first 16 hex digits of the SHA-256 of its raw public bytes."""
    return hashlib.sha256(contract.b64u_decode(public)).hexdigest()[:16]


def records(hub: "Hub", sub_id: str) -> list[KeyRecord]:
    return sorted((KeyRecord.model_validate(d) for d in hub.store.list_prefix(COLLECTION, f"{sub_id}:")),
                  key=lambda r: r.created_at)


def _with(hub: "Hub", sub_id: str, status: str) -> KeyRecord | None:
    return next((r for r in records(hub, sub_id) if r.status == status), None)


def current(hub: "Hub", sub_id: str) -> KeyRecord | None:
    return _with(hub, sub_id, "current")


def staged(hub: "Hub", sub_id: str) -> KeyRecord | None:
    return _with(hub, sub_id, "next")


def _add(hub: "Hub", sub_id: str, status: str) -> KeyRecord:
    key = contract.new_key()
    public = contract.public_b64(key)
    record = KeyRecord(id=f"{sub_id}:{kid_of(public)}", subsidiary_id=sub_id, kid=kid_of(public),
                       private=hub.secrets.encrypt(contract.private_b64(key)), public=public, status=status)
    hub.store.put(COLLECTION, record.model_dump(mode="json"))
    return record


def _retire(hub: "Hub", record: KeyRecord) -> None:
    record.status, record.private, record.retired_at = "retired", "", time.time()
    hub.store.put(COLLECTION, record.model_dump(mode="json"))


def ensure(hub: "Hub", sub_id: str) -> KeyRecord:
    """The current key, created on first use."""
    return current(hub, sub_id) or _add(hub, sub_id, "current")


def public_keys(hub: "Hub", sub_id: str) -> list[str]:
    """What bridges accept: the current key, then the staged one."""
    return [r.public for r in (current(hub, sub_id), staged(hub, sub_id)) if r is not None]


def bridge_keys(hub: "Hub", sub_id: str) -> str:
    """The value of ATRIUM_BRIDGE_KEYS in bridge.env."""
    return ",".join(public_keys(hub, sub_id))


def signer(hub: "Hub", sub_id: str) -> Ed25519PrivateKey:
    """The current private key, decrypted for one signature (LookupError when there is none)."""
    record = current(hub, sub_id)
    if record is None or not record.private:
        raise LookupError(f"subsidiary {sub_id} has no signing key")
    return contract.private_key(hub.secrets.decrypt(record.private))


def stage(hub: "Hub", sub_id: str) -> KeyRecord:
    """Add the next key (idempotent: an already staged key is returned)."""
    ensure(hub, sub_id)
    return staged(hub, sub_id) or _add(hub, sub_id, "next")


def finish(hub: "Hub", sub_id: str) -> KeyRecord:
    """The staged key becomes current; the old one is retired (ValueError when nothing is staged)."""
    nxt, cur = staged(hub, sub_id), current(hub, sub_id)
    if nxt is None:
        raise ValueError("No key is staged: stage the next key first.")
    if cur is not None:
        _retire(hub, cur)
    nxt.status = "current"
    hub.store.put(COLLECTION, nxt.model_dump(mode="json"))
    return nxt


def rotate_now(hub: "Hub", sub_id: str) -> KeyRecord:
    """Retire every key and make a new current one, without staging."""
    for record in records(hub, sub_id):
        if record.status != "retired":
            _retire(hub, record)
    return _add(hub, sub_id, "current")


def retire_all(hub: "Hub", sub_id: str) -> int:
    count = 0
    for record in records(hub, sub_id):
        if record.status != "retired":
            _retire(hub, record)
            count += 1
    return count


def issue_ticket(hub: "Hub", sub_id: str, **fields: Any) -> tuple[str, dict[str, Any]]:
    """A ticket signed with the subsidiary's current key (fields: contract.make_ticket's)."""
    return contract.make_ticket(signer(hub, sub_id), sub=sub_id, **fields)


def issue_grant(hub: "Hub", sub_id: str, **fields: Any) -> tuple[str, dict[str, Any]]:
    """A grant signed with the subsidiary's current key (fields: contract.make_grant's)."""
    return contract.make_grant(signer(hub, sub_id), sub=sub_id, **fields)


def secret_values(hub: "Hub") -> list[str]:
    """Every signing key's private value this hub holds, for masking text that leaves its control."""
    values = []
    for doc in hub.store.list(COLLECTION):
        if doc.get("private"):
            try:
                values.append(hub.secrets.decrypt(doc["private"]))
            except (SecretError, TypeError):  # a key that cannot be decrypted cannot leak either
                continue
    return values
