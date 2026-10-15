"""Provider adapters: the only code that builds provider request bodies or reads their answers."""

from __future__ import annotations

import hashlib
import os
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...core import Hub

INSTALL_ID_DOC = "llm_install_id"


def cloud_off() -> bool:
    """HUB_LLM=off switches the cloud providers (Anthropic, OpenAI) off; local model servers keep working."""
    return os.environ.get("HUB_LLM", "").strip().lower() == "off"


def safety_id(hub: "Hub", person: str | None) -> str | None:
    """A stable, salted hash of the person who asked (for the providers' abuse detection): never a name or email."""
    if not person:
        return None
    doc = hub.store.get("settings", INSTALL_ID_DOC)
    if doc is None:
        doc = hub.store.put("settings", {"id": INSTALL_ID_DOC, "value": secrets.token_hex(16)})
    return hashlib.sha256(f"{doc['value']}|{person}".encode()).hexdigest()[:32]


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4) if text else 0
