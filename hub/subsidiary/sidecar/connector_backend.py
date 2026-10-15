"""Sidecar-only mode (6.7): the team reads the tool through its API with a dedicated, read-only credential.

At start the sidecar fetches the credential once (``GET /credential``: the connector kind, its non-secret settings and
the secret values) and keeps it in memory only - never in the state directory, the spool or the log. Reads
(``act__records-<domain>-list``) run here with ``hub.connectors.build``; writes (``records.<domain>.upsert``) are always
approvals, carried out in Atrium by the Tool Supervisor with the hub's own connection. K1 of the conformance checks is
the connector's own test with this credential.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from ... import connectors
from ...connectors.base import redact
from ..models import CredentialResponse

LIST_RE = re.compile(r"^records\.([a-z][a-z0-9_]{0,40})\.list$")
MAX_RECORDS = 50
# mirrors hub.integration.flows.SECRET_KEY / sanitize (flows pulls in the store, which the sidecar never imports)
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|credential)")


def sanitize(value: Any, secrets: dict[str, str] | list[str] | None = None, depth: int = 0) -> Any:
    """A value safe to hand a model: secret-looking keys masked, secret values redacted, long values and lists cut
    short (as flows.sanitize)."""
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(k): "***" if SECRET_KEY.search(str(k)) else sanitize(v, secrets, depth + 1)
                for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, secrets, depth + 1) for v in list(value)[:3]]
    if isinstance(value, str):
        return redact(value, secrets)[:500]
    return value


class ConnectorBackend:
    def __init__(self, credential: CredentialResponse, *, transport: httpx.AsyncBaseTransport | None = None):
        self.kind = credential.kind
        self.secrets = dict(credential.secrets)
        self.connector = connectors.build(credential.kind, dict(credential.config), self.secrets, transport)

    def values(self) -> list[str]:
        return [v for v in self.secrets.values() if isinstance(v, str)]

    async def test(self) -> tuple[bool, str]:
        """K1: the connector's own test with the dedicated credential -> (ok, a short detail without secrets)."""
        try:
            answer = await self.connector.test()
        except Exception as exc:
            return False, redact(f"the test failed ({exc.__class__.__name__}: {exc})", self.secrets)[:300]
        ok = bool(answer.get("ok"))
        return ok, redact(str(answer.get("detail") or ("passed" if ok else "failed")), self.secrets)[:300]

    async def list(self, action_id: str, params: dict[str, Any]) -> dict[str, Any]:
        """records.<domain>.list: the domain's records, normalized by the connector, at most 50 (or `limit`), each
        sanitized. `q` keeps the records whose text contains it."""
        found = LIST_RE.match(action_id)
        if found is None:
            raise ValueError(f"{action_id} is not a records list action")
        domain = found.group(1)
        if "read" not in self.connector.domains().get(domain, []):
            raise ValueError(f"the connector does not read {domain}")
        records = await self.connector.pull(domain)
        query = str(params.get("q") or "").lower()
        if query:
            records = [r for r in records if query in json.dumps(r, default=str, ensure_ascii=False).lower()]
        limit = params.get("limit")
        limit = max(1, min(MAX_RECORDS, limit)) if isinstance(limit, int) and not isinstance(limit, bool) \
            else MAX_RECORDS
        return {"domain": domain, "count": len(records),
                "records": [sanitize(r, self.secrets) for r in records[:limit]]}
