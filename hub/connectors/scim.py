"""Generic SCIM 2.0 connector (RFC 7643 / RFC 7644): reads /Users into the People app - or, for an application's own
SCIM endpoint, as that application's user accounts.

- "Authorization: Bearer <token>", Accept application/scim+json;
- GET {base}/Users?startIndex=1&count=N answers a ListResponse (totalResults, startIndex, itemsPerPage, Resources);
  startIndex is 1-based and a server may return fewer than `count` items, so the next startIndex follows the items
  actually received;
- a User: id, userName, name {formatted, givenName, familyName}, displayName, title, emails [{value, primary}],
  phoneNumbers, addresses [{locality}], active, groups [{value, display}], and the enterprise extension
  urn:ietf:params:scim:schemas:extension:enterprise:2.0:User {department, manager {value}}.

Lenient where servers differ: "resources" in lower case is accepted, a missing `active` means active, and a server
that ignores paging (everything on the first page) is read once.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check

ENTERPRISE = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
MAX_RECORDS = 100_000
DEFAULT_PAGE = 100


def _primary(items: Any, key: str = "value") -> str | None:
    if not isinstance(items, list):
        return None
    entries = [i for i in items if isinstance(i, dict) and i.get(key)]
    chosen = next((i for i in entries if i.get("primary")), entries[0] if entries else None)
    return str(chosen[key]) if chosen else None


class ScimConnector(Connector):
    kind = "scim"
    title = "SCIM 2.0"
    description = "Any SCIM 2.0 service provider: reads its users into the People app, or as the tool's accounts."
    fields = [
        ConnectorField(name="base_url", label="SCIM base URL", kind="url", required=True,
                       placeholder="https://example.com/scim/v2", help="The URL the /Users endpoint lives under."),
        ConnectorField(name="token", label="Bearer token", kind="secret", required=True),
        ConnectorField(name="use_as", label="The users are", kind="select", default="people", choices=[
            {"value": "people", "label": "People (a directory or HR system)"},
            {"value": "accounts", "label": "Accounts of this tool"}]),
        ConnectorField(name="page_size", label="Page size", kind="number", default=DEFAULT_PAGE),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
    ]
    capabilities = {"people": {"read"}, "accounts": {"read"}}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("scim",), ("scim", "provisioning.scim"), score=40)

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The SCIM base URL must start with http:// or https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the token in its own field, not in the URL")
        if base.lower().endswith("/users"):
            base = base[:-6]
        try:
            size = int(config.get("page_size") or DEFAULT_PAGE)
        except (TypeError, ValueError) as exc:
            raise ConnectorError("The page size must be a number") from exc
        if config.get("use_as", "people") not in ("people", "accounts"):
            raise ConnectorError("The users are 'people' or 'accounts'")
        return {**config, "base_url": base, "page_size": max(1, min(size, 1000))}

    def domains(self) -> dict[str, list[str]]:
        return {str(self.config.get("use_as") or "people"): ["read"]}

    def client(self) -> httpx.AsyncClient:
        token = self.secrets.get("token")
        if not token:
            raise self.error("Enter the SCIM bearer token in the connection settings")
        return self.http(str(self.config.get("base_url") or "").rstrip("/"),
                         headers={"Accept": "application/scim+json, application/json", "Authorization": f"Bearer {token}"},
                         verify=bool(self.config.get("verify_tls", True)))

    async def _users(self, client: httpx.AsyncClient, pages: int | None = None) -> tuple[list[dict[str, Any]], int | None]:
        size = int(self.config.get("page_size") or DEFAULT_PAGE)
        users: list[dict[str, Any]] = []
        start, fetched, total = 1, 0, None
        seen: set[str] = set()
        while True:
            answer = await self.request_json(client, "GET", "/Users", what="list users",
                                             params={"startIndex": start, "count": size})
            if not isinstance(answer, dict):
                raise self.error("Unexpected answer from the SCIM server (list users): not a ListResponse")
            page = answer.get("Resources", answer.get("resources")) or []
            if not isinstance(page, list):
                raise self.error("Unexpected answer from the SCIM server (list users): Resources is not a list")
            fresh = [u for u in page if isinstance(u, dict) and u.get("id") and str(u["id"]) not in seen]
            if page and not fresh and fetched:
                raise self.error("The SCIM server answered the same users again - it seems to ignore startIndex")
            seen.update(str(u["id"]) for u in fresh)
            users.extend(fresh)
            fetched += 1
            try:
                total = int(answer.get("totalResults"))
            except (TypeError, ValueError):
                total = None
            if len(users) > MAX_RECORDS:
                raise self.error(f"The SCIM server lists more than {MAX_RECORDS} users; the hub reads at most that many")
            served_all = total is not None and len(page) >= total  # a server that ignores paging
            if not page or served_all or (total is not None and start - 1 + len(page) >= total) \
                    or (total is None and len(page) < size) or (pages is not None and fetched >= pages):
                return users, total
            start += len(page)

    @staticmethod
    def to_person(user: dict[str, Any]) -> dict[str, Any]:
        name = user.get("name") if isinstance(user.get("name"), dict) else {}
        enterprise = user.get(ENTERPRISE) if isinstance(user.get(ENTERPRISE), dict) else {}
        manager = enterprise.get("manager")
        display = user.get("displayName") or name.get("formatted") or " ".join(
            str(x) for x in (name.get("givenName"), name.get("familyName")) if x)
        addresses = user.get("addresses") if isinstance(user.get("addresses"), list) else []
        return {
            "external_id": user.get("id"), "display_name": display or user.get("userName"),
            "email": _primary(user.get("emails")), "login": user.get("userName"), "title": user.get("title"),
            "department": enterprise.get("department"),
            "manager_external_id": manager.get("value") if isinstance(manager, dict) else manager,
            "status": "active" if user.get("active", True) not in (False, "false", "False") else "suspended",
            "groups": [g.get("display") or g.get("value") for g in user.get("groups") or [] if isinstance(g, dict)],
            "location": next((a.get("locality") for a in addresses if isinstance(a, dict) and a.get("locality")), None),
            "phone": _primary(user.get("phoneNumbers")),
        }

    @classmethod
    def to_account(cls, user: dict[str, Any]) -> dict[str, Any]:
        person = cls.to_person(user)
        meta = user.get("meta") if isinstance(user.get("meta"), dict) else {}
        return {"external_id": person["external_id"], "login": person["login"], "email": person["email"],
                "display_name": person["display_name"], "active": person["status"] == "active",
                "last_login": meta.get("lastLogin")}

    async def test(self) -> dict[str, Any]:
        domains: dict[str, list[str]] = {}
        try:
            client = self.client()
        except ConnectorError as exc:
            return self._result([check("Token", False, exc.message)], domains)
        async with client:
            try:
                users, total = await self._users(client, pages=1)
            except ConnectorError as exc:
                name = "Token" if exc.status in (401, 403) else "Read users"
                return self._result([check(name, False, exc.message)], domains)
        domains.update(self.domains())
        what = "people" if self.config.get("use_as", "people") == "people" else "accounts"
        count = total if total is not None else len(users)
        return self._result([check("Token", True, "accepted"),
                             check("Read users", True, f"{count} user(s), read as {what}")], domains)

    @staticmethod
    def _result(checks: list[dict[str, Any]], domains: dict[str, list[str]]) -> dict[str, Any]:
        failed = [c for c in checks if not c["ok"]]
        detail = f"{failed[0]['name']}: {failed[0]['detail']}" if failed else "Connected to the SCIM server"
        return {"ok": bool(checks) and not failed, "detail": detail, "checks": checks, "domains": domains}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain not in self.domains():
            raise self.error(f"This SCIM connection reads {next(iter(self.domains()))}, not {domain}")
        async with self.client() as client:
            users, _ = await self._users(client)
        return [self.to_person(u) if domain == "people" else self.to_account(u) for u in users]
