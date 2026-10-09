"""Okta connector (Management API v1): reads the workforce directory into the People app, and each person's app
assignments (app links) as their accounts.

Checked against Okta's management OpenAPI spec (okta/okta-sdk-python openapi/api.yaml, October 2026):

- an API token is sent as "Authorization: SSWS <token>";
- GET /api/v1/users pages with `limit` (at most 200) and the Link header (rel="next" carries the `after` cursor);
  the plain list leaves out DEPROVISIONED users, so they are read with a second list, filter=status eq "DEPROVISIONED";
- user statuses: ACTIVE, PROVISIONED, STAGED, RECOVERY, PASSWORD_EXPIRED, LOCKED_OUT (all still employed: "active"),
  SUSPENDED ("suspended") and DEPROVISIONED ("terminated"); `lastLogin` is an ISO timestamp;
- profile: login, email, displayName, firstName, lastName, title, department, managerId, manager, city, countryCode,
  mobilePhone, primaryPhone;
- GET /api/v1/users/{id}/groups lists group objects (profile.name), GET /api/v1/users/{id}/appLinks the assigned apps
  (id, label, appName, appInstanceId, appAssignmentId);
- HTTP 429 when rate limited, with X-Rate-Limit-Reset (epoch seconds).

UNVERIFIED: `profile.managerId` is free text in Okta (often the manager's login or employee id, not their Okta id);
the hub resolves it against the manager's Okta id, login or email, whichever matches. Groups and app links cost one
call per user each: switch them off for very large directories.
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check, endpoint_of

API = "/api/v1"
PAGE = 200
MAX_RECORDS = 100_000
RETRIES = 3
PARALLEL = 4  # per-user calls (groups, app links) at once
ACTIVE = {"ACTIVE", "PROVISIONED", "STAGED", "RECOVERY", "PASSWORD_EXPIRED", "LOCKED_OUT"}
STATUS = {"SUSPENDED": "suspended", "DEPROVISIONED": "terminated"}


def person_status(okta_status: Any) -> str:
    return STATUS.get(str(okta_status or "").upper(), "active")


class OktaConnector(Connector):
    kind = "okta"
    title = "Okta"
    description = "Workforce directory: reads people (status, manager, groups) into the People app, and their app " \
                  "assignments as accounts."
    fields = [
        ConnectorField(name="base_url", label="Okta org URL", kind="url", required=True,
                       placeholder="https://your-org.okta.com", help="Your Okta domain (not the -admin address)."),
        ConnectorField(name="token", label="API token", kind="secret", required=True,
                       help="Okta Admin Console > Security > API > Tokens. A read-only administrator's token is "
                            "enough."),
        ConnectorField(name="include_groups", label="Read each person's groups", kind="bool", default=True,
                       help="One extra call per person."),
        ConnectorField(name="include_app_links", label="Read app assignments as accounts", kind="bool", default=True,
                       help="One extra call per person; turns on the accounts data flow."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
    ]
    capabilities = {"people": {"read"}, "accounts": {"read"}}
    system_of_record = {"people"}
    retry_cap: ClassVar[float] = 30.0

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("okta",), ("directory.users",))

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The Okta org URL must start with https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the API token in its own field, not in the URL")
        base = re.sub(r"(?i)/api(?:/v1)?$", "", base)
        return {**config, "base_url": re.sub(r"(?i)-admin\.(okta|oktapreview|okta-emea)\.com", r".\1.com", base)}

    def domains(self) -> dict[str, list[str]]:
        out = {"people": ["read"]}
        if self.config.get("include_app_links", True):
            out["accounts"] = ["read"]
        return out

    # -- HTTP ----------------------------------------------------------------------

    def client(self) -> httpx.AsyncClient:
        token = self.secrets.get("token")
        if not token:
            raise self.error("Enter the Okta API token in the connection settings")
        return self.http(str(self.config.get("base_url") or "").rstrip("/"),
                         headers={"Accept": "application/json", "Authorization": f"SSWS {token}"},
                         verify=bool(self.config.get("verify_tls", True)))

    def _wait(self, response: httpx.Response, attempt: int) -> float:
        reset = response.headers.get("x-rate-limit-reset", "").strip()
        wait = float(reset) - time.time() if reset.isdigit() else 2.0 * (attempt + 1)
        return max(0.0, min(wait, self.retry_cap))

    async def _get(self, client: httpx.AsyncClient, url: str, *, what: str, params: dict[str, Any] | None = None) -> httpx.Response:
        response: httpx.Response | None = None
        for attempt in range(RETRIES + 1):
            try:
                response = await client.get(url, params=params)
            except httpx.TimeoutException as exc:
                raise self.error(f"Okta did not answer in time ({what})") from exc
            except httpx.HTTPError as exc:
                raise self.error(f"Cannot reach Okta: {exc.__class__.__name__}: {exc}") from exc
            if response.status_code != 429 or attempt == RETRIES:
                break
            await asyncio.sleep(self._wait(response, attempt))
        assert response is not None
        self.raise_for_status(response, what)
        return response

    def _json(self, response: httpx.Response, what: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise self.error(f"Okta did not answer with JSON ({what}) - is the URL your Okta domain?",
                             status=response.status_code, excerpt=response.text) from exc

    async def _list(self, client: httpx.AsyncClient, path: str, params: dict[str, Any] | None, *, what: str,
                    pages: int | None = None) -> list[dict[str, Any]]:
        """Every item of a list endpoint, following the Link header - only on the org's own address, so the token
        never follows a link elsewhere."""
        own = endpoint_of(self.config.get("base_url"))
        url: str | None = f"{API}{path}"
        items: list[dict[str, Any]] = []
        fetched = 0
        while url:
            response = await self._get(client, url, what=what, params=params)
            page = self._json(response, what)
            if not isinstance(page, list):
                raise self.error(f"Unexpected answer from Okta ({what}): not a list")
            items.extend(i for i in page if isinstance(i, dict))
            fetched += 1
            if len(items) > MAX_RECORDS:
                raise self.error(f"Okta lists more than {MAX_RECORDS} items ({what}); the hub reads at most that many")
            following = (response.links.get("next") or {}).get("url")
            if not following or not page or (pages is not None and fetched >= pages):
                break
            if endpoint_of(following) != own:
                raise self.error("Okta's next-page link points to another address - refusing to send the token there")
            url, params = following, None  # the link carries the cursor and the filter
        return items

    async def _users(self, client: httpx.AsyncClient) -> list[dict[str, Any]]:
        users = await self._list(client, "/users", {"limit": PAGE}, what="list users")
        gone = await self._list(client, "/users", {"limit": PAGE, "filter": 'status eq "DEPROVISIONED"'},
                                what="list deprovisioned users")
        return list({str(u.get("id")): u for u in [*users, *gone] if u.get("id")}.values())

    async def _per_user(self, client: httpx.AsyncClient, users: list[dict[str, Any]], suffix: str,
                        what: str) -> dict[str, list[dict[str, Any]]]:
        limit = asyncio.Semaphore(PARALLEL)

        async def one(user_id: str) -> tuple[str, list[dict[str, Any]]]:
            async with limit:
                return user_id, await self._list(client, f"/users/{user_id}/{suffix}", None, what=what)

        pairs = await asyncio.gather(*(one(str(u["id"])) for u in users))
        return dict(pairs)

    # -- records -------------------------------------------------------------------

    @staticmethod
    def to_person(user: dict[str, Any], groups: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        p = user.get("profile") if isinstance(user.get("profile"), dict) else {}
        name = p.get("displayName") or " ".join(str(x) for x in (p.get("firstName"), p.get("lastName")) if x)
        return {
            "external_id": user.get("id"), "display_name": name or p.get("login"), "email": p.get("email"),
            "login": p.get("login"), "title": p.get("title"), "department": p.get("department"),
            "manager_external_id": p.get("managerId") or p.get("manager"), "status": person_status(user.get("status")),
            "groups": [(g.get("profile") or {}).get("name") for g in groups or [] if isinstance(g.get("profile"), dict)],
            "location": ", ".join(str(x) for x in (p.get("city"), p.get("countryCode")) if x) or None,
            "phone": p.get("mobilePhone") or p.get("primaryPhone"),
        }

    @staticmethod
    def to_accounts(user: dict[str, Any], links: list[dict[str, Any]]) -> list[dict[str, Any]]:
        p = user.get("profile") if isinstance(user.get("profile"), dict) else {}
        active = str(user.get("status") or "").upper() in ACTIVE
        out = []
        for link in links:
            key = link.get("appAssignmentId") or link.get("appInstanceId") or link.get("id")
            if not key:
                continue
            out.append({"external_id": f"{user.get('id')}:{key}", "login": p.get("login"), "email": p.get("email"),
                        "display_name": p.get("displayName") or p.get("login"), "active": active,
                        "last_login": user.get("lastLogin"), "app": link.get("label") or link.get("appName")})
        return out

    # -- operations ----------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        domains: dict[str, list[str]] = {}
        try:
            client = self.client()
        except ConnectorError as exc:
            return self._result([check("API token", False, exc.message)], domains)
        async with client:
            try:
                me = self._json(await self._get(client, f"{API}/users/me", what="read the token's account"), "users/me")
                login = (me.get("profile") or {}).get("login") if isinstance(me, dict) else None
                checks.append(check("API token", True, f"accepted - acting as {login}" if login else "accepted"))
            except ConnectorError as exc:
                name = "API token" if exc.status in (401, 403) else "Connection"
                return self._result([check(name, False, exc.message)], domains)
            try:
                sample = await self._list(client, "/users", {"limit": 25}, what="list users", pages=1)
                checks.append(check("Read users", True, f"{len(sample)} user(s) on the first page" if sample else
                                    "no users visible to this token"))
                domains["people"] = ["read"]
            except ConnectorError as exc:
                return self._result(checks + [check("Read users", False, exc.message)], domains)
            if sample and (self.config.get("include_groups", True) or self.config.get("include_app_links", True)):
                first = str(sample[0]["id"])
                for key, suffix, label in (("include_groups", "groups", "Read groups"),
                                           ("include_app_links", "appLinks", "Read app assignments")):
                    if not self.config.get(key, True):
                        continue
                    try:
                        found = await self._list(client, f"/users/{first}/{suffix}", None, what=label.lower())
                        checks.append(check(label, True, f"{len(found)} for the first user"))
                        if suffix == "appLinks":
                            domains["accounts"] = ["read"]
                    except ConnectorError as exc:
                        checks.append(check(label, False, exc.message))
            elif self.config.get("include_app_links", True):
                domains["accounts"] = ["read"]
        return self._result(checks, domains)

    @staticmethod
    def _result(checks: list[dict[str, Any]], domains: dict[str, list[str]]) -> dict[str, Any]:
        failed = [c for c in checks if not c["ok"]]
        detail = f"{failed[0]['name']}: {failed[0]['detail']}" if failed else "Connected to Okta"
        return {"ok": bool(checks) and not failed, "detail": detail, "checks": checks, "domains": domains}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain not in self.domains():
            raise self.error(f"Okta cannot read {domain} with these settings")
        async with self.client() as client:
            users = await self._users(client)
            if domain == "people":
                groups = await self._per_user(client, users, "groups", "list a user's groups") \
                    if self.config.get("include_groups", True) else {}
                return [self.to_person(u, groups.get(str(u["id"]))) for u in users]
            links = await self._per_user(client, [u for u in users if str(u.get("status")).upper() != "DEPROVISIONED"],
                                         "appLinks", "list a user's app assignments")
            return [a for u in users for a in self.to_accounts(u, links.get(str(u["id"]), []))]
