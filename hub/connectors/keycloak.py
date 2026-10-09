"""Keycloak admin API connector: reads a realm's users (enabled or not, with their groups) into the People app.

Checked against Keycloak's admin REST API OpenAPI document (keycloak.org/docs-api/latest/rest-api/openapi.json,
October 2026):

- a service-account client gets a token with the client-credentials grant at
  {base}/realms/{token realm}/protocol/openid-connect/token (client_id and client_secret in the form);
- GET {base}/admin/realms/{realm}/users pages with `first` / `max` (the hub sends max explicitly and stops at a short
  page) and briefRepresentation=false; a user has id, username, email, firstName, lastName, enabled, attributes,
  createdTimestamp; GET /users/count counts them;
- GET {base}/admin/realms/{realm}/users/{id}/groups lists the user's groups (name, path).

The service account needs the realm-management roles view-users (and query-groups). Keycloak before version 17 serves
everything under /auth: put that in the URL. Keycloak has no "terminated" state: a disabled user is "suspended", and a
user deleted from the realm disappears from the pull (the hub then records the person as having left that directory).

UNVERIFIED: title, department, manager, phone and location come from user attributes, which are not standardised in
Keycloak; the hub reads the common names (title / jobTitle, department, manager, phoneNumber / phone, location / city).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .base import Connector, ConnectorError, ConnectorField, check

PAGE = 100
MAX_RECORDS = 100_000
REALM_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _attr(attributes: Any, *names: str) -> str | None:
    if not isinstance(attributes, dict):
        return None
    for name in names:
        value = attributes.get(name)
        if isinstance(value, list):
            value = next((v for v in value if v not in (None, "")), None)
        if value not in (None, ""):
            return str(value)
    return None


class KeycloakConnector(Connector):
    kind = "keycloak"
    title = "Keycloak (admin API)"
    description = "Identity provider directory: reads a realm's users, their groups and whether they are enabled " \
                  "into the People app."
    fields = [
        ConnectorField(name="base_url", label="Keycloak URL", kind="url", required=True,
                       placeholder="https://keycloak.example.com",
                       help="Keycloak's address (add /auth for Keycloak 16 and older)."),
        ConnectorField(name="realm", label="Realm", required=True, placeholder="company",
                       help="The realm whose users are read."),
        ConnectorField(name="client_id", label="Client ID", required=True, placeholder="atrium-directory",
                       help="A confidential client with service accounts enabled and the realm-management roles "
                            "view-users and query-groups."),
        ConnectorField(name="client_secret", label="Client secret", kind="secret", required=True),
        ConnectorField(name="token_realm", label="Realm of the client (if not the same)", placeholder="master",
                       help="Leave empty when the client lives in the realm above."),
        ConnectorField(name="include_groups", label="Read each person's groups", kind="bool", default=True,
                       help="One extra call per person."),
        ConnectorField(name="verify_tls", label="Verify TLS certificate", kind="bool", default=True),
    ]
    capabilities = {"people": {"read"}}
    system_of_record = {"people"}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("keycloak",), (), score=70)

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        base = str(config.get("base_url") or "").strip().rstrip("/")
        parts = urlsplit(base)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConnectorError("The Keycloak URL must start with http:// or https://")
        if parts.username or parts.password or parts.query or parts.fragment:
            raise ConnectorError("Put the client secret in its own field, not in the URL")
        base = re.sub(r"/(?:admin|realms)(?:/.*)?$", "", base)
        for key in ("realm", "token_realm"):
            value = str(config.get(key) or "").strip()
            if value and not REALM_RE.match(value):
                raise ConnectorError(f"The {key.replace('_', ' ')} name has characters Keycloak realm names do not use")
        return {**config, "base_url": base}

    # -- HTTP ----------------------------------------------------------------------

    def _base(self) -> str:
        return str(self.config.get("base_url") or "").rstrip("/")

    def _realm(self) -> str:
        return quote(str(self.config.get("realm") or ""), safe="")

    async def _call(self, client: httpx.AsyncClient, method: str, url: str, *, what: str, **kwargs: Any) -> Any:
        return await self.request_json(client, method, url, what=what, **kwargs)

    async def client(self) -> httpx.AsyncClient:
        """An HTTP client carrying a fresh service-account access token."""
        secret = self.secrets.get("client_secret")
        if not secret:
            raise self.error("Enter the client secret in the connection settings")
        verify = bool(self.config.get("verify_tls", True))
        token_realm = quote(str(self.config.get("token_realm") or self.config.get("realm") or ""), safe="")
        async with self.http(self._base(), verify=verify) as plain:
            try:
                answer = await self._call(plain, "POST", f"/realms/{token_realm}/protocol/openid-connect/token",
                                          what="get a service-account token",
                                          data={"grant_type": "client_credentials",
                                                "client_id": str(self.config.get("client_id") or ""),
                                                "client_secret": secret})
            except ConnectorError as exc:
                if exc.status in (400, 401):
                    raise self.error("Keycloak refused the client credentials - check the client ID and secret, and "
                                     "that the client has service accounts enabled", status=exc.status,
                                     excerpt=exc.excerpt) from exc
                raise
        token = answer.get("access_token") if isinstance(answer, dict) else None
        if not isinstance(token, str) or not token:
            raise self.error("Keycloak's token answer has no access_token")
        self.secrets["access_token"] = token  # masked in every error message from here on
        return self.http(self._base(), verify=verify,
                         headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})

    async def _users(self, client: httpx.AsyncClient, pages: int | None = None) -> list[dict[str, Any]]:
        users: list[dict[str, Any]] = []
        first, fetched = 0, 0
        while True:
            page = await self._call(client, "GET", f"/admin/realms/{self._realm()}/users", what="list users",
                                    params={"first": first, "max": PAGE, "briefRepresentation": "false"})
            if not isinstance(page, list):
                raise self.error("Unexpected answer from Keycloak (list users): not a list")
            users.extend(u for u in page if isinstance(u, dict) and u.get("id"))
            first, fetched = first + len(page), fetched + 1
            if len(users) > MAX_RECORDS:
                raise self.error(f"Keycloak lists more than {MAX_RECORDS} users; the hub reads at most that many")
            if len(page) < PAGE or (pages is not None and fetched >= pages):
                return users

    async def _groups(self, client: httpx.AsyncClient, user_id: str) -> list[str]:
        found = await self._call(client, "GET", f"/admin/realms/{self._realm()}/users/{quote(user_id, safe='')}/groups",
                                 what="list a user's groups", params={"max": 1000})
        return [str(g.get("name") or g.get("path") or "") for g in found or [] if isinstance(g, dict)]

    def _forbidden(self, exc: ConnectorError) -> ConnectorError:
        if exc.status == 403:
            return self.error("Keycloak refused to list users (HTTP 403) - give the client's service account the "
                              "realm-management roles view-users and query-groups", status=403, excerpt=exc.excerpt)
        if exc.status == 404:
            return self.error(f"Keycloak has no realm '{self.config.get('realm')}' at this address (HTTP 404) - check "
                              "the realm, and add /auth to the URL for Keycloak 16 and older", status=404)
        return exc

    @staticmethod
    def to_person(user: dict[str, Any], groups: list[str] | None = None) -> dict[str, Any]:
        attributes = user.get("attributes")
        name = " ".join(str(x) for x in (user.get("firstName"), user.get("lastName")) if x)
        return {
            "external_id": user.get("id"), "display_name": name or user.get("username"), "email": user.get("email"),
            "login": user.get("username"), "title": _attr(attributes, "title", "jobTitle", "job_title"),
            "department": _attr(attributes, "department"), "manager_external_id": _attr(attributes, "manager"),
            "status": "active" if user.get("enabled", True) else "suspended", "groups": groups or [],
            "location": _attr(attributes, "location", "city"), "phone": _attr(attributes, "phoneNumber", "phone"),
        }

    # -- operations ----------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []
        domains: dict[str, list[str]] = {}
        try:
            client = await self.client()
        except ConnectorError as exc:
            return self._result([check("Service-account token", False, exc.message)], domains)
        checks.append(check("Service-account token", True, f"issued to {self.config.get('client_id')}"))
        async with client:
            try:
                count = await self._call(client, "GET", f"/admin/realms/{self._realm()}/users/count", what="count users")
                users = await self._users(client, pages=1)
                checks.append(check("Read users", True, f"{count if isinstance(count, int) else len(users)} user(s) in "
                                                        f"realm {self.config.get('realm')}"))
                domains["people"] = ["read"]
            except ConnectorError as exc:
                return self._result(checks + [check("Read users", False, self._forbidden(exc).message)], domains)
            if users and self.config.get("include_groups", True):
                try:
                    groups = await self._groups(client, str(users[0]["id"]))
                    checks.append(check("Read groups", True, f"{len(groups)} group(s) for the first user"))
                except ConnectorError as exc:
                    checks.append(check("Read groups", False, exc.message + " - add the query-groups role, or switch "
                                                                            "groups off"))
        return self._result(checks, domains)

    @staticmethod
    def _result(checks: list[dict[str, Any]], domains: dict[str, list[str]]) -> dict[str, Any]:
        failed = [c for c in checks if not c["ok"]]
        detail = f"{failed[0]['name']}: {failed[0]['detail']}" if failed else "Connected to Keycloak"
        return {"ok": bool(checks) and not failed, "detail": detail, "checks": checks, "domains": domains}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "people":
            raise self.error(f"Keycloak cannot read {domain} (only people)")
        async with await self.client() as client:
            try:
                users = await self._users(client)
            except ConnectorError as exc:
                raise self._forbidden(exc) from exc
            out = []
            for user in users:
                groups = await self._groups(client, str(user["id"])) if self.config.get("include_groups", True) else []
                out.append(self.to_person(user, groups))
            return out
