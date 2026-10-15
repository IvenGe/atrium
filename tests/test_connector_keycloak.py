"""The Keycloak admin API connector against a fake Keycloak (httpx.MockTransport, no network): the client-credentials
token, first/max paging, groups and enabled -> status."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.keycloak import PAGE, KeycloakConnector
from hub.integration.connections import clean_config

SECRET = "kc-client-secret-0123456789"
ACCESS = "eyJhbGciOiJSUzI1NiJ9.access-token-value"
BASE = "https://kc.example.com"


def run(coro):
    return asyncio.run(coro)


class FakeKeycloak:
    def __init__(self, count: int, prefix: str = ""):
        self.users = [{"id": f"u{i:03}", "username": f"user{i}", "email": f"user{i}@acme.com", "firstName": "User",
                       "lastName": str(i), "enabled": i % 10 != 3, "createdTimestamp": 1700000000000,
                       "attributes": {"department": ["Sales"], "title": ["Rep"]} if i == 1 else {}} for i in range(count)]
        self.prefix = prefix
        self.calls: list[httpx.Request] = []
        self.forbid = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path.removeprefix(self.prefix)
        if path == "/realms/master/protocol/openid-connect/token" or path == "/realms/acme/protocol/openid-connect/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            if form != {"grant_type": "client_credentials", "client_id": "atrium-directory", "client_secret": SECRET}:
                return httpx.Response(401, json={"error": "unauthorized_client", "error_description": "Invalid client"})
            return httpx.Response(200, json={"access_token": ACCESS, "expires_in": 60, "token_type": "Bearer"})
        if request.headers.get("Authorization") != f"Bearer {ACCESS}":
            return httpx.Response(401, json={"error": "HTTP 401 Unauthorized"})
        if self.forbid:
            return httpx.Response(403, json={"error": "HTTP 403 Forbidden"})
        params = dict(request.url.params)
        if path == "/admin/realms/acme/users/count":
            return httpx.Response(200, json=len(self.users))
        if path == "/admin/realms/acme/users":
            first, size = int(params.get("first", 0)), int(params.get("max", 100))
            assert params.get("briefRepresentation") == "false"
            return httpx.Response(200, json=self.users[first:first + size])
        parts = path.strip("/").split("/")
        if parts[:4] == ["admin", "realms", "acme", "users"] and parts[-1] == "groups":
            return httpx.Response(200, json=[{"id": "g1", "name": "staff", "path": "/staff"}] if parts[4] == "u001" else [])
        return httpx.Response(404, json={"error": "Realm not found."})


def connector(fake: Any, **config: Any) -> KeycloakConnector:
    cfg = clean_config(KeycloakConnector, {"base_url": BASE, "realm": "acme", "client_id": "atrium-directory", **config})
    return KeycloakConnector(cfg, {"client_secret": SECRET}, httpx.MockTransport(fake))


def test_registry_and_settings():
    assert connectors.connector_class("keycloak") is KeycloakConnector
    cfg = clean_config(KeycloakConnector, {"base_url": "https://kc.example.com/admin/master/console/", "realm": "acme",
                                           "client_id": "x"})
    assert cfg["base_url"] == "https://kc.example.com"
    with pytest.raises(ValueError):
        clean_config(KeycloakConnector, {"base_url": BASE, "realm": "acme/../master", "client_id": "x"})


def test_users_are_paged_with_first_and_max_and_mapped():
    fake = FakeKeycloak(PAGE + 5)
    records, errors = normalize("people", run(connector(fake).pull("people")))
    assert not errors and len(records) == PAGE + 5
    pages = [dict(r.url.params) for r in fake.calls if r.url.path == "/admin/realms/acme/users"]
    assert [(p["first"], p["max"]) for p in pages] == [("0", str(PAGE)), (str(PAGE), str(PAGE))]
    by_id = {r["external_id"]: r for r in records}
    one = by_id["u001"]
    assert (one["display_name"], one["login"], one["email"], one["status"]) == ("User 1", "user1", "user1@acme.com", "active")
    assert (one["department"], one["title"], one["groups"]) == ("Sales", "Rep", ["staff"])
    assert by_id["u003"]["status"] == "suspended" and by_id["u013"]["status"] == "suspended"
    token_calls = [r for r in fake.calls if r.url.path.endswith("/token")]
    assert len(token_calls) == 1 and token_calls[0].url.path == "/realms/acme/protocol/openid-connect/token"


def test_a_client_in_another_realm_and_an_old_auth_prefix():
    fake = FakeKeycloak(3, prefix="/auth")
    records = run(connector(fake, base_url=f"{BASE}/auth", token_realm="master", include_groups=False).pull("people"))
    assert len(records) == 3 and fake.calls[0].url.path == "/auth/realms/master/protocol/openid-connect/token"


def test_wrong_secret_and_missing_roles_are_explained_without_secrets():
    bad = KeycloakConnector(clean_config(KeycloakConnector, {"base_url": BASE, "realm": "acme", "client_id": "atrium-directory"}),
                            {"client_secret": "not-the-secret-123"}, httpx.MockTransport(FakeKeycloak(1)))
    result = run(bad.test())
    assert not result["ok"] and "check the client ID and secret" in result["detail"]
    assert "not-the-secret-123" not in json.dumps(result)
    fake = FakeKeycloak(2)
    fake.forbid = True
    result = run(connector(fake).test())
    assert not result["ok"] and "view-users" in result["detail"] and ACCESS not in json.dumps(result)
    with pytest.raises(ConnectorError) as info:
        run(connector(fake).pull("people"))
    assert "view-users" in info.value.message


def test_test_counts_users_and_checks_groups():
    result = run(connector(FakeKeycloak(4)).test())
    assert result["ok"] and result["domains"] == {"people": ["read"]}
    assert [c["name"] for c in result["checks"]] == ["Service-account token", "Read users", "Read groups"]
    assert "4 user(s) in realm acme" in result["checks"][1]["detail"]
