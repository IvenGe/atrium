"""The generic SCIM 2.0 connector against a fake SCIM service provider (httpx.MockTransport, no network)."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.scim import ENTERPRISE, ScimConnector
from hub.integration.connections import clean_config

TOKEN = "scim-bearer-token-0123456789"
BASE = "https://hr.example.com/scim/v2"


def run(coro):
    return asyncio.run(coro)


def scim_user(i: int, active: bool = True) -> dict[str, Any]:
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE], "id": f"id-{i}",
            "userName": f"user{i}", "name": {"givenName": "User", "familyName": str(i)}, "active": active,
            "title": "Analyst", "emails": [{"value": f"other{i}@x.com"}, {"value": f"User{i}@Acme.com", "primary": True}],
            "phoneNumbers": [{"value": "+1 555"}], "addresses": [{"locality": "Brussels"}],
            "groups": [{"value": "g1", "display": "Finance"}],
            ENTERPRISE: {"department": "Finance", "manager": {"value": "id-0"}},
            "meta": {"resourceType": "User", "lastLogin": "2026-09-01T10:00:00Z"}}


class FakeScim:
    def __init__(self, count: int, cap: int = 3, key: str = "Resources", ignore_paging: bool = False):
        self.users = [scim_user(i, active=i != 2) for i in range(count)]
        self.cap, self.key, self.ignore_paging = cap, key, ignore_paging
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "status": "401"})
        if request.url.path != "/scim/v2/Users":
            return httpx.Response(404)
        params = dict(request.url.params)
        start = 1 if self.ignore_paging else int(params.get("startIndex", 1))
        count = min(int(params.get("count", 100)), self.cap)  # a server may return fewer than asked
        page = self.users[start - 1:start - 1 + count]
        return httpx.Response(200, json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                                         "totalResults": len(self.users), "startIndex": start,
                                         "itemsPerPage": len(page), self.key: page})


def connector(fake: Any, **config: Any) -> ScimConnector:
    return ScimConnector(clean_config(ScimConnector, {"base_url": BASE, **config}), {"token": TOKEN},
                         httpx.MockTransport(fake))


def test_registry_and_settings():
    assert connectors.connector_class("scim") is ScimConnector
    assert clean_config(ScimConnector, {"base_url": BASE + "/Users"})["base_url"] == BASE
    assert ScimConnector(clean_config(ScimConnector, {"base_url": BASE, "use_as": "accounts"}), {}).domains() == {
        "accounts": ["read"]}
    with pytest.raises(ValueError):
        clean_config(ScimConnector, {"base_url": BASE, "use_as": "groups"})


def test_users_page_by_start_index_with_short_pages():
    fake = FakeScim(7, cap=3)
    records, errors = normalize("people", run(connector(fake, page_size=5).pull("people")))
    assert not errors and len(records) == 7
    starts = [(r.url.params["startIndex"], r.url.params["count"]) for r in fake.calls]
    assert starts == [("1", "5"), ("4", "5"), ("7", "5")]  # the next index follows what was actually received
    one = next(r for r in records if r["external_id"] == "id-1")
    assert (one["display_name"], one["email"], one["login"], one["department"], one["manager_external_id"]) == (
        "User 1", "user1@acme.com", "user1", "Finance", "id-0")
    assert (one["groups"], one["location"], one["phone"], one["status"]) == (["Finance"], "Brussels", "+1 555", "active")
    assert next(r for r in records if r["external_id"] == "id-2")["status"] == "suspended"


def test_lower_case_resources_and_accounts_mode():
    fake = FakeScim(2, key="resources")
    records, errors = normalize("accounts", run(connector(fake, use_as="accounts").pull("accounts")))
    assert not errors and [(r["login"], r["active"]) for r in records] == [("user0", True), ("user1", True)]
    assert records[0]["last_login"]


def test_a_server_that_ignores_start_index_is_caught():
    with pytest.raises(ConnectorError) as info:
        run(connector(FakeScim(7, cap=3, ignore_paging=True)).pull("people"))
    assert "ignore startIndex" in info.value.message


def test_test_reports_the_total():
    result = run(connector(FakeScim(4)).test())
    assert result["ok"] and result["domains"] == {"people": ["read"]} and "4 user(s)" in result["checks"][1]["detail"]
    bad = ScimConnector(clean_config(ScimConnector, {"base_url": BASE}), {"token": "nope-nope-nope"},
                        httpx.MockTransport(FakeScim(1)))
    result = run(bad.test())
    assert not result["ok"] and result["checks"][0]["name"] == "Token" and "nope-nope-nope" not in str(result)
