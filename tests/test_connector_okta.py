"""The Okta connector against a fake Okta Management API (httpx.MockTransport, no network): SSWS auth, Link-header
pagination, the separate list of deprovisioned users, status mapping, groups and app links."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.okta import OktaConnector, person_status
from hub.integration.connections import clean_config

TOKEN = "00okta-api-token-abcdef0123456789"
BASE = "https://acme.okta.com"


def run(coro):
    return asyncio.run(coro)


def user(uid: str, status: str = "ACTIVE", **profile: Any) -> dict[str, Any]:
    first, last = profile.pop("first", uid.title()), profile.pop("last", "Doe")
    return {"id": uid, "status": status, "lastLogin": "2026-09-30T08:00:00.000Z",
            "profile": {"login": f"{uid}@acme.com", "email": f"{uid}@acme.com", "firstName": first, "lastName": last,
                        **profile}}


class FakeOkta:
    def __init__(self, users: list[dict[str, Any]], page: int = 2):
        self.users, self.page = users, page
        self.calls: list[httpx.Request] = []
        self.groups = {"alice": [{"id": "g1", "profile": {"name": "Engineering"}}, {"id": "g2", "profile": {"name": "atrium-admins"}}]}
        self.links = {"alice": [{"id": "alice", "label": "GitHub", "appName": "github", "appInstanceId": "0oa1",
                                 "appAssignmentId": "0ua1"}],
                      "bob": [{"id": "bob", "label": "Slack", "appName": "slack", "appInstanceId": "0oa2",
                               "appAssignmentId": "0ua2"}]}
        self.answers: list[httpx.Response] = []
        self.next_host = BASE

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if request.headers.get("Authorization") != f"SSWS {TOKEN}":
            return httpx.Response(401, json={"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
        if self.answers:
            return self.answers.pop(0)
        path, params = request.url.path, dict(request.url.params)
        if path == "/api/v1/users/me":
            return httpx.Response(200, json=user("svc"))
        if path == "/api/v1/users":
            gone = params.get("filter") == 'status eq "DEPROVISIONED"'
            rows = [u for u in self.users if (u["status"] == "DEPROVISIONED") == gone]
            start = int(params.get("after") or 0)
            limit = min(int(params.get("limit") or 200), self.page)
            chunk = rows[start:start + limit]
            headers = {}
            if start + limit < len(rows):
                query = {"limit": str(limit), "after": str(start + limit), **({"filter": params["filter"]} if gone else {})}
                headers["Link"] = f'<{self.next_host}/api/v1/users?{httpx.QueryParams(query)}>; rel="next"'
            return httpx.Response(200, json=chunk, headers=headers)
        parts = path.strip("/").split("/")  # api v1 users {id} groups|appLinks
        if len(parts) == 5 and parts[4] == "groups":
            return httpx.Response(200, json=self.groups.get(parts[3], []))
        if len(parts) == 5 and parts[4] == "appLinks":
            return httpx.Response(200, json=self.links.get(parts[3], []))
        return httpx.Response(404, json={"errorCode": "E0000007", "errorSummary": "Not found"})

    def paths(self) -> list[str]:
        return [r.url.path for r in self.calls]


def connector(fake: Any, **config: Any) -> OktaConnector:
    conn = OktaConnector(clean_config(OktaConnector, {"base_url": BASE, **config}), {"token": TOKEN},
                         httpx.MockTransport(fake))
    conn.retry_cap = 0  # type: ignore[misc]
    return conn


def directory() -> list[dict[str, Any]]:
    return [user("alice", title="Engineer", department="R&D", managerId="carol@acme.com", city="Ghent", countryCode="BE",
                 mobilePhone="+32 470"),
            user("bob", "SUSPENDED"), user("carol", "LOCKED_OUT", displayName="Carol Boss"),
            user("dave", "DEPROVISIONED"), user("erin", "PROVISIONED")]


def test_registry_and_settings():
    assert "okta" in connectors.REGISTRY and connectors.connector_class("okta") is OktaConnector
    cfg = clean_config(OktaConnector, {"base_url": "https://acme-admin.okta.com/api/v1/"})
    assert cfg["base_url"] == "https://acme.okta.com" and cfg["include_groups"] is True
    with pytest.raises(ValueError):
        clean_config(OktaConnector, {"base_url": "https://token:x@acme.okta.com"})
    assert OktaConnector(clean_config(OktaConnector, {"base_url": BASE, "include_app_links": False}), {}).domains() == {
        "people": ["read"]}


@pytest.mark.parametrize("okta,hub", [("ACTIVE", "active"), ("PROVISIONED", "active"), ("STAGED", "active"),
                                      ("RECOVERY", "active"), ("PASSWORD_EXPIRED", "active"), ("LOCKED_OUT", "active"),
                                      ("SUSPENDED", "suspended"), ("DEPROVISIONED", "terminated"), (None, "active")])
def test_status_mapping(okta, hub):
    assert person_status(okta) == hub


def test_people_follow_link_pagination_and_include_deprovisioned():
    fake = FakeOkta(directory(), page=2)
    records, errors = normalize("people", run(connector(fake).pull("people")))
    assert not errors and len(records) == 5
    by_id = {r["external_id"]: r for r in records}
    assert {k: r["status"] for k, r in by_id.items()} == {
        "alice": "active", "bob": "suspended", "carol": "active", "dave": "terminated", "erin": "active"}
    alice = by_id["alice"]
    assert (alice["display_name"], alice["email"], alice["login"], alice["title"], alice["department"]) == (
        "Alice Doe", "alice@acme.com", "alice@acme.com", "Engineer", "R&D")
    assert alice["manager_external_id"] == "carol@acme.com" and alice["location"] == "Ghent, BE"
    assert alice["phone"] == "+32 470" and alice["groups"] == ["Engineering", "atrium-admins"]
    assert by_id["carol"]["display_name"] == "Carol Boss"
    lists = [r for r in fake.calls if r.url.path == "/api/v1/users"]
    assert len(lists) == 2 + 1  # two pages of the 4 other users (following the cursor), one of the deprovisioned
    assert lists[1].url.params["after"] == "2" and lists[2].url.params["filter"] == 'status eq "DEPROVISIONED"'
    assert all(r.headers["Authorization"] == f"SSWS {TOKEN}" for r in fake.calls)
    assert sum(1 for p in fake.paths() if p.endswith("/groups")) == 5


def test_app_links_are_accounts():
    fake = FakeOkta(directory())
    records, errors = normalize("accounts", run(connector(fake).pull("accounts")))
    assert not errors
    assert {(r["external_id"], r["app"], r["active"], r["email"]) for r in records} == {
        ("alice:0ua1", "GitHub", True, "alice@acme.com"), ("bob:0ua2", "Slack", False, "bob@acme.com")}
    assert records[0]["last_login"] and not any(p.endswith("/dave/appLinks") for p in fake.paths())


def test_groups_and_app_links_can_be_switched_off():
    fake = FakeOkta(directory())
    records = run(connector(fake, include_groups=False).pull("people"))
    assert all(r["groups"] == [] for r in records) and not any(p.endswith("/groups") for p in fake.paths())
    with pytest.raises(ConnectorError):
        run(connector(fake, include_app_links=False).pull("accounts"))


def test_a_next_link_to_another_host_is_refused():
    fake = FakeOkta(directory(), page=1)
    fake.next_host = "https://evil.example.com"
    with pytest.raises(ConnectorError) as info:
        run(connector(fake).pull("people"))
    assert "another address" in info.value.message
    assert all(r.url.host == "acme.okta.com" for r in fake.calls)


def test_rate_limits_are_retried():
    fake = FakeOkta(directory())
    fake.answers = [httpx.Response(429, headers={"X-Rate-Limit-Reset": "0"}, json={"errorCode": "E0000047"})]
    assert len(run(connector(fake, include_groups=False).pull("people"))) == 5


def test_test_reports_token_users_groups_and_app_links():
    result = run(connector(FakeOkta(directory())).test())
    assert result["ok"] and result["domains"] == {"people": ["read"], "accounts": ["read"]}
    assert [c["name"] for c in result["checks"]] == ["API token", "Read users", "Read groups", "Read app assignments"]
    assert "svc@acme.com" in result["checks"][0]["detail"]


def test_a_wrong_token_is_reported_without_echoing_it():
    conn = OktaConnector(clean_config(OktaConnector, {"base_url": BASE}), {"token": "wrong-token-123456789"},
                         httpx.MockTransport(FakeOkta(directory())))
    result = run(conn.test())
    assert not result["ok"] and result["domains"] == {} and "check the API token" in result["detail"]
    assert "wrong-token-123456789" not in json.dumps(result)
