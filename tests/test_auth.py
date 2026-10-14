"""Built-in sign-in: passwords, sessions, roles, API tokens, first-run setup, SSO provisioning and the CLI."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import unquote

import pytest
from conftest import ADMIN_PASSWORD, PASSWORD, make_settings
from fastapi.testclient import TestClient
from starlette.requests import Request

from hub.__main__ import build_parser, main
from hub.app import create_app
from hub.auth import service
from hub.auth.oidc import OidcError, OidcIdentity
from hub.auth.passwords import hash_password, validate_password, verify_password
from hub.auth.policy import is_api, required_role
from hub.config import Settings
from hub.store import Store

try:
    from fastapi.routing import iter_route_contexts  # FastAPI keeps included routers nested in app.routes
except ImportError:  # older FastAPI flattens them
    def iter_route_contexts(routes):
        return routes

NEW_PASSWORD = "a brand new secret 7"


def api_routes(app) -> list[tuple[str, str]]:
    """(method, path template) of every /api route of the app, including those of included routers."""
    return [(method, route.path) for route in iter_route_contexts(app.routes) if is_api(route.path or "")
            for method in sorted(route.methods or ())]


@contextmanager
def running(tmp_path: Path, **overrides):
    """A hub with custom settings and nobody signed in."""
    app = create_app(make_settings(tmp_path, **overrides))
    with TestClient(app, headers={"X-Hub-Request": "1"}) as c:
        yield c


def login(c: TestClient, username: str, password: str):
    return c.post("/api/auth/login", json={"username": username, "password": password})


def session_doc(c: TestClient) -> dict | None:
    sid = hashlib.sha256(c.cookies["atrium_session"].encode()).hexdigest()
    return c.app.state.hub.store.get("sessions", sid)


def activity(c: TestClient) -> list[dict]:
    return c.app.state.hub.store.tail("activity", 500)


# -- passwords -----------------------------------------------------------------------------


def test_password_hashing_and_verification():
    encoded = hash_password(PASSWORD)
    assert encoded.startswith("scrypt$16384$8$1$") and len(encoded.split("$")) == 6
    assert verify_password(PASSWORD, encoded)
    assert not verify_password(PASSWORD + "!", encoded)
    assert hash_password(PASSWORD) != encoded  # random salt
    scheme, n, r, p, salt, digest = encoded.split("$")
    for broken in (None, "", "scrypt$", "bcrypt$16384$8$1$" + salt + "$" + digest, f"scrypt$x$8$1${salt}${digest}",
                   "scrypt$16384$8$1$!!$" + digest, f"scrypt$16384$8$1${salt}$", f"scrypt$1048576$64$64${salt}${digest}"):
        assert verify_password(PASSWORD, broken) is False


@pytest.mark.parametrize("password,message", [
    ("short pw 1", "at least 12"),
    ("x" * 257, "at most 256"),
    ("my name is Alice!!", "must not contain the username"),
    ("abababababababab", "different characters"),
])
def test_password_policy(password, message):
    with pytest.raises(ValueError, match=message):
        validate_password(password, "alice")
    validate_password(PASSWORD, "alice")


# -- policy ----------------------------------------------------------------------------------


@pytest.mark.parametrize("method,path,role", [
    ("GET", "/api/health", None), ("HEAD", "/api/health", None), ("GET", "/api/auth/me", None),
    ("POST", "/api/auth/login", None), ("POST", "/api/auth/setup", None),
    ("GET", "/api/auth/oidc/login", None), ("GET", "/api/auth/oidc/callback", None),
    ("POST", "/api/auth/logout", "viewer"), ("POST", "/api/auth/password", "viewer"),
    ("GET", "/api/auth/sessions", "viewer"), ("DELETE", "/api/auth/sessions", "viewer"),
    ("GET", "/api/users", "admin"), ("GET", "/api/users/", "admin"), ("DELETE", "/api/users/u_1", "admin"),
    ("POST", "/api/users/u_1/password", "admin"), ("POST", "/api/tokens", "admin"), ("GET", "/api/tokens/a/b", "admin"),
    ("GET", "/api/usersX", "viewer"), ("POST", "/api/tokensfoo", "operator"),  # never a bare prefix match
    ("PATCH", "/api/settings", "admin"), ("PATCH", "/api/settings/", "admin"), ("GET", "/api/settings", "viewer"),
    ("PATCH", "/api/agents/patcher", "admin"), ("PATCH", "/api/agents/tool:abc", "admin"),
    ("PATCH", "/api/agents/a/b", "operator"), ("GET", "/api/agents/patcher/messages", "viewer"),
    ("GET", "/api/overview", "viewer"), ("HEAD", "/api/overview", "viewer"), ("GET", "/api/events", "viewer"),
    ("GET", "/api/docs", "viewer"), ("POST", "/api/commands", "operator"), ("DELETE", "/api/assets/a", "operator"),
    ("POST", "/api/health", "operator"), ("GET", "/api/auth/login", "viewer"), ("PUT", "/api/anything", "operator"),
    ("GET", "/api/identity-providers", "viewer"), ("PUT", "/api/identity-providers/default", "admin"),
    ("PATCH", "/api/identity-providers/keycloak", "admin"), ("POST", "/api/identity-providers/keycloak/atrium", "admin"),
    ("POST", "/api/identity-providers/keycloak", "operator"), ("POST", "/api/tools/crm/sso", "operator"),
    ("POST", "/api/tools/crm/sso/register", "operator"), ("PATCH", "/api/identity-providers/a/b", "operator"),
    ("GET", "/api/connectors", "viewer"), ("GET", "/api/tools/crm/connection", "viewer"),
    ("PUT", "/api/tools/crm/connection", "admin"), ("DELETE", "/api/tools/crm/connection", "admin"),
    ("PUT", "/api/tools/crm/connection/", "admin"), ("POST", "/api/tools/crm/connection/test", "operator"),
    ("GET", "/api/tools/crm/connection/options/model_id", "operator"), ("GET", "/api/tools/crm/connection/options", "viewer"),
    ("POST", "/api/tools/crm/connection/generate", "operator"), ("PUT", "/api/tools/a/b/connection", "operator"),
    ("GET", "/api/flows", "viewer"), ("PATCH", "/api/flows/fl_1", "operator"), ("POST", "/api/flows/fl_1/run", "operator"),
    ("GET", "/api/vulnerabilities/summary", "viewer"), ("PATCH", "/api/vulnerabilities/v_1", "operator"),
    ("POST", "/api/vulnerabilities/scan", "operator"), ("POST", "/api/assets/scan-scope", "operator"),
    ("POST", "/api/agents", "admin"), ("POST", "/api/agents/", "admin"), ("DELETE", "/api/agents/agent:x", "admin"),
    ("POST", "/api/agents/agent:x/chat", "operator"), ("POST", "/api/agents/agent:x/run", "operator"),
    ("POST", "/api/agents/supervisor/chat/reset", "operator"), ("GET", "/api/agents/teams", "viewer"),
    ("POST", "/api/tools/crm/team", "operator"), ("PATCH", "/api/settings/guardrails", "admin"),
    ("GET", "/api/llm/providers", "viewer"), ("POST", "/api/llm/providers", "admin"),
    ("PATCH", "/api/llm/providers/ollama", "admin"), ("DELETE", "/api/llm/providers/ollama", "admin"),
    ("POST", "/api/llm/providers/ollama/test", "admin"), ("POST", "/api/llm/providers/ollama", "operator"),
    ("GET", "/api/auth/sso", "admin"), ("PUT", "/api/auth/sso", "admin"), ("DELETE", "/api/auth/sso", "admin"),
    ("POST", "/api/auth/sso/test", "admin"), ("GET", "/api/auth/sso/test", "viewer"),
    ("GET", "/api/people", "viewer"), ("GET", "/api/people/p_1", "viewer"), ("GET", "/api/people/leavers", "viewer"),
    ("POST", "/api/people", "operator"), ("PATCH", "/api/people/p_1", "operator"), ("DELETE", "/api/people/p_1", "operator"),
    ("POST", "/api/people/p_1/actions/unassign_assets", "operator"),
    ("POST", "/api/people/p_1/actions/disable_atrium_account", "admin"),
    ("POST", "/api/people/p_1/actions/disable_atrium_account/", "admin"),
    ("GET", "/api/accounts", "viewer"), ("PATCH", "/api/accounts/okta|00u1", "operator"),
    ("GET", "/api/extensions", "viewer"), ("GET", "/api/extensions/wazuh-alerts", "viewer"),
    ("POST", "/api/extensions", "admin"), ("POST", "/api/extensions/", "admin"),
    ("PATCH", "/api/extensions/wazuh-alerts", "admin"), ("DELETE", "/api/extensions/wazuh-alerts", "admin"),
    ("POST", "/api/extensions/wazuh-alerts/rollback", "admin"), ("POST", "/api/extensions/a/b", "operator"),
    ("POST", "/api/tools/wazuh/extend", "admin"), ("GET", "/api/x", "viewer"), ("GET", "/api/x/alerts", "viewer"),
    ("GET", "/api/x/alerts/x_1", "viewer"), ("POST", "/api/x/alerts", "operator"),
    ("PATCH", "/api/x/alerts/x_1", "operator"), ("DELETE", "/api/x/alerts/x_1", "operator"),
    ("GET", "/api/self-patches", "viewer"), ("GET", "/api/self-patches/sp_1", "viewer"),
    ("POST", "/api/self-patches", "admin"), ("POST", "/api/self-patches/sp_1/apply", "admin"),
    ("POST", "/api/self-patches/sp_1", "operator"), ("POST", "/api/approvals/ap_1", "operator"),
    ("GET", "/api/network/devices", "viewer"), ("GET", "/api/network/devices/fw1", "viewer"),
    ("POST", "/api/network/devices/fw1/refresh", "operator"), ("POST", "/api/network/devices/fw1/backups", "operator"),
    ("POST", "/api/network/devices/fw1/baseline", "admin"), ("DELETE", "/api/network/devices/fw1/baseline", "admin"),
    ("POST", "/api/network/drift/dr_1/ack", "operator"), ("GET", "/api/network/backups/bk_1/download", "admin"),
    ("GET", "/api/network/backups", "viewer"), ("PATCH", "/api/network/settings", "admin"),
    ("GET", "/api/network/settings", "viewer"), ("GET", "/api/segmentation", "viewer"),
    ("PATCH", "/api/segmentation/zones/z:fw1:lan", "admin"), ("PATCH", "/api/segmentation/zones/z:sw1:Gi1/0/1", "admin"),
    ("PUT", "/api/segmentation/placements/a_1", "operator"), ("PUT", "/api/segmentation/policy", "admin"),
    ("GET", "/api/segmentation/policy", "viewer"), ("POST", "/api/segmentation/refresh", "operator"),
    ("GET", "/api/frameworks", "viewer"), ("GET", "/api/frameworks/cyfun2025", "viewer"),
    ("POST", "/api/frameworks/cyfun2025/assessments", "operator"),
    ("PATCH", "/api/frameworks/cyfun2025/assessments/fa_1", "operator"),
    ("PATCH", "/api/frameworks/cyfun2025/assessments/fa_1/requirements/PR.AA-01.1", "operator"),
    ("GET", "/api/frameworks/cyfun2025/assessments/fa_1/audit-pack", "viewer"),
    ("DELETE", "/api/frameworks/cyfun2025/assessments/fa_1", "admin"),
    ("POST", "/api/segmentation/changes/preview", "operator"), ("POST", "/api/segmentation/changes", "operator"),
    ("GET", "/api/segmentation/changes", "viewer"), ("GET", "/api/segmentation/changes/chg_1", "viewer"),
    ("DELETE", "/api/segmentation/changes/chg_1", "operator"), ("POST", "/api/segmentation/changes/chg_1/revert", "operator"),
    ("POST", "/api/segmentation/changes/chg_1/emergency", "admin"), ("POST", "/api/network/backups/bk_1/restore", "operator"),
    ("GET", "/api/network/maintenance-windows", "viewer"), ("POST", "/api/network/maintenance-windows", "admin"),
    ("PATCH", "/api/network/maintenance-windows/mw_1", "admin"),
    ("DELETE", "/api/network/maintenance-windows/mw_1", "admin"),
    ("GET", "/api/integration/map", "viewer"), ("GET", "/api/integration/map/options", "viewer"),
    ("POST", "/api/flows", "operator"), ("GET", "/api/layouts/integration", "viewer"),
    ("PATCH", "/api/layouts/integration", "operator"), ("DELETE", "/api/layouts/segmentation", "operator"),
])
def test_required_role(method, path, role):
    assert required_role(method, path) == role


# Written from the product contract on purpose, independently of hub.auth.policy.
PUBLIC = {("GET", "/api/health"), ("GET", "/api/auth/me"), ("POST", "/api/auth/login"), ("POST", "/api/auth/setup"),
          ("GET", "/api/auth/oidc/login"), ("GET", "/api/auth/oidc/callback")}
SELF_SERVICE = {("POST", "/api/auth/logout"), ("POST", "/api/auth/password"), ("GET", "/api/auth/sessions"),
                ("DELETE", "/api/auth/sessions")}
INTEGRATION = {("POST", "/api/bus/publish"), ("GET", "/api/health")}
RANK = {"viewer": 1, "operator": 2, "admin": 3}


def contract_role(method: str, path: str) -> str | None:
    if (method, path) in PUBLIC:
        return None
    if (method, path) in SELF_SERVICE:
        return "viewer"
    if path.split("/")[2] in ("users", "tokens"):
        return "admin"
    if method == "PATCH" and path in ("/api/settings", "/api/agents/{agent_id}"):
        return "admin"
    # identity providers: choosing the suite default, provider settings and Atrium's own sign-in client
    if (method, path) in {("PUT", "/api/identity-providers/default"), ("PATCH", "/api/identity-providers/{tool_id}"),
                          ("POST", "/api/identity-providers/{tool_id}/atrium")}:
        return "admin"
    # a tool's connection holds its API credentials; listing a field's choices uses them
    if (method, path) in {("PUT", "/api/tools/{tool_id}/connection"), ("DELETE", "/api/tools/{tool_id}/connection")}:
        return "admin"
    if (method, path) == ("GET", "/api/tools/{tool_id}/connection/options/{field}"):
        return "operator"
    # agent definitions, the guardrails and the AI model providers (which may hold API keys)
    if (method, path) in {("PATCH", "/api/settings/guardrails"), ("POST", "/api/agents"),
                          ("DELETE", "/api/agents/{agent_id}"), ("POST", "/api/llm/providers"),
                          ("PATCH", "/api/llm/providers/{provider_id}"), ("DELETE", "/api/llm/providers/{provider_id}"),
                          ("POST", "/api/llm/providers/{provider_id}/test")}:
        return "admin"
    # Atrium's own sign-in settings (they hold its client secret) - reading them too
    if (method, path) in {("GET", "/api/auth/sso"), ("PUT", "/api/auth/sso"), ("DELETE", "/api/auth/sso"),
                          ("POST", "/api/auth/sso/test")}:
        return "admin"
    # People: operators change people and links; disabling someone's Atrium account is account administration
    if (method, path) == ("POST", "/api/people/{person_id}/actions/{action}"):
        return "operator"  # per action: see test_required_role
    # extensions and self-patches change Atrium itself (reading them and extension records follow the default)
    if (method, path) in {("POST", "/api/extensions"), ("PATCH", "/api/extensions/{ext_id}"),
                          ("DELETE", "/api/extensions/{ext_id}"), ("POST", "/api/extensions/{ext_id}/rollback"),
                          ("POST", "/api/tools/{tool_id}/extend"), ("POST", "/api/self-patches"),
                          ("POST", "/api/self-patches/{patch_id}/apply")}:
        return "admin"
    # compliance frameworks: viewers read (incl. the audit pack), operators start and score assessments, admins delete
    if (method, path) == ("DELETE", "/api/frameworks/{framework_id}/assessments/{assessment_id}"):
        return "admin"
    # network devices: baselines, backup downloads (full configurations) and settings; segmentation zone roles and
    # the policy (they decide compliance verdicts)
    if (method, path) in {("POST", "/api/network/devices/{tool_id}/baseline"),
                          ("DELETE", "/api/network/devices/{tool_id}/baseline"),
                          ("GET", "/api/network/backups/{backup_id}/download"), ("PATCH", "/api/network/settings"),
                          ("PATCH", "/api/segmentation/zones/{zone_id:path}"), ("PUT", "/api/segmentation/policy")}:
        return "admin"
    # device changes: operators propose, withdraw and revert; an emergency apply and maintenance windows are admin's
    if (method, path) in {("POST", "/api/segmentation/changes/{change_id}/emergency"),
                          ("POST", "/api/network/maintenance-windows"),
                          ("PATCH", "/api/network/maintenance-windows/{window_id}"),
                          ("DELETE", "/api/network/maintenance-windows/{window_id}")}:
        return "admin"
    return "viewer" if method in ("GET", "HEAD") else "operator"


def test_permission_matrix_covers_every_route(client, sign_in, browser):
    token = client.post("/api/tokens", json={"name": "matrix", "role": "integration"}).json()["token"]
    callers = {
        "anonymous": browser(),
        "viewer": sign_in("viewer"),
        "operator": sign_in("operator"),
        "admin": sign_in("admin"),
        "integration": browser(headers={"Authorization": f"Bearer {token}"}),
    }
    # signing out last keeps the sessions alive
    routes = sorted(api_routes(client.app), key=lambda r: r == ("POST", "/api/auth/logout"))
    assert len(routes) > 50 and ("GET", "/api/users") in routes and ("POST", "/api/bus/publish") in routes
    for method, template in routes:
        path = template.replace("{", "").replace("}", "")  # /api/users/{user_id} -> /api/users/user_id
        expected = contract_role(method, template)
        assert required_role(method, path) == expected, (method, template)
        for who, caller in callers.items():
            if who == "anonymous":
                allowed = expected is None
            elif who == "integration":
                allowed = (method, template) in INTEGRATION
            else:
                allowed = expected is None or RANK[who] >= RANK[expected]
            if allowed and template == "/api/events":
                continue  # an open event stream never ends under TestClient
            status = caller.request(method, path).status_code
            if allowed:
                assert status not in (401, 403), (who, method, template, status)
            else:
                assert status == (401 if who == "anonymous" else 403), (who, method, template, status)


def test_anonymous_requests(browser):
    anon = browser()
    response = anon.get("/api/overview")
    assert response.status_code == 401 and response.json() == {"detail": "Sign in required"}
    assert anon.get("/api/health").json() == {"ok": True}
    assert anon.get("/").status_code == 200  # the UI itself is public; it shows the sign-in screen
    me = anon.get("/api/auth/me").json()
    assert me == {"authenticated": False, "user": None, "setup_required": False,
                  "oidc": {"enabled": False, "label": "Sign in with SSO"}, "session": {"idle_minutes": 720, "days": 7}}
    # the cross-site guard runs before authentication
    blocked = anon.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}, headers={"X-Hub-Request": ""})
    assert blocked.status_code == 403 and "X-Hub-Request" in blocked.json()["detail"]


def test_viewer_is_told_why(sign_in):
    viewer = sign_in("viewer")
    response = viewer.post("/api/grc/evaluate")
    assert response.status_code == 403 and response.json() == {"detail": "Your role (viewer) cannot do this."}
    assert viewer.get("/api/grc").status_code == 200


# -- signing in ------------------------------------------------------------------------------


def test_login_sets_a_hardened_session_cookie(client, browser):
    hub = client.app.state.hub
    response = login(browser(), "ADMIN ", ADMIN_PASSWORD)  # usernames are case-insensitive
    assert response.status_code == 200
    user = response.json()["user"]
    assert user["username"] == "admin" and user["role"] == "admin" and user["has_password"]
    assert "password_hash" not in user
    cookie = response.headers["set-cookie"].lower()
    for flag in ("atrium_session=", "httponly", "samesite=lax", "path=/", f"max-age={7 * 86400}"):
        assert flag in cookie
    assert "secure" not in cookie
    assert hub.auth.find_user("admin").last_login > time.time() - 60

    hub.settings.cookie_secure = True
    assert "secure" in login(browser(), "admin", ADMIN_PASSWORD).headers["set-cookie"].lower()
    hub.settings.cookie_secure = False
    https = browser(base_url="https://testserver")
    assert "secure" in login(https, "admin", ADMIN_PASSWORD).headers["set-cookie"].lower()
    assert https.get("/api/overview").status_code == 200


def test_login_failures_and_activity_log(client, browser):
    anon = browser()
    wrong = login(anon, "admin", "not the password")
    assert wrong.status_code == 401 and wrong.json()["detail"] == "Invalid username or password."
    unknown = login(anon, "ghost", ADMIN_PASSWORD)
    assert unknown.status_code == 401 and unknown.json()["detail"] == "Invalid username or password."

    hub = client.app.state.hub
    hub.auth.create_user("dora", PASSWORD, actor="test")
    dora = hub.auth.find_user("dora")
    client.patch(f"/api/users/{dora.id}", json={"disabled": True})
    disabled = login(anon, "dora", PASSWORD)
    assert disabled.status_code == 403 and disabled.json()["detail"] == "This account is disabled."

    entries = activity(client)
    failed = [e for e in entries if e["actor"] == "auth" and e["text"].startswith("Failed sign-in")]
    assert [e["data"]["username"] for e in failed] == ["admin", "ghost"]
    assert all(e["level"] == "warn" and e["data"]["ip"] == "testclient" for e in failed)
    assert any(e["actor"] == "admin" and e["text"] == "Signed in" and e["level"] == "info" for e in entries)


def test_unknown_usernames_still_cost_a_password_check(client, browser, monkeypatch):
    checked = []
    real = service.verify_password
    monkeypatch.setattr(service, "verify_password", lambda password, encoded: checked.append(encoded) or real(password, encoded))
    assert login(browser(), "ghost", ADMIN_PASSWORD).status_code == 401
    assert checked == [service.dummy_hash()]


def test_repeated_failures_lock_the_username_on_that_ip(client, browser):
    anon = browser()
    for _ in range(5):
        assert login(anon, "admin", "wrong password!").status_code == 401
    locked = login(anon, "admin", ADMIN_PASSWORD)  # even the right password
    assert locked.status_code == 429
    assert locked.json()["detail"] == "Too many failed sign-ins. Try again in 15 minutes."
    assert 840 < int(locked.headers["retry-after"]) <= 900
    assert any(e["actor"] == "auth" and e["text"].startswith("Locked out admin") for e in activity(client))
    # other usernames from this ip, and this username from another ip, are not affected
    client.app.state.hub.auth.create_user("other", PASSWORD, actor="test")
    assert login(anon, "other", PASSWORD).status_code == 200
    assert login(browser(client=("10.0.0.9", 4000)), "admin", ADMIN_PASSWORD).status_code == 200


def test_parallel_guesses_cannot_slip_past_the_limit(client):
    auth = client.app.state.hub.auth
    request = Request({"type": "http", "method": "POST", "path": "/api/auth/login", "headers": [], "client": ("10.1.1.1", 1)})

    async def guess() -> int:
        try:
            await auth.login("admin", "wrong password!", request)
        except service.AuthError as exc:
            return exc.status
        return 200

    async def burst() -> list[int]:
        return list(await asyncio.gather(*(guess() for _ in range(12))))

    statuses = client.portal.call(burst)
    assert statuses.count(401) == 5 and statuses.count(429) == 7


def test_successful_login_clears_the_counter(client, browser):
    anon = browser()
    for _ in range(4):
        login(anon, "admin", "wrong password!")
    assert login(anon, "admin", ADMIN_PASSWORD).status_code == 200
    for _ in range(4):
        assert login(anon, "admin", "wrong password!").status_code == 401
    assert login(anon, "admin", ADMIN_PASSWORD).status_code == 200


def test_too_many_failures_from_one_ip(client, browser):
    anon = browser(client=("10.0.0.7", 4000))
    for i in range(20):
        assert login(anon, f"user{i}", "wrong password!").status_code == 401
    assert login(anon, "admin", ADMIN_PASSWORD).status_code == 429
    assert login(browser(), "admin", ADMIN_PASSWORD).status_code == 200


# -- sessions --------------------------------------------------------------------------------


def test_idle_sessions_expire_and_last_seen_is_touched_sparingly(client):
    hub = client.app.state.hub
    idle = hub.settings.session_idle_minutes * 60
    doc = session_doc(client)
    hub.store.put("sessions", {**doc, "last_seen": time.time() - 30})
    stored = session_doc(client)["last_seen"]
    assert client.get("/api/overview").status_code == 200
    assert session_doc(client)["last_seen"] == stored  # touched at most once a minute
    hub.store.put("sessions", {**doc, "last_seen": time.time() - idle + 120})
    assert client.get("/api/overview").status_code == 200
    assert session_doc(client)["last_seen"] > time.time() - 10
    hub.store.put("sessions", {**doc, "last_seen": time.time() - idle - 1})
    assert client.get("/api/overview").status_code == 401
    assert session_doc(client) is None  # expired sessions are deleted when seen


def test_sessions_have_an_absolute_lifetime(client):
    hub = client.app.state.hub
    doc = session_doc(client)
    assert abs(doc["expires_at"] - doc["created_at"] - 7 * 86400) < 1
    hub.store.put("sessions", {**doc, "expires_at": time.time() - 1, "last_seen": time.time()})
    assert client.get("/api/overview").status_code == 401
    assert session_doc(client) is None


def test_logout(client, browser):
    old = client.cookies["atrium_session"]
    response = client.post("/api/auth/logout")
    assert response.json() == {"ok": True}
    assert "max-age=0" in response.headers["set-cookie"].lower()
    assert client.get("/api/overview").status_code == 401
    replay = browser(headers={"Cookie": f"atrium_session={old}"})
    assert replay.get("/api/overview").status_code == 401
    assert any(e["actor"] == "admin" and e["text"] == "Signed out" for e in activity(client))


def test_signing_in_again_replaces_the_browser_session(client):
    hub = client.app.state.hub
    admin = hub.auth.find_user("admin")
    assert login(client, "admin", ADMIN_PASSWORD).status_code == 200
    assert len(hub.auth.sessions(admin.id)) == 1


def test_list_and_revoke_other_sessions(client, browser):
    phone = browser(headers={"X-Hub-Request": "1", "user-agent": "Phone"})
    login(phone, "admin", ADMIN_PASSWORD)
    sessions = client.get("/api/auth/sessions").json()
    assert len(sessions) == 2 and sum(s["current"] for s in sessions) == 1
    assert set(sessions[0]) == {"id", "created_at", "last_seen", "expires_at", "ip", "user_agent", "current"}
    assert all(len(s["id"]) == 12 for s in sessions)
    assert "Phone" in {s["user_agent"] for s in sessions}
    assert client.delete("/api/auth/sessions").json() == {"revoked": 1}
    assert phone.get("/api/overview").status_code == 401
    assert client.get("/api/overview").status_code == 200


def test_change_password(client, browser):
    other = browser()
    login(other, "admin", ADMIN_PASSWORD)

    def change(current, new):
        return client.post("/api/auth/password", json={"current_password": current, "new_password": new})

    assert change("not it at all", NEW_PASSWORD).json()["detail"] == "Your current password is incorrect."
    assert "at least 12" in change(ADMIN_PASSWORD, "short").json()["detail"]
    assert "username" in change(ADMIN_PASSWORD, "admin password 2024").json()["detail"]
    assert change(ADMIN_PASSWORD, ADMIN_PASSWORD).status_code == 400
    assert change(ADMIN_PASSWORD, NEW_PASSWORD).json() == {"ok": True}
    assert other.get("/api/overview").status_code == 401  # other sessions are signed out
    assert client.get("/api/overview").status_code == 200  # this one stays
    assert login(browser(), "admin", ADMIN_PASSWORD).status_code == 401
    assert login(browser(), "admin", NEW_PASSWORD).status_code == 200
    assert any(e["actor"] == "admin" and e["text"] == "Changed their password" for e in activity(client))


def test_must_change_password_blocks_everything_else(client, browser):
    created = client.post("/api/users", json={"username": "newbie", "password": PASSWORD, "role": "operator"})
    assert created.status_code == 201 and created.json()["must_change_password"] is True
    newbie = browser()
    assert login(newbie, "newbie", PASSWORD).json()["user"]["must_change_password"] is True
    blocked = newbie.get("/api/overview")
    assert blocked.status_code == 403
    assert blocked.json() == {"detail": "Change your password first.", "code": "password_change_required"}
    assert newbie.get("/api/auth/sessions").status_code == 403
    assert newbie.get("/api/auth/me").json()["user"]["must_change_password"] is True
    assert newbie.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD}).status_code == 200
    assert newbie.get("/api/auth/me").json()["user"]["must_change_password"] is False
    assert newbie.get("/api/overview").status_code == 200
    assert newbie.post("/api/auth/logout").status_code == 200


# -- first run -------------------------------------------------------------------------------


def test_first_run_setup(tmp_path):
    with running(tmp_path) as c:
        hub = c.app.state.hub
        token = hub.auth.setup_token
        assert token and c.get("/api/auth/me").json()["setup_required"] is True
        assert c.get("/api/overview").status_code == 401
        body = {"token": "wrong", "username": "Root", "password": ADMIN_PASSWORD, "display_name": "Root", "email": "root@example.com"}
        wrong = c.post("/api/auth/setup", json=body)
        assert wrong.status_code == 403
        weak = c.post("/api/auth/setup", json={**body, "token": token, "password": "short"})
        assert weak.status_code == 400 and hub.auth.setup_token == token
        done = c.post("/api/auth/setup", json={**body, "token": token})
        assert done.status_code == 200
        assert done.json()["user"]["username"] == "root" and done.json()["user"]["role"] == "admin"
        assert "atrium_session=" in done.headers["set-cookie"]
        me = c.get("/api/auth/me").json()
        assert me["authenticated"] and me["user"]["username"] == "root" and not me["setup_required"]
        assert hub.auth.setup_token is None
        assert c.post("/api/auth/setup", json={**body, "token": token}).status_code == 409
        assert c.get("/api/overview").status_code == 200


def test_setup_token_guessing_is_throttled(tmp_path):
    with running(tmp_path, setup_token="fixed-setup-token") as c:
        assert c.app.state.hub.auth.setup_token == "fixed-setup-token"
        body = {"token": "guess", "username": "root", "password": ADMIN_PASSWORD}
        for _ in range(5):
            assert c.post("/api/auth/setup", json=body).status_code == 403
        assert c.post("/api/auth/setup", json={**body, "token": "fixed-setup-token"}).status_code == 429


def test_bootstrap_admin_from_settings(tmp_path):
    with running(tmp_path, admin_username="Boss", admin_password=ADMIN_PASSWORD) as c:
        hub = c.app.state.hub
        assert hub.auth.setup_token is None
        assert [(u.username, u.role) for u in hub.auth.users()] == [("boss", "admin")]
        assert login(c, "boss", ADMIN_PASSWORD).status_code == 200
        assert any(e["text"] == "Created admin account boss" for e in activity(c))
    with running(tmp_path, admin_username="other", admin_password=ADMIN_PASSWORD) as c:  # only on an empty hub
        assert [u.username for u in c.app.state.hub.auth.users()] == ["boss"]


def test_bootstrap_rejects_a_weak_admin_password(tmp_path):
    with pytest.raises(ValueError, match="HUB_ADMIN_PASSWORD"):
        create_app(make_settings(tmp_path, admin_username="boss", admin_password="short"))


def test_settings_from_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for key, value in {"HUB_SESSION_IDLE_MINUTES": "30", "HUB_SESSION_DAYS": "2", "HUB_COOKIE_SECURE": "1",
                       "HUB_PUBLIC_URL": "https://hub.example.com/", "HUB_ADMIN_USERNAME": "boss",
                       "HUB_ADMIN_PASSWORD": ADMIN_PASSWORD, "HUB_SETUP_TOKEN": "tok",
                       "HUB_OIDC_ISSUER": "https://idp.example.com/realms/x", "HUB_OIDC_CLIENT_ID": "atrium",
                       "HUB_OIDC_ROLE_CLAIM": "realm_access.roles", "HUB_OIDC_ADMIN_VALUES": "ops-admins, root",
                       "HUB_OIDC_LABEL": "Sign in with Keycloak", "HUB_OIDC_ALLOW_HTTP": "true"}.items():
        monkeypatch.setenv(key, value)
    s = Settings.from_env()
    assert (s.session_idle_minutes, s.session_days, s.cookie_secure) == (30, 2, True)
    assert s.public_url == "https://hub.example.com"
    assert (s.admin_username, s.admin_password, s.setup_token) == ("boss", ADMIN_PASSWORD, "tok")
    assert s.oidc_role_claim == "realm_access.roles" and s.oidc_admin_values == ["ops-admins", "root"]
    assert s.oidc_operator_values == ["atrium-operators"] and s.oidc_default_role == "viewer"
    assert s.oidc_scopes == "openid profile email" and s.oidc_label == "Sign in with Keycloak" and s.oidc_allow_http
    assert Settings(port=9000).public_url == "http://127.0.0.1:9000"


# -- account administration ------------------------------------------------------------------


def test_admin_manages_users(client, sign_in):
    created = client.post("/api/users", json={"username": "Vera", "password": PASSWORD, "role": "viewer",
                                              "display_name": "Vera V", "email": "vera@example.com"})
    assert created.status_code == 201
    vera = created.json()
    assert vera["username"] == "vera" and vera["id"].startswith("u_") and vera["has_password"]
    assert client.post("/api/users", json={"username": "VERA", "password": PASSWORD}).status_code == 409
    assert client.post("/api/users", json={"username": "-bad-", "password": PASSWORD}).status_code == 400
    assert client.post("/api/users", json={"username": "weak", "password": "short"}).status_code == 400

    updated = client.patch(f"/api/users/{vera['id']}", json={"role": "operator", "display_name": "Vera", "email": None})
    assert updated.json()["role"] == "operator" and updated.json()["email"] is None

    reset = client.post(f"/api/users/{vera['id']}/password", json={"new_password": NEW_PASSWORD})
    assert reset.status_code == 200 and reset.json()["must_change_password"] is True

    assert client.delete(f"/api/users/{vera['id']}").json() == {"ok": True}
    assert client.delete(f"/api/users/{vera['id']}").status_code == 404
    texts = [(e["actor"], e["text"]) for e in activity(client)]
    for text in ("Created viewer account vera", "Updated account vera: role viewer -> operator, display name, email",
                 "Reset the password of vera", "Deleted account vera"):
        assert ("admin", text) in texts


def test_reset_disable_and_delete_sign_the_user_out(client, sign_in):
    hub = client.app.state.hub
    vic = sign_in("viewer", "vic")
    uid = hub.auth.find_user("vic").id
    client.post(f"/api/users/{uid}/password", json={"new_password": NEW_PASSWORD, "must_change_password": False})
    assert vic.get("/api/overview").status_code == 401
    assert login(vic, "vic", NEW_PASSWORD).status_code == 200

    client.patch(f"/api/users/{uid}", json={"disabled": True})
    assert vic.get("/api/overview").status_code == 401 and hub.auth.sessions(uid) == []
    assert login(vic, "vic", NEW_PASSWORD).status_code == 403
    client.patch(f"/api/users/{uid}", json={"disabled": False})
    assert login(vic, "vic", NEW_PASSWORD).status_code == 200
    client.delete(f"/api/users/{uid}")
    assert vic.get("/api/overview").status_code == 401 and hub.auth.sessions(uid) == []


def test_self_and_last_admin_guards(client, browser):
    me = next(u for u in client.get("/api/users").json() if u["username"] == "admin")
    url = f"/api/users/{me['id']}"
    for response, words in [(client.patch(url, json={"role": "viewer"}), "own role"),
                            (client.patch(url, json={"disabled": True}), "disable your own"),
                            (client.delete(url), "delete your own"),
                            (client.post(f"{url}/password", json={"new_password": NEW_PASSWORD}), "Change password")]:
        assert response.status_code == 400 and words in response.json()["detail"]

    # an admin API token is not an account, so only the last-admin rule protects "admin" from it
    token = client.post("/api/tokens", json={"name": "root", "role": "admin"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {token}"})
    for response in (bot.patch(url, json={"role": "operator"}), bot.patch(url, json={"disabled": True}), bot.delete(url)):
        assert response.status_code == 400
        assert response.json()["detail"] == "At least one enabled administrator must remain."

    second = bot.post("/api/users", json={"username": "second", "password": PASSWORD, "role": "admin"}).json()
    assert bot.patch(url, json={"role": "operator"}).json()["role"] == "operator"
    assert client.get("/api/users").status_code == 403  # "admin" was demoted: the new role applies at once
    # ... to the token too: it acts for "admin" and never with more than admin's role (F2)
    assert bot.patch(f"/api/users/{second['id']}", json={"disabled": True}).status_code == 403
    # a token of the last enabled administrator still cannot disable, demote or delete that administrator
    browser_second = browser()
    assert browser_second.post("/api/auth/login", json={"username": "second", "password": PASSWORD}).status_code == 200
    browser_second.post("/api/auth/password", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    token2 = browser_second.post("/api/tokens", json={"name": "root2", "role": "admin"}).json()["token"]
    bot2 = browser(headers={"Authorization": f"Bearer {token2}"})
    for response in (bot2.patch(f"/api/users/{second['id']}", json={"disabled": True}),
                     bot2.patch(f"/api/users/{second['id']}", json={"role": "operator"}), bot2.delete(f"/api/users/{second['id']}")):
        assert response.status_code == 400
        assert response.json()["detail"] == "At least one enabled administrator must remain."


# -- API tokens ------------------------------------------------------------------------------


def test_api_tokens(client, browser):
    hub = client.app.state.hub
    created = client.post("/api/tokens", json={"name": "ci", "role": "operator", "expires_days": 30})
    assert created.status_code == 201
    body = created.json()
    secret = body["token"]
    assert secret.startswith("atr_") and body["prefix"] == secret[4:12] and body["created_by"] == "admin"
    assert set(body) == {"id", "name", "role", "prefix", "created_by", "created_at", "last_used", "expires_at", "token"}
    listed = client.get("/api/tokens").json()
    assert [t["id"] for t in listed] == [body["id"]] and "token" not in listed[0] and "token_hash" not in listed[0]
    doc = hub.store.get("tokens", body["id"])
    assert doc["token_hash"] == hashlib.sha256(secret.encode()).hexdigest()
    assert secret[4:] not in json.dumps(hub.store.list("tokens"))  # only the hash is stored
    assert abs(doc["expires_at"] - (time.time() + 30 * 86400)) < 60
    assert client.post("/api/tokens", json={"name": "ci", "role": "viewer"}).status_code == 409

    # Bearer clients are not browsers: they skip the X-Hub-Request header; cookie requests still need it
    bot = browser(headers={"Authorization": f"Bearer {secret}"})
    assert bot.post("/api/grc/evaluate").status_code == 200
    assert hub.store.get("tokens", body["id"])["last_used"] > time.time() - 60
    assert client.post("/api/grc/evaluate", headers={"X-Hub-Request": ""}).status_code == 403
    assert bot.get("/api/users").status_code == 403  # operator tokens cannot administer

    # a Bearer header means token auth only: the session cookie is then ignored
    assert client.get("/api/overview", headers={"Authorization": "Bearer atr_nope"}).status_code == 401
    assert browser(headers={"Authorization": f"Bearer {secret[4:]}"}).get("/api/overview").status_code == 401

    hub.store.put("tokens", {**hub.store.get("tokens", body["id"]), "expires_at": time.time() - 1})
    assert bot.get("/api/overview").status_code == 401
    hub.store.put("tokens", {**hub.store.get("tokens", body["id"]), "expires_at": None})
    assert bot.get("/api/overview").status_code == 200
    assert client.delete(f"/api/tokens/{body['id']}").json() == {"ok": True}
    assert bot.get("/api/overview").status_code == 401
    texts = [(e["actor"], e["text"]) for e in activity(client)]
    assert ("admin", "Created API token ci (operator)") in texts and ("admin", "Revoked API token ci") in texts


def test_integration_tokens_only_publish_events(client, browser):
    secret = client.post("/api/tokens", json={"name": "crm", "role": "integration"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {secret}"})
    published = bot.post("/api/bus/publish", json={"source": "crm", "event": "crm.changed", "payload": {}})
    assert published.status_code == 200 and published.json() == {"deliveries": []}
    assert bot.get("/api/health").status_code == 200
    for method, path in [("GET", "/api/overview"), ("GET", "/api/auth/me"), ("POST", "/api/commands"),
                         ("GET", "/api/events"), ("POST", "/api/auth/login")]:
        assert bot.request(method, path).status_code == 403


def test_people_run_commands_but_tokens_are_automation(client, browser, sign_in):
    command = f'"{sys.executable}" -c "print(6*7)"'
    secret = client.post("/api/tokens", json={"name": "ci", "role": "operator"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {secret}"})
    queued = bot.post("/api/commands", json={"command": command}).json()
    assert queued["status"] == "pending_approval"  # tokens follow the autonomy policy like agents
    approval = next(a for a in client.get("/api/approvals").json() if a["id"] == queued["approval_id"])
    assert approval["payload"]["origin"] == "token:ci"

    olga = sign_in("admin", "olga")  # an operator's commands on the hub machine wait for an admin (test_security_core)
    assert olga.post("/api/commands", json={"command": command}).json()["status"] == "done"
    assert client.get("/api/commands").json()[-1]["origin"] == "user:olga"
    decided = olga.post(f"/api/approvals/{queued['approval_id']}", json={"approve": False}).json()
    assert decided["decided_by"] == "olga" and decided["status"] == "rejected"

    senders = {(m["sender"], m["recipient"], m["subject"]) for m in client.get("/api/messages").json()}
    assert ("token:ci", "operator", "run") in senders and ("user:olga", "operator", "run") in senders
    assert ("user:olga", "operator", "approval.decided") in senders
    assert ("olga", "Rejected: " + approval["title"]) in [(e["actor"], e["text"]) for e in activity(client)]


def test_activity_names_the_acting_user(client, sign_in):
    client.patch("/api/settings", json={"autonomy": "manual"})
    olga = sign_in("operator", "olga")
    olga.post("/api/hosts", json={"name": "web-1", "address": "10.0.0.5", "username": "ops"})
    texts = [(e["actor"], e["text"]) for e in activity(client)]
    assert ("admin", "Settings changed: autonomy=manual") in texts
    assert ("olga", "Registered host web-1 (ops@10.0.0.5)") in texts
    assert client.patch("/api/agents/patcher", json={"paused": True}).status_code == 200
    assert ("admin", "Configured Patch Agent: paused") in [(e["actor"], e["text"]) for e in activity(client)]


def test_no_endpoint_returns_password_or_token_hashes(client, sign_in):
    hub = client.app.state.hub
    events = hub.bus.subscribe(maxsize=5000)
    sign_in("viewer")
    exposed = [
        client.post("/api/users", json={"username": "vera", "password": PASSWORD, "role": "operator"}),
        client.post("/api/tokens", json={"name": "ci", "role": "viewer"}),
        client.get("/api/auth/me"),
    ]
    vera = exposed[0].json()["id"]
    exposed += [client.patch(f"/api/users/{vera}", json={"role": "viewer"}),
                client.post(f"/api/users/{vera}/password", json={"new_password": NEW_PASSWORD})]
    for method, path in api_routes(client.app):
        if method == "GET" and "{" not in path and path != "/api/events":
            exposed.append(client.get(path))
    secrets = [u["password_hash"] for u in hub.store.list("users")] + [t["token_hash"] for t in hub.store.list("tokens")]
    assert len(secrets) == 4  # admin, viewer1, vera and the ci token
    streamed = []
    while not events.empty():
        streamed.append(json.dumps(events.get_nowait(), default=str))
    hub.bus.unsubscribe(events)
    for text in [r.text for r in exposed] + streamed:
        assert "password_hash" not in text and "token_hash" not in text
        assert not any(secret in text for secret in secrets)


# -- single sign-on provisioning (the protocol itself is tested in test_oidc.py) -------------


class FakeOidc:
    enabled = True
    label = "Sign in with Keycloak"

    def __init__(self, identity: OidcIdentity, error: str | None = None):
        self.identity, self.error, self.calls = identity, error, []

    async def begin(self) -> tuple[str, str]:
        return "https://idp.example.com/auth?client_id=atrium", "state-cookie-value"

    async def complete(self, code: str, state: str, state_cookie: str | None) -> OidcIdentity:
        self.calls.append((code, state, state_cookie))
        if self.error:
            raise OidcError(self.error)
        return self.identity


def identity(**overrides) -> OidcIdentity:
    fields = dict(issuer="https://idp.example.com", subject="123", username="admin", email="ada@example.com",
                  name="Ada Lovelace", role="operator", claims={})
    return OidcIdentity(**{**fields, **overrides})


def test_sso_routes_are_404_without_configuration(browser):
    anon = browser()
    assert anon.get("/api/auth/oidc/login", follow_redirects=False).status_code == 404
    assert anon.get("/api/auth/oidc/callback?code=a&state=b", follow_redirects=False).status_code == 404


def test_sso_sign_in_provisions_and_syncs_accounts(client, browser):
    hub = client.app.state.hub
    fake = hub.auth.oidc = FakeOidc(identity())
    anon = browser()
    assert anon.get("/api/auth/me").json()["oidc"] == {"enabled": True, "label": "Sign in with Keycloak"}
    start = anon.get("/api/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 302 and start.headers["location"].startswith("https://idp.example.com/auth")
    state_cookie = start.headers["set-cookie"].lower()
    for flag in ("atrium_oidc_state=state-cookie-value", "httponly", "max-age=600", "path=/api/auth/oidc", "samesite=lax"):
        assert flag in state_cookie

    done = anon.get("/api/auth/oidc/callback?code=c1&state=s1", follow_redirects=False)
    assert done.status_code == 302 and done.headers["location"] == "/#/"
    assert fake.calls == [("c1", "s1", "state-cookie-value")]
    assert any("atrium_oidc_state=" in c and "max-age=0" in c.lower() for c in done.headers.get_list("set-cookie"))
    user = anon.get("/api/auth/me").json()["user"]
    assert user["username"] == "admin-2"  # the local "admin" is never taken over
    assert (user["auth_source"], user["role"], user["has_password"], user["display_name"]) == ("oidc", "operator", False, "Ada Lovelace")
    assert user["oidc_subject"] == "https://idp.example.com|123"
    assert anon.post("/api/auth/password", json={"current_password": "x", "new_password": NEW_PASSWORD}).json()["detail"] \
        == "Your account signs in through single sign-on."

    fake.identity = identity(role="viewer")  # the identity provider is authoritative for the role
    again = browser()
    again.get("/api/auth/oidc/callback?code=c2&state=s2")
    synced = again.get("/api/auth/me").json()["user"]
    assert (synced["id"], synced["username"], synced["role"]) == (user["id"], "admin-2", "viewer")
    assert len(hub.auth.users()) == 2

    client.patch(f"/api/users/{user['id']}", json={"disabled": True})
    refused = browser().get("/api/auth/oidc/callback?code=c3&state=s3", follow_redirects=False)
    assert refused.headers["location"].startswith("/#/login?error=")
    assert unquote(refused.headers["location"].split("error=", 1)[1]) == "This account is disabled."


def test_sso_failures_redirect_to_the_login_screen(client, browser):
    hub = client.app.state.hub
    hub.auth.oidc = FakeOidc(identity(), error="State mismatch")
    anon = browser()
    failed = anon.get("/api/auth/oidc/callback?code=c&state=s", follow_redirects=False)
    assert failed.status_code == 302 and unquote(failed.headers["location"]) == "/#/login?error=State mismatch"
    denied = anon.get("/api/auth/oidc/callback?error=access_denied", follow_redirects=False)
    assert "access_denied" in unquote(denied.headers["location"])
    assert anon.get("/api/auth/me").json()["authenticated"] is False
    assert any(e["actor"] == "auth" and e["text"].startswith("Single sign-on failed") for e in activity(client))


# -- GRC -------------------------------------------------------------------------------------


def test_grc_evaluates_hub_accounts(client):
    assert client.post("/api/grc/evaluate").status_code == 200
    controls = {c["id"]: c for c in client.get("/api/grc").json()["controls"]}
    assert controls["HB-AC-4"]["status"] == "partial" and "OIDC" in controls["HB-AC-4"]["detail"]
    assert controls["HB-AC-5"]["status"] == "pass"
    assert any(r["source"] == "auto:HB-AC-4" and r["status"] == "open" for r in client.get("/api/grc/risks").json())
    client.app.state.hub.auth.oidc = FakeOidc(identity())
    client.post("/api/grc/evaluate")
    controls = {c["id"]: c for c in client.get("/api/grc").json()["controls"]}
    assert controls["HB-AC-4"]["status"] == "pass"


# -- command line ----------------------------------------------------------------------------


def test_cli_keeps_plain_serve_options():
    args = build_parser().parse_args(["--port", "8711"])
    assert args.command is None and args.port == 8711
    args = build_parser().parse_args(["serve", "--port", "8712", "--data-dir", "x"])
    assert args.command == "serve" and args.port == 8712 and args.data_dir == "x"
    args = build_parser().parse_args(["--data-dir", "y", "user", "list"])
    assert (args.command, args.action, args.data_dir) == ("user", "list", "y")


def test_cli_prints_the_setup_link(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("HUB_SETUP_TOKEN", "first-run-token")
    monkeypatch.delenv("HUB_PUBLIC_URL", raising=False)
    served = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: served.append(kwargs))
    assert main(["--port", "8799", "--data-dir", str(tmp_path / "data")]) == 0
    assert served and served[0]["port"] == 8799
    out = capsys.readouterr().out
    assert "First run: create the administrator at http://127.0.0.1:8799/#/setup?token=first-run-token" in out


def test_cli_user_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    data = str(tmp_path / "cli")

    def run(*argv: str, stdin: str = "") -> int:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        return main(list(argv))

    assert run("user", "list", "--data-dir", data) == 1  # no database yet
    assert run("user", "create", "Root", "--role", "admin", "--password-stdin", "--data-dir", data,
               stdin=ADMIN_PASSWORD + "\n") == 0
    assert "Created admin account root" in capsys.readouterr().out
    assert run("user", "create", "bob", "--password-stdin", "--data-dir", data, stdin="short\n") == 1
    assert "at least 12" in capsys.readouterr().err
    assert run("user", "create", "root", "--password-stdin", "--data-dir", data, stdin=PASSWORD + "\n") == 1
    answers = iter([PASSWORD, PASSWORD + "x"])
    monkeypatch.setattr("getpass.getpass", lambda prompt="": next(answers))
    assert run("user", "create", "eve", "--data-dir", data) == 2
    assert "do not match" in capsys.readouterr().err

    store = Store(Path(data) / "hub.db")
    root = next(u for u in store.list("users") if u["username"] == "root")
    store.put("users", {**root, "must_change_password": True})
    store.put("sessions", {"id": "s1", "user_id": root["id"], "created_at": time.time(), "last_seen": time.time(),
                           "expires_at": time.time() + 3600, "ip": "x", "user_agent": ""})
    store.close()
    assert run("user", "passwd", "root", "--password-stdin", "--data-dir", data, stdin=NEW_PASSWORD + "\n") == 0
    assert run("user", "passwd", "nobody", "--password-stdin", "--data-dir", data, stdin=NEW_PASSWORD + "\n") == 1
    assert run("--data-dir", data, "user", "list") == 0
    out = capsys.readouterr().out
    assert "root" in out and "admin" in out and "bob" not in out

    store = Store(Path(data) / "hub.db")
    root = next(u for u in store.list("users") if u["username"] == "root")
    assert verify_password(NEW_PASSWORD, root["password_hash"]) and root["must_change_password"] is False
    assert store.list("sessions") == []
    assert any(e["actor"] == "cli" for e in store.tail("activity"))
    store.close()
