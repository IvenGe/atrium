"""Sign-in & SSO settings: stored in the database with the client secret encrypted, environment variables win, the
Test button runs discovery without saving, and saving rebuilds the OIDC client (no restart) - with the fake identity
provider of test_oidc (no network)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from conftest import ADMIN_PASSWORD, make_settings, new_browser
from hub.app import create_app
from hub.auth import sso_settings
from hub.config import Settings
from test_oidc import CLIENT_ID, CLIENT_SECRET, ISSUER, FakeIdP, callback, start

SETTINGS = {"preset": "keycloak", "provider_name": "Keycloak", "issuer": ISSUER, "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET, "role_claim": "groups", "admin_values": ["atrium-admins"],
            "operator_values": ["atrium-operators"]}


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


def hub_with(tmp_path: Path, idp: FakeIdP, **overrides):
    app = create_app(make_settings(tmp_path, **overrides))
    c = TestClient(app, headers={"X-Hub-Request": "1"})
    c.__enter__()
    hub = c.app.state.hub
    hub.auth.oidc_transport = idp.transport
    hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
    assert c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    return c


@pytest.fixture
def admin(tmp_path, idp):
    c = hub_with(tmp_path, idp)
    yield c
    c.__exit__(None, None, None)


def test_saved_settings_turn_on_sign_in_without_a_restart(admin, idp):
    hub = admin.app.state.hub
    before = admin.get("/api/auth/sso").json()
    assert before["enabled"] is False and before["env"] == [] and before["source"]["issuer"] == "default"
    assert before["redirect_uri"].endswith("/api/auth/oidc/callback") and {p["id"] for p in before["presets"]} == {
        "okta", "entra", "google", "keycloak", "authentik", "generic"}
    old_client = hub.auth.oidc

    saved = admin.put("/api/auth/sso", json=SETTINGS)
    assert saved.status_code == 200, saved.text
    view = saved.json()
    assert view["enabled"] and view["label"] == "Sign in with Keycloak" and view["client_secret_set"]
    assert view["source"]["issuer"] == "database" and view["source"]["client_secret"] == "database"
    assert hub.auth.oidc is not old_client and hub.auth.oidc.enabled
    anon = new_browser(admin)
    assert anon.get("/api/auth/me").json()["oidc"] == {"enabled": True, "label": "Sign in with Keycloak"}

    url, state = start(anon)  # the rebuilt client signs people in, with the stored (decrypted) secret
    done = callback(anon, idp.authorize(url, claims={"groups": ["atrium-admins"]}), state)
    assert done.status_code == 302 and done.headers["location"] == "/#/"
    me = anon.get("/api/auth/me").json()
    assert me["user"]["username"] == "ada" and me["user"]["role"] == "admin"
    assert idp.token_requests[0].headers["authorization"].startswith("Basic ")

    # the secret is never shown, logged or stored in the clear
    stored = hub.store.get("settings", "sso")
    assert stored["client_secret"] != CLIENT_SECRET and hub.secrets.decrypt(stored["client_secret"]) == CLIENT_SECRET
    shown = json.dumps([view, admin.get("/api/auth/sso").json(), admin.get("/api/activity?limit=500").json(),
                        admin.get("/api/settings").json()])
    assert CLIENT_SECRET not in shown and stored["client_secret"] not in shown
    db = Path(hub.settings.db_path)
    assert CLIENT_SECRET.encode() not in b"".join(p.read_bytes() for p in db.parent.glob("hub.db*"))
    assert any("Changed the Sign-in & SSO settings" in e["text"] and "client secret updated" in e["text"]
               for e in admin.get("/api/activity?limit=100").json())

    # removing them turns sign-in off again
    assert admin.delete("/api/auth/sso").json()["enabled"] is False
    assert anon.get("/api/auth/me").json()["oidc"]["enabled"] is False


def test_the_stored_secret_only_goes_to_its_issuer(admin):
    assert admin.put("/api/auth/sso", json=SETTINGS).status_code == 200
    moved = admin.put("/api/auth/sso", json={"issuer": "https://other.example.com/realms/hub"})
    assert moved.status_code == 400 and "again" in moved.json()["detail"]
    assert admin.get("/api/auth/sso").json()["values"]["issuer"] == ISSUER  # nothing was stored
    ok = admin.put("/api/auth/sso", json={"issuer": "https://other.example.com/realms/hub", "client_secret": "new-secret-1"})
    assert ok.status_code == 200 and ok.json()["values"]["issuer"] == "https://other.example.com/realms/hub"
    keep = admin.put("/api/auth/sso", json={"scopes": "profile email groups"})  # same issuer: the secret stays
    assert keep.json()["client_secret_set"] and keep.json()["values"]["scopes"] == "openid profile email groups"
    cleared = admin.put("/api/auth/sso", json={"clear_client_secret": True}).json()
    assert cleared["client_secret_set"] is False and cleared["enabled"]  # a public client (PKCE only)


@pytest.mark.parametrize("body,message", [
    ({"issuer": "http://idp.example.com"}, "plain http"),
    ({"issuer": "https://<your-domain>/oauth2/default"}, "placeholders"),
    ({"issuer": "ftp://idp.example.com"}, "https"),
    ({"role_claim": "groups; drop"}, "role claim"),
    ({"default_role": "root"}, None),
    ({"preset": "myspace"}, "preset"),
    ({"client_id": "two words"}, "client ID"),
])
def test_invalid_settings_are_refused(admin, body, message):
    response = admin.put("/api/auth/sso", json=body)
    assert response.status_code in (400, 422) and (message is None or message in response.text)
    assert admin.app.state.hub.store.get("settings", "sso") is None


def test_plain_http_only_when_allowed_or_local(admin):
    assert admin.put("/api/auth/sso", json={"issuer": "http://localhost:8080/realms/lab", "client_id": "x"}).status_code == 200
    lab = admin.put("/api/auth/sso", json={"issuer": "http://idp.lab:8080/realms/lab", "allow_http": True})
    assert lab.status_code == 200 and lab.json()["values"]["allow_http"] is True


def test_plain_http_allowed_by_the_environment(tmp_path, idp):
    lab = "http://keycloak.lab:8080/realms/hub"
    allowed = Settings(oidc_allow_http=True, oidc_env=("oidc_allow_http",))
    assert sso_settings.clean({"issuer": lab}, {}, {"allow_http"}, allowed)["issuer"] == lab
    denied = Settings(oidc_allow_http=False, oidc_env=("oidc_allow_http",))
    with pytest.raises(ValueError, match="plain http"):  # the environment wins over the body either way
        sso_settings.clean({"issuer": lab, "allow_http": True}, {}, {"allow_http"}, denied)
    c = hub_with(tmp_path, idp, oidc_allow_http=True, oidc_env=("oidc_allow_http",))
    try:
        assert c.post("/api/auth/sso/test", json={"issuer": lab, "client_id": "x"}).status_code == 200  # Test too
        saved = c.put("/api/auth/sso", json={"issuer": lab, "client_id": "x"})  # the UI leaves allow_http out
        assert saved.status_code == 200, saved.text
        assert saved.json()["values"]["allow_http"] is True and saved.json()["source"]["allow_http"] == "environment"
        assert saved.json()["values"]["issuer"] == lab
    finally:
        c.__exit__(None, None, None)


def test_test_runs_discovery_without_saving(admin, idp):
    hub = admin.app.state.hub
    result = admin.post("/api/auth/sso/test", json={"issuer": ISSUER, "client_id": CLIENT_ID}).json()
    assert result["ok"] and result["signing_keys"] == 3 and result["issuer"] == ISSUER
    assert result["token_endpoint"].endswith("/token") and idp.calls == ["discovery", "jwks"]
    assert hub.store.get("settings", "sso") is None and not hub.auth.oidc.enabled  # nothing was saved
    idp.discovery["claims_supported"] = ["sub", "email"]
    noted = admin.post("/api/auth/sso/test", json={"issuer": ISSUER, "client_id": CLIENT_ID}).json()
    assert noted["ok"] and noted["role_claim_advertised"] is False and "groups" in noted["notes"][0]
    wrong = admin.post("/api/auth/sso/test", json={"issuer": "https://idp.example.com/realms/other", "client_id": "x"}).json()
    assert wrong["ok"] is False and "HTTP 404" in wrong["detail"]
    idp.discovery["issuer"] = "https://evil.example.com"  # every discovery check of sign-in applies
    mismatch = admin.post("/api/auth/sso/test", json={"issuer": ISSUER, "client_id": CLIENT_ID}).json()
    assert mismatch["ok"] is False and "different issuer" in mismatch["detail"]
    assert admin.post("/api/auth/sso/test", json={"issuer": "http://idp.example.com"}).status_code == 400


def test_only_admins_manage_sign_in(admin):
    from conftest import PASSWORD

    hub = admin.app.state.hub
    hub.auth.create_user("oper", PASSWORD, role="operator", actor="test")
    operator = new_browser(admin)
    assert operator.post("/api/auth/login", json={"username": "oper", "password": PASSWORD}).status_code == 200
    for method, path in (("GET", "/api/auth/sso"), ("PUT", "/api/auth/sso"), ("DELETE", "/api/auth/sso"),
                         ("POST", "/api/auth/sso/test")):
        assert operator.request(method, path, json={}).status_code == 403
    assert admin.put("/api/auth/sso", json={"generated_secret_from": "keycloak"}).status_code == 400


def test_environment_variables_win(tmp_path, idp):
    c = hub_with(tmp_path, idp, oidc_issuer=ISSUER, oidc_client_id="env-client", oidc_label="Sign in with Corp")
    try:
        hub = c.app.state.hub
        view = c.get("/api/auth/sso").json()
        assert set(view["env"]) == {"issuer", "client_id", "label"} and view["env_vars"]["issuer"] == "HUB_OIDC_ISSUER"
        saved = c.put("/api/auth/sso", json={**SETTINGS, "issuer": "https://other.example.com/realms/x",
                                             "client_id": "db-client", "provider_name": "Okta"}).json()
        assert saved["values"]["issuer"] == ISSUER and saved["source"]["issuer"] == "environment"
        assert saved["values"]["client_id"] == "env-client" and saved["label"] == "Sign in with Corp"
        assert saved["source"]["client_secret"] == "database" and saved["client_secret_set"]  # entered for ISSUER
        assert hub.auth.oidc.client_id == "env-client" and hub.settings.oidc_client_secret is None
        assert "issuer" not in hub.store.get("settings", "sso")  # an environment value is never stored
    finally:
        c.__exit__(None, None, None)


def test_env_fields_come_from_the_variables_that_are_set(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for key in ("HUB_OIDC_ISSUER", "HUB_OIDC_CLIENT_ID", "HUB_OIDC_CLIENT_SECRET", "HUB_OIDC_LABEL"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HUB_OIDC_SCOPES", "openid email")
    monkeypatch.setenv("HUB_OIDC_DEFAULT_ROLE", "viewer")  # the default value, but set: it still wins
    settings = Settings.from_env()
    assert sso_settings.env_keys(settings) == {"scopes", "default_role"}
    assert sso_settings.env_keys(Settings(oidc_label="Sign in with X")) == {"label"}


def test_an_imported_keycloak_prefills_and_lends_its_generated_secret(admin):
    from hub.models import Manifest, PortalUi, Tool

    hub = admin.app.state.hub
    tool = Tool(id="keycloak", name="Keycloak", source_type="saas", source="https://sso.example.com", status="ready",
                manifest=Manifest(id="keycloak", name="Keycloak", kind="saas", provides=["auth.oidc"],
                                  ui=PortalUi(url="https://sso.example.com")))
    hub.save_tool(tool)
    [imported] = admin.get("/api/auth/sso").json()["imported"]
    assert (imported["preset"], imported["issuer"], imported["client_id"]) == (
        "keycloak", "https://sso.example.com/realms/hub", "atrium")
    assert imported["generated_secret"] is False
    assert admin.put("/api/auth/sso", json={"generated_secret_from": "keycloak"}).status_code == 400  # not generated yet
    assert admin.post("/api/identity-providers/keycloak/atrium", json={}).status_code == 200
    secret = (hub.settings.workspace / "secrets" / "sso" / "atrium--keycloak--client-secret").read_text().strip()
    assert admin.get("/api/auth/sso").json()["imported"][0]["generated_secret"] is True
    body = {k: imported[k] for k in ("preset", "provider_name", "issuer", "client_id", "role_claim", "admin_values",
                                     "operator_values")}
    view = admin.put("/api/auth/sso", json={**body, "generated_secret_from": "keycloak"}).json()
    assert view["client_secret_set"] and view["label"] == "Sign in with Keycloak"
    assert hub.auth.oidc.settings.oidc_client_secret == secret and secret not in json.dumps(view)
