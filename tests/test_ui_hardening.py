"""What the web UI shows that others wrote: a tool's own manifest styling its tile, and the sign-in screen's notices."""

from __future__ import annotations

from pathlib import Path

import yaml

from hub.integration.analyzer import analyze_repo
from hub.models import Manifest, PortalUi, Tool

HOSTILE_COLOR = "#7c3aed;position:fixed;inset:0;z-index:2147483647;width:100vw;height:100vh;font-size:60px"


def test_a_manifest_colour_or_icon_that_is_more_than_a_colour_or_a_glyph_is_dropped():
    for color in (HOSTILE_COLOR, "url(https://attacker.example/beacon)", "red", "#12345", "#0d9488 !important", 7):
        assert PortalUi(color=color).color is None, color
    for color in ("#0d9488", "#ABC", "#0d9488cc", " #abcd "):
        assert PortalUi(color=color).color == color.strip()
    for icon in ("Session expired - sign in at https://evil.example", "CRM", "a b", "‮A", "", 3):
        assert PortalUi(icon=icon).icon is None, icon
    for icon in ("C", "CR", "🛡️", "👨‍💻", "🇧🇪", "é"):
        assert PortalUi(icon=icon).icon == icon


def test_a_repository_manifest_cannot_style_the_hubs_pages(node_repo: Path):
    """The rest of a native manifest still applies; only the hostile values are dropped."""
    (node_repo / "hub.manifest.yaml").write_text(yaml.safe_dump({
        "name": "CRM", "launch": {"port": 4100},
        "ui": {"color": HOSTILE_COLOR, "icon": "Your session expired. Sign in at https://evil.example"},
    }))
    m, notes = analyze_repo(node_repo, "crm-app", "CRM App")
    assert m.native and m.launch.port == 4100 and not any("invalid" in n for n in notes)
    assert (m.ui.color, m.ui.icon) == (None, None)


def test_a_stored_tool_with_a_hostile_colour_loads_without_it():
    """A tool imported before the check: its manifest is re-validated whenever it is read back."""
    raw = Manifest(id="t", name="T").model_dump()
    raw["ui"].update(color=HOSTILE_COLOR, icon="sign in at evil.example")
    tool = Tool.model_validate({"id": "t", "name": "T", "source_type": "local", "source": "/x", "manifest": raw})
    assert (tool.manifest.ui.color, tool.manifest.ui.icon) == (None, None)


def test_the_api_never_serves_a_hostile_tile(client, wait_for, node_repo: Path):
    (node_repo / "hub.manifest.yaml").write_text(yaml.safe_dump({"ui": {"color": HOSTILE_COLOR, "icon": "ok"}}))
    response = client.post("/api/tools/import", json={"source_type": "local", "source": str(node_repo)})
    assert response.status_code == 202, response.text
    tool = wait_for(lambda: (t := client.get(f"/api/tools/{response.json()['id']}").json())["manifest"] and t)
    assert tool["manifest"]["ui"]["color"] is None and tool["manifest"]["ui"]["icon"] == "ok"
    assert HOSTILE_COLOR not in client.get("/api/tools").text


# -- the sign-in screen's notice (review F32) ----------------------------------------------------------------------


def test_a_link_or_the_public_callback_cannot_put_its_own_text_on_the_sign_in_screen(client, browser):
    """The sign-in screen used to show any ?error= text from the URL, and the callback passed the provider's
    error_description through: a phishing link made the hub's own page say "reset your password at evil.example"."""
    from test_auth import FakeOidc, identity

    client.app.state.hub.auth.oidc = FakeOidc(identity())
    victim = browser()
    # the old link form: the redirect no longer carries text, so the screen has nothing from the URL to show
    assert victim.get("/api/auth/me").json()["sso_error"] is None

    # sent straight to the public callback with an error and a description of the attacker's choosing
    lure = "Your password expired. Reset it at https://evil.example first"
    response = victim.get("/api/auth/oidc/callback", params={"error": "access_denied", "error_description": lure},
                          follow_redirects=False)
    assert response.status_code == 302 and response.headers["location"] == "/#/login"
    assert "evil.example" not in str(response.headers)
    assert victim.get("/api/auth/me").json()["sso_error"] == "The identity provider refused the sign-in (access_denied)."
    assert victim.get("/api/auth/me").json()["sso_error"] is None  # shown once

    # a made-up error code is not echoed either
    victim.get("/api/auth/oidc/callback", params={"error": "password_expired_reset_at_evil.example"}, follow_redirects=False)
    assert victim.get("/api/auth/me").json()["sso_error"] == "The identity provider refused the sign-in."
    log = [e["text"] for e in client.get("/api/activity").json() if e["actor"] == "auth"]
    assert not any("Reset it" in text for text in log)


def test_a_notice_cookie_the_hub_did_not_seal_is_ignored_and_cleared(client, browser, tmp_path: Path):
    """Cookies do not isolate ports: a tool's page on the same host can set one for the hub. Only a value sealed by
    this hub process is shown."""
    from fastapi.testclient import TestClient
    from test_auth import FakeOidc, identity

    from conftest import make_settings
    from hub.app import create_app
    from hub.auth.routes import SSO_NOTICE_COOKIE

    client.app.state.hub.auth.oidc = FakeOidc(identity())
    victim = browser()
    victim.cookies.set(SSO_NOTICE_COOKIE, "Your password expired. Reset it at https://evil.example", path="/api/auth")
    answer = victim.get("/api/auth/me")
    assert answer.json()["sso_error"] is None
    assert any(SSO_NOTICE_COOKIE in c and "max-age=0" in c.lower() for c in answer.headers.get_list("set-cookie"))

    # a notice sealed by another hub (or before a restart) does not open either
    with TestClient(create_app(make_settings(tmp_path / "other")), headers={"X-Hub-Request": "1"}) as other:
        other.app.state.hub.auth.oidc = FakeOidc(identity(), error="This account is disabled.")
        other.get("/api/auth/oidc/callback?code=c&state=s", follow_redirects=False)
        sealed = other.cookies.get(SSO_NOTICE_COOKIE)
    assert sealed
    replay = browser()
    replay.cookies.set(SSO_NOTICE_COOKIE, sealed, path="/api/auth")
    assert replay.get("/api/auth/me").json()["sso_error"] is None
