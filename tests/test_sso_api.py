"""End to end through the API: the agents connect tools to the suite's identity providers."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from hub.integration.identity import CLIENT_SECRET


def compose_project(root: Path, services: dict) -> Path:
    root.mkdir(parents=True)
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
    return root


def import_tool(client, wait_for, path: Path) -> dict:
    tool_id = client.post("/api/tools/import", json={"source_type": "local", "source": str(path)}).json()["id"]
    return wait_for(lambda: (t := client.get(f"/api/tools/{tool_id}").json())["report"] and t["status"] in ("ready", "needs_patch") and t)


def sso_approvals(client, tool_id: str) -> list[dict]:
    return [a for a in client.get("/api/approvals?status=pending").json()
            if a["kind"] == "patch" and a["payload"]["tool_id"] == tool_id and a["patch"]["strategy"].startswith("sso_")]


def sso_check(client, tool_id: str) -> dict:
    return next(c for c in client.get(f"/api/tools/{tool_id}").json()["report"]["checks"] if c["id"] == "sso")


def test_identity_providers_end_to_end(client, wait_for, browser, sign_in, tmp_path: Path):
    hub = client.app.state.hub
    grafana = compose_project(tmp_path / "grafana", {"grafana": {"image": "grafana/grafana:12.0.0", "ports": ["3000:3000"]}})
    keycloak = compose_project(tmp_path / "keycloak", {"keycloak": {"image": "quay.io/keycloak/keycloak:26.0", "ports": ["8080:8080"]}})
    authentik = compose_project(tmp_path / "authentik", {
        "server": {"image": "ghcr.io/goauthentik/server:2025.8", "ports": ["9000:9000"]},
        "worker": {"image": "ghcr.io/goauthentik/server:2025.8", "command": "worker"}})

    # no identity provider yet: the SSO gap falls back to the proxy, and the overview says so
    import_tool(client, wait_for, grafana)
    first = wait_for(lambda: sso_approvals(client, "grafana"))
    assert first[0]["patch"]["strategy"] == "sso_proxy" and "Import an identity provider" in sso_check(client, "grafana")["detail"]
    assert client.get("/api/identity-providers").json()["tools"][0]["status"] == "pending"

    # importing Keycloak re-plans Grafana: the proxy approval is superseded by a native connection
    import_tool(client, wait_for, keycloak)
    connect = wait_for(lambda: [a for a in sso_approvals(client, "grafana") if a["patch"]["strategy"] == "sso_connect"])[0]
    assert connect["patch"]["sso"]["provider"] == "keycloak" and connect["patch"]["sso"]["provider_name"] == "keycloak"
    old = next(a for a in client.get("/api/approvals").json() if a["id"] == first[0]["id"])
    assert old["status"] == "rejected" and old["note"].startswith("Superseded")
    overview = client.get("/api/identity-providers").json()
    provider = overview["providers"][0]
    assert (provider["tool_id"], provider["kind"], provider["issuer"]) == ("keycloak", "keycloak", "http://localhost:8080/realms/hub")
    assert overview["default"] is None and overview["needs_choice"] is False
    row = next(r for r in overview["tools"] if r["tool_id"] == "grafana")
    assert (row["status"], row["selected"], row["reason"], row["strategy"]) == ("pending", "keycloak", "only", "sso_connect")

    # a second provider: Grafana now needs a choice; the pending patch stays until someone makes it
    import_tool(client, wait_for, authentik)
    wait_for(lambda: client.get("/api/identity-providers").json()["needs_choice"])
    assert sso_check(client, "grafana")["fix"] is None
    assert [a["id"] for a in sso_approvals(client, "grafana")] == [connect["id"]]

    # choosing authentik for Grafana supersedes the Keycloak approval with a note
    viewer = sign_in("viewer")
    assert viewer.post("/api/tools/grafana/sso", json={"provider": "authentik"}).status_code == 403
    assert client.post("/api/tools/grafana/sso", json={"provider": "nope"}).status_code == 404
    assert client.post("/api/tools/keycloak/sso", json={"provider": "keycloak"}).status_code == 400
    planned = client.post("/api/tools/grafana/sso", json={"provider": "authentik"}).json()
    assert planned["provider"] == "authentik" and planned["superseded"] == [connect["id"]] and len(planned["patches"]) == 1
    superseded = next(a for a in client.get("/api/approvals").json() if a["id"] == connect["id"])
    assert superseded["status"] == "rejected" and superseded["note"] == "Superseded: grafana now signs in through authentik."
    assert superseded["decided_by"] == "admin"
    replacement = sso_approvals(client, "grafana")
    assert len(replacement) == 1 and replacement[0]["patch"]["sso"]["provider"] == "authentik"
    assert "Connect to authentik (OIDC)" in replacement[0]["title"]

    # approving applies both sides; the tool is re-scored as connected and the map draws the identity link
    assert client.post(f"/api/approvals/{replacement[0]['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: sso_check(client, "grafana")["status"] == "pass")
    tool = client.get("/api/tools/grafana").json()
    assert tool["manifest"]["auth"]["provider"] == "authentik" and sso_check(client, "grafana")["detail"] == "Signs in through authentik (OIDC)."
    links = client.get("/api/integration").json()["links"]
    assert {"source": "authentik", "target": "grafana", "type": "identity", "via": "SSO (oidc)"} in links
    row = next(r for r in client.get("/api/identity-providers").json()["tools"] if r["tool_id"] == "grafana")
    assert row["status"] == "connected" and row["applied"]["can_register"]

    adapters = hub.settings.workspace / "adapters" / "grafana"
    secret = (hub.settings.workspace / "secrets" / "sso" / "grafana--authentik--client-secret").read_text().strip()
    assert f"GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET={secret}" in (adapters / "sso" / "grafana.env").read_text()
    blueprint = (adapters / "idp" / "authentik" / "authentik-blueprint.yaml").read_text()
    assert json.dumps(secret) in blueprint and CLIENT_SECRET not in blueprint

    # registering at the provider goes through the Operator Agent and its policy (a token is automation)
    token = client.post("/api/tokens", json={"name": "ci", "role": "operator"}).json()["token"]
    bot = browser(headers={"Authorization": f"Bearer {token}"})
    queued = bot.post("/api/tools/grafana/sso/register").json()
    assert queued["status"] == "pending_approval"
    approval = next(a for a in client.get("/api/approvals").json() if a["id"] == queued["approval_id"])
    assert approval["kind"] == "command" and approval["payload"]["origin"] == "token:ci"
    assert approval["payload"]["command"].endswith('idp/authentik/register-authentik-compose.sh"')
    assert client.post("/api/tools/keycloak/sso/register").status_code == 400  # nothing applied there

    # the suite default and provider settings (admin only), validated
    operator = sign_in("operator")
    assert operator.put("/api/identity-providers/default", json={"tool_id": "keycloak"}).status_code == 403
    assert client.put("/api/identity-providers/default", json={"tool_id": "nope"}).status_code == 404
    overview = client.put("/api/identity-providers/default", json={"tool_id": "keycloak"}).json()
    assert overview["default"] == "keycloak" and overview["needs_choice"] is False
    assert client.patch("/api/identity-providers/keycloak", json={"realm": "bad realm!"}).status_code == 400
    assert client.patch("/api/identity-providers/keycloak", json={"slug": "x"}).status_code == 400
    assert client.patch("/api/identity-providers/keycloak", json={"settings": {"realm": "Bad Realm"}}).status_code == 400
    nested = client.patch("/api/identity-providers/authentik", json={"settings": {"slug": "portal"}}).json()
    assert next(p for p in nested["providers"] if p["tool_id"] == "authentik")["issuer"] == "http://localhost:9000/application/o/portal/"
    updated = client.patch("/api/identity-providers/keycloak", json={"realm": "corp", "base_url": "https://sso.example.com/"}).json()
    kc = next(p for p in updated["providers"] if p["tool_id"] == "keycloak")
    assert kc["issuer"] == "https://sso.example.com/realms/corp" and kc["settings"] == {"realm": "corp", "base_url": "https://sso.example.com"}
    assert ("admin", "Default identity provider: keycloak") in [(e["actor"], e["text"]) for e in hub.store.tail("activity", 500)]

    # Atrium's own sign-in client: files with the secret in the workspace, never in the answer
    assert operator.post("/api/identity-providers/keycloak/atrium", json={}).status_code == 403
    atrium = client.post("/api/identity-providers/keycloak/atrium", json={}).json()
    assert (atrium["client_id"], atrium["issuer"]) == ("atrium", "https://sso.example.com/realms/corp")
    assert atrium["redirect_uri"] == "http://127.0.0.1:8710/api/auth/oidc/callback" and "client_secret" not in atrium
    assert "HUB_OIDC_CLIENT_SECRET=<see atrium-oidc.env>" in atrium["env"]
    folder = Path(atrium["location"])
    atrium_secret = (hub.settings.workspace / "secrets" / "sso" / "atrium--keycloak--client-secret").read_text().strip()
    assert f"HUB_OIDC_CLIENT_SECRET={atrium_secret}" in (folder / "atrium-oidc.env").read_text()
    client_json = json.loads((folder / "keycloak-client.json").read_text())
    assert client_json["secret"] == atrium_secret and client_json["redirectUris"] == [atrium["redirect_uri"]]
    assert "atrium-admins" in (folder / "register-keycloak-compose.sh").read_text()
    assert atrium["register_command"].endswith('register-keycloak-compose.sh"')
    from hub.integration.identity import atrium_client
    assert atrium_client(hub, "keycloak").client_secret.get_secret_value() == atrium_secret  # for the sign-in settings

    # no secret in any API answer, approval, bus message or activity entry
    exposed = [client.get(path).text for path in ("/api/tools", "/api/tools/grafana", "/api/approvals", "/api/messages?limit=2000",
                                                  "/api/activity?limit=2000", "/api/identity-providers", "/api/integration",
                                                  "/api/settings", "/api/commands")]
    exposed += [client.get(f"/api/patches/{p['id']}").text for p in tool["patches"]]
    exposed += [json.dumps(atrium), json.dumps(planned)]
    for text in exposed:
        assert secret not in text and atrium_secret not in text

    # removing a provider clears it from the preferences
    assert client.delete("/api/tools/keycloak").json()["ok"]
    after = wait_for(lambda: (o := client.get("/api/identity-providers").json()) and len(o["providers"]) == 1 and o)
    assert after["default"] is None and "keycloak" not in (hub.prefs.get("idp_settings") or {})


def test_code_patch_adds_oidc_login_with_claude(client, wait_for, tmp_path: Path, plain_repo: Path):
    from test_llm_paths import FakeLLM

    hub = client.app.state.hub
    keycloak = compose_project(tmp_path / "keycloak", {"keycloak": {"image": "quay.io/keycloak/keycloak:26.0", "ports": ["8080:8080"]}})
    import_tool(client, wait_for, keycloak)
    new_app = (plain_repo / "app.py").read_text() + "\nimport os\nOIDC_ISSUER = os.environ.get('OIDC_ISSUER')\n"
    fake = hub.llm = FakeLLM(json_result={"title": "Add OIDC sign-in", "rationale": "People sign in through the suite.",
                                          "health_path": "", "changes": [{"path": "app.py", "content": new_app}]})
    import_tool(client, wait_for, plain_repo)
    patch = wait_for(lambda: next((p for p in client.get("/api/tools/notes").json()["patches"] if p["strategy"] == "sso_code"), None))
    assert patch["target"] == "repo" and patch["sso"]["provider"] == "keycloak"
    assert patch["sso"]["redirect_uris"] == ["http://localhost:5000/auth/oidc/callback"]
    assert [c["path"] for c in patch["adapter_changes"]][:2] == ["sso/oidc.env", "idp/keycloak/keycloak-client.json"]
    assert "+OIDC_ISSUER = os.environ.get('OIDC_ISSUER')" in patch["diff"] and "hub-adapter/sso/oidc.env" in patch["diff"]
    goal = next(c["prompt"] for c in fake.calls if "OIDC_CLIENT_SECRET" in c.get("prompt", ""))
    assert "/auth/oidc/callback" in goal and "keycloak" in goal and "Never hard-code" in goal


def test_choosing_a_provider_without_providers_or_tools(client, wait_for, plain_repo: Path):
    assert client.get("/api/identity-providers").json() == {"providers": [], "default": None, "needs_choice": False, "tools": []}
    assert client.post("/api/tools/nope/sso", json={"provider": "keycloak"}).status_code == 404
    assert client.post("/api/tools/nope/sso/register").status_code == 404
    assert client.post("/api/identity-providers/nope/atrium", json={}).status_code == 404
    import_tool(client, wait_for, plain_repo)
    row = client.get("/api/identity-providers").json()["tools"][0]
    assert row["status"] in ("pending", "no_provider") and row["selected"] is None and row["reason"] == "none"
