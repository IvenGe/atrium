"""Identity providers, provider selection, the SSO catalog, strategy selection and SSO patches (no running hub)."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from hub.agents.patcher import render_diff
from hub.integration import identity, sso_catalog
from hub.integration.analyzer import analyze_repo
from hub.integration.compatibility import evaluate_tool, sso_check, suite_matrix
from hub.integration.identity import CLIENT_SECRET, IdentityPrefs, list_providers, select
from hub.integration.patches import apply_patch, attach_sso, plan_patch
from hub.models import FileChange, Manifest, Patch, Tool


def make_tool(tool_id: str, *, name: str | None = None, path: str | None = None, source: str = "/srv", **manifest) -> Tool:
    m = Manifest(id=tool_id, name=name or tool_id.title(), **manifest)
    return Tool(id=tool_id, name=m.name, source_type="local", source=source, path=path, manifest=m, status="ready")


def keycloak(path: str | None = None, **kw) -> Tool:
    return make_tool("keycloak", provides=["auth.oidc", "auth.saml"], launch={"port": 8080}, path=path, **kw)


def authentik(path: str | None = None) -> Tool:
    return make_tool("authentik", provides=["auth.oidc", "auth.saml"], ui={"url": "https://auth.example.com/"}, path=path)


def zitadel() -> Tool:
    return make_tool("zitadel", provides=["auth.oidc"], ui={"url": "https://id.example.com"})


def app(tool_id: str, port: int = 3000, **kw) -> Tool:
    return make_tool(tool_id, launch={"port": port}, ui={"url": f"http://localhost:{port}"}, **kw)


class Tagged(yaml.SafeLoader):
    """Reads authentik blueprints: keeps !Find / !KeyOf tags as (tag, value)."""


Tagged.add_multi_constructor("!", lambda loader, suffix, node: (suffix, loader.construct_sequence(node, deep=True)
                             if isinstance(node, yaml.SequenceNode) else loader.construct_scalar(node)))


class FakeHub:
    """Just enough of Hub for apply_patch."""

    def __init__(self, workspace: Path, tool: Tool):
        self.settings = SimpleNamespace(workspace=workspace)
        self.tool = tool

    def get_tool(self, tool_id):
        return self.tool

    def save_tool(self, tool):
        self.tool = tool
        return tool

    def save_patch(self, patch):
        return patch


def secret_of(workspace: Path, owner: str, provider: str) -> str:
    return (workspace / "secrets" / "sso" / f"{owner}--{provider}--client-secret").read_text().strip()


def compose_dir(tmp_path: Path, name: str, services: dict) -> Path:
    root = tmp_path / name
    root.mkdir()
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
    return root


# -- providers -------------------------------------------------------------------------------


def test_providers_are_detected_with_kind_issuer_and_endpoints():
    other = make_tool("dex", provides=["auth.oidc"], ui={"url": "https://dex.example.com/"})
    found = {p.tool_id: p for p in list_providers([keycloak(), authentik(), zitadel(), other, app("wiki")])}
    assert set(found) == {"keycloak", "authentik", "zitadel", "dex"}
    kc, ak, zi, dex = found["keycloak"], found["authentik"], found["zitadel"], found["dex"]
    assert (kc.kind, ak.kind, zi.kind, dex.kind) == ("keycloak", "authentik", "zitadel", "generic")
    assert kc.protocols == ["oidc", "saml"] and zi.protocols == ["oidc"]

    assert kc.issuer == "http://localhost:8080/realms/hub"  # realm "hub" by default
    assert kc.discovery_url() == "http://localhost:8080/realms/hub/.well-known/openid-configuration"
    assert kc.endpoints()["token"] == "http://localhost:8080/realms/hub/protocol/openid-connect/token"
    assert kc.saml_metadata_url() == "http://localhost:8080/realms/hub/protocol/saml/descriptor"

    assert ak.base_url == "https://auth.example.com" and ak.issuer == "https://auth.example.com/application/o/atrium/"
    assert ak.client_issuer("hub-wiki") == "https://auth.example.com/application/o/hub-wiki/"  # one application per client
    assert ak.discovery_url("hub-wiki") == "https://auth.example.com/application/o/hub-wiki/.well-known/openid-configuration"
    assert ak.endpoints("hub-wiki")["authorize"] == "https://auth.example.com/application/o/authorize/"
    assert ak.saml_metadata_url("hub-wiki") == "https://auth.example.com/application/saml/hub-wiki/metadata/"

    assert zi.issuer == "https://id.example.com" and zi.endpoints()["userinfo"] == "https://id.example.com/oidc/v1/userinfo"
    assert dex.issuer == "https://dex.example.com" and dex.endpoints()["authorize"] is None and dex.saml_metadata_url() is None


def test_provider_settings_change_issuer_and_unknown_urls_are_flagged():
    kc = list_providers([keycloak()], {"keycloak": {"realm": "corp", "base_url": "https://sso.example.com"}})[0]
    assert kc.issuer == "https://sso.example.com/realms/corp" and kc.configured
    ak = list_providers([authentik()], {"authentik": {"slug": "portal", "realm": "ignored"}})[0]
    assert ak.issuer == "https://auth.example.com/application/o/portal/" and "realm" not in ak.settings
    bare = list_providers([make_tool("authelia", provides=["auth.oidc"])])[0]
    assert bare.kind == "authelia" and not bare.configured and bare.base_url == identity.PLACEHOLDER_BASE
    with pytest.raises(ValueError):
        identity.validate_setting("realm", "bad realm!")
    with pytest.raises(ValueError):
        identity.validate_setting("base_url", "ftp://x")
    assert identity.validate_setting("base_url", "https://sso.example.com/") == "https://sso.example.com"


def test_selection_with_zero_one_and_two_providers():
    wiki = app("wiki")
    assert select(wiki, []).reason == "none" and select(wiki, []).provider is None

    one = list_providers([keycloak()])
    assert (select(wiki, one).provider.tool_id, select(wiki, one).reason) == ("keycloak", "only")
    assert select(keycloak(), one).reason == "none"  # a provider never signs in through itself

    two = list_providers([keycloak(), authentik()])
    needs = select(wiki, two)
    assert needs.provider is None and needs.reason == "needs_choice" and len(needs.candidates) == 2
    by_default = select(wiki, two, IdentityPrefs(default="authentik"))
    assert (by_default.provider.tool_id, by_default.reason) == ("authentik", "default")
    declared = app("wiki", auth={"provider": "keycloak"})
    assert select(declared, two, IdentityPrefs(default="authentik")).reason == "manifest"
    chosen = select(declared, two, IdentityPrefs(default="authentik", choices={"wiki": "authentik"}))
    assert (chosen.provider.tool_id, chosen.reason) == ("authentik", "choice")
    stale = select(wiki, two, IdentityPrefs(default="gone", choices={"wiki": "gone"}))
    assert stale.reason == "needs_choice"  # choices of providers that left the suite are ignored


# -- catalog generators (golden checks on keys and redirect URIs) ------------------------------


def generate(tool: Tool, provider_tool: Tool | None = None):
    provider = list_providers([provider_tool or keycloak()])[0]
    return sso_catalog.generate(tool, provider)


def env_of(config) -> dict[str, str]:
    text = next(f.content for f in config.files if f.path.endswith(".env"))
    return {k: json.loads(v) if v.startswith('"') else v
            for k, v in (line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))}


def test_grafana_generic_oauth():
    config = generate(app("grafana"))
    env = env_of(config)
    issuer = "http://localhost:8080/realms/hub"
    assert config.protocol == "oidc" and config.redirect_uris == ["http://localhost:3000/login/generic_oauth"]
    assert env["GF_AUTH_GENERIC_OAUTH_ENABLED"] == "true" and env["GF_SERVER_ROOT_URL"] == "http://localhost:3000"
    assert env["GF_AUTH_GENERIC_OAUTH_CLIENT_ID"] == "hub-grafana"
    assert env["GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET"] == CLIENT_SECRET
    assert env["GF_AUTH_GENERIC_OAUTH_AUTH_URL"] == f"{issuer}/protocol/openid-connect/auth"
    assert env["GF_AUTH_GENERIC_OAUTH_TOKEN_URL"] == f"{issuer}/protocol/openid-connect/token"
    assert env["GF_AUTH_GENERIC_OAUTH_API_URL"] == f"{issuer}/protocol/openid-connect/userinfo"
    assert "atrium-admins" in env["GF_AUTH_GENERIC_OAUTH_ROLE_ATTRIBUTE_PATH"]
    ak = env_of(generate(app("grafana"), authentik()))
    assert ak["GF_AUTH_GENERIC_OAUTH_AUTH_URL"] == "https://auth.example.com/application/o/authorize/"
    generic = generate(app("grafana"), make_tool("dex", provides=["auth.oidc"], ui={"url": "https://dex.example.com"}))
    assert env_of(generic)["GF_AUTH_GENERIC_OAUTH_TOKEN_URL"].startswith("<token_endpoint from https://dex.example.com/.well-known")
    assert any("placeholders" in s for s in generic.steps)


@pytest.mark.parametrize("tool_id,binary", [("gitea", "gitea"), ("forgejo", "forgejo")])
def test_gitea_and_forgejo_add_an_oauth_source(tool_id, binary):
    config = generate(app(tool_id))
    script = config.files[0].content
    assert config.redirect_uris == ["http://localhost:3000/user/oauth2/keycloak/callback"]
    for part in ("ARGS=(admin auth add-oauth --name keycloak", f'  {binary} "${{ARGS[@]}}"', "--provider openidConnect", "--key hub-" + tool_id, f"--secret '{CLIENT_SECRET}'",
                 "--auto-discover-url http://localhost:8080/realms/hub/.well-known/openid-configuration",
                 f'docker exec -u git "${{{binary.upper()}_CONTAINER}}" {binary}'):
        assert part in script


def test_minio_bookstack_outline_and_nextcloud():
    minio = generate(app("minio", 9001))
    env = env_of(minio)
    assert minio.redirect_uris == ["http://localhost:9001/oauth_callback"]
    assert env["MINIO_IDENTITY_OPENID_CONFIG_URL"] == "http://localhost:8080/realms/hub/.well-known/openid-configuration"
    assert env["MINIO_IDENTITY_OPENID_CLIENT_SECRET"] == CLIENT_SECRET and env["MINIO_BROWSER_REDIRECT_URL"] == "http://localhost:9001"
    assert env["MINIO_IDENTITY_OPENID_SCOPES"] == "openid,profile,email"

    bookstack = generate(app("bookstack", 6875))
    env = env_of(bookstack)
    assert bookstack.redirect_uris == ["http://localhost:6875/oidc/callback"]
    assert (env["AUTH_METHOD"], env["OIDC_ISSUER"], env["OIDC_ISSUER_DISCOVER"]) == ("oidc", "http://localhost:8080/realms/hub", "true")
    assert any("https://" in s for s in bookstack.steps)  # BookStack refuses a plain-http issuer

    outline = generate(app("outline"))
    env = env_of(outline)
    assert outline.redirect_uris == ["http://localhost:3000/auth/oidc.callback"]
    assert env["OIDC_ISSUER_URL"] == "http://localhost:8080/realms/hub" and env["OIDC_USERNAME_CLAIM"] == "preferred_username"
    assert env["OIDC_LOGOUT_URI"].endswith("/protocol/openid-connect/logout")

    nextcloud = generate(app("nextcloud", 8081))
    script = nextcloud.files[0].content
    assert "occ app:install user_oidc || occ app:enable user_oidc" in script
    assert "occ user_oidc:provider Keycloak --clientid=hub-nextcloud" in script and "--discoveryuri=" in script
    assert nextcloud.redirect_uris[0] == "http://localhost:8081/apps/user_oidc/code"


@pytest.mark.parametrize("tool_id,security", [("wazuh-dashboard", "/etc/wazuh-indexer/opensearch-security"),
                                              ("opensearch-dashboards", "/usr/share/opensearch/config/opensearch-security")])
def test_wazuh_and_opensearch_dashboards(tool_id, security):
    config = generate(app(tool_id, 5601))
    files = {f.path: f.content for f in config.files}
    domain = yaml.safe_load(files["sso/opensearch-security-openid.yml"])["openid_auth_domain"]
    assert domain["http_authenticator"]["type"] == "openid" and domain["authentication_backend"]["type"] == "noop"
    assert domain["http_authenticator"]["config"]["openid_connect_url"].endswith("/realms/hub/.well-known/openid-configuration")
    dashboards = yaml.safe_load(files["sso/opensearch_dashboards.yml"])
    assert dashboards["opensearch_security.auth.type"] == ["basicauth", "openid"]
    assert dashboards["opensearch_security.openid.client_id"] == f"hub-{tool_id}"
    assert dashboards["opensearch_security.openid.client_secret"] == CLIENT_SECRET
    assert dashboards["opensearch_security.openid.base_redirect_url"] == "http://localhost:5601"
    assert f'SECURITY_DIR="${{SECURITY_DIR:-{security}}}"' in files["sso/apply-security-config.sh"]
    assert "securityadmin.sh" in files["sso/apply-security-config.sh"] and "-icl" in files["sso/apply-security-config.sh"]
    assert config.redirect_uris == ["http://localhost:5601/auth/openid/login"]


def test_ui_configured_tools_ciso_assistant_snipe_it_and_zammad():
    ciso = generate(app("ciso-assistant", 8443))
    assert ciso.redirect_uris == ["http://localhost:8443/api/accounts/oidc/openid_connect/login/callback/"]
    assert "Server URL: `http://localhost:8080/realms/hub/.well-known/openid-configuration`" in ciso.files[0].content

    snipe = generate(app("snipe-it", 8000))
    assert snipe.protocol == "saml" and snipe.entity_id == "http://localhost:8000"
    assert (snipe.acs_url, snipe.slo_url) == ("http://localhost:8000/saml/acs", "http://localhost:8000/saml/sls")
    assert "http://localhost:8080/realms/hub/protocol/saml/descriptor" in snipe.files[0].content
    assert sso_catalog.generate(app("snipe-it", 8000), list_providers([zitadel()])[0]) is None  # SAML only

    zammad = generate(app("zammad"))
    assert zammad.public_client and zammad.redirect_uris == ["http://localhost:3000/auth/openid_connect/callback"]
    assert CLIENT_SECRET not in zammad.files[0].content and "PKCE: yes" in zammad.files[0].content


@pytest.mark.parametrize("tool_id", ["uptime-kuma", "n8n", "mattermost"])
def test_tools_without_free_oidc_have_no_native_route(tool_id):
    assert sso_catalog.native(app(tool_id, auth={"sso": "oidc"}), list_providers([keycloak()])[0]) is None


def test_generic_strategy_fills_exactly_the_env_example_keys(tmp_path: Path):
    root = tmp_path / "board"
    root.mkdir()
    (root / "package.json").write_text(json.dumps({"name": "board", "scripts": {"start": "node index.js"}}))
    (root / "index.js").write_text("require('http').createServer().listen(4000)\n")
    (root / ".env.example").write_text(
        "PORT=4000\nOIDC_ISSUER=\nOIDC_CLIENT_ID=\nOIDC_CLIENT_SECRET=\nOIDC_REDIRECT_URI=http://localhost:4000/auth/sso/callback\n"
        "OIDC_SCOPES=openid,email\nOIDC_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_basic\nOAUTH2_PROVIDER_NAME=\n")
    m, _ = analyze_repo(root, "board", "Board")
    assert m.auth.env_keys == ["OAUTH2_PROVIDER_NAME", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET", "OIDC_ISSUER",
                               "OIDC_REDIRECT_URI", "OIDC_SCOPES", "OIDC_TOKEN_ENDPOINT_AUTH_METHOD"]
    tool = Tool(id="board", name="Board", source_type="local", source=str(root), path=str(root), manifest=m)
    config = generate(tool)
    env = env_of(config)
    assert set(env) == set(m.auth.env_keys)  # exactly the keys of the example, nothing else
    assert env["OIDC_ISSUER"] == "http://localhost:8080/realms/hub" and env["OIDC_CLIENT_ID"] == "hub-board"
    assert env["OIDC_CLIENT_SECRET"] == CLIENT_SECRET and env["OIDC_SCOPES"] == "openid,profile,email"
    assert env["OIDC_REDIRECT_URI"] == "http://localhost:4000/auth/sso/callback" and env["OAUTH2_PROVIDER_NAME"] == "Keycloak"
    assert env["OIDC_TOKEN_ENDPOINT_AUTH_METHOD"] == "client_secret_basic"  # unknown key: kept, and flagged
    assert config.redirect_uris == ["http://localhost:4000/auth/sso/callback"]
    assert any("OIDC_TOKEN_ENDPOINT_AUTH_METHOD" in s for s in config.steps)


# -- strategy selection ----------------------------------------------------------------------


def fix(tool: Tool, others: list[Tool], idp: IdentityPrefs | None = None):
    check = sso_check(tool, others, idp)
    return check.status, check.fix, check.detail


def test_strategies_per_case(plain_repo: Path):
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    notes = Tool(id="notes", name="Notes", source_type="local", source=str(plain_repo), path=str(plain_repo), manifest=m)

    status, strategy, detail = fix(notes, [])  # no identity provider in the suite
    assert (status, strategy) == ("fail", "sso_proxy") and "Import an identity provider" in detail
    assert fix(app("crm", auth={"sso": "oidc"}), [])[:2] == ("pass", None)

    kc = keycloak()
    assert fix(app("grafana"), [kc])[:2] == ("warn", "sso_connect")
    assert fix(notes, [kc], IdentityPrefs(llm=True))[:2] == ("fail", "sso_code")
    assert fix(notes, [kc])[:2] == ("fail", "sso_proxy")  # no Claude: the proxy
    status, strategy, detail = fix(app("uptime-kuma"), [kc], IdentityPrefs(llm=True))
    assert strategy == "sso_proxy" and "no single sign-on" in detail.lower()
    status, strategy, detail = fix(app("snipe-it", 8000), [zitadel()])
    assert strategy == "sso_proxy" and "SAML only" in detail
    assert fix(app("crm", auth={"sso": "oidc"}), [kc])[:2] == ("warn", "sso_connect")  # supports OIDC, not connected yet
    assert fix(app("crm", auth={"sso": "oidc", "provider": "keycloak"}), [kc])[0] == "pass"
    assert fix(kc, [app("crm")])[0] == "pass"  # the provider itself

    saas = make_tool("crm-cloud", kind="saas", ui={"url": "https://crm.example.com"})
    assert fix(saas, [kc])[1] is None
    assert fix(make_tool("crm-cloud", kind="saas", auth={"sso": "oidc"}, ui={"url": "https://crm.example.com"}), [kc])[1] == "sso_connect"

    two = [kc, authentik()]
    status, strategy, detail = fix(app("grafana"), two)
    assert strategy is None and "2 identity providers" in detail and "Choose" in detail
    assert fix(app("grafana"), two, IdentityPrefs(default="authentik"))[1] == "sso_connect"
    status, strategy, detail = fix(app("grafana", auth={"sso": "oidc", "provider": "keycloak"}), two,
                                   IdentityPrefs(choices={"grafana": "authentik"}))
    assert strategy == "sso_connect" and detail.startswith("Connected to Keycloak, but Authentik is selected.")


def test_identity_links_come_from_auth_provider():
    kc = keycloak()
    wiki = app("wiki", auth={"sso": "oidc", "provider": "keycloak"}, consumes=["auth.oidc"])
    other = app("other", auth={"sso": "oidc"})  # supports OIDC but is not connected: no identity link
    links = {(l["source"], l["target"], l["type"]) for l in suite_matrix([kc, wiki, other])["links"]}
    assert ("keycloak", "wiki", "identity") in links and ("keycloak", "other", "identity") not in links
    assert next(c for c in evaluate_tool(wiki, [kc, other]).checks if c.id == "sso").status == "pass"


# -- patches and secrets ---------------------------------------------------------------------


def test_sso_connect_patch_configures_both_sides_and_secrets_stay_in_the_workspace(tmp_path: Path):
    kc_dir = compose_dir(tmp_path, "kc", {"keycloak": {"image": "quay.io/keycloak/keycloak:26.0", "ports": ["8080:8080"]}})
    grafana = app("grafana")
    patch = plan_patch(grafana, [keycloak(str(kc_dir))], "sso_connect", "http://x")
    assert patch.target == "adapter" and patch.strategy == "sso_connect" and patch.title == "Connect to Keycloak (OIDC)"
    paths = [c.path for c in patch.changes]
    assert paths == ["sso/grafana.env", "idp/keycloak/keycloak-client.json", "idp/keycloak/register-keycloak.sh",
                     "idp/keycloak/register-keycloak-compose.sh"]
    assert patch.manifest_update["auth"]["provider"] == "keycloak" and patch.manifest_update["auth"]["sso"] == "oidc"
    assert patch.sso.register_script == "idp/keycloak/register-keycloak-compose.sh"
    assert patch.sso.redirect_uris == ["http://localhost:3000/login/generic_oauth"]
    client = json.loads(patch.changes[1].content)
    assert (client["clientId"], client["protocol"], client["publicClient"]) == ("hub-grafana", "openid-connect", False)
    assert client["redirectUris"] == ["http://localhost:3000/login/generic_oauth"] and client["secret"] == CLIENT_SECRET
    assert client["protocolMappers"][0]["config"]["claim.name"] == "groups"
    compose_script = patch.changes[3].content
    # defaults are quoted assignments; the environment can override them
    assert f"COMPOSE_DIR_DEFAULT={kc_dir.as_posix()}\n" in compose_script
    assert 'COMPOSE_DIR="${KEYCLOAK_COMPOSE_DIR:-$COMPOSE_DIR_DEFAULT}"' in compose_script
    assert "SERVICE_DEFAULT=keycloak\n" in compose_script and 'SERVICE="${KEYCLOAK_SERVICE:-$SERVICE_DEFAULT}"' in compose_script
    assert "docker compose exec -T" in compose_script
    assert "kc create clients" in compose_script and 'kc update "clients/$ID"' in compose_script
    assert ": \"${KEYCLOAK_ADMIN_USER:?" in patch.changes[2].content

    hub = FakeHub(tmp_path / "ws", grafana)
    applied = asyncio.run(apply_patch(hub, patch))
    workspace = tmp_path / "ws"
    value = secret_of(workspace, "grafana", "keycloak")
    root = workspace / "adapters" / "grafana"
    assert f"GF_AUTH_GENERIC_OAUTH_CLIENT_SECRET={value}" in (root / "sso/grafana.env").read_text()
    assert json.loads((root / "idp/keycloak/keycloak-client.json").read_text())["secret"] == value
    assert applied.sso.register_command == f'bash "{(root / "idp/keycloak/register-keycloak-compose.sh").as_posix()}"'
    assert hub.tool.manifest.auth.provider == "keycloak" and hub.tool.manifest.auth.sso == "oidc"
    # the patch itself (what the API shows and the diff reviewers read) never carries the secret
    assert value not in applied.model_dump_json() and value not in render_diff(grafana, applied)
    assert CLIENT_SECRET in render_diff(grafana, applied)

    again = plan_patch(grafana, [keycloak(str(kc_dir))], "sso_connect", "http://x")
    asyncio.run(apply_patch(hub, again))
    assert secret_of(workspace, "grafana", "keycloak") == value  # generated once per tool and provider


def test_authentik_blueprint_and_saml_clients(tmp_path: Path):
    ak_dir = compose_dir(tmp_path, "ak", {"server": {"image": "ghcr.io/goauthentik/server:2025.8"},
                                          "worker": {"image": "ghcr.io/goauthentik/server:2025.8", "command": "worker"}})
    patch = plan_patch(app("grafana"), [authentik(str(ak_dir))], "sso_connect", "http://x")
    files = {c.path: c.content for c in patch.changes}
    blueprint = yaml.load(files["idp/authentik/authentik-blueprint.yaml"], Loader=Tagged)
    provider, application = blueprint["entries"][0], blueprint["entries"][1]
    assert blueprint["version"] == 1 and provider["model"] == "authentik_providers_oauth2.oauth2provider"
    attrs = provider["attrs"]
    assert (attrs["client_id"], attrs["client_secret"], attrs["client_type"]) == ("hub-grafana", CLIENT_SECRET, "confidential")
    assert attrs["redirect_uris"] == [{"matching_mode": "strict", "url": "http://localhost:3000/login/generic_oauth"}]
    assert attrs["authorization_flow"] == ("Find", ["authentik_flows.flow", ["slug", "default-provider-authorization-implicit-consent"]])
    assert attrs["invalidation_flow"][1][1] == ["slug", "default-provider-invalidation-flow"]
    assert application["model"] == "authentik_core.application" and application["identifiers"] == {"slug": "hub-grafana"}
    assert application["attrs"]["provider"] == ("KeyOf", "provider")
    assert patch.sso.issuer == "https://auth.example.com/application/o/hub-grafana/"
    assert patch.sso.register_script == "idp/authentik/register-authentik-compose.sh"
    script = files["idp/authentik/register-authentik-compose.sh"]
    assert "SERVICE_DEFAULT=worker\n" in script and 'SERVICE="${AUTHENTIK_SERVICE:-$SERVICE_DEFAULT}"' in script
    assert 'ak apply_blueprint "$FILE"' in script

    snipe = plan_patch(app("snipe-it", 8000), [keycloak()], "sso_connect", "http://x")
    client = json.loads(next(c.content for c in snipe.changes if c.path.endswith("keycloak-client.json")))
    assert (client["clientId"], client["protocol"]) == ("http://localhost:8000", "saml")
    assert client["attributes"]["saml_assertion_consumer_url_post"] == "http://localhost:8000/saml/acs"
    assert "secret" not in client and snipe.sso.protocol == "saml" and snipe.manifest_update["auth"]["sso"] == "saml"
    saml = plan_patch(app("snipe-it", 8000), [authentik()], "sso_connect", "http://x")
    entry = yaml.load(saml.changes[-1].content, Loader=Tagged)["entries"][0]
    assert entry["model"] == "authentik_providers_saml.samlprovider"
    assert (entry["attrs"]["acs_url"], entry["attrs"]["audience"]) == ("http://localhost:8000/saml/acs", "http://localhost:8000")

    zammad = plan_patch(app("zammad"), [keycloak()], "sso_connect", "http://x")
    client = json.loads(next(c.content for c in zammad.changes if c.path.endswith("keycloak-client.json")))
    assert client["publicClient"] is True and "secret" not in client


def test_generic_provider_gets_registration_instructions():
    provider = make_tool("authelia", provides=["auth.oidc"], ui={"url": "https://auth.example.org"})
    patch = plan_patch(app("outline"), [provider], "sso_connect", "http://x")
    files = {c.path: c.content for c in patch.changes}
    text = files["idp/authelia/REGISTER.md"]
    assert "Client ID: `hub-outline`" in text and "http://localhost:3000/auth/oidc.callback" in text
    assert "identity_providers.oidc.clients" in text and patch.sso.register_script is None
    env = env_of(SimpleNamespace(files=[FileChange(path="x.env", content=files["sso/outline.env"])]))
    assert env["OIDC_AUTH_URI"] == "https://auth.example.org/api/oidc/authorization"


def test_sso_proxy_uses_the_selected_provider_and_registers_the_proxy(tmp_path: Path):
    tool = app("kuma", 3001)
    patch = plan_patch(tool, [authentik()], "sso_proxy", "http://x")
    files = {c.path: c.content for c in patch.changes}
    assert "OIDC_ISSUER_URL=https://auth.example.com/application/o/hub-kuma/" in files["sso-proxy/.env"]
    assert patch.manifest_update["auth"] == {"sso": "oidc", "notes": "via oauth2-proxy adapter", "provider": "authentik"}
    assert "idp/authentik/authentik-blueprint.yaml" in files and patch.sso.provider == "authentik"
    hub = FakeHub(tmp_path / "ws", tool)
    asyncio.run(apply_patch(hub, patch))
    env = (tmp_path / "ws" / "adapters" / "kuma" / "sso-proxy" / ".env").read_text()
    cookie = next(line.split("=", 1)[1] for line in env.splitlines() if line.startswith("COOKIE_SECRET="))
    assert len(cookie) == 44 and secret_of(tmp_path / "ws", "kuma", "authentik") in env
    assert "change-me" in files["sso-proxy/.env.example"]  # the example stays a template


def test_sso_code_patch_keeps_the_secret_out_of_the_repository(tmp_path: Path, plain_repo: Path):
    git = ["git", "-C", str(plain_repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(plain_repo)], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    tool = Tool(id="notes", name="Notes", source_type="local", source=str(plain_repo), path=str(plain_repo), manifest=m)
    provider = list_providers([keycloak()])[0]
    code = Patch(id="p_code000001", tool_id="notes", title="Add OIDC login", rationale="Sign in through the suite.",
                 strategy="sso_code", target="repo",
                 changes=[FileChange(path="app.py", content="import os\nISSUER = os.environ['OIDC_ISSUER']\n")])
    patch = attach_sso(tool, provider, code)
    assert [c.path for c in patch.adapter_changes][:2] == ["sso/oidc.env", "idp/keycloak/keycloak-client.json"]
    assert patch.sso.redirect_uris == ["http://localhost:5000/auth/oidc/callback"]
    assert patch.manifest_update["auth"]["provider"] == "keycloak"
    diff = render_diff(tool, patch)
    assert "hub-adapter/sso/oidc.env" in diff and "+++ b/app.py" in diff

    hub = FakeHub(tmp_path / "ws", tool)
    applied = asyncio.run(apply_patch(hub, patch))
    value = secret_of(tmp_path / "ws", "notes", "keycloak")
    assert f"OIDC_CLIENT_SECRET={value}" in (tmp_path / "ws" / "adapters" / "notes" / "sso" / "oidc.env").read_text()
    committed = subprocess.run([*git, "log", "-p", "--all"], capture_output=True, text=True).stdout
    assert applied.branch and value not in committed and CLIENT_SECRET not in committed

    leaky = Patch(id="p_code000002", tool_id="notes", title="x", rationale="y", strategy="sso_code", target="repo",
                  changes=[FileChange(path="settings.py", content=f"SECRET = '{value}'\n")], sso=patch.sso)
    with pytest.raises(ValueError, match="client secret"):
        asyncio.run(apply_patch(hub, leaky))
    with pytest.raises(ValueError, match="secrets"):
        attach_sso(tool, provider, Patch(id="p_3", tool_id="notes", title="x", rationale="y", strategy="sso_code",
                                         target="repo", changes=[FileChange(path="a.py", content=CLIENT_SECRET)]))


def test_secret_files_and_identifiers_are_safe(tmp_path: Path):
    assert identity.secret(tmp_path, "crm", "keycloak") == identity.secret(tmp_path, "crm", "keycloak")
    assert identity.secret(tmp_path, "crm", "keycloak") != identity.secret(tmp_path, "crm", "authentik")
    with pytest.raises(ValueError):
        identity.secret(tmp_path, "../x", "keycloak")


def _stub(bin_dir: Path, name: str, log: Path) -> None:
    """An executable `name` that logs its arguments, one per line, and succeeds."""
    bin_dir.mkdir(exist_ok=True)
    path = bin_dir / name
    path.write_text(f'#!/usr/bin/env bash\nfor a in "$@"; do printf "%s\\n" "$a" >> {log.as_posix()!r}; done\n')
    path.chmod(0o755)


def _run_script(folder: Path, files: list[FileChange], script: str, bin_dir: Path, **env: str) -> None:
    for f in files:
        (folder / f.path).parent.mkdir(parents=True, exist_ok=True)
        (folder / f.path).write_text(f.content)
    environ = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(folder), "ATRIUM_MARK": str(folder.parent / "PWNED"), **env}
    done = subprocess.run(["bash", str(folder / script)], cwd=folder, env=environ, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr


def test_register_scripts_never_run_values_from_a_repository(tmp_path: Path, monkeypatch):
    """Review finding: a compose service named 'keycloak$(...)', a manifest URL with $(...) or a tool name with a line
    break went into the generated register script, which the Register button runs with bash on the hub."""
    mark = tmp_path / "PWNED"
    payload = "$(touch $ATRIUM_MARK)"  # _run_script points ATRIUM_MARK at `mark`
    kc_dir = compose_dir(tmp_path, "kc", {f"keycloak{payload}": {"image": "quay.io/keycloak/keycloak:26.0"}})
    hostile = make_tool("keycloak", name=f"Keycloak\ntouch {mark.as_posix()}", provides=["auth.oidc"],
                        ui={"url": f"http://kc.example.com/{payload}"}, path=str(kc_dir))
    grafana = make_tool("grafana", name=f"Grafana\ntouch {mark.as_posix()}", launch={"port": 3000},
                        ui={"url": "http://localhost:3000"})

    # 1. the values are refused at the source: the URL counts as unknown, the service name is never used
    provider = list_providers([hostile])[0]
    assert provider.base_url == identity.PLACEHOLDER_BASE and not provider.configured
    assert identity.compose_target(provider) is None
    with pytest.raises(ValueError, match="plain address"):
        identity.validate_setting("base_url", f"http://kc.example.com/{payload}")
    assert list_providers([hostile], {"keycloak": {"base_url": "https://sso.example.com/`id`"}})[0].base_url == identity.PLACEHOLDER_BASE
    patch = plan_patch(grafana, [hostile], "sso_connect", "http://x")
    assert patch.sso.register_script == "idp/keycloak/register-keycloak.sh"
    files = [c for c in patch.changes if c.path.startswith("idp/")]
    for f in files:  # no name breaks out of a comment line
        assert not any(line.startswith("touch ") for line in f.content.splitlines()), f.path
    log, bin_dir = tmp_path / "calls.log", tmp_path / "bin"
    _stub(bin_dir, "kcadm.sh", log)
    _run_script(tmp_path / "out1", files, "idp/keycloak/register-keycloak.sh", bin_dir,
                KEYCLOAK_ADMIN_USER="admin", KEYCLOAK_ADMIN_PASSWORD="pw")
    assert not mark.exists() and identity.PLACEHOLDER_BASE in log.read_text().splitlines()

    # 2. and quoted where they are written, should one ever get through: run both Keycloak scripts and the authentik one
    odd_dir = tmp_path / f"compose {payload}"
    odd_dir.mkdir()
    monkeypatch.setattr(identity, "compose_target", lambda p: (odd_dir.as_posix(), f"kc{payload}"))
    for kind in ("keycloak", "authentik"):
        raw = identity.IdentityProvider(tool_id=kind, name=f"{kind}\ntouch {mark.as_posix()}", kind=kind,
                                        base_url=f"http://kc.example.com/{payload}", configured=True,
                                        protocols=["oidc"], issuer="x", settings={"realm": f"hub{payload}"}, path="x")
        spec = identity.ClientSpec(client_id=f"hub-x{payload}", name=f"X\ntouch {mark.as_posix()}",
                                   redirect_uris=["http://localhost:3000/cb"], app_slug="hub-x", groups=[f"g{payload}"])
        reg = identity.registration(raw, spec, "")
        log.unlink(missing_ok=True)
        _stub(bin_dir, "docker", log)
        _run_script(tmp_path / f"out-{kind}", reg.files, reg.script, bin_dir)
        assert not mark.exists(), kind
        calls = log.read_text().splitlines()
        assert f"kc{payload}" in calls  # the service, passed literally
        if kind == "keycloak":
            assert f"hub{payload}" in calls and f"g{payload}" in " ".join(calls)
            log.unlink()
            _run_script(tmp_path / f"out-{kind}", reg.files, "register-keycloak.sh", bin_dir, KCADM=str(bin_dir / "kcadm.sh"),
                        KEYCLOAK_ADMIN_USER="admin", KEYCLOAK_ADMIN_PASSWORD="pw")
            assert not mark.exists() and f"http://kc.example.com/{payload}" in log.read_text().splitlines()
        else:
            assert "custom/atrium-hub-x.yaml" in calls


def test_names_cannot_add_lines_to_generated_env_files():
    text = sso_catalog.env_text("Grafana\nOIDC_ISSUER=https://evil.example.com", {"OIDC_ISSUER": "https://good.example.com"},
                                {"OIDC_ISSUER": "issuer\nEXTRA=1"})
    lines = text.splitlines()
    assert "OIDC_ISSUER=https://good.example.com" in lines
    assert not any(line.startswith(("OIDC_ISSUER=https://evil", "EXTRA=")) for line in lines)
