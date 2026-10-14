from pathlib import Path

import pytest
import yaml

from hub.integration.analyzer import analyze_repo, list_files


def test_node_app_is_understood(node_repo: Path):
    m, notes = analyze_repo(node_repo, "crm-app", "CRM App")
    assert m.kind == "oss"
    assert m.version == "2.3.1"
    assert m.license == "MIT"
    assert "node" in m.stack and "docker" in m.stack
    assert m.launch.port == 4000
    assert m.launch.command == "npm start" and m.launch.setup == "npm install"
    assert m.health.url == "http://localhost:4000/healthz"
    assert m.auth.sso == "oidc"
    assert "api.rest" in m.provides and "webhooks" in m.provides
    assert {"db.postgres", "notify.email"} <= set(m.consumes)
    assert m.events.emits == ["crm-app.*"]
    assert m.description.startswith("A tiny CRM")
    assert not m.native


def test_plain_flask_app_has_gaps(plain_repo: Path):
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    assert "python" in m.stack
    assert m.launch.port == 5000
    assert m.launch.command.startswith("flask run")
    assert m.health.url is None
    assert m.auth.sso == "none"
    assert "cache.redis" in m.consumes


def test_native_manifest_wins(node_repo: Path):
    (node_repo / "hub.manifest.yaml").write_text(yaml.safe_dump({
        "name": "CRM", "launch": {"port": 4100}, "events": {"listens": ["billing.*"]},
    }))
    m, notes = analyze_repo(node_repo, "crm-app", "CRM App")
    assert m.native
    assert m.launch.port == 4100
    assert m.launch.command == "npm start"  # inferred values survive where the manifest is silent
    assert m.events.listens == ["billing.*"]
    assert any("native" in n for n in notes)


def test_closed_source_folder(tmp_path: Path):
    root = tmp_path / "vendor-app"
    root.mkdir()
    (root / "VendorApp.exe").write_bytes(b"MZ\x00\x00")
    (root / "engine.dll").write_bytes(b"MZ\x00\x00")
    m, notes = analyze_repo(root, "vendor-app", "Vendor App")
    assert m.kind == "closed"
    assert m.launch.command == '"VendorApp.exe"'


def test_identity_provider_is_recognised(tmp_path: Path):
    root = tmp_path / "keycloak"
    root.mkdir()
    (root / "docker-compose.yml").write_text(yaml.safe_dump({
        "services": {"keycloak": {"image": "quay.io/keycloak/keycloak", "ports": ["8080:8080"]}}
    }))
    m, _ = analyze_repo(root, "keycloak", "Keycloak")
    assert "auth.oidc" in m.provides
    assert m.auth.sso == "oidc"
    assert m.launch.port == 8080
    assert m.launch.command == "docker compose up"


@pytest.mark.parametrize("folder,service,image,capabilities", [
    ("greenbone-community", "gvmd", "registry.community.greenbone.net/community/gvmd:stable", {"vuln.scanner"}),
    ("openvas", "openvas", "immauss/openvas", {"vuln.scanner"}),
    ("ciso-assistant-community", "backend", "ghcr.io/intuitem/ciso-assistant-community/backend", {"grc.compliance", "grc.risks"}),
    ("snipe-it", "app", "snipe/snipe-it", {"assets.inventory"}),
    ("keycloak", "keycloak", "quay.io/keycloak/keycloak", {"auth.oidc", "identity.source"}),
])
def test_fabric_tools_are_recognised(tmp_path: Path, folder, service, image, capabilities):
    root = tmp_path / folder
    root.mkdir()
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": {service: {"image": image}}}))
    m, _ = analyze_repo(root, folder, folder)
    assert capabilities <= set(m.provides)


def test_list_files_skips_vendored_directories(node_repo: Path):
    (node_repo / "node_modules" / "x").mkdir(parents=True)
    (node_repo / "node_modules" / "x" / "index.js").write_text("")
    assert not any("node_modules" in f.parts for f in list_files(node_repo))


def test_symbolic_links_never_lead_the_hub_out_of_a_repository(tmp_path: Path):
    """Review finding: a README.md linking to ../../../secret.key became the tool's description, shown to every
    viewer and sent to the model. No reader of repository files may follow a link out of the repository."""
    import asyncio
    from types import SimpleNamespace

    from hub.agents.patcher import load_openapi, render_diff
    from hub.agents.tool_supervisor import ToolSupervisor
    from hub.integration import identity, sso_catalog
    from hub.integration.analyzer import read_repo_file
    from hub.models import FileChange, Manifest, Patch, Tool

    secret = "SECRET-MASTER-KEY-0123456789 is the first paragraph of the key file and long enough to be one"
    outside = tmp_path / "data"
    (outside / "dir").mkdir(parents=True)
    (outside / "secret.key").write_text(secret + "\n")
    (outside / "manifest.yaml").write_text(yaml.safe_dump({"name": secret, "description": secret}))
    (outside / "compose.yml").write_text(yaml.safe_dump({"services": {"keycloak": {"image": "keycloak", "environment": {"S": secret}}}}))
    (outside / "env").write_text(f"OIDC_CLIENT_SECRET={secret}\n")
    (outside / "dir" / "openapi.yaml").write_text(yaml.safe_dump({"openapi": "3.0.0", "info": {"title": secret}, "paths": {}}))
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("print('hi')\n")
    for name, target in (("README.md", "secret.key"), ("LICENSE", "secret.key"), ("hub.manifest.yaml", "manifest.yaml"),
                         ("docker-compose.yml", "compose.yml"), (".env.example", "env"), ("main.py", "secret.key")):
        (repo / name).symlink_to(outside / target)
    (repo / "docs").symlink_to(outside / "dir", target_is_directory=True)

    assert read_repo_file(repo, "README.md") is None and read_repo_file(repo, "docs/openapi.yaml") is None
    assert read_repo_file(repo, "app.py") == "print('hi')\n"
    m, notes = analyze_repo(repo, "evil", "Evil")
    assert secret not in m.model_dump_json() and not m.native and m.license is None

    tool = Tool(id="evil", name="Evil", source_type="github", source="https://github.com/x/evil", path=str(repo),
                manifest=m.model_copy(update={"provides": ["auth.oidc"], "kind": "oss"}))
    provider = identity.make_provider(tool)
    assert identity.compose_target(provider) is None  # the linked compose file is not read
    assert sso_catalog.env_example(tool) == {}

    prompts: list[str] = []

    async def fake_json(**kw):
        prompts.append(kw["prompt"])
        return {"description": "", "provides": [], "consumes": []}

    fake = SimpleNamespace(instructions="", model="m", hub=SimpleNamespace(llm=SimpleNamespace(json=fake_json)))
    asyncio.run(ToolSupervisor._enrich(fake, Manifest(id="evil", name="Evil"), repo))
    assert prompts and secret not in prompts[0]

    spec_tool = tool.model_copy(update={"manifest": m.model_copy(update={"api": m.api.model_copy(update={"spec": "docs/openapi.yaml"})})})
    with pytest.raises(ValueError, match="missing"):
        asyncio.run(load_openapi(spec_tool))
    patch = Patch(id="p_1", tool_id="evil", title="t", rationale="r", strategy="sso_code", target="repo",
                  changes=[FileChange(path="README.md", content="new\n"), FileChange(path="docs/openapi.yaml", content="x\n")])
    assert secret not in render_diff(tool, patch)


def test_saas_import_of_a_well_known_tool_gets_its_capabilities():
    """A hosted Keycloak or Okta is an identity provider like a cloned one: SaaS imports apply the well-known tools by
    id, name or host name too (before, only repository analysis did, so a SaaS identity provider was never one)."""
    import asyncio

    from hub.integration import identity
    from hub.integration.analyzer import analyze_saas
    from hub.models import Tool

    def saas(tool_id: str, name: str, url: str):
        m, notes = asyncio.run(analyze_saas(tool_id, name, url, None))
        return m, notes, Tool(id=tool_id, name=name, source_type="saas", source=url, manifest=m)

    m, notes, tool = saas("okta", "Okta", "https://acme.okta.com")
    assert {"auth.oidc", "auth.saml", "identity.source"} <= set(m.provides) and m.auth.sso == "oidc"
    assert identity.is_provider(tool) and any("well-known" in n for n in notes)
    m, _, tool = saas("company-login", "Company login", "https://keycloak.example.com")  # by its host name
    assert identity.is_provider(tool) and identity.provider_kind(tool) == "keycloak"
    m, _, _ = saas("assets", "Snipe-IT", "https://assets.example.com")
    assert m.provides == ["assets.inventory"] and m.auth.sso == "unknown"
    m, notes, tool = saas("crm", "Sales CRM", "https://crm.example.com")  # nothing known: nothing claimed
    assert m.provides == [] and m.auth.sso == "unknown" and not identity.is_provider(tool)
    assert notes == ["No OpenAPI spec given - its API is unknown until one is added."]
