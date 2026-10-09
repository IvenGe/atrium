from pathlib import Path

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


def test_list_files_skips_vendored_directories(node_repo: Path):
    (node_repo / "node_modules" / "x").mkdir(parents=True)
    (node_repo / "node_modules" / "x" / "index.js").write_text("")
    assert not any("node_modules" in f.parts for f in list_files(node_repo))
