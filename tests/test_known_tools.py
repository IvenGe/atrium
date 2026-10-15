"""Known-product profiles (hub/integration/known_tools.py) and the analyzer's generic fallbacks.

Every fixture is built in tmp_path: a Keycloak source checkout, release folder and compose folder, SaaS hosts, and
large synthetic trees for the listing order, the deep OpenAPI search and the time budget."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
import yaml

from hub import connectors
from hub.integration import identity, known_tools
from hub.integration.analyzer import (
    KNOWN_TOOLS, MAX_FILES, analyze_repo, analyze_saas, bin_launchers, find_spec, list_files, placeholder,
)
from hub.models import Manifest, Tool

DOCS_API = "https://www.keycloak.org/docs-api/latest/rest-api/openapi.json"
# the recipe publishes on loopback only: Docker would otherwise publish past a host firewall (review)
KC_COMMAND = ("docker run --rm --name atrium-keycloak -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 "
              "-e KC_HEALTH_ENABLED=true "
              "-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD quay.io/keycloak/keycloak:26.0 "
              "start-dev")

# The former analyzer.KNOWN_TOOLS table, frozen: every name still gives exactly what it provided.
OLD_KNOWN_TOOLS = {
    "keycloak": ["auth.oidc", "auth.saml", "identity.source"], "okta": ["auth.oidc", "auth.saml", "identity.source"],
    "authentik": ["auth.oidc", "auth.saml"], "zitadel": ["auth.oidc"],
    "openvas": ["vuln.scanner"], "greenbone": ["vuln.scanner"], "gvm": ["vuln.scanner"],
    "ciso-assistant": ["grc.compliance", "grc.risks"], "snipeit": ["assets.inventory"],
    "authelia": ["auth.oidc"], "gitea": ["git.hosting", "webhooks"], "forgejo": ["git.hosting", "webhooks"],
    "gitlab": ["git.hosting", "ci", "webhooks"], "mattermost": ["chat", "webhooks"], "rocket.chat": ["chat", "webhooks"],
    "nextcloud": ["storage.files"], "minio": ["storage.s3"], "grafana": ["monitoring.dashboards"],
    "prometheus": ["monitoring.metrics"], "uptime-kuma": ["monitoring.uptime"], "wiki.js": ["docs.wiki"],
    "bookstack": ["docs.wiki"], "outline": ["docs.wiki"], "n8n": ["automation", "webhooks"],
    "glpi": ["assets.inventory", "ticketing"], "snipe-it": ["assets.inventory"], "zammad": ["ticketing"],
    "osticket": ["ticketing"], "vaultwarden": ["secrets.vault"], "mailpit": ["notify.email"], "mailhog": ["notify.email"],
    "postgres": ["db.postgres"], "redis": ["cache.redis"], "openldap": ["directory.ldap"],
}
NO_PROFILE = {"generic_rest", "scim", "fake_firewall", "hostfw", "windows_firewall"}


def keycloak_source(root: Path, version: str = "999.0.0-SNAPSHOT") -> Path:
    """The shape of a git checkout of keycloak/keycloak: a Maven parent pom, Java modules and a README."""
    (root / "quarkus").mkdir(parents=True)
    (root / "services").mkdir()
    (root / "pom.xml").write_text(
        "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <name>Keycloak</name>\n  <groupId>org.keycloak</groupId>\n"
        f"  <artifactId>keycloak-parent</artifactId>\n  <version>{version}</version>\n  <packaging>pom</packaging>\n"
        "</project>\n")
    (root / "quarkus" / "x.java").write_text("class X { String probe = \"/health\"; }\n")
    (root / "services" / "y.java").write_text("class Y {}\n")
    (root / "README.md").write_text("# Keycloak\n\nOpen Source Identity and Access Management for modern apps.\n")
    return root


def keycloak_release(root: Path) -> Path:
    """An unpacked Keycloak download: launchers, configuration, jars and version.txt."""
    for folder in ("bin", "conf", "lib"):
        (root / folder).mkdir(parents=True)
    (root / "bin" / "kc.sh").write_text("#!/bin/sh\nexec java -jar ../lib/quarkus-run.jar \"$@\"\n")
    (root / "bin" / "kc.bat").write_text("@echo off\r\n")
    (root / "conf" / "keycloak.conf").write_text("# db=postgres\n")
    (root / "lib" / "quarkus-run.jar").write_bytes(b"PK\x03\x04")
    (root / "version.txt").write_text("Keycloak - Version 26.0.5\n")
    return root


def keycloak_compose(root: Path, *, health_env: bool) -> Path:
    root.mkdir(parents=True)
    env = {"KC_BOOTSTRAP_ADMIN_USERNAME": "admin", "KC_BOOTSTRAP_ADMIN_PASSWORD": "change-me"}
    if health_env:
        env["KC_HEALTH_ENABLED"] = "true"
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": {
        "keycloak-db": {"image": "postgres:16"},
        "keycloak": {"image": "quay.io/keycloak/keycloak:25.0", "command": "start-dev", "environment": env,
                     "ports": ["8080:8080", "9000:9000"]},
    }}))
    return root


def saas(tool_id: str, name: str, url: str) -> Manifest:
    m, _ = asyncio.run(analyze_saas(tool_id, name, url, None))
    return m


# --------------------------------------------------------------------------------------
# Keycloak in its four shapes
# --------------------------------------------------------------------------------------


def test_keycloak_source_checkout_runs_the_official_image(tmp_path: Path):
    m, notes = analyze_repo(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak")
    assert (m.known.profile, m.known.shape, m.known.by) == ("keycloak", "source", "marker")
    assert m.launch.command is None and m.launch.port is None  # a source checkout is not built: the patch sets both
    assert m.api.type == "rest" and m.api.spec == DOCS_API
    assert "auth.oidc" in m.provides and "auth.oidc" not in m.consumes and m.auth.sso == "oidc"
    assert m.health.url is None  # the "/health" string in its source is not Keycloak's health endpoint
    assert any("Recognised Keycloak (source code)" in n for n in notes)

    plan = known_tools.launch_plan(m, "keycloak")
    assert plan.command == KC_COMMAND
    assert plan.secret_env == ("KC_BOOTSTRAP_ADMIN_PASSWORD",) and plan.env == {}
    assert plan.health_url == "http://localhost:9000/health/ready" and plan.port == 8080
    assert plan.api_base_url == "http://localhost:8080/admin/realms" and plan.requires == "Docker on the hub machine"
    assert plan.summary == "the official container image quay.io/keycloak/keycloak:26.0"
    health = known_tools.health_plan(m, "keycloak")
    assert health.via == "launch" and health.url == plan.health_url
    assert known_tools.describes(m) and "per realm" in known_tools.events_note(m)


@pytest.mark.parametrize("version,tag,admin,health,ports,api", [
    ("25.0.6", "25.0.6", "KEYCLOAK_ADMIN", "http://localhost:9000/health/ready", ["127.0.0.1:8080:8080", "127.0.0.1:9000:9000"],
     "/admin/realms"),
    ("24.0.5", "24.0.5", "KEYCLOAK_ADMIN", "http://localhost:8080/health/ready", ["127.0.0.1:8080:8080"], "/admin/realms"),
    ("16.1.1", "16.1.1", "KEYCLOAK_ADMIN", None, ["127.0.0.1:8080:8080"], "/auth/admin/realms"),  # loopback only
])
def test_keycloak_facts_follow_the_version(tmp_path: Path, version, tag, admin, health, ports, api):
    m, _ = analyze_repo(keycloak_source(tmp_path / "kc", version), "iam", "IAM")
    assert m.known.version == version and m.version == version
    plan = known_tools.launch_plan(m, "iam")
    assert f"quay.io/keycloak/keycloak:{tag} start-dev" in plan.command
    assert f"-e {admin}=admin" in plan.command and plan.secret_env == (f"{admin}_PASSWORD",)
    assert [p for p in plan.command.split() if ":" in p and p[0].isdigit()] == ports
    assert plan.health_url == health
    assert known_tools.api_info(m).base_path == api
    assert (known_tools.health_plan(m) is None) == (health is None)


def test_keycloak_release_folder_starts_with_its_launcher(tmp_path: Path):
    m, notes = analyze_repo(keycloak_release(tmp_path / "keycloak-26.0.5"), "keycloak", "Keycloak")
    assert m.kind == "oss" and {"java", "dist"} <= set(m.stack)  # jars + bin/ launchers: a distribution, not closed
    assert (m.known.shape, m.known.version, m.version) == ("release", "26.0.5", "26.0.5")
    assert m.launch.command == "bin/kc.sh start-dev" and m.launch.cwd == "." and m.launch.port == 8080
    assert m.health.url is None  # health needs KC_HEALTH_ENABLED: the health_config patch passes it
    plan = known_tools.health_plan(m, "keycloak")
    assert plan.via == "config" and plan.env == {"KC_HEALTH_ENABLED": "true"}
    assert plan.url == "http://localhost:9000/health/ready"
    assert m.api.base_url == "http://localhost:8080/admin/realms" and m.api.spec == DOCS_API
    assert m.ui.url == "http://localhost:8080"
    assert "Recognised Keycloak 26.0.5 (release folder)." in notes
    # once the launch environment switches it on, the URL works as found
    m.launch.env = {"KC_HEALTH_ENABLED": "true"}
    assert known_tools.health_plan(m).via == "builtin"


def test_keycloak_compose_folder_health_comes_from_the_compose_env(tmp_path: Path):
    m, _ = analyze_repo(keycloak_compose(tmp_path / "with", health_env=True), "keycloak", "Keycloak")
    assert m.known.shape == "compose" and m.known.version == "25.0" and m.version == "25.0"
    assert m.health.url == "http://localhost:9000/health/ready"
    assert m.launch.command == "docker compose up" and m.launch.port == 8080
    assert m.api.base_url == "http://localhost:8080/admin/realms"

    m, _ = analyze_repo(keycloak_compose(tmp_path / "without", health_env=False), "keycloak", "Keycloak")
    assert m.health.url is None
    plan = known_tools.health_plan(m)
    assert plan.via == "compose" and plan.url is None
    assert "KC_HEALTH_ENABLED=true" in plan.note and "9000" in plan.note and "compose file" in plan.note


def test_a_container_command_needs_its_own_flags_for_health(tmp_path: Path):
    m, _ = analyze_repo(keycloak_source(tmp_path / "kc"), "keycloak", "Keycloak")
    m.launch.command = "docker run --rm -p 8080:8080 quay.io/keycloak/keycloak:26.0 start-dev"
    plan = known_tools.health_plan(m)
    assert plan.url is None and plan.via not in ("config", "launch", "compose")
    assert "-e KC_HEALTH_ENABLED=true" in plan.note and "-p 127.0.0.1:9000:9000" in plan.note  # loopback (review)
    m.launch.command = known_tools.launch_plan(m, "keycloak").command
    assert known_tools.health_plan(m).url == "http://localhost:9000/health/ready"


def test_a_native_manifest_beats_the_profile_and_cannot_claim_hub_keys(tmp_path: Path):
    root = keycloak_source(tmp_path / "kc")
    (root / "hub.manifest.yaml").write_text(yaml.safe_dump({
        "name": "Company IAM", "native": False, "adopted": "hub/add-manifest-x",
        "known": {"profile": "okta", "shape": "saas", "by": "host"},
        "launch": {"command": "TODO: command that starts the tool", "port": 8443},
        "api": {"base_url": "https://iam.example.org/admin/realms", "spec": "docs/admin-api.yaml"},
        "health": {"url": "todo"},
    }))
    m, notes = analyze_repo(root, "iam", "IAM")
    assert m.native and m.adopted is None and m.known.profile == "keycloak"
    assert m.name == "Company IAM" and m.launch.port == 8443
    assert m.api.base_url == "https://iam.example.org/admin/realms" and m.api.spec == "docs/admin-api.yaml"
    assert m.health.url is None and "Ignored a TODO placeholder in hub.manifest.yaml: health.url" in notes
    assert m.launch.command is None
    assert "Ignored a TODO placeholder in hub.manifest.yaml: launch.command" in notes
    assert placeholder("todo later") and placeholder("  TODO") and not placeholder("bin/start.sh") and not placeholder(None)


def test_saas_hosts_get_the_api_under_their_address():
    m = saas("company-login", "Company login", "https://keycloak.example.com")
    assert (m.known.profile, m.known.shape, m.known.by) == ("keycloak", "saas", "host")
    assert m.api.base_url == "https://keycloak.example.com/admin/realms" and m.api.spec == DOCS_API
    assert m.launch.port is None and m.health.url == "https://keycloak.example.com"
    assert known_tools.launch_plan(m, "company-login") is None and known_tools.health_plan(m) is None
    m = saas("okta", "Okta", "https://acme.okta.com")
    assert m.api.base_url == "https://acme.okta.com/api/v1" and m.known.by == "name"
    m = saas("assets", "Snipe-IT", "https://assets.example.com")
    assert m.provides == ["assets.inventory"] and m.api.base_url == "https://assets.example.com/api/v1"


# --------------------------------------------------------------------------------------
# legacy behaviour and links to connectors and identity
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("name,provides", sorted(OLD_KNOWN_TOOLS.items()))
def test_every_former_known_tool_still_provides_what_it_did(tmp_path: Path, name, provides):
    root = tmp_path / "t"
    root.mkdir()
    m, _ = analyze_repo(root, "t", name)
    assert sorted(m.provides) == sorted(provides)
    assert sorted(KNOWN_TOOLS[name]) == sorted(provides)  # the derived back-compat table


def test_compose_service_names_add_capabilities_without_recognising_the_tool(tmp_path: Path):
    root = tmp_path / "app"
    root.mkdir()
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": {
        "web": {"image": "acme/app", "ports": ["8000:8000"]}, "redis": {"image": "redis:7"}}}))
    m, _ = analyze_repo(root, "app", "App")
    assert "cache.redis" in m.provides and m.known is None


def test_unknown_programs_keep_their_inferred_values(node_repo: Path, plain_repo: Path):
    m, _ = analyze_repo(node_repo, "crm-app", "CRM App")
    assert m.known is None and m.launch.command == "npm start" and m.launch.port == 4000
    assert m.health.url == "http://localhost:4000/healthz" and m.api.type == "rest"
    assert m.api.base_url == "http://localhost:4000"
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    assert m.known is None and m.launch.command.startswith("flask run") and m.launch.port == 5000
    assert m.health.url is None and m.api.type == "rest" and m.api.base_url == "http://localhost:5000"  # flask


def test_profiles_and_connectors_point_at_each_other(tmp_path: Path):
    assert all(p.connector in connectors.REGISTRY for p in known_tools.PROFILES.values() if p.connector)
    linked = {p.connector for p in known_tools.PROFILES.values()}
    assert set(connectors.REGISTRY) - NO_PROFILE <= linked

    m, _ = analyze_repo(keycloak_source(tmp_path / "iam"), "iam", "Identity")  # nothing in its names says Keycloak
    tool = Tool(id="iam", name="Identity", source_type="local", source=str(tmp_path / "iam"), path=str(tmp_path / "iam"),
                manifest=m)
    best = connectors.detect(tool)[0]
    assert best["kind"] == "keycloak" and best["score"] >= 50
    assert identity.provider_kind(tool) == "keycloak"
    assert known_tools.recognise_tool(tool).profile.id == "keycloak"


def test_a_guessed_port_gives_way_to_the_products_own(tmp_path: Path):
    root = tmp_path / "gitea"
    root.mkdir()
    (root / "go.mod").write_text("module code.gitea.io/gitea\n\ngo 1.22\n")
    (root / "main.go").write_text('package main\nfunc main() { route("/api/healthz") }\n')
    m, notes = analyze_repo(root, "gitea", "Gitea")
    assert (m.known.profile, m.known.shape, m.known.by) == ("gitea", "other", "name")
    assert m.launch.command == "go run ." and m.launch.port == 3000  # not the Go default 8080
    assert m.health.url == "http://localhost:3000/api/healthz" and not any("guessed" in n for n in notes)


def test_a_name_only_match_does_not_take_its_folders_version(tmp_path: Path):
    root = tmp_path / "keycloak"
    root.mkdir()
    (root / "pom.xml").write_text("<project><artifactId>keycloak-theme</artifactId><version>1.2.0</version></project>")
    (root / "version.txt").write_text("Version 1.2\n")
    m, _ = analyze_repo(root, "keycloak", "Keycloak")
    assert m.known.by == "name" and m.known.version is None  # its own version, not Keycloak's
    assert known_tools.api_info(m).base_path == "/admin/realms"
    # integration: a project merely named after the product is not recognised by its name (no false API or launch
    # facts); it keeps what the name gave before profiles existed
    m, _ = analyze_repo(root, "keycloak-theme", "Keycloak theme")
    assert m.known is None and m.api.type == "none" and "auth.oidc" in m.provides


def test_pick_takes_the_last_applicable_version():
    values = ((None, "a"), ("17", "b"), ("25", "c"))
    assert [known_tools.pick(values, v) for v in ("16.1", "17", "24.0.5", "25.0", "999.0.0-SNAPSHOT", None, "nightly")] \
        == ["a", "b", "b", "c", "c", "c", "c"]
    assert known_tools.pick((), "1.0") is None


def test_public_manifest_names_launch_secrets_without_values():
    m = Manifest(id="kc", name="Keycloak")
    m.launch.env = {"KC_HEALTH_ENABLED": "true"}
    m.launch.secret_env = ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    data = m.public()
    assert data["launch"]["env_keys"] == ["KC_BOOTSTRAP_ADMIN_PASSWORD", "KC_HEALTH_ENABLED"]
    assert "env" not in data["launch"]
    tool = Tool(id="kc", name="Keycloak", source_type="local", source="/x", manifest=m,
                manifest_overrides={"launch": {"command": "x", "env": {"PORT": "8081"}}, "health": {"url": "http://h"}})
    public = tool.public()
    assert "manifest_overrides" not in public and "8081" not in str(public)
    assert public["overridden"] == ["health.url", "launch.command", "launch.env.PORT"]


# --------------------------------------------------------------------------------------
# generic fallbacks for programs no profile knows
# --------------------------------------------------------------------------------------


def _files(root: Path, folder: str, count: int, suffix: str = ".txt") -> None:
    (root / folder).mkdir(parents=True, exist_ok=True)
    for n in range(count):
        (root / folder / f"f{n:05d}{suffix}").write_text("")


def test_listing_is_breadth_first_with_test_suites_last(tmp_path: Path):
    root = tmp_path / "big"
    _files(root, "tests/unit", 3000)
    _files(root, "src/app", 1990)
    (root / "api" / "v1").mkdir(parents=True)
    (root / "api" / "v1" / "openapi.json").write_text('{"openapi": "3.0.0", "paths": {"/a": {"get": {}}}}')
    (root / "README.md").write_text("# Big\n")
    files = list_files(root)
    assert len(files) == MAX_FILES and files[0] == Path("README.md")
    assert Path("api/v1/openapi.json") in files
    first_test = next(i for i, f in enumerate(files) if f.parts[0] == "tests")
    assert all(f.parts[0] != "tests" for f in files[:first_test]) and first_test == 1992
    m, _ = analyze_repo(root, "big", "Big")
    assert m.api.type == "rest" and m.api.spec == "api/v1/openapi.json" and m.api.endpoints == 1


def test_a_spec_past_the_listing_cap_is_found_but_not_copies(tmp_path: Path):
    root = tmp_path / "huge"
    _files(root, "a", MAX_FILES + 10)
    (root / "node_modules" / "x").mkdir(parents=True)
    (root / "node_modules" / "x" / "openapi.json").write_text("{}")
    (root / "tests").mkdir()
    (root / "tests" / "openapi.yaml").write_text("{}")
    assert find_spec(root) is None
    (root / "z" / "docs").mkdir(parents=True)
    (root / "z" / "docs" / "swagger.yaml").write_text(yaml.safe_dump({"swagger": "2.0", "paths": {}}))
    assert Path("z/docs/swagger.yaml") not in list_files(root)
    assert find_spec(root) == Path("z/docs/swagger.yaml")
    m, _ = analyze_repo(root, "huge", "Huge")
    assert m.api.type == "rest" and m.api.spec == "z/docs/swagger.yaml"


def test_a_release_folder_with_a_bin_launcher_is_runnable(tmp_path: Path):
    root = tmp_path / "vendor-server"
    (root / "bin").mkdir(parents=True)
    (root / "lib").mkdir()
    (root / "bin" / "run.sh").write_text("#!/bin/sh\n")
    (root / "bin" / "stop.sh").write_text("#!/bin/sh\n")
    (root / "bin" / "linked.sh").symlink_to(root / "bin" / "run.sh")
    (root / "lib" / "app.jar").write_bytes(b"PK")
    assert bin_launchers(root) == ["bin/run.sh", "bin/stop.sh"]
    m, notes = analyze_repo(root, "vendor-server", "Vendor server")
    assert m.kind == "oss" and {"java", "dist"} <= set(m.stack) and m.known is None
    assert m.launch.command == "bin/run.sh" and m.launch.cwd == "." and m.launch.port is None
    (root / "bin" / "vendor-server.sh").write_text("#!/bin/sh\n")
    assert analyze_repo(root, "vendor-server", "Vendor server")[0].launch.command == "bin/vendor-server.sh"


def test_quarkus_and_spring_builds_are_understood(tmp_path: Path):
    root = tmp_path / "orders"
    root.mkdir()
    (root / "pom.xml").write_text(
        "<project><groupId>com.acme</groupId><artifactId>orders</artifactId><version>1.0.0</version><dependencies>"
        "<dependency><groupId>io.quarkus</groupId><artifactId>quarkus-rest</artifactId></dependency>"
        "</dependencies></project>")
    m, notes = analyze_repo(root, "orders", "Orders")
    assert {"java", "quarkus"} <= set(m.stack) and m.launch.port == 8080 and m.api.type == "rest"
    assert "Port 8080 guessed from the quarkus default." in notes

    root = tmp_path / "billing"
    root.mkdir()
    (root / "build.gradle").write_text(
        "plugins { id 'org.springframework.boot' version '3.2.0' }\n"
        "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n")
    m, _ = analyze_repo(root, "billing", "Billing")
    assert {"java", "spring"} <= set(m.stack) and m.launch.port == 8080 and m.api.type == "rest"


def test_a_large_tree_is_analysed_within_the_time_budget(tmp_path: Path):
    root = keycloak_source(tmp_path / "kc13k")
    _files(root, "testsuite/integration", 6000, ".java")
    for n in range(7):
        _files(root, f"module{n}/src/main/java", 1000, ".java")
    started = time.monotonic()
    m, _ = analyze_repo(root, "keycloak", "Keycloak")
    assert time.monotonic() - started < 10
    assert m.known.profile == "keycloak" and m.health.url is None
    listed = list_files(root)
    assert [f.as_posix() for f in listed[:4]] == ["README.md", "pom.xml", "quarkus/x.java", "services/y.java"]
    assert not any(f.parts[0] == "testsuite" for f in listed)  # 7,000 module files fill the listing first


# --------------------------------------------------------------------------------------
# review regressions: no launcher, product or address from the wrong evidence
# --------------------------------------------------------------------------------------


def test_a_lone_deploy_or_stop_script_is_no_launch_command(tmp_path: Path):
    """Review R8: any single bin/*.sh became the launch command, in source repositories too - a deploy or stop script
    got a Launch PASS and ran when an administrator started the tool."""
    node = tmp_path / "shop"
    (node / "bin").mkdir(parents=True)
    (node / "package.json").write_text('{"name": "shop", "dependencies": {"express": "4"}}')
    (node / "index.js").write_text("require('express')().listen(3000)\n")
    (node / "bin" / "deploy.sh").write_text("#!/bin/sh\nrsync -a . prod:/srv\n")
    m, notes = analyze_repo(node, "shop", "Shop")
    assert m.launch.command is None and not any("launcher" in n for n in notes)
    (node / "bin" / "deploy.sh").rename(node / "bin" / "serve-it.sh")  # a source repo: no single-script guess either
    assert analyze_repo(node, "shop", "Shop")[0].launch.command is None
    dist = tmp_path / "vendor"
    (dist / "bin").mkdir(parents=True)
    (dist / "lib").mkdir()
    (dist / "lib" / "app.jar").write_bytes(b"PK")
    (dist / "bin" / "stop.sh").write_text("#!/bin/sh\n")
    assert analyze_repo(dist, "vendor", "Vendor")[0].launch.command is None
    (dist / "bin" / "vendorctl.sh").write_text("#!/bin/sh\n")  # a release folder's only plausible launcher
    assert analyze_repo(dist, "vendor", "Vendor")[0].launch.command == "bin/vendorctl.sh"


def test_a_compose_folder_is_recognised_by_the_image_it_runs(tmp_path: Path):
    """Review R9: a compose folder was recognised only when the tool's name named the product."""
    iam = tmp_path / "iam-stack"
    iam.mkdir()
    (iam / "docker-compose.yml").write_text(yaml.safe_dump({"services": {"keycloak": {
        "image": "quay.io/keycloak/keycloak:26.0", "command": "start-dev", "environment": {"KC_HEALTH_ENABLED": "true"},
        "ports": ["8080:8080", "9000:9000"]}}}))
    m, _ = analyze_repo(iam, "iam-stack", "IAM stack")
    assert (m.known.profile, m.known.shape, m.known.by, m.known.version) == ("keycloak", "compose", "image", "26.0")
    assert m.health.url == "http://localhost:9000/health/ready" and m.api.base_url == "http://localhost:8080/admin/realms"
    tool = Tool(id="iam-stack", name="IAM stack", source_type="local", source=str(iam), path=str(iam), manifest=m)
    assert identity.provider_kind(tool) == "keycloak"
    # the official authentik compose file (a server and a worker, PostgreSQL and Redis beside them) under another name
    idp = tmp_path / "idp"
    idp.mkdir()
    (idp / "docker-compose.yml").write_text(yaml.safe_dump({"services": {
        "postgresql": {"image": "docker.io/library/postgres:16-alpine"},
        "redis": {"image": "docker.io/library/redis:alpine"},
        "server": {"image": "${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2024.8.3}",
                   "command": "server", "ports": ["${COMPOSE_PORT_HTTP:-9000}:9000"]},
        "worker": {"image": "${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2024.8.3}",
                   "command": "worker"}}}))
    m, _ = analyze_repo(idp, "idp", "idp")
    assert m.known.profile == "authentik" and m.known.by == "image" and "auth.oidc" in m.provides
    assert "auth.oidc" not in m.consumes and m.launch.port == 9000
    # an app of its own beside a product, or two products: not recognised by image
    for services in ({"web": {"image": "acme/shop:1", "ports": ["8000:8000"]},
                      "keycloak": {"image": "quay.io/keycloak/keycloak:26.0", "ports": ["8080:8080"]}},
                     {"grafana": {"image": "grafana/grafana:11", "ports": ["3000:3000"]},
                      "prometheus": {"image": "prom/prometheus:v2", "ports": ["9090:9090"]}}):
        mixed = tmp_path / f"mixed{len(list(tmp_path.iterdir()))}"
        mixed.mkdir()
        (mixed / "docker-compose.yml").write_text(yaml.safe_dump({"services": services}))
        assert analyze_repo(mixed, "suite", "Suite")[0].known is None


def test_a_pom_that_only_names_keycloak_as_its_parent_is_not_keycloak(tmp_path: Path):
    """Review R11: a Keycloak theme or extension (keycloak-parent as its <parent> or as an imported BOM) was taken for
    Keycloak itself - an identity provider of the suite, run with the official image."""
    for pom in ("<project><parent><groupId>org.keycloak</groupId><artifactId>keycloak-parent</artifactId>"
                "<version>26.0.5</version></parent><artifactId>my-theme</artifactId></project>",
                "<project><groupId>com.acme</groupId><artifactId>kc-ext</artifactId><version>1.0.0</version>"
                "<dependencyManagement><dependencies><dependency><groupId>org.keycloak</groupId>"
                "<artifactId>keycloak-parent</artifactId><version>26.0.5</version><type>pom</type>"
                "<scope>import</scope></dependency></dependencies></dependencyManagement></project>"):
        root = tmp_path / f"ext{len(list(tmp_path.iterdir()))}"
        (root / "src" / "main" / "resources").mkdir(parents=True)
        (root / "pom.xml").write_text(pom)
        m, _ = analyze_repo(root, "acme-login", "Acme login")
        assert m.known is None and "auth.oidc" not in m.provides and m.api.type == "none"
    m, _ = analyze_repo(keycloak_source(tmp_path / "kc"), "iam", "IAM")  # Keycloak's own parent pom still is
    assert (m.known.profile, m.known.by) == ("keycloak", "marker")


def test_a_native_port_moves_the_addresses_derived_from_the_default(tmp_path: Path):
    """Review R12: a tool's own hub.manifest.yaml with another port left the portal and API addresses on the port
    Atrium had guessed, while the health check used the new one."""
    root = keycloak_release(tmp_path / "keycloak")
    (root / "version.txt").write_text("Keycloak - Version 24.0.5\n")
    (root / "hub.manifest.yaml").write_text("name: Keycloak\nlaunch:\n  port: 8180\n")
    m, _ = analyze_repo(root, "keycloak", "Keycloak")
    assert m.launch.port == 8180 and m.ui.url == "http://localhost:8180"
    assert m.api.base_url == "http://localhost:8180/admin/realms"
    assert known_tools.health_plan(m, "keycloak").url == "http://localhost:8180/health/ready"
    (root / "hub.manifest.yaml").write_text("name: Keycloak\nlaunch:\n  port: 8180\nui:\n  url: https://sso.example.org\n")
    m, _ = analyze_repo(root, "keycloak", "Keycloak")
    assert m.ui.url == "https://sso.example.org" and m.api.base_url == "http://localhost:8180/admin/realms"


def test_a_tool_named_after_a_host_firewall_gets_no_api_from_its_connector(tmp_path: Path):
    """Review R10: an "iptables_exporter" Go project passed Programmable API through the Linux host firewall
    connector, found by its name alone. Only a saved connection or the recognised product's connector counts."""
    from types import SimpleNamespace

    from hub.integration import strategies

    root = tmp_path / "iptables_exporter"
    root.mkdir()
    (root / "go.mod").write_text("module github.com/x/iptables_exporter\n")
    (root / "main.go").write_text("package main\nfunc main(){}\n")
    m, _ = analyze_repo(root, "iptables_exporter", "iptables_exporter")
    tool = Tool(id="iptables_exporter", name="iptables_exporter", source_type="local", source=str(root),
                path=str(root), manifest=m)
    hub = SimpleNamespace(store=SimpleNamespace(get=lambda *a, **k: None))
    assert strategies.builtin_connector(tool) is not None  # still offered on the Data flows card
    assert strategies.connector_api(hub, tool) is None
