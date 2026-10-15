import asyncio
import subprocess
from pathlib import Path
from types import SimpleNamespace

from hub.integration.analyzer import analyze_repo
from hub.integration.compatibility import evaluate_suite, evaluate_tool, suite_matrix
from hub.integration.patches import apply_patch, plan_patch, safe_relative
from hub.models import Manifest, Tool

import pytest


def make_tool(tool_id: str, **manifest) -> Tool:
    m = Manifest(id=tool_id, name=tool_id.title(), **manifest)
    return Tool(id=tool_id, name=m.name, source_type="local", source="/tmp", manifest=m, status="ready")


def test_well_integrated_tool_scores_high(node_repo: Path):
    m, _ = analyze_repo(node_repo, "crm-app", "CRM App")
    m.native = True
    tool = Tool(id="crm-app", name="CRM", source_type="local", source=str(node_repo), path=str(node_repo), manifest=m)
    report = evaluate_tool(tool, [make_tool("postgres", provides=["db.postgres"]), make_tool("mail", provides=["notify.email"])])
    assert report.level == "native"
    assert report.score >= 85


def test_gaps_carry_patch_strategies(plain_repo: Path):
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    tool = Tool(id="notes", name="Notes", source_type="local", source=str(plain_repo), path=str(plain_repo), manifest=m)
    report = evaluate_tool(tool, [])
    fixes = {c.id: c.fix for c in report.checks if c.status != "pass"}
    assert fixes["sso"] == "sso_proxy"
    assert fixes["health"] == "health_endpoint"
    assert fixes["events"] == "event_adapter"
    assert report.level in ("patchable", "incompatible")


def test_port_conflicts_and_links():
    idp = make_tool("keycloak", provides=["auth.oidc"], launch={"port": 8080})
    wiki = make_tool("wiki", auth={"sso": "oidc"}, consumes=["auth.oidc"], launch={"port": 8080},
                     events={"listens": ["keycloak.*"]})
    idp.manifest.events.emits = ["keycloak.user.created"]
    reports = evaluate_suite([idp, wiki])
    assert any(c.id == "ports" and c.status == "fail" for c in reports["wiki"].checks)
    idp.report, wiki.report = reports["keycloak"], reports["wiki"]
    matrix = suite_matrix([idp, wiki])
    kinds = {(l["source"], l["target"], l["type"]) for l in matrix["links"]}
    assert ("keycloak", "wiki", "capability") in kinds
    assert ("keycloak", "wiki", "event") in kinds
    assert matrix["conflicts"] == [{"port": 8080, "tools": ["Keycloak", "Wiki"]}]


def test_closed_tools_get_adapters_not_code_patches():
    vendor = make_tool("vendor", kind="closed", launch={"port": 9000, "command": "vendor.exe"})
    report = evaluate_tool(vendor, [])
    fixes = {c.id: c.fix for c in report.checks if c.fix}
    assert fixes["health"] == "health_probe"
    assert fixes["api"] == "api_adapter"
    assert report.level == "adapter"


def test_reassign_port_patch_picks_a_free_port():
    a = make_tool("a", launch={"port": 3000})
    b = make_tool("b", launch={"port": 3000, "env": {}}, health={"url": "http://localhost:3000/health"})
    c = make_tool("c", launch={"port": 3001})
    patch = plan_patch(b, [a, c], "reassign_port", "http://127.0.0.1:8710")
    assert patch.target == "manifest"
    assert patch.manifest_update["launch"]["port"] == 3002
    assert patch.manifest_update["health"]["url"] == "http://localhost:3002/health"


def keycloak_release(root: Path) -> Path:
    for rel, text in (("bin/kc.sh", "#!/bin/sh\n"), ("bin/kc.bat", "@echo off\r\n"), ("conf/keycloak.conf", "\n"),
                      ("version.txt", "Keycloak - Version 26.0.5\n")):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    (root / "lib").mkdir()
    (root / "lib" / "quarkus-run.jar").write_bytes(b"PK\x03\x04")
    return root


def on_disk(root: Path, tool_id: str) -> Tool:
    m, _ = analyze_repo(root, tool_id, tool_id.title())
    return Tool(id=tool_id, name=m.name, source_type="local", source=str(root), path=str(root), manifest=m)


def test_reassign_port_moves_only_what_the_launch_can_take(tmp_path: Path):
    """Review R7: the patch used to set PORT for every tool, closing "Port is free" while a product that reads its own
    variable (Keycloak: KC_HTTP_PORT) or a container publishing -p 8080:8080 kept its port."""
    from hub.integration import gapfix
    from hub.integration.patches import Skip, plan

    other = make_tool("busy", launch={"port": 8080})
    kc = on_disk(keycloak_release(tmp_path / "keycloak"), "keycloak")
    assert kc.manifest.launch.command == "bin/kc.sh start-dev" and kc.manifest.launch.port == 8080
    patch = plan(kc, [other], "reassign_port", "http://x")
    assert patch.manifest_update["launch"] == {"port": 8081, "env": {"KC_HTTP_PORT": "8081"}}
    assert "KC_HTTP_PORT=8081" in patch.rationale and not gapfix.touches_launch(patch)  # a port number only
    assert patch.manifest_update["api"]["base_url"] == "http://localhost:8081/admin/realms"

    spring = make_tool("ledger", stack=["java", "spring"], launch={"port": 8080, "command": "./mvnw spring-boot:run"})
    assert plan(spring, [other], "reassign_port", "http://x").manifest_update["launch"]["env"] == {"SERVER_PORT": "8081"}
    node = make_tool("crm", stack=["node"], launch={"port": 8080, "command": "npm start"})
    assert plan(node, [other], "reassign_port", "http://x").manifest_update["launch"]["env"] == {"PORT": "8081"}

    docker = make_tool("wiki", launch={"port": 8080, "command": "docker run --rm -p 127.0.0.1:8080:3000 wiki:2"},
                       health={"url": "http://localhost:8080/healthz"})
    patch = plan(docker, [other], "reassign_port", "http://x")
    assert patch.manifest_update["launch"] == {"port": 8081, "command": "docker run --rm -p 127.0.0.1:8081:3000 wiki:2"}
    assert patch.manifest_update["health"]["url"] == "http://localhost:8081/healthz" and gapfix.touches_launch(patch)

    for tool in (make_tool("stack", launch={"port": 8080, "command": "docker compose up"}),
                 make_tool("metrics", known={"profile": "prometheus", "shape": "other"},
                           launch={"port": 8080, "command": "./prometheus"}),
                 make_tool("oddity", launch={"port": 8080, "command": "docker run --rm -p 9999:8080 x"})):
        skip = plan(tool, [other], "reassign_port", "http://x")
        assert isinstance(skip, Skip) and skip.needs_input and "Integration > Launch > Edit" in skip.reason, tool.id


def test_health_endpoint_never_for_a_known_product_or_a_container(tmp_path: Path):
    """Review R4: a Keycloak source checkout started with the official image got health_endpoint - a code patch to
    source that never runs - instead of the probe and the note naming the flags to add."""
    root = tmp_path / "keycloak"
    root.mkdir()
    (root / "pom.xml").write_text("<project><groupId>org.keycloak</groupId><artifactId>keycloak-parent</artifactId>"
                                  "<version>999.0.0-SNAPSHOT</version></project>\n")
    (root / "quarkus").mkdir()
    (root / "quarkus" / "x.java").write_text("class X {}\n")
    kc = on_disk(root, "keycloak")
    kc.manifest.launch.command = "docker run --rm -p 8080:8080 quay.io/keycloak/keycloak:26.0 start-dev"
    kc.manifest.launch.port = 8080
    health = next(c for c in evaluate_tool(kc, []).checks if c.id == "health")
    assert health.fix == "health_probe" and "-e KC_HEALTH_ENABLED=true" in health.detail
    app = make_tool("shop", stack=["node"], launch={"port": 3000, "command": "docker compose up -d"})
    app.path = str(tmp_path)
    assert next(c for c in evaluate_tool(app, []).checks if c.id == "health").fix == "health_probe"
    app.manifest.launch.command = "npm start"  # its own process: a code patch can add the endpoint
    assert next(c for c in evaluate_tool(app, []).checks if c.id == "health").fix == "health_endpoint"


def test_an_api_adapter_skeleton_is_no_api(tmp_path: Path):
    """Review R5: approving the api_adapter skeleton set api.type rest - a pass - though it is full of TODOs and the hub
    never runs it. It sets nothing now, and the check says what a person does next, with no fix."""
    from hub.integration import gapfix
    from hub.integration.compatibility import EvalContext
    from hub.integration.patches import plan

    vendor = make_tool("vendor", kind="closed", launch={"port": 9000, "command": "vendor.exe"})
    skeleton = plan(vendor, [], "api_adapter", "http://x")
    assert skeleton.manifest_update == {} and "TODO" in skeleton.changes[0].content
    skeleton.status = "applied"
    ctx = EvalContext(waiting=lambda t, check_id: gapfix.waiting(t, check_id, [skeleton]))
    api = next(c for c in evaluate_tool(vendor, [], ctx=ctx).checks if c.id == "api")
    assert api.status == "warn" and api.fix is None
    assert api.detail.startswith("An API adapter skeleton was generated (adapters/vendor/api/adapter.py)")
    vendor.manifest.api.type, vendor.manifest.api.base_url = "rest", "http://127.0.0.1:9100"  # set by a person
    assert next(c for c in evaluate_tool(vendor, [], ctx=ctx).checks if c.id == "api").status == "pass"


@pytest.mark.parametrize("path", ["../evil.py", "/etc/passwd", "C:/Windows/x", "a/../../b"])
def test_patch_paths_cannot_escape(path):
    with pytest.raises(ValueError):
        safe_relative(path)


class FakeHub:
    """Just enough of Hub for apply_patch."""

    def __init__(self, workspace: Path, tool: Tool):
        self.settings = SimpleNamespace(workspace=workspace)
        self.tool = tool
        self.saved = []

    def get_tool(self, tool_id):
        return self.tool

    def save_tool(self, tool):
        self.tool = tool
        return tool

    def save_patch(self, patch):
        self.saved.append(patch)
        return patch


def test_repo_patch_lands_on_a_branch_in_a_worktree(tmp_path: Path, plain_repo: Path):
    git = ["git", "-C", str(plain_repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(plain_repo)], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    m, _ = analyze_repo(plain_repo, "notes", "Notes")
    tool = Tool(id="notes", name="Notes", source_type="local", source=str(plain_repo), path=str(plain_repo), manifest=m)
    hub = FakeHub(tmp_path / "ws", tool)
    patch = plan_patch(tool, [], "add_manifest", "http://127.0.0.1:8710")
    assert patch.target == "repo"
    applied = asyncio.run(apply_patch(hub, patch))
    assert applied.status == "applied" and applied.branch.startswith("hub/add-manifest-")
    assert (Path(applied.location) / "hub.manifest.yaml").is_file()
    assert not (plain_repo / "hub.manifest.yaml").exists()  # the user's checkout is untouched
    branches = subprocess.run([*git, "branch", "--list", "hub/*"], capture_output=True, text=True).stdout
    assert applied.branch in branches
    # an adopted manifest waits unmerged on its branch: it is recorded where it waits, and the tool does not ship its
    # own manifest (native) until it is merged and re-analysed - it used to claim native here (a false PASS)
    assert not hub.tool.manifest.native
    assert hub.tool.manifest.adopted == applied.branch
    assert hub.tool.manifest_overrides == {"adopted": applied.branch}
    assert "TODO" not in patch.changes[0].content


def test_adapter_patch_updates_manifest(tmp_path: Path):
    tool = make_tool("crm", launch={"port": 4000})
    hub = FakeHub(tmp_path / "ws", tool)
    patch = plan_patch(tool, [make_tool("keycloak", provides=["auth.oidc"], launch={"port": 8080})], "sso_proxy", "http://x")
    asyncio.run(apply_patch(hub, patch))
    compose = tmp_path / "ws" / "adapters" / "crm" / "sso-proxy" / "docker-compose.yml"
    assert "oauth2-proxy" in compose.read_text()
    assert "localhost:8080" in (compose.parent / ".env.example").read_text()
    assert hub.tool.manifest.auth.sso == "oidc"


def test_event_adapter_authenticates_with_an_integration_token():
    patch = plan_patch(make_tool("crm", launch={"port": 4000}), [], "event_adapter", "http://127.0.0.1:8710")
    script = patch.changes[0].content
    compile(script, "adapter.py", "exec")
    assert 'HUB_TOKEN = os.environ.get("HUB_TOKEN", "")' in script
    assert 'headers["Authorization"] = f"Bearer {HUB_TOKEN}"' in script
    assert '"integration" role' in script
