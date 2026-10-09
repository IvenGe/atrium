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
    assert hub.tool.manifest.native


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
