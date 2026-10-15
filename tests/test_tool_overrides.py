"""Hub-side patches and persistence (hub/integration/patches.py, overrides.py, launch_secrets.py): the launch_command
and health_config patches, honest event adapters and adopted manifests, hub-side overrides that survive every
re-analysis, the launch secrets that never leave the hub's private file, and the one-time migration of stored tools.

Every fixture is built in tmp_path (a Keycloak source checkout and release folder, small apps, legacy stored tools)."""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from conftest import make_settings
from hub.agents.patcher import render_diff
from hub.agents.reader import LaunchProposal
from hub.integration import launch_secrets, overrides
from hub.integration.analyzer import analyze_repo
from hub.integration.patches import (
    R_NEEDS_LAUNCH, Skip, apply_patch, manifest_yaml, plan, plan_patch,
)
from hub.models import FileChange, Manifest, Patch, Tool
from hub.secrets import hub_secret_values
from llm_fakes import FakeClaude, use_claude

# the recipe publishes on loopback only: Docker would otherwise publish past a host firewall (review)
KC_COMMAND = ("docker run --rm --name atrium-keycloak -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 "
              "-e KC_HEALTH_ENABLED=true "
              "-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD quay.io/keycloak/keycloak:26.0 "
              "start-dev")
SECRET_RE = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{32}(?![A-Za-z0-9_-])")  # secrets.token_urlsafe(24)


# --------------------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------------------


def keycloak_source(root: Path) -> Path:
    """The shape of a git checkout of keycloak/keycloak: a Maven parent pom, Java modules and a README."""
    (root / "quarkus").mkdir(parents=True)
    (root / "services").mkdir()
    (root / "pom.xml").write_text(
        "<project>\n  <groupId>org.keycloak</groupId>\n  <artifactId>keycloak-parent</artifactId>\n"
        "  <version>999.0.0-SNAPSHOT</version>\n  <packaging>pom</packaging>\n</project>\n")
    (root / "quarkus" / "x.java").write_text("class X {}\n")
    (root / "services" / "y.java").write_text("class Y {}\n")
    (root / "README.md").write_text("# Keycloak\n\nOpen Source Identity and Access Management.\n")
    return root


def keycloak_release(root: Path) -> Path:
    for folder in ("bin", "conf", "lib"):
        (root / folder).mkdir(parents=True)
    (root / "bin" / "kc.sh").write_text("#!/bin/sh\nexec java -jar ../lib/quarkus-run.jar \"$@\"\n")
    (root / "bin" / "kc.bat").write_text("@echo off\r\n")
    (root / "conf" / "keycloak.conf").write_text("# db=postgres\n")
    (root / "lib" / "quarkus-run.jar").write_bytes(b"PK\x03\x04")
    (root / "version.txt").write_text("Keycloak - Version 26.0.5\n")
    return root


def analysed(root: Path, tool_id: str, name: str, **fields) -> Tool:
    m, _ = analyze_repo(root, tool_id, name)
    return Tool(id=tool_id, name=name, source_type="local", source=str(root), path=str(root), manifest=m,
                status="ready", **fields)


def make_tool(tool_id: str, path: str | None = None, **manifest) -> Tool:
    m = Manifest(id=tool_id, name=tool_id.title(), **manifest)
    return Tool(id=tool_id, name=m.name, source_type="local", source=path or "/tmp", path=path, manifest=m,
                status="ready")


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


def outputs(patch: Patch) -> str:
    """Everything a patch shows people and agents: its changes, manifest update, rationale and diff."""
    return json.dumps(patch.model_dump(mode="json"))


def secret_file(workspace: Path, tool_id: str) -> Path:
    return workspace / "adapters" / tool_id / launch_secrets.ENV_FILE


# --------------------------------------------------------------------------------------
# launch_command
# --------------------------------------------------------------------------------------


def test_launch_command_for_a_keycloak_source_checkout_runs_the_official_image(tmp_path: Path):
    tool = analysed(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak")
    patch = plan(tool, [], "launch_command", "http://127.0.0.1:8710")
    assert isinstance(patch, Patch) and patch.target == "manifest" and patch.strategy == "launch_command"
    launch = patch.manifest_update["launch"]
    assert launch["command"] == KC_COMMAND and launch["port"] == 8080 and launch["cwd"] == "."
    assert launch["secret_env"] == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert launch_secrets.ENV_FILE in launch["env_files"]
    assert patch.manifest_update["health"] == {"url": "http://localhost:9000/health/ready"}
    assert patch.manifest_update["api"] == {"base_url": "http://localhost:8080/admin/realms"}
    assert patch.title == "Start Keycloak with the official container image quay.io/keycloak/keycloak:26.0"
    assert "source code; the hub does not build it" in patch.rationale and "Docker on the hub machine" in patch.rationale
    assert "8080 and 9000" in patch.rationale and "Integration > Launch > Edit" in patch.rationale
    assert yaml.safe_load(patch.changes[0].content) == patch.manifest_update
    patch.diff = render_diff(tool, patch)
    assert not SECRET_RE.findall(outputs(patch))  # no generated value: only the variable's name
    # back-compat: plan_patch gives the same kind of patch, and None where plan() skips
    assert plan_patch(tool, [], "launch_command", "http://x").strategy == "launch_command"
    assert plan_patch(tool, [], "event_adapter", "http://x") is None


def test_applying_launch_command_generates_the_secret_privately_and_keeps_it(tmp_path: Path):
    root = keycloak_source(tmp_path / "keycloak")
    tool = analysed(root, "keycloak", "Keycloak")
    hub = FakeHub(tmp_path / "ws", tool)
    patch = plan(tool, [], "launch_command", "http://x")
    applied = asyncio.run(apply_patch(hub, patch))
    path = secret_file(tmp_path / "ws", "keycloak")
    value = launch_secrets._read(tmp_path / "ws", "keycloak")["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert len(value) >= 24
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600 and stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    m = hub.tool.manifest
    assert m.launch.command == KC_COMMAND and m.launch.port == 8080 and m.health.url.endswith(":9000/health/ready")
    assert hub.tool.manifest_overrides["launch"]["command"] == KC_COMMAND
    assert value not in outputs(applied) and value not in hub.tool.model_dump_json()  # only the name is stored
    public = hub.tool.public()
    assert public["manifest"]["launch"]["env_keys"] == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert "launch.command" in public["overridden"] and "manifest_overrides" not in public
    assert value not in json.dumps(public)
    # the tool now has a command and a port: nothing more to plan; a second launch_command patch keeps the value
    assert plan(hub.tool, [], "launch_command", "http://x") == Skip(
        "Keycloak already has a launch command and a port: there is nothing to set.")
    asyncio.run(apply_patch(hub, plan(analysed(root, "keycloak", "Keycloak"), [], "launch_command", "http://x")))
    assert launch_secrets._read(tmp_path / "ws", "keycloak")["KC_BOOTSTRAP_ADMIN_PASSWORD"] == value
    assert launch_secrets.ensure(tmp_path / "ws", "keycloak", ["KC_BOOTSTRAP_ADMIN_PASSWORD"]) == []
    assert launch_secrets.keys(tmp_path / "ws", "keycloak") == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]


def test_launch_secret_is_masked_and_never_published(client, tmp_path: Path):
    hub = client.app.state.hub
    tool = analysed(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak")
    hub.save_tool(tool)
    events: list[tuple[str, str]] = []
    hub.bus.listen(lambda kind, data: events.append((kind, json.dumps(data, default=str))))
    patch = hub.save_patch(plan(tool, [], "launch_command", str(client.base_url)))
    applied = client.portal.call(apply_patch, hub, patch)
    value = launch_secrets._read(hub.settings.workspace, "keycloak")["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert value in hub_secret_values(hub)
    assert any(kind == "tool" for kind, _ in events) and not any(value in data for _, data in events)
    shown = client.get("/api/tools/keycloak").json()
    assert shown["manifest"]["launch"]["env_keys"] == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert shown["manifest"]["launch"]["command"] == KC_COMMAND
    assert value not in json.dumps(shown) and value not in json.dumps(client.get("/api/tools").json())
    assert value not in outputs(applied)
    assert hub.cleaned(f"the password is {value}") != f"the password is {value}"  # masked in the activity log
    launch_secrets.forget(hub.settings.workspace, "keycloak")
    assert not secret_file(hub.settings.workspace, "keycloak").exists()
    assert value not in hub_secret_values(hub)


def test_launch_secrets_refuse_values_that_would_not_read_back(tmp_path: Path):
    ws = tmp_path / "ws"
    for bad in ("two\nlines", "nul\x00", '"quoted"', "'x", " padded", ""):
        with pytest.raises(ValueError):
            launch_secrets.put(ws, "app", {"ADMIN_PASSWORD": bad})
    with pytest.raises(ValueError):
        launch_secrets.put(ws, "app", {"BAD-NAME": "x"})
    with pytest.raises(ValueError):
        launch_secrets.ensure(ws, "../escape", ["X"])
    launch_secrets.put(ws, "app", {"ADMIN_PASSWORD": "s3cret-v@lue=with=equals", "OTHER": "kept"})
    assert launch_secrets._read(ws, "app") == {"ADMIN_PASSWORD": "s3cret-v@lue=with=equals", "OTHER": "kept"}
    launch_secrets.put(ws, "app", {"ADMIN_PASSWORD": None})
    assert launch_secrets.keys(ws, "app") == ["OTHER"] and launch_secrets.values(ws) == ["kept"]


def test_launch_command_from_an_ai_proposal_is_marked_and_checked(tmp_path: Path):
    folder = tmp_path / "shop"
    folder.mkdir()
    (folder / "README.md").write_text("Run ./gradlew bootRun\n")
    (folder / "gradlew").write_text("#!/bin/sh\n")  # a model's command starts a program of the folder (review R16)
    tool = make_tool("shop", path=str(folder), stack=["java"])
    proposal = LaunchProposal(command="./gradlew bootRun", setup=None, cwd=".", port=8080,
                              health_path="/actuator/health", rationale="The README starts it with Gradle.",
                              evidence=["README.md"], generated_by={"provider": "anthropic", "model": "claude-test"})
    patch = plan(tool, [], "launch_command", "http://x", proposal=proposal)
    assert isinstance(patch, Patch) and patch.generated_by == {"provider": "anthropic", "model": "claude-test"}
    assert patch.title == "Launch command proposed by claude-test - check it before approving"
    assert "README.md" in patch.rationale and "Atrium's privileges" in patch.rationale
    assert patch.manifest_update == {"launch": {"command": "./gradlew bootRun", "cwd": ".", "port": 8080},
                                     "health": {"url": "http://localhost:8080/actuator/health"},
                                     "ui": {"url": "http://localhost:8080"}}
    for command in ("rm -rf /", "TODO: find the command"):
        skip = plan(tool, [], "launch_command", "http://x",
                    proposal=LaunchProposal(command=command, setup=None, cwd=".", port=None, health_path=None,
                                            rationale="", evidence=["README.md"], generated_by={}))
        assert isinstance(skip, Skip), command
    # nothing known and no proposal: a person must say how it starts, and the card says where
    skip = plan(tool, [], "launch_command", "http://x")
    assert isinstance(skip, Skip) and skip.needs_input
    assert skip.reason.startswith("Atrium does not know how to start Shop.")
    assert "Integration > Launch > Edit" in skip.reason and "AI model" in skip.reason
    saas = Tool(id="crm", name="CRM", source_type="saas", source="https://crm.io", manifest=Manifest(
        id="crm", name="CRM", kind="saas"))
    assert plan(saas, [], "launch_command", "http://x") == Skip("A SaaS service is not started by the hub.")
    assert R_NEEDS_LAUNCH.format(tool="X", hint="") == ("Atrium does not know how to start X. An administrator can set "
                                                         "the launch command in Integration > Launch > Edit.")


# --------------------------------------------------------------------------------------
# health_config, event_adapter, add_manifest
# --------------------------------------------------------------------------------------


def test_health_config_switches_on_a_release_folders_own_health_check(tmp_path: Path):
    tool = analysed(keycloak_release(tmp_path / "kc-26"), "keycloak", "Keycloak")
    assert tool.manifest.launch.command == "bin/kc.sh start-dev" and not tool.manifest.health.url
    patch = plan(tool, [], "health_config", "http://x")
    assert isinstance(patch, Patch) and patch.target == "manifest"
    assert patch.manifest_update == {"launch": {"env": {"KC_HEALTH_ENABLED": "true"}},
                                     "health": {"url": "http://localhost:9000/health/ready"}}
    assert "KC_HEALTH_ENABLED=true" in patch.rationale and "9000" in patch.rationale
    hub = FakeHub(tmp_path / "ws", tool)
    asyncio.run(apply_patch(hub, patch))
    assert hub.tool.manifest.launch.env["KC_HEALTH_ENABLED"] == "true"
    assert hub.tool.manifest.health.url == "http://localhost:9000/health/ready"
    # a container launch command: the env must go into the command itself, which a person changes
    tool.manifest.launch.command = "docker run -p 8080:8080 quay.io/keycloak/keycloak:26.0 start-dev"
    skip = plan(tool, [], "health_config", "http://x")
    assert isinstance(skip, Skip) and skip.needs_input
    assert "-e KC_HEALTH_ENABLED=true" in skip.reason and "-p 127.0.0.1:9000:9000" in skip.reason  # loopback (review)


def test_event_adapter_never_polls_a_made_up_address(tmp_path: Path):
    nowhere = make_tool("nowhere")
    skip = plan(nowhere, [], "event_adapter", "http://x")
    assert isinstance(skip, Skip) and skip.needs_input and "No port or address is known for Nowhere" in skip.reason
    kc = analysed(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak")
    skip = plan(kc, [], "event_adapter", "http://x")
    assert isinstance(skip, Skip) and "per realm" in skip.reason  # the profile says why a poller cannot do it
    crm = make_tool("crm", launch={"port": 4000}, events={"emits": ["crm.deal.won"]})
    patch = plan(crm, [], "event_adapter", "http://x")
    assert patch.manifest_update == {"events": {"emits": ["crm.changed"]}}
    assert 'WATCH_URL", "http://localhost:4000"' in patch.changes[0].content
    hub = FakeHub(tmp_path / "ws", crm)
    asyncio.run(apply_patch(hub, patch))
    assert hub.tool.manifest.events.emits == ["crm.deal.won", "crm.changed"]  # unioned, nothing lost
    for tool in (nowhere, crm, make_tool("ui", ui={"url": "http://10.0.0.5"}), make_tool("bare", launch={"port": 1})):
        for strategy in ("event_adapter", "sso_proxy", "health_probe", "launch_command", "add_manifest"):
            result = plan(tool, [], strategy, "http://x")
            text = outputs(result) if isinstance(result, Patch) else result.reason
            assert "example.com" not in text and "TODO:" not in text, (tool.id, strategy)


def test_adopted_manifest_is_honest_and_never_native(tmp_path: Path):
    root = keycloak_source(tmp_path / "keycloak")
    git = ["git", "-C", str(root), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    tool = analysed(root, "keycloak", "Keycloak")
    patch = plan(tool, [], "add_manifest", "http://x")
    assert patch.manifest_update == {} and patch.target == "repo"
    draft = yaml.safe_load(patch.changes[0].content.split("\n", 1)[1])
    assert "TODO" not in patch.changes[0].content and draft["launch"]["command"] is None
    assert not {"id", "native", "known", "adopted"} & set(draft) and "secret_env" not in draft["launch"]
    assert draft["api"]["spec"] == "https://www.keycloak.org/docs-api/latest/rest-api/openapi.json"
    assert "auth.oidc" in draft["provides"] and "launch.command" in patch.rationale
    hub = FakeHub(tmp_path / "ws", tool)
    applied = asyncio.run(apply_patch(hub, patch))
    assert applied.branch and not hub.tool.manifest.native
    assert hub.tool.manifest.adopted == applied.branch == hub.tool.manifest_overrides["adopted"]
    assert applied.manifest_update == {"adopted": applied.branch}
    # the hub-only keys and launch secrets never reach a draft, even from a manifest that has them
    m = hub.tool.manifest.model_copy(update={"launch": hub.tool.manifest.launch.model_copy(
        update={"secret_env": ["ADMIN_PASSWORD"], "env_files": ["launch/secrets.env"], "command": "TODO: x"})})
    text = manifest_yaml(m)
    assert "ADMIN_PASSWORD" not in text and "adopted" not in text and "known" not in text and "TODO" not in text


# --------------------------------------------------------------------------------------
# overrides: merge, apply, set_fields
# --------------------------------------------------------------------------------------


def test_override_merge_rules():
    current = {"launch": {"port": 8081, "env": {"PORT": "8081"}}, "events": {"emits": ["a.x"]}}
    merged = overrides.merge(current, {"events": {"emits": ["a.changed"]}, "native": True, "known": {"profile": "x"},
                                       "launch": {"env": {"PORT": None}, "secret_env": ["S"]}})
    assert merged == {"launch": {"port": 8081, "secret_env": ["S"]}, "events": {"emits": ["a.x", "a.changed"]}}
    assert current["launch"]["env"] == {"PORT": "8081"}  # inputs are never changed
    m = Manifest(id="a", name="A", native=True, provides=["x"], launch={"port": 1, "env": {"K": "v"}})
    out = overrides.apply(m, {"native": False, "provides": ["y"], "launch": {"port": "not a port", "cwd": "sub"}})
    assert out.native and out.provides == ["x", "y"] and out.launch.port == 1 and out.launch.cwd == "sub"
    with pytest.raises(ValueError):
        overrides.apply(m, {"launch": {"port": "not a port"}}, strict=True)
    assert overrides.apply(m, {}) == m and overrides.apply(m, {}) is not m


def test_set_fields_sets_and_clears_overrides():
    tool = make_tool("app", launch={"port": 3000}, events={"emits": ["app.x"]})
    overrides.set_fields(tool, {"launch.command": "npm start", "launch.env.NODE_ENV": "production",
                                "launch.secret_env": ["ADMIN_PASSWORD"], "health.url": "http://localhost:3000/health"})
    assert tool.manifest.launch.command == "npm start" and tool.manifest.launch.env == {"NODE_ENV": "production"}
    assert tool.public()["overridden"] == ["health.url", "launch.command", "launch.env.NODE_ENV", "launch.secret_env"]
    assert "production" not in json.dumps(tool.public()["overridden"])
    overrides.set_fields(tool, {"launch.command": None, "health.url": None})
    assert tool.manifest_overrides == {"launch": {"env": {"NODE_ENV": "production"}, "secret_env": ["ADMIN_PASSWORD"]}}
    for bad in ({"native": True}, {"known.profile": "x"}, {"launch.port": "x"}, {"launch.secret_env": ["bad-name"]}):
        with pytest.raises(ValueError):
            overrides.set_fields(tool, bad)
    assert tool.manifest.launch.port == 3000


# --------------------------------------------------------------------------------------
# re-analysis keeps hub-side decisions (ToolSupervisor.on_analyze)
# --------------------------------------------------------------------------------------


def analyse(client, tool: Tool) -> Tool:
    hub = client.app.state.hub
    agent = client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    reply = client.portal.call(agent.on_analyze, {}, None)
    assert reply["manifest"]
    return hub.get_tool(tool.id)


def test_reanalysis_keeps_a_launch_command_and_an_api_adapter(client, tmp_path: Path):
    hub = client.app.state.hub
    tool = hub.save_tool(analysed(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak"))
    client.portal.call(apply_patch, hub, hub.save_patch(plan(tool, [], "launch_command", "http://x")))
    again = analyse(client, hub.get_tool("keycloak"))
    m = again.manifest
    assert m.launch.command == KC_COMMAND and m.launch.port == 8080 and m.launch.secret_env == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert m.health.url == "http://localhost:9000/health/ready" and m.known.profile == "keycloak" and not m.native
    assert any(n.startswith("Kept ") and "launch.command" in n for n in again.notes)
    # a closed tool's API adapter
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "vendor.exe").write_bytes(b"MZ\x90\x00")
    closed = hub.save_tool(analysed(vendor, "vendor", "Vendor"))
    assert closed.manifest.kind == "closed"
    skeleton = client.portal.call(apply_patch, hub, hub.save_patch(plan(closed, [], "api_adapter", "http://x")))
    m = analyse(client, hub.get_tool("vendor")).manifest
    # review R5: a skeleton full of TODOs that nothing runs is no API - it sets nothing (the check says so instead)
    assert skeleton.status == "applied" and m.api.type == "none" and m.api.base_url is None
    assert (Path(skeleton.location) / "api" / "adapter.py").is_file()


def test_reanalysis_keeps_a_moved_port_and_single_sign_on(client, plain_repo: Path):
    hub = client.app.state.hub
    notes = hub.save_tool(analysed(plain_repo, "notes", "Notes"))
    assert notes.manifest.launch.port == 5000
    keycloak = hub.save_tool(make_tool("keycloak", provides=["auth.oidc"], launch={"port": 5000},
                                       ui={"url": "http://localhost:5000"}))
    move = plan(notes, [keycloak], "reassign_port", "http://x")
    client.portal.call(apply_patch, hub, hub.save_patch(move))
    sso = plan(hub.get_tool("notes"), [keycloak], "sso_proxy", "http://x")
    client.portal.call(apply_patch, hub, hub.save_patch(sso))
    m = analyse(client, hub.get_tool("notes")).manifest
    assert m.launch.port == 5001 and m.launch.env["PORT"] == "5001"
    assert m.ui.url == sso.manifest_update["ui"]["url"]  # the proxy in front of it (applied last)
    assert m.auth.sso == "oidc" and m.auth.provider == "keycloak" and "oauth2-proxy" in m.auth.notes


def test_reanalysis_recomputes_native_after_an_adoption(client, tmp_path: Path):
    hub = client.app.state.hub
    root = keycloak_source(tmp_path / "keycloak")
    tool = hub.save_tool(analysed(root, "keycloak", "Keycloak"))
    applied = client.portal.call(apply_patch, hub, hub.save_patch(plan(tool, [], "add_manifest", "http://x")))
    assert applied.location and not applied.branch  # not a git repository: the draft waits in a folder
    m = analyse(client, hub.get_tool("keycloak")).manifest
    assert not m.native and m.adopted == applied.location
    # once the draft is merged into the folder, the tool ships its own manifest
    (root / "hub.manifest.yaml").write_text((Path(applied.location) / "hub.manifest.yaml").read_text())
    m = analyse(client, hub.get_tool("keycloak")).manifest
    assert m.native and m.known.profile == "keycloak"


def test_enrichment_is_not_called_for_a_known_tool(client, monkeypatch, tmp_path: Path, plain_repo: Path):
    hub = client.app.state.hub
    fake = use_claude(hub, monkeypatch, FakeClaude(json_result={"description": "Takes notes.", "provides": [],
                                                                "consumes": []}))
    analyse(client, hub.save_tool(analysed(keycloak_source(tmp_path / "keycloak"), "keycloak", "Keycloak")))
    assert fake.calls == []
    analyse(client, hub.save_tool(analysed(plain_repo, "notes", "Notes")))  # an unknown tool still gets it
    assert len(fake.calls) == 1


# --------------------------------------------------------------------------------------
# migration of tools stored before the overrides
# --------------------------------------------------------------------------------------


def legacy_keycloak(root: Path) -> tuple[Tool, list[Patch]]:
    """A Keycloak tool as an earlier Atrium stored it: native from an adopted manifest, an event adapter that polled
    https://example.com, and a port moved by reassign_port."""
    m = Manifest(id="keycloak", name="Keycloak", stack=["java"], native=True,
                 provides=["auth.oidc", "auth.saml", "identity.source"], auth={"sso": "oidc"},
                 launch={"port": 8081, "env": {"PORT": "8081"}}, ui={"url": "http://localhost:8081"},
                 events={"emits": ["keycloak.changed"]})
    tool = Tool(id="keycloak", name="Keycloak", source_type="local", source=str(root), path=str(root), manifest=m,
                status="ready", created_at=1.0)
    hollow = 'WATCH_URL = os.environ.get("WATCH_URL", "https://example.com")\n'
    patches = [
        Patch(id="p_adopt1", tool_id="keycloak", title="Adopt a hub manifest", rationale="", strategy="add_manifest",
              target="repo", status="applied", branch="hub/add-manifest-adopt1", location="/ws/patches/p_adopt1",
              changes=[FileChange(path="hub.manifest.yaml", content="launch:\n  command: 'TODO: x'\n")],
              manifest_update={"native": True}, created_at=2.0),
        Patch(id="p_events", tool_id="keycloak", title="Add an event adapter", rationale="", strategy="event_adapter",
              target="adapter", status="applied", changes=[FileChange(path="events/adapter.py", content=hollow)],
              manifest_update={"events": {"emits": ["keycloak.changed"]}}, created_at=3.0),
        Patch(id="p_port", tool_id="keycloak", title="Move the tool to a free port", rationale="",
              strategy="reassign_port", target="manifest", status="applied",
              manifest_update={"launch": {"port": 8081, "env": {"PORT": "8081"}}, "ui": {"url": "http://localhost:8081"}},
              created_at=4.0),
        Patch(id="p_rejected", tool_id="keycloak", title="x", rationale="", strategy="health_probe", target="adapter",
              status="rejected", manifest_update={"health": {"url": "tcp://127.0.0.1:8081"}}, created_at=5.0),
    ]
    return tool, patches


def test_migration_moves_legacy_tools_to_overrides_once(tmp_path: Path):
    from hub.core import Hub

    hub = Hub(make_settings(tmp_path))
    try:
        tool, patches = legacy_keycloak(keycloak_source(tmp_path / "keycloak"))
        hub.save_tool(tool)
        for patch in patches:
            hub.save_patch(patch)
        plain = hub.save_tool(make_tool("plain", launch={"port": 7000}))
        assert overrides.migrate(hub) == 1
        migrated = hub.get_tool("keycloak")
        m = migrated.manifest
        assert not m.native and m.adopted == "hub/add-manifest-adopt1"
        assert "keycloak.changed" not in m.events.emits
        assert m.launch.port == 8081 and m.launch.env == {"PORT": "8081"} and m.ui.url == "http://localhost:8081"
        assert m.known.profile == "keycloak" and m.known.shape == "source" and m.api.type == "rest"
        assert not m.health.url  # the rejected probe is not an override
        assert migrated.manifest_overrides == {"adopted": "hub/add-manifest-adopt1",
                                               "launch": {"port": 8081, "env": {"PORT": "8081"}},
                                               "ui": {"url": "http://localhost:8081"}}
        assert hub.get_tool("plain") == plain  # nothing to change
        assert hub.prefs[overrides.MIGRATION_PREF] == 1
        assert overrides.migrate(hub) == 0  # once
    finally:
        hub.store.close()


def test_hub_start_runs_the_migration(tmp_path: Path):
    from fastapi.testclient import TestClient

    from hub.app import create_app
    from hub.core import Hub

    settings = make_settings(tmp_path)
    hub = Hub(settings)
    tool, patches = legacy_keycloak(keycloak_source(tmp_path / "keycloak"))
    hub.save_tool(tool)
    for patch in patches:
        hub.save_patch(patch)
    hub.store.close()
    with TestClient(create_app(settings), headers={"X-Hub-Request": "1"}) as c:
        started = c.app.state.hub
        m = started.get_tool("keycloak").manifest
        assert not m.native and m.known.profile == "keycloak" and m.adopted == "hub/add-manifest-adopt1"
        assert started.prefs[overrides.MIGRATION_PREF] == 1
