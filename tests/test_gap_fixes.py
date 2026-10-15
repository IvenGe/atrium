"""Fix selection, the proposal loop and the Operator's answer for a tool that cannot start (build spec 5: C, F, H).

Every open check names a fix that can close it, or none and what a person can do instead; the Patch Agent proposes
only what is proposable, says why for every other gap (once), never proposes a rejected or twice-failed patch again by
itself, and a tool without a launch command answers "needs input" instead of an agent error. All fixtures are built
in tmp_path; patches.plan and reader.propose_launch are stubbed where a test needs a specific result."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
import yaml

from hub.agents import reader
from hub.agents import patcher as patcher_module
from hub.integration import gapfix, patches, strategies
from hub.integration.analyzer import analyze_repo
from hub.integration.compatibility import EvalContext, evaluate_tool
from hub.models import FileChange, KnownMatch, Manifest, Patch, Tool
from llm_fakes import FakeClaude, use_claude

EDITOR = "Integration > Launch > Edit"


# --------------------------------------------------------------------------------------
# fixtures (folders built in tmp_path)
# --------------------------------------------------------------------------------------


def keycloak_source(root: Path) -> Path:
    (root / "quarkus").mkdir(parents=True)
    (root / "pom.xml").write_text("<project>\n  <groupId>org.keycloak</groupId>\n  <artifactId>keycloak-parent</artifactId>\n"
                                  "  <version>999.0.0-SNAPSHOT</version>\n</project>\n")
    (root / "quarkus" / "x.java").write_text("class X {}\n")
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


def keycloak_compose(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": {"keycloak": {
        "image": "quay.io/keycloak/keycloak:25.0", "command": "start-dev", "ports": ["8080:8080", "9000:9000"],
        "environment": {"KC_BOOTSTRAP_ADMIN_USERNAME": "admin"}}}}))
    return root


def java_app(root: Path) -> Path:
    """An unknown Maven application: no launch rule, no port."""
    (root / "src" / "main" / "java").mkdir(parents=True)
    (root / "pom.xml").write_text("<project>\n  <groupId>com.example</groupId>\n  <artifactId>ledger</artifactId>\n"
                                  "  <version>1.0.0</version>\n</project>\n")
    (root / "src" / "main" / "java" / "App.java").write_text("public class App { public static void main(String[] a) {} }\n")
    (root / "README.md").write_text("# Ledger\n\nRun it with ./mvnw spring-boot:run.\n")
    return root


def compose_only(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "docker-compose.yml").write_text(yaml.safe_dump({"services": {"web": {"image": "nginx:1.25",
                                                                                  "ports": ["8081:80"]}}}))
    return root


def analysed(root: Path, tool_id: str, name: str, **fields) -> Tool:
    m, _ = analyze_repo(root, tool_id, name)
    return Tool(id=tool_id, name=name, source_type="local", source=str(root), path=str(root), manifest=m,
                status="ready", **fields)


def made(tool_id: str, *, path: str | None = None, **manifest) -> Tool:
    m = Manifest(id=tool_id, name=tool_id.title(), **manifest)
    return Tool(id=tool_id, name=m.name, source_type="local", source=path or "/tmp", path=path, manifest=m,
                status="ready")


def checks(tool: Tool, ctx: EvalContext | None = None) -> dict:
    return {c.id: c for c in evaluate_tool(tool, [], ctx=ctx).checks}


# --------------------------------------------------------------------------------------
# C: which fix each check offers
# --------------------------------------------------------------------------------------


def test_a_native_manifest_without_a_launch_command_gets_launch_command_never_add_manifest(tmp_path: Path):
    tool = made("native", path=str(tmp_path), native=True, kind="oss", stack=["python"])
    found = checks(tool)
    assert found["manifest"].status == "pass" and found["manifest"].fix is None
    assert found["launch"].fix == "launch_command" and "Integration > Launch > Edit" in found["launch"].detail
    assert all(c.fix != "add_manifest" for c in found.values())


def test_a_todo_launch_command_counts_as_missing(tmp_path: Path):
    tool = made("todo", path=str(tmp_path), native=True, launch={"command": "TODO: command that starts the tool"})
    launch = checks(tool)["launch"]
    assert launch.status == "warn" and launch.fix == "launch_command" and "TODO" not in launch.detail


def test_an_oss_java_tool_without_a_port_gets_launch_command_for_health_and_events(tmp_path: Path):
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger")
    assert tool.manifest.launch.port is None and "java" in tool.manifest.stack
    found = checks(tool)
    assert found["health"].fix == "launch_command"  # no health_endpoint: no port, nothing to probe
    assert "No port or address is known yet" in found["health"].detail
    assert found["events"].fix == "launch_command"
    assert found["api"].fix is None and "Integration > API > Edit" in found["api"].detail


def test_keycloak_fixes_by_folder_shape(tmp_path: Path):
    release = checks(analysed(keycloak_release(tmp_path / "kc-release"), "keycloak", "Keycloak"))
    assert release["launch"].status == "pass" and release["health"].fix == "health_config"
    assert "KC_HEALTH_ENABLED" in release["health"].detail

    source = checks(analysed(keycloak_source(tmp_path / "kc-src"), "keycloak", "Keycloak"))
    assert source["launch"].fix == "launch_command"
    assert "official container image quay.io/keycloak/keycloak" in source["launch"].detail
    assert source["health"].fix == "launch_command" and "launch_command patch switches it on" in source["health"].detail
    assert source["manifest"].status == "pass" and "built-in Keycloak profile" in source["manifest"].detail
    assert source["api"].status == "pass" and source["api"].detail.startswith("REST API (Keycloak admin REST API)")
    assert source["events"].status == "warn" and source["events"].fix is None
    assert "realm" in source["events"].detail  # the profile's note: the poller cannot read them

    compose = checks(analysed(keycloak_compose(tmp_path / "kc-compose"), "keycloak", "Keycloak"))
    assert compose["health"].fix == "health_probe"
    assert "KC_HEALTH_ENABLED=true" in compose["health"].detail and "compose file" in compose["health"].detail


def test_code_patch_only_for_source_with_a_port_and_probes_otherwise(tmp_path: Path, plain_repo: Path):
    assert checks(analysed(plain_repo, "notes", "Notes"))["health"].fix == "health_endpoint"
    web = analysed(compose_only(tmp_path / "web"), "web", "Web")
    assert checks(web)["health"].fix == "health_probe"


def test_api_passes_through_the_profile_or_a_built_in_connector(tmp_path: Path):
    plain = made("ledger", path=str(tmp_path), kind="oss")
    assert checks(plain)["api"].status == "warn"
    via = checks(plain, EvalContext(builtin_api=lambda t: "Keycloak"))["api"]
    assert via.status == "pass" and "Keycloak" in via.detail
    rest = made("kc", path=str(tmp_path), kind="oss", api={"type": "rest"},
                known=KnownMatch(profile="keycloak", shape="source", by="marker"))
    detail = checks(rest, EvalContext(builtin_api=lambda t: "Keycloak"))["api"].detail
    assert detail == "REST API (Keycloak admin REST API); built-in connector: Keycloak"
    profile = made("kc", path=str(tmp_path), kind="oss", known=KnownMatch(profile="keycloak", shape="source"))
    assert profile.manifest.api.type == "none"  # nothing detected, but the profile knows the product's API
    api = checks(profile)["api"]
    assert api.status == "pass" and api.detail == "REST API (Keycloak admin REST API)"
    closed = made("vendor", kind="closed", launch={"port": 9000, "command": "vendor.exe"})
    assert checks(closed)["api"].fix == "api_adapter"


def test_a_known_health_endpoint_is_used_once_the_port_is_known(tmp_path: Path):
    """A source checkout gets its port from the launch command set later (a patch or an administrator): the
    product's own health endpoint is then known, and health_config sets it instead of an outside probe."""
    grafana = made("grafana", path=str(tmp_path), kind="oss", stack=["go"],
                   known=KnownMatch(profile="grafana", shape="source", by="marker"),
                   launch={"command": "./bin/grafana server", "port": 3000})
    health = checks(grafana)["health"]
    assert health.fix == "health_config" and "http://localhost:3000/api/health" in health.detail


def test_hub_manifest_known_adopted_and_inferred(tmp_path: Path):
    known = made("kc", path=str(tmp_path), kind="oss", known=KnownMatch(profile="keycloak", shape="source", by="marker"),
                 adopted="hub/add-manifest-abc123")
    check = checks(known)["manifest"]
    assert check.status == "pass" and "waits unmerged at hub/add-manifest-abc123" in check.detail
    adopted = made("app", path=str(tmp_path), kind="oss", adopted="hub/add-manifest-abc123")
    check = checks(adopted)["manifest"]
    assert check.status == "warn" and check.fix is None and "merge it into" in check.detail
    assert checks(made("app", path=str(tmp_path), kind="oss"))["manifest"].fix == "add_manifest"
    # a capability-only profile (Redis: what it provides, nothing about running it) describes nothing
    redis = made("cache", path=str(tmp_path), known=KnownMatch(profile="redis"))
    assert checks(redis)["manifest"].fix == "add_manifest"


def test_events_from_a_generated_poller_are_no_pass(tmp_path: Path):
    tool = made("crm", path=str(tmp_path), kind="oss", launch={"port": 4000}, events={"emits": ["crm.changed"]})
    tool.manifest_overrides = {"events": {"emits": ["crm.changed"]}}
    events = checks(tool)["events"]
    assert events.status == "warn" and events.fix is None and "adapters/crm/events/adapter.py" in events.detail
    tool.manifest.events.emits = ["crm.changed", "crm.deal.won"]  # the tool's own events pass
    assert checks(tool)["events"].status == "pass"
    assert checks(made("crm", launch={"port": 4000}))["events"].fix == "event_adapter"


def test_the_check_detail_carries_the_history_note(tmp_path: Path):
    tool = made("crm", path=str(tmp_path), kind="closed", launch={"port": 4000, "command": "crm"})
    ctx = EvalContext(note=lambda t, c: "You rejected it." if c.id == "health" else None)
    assert checks(tool, ctx)["health"].detail == "No health endpoint detected. You rejected it."


# --------------------------------------------------------------------------------------
# gapfix: fingerprints and touches_launch
# --------------------------------------------------------------------------------------


def test_fingerprint_follows_the_inputs_of_the_plan():
    tool = made("crm", launch={"port": 4000})
    first = gapfix.fingerprint(tool, "event_adapter")
    assert first == gapfix.fingerprint(tool, "event_adapter") and len(first) == 16
    tool.manifest.description = "changed, but no input of the plan"
    assert gapfix.fingerprint(tool, "event_adapter") == first
    tool.manifest.launch.port = 4001
    assert gapfix.fingerprint(tool, "event_adapter") != first
    tool.manifest.launch.command = "TODO: start it"  # a placeholder is no value
    assert gapfix.fingerprint(tool, "launch_command") == gapfix.fingerprint(made("crm", launch={"port": 4001}),
                                                                            "launch_command")
    other = made("other", launch={"port": 3000})
    assert gapfix.fingerprint(tool, "reassign_port", [other]) != gapfix.fingerprint(tool, "reassign_port", [])


@pytest.mark.parametrize(("update", "touches"), [
    ({"launch": {"command": "x", "port": 8080, "cwd": "."}}, True),
    ({"launch": {"env": {"KC_HEALTH_ENABLED": "true"}}, "health": {"url": "http://localhost:9000/health"}}, True),
    ({"launch": {"secret_env": ["PW"], "env_files": ["launch/secrets.env"]}}, True),
    ({"launch": {"port": 3002, "env": {"PORT": "3002"}}, "ui": {"url": "http://localhost:3002"}}, False),
    ({"health": {"url": "tcp://127.0.0.1:5000"}}, False),
    ({}, False),
])
def test_touches_launch(update, touches):
    patch = Patch(id="p_x", tool_id="t", title="t", rationale="", strategy="x", target="manifest", manifest_update=update)
    assert gapfix.touches_launch(patch) is touches


# --------------------------------------------------------------------------------------
# F: the proposal loop (a running hub)
# --------------------------------------------------------------------------------------


def hub_of(client):
    return client.app.state.hub


def rescore(client) -> None:
    async def run():
        hub_of(client).agents.get("supervisor").reevaluate()
    client.portal.call(run)


def put(client, tool: Tool) -> Tool:
    hub = hub_of(client)
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    rescore(client)
    return hub.get_tool(tool.id)


def propose(client, tool_id: str, **body) -> dict:
    hub = hub_of(client)
    return client.portal.call(hub.bus.request, "user:admin", "patcher", "propose", {"tool_id": tool_id, **body}, 120)


def decide(client, wait_for, patch_id: str, approve: bool) -> Patch:
    hub = hub_of(client)
    patch = hub.get_patch(patch_id)
    assert patch.approval_id, "every proposed patch names its approval"
    assert client.post(f"/api/approvals/{patch.approval_id}", json={"approve": approve}).status_code == 200
    return wait_for(lambda: (p := hub.get_patch(patch_id)).status != "proposed" and p)


def strategy_of(client, patch_ids: list[str]) -> dict[str, str]:
    return {hub_of(client).get_patch(i).strategy: i for i in patch_ids}


def not_proposed(client, tool_name: str) -> list[str]:
    return [e["text"] for e in hub_of(client).store.tail("activity", 1000)
            if e.get("text", "").startswith(f"{tool_name}: '") and "was not proposed" in e.get("text", "")]


def test_a_rejected_patch_is_not_proposed_again_until_an_administrator_asks(client, wait_for, plain_repo: Path):
    hub = hub_of(client)
    put(client, analysed(plain_repo, "notes", "Notes"))
    first = propose(client, "notes")
    assert set(first) == {"patches", "pending", "skipped"}
    made_by = strategy_of(client, first["patches"])
    assert {"health_probe", "event_adapter", "add_manifest", "sso_proxy"} <= set(made_by)
    approval = hub.approvals.get(hub.get_patch(made_by["health_probe"]).approval_id)
    assert approval.payload == {"patch_id": made_by["health_probe"], "tool_id": "notes", "strategy": "health_probe"}
    assert hub.get_tool("notes").status == "needs_patch"

    decide(client, wait_for, made_by["health_probe"], False)
    count = len(hub.patches("notes"))
    again = propose(client, "notes")
    assert again["patches"] == [] and len(hub.patches("notes")) == count
    assert set(again["pending"]) == {made_by[s] for s in ("event_adapter", "add_manifest", "sso_proxy")}
    health = next(s for s in again["skipped"] if s["fix"] == "health_endpoint")
    assert health["state"] == "skipped" and health["reason"].startswith("You rejected 'Add a health probe adapter'")
    assert health["title"] == "Health check" and health["check"] == "health"
    rescore(client)
    detail = next(c for c in hub.get_tool("notes").report.checks if c.id == "health").detail
    assert "You rejected 'Add a health probe adapter'" in detail

    asked = propose(client, "notes", again=True)  # an administrator asks again
    assert [hub.get_patch(i).strategy for i in asked["patches"]] == ["health_probe"]


def test_two_failed_applies_stop_the_proposals_and_name_the_last_error(client, wait_for, plain_repo: Path,
                                                                       monkeypatch):
    hub = hub_of(client)
    put(client, analysed(plain_repo, "notes", "Notes"))

    async def broken(hub_, patch):
        raise RuntimeError(f"disk full ({patch.id})")

    monkeypatch.setattr(patcher_module, "apply_patch", broken)
    for attempt in (1, 2):
        result = propose(client, "notes", fixes=["health_endpoint"])
        assert len(result["patches"]) == 1, attempt
        failed = decide(client, wait_for, result["patches"][0], True)
        assert failed.status == "failed" and "disk full" in failed.error
    third = propose(client, "notes", fixes=["health_endpoint"])
    assert third["patches"] == []
    reason = third["skipped"][0]["reason"]
    assert reason.startswith("'Add a health probe adapter' failed 2 times; last error: disk full")
    assert "Integration > Health > Edit" in reason
    rescore(client)
    detail = next(c for c in hub.get_tool("notes").report.checks if c.id == "health").detail
    assert "failed 2 times; last error: disk full" in detail


def test_an_applied_patch_that_leaves_the_gap_open_is_not_proposed_again(client, wait_for, plain_repo: Path,
                                                                         monkeypatch):
    real = patches.plan

    def plan(tool, others, strategy, hub_url, idp=None, *, proposal=None):
        if strategy == "event_adapter":  # a poller that changes nothing in the manifest
            return Patch(id=f"p_{time.time_ns()}", tool_id=tool.id, title="Add an event adapter",
                         strategy="event_adapter", target="adapter",
                         changes=[FileChange(path="events/adapter.py", content="pass\n")], rationale="")
        return real(tool, others, strategy, hub_url, idp, proposal=proposal)

    monkeypatch.setattr(patches, "plan", plan)
    put(client, analysed(plain_repo, "notes", "Notes"))
    result = propose(client, "notes", fixes=["event_adapter"])
    assert decide(client, wait_for, result["patches"][0], True).status == "applied"
    rescore(client)  # the check's detail now ends with the note on the applied patch
    detail = next(c for c in hub_of(client).get_tool("notes").report.checks if c.id == "events").detail
    assert detail.endswith(" 'Add an event adapter' was applied, but the gap is still open.")
    again = propose(client, "notes", fixes=["event_adapter"])
    assert again["patches"] == [] and again["skipped"][0]["reason"] == (
        "'Add an event adapter' was applied, but the gap is still open: Other tools cannot react to changes in this "
        "tool.")  # the check's own detail, without the note repeated
    hub = hub_of(client)
    card = next(i for i in strategies.tool_strategies(hub, hub.get_tool("notes")) if i["id"] == "events")
    assert card["state"] == "needs_input"  # an applied poller is not "active": nothing runs it yet


def test_nothing_proposable_settles_the_tool_and_logs_each_reason_once(client, tmp_path: Path):
    hub = hub_of(client)
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger", )
    tool.manifest.native = True  # nothing to adopt: every gap needs a launch command first
    tool.status = "needs_patch"
    put(client, tool)
    for _ in range(2):
        result = propose(client, "ledger")
        assert result["patches"] == [] and result["pending"] == []
        states = {s["fix"]: s for s in result["skipped"]}
        launch = states["launch_command"]
        assert launch["state"] == "needs_input" and EDITOR in launch["reason"]
        assert "with an AI model (Settings > AI providers)" in launch["reason"]  # no model: the hint
        assert launch["title"] == "Launchable from the hub, Health check and Emits events"
        assert states["sso_proxy"]["state"] == "needs_input"  # no port for a proxy either
    assert hub.get_tool("ledger").status == "ready"
    assert len(not_proposed(client, "Ledger")) == len(result["skipped"])  # once each, across two passes
    assert hub.agent_errors.stored("patcher") == 0
    assert hub.patches("ledger") == []


def test_a_command_without_a_port_asks_for_the_port(client, tmp_path: Path):
    put(client, made("runner", path=str(tmp_path), kind="oss", native=True, launch={"command": "bin/run.sh"}))
    launch = next(s for s in propose(client, "runner")["skipped"] if s["fix"] == "launch_command")
    assert launch["title"] == "Health check and Emits events"  # the launch itself passes
    assert launch["state"] == "needs_input" and "port" in launch["reason"] and EDITOR in launch["reason"]


def test_an_unknown_program_gets_an_ai_launch_proposal_with_a_model(client, tmp_path: Path, monkeypatch):
    hub = hub_of(client)
    use_claude(hub, monkeypatch, FakeClaude())
    asked: list[str] = []

    async def propose_launch(hub_, tool, agent_id="patcher"):
        asked.append(tool.id)
        return reader.LaunchProposal(command="./mvnw spring-boot:run", setup=None, cwd=".", port=8080,
                                     health_path="/actuator/health", rationale="The README says so.",
                                     evidence=["README.md"], generated_by={"provider": "anthropic", "model": "m"})

    seen = []
    real = patches.plan

    def plan(tool, others, strategy, hub_url, idp=None, *, proposal=None):
        if strategy != "launch_command":
            return real(tool, others, strategy, hub_url, idp, proposal=proposal)
        seen.append(proposal)
        return Patch(id=f"p_{time.time_ns()}", tool_id=tool.id, strategy="launch_command", target="manifest",
                     title="Launch command proposed by Claude - check it before approving", rationale="",
                     manifest_update={"launch": {"command": proposal.command, "port": proposal.port, "cwd": "."}},
                     generated_by=proposal.generated_by)

    monkeypatch.setattr(reader, "propose_launch", propose_launch)
    monkeypatch.setattr(patches, "plan", plan)
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger")
    tool.manifest.native = True
    put(client, tool)
    result = propose(client, "ledger", fixes=["launch_command"])
    assert asked == ["ledger"] and seen[0].command == "./mvnw spring-boot:run"
    patch = hub.get_patch(result["patches"][0])
    assert patch.strategy == "launch_command" and patch.generated_by and patch.status == "proposed"
    assert patch.fingerprint == gapfix.fingerprint(hub.get_tool("ledger"), "launch_command")
    approval = hub.approvals.get(patch.approval_id)
    assert "Only an administrator approves this patch" in approval.detail


def test_a_failed_ai_launch_proposal_is_not_paid_for_again_until_asked(client, tmp_path: Path, monkeypatch):
    hub = hub_of(client)
    use_claude(hub, monkeypatch, FakeClaude())
    calls: list[str] = []

    async def propose_launch(hub_, tool, agent_id="patcher"):
        calls.append(tool.id)
        raise ValueError("evidence names 'docs/run.md', which you have not read")

    monkeypatch.setattr(reader, "propose_launch", propose_launch)
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger")
    tool.manifest.native = True
    put(client, tool)
    first = propose(client, "ledger", fixes=["launch_command"])
    reason = first["skipped"][0]["reason"]
    assert first["patches"] == [] and first["skipped"][0]["state"] == "needs_input"
    assert reason.startswith("The AI model could not work out how to start Ledger: evidence names")
    assert reason.endswith("Set it in Integration > Launch > Edit, or ask again.")
    second = propose(client, "ledger", fixes=["launch_command"])
    assert calls == ["ledger"] and second["skipped"][0]["reason"] == reason
    propose(client, "ledger", fixes=["launch_command"], again=True)
    assert calls == ["ledger", "ledger"]
    assert len(not_proposed(client, "Ledger")) == 1  # the same reason each time: logged once
    assert hub.agent_errors.stored("patcher") == 0


def test_a_launch_patch_waits_for_an_administrator_even_in_autonomous_mode(client, tmp_path: Path, monkeypatch):
    hub = hub_of(client)
    hub.update_prefs("test", autonomy="autonomous")

    def plan(tool, others, strategy, hub_url, idp=None, *, proposal=None):
        if strategy == "launch_command":
            return Patch(id=f"p_{time.time_ns()}", tool_id=tool.id, strategy=strategy, target="manifest",
                         title="Start Keycloak with the official container image", rationale="",
                         manifest_update={"launch": {"command": "docker run x", "port": 8080, "cwd": "."}})
        return patches.Skip("not in this test")

    monkeypatch.setattr(patches, "plan", plan)
    put(client, analysed(keycloak_source(tmp_path / "kc"), "keycloak", "Keycloak"))
    result = propose(client, "keycloak")
    patch = hub.get_patch(result["patches"][0])
    assert patch.strategy == "launch_command" and patch.status == "proposed" and patch.approval_id
    approval = hub.approvals.get(patch.approval_id)
    assert approval.status == "pending" and approval.payload["strategy"] == "launch_command"
    assert hub.get_tool("keycloak").status == "needs_patch"


# --------------------------------------------------------------------------------------
# H: the Operator, the Adapters card and the rules chat
# --------------------------------------------------------------------------------------


def test_starting_a_tool_without_a_launch_command_needs_input(client, tmp_path: Path):
    hub = hub_of(client)
    put(client, made("ledger", path=str(tmp_path), kind="oss", launch={"command": "TODO: start it"}))
    answer = client.post("/api/tools/ledger/start").json()
    assert answer == {"status": "needs_input", "reason": "Launch needs a launch command: approve the launch_command "
                                                         "patch or set it in Integration > Launch > Edit."}
    hub.save_patch(Patch(id="p_waiting", tool_id="ledger", title="Set how the hub starts the tool", rationale="",
                         strategy="launch_command", target="manifest"))
    assert client.post("/api/tools/ledger/start").json()["reason"].endswith(" One is waiting on the Approvals page.")
    assert hub.agent_errors.stored("operator") == 0


def test_an_approved_start_whose_command_was_removed_fails_cleanly(client, sign_in, wait_for, tmp_path: Path):
    hub = hub_of(client)
    put(client, made("ledger", path=str(tmp_path), kind="oss", launch={"command": "java -jar ledger.jar"}))
    asked = sign_in("operator").post("/api/tools/ledger/start").json()
    assert asked["status"] == "pending_approval"
    tool = hub.get_tool("ledger")
    tool.manifest.launch.command = None
    hub.save_tool(tool)
    assert client.post(f"/api/approvals/{asked['approval_id']}", json={"approve": True}).status_code == 200
    done = wait_for(lambda: (a := hub.approvals.get(asked["approval_id"])).status in ("done", "failed") and a)
    assert done.status == "failed" and "Launch needs a launch command" in done.result["error"]
    assert not hub.processes.status("ledger")["running"]
    assert hub.agent_errors.stored("operator") == 0


def test_the_adapters_card_says_what_is_missing(client, wait_for, tmp_path: Path, plain_repo: Path):
    hub = hub_of(client)
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger")
    tool.manifest.native = True
    put(client, tool)
    card = next(i for i in strategies.tool_strategies(hub, hub.get_tool("ledger")) if i["id"] == "adapter")
    assert card["state"] == "needs_input" and card["action"] == "edit_manifest"
    assert card["detail"].startswith("Launchable from the hub, Health check and Emits events: Atrium does not know "
                                     "how to start Ledger.")

    put(client, analysed(plain_repo, "notes", "Notes"))
    card = next(i for i in strategies.tool_strategies(hub, hub.get_tool("notes")) if i["id"] == "adapter")
    assert card["state"] == "available" and card["action"] == "propose_patches"
    propose(client, "notes")
    card = next(i for i in strategies.tool_strategies(hub, hub.get_tool("notes")) if i["id"] == "adapter")
    assert card["state"] == "pending" and card["action"] is None

    # an unknown program with a manifest to adopt: the adoption waits, and the card still says what no patch closes
    put(client, analysed(java_app(tmp_path / "billing"), "billing", "Billing"))
    created = propose(client, "billing")["patches"]
    assert [hub.get_patch(i).strategy for i in created] == ["add_manifest"]
    card = next(i for i in strategies.tool_strategies(hub, hub.get_tool("billing")) if i["id"] == "adapter")
    assert card["state"] == "pending" and card["action"] == "edit_manifest"
    assert "Not proposed - Launchable from the hub, Health check and Emits events: Atrium does not know" in card["detail"]


def test_rejecting_the_last_waiting_patch_makes_the_tool_ready(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    put(client, analysed(java_app(tmp_path / "billing"), "billing", "Billing"))
    created = propose(client, "billing")["patches"]
    assert hub.get_tool("billing").status == "needs_patch"
    decide(client, wait_for, created[0], False)
    wait_for(lambda: hub.get_tool("billing").status == "ready")
    manifest = wait_for(lambda: next(c for c in hub.get_tool("billing").report.checks if c.id == "manifest"
                                     and "You rejected" in c.detail))
    assert manifest.fix == "add_manifest"  # the chip stays: an administrator may ask again


def test_connector_api_names_the_saved_or_built_in_connector(client, tmp_path: Path):
    hub = hub_of(client)
    kc = put(client, analysed(keycloak_source(tmp_path / "kc"), "iam", "Identity"))
    assert strategies.connector_api(hub, kc) == "Keycloak (admin API)"  # recognised by its pom.xml, not its name
    api = next(c for c in kc.report.checks if c.id == "api")
    assert api.status == "pass" and api.detail.endswith("; built-in connector: Keycloak (admin API)")
    assert strategies.connector_api(hub, put(client, made("ledger", kind="oss"))) is None


def test_the_rules_chat_gives_the_reasons(client, tmp_path: Path):
    tool = analysed(java_app(tmp_path / "ledger"), "ledger", "Ledger")
    tool.manifest.native = True
    put(client, tool)
    reply = client.post("/api/chat", json={"text": "patch ledger"}).json()["reply"]
    assert reply.startswith("The Patch Agent proposed 0 patch(es) for Ledger.")
    assert "Not proposed:" in reply and "Atrium does not know how to start Ledger." in reply
    reply = client.post("/api/chat", json={"text": "start ledger"}).json()["reply"]
    assert reply == ("Start Ledger: needs_input - Launch needs a launch command: approve the launch_command patch or "
                     "set it in Integration > Launch > Edit.")
