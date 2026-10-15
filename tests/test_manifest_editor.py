"""The administrators' manifest editor and the end-to-end result of the known-product work (build spec 6, I).

PATCH /api/tools/{id}/manifest sets how the hub starts and reaches a tool as hub-side overrides that every analysis
applies again; environment values go to the tool's private launch secrets and never reach an API answer, the activity
log, the bus or a patch. Then whole imports, as a person sees them: a Keycloak source checkout is closed by one
administrator approval, a release folder by one health_config approval, an unknown Maven application says what is
missing and is closed by the editor, the shipped Keycloak example passes as it is, and a Keycloak stored by an earlier
Atrium is migrated at start. Every fixture is built in tmp_path (except the shipped example, read in place)."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from conftest import ADMIN_PASSWORD, make_settings
from hub.app import create_app
from hub.integration import launch_secrets, overrides, strategies
from hub.integration.analyzer import analyze_repo
from hub.integration.compatibility import evaluate_tool
from hub.models import FileChange, Manifest, Patch, Tool

ROOT = Path(__file__).resolve().parent.parent
SECRET = "Ledger-db-Pa55word-not-for-anyone"
EDITOR = "Integration > Launch > Edit"
# the recipe publishes on loopback only: Docker would otherwise publish past a host firewall (review)
KC_COMMAND = ("docker run --rm --name atrium-keycloak -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 "
              "-e KC_HEALTH_ENABLED=true "
              "-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD quay.io/keycloak/keycloak:26.0 "
              "start-dev")


# --------------------------------------------------------------------------------------
# fixtures (folders built in tmp_path)
# --------------------------------------------------------------------------------------


def keycloak_source(root: Path) -> Path:
    """The shape of a git checkout of keycloak/keycloak: a Maven parent pom, Java modules and a README."""
    (root / "quarkus").mkdir(parents=True)
    (root / "services").mkdir()
    (root / "pom.xml").write_text("<project>\n  <groupId>org.keycloak</groupId>\n  <artifactId>keycloak-parent</artifactId>\n"
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


def java_app(root: Path) -> Path:
    """An unknown Maven application with no launch rule and no port. It ships a hub manifest that only names it, so
    the Hub manifest check passes and only what Atrium cannot know stays open."""
    (root / "src" / "main" / "java").mkdir(parents=True)
    (root / "pom.xml").write_text("<project>\n  <groupId>com.example</groupId>\n  <artifactId>ledger</artifactId>\n"
                                  "  <version>1.0.0</version>\n</project>\n")
    (root / "src" / "main" / "java" / "App.java").write_text("public class App { public static void main(String[] a) {} }\n")
    (root / "README.md").write_text("# Ledger\n\nBuild it with ./mvnw package, then run java -jar target/ledger.jar.\n")
    (root / "hub.manifest.yaml").write_text("name: Ledger\ndescription: Books and invoices.\n")
    return root


def hub_of(client: TestClient):
    return client.app.state.hub


def rescore(client: TestClient) -> None:
    async def run():
        hub_of(client).agents.get("supervisor").reevaluate()
    client.portal.call(run)


def put(client: TestClient, root: Path, tool_id: str, name: str) -> Tool:
    """The folder analysed and stored as a tool with its supervisor, and the suite scored (no propose pass)."""
    hub = hub_of(client)
    m, _ = analyze_repo(root, tool_id, name)
    tool = hub.save_tool(Tool(id=tool_id, name=name, source_type="local", source=str(root), path=str(root),
                              manifest=m, status="ready"))
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    rescore(client)
    return hub.get_tool(tool_id)


def imported(client: TestClient, wait_for, root: Path) -> str:
    """Import a local folder as a person does and wait until the Hub Supervisor scored it and its gaps went to the
    Patch Agent (the propose pass that follows runs under the tool's lock, so a later one waits for it)."""
    response = client.post("/api/tools/import", json={"source_type": "local", "source": str(root)})
    assert response.status_code == 202, response.text
    tool_id = response.json()["id"]
    wait_for(lambda: (t := hub_of(client).get_tool(tool_id)) and t.report and t.status in ("ready", "needs_patch"))
    return tool_id


def checks(client: TestClient, tool_id: str) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in client.get(f"/api/tools/{tool_id}").json()["report"]["checks"]}


def edit(client: TestClient, tool_id: str, body: dict[str, Any]):
    return client.patch(f"/api/tools/{tool_id}/manifest", json=body)


def approve(client: TestClient, wait_for, patch_id: str, yes: bool = True) -> Patch:
    hub = hub_of(client)
    patch = hub.get_patch(patch_id)
    response = client.post(f"/api/approvals/{patch.approval_id}", json={"approve": yes})
    assert response.status_code == 200, response.text
    return wait_for(lambda: (p := hub.get_patch(patch_id)).status != "proposed" and p)


def everything_an_api_shows(client: TestClient, tool_id: str) -> str:
    """Every API answer a signed-in person can read about the tool and the hub's work on it."""
    answers = [client.get(path).json() for path in (
        f"/api/tools/{tool_id}", "/api/tools", "/api/activity?limit=500", "/api/messages?limit=500", "/api/approvals",
        f"/api/tools/{tool_id}/strategies", "/api/integration", "/api/integration/strategies",
        f"/api/tools/{tool_id}/logs")]  # the tool's process output (review R14)
    answers += [client.get(f"/api/patches/{p.id}").json() for p in hub_of(client).patches(tool_id)]
    return json.dumps(answers)


# --------------------------------------------------------------------------------------
# the editor: who may use it, and where its secrets go
# --------------------------------------------------------------------------------------


def test_only_administrators_edit_and_the_secret_stays_in_the_private_file(client, sign_in, wait_for,
                                                                             tmp_path: Path):
    hub = hub_of(client)
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    seen: list[str] = []
    hub.bus.listen(lambda type_, data: seen.append(json.dumps(data, default=str)))
    body = {"launch": {"command": "java -jar target/ledger.jar", "port": 8080, "env": {"LEDGER_DB_PASSWORD": SECRET}}}
    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert edit(viewer, "ledger", body).status_code == 403
    assert edit(operator, "ledger", body).status_code == 403
    assert hub.get_tool("ledger").manifest_overrides == {}

    response = edit(client, "ledger", body)
    assert response.status_code == 200, response.text
    shown = response.json()
    launch = shown["manifest"]["launch"]
    assert launch["command"] == "java -jar target/ledger.jar" and launch["port"] == 8080
    assert launch["env_keys"] == ["LEDGER_DB_PASSWORD"] and launch["secret_env"] == ["LEDGER_DB_PASSWORD"]
    assert launch_secrets.ENV_FILE in launch["env_files"]
    assert {"launch.command", "launch.port", "launch.secret_env"} <= set(shown["overridden"])
    assert "manifest_overrides" not in shown and SECRET not in json.dumps(shown)

    # the value: only in the private file (0600) - never in an answer, the activity log, the bus or an SSE event
    secrets_file = hub.settings.workspace / "adapters" / "ledger" / launch_secrets.ENV_FILE
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600
    assert f"LEDGER_DB_PASSWORD={SECRET}" in secrets_file.read_text()
    assert SECRET not in json.dumps(hub.get_tool("ledger").model_dump(mode="json"))  # nor in the stored tool
    entry = next(e for e in hub.store.tail("activity", 200) if e.get("text", "").startswith("admin changed"))
    assert entry["text"] == "admin changed launch.command, launch.env.LEDGER_DB_PASSWORD, launch.port of Ledger"
    assert "java -jar" not in entry["text"]  # paths only, never the command
    client.post("/api/tools/ledger/patches")  # a propose pass after the edit: its patches hold no value either
    assert SECRET not in everything_an_api_shows(client, "ledger")
    assert SECRET not in everything_an_api_shows(viewer, "ledger")
    assert viewer.get("/api/tools/ledger").json()["manifest"]["launch"]["env_keys"] == ["LEDGER_DB_PASSWORD"]
    assert seen and not any(SECRET in event for event in seen)

    # starting the tool: the child process gets the value through launch.env_files
    started: dict[str, Any] = {}

    async def fake_start(tool_id, command, cwd=None, env=None):
        started.update(tool_id=tool_id, command=command, env=env)
        return {"status": "started", "pid": 1}

    hub.processes.start = fake_start
    assert client.post("/api/tools/ledger/start").status_code == 200
    assert started["command"] == "java -jar target/ledger.jar" and started["env"]["LEDGER_DB_PASSWORD"] == SECRET
    assert started["env"]["PORT"] == "8080"

    # removing it: the value, its name and the private file go
    response = edit(client, "ledger", {"launch": {"env": {"LEDGER_DB_PASSWORD": None}}})
    assert response.status_code == 200, response.text
    launch = response.json()["manifest"]["launch"]
    assert launch["env_keys"] == [] and launch["secret_env"] == [] and launch_secrets.ENV_FILE not in launch["env_files"]
    assert not secrets_file.exists()
    assert "launch" in hub.get_tool("ledger").manifest_overrides  # the command and port stay
    assert set(hub.get_tool("ledger").manifest_overrides["launch"]) == {"command", "port"}
    assert any(e.get("text") == "admin changed launch.env.LEDGER_DB_PASSWORD (reset) of Ledger"
               for e in hub.store.tail("activity", 200))


def test_a_launch_secret_the_process_echoes_is_masked_in_its_log(client, sign_in, wait_for, tmp_path: Path):
    """Review R14: GET /api/tools/{id}/logs returned the child's output raw, so a launcher that echoes its environment
    (set -x) showed the launch secret to viewers."""
    hub = hub_of(client)
    root = java_app(tmp_path / "ledger")
    (root / "run.sh").write_text('#!/bin/sh\nset -x\necho "connecting with $LEDGER_DB_PASSWORD"\nexec sleep 30\n')
    put(client, root, "ledger", "Ledger")
    assert edit(client, "ledger", {"launch": {"command": "sh run.sh", "port": 8080,
                                              "env": {"LEDGER_DB_PASSWORD": SECRET}}}).status_code == 200
    assert client.post("/api/tools/ledger/start").status_code == 200
    try:
        viewer = sign_in("viewer")
        logs = wait_for(lambda: (j := viewer.get("/api/tools/ledger/logs").json())["lines"]
                        and any("connecting with" in line for line in j["lines"]) and j)
        assert SECRET not in json.dumps(logs) and any("connecting with ***" in line for line in logs["lines"])
        assert SECRET not in everything_an_api_shows(client, "ledger")
        assert SECRET in "\n".join(hub.processes._procs["ledger"].lines)  # the process did echo it
    finally:
        client.portal.call(hub.processes.stop, "ledger")


def test_plain_env_constants_are_no_hub_wide_secrets(client, tmp_path: Path):
    """Review R1: every env value typed in the editor became a launch secret, so 'true' or 'info' were masked as ***
    in every prompt and output of every tool, and code patches of any file holding them were refused. Plain
    constants are hub-side launch.env overrides now; only rows marked secret (or named like a credential) go to the
    private file, and a weak secret is kept private but never masked."""
    hub = hub_of(client)
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    response = edit(client, "ledger", {"launch": {"env": {"FLASK_DEBUG": "true", "LOG_LEVEL": "info"}}})
    assert response.status_code == 200, response.text
    launch = response.json()["manifest"]["launch"]
    assert launch["env_keys"] == ["FLASK_DEBUG", "LOG_LEVEL"] and launch["secret_env"] == [] and "env" not in launch
    tool = hub.get_tool("ledger")
    assert tool.manifest.launch.env == {"FLASK_DEBUG": "true", "LOG_LEVEL": "info"}
    assert tool.manifest_overrides["launch"]["env"] == {"FLASK_DEBUG": "true", "LOG_LEVEL": "info"}
    secrets_file = hub.settings.workspace / "adapters" / "ledger" / launch_secrets.ENV_FILE
    assert not secrets_file.exists()
    hub.llm.mask.invalidate()
    assert not {"true", "info"} & set(hub.llm.mask.values())
    text = '{"enabled": true, "level": "info"}'
    assert hub.llm.mask.text(text) == text

    # marked secret: the private file; a weak value ("admin") is kept there too, but masked nowhere
    strong, weak = "Sig-Value-7f3a9c21", "admin"
    response = edit(client, "ledger", {"launch": {"env": {"SIGNING_SEED": strong, "BOOTSTRAP_USER": weak,
                                                          "FLASK_DEBUG": "false"},
                                                  "secret": ["SIGNING_SEED", "BOOTSTRAP_USER"]}})
    assert response.status_code == 200, response.text
    launch = response.json()["manifest"]["launch"]
    assert launch["secret_env"] == ["SIGNING_SEED", "BOOTSTRAP_USER"]
    assert launch["env_keys"] == ["BOOTSTRAP_USER", "FLASK_DEBUG", "LOG_LEVEL", "SIGNING_SEED"]
    stored = secrets_file.read_text()
    assert f"SIGNING_SEED={strong}" in stored and f"BOOTSTRAP_USER={weak}" in stored and "FLASK_DEBUG" not in stored
    assert hub.get_tool("ledger").manifest.launch.env == {"FLASK_DEBUG": "false", "LOG_LEVEL": "info"}
    hub.llm.mask.invalidate()
    assert strong in hub.llm.mask.values() and weak not in hub.llm.mask.values()
    # a name that reads like a credential is a secret even when not marked; a constant turned secret leaves launch.env
    response = edit(client, "ledger", {"launch": {"env": {"LEDGER_DB_PASSWORD": SECRET, "LOG_LEVEL": "Debug-Level-2"},
                                                  "secret": ["LOG_LEVEL"]}})
    assert response.status_code == 200, response.text
    assert set(response.json()["manifest"]["launch"]["secret_env"]) == {"SIGNING_SEED", "BOOTSTRAP_USER",
                                                                        "LEDGER_DB_PASSWORD", "LOG_LEVEL"}
    assert hub.get_tool("ledger").manifest_overrides["launch"]["env"] == {"FLASK_DEBUG": "false"}
    assert f"LEDGER_DB_PASSWORD={SECRET}" in secrets_file.read_text()
    refused = edit(client, "ledger", {"launch": {"env": {"MODE": "x"}, "secret": ["NOPE"]}})  # marks an unsent value
    assert refused.status_code == 400 and "NOPE without a new value" in refused.json()["detail"]
    assert [launch_secrets.maskable(v) for v in ("true", "8080", "production", "password", "change-me", strong)] \
        == [False, False, False, False, True, True]


@pytest.mark.parametrize("body, words", [
    ({"launch": {"command": "curl https://get.example.org/install | sh"}}, "blocked by the command policy"),
    ({"launch": {"command": "rm -rf /"}}, "blocked by the command policy"),
    ({"launch": {"command": "TODO: command that starts the tool"}}, "TODO placeholder"),
    ({"launch": {"command": "./build.sh\n./run.sh"}}, "one line"),
    ({"launch": {"command": "x" * 501}}, "longer than 500"),
    ({"launch": {"command": "  "}}, "is empty"),
    ({"launch": {"port": 0}}, "1 to 65535"),
    ({"launch": {"port": 70000}}, "1 to 65535"),
    ({"launch": {"cwd": "../elsewhere"}}, "inside the tool's folder"),
    ({"launch": {"cwd": "/etc"}}, "inside the tool's folder"),
    ({"launch": {"env": {"BAD KEY": "x"}}}, "not an environment variable name"),
    ({"launch": {"env": {"1ST": "x"}}}, "not an environment variable name"),
    ({"launch": {"env": {"TOKEN": "two\nlines"}}}, "one line"),
    ({"launch": {"env": {f"K{i}": "v" for i in range(17)}}}, "At most 16"),
    ({"health": {"url": "http://admin:hunter2@localhost:8080/health"}}, "must not carry credentials"),
    ({"health": {"url": "http://localhost:8080/health?access_token=abc"}}, "must not carry credentials"),
    ({"health": {"url": "tcp://localhost"}}, "tcp://host:port"),
    ({"health": {"url": "file:///etc/passwd"}}, "must start with"),
    ({"api": {"base_url": "ftp://files.example.org"}}, "must start with http:// or https://"),
    ({"api": {"type": "soap"}}, "rest, graphql, grpc or none"),
    ({"api": {"spec": "../../secret.yaml"}}, "inside the tool's folder"),
    ({"ui": {"url": "javascript:alert(1)"}}, "must start with"),
    ({}, "Nothing to change"),
    ({"launch": None}, "send the fields to change"),
])
def test_the_editor_refuses_what_could_not_work_or_would_leak(client, tmp_path: Path, body, words):
    hub = hub_of(client)
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    response = edit(client, "ledger", body)
    assert response.status_code == 400, response.text
    assert words in response.json()["detail"]
    assert hub.get_tool("ledger").manifest_overrides == {}
    assert not (hub.settings.workspace / "adapters" / "ledger" / launch_secrets.ENV_FILE).exists()


def test_the_editor_body_is_strict_and_saas_has_no_launch(client, tmp_path: Path):
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    assert edit(client, "ledger", {"launch": {"commands": "x"}}).status_code == 422  # an unknown field: refused
    assert edit(client, "ledger", {"manifest": {}}).status_code == 422
    assert edit(client, "ledger", {"launch": {"port": "8080"}}).status_code == 422  # a number, not text
    assert edit(client, "nope", {"launch": {"port": 8080}}).status_code == 404

    hub = hub_of(client)
    saas = hub.save_tool(Tool(id="crm", name="CRM", source_type="saas", source="https://crm.example.org",
                              manifest=Manifest(id="crm", name="CRM", kind="saas"), status="ready"))
    client.portal.call(hub.agents.ensure_tool_supervisor, saas)
    refused = edit(client, "crm", {"launch": {"command": "crm serve"}})
    assert refused.status_code == 400 and "SaaS" in refused.json()["detail"]
    fine = edit(client, "crm", {"health": {"url": "https://crm.example.org/status"},
                                "api": {"type": "REST", "base_url": "https://crm.example.org/api/v2",
                                        "spec": "https://crm.example.org/api/v2/openapi.json"},
                                "ui": {"url": "https://crm.example.org/"}})
    assert fine.status_code == 200, fine.text
    m = fine.json()["manifest"]
    assert m["health"]["url"] == "https://crm.example.org/status" and m["api"]["type"] == "rest"
    assert m["api"]["base_url"] == "https://crm.example.org/api/v2" and m["ui"]["url"] == "https://crm.example.org/"
    assert {c["id"]: c["status"] for c in fine.json()["report"]["checks"]}["health"] == "pass"


# --------------------------------------------------------------------------------------
# persistence: an edit survives every analysis, a reset brings back what the analysis finds
# --------------------------------------------------------------------------------------


def test_an_edit_survives_reanalysis_and_a_reset_brings_back_the_inferred_value(client, wait_for, tmp_path: Path,
                                                                              node_repo: Path):
    hub = hub_of(client)
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    before = checks(client, "ledger")
    assert before["launch"]["status"] == "warn" and before["launch"]["fix"] == "launch_command"
    response = edit(client, "ledger", {"launch": {"command": "java -jar target/ledger.jar", "port": 8080},
                                       "health": {"url": "http://localhost:8080/actuator/health"}})
    assert response.status_code == 200, response.text
    after = {c["id"]: c for c in response.json()["report"]["checks"]}
    assert after["launch"]["status"] == "pass" and after["health"]["status"] == "pass"

    analysed_at = len([e for e in hub.store.tail("activity", 500) if "Analysed Ledger" in e.get("text", "")])
    assert client.post("/api/tools/ledger/analyze").status_code == 202
    wait_for(lambda: len([e for e in hub.store.tail("activity", 500)
                          if "Analysed Ledger" in e.get("text", "")]) > analysed_at)
    tool = wait_for(lambda: (t := hub.get_tool("ledger")).status in ("ready", "needs_patch") and t.report and t)
    assert tool.manifest.launch.command == "java -jar target/ledger.jar" and tool.manifest.launch.port == 8080
    assert any(n.startswith("Kept 3 hub-side setting(s)") for n in tool.notes)
    kept = checks(client, "ledger")
    assert kept["launch"]["status"] == "pass" and kept["health"]["status"] == "pass"

    # a reset: the override goes, and the analysis brings back what it finds (here: what a Node app's package says)
    inferred = put(client, node_repo, "crm", "CRM").manifest.launch.command
    assert inferred
    assert edit(client, "crm", {"launch": {"command": "node src/server.js --inspect"}}).status_code == 200
    assert hub.get_tool("crm").manifest.launch.command == "node src/server.js --inspect"
    response = edit(client, "crm", {"launch": {"command": None}})
    assert response.status_code == 200 and "launch.command" not in response.json()["overridden"]
    wait_for(lambda: hub.get_tool("crm").manifest.launch.command == inferred)
    assert hub.get_tool("crm").manifest_overrides == {}


# --------------------------------------------------------------------------------------
# approvals: a launch patch is an administrator's, and only an administrator asks again
# --------------------------------------------------------------------------------------


def test_a_launch_patch_is_approved_by_an_administrator_and_only_they_ask_again(client, sign_in, wait_for,
                                                                              tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_source(tmp_path / "keycloak"))
    launch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "launch_command"), None))
    operator = sign_in("operator")
    refused = operator.post(f"/api/approvals/{launch.approval_id}", json={"approve": True})
    assert refused.status_code == 403 and refused.json()["detail"]["code"] == "admin_required"
    assert "changes how a tool is started" in refused.json()["detail"]["message"]
    assert operator.post(f"/api/tools/{tool_id}/patches", json={"again": True}).status_code == 403

    # an operator may still reject it; then nothing proposes it again by itself, however often it is asked
    assert operator.post(f"/api/approvals/{launch.approval_id}", json={"approve": False}).status_code == 200
    wait_for(lambda: hub.get_patch(launch.id).status == "rejected")
    for _ in range(3):
        result = client.post(f"/api/tools/{tool_id}/patches").json()
        assert result["patches"] == []
        assert any(s["fix"] == "launch_command" and s["reason"].startswith("You rejected") for s in result["skipped"])
    assert len(hub.patches(tool_id)) == 1
    assert operator.post(f"/api/tools/{tool_id}/patches").status_code == 202  # proposing as such stays operator's

    # an administrator asks again: proposed again, and their approval applies it
    again = client.post(f"/api/tools/{tool_id}/patches", json={"again": True})
    assert again.status_code == 202, again.text
    [new_id] = again.json()["patches"]
    assert hub.get_patch(new_id).strategy == "launch_command" and len(hub.patches(tool_id)) == 2
    applied = approve(client, wait_for, new_id)
    assert applied.status == "applied", applied.error


# --------------------------------------------------------------------------------------
# end to end: every shape ends closed, or says exactly what is missing and offers the next step
# --------------------------------------------------------------------------------------


def test_a_keycloak_source_checkout_is_closed_by_one_administrator_approval(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_source(tmp_path / "keycloak"))
    found = checks(client, tool_id)
    assert found["manifest"]["status"] == "pass" and "built-in Keycloak profile" in found["manifest"]["detail"]
    assert (found["launch"]["status"], found["launch"]["fix"]) == ("warn", "launch_command")
    assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "launch_command")
    assert found["api"]["status"] == "pass" and "Keycloak (admin API)" in found["api"]["detail"]
    assert found["events"]["status"] == "warn" and found["events"]["fix"] is None
    assert "switched on per realm" in found["events"]["detail"]

    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    result = client.post(f"/api/tools/{tool_id}/patches").json()  # the import's own pass made it: nothing new
    assert result["patches"] == [] and result["pending"] == [patch.id]
    assert [p.strategy for p in hub.patches(tool_id)] == ["launch_command"]  # exactly one, and no add_manifest

    applied = approve(client, wait_for, patch.id)
    assert applied.status == "applied", applied.error
    closed = wait_for(lambda: (c := checks(client, tool_id))["launch"]["status"] == "pass" and c)
    assert closed["launch"]["detail"] == f"`{KC_COMMAND}`"
    assert closed["health"]["status"] == "pass" and closed["health"]["detail"] == "http://localhost:9000/health/ready"
    assert client.get(f"/api/tools/{tool_id}").json()["report"]["score"] >= 90

    password = launch_secrets._read(hub.settings.workspace, tool_id)["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert len(password) >= 24 and password not in everything_an_api_shows(client, tool_id)

    again = client.post(f"/api/tools/{tool_id}/patches").json()
    assert again == {"patches": [], "pending": [], "skipped": []}
    assert hub.get_tool(tool_id).status == "ready"


def test_a_keycloak_release_folder_is_closed_by_one_health_config_approval(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_release(tmp_path / "keycloak"))
    found = checks(client, tool_id)
    assert found["launch"]["status"] == "pass" and "bin/kc.sh start-dev" in found["launch"]["detail"]
    assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "health_config")
    assert found["api"]["status"] == "pass"
    patch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "health_config"), None))
    assert [p.strategy for p in hub.patches(tool_id)] == ["health_config"]
    applied = approve(client, wait_for, patch.id)
    assert applied.status == "applied", applied.error
    closed = wait_for(lambda: (c := checks(client, tool_id))["health"]["status"] == "pass" and c)
    assert closed["health"]["detail"] == "http://localhost:9000/health/ready"
    assert hub.get_tool(tool_id).manifest.launch.env == {"KC_HEALTH_ENABLED": "true"}


def test_an_unknown_maven_app_says_what_is_missing_and_the_editor_closes_it(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, java_app(tmp_path / "ledger"))
    found = checks(client, tool_id)
    assert found["manifest"]["status"] == "pass"
    assert (found["launch"]["status"], found["launch"]["fix"]) == ("warn", "launch_command")
    assert EDITOR in found["launch"]["detail"]

    def card():
        return next(i for i in client.get(f"/api/tools/{tool_id}/strategies").json() if i["id"] == "adapter")

    stuck = wait_for(lambda: (c := card())["state"] == "needs_input" and c)
    assert stuck["action"] == "edit_manifest" and EDITOR in stuck["detail"]
    result = client.post(f"/api/tools/{tool_id}/patches").json()
    launch = next(s for s in result["skipped"] if s["fix"] == "launch_command")
    assert launch["state"] == "needs_input" and EDITOR in launch["reason"] and result["patches"] == []
    assert any("was not proposed" in e.get("text", "") and EDITOR in e.get("text", "")
               for e in hub.store.tail("activity", 500))
    assert hub.agent_errors.stored("patcher") == 0

    response = edit(client, tool_id, {"launch": {"command": "java -jar target/ledger.jar", "port": 8080}})
    assert response.status_code == 200, response.text
    after = {c["id"]: c for c in response.json()["report"]["checks"]}
    assert after["launch"]["status"] == "pass"
    assert after["health"]["status"] == "warn" and after["health"]["fix"] in ("health_probe", "health_endpoint")
    assert card()["state"] in ("available", "pending")  # a patch can close the rest now


def test_the_shipped_keycloak_example_passes_except_events():
    root = ROOT / "examples" / "keycloak"
    m, _ = analyze_repo(root, "keycloak", "keycloak")
    assert m.native and m.known is not None and m.known.profile == "keycloak"
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())["services"]["keycloak"]
    assert compose["image"] == "quay.io/keycloak/keycloak:26.0" and compose["command"] == "start-dev"
    assert compose["environment"]["KC_HEALTH_ENABLED"] == "true" and set(compose["ports"]) == {"8080:8080", "9000:9000"}
    report = evaluate_tool(Tool(id="keycloak", name="Keycloak", source_type="local", source=str(root),
                                path=str(root), manifest=m, status="ready"), [])
    assert report.level == "native"
    status = {c.id: c.status for c in report.checks}
    assert status.pop("events") == "warn" and set(status.values()) == {"pass"}, status
    assert m.health.url == "http://localhost:9000/health/ready"
    assert m.api.type == "rest" and m.api.base_url == "http://localhost:8080/admin/realms"


def test_a_keycloak_stored_by_an_earlier_atrium_is_migrated_at_start(tmp_path: Path, wait_for):
    from hub.core import Hub

    root = keycloak_source(tmp_path / "keycloak")
    settings = make_settings(tmp_path)
    old = Hub(settings)
    old.save_tool(Tool(id="keycloak", name="Keycloak", source_type="local", source=str(root), path=str(root),
                       status="ready", created_at=1.0,
                       manifest=Manifest(id="keycloak", name="Keycloak", stack=["java"], native=True,
                                         provides=["auth.oidc", "auth.saml", "identity.source"],
                                         auth={"sso": "oidc"}, events={"emits": ["keycloak.changed"]})))
    old.save_patch(Patch(id="p_adopt", tool_id="keycloak", title="Adopt a hub manifest", rationale="",
                         strategy="add_manifest", target="repo", status="applied", branch="hub/add-manifest-adopt",
                         changes=[FileChange(path="hub.manifest.yaml", content="launch:\n  command: 'TODO: x'\n")],
                         manifest_update={"native": True}, created_at=2.0))
    old.save_patch(Patch(id="p_events", tool_id="keycloak", title="Add an event adapter", rationale="",
                         strategy="event_adapter", target="adapter", status="applied",
                         changes=[FileChange(path="events/adapter.py",
                                             content='URL = os.environ.get("WATCH_URL", "https://example.com")\n')],
                         manifest_update={"events": {"emits": ["keycloak.changed"]}}, created_at=3.0))
    old.store.close()

    with TestClient(create_app(settings), headers={"X-Hub-Request": "1"}) as c:
        hub = hub_of(c)
        hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
        assert c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
        c.post("/api/integration/evaluate")
        manifest = wait_for(lambda: (t := hub.get_tool("keycloak")).report and next(
            x for x in t.report.checks if x.id == "manifest"))
        assert "Ships its own" not in manifest.detail and manifest.status == "pass"
        assert "waits unmerged at hub/add-manifest-adopt" in manifest.detail
        assert "keycloak.changed" not in hub.get_tool("keycloak").manifest.events.emits
        result = c.post("/api/tools/keycloak/patches").json()
        assert [hub.get_patch(i).strategy for i in result["patches"]] == ["launch_command"]
        events = next(x for x in hub.get_tool("keycloak").report.checks if x.id == "events")
        assert events.fix is None  # no example.com poller proposed again


def test_launch_secrets_and_outcomes_go_with_the_tool(client, tmp_path: Path):
    hub = hub_of(client)
    put(client, java_app(tmp_path / "ledger"), "ledger", "Ledger")
    assert edit(client, "ledger", {"launch": {"command": "java -jar app.jar", "port": 8080,
                                              "env": {"LEDGER_DB_PASSWORD": SECRET}}}).status_code == 200
    client.post("/api/tools/ledger/patches")
    secrets_file = hub.settings.workspace / "adapters" / "ledger" / launch_secrets.ENV_FILE
    assert secrets_file.exists() and hub.store.get("gap_outcomes", "ledger") is not None
    assert client.delete("/api/tools/ledger").status_code == 200
    assert not secrets_file.exists() and hub.store.get("gap_outcomes", "ledger") is None
    assert SECRET not in "".join(launch_secrets.values(hub.settings.workspace))


def test_check_edit_normalises_what_it_accepts():
    assert overrides.check_edit("launch.cwd", "./") == "."
    assert overrides.check_edit("launch.cwd", "server\\app") == "server/app"
    assert overrides.check_edit("launch.command", "  npm start  ") == "npm start"
    assert overrides.check_edit("api.type", "GraphQL") == "graphql"
    assert overrides.check_edit("api.spec", "docs/openapi.yaml") == "docs/openapi.yaml"
    assert overrides.check_edit("health.url", "tcp://127.0.0.1:5432") == "tcp://127.0.0.1:5432"
    assert overrides.check_edit("ui.url", None) is None
    with pytest.raises(ValueError, match="cannot be set by hand"):
        overrides.check_edit("native", True)
    with pytest.raises(ValueError, match="1 to 65535"):
        overrides.check_edit("launch.port", True)
    assert strategies.EDITABLE_CHECKS == ("launch", "health", "api")  # the rows that offer the editor
