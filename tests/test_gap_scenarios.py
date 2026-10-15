"""End-to-end gap scenarios: every imported program ends closed (automatically or with one approval), or its card says
exactly what is missing and offers a working next step - never a dead-end fix, a silent skip, a duplicate proposal or
a false pass (the integration of build spec stages 1-3, proven with the real app and the fake AI model).

1. A git checkout of Keycloak's source (thousands of files, a nested testsuite keycloak.conf, an OpenAPI file late in
   the tree): one administrator approval of the launch_command patch closes Launch and Health (the recipe switches
   the health check on), the API passes through the profile and the built-in connector, the Hub manifest check
   names Atrium's Keycloak profile (never "Ships its own"), nothing is proposed twice, and a Re-analyse keeps it all.
2. A Keycloak release folder (bin/kc.sh, jars): open source, started by its own launcher; health_config closes Health.
3. An unknown Maven web application: with an AI model the Patch Agent reads the folder and proposes a launch command
   for review; without one the gap says "needs input" and names the editor; health follows once a port is known.
4. The AI code patch on a big repository: a rewrite of a file the model never read is a tool error it fixes by
   reading the file - no crash, no agent error.
5. A rejected patch is not proposed again; a patch whose apply fails twice is not tried a third time, and the error
   shows on the check.
6. A tool stored by an earlier Atrium (native from an applied add_manifest, a TODO launch command) is migrated at start.
7. The Operator answers a start without a launch command plainly - no agent error, also when the rules chat asks.
8. The administrators' manifest editor: values survive re-analysis; operators and viewers get 403; environment values
   never reach GET /api/tools or the live event stream; a launch patch approved after an administrator set the
   command by hand is set aside, not applied over it.
9. A project merely named after a product ("keycloak-theme") or kept in a folder named after one gets none of that
   product's facts or passes.

Every fixture is built in tmp_path inside the tests.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any, Callable

from fastapi.testclient import TestClient

from conftest import ADMIN_PASSWORD, make_settings
from hub.app import create_app
from hub.dashboards import widgets
from hub.integration import gapfix, launch_secrets
from hub.integration.analyzer import analyze_repo, list_files
from hub.models import FileChange, Manifest, Patch, Tool
from llm_fakes import FakeClaude, ScriptedClaude, block, message, tool_results, tool_turn, use_claude

EDITOR = "Integration > Launch > Edit"
KC_IMAGE = "quay.io/keycloak/keycloak:26.0"
# the recipe publishes on loopback only: Docker would otherwise publish past a host firewall (review)
KC_COMMAND = ("docker run --rm --name atrium-{id} -p 127.0.0.1:8080:8080 -p 127.0.0.1:9000:9000 "
              "-e KC_HEALTH_ENABLED=true "
              "-e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD " + KC_IMAGE + " start-dev")
KC_DOCS_API = "https://www.keycloak.org/docs-api/latest/rest-api/openapi.json"
TOKEN_LIKE = re.compile(r"[A-Za-z0-9_-]{32}")  # a generated launch secret (secrets.token_urlsafe(24))


# --------------------------------------------------------------------------------------
# folders (built in tmp_path)
# --------------------------------------------------------------------------------------


def write(root: Path, rel: str, text: str = "") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def many(root: Path, folder: str, count: int, suffix: str = ".java") -> None:
    """`count` small source files in `folder` (the bulk of a big repository)."""
    base = root / folder
    base.mkdir(parents=True, exist_ok=True)
    for n in range(count):
        (base / f"Gen{n:05d}{suffix}").write_text(f"class Gen{n} {{}}\n")


def keycloak_checkout(root: Path) -> Path:
    """The shape of a git import of keycloak/keycloak: the Maven parent pom (Quarkus inside), quarkus/ and services/
    modules, a testsuite with its own keycloak.conf deep down, and an OpenAPI file of the admin client late in the
    tree - more than the analyzer's 4,000-file listing holds before reaching it."""
    write(root, "pom.xml", "<project>\n  <groupId>org.keycloak</groupId>\n  <artifactId>keycloak-parent</artifactId>\n"
                           "  <version>999.0.0-SNAPSHOT</version>\n  <packaging>pom</packaging>\n"
                           "  <properties><quarkus.version>3.15.1</quarkus.version></properties>\n"
                           "  <modules><module>quarkus</module><module>services</module></modules>\n</project>\n")
    write(root, "README.md", "# Keycloak\n\nOpen Source Identity and Access Management.\n\nBuild with ./mvnw clean "
                             "install -DskipTests, then run quarkus/dist.\n")
    write(root, "mvnw", "#!/bin/sh\n")
    write(root, "quarkus/runtime/src/main/java/org/keycloak/quarkus/runtime/KeycloakMain.java",
          "package org.keycloak.quarkus.runtime;\npublic class KeycloakMain {}\n")
    write(root, "quarkus/runtime/src/main/resources/application.properties", "quarkus.http.port=8080\n")
    many(root, "model/jpa", 4_100)  # shallow bulk: the breadth-first listing is full before depth 4
    many(root, "services/src/main/java/org/keycloak/services/resources/admin", 400)
    write(root, "services/src/main/java/org/keycloak/services/resources/HealthCheck.java",
          'class HealthCheck { String path = "/health"; }\n')
    write(root, "testsuite/integration-arquillian/tests/base/src/test/resources/keycloak.conf",
          "# test server\nhealth-enabled=true\n")
    many(root, "testsuite/integration-arquillian/tests/base/src/test/java", 300)
    write(root, "js/libs/keycloak-admin-client/openapi.json", json.dumps({"openapi": "3.0.0", "paths": {}}))
    return root


def keycloak_release(root: Path, version: str = "26.0.5") -> Path:
    """An unpacked Keycloak release: its launchers in bin/, conf/, the jars in lib/ and version.txt."""
    write(root, "bin/kc.sh", '#!/bin/sh\nexec java -jar "$(dirname "$0")/../lib/quarkus-run.jar" "$@"\n')
    write(root, "bin/kc.bat", "@echo off\r\n")
    write(root, "conf/keycloak.conf", "# db=postgres\n")
    write(root, "version.txt", f"Keycloak - Version {version}\n")
    for n in range(40):
        (root / "lib" / "lib" / "main").mkdir(parents=True, exist_ok=True)
        (root / "lib" / "lib" / "main" / f"org.keycloak.module{n}.jar").write_bytes(b"PK\x03\x04")
    (root / "lib" / "quarkus-run.jar").write_bytes(b"PK\x03\x04")
    return root


def ledger_app(root: Path, *, framework: str = "spring", bulk: int = 4_200) -> Path:
    """An unknown Java web application built with Maven: no launch rule fits, the README and docs/RUNNING.md say how
    it starts (the docs file is not among the files shown up front: the model has to read it)."""
    dependency = {"spring": "<artifactId>spring-boot-starter-web</artifactId>",
                  "quarkus": "<artifactId>quarkus-rest</artifactId>"}[framework]
    write(root, "pom.xml", f"<project>\n  <groupId>com.example</groupId>\n  <artifactId>ledger</artifactId>\n"
                           f"  <version>1.4.0</version>\n  <dependencies><dependency>{dependency}</dependency>"
                           "</dependencies>\n</project>\n")
    write(root, "mvnw", "#!/bin/sh\n")  # the Maven wrapper: a model's command must start a program of the folder (R16)
    write(root, "README.md", "# Ledger\n\nBooks and invoices for small firms.\n\nSee docs/RUNNING.md to run it.\n")
    write(root, "docs/RUNNING.md", "# Running\n\nStart it with `./mvnw spring-boot:run`; it listens on port 8080 and "
                                   "answers GET /actuator/health.\n")
    write(root, "src/main/java/com/example/ledger/LedgerApplication.java",
          "package com.example.ledger;\npublic class LedgerApplication { public static void main(String[] a) {} }\n")
    many(root, "src/main/java/com/example/ledger/books", bulk)
    return root


def flask_monorepo(root: Path) -> Path:
    """A Python web app with thousands of files; the route module sits beyond the old 2,000-file list."""
    write(root, "requirements.txt", "flask==3.0.0\n")
    write(root, "app.py", "from zz_web.routes import app\n\nif __name__ == '__main__':\n    app.run(port=5000)\n")
    write(root, ".env.example", "PORT=5000\n")
    many(root, "aa_generated", 2_500, ".py")
    write(root, "zz_web/__init__.py")
    write(root, "zz_web/routes.py", "from flask import Flask\napp = Flask(__name__)\n\n\n@app.get('/')\ndef index():\n"
                                    "    return 'shop'\n")
    return root


# --------------------------------------------------------------------------------------
# driving the running hub as a person does
# --------------------------------------------------------------------------------------


def hub_of(client: TestClient):
    return client.app.state.hub


def in_suite(client: TestClient, name: str) -> int:
    """How often the Hub Supervisor has scored `name` after an analysis (import or Re-analyse)."""
    return sum(1 for e in hub_of(client).store.tail("activity", 2_000) if f"{name} is in the suite" in e.get("text", ""))


def imported(client: TestClient, wait_for, root: Path, name: str | None = None) -> str:
    """Import a local folder (Integration > Import) and wait until it is analysed and scored; the propose pass the
    import starts runs under the tool's lock, so the next propose waits for it."""
    response = client.post("/api/tools/import", json={"source_type": "local", "source": str(root),
                                                      **({"name": name} if name else {})})
    assert response.status_code == 202, response.text
    tool_id = response.json()["id"]
    wait_for(lambda: (t := hub_of(client).get_tool(tool_id)) and t.report and t.status in ("ready", "needs_patch")
             and in_suite(client, t.name), timeout=60)
    return tool_id


def reanalyse(client: TestClient, wait_for, tool_id: str) -> Tool:
    """Re-analyse (Integration > Re-analyse) and wait until the tool is scored again."""
    hub = hub_of(client)
    name = hub.get_tool(tool_id).name
    before = in_suite(client, name)
    assert client.post(f"/api/tools/{tool_id}/analyze").status_code == 202
    wait_for(lambda: in_suite(client, name) > before, timeout=60)
    return wait_for(lambda: (t := hub.get_tool(tool_id)).status in ("ready", "needs_patch") and t.report and t)


def checks(client: TestClient, tool_id: str) -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in client.get(f"/api/tools/{tool_id}").json()["report"]["checks"]}


def propose(client: TestClient, tool_id: str, **body: Any) -> dict[str, Any]:
    response = client.post(f"/api/tools/{tool_id}/patches", json=body or None)
    assert response.status_code == 202, response.text
    return response.json()


def decide(client: TestClient, wait_for, patch_id: str, approve: bool = True) -> Patch:
    hub = hub_of(client)
    patch = hub.get_patch(patch_id)
    assert patch.approval_id, "every proposed patch names the approval it waits for"
    response = client.post(f"/api/approvals/{patch.approval_id}", json={"approve": approve})
    assert response.status_code == 200, response.text
    return wait_for(lambda: (p := hub.get_patch(patch_id)).status != "proposed" and p)


def card(client: TestClient, tool_id: str, item: str = "adapter") -> dict[str, Any]:
    return next(i for i in client.get(f"/api/tools/{tool_id}/strategies").json() if i["id"] == item)


def strategies_of(hub, tool_id: str) -> list[str]:
    return sorted(p.strategy for p in hub.patches(tool_id))


def not_proposed_log(hub, name: str) -> list[str]:
    return [e["text"] for e in hub.store.tail("activity", 2_000)
            if e.get("text", "").startswith(f"{name}: '") and "was not proposed" in e.get("text", "")]


def no_agent_errors(hub, *agents: str) -> None:
    for agent in agents or ("patcher", "supervisor", "operator"):
        assert hub.agent_errors.stored(agent) == 0, agent


def everything_shown(client: TestClient, tool_id: str) -> str:
    """Every API answer a signed-in person reads about the tool and the hub's work on it."""
    answers = [client.get(path).json() for path in (
        f"/api/tools/{tool_id}", "/api/tools", "/api/activity?limit=1000", "/api/messages?limit=1000",
        "/api/approvals", f"/api/tools/{tool_id}/strategies", "/api/integration")]
    answers += [client.get(f"/api/patches/{p.id}").json() for p in hub_of(client).patches(tool_id)]
    return json.dumps(answers)


def sse_events(hub, action: Callable[[], Any]) -> list[dict[str, Any]]:
    """The live events (GET /api/events, as an operator's stream renders them) published while `action` runs."""
    queue = hub.bus.subscribe(maxsize=5_000)
    try:
        action()
        events = []
        while not queue.empty():
            events.append(hub.conversations.event(queue.get_nowait(), True))
    finally:
        hub.bus.unsubscribe(queue)
    return events


def done() -> Any:
    return message(content=[block("text", text="Done.")])


def tool_errors(fake: FakeClaude) -> list[str]:
    return [r["content"] for c in fake.calls for r in tool_results(c) if r.get("is_error")]


def submit_tool(call: dict[str, Any]) -> str | None:
    return next((t["name"] for t in call.get("tools") or [] if str(t.get("name", "")).startswith("submit_")), None)


# --------------------------------------------------------------------------------------
# 1. Keycloak source checkout
# --------------------------------------------------------------------------------------


def test_1_a_keycloak_source_checkout_closes_with_one_admin_approval(client, wait_for, tmp_path: Path, monkeypatch):
    hub = hub_of(client)
    root = keycloak_checkout(tmp_path / "keycloak")
    assert len(list_files(root, 100_000)) > 4_000
    fake = use_claude(hub, monkeypatch, FakeClaude())  # an AI model is there: nothing here may need it
    tool_id = imported(client, wait_for, root)
    tool = hub.get_tool(tool_id)
    m = tool.manifest
    assert m.kind == "oss" and "java" in m.stack and not m.native
    assert (m.known.profile, m.known.shape, m.known.by) == ("keycloak", "source", "marker")
    assert m.api.type == "rest" and m.api.spec == KC_DOCS_API  # the profile's, not the testsuite's or a guess
    assert m.health.url is None and m.launch.command is None  # no "/health" string from the source as a URL

    found = checks(client, tool_id)
    # Hub manifest: Atrium's own Keycloak profile describes it, and says so - never "Ships its own hub manifest"
    assert found["manifest"]["status"] == "pass" and "built-in Keycloak profile" in found["manifest"]["detail"]
    assert "Ships its own" not in found["manifest"]["detail"] and found["manifest"]["fix"] is None
    assert (found["launch"]["status"], found["launch"]["fix"]) == ("warn", "launch_command")
    assert KC_IMAGE in found["launch"]["detail"] and "Docker on the hub machine" in found["launch"]["detail"]
    # Health: the launch_command patch switches it on (one approval closes both, never a code patch)
    assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "launch_command")
    assert "9000" in found["health"]["detail"] and "KC_HEALTH_ENABLED=true" in found["health"]["detail"]
    assert found["api"]["status"] == "pass" and "Keycloak admin REST API" in found["api"]["detail"]
    assert "built-in connector: Keycloak" in found["api"]["detail"]
    assert found["events"]["status"] == "warn" and found["events"]["fix"] is None  # honest: no hollow poller
    assert found["sso"]["status"] == "pass"

    # the import's own propose pass made exactly one patch; pressing Propose again adds nothing
    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    for _ in range(3):
        result = propose(client, tool_id)
        assert result["patches"] == [] and result["pending"] == [patch.id] and result["skipped"] == []
    assert strategies_of(hub, tool_id) == ["launch_command"]  # no health_endpoint code patch, no add_manifest
    assert patch.target == "manifest" and patch.fingerprint and patch.approval_id
    assert patch.manifest_update["launch"]["command"] == KC_COMMAND.format(id=tool_id)
    assert patch.manifest_update["health"] == {"url": "http://localhost:9000/health/ready"}
    assert patch.manifest_update["launch"]["secret_env"] == ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    approval = hub.approvals.get(patch.approval_id)
    assert approval.payload["strategy"] == "launch_command" and "only an administrator" in approval.detail.lower()
    assert approval.detail.lower().count("only an administrator") == 1  # said once
    assert widgets.needs_admin(approval, hub)  # the Home approvals widget says so too
    assert not [c for c in fake.calls if submit_tool(c)]  # no paid launch proposal or code patch
    assert card(client, tool_id)["state"] == "pending"

    applied = decide(client, wait_for, patch.id)
    assert applied.status == "applied", applied.error
    closed = wait_for(lambda: (c := checks(client, tool_id))["launch"]["status"] == "pass" and c)
    assert closed["launch"]["detail"] == f"`{KC_COMMAND.format(id=tool_id)}`"
    assert closed["health"]["status"] == "pass" and closed["health"]["detail"] == "http://localhost:9000/health/ready"
    assert client.get(f"/api/tools/{tool_id}").json()["report"]["score"] >= 90
    password = launch_secrets._read(hub.settings.workspace, tool_id)["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert len(password) >= 24 and password not in everything_shown(client, tool_id)
    assert not TOKEN_LIKE.search(json.dumps([applied.manifest_update, [c.content for c in applied.changes]]))

    # Re-analyse: the hub-side settings are applied again, the checks stay closed
    tool = reanalyse(client, wait_for, tool_id)
    assert tool.manifest.launch.command == KC_COMMAND.format(id=tool_id)
    assert any(n.startswith("Kept ") and "launch.command" in n for n in tool.notes)
    after = checks(client, tool_id)
    assert after["launch"]["status"] == "pass" and after["health"]["status"] == "pass"
    assert after["manifest"]["status"] == "pass" and after["api"]["status"] == "pass"

    # Propose again: nothing new, nothing waiting, no reason given for a gap that is closed
    assert propose(client, tool_id) == {"patches": [], "pending": [], "skipped": []}
    assert strategies_of(hub, tool_id) == ["launch_command"]
    assert hub.get_tool(tool_id).status == "ready"
    assert card(client, tool_id)["state"] == "active"
    assert not [c for c in fake.calls if submit_tool(c)]
    no_agent_errors(hub)


# --------------------------------------------------------------------------------------
# 2. Keycloak release folder
# --------------------------------------------------------------------------------------


def test_2_a_keycloak_release_folder_starts_with_its_launcher_and_health_config_closes_health(client, wait_for,
                                                                                            tmp_path: Path):
    hub = hub_of(client)
    root = keycloak_release(tmp_path / "keycloak-26.0.5")
    m, _ = analyze_repo(root, "keycloak", "keycloak-26.0.5")
    assert m.kind == "oss" and {"java", "dist"} <= set(m.stack)  # jars and a launcher: a release, not closed
    assert (m.known.profile, m.known.shape, m.known.version) == ("keycloak", "release", "26.0.5")
    assert m.launch.command == "bin/kc.sh start-dev" and m.launch.port == 8080
    assert m.api.base_url == "http://localhost:8080/admin/realms"

    tool_id = imported(client, wait_for, root)
    found = checks(client, tool_id)
    assert found["launch"]["status"] == "pass" and found["launch"]["detail"] == "`bin/kc.sh start-dev`"
    assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "health_config")
    assert found["api"]["status"] == "pass" and found["manifest"]["status"] == "pass"
    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    assert strategies_of(hub, tool_id) == ["health_config"]  # no probe, no code patch for a folder of jars
    assert patch.manifest_update == {"launch": {"env": {"KC_HEALTH_ENABLED": "true"}},
                                     "health": {"url": "http://localhost:9000/health/ready"}}
    assert propose(client, tool_id)["patches"] == []

    applied = decide(client, wait_for, patch.id)
    assert applied.status == "applied", applied.error
    closed = wait_for(lambda: (c := checks(client, tool_id))["health"]["status"] == "pass" and c)
    assert closed["health"]["detail"] == "http://localhost:9000/health/ready"
    tool = reanalyse(client, wait_for, tool_id)
    assert tool.manifest.launch.env == {"KC_HEALTH_ENABLED": "true"} and tool.manifest.launch.command == "bin/kc.sh start-dev"
    assert checks(client, tool_id)["health"]["status"] == "pass"

    # starting it: the launcher from the release folder, with health switched on in its environment
    started: dict[str, Any] = {}

    async def fake_start(tool_id_, command, cwd=None, env=None):
        started.update(command=command, cwd=cwd, env=env)
        return {"status": "started", "pid": 1}

    hub.processes.start = fake_start
    assert client.post(f"/api/tools/{tool_id}/start").status_code == 200
    assert started["command"] == "bin/kc.sh start-dev" and started["cwd"] == str(root)
    assert started["env"]["KC_HEALTH_ENABLED"] == "true" and started["env"]["PORT"] == "8080"
    assert propose(client, tool_id) == {"patches": [], "pending": [], "skipped": []}
    no_agent_errors(hub)


# --------------------------------------------------------------------------------------
# 3. An unknown Maven web application
# --------------------------------------------------------------------------------------

ENRICHED = {"description": "Books and invoices for small firms.", "provides": [], "consumes": []}


def launch_reader(call: dict[str, Any]) -> Any:
    """The model's side of a launch proposal: it reads docs/RUNNING.md (not shown up front), then submits what that
    file says, naming it as evidence."""
    step = sum(1 for m in call["messages"] if m.get("role") == "assistant")
    if step == 0:
        return tool_turn(("read_file", {"path": "docs/RUNNING.md", "start_line": 0, "end_line": 0}))
    if step == 1:
        assert "spring-boot:run" in tool_results(call)[0]["content"]  # what it read came back
        return tool_turn(("submit_launch", {"command": "./mvnw spring-boot:run", "setup": "", "cwd": "", "port": 8080,
                                            "health_path": "/actuator/health", "evidence": ["docs/RUNNING.md"],
                                            "rationale": "docs/RUNNING.md says so."}))
    return done()


def test_3a_an_unknown_maven_app_gets_an_ai_launch_proposal_read_from_its_folder(client, wait_for, tmp_path: Path,
                                                                                 monkeypatch):
    hub = hub_of(client)
    seen: list[str] = []

    def script(call: dict[str, Any]) -> Any:
        seen.append(submit_tool(call) or "chat")
        if submit_tool(call) == "submit_launch":
            return launch_reader(call)
        return done()  # a code patch for the health check: the model gives up (the probe is planned instead)

    fake = use_claude(hub, monkeypatch, ScriptedClaude(script, json_result=ENRICHED))
    root = ledger_app(tmp_path / "ledger")
    tool_id = imported(client, wait_for, root)
    m = hub.get_tool(tool_id).manifest
    assert m.known is None and {"java", "spring"} <= set(m.stack) and m.launch.port == 8080
    found = checks(client, tool_id)
    assert (found["launch"]["status"], found["launch"]["fix"]) == ("warn", "launch_command")
    assert EDITOR in found["launch"]["detail"] and "add_manifest" not in (found["launch"]["fix"] or "")

    launch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "launch_command"), None))
    assert launch.title.startswith("Launch command proposed by") and launch.title.endswith("check it before approving")
    assert launch.generated_by.get("provider") == "anthropic"
    assert launch.manifest_update["launch"] == {"command": "./mvnw spring-boot:run", "cwd": "."}
    assert launch.manifest_update["health"] == {"url": "http://localhost:8080/actuator/health"}
    assert "docs/RUNNING.md" in launch.rationale
    assert "only an administrator can" in hub.approvals.get(launch.approval_id).detail
    launch_calls = [c for c in fake.calls if submit_tool(c) == "submit_launch"]
    assert len(launch_calls) == 3 and tool_errors(fake) == []  # read_file, an accepted submit, one closing sentence
    names = [t["name"] for t in launch_calls[0]["tools"]]
    assert {"list_files", "read_file", "search", "submit_launch"} <= set(names)

    # proposing again pays for nothing: the proposal waits for approval
    calls = len(fake.calls)
    result = propose(client, tool_id)
    assert result["patches"] == [] and launch.id in result["pending"] and len(fake.calls) == calls
    assert [p.strategy for p in hub.patches(tool_id)].count("launch_command") == 1

    # the proposal also sets the health check: no second patch (code patch or probe) for the same gap meanwhile
    assert not any(p.strategy.startswith("health") for p in hub.patches(tool_id))
    assert "submit_patch" not in seen  # and no paid code patch for it
    health = next(o for o in gapfix.outlook(hub, hub.get_tool(tool_id)) if o.check == "health")
    assert (health.state, health.patch_id) == ("pending", launch.id)
    wait_for(lambda: "it also sets the health check" in checks(client, tool_id)["health"]["detail"])
    applied = decide(client, wait_for, launch.id)
    assert applied.status == "applied", applied.error
    closed = wait_for(lambda: (c := checks(client, tool_id))["launch"]["status"] == "pass" and c)
    assert closed["launch"]["detail"] == "`./mvnw spring-boot:run`"
    assert closed["health"]["status"] == "pass" and closed["health"]["detail"] == "http://localhost:8080/actuator/health"
    tool = reanalyse(client, wait_for, tool_id)
    assert tool.manifest.launch.command == "./mvnw spring-boot:run"
    assert checks(client, tool_id)["launch"]["status"] == "pass"
    no_agent_errors(hub)


def test_3b_without_a_model_the_launch_gap_needs_input_and_names_the_editor(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, ledger_app(tmp_path / "ledger", framework="quarkus"))
    m = hub.get_tool(tool_id).manifest
    assert {"java", "quarkus"} <= set(m.stack) and m.launch.port == 8080 and m.api.type == "rest"
    result = propose(client, tool_id)
    launch = next(s for s in result["skipped"] if s["fix"] == "launch_command")
    assert launch["state"] == "needs_input" and EDITOR in launch["reason"]
    assert "Settings > AI providers" in launch["reason"]  # what a model would add
    # health: the port is known (Quarkus' default), so without a model a probe is proposed - never a dead end
    found = checks(client, tool_id)
    assert found["health"]["fix"] in ("health_endpoint", "health_probe")
    assert "health_probe" in strategies_of(hub, tool_id)
    adapters = card(client, tool_id)
    assert adapters["action"] == "edit_manifest" and EDITOR in adapters["detail"]
    assert len([t for t in not_proposed_log(hub, "ledger") if "Launchable from the hub" in t]) == 1
    propose(client, tool_id)
    propose(client, tool_id)
    assert len([t for t in not_proposed_log(hub, "ledger") if "Launchable from the hub" in t]) == 1  # logged once
    no_agent_errors(hub)


def test_3c_health_follows_once_the_editor_gives_a_port(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    root = ledger_app(tmp_path / "ledger", framework="spring", bulk=50)
    (root / "pom.xml").write_text("<project>\n  <groupId>com.example</groupId>\n  <artifactId>ledger</artifactId>\n"
                                  "  <version>1.4.0</version>\n</project>\n")  # plain Maven: no framework, no port
    tool_id = imported(client, wait_for, root)
    m = hub.get_tool(tool_id).manifest
    assert m.launch.port is None and m.launch.command is None
    found = checks(client, tool_id)
    assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "launch_command")
    assert "No port or address is known yet" in found["health"]["detail"]
    result = propose(client, tool_id)
    assert {s["fix"] for s in result["skipped"]} >= {"launch_command"}
    assert not any(p.strategy.startswith("health") for p in hub.patches(tool_id))

    response = client.patch(f"/api/tools/{tool_id}/manifest",
                            json={"launch": {"command": "java -jar target/ledger.jar", "port": 8080}})
    assert response.status_code == 200, response.text
    found = {c["id"]: c for c in response.json()["report"]["checks"]}
    assert found["launch"]["status"] == "pass"
    assert found["health"]["fix"] in ("health_endpoint", "health_probe")
    result = propose(client, tool_id)
    probe = next(hub.get_patch(i) for i in result["patches"] if hub.get_patch(i).strategy == "health_probe")
    assert "port: 8080" in probe.changes[0].content
    no_agent_errors(hub)


# --------------------------------------------------------------------------------------
# 4. The AI code patch on a big repository
# --------------------------------------------------------------------------------------

ROUTES = "zz_web/routes.py"
HEALTHY = ("from flask import Flask\napp = Flask(__name__)\n\n\n@app.get('/')\ndef index():\n    return 'shop'\n\n\n"
           "@app.get('/healthz')\ndef healthz():\n    return {'status': 'ok'}\n")


def test_4_a_code_patch_on_a_big_repo_reads_the_file_it_rewrites_instead_of_crashing(client, wait_for,
                                                                                      tmp_path: Path, monkeypatch):
    hub = hub_of(client)
    root = flask_monorepo(tmp_path / "shop")
    assert sorted(f.as_posix() for f in list_files(root, 100_000)).index(ROUTES) > 2_000  # beyond the old list
    submission = ("submit_patch", {"title": "Add /healthz", "rationale": "A health route for the hub.",
                                   "health_path": "/healthz", "changes": [{"path": ROUTES, "content": HEALTHY}]})
    steps: list[str] = []

    def script(call: dict[str, Any]) -> Any:
        if submit_tool(call) != "submit_patch":
            return done()
        step = sum(1 for m in call["messages"] if m.get("role") == "assistant")
        if step == 0:  # a blind rewrite of a file it never saw, as the old one-shot patcher did
            steps.append("blind submit")
            return tool_turn(submission)
        if step == 1:
            assert "You have not read zz_web/routes.py in full" in tool_results(call)[0]["content"]
            steps.append("read")
            return tool_turn(("read_file", {"path": ROUTES, "start_line": 0, "end_line": 0}))
        if step == 2:
            assert "return 'shop'" in tool_results(call)[0]["content"]
            steps.append("submit")
            return tool_turn(submission)
        return done()

    fake = use_claude(hub, monkeypatch, ScriptedClaude(script, json_result=ENRICHED))
    tool_id = imported(client, wait_for, root)
    assert hub.get_tool(tool_id).manifest.launch.port == 5000
    patch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "health_endpoint"), None))
    assert steps == ["blind submit", "read", "submit"]
    assert tool_errors(fake) == ["Error: You have not read zz_web/routes.py in full: read it with read_file (all "
                                 "lines), then submit again."]
    assert [(c.path, c.content) for c in patch.changes] == [(ROUTES, HEALTHY)]
    assert patch.manifest_update == {"health": {"url": "http://localhost:5000/healthz"}}
    assert patch.generated_by and patch.target == "repo" and patch.approval_id
    assert not any(p.strategy == "health_probe" for p in hub.patches(tool_id))  # no fallback was needed
    assert "without having seen it" not in json.dumps(hub.store.tail("activity", 2_000))
    no_agent_errors(hub)

    applied = decide(client, wait_for, patch.id)
    assert applied.status == "applied", applied.error
    assert (Path(applied.location) / ROUTES).read_text() == HEALTHY  # beside the checkout, never in it
    assert "healthz" not in (root / ROUTES).read_text()
    # review R6: the change is not in the tool's folder yet - no pass until a person merges it (it used to pass here)
    waiting = wait_for(lambda: (c := checks(client, tool_id)["health"])["detail"].startswith(f"'{applied.title}'") and c)
    assert waiting["status"] == "warn" and waiting["fix"] is None and "not merged yet" in waiting["detail"]
    assert propose(client, tool_id)["patches"] == []
    (root / ROUTES).write_text(HEALTHY)  # a person merges it, then Re-analyses
    reanalyse(client, wait_for, tool_id)
    wait_for(lambda: checks(client, tool_id)["health"]["status"] == "pass")
    assert propose(client, tool_id)["patches"] == []
    no_agent_errors(hub)


# --------------------------------------------------------------------------------------
# 5. Rejected and failing patches
# --------------------------------------------------------------------------------------


def test_5a_a_rejected_patch_is_not_proposed_again_until_an_administrator_asks(client, sign_in, wait_for,
                                                                                tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_release(tmp_path / "keycloak"))
    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    operator = sign_in("operator")
    refused = operator.post(f"/api/approvals/{patch.approval_id}", json={"approve": True})
    assert refused.status_code == 403  # it changes the environment the hub starts the tool with: an admin's call
    assert decide(operator, wait_for, patch.id, approve=False).status == "rejected"  # operators may still reject

    for _ in range(3):  # Propose, as often as anyone presses it, and a Re-analyse in between
        result = propose(client, tool_id)
        assert result["patches"] == [] and result["pending"] == []
        [health] = [s for s in result["skipped"] if s["fix"] == "health_config"]
        assert health["reason"].startswith("You rejected 'Switch on Keycloak's own health check'")
    reanalyse(client, wait_for, tool_id)
    assert strategies_of(hub, tool_id) == ["health_config"]  # still the one rejected patch
    found = wait_for(lambda: (c := checks(client, tool_id)["health"]) and "You rejected" in c["detail"] and c)
    assert found["status"] == "warn" and found["fix"] == "health_config"
    adapters = card(client, tool_id)
    assert adapters["state"] == "needs_input" and adapters["action"] == "edit_manifest"
    assert len([t for t in not_proposed_log(hub, "keycloak") if "You rejected" in t]) == 1  # logged once

    assert operator.post(f"/api/tools/{tool_id}/patches", json={"again": True}).status_code == 403
    again = propose(client, tool_id, again=True)  # an administrator asks again
    [new_id] = again["patches"]
    assert hub.get_patch(new_id).strategy == "health_config" and decide(client, wait_for, new_id).status == "applied"
    wait_for(lambda: checks(client, tool_id)["health"]["status"] == "pass")
    no_agent_errors(hub, "supervisor", "operator", "patcher")


def test_5b_a_patch_that_fails_twice_is_not_tried_a_third_time_and_the_error_shows(client, wait_for, tmp_path: Path,
                                                                                  plain_repo: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, plain_repo)
    adapters = hub.settings.workspace / "adapters" / tool_id
    adapters.parent.mkdir(parents=True, exist_ok=True)
    adapters.write_text("not a folder")  # every adapter write fails, the same way each time

    def probe() -> Patch:
        return next((p for p in hub.patches(tool_id) if p.strategy == "health_probe" and p.status == "proposed"),
                    None)

    first = wait_for(probe)
    assert decide(client, wait_for, first.id).status == "failed"
    result = propose(client, tool_id)
    second = probe()
    assert second is not None and second.id in result["patches"]  # one failure: tried once more
    failed = decide(client, wait_for, second.id)
    assert failed.status == "failed" and failed.error

    for _ in range(2):
        result = propose(client, tool_id)
        assert not any(hub.get_patch(i).strategy == "health_probe" for i in result["patches"])
        [health] = [s for s in result["skipped"] if s["fix"] in ("health_endpoint", "health_probe")]
        assert health["reason"].startswith("'Add a health probe adapter' failed 2 times; last error: ")
        assert failed.error[:60] in health["reason"] and "Integration > Health > Edit" in health["reason"]
    assert [p.status for p in hub.patches(tool_id) if p.strategy == "health_probe"] == ["failed", "failed"]
    detail = wait_for(lambda: (c := checks(client, tool_id)["health"]) and "failed 2 times" in c["detail"] and c)
    assert failed.error[:60] in detail["detail"]


# --------------------------------------------------------------------------------------
# 6. Upgrade: tools stored by an earlier Atrium
# --------------------------------------------------------------------------------------


def started(settings) -> TestClient:
    """The app on an existing data folder, signed in as the administrator (the hub starts: the migration runs)."""
    client = TestClient(create_app(settings), headers={"X-Hub-Request": "1"})
    client.__enter__()
    if not client.app.state.hub.auth.find_user("admin"):
        client.app.state.hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
    assert client.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
    return client


def moved(hub) -> int:
    return sum(1 for e in hub.store.tail("activity", 5_000) if "Moved the hub-side settings" in e.get("text", ""))


def test_6_tools_stored_the_old_way_are_migrated_at_start_and_close_with_one_approval(tmp_path: Path, wait_for,
                                                                                      node_repo: Path):
    from hub.core import Hub

    kc_root = keycloak_checkout(tmp_path / "keycloak")
    settings = make_settings(tmp_path)
    old = Hub(settings)
    # Keycloak as the old Atrium left it: "native" carried from an applied add_manifest whose draft (launch "TODO")
    # waits unmerged on its branch, and an event adapter that polled https://example.com
    old.save_tool(Tool(id="keycloak", name="Keycloak", source_type="github", source="keycloak/keycloak",
                       path=str(kc_root), status="needs_patch", created_at=1.0,
                       manifest=Manifest(id="keycloak", name="Keycloak", kind="oss", stack=["java"], native=True,
                                         launch={"command": "TODO: command that starts the tool", "port": 8080},
                                         provides=["auth.oidc", "auth.saml", "identity.source"],
                                         auth={"sso": "oidc"}, events={"emits": ["keycloak.changed"]})))
    old.save_patch(Patch(id="p_kc_adopt", tool_id="keycloak", title="Adopt a hub manifest", rationale="",
                         strategy="add_manifest", target="repo", status="applied", branch="hub/add-manifest-kc0001",
                         changes=[FileChange(path="hub.manifest.yaml",
                                             content="launch:\n  command: 'TODO: command that starts the tool'\n")],
                         manifest_update={"native": True}, created_at=2.0))
    old.save_patch(Patch(id="p_kc_events", tool_id="keycloak", title="Add an event adapter", rationale="",
                         strategy="event_adapter", target="adapter", status="applied",
                         changes=[FileChange(path="events/adapter.py",
                                             content='BASE = "https://example.com"\n')],
                         manifest_update={"events": {"emits": ["keycloak.changed"]}}, created_at=3.0))
    old.save_patch(Patch(id="p_kc_code", tool_id="keycloak", title="Add a health endpoint", rationale="",
                         strategy="health_endpoint", target="repo", status="failed", created_at=4.0,
                         error="The AI model tried to rewrite testsuite/.../keycloak.conf without having seen it"))
    # an unknown app adopted the same way: honest now - adopted, not native, until the draft is merged
    m, _ = analyze_repo(node_repo, "crm", "CRM")
    m.native = True
    old.save_tool(Tool(id="crm", name="CRM", source_type="local", source=str(node_repo), path=str(node_repo),
                       status="ready", created_at=1.0, manifest=m))
    old.save_patch(Patch(id="p_crm_adopt", tool_id="crm", title="Adopt a hub manifest", rationale="",
                         strategy="add_manifest", target="repo", status="applied", branch="hub/add-manifest-crm001",
                         changes=[FileChange(path="hub.manifest.yaml", content="name: CRM\n")],
                         manifest_update={"native": True}, created_at=2.0))
    old.store.close()

    client = started(settings)
    try:
        hub = hub_of(client)
        kc = wait_for(lambda: (t := hub.get_tool("keycloak")).report and t)
        assert not kc.manifest.native and kc.manifest.adopted == "hub/add-manifest-kc0001"
        assert kc.manifest.known.profile == "keycloak" and "keycloak.changed" not in kc.manifest.events.emits
        found = checks(client, "keycloak")
        assert found["manifest"]["status"] == "pass" and "Ships its own" not in found["manifest"]["detail"]
        assert "waits unmerged at hub/add-manifest-kc0001" in found["manifest"]["detail"]
        assert (found["launch"]["status"], found["launch"]["fix"]) == ("warn", "launch_command")  # TODO is no command
        assert (found["health"]["status"], found["health"]["fix"]) == ("warn", "launch_command")
        assert found["api"]["status"] == "pass" and found["events"]["fix"] is None

        result = propose(client, "keycloak")  # one press, one approval, no re-analysis
        assert [hub.get_patch(i).strategy for i in result["patches"]] == ["launch_command"]
        assert not [s for s in result["skipped"] if s["fix"] in ("launch_command", "health_endpoint")]
        applied = decide(client, wait_for, result["patches"][0])
        assert applied.status == "applied", applied.error
        closed = wait_for(lambda: (c := checks(client, "keycloak"))["launch"]["status"] == "pass" and c)
        assert closed["health"]["status"] == "pass" and KC_IMAGE in closed["launch"]["detail"]
        kc = reanalyse(client, wait_for, "keycloak")  # and a Re-analyse gives the same
        assert not kc.manifest.native and kc.manifest.adopted == "hub/add-manifest-kc0001"
        assert checks(client, "keycloak")["launch"]["status"] == "pass"
        assert propose(client, "keycloak") == {"patches": [], "pending": [], "skipped": []}

        crm = hub.get_tool("crm")
        assert not crm.manifest.native and crm.manifest.adopted == "hub/add-manifest-crm001"
        manifest = checks(client, "crm")["manifest"]
        assert manifest["status"] == "warn" and manifest["fix"] is None
        assert "not merged yet" in manifest["detail"] and "hub/add-manifest-crm001" in manifest["detail"]
        assert not any(p.strategy == "add_manifest" and p.status == "proposed" for p in hub.patches("crm"))
        (node_repo / "hub.manifest.yaml").write_text("name: CRM\ndescription: A tiny CRM.\n")  # merged by a person
        crm = reanalyse(client, wait_for, "crm")
        assert crm.manifest.native
        assert checks(client, "crm")["manifest"]["detail"] == "Ships its own hub manifest."
        assert hub.prefs.get("migrations.tool_overrides") == 1 and moved(hub) == 1
    finally:
        client.__exit__(None, None, None)

    again = started(settings)  # a second start migrates nothing again, and keeps what was decided
    try:
        hub = hub_of(again)
        assert moved(hub) == 1
        assert hub.get_tool("keycloak").manifest.launch.command == KC_COMMAND.format(id="keycloak")
        assert hub.get_tool("crm").manifest.native
    finally:
        again.__exit__(None, None, None)


# --------------------------------------------------------------------------------------
# 7. Starting a tool without a launch command
# --------------------------------------------------------------------------------------

NEEDS_LAUNCH = ("Launch needs a launch command: approve the launch_command patch or set it in Integration > Launch > "
                "Edit.")


def test_7_starting_without_a_launch_command_is_a_plain_answer_never_an_agent_error(client, wait_for, tmp_path: Path,
                                                                                   monkeypatch):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_checkout(tmp_path / "keycloak"))
    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    processes = len(hub.approvals.list("pending"))

    answer = client.post(f"/api/tools/{tool_id}/start").json()  # the Start button
    assert answer == {"status": "needs_input", "reason": f"{NEEDS_LAUNCH} One is waiting on the Approvals page."}
    reply = client.post("/api/chat", json={"text": f"start {tool_id}"}).json()["reply"]  # the rules chat
    assert reply == f"Start keycloak: needs_input - {NEEDS_LAUNCH} One is waiting on the Approvals page."
    assert len(hub.approvals.list("pending")) == processes  # nothing to approve: no process approval was made

    # the Hub Supervisor with an AI model asks the Operator to start it - the call that used to crash
    def script(call: dict[str, Any]) -> Any:
        if not tool_results(call):
            return tool_turn(("start_tool", {"tool_id": tool_id}))
        assert "needs_input" in tool_results(call)[0]["content"] and not tool_results(call)[0].get("is_error")
        return message(content=[block("text", text="Keycloak needs a launch command first; one waits for approval.")])

    use_claude(hub, monkeypatch, ScriptedClaude(script))
    reply = client.post("/api/chat", json={"text": "Please start Keycloak."}).json()["reply"]
    assert "needs a launch command" in reply
    no_agent_errors(hub, "supervisor", "operator", f"tool:{tool_id}", "patcher")
    assert not hub.processes.status(tool_id)["running"]

    # once the launch_command patch is approved, Start runs the recipe with the generated password in its environment
    assert decide(client, wait_for, patch.id).status == "applied"
    seen: dict[str, Any] = {}

    async def fake_start(tool_id_, command, cwd=None, env=None):
        seen.update(command=command, env=env)
        return {"status": "started", "pid": 4242}

    hub.processes.start = fake_start
    assert client.post(f"/api/tools/{tool_id}/start").json()["status"] == "started"
    password = launch_secrets._read(hub.settings.workspace, tool_id)["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    assert seen["command"] == KC_COMMAND.format(id=tool_id) and seen["env"]["KC_BOOTSTRAP_ADMIN_PASSWORD"] == password
    assert password not in everything_shown(client, tool_id)


# --------------------------------------------------------------------------------------
# 8. The administrators' manifest editor
# --------------------------------------------------------------------------------------

DB_PASSWORD = "Ledger-db-Pa55word-for-nobody-else"


def test_8_the_editor_closes_gaps_for_good_and_keeps_its_secrets(client, sign_in, wait_for, tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, ledger_app(tmp_path / "ledger", bulk=200))
    assert propose(client, tool_id)["patches"] == []  # the import's pass proposed what it could
    viewer, operator = sign_in("viewer"), sign_in("operator")
    body = {"launch": {"command": "java -jar target/ledger.jar", "port": 8080, "env": {"LEDGER_DB_PASSWORD": DB_PASSWORD}},
            "health": {"url": "http://localhost:8080/actuator/health"},
            "api": {"type": "rest", "base_url": "http://localhost:8080/api", "spec": "docs/openapi.yaml"}}
    for who in (viewer, operator):
        assert who.patch(f"/api/tools/{tool_id}/manifest", json=body).status_code == 403
    assert hub.get_tool(tool_id).manifest_overrides == {}

    def edit() -> None:
        response = client.patch(f"/api/tools/{tool_id}/manifest", json=body)
        assert response.status_code == 200, response.text

    events = sse_events(hub, edit)
    found = checks(client, tool_id)
    assert found["launch"]["status"] == "pass" and found["health"]["status"] == "pass"
    assert found["api"]["status"] == "pass"
    # the value lives only in the private 0600 file; names are shown, values never
    secrets_file = hub.settings.workspace / "adapters" / tool_id / launch_secrets.ENV_FILE
    assert stat.S_IMODE(secrets_file.stat().st_mode) == 0o600 and DB_PASSWORD in secrets_file.read_text()
    assert [e for e in events if e["type"] == "tool"] and DB_PASSWORD not in json.dumps(events, default=str)
    for who in (client, operator, viewer):
        listed = next(t for t in who.get("/api/tools").json() if t["id"] == tool_id)
        assert listed["manifest"]["launch"]["env_keys"] == ["LEDGER_DB_PASSWORD"]
        assert DB_PASSWORD not in json.dumps(listed) and DB_PASSWORD not in everything_shown(who, tool_id)
    assert DB_PASSWORD not in json.dumps(hub.get_tool(tool_id).model_dump(mode="json"))

    # every hand-set value survives a Re-analyse, and nothing is proposed against it
    events = sse_events(hub, lambda: reanalyse(client, wait_for, tool_id))
    tool = hub.get_tool(tool_id)
    assert tool.manifest.launch.command == "java -jar target/ledger.jar" and tool.manifest.api.spec == "docs/openapi.yaml"
    assert tool.manifest.health.url == "http://localhost:8080/actuator/health"
    after = checks(client, tool_id)
    assert all(after[c]["status"] == "pass" for c in ("launch", "health", "api"))
    assert DB_PASSWORD not in json.dumps(events, default=str)
    result = propose(client, tool_id)
    assert not any(s["fix"] in ("launch_command", "health_endpoint", "health_probe") for s in result["skipped"])
    assert not any(hub.get_patch(i).strategy in ("launch_command", "health_endpoint", "health_probe")
                   for i in result["patches"])
    no_agent_errors(hub)


def test_8b_a_launch_patch_that_waited_while_the_admin_set_it_by_hand_is_not_applied(client, wait_for,
                                                                                    tmp_path: Path):
    hub = hub_of(client)
    tool_id = imported(client, wait_for, keycloak_checkout(tmp_path / "keycloak"))
    patch = wait_for(lambda: next(iter(hub.patches(tool_id)), None))
    own = "docker run --rm -p 8080:8080 -p 9000:9000 -e KC_HEALTH_ENABLED=true " + KC_IMAGE + " start-dev"
    response = client.patch(f"/api/tools/{tool_id}/manifest", json={"launch": {"command": own}})
    assert response.status_code == 200, response.text
    assert {c["id"]: c for c in response.json()["report"]["checks"]}["launch"]["status"] == "pass"

    late = decide(client, wait_for, patch.id)  # approved after all: the administrator's command stays
    assert late.status == "rejected" and late.error.startswith(gapfix.NOT_APPLIED)
    assert hub.get_tool(tool_id).manifest.launch.command == own
    assert hub.approvals.get(patch.approval_id).status == "failed"
    assert not (hub.settings.workspace / "adapters" / tool_id / launch_secrets.ENV_FILE).exists()
    no_agent_errors(hub)

    # put back to what the analysis finds: the gap is open again and the recipe is proposed again
    response = client.patch(f"/api/tools/{tool_id}/manifest", json={"launch": {"command": None}})
    assert response.status_code == 200
    wait_for(lambda: checks(client, tool_id)["launch"]["status"] == "warn")
    result = propose(client, tool_id)  # (the re-analysis the reset started may have proposed it already)
    [waiting] = [p for p in hub.patches(tool_id) if p.status == "proposed"]
    assert waiting.strategy == "launch_command" and waiting.id in result["patches"] + result["pending"]


# --------------------------------------------------------------------------------------
# 9. Programs named after a product are not that product (no false pass from a name)
# --------------------------------------------------------------------------------------


def test_9_a_project_named_after_a_product_gets_no_facts_or_passes_of_that_product(client, wait_for, tmp_path: Path):
    hub = hub_of(client)
    lab = tmp_path / "keycloak-lab"  # the folder the projects sit in says nothing about them either
    theme = lab / "keycloak-theme"
    write(theme, "pom.xml", "<project>\n  <groupId>com.example</groupId>\n  <artifactId>keycloak-theme</artifactId>\n"
                            "  <version>1.2.0</version>\n</project>\n")
    write(theme, "src/main/resources/theme/acme/login/theme.properties", "parent=keycloak\n")
    write(theme, "version.txt", "Version 1.2\n")
    exporter = lab / "prometheus-node-exporter"
    write(exporter, "go.mod", "module github.com/prometheus/node_exporter\n\ngo 1.22\n")
    write(exporter, "main.go", 'package main\nfunc main() { listen(":9100") }\n')
    ledger = ledger_app(lab / "ledger", bulk=20)

    theme_id = imported(client, wait_for, theme)
    m = hub.get_tool(theme_id).manifest
    assert m.known is None and m.api.type == "none" and m.launch.command is None
    found = checks(client, theme_id)
    assert found["manifest"]["fix"] == "add_manifest" and "Keycloak" not in found["manifest"]["detail"]
    assert found["api"]["status"] == "warn" and "connector" not in found["api"]["detail"]  # no false API pass
    assert found["launch"]["fix"] == "launch_command" and KC_IMAGE not in found["launch"]["detail"]
    launch = next(s for s in propose(client, theme_id)["skipped"] if s["fix"] == "launch_command")
    assert launch["state"] == "needs_input" and EDITOR in launch["reason"]  # never a Keycloak container recipe

    exporter_id = imported(client, wait_for, exporter)
    m = hub.get_tool(exporter_id).manifest
    assert m.known is None and m.launch.port != 9090 and not (m.health.url or "").endswith("/-/ready")

    ledger_id = imported(client, wait_for, ledger)
    assert "Keycloak" not in checks(client, ledger_id)["api"]["detail"]  # nor from the folder it sits in
    no_agent_errors(hub)


# --------------------------------------------------------------------------------------
# 10. Review regressions: no repeated proposals or paid AI calls, no false pass, no hub-wide masking
# --------------------------------------------------------------------------------------


def count_sso_plans(hub, monkeypatch) -> list[str]:
    """The tools the Patch Agent finished (re)planning single sign-on for (sso.plan: a provider's sweep)."""
    patcher = hub.agents.get("patcher")
    original = patcher.on_sso_plan
    finished: list[str] = []

    async def counted(body, msg):
        try:
            return await original(body, msg)
        finally:
            finished.append(str(body.get("tool_id")))

    monkeypatch.setattr(patcher, "on_sso_plan", counted)
    return finished


def never_submits() -> ScriptedClaude:
    """A model that answers every conversation with text and never calls a tool: a code patch or launch proposal then
    fails ("The AI model proposed no patch"); structured calls get an empty object."""
    def script(call):
        if "schema" in call:
            return {}
        return message(content=[block("text", text="I cannot work this out.")])
    return ScriptedClaude(script)


def test_10a_a_rejected_sso_patch_is_not_proposed_again_when_its_provider_is_reanalysed(client, wait_for, tmp_path: Path,
                                                                                        plain_repo: Path, monkeypatch):
    """Re-analysing the identity provider re-plans SSO for every other tool (a sweep): it follows the same history
    rules as a propose pass - only a person's provider choice (or an administrator's ask again) plans regardless."""
    hub = hub_of(client)
    kc = imported(client, wait_for, keycloak_release(tmp_path / "keycloak"))
    tool_id = imported(client, wait_for, plain_repo)
    sso = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy.startswith("sso_")
                                 and p.status == "proposed"), None))
    decide(client, wait_for, sso.id, approve=False)
    before = [(p.id, p.status) for p in hub.patches(tool_id) if p.strategy.startswith("sso_")]
    planned = count_sso_plans(hub, monkeypatch)
    reanalyse(client, wait_for, kc)
    wait_for(lambda: tool_id in planned)
    assert [(p.id, p.status) for p in hub.patches(tool_id) if p.strategy.startswith("sso_")] == before
    skipped = next(s for s in propose(client, tool_id)["skipped"] if s["fix"].startswith("sso_"))
    assert skipped["reason"].startswith(f"You rejected '{sso.title}'")
    # a person choosing the provider is an explicit request: it is proposed again
    chosen = client.post(f"/api/tools/{tool_id}/sso", json={"provider": kc}).json()
    assert len(chosen["patches"]) == 1 and hub.get_patch(chosen["patches"][0]).status == "proposed"
    no_agent_errors(hub)


def test_10b_a_failed_ai_sso_code_patch_is_not_paid_for_again(client, wait_for, tmp_path: Path, monkeypatch):
    """sso_code is written by the AI model; when it fails and no SSO proxy fits (no port), the reason names the model's
    error and the proxy's, and neither a propose pass nor the provider's re-analysis holds the conversation again."""
    hub = hub_of(client)
    kc = imported(client, wait_for, keycloak_release(tmp_path / "keycloak"))
    fake = use_claude(hub, monkeypatch, never_submits())
    app = tmp_path / "billing"
    write(app, "pom.xml", "<project><groupId>x</groupId><artifactId>billing</artifactId><version>1.0</version></project>")
    write(app, "src/main/java/x/Main.java", "class Main { public static void main(String[] a) {} }\n")
    write(app, "README.md", "# Billing\n")
    tool_id = imported(client, wait_for, app)
    assert checks(client, tool_id)["sso"]["fix"] == "sso_code"

    def conversations() -> int:  # the paid code-patch conversations started (their first turn)
        return sum(1 for c in fake.calls if submit_tool(c) == "submit_patch" and not c.get("messages")[1:])

    first = conversations()
    assert first == 1  # the import's propose pass tried once
    result = propose(client, tool_id)
    sso = next(s for s in result["skipped"] if s["fix"] == "sso_code")
    assert sso["reason"].startswith("The AI model could not add OpenID Connect sign-in to billing")
    assert "port" in sso["reason"] and "ask again" in sso["reason"]
    planned = count_sso_plans(hub, monkeypatch)
    reanalyse(client, wait_for, kc)
    wait_for(lambda: tool_id in planned)
    propose(client, tool_id)
    assert conversations() == first
    propose(client, tool_id, again=True)  # an administrator asks again: one more attempt
    assert conversations() == first + 1
    no_agent_errors(hub, "patcher", "supervisor")


def test_10c_a_code_patch_on_an_unmerged_branch_is_no_pass_until_it_is_merged(client, wait_for, tmp_path: Path,
                                                                             plain_repo: Path, monkeypatch):
    """Review R6: an applied health_endpoint code patch (committed on a branch in a worktree) set health.url at once -
    Health PASS while the tool's own checkout did not have the change. What a code patch sets waits until a
    Re-analyse finds the change in the folder; meanwhile the check says to merge it, with no fix."""
    import subprocess

    from llm_fakes import submits

    hub = hub_of(client)
    git = ["git", "-C", str(plain_repo), "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(plain_repo)], check=True)
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    use_claude(hub, monkeypatch, submits({
        "title": "Add /healthz", "rationale": "A health endpoint.", "health_path": "/healthz",
        "changes": [{"path": "health.py", "content": "def healthz():\n    return 'ok'\n"}]}, json_result={}))
    tool_id = imported(client, wait_for, plain_repo)
    patch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "health_endpoint"), None))
    applied = decide(client, wait_for, patch.id)
    assert applied.status == "applied" and applied.branch and applied.merged is False
    assert not (plain_repo / "health.py").exists()
    health = wait_for(lambda: (c := checks(client, tool_id)["health"])["detail"].startswith(f"'{applied.title}'") and c)
    assert health["status"] == "warn" and health["fix"] is None
    assert f"applied on branch {applied.branch}, not merged yet: merge it into {plain_repo}" in health["detail"]
    assert hub.get_tool(tool_id).manifest.health.url is None
    assert not [s for s in propose(client, tool_id)["skipped"] if s["fix"] in ("health_endpoint", "health_probe")]
    assert [p.id for p in hub.patches(tool_id) if p.strategy in ("health_endpoint", "health_probe")] == [patch.id]
    reanalyse(client, wait_for, tool_id)  # nothing merged yet: still waiting
    assert checks(client, tool_id)["health"]["status"] == "warn"

    subprocess.run([*git, "merge", "-q", "--no-edit", applied.branch], check=True)  # a person merges it
    tool = reanalyse(client, wait_for, tool_id)
    assert tool.manifest.health.url == "http://localhost:5000/healthz" and hub.get_patch(patch.id).merged is True
    assert checks(client, tool_id)["health"]["status"] == "pass"
    no_agent_errors(hub)


def test_10d_an_api_adapter_skeleton_leaves_the_api_open_with_the_next_step(client, wait_for, tmp_path: Path):
    """Review R5 end to end: approving the skeleton no longer turns Programmable API into a pass."""
    hub = hub_of(client)
    root = tmp_path / "vendorapp"
    root.mkdir()
    (root / "vendorapp.exe").write_bytes(b"MZ" + b"\0" * 64)
    (root / "core.dll").write_bytes(b"MZ" + b"\0" * 64)
    tool_id = imported(client, wait_for, root)
    patch = wait_for(lambda: next((p for p in hub.patches(tool_id) if p.strategy == "api_adapter"), None))
    applied = decide(client, wait_for, patch.id)
    assert "TODO" in (Path(applied.location) / "api" / "adapter.py").read_text()
    api = wait_for(lambda: (c := checks(client, tool_id)["api"])["fix"] is None and c)
    assert api["status"] == "warn" and "fill in its TODOs and run it" in api["detail"]
    assert "api_adapter" not in [s["fix"] for s in propose(client, tool_id)["skipped"]]
    assert strategies_of(hub, tool_id).count("api_adapter") == 1


def test_10e_a_product_on_a_taken_port_is_moved_through_its_own_variable(client, wait_for, tmp_path: Path):
    """Review R7 end to end: Keycloak (release) and a Spring app both on 8080 - Keycloak is moved with KC_HTTP_PORT,
    which it reads, not PORT, which it ignores."""
    hub = hub_of(client)
    ledger_app(tmp_path / "ledger", bulk=5)
    write(tmp_path / "ledger", "hub.manifest.yaml", "name: Ledger\nlaunch:\n  command: ./mvnw spring-boot:run\n"
                                                     "  port: 8080\n")
    imported(client, wait_for, tmp_path / "ledger")
    kc = imported(client, wait_for, keycloak_release(tmp_path / "keycloak"))
    patch = wait_for(lambda: next((p for p in hub.patches(kc) if p.strategy == "reassign_port"), None))
    assert patch.manifest_update["launch"] == {"port": 8081, "env": {"KC_HTTP_PORT": "8081"}}
    decide(client, wait_for, patch.id)
    wait_for(lambda: checks(client, kc)["ports"]["status"] == "pass")
    launch = hub.get_tool(kc).manifest.launch
    assert launch.port == 8081 and launch.env["KC_HTTP_PORT"] == "8081" and launch.command == "bin/kc.sh start-dev"
