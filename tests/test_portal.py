"""The portal address: this machine, or a server that already runs the app."""

from hub.execution.runtime import runtime_problem
from hub.integration.portal import apply_portal_url, normalize_portal_url
from hub.models import Manifest, Tool


def _tool() -> Tool:
    return Tool(
        id="ciso", name="CISO Assistant", source_type="github", source="https://example.com/ciso.git", status="ready",
        manifest=Manifest(
            id="ciso", name="CISO Assistant",
            ui={"url": "http://localhost:6333"},
            health={"url": "http://localhost:6333/api/health"},
            api={"type": "rest", "base_url": "http://127.0.0.1:6333"},
            launch={"command": "docker compose up", "port": 6333},
        ),
    )


def test_remote_address_moves_local_health_and_api():
    tool = _tool()
    apply_portal_url(tool.manifest, "http://ciso.lab.example:8443/")
    assert tool.manifest.ui.url == "http://ciso.lab.example:8443"
    assert tool.manifest.health.url == "http://ciso.lab.example:8443/api/health"
    assert tool.manifest.api.base_url == "http://ciso.lab.example:8443"


def test_a_different_local_port_is_left_alone():
    tool = _tool()
    tool.manifest.health.url = "tcp://127.0.0.1:5432"
    apply_portal_url(tool.manifest, "https://ciso.example.com")
    assert tool.manifest.ui.url == "https://ciso.example.com"
    assert tool.manifest.health.url == "tcp://127.0.0.1:5432"
    assert tool.manifest.api.base_url == "https://ciso.example.com"


def test_moving_the_portal_again_brings_health_and_api_along():
    tool = _tool()
    apply_portal_url(tool.manifest, "https://ciso.example.com")
    apply_portal_url(tool.manifest, "http://10.0.0.8:6333")
    assert tool.manifest.health.url == "http://10.0.0.8:6333/api/health"
    assert tool.manifest.api.base_url == "http://10.0.0.8:6333"
    apply_portal_url(tool.manifest, "http://localhost:6333")
    assert tool.manifest.ui.url == "http://localhost:6333"
    assert tool.manifest.health.url == "http://localhost:6333/api/health"
    assert tool.manifest.api.base_url == "http://localhost:6333"


def test_a_separate_remote_api_stays_when_the_portal_moves_again():
    tool = _tool()
    tool.manifest.api.base_url = "https://api.vendor.example"
    apply_portal_url(tool.manifest, "https://ciso.example.com")
    apply_portal_url(tool.manifest, "http://10.0.0.8:6333")
    assert tool.manifest.api.base_url == "https://api.vendor.example"
    assert tool.manifest.health.url == "http://10.0.0.8:6333/api/health"


def test_an_address_that_is_already_remote_stays():
    tool = _tool()
    tool.manifest.api.base_url = "https://api.vendor.example"
    apply_portal_url(tool.manifest, "http://10.0.0.8:6333")
    assert tool.manifest.api.base_url == "https://api.vendor.example"
    assert tool.manifest.health.url == "http://10.0.0.8:6333/api/health"


def test_portal_address_rejects_credentials_and_other_schemes():
    for bad in ("http://user:secret@ciso.example", "javascript:alert(1)", "ftp://files.example", "http://", ""):
        try:
            normalize_portal_url(bad)
        except ValueError:
            continue
        raise AssertionError(bad)


def test_missing_docker_is_reported_before_a_start(monkeypatch):
    monkeypatch.setattr("hub.execution.runtime.shutil.which", lambda name: None if name == "docker" else "/usr/bin/" + name)
    message = runtime_problem("docker compose up")
    assert message and "not installed" in message
    assert runtime_problem("npm start") is None
    monkeypatch.setattr("hub.execution.runtime.shutil.which", lambda name: "/usr/bin/" + name)
    assert runtime_problem("docker compose up") is None


def test_start_refuses_docker_when_it_is_not_installed(client, monkeypatch):
    monkeypatch.setattr("hub.execution.runtime.shutil.which", lambda name: None if name == "docker" else "/usr/bin/" + name)
    client.app.state.hub.save_tool(_tool())
    result = client.post("/api/tools/ciso/start").json()
    assert result["status"] == "failed"
    assert "not installed" in result["reason"]
    assert client.get("/api/tools/ciso").json()["launch_error"]
    assert client.get("/api/tools/ciso").json()["process"]["running"] is False


def test_api_points_a_tool_at_a_remote_server(client, sign_in):
    hub = client.app.state.hub
    hub.save_tool(_tool())
    response = client.patch("/api/tools/ciso/portal", json={"url": "http://10.1.2.3:6333"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["manifest"]["ui"]["url"] == "http://10.1.2.3:6333"
    assert body["manifest"]["health"]["url"] == "http://10.1.2.3:6333/api/health"
    assert hub.get_tool("ciso").manifest.ui.url == "http://10.1.2.3:6333"

    refused = client.patch("/api/tools/ciso/portal", json={"url": "http://admin:pw@10.1.2.3"})
    assert refused.status_code == 400

    viewer = sign_in("viewer")
    assert viewer.patch("/api/tools/ciso/portal", json={"url": "http://10.9.9.9"}).status_code == 403


def test_a_remote_portal_is_not_blamed_on_this_machine(client, monkeypatch):
    monkeypatch.setattr("hub.execution.runtime.shutil.which", lambda name: None if name == "docker" else "/usr/bin/" + name)
    client.app.state.hub.save_tool(_tool())
    local = client.get("/api/tools/ciso").json()
    assert "not installed" in local["launch_error"]

    moved = client.patch("/api/tools/ciso/portal", json={"url": "http://10.1.2.3:6333"})
    assert moved.status_code == 200
    assert moved.json()["launch_error"] is None
    assert client.get("/api/tools/ciso").json()["launch_error"] is None


def test_a_process_that_exits_keeps_its_error(client, wait_for):
    tool = _tool()
    tool.manifest.launch.command = "sh -c 'echo broke; exit 7'"
    client.app.state.hub.save_tool(tool)
    started = client.post("/api/tools/ciso/start").json()
    assert started.get("status") != "failed", started
    body = wait_for(lambda: _exited(client))
    assert body["process"]["exit_code"] == 7
    assert "broke" in body["launch_error"]
    assert body["process"]["running"] is False


def _exited(client):
    body = client.get("/api/tools/ciso").json()
    return body if body["process"].get("exit_code") == 7 else None
