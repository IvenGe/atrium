from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Callable

import pytest
from fastapi.testclient import TestClient

from hub.app import create_app
from hub.config import Settings


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Tests marked ``slow`` (performance budgets over large data sets) run only with HUB_SLOW_TESTS=1."""
    if os.environ.get("HUB_SLOW_TESTS") == "1":
        return
    skip = pytest.mark.skip(reason="slow test: set HUB_SLOW_TESTS=1 to run it")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(autouse=True)
def no_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never call a real model - and never self-patch (or run the tests of) this checkout: self-patch tests
    point hub.self_patch at a temporary repository."""
    monkeypatch.setenv("HUB_LLM", "off")
    monkeypatch.setenv("HUB_SELF_PATCH", "off")
    monkeypatch.setenv("HUB_BRIDGE_TESTS", "off")  # bridge patches never find a real container runtime by themselves
    # a developer's own credentials are never used and never change a result (tests/llm_fakes.py plugs in fakes)
    for name in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "OPENAI_API_KEY", "OPENAI_BASE_URL"):
        monkeypatch.delenv(name, raising=False)


ADMIN_PASSWORD = "correct horse battery staple"
PASSWORD = "plenty of entropy 42"


def make_settings(tmp_path: Path, **overrides) -> Settings:
    return Settings(data_dir=tmp_path / "data", allowed_hosts=["testserver"], start_background_tasks=False, **overrides)


@pytest.fixture
def client(tmp_path: Path):
    """A browser signed in as the administrator "admin"."""
    app = create_app(make_settings(tmp_path))
    with TestClient(app, headers={"X-Hub-Request": "1"}) as c:
        c.app.state.hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
        response = c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD})
        assert response.status_code == 200, response.text
        yield c


def new_browser(running: TestClient, /, **kwargs) -> TestClient:
    """Another browser on the same running hub: its own cookies (and optionally its own `client` address),
    but the same app and event loop."""
    kwargs.setdefault("headers", {"X-Hub-Request": "1"})
    other = TestClient(running.app, **kwargs)
    other.portal = running.portal  # share the running portal: no second lifespan, agents stay on one loop
    return other


@pytest.fixture
def browser(client: TestClient) -> Callable[..., TestClient]:
    return lambda **kwargs: new_browser(client, **kwargs)


@pytest.fixture
def sign_in(client: TestClient) -> Callable[..., TestClient]:
    """sign_in(role) -> a new browser signed in as a new account with that role."""
    counter = iter(range(1, 1000))

    def make(role: str, username: str | None = None, **user_fields) -> TestClient:
        username = username or f"{role}{next(counter)}"
        client.app.state.hub.auth.create_user(username, PASSWORD, role=role, actor="test", **user_fields)
        other = new_browser(client)
        response = other.post("/api/auth/login", json={"username": username, "password": PASSWORD})
        assert response.status_code == 200, response.text
        return other
    return make


@pytest.fixture
def wait_for() -> Callable:
    def wait(predicate: Callable[[], object], timeout: float = 20, interval: float = 0.1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(interval)
        raise AssertionError("condition not met in time")
    return wait


@pytest.fixture
def node_repo(tmp_path: Path) -> Path:
    """A small Node.js web app with OIDC, Postgres, SMTP and a health route."""
    root = tmp_path / "crm-app"
    (root / "src").mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({
        "name": "crm-app", "version": "2.3.1",
        "scripts": {"start": "node src/server.js"},
        "dependencies": {"express": "^4.19.0", "openid-client": "^5.6.0", "pg": "^8.11.0"},
    }))
    (root / ".env.example").write_text("PORT=4000\nDATABASE_URL=postgres://crm@db/crm\nSMTP_HOST=mail\n")
    (root / "Dockerfile").write_text("FROM node:20\nEXPOSE 4000\nCMD [\"npm\", \"start\"]\n")
    (root / "src" / "server.js").write_text(
        "const app = require('express')();\n"
        "app.get('/healthz', (req, res) => res.json({status: 'ok'}));\n"
        "app.post('/webhooks/deals', (req, res) => res.sendStatus(204));\n"
        "app.listen(process.env.PORT || 4000);\n"
    )
    (root / "README.md").write_text("# CRM App\n\n[![build](x)](y)\n\nA tiny CRM that tracks customers, deals and follow-ups for small teams.\n")
    (root / "LICENSE").write_text("MIT License\n\nPermission is hereby granted, free of charge...\n")
    return root


@pytest.fixture
def plain_repo(tmp_path: Path) -> Path:
    """A Flask app with no SSO, no health route and no events."""
    root = tmp_path / "notes"
    root.mkdir()
    (root / "requirements.txt").write_text("flask==3.0.0\nredis>=5\n")
    (root / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n\n@app.get('/')\ndef index():\n    return 'notes'\n")
    return root
