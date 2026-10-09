from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable

import pytest
from fastapi.testclient import TestClient

from hub.app import create_app
from hub.config import Settings


@pytest.fixture(autouse=True)
def no_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never call a real model."""
    monkeypatch.setenv("HUB_LLM", "off")


@pytest.fixture
def client(tmp_path: Path):
    settings = Settings(data_dir=tmp_path / "data", allowed_hosts=["testserver"], start_background_tasks=False)
    app = create_app(settings)
    with TestClient(app, headers={"X-Hub-Request": "1"}) as c:
        yield c


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
