"""The fake tool APIs of scripts/demo_hub.py (the demo data behind scripts/screenshots.py) against the real connectors,
so a connector change that the fakes no longer satisfy shows up here and not as a broken screenshot run. Everything
runs on 127.0.0.1; nothing is contacted outside this machine."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from hub.connectors import build

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import demo_hub  # noqa: E402 - from scripts/


def run(coro):
    return asyncio.run(coro)


@pytest.fixture(scope="module")
def tools():
    fakes = demo_hub.DemoTools(0).start()  # any free ports
    yield fakes
    fakes.stop()


def test_snipeit_lists_the_hardware_with_addresses_and_who_uses_it(tools):
    snipeit = build("snipeit", {"base_url": tools.urls["snipeit"], "read_accounts": True},
                    {"token": demo_hub.SNIPEIT_TOKEN})
    outcome = run(snipeit.test())
    assert outcome["ok"], outcome
    assert outcome["domains"] == {"assets": ["read"], "accounts": ["read"]}
    assets = {a["name"]: a for a in run(snipeit.pull("assets"))}
    assert len(assets) == len(demo_hub.HARDWARE)
    assert assets["db-01"]["addresses"] == ["10.0.20.11"] and assets["db-01"]["type"] == "server"
    assert assets["LT-1046"]["facts"]["assigned_email"] == demo_hub.email_of(demo_hub.LEAVER)
    accounts = run(snipeit.pull("accounts"))
    assert len(accounts) == len(demo_hub.PEOPLE) and all(a["active"] for a in accounts)
    wrong = build("snipeit", {"base_url": tools.urls["snipeit"]}, {"token": "another-token"})
    assert not run(wrong.test())["ok"]


def test_keycloak_lists_the_people_and_the_leaver_is_disabled(tools):
    keycloak = build("keycloak", {"base_url": tools.urls["keycloak"], "realm": "company", "client_id": "atrium-directory",
                                  "include_groups": True}, {"client_secret": demo_hub.KEYCLOAK_SECRET})
    outcome = run(keycloak.test())
    assert outcome["ok"], outcome
    people = {p["login"]: p for p in run(keycloak.pull("people"))}
    assert len(people) == len(demo_hub.PEOPLE)
    assert people[demo_hub.LEAVER]["status"] == "suspended" and people["ava.martens"]["status"] == "active"
    assert people["noah.willems"]["groups"] == ["it", "security"] and people["noah.willems"]["department"] == "IT"
    assert people["noah.willems"]["manager_external_id"] == people["ava.martens"]["external_id"]


def test_greenbone_scans_the_targets_and_reports_their_findings(tools):
    openvas = build("openvas", {"connection_type": "tcp", "host": "127.0.0.1", "port": tools.gmp_port,
                                "username": "atrium"}, {"password": demo_hub.GREENBONE_PASSWORD})
    outcome = run(openvas.test())
    assert outcome["ok"], outcome
    job = run(openvas.scan(["10.0.20.12", "10.0.99.20"], "Demo scan"))
    assert run(openvas.scan_status(job["job_id"]))["done"]
    findings = run(openvas.pull("vulnerabilities", since=0))
    assert sorted(f["host"] for f in findings) == ["10.0.20.12", "10.0.20.12", "10.0.99.20"]
    tomcat = next(f for f in findings if "Tomcat" in f["title"])
    assert tomcat["severity"] == "critical" and tomcat["cves"] == ["CVE-2025-24813"] and tomcat["port"] == "8080/tcp"


def test_ciso_assistant_accepts_the_connection(tools):
    ciso = build("ciso_assistant", {"base_url": tools.urls["ciso"]}, {"token": demo_hub.CISO_TOKEN})
    outcome = run(ciso.test())
    assert outcome["ok"], outcome
    assert {"assets", "controls", "vulnerabilities", "frameworks"} <= set(outcome["domains"])


def test_the_tools_answer_health_checks_and_serve_their_openapi_documents(tools):
    import httpx

    for key in ("snipeit", "keycloak", "greenbone", "ciso", "grafana", "wazuh", "firewall"):
        assert httpx.get(tools.urls[key] + "/", timeout=5).status_code == 200
    spec = httpx.get(tools.urls["keycloak"] + "/openapi.json", timeout=5).json()
    assert spec["components"]["securitySchemes"]["auth"]["type"] == "openIdConnect"
    assert spec["servers"] == [{"url": tools.urls["keycloak"]}]
