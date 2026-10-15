"""The fake tool APIs of scripts/demo_hub.py (the demo data behind scripts/screenshots.py) against the real connectors,
so a connector change that the fakes no longer satisfy shows up here and not as a broken screenshot run; and its fake
AI model servers, which answer the OpenAI-compatible API with canned text. Everything runs on 127.0.0.1; nothing is
contacted outside this machine."""

from __future__ import annotations

import asyncio
import json
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


def test_ciso_assistant_gives_the_subsidiary_team_a_read_only_account(tools):
    import httpx

    team = build("ciso_assistant", {"base_url": tools.urls["ciso"]}, {"token": demo_hub.CISO_TEAM_TOKEN})
    outcome = run(team.test())  # K1 of the API-only subsidiary: the connector's own test with the team's credential
    assert outcome["ok"], outcome
    headers = {"Authorization": f"Token {demo_hub.CISO_TEAM_TOKEN}"}
    assert httpx.get(tools.urls["ciso"] + "/api/iam/current-user", headers=headers).json()["email"].startswith(
        "atrium-team@")
    refused = httpx.post(tools.urls["ciso"] + "/api/applied-controls/", json={"name": "x"}, headers=headers)
    assert refused.status_code == 403


def chat(tools, key: str, body: dict, api_key: str | None = None):
    import httpx

    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    return httpx.post(tools.urls[key] + "/v1/chat/completions", json=body, headers=headers, timeout=5)


def test_the_model_servers_speak_the_openai_compatible_api_with_canned_answers(tools):
    import httpx

    cloud, local = tools.urls["model_cloud"], tools.urls["model_local"]
    assert httpx.get(cloud + "/v1/models", timeout=5).status_code == 401  # the cloud one needs its key
    listed = httpx.get(cloud + "/v1/models", headers={"Authorization": f"Bearer {demo_hub.MODEL_CLOUD_KEY}"}).json()
    assert [m["id"] for m in listed["data"]] == demo_hub.MODEL_CLOUD[2]
    assert [m["id"] for m in httpx.get(local + "/v1/models").json()["data"]] == demo_hub.MODEL_LOCAL[2]

    answer = chat(tools, "model_local", {"model": "qwen3:32b", "messages": [
        {"role": "system", "content": "You are an agent."}, {"role": "user", "content": "Which leavers still have access?"}]})
    body = answer.json()
    assert body["choices"][0]["message"]["content"] == demo_hub.REPLIES[0][1]
    assert body["choices"][0]["finish_reason"] == "stop" and body["usage"]["prompt_tokens"] > 0

    upsert = {"type": "function", "function": {"name": "act__records-controls-upsert", "parameters": {}}}
    asked = chat(tools, "model_local", {"model": "qwen3:32b", "tools": [upsert], "messages": [
        {"role": "user", "content": demo_hub.TEAM_TASK}]}).json()["choices"][0]
    call = asked["message"]["tool_calls"][0]
    assert asked["finish_reason"] == "tool_calls" and call["function"]["name"] == "act__records-controls-upsert"
    assert json.loads(call["function"]["arguments"]) == demo_hub.TEAM_CHANGE

    probe = {"type": "function", "function": {"name": "report_ok", "parameters": {
        "type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}}}}
    told = chat(tools, "model_cloud", {"model": "chat-large-v3", "tools": [probe], "messages": [
        {"role": "user", "content": "Call the report_ok tool once with ok set to true."}]}, demo_hub.MODEL_CLOUD_KEY)
    assert told.json()["choices"][0]["message"]["tool_calls"][0]["function"]["name"] == "report_ok"

    schema = {"type": "object", "required": ["title", "severity", "items"], "properties": {
        "title": {"type": "string"}, "severity": {"enum": ["low", "high"]}, "items": {"type": "array"},
        "note": {"type": "string"}}}
    shaped = chat(tools, "model_local", {"model": "qwen3:32b", "messages": [{"role": "user", "content": "x"}],
                                         "response_format": {"type": "json_schema", "json_schema": {"schema": schema}}})
    assert json.loads(shaped.json()["choices"][0]["message"]["content"]) == {"title": "", "severity": "low",
                                                                            "items": []}


def test_the_tools_answer_health_checks_and_serve_their_openapi_documents(tools):
    import httpx

    for key in ("snipeit", "keycloak", "greenbone", "ciso", "grafana", "wazuh", "firewall", "model_cloud",
                "model_local"):
        assert httpx.get(tools.urls[key] + "/", timeout=5).status_code == 200
    spec = httpx.get(tools.urls["keycloak"] + "/openapi.json", timeout=5).json()
    assert spec["components"]["securitySchemes"]["auth"]["type"] == "openIdConnect"
    assert spec["servers"] == [{"url": tools.urls["keycloak"]}]
