"""The connector SDK (canonical records, redaction, registry) and the generic REST connector, without a network."""

import asyncio
import json

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize, redact, severity_from_score, to_timestamp, valid_scan_target
from hub.connectors.generic_rest import GenericRestConnector, validate_mapping
from hub.models import Manifest, Tool

TOKEN = "gr-token-0123456789"


def run(coro):
    return asyncio.run(coro)


# -- canonical records -----------------------------------------------------------------------


def test_normalize_coerces_and_drops():
    assets, errors = normalize("assets", [
        {"external_id": 7, "name": {"name": "web-1"}, "type": "Server", "status": "Ready to Deploy",
         "addresses": "10.0.0.5, web-1.example.com", "facts": {"serial": "S1", "empty": ""}, "updated_at": "2026-01-02T03:04:05Z"},
        {"name": "no id"},
        "not a dict",
    ])
    assert assets == [{"external_id": "7", "hub_id": None, "name": "web-1", "type": "server", "owner": None,
                       "status": "active", "addresses": ["10.0.0.5", "web-1.example.com"], "facts": {"serial": "S1"},
                       "updated_at": to_timestamp("2026-01-02T03:04:05Z")}]
    assert len(errors) == 2 and "external_id" in errors[0]
    vulns, _ = normalize("vulnerabilities", [{"external_id": "1.3.6|10.0.0.5|443/tcp", "title": "TLS", "cvss": "9.8",
                                              "cves": "cve-2024-0001 CVE-2023-12345", "port": 443}])
    assert vulns[0]["severity"] == "critical" and vulns[0]["cves"] == ["CVE-2023-12345", "CVE-2024-0001"]
    assert vulns[0]["port"] == "443"
    risks, _ = normalize("risks", [{"external_id": "r1", "title": "x", "likelihood": 9, "impact": "0", "status": "in treatment"}])
    assert (risks[0]["likelihood"], risks[0]["impact"], risks[0]["status"]) == (5, 1, "in_treatment")
    with pytest.raises(ConnectorError):
        normalize("tickets", [])


@pytest.mark.parametrize("score,severity", [(None, "info"), (0, "info"), (0.1, "low"), (4, "medium"), (6.9, "medium"),
                                            (7, "high"), (8.9, "high"), (9, "critical"), (10, "critical")])
def test_severity_bands(score, severity):
    assert severity_from_score(score) == severity


def test_redaction_masks_values_and_credential_pairs():
    text = f'token={TOKEN} Authorization: Bearer {TOKEN} {{"password": "pw-123456"}} api_key=abc123'
    out = redact(text, {"token": TOKEN})
    assert TOKEN not in out and "pw-123456" not in out and "abc123" not in out
    assert out.count("***") >= 3


@pytest.mark.parametrize("value,ok", [("10.0.0.5", True), ("10.0.0.0/24", True), ("2001:db8::1", True),
                                      ("web-1.example.com", True), ("-oX", False), ("a b", False), ("<x>", False),
                                      ("host;rm -rf", False), ("", False), ("x" * 300, False)])
def test_scan_targets_are_addresses_or_hostnames(value, ok):
    assert valid_scan_target(value) is ok


def test_registry_catalog_and_detection():
    kinds = {c["kind"]: c for c in connectors.catalog()}
    assert {"snipeit", "ciso_assistant", "openvas", "generic_rest"} <= set(kinds)
    assert kinds["openvas"]["actions"] == ["scan", "scan_status"] and kinds["snipeit"]["system_of_record"] == ["assets"]
    assert any(f["kind"] == "secret" for f in kinds["generic_rest"]["fields"])
    tool = Tool(id="snipe-it", name="Snipe-IT", source_type="local", source="/x", manifest=Manifest(id="snipe-it", name="Snipe-IT"))
    assert connectors.detect(tool)[0]["kind"] == "snipeit"
    scanner = Tool(id="scanner", name="Scanner", source_type="local", source="/x",
                   manifest=Manifest(id="scanner", name="Scanner", provides=["vuln.scanner"]))
    assert connectors.detect(scanner)[0] == {"kind": "openvas", "title": "OpenVAS / Greenbone", "score": 30}
    with pytest.raises(ConnectorError, match="Unknown connector kind"):
        connectors.connector_class("nope")


# -- generic REST: mapping validation -----------------------------------------------------------

MAPPING = {
    "assets": {
        "list": {"path": "/items", "items": "data", "pagination": {"type": "offset", "page_size": 2, "total": "total"}},
        "fields": {"external_id": "id", "name": "name", "addresses": ["ip", "fqdn"], "facts": {"serial": "serial"}},
        "defaults": {"type": "server"},
        "create": {"path": "/items", "method": "POST", "body": {"name": "{name}", "ips": "{addresses}"}, "id": "data.id"},
        "update": {"path": "/items/{external_id}", "method": "PATCH"},
    },
}


@pytest.mark.parametrize("path", ["https://evil.example/x", "//evil.example/x", "/a/../b", "/a?x=1", "items", "/a b", "/a\\b"])
def test_mapping_paths_stay_relative(path):
    with pytest.raises(ConnectorError, match="Invalid mapping"):
        validate_mapping({"assets": {"list": {"path": path}, "fields": {"external_id": "id"}}})


def test_mapping_needs_known_domains_and_ids():
    with pytest.raises(ConnectorError, match="unknown domain"):
        validate_mapping({"tickets": {"list": {"path": "/t"}}})
    with pytest.raises(ConnectorError, match="external_id"):
        validate_mapping({"assets": {"list": {"path": "/t"}, "fields": {"name": "n"}}})
    with pytest.raises(ConnectorError, match="method"):
        validate_mapping({"assets": {"create": {"path": "/t", "method": "DELETE"}}})
    with pytest.raises(ConnectorError, match="not valid JSON"):
        validate_mapping("{oops")


def test_config_keeps_credentials_out_of_the_url():
    base = {"auth": "bearer", "mapping": MAPPING}
    with pytest.raises(ConnectorError, match="http"):
        GenericRestConnector.validate_config({**base, "base_url": "ftp://x"})
    with pytest.raises(ConnectorError, match="secret fields"):
        GenericRestConnector.validate_config({**base, "base_url": "https://user:pw@x.example"})
    with pytest.raises(ConnectorError, match="header name"):
        GenericRestConnector.validate_config({**base, "base_url": "https://x.example", "auth": "header", "auth_header": "X Bad"})
    ok = GenericRestConnector.validate_config({**base, "base_url": "https://x.example/api/"})
    assert ok["base_url"] == "https://x.example/api"


# -- generic REST: talking to an API --------------------------------------------------------------


def connector(handler, mapping=None, **config) -> GenericRestConnector:
    cfg = GenericRestConnector.validate_config({"base_url": "https://inv.example.com/api", "auth": "bearer",
                                                "mapping": json.loads(json.dumps(mapping or MAPPING)), **config})
    return GenericRestConnector(cfg, {"token": TOKEN}, httpx.MockTransport(handler))


def test_pull_with_offset_pages_and_bearer_auth():
    rows = [{"id": i, "name": f"host-{i}", "ip": f"10.0.0.{i}", "fqdn": None, "serial": f"S{i}"} for i in range(5)]
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == f"Bearer {TOKEN}"
        offset, limit = int(request.url.params["offset"]), int(request.url.params["limit"])
        seen.append((request.url.path, offset))
        return httpx.Response(200, json={"total": 5, "data": rows[offset:offset + limit]})

    records = run(connector(handler).pull("assets"))
    assert [r["external_id"] for r in records] == [0, 1, 2, 3, 4]
    assert records[1] == {"type": "server", "external_id": 1, "name": "host-1", "addresses": ["10.0.0.1"], "facts": {"serial": "S1"}}
    assert seen == [("/api/items", 0), ("/api/items", 2), ("/api/items", 4)]


def test_next_links_must_stay_on_the_configured_host():
    mapping = {"risks": {"list": {"path": "/risks", "items": "results", "pagination": {"type": "next", "next": "next"}},
                         "fields": {"external_id": "id", "title": "name"}}}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.params.get("page") == "2":
            return httpx.Response(200, json={"results": [{"id": "b", "name": "B"}], "next": "https://evil.example/steal"})
        return httpx.Response(200, json={"results": [{"id": "a", "name": "A"}], "next": "/api/risks?page=2"})

    with pytest.raises(ConnectorError, match="another host"):
        run(connector(handler, mapping).pull("risks"))


def test_push_creates_updates_and_reports_rejections_verbatim():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls.append((request.method, request.url.path, body))
        if body.get("name") == "bad":
            return httpx.Response(422, json={"messages": {"name": ["The name is reserved."]}})
        if request.method == "POST":
            return httpx.Response(201, json={"data": {"id": 42}})
        return httpx.Response(200, json={})

    records = [{"hub_id": "a_1", "name": "web-1", "addresses": ["10.0.0.5"]},
               {"hub_id": "a_2", "name": "web-2", "addresses": [], "facts": {"serial": "S2"}},
               {"hub_id": "a_3", "name": "bad", "addresses": []}]
    results = run(connector(handler).push("assets", records, {"a_2": "17"}))
    assert [(r["action"], r["external_id"]) for r in results] == [("created", "42"), ("updated", "17"), ("failed", None)]
    assert "The name is reserved." in results[2]["error"]
    assert calls[0] == ("POST", "/api/items", {"name": "web-1", "ips": ["10.0.0.5"]})
    assert calls[1] == ("PATCH", "/api/items/17", {"name": "web-2", "serial": "S2"})  # no body: mapped back through fields


def test_rejected_credentials_fail_the_whole_push_without_leaking_the_token():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text=f"bad token {TOKEN}")

    with pytest.raises(ConnectorError) as info:
        run(connector(handler).push("assets", [{"hub_id": "a_1", "name": "x", "addresses": []}], {}))
    assert info.value.status == 401 and TOKEN not in (info.value.excerpt or "") and TOKEN not in info.value.message


def test_test_reports_the_mapped_domains():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/items"):
            return httpx.Response(200, json={"total": 1, "data": [{"id": 1, "name": "x"}]})
        return httpx.Response(404, text="nope")

    mapping = {**MAPPING, "risks": {"list": {"path": "/risks"}, "fields": {"external_id": "id"}}}
    result = run(connector(handler, mapping).test())
    assert result["ok"] is False and result["domains"] == {"assets": ["read", "write"]}
    failed = next(c for c in result["checks"] if not c["ok"])
    assert failed["name"] == "risks: read" and "404" in failed["detail"]
