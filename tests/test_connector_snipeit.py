"""The Snipe-IT connector against a fake Snipe-IT API v1 (httpx.MockTransport, no network)."""

import asyncio
import json
from typing import Any

import httpx
import pytest

from hub import connectors
from hub.connectors import snipeit
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.snipeit import SnipeItConnector, asset_type, split_addresses, split_macs
from hub.integration.connections import clean_config
from hub.models import Manifest, Tool

TOKEN = "snipe-token-0123456789abcdef"
BASE = "https://snipe.example.com"


def run(coro):
    return asyncio.run(coro)


def envelope(status: str, messages: Any, payload: Any = None, code: int = 200) -> httpx.Response:
    return httpx.Response(code, json={"status": status, "messages": messages, "payload": payload})


def hardware(id: int, **extra: Any) -> dict[str, Any]:
    """A hardware row shaped like Snipe-IT's AssetsTransformer output."""
    row = {"id": id, "name": f"host-{id}", "asset_tag": f"T{id:03}", "serial": f"SN{id}",
           "model": {"id": 1, "name": "PowerEdge R650"}, "model_number": "R650",
           "status_label": {"id": 1, "name": "Ready to Deploy", "status_type": "deployable", "status_meta": "deployable"},
           "category": {"id": 1, "name": "Servers", "tag_color": None}, "manufacturer": {"id": 1, "name": "Dell"},
           "location": None, "rtd_location": {"id": 2, "name": "DC 1"}, "company": None, "assigned_to": None,
           "custom_fields": {}, "purchase_date": {"date": "2025-03-01", "formatted": "01/03/2025"},
           "updated_at": {"datetime": "2026-09-01 10:00:00", "formatted": "01/09/2026 10:00"}, "deleted_at": None}
    row.update(extra)
    return row


def ip_field(value: str, label: str = "IP Address", column: str = "_snipeit_ip_address_2", fmt: str = "IP") -> dict:
    return {label: {"field": column, "value": value, "field_format": fmt, "element": "text"}}


class FakeSnipe:
    """Just enough of Snipe-IT's API v1: bearer auth, {total, rows} lists capped at `max_results`, HTTP 200
    {"status": "error"} envelopes for validation errors and missing look-ups, 404 for updating a missing asset."""

    def __init__(self, rows: list[dict[str, Any]] | None = None, max_results: int = 500, prefix: str = "/api/v1"):
        self.rows = {r["id"]: r for r in rows or []}
        self.max_results, self.prefix = max_results, prefix
        self.calls: list[tuple[str, str, dict[str, str], Any]] = []
        self.models = [{"id": 5, "name": "Latitude 7440", "manufacturer": {"id": 1, "name": "Dell"}, "model_number": "7440"}]
        self.statuslabels = [{"id": 2, "name": "Ready to Deploy", "type": "deployable"},
                             {"id": 3, "name": "Broken &amp; Out", "type": "undeployable"}]
        self.fields = [{"id": 1, "name": "Purchase order", "db_column_name": "_snipeit_purchase_order_1", "format": "ANY"},
                       {"id": 2, "name": "IP Address", "db_column_name": "_snipeit_ip_address_2", "format": "IP"}]
        self.answers: dict[str, list[httpx.Response]] = {}  # path -> canned answers, used up first
        self.has_version = True
        self.next_id = 100

    @staticmethod
    def listing(rows: list[dict[str, Any]], params: dict[str, str], cap: int) -> httpx.Response:
        offset, limit = int(params.get("offset", 0)), min(int(params.get("limit", 50)), cap)
        return httpx.Response(200, json={"total": len(rows), "rows": rows[offset:offset + limit]})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith(self.prefix), request.url.path
        path = request.url.path[len(self.prefix):]
        params = dict(request.url.params)
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, params, body))
        if request.headers.get("Authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"status": "error", "messages": "Unauthenticated.", "payload": None})
        if request.headers.get("Accept") != "application/json":
            return httpx.Response(302, headers={"Location": f"{BASE}/login"})
        if self.answers.get(path):
            return self.answers[path].pop(0)
        method, parts = request.method, path.strip("/").split("/")
        if path == "/version":
            return httpx.Response(200, json={"version": "v8.3.1", "build_version": "1", "hash_version": "abc",
                                             "full_version": "v8.3.1 build 1 (abc)"}) if self.has_version else \
                httpx.Response(404, json={"status": "error", "messages": "404 endpoint not found", "payload": None})
        if path == "/users/me":
            return httpx.Response(200, json={"id": 1, "username": "atrium-sync", "name": "Atrium Sync"})
        if parts[0] == "hardware":
            return self.hardware(method, parts, params, body)
        if parts[0] in ("models", "statuslabels"):
            items = self.models if parts[0] == "models" else self.statuslabels
            if len(parts) == 1:
                return self.listing(items, params, self.max_results)
            found = next((i for i in items if str(i["id"]) == parts[1]), None)
            return httpx.Response(200, json=found) if found else envelope("error", f"{parts[0]} not found")
        if path == "/fields":  # Snipe-IT lists every custom field, ignoring limit and offset
            return httpx.Response(200, json={"total": len(self.fields), "rows": self.fields})
        return httpx.Response(404, json={"status": "error", "messages": "404 endpoint not found", "payload": None})

    def hardware(self, method: str, parts: list[str], params: dict[str, str], body: Any) -> httpx.Response:
        if method == "GET" and len(parts) == 1:
            return self.listing(sorted(self.rows.values(), key=lambda r: r["id"]), params, self.max_results)
        if method == "GET" and parts[1] == "bytag":
            found = next((r for r in self.rows.values() if r["asset_tag"] == "/".join(parts[2:])), None)
            return httpx.Response(200, json=found) if found else envelope("error", "Asset does not exist.")
        if method == "POST":
            tag = body.get("asset_tag")
            if not tag:
                return envelope("error", {"asset_tag": ["The asset tag field is required."]})
            if " " in tag:
                return envelope("error", {"asset_tag": ["The asset tag format is invalid."]})
            if any(r["asset_tag"] == tag for r in self.rows.values()):
                return envelope("error", {"asset_tag": ["The asset tag must be unique."]})
            row = hardware(self.next_id, **{k: v for k, v in body.items() if k in ("name", "serial", "asset_tag")})
            self.rows[row["id"]] = row
            self.next_id += 1
            return envelope("success", "Asset created successfully. :)", {"id": row["id"], "asset_tag": tag})
        if method == "PATCH":
            row = self.rows.get(int(parts[1]))
            if row is None:
                return envelope("error", "Asset not found", code=404)
            row.update({k: v for k, v in body.items() if k in ("name", "serial")})
            return envelope("success", "Asset updated successfully.", {"id": row["id"]})
        return httpx.Response(405)

    def hits(self, method: str, path: str) -> list[tuple[str, str, dict[str, str], Any]]:
        return [c for c in self.calls if c[0] == method and c[1] == path]


def connector(fake: Any, token: str = TOKEN, **config: Any) -> SnipeItConnector:
    cfg = clean_config(SnipeItConnector, {"base_url": BASE, **config})
    conn = SnipeItConnector(cfg, {"token": token}, httpx.MockTransport(fake))
    conn.retry_cap = 0  # type: ignore[misc]
    return conn


# -- settings, registry ----------------------------------------------------------------------


def test_settings_are_normalised_and_validated():
    cfg = clean_config(SnipeItConnector, {"base_url": "https://snipe.example.com/api/v1/", "model_id": "5", "status_id": 2})
    assert cfg == {"base_url": "https://snipe.example.com", "verify_tls": True, "asset_tags": "hub", "model_id": 5,
                   "status_id": 2}
    assert clean_config(SnipeItConnector, {"base_url": "https://example.com/snipe/API"})["base_url"] == "https://example.com/snipe"
    # the stored token stays bound to scheme/host/port: pasting the API root does not count as moving it
    assert SnipeItConnector.endpoint(cfg) == SnipeItConnector.endpoint({"base_url": "https://snipe.example.com"})
    with pytest.raises(ValueError, match="credentials"):
        clean_config(SnipeItConnector, {"base_url": "https://admin:pw@snipe.example.com"})
    with pytest.raises(ValueError, match="model for new hardware must be a Snipe-IT id"):
        clean_config(SnipeItConnector, {"base_url": BASE, "model_id": "Latitude"})
    with pytest.raises(ValueError, match="Asset tags"):
        clean_config(SnipeItConnector, {"base_url": BASE, "asset_tags": "random"})
    with pytest.raises(ValueError, match="address custom field"):
        clean_config(SnipeItConnector, {"base_url": BASE, "address_field": "<script>"})
    with pytest.raises(ValueError, match="no setting 'token'|secret"):
        clean_config(SnipeItConnector, {"base_url": BASE, "token": TOKEN})


def test_registry_builds_it_and_detection_finds_snipe_it():
    built = connectors.build("snipeit", {"base_url": BASE}, {"token": TOKEN})
    assert isinstance(built, SnipeItConnector) and built.config["asset_tags"] == "hub"
    described = SnipeItConnector.describe()
    assert described["capabilities"] == {"assets": ["read", "write"]} and described["system_of_record"] == ["assets"]
    assert {f["name"] for f in described["fields"] if f["options"]} == {"address_field", "model_id", "status_id"}
    imported = Tool(id="inventory", name="Inventory", source_type="github", source="https://github.com/grokability/snipe-it")
    assert SnipeItConnector.detect(imported) == 90
    other = Tool(id="wiki", name="Wiki", source_type="local", source="/x", manifest=Manifest(id="wiki", name="Wiki"))
    assert SnipeItConnector.detect(other) == 0
    inventory = Tool(id="cmdb", name="CMDB", source_type="local", source="/x",
                     manifest=Manifest(id="cmdb", name="CMDB", provides=["assets.inventory"]))
    assert SnipeItConnector.detect(inventory) == 30


# -- reading hardware --------------------------------------------------------------------------


def test_pull_pages_through_hardware_and_maps_canonical_records():
    jane = {"id": 9, "username": "jdoe", "name": "Jane O&#039;Doe", "first_name": "Jane", "last_name": "O'Doe",
            "email": "jane@example.com", "employee_number": "E7", "jobtitle": None, "type": "user"}
    rows = [
        hardware(1, name="R&amp;D laptop", category={"id": 3, "name": "Laptops"}, assigned_to=jane,
                 status={"id": 1, "name": "Ready to Deploy", "status_type": "deployable", "status_meta": "deployed"},
                 custom_fields={**ip_field("10.0.0.5"),
                                "FQDN": {"field": "_snipeit_fqdn_3", "value": "LT-1.corp.example.com.", "field_format": "ANY"},
                                "MAC Address": {"field": "_snipeit_mac_address_1", "value": "AA-BB-CC-DD-EE-FF",
                                                "field_format": "MAC"},
                                "Purchase order": {"field": "_snipeit_purchase_order_4", "value": "PO-1", "field_format": "ANY"}}),
        hardware(2, name="", status_label={"id": 4, "name": "Archived", "status_type": "archived", "status_meta": "archived"}),
        hardware(3, category={"id": 4, "name": "Switches"}, assigned_to={"id": 4, "name": "Lab", "type": "location"},
                 status_label={"id": 5, "name": "Pending", "status_type": "pending", "status_meta": "pending"},
                 custom_fields=ip_field("DHCP")),
        hardware(4, category={"id": 5, "name": "Printers"}, primary_ip="10.0.0.9", primary_mac="001122334455",
                 deleted_at={"datetime": "2026-09-02 08:00:00", "formatted": "..."}),
        hardware(5, status_label={"id": 6, "name": "Broken", "status_type": "undeployable", "status_meta": "undeployable"}),
    ]
    fake = FakeSnipe(rows, max_results=2)  # a page is capped below the requested limit: the offset follows the rows
    records = run(connector(fake).pull("assets"))
    listed = fake.hits("GET", "/hardware")
    assert [(c[2]["offset"], c[2]["limit"], c[2]["sort"], c[2]["order"]) for c in listed] == \
        [("0", "500", "id", "asc"), ("2", "500", "id", "asc"), ("4", "500", "id", "asc")]
    assert records[0] == {
        "external_id": "1", "name": "R&D laptop", "type": "workstation", "owner": "Jane O'Doe", "status": "active",
        "addresses": ["10.0.0.5", "lt-1.corp.example.com"],
        "facts": {"snipeit_id": 1, "asset_tag": "T001", "serial": "SN1", "model": "PowerEdge R650", "model_number": "R650",
                  "manufacturer": "Dell", "category": "Laptops", "location": "DC 1", "status_label": "Ready to Deploy",
                  "mac": "aa:bb:cc:dd:ee:ff", "assigned_type": "user", "assigned_name": "Jane O'Doe",
                  "assigned_username": "jdoe", "assigned_email": "jane@example.com", "assigned_employee_number": "E7",
                  "purchase_date": "2025-03-01"},
        "updated_at": {"datetime": "2026-09-01 10:00:00", "formatted": "01/09/2026 10:00"},
    }
    by_id = {r["external_id"]: r for r in records}
    assert (by_id["2"]["name"], by_id["2"]["status"]) == ("T002", "retired")  # archived; no name -> the asset tag
    assert (by_id["3"]["type"], by_id["3"]["status"], by_id["3"]["owner"], by_id["3"]["addresses"]) == \
        ("network", "maintenance", None, [])  # "DHCP" is no address; a location is no owner
    assert by_id["3"]["facts"]["assigned_name"] == "Lab" and "assigned_username" not in by_id["3"]["facts"]
    assert (by_id["4"]["type"], by_id["4"]["status"], by_id["4"]["addresses"], by_id["4"]["facts"]["mac"]) == \
        ("other", "retired", ["10.0.0.9"], "00:11:22:33:44:55")
    assert by_id["5"]["status"] == "maintenance"
    canonical, errors = normalize("assets", records)  # what the tool supervisor does with them
    assert not errors and len(canonical) == 5
    assert canonical[0]["updated_at"] == pytest.approx(1788256800.0) and canonical[0]["facts"]["assigned_email"] == "jane@example.com"


def test_the_chosen_address_field_is_read_and_values_are_cleaned():
    row = hardware(1, custom_fields={
        "Management": {"field": "_snipeit_management_5", "value": "https://mgmt-1.example.com/login, 10.1.1.1:443",
                       "field_format": "ANY"},
        **ip_field("n/a"),
        "Host name": {"field": "_snipeit_host_name_6", "value": "Encrypted", "field_format": "ANY"}})
    records = run(connector(FakeSnipe([row]), address_field="management").pull("assets"))
    assert records[0]["addresses"] == ["mgmt-1.example.com", "10.1.1.1"]


@pytest.mark.parametrize("value,expected", [
    ("10.0.0.5", ["10.0.0.5"]), ("10.0.0.5, 10.0.0.6;web-1", ["10.0.0.5", "10.0.0.6", "web-1"]),
    ("[2001:db8::1]", ["2001:db8::1"]), ("2001:db8::2", ["2001:db8::2"]), ("WEB-1.Example.com.", ["web-1.example.com"]),
    ("http://10.0.0.7:8080/x", ["10.0.0.7"]), ("dhcp", []), ("N/A", []), ("10.0.0.0/24", []), ("12345", []),
    ("<b>x</b>", []), ("10.0.0", []), (None, []), ("10.0.0.5 10.0.0.5", ["10.0.0.5"]),
])
def test_split_addresses(value, expected):
    assert split_addresses(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("AA:BB:CC:DD:EE:FF", ["aa:bb:cc:dd:ee:ff"]), ("aabb.ccdd.eeff", ["aa:bb:cc:dd:ee:ff"]),
    ("00-11-22-33-44-55, 001122334466", ["00:11:22:33:44:55", "00:11:22:33:44:66"]), ("not a mac", []), ("", []),
])
def test_split_macs(value, expected):
    assert split_macs(value) == expected


@pytest.mark.parametrize("category,kind", [
    ("Laptops", "workstation"), ("Desktops", "workstation"), ("Mobile Phones", "workstation"), ("Servers", "server"),
    ("Virtual Machines", "server"), ("Switches", "network"), ("Access Points", "network"), ("Firewalls", "network"),
    ("Cloud subscriptions", "cloud"), ("Software", "software"), ("Printers", "other"), ("Monitors", "other"),
    (None, "other"),
])
def test_categories_suggest_asset_types(category, kind):
    assert asset_type(category) == kind


def test_an_error_envelope_with_http_200_is_an_error():
    fake = FakeSnipe([hardware(1)])
    fake.answers["/hardware"] = [envelope("error", "You do not have permission to view hardware.")]
    with pytest.raises(ConnectorError) as info:
        run(connector(fake).pull("assets"))
    assert info.value.status == 200 and "You do not have permission to view hardware." in info.value.message


def test_a_huge_or_unpageable_inventory_is_refused_rather_than_truncated(monkeypatch):
    monkeypatch.setattr(snipeit, "MAX_RECORDS", 3)
    with pytest.raises(ConnectorError, match="at most 3"):
        run(connector(FakeSnipe([hardware(i) for i in range(1, 6)], max_results=2)).pull("assets"))
    monkeypatch.setattr(snipeit, "PAGE", 2)  # a full page without a total may be partial: the rest would be retired
    fake = FakeSnipe()
    fake.answers["/hardware"] = [httpx.Response(200, json={"rows": [hardware(1), hardware(2)]})]
    with pytest.raises(ConnectorError, match="no total"):
        run(connector(fake).pull("assets"))
    fake.answers["/hardware"] = [httpx.Response(200, json={"rows": [hardware(1)]})]
    assert len(run(connector(fake).pull("assets"))) == 1


def test_only_assets_and_a_subdirectory_install():
    fake = FakeSnipe([hardware(1)], prefix="/it/snipe/api/v1")
    conn = connector(fake, base_url="https://intranet.example.com/it/snipe")
    assert [r["external_id"] for r in run(conn.pull("assets"))] == ["1"]
    with pytest.raises(ConnectorError, match="only assets"):
        run(conn.pull("vulnerabilities"))


def test_rate_limits_are_waited_out_then_reported():
    fake = FakeSnipe([hardware(1)])
    fake.answers["/hardware"] = [httpx.Response(429, headers={"Retry-After": "0"}, json={"message": "Too Many Attempts."})]
    assert len(run(connector(fake).pull("assets"))) == 1 and len(fake.hits("GET", "/hardware")) == 2
    fake.answers["/hardware"] = [httpx.Response(429, headers={"Retry-After": "60"}) for _ in range(4)]
    with pytest.raises(ConnectorError) as info:
        run(connector(fake).pull("assets"))
    assert info.value.status == 429 and "rate limiting" in info.value.message


# -- test() ------------------------------------------------------------------------------------


def test_test_reports_version_account_hardware_addresses_and_write_settings():
    rows = [hardware(1, custom_fields=ip_field("10.0.0.5")), hardware(2, custom_fields=ip_field("10.0.0.6")), hardware(3)]
    fake = FakeSnipe(rows)
    result = run(connector(fake, model_id=5, status_id=2, address_field="_snipeit_ip_address_2").test())
    assert result["ok"] is True and result["domains"] == {"assets": ["read", "write"]}
    assert result["detail"] == "Connected to Snipe-IT v8.3.1, 3 asset(s)"
    checks = {c["name"]: c for c in result["checks"]}
    assert list(checks) == ["Connection", "API token", "Read hardware", "Addresses", "Create hardware"]
    assert checks["API token"]["detail"] == "accepted - signed in as atrium-sync"
    assert checks["Read hardware"]["detail"] == "3 asset(s) visible to this account"
    assert "2 of the first 3 assets have an IP address or hostname (from IP Address)" in checks["Addresses"]["detail"]
    assert "model 'Latitude 7440' and status 'Ready to Deploy'" in checks["Create hardware"]["detail"]
    assert "_snipeit_ip_address_2" in checks["Create hardware"]["detail"]
    assert fake.hits("GET", "/hardware")[0][2]["limit"] == "50" and len(fake.hits("GET", "/hardware")) == 1
    assert not [c for c in fake.calls if c[0] != "GET"]  # a test never writes


def test_test_without_write_settings_on_an_older_version_is_read_only():
    fake = FakeSnipe([hardware(1)])
    fake.has_version = False
    result = run(connector(fake).test())
    assert result["ok"] is True and result["domains"] == {"assets": ["read"]}
    assert result["detail"] == "Connected to Snipe-IT, 1 asset(s) (read only)"
    checks = {c["name"]: c for c in result["checks"]}
    assert "does not report its version" in checks["Connection"]["detail"]
    assert "None of the first 1 assets has an IP address" in checks["Addresses"]["detail"]
    assert checks["Create hardware"]["ok"] and "only reads" in checks["Create hardware"]["detail"]


def test_test_with_a_rejected_token_stops_and_never_shows_it():
    fake = FakeSnipe([hardware(1)])
    result = run(connector(fake, token="wrong-token-123456").test())
    assert result["ok"] is False and result["domains"] == {}
    assert [(c["name"], c["ok"]) for c in result["checks"]] == [("API token", False)]
    assert "check the API token" in result["detail"] and "wrong-token-123456" not in json.dumps(result)
    assert len(fake.calls) == 1


@pytest.mark.parametrize("answer,expected", [
    (httpx.Response(302, headers={"Location": f"{BASE}/login"}), "redirected to https://snipe.example.com/login"),
    (httpx.Response(200, text="<html>Welcome to nginx</html>"), "did not answer with JSON"),
    (httpx.Response(502, text="Bad gateway"), "HTTP 502"),
])
def test_test_explains_a_wrong_address(answer, expected):
    fake = FakeSnipe()
    fake.answers["/version"] = [answer]
    result = run(connector(fake).test())
    assert result["ok"] is False and len(result["checks"]) == 1 and expected in result["checks"][0]["detail"]


def test_test_when_snipe_it_cannot_be_reached():
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    result = run(connector(refuse).test())
    assert result["ok"] is False and "Cannot reach Snipe-IT" in result["detail"]


def test_test_flags_a_missing_address_field_and_unknown_write_settings():
    fake = FakeSnipe([hardware(1, custom_fields=ip_field("10.0.0.5"))])
    result = run(connector(fake, model_id=77, status_id=2, address_field="_snipeit_mgmt_ip_9").test())
    assert result["ok"] is False and result["domains"] == {"assets": ["read"]}
    checks = {c["name"]: c for c in result["checks"]}
    assert not checks["Addresses"]["ok"] and "'_snipeit_mgmt_ip_9'" in checks["Addresses"]["detail"]
    assert not checks["Create hardware"]["ok"] and "models not found" in checks["Create hardware"]["detail"]
    assert result["detail"].startswith("Addresses: None of the first 1 assets has the custom field")


# -- options -----------------------------------------------------------------------------------


def test_options_for_models_status_labels_and_address_fields():
    conn = connector(FakeSnipe())
    assert run(conn.options("model_id")) == [{"value": "5", "label": "Latitude 7440 - Dell - 7440"}]
    assert run(conn.options("status_id")) == [{"value": "2", "label": "Ready to Deploy (deployable)"},
                                              {"value": "3", "label": "Broken & Out (undeployable)"}]
    assert run(conn.options("address_field")) == [{"value": "_snipeit_ip_address_2", "label": "IP Address (IP)"},
                                                  {"value": "_snipeit_purchase_order_1", "label": "Purchase order (ANY)"}]
    with pytest.raises(ConnectorError, match="no choices"):
        run(conn.options("asset_tags"))


# -- writing hardware --------------------------------------------------------------------------


def test_push_creates_updates_recreates_and_reports_rejections_verbatim():
    fake = FakeSnipe([hardware(7, asset_tag="T007")])
    conn = connector(fake, model_id=5, status_id=2, address_field="IP Address")  # chosen by name: looked up
    records = [
        {"hub_id": "a_1", "name": "web-1", "addresses": ["web-1.example.com", "10.0.0.5"], "facts": {"serial": "SN-1"}},
        {"hub_id": "a_2", "name": "db-1", "addresses": ["10.0.0.7"], "facts": {}},
        {"hub_id": "a_3", "name": "old-1", "addresses": [], "facts": {}},
        {"hub_id": "a_4", "name": "odd", "addresses": [], "facts": {"asset_tag": "BAD TAG"}},
    ]
    results = run(conn.push("assets", records, {"a_2": "7", "a_3": "999"}))
    assert [(r["hub_id"], r["action"], r["external_id"]) for r in results] == [
        ("a_1", "created", "100"), ("a_2", "updated", "7"), ("a_3", "created", "101"), ("a_4", "failed", None)]
    assert results[3]["error"] == "Snipe-IT could not create hardware: asset_tag: The asset tag format is invalid."
    created = fake.hits("POST", "/hardware")
    assert created[0][3] == {"name": "web-1", "serial": "SN-1", "_snipeit_ip_address_2": "10.0.0.5", "model_id": 5,
                             "status_id": 2, "asset_tag": "a_1", "notes": "Created by Atrium from hub asset a_1"}
    assert fake.hits("PATCH", "/hardware/7")[0][3] == {"name": "db-1", "_snipeit_ip_address_2": "10.0.0.7"}
    assert fake.hits("PATCH", "/hardware/999") and created[1][3]["asset_tag"] == "a_3"  # deleted in Snipe-IT: re-created
    assert fake.rows[7]["name"] == "db-1" and fake.rows[100]["serial"] == "SN-1"


def test_push_finds_hardware_it_created_before_instead_of_duplicating():
    fake = FakeSnipe([hardware(42, asset_tag="a_1")])
    results = run(connector(fake, model_id=5, status_id=2).push("assets", [{"hub_id": "a_1", "name": "web-1"}], {}))
    assert results == [{"hub_id": "a_1", "external_id": "42", "action": "updated", "error": None}]
    assert not fake.hits("POST", "/hardware") and fake.rows[42]["name"] == "web-1"


def test_push_without_create_settings_still_updates_and_auto_tags_are_left_to_snipe_it():
    fake = FakeSnipe([hardware(7)])
    results = run(connector(fake).push("assets", [{"hub_id": "a_1", "name": "new"}, {"hub_id": "a_2", "name": "known"}],
                                       {"a_2": "7"}))
    assert [r["action"] for r in results] == ["failed", "updated"] and "Choose a model and a status label" in results[0]["error"]
    fake = FakeSnipe()
    results = run(connector(fake, model_id=5, status_id=2, asset_tags="auto").push("assets", [{"hub_id": "a_1", "name": "x"}], {}))
    assert results[0]["action"] == "failed" and "The asset tag field is required." in results[0]["error"]
    assert "asset_tag" not in fake.hits("POST", "/hardware")[0][3] and not fake.hits("GET", "/hardware/bytag/a_1")


def test_push_stops_when_the_token_is_rejected_without_leaking_it():
    with pytest.raises(ConnectorError) as info:
        run(connector(FakeSnipe(), token="leaky-token-987654", model_id=5, status_id=2)
            .push("assets", [{"hub_id": "a_1", "name": "x"}], {}))
    assert info.value.status == 401
    assert "leaky-token-987654" not in info.value.message + (info.value.excerpt or "")


def test_hardware_flows_into_hub_assets_through_the_agents(client, wait_for):
    """Connection, test, the planned pull flow and its run - through the API, the tool supervisor and the Asset
    Supervisor, with only the HTTP faked."""
    hub = client.app.state.hub
    jane = {"id": 9, "username": "jdoe", "name": "Jane Doe", "email": "jane@example.com", "type": "user"}
    fake = FakeSnipe([hardware(1, name="web-1", custom_fields=ip_field("10.0.0.5")),
                      hardware(2, name="laptop-7", category={"id": 3, "name": "Laptops"}, assigned_to=jane)])
    hub.connector_transport = httpx.MockTransport(fake)
    known = client.post("/api/assets", json={"name": "Web server", "type": "server", "facts": {"addresses": ["10.0.0.5"]}}).json()
    tool = Tool(id="snipe-it", name="Snipe-IT", source_type="saas", source=BASE, status="ready",
                manifest=Manifest(id="snipe-it", name="Snipe-IT", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)

    saved = client.put("/api/tools/snipe-it/connection", json={
        "kind": "snipeit", "config": {"base_url": f"{BASE}/api/v1"}, "secrets": {"token": TOKEN}})
    assert saved.status_code == 200, saved.text
    assert saved.json()["detected"][0]["kind"] == "snipeit" and saved.json()["config"]["base_url"] == BASE
    tested = client.post("/api/tools/snipe-it/connection/test").json()
    assert tested["ok"] and tested["domains"] == {"assets": ["read"]}, tested
    options = client.get("/api/tools/snipe-it/connection/options/model_id").json()
    assert options == {"options": [{"value": "5", "label": "Latitude 7440 - Dell - 7440"}]}

    [approval] = wait_for(lambda: [a for a in client.get("/api/approvals?status=pending").json()
                                   if a["kind"] == "flow" and a["payload"]["tool_id"] == "snipe-it"])
    assert approval["payload"]["source"] == "tool:snipe-it" and approval["payload"]["target"] == "hub"
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    [flow] = wait_for(lambda: [f for f in client.get("/api/flows?tool_id=snipe-it").json() if f["status"] == "enabled"])
    result = client.post(f"/api/flows/{flow['id']}/run").json()
    assert result["ok"] and (result["counts"]["created"], result["counts"]["merged"]) == (1, 1), result

    assets = {a["id"]: a for a in client.get("/api/assets").json()}
    merged = assets[known["id"]]  # the same machine, known by its address: merged, not duplicated
    assert merged["name"] == "Web server" and merged["facts"]["external_ids"] == {"snipe-it": "1"}
    assert merged["facts"]["asset_tag"] == "T001" and merged["facts"]["serial"] == "SN1"
    laptop = next(a for a in assets.values() if a["source"] == "sync:snipe-it")
    assert (laptop["name"], laptop["type"], laptop["owner"]) == ("laptop-7", "workstation", "Jane Doe")
    assert (laptop["facts"]["assigned_username"], laptop["facts"]["assigned_email"]) == ("jdoe", "jane@example.com")
    for path in ("/api/assets", "/api/flows", "/api/messages?limit=2000", "/api/activity?limit=2000",
                 "/api/tools/snipe-it/connection"):
        assert TOKEN not in client.get(path).text


def test_push_refuses_a_stored_id_that_is_not_a_number():
    fake = FakeSnipe()
    results = run(connector(fake).push("assets", [{"hub_id": "a_1", "name": "x"}], {"a_1": "../users/1"}))
    assert results[0]["action"] == "failed" and "not a Snipe-IT asset id" in results[0]["error"] and not fake.calls
