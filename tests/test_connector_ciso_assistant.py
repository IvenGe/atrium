"""The CISO Assistant connector against an in-memory fake of its REST API (httpx.MockTransport, no network)."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from pathlib import Path

import httpx
import pytest

from hub import connectors
from hub.connectors import ciso_assistant
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.ciso_assistant import CisoAssistantConnector, rescale
from hub.grc.baseline import CONTROLS
from hub.models import Manifest, Tool

TOKEN = "ca-token-5f4e3d2c1b0a99887766"
GLOBAL, DOMAIN, ENCLAVE = (str(uuid.uuid4()) for _ in range(3))
TYPE_LABELS = {"PR": "Primary", "SP": "Support"}
SEVERITY_LABELS = {-1: "undefined", 0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
CONTROL_STATES = (None, "to_do", "in_progress", "on_hold", "active", "deprecated", "degraded", "--")


def run(coro):
    return asyncio.run(coro)


class FakeCiso:
    """Enough of CISO Assistant's REST API: Knox token auth, limit/offset lists with relative next links, folder
    filters, {"id", "str"} relations, label rendering on read and per-folder unique names."""

    UNIQUE = {"assets": ("name",), "evidences": ("name",), "applied-controls": ("ref_id", "name"),
              "vulnerabilities": ("ref_id", "name")}

    def __init__(self, *, vulnerabilities: bool = True, plain_lists: bool = False):
        self.vulnerabilities = vulnerabilities
        self.plain_lists = plain_lists
        self.data: dict[str, dict[str, dict]] = {name: {} for name in (
            "folders", "assets", "applied-controls", "evidences", "risk-scenarios", "risk-matrices", "risk-assessments",
            "vulnerabilities")}
        for fid, name, kind in ((GLOBAL, "Global", "GL"), (DOMAIN, "IT", "DO"), (ENCLAVE, "Vendor X", "EN")):
            self.data["folders"][fid] = {"id": fid, "name": name, "content_type": kind}
        self.requests: list[httpx.Request] = []

    def add(self, collection: str, **fields) -> dict:
        item = {"id": str(uuid.uuid4()), "folder": GLOBAL, **fields}
        self.data[collection][item["id"]] = item
        return item

    def of(self, collection: str, **match) -> list[dict]:
        return [i for i in self.data[collection].values() if all(i.get(k) == v for k, v in match.items())]

    def _str(self, collection: str, object_id: str) -> dict:
        item = self.data[collection].get(object_id) or {}
        return {"id": object_id, "str": item.get("name", "?")}

    def read(self, collection: str, item: dict) -> dict:
        out = dict(item)
        if collection == "folders":
            out["content_type"] = {"GL": "GLOBAL", "DO": "DOMAIN", "EN": "ENCLAVE"}.get(item["content_type"], item["content_type"])
            return out
        out["folder"] = self._str("folders", item["folder"])
        if collection == "assets":
            out["type"] = TYPE_LABELS[item.get("type", "SP")]
        if collection == "vulnerabilities":
            out["severity"] = SEVERITY_LABELS[item.get("severity", -1)]
            out["assets"] = [self._str("assets", a) for a in item.get("assets", [])]
        if collection == "evidences":
            out["applied_controls"] = [self._str("applied-controls", a) for a in item.get("applied_controls", [])]
        return out

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.headers.get("authorization") != f"Token {TOKEN}":
            return httpx.Response(401, json={"detail": "Invalid token."})
        if not request.url.path.startswith("/api/"):
            return httpx.Response(404, text="<html>Not found</html>")
        parts = request.url.path[len("/api/"):].strip("/").split("/")
        if parts == ["iam", "current-user"]:
            return httpx.Response(200, json={"id": "u1", "email": "hub-bot@example.com", "first_name": "Hub"})
        if parts == ["build"]:
            return httpx.Response(200, json={"version": "v3.2.0", "build": "abc123"})
        collection = parts[0]
        if collection not in self.data or (collection == "vulnerabilities" and not self.vulnerabilities):
            return httpx.Response(404, json={"detail": "Not found."})
        if len(parts) == 1:
            if request.method == "GET":
                return self.list(collection, request.url.params)
            if request.method == "POST":
                return self.create(collection, json.loads(request.content))
            return httpx.Response(405)
        item = self.data[collection].get(parts[1])
        if item is None:
            return httpx.Response(404, json={"detail": "No object matches the given query."})
        if request.method == "GET":
            return httpx.Response(200, json=self.read(collection, item))
        if request.method == "PATCH":
            body = json.loads(request.content)
            error = self.invalid(collection, {**item, **body}, item["id"])
            if error:
                return error
            item.update(body)
            return httpx.Response(200, json=self.read(collection, item))
        return httpx.Response(405)

    def invalid(self, collection: str, values: dict, own_id: str | None = None) -> httpx.Response | None:
        if not values.get("name"):
            return httpx.Response(400, json={"name": ["This field is required."]})
        if values["folder"] not in self.data["folders"]:
            return httpx.Response(400, json={"folder": [f'Invalid pk "{values["folder"]}" - object does not exist.']})
        if collection == "applied-controls" and values.get("status") not in CONTROL_STATES:
            return httpx.Response(400, json={"status": [f'"{values["status"]}" is not a valid choice.']})
        if collection == "vulnerabilities" and values.get("severity", -1) not in SEVERITY_LABELS:
            return httpx.Response(400, json={"severity": ["not a valid choice."]})
        fields = self.UNIQUE.get(collection, ())
        for other in self.data[collection].values():
            if other["id"] != own_id and other["folder"] == values["folder"] and fields \
                    and all(str(other.get(f, "")).lower() == str(values.get(f, "")).lower() for f in fields):
                return httpx.Response(400, json={"name": [f"{values['name']} is already used in this scope. "
                                                          "Please choose another value."]})
        return None

    def create(self, collection: str, body: dict) -> httpx.Response:
        body.setdefault("folder", GLOBAL)
        error = self.invalid(collection, body)
        if error:
            return error
        item = {"id": str(uuid.uuid4()), **body}
        if collection == "assets":
            item.setdefault("type", "SP")
        self.data[collection][item["id"]] = item
        return httpx.Response(201, json=self.read(collection, item))

    def list(self, collection: str, params: httpx.QueryParams) -> httpx.Response:
        folder = params.get("folder")
        items = [self.read(collection, i) for i in self.data[collection].values()
                 if collection == "folders" or not folder or i["folder"] == folder]
        if self.plain_lists:
            return httpx.Response(200, json=items)
        limit, offset = int(params.get("limit", 5000)), int(params.get("offset", 0))
        more = offset + limit < len(items)
        return httpx.Response(200, json={"count": len(items), "previous": None, "results": items[offset:offset + limit],
                                         "next": f"/api/{collection}/?limit={limit}&offset={offset + limit}" if more else None})

    def lists(self, collection: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.method == "GET" and r.url.path == f"/api/{collection}/"]


def make(fake: FakeCiso | None = None, *, base_url: str = "https://ciso.example.com", folder: str | None = DOMAIN,
         token: str = TOKEN, transport: httpx.AsyncBaseTransport | None = None) -> CisoAssistantConnector:
    config = CisoAssistantConnector.validate_config({"base_url": base_url, "folder_id": folder})
    return CisoAssistantConnector(config, {"token": token}, transport or httpx.MockTransport(fake.handler))


# -- settings, detection --------------------------------------------------------------------------


def test_settings_api_root_and_detection():
    with_api = CisoAssistantConnector.validate_config({"base_url": "https://ciso.example.com/api/", "folder_id": DOMAIN.upper()})
    assert with_api["base_url"] == "https://ciso.example.com/api" and with_api["folder_id"] == DOMAIN
    assert CisoAssistantConnector(with_api, {}).api == "https://ciso.example.com/api"
    assert CisoAssistantConnector({"base_url": "https://ciso.example.com/grc"}, {}).api == "https://ciso.example.com/grc/api"
    # with or without /api it is the same endpoint: the stored token stays usable
    assert CisoAssistantConnector.endpoint(with_api) == CisoAssistantConnector.endpoint({"base_url": "https://ciso.example.com"})
    for bad in ({"base_url": "ftp://ciso"}, {"base_url": "https://u:p@ciso.example.com"},
                {"base_url": "https://ciso.example.com?x=1"}, {"base_url": "https://ciso.example.com", "folder_id": "../x"}):
        with pytest.raises(ConnectorError):
            CisoAssistantConnector.validate_config(bad)
    assert "folder_id" not in CisoAssistantConnector.validate_config({"base_url": "https://c.example.com", "folder_id": ""})

    named = Tool(id="ciso-assistant", name="CISO Assistant", source_type="local", source="/x",
                 manifest=Manifest(id="ciso-assistant", name="CISO Assistant"))
    grc = Tool(id="grc", name="GRC", source_type="local", source="/x", manifest=Manifest(id="grc", name="GRC", provides=["grc.risks"]))
    assert CisoAssistantConnector.detect(named) == 90 and CisoAssistantConnector.detect(grc) == 30
    assert connectors.detect(named)[0]["kind"] == "ciso_assistant"
    entry = next(c for c in connectors.catalog() if c["kind"] == "ciso_assistant")
    assert "error" not in entry and entry["capabilities"] == {"assets": ["read", "write"], "controls": ["write"],
                                                               "risks": ["read"], "vulnerabilities": ["write"],
                                                               "frameworks": ["read"], "assessments": ["write"]}
    assert next(f for f in entry["fields"] if f["name"] == "folder_id")["options"] is True


def test_rescale_matrix_levels():
    assert [rescale(i, 5) for i in range(5)] == [1, 2, 3, 4, 5]
    assert [rescale(i, 4) for i in range(4)] == [1, 2, 4, 5]
    assert [rescale(i, 3) for i in range(3)] == [1, 3, 5]
    assert rescale(None, 5) is None and rescale(2, None) == 3 and rescale(9, None) == 5 and rescale(0, 1) == 3


# -- test() -----------------------------------------------------------------------------------------


@pytest.mark.parametrize("base_url", ["https://ciso.example.com", "https://ciso.example.com/api/"])
def test_test_reports_what_the_instance_supports(base_url):
    fake = FakeCiso()
    fake.add("assets", name="web-1", folder=DOMAIN)
    fake.add("assets", name="elsewhere")
    result = run(make(fake, base_url=base_url).test())
    assert result["ok"], result
    assert result["domains"] == {"assets": ["read", "write"], "controls": ["write"], "risks": ["read"],
                                 "vulnerabilities": ["write"]}
    checks = {c["name"]: c for c in result["checks"]}
    assert "v3.2.0" in checks["API"]["detail"] and "hub-bot@example.com" in checks["API token"]["detail"]
    assert "'IT'" in checks["Folder"]["detail"] and checks["Assets"]["detail"].startswith("1 in the folder")
    assert {"Applied controls", "Evidence", "Risk scenarios", "Vulnerabilities"} <= set(checks)
    assert all(r.url.path.startswith("/api/") and not r.url.path.startswith("/api/api") for r in fake.requests)
    assert all(r.headers["authorization"] == f"Token {TOKEN}" for r in fake.requests)
    assert result["detail"].startswith("Connected as hub-bot@example.com")


def test_test_without_vulnerabilities_module_narrows_the_domains():
    result = run(make(FakeCiso(vulnerabilities=False), folder=None).test())
    assert result["ok"] and "vulnerabilities" not in result["domains"] and set(result["domains"]) == {"assets", "controls", "risks"}
    checks = {c["name"]: c for c in result["checks"]}
    assert checks["Vulnerabilities"]["ok"] and "Not available" in checks["Vulnerabilities"]["detail"]
    assert "Global folder" in checks["Folder"]["detail"] and "not on this instance: vulnerabilities" in result["detail"]


def test_test_explains_what_is_wrong():
    fake = FakeCiso()
    wrong = "wrong-token-0a1b2c3d4e"
    rejected = run(make(fake, token=wrong).test())
    assert not rejected["ok"] and rejected["domains"] == {}
    assert [(c["name"], c["ok"]) for c in rejected["checks"]] == [("API", True), ("API token", False)]
    assert "rejected the API token" in rejected["detail"] and wrong not in json.dumps(rejected)

    page = httpx.MockTransport(lambda r: httpx.Response(200, text="<!doctype html><html>CISO Assistant</html>"))
    web = run(make(transport=page).test())
    assert not web["ok"] and "No CISO Assistant API at https://ciso.example.com/api" in web["detail"]

    def down(request):
        raise httpx.ConnectError("connection refused", request=request)

    unreachable = run(make(transport=httpx.MockTransport(down)).test())
    assert not unreachable["ok"] and "Cannot reach CISO Assistant" in unreachable["detail"]

    gone = str(uuid.uuid4())
    missing_folder = run(make(fake, folder=gone).test())
    folder_check = next(c for c in missing_folder["checks"] if c["name"] == "Folder")
    assert not missing_folder["ok"] and not folder_check["ok"] and "does not exist any more" in folder_check["detail"]
    assert all(r.url.params.get("folder") != gone for r in fake.requests if r.method == "GET")  # probes ran unfiltered
    enclave = run(make(fake, folder=ENCLAVE).test())
    assert not enclave["ok"] and "enclave" in next(c for c in enclave["checks"] if c["name"] == "Folder")["detail"]


def test_folder_choices_skip_enclaves_and_follow_pages(monkeypatch):
    monkeypatch.setattr(ciso_assistant, "PAGE", 1)
    fake = FakeCiso()
    archive = str(uuid.uuid4())
    fake.data["folders"][archive] = {"id": archive, "name": "Archive", "content_type": "DO"}
    options = run(make(fake, folder=None).options("folder_id"))
    assert options == [{"value": GLOBAL, "label": "Global (global)"}, {"value": archive, "label": "Archive (domain)"},
                       {"value": DOMAIN, "label": "IT (domain)"}]
    assert [r.url.params["offset"] for r in fake.lists("folders")] == ["0", "1", "2", "3"]
    with pytest.raises(ConnectorError):
        run(make(fake).options("base_url"))


# -- reading ----------------------------------------------------------------------------------------


def test_pull_assets_reads_the_folder_page_by_page(monkeypatch):
    monkeypatch.setattr(ciso_assistant, "PAGE", 2)
    fake = FakeCiso()
    fake.add("assets", name="web-1", folder=DOMAIN, type="SP", ref_id="A-1",
             description="Front end.\nAddresses: 10.0.0.5, web-1.corp", asset_class={"id": "c1", "str": "Physical server"},
             owner=[{"id": "o1", "str": "Alice"}], updated_at="2026-10-01T10:00:00Z")
    fake.add("assets", name="Online sales", folder=DOMAIN, type="PR", description="Business process")
    fake.add("assets", name="laptop-7", folder=DOMAIN, asset_class={"id": "c2", "str": "Laptop"})
    fake.add("assets", name="in another folder")
    records, errors = normalize("assets", run(make(fake).pull("assets")))
    assert errors == [] and len(records) == 3 and len(fake.lists("assets")) == 2
    web = next(r for r in records if r["name"] == "web-1")
    assert (web["type"], web["owner"], web["addresses"]) == ("server", "Alice", ["10.0.0.5", "web-1.corp"])
    assert web["facts"] == {"ciso_assistant_type": "supporting", "ref_id": "A-1", "folder": "IT", "asset_class": "Physical server"}
    assert web["updated_at"] > 0
    sales = next(r for r in records if r["name"] == "Online sales")
    assert sales["type"] == "other" and sales["facts"]["ciso_assistant_type"] == "primary" and sales["addresses"] == []
    assert next(r for r in records if r["name"] == "laptop-7")["type"] == "workstation"
    assert len(run(make(fake, folder=None).pull("assets"))) == 4
    assert len(run(make(FakeCiso(plain_lists=True), folder=None).pull("assets"))) == 0
    with pytest.raises(ConnectorError):
        run(make(fake).pull("vulnerabilities"))


def test_pull_risks_rescales_each_matrix_and_maps_treatments():
    fake = FakeCiso(plain_lists=True)  # some versions answer plain lists
    four = fake.add("risk-matrices", name="4x4", json_definition={"probability": [{}] * 4, "impact": [{}] * 4})
    five = fake.add("risk-matrices", name="5x5", json_definition=json.dumps({"probability": [{}] * 5, "impact": [{}] * 5}))
    assessment = fake.add("risk-assessments", name="2026 review", risk_matrix={"id": four["id"], "str": "4x4"})
    fake.add("risk-scenarios", folder=DOMAIN, name="Ransomware", ref_id="R.1", risk_matrix=four["id"], treatment="mitigate",
             current_proba={"value": 3, "name": "Very likely"}, current_impact={"value": 1, "name": "Minor"},
             current_level={"value": 2, "name": "High"}, risk_assessment={"id": assessment["id"], "str": "2026 review"},
             applied_controls=[{"id": "c", "str": "Backups"}], description="Files encrypted")
    fake.add("risk-scenarios", folder=DOMAIN, name="Supplier outage", treatment="accept",
             risk_assessment={"id": assessment["id"], "str": "2026 review"},  # older versions: no risk_matrix id
             current_proba={"value": -1}, current_impact={"value": -1}, inherent_proba=2, inherent_impact=0)
    fake.add("risk-scenarios", folder=DOMAIN, name="Old app", risk_matrix=five["id"], treatment="cancelled",
             current_proba={"value": 4}, current_impact=4)
    fake.add("risk-scenarios", folder=DOMAIN, name="Unrated", risk_matrix=str(uuid.uuid4()), treatment="open",
             current_proba={"value": 2}, current_impact={"value": -1})
    records, errors = normalize("risks", run(make(fake).pull("risks")))
    assert errors == []
    risks = {r["title"]: r for r in records}
    ransomware = risks["R.1 Ransomware"]
    assert (ransomware["likelihood"], ransomware["impact"], ransomware["status"], ransomware["treatment"]) == (5, 2, "in_treatment", "mitigate")
    assert "Files encrypted" in ransomware["description"] and "2026 review" in ransomware["description"]
    assert "Current level: High" in ransomware["description"] and "Applied controls: Backups" in ransomware["description"]
    assert (risks["Supplier outage"]["likelihood"], risks["Supplier outage"]["impact"]) == (4, 1)
    assert (risks["Supplier outage"]["status"], risks["Supplier outage"]["treatment"]) == ("in_treatment", "accept")
    assert (risks["Old app"]["likelihood"], risks["Old app"]["impact"], risks["Old app"]["status"]) == (5, 5, "closed")
    assert risks["Old app"]["treatment"] is None
    # an unreadable matrix counts as five levels; an unrated impact keeps the hub's default
    assert (risks["Unrated"]["likelihood"], risks["Unrated"]["impact"], risks["Unrated"]["status"]) == (3, 3, "open")


# -- writing ----------------------------------------------------------------------------------------


def asset(hub_id: str, name: str, **extra) -> dict:
    return {"hub_id": hub_id, "external_id": None, "name": name, "type": "server", "owner": "ops", "status": "active",
            "addresses": ["10.0.0.5"], "facts": {"serial": "S1"}, "criticality": "high", **extra}


def test_push_assets_creates_updates_adopts_and_recreates():
    fake = FakeCiso()
    existing = fake.add("assets", name="db-1", folder=DOMAIN, type="PR", description="Kept by a person")
    connector = make(fake)
    first = run(connector.push("assets", [asset("a1", "web-1"), asset("a2", "DB-1", addresses=["10.0.0.9"])], {}))
    assert [(r["hub_id"], r["action"], r["error"]) for r in first] == [("a1", "created", None), ("a2", "updated", None)]
    assert first[1]["external_id"] == existing["id"] and len(fake.data["assets"]) == 2  # adopted, not duplicated
    web = fake.data["assets"][first[0]["external_id"]]
    assert (web["type"], web["folder"], web["name"]) == ("SP", DOMAIN, "web-1")
    assert web["description"].startswith(ciso_assistant.MARKER) and "Addresses: 10.0.0.5" in web["description"]
    assert "Criticality: high" in web["description"] and "- serial: S1" in web["description"]
    adopted = fake.data["assets"][existing["id"]]
    assert adopted["type"] == "PR"  # an update never changes the asset's type
    assert adopted["description"].startswith("Kept by a person\n\n" + ciso_assistant.MARKER)  # the person's text stays
    assert "Addresses: 10.0.0.9" in adopted["description"]

    links = {r["hub_id"]: r["external_id"] for r in first}
    web["description"] = "Racked in DC-2.\n\n" + web["description"]  # a person adds a note above the marker
    again = run(make(fake).push("assets", [asset("a1", "web-1", owner="dba")], links))
    assert again[0]["action"] == "updated" and "Owner: dba" in web["description"] and "Owner: ops" not in web["description"]
    assert web["description"].startswith("Racked in DC-2.") and web["description"].count(ciso_assistant.MARKER) == 1

    del fake.data["assets"][links["a1"]]  # deleted in CISO Assistant: created again
    recreated = run(make(fake).push("assets", [asset("a1", "web-1")], links))[0]
    assert recreated["action"] == "created" and recreated["external_id"] != links["a1"]

    # a second hub asset with a taken name may not take over the linked one: CISO Assistant's message, verbatim
    twin = run(make(fake).push("assets", [asset("a3", "db-1")], links))[0]
    assert twin["action"] == "failed" and "db-1 is already used in this scope. Please choose another value." in twin["error"]

    # what the hub wrote comes back on a read
    back, _ = normalize("assets", run(make(fake).pull("assets")))
    pulled = next(r for r in back if r["name"] == "web-1")
    assert pulled["addresses"] == ["10.0.0.5"] and pulled["type"] == "server"

    # without a chosen folder, objects go to the root folder - named explicitly, found even by its parentless-ness
    fake.data["folders"][GLOBAL]["content_type"] = "XX"
    fake.data["folders"][GLOBAL]["parent_folder"] = None
    fake.data["folders"][DOMAIN]["parent_folder"] = GLOBAL
    created = run(make(fake, folder=None).push("assets", [asset("a9", "mail-1")], {}))[0]
    assert created["action"] == "created" and fake.data["assets"][created["external_id"]]["folder"] == GLOBAL
    posted = [json.loads(r.content) for r in fake.requests if r.method == "POST" and r.url.path == "/api/assets/"]
    assert posted[-1]["folder"] == GLOBAL and posted[-1]["type"] == "SP"


def control(ref: str, status: str = "pass", **extra) -> dict:
    return {"hub_id": ref, "external_id": ref, "ref_id": ref, "name": f"Control {ref}", "description": f"What {ref} checks",
            "status": status, "evidence": [f"{ref}: 3 of 3 assets scanned", "Scanner: OpenVAS"],
            "refs": {"ISO27001": "A.8.8", "SOC2": "CC7.1"}, "family": "Vulnerability management",
            "detail": "3 of 3 assets scanned", "evaluated_at": time.time(), **extra}


def test_push_controls_writes_applied_controls_with_their_evidence():
    fake = FakeCiso()
    by_person = fake.add("applied-controls", folder=DOMAIN, name="Patch management", ref_id="HB-VM-3", status="active",
                         description="Owned by the infra team.")
    first = run(make(fake).push("controls", [control("HB-VM-2"), control("HB-AC-9", "manual"), control("HB-VM-3", "fail")], {}))
    assert [r["action"] for r in first] == ["created", "created", "updated"]
    applied_id, evidence_id = first[0]["external_id"].split("|")
    applied, evidence = fake.data["applied-controls"][applied_id], fake.data["evidences"][evidence_id]
    assert (applied["ref_id"], applied["name"], applied["status"], applied["folder"]) == ("HB-VM-2", "Control HB-VM-2", "active", DOMAIN)
    assert "Atrium check: pass - 3 of 3 assets scanned" in applied["description"] and "ISO27001 A.8.8" in applied["description"]
    assert evidence["applied_controls"] == [applied_id] and evidence["folder"] == DOMAIN
    assert evidence["name"] == "HB-VM-2 automated evidence (Atrium)" and "- HB-VM-2: 3 of 3 assets scanned" in evidence["description"]
    assert fake.data["applied-controls"][first[1]["external_id"].split("|")[0]]["status"] == "--"
    # the person's applied control with the same ref_id is adopted and gets the hub's evidence
    assert first[2]["external_id"].split("|")[0] == by_person["id"] and by_person["status"] == "to_do"
    assert by_person["description"].startswith("Owned by the infra team.") and "Atrium check: fail" in by_person["description"]
    assert len(fake.data["applied-controls"]) == 3 and len(fake.data["evidences"]) == 3

    links = {r["hub_id"]: r["external_id"] for r in first}
    second = run(make(fake).push("controls", [control("HB-VM-2", "partial", detail="2 of 3 assets scanned")], links))
    assert second[0] == {"hub_id": "HB-VM-2", "external_id": links["HB-VM-2"], "action": "updated", "error": None}
    assert applied["status"] == "in_progress" and "Result: partial" in evidence["description"]
    assert len(fake.data["applied-controls"]) == 3 and len(fake.data["evidences"]) == 3

    del fake.data["evidences"][evidence_id]  # a person deleted the evidence: it is written again
    third = run(make(fake).push("controls", [control("HB-VM-2")], links))[0]
    new_evidence = third["external_id"].split("|")[1]
    assert third["action"] == "updated" and new_evidence != evidence_id
    assert fake.data["evidences"][new_evidence]["applied_controls"] == [applied_id]


def finding(hub_id: str, host: str, **extra) -> dict:
    return {"hub_id": hub_id, "external_id": None, "title": "TLS certificate expired", "severity": "critical", "cvss": 9.1,
            "cves": ["CVE-2024-1234"], "host": host, "port": "443/tcp", "description": "The certificate expired.",
            "solution": "Renew it", "detected_at": 1_790_000_000, "scanner": "OpenVAS", "status": "open",
            "asset": "web-1", "due_at": 1_790_600_000, "first_seen": 1_790_000_000, **extra}


def test_push_vulnerabilities_maps_severity_status_and_assets():
    fake = FakeCiso()
    web = fake.add("assets", folder=DOMAIN, name="web-1")
    results = run(make(fake).push("vulnerabilities", [
        finding("v1", "10.0.0.5"),
        finding("v2", "10.0.0.6", severity="info", status="false_positive", asset=None, cves=[]),
    ], {}))
    assert [r["action"] for r in results] == ["created", "created"]
    first, second = (fake.data["vulnerabilities"][r["external_id"]] for r in results)
    assert (first["name"], first["severity"], first["status"], first["ref_id"]) == (
        "TLS certificate expired on 10.0.0.5:443/tcp", 4, "potential", "CVE-2024-1234")
    assert first["assets"] == [web["id"]] and first["folder"] == DOMAIN and first["detected_at"] == "2026-09-21"
    assert "Solution: Renew it" in first["description"] and "Atrium status: open · due 2026-09-28" in first["description"]
    assert (second["severity"], second["status"], second["ref_id"]) == (0, "unaffected", "")
    assert "assets" not in second

    links = {r["hub_id"]: r["external_id"] for r in results}
    fixed = run(make(fake).push("vulnerabilities", [finding("v1", "10.0.0.5", status="fixed")], links))[0]
    assert fixed["action"] == "updated" and first["status"] == "fixed" and first["assets"] == [web["id"]]

    with pytest.raises(ConnectorError) as missing:  # no vulnerabilities module: the whole push fails once, clearly
        run(make(FakeCiso(vulnerabilities=False)).push("vulnerabilities", [finding("v1", "10.0.0.5")], {}))
    assert missing.value.status == 404 and "no vulnerabilities endpoint" in missing.value.message


def test_rejections_fail_one_record_and_bad_tokens_fail_the_push():
    fake = FakeCiso()
    gone = str(uuid.uuid4())
    results = run(make(fake, folder=gone).push("assets", [asset("a1", "web-1")], {}))
    assert results[0]["action"] == "failed" and f'folder: Invalid pk "{gone}" - object does not exist.' in results[0]["error"]
    wrong = "wrong-token-0a1b2c3d4e"
    with pytest.raises(ConnectorError) as denied:
        run(make(fake, token=wrong).push("controls", [control("HB-VM-2")], {}))
    assert denied.value.status == 401 and wrong not in denied.value.message + str(denied.value.excerpt)
    with pytest.raises(ConnectorError):
        run(make(fake).push("risks", [], {}))


# -- through the hub -------------------------------------------------------------------------------


def test_the_hub_plans_and_runs_flows_through_ciso_assistant(client, wait_for):
    hub = client.app.state.hub
    fake = FakeCiso()
    hub.connector_transport = httpx.MockTransport(fake.handler)
    tool = Tool(id="ciso", name="CISO Assistant", source_type="saas", source="https://ciso.example.com", status="ready",
                manifest=Manifest(id="ciso", name="CISO Assistant", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    view = client.get("/api/tools/ciso/connection").json()
    assert view["detected"][0]["kind"] == "ciso_assistant"
    assert client.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": TOKEN},
                                                         "config": {"base_url": "https://ciso.example.com/api"}}).status_code == 200
    choices = client.get("/api/tools/ciso/connection/options/folder_id").json()["options"]
    assert [c["label"] for c in choices] == ["Global (global)", "IT (domain)"]
    saved = client.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": ""},
                                                           "config": {"base_url": "https://ciso.example.com", "folder_id": DOMAIN}})
    assert saved.status_code == 200 and saved.json()["secrets"] == {"token": True}  # same endpoint: token kept

    tested = client.post("/api/tools/ciso/connection/test").json()
    assert tested["ok"] and set(tested["domains"]) == {"assets", "controls", "risks", "vulnerabilities"}
    pending = wait_for(lambda: len(a := [x for x in client.get("/api/approvals?status=pending").json()
                                         if x["kind"] == "flow" and x["payload"]["tool_id"] == "ciso"]) == 4 and a)
    for approval in pending:
        assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    planned = wait_for(lambda: len(found := {(f["domain"], f["direction"]): f for f in client.get("/api/flows?tool_id=ciso").json()
                                             if f["status"] == "enabled"}) == 4 and found)
    assert set(planned) == {("assets", "push"), ("controls", "push"), ("risks", "pull"), ("vulnerabilities", "push")}

    controls = client.post(f"/api/flows/{planned[('controls', 'push')]['id']}/run").json()
    assert controls["ok"] and controls["counts"]["created"] == len(CONTROLS), controls
    assert len(fake.of("applied-controls", folder=DOMAIN)) == len(CONTROLS) == len(fake.of("evidences", folder=DOMAIN))
    assert {c["ref_id"] for c in fake.data["applied-controls"].values()} == {c.id for c in CONTROLS}
    again = client.post(f"/api/flows/{planned[('controls', 'push')]['id']}/run").json()
    assert again["ok"] and again["counts"]["created"] == 0 and again["counts"]["skipped"] > 0  # unchanged: not sent again
    assert len(fake.data["applied-controls"]) == len(CONTROLS) == len(fake.data["evidences"])

    client.post("/api/assets", json={"name": "web-1", "type": "server", "facts": {"addresses": ["10.0.0.5"]}})
    assets = client.post(f"/api/flows/{planned[('assets', 'push')]['id']}/run").json()
    assert assets["ok"] and assets["counts"]["failed"] == 0 and fake.of("assets", name="web-1")

    fake.add("risk-scenarios", folder=DOMAIN, name="Ransomware", treatment="mitigate", current_proba={"value": 3},
             current_impact={"value": 4})
    risks = client.post(f"/api/flows/{planned[('risks', 'pull')]['id']}/run").json()
    assert risks["ok"] and risks["counts"]["created"] == 1
    risk = next(r for r in client.get("/api/grc/risks").json() if r["source"] == "sync:ciso")
    assert (risk["title"], risk["likelihood"], risk["impact"], risk["status"]) == ("Ransomware", 4, 5, "in_treatment")

    assert TOKEN.encode() not in Path(hub.settings.db_path).read_bytes()
    for path in ("/api/tools/ciso/connection", "/api/flows", "/api/activity?limit=2000", "/api/messages?limit=2000"):
        assert TOKEN not in client.get(path).text
