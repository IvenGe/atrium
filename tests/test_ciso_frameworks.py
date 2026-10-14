"""CISO Assistant framework sync: reading loaded frameworks and assessments, sending the hub's CyFun
self-assessments (only when an administrator allows it), and the 4.9 fixes (degraded status, evidence observation).
In-memory fake of the REST API (httpx.MockTransport), no network."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import httpx
from test_connector_ciso_assistant import DOMAIN, GLOBAL, TOKEN, FakeCiso, make, run

from hub.connectors.base import normalize
from hub.connectors.ciso_assistant import MARKER, CisoAssistantConnector
from hub.grc.frameworks import load
from hub.grc.frameworks import sync
from hub.models import Manifest, Tool

CYFUN2025 = "urn:intuitem:risk:framework:ccb-cyfun2025"
CYFUN2023 = "urn:intuitem:risk:framework:ccb-cff-2023-03-01"
CRA = "urn:intuitem:risk:framework:cra-resolution-annexes"
RESULTS = ("not_assessed", "partially_compliant", "non_compliant", "compliant", "not_applicable")


class FakeGrc(FakeCiso):
    """FakeCiso plus loaded libraries, frameworks, requirement nodes, compliance and requirement assessments, mapping
    sets and global_score. Creating a compliance assessment creates one requirement assessment per node, as
    CISO Assistant's perform_create does."""

    EXTRA = ("frameworks", "requirement-nodes", "compliance-assessments", "requirement-assessments", "loaded-libraries",
             "requirement-mapping-sets")

    def __init__(self, *, degraded: bool = True, **kwargs):
        super().__init__(**kwargs)
        self.degraded = degraded
        for name in self.EXTRA:
            self.data[name] = {}

    def load_framework(self, urn: str, library_urn: str, name: str, nodes: list[dict], version: int = 1) -> dict:
        library = self.add("loaded-libraries", urn=library_urn, name=name, version=version)
        framework = self.add("frameworks", urn=urn, ref_id=urn.rsplit(":", 1)[-1], name=name,
                             description=f"{name}: the library's own description", library=library["id"],
                             provider="CCB" if "ccb" in urn else "EU", min_score=1, max_score=5,
                             implementation_groups_definition=[{"ref_id": "B", "name": "Basic"},
                                                               {"ref_id": "I", "name": "Important"}])
        for node in nodes:
            self.add("requirement-nodes", framework=framework["id"], **node)
        return framework

    def read(self, collection: str, item: dict) -> dict:
        if collection not in self.EXTRA:
            return super().read(collection, item)
        out = {**item, "folder": self._str("folders", item["folder"])}
        for key, target in (("library", "loaded-libraries"), ("framework", "frameworks")):
            if item.get(key):
                out[key] = self._str(target, item[key])
        if collection == "requirement-assessments":
            out["compliance_assessment"] = self._str("compliance-assessments", item["compliance_assessment"])
        return out

    def list(self, collection: str, params: httpx.QueryParams):
        response = super().list(collection, params)
        if collection not in self.EXTRA:
            return response
        body = json.loads(response.content)
        for key in ("framework", "compliance_assessment"):
            if params.get(key):
                body["results"] = [i for i in body["results"] if (i.get(key) or {}).get("id") == params[key]]
                body["count"] = len(body["results"])
        return httpx.Response(200, json=body)

    def handler(self, request: httpx.Request) -> httpx.Response:
        parts = request.url.path.strip("/").split("/")[1:]
        if len(parts) == 3 and parts[0] == "compliance-assessments" and parts[2] == "global_score":
            self.requests.append(request)
            rows = [r for r in self.data["requirement-assessments"].values()
                    if r["compliance_assessment"] == parts[1] and r.get("is_scored") and r.get("score")]
            implementation = sum(r["score"] for r in rows) / len(rows) if rows else -1
            documentation = sum(r.get("documentation_score") or 1 for r in rows) / len(rows) if rows else None
            maturity = (implementation + documentation) / 2 if rows else -1
            return httpx.Response(200, json={"implementation_score": implementation, "documentation_score": documentation,
                                             "maturity_score": maturity, "max_score": 5, "min_score": 1})
        return super().handler(request)

    def invalid(self, collection: str, values: dict, own_id: str | None = None):
        if collection == "applied-controls" and values.get("status") == "degraded" and not self.degraded:
            return httpx.Response(400, json={"status": ['"degraded" is not a valid choice.']})
        if collection == "requirement-assessments":
            if values.get("result") not in RESULTS:
                return httpx.Response(400, json={"result": ["not a valid choice."]})
            for key in ("score", "documentation_score"):
                if values.get(key) is not None and not 1 <= values[key] <= 5:
                    return httpx.Response(400, json={key: ["Score must be between 1 and 5"]})
            return None
        if collection == "compliance-assessments":
            if not isinstance(values.get("selected_implementation_groups", []), list):
                return httpx.Response(400, json={"selected_implementation_groups": ["Expected a list of items."]})
            if values.get("framework") not in self.data["frameworks"]:
                return httpx.Response(400, json={"framework": ["This field is required."]})
        return super().invalid(collection, values, own_id)

    def create(self, collection: str, body: dict) -> httpx.Response:
        response = super().create(collection, body)
        if collection == "compliance-assessments" and response.status_code == 201:
            assessment = json.loads(response.content)
            for node in self.of("requirement-nodes", framework=body["framework"]):
                self.add("requirement-assessments", folder=assessment["folder"]["id"], compliance_assessment=assessment["id"],
                         requirement=node["id"], result="not_assessed", status="to_do", score=None,
                         documentation_score=None, is_scored=False, observation=None)
        return response

    def ra(self, assessment_id: str, ref: str) -> dict:
        node = next(n for n in self.data["requirement-nodes"].values() if n["ref_id"].endswith(ref))
        return next(r for r in self.data["requirement-assessments"].values()
                    if r["compliance_assessment"] == assessment_id and r["requirement"] == node["id"])


def cyfun2025_nodes() -> list[dict]:
    """The CyFun 2025 tree as the library has it, with stand-in texts that must never reach the hub."""
    catalog = load("cyfun2025")
    base = "urn:intuitem:risk:req_node:ccb-cyfun2025:"
    nodes = []
    for depth, kind, parent_key in ((1, "functions", None), (2, "categories", "function"),
                                    (3, "subcategories", "category")):
        for item in catalog.data[kind]:
            nodes.append({"urn": base + item["id"].lower(), "ref_id": item["id"], "depth": depth, "assessable": False,
                          "parent_urn": base + item[parent_key].lower() if parent_key else None,
                          "name": f"CCB NAME {item['id']}", "description": f"CCB TEXT {item['id']}"})
    for r in catalog.requirements:
        nodes.append({"urn": base + r.ref_id.lower(), "ref_id": r.ref_id, "parent_urn": base + r.subcategory.lower(),
                      "assessable": True, "implementation_groups": list(r.tags), "name": f"CCB NAME {r.ref_id}",
                      "description": f"CCB TEXT {r.ref_id}"})
    return nodes


def cyfun2023_nodes() -> list[dict]:
    base = "urn:intuitem:risk:req_node:ccb-cff-2023-03-01:"
    return [{"urn": base + "pr", "ref_id": "PR", "assessable": False, "name": "CCB NAME PR"},
            {"urn": base + "pr.ac", "ref_id": "PR.AC", "parent_urn": base + "pr", "assessable": False},
            {"urn": base + "pr.ac-3", "ref_id": "PR.AC-3", "parent_urn": base + "pr.ac", "assessable": False},
            {"urn": base + "important_r.ac-3.4", "ref_id": "IMPORTANT_R.AC-3.4", "parent_urn": base + "pr.ac-3",
             "assessable": True, "implementation_groups": ["E"], "description": "CCB TEXT 2023"},
            {"urn": base + "basic_pr.ac-3.1", "ref_id": "BASIC_PR.AC-3.1", "parent_urn": base + "pr.ac-3",
             "assessable": True, "implementation_groups": ["B", "I", "E"], "description": "CCB TEXT 2023"}]


def cra_nodes() -> list[dict]:
    base = "urn:intuitem:risk:req_node:cra-resolution-annexes:"
    return [{"urn": base + "annex-i", "ref_id": "Annex I", "name": "Essential cybersecurity requirements", "assessable": False},
            {"urn": base + "annex-i-1", "ref_id": "Annex I.1", "parent_urn": base + "annex-i", "assessable": True,
             "name": "Security by design", "description": "Products are designed with an appropriate level of security."},
            {"urn": base + "annex-i-2", "ref_id": "Annex I.2", "parent_urn": base + "annex-i", "assessable": True,
             "name": "<img src=x onerror=alert(1)>", "description": "Device text is data."}]


def grc_fake(**kwargs) -> tuple[FakeGrc, dict]:
    fake = FakeGrc(**kwargs)
    frameworks = {
        "cyfun2025": fake.load_framework(CYFUN2025, "urn:intuitem:risk:library:ccb-cyfun2025", "CyberFundamentals 2025",
                                         cyfun2025_nodes(), version=10),
        "cra": fake.load_framework(CRA, "urn:intuitem:risk:library:cra-resolution-annexes", "CRA annexes", cra_nodes(),
                                   version=3),
    }
    return fake, frameworks


def push_connector(fake: FakeGrc, **config) -> CisoAssistantConnector:
    cfg = CisoAssistantConnector.validate_config({"base_url": "https://ciso.example.com", "folder_id": DOMAIN,
                                                  "push_assessments": True, **config})
    return CisoAssistantConnector(cfg, {"token": TOKEN}, httpx.MockTransport(fake.handler))


def record(**extra) -> dict:
    return {"hub_id": "fa_1", "external_id": None, "name": "Atrium: 2026 review", "framework": "cyfun2025",
            "framework_urn": CYFUN2025, "level": "I", "ref_aliases": {}, "summary": "Verdict not met; maturity 3.20.",
            "requirements": [{"ref_id": "PR.AA-01.1", "result": "compliant", "score": 3, "documentation_score": 4,
                              "observation": "Okta for everyone"},
                             {"ref_id": "PR.AA-01.2", "result": "not_applicable", "observation": "N/A: no such systems"}],
            **extra}


# -- reading ----------------------------------------------------------------------------------------------------------


def test_pull_frameworks_reads_trees_and_assessments_without_ccb_text():
    fake, frameworks = grc_fake()
    cra_assessment = fake.add("compliance-assessments", folder=DOMAIN, name="CRA readiness", framework=frameworks["cra"]["id"],
                              status="in_progress", version="1.0", selected_implementation_groups=[],
                              computed_outcome={"ready": False})
    cra_nodes_ = {n["ref_id"]: n for n in fake.of("requirement-nodes", framework=frameworks["cra"]["id"])}
    for ref, result, score in (("Annex I.1", "compliant", 4), ("Annex I.2", "non_compliant", 1), ("Annex I", "compliant", None)):
        fake.add("requirement-assessments", folder=DOMAIN, compliance_assessment=cra_assessment["id"],
                 requirement=cra_nodes_[ref]["id"], result=result, status="done", score=score, documentation_score=3,
                 is_scored=score is not None)
    fake.add("compliance-assessments", folder=DOMAIN, name="CyFun audit", framework=frameworks["cyfun2025"]["id"],
             status="planned", selected_implementation_groups=["I"],
             computed_outcome={"important_maturity": True, "important_key_measures": False})
    fake.add("compliance-assessments", folder=GLOBAL, name="Other team's audit", framework=frameworks["cra"]["id"])
    fake.add("requirement-mapping-sets", name="CyFun 2023 -> 2025", source_framework=frameworks["cyfun2025"]["id"],
             target_framework=frameworks["cra"]["id"])

    records = run(make(fake).pull("frameworks"))
    valid, errors = normalize("frameworks", records)
    assert errors == [] and len(valid) == 2
    by_urn = {r["urn"]: r for r in valid}
    cyfun, cra = by_urn[CYFUN2025], by_urn[CRA]
    assert "CCB NAME" not in json.dumps(valid) and "CCB TEXT" not in json.dumps(valid)  # the CCB's text stays out
    assert cyfun["description"] == "" and all(n["name"] == "" == n["description"] for n in cyfun["requirements"])
    assert sum(1 for n in cyfun["requirements"] if n["assessable"]) == 218
    pr_aa = next(n for n in cyfun["requirements"] if n["ref_id"] == "PR.AA-01.1")
    assert pr_aa["depth"] == 4 and pr_aa["implementation_groups"] == ["B", "I", "E", "BK", "IK", "EK"]
    assert cyfun["library_urn"] == "urn:intuitem:risk:library:ccb-cyfun2025"
    assert [a["name"] for a in cyfun["assessments"]] == ["CyFun audit"]
    assert cyfun["assessments"][0]["outcomes"] == ["important_maturity"]
    assert cyfun["assessments"][0]["selected_implementation_groups"] == ["I"]

    assert cra["name"] == "CRA annexes" and cra["description"].startswith("CRA annexes: the library's own")
    names = {n["ref_id"]: n["name"] for n in cra["requirements"]}
    assert names["Annex I.1"] == "Security by design" and names["Annex I.2"] == "<img src=x onerror=alert(1)>"
    (state,) = cra["assessments"]  # the other folder's assessment is not read
    assert state["name"] == "CRA readiness" and state["results"] == {"compliant": 1, "non_compliant": 1}
    assert state["scores"] == {"implementation": 2.5, "documentation": 3.0, "maturity": 2.75}
    assert {r["ref_id"]: r["score"] for r in state["requirements"]} == {"Annex I.1": 4, "Annex I.2": 1}
    assert cra["mappings"] == cyfun["mappings"] and cra["mappings"][0]["source"] == CYFUN2025
    assert all(r.method == "GET" for r in fake.requests)  # reading writes nothing


def test_pull_strips_cyfun2023_prefixes_and_typos():
    fake = FakeGrc()
    fake.load_framework(CYFUN2023, "urn:intuitem:risk:library:ccb-cff-2023-03-01", "CyFun 2023", cyfun2023_nodes(), 8)
    (framework,) = normalize("frameworks", run(make(fake).pull("frameworks")))[0]
    refs = {n["ref_id"] for n in framework["requirements"] if n["assessable"]}
    assert refs == {"PR.AC-3.4", "PR.AC-3.1"} and "CCB TEXT" not in json.dumps(framework)


def test_test_reports_loaded_libraries_and_the_push_switch():
    fake, _ = grc_fake()
    result = run(make(fake).test())
    assert result["ok"] and result["domains"]["frameworks"] == ["read"] and "assessments" not in result["domains"]
    checks = {c["name"]: c for c in result["checks"]}
    assert checks["Frameworks"]["detail"] == ("2 loaded, 0 compliance assessments in the folder - shown read-only in the "
                                              "Compliance hub")
    assert checks["Libraries"]["detail"].startswith("Loaded: CyFun 2025 (version 10), Cyber Resilience Act (CRA) "
                                                    "(version 3); not loaded: CyFun 2023 - an administrator of CISO "
                                                    "Assistant can import them")
    assert "Not sent" in checks["Self-assessments"]["detail"]
    assert all(r.method == "GET" for r in fake.requests)  # test() never imports a library or writes anything

    pushing = run(push_connector(fake).test())
    assert pushing["domains"]["assessments"] == ["write"]
    assert "Atrium writes its CyFun self-assessments" in {c["name"]: c for c in pushing["checks"]}["Self-assessments"]["detail"]
    bare = FakeGrc()  # nothing loaded
    assert "None of CyFun 2025, CyFun 2023 or the CRA is loaded" in json.dumps(run(make(bare).test())["checks"])
    assert "load a CyFun library" not in json.dumps(run(push_connector(bare).test())["checks"])  # no library list read


# -- pushing self-assessments -------------------------------------------------------------------------------------------


def test_push_assessments_only_when_allowed():
    fake, _ = grc_fake()
    assert "assessments" not in make(fake).domains()
    assert push_connector(fake).domains()["assessments"] == ["write"]
    assert "assessments" not in push_connector(fake, push_assessments=False).domains()


def test_push_assessment_writes_results_and_scores():
    fake, frameworks = grc_fake()
    (first,) = run(push_connector(fake).push("assessments", [record()], {}))
    assert first["action"] == "created" and first["error"] is None
    assessment = fake.data["compliance-assessments"][first["external_id"]]
    assert assessment["framework"] == frameworks["cyfun2025"]["id"] and assessment["folder"] == DOMAIN
    assert assessment["selected_implementation_groups"] == ["I"] and assessment["status"] == "in_progress"
    assert assessment["observation"].startswith(MARKER) and "Verdict not met" in assessment["observation"]
    scored, na = fake.ra(assessment["id"], "PR.AA-01.1"), fake.ra(assessment["id"], "PR.AA-01.2")
    assert (scored["result"], scored["score"], scored["documentation_score"], scored["is_scored"], scored["status"]) == \
        ("compliant", 3, 4, True, "done")
    assert "Okta for everyone" in scored["observation"] and MARKER in scored["observation"]
    assert (na["result"], na["score"], na["status"]) == ("not_applicable", None, "done")
    untouched = fake.ra(assessment["id"], "PR.AA-01.3")
    assert (untouched["result"], untouched["status"], untouched["observation"]) == ("not_assessed", "to_do", None)

    # a person's notes above the marker stay; unchanged requirements are not written again
    assessment["observation"] = "Reviewed by the CISO.\n\n" + assessment["observation"]
    scored["observation"] = "Checked in the audit.\n\n" + scored["observation"]
    fake.requests.clear()
    (second,) = run(push_connector(fake).push("assessments", [record()], {"fa_1": first["external_id"]}))
    assert second == {"hub_id": "fa_1", "external_id": first["external_id"], "action": "updated", "error": None}
    assert assessment["observation"].startswith("Reviewed by the CISO.") and scored["observation"].startswith("Checked")
    assert not [r for r in fake.requests if r.method == "PATCH" and "requirement-assessments" in r.url.path]
    assert len(fake.data["compliance-assessments"]) == 1

    changed = record(requirements=[{"ref_id": "PR.AA-01.1", "result": "partially_compliant", "score": 2,
                                    "documentation_score": 2, "observation": ""}])
    run(push_connector(fake).push("assessments", [changed], {"fa_1": first["external_id"]}))
    assert (scored["result"], scored["score"]) == ("partially_compliant", 2)
    assert scored["observation"].startswith("Checked in the audit.") and "Okta" not in scored["observation"]


def test_push_assessment_failures_are_per_record():
    fake, frameworks = grc_fake()
    other = fake.add("compliance-assessments", folder=DOMAIN, name="Atrium: adopted", framework=frameworks["cyfun2025"]["id"])
    for node in fake.of("requirement-nodes", framework=frameworks["cyfun2025"]["id"]):
        fake.add("requirement-assessments", folder=DOMAIN, compliance_assessment=other["id"], requirement=node["id"],
                 result="not_assessed", status="to_do", is_scored=False)
    results = run(push_connector(fake).push("assessments", [
        record(hub_id="fa_2023", name="Atrium: 2023", framework="cyfun2023", framework_urn=CYFUN2023),
        record(hub_id="fa_bad", name="Atrium: bad", requirements=[{"ref_id": "XX.YY-01.1", "result": "compliant",
                                                                    "score": 3}]),
        record(hub_id="fa_adopt", name="Atrium: adopted"),
    ], {}))
    by_id = {r["hub_id"]: r for r in results}
    assert by_id["fa_2023"]["action"] == "failed" and "is not loaded in CISO Assistant" in by_id["fa_2023"]["error"]
    assert "Atrium never imports libraries" in by_id["fa_2023"]["error"]
    assert by_id["fa_bad"]["action"] == "failed" and "XX.YY-01.1 is not in CISO Assistant's framework" in by_id["fa_bad"]["error"]
    assert by_id["fa_adopt"] == {"hub_id": "fa_adopt", "external_id": other["id"], "action": "updated", "error": None}
    assert fake.ra(other["id"], "PR.AA-01.1")["score"] == 3
    assert not fake.of("loaded-libraries", urn="urn:intuitem:risk:library:ccb-cff-2023-03-01")  # never imported


def test_push_to_cyfun2023_follows_the_corrected_ids():
    fake = FakeGrc()
    fake.load_framework(CYFUN2023, "urn:intuitem:risk:library:ccb-cff-2023-03-01", "CyFun 2023", cyfun2023_nodes(), 8)
    rec = record(framework="cyfun2023", framework_urn=CYFUN2023, ref_aliases={"R.AC-3.4": "PR.AC-3.4"}, level="E",
                 requirements=[{"ref_id": "PR.AC-3.4", "result": "compliant", "score": 4, "documentation_score": 3}])
    (result,) = run(push_connector(fake).push("assessments", [rec], {}))
    assert result["action"] == "created", result
    row = fake.ra(result["external_id"], "R.AC-3.4")
    assert (row["result"], row["score"]) == ("compliant", 4)


# -- the 4.9 fixes: degraded status and evidence revisions ---------------------------------------------------------------


def control(status="partial") -> dict:
    return {"hub_id": "HB-VM-2", "external_id": "HB-VM-2", "ref_id": "HB-VM-2", "name": "Scanned", "description": "d",
            "status": status, "evidence": ["web: scanned"], "refs": {"ISO27001": "A.8.8"}, "family": "Vulnerability",
            "detail": "2 of 3 assets scanned", "evaluated_at": 1_790_000_000}


def test_partial_controls_as_degraded_and_evidence_with_an_observation():
    fake = FakeGrc()
    (pushed,) = run(push_connector(fake, partial_status="degraded").push("controls", [control()], {}))
    applied_id, evidence_id = pushed["external_id"].split("|")
    assert fake.data["applied-controls"][applied_id]["status"] == "degraded"
    observation = fake.data["evidences"][evidence_id]["observation"]
    assert observation.startswith("Atrium check: partial (") and observation.endswith("- 2 of 3 assets scanned")

    old = FakeGrc(degraded=False)  # a version without "degraded": the push falls back to in_progress
    (fallback,) = run(push_connector(old, partial_status="degraded").push("controls", [control()], {}))
    assert fallback["action"] == "created"
    assert old.data["applied-controls"][fallback["external_id"].split("|")[0]]["status"] == "in_progress"
    default = FakeGrc()
    (plain,) = run(push_connector(default).push("controls", [control()], {}))
    assert default.data["applied-controls"][plain["external_id"].split("|")[0]]["status"] == "in_progress"


# -- through the hub ---------------------------------------------------------------------------------------------------


def test_the_hub_syncs_frameworks_with_ciso_assistant(client, sign_in, wait_for):
    hub = client.app.state.hub
    fake, frameworks = grc_fake()
    hub.connector_transport = httpx.MockTransport(fake.handler)
    tool = Tool(id="ciso", name="CISO Assistant", source_type="saas", source="https://ciso.example.com", status="ready",
                manifest=Manifest(id="ciso", name="CISO Assistant", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    config = {"base_url": "https://ciso.example.com", "folder_id": DOMAIN, "push_assessments": True}
    operator = sign_in("operator")
    assert operator.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": TOKEN},
                                                           "config": config}).status_code == 403  # admins only
    assert client.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": TOKEN},
                                                          "config": config}).status_code == 200
    tested = client.post("/api/tools/ciso/connection/test").json()
    assert tested["ok"] and tested["domains"]["frameworks"] == ["read"] and tested["domains"]["assessments"] == ["write"]
    wanted = {("frameworks", "pull"), ("assessments", "push")}

    def planned():
        flows = {(f["domain"], f["direction"]): f for f in client.get("/api/flows?tool_id=ciso").json()}
        return flows if wanted <= set(flows) else None

    flows = wait_for(planned)
    for approval in client.get("/api/approvals?status=pending").json():
        if approval["kind"] == "flow" and approval["payload"].get("domain") in ("frameworks", "assessments"):
            assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    flows = wait_for(lambda: (f := planned()) and all(f[k]["status"] == "enabled" for k in wanted) and f)

    pulled = client.post(f"/api/flows/{flows[('frameworks', 'pull')]['id']}/run").json()
    assert pulled["ok"] and pulled["counts"]["created"] == 2, pulled
    viewer = sign_in("viewer")
    listing = viewer.get("/api/frameworks").json()
    external = [f for f in listing["frameworks"] if f["kind"] == "external"]
    assert [f["name"] for f in external] == ["CRA annexes"] and external[0]["read_only"]
    assert external[0]["caveat"].startswith("CISO Assistant's CRA library") and external[0]["counts"]["requirements"] == 2
    cyfun = next(f for f in listing["frameworks"] if f["id"] == "cyfun2025")
    assert [s["source"]["tool_id"] for s in cyfun["ciso_assistant"]] == ["ciso"]
    (status,) = listing["sync"]
    assert status["push_enabled"] and status["loaded"] == {"cyfun2025": True, "cyfun2023": False, "cra": True}
    detail = viewer.get(f"/api/frameworks/{external[0]['id']}").json()
    assert detail["tree"][0]["ref_id"] == "Annex I" and detail["tree"][0]["children"][1]["name"].startswith("<img")
    assert viewer.get(f"/api/frameworks/{external[0]['id']}/assessments").status_code == 404  # assessed in CISO Assistant
    assert "CCB TEXT" not in json.dumps(hub.store.list("external_frameworks"))

    aid = client.post("/api/frameworks/cyfun2025/assessments", json={"name": "2026 review", "target_level": "I"}).json()["id"]
    client.patch(f"/api/frameworks/cyfun2025/assessments/{aid}/requirements/PR.AA-01.1",
                 json={"implementation": 3, "documentation": 3})
    client.patch(f"/api/frameworks/cyfun2025/assessments/{aid}/requirements/PR.AA-01.2",
                 json={"implementation": 1, "documentation": 2})
    pushed = client.post(f"/api/flows/{flows[('assessments', 'push')]['id']}/run").json()
    assert pushed["ok"] and pushed["counts"]["created"] == 1, pushed
    (remote,) = fake.of("compliance-assessments", name="Atrium: 2026 review")
    assert (fake.ra(remote["id"], "PR.AA-01.1")["result"], fake.ra(remote["id"], "PR.AA-01.2")["result"]) == \
        ("compliant", "non_compliant")
    assert viewer.get("/api/frameworks").json()["sync"][0]["assessments"][aid]["external_id"] == remote["id"]
    again = client.post(f"/api/flows/{flows[('assessments', 'push')]['id']}/run").json()
    assert again["ok"] and again["counts"]["skipped"] == 1  # unchanged: not sent again

    # an administrator switches sending off: the push flow goes at once (it would fail on every run); reading stays
    push_id = flows[("assessments", "push")]["id"]
    off = {"kind": "ciso_assistant", "config": {**config, "push_assessments": False}}
    assert client.put("/api/tools/ciso/connection", json=off).status_code == 200
    connection = client.get("/api/tools/ciso/connection").json()
    assert "assessments" not in connection["capabilities"] and connection["capabilities"]["frameworks"] == ["read"]
    current = {(f["domain"], f["direction"]): f for f in client.get("/api/flows?tool_id=ciso").json()}
    assert ("assessments", "push") not in current and current[("frameworks", "pull")]["status"] == "enabled"
    assert client.post(f"/api/flows/{push_id}/run").status_code == 404
    assert any(e["text"].startswith("Removed data flow") and "no longer writes assessments" in e["text"]
               for e in hub.store.tail("activity", 300))
    assert viewer.get("/api/frameworks").json()["sync"][0]["push_flow"] is None
    client.portal.call(hub.agents.get("supervisor").on_flows_plan, {}, None)  # the planner does not bring it back
    assert ("assessments", "push") not in {(f["domain"], f["direction"]) for f in client.get("/api/flows?tool_id=ciso").json()}
    # switched on again (the last test covered it): proposed anew, so it needs a new approval
    assert client.put("/api/tools/ciso/connection", json={**off, "config": config}).status_code == 200
    proposed = wait_for(lambda: (f := planned()) and f[("assessments", "push")])
    assert proposed["status"] == "proposed" and proposed["id"] != push_id

    assert client.delete("/api/tools/ciso/connection").status_code == 200
    assert hub.store.list("external_frameworks") == []  # what was read from it goes with the connection
    assert [f["kind"] for f in viewer.get("/api/frameworks").json()["frameworks"]] == ["builtin", "builtin"]
    assert viewer.get(f"/api/frameworks/{external[0]['id']}").status_code == 404
    on_disk = b"".join(p.read_bytes() for p in Path(hub.settings.db_path).parent.glob("hub.db*"))  # + the WAL
    assert TOKEN.encode() not in on_disk
    for path in ("/api/frameworks", "/api/flows", "/api/activity?limit=2000", "/api/messages?limit=2000"):
        assert TOKEN not in client.get(path).text


def test_push_records_map_maturity_to_results(client):
    hub = client.app.state.hub
    aid = client.post("/api/frameworks/cyfun2025/assessments", json={"name": "r", "target_level": "B"}).json()["id"]
    for ref, body in (("PR.AA-01.1", {"implementation": 3, "documentation": 2}),  # 2.5 = Basic target: compliant
                      ("PR.AA-03.2", {"implementation": 2, "documentation": 2}),  # 2.0: partially
                      ("PR.AA-05.1", {"implementation": 1, "documentation": 2}),  # 1.5: non compliant
                      ("PR.AA-05.2", {"na": True, "na_justification": "Nothing critical"}),
                      ("PR.AA-05.3", {"notes": "only a note"})):
        assert client.patch(f"/api/frameworks/cyfun2025/assessments/{aid}/requirements/{ref}", json=body).status_code == 200
    archived = client.post("/api/frameworks/cyfun2025/assessments", json={"name": "old"}).json()["id"]
    client.patch(f"/api/frameworks/cyfun2025/assessments/{archived}", json={"status": "archived"})
    (rec,) = sync.push_records(hub)
    assert rec["hub_id"] == aid and rec["framework_urn"] == CYFUN2025 and rec["level"] == "B"
    results = {r["ref_id"]: (r["result"], r.get("score"), r.get("documentation_score")) for r in rec["requirements"]}
    assert results == {"PR.AA-01.1": ("compliant", 3, 2), "PR.AA-03.2": ("partially_compliant", 2, 2),
                       "PR.AA-05.1": ("non_compliant", 1, 2), "PR.AA-05.2": ("not_applicable", None, None)}
    assert "verdict" in rec["summary"] and sync.push_records(hub) == [rec]  # deterministic: unchanged runs skip


def test_store_retires_frameworks_no_longer_loaded(client):
    hub = client.app.state.hub
    records = [{"external_id": str(uuid.uuid4()), "urn": CRA, "name": "CRA"},
               {"external_id": str(uuid.uuid4()), "urn": CYFUN2025, "name": "CyFun"}]
    assert sync.store(hub, "ciso", records) == {"total": 2, "created": 2, "updated": 0, "unchanged": 0, "removed": 0}
    assert sync.store(hub, "ciso", records)["unchanged"] == 2
    assert sync.store(hub, "ciso", records[:1])["removed"] == 1
    (doc,) = sync.all_docs(hub, "ciso")
    assert doc["cyfun"] is None and doc["id"] == f"ext:ciso:{records[0]['external_id']}"
    assert sync.external_list(hub) == []  # no CISO Assistant connection: nothing shown


def test_deep_external_trees_are_bounded_and_go_with_the_tool(client):
    """A tool's requirement tree is untrusted: a 1000-node parent chain or a parent cycle must not break the API."""
    hub = client.app.state.hub
    hub.save_tool(Tool(id="ciso", name="CISO Assistant", source_type="saas", source="https://ciso.example.com",
                       status="ready"))
    assert client.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": TOKEN},
                                                          "config": {"base_url": "https://ciso.example.com"}}).status_code == 200
    chain = [{"urn": f"urn:x:{i}", "parent_urn": f"urn:x:{i - 1}" if i else None, "ref_id": f"R{i}", "name": f"node {i}",
              "assessable": True} for i in range(1000)]
    cycle = [{"urn": "urn:x:a", "parent_urn": "urn:x:b", "ref_id": "A"}, {"urn": "urn:x:b", "parent_urn": "urn:x:a", "ref_id": "B"}]
    sync.store(hub, "ciso", [{"external_id": "deep", "urn": "urn:x:framework", "name": "Deep", "requirements": chain + cycle}])
    response = client.get("/api/frameworks/ext:ciso:deep")
    assert response.status_code == 200, response.text

    levels: dict[str, int] = {}
    pending = [(node, 1) for node in response.json()["tree"]]
    while pending:
        node, level = pending.pop()
        levels[node["ref_id"]] = level
        pending += [(child, level + 1) for child in node["children"]]
    assert len(levels) == 1002 and max(levels.values()) == sync.TREE_DEPTH
    assert [levels[f"R{i}"] for i in range(sync.TREE_DEPTH)] == list(range(1, sync.TREE_DEPTH + 1))
    assert levels["R999"] == sync.TREE_DEPTH and levels["A"] == 1 and levels["B"] == 2  # a cycle shows at the top

    assert client.delete("/api/tools/ciso").status_code == 200
    assert hub.store.list("external_frameworks") == []
