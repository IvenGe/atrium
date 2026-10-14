"""CyberFundamentals catalogs, scoring and conformity, self-assessments, the audit pack and the HB-PO-3 control."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import re
import time
import zipfile
from datetime import date
from pathlib import Path

import pytest

from hub.grc.baseline import CONTROLS, CONTROLS_BY_ID, FRAMEWORKS
from hub.grc.checks import Snapshot, check_framework_assessment, evaluate_controls, framework_scores
from hub.grc.frameworks import CATALOG_IDS, LEVELS, load, mapping, scoring
from hub.grc.frameworks import assessments as fa
from hub.grc.frameworks.scoring import evaluate, evaluate_level, fmt, requirement_maturity, subset, tree_average

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINTS = json.loads((ROOT / "tests" / "data" / "cyfun_library_fingerprints.json").read_text())
REQ_2025 = re.compile(r"^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}\.\d{1,2}$")
REQ_2023 = re.compile(r"^(ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{1,2}\.\d{1,2}$")


def build_script():
    spec = importlib.util.spec_from_file_location("build_cyfun_catalog", ROOT / "scripts" / "build_cyfun_catalog.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def entry(implementation=None, documentation=None, na=False):
    return fa.Entry(implementation=implementation, documentation=documentation, na=na,
                    na_justification="not used here" if na else "")


def scored(catalog, refs, implementation, documentation):
    return {ref: entry(implementation, documentation) for ref in refs}


def in_level(catalog, tag):
    return [r.ref_id for r in catalog.requirements if tag in r.tags]


# -- catalogs ---------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("framework_id, total, functions, pattern", [("cyfun2025", 218, 6, REQ_2025),
                                                                     ("cyfun2023", 219, 5, REQ_2023)])
def test_catalog_integrity(framework_id, total, functions, pattern):
    catalog = load(framework_id)
    data = catalog.data
    assert len(catalog.requirements) == data["counts"]["requirements"] == total
    assert len(data["functions"]) == functions
    for key in ("library_urn", "framework_urn", "version", "publication_date", "url", "sha256"):
        assert data["source"][key], key
    assert data["source"]["url"].startswith("https://raw.githubusercontent.com/intuitem/ciso-assistant-community/")
    assert data["text_url"] == "https://cyfun.eu"
    functions_ = {f["id"] for f in data["functions"]}
    categories = {c["id"]: c["function"] for c in data["categories"]}
    subcategories = {s["id"]: s["category"] for s in data["subcategories"]}
    assert set(categories.values()) <= functions_ and set(subcategories.values()) <= set(categories)
    seen = set()
    groups = ("B", "I", "E", "BK", "IK", "EK", "BG", "IG", "EG")
    # per requirement only its ids, level tags and a short title - never text
    assert all(set(raw) == {"ref_id", "function", "category", "subcategory", "tags", "title"}
               for raw in data["requirements"])
    for r in catalog.requirements:
        assert pattern.match(r.ref_id) and r.ref_id not in seen, r.ref_id
        assert not r.ref_id.startswith(("BASIC_", "IMPORTANT_", "ESSENTIAL_"))
        seen.add(r.ref_id)
        assert subcategories[r.subcategory] == r.category and categories[r.category] == r.function
        assert r.ref_id.rsplit(".", 1)[0] == r.subcategory
        assert set(r.tags) <= set(groups) and r.title
        # levels are cumulative: Basic is also Important and Essential, a Basic key measure is one at every level
        for has, needs in (("B", "I"), ("I", "E"), ("BK", "IK"), ("IK", "EK"), ("BG", "IG"), ("IG", "EG"),
                           ("BK", "B"), ("IK", "I"), ("EK", "E"), ("BG", "B"), ("IG", "I"), ("EG", "E")):
            assert has not in r.tags or needs in r.tags, (r.ref_id, r.tags)
        assert "E" in r.tags  # Essential holds every requirement
    counts = {g: len(in_level(catalog, g)) for g in groups}
    assert all(counts[f"{level}K"] > 0 for level in LEVELS)  # key measures at every level
    assert counts["B"] < counts["I"] < counts["E"] == total
    assert {g: data["counts"].get(g, 0) for g in groups} == counts
    if framework_id == "cyfun2025":
        assert counts["EG"] > 0 and catalog.management_aspects
        assert {"GV.SC-04", "ID.RA-07", "GV.PO-02"}.isdisjoint(subcategories)  # not in CyFun 2025
        assert catalog.transition() is None
    else:
        assert counts["EG"] == 0 and not catalog.management_aspects
        assert "PR.AC-3.4" in catalog.by_ref  # the library's typo R.AC-3.4 is corrected and recorded
        assert {c["library_ref_id"] for c in data["corrections"]} == {"R.AC-3.4", "R.AC-3.5"}
        assert data["transition"]["assess_until"] == "2027-04-18"
        assert catalog.transition(date(2027, 4, 18))["open"] and not catalog.transition(date(2027, 4, 19))["open"]
        pairs = data["edition_mapping"]["pairs"]
        target = load("cyfun2025").by_ref
        assert len(pairs) > 150 and all(a in catalog.by_ref and b in target and rel in ("equal", "intersect", "subset",
                                                                                         "superset")
                                        for a, b, rel in pairs)


def _strings(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


@pytest.mark.parametrize("framework_id", CATALOG_IDS)
def test_no_ccb_requirement_text_is_shipped(framework_id):
    """The catalogs hold ids, tags and NIST CSF titles only: no string in them (titles included) equals a requirement
    name, description or annotation of the CISO Assistant library copy (compared by fingerprint, so the test does not
    ship the text either)."""
    script = build_script()
    catalog = load(framework_id)
    prints = FINGERPRINTS[framework_id]
    assert prints["library_sha256"] == catalog.data["source"]["sha256"]  # fingerprints of the very library used
    library = set(prints["text_fingerprints"])
    assert len(library) > 300
    # everything but the attribution block (library name, URNs, copyright line)
    strings = list(_strings({k: v for k, v in catalog.data.items() if k != "source"}))
    titles = [r.title for r in catalog.requirements] + [s["title"] for s in catalog.data["subcategories"]] \
        + [c["title"] for c in catalog.data["categories"]]
    assert set(titles) <= set(strings)
    leaks = [s for s in strings if script.norm(s) and script.fingerprint(s) in library]
    assert leaks == []
    # titles are short statements, not requirement texts
    assert max(len(t) for t in titles) <= 240
    # and the API never adds a description to a requirement
    assert set(catalog.requirements[0].public()) == {"ref_id", "function", "category", "subcategory", "tags", "title",
                                                      "level", "key_measure", "management", "text_url"}


def test_build_script_rules():
    script = build_script()
    assert script.hub_ref("BASIC_ID.AM-1.1", {}) == "ID.AM-1.1"
    assert script.hub_ref("IMPORTANT_R.AC-3.4", {"R.AC-3.4": "PR.AC-3.4"}) == "PR.AC-3.4"
    script.check_tags("X", ["B", "I", "E", "BK", "IK", "EK"], True)
    for broken in (["B", "E"], ["I", "E", "BK"], ["E", "IK", "EK"], ["I", "E", "IG"]):
        with pytest.raises(script.BuildError, match="cumulative"):
            script.check_tags("X", broken, True)
    with pytest.raises(script.BuildError, match="unknown level tags"):
        script.check_tags("X", ["B", "I", "E", "BG"], False)  # CyFun 2023 has no management aspects
    # the cache must stay outside the repository: the library files are never committed
    assert script.main(["--cache-dir", str(ROOT / "tmp-cache"), "--offline"]) == 2
    assert not (ROOT / "tmp-cache").exists()


# -- scoring and conformity -------------------------------------------------------------------------------------------


def test_requirement_maturity_and_formatting():
    c = load("cyfun2025")
    assert requirement_maturity(c, entry(3, 4)) == 3.5
    assert requirement_maturity(c, entry(4)) == 2.5  # a missing documentation maturity counts as 1
    assert requirement_maturity(c, entry(na=True)) == 3.0  # N/A is anchored to the target
    assert requirement_maturity(c, entry()) is None and requirement_maturity(c, None) is None
    assert (fmt(2.345), fmt(2.5), fmt(3.0049999), fmt(None)) == ("2.35", "2.50", "3.00", "-")


def test_scores_are_an_average_of_averages():
    c = load("cyfun2025")
    reqs = [c.by_ref[ref] for ref in ("GV.OC-03.1", "GV.OC-03.2", "GV.OC-04.1", "PR.AA-01.1")]
    values = {"GV.OC-03.1": 2.0, "GV.OC-03.2": 4.0, "GV.OC-04.1": 5.0, "PR.AA-01.1": 1.0}
    # GV.OC-03 = 3, GV.OC-04 = 5 -> GV.OC = 4; PR.AA = 1 -> (4 + 1) / 2 (a plain average would be 3.0)
    assert tree_average(reqs, values) == 2.5
    scores = subset(c, reqs, {"GV.OC-03.1": entry(2, 2), "GV.OC-03.2": entry(4, 4), "GV.OC-04.1": entry(5, 5),
                              "PR.AA-01.1": entry(1, 1)})
    assert (scores["maturity"], scores["min_maturity"], scores["scored"], scores["total"]) == (2.5, 1.0, 4, 4)
    partial = subset(c, reqs, {"GV.OC-03.1": entry(2, 2)})
    assert partial["maturity"] == 2.0 and partial["min_maturity"] == scoring.MISSING  # unscored count as -1 in min


def test_basic_level_golden_cases():
    c = load("cyfun2025")
    basic, keys = in_level(c, "B"), in_level(c, "BK")
    met = evaluate_level(c, scored(c, basic, 3, 2), "B")  # every requirement 2.5: exactly the threshold
    assert met["verdict"] == "met" and met["rules_met"] and met["reasons"] == []
    assert met["groups"]["B"]["maturity"] == 2.5 and met["groups"]["BK"]["min_maturity"] == 2.5

    low_key = {**scored(c, basic, 3, 2), keys[0]: entry(2, 2)}
    result = evaluate_level(c, low_key, "B")
    assert result["verdict"] == "not_met"
    assert f"Key measures below 2.50: {keys[0]} (2.00)" in result["reasons"]

    unscored = evaluate_level(c, {}, "B")
    assert unscored["verdict"] == "incomplete" and "No requirement of this level is scored yet" in unscored["reasons"]
    half = evaluate_level(c, scored(c, [r for r in basic if r not in keys], 4, 4), "B")
    assert half["verdict"] == "incomplete"  # key measures not scored yet: incomplete, not failed
    assert any(reason.startswith("Key measures not scored yet") for reason in half["reasons"])

    others = [r for r in basic if r not in keys]
    one_na = {**scored(c, basic, 3, 2), others[0]: entry(na=True)}
    assert evaluate_level(c, one_na, "B")["verdict"] == "met"  # one exclusion allowed at Basic
    two_na = {**one_na, others[1]: entry(na=True)}
    result = evaluate_level(c, two_na, "B")
    assert result["verdict"] == "not_met" and "2 requirements are N/A; at most 1 allowed at this level" in result["reasons"]
    key_na = {**scored(c, basic, 3, 2), keys[0]: entry(na=True)}
    result = evaluate_level(c, key_na, "B")
    assert result["verdict"] == "not_met" and f"Key measures marked N/A (none allowed): {keys[0]}" in result["reasons"]


def test_important_thresholds_and_na_limit():
    c = load("cyfun2025")
    important = in_level(c, "I")
    assert evaluate_level(c, scored(c, important, 3, 3), "I")["verdict"] == "met"
    below = evaluate_level(c, scored(c, important, 3, 2), "I")  # 2.5 < 3.0
    assert below["verdict"] == "not_met" and "Overall maturity 2.50 is below 3.00" in below["reasons"]
    plain = [r for r in important if "IK" not in c.by_ref[r].tags]
    four_na = {**scored(c, important, 3, 3), **{r: entry(na=True) for r in plain[:4]}}
    result = evaluate_level(c, four_na, "I")
    assert result["verdict"] == "not_met" and "4 requirements are N/A; at most 3 allowed at this level" in result["reasons"]
    assert evaluate_level(c, {**scored(c, important, 3, 3), **{r: entry(na=True) for r in plain[:3]}}, "I")["verdict"] == "met"


def test_essential_category_and_management_rules():
    c = load("cyfun2025")
    everything = in_level(c, "E")
    entries = scored(c, everything, 4, 4)
    entries.update(scored(c, [r.ref_id for r in c.requirements if r.category == "RC.CO"], 1, 1))
    result = evaluate_level(c, entries, "E")
    # 21 categories at 4.0 and RC.CO at 1.0: overall 85 / 22 = 3.86 >= 3.5, key measures 4.0 - only the category fails
    assert result["groups"]["E"]["maturity"] == pytest.approx(85 / 22)
    rules = {r["id"]: r for r in result["rules"]}
    assert rules["maturity"]["ok"] and rules["key_measures"]["ok"] and rules["exclusions"]["ok"]
    assert not rules["categories"]["ok"] and result["verdict"] == "not_met"
    assert result["reasons"] == ["Categories below 3.00: RC.CO (1.00)"]

    management = next(r for r in everything if "EG" in c.by_ref[r].tags and "EK" not in c.by_ref[r].tags)
    with_na = {**scored(c, everything, 4, 4), management: entry(na=True)}
    result = evaluate_level(c, with_na, "E")
    assert result["verdict"] == "not_met"
    assert f"Management aspects marked N/A (none allowed): {management}" in result["reasons"]
    assert evaluate_level(c, scored(c, everything, 4, 3), "E")["verdict"] == "met"  # 3.5 overall, every category 3.5
    assert evaluate_level(c, scored(c, everything, 4, 2), "E")["verdict"] == "not_met"  # 3.0 < 3.5


def test_evaluate_reports_targets_gaps_and_key_measures():
    c = load("cyfun2025")
    important = in_level(c, "I")
    entries = scored(c, important, 3, 3)
    gap = next(r for r in important if "IK" in c.by_ref[r].tags)
    entries[gap] = entry(2, 3)
    entries["GV.OC-03.2"] = entry(4)  # documentation missing
    result = evaluate(c, entries, "I")
    assert result["target_level"] == "I" and result["verdict"] == "not_met"
    assert [g["ref_id"] for g in result["gaps"]][:1] == [gap] and result["gaps"][0]["key_measure"]
    assert result["documentation_missing"] == ["GV.OC-03.2"]
    levels = {lv["level"]: lv for lv in result["levels"]}
    assert levels["B"]["targeted"] and levels["I"]["targeted"] and not levels["E"]["targeted"]
    assert any(k["ref_id"] == gap and not k["ok"] for k in result["key_measures"])
    assert "CISO Assistant" in result["method"]["source"] and result["method"]["na_counts_as"] == 3.0
    assert {f["id"] for f in result["functions"]} == {"GV", "ID", "PR", "DE", "RS", "RC"}
    # CyFun 2023 has no conformity rules of its own: the 2025 rules apply, said so
    assert evaluate(load("cyfun2023"), {}, "B")["method"]["source"].startswith("UNVERIFIED")


# -- controls and baseline refs ---------------------------------------------------------------------------------------


def test_baseline_cyfun_refs_follow_the_mapping():
    known = {key: load(key).by_ref for key in CATALOG_IDS}
    assert {"CyFun2025", "CyFun2023"} <= set(FRAMEWORKS)
    for control in CONTROLS:
        expected = mapping.refs_text(control)
        assert {k: control.refs.get(k) for k in ("CyFun2025", "CyFun2023") if k in control.refs} == expected, control.id
        for name, key in (("CyFun2025", "cyfun2025"), ("CyFun2023", "cyfun2023")):
            for ref in filter(None, (s.strip() for s in control.refs.get(name, "").split("/"))):
                assert ref in known[key], (control.id, ref)
    assert "CyFun2025" in CONTROLS_BY_ID["HB-AC-4"].refs and "PR.AA-05.1" in CONTROLS_BY_ID["HB-AC-4"].refs["CyFun2025"]
    # weak rows of the research table stay out of the refs but are suggested with their fit
    assert "PR.AA-03.2" not in CONTROLS_BY_ID["HB-AC-3"].refs["CyFun2025"]
    rows = mapping.by_requirement("cyfun2025")["PR.AA-03.2"]
    assert {"control": "HB-AC-3", "fit": "W"} in rows and rows[0]["fit"] in ("P", "S") and rows[-1]["fit"] == "W"
    scores = {s["id"]: s for s in framework_scores(evaluate_controls(Snapshot([], [], [], [], [], [], "supervised", 0), {}))}
    assert scores["CyFun2025"]["controls"] == sum(1 for c in CONTROLS if "CyFun2025" in c.refs)


def summary_of(name="2026 review", assessed_at=None, below=(), target="I", framework="cyfun2025"):
    return {"id": "fa_1", "name": name, "framework": framework, "framework_name": load(framework).short_name,
            "target_level": target, "target_name": {"B": "Basic", "I": "Important", "E": "Essential"}[target],
            "assessed_at": assessed_at, "updated_at": assessed_at, "status": "in_progress", "verdict": "not_met",
            "progress": {"percent": 50}, "key_measures_below": list(below)}


def test_self_assessment_control():
    control = CONTROLS_BY_ID["HB-PO-3"]
    assert control.family == "Governance" and control.check == "framework_assessment"
    assert control.refs["CyFun2025"] == "GV.OV-03.1" and "CyFun2023" not in control.refs

    def status(*frameworks):
        return check_framework_assessment(Snapshot([], [], [], [], [], [], "supervised", 0, frameworks=list(frameworks)))

    assert status()[0] == "manual"
    now = time.time()
    state, detail, evidence = status(summary_of(assessed_at=now - 86400))
    assert state == "pass" and "every key measure of the Important level reaches its threshold" in detail
    assert evidence[0].startswith("CyFun 2025 '2026 review' (target Important): not met, 50% assessed")
    state, detail, _ = status(summary_of(assessed_at=now - 400 * 86400))
    assert state == "partial" and "more than 12 months ago" in detail
    state, detail, _ = status(summary_of(assessed_at=now, below=["PR.AA-01.1", "PR.IR-01.1"]))
    assert state == "partial" and "2 key measure(s) of the Important level" in detail and "PR.AA-01.1" in detail
    assert status(summary_of(assessed_at=None))[0] == "partial"
    # the most recently scored assessment counts
    assert status(summary_of(assessed_at=now - 400 * 86400), summary_of("newer", assessed_at=now))[0] == "pass"


# -- the API ------------------------------------------------------------------------------------------------------------


def create(c, framework="cyfun2025", **body):
    response = c.post(f"/api/frameworks/{framework}/assessments", json={"name": "2026 review", "target_level": "B", **body})
    assert response.status_code == 201, response.text
    return response.json()


def score(c, aid, ref, framework="cyfun2025", **body):
    return c.patch(f"/api/frameworks/{framework}/assessments/{aid}/requirements/{ref}", json=body)


def test_catalog_api(client, sign_in):
    viewer = sign_in("viewer")
    listing = viewer.get("/api/frameworks").json()
    by_id = {f["id"]: f for f in listing["frameworks"]}
    assert listing["default"] == "cyfun2025" and set(by_id) == {"cyfun2025", "cyfun2023"}
    assert by_id["cyfun2025"]["counts"]["requirements"] == 218 and by_id["cyfun2025"]["kind"] == "builtin"
    assert by_id["cyfun2023"]["transition"]["note"].startswith("CyFun 2023 may still be applied")
    assert "CISO Assistant library copy" in by_id["cyfun2025"]["conformity_source"]
    assert [s["name"] for s in listing["scale"]] == ["Initial", "Repeatable", "Defined", "Managed", "Optimizing"]
    assert listing["sync"] == []

    framework = viewer.get("/api/frameworks/cyfun2025").json()
    assert [f["id"] for f in framework["tree"]] == ["GV", "ID", "PR", "DE", "RS", "RC"]
    pr = next(f for f in framework["tree"] if f["id"] == "PR")
    aa = next(cat for cat in pr["categories"] if cat["id"] == "PR.AA")
    first = aa["subcategories"][0]["requirements"][0]
    assert first["ref_id"] == "PR.AA-01.1" and first["key_measure"] == ["B", "I", "E"] and first["level"] == "B"
    assert "description" not in first and first["text_url"] == "https://cyfun.eu"
    suggested = framework["controls"]["PR.AA-05.1"]
    assert {"HB-AC-4", "HB-PO-2"} <= {s["control"] for s in suggested} and suggested[0]["fit"] == "P"
    assert framework["conformity"]["levels"]["E"]["category_min"] == 3.0
    assert viewer.get("/api/frameworks/nist-csf").status_code == 404
    assert viewer.get("/api/frameworks/nist-csf/assessments").status_code == 404


def test_assessment_lifecycle_and_permissions(client, sign_in):
    hub = client.app.state.hub
    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.post("/api/frameworks/cyfun2025/assessments", json={"name": "x"}).status_code == 403
    created = create(operator, target_level="I", scope="All of ACME's IT")
    aid = created["id"]
    assert created["target_level"] == "I" and created["verdict"] == "incomplete" and created["created_by"].startswith("operator")
    assert len(created["requirements"]) == 218 and created["requirements"]["PR.AA-01.1"]["in_scope"]
    assert any(e["text"].startswith("Started the CyFun 2025 self-assessment '2026 review'")
               for e in hub.store.tail("activity", 500))
    assert viewer.get("/api/frameworks/cyfun2025/assessments").json()[0]["id"] == aid
    assert viewer.get(f"/api/frameworks/cyfun2023/assessments/{aid}").status_code == 404  # another edition's

    person = client.post("/api/people", json={"display_name": "Ada Owner", "email": "ada@example.com"}).json()
    response = score(operator, aid, "PR.AA-01.1", implementation=3, documentation=4, owner_person_id=person["id"],
                     notes="Okta for everyone", evidence=[{"kind": "control", "ref": "HB-AC-4"},
                                                          {"kind": "url", "ref": "https://wiki.example.com/iam"}])
    assert response.status_code == 200, response.text
    body = response.json()
    requirement = body["requirement"]
    assert requirement["maturity"] == 3.5 and requirement["owner"]["display_name"] == "Ada Owner"
    assert requirement["key_measure"] and requirement["updated_by"].startswith("operator")
    assert [e["kind"] for e in requirement["evidence"]] == ["control", "url"]
    assert requirement["evidence"][0]["status"] in ("pass", "partial", "fail", "manual")
    assert requirement["history"][-1]["changes"]["implementation"] == [None, 3]
    assert body["assessment"]["progress"]["scored"] == 1 and body["evaluation"]["target_level"] == "I"
    assert viewer.patch(f"/api/frameworks/cyfun2025/assessments/{aid}/requirements/PR.AA-01.1",
                        json={"implementation": 1}).status_code == 403

    # validation
    assert score(operator, aid, "PR.AA-01.1", implementation=6).status_code == 422
    assert score(operator, aid, "XX.YY-01.1", implementation=3).status_code == 404
    assert score(operator, aid, "PR.AA-01.2", na=True).json()["detail"] == "Marking a requirement N/A needs a justification"
    assert score(operator, aid, "PR.AA-01.2", owner_person_id="p_nobody").status_code == 400
    assert score(operator, aid, "PR.AA-01.2", evidence=[{"kind": "control", "ref": "HB-XX-9"}]).status_code == 422
    assert score(operator, aid, "PR.AA-01.2", evidence=[{"kind": "url", "ref": "https://u:p@x.example.com"}]).status_code == 422
    assert score(operator, aid, "PR.AA-01.2", evidence=[{"kind": "url", "ref": "javascript:alert(1)"}]).status_code == 422
    assert score(operator, aid, "PR.AA-01.2", evidence=[{"kind": "policy", "ref": "pol_missing"}]).status_code == 400
    assert score(operator, aid, "PR.AA-01.2", unknown=1).status_code == 422
    na = score(operator, aid, "PR.AA-01.2", na=True, na_justification="No remote access at all")
    assert na.status_code == 200 and na.json()["requirement"]["maturity"] == 3.0

    # copy into a new assessment, archive, reopen, delete
    copy = create(operator, name="2027 review", copy_from=aid)
    assert copy["requirements"]["PR.AA-01.1"]["implementation"] == 3 and copy["requirements"]["PR.AA-01.1"]["history"] == []
    archived = operator.patch(f"/api/frameworks/cyfun2025/assessments/{aid}", json={"status": "archived"})
    assert archived.status_code == 200 and archived.json()["status"] == "archived"
    assert score(operator, aid, "PR.AA-01.1", implementation=4).status_code == 409
    assert operator.patch(f"/api/frameworks/cyfun2025/assessments/{aid}", json={"status": "in_progress"}).status_code == 200
    assert operator.patch(f"/api/frameworks/cyfun2025/assessments/{aid}", json={"target_level": "X"}).status_code == 422
    assert operator.delete(f"/api/frameworks/cyfun2025/assessments/{aid}").status_code == 403
    assert client.delete(f"/api/frameworks/cyfun2025/assessments/{aid}").json() == {"ok": True}
    assert viewer.get(f"/api/frameworks/cyfun2025/assessments/{aid}").status_code == 404
    assert any(e["text"].startswith("Deleted the CyFun 2025 self-assessment") and e["level"] == "warn"
               for e in hub.store.tail("activity", 500))


def test_cyfun2023_assessments_and_the_transition(client):
    hub = client.app.state.hub
    created = create(client, framework="cyfun2023")
    assert created["framework_name"] == "CyFun 2023" and created["transition"]["open"]
    assert score(client, created["id"], "PR.AC-3.4", framework="cyfun2023", implementation=2).status_code == 200
    with pytest.raises(fa.AssessmentError, match="no longer be used"):
        fa.create(hub, load("cyfun2023"), fa.AssessmentCreate(name="late"), "test", today=date(2027, 4, 19))


def test_hb_po_3_follows_the_assessments(client, wait_for):
    def state():
        return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == "HB-PO-3")

    client.post("/api/grc/evaluate")
    assert state()["status"] == "manual"
    aid = create(client)["id"]  # Basic target, nothing scored
    wait_for(lambda: state()["status"] == "partial")
    basic = in_level(load("cyfun2025"), "B")
    hub = client.app.state.hub
    assessment = fa.get(hub, "cyfun2025", aid)
    for ref in basic[:-1]:
        fa.update_requirement(hub, load("cyfun2025"), assessment, ref, fa.RequirementPatch(implementation=3, documentation=3), "t")
    assert score(client, aid, basic[-1], implementation=3, documentation=3).status_code == 200
    client.post("/api/grc/evaluate")
    assert wait_for(lambda: state()["status"] == "pass")
    assert "every key measure of the Basic level" in state()["detail"]


DAY = 86400


def hb_po_3(c):
    return next(x for x in c.get("/api/grc").json()["controls"] if x["id"] == "HB-PO-3")


def scored_assessment(c, name, implementation=3, documentation=3, refs=None):
    """An assessment (Basic target) with the given requirements - by default every Basic one - scored."""
    hub, catalog = c.app.state.hub, load("cyfun2025")
    aid = create(c, name=name)["id"]
    assessment = fa.get(hub, "cyfun2025", aid)
    for ref in in_level(catalog, "B") if refs is None else refs:
        fa.update_requirement(hub, catalog, assessment, ref,
                              fa.RequirementPatch(implementation=implementation, documentation=documentation), "t")
    return aid


def backdate(hub, aid, seconds):
    doc = hub.store.get(fa.COLLECTION, aid)
    hub.store.put(fa.COLLECTION, {**doc, "assessed_at": doc["assessed_at"] - seconds,
                                  "updated_at": doc["updated_at"] - seconds})


def test_a_copy_keeps_the_age_of_its_scores(client, wait_for):
    """Copying a two-year-old assessment does not make HB-PO-3 pass: nothing was reviewed."""
    hub = client.app.state.hub
    old = scored_assessment(client, "2024 review")
    backdate(hub, old, 2 * 365 * DAY)
    client.post("/api/grc/evaluate")
    assert wait_for(lambda: "more than 12 months ago" in hb_po_3(client)["detail"])
    copy = create(client, name="copy", copy_from=old)
    assert copy["stale"] and copy["assessed_at"] == fa.get(hub, "cyfun2025", old).assessed_at
    assert copy["requirements"]["PR.AA-01.1"]["implementation"] == 3
    state = wait_for(lambda: (s := hb_po_3(client)) and "'copy'" in s["detail"] and s)
    assert state["status"] == "partial" and "more than 12 months ago" in state["detail"]
    # a person reviews a requirement of the copy: it is current again
    assert score(client, copy["id"], "PR.AA-01.1", implementation=4, documentation=4).status_code == 200
    assert not client.get(f"/api/frameworks/cyfun2025/assessments/{copy['id']}").json()["stale"]
    assert wait_for(lambda: hb_po_3(client)["status"] == "pass")
    # copying an assessment with nothing scored yet leaves the copy unscored
    empty = create(client, name="empty")
    assert create(client, name="copy of empty", copy_from=empty["id"])["assessed_at"] is None


def test_hb_po_3_follows_the_latest_scored_assessment(client, wait_for):
    """Scoring any requirement re-evaluates HB-PO-3 (it judges the most recently scored assessment), and the hourly
    scheduler pass (its vulnerability SLA check) re-evaluates compliance, so an assessment turns out of date without
    anything else happening."""
    hub, catalog = client.app.state.hub, load("cyfun2025")
    key = [r.ref_id for r in catalog.requirements if r.key_measure("B")]
    other = [ref for ref in in_level(catalog, "B") if ref not in key]
    bad = scored_assessment(client, "bad", 1, 1, refs=key[:1])
    backdate(hub, bad, DAY)
    scored_assessment(client, "good")
    client.post("/api/grc/evaluate")
    assert wait_for(lambda: (s := hb_po_3(client))["status"] == "pass" and "'good'" in s["detail"])
    assert score(client, bad, other[0], implementation=3, documentation=3).status_code == 200  # not a key measure
    state = wait_for(lambda: (s := hb_po_3(client)) and "'bad'" in s["detail"] and s)
    assert state["status"] == "partial" and "key measure(s) of the Basic level below" in state["detail"]

    for item in fa.all_assessments(hub):
        backdate(hub, item.id, 400 * DAY)
    client.portal.call(hub.tick_flows, time.time() + DAY + 60)
    assert wait_for(lambda: "more than 12 months ago" in hb_po_3(client)["detail"])


def test_assessment_names_must_not_be_blank(client):
    for name in ("   ", "\u0000\u0007", "\t\n"):
        response = client.post("/api/frameworks/cyfun2025/assessments", json={"name": name})
        assert response.status_code == 400 and response.json()["detail"] == "Give the assessment a name"
    aid = create(client)["id"]
    url = f"/api/frameworks/cyfun2025/assessments/{aid}"
    response = client.patch(url, json={"name": " \u0001 "})
    assert response.status_code == 400 and response.json()["detail"] == "Give the assessment a name"
    assert client.get(url).json()["name"] == "2026 review"
    assert client.patch(url, json={"name": "  2027\u0007 review "}).json()["name"] == "2027 review"


def test_archived_assessments_are_read_only(client):
    aid = create(client)["id"]
    url = f"/api/frameworks/cyfun2025/assessments/{aid}"
    assert client.patch(url, json={"status": "archived"}).status_code == 200
    for body in ({"target_level": "E", "name": "B"}, {"notes": "changed"}, {"scope": "x", "status": "archived"}):
        response = client.patch(url, json=body)
        assert response.status_code == 409 and "reopen it" in response.json()["detail"]
    detail = client.get(url).json()
    assert (detail["status"], detail["target_level"], detail["name"], detail["notes"], detail["scope"]) == \
        ("archived", "B", "2026 review", "", "")
    assert client.patch(url, json={"status": "archived", "name": "2026 review"}).status_code == 200  # nothing changes
    reopened = client.patch(url, json={"status": "in_progress", "target_level": "I"})  # reopening allows changes
    assert reopened.status_code == 200 and reopened.json()["target_level"] == "I"


# -- the audit pack -----------------------------------------------------------------------------------------------------


def test_audit_pack_contents_hashes_and_no_secrets(client, sign_in, monkeypatch):
    hub = client.app.state.hub
    secret = "ca-token-77aa88bb99cc00dd"
    env_secret = "env-secret-0f1e2d3c4b5a6978"
    monkeypatch.setenv("ACME_SERVICE_API_KEY", env_secret)  # a secret this process knows
    hub.save_tool(__import__("hub.models", fromlist=["Tool"]).Tool(id="ciso", name="CISO", source_type="saas",
                                                                  source="https://c.example.com", status="ready"))
    assert client.put("/api/tools/ciso/connection", json={"kind": "ciso_assistant", "secrets": {"token": secret},
                                                          "config": {"base_url": "https://c.example.com"}}).status_code == 200
    created = create(client, name="<script>alert(1)</script> review", target_level="B")
    aid = created["id"]
    policy = client.post("/api/grc/policies", json={"title": "Access policy", "category": "access",
                                                    "status": "approved"}).json()
    assert score(client, aid, "PR.AA-01.1", implementation=3, documentation=2,
                 notes=f"=HYPERLINK(\"x\") token={secret} password=hunter2-secret-9 {env_secret} {secret}",
                 evidence=[{"kind": "control", "ref": "HB-AC-4"}, {"kind": "policy", "ref": policy["id"]},
                           {"kind": "file", "ref": "ISMS share: iam-review-2026.pdf"}]).status_code == 200
    assert score(client, aid, "PR.AA-01.2", na=True, na_justification="No such systems").status_code == 200

    viewer = sign_in("viewer")
    response = viewer.get(f"/api/frameworks/cyfun2025/assessments/{aid}/audit-pack")
    assert response.status_code == 200 and response.headers["content-type"] == "application/zip"
    assert re.fullmatch(r'attachment; filename="atrium-cyfun2025-fa_[0-9a-f]+-\d{8}\.zip"',
                        response.headers["content-disposition"])
    pack = zipfile.ZipFile(io.BytesIO(response.content))
    names = pack.namelist()
    assert names == ["summary.html", "requirements.csv", "evidence/index.csv", "evidence/controls.json",
                     "evidence/items.json", "assessment.json", "manifest.json", "SHA256SUMS"]
    files = {name: pack.read(name) for name in names}
    manifest = json.loads(files["manifest.json"])
    assert [f["path"] for f in manifest["files"]] == names[:-2]
    for item in manifest["files"]:
        assert hashlib.sha256(files[item["path"]]).hexdigest() == item["sha256"] and len(files[item["path"]]) == item["size"]
    assert files["SHA256SUMS"].decode() == "".join(f"{f['sha256']}  {f['path']}\n" for f in manifest["files"])
    assert manifest["framework_source"]["library_urn"] == "urn:intuitem:risk:library:ccb-cyfun2025"
    assert manifest["exported_by"].startswith("viewer")

    everything = b"".join(files.values()).decode("utf-8")
    for leaked in (secret, "hunter2-secret-9", env_secret):
        assert leaked not in everything

    summary = files["summary.html"].decode()
    assert "<script" not in summary and "&lt;script&gt;alert(1)&lt;/script&gt; review" in summary
    assert not re.search(r"""(?:src|href)\s*=\s*["'](?!https://cyfun\.eu)""", summary)  # self-contained
    assert "Basic" in summary and "Key measures" in summary and "CISO Assistant" in summary
    rows = list(csv.reader(io.StringIO(files["requirements.csv"].decode("utf-8-sig"))))
    assert len(rows) == 219 and rows[0][:2] == ["ref_id", "function"]
    row = next(r for r in rows if r[0] == "PR.AA-01.1")
    header = rows[0]
    assert row[header.index("maturity")] == "2.50" and row[header.index("key_measure")] == "yes"
    assert row[header.index("notes")].startswith("'=HYPERLINK")  # never a live formula
    na_row = next(r for r in rows if r[0] == "PR.AA-01.2")
    assert na_row[header.index("na")] == "yes" and na_row[header.index("na_justification")] == "No such systems"
    index = list(csv.reader(io.StringIO(files["evidence/index.csv"].decode("utf-8-sig"))))
    assert {(r[1], r[2]) for r in index[1:]} == {("control", "HB-AC-4"), ("policy", policy["id"]),
                                                 ("file", "ISMS share: iam-review-2026.pdf")}
    controls = json.loads(files["evidence/controls.json"])["controls"]
    assert any(c["id"] == "HB-AC-4" and {"ref_id": "PR.AA-01.1", "fit": "P"} in c["requirements"] for c in controls)
    items = json.loads(files["evidence/items.json"])["items"]
    assert any(i["kind"] == "policy" and i["title"] == "Access policy" for i in items)
    data = json.loads(files["assessment.json"])
    assert data["assessment"]["id"] == aid and data["evaluation"]["target_level"] == "B"

    entry_ = next(e for e in hub.store.tail("activity", 500) if e["text"].startswith("Exported the audit pack"))
    assert entry_["data"]["sha256"] == hashlib.sha256(response.content).hexdigest() and entry_["actor"].startswith("viewer")
    assert viewer.get("/api/frameworks/cyfun2025/assessments/fa_missing/audit-pack").status_code == 404
