import time

from hub.grc.baseline import CONTROLS, CONTROLS_BY_ID, FRAMEWORKS
from hub.grc.checks import Snapshot, evaluate_controls, framework_scores
from hub.integration import flows
from hub.models import Asset, ControlState, Flow, Host, Manifest, Policy, Tool, User, Vulnerability


def snapshot(**overrides) -> Snapshot:
    base = dict(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[], autonomy="assisted", audit_entries=10)
    base.update(overrides)
    return Snapshot(**base)


def by_id(states):
    return {s.id: s for s in states}


def test_empty_hub_fails_inventory_and_policies():
    states = by_id(evaluate_controls(snapshot(), {}))
    assert states["HB-AM-1"].status == "fail"
    assert states["HB-PO-1"].status == "fail"
    assert states["HB-AC-2"].status == "pass"
    assert states["HB-OP-2"].status == "pass"
    assert states["HB-AC-3"].status == "na"


def test_sso_and_inventory_checks():
    sso_tool = Tool(id="a", name="A", source_type="local", source="/a", manifest=Manifest(id="a", name="A", auth={"sso": "oidc"}))
    local_tool = Tool(id="b", name="B", source_type="local", source="/b", manifest=Manifest(id="b", name="B", auth={"sso": "none"}))
    assets = [Asset(id="1", name="A", source="tool:a", owner="ops"), Asset(id="2", name="B", source="tool:b")]
    states = by_id(evaluate_controls(snapshot(tools=[sso_tool, local_tool], assets=assets), {}))
    assert states["HB-AC-1"].status == "partial"
    assert "B" in states["HB-AC-1"].detail
    assert states["HB-AM-1"].status == "pass"
    assert states["HB-AM-2"].status == "partial"


def test_policies_and_autonomy():
    policies = [Policy(id="p", title="ISP", category="security", status="approved", owner="CISO"),
                Policy(id="q", title="IR", category="incident", status="draft")]
    states = by_id(evaluate_controls(snapshot(policies=policies, autonomy="autonomous"), {}))
    assert states["HB-PO-1"].status == "pass"
    assert states["HB-IR-1"].status == "partial"
    assert states["HB-AC-2"].status == "fail"


def test_ssh_hardening():
    hosts = [Host(id="h1", name="web", address="10.0.0.5", username="ops", key_path="~/.ssh/id_ed25519"),
             Host(id="h2", name="db", address="10.0.0.6", username="ops", strict_host_keys=False)]
    states = by_id(evaluate_controls(snapshot(hosts=hosts), {}))
    assert states["HB-AC-3"].status == "partial"


def test_manual_override_wins():
    overrides = {"HB-BC-1": ControlState(id="HB-BC-1", status="pass", manual=True, note="Backups by provider")}
    states = by_id(evaluate_controls(snapshot(), overrides))
    assert states["HB-BC-1"].status == "pass" and states["HB-BC-1"].manual


def test_framework_scores_cover_every_framework():
    scores = framework_scores(evaluate_controls(snapshot(), {}))
    assert [s["id"] for s in scores] == ["BASELINE", *FRAMEWORKS]
    assert scores[0]["controls"] == len(CONTROLS)
    assert all(0 <= s["score"] <= 100 for s in scores)


def test_hub_auth_control():
    admin = User(username="root", role="admin", password_hash="x", last_login=time.time())
    states = by_id(evaluate_controls(snapshot(), {}))
    assert states["HB-AC-4"].status == "fail"
    states = by_id(evaluate_controls(snapshot(users=[admin.model_copy(update={"disabled": True})]), {}))
    assert states["HB-AC-4"].status == "fail"  # no *enabled* administrator
    states = by_id(evaluate_controls(snapshot(users=[admin]), {}))
    assert states["HB-AC-4"].status == "partial" and "OIDC" in states["HB-AC-4"].detail
    states = by_id(evaluate_controls(snapshot(users=[admin], oidc_enabled=True), {}))
    assert states["HB-AC-4"].status == "pass"
    control = CONTROLS_BY_ID["HB-AC-4"]
    assert control.refs == {"ISO27001": "A.5.15 / A.8.5", "SOC2": "CC6.1", "NIS2": "21(2)(i) / 21(2)(j)",
                            "CyFun2025": "PR.AA-01.1 / PR.AA-05.1 / PR.AA-05.3 / PR.AA-05.4 / PR.AA-03.2",
                            "CyFun2023": "PR.AC-1.1 / PR.AC-4.1 / PR.AC-4.3 / PR.AC-4.4"}
    assert control.risk == ("Hub accounts are protected by passwords only", 2, 4)


def test_dormant_accounts_control():
    long_ago = time.time() - 100 * 24 * 3600
    active = User(username="active", role="admin", last_login=time.time())
    never = User(username="never", created_at=long_ago)
    gone = User(username="gone", created_at=long_ago, last_login=long_ago)
    off = User(username="off", created_at=long_ago, disabled=True)
    fresh = User(username="fresh")  # created recently, not signed in yet

    def status(*users):
        return by_id(evaluate_controls(snapshot(users=list(users)), {}))["HB-AC-5"]

    assert status().status == "manual"
    assert status(active, off, fresh).status == "pass"
    partial = status(active, never, gone)
    assert partial.status == "partial" and "never" in partial.detail and "gone" in partial.detail
    assert status(never, gone, off).status == "fail"
    control = CONTROLS_BY_ID["HB-AC-5"]
    assert control.refs == {"ISO27001": "A.5.18", "SOC2": "CC6.2", "NIS2": "21(2)(i)",
                            "CyFun2025": "PR.AA-01.3 / PR.AA-05.1", "CyFun2023": "PR.AC-1.3"}
    assert control.risk == ("Dormant accounts could be misused", 2, 3)


def test_scan_coverage_control():
    now = time.time()
    scanned = Asset(id="1", name="web", scan_scope=True, last_scanned_at=now - 3 * 86400)
    stale = Asset(id="2", name="db", scan_scope=True, last_scanned_at=now - 45 * 86400)
    never = Asset(id="3", name="nas", scan_scope=True)
    outside = Asset(id="4", name="printer")
    retired = Asset(id="5", name="old", scan_scope=True, status="retired")

    def state(*assets):
        return by_id(evaluate_controls(snapshot(assets=list(assets)), {}))["HB-VM-2"]

    assert state(outside).status == "manual"  # nothing in scope: assess by hand
    assert state(scanned, outside, retired).status == "pass" and state(scanned).evidence[0].startswith("web: scanned")
    partial = state(scanned, stale, never)
    assert partial.status == "partial" and "db" in partial.detail and "nas" in partial.detail
    assert state(stale, never).status == "fail"
    control = CONTROLS_BY_ID["HB-VM-2"]
    assert control.refs == {"ISO27001": "A.8.8", "SOC2": "CC7.1", "NIS2": "21(2)(e)",
                            "CyFun2025": "ID.RA-01.1 / ID.RA-01.2 / ID.RA-01.6 / ID.RA-01.5 / ID.IM-03.9",
                            "CyFun2023": "DE.DP-5.2 / ID.RA-1.1 / ID.RA-1.2"}
    assert control.risk == ("Vulnerabilities on unscanned assets go unnoticed", 3, 4)


def test_vulnerability_sla_control():
    now = time.time()
    in_scope = Asset(id="1", name="web", scan_scope=True)

    def vuln(severity, due, status="open"):
        return Vulnerability(id=f"v{severity}{due}", title=f"{severity} issue", severity=severity, status=status,
                             host="10.0.0.5", due_at=now + due * 86400)

    def state(assets=(), vulns=()):
        return by_id(evaluate_controls(snapshot(assets=list(assets), vulnerabilities=list(vulns)), {}))["HB-VM-3"]

    assert state().status == "manual"
    assert state([in_scope]).status == "pass"  # scanned scope without findings
    assert state(vulns=[vuln("critical", 3), vuln("medium", -10)]).status == "pass"  # only critical/high count
    assert state(vulns=[vuln("high", -1)]).status == "partial"
    failing = state(vulns=[vuln("critical", -1), vuln("critical", -5, "accepted"), vuln("high", -2, "fixed")])
    assert failing.status == "fail" and "1 critical/high finding(s) past their SLA" in failing.detail
    assert vuln("critical", -1).overdue and not vuln("critical", -1, "accepted").overdue and not vuln("low", 1).overdue
    assert CONTROLS_BY_ID["HB-VM-3"].risk == ("Known critical vulnerabilities remain exploitable", 4, 5)


def test_a_blank_requirement_status_does_not_drop_the_framework():
    from hub.connectors.grcmodel import normalize_frameworks
    records, errors = normalize_frameworks([{
        "external_id": "fw", "urn": "urn:x", "name": "CRA",
        "assessments": [{"external_id": "a1", "requirements": [
            {"urn": "u", "ref_id": "R1", "status": None, "result": "compliant"}]}],
    }])
    assert errors == []
    assert records[0]["assessments"][0]["requirements"][0]["status"] == ""
    assert records[0]["name"] == "CRA"


def test_the_grc_supervisor_runs_framework_flows_without_an_agent_error(client):
    hub = client.app.state.hub
    grc = hub.agents.get("module:grc")
    before = grc.errors
    hub.save_tool(Tool(id="ciso", name="CISO Assistant", source_type="saas", source="https://ciso.example",
                       status="ready", manifest=Manifest(id="ciso", name="CISO Assistant", kind="saas")))

    async def pull_records(flow, since=None):
        return [{
            "external_id": "fw-cra", "urn": "urn:example:risk:framework:cra", "ref_id": "CRA",
            "name": "Cyber Resilience Act", "description": "Imported", "provider": "EU",
            "requirements": [], "assessments": [],
        }], {"dropped": 0, "errors": []}

    grc.pull_records = pull_records
    pull = flows.save(hub, Flow(id="flow_fw", domain="frameworks", source="tool:ciso", target="hub", status="enabled",
                                title="Pull frameworks from CISO Assistant"))
    result = client.post(f"/api/flows/{pull.id}/run").json()
    assert result["ok"] is True, result
    assert result["counts"]["created"] == 1
    docs = hub.store.list("external_frameworks")
    assert len(docs) == 1 and docs[0]["name"] == "Cyber Resilience Act" and docs[0]["tool_id"] == "ciso"
    assert grc.errors == before

    created = client.post("/api/frameworks/cyfun2025/assessments", json={"name": "Q4", "target_level": "B"})
    assert created.status_code == 201, created.text
    sent = []

    async def push_records(flow, records, label=None):
        sent.extend(records)
        return {"total": len(records), "created": len(records), "updated": 0, "skipped": 0, "failed": 0}

    grc.push_records = push_records
    push = flows.save(hub, Flow(id="flow_as", domain="assessments", source="hub", target="tool:ciso", status="enabled",
                                title="Push assessments to CISO Assistant"))
    pushed = client.post(f"/api/flows/{push.id}/run").json()
    assert pushed["ok"] is True, pushed
    assert pushed["counts"]["created"] == 1
    assert sent and sent[0]["framework"] == "cyfun2025" and sent[0]["name"].startswith("Atrium:")
    assert grc.errors == before

    wrong = flows.save(hub, Flow(id="flow_bad", domain="frameworks", source="hub", target="tool:ciso", status="enabled",
                                 title="Push frameworks the wrong way"))
    refused = client.post(f"/api/flows/{wrong.id}/run").json()
    assert refused["ok"] is False
    assert "cannot push frameworks" in refused["error"]["message"]
    assert grc.errors == before
