from hub.grc.baseline import CONTROLS, FRAMEWORKS
from hub.grc.checks import Snapshot, evaluate_controls, framework_scores
from hub.models import Asset, ControlState, Host, Manifest, Policy, Tool


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
