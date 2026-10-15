"""Extensions: strict data-only packs (validation, no code execution), versions with enable / disable / rollback in
process, extension domains and their records (links to assets and people), connectors pulling and pushing them,
compliance evidence, SSO recipes, team templates, gap detection after an import with template packs (no Claude) and
packs Claude writes (a fake model), the "extension" approval and the HB-CM-2 guardrails. No network: tools' APIs are
httpx mock transports."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from llm_fakes import use_claude

from hub import guardrails
from hub.agents import teams
from hub.connectors.base import normalize
from hub.connectors.generic_rest import GenericRestConnector
from hub.extensions import gaps, generate, pack, records, registry
from hub.grc.checks import Snapshot, evaluate_controls
from hub.integration import identity, sso_catalog
from hub.models import ControlState, Manifest, Tool

OLD = "2020-01-02T03:04:05Z"


def alerts_pack(version: str = "1.0.0", **extra) -> dict:
    data = {
        "id": "siem-alerts", "name": "SIEM alerts", "version": version, "description": "Alerts from the SIEM.",
        "items": [
            {"kind": "domain", "key": "alerts", "title": "Alerts", "singular": "Alert", "icon": "bell",
             "fields": [{"name": "title", "label": "Title", "required": True},
                        {"name": "severity", "label": "Severity", "type": "severity"},
                        {"name": "status", "label": "Status", "type": "enum", "values": ["open", "closed"]},
                        {"name": "host", "label": "Host"}, {"name": "user", "label": "User"},
                        {"name": "detected", "label": "Detected", "type": "date"},
                        {"name": "link", "label": "Link", "type": "link"}],
             "title_field": "title",
             "links": [{"target": "asset", "field": "host"}, {"target": "person", "field": "user"}]},
            {"kind": "controls", "rules": [
                {"control": "HB-OP-2", "domain": "alerts", "title": "Critical alerts open for more than 7 days",
                 "where": [{"field": "severity", "op": "eq", "value": "critical"},
                           {"field": "status", "op": "ne", "value": "closed"}],
                 "age_field": "detected", "older_than_days": 7, "fail_above": 0}]},
        ],
    }
    data.update(extra)
    return data


def add_tool(client, tool_id: str, name: str, **manifest) -> Tool:
    hub = client.app.state.hub
    tool = Tool(id=tool_id, name=name, source_type="saas", source=f"https://{tool_id}.example.com", status="ready",
                manifest=Manifest(id=tool_id, name=name, kind="saas", **manifest))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    return tool


def upload(client, data: dict, enable: bool = False, status: int = 201) -> dict:
    response = client.post(f"/api/extensions{'?enable=true' if enable else ''}", json=data)
    assert response.status_code == status, response.text
    return response.json()


def pending(client, kind: str) -> list[dict]:
    return [a for a in client.get("/api/approvals?status=pending").json() if a["kind"] == kind]


def control(client, control_id: str) -> dict:
    client.post("/api/grc/evaluate")
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


def activity(client) -> list[dict]:
    return client.get("/api/activity?limit=2000").json()


# -- packs: strict and data only -------------------------------------------------------------------


def bad(data: dict, *fragments: str) -> None:
    with pytest.raises(ValueError) as caught:
        pack.parse(data)
    for fragment in fragments:
        assert fragment in str(caught.value), (fragment, str(caught.value))


def test_pack_validation_rejects_unknown_kinds_and_unsafe_values():
    good = pack.parse(alerts_pack())
    assert good.summary()["domains"] == ["alerts"] and good.summary()["controls"] == ["HB-OP-2"]
    assert pack.parse(json.dumps(alerts_pack())).id == "siem-alerts"  # JSON text works too

    def with_item(item: dict) -> dict:
        data = alerts_pack()
        data["items"].append(item)
        return data

    def domain(**changes) -> dict:
        data = alerts_pack()
        data["items"][0].update(changes)
        return data

    bad(with_item({"kind": "python", "code": "import os; os.system('id')"}), "python")  # no executable kinds
    bad(with_item({"kind": "script", "command": "rm -rf /"}), "script")
    bad(domain(on_load="__import__('os').system('id')"), "on_load")  # unknown keys are rejected everywhere
    bad({**alerts_pack(), "hooks": {"enable": "curl evil"}}, "hooks")
    bad(domain(key="assets"), "built-in domain")
    bad(domain(key="../alerts"), "domain key")
    bad(domain(icon="<svg onload=alert(1)>"), "icon")
    bad(domain(title="Alerts\x00"), "control characters")
    bad(domain(fields=[{"name": "__class__", "label": "x"}], title_field="__class__"), "field name")
    bad(domain(fields=[{"name": "kind", "label": "Kind", "type": "enum"}], title_field="kind"), "needs values")
    bad(domain(fields=[{"name": "title", "label": "T", "type": "code"}]), "type")
    bad(domain(fields=[{"name": "title", "label": "T", "required": "yes"}]), "required")  # strict: no coercion
    bad(domain(title_field="nope"), "title_field")
    bad({**alerts_pack(), "id": "Siem Alerts"}, "pack id")
    bad({**alerts_pack(), "version": "1.0; rm -rf"}, "version")
    bad({**alerts_pack(), "items": []}, "items")
    connector = {"kind": "connector", "tool": "wazuh", "mapping": {"x:alerts": {"list": {"path": "/alerts"},
                                                                                "fields": {"external_id": "id"}}}}
    pack.parse(with_item(connector))
    bad(with_item({**connector, "base_url": "javascript:alert(1)"}), "http")
    bad(with_item({**connector, "base_url": "https://user:pw@siem.example.com"}), "credentials")
    bad(with_item({**connector, "mapping": {"x:alerts": {"list": {"path": "https://evil.example.com/steal"},
                                                         "fields": {"external_id": "id"}}}}), "relative")
    bad(with_item({**connector, "mapping": {"x:alerts": {"list": {"path": "/../admin"}, "fields": {"external_id": "id"}}}}))
    bad(with_item({**connector, "mapping": {"secrets": {"list": {"path": "/x"}, "fields": {"external_id": "id"}}}}),
        "unknown domain")
    bad(with_item({**connector, "auth_header": "X-Key\r\nEvil: 1"}), "header")
    bad(with_item({**connector, "mapping": {"x:alerts": {"list": {"path": "/alerts", "params": {"api_key": "s3cr3t"}},
                                                         "fields": {"external_id": "id"}}}}), "no credentials")
    sso = {"kind": "sso", "key": "acme", "name": "Acme", "match": ["acme"], "redirect_path": "/oauth/callback",
           "file": "sso/acme.env", "template": "ACME_ISSUER={issuer}\n"}
    pack.parse(with_item(sso))
    bad(with_item({**sso, "file": "../../etc/cron.d/x"}), "file name")
    bad(with_item({**sso, "file": "sso/../../x"}), "file name")
    bad(with_item({**sso, "redirect_path": "/a/../../b"}), "..")
    bad(with_item({**sso, "redirect_path": "https://evil.example.com/cb"}), "path")
    bad(with_item({**sso, "protocol": "saml"}), "acs_path")
    bad(with_item({"kind": "controls", "rules": [{"control": "HB-XX-9", "domain": "alerts", "title": "x", "fail_above": 0}]}),
        "unknown control")
    bad(with_item({"kind": "controls", "rules": [{"control": "HB-OP-2", "domain": "alerts", "title": "x"}]}),
        "fail_above")
    bad(with_item({"kind": "controls", "rules": [{"control": "HB-OP-2", "domain": "alerts", "title": "x",
                                                  "where": [{"field": "nope", "op": "eq", "value": 1}], "fail_above": 0}]}),
        "not a field")
    role = {"role": "watcher", "title": "Watcher", "permissions": ["read"], "schedule_minutes": 60}
    pack.parse(with_item({"kind": "team", "category": "ticketing", "title": "Service desk", "roles": [role]}))
    bad(with_item({"kind": "team", "category": "x", "title": "X", "roles": [{**role, "permissions": ["root"]}]}), "permissions")
    bad(with_item({"kind": "team", "category": "x", "title": "X", "roles": [{**role, "schedule_minutes": 2}]}), "schedule")
    bad({**alerts_pack(), "description": "x" * 600_000}, "larger")
    with pytest.raises(ValueError, match="not valid JSON"):
        pack.parse("{not json")


def test_pack_texts_are_substituted_never_evaluated(client):
    """Placeholders are plain text substitution of known names: format-string tricks stay as they are."""
    assert pack.fill("{issuer} {tool.__class__} {__import__} {0}", {"issuer": "https://idp"}) == \
        "https://idp {tool.__class__} {__import__} {0}"
    hub = client.app.state.hub
    team = {"kind": "team", "category": "ticketing", "title": "Service desk", "match": {"names": ["zammad"]},
            "roles": [{"role": "triage", "title": "Triage", "description": "Watches {tool} {tool.__class__.__mro__}",
                       "permissions": ["read"]}]}
    registry.upload(hub, pack.parse({**alerts_pack(), "items": [team]}), "test", enable=True)
    tool = add_tool(client, "zammad", "Zammad")
    assert teams.classify(hub, tool) == "ticketing" and teams.category_title(hub, "ticketing") == "Service desk"
    member = next(m for m in teams.template_members(hub, tool, "ticketing") if m["title"] == "Triage")
    assert member["description"] == "Watches Zammad {tool.__class__.__mro__}"


# -- versions, enable / disable / rollback -----------------------------------------------------------


def test_upload_enable_new_version_rollback_disable_and_delete_in_process(client, sign_in):
    operator, viewer = sign_in("operator"), sign_in("viewer")
    assert operator.post("/api/extensions", json=alerts_pack()).status_code == 403
    created = upload(client, alerts_pack())
    assert created["status"] == "disabled" and not created["active"] and created["version"] == "1.0.0"
    assert created["created_by"] == "admin" and created["summary"]["kinds"] == {"domain": 1, "controls": 1}
    assert viewer.get("/api/extensions").json()["extensions"][0]["id"] == "siem-alerts"
    assert client.get("/api/x/alerts").status_code == 404  # not enabled: no app yet

    assert operator.patch("/api/extensions/siem-alerts", json={"status": "enabled"}).status_code == 403
    enabled = client.patch("/api/extensions/siem-alerts", json={"status": "enabled"}).json()
    assert enabled["status"] == "enabled" and enabled["active"]
    assert [d["key"] for d in viewer.get("/api/x").json()] == ["alerts"]  # at once, no restart
    assert viewer.get("/api/x/alerts").json()["total"] == 0

    assert upload(client, alerts_pack(), status=409)  # the same version again
    v2 = alerts_pack("2.0.0")
    v2["items"][0]["fields"].append({"name": "rule", "label": "Rule"})
    updated = upload(client, v2)
    assert updated["version"] == "2.0.0" and updated["status"] == "enabled" and updated["can_rollback"]
    assert "rule" in [f["name"] for f in client.get("/api/x/alerts").json()["domain"]["fields"]]

    rolled = client.post("/api/extensions/siem-alerts/rollback").json()
    assert rolled["version"] == "1.0.0" and [v["version"] for v in rolled["versions"]] == ["1.0.0", "2.0.0"]
    assert "rule" not in [f["name"] for f in client.get("/api/x/alerts").json()["domain"]["fields"]]
    assert client.post("/api/extensions/siem-alerts/rollback").status_code == 400  # nothing before 1.0.0
    assert client.post("/api/extensions/siem-alerts/rollback", json={"version": "2.0.0"}).json()["version"] == "2.0.0"
    full = client.get("/api/extensions/siem-alerts").json()
    assert full["pack"]["version"] == "2.0.0" and len(full["versions"]) == 2 and full["versions"][0]["pack"]["items"]
    assert [h["action"] for h in full["history"]] == ["added", "enabled", "new version", "rolled back from 2.0.0",
                                                     "rolled back from 1.0.0"]

    # one owner per domain key
    other = alerts_pack(id="other-alerts")
    upload(client, other)
    refused = client.patch("/api/extensions/other-alerts", json={"status": "enabled"})
    assert refused.status_code == 400 and "already defined" in refused.json()["detail"]

    # the guardrail switches every pack off at once
    client.patch("/api/settings/guardrails", json={"allow_extensions": False})
    assert client.get("/api/x").json() == [] and client.get("/api/x/alerts").status_code == 404
    assert client.get("/api/extensions").json()["allowed"] is False
    assert "allow_extensions" in client.post("/api/extensions?enable=true", json=alerts_pack(id="third")).json()["detail"]
    client.patch("/api/settings/guardrails", json={"allow_extensions": True})
    entries = [(e["level"], e["text"]) for e in activity(client)]
    assert ("info", "Guardrail 'Allow extensions' changed: on -> off") in entries
    assert ("warn", "Guardrail 'Allow extensions' relaxed: off -> on") in entries  # allowing again is the relaxation

    client.post("/api/x/alerts", json={"fields": {"title": "Brute force"}})
    assert client.patch("/api/extensions/siem-alerts", json={"status": "disabled"}).json()["active"] is False
    assert client.get("/api/x/alerts").status_code == 404
    client.patch("/api/extensions/siem-alerts", json={"status": "enabled"})
    assert client.get("/api/x/alerts").json()["total"] == 1  # records survive disabling
    assert operator.delete("/api/extensions/siem-alerts").status_code == 403
    assert client.delete("/api/extensions/siem-alerts?purge=true").json() == {"ok": True, "purged": 1}
    assert client.get("/api/extensions/siem-alerts").status_code == 404
    texts = [e["text"] for e in activity(client) if e["actor"] == "admin"]
    assert "Added the extension SIEM alerts 1.0.0" in texts and "Extension SIEM alerts 2.0.0 enabled" in texts
    assert "Removed the extension siem-alerts and 1 record(s)" in texts


def test_purging_keeps_the_records_of_another_enabled_pack_while_extensions_are_off(client):
    upload(client, alerts_pack(), enable=True)
    assert client.post("/api/x/alerts", json={"fields": {"title": "Brute force"}}).status_code == 201
    upload(client, alerts_pack(id="other-alerts"))  # disabled, defines the same domain
    client.patch("/api/settings/guardrails", json={"allow_extensions": False})
    assert client.delete("/api/extensions/other-alerts?purge=true").json() == {"ok": True, "purged": 0}
    client.patch("/api/settings/guardrails", json={"allow_extensions": True})
    assert client.get("/api/x/alerts").json()["total"] == 1  # siem-alerts still defines them
    client.patch("/api/settings/guardrails", json={"allow_extensions": False})
    assert client.delete("/api/extensions/siem-alerts?purge=true").json() == {"ok": True, "purged": 1}


# -- records -----------------------------------------------------------------------------------------


def test_domain_records_are_typed_and_linked_to_assets_and_people(client, sign_in):
    hub = client.app.state.hub
    asset = client.post("/api/assets", json={"name": "web01", "facts": {"addresses": ["10.0.0.5", "web01.example.com"]}}).json()
    person = client.post("/api/people", json={"display_name": "Ann Smith", "email": "ann@example.com"}).json()
    upload(client, alerts_pack(), enable=True)
    viewer, operator = sign_in("viewer"), sign_in("operator")

    body = {"fields": {"title": "Brute force on web01", "severity": "Critical", "host": "WEB01.example.com:22",
                       "user": "Ann@Example.com", "detected": OLD, "link": "javascript:alert(1)"}}
    assert viewer.post("/api/x/alerts", json=body).status_code == 403
    refused = operator.post("/api/x/alerts", json=body)
    assert refused.status_code == 400 and "Link" in refused.json()["detail"]  # javascript: is not a link
    body["fields"]["link"] = "https://siem.example.com/alerts/1"
    created = operator.post("/api/x/alerts", json=body).json()
    assert created["fields"]["severity"] == "critical" and created["title"] == "Brute force on web01"
    assert created["fields"]["detected"] == pytest.approx(1577934245.0)
    assert (created["asset_id"], created["person_id"]) == (asset["id"], person["id"])
    assert created["asset"]["name"] == "web01" and created["person"]["display_name"] == "Ann Smith"
    for bad_fields, message in (({"status": "maybe"}, "Status must be one of open, closed"), ({"nope": 1}, "no field"),
                                ({"severity": "loud"}, "Severity must be")):
        response = operator.patch(f"/api/x/alerts/{created['id']}", json={"fields": bad_fields})
        assert response.status_code == 400 and message in response.json()["detail"], response.text
    assert operator.post("/api/x/alerts", json={"fields": {"severity": "low"}}).json()["detail"] == "Required: Title"

    # a link set by hand sticks, relink makes it automatic again
    record_id = created["id"]
    unlinked = operator.patch(f"/api/x/alerts/{record_id}", json={"person_id": None}).json()
    assert unlinked["person_id"] is None and unlinked["person_source"] == "manual"
    assert operator.patch(f"/api/x/alerts/{record_id}", json={"fields": {"status": "Closed"}}).json()["person_id"] is None
    relinked = operator.patch(f"/api/x/alerts/{record_id}", json={"relink": True}).json()
    assert relinked["person_id"] == person["id"] and relinked["fields"]["status"] == "closed"
    assert operator.patch(f"/api/x/alerts/{record_id}", json={"asset_id": "a_nope"}).status_code == 400

    listing = viewer.get(f"/api/x/alerts?asset_id={asset['id']}").json()
    assert listing["total"] == 1 and listing["records"][0]["source"] == "manual"
    assert viewer.get("/api/x/alerts?q=brute").json()["total"] == 1 and viewer.get("/api/x/alerts?q=zzz").json()["total"] == 0
    assert viewer.get(f"/api/x/alerts/{record_id}").json()["domain_def"]["key"] == "alerts"
    assert hub.store.get("x:alerts", record_id)["domain"] == "alerts"  # stored in the collection "x:alerts"
    assert operator.delete(f"/api/x/alerts/{record_id}").json() == {"ok": True}
    assert viewer.get(f"/api/x/alerts/{record_id}").status_code == 404


def test_value_coercion():
    defn = pack.parse(alerts_pack()).domains[0]
    fields, problems = records.coerce(defn, {"title": ["a", "b"], "severity": 9.8, "status": "CLOSED",
                                             "detected": 1700000000000, "host": {"name": "db01"}, "extra": "dropped"})
    assert problems == [] and fields == {"title": "a, b", "severity": "critical", "status": "closed",
                                         "detected": 1700000000.0, "host": "db01"}
    assert records.coerce(defn, {"severity": "high"})[1] == ["Title is required"]
    status = defn.field("status")
    assert records.coerce_value(status, "2 open") == "open" and records.coerce_value(status, "reopened") is None
    assert records.coerce_value(defn.field("link"), "data:text/html,x") is None
    assert records._severity("Disaster") == "critical" and records._severity("warning") == "medium"


# -- connectors and flows ----------------------------------------------------------------------------


def siem_api(alerts: list[dict], seen: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.url.host == "siem.example.com"
        if request.method == "GET" and request.url.path == "/api/alerts":
            return httpx.Response(200, json={"data": {"items": alerts}})
        return httpx.Response(404, json={"error": "not found"})
    return handler


def test_connector_pulls_an_extension_domain_into_linked_records_and_controls(client, wait_for):
    hub = client.app.state.hub
    asset = client.post("/api/assets", json={"name": "db01", "facts": {"address": "10.0.0.7"}}).json()
    add_tool(client, "wazuh", "Wazuh", provides=["siem"])
    data = alerts_pack()
    data["source_tool"] = "wazuh"
    data["items"].append({"kind": "connector", "base_url": "https://siem.example.com/api", "auth": "bearer",
                          "mapping": {"x:alerts": {
                              "list": {"path": "/alerts", "items": "data.items"},
                              "fields": {"external_id": "id", "title": "rule.description", "severity": "rule.severity",
                                         "status": "state", "host": "agent.ip", "detected": "timestamp"}}}})
    rec = upload(client, data, enable=True)
    assert rec["applied"] == {"wazuh": {"created": True, "domains": ["x:alerts"]}}
    assert any("enters its credentials" in n for n in rec["notes"])
    conn = client.get("/api/tools/wazuh/connection").json()
    assert conn["kind"] == "generic_rest" and conn["config"]["base_url"] == "https://siem.example.com/api"
    assert "x:alerts" in conn["config"]["mapping"]

    alerts = [{"id": "a1", "rule": {"description": "SSH brute force", "severity": "critical"}, "state": "open",
               "agent": {"ip": "10.0.0.7"}, "timestamp": OLD},
              {"id": "a2", "rule": {"description": "Port scan", "severity": "low"}, "state": "open",
               "agent": {"ip": "10.9.9.9"}, "timestamp": OLD}]
    seen: list[httpx.Request] = []
    hub.connector_transport = httpx.MockTransport(siem_api(alerts, seen))
    client.put("/api/tools/wazuh/connection", json={"kind": "generic_rest", "config": conn["config"],
                                                    "secrets": {"token": "siem-token-1234567"}})
    tested = client.post("/api/tools/wazuh/connection/test").json()
    assert tested["ok"] and tested["domains"] == {"x:alerts": ["read"]}
    flow = wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=wazuh").json() if f["domain"] == "x:alerts"), None))
    assert (flow["direction"], flow["owner"], flow["title"]) == ("pull", "module:extensions", "Wazuh alerts -> Hub Alerts")
    client.patch(f"/api/flows/{flow['id']}", json={"status": "enabled"})
    result = client.post(f"/api/flows/{flow['id']}/run").json()
    assert result["ok"] and result["counts"]["created"] == 2, result
    assert seen[-1].headers["authorization"] == "Bearer siem-token-1234567"
    listing = client.get("/api/x/alerts").json()
    by_id = {r["external_id"]: r for r in listing["records"]}
    assert by_id["a1"]["asset_id"] == asset["id"] and by_id["a1"]["source"] == "wazuh" and by_id["a1"]["source_name"] == "Wazuh"
    assert by_id["a2"]["asset_id"] is None and listing["records"][0]["external_id"] == "a1"  # most severe first

    # the pack's control rule: a critical alert open for more than 7 days fails HB-OP-2 (its own check passes)
    state = wait_for(lambda: (c := control(client, "HB-OP-2"))["status"] == "fail" and c)
    assert "Extension evidence: Critical alerts open for more than 7 days: 1 of 2 alerts (SSH brute force)" in state["detail"]
    assert any(e.startswith("siem-alerts:") for e in state["evidence"])

    # unchanged records are skipped; an alert the tool no longer reports turns stale (and stops counting)
    assert client.post(f"/api/flows/{flow['id']}/run").json()["counts"]["unchanged"] == 2
    alerts.pop(0)
    assert client.post(f"/api/flows/{flow['id']}/run").json()["counts"]["stale"] == 1
    assert client.get("/api/x/alerts").json()["total"] == 1 and client.get("/api/x/alerts?stale=true").json()["total"] == 2
    wait_for(lambda: control(client, "HB-OP-2")["status"] == "pass")

    # disabling the pack takes its mapping out again (the credentials stay: the connection is kept), and its flows
    client.patch("/api/extensions/siem-alerts", json={"status": "disabled"})
    assert client.get("/api/flows?tool_id=wazuh").json() == []
    kept = client.get("/api/tools/wazuh/connection").json()
    assert kept["kind"] == "generic_rest" and kept["secrets"] == {"token": True, "password": False}
    assert "x:alerts" not in kept["config"].get("mapping", {}) and kept["capabilities"] == {}
    assert client.get("/api/extensions/siem-alerts").json()["applied"] == {}
    # enabled again, the pack maps its domain into the kept connection; removing it takes the mapping out for good
    again = client.patch("/api/extensions/siem-alerts", json={"status": "enabled"}).json()
    assert again["applied"] == {"wazuh": {"created": False, "domains": ["x:alerts"]}}
    assert "x:alerts" in client.get("/api/tools/wazuh/connection").json()["config"]["mapping"]
    assert client.delete("/api/extensions/siem-alerts").status_code == 200
    assert "x:alerts" not in client.get("/api/tools/wazuh/connection").json()["config"].get("mapping", {})
    # no secret anywhere it should not be
    dump = json.dumps([client.get("/api/extensions").json(), activity(client), client.get("/api/messages?limit=2000").json()])
    assert "siem-token-1234567" not in dump


def test_extension_domains_push_through_generic_rest():
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(201, json={"ticket": {"id": 77}})

    mapping = {"x:tickets": {"create": {"path": "/tickets", "id": "ticket.id",
                                        "body": {"subject": "{title}", "prio": "{priority}"}},
                             "fields": {"external_id": "id"}}}
    config = GenericRestConnector.validate_config({"base_url": "https://desk.example.com", "auth": "none", "mapping": mapping})
    connector = GenericRestConnector(config, {}, httpx.MockTransport(handler))
    assert connector.domains() == {"x:tickets": ["write"]}
    results = asyncio.run(connector.push("x:tickets", [{"hub_id": "x_1", "title": "Laptop broken", "priority": "high"}], {}))
    assert results == [{"hub_id": "x_1", "external_id": "77", "action": "created", "error": None}]
    assert sent == [{"subject": "Laptop broken", "prio": "high"}]
    valid, errors = normalize("x:tickets", [{"external_id": 5, "title": "A", "Bad Key": 1, "tags": ["a", {"name": "b"}],
                                             "nested": {"name": "n"}}, {"title": "no id"}])
    assert valid == [{"external_id": "5", "title": "A", "tags": ["a", "b"], "nested": "n"}]
    assert errors == ["record 1: external_id is required"]


# -- compliance -------------------------------------------------------------------------------------


def snapshot(**guards) -> Snapshot:
    return Snapshot(tools=[], hosts=[], assets=[], risks=[], policies=[], patches=[], autonomy="assisted",
                    audit_entries=1, guardrails={**guardrails.defaults(), **guards})


def test_hb_cm_2_reflects_the_extension_and_self_patch_guardrails():
    def status(**guards) -> ControlState:
        return {s.id: s for s in evaluate_controls(snapshot(**guards), {})}["HB-CM-2"]

    assert status().status == "pass"
    for key in ("self_patch_requires_approval", "self_patch_requires_tests"):
        failed = status(**{key: False})
        assert failed.status == "fail" and guardrails.REGISTRY[key].title in failed.detail, key
    loose = status(extensions_need_approval=False)
    assert loose.status == "partial" and "extensions that agents generate are enabled without approval" in loose.detail
    # switching a capability off is not a weakness; via_pull_request off is not mapped to a control
    assert status(allow_extensions=False, allow_self_patching=False, self_patch_via_pull_request=False).status == "pass"
    catalog = {g["key"]: g for g in guardrails.catalog({**guardrails.defaults(), "allow_extensions": False})}
    assert catalog["allow_extensions"]["relaxed"] is False and catalog["extensions_need_approval"]["control"] == "HB-CM-2"
    assert catalog["self_patch_requires_tests"]["group"] == "self_patching"


def test_extension_evidence_takes_the_worse_status():
    def merged(base_status_guards: dict, results: list[dict]) -> dict[str, ControlState]:
        s = snapshot(**base_status_guards)
        s.extension_results = results
        return {x.id: x for x in evaluate_controls(s, {})}

    states = merged({}, [{"control": "HB-OP-2", "status": "partial", "detail": "2 alerts", "extension": "p"},
                         {"control": "HB-AC-3", "status": "fail", "detail": "1 thing", "extension": "p"},
                         {"control": "HB-AC-3", "status": "pass", "detail": "ok", "extension": "q"}])
    assert states["HB-OP-2"].status == "partial" and "Extension evidence: 2 alerts." in states["HB-OP-2"].detail
    assert states["HB-AC-3"].status == "fail"  # no hosts: "na" by itself, but the evidence found a problem
    only_pass = merged({}, [{"control": "HB-AC-3", "status": "pass", "detail": "ok", "extension": "p"}])["HB-AC-3"]
    assert only_pass.status == "na" and only_pass.evidence == ["p: ok"]  # passing evidence never upgrades "na"


# -- SSO recipes -------------------------------------------------------------------------------------


def test_sso_recipe_from_an_extension_connects_an_unknown_tool(client):
    hub = client.app.state.hub
    add_tool(client, "keycloak", "Keycloak", provides=["auth.oidc", "auth.saml"], ui={"url": "https://sso.example.com"})
    acme = add_tool(client, "acme", "Acme Desk", auth={"sso": "oidc"}, ui={"url": "https://acme.example.com"})
    provider = identity.list_providers(hub.tools(), {})[0]
    assert sso_catalog.match(acme) is None
    assert [g.kind for g in gaps.detect(hub, acme)] == ["sso"]
    recipe = {"kind": "sso", "key": "acme", "name": "Acme Desk", "match": ["acme"], "redirect_path": "/auth/oidc/callback",
              "file": "sso/acme.env",
              "template": "ACME_ISSUER={issuer}\nACME_CLIENT_ID={client_id}\nACME_SECRET={client_secret}\n"
                          "ACME_REDIRECT={redirect_uri}\nKEEP={tool.__class__}\n",
              "steps": ["Load sso/acme.env into {tool_name} and restart it."]}
    upload(client, {**alerts_pack(id="acme-sso"), "items": [recipe]}, enable=True)
    catalog = identity.load_prefs(hub).catalog
    assert [e.key for e in catalog] == ["x:acme"] and gaps.detect(hub, acme) == []
    config = sso_catalog.generate(acme, provider, catalog)
    text = config.files[0].content
    assert config.files[0].path == "sso/acme.env" and config.redirect_uris == ["https://acme.example.com/auth/oidc/callback"]
    assert "ACME_CLIENT_ID=hub-acme" in text and "ACME_SECRET=<generated-client-secret>" in text
    assert f"ACME_ISSUER={provider.client_issuer('hub-acme')}" in text and "KEEP={tool.__class__}" in text
    assert config.steps[0] == "Load sso/acme.env into Acme Desk and restart it."
    # the compatibility check picks it up: the Patch Agent can connect the tool natively
    client.post("/api/integration/evaluate")
    check = next(c for c in client.get("/api/tools/acme").json()["report"]["checks"] if c["id"] == "sso")
    assert check["fix"] == "sso_connect" and "Acme Desk supports OIDC natively" in check["detail"]
    client.patch("/api/extensions/acme-sso", json={"status": "disabled"})
    assert identity.load_prefs(hub).catalog == ()


# -- gaps, templates and the "extension" approval ---------------------------------------------------


def test_importing_a_siem_tool_proposes_a_template_extension_for_approval(client, sign_in, wait_for):
    tool_id = client.post("/api/tools/import", json={"source_type": "saas", "source": "https://wazuh.example.com",
                                                     "name": "Wazuh"}).json()["id"]
    [approval] = wait_for(lambda: pending(client, "extension"))
    payload = approval["payload"]
    assert approval["requested_by"] == "patcher" and payload["tool_id"] == tool_id and payload["designer"] == "templates"
    assert payload["summary"]["domains"] == ["alerts"] and payload["summary"]["controls"] == ["HB-IR-1"]
    assert payload["pack"]["status"] == "proposed" and {g["kind"] for g in payload["gaps"]} == {"domain"}
    assert approval["extension"]["status"] == "proposed" and approval["extension"]["approval_id"] == approval["id"]
    assert "Alerts from Wazuh 1.0.0 adds" in approval["detail"]
    listing = client.get("/api/extensions").json()
    assert listing["extensions"][0]["status"] == "proposed" and listing["domains"] == []

    operator = sign_in("operator")
    refused = operator.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    assert refused.status_code == 403 and "administrators" in refused.json()["detail"]
    client.post(f"/api/approvals/{approval['id']}", json={"approve": True})
    done = wait_for(lambda: (a := next(x for x in client.get("/api/approvals").json() if x["id"] == approval["id"]))["status"] == "done" and a)
    assert done["result"]["enabled"] is True
    ext = client.get(f"/api/extensions/{payload['extension_id']}").json()
    assert ext["status"] == "enabled" and ext["source_tool_name"] == "Wazuh"
    assert [d["key"] for d in client.get("/api/x").json()] == ["alerts"]
    # the pack's team template joins the SIEM team suggestions
    team = next(t for t in client.get("/api/agents/teams").json()["teams"] if t["team"] == tool_id)
    assert "Alert reviewer" in team["suggested"] and team["category_title"] == "SIEM / monitoring"
    # no gap left, and the hub does not propose again by itself
    assert client.post(f"/api/tools/{tool_id}/extend").json()["detail"] == "Atrium has no gap to close for Wazuh"
    assert sign_in("operator").post(f"/api/tools/{tool_id}/extend").status_code == 403


def test_rejected_proposal_and_auto_enable_when_approval_is_off(client, wait_for):
    hub = client.app.state.hub
    zammad = add_tool(client, "zammad", "Zammad", provides=["ticketing"], ui={"url": "https://desk.example.com"},
                      api={"type": "rest", "base_url": "https://desk.example.com"})
    found = gaps.detect(hub, zammad)
    assert [(g.kind, g.domain, g.needs_claude) for g in found] == [("domain", "tickets", False), ("connector", "tickets", False)]
    proposal = client.post("/api/tools/zammad/extend", json={"designer": "templates"}).json()
    assert proposal["proposed"] and proposal["approval_id"] and proposal["designer"] == "templates"
    approval = next(a for a in pending(client, "extension") if a["id"] == proposal["approval_id"])
    kinds = [i["kind"] for i in approval["payload"]["pack"]["items"]]
    assert kinds == ["domain", "team", "connector"]  # no compliance rule for tickets
    connector = approval["payload"]["pack"]["items"][2]
    assert connector["mapping"]["x:tickets"]["list"]["path"] == "/api/v1/tickets" and connector["auth_header"] == "Authorization"
    client.post(f"/api/approvals/{approval['id']}", json={"approve": False})
    wait_for(lambda: client.get(f"/api/extensions/{proposal['extension_id']}").json()["status"] == "disabled")
    assert client.get("/api/tools/zammad/connection").json()["kind"] is None  # nothing was applied
    assert hub.store.get("extensions", proposal["extension_id"])["history"][-1]["action"] == "rejected"

    # with the guardrail off, a generated pack is enabled at once (and logged as a warning), HB-CM-2 goes partial
    client.patch("/api/settings/guardrails", json={"extensions_need_approval": False})
    tool = add_tool(client, "alertmanager", "Alertmanager", provides=["monitoring.metrics"],
                    api={"type": "rest", "base_url": "http://alertmanager.example.com:9093"})
    result = client.post(f"/api/tools/{tool.id}/extend").json()
    assert result["enabled"] and result["approval_id"] is None and result["extension_id"] == "alertmanager-incidents"
    ext = client.get("/api/extensions/alertmanager-incidents").json()
    assert ext["status"] == "enabled" and ext["applied"]["alertmanager"]["domains"] == ["x:incidents"]
    conn = client.get("/api/tools/alertmanager/connection").json()
    assert conn["config"]["mapping"]["x:incidents"]["list"]["path"] == "/api/v2/alerts"
    assert conn["config"]["base_url"] == "http://alertmanager.example.com:9093"
    assert any(e["level"] == "warn" and "without approval" in e["text"] for e in activity(client))
    state = wait_for(lambda: (c := control(client, "HB-CM-2"))["status"] == "partial" and c)
    assert "extensions that agents generate are enabled without approval" in state["detail"]


def test_claude_cannot_point_a_generated_connector_at_another_host(client, monkeypatch):
    hub = client.app.state.hub
    graylog = add_tool(client, "graylog", "Graylog", provides=["logs.search"], api={"type": "rest"})  # no OpenAPI
    written = alerts_pack(id="graylog-alerts")
    written["items"].append({"kind": "connector", "tool": "wazuh", "base_url": "https://collector.attacker.example/api",
                             "mapping": {"x:alerts": {"list": {"path": "/events/search"}, "fields": {"external_id": "id"}}}})
    use_claude(hub, monkeypatch, json_result={"rationale": "x", "pack_json": json.dumps(written), "needs_code": False,
                                              "code_goal": ""})
    made, *_ = client.portal.call(generate.model_pack, hub, graylog, [])
    [item] = made.of("connector")
    assert (item.base_url, item.tool) == ("https://graylog.example.com", "graylog")  # the address the hub knows
    # the hub knows no address for the tool: the pack carries none (an administrator sets the connection up)
    notes = Tool(id="notes", name="Notes", source_type="local", source="/srv/notes", status="ready",
                 manifest=Manifest(id="notes", name="Notes", api={"type": "rest"}))
    hub.save_tool(notes)
    made, *_ = client.portal.call(generate.model_pack, hub, notes, [])
    assert made.of("connector")[0].base_url is None


def test_claude_writes_the_pack_with_structured_output(client, wait_for, monkeypatch):
    hub = client.app.state.hub
    add_tool(client, "graylog", "Graylog", provides=["logs.search"], api={"type": "rest"})
    written = alerts_pack(id="Graylog Alerts!")
    written["items"].append({"kind": "connector", "base_url": "https://graylog.example.com/api",
                             "mapping": {"x:alerts": {"list": {"path": "/events/search"}, "fields": {"external_id": "id"}}}})
    fake = use_claude(hub, monkeypatch, json_result={"rationale": "Graylog events become alerts.",
                                                     "pack_json": json.dumps(written), "needs_code": False, "code_goal": ""})
    result = client.post("/api/tools/graylog/extend", json={"designer": "claude"}).json()  # "claude": the old name
    assert result["designer"] == "model" and result["proposed"] and result["self_patch"] is None
    approval = next(a for a in pending(client, "extension") if a["id"] == result["approval_id"])
    pack_json = approval["payload"]["pack"]
    assert pack_json["id"] == "graylog-alerts" and pack_json["source_tool"] == "graylog"  # sanitized and attributed
    assert pack_json["items"][2]["tool"] == "graylog" and approval["detail"].startswith("Graylog events become alerts.")
    assert approval["payload"]["generated_by"] == {"provider": "anthropic", "model": "claude-opus-5-5"}
    call = fake.calls[0]
    assert call["schema"]["required"] == ["rationale", "pack_json", "needs_code", "code_goal"]
    assert "<pack_format>" in call["prompt"] and "HB-IR-1" in call["prompt"]

    # an unusable answer falls back to the templates
    add_tool(client, "splunk", "Splunk", provides=["siem"])
    use_claude(hub, monkeypatch, json_result={"rationale": "x", "pack_json": json.dumps({**alerts_pack(), "items": [{"kind": "exec"}]}),
                                              "needs_code": False, "code_goal": ""})
    # turning down Graylog's proposal leaves the alerts domain to model again
    client.patch(f"/api/extensions/{pack_json['id']}", json={"status": "disabled"})
    fallback = client.post("/api/tools/splunk/extend").json()
    assert fallback["designer"] == "templates" and fallback["proposed"]
    assert any("using the templates" in e["text"] for e in activity(client))


def test_removing_a_tool_withdraws_its_proposal_and_its_records_turn_stale(client):
    hub = client.app.state.hub
    upload(client, alerts_pack(), enable=True)
    add_tool(client, "wazuh", "Wazuh", provides=["siem"])
    records.save(hub, records.ExtRecord(domain="alerts", source="wazuh", external_id="a1", fields={"title": "Old"},
                                        title="Old"))
    add_tool(client, "zammad", "Zammad", provides=["ticketing"])
    proposal = client.post("/api/tools/zammad/extend").json()
    assert proposal["approval_id"]
    client.delete("/api/tools/zammad")
    withdrawn = next(a for a in client.get("/api/approvals").json() if a["id"] == proposal["approval_id"])
    assert withdrawn["status"] == "rejected" and "tool was removed" in withdrawn["note"]
    assert client.get(f"/api/extensions/{proposal['extension_id']}").json()["status"] == "disabled"
    assert client.get("/api/x/alerts").json()["total"] == 1
    client.delete("/api/tools/wazuh")
    assert client.get("/api/x/alerts").json()["total"] == 0 and client.get("/api/x/alerts?stale=true").json()["total"] == 1


def test_template_packs_for_the_three_kinds(client):
    hub = client.app.state.hub
    for tool_id, provides, domain, controls in (("ossec", ["siem"], "alerts", ["HB-IR-1"]),
                                                ("osticket", ["ticketing"], "tickets", []),
                                                ("zabbix", ["monitoring.uptime"], "incidents", ["HB-OP-1"])):
        tool = add_tool(client, tool_id, tool_id.capitalize(), provides=provides)
        found = gaps.detect(hub, tool)
        assert found[0].kind == "domain" and found[0].domain == domain
        built = gaps.template_pack(hub, tool, found)
        assert built is not None and built.summary()["domains"] == [domain] and built.summary()["controls"] == controls
        assert built.source_tool == tool_id and built.status == "proposed"
    assert gaps.template_pack(hub, add_tool(client, "notes", "Notes"), []) is None
    assert gaps.category(Tool(id="x", name="Uptime Kuma", source_type="saas", source="https://u.example.com")) == "monitoring"
