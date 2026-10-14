"""The segmentation read model (hub/integration/segmentation.py): zones, longest-prefix asset placement, allowed
traffic aggregated per interface (an over-approximation), the policy and its verdicts, overlays, the HB-NW-1
control, and the segmentation API with its roles (canvas-design 6.2-6.5, 7.5-7.6, 13/B2)."""

from __future__ import annotations

import pytest

from hub.connectors.netmodel import normalize_record
from hub.integration import network, segmentation
from hub.integration.segmentation import INTERNET, Topology, aggregate, evaluate_policy, place
from hub.models import Asset, Vulnerability


def record(rules: list[dict], **extra) -> dict:
    return normalize_record({
        "external_id": "fw", "revision": "1", "kind": "firewall",
        "interfaces": [
            {"id": "wan", "name": "WAN", "role": "wan", "subnets": ["203.0.113.0/29"]},
            {"id": "lan", "name": "LAN", "role": "lan", "subnets": ["10.0.0.0/16"]},
            {"id": "srv", "name": "SERVERS", "subnets": ["10.0.20.0/24"], "vlan": 20},
            {"id": "mgmt", "name": "MGMT", "subnets": ["10.0.99.0/24"], "vlan": 99},
            {"id": "guest", "name": "GUEST", "subnets": ["10.0.30.0/24"], "vlan": 30},
        ],
        "aliases": [{"name": "WEB", "cidrs": ["10.0.20.10"]}, {"name": "FEED", "kind": "url", "resolved": False}],
        "self_addresses": ["10.0.0.1", "203.0.113.2"],
        "rules": rules, **extra})


def topology(rules: list[dict], **extra) -> Topology:
    return Topology("fw", record(rules, **extra), {})


def edges(rules: list[dict], **extra) -> dict[tuple[str, str], dict]:
    return {(e["source"], e["target"]): e for e in aggregate(topology(rules, **extra))}


def z(native: str) -> str:
    return f"z:fw:{native}"


# -- zones --------------------------------------------------------------------------------------


def test_zones_from_interfaces_with_heuristic_roles():
    top = topology([])
    zones = {zone["id"]: zone for zone in top.zones}
    assert set(zones) == {INTERNET, z("lan"), z("srv"), z("mgmt"), z("guest")}  # WAN is the internet pseudo-zone
    assert zones[z("mgmt")]["role"] == "management" and zones[z("mgmt")]["lane"] == "core"
    assert zones[z("guest")]["role"] == "guest" and zones[z("srv")]["role"] == "servers"
    assert zones[z("lan")]["role"] == "users" and zones[z("lan")]["role_source"] == "heuristic"
    assert "role not confirmed" in zones[z("lan")]["badges"] and zones[z("srv")]["kind"] == "vlan"
    assert segmentation.heuristic_role("GUEST_LAN") == "guest" and segmentation.heuristic_role("xyz") == "unknown"
    with_override = Topology("fw", record([]), {z("srv"): {"role": "dev"}})
    srv = next(zone for zone in with_override.zones if zone["id"] == z("srv"))
    assert srv["role"] == "dev" and srv["role_source"] == "manual" and srv["badges"] == []


def test_vendor_zones_group_interfaces():
    rec = record([{"id": "p1", "action": "pass", "source_zones": ["inside"], "destination_zones": ["dmz"],
                   "source": {"any": True}, "destination": {"any": True}, "services": ["tcp/443"]}],
                 zones=[{"id": "inside", "name": "Inside", "interfaces": ["lan", "srv"]},
                        {"id": "dmz", "name": "DMZ", "interfaces": ["guest"]},
                        {"id": "outside", "interfaces": ["wan"]}])
    top = Topology("fw", rec, {})
    ids = {zone["id"] for zone in top.zones}
    assert z("inside") in ids and z("dmz") in ids and z("outside") not in ids  # WAN-only zone = internet
    found = {(e["source"], e["target"]) for e in aggregate(top)}
    assert found == {(z("inside"), z("dmz"))}


# -- placement ----------------------------------------------------------------------------------


def asset(asset_id: str, *addresses: str, status: str = "active") -> Asset:
    return Asset(id=asset_id, name=asset_id, type="server", status=status, facts={"addresses": list(addresses)})


def test_longest_prefix_placement():
    top = topology([])
    assets = [asset("a1", "10.0.20.5"),  # the /24 wins over the LAN's /16
              asset("a2", "10.0.1.7"),
              asset("a3", "10.0.20.6", "10.0.99.6"),  # multi-homed
              asset("a4", "8.8.8.8"),  # public, outside every zone: external
              asset("a5", "192.168.7.7"),  # private, outside every zone: unplaced
              asset("a6", "printer-3.lan"),  # hostname only: unplaced, no DNS lookups
              asset("a7", "10.0.20.9", status="retired"),
              asset("a8", "8.8.4.4", "10.0.30.8"),  # an internal match wins over a public address
              asset("a9", "10.0.20.0/28"),  # a CIDR inside a zone
              asset("a10", "10.0.20.0/23")]  # a CIDR wider than the zone: not inside it
    placed, unplaced = place(top, assets, {"a2": z("mgmt")})
    by_id = {a["id"]: a for a in placed}
    assert by_id["a1"]["zone"] == z("srv") and by_id["a1"]["placement"] == "subnet"
    assert by_id["a3"]["zone"] == z("srv") and by_id["a3"]["zones"] == [z("srv"), z("mgmt")]
    assert "multi-homed" in by_id["a3"]["badges"]
    assert by_id["a4"]["zone"] == INTERNET and "external" in by_id["a4"]["badges"]
    assert by_id["a8"]["zone"] == z("guest")
    assert by_id["a9"]["zone"] == z("srv")
    assert by_id["a2"]["zone"] == z("mgmt") and by_id["a2"]["placement"] == "manual"
    assert by_id["a2"]["warning"] and "LAN" in by_id["a2"]["warning"]  # its address says otherwise
    assert "a7" not in by_id and "a7" not in {u["id"] for u in unplaced}
    reasons = {u["id"]: u["reason"] for u in unplaced}
    assert reasons["a6"] == "hostname only" and "no zone contains 192.168.7.7" in reasons["a5"]
    assert by_id["a10"]["zone"] == z("lan")  # 10.0.20.0/23 lies within the LAN's /16 only


# -- allowed traffic --------------------------------------------------------------------------


def test_aggregation_is_interface_bound():
    found = edges([
        {"id": "lan-out", "action": "pass", "interfaces": ["lan"], "source": {"any": True},
         "destination": {"any": True}, "services": ["tcp/443"]},
        {"id": "wan-web", "action": "pass", "interfaces": ["wan"], "source": {"any": True},
         "destination": {"aliases": ["WEB"]}, "services": ["tcp/443", "tcp/80"]},
        {"id": "blocked", "action": "block", "interfaces": ["guest"], "source": {"any": True},
         "destination": {"any": True}},
        {"id": "off", "action": "pass", "enabled": False, "interfaces": ["guest"], "source": {"any": True},
         "destination": {"any": True}}])
    # a LAN rule with source any starts traffic in the LAN only: no edge from the internet
    assert (z("lan"), INTERNET) in found and (z("lan"), z("srv")) in found
    assert not any(src == INTERNET and rule_id == "lan-out" for (src, _), e in found.items()
                   for rule_id in [r["id"].split(":")[1] for r in e["rules"]])
    # a WAN rule is traffic from the internet
    web = found[(INTERNET, z("srv"))]
    assert {s["label"] for s in web["services"]} == {"HTTPS", "HTTP"} and web["approximate"]
    assert all(s != z("guest") for s, _ in found)  # block rules and disabled rules add nothing
    assert (z("lan"), z("lan")) not in found  # traffic within a zone does not cross the firewall


def test_floating_out_and_any_direction_rules():
    floating = edges([{"id": "f", "action": "pass", "source": {"cidrs": ["10.0.30.0/24"]},
                       "destination": {"cidrs": ["10.0.99.5"]}, "services": ["tcp/22"]}])
    assert set(floating) == {(z("guest"), z("mgmt"))}
    out = edges([{"id": "o", "action": "pass", "interfaces": ["srv"], "direction": "out", "source": {"any": True},
                  "destination": {"any": True}, "services": ["tcp/5432"]}])
    assert {d for _, d in out} == {z("srv")} and (INTERNET, z("srv")) in out
    both = edges([{"id": "b", "action": "pass", "interfaces": ["guest"], "direction": "any",
                   "source": {"any": True}, "destination": {"any": True}, "services": ["tcp/80"]}])
    assert (z("guest"), INTERNET) in both and (z("lan"), z("guest")) in both
    bidirectional = edges([
        {"id": "x", "action": "pass", "interfaces": ["lan"], "source": {"nets": ["lan"]},
         "destination": {"nets": ["srv"]}, "services": ["tcp/443"]},
        {"id": "y", "action": "pass", "interfaces": ["srv"], "source": {"nets": ["srv"]},
         "destination": {"nets": ["lan"]}, "services": ["tcp/22"]}])
    assert bidirectional[(z("lan"), z("srv"))]["bidirectional"] is True


def test_unresolved_aliases_and_any_service_are_noted():
    found = edges([{"id": "feed", "action": "pass", "interfaces": ["wan"], "source": {"aliases": ["FEED"]},
                    "destination": {"nets": ["srv"]}}])
    edge = found[(INTERNET, z("srv"))]
    assert "unresolved alias FEED" in edge["notes"] and edge["any_service"] is True and edge["services"] == []


# -- policy -------------------------------------------------------------------------------------


def evaluate(found: dict, top: Topology, rules: list[dict] | None = None) -> dict[tuple[str, str], list[dict]]:
    zones = {zone["id"]: zone for zone in top.zones}
    return {k: evaluate_policy(e, zones, rules or segmentation.DEFAULT_POLICY) for k, e in found.items()}


def test_policy_verdicts():
    rules = [{"id": "g", "action": "pass", "interfaces": ["guest"], "source": {"any": True},
              "destination": {"any": True}, "services": ["tcp/443"]},
             {"id": "w", "action": "pass", "interfaces": ["wan"], "source": {"any": True},
              "destination": {"nets": ["mgmt"]}, "services": ["tcp/22"]},
             {"id": "aa", "action": "pass", "interfaces": ["lan"], "source": {"any": True},
              "destination": {"any": True}}]
    top = topology(rules)
    verdicts = evaluate({(e["source"], e["target"]): e for e in aggregate(top)}, top)
    assert {v["policy"] for v in verdicts[(z("guest"), z("srv"))]} == {"guest-iot-isolated"}
    assert verdicts[(z("guest"), INTERNET)] == []
    wan_mgmt = {v["policy"] for v in verdicts[(INTERNET, z("mgmt"))]}
    assert wan_mgmt == {"untrusted-to-management", "internet-must-hit-dmz"}
    assert all(v["possible"] and v["verdict"] == "forbidden" for v in verdicts[(INTERNET, z("mgmt"))])
    assert "no-any-any" in {v["policy"] for v in verdicts[(z("lan"), z("srv"))]}


def test_restricted_rules_exceptions_and_unclassified_zones():
    top = Topology("fw", record([{"id": "d", "action": "pass", "interfaces": ["srv"], "source": {"nets": ["srv"]},
                                  "destination": {"nets": ["lan"]}, "services": ["tcp/443"]}]),
                   {z("srv"): {"role": "dev"}, z("lan"): {"role": "servers"}})
    found = {(e["source"], e["target"]): e for e in aggregate(top)}
    restricted = [{"id": "r", "from": ["dev"], "to": ["servers"], "verdict": "restricted", "control": "HB-NW-1",
                   "except_services": [{"proto": "tcp", "ports": "443"}]}]
    assert evaluate(found, top, restricted)[(z("srv"), z("lan"))] == []
    assert evaluate(found, top, [{**restricted[0], "except_services": [{"proto": "tcp", "ports": "22"}]}])[
        (z("srv"), z("lan"))][0]["verdict"] == "restricted"
    exception = [{"id": "ok", "from": ["dev"], "to": ["servers"], "verdict": "allowed"}, *restricted[:0],
                 {"id": "no", "from": ["dev"], "to": ["servers"], "verdict": "forbidden"}]
    assert evaluate(found, top, exception)[(z("srv"), z("lan"))] == []
    unknown = Topology("fw", record([{"id": "u", "action": "pass", "interfaces": ["lan"], "source": {"any": True},
                                      "destination": {"nets": ["srv"]}, "services": ["tcp/1"]}]),
                       {z("srv"): {"role": "unknown"}})
    edge = aggregate(unknown)[0]
    evaluate_policy(edge, {zone["id"]: zone for zone in unknown.zones}, segmentation.DEFAULT_POLICY)
    assert edge["evaluable"] is False and "cannot evaluate: unclassified zone" in edge["notes"]


def test_policy_validation():
    with pytest.raises(ValueError):
        segmentation.Policy.model_validate({"rules": [{"id": "x", "from": ["guest"], "verdict": "forbidden"}]})
    with pytest.raises(ValueError):
        segmentation.Policy.model_validate({"rules": [{"id": "x", "from": ["moon"], "to": ["users"],
                                                       "verdict": "forbidden"}]})
    with pytest.raises(ValueError):
        segmentation.Policy.model_validate({"rules": [{"id": "x", "from": ["dev"], "to": ["users"],
                                                       "verdict": "forbidden", "except_services": [{"proto": "tcp"}]}]})
    segmentation.Policy.model_validate({"rules": segmentation.DEFAULT_POLICY})


# -- the hub: overlays, control, API --------------------------------------------------------------


def ingest(hub, tool_id: str, rec: dict) -> None:
    network.ingest(hub, tool_id, {**rec, "external_id": tool_id})


def grc_control(client, control_id: str) -> dict:
    client.post("/api/grc/evaluate")
    return next(c for c in client.get("/api/grc").json()["controls"] if c["id"] == control_id)


def test_map_overlays_control_and_roles(client, sign_in):
    hub = client.app.state.hub
    assert client.get("/api/segmentation").json()["firewalls"] == []
    assert grc_control(client, "HB-NW-1")["status"] == "manual"
    ingest(hub, "fw", record([{"id": "web", "action": "pass", "interfaces": ["wan"], "source": {"any": True},
                               "destination": {"aliases": ["WEB"]}, "services": ["tcp/443"]},
                              {"id": "dns", "action": "pass", "interfaces": ["srv"], "source": {"nets": ["srv"]},
                               "destination": {"any": True}, "services": ["udp/53"]}],
                             aliases=[{"name": "WEB", "cidrs": ["10.0.20.10"]}]))
    a = client.post("/api/assets", json={"name": "web-1", "type": "server", "facts": {"addresses": ["10.0.20.10"]}})
    assert a.status_code == 201, a.text
    asset_id = a.json()["id"]
    for severity, port in (("critical", "443/tcp"), ("high", "22/tcp")):
        hub.save("vulnerabilities", Vulnerability(id=f"v_{severity}", title=f"{severity} bug", severity=severity,
                                                  asset_id=asset_id, host="10.0.20.10", port=port))
    view = client.get("/api/segmentation").json()
    assert view["selected"] == "fw" and view["evaluation"]["mode"] == "approximate"
    assert view["firewalls"][0]["writable"] is False and view["guardrails"]["device_changes"] is False
    zones = {zone["id"]: zone for zone in view["zones"]}
    assert zones[z("srv")]["asset_count"] == 1 and zones[z("srv")]["vuln"]["critical"] == 1
    edge = next(e for e in view["edges"] if e["source"] == INTERNET and e["target"] == z("srv"))
    assert edge["exposure"] == {"critical": 1, "high": 0, "not_on_allowed_ports": {"critical": 0, "high": 1}}
    assert {v["policy"] for v in edge["violations"]} == {"internet-must-hit-dmz"}
    assert view["assets"][0]["vuln"] == {"critical": 1, "high": 1, "overdue": 0}
    nw1 = grc_control(client, "HB-NW-1")
    assert nw1["status"] == "partial" and "internet -> servers on fw" in nw1["detail"]

    viewer, operator = sign_in("viewer"), sign_in("operator")
    assert viewer.get(f"/api/segmentation?firewall=fw").status_code == 200
    assert viewer.get("/api/segmentation?firewall=nope").status_code == 404
    # zone roles and the policy are admin decisions; placement is an operator's drawing aid
    assert operator.patch(f"/api/segmentation/zones/{z('srv')}", json={"role": "dmz"}).status_code == 403
    assert client.patch("/api/segmentation/zones/z:fw:nope", json={"role": "dmz"}).status_code == 404
    assert client.patch(f"/api/segmentation/zones/{z('srv')}", json={"role": "moon"}).status_code == 422
    changed = client.patch(f"/api/segmentation/zones/{z('srv')}", json={"role": "dmz", "label": "Web DMZ"})
    assert changed.status_code == 200 and changed.json()["role"] == "dmz"
    srv = next(zone for zone in client.get("/api/segmentation").json()["zones"] if zone["id"] == z("srv"))
    assert srv["role"] == "dmz" and srv["role_source"] == "manual" and srv["label"] == "Web DMZ"
    assert viewer.put(f"/api/segmentation/placements/{asset_id}", json={"zone_id": z("mgmt")}).status_code == 403
    placed = operator.put(f"/api/segmentation/placements/{asset_id}", json={"zone_id": z("mgmt")})
    assert placed.status_code == 200 and "does not change the network" in placed.json()["note"]
    moved = next(x for x in client.get("/api/segmentation").json()["assets"] if x["id"] == asset_id)
    assert moved["zone"] == z("mgmt") and moved["placement"] == "manual" and moved["warning"]
    assert operator.put(f"/api/segmentation/placements/{asset_id}", json={"zone_id": "z:fw:nope"}).status_code == 400
    assert operator.put("/api/segmentation/placements/a_missing", json={"zone_id": None}).status_code == 404
    assert operator.put(f"/api/segmentation/placements/{asset_id}", json={"zone_id": None}).status_code == 200

    # with every role confirmed and nothing violating the policy, HB-NW-1 passes
    for native, role in (("lan", "users"), ("mgmt", "management"), ("guest", "guest")):
        assert client.patch(f"/api/segmentation/zones/{z(native)}", json={"role": role}).status_code == 200
    nw1 = grc_control(client, "HB-NW-1")
    assert nw1["status"] == "pass", nw1

    policy = client.get("/api/segmentation/policy").json()
    assert policy["version"] == 0 and policy["default"] and len(policy["defaults"]) == 5
    strict = {"rules": [{"id": "no-dmz-to-internet", "from": ["dmz"], "to": ["internet"], "verdict": "forbidden",
                         "control": "HB-NW-1"}]}
    assert operator.put("/api/segmentation/policy", json=strict).status_code == 403
    assert client.put("/api/segmentation/policy", json={"rules": [{"id": "Bad Id"}]}).status_code == 400
    saved = client.put("/api/segmentation/policy", json=strict)
    assert saved.status_code == 200 and saved.json()["version"] == 1
    assert client.get("/api/segmentation").json()["policy_version"] == 1
    assert grc_control(client, "HB-NW-1")["status"] == "partial"  # the DMZ's DNS rule reaches the internet
