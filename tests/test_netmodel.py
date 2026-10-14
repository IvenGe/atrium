"""The network domain's shapes and helpers (hub/connectors/netmodel.py) and the device connector contract in base.py."""

from __future__ import annotations

import asyncio
import copy

import pytest

from hub.connectors import netmodel
from hub.connectors.base import Connector, ConnectorError, normalize
from hub.connectors.fake_firewall import FakeDevice
from hub.connectors.netmodel import (ChangeError, diff_records, exposes_management, inverse_ops, is_any_any,
                                     management_guard, normalize_record, ops_applied, ops_diff, ops_hash, ops_reverted,
                                     parse_ops, record_hash, rule_matches_allow, validate_write_spec)


def fake_record(name: str = "fw1") -> dict:
    return normalize_record(FakeDevice(name).record())


def allow(**overrides) -> dict:
    op = {"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
          "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]}, "services": [{"proto": "tcp", "ports": "443"}],
          "log": True, "description": "Users to intranet", "marker": "atrium:chg_1"}
    return {**op, **overrides}


# -- normalisation ----------------------------------------------------------------------


def test_normalises_the_fake_device():
    record = fake_record()
    assert record["external_id"] == "fw1" and record["revision"] == "r1" and record["kind"] == "firewall"
    assert record["device"]["vendor"] == "Atrium" and record["errors"] == []
    assert [r["id"] for r in record["rules"]] == ["r1", "r2", "r3", "r4", "r5", "r6", "r7"]
    lan = next(i for i in record["interfaces"] if i["id"] == "lan")
    assert lan["subnets"] == ["10.0.10.0/24"] and lan["role"] == "lan"
    r3 = next(r for r in record["rules"] if r["id"] == "r3")
    assert r3["vendor_ref"] == "2f3a-web-in" and r3["source"]["any"] is True
    assert r3["destination"]["cidrs"] == ["10.0.20.10/32"] and r3["services"] == [
        {"proto": "tcp", "ports": "443", "alias": None, "name": ""}]
    r2 = next(r for r in record["rules"] if r["id"] == "r2")
    assert r2["services"] is None and r2["destination"]["any"] is True and r2["source"]["nets"] == ["lan"]
    assert next(a for a in record["aliases"] if a["name"] == "BLOCKLIST")["resolved"] is False
    assert "secrets" not in str(record)  # the backup-only part of the fake never appears in a read


def test_bad_entries_are_dropped_with_a_message_and_text_is_cleaned():
    record = normalize_record({
        "external_id": "fw\x00x", "revision": 7, "kind": "router",
        "interfaces": [{"id": "lan", "subnets": ["10.0.0.9/24"], "vlan": "12"},
                       {"id": "bad", "subnets": ["not-a-network"]}],
        "rules": [{"id": "a", "order": 2, "action": "accept", "description": "evil‮text\x1b[31m",
                   "services": [{"proto": "tcp/udp", "ports": "53"}, "443/tcp"], "source": {}, "destination": {"cidrs": "10.0.0.1"}},
                  {"id": "b", "order": 1, "action": "explode"},
                  {"id": "a", "order": 3}],
    })
    assert record["external_id"] == "fwx" and record["revision"] == "7" and record["kind"] == "router"
    assert record["interfaces"][0]["subnets"] == ["10.0.0.0/24"] and record["interfaces"][0]["vlan"] == 12
    assert [r["id"] for r in record["rules"]] == ["a"]
    rule = record["rules"][0]
    assert rule["action"] == "pass" and rule["source"]["any"] and rule["floating"]
    assert "‮" not in rule["description"] and "\x1b" not in rule["description"]
    assert [(s["proto"], s["ports"]) for s in rule["services"]] == [("tcp", "53"), ("udp", "53"), ("tcp", "443")]
    assert len(record["errors"]) == 3  # bad subnet, unknown action, duplicate id
    assert any("duplicate" in e for e in record["errors"])


def test_record_level_problems_raise():
    with pytest.raises(ValueError):
        normalize_record({"external_id": "x"})  # no revision
    with pytest.raises(ValueError):
        normalize_record({"external_id": "x", "revision": "1", "kind": "toaster"})
    valid, errors = normalize("network", [{"external_id": "a", "revision": "1"}, {"external_id": "b", "revision": "1"}])
    assert len(valid) == 1 and "only the first is used" in errors[0]


def test_record_hash_ignores_counters_and_read_times():
    record = fake_record()
    again = copy.deepcopy(record)
    again["read_at"], again["revision"] = 1.0, "r99"
    again["rules"][1]["hits"] = 999999
    assert record_hash(record) == record_hash(again)
    again["rules"][1]["description"] = "changed"
    assert record_hash(record) != record_hash(again)


def test_markers_are_read_back_from_descriptions():
    record = normalize_record({"external_id": "x", "revision": "1",
                               "rules": [{"id": "n1", "description": "atrium:chg_42 Users to web"}]})
    assert record["rules"][0]["marker"] == "chg_42"
    assert netmodel.marker("chg_42") == "atrium:chg_42"
    with pytest.raises(ValueError):
        netmodel.marker("bad id; rm -rf")


# -- change operations -----------------------------------------------------------------


def test_allow_ops_are_explicit():
    parsed = parse_ops([allow()])
    assert parsed[0]["services"] == [{"proto": "tcp", "ports": "443"}]
    for bad in (allow(destination={"zone": "opt1", "cidrs": ["0.0.0.0/0"]}),
                allow(services=[{"proto": "tcp"}]),
                allow(services=[{"proto": "any", "ports": "1"}]),
                allow(services=[{"proto": "tcp", "ports": str(p)} for p in range(1, 18)]),
                allow(marker="chg_1"), allow(extra=True), allow(source={"zone": "lan", "cidrs": []})):
        with pytest.raises(ValueError):
            parse_ops([bad])
    with pytest.raises(ValueError):
        parse_ops([])
    assert parse_ops([{"op": "enable_rules", "rules": [{"id": "r2"}]}])[0]["rules"] == [{"id": "r2", "vendor_ref": "r2"}]


def test_ops_hash_is_canonical():
    one = allow()
    reordered = {k: one[k] for k in reversed(list(one))}
    assert ops_hash([one]) == ops_hash([reordered]) and ops_hash([one]).startswith("sha256:")
    assert ops_hash([one]) != ops_hash([allow(log=False)])


def test_management_guard_protects_the_management_path():
    record = fake_record()
    problems = management_guard(record, parse_ops([{"op": "disable_rules", "rules": [{"id": "r1"}]}]))
    assert problems and "cut the hub off" in problems[0]
    assert management_guard(record, parse_ops([{"op": "disable_rules", "rules": [{"id": "r3"}]}])) == []
    assert "not on the device" in management_guard(record, parse_ops([{"op": "disable_rules",
                                                                         "rules": [{"id": "gone"}]}]))[0]
    # "LAN to any" reaches the device's own LAN address: refused as well while the hub's address is unknown
    lan_any = parse_ops([{"op": "disable_rules", "rules": [{"id": "r2"}]}])
    assert management_guard(record, lan_any)
    # a connector that knows where the hub connects from (and on which port) narrows it
    assert management_guard(record, lan_any, hub_addresses=["10.0.99.10"], management_ports=[443]) == []
    assert management_guard(record, lan_any, hub_addresses=["10.0.10.5"], management_ports=[443])
    anti_lockout = parse_ops([{"op": "disable_rules", "rules": [{"id": "r1"}]}])
    assert management_guard(record, anti_lockout, hub_addresses=["10.0.99.10"], management_ports=[443])
    assert management_guard(record, anti_lockout, hub_addresses=["10.0.99.10"], management_ports=[8443]) == []


def test_exposure_and_any_any():
    record = normalize_record({**FakeDevice("x").record(), "rules": [
        {"id": "ssh", "action": "pass", "interfaces": ["wan"], "source": {"any": True}, "destination": {"self": True},
         "services": [{"proto": "tcp", "ports": "22"}]},
        {"id": "web", "action": "pass", "interfaces": ["wan"], "source": {"any": True},
         "destination": {"cidrs": ["10.0.20.10"]}, "services": [{"proto": "tcp", "ports": "443"}]},
        {"id": "lan-ssh", "action": "pass", "interfaces": ["lan"], "source": {"any": True},
         "destination": {"self": True}, "services": [{"proto": "tcp", "ports": "22"}]},
        {"id": "anyany", "action": "pass", "source": {"any": True}, "destination": {"any": True}}]})
    rules = {r["id"]: r for r in record["rules"]}
    assert exposes_management(record, rules["ssh"]) and not exposes_management(record, rules["web"])
    assert not exposes_management(record, rules["lan-ssh"])  # from the LAN, not from anywhere
    assert exposes_management(record, rules["anyany"]) and is_any_any(rules["anyany"]) and not is_any_any(rules["ssh"])


def test_diff_records_reports_every_kind():
    old = fake_record()
    new = copy.deepcopy(old)
    new["rules"] = [r for r in new["rules"] if r["id"] != "r6"]
    next(r for r in new["rules"] if r["id"] == "r4")["enabled"] = False
    next(r for r in new["rules"] if r["id"] == "r3")["services"] = [{"proto": "tcp", "ports": "8443", "alias": None,
                                                                      "name": ""}]
    new["rules"].append(normalize_record({"external_id": "x", "revision": "1", "rules": [
        {"id": "r9", "action": "pass", "source": {"any": True}, "destination": {"any": True},
         "description": "temp"}]})["rules"][0])
    next(i for i in new["interfaces"] if i["id"] == "opt3")["subnets"] = ["10.0.31.0/24"]
    new["default_policy"] = {"inbound": "pass"}
    kinds = sorted(item["kind"] for item in diff_records(old, new))
    assert kinds == sorted(["rule_removed", "rule_disabled", "rule_changed", "rule_added", "interface_changed",
                            "default_policy_changed", "any_any_introduced", "management_exposed"])
    critical = [i for i in diff_records(old, new) if i["severity"] == "critical"]
    assert {i["kind"] for i in critical} == {"any_any_introduced", "management_exposed"}
    assert diff_records(old, copy.deepcopy(old)) == []


def test_preview_diff_verification_and_inverse():
    record = fake_record()
    ops = parse_ops([allow(), {"op": "disable_rules", "rules": [{"id": "r4", "vendor_ref": "3b4c-guest-web"}]}])
    text = ops_diff(record, ops)
    assert "+ pass in on lan from 10.0.10.0/24 to 10.0.20.0/24 tcp/443 log  # atrium:chg_1 Users to intranet" in text
    assert "- pass in on opt3" in text and "[disabled]" in text
    assert ops_applied(record, ops)  # nothing applied yet: problems
    after = copy.deepcopy(record)
    after["rules"].insert(0, {**netmodel._op_rule(ops[0]), "id": "n1", "vendor_ref": "n1", "marker": "chg_1",
                              "source": {"any": False, "cidrs": ["10.0.10.0/24"], "aliases": [], "nets": [],
                                         "self": False, "negate": False},
                              "destination": {"any": False, "cidrs": ["10.0.20.0/24"], "aliases": [], "nets": [],
                                              "self": False, "negate": False}})
    next(r for r in after["rules"] if r["id"] == "r4")["enabled"] = False
    assert ops_applied(after, ops) == []
    assert ops_reverted(record, after, ops)  # still applied
    assert ops_reverted(record, record, ops) == []
    wider = copy.deepcopy(after)
    wider["rules"][0]["services"] = [{"proto": "tcp", "ports": "1-65535"}]
    assert not rule_matches_allow(wider["rules"][0], ops[0]) and ops_applied(wider, ops)
    # a zone-based product writes address objects: they are resolved with the device's record
    objects = normalize_record({"external_id": "x", "revision": "1",
                                "aliases": [{"name": "atrium-src", "cidrs": ["10.0.10.0/24"]},
                                            {"name": "atrium-dst", "cidrs": ["10.0.20.0/24"]}],
                                "rules": [{"id": "p1", "action": "pass", "source": {"aliases": ["atrium-src"]},
                                           "destination": {"aliases": ["atrium-dst"]}, "services": ["tcp/443"],
                                           "description": "atrium:chg_1"}]})
    assert rule_matches_allow(objects["rules"][0], ops[0], objects)
    assert not rule_matches_allow(objects["rules"][0], ops[0])
    assert ops_applied(objects, ops[:1]) == []
    undo = inverse_ops(ops, {"created": [{"op": 0, "id": "n1", "vendor_ref": "n1"}]})
    assert undo == [{"op": "disable_rules", "rules": [{"id": "n1", "vendor_ref": "n1"}]},
                    {"op": "enable_rules", "rules": [{"id": "r4", "vendor_ref": "3b4c-guest-web"}]}]
    with pytest.raises(ValueError):
        inverse_ops(ops, {"created": []})


def test_write_spec_validation():
    assert validate_write_spec(None) is None
    assert validate_write_spec({"ops": ["allow", "teleport"], "rollback": "savepoint", "window_s": 60}) == {
        "ops": ["allow"], "rollback": "savepoint", "window_s": 60}
    with pytest.raises(ValueError):
        validate_write_spec({"ops": ["allow"], "rollback": "hope", "window_s": 60})
    with pytest.raises(ValueError):
        validate_write_spec({"ops": ["allow"], "rollback": "deadman", "window_s": 5})
    assert netmodel.derived_revision({"a": 1}) == netmodel.derived_revision({"a": 1}) != netmodel.derived_revision({})


# -- the connector contract ------------------------------------------------------------


def test_write_methods_can_never_be_actions():
    for name in ("apply_change", "backup", "restore_backup", "allow", "disable_rules", "confirm_change"):
        with pytest.raises(TypeError):
            type("Bad", (Connector,), {"kind": "bad", "actions": {name}})
    with pytest.raises(ValueError):
        type("BadSpec", (Connector,), {"kind": "bad", "network_write": {"ops": ["allow"], "rollback": "x"}})


def test_unimplemented_write_methods_refuse():
    class ReadOnly(Connector):
        kind = "ro"
        capabilities = {"network": {"read"}}
        network_write = {"ops": ["allow"], "rollback": "savepoint", "window_s": 60}

    connector = ReadOnly({}, {})
    assert connector.write_capability() is None  # declared, but the methods are missing
    assert ReadOnly.describe()["can_backup"] is False
    with pytest.raises(ChangeError) as caught:
        asyncio.run(connector.apply_change([allow()], "r1", None))
    assert caught.value.code == "unsupported" and caught.value.state == "unchanged"
    assert isinstance(caught.value, ConnectorError)


def test_ssh_settings_helpers():
    config = netmodel.validate_ssh_config({"host": "fw1.example.net", "port": "2222", "username": "CORP\\atrium",
                                           "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK0 fw1"})
    assert config["port"] == 2222
    for bad in ({"host": "-oProxyCommand=x", "username": "a"}, {"host": "fw 1", "username": "a"},
                {"host": "fw1", "username": "a b"}, {"host": "fw1", "username": "a", "port": 70000},
                {"host": "fw1", "username": "a", "host_key": "not a key"}):
        with pytest.raises(ValueError):
            netmodel.validate_ssh_config(bad)
    with pytest.raises(ConnectorError):
        netmodel.ssh_target(config, {})
    target = netmodel.ssh_target(config, {"private_key": "KEY"})
    assert target.port == 2222 and target.strict_host_keys and "KEY" not in repr(target)
    assert [f.name for f in netmodel.SSH_FIELDS][:3] == ["host", "port", "username"]


# documents a device could send to get entities declared: a DOCTYPE after more than 64 KiB of comment (beyond any
# prefix scan) and one in UTF-16 (invisible to a byte scan for "<!DOCTYPE"); each would expand &b; if parsed
ENTITIES = '<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
UNSAFE_XML = [
    ("<!--" + "x" * 70_000 + "-->" + ENTITIES + "<{root}>&b;</{root}>").encode(),
    ('<?xml version="1.0" encoding="UTF-16"?>' + ENTITIES + "<{root}>&b;</{root}>").encode("utf-16"),
    ('<?xml version="1.0"?><!DOCTYPE {root} SYSTEM "file:///etc/passwd"><{root}/>').encode(),
]


def unsafe(root: str) -> list[bytes]:
    return [doc.replace(b"{root}", root.encode()) if b"{root}" in doc
            else doc.decode("utf-16").replace("{root}", root).encode("utf-16") for doc in UNSAFE_XML]


def test_device_xml_never_declares_entities():
    import xml.etree.ElementTree as ET

    from hub.connectors import cisco_iosxe, hostfw, panos, pfsense

    for doc in unsafe("r"):
        with pytest.raises(netmodel.UnsafeXml):
            netmodel.parse_untrusted_xml(doc)
    with pytest.raises(netmodel.UnsafeXml):
        netmodel.parse_untrusted_xml("<!--" + "x" * 70_000 + '--><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>')  # str
    with pytest.raises(ET.ParseError, match="undefined entity"):  # no DTD: entity references go nowhere
        netmodel.parse_untrusted_xml(b"<r>&a;</r>")
    padded = b"<!--" + b"x" * 70_000 + b'--><r a="1"><x>caf\xc3\xa9</x></r>'
    assert netmodel.parse_untrusted_xml(padded).find("x").text == "café"  # long comments alone are fine
    assert netmodel.parse_untrusted_xml("<r><![CDATA[<!DOCTYPE x>]]></r>").text == "<!DOCTYPE x>"  # data, not a DTD

    for doc in unsafe("response"):
        with pytest.raises(ConnectorError, match="DOCTYPE"):
            panos.parse_xml(doc)
    for doc in unsafe("pfsense"):
        with pytest.raises(ValueError, match="DOCTYPE"):
            pfsense.parse_config_xml(doc)
    for doc in unsafe("rpc-reply"):
        with pytest.raises(cisco_iosxe.NetconfError, match="DOCTYPE"):
            cisco_iosxe.parse_xml(doc)
    padded_service = "<!--" + "x" * 70_000 + "-->" + ENTITIES + '<service><port protocol="tcp" port="1"/></service>'
    services = hostfw.parse_services("### atrium-service evil.xml\n" + padded_service + "\n### atrium-service ok.xml\n"
                                     '<service><port protocol="tcp" port="2"/></service>\n')
    assert "evil" not in services and services["ok"] == [("tcp", "2")]
