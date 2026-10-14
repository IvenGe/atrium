"""The PAN-OS connector against a fake PAN-OS XML API (httpx.MockTransport, no network). The fake follows the research
doc (docs/research/fw-fortigate-panos-cisco.md section 3) and pan-os-python: form-encoded POSTs to /api/ with
X-PAN-KEY, <response status=... code=...> answers, a running and a candidate configuration (show reads the running
one, set/delete/move change the candidate), partial commits as jobs polled with <show><jobs> (FIN / OK / FAIL),
pending changes, locks, partial revert, save/load of named snapshots, export and import of the configuration."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from email.parser import BytesParser
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from hub.connectors.base import normalize
from hub.connectors.netmodel import (Backup, ChangeError, exposes_management, inverse_ops, ops_applied, ops_reverted,
                                     parse_ops)
from hub.connectors.panos import PanosConnector, parse_version
from hub.integration.connections import clean_config

KEY = "LUFRPT1panos-api-key-0123456789abcdef=="
BASE = "https://pa.example.net"
ADMIN = "atrium-api"
PHASH = "$5$panos-admin-password-hash-do-not-leak"
VSYS = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"

RUNNING = f"""<config version="11.1.0" urldb="paloaltonetworks">
<mgt-config><users>
  <entry name="{ADMIN}"><phash>{PHASH}</phash><permissions><role-based><superuser>yes</superuser></role-based>
  </permissions></entry>
</users></mgt-config>
<shared>
  <address><entry name="shared-dns"><ip-netmask>10.0.0.53</ip-netmask></entry></address>
  <service><entry name="shared-ntp"><protocol><udp><port>123</port></udp></protocol></entry></service>
</shared>
<devices><entry name="localhost.localdomain">
  <network>
    <interface>
      <ethernet>
        <entry name="ethernet1/1"><layer3><ip><entry name="203.0.113.2/29"/></ip>
          <interface-management-profile>ping-only</interface-management-profile></layer3></entry>
        <entry name="ethernet1/2"><layer3><ip><entry name="10.0.10.1/24"/></ip>
          <interface-management-profile>allow-mgmt</interface-management-profile>
          <units><entry name="ethernet1/2.30"><tag>30</tag><ip><entry name="10.0.30.1/24"/></ip></entry></units>
        </layer3></entry>
        <entry name="ethernet1/3"><layer3><ip><entry name="srv-gw"/></ip></layer3></entry>
        <entry name="ethernet1/4"><layer3><dhcp-client/></layer3></entry>
      </ethernet>
      <loopback><units><entry name="loopback.1"><ip><entry name="10.0.99.1"/></ip></entry></units></loopback>
    </interface>
    <profiles><interface-management-profile>
      <entry name="allow-mgmt"><https>yes</https><ssh>yes</ssh><ping>yes</ping>
        <permitted-ip><entry name="10.0.99.0/24"/></permitted-ip></entry>
      <entry name="ping-only"><ping>yes</ping></entry>
    </interface-management-profile></profiles>
  </network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
      <entry name="dmz"><network><layer3><member>ethernet1/3</member></layer3></network></entry>
      <entry name="guest"><network><layer3><member>ethernet1/2.30</member></layer3></network></entry>
      <entry name="mgmt"><network><layer3><member>loopback.1</member></layer3></network></entry>
    </zone>
    <address>
      <entry name="LAN-net"><ip-netmask>10.0.10.0/24</ip-netmask></entry>
      <entry name="srv-gw"><ip-netmask>10.0.20.1/24</ip-netmask></entry>
      <entry name="SERVERS-net"><ip-netmask>10.0.20.0/24</ip-netmask></entry>
      <entry name="web-srv"><ip-netmask>10.0.20.10</ip-netmask></entry>
      <entry name="guest-range"><ip-range>10.0.30.1-10.0.30.6</ip-range></entry>
      <entry name="updates"><fqdn>updates.example.com</fqdn></entry>
    </address>
    <address-group>
      <entry name="internal"><static><member>LAN-net</member><member>web-srv</member></static></entry>
      <entry name="tagged"><dynamic><filter>'web'</filter></dynamic></entry>
    </address-group>
    <service>
      <entry name="tcp-8443"><protocol><tcp><port>8443</port></tcp></protocol></entry>
      <entry name="web-ports"><protocol><tcp><port>80,443,8000-8080</port></tcp></protocol></entry>
    </service>
    <service-group>
      <entry name="web-and-ntp"><members><member>web-ports</member><member>shared-ntp</member></members></entry>
    </service-group>
    <rulebase><security><rules>
      <entry name="mgmt-ssh" uuid="0a1b"><from><member>mgmt</member></from><to><member>trust</member></to>
        <source><member>any</member></source><destination><member>LAN-net</member></destination>
        <source-user><member>any</member></source-user><application><member>ssh</member></application>
        <service><member>application-default</member></service><action>allow</action></entry>
      <entry name="lan-to-web"><from><member>trust</member></from><to><member>dmz</member></to>
        <source><member>LAN-net</member></source><destination><member>web-srv</member></destination>
        <application><member>any</member></application><service><member>web-ports</member></service>
        <action>allow</action><log-end>yes</log-end></entry>
      <entry name="web-from-internet"><from><member>untrust</member></from><to><member>dmz</member></to>
        <source><member>any</member></source><destination><member>web-srv</member></destination>
        <application><member>web-browsing</member><member>ssl</member></application>
        <service><member>application-default</member></service><action>allow</action>
        <description>Web &lt;b&gt;in&lt;/b&gt;</description></entry>
      <entry name="guest-block"><from><member>guest</member></from><to><member>any</member></to>
        <source><member>guest-range</member></source><destination><member>internal</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>deny</action></entry>
      <entry name="lan-out"><from><member>trust</member></from><to><member>untrust</member></to>
        <source><member>any</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>allow</action><log-end>no</log-end></entry>
      <entry name="old-rule"><from><member>trust</member></from><to><member>dmz</member></to>
        <source><member>10.0.10.5</member></source><destination><member>10.0.20.0/24</member></destination>
        <application><member>any</member></application><service><member>web-and-ntp</member></service>
        <action>allow</action><disabled>yes</disabled></entry>
      <entry name="edl-block"><from><member>untrust</member></from><to><member>any</member></to>
        <source><member>panw-known-ip-list</member></source><destination><member>any</member></destination>
        <application><member>any</member></application><service><member>any</member></service>
        <action>drop</action><negate-destination>no</negate-destination></entry>
      <entry name="it's-odd"><from><member>trust</member></from><to><member>dmz</member></to>
        <source><member>10.0.10.7</member></source><destination><member>web-srv</member></destination>
        <application><member>any</member></application><service><member>service-https</member></service>
        <action>allow</action></entry>
    </rules></security></rulebase>
  </entry></vsys>
</entry></devices>
</config>"""


def run(coro):
    return asyncio.run(coro)


def steps(xpath: str) -> list[str]:
    """An xpath split at "/" outside quotes."""
    out, current, quoted = [], "", False
    for ch in xpath.strip("/"):
        if ch == "'":
            quoted = not quoted
        if ch == "/" and not quoted:
            out.append(current)
            current = ""
        else:
            current += ch
    return out + [current]


STEP_RE = re.compile(r"^([\w.-]+)(?:\[@name='([^']*)'\])?$")


class FakePanos:
    """Just enough of the PAN-OS XML API for the connector."""

    def __init__(self, version: str = "11.1.4-h7"):
        self.version = version
        self.running = ET.fromstring(RUNNING)
        self.candidate = copy.deepcopy(self.running)
        self.saved: dict[str, ET.Element] = {}
        self.imported: dict[str, bytes] = {}
        self.own_pending = False
        self.others_pending = False
        self.locks: list[str] = []
        self.panorama = False
        self.denied: set[str] = set()  # "op", "commit", "export", "import", "rules", ...
        self.jobs: dict[str, dict[str, Any]] = {}
        self.polls_before_done = 1
        self.commit_result = "OK"  # or "FAIL" / "HANG"
        self.fail_set = False
        self.unreachable = False
        self.tls_untrusted = False
        self.calls: list[dict[str, str]] = []
        self.hits = {"lan-to-web": 42, "lan-out": 99120}

    # -- configuration trees ---------------------------------------------------------------

    @staticmethod
    def find(tree: ET.Element, xpath: str) -> ET.Element | None:
        parts = steps(xpath)
        assert parts[0] == "config", xpath
        node = tree
        for step in parts[1:]:
            tag, name = STEP_RE.match(step).groups()
            node = next((c for c in node if c.tag == tag and (name is None or c.get("name") == name)), None)
            if node is None:
                return None
        return node

    @staticmethod
    def ensure(tree: ET.Element, xpath: str) -> ET.Element:
        node = tree
        for step in steps(xpath)[1:]:
            tag, name = STEP_RE.match(step).groups()
            found = next((c for c in node if c.tag == tag and (name is None or c.get("name") == name)), None)
            if found is None:
                found = ET.SubElement(node, tag, {"name": name} if name is not None else {})
            node = found
        return node

    @classmethod
    def merge(cls, target: ET.Element, new: ET.Element) -> None:
        for child in new:
            if child.tag == "member":
                if child.text not in [m.text for m in target.findall("member")]:
                    ET.SubElement(target, "member").text = child.text
                continue
            existing = next((c for c in target if c.tag == child.tag and c.get("name") == child.get("name")), None)
            if existing is None:
                target.append(copy.deepcopy(child))
            elif len(child) == 0:
                existing.text = child.text
            else:
                cls.merge(existing, child)

    def rule_names(self, tree: ET.Element | None = None) -> list[str]:
        rules = self.find(tree if tree is not None else self.running, f"{VSYS}/rulebase/security/rules")
        return [e.get("name") for e in rules.findall("entry")]

    def rule(self, name: str, tree: ET.Element | None = None) -> ET.Element | None:
        return self.find(tree if tree is not None else self.running, f"{VSYS}/rulebase/security/rules/entry[@name='{name}']")

    # -- HTTP -------------------------------------------------------------------------------

    @staticmethod
    def ok(result: str = "", **attrs: str) -> httpx.Response:
        extra = "".join(f' {k}="{v}"' for k, v in attrs.items())
        return httpx.Response(200, text=f'<response status="success"{extra}><result>{result}</result></response>')

    @staticmethod
    def err(code: str, msg: str = "error") -> httpx.Response:
        return httpx.Response(200, text=f'<response status="error" code="{code}"><msg><line>{msg}</line></msg></response>')

    @staticmethod
    def form(request: httpx.Request) -> tuple[dict[str, str], dict[str, tuple[str, bytes]]]:
        ctype = request.headers.get("content-type", "")
        if ctype.startswith("multipart/form-data"):
            message = BytesParser().parsebytes(b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + request.content)
            fields, files = {}, {}
            for part in message.get_payload():
                name = part.get_param("name", header="content-disposition")
                filename = part.get_param("filename", header="content-disposition")
                if filename:
                    files[name] = (filename, part.get_payload(decode=True))
                else:
                    fields[name] = part.get_payload(decode=True).decode()
            return fields, files
        return {k: v[0] for k, v in parse_qs(request.content.decode(), keep_blank_values=True).items()}, {}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.unreachable:
            raise httpx.ConnectTimeout("timed out", request=request)
        if self.tls_untrusted:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=request)
        assert request.method == "POST" and request.url.path == "/api/" and not request.url.query  # nothing in URLs
        if request.headers.get("x-pan-key") != KEY:
            return httpx.Response(403, text='<response status="error" code="403"><result><msg>Invalid Credential'
                                            '</msg></result></response>')
        data, files = self.form(request)
        self.calls.append(data)
        kind = data.get("type")
        if kind == "version":
            return self.ok(f"<sw-version>{self.version}</sw-version><multi-vsys>off</multi-vsys><model>PA-VM</model>"
                           "<serial>007951000123456</serial>")
        if kind in self.denied:
            return self.err("16", "Unauthorized request")
        if kind == "config":
            return self.config(data)
        if kind == "op":
            return self.op(data["cmd"])
        if kind == "commit":
            return self.commit(data)
        if kind == "export":
            return httpx.Response(200, content=b'<?xml version="1.0"?>\n' + ET.tostring(self.running))
        if kind == "import":
            name, content = files["file"]
            self.imported[name] = content
            return self.ok(f"<msg>{name} saved</msg>")
        return self.err("400", "bad request")

    def config(self, data: dict[str, str]) -> httpx.Response:
        action, xpath = data.get("action"), data.get("xpath", "")
        if action == "show":
            if "rulebase" in xpath and "rules" in self.denied:
                return self.err("16")
            node = self.find(self.running, xpath)
            return self.ok(ET.tostring(node, encoding="unicode") if node is not None else "")
        if self.fail_set and action == "set":
            return self.err("12", "rule -> service 'x' is not a valid reference")
        self.own_pending = True
        if action == "set":
            element = ET.fromstring(f"<x>{data['element']}</x>")
            self.merge(self.ensure(self.candidate, xpath), element)
            return self.ok(code="20")
        parent_path, _, last = xpath.rpartition("/")
        parent = self.find(self.candidate, parent_path)
        node = self.find(self.candidate, xpath)
        if node is None or parent is None:
            return self.err("7", "Object doesn't exist")
        if action == "delete":
            parent.remove(node)
            return self.ok(code="20")
        if action == "move":
            anchor = next((c for c in parent if c.get("name") == data.get("dst")), None)
            if anchor is None or data.get("where") != "before":
                return self.err("14")
            parent.remove(node)
            parent.insert(list(parent).index(anchor), node)
            return self.ok(code="20")
        return self.err("400")

    def op(self, cmd: str) -> httpx.Response:
        root = ET.fromstring(cmd)
        if "op" in self.denied and root.tag != "save":
            return self.err("16", "Unauthorized request")
        if root.tag == "check":
            return self.ok("yes" if self.own_pending or self.others_pending else "no")
        if root.tag == "show" and root.find("config-locks") is not None:
            return self.ok("<config-locks>" + "".join(f'<entry name="{n}"><comment>busy</comment></entry>'
                                                      for n in self.locks) + "</config-locks>")
        if root.tag == "show" and root.find("commit-locks") is not None:
            return self.ok("<commit-locks/>")
        if root.tag == "show" and root.find("panorama-status") is not None:
            return self.ok(f"Panorama Server 1 : 10.1.1.1\n Connected : {'yes' if self.panorama else 'no'}\n")
        if root.tag == "show" and root.find("jobs") is not None:
            job = self.jobs[root.findtext("jobs/id")]
            job["polls"] += 1
            if self.commit_result == "HANG" or job["polls"] <= self.polls_before_done:
                return self.ok(f"<job><id>{job['id']}</id><status>ACT</status><result>PEND</result>"
                               "<progress>55</progress></job>")
            return self.ok(f"<job><id>{job['id']}</id><type>Commit</type><status>FIN</status>"
                           f"<result>{job['result']}</result><progress>100</progress></job>")
        if root.tag == "show" and root.find("rule-hit-count") is not None:
            entries = "".join(f'<entry name="{n}"><hit-count>{c}</hit-count></entry>' for n, c in self.hits.items())
            return self.ok("<rule-hit-count><vsys><entry name=\"vsys1\"><rule-base><entry name=\"security\"><rules>"
                           f"{entries}</rules></entry></rule-base></entry></vsys></rule-hit-count>")
        if root.tag == "revert":
            assert root.findtext("config/partial/admin/member") == ADMIN
            self.candidate, self.own_pending = copy.deepcopy(self.running), False
            return self.ok()
        if root.tag == "save":
            self.saved[root.findtext("config/to")] = copy.deepcopy(self.candidate)
            return self.ok(f"<msg>Config saved to {root.findtext('config/to')}</msg>")
        if root.tag == "load":
            name = root.findtext("config/from")
            if name == "running-config.xml":
                self.candidate = copy.deepcopy(self.running)
            elif name in self.saved:
                self.candidate = copy.deepcopy(self.saved[name])
            elif name in self.imported:
                self.candidate = ET.fromstring(self.imported[name].split(b"?>", 1)[-1])
            else:
                return self.err("7", "file not found")
            self.own_pending, self.others_pending = True, False
            return self.ok("<msg>Config loaded</msg>")
        return self.err("17", "invalid command")

    def commit(self, data: dict[str, str]) -> httpx.Response:
        root = ET.fromstring(data["cmd"])
        partial = root.find("partial") is not None
        if partial:
            assert data.get("action") == "partial" and root.findtext("partial/admin/member") == ADMIN
        if not (self.own_pending or (self.others_pending and not partial)):
            return httpx.Response(200, text='<response status="success" code="19"><msg>There are no changes to '
                                            'commit.</msg></response>')
        job = str(len(self.jobs) + 1)
        self.jobs[job] = {"id": job, "polls": 0, "result": "FAIL" if self.commit_result == "FAIL" else "OK"}
        if self.commit_result == "OK":
            self.running = copy.deepcopy(self.candidate)
            self.own_pending = False
            if not partial:
                self.others_pending = False
        return httpx.Response(200, text=f'<response status="success" code="19"><result><msg><line>Commit job enqueued '
                                        f'with jobid {job}</line></msg><job>{job}</job></result></response>')


@pytest.fixture
def fake(monkeypatch) -> FakePanos:
    device = FakePanos()
    now = [1000.0]

    async def sleep(seconds: float) -> None:
        now[0] += seconds

    monkeypatch.setattr(PanosConnector, "clock", staticmethod(lambda: now[0]))
    monkeypatch.setattr(PanosConnector, "sleep", staticmethod(sleep))
    return device


def connector(fake: FakePanos, **config: Any) -> PanosConnector:
    """A new instance (= a new connection); the hub manages the firewall from 10.0.99.10."""
    config = {"hub_address": "10.0.99.10", "api_admin": ADMIN, **config}
    return PanosConnector(clean_config(PanosConnector, {"base_url": BASE, **{k: v for k, v in config.items()
                                                                              if v is not None}}),
                          {"api_key": KEY}, httpx.MockTransport(fake))


def snapshot(fake: FakePanos, **config: Any) -> dict[str, Any]:
    records, errors = normalize("network", run(connector(fake, **config).pull("network")))
    assert errors == [] and records[0]["errors"] == [], errors or records[0]["errors"]
    return records[0]


def rule(record: dict[str, Any], rid: str) -> dict[str, Any]:
    return next(r for r in record["rules"] if r["id"] == rid)


ALLOW = parse_ops([{"op": "allow", "source": {"zone": "trust", "cidrs": ["10.0.10.0/24"]},
                    "destination": {"zone": "dmz", "cidrs": ["10.0.20.0/24"]},
                    "services": [{"proto": "tcp", "ports": "443"}, {"proto": "tcp", "ports": "8443"}],
                    "log": True, "description": "Users to <intranet>", "marker": "atrium:chg_7"}])


def disable(*names: str) -> list[dict[str, Any]]:
    return parse_ops([{"op": "disable_rules", "rules": [{"id": n, "vendor_ref": n} for n in names]}])


def writes(fake: FakePanos) -> list[dict[str, str]]:
    return [c for c in fake.calls if c.get("type") in ("commit", "import") or
            (c.get("type") == "config" and c.get("action") != "show")]


# --------------------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------------------


def test_reads_rules_zones_and_objects_into_the_network_model(fake):
    record = snapshot(fake)
    assert record["external_id"] == "007951000123456" and record["kind"] == "firewall"
    assert record["device"]["vendor"] == "Palo Alto Networks" and record["device"]["version"] == "11.1.4"
    assert record["device"]["model"] == "PA-VM"
    ifaces = {i["id"]: i for i in record["interfaces"]}
    assert set(ifaces) == {"ethernet1/1", "ethernet1/2", "ethernet1/2.30", "ethernet1/3", "ethernet1/4", "loopback.1"}
    assert ifaces["ethernet1/1"]["role"] == "wan" and ifaces["ethernet1/2"]["role"] == "lan"
    assert ifaces["ethernet1/2.30"]["vlan"] == 30 and ifaces["ethernet1/2.30"]["subnets"] == ["10.0.30.0/24"]
    assert ifaces["ethernet1/3"]["subnets"] == ["10.0.20.0/24"]  # the ip entry names an address object
    assert ifaces["loopback.1"]["role"] == "mgmt" and ifaces["ethernet1/4"]["subnets"] == []
    assert set(record["self_addresses"]) == {"203.0.113.2", "10.0.10.1", "10.0.30.1", "10.0.20.1", "10.0.99.1"}
    zones = {z["id"]: z["interfaces"] for z in record["zones"]}
    assert zones["trust"] == ["ethernet1/2"] and zones["guest"] == ["ethernet1/2.30"]

    aliases = {a["name"]: a for a in record["aliases"]}
    assert aliases["web-srv"] == {"name": "web-srv", "kind": "host", "cidrs": ["10.0.20.10/32"], "ports": None,
                                  "resolved": True}
    assert aliases["internal"]["cidrs"] == ["10.0.10.0/24", "10.0.20.10/32"] and aliases["internal"]["resolved"]
    assert aliases["tagged"]["resolved"] is False and aliases["updates"]["resolved"] is False
    assert aliases["guest-range"]["cidrs"][0] == "10.0.30.1/32" and aliases["shared-dns"]["cidrs"] == ["10.0.0.53/32"]

    policies = [r for r in record["rules"] if not r["id"].startswith("mgmt-profile:")]
    assert [r["id"] for r in policies] == ["mgmt-ssh", "lan-to-web", "web-from-internet", "guest-block", "lan-out",
                                           "old-rule", "edl-block", "it's-odd"]
    web = rule(record, "lan-to-web")
    assert web["source_zones"] == ["trust"] and web["destination_zones"] == ["dmz"] and web["interfaces"] == []
    assert web["services"] == [{"proto": "tcp", "ports": "80,443,8000-8080", "alias": None, "name": "web-ports"}]
    assert web["hits"] == 42 and web["log"] and web["vendor_ref"] == "lan-to-web"
    internet = rule(record, "web-from-internet")
    assert internet["services"][0]["alias"] == "application-default" and "web-browsing" in internet["services"][0]["name"]
    assert internet["description"] == "Web <b>in</b>" and internet["log"]  # device text stays text (never HTML)
    assert rule(record, "guest-block")["action"] == "block" and rule(record, "guest-block")["destination_zones"] == []
    out = rule(record, "lan-out")
    assert out["source"]["any"] and out["services"] is None and out["log"] is False
    old = rule(record, "old-rule")
    assert not old["enabled"] and old["source"]["cidrs"] == ["10.0.10.5/32"]
    assert {(s["proto"], s["ports"]) for s in old["services"]} == {("tcp", "80,443,8000-8080"), ("udp", "123")}
    assert rule(record, "edl-block")["source"]["aliases"] == ["panw-known-ip-list"]
    assert rule(record, "it's-odd")["services"][0]["ports"] == "443"  # predefined service-https
    mgmt = rule(record, "mgmt-profile:ethernet1/2")
    assert mgmt["destination"]["self"] and mgmt["source"]["cidrs"] == ["10.0.99.0/24"]
    assert {(s["proto"], s["ports"]) for s in mgmt["services"]} == {("tcp", "443"), ("tcp", "22"), ("icmp", None)}
    assert not any(exposes_management(record, r) for r in record["rules"])
    assert KEY not in json.dumps(record) and PHASH not in json.dumps(record)


def test_management_profile_on_the_internet_zone_is_exposure(fake):
    profile = fake.find(fake.running, "/config/devices/entry[@name='localhost.localdomain']/network/profiles/"
                                      "interface-management-profile/entry[@name='ping-only']")
    ET.SubElement(profile, "https").text = "yes"
    record = snapshot(fake)
    assert exposes_management(record, rule(record, "mgmt-profile:ethernet1/1"))
    assert snapshot(fake, wan_zones="dmz")["interfaces"][0]["role"] != "wan"  # the setting overrides the guess


def test_revision_follows_the_configuration_not_counters(fake):
    first = snapshot(fake)
    fake.hits["lan-to-web"] = 777
    assert snapshot(fake)["revision"] == first["revision"]
    fake.rule("lan-to-web").find("action").text = "deny"
    assert snapshot(fake)["revision"] != first["revision"]


def test_unsupported_versions_and_missing_rights(fake):
    fake.version = "9.1.16"
    with pytest.raises(Exception, match="not supported"):
        run(connector(fake).pull("network"))
    fake.version = "11.1.4"
    fake.denied = {"rules"}
    with pytest.raises(Exception, match="role lacks"):
        run(connector(fake).pull("network"))
    fake.denied = {"op"}  # no hit counts, nothing else lost
    record = snapshot(fake)
    assert rule(record, "lan-to-web")["hits"] is None and any("hit counts" in n for n in record["notes"])


# --------------------------------------------------------------------------------------
# test()
# --------------------------------------------------------------------------------------


def names(result: dict[str, Any]) -> list[str]:
    return [c["name"] for c in result["checks"]]


def detail(result: dict[str, Any], name: str) -> str:
    return next(c["detail"] for c in result["checks"] if c["name"] == name)


def test_test_reports_each_step_and_the_write_capability(fake):
    result = run(connector(fake).test())
    assert result["ok"], result
    assert names(result)[:6] == ["reachability", "tls", "authentication", "privileges", "version", "api_features"]
    assert result["network_write"] == {"ops": ["allow", "disable_rules", "enable_rules"], "rollback": "backup_restore",
                                       "window_s": 300}
    assert "role superuser" in detail(result, "privileges") and "read-only one is recommended" in detail(result,
                                                                                                         "privileges")
    assert "PAN-OS 11.1.4 PA-VM - supported" in detail(result, "version")
    assert "partial commits" in detail(result, "api_features") and "Panorama: not connected" in detail(result,
                                                                                                    "api_features")
    assert "Connected to PAN-OS 11.1.4" in result["detail"]
    assert writes(fake) == []  # the test changed nothing

    role = fake.find(fake.running, f"/config/mgt-config/users/entry[@name='{ADMIN}']/permissions/role-based")
    role.remove(role.find("superuser"))
    ET.SubElement(role, "superreader").text = "yes"
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None and "read-only role" in detail(result, "privileges")


@pytest.mark.parametrize("change, reason", [
    (lambda f: setattr(f, "panorama", True), "Panorama"),
    (lambda f: f.denied.add("op"), "Operational Requests"),
])
def test_write_capability_needs_a_safe_setup(fake, change, reason):
    change(fake)
    result = run(connector(fake).test())
    assert result["ok"] and result["network_write"] is None, result
    assert reason in detail(result, "privileges")


def test_without_the_admin_account_or_with_read_only_nothing_is_written(fake):
    result = run(connector(fake, api_admin=None).test())
    assert result["ok"] and result["network_write"] is None and "API admin account" in detail(result, "privileges")
    assert connector(fake, api_admin=None).write_capability() is None
    assert connector(fake, read_only=True).write_capability() is None
    with pytest.raises(ChangeError) as caught:
        run(connector(fake, read_only=True).apply_change(ALLOW, snapshot(fake)["revision"], None))
    assert caught.value.code == "unsupported" and writes(fake) == []


def test_test_failures_say_what_to_fix(fake):
    fake.unreachable = True
    result = run(connector(fake).test())
    assert result["ok"] is False and names(result) == ["reachability"]
    fake.unreachable, fake.tls_untrusted = False, True
    result = run(connector(fake).test())
    assert names(result) == ["reachability", "tls"] and "CA certificate file" in detail(result, "tls")
    fake.tls_untrusted = False
    bad = PanosConnector({"base_url": BASE}, {"api_key": "wrong-key-value"}, httpx.MockTransport(fake))
    result = run(bad.test())
    assert names(result)[-1] == "authentication" and "refused the API key" in result["detail"]
    assert "wrong-key-value" not in json.dumps(result) and KEY not in json.dumps(result)
    fake.denied = {"config"}
    result = run(connector(fake).test())
    assert result["ok"] is False and "XML API: Configuration" in detail(result, "privileges")
    fake.denied = set()
    html = httpx.MockTransport(lambda request: httpx.Response(200, text="<!DOCTYPE html><html>login</html>"))
    result = run(PanosConnector({"base_url": BASE}, {"api_key": KEY}, html).test())
    assert names(result) == ["reachability", "tls", "authentication"] and "not like PAN-OS" in result["detail"]


def test_config_validation_options_and_detection(fake):
    from hub.models import Manifest, Tool

    cfg = clean_config(PanosConnector, {"base_url": "https://pa:8443/api/"})
    assert cfg["base_url"] == "https://pa:8443" and cfg["vsys"] == "vsys1" and cfg["commit_timeout"] == 300
    for bad in ("http://pa", "https://user:pw@pa", "https://pa/?key=1"):
        with pytest.raises(ValueError):
            clean_config(PanosConnector, {"base_url": bad})
    for field, value in (("vsys", "vsys1']/x"), ("api_admin", "a'b"), ("wan_zones", "untrust, x'y"),
                         ("commit_timeout", 5), ("hub_address", "hub.local"), ("ca_file", "ca.pem")):
        with pytest.raises(ValueError):
            clean_config(PanosConnector, {"base_url": BASE, field: value})
    assert clean_config(PanosConnector, {"base_url": BASE, "wan_zones": " untrust ,outside"})["wan_zones"] == \
        "untrust, outside"
    assert run(connector(fake).options("vsys")) == [{"value": "vsys1", "label": "vsys1"}]
    tool = Tool(id="pa1", name="Palo Alto edge", source_type="saas", source="https://paloaltonetworks.com",
                status="ready", manifest=Manifest(id="pa1", name="Palo Alto edge", kind="saas"))
    assert PanosConnector.detect(tool) == 50  # the vendor name alone is a weak hint
    firewall = Tool(id="pa2", name="PAN-OS edge", source_type="saas", source="https://example.net", status="ready",
                    manifest=Manifest(id="pa2", name="PAN-OS edge", kind="saas"))
    assert PanosConnector.detect(firewall) == 90
    assert parse_version("10.2.10-h3") == (10, 2, 10)


# --------------------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------------------


def test_apply_snapshots_writes_the_candidate_and_commits_only_its_admin(fake):
    before = snapshot(fake)
    preview = run(connector(fake).preview_change(ALLOW, before))
    assert preview["problems"] == [], preview
    step = preview["steps"][0]
    assert "before rule lan-to-web" in step["position"] and "atrium-tcp-443" in step["detail"]
    assert writes(fake) == []  # a preview writes nothing

    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert applied["created"] == [{"op": 0, "id": "atrium-chg_7", "vendor_ref": "atrium-chg_7"}]
    token = json.loads(applied["token"])
    assert token == {"v": 1, "vsys": "vsys1", "admin": ADMIN, "snapshot": "atrium-pre-chg_7.xml",
                     "rules": ["atrium-chg_7"], "services": ["atrium-tcp-443"], "toggled": {}}
    assert "atrium-pre-chg_7.xml" in fake.saved
    kinds = [(c["type"], c.get("action")) for c in writes(fake)]
    assert kinds == [("config", "set"), ("config", "set"), ("config", "move"), ("commit", "partial")]
    new = fake.rule("atrium-chg_7")
    assert [m.text for m in new.findall("from/member")] == ["trust"]
    assert [m.text for m in new.findall("source/member")] == ["10.0.10.0/24"]
    assert [m.text for m in new.findall("service/member")] == ["atrium-tcp-443", "tcp-8443"]
    assert [m.text for m in new.findall("application/member")] == ["any"]
    assert new.findtext("description") == "atrium:chg_7 Users to <intranet>"  # escaped on the wire, text on the device
    assert fake.rule_names().index("atrium-chg_7") == fake.rule_names().index("lan-to-web") - 1
    assert not fake.own_pending

    after = snapshot(fake)
    assert ops_applied(after, ALLOW) == [] and rule(after, "atrium-chg_7")["marker"] == "chg_7"
    confirmed = run(connector(fake).confirm_change(applied["token"]))
    assert confirmed["confirmed"] and any("atrium-pre-chg_7.xml" in n for n in confirmed["notes"])
    revert = inverse_ops(ALLOW, applied)  # a revert is a new change: the created rule is disabled
    again = run(connector(fake).apply_change(revert, after["revision"], None))
    assert again["disabled"] == ["atrium-chg_7"] and ops_reverted(before, snapshot(fake), ALLOW) == []


def test_rollback_with_inverse_ops(fake):
    before = snapshot(fake)
    ops = ALLOW + disable("lan-to-web")
    applied = run(connector(fake).apply_change(ops, before["revision"], None))
    assert applied["disabled"] == ["lan-to-web"] and fake.rule("lan-to-web").findtext("disabled") == "yes"
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["method"] == "inverse_ops"
    assert fake.rule("atrium-chg_7") is None and fake.rule("lan-to-web").findtext("disabled") == "no"
    assert fake.find(fake.running, f"{VSYS}/service/entry[@name='atrium-tcp-443']") is None
    assert ops_reverted(before, snapshot(fake), ops) == []
    assert run(connector(fake).rollback_change(applied["token"], None))["notes"] == \
        ["the firewall no longer runs the change"]


def test_rollback_falls_back_to_the_snapshot(fake, monkeypatch):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(ALLOW, before["revision"], None))
    original = FakePanos.config

    def refuse_delete(self, data):
        if data.get("action") == "delete":
            return self.err("10", "referenced")
        return original(self, data)

    monkeypatch.setattr(FakePanos, "config", refuse_delete)
    fake.others_pending = True  # another admin started editing meanwhile: the load discards it
    rolled = run(connector(fake).rollback_change(applied["token"], None))
    assert rolled["method"] == "backup_restore" and any("snapshot" in n for n in rolled["notes"])
    assert fake.rule("atrium-chg_7") is None and ops_reverted(before, snapshot(fake), ALLOW) == []
    full = [c for c in fake.calls if c.get("type") == "commit"][-1]
    assert "action" not in full and ET.fromstring(full["cmd"]).find("partial") is None


def test_a_failed_commit_is_reverted_and_reported_unchanged(fake):
    before = snapshot(fake)
    fake.commit_result = "FAIL"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "unchanged" and "failed" in caught.value.message
    assert fake.rule("atrium-chg_7") is None and not fake.own_pending  # the candidate was cleaned up


def test_a_commit_that_does_not_finish_is_unknown(fake):
    before = snapshot(fake)
    fake.commit_result = "HANG"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake, commit_timeout=30).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "unknown" and "may still complete" in caught.value.message


def test_a_failed_write_discards_the_candidate(fake):
    before = snapshot(fake)
    fake.fail_set = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.state == "unchanged" and "code 12" in caught.value.message
    assert not fake.own_pending and not [c for c in fake.calls if c.get("type") == "commit"]


def test_preflight_pending_changes_and_locks(fake):
    before = snapshot(fake)
    fake.own_pending = True  # a leftover of the API admin: discarded before writing
    applied = run(connector(fake).apply_change(disable("lan-to-web"), before["revision"], None))
    assert any("discarded" in n for n in applied["notes"])
    record = snapshot(fake)
    fake.others_pending = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable("guest-block"), record["revision"], None))
    assert caught.value.state == "unchanged" and "other administrators" in caught.value.message
    fake.others_pending = False
    fake.locks = ["admin"]
    preview = run(connector(fake).preview_change(disable("guest-block"), record))
    assert any("locks are held by admin" in p for p in preview["problems"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable("guest-block"), record["revision"], None))
    assert caught.value.state == "unchanged" and "never removes" in caught.value.message


def test_stale_lockout_and_refused_ops(fake):
    before = snapshot(fake)
    fake.rule("lan-to-web").find("action").text = "deny"
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, before["revision"], None))
    assert caught.value.code == "stale"

    record = snapshot(fake)
    preview = run(connector(fake).preview_change(disable("lan-out"), record))
    assert any("cut the hub off" in p for p in preview["problems"])
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(disable("lan-out"), record["revision"], None))
    assert caught.value.code == "lockout"
    problems = run(connector(fake).preview_change(disable("it's-odd"), record))["problems"]
    assert any("cannot address safely" in p for p in problems)
    problems = run(connector(fake).preview_change(disable("mgmt-profile:ethernet1/2"), record))["problems"]
    assert any("interface settings" in p for p in problems)
    icmp = parse_ops([{"op": "allow", "source": {"zone": "trust", "cidrs": ["10.0.10.0/24"]},
                       "destination": {"zone": "nowhere", "cidrs": ["10.0.20.0/24"]}, "services": [{"proto": "icmp"}],
                       "marker": "atrium:chg_9"}])
    problems = run(connector(fake).preview_change(icmp, record))["problems"]
    assert any("App-ID" in p for p in problems) and any("no zone 'nowhere'" in p for p in problems)
    assert writes(fake) == []


def test_disabling_an_already_disabled_rule_writes_nothing(fake):
    before = snapshot(fake)
    applied = run(connector(fake).apply_change(disable("old-rule"), before["revision"], None))
    assert applied["disabled"] == [] and not [c for c in writes(fake) if c.get("type") == "commit"]
    assert run(connector(fake).confirm_change(applied["token"]))["confirmed"]


def test_tokens_are_validated(fake):
    good = {"v": 1, "vsys": "vsys1", "admin": ADMIN, "snapshot": "atrium-pre-x.xml", "rules": [], "services": [],
            "toggled": {}}
    for bad in ("{}", "not json", json.dumps({**good, "rules": ["x']/../../entry"]}),
                json.dumps({**good, "snapshot": "../../etc/passwd"}), json.dumps({**good, "admin": "admin"}),
                json.dumps({**good, "toggled": {"lan-to-web": "maybe"}})):
        with pytest.raises(ChangeError) as caught:
            run(connector(fake).rollback_change(bad, None))
        assert caught.value.code == "invalid"


# --------------------------------------------------------------------------------------
# backups
# --------------------------------------------------------------------------------------


def test_backup_and_restore(fake):
    taken = run(connector(fake).backup())
    assert taken["format"] == "xml" and PHASH.encode() in taken["content"] and b"<config" in taken["content"]
    content = taken["content"]
    backup = Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, "xml")
    before = snapshot(fake)
    run(connector(fake).apply_change(ALLOW, before["revision"], None))
    restored = run(connector(fake).restore_backup(backup))
    assert restored["restored"] and "atrium-restore-bk_1.xml" in fake.imported
    assert ops_reverted(before, snapshot(fake), ALLOW) == [] and fake.rule("atrium-chg_7") is None

    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(Backup("bk_2", b"#config-version", "x", 0.0, "text")))
    assert caught.value.code == "invalid" and caught.value.state == "unchanged"
    fake.denied = {"export"}
    with pytest.raises(Exception, match="XML API: Export"):
        run(connector(fake).backup())


def test_restore_refuses_other_administrators_changes(fake):
    content = run(connector(fake).backup())["content"]
    fake.others_pending = True
    backup = Backup("bk", content, hashlib.sha256(content).hexdigest(), 0.0, "xml")
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(backup))
    assert caught.value.state == "unchanged" and not fake.imported
    fake.others_pending = False
    fake.denied = {"import"}
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).restore_backup(backup))
    assert caught.value.state == "unchanged" and "XML API: Import" in caught.value.message
    # nothing was loaded, so nothing is discarded: other administrators' candidate edits are never thrown away
    assert not [c for c in fake.calls if c.get("type") == "op" and "<load>" in c.get("cmd", "")]


def test_errors_never_carry_secrets(fake):
    fake.fail_set = True
    with pytest.raises(ChangeError) as caught:
        run(connector(fake).apply_change(ALLOW, snapshot(fake)["revision"], None))
    text = json.dumps(caught.value.as_dict())
    assert KEY not in text and "not a valid reference" not in text  # device text is not quoted


# --------------------------------------------------------------------------------------
# through the hub
# --------------------------------------------------------------------------------------


def test_through_the_hub(client, monkeypatch, wait_for):
    from hub.models import Manifest, Tool

    fake = FakePanos()
    hub = client.app.state.hub
    monkeypatch.setattr(hub, "connector_transport", httpx.MockTransport(fake), raising=False)
    tool = Tool(id="pa1", name="Palo Alto edge", source_type="saas", source="https://paloaltonetworks.com",
                status="ready", manifest=Manifest(id="pa1", name="Palo Alto edge", kind="saas"))
    hub.save_tool(tool)
    client.portal.call(hub.agents.ensure_tool_supervisor, tool)
    assert any(c["kind"] == "panos" and c["can_backup"] for c in client.get("/api/connectors").json())
    response = client.put("/api/tools/pa1/connection", json={"kind": "panos", "config": {"base_url": BASE,
                                                                                        "api_admin": ADMIN},
                                                             "secrets": {"api_key": KEY}})
    assert response.status_code == 200, response.text
    tested = client.post("/api/tools/pa1/connection/test").json()
    assert tested["ok"] and tested["network_write"]["rollback"] == "backup_restore", tested
    assert KEY not in json.dumps(tested)
    approval = wait_for(lambda: next((a for a in client.get("/api/approvals?status=pending").json()
                                      if a["kind"] == "flow" and a["payload"]["tool_id"] == "pa1"), None))
    assert client.post(f"/api/approvals/{approval['id']}", json={"approve": True}).status_code == 200
    wait_for(lambda: next((f for f in client.get("/api/flows?tool_id=pa1").json()
                           if f["domain"] == "network" and f["status"] == "enabled"), None))
    refreshed = client.post("/api/network/devices/pa1/refresh").json()
    assert refreshed["results"][0]["ok"], refreshed
    device = client.get("/api/network/devices/pa1").json()
    assert device["record"]["device"]["vendor"] == "Palo Alto Networks" and len(device["record"]["rules"]) == 10
    assert KEY not in json.dumps(device) and PHASH not in json.dumps(device)
    seg = client.get("/api/segmentation?firewall=pa1").json()
    edges = {(e["source"], e["target"]) for e in seg["edges"]}
    assert ("z:pa1:trust", "z:pa1:dmz") in edges and ("z:internet", "z:pa1:dmz") in edges, edges
    backup = client.post("/api/network/devices/pa1/backups")
    assert backup.status_code == 201, backup.text
    assert PHASH not in backup.text
