"""PAN-OS connector against a fake XML API (httpx.MockTransport, no network)."""

from __future__ import annotations

import asyncio
import copy
import json
import xml.etree.ElementTree as ET
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from hub import connectors
from hub.connectors.base import ConnectorError, normalize
from hub.connectors.netmodel import TEST_CHECKS, Backup, ChangeError, ops_applied, ops_reverted
from hub.connectors.panos import PanOsConnector

KEY = "pan-secret-key-value-abcdef"
BASE = "https://fw.example"
USER = "atrium-api"


def run(coro):
    return asyncio.run(coro)


def allow(marker: str = "atrium:chg_31") -> dict[str, Any]:
    return {"op": "allow", "source": {"zone": "trust", "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": "dmz", "cidrs": ["10.0.20.0/24"]},
            "services": [{"proto": "tcp", "ports": "443"}], "log": True,
            "description": "Users to intranet", "marker": marker}


@pytest.fixture(autouse=True)
def _register(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "panos", PanOsConnector)


def _form(request: httpx.Request) -> dict[str, str]:
    if not request.content:
        return {}
    parsed = parse_qs(request.content.decode())
    return {key: values[0] for key, values in parsed.items()}


def _rule(**kwargs: Any) -> dict[str, Any]:
    base = {"from": ["trust"], "to": ["untrust"], "source": ["any"], "destination": ["any"],
            "service": ["any"], "action": "allow", "disabled": "no", "description": "", "log": "no"}
    base.update(kwargs)
    return base


class FakePan:
    def __init__(self):
        self.running = {
            "addresses": {"web-srv": "10.0.20.10/32", "users": "10.0.10.0/24"},
            "services": {"tcp-443": ("tcp", "443")},
            "rules": [
                _rule(name="allow-web", destination=["web-srv"], service=["application-default"], log="yes",
                      description="web\u202e"),
                _rule(name="servers", to=["dmz"], source=["users"], destination=["web-srv"], service=["tcp-443"],
                      description="servers"),
                _rule(name="to-any", source=["users"], destination=["any"], description="wide"),
            ],
        }
        self.candidate = copy.deepcopy(self.running)
        self.snapshots: dict[str, dict[str, Any]] = {}
        self.fail_commits = 0
        self.locked = False
        self.panorama = ""
        self.version_error = False
        self.hide_version = False
        self.calls: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if KEY in str(request.url):
            return self._error("500", f"url leaked {KEY}")
        if request.headers.get("X-PAN-KEY") != KEY:
            return self._error("403", f"Invalid credential {KEY}")
        form = _form(request)
        kind = form.get("type", "")
        if self.version_error and kind == "version":
            return self._error("500", f"rejected {KEY}")
        if kind == "version":
            if self.hide_version:
                return self._xml("<response status='success'><result><model>PA-VM</model></result></response>")
            return self._xml("<response status='success'><result><sw-version>11.1.4</sw-version><model>PA-VM</model>"
                             "<serial>012345678901</serial><hostname>pa1</hostname></result></response>")
        if kind == "export":
            return self._xml("<config>panos-test-configuration</config>")
        if kind == "commit":
            return self._xml("<response status='success' code='19'><result><job>15</job>"
                             "<msg><line>Commit job enqueued with jobid 15</line></msg></result></response>")
        if kind == "op":
            return self._op(form.get("cmd", ""))
        if kind == "config":
            return self._config(form)
        return self._error("400", "unexpected request")

    def _op(self, cmd: str) -> httpx.Response:
        if "<jobs>" in cmd:
            if self.fail_commits:
                self.fail_commits -= 1
                return self._xml("<response status='success'><result><job><id>15</id><status>FIN</status>"
                                 "<result>FAIL</result></job></result></response>")
            self.running = copy.deepcopy(self.candidate)
            return self._xml("<response status='success'><result><job><id>15</id><status>FIN</status>"
                             "<result>OK</result></job></result></response>")
        if "<save>" in cmd:
            name = ET.fromstring(cmd).findtext(".//to") or ""
            self.snapshots[name] = copy.deepcopy(self.running)
            return self._ok()
        if "<load>" in cmd:
            name = ET.fromstring(cmd).findtext(".//from") or ""
            if name not in self.snapshots:
                return self._error("7", "snapshot missing")
            self.candidate = copy.deepcopy(self.snapshots[name])
            return self._ok()
        if "<revert>" in cmd:
            self.candidate = copy.deepcopy(self.running)
            return self._ok()
        if "rule-hit-count" in cmd:
            return self._xml("<response status='success'><result><entry name='allow-web'><hit-count>42</hit-count>"
                             "</entry></result></response>")
        if "config-locks" in cmd:
            if self.locked:
                return self._xml("<response status='success'><result><entry name='other'/></result></response>")
            return self._ok()
        if "pending-changes" in cmd:
            return self._ok()
        return self._ok()

    def _config(self, form: dict[str, str]) -> httpx.Response:
        action, xpath, element = form.get("action", ""), form.get("xpath", ""), form.get("element", "")
        if action == "show":
            return self._xml(self._show(xpath))
        if action == "set":
            self._apply_set(xpath, element)
            return self._ok()
        if action == "move":
            name = self._entry_name(xpath)
            dst = form.get("dst", "")
            rules = self.candidate["rules"]
            rule = next((r for r in rules if r["name"] == name), None)
            if rule is not None and any(r["name"] == dst for r in rules):
                rules.remove(rule)
                rules.insert(next(i for i, r in enumerate(rules) if r["name"] == dst), rule)
            return self._ok()
        return self._error("400", "bad config action")

    def _show(self, xpath: str) -> str:
        if xpath.endswith("panorama-server"):
            body = f"<panorama-server>{self.panorama}</panorama-server>" if self.panorama else ""
            return f"<response status='success' code='19'><result>{body}</result></response>"
        if xpath.endswith("/network/interface"):
            return ("<response status='success' code='19'><result><ethernet>"
                    "<entry name='ethernet1/1'><layer3><ip><entry name='203.0.113.2/29'/></ip></layer3></entry>"
                    "<entry name='ethernet1/2'><layer3><ip><entry name='10.0.10.1/24'/></ip></layer3></entry>"
                    "<entry name='ethernet1/3'><layer3><ip><entry name='10.0.20.1/24'/></ip><units>"
                    "<entry name='ethernet1/3.20'><tag>20</tag><ip><entry name='10.0.30.1/24'/></ip></entry>"
                    "</units></layer3></entry></ethernet></result></response>")
        if xpath.endswith("/zone"):
            return ("<response status='success' code='19'><result><zone>"
                    "<entry name='trust'><network><layer3><member>ethernet1/2</member></layer3></network></entry>"
                    "<entry name='untrust'><network><layer3><member>ethernet1/1</member></layer3></network></entry>"
                    "<entry name='dmz'><network><layer3><member>ethernet1/3</member></layer3></network></entry>"
                    "</zone></result></response>")
        state = self.running if True else self.candidate
        if xpath.endswith("/address"):
            entries = "".join(f"<entry name='{name}'><ip-netmask>{cidr}</ip-netmask></entry>"
                              for name, cidr in state["addresses"].items())
            return f"<response status='success' code='19'><result><address>{entries}</address></result></response>"
        if xpath.endswith("/service"):
            entries = []
            for name, (proto, port) in state["services"].items():
                if proto == "icmp":
                    entries.append(f"<entry name='{name}'><protocol><icmp/></protocol></entry>")
                else:
                    entries.append(f"<entry name='{name}'><protocol><{proto}><port>{port}</port></{proto}></protocol></entry>")
            return f"<response status='success' code='19'><result><service>{''.join(entries)}</service></result></response>"
        if xpath.endswith("/rules"):
            return f"<response status='success' code='19'><result><rules>{''.join(self._rule_xml(r) for r in state['rules'])}</rules></result></response>"
        return "<response status='success' code='19'><result></result></response>"

    def _rule_xml(self, rule: dict[str, Any]) -> str:
        def members(tag: str, values: list[str]) -> str:
            return f"<{tag}>" + "".join(f"<member>{v}</member>" for v in values) + f"</{tag}>"
        return ("<entry name='" + rule["name"] + "'>" + members("from", rule["from"]) + members("to", rule["to"])
                + members("source", rule["source"]) + members("destination", rule["destination"])
                + members("service", rule["service"]) + f"<action>{rule['action']}</action>"
                + f"<disabled>{rule['disabled']}</disabled><log-end>{rule['log']}</log-end>"
                + f"<description>{rule['description']}</description></entry>")

    def _apply_set(self, xpath: str, element: str) -> None:
        name = self._entry_name(xpath)
        wrap = ET.fromstring(f"<wrap>{element}</wrap>")
        if "/address/" in xpath:
            self.candidate["addresses"][name] = (wrap.findtext("ip-netmask") or "").strip()
            return
        if "/service/" in xpath:
            if wrap.find("protocol/icmp") is not None:
                self.candidate["services"][name] = ("icmp", "")
            elif wrap.find("protocol/udp/port") is not None:
                self.candidate["services"][name] = ("udp", (wrap.findtext("protocol/udp/port") or "").strip())
            else:
                self.candidate["services"][name] = ("tcp", (wrap.findtext("protocol/tcp/port") or "").strip())
            return
        disabled = wrap.findtext("disabled")
        if wrap.find("from") is None and disabled is not None:
            for rule in self.candidate["rules"]:
                if rule["name"] == name:
                    rule["disabled"] = disabled.strip()
            return
        rule = _rule(name=name, **{
            "from": [m.text for m in wrap.findall("from/member")],
            "to": [m.text for m in wrap.findall("to/member")],
            "source": [m.text for m in wrap.findall("source/member")],
            "destination": [m.text for m in wrap.findall("destination/member")],
            "service": [m.text for m in wrap.findall("service/member")],
            "action": (wrap.findtext("action") or "allow").strip(),
            "disabled": (disabled or "no").strip(),
            "description": wrap.findtext("description") or "",
            "log": (wrap.findtext("log-end") or "no").strip(),
        })
        self.candidate["rules"] = [r for r in self.candidate["rules"] if r["name"] != name] + [rule]

    def _entry_name(self, xpath: str) -> str:
        marker = "entry[@name='"
        start = xpath.rfind(marker)
        if start < 0:
            return ""
        rest = xpath[start + len(marker):]
        return rest.split("'", 1)[0]

    def _ok(self) -> httpx.Response:
        return self._xml("<response status='success' code='19'><result></result></response>")

    def _error(self, code: str, message: str) -> httpx.Response:
        return self._xml(f"<response status='error' code='{code}'><result><msg>{message}</msg></result></response>")

    def _xml(self, body: str) -> httpx.Response:
        return httpx.Response(200, content=body.encode(), headers={"content-type": "application/xml"})


def connector(fake: FakePan, **config: Any) -> PanOsConnector:
    cfg = {"base_url": BASE, "vsys": "vsys1", "verify_tls": True, "can_write": False, "api_user": USER, **config}
    return PanOsConnector(cfg, {"api_key": KEY}, httpx.MockTransport(fake))


def pulled(fake: FakePan, **config: Any) -> dict[str, Any]:
    records = run(connector(fake, **config).pull("network"))
    assert isinstance(records, list) and len(records) == 1
    valid, errors = normalize("network", records)
    assert not errors and len(valid) == 1
    return valid[0]


def test_registry_and_config():
    assert connectors.connector_class("panos") is PanOsConnector
    described = PanOsConnector.describe()
    assert described["capabilities"] == {"network": ["read"]}
    assert described["network_write"]["rollback"] == "backup_restore"
    assert PanOsConnector({"base_url": BASE, "api_user": USER}, {"api_key": KEY}).write_capability() is None
    with pytest.raises(ConnectorError, match="https://"):
        PanOsConnector.validate_config({"base_url": "http://fw.example", "vsys": "vsys1"})
    with pytest.raises(ConnectorError, match="API admin"):
        PanOsConnector.validate_config({"base_url": BASE, "vsys": "vsys1", "can_write": True})


def test_pull_rules_zones_and_interfaces():
    record = pulled(FakePan())
    assert record["external_id"] == "012345678901"
    assert record["device"]["version"] == "11.1.4" and record["device"]["hostname"] == "pa1"
    assert record["revision"].startswith("h-")
    wan = next(i for i in record["interfaces"] if i["id"] == "ethernet1/1")
    assert wan["role"] == "wan" and wan["addresses"] == ["203.0.113.2"]
    unit = next(i for i in record["interfaces"] if i["id"] == "ethernet1/3.20")
    assert unit["vlan"] == 20 and "10.0.30.1" in unit["addresses"]
    assert {z["id"] for z in record["zones"]} == {"trust", "untrust", "dmz"}
    web = next(r for r in record["rules"] if r["id"] == "allow-web")
    assert web["vendor_ref"] == "allow-web" and web["hits"] == 42 and web["action"] == "pass"
    assert web["destination"]["cidrs"] == ["10.0.20.10/32"] and web["source"]["any"] is True
    assert web["services"][0]["alias"] == "application-default"
    assert "\u202e" not in web["description"]
    servers = next(r for r in record["rules"] if r["id"] == "servers")
    assert servers["services"][0]["ports"] == "443" and servers["source"]["cidrs"] == ["10.0.10.0/24"]
    assert "10.0.10.1" in record["self_addresses"]


def test_checks_privilege_note_and_xml_error_on_http_200():
    result = run(connector(FakePan(), can_write=True).test())
    assert result["ok"] is True
    assert [c["name"] for c in result["checks"]] == list(TEST_CHECKS)
    assert "read-only" in result["checks"][3]["detail"]
    assert result["network_write"]["rollback"] == "backup_restore"
    assert KEY not in json.dumps(result)

    read_only = run(connector(FakePan(), can_write=False).test())
    assert read_only["network_write"] is None and "read-only credential" in read_only["checks"][3]["detail"]

    hidden = FakePan()
    hidden.hide_version = True
    assert run(connector(hidden, can_write=True).test())["network_write"] is None

    broken = FakePan()
    broken.version_error = True
    failed = run(connector(broken, can_write=True).test())
    assert failed["ok"] is False and failed["network_write"] is None
    assert KEY not in failed["detail"] and "***" in failed["detail"]

    denied = run(PanOsConnector({"base_url": BASE, "vsys": "vsys1", "verify_tls": True}, {"api_key": "other-key-value"},
                                httpx.MockTransport(FakePan())).test())
    assert denied["ok"] is False and any(c["name"] == "authentication" and not c["ok"] for c in denied["checks"])
    assert "other-key-value" not in json.dumps(denied)


def test_preview_does_not_edit_the_candidate():
    fake = FakePan()
    preview = run(connector(fake, can_write=True).preview_change([allow()], {}))
    assert preview["problems"] == []
    assert preview["steps"][0]["detail"].endswith("atrium:chg_31")
    forms = [_form(call) for call in fake.calls]
    assert all(form.get("action") != "set" and form.get("type") != "commit" for form in forms)
    bad = run(connector(FakePan(), can_write=True).preview_change([allow()], {}))
    # unknown zone
    refused = run(connector(FakePan(), can_write=True).preview_change(
        [{**allow(), "source": {**allow()["source"], "zone": "no-such"}}], {}))
    assert any("no-such" in problem for problem in refused["problems"])
    locked = run(connector(FakePan(), can_write=True).preview_change(
        [{"op": "disable_rules", "rules": [{"id": "to-any", "vendor_ref": "to-any"}]}], {}))
    assert any("device itself" in problem for problem in locked["problems"])
    assert bad["problems"] == []


def test_apply_partial_commit_and_inverse_rollback():
    fake = FakePan()
    before = pulled(fake)
    conn = connector(fake, can_write=True)
    applied = run(conn.apply_change([allow()], before["revision"], None))
    assert applied["rollback_until"] is None and applied["created"][0]["vendor_ref"].startswith("atr-r-")
    assert KEY not in applied["token"]
    forms = [_form(call) for call in fake.calls]
    commits = [form for form in forms if form.get("type") == "commit"]
    assert commits and commits[0].get("action") == "partial" and f"<member>{USER}</member>" in commits[0]["cmd"]
    assert all(KEY not in (call.content or b"").decode() and KEY not in str(call.url) for call in fake.calls)
    moves = [form for form in forms if form.get("action") == "move"]
    assert moves and moves[0]["where"] == "before" and moves[0]["dst"] == "allow-web"
    saved = [form for form in forms if form.get("type") == "op" and "<save>" in form.get("cmd", "")]
    assert saved and "atrium-pre-chg_31.xml" in saved[0]["cmd"]
    after = pulled(fake)
    assert ops_applied(after, [allow()]) == []
    assert after["revision"] != before["revision"]
    rolled = run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    assert rolled["method"] == "inverse_ops"
    again = pulled(fake)
    assert ops_reverted(before, again, [allow()]) == []


def test_disable_then_confirm_does_not_commit_again():
    fake = FakePan()
    current = pulled(fake)
    conn = connector(fake, can_write=True)
    applied = run(conn.apply_change([{"op": "disable_rules", "rules": [{"id": "servers", "vendor_ref": "servers"}]}],
                                    current["revision"], None))
    assert applied["disabled"] == ["servers"]
    assert next(r for r in pulled(fake)["rules"] if r["id"] == "servers")["enabled"] is False
    commits = sum(1 for call in fake.calls if _form(call).get("type") == "commit")
    confirmed = run(connector(fake, can_write=True).confirm_change(applied["token"]))
    assert confirmed["confirmed"] is True
    assert sum(1 for call in fake.calls if _form(call).get("type") == "commit") == commits
    run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    assert next(r for r in pulled(fake)["rules"] if r["id"] == "servers")["enabled"] is True


def test_refuses_stale_lockout_lock_panorama_and_read_only():
    fake = FakePan()
    current = pulled(fake)
    with pytest.raises(ChangeError) as exc:
        run(connector(fake, can_write=True).apply_change([allow()], "h-stale", None))
    assert exc.value.code == "stale" and exc.value.state == "unchanged"
    assert not any(_form(call).get("type") == "commit" for call in fake.calls)

    with pytest.raises(ChangeError) as exc:
        run(connector(fake, can_write=True).apply_change(
            [{"op": "disable_rules", "rules": [{"id": "to-any", "vendor_ref": "to-any"}]}], current["revision"], None))
    assert exc.value.code == "lockout"

    held = FakePan()
    held.locked = True
    revision = pulled(held)["revision"]
    with pytest.raises(ChangeError) as exc:
        run(connector(held, can_write=True).apply_change([allow()], revision, None))
    assert exc.value.state == "unchanged"
    assert not any("<save>" in _form(call).get("cmd", "") for call in held.calls)

    managed = FakePan()
    managed.panorama = "10.1.1.1"
    tested = run(connector(managed, can_write=True).test())
    assert tested["network_write"] is None
    revision = pulled(managed)["revision"]
    with pytest.raises(ChangeError) as exc:
        run(connector(managed, can_write=True).apply_change([allow()], revision, None))
    assert exc.value.code == "invalid"

    quiet = FakePan()
    with pytest.raises(ChangeError) as exc:
        run(connector(quiet, can_write=False).apply_change([allow()], "h-anything", None))
    assert exc.value.code == "unsupported" and quiet.calls == []


def test_failed_commit_leaves_running_config_unchanged():
    fake = FakePan()
    revision = pulled(fake)["revision"]
    fake.fail_commits = 1
    with pytest.raises(ChangeError) as exc:
        run(connector(fake, can_write=True).apply_change([allow()], revision, None))
    assert exc.value.state == "unchanged"
    assert not any(r.get("marker") == "chg_31" for r in pulled(fake)["rules"])


def test_backup_export_and_snapshot_restore():
    fake = FakePan()
    backup = run(connector(fake, can_write=True).backup())
    assert backup["format"] == "xml" and b"panos-test-configuration" in backup["content"]
    assert KEY not in backup["content"].decode()
    assert backup["device_backup_id"].startswith("atrium-hub-")
    assert backup["sha256"]
    restored = run(connector(fake, can_write=True).restore_backup(
        Backup("b1", backup["content"], backup["sha256"], 0.0, format="xml", device_backup_id=backup["device_backup_id"])))
    assert restored["restored"] is True
    secret = b"<config>super-secret-config-line</config>"
    with pytest.raises(ChangeError) as exc:
        run(connector(fake, can_write=True).restore_backup(Backup("b2", secret, "abc", 0.0, format="xml")))
    assert exc.value.code == "unsupported" and "super-secret-config-line" not in exc.value.message


def test_inverse_failure_loads_the_snapshot():
    fake = FakePan()
    revision = pulled(fake)["revision"]
    applied = run(connector(fake, can_write=True).apply_change([allow()], revision, None))
    assert any(r.get("marker") == "chg_31" for r in pulled(fake)["rules"])
    fake.fail_commits = 1
    rolled = run(connector(fake, can_write=True).rollback_change(applied["token"], None))
    assert rolled["method"] == "backup_restore"
    assert not any(r.get("marker") == "chg_31" and r.get("enabled", True) for r in pulled(fake)["rules"])


def test_requests_stay_on_the_firewall():
    fake = FakePan()
    run(connector(fake).pull("network"))
    assert fake.calls
    for call in fake.calls:
        assert call.url.host == "fw.example"
        assert KEY not in str(call.url)
        assert call.headers.get("X-PAN-KEY") == KEY
    with pytest.raises(ConnectorError):
        run(connector(fake).pull("assets"))
