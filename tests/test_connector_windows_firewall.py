"""Windows Defender Firewall connector against FakeSshTransport. No SSH, no network."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import shlex

import pytest

from hub import connectors
from hub.connectors.base import ConnectorError
from hub.connectors.netmodel import (
    LEAST_PRIVILEGE_NOTE,
    TEST_CHECKS,
    Backup,
    ChangeError,
    marker,
    ops_applied,
)
from hub.connectors.windows_firewall import PS_ARGV, WRITE_SCRIPT, WindowsFirewallConnector
from hub.execution.sshfake import FakeSshTransport

KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAB3NzaC1lZDI1NTE5AAAAIWindowsFwTestKey\n-----END OPENSSH PRIVATE KEY-----\n"
PASSPHRASE = "key-pass-phrase-not-a-password"
CONFIG = {"host": "10.0.99.20", "username": "atrium", "host_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest"}
SECRETS = {"private_key": KEY, "passphrase": PASSPHRASE}
OPENSSH = {
    "name": "OpenSSH-Server-In-TCP", "display_name": "OpenSSH Server (sshd)", "group": None,
    "enabled": "True", "direction": "Inbound", "action": "Allow", "profile": "Any",
    "primary_status": "OK", "enforcement": ["Full"], "source": "PersistentStore", "source_type": "Local",
    "protocol": "TCP", "local_port": ["22"], "remote_port": ["Any"],
    "local_address": ["Any"], "remote_address": ["Any"], "description": "OpenSSH Server (sshd)",
}
APP = {
    "name": "App-HTTPS", "display_name": "App HTTPS", "enabled": "True", "direction": "Inbound",
    "action": "Allow", "profile": "Any", "protocol": "TCP", "local_port": ["443"], "remote_port": ["Any"],
    "local_address": ["10.2.2.2/32"], "remote_address": ["10.1.1.0/24"], "description": "app",
}


def run(coro):
    return asyncio.run(coro)


def allow(zone: str = "private", description: str = "Users $(calc)") -> dict:
    return {"op": "allow", "source": {"zone": zone, "cidrs": ["10.0.10.0/24"]},
            "destination": {"zone": zone, "cidrs": ["10.0.20.10/32"]},
            "services": [{"proto": "tcp", "ports": "443"}, {"proto": "tcp", "ports": "80"}],
            "log": True, "description": description, "marker": marker("chg_31")}


class WindowsHost:
    def __init__(self, *, elevated: bool = True, allow_local: bool = True, rules: list | None = None):
        self.elevated = elevated
        self.allow_local = allow_local
        self.rules = [dict(rule) for rule in (rules if rules is not None else [OPENSSH])]
        self.client_port = 51000
        self.verbs: list[str] = []
        self.payloads: list[dict] = []
        self.transport = FakeSshTransport(self.answer)

    def document(self) -> dict:
        profiles = []
        for name in ("Domain", "Private", "Public"):
            profiles.append({"name": name, "enabled": "True", "inbound": "Block", "outbound": "Allow",
                             "allow_local": "True" if self.allow_local else "False"})
        return {"ok": True, "hostname": "WIN-HOST",
                "ssh_connection": f"10.0.0.8 {self.client_port} 10.0.99.20 22",
                "elevated": self.elevated,
                "os": {"Caption": "Microsoft Windows Server 2022", "Version": "10.0.20348", "BuildNumber": "20348"},
                "profiles": profiles,
                "addresses": [{"alias": "Ethernet", "address": "10.0.99.20", "prefix": 24, "family": "IPv4"}],
                "rules": self.rules}

    def answer(self, command: str, stdin: str | None, session):
        if shlex.split(command) != PS_ARGV:
            return (127, "", f"fake: {command}")
        if stdin and "FromBase64String" in stdin:
            found = re.search(r"@'\s*([A-Za-z0-9+/=]+)\s*'@", stdin)
            payload = json.loads(base64.b64decode(found.group(1)))
            self.verbs.append(payload["verb"])
            self.payloads.append(payload)
            self._mutate(payload)
            return json.dumps({"ok": True, "confirmed": payload["verb"] == "confirm",
                               "path": r"C:\ProgramData\Atrium\fw\backup.wfw", "wfw_b64": "QQ=="}) + "\n"
        return json.dumps(self.document()) + "\n"

    def _mutate(self, payload: dict) -> None:
        if payload.get("verb") != "apply":
            return
        for rule in payload.get("rules") or []:
            if rule["op"] == "disable":
                for item in self.rules:
                    if item["name"] == rule["name"]:
                        item["enabled"] = "False"
            elif rule["op"] == "enable":
                for item in self.rules:
                    if item["name"] == rule["name"]:
                        item["enabled"] = "True"
            else:
                self.rules.append({
                    "name": rule["name"], "display_name": rule.get("display_name") or rule["name"],
                    "enabled": "True", "direction": "Inbound", "action": "Allow", "profile": "Any",
                    "protocol": rule["protocol"], "local_port": list(rule.get("ports") or []),
                    "remote_port": ["Any"], "local_address": list(rule.get("local") or []),
                    "remote_address": list(rule.get("remote") or []), "description": rule.get("description") or "",
                })


def connect(host: WindowsHost, **config) -> WindowsFirewallConnector:
    return WindowsFirewallConnector({**CONFIG, **config}, SECRETS, host.transport)


def pulled(host: WindowsHost, **config) -> dict:
    return run(connect(host, **config).pull("network"))[0]


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    monkeypatch.setitem(connectors.REGISTRY, "windows_firewall", WindowsFirewallConnector)


def test_contract_and_password_refused():
    text = WindowsFirewallConnector.__doc__ or ""
    module = __import__("hub.connectors.windows_firewall", fromlist=["__doc__"]).__doc__ or ""
    assert "password" in module
    assert "Scheduled Task" in text or "Scheduled Task" in module
    assert "Enabled = 'True'" in WRITE_SCRIPT
    assert WRITE_SCRIPT.index("Register-ScheduledTask") < WRITE_SCRIPT.index("New-NetFirewallRule")
    assert "OpenSSH-Server-In-TCP" in WRITE_SCRIPT
    assert "atrium-fw-revert-" in WRITE_SCRIPT
    assert all(field.name not in {"password", "sudo_password"} for field in WindowsFirewallConnector.fields)
    assert WindowsFirewallConnector.capabilities == {"network": {"read"}}
    assert WindowsFirewallConnector.kind == "windows_firewall"
    spec = WindowsFirewallConnector(CONFIG, SECRETS, None).write_capability()
    assert spec["rollback"] == "deadman" and "allow" in spec["ops"] and "disable_rules" in spec["ops"]
    with pytest.raises(ConnectorError):
        WindowsFirewallConnector.validate_config({**CONFIG, "sudo_password": "hunter2"})
    host = WindowsHost()
    refused = run(WindowsFirewallConnector(CONFIG, {**SECRETS, "password": "hunter2"}, host.transport).test())
    assert refused["ok"] is False and refused["network_write"] is None
    assert "password" in refused["detail"]
    assert host.transport.sessions == []


def test_registry_round_trip():
    assert connectors.connector_class("windows_firewall") is WindowsFirewallConnector


def test_pull_and_test_report_write_capability():
    host = WindowsHost()
    record = pulled(host)
    assert record["kind"] == "host"
    assert record["device"]["model"] == "Windows Defender Firewall"
    assert record["device"]["vendor"] == "Microsoft"
    rule = next(item for item in record["rules"] if item["id"] == "OpenSSH-Server-In-TCP")
    assert rule["action"] == "pass" and rule["enabled"] is True
    assert {(svc["proto"], svc["ports"]) for svc in rule["services"]} == {("tcp", "22")}
    assert rule["source"]["any"] is True and rule["destination"]["any"] is True
    assert record["device"]["management_address"] == "10.0.99.20"
    first = record["revision"]
    host.client_port = 60001
    assert pulled(host)["revision"] == first

    checked = run(connect(host).test())
    assert checked["ok"] is True
    assert [item["name"] for item in checked["checks"]] == list(TEST_CHECKS)
    assert all(item["ok"] for item in checked["checks"])
    assert checked["network_write"]["rollback"] == "deadman"
    assert LEAST_PRIVILEGE_NOTE in checked["checks"][3]["detail"]
    assert "Windows Defender Firewall" in checked["checks"][4]["detail"]
    assert host.transport.sessions[0].target.password is None
    assert shlex.split(host.transport.sessions[0].calls[0].command) == PS_ARGV

    plain = WindowsHost(elevated=False)
    plain_result = run(connect(plain).test())
    assert plain_result["ok"] is True
    assert plain_result["network_write"] is None
    assert "not elevated" in plain_result["checks"][3]["detail"]

    gpo = WindowsHost(allow_local=False)
    gpo_result = run(connect(gpo).test())
    assert gpo_result["network_write"] is None
    assert "Group Policy" in gpo_result["checks"][3]["detail"]

    readonly = run(connect(WindowsHost(), read_only=True).test())
    assert readonly["ok"] is True and readonly["network_write"] is None
    assert "read-only" in readonly["checks"][3]["detail"]


def test_reachability_auth_and_host_key():
    down = WindowsHost()
    down.transport.fail_connect = "timed out waiting for SSH"
    failed = run(connect(down).test())
    assert failed["checks"][0]["name"] == "reachability" and failed["checks"][0]["ok"] is False
    assert failed["network_write"] is None

    denied = WindowsHost()
    denied.transport.fail_connect = "authentication failed"
    auth = run(connect(denied).test())
    assert auth["checks"][0]["ok"] is True
    assert any(item["name"] == "authentication" and item["ok"] is False for item in auth["checks"])

    mismatch = WindowsHost()
    mismatch.transport.fail_connect = "host key verification failed"
    keys = run(connect(mismatch).test())
    assert any(item["name"] == "tls" and item["ok"] is False for item in keys["checks"])

    loose = run(connect(WindowsHost(), strict_host_keys=False).test())
    assert loose["ok"] is False
    assert any(item["name"] == "tls" and item["ok"] is False for item in loose["checks"])


def test_apply_arms_task_before_the_rule_and_confirm_is_a_new_session():
    host = WindowsHost()
    conn = connect(host, window_s=90)
    record = run(conn.pull("network"))[0]
    op = allow()
    preview = run(conn.preview_change([op], {"revision": record["revision"]}))
    assert preview["problems"] == [] and host.verbs == []
    assert any("Scheduled Task" in note for note in preview["notes"])

    with pytest.raises(ChangeError) as stale:
        run(conn.apply_change([op], "h-stale", None))
    assert stale.value.code == "stale" and stale.value.state == "unchanged"
    assert host.verbs == []

    applied = run(conn.apply_change([op], record["revision"], None))
    assert host.verbs == ["snapshot", "arm-revert", "apply"]
    assert host.payloads[1]["window_s"] == 90
    assert host.payloads[2]["rules"]
    assert all(rule["name"] != "OpenSSH-Server-In-TCP" for rule in host.payloads[2]["rules"])
    blob = json.dumps(host.payloads)
    assert "$" not in blob and "(" not in blob
    for _n, call in host.transport.calls:
        assert shlex.split(call.command) == PS_ARGV
        assert "calc" not in call.command and "$(" not in call.command
        assert KEY not in call.command and PASSPHRASE not in (call.input or "")
    fresh = pulled(host)
    assert ops_applied(fresh, [op]) == []
    assert applied["created"][0]["id"].startswith("atrium:chg_31")
    assert KEY not in applied["token"]

    other = WindowsFirewallConnector({**CONFIG, "window_s": 90}, SECRETS, host.transport)
    confirmed = run(other.confirm_change(applied["token"]))
    assert confirmed["confirmed"] is True
    assert host.verbs[-1] == "confirm"
    assert any("persistent" in note for note in confirmed["notes"])
    assert host.transport.sessions[-1].number != host.transport.sessions[-2].number
    rolled = run(WindowsFirewallConnector(CONFIG, SECRETS, host.transport).rollback_change(applied["token"], None))
    assert rolled["rolled_back"] is True and rolled["method"] == "deadman"
    assert host.verbs[-1] == "revert-now"


def test_openssh_lockout_and_callers_that_cannot_write():
    host = WindowsHost()
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    op = {"op": "disable_rules", "rules": [{"id": "OpenSSH-Server-In-TCP", "vendor_ref": "OpenSSH-Server-In-TCP"}]}
    with pytest.raises(ChangeError) as locked:
        run(conn.apply_change([op], record["revision"], None))
    assert locked.value.code == "lockout" and locked.value.state == "unchanged"
    assert host.verbs == []
    assert all(rule["enabled"] == "True" for rule in host.rules)

    bad_zone = allow(zone="private;calc")
    with pytest.raises(ChangeError) as invalid:
        run(conn.apply_change([bad_zone], record["revision"], None))
    assert invalid.value.code == "invalid"
    assert host.verbs == []
    blob = json.dumps([(call.command, call.input) for _n, call in host.transport.calls])
    assert "calc" not in blob and "private;calc" not in blob

    for kwargs, message in (({"elevated": False}, "cannot write"), ({"allow_local": False}, "Group Policy")):
        blocked = WindowsHost(**kwargs)
        with pytest.raises(ChangeError) as exc:
            run(connect(blocked).apply_change([allow()], pulled(blocked)["revision"], None))
        assert exc.value.code == "unsupported" and exc.value.state == "unchanged"
        assert blocked.verbs == []
        assert message in exc.value.message
    marked = WindowsHost()
    with pytest.raises(ChangeError) as exc:
        run(connect(marked, read_only=True).apply_change([allow()], pulled(marked)["revision"], None))
    assert exc.value.code == "unsupported"
    assert marked.verbs == []


def test_disable_keeps_the_rule_and_backup_restores():
    host = WindowsHost(rules=[OPENSSH, APP])
    conn = connect(host)
    record = run(conn.pull("network"))[0]
    op = {"op": "disable_rules", "rules": [{"id": "App-HTTPS", "vendor_ref": "App-HTTPS"}]}
    run(conn.apply_change([op], record["revision"], None))
    after = pulled(host)
    found = next(rule for rule in after["rules"] if rule["id"] == "App-HTTPS")
    assert found["enabled"] is False
    assert any(rule["id"] == "OpenSSH-Server-In-TCP" and rule["enabled"] for rule in after["rules"])
    saved = run(conn.backup())
    body = json.loads(saved["content"])
    assert body["wfw_b64"] == "QQ=="
    assert KEY not in saved["content"]
    restored = run(conn.restore_backup(Backup("b1", saved["content"].encode(), "sha", 0.0, "json")))
    assert restored["restored"] is True
    assert "import" in host.verbs and "arm-revert" in host.verbs
    with pytest.raises(ChangeError) as exc:
        run(conn.restore_backup(Backup("b2", json.dumps({"manager": "windows_firewall"}).encode(), "sha", 0.0, "json")))
    assert exc.value.code == "invalid"
