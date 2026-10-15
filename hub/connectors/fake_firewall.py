"""A fake firewall: an in-memory device with interfaces, VLANs, aliases and rules that implements the whole device
contract (read, test, backup, preview, apply, confirm, rollback, restore). Nothing real is ever changed.

It is registered only for tests (``monkeypatch.setitem(connectors.REGISTRY, "fake_firewall", FakeFirewallConnector)``)
or when the hub runs with ``HUB_DEV_FAKE_DEVICES=1`` (to try the Network app and the change flow by hand).

Devices live in ``DEVICES`` by name (the connection's "device" setting), so every connector instance the hub builds
- one per call, like a real connection - sees the same device. Tests reach it with ``device("fw1")`` to change rules
out of band (drift), drive the clock (``dev.clock``) and flip the failure switch ``dev.simulate``:

``None``             behaves like a well-run device
``"unreachable"``    every call fails as if the management address does not answer
``"auth_fail"``      the API key is refused (test() reports it; pulls fail)
``"apply_error"``    apply_change fails cleanly (``ChangeError(code="failed", state="unchanged")``)
``"verify_fail"``    apply_change answers success but does not change the rules (a re-read shows the change missing)
``"lockout"``        after apply_change the device stops answering (test, pull, confirm fail) until the change is
                     rolled back - by the timer when the window passes (savepoint / deadman / commit_confirm), else
                     never (backup_restore has no timer: the hub must restore out of band)
``"rollback_fails"`` rollback_change answers an error and leaves the change in place
``"stale"``          apply_change sees a revision different from the one it was given

``dev.calls`` lists the contract methods called, in order (e.g. to prove a preview changed nothing or that
confirm_change was never called).
"""

from __future__ import annotations

import copy
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from .base import Connector, ConnectorError, ConnectorField, check
from .netmodel import (LEAST_PRIVILEGE_NOTE, ROLLBACK_MODES, Backup, ChangeError, management_guard, normalize_record,
                       parse_ops, validate_write_spec)

TIMED = ("savepoint", "deadman", "commit_confirm")
OPS = ["allow", "disable_rules", "enable_rules"]


def _default_state(name: str) -> dict[str, Any]:
    return {
        "interfaces": [
            {"id": "wan", "name": "WAN", "role": "wan", "subnets": ["203.0.113.0/29"], "addresses": ["203.0.113.2"]},
            {"id": "lan", "name": "LAN", "role": "lan", "subnets": ["10.0.10.0/24"], "addresses": ["10.0.10.1"]},
            {"id": "opt1", "name": "SERVERS", "vlan": 20, "subnets": ["10.0.20.0/24"], "addresses": ["10.0.20.1"]},
            {"id": "opt2", "name": "MGMT", "role": "mgmt", "vlan": 99, "subnets": ["10.0.99.0/24"],
             "addresses": ["10.0.99.1"]},
            {"id": "opt3", "name": "GUEST", "vlan": 30, "subnets": ["10.0.30.0/24"], "addresses": ["10.0.30.1"]},
        ],
        "zones": [],
        "aliases": [
            {"name": "MGMT_NET", "kind": "network", "cidrs": ["10.0.99.0/24"]},
            {"name": "ADMIN_HOSTS", "kind": "host", "cidrs": ["10.0.10.5", "10.0.10.6"]},
            {"name": "BLOCKLIST", "kind": "url", "resolved": False},
        ],
        "rules": [
            {"id": "r1", "vendor_ref": "0b1c-anti-lockout", "order": 1, "action": "pass", "interfaces": ["opt2"],
             "source": {"aliases": ["MGMT_NET"]}, "destination": {"self": True},
             "services": [{"proto": "tcp", "ports": "22,443"}], "description": "Anti-lockout rule"},
            {"id": "r2", "vendor_ref": "1d2e-lan-any", "order": 2, "action": "pass", "interfaces": ["lan"],
             "source": {"nets": ["lan"]}, "destination": {"any": True}, "description": "Default allow LAN to any",
             "hits": 15320},
            {"id": "r3", "vendor_ref": "2f3a-web-in", "order": 3, "action": "pass", "interfaces": ["wan"],
             "source": {"any": True}, "destination": {"cidrs": ["10.0.20.10"]},
             "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "Web server from internet"},
            {"id": "r4", "vendor_ref": "3b4c-guest-web", "order": 4, "action": "pass", "interfaces": ["opt3"],
             "source": {"nets": ["opt3"]}, "destination": {"any": True},
             "services": [{"proto": "tcp", "ports": "80,443"}], "description": "Guest web"},
            {"id": "r5", "vendor_ref": "4d5e-guest-block", "order": 5, "action": "block", "interfaces": ["opt3"],
             "source": {"nets": ["opt3"]}, "destination": {"cidrs": ["10.0.0.0/8"]}, "log": True,
             "description": "Guest isolation"},
            {"id": "r6", "vendor_ref": "5f6a-dns", "order": 6, "action": "pass", "interfaces": ["opt1"],
             "source": {"nets": ["opt1"]}, "destination": {"any": True}, "services": [{"proto": "udp", "ports": "53"}],
             "description": "Servers DNS"},
            {"id": "r7", "vendor_ref": "6b7c-blocklist", "order": 7, "action": "block", "interfaces": ["wan"],
             "source": {"aliases": ["BLOCKLIST"]}, "destination": {"any": True}, "description": "Blocklist"},
        ],
        "default_policy": {"inbound": "block", "forward": "block"},
        "hostname": name,
        "version": "1.4.2",
        # only in backups, never in what pull() returns: a stand-in for the password hashes and keys real
        # configurations hold (tests check it never reaches the database unencrypted)
        "secrets": {"admin_password_hash": f"$2y$10$fake-device-secret-{name}"},
    }


@dataclass
class FakeDevice:
    name: str
    state: dict[str, Any] = field(default_factory=dict)
    revision: int = 1
    simulate: str | None = None
    locked_out: bool = False
    pending: dict[str, Any] | None = None  # the unconfirmed change: {token, before, deadline, mode, ops}
    backups: dict[str, str] = field(default_factory=dict)  # the device's own backups (id -> content)
    calls: list[str] = field(default_factory=list)
    clock: Callable[[], float] = time.time
    next_rule: int = 1
    hub_address: str = "10.0.99.10"  # where the hub's management connection comes from (as the device sees it)
    management_port: int = 443

    def __post_init__(self) -> None:
        self.state = self.state or _default_state(self.name)

    # -- what tests use ----------------------------------------------------------------

    @property
    def rev(self) -> str:
        return f"r{self.revision}"

    def rules(self) -> list[dict[str, Any]]:
        return self.state["rules"]

    def rule(self, rule_id: str) -> dict[str, Any]:
        return next(r for r in self.rules() if r["id"] == rule_id)

    def change(self, mutate: Callable[[dict[str, Any]], None]) -> None:
        """An out-of-band change (someone on the device's own UI): mutate the state, bump the revision."""
        mutate(self.state)
        self.revision += 1

    def add_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        rule = {"order": max((r["order"] for r in self.rules()), default=0) + 1, **rule}
        self.change(lambda s: s["rules"].append(rule))
        return rule

    def unlock(self) -> None:
        """Someone at the console restores access (after a "lockout" with a mode that has no device timer)."""
        self.locked_out, self.simulate = False, None

    # -- device behaviour ----------------------------------------------------------------

    def tick(self) -> None:
        """The device's own timer: an unconfirmed change reverts once its window has passed."""
        if self.pending and self.pending["deadline"] is not None and self.clock() >= self.pending["deadline"]:
            self._revert()

    def _revert(self) -> None:
        assert self.pending is not None
        self.state = copy.deepcopy(self.pending["before"])
        self.pending, self.locked_out = None, False
        self.revision += 1

    def reachable(self) -> None:
        self.tick()
        if self.simulate == "unreachable" or self.locked_out:
            raise ConnectorError(f"Cannot reach the fake firewall {self.name}: ConnectTimeout")

    def record(self) -> dict[str, Any]:
        s = self.state
        return {"external_id": self.name, "revision": self.rev, "read_at": self.clock(), "kind": "firewall",
                "device": {"vendor": "Atrium", "model": "Fake firewall", "version": s["version"],
                           "hostname": s["hostname"], "management_address": "10.0.99.1", "serial": f"FAKE-{self.name}"},
                "interfaces": copy.deepcopy(s["interfaces"]), "zones": copy.deepcopy(s["zones"]),
                "aliases": copy.deepcopy(s["aliases"]),
                "self_addresses": [a for i in s["interfaces"] for a in i.get("addresses") or []],
                "rules": copy.deepcopy(s["rules"]), "default_policy": dict(s["default_policy"]),
                "nat_evaluated": False, "notes": ["simulated device: nothing real is changed"]}


DEVICES: dict[str, FakeDevice] = {}


def device(name: str = "fw1") -> FakeDevice:
    if name not in DEVICES:
        DEVICES[name] = FakeDevice(name)
    return DEVICES[name]


def reset() -> None:
    DEVICES.clear()


class FakeFirewallConnector(Connector):
    kind = "fake_firewall"
    title = "Fake firewall (development)"
    description = ("An in-memory firewall for trying the Network app and device changes without a real device "
                   "(HUB_DEV_FAKE_DEVICES=1). Nothing real is read or changed.")
    fields = [
        ConnectorField(name="base_url", label="Address", kind="url", default="https://fake-firewall.invalid"),
        ConnectorField(name="device", label="Device name", default="fw1", help="Connections with the same name share "
                       "one simulated device."),
        ConnectorField(name="api_key", label="API key", kind="secret", help="Any value; the fake does not check it."),
        ConnectorField(name="rollback", label="Rollback mode", kind="select", default="savepoint",
                       choices=[{"value": m, "label": m} for m in ROLLBACK_MODES]),
        ConnectorField(name="window_s", label="Rollback window (seconds)", kind="number", default=60),
        ConnectorField(name="read_only", label="Read-only credential", kind="bool", default=False),
    ]
    capabilities = {"network": {"read"}}
    network_write = {"ops": OPS, "rollback": "savepoint", "window_s": 60}

    @classmethod
    def validate_config(cls, config: dict[str, Any]) -> dict[str, Any]:
        name = str(config.get("device") or "fw1")
        if not name.replace("-", "").replace("_", "").isalnum() or len(name) > 40:
            raise ConnectorError("The device name is up to 40 letters, digits, '-' and '_'")
        window = int(config.get("window_s") or 60)
        if not 10 <= window <= 3600:
            raise ConnectorError("The rollback window is 10-3600 seconds")
        return {**config, "device": name, "window_s": window}

    @classmethod
    def detect(cls, tool) -> int:
        return cls.name_score(tool, ("fake-firewall", "fake firewall", "fakefw"))

    @property
    def dev(self) -> FakeDevice:
        return device(str(self.config.get("device") or "fw1"))

    def write_capability(self) -> dict[str, Any] | None:
        mode = self.config.get("rollback") or "savepoint"
        if self.config.get("read_only") or mode == "none":
            return None
        return validate_write_spec({"ops": OPS, "rollback": mode, "window_s": int(self.config.get("window_s") or 60)})

    def _auth(self) -> None:
        self.dev.reachable()
        if self.dev.simulate == "auth_fail":
            raise ConnectorError("The fake firewall rejected the credentials (HTTP 401) - check the API key", status=401)

    # -- reading -------------------------------------------------------------------------

    async def test(self) -> dict[str, Any]:
        dev, checks = self.dev, []
        try:
            dev.reachable()
        except ConnectorError as exc:
            return {"ok": False, "detail": exc.message, "checks": [check("reachability", False, exc.message)],
                    "domains": {}, "network_write": None}
        checks.append(check("reachability", True, f"{self.config['base_url']} answers"))
        checks.append(check("tls", True, "certificate verified (simulated)"))
        if dev.simulate == "auth_fail":
            checks.append(check("authentication", False, "the API key was refused (HTTP 401)"))
            return {"ok": False, "detail": "Authentication failed", "checks": checks, "domains": {},
                    "network_write": None}
        checks.append(check("authentication", True, "API key accepted"))
        write = self.write_capability()
        checks.append(check("privileges", True, "read-only credential: device changes are unavailable" if write is None
                            else LEAST_PRIVILEGE_NOTE))
        checks.append(check("version", True, f"Atrium fake firewall {dev.state['version']} (supported)"))
        checks.append(check("api_features", True, f"rollback: {write['rollback']}, window {write['window_s']}s"
                            if write else "rules, interfaces, aliases readable; writes off"))
        return {"ok": True, "detail": f"Connected to the fake firewall {dev.name} ({dev.rev}).", "checks": checks,
                "domains": self.domains(), "network_write": write}

    async def pull(self, domain: str, since: float | None = None) -> list[dict[str, Any]]:
        if domain != "network":
            raise ConnectorError(f"{self.title} cannot read {domain}")
        self._auth()
        return [self.dev.record()]

    # -- backups and changes --------------------------------------------------------------

    async def backup(self) -> dict[str, Any]:
        self._auth()
        dev = self.dev
        dev.calls.append("backup")
        content = json.dumps({"device": dev.name, "revision": dev.rev, "state": dev.state}, sort_keys=True)
        ref = f"bk-{dev.rev}-{len(dev.backups) + 1}"
        dev.backups[ref] = content
        return {"content": content, "format": "json", "device_backup_id": ref, "revision": dev.rev}

    def _guard(self, ops: list[dict[str, Any]]) -> list[str]:
        dev = self.dev
        return management_guard(normalize_record(dev.record()), ops, hub_addresses=[dev.hub_address],
                                management_ports=[dev.management_port])

    def _zones(self) -> set[str]:
        s = self.dev.state
        return {i["id"] for i in s["interfaces"]} | {z["id"] for z in s["zones"]}

    async def preview_change(self, ops: list[dict[str, Any]], snapshot: dict[str, Any]) -> dict[str, Any]:
        self._auth()
        self.dev.calls.append("preview_change")
        ops = parse_ops(ops)
        problems = self._guard(ops)
        steps, zones = [], self._zones()
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                for side in ("source", "destination"):
                    if op[side]["zone"] not in zones:
                        problems.append(f"the device has no interface or zone '{op[side]['zone']}'")
                steps.append({"op": index, "kind": "add_rule", "position": f"top of {op['source']['zone']} rules",
                              "detail": "one pass rule, marked " + op["marker"]})
            else:
                verb = "disable" if op["op"] == "disable_rules" else "enable"
                steps.extend({"op": index, "kind": f"{verb}_rule", "position": "in place",
                              "detail": f"{verb} {ref['vendor_ref']}"} for ref in op["rules"])
        return {"steps": steps, "notes": ["simulated device"], "problems": problems}

    async def apply_change(self, ops: list[dict[str, Any]], base_revision: str, backup: Backup | None) -> dict[str, Any]:
        dev = self.dev
        try:
            self._auth()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable", state="unchanged") from exc
        dev.calls.append("apply_change")
        ops = parse_ops(ops)
        if dev.simulate == "stale" or dev.rev != base_revision:
            raise ChangeError(f"The device is at revision {dev.rev}, not {base_revision}: re-read it and preview again",
                              code="stale", state="unchanged")
        problems = self._guard(ops)
        if problems:
            raise ChangeError("Refused by the management-path guard: " + "; ".join(problems), code="lockout",
                              state="unchanged")
        if dev.pending is not None:
            raise ChangeError("Another change is waiting for confirmation on this device", code="failed",
                              state="unchanged")
        if dev.simulate == "apply_error":
            raise ChangeError("The device rejected the rule (simulated)", code="failed", state="unchanged")
        mode = (self.write_capability() or {}).get("rollback")
        if mode is None:
            raise ChangeError("This connection is read-only", code="unsupported", state="unchanged")
        window = int(self.config.get("window_s") or 60)
        before = copy.deepcopy(dev.state)
        created, disabled, enabled = [], [], []
        for index, op in enumerate(ops):
            if op["op"] == "allow":
                number = dev.next_rule
                dev.next_rule += 1
                rule = {"id": f"atr{number}", "vendor_ref": f"atr-{uuid.uuid4().hex[:12]}",
                        "order": min((r["order"] for r in dev.rules()), default=1) - 1, "action": "pass",
                        "interfaces": [op["source"]["zone"]], "source": {"cidrs": op["source"]["cidrs"]},
                        "destination": {"cidrs": op["destination"]["cidrs"]}, "services": op["services"],
                        "log": op["log"], "description": f"{op['marker']} {op['description']}".strip()}
                if dev.simulate != "verify_fail":
                    dev.rules().insert(0, rule)
                created.append({"op": index, "id": rule["id"], "vendor_ref": rule["vendor_ref"]})
            else:
                for ref in op["rules"]:
                    rule = next((r for r in dev.rules() if r["id"] == ref["id"] or r["vendor_ref"] == ref["vendor_ref"]),
                                None)
                    if rule is None:
                        dev.state = before
                        raise ChangeError(f"Rule {ref['vendor_ref']} is not on the device", code="invalid",
                                          state="unchanged")
                    if dev.simulate != "verify_fail":
                        rule["enabled"] = op["op"] == "enable_rules"
                    (enabled if op["op"] == "enable_rules" else disabled).append(rule["vendor_ref"])
        dev.revision += 1
        token = f"fake-{uuid.uuid4().hex[:16]}"
        deadline = dev.clock() + window if mode in TIMED else None
        dev.pending = {"token": token, "before": before, "deadline": deadline, "mode": mode, "ops": ops}
        if dev.simulate == "lockout":
            dev.locked_out = True
        return {"token": token, "rollback_until": deadline, "revision": dev.rev, "created": created,
                "disabled": disabled, "enabled": enabled, "notes": [f"rollback: {mode}"]}

    async def confirm_change(self, token: str) -> dict[str, Any]:
        dev = self.dev
        try:
            dev.reachable()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable", state="unknown") from exc
        dev.calls.append("confirm_change")
        if dev.pending is None or dev.pending["token"] != token:
            raise ChangeError("Nothing to confirm: the window passed and the device reverted the change",
                              code="failed", state="rolled_back")
        dev.pending = None
        return {"confirmed": True, "revision": dev.rev, "notes": []}

    async def rollback_change(self, token: str, backup: Backup | None) -> dict[str, Any]:
        dev = self.dev
        try:
            dev.reachable()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable", state="unknown") from exc
        dev.calls.append("rollback_change")
        if dev.pending is None or dev.pending["token"] != token:
            return {"rolled_back": True, "method": "already reverted", "notes": ["no unconfirmed change on the device"]}
        if dev.simulate == "rollback_fails":
            raise ChangeError("The device did not revert the change (simulated)", code="failed", state="applied")
        mode = dev.pending["mode"]
        dev._revert()
        return {"rolled_back": True, "method": "inverse_ops" if mode == "backup_restore" else mode, "notes": []}

    async def restore_backup(self, backup: Backup) -> dict[str, Any]:
        dev = self.dev
        try:
            self._auth()
        except ConnectorError as exc:
            raise ChangeError(exc.message, code="unreachable", state="unchanged") from exc
        dev.calls.append("restore_backup")
        try:
            saved = json.loads(backup.text())
            state = saved["state"]
            assert isinstance(state, dict) and isinstance(state.get("rules"), list)
        except (ValueError, KeyError, AssertionError, UnicodeError) as exc:
            raise ChangeError("The backup is not a configuration of this fake device", code="invalid",
                              state="unchanged") from exc
        dev.state, dev.pending, dev.locked_out = copy.deepcopy(state), None, False
        dev.revision += 1
        return {"restored": True, "revision": dev.rev, "notes": []}
