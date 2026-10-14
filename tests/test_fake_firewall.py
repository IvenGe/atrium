"""The fake firewall (hub/connectors/fake_firewall.py) implements the whole device contract - the reference the
device connectors and the change path are built against."""

from __future__ import annotations

import asyncio
import json

import pytest

from hub.connectors import fake_firewall
from hub.connectors.fake_firewall import FakeFirewallConnector
from hub.connectors.netmodel import (Backup, ChangeError, normalize_record, ops_applied, ops_reverted, parse_ops,
                                     inverse_ops)


def run(coro):
    return asyncio.run(coro)


@pytest.fixture
def dev():
    fake_firewall.reset()
    device = fake_firewall.device("fw1")
    now = [1000.0]
    device.clock = lambda: now[0]
    device.now = now  # type: ignore[attr-defined]
    yield device
    fake_firewall.reset()


def connector(**config) -> FakeFirewallConnector:
    return FakeFirewallConnector({"device": "fw1", **config}, {"api_key": "k"})


OPS = parse_ops([{"op": "allow", "source": {"zone": "lan", "cidrs": ["10.0.10.0/24"]},
                  "destination": {"zone": "opt1", "cidrs": ["10.0.20.0/24"]},
                  "services": [{"proto": "tcp", "ports": "443"}], "log": True, "description": "web",
                  "marker": "atrium:chg_7"}])


def snapshot() -> dict:
    return normalize_record(run(connector().pull("network"))[0])


def backup_of(taken: dict) -> Backup:
    import hashlib
    content = taken["content"].encode()
    return Backup("bk_1", content, hashlib.sha256(content).hexdigest(), 0.0, taken["format"])


def test_apply_verify_confirm(dev):
    before = snapshot()
    preview = run(connector().preview_change(OPS, before))
    assert preview["problems"] == [] and preview["steps"][0]["kind"] == "add_rule"
    assert dev.rev == "r1" and dev.calls == ["preview_change"]  # a preview changes nothing
    applied = run(connector().apply_change(OPS, "r1", None))
    assert applied["rollback_until"] == 1060.0 and applied["created"][0]["op"] == 0
    after = snapshot()  # a new connector instance: a new connection
    assert ops_applied(after, OPS) == []
    assert run(connector().confirm_change(applied["token"]))["confirmed"]
    dev.now[0] = 5000.0
    assert ops_applied(snapshot(), OPS) == []  # confirmed: the timer no longer reverts it
    undo = inverse_ops(OPS, applied)
    assert run(connector().apply_change(undo, dev.rev, None))["disabled"] == [applied["created"][0]["vendor_ref"]]


def test_unconfirmed_changes_revert_by_themselves(dev):
    before = snapshot()
    applied = run(connector().apply_change(OPS, "r1", None))
    dev.now[0] = 1061.0
    assert ops_reverted(before, snapshot(), OPS) == []
    with pytest.raises(ChangeError) as caught:
        run(connector().confirm_change(applied["token"]))
    assert caught.value.state == "rolled_back"


@pytest.mark.parametrize("mode", ["savepoint", "deadman", "commit_confirm", "backup_restore"])
def test_rollback_modes(dev, mode):
    before = snapshot()
    conn = connector(rollback=mode)
    assert conn.write_capability()["rollback"] == mode
    applied = run(conn.apply_change(OPS, "r1", None))
    assert (applied["rollback_until"] is None) == (mode == "backup_restore")
    result = run(connector(rollback=mode).rollback_change(applied["token"], None))
    assert result["rolled_back"] and ops_reverted(before, snapshot(), OPS) == []


def test_failure_switches(dev):
    with pytest.raises(ChangeError) as stale:
        run(connector().apply_change(OPS, "r0", None))
    assert stale.value.code == "stale" and stale.value.state == "unchanged"

    dev.simulate = "apply_error"
    with pytest.raises(ChangeError) as failed:
        run(connector().apply_change(OPS, "r1", None))
    assert failed.value.state == "unchanged"

    dev.simulate = "verify_fail"
    applied = run(connector().apply_change(OPS, "r1", None))
    assert ops_applied(snapshot(), OPS)  # the device said yes but holds nothing
    run(connector().rollback_change(applied["token"], None))

    dev.simulate = "lockout"
    applied = run(connector().apply_change(OPS, dev.rev, None))
    with pytest.raises(Exception, match="Cannot reach"):
        snapshot()
    assert run(connector().test())["ok"] is False
    dev.now[0] += 61  # the device's own timer brings it back
    assert run(connector().test())["ok"] is True

    dev.simulate = "rollback_fails"
    applied = run(connector(rollback="backup_restore").apply_change(OPS, dev.rev, None))
    with pytest.raises(ChangeError) as stuck:
        run(connector().rollback_change(applied["token"], None))
    assert stuck.value.state == "applied"

    dev.simulate = None
    guard = parse_ops([{"op": "disable_rules", "rules": [{"id": "r1"}]}])
    assert run(connector().preview_change(guard, snapshot()))["problems"]
    with pytest.raises(ChangeError) as lockout:
        run(connector().apply_change(guard, dev.rev, None))
    assert lockout.value.code == "lockout"


def test_backup_and_restore(dev):
    taken = run(connector().backup())
    assert taken["format"] == "json" and json.loads(taken["content"])["revision"] == "r1"
    assert "fake-device-secret" in taken["content"] and "fake-device-secret" not in json.dumps(snapshot())
    dev.change(lambda s: s["rules"].clear())
    assert snapshot()["rules"] == []
    restored = run(connector().restore_backup(backup_of(taken)))
    assert restored["restored"] and len(snapshot()["rules"]) == 7
    with pytest.raises(ChangeError):
        run(connector().restore_backup(Backup("bk_x", b"not a config", "x", 0.0)))


def test_read_only_credential_and_test_checks(dev):
    result = run(connector(read_only=True).test())
    assert result["ok"] and result["network_write"] is None
    assert [c["name"] for c in result["checks"]][:6] == ["reachability", "tls", "authentication", "privileges",
                                                        "version", "api_features"]
    writable = run(connector().test())
    assert "read-only one is recommended" in next(c for c in writable["checks"] if c["name"] == "privileges")["detail"]
    dev.simulate = "auth_fail"
    failing = run(connector().test())
    assert failing["ok"] is False and failing["checks"][-1]["name"] == "authentication"
