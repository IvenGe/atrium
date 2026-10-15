"""The SSH session API for device connectors (hub/execution/runner.py) and its fake (hub/execution/sshfake.py)."""

from __future__ import annotations

import asyncio
import re

import pytest

from hub.connectors import netmodel
from hub.connectors.base import Connector
from hub.execution.runner import SSH, SshError, SshResult, SshTarget, parse_ssh_connection, posix_command, ps_quote
from hub.execution.sshfake import FakeSshTransport


def run(coro):
    return asyncio.run(coro)


def target(**overrides) -> SshTarget:
    return SshTarget(**{"host": "10.0.99.1", "username": "atrium", "private_key": "KEY", **overrides})


class Probe(Connector):
    kind = "probe"
    fields = netmodel.SSH_FIELDS

    async def session_commands(self) -> list[SshResult]:
        async with self.ssh(netmodel.ssh_target(self.config, self.secrets)) as session:
            return [await session.run("echo $SSH_CONNECTION"),
                    await session.run("sudo -n /usr/local/sbin/atrium-fw apply", input="table inet atrium {}\n")]


def test_fake_transport_answers_records_and_keeps_sessions():
    ssh = FakeSshTransport()
    ssh.on("echo $SSH_CONNECTION", "10.0.0.5 50000 10.0.99.1 22\n")
    ssh.on(re.compile(r"^sudo -n /usr/local/sbin/atrium-fw apply$"), lambda cmd, stdin, s: (0, f"got {len(stdin)}", ""))
    connector = Probe({"host": "10.0.99.1", "username": "atrium"}, {"private_key": "KEY"}, ssh)
    first, second = run(connector.session_commands())
    assert parse_ssh_connection(first.stdout) == {"client_ip": "10.0.0.5", "client_port": 50000,
                                                  "server_ip": "10.0.99.1", "server_port": 22}
    assert second.ok and second.stdout == "got 21"
    assert len(ssh.sessions) == 1 and ssh.sessions[0].closed  # one connection for the whole session
    assert ssh.calls[1][1].input == "table inet atrium {}\n"  # the script went on stdin, not on the command line
    run(connector.session_commands())
    assert len(ssh.sessions) == 2


def test_fake_transport_failures_truncation_and_json():
    ssh = FakeSshTransport()
    ssh.on("big", "x" * 100)
    ssh.on("json", '{"ok": true}')

    async def go():
        async with ssh.session(target()) as session:
            unknown = await session.run("rm -rf /")
            big = await session.run("big", limit=10)
            good = await session.run("json")
        return unknown, big, good

    unknown, big, good = run(go())
    assert unknown.exit_status == 127 and not unknown.ok
    assert big.truncated and big.stdout == "x" * 10
    with pytest.raises(SshError, match="partial JSON"):
        big.json()
    assert good.json() == {"ok": True}
    with pytest.raises(SshError):
        SshResult(1, "{}", "").json()
    ssh.fail_connect = "connection refused"
    with pytest.raises(SshError, match="connection refused"):
        run(go())


def test_quoting_helpers():
    assert posix_command(["nft", "-j", "list", "ruleset; rm -rf /"]) == "nft -j list 'ruleset; rm -rf /'"
    assert ps_quote("it's $(evil)") == "'it''s $(evil)'"
    # PowerShell closes a single-quoted literal on ' and on U+2018, U+2019, U+201A and U+201B: each one is doubled,
    # so after the literal's own quotes every quote character comes in pairs (no way to close it early)
    for quote in ("'", "\u2018", "\u2019", "\u201a", "\u201b"):
        quoted = ps_quote(f"x{quote}; Remove-Item C:\\ -Recurse #")
        assert quoted == f"'x{quote}{quote}; Remove-Item C:\\ -Recurse #'", repr(quote)
        inner = quoted[1:-1]
        assert all(len(run) % 2 == 0 for run in re.findall("['\u2018\u2019\u201a\u201b]+", inner)), repr(quote)
    assert ps_quote("\u201b\u201a") == "'\u201b\u201b\u201a\u201a'" and ps_quote("") == "''"
    for bad in ("a\nRemove-Item x", "a\rb", "a\x00b", "a\u2028b", "a\x85b"):
        with pytest.raises(ValueError, match="control characters"):
            ps_quote(bad)
    assert ps_quote("tab\there") == "'tab\there'"
    assert parse_ssh_connection("garbage") is None


# -- the real transport (asyncssh) against an in-process SSH server ----------------------

asyncssh = pytest.importorskip("asyncssh")


async def _handle(process) -> None:
    command = process.command or ""
    if command == "cat":
        process.stdout.write(await process.stdin.read())
        process.exit(0)
    elif command == "fail":
        process.stdout.write("out\n")
        process.stderr.write("bad thing\n")
        process.exit(3)
    elif command.startswith("big "):
        process.stdout.write("x" * int(command.split()[1]))
        process.exit(0)
    else:
        process.exit(127)


async def _with_server(check, *, pin: str = "right"):
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    other = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        asyncssh.SSHServer, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle,
        authorized_client_keys=asyncssh.import_authorized_keys(client_key.export_public_key().decode()))
    try:
        port = server.sockets[0].getsockname()[1]
        pinned = {"right": host_key, "wrong": other, "none": None}[pin]
        tgt = SshTarget(host="127.0.0.1", port=port, username="atrium",
                        private_key=client_key.export_private_key().decode(),
                        host_key=pinned.export_public_key().decode().strip() if pinned else None)
        return await check(tgt)
    finally:
        server.close()


def test_real_session_keeps_streams_apart_and_reads_stdin():
    async def check(tgt):
        async with SSH.session(tgt) as session:
            return [await session.run("cat", input="table inet atrium {}\n"), await session.run("fail"),
                    await session.run("big 100000", limit=1000), await session.run("cat")]

    cat, fail, big, empty = run(_with_server(check))
    assert cat.ok and cat.stdout == "table inet atrium {}\n" and cat.stderr == ""
    assert fail.exit_status == 3 and fail.stdout == "out\n" and fail.stderr == "bad thing\n"
    assert big.truncated and big.stdout == "x" * 1000  # the head is kept and the cut is said
    assert empty.ok and empty.stdout == ""  # no input: stdin is closed, the command does not hang


@pytest.mark.parametrize("pin", ["wrong", "none"])
def test_real_session_refuses_unknown_host_keys(pin, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))  # no ~/.ssh/known_hosts: nothing is trusted

    async def check(tgt):
        async with SSH.session(tgt) as session:
            return await session.run("cat", input="secret")

    with pytest.raises(SshError, match="host key is not trusted"):
        run(_with_server(check, pin=pin))


def test_a_missing_known_hosts_file_is_an_error():
    with pytest.raises(SshError, match="does not exist"):
        SSH.options(target(private_key=None, password="pw", known_hosts="/nonexistent/known_hosts"))
