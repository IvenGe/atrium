"""Low-level command execution: local shell, argv exec (no shell), SSH commands, and SSH sessions for device
connectors (``SshTarget`` / ``SSH.session``)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Protocol

from ..models import Host

MAX_OUTPUT = 64_000
IS_WINDOWS = sys.platform == "win32"
READ_LIMIT = 32 * 1024 * 1024  # per stream in a device session: large rulesets fit, runaway output does not


@dataclass
class CommandResult:
    exit_code: int
    output: str
    duration: float
    timed_out: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _decode(raw: bytes | str | None) -> str:
    if raw is None:
        return ""
    text = raw if isinstance(raw, str) else raw.decode("utf-8", errors="replace")
    return text[-MAX_OUTPUT:]


def new_group_kwargs() -> dict[str, Any]:
    """Start children in their own process group so the whole tree can be stopped."""
    if IS_WINDOWS:
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _kill_tree_sync(pid: int) -> None:
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
        return
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass


async def kill_tree(pid: int) -> None:
    await asyncio.to_thread(_kill_tree_sync, pid)


async def run_local(
    command: str, cwd: str | None = None, timeout: float = 120, env: dict[str, str] | None = None
) -> CommandResult:
    started = time.monotonic()
    proc = await asyncio.create_subprocess_shell(
        command,
        cwd=cwd or None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, **(env or {})},
        **new_group_kwargs(),
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.CancelledError:
        await kill_tree(proc.pid)
        with contextlib.suppress(Exception):
            await proc.wait()
        raise
    except asyncio.TimeoutError:
        await kill_tree(proc.pid)
        await proc.wait()
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)
    return CommandResult(proc.returncode or 0, _decode(out), time.monotonic() - started)


async def run_exec(args: list[str], cwd: str | Path | None = None, timeout: float = 600,
                   env: dict[str, str] | None = None) -> CommandResult:
    """Run a program with an argv list - no shell, so arguments cannot inject commands. `env` replaces the
    environment (default: this process's)."""
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        cwd=str(cwd) if cwd else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**(os.environ if env is None else env), "GIT_TERMINAL_PROMPT": "0"},
        **new_group_kwargs(),
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        await kill_tree(proc.pid)
        await proc.wait()
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)
    return CommandResult(proc.returncode or 0, _decode(out), time.monotonic() - started)


async def run_ssh(host: Host, command: str, timeout: float = 120) -> CommandResult:
    try:
        import asyncssh
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("SSH support needs asyncssh: pip install 'atrium[ssh]'") from exc

    options: dict[str, Any] = {"host": host.address, "port": host.port, "username": host.username}
    if host.key_path:
        options["client_keys"] = [os.path.expanduser(host.key_path)]
    if not host.strict_host_keys:
        options["known_hosts"] = None

    started = time.monotonic()

    async def _run() -> CommandResult:
        async with asyncssh.connect(**options) as conn:
            res = await conn.run(command, check=False)
            output = _decode(res.stdout) + _decode(res.stderr)
            code = res.exit_status if res.exit_status is not None else -1
            return CommandResult(code, output[-MAX_OUTPUT:], time.monotonic() - started)

    try:
        return await asyncio.wait_for(_run(), timeout)
    except asyncio.TimeoutError:
        return CommandResult(-1, f"Timed out after {timeout:.0f}s", time.monotonic() - started, True)


# --------------------------------------------------------------------------------------
# SSH sessions for device connectors (host firewalls, CLI-only network devices)
# --------------------------------------------------------------------------------------
# One connection for the whole session (a change and its checks), stdout and stderr kept apart with the exit status,
# scripts passed on stdin, output read in full up to READ_LIMIT per stream - beyond it the result says
# truncated=True and keeps the HEAD (never a silently cut JSON document). Strict host-key checking is honoured:
# a pinned key (SshTarget.host_key), a known_hosts file, or the hub user's ~/.ssh/known_hosts. Tests replace the
# transport with execution/sshfake.FakeSshTransport.


class SshError(Exception):
    """An SSH problem a person can act on; the message never holds a secret."""


@dataclass
class SshTarget:
    host: str
    username: str
    port: int = 22
    private_key: str | None = field(default=None, repr=False)  # OpenSSH/PEM key text (a connection secret)
    passphrase: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)  # discouraged: keys are preferred
    key_path: str | None = None  # a key file on the hub
    strict_host_keys: bool = True
    host_key: str | None = None  # pinned public key, "ssh-ed25519 AAAA..." (wins over known_hosts)
    known_hosts: str | None = None  # a known_hosts file; default: the hub user's ~/.ssh/known_hosts
    connect_timeout: float = 10.0
    command_timeout: float = 120.0

    @property
    def label(self) -> str:
        return f"{self.username}@{self.host}:{self.port}"


@dataclass
class SshResult:
    exit_status: int
    stdout: str
    stderr: str
    duration: float = 0.0
    truncated: bool = False
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_status == 0 and not self.timed_out

    def json(self) -> Any:
        """stdout parsed as JSON; SshError when it was truncated, the command failed or the text is not JSON."""
        if self.truncated:
            raise SshError("the output was larger than the read limit and was cut - refusing to parse partial JSON")
        if not self.ok:
            raise SshError(f"the command failed (exit status {self.exit_status})" + (" - timed out" if self.timed_out else ""))
        try:
            return json.loads(self.stdout)
        except ValueError as exc:
            raise SshError(f"the command did not print JSON ({exc.msg} at line {exc.lineno})") from exc


class SshSession(Protocol):
    """What a device connector gets from ``Connector.ssh(target)``."""

    target: SshTarget

    async def run(self, command: str, *, input: str | bytes | None = None, timeout: float | None = None,
                  limit: int = READ_LIMIT) -> SshResult: ...


def posix_command(argv: list[str]) -> str:
    """argv as one POSIX shell command line, every argument quoted (for values that came from people or devices)."""
    return shlex.join(str(a) for a in argv)


def ps_quote(value: str) -> str:
    """A PowerShell single-quoted literal (no expansion inside; a quote is doubled)."""
    return "'" + str(value).replace("'", "''").replace("‘", "‘‘").replace("’", "’’") + "'"


SSH_CONNECTION_RE = re.compile(r"^\s*(\S+)\s+(\d{1,5})\s+(\S+)\s+(\d{1,5})\s*$")


def parse_ssh_connection(text: str) -> dict[str, Any] | None:
    """The OpenSSH server's SSH_CONNECTION value ("client_ip client_port server_ip server_port") - how the device
    sees the hub (its source address after NAT) and its own sshd port, for the management-path guard."""
    import ipaddress

    match = SSH_CONNECTION_RE.match(text or "")
    if not match:
        return None
    try:
        client, server = ipaddress.ip_address(match.group(1)), ipaddress.ip_address(match.group(3))
    except ValueError:
        return None
    return {"client_ip": str(client), "client_port": int(match.group(2)), "server_ip": str(server),
            "server_port": int(match.group(4))}


def _decode_bytes(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


async def _drain(stream: Any, limit: int) -> tuple[bytes, bool]:
    chunks, size, truncated = [], 0, False
    while True:
        chunk = await stream.read(65536)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        if size < limit:
            chunks.append(chunk[: limit - size])
        size += len(chunk)
        truncated = truncated or size > limit
    return b"".join(chunks), truncated


class _AsyncsshSession:
    def __init__(self, conn: Any, target: SshTarget):
        self._conn, self.target = conn, target

    async def run(self, command: str, *, input: str | bytes | None = None, timeout: float | None = None,
                  limit: int = READ_LIMIT) -> SshResult:
        started = time.monotonic()
        data = input.encode("utf-8") if isinstance(input, str) else input
        try:
            process = await self._conn.create_process(command, input=data, encoding=None)
        except Exception as exc:  # channel refused (MaxSessions), connection lost
            raise SshError(f"{self.target.label}: cannot start a command ({exc.__class__.__name__})") from exc
        try:
            (out, out_cut), (err, err_cut) = await asyncio.wait_for(
                asyncio.gather(_drain(process.stdout, limit), _drain(process.stderr, limit)),
                timeout or self.target.command_timeout)
            await asyncio.wait_for(process.wait_closed(), 10)
        except asyncio.TimeoutError:
            process.close()
            return SshResult(-1, "", f"timed out after {timeout or self.target.command_timeout:.0f}s",
                             time.monotonic() - started, timed_out=True)
        status = process.exit_status
        return SshResult(status if status is not None else -1, _decode_bytes(out), _decode_bytes(err),
                         time.monotonic() - started, truncated=out_cut or err_cut)


class AsyncsshTransport:
    """The real SSH transport (asyncssh, the "ssh" extra)."""

    @staticmethod
    def options(target: SshTarget) -> dict[str, Any]:
        import asyncssh

        options: dict[str, Any] = {"host": target.host, "port": target.port, "username": target.username,
                                   "connect_timeout": target.connect_timeout, "config": [], "agent_path": None}
        if target.private_key:
            try:
                options["client_keys"] = [asyncssh.import_private_key(target.private_key, target.passphrase)]
            except (asyncssh.KeyImportError, ValueError) as exc:
                raise SshError("The private key cannot be read (wrong format or passphrase)") from exc
        elif target.key_path:
            options["client_keys"] = [os.path.expanduser(target.key_path)]
            if target.passphrase:
                options["passphrase"] = target.passphrase
        if target.password:
            options["password"] = target.password
        if not target.strict_host_keys:
            options["known_hosts"] = None
        elif target.host_key:
            pattern = target.host if target.port == 22 else f"[{target.host}]:{target.port}"
            try:
                options["known_hosts"] = asyncssh.import_known_hosts(f"{pattern} {target.host_key.strip()}\n")
            except (ValueError, asyncssh.KeyImportError) as exc:
                raise SshError("The pinned host key is not a public key line such as 'ssh-ed25519 AAAA...'") from exc
        elif target.known_hosts:
            options["known_hosts"] = os.path.expanduser(target.known_hosts)
        return options

    @contextlib.asynccontextmanager
    async def session(self, target: SshTarget) -> AsyncIterator[SshSession]:
        try:
            import asyncssh
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise SshError("SSH support needs asyncssh: pip install 'atrium[ssh]'") from exc
        options = self.options(target)
        try:
            conn = await asyncio.wait_for(asyncssh.connect(**options), target.connect_timeout + 20)
        except asyncssh.HostKeyNotVerifiable as exc:
            raise SshError(f"{target.label}: the host key is not trusted - pin it in the connection or add it to "
                           "known_hosts (strict host-key checking is on)") from exc
        except asyncssh.PermissionDenied as exc:
            raise SshError(f"{target.label}: authentication failed - check the user and key") from exc
        except asyncio.TimeoutError as exc:
            raise SshError(f"{target.label}: no answer within {target.connect_timeout:.0f}s") from exc
        except (OSError, asyncssh.Error) as exc:
            reason = exc.strerror if isinstance(exc, OSError) else getattr(exc, "reason", "")
            raise SshError(f"{target.label}: cannot connect ({exc.__class__.__name__}: {reason or exc})") from exc
        try:
            yield _AsyncsshSession(conn, target)
        finally:
            conn.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(conn.wait_closed(), 5)


SSH = AsyncsshTransport()
