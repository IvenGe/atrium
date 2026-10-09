"""A scriptable SSH transport for tests of SSH-based device connectors (no network, no asyncssh).

    ssh = FakeSshTransport()
    ssh.on("echo $SSH_CONNECTION", "10.0.0.5 50000 10.0.99.1 22\\n")
    ssh.on(re.compile(r"^sudo -n /usr/local/sbin/atrium-fw apply "), lambda cmd, stdin, session: (0, "ok", ""))
    connector = HostFirewallConnector(config, secrets, ssh)   # Connector.ssh() uses it

Answers are an ``SshResult``, an ``(exit_status, stdout, stderr)`` tuple, a string (stdout, exit 0), or a callable
``(command, input, session) -> any of those``. Unmatched commands fail with exit status 127. Every session is kept
(``sessions``) with its commands and stdin, so tests can assert "verified over a NEW connection" or "the script
went on stdin, not on the command line".
"""

from __future__ import annotations

import contextlib
import re
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Callable

from .runner import READ_LIMIT, SshError, SshResult, SshTarget


@dataclass
class FakeCall:
    command: str
    input: str | None


@dataclass
class FakeSshSession:
    transport: "FakeSshTransport"
    target: SshTarget
    number: int
    calls: list[FakeCall] = field(default_factory=list)
    closed: bool = False

    async def run(self, command: str, *, input: str | bytes | None = None, timeout: float | None = None,
                  limit: int = READ_LIMIT) -> SshResult:
        if self.closed:
            raise SshError(f"{self.target.label}: the session is closed")
        text = input.decode("utf-8") if isinstance(input, bytes) else input
        self.calls.append(FakeCall(command, text))
        result = self.transport.answer(command, text, self)
        out = result.stdout.encode("utf-8")
        err = result.stderr.encode("utf-8")
        if len(out) > limit or len(err) > limit:
            return SshResult(result.exit_status, out[:limit].decode("utf-8", "ignore"),
                             err[:limit].decode("utf-8", "ignore"), result.duration, True, result.timed_out)
        return result


Answer = Any  # SshResult | tuple[int, str, str] | str | Callable[[str, str | None, FakeSshSession], ...]


class FakeSshTransport:
    def __init__(self, handler: Callable[[str, str | None, FakeSshSession], Answer] | None = None):
        self.handler = handler
        self.rules: list[tuple[str | re.Pattern[str], Answer]] = []
        self.sessions: list[FakeSshSession] = []
        self.fail_connect: str | None = None  # set to a message: the next sessions fail to connect (SshError)

    def on(self, pattern: str | re.Pattern[str], answer: Answer) -> "FakeSshTransport":
        """Answer `pattern` (an exact command or a compiled regex, searched) with `answer`; later rules win."""
        self.rules.insert(0, (pattern, answer))
        return self

    @property
    def calls(self) -> list[tuple[int, FakeCall]]:
        return [(s.number, c) for s in self.sessions for c in s.calls]

    def answer(self, command: str, stdin: str | None, session: FakeSshSession) -> SshResult:
        for pattern, answer in self.rules:
            if (pattern.search(command) if isinstance(pattern, re.Pattern) else pattern == command):
                return self._result(answer, command, stdin, session)
        if self.handler is not None:
            return self._result(self.handler, command, stdin, session)
        return SshResult(127, "", f"fake: no answer for {command!r}")

    def _result(self, answer: Answer, command: str, stdin: str | None, session: FakeSshSession) -> SshResult:
        if callable(answer) and not isinstance(answer, SshResult):
            answer = answer(command, stdin, session)
        if isinstance(answer, SshResult):
            return answer
        if isinstance(answer, tuple):
            status, out, err = answer
            return SshResult(int(status), str(out), str(err))
        return SshResult(0, str(answer), "")

    @contextlib.asynccontextmanager
    async def session(self, target: SshTarget) -> AsyncIterator[FakeSshSession]:
        if self.fail_connect:
            raise SshError(f"{target.label}: {self.fail_connect}")
        session = FakeSshSession(self, target, len(self.sessions) + 1)
        self.sessions.append(session)
        try:
            yield session
        finally:
            session.closed = True
