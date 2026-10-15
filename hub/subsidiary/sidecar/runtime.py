"""The sidecar runtime (6.1): one asyncio process next to the tool, outbound only.

| Task | Behaviour |
| --- | --- |
| enroll | first start only: a new Ed25519 key, ``POST /enroll`` with the one-time code, the token saved (0600) |
| heartbeat | every 30 s: version, health, the bridge's ``atrium.ping``, runs under way, clock, runtime facts and the spool; the answer brings status, flags, a ticket when due and the charter version |
| inbox | long-polls ``GET /inbox``: run, chat, grant, denied, action_result, pause, resume, stop, charter_changed, conformance |
| runner | staff runs over Atrium's model gateway (runner.py), granted actions with the exact approved bytes |
| panel | questions asked inside the tool (panel.py) |
| events | the tool's events relayed to Atrium (events.py) |
| spool | the claimed audit trail (spool.py) |

The sidecar has no scheduler: Atrium decides when staff work. While Atrium has the subsidiary paused (or the master
switch off) it idles with only the heartbeat and the inbox; the runs under way are cancelled. Exit codes: 3 when the
sidecar needs a (new) enrollment - its token no longer works after five tries, or the enrollment code was refused or
is missing; 4 when Atrium stopped the subsidiary. ``once()`` makes one pass of every task and ``check()`` runs
conformance once (``--once`` and ``--check``).

Imports only contract, wire, models, hub.agents.loops and, in API-only mode, hub.connectors: never hub.core,
hub.store, FastAPI or a model SDK.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import socket
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Awaitable, Callable, Mapping

import httpx
from pydantic import ValidationError

from ... import __version__
from .. import contract
from ..models import (HEARTBEAT_SECONDS, INBOX_BODIES, CharterView, ConformanceMessage, ConformanceRow,
                      CredentialResponse, EnrollResponse, HeartbeatResponse, InboxItem, InboxResponse,
                      RotateResponse)
from .bridge_client import BridgeClient, BridgeError
from .client import (EXIT_STOPPED, EXIT_TOKEN, LONG_POLL_TIMEOUT, AtriumClient, AtriumError, Backoff, Exit,
                     Unavailable)
from .config import ENROLL_ENV, SidecarConfig, State, TokenFile
from .events import Events
from .panel import Panel
from .runner import Grants, Runner
from .spool import MaskFilter, Secrets, Spool, digest

if TYPE_CHECKING:
    from .connector_backend import ConnectorBackend

VERSION = f"atrium-sidecar/{__version__}"
LOG = logging.getLogger("atrium.sidecar")
PULL_GAP = 5.0  # seconds between pulls that came back early (bridges that cannot hold a long-poll)
IDLE = 5.0  # seconds between checks while the panel or the relay has nothing to do
REFUSED, STOPPED = "refused.json", "stopped.json"  # what Atrium said last time: a restart does not ask again
CHECK_POLLS = 3  # inbox polls --check waits for Atrium's conformance vectors


def runtime_facts() -> dict[str, Any]:
    """What the heartbeat claims about where the sidecar runs (shown in Atrium, never trusted)."""
    container = Path("/.dockerenv").exists() or Path("/run/.containerenv").exists() or bool(os.environ.get("container"))
    return {"uid": os.getuid() if hasattr(os, "getuid") else -1, "container": container,
            "hostname_hash": digest(socket.gethostname())}


class Runtime:
    def __init__(self, config: SidecarConfig, *, atrium_transport: httpx.AsyncBaseTransport | None = None,
                 bridge_transport: httpx.AsyncBaseTransport | None = None,
                 connector_transport: httpx.AsyncBaseTransport | None = None,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], Awaitable[None]] = asyncio.sleep, env: Mapping[str, str] | None = None,
                 rng: random.Random | None = None):
        self.config, self.clock, self.sleep = config, clock, sleep
        self.env = os.environ if env is None else env
        self.bridge_transport, self.connector_transport = bridge_transport, connector_transport
        self.state = State(config.state_dir)
        self.secrets = Secrets()
        self.log = LOG
        if not any(isinstance(f, MaskFilter) for f in LOG.filters):
            LOG.addFilter(MaskFilter(self.secrets))
        else:
            next(f for f in LOG.filters if isinstance(f, MaskFilter)).secrets = self.secrets
        self.spool = Spool(self.state, clock=clock, secrets=self.secrets)
        token = self.state.token()
        self.atrium = AtriumClient(config, transport=atrium_transport, token=token.token if token else None,
                                   charter_version=lambda: self.charter.version if self.charter else None)
        self.atrium.on_exit = self._exiting
        if token is not None:
            self.secrets.add(token.token)
        self.key = self.state.key()
        if self.key is not None:
            self.secrets.add(contract.private_b64(self.key))
        self.bridge: BridgeClient | None = None
        self.status: str | None = None
        self.flags: list[str] = []
        self.charter: CharterView | None = None
        self.charter_etag: str | None = None
        self.connector: ConnectorBackend | None = None
        self.cursor = 0
        self.server_skew = 0.0
        self.runner = Runner(self)
        self.grants = Grants(self)
        self.panel = Panel(self)
        self.events = Events(self)
        self.backoff = Backoff(rng=rng)
        self.exit: Exit | None = None
        self._exited: asyncio.Event | None = None
        self._wake: asyncio.Event | None = None
        self._pending: set[asyncio.Task[Any]] = set()

    # -- small helpers ----------------------------------------------------------------------

    def working(self) -> bool:
        """Atrium lets the team work: active (paused, probation, stopped and the kill switch are not)."""
        return self.status == "active"

    def _exiting(self, exc: Exit) -> None:
        self.exit = self.exit or exc
        if self._exited is not None:
            self._exited.set()

    def _bridge(self) -> BridgeClient | None:
        if self.config.mode != "bridge" or self.key is None or not self.config.bridge_url:
            return None
        if self.bridge is None:
            self.bridge = BridgeClient(self.config.bridge_url, self.key, transport=self.bridge_transport,
                                       clock=self.clock)
        return self.bridge

    def spawn(self, work: Awaitable[Any]) -> asyncio.Task[Any]:
        task = asyncio.get_running_loop().create_task(work)  # type: ignore[arg-type]
        self._pending.add(task)
        task.add_done_callback(self._pending.discard)
        return task

    async def aclose(self) -> None:
        await self.runner.cancel_all()
        for task in list(self._pending):
            task.cancel()
        await asyncio.gather(*self._pending, return_exceptions=True)
        await self.atrium.aclose()
        if self.bridge is not None:
            await self.bridge.aclose()

    # -- enrollment and the token ----------------------------------------------------------------

    async def enroll(self, code: str | None = None, *, again: bool = False) -> None:
        """First start: a key of its own, then POST /enroll with the one-time code (never written anywhere). `again`:
        the token was refused (or belongs to another subsidiary) and a new code was given - a new key too."""
        if self.state.token() is not None and not again:
            return
        code = code or self.env.get(ENROLL_ENV) or ""
        if not code:
            raise Exit(EXIT_TOKEN, f"The sidecar is not enrolled: start it once with {ENROLL_ENV} set to the one-time "
                                   "code an administrator issued in Atrium.")
        self.secrets.add(code)
        self.state.ensure()
        if again:
            self.key = self.state.new_key(replace=True)
            self.atrium.token, self.atrium.unauthorized = None, 0
            if self.bridge is not None:
                await self.bridge.aclose()
                self.bridge = None
        self.key = self.key or self.state.new_key()
        self.secrets.add(contract.private_b64(self.key))
        body = {"code": code, "public_key": contract.public_b64(self.key), "version": VERSION}
        try:
            answer = EnrollResponse.model_validate(await self.atrium.post("enroll", body))
        except AtriumError as exc:
            raise Exit(EXIT_TOKEN, f"Atrium refused the enrollment ({exc.status}): "
                                   f"{exc.message or exc.code or 'no reason given'}") from None
        except ValidationError:
            raise Unavailable("Atrium's enrollment answer was not understood") from None
        if answer.subsidiary_id != self.config.subsidiary_id or answer.tool_id != self.config.tool_id:
            raise Exit(EXIT_TOKEN, "The enrollment code belongs to another subsidiary than config.json names.")
        self.secrets.add(answer.token)
        self.state.save_token(TokenFile(token=answer.token, subsidiary_id=answer.subsidiary_id,
                                        tool_id=answer.tool_id, issued_at=self.clock(), expires_at=answer.expires_at))
        self.atrium.token = answer.token
        self.state.remove(REFUSED)
        self.spool.add("enroll", outcome="ok", detail={"key_fingerprint": contract.fingerprint(body["public_key"])})
        self.log.info("Enrolled with Atrium as the sidecar of %s (key %s)", self.config.tool_id,
                      contract.fingerprint(body["public_key"]))

    async def rotate_token(self) -> None:
        """At half-life: a new token, saved before it is first used (its first use retires the old one)."""
        token = self.state.token()
        if token is None:
            return
        answer = RotateResponse.model_validate(await self.atrium.post("rotate", {}))
        self.secrets.add(answer.token)
        self.state.save_token(TokenFile(token=answer.token, subsidiary_id=token.subsidiary_id,
                                        tool_id=token.tool_id, issued_at=self.clock(), expires_at=answer.expires_at))
        self.atrium.token = answer.token
        self.spool.add("token.rotate", outcome="ok")

    # -- heartbeat ------------------------------------------------------------------------------

    async def ping(self) -> dict[str, Any] | None:
        bridge = self._bridge()
        if bridge is None:
            return None
        if not bridge.allows("atrium.ping"):
            return {"ok": await bridge.health(), "error": "no ticket yet"}
        try:
            answer = await bridge.call("atrium.ping")
        except BridgeError as exc:
            return {"ok": False, "error": str(exc)[:200]}
        if not answer.ok or not isinstance(answer.result, dict):
            return {"ok": False, "error": answer.refusal()}
        keep = ("tool", "contract", "core", "manifest_sha256", "time", "drops")
        return {"ok": True, **{k: answer.result[k] for k in keep if isinstance(answer.result.get(k), (str, int))}}

    async def heartbeat_once(self) -> HeartbeatResponse:
        ping = await self.ping()
        entries, dropped = self.spool.batch()
        bridge = self.bridge
        health = "ok" if ping is None or ping.get("ok") else "degraded"
        body = {"version": VERSION, "health": health, "bridge_ping": ping, "runs": [*self.runner.running(), *self.panel.running()][:50],
                "clock": self.clock(), "runtime": runtime_facts(), "spool": entries, "spool_dropped": dropped,
                "ticket_exp": bridge.ticket.exp if bridge is not None and bridge.ticket is not None else None}
        reply = HeartbeatResponse.model_validate(await self.atrium.post("heartbeat", body))
        self.spool.shipped(len(entries), dropped)
        await self.apply(reply)
        return reply

    async def apply(self, reply: HeartbeatResponse) -> None:
        """What a heartbeat answer says: status, flags, a new ticket, the charter version."""
        before = self.status
        self.status, self.flags = reply.status, list(reply.flags)
        self.server_skew = round(self.clock() - reply.server_time, 1)
        if abs(self.server_skew) > contract.CLOCK_LEEWAY:
            self.log.warning("This machine's clock is %.0f s off Atrium's: the bridge refuses calls dated outside "
                             "+-60 s. Fix the clock (NTP).", self.server_skew)
        if reply.ticket:
            self.secrets.add(reply.ticket)
            bridge = self._bridge()
            if bridge is not None:
                bridge.set_ticket(reply.ticket)
        if reply.status == "stopped":
            raise Exit(EXIT_STOPPED, "Atrium stopped the subsidiary.", remember=True)
        if reply.status != "active":
            if before == "active":
                await self.pause(f"Atrium has the subsidiary {reply.status}")
            else:  # grants left from before a restart never run after a later resume (no backlog)
                await self.grants.drop_pending("the team was not working when it could be carried out")
        if reply.status in ("probation", "active"):
            if self.charter is None or self.charter.version != reply.charter_version:
                await self.refresh_charter()
            if self.config.mode == "sidecar_only" and self.connector is None:
                await self.load_credential()
        token = self.state.token()
        if token is not None and token.due(self.clock()):
            try:
                await self.rotate_token()
            except (AtriumError, Unavailable, ValidationError) as exc:
                self.log.warning("Rotating the token failed (retried at the next heartbeat): %s", exc)
        if self.working():
            await self.grants.retry()

    async def pause(self, why: str) -> None:
        """Paused, probation again or switched off: the runs under way stop, grants not yet sent are dropped."""
        cancelled = await self.runner.cancel_all()
        for task in list(self.panel.tasks.values()):
            task.cancel()
        await self.grants.drop_pending("the team was paused before it was carried out")
        if cancelled:
            self.log.info("%s: cancelled %d run(s)", why, cancelled)

    async def refresh_charter(self) -> CharterView | None:
        try:
            status, data, headers = await self.atrium.call(
                "GET", "charter", extra_headers={"If-None-Match": self.charter_etag} if self.charter_etag else None)
        except AtriumError as exc:
            self.log.info("The charter is not available: %s", exc)
            return self.charter
        if status == 304 and self.charter is not None:
            return self.charter
        try:
            self.charter = CharterView.model_validate(data)
        except ValidationError:
            self.log.warning("Atrium's charter was not understood")
            return self.charter
        self.charter_etag = headers.get("etag")
        self.spool.add("charter.load", outcome="ok", detail={"version": self.charter.version})
        return self.charter

    async def load_credential(self) -> ConnectorBackend | None:
        """API-only mode: the dedicated credential, fetched once per start and kept in memory only."""
        try:
            credential = CredentialResponse.model_validate(await self.atrium.get("credential"))
        except (AtriumError, ValidationError) as exc:
            self.log.info("The dedicated credential is not available: %s", exc)
            return None
        self.secrets.add(*credential.secrets.values())
        from .connector_backend import ConnectorBackend  # hub.connectors: API-only mode only

        try:
            self.connector = ConnectorBackend(credential, transport=self.connector_transport)
        except Exception as exc:
            self.log.warning("The tool's connector could not be built: %s", exc)
            return None
        return self.connector

    # -- the inbox ---------------------------------------------------------------------------------

    async def inbox_once(self, wait: int = contract.WAIT_MAX) -> list[asyncio.Task[Any]]:
        """One poll: handle each message, then move the cursor (the next poll acknowledges them). Returns the work it
        started (runs, grants, conformance)."""
        data = await self.atrium.get("inbox", params={"cursor": self.cursor, "wait": max(0, wait)},
                                     timeout=LONG_POLL_TIMEOUT)
        answer = InboxResponse.model_validate(data)
        started = []
        for item in answer.messages:
            task = await self.handle(item)
            if task is not None:
                started.append(task)
        self.cursor = max(self.cursor, answer.cursor)
        return started

    async def handle(self, item: InboxItem) -> asyncio.Task[Any] | None:
        try:
            body = INBOX_BODIES[item.type].model_validate(item.body)
        except (KeyError, ValidationError):
            self.log.warning("Ignored an inbox %s message Atrium sent in an unexpected shape", item.type)
            return None
        kind = item.type
        if kind in ("run", "chat"):
            if body.run_id in self.runner.tasks:  # type: ignore[attr-defined]
                return None
            return self.runner.start(body.run_id, self.runner.relayed(body))  # type: ignore[attr-defined,arg-type]
        if kind == "grant":
            if not self.working():
                await self.grants.refuse_paused(body)  # type: ignore[arg-type]
                return None
            return self.spawn(self.grants.execute(body))  # type: ignore[arg-type]
        if kind == "denied":
            self.grants.denied(body)  # type: ignore[arg-type]
        elif kind == "action_result":
            self.grants.action_result(body)  # type: ignore[arg-type]
        elif kind == "pause":
            self.status = "paused"
            await self.pause("Atrium paused the subsidiary")
        elif kind == "resume":
            if self._wake is not None:
                self._wake.set()  # the next heartbeat brings the status and a ticket
        elif kind == "stop":
            await self.pause("Atrium stopped the subsidiary")
            raise Exit(EXIT_STOPPED, "Atrium stopped the subsidiary.", remember=True)
        elif kind == "charter_changed":
            await self.refresh_charter()
        elif kind == "conformance":
            return self.spawn(self.run_conformance(body))  # type: ignore[arg-type]
        return None

    # -- conformance (sidecar-run: claimed) ----------------------------------------------------------

    async def run_conformance(self, msg: ConformanceMessage) -> list[ConformanceRow]:
        rows = []
        for raw in msg.vectors:
            if raw.get("check") == "connector_test":
                rows.append(await self._k1(str(raw.get("id", "K1"))))
                continue
            try:
                vector = contract.Vector.from_json(raw)
            except (KeyError, TypeError, ValueError):
                rows.append(ConformanceRow(id=str(raw.get("id", "?"))[:8], ok=False, detail="unreadable vector"))
                continue
            rows.append(await self._vector(vector))
        try:
            await self.atrium.post("conformance", {"rows": [r.model_dump(mode="json") for r in rows],
                                                   "built_at": msg.built_at})
        except (AtriumError, Unavailable) as exc:
            self.log.warning("Atrium did not take the conformance results: %s", exc)
        self.spool.add("conformance.run", outcome="passed" if rows and all(r.ok for r in rows) else "failed",
                       detail={"rows": len(rows), "failed": [r.id for r in rows if not r.ok][:20]})
        return rows

    async def _vector(self, vector: contract.Vector) -> ConformanceRow:
        bridge = self._bridge()
        if bridge is None:
            return ConformanceRow(id=vector.id, ok=False, detail="no bridge configured")
        ok, detail, status, code = True, "ok", None, None
        for step in vector.steps:
            try:
                status, body = await bridge.step(step)
            except BridgeError as exc:
                ok, detail = False, f"no answer ({exc.code})"
                break
            try:
                found = json.loads(body.decode("utf-8")).get("code")
            except (ValueError, UnicodeError, AttributeError):
                found = None
            code = found if isinstance(found, str) and found.isidentifier() and len(found) <= 40 else None
            ok, detail = contract.check_answer(step, status, body)
            if not ok:
                break
        return ConformanceRow(id=vector.id, ok=ok, status=status, code=code, detail=detail[:300])

    async def _k1(self, row_id: str) -> ConformanceRow:
        backend = self.connector or await self.load_credential()
        if backend is None:
            return ConformanceRow(id=row_id, ok=False, detail="the dedicated credential is not available")
        ok, detail = await backend.test()
        return ConformanceRow(id=row_id, ok=ok, detail=detail[:300])

    # -- the passes ----------------------------------------------------------------------------------

    def marked(self, name: str) -> bool:
        data = self.state.read_json(name)
        return isinstance(data, dict) and data.get("subsidiary_id") == self.config.subsidiary_id

    def remember(self, exc: Exit) -> None:
        """Atrium stopped the subsidiary, or refused the token: the next start exits at once (a container restart
        policy does not hammer Atrium) - until a new enrollment code is given, after a refused token."""
        if exc.remember:
            self.state.write_json(STOPPED if exc.code == EXIT_STOPPED else REFUSED,
                                  {"subsidiary_id": self.config.subsidiary_id, "at": self.clock()})

    async def start(self) -> HeartbeatResponse:
        self.state.ensure()
        for name in self.state.loose():
            self.log.warning("%s in the state directory can be read by other users: it should be 0600", name)
        if self.marked(STOPPED):
            raise Exit(EXIT_STOPPED, "Atrium stopped this subsidiary: it does not work again. A new subsidiary comes "
                                     "with a new bundle.")
        token = self.state.token()
        if token is not None and (token.subsidiary_id != self.config.subsidiary_id or self.marked(REFUSED)):
            if not self.env.get(ENROLL_ENV):
                raise Exit(EXIT_TOKEN, "This sidecar's token no longer works (Atrium refused it, or config.json names "
                                       f"another subsidiary): enroll again - start it with {ENROLL_ENV} set to a new "
                                       "one-time code an administrator issued in Atrium.")
            await self.enroll(again=True)
        else:
            await self.enroll()
        if self.key is None:
            raise Exit(EXIT_TOKEN, "The state directory holds a token but no key: enroll again.")
        return await self.heartbeat_once()

    async def once(self) -> int:
        """--once: one pass of every task (enroll when needed, heartbeat, inbox, panel, events), waiting for the work
        it started, then a heartbeat that ships the spool."""
        try:
            await self.start()
            work = await self.inbox_once(wait=0)
            work += await self.panel.once(wait=0)
            await self.events.once(wait=0)
            if work:
                await asyncio.gather(*work, return_exceptions=True)
            await self.heartbeat_once()
            return 0
        except Exit as exc:
            self.remember(exc)
            self.log.error("%s", exc)
            return exc.code
        finally:
            await self.aclose()

    async def check(self, out: Callable[[str], None] = print) -> int:
        """--check: Atrium and the bridge (or the tool's API) answer, and the conformance vectors Atrium sends next
        pass. 0 when everything that ran passed."""
        try:
            reply = await self.start()
            out(f"Atrium: reachable, the subsidiary is {reply.status}"
                + (f" ({', '.join(reply.flags)})" if reply.flags else ""))
            ok = True
            if self.config.mode == "bridge":
                bridge = self._bridge()
                healthy = bridge is not None and await bridge.health()
                ping = await self.ping()
                out(f"Bridge: health {'ok' if healthy else 'FAILED'}; ping "
                    + ("ok, manifest " + str(ping.get("manifest_sha256", "?"))[:16] if ping and ping.get("ok")
                       else f"not ok ({(ping or {}).get('error', 'no ticket')})"))
                ok = ok and healthy
            else:
                backend = self.connector or await self.load_credential()
                passed, detail = await backend.test() if backend else (False, "no dedicated credential")
                out(f"Tool API: {'ok' if passed else 'FAILED'} ({detail})")
                ok = ok and passed
            rows: list[ConformanceRow] = []
            for _ in range(CHECK_POLLS):
                for item in (InboxResponse.model_validate(await self.atrium.get(
                        "inbox", params={"cursor": self.cursor, "wait": contract.WAIT_MAX},
                        timeout=LONG_POLL_TIMEOUT))).messages:
                    self.cursor = max(self.cursor, item.seq)
                    if item.type == "conformance":
                        rows = await self.run_conformance(ConformanceMessage.model_validate(item.body))
                if rows:
                    break
            if rows:
                failed = [r.id for r in rows if not r.ok]
                out(f"Conformance: {len(rows) - len(failed)} of {len(rows)} passed"
                    + (f"; failed: {', '.join(failed)}" if failed else ""))
                ok = ok and not failed
            else:
                out("Conformance: Atrium did not send vectors (an administrator re-runs them in Atrium)")
            return 0 if ok else 1
        except Exit as exc:
            self.remember(exc)
            out(str(exc))
            return exc.code
        except (AtriumError, Unavailable) as exc:
            out(f"Atrium: {exc}")
            return 1
        finally:
            await self.aclose()

    async def run(self) -> int:
        """Run until Atrium stops the subsidiary (4) or the token no longer works (3)."""
        self._exited, self._wake = asyncio.Event(), asyncio.Event()
        try:
            while True:
                try:
                    await self.start()
                    break
                except (Unavailable, AtriumError, ValidationError) as exc:  # five 401s in a row end it (Exit)
                    delay = self.backoff.next()
                    self.log.warning("%s; retrying in %.0f s", exc, delay)
                    await self.sleep(delay)
            self.backoff.reset()
            loops = [self.spawn(self._loop("heartbeat", self._heartbeat_step)),
                     self.spawn(self._loop("inbox", self._inbox_step)),
                     self.spawn(self._loop("panel", self._panel_step)),
                     self.spawn(self._loop("events", self._events_step))]
            exited = self.spawn(self._exited.wait())
            done, _ = await asyncio.wait([*loops, exited], return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                if task is not exited and task.exception() is not None:
                    raise task.exception()  # type: ignore[misc]
            if self.exit is not None:
                raise self.exit
            return 0
        except Exit as exc:
            self.remember(exc)
            self.log.error("%s", exc)
            return exc.code
        finally:
            await self.aclose()

    async def _loop(self, name: str, step: Callable[[], Awaitable[None]]) -> None:
        backoff = Backoff(rng=self.backoff.rng)
        while True:
            try:
                await step()
                backoff.reset()
            except Exit as exc:
                self._exiting(exc)
                return
            except (Unavailable, AtriumError, ValidationError) as exc:
                delay = backoff.next()
                self.log.warning("%s: %s; retrying in %.0f s", name, exc, delay)
                await self.sleep(delay)

    async def _heartbeat_step(self) -> None:
        await self.heartbeat_once()
        if self._wake is not None:
            try:
                await asyncio.wait_for(self._wake.wait(), HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def _inbox_step(self) -> None:
        await self.inbox_once()

    async def _panel_step(self) -> None:
        if not self.panel.enabled():
            await self.sleep(IDLE)
            return
        began = self.clock()
        await self.panel.once()
        if self.clock() - began < PULL_GAP:
            await self.sleep(PULL_GAP)

    async def _events_step(self) -> None:
        if not self.events.enabled():
            await self.sleep(IDLE)
            return
        began = self.clock()
        await self.events.once()
        if self.clock() - began < PULL_GAP:
            await self.sleep(PULL_GAP)
