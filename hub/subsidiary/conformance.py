"""Conformance (4.14): proving that a deployed bridge behaves before its subsidiary may act.

Bridge mode. Atrium builds the vectors V1-V20 (``contract.build_vectors``): complete pre-signed requests, invalid on
purpose, signed with the subsidiary's real key for an ephemeral probe key nobody holds, expiring 60 s after they were
built. When Atrium reaches the bridge (``bridge_url``) it sends them itself through
``hub.subsidiary_config.bridge_transport`` without following redirects, and records the answers as **observed**;
otherwise the sidecar runs them (inbox ``conformance``) and posts its rows to ``POST /api/subsidiary/v1/conformance``,
recorded as **claimed**.

API-only mode: K1 (the dedicated credential passes the connector's test; the sidecar runs it), K2 (the connection is
not a network device) and K3 (the dedicated credential differs from the hub connection's, while
``subsidiary_separate_credential`` is on) - K2 and K3 are checked in Atrium.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from .. import guardrails
from ..integration import connections
from . import audit, contract, governance, keys, runtime
from .models import Conformance, ConformanceResults, ConformanceRow, Subsidiary

if TYPE_CHECKING:
    from ..core import Hub

PANEL_FILE = Path(__file__).parent / "templates" / "panel" / "panel.js"
BRIDGE_IDS = tuple(f"V{n}" for n in range(1, 21))
SIDECAR_ONLY_IDS = ("K1", "K2", "K3")
RESULT_WINDOW = 10 * 60  # sidecar-run results are accepted this long after the vectors were built
K1 = {"id": "K1", "title": "The dedicated credential passes the connector's test", "steps": [],
      "check": "connector_test"}


def vendored_panel() -> bytes | None:
    """The vendored panel widget (templates/panel/panel.js), when this hub ships it."""
    try:
        return PANEL_FILE.read_bytes()
    except OSError:
        return None


def panel_sha256() -> str | None:
    panel = vendored_panel()
    return contract.sha256_hex(panel) if panel is not None else None


def bridge_url(hub: "Hub", sub: Subsidiary) -> str | None:
    """Where the bridge is served: the URL recorded with the bridge, else the tool's own web address."""
    if sub.bridge and sub.bridge.bridge_url:
        return sub.bridge.bridge_url
    tool = hub.get_tool(sub.tool_id)
    if tool and tool.manifest:
        return tool.manifest.ui.url or tool.manifest.api.base_url
    return None


def build(hub: "Hub", sub: Subsidiary) -> list[contract.Vector]:
    if sub.bridge is None:
        raise governance.GovernanceError(409, "The subsidiary has no applied bridge yet.", "no_bridge")
    return contract.build_vectors(keys.signer(hub, sub.id), tool=sub.tool_id, sub=sub.id, manifest=sub.bridge.manifest,
                                  manifest_sha=sub.bridge.manifest_sha256, panel_sha=panel_sha256(),
                                  now=int(governance.clock(hub)), cv=sub.charter_version)


def _code(body: bytes) -> str | None:
    """The refusal code of an answer (a short identifier), never anything else it says."""
    try:
        value = json.loads(body.decode("utf-8")).get("code")
    except (ValueError, UnicodeError, AttributeError):
        return None
    return value if isinstance(value, str) and value.isidentifier() and len(value) <= 40 else None


async def _send(http: httpx.AsyncClient, step: contract.Step) -> tuple[int, bytes]:
    body = b""
    async with http.stream(step.method, step.path, headers=step.headers, content=step.body or None) as answer:
        async for chunk in answer.aiter_bytes():
            body += chunk
            if len(body) > contract.MAX_RESPONSE:
                break
        return answer.status_code, body


async def run_atrium(hub: "Hub", sub: Subsidiary, vectors: list[contract.Vector],
                     base_url: str) -> list[ConformanceRow] | None:
    """Send the vectors to the bridge; None when the bridge cannot be reached at all (the sidecar runs them then)."""
    cfg = hub.subsidiary_config
    rows = []
    async with httpx.AsyncClient(base_url=base_url, transport=cfg.bridge_transport, follow_redirects=False,
                                 timeout=cfg.bridge_timeout) as http:
        for vector in vectors:
            ok, detail, status, code = True, "ok", None, None
            for step in vector.steps:
                try:
                    status, body = await _send(http, step)
                except httpx.HTTPError as exc:
                    if vector.id == "V1":
                        return None
                    ok, detail = False, f"no answer ({exc.__class__.__name__})"
                    break
                code = _code(body)
                ok, detail = contract.check_answer(step, status, body)
                if not ok:
                    break
            rows.append(ConformanceRow(id=vector.id, ok=ok, status=status, code=code, detail=detail[:300]))
    return rows


def _result(status: int, body: bytes) -> Any:
    """The ``result`` of a successful bridge answer, or None."""
    try:
        data = json.loads(body.decode("utf-8")) if status == 200 and len(body) <= contract.MAX_RESPONSE else None
    except (ValueError, UnicodeError):
        return None
    return data.get("result") if isinstance(data, dict) and data.get("ok") is True else None


async def bridge_receipt(hub: "Hub", sub: Subsidiary, jti: str) -> tuple[str, int | None] | None:
    """What the bridge itself says about a grant (observed, not the sidecar's word): ``atrium.receipt`` and the bridge's
    clock (``atrium.ping``), asked with a probation ticket for a probe key only Atrium holds. (status, bridge time) -
    None when Atrium cannot reach the bridge or the answer is unusable."""
    url = bridge_url(hub, sub)
    if sub.mode != "bridge" or not url:
        return None
    cfg, probe, now = hub.subsidiary_config, contract.new_key(), int(governance.clock(hub))
    rate = sub.charter.budgets.rate() if sub.charter else dict(contract.DEFAULT_RATE)
    token, ticket = keys.issue_ticket(hub, sub.id, tool=sub.tool_id, cv=sub.charter_version, mode="probation",
                                      act=["atrium.ping", "atrium.receipt"], cnf=contract.public_b64(probe), rl=rate,
                                      now=now, ttl=contract.VECTOR_TTL)
    answers = []
    try:
        async with httpx.AsyncClient(base_url=url, transport=cfg.bridge_transport, follow_redirects=False,
                                     timeout=cfg.bridge_timeout) as http:
            for action, params in (("atrium.ping", {}), ("atrium.receipt", {"jti": jti})):
                body, path = contract.body_bytes(params), contract.call_path(action)
                headers = contract.call_headers(probe, ticket=token, ticket_jti=ticket["jti"], path=path, body=body,
                                                date=now)
                answers.append(_result(*await _send(http, contract.Step("POST", path, headers, body, 200))))
    except (httpx.HTTPError, httpx.InvalidURL):
        return None
    ping, receipt = answers
    status = receipt.get("status") if isinstance(receipt, dict) else None
    if status not in ("unused", "executed", "failed", "unknown"):  # unknown: it started, it may have run
        return None
    clock = ping.get("time") if isinstance(ping, dict) else None
    return status, clock if isinstance(clock, int) and not isinstance(clock, bool) else None


def _record(hub: "Hub", sub: Subsidiary, rows: list[ConformanceRow], *, by: str, actor: str) -> Conformance:
    expected = BRIDGE_IDS if sub.mode == "bridge" else SIDECAR_ONLY_IDS
    seen = {r.id for r in rows}
    ok = all(r.ok for r in rows) and set(expected) <= seen
    origin = "observed" if by == "atrium" else "claimed"
    result = Conformance(ok=ok, at=governance.clock(hub), by=by, origin=origin,  # type: ignore[arg-type]
                         manifest_sha256=sub.bridge.manifest_sha256 if sub.bridge else None, rows=rows)
    sub.conformance = result
    failed = [r.id for r in rows if not r.ok] + [i for i in expected if i not in seen]
    audit.record(hub, sub.id, "conformance", outcome="passed" if ok else "failed",
                 detail={"by": by, "origin": result.origin, "failed": failed[:20], "rows": len(rows)})
    hub.activity(actor, "info" if ok else "warn",
                 f"Conformance of the {governance.tool_name(hub, sub.tool_id)} "
                 f"{'bridge' if sub.mode == 'bridge' else 'sidecar'} {'passed' if ok else 'failed'} "
                 f"({'observed by Atrium' if by == 'atrium' else 'claimed by the sidecar'})"
                 + (f": {', '.join(failed[:8])}" if failed else ""), subsidiary_id=sub.id)
    governance.after_conformance(hub, sub, actor)
    return result


def atrium_rows(hub: "Hub", sub: Subsidiary) -> list[ConformanceRow]:
    """K2 and K3, checked in Atrium."""
    from ..agents.patcher import network_device

    conn = connections.get(hub, sub.tool_id)
    k2 = conn is not None and not network_device(conn.kind)
    rows = [ConformanceRow(id="K2", ok=k2, detail="the connection is not a network device" if k2
                           else "no connection, or a network device")]
    if not guardrails.value(hub, "subsidiary_separate_credential"):
        rows.append(ConformanceRow(id="K3", ok=True, detail="not required (subsidiary_separate_credential is off)"))
        return rows
    same = True
    if conn is not None and sub.credential is not None:
        try:
            own = set(connections.decrypt(hub, conn).values())
            mine = {hub.secrets.decrypt(v) for v in sub.credential.secrets.values()}
            same = bool(own & mine)
        except Exception:
            same = True
    detail = "the dedicated credential is missing or equals the hub's" if same else \
        "the dedicated credential differs from the hub's"
    rows.append(ConformanceRow(id="K3", ok=not same, detail=detail))
    return rows


def request_sidecar(hub: "Hub", sub: Subsidiary, vectors: list[dict[str, Any]]) -> float:
    """Ask the sidecar to run `vectors` (inbox ``conformance``); returns their build time, which its results quote."""
    built_at = governance.clock(hub)
    runtime.cancel(hub, sub.id, ("conformance",))
    runtime.post(hub, sub.id, "conformance", {"vectors": vectors, "built_at": built_at},
                 expires_at=built_at + RESULT_WINDOW)
    hub.subsidiaries.conformance[sub.id] = built_at
    audit.record(hub, sub.id, "conformance.request", detail={"vectors": len(vectors)})
    return built_at


async def run(hub: "Hub", sub: Subsidiary, actor: str) -> dict[str, Any]:
    """Run conformance now: Atrium-run when it reaches the bridge, else the sidecar's turn. Returns {by, conformance}
    (conformance None while the sidecar runs them)."""
    if sub.status not in ("deploying", "probation", "active", "paused"):
        raise governance.GovernanceError(409, f"The subsidiary is {sub.status}.", sub.status)
    if sub.mode == "sidecar_only":
        if sub.sidecar is None:
            raise governance.GovernanceError(409, "The sidecar is not enrolled yet: it runs K1.", "not_enrolled")
        request_sidecar(hub, sub, [K1])
        return {"by": "sidecar", "conformance": None}
    vectors = build(hub, sub)
    url = bridge_url(hub, sub)
    rows = await run_atrium(hub, sub, vectors, url) if url else None
    if rows is not None:
        current = governance.get(hub, sub.id) or sub  # the subsidiary may have changed while the bridge answered
        return {"by": "atrium", "conformance": _record(hub, current, rows, by="atrium", actor=actor)}
    if sub.sidecar is None:
        raise governance.GovernanceError(409, "Atrium cannot reach the bridge and no sidecar is enrolled to run the "
                                              "vectors.", "unreachable")
    request_sidecar(hub, sub, [v.to_json() for v in vectors])
    return {"by": "sidecar", "conformance": None}


def from_sidecar(hub: "Hub", sub: Subsidiary, results: ConformanceResults) -> Conformance:
    """POST /conformance: the rows of vectors Atrium asked the sidecar to run (claimed)."""
    built_at = hub.subsidiaries.conformance.get(sub.id)
    now = governance.clock(hub)
    if built_at is None or results.built_at is None or abs(results.built_at - built_at) > 1e-6 \
            or now - built_at > RESULT_WINDOW:
        raise governance.GovernanceError(409, "No conformance run is waiting for these results.", "not_requested")
    expected = BRIDGE_IDS if sub.mode == "bridge" else ("K1",)
    rows = [r for r in results.rows if r.id in expected]
    if len({r.id for r in rows}) != len(rows):
        raise governance.GovernanceError(422, "Each vector is reported once.", "duplicate")
    if sub.mode == "sidecar_only":
        rows += atrium_rows(hub, sub)
    del hub.subsidiaries.conformance[sub.id]
    return _record(hub, sub, rows, by="sidecar", actor=governance.ACTOR)


def due(hub: "Hub", sub: Subsidiary) -> bool:
    """Whether a heartbeat starts conformance on its own: on probation with none recorded and none under way."""
    return (sub.status == "probation" and sub.conformance is None and sub.id not in hub.subsidiaries.conformance
            and not (sub.id in hub.subsidiaries.tasks and not hub.subsidiaries.tasks[sub.id].done())
            and (sub.mode == "sidecar_only" or sub.bridge is not None))


def launch(hub: "Hub", sub: Subsidiary, actor: str = governance.ACTOR) -> asyncio.Task[Any]:
    """Run conformance in the background (from a heartbeat: the sidecar is not kept waiting)."""

    async def go() -> None:
        try:
            await run(hub, sub, actor)
        except Exception as exc:  # recorded, never raised into the event loop
            hub.activity(governance.ACTOR, "warn", f"Conformance of the {governance.tool_name(hub, sub.tool_id)} "
                                                   f"subsidiary could not run: {exc}", subsidiary_id=sub.id)
        await hub.bus.tell(governance.ACTOR, "module:grc", "evaluate")

    task = asyncio.get_running_loop().create_task(go())
    hub.subsidiaries.tasks[sub.id] = task
    return task
