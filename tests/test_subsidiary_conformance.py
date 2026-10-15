"""Conformance V1-V20 (contract 4.14) against the fake Helpdesk running the REAL vendored Python bridge
(tests/fakes/subsidiary_tool.py): the committed cross-language vectors and freshly built ones pass with every adapter,
Atrium-run (hub.subsidiary.conformance.run_atrium, over an in-process transport) and the way a sidecar runs them; each
broken variant of the core fails exactly the vectors that catch its bug; vectors expire. No real tool or network."""

from __future__ import annotations

import asyncio
import base64
import json
import random
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from fakes import subsidiary_tool as fake

from hub.subsidiary import conformance
from hub.subsidiary import contract as c
from hub.subsidiary import templates

VECTORS = json.loads((templates.ROOT.parent / "contract" / "vectors.json").read_text())
KEY = c.new_key(bytes([31]) * 32)
NOW = 1_800_000_000
IDS = [f"V{n}" for n in range(1, 21)]


def run(app: Any, vectors: list[c.Vector], *, wsgi: bool = False) -> dict[str, bool]:
    """What a sidecar does with the vectors: send each step verbatim, in order, and compare the answers."""
    transport = httpx.WSGITransport(app=app) if wsgi else None
    http = httpx.Client(transport=transport, base_url="http://helpdesk.test", follow_redirects=False) if wsgi \
        else TestClient(app, base_url="http://helpdesk.test", follow_redirects=False)
    out = {}
    for vector in vectors:
        ok = True
        for step in vector.steps:
            answer = http.request(step.method, step.path, headers=step.headers, content=step.body or None)
            ok, _ = c.check_answer(step, answer.status_code, answer.content)
            if not ok:
                break
        out[vector.id] = ok
    return out


def committed() -> tuple[dict[str, Any], list[c.Vector]]:
    conf = VECTORS["conformance"]
    options = {"keys": conf["env"]["ATRIUM_BRIDGE_KEYS"], "sub": conf["env"]["ATRIUM_SUBSIDIARY_ID"],
               "manifest": base64.b64decode(conf["manifest_b64"]), "panel_js": base64.b64decode(conf["panel_js_b64"]),
               "panel_sha256": conf["panel_sha256"], "clock": lambda: VECTORS["now"]}
    return options, [c.Vector.from_json(v) for v in conf["vectors"]]


def fresh(now: int = NOW, seed: int = 7) -> list[c.Vector]:
    return c.build_vectors(KEY, tool=fake.TOOL, sub=fake.SUB, manifest=fake.MANIFEST,
                           manifest_sha=c.manifest_sha256(fake.MANIFEST_RAW), panel_sha=templates.panel_sha256(),
                           now=now, rng=random.Random(seed))


@pytest.mark.parametrize("adapter", ["fastapi", "starlette", "mount", "middleware", "wsgi"])
def test_the_committed_vectors_pass_with_every_adapter(adapter):
    options, vectors = committed()
    if adapter == "wsgi":
        app, wsgi = fake.helpdesk_wsgi(**options).app, True
    else:
        app, wsgi = fake.helpdesk_app(adapter=adapter, **options).app, False
    assert run(app, vectors, wsgi=wsgi) == dict.fromkeys(IDS, True)


def test_fresh_vectors_pass_atrium_run_and_sidecar_run():
    tool = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW)
    vectors = fresh()
    stub = SimpleNamespace(subsidiary_config=SimpleNamespace(
        bridge_transport=httpx.ASGITransport(app=tool.app), bridge_timeout=10))
    rows = asyncio.run(conformance.run_atrium(stub, None, vectors, "http://helpdesk.test"))
    assert [(r.id, r.ok) for r in rows] == [(i, True) for i in IDS], [r for r in rows if not r.ok]
    second = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW)  # a sidecar runs them on a fresh bridge
    assert run(second.app, [c.Vector.from_json(v.to_json()) for v in fresh(seed=8)]) == dict.fromkeys(IDS, True)
    # nothing the vectors did reached the tool's data: only built-ins were called
    assert tool.desk.calls == [] and second.desk.calls == []


@pytest.mark.parametrize("broken, failing", [
    ("accepts_expired", {"V5", "V9"}),
    ("ignores_grant", {"V12"}),
    ("any_key", {"V3", "V6", "V7"}),  # without the request signature a changed body (V7) goes unnoticed as well
    ("no_nonce", {"V8"}),
    ("ignores_body_hash", {"V13"}),
    ("html_in_answer", {"V20"}),  # a re-pinned widget that renders answers as HTML is not the vendored one
    ("ignores_on_behalf", set()),  # the glue's job: black-box conformance cannot see it (test_bridge_core_python)
    ("writes_ungranted", {"V12", "V13"}),  # grants checked for atrium.noop_write only
])
def test_each_broken_variant_fails_exactly_its_vectors(broken, failing):
    tool = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW, broken=[broken])
    results = run(tool.app, fresh())
    assert {v for v, ok in results.items() if not ok} == failing


def test_the_vectors_probe_every_manifest_write_without_ever_running_one(monkeypatch):
    """Review (medium): V12-V15 tested grants on atrium.noop_write only, so a core that never asks a grant for the
    tool's own writes passed every vector. V12 and V13 now probe each manifest write and admin action - in a way that
    a core skipping the grant check (and even the on-behalf-of check) still refuses, so the probe never writes."""
    tool = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW, broken=["writes_ungranted"])
    results = run(tool.app, fresh())
    assert {v for v, ok in results.items() if not ok} == {"V12", "V13"}
    monkeypatch.setattr(fake.core.Bridge, "_on_behalf", lambda self, question_id, spec: None)
    worse = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW, broken=["writes_ungranted"])
    assert {v for v, ok in run(worse.app, fresh()).items() if not ok} == {"V12", "V13"}
    assert tool.desk.calls == [] and worse.desk.calls == []  # refused at step 7, then at step 8 (no call a minute)
    v12 = next(v for v in fresh() if v.id == "V12")
    assert [s.path.rsplit("/", 1)[1] for s in v12.steps] == ["atrium.noop_write", "tickets.set_priority",
                                                             "tickets.delete"]


def test_vectors_expire_sixty_seconds_after_they_were_built():
    clock = SimpleNamespace(now=NOW)
    tool = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: clock.now)
    clock.now = NOW + 61
    results = run(tool.app, fresh())
    assert results["V1"] and results["V20"]  # health and the widget need no signature
    assert not results["V8"] and not results["V15"] and not results["V19"]


def test_a_bridge_with_another_manifest_fails_v19():
    other = json.loads(fake.MANIFEST_RAW)
    other["actions"] = other["actions"][:1]
    tool = fake.helpdesk_app(keys=c.public_b64(KEY), clock=lambda: NOW, manifest=json.dumps(other).encode())
    results = run(tool.app, fresh())
    # V12 and V13 probe the approved manifest's write and admin actions too: this bridge does not have them
    assert {v for v, ok in results.items() if not ok} == {"V12", "V13", "V19"}


def test_a_bridge_signed_for_the_old_key_fails_after_rotation():
    """Stop rotates the subsidiary's key at once: a bridge still configured with the old key refuses new tickets."""
    tool = fake.helpdesk_app(keys=c.public_b64(c.new_key(bytes([32]) * 32)), clock=lambda: NOW)
    results = run(tool.app, fresh())
    assert results["V1"] and results["V2"] and results["V3"] and results["V20"]
    assert not results["V8"] and not results["V19"]
