"""The vendored Python bridge core and adapters (hub/subsidiary/templates/python) inside a fake Helpdesk tool
(tests/fakes/subsidiary_tool.py): every row of the verification order (contract 4.8) and the built-ins (4.9), fail
closed, the panel's session, CSRF header and per-user rules, on-behalf-of, single-use grants that survive a restart,
the bounded non-blocking outbox, the widget served byte-identical, the ASGI and WSGI adapters, the glue skeleton and
the sidecar bundle templates. No real tool, model or network."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from fakes import subsidiary_tool as fake

from hub.subsidiary import contract as c
from hub.subsidiary import templates
from hub.subsidiary.templates.python import adapters
from hub.subsidiary.templates.python import atrium_bridge_core as core

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "hub" / "subsidiary" / "contract" / "vectors.json").read_text())
KEY, NEXT, STRANGER, PROBE = (c.new_key(bytes([n]) * 32) for n in (21, 22, 23, 24))
KEYS = c.public_b64(KEY)
NOW = 1_800_000_000
EVERYTHING = [a["id"] for a in fake.MANIFEST["actions"]] + list(c.BUILTINS)


class Clock:
    def __init__(self, now: float = NOW):
        self.now = now

    def __call__(self) -> float:
        return self.now


class Sidecar:
    """Atrium's signatures and the sidecar's calls, made with the contract's reference functions."""

    def __init__(self, http: Any, clock: Clock, *, key=KEY, sub: str = fake.SUB, rl: dict[str, int] | None = None):
        self.http, self.clock, self.key, self.sub = http, clock, key, sub
        self.rl = rl or {"calls_per_min": 1000, "panel_per_user_hour": 10}

    def ticket(self, mode: str = "active", act: list[str] | None = None, **fields: Any) -> tuple[str, str]:
        token, p = c.make_ticket(fields.pop("signer", self.key), sub=fields.pop("sub", self.sub),
                                 tool=fields.pop("tool", fake.TOOL), cv=1, mode=mode,
                                 act=EVERYTHING if act is None else act, cnf=c.public_b64(PROBE), rl=self.rl,
                                 now=int(self.clock()), **fields)
        return token, p["jti"]

    def grant(self, action: str, params: dict[str, Any], **fields: Any) -> tuple[str, str]:
        token, p = c.make_grant(self.key, sub=self.sub, tool=fake.TOOL, cv=1, act=action, body=c.body_bytes(params),
                                apv="ap_test", now=int(self.clock()), **fields)
        return token, p["jti"]

    def headers(self, action: str, body: bytes, *, ticket: tuple[str, str] | None = None,
                grant: tuple[str, str] | None = None, obo: str | None = None, signer=PROBE) -> dict[str, str]:
        token, jti = ticket or self.ticket()
        return c.call_headers(signer, ticket=token, ticket_jti=jti, path=c.call_path(action), body=body,
                              date=int(self.clock()), grant=grant[0] if grant else None,
                              grant_jti=grant[1] if grant else None, on_behalf_of=obo)

    def call(self, action: str, params: dict[str, Any] | None = None, *, body: bytes | None = None,
             **options: Any) -> httpx.Response:
        body = c.body_bytes(params or {}) if body is None else body
        return self.http.post(c.call_path(action), content=body, headers=self.headers(action, body, **options))


def make(adapter: str = "fastapi", *, keys: str | None = KEYS, clock: Clock | None = None, **options: Any):
    clock = clock or Clock()
    tool = fake.helpdesk_app(keys=keys, adapter=adapter, clock=clock, **options)
    http = TestClient(tool.app, base_url="http://helpdesk.test", follow_redirects=False)
    return tool, http, Sidecar(http, clock), clock


def browser(tool: fake.FakeTool, username: str | None) -> TestClient:
    http = TestClient(tool.app, base_url="http://helpdesk.test", follow_redirects=False)
    if username:
        assert http.post("/login", json={"username": username}).status_code == 200
    http.headers["X-Atrium-Panel"] = "1"
    return http


def result(response: httpx.Response) -> Any:
    assert response.status_code == 200, response.text
    return response.json()["result"]


def refused(response: httpx.Response) -> tuple[int, str]:
    return response.status_code, response.json().get("code")


# --------------------------------------------------------------------------------------
# the vendored files
# --------------------------------------------------------------------------------------


def test_the_core_is_the_contract():
    for name in ("CONTRACT", "STATUS", "PANEL_STATUS", "BUILTINS", "PROBATION_BUILTINS", "MAX_BODY", "MAX_RESPONSE",
                 "CLOCK_LEEWAY", "NONCE_TTL", "NONCE_CAPACITY", "GRANT_JTI_KEEP", "MAX_TOKEN", "MAX_TOKEN_PAYLOAD",
                 "PANEL_OPEN_MAX", "PANEL_EXPIRY", "PANEL_UNAVAILABLE", "OUTBOX_MAX", "OUTBOX_TTL",
                 "EVENT_PAYLOAD_MAX", "DEFAULT_RATE", "WAIT_MAX"):
        assert getattr(core, name) == getattr(c, name), name
    for name in ("ACTION_ID_RE", "TOOL_ID_RE", "SUBSIDIARY_ID_RE", "PARAM_NAME_RE", "DATE_RE", "QUESTION_ID_RE"):
        assert getattr(core, name).pattern == getattr(c, name).pattern, name


def test_cores_manifest_is_up_to_date_and_pins_the_widget():
    assert templates.problems() == []
    doc = templates.manifest()
    assert doc["panel"]["sha256"] == templates.panel_sha256() == core.PANEL_JS_SHA256
    for family, spec in doc["cores"].items():
        for item in spec["files"]:
            assert hashlib.sha256(templates.read(item["template"])).hexdigest() == item["sha256"]
        assert set(templates.vendored(family)) == {f["path"] for f in spec["files"]}
        assert spec["stacks"] == list(c.CORE_FAMILIES[family])
    assert templates.vendored_sha256s()[templates.panel_sha256()] == "panel/panel.js"
    with pytest.raises(ValueError):
        templates.read("../contract.py")


def test_the_vendored_widget_and_cores_are_static():
    widget = templates.panel_js().decode()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in widget
    python = templates.read("python/atrium_bridge_core.py").decode() + templates.read("python/adapters.py").decode()
    for banned in ("eval(", "exec(", "subprocess", "os.system", "os.popen", "pickle", "0.0.0.0"):
        assert banned not in python


def test_unit_vectors_against_the_python_core():
    u = VECTORS["units"]
    for case in u["b64u"]:
        try:
            out = core.b64u_decode(case["in"]).hex()
        except ValueError:
            out = None
        assert (out is not None) == case["ok"] and (not case["ok"] or out == case["hex"]), case
    for case in u["keys"]:
        try:
            count = len(core.parse_keys(case["value"]))
        except ValueError:
            count = None
        assert (count is not None) == case["ok"] and (not case["ok"] or count == case["count"]), case
    for name, prefix, refusal, fields_ok in (("tickets", "AT1", "bad_ticket", core.ticket_fields_ok),
                                             ("grants", "AG1", "grant_mismatch", core.grant_fields_ok)):
        units = u[name]
        bridge = core.Bridge(env={})
        bridge.tool, bridge.sub = units["tool"], units["sub"]
        for case in units["cases"]:
            try:
                p = core.verify_token(case["token"], prefix, core.parse_keys(units["keys"]), refusal)
                if not fields_ok(p):
                    raise core.Refused(refusal)
                if name == "tickets":
                    bridge._check_ticket(p, units["now"])
                else:
                    bridge._check_grant(p, case["action"], base64.b64decode(case.get("body_b64", "")), units["now"])
                got = None
            except core.Refused as exc:
                got = exc.code
            assert got == (None if case["ok"] else case["code"]), case["title"]
            if case["ok"]:
                assert p == case["payload"]
    for case in u["signing"]:
        body = base64.b64decode(case["body_b64"])
        message = core.signing_string(case["method"], case["path"], case["date"], case["nonce"], body,
                                      case["ticket_jti"], case["grant_jti"], case["on_behalf_of"])
        assert not case["valid"] or message.decode() == case["string"]
        assert core.verify_signature(case["cnf"], case["signature"], message) is case["valid"], case["title"]
    for case in u["params"]["cases"]:
        try:
            got = core.validate_params(u["params"]["schemas"][case["schema"]],
                                       core.parse_body(base64.b64decode(case["body_b64"])))
        except core.Refused as exc:
            got = exc.code
        assert got == (case["params"] if case["ok"] else "bad_params"), case["title"]


# --------------------------------------------------------------------------------------
# fail closed, routes, headers
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("env", [{}, {"ATRIUM_BRIDGE_KEYS": "not-a-key"}, {"ATRIUM_BRIDGE_KEYS": f"{KEYS},{KEYS},{KEYS}"},
                                 {"ATRIUM_BRIDGE_KEYS": KEYS, "ATRIUM_TOOL_ID": "another-tool"},
                                 {"ATRIUM_BRIDGE_KEYS": KEYS, "ATRIUM_SUBSIDIARY_ID": "sub_x"},
                                 {"ATRIUM_BRIDGE_KEYS": KEYS, "ATRIUM_BRIDGE_ALLOW": "10.0.0.0/33"}])
def test_without_valid_configuration_everything_but_health_fails_closed(env):
    tool, http, sidecar, _ = make(keys=None, env=env)
    assert not tool.bridge.ready
    assert http.get(c.HEALTH_PATH).json() == {"status": "ok"}
    for method, path in (("GET", c.PANEL_JS_PATH), ("GET", c.PANEL_STATUS_PATH), ("POST", c.PANEL_ASK_PATH),
                         ("POST", c.call_path("atrium.ping")), ("GET", "/.atrium/v1/anything")):
        answer = http.request(method, path, content=b'{"params":{}}')
        assert (answer.status_code, answer.json()) == (503, {"ok": False, "code": "not_configured"}), path
    assert sidecar.call("atrium.ping").status_code == 503
    assert tool.bridge.emit("helpdesk.ticket.created", {}) is False
    # the tool works unchanged
    assert http.get("/").status_code == 200 and "/.atrium/panel.js" in http.get("/").text
    assert http.post("/login", json={"username": "agent"}).status_code == 200
    assert len(http.get("/api/tickets").json()) == 3


def test_a_manifest_that_breaks_the_contract_fails_closed():
    bad = json.loads(fake.MANIFEST_RAW)
    bad["actions"][0]["params"]["properties"]["q"] = {"type": "string"}  # no maxLength
    tool, http, sidecar, _ = make(manifest=json.dumps(bad).encode())
    assert not tool.bridge.ready and "breaks the contract" in tool.bridge.problem
    assert sidecar.call("atrium.ping").status_code == 503


def test_answers_are_json_nosniff_without_cors_and_never_echo_the_request():
    tool, http, sidecar, _ = make()
    marker = "ECHO-ME-" + "x" * 20
    answers = [http.get(c.HEALTH_PATH), http.get("/.atrium/v1/nothing"),
               sidecar.call("tickets.list", {"q": marker}, ticket=sidecar.ticket(signer=STRANGER)),
               sidecar.call("tickets.list", {"q": marker, "extra": marker}),
               http.post(c.call_path("atrium.ping"), content=marker.encode(), headers={"Atrium-Ticket": marker})]
    assert [a.status_code for a in answers] == [200, 404, 401, 422, 401]
    for answer in answers:
        assert answer.headers["content-type"] == "application/json"
        assert answer.headers["x-content-type-options"] == "nosniff"
        assert not any(h.startswith("access-control-") for h in answer.headers)
        assert marker not in answer.text


# --------------------------------------------------------------------------------------
# the verification order, row by row
# --------------------------------------------------------------------------------------


def test_source_allow_list_comes_first():
    clock = Clock()
    tool = fake.helpdesk_app(keys=KEYS, clock=clock, env={"ATRIUM_BRIDGE_ALLOW": "10.0.0.0/8"})
    sidecar = Sidecar(TestClient(tool.app, base_url="http://helpdesk.test"), clock)
    assert refused(sidecar.call("atrium.ping", ticket=sidecar.ticket(signer=STRANGER))) == (403, "source_not_allowed")

    async def through(allow: str) -> int:
        app = fake.helpdesk_app(keys=KEYS, clock=clock, env={"ATRIUM_BRIDGE_ALLOW": allow}).app
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=("10.1.2.3", 4000)),
                                     base_url="http://helpdesk.test") as http:
            body = c.body_bytes({})
            answer = await http.post(c.call_path("atrium.ping"), content=body,
                                     headers=Sidecar(None, clock).headers("atrium.ping", body))
            return answer.status_code
    assert asyncio.run(through("10.0.0.0/8, fd00::/8")) == 200
    assert asyncio.run(through("192.168.0.0/16")) == 403


def test_size_limit_before_the_ticket():
    tool, http, sidecar, _ = make()
    big = b'{"params":{"q":"' + b"x" * (70 * 1024) + b'"}}'
    assert refused(http.post(c.call_path("tickets.list"), content=big)) == (413, "too_large")
    assert refused(sidecar.call("tickets.list", body=big)) == (413, "too_large")


@pytest.mark.parametrize("change, expected", [
    (lambda s: {"ticket": s.ticket(signer=STRANGER)}, (401, "bad_ticket")),
    (lambda s: {"ticket": s.ticket(tool="other")}, (401, "bad_ticket")),
    (lambda s: {"ticket": s.ticket(sub="sub_111111111111")}, (401, "bad_ticket")),
    (lambda s: {"ticket": s.ticket(ttl=-120)}, (401, "expired")),
    (lambda s: {"signer": STRANGER}, (401, "bad_signature")),
])
def test_ticket_and_signature_rows(change, expected):
    tool, http, sidecar, _ = make()
    assert refused(sidecar.call("atrium.ping", **change(sidecar))) == expected


def test_both_rotation_keys_are_accepted_and_tickets_are_bound_to_the_sidecar_key():
    tool, http, sidecar, _ = make(keys=f"{KEYS}, {c.public_b64(NEXT)}")
    assert result(sidecar.call("atrium.ping", ticket=sidecar.ticket(signer=NEXT)))["contract"] == c.CONTRACT
    assert result(sidecar.call("atrium.ping"))["core"] == core.CORE_VERSION


def test_dates_and_nonces():
    tool, http, sidecar, clock = make()
    body = c.body_bytes({})
    headers = sidecar.headers("atrium.ping", body)
    assert http.post(c.call_path("atrium.ping"), content=body, headers=headers).status_code == 200
    assert refused(http.post(c.call_path("atrium.ping"), content=body, headers=headers)) == (401, "replay")
    moved = {**sidecar.headers("atrium.ping", body), "Atrium-Date": str(NOW + 1)}
    assert refused(http.post(c.call_path("atrium.ping"), content=body, headers=moved)) == (401, "bad_signature")
    stale = Sidecar(http, Clock(clock.now - 300))
    assert refused(stale.call("atrium.ping", ticket=sidecar.ticket())) == (401, "expired")
    for header, value in (("Atrium-Nonce", "short"), ("Atrium-Date", "soon"), ("Atrium-On-Behalf-Of", "a b")):
        assert refused(http.post(c.call_path("atrium.ping"), content=body,
                                 headers={**sidecar.headers("atrium.ping", body), header: value})) \
            == (401, "bad_signature"), header


def test_a_full_nonce_store_refuses_rather_than_forget():
    tool, http, sidecar, _ = make()
    tool.bridge.nonces.capacity = 2
    assert sidecar.call("atrium.ping").status_code == 200
    assert sidecar.call("atrium.ping").status_code == 200
    assert refused(sidecar.call("atrium.ping")) == (503, "busy")


def test_action_rows_probation_and_the_ticket_list():
    tool, http, sidecar, _ = make()
    probation = sidecar.ticket(mode="probation", act=[*c.PROBATION_BUILTINS, "tickets.list"])
    assert refused(sidecar.call("tickets.list", ticket=probation)) == (403, "probation")
    assert result(sidecar.call("atrium.describe", ticket=probation))["tool_id"] == fake.TOOL
    assert refused(sidecar.call("tickets.list", ticket=sidecar.ticket(act=["atrium.ping"]))) \
        == (403, "action_not_allowed")
    assert refused(sidecar.call("tickets.unknown", ticket=sidecar.ticket(act=["tickets.unknown"]))) \
        == (403, "action_not_allowed")


def test_params_are_refused_before_any_handler_runs():
    tool, http, sidecar, _ = make()
    for params in ({"status": "archived"}, {"q": 5}, {"q": "x", "limit": 3}, {"q": None}):
        assert refused(sidecar.call("tickets.list", params)) == (422, "bad_params")
    for body in (b'{"params":{},"extra":1}', b'[1]', b'{"params":[]}', b'{"params":{"q":NaN}}', b"\xff"):
        assert refused(sidecar.call("tickets.list", body=body)) == (422, "bad_params")
    assert tool.desk.calls == []
    assert len(result(sidecar.call("tickets.list", {"status": "open", "q": "printer"}))) == 1
    assert tool.desk.calls == [("tickets.list", {"status": "open", "q": "printer"})]


def test_writes_need_a_grant_bound_to_the_exact_body_and_used_once(tmp_path):
    grants = core.SqliteGrants(tmp_path / "grants.sqlite3")
    tool, http, sidecar, clock = make(grants=grants)
    params = {"ticket_id": 1, "priority": "high"}
    assert refused(sidecar.call("tickets.set_priority", params)) == (403, "grant_required")
    granted = sidecar.grant("tickets.set_priority", params)
    assert refused(sidecar.call("tickets.set_priority", {"ticket_id": 2, "priority": "high"}, grant=granted)) \
        == (403, "grant_mismatch")
    assert refused(sidecar.call("tickets.set_priority", body=json.dumps({"params": params}).encode(),
                                grant=granted)) == (403, "grant_mismatch")  # same params, other bytes
    assert refused(sidecar.call("tickets.delete", {"ticket_id": 1}, grant=granted)) == (403, "grant_mismatch")
    answer = sidecar.call("tickets.set_priority", params, grant=granted)
    assert answer.status_code == 200
    assert answer.json()["receipt"] == {"jti": granted[1], "status": "executed", "at": NOW}
    assert tool.desk.tickets[1].priority == "high"
    assert refused(sidecar.call("tickets.set_priority", params, grant=granted)) == (409, "grant_used")
    assert result(sidecar.call("atrium.receipt", {"jti": granted[1]})) == {"status": "executed", "at": NOW}
    assert result(sidecar.call("atrium.receipt", {"jti": "never-used"})) == {"status": "unused"}
    expired = sidecar.grant("tickets.set_priority", params, ttl=-61)
    assert refused(sidecar.call("tickets.set_priority", params, grant=expired)) == (401, "expired")
    # admin risk needs a grant too
    assert refused(sidecar.call("tickets.delete", {"ticket_id": 3})) == (403, "grant_required")
    assert result(sidecar.call("tickets.delete", {"ticket_id": 3},
                               grant=sidecar.grant("tickets.delete", {"ticket_id": 3}))) == {"deleted": 3}
    # a restart (a new bridge on the same store) still refuses the used grant
    tool2, http2, sidecar2, _ = make(grants=core.SqliteGrants(tmp_path / "grants.sqlite3"), clock=clock)
    assert refused(sidecar2.call("tickets.set_priority", params, grant=granted)) == (409, "grant_used")
    assert tool2.desk.tickets[1].priority == "normal"


def test_marking_is_the_authoritative_single_use_check(tmp_path):
    """Two calls racing with one grant both pass used(); only one can mark it."""
    class Racing(core.SqliteGrants):
        def used(self, jti: str) -> bool:
            return False
    tool, http, sidecar, _ = make(grants=Racing(tmp_path / "g.sqlite3"))
    params = {"ticket_id": 1, "priority": "low"}
    granted = sidecar.grant("tickets.set_priority", params)
    assert sidecar.call("tickets.set_priority", params, grant=granted).status_code == 200
    assert refused(sidecar.call("tickets.set_priority", params, grant=granted)) == (409, "grant_used")
    assert [name for name, _ in tool.desk.calls] == ["tickets.set_priority"]
    memory = core.MemoryGrants()
    assert memory.mark("j", NOW + 10, NOW) is True and memory.mark("j", NOW + 10, NOW) is False


def test_shared_nonces_refuse_a_request_replayed_to_another_worker(tmp_path):
    clock = Clock()
    workers = [fake.helpdesk_app(keys=KEYS, clock=clock, nonces=core.SqliteNonces(tmp_path / "nonces.sqlite3"))
               for _ in range(2)]
    first, second = (TestClient(w.app, base_url="http://helpdesk.test") for w in workers)
    body = c.body_bytes({})
    headers = Sidecar(None, clock).headers("atrium.ping", body)
    assert first.post(c.call_path("atrium.ping"), content=body, headers=headers).status_code == 200
    assert refused(second.post(c.call_path("atrium.ping"), content=body, headers=headers)) == (401, "replay")
    store = core.SqliteNonces(tmp_path / "small.sqlite3", capacity=1)
    store.add("a" * 22, NOW)
    with pytest.raises(core.Refused) as busy:
        store.add("b" * 22, NOW)
    assert busy.value.code == "busy" and len(store) == 1
    store.add("b" * 22, NOW + core.NONCE_TTL)  # the old one expired
    assert len(store) == 1


def test_a_grant_marked_but_never_finished_reports_unknown_never_unused(tmp_path):
    grants = core.SqliteGrants(tmp_path / "g.sqlite3")
    grants.mark("crashed", NOW + 3600, NOW)
    tool, http, sidecar, _ = make(grants=grants)
    assert result(sidecar.call("atrium.receipt", {"jti": "crashed"})) == {"status": "unknown", "at": NOW}


def test_a_failing_handler_is_recorded_failed_and_the_grant_stays_used():
    tool, http, sidecar, _ = make()
    params = {"ticket_id": 99, "priority": "low"}  # no ticket 99: the tool's own service layer fails
    granted = sidecar.grant("tickets.set_priority", params)
    answer = sidecar.call("tickets.set_priority", params, grant=granted)
    assert answer.status_code == 500
    assert answer.json() == {"ok": False, "code": "failed", "receipt": {"jti": granted[1], "status": "failed", "at": NOW}}
    assert refused(sidecar.call("tickets.set_priority", params, grant=granted)) == (409, "grant_used")


def test_the_rate_limit_comes_from_the_ticket():
    tool, http, sidecar, _ = make()
    sidecar.rl = {"calls_per_min": 2, "panel_per_user_hour": 10}
    assert [sidecar.call("atrium.ping").status_code for _ in range(3)] == [200, 200, 429]


# --------------------------------------------------------------------------------------
# the panel and on-behalf-of
# --------------------------------------------------------------------------------------


def test_the_panel_needs_the_session_and_the_header():
    tool, http, sidecar, _ = make()
    anonymous = browser(tool, None)
    assert refused(anonymous.get(c.PANEL_STATUS_PATH)) == (401, "no_session")
    signed_in = browser(tool, "agent")
    no_header = TestClient(tool.app, base_url="http://helpdesk.test", cookies=signed_in.cookies)
    assert refused(no_header.post(c.PANEL_ASK_PATH, json={"text": "hi"})) == (403, "panel_header_required")
    assert signed_in.get(c.PANEL_STATUS_PATH).json() == {"enabled": True, "team_online": False}
    for body in ({"text": ""}, {"text": "x" * 2001}, {"text": "x", "page": {"path": "/" * 301}},
                 {"text": "x", "page": {"other": "y"}}, {"text": "x", "user": "admin"}, ["x"]):
        assert refused(signed_in.post(c.PANEL_ASK_PATH, json=body)) == (422, "bad_params"), body
    assert refused(signed_in.post(c.PANEL_ASK_PATH, content=b"x" * (65 * 1024))) == (413, "too_large")


def test_panel_questions_are_private_rate_limited_and_answered_as_text():
    tool, http, sidecar, clock = make()
    rita, abe = browser(tool, "requester"), browser(tool, "agent")
    qid = rita.post(c.PANEL_ASK_PATH, json={"text": "Where is my ticket?", "page": {"path": "/t/1",
                                                                                   "record_id": "ticket:1"}}).json()["question_id"]
    assert rita.get(c.PANEL_QUESTION_PREFIX + qid).json()["status"] == "waiting"
    assert refused(abe.get(c.PANEL_QUESTION_PREFIX + qid)) == (404, "not_found")
    pulled = result(sidecar.call("atrium.panel.pull", {"wait": 0}))
    assert pulled == [{"id": qid, "text": "Where is my ticket?", "page": {"path": "/t/1", "record_id": "ticket:1"},
                       "asked_at": NOW, "tool_user": {"id": "requester", "display": "Rita Requester",
                                                      "roles": ["requester"]}}]
    assert rita.get(c.PANEL_STATUS_PATH).json()["team_online"] is True
    assert result(sidecar.call("atrium.panel.pull", {})) == []  # delivered once
    assert result(sidecar.call("atrium.panel.answer", {"question_id": qid, "text": "Looking...",
                                                       "status": "working"})) == {"ok": True}
    assert rita.get(c.PANEL_QUESTION_PREFIX + qid).json()["status"] == "answering"
    html = "<img src=x onerror=alert(1)> Ticket 1 is open."
    assert result(sidecar.call("atrium.panel.answer", {"question_id": qid, "text": html, "status": "answered",
                                                       "by": "Front desk"})) == {"ok": True}
    assert rita.get(c.PANEL_QUESTION_PREFIX + qid).json() == {
        "id": qid, "status": "answered", "text": "Where is my ticket?", "asked_at": NOW, "answer": html,
        "by": "Front desk"}
    assert result(sidecar.call("atrium.panel.answer", {"question_id": qid, "text": "again",
                                                       "status": "answered"})) == {"ok": False}
    # per user and hour, from the ticket (2 here); other users are not affected
    sidecar.rl = {"calls_per_min": 1000, "panel_per_user_hour": 2}
    sidecar.call("atrium.ping")
    assert rita.post(c.PANEL_ASK_PATH, json={"text": "two"}).status_code == 200
    assert refused(rita.post(c.PANEL_ASK_PATH, json={"text": "three"})) == (429, "rate_limited")
    assert abe.post(c.PANEL_ASK_PATH, json={"text": "mine"}).status_code == 200
    clock.now += 3601
    sidecar.clock = clock
    assert rita.post(c.PANEL_ASK_PATH, json={"text": "an hour later"}).status_code == 200


def test_unanswered_questions_become_unavailable_and_expire(monkeypatch):
    tool, http, sidecar, clock = make()
    rita = browser(tool, "requester")
    qid = rita.post(c.PANEL_ASK_PATH, json={"text": "anyone?"}).json()["question_id"]
    clock.now += 119
    assert rita.get(c.PANEL_QUESTION_PREFIX + qid).json()["status"] == "waiting"
    clock.now += 1
    assert rita.get(c.PANEL_QUESTION_PREFIX + qid).json() | {"asked_at": 0} == {
        "id": qid, "status": "unavailable", "text": "anyone?", "asked_at": 0, "answer": c.PANEL_UNAVAILABLE,
        "by": "Atrium"}
    clock.now += 30 * 60
    assert refused(rita.get(c.PANEL_QUESTION_PREFIX + qid)) == (404, "not_found")
    monkeypatch.setattr(core, "PANEL_OPEN_MAX", 1)
    assert rita.post(c.PANEL_ASK_PATH, json={"text": "one"}).status_code == 200
    assert refused(rita.post(c.PANEL_ASK_PATH, json={"text": "two"})) == (503, "busy")


@pytest.mark.parametrize("options, enabled", [({"panel": False}, False),
                                              ({"env": {"ATRIUM_PANEL_ROLES": "agent,admin"}}, False),
                                              ({"env": {"ATRIUM_PANEL_ROLES": "requester"}}, True),
                                              ({"panel_sha256": "0" * 64}, False)])
def test_the_panel_can_be_off_or_limited_to_roles(options, enabled):
    tool, http, sidecar, _ = make(**options)
    rita = browser(tool, "requester")
    assert rita.get(c.PANEL_STATUS_PATH).json()["enabled"] is enabled
    assert (rita.post(c.PANEL_ASK_PATH, json={"text": "hi"}).status_code == 200) is enabled
    if not enabled:
        assert refused(rita.post(c.PANEL_ASK_PATH, json={"text": "hi"})) == (404, "not_found")


def test_panel_runs_act_as_the_asking_user_and_the_service_principal():
    tool, http, sidecar, _ = make()
    rita = browser(tool, "requester")
    qid = rita.post(c.PANEL_ASK_PATH, json={"text": "Show me the payroll ticket"}).json()["question_id"]
    result(sidecar.call("atrium.panel.pull", {}))
    assert [t["id"] for t in result(sidecar.call("tickets.list", {}))] == [3, 2, 1]  # the service principal alone
    assert [t["id"] for t in result(sidecar.call("tickets.list", {}, obo=qid))] == [1]  # requester AND principal
    failed = sidecar.call("tickets.draft_reply", {"ticket_id": 2, "text": "Payday is Friday"}, obo=qid)
    assert failed.status_code == 500 and tool.desk.tickets[2].drafts == []
    assert result(sidecar.call("tickets.draft_reply", {"ticket_id": 1, "text": "On it"}, obo=qid))["draft"] == 1
    params = {"ticket_id": 1, "priority": "high"}
    assert refused(sidecar.call("tickets.set_priority", params, grant=sidecar.grant("tickets.set_priority", params),
                                obo=qid)) == (403, "forbidden_on_behalf")
    assert refused(sidecar.call("atrium.panel.answer", {"question_id": qid, "text": "x", "status": "answered"},
                                obo=qid)) == (403, "forbidden_on_behalf")
    assert refused(sidecar.call("tickets.list", {}, obo="q_somebody_else")) == (403, "forbidden_on_behalf")
    result(sidecar.call("atrium.panel.answer", {"question_id": qid, "text": "done", "status": "answered"}))
    assert refused(sidecar.call("tickets.list", {}, obo=qid)) == (403, "forbidden_on_behalf")


def test_writes_never_act_on_behalf_of_a_tool_user_even_if_a_local_manifest_says_so():
    loose = json.loads(fake.MANIFEST_RAW)
    loose["actions"][2]["on_behalf_of"] = True  # Atrium refuses such a manifest; the bridge does not trust it either
    tool, http, sidecar, _ = make(manifest=json.dumps(loose).encode())
    qid = browser(tool, "requester").post(c.PANEL_ASK_PATH, json={"text": "raise it"}).json()["question_id"]
    result(sidecar.call("atrium.panel.pull", {}))
    params = {"ticket_id": 1, "priority": "high"}
    assert refused(sidecar.call("tickets.set_priority", params, grant=sidecar.grant("tickets.set_priority", params),
                                obo=qid)) == (403, "forbidden_on_behalf")
    assert tool.desk.calls == []


def test_a_glue_that_ignores_on_behalf_of_is_a_confused_deputy():
    """Black-box conformance cannot see this (the glue's job); the template tests can."""
    tool, http, sidecar, _ = make(broken=["ignores_on_behalf"])
    qid = browser(tool, "requester").post(c.PANEL_ASK_PATH, json={"text": "payroll?"}).json()["question_id"]
    result(sidecar.call("atrium.panel.pull", {}))
    assert [t["id"] for t in result(sidecar.call("tickets.list", {}, obo=qid))] == [3, 2, 1]


# --------------------------------------------------------------------------------------
# events
# --------------------------------------------------------------------------------------


def test_events_are_declared_bounded_acknowledged_and_carry_their_cause():
    tool, http, sidecar, clock = make()
    agent = browser(tool, "agent")
    assert agent.post("/api/tickets", json={"title": "New", "body": "b"}).status_code == 201
    params = {"ticket_id": 1, "priority": "low"}
    granted = sidecar.grant("tickets.set_priority", params)
    result(sidecar.call("tickets.set_priority", params, grant=granted))
    events = result(sidecar.call("atrium.events.pull", {"after": 0}))
    assert [(e["seq"], e["name"], e.get("cause")) for e in events["events"]] == [
        (1, "helpdesk.ticket.created", None), (2, "helpdesk.ticket.updated", {"jti": granted[1]})]
    assert events["events"][0]["payload"] == {"id": 4, "title": "New"} and events["next"] == 2
    assert result(sidecar.call("atrium.events.pull", {"after": 2})) == {"events": [], "next": 2}
    assert result(sidecar.call("atrium.events.pull", {"after": 0}))["events"] == []  # acknowledged ones are gone
    assert tool.bridge.emit("helpdesk.other", {}) is False
    assert tool.bridge.emit("helpdesk.ticket.created", {"big": "x" * (16 * 1024)}) is False
    assert tool.bridge.emit("helpdesk.ticket.created", {"bad": float("nan")}) is False
    assert tool.bridge.emit("helpdesk.ticket.created", ["not", "an", "object"]) is False
    started = time.monotonic()
    for n in range(1100):
        tool.bridge.emit("helpdesk.ticket.created", {"n": n})
    assert time.monotonic() - started < 2
    assert tool.bridge.drops == 100 and len(tool.bridge._events) == core.OUTBOX_MAX
    assert result(sidecar.call("atrium.ping"))["drops"] == 100
    pulled = result(sidecar.call("atrium.events.pull", {"after": 2}))
    assert len(pulled["events"]) == 100 and pulled["events"][0]["payload"] == {"n": 0}
    clock.now += core.OUTBOX_TTL
    assert result(sidecar.call("atrium.events.pull", {"after": pulled["next"]}))["events"] == []
    # the module-level emit (atrium_bridge.emit) goes to the latest bridge and never raises
    assert adapters.emit is core.emit
    assert core.emit("helpdesk.ticket.created", object()) is False  # type: ignore[arg-type]


def test_long_polls_never_hold_up_the_tool():
    clock = Clock()
    tool = fake.helpdesk_app(keys=KEYS, clock=clock)
    sidecar = Sidecar(None, clock)

    async def scenario() -> tuple[float, int, float, dict[str, Any]]:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=tool.app), base_url="http://helpdesk.test") as h:
            assert (await h.post("/login", json={"username": "agent"})).status_code == 200
            body = c.body_bytes({"after": 0, "wait": 5})
            started = time.monotonic()
            poll = asyncio.create_task(h.post(c.call_path("atrium.events.pull"), content=body,
                                              headers=sidecar.headers("atrium.events.pull", body)))
            await asyncio.sleep(0.3)
            quick = time.monotonic()
            for _ in range(5):
                assert (await h.get("/api/tickets")).status_code == 200
            tool_time = time.monotonic() - quick
            created = await h.post("/api/tickets", json={"title": "wake up", "body": "now"})
            answer = await poll
            return tool_time, created.status_code, time.monotonic() - started, answer.json()
    tool_time, created, waited, answer = asyncio.run(scenario())
    assert created == 201 and tool_time < 1.0
    assert waited < 3 and [e["name"] for e in answer["result"]["events"]] == ["helpdesk.ticket.created"]


# --------------------------------------------------------------------------------------
# the widget file and the adapters
# --------------------------------------------------------------------------------------


@pytest.mark.parametrize("adapter", ["fastapi", "starlette", "mount", "middleware"])
def test_panel_js_is_served_byte_identical_by_every_adapter(adapter):
    tool, http, sidecar, _ = make(adapter)
    answer = http.get(c.PANEL_JS_PATH)
    assert answer.status_code == 200 and answer.content == templates.panel_js()
    assert answer.headers["etag"] == f'"{templates.panel_sha256()}"'
    assert answer.headers["content-type"].startswith("application/javascript")
    assert answer.headers["x-content-type-options"] == "nosniff"
    assert http.get(c.PANEL_JS_PATH, headers={"If-None-Match": answer.headers["etag"]}).status_code == 304
    assert result(sidecar.call("atrium.ping"))["manifest_sha256"] == c.manifest_sha256(fake.MANIFEST_RAW)
    assert result(sidecar.call("atrium.describe")) == json.loads(fake.MANIFEST_RAW)
    assert http.get("/").status_code == 200


def test_the_wsgi_adapter_serves_the_same_bridge_without_holding_workers():
    clock = Clock()
    tool = fake.helpdesk_wsgi(keys=KEYS, clock=clock)
    http = httpx.Client(transport=httpx.WSGITransport(app=tool.app), base_url="http://helpdesk.test")
    sidecar = Sidecar(http, clock)
    assert http.get(c.HEALTH_PATH).json() == {"status": "ok"}
    assert http.get(c.PANEL_JS_PATH).content == templates.panel_js()
    assert http.get("/").text.startswith("<!doctype html>")
    assert http.post("/login", json={"username": "requester"}).status_code == 200
    http.headers["X-Atrium-Panel"] = "1"
    qid = http.post(c.PANEL_ASK_PATH, json={"text": "hi from WSGI"}).json()["question_id"]
    started = time.monotonic()
    assert result(sidecar.call("atrium.events.pull", {"wait": 25})) == {"events": [], "next": 0}
    assert time.monotonic() - started < 2  # sync_wait 0: a WSGI worker is never parked on a long-poll
    assert result(sidecar.call("atrium.panel.pull", {}))[0]["id"] == qid
    assert [t["id"] for t in result(sidecar.call("tickets.list", {}, obo=qid))] == [1]
    params = {"ticket_id": 1, "priority": "high"}
    assert sidecar.call("tickets.set_priority", params, grant=sidecar.grant("tickets.set_priority", params)).json()[
        "receipt"]["status"] == "executed"
    big = b'{"params":{"q":"' + b"x" * (70 * 1024) + b'"}}'
    assert refused(sidecar.call("tickets.list", body=big)) == (413, "too_large")
    assert http.get("/api/tickets").status_code == 200


def test_bridge_paths_under_a_prefix():
    assert adapters.bridge_path("/app/.atrium/v1/health") == "/.atrium/v1/health"
    assert adapters.bridge_path("/v1/health", "/.atrium") == "/.atrium/v1/health"
    assert adapters.bridge_path("/tickets") is None


def test_the_flask_blueprint():
    flask = pytest.importorskip("flask")
    clock = Clock()
    desk = fake.Helpdesk()
    bridge, glue = fake.make_bridge(desk, keys=KEYS, clock=clock)
    app = flask.Flask("helpdesk")
    app.register_blueprint(adapters.flask_blueprint(bridge))
    http = httpx.Client(transport=httpx.WSGITransport(app=app), base_url="http://helpdesk.test")
    assert http.get(c.HEALTH_PATH).json() == {"status": "ok"}
    assert result(Sidecar(http, clock).call("atrium.ping"))["tool"] == fake.TOOL


def load_skeleton():
    spec = importlib.util.spec_from_file_location("glue_skeleton", templates.ROOT / "python" / "glue_skeleton.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_glue_skeleton_gives_a_working_bridge_with_the_built_ins_only(monkeypatch):
    glue = load_skeleton()
    assert glue.actions == {} and glue.service_principal() == "atrium-team"
    anonymous = SimpleNamespace(user=SimpleNamespace(is_authenticated=False))
    signed_in = SimpleNamespace(user=SimpleNamespace(is_authenticated=True, id=7, username="rita", roles=["staff"]))
    assert glue.current_user(anonymous) is None
    assert glue.current_user(SimpleNamespace()) is None  # no session middleware at all
    assert glue.current_user(signed_in) == {"id": "7", "display": "rita", "roles": ["staff"]}
    manifest = json.dumps({**fake.MANIFEST, "actions": []}).encode()
    glue.MANIFEST, glue.PANEL_JS = manifest, templates.panel_js()
    monkeypatch.setenv("ATRIUM_BRIDGE_KEYS", KEYS)
    monkeypatch.setenv("ATRIUM_TOOL_ID", fake.TOOL)
    monkeypatch.setenv("ATRIUM_SUBSIDIARY_ID", fake.SUB)
    bridge = adapters.bridge_for(glue)
    assert adapters.bridge_for(glue) is bridge and bridge.ready and bridge.panel_on
    http = TestClient(adapters.asgi_middleware(lambda scope, receive, send: None, glue), base_url="http://t.test")
    sidecar = Sidecar(http, Clock(time.time()))
    assert result(sidecar.call("atrium.ping"))["contract"] == c.CONTRACT
    assert refused(sidecar.call("tickets.list")) == (403, "action_not_allowed")


# --------------------------------------------------------------------------------------
# the sidecar bundle templates
# --------------------------------------------------------------------------------------


def test_the_sidecar_bundle_holds_no_secret_and_is_hardened():
    files = templates.sidecar_bundle(atrium_url="https://atrium.example.com", subsidiary_id=fake.SUB,
                                     tool_id=fake.TOOL, mode="bridge", bridge_url="http://helpdesk:8000",
                                     image="registry.example.com/atrium-sidecar@sha256:" + "a" * 64)
    assert set(files) == {"config.json", "docker-compose.yml", "atrium-sidecar.service", "README.md"}
    config = json.loads(files["config.json"])
    assert config == {"atrium_url": "https://atrium.example.com", "subsidiary_id": fake.SUB, "tool_id": fake.TOOL,
                      "mode": "bridge", "bridge_url": "http://helpdesk:8000", "state_dir": "/var/lib/atrium-sidecar"}
    compose = files["docker-compose.yml"].decode()
    for line in ('user: "10001"', "read_only: true", "cap_drop: [ALL]", '"no-new-privileges:true"', "mem_limit: 512m",
                 "cpus: 1.0", "name: helpdesk_default", "external: true", "@sha256:" + "a" * 64):
        assert line in compose, line
    assert "ports:" not in compose
    unit = files["atrium-sidecar.service"].decode()
    for line in ("DynamicUser=yes", "StateDirectory=atrium-sidecar", "ProtectSystem=strict", "ProtectHome=yes",
                 "PrivateTmp=yes", "NoNewPrivileges=yes", "MemoryMax=512M", "RestartPreventExitStatus=3 4"):
        assert line in unit, line
    readme = files["README.md"].decode()
    assert "through its bridge (http://helpdesk:8000)" in readme and "never as Atrium's account" in readme
    for text in map(bytes.decode, files.values()):
        assert "{{" not in text and "token\":" not in text
    only = templates.sidecar_bundle(atrium_url="https://atrium.example.com", subsidiary_id=fake.SUB,
                                    tool_id=fake.TOOL, mode="sidecar_only", atrium_cert_sha256="b" * 64)
    assert json.loads(only["config.json"]) == {"atrium_url": "https://atrium.example.com", "subsidiary_id": fake.SUB,
                                               "tool_id": fake.TOOL, "mode": "sidecar_only",
                                               "atrium_cert_sha256": "b" * 64, "state_dir": "/var/lib/atrium-sidecar"}
    assert b"dedicated read-only credential" in only["README.md"]


@pytest.mark.parametrize("change", [{"atrium_url": "https://a.example.com\nimage: evil"}, {"mode": "root"},
                                    {"image": "evil\n    privileged: true"}, {"network": "x y"},
                                    {"bridge_url": "javascript:alert(1)"}, {"atrium_cert_sha256": "XYZ"},
                                    {"memory": "lots"}, {"subsidiary_id": "sub_x"}, {"executable": "$(rm -rf /)"}])
def test_the_sidecar_bundle_refuses_values_that_could_break_out(change):
    values = {"atrium_url": "https://atrium.example.com", "subsidiary_id": fake.SUB, "tool_id": fake.TOOL,
              "mode": "bridge", **change}
    with pytest.raises(ValueError):
        templates.sidecar_bundle(**values)


# --------------------------------------------------------------------------------------
# a real browser (optional): the widget in the fake Helpdesk, answers rendered as text
# --------------------------------------------------------------------------------------


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_the_widget_in_a_real_browser_renders_answers_as_text():
    sync_api = pytest.importorskip("playwright.sync_api")
    import uvicorn
    from test_ui_browser import launch

    clock = time.time
    tool = fake.helpdesk_app(keys=KEYS, clock=clock)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(tool.app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started:
        assert time.monotonic() < deadline and thread.is_alive(), "the fake tool did not start"
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    sidecar = Sidecar(httpx.Client(base_url=base), Clock(time.time()))
    try:
        with sync_api.sync_playwright() as p:
            chromium = launch(p)
            try:
                page = chromium.new_page()
                page.set_default_timeout(10_000)
                page.goto(base + "/")
                assert page.locator("[data-atrium-team]").count() == 0  # signed out: no button
                page.evaluate("fetch('/login', {method: 'POST', headers: {'Content-Type': 'application/json'},"
                              " body: JSON.stringify({username: 'requester'})})")
                page.reload()
                page.get_by_role("button", name="Ask the team").click()
                page.locator("textarea").fill("Is <b>ticket 1</b> fixed?")
                page.get_by_role("button", name="Ask", exact=True).click()
                page.locator("p.status", has_text="Waiting for the team").wait_for()
                sidecar.clock.now = time.time()
                [question] = result(sidecar.call("atrium.panel.pull", {}))
                assert question["page"] == {"path": "/", "record_id": "ticket:1"}
                html = "<img src=x onerror=\"document.title='pwned'\"><b>Not yet</b>"
                result(sidecar.call("atrium.panel.answer", {"question_id": question["id"], "text": html,
                                                           "status": "answered", "by": "desk"}))
                page.evaluate("window.AtriumTeam.refresh()")
                answer = page.locator("p.answer")
                answer.wait_for()
                assert answer.inner_text() == html
                assert page.locator("[data-atrium-team] img, [data-atrium-team] b").count() == 0
                assert page.title() == "Helpdesk"
                page.locator("textarea").focus()
                page.keyboard.press("Escape")
                assert page.evaluate("document.activeElement.shadowRoot.activeElement.className") == "button"
                assert page.locator("section[role=dialog]").is_hidden()
            finally:
                chromium.close()
    finally:
        server.should_exit = True
        thread.join(15)
