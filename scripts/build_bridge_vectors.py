#!/usr/bin/env python3
"""Build hub/subsidiary/contract/vectors.json: the cross-language test vectors of the bridge contract atrium-bridge/1.

    python scripts/build_bridge_vectors.py [--check]

Everything comes from a fixed seed and a fixed clock, so the file regenerates byte for byte (Ed25519 signatures are
deterministic); --check exits 1 when the committed file differs. The vectors are signed for NOW: a core's tests run
them with their clock set to the file's "now".

The file holds:

* conformance - V1 to V20 (contract/SPEC.md "Conformance"): the bridge's environment, the manifest file and the panel
  widget to configure it with, and complete pre-signed requests with the answer each must get. Run them in order
  against ONE freshly started bridge (V8 and V15 depend on what the bridge saw before).
* units - the primitives on their own: base64url, ATRIUM_BRIDGE_KEYS, tickets, grants, signing strings, body hashes,
  params validation (with the raw body bytes, since 2.0 and 1e2 are integers) and the model-facing tool names.

Each unit case states the result the contract requires; the build fails when the Python reference disagrees.
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from hub.subsidiary import contract as c  # noqa: E402

OUT = ROOT / "hub" / "subsidiary" / "contract" / "vectors.json"
SEED = 20261014
NOW = 1791936000  # 2026-10-14T00:00:00Z
TOOL = "helpdesk"

# the manifest of 4.3 (plus an admin action), as a tool would commit it
MANIFEST = {
    "contract": c.CONTRACT,
    "tool_id": TOOL,
    "stack": "python-fastapi",
    "core": "python/1.0.0",
    "service_principal": "atrium-team",
    "panel": {"enabled": True},
    "events": {"names": ["helpdesk.ticket.created"]},
    "files": ["atrium/atrium_bridge_core.py", "atrium/glue.py", "atrium/panel.js", "atrium-bridge.json"],
    "actions": [
        {"id": "tickets.list", "title": "List tickets", "description": "Open tickets, newest first", "risk": "read",
         "category": "data", "on_behalf_of": True,
         "params": {"type": "object", "additionalProperties": False,
                    "properties": {"status": {"enum": ["open", "pending", "closed"]},
                                   "q": {"type": "string", "maxLength": 200}}}},
        {"id": "tickets.draft_reply", "title": "Draft a reply", "risk": "propose", "category": "content",
         "on_behalf_of": True,
         "params": {"type": "object", "additionalProperties": False, "required": ["ticket_id", "text"],
                    "properties": {"ticket_id": {"type": "integer"}, "text": {"type": "string", "maxLength": 4000}}}},
        {"id": "tickets.set_priority", "title": "Change a ticket's priority", "risk": "write", "category": "workflow",
         "reversible": True, "external_effect": False, "on_behalf_of": False,
         "params": {"type": "object", "additionalProperties": False, "required": ["ticket_id", "priority"],
                    "properties": {"ticket_id": {"type": "integer"}, "priority": {"enum": ["low", "normal", "high"]}}}},
        {"id": "tickets.delete", "title": "Delete a ticket", "risk": "admin", "category": "data",
         "params": {"type": "object", "additionalProperties": False, "required": ["ticket_id"],
                    "properties": {"ticket_id": {"type": "integer", "minimum": 1}}}},
    ],
}
PANEL_JS = b"/* atrium-bridge/1 conformance stand-in for panel.js: a core serves its configured widget file */\n"

SCHEMAS = {
    "query": {"type": "object", "additionalProperties": False, "required": [], "properties": {
        "status": {"enum": ["open", "pending", "closed"]},
        "q": {"type": "string", "maxLength": 5},
        "limit": {"type": "integer", "minimum": 1, "maximum": 50},
        "tags": {"type": "array", "maxItems": 2, "items": {"type": "string", "maxLength": 3}},
        "urgent": {"type": "boolean"},
        "level": {"enum": [1, 2, 3]}}},
    "ticket": {"type": "object", "additionalProperties": False, "required": ["ticket_id"],
               "properties": {"ticket_id": {"type": "integer"}}},
}
# (title, schema, raw body, normalized params or None when the body is refused with 422 bad_params)
PARAMS: list[tuple[str, str, bytes, dict[str, Any] | None]] = [
    ("no params", "query", b'{"params":{}}', {}),
    ("an enum value and a short string", "query", b'{"params":{"status":"open","q":"abc"}}',
     {"status": "open", "q": "abc"}),
    ("a value outside the enum", "query", b'{"params":{"status":"archived"}}', None),
    ("a string over maxLength", "query", b'{"params":{"q":"abcdef"}}', None),
    ("maxLength counts code points: five emoji fit", "query",
     '{"params":{"q":"\U0001F600\U0001F600\U0001F600\U0001F600\U0001F600"}}'.encode(),
     {"q": "\U0001F600" * 5}),
    ("maxLength counts code points: six emoji do not", "query", ('{"params":{"q":"' + "\U0001F600" * 6 + '"}}').encode(),
     None),
    ("an escaped string counts its characters", "query", b'{"params":{"q":"\\u00e9t\\u00e9"}}', {"q": "été"}),
    ("2.0 is an integer", "query", b'{"params":{"limit":2.0}}', {"limit": 2}),
    ("1e1 is an integer", "query", b'{"params":{"limit":1e1}}', {"limit": 10}),
    ("2.5 is not an integer", "query", b'{"params":{"limit":2.5}}', None),
    ("below minimum", "query", b'{"params":{"limit":0}}', None),
    ("above maximum", "query", b'{"params":{"limit":51}}', None),
    ("true is not an integer", "query", b'{"params":{"limit":true}}', None),
    ("a numeric string is not an integer", "query", b'{"params":{"limit":"5"}}', None),
    ("an array within maxItems", "query", b'{"params":{"tags":["a","bc"]}}', {"tags": ["a", "bc"]}),
    ("an array over maxItems", "query", b'{"params":{"tags":["a","b","c"]}}', None),
    ("an array item over its maxLength", "query", b'{"params":{"tags":["abcd"]}}', None),
    ("an array item of the wrong type", "query", b'{"params":{"tags":[1]}}', None),
    ("1 is not a boolean", "query", b'{"params":{"urgent":1}}', None),
    ("a boolean", "query", b'{"params":{"urgent":false}}', {"urgent": False}),
    ("an integer enum", "query", b'{"params":{"level":2}}', {"level": 2}),
    ("true is not in an integer enum", "query", b'{"params":{"level":true}}', None),
    ("\"2\" is not in an integer enum", "query", b'{"params":{"level":"2"}}', None),
    ("null is never a value", "query", b'{"params":{"q":null}}', None),
    ("an unknown parameter", "query", b'{"params":{"extra":1}}', None),
    ("a missing required parameter", "ticket", b'{"params":{}}', None),
    ("the largest safe integer", "ticket", b'{"params":{"ticket_id":9007199254740991}}', {"ticket_id": 2**53 - 1}),
    ("the smallest safe integer", "ticket", b'{"params":{"ticket_id":-9007199254740991}}', {"ticket_id": -(2**53 - 1)}),
    ("beyond the safe integers", "ticket", b'{"params":{"ticket_id":9007199254740992}}', None),
    ("a member besides params", "ticket", b'{"params":{"ticket_id":1},"extra":1}', None),
    ("params is not an object", "ticket", b'{"params":[1]}', None),
    ("the body is not an object", "ticket", b'[{"ticket_id":1}]', None),
    ("NaN is not JSON", "ticket", b'{"params":{"ticket_id":NaN}}', None),
    ("not JSON", "ticket", b"ticket_id=1", None),
    ("not UTF-8", "ticket", b'{"params":{"ticket_id":1,"x":"\xff"}}', None),
]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def raw_token(prefix: str, raw: bytes, key: Any) -> str:
    """A token over arbitrary payload bytes (the cases a correct signer never makes)."""
    signed = f"{prefix}.{c.b64u(raw)}"
    return f"{signed}.{c.b64u(key.sign(signed.encode('ascii')))}"


def payload_token(prefix: str, payload: dict[str, Any], key: Any) -> str:
    return raw_token(prefix, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(), key)


def swap_payload(token: str, payload: dict[str, Any]) -> str:
    """`token` with another payload and its original signature."""
    prefix, _, signature = token.split(".")
    return f"{prefix}.{c.b64u(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode())}.{signature}"


def expect(case: dict[str, Any], run: Any) -> dict[str, Any]:
    """Run the Python reference on a case and fail the build when it disagrees with the stated result."""
    try:
        got: dict[str, Any] = {"ok": True, "payload": run()}
    except c.Refused as exc:
        got = {"ok": False, "code": exc.code}
    want_ok, want_code = case["ok"], case.get("code")
    if got["ok"] != want_ok or (not want_ok and got["code"] != want_code):
        raise SystemExit(f"the reference disagrees on {case['title']!r}: {got}")
    if want_ok:
        case["payload"] = got["payload"]
    return case


def ticket_units(key: Any, nxt: Any, stranger: Any, cnf: str, sub: str, rng: random.Random) -> dict[str, Any]:
    keys = f"{c.public_b64(key)},{c.public_b64(nxt)}"
    good = {"v": 1, "typ": "ticket", "sub": sub, "tool": TOOL, "cv": 3, "mode": "active",
            "act": ["tickets.list", "atrium.ping"], "cnf": cnf, "rl": dict(c.DEFAULT_RATE), "iat": NOW, "exp": NOW + 600}

    def make(signer: Any = key, prefix: str = c.TICKET_PREFIX, **changes: Any) -> str:
        return payload_token(prefix, {**good, "jti": c.new_jti(rng), **changes}, signer)

    valid = make()
    cases = [
        {"title": "a valid ticket", "token": valid, "ok": True},
        {"title": "signed with the staged next key", "token": make(nxt), "ok": True},
        {"title": "a probation ticket", "token": make(mode="probation", act=list(c.PROBATION_BUILTINS)), "ok": True},
        {"title": "expired 30 s ago: within the leeway", "token": make(iat=NOW - 630, exp=NOW - 30), "ok": True},
        {"title": "issued 30 s in the future: within the leeway", "token": make(iat=NOW + 30, exp=NOW + 630),
         "ok": True},
        {"title": "signed with another key", "token": make(stranger), "ok": False, "code": "bad_ticket"},
        {"title": "the payload changed after signing", "ok": False, "code": "bad_ticket",
         "token": swap_payload(valid, {**good, "jti": "x", "act": ["tickets.delete"]})},
        {"title": "the AG1 prefix on a ticket", "token": make(prefix=c.GRANT_PREFIX), "ok": False, "code": "bad_ticket"},
        {"title": "typ grant under AT1", "token": make(typ="grant"), "ok": False, "code": "bad_ticket"},
        {"title": "v 2", "token": make(v=2), "ok": False, "code": "bad_ticket"},
        {"title": "v true", "token": make(v=True), "ok": False, "code": "bad_ticket"},
        {"title": "another tool", "token": make(tool="wiki"), "ok": False, "code": "bad_ticket"},
        {"title": "another subsidiary", "token": make(sub="sub_000000000000"), "ok": False, "code": "bad_ticket"},
        {"title": "expired", "token": make(iat=NOW - 700, exp=NOW - 100), "ok": False, "code": "expired"},
        {"title": "issued 2 minutes in the future", "token": make(iat=NOW + 120, exp=NOW + 720), "ok": False,
         "code": "bad_ticket"},
        {"title": "an unknown mode", "token": make(mode="admin"), "ok": False, "code": "bad_ticket"},
        {"title": "a cnf that is not a key", "token": make(cnf="not-a-key"), "ok": False, "code": "bad_ticket"},
        {"title": "a string expiry", "token": make(exp=str(NOW + 600)), "ok": False, "code": "bad_ticket"},
        {"title": "a signed payload that is not JSON", "token": raw_token(c.TICKET_PREFIX, b"not json", key),
         "ok": False, "code": "bad_ticket"},
        {"title": "a signed payload over 4 KiB", "ok": False, "code": "bad_ticket",
         "token": payload_token(c.TICKET_PREFIX, {**good, "jti": "j", "pad": "x" * 4200}, key)},
        {"title": "padding on the signature", "token": valid + "=", "ok": False, "code": "bad_ticket"},
        {"title": "four parts", "token": valid + ".x", "ok": False, "code": "bad_ticket"},
        {"title": "a JOSE header with alg none", "ok": False, "code": "bad_ticket",
         "token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." + c.b64u(json.dumps(good).encode()) + "."},
        {"title": "empty", "token": "", "ok": False, "code": "bad_ticket"},
    ]
    parsed = c.parse_keys(keys)
    for case in cases:
        expect(case, lambda case=case: c.verify_ticket(case["token"], parsed, tool=TOOL, sub=sub, now=NOW))
    return {"keys": keys, "tool": TOOL, "sub": sub, "now": NOW, "cases": cases}


def grant_units(key: Any, stranger: Any, sub: str, rng: random.Random) -> dict[str, Any]:
    body = c.body_bytes({"priority": "high", "ticket_id": 42})
    good = {"v": 1, "typ": "grant", "sub": sub, "tool": TOOL, "cv": 3, "act": "tickets.set_priority",
            "bh": c.body_hash(body), "apv": "ap_0123456789ab", "iat": NOW, "exp": NOW + c.GRANT_TTL}

    def make(signer: Any = key, prefix: str = c.GRANT_PREFIX, **changes: Any) -> str:
        return payload_token(prefix, {**good, "jti": c.new_jti(rng), **changes}, signer)

    other = c.body_bytes({"priority": "low", "ticket_id": 42})
    cases = [
        {"title": "a valid grant", "token": make(), "action": "tickets.set_priority", "body": body, "ok": True},
        {"title": "expired 30 s ago: within the leeway", "token": make(exp=NOW - 30), "action": "tickets.set_priority",
         "body": body, "ok": True},
        {"title": "another body", "token": make(), "action": "tickets.set_priority", "body": other, "ok": False,
         "code": "grant_mismatch"},
        {"title": "the same params serialized differently", "token": make(), "action": "tickets.set_priority",
         "body": b'{"params": {"priority": "high", "ticket_id": 42}}', "ok": False, "code": "grant_mismatch"},
        {"title": "another action", "token": make(), "action": "tickets.delete", "body": body, "ok": False,
         "code": "grant_mismatch"},
        {"title": "another tool", "token": make(tool="wiki"), "action": "tickets.set_priority", "body": body,
         "ok": False, "code": "grant_mismatch"},
        {"title": "another subsidiary", "token": make(sub="sub_000000000000"), "action": "tickets.set_priority",
         "body": body, "ok": False, "code": "grant_mismatch"},
        {"title": "signed with another key", "token": make(stranger), "action": "tickets.set_priority", "body": body,
         "ok": False, "code": "grant_mismatch"},
        {"title": "the AT1 prefix on a grant", "token": make(prefix=c.TICKET_PREFIX), "action": "tickets.set_priority",
         "body": body, "ok": False, "code": "grant_mismatch"},
        {"title": "typ ticket under AG1", "token": make(typ="ticket"), "action": "tickets.set_priority", "body": body,
         "ok": False, "code": "grant_mismatch"},
        {"title": "expired", "token": make(iat=NOW - 700, exp=NOW - 100), "action": "tickets.set_priority",
         "body": body, "ok": False, "code": "expired"},
    ]
    parsed = c.parse_keys(c.public_b64(key))
    for case in cases:
        expect(case, lambda case=case: c.verify_grant(case["token"], parsed, tool=TOOL, sub=sub, action=case["action"],
                                                     body=case["body"], now=NOW))
        case["body_b64"] = b64(case.pop("body"))
    return {"keys": c.public_b64(key), "tool": TOOL, "sub": sub, "now": NOW, "cases": cases}


def signing_units(probe: Any, stranger: Any, rng: random.Random) -> list[dict[str, Any]]:
    cnf = c.public_b64(probe)
    rows = [
        ("a read call", "/.atrium/v1/call/tickets.list", c.body_bytes({"status": "open"}), None, None),
        ("a granted write", "/.atrium/v1/call/tickets.set_priority",
         c.body_bytes({"priority": "high", "ticket_id": 42}), "Zm9vYmFyYmF6cXV4cXV1eA", None),
        ("a panel run's read, with a query string", "/.atrium/v1/call/tickets.list?page=2",
         c.body_bytes({"q": "café"}), None, "q_91"),
        ("an empty body", "/.atrium/v1/call/atrium.ping", b"", None, None),
    ]
    out = []
    for title, path, body, grant_jti, obo in rows:
        date, nonce, tjti = str(NOW), c.new_nonce(rng), c.new_jti(rng)
        message = c.signing_string("POST", path, date, nonce, body, tjti, grant_jti, obo)
        signature = c.sign(probe, message)
        assert c.verify_signature(cnf, signature, message)
        out.append({"title": title, "method": "POST", "path": path, "date": date, "nonce": nonce,
                    "body_b64": b64(body), "body_sha256": c.sha256_hex(body), "ticket_jti": tjti,
                    "grant_jti": grant_jti, "on_behalf_of": obo, "string": message.decode("utf-8"), "cnf": cnf,
                    "signature": signature, "valid": True})
    first = out[0]
    wrong = c.sign(stranger, first["string"].encode())
    out.append({**first, "title": "signed with a key other than cnf", "signature": wrong, "valid": False})
    changed = c.body_bytes({"status": "closed"})
    out.append({**first, "title": "the body changed after signing", "body_b64": b64(changed),
                "body_sha256": c.sha256_hex(changed), "valid": False,
                "string": c.signing_string("POST", first["path"], first["date"], first["nonce"], changed,
                                           first["ticket_jti"]).decode("utf-8")})
    for row in out[-2:]:
        assert not c.verify_signature(cnf, row["signature"], row["string"].encode())
    return out


def params_units() -> dict[str, Any]:
    cases = []
    for title, schema, body, params in PARAMS:
        try:
            got: dict[str, Any] | None = c.validate_params(SCHEMAS[schema], c.parse_body(body))
        except c.Refused as exc:
            assert exc.code == "bad_params", (title, exc.code)
            got = None
        if got != params or (got is not None and any(type(got[k]) is not type(v) for k, v in params.items())):
            raise SystemExit(f"the reference disagrees on params case {title!r}: {got}")
        cases.append({"title": title, "schema": schema, "body_b64": b64(body), "ok": params is not None,
                      **({"params": params} if params is not None else {"code": "bad_params"})})
    return {"schemas": SCHEMAS, "cases": cases}


def b64u_units() -> list[dict[str, Any]]:
    rows = [("AAEC", "000102"), ("", ""), ("_-8", "ffef"), ("AAE", "0001"), ("AAF", None), ("AAE=", None),
            ("AA+/", None), ("A", None), ("AA AA", None)]
    out = []
    for text, hexed in rows:
        try:
            got: str | None = c.b64u_decode(text).hex()
        except ValueError:
            got = None
        assert got == hexed, (text, got)
        out.append({"in": text, "ok": hexed is not None, **({"hex": hexed} if hexed is not None else {})})
    return out


def key_units(key: Any, nxt: Any) -> list[dict[str, Any]]:
    a, b = c.public_b64(key), c.public_b64(nxt)
    rows = [(a, 1), (f"{a},{b}", 2), (f" {a} , {b} ", 2), ("", None), (f"{a},{b},{a}", None), ("not-a-key", None),
            (a[:-1], None), (c.b64u(b"\x00" * 31), None)]
    out = []
    for value, count in rows:
        try:
            got: int | None = len(c.parse_keys(value))
        except ValueError:
            got = None
        assert got == count, (value, got)
        out.append({"value": value, "ok": count is not None, **({"count": count} if count else {})})
    return out


def tool_name_units() -> dict[str, Any]:
    longest = "a" + "b" * 56 + "c"
    forward = [(a, c.tool_name(a)) for a in ("tickets.list", "tickets.set_priority", "kb.articles.draft", longest)]
    assert all(len(name) <= 64 and c.action_of(name) == a for a, name in forward)
    reverse = [("act__tickets-list", "tickets.list"), ("act__atrium-ping", None), ("tickets.list", None),
               ("act__Tickets-list", None), ("act__", None), ("atrium__get_tool", None)]
    assert all(c.action_of(name) == a for name, a in reverse)
    return {"forward": [{"action": a, "name": n} for a, n in forward],
            "reverse": [{"name": n, "action": a} for n, a in reverse]}


def build(seed: int = SEED, now: int = NOW) -> dict[str, Any]:
    """The whole document; the same seed and clock give the same bytes."""
    rng = random.Random(seed)
    key, nxt, stranger, probe = (c.new_key(rng.randbytes(32)) for _ in range(4))
    sub = f"sub_{rng.randbytes(6).hex()}"
    manifest_raw = (json.dumps(MANIFEST, indent=2, ensure_ascii=False) + "\n").encode()
    manifest = c.validate_manifest(manifest_raw, tool_id=TOOL)
    manifest_sha = c.manifest_sha256(manifest_raw)
    panel_sha = c.sha256_hex(PANEL_JS)
    vectors = c.build_vectors(key, tool=TOOL, sub=sub, manifest=manifest, manifest_sha=manifest_sha,
                              panel_sha=panel_sha, now=now, rng=rng)
    return {
        "contract": c.CONTRACT,
        "generator": "scripts/build_bridge_vectors.py",
        "seed": seed,
        "now": now,
        "note": "Signed for 'now': run every case with the clock set to it. Conformance vectors run in order against "
                "one freshly started bridge configured with 'env', 'manifest_b64' (the committed atrium-bridge.json) "
                "and 'panel_js_b64' (the widget it serves). Bodies are base64 (standard alphabet, padded), except a "
                "conformance step's 'body_b64': base64url without padding, as on the wire.",
        "conformance": {
            "env": {c.ENV_KEYS: c.public_b64(key), c.ENV_TOOL: TOOL, c.ENV_SUBSIDIARY: sub, c.ENV_PANEL: "on"},
            "manifest_b64": b64(manifest_raw),
            "manifest_sha256": manifest_sha,
            "panel_js_b64": b64(PANEL_JS),
            "panel_sha256": panel_sha,
            "vectors": [v.to_json() for v in vectors],
        },
        "units": {
            "b64u": b64u_units(),
            "keys": key_units(key, nxt),
            "tickets": ticket_units(key, nxt, stranger, c.public_b64(probe), sub, rng),
            "grants": grant_units(key, stranger, sub, rng),
            "signing": signing_units(probe, stranger, rng),
            "params": params_units(),
            "tool_names": tool_name_units(),
        },
    }


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the committed file differs")
    args = parser.parse_args(argv)
    text = render(build())
    if args.check:
        same = OUT.exists() and OUT.read_text(encoding="utf-8") == text
        print("vectors.json is up to date" if same else "vectors.json differs: run scripts/build_bridge_vectors.py")
        return 0 if same else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
