"""Single sign-on: the OpenID Connect flow and ID-token checks against a fake identity provider.

FakeIdP is an httpx.MockTransport serving discovery, the key set (real RSA and EC keys made with cryptography) and
the token endpoint; it signs the ID tokens itself. Every network call of OidcClient goes through its `transport`
argument, so the tests hand it the fake one: unit tests build an OidcClient directly, and the end-to-end tests
replace `hub.auth.oidc` on a running hub (whose settings configure SSO) with an OidcClient on that transport, the
same seam test_auth.py uses for its FakeOidc. Nothing is monkeypatched inside the protocol code itself.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from conftest import ADMIN_PASSWORD, make_settings, new_browser
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient

from hub.app import create_app
from hub.auth import oidc as oidc_module
from hub.auth.oidc import OidcClient, OidcError, OidcIdentity
from hub.auth.service import STATE_COOKIE
from hub.config import Settings

ISSUER = "https://idp.example.com/realms/hub"
CLIENT_ID = "atrium"
CLIENT_SECRET = "idp-client-secret-value"
CALLBACK = "http://127.0.0.1:8710/api/auth/oidc/callback"
SUBJECT = "f3a1-0042"
HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}
KEYS: dict[str, Any] = {
    "rsa": rsa.generate_private_key(65537, 2048),
    "ec": ec.generate_private_key(ec.SECP256R1()),
    "ec384": ec.generate_private_key(ec.SECP384R1()),
    "rogue": rsa.generate_private_key(65537, 2048),  # never published by the provider
}
RSA_PUBLIC_PEM = KEYS["rsa"].public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def to_bytes(value: int, size: int | None = None) -> bytes:
    return value.to_bytes(size or (value.bit_length() + 7) // 8, "big")


def jwk(kid: str, key: Any) -> dict[str, Any]:
    numbers = key.public_key().public_numbers()
    if isinstance(key, rsa.RSAPrivateKey):
        return {"kty": "RSA", "kid": kid, "use": "sig", "n": b64(to_bytes(numbers.n)), "e": b64(to_bytes(numbers.e))}
    size = (key.curve.key_size + 7) // 8
    return {"kty": "EC", "kid": kid, "use": "sig", "crv": f"P-{key.curve.key_size}",
            "x": b64(to_bytes(numbers.x, size)), "y": b64(to_bytes(numbers.y, size))}


def sign(claims: dict[str, Any], key: Any, alg: str = "RS256", kid: str | None = "rsa",
         header: dict[str, Any] | None = None) -> str:
    head = {"alg": alg, "typ": "JWT", **({"kid": kid} if kid else {}), **(header or {})}
    signing_input = f"{b64(json.dumps(head).encode())}.{b64(json.dumps(claims).encode())}"
    data = signing_input.encode()
    if alg == "none":
        signature = b""
    elif alg.startswith("HS"):
        signature = hmac.new(key, data, hashlib.sha256).digest()
    else:
        digest = HASHES[alg[2:]]()
        if alg.startswith("RS"):
            signature = key.sign(data, padding.PKCS1v15(), digest)
        elif alg.startswith("PS"):
            signature = key.sign(data, padding.PSS(padding.MGF1(digest), padding.PSS.DIGEST_LENGTH), digest)
        else:
            r, s = decode_dss_signature(key.sign(data, ec.ECDSA(digest)))
            size = (key.curve.key_size + 7) // 8
            signature = to_bytes(r, size) + to_bytes(s, size)
    return f"{signing_input}.{b64(signature)}"


class FakeIdP:
    """Discovery, key set and token endpoint of an identity provider, as an httpx transport."""

    def __init__(self, issuer: str = ISSUER, client_secret: str | None = CLIENT_SECRET):
        self.issuer, self.client_secret = issuer, client_secret
        self.published = ["rsa", "ec", "ec384"]
        self.discovery: dict[str, Any] = {
            "issuer": issuer, "authorization_endpoint": f"{issuer}/protocol/openid-connect/auth",
            "token_endpoint": f"{issuer}/protocol/openid-connect/token", "jwks_uri": f"{issuer}/protocol/openid-connect/certs",
        }
        self.grants: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []
        self.token_requests: list[httpx.Request] = []
        self.transport = httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url.copy_with(query=None))
        if request.method == "GET" and url == f"{self.issuer}/.well-known/openid-configuration":
            self.calls.append("discovery")
            return httpx.Response(200, json=self.discovery)
        if request.method == "GET" and url == self.discovery["jwks_uri"]:
            self.calls.append("jwks")
            return httpx.Response(200, json={"keys": [jwk(kid, KEYS[kid]) for kid in self.published]})
        if request.method == "POST" and url == self.discovery["token_endpoint"]:
            self.calls.append("token")
            self.token_requests.append(request)
            return self.token(request)
        return httpx.Response(404, json={"error": "not_found"})

    def authorize(self, url: str, *, claims: dict[str, Any] | None = None, alg: str = "RS256", kid: str | None = "rsa",
                  key: Any = None, header: dict[str, Any] | None = None,
                  tamper: Callable[[str], str] | None = None) -> str:
        """What the provider does once the person has signed in there: take the authorization request and issue a
        code. `claims` override the ID token's claims (None removes one); the rest shape how it is signed."""
        assert url.startswith(self.discovery["authorization_endpoint"] + "?")
        query = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        now = time.time()
        base = {"iss": self.issuer, "sub": SUBJECT, "aud": CLIENT_ID, "azp": CLIENT_ID, "exp": now + 300, "iat": now,
                "nonce": query["nonce"], "preferred_username": "ada", "email": "ada@example.com", "name": "Ada Lovelace",
                "groups": ["atrium-operators"]}
        code = secrets.token_urlsafe(16)
        self.grants[code] = {"query": query, "claims": {k: v for k, v in {**base, **(claims or {})}.items() if v is not None},
                             "alg": alg, "kid": kid, "key": key if key is not None else KEYS.get(kid or "rsa"),
                             "header": header, "tamper": tamper}
        return code

    def token(self, request: httpx.Request) -> httpx.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if self.client_secret:
            basic = "Basic " + base64.b64encode(f"{CLIENT_ID}:{self.client_secret}".encode()).decode()
            if request.headers.get("authorization") != basic:
                return httpx.Response(401, json={"error": "invalid_client"})
        elif "authorization" in request.headers or form.get("client_id") != CLIENT_ID:
            return httpx.Response(401, json={"error": "invalid_client"})
        grant = self.grants.pop(form.get("code", ""), None)
        if grant is None or form.get("grant_type") != "authorization_code" \
                or form.get("redirect_uri") != grant["query"]["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": f"bad code {form.get('code')}"})
        if b64(hashlib.sha256(form.get("code_verifier", "").encode()).digest()) != grant["query"]["code_challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": "PKCE verification failed"})
        token = sign(grant["claims"], grant["key"], grant["alg"], grant["kid"], grant["header"])
        if grant["tamper"]:
            token = grant["tamper"](token)
        return httpx.Response(200, json={"access_token": "opaque-access-token", "token_type": "Bearer", "id_token": token})


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


def client_for(idp: FakeIdP, **overrides) -> OidcClient:
    fields: dict[str, Any] = {"oidc_issuer": idp.issuer, "oidc_client_id": CLIENT_ID, "oidc_client_secret": idp.client_secret}
    return OidcClient(Settings(**{**fields, **overrides}), transport=idp.transport)


def sign_in(oidc: OidcClient, idp: FakeIdP, **grant) -> OidcIdentity:
    url, state = asyncio.run(oidc.begin())
    return asyncio.run(oidc.complete(idp.authorize(url, **grant), state, state))


def query(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


# -- the protocol ------------------------------------------------------------------------------


def test_authorization_request_uses_pkce_and_a_fresh_state(idp):
    oidc = client_for(idp)
    url, state = asyncio.run(oidc.begin())
    q = query(url)
    assert url.startswith(idp.discovery["authorization_endpoint"] + "?") and "scope=openid%20profile%20email" in url
    assert (q["response_type"], q["client_id"], q["redirect_uri"], q["scope"]) == ("code", CLIENT_ID, CALLBACK, "openid profile email")
    assert q["state"] == state and len(state) >= 43 and len(q["nonce"]) >= 43 and q["nonce"] != state
    assert q["code_challenge_method"] == "S256" and len(q["code_challenge"]) == 43
    other_url, other_state = asyncio.run(oidc.begin())
    assert other_state != state and query(other_url)["nonce"] != q["nonce"]
    assert idp.calls == ["discovery"]  # the discovery document is cached


def test_authorization_endpoint_with_its_own_query_and_scopes_without_openid(idp):
    idp.discovery["authorization_endpoint"] += "?p=signin"
    url, _ = asyncio.run(client_for(idp, oidc_scopes="profile email").begin())
    assert url.startswith(f"{ISSUER}/protocol/openid-connect/auth?p=signin&")
    assert query(url)["scope"] == "openid profile email"


@pytest.mark.parametrize("alg, kid", [("RS256", "rsa"), ("RS384", "rsa"), ("RS512", "rsa"), ("PS256", "rsa"),
                                      ("ES256", "ec"), ("ES384", "ec384")])
def test_sign_in_with_each_accepted_algorithm(idp, alg, kid):
    identity = sign_in(client_for(idp), idp, alg=alg, kid=kid)
    assert (identity.issuer, identity.subject, identity.username) == (ISSUER, SUBJECT, "ada")
    assert (identity.email, identity.name, identity.role) == ("ada@example.com", "Ada Lovelace", "operator")
    assert identity.claims["groups"] == ["atrium-operators"]
    token_request = idp.token_requests[0]
    form = query("?" + token_request.content.decode())
    assert form["grant_type"] == "authorization_code" and form["redirect_uri"] == CALLBACK and "client_id" not in form
    assert token_request.headers["authorization"].startswith("Basic ")  # client_secret_basic


def test_public_client_sends_pkce_without_a_secret():
    idp = FakeIdP(client_secret=None)
    assert sign_in(client_for(idp), idp).username == "ada"
    form = query("?" + idp.token_requests[0].content.decode())
    assert form["client_id"] == CLIENT_ID and "code_verifier" in form and "authorization" not in idp.token_requests[0].headers


def test_issuer_trailing_slash_and_azp_with_several_audiences(idp):
    oidc = client_for(idp, oidc_issuer=ISSUER + "/")  # configured with a slash, discovery says without
    assert sign_in(oidc, idp, claims={"aud": [CLIENT_ID, "account"], "azp": CLIENT_ID}).subject == SUBJECT
    slashed = FakeIdP()
    slashed.discovery["issuer"] = ISSUER + "/"  # the provider's own spelling is what tokens must carry
    assert sign_in(client_for(slashed), slashed, claims={"iss": ISSUER + "/"}).issuer == ISSUER + "/"
    assert sign_in(client_for(idp), idp, claims={"exp": time.time() - 30}).subject == SUBJECT  # within the clock skew


def tamper_signature(token: str) -> str:
    head, body, sig = token.split(".")
    raw = bytearray(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)))
    raw[len(raw) // 2] ^= 0x01
    return f"{head}.{body}.{b64(bytes(raw))}"


def tamper_claims(token: str) -> str:
    head, body, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    return f"{head}.{b64(json.dumps({**claims, 'groups': ['atrium-admins']}).encode())}.{sig}"


REJECTED: dict[str, tuple[dict[str, Any], str]] = {
    "wrong nonce": ({"claims": {"nonce": "another-sign-in"}}, "does not belong to this sign-in"),
    "no nonce": ({"claims": {"nonce": None}}, "does not belong to this sign-in"),
    "wrong issuer": ({"claims": {"iss": "https://evil.example.com"}}, "different identity provider"),
    "wrong audience": ({"claims": {"aud": "another-app", "azp": None}}, "different application"),
    "several audiences without azp": ({"claims": {"aud": [CLIENT_ID, "another-app"], "azp": None}}, "different application"),
    "azp of another client": ({"claims": {"aud": [CLIENT_ID, "another-app"], "azp": "another-app"}}, "different application"),
    "expired token": ({"claims": {"exp": time.time() - 120}}, "has expired"),
    "issued in the future": ({"claims": {"iat": time.time() + 3600}}, "not valid yet"),
    "no expiry": ({"claims": {"exp": None}}, "no valid lifetime"),
    "no subject": ({"claims": {"sub": None}}, "does not identify the person"),
    "alg none": ({"alg": "none"}, r"does not accept \(none\)"),
    "HS256 keyed with the client secret": ({"alg": "HS256", "key": CLIENT_SECRET.encode()}, r"does not accept \(HS256\)"),
    "HS256 keyed with the public key": ({"alg": "HS256", "key": RSA_PUBLIC_PEM}, r"does not accept \(HS256\)"),
    "unsupported alg": ({"alg": "ES512", "kid": "ec"}, r"does not accept \(ES512\)"),
    "tampered signature": ({"tamper": tamper_signature}, "signature is not valid"),
    "tampered claims": ({"tamper": tamper_claims}, "signature is not valid"),
    "signed by another key under a published kid": ({"key": KEYS["rogue"]}, "signature is not valid"),
    "kid of a key of another type": ({"kid": "ec", "key": KEYS["rsa"]}, "does not publish"),
    "unknown kid": ({"kid": "rogue"}, "does not publish"),
    "critical header extension": ({"header": {"crit": ["exp"], "exp": 1}}, "extensions"),
    "not a JWT": ({"tamper": lambda token: token + ".extra"}, "malformed"),
}


@pytest.mark.parametrize("grant, message", REJECTED.values(), ids=REJECTED.keys())
def test_bad_id_tokens_are_rejected(idp, grant, message):
    with pytest.raises(OidcError, match=message):
        sign_in(client_for(idp), idp, **grant)


def test_unknown_kid_refetches_the_key_set_once(idp):
    oidc = client_for(idp)
    sign_in(oidc, idp)
    sign_in(oidc, idp, alg="ES256", kid="ec")
    assert idp.calls.count("jwks") == 1  # cached
    with pytest.raises(OidcError, match="does not publish"):
        sign_in(oidc, idp, kid="rogue")
    assert idp.calls.count("jwks") == 2  # refetched once, then refused
    idp.published.append("rogue")  # key rotation at the provider: picked up without a restart
    assert sign_in(oidc, idp, kid="rogue").subject == SUBJECT
    assert idp.calls.count("jwks") == 3 and idp.calls.count("discovery") == 1


def test_state_must_match_the_cookie_and_is_single_use(idp):
    oidc = client_for(idp)
    url, state = asyncio.run(oidc.begin())
    code = idp.authorize(url)
    for cookie in (None, "", "another-browser-state"):
        with pytest.raises(OidcError, match="not started in this browser"):
            asyncio.run(oidc.complete(code, state, cookie))
    assert asyncio.run(oidc.complete(code, state, state)).subject == SUBJECT  # failed checks did not consume it
    with pytest.raises(OidcError, match="expired or was already used"):
        asyncio.run(oidc.complete(idp.authorize(url), state, state))
    with pytest.raises(OidcError, match="expired or was already used"):
        asyncio.run(oidc.complete("code", "never-issued", "never-issued"))
    assert idp.calls.count("token") == 1  # refused states never reach the token endpoint


def test_state_expires(idp, monkeypatch):
    monkeypatch.setattr(oidc_module, "PENDING_TTL", -1)
    oidc = client_for(idp)
    url, state = asyncio.run(oidc.begin())
    with pytest.raises(OidcError, match="expired or was already used"):
        asyncio.run(oidc.complete(idp.authorize(url), state, state))


def test_pending_sign_ins_are_bounded(idp, monkeypatch):
    """The client keeps nothing per started sign-in, so a flood of anonymous starts cannot push a person's sign-in
    out (review F30); it remembers only finished ones - at most MAX_PENDING - so each state is used once."""
    monkeypatch.setattr(oidc_module, "MAX_PENDING", 3)
    oidc = client_for(idp)
    started = [asyncio.run(oidc.begin()) for _ in range(50)]
    assert len(oidc._used) == 0
    first_url, first_state = started[0]
    assert asyncio.run(oidc.complete(idp.authorize(first_url), first_state, first_state)).subject == SUBJECT
    for url, state in started[1:6]:
        assert asyncio.run(oidc.complete(idp.authorize(url), state, state)).subject == SUBJECT
    assert len(oidc._used) == 3  # bounded
    last_url, last_state = started[5]
    with pytest.raises(OidcError, match="expired or was already used"):
        asyncio.run(oidc.complete(idp.authorize(last_url), last_state, last_state))


@pytest.mark.parametrize("issuer, allow_http, allowed", [
    ("http://idp.example.com/realms/hub", False, False),
    ("http://idp.example.com/realms/hub", True, True),
    ("http://localhost:8080/realms/hub", False, True),
    ("http://127.0.0.1:8080/realms/hub", False, True),
])
def test_plain_http_issuers_only_on_localhost(issuer, allow_http, allowed):
    idp = FakeIdP(issuer=issuer)
    oidc = client_for(idp, oidc_allow_http=allow_http)
    if allowed:
        assert sign_in(oidc, idp).issuer == issuer
    else:
        with pytest.raises(OidcError, match="plain http"):
            asyncio.run(oidc.begin())
        assert idp.calls == []  # refused before any request


def test_discovery_is_checked(idp):
    idp.discovery["issuer"] = "https://evil.example.com"
    with pytest.raises(OidcError, match="different issuer"):
        asyncio.run(client_for(idp).begin())
    downgraded = FakeIdP()
    downgraded.discovery["token_endpoint"] = "http://idp.example.com/token"
    with pytest.raises(OidcError, match="token endpoint uses plain http"):
        asyncio.run(client_for(downgraded).begin())
    missing = FakeIdP()
    del missing.discovery["jwks_uri"]
    with pytest.raises(OidcError, match="jwks uri is not a valid"):
        asyncio.run(client_for(missing).begin())


def test_provider_errors_are_safe_to_show(idp):
    oidc = client_for(idp)
    url, state = asyncio.run(oidc.begin())
    with pytest.raises(OidcError) as caught:
        asyncio.run(oidc.complete("forged-code-123", state, state))
    assert str(caught.value) == "The identity provider refused the token request: HTTP 400 (invalid_grant)."

    wrong_secret = client_for(idp, oidc_client_secret="not-the-secret")
    url, state = asyncio.run(wrong_secret.begin())
    with pytest.raises(OidcError) as caught:
        asyncio.run(wrong_secret.complete(idp.authorize(url), state, state))
    assert "invalid_client" in str(caught.value) and "not-the-secret" not in str(caught.value)

    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)
    offline = OidcClient(client_for(idp).settings, transport=httpx.MockTransport(down))
    with pytest.raises(OidcError, match=r"Could not reach the identity provider \(discovery request\)"):
        asyncio.run(offline.begin())


def test_no_id_token_in_the_token_response(idp):
    oidc = client_for(idp)
    url, state = asyncio.run(oidc.begin())
    idp.token = lambda request: httpx.Response(200, json={"access_token": "x", "token_type": "Bearer"})  # type: ignore[method-assign]
    with pytest.raises(OidcError, match="did not return an ID token"):
        asyncio.run(oidc.complete("code", state, state))


@pytest.mark.parametrize("claims, username", [
    ({"preferred_username": "Ada.Lovelace"}, "ada.lovelace"),
    ({"preferred_username": "José Pérez"}, "jose-perez"),
    ({"preferred_username": "ada@example.com"}, "ada-example.com"),
    ({"preferred_username": None, "email": "Grace.Hopper@example.com"}, "grace.hopper"),
    ({"preferred_username": "李", "email": None}, SUBJECT),
    ({"preferred_username": "_x", "email": None, "sub": "!"}, "x-user"),
])
def test_username_from_the_identity(idp, claims, username):
    assert sign_in(client_for(idp), idp, claims=claims).username == username


def test_display_name_and_email_from_the_identity(idp):
    identity = sign_in(client_for(idp), idp, claims={"name": None, "given_name": "Grace", "family_name": "Hopper",
                                                     "email": "not an email"})
    assert (identity.name, identity.email) == ("Grace Hopper", None)


def test_an_email_the_provider_marks_unverified_is_not_taken(idp):
    """email_verified false (or "false"): no email. A provider that sends no email_verified at all (Entra ID work
    accounts) manages the address itself, so it is taken."""
    for flag in (False, "false"):
        refused = sign_in(client_for(idp), idp, claims={"email_verified": flag})
        assert refused.email is None and refused.username == "ada"
    assert sign_in(client_for(idp), idp, claims={"email_verified": True}).email == "ada@example.com"
    assert sign_in(client_for(idp), idp, claims={"email_verified": None}).email == "ada@example.com"


@pytest.mark.parametrize("overrides, claims, role", [
    ({}, {"groups": ["staff", "atrium-admins", "atrium-operators"]}, "admin"),
    ({}, {"groups": ["atrium-operators"]}, "operator"),
    ({}, {"groups": "atrium-operators"}, "operator"),
    ({}, {"groups": ["staff"]}, "viewer"),
    ({}, {}, "viewer"),
    ({"oidc_default_role": "operator"}, {"groups": ["staff"]}, "operator"),
    ({"oidc_role_claim": "realm_access.roles", "oidc_admin_values": ["root", "ops"]},
     {"realm_access": {"roles": ["ops"]}}, "admin"),
    ({"oidc_role_claim": "realm_access.roles"}, {"realm_access": ["atrium-admins"]}, "viewer"),
    ({"oidc_role_claim": "https://atrium.example.com/roles"}, {"https://atrium.example.com/roles": ["atrium-admins"]}, "admin"),
])
def test_role_mapping(idp, overrides, claims, role):
    assert client_for(idp, **overrides).role_for(claims) == role


# -- end to end through the hub ----------------------------------------------------------------


@pytest.fixture
def hub_client(tmp_path: Path, idp: FakeIdP):
    """A hub with SSO configured against the fake provider, and the administrator "admin" signed in."""
    settings = make_settings(tmp_path, oidc_issuer=ISSUER, oidc_client_id=CLIENT_ID, oidc_client_secret=CLIENT_SECRET,
                             oidc_label="Sign in with Keycloak")
    with TestClient(create_app(settings), headers={"X-Hub-Request": "1"}) as c:
        hub = c.app.state.hub
        hub.auth.oidc = OidcClient(hub.settings, transport=idp.transport)
        hub.auth.create_user("admin", ADMIN_PASSWORD, role="admin", actor="test")
        assert c.post("/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}).status_code == 200
        yield c


def start(browser: TestClient) -> tuple[str, str]:
    """GET /api/auth/oidc/login -> (authorization URL, state)."""
    response = browser.get("/api/auth/oidc/login", follow_redirects=False)
    assert response.status_code == 302, response.text
    return response.headers["location"], query(response.headers["location"])["state"]


def callback(browser: TestClient, code: str, state: str) -> httpx.Response:
    return browser.get("/api/auth/oidc/callback", params={"code": code, "state": state}, follow_redirects=False)


def sso(browser: TestClient, idp: FakeIdP, **grant) -> httpx.Response:
    url, state = start(browser)
    return callback(browser, idp.authorize(url, **grant), state)


def login_error(response: httpx.Response, browser: TestClient) -> str:
    """Why a sign-in failed, as the sign-in screen shows it: the redirect carries no text (review F32), the browser's
    next GET /api/auth/me does, once."""
    location = response.headers["location"]
    assert response.status_code == 302 and location == "/#/login", location
    message = browser.get("/api/auth/me").json()["sso_error"]
    assert message and browser.get("/api/auth/me").json()["sso_error"] is None
    return message


def test_sso_end_to_end(hub_client, idp):
    hub = hub_client.app.state.hub
    anon = new_browser(hub_client)
    assert anon.get("/api/auth/me").json()["oidc"] == {"enabled": True, "label": "Sign in with Keycloak"}

    begun = anon.get("/api/auth/oidc/login", follow_redirects=False)
    assert begun.status_code == 302
    url = begun.headers["location"]
    q = query(url)
    assert url.startswith(f"{ISSUER}/protocol/openid-connect/auth?") and q["redirect_uri"] == CALLBACK
    assert (q["response_type"], q["client_id"], q["code_challenge_method"]) == ("code", CLIENT_ID, "S256")
    assert q["code_challenge"] and q["nonce"]
    state_cookie = begun.headers["set-cookie"]
    assert state_cookie.startswith(f"atrium_oidc_state={q['state']};")
    for flag in ("httponly", "max-age=600", "path=/api/auth/oidc", "samesite=lax"):
        assert flag in state_cookie.lower()

    done = callback(anon, idp.authorize(url, claims={"groups": ["atrium-operators"]}), q["state"])
    assert done.status_code == 302 and done.headers["location"] == "/#/"
    cookies = done.headers.get_list("set-cookie")
    assert any(c.startswith("atrium_session=") and "httponly" in c.lower() for c in cookies)
    assert any(c.startswith("atrium_oidc_state=") and "max-age=0" in c.lower() for c in cookies)
    me = anon.get("/api/auth/me").json()
    user = me["user"]
    assert me["authenticated"] and (user["username"], user["role"], user["auth_source"]) == ("ada", "operator", "oidc")
    assert (user["has_password"], user["email"], user["display_name"]) == (False, "ada@example.com", "Ada Lovelace")
    assert user["oidc_subject"] == f"{ISSUER}|{SUBJECT}" and user["last_login"]
    assert anon.get("/api/tools").status_code == 200
    assert anon.get("/api/users").status_code == 403  # operators are not admins
    signed_in = [e for e in hub.store.tail("activity", 200) if e["actor"] == "ada" and e["text"] == "Signed in"]
    assert signed_in and signed_in[-1]["data"]["method"] == "sso"

    again = new_browser(hub_client)  # the provider is authoritative for the role: re-synced at every sign-in
    assert sso(again, idp, claims={"groups": ["atrium-admins"]}).headers["location"] == "/#/"
    synced = again.get("/api/auth/me").json()["user"]
    assert (synced["id"], synced["username"], synced["role"]) == (user["id"], "ada", "admin")
    assert again.get("/api/users").status_code == 200
    assert sso(new_browser(hub_client), idp, claims={"groups": []}).headers["location"] == "/#/"
    assert again.get("/api/auth/me").json()["user"]["role"] == "viewer"
    assert len(hub.auth.users()) == 2

    assert hub_client.patch(f"/api/users/{user['id']}", json={"disabled": True}).status_code == 200
    refused = new_browser(hub_client)
    assert login_error(sso(refused, idp), refused) == "This account is disabled."
    assert again.get("/api/auth/me").json()["authenticated"] is False


def test_sso_callback_rejections_land_on_the_login_screen(hub_client, idp):
    hub = hub_client.app.state.hub
    anon = new_browser(hub_client)
    url, state = start(anon)
    code = idp.authorize(url)
    stranger = new_browser(hub_client)  # never started a sign-in, so it has no state cookie
    assert login_error(callback(stranger, code, state), stranger) == "This sign-in was not started in this browser. Start again."
    assert stranger.get("/api/auth/me").json()["authenticated"] is False

    url, _ = start(anon)  # a newer sign-in in the same browser replaces the state cookie
    assert login_error(callback(anon, idp.authorize(url), state), anon) == "This sign-in was not started in this browser. Start again."
    assert "different identity provider" in login_error(sso(anon, idp, claims={"iss": "https://evil.example.com"}), anon)
    assert "does not accept (none)" in login_error(sso(anon, idp, alg="none"), anon)
    assert "signature is not valid" in login_error(sso(anon, idp, tamper=tamper_claims), anon)
    assert anon.get("/api/auth/me").json()["authenticated"] is False
    assert hub.auth.users()[0].username == "admin" and len(hub.auth.users()) == 1
    failures = [e for e in hub.store.tail("activity", 200) if e["actor"] == "auth" and e["text"].startswith("Single sign-on failed")]
    assert len(failures) == 5
    assert not any(CLIENT_SECRET in e["text"] or code in e["text"] for e in failures)


def test_sso_refuses_a_plain_http_issuer(tmp_path: Path):
    idp = FakeIdP(issuer="http://idp.example.com/realms/hub")
    settings = make_settings(tmp_path, oidc_issuer=idp.issuer, oidc_client_id=CLIENT_ID)
    with TestClient(create_app(settings), headers={"X-Hub-Request": "1"}) as c:
        c.app.state.hub.auth.oidc = OidcClient(c.app.state.hub.settings, transport=idp.transport)
        response = c.get("/api/auth/oidc/login", follow_redirects=False)
        assert "plain http" in login_error(response, c) and not any(STATE_COOKIE in cookie for cookie in response.headers.get_list("set-cookie"))
        assert idp.calls == []
