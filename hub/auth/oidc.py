"""Single sign-on through an OpenID Connect identity provider: the authorization code flow with PKCE, and the
checks an ID token must pass (issuer, audience, lifetime, nonce, and its signature against the provider's keys)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import time
import unicodedata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import quote, quote_plus, urlencode, urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ..models import USERNAME_RE

if TYPE_CHECKING:
    from ..config import Settings

CACHE_TTL = 3600  # seconds the discovery document and the provider's signing keys are reused
PENDING_TTL = 600  # seconds a started sign-in stays valid
MAX_PENDING = 10_000  # started sign-ins kept in memory; the oldest give way first
CLOCK_SKEW = 60
MAX_TOKEN_SIZE = 64 * 1024
LOCAL_HOSTS = ("localhost", "127.0.0.1")
CURVES: dict[str, type[ec.EllipticCurve]] = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1}
# The only signature algorithms accepted, whatever a token or the provider claims: never "none", never HMAC.
# alg -> (key type, curve, digest)
ALGORITHMS: dict[str, tuple[str, str | None, type[hashes.HashAlgorithm]]] = {
    "RS256": ("RSA", None, hashes.SHA256), "RS384": ("RSA", None, hashes.SHA384), "RS512": ("RSA", None, hashes.SHA512),
    "PS256": ("RSA", None, hashes.SHA256), "ES256": ("EC", "P-256", hashes.SHA256), "ES384": ("EC", "P-384", hashes.SHA384),
}

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey


class OidcError(Exception):
    """Sign-in through the identity provider failed; the message is safe to show to the person."""


@dataclass
class OidcIdentity:
    issuer: str
    subject: str
    username: str
    email: str | None
    name: str | None
    role: str
    claims: dict[str, Any]


@dataclass
class _Pending:
    nonce: str
    verifier: str
    expires_at: float


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64int(value: Any) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError("missing key parameter")
    return int.from_bytes(_b64decode(value), "big")


def _safe(value: Any) -> str:
    """A provider-supplied code (error, alg) reduced to something harmless to echo."""
    return re.sub(r"[^\w.-]", "", str(value))[:60] or "?"


def _number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _public_key(jwk: dict[str, Any]) -> PublicKey:
    """The public key of a JWK; raises ValueError for anything malformed or too weak."""
    if jwk.get("kty") == "RSA":
        key = rsa.RSAPublicNumbers(_b64int(jwk.get("e")), _b64int(jwk.get("n"))).public_key()
        if key.key_size < 2048:
            raise ValueError("RSA key too small")
        return key
    if jwk.get("kty") == "EC" and jwk.get("crv") in CURVES:
        curve = CURVES[jwk["crv"]]()
        return ec.EllipticCurvePublicNumbers(_b64int(jwk.get("x")), _b64int(jwk.get("y")), curve).public_key()
    raise ValueError("unsupported key type")


def _verify(alg: str, key: PublicKey, data: bytes, signature: bytes) -> bool:
    digest = ALGORITHMS[alg][2]()
    try:
        if alg.startswith(("RS", "PS")):
            if not isinstance(key, rsa.RSAPublicKey):
                return False
            if alg.startswith("RS"):
                key.verify(signature, data, padding.PKCS1v15(), digest)
            else:
                key.verify(signature, data, padding.PSS(padding.MGF1(digest), padding.PSS.DIGEST_LENGTH), digest)
        else:  # JWS carries ECDSA signatures as the raw r || s pair
            if not isinstance(key, ec.EllipticCurvePublicKey):
                return False
            size = (key.curve.key_size + 7) // 8
            if len(signature) != 2 * size:
                return False
            r, s = int.from_bytes(signature[:size], "big"), int.from_bytes(signature[size:], "big")
            key.verify(encode_dss_signature(r, s), data, ec.ECDSA(digest))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _slug(value: Any) -> str:
    """A hub username made from a claim, or "" when nothing usable is left."""
    if not isinstance(value, str):
        return ""
    plain = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^a-z0-9._-]+", "-", plain.strip().lower())
    name = re.sub(r"^[^a-z0-9]+", "", name)[:64].rstrip("-")
    if len(name) == 1:
        name += "-user"
    return name if USERNAME_RE.match(name) else ""


def _username(claims: dict[str, Any]) -> str:
    email = claims.get("email")
    local = email.split("@", 1)[0] if isinstance(email, str) else None
    for candidate in (claims.get("preferred_username"), local, claims.get("sub")):
        if name := _slug(candidate):
            return name
    return "user"


def _email(value: Any) -> str | None:
    if isinstance(value, str) and "@" in value and len(value) <= 254 and not any(c.isspace() for c in value):
        return value
    return None


def _display_name(claims: dict[str, Any]) -> str | None:
    name = claims.get("name")
    if not isinstance(name, str) or not name.strip():
        parts = [claims.get("given_name"), claims.get("family_name")]
        name = " ".join(p for p in parts if isinstance(p, str))
    name = " ".join("".join(c for c in name if c.isprintable() or c.isspace()).split())[:100]
    return name or None


def _claim(claims: dict[str, Any], path: str) -> Any:
    """A claim by name, or by a dotted path into nested claims (realm_access.roles)."""
    if path in claims:
        return claims[path]
    value: Any = claims
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


class OidcClient:
    """The hub's side of the OpenID Connect authorization code flow (with PKCE)."""

    def __init__(self, settings: "Settings", transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self._transport = transport
        self.issuer = (settings.oidc_issuer or "").strip().rstrip("/")
        self.client_id = (settings.oidc_client_id or "").strip()
        self.enabled = bool(self.issuer and self.client_id)
        self.label = settings.oidc_label
        self.redirect_uri = f"{settings.public_url}/api/auth/oidc/callback"
        self._pending: dict[str, _Pending] = {}  # by state; insertion order is age
        self._config: dict[str, Any] | None = None
        self._config_at = 0.0
        self._jwks: tuple[str, float, list[dict[str, Any]]] | None = None  # (jwks_uri, fetched at, keys)

    # -- the flow ----------------------------------------------------------------------

    async def begin(self) -> tuple[str, str]:
        """(authorization URL, state value for the "atrium_oidc_state" cookie)."""
        if not self.enabled:
            raise OidcError("Single sign-on is not configured.")
        config = await self._discovery()
        state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        self._remember(state, _Pending(nonce, verifier, time.time() + PENDING_TTL))
        scopes = self.settings.oidc_scopes.split()
        if "openid" not in scopes:
            scopes.insert(0, "openid")
        params = {
            "response_type": "code", "client_id": self.client_id, "redirect_uri": self.redirect_uri,
            "scope": " ".join(scopes), "state": state, "nonce": nonce,
            "code_challenge": _b64encode(hashlib.sha256(verifier.encode("ascii")).digest()),
            "code_challenge_method": "S256",
        }
        endpoint = config["authorization_endpoint"]
        return f"{endpoint}{'&' if urlsplit(endpoint).query else '?'}{urlencode(params, quote_via=quote)}", state

    async def complete(self, code: str, state: str, state_cookie: str | None) -> OidcIdentity:
        if not self.enabled:
            raise OidcError("Single sign-on is not configured.")
        if not state_cookie or not hmac.compare_digest(state_cookie.encode(), state.encode()):
            raise OidcError("This sign-in was not started in this browser. Start again.")
        pending = self._pending.pop(state, None)
        if pending is None or pending.expires_at <= time.time():
            raise OidcError("This sign-in has expired or was already used. Start again.")
        config = await self._discovery()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "code_verifier": pending.verifier}
        auth: httpx.BasicAuth | None = None
        if self.settings.oidc_client_secret:  # client_secret_basic (RFC 6749 2.3.1: both parts form-encoded)
            auth = httpx.BasicAuth(quote_plus(self.client_id), quote_plus(self.settings.oidc_client_secret))
        else:  # a public client: PKCE alone ties the code to this hub
            form["client_id"] = self.client_id
        tokens = await self._call("token request", "POST", config["token_endpoint"], data=form, auth=auth,
                                  headers={"Accept": "application/json"})
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str):
            raise OidcError("The identity provider did not return an ID token. Check that the openid scope is allowed.")
        claims = await self._validate(id_token, config, pending.nonce)
        return OidcIdentity(issuer=claims["iss"], subject=claims["sub"], username=_username(claims),
                            email=_email(claims.get("email")), name=_display_name(claims), role=self.role_for(claims),
                            claims=claims)

    async def check(self) -> dict[str, Any]:
        """Discovery and the signing keys, with every check sign-in applies to them (for the settings' Test button);
        nothing is sent but the two public GET requests. Raises OidcError."""
        if not self.issuer:
            raise OidcError("Enter the issuer URL.")
        if not self.client_id:
            raise OidcError("Enter the client ID.")
        self._config = None  # always fresh
        config = await self._discovery()
        keys = await self._signing_keys(config, refresh=True)
        usable = [k for k in keys if k.get("use", "sig") == "sig" and k.get("kty") in ("RSA", "EC")]
        if not usable:
            raise OidcError("The identity provider publishes no RSA or EC signing key.")
        claims = config.get("claims_supported") if isinstance(config.get("claims_supported"), list) else None
        scopes = config.get("scopes_supported") if isinstance(config.get("scopes_supported"), list) else None
        role_root = self.settings.oidc_role_claim.split(".", 1)[0]
        return {
            "issuer": config["issuer"], "authorization_endpoint": config["authorization_endpoint"],
            "token_endpoint": config["token_endpoint"], "jwks_uri": config["jwks_uri"], "signing_keys": len(usable),
            "pkce_s256": "S256" in (config.get("code_challenge_methods_supported") or ["S256"]),
            "scopes_supported": [str(s) for s in scopes][:50] if scopes else None,
            "role_claim_advertised": (role_root in claims) if claims is not None else None,
        }

    def role_for(self, claims: dict[str, Any]) -> str:
        """The hub role for the claim named by HUB_OIDC_ROLE_CLAIM (a string or a list of strings)."""
        s = self.settings
        raw = _claim(claims, s.oidc_role_claim)
        values = {raw} if isinstance(raw, str) else set()
        if isinstance(raw, list):
            values = {v for v in raw if isinstance(v, str)}
        if values & set(s.oidc_admin_values):
            return "admin"
        if values & set(s.oidc_operator_values):
            return "operator"
        return s.oidc_default_role

    def _remember(self, state: str, pending: _Pending) -> None:
        now = time.time()
        for key in [k for k, p in self._pending.items() if p.expires_at <= now]:
            del self._pending[key]
        while len(self._pending) >= MAX_PENDING:
            del self._pending[next(iter(self._pending))]
        self._pending[state] = pending

    # -- the ID token ------------------------------------------------------------------

    async def _validate(self, token: str, config: dict[str, Any], nonce: str) -> dict[str, Any]:
        try:
            if len(token) > MAX_TOKEN_SIZE:
                raise ValueError("too large")
            head, body, sig = token.split(".")
            header, claims, signature = json.loads(_b64decode(head)), json.loads(_b64decode(body)), _b64decode(sig)
            if not isinstance(header, dict) or not isinstance(claims, dict):
                raise ValueError("not a JSON object")
            if header.get("kid") is not None and not isinstance(header["kid"], str):
                raise ValueError("bad kid")
        except (ValueError, RecursionError):
            raise OidcError("The identity provider returned a malformed ID token.") from None
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in ALGORITHMS:
            raise OidcError(f"The ID token uses a signature algorithm the hub does not accept ({_safe(alg)}).")
        if "crit" in header:
            raise OidcError("The ID token uses extensions the hub does not understand.")
        kid = header.get("kid")
        keys = self._candidates(await self._signing_keys(config), alg, kid)
        if not keys:  # perhaps a rotated key: fetch the key set again, once
            keys = self._candidates(await self._signing_keys(config, refresh=True), alg, kid)
        if not keys:
            raise OidcError("The ID token was signed with a key the identity provider does not publish.")
        data = f"{head}.{body}".encode("ascii")
        if not any(_verify(alg, key, data, signature) for key in keys):
            raise OidcError("The ID token's signature is not valid.")
        self._check_claims(claims, config["issuer"], nonce)
        return claims

    @staticmethod
    def _candidates(jwks: list[dict[str, Any]], alg: str, kid: str | None) -> list[PublicKey]:
        kty, crv, _ = ALGORITHMS[alg]
        keys = []
        for jwk in jwks:
            if jwk.get("kty") != kty or jwk.get("use", "sig") != "sig" or jwk.get("alg", alg) != alg:
                continue
            if (crv and jwk.get("crv") != crv) or (kid is not None and jwk.get("kid") != kid):
                continue
            try:
                keys.append(_public_key(jwk))
            except (ValueError, TypeError):
                continue
        return keys

    def _check_claims(self, claims: dict[str, Any], issuer: str, nonce: str) -> None:
        now = time.time()
        if claims.get("iss") != issuer:
            raise OidcError("The ID token was issued by a different identity provider.")
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []
        azp = claims.get("azp")
        if self.client_id not in audiences or ((len(audiences) > 1 or azp is not None) and azp != self.client_id):
            raise OidcError("The ID token was issued for a different application.")
        exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
        if not _number(exp) or not _number(iat) or (nbf is not None and not _number(nbf)):
            raise OidcError("The ID token has no valid lifetime.")
        if exp <= now - CLOCK_SKEW:
            raise OidcError("The ID token has expired. Check that the hub's clock is correct.")
        if iat > now + CLOCK_SKEW or (nbf is not None and nbf > now + CLOCK_SKEW):
            raise OidcError("The ID token is not valid yet. Check that the hub's clock is correct.")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not hmac.compare_digest(token_nonce.encode(), nonce.encode()):
            raise OidcError("The ID token does not belong to this sign-in.")
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub or len(sub) > 255:
            raise OidcError("The ID token does not identify the person.")

    # -- talking to the provider -------------------------------------------------------

    def _require_secure(self, url: Any, what: str) -> str:
        try:
            parts = urlsplit(url) if isinstance(url, str) else None
            host = parts.hostname if parts else None
        except ValueError:
            parts = host = None
        if parts and host and parts.scheme == "https":
            return url
        if parts and host and parts.scheme == "http":
            if host in LOCAL_HOSTS or self.settings.oidc_allow_http:
                return url
            raise OidcError(f"The identity provider's {what} uses plain http. Use https, "
                            "or set HUB_OIDC_ALLOW_HTTP=1 in a lab.")
        raise OidcError(f"The identity provider's {what} is not a valid http(s) URL.")

    async def _discovery(self) -> dict[str, Any]:
        if self._config is not None and time.time() - self._config_at < CACHE_TTL:
            return self._config
        self._require_secure(self.issuer, "issuer (HUB_OIDC_ISSUER)")
        doc = await self._call("discovery request", "GET", f"{self.issuer}/.well-known/openid-configuration")
        issuer = doc.get("issuer")
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.issuer:
            raise OidcError("The identity provider's discovery document names a different issuer than HUB_OIDC_ISSUER.")
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            self._require_secure(doc.get(name), name.replace("_", " "))
        self._config, self._config_at = doc, time.time()
        return doc

    async def _signing_keys(self, config: dict[str, Any], refresh: bool = False) -> list[dict[str, Any]]:
        uri = config["jwks_uri"]
        if not refresh and self._jwks and self._jwks[0] == uri and time.time() - self._jwks[1] < CACHE_TTL:
            return self._jwks[2]
        doc = await self._call("key request", "GET", uri)
        found = doc.get("keys")
        keys = [k for k in found if isinstance(k, dict)] if isinstance(found, list) else []
        self._jwks = (uri, time.time(), keys)
        return keys

    async def _call(self, what: str, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(transport=self._transport, timeout=15) as client:
                response = await client.request(method, url, **kwargs)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            raise OidcError(f"Could not reach the identity provider ({what}).") from exc
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code != 200:
            error = body.get("error") if isinstance(body, dict) else None
            detail = f" ({_safe(error)})" if isinstance(error, str) else ""
            raise OidcError(f"The identity provider refused the {what}: HTTP {response.status_code}{detail}.")
        if not isinstance(body, dict):
            raise OidcError(f"The identity provider answered the {what} with something other than a JSON object.")
        return body
