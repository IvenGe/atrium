"""Password hashing (scrypt from the standard library) and the password policy."""

from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import hmac
import secrets

N, R, P, DKLEN = 2**14, 8, 1, 32
MIN_LENGTH, MAX_LENGTH, MIN_DISTINCT = 12, 256, 5


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = _scrypt(password, salt, N, R, P, DKLEN)
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str | None) -> bool:
    """Constant-time check of a password against an encoded hash; anything malformed is simply False."""
    try:
        scheme, n, r, p, salt_b64, hash_b64 = (encoded or "").split("$")
        n_, r_, p_ = int(n), int(r), int(p)
        if scheme != "scrypt" or not (2 <= n_ <= 2**20 and 1 <= r_ <= 32 and 1 <= p_ <= 16):
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(hash_b64, validate=True)
        if not salt or not expected:
            return False
        actual = _scrypt(password, salt, n_, r_, p_, len(expected))
    except (ValueError, TypeError, binascii.Error, MemoryError):
        return False
    return hmac.compare_digest(actual, expected)


@functools.cache
def dummy_hash() -> str:
    """A real hash of a random password: verifying against it costs as much as verifying a real account."""
    return hash_password(secrets.token_urlsafe(16))


def validate_password(password: str, username: str = "") -> None:
    """Raise ValueError with a message people can act on when a password breaks the policy."""
    if len(password) < MIN_LENGTH:
        raise ValueError(f"Passwords must be at least {MIN_LENGTH} characters long.")
    if len(password) > MAX_LENGTH:
        raise ValueError(f"Passwords can be at most {MAX_LENGTH} characters long.")
    if username and username.strip().lower() in password.lower():
        raise ValueError("The password must not contain the username.")
    if len(set(password)) < MIN_DISTINCT:
        raise ValueError(f"The password needs at least {MIN_DISTINCT} different characters.")
