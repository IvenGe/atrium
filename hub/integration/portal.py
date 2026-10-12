"""Where a tool's web interface lives: this machine, or a server that already runs it."""

from __future__ import annotations

from urllib.parse import ParseResult, urlparse, urlunparse

from ..models import Manifest

LOOPBACK = {"localhost", "127.0.0.1", "::1"}


def normalize_portal_url(value: str) -> str:
    """An http(s) address with a host and no embedded credentials."""
    raw = value.strip()
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "Use an http or https address, for example https://ciso.example.com or http://10.0.0.8:6333"
        )
    if parsed.username or parsed.password:
        raise ValueError("Put credentials in the tool's Connection, not in the address")
    return raw.rstrip("/")


def apply_portal_url(manifest: Manifest, url: str) -> str:
    """Point the portal at `url`. Health and API addresses that still name the previous server follow it."""
    new = normalize_portal_url(url)
    old = manifest.ui.url
    if old and old != new:
        if manifest.health.url:
            manifest.health.url = retarget(old, new, manifest.health.url)
        if manifest.api.base_url:
            manifest.api.base_url = retarget(old, new, manifest.api.base_url)
    manifest.ui.url = new
    return new


def retarget(old_ui: str, new_ui: str, current: str) -> str:
    """Move an address that still names the old portal's server onto the new one. Anything else stays."""
    old, new, cur = urlparse(old_ui), urlparse(new_ui), urlparse(current)
    if not _same_service(old, cur):
        return current
    hostname = new.hostname or ""
    if cur.scheme == "tcp":
        port = new.port if new.port is not None else cur.port
        scheme = "tcp"
    else:
        port = new.port
        scheme = new.scheme or cur.scheme
    return urlunparse((scheme, _netloc(hostname, port), cur.path, "", cur.query, ""))


def is_remote(url: str | None) -> bool:
    """True when the address is not served by this machine."""
    return not _loopback(urlparse(url or "").hostname)


def _same_service(old: ParseResult, cur: ParseResult) -> bool:
    if not old.hostname or not cur.hostname:
        return False
    if _loopback(old.hostname) and _loopback(cur.hostname):
        return not (old.port and cur.port and old.port != cur.port)
    return _endpoint(old) == _endpoint(cur)


def _endpoint(parsed: ParseResult) -> tuple[str, int | None]:
    port = parsed.port
    if port is None:
        port = {"http": 80, "https": 443}.get(parsed.scheme)
    return ((parsed.hostname or "").lower(), port)


def _loopback(hostname: str | None) -> bool:
    return (hostname or "").lower() in LOOPBACK


def _netloc(hostname: str, port: int | None) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    return host if port is None else f"{host}:{port}"
