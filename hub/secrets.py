"""Encryption for credentials the hub stores (connector API tokens, passwords).

Values are encrypted with Fernet (AES-128-CBC + HMAC-SHA256, from the ``cryptography`` package). The key comes from
``HUB_SECRET_KEY`` - one Fernet key, or several separated by commas to rotate: the first encrypts, all decrypt - or,
when that is not set, from ``{data_dir}/secret.key``, generated on first use and readable by its owner only where the
operating system supports POSIX permissions (on Windows the data folder's ACLs protect it). Anyone with the key and
the database can read the secrets: back them up separately.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

KEY_FILE = "secret.key"
GENERATE_HINT = "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""


class SecretError(RuntimeError):
    """A secret cannot be encrypted or decrypted (wrong or missing key)."""


def _fernets(raw: str, origin: str) -> list[Fernet]:
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        raise SecretError(f"{origin} is empty")
    try:
        return [Fernet(k.encode()) for k in keys]
    except (ValueError, TypeError) as exc:
        raise SecretError(f"{origin} must hold Fernet keys (32 url-safe base64-encoded bytes); generate one with "
                          f"{GENERATE_HINT}") from exc


def _write_key_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # owner-only from the first byte (POSIX)
    except FileExistsError:
        return  # created concurrently: use that one
    with os.fdopen(fd, "wb") as fh:
        fh.write(Fernet.generate_key())
    try:
        path.chmod(0o600)
    except OSError:  # best effort where mode bits do not apply
        pass


class SecretBox:
    """encrypt/decrypt strings with the hub's key, loaded (or created) on first use."""

    def __init__(self, key: str | None = None, key_file: Path | None = None):
        self._key, self._key_file = key, key_file
        self._fernet: MultiFernet | None = None
        self._lock = threading.Lock()

    @classmethod
    def for_settings(cls, settings) -> "SecretBox":
        return cls(settings.secret_key, settings.data_dir / KEY_FILE)

    @property
    def source(self) -> str:
        return "HUB_SECRET_KEY" if self._key else "key file"

    def _cipher(self) -> MultiFernet:
        with self._lock:
            if self._fernet is None:
                if self._key:
                    fernets = _fernets(self._key, "HUB_SECRET_KEY")
                elif self._key_file is not None:
                    if not self._key_file.is_file():
                        _write_key_file(self._key_file)
                    fernets = _fernets(self._key_file.read_text(encoding="ascii"), str(self._key_file))
                else:
                    raise SecretError("No secret key configured")
                self._fernet = MultiFernet(fernets)
            return self._fernet

    def encrypt(self, value: str) -> str:
        return self._cipher().encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, token: str) -> str:
        try:
            return self._cipher().decrypt(token.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError) as exc:
            raise SecretError("A stored secret cannot be decrypted - HUB_SECRET_KEY or secret.key changed since it "
                              "was saved; enter the secret again.") from exc


def hub_secret_values(hub) -> list[str]:
    """Every secret value this hub holds, for masking text that leaves its control (command output that viewers and
    models read, audit packs): its settings and credential-looking environment variables, the Fernet key(s) - from
    HUB_SECRET_KEY or the key file - and the stored credentials it can decrypt (tool connections, AI model
    providers, the SSO client secret, the subsidiaries' signing keys) and the tools' launch secrets
    (adapters/<id>/launch/secrets.env) distinctive enough to search for (launch_secrets.maskable)."""
    from .extensions.selfpatch import known_secrets
    from .integration import connections, launch_secrets
    from . import llm_providers

    values = list(known_secrets(hub))
    raw_keys = hub.settings.secret_key or ""
    try:
        if not raw_keys:
            raw_keys = (hub.settings.data_dir / KEY_FILE).read_text(encoding="ascii")
    except (OSError, UnicodeError):
        pass
    values += [k.strip() for k in raw_keys.split(",") if k.strip()]
    stored: list[str] = []
    for conn in connections.all_connections(hub):
        stored += list(conn.secrets.values())
    stored += [p.api_key for p in llm_providers.all_providers(hub) if p.api_key]
    sso = hub.store.get("settings", "sso") or {}
    if sso.get("client_secret"):
        stored.append(sso["client_secret"])
    for token in stored:
        try:
            values.append(hub.secrets.decrypt(token))
        except (SecretError, TypeError, AttributeError):  # a credential that cannot be decrypted cannot leak either
            continue
    from .subsidiary import governance as subsidiaries
    from .subsidiary import keys as subsidiary_keys
    values += subsidiary_keys.secret_values(hub)  # the subsidiaries' signing keys
    values += subsidiaries.credential_values(hub)  # and the dedicated credentials of API-only subsidiaries
    values += launch_secrets.mask_values(hub.settings.workspace)  # a tool's launch secrets (never plain words)
    return [v for v in values if isinstance(v, str) and len(v) >= 4]
