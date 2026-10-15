"""Secrets for a tool's launch: the values of the environment variables named in ``launch.secret_env``.

They are kept like the SSO proxy secrets: in a private file of the hub's adapter folder for the tool
(``adapters/<id>/launch/secrets.env``: the file 0600, its folder 0700), never in a manifest, a patch, an API answer, the
activity log or the bus. A launch_command patch names the variables (an admin password a container image needs, for
example) and the values are generated when an administrator approves it; an administrator can set their own in
Integration > Launch > Edit (``put``: only the environment rows they mark as secret, or whose name or value looks like
a credential - ``overrides.secret_like``; a plain constant such as ``LOG_LEVEL=info`` stays a hub-side ``launch.env``
override instead). The Operator merges the file into the child environment through ``launch.env_files``
(operator.env_files), and ``hub.secrets.hub_secret_values`` masks every value distinctive enough to search for
(``mask_values``) wherever text leaves the hub's control (command output, a tool's process log, a model's prompt, the
activity log). A short or one-kind value ("admin", "8080", "production") is kept just as private but never masked:
masking it would rewrite every text of every tool that happens to contain the word, and the code patcher refuses to
rewrite a file holding a masked value.

Values are plain ``KEY=value`` lines, read back by ``analyzer.parse_env_file``, which strips quotes and surrounding
blanks: values that would not survive that round trip (a line break, a NUL, surrounding quotes or blanks) are refused
rather than stored changed.
"""

from __future__ import annotations

import os
import re
import secrets
import tempfile
from pathlib import Path
from typing import Iterable

from .analyzer import parse_env_file, read_repo_file

ENV_FILE = "launch/secrets.env"
SAFE_TOOL_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MAX_VALUE = 4_000
MASK_MIN = 8  # a launch secret shorter than this is never masked in texts (see maskable)
KINDS = (re.compile(r"[a-z]"), re.compile(r"[A-Z]"), re.compile(r"[0-9]"), re.compile(r"[^a-zA-Z0-9]"))
HEADER = ("# Launch secrets of this tool, kept by Atrium (never committed, never shown).\n"
          "# Change them in Integration > Launch > Edit.\n")


def _env_key():
    from ..agents.operator import ENV_KEY  # late import: the agents import the integration modules

    return ENV_KEY


def _folder(workspace: Path, tool_id: str) -> Path:
    if not SAFE_TOOL_ID.match(tool_id or ""):
        raise ValueError("Unsafe tool id for launch secrets")
    return workspace / "adapters" / tool_id


def _read(workspace: Path, tool_id: str) -> dict[str, str]:
    root = _folder(workspace, tool_id)
    text = read_repo_file(root, ENV_FILE, 64_000) if root.is_dir() else None  # never through a symbolic link
    key = _env_key()
    return {k: v for k, v in parse_env_file(text or "").items() if key.match(k)}


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:  # best effort (Windows ACLs are not mode bits)
        pass


def _write(workspace: Path, tool_id: str, values: dict[str, str]) -> None:
    """Replace the file atomically: a temporary file created 0600 in the same folder, then renamed over it (a symbolic
    link planted at the path is replaced, never followed)."""
    path = _folder(workspace, tool_id) / ENV_FILE
    if not values:
        forget(workspace, tool_id)
        return
    _private_dir(path.parent.parent)
    _private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".secrets-", dir=path.parent)  # mode 0600 from the first byte
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(HEADER + "".join(f"{k}={v}\n" for k, v in sorted(values.items())))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _check_key(name: str) -> str:
    if not isinstance(name, str) or not _env_key().match(name):
        raise ValueError(f"'{str(name)[:60]}' is not an environment variable name (letters, digits and _)")
    return name


def check_value(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"Give a value for {name}, or reset it")
    if len(value) > MAX_VALUE:
        raise ValueError(f"The value of {name} is longer than {MAX_VALUE} characters")
    if any(c in value for c in "\n\r\x00"):
        raise ValueError(f"The value of {name} must be one line")
    if value != value.strip() or value[0] in "\"'" or value[-1] in "\"'":
        raise ValueError(f"The value of {name} must not start or end with a quote or a blank")
    return value


def ensure(workspace: Path, tool_id: str, keys: Iterable[str]) -> list[str]:
    """Generate a value for every named variable that has none yet (32 url-safe characters); the values already set
    (generated earlier or chosen by an administrator) are kept. Returns the names it generated."""
    names = [_check_key(k) for k in dict.fromkeys(keys)]
    current = _read(workspace, tool_id)
    generated = [k for k in names if not current.get(k)]
    if generated:
        _write(workspace, tool_id, {**current, **{k: secrets.token_urlsafe(24) for k in generated}})
    return generated


def put(workspace: Path, tool_id: str, values: dict[str, str | None]) -> None:
    """Set (or with None, remove) launch secrets chosen by an administrator. Refuses a bad name or a value that would
    not read back unchanged; nothing is written then."""
    current = _read(workspace, tool_id)
    for name, value in values.items():
        _check_key(name)
        if value is None:
            current.pop(name, None)
        else:
            current[name] = check_value(name, value)
    _write(workspace, tool_id, current)


def keys(workspace: Path, tool_id: str) -> list[str]:
    """The names of the tool's launch secrets that hold a value (never the values)."""
    return sorted(k for k, v in _read(workspace, tool_id).items() if v)


def maskable(value: str) -> bool:
    """Whether a launch secret value is distinctive enough to be masked wherever text leaves the hub: at least
    MASK_MIN characters of at least two kinds (lower case, upper case, digits, others). Generated values always are;
    a plain word or number ("admin", "password", "8080", "true") is not - masking it would hide that word in every
    prompt, command output and log of every tool, and block code patches of any file that contains it."""
    return isinstance(value, str) and len(value) >= MASK_MIN and sum(bool(k.search(value)) for k in KINDS) >= 2


def mask_values(workspace: Path) -> list[str]:
    """The launch secret values masked in texts (hub.secrets.hub_secret_values): the maskable ones of ``values``."""
    return [v for v in values(workspace) if maskable(v)]


def values(workspace: Path) -> list[str]:
    """Every tool's launch secret values (``mask_values``: the ones masked in texts)."""
    out: list[str] = []
    adapters = workspace / "adapters"
    try:
        entries = list(os.scandir(adapters))
    except OSError:
        return out
    for entry in entries:
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False) or not SAFE_TOOL_ID.match(entry.name):
            continue
        out += [v for v in _read(workspace, entry.name).values() if v]
    return out


def forget(workspace: Path, tool_id: str) -> None:
    """Remove the tool's launch secrets (the tool was removed, or every secret was reset)."""
    path = _folder(workspace, tool_id) / ENV_FILE
    try:
        path.unlink(missing_ok=True)
        path.parent.rmdir()  # only when nothing else is in launch/
    except OSError:
        pass
