"""Hub-side decisions about a tool's manifest, re-applied after every analysis.

A tool's manifest comes from four layers, low to high (docs/MANIFEST.md): the analyzer's generic heuristics, the
known-product profile (it fills empty fields only), the tool's own ``hub.manifest.*`` (it beats both), and the hub-side
overrides kept here in ``Tool.manifest_overrides``: what applied patches set (a launch command, a health URL, a moved
port, single sign-on) and what administrators set in Integration > ... > Edit. The analysis never keeps anything from
the previous manifest by itself: every hub-side decision lives in the overrides, so a Re-analyse gives the same result
and ``native`` and ``known`` always come from the folder as it is now.

Merge rules (``merge`` and ``apply``): nested dicts are merged; the lists in UNION are unioned (a patch that adds an
event, an env file or a launch secret keeps what is there); any other value replaces; None deletes the key (an override
cleared, the analysis value comes back); ``native`` and ``known`` (and ``id``) are never taken from an override.

``check_edit`` and ``check_env_key`` are the checks of the administrators' manifest editor (PATCH
/api/tools/{id}/manifest): a value that could not work or would leak (a blocked or placeholder command, a port out of
range, a folder outside the tool's, an address with credentials in it) is refused in plain words before anything is set.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from pydantic import ValidationError

from ..execution.policy import classify
from ..models import Manifest, Patch, Tool, url_credentials
from . import known_tools
from .analyzer import load_native_manifest, placeholder

if TYPE_CHECKING:
    from ..core import Hub

UNION = ("provides", "consumes", "events.emits", "events.listens", "launch.env_files", "launch.secret_env")
DROPPED = ("id", "native", "known")  # set by the analysis only, never by an override
MIGRATION_PREF = "migrations.tool_overrides"
HOLLOW_URL = "https://example.com"  # the address the former event adapter polled when it knew none

# What an administrator sets by hand in Integration > Launch / Health / API > Edit (PATCH /api/tools/{id}/manifest),
# with the name each field has in a refusal; launch.env.<KEY> values marked secret (or secret_like) go to
# launch_secrets, never into the manifest; plain constants are launch.env.<KEY> overrides.
EDITABLE = {"launch.command": "The launch command", "launch.port": "The port", "launch.cwd": "The working folder",
            "health.url": "The health URL", "api.type": "The API type", "api.base_url": "The API base URL",
            "api.spec": "The API spec", "ui.url": "The portal URL"}
API_TYPES = ("rest", "graphql", "grpc", "none")
MAX_COMMAND = 500
MAX_URL = 500
MAX_ENV = 16  # Launch.secret_env


def _merge(current: dict[str, Any], update: dict[str, Any], prefix: str = "", *, prune: bool) -> dict[str, Any]:
    out = dict(current)
    for key, value in update.items():
        key = str(key)
        if not prefix and key in DROPPED:
            continue
        path = f"{prefix}{key}"
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict):
            base = out.get(key)
            out[key] = _merge(base if isinstance(base, dict) else {}, value, f"{path}.", prune=prune)
            if prune and not out[key]:
                out.pop(key)
        elif path in UNION and isinstance(value, list) and isinstance(out.get(key), list):
            out[key] = list(dict.fromkeys([*out[key], *copy.deepcopy(value)]))
        else:
            out[key] = copy.deepcopy(value)
    return out


def merge(current: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    """`current` overrides with `update` merged in (a new dict): nested dicts merged, UNION lists unioned, None deletes
    a key, ``native``/``known``/``id`` dropped; empty dicts are left out."""
    return _merge(current or {}, update or {}, prune=True)


def _leaves(values: dict[str, Any], prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    for key, value in values.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out += _leaves(value, f"{path}.")
        else:
            out.append((path, value))
    return out


def _nested(path: str, value: Any) -> dict[str, Any]:
    head, _, rest = path.partition(".")
    return {head: _nested(rest, value) if rest else value}


def apply(m: Manifest, overrides: dict[str, Any], *, strict: bool = False) -> Manifest:
    """A validated copy of `m` with `overrides` merged in (the merge rules above). An override that fails validation
    (a value a newer Atrium no longer accepts) is skipped, the others still apply; with `strict` the ValueError is
    raised instead (a patch being applied must not be recorded as applied without its effect)."""
    if not overrides:
        return m.model_copy(deep=True)
    data = m.model_dump()
    try:
        return Manifest.model_validate(_merge(data, overrides, prune=False))
    except ValidationError:
        if strict:
            raise
    for path, value in _leaves(overrides):  # one leaf at a time: only the bad ones are left out
        candidate = _merge(data, _nested(path, value), prune=False)
        try:
            Manifest.model_validate(candidate)
        except ValidationError:
            continue
        data = candidate
    return Manifest.model_validate(data)


def _put(data: dict[str, Any], parts: list[str], value: Any) -> None:
    for part in parts[:-1]:
        if not isinstance(data.get(part), dict):
            data[part] = {}
        data = data[part]
    data[parts[-1]] = value


def _remove(data: dict[str, Any], parts: list[str]) -> None:
    if len(parts) == 1:
        data.pop(parts[0], None)
        return
    child = data.get(parts[0])
    if isinstance(child, dict):
        _remove(child, parts[1:])
        if not child:
            data.pop(parts[0])


def set_fields(tool: Tool, values: dict[str, Any]) -> Tool:
    """Set hub-side values by dotted path ("launch.command", "launch.env.KC_HOSTNAME", "health.url") on both the
    overrides and the manifest: each value replaces what is there (lists too). None clears that override; the
    manifest keeps its value until the next analysis brings back the inferred one (the caller re-analyses). Raises
    ValueError, changing nothing, for a path the hub owns or a value the manifest does not accept."""
    if tool.manifest is None:
        raise ValueError("The tool has not been analysed yet")
    overrides = copy.deepcopy(tool.manifest_overrides)
    data = tool.manifest.model_dump()
    for path, value in values.items():
        parts = str(path).split(".")
        if not all(parts) or parts[0] in DROPPED:
            raise ValueError(f"{path} cannot be set by hand")
        if value is None:
            _remove(overrides, parts)
        else:
            _put(overrides, parts, copy.deepcopy(value))
            _put(data, parts, copy.deepcopy(value))
    manifest = Manifest.model_validate(data)  # a pydantic ValidationError is a ValueError
    tool.manifest, tool.manifest_overrides = manifest, merge({}, overrides)
    return tool


# --------------------------------------------------------------------------------------
# what an administrator may set by hand (the manifest editor)
# --------------------------------------------------------------------------------------


def _address(label: str, text: str, schemes: tuple[str, ...]) -> str:
    """An http(s) (or tcp://host:port) address with no credentials in it: the hub stores, probes and shows it as is."""
    if len(text) > MAX_URL:
        raise ValueError(f"{label} is longer than {MAX_URL} characters")
    if any(c.isspace() or ord(c) < 32 for c in text):
        raise ValueError(f"{label} must not contain spaces or control characters")
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ValueError(f"{label} is not a valid address") from None
    scheme = parts.scheme.lower()
    if scheme not in schemes or not parts.hostname:
        raise ValueError(f"{label} must start with " + " or ".join(f"{s}://" for s in schemes) + " and name a host")
    if scheme == "tcp" and (port is None or parts.path not in ("", "/") or parts.query or parts.fragment):
        raise ValueError(f"{label} must look like tcp://host:port for a port check")
    found = url_credentials(text)
    if found:
        raise ValueError(f"{label} must not carry credentials ({', '.join(found)}): everyone who can see the tool "
                         "would read them")
    return text


def _inside(label: str, text: str) -> str:
    """A path inside the tool's folder ("." included), as a forward-slash relative path."""
    from .patches import safe_relative  # patches imports this module

    if text in (".", "./"):
        return "."
    try:
        return safe_relative(text).as_posix()
    except ValueError:
        raise ValueError(f"{label} must be a path inside the tool's folder (no .., no absolute path)") from None


def check_edit(path: str, value: Any) -> Any:
    """An administrator's value for one editable field (EDITABLE), checked and normalised for ``set_fields``; None
    (back to what the analysis finds) passes as is. Raises ValueError with a plain message naming the field:

    - launch.command: one line of at most 500 characters, no NUL, not a "TODO" placeholder, not blocked by the
      command policy (hub/execution/policy.py; it runs on the hub machine when someone starts the tool);
    - launch.port: a whole number from 1 to 65535; launch.cwd: "." or a folder inside the tool's folder;
    - health.url: http(s)://... or tcp://host:port; api.base_url and ui.url: http(s)://...; never with credentials
      in them (user info, or a query parameter named like a token: models.url_credentials);
    - api.spec: an http(s) address or a path inside the tool's folder; api.type: rest, graphql, grpc or none."""
    if path not in EDITABLE:
        raise ValueError(f"{path} cannot be set by hand")
    if value is None:
        return None
    label = EDITABLE[path]
    if path == "launch.port":
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise ValueError("The port must be a whole number from 1 to 65535")
        return value
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    if "\x00" in value:
        raise ValueError(f"{label} must not contain a NUL character")
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is empty: give a value, or reset it to what Atrium found")
    if path == "launch.command":
        if len(text) > MAX_COMMAND:
            raise ValueError(f"The launch command is longer than {MAX_COMMAND} characters")
        if "\n" in text or "\r" in text:
            raise ValueError("The launch command must be one line (put several steps in a script in the tool's "
                             "folder)")
        if placeholder(text):
            raise ValueError("The launch command is a TODO placeholder: give the command that starts the tool")
        risk, why = classify(text)
        if risk == "blocked":
            raise ValueError(f"The command is blocked by the command policy ({why}).")
        return text
    if path == "launch.cwd":
        return _inside(label, text)
    if path == "api.type":
        if text.lower() not in API_TYPES:
            raise ValueError("The API type is rest, graphql, grpc or none")
        return text.lower()
    if path == "api.spec" and not text.lower().startswith(("http://", "https://")):
        return _inside(label, text)
    return _address(label, text, ("http", "https", "tcp") if path == "health.url" else ("http", "https"))


def secret_like(name: str, value: str | None = None) -> bool:
    """Whether a launch environment row is a secret even when the administrator did not mark it as one: its name
    reads like a credential (the rule that keeps such variables out of every child process, runner.SECRET_ENV:
    PASSWORD, TOKEN, API_KEY, SECRET, ...) or its value is an address with credentials in it. Such a value goes to the
    private launch secrets, never into the manifest (where an adopted hub.manifest draft would show it)."""
    from ..execution.runner import SECRET_ENV

    return bool(SECRET_ENV.search(str(name)) or (value and url_credentials(value)))


def check_env_value(name: str, value: Any) -> str:
    """A plain launch environment value an administrator sets (a hub-side launch.env constant, e.g. LOG_LEVEL=info):
    the same rules as a launch secret (launch_secrets.put: one line of at most 4,000 characters, no NUL, no quote or
    blank at either end), so a row can turn secret or plain later; else ValueError naming the variable, never the
    value."""
    from .launch_secrets import check_value

    return check_value(name, value)


def check_env_key(name: Any) -> str:
    """A launch environment variable name (the Operator's ENV_KEY rule: letters, digits and _, not starting with a
    digit), else ValueError."""
    from ..agents.operator import ENV_KEY  # late import: the agents import the integration modules

    if not isinstance(name, str) or not ENV_KEY.fullmatch(name):  # fullmatch: no trailing line break either
        raise ValueError(f"'{str(name)[:60]}' is not an environment variable name (letters, digits and _, not "
                         "starting with a digit)")
    return name


# --------------------------------------------------------------------------------------
# migration: tools stored before the overrides existed
# --------------------------------------------------------------------------------------


def hollow(patch: Patch) -> bool:
    """A former event adapter that polled https://example.com because it knew no address: it never worked."""
    return patch.strategy == "event_adapter" and any(HOLLOW_URL in c.content for c in patch.changes)


def rebuild(tool: Tool, patches: list[Patch]) -> tuple[dict[str, Any], bool]:
    """The overrides a stored tool's applied patches imply, in the order they were made: an adopted manifest becomes
    ``adopted`` (never ``native``), a hollow event adapter is left out. Returns them and whether one was hollow."""
    overrides: dict[str, Any] = {}
    skipped = False
    for patch in sorted((p for p in patches if p.tool_id == tool.id and p.status == "applied"),
                        key=lambda p: p.created_at):
        if patch.strategy == "add_manifest":
            where = patch.branch or patch.location
            update: dict[str, Any] = {"adopted": where} if where else {}
        elif hollow(patch):
            skipped = True
            continue
        else:
            update = patch.manifest_update
        overrides = merge(overrides, update)
    return overrides, skipped


def migrate_tool(tool: Tool, patches: list[Patch]) -> Tool:
    """One stored tool brought to the overrides model, from root files only (no tree walk, network or model): its
    overrides rebuilt when it has none, ``native`` recomputed from its folder, its known product recognised, and the
    overrides applied."""
    assert tool.manifest is not None
    m = tool.manifest.model_copy(deep=True)
    hollow_seen = False
    if not tool.manifest_overrides:
        tool.manifest_overrides, hollow_seen = rebuild(tool, patches)
    root = Path(tool.path) if tool.path else None
    folder = root is not None and root.is_dir()
    m.native = bool(folder and load_native_manifest(root)[0] is not None)
    if m.known is None:
        match = known_tools.recognise_tool(tool)
        if match is not None:
            known_tools.apply(m, match, root=root if folder else None,
                              compose=known_tools.read_compose(root) if folder else None)
    changed = f"{tool.id}.changed"
    if hollow_seen and changed not in (tool.manifest_overrides.get("events") or {}).get("emits", []):
        m.events.emits = [e for e in m.events.emits if e != changed]
    tool.manifest = apply(m, tool.manifest_overrides)
    return tool


def migrate(hub: "Hub") -> int:
    """Once per hub (pref "migrations.tool_overrides" = 1), at start: every stored tool with a manifest goes through
    migrate_tool. A tool that cannot be migrated is left as it was (logged). Returns how many tools changed."""
    if hub.prefs.get(MIGRATION_PREF) == 1:
        return 0
    patches = hub.patches()
    changed = 0
    for tool in hub.tools():
        if tool.manifest is None:
            continue
        before = tool.model_dump(mode="json")
        try:
            tool = migrate_tool(tool, patches)
        except Exception as exc:  # one odd stored tool must not keep the hub from starting
            hub.activity("hub", "warn", f"Could not move the hub-side settings of {tool.name} to the new model: {exc}")
            continue
        if tool.model_dump(mode="json") != before:
            hub.save_tool(tool)
            changed += 1
    hub.put_pref(MIGRATION_PREF, 1)
    if changed:
        hub.activity("hub", "info", f"Moved the hub-side settings of {changed} tool(s) to manifest overrides")
    return changed
