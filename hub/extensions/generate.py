"""Extension packs and self-patches written by Claude (structured output). Everything Claude returns is validated like
an upload: a pack through the strict pack models, a self-patch through the path and secret checks of selfpatch.py,
and Claude may only rewrite files of Atrium it was shown."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any

from ..connectors import base as connector_sdk
from ..connectors import generic_rest
from ..connectors.base import endpoint_of
from ..grc.baseline import CONTROLS
from ..models import AGENT_PERMISSIONS, FileChange, Tool
from . import pack as pack_format
from . import registry, selfpatch
from .gaps import Gap
from .pack import ExtensionPack, parse

if TYPE_CHECKING:
    from ..core import Hub

PROMPT_CHARS = 60_000
FILE_CHARS = 40_000
EXTENSION_SCHEMA = {
    "type": "object",
    "properties": {"rationale": {"type": "string"}, "pack_json": {"type": "string"},
                   "needs_code": {"type": "boolean"}, "code_goal": {"type": "string"}},
    "required": ["rationale", "pack_json", "needs_code", "code_goal"],
    "additionalProperties": False,
}
EXTENSION_INSTRUCTIONS = (
    "You extend an integration hub called Atrium with data-only extension packs when a newly imported tool needs "
    "something Atrium does not model. You get the tool's manifest, the gaps the hub found, Atrium's existing extension "
    "domains, its compliance controls and, when there is one, the tool's OpenAPI document. Write one pack in the "
    "documented format as JSON in pack_json ('' when no pack helps). Reuse an existing domain key instead of defining "
    "it again; map only API operations that exist in the OpenAPI document and never invent paths or fields; keep field "
    "lists short and useful; add control rules only for evidence an auditor would accept. A pack is data: never put "
    "code, scripts or shell commands in it. If a gap can only be closed by changing Atrium's own code (for example an "
    "API that is not REST/JSON), set needs_code to true and describe the change in code_goal for a developer; "
    "otherwise false and ''. In rationale, explain the pack in two or three sentences for the administrator who "
    "approves it."
)
SELF_PATCH_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"}, "rationale": {"type": "string"},
        "changes": {"type": "array", "items": {
            "type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
            "required": ["path", "content"], "additionalProperties": False}},
    },
    "required": ["title", "rationale", "changes"],
    "additionalProperties": False,
}
SELF_PATCH_INSTRUCTIONS = (
    "You change Atrium, an agent-run integration hub written in Python (FastAPI, pydantic, asyncio), so it can work "
    "with a new tool. Make the smallest change that achieves the goal, in the style of the files you are shown: "
    "concise, typed, sparse comments. Prefer adding a module (for example a connector in hub/connectors/ registered "
    "in hub/connectors/__init__.py) over changing existing behaviour, and add a pytest test under tests/ that needs "
    "no network (httpx.MockTransport). Never add secrets, never weaken a security check, and only rewrite files you "
    "were shown (new files are fine). Each change holds the complete new content of one file. The change is tested "
    "and reviewed by an administrator before it is merged."
)
SELF_PATCH_CONTEXT = ("hub/connectors/__init__.py", "hub/connectors/base.py", "hub/connectors/generic_rest.py")


def _pack_id(text: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")[:48].strip("-") or "extension"


async def claude_pack(hub: "Hub", tool: Tool, gaps: list[Gap], model: str) -> tuple[ExtensionPack | None, str, bool, str]:
    """(pack or None, rationale, needs_code, code_goal) - raises when Claude's answer is not usable."""
    from ..agents.patcher import load_openapi

    spec, known_base = "", None
    try:
        spec, known_base = await load_openapi(tool)
    except ValueError:
        pass
    m = tool.manifest
    described = {"id": tool.id, "name": tool.name, "kind": m.kind if m else None,
                 "description": m.description if m else "", "provides": m.provides if m else [],
                 "api": m.api.model_dump() if m else None, "sso": m.auth.sso if m else None}
    domains = {key: defn.model_dump(mode="json") for key, (defn, _) in registry.active_domains(hub).items()}
    controls = [{"id": c.id, "family": c.family, "title": c.title} for c in CONTROLS]
    prompt = (f"<tool>\n{json.dumps(described, default=str)}\n</tool>\n"
              f"<gaps>\n{json.dumps([g.as_dict() for g in gaps])}\n</gaps>\n"
              f"<pack_format>\n{pack_format.__doc__}\n</pack_format>\n"
              f"<connector_mapping_format>\n{generic_rest.__doc__}\n</connector_mapping_format>\n"
              f"<canonical_records>\n{connector_sdk.__doc__}\n</canonical_records>\n"
              f"<existing_domains>\n{json.dumps(domains)}\n</existing_domains>\n"
              f"<controls>\n{json.dumps(controls)}\n</controls>\n"
              f"<agent_permissions>{', '.join(AGENT_PERMISSIONS)}</agent_permissions>\n"
              + (f"<openapi known_api_base=\"{known_base or ''}\">\n{spec[:PROMPT_CHARS]}\n</openapi>" if spec else
                 "<openapi>none</openapi>"))
    result = await hub.llm.json(system=EXTENSION_INSTRUCTIONS, prompt=prompt, schema=EXTENSION_SCHEMA, model=model,
                                effort="high", max_tokens=32_000)
    rationale = str(result.get("rationale") or "").strip()[:4000]
    needs_code, goal = bool(result.get("needs_code")), str(result.get("code_goal") or "").strip()[:4000]
    raw = str(result.get("pack_json") or "").strip()
    if not raw or raw in ("{}", "null"):
        return None, rationale, needs_code, goal
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("pack_json is not an object")
    data.update(source_tool=tool.id, created_by="patcher", status="proposed")
    data["id"] = _pack_id(str(data.get("id") or f"{tool.id}-extension"))
    data.setdefault("version", "1.0.0")
    for item in data.get("items") or []:
        if not isinstance(item, dict) or item.get("kind") != "connector":
            continue
        item.setdefault("tool", tool.id)
        if known_base and item.get("base_url") and endpoint_of(item["base_url"]) != endpoint_of(known_base):
            item["base_url"] = known_base.rstrip("/")  # the mapping may pick the API root's path, never another host
    return parse(data), rationale, needs_code, goal


async def claude_self_patch(hub: "Hub", goal: str, tool: Tool | None, model: str) -> tuple[str, str, list[FileChange]]:
    """(title, rationale, changes) for a change to Atrium's own repository."""
    root = selfpatch.config(hub).root()
    if root is None:
        raise ValueError("Atrium does not run from a git checkout, so it cannot patch itself")
    listed = await selfpatch.config(hub).git(["git", "-C", str(root), "ls-files"], root, 60, None)
    names = set(listed.output.split("\n")) if listed.exit_code == 0 else set()
    tree = "\n".join(sorted(n for n in names if n and not n.startswith("hub/web/"))[:600])
    shown = [n for n in SELF_PATCH_CONTEXT if (root / n).is_file()]
    files = "\n\n".join(f'<file path="{n}">\n{(root / n).read_text(encoding="utf-8", errors="replace")[:FILE_CHARS]}\n</file>'
                        for n in shown)
    described = ""
    if tool is not None and tool.manifest is not None:
        described = json.dumps({"id": tool.id, "name": tool.name, "api": tool.manifest.api.model_dump(),
                                "provides": tool.manifest.provides, "description": tool.manifest.description},
                               default=str)
    prompt = (f"<goal>{goal}</goal>\n" + (f"<tool>{described}</tool>\n" if described else "")
              + f"<file_tree>\n{tree}\n</file_tree>\n\n{files}")
    result = await hub.llm.json(system=SELF_PATCH_INSTRUCTIONS, prompt=prompt, schema=SELF_PATCH_SCHEMA, model=model,
                                effort="high", max_tokens=64_000)
    changes = []
    for change in (result.get("changes") or [])[:selfpatch.MAX_FILES]:
        path = str(change.get("path") or "").replace("\\", "/").strip()
        path = path[2:] if path.startswith("./") else path
        if path in names and path not in shown:
            raise ValueError(f"Claude tried to rewrite {path} without having seen it")
        changes.append(FileChange(path=path, content=str(change.get("content") or "")))
    if not changes:
        raise ValueError("Claude proposed no changes")
    return str(result.get("title") or "Change Atrium")[:120], str(result.get("rationale") or "")[:4000], changes
