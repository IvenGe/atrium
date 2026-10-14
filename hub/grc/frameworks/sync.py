"""The hub's side of the CISO Assistant framework sync.

- ``frameworks`` pull: every framework a CISO Assistant instance has loaded, with its requirement tree, its
  compliance assessments there and mapping sets, kept read-only in collection ``external_frameworks`` (one document
  per tool and framework, id ``ext:<tool id>:<framework id>``). Frameworks other than CyFun (e.g. the CRA) appear in
  the Compliance hub as read-only frameworks; the CyFun ones show as the sync status of Atrium's own catalogs.
- ``assessments`` push: the hub's CyFun self-assessments as records for ``CisoAssistantConnector`` (result and both
  maturity scores per scored requirement). Only when an administrator switched on "Send CyFun self-assessments" in
  the connection (the connector offers the domain only then, and the planner proposes the flow only then).

Text read from CISO Assistant (framework and requirement names, descriptions) is the tool's: shown as text, never
used as instructions.
"""

from __future__ import annotations

import time
from collections import deque
from typing import TYPE_CHECKING, Any

from ...integration import connections, flows
from . import CATALOG_IDS, LEVEL_NAMES, LIBRARY_NAMES, LIBRARY_URNS, load, scoring
from .assessments import all_assessments

if TYPE_CHECKING:
    from ...core import Hub

COLLECTION = "external_frameworks"
EVENT = "external_framework"
CONNECTOR = "ciso_assistant"
FRAMEWORK_URNS = {key: load(key).data["source"]["framework_urn"].lower() for key in CATALOG_IDS}
CYFUN_URNS = {urn: key for key, urn in FRAMEWORK_URNS.items()}
CRA_CAVEAT = ("CISO Assistant's CRA library (cra-resolution-annexes, version 3, 2024-06-25) appears to be built from the "
              "European Parliament's text, not the text published in the Official Journal (Regulation (EU) 2024/2847): "
              "check requirement wording against the OJ text.")


def doc_id(tool_id: str, external_id: str) -> str:
    return f"ext:{tool_id}:{external_id}"


def all_docs(hub: "Hub", tool_id: str | None = None) -> list[dict[str, Any]]:
    return [d for d in hub.store.list(COLLECTION) if tool_id is None or d.get("tool_id") == tool_id]


def store(hub: "Hub", tool_id: str, records: list[dict[str, Any]], retire_missing: bool = True) -> dict[str, int]:
    """Keep what a pull read; frameworks no longer loaded there are removed (with retire_missing)."""
    counts = {"total": len(records), "created": 0, "updated": 0, "unchanged": 0, "removed": 0}
    known = {d["id"]: d for d in all_docs(hub, tool_id)}
    seen = set()
    now = time.time()
    for record in records:
        key = doc_id(tool_id, record["external_id"])
        seen.add(key)
        digest = flows.content_hash(record)
        current = known.get(key)
        if current and current.get("hash") == digest:
            counts["unchanged"] += 1
            continue
        counts["updated" if current else "created"] += 1
        hub.store.put(COLLECTION, {**record, "id": key, "tool_id": tool_id, "hash": digest, "pulled_at": now,
                                   "cyfun": CYFUN_URNS.get(str(record.get("urn") or "").lower())})
        hub.bus.publish(EVENT, {"id": key, "tool_id": tool_id})
    if retire_missing:
        for key in set(known) - seen:
            hub.store.delete(COLLECTION, key)
            hub.bus.publish(f"{EVENT}_removed", {"id": key, "tool_id": tool_id})
            counts["removed"] += 1
    # every framework was read again: remember when, also for the unchanged ones
    for key in seen:
        doc = hub.store.get(COLLECTION, key)
        if doc and doc.get("pulled_at") != now:
            hub.store.put(COLLECTION, {**doc, "pulled_at": now})
    return counts


def forget_tool(hub: "Hub", tool_id: str) -> int:
    """The tool or its connection was removed: what was read from it goes too."""
    docs = all_docs(hub, tool_id)
    for doc in docs:
        hub.store.delete(COLLECTION, doc["id"])
        hub.bus.publish(f"{EVENT}_removed", {"id": doc["id"], "tool_id": tool_id})
    return len(docs)


# -- pushing self-assessments --------------------------------------------------------------------------------------

RESULT_NOTE = ("Result from the maturity: N/A -> not applicable; at least the level's target (B 2.5, I and E 3.0) -> "
               "compliant; below 2.0 -> non compliant; in between -> partially compliant (Atrium's mapping)")


def result_for(maturity: float, target: float) -> str:
    if maturity >= target:
        return "compliant"
    return "non_compliant" if maturity < 2.0 else "partially_compliant"


def push_records(hub: "Hub") -> list[dict[str, Any]]:
    """One record per CyFun self-assessment that is not archived (deterministic: unchanged ones are skipped)."""
    out = []
    for assessment in all_assessments(hub):
        if assessment.status == "archived":
            continue
        catalog = load(assessment.framework)
        result = scoring.evaluate(catalog, assessment.requirements, assessment.target_level)
        target = catalog.group_target(assessment.target_level)
        requirements = []
        for ref, entry in sorted(assessment.requirements.items()):
            if ref not in catalog.by_ref:
                continue
            lines = []
            if entry.na:
                lines.append(f"N/A: {entry.na_justification}")
            if entry.notes:
                lines.append(entry.notes)
            if entry.evidence:
                lines.append("Evidence: " + "; ".join(f"{e.kind} {e.ref}" for e in entry.evidence))
            observation = "\n".join(lines)[:4000]
            if entry.na:
                requirements.append({"ref_id": ref, "result": "not_applicable", "observation": observation})
                continue
            maturity = scoring.requirement_maturity(catalog, entry)
            if maturity is None:
                continue  # not scored in Atrium: CISO Assistant keeps whatever is there
            requirements.append({"ref_id": ref, "result": result_for(maturity, target), "score": entry.implementation,
                                 "documentation_score": entry.documentation, "observation": observation})
        progress = result["progress"]
        summary = (f"Atrium self-assessment '{assessment.name}' ({catalog.short_name}, target "
                   f"{LEVEL_NAMES[assessment.target_level]}): verdict {result['verdict'].replace('_', ' ')}; maturity "
                   f"{scoring.fmt(result['overall']['maturity'])}; {progress['scored']} scored, {progress['na']} N/A, "
                   f"{progress['unscored']} not scored of {progress['total']}. {RESULT_NOTE}.")
        out.append({"hub_id": assessment.id, "name": f"Atrium: {assessment.name}"[:200], "framework": catalog.id,
                    "framework_urn": catalog.data["source"]["framework_urn"], "level": assessment.target_level,
                    "ref_aliases": {c["library_ref_id"]: c["ref_id"] for c in catalog.data.get("corrections", [])},
                    "summary": summary, "requirements": requirements})
    return out


# -- views ----------------------------------------------------------------------------------------------------------


def _flow_view(flow) -> dict[str, Any] | None:
    if flow is None:
        return None
    last = flow.last_result or {}
    return {"id": flow.id, "status": flow.status, "last_run": flow.last_run, "ok": last.get("ok"),
            "error": (last.get("error") or {}).get("message"), "counts": last.get("counts")}


def status(hub: "Hub") -> list[dict[str, Any]]:
    """Per CISO Assistant connection: which libraries are loaded, the flows, and the hub assessments it holds."""
    out = []
    for conn in connections.all_connections(hub):
        if conn.kind != CONNECTOR:
            continue
        tool = hub.get_tool(conn.id)
        docs = all_docs(hub, conn.id)
        libraries = {str(d.get("library_urn") or "").lower() for d in docs}
        framework_urns = {str(d.get("urn") or "").lower() for d in docs}
        # None: nothing read yet; the library URN, or for CyFun the framework URN when libraries were not readable
        loaded = {key: (urn in libraries or FRAMEWORK_URNS.get(key, "-") in framework_urns) if docs else None
                  for key, urn in LIBRARY_URNS.items()}
        tool_flows = flows.all_flows(hub, conn.id)
        pull = next((f for f in tool_flows if f.domain == "frameworks" and f.direction == "pull"), None)
        push = next((f for f in tool_flows if f.domain == "assessments" and f.direction == "push"), None)
        links = flows.links(hub, conn.id, "assessments")
        out.append({
            "tool_id": conn.id, "tool_name": tool.name if tool else conn.id,
            "push_enabled": bool(conn.config.get("push_assessments")),
            "loaded": loaded, "library_names": LIBRARY_NAMES,
            "frameworks": len(docs), "pulled_at": max((d.get("pulled_at") or 0 for d in docs), default=None) or None,
            "pull_flow": _flow_view(pull), "push_flow": _flow_view(push),
            "assessments": {hub_id: {"external_id": link.external_id, "synced_at": link.synced_at}
                            for hub_id, link in links.items()},
        })
    return out


def _brief(doc: dict[str, Any], tool_names: dict[str, str]) -> dict[str, Any]:
    requirements = doc.get("requirements") or []
    return {"id": doc["id"], "kind": "external", "read_only": True, "name": doc.get("name"),
            "ref_id": doc.get("ref_id"), "provider": doc.get("provider"), "urn": doc.get("urn"),
            "library_urn": doc.get("library_urn"), "cyfun": doc.get("cyfun"),
            "source": {"tool_id": doc["tool_id"], "tool_name": tool_names.get(doc["tool_id"], doc["tool_id"]),
                       "connector": CONNECTOR, "pulled_at": doc.get("pulled_at")},
            "counts": {"requirements": sum(1 for n in requirements if n.get("assessable")), "nodes": len(requirements),
                       "assessments": len(doc.get("assessments") or [])},
            "assessments": [{k: a.get(k) for k in ("external_id", "name", "status", "selected_implementation_groups",
                                                   "updated_at", "scores", "results", "outcomes")}
                            for a in doc.get("assessments") or []],
            "caveat": CRA_CAVEAT if str(doc.get("library_urn") or "").lower() == LIBRARY_URNS["cra"] else None}


def _current(hub: "Hub") -> list[dict[str, Any]]:
    """What was read from tools that still have a CISO Assistant connection (a removed connection's frameworks
    disappear with it)."""
    tools = {c.id for c in connections.all_connections(hub) if c.kind == CONNECTOR}
    return [d for d in hub.store.list(COLLECTION) if d.get("tool_id") in tools]


def external_list(hub: "Hub") -> list[dict[str, Any]]:
    """Frameworks other than CyFun that CISO Assistant has loaded (CyFun shows as the built-in catalogs' status)."""
    names = {t.id: t.name for t in hub.tools()}
    return [_brief(d, names) for d in _current(hub) if not d.get("cyfun")]


def cyfun_status(hub: "Hub", framework_id: str) -> list[dict[str, Any]]:
    """For a built-in CyFun catalog: the instances that have it loaded and their compliance assessments of it."""
    names = {t.id: t.name for t in hub.tools()}
    return [_brief(d, names) for d in _current(hub) if d.get("cyfun") == framework_id]


TREE_DEPTH = 20  # levels of an external requirement tree; deeper nodes are shown at the last level


def _tree(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The requirement tree of a framework read from a tool (untrusted shape): nested by parent_urn, at most
    TREE_DEPTH levels deep (a longer parent chain is flattened at the last level), nodes on a parent cycle at the
    top."""
    items: dict[str, dict[str, Any]] = {}
    parents: dict[str, str] = {}
    for node in nodes:
        urn = node.get("urn")
        if urn and urn not in items:
            items[urn] = {**{k: node.get(k) for k in ("urn", "ref_id", "name", "description", "assessable",
                                                     "implementation_groups", "depth")}, "children": []}
            parents[urn] = node.get("parent_urn") or ""
    children: dict[str, list[str]] = {}
    for urn, parent in parents.items():
        if parent in items and parent != urn:
            children.setdefault(parent, []).append(urn)
    roots: list[dict[str, Any]] = []
    placed: set[str] = set()

    def place(start: str) -> None:
        queue = deque([(start, roots, 0)])
        while queue:
            urn, into, level = queue.popleft()
            if urn in placed:
                continue
            placed.add(urn)
            into.append(items[urn])
            below = items[urn]["children"] if level < TREE_DEPTH - 1 else into
            queue.extend((child, below, min(level + 1, TREE_DEPTH - 1)) for child in children.get(urn, []))

    for urn, parent in parents.items():
        if parent not in items or parent == urn:
            place(urn)
    for urn in parents:  # what is left hangs on a parent cycle
        place(urn)
    return roots


def external_detail(hub: "Hub", framework_id: str) -> dict[str, Any] | None:
    doc = next((d for d in _current(hub) if d["id"] == framework_id), None)
    if doc is None:
        return None
    names = {t.id: t.name for t in hub.tools()}
    return {**_brief(doc, names), "description": doc.get("description"),
            "implementation_groups": doc.get("implementation_groups") or [],
            "min_score": doc.get("min_score"), "max_score": doc.get("max_score"),
            "tree": _tree(doc.get("requirements") or []),
            "assessments": doc.get("assessments") or [], "mappings": doc.get("mappings") or [],
            "notice": "Read-only: loaded in CISO Assistant and read by Atrium. Names and descriptions are CISO "
                      "Assistant's text."}
