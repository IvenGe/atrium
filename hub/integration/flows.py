"""Data flows: what moves between the tools and the hub's apps, how often, and how the last run went.

A flow is owned by the module agent of its domain (``OWNERS``), which runs it by asking the tool's supervisor for
``connector.pull`` / ``connector.push`` / ``connector.action``. Sync links (collection ``sync_links``) pair a hub
record with its counterpart in a tool and keep the hash of what was last pushed, so unchanged records are skipped.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import TYPE_CHECKING, Any

from ..connectors.base import SEVERITIES, redact
from ..models import Flow, SyncLink
from ..store import new_id
from . import connections

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "flows"
LINKS = "sync_links"
OWNERS = {"assets": "module:assets", "vulnerabilities": "module:vulns", "risks": "module:grc", "controls": "module:grc",
          "people": "module:people", "accounts": "module:people", "network": "module:network",
          "frameworks": "module:grc", "assessments": "module:grc"}
APPS = {"assets": "Hub Assets", "vulnerabilities": "Hub Vulnerabilities", "risks": "Hub risk register",
        "controls": "Hub controls and evidence", "people": "Hub People", "accounts": "Hub People (accounts)",
        "network": "Hub Network", "frameworks": "Hub Compliance frameworks",
        "assessments": "Hub framework self-assessments"}
DEFAULT_SCHEDULE = {"pull": 60, "push": 60, "scan": 7 * 24 * 60}
DOMAIN_SCHEDULE = {"network": 15}  # pull minutes where the default does not fit (device drift is noticed sooner)
REPAIR_AFTER = 3  # consecutive failures before the Hub Supervisor asks the Patch Agent for a repair
STALE_RUN = 30 * 60  # a run marked as under way for longer than this was interrupted
ASSET_TYPES = ("server", "workstation", "network", "software", "saas", "cloud", "data", "other")
SECRET_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|credential)")


def get(hub: "Hub", flow_id: str) -> Flow | None:
    return hub.one(COLLECTION, flow_id, Flow)


def all_flows(hub: "Hub", tool_id: str | None = None) -> list[Flow]:
    items = hub.all(COLLECTION, Flow)
    return [f for f in items if f.tool_id == tool_id] if tool_id else items


def save(hub: "Hub", flow: Flow) -> Flow:
    flow.updated_at = time.time()
    return hub.save(COLLECTION, flow, "flow")


EXTENSIONS_OWNER = "module:extensions"  # extension domains ("x:<key>") are run by the Extensions Supervisor


def owner(flow: Flow) -> str:
    return OWNERS.get(flow.domain) or (EXTENSIONS_OWNER if flow.domain.startswith("x:") else OWNERS[flow.domain])


def app_name(hub: "Hub", domain: str) -> str:
    if domain in APPS:
        return APPS[domain]
    from ..extensions import registry

    defn = registry.domain(hub, domain.removeprefix("x:"))
    return f"Hub {defn.title}" if defn else f"Hub {domain.removeprefix('x:')}"


def end_name(hub: "Hub", end: str, domain: str) -> str:
    if end == "hub":
        return app_name(hub, domain)
    tool = hub.get_tool(end.split(":", 1)[1])
    return tool.name if tool else end


def title(hub: "Hub", flow: Flow) -> str:
    if flow.direction == "scan":
        return f"Scan in-scope assets with {end_name(hub, flow.target, flow.domain)} -> {APPS['vulnerabilities']}"
    what = flow.domain.removeprefix("x:")
    return f"{end_name(hub, flow.source, flow.domain)} {what} -> {end_name(hub, flow.target, flow.domain)}"


def key(flow: Flow) -> tuple[str, str, str, str | None]:
    return flow.domain, flow.source, flow.target, flow.action


class FlowError(ValueError):
    """A create/enable refusal the API turns into 400 or 409 with `detail.code`."""

    def __init__(self, code: str, message: str, status: int = 400, **extra: Any):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra

    def body(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.extra}


def ends_ok(source: str, target: str) -> bool:
    return {bool(re.fullmatch(r"hub|tool:[A-Za-z0-9._:-]+", source)),
            bool(re.fullmatch(r"hub|tool:[A-Za-z0-9._:-]+", target))} == {True} and (source == "hub") != (target == "hub")


def occupying(flow: Flow) -> bool:
    return flow.status in ("proposed", "enabled")


def same_flow(hub: "Hub", domain: str, source: str, target: str, action: str | None) -> Flow | None:
    key = (domain, source, target, action)
    return next((f for f in all_flows(hub) if (f.domain, f.source, f.target, f.action) == key), None)


def loop_conflict(hub: "Hub", domain: str, source: str, target: str, action: str | None,
                  ignore_id: str | None = None) -> Flow | None:
    """A pull and a push of the same domain for the same tool must not both be proposed or enabled (F7)."""
    if action == "scan" or source == target:
        return None
    if "hub" not in (source, target):
        return None
    opposite_source, opposite_target = (target, source)
    for flow in all_flows(hub):
        if ignore_id and flow.id == ignore_id:
            continue
        if not occupying(flow) or flow.domain != domain or flow.action:
            continue
        if flow.source == opposite_source and flow.target == opposite_target:
            return flow
    return None


def create_explicit(hub: "Hub", *, domain: str, source: str, target: str, action: str | None,
                    actor: str, schedule_minutes: int | None = None,
                    options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a flow a person asked for (the map's connect panel). Raises FlowError."""
    from . import strategies

    if action not in (None, "scan") or not ends_ok(source, target):
        raise FlowError("invalid", "A flow goes between the hub and a tool; action is empty or 'scan'.")
    if source.startswith("tool:") and target.startswith("tool:"):
        raise FlowError("invalid", "Tools exchange data through the hub, not directly.")
    tool_id = (target if target.startswith("tool:") else source).split(":", 1)[1]
    tool = hub.get_tool(tool_id)
    if tool is None:
        raise FlowError("invalid", f"Unknown tool '{tool_id}'")
    conn = connections.get(hub, tool_id)
    if conn is None:
        raise FlowError("no_connection", f"{tool.name} has no API connection yet.")
    existing = same_flow(hub, domain, source, target, action)
    if existing is not None:
        raise FlowError("flow_exists", "That data flow already exists.", 409, flow_id=existing.id)
    other = loop_conflict(hub, domain, source, target, action)
    if other is not None:
        raise FlowError("flow_conflict",
                        "A pull and a push of the same domain for the same tool would loop.",
                        409, flow_id=other.id)
    allowed = {(m.domain, m.source, m.target, m.action): m for m in strategies.moves(hub, tool_id)}
    move = allowed.get((domain, source, target, action))
    if move is None:
        raise FlowError("no_capability", f"{tool.name} cannot {action or ('pull' if target == 'hub' else 'push')} {domain}.")
    if move.blocked:
        raise FlowError("system_of_record", move.blocked)
    try:
        flow = make(hub, domain, source, target, action, reason=move.reason, created_by=actor, strategy=move.strategy)
    except ValueError as exc:
        raise FlowError("invalid", str(exc)) from exc
    if schedule_minutes is not None:
        flow.schedule_minutes = schedule_minutes
    if options:
        try:
            flow.options = validate_options(flow, options)
        except ValueError as exc:
            raise FlowError("invalid", str(exc)) from exc
    autonomous = hub.prefs["autonomy"] == "autonomous"
    if autonomous:
        flow.status = "enabled"
        save(hub, flow)
        hub.activity(actor, "info", f"{actor} enabled data flow {flow.title}", flow_id=flow.id)
        return {"flow": flow, "approval_id": None}
    save(hub, flow)
    approval = hub.approvals.create(
        "flow", f"Data flow: {flow.title}", flow.reason,
        {"flow_id": flow.id, "tool_id": flow.tool_id, "domain": flow.domain, "source": flow.source,
         "target": flow.target, "action": flow.action, "schedule_minutes": flow.schedule_minutes,
         "proposed_by": actor},
        "supervisor")
    flow.approval_id = approval.id
    save(hub, flow)
    hub.activity(actor, "info", f"{actor} proposed data flow {flow.title}", flow_id=flow.id)
    return {"flow": flow, "approval_id": approval.id}


def make(hub: "Hub", domain: str, source: str, target: str, action: str | None = None, *, reason: str = "",
         created_by: str = "supervisor", strategy: str = "connector", status: str = "proposed") -> Flow:
    flow = Flow(id=new_id("fl_"), domain=domain, source=source, target=target, action=action,  # type: ignore[arg-type]
                reason=reason, created_by=created_by, strategy=strategy, status=status)  # type: ignore[arg-type]
    flow.schedule_minutes = DOMAIN_SCHEDULE.get(domain, DEFAULT_SCHEDULE[flow.direction]) if flow.direction == "pull" \
        else DEFAULT_SCHEDULE[flow.direction]
    flow.title = title(hub, flow)
    return flow


def validate_options(flow: Flow, options: dict[str, Any]) -> dict[str, Any]:
    """Per-flow options: asset_types (push assets), retire_missing (pulls: retire / close / mark fixed what disappeared
    from the tool, default true), min_severity (push vulnerabilities, default low), include_info (scans and
    vulnerability pulls: also import informational results, default false), scan_name (scans)."""
    out: dict[str, Any] = {}
    for name, value in (options or {}).items():
        if name == "include_info" and flow.domain == "vulnerabilities" and flow.direction in ("pull", "scan"):
            if not isinstance(value, bool):
                raise ValueError("include_info must be true or false")
            out[name] = value
        elif name == "asset_types" and flow.domain == "assets":
            if not isinstance(value, list) or any(v not in ASSET_TYPES for v in value):
                raise ValueError(f"asset_types must be a list of {', '.join(ASSET_TYPES)}")
            out[name] = sorted(set(value))
        elif name == "retire_missing" and flow.direction == "pull":
            if not isinstance(value, bool):
                raise ValueError("retire_missing must be true or false")
            out[name] = value
        elif name == "min_severity" and flow.domain == "vulnerabilities" and flow.direction == "push":
            if value not in SEVERITIES:
                raise ValueError(f"min_severity must be one of {', '.join(SEVERITIES)}")
            out[name] = value
        elif name == "scan_name" and flow.direction == "scan":
            if not isinstance(value, str) or len(value) > 80 or not re.match(r"^[\w .:-]*$", value):
                raise ValueError("scan_name is up to 80 letters, digits, spaces, dots, colons and dashes")
            out[name] = value.strip()
        else:
            raise ValueError(f"Unknown option '{name}' for this flow")
    return out


def next_run(flow: Flow) -> float | None:
    if flow.status != "enabled" or not flow.schedule_minutes:
        return None
    return (flow.last_run or 0) + flow.schedule_minutes * 60


def is_due(flow: Flow, now: float) -> bool:
    due = next_run(flow)
    if due is None or due > now or (flow.job and flow.job.get("status") in ("running", "awaiting_approval")):
        return False
    return not (flow.running and now - flow.running < STALE_RUN)


def public(hub: "Hub", flow: Flow) -> dict[str, Any]:
    return {**flow.model_dump(mode="json"), "tool_id": flow.tool_id, "direction": flow.direction, "owner": owner(flow),
            "next_run": next_run(flow), "title": flow.title or title(hub, flow)}


def begin(hub: "Hub", flow_id: str) -> Flow:
    flow = get(hub, flow_id)
    if flow is None:
        raise ValueError(f"Unknown flow '{flow_id}'")
    flow.running = time.time()
    return save(hub, flow)


def finish(hub: "Hub", flow_id: str, *, ok: bool, counts: dict[str, Any], trigger: str, started: float,
           error: dict[str, Any] | None = None, count_failure: bool = True, detail: str = "",
           sample: Any = None) -> Flow | None:
    """Record a run. A failure that says something about the integration (count_failure) adds to the consecutive
    failures that trigger a repair; a success resets them. `sample` (sanitized) shows what a failed run sent."""
    flow = get(hub, flow_id)
    if flow is None:  # removed while it ran
        return None
    now = time.time()
    flow.running = None
    flow.last_run = now
    flow.last_result = {"ok": ok, "counts": counts, "error": error, "detail": detail, "trigger": trigger,
                        "at": now, "duration": round(now - started, 2)}
    if sample is not None:
        flow.last_result["sample"] = sanitize(sample)
    if ok:
        flow.failures = 0
    elif count_failure:
        flow.failures += 1
    return save(hub, flow)


def remove(hub: "Hub", flow_id: str, actor: str, note: str = "The data flow was removed.") -> Flow | None:
    flow = get(hub, flow_id)
    if flow is None:
        return None
    for approval in hub.approvals.list("pending"):
        if approval.payload.get("flow_id") == flow_id:
            hub.approvals.withdraw(approval.id, note, actor)
    hub.store.delete(COLLECTION, flow_id)
    hub.bus.publish("flow_removed", {"id": flow_id})
    return flow


def forget_tool(hub: "Hub", tool_id: str, actor: str) -> None:
    """A tool left the hub: its connection, flows and sync links go with it."""
    connections.delete(hub, tool_id)
    for flow in all_flows(hub, tool_id):
        remove(hub, flow.id, actor, "Superseded: the tool was removed from the hub.")
    for link in hub.store.list(LINKS):
        if link.get("tool_id") == tool_id:
            hub.store.delete(LINKS, link["id"])


def reset_running(hub: "Hub") -> None:
    """At start-up nothing is running yet: clear markers left by an interrupted process."""
    for flow in all_flows(hub):
        if flow.running:
            flow.running = None
            save(hub, flow)


# --------------------------------------------------------------------------------------
# sync links
# --------------------------------------------------------------------------------------


def link_id(tool_id: str, domain: str, hub_id: str) -> str:
    return f"{tool_id}|{domain}|{hub_id}"


def links(hub: "Hub", tool_id: str, domain: str) -> dict[str, SyncLink]:
    """hub id -> link, for one tool and domain."""
    out = {}
    for doc in hub.store.list(LINKS):
        if doc.get("tool_id") == tool_id and doc.get("domain") == domain:
            link = SyncLink.model_validate(doc)
            out[link.hub_id] = link
    return out


def put_link(hub: "Hub", tool_id: str, domain: str, hub_id: str, external_id: str, digest: str | None = None) -> SyncLink:
    link = SyncLink(id=link_id(tool_id, domain, hub_id), tool_id=tool_id, domain=domain, hub_id=hub_id,
                    external_id=str(external_id), hash=digest)
    hub.store.put(LINKS, link.model_dump(mode="json"))
    return link


def drop_link(hub: "Hub", tool_id: str, domain: str, hub_id: str) -> None:
    hub.store.delete(LINKS, link_id(tool_id, domain, hub_id))


def content_hash(record: dict[str, Any]) -> str:
    """What a pushed record says, ignoring ids and timestamps that change without the content changing."""
    body = {k: v for k, v in record.items() if k not in ("hub_id", "external_id", "updated_at", "evaluated_at")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


# --------------------------------------------------------------------------------------
# samples for repairs
# --------------------------------------------------------------------------------------


def sanitize(value: Any, secrets: dict[str, str] | list[str] | None = None, depth: int = 0) -> Any:
    """A sample safe to show an agent or a person: secret-looking keys masked, secret values redacted, long values
    and lists cut short."""
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(k): "***" if SECRET_KEY.search(str(k)) else sanitize(v, secrets, depth + 1)
                for k, v in list(value.items())[:40]}
    if isinstance(value, (list, tuple)):
        return [sanitize(v, secrets, depth + 1) for v in list(value)[:3]]
    if isinstance(value, str):
        return redact(value, secrets)[:500]
    return value
