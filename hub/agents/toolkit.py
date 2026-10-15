"""The shared agent toolkit: the tools agents can call from a model, each tagged with the permission it needs. The
provider layer (hub/llm) runs the conversation with whichever model an agent resolves to.

The Hub Supervisor's chat gets every tool. A custom (team) agent gets the tools its effective permissions allow
(see teams.effective_permissions), and an agent of a tool's team only reaches that tool through the tools that act on
one tool (its API, its flows, its team). Tools never bypass the hub's policies: commands go through the Operator Agent,
patches through the Patch Agent's approval flow, scans through the Vulnerability Supervisor - always with the calling
agent as the sender, so the guardrails and the autonomy level apply to it.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Awaitable, Callable

from ..integration import flows, identity, importer
from ..integration.compatibility import suite_matrix
from ..models import AGENT_PERMISSIONS, OPEN_STATES, SEVERITY_ORDER, Risk, Vulnerability
from ..store import new_id

if TYPE_CHECKING:
    from ..core import Hub
    from .base import BaseAgent

STR = {"type": "string"}
INT = {"type": "integer"}
# The only hub tools a subsidiary's sidecar staff reach (POST /api/subsidiary/v1/hub-request, hub/subsidiary/
# hubrequest.py), each forced to their own tool and narrowed further to the staff member's charter scope.
SIDECAR_HUB_TOOLS = frozenset({"get_tool", "tool_health", "data_flows", "propose_patches", "request_code_patch"})


@dataclass
class ToolContext:
    """Who is calling: the agent (the sender of every bus message a tool sends), its effective permissions and, for
    an agent of a tool's team, that tool."""

    hub: "Hub"
    agent: "BaseAgent"
    permissions: frozenset[str]
    tool_scope: str | None = None  # a tool id: tools that act on one tool only reach this one
    # the person ("user:<name>" / "token:<name>") whose chat message or manual run the agent acts on: the Operator
    # Agent judges commands and tool starts on the hub machine by that person's role (F1)
    requested_by: str | None = None

    def scoped(self, tool_id: str) -> str:
        tool_id = str(tool_id or "").strip()
        if self.tool_scope and tool_id != self.tool_scope:
            raise PermissionError(f"{self.agent.name} works for the {self.tool_scope} team and cannot act on '{tool_id}'")
        if self.hub.get_tool(tool_id) is None:
            raise ValueError(f"Unknown tool id '{tool_id}'")
        return tool_id

    def owns(self, source: str) -> bool:
        """Whether this agent may change a hub record whose ``source`` is `source`. Hub-wide agents may change any; an
        agent of a tool's team only what its tool supplied (``tool:<id>``, ``sync:<id>``, or the tool id itself, as
        findings record it) and what an agent of its team created - never people's records or other teams'."""
        scope = self.tool_scope
        if not scope:
            return True
        if source in (scope, f"tool:{scope}", f"sync:{scope}"):
            return True
        from . import teams

        defn = teams.get_def(self.hub, source) if source.startswith("agent:") else None
        return defn is not None and defn.team == scope

    def check_owns(self, kind: str, record_id: str, source: str) -> None:
        if not self.owns(source):
            raise PermissionError(f"{self.agent.name} works for the {self.tool_scope} team: it changes only {kind}s "
                                  f"that {self.tool_scope} or its team supplied, not {kind} {record_id} ({source})")

    async def ask(self, recipient: str, subject: str, body: dict[str, Any] | None = None, timeout: float = 300) -> dict[str, Any]:
        target = self.hub.agents.get(recipient)
        if target is not None and target.paused:  # it would answer only after it is resumed: fail now, not at the timeout
            raise RuntimeError(f"{target.name} is paused")
        body = dict(body or {})
        if recipient == "operator":  # always set here, never taken from a tool's arguments
            body["requested_by"] = self.requested_by
        return await self.agent.ask(recipient, subject, body, timeout)


Handler = Callable[[ToolContext, dict[str, Any]], Awaitable[Any]]


@dataclass(frozen=True)
class AgentTool:
    name: str
    description: str
    permission: str
    properties: dict[str, Any] = field(default_factory=dict)
    run: Handler | None = None

    def definition(self) -> dict[str, Any]:
        """The Claude tool definition (strict: every property is required; empty strings mean "not given")."""
        return {"name": self.name, "description": self.description, "strict": True,
                "input_schema": {"type": "object", "properties": self.properties, "required": list(self.properties),
                                 "additionalProperties": False}}


TOOLS: dict[str, AgentTool] = {}


def tool(name: str, description: str, permission: str, properties: dict[str, Any] | None = None):
    assert permission in AGENT_PERMISSIONS, permission

    def register(fn: Handler) -> Handler:
        TOOLS[name] = AgentTool(name, description, permission, properties or {}, fn)
        return fn
    return register


def available(permissions: set[str] | frozenset[str]) -> list[AgentTool]:
    return [t for t in TOOLS.values() if t.permission in permissions]


def definitions(permissions: set[str] | frozenset[str]) -> list[dict[str, Any]]:
    return [t.definition() for t in available(permissions)]


async def execute(ctx: ToolContext, name: str, args: dict[str, Any]) -> Any:
    """Run one tool call - refused when the caller lacks the tool's permission or the arguments break the schema."""
    spec = TOOLS.get(name)
    if spec is None or spec.run is None:
        raise ValueError(f"Unknown tool {name}")
    if spec.permission not in ctx.permissions:
        raise PermissionError(f"{ctx.agent.name} lacks the '{spec.permission}' permission needed for {name}")
    return await spec.run(ctx, validate_args(spec, args))


def validate_args(spec: AgentTool, args: Any) -> dict[str, Any]:
    """The arguments checked against the tool's schema here, not only by the model provider: a local model gets no
    strict schemas, so enums (e.g. the domains read_tool_records may read) would otherwise be advisory. Unknown keys
    are dropped, null (or "" for a non-string) means "not given" (dropped), a wrong type or a value outside an enum is
    refused. Integers and booleans sent as strings ("5", "true") are accepted, as local models often send them."""
    if not isinstance(args, dict):
        raise ValueError(f"{spec.name}: the arguments must be an object")
    return {key: _check_value(schema, args[key], f"{spec.name}.{key}") for key, schema in spec.properties.items()
            if args.get(key) is not None and not (args[key] == "" and schema.get("type") != "string")}


def _check_value(schema: dict[str, Any], value: Any, where: str) -> Any:
    kind = schema.get("type")
    if kind == "string":
        if not isinstance(value, str):
            raise ValueError(f"{where} must be a string")
    elif kind == "integer":
        if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,18}", value.strip()):
            value = int(value)
        elif isinstance(value, float) and value.is_integer():
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{where} must be an integer")
    elif kind == "boolean":
        value = {"true": True, "false": False}.get(value.strip().lower(), value) if isinstance(value, str) else value
        if not isinstance(value, bool):
            raise ValueError(f"{where} must be true or false")
    elif kind == "array":
        if not isinstance(value, list):
            raise ValueError(f"{where} must be a list")
        value = [_check_value(schema.get("items") or {}, item, f"{where}[]") for item in value]
    elif kind == "object" and not isinstance(value, dict):
        raise ValueError(f"{where} must be an object")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{where} must be one of: {', '.join(map(str, schema['enum']))}")
    return value


# --------------------------------------------------------------------------------------
# read
# --------------------------------------------------------------------------------------


@tool("list_tools", "List imported tools with kind, status, integration score and level.", "read")
async def _list_tools(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return [{"id": t.id, "name": t.name, "kind": t.manifest.kind if t.manifest else None, "status": t.status,
             "score": t.report.score if t.report else None, "level": t.report.level if t.report else None,
             "running": t.running, "health": t.health} for t in ctx.hub.tools()]


@tool("get_tool", "Full manifest, compatibility checks and patches of one tool.", "read", {"tool_id": STR})
async def _get_tool(ctx: ToolContext, args: dict[str, Any]) -> Any:
    tool_ = ctx.hub.get_tool(args["tool_id"])
    if tool_ is None:
        raise ValueError("Unknown tool id")
    return {"tool": tool_.public(),  # no webhook URL or launch env values for the model or the run log (F24)
            "patches": [{"id": p.id, "title": p.title, "status": p.status} for p in ctx.hub.patches(tool_.id)]}


@tool("integration_overview", "How tools connect: capability, identity and event links, port conflicts, unmet dependencies.", "read")
async def _integration(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return suite_matrix(ctx.hub.tools())


@tool("identity_overview", "The suite's identity providers, the default provider, and each tool's single sign-on status.", "read")
async def _identity(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return identity.overview(ctx.hub)


@tool("list_hosts", "List registered SSH hosts.", "read")
async def _hosts(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return [{"id": h.id, "name": h.name, "address": h.address, "user": h.username} for h in ctx.hub.hosts()]


@tool("tool_health", "Check the health of one tool now.", "read", {"tool_id": STR})
async def _health(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask(f"tool:{ctx.scoped(args['tool_id'])}", "health", timeout=30)


@tool("asset_summary", "Summary of the asset register.", "read")
async def _assets(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("module:assets", "summary")


@tool("people_summary", "People in the People app by status, their accounts, and leavers who still have access or "
      "company devices.", "read")
async def _people(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("module:people", "summary")


@tool("network_summary", "Network devices (firewalls, routers, switches, host firewalls): how many, how many without a "
      "current snapshot, unexplained configuration changes (drift) and how many accept changes now. Counts only.", "read")
async def _network(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("module:network", "summary")


@tool("compliance_summary", "Framework scores, failing controls and top risks.", "read")
async def _compliance(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("module:grc", "summary")


@tool("data_flows", "Data flows between tools and the hub's apps: status, schedule, last result, failures.", "read")
async def _flows(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return [{k: v for k, v in flows.public(ctx.hub, f).items() if k in (
        "id", "title", "status", "schedule_minutes", "last_run", "last_result", "failures", "job", "tool_id")}
        for f in flows.all_flows(ctx.hub, ctx.tool_scope)]


@tool("subsidiary_summary", "The agent teams working inside tools (subsidiaries): status, flags, staff, today's usage "
      "and approvals waiting. Counts only - never text from the tools.", "read")
async def _subsidiaries(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from ..subsidiary import governance

    out = []
    for sub in governance.all_subsidiaries(ctx.hub):
        if sub.status == "archived" or (ctx.tool_scope and sub.tool_id != ctx.tool_scope):
            continue
        summary = governance.summary(ctx.hub, sub)
        out.append({k: summary[k] for k in ("tool_id", "tool_name", "mode", "status", "flags", "charter_version",
                                            "staff_count", "pending_approvals", "last_seen")}
                   | {"usage": {k: v for k, v in summary["usage"].items() if isinstance(v, (int, float, type(None)))}})
    return {"allowed": governance.allowed(ctx.hub), "subsidiaries": out}


@tool("vulnerability_summary", "Open findings by severity, overdue findings, scan coverage and scanners.", "read")
async def _vuln_summary(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from .vulns import summary

    return summary(ctx.hub)


@tool("list_vulnerabilities", "Open vulnerability findings (at most 100), most severe first. source: a tool id or '' "
      "for all; severity: comma-separated severities or '' for all.", "read", {"source": STR, "severity": STR})
async def _vulns(ctx: ToolContext, args: dict[str, Any]) -> Any:
    severities = {s.strip() for s in str(args.get("severity") or "").split(",") if s.strip()}
    items = [v for v in ctx.hub.all("vulnerabilities", Vulnerability) if v.status in OPEN_STATES
             and (not args.get("source") or v.source == args["source"]) and (not severities or v.severity in severities)]
    items.sort(key=lambda v: (SEVERITY_ORDER.index(v.severity), v.due_at or float("inf")))
    return [{"id": v.id, "title": v.title, "severity": v.severity, "cvss": v.cvss, "cves": v.cves[:5], "host": v.host,
             "asset_id": v.asset_id, "source": v.source, "status": v.status, "overdue": v.overdue, "due_at": v.due_at,
             "note": v.note} for v in items[:100]]


@tool("list_risks", "Open risks in the risk register (at most 50), highest score first.", "read")
async def _risks(ctx: ToolContext, args: dict[str, Any]) -> Any:
    risks = sorted((r for r in ctx.hub.all("risks", Risk) if r.status != "closed"), key=lambda r: -r.score)
    return [{"id": r.id, "title": r.title, "score": r.score, "status": r.status, "treatment": r.treatment,
             "source": r.source, "owner": r.owner} for r in risks[:50]]


@tool("extension_records", "Records of an app an extension pack adds (alerts, tickets, incidents...). domain: its key, "
      "or '' to list the enabled extension domains; q: text to search for or ''. At most 100, most severe first.",
      "read", {"domain": STR, "q": STR})
async def _extension_records(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from ..extensions import records, registry

    domains = registry.active_domains(ctx.hub)
    key = str(args.get("domain") or "").strip().removeprefix("x:")
    if not key:
        return [{"domain": k, "title": d.title, "fields": [f.name for f in d.fields]} for k, (d, _) in domains.items()]
    if key not in domains:
        raise ValueError(f"No enabled extension domain '{key}' (enabled: {', '.join(domains) or 'none'})")
    listed = records.listing(ctx.hub, domains[key][0], q=str(args.get("q") or "")[:200], source=ctx.tool_scope or "",
                             limit=100)
    return [{k: r[k] for k in ("id", "title", "fields", "source", "asset", "person", "updated_at")}
            for r in listed["records"]]


@tool("list_approvals", "Actions waiting for human approval.", "read")
async def _approvals(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return [{"id": a.id, "title": a.title, "kind": a.kind, "requested_by": a.requested_by}
            for a in ctx.hub.approvals.list("pending")]


@tool("escalate", "Ask a person instead of deciding yourself: it waits in Approvals, and their answer reaches you "
      "in a later turn. Use it when one of your escalation rules applies, when you are blocked, or when you are unsure "
      "whether an action is safe. summary: what happened and what you need (the first line is its title); severity: "
      "info, warning or critical; needs: decision or information.", "read",
      {"summary": STR, "severity": {"type": "string", "enum": ["info", "warning", "critical"]},
       "needs": {"type": "string", "enum": ["decision", "information"]}})
async def _escalate(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from . import notify

    return notify.escalate(ctx.hub, ctx.agent, summary=str(args.get("summary") or ""),
                           severity=str(args.get("severity") or "warning"), needs=str(args.get("needs") or "decision"))


@tool("agent_teams", "The agent teams: each tool's, the hub's and the built-in apps' leads and team members.", "read")
async def _teams(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from . import teams

    return [{"team": t["team"], "name": t["name"], "lead": t["lead"]["id"] if t["lead"] else None,
             "members": [{"id": m["id"], "name": m["name"], "title": m["title"], "provider": m["provider"],
                          "permissions": m["effective_permissions"], "enabled": m["enabled"]} for m in t["members"]]}
            for t in teams.overview(ctx.hub)["teams"] if t["members"] or t["kind"] == "tool"]


# --------------------------------------------------------------------------------------
# tool_api: a tool's own API through its connector (the tool's supervisor holds the credentials)
# --------------------------------------------------------------------------------------


@tool("test_tool_connection", "Test the connection to a tool's own API (its connector).", "tool_api", {"tool_id": STR})
async def _test_connection(ctx: ToolContext, args: dict[str, Any]) -> Any:
    result = await ctx.ask(f"tool:{ctx.scoped(args['tool_id'])}", "connector.test", timeout=180)
    result.pop("failure", None)
    return result


# Not "network" (device configuration: untrusted rule descriptions and interface names) nor "frameworks" (licensed
# requirement text): agents read those through the summaries of the apps that own them.
READ_DOMAINS = ("assets", "vulnerabilities", "risks", "controls", "people", "accounts")


@tool("read_tool_records", "Read records of one domain (assets, vulnerabilities, risks, controls, people or accounts) "
      "from a tool's own API; returns the count and the first 20 records.", "tool_api",
      {"tool_id": STR, "domain": {"type": "string", "enum": list(READ_DOMAINS)}})
async def _read_records(ctx: ToolContext, args: dict[str, Any]) -> Any:
    domain = args.get("domain")
    if domain not in READ_DOMAINS:  # also checked by the schema; kept here so no caller can widen it
        raise ValueError(f"read_tool_records reads only {', '.join(READ_DOMAINS)}")
    reply = await ctx.ask(f"tool:{ctx.scoped(args['tool_id'])}", "connector.pull", {"domain": domain}, timeout=600)
    if reply.get("failure"):
        raise RuntimeError(reply["failure"].get("message") or "the connector failed")
    records = list(reply.get("records") or [])
    return {"count": len(records), "dropped": reply.get("dropped", 0), "records": flows.sanitize(records[:20])}


# --------------------------------------------------------------------------------------
# commands (through the Operator Agent's policy)
# --------------------------------------------------------------------------------------


@tool("run_command", "Run a shell command through the Operator Agent. target is 'local' or a host id from list_hosts. "
      "The command policy applies: blocked commands are refused, state-changing ones may wait for approval.",
      "commands", {"target": STR, "command": STR, "reason": STR})
async def _run_command(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("operator", "run", {"target": args["target"] or "local", "command": args["command"],
                                             "reason": args.get("reason", "")}, timeout=900)


@tool("start_tool", "Start a tool's process through the Operator Agent (may wait for approval).", "commands", {"tool_id": STR})
async def _start(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("operator", "launch", {"tool_id": ctx.scoped(args["tool_id"])}, timeout=120)


@tool("stop_tool", "Stop a tool's process.", "commands", {"tool_id": STR})
async def _stop(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("operator", "stop_tool", {"tool_id": ctx.scoped(args["tool_id"])}, timeout=60)


# --------------------------------------------------------------------------------------
# patches and the suite (through the Patch Agent and the Hub Supervisor)
# --------------------------------------------------------------------------------------


@tool("import_tool", "Import a tool. source_type is github (URL or owner/repo), local (folder path) or saas (https URL).",
      "patches", {"source_type": {"type": "string", "enum": ["github", "local", "saas"]}, "source": STR})
async def _import(ctx: ToolContext, args: dict[str, Any]) -> Any:
    if ctx.tool_scope:
        raise PermissionError("Agents of a tool's team cannot import other tools")
    tool_ = importer.create_tool(ctx.hub, importer.ImportRequest(source_type=args["source_type"], source=args["source"]))
    await ctx.agent.tell("supervisor", "tool.import", {"tool_id": tool_.id})
    return {"tool_id": tool_.id, "status": "importing in the background"}


@tool("reanalyze_tool", "Ask a tool's supervisor to re-analyse it and re-score the suite.", "patches", {"tool_id": STR})
async def _reanalyze(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("supervisor", "tool.imported", {"tool_id": ctx.scoped(args["tool_id"])}, timeout=900)


@tool("propose_patches", "Ask the Patch Agent to propose patches for every open integration gap of a tool.", "patches",
      {"tool_id": STR})
async def _propose_patches(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("patcher", "propose", {"tool_id": ctx.scoped(args["tool_id"])}, timeout=600)


@tool("request_code_patch", "Ask the Patch Agent for a custom source-code patch to a tool with source code.", "patches",
      {"tool_id": STR, "goal": STR})
async def _code_patch(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("patcher", "custom", {"tool_id": ctx.scoped(args["tool_id"]), "goal": args["goal"]}, timeout=900)


# --------------------------------------------------------------------------------------
# flows and scans
# --------------------------------------------------------------------------------------


@tool("run_flow", "Run one enabled data flow now (ids from data_flows).", "flows", {"flow_id": STR})
async def _run_flow(ctx: ToolContext, args: dict[str, Any]) -> Any:
    flow = flows.get(ctx.hub, str(args["flow_id"]))
    if flow is None:
        raise ValueError("Unknown flow id")
    ctx.scoped(flow.tool_id)
    if flow.status != "enabled" and not flow.job:
        raise ValueError("Only enabled flows can be run; a person approves or enables proposed ones")
    result = await ctx.ask(flows.owner(flow), "flow.run", {"flow_id": flow.id, "trigger": "agent"}, timeout=900)
    return {k: v for k, v in result.items() if k in ("ok", "pending", "detail", "counts", "failure")}


@tool("plan_flows", "Ask the Hub Supervisor to propose the data flows the tools' connections make possible.", "flows")
async def _plan(ctx: ToolContext, args: dict[str, Any]) -> Any:
    result = await ctx.ask("supervisor", "flows.plan", timeout=120)
    return {"proposed": [f["title"] for f in result.get("proposed", [])]}


@tool("request_scan", "Ask the Vulnerability Supervisor to scan the assets in scan scope. scanner_tool_id: '' for the "
      "only connected scanner. Scans agents start wait for approval unless an admin relaxed that guardrail.", "flows",
      {"scanner_tool_id": STR})
async def _scan(ctx: ToolContext, args: dict[str, Any]) -> Any:
    scanner = str(args.get("scanner_tool_id") or "") or ctx.tool_scope
    if scanner:
        ctx.scoped(scanner)
    result = await ctx.ask("module:vulns", "scan.request", {"scanner_tool_id": scanner or None}, timeout=600)
    return {k: v for k, v in result.items() if k in ("ok", "pending", "detail", "counts", "failure")}


# --------------------------------------------------------------------------------------
# assets_write
# --------------------------------------------------------------------------------------


@tool("update_asset", "Change an asset's owner, criticality or status ('' leaves a field unchanged).", "assets_write",
      {"asset_id": STR, "owner": STR, "criticality": {"type": "string", "enum": ["", "low", "medium", "high", "critical"]},
       "status": {"type": "string", "enum": ["", "active", "maintenance", "retired"]}})
async def _update_asset(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from ..models import Asset

    asset = ctx.hub.one("assets", str(args["asset_id"]), Asset)
    if asset is None:
        raise ValueError("Unknown asset id")
    ctx.check_owns("asset", asset.id, asset.source)
    changes = {k: args[k] for k in ("owner", "criticality", "status") if args.get(k)}
    if not changes:
        return {"changed": []}
    updated = Asset.model_validate({**asset.model_dump(), **changes, "updated_at": time.time()})
    ctx.hub.save("assets", updated, "asset")
    ctx.hub.activity(ctx.agent.id, "info", f"Asset {updated.name}: " + ", ".join(f"{k}={v}" for k, v in changes.items()),
                     asset_id=updated.id)
    await ctx.agent.tell("module:grc", "evaluate")
    return {"changed": sorted(changes)}


@tool("set_scan_scope", "Put assets in (or take them out of) vulnerability-scan scope.", "assets_write",
      {"asset_ids": {"type": "array", "items": STR}, "in_scope": {"type": "boolean"}})
async def _scope(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from ..models import Asset

    asset_ids = [str(a) for a in list(args["asset_ids"])[:1000]]
    if ctx.tool_scope:  # every asset first: nothing changes when one of them is out of reach
        for asset_id in asset_ids:
            asset = ctx.hub.one("assets", asset_id, Asset)
            if asset is None:
                raise ValueError(f"Unknown asset id '{asset_id}'")
            ctx.check_owns("asset", asset.id, asset.source)
    return await ctx.ask("module:assets", "scan.scope", {"asset_ids": asset_ids, "in_scope": bool(args["in_scope"])})


@tool("sync_assets", "Ask the Asset Supervisor to sync tools and hosts into the asset register.", "assets_write")
async def _sync(ctx: ToolContext, args: dict[str, Any]) -> Any:
    return await ctx.ask("module:assets", "sync")


# --------------------------------------------------------------------------------------
# grc_write
# --------------------------------------------------------------------------------------


@tool("create_risk", "Record a risk in the risk register (likelihood and impact 1-5).", "grc_write",
      {"title": STR, "description": STR, "likelihood": INT, "impact": INT})
async def _create_risk(ctx: ToolContext, args: dict[str, Any]) -> Any:
    risk = Risk(id=new_id("r_"), title=str(args["title"])[:200], description=str(args.get("description") or "")[:4000],
                likelihood=min(5, max(1, int(args["likelihood"]))), impact=min(5, max(1, int(args["impact"]))),
                source=ctx.agent.id, reviewed_at=time.time())
    ctx.hub.save("risks", risk, "risk")
    ctx.hub.activity(ctx.agent.id, "info", f"Recorded risk: {risk.title} (score {risk.score})", risk_id=risk.id)
    await ctx.agent.tell("module:grc", "evaluate")
    return {"risk_id": risk.id, "score": risk.score}


@tool("update_risk", "Change a risk's status or treatment and add a note ('' leaves a field unchanged).", "grc_write",
      {"risk_id": STR, "status": {"type": "string", "enum": ["", "open", "in_treatment", "closed"]},
       "treatment": {"type": "string", "enum": ["", "mitigate", "accept", "transfer", "avoid"]}, "note": STR})
async def _update_risk(ctx: ToolContext, args: dict[str, Any]) -> Any:
    risk = ctx.hub.one("risks", str(args["risk_id"]), Risk)
    if risk is None:
        raise ValueError("Unknown risk id")
    ctx.check_owns("risk", risk.id, risk.source)
    changes = {k: args[k] for k in ("status", "treatment") if args.get(k)}
    if args.get("note"):
        changes["description"] = (risk.description + "\n\n" if risk.description else "") + f"{ctx.agent.name}: {args['note']}"[:4000]
    risk = risk.model_copy(update={**changes, "reviewed_at": time.time()})
    ctx.hub.save("risks", risk, "risk")
    ctx.hub.activity(ctx.agent.id, "info", f"Updated risk: {risk.title}", risk_id=risk.id)
    await ctx.agent.tell("module:grc", "evaluate")
    return {"risk_id": risk.id, "changed": sorted(changes)}


@tool("update_vulnerability", "Set a finding's status and/or add a note ('' leaves the status unchanged). Use "
      "false_positive or accepted only with clear evidence, written in the note.", "grc_write",
      {"vulnerability_id": STR, "status": {"type": "string", "enum": ["", "open", "in_progress", "accepted",
                                                                       "false_positive", "fixed"]}, "note": STR})
async def _update_vuln(ctx: ToolContext, args: dict[str, Any]) -> Any:
    vuln = ctx.hub.one("vulnerabilities", str(args["vulnerability_id"]), Vulnerability)
    if vuln is None:
        raise ValueError("Unknown vulnerability id")
    if ctx.tool_scope and not ctx.owns(vuln.source):
        raise PermissionError(f"{ctx.agent.name} only triages findings from {ctx.tool_scope}")
    status = args.get("status") or None
    if status and status != vuln.status:
        vuln.status, vuln.fixed_at = status, time.time() if status == "fixed" else None
    if args.get("note"):
        vuln.note = ((vuln.note + "\n") if vuln.note else "") + f"{ctx.agent.name}: {args['note']}"[:4000]
    ctx.hub.save("vulnerabilities", vuln, "vulnerability")
    ctx.hub.activity(ctx.agent.id, "info", f"Vulnerability '{vuln.title}' ({vuln.host or 'no host'}): {vuln.status}",
                     vulnerability_id=vuln.id)
    await ctx.agent.tell("module:vulns", "reconcile")
    return {"vulnerability_id": vuln.id, "status": vuln.status}


@tool("evaluate_controls", "Ask the GRC Supervisor to re-evaluate the compliance controls now.", "grc_write")
async def _evaluate(ctx: ToolContext, args: dict[str, Any]) -> Any:
    result = await ctx.ask("module:grc", "evaluate")
    return {"frameworks": result.get("frameworks"), "changed": result.get("changed")}


# --------------------------------------------------------------------------------------
# agents: teams (the guardrails decide what is allowed)
# --------------------------------------------------------------------------------------


@tool("propose_team", "Ask a tool's supervisor to propose an AI agent team for the tool (it waits for approval unless "
      "an admin relaxed that guardrail).", "agents", {"tool_id": STR})
async def _propose_team(ctx: ToolContext, args: dict[str, Any]) -> Any:
    tool_id = ctx.scoped(args["tool_id"])
    return await ctx.ask(f"tool:{tool_id}", "team.propose", {"designer": "auto"}, timeout=600)


@tool("create_team_member", "Propose a new agent that reports to you (a member of your own team). permissions: a subset "
      "of yours. schedule_minutes: 0 for none, else at least 5. Nested teams, team size and approval follow the "
      "guardrails.", "agents",
      {"name": STR, "title": STR, "description": STR, "instructions": STR,
       "permissions": {"type": "array", "items": {"type": "string", "enum": list(AGENT_PERMISSIONS)}},
       "task": STR, "schedule_minutes": INT})
async def _create_member(ctx: ToolContext, args: dict[str, Any]) -> Any:
    from . import teams

    # only the schema's fields: a local model (no strict schemas) must not pick an id, a provider or a template
    member = {k: args.get(k) for k in ("name", "title", "description", "instructions", "permissions", "task",
                                       "schedule_minutes")}
    return teams.propose_members(ctx.hub, requested_by=ctx.agent.id, parent=ctx.agent.id, members=[member],
                                 designer="agent", rationale=f"Requested by {ctx.agent.name}.")
