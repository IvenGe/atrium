"""Agent teams: the custom agents people and agents create, the templates Tool Supervisors propose teams from, and the
guardrails that bound them.

A team belongs to a tool (team = the tool id; its lead is the Tool Supervisor), to the hub ("hub"; lead: the Hub
Supervisor) or to a built-in app ("module:assets", "module:vulns", "module:grc", "module:people", "module:extensions";
lead: that app's supervisor). Extension packs can add team templates for kinds of tools (classify, roles_for). Every
custom agent has a parent: the agent that created it or, for an agent a person creates, the team's lead (or another
agent of the team the person picks). Depth counts the levels below the core agents: a lead's members have depth 1.

Guardrails (hub/guardrails.py): limit_to_parent_permissions clamps a member's permissions to its parent's effective
permissions every time it acts; allow_nested_teams and max_team_depth bound the depth; limit_team_size and
max_team_size bound the members per team; team_requires_approval turns proposals into approvals of kind "agent_team"
(unless the hub is autonomous).
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from .. import connectors, guardrails, llm_providers
from ..integration import connections, flows
from ..models import AGENT_PERMISSIONS, MIN_SCHEDULE, AgentDef, Tool

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "agent_defs"
MODULE_TEAMS = {"module:assets": "Assets", "module:vulns": "Vulnerabilities", "module:grc": "Compliance",
                "module:people": "People", "module:extensions": "Extensions", "module:network": "Network"}
STALE_RUN = 30 * 60
PERMISSION_INFO = {
    "read": "Read the hub's state: tools, assets, findings, risks, flows, approvals.",
    "tool_api": "Use the tool's own API through its connection (test it, read records).",
    "commands": "Run commands through the Operator Agent (the command policy and approvals apply).",
    "patches": "Ask the Patch Agent for patches and re-analysis (its approval flow applies).",
    "flows": "Run and plan data flows, and request vulnerability scans.",
    "assets_write": "Change assets and their vulnerability-scan scope.",
    "grc_write": "Record and update risks, triage vulnerabilities, re-evaluate controls.",
    "agents": "Propose agent teams and team members (the guardrails apply).",
}
PROVIDER_LABELS = {"anthropic": "Claude", "local": "Local", "rules": "Rules"}


# --------------------------------------------------------------------------------------
# definitions
# --------------------------------------------------------------------------------------


def defs(hub: "Hub") -> list[AgentDef]:
    return [AgentDef.model_validate(d) for d in hub.store.list(COLLECTION)]


def get_def(hub: "Hub", agent_id: str) -> AgentDef | None:
    doc = hub.store.get(COLLECTION, agent_id)
    return AgentDef.model_validate(doc) if doc else None


def save_def(hub: "Hub", defn: AgentDef) -> AgentDef:
    """Store a definition and refresh the running agent (and its card in the UI)."""
    hub.store.put(COLLECTION, defn.model_dump(mode="json"))
    agent = hub.agents.get(defn.id)
    if agent is not None and hasattr(agent, "defn"):
        agent.defn = defn  # type: ignore[attr-defined]
        if agent.paused == defn.enabled:
            agent.set_paused(not defn.enabled)
        hub.bus.publish("agent", agent.record())
    return defn


def is_agent_id(value: str | None) -> bool:
    return bool(value) and not str(value).startswith(("user:", "token:"))


def slug(text: str, limit: int = 48) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:limit].strip("-") or "agent"


def unique_id(hub: "Hub", base: str) -> str:
    stem = slug(base, 44)
    agent_id, n = f"agent:{stem}", 2
    while get_def(hub, agent_id) is not None or hub.agents.get(agent_id) is not None:
        agent_id, n = f"agent:{stem}-{n}", n + 1
    return agent_id


# --------------------------------------------------------------------------------------
# teams, permissions and limits
# --------------------------------------------------------------------------------------


def team_kind(team: str) -> str:
    return "hub" if team == "hub" else "module" if team in MODULE_TEAMS else "tool"


def team_lead(team: str) -> str:
    return "supervisor" if team == "hub" else team if team in MODULE_TEAMS else f"tool:{team}"


def team_name(hub: "Hub", team: str) -> str:
    if team == "hub":
        return "Hub"
    if team in MODULE_TEAMS:
        return MODULE_TEAMS[team]
    tool = hub.get_tool(team)
    return tool.name if tool else team


def validate_team(hub: "Hub", team: str) -> str:
    team = (team or "hub").strip()
    if team == "hub" or team in MODULE_TEAMS or hub.get_tool(team) is not None:
        return team
    raise ValueError(f"Unknown team '{team}': use 'hub', a tool id or one of {', '.join(MODULE_TEAMS)}")


def team_of(hub: "Hub", agent_id: str) -> str:
    """The team an agent leads or belongs to."""
    defn = get_def(hub, agent_id)
    if defn is not None:
        return defn.team
    if agent_id.startswith("tool:"):
        return agent_id.split(":", 1)[1]
    return agent_id if agent_id in MODULE_TEAMS else "hub"


def permissions_of(hub: "Hub", agent_id: str, _seen: set[str] | None = None) -> set[str]:
    """What an agent may do: a core agent's declared permissions, a custom agent's effective ones."""
    defn = get_def(hub, agent_id)
    if defn is not None:
        return set(effective_permissions(hub, defn, _seen))
    agent = hub.agents.get(agent_id)
    if agent is not None:
        return set(agent.permissions)
    return set(AGENT_PERMISSIONS) if agent_id.startswith("tool:") else set()


def effective_permissions(hub: "Hub", defn: AgentDef, _seen: set[str] | None = None) -> list[str]:
    """Its permissions - clamped to its parent's effective permissions while limit_to_parent_permissions is on."""
    perms = set(defn.permissions)
    if guardrails.value(hub, "limit_to_parent_permissions") and is_agent_id(defn.parent):
        seen = _seen or set()
        if defn.id in seen:  # a parent cycle grants nothing
            return []
        seen.add(defn.id)
        perms &= permissions_of(hub, str(defn.parent), seen)
    return [p for p in AGENT_PERMISSIONS if p in perms]


def depth_for(hub: "Hub", parent: str | None) -> int:
    parent_def = get_def(hub, parent) if parent else None
    return parent_def.depth + 1 if parent_def else 1


def check_depth(hub: "Hub", depth: int) -> None:
    if depth <= 1:
        return
    if not guardrails.value(hub, "allow_nested_teams"):
        raise ValueError("Nested teams are switched off (guardrail allow_nested_teams): only members of a lead's own "
                         "team can be created, not members of a team agent")
    limit = int(guardrails.value(hub, "max_team_depth"))
    if depth > limit:
        raise ValueError(f"A team agent at depth {depth} exceeds the maximum team depth of {limit} "
                         "(guardrail max_team_depth)")


def outside_guardrails(hub: "Hub", defn: AgentDef) -> str | None:
    """Why an existing agent may not act now that the guardrails are tighter than when it was created (None: it may)."""
    try:
        check_depth(hub, defn.depth)
    except ValueError as exc:
        return str(exc)
    if guardrails.value(hub, "limit_team_size"):
        limit = int(guardrails.value(hub, "max_team_size"))
        team = sorted(members(hub, defn.team), key=lambda d: (d.created_at, d.id))
        if any(d.id == defn.id for d in team[limit:]):  # the oldest members keep acting
            return (f"the {team_name(hub, defn.team)} team has {len(team)} agents, more than the maximum team size of "
                    f"{limit} (guardrail max_team_size) - remove agents or raise the limit")
    return None


def members(hub: "Hub", team: str, exclude: str | None = None) -> list[AgentDef]:
    return [d for d in defs(hub) if d.team == team and d.id != exclude]


def room(hub: "Hub", team: str, exclude: str | None = None) -> int | None:
    """How many more agents the team may have (None: no limit)."""
    if not guardrails.value(hub, "limit_team_size"):
        return None
    return max(0, int(guardrails.value(hub, "max_team_size")) - len(members(hub, team, exclude)))


def check_size(hub: "Hub", team: str, exclude: str | None = None) -> None:
    if room(hub, team, exclude) == 0:
        limit = guardrails.value(hub, "max_team_size")
        raise ValueError(f"The {team_name(hub, team)} team already has {limit} agents, the most allowed "
                         "(guardrail max_team_size)")


def check_parent(hub: "Hub", team: str, parent: str) -> None:
    """A parent is the team's lead, the Hub Supervisor, or a custom agent of the same team."""
    parent_def = get_def(hub, parent)
    if parent_def is not None:
        if parent_def.team != team:
            raise ValueError(f"{parent_def.name} belongs to the {team_name(hub, parent_def.team)} team, not to "
                             f"{team_name(hub, team)}")
        return
    if parent not in (team_lead(team), "supervisor"):
        raise ValueError(f"The parent must be the team's lead ({team_lead(team)}), the Hub Supervisor or an agent of "
                         "the team")
    if hub.agents.get(parent) is None:
        raise ValueError(f"Unknown parent agent '{parent}'")


# --------------------------------------------------------------------------------------
# model providers
# --------------------------------------------------------------------------------------


def provider_kind(provider: str) -> str:
    return provider if provider in ("anthropic", "rules") else "local"


def check_provider(hub: "Hub", provider: str) -> str:
    provider = (provider or "").strip()
    if provider in ("anthropic", "rules") or llm_providers.get(hub, provider) is not None:
        return provider
    raise ValueError(f"Unknown provider '{provider}': use 'anthropic', 'rules' or a configured local provider id")


def default_provider(hub: "Hub") -> str:
    """Claude when it is available, else the first local provider, else rules."""
    if hub.llm.available:
        return "anthropic"
    local = next((p for p in llm_providers.all_providers(hub) if p.default_model), None)
    return local.id if local else "rules"


def provider_choices(hub: "Hub") -> list[dict[str, Any]]:
    out = [{"id": "anthropic", "label": "Claude", "kind": "anthropic", "available": hub.llm.available,
            "default_model": hub.prefs["model"], "models": []},
           {"id": "rules", "label": "Rules", "kind": "rules", "available": True, "default_model": "", "models": []}]
    for p in llm_providers.all_providers(hub):
        out.append({"id": p.id, "label": p.name, "kind": "local", "available": bool(p.last_test and p.last_test.get("ok")),
                    "default_model": p.default_model, "models": p.models})
    return out


def model_of(hub: "Hub", defn: AgentDef) -> str:
    if defn.model:
        return defn.model
    if defn.provider == "anthropic":
        return hub.prefs["model"]
    provider = llm_providers.get(hub, defn.provider)
    return provider.default_model if provider else ""


# --------------------------------------------------------------------------------------
# create, update, remove
# --------------------------------------------------------------------------------------

FIELDS = ("name", "title", "description", "instructions", "provider", "model", "permissions", "team", "parent",
          "schedule_minutes", "task", "enabled")


def _validated(data: dict[str, Any]) -> AgentDef:
    """An AgentDef, or ValueError with one readable message."""
    try:
        return AgentDef.model_validate(data)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(x) for x in first.get("loc", ()))
        raise ValueError(f"{where}: {str(first.get('msg', 'invalid')).removeprefix('Value error, ')}") from exc


def create(hub: "Hub", values: dict[str, Any], actor: str, *, created_by: str | None = None,
           template: str | None = None) -> AgentDef:
    """Validate a new custom agent against the guardrails (team, parent, depth, size), store it and start it."""
    team = validate_team(hub, str(values.get("team") or "hub"))
    parent = str(values.get("parent") or team_lead(team))
    check_parent(hub, team, parent)
    depth = depth_for(hub, parent)
    check_depth(hub, depth)
    check_size(hub, team)
    provider = check_provider(hub, str(values.get("provider") or default_provider(hub)))
    wanted = values.get("id")
    if wanted:
        agent_id = wanted if str(wanted).startswith("agent:") else f"agent:{wanted}"
        if get_def(hub, agent_id) is not None or hub.agents.get(agent_id) is not None:
            raise ValueError(f"An agent '{agent_id}' already exists")
    else:
        agent_id = unique_id(hub, f"{team}-{values.get('name') or 'agent'}" if team_kind(team) == "tool"
                             else str(values.get("name") or "agent"))
    now = time.time()
    defn = _validated({
        **{k: v for k, v in values.items() if k in FIELDS and v is not None},
        "id": agent_id, "team": team, "parent": parent, "depth": depth, "provider": provider, "template": template,
        "created_by": created_by or actor, "created_at": now, "updated_by": actor, "updated_at": now,
    })
    save_def(hub, defn)
    hub.agents.add_custom(defn)
    hub.activity(actor, "info", f"Created agent {defn.name} ({defn.title}) in the {team_name(hub, team)} team",
                 agent_id=defn.id, permissions=defn.permissions, provider=defn.provider)
    return defn


def update(hub: "Hub", agent_id: str, changes: dict[str, Any], actor: str) -> AgentDef:
    """Change a custom agent; moving it to another team or parent re-checks depth and size."""
    current = get_def(hub, agent_id)
    if current is None:
        raise KeyError(agent_id)
    data = current.model_dump()
    data.update({k: v for k, v in changes.items() if k in FIELDS and v is not None})
    if "provider" in changes and changes["provider"] is not None:
        data["provider"] = check_provider(hub, str(changes["provider"]))
    team_changed = data["team"] != current.team
    parent_changed = changes.get("parent") is not None and changes["parent"] != current.parent
    if team_changed or parent_changed:
        team = validate_team(hub, data["team"])
        parent = str(changes["parent"]) if parent_changed else team_lead(team)  # a new team: its lead, unless chosen
        if parent == agent_id or parent in descendants(hub, agent_id):
            raise ValueError("An agent cannot report to itself or to one of its own team members")
        check_parent(hub, team, parent)
        depth = depth_for(hub, parent)
        check_depth(hub, depth + max_subtree_depth(hub, agent_id))
        if team != current.team:  # its own members move with it
            moving, space = 1 + len(descendants(hub, agent_id)), room(hub, team, exclude=agent_id)
            if space is not None and space < moving:
                raise ValueError(f"The {team_name(hub, team)} team has room for {space} more agent(s), not {moving} "
                                 "(guardrail max_team_size)")
        data.update(team=team, parent=parent, depth=depth)
    data.update(updated_by=actor, updated_at=time.time())
    defn = _validated(data)
    save_def(hub, defn)
    if defn.depth != current.depth or defn.team != current.team:
        _cascade(hub, defn)
    changed = [k for k in FIELDS if getattr(defn, k) != getattr(current, k)]
    if changed:
        hub.activity(actor, "info", f"Configured agent {defn.name}: {', '.join(changed)}", agent_id=defn.id)
    return defn


def descendants(hub: "Hub", agent_id: str) -> set[str]:
    out: set[str] = set()
    frontier = [agent_id]
    all_defs = defs(hub)
    while frontier:
        parent = frontier.pop()
        for d in all_defs:
            if d.parent == parent and d.id not in out:
                out.add(d.id)
                frontier.append(d.id)
    return out


def max_subtree_depth(hub: "Hub", agent_id: str) -> int:
    """How many levels of members sit below an agent."""
    children = [d for d in defs(hub) if d.parent == agent_id]
    return 1 + max(max_subtree_depth(hub, c.id) for c in children) if children else 0


def _cascade(hub: "Hub", parent: AgentDef) -> None:
    for child in [d for d in defs(hub) if d.parent == parent.id]:
        child.depth, child.team = parent.depth + 1, parent.team
        save_def(hub, child)
        _cascade(hub, child)


async def remove(hub: "Hub", agent_id: str, actor: str) -> AgentDef:
    """Remove a custom agent; its members report to its parent from then on."""
    defn = get_def(hub, agent_id)
    if defn is None:
        raise KeyError(agent_id)
    for child in [d for d in defs(hub) if d.parent == agent_id]:
        child.parent, child.depth = defn.parent, defn.depth
        save_def(hub, child)
        _cascade(hub, child)
    hub.store.delete(COLLECTION, agent_id)
    await hub.agents.remove(agent_id)
    for approval in hub.approvals.list("pending"):  # nobody would act on their decision any more
        if approval.kind == "agent_team" and agent_id in (approval.requested_by, approval.payload.get("parent")):
            hub.approvals.withdraw(approval.id, f"Superseded: {defn.name} was removed.", actor)
    hub.activity(actor, "info", f"Removed agent {defn.name} from the {team_name(hub, defn.team)} team", agent_id=agent_id)
    return defn


async def forget_tool(hub: "Hub", tool_id: str, actor: str) -> None:
    """A tool left the hub: its team goes with it, and pending team proposals are withdrawn."""
    for defn in sorted(members(hub, tool_id), key=lambda d: -d.depth):
        hub.store.delete(COLLECTION, defn.id)
        await hub.agents.remove(defn.id)
    for approval in hub.approvals.list("pending"):
        if approval.kind == "agent_team" and approval.payload.get("team") == tool_id:
            hub.approvals.withdraw(approval.id, "Superseded: the tool was removed from the hub.", actor)


# --------------------------------------------------------------------------------------
# what a tool is, and the team templates
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Role:
    role: str
    title: str
    description: str
    instructions: str
    permissions: tuple[str, ...]
    schedule_minutes: int
    task: str
    rules_ok: bool  # a rules agent can do the standing task (health check, data flows, summary)


CATEGORIES = {"siem": "SIEM / monitoring", "grc": "GRC / compliance", "inventory": "Asset inventory",
              "scanner": "Vulnerability scanner"}
# (category, connector kinds, manifest capabilities, name keywords) - first match wins
CATEGORY_RULES: tuple[tuple[str, set[str], set[str], tuple[str, ...]], ...] = (
    ("scanner", {"openvas"}, {"vuln.scanner"}, ("openvas", "greenbone", "gvm", "nessus", "nuclei", "trivy", "zaproxy")),
    ("grc", {"ciso_assistant"}, {"grc.compliance", "grc.risks"}, ("ciso-assistant", "ciso assistant", "eramba",
                                                                    "simplerisk")),
    ("inventory", {"snipeit"}, {"assets.inventory"}, ("snipe-it", "snipeit", "glpi", "netbox", "ralph", "cmdb")),
    ("siem", set(), {"siem", "monitoring.alerts", "monitoring.metrics", "monitoring.uptime", "monitoring.dashboards",
                     "logs.search"},
     ("wazuh", "ossec", "graylog", "splunk", "security-onion", "security onion", "siem", "zabbix", "nagios", "icinga",
      "prometheus", "grafana", "uptime-kuma", "uptime kuma", "librenms", "checkmk")),
)

TEMPLATES: dict[str, tuple[Role, ...]] = {
    "siem": (
        Role("alert-triage", "Alert triage analyst",
             "Reviews {tool}'s alerts and findings, groups duplicates and raises the ones that need a person.",
             "You are the alert triage analyst for {tool}, a SIEM / monitoring tool in an integration hub. Each run: look "
             "at what {tool} reports - its findings through its connection (read_tool_records) when it has one, and the "
             "hub's data about it - group duplicates and noise, and summarize what needs a person's attention, most "
             "severe first, with the affected asset and a suggested next step. Record lasting problems as risks "
             "instead of repeating them every run. Never change {tool}'s configuration.",
             ("read", "tool_api", "grc_write"), 60,
             "Triage what {tool} reported since the last run: group duplicates, summarize what needs a person's "
             "attention and record lasting problems as risks.", False),
        Role("health-watcher", "Health watcher", "Checks that {tool} is up and reports outages.",
             "You watch the health of {tool}. Check it, compare with what you saw before, and report outages and "
             "recoveries briefly. Use only read-only commands for diagnosis.",
             ("read", "commands"), 15, "Check the health of {tool} and summarize its state.", True),
    ),
    "grc": (
        Role("compliance-analyst", "Compliance analyst",
             "Reviews failing controls and the risks shared with {tool}, and proposes remediation.",
             "You are the compliance analyst for {tool}, the GRC tool of an integration hub. Review the failing and "
             "partial controls, the open risks and the data flows to and from {tool}. Propose concrete remediation "
             "steps a person can take, and update risk treatments only where the evidence supports it.",
             ("read", "tool_api", "grc_write", "flows"), 1440,
             "Review the failing and partial compliance controls and the open risks shared with {tool}; propose "
             "remediation and update risk treatments where the evidence supports it.", False),
        Role("evidence-collector", "Evidence collector",
             "Keeps {tool} supplied with the hub's controls and their automated evidence.",
             "You keep {tool} supplied with the hub's controls and automated evidence: run the data flows to it and "
             "report what changed or failed.",
             ("read", "flows", "grc_write"), 1440, "Run the data flows of {tool} and summarize the state.", True),
    ),
    "inventory": (
        Role("inventory-reconciler", "Inventory reconciler",
             "Keeps the hub's asset register and {tool} in step and reports discrepancies.",
             "You reconcile the asset inventory in {tool} with the hub's asset register: run the asset data flows, then "
             "look for assets without an owner, without an address, or retired in {tool}, and report the "
             "discrepancies. Change assets only to fix clear mistakes.",
             ("read", "tool_api", "flows", "assets_write"), 360,
             "Run the asset data flows of {tool} and summarize the state of the asset register.", True),
    ),
    "scanner": (
        Role("vuln-triage", "Vulnerability triage analyst",
             "Prioritises {tool}'s findings by severity, asset criticality and deadline.",
             "You triage the vulnerability findings {tool} reports. Prioritise critical and high findings by asset "
             "criticality and remediation deadline, add short triage notes, and mark a finding a false positive or "
             "accepted only with clear evidence, written in the note. Never start scans yourself unless asked.",
             ("read", "flows", "grc_write"), 1440,
             "Review the open findings from {tool}: prioritise critical and high ones by asset criticality and "
             "deadline, and add triage notes.", False),
    ),
}
MAINTAINER = Role("maintainer", "Maintainer", "Watches {tool}'s health, integration score and open patches.",
                  "You maintain {tool} inside the integration hub: watch its health, its integration score and gaps, and "
                  "its open patches, and say what needs maintenance. Ask the Patch Agent for a patch only for a clear "
                  "gap; every patch waits for approval.",
                  ("read", "commands", "patches"), 1440,
                  "Check the health of {tool}, its integration score and open patches, and summarize what needs "
                  "maintenance.", True)


def _extension_teams(hub: "Hub | None") -> list[Any]:
    """Team templates of the active extension packs (hub/extensions)."""
    if hub is None:
        return []
    from ..extensions import registry

    return registry.team_items(hub)


def classify(hub: "Hub", tool: Tool) -> str | None:
    """What kind of tool this is, for the team templates: siem, grc, inventory, scanner, a category an extension pack
    adds - or None."""
    conn = connections.get(hub, tool.id)
    provides = set(tool.manifest.provides) if tool.manifest else set()
    text = " ".join([tool.id, tool.name, tool.manifest.name if tool.manifest else ""]).lower()
    for category, kinds, capabilities, names in CATEGORY_RULES:
        if conn is not None and conn.kind in kinds:
            return category
    for category, kinds, capabilities, names in CATEGORY_RULES:
        if provides & capabilities or any(n in text for n in names):
            return category
    detected = connectors.detect(tool)
    best = detected[0]["kind"] if detected and detected[0]["score"] >= 50 else None
    builtin = next((c for c, kinds, _, _ in CATEGORY_RULES if best in kinds), None)
    if builtin:
        return builtin
    for item in _extension_teams(hub):
        match = item.match
        if (conn is not None and conn.kind in match.connector_kinds) or provides & set(match.capabilities) \
                or any(n in text for n in match.names):
            return item.category
    return None


def category_title(hub: "Hub | None", category: str | None) -> str | None:
    if not category:
        return None
    if category in CATEGORIES:
        return CATEGORIES[category]
    return next((t.title for t in _extension_teams(hub) if t.category == category), category)


def roles_for(category: str | None, hub: "Hub | None" = None) -> list[Role]:
    """The template roles for a category: the built-in ones, those extension packs add, and a maintainer."""
    roles = list(TEMPLATES.get(category or "", ()))
    for item in _extension_teams(hub):
        if category and item.category == category:
            roles += [Role(r.role, r.title, r.description, r.instructions, tuple(r.permissions), r.schedule_minutes,
                           r.task, r.rules_ok) for r in item.roles if r.role not in {x.role for x in roles}]
    return [*roles, MAINTAINER]


def fill_text(text: str, values: dict[str, str]) -> str:
    """"{tool}" -> the tool's name; plain substitution (template texts may come from extension packs)."""
    return re.sub(r"\{([a-z_]+)\}", lambda m: values.get(m.group(1), m.group(0)), text)


def template_members(hub: "Hub", tool: Tool, category: str | None) -> list[dict[str, Any]]:
    provider = default_provider(hub)
    out = []
    for role in roles_for(category, hub):
        fill = {"tool": tool.name}
        out.append({
            "id": f"agent:{slug(f'{tool.id}-{role.role}')}", "name": f"{role.title} for {tool.name}"[:80],
            "title": role.title, "description": fill_text(role.description, fill),
            "instructions": fill_text(role.instructions, fill), "permissions": list(role.permissions),
            # a rules agent cannot do an analyst's task: it gets no schedule (it would only say it needs a model)
            "schedule_minutes": role.schedule_minutes if provider != "rules" or role.rules_ok else 0,
            "task": fill_text(role.task, fill), "provider": provider, "model": "",
            "template": f"{category or 'any'}:{role.role}",
        })
    return out


TEAM_SCHEMA = {
    "type": "object",
    "properties": {
        "rationale": {"type": "string"},
        "members": {"type": "array", "items": {
            "type": "object",
            "properties": {
                "role": {"type": "string"}, "title": {"type": "string"}, "description": {"type": "string"},
                "instructions": {"type": "string"},
                "permissions": {"type": "array", "items": {"type": "string", "enum": list(AGENT_PERMISSIONS)}},
                "schedule_minutes": {"type": "integer"}, "task": {"type": "string"},
            },
            "required": ["role", "title", "description", "instructions", "permissions", "schedule_minutes", "task"],
            "additionalProperties": False}},
    },
    "required": ["rationale", "members"],
    "additionalProperties": False,
}
TEAM_DESIGN_INSTRUCTIONS = (
    "You design small teams of AI agents that look after one tool inside an integration hub. Each agent has one clear "
    "role, the fewest permissions it needs (from the list you are given), a standing task it runs on a schedule "
    "(schedule_minutes: 0 for none, else at least 5; prefer hours to minutes) and instructions written to the agent "
    "in the second person. Agents act only through the hub's tools: commands, patches and scans go through approval. "
    "Propose at most the number of agents you are allowed, and always include a maintainer. In rationale, explain the "
    "team in two or three sentences for the administrator who approves it."
)


async def design_with_claude(hub: "Hub", tool: Tool, category: str | None, model: str, limit: int) -> tuple[list[dict[str, Any]], str]:
    """A team Claude designs for the tool (structured output), as member dicts; raises when the answer is unusable."""
    m = tool.manifest
    conn = connections.get(hub, tool.id)
    described = {
        "name": tool.name, "kind": m.kind if m else None, "description": m.description if m else "",
        "provides": m.provides if m else [], "category": category_title(hub, category) or "general tool",
        "connection": {"kind": conn.kind, "capabilities": connections.capabilities(conn)} if conn else None,
        "flows": [f.title for f in flows.all_flows(hub, tool.id)],
    }
    templates = [{"title": r.title, "task": fill_text(r.task, {"tool": tool.name}), "permissions": list(r.permissions)}
                 for r in roles_for(category, hub)]
    prompt = (f"<tool>\n{described}\n</tool>\n<permissions>\n{PERMISSION_INFO}\n</permissions>\n"
              f"<template_team>\n{templates}\n</template_team>\n<max_agents>{limit}</max_agents>")
    result = await hub.llm.json(system=TEAM_DESIGN_INSTRUCTIONS, prompt=prompt, schema=TEAM_SCHEMA, model=model,
                                effort="low", max_tokens=8000)
    provider = "anthropic"
    out = []
    for item in (result.get("members") or [])[:limit]:
        title = str(item.get("title") or "").strip()[:80]
        if not title:
            continue
        schedule = int(item.get("schedule_minutes") or 0)
        out.append({
            "id": f"agent:{slug(f'{tool.id}-' + str(item.get('role') or title))}", "name": f"{title} for {tool.name}"[:80],
            "title": title, "description": str(item.get("description") or "")[:1000],
            "instructions": str(item.get("instructions") or "")[:20_000],
            "permissions": [p for p in AGENT_PERMISSIONS if p in set(item.get("permissions") or [])],
            "schedule_minutes": 0 if schedule <= 0 else max(MIN_SCHEDULE, min(schedule, 525_600)),
            "task": str(item.get("task") or "")[:4000], "provider": provider, "model": "", "template": "claude",
        })
    if not out:
        raise ValueError("Claude proposed no usable team member")
    return out, str(result.get("rationale") or "")[:2000]


# --------------------------------------------------------------------------------------
# proposals and their approval
# --------------------------------------------------------------------------------------


def has_team_or_proposal(hub: "Hub", team: str) -> bool:
    """Whether a team exists or was ever proposed (a rejected proposal is not proposed again automatically)."""
    return bool(members(hub, team)) or any(a.kind == "agent_team" and a.payload.get("team") == team
                                           for a in hub.approvals.list())


def pending_proposal(hub: "Hub", team: str) -> str | None:
    return next((a.id for a in hub.approvals.list("pending")
                 if a.kind == "agent_team" and a.payload.get("team") == team), None)


def _member(hub: "Hub", raw: dict[str, Any], team: str, parent_perms: set[str] | None) -> dict[str, Any]:
    """A proposed member, normalized, with its permissions clamped to the parent's (the `clamped` ones removed)."""
    name = str(raw.get("name") or raw.get("title") or "Team agent").strip()[:80]
    perms = [p for p in AGENT_PERMISSIONS if p in set(raw.get("permissions") or ["read"])]
    clamped = [p for p in perms if parent_perms is not None and p not in parent_perms]
    schedule = int(raw.get("schedule_minutes") or 0)
    provider = str(raw.get("provider") or default_provider(hub))
    return {
        "id": str(raw.get("id") or "") or unique_id(hub, f"{team}-{name}" if team_kind(team) == "tool" else name),
        "name": name, "title": str(raw.get("title") or "Team agent").strip()[:80] or "Team agent",
        "description": str(raw.get("description") or "")[:1000], "instructions": str(raw.get("instructions") or "")[:20_000],
        "permissions": [p for p in perms if p not in clamped], "clamped": clamped,
        "schedule_minutes": 0 if schedule <= 0 else max(MIN_SCHEDULE, min(schedule, 525_600)),
        "task": str(raw.get("task") or "")[:4000], "provider": provider if provider_ok(hub, provider) else "rules",
        "model": str(raw.get("model") or "")[:200], "template": raw.get("template"),
    }


def provider_ok(hub: "Hub", provider: str) -> bool:
    try:
        check_provider(hub, provider)
        return True
    except ValueError:
        return False


def propose_members(hub: "Hub", *, requested_by: str, parent: str, members: list[dict[str, Any]], designer: str,
                    rationale: str = "", tool_id: str | None = None, category: str | None = None,
                    on_behalf_of: str | None = None) -> dict[str, Any]:
    """Check proposed members of `parent`'s team against the guardrails, then create them (autonomous mode, or the
    team_requires_approval guardrail off) or queue one approval of kind "agent_team". Raises ValueError when the
    guardrails forbid the whole proposal (nesting, depth). `on_behalf_of`: the team agent that asked a lead for the
    proposal - while limit_to_parent_permissions is on, the members get no permission that agent lacks either."""
    team = team_of(hub, parent)
    depth = depth_for(hub, parent)
    check_depth(hub, depth)
    parent_perms = None
    if guardrails.value(hub, "limit_to_parent_permissions"):
        parent_perms = permissions_of(hub, parent)
        if on_behalf_of and get_def(hub, on_behalf_of) is not None:
            parent_perms &= permissions_of(hub, on_behalf_of)
    prepared: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for raw in members:
        member = _member(hub, raw, team, parent_perms)
        if get_def(hub, member["id"]) is not None or any(m["id"] == member["id"] for m in prepared):
            skipped.append({"name": member["name"], "reason": "already in the team"})
            continue
        prepared.append(member)
    space = room(hub, team)
    if space is not None and len(prepared) > space:
        skipped += [{"name": m["name"], "reason": "team size limit (guardrail max_team_size)"} for m in prepared[space:]]
        prepared = prepared[:space]
    name = team_name(hub, team)
    result: dict[str, Any] = {"proposed": False, "approval_id": None, "created": [], "members": prepared,
                              "skipped": skipped, "team": team, "designer": designer, "category": category}
    if not prepared:
        result["detail"] = (f"Nothing to propose for the {name} team: "
                            + "; ".join(f"{s['name']} ({s['reason']})" for s in skipped) if skipped
                            else f"Nothing to propose for the {name} team.")
        return result
    payload = {"team": team, "tool_id": tool_id, "parent": parent, "depth": depth, "members": prepared,
               "designer": designer, "category": category, "rationale": rationale, "on_behalf_of": on_behalf_of}
    names = ", ".join(m["title"] for m in prepared)
    if hub.prefs["autonomy"] == "autonomous" or not guardrails.value(hub, "team_requires_approval"):
        created, failed = create_members(hub, payload, requested_by)
        result.update(proposed=True, created=[d.id for d in created], skipped=skipped + failed,
                      detail=f"Created {len(created)} agent(s) in the {name} team: {names}.")
        return result
    lines = [f"- {m['name']} ({m['provider']}): {', '.join(m['permissions']) or 'no permissions'}"
             + (f"; every {m['schedule_minutes']} min: {m['task']}" if m["schedule_minutes"] else "")
             + (f" [not granted: {', '.join(m['clamped'])}]" if m["clamped"] else "") for m in prepared]
    approval = hub.approvals.create("agent_team", f"Agent team for {name}: {names}",
                                    (rationale + "\n\n" if rationale else "") + "\n".join(lines), payload, requested_by)
    result.update(proposed=True, approval_id=approval.id, detail=f"Proposed {len(prepared)} agent(s) for the {name} team; "
                                                                 "waiting for approval.")
    return result


def create_members(hub: "Hub", payload: dict[str, Any], actor: str) -> tuple[list[AgentDef], list[dict[str, str]]]:
    """Create the members of a team proposal; each is re-checked against the guardrails as they are now."""
    created, failed = [], []
    for member in payload.get("members") or []:
        values = {k: member.get(k) for k in FIELDS if k not in ("team", "parent")}
        try:
            created.append(create(hub, {**values, "id": member.get("id"), "team": payload["team"],
                                        "parent": payload["parent"]}, actor, created_by=actor,
                                  template=member.get("template")))
        except ValueError as exc:
            failed.append({"name": str(member.get("name")), "reason": str(exc)})
    return created, failed


def settle(hub: "Hub", approval_id: str, approved: bool) -> None:
    """A person decided an "agent_team" approval: create the team (the requester is recorded as its creator)."""
    approval = hub.approvals.get(approval_id)
    if approval is None or approval.kind != "agent_team" or approval.status != "approved" or not approved:
        return
    created, failed = create_members(hub, approval.payload, approval.requested_by)
    hub.approvals.complete(approval.id, bool(created) or not failed,
                           {"created": [d.id for d in created], "skipped": failed})


# --------------------------------------------------------------------------------------
# schedules
# --------------------------------------------------------------------------------------


def next_run(defn: AgentDef) -> float | None:
    if not defn.enabled or not defn.schedule_minutes or not defn.task.strip():
        return None
    return (defn.last_run or defn.created_at) + defn.schedule_minutes * 60


def is_due(defn: AgentDef, now: float) -> bool:
    """Whether the scheduler should start the agent's standing task (callers also skip agents outside_guardrails)."""
    due = next_run(defn)
    if due is None or due > now:
        return False
    return not (defn.running and now - defn.running < STALE_RUN)


def reset_running(hub: "Hub") -> None:
    """At start-up nothing is running yet: clear markers left by an interrupted process."""
    for defn in defs(hub):
        if defn.running:
            defn.running = None
            save_def(hub, defn)


# --------------------------------------------------------------------------------------
# overview
# --------------------------------------------------------------------------------------


def overview(hub: "Hub") -> dict[str, Any]:
    """Every team with its lead and members: the hub, each tool (with what a proposal would contain) and the
    built-in apps."""
    records = {a.id: a.record() for a in hub.agents.all()}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for defn in defs(hub):
        record = records.get(defn.id)
        if record:
            grouped.setdefault(defn.team, []).append(record)
    limit = int(guardrails.value(hub, "max_team_size")) if guardrails.value(hub, "limit_team_size") else None

    def team(team_id: str, extra: dict[str, Any]) -> dict[str, Any]:
        found = sorted(grouped.get(team_id, []), key=lambda r: (r["depth"], r["name"].lower()))
        return {"team": team_id, "kind": team_kind(team_id), "name": team_name(hub, team_id),
                "lead": records.get(team_lead(team_id)), "members": found, "size": len(found), "max_size": limit,
                "pending_approval": pending_proposal(hub, team_id), "category": None, "category_title": None,
                "suggested": [], "can_propose": False, **extra}

    out = [team("hub", {})]
    for tool in sorted(hub.tools(), key=lambda t: t.name.lower()):
        category = classify(hub, tool) if tool.manifest else None
        out.append(team(tool.id, {"category": category, "category_title": category_title(hub, category),
                                  "suggested": [r.title for r in roles_for(category, hub)],
                                  "can_propose": tool.manifest is not None and f"tool:{tool.id}" in records}))
    out += [team(module, {}) for module in MODULE_TEAMS]
    values = hub.prefs["guardrails"]
    return {"teams": out, "permissions": [{"id": p, "description": PERMISSION_INFO[p]} for p in AGENT_PERMISSIONS],
            "providers": provider_choices(hub),
            "limits": {k: values.get(k) for k in ("limit_to_parent_permissions", "allow_nested_teams", "max_team_depth",
                                                  "limit_team_size", "max_team_size", "team_requires_approval",
                                                  "team_actions_need_approval")}}
