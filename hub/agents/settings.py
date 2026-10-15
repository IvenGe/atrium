"""Per-agent settings (GET/PATCH /api/agents/{id}/settings), the same for core and custom agents: the model the agent
runs on ("" = inherit the suite's choice, hub/llm/selection.py), the Patch Agent's per-task models, "local only",
model parameters (effort, temperature, output cap, tool rounds), instructions (core agents: appended to the built-in
ones, or replacing them), the reply language and memory of chat agents, the tools they may use, budgets and rate
limits; for custom agents also their definition (name, role, description, instructions, permissions, team, task,
schedule, enabled). Core agents keep them in their "agents" document, custom agents in their definition
(AgentDef.provider / model / config).

Every change bumps the agent's settings version (optimistic concurrency: a write that names an older version is
refused), keeps a copy in the history ("agent_config_history", the last HISTORY_KEEP versions, restorable), is logged
- instructions only as their length and hash; widening changes (local only off, more tools or permissions, the hard
stop off) as warnings - and publishes `agent_settings {id, version}`, the event configuration views listen to
instead of `agent`, which fires after every handled message."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from ..llm import prompting
from ..llm import resolve as resolution
from ..llm.usage import DAILY, day_of, price_for
from ..models import AgentConfig, LlmChoice
from . import notify, teams, toolkit

if TYPE_CHECKING:
    from ..core import Hub
    from .base import BaseAgent

HISTORY = "agent_config_history"
HISTORY_KEEP = 20
CUSTOM_FIELDS = ("name", "title", "description", "permissions", "team", "parent", "schedule_minutes", "task", "enabled")
RESTORED_FIELDS = ("name", "title", "description", "permissions", "schedule_minutes", "task", "enabled")  # not the place in a team
CONFIG_KEYS = tuple(k for k in AgentConfig.model_fields if k != "version")
NESTED = ("params", "budget", "rate", "memory", "escalation", "notify")
CHAT_ONLY = ("language", "memory", "allowed_tools", "escalation")
NO_MODEL = ("notify",)  # what agents without an AI model have of these settings
TASKS = {"code": "Code changes", "generate": "Structured generation"}
USAGE_DAYS = 30
# the most output tokens a call of the agent asks for (a lower cap cuts those answers off: the page warns)
CALL_TOKENS = {"supervisor": {"chat": 16_000}, "patcher": {"code": 64_000, "generate": 32_000},
               "custom": {"chat": 16_000}, "tool": {"generate": 8_000}}
LABELS = {  # how validation errors name a setting (the page focuses the field)
    "params.effort": "Effort", "params.temperature": "Temperature", "params.max_output_tokens": "Max output tokens",
    "params.max_tool_rounds": "Max tool rounds", "extra_instructions": "Additional instructions",
    "instructions_mode": "Instructions", "language": "Language", "allowed_tools": "Allowed tools",
    "budget.daily_tokens": "Daily tokens", "budget.daily_cost_usd": "Daily cost",
    "budget.monthly_cost_usd": "Monthly cost", "budget.hard_stop": "Hard stop",
    "rate.calls_per_minute": "Calls per minute", "rate.runs_per_hour": "Runs per hour",
    "memory.mode": "Memory", "memory.max_turns": "Max turns", "memory.retention_days": "Retention days",
    "memory": "Memory", "escalation": "Escalation", "escalation.tool": "Escalate tool",
    "escalation.rules": "Escalation rules", "escalation.failed_runs": "Failed runs before pausing",
    "escalation.pause_schedule": "Pause the schedule", "escalation.max_per_day": "Escalations per day",
    "notify": "Notifications", "notify.events": "Notification events", "notify.targets": "Notification targets",
    "notify.toolbus": "Tool bus",
}


class Conflict(Exception):
    """The agent's settings changed since the version the caller read."""

    def __init__(self, view: dict[str, Any]):
        super().__init__("Someone else changed these settings")
        self.view = view


@dataclass
class Draft:
    """Settings checked like a save but not stored (a save in progress, or the playground's draft)."""

    choice: LlmChoice
    config: AgentConfig
    instructions: str | None  # core: the replacement text (replace mode); custom: its instructions
    definition: dict[str, Any] = field(default_factory=dict)  # custom agents: changed definition fields


def uses_model(agent: "BaseAgent") -> bool:
    return bool(agent.uses_llm or agent.kind == "custom")


def chats(agent: "BaseAgent") -> bool:
    """Chat agents: the Hub Supervisor and custom agents (reply language, memory, allowed tools)."""
    return agent.id == "supervisor" or agent.kind == "custom"


def per_task(agent: "BaseAgent") -> list[str]:
    """The purposes an agent may choose a model for separately (agents with several: the Patch Agent)."""
    purposes = list(getattr(agent, "purposes", ()))
    return [p for p in purposes if p in TASKS] if len(purposes) > 1 else []


def call_tokens(agent: "BaseAgent") -> dict[str, int]:
    key = agent.id if agent.id in CALL_TOKENS else "custom" if agent.kind == "custom" else \
        "tool" if agent.id.startswith("tool:") else ""
    return dict(CALL_TOKENS.get(key, {}))


def tabs(agent: "BaseAgent") -> list[str]:
    """The settings page's tabs for this agent (spec 6.3): "escalation" is the escalate tool and notifications for chat
    agents, notifications only for the others."""
    if not uses_model(agent):
        return ["overview", "escalation", "history"]
    return ["overview", "model", "behaviour", "tools", "limits", "escalation", "playground", "history"]


def usage(hub: "Hub", agent_id: str, days: int = USAGE_DAYS) -> dict[str, Any]:
    """The agent's model calls per UTC day (oldest first) and today's totals, from the daily aggregates (counts and
    estimated cost only)."""
    now = time.time()
    rows = []
    for n in range(days - 1, -1, -1):
        day = day_of(now - n * 86400)
        found = hub.store.list_prefix(DAILY, f"{day}|{agent_id}|")
        rows.append({"day": day, "calls": sum(int(d.get("calls") or 0) for d in found),
                     "errors": sum(int(d.get("errors") or 0) for d in found),
                     "stopped": sum(int(d.get("stopped") or 0) for d in found),
                     "input_tokens": sum(int(d.get("input_tokens") or 0) + int(d.get("cached_input_tokens") or 0)
                                         + int(d.get("cache_write_tokens") or 0) for d in found),
                     "output_tokens": sum(int(d.get("output_tokens") or 0) for d in found),
                     "cost_usd": round(sum(float(d.get("cost_usd") or 0) for d in found), 6)})
    return {"days": rows, "today": rows[-1]}


def memory_note(config: AgentConfig, restarted: bool) -> dict[str, Any]:
    """What a chat reply tells the person about the agent's memory (the chat panel shows it)."""
    m = config.memory
    return {"mode": m.mode, "retention_days": m.retention_days if m.mode == "persisted" else None,
            "max_turns": m.max_turns, "restarted": restarted}


def instructions_of(hub: "Hub", agent: "BaseAgent") -> str:
    """The stored instruction text: a custom agent's instructions, a core agent's replacement text."""
    defn = teams.get_def(hub, agent.id)
    if defn is not None:
        return defn.instructions
    return str((hub.store.get("agents", agent.id) or {}).get("instructions") or "")


def settings_of(hub: "Hub", agent: "BaseAgent") -> dict[str, Any]:
    """The unified settings document of the page (and of the history): {llm, config, instructions, + the definition
    fields of a custom agent}."""
    choice, config = resolution.own_settings(hub.llm, agent.id)
    out: dict[str, Any] = {"llm": choice.model_dump(), "config": config.model_dump(mode="json", exclude={"version"}),
                           "instructions": instructions_of(hub, agent)}
    defn = teams.get_def(hub, agent.id)
    if defn is not None:
        out.update({k: getattr(defn, k) for k in CUSTOM_FIELDS})
    return out


def tools_catalog(hub: "Hub", agent: "BaseAgent", config: AgentConfig) -> list[dict[str, Any]]:
    """Every toolkit tool with its permission, whether the agent's permissions grant it and whether it is allowed."""
    granted = set(agent.permissions)
    allowed = None if config.allowed_tools is None else set(config.allowed_tools)
    return [{"name": t.name, "permission": t.permission, "description": t.description,
             "granted": t.permission in granted, "allowed": t.permission in granted and (allowed is None or t.name in allowed)}
            for t in toolkit.TOOLS.values()]


def allowed_definitions(agent: "BaseAgent", permissions: frozenset[str] | set[str],
                        config: AgentConfig) -> tuple[list[dict[str, Any]], set[str]]:
    """The tool definitions a chat agent's model is offered, and their names (calls to other tools are refused)."""
    names = {t.name for t in toolkit.available(permissions)}
    if config.allowed_tools is not None:
        names &= set(config.allowed_tools)
    if not config.escalation.tool:  # switched off on the Escalation tab
        names.discard("escalate")
    return [t.definition() for t in toolkit.available(permissions) if t.name in names], names


def check_allowed(agent: "BaseAgent", name: str, permissions: frozenset[str] | set[str], allowed: set[str]) -> None:
    """A tool call the model made: refused when the agent's permissions grant the tool but an administrator took it out
    of the allowed tools (unknown tools and missing permissions are refused by toolkit.execute)."""
    spec = toolkit.TOOLS.get(name)
    if spec is not None and spec.permission in permissions and name not in allowed:
        raise PermissionError(f"{name} is not among the tools an administrator allows {agent.name}")


def model_caps(hub: "Hub", agent: "BaseAgent", purposes: list[str]) -> dict[str, Any]:
    """Per purpose: the model the agent runs on now and what it supports (the Model tab's effort and temperature)."""
    out = {}
    for purpose in purposes:
        res = hub.llm.resolve(agent.id, purpose)
        caps = hub.llm.caps(res.provider, res.model) if res.ready else None
        out[purpose] = {"provider": res.provider, "model": res.model, "kind": res.provider_kind,
                        "caps": caps.model_dump(mode="json") if caps else None,
                        "priced": None if not res.ready else (price_for(hub, res.provider, res.model) is not None
                                                              or res.location == "self_hosted")}
    return out


def history(hub: "Hub", agent_id: str) -> list[dict[str, Any]]:
    """The kept versions, newest first: {version, actor, at, changed, restored_from}."""
    docs = hub.store.list_prefix(HISTORY, f"{agent_id}|")
    return [{k: d.get(k) for k in ("version", "actor", "at", "changed", "restored_from")}
            for d in sorted(docs, key=lambda d: -int(d.get("version") or 0))]


def view(hub: "Hub", agent: "BaseAgent") -> dict[str, Any]:
    """What the agent settings page shows: the stored settings, what it resolves to per purpose and through which
    levels, its budgets against today's spending, the tools it may use, its usage and history."""
    choice, config = resolution.own_settings(hub.llm, agent.id)
    model_using = uses_model(agent)
    purposes = list(getattr(agent, "purposes", ())) if model_using else []
    team = resolution.team_of(hub.llm, agent.id)
    sel = resolution.selection(hub.llm)
    team_default = sel.teams.get(team) if team else None
    chat = chats(agent)
    return {
        "agent_id": agent.id, "name": agent.name, "kind": agent.kind, "role": agent.role, "title": agent.title,
        "uses_model": model_using, "chats": chat, "purposes": purposes, "per_task": per_task(agent),
        "version": config.version, "tabs": tabs(agent),
        "settings": settings_of(hub, agent),
        "builtin_instructions": agent.default_instructions if agent.kind != "custom" else "",
        "team": team, "team_name": teams.team_name(hub, team) if team else None,
        "team_default": team_default.model_dump() if team_default else None,
        "effective": hub.llm.block(agent),
        "chain": {p: hub.llm.chain(agent.id, p) for p in purposes},
        # what "inherit" means now: without the agent's own choice (per purpose), and without a per-task choice
        "inherited": {p: resolution.inherited(hub.llm, agent.id, p).view() for p in purposes},
        "inherited_task": {p: resolution.inherited(hub.llm, agent.id, p, keep_agent=True).view()
                           for p in per_task(agent)},
        "models": model_caps(hub, agent, purposes),
        "call_tokens": call_tokens(agent),
        "language": {"suite": sel.language, "effective": prompting.reply_language(hub.llm, config) if chat else None},
        "tools_catalog": tools_catalog(hub, agent, config) if chat else [],
        "permissions_catalog": [{"id": k, "description": v} for k, v in teams.PERMISSION_INFO.items()]
        if agent.kind == "custom" else [],
        "effective_permissions": list(agent.permissions),
        "budget_state": hub.llm.meter.state(agent.id, config.budget) if model_using else None,
        "suite_budget": hub.llm.meter.suite_budget(),
        "memory": {"sessions": hub.llm.memory.count(agent.id), "stored": len(hub.llm.memory.stored(agent.id))}
        if chat else None,
        "usage": usage(hub, agent.id) if model_using else None,
        "history_versions": len(hub.store.ids_prefix(HISTORY, f"{agent.id}|")),
        **escalation_view(hub, agent, config),
    }


def escalation_view(hub: "Hub", agent: "BaseAgent", config: AgentConfig) -> dict[str, Any]:
    """The Escalation tab: what the agent escalated, its schedule after failed runs, its notification events and
    targets (names), and the integrated tools that receive agent events (names only)."""
    defn = teams.get_def(hub, agent.id)
    mine = notify.escalations(hub, agent.id) if chats(agent) else []
    return {
        "escalation": {"pending": sum(1 for a in mine if a.status == "pending"), "today": notify.today(hub, agent.id),
                       "limit": config.escalation.max_per_day, "answers_waiting": len(notify.inbox(hub, agent.id))}
        if chats(agent) else None,
        "schedule": {"paused": defn.schedule_paused, "failures": defn.failures,
                     "has_schedule": bool(defn.schedule_minutes and defn.task.strip())} if defn is not None else None,
        "notify_events": [{"id": e, "label": notify.EVENTS[e]} for e in notify.events_for(agent)],
        "notify_targets": notify.target_labels(hub, config.notify.targets),
        "target_roles": [{"id": k, "label": v} for k, v in notify.ROLE_TARGETS.items()],
        "toolbus_listeners": notify.listeners(hub),
    }


# -- validation ---------------------------------------------------------------------------------


def _check(hub: "Hub", c: LlmChoice, where: str) -> LlmChoice:
    provider, model = c.provider.strip(), c.model.strip()
    if not provider and model:
        raise ValueError(f"{where}: a model needs a provider")
    if provider == "rules" and model:
        raise ValueError(f"{where}: rules have no model")
    if provider == "auto":
        raise ValueError(f"{where}: 'auto' is only for the suite default - leave the provider empty to inherit it")
    if provider not in ("", "rules") and hub.llm.record(provider) is None:
        raise ValueError(f"{where}: unknown provider '{provider}'")
    return LlmChoice(provider=provider, model=model)


def _readable(exc: ValidationError, prefix: str = "") -> ValueError:
    first = exc.errors()[0]
    parts = [str(x) for x in first.get("loc", ())]
    loc = ".".join(parts)
    named = next((".".join(parts[:n]) for n in range(len(parts), 0, -1) if ".".join(parts[:n]) in LABELS), None)
    name = LABELS[named] if named else (prefix + loc if loc else "Settings")  # "escalation.rules.0" -> its list
    return ValueError(f"{name}: {str(first.get('msg', 'invalid')).removeprefix('Value error, ')}")


def _merge_config(current: AgentConfig, given: dict[str, Any], agent: "BaseAgent") -> AgentConfig:
    """`given` (a partial config) over `current`: nested groups key by key, per-task models per task (None unsets)."""
    unknown = sorted(k for k in given if k not in CONFIG_KEYS)
    if unknown:
        raise ValueError(f"Unknown setting: config.{unknown[0]}")
    data = current.model_dump(mode="json")
    for key, value in given.items():
        if key == "purposes":
            continue
        if key in NESTED and isinstance(value, dict):
            extra = sorted(k for k in value if k not in data[key])
            if extra:
                raise ValueError(f"Unknown setting: config.{key}.{extra[0]}")
            data[key] = {**data[key], **value}
        else:
            data[key] = value
    try:
        merged = AgentConfig.model_validate(data)
    except ValidationError as exc:
        raise _readable(exc) from exc
    tasks = per_task(agent)
    for purpose, value in (given.get("purposes") or {}).items():
        if purpose not in tasks:
            raise ValueError(f"{agent.name} has no separate model for '{purpose}'"
                             + (f" (only for {', '.join(tasks)})" if tasks else ""))
    return merged


def draft(hub: "Hub", agent: "BaseAgent", body: dict[str, Any]) -> Draft:
    """The agent's settings with `body` (a partial AgentSettings) applied - validated, not stored. ValueError names
    the first problem."""
    custom = agent.kind == "custom"
    allowed = {"llm", "config", "version", "instructions", *(CUSTOM_FIELDS if custom else ())}
    unknown = sorted(k for k in body if k not in allowed)
    if unknown:
        if not custom and unknown[0] in CUSTOM_FIELDS:
            raise ValueError(f"{agent.name} is a core agent: its {unknown[0]} cannot be changed")
        raise ValueError(f"Unknown setting: {unknown[0]}")
    config_in = dict(body.get("config") or {})
    choice, config = resolution.own_settings(hub.llm, agent.id)
    if not uses_model(agent) and (body.get("llm") is not None or body.get("instructions") is not None
                                  or any(k not in NO_MODEL for k in config_in)):
        raise ValueError(f"{agent.name} works without an AI model: there is no model to choose or instruct "
                         "(only its notifications can be set)")
    new_choice = _check(hub, LlmChoice.model_validate(body["llm"]), "Model") if body.get("llm") is not None else choice
    new_config = _merge_config(config, config_in, agent)
    new_config.purposes = dict(config.purposes)
    for purpose, value in (config_in.get("purposes") or {}).items():
        chosen = _check(hub, LlmChoice.model_validate(value), TASKS[purpose]) if value is not None else LlmChoice()
        if chosen.provider:
            new_config.purposes[purpose] = chosen  # type: ignore[index]
        else:
            new_config.purposes.pop(purpose, None)  # type: ignore[call-overload]
    if not chats(agent):
        for key in CHAT_ONLY:
            if key in config_in and getattr(new_config, key) != getattr(AgentConfig(), key):
                raise ValueError(f"{LABELS[key]}: {agent.name} does not chat - only chat agents have this setting")
    if custom and ("extra_instructions" in config_in and new_config.extra_instructions.strip()):
        raise ValueError("Additional instructions: a custom agent's instructions are its own - edit them instead")
    if custom and new_config.instructions_mode != "append":
        raise ValueError("Instructions: a custom agent's instructions are its own - there is nothing to replace")
    new_config.language = prompting.check_language(new_config.language)
    if "escalation" in config_in:
        rules = [" ".join(str(r).split()) for r in new_config.escalation.rules]
        new_config.escalation.rules = list(dict.fromkeys(r for r in rules if r))
    if "notify" in config_in:
        new_config.notify.events = [e for e in notify.EVENTS if e in set(new_config.notify.events)]  # type: ignore[misc]
        new_config.notify.targets = notify.check_targets(hub, new_config.notify.targets)
    if new_config.allowed_tools is not None:
        names = list(dict.fromkeys(str(t).strip() for t in new_config.allowed_tools))
        unknown_tools = [t for t in names if t not in toolkit.TOOLS]
        if unknown_tools:
            raise ValueError(f"Allowed tools: unknown tool '{unknown_tools[0]}'")
        new_config.allowed_tools = names
    if new_config.local_only:
        for c in (new_choice, *new_config.purposes.values()):
            if c.provider not in ("", "rules") and hub.llm.location(c.provider) == "third_party":
                raise ValueError(f"{agent.name} is local-only: {hub.llm.label(c.provider)} is a cloud provider "
                                 "- choose a self-hosted provider, or inherit")
    if new_config.params.temperature is not None:
        for purpose in getattr(agent, "purposes", ()):
            res = resolution.resolve(hub.llm, agent.id, purpose, (new_choice, new_config))
            if res.ready and hub.llm.caps(res.provider, res.model).temperature is False:
                raise ValueError(f"Temperature: {res.provider_label} {res.model} sets its own sampling and refuses a "
                                 "temperature - use effort instead")
    instructions = body.get("instructions")
    if instructions is not None:
        instructions = str(instructions)
        if len(instructions) > 20_000:
            raise ValueError("Instructions: at most 20 000 characters")
    definition: dict[str, Any] = {}
    if custom:
        definition = {k: body[k] for k in CUSTOM_FIELDS if k in body and body[k] is not None}
    return Draft(new_choice, new_config, instructions, definition)


# -- saving -----------------------------------------------------------------------------------


def choice_text(c: LlmChoice | None) -> str:
    if c is None or not c.provider:
        return "inherit"
    if c.provider == "rules":
        return "rules"
    return f"{c.provider}/{c.model}" if c.model else f"{c.provider} (default model)"


def text_summary(text: str) -> str:
    """Instructions in the activity log: length and hash, never the text."""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    return f"{len(text):,}".replace(",", " ") + f" chars, sha256 {digest}"


def _value(v: Any) -> str:
    return "none" if v is None or v == "" else "on" if v is True else "off" if v is False else str(v)


def describe(agent: "BaseAgent", before: dict[str, Any], after: dict[str, Any]) -> tuple[list[str], bool]:
    """What changed between two settings documents (settings_of), as activity-log words, and whether a protection
    was loosened (local only off, more tools or permissions, the hard stop off, a budget or limit raised)."""
    lines: list[str] = []
    loosened = False
    b_llm, a_llm = LlmChoice.model_validate(before["llm"]), LlmChoice.model_validate(after["llm"])
    if b_llm != a_llm:
        lines.append(f"model {choice_text(b_llm)} -> {choice_text(a_llm)}")
    bc, ac = before["config"], after["config"]
    for purpose in TASKS:
        old, new = (bc.get("purposes") or {}).get(purpose), (ac.get("purposes") or {}).get(purpose)
        if old != new:
            lines.append(f"{TASKS[purpose].lower()} model {choice_text(LlmChoice.model_validate(old) if old else None)} "
                         f"-> {choice_text(LlmChoice.model_validate(new) if new else None)}")
    if bc.get("local_only") != ac.get("local_only"):
        lines.append(f"local only {'on' if ac.get('local_only') else 'off'}")
        loosened = loosened or not ac.get("local_only")
    for group, key, words in (("params", "effort", "effort"), ("params", "temperature", "temperature"),
                              ("params", "max_output_tokens", "max output tokens"),
                              ("params", "max_tool_rounds", "max tool rounds"),
                              ("budget", "daily_tokens", "budget daily_tokens"),
                              ("budget", "daily_cost_usd", "budget daily_cost_usd"),
                              ("budget", "monthly_cost_usd", "budget monthly_cost_usd"),
                              ("rate", "calls_per_minute", "calls per minute"), ("rate", "runs_per_hour", "runs per hour"),
                              ("memory", "max_turns", "memory max turns"), ("memory", "retention_days", "retention days")):
        old, new = (bc.get(group) or {}).get(key), (ac.get(group) or {}).get(key)
        if old != new:
            lines.append(f"{words} {_value(old)} -> {_value(new)}")
            if group in ("budget", "rate") and old is not None and (new is None or new > old):
                loosened = True
    if (bc.get("budget") or {}).get("hard_stop") != (ac.get("budget") or {}).get("hard_stop"):
        hard = (ac.get("budget") or {}).get("hard_stop")
        lines.append(f"hard stop {'on' if hard else 'off'}")
        loosened = loosened or not hard
    if (bc.get("memory") or {}).get("mode") != (ac.get("memory") or {}).get("mode"):
        lines.append(f"memory {(bc.get('memory') or {}).get('mode')} -> {(ac.get('memory') or {}).get('mode')}")
    if bc.get("language") != ac.get("language"):
        lines.append(f"language {bc.get('language') or 'suite default'} -> {ac.get('language') or 'suite default'}")
    if bc.get("instructions_mode") != ac.get("instructions_mode"):
        lines.append(f"instructions {bc.get('instructions_mode')} -> {ac.get('instructions_mode')}")
    if bc.get("extra_instructions") != ac.get("extra_instructions"):
        lines.append(f"additional instructions changed ({text_summary(ac.get('extra_instructions') or '')})")
    if before.get("instructions") != after.get("instructions"):
        lines.append(f"instructions changed ({text_summary(after.get('instructions') or '')})")
    be, ae = bc.get("escalation") or {}, ac.get("escalation") or {}
    if be.get("tool") != ae.get("tool"):
        lines.append(f"escalate tool {'on' if ae.get('tool') else 'off'}")
    if be.get("rules") != ae.get("rules"):
        lines.append(f"escalation rules: {len(ae.get('rules') or [])}")
    for key, words in (("failed_runs", "pause after failed runs"), ("max_per_day", "escalations per day")):
        old, new = be.get(key), ae.get(key)
        if old != new:
            lines.append(f"{words} {_value(old)} -> {_value(new)}")
            # more failures before a pause (0 = never) or more escalations a day: a limit raised
            loosened = loosened or (old not in (None, 0) and (new == 0 or (new or 0) > old))
    if be.get("pause_schedule") != ae.get("pause_schedule"):
        lines.append(f"pause the schedule after failed runs {'on' if ae.get('pause_schedule') else 'off'}")
        loosened = loosened or not ae.get("pause_schedule")
    bn, an = bc.get("notify") or {}, ac.get("notify") or {}
    if bn.get("events") != an.get("events"):
        lines.append(f"notifications: {', '.join(an.get('events') or []) or 'none'}")
    if bn.get("targets") != an.get("targets"):
        lines.append(f"notification targets: {', '.join(an.get('targets') or []) or 'none'}")
    if bn.get("toolbus") != an.get("toolbus"):
        lines.append(f"tool bus notifications {'on' if an.get('toolbus') else 'off'}")
        loosened = loosened or bool(an.get("toolbus"))  # summaries now go to integrated tools
    old_tools, new_tools = bc.get("allowed_tools"), ac.get("allowed_tools")
    if old_tools != new_tools:
        if new_tools is None:
            lines.append("allowed tools: all its permissions allow")
        else:
            lines.append(f"allowed tools: {len(new_tools)} tool(s)"
                         + (f" (added {', '.join(sorted(set(new_tools) - set(old_tools)))})"
                            if old_tools is not None and set(new_tools) - set(old_tools) else ""))
        loosened = loosened or (old_tools is not None and (new_tools is None or bool(set(new_tools) - set(old_tools))))
    for key in CUSTOM_FIELDS:
        if key not in before or before.get(key) == after.get(key):
            continue
        old, new = before.get(key), after.get(key)
        if key == "permissions":
            added, removed = sorted(set(new) - set(old)), sorted(set(old) - set(new))
            lines.append("permissions" + (f" +{', +'.join(added)}" if added else "") + (f" -{', -'.join(removed)}" if removed else ""))
            loosened = loosened or bool(added)
        elif key in ("description", "task"):
            lines.append(f"{key} changed")
        elif key == "schedule_minutes":
            lines.append(f"schedule {old or 'none'} -> {new or 'none'} minutes")
        elif key == "enabled":
            lines.append("enabled" if new else "disabled")
        else:
            lines.append(f"{key} {old or 'none'} -> {new or 'none'}")
    return lines, loosened


def save(hub: "Hub", agent: "BaseAgent", body: dict[str, Any], actor: str, *,
         restored_from: int | None = None) -> tuple[dict[str, Any], list[str], bool]:
    """Apply a partial change (a partial AgentSettings with the `version` read). Returns (the new view, what changed
    as words, whether a protection was loosened). Raises ValueError (invalid) or Conflict (a stale version)."""
    version = body.get("version")
    _, config = resolution.own_settings(hub.llm, agent.id)
    if version is not None and int(version) != config.version:
        raise Conflict(view(hub, agent))
    new = draft(hub, agent, {k: v for k, v in body.items() if k != "version"})
    before = settings_of(hub, agent)
    if agent.kind != "custom" and new.config.instructions_mode == "append" and new.instructions is None \
            and (body.get("config") or {}).get("instructions_mode") == "append":
        new.instructions = ""  # back to the built-in instructions: the replacement text goes (the history keeps it)
    after = {"llm": new.choice.model_dump(), "config": new.config.model_dump(mode="json", exclude={"version"}),
             "instructions": before["instructions"] if new.instructions is None else new.instructions}
    if agent.kind == "custom":
        after.update({k: new.definition.get(k, before[k]) for k in CUSTOM_FIELDS})
    lines, loosened = describe(agent, before, after)
    if not lines:
        return view(hub, agent), [], False
    if restored_from is not None:
        lines.insert(0, f"restored version {restored_from}")
    if not hub.store.ids_prefix(HISTORY, f"{agent.id}|"):  # the first change keeps the settings it started from
        _remember(hub, agent.id, config.version, before, [], "", None)
    new.config.version = config.version + 1
    _store(hub, agent, new, actor)
    old_mode, new_mode = before["config"]["memory"]["mode"], new.config.memory.mode
    if old_mode != new_mode:
        if old_mode == "persisted":
            dropped = hub.llm.memory.drop_stored(agent.id)
            if dropped:
                lines.append(f"{dropped} stored conversation(s) deleted")
        if new_mode == "off":
            hub.llm.memory.forget_agent(agent.id, keep_stored=True)
    _remember(hub, agent.id, new.config.version, settings_of(hub, agent), _keys(before, after), actor, restored_from)
    published(hub, agent.id, new.config.version)
    return view(hub, agent), lines, loosened


def _keys(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    out = []
    for key in sorted(set(before) | set(after)):
        if key == "config":
            out += [f"config.{k}" for k in CONFIG_KEYS if before["config"].get(k) != after["config"].get(k)]
        elif before.get(key) != after.get(key):
            out.append(key)
    return out


def _remember(hub: "Hub", agent_id: str, version: int, settings: dict[str, Any], changed: list[str], actor: str,
              restored_from: int | None) -> None:
    hub.store.put(HISTORY, {"id": f"{agent_id}|{version:08d}", "agent_id": agent_id, "version": version,
                            "settings": settings, "changed": changed, "actor": actor, "at": time.time(),
                            "restored_from": restored_from})
    ids = hub.store.ids_prefix(HISTORY, f"{agent_id}|")
    if len(ids) > HISTORY_KEEP:
        hub.store.delete_many(HISTORY, ids[:-HISTORY_KEEP])


def restore(hub: "Hub", agent: "BaseAgent", version: int, actor: str,
            expected: int | None = None) -> tuple[dict[str, Any], list[str], bool]:
    """Bring back a kept version's settings as a new version (the team and the reporting line stay as they are).
    KeyError: no such version; ValueError: it no longer validates (e.g. its provider was removed)."""
    doc = hub.store.get(HISTORY, f"{agent.id}|{int(version):08d}")
    if doc is None:
        raise KeyError(version)
    kept = doc["settings"]
    body: dict[str, Any] = {"version": expected}
    if uses_model(agent):
        config = dict(kept.get("config") or {})
        config["purposes"] = {task: (config.get("purposes") or {}).get(task) for task in per_task(agent)}
        body.update(llm=kept.get("llm"), config=config, instructions=kept.get("instructions") or "")
    elif (kept.get("config") or {}).get("notify") is not None:  # agents without a model: their notifications
        body["config"] = {"notify": kept["config"]["notify"]}
    if agent.kind == "custom":
        body.update({k: kept[k] for k in RESTORED_FIELDS if k in kept})
    try:
        return save(hub, agent, body, actor, restored_from=int(version))
    except ValueError as exc:
        raise ValueError(f"Version {version} cannot be restored: {exc}") from exc


def _store(hub: "Hub", agent: "BaseAgent", new: Draft, actor: str) -> None:
    defn = teams.get_def(hub, agent.id)
    if defn is not None:
        changes: dict[str, Any] = {**new.definition, "provider": new.choice.provider, "model": new.choice.model,
                                   "config": new.config.model_dump(mode="json")}
        if new.instructions is not None:
            changes["instructions"] = new.instructions
        teams.update(hub, agent.id, changes, actor, log=False)  # validates team, parent, depth and size
        return
    doc = hub.store.get("agents", agent.id) or {"id": agent.id, "paused": agent.paused}
    kept = {k: v for k, v in (doc.get("config") or {}).items() if k not in AgentConfig.model_fields}
    instructions = doc.get("instructions") if new.instructions is None else (new.instructions.strip() or None)
    hub.store.put("agents", {**doc, "id": agent.id, "provider": new.choice.provider, "model": new.choice.model or None,
                             "instructions": instructions, "config": {**kept, **new.config.model_dump(mode="json")}})
    agent.model_override = new.choice.model or None
    agent.instructions_override = instructions
    hub.llm.invalidate()
    hub.bus.publish("agent", agent.record())


def published(hub: "Hub", agent_id: str, version: int | None = None) -> None:
    """Tell configuration views that an agent's model choice or settings changed (no values, no secrets)."""
    if version is None:
        version = resolution.own_settings(hub.llm, agent_id)[1].version
    hub.bus.publish("agent_settings", {"id": agent_id, "version": version})


def bump(hub: "Hub", agent_id: str) -> None:
    """Settings changed through the older routes (PATCH /api/agents/{id}): a new settings version, kept in the
    history, so a view that read the old one cannot overwrite it unseen."""
    agent = hub.agents.get(agent_id)
    defn = teams.get_def(hub, agent_id)
    if defn is not None:
        config = defn.config.model_copy(update={"version": defn.config.version + 1})
        teams.save_def(hub, defn.model_copy(update={"config": config}))
        version = config.version
    else:
        doc = hub.store.get("agents", agent_id)
        if doc is None:
            return
        config_doc = dict(doc.get("config") or {})
        version = int(config_doc.get("version") or 0) + 1
        hub.store.put("agents", {**doc, "config": {**config_doc, "version": version}})
    if agent is not None:
        _remember(hub, agent_id, version, settings_of(hub, agent), ["(an older route)"], "", None)
    published(hub, agent_id, version)
