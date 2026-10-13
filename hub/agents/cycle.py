"""A maintenance cycle: the Hub Supervisor plans work, dispatches it, and shows each handoff.

The plan comes from the selected model when that model returns usable JSON. The work itself always runs on the
real agents (GRC, assets, a tool supervisor, the Patch Agent). A model that is down, or that answers with
something other than the plan, does not skip the work: the same items run from the suite's own state.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .. import llm_providers
from . import teams

MAX_ITEMS = 6
REPAIR_WORDS = ("fix", "bug", "patch", "broken", "repair", "error", "fail")
ASSEMBLE_WORDS = ("assemble", "assble", "team", "agent")
BROAD_WORDS = ("plan", "maintenance", "cycle", "compliance", "risk", "asset", "installed", "software")
PLAN_SYSTEM = (
    "You are the Hub Supervisor planning one maintenance cycle. "
    "Reply with JSON only, no markdown: {\"items\":[{\"id\":\"...\",\"priority\":1,\"goal\":\"...\"}]}. "
    "Use only ids from the work list. priority is 1, 2 or 3. "
    "Write a new goal for every id: one concrete sentence based on the facts. "
    "Do not invent tools, controls, risks or agents."
)


def wants(text: str) -> bool:
    """A request the supervisor should run as a cycle instead of answering alone."""
    low = text.lower()
    return any(word in low for word in (*REPAIR_WORDS, *ASSEMBLE_WORDS, *BROAD_WORDS))


def _asks_repair(low: str) -> bool:
    return any(word in low for word in REPAIR_WORDS)


def _asks_assemble(low: str) -> bool:
    return any(word in low for word in ASSEMBLE_WORDS) or "installed" in low or "software" in low


def _asks_broad(low: str) -> bool:
    return any(word in low for word in BROAD_WORDS) or _asks_assemble(low)


def _down(tool: Any) -> bool:
    """A tool the Patch Agent should work on: it is in error, needs a patch, or its health check is failing.

    A healthy tool that merely has a gap (for example single sign-on not wired yet) is not restarted and not
    patched from a broad "fix what needs it" request. Naming that tool still sends it.
    """
    return bool(tool.status in ("needs_patch", "error") or tool.error or (tool.health or {}).get("ok") is False)


def _named(tools: list[Any], low: str) -> list[Any]:
    return [tool for tool in tools if tool.id in low or tool.name.lower() in low]


def _agent_key(who: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", who.lower()).strip("_") or "agent"


def _priority(value: Any) -> int:
    if isinstance(value, str) and value.lower().startswith("p"):
        value = value[1:]
    try:
        number = int(value)
    except (TypeError, ValueError):
        return 2
    return min(3, max(1, number))


def _parse_plan(text: str) -> list[dict[str, Any]] | None:
    raw = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*|\[.*)", raw, re.DOTALL)
    if fenced:
        raw = fenced.group(1)
    else:
        object_at = raw.find("{")
        array_at = raw.find("[")
        if array_at >= 0 and (object_at < 0 or array_at < object_at):
            raw = raw[array_at:]
        elif object_at >= 0:
            raw = raw[object_at:]
    try:
        data, _ = json.JSONDecoder().raw_decode(raw.lstrip())
    except (json.JSONDecodeError, ValueError):
        return None
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return None
    parsed = []
    for item in items:
        if not isinstance(item, dict) or not str(item.get("id") or "").strip():
            continue
        goal = " ".join(str(item.get("goal") or "").split())[:400]
        parsed.append({"id": str(item["id"]).strip(), "priority": _priority(item.get("priority")), "goal": goal})
    return parsed or None


def _catalog(agent: Any, text: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """The real work this request can dispatch, already capped, plus how much was left out."""
    hub = agent.hub
    low = text.lower()
    tools = hub.tools()
    named = _named(tools, low)
    broken = [tool for tool in tools if _down(tool)]
    broken.sort(key=lambda tool: (tool.status not in ("needs_patch", "error"), tool.name.lower()))
    if named and _asks_repair(low):
        repair = [tool for tool in named if _down(tool)] or [tool for tool in named]
    elif _asks_repair(low):
        repair = broken
    else:
        repair = []

    items: list[dict[str, Any]] = []
    slots = MAX_ITEMS
    if _asks_broad(low):
        items.append({
            "id": "grc", "kind": "grc", "agent_id": "module:grc", "who": "GRC Supervisor", "priority": 1,
            "goal": "Evaluate the controls and report the failing ones and the open risks.",
        })
        items.append({
            "id": "assets", "kind": "assets", "agent_id": "module:assets", "who": "Asset Supervisor", "priority": 2,
            "goal": "Summarize the assets, including the ones with no owner.",
        })
        slots -= 2

    left = {"repairs": 0, "teams": 0}
    for tool in repair:
        if slots < 1:
            left["repairs"] += 1
            continue
        if hub.agents.get(f"tool:{tool.id}") is not None and slots >= 2:
            items.append({
                "id": f"health:{tool.id}", "kind": "health", "agent_id": f"tool:{tool.id}", "tool_id": tool.id,
                "who": f"{tool.name} Supervisor", "priority": 1,
                "goal": f"Check {tool.name} and report whether it is up.",
            })
            slots -= 1
        elif slots < 1:
            left["repairs"] += 1
            continue
        items.append({
            "id": f"repair:{tool.id}", "kind": "repair", "agent_id": "patcher", "tool_id": tool.id,
            "who": "Patch Agent", "priority": 1,
            "goal": f"Bring {tool.name} up and clear its error, or file a patch if it cannot be started.",
        })
        slots -= 1

    if _asks_assemble(low) and slots > 0:
        missing = [tool for tool in tools if not teams.has_team_or_proposal(hub, tool.id)]
        ordered = [tool for tool in named if tool in missing]
        ordered += [tool for tool in sorted(missing, key=lambda tool: tool.name.lower()) if tool not in ordered]
        for tool in ordered:
            if slots < 1:
                left["teams"] += 1
                continue
            if hub.agents.get(f"tool:{tool.id}") is None:
                left["teams"] += 1
                continue
            items.append({
                "id": f"team:{tool.id}", "kind": "team", "agent_id": f"tool:{tool.id}", "tool_id": tool.id,
                "who": f"{tool.name} Supervisor", "priority": 2,
                "goal": f"Assemble the template AI team for {tool.name}.",
            })
            slots -= 1
    for index, item in enumerate(items):
        item["_order"] = index
    return items, left


def _facts(agent: Any, text: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    hub = agent.hub
    listed = []
    for item in items:
        tool = hub.get_tool(item["tool_id"]) if item.get("tool_id") else None
        if tool is None:
            continue
        listed.append({
            "id": tool.id, "name": tool.name, "status": tool.status, "error": tool.error or "",
            "health_ok": (tool.health or {}).get("ok"),
            "has_team": teams.has_team_or_proposal(hub, tool.id),
        })
    return {
        "request": text[:1000],
        "work": [{"id": item["id"], "who": item["who"], "kind": item["kind"]} for item in items],
        "tools": listed[:12],
        "tools_total": len(hub.tools()),
    }


async def _complete(agent: Any, provider: Any, model: str, prompt: str) -> str:
    history = [{"role": "user", "content": prompt}]

    async def unused(name: str, args: dict[str, Any]) -> dict[str, Any]:
        return {}

    return await llm_providers.chat_loop(
        agent.hub, provider, model=model, system=PLAN_SYSTEM, history=history, tools=[], execute=unused)


async def _model_plan(agent: Any, provider: Any, items: list[dict[str, Any]], text: str) -> tuple[str | None, str | None]:
    """Apply the model's priorities and goals. Returns the model that answered, or an error note."""
    preferred = agent.hub.prefs.get("model") if teams.saved_provider(agent.hub) == provider.id else ""
    models = [str(preferred or provider.default_model or "").strip()]
    if provider.default_model and provider.default_model not in models:
        models.append(provider.default_model)
    models = [model for model in models if model]
    prompt = json.dumps(_facts(agent, text, items), default=str)[:12000]
    notes: list[str] = []
    for model in models:
        try:
            parsed = _parse_plan(await _complete(agent, provider, model, prompt))
        except llm_providers.ProviderError as exc:
            notes.append(f"{model}: {exc}")
            continue
        if not parsed:
            notes.append(f"{model}: no usable plan")
            continue
        chosen = {item["id"]: item for item in parsed}
        for item in items:
            match = chosen.get(item["id"])
            if match is None:
                continue
            if match["goal"]:
                item["goal"] = match["goal"]
            item["priority"] = match["priority"]
        items.sort(key=lambda item: (item["priority"], item["_order"]))
        return model, None
    detail = "; ".join(notes)[:300] or "no model answered"
    return None, detail


def _shown(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"agent": _agent_key(item["who"]), "goal": item["goal"], "priority": item["priority"]} for item in items]


def _dispatch(items: list[dict[str, Any]]) -> str:
    parts = [f"{item['who']} (P{item['priority']})" for item in items]
    return f"Dispatching {len(items)} work item(s): " + ", ".join(parts) + "."


def _grc_text(evaluated: dict[str, Any], summary: dict[str, Any]) -> str:
    lines = []
    frameworks = summary.get("frameworks") or []
    if frameworks:
        scores = []
        for framework in frameworks:
            score = framework.get("score")
            scores.append(f"{framework.get('name')}: {'n/a' if score is None else str(score) + '%'}")
        lines.append("Frameworks: " + "; ".join(scores) + ".")
    failing = list(summary.get("failing_controls") or [])
    lines.append("Failing or partial controls:")
    lines.extend(f"- {control}" for control in failing[:8])
    if not failing:
        lines.append("- none")
    risks = list(summary.get("top_risks") or [])
    lines.append("Open risks:")
    lines.extend(f"- {risk}" for risk in risks[:5])
    if not risks:
        lines.append("- none")
    changed = evaluated.get("changed") or []
    opened = evaluated.get("risks_opened") or 0
    closed = evaluated.get("risks_closed") or 0
    lines.append(f"Evaluation changed {len(changed)} control(s); {opened} risk(s) opened, {closed} closed.")
    return "\n".join(lines)


def _asset_text(summary: dict[str, Any]) -> str:
    kinds = ", ".join(f"{count} {kind}" for kind, count in (summary.get("by_type") or {}).items()) or "none"
    total = summary.get("total", 0)
    owners = summary.get("without_owner", 0)
    critical = summary.get("critical", 0)
    return f"{total} active assets ({kinds}); {owners} without an owner; {critical} critical."


def _unpatched(agent: Any) -> str:
    notes: list[str] = []
    extra = 0
    for tool in agent.hub.tools():
        if not tool.report:
            continue
        for check in tool.report.checks:
            if check.status == "pass" or check.fix:
                continue
            if len(notes) < 6:
                notes.append(f"{tool.name}: {check.title} ({check.status})")
            else:
                extra += 1
    if not notes:
        return ""
    text = "No patch applies to these checks: " + "; ".join(notes) + "."
    if extra:
        text += f" {extra} more check(s) also have no automatic patch."
    return text


def _remainder(left: dict[str, int], unpatched: str) -> str:
    lines = []
    if left.get("teams"):
        lines.append(f"{left['teams']} more tool(s) still have no AI team. Ask again to assemble the next ones.")
    if left.get("repairs"):
        lines.append(f"{left['repairs']} more tool(s) still need a look. Say `patch <name>` for one of them.")
    if unpatched:
        lines.append(unpatched)
    return "\n\n".join(lines)


async def _bundle(agent: Any, tool: Any, low: str, requester: str, cache: dict[str, Any]) -> tuple[list[dict[str, str]], list[str]]:
    cached = cache.get(tool.id)
    if cached is None:
        cached = await agent._tool_fix(tool, low, requester)
        cache[tool.id] = cached
    return cached


def _report_for(reports: list[dict[str, str]], who: str) -> str:
    matched = [report["text"] for report in reports if report["who"] == who and report.get("text")]
    if matched:
        return "\n\n".join(matched)
    return "No report."


async def _perform(agent: Any, item: dict[str, Any], low: str, requester: str, cache: dict[str, Any]) -> tuple[str, list[str]]:
    kind = item["kind"]
    try:
        if kind in ("health", "repair"):
            tool = agent.hub.get_tool(item["tool_id"])
            if tool is None:
                return f"I don't know a tool called '{item['tool_id']}'.", []
            reports, delegated = await _bundle(agent, tool, low, requester, cache)
            return _report_for(reports, item["who"]), delegated
        if kind == "team":
            result = await agent.ask(item["agent_id"], "team.propose", {"designer": "templates"}, timeout=120)
            detail = str(result.get("detail") or "No team was proposed.")
            created = [str(agent_id) for agent_id in result.get("created") or []]
            if created:
                detail = detail.rstrip(".") + ". Members: " + ", ".join(created) + "."
            return detail, [item["agent_id"]]
        if kind == "grc":
            evaluated = await agent.ask("module:grc", "evaluate", timeout=180)
            summary = await agent.ask("module:grc", "summary", timeout=60)
            return _grc_text(evaluated if isinstance(evaluated, dict) else {}, summary if isinstance(summary, dict) else {}), [item["agent_id"]]
        if kind == "assets":
            summary = await agent.ask("module:assets", "summary", timeout=60)
            return _asset_text(summary if isinstance(summary, dict) else {}), [item["agent_id"]]
    except Exception as exc:
        return f"Could not finish: {exc}", [item["agent_id"]]
    return "No report.", []


def _nothing() -> dict[str, Any]:
    return {
        "reply": "I asked the team. They report back here.\n\nNothing is waiting. "
                 "Say `patch <tool>` to send one tool to its supervisor and the Patch Agent.",
        "mode": "team", "delegated": [], "steps": [],
    }


async def run(agent: Any, text: str, requester: str, provider: Any) -> dict[str, Any]:
    """Plan, dispatch and collect the reports. The reply is the whole transcript; steps are one bubble each."""
    items, left = _catalog(agent, text)
    if not items:
        return _nothing()
    model, problem = await _model_plan(agent, provider, items, text)
    plan = _shown(items)
    opening = "```json\n" + json.dumps(plan, indent=2) + "\n```"
    if problem:
        opening = f"{provider.name} could not draft the plan ({problem}). This plan is from the suite.\n\n" + opening
    steps: list[dict[str, Any]] = [
        {"who": "Hub Supervisor", "text": opening},
        {"who": "Hub Supervisor", "text": _dispatch(items)},
    ]
    delegated: list[str] = []
    seen: set[str] = set()
    cache: dict[str, Any] = {}
    low = text.lower()
    agent.log("info", f"Dispatching {len(items)} work item(s) for a maintenance cycle")
    for item in items:
        report, ids = await _perform(agent, item, low, requester, cache)
        for agent_id in ids:
            if agent_id not in seen:
                seen.add(agent_id)
                delegated.append(agent_id)
        steps.append({"who": "Hub Supervisor", "text": f"Supervisor hands off to {item['who']}", "handoff": True})
        steps.append({"who": item["who"], "text": report})
    tail = _remainder(left, _unpatched(agent))
    if tail:
        steps.append({"who": "Hub Supervisor", "text": tail})
    return {
        "reply": "\n\n".join(step["text"] for step in steps),
        "mode": "local" if model else "team",
        "delegated": delegated,
        "steps": steps,
    }
