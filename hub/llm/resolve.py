"""Which provider and model a call runs on: agent purpose override > agent override > team default > purpose default
> suite default ("auto" = Claude, else OpenAI, else the first local provider with a default model) > fallback chain
> rules. A level whose provider is removed, unavailable, failing (circuit open) or has no model is skipped, and the
reason is kept in `blocked` so every agent record can say where its model comes from and why.

Constraints apply at every level: an agent (or its team) that is local-only skips third-party providers, and the
guardrail allow_cloud_llm off blocks them for everyone (LLM.blocked_reason). The levels are edited through
PATCH /api/llm/selection (selection.py) and PATCH /api/agents/{id}/settings (agent_settings.py)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from ..models import AgentConfig, LlmChoice, LlmSelection

if TYPE_CHECKING:
    from . import LLM

SELECTION_DOC = "llm_selection"
PURPOSE_LABELS = {"chat": "Chat and agent tasks", "code": "Code changes", "generate": "Structured generation"}
AUTO_ORDER = ("anthropic", "openai")  # then local providers with a default model, by name
KIND_LABELS = {"anthropic": "anthropic", "openai": "openai", "openai_compatible": "local"}


class Candidate(BaseModel):
    level: str  # agent_purpose | agent | team | purpose | suite | fallback | rules
    provider: str
    model: str = ""
    auto: bool = False  # expanded from the suite default "auto"
    team: str | None = None  # the team of a team default


class Blocked(BaseModel):
    level: str
    provider: str
    reason: str


class Resolution(BaseModel):
    agent_id: str
    purpose: str
    local_only: bool = False
    local_only_from: str | None = None  # "agent" or "team" (what made it local-only)
    provider: str = "rules"
    provider_label: str = "Rules"
    provider_kind: str = "rules"  # anthropic | openai | local | rules
    model: str = ""
    location: str | None = None
    source: str = "rules"
    source_label: str = "Rules"
    fallback: bool = False
    blocked: list[Blocked] = []
    # later fallback-chain entries the agent may use (none third-party when local-only), tried when the chosen
    # provider fails at call time
    fallbacks: list[Candidate] = []
    intended: Candidate | None = None  # the first level someone set explicitly, even when it is blocked

    @property
    def ready(self) -> bool:
        return self.provider != "rules"

    def view(self) -> dict[str, Any]:
        """The per-purpose entry of an agent record's `llm` block."""
        return {"provider": self.provider, "provider_label": self.provider_label, "provider_kind": self.provider_kind,
                "model": self.model, "location": self.location, "source": self.source,
                "source_label": self.source_label, "fallback": self.fallback,
                "blocked": [b.model_dump() for b in self.blocked]}


def selection(gw: "LLM") -> LlmSelection:
    doc = gw.hub.store.get("settings", SELECTION_DOC)
    try:
        return LlmSelection.model_validate(doc or {})
    except ValueError:  # an unreadable document: the defaults (automatic), never a crash in every agent record
        return LlmSelection()


def team_of(gw: "LLM", agent_id: str) -> str | None:
    """The team whose default applies to an agent: a custom agent's team; a tool team's lead (its Tool Supervisor).
    Not the Hub Supervisor or the module leads: they serve the whole suite."""
    from ..agents import teams

    defn = teams.get_def(gw.hub, agent_id)
    if defn is not None:
        return defn.team
    return agent_id.split(":", 1)[1] if agent_id.startswith("tool:") else None


def own_settings(gw: "LLM", agent_id: str) -> tuple[LlmChoice, AgentConfig]:
    """An agent's own model choice ("" = inherit) and its settings: from its definition (custom agents) or its
    "agents" document (core agents; a legacy model override without a provider is a Claude model)."""
    from ..agents import teams

    defn = teams.get_def(gw.hub, agent_id)
    if defn is not None:
        return LlmChoice(provider=defn.provider, model=defn.model), defn.config
    doc = gw.hub.store.get("agents", agent_id) or {}
    provider = str(doc.get("provider") or ("anthropic" if doc.get("model") else ""))
    try:
        config = AgentConfig.model_validate(doc.get("config") or {})
    except ValueError:  # an unreadable document: the defaults, never a crash in every agent record
        config = AgentConfig()
    return LlmChoice(provider=provider, model=str(doc.get("model") or "") if provider else ""), config


Own = tuple[LlmChoice, AgentConfig]  # an agent's model choice and settings (stored, or a playground draft)


def agent_levels(gw: "LLM", agent_id: str, purpose: str, own: Own | None = None) -> tuple[list[Candidate], str | None]:
    """The agent's own levels (purpose override, override) and the team whose default applies to it."""
    choice, config = own or own_settings(gw, agent_id)
    out: list[Candidate] = []
    per_task = config.purposes.get(purpose)  # type: ignore[call-overload]
    if per_task is not None and per_task.provider:
        out.append(Candidate(level="agent_purpose", provider=per_task.provider, model=per_task.model))
    if choice.provider:
        out.append(Candidate(level="agent", provider=choice.provider, model=choice.model))
    return out, team_of(gw, agent_id)


def local_only(gw: "LLM", agent_id: str, config: AgentConfig | None = None) -> str | None:
    """"agent" or "team" when the agent may only run on self-hosted models (its own setting or its team's)."""
    config = config or own_settings(gw, agent_id)[1]
    if config.local_only:
        return "agent"
    team = team_of(gw, agent_id)
    sel = selection(gw)
    return "team" if team and team in sel.teams and sel.teams[team].local_only else None


def candidates(gw: "LLM", agent_id: str, purpose: str, own: Own | None = None) -> list[Candidate]:
    sel = selection(gw)
    levels, team = agent_levels(gw, agent_id, purpose, own)
    out = list(levels)
    if team and team in sel.teams and sel.teams[team].provider:
        out.append(Candidate(level="team", provider=sel.teams[team].provider, model=sel.teams[team].model, team=team))
    chosen = sel.purposes.get(purpose)  # type: ignore[call-overload]
    if chosen is not None and chosen.provider:
        out.append(Candidate(level="purpose", provider=chosen.provider, model=chosen.model))
    default = sel.default
    if default.provider in ("", "auto"):
        # model servers people added: self-hosted ones first, then OpenAI-compatible cloud services (by name)
        locals_ = sorted((p for p in gw.providers() if p.kind == "openai_compatible" and p.default_model),
                         key=lambda p: (p.location == "third_party", p.name.lower(), p.id))
        out += [Candidate(level="suite", provider=p, auto=True) for p in (*AUTO_ORDER, *(p.id for p in locals_))]
    else:
        out.append(Candidate(level="suite", provider=default.provider, model=default.model))
    out += [Candidate(level="fallback", provider=p) for p in sel.fallback if p != "rules"]
    return out


def source_label(gw: "LLM", c: Candidate, purpose: str) -> str:
    from ..agents import teams

    level = c.level
    if level == "agent_purpose":
        return f"This agent's choice for {PURPOSE_LABELS.get(purpose, purpose).lower()}"
    if level == "agent":
        return "This agent's choice"
    if level == "team":
        return f"{teams.team_name(gw.hub, c.team or '')} team default"
    if level == "purpose":
        return f"{PURPOSE_LABELS.get(purpose, purpose)} default"
    if level == "suite":
        return "Suite default (automatic)" if c.auto else "Suite default"
    if level == "fallback":
        return "Fallback"
    return teams.PROVIDER_LABELS["rules"]


def resolve(gw: "LLM", agent_id: str, purpose: str, own: Own | None = None) -> Resolution:
    """What the agent runs on for `purpose` - with `own`, on a draft of its settings (the playground; nothing is
    stored or cached)."""
    agent = gw.hub.agents.get(agent_id)
    if agent is not None and agent.kind != "custom" and (not agent.uses_llm or purpose not in agent.purposes):
        return Resolution(agent_id=agent_id, purpose=purpose, source="deterministic", source_label="Deterministic")
    return walk(gw, agent_id, purpose, candidates(gw, agent_id, purpose, own), own[1] if own else None)


def inherited(gw: "LLM", agent_id: str, purpose: str, *, keep_agent: bool = False) -> Resolution:
    """What the agent would run on without its own choices (team, task and suite defaults; its local-only rule kept),
    or with `keep_agent` without its per-task choice only: the "Inherit (currently ...)" lines of the agent settings
    page."""
    skip = ("agent_purpose",) if keep_agent else ("agent", "agent_purpose")
    found = [c for c in candidates(gw, agent_id, purpose) if c.level not in skip]
    return walk(gw, agent_id, purpose, found)


def walk(gw: "LLM", agent_id: str, purpose: str, found: list[Candidate], config: AgentConfig | None = None
         ) -> Resolution:
    """The first usable candidate, in order, with the reasons the earlier ones were skipped."""
    bound = local_only(gw, agent_id, config) if agent_id else None
    res = Resolution(agent_id=agent_id, purpose=purpose, local_only=bound is not None, local_only_from=bound)
    local_reason = None if bound is None else "agent is local-only" if bound == "agent" else \
        f"the {team_label(gw, team_of(gw, agent_id))} team is local-only"
    blocked: list[Blocked] = []
    auto_reasons: list[str] = []
    for n, c in enumerate(found):
        if res.intended is None and not c.auto and c.level != "fallback":
            res.intended = c.model_copy(update={"model": c.model or gw.default_model(c.provider)})
        if c.provider == "rules":
            res.source, res.source_label = c.level, source_label(gw, c, purpose)
            break
        reason = local_reason if local_reason and gw.location(c.provider) == "third_party" else None
        reason = reason or gw.blocked_reason(c.provider)
        model = c.model or (gw.default_model(c.provider) if reason is None else "")
        if reason is None and not model:
            reason = "no model chosen"
        if reason is not None:
            if c.auto:  # the automatic choice tries every provider: one summary line instead of one per provider
                auto_reasons.append(f"{gw.label(c.provider)}: {reason}")
            else:
                blocked.append(Blocked(level=c.level, provider=c.provider, reason=reason))
            continue
        res.provider, res.model = c.provider, model
        res.provider_label, res.provider_kind = gw.label(c.provider), gw.kind_of(c.provider)
        res.location = gw.location(c.provider)
        res.source, res.source_label = c.level, source_label(gw, c, purpose)
        res.fallback = c.level == "fallback"
        # the same local-only rule for the call-time fallbacks (the rest is checked when one is needed)
        res.fallbacks = [x for x in found[n + 1:] if x.level == "fallback"
                         and not (bound and gw.location(x.provider) != "self_hosted")]
        break
    else:
        res.source_label = "No AI model available"
    if res.source != "suite" and auto_reasons:
        blocked.append(Blocked(level="suite", provider="auto", reason="no usable provider ("
                               + "; ".join(auto_reasons[:4]) + ")"))
    res.blocked = blocked
    return res


def team_label(gw: "LLM", team: str | None) -> str:
    from ..agents import teams

    return teams.team_name(gw.hub, team or "")


LEVEL_TITLES = {"agent_purpose": "This agent, for {purpose}", "agent": "This agent", "team": "{team} team",
                "purpose": "{purpose_title} default", "suite": "Suite default", "fallback": "Fallback", "rules": "Rules"}


def chain(gw: "LLM", agent_id: str, purpose: str) -> list[dict[str, Any]]:
    """Every level that could decide the agent's model for `purpose`, in order, with what is set there and what
    happened to it: "used", "blocked" (with the reason), "not reached", "not set" (the agent settings page shows it
    as an ordered list)."""
    res = gw.resolve(agent_id, purpose)
    if res.source == "deterministic":
        return []
    sel = selection(gw)
    own, team = agent_levels(gw, agent_id, purpose)
    by_level = {c.level: c for c in own}
    words = {"purpose": PURPOSE_LABELS.get(purpose, purpose).lower(), "purpose_title": PURPOSE_LABELS.get(purpose, purpose),
             "team": team_label(gw, team)}
    agent = gw.hub.agents.get(agent_id)
    levels: list[tuple[str, Candidate | None]] = []
    if agent is not None and len(getattr(agent, "purposes", ())) > 1 or "agent_purpose" in by_level:
        levels.append(("agent_purpose", by_level.get("agent_purpose")))
    levels.append(("agent", by_level.get("agent")))
    if team:
        t = sel.teams.get(team)
        levels.append(("team", Candidate(level="team", provider=t.provider, model=t.model, team=team)
                       if t is not None and t.provider else None))
    p = sel.purposes.get(purpose)  # type: ignore[call-overload]
    levels.append(("purpose", Candidate(level="purpose", provider=p.provider, model=p.model)
                   if p is not None and p.provider else None))
    d = sel.default
    levels.append(("suite", Candidate(level="suite", provider=d.provider or "auto", model=d.model,
                                      auto=d.provider in ("", "auto"))))
    levels += [("fallback", Candidate(level="fallback", provider=f)) for f in sel.fallback if f != "rules"]
    levels.append(("rules", Candidate(level="rules", provider="rules")))
    blocked = {(b.level, b.provider): b.reason for b in res.blocked}
    out: list[dict[str, Any]] = []
    reached = True
    for level, c in levels:
        row: dict[str, Any] = {"level": level, "title": LEVEL_TITLES[level].format(**words), "provider": None,
                               "provider_label": None, "model": None, "status": "not set", "reason": None}
        if c is not None:
            auto = c.auto
            row.update(provider="auto" if auto else c.provider,
                       provider_label="Automatic" if auto else gw.label(c.provider),
                       model=c.model or (None if auto or c.provider == "rules" else gw.default_model(c.provider) or None))
            used = reached and res.source == level and (level != "fallback" or res.provider == c.provider) and (
                auto or c.provider == res.provider or level == "rules")
            if used:
                row.update(status="used", provider_label=res.provider_label if auto else row["provider_label"],
                           model=res.model or None)
                if auto:
                    row["title"] += " (automatic)"
                reached = False
            elif (level, "auto" if auto else c.provider) in blocked:
                row.update(status="blocked", reason=blocked[(level, "auto" if auto else c.provider)])
            elif not reached:
                row["status"] = "not reached"
            else:
                row["status"] = "blocked" if level != "rules" else "used"
        out.append(row)
    return out


def effective(res: Resolution, gw: "LLM") -> dict[str, Any]:
    """The provider fields an agent record shows: what runs, or - when nothing can - what was chosen for it."""
    if res.ready or res.intended is None or res.intended.provider == "rules":
        return {"provider": res.provider, "provider_kind": res.provider_kind, "provider_label": res.provider_label,
                "model": res.model}
    c = res.intended
    return {"provider": c.provider, "provider_kind": gw.kind_of(c.provider), "provider_label": gw.label(c.provider),
            "model": c.model}
