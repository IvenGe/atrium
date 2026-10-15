"""The suite's model choice (settings doc "llm_selection"): the suite default ("auto" = Claude, else OpenAI, else a
local model with a default model), a default per purpose (chat, code changes, structured generation), a default per
team (with an optional local-only rule) and the fallback chain tried when a provider fails at call time. Agents that
choose nothing inherit these (resolve.py). Changes are versioned: a write that names an older version is refused, so
two administrators (or the Settings page and the Home widget) cannot overwrite each other unseen."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from ..models import LlmChoice, LlmSelection, TeamLlm
from .prompting import check_language
from .resolve import PURPOSE_LABELS, SELECTION_DOC, selection

if TYPE_CHECKING:
    from ..core import Hub

MAX_FALLBACK = 8


class Conflict(Exception):
    """The selection changed since the version the caller read."""

    def __init__(self, current: LlmSelection):
        super().__init__("Someone else changed the model choice")
        self.current = current


def choice_text(c: LlmChoice | None) -> str:
    """How a choice reads in the activity log: "automatic", "rules", "openai/gpt-6-luna", "ollama (default model)"."""
    if c is None or not c.provider:
        return "not set"
    if c.provider == "auto":
        return "automatic"
    if c.provider == "rules":
        return "rules"
    return f"{c.provider}/{c.model}" if c.model else f"{c.provider} (default model)"


def check_choice(hub: "Hub", c: LlmChoice, where: str, *, auto: bool = False) -> LlmChoice:
    """A valid choice: "" (not set), "rules", "auto" (the suite default only) or a provider that exists - a model only
    with a provider. ValueError naming `where` otherwise."""
    from .. import llm_providers

    provider, model = c.provider.strip(), c.model.strip()
    if provider in ("", "auto") and model:
        raise ValueError(f"{where}: a model needs a provider")
    if provider == "auto" and not auto:
        raise ValueError(f"{where}: 'auto' is only for the suite default")
    if provider == "rules" and model:
        raise ValueError(f"{where}: rules have no model")
    if provider not in ("", "auto", "rules") and llm_providers.get(hub, provider) is None:
        raise ValueError(f"{where}: unknown provider '{provider}'")
    return c.model_copy(update={"provider": provider, "model": model})


def save(hub: "Hub", changes: dict[str, Any], actor: str, version: int | None = None
         ) -> tuple[LlmSelection, list[str], bool]:
    """Apply a partial change: `default` (a choice), `purposes` / `teams` ({key: choice or None to unset}),
    `fallback` (the whole ordered list) and `language` (the default reply language: "auto" or a BCP 47 code). Returns (selection, what changed as words, whether a protection was
    loosened). Raises ValueError (invalid) or Conflict (`version` is not the current one)."""
    from ..agents import teams

    gw = hub.llm
    current = selection(gw)
    if version is not None and version != current.version:
        raise Conflict(current)
    new = current.model_copy(deep=True)
    if changes.get("default") is not None:
        chosen = check_choice(hub, LlmChoice.model_validate(changes["default"]), "Suite default", auto=True)
        new.default = chosen if chosen.provider else LlmChoice(provider="auto")
    for purpose, value in (changes.get("purposes") or {}).items():
        if purpose not in PURPOSE_LABELS:
            raise ValueError(f"Unknown purpose '{purpose}': use chat, code or generate")
        chosen = check_choice(hub, LlmChoice.model_validate(value), f"{PURPOSE_LABELS[purpose]} default") \
            if value is not None else LlmChoice()
        if chosen.provider:
            new.purposes[purpose] = chosen  # type: ignore[index]
        else:
            new.purposes.pop(purpose, None)  # type: ignore[call-overload]
    for team, value in (changes.get("teams") or {}).items():
        if value is None:
            new.teams.pop(team, None)
            continue
        team = teams.validate_team(hub, team)
        name = f"{teams.team_name(hub, team)} team"
        chosen = check_choice(hub, TeamLlm.model_validate(value), name)  # a TeamLlm (local_only kept)
        if chosen.local_only and chosen.provider and gw.location(chosen.provider) == "third_party":
            raise ValueError(f"{name}: local-only teams cannot use {gw.label(chosen.provider)}, a cloud provider")
        if chosen.provider or chosen.local_only:
            new.teams[team] = chosen
        else:
            new.teams.pop(team, None)
    if changes.get("fallback") is not None:
        chain = [str(p).strip() for p in changes["fallback"]]
        if len(chain) > MAX_FALLBACK:
            raise ValueError(f"The fallback chain has at most {MAX_FALLBACK} providers")
        if len(set(chain)) != len(chain):
            raise ValueError("A provider can be in the fallback chain only once")
        for provider in chain:
            if provider in ("", "auto", "rules"):
                raise ValueError("The fallback chain names providers; rules always come last by themselves")
            check_choice(hub, LlmChoice(provider=provider), "Fallback chain")
        new.fallback = chain
    if changes.get("language") is not None:  # chat agents answer in it unless they choose their own
        new.language = check_language(str(changes["language"]), "Default reply language") or "auto"
    lines, loosened = describe(hub, current, new)
    if not lines:
        return current, [], False
    new.version, new.updated_by, new.updated_at = current.version + 1, actor, time.time()
    hub.store.put("settings", {"id": SELECTION_DOC, **new.model_dump(mode="json")})
    gw.invalidate()
    hub.bus.publish("llm_selection", new.model_dump(mode="json"))
    return new, lines, loosened


def describe(hub: "Hub", before: LlmSelection, after: LlmSelection) -> tuple[list[str], bool]:
    """What changed between two selections, as activity-log words, and whether a team lost its local-only rule."""
    from ..agents import teams

    lines: list[str] = []
    if before.default != after.default:
        lines.append(f"suite default {choice_text(before.default)} -> {choice_text(after.default)}")
    for purpose, label in PURPOSE_LABELS.items():
        old, new = before.purposes.get(purpose), after.purposes.get(purpose)  # type: ignore[call-overload]
        if old != new:
            what = f"{label.lower()} default"
            lines.append(f"{what} set to {choice_text(new)}" if new else f"{what} removed (was {choice_text(old)})")
    loosened = False
    for team in sorted(set(before.teams) | set(after.teams)):
        old, new = before.teams.get(team), after.teams.get(team)
        if old == new:
            continue
        parts = []
        if (old.provider if old else "", old.model if old else "") != (new.provider if new else "", new.model if new else ""):
            parts.append(f"model {choice_text(old)} -> {choice_text(new)}")
        if bool(old and old.local_only) != bool(new and new.local_only):
            parts.append(f"local-only {'on' if new and new.local_only else 'off'}")
            loosened = loosened or not (new and new.local_only)
        lines.append(f"{teams.team_name(hub, team)} team: {', '.join(parts)}")
    if before.fallback != after.fallback:
        lines.append("fallback chain " + (" > ".join(after.fallback) or "empty") + " > rules")
    if before.language != after.language:
        lines.append(f"default reply language {before.language} -> {after.language}")
    return lines, loosened


def effective(hub: "Hub") -> list[dict[str, Any]]:
    """Every agent that can use a model with what it runs on per purpose (the `llm` block of its record)."""
    out = []
    for agent in sorted(hub.agents.all(), key=lambda a: (a.kind == "custom", a.name.lower())):
        if not (agent.uses_llm or agent.kind == "custom"):
            continue
        out.append({"agent_id": agent.id, "name": agent.name, "kind": agent.kind, "team": agent.team,
                    "llm": hub.llm.block(agent)})
    return out


def view(hub: "Hub") -> dict[str, Any]:
    """GET /api/llm/selection: the stored choice, what each agent runs on, and how many agents use no model."""
    agents = effective(hub)
    return {"selection": selection(hub.llm).model_dump(mode="json"), "effective": agents,
            "deterministic": sum(1 for a in hub.agents.all() if not (a.uses_llm or a.kind == "custom")),
            "suite": hub.llm.resolve("", "chat").view()}
