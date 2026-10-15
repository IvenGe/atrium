"""The settings widgets (round4-dashboard-spec.md 6.2 and 6.7, stage D4): ``ai_models`` - which AI model every agent
runs on, one lane per provider, where an administrator drags agents between lanes - ``safety_settings`` (the autonomy
level and the relaxed guardrails, read-only) and ``hub_accounts`` (administrators: hub accounts by role, dormant
accounts and active API tokens).

``ai_models`` projects R4-LLM's data and never re-implements the model resolution: the providers are
``teams.provider_choices`` (what the Agents page offers), each agent's lane is its own stored choice
(``resolve.own_settings``) and what it runs on is the primary purpose of its record's ``llm`` block. The data has no
per-viewer field and no volatile agent field (status, activity), so one cached result serves every viewer and its
version only moves when the configuration does. The widget writes through R4-LLM's admin routes only
(``PATCH /api/agents/{id}/settings``, ``PATCH /api/llm/selection``); this module adds no write path.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, Literal

from .registry import FieldSpec, WidgetType, options, register, suggester, suggestion
from .resolve import ResolveContext, clean
from .widgets import Strict, route

if TYPE_CHECKING:
    from ..core import Hub

MAX_MODELS = 50  # model names per provider in the widget (pinned ones first)
MAX_DORMANT = 10
SHOW = {"all": "AI models", "custom": "AI models: custom agents", "core": "AI models: built-in agents"}
AI_EVENTS = ("agent_settings", "agent_removed", "llm_provider", "llm_provider_removed", "llm_selection", "settings",
             # a new tool brings its Tool Supervisor ("agent" is left out: it follows every message an agent handles)
             "tool", "tool_removed")


# -- ai_models ------------------------------------------------------------------------------------


class AiModelsConfig(Strict):
    show: Literal["all", "custom", "core"] = "all"


def steady(reason: str | None) -> str | None:
    """A provider's reason without the seconds of an open circuit ("failing - retry in 12s" -> "failing"), so the
    widget's data does not change every second while a provider recovers."""
    return reason.split(" - retry in ", 1)[0] if reason else reason


def provider_view(choice: dict[str, Any]) -> dict[str, Any]:
    """A lane: what the Agents page offers for the provider - never its key, key source, address or supplier."""
    models = list(dict.fromkeys([*choice.get("pinned_models", []), *choice.get("models", [])]))[:MAX_MODELS]
    return {"id": choice["id"], "kind": choice["kind"], "variant": choice.get("variant"),
            "label": clean(choice["label"], 80), "location": choice["location"], "available": bool(choice["available"]),
            "reason": steady(choice["reason"]), "default_model": clean(choice["default_model"], 200),
            "models": [clean(m, 200) for m in models]}


def suite_default(ctx: ResolveContext) -> dict[str, Any]:
    """The suite default as stored ("auto", a provider or "rules") and what it resolves to now: the suite level and the
    fallback chain only (team and task defaults do not apply to it)."""
    from ..llm import resolve as resolution

    gw = ctx.hub.llm
    chosen = resolution.selection(gw).default
    provider = chosen.provider or "auto"
    found = [c for c in resolution.candidates(gw, "", "chat") if c.level in ("suite", "fallback")]
    res = resolution.walk(gw, "", "chat", found)
    label = "Automatic" if provider == "auto" else "Rules" if provider == "rules" else clean(gw.label(provider), 80)
    return {"provider": provider, "model": chosen.model, "label": label,
            "resolved": {"provider": res.provider, "provider_label": clean(res.provider_label, 80), "model": res.model,
                         "ready": res.ready, "fallback": res.fallback}}


def agent_view(record: dict[str, Any]) -> dict[str, Any]:
    """An agent chip: its own choice ("" = inherit), its settings version and what its primary purpose runs on."""
    llm = record.get("llm") or {}
    primary = llm.get("primary")
    e = (llm.get("purposes") or {}).get(primary) or {}
    choice = llm.get("choice") or {}
    return {
        "id": record["id"], "name": clean(record.get("name"), 120), "title": clean(record.get("title"), 120),
        "team": record.get("team"), "kind": record.get("kind"),
        "settings_version": int(llm.get("settings_version") or 0),
        "choice": {"provider": str(choice.get("provider") or ""), "model": clean(choice.get("model") or "", 200)},
        "local_only": bool(llm.get("local_only")), "local_only_from": llm.get("local_only_from"),
        "per_task": int(llm.get("per_task") or 0),
        "effective": {"provider": e.get("provider", "rules"), "provider_label": clean(e.get("provider_label") or "", 80),
                      "model": clean(e.get("model") or "", 200), "location": e.get("location"),
                      "source": e.get("source", "rules"), "source_label": clean(e.get("source_label") or "", 120),
                      "fallback": bool(e.get("fallback")), "ready": bool(llm.get("ready"))},
        "href": route("agents", record["id"], "settings"),
    }


def resolve_ai_models(ctx: ResolveContext, cfg: AiModelsConfig) -> dict[str, Any]:
    from ..agents import teams
    from ..llm import resolve as resolution

    agents, without = [], 0
    for record in sorted(ctx.snap.agent_records, key=lambda r: (r.get("kind") == "custom", str(r.get("name")).lower())):
        if not (record.get("uses_llm") or record.get("kind") == "custom"):
            without += 1
            continue
        if cfg.show != "all" and (record.get("kind") == "custom") != (cfg.show == "custom"):
            continue
        agents.append(agent_view(record))
    return {
        "selection_version": resolution.selection(ctx.hub.llm).version,
        "default": suite_default(ctx),
        "providers": [provider_view(c) for c in teams.provider_choices(ctx.hub)],
        "agents": agents,
        "deterministic": without,
        "href": "#/settings/ai",
    }


# -- safety_settings -------------------------------------------------------------------------------


class NoConfig(Strict):
    pass


def resolve_safety(ctx: ResolveContext, cfg: NoConfig) -> dict[str, Any]:
    """The autonomy level and the guardrails relaxed from their protective default, with the controls they weaken.
    Read-only: the Settings page owns the changes and their risk confirmations."""
    from .. import guardrails

    prefs = ctx.hub.prefs
    catalog = guardrails.catalog(prefs["guardrails"])
    relaxed = [{"key": g["key"], "title": clean(g["title"], 120), "group": g["group"], "control": g["control"]}
               for g in catalog if g["relaxed"]]
    values = {g["key"]: g["value"] for g in catalog}
    return {
        "autonomy": prefs["autonomy"],
        "relaxed": relaxed,
        "controls_affected": sorted({g["control"] for g in relaxed if g["control"]}),
        "total_guardrails": len(catalog),
        "device_changes_on": bool(values.get("device_changes")),
        "cloud_ai": bool(values.get("allow_cloud_llm", True)),
        "spend_limit": values.get("max_daily_llm_spend") if values.get("limit_llm_spend") else None,
        "href": "#/settings",
    }


# -- hub_accounts (administrators) -----------------------------------------------------------------


def resolve_accounts(ctx: ResolveContext, cfg: NoConfig) -> dict[str, Any]:
    """Hub accounts by role, the disabled ones, enabled accounts without a sign-in for 90 days (the compliance check's
    rule) and API tokens that work now - names and counts only."""
    from ..grc.checks import DORMANT_AFTER

    auth, now = ctx.hub.auth, time.time()
    users = auth.users()
    enabled = [u for u in users if not u.disabled]
    by_id = {u.id: u for u in users}
    dormant = sorted((u for u in enabled if (u.last_login or u.created_at) < now - DORMANT_AFTER),
                     key=lambda u: u.last_login or 0)

    def works(token: Any) -> bool:  # unexpired, and its owner exists and is enabled (a token without one: next use)
        owner = by_id.get(token.owner_id) if token.owner_id else None
        alive = token.expires_at is None or token.expires_at > now
        return alive and (token.owner_id is None or (owner is not None and not owner.disabled))

    return {
        "by_role": {role: sum(1 for u in enabled if u.role == role) for role in ("admin", "operator", "viewer")},
        "total": len(users), "disabled": len(users) - len(enabled),
        "dormant_90d": [{"username": clean(u.username, 80), "last_seen": u.last_login} for u in dormant[:MAX_DORMANT]],
        "dormant_total": len(dormant),
        "tokens_active": sum(1 for t in auth.tokens() if works(t)),
        "href": "#/users",
    }


# -- registration ---------------------------------------------------------------------------------------

register(WidgetType(
    "ai_models", "AI models", "Which AI model every agent runs on, one lane per provider. Administrators drag agents "
    "between providers or change the suite default.", "settings", AiModelsConfig, resolve_ai_models,
    (4, 3), (8, 4), (12, 8),
    fields=(FieldSpec("show", "Agents", "select", options=options(("all", "All agents that use a model"),
                                                                  ("custom", "Custom agents"),
                                                                  ("core", "Built-in agents"))),),
    events=AI_EVENTS, ttl=15, title_for=lambda c: SHOW[c.show]))
register(WidgetType(
    "safety_settings", "Safety settings", "The agents' autonomy level and the guardrails relaxed from their safe "
    "default (read-only: change them in Settings).", "settings", NoConfig, resolve_safety, (3, 2), (4, 3), (8, 6),
    events=("settings",), ttl=30, title_for=lambda c: "Safety settings"))
register(WidgetType(
    "hub_accounts", "Hub accounts", "Atrium accounts by role, disabled and dormant accounts, and active API tokens "
    "(administrators).", "settings", NoConfig, resolve_accounts, (3, 2), (4, 3), (8, 6), min_role="admin",
    events=("settings",), ttl=300, refresh=300, cache=False, title_for=lambda c: "Hub accounts"))


@suggester
def settings_suggestions(hub: "Hub") -> list[dict[str, Any]]:
    """The settings widgets (6.5 item 3); the AI spending metric comes with every other metric."""
    out = [suggestion("hub", "ai_models", {"show": "all"}, "AI models",
                      "Which model every agent runs on; administrators drag agents between providers"),
           suggestion("hub", "ai_models", {"show": "custom"}, "AI models: custom agents",
                      "The model of each custom agent", size=(6, 3)),
           suggestion("hub", "safety_settings", {}, "Safety settings",
                      "Autonomy and the guardrails relaxed from their safe default"),
           suggestion("hub", "hub_accounts", {}, "Hub accounts",
                      "Accounts by role, dormant accounts and active API tokens")]
    return [x for x in out if x is not None]
