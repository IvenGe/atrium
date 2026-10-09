"""Guardrails: safety switches for the hub's AI agents that administrators can relax (Settings > Agent guardrails).

Each guardrail is registered once - its default, its type, and what relaxing it risks (the UI shows that text before
a person switches a protection off). Later features add their own with `register`. Values live in the "guardrails"
preference; every change is logged with the actor (relaxations as warnings) and the GRC Supervisor re-evaluates
control HB-AC-6.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .core import Hub


@dataclass(frozen=True)
class Guardrail:
    key: str
    title: str
    description: str
    default: bool | int
    risk: str  # what relaxing it risks; shown before a person relaxes it
    group: str = "agents"
    minimum: int = 1  # numbers only
    maximum: int = 100
    requires: str | None = None  # a number that only matters while this switch is on (or, for limits, on)
    # the compliance control that relaxing this switch weakens, how far ("fail" or "partial"), and the finding text
    control: str | None = None
    weakens: Literal["fail", "partial"] = "partial"
    finding: str = ""

    @property
    def kind(self) -> str:
        return "bool" if isinstance(self.default, bool) else "int"

    @property
    def safe(self) -> bool | int:
        """The protective position of a switch (its default); numbers are tighter when lower."""
        return self.default

    def relaxes(self, old: Any, new: Any) -> bool:
        if self.kind == "bool":
            return old == self.safe and new != self.safe
        return int(new) > int(old)


REGISTRY: dict[str, Guardrail] = {}


def register(guardrail: Guardrail) -> Guardrail:
    REGISTRY[guardrail.key] = guardrail
    return guardrail


for _g in (
    Guardrail("limit_to_parent_permissions", "Team agents never get more permissions than their parent",
              "A team member's permissions are limited to those of the agent that created it (for a team a person "
              "creates: the lead of the team).", True,
              "Team agents could hold permissions their parent does not have - running commands, applying patches or "
              "writing compliance data - so an agent could create a more powerful agent than itself.", group="teams"),
    Guardrail("allow_nested_teams", "Team agents may build their own teams",
              "Lets team agents with the 'agents' permission create sub-team members, up to the maximum depth.", False,
              "Agents created by agents act further and further away from a person's decision, and the number of "
              "agents (and of scheduled model calls) can multiply.", group="teams", requires="max_team_depth"),
    Guardrail("max_team_depth", "Maximum team depth",
              "How many levels of agents may sit below a core agent. 1 = only the members of a lead's team.", 1,
              "Deeper nesting means agents created by agents created by agents; each level is further from a person.",
              group="teams", minimum=1, maximum=5),
    Guardrail("limit_team_size", "Limit the size of agent teams",
              "Caps the number of team agents per team (a tool, the hub or a built-in app).", True,
              "A team could grow without bound: every member may run on a schedule and call a model, so costs, noise "
              "and the number of agents acting on a tool grow with it.", group="teams", requires="max_team_size"),
    Guardrail("max_team_size", "Maximum team size", "Team agents per team, leads not counted.", 5,
              "Larger teams mean more scheduled runs, more model calls and more agents acting on the tool.",
              group="teams", minimum=1, maximum=50),
    Guardrail("team_actions_need_approval", "Team agents' actions follow the autonomy level",
              "State-changing commands and patches from team agents wait for approval like those of every other agent "
              "(manual and assisted modes).", True,
              "Team agents' state-changing commands and code patches would run without waiting in the approval queue, "
              "whatever the autonomy level. A model's misunderstanding could change or break a tool before anyone "
              "sees it."),
    Guardrail("block_catastrophic_commands", "Block catastrophic commands",
              "Commands that wipe disks, delete the whole filesystem, shut machines down or pipe downloads into a "
              "shell are refused for everyone.", True,
              "Those commands would no longer be refused: they become ordinary state-changing commands, which people "
              "run directly and agents run after approval - or without it in autonomous mode.", group="commands"),
    Guardrail("scans_need_approval", "Scheduled and agent-started scans need approval",
              "Vulnerability scans that a schedule or an agent starts wait for approval (unless the hub is autonomous).",
              True, "Scans would start without a person deciding. Active scans can load or disturb the scanned systems.",
              group="scans"),
    Guardrail("team_requires_approval", "New agent teams need approval",
              "Agent teams that tool supervisors (or team agents) propose wait in the approval queue (unless the hub "
              "is autonomous).", True,
              "Agents would create new agents - with their roles, schedules and permissions - without a person "
              "reviewing them.", group="teams"),
):
    register(_g)


def defaults() -> dict[str, Any]:
    return {key: g.default for key, g in REGISTRY.items()}


def merged(stored: dict[str, Any] | None) -> dict[str, Any]:
    """The defaults overlaid with the stored values (unknown keys from older or newer versions are kept)."""
    return {**defaults(), **(stored or {})}


def value(hub: "Hub", key: str) -> Any:
    return hub.prefs["guardrails"].get(key, REGISTRY[key].default)


def catalog(current: dict[str, Any]) -> list[dict[str, Any]]:
    """What the settings screen shows: every guardrail with its value, default, bounds and the risk of relaxing it."""
    out = []
    for key, g in REGISTRY.items():
        now = current.get(key, g.default)
        out.append({"key": key, "kind": g.kind, "title": g.title, "description": g.description, "group": g.group,
                    "default": g.default, "value": now, "risk": g.risk, "requires": g.requires,
                    "min": g.minimum if g.kind == "int" else None, "max": g.maximum if g.kind == "int" else None,
                    "relaxed": g.relaxes(g.default, now) if now != g.default else False})
    return out


def validate(changes: dict[str, Any]) -> dict[str, Any]:
    """Typed, range-checked values; ValueError naming the first bad key."""
    out: dict[str, Any] = {}
    for key, raw in (changes or {}).items():
        g = REGISTRY.get(key)
        if g is None:
            raise ValueError(f"Unknown guardrail '{key}'")
        if g.kind == "bool":
            if not isinstance(raw, bool):
                raise ValueError(f"{key} must be true or false")
            out[key] = raw
        else:
            if isinstance(raw, bool) or not isinstance(raw, int):
                raise ValueError(f"{key} must be a whole number")
            if not g.minimum <= raw <= g.maximum:
                raise ValueError(f"{key} must be between {g.minimum} and {g.maximum}")
            out[key] = raw
    return out


def update(hub: "Hub", actor: str, changes: dict[str, Any]) -> dict[str, Any]:
    """Store validated changes and log each one with the actor - relaxing a protection as a warning."""
    changes = validate(changes)
    current = hub.prefs["guardrails"]
    new = {**current, **changes}
    stored = (hub.store.get("settings", "prefs") or {}).get("values", {})
    hub.put_pref("guardrails", {**(stored.get("guardrails") or {}), **changes})
    for key, after in changes.items():
        before = current.get(key, REGISTRY[key].default)
        if before == after:
            continue
        g = REGISTRY[key]
        relaxed = g.relaxes(before, after)
        shown = (lambda v: "on" if v else "off") if g.kind == "bool" else str
        hub.activity(actor, "warn" if relaxed else "info",
                     f"Guardrail '{g.title}' {'relaxed' if relaxed else 'changed'}: {shown(before)} -> {shown(after)}",
                     guardrail=key, before=before, after=after)
    return new


# --------------------------------------------------------------------------------------
# what the guardrails mean for an action
# --------------------------------------------------------------------------------------


def is_team_agent(sender: str) -> bool:
    """Custom (team) agents talk on the bus as "agent:<slug>"."""
    return sender.startswith("agent:")


def effective_autonomy(hub: "Hub", sender: str) -> str:
    """The autonomy level an action from `sender` follows: team agents act without approval only when the
    team_actions_need_approval guardrail is off."""
    autonomy = hub.prefs["autonomy"]
    if is_team_agent(sender) and not value(hub, "team_actions_need_approval"):
        return "autonomous"
    return autonomy
