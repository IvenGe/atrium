"""Guardrails: safety switches for the hub's AI agents that administrators can relax (Settings > Agent guardrails).

Each guardrail is registered once - its default, its type, and what relaxing it risks (the UI shows that text before
a person switches a protection off). Later features add their own with `register`, naming the compliance control that
relaxing it weakens (`control`, `weakens`, `finding`; see `weakened`). Values live in the "guardrails" preference;
every change is logged with the actor (relaxations as warnings) and the GRC Supervisor re-evaluates the controls
(HB-AC-6 for the agent guardrails, HB-AC-2 for the approval switches, HB-CM-2 for extensions and self-patching,
HB-CM-3 for network device changes). Switching ``device_changes`` off is the kill switch: approved device changes
that were not applied yet become "blocked" at once (``integration.changes.kill_switch``).
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
    # the protective position when it is not the default: switches that allow a capability ("allow_extensions") are
    # on by default but off is the safe side, so switching them back on is logged as relaxing
    safe_value: bool | None = None

    @property
    def kind(self) -> str:
        return "bool" if isinstance(self.default, bool) else "int"

    @property
    def safe(self) -> bool | int:
        """The protective position of a switch (its default unless `safe_value` says otherwise); numbers are tighter
        when lower."""
        return self.default if self.safe_value is None else self.safe_value

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
              "writing compliance data - so an agent could create a more powerful agent than itself.", group="teams",
              control="HB-AC-6", weakens="fail"),
    Guardrail("allow_nested_teams", "Team agents may build their own teams",
              "Lets team agents with the 'agents' permission create sub-team members, up to the maximum depth.", False,
              "Agents created by agents act further and further away from a person's decision, and the number of "
              "agents (and of scheduled model calls) can multiply.", group="teams", requires="max_team_depth",
              control="HB-AC-6", finding="team agents may build nested teams"),
    Guardrail("max_team_depth", "Maximum team depth",
              "How many levels of agents may sit below a core agent. 1 = only the members of a lead's team.", 1,
              "Deeper nesting means agents created by agents created by agents; each level is further from a person.",
              group="teams", minimum=1, maximum=5),
    Guardrail("limit_team_size", "Limit the size of agent teams",
              "Caps the number of team agents per team (a tool, the hub or a built-in app).", True,
              "A team could grow without bound: every member may run on a schedule and call a model, so costs, noise "
              "and the number of agents acting on a tool grow with it.", group="teams", requires="max_team_size",
              control="HB-AC-6", finding="agent teams have no size limit"),
    Guardrail("max_team_size", "Maximum team size", "Team agents per team, leads not counted.", 5,
              "Larger teams mean more scheduled runs, more model calls and more agents acting on the tool.",
              group="teams", minimum=1, maximum=50),
    Guardrail("team_actions_need_approval", "Team agents' actions follow the autonomy level",
              "State-changing commands and patches from team agents wait for approval like those of every other agent "
              "(manual and assisted modes).", True,
              "Team agents' state-changing commands and code patches would run without waiting in the approval queue, "
              "whatever the autonomy level. A model's misunderstanding could change or break a tool before anyone "
              "sees it.", control="HB-AC-6", weakens="fail"),
    Guardrail("block_catastrophic_commands", "Block catastrophic commands",
              "Commands that wipe disks, delete the whole filesystem, shut machines down or pipe downloads into a "
              "shell are refused for everyone.", True,
              "Those commands would no longer be refused: they become ordinary state-changing commands, which people "
              "run directly and agents run after approval - or without it in autonomous mode.", group="commands",
              control="HB-AC-6", weakens="fail"),
    Guardrail("scans_need_approval", "Scheduled and agent-started scans need approval",
              "Vulnerability scans that a schedule or an agent starts wait for approval (unless the hub is autonomous).",
              True, "Scans would start without a person deciding. Active scans can load or disturb the scanned systems.",
              group="scans", control="HB-AC-2", finding="scans that schedules or agents start run without approval"),
    Guardrail("team_requires_approval", "New agent teams need approval",
              "Agent teams that tool supervisors (or team agents) propose wait in the approval queue (unless the hub "
              "is autonomous).", True,
              "Agents would create new agents - with their roles, schedules and permissions - without a person "
              "reviewing them.", group="teams", control="HB-AC-2",
              finding="agent teams are created without approval"),
    # extensions and self-patching (hub/extensions/)
    Guardrail("allow_extensions", "Allow extensions",
              "Extension packs can add data types, connector mappings, SSO recipes, compliance evidence and team "
              "templates to Atrium. Packs are data only: nothing in them is ever executed. Off: no pack is active and "
              "none is proposed.", True,
              "Enabled packs change what Atrium models and which tool APIs its connections call.", group="extensions",
              safe_value=False),
    Guardrail("extensions_need_approval", "Generated extensions need approval",
              "Extension packs the Patch Agent generates after an import wait in the approval queue before they are "
              "enabled.", True,
              "Packs an agent generated (from templates or by an AI model) would be enabled without a person reviewing the "
              "data types, connector mappings and compliance rules they add.", group="extensions", control="HB-CM-2",
              finding="extensions that agents generate are enabled without approval"),
    Guardrail("allow_self_patching", "Allow self-patching",
              "When an extension cannot express what a new tool needs, the Patch Agent (with an AI model) may propose a "
              "change to Atrium's own code on a separate branch, tested before anyone decides. Off: it never does.",
              True, "Changes to Atrium's own code that an AI model writes would be proposed (and their tests run) again.",
              group="self_patching", safe_value=False),
    Guardrail("self_patch_requires_tests", "Self-patches must pass the tests",
              "A change to Atrium's own code can only be approved when Atrium's test suite passed on its branch.", True,
              "Changes to Atrium's own code could be merged although its test suite fails on them - a broken or "
              "insecure Atrium after the next restart.", group="self_patching", control="HB-CM-2", weakens="fail"),
    Guardrail("self_patch_requires_approval", "Self-patches need approval",
              "Changes to Atrium's own code wait in the approval queue (an administrator decides).", True,
              "Changes to Atrium's own code that an AI model writes would be merged into the running checkout without a person "
              "reading them first.", group="self_patching", control="HB-CM-2", weakens="fail"),
    Guardrail("self_patch_via_pull_request", "Self-patches go through a pull request",
              "An approved self-patch is pushed as a branch and opened as a pull request (GitHub CLI, origin remote) "
              "instead of being merged locally. Without the GitHub CLI or an origin remote it is merged locally.", True,
              "Approved changes to Atrium's own code would be merged straight into the current branch, without the "
              "review and CI of a pull request.", group="self_patching"),
    # the second-person rule for approvals that record their proposer (device changes have their own switch below)
    Guardrail("approvals_need_second_person", "Approvals need a second person",
              "An approval that records who proposed it (a self-patch someone asked for, a data flow proposed from the "
              "integration map) must be decided by someone else. Device changes follow their own switch (Network).",
              False, "The person who proposed a change could approve it themselves.", safe_value=True),
    # network device changes (hub/integration/changes.py, canvas-design 6.6): off by default; every change is a
    # proposal an administrator approves, applied by the Network Supervisor with a backup and an automatic rollback
    Guardrail("device_changes", "Allow device changes",
              "Atrium may change firewall and network device rules: only changes a person proposed and an "
              "administrator approved, after a configuration backup, with the device's automatic rollback and a "
              "verification. Off: Atrium only reads devices, and approved changes that were not applied yet are "
              "blocked.", False,
              "Approved changes would be written to firewalls and network devices. A wrong rule can open the network "
              "or cut systems off; the rollback and the anti-lockout check limit that but cannot exclude it.",
              group="network"),
    Guardrail("device_changes_need_second_person", "Device changes need a second administrator",
              "Only an administrator who did not propose a device change can approve it. Switch off only where a "
              "single administrator runs Atrium.", True,
              "One person could propose and approve their own firewall change: nobody else reviews it.",
              group="network", control="HB-CM-3", weakens="fail"),
    Guardrail("device_changes_need_maintenance_window", "Device changes wait for a maintenance window",
              "An approved device change waits (status 'scheduled') until a maintenance window that covers the device "
              "starts; an administrator may apply one at once as an emergency, with a justification.", True,
              "Approved changes would be applied as soon as they are approved, also during working hours.",
              group="network", control="HB-CM-3", weakens="partial",
              finding="device changes are applied outside maintenance windows"),
    Guardrail("device_changes_need_backup", "Back up a device before changing it",
              "Atrium takes an encrypted, checksummed configuration backup before every device change and does not "
              "apply the change when the backup fails.", True,
              "Changes would be applied without a backup of the configuration to go back to when the device's own "
              "rollback fails.", group="network", control="HB-CM-3", weakens="fail"),
    Guardrail("approval_expiry_hours", "Approvals of device changes expire after (hours)",
              "A proposed device change must be approved and applied within this many hours of its proposal (an "
              "approval of a self-patch, of a subsidiary charter or of an in-tool action must be decided within it); "
              "afterwards it expires and is proposed again against the device's current rules.", 24,
              "A change could be applied long after the review that judged it, on a network that changed since.",
              group="network", minimum=1, maximum=72),
    # AI model providers (hub/llm/resolve.py): on by default - nothing reaches a cloud provider until an administrator
    # enters a key or sets one in the environment - but off is the safe side. Off: every third-party provider is
    # blocked and agents move on to a self-hosted model or rules at once. Compliance reflects cloud use through the
    # supplier records of HB-SC-1 (hub/grc/checks.py), not through this switch.
    Guardrail("allow_cloud_llm", "Agents may send data to cloud AI providers",
              "Agents may run on AI providers that a third party hosts (Claude, OpenAI, Azure OpenAI and other cloud "
              "services). Off: they run only on self-hosted models, or on rules.", True,
              "Agents send prompts, the hub data their tools read and tool results to the cloud AI providers you "
              "configured (Anthropic, OpenAI, others). Those providers process the data under their terms.",
              group="models", safe_value=False),
    # the suite's daily AI spending cap (hub/llm/usage.py): estimated from the price table, per UTC day; a reached cap
    # stops new model calls until the day ends (each agent's own budgets come on top, on its settings page)
    Guardrail("limit_llm_spend", "Cap the AI model spending per day",
              "New model calls stop for the rest of the UTC day once the agents' estimated spending reaches the "
              "maximum below (a call already running finishes). Agents fall back to rules or templates; chat answers "
              "that the budget is reached.", True,
              "Agents could spend without a limit: a runaway schedule, a loop or a prompt injection keeps calling paid "
              "models until someone notices the bill.", group="models", requires="max_daily_llm_spend",
              control="HB-AC-6", finding="agents' AI model spending has no daily limit"),
    Guardrail("max_daily_llm_spend", "Maximum AI spending per day (USD)",
              "The estimated cost (price table, Settings > AI models) of all model calls in one UTC day.", 20,
              "A higher cap lets agents spend more before they are stopped.", group="models", minimum=1,
              maximum=100_000),
    # subsidiaries: agent teams that work inside a tool through a bridge or a sidecar (hub/subsidiary/). Off by
    # default; switching it off is the global kill switch (every subsidiary is paused, its approvals withdrawn).
    Guardrail("allow_subsidiaries", "Allow subsidiaries (agent teams inside tools)",
              "Agent teams may work inside tools through an Atrium bridge or a sidecar, within a charter an "
              "administrator approved. Off: the kill switch - every subsidiary is paused at once, its pending approvals "
              "are withdrawn and its sidecar gets no answers, tickets or grants.", False,
              "AI agent teams act inside business tools: they read the tools' data, send it to the model providers "
              "their charter allows and ask for changes there (which wait for approval).", group="subsidiaries"),
    Guardrail("subsidiary_tool_writes_need_approval", "In-tool changes of subsidiaries need a person",
              "Every change a subsidiary team wants to make inside its tool waits for a person's approval. Off: a "
              "charter may let reversible changes without an external effect run at once (never from the panel).",
              True, "Reversible in-tool changes an AI team decides on would run without a person reviewing them.",
              group="subsidiaries", control="HB-AC-2",
              finding="reversible in-tool writes of subsidiary teams run without approval"),
    Guardrail("subsidiary_panel_actions", "Questions inside a tool may lead to change requests",
              "Questions tool users ask the team inside the tool ('Ask the team') may lead to requests for changes, "
              "which always need approval and are marked user-steered. Off: panel questions only read, draft and "
              "escalate.", False,
              "A tool user could steer the AI team into asking for changes (prompt injection through the panel); a "
              "person still decides each one.", group="subsidiaries", control="HB-AC-8",
              finding="tool users can steer subsidiary write requests"),
    Guardrail("subsidiary_bridge_requires_tests", "Bridge patches must pass their checks and tests",
              "A bridge patch can be approved only when Atrium's static checks passed and the tool's own tests did not "
              "fail (tests that could not run in a container are shown, not counted as a failure).", True,
              "A bridge patch could be approved although Atrium's checks found unsafe code or the tool's tests fail.",
              group="subsidiaries", control="HB-CM-2", weakens="fail"),
    Guardrail("subsidiary_bridge_requires_conformance", "Bridges must pass conformance",
              "A charter can be approved, and a subsidiary can be active, only after the bridge passed the conformance "
              "vectors for the approved manifest.", True,
              "A bridge that does not verify Atrium's signatures, grants or replays could be trusted with an AI team's "
              "work inside the tool.", group="subsidiaries", control="HB-AC-8", weakens="fail"),
    Guardrail("subsidiary_separate_credential", "API-only subsidiaries use their own credential",
              "A subsidiary without a bridge reads the tool with a dedicated (read-only) credential, never with the "
              "hub's own connection credential.", True,
              "The sidecar could hold the same credential as the hub's connection, often with write access.",
              group="subsidiaries", control="HB-AC-8",
              finding="subsidiary teams use the hub's own tool credential"),
    Guardrail("subsidiary_ticket_minutes", "Subsidiary ticket lifetime (minutes)",
              "How long a ticket to call a tool's bridge stays valid: the longest a bridge keeps answering reads after "
              "a pause, a stop or the kill switch.", 10,
              "Bridge reads continue longer after a subsidiary is paused or stopped.", group="subsidiaries",
              minimum=1, maximum=60, control="HB-AC-8",
              finding="the subsidiary kill switch takes up to {subsidiary_ticket_minutes} minutes"),
    Guardrail("subsidiary_max_tokens_per_day", "Subsidiary model tokens per day (thousands)",
              "The ceiling on every subsidiary charter's daily model budget.", 300,
              "Subsidiary teams can spend more on AI models each day.", group="subsidiaries", minimum=10,
              maximum=20_000),
):
    register(_g)


def defaults() -> dict[str, Any]:
    return {key: g.default for key, g in REGISTRY.items()}


def merged(stored: dict[str, Any] | None) -> dict[str, Any]:
    """The defaults overlaid with the stored values (unknown keys from older or newer versions are kept)."""
    return {**defaults(), **(stored or {})}


def value(hub: "Hub", key: str) -> Any:
    return hub.prefs["guardrails"].get(key, REGISTRY[key].default)


def weakened(current: dict[str, Any] | None, control: str) -> list[Guardrail]:
    """The guardrails mapped to `control` that are relaxed from their protective default in `current`. Compliance
    checks use this, so a guardrail a later feature registers with a `control` is reflected without editing them."""
    values = merged(current)
    return [g for g in REGISTRY.values() if g.control == control and g.relaxes(g.default, values[g.key])]


def catalog(current: dict[str, Any]) -> list[dict[str, Any]]:
    """What the settings screen shows: every guardrail with its value, default, bounds and the risk of relaxing it."""
    out = []
    for key, g in REGISTRY.items():
        now = current.get(key, g.default)
        out.append({"key": key, "kind": g.kind, "title": g.title, "description": g.description, "group": g.group,
                    "default": g.default, "safe": g.safe, "value": now, "risk": g.risk, "requires": g.requires,
                    "control": g.control,
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
    if changes.get("device_changes") is False:  # the kill switch (canvas-design S14)
        from .integration import changes as device_changes

        device_changes.kill_switch(hub, actor)
    if changes.get("allow_subsidiaries") is False:  # the subsidiaries' kill switch (round4-spec 7.7)
        from .subsidiary import governance

        governance.kill_switch(hub, actor)
    llm = getattr(hub, "llm", None)
    if llm is not None:  # which provider an agent runs on follows allow_cloud_llm at once
        llm.invalidate()
    return new


# --------------------------------------------------------------------------------------
# what the guardrails mean for an action
# --------------------------------------------------------------------------------------


def is_team_agent(sender: str) -> bool:
    """Custom (team) agents talk on the bus as "agent:<slug>"."""
    return sender.startswith("agent:")


def effective_autonomy(hub: "Hub", sender: str) -> str:
    """The autonomy level an action from `sender` follows: team agents act without approval only when the
    team_actions_need_approval guardrail is off; a subsidiary's sidecar staff never do (always "manual")."""
    from .subsidiary import governance

    if governance.is_staff(hub, sender):
        return "manual"
    autonomy = hub.prefs["autonomy"]
    if is_team_agent(sender) and not value(hub, "team_actions_need_approval"):
        return "autonomous"
    return autonomy
