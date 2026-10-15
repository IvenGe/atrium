"""One decision for every open gap: is a patch proposable, already waiting, or why not - for the Patch Agent's
propose pass, the Adapters card and the notes on the checks.

The rules, per open check with a fix (``outlook``), with the history of the tool's patches of that fix (the health
fixes share one history; single sign-on: the patches for the selected identity provider):

- a proposed patch: ``pending`` (waiting for approval) - for the health fixes also a launch_command patch that sets
  the health check too (one approval closes both: no second patch for the same gap);
- unless an administrator asks again (``again``): the latest one rejected, ``MAX_FAILED`` failed applies, the latest
  one applied while the gap is still open, or an AI attempt that failed before - each for the same manifest inputs
  (``fingerprint``) - is ``skipped`` with the reason. A change of the tool (a new port, a launch command, another
  recognised version) changes the fingerprint, and the fix is tried again;
- otherwise a dry ``patches.plan``: a patch is ``proposable``, a ``Skip`` is ``skipped`` or ``needs_input`` (a person
  must supply something: the manifest editor) with its reason. A launch command without a known recipe is proposable
  with an AI model and the tool's folder (the model reads it and proposes one for review), else the dry plan says
  what an administrator must set (R_NEEDS_LAUNCH, or the port); a health endpoint is proposable with an AI model (a
  code patch), else the probe's dry plan decides.

An approved patch whose gap was closed another way while it waited (``closed_since``: an administrator set the value
by hand, another patch closed it) is set aside, not applied: it would only replace what closed it.

Nothing here calls a model or writes, except ``record``: it keeps the last outcome per fix (store collection
``gap_outcomes``), so a reason is logged once when it changes and a failed AI attempt is not paid for again until the
tool changes or an administrator asks again.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from ..models import Check, Manifest, Patch, Tool
from . import identity, known_tools, patches
from .analyzer import placeholder
from .identity import SSO_STRATEGIES

if TYPE_CHECKING:
    from ..core import Hub

MAX_FAILED = 2
OUTCOMES = "gap_outcomes"  # store doc per tool: {"id": tool_id, "fixes": {fix: {reason, state, fingerprint, at, ai_failed}}}
FIX_INPUTS: dict[str, tuple[str, ...]] = {  # the manifest paths a plan reads ("known": the whole KnownMatch)
    "launch_command": ("known", "kind", "launch.command", "launch.port"),
    "health_config": ("known", "launch.command", "launch.port", "health.url"),
    "health_endpoint": ("kind", "stack", "launch.port", "health.url"),  # with health_probe: one history
    "health_probe": ("kind", "launch.port", "ui.url", "api.base_url", "health.url"),
    "event_adapter": ("api.base_url", "ui.url", "launch.port"),
    "api_adapter": ("kind", "api.type", "launch.port"),
    "add_manifest": ("native", "adopted"),
    "reassign_port": ("launch.port",),  # + the ports of the other tools
}
HEALTH_FAMILY = ("health_endpoint", "health_probe")
HEALTH_FIXES = ("health_config", *HEALTH_FAMILY)  # what a launch_command patch that also sets health.url covers
# the check each fix closes (launch_command: every check that names it - the launch, and health or events without
# an address); an approved patch whose gap is closed by now is not applied (closed_since)
CLOSES = {"health_config": "health", "health_endpoint": "health", "health_probe": "health", "event_adapter": "events",
          "api_adapter": "api", "add_manifest": "manifest", "reassign_port": "ports"}
NOT_APPLIED = "Not applied: "  # the error of a patch the hub set aside because its gap was closed another way
SUPERSEDED = "Superseded: "  # the error of an SSO patch set aside for another provider (PatchAgent._supersede)
EDIT_ROWS = {"launch": "Launch", "health": "Health", "api": "API"}  # check -> its row in Integration (manifest editor)
State = Literal["proposable", "pending", "skipped", "needs_input"]
_SELECT = object()  # fingerprint(): select the identity provider


@dataclass
class GapOutcome:
    """What happens to one fix of a tool: `check` the ids of the open checks it closes (comma-separated), `title`
    their titles, `reason` why it is not proposed (or what it waits for), `patch_id` the patch it waits on."""

    check: str
    title: str
    fix: str
    state: State
    reason: str = ""
    patch_id: str | None = None

    def public(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if k != "patch_id"}


def hub_url(hub: "Hub") -> str:
    return f"http://{hub.settings.host}:{hub.settings.port}"


# --------------------------------------------------------------------------------------
# fingerprints and history
# --------------------------------------------------------------------------------------


def _read(m: Manifest, path: str) -> Any:
    if path == "known":
        return m.known.model_dump(mode="json") if m.known else None
    value: Any = m
    for part in path.split("."):
        value = getattr(value, part, None)
    if isinstance(value, str) and placeholder(value):
        return None
    return sorted(value) if isinstance(value, list) else value


def fingerprint(tool: Tool, fix: str, others: list[Tool] = (), *, provider: Any = _SELECT) -> str:  # type: ignore[assignment]
    """The manifest inputs a plan of `fix` reads (FIX_INPUTS), hashed: sha256 hex[:16] of canonical JSON. Single
    sign-on strategies: the family "sso" and the selected identity provider's tool id (`provider`, else selected
    with the default identity preferences)."""
    m = tool.manifest
    if fix in SSO_STRATEGIES:
        if provider is _SELECT:
            found = patches.selected_provider(tool, list(others))
            provider = found.tool_id if found else None
        data: Any = {"fix": "sso", "provider": provider}
    else:
        data = {"fix": fix, "inputs": {p: _read(m, p) for p in FIX_INPUTS.get(fix, ())} if m else None}
        if fix == "reassign_port":
            data["others"] = sorted({o.manifest.launch.port for o in others
                                     if o.manifest and o.manifest.launch.port and o.manifest.kind != "saas"})
    text = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _family(fix: str) -> tuple[str, ...]:
    if fix in HEALTH_FAMILY:
        return HEALTH_FAMILY
    if fix in SSO_STRATEGIES:
        return tuple(SSO_STRATEGIES)
    return (fix,)


def _history(fix: str, items: list[Patch], provider: str | None) -> list[Patch]:
    """The tool's patches of `fix` (its family), oldest first; single sign-on: those for `provider`."""
    family = _family(fix)
    found = [p for p in items if p.strategy in family]
    if fix in SSO_STRATEGIES:
        found = [p for p in found if p.status == "proposed" or (p.sso.provider if p.sso else None) == provider]
    return sorted(found, key=lambda p: p.created_at)


def _drop_note(detail: str, note: str | None) -> str:
    """A check's detail without the history note the Hub Supervisor appended to it."""
    return detail[:-len(note)].rstrip() if note and detail.endswith(note) else detail


@dataclass
class _Context:
    """What one outlook / note pass reads once: the other tools, the identity preferences and the selected provider
    (single sign-on), the tool's patches and its stored outcomes."""

    hub: "Hub"
    tool: Tool
    others: list[Tool]
    items: list[Patch]
    stored: dict[str, Any]
    idp: identity.IdentityPrefs | None = None
    _provider: tuple[str | None] | None = None

    def provider(self) -> str | None:
        if self._provider is None:
            if self.idp is None:
                self.idp = identity.load_prefs(self.hub)
            found = patches.selected_provider(self.tool, self.others, self.idp)
            self._provider = (found.tool_id if found else None,)
        return self._provider[0]

    def fingerprint(self, fix: str) -> str:
        return fingerprint(self.tool, fix, self.others,
                           provider=self.provider() if fix in SSO_STRATEGIES else None)

    def history(self, fix: str) -> list[Patch]:
        return _history(fix, self.items, self.provider() if fix in SSO_STRATEGIES else None)


def _context(hub: "Hub", tool: Tool, others: list[Tool] | None = None, items: list[Patch] | None = None,
             stored: dict[str, Any] | None = None, idp: identity.IdentityPrefs | None = None) -> _Context:
    if others is None:
        others = [t for t in hub.tools() if t.id != tool.id]
    if items is None:
        items = hub.patches(tool.id)
    if stored is None:
        stored = (hub.store.get(OUTCOMES, tool.id) or {}).get("fixes") or {}
    return _Context(hub, tool, others, items, stored, idp)


class _Found(NamedTuple):
    state: State
    reason: str
    patch_id: str | None = None
    note: str | None = None  # the sentence for the check's detail (history_note), when it differs from the reason


def waiting(tool: Tool, check_id: str, items: list[Patch]) -> str | None:
    """Why the latest applied patch for check `check_id` has no effect yet, in one sentence - None when it has (or
    none was applied): a code change waiting on its branch for a person to merge it (``Patch.merged`` False: what it
    sets applies once an analysis finds it in the tool's folder), or an API adapter skeleton that nothing runs. The
    check then gets no fix: the next step is a person's (compatibility.EvalContext.waiting)."""
    for patch in sorted(items, key=lambda p: p.created_at, reverse=True):
        closes = "sso" if patch.strategy in SSO_STRATEGIES else CLOSES.get(patch.strategy)
        if patch.status != "applied" or patch.tool_id != tool.id or closes != check_id:
            continue
        if patch.merged is False:
            where = f"branch {patch.branch}" if patch.branch else (patch.location or "a folder of its own")
            row = EDIT_ROWS.get(check_id)
            by_hand = f" (or set it by hand in Integration > {row} > Edit)" if row else ""
            return (f"'{patch.title}' was applied on {where}, not merged yet: merge it into "
                    f"{tool.path or 'the tool'} and Re-analyse{by_hand}.")
        if patch.strategy == "api_adapter":
            return (f"An API adapter skeleton was generated (adapters/{tool.id}/api/adapter.py); fill in its TODOs and "
                    "run it, then set the API in Integration > API > Edit.")
        return None
    return None


def _applied(ctx: "_Context", patch: Patch, check: Check) -> _Found:
    pending = waiting(ctx.tool, check.id.split(",")[0], ctx.items)
    if pending:  # in effect only once a person acts: the reason says what to do, never "proposed again"
        return _Found("skipped", pending, None, pending)
    sentence = f"'{patch.title}' was applied, but the gap is still open"
    return _Found("skipped", f"{sentence}: {check.detail}", None, f"{sentence}.")


def _earlier(ctx: _Context, fix: str, check: Check, again: bool = False) -> _Found | None:
    """The history rules for one fix, when the history decides its outcome (else None)."""
    history = ctx.history(fix)
    waiting = [p for p in history if p.status == "proposed"]
    if fix in SSO_STRATEGIES:  # any provider's pending SSO patch holds the planning (PatchAgent.on_sso_plan settles it)
        waiting = [p for p in ctx.items if p.strategy in SSO_STRATEGIES and p.status == "proposed"]
    if waiting:
        return _Found("pending", f"Waiting for approval: '{waiting[-1].title}'.", waiting[-1].id)
    cover = covering_launch(ctx.items) if fix in HEALTH_FIXES else None
    if cover is not None:  # one approval closes both: no second patch for the health check meanwhile
        return _Found("pending", f"Waiting for approval: '{cover.title}' - it also sets the health check.", cover.id)
    done = [p for p in history if p.status != "proposed"]
    fp = ctx.fingerprint(fix)
    latest = done[-1] if done else None
    applied = [p for p in done if p.status == "applied"]
    if fix in SSO_STRATEGIES and applied:  # applied for the selected provider: _sso_patch plans no other
        return _applied(ctx, applied[-1], check)
    if again:
        return None
    if latest is not None and latest.status == "rejected" and latest.fingerprint in (fp, None) \
            and not (latest.error or "").startswith((NOT_APPLIED, SUPERSEDED)):  # set aside by the hub, not a person
        return _Found("skipped", f"You rejected '{latest.title}'. It is proposed again when the tool changes, or when "
                                 "an administrator asks again.")
    failed = [p for p in done if p.status == "failed" and p.fingerprint == fp]
    if len(failed) >= MAX_FAILED:
        last = failed[-1]
        row = EDIT_ROWS.get(check.id.split(",")[0])
        by_hand = f", or set it by hand in Integration > {row} > Edit" if row else ""
        return _Found("skipped", f"'{last.title}' failed {len(failed)} times; last error: "
                                 f"{(last.error or 'unknown')[:300]}. Fix the cause and ask again (administrator)"
                                 f"{by_hand}.")
    if latest is not None and latest.status == "applied" and latest.fingerprint == fp:
        return _applied(ctx, latest, check)
    stored = ctx.stored.get(fix) or {}
    if stored.get("ai_failed") and stored.get("fingerprint") == fp and stored.get("reason"):
        state = stored["state"] if stored.get("state") in ("skipped", "needs_input") else "skipped"
        return _Found(state, str(stored["reason"]))
    return None


def history_note(hub: "Hub", tool: Tool, check: Check, *, others: list[Tool] | None = None,
                 items: list[Patch] | None = None, stored: dict[str, Any] | None = None,
                 idp: identity.IdentityPrefs | None = None) -> str | None:
    """One sentence on the earlier attempts at `check`'s fix, for its detail: waiting for approval, rejected, failed
    (with the last error), applied but still open, or the AI model's failed attempt; None when nothing was tried.
    `others`, `items` (the tool's patches), `stored` and `idp` let a caller read them once for many checks."""
    if not check.fix or check.status == "pass" or tool.manifest is None:
        return None
    ctx = _context(hub, tool, others, items, stored, idp)
    found = _earlier(ctx, check.fix, check)
    if found is not None:
        return found.note or found.reason
    failed = [p for p in ctx.history(check.fix) if p.status == "failed"]
    if failed and failed[-1].fingerprint == ctx.fingerprint(check.fix):
        return f"'{failed[-1].title}' failed: {(failed[-1].error or 'unknown')[:300]}."
    return None


# --------------------------------------------------------------------------------------
# the outlook of a tool's gaps
# --------------------------------------------------------------------------------------


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _dry(ctx: _Context, fix: str) -> tuple[State, str]:
    """A dry plan of a deterministic strategy (nothing is saved): proposable, or the Skip's reason."""
    result = patches.plan(ctx.tool, ctx.others, fix, hub_url(ctx.hub))
    if isinstance(result, Patch):
        return "proposable", ""
    reason = getattr(result, "reason", None) or f"No patch fits '{patches.STRATEGY_TITLES.get(fix, fix)}' yet."
    return ("needs_input" if getattr(result, "needs_input", False) else "skipped"), reason


def outlook(hub: "Hub", tool: Tool, *, others: list[Tool] | None = None, fixes: list[str] | None = None,
            again: bool = False) -> list[GapOutcome]:
    """What would happen to each open gap of `tool` (its report's checks with a fix; `fixes` limits them): one
    outcome per distinct fix, titled with every check it closes. No model calls and no writes."""
    m = tool.manifest
    if m is None or tool.report is None:
        return []
    groups: dict[str, list[Check]] = {}
    for check in tool.report.checks:
        if check.status != "pass" and check.fix and (not fixes or check.fix in fixes):
            groups.setdefault(check.fix, []).append(check)
    if not groups:
        return []
    ctx = _context(hub, tool, others)
    model = hub.llm.ready("patcher", "code")
    out: list[GapOutcome] = []
    for fix, checks in groups.items():
        first = checks[0]
        base = first.model_copy(update={"detail": _drop_note(first.detail, history_note(
            hub, tool, first, others=ctx.others, items=ctx.items, stored=ctx.stored, idp=ctx.idp))})
        outcome = GapOutcome(check=",".join(c.id for c in checks), title=_join([c.title for c in checks]), fix=fix,
                             state="proposable")
        found = _earlier(ctx, fix, base, again)
        if found is not None:
            outcome.state, outcome.reason, outcome.patch_id = found.state, found.reason, found.patch_id
        elif fix in SSO_STRATEGIES:
            pass  # proposable: PatchAgent._sso_patch plans it for the selected provider
        elif fix == "launch_command" and known_tools.launch_plan(m, tool.id) is None:
            if not (model and tool.path and m.kind != "saas"):  # the dry plan says what a person must set
                outcome.state, outcome.reason = _dry(ctx, fix)
        elif fix == "health_endpoint" and model and tool.path and m.kind == "oss":
            pass  # proposable: a code patch written by the AI model
        else:
            outcome.state, outcome.reason = _dry(ctx, "health_probe" if fix == "health_endpoint" else fix)
        out.append(outcome)
    return out


def record(hub: "Hub", tool_id: str, outcomes: list[GapOutcome], ai_failed: set[str] = frozenset()  # type: ignore[assignment]
           ) -> list[GapOutcome]:
    """Keep the outcome of each fix (its reason, state and fingerprint; `ai_failed`: the fixes whose AI attempt failed
    this time - a stored failure stays while it still decides the outcome). Entries of gaps that are closed now are
    dropped. Returns the outcomes whose reason changed (each is logged once)."""
    tool = hub.get_tool(tool_id)
    if tool is None:
        hub.store.delete(OUTCOMES, tool_id)
        return []
    ctx = _context(hub, tool)
    before = ctx.stored
    open_fixes = {c.fix for c in (tool.report.checks if tool.report else []) if c.fix and c.status != "pass"}
    kept = {fix: entry for fix, entry in before.items() if fix in open_fixes}
    changed = []
    for o in outcomes:
        fp = ctx.fingerprint(o.fix)
        prev = before.get(o.fix) or {}
        still = (bool(prev.get("ai_failed")) and prev.get("fingerprint") == fp and o.reason == prev.get("reason")
                 and o.state in ("skipped", "needs_input"))
        if prev.get("reason", "") != o.reason:
            changed.append(o)
        kept[o.fix] = {"reason": o.reason, "state": o.state, "fingerprint": fp,
                       "at": prev.get("at") if prev.get("reason") == o.reason and prev.get("at") else time.time(),
                       "ai_failed": o.fix in ai_failed or still}
    hub.store.put(OUTCOMES, {"id": tool_id, "fixes": kept})
    return changed


def forget(hub: "Hub", tool_id: str) -> None:
    hub.store.delete(OUTCOMES, tool_id)


def sets_health(patch: Patch) -> bool:
    """A launch_command patch that also switches on and sets the health check (a known product's recipe, or an AI
    proposal that found the health path)."""
    return patch.strategy == "launch_command" and bool(((patch.manifest_update or {}).get("health") or {}).get("url"))


def covering_launch(items: list[Patch]) -> Patch | None:
    """The tool's launch_command patch waiting for approval that also sets the health check, if any (`items`: the
    tool's patches): the health fixes wait for it instead of proposing a second patch for the same gap."""
    return next((p for p in items if p.status == "proposed" and sets_health(p)), None)


def closed_since(tool: Tool | None, patch: Patch) -> str | None:
    """Why an approved patch is not applied any more: the gap it was proposed for was closed another way while it
    waited (an administrator set the value by hand, another patch closed it, the tool now ships its own manifest), so
    applying it would only replace what closed it. None when its gap is still open (or for patches this does not
    judge: single sign-on, bridges, extensions). The text starts with NOT_APPLIED."""
    if tool is None or tool.report is None or (patch.strategy not in CLOSES and patch.strategy != "launch_command"):
        return None
    checks = tool.report.checks
    if patch.strategy == "launch_command":
        if any(c.status != "pass" and c.fix == "launch_command" for c in checks):
            return None
        title = "Launchable from the hub"
    else:
        check = next((c for c in checks if c.id == CLOSES[patch.strategy]), None)
        if check is not None and check.status != "pass":
            return None
        title = check.title if check is not None else CLOSES[patch.strategy]
    return (f"{NOT_APPLIED}its gap was closed another way while it waited ({title} needs no patch now), so applying it "
            "would only replace what closed it.")


def port_variables() -> frozenset[str]:
    """The environment variables that only say which port a program listens on (reassign_port sets them): PORT, the
    frameworks' (patches.STACK_PORT_ENV) and the known products' (known_tools.Profile.port_env)."""
    return frozenset({"PORT", *(env for _, env in patches.STACK_PORT_ENV),
                      *(p.port_env for p in known_tools.PROFILES.values() if p.port_env)})


def touches_launch(patch: Patch) -> bool:
    """Whether a patch changes what runs on the hub machine when the tool starts - its launch command, setup, working
    folder, environment files, launch secrets or environment (other than a port variable holding a port number,
    port_variables): an administrator approves it, and it is never applied automatically."""
    launch = (patch.manifest_update or {}).get("launch")
    if not isinstance(launch, dict):
        return False
    if any(key in launch for key in ("command", "setup", "cwd", "env_files", "secret_env")):
        return True
    ports = port_variables()
    return any(key not in ports or not str(value).isdigit() for key, value in (launch.get("env") or {}).items())
