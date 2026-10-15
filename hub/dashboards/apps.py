"""The compliance, network and people widgets (round4-dashboard-spec.md 6.2, stage D3): ``compliance_overview``,
``controls_status``, ``risk_matrix``, ``vuln_sla``, ``network_overview`` and ``leavers``.

Each one reads what its app's page shows, through the same helpers, and projects whitelisted fields only (an
assessment's notes, scope and history, a device's address and errors, a leaver's e-mail are never in widget data).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field, field_validator

from ..models import OPEN_STATES, SEVERITY_ORDER
from . import domains
from .registry import FieldSpec, Outcome, Unavailable, WidgetType, options, register
from .resolve import ResolveContext, clean
from .widgets import LIMIT_FIELD, TOOL_ID, Strict, check_tool, route

if TYPE_CHECKING:
    from ..core import Hub

DAY = 86400
TOOL_SOURCE = r"^(all|manual|tool:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$"
BASELINE_FRAMEWORKS = ("BASELINE", "ISO27001", "SOC2", "NIS2", "CyFun2025", "CyFun2023")
FRAMEWORK_NAMES = {"BASELINE": "Hub Security Baseline", "ISO27001": "ISO/IEC 27001", "SOC2": "SOC 2", "NIS2": "NIS2",
                   "CyFun2025": "CyberFundamentals 2025", "CyFun2023": "CyberFundamentals 2023"}
CYFUN_PAGES = {"CyFun2025": "cyfun2025", "CyFun2023": "cyfun2023"}
CONTROL_STATES = domains.CONTROL_STATES
RISK_STATES = ("open", "in_treatment", "closed")


def tool_scope(ctx: ResolveContext, source: str) -> tuple[str | None, str]:
    """The tool of a "tool:<id>" source and the source's label; Unavailable when the tool was removed."""
    if not source.startswith("tool:"):
        return None, domains.MANUAL_LABEL if source == "manual" else "All sources"
    tool = ctx.snap.tools_by_id.get(source[5:])
    if tool is None:
        raise Unavailable("The tool this widget shows was removed.", "tool_removed")
    return tool.id, clean(tool.name, 80)


def check_source(hub: "Hub", source: str) -> None:
    if source.startswith("tool:"):
        check_tool(hub, source[5:])


# -- compliance_overview --------------------------------------------------------------------------


class ComplianceConfig(Strict):
    frameworks: Literal["all"] | list[Literal[BASELINE_FRAMEWORKS]] = "all"  # type: ignore[valid-type]
    external: str = Field("all", pattern=r"^(all|none|tool:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$")
    cyfun: bool = True  # the latest CyFun self-assessment

    @field_validator("frameworks")
    @classmethod
    def _unique(cls, v: Any) -> Any:
        return list(dict.fromkeys(v)) if isinstance(v, list) else v

    def check(self, hub: "Hub") -> None:
        check_source(hub, self.external)


def cyfun_brief(ctx: ResolveContext) -> dict[str, Any] | None:
    """The most recently changed CyFun self-assessment, without its notes, scope or history."""
    from ..grc.frameworks import assessments as fa

    if "cyfun_latest" not in ctx.snap.memo:
        found = max(fa.all_assessments(ctx.hub), key=lambda a: a.updated_at, default=None)
        brief = fa.brief(found) if found else None
        ctx.snap.memo["cyfun_latest"] = None if brief is None else {
            "id": brief["id"], "name": clean(brief["name"], 120), "framework": brief["framework"],
            "framework_name": clean(brief["framework_name"], 80), "target_name": clean(brief["target_name"], 40),
            "status": brief["status"], "verdict": brief["verdict"], "maturity": brief.get("maturity"),
            "progress": {k: brief["progress"].get(k) for k in ("total", "scored", "na")},
            "assessed_at": brief.get("assessed_at"), "stale": bool(brief.get("stale")),
            "href": route("compliance", "frameworks", brief["framework"], brief["id"])}
    return ctx.snap.memo["cyfun_latest"]


def external_frameworks(ctx: ResolveContext) -> list[dict[str, Any]]:
    """Frameworks a GRC tool (CISO Assistant) has loaded, with the result of its latest assessment."""
    from ..grc.frameworks import sync

    if "external_frameworks" not in ctx.snap.memo:
        out = []
        for f in sync.external_list(ctx.hub):
            latest = max(f.get("assessments") or [], key=lambda a: str(a.get("updated_at") or ""), default=None)
            results = (latest or {}).get("results") or {}
            rated = sum(results.get(k, 0) for k in ("compliant", "partially_compliant", "non_compliant"))
            out.append({"id": f["id"], "name": clean(f.get("name") or f["id"], 120),
                        "tool_id": f["source"]["tool_id"], "source_tool": clean(f["source"]["tool_name"], 80),
                        "assessments": len(f.get("assessments") or []),
                        "score": round(100 * results.get("compliant", 0) / rated) if rated else None,
                        "maturity": ((latest or {}).get("scores") or {}).get("maturity"),
                        "href": route("compliance", "frameworks", f["id"])})
        ctx.snap.memo["external_frameworks"] = out
    return ctx.snap.memo["external_frameworks"]


def resolve_compliance(ctx: ResolveContext, cfg: ComplianceConfig) -> dict[str, Any] | Outcome:
    from ..grc.checks import framework_scores

    tool_id = None
    if cfg.external.startswith("tool:"):
        tool_id, _ = tool_scope(ctx, cfg.external)
    wanted = BASELINE_FRAMEWORKS if cfg.frameworks == "all" else cfg.frameworks
    scores = framework_scores(ctx.snap.controls) if ctx.snap.controls else []
    frameworks = [{"id": f["id"], "name": FRAMEWORK_NAMES.get(f["id"], clean(f["name"], 80)), "score": f["score"],
                   "passing": f["passing"], "failing": f["failing"], "total": f["controls"],
                   "href": route("compliance", "frameworks", CYFUN_PAGES[f["id"]]) if f["id"] in CYFUN_PAGES
                   else "#/compliance"}
                  for f in scores if f["id"] in wanted]
    external = [] if cfg.external == "none" else [
        f for f in external_frameworks(ctx) if tool_id is None or f["tool_id"] == tool_id]
    data = {"frameworks": frameworks, "cyfun": cyfun_brief(ctx) if cfg.cyfun else None, "external": external,
            "evaluated": bool(ctx.snap.controls), "href": "#/compliance"}
    if not frameworks and not external and data["cyfun"] is None:
        hint = ({"text": "Evaluate the controls", "href": "#/compliance", "min_role": "operator"} if not tool_id
                else {"text": "Pull the frameworks from this tool", "href": route("tools", tool_id, "connection"),
                      "min_role": "admin"})
        return Outcome("empty", data, hint=hint)
    return data


# -- controls_status ------------------------------------------------------------------------------


class ControlsConfig(Strict):
    status: list[Literal[CONTROL_STATES]] = Field(default_factory=lambda: ["fail", "partial"],  # type: ignore[valid-type]
                                                  max_length=len(CONTROL_STATES))
    family: str | None = None
    limit: int = Field(10, ge=1, le=25)

    @field_validator("family")
    @classmethod
    def _family(cls, v: str | None) -> str | None:
        if not v:
            return None
        if v not in domains.BUILTIN["controls"].fields["family"].values:
            raise ValueError("is not a control family")
        return v


def resolve_controls(ctx: ResolveContext, cfg: ControlsConfig) -> dict[str, Any] | Outcome:
    rows = domains.BUILTIN["controls"].rows(ctx.snap)
    counts = dict.fromkeys(CONTROL_STATES, 0)
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    order = {s: n for n, s in enumerate(("fail", "partial", "manual", "pass", "na"))}
    picked = [r for r in rows if (not cfg.status or r["status"] in cfg.status)
              and (cfg.family is None or r["family"] == cfg.family)]
    picked.sort(key=lambda r: (order.get(r["status"], 9), r["id"]))
    from ..grc.baseline import CONTROLS_BY_ID

    details = {s.id: s.detail for s in ctx.snap.controls}
    data = {"counts": counts, "total": len(picked), "evaluated": bool(ctx.snap.controls), "href": "#/compliance/controls",
            "rows": [{"id": r["id"], "title": clean(r["title"], 200), "family": r["family"], "status": r["status"],
                      "detail": clean(details.get(r["id"], ""), 300),
                      "automated": CONTROLS_BY_ID[r["id"]].check is not None if r["id"] in CONTROLS_BY_ID else False}
                     for r in picked[:cfg.limit]]}
    if not ctx.snap.controls:
        return Outcome("empty", data, hint={"text": "Evaluate the controls", "href": "#/compliance/controls",
                                            "min_role": "operator"})
    return data


# -- risk_matrix ----------------------------------------------------------------------------------


class RiskMatrixConfig(Strict):
    source: str = Field("all", pattern=TOOL_SOURCE)
    status: list[Literal[RISK_STATES]] = Field(default_factory=lambda: ["open", "in_treatment"],  # type: ignore[valid-type]
                                               max_length=3)

    def check(self, hub: "Hub") -> None:
        check_source(hub, self.source)


def resolve_risk_matrix(ctx: ResolveContext, cfg: RiskMatrixConfig) -> dict[str, Any] | Outcome:
    """cells[likelihood - 1][impact - 1] = how many risks."""
    tool_id, label = tool_scope(ctx, cfg.source)
    spec = domains.BUILTIN["risks"]
    base = [r for r in spec.rows(ctx.snap)
            if (tool_id is None and cfg.source == "all") or (tool_id is not None and tool_id in spec.tools_of(r))
            or (cfg.source == "manual" and not spec.tools_of(r))]
    cells = [[0] * 5 for _ in range(5)]
    total = 0
    for r in base:
        if cfg.status and r["status"] not in cfg.status:
            continue
        likelihood, impact = int(r["likelihood"] or 3), int(r["impact"] or 3)
        if 1 <= likelihood <= 5 and 1 <= impact <= 5:
            cells[likelihood - 1][impact - 1] += 1
            total += 1
    data = {"cells": cells, "total": total, "source": cfg.source, "source_label": label, "href": "#/compliance/risks"}
    if not base:
        hint = ({"text": "Add a risk or connect a GRC tool", "href": "#/compliance/risks", "min_role": "operator"}
                if tool_id is None else {"text": f"Set up a data flow from {label}",
                                         "href": route("tools", tool_id, "connection"), "min_role": "admin"})
        return Outcome("empty", data, hint=hint)
    return data


# -- vuln_sla -------------------------------------------------------------------------------------


class SourceConfig(Strict):
    source: str = Field("all", pattern=TOOL_SOURCE)

    def check(self, hub: "Hub") -> None:
        check_source(hub, self.source)


def resolve_vuln_sla(ctx: ResolveContext, cfg: SourceConfig) -> dict[str, Any] | Outcome:
    """The SLA state of open findings (from every scanner or one), as the Vulnerabilities page shows it. Asset coverage
    (in scan scope, scanned in 30 days) is hub-wide: assets do not belong to a scanner."""
    tool_id, label = tool_scope(ctx, cfg.source)
    spec = domains.BUILTIN["vulnerabilities"]
    rows = [r for r in spec.rows(ctx.snap) if cfg.source == "all" or (tool_id is not None and tool_id in spec.tools_of(r))
            or (cfg.source == "manual" and not spec.tools_of(r))]
    now = ctx.now
    open_ = [r for r in rows if r["status"] in OPEN_STATES]
    assets = [a for a in ctx.snap.facts("assets", ("status", "scan_scope", "last_scanned_at")) if a["status"] != "retired"]
    in_scope = [a for a in assets if a["scan_scope"]]
    data = {"open": len(open_), "overdue": sum(1 for r in open_ if r["overdue"]),
            "by_severity": {s: sum(1 for r in open_ if r["severity"] == s) for s in SEVERITY_ORDER},
            "overdue_by_severity": {s: sum(1 for r in open_ if r["overdue"] and r["severity"] == s) for s in SEVERITY_ORDER},
            "sla_days": {s: ctx.hub.prefs["vuln_sla_days"].get(s) for s in SEVERITY_ORDER},
            "fixed_last_30_days": sum(1 for r in rows if r["fixed_at"] and r["fixed_at"] >= now - 30 * DAY),
            "in_scope_assets": len(in_scope),
            "scanned_last_30_days": sum(1 for a in in_scope if a["last_scanned_at"] and a["last_scanned_at"] >= now - 30 * DAY),
            "source": cfg.source, "source_label": label, "href": domains.vuln_link(
                {"status": list(OPEN_STATES), **({"source": tool_id or "manual"} if cfg.source != "all" else {})})}
    if not rows and not in_scope:
        hint = ({"text": "Put assets in scan scope or connect a scanner", "href": "#/vulnerabilities/scope",
                 "min_role": "operator"} if tool_id is None
                else {"text": f"Set up a data flow from {label}", "href": route("tools", tool_id, "connection"),
                      "min_role": "admin"})
        return Outcome("empty", data, hint=hint)
    return data


# -- network_overview -----------------------------------------------------------------------------


class NetworkConfig(Strict):
    tools: Literal["all"] | list[str] = "all"

    @field_validator("tools")
    @classmethod
    def _tools(cls, v: Any) -> Any:
        if isinstance(v, list):
            if not 1 <= len(v) <= 20:
                raise ValueError("lists 1 to 20 devices (or is \"all\")")
            if any(not re.match(TOOL_ID, x) for x in v):
                raise ValueError("holds an invalid tool id")
            return list(dict.fromkeys(v))
        return v

    def check(self, hub: "Hub") -> None:
        for tool_id in self.tools if isinstance(self.tools, list) else ():
            check_tool(hub, tool_id)


def resolve_network(ctx: ResolveContext, cfg: NetworkConfig) -> dict[str, Any] | Outcome:
    from ..integration import changes as device_changes

    everything = domains.devices(ctx.snap)
    wanted = None if cfg.tools == "all" else set(cfg.tools)
    if wanted is not None and not wanted & {t.id for t in ctx.snap.tools}:
        raise Unavailable("The devices this widget shows were removed.", "tool_removed")
    devices = [d for d in everything if wanted is None or d["tool_id"] in wanted]
    ids = {d["tool_id"] for d in devices}
    drift = [d for d in ctx.snap.drift if d.get("tool_id") in ids]
    changes = [c for c in ctx.snap.device_changes if c.get("firewall") in ids]
    by_id = {r["id"]: r for r in domains.BUILTIN["network"].rows(ctx.snap)}
    data = {
        "devices": [{"tool_id": d["tool_id"], "name": clean(d.get("name"), 120),
                     "product": clean(by_id[d["tool_id"]]["product"], 80) if by_id[d["tool_id"]]["product"] else None,
                     "snapshot_at": by_id[d["tool_id"]]["snapshot_at"], "stale": by_id[d["tool_id"]]["stale"],
                     "writable": by_id[d["tool_id"]]["writable"], "open_drift": by_id[d["tool_id"]]["open_drift"],
                     "critical_drift": by_id[d["tool_id"]]["critical_drift"],
                     "connection": (d.get("connection") or {}).get("state"), "href": route("network", d["tool_id"])}
                    for d in devices],
        "drift": {"open": sum(1 for d in drift if d.get("status") == "open"),
                  "attributed": sum(1 for d in drift if d.get("status") == "attributed"),
                  "acknowledged": sum(1 for d in drift if d.get("status") == "acknowledged"),
                  "critical_open": sum(1 for d in drift if d.get("status") == "open" and d.get("severity") == "critical")},
        "changes": {"proposed": sum(1 for c in changes if c.get("status") == "proposed"),
                    "scheduled": sum(1 for c in changes if c.get("status") in device_changes.DECIDED),
                    "verifying": sum(1 for c in changes if c.get("status") in device_changes.ACTIVE)},
        "device_changes_on": bool(ctx.hub.prefs["guardrails"].get("device_changes", False)),
        "href": "#/network",
    }
    if not devices:
        return Outcome("empty", data, hint={"text": "Connect a firewall or network device", "href": "#/network",
                                            "min_role": "operator"})
    return data


# -- leavers --------------------------------------------------------------------------------------


class LeaversConfig(Strict):
    limit: int = Field(8, ge=1, le=25)


def resolve_leavers(ctx: ResolveContext, cfg: LeaversConfig) -> dict[str, Any]:
    """People who left but still hold assets, tool accounts or an Atrium sign-in (no e-mail addresses)."""
    found = ctx.snap.leavers
    return {"total": len(found), "href": "#/people/leavers",
            "rows": [{"id": f["person_id"], "display_name": clean(f["display_name"], 120), "status": f["status"],
                      "severity": f["severity"], "terminated_at": f.get("terminated_at"),
                      "holds": {"assets": len(f["assets"]), "accounts": len(f["accounts"]),
                                "atrium_account": bool(f["atrium_accounts"])},
                      "href": route("people", f["person_id"])} for f in found[:cfg.limit]]}


# -- registration ---------------------------------------------------------------------------------

register(WidgetType(
    "compliance_overview", "Compliance", "Framework scores, the latest CyFun self-assessment and the frameworks your "
    "GRC tools hold.", "compliance", ComplianceConfig, resolve_compliance, (3, 2), (6, 3), (12, 6),
    fields=(FieldSpec("frameworks", "Hub frameworks", "multiselect",
                      options=options(*((k, FRAMEWORK_NAMES[k]) for k in BASELINE_FRAMEWORKS)),
                      hint="Scores of the Hub Security Baseline and the frameworks it maps to"),
            FieldSpec("external", "Frameworks from tools", "tool", domain="frameworks",
                      options=options(("all", "Every tool"), ("none", "None"))),
            FieldSpec("cyfun", "Latest CyFun self-assessment", "toggle")),
    events=("grc", "framework_assessment", "framework_assessment_removed", "external_framework",
            "external_framework_removed", "tool_removed"), ttl=60, title_for=lambda c: "Compliance"))
register(WidgetType(
    "controls_status", "Controls", "Controls of the Hub Security Baseline by status, failing ones first.", "compliance",
    ControlsConfig, resolve_controls, (3, 2), (6, 4), (12, 8),
    fields=(FieldSpec("status", "Status", "multiselect", options=options(
                ("fail", "Fail"), ("partial", "Partial"), ("manual", "To check by hand"), ("pass", "Pass"),
                ("na", "Not applicable")), hint="None selected: every status"),
            FieldSpec("family", "Family", "select", options=options(
                ("", "Every family"), *((f, f) for f in domains.BUILTIN["controls"].fields["family"].values))),
            LIMIT_FIELD(1, 25)),
    events=("grc",), ttl=60, title_for=lambda c: "Failing controls" if set(c.status) <= {"fail", "partial"} and c.status
    else "Controls"))
register(WidgetType(
    "risk_matrix", "Risk matrix", "Risks by likelihood and impact (5 x 5), from every source or one tool.", "compliance",
    RiskMatrixConfig, resolve_risk_matrix, (3, 3), (4, 4), (6, 6),
    fields=(FieldSpec("source", "From", "tool", domain="risks"),
            FieldSpec("status", "Status", "multiselect", options=options(
                ("open", "Open"), ("in_treatment", "In treatment"), ("closed", "Closed")),
                hint="None selected: every status")),
    events=("risk", "risk_removed", "tool_removed"), ttl=30, title_for=lambda c: "Risk matrix"))
register(WidgetType(
    "vuln_sla", "Vulnerability deadlines", "Open findings past their deadline by severity, fixes and scan coverage.",
    "compliance", SourceConfig, resolve_vuln_sla, (3, 2), (4, 3), (8, 5),
    fields=(FieldSpec("source", "From", "tool", domain="vulnerabilities"),),
    events=("vulnerability", "asset", "asset_removed", "settings", "tool_removed"), ttl=30, refresh=3600,
    title_for=lambda c: "Vulnerability deadlines"))
register(WidgetType(
    "network_overview", "Network devices", "Firewalls and network devices: last read, configuration drift and "
    "device changes.", "network", NetworkConfig, resolve_network, (3, 2), (6, 3), (12, 6),
    fields=(FieldSpec("tools", "Devices", "tools", domain="network", hint="All devices, or up to 20"),),
    events=("network_snapshot", "network_drift", "network_baseline", "firewall_change", "maintenance_window",
            "connection", "settings", "tool_removed"), ttl=30, refresh=300, title_for=lambda c: "Network devices"))
register(WidgetType(
    "leavers", "Leavers", "People who left but still hold assets, tool accounts or an Atrium sign-in.", "people",
    LeaversConfig, resolve_leavers, (3, 2), (4, 4), (12, 8), fields=(LIMIT_FIELD(1, 25),),
    events=("person", "person_removed", "asset", "asset_removed", "account", "accounts_removed"), ttl=30,
    title_for=lambda c: "Leavers"))
