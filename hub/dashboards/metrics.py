"""Metrics: the numbers of the KPI tiles (round4-dashboard-spec.md 6.3), and the counts ``GET /api/overview`` returns.

Both read the same helpers over a ``Snapshot``, so a tile on Home and the shell's badges can never disagree. Each metric
has a key, label, icon, link, value, subtext, tone (ok | warn | bad | None, always with text: the subtext says why) and
the bus events that change it. The seven metrics of the shared "Overview" dashboard reproduce the tiles of the Home page
before dashboards (labels, subtexts and links). Later stages add metrics with ``register`` (D4: ``llm_spend_today``).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from ..integration import changes as device_changes
from ..models import OPEN_STATES
from .resolve import Snapshot

Value = int | float | None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


# -- the shared counts ------------------------------------------------------------------------


def running(s: Snapshot) -> int:
    return sum(1 for t in s.tools if t.running)


def suite_score(s: Snapshot) -> int | None:
    scores = [t.report.score for t in s.tools if t.report]
    return round(sum(scores) / len(scores)) if scores else None


def agents_working(s: Snapshot) -> int:
    return sum(1 for a in s.agents if a.status == "working")


def approvals_pending(s: Snapshot) -> int:
    return sum(1 for a in s.approvals if a.status == "pending")


# The large collections are counted over a few fields read inside SQLite, not over parsed records (spec 8.3).
ASSET_FACTS = ("status",)
VULN_FACTS = ("status", "due_at")


def assets(s: Snapshot) -> int:
    return sum(1 for a in s.facts("assets", ASSET_FACTS) if a["status"] != "retired")


def compliance_score(s: Snapshot) -> int | None:
    from ..grc.checks import framework_scores

    return framework_scores(s.controls)[0]["score"] if s.controls else None


def risks_open(s: Snapshot) -> int:
    return sum(1 for r in s.risks if r.status != "closed")


def vulnerabilities_open(s: Snapshot) -> int:
    return sum(1 for v in s.facts("vulnerabilities", VULN_FACTS) if v["status"] in OPEN_STATES)


def vulnerabilities_overdue(s: Snapshot) -> int:
    """``Vulnerability.overdue`` over the two fields it reads (the stored ``overdue`` is as old as the record)."""
    now = time.time()
    return sum(1 for v in s.facts("vulnerabilities", VULN_FACTS)
               if v["status"] in OPEN_STATES and v["due_at"] is not None and v["due_at"] < now)


def flows_enabled(s: Snapshot) -> int:
    return sum(1 for f in s.flows if f.status == "enabled")


def flows_failing(s: Snapshot) -> int:
    return sum(1 for f in s.flows if f.status == "enabled" and (f.last_result or {}).get("ok") is False)


def extensions_enabled(s: Snapshot) -> int:
    return sum(1 for r in s.extensions if r.status == "enabled")


def drift_open(s: Snapshot) -> int:
    return sum(1 for d in s.drift if d.get("status") == "open")


def drift_critical(s: Snapshot) -> int:
    return sum(1 for d in s.drift if d.get("status") == "open" and d.get("severity") == "critical")


def device_changes_pending(s: Snapshot) -> int:
    return sum(1 for c in s.device_changes if c.get("status") in device_changes.WAITING)


def overview(s: Snapshot) -> dict[str, Any]:
    """The counts of GET /api/overview (its other keys - restart_required, llm, autonomy - stay in the route)."""
    return {
        "tools": len(s.tools),
        "running": running(s),
        "suite_score": suite_score(s),
        "agents": len(s.agents),
        "agents_working": agents_working(s),
        "approvals_pending": approvals_pending(s),
        "assets": assets(s),
        "compliance_score": compliance_score(s),
        "risks_open": risks_open(s),
        "vulnerabilities_open": vulnerabilities_open(s),
        "vulnerabilities_overdue": vulnerabilities_overdue(s),
        "flows_enabled": flows_enabled(s),
        "people": s.people_count,
        "leavers": len(s.leavers),
        "extensions": extensions_enabled(s),
        "extension_domains": len(s.ext_domains),
    }


# -- metrics --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Metric:
    key: str
    label: str
    icon: str  # an ICONS key of hub/web/js/ui.js
    events: tuple[str, ...]
    value: Callable[[Snapshot], Value]
    href: str | Callable[[Snapshot, Value], str]
    sub: Callable[[Snapshot, Value], str] = lambda s, v: ""
    tone: Callable[[Snapshot, Value], str | None] = lambda s, v: None
    unit: str | None = None  # shown after the value ("%")
    description: str = ""
    display: Callable[[Snapshot, Value], str] | None = None  # the value as shown, when not the plain number ("$4.20")
    hint: str = ""  # said with the label (its title and accessible name): "estimated"

    def data(self, s: Snapshot) -> dict[str, Any]:
        v = self.value(s)
        href = self.href(s, v) if callable(self.href) else self.href
        out = {"key": self.key, "value": v, "unit": self.unit, "label": self.label, "sub": self.sub(s, v),
               "href": href, "icon": self.icon, "tone": self.tone(s, v)}
        if self.display is not None:
            out["display"] = self.display(s, v)
        if self.hint:
            out["hint"] = self.hint
        return out

    def view(self) -> dict[str, Any]:
        return {"key": self.key, "label": self.label, "icon": self.icon, "description": self.description,
                "href": self.href if isinstance(self.href, str) else None}


METRICS: dict[str, Metric] = {}


def register(m: Metric) -> Metric:
    METRICS[m.key] = m
    return m


def _over(tone: str) -> Callable[[Snapshot, Value], str | None]:
    return lambda s, v: tone if v else None


register(Metric(
    "tools", "Apps integrated", "grid", ("tool", "tool_removed"), lambda s: len(s.tools), "#/tools",
    sub=lambda s, v: (f"suite score {suite_score(s)} - {running(s)} running" if suite_score(s) is not None
                      else "import your first tool"),
    description="Tools imported into the suite, with the average integration score"))
register(Metric(
    "agents", "Agents", "bot", ("agent", "agent_removed"), lambda s: len(s.agents), "#/agents",
    sub=lambda s, v: f"{agents_working(s)} working now", description="Agents in the hub and how many are working"))
register(Metric(
    "approvals_pending", "Awaiting approval", "checkCircle", ("approval",), approvals_pending, "#/approvals",
    sub=lambda s, v: "agent commands & patches", tone=_over("warn"), description="Decisions waiting for a person"))
register(Metric(
    "assets", "Assets", "box", ("asset", "asset_removed"), assets, "#/assets", sub=lambda s, v: "in the register",
    description="Assets in the register that are not retired"))
register(Metric(
    "people", "People", "contact", ("person", "person_removed", "asset", "account", "accounts_removed"),
    lambda s: s.people_count, lambda s, v: "#/people/leavers" if s.leavers else "#/people",
    sub=lambda s, v: (f"{_plural(len(s.leavers), 'leaver')} still holding something" if s.leavers
                      else "in the directory"),
    description="People in the directory, and leavers who still hold something"))
register(Metric(
    "leavers", "Leavers holding something", "contact", ("person", "person_removed", "asset", "account",
                                                        "accounts_removed"),
    lambda s: len(s.leavers), "#/people/leavers",
    sub=lambda s, v: "assets, accounts or sign-ins to take back" if v else "nobody",
    tone=_over("bad"), description="People who left but still hold assets, accounts or an Atrium sign-in"))
register(Metric(
    "vulnerabilities_open", "Vulnerabilities", "bug", ("vulnerability",), vulnerabilities_open, "#/vulnerabilities",
    sub=lambda s, v: (f"{vulnerabilities_overdue(s)} past their deadline" if vulnerabilities_overdue(s)
                      else "open findings"),
    description="Open findings, and how many are past their deadline"))
register(Metric(
    "vulnerabilities_overdue", "Past their deadline", "clock", ("vulnerability",), vulnerabilities_overdue,
    "#/vulnerabilities", sub=lambda s, v: "open findings past their fix deadline" if v else "none overdue",
    tone=_over("bad"), description="Open findings past the deadline of their severity"))
register(Metric(
    "compliance_score", "Compliance", "shield", ("grc", "risk"), compliance_score, "#/compliance",
    sub=lambda s, v: f"{risks_open(s)} open risks", unit="%",
    description="The Hub Security Baseline score, with the number of open risks"))
register(Metric(
    "risks_open", "Open risks", "flag", ("risk",), risks_open, "#/compliance/risks",
    sub=lambda s, v: "in the risk register", description="Risks that are not closed"))
register(Metric(
    "flows_enabled", "Data flows", "flow", ("flow", "flow_removed"), flows_enabled, "#/integration",
    sub=lambda s, v: f"{flows_failing(s)} failing" if flows_failing(s) else "enabled",
    description="Enabled data flows between tools and the hub"))
register(Metric(
    "flows_failing", "Failing data flows", "alert", ("flow", "flow_removed"), flows_failing, "#/integration",
    sub=lambda s, v: "their last run failed" if v else "all last runs worked", tone=_over("bad"),
    description="Enabled data flows whose last run failed"))
register(Metric(
    "drift_open", "Configuration drift", "activity", ("network_drift", "network_snapshot"), drift_open,
    "#/network/drift", sub=lambda s, v: (f"{drift_critical(s)} critical" if drift_critical(s)
                                         else "unexplained device changes" if v else "none open"),
    tone=_over("warn"), description="Open, unexplained configuration changes on network devices"))
register(Metric(
    "drift_critical", "Critical drift", "alert", ("network_drift", "network_snapshot"), drift_critical,
    "#/network/drift", sub=lambda s, v: "critical device changes nobody explained" if v else "none open",
    tone=_over("bad"), description="Open configuration drift of critical severity"))
register(Metric(
    "device_changes_pending", "Device changes waiting", "firewall", ("firewall_change",), device_changes_pending,
    "#/network/changes", sub=lambda s, v: "proposed, approved or scheduled",
    description="Firewall changes proposed, approved or scheduled and not applied yet"))
register(Metric(
    "extension_domains", "Extension apps", "puzzle", ("extension", "extension_removed"),
    lambda s: len(s.ext_domains), "#/extensions",
    sub=lambda s, v: f"from {_plural(extensions_enabled(s), 'enabled extension')}",
    description="Data types extension packs add as apps"))


# -- AI spending (stage D4, from R4-LLM's usage meter) --------------------------------------------


def llm_budget(s: Snapshot) -> dict[str, Any]:
    """Today's (UTC) estimated AI spending of every agent and the playground, with the suite's daily cap: R4-LLM's
    ``suite_budget`` - the numbers of GET /api/llm/usage - read once per request."""
    if "llm_budget" not in s.memo:
        s.memo["llm_budget"] = s.hub.llm.meter.suite_budget()
    return s.memo["llm_budget"]


def _usd(v: float | int | None, whole: bool = False) -> str:
    """"$4.20"; with `whole`, a round amount without cents ("$20", a limit)."""
    amount = float(v or 0)
    return f"${amount:,.0f}" if whole and amount.is_integer() else f"${amount:,.2f}"


def _spend_share(s: Snapshot) -> float | None:
    b = llm_budget(s)
    return b["spent_today"] / b["limit"] if b["limit"] else None


def _spend_sub(s: Snapshot, v: Value) -> str:
    b = llm_budget(s)
    if b["limit"] is None:
        return "no daily limit"
    if b["stopped"]:
        return f"daily limit of {_usd(b['limit'], True)} reached - AI calls stop until tomorrow (UTC)"
    share = _spend_share(s) or 0
    return f"of {_usd(b['limit'], True)} daily limit" + (f" - {round(share * 100)}% used" if share >= 0.8 else "")


def _spend_tone(s: Snapshot, v: Value) -> str | None:
    share = _spend_share(s)
    return None if share is None else "bad" if share >= 1 else "warn" if share >= 0.8 else None


register(Metric(
    "llm_spend_today", "AI spending today", "activity", ("llm_usage", "settings"),
    lambda s: llm_budget(s)["spent_today"], "#/settings/ai", sub=_spend_sub, tone=_spend_tone,
    display=lambda s, v: _usd(v), hint="estimated",
    description="Estimated cost of today's AI model calls (UTC day), against the suite's daily spending limit"))
