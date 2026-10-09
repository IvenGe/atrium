"""GRC Supervisor: runs the compliance checks, keeps evidence current and raises risks automatically."""

from __future__ import annotations

import time
from typing import Any

from ..bus import Message
from ..grc.baseline import CONTROLS, CONTROLS_BY_ID
from ..grc.checks import Snapshot, evaluate_controls, framework_scores
from ..models import Asset, ControlState, Patch, Policy, Risk
from ..store import new_id
from .base import BaseAgent


class GrcSupervisor(BaseAgent):
    role = "module-supervisor"
    title = "GRC Supervisor"
    max_concurrency = 1  # evaluations must not interleave
    description = ("Responsible for the Compliance hub: evaluates controls against live hub state, collects evidence, "
                   "maps it to ISO 27001, SOC 2 and NIS2, and opens or closes risks when controls fail or recover.")

    def __init__(self, hub):
        super().__init__(hub, "module:grc", "GRC Supervisor", scope="grc")

    def snapshot(self) -> Snapshot:
        hub = self.hub
        return Snapshot(
            tools=hub.tools(), hosts=hub.hosts(), assets=hub.all("assets", Asset), risks=hub.all("risks", Risk),
            policies=hub.all("policies", Policy), patches=hub.all("patches", Patch), autonomy=hub.prefs["autonomy"],
            audit_entries=hub.store.count("activity") + hub.store.count("messages"),
            users=hub.auth.users(), oidc_enabled=hub.auth.oidc.enabled,
        )

    async def on_evaluate(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        overrides = {s.id: s for s in self.hub.all("controls", ControlState)}
        states = evaluate_controls(self.snapshot(), overrides)
        changed = []
        for state in states:
            previous = overrides.get(state.id)
            if previous is None or previous.status != state.status:
                changed.append(state)
            self.hub.store.put("controls", state.model_dump(mode="json"))
        opened, closed = self._reconcile_risks(states)
        scores = framework_scores(states)
        self.hub.bus.publish("grc", {"frameworks": scores})
        if changed and overrides:  # stay quiet on the very first evaluation
            moves = ", ".join(f"{s.id} -> {s.status}" for s in changed[:6])
            self.log("info", f"Compliance changed: {moves}" + (f"; {opened} risk(s) opened" if opened else "")
                     + (f"; {closed} risk(s) closed" if closed else ""))
        return {"frameworks": scores, "changed": [s.id for s in changed], "risks_opened": opened, "risks_closed": closed}

    async def on_summary(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        states = self.hub.all("controls", ControlState)
        risks = self.hub.all("risks", Risk)
        open_risks = sorted((r for r in risks if r.status != "closed"), key=lambda r: r.score, reverse=True)
        return {
            "frameworks": framework_scores(states) if states else [],
            "failing_controls": [f"{s.id} {CONTROLS_BY_ID[s.id].title}: {s.detail}" for s in states
                                 if s.status in ("fail", "partial") and s.id in CONTROLS_BY_ID],
            "top_risks": [f"{r.title} (score {r.score})" for r in open_risks[:5]],
        }

    def _reconcile_risks(self, states: list[ControlState]) -> tuple[int, int]:
        risks = {r.source: r for r in self.hub.all("risks", Risk) if r.source.startswith("auto:")}
        opened = closed = 0
        for state in states:
            control = CONTROLS_BY_ID[state.id]
            if not control.risk:
                continue
            source = f"auto:{control.id}"
            risk = risks.get(source)
            failing = state.status in ("fail", "partial")
            if failing and (risk is None or risk.status == "closed"):
                title, likelihood, impact = control.risk
                risk = risk or Risk(id=new_id("r_"), title=title, likelihood=likelihood, impact=impact,
                                    source=source, control_ids=[control.id], category=control.family.lower())
                risk.status = "open"
                risk.description = f"Raised automatically because control {control.id} is {state.status}: {state.detail}"
                risk.reviewed_at = time.time()
                self.hub.save("risks", risk, "risk")
                opened += 1
            elif failing and risk is not None:
                detail = f"Raised automatically because control {control.id} is {state.status}: {state.detail}"
                if risk.description != detail:
                    risk.description = detail
                    self.hub.save("risks", risk, "risk")
            elif not failing and risk is not None and risk.status != "closed" and state.status == "pass":
                risk.status = "closed"
                risk.description += f"\nClosed automatically: control {control.id} now passes."
                self.hub.save("risks", risk, "risk")
                closed += 1
        return opened, closed


def control_catalog(states: list[ControlState]) -> list[dict[str, Any]]:
    by_id = {s.id: s for s in states}
    out = []
    for control in CONTROLS:
        state = by_id.get(control.id) or ControlState(id=control.id)
        out.append({
            "id": control.id, "family": control.family, "title": control.title, "description": control.description,
            "automated": control.check is not None, "refs": control.refs, **state.model_dump(exclude={"id"}),
        })
    return out
