"""GRC Supervisor: runs the compliance checks, keeps evidence current and raises risks automatically."""

from __future__ import annotations

import time
from typing import Any

from ..bus import Message
from ..extensions import controls as extension_controls
from ..grc.baseline import CONTROLS, CONTROLS_BY_ID
from ..grc.checks import Snapshot, evaluate_controls, framework_scores
from ..grc.frameworks import assessments as framework_assessments
from ..grc.frameworks import sync as framework_sync
from ..integration import flows
from ..integration import network as network_app
from .. import people
from ..models import Asset, ControlState, Flow, Patch, Policy, Risk, Vulnerability
from ..store import new_id
from .fabric import FlowOwner

TREATMENTS = ("mitigate", "accept", "transfer", "avoid")


class GrcSupervisor(FlowOwner):
    role = "module-supervisor"
    title = "GRC Supervisor"
    max_concurrency = 1  # evaluations must not interleave
    description = ("Responsible for the Compliance hub: evaluates controls against live hub state, collects evidence, "
                   "maps it to ISO 27001, SOC 2 and NIS2, opens or closes risks when controls fail or recover, pushes "
                   "controls and evidence to GRC tools, pulls their risk scenarios into the risk register, pulls the "
                   "frameworks they have loaded, and pushes CyFun self-assessments when that flow is on.")
    flow_domains = ("controls", "risks", "frameworks", "assessments")
    permissions = ("read", "tool_api", "flows", "grc_write", "agents")

    def __init__(self, hub):
        super().__init__(hub, "module:grc", "GRC Supervisor", scope="grc")

    def snapshot(self) -> Snapshot:
        hub = self.hub
        return Snapshot(
            tools=hub.tools(), hosts=hub.hosts(), assets=hub.all("assets", Asset), risks=hub.all("risks", Risk),
            policies=hub.all("policies", Policy), patches=hub.all("patches", Patch), autonomy=hub.prefs["autonomy"],
            audit_entries=hub.store.count("activity") + hub.store.count("messages"),
            users=hub.auth.users(), oidc_enabled=hub.auth.oidc.enabled,
            vulnerabilities=hub.all("vulnerabilities", Vulnerability), guardrails=hub.prefs["guardrails"],
            people=people.all_people(hub), accounts=people.all_accounts(hub),
            extension_results=extension_controls.evaluate(hub), network=self._network_facts(),
            frameworks=self._framework_facts(),
        )

    def _network_facts(self) -> dict[str, Any]:
        try:
            return network_app.compliance_facts(self.hub)
        except Exception as exc:  # the other controls must still be evaluated
            self.log("warn", f"Network compliance facts unavailable: {exc.__class__.__name__}: {exc}")
            return {}

    def _framework_facts(self) -> list[dict[str, Any]]:
        try:
            return framework_assessments.control_summaries(self.hub)
        except Exception as exc:
            self.log("warn", f"Framework assessment facts unavailable: {exc.__class__.__name__}: {exc}")
            return []

    # -- data flows ------------------------------------------------------------------

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.domain == "controls" and flow.direction == "push":
            states = self.hub.all("controls", ControlState)
            records = [control_record(c) for c in control_catalog(states)]
            return {"counts": await self.push_records(flow, records, label=lambda r: r["ref_id"])}
        if flow.domain == "risks" and flow.direction == "pull":
            return await self._pull_risks(flow)
        if flow.domain == "frameworks" and flow.direction == "pull":
            return await self._pull_frameworks(flow)
        if flow.domain == "assessments" and flow.direction == "push":
            return await self._push_assessments(flow)
        raise ValueError(f"The GRC Supervisor cannot {flow.direction} {flow.domain}")

    async def _pull_frameworks(self, flow: Flow) -> dict[str, Any]:
        """Store the frameworks a GRC tool has loaded. They stay read-only in the Compliance hub."""
        records, info = await self.pull_records(flow)
        counts = framework_sync.store(self.hub, flow.tool_id, records, bool(flow.options.get("retire_missing", True)))
        counts["dropped"] = info["dropped"]
        detail = ""
        if info["dropped"]:
            detail = f"{info['dropped']} record(s) could not be read: {'; '.join(info['errors'][:3])}"
        return {"counts": counts, "detail": detail}

    async def _push_assessments(self, flow: Flow) -> dict[str, Any]:
        """Send the hub's CyFun self-assessments. The connector writes them only when the connection allows it."""
        records = framework_sync.push_records(self.hub)
        counts = await self.push_records(flow, records, label=lambda r: r.get("name") or r["hub_id"])
        return {"counts": counts}

    async def _pull_risks(self, flow: Flow) -> dict[str, Any]:
        records, info = await self.pull_records(flow)
        tool_id, source = flow.tool_id, f"sync:{flow.tool_id}"
        tool = self.hub.get_tool(tool_id)
        known = flows.links(self.hub, tool_id, "risks")
        by_external = {link.external_id: hub_id for hub_id, link in known.items()}
        risks = {r.id: r for r in self.hub.all("risks", Risk)}
        counts = {"total": len(records), "created": 0, "updated": 0, "unchanged": 0, "closed": 0, "dropped": info["dropped"]}
        seen: set[str] = set()
        for record in records:
            digest = flows.content_hash(record)
            risk = risks.get(by_external.get(record["external_id"], ""))
            if risk is not None and known[risk.id].hash == digest:
                counts["unchanged"] += 1
                seen.add(risk.id)
                continue
            treatment = (record.get("treatment") or "").strip()
            description = record["description"]
            if treatment and treatment.lower() not in TREATMENTS:
                description = (description + "\n\n" if description else "") + f"Treatment: {treatment}"
            values = {"title": record["title"], "description": description, "likelihood": record["likelihood"],
                      "impact": record["impact"], "status": record["status"], "reviewed_at": time.time()}
            if treatment.lower() in TREATMENTS:
                values["treatment"] = treatment.lower()
            if risk is None:
                risk = Risk(id=new_id("r_"), source=source, category="security", **values)
                counts["created"] += 1
            else:
                risk = risk.model_copy(update=values)
                counts["updated"] += 1
            self.hub.save("risks", risk, "risk")
            flows.put_link(self.hub, tool_id, "risks", risk.id, record["external_id"], digest)
            seen.add(risk.id)
        if flow.options.get("retire_missing", True):
            for hub_id in set(known) - seen:
                risk = risks.get(hub_id)
                if risk is None:
                    flows.drop_link(self.hub, tool_id, "risks", hub_id)
                elif risk.source == source and risk.status != "closed":
                    risk.status = "closed"
                    risk.description += f"\nClosed: no longer in {tool.name if tool else tool_id}."
                    self.hub.save("risks", risk, "risk")
                    counts["closed"] += 1
        return {"counts": counts}

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


def control_record(control: dict[str, Any]) -> dict[str, Any]:
    """A catalog entry as a canonical control record (external_id and ref_id are the hub control id)."""
    evidence = [control["detail"]] if control.get("detail") else []
    evidence += [str(e) for e in control.get("evidence") or [] if str(e) not in evidence]
    if control.get("manual") and control.get("note"):
        evidence.append(f"Set by hand: {control['note']}")
    return {"hub_id": control["id"], "external_id": control["id"], "ref_id": control["id"], "name": control["title"],
            "description": control["description"], "status": control["status"], "evidence": evidence,
            "refs": control["refs"], "family": control["family"], "detail": control.get("detail") or "",
            "evaluated_at": control.get("evaluated_at")}


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
