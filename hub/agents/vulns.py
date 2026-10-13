"""Vulnerability Supervisor: the Vulnerabilities app - scans of in-scope assets, findings from scanners and other
tools, remediation deadlines (SLA), and risks for critical findings that miss them."""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from .. import connectors
from ..bus import Message
from ..connectors.base import FAILED_SCAN_STATES
from ..integration import connections, flows
from ..models import OPEN_STATES, SEVERITY_ORDER, Asset, Flow, Risk, Vulnerability
from ..store import new_id
from .assets import address_index, scan_targets
from .fabric import FlowFailure, FlowOwner

DAY = 86400
SINCE_SLACK = 300  # the scanner's clock may be behind the hub's: pull results from a little before the scan started
SCAN_STATES = ("running", "awaiting_approval")


def due_at(first_seen: float, severity: str, sla_days: dict[str, int]) -> float | None:
    days = sla_days.get(severity)
    return first_seen + int(days) * DAY if days else None


def scanners(hub) -> list[dict[str, Any]]:
    """Tools whose connection can run scans, with their scan flow (if any)."""
    out = []
    by_tool = {f.tool_id: f for f in flows.all_flows(hub) if f.direction == "scan"}
    for conn in connections.all_connections(hub):
        tool = hub.get_tool(conn.id)
        try:
            can_scan = tool is not None and "scan" in connectors.connector_class(conn.kind).actions
        except connectors.ConnectorError:
            can_scan = False
        if can_scan and tool is not None:
            flow = by_tool.get(tool.id)
            out.append({"tool_id": tool.id, "name": tool.name, "kind": conn.kind, "flow_id": flow.id if flow else None,
                        "flow_status": flow.status if flow else None, "job": flow.job if flow else None,
                        "last_result": flow.last_result if flow else None})
    return out


def summary(hub) -> dict[str, Any]:
    now = time.time()
    vulns = hub.all("vulnerabilities", Vulnerability)
    open_ = [v for v in vulns if v.status in OPEN_STATES]
    assets = [a for a in hub.all("assets", Asset) if a.status != "retired"]
    in_scope = [a for a in assets if a.scan_scope]
    prefs = hub.prefs
    return {
        "open": len(open_),
        "by_severity": {s: sum(1 for v in open_ if v.severity == s) for s in SEVERITY_ORDER},
        "by_status": {s: sum(1 for v in vulns if v.status == s) for s in ("open", "in_progress", "accepted", "false_positive", "fixed")},
        "overdue": sum(1 for v in open_ if v.overdue),
        "overdue_by_severity": {s: sum(1 for v in open_ if v.overdue and v.severity == s) for s in SEVERITY_ORDER},
        "fixed_last_30_days": sum(1 for v in vulns if v.fixed_at and v.fixed_at >= now - 30 * DAY),
        "total": len(vulns),
        "sla_days": prefs["vuln_sla_days"],
        "assets": len(assets),
        "in_scope_assets": len(in_scope),
        "in_scope_without_address": sum(1 for a in in_scope if not scan_targets(a)),
        "scanned_last_30_days": sum(1 for a in in_scope if a.last_scanned_at and a.last_scanned_at >= now - 30 * DAY),
        "last_scan_at": max((a.last_scanned_at for a in assets if a.last_scanned_at), default=None),
        "scanners": scanners(hub),
        "scans_need_approval": prefs["autonomy"] != "autonomous" and bool(prefs["guardrails"].get("scans_need_approval", True)),
    }


def in_targets(host: str | None, targets: list[str]) -> bool:
    """Whether a finding's host is one of the scanned targets (an exact name or address, or inside a CIDR)."""
    if not host:
        return False
    host = host.strip().lower().rstrip(".")
    for target in targets:
        target = target.strip().lower().rstrip(".")
        if host == target:
            return True
        if "/" in target:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(target, strict=False):
                    return True
            except ValueError:
                continue
    return False


class VulnerabilitySupervisor(FlowOwner):
    role = "module-supervisor"
    title = "Vulnerability Supervisor"
    description = ("Responsible for the Vulnerabilities app: has scanners scan the assets in scan scope (with approval), "
                   "imports their findings, tracks remediation deadlines, marks findings fixed when a rescan no longer "
                   "finds them, raises risks for critical findings past their SLA, and shares findings with GRC tools.")
    flow_domains = ("vulnerabilities",)
    permissions = ("read", "tool_api", "flows", "assets_write", "grc_write", "agents")

    def __init__(self, hub):
        super().__init__(hub, "module:vulns", "Vulnerability Supervisor", scope="vulnerabilities")

    def _vulns(self) -> list[Vulnerability]:
        return self.hub.all("vulnerabilities", Vulnerability)

    def _save(self, vuln: Vulnerability) -> Vulnerability:
        return self.hub.save("vulnerabilities", vuln, "vulnerability")

    # -- flows -----------------------------------------------------------------------

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        if flow.direction == "scan":
            return await self._scan(flow, body, msg)
        if flow.direction == "pull":
            records, info = await self.pull_records(flow)
            complete = not info["dropped"]  # with unreadable records, "missing" proves nothing
            counts = self.import_findings(flow.tool_id, records, include_info=bool(flow.options.get("include_info")),
                                          missing_fixed=complete and flow.options.get("retire_missing", True))
            counts["dropped"] = info["dropped"]
            await self._after_change()
            return {"counts": counts}
        rank = SEVERITY_ORDER.index(flow.options.get("min_severity") or "low")
        assets = {a.id: a for a in self.hub.all("assets", Asset)}
        tool_names = {t.id: t.name for t in self.hub.tools()}
        records = [push_record(v, assets, tool_names) for v in self._vulns()
                   if v.source != flow.tool_id and SEVERITY_ORDER.index(v.severity) <= rank]
        return {"counts": await self.push_records(flow, records, label=lambda r: r["title"])}

    async def _scan(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        job = flow.job or {}
        if job.get("status") == "running":
            return await self._poll(flow)
        if job.get("status") == "awaiting_approval":
            return {"pending": True, "detail": "The scan is waiting for approval."}
        assets = self._in_scope(body.get("asset_ids"))
        if not assets:
            raise FlowFailure("No assets are in scan scope - put the assets to scan in scope first.", count=False)
        hosts = sorted({t for a in assets for t in scan_targets(a)})
        if not hosts:
            raise FlowFailure("None of the in-scope assets has an IP address or hostname to scan.", count=False)
        asset_ids = [a.id for a in assets if scan_targets(a)]
        prefs = self.hub.prefs
        from_person = msg.sender.startswith("user:")  # a person pressing "Scan now" decides themselves
        if prefs["autonomy"] != "autonomous" and prefs["guardrails"].get("scans_need_approval", True) and not from_person:
            tool = self.hub.get_tool(flow.tool_id)
            name = tool.name if tool else flow.tool_id
            shown = ", ".join(hosts[:12]) + (f" and {len(hosts) - 12} more" if len(hosts) > 12 else "")
            approval = self.hub.approvals.create(
                "scan", f"Scan {len(asset_ids)} asset(s) with {name}",
                f"{name} actively scans these hosts for vulnerabilities: {shown}. Scans can load the scanned systems.",
                {"flow_id": flow.id, "tool_id": flow.tool_id, "asset_ids": asset_ids, "hosts": hosts,
                 "origin": msg.sender}, self.id)
            current = flows.get(self.hub, flow.id) or flow
            current.job = {"status": "awaiting_approval", "approval_id": approval.id, "asset_ids": asset_ids,
                           "hosts": hosts, "requested_at": time.time(), "requested_by": msg.sender}
            flows.save(self.hub, current)
            return {"pending": True, "detail": "The scan is waiting for approval.", "approval_id": approval.id}
        return await self._start(flow, asset_ids, hosts)

    def _in_scope(self, asset_ids: list[str] | None) -> list[Asset]:
        scope = [a for a in self.hub.all("assets", Asset) if a.scan_scope and a.status != "retired"]
        if asset_ids:
            wanted = set(asset_ids)
            scope = [a for a in scope if a.id in wanted]
        return scope

    async def _start(self, flow: Flow, asset_ids: list[str], hosts: list[str], approval_id: str | None = None) -> dict[str, Any]:
        name = flow.options.get("scan_name") or f"Atrium scan {time.strftime('%Y-%m-%d %H:%M', time.gmtime())}"
        started = time.time()
        reply = await self.connector(flow.tool_id, "action", {"name": "scan", "params": {"hosts": hosts, "name": name}})
        job_id = (reply.get("result") or {}).get("job_id")
        if not job_id:
            raise FlowFailure("The scanner started no scan (its answer has no job id).")
        current = flows.get(self.hub, flow.id) or flow
        current.job = {"status": "running", "job_id": str(job_id), "started_at": started, "hosts": hosts,
                       "asset_ids": asset_ids, "progress": 0, "approval_id": approval_id}
        flows.save(self.hub, current)
        self.log("info", f"Started a vulnerability scan of {len(hosts)} host(s): {current.title}", flow_id=flow.id)
        return {"pending": True, "detail": f"Scan of {len(hosts)} host(s) started.", "job_id": str(job_id)}

    async def _poll(self, flow: Flow) -> dict[str, Any]:
        job = dict(flow.job or {})
        reply = await self.connector(flow.tool_id, "action", {"name": "scan_status", "params": {"job_id": job["job_id"]}})
        status = reply.get("result") or {}
        state = str(status.get("status") or "").lower()
        if state in FAILED_SCAN_STATES:
            self._set_job(flow.id, None)
            if job.get("approval_id"):
                self.hub.approvals.complete(job["approval_id"], False, {"job_id": job["job_id"], "status": state})
            detail = " ".join(str(status.get("detail") or "").split())
            text = f"The scan {state} in the scanner (job {job['job_id']})."
            if detail:
                text = f"{text} {detail}"
            raise FlowFailure(text)
        if not status.get("done"):
            job.update({"progress": status.get("progress"), "scanner_status": status.get("status")})
            self._set_job(flow.id, job)
            return {"pending": True, "detail": f"Scan {state or 'running'} ({status.get('progress') or 0}%)."}
        records, info = await self.pull_records(flow, since=float(job["started_at"]) - SINCE_SLACK)
        complete = not info["dropped"]  # with unreadable results, "missing" proves nothing
        counts = self.import_findings(flow.tool_id, records, include_info=bool(flow.options.get("include_info")),
                                      scanned=(job.get("hosts") or []) if complete else None,
                                      scanned_assets=job.get("asset_ids") or [])
        counts["dropped"] = info["dropped"]
        now = time.time()
        scanned_ids = set(job.get("asset_ids") or [])
        for asset in self.hub.all("assets", Asset):
            if asset.id in scanned_ids:
                asset.last_scanned_at = now
                self.hub.save("assets", asset, "asset")
        self._set_job(flow.id, None)
        if job.get("approval_id"):
            self.hub.approvals.complete(job["approval_id"], True, {"job_id": job["job_id"], "counts": counts})
        await self._after_change()
        return {"counts": counts, "detail": f"Scan of {len(job.get('hosts') or [])} host(s) finished."}

    def _set_job(self, flow_id: str, job: dict[str, Any] | None) -> None:
        current = flows.get(self.hub, flow_id)
        if current is not None:
            current.job = job
            flows.save(self.hub, current)

    async def on_scan_poll(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        flow = flows.get(self.hub, str(body.get("flow_id")))
        if flow is None or not flow.job or flow.job.get("status") != "running":
            return {"status": "idle"}
        return await self.on_flow_run({"flow_id": flow.id, "trigger": "scan"}, msg)

    async def on_scan_request(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """"Scan now": the chosen (or only) scanner scans the given in-scope assets, or all of them."""
        available = scanners(self.hub)
        wanted = body.get("scanner_tool_id")
        if wanted:
            scanner = next((s for s in available if s["tool_id"] == wanted), None)
            if scanner is None:
                raise ValueError(f"'{wanted}' is not a connected vulnerability scanner")
        elif len(available) == 1:
            scanner = available[0]
        elif not available:
            raise ValueError("Connect a vulnerability scanner (such as OpenVAS / Greenbone) in its tool's Connection tab first")
        else:
            raise ValueError("Choose the scanner: " + ", ".join(s["name"] for s in available))
        asset_ids = list(body.get("asset_ids") or [])
        in_scope = {a.id for a in self._in_scope(None)}
        outside = [i for i in asset_ids if i not in in_scope]
        if outside:
            raise ValueError(f"Only assets in scan scope are scanned; not in scope: {', '.join(outside[:10])}")
        if not (asset_ids or in_scope):
            raise ValueError("No assets are in scan scope - put the assets to scan in scope first")
        flow = flows.get(self.hub, scanner["flow_id"]) if scanner["flow_id"] else None
        if flow is None:  # a scan by hand needs no schedule: the flow is created switched off
            flow = flows.make(self.hub, "vulnerabilities", "hub", f"tool:{scanner['tool_id']}", "scan",
                              created_by=msg.sender, status="disabled",
                              reason="Created for a scan requested by hand; enable it to scan on a schedule.")
            flows.save(self.hub, flow)
        if flow.job and flow.job.get("status") in SCAN_STATES:
            return {"ok": True, "pending": True, "detail": f"A scan is already {flow.job['status'].replace('_', ' ')}.",
                    "flow": flows.public(self.hub, flow)}
        return await self.on_flow_run({"flow_id": flow.id, "trigger": "manual", "asset_ids": asset_ids}, msg)

    async def on_approval_decided(self, body: dict[str, Any], msg: Message) -> None:
        approval = self.hub.approvals.get(body["approval_id"])
        if approval is None or approval.kind != "scan":
            return
        flow = flows.get(self.hub, approval.payload.get("flow_id", ""))
        if flow is None or not flow.job or flow.job.get("approval_id") != approval.id:
            return
        async with self._flow_locks.setdefault(flow.id, asyncio.Lock()):
            started = time.time()
            if not body.get("approved"):
                self._set_job(flow.id, None)
                await self.record_failure(flow.id, FlowFailure("The scan was rejected.", count=False), "approval", started)
                return
            flows.begin(self.hub, flow.id)
            try:
                await self._start(flow, list(approval.payload.get("asset_ids") or []),
                                  list(approval.payload.get("hosts") or []), approval.id)
            except FlowFailure as exc:
                self._set_job(flow.id, None)
                self.hub.approvals.complete(approval.id, False, {"error": exc.message})
                await self.record_failure(flow.id, exc, "approval", started)
                return
            current = flows.get(self.hub, flow.id)
            if current:
                current.running = None
                flows.save(self.hub, current)

    # -- findings --------------------------------------------------------------------

    def import_findings(self, tool_id: str, records: list[dict[str, Any]], *, include_info: bool = False,
                        scanned: list[str] | None = None, scanned_assets: list[str] | None = None,
                        missing_fixed: bool = False) -> dict[str, int]:
        """Merge canonical vulnerability records from `tool_id`. After a completed scan (`scanned` hosts), an open
        finding of a scanned host that the scan no longer reports is fixed; after a full pull (`missing_fixed`), so is
        every open finding of that tool that disappeared."""
        now = time.time()
        sla = self.hub.prefs["vuln_sla_days"]
        existing = {(v.source, v.external_id): v for v in self._vulns()}
        index = address_index(self.hub.all("assets", Asset))
        counts = {"total": len(records), "new": 0, "updated": 0, "reopened": 0, "fixed": 0, "ignored": 0}
        seen: set[str] = set()
        stamp = time.strftime("%Y-%m-%d", time.gmtime(now))
        for record in records:
            if record["severity"] == "info" and not include_info:
                counts["ignored"] += 1
                continue
            host = (record.get("host") or "").strip()
            asset_id = index.get(host.lower().rstrip(".")) if host else None
            vuln = existing.get((tool_id, record["external_id"]))
            values = {"title": record["title"], "severity": record["severity"], "cvss": record.get("cvss"),
                      "cves": record.get("cves") or [], "host": host or None, "port": record.get("port"),
                      "description": record.get("description") or "", "solution": record.get("solution") or ""}
            if vuln is None:
                first = min(now, record.get("detected_at") or now)
                vuln = Vulnerability(id=new_id("v_"), source=tool_id, external_id=record["external_id"], asset_id=asset_id,
                                     first_seen=first, last_seen=now, due_at=due_at(first, record["severity"], sla), **values)
                counts["new"] += 1
            else:
                severity_changed = vuln.severity != record["severity"]
                vuln = vuln.model_copy(update={**values, "last_seen": now, "asset_id": vuln.asset_id or asset_id})
                if severity_changed:
                    vuln.due_at = due_at(vuln.first_seen, vuln.severity, sla)
                if vuln.status == "fixed":
                    vuln.status, vuln.fixed_at = "open", None
                    vuln.note = ((vuln.note + "\n") if vuln.note else "") + f"Reopened: found again on {stamp}."
                    counts["reopened"] += 1
                else:
                    counts["updated"] += 1
            self._save(vuln)
            seen.add(vuln.id)
        if scanned is not None or missing_fixed:
            assets = set(scanned_assets or [])
            for vuln in self._vulns():
                if vuln.source != tool_id or vuln.status not in OPEN_STATES or vuln.id in seen:
                    continue
                if missing_fixed or in_targets(vuln.host, scanned or []) or (vuln.asset_id and vuln.asset_id in assets):
                    vuln.status, vuln.fixed_at = "fixed", now
                    reason = "the rescan no longer finds it" if scanned is not None else "the tool no longer reports it"
                    vuln.note = ((vuln.note + "\n") if vuln.note else "") + f"Fixed automatically on {stamp}: {reason}."
                    self._save(vuln)
                    counts["fixed"] += 1
        if counts["new"] or counts["reopened"] or counts["fixed"]:
            self.log("info", f"Findings from {tool_id}: {counts['new']} new, {counts['reopened']} reopened, "
                             f"{counts['fixed']} fixed")
        return counts

    async def _after_change(self) -> None:
        self.reconcile_risks()
        await self.tell("module:grc", "evaluate")

    # -- SLA and risks ---------------------------------------------------------------

    async def on_sla_check(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        opened, closed = self.reconcile_risks()
        await self.tell("module:grc", "evaluate")
        return {"risks_opened": opened, "risks_closed": closed}

    async def on_reconcile(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """A person changed a finding: re-check the risks and compliance."""
        return await self.on_sla_check(body, msg)

    async def on_sla_recompute(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        """The SLA days changed: new deadlines for findings that are still open."""
        sla = self.hub.prefs["vuln_sla_days"]
        changed = 0
        for vuln in self._vulns():
            due = due_at(vuln.first_seen, vuln.severity, sla)
            if vuln.status in OPEN_STATES and due != vuln.due_at:
                vuln.due_at = due
                self._save(vuln)
                changed += 1
        return {"changed": changed, **(await self.on_sla_check(body, msg))}

    def reconcile_risks(self) -> tuple[int, int]:
        """One risk per asset (or host) with open critical findings past their SLA; closed once there are none."""
        now = time.time()
        assets = {a.id: a for a in self.hub.all("assets", Asset)}
        groups: dict[str, list[Vulnerability]] = {}
        for vuln in self._vulns():
            if vuln.severity == "critical" and vuln.status in OPEN_STATES and vuln.due_at and vuln.due_at < now:
                groups.setdefault(f"vuln:{vuln.asset_id or vuln.host or 'unknown'}", []).append(vuln)
        existing = {r.source: r for r in self.hub.all("risks", Risk) if r.source.startswith("vuln:")}
        opened = closed = 0
        for source, items in groups.items():
            first = items[0]
            name = assets[first.asset_id].name if first.asset_id in assets else (first.host or "an unknown host")
            lines = [f"- {v.title}" + (f" ({', '.join(v.cves[:3])})" if v.cves else "") + " - due "
                     + time.strftime("%Y-%m-%d", time.gmtime(v.due_at or now)) for v in items[:10]]
            description = (f"Raised automatically: {len(items)} critical finding(s) on {name} are past their "
                           f"remediation deadline.\n" + "\n".join(lines))
            risk = existing.get(source)
            if risk is None or risk.status == "closed":
                risk = risk or Risk(id=new_id("r_"), title=f"Overdue critical vulnerabilities on {name}", likelihood=4,
                                    impact=5, category="vulnerability", source=source,
                                    asset_ids=[first.asset_id] if first.asset_id else [])
                risk.status, risk.description, risk.reviewed_at = "open", description, now
                self.hub.save("risks", risk, "risk")
                opened += 1
            elif risk.description != description:
                risk.description = description
                self.hub.save("risks", risk, "risk")
        for source, risk in existing.items():
            if source not in groups and risk.status != "closed":
                risk.status = "closed"
                risk.description += "\nClosed automatically: no critical finding is past its deadline any more."
                self.hub.save("risks", risk, "risk")
                closed += 1
        if opened or closed:
            self.log("info", f"Vulnerability risks: {opened} opened, {closed} closed")
        return opened, closed


def push_record(vuln: Vulnerability, assets: dict[str, Asset], tool_names: dict[str, str]) -> dict[str, Any]:
    asset = assets.get(vuln.asset_id or "")
    return {"hub_id": vuln.id, "external_id": None, "title": vuln.title, "severity": vuln.severity, "cvss": vuln.cvss,
            "cves": vuln.cves, "host": vuln.host, "port": vuln.port, "description": vuln.description,
            "solution": vuln.solution, "detected_at": vuln.first_seen, "scanner": tool_names.get(vuln.source, vuln.source),
            "status": vuln.status, "asset": asset.name if asset else None, "due_at": vuln.due_at,
            "first_seen": vuln.first_seen}
