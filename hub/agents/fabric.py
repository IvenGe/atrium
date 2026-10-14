"""What every module agent that owns a data domain shares: running its data flows through the tool supervisors."""

from __future__ import annotations

import asyncio
import time
from typing import Any

from ..bus import AgentError, Message
from ..connectors.base import redact
from ..integration import flows
from ..models import Flow
from .base import BaseAgent


class FlowFailure(Exception):
    """A flow run that failed. `count` says whether it tells something about the integration (it then counts toward
    a repair); `sample` is a sanitized example of what was sent or received."""

    def __init__(self, message: str, *, status: int | None = None, excerpt: str | None = None,
                 counts: dict[str, Any] | None = None, sample: Any = None, count: bool = True):
        super().__init__(message)
        self.message, self.status, self.excerpt = message, status, excerpt
        self.counts, self.sample, self.count = counts or {}, sample, count

    def as_dict(self) -> dict[str, Any]:
        return {"message": self.message, "status": self.status, "excerpt": self.excerpt}


class FlowOwner(BaseAgent):
    """Base of the module agents that own a data domain. Subclasses set `flow_domains` and implement `execute`,
    which returns {"counts", "detail"} for a finished run, or {"pending": True, "detail"} when the run continues
    later (a scan in progress, a scan awaiting approval)."""

    flow_domains: tuple[str, ...] = ()

    def __init__(self, hub, agent_id: str, name: str, scope: str | None = None):
        super().__init__(hub, agent_id, name, scope)
        self._flow_locks: dict[str, asyncio.Lock] = {}

    @property
    def team(self) -> str:
        return self.id  # each built-in app's supervisor leads that app's team

    async def execute(self, flow: Flow, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        raise NotImplementedError

    def owns(self, domain: str) -> bool:
        return domain in self.flow_domains

    # -- talking to the tool's supervisor ------------------------------------------------

    async def connector(self, tool_id: str, op: str, body: dict[str, Any], timeout: float = 900) -> dict[str, Any]:
        try:
            reply = await self.ask(f"tool:{tool_id}", f"connector.{op}", body, timeout)
        except AgentError as exc:
            raise FlowFailure(f"The tool's supervisor could not {op}: {exc}") from exc
        failure = reply.get("failure")
        if failure:
            raise FlowFailure(failure.get("message") or f"connector.{op} failed", status=failure.get("status"),
                              excerpt=failure.get("excerpt"))
        return reply

    async def pull_records(self, flow: Flow, since: float | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        reply = await self.connector(flow.tool_id, "pull", {"domain": flow.domain, "since": since})
        return list(reply.get("records") or []), {"dropped": reply.get("dropped", 0), "errors": reply.get("errors", [])}

    async def push_records(self, flow: Flow, records: list[dict[str, Any]], label=lambda r: r.get("name") or r["hub_id"]) -> dict[str, int]:
        """Send the records that changed since their last successful push; keep the links the tool answers with.
        Records the tool rejects fail the run with its messages verbatim (minus secrets)."""
        tool_id, domain = flow.tool_id, flow.domain
        known = flows.links(self.hub, tool_id, domain)
        counts = {"total": len(records), "created": 0, "updated": 0, "skipped": 0, "failed": 0}
        hashes, send = {}, []
        for record in records:
            digest = flows.content_hash(record)
            link = known.get(record["hub_id"])
            if link and link.hash == digest:
                counts["skipped"] += 1
                continue
            if domain != "controls":
                record = {**record, "external_id": link.external_id if link else None}
            hashes[record["hub_id"]] = digest
            send.append(record)
        if not send:
            return counts
        reply = await self.connector(tool_id, "push", {"domain": domain, "records": send,
                                                        "links": {h: link.external_id for h, link in known.items()}})
        by_id = {r["hub_id"]: r for r in send}
        errors, failed = [], []
        for result in reply.get("results") or []:
            hub_id, action = result.get("hub_id"), result.get("action", "failed")
            counts[action] = counts.get(action, 0) + 1
            if action in ("created", "updated") and hub_id in by_id and result.get("external_id"):
                flows.put_link(self.hub, tool_id, domain, hub_id, str(result["external_id"]), hashes.get(hub_id))
            elif action == "failed":
                errors.append(f"{label(by_id[hub_id]) if hub_id in by_id else hub_id}: {result.get('error') or 'rejected'}")
                failed.append(by_id.get(hub_id))
        if errors:
            shown = "; ".join(errors[:3]) + (f" (and {len(errors) - 3} more)" if len(errors) > 3 else "")
            raise FlowFailure(f"{len(errors)} of {len(send)} record(s) were rejected: {shown}", counts=counts,
                              sample={"records": flows.sanitize([r for r in failed if r][:2])})
        return counts

    # -- running -------------------------------------------------------------------------

    async def on_flow_run(self, body: dict[str, Any], msg: Message) -> dict[str, Any]:
        flow_id = str(body.get("flow_id"))
        flow = flows.get(self.hub, flow_id)
        if flow is None:
            raise ValueError(f"Unknown flow '{flow_id}'")
        if not self.owns(flow.domain):
            raise ValueError(f"{self.name} does not own {flow.domain} flows")
        trigger = str(body.get("trigger") or ("manual" if msg.sender.startswith(("user:", "token:")) else "agent"))
        async with self._flow_locks.setdefault(flow_id, asyncio.Lock()):
            current = flows.get(self.hub, flow_id)
            if trigger != "manual" and current is not None and current.status != "enabled" and not current.job:
                # disabled (or still proposed) since the run was asked for - e.g. queued while this agent was paused:
                # only a person running it by hand runs it now (F25)
                current.running = None
                flows.save(self.hub, current)
                return {"ok": False, "skipped": True, "detail": f"Not run: the flow is {current.status}",
                        "flow": self._public(flow_id)}
            flow = flows.begin(self.hub, flow_id)
            started = time.time()
            try:
                outcome = await self.execute(flow, body, msg)
            except FlowFailure as exc:
                return await self.record_failure(flow_id, exc, trigger, started)
            except Exception as exc:  # a bug or an unexpected answer: recorded like any failure, never raised blind
                failure = FlowFailure(redact(f"{exc.__class__.__name__}: {exc}"))
                return await self.record_failure(flow_id, failure, trigger, started)
            if outcome.get("pending"):
                current = flows.get(self.hub, flow_id)
                if current:
                    current.running = None
                    flows.save(self.hub, current)
                return {"ok": True, "pending": True, "detail": outcome.get("detail", ""), "flow": self._public(flow_id)}
            return await self.record_success(flow_id, outcome.get("counts", {}), trigger, started, outcome.get("detail", ""))

    async def record_success(self, flow_id: str, counts: dict[str, Any], trigger: str, started: float,
                             detail: str = "") -> dict[str, Any]:
        flow = flows.finish(self.hub, flow_id, ok=True, counts=counts, trigger=trigger, started=started, detail=detail)
        if flow is not None:
            moved = ", ".join(f"{v} {k}" for k, v in counts.items() if v and k != "total") or "nothing changed"
            self.log("info", f"Flow '{flow.title}': {moved}", flow_id=flow_id)
        return {"ok": True, "detail": detail, "counts": counts, "flow": self._public(flow_id)}

    async def record_failure(self, flow_id: str, exc: FlowFailure, trigger: str, started: float) -> dict[str, Any]:
        flow = flows.finish(self.hub, flow_id, ok=False, counts=exc.counts, trigger=trigger, started=started,
                            error=exc.as_dict(), count_failure=exc.count, sample=exc.sample)
        if flow is not None:
            self.log("warn" if exc.count else "info", f"Flow '{flow.title}' failed: {exc.message}", flow_id=flow_id)
            if exc.count:
                await self.tell("supervisor", "flow.failed", {"flow_id": flow_id, "failures": flow.failures,
                                                              "error": exc.as_dict(), "sample": exc.sample})
        # "failure", not "error": an "error" key in a reply means the agent itself failed (AgentError at the caller)
        return {"ok": False, "failure": exc.as_dict(), "counts": exc.counts, "flow": self._public(flow_id)}

    def _public(self, flow_id: str) -> dict[str, Any] | None:
        flow = flows.get(self.hub, flow_id)
        return flows.public(self.hub, flow) if flow else None
