"""Stored extension packs (collection "extensions"): versions, status, and what is active right now.

Every version of a pack is kept; `version` names the current one. Enabling, disabling, a new version and a rollback
take effect at once, in-process: everything that uses extensions (domains, flows, the SSO catalog, team templates,
compliance rules) reads the active packs from the store when it needs them. Enabling a pack checks it against the
other active packs (one owner per domain key and SSO key; the domains its connector mappings and control rules use
must exist) and applies its connector items to the tools' generic REST connections; disabling undoes that.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field

from .. import guardrails
from ..integration import connections, flows
from .pack import ControlRule, DomainItem, ExtensionPack, SsoItem, TeamItem

if TYPE_CHECKING:
    from ..core import Hub

COLLECTION = "extensions"
HISTORY = 100
_parsed: dict[str, ExtensionPack] = {}  # json digest -> validated pack (a version never changes)


class ExtensionRecord(BaseModel):
    id: str
    status: Literal["proposed", "enabled", "disabled"] = "disabled"
    version: str  # the current version
    versions: list[dict[str, Any]]  # every version's pack, in the order they were added
    source_tool: str | None = None
    approval_id: str | None = None  # the pending proposal
    created_by: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_by: str = ""
    updated_at: float = Field(default_factory=time.time)
    # connections its connector items changed: tool id -> {"created": bool, "domains": [...], "previous": {domain: spec}}
    applied: dict[str, Any] = {}
    notes: list[str] = []  # what could not be applied
    history: list[dict[str, Any]] = []  # [{at, actor, action, version}]

    def pack(self, version: str | None = None) -> ExtensionPack:
        version = version or self.version
        doc = next((v for v in self.versions if v.get("version") == version), None)
        if doc is None:
            raise KeyError(version)
        digest = hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode()).hexdigest()
        if digest not in _parsed:
            if len(_parsed) > 512:
                _parsed.clear()
            _parsed[digest] = ExtensionPack.model_validate(doc)
        return _parsed[digest]

    def log(self, actor: str, action: str, version: str | None = None) -> None:
        self.history = [*self.history, {"at": time.time(), "actor": actor, "action": action,
                                        "version": version or self.version}][-HISTORY:]


def records(hub: "Hub") -> list[ExtensionRecord]:
    return [ExtensionRecord.model_validate(d) for d in hub.store.list(COLLECTION)]


def get(hub: "Hub", ext_id: str) -> ExtensionRecord | None:
    doc = hub.store.get(COLLECTION, ext_id)
    return ExtensionRecord.model_validate(doc) if doc else None


def save(hub: "Hub", rec: ExtensionRecord, actor: str = "") -> ExtensionRecord:
    rec.updated_at = time.time()
    if actor:
        rec.updated_by = actor
    hub.store.put(COLLECTION, rec.model_dump(mode="json"))
    hub.bus.publish("extension", {"id": rec.id, "status": rec.status, "version": rec.version})
    return rec


def _dump(pack: ExtensionPack) -> dict[str, Any]:
    return pack.model_dump(mode="json")


# --------------------------------------------------------------------------------------
# what is active
# --------------------------------------------------------------------------------------


def allowed(hub: "Hub") -> bool:
    return bool(guardrails.value(hub, "allow_extensions"))


def active(hub: "Hub", exclude: str | None = None) -> list[ExtensionPack]:
    """The current version of every enabled pack (none while the allow_extensions guardrail is off)."""
    if not allowed(hub):
        return []
    out = []
    for rec in records(hub):
        if rec.status == "enabled" and rec.id != exclude:
            try:
                out.append(rec.pack())
            except Exception:  # a stored pack from an incompatible version is skipped, not fatal
                continue
    return out


def active_domains(hub: "Hub", exclude: str | None = None) -> dict[str, tuple[DomainItem, str]]:
    """domain key -> (definition, pack id)."""
    out: dict[str, tuple[DomainItem, str]] = {}
    for pack in active(hub, exclude):
        for item in pack.domains:
            out.setdefault(item.key, (item, pack.id))
    return out


def domain(hub: "Hub", key: str) -> DomainItem | None:
    found = active_domains(hub).get(key)
    return found[0] if found else None


def sso_items(hub: "Hub") -> list[SsoItem]:
    return [item for pack in active(hub) for item in pack.of("sso")]


def team_items(hub: "Hub") -> list[TeamItem]:
    return [item for pack in active(hub) for item in pack.of("team")]


def control_rules(hub: "Hub") -> list[tuple[str, ControlRule]]:
    return [(pack.id, rule) for pack in active(hub) for item in pack.of("controls") for rule in item.rules]


def covers_tool(hub: "Hub", tool_id: str) -> bool:
    """Whether a pack was made for this tool or proposed for it (a rejected proposal is not proposed again)."""
    return any(rec.source_tool == tool_id for rec in records(hub))


# --------------------------------------------------------------------------------------
# checks and activation
# --------------------------------------------------------------------------------------


def check(hub: "Hub", pack: ExtensionPack, exclude: str | None = None) -> None:
    """ValueError when `pack` cannot be enabled next to the other active packs."""
    if not allowed(hub):
        raise ValueError("Extensions are switched off (guardrail allow_extensions)")
    others = active(hub, exclude)
    taken = {d.key: p for p in others for d in p.domains}
    for item in pack.domains:
        if item.key in taken:
            raise ValueError(f"The domain '{item.key}' is already defined by the extension '{taken[item.key].name}' "
                             f"({taken[item.key].id}) - disable that one first")
    sso = {s.key: p for p in others for s in p.of("sso")}
    for item in pack.of("sso"):
        if item.key in sso:
            raise ValueError(f"The SSO recipe '{item.key}' is already defined by the extension '{sso[item.key].name}'")
    available = {d.key: d for p in [*others, pack] for d in p.domains}
    for item in pack.of("connector"):
        for name in item.mapping:
            if name.startswith("x:") and name[2:] not in available:
                raise ValueError(f"The connector mapping uses the domain '{name}', which no enabled extension defines")
    for rule in (r for c in pack.of("controls") for r in c.rules):
        defn = available.get(rule.domain)
        if defn is None:
            raise ValueError(f"The control rule '{rule.title}' uses the domain '{rule.domain}', which no enabled "
                             "extension defines")
        for name in [c.field for c in rule.where] + ([rule.age_field] if rule.age_field else []):
            if defn.field(name) is None:
                raise ValueError(f"The control rule '{rule.title}': '{name}' is not a field of '{rule.domain}'")


def _base_url(hub: "Hub", tool_id: str) -> str | None:
    tool = hub.get_tool(tool_id)
    m = tool.manifest if tool else None
    if m and m.api.base_url:
        return m.api.base_url
    return tool.source if tool and tool.source_type == "saas" else None


def _apply_connectors(hub: "Hub", rec: ExtensionRecord, pack: ExtensionPack, actor: str) -> None:
    """Merge the pack's connector mappings into the tools' generic REST connections (creating one when a tool has
    none; the administrator enters the credentials afterwards). Another connector kind is left alone."""
    notes: list[str] = []
    applied: dict[str, Any] = {}
    for item in pack.of("connector"):
        tool_id = item.tool or pack.source_tool or ""
        tool = hub.get_tool(tool_id)
        if tool is None:
            notes.append(f"Connector mapping for '{tool_id}' not applied: the tool is not in the hub")
            continue
        conn = connections.get(hub, tool_id)
        if conn is not None and conn.kind != "generic_rest":
            notes.append(f"Connector mapping for {tool.name} not applied: it has a built-in {conn.kind} connection")
            continue
        mapping = dict((conn.config.get("mapping") if conn else None) or {})
        info = applied.setdefault(tool_id, {"created": conn is None, "domains": [], "previous": {}})
        for name, spec in item.mapping.items():
            if name not in info["domains"]:
                info["previous"][name] = mapping.get(name)
                info["domains"].append(name)
            mapping[name] = spec
        changes: dict[str, Any] = {"mapping": mapping}
        if conn is None:
            base = item.base_url or _base_url(hub, tool_id)
            if not base:
                applied.pop(tool_id, None)
                notes.append(f"Connector mapping for {tool.name} not applied: no API base URL is known - set up a "
                             "generic REST connection first")
                continue
            changes.update(base_url=base, auth=item.auth, auth_header=item.auth_header, verify_tls=item.verify_tls)
        elif item.base_url and conn.config.get("base_url") != item.base_url:
            notes.append(f"{tool.name} keeps its configured base URL {conn.config.get('base_url')} (the pack suggests "
                         f"{item.base_url})")
        try:
            connections.update_config(hub, tool_id, changes, f"{actor} (extension {pack.id})", kind="generic_rest")
        except Exception as exc:  # a refused mapping (ValueError, ConnectorError) is a note, not a failed enable
            applied.pop(tool_id, None)
            notes.append(f"Connector mapping for {tool.name} not applied: {getattr(exc, 'message', None) or exc}")
            continue
        if conn is None:
            notes.append(f"Created a generic REST connection for {tool.name}: an administrator enters its credentials "
                         "in the tool's Connection tab")
    rec.applied, rec.notes = applied, notes


def _unapply_connectors(hub: "Hub", rec: ExtensionRecord, actor: str) -> None:
    """Undo the pack's connector mappings: restore what each domain was mapped to before, drop its flows, and remove
    a connection the pack created when nothing (no other mapping, no credentials) is left in it."""
    for tool_id, info in (rec.applied or {}).items():
        conn = connections.get(hub, tool_id)
        if conn is None or conn.kind != "generic_rest":
            continue
        mapping = dict(conn.config.get("mapping") or {})
        dropped = []
        for name in info.get("domains", []):
            previous = (info.get("previous") or {}).get(name)
            if previous:
                mapping[name] = previous
            else:
                mapping.pop(name, None)
                dropped.append(name)
        for flow in flows.all_flows(hub, tool_id):
            if flow.domain in dropped:
                flows.remove(hub, flow.id, actor, f"Superseded: the extension {rec.id} was disabled.")
        if mapping:
            try:
                connections.update_config(hub, tool_id, {"mapping": mapping}, f"{actor} (extension {rec.id})",
                                          kind="generic_rest")
            except ValueError:
                pass
        elif info.get("created") and not conn.secrets:
            connections.delete(hub, tool_id)
    rec.applied = {}


def _activate(hub: "Hub", rec: ExtensionRecord, pack: ExtensionPack, actor: str) -> None:
    check(hub, pack, exclude=rec.id)
    _apply_connectors(hub, rec, pack, actor)


# --------------------------------------------------------------------------------------
# changes
# --------------------------------------------------------------------------------------


def _new_record(pack: ExtensionPack, actor: str, status: str, approval_id: str | None = None) -> ExtensionRecord:
    now = time.time()
    pack = pack.model_copy(update={"created_by": actor or pack.created_by, "created_at": now})
    rec = ExtensionRecord(id=pack.id, status=status, version=pack.version, versions=[_dump(pack)],  # type: ignore[arg-type]
                          source_tool=pack.source_tool, approval_id=approval_id, created_by=actor, created_at=now,
                          updated_by=actor, updated_at=now)
    rec.log(actor, "proposed" if status == "proposed" else "added")
    return rec


def upload(hub: "Hub", pack: ExtensionPack, actor: str, enable: bool = False) -> ExtensionRecord:
    """Store an uploaded pack - a new pack, or a new version of an existing one (which takes effect at once when the
    pack is enabled). LookupError when that version exists; ValueError when it cannot be enabled."""
    rec = get(hub, pack.id)
    if rec is None:
        rec = _new_record(pack, actor, "disabled")
        if enable:
            _activate(hub, rec, pack, actor)
            rec.status = "enabled"
            rec.log(actor, "enabled")
        save(hub, rec, actor)
        hub.activity(actor, "info", f"Added the extension {pack.name} {pack.version}" + (" (enabled)" if enable else ""),
                     extension_id=pack.id)
        return rec
    if any(v.get("version") == pack.version for v in rec.versions):
        raise LookupError(f"Version {pack.version} of {pack.id} exists already - raise the version to upload a change")
    if rec.status == "proposed":
        raise ValueError(f"{pack.id} is a proposal waiting for approval - decide it first")
    stored = pack.model_copy(update={"created_by": actor, "created_at": time.time()})
    turn_on = enable or rec.status == "enabled"
    if turn_on:
        check(hub, stored, exclude=rec.id)
        _unapply_connectors(hub, rec, actor)
    rec.versions.append(_dump(stored))
    rec.version, rec.source_tool = stored.version, stored.source_tool or rec.source_tool
    rec.log(actor, "new version")
    if turn_on:
        _apply_connectors(hub, rec, stored, actor)
        rec.status = "enabled"
    save(hub, rec, actor)
    hub.activity(actor, "info", f"New version of the extension {stored.name}: {stored.version}"
                 + (" (active)" if turn_on else ""), extension_id=rec.id)
    return rec


def propose(hub: "Hub", pack: ExtensionPack, actor: str) -> ExtensionRecord:
    """Store a generated pack as a proposal (its id made unique)."""
    base, n = pack.id, 2
    while get(hub, pack.id) is not None:
        pack = pack.model_copy(update={"id": f"{base[:44]}-{n}"})
        n += 1
    rec = _new_record(pack, actor, "proposed")
    return save(hub, rec, actor)


def set_status(hub: "Hub", ext_id: str, status: str, actor: str) -> ExtensionRecord:
    rec = get(hub, ext_id)
    if rec is None:
        raise KeyError(ext_id)
    if status not in ("enabled", "disabled"):
        raise ValueError("status is enabled or disabled")
    if rec.status == status:
        return rec
    pack = rec.pack()
    if status == "enabled":
        _activate(hub, rec, pack, actor)
    else:
        _unapply_connectors(hub, rec, actor)
    rec.status, rec.approval_id = status, None  # type: ignore[assignment]
    rec.log(actor, status)
    save(hub, rec, actor)
    hub.activity(actor, "info", f"Extension {pack.name} {pack.version} {status}", extension_id=rec.id)
    return rec


def rollback(hub: "Hub", ext_id: str, actor: str, version: str | None = None) -> ExtensionRecord:
    """Make an earlier version current (the one before the current, unless `version` names one); every version is
    kept. An enabled pack switches over at once."""
    rec = get(hub, ext_id)
    if rec is None:
        raise KeyError(ext_id)
    order = [v.get("version") for v in rec.versions]
    if version is None:
        index = order.index(rec.version)
        if index == 0:
            raise ValueError(f"{rec.id} has no version before {rec.version}")
        version = order[index - 1]
    if version not in order:
        raise ValueError(f"{rec.id} has no version {version}")
    if version == rec.version:
        raise ValueError(f"{version} is already the current version")
    target = rec.pack(version)
    if rec.status == "enabled":
        check(hub, target, exclude=rec.id)
        _unapply_connectors(hub, rec, actor)
        _apply_connectors(hub, rec, target, actor)
    previous, rec.version = rec.version, version
    rec.log(actor, f"rolled back from {previous}")
    save(hub, rec, actor)
    hub.activity(actor, "info", f"Extension {target.name} rolled back from {previous} to {version}", extension_id=rec.id)
    return rec


def remove(hub: "Hub", ext_id: str, actor: str, purge: bool = False) -> int:
    """Remove a pack and all its versions; with `purge`, also the records of the domains it defined. Returns the
    number of records removed."""
    from . import records as ext_records

    rec = get(hub, ext_id)
    if rec is None:
        raise KeyError(ext_id)
    if rec.status == "enabled":
        _unapply_connectors(hub, rec, actor)
    if rec.approval_id:
        hub.approvals.withdraw(rec.approval_id, "Superseded: the extension was removed.", actor)
    removed = 0
    if purge:
        in_use = set(active_domains(hub, exclude=rec.id))
        for version in {v.get("version") for v in rec.versions}:
            for item in rec.pack(version).domains:
                if item.key not in in_use:
                    removed += ext_records.purge(hub, item.key)
    hub.store.delete(COLLECTION, rec.id)
    hub.bus.publish("extension_removed", {"id": rec.id})
    hub.activity(actor, "info", f"Removed the extension {rec.id}" + (f" and {removed} record(s)" if removed else ""),
                 extension_id=rec.id)
    return removed


def forget_tool(hub: "Hub", tool_id: str, actor: str) -> None:
    """A tool left the hub: pending proposals made for it are withdrawn, and the records it reported turn stale (they
    stay, but no longer count as current - nobody reports them any more)."""
    from . import records as ext_records

    keys: set[str] = set()
    for rec in records(hub):
        for version in rec.versions:
            keys |= {i.get("key") for i in version.get("items") or [] if i.get("kind") == "domain"}
        if rec.source_tool == tool_id and rec.status == "proposed":
            if rec.approval_id:
                hub.approvals.withdraw(rec.approval_id, "Superseded: the tool was removed from the hub.", actor)
            rec.status, rec.approval_id = "disabled", None
            rec.log(actor, "withdrawn: the tool was removed")
            save(hub, rec, actor)
    for key in sorted(k for k in keys if k):
        for record in ext_records.all_records(hub, key):
            if record.source == tool_id and not record.stale:
                record.stale = True
                ext_records.save(hub, record)


async def changed(hub: "Hub", sender: str) -> None:
    """After a change: re-score the suite (SSO recipes), re-evaluate compliance and plan the flows new domains and
    mappings make possible."""
    await hub.bus.tell(sender, "supervisor", "reevaluate")
    await hub.bus.tell(sender, "supervisor", "flows.plan")


# --------------------------------------------------------------------------------------
# what the API shows
# --------------------------------------------------------------------------------------


def public(hub: "Hub", rec: ExtensionRecord, full: bool = False) -> dict[str, Any]:
    pack = rec.pack()
    tool = hub.get_tool(rec.source_tool) if rec.source_tool else None
    order = [v.get("version") for v in rec.versions]
    out: dict[str, Any] = {
        "id": rec.id, "name": pack.name, "version": rec.version, "description": pack.description,
        "source_tool": rec.source_tool, "source_tool_name": tool.name if tool else None, "status": rec.status,
        "active": rec.status == "enabled" and allowed(hub), "approval_id": rec.approval_id,
        "created_by": rec.created_by, "created_at": rec.created_at, "updated_by": rec.updated_by,
        "updated_at": rec.updated_at, "summary": pack.summary(),
        "items": [item.model_dump(mode="json") for item in pack.items],
        "versions": [{"version": v.get("version"), "name": v.get("name"), "created_by": v.get("created_by"),
                      "created_at": v.get("created_at"), "current": v.get("version") == rec.version} for v in rec.versions],
        "can_rollback": order.index(rec.version) > 0 if rec.version in order else False,
        "applied": {t: {"created": i.get("created"), "domains": i.get("domains", [])} for t, i in rec.applied.items()},
        "notes": rec.notes,
    }
    if full:
        out["pack"] = _dump(pack)
        out["history"] = rec.history
        for entry, doc in zip(out["versions"], rec.versions):
            entry["pack"] = doc
    return out
