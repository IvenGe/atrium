"""Records of extension domains: the collection "x:<key>" holds one document per alert, ticket, incident... typed by the
domain's field definitions and linked to an asset (by an address or hostname field) and a person (by an email or
login field). Links set by hand stick until someone sets them back to automatic."""

from __future__ import annotations

import math
import re
import time
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from .. import people
from ..connectors.base import severity_from_score, to_timestamp
from ..integration import flows
from ..models import Asset
from ..store import new_id
from .pack import CONTROL_CHARS, SEVERITIES, DomainField, DomainItem

if TYPE_CHECKING:
    from ..core import Hub

PREFIX = "x:"
MAX_TEXT = 4000
SEVERITY_WORDS = {
    "critical": "critical", "crit": "critical", "disaster": "critical", "emergency": "critical", "fatal": "critical",
    "high": "high", "major": "high", "error": "high", "severe": "high", "urgent": "high",
    "medium": "medium", "moderate": "medium", "average": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low", "notice": "low",
    "info": "info", "informational": "info", "information": "info", "none": "info", "debug": "info", "not classified": "info",
}


class ExtRecord(BaseModel):
    """One record of an extension domain, stored in "x:<domain>"."""

    id: str = Field(default_factory=lambda: new_id("x_"))
    domain: str
    title: str = ""
    fields: dict[str, Any] = {}
    source: str = "manual"  # "manual" or the id of the tool it was pulled from
    external_id: str = ""
    stale: bool = False  # no longer reported by its tool (pulls with retire_missing); not counted by control rules
    asset_id: str | None = None
    person_id: str | None = None
    asset_source: Literal["auto", "manual"] = "auto"
    person_source: Literal["auto", "manual"] = "auto"
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


def collection(key: str) -> str:
    return f"{PREFIX}{key}"


def all_records(hub: "Hub", key: str) -> list[ExtRecord]:
    return hub.all(collection(key), ExtRecord)


def get(hub: "Hub", key: str, record_id: str) -> ExtRecord | None:
    return hub.one(collection(key), record_id, ExtRecord)


def save(hub: "Hub", record: ExtRecord) -> ExtRecord:
    record.updated_at = time.time()
    return hub.save(collection(record.domain), record, "x_record")


def delete(hub: "Hub", key: str, record_id: str) -> bool:
    removed = hub.store.delete(collection(key), record_id)
    if removed:
        hub.bus.publish("x_record_removed", {"domain": key, "id": record_id})
    return removed


def purge(hub: "Hub", key: str) -> int:
    items = hub.store.list(collection(key))
    for doc in items:
        hub.store.delete(collection(key), doc["id"])
    for link in hub.store.list(flows.LINKS):
        if link.get("domain") == collection(key):
            hub.store.delete(flows.LINKS, link["id"])
    return len(items)


# --------------------------------------------------------------------------------------
# typing values by the domain's fields
# --------------------------------------------------------------------------------------


def _number(value: Any) -> float | int | None:
    if isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() and abs(number) < 2**53 else number


def _severity(value: Any) -> str | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return severity_from_score(float(value)) if 0 <= value <= 10 else None
    text = str(value).strip().lower()
    if text in SEVERITY_WORDS:
        return SEVERITY_WORDS[text]
    number = _number(text)
    if number is not None:
        return _severity(number)
    return next((SEVERITY_WORDS[w] for w in re.findall(r"[a-z]+", text) if w in SEVERITY_WORDS), None)


def _link(value: Any) -> str | None:
    text = str(value).strip()
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.hostname or len(text) > 2000 or CONTROL_CHARS.search(text):
        return None  # javascript:, data: and the like are dropped
    return text


def _enum(field: DomainField, value: Any) -> str | None:
    text = str(value).strip().lower()
    by_lower = {v.lower(): v for v in field.values}
    if text in by_lower:
        return by_lower[text]
    words = set(re.findall(r"[a-z0-9_]+", text))  # "2 normal" -> normal, "pending reminder" -> pending
    return next((v for v in field.values if v.lower() in words), None)


def coerce_value(field: DomainField, value: Any) -> Any:
    """`value` in the field's type, or None when it does not fit."""
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, dict):
        value = value.get("name") or value.get("value") or value.get("label")
        if value is None:
            return None
    if isinstance(value, (list, tuple)):
        items = [v for v in value if v not in (None, "")]
        if not items:
            return None
        value = ", ".join(str(v) for v in items) if field.type == "text" else items[0]
    kind = field.type
    if kind == "text":
        text = CONTROL_CHARS.sub("", str(value)).strip()[:MAX_TEXT]
        return text or None
    if kind == "number":
        return _number(value)
    if kind == "date":
        return to_timestamp(value)
    if kind == "severity":
        return _severity(value)
    if kind == "link":
        return _link(value)
    return _enum(field, value)


def coerce(defn: DomainItem, raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """The domain's fields from `raw` (unknown keys dropped), and the problems that make the record unusable."""
    fields: dict[str, Any] = {}
    problems: list[str] = []
    for field in defn.fields:
        if field.name not in raw:
            if field.required:
                problems.append(f"{field.label} is required")
            continue
        value = coerce_value(field, raw[field.name])
        if value is None:
            if field.required:
                problems.append(f"{field.label} is required" if raw[field.name] in (None, "", []) else
                                f"{field.label} is not a valid {field.type}")
            continue
        fields[field.name] = value
    return fields, problems


def title_of(defn: DomainItem, fields: dict[str, Any], external_id: str = "") -> str:
    value = fields.get(defn.title_field)
    if value not in (None, ""):
        return str(value)[:300]
    return f"{defn.singular or defn.title} {external_id}".strip()[:300]


# --------------------------------------------------------------------------------------
# links to assets and people
# --------------------------------------------------------------------------------------


class Linker:
    """Address/hostname -> asset id and email/login -> person id, built once per pass."""

    def __init__(self, hub: "Hub"):
        from ..agents.assets import address_index

        self.assets = address_index(hub.all("assets", Asset))
        self.people = people.Index.of(people.all_people(hub))

    def asset(self, value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        text = value.strip().lower()
        host = urlsplit(text).hostname if "://" in text else text.rsplit(":", 1)[0] if text.count(":") == 1 else text
        host = (host or "").rstrip(".")
        return self.assets.get(host) or (self.assets.get(host.split(".")[0]) if "." in host and not host[0].isdigit()
                                         else None)

    def person(self, value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        value = value.strip()
        return self.people.match(value if "@" in value else None, value)

    def apply(self, defn: DomainItem, record: ExtRecord) -> bool:
        """Re-link a record by the domain's link rules (links set by hand are kept). True when something changed."""
        before = (record.asset_id, record.person_id)
        if record.asset_source == "auto":
            rules = [r for r in defn.links if r.target == "asset"]
            record.asset_id = next((m for r in rules if (m := self.asset(record.fields.get(r.field)))), None)
        if record.person_source == "auto":
            rules = [r for r in defn.links if r.target == "person"]
            record.person_id = next((m for r in rules if (m := self.person(record.fields.get(r.field)))), None)
        return before != (record.asset_id, record.person_id)


def relink(hub: "Hub", defn: DomainItem) -> int:
    linker = Linker(hub)
    changed = 0
    for record in all_records(hub, defn.key):
        if linker.apply(defn, record):
            save(hub, record)
            changed += 1
    return changed


# --------------------------------------------------------------------------------------
# data flows
# --------------------------------------------------------------------------------------


def apply_pulled(hub: "Hub", defn: DomainItem, tool_id: str, pulled: list[dict[str, Any]],
                 retire_missing: bool = True) -> dict[str, int]:
    """Merge records a tool reported (matched by the sync link of their external id); with `retire_missing`, records
    of this tool it no longer reports are marked stale (kept, but no longer counted as current)."""
    domain = collection(defn.key)
    known = flows.links(hub, tool_id, domain)
    by_external = {link.external_id: hub_id for hub_id, link in known.items()}
    current = {r.id: r for r in all_records(hub, defn.key)}
    linker = Linker(hub)
    counts = {"total": len(pulled), "created": 0, "updated": 0, "unchanged": 0, "stale": 0, "dropped": 0}
    seen: set[str] = set()
    for raw in pulled:
        external_id = str(raw.get("external_id") or "")
        fields, problems = coerce(defn, raw)
        if problems or not external_id:
            counts["dropped"] += 1
            continue
        digest = flows.content_hash({"fields": fields})
        record = current.get(by_external.get(external_id, ""))
        if record is not None and known[record.id].hash == digest and not record.stale:
            counts["unchanged"] += 1
            seen.add(record.id)
            continue
        if record is None:
            record = ExtRecord(domain=defn.key, source=tool_id, external_id=external_id)
            counts["created"] += 1
        else:
            counts["updated"] += 1
        record.fields, record.stale = fields, False
        record.title = title_of(defn, fields, external_id)
        linker.apply(defn, record)
        save(hub, record)
        flows.put_link(hub, tool_id, domain, record.id, external_id, digest)
        seen.add(record.id)
    if retire_missing:
        for hub_id in set(known) - seen:
            record = current.get(hub_id)
            if record is None:
                flows.drop_link(hub, tool_id, domain, hub_id)
            elif not record.stale:
                record.stale = True
                save(hub, record)
                counts["stale"] += 1
    return counts


def push_records(hub: "Hub", defn: DomainItem) -> list[dict[str, Any]]:
    """The domain's current records as canonical records for a tool: hub_id, external_id, title and the fields."""
    return [{"hub_id": r.id, "external_id": None, "title": r.title, **r.fields}
            for r in all_records(hub, defn.key) if not r.stale]


# --------------------------------------------------------------------------------------
# what the API shows
# --------------------------------------------------------------------------------------


def public(hub: "Hub", record: ExtRecord, *, names: dict[str, str] | None = None,
           assets: dict[str, Asset] | None = None, persons: dict[str, Any] | None = None) -> dict[str, Any]:
    names = names if names is not None else {t.id: t.name for t in hub.tools()}
    asset = (assets.get(record.asset_id) if assets is not None else hub.one("assets", record.asset_id, Asset)) \
        if record.asset_id else None
    person = (persons.get(record.person_id) if persons is not None else people.get(hub, record.person_id)) \
        if record.person_id else None
    return {**record.model_dump(mode="json"), "source_name": names.get(record.source, record.source),
            "asset": {"id": asset.id, "name": asset.name, "type": asset.type, "status": asset.status} if asset else None,
            "person": people.brief(person)}


def matches(record: ExtRecord, needle: str) -> bool:
    haystack = " ".join([record.title, record.external_id, *(str(v) for v in record.fields.values())]).lower()
    return needle in haystack


def listing(hub: "Hub", defn: DomainItem, *, q: str = "", asset_id: str = "", person_id: str = "", source: str = "",
            include_stale: bool = False, limit: int = 1000) -> dict[str, Any]:
    items = all_records(hub, defn.key)
    needle = q.strip().lower()
    out = [r for r in items if (include_stale or not r.stale) and (not needle or matches(r, needle))
           and (not asset_id or r.asset_id == asset_id) and (not person_id or r.person_id == person_id)
           and (not source or r.source == source)]
    severity = next((f.name for f in defn.fields if f.type == "severity"), None)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    out.sort(key=lambda r: (rank.get(r.fields.get(severity), 9) if severity else 0, -r.updated_at))
    names = {t.id: t.name for t in hub.tools()}
    assets = {a.id: a for a in hub.all("assets", Asset)}
    persons = {p.id: p for p in people.all_people(hub)}
    shown = out[:max(1, min(limit, 10_000))]
    return {"records": [public(hub, r, names=names, assets=assets, persons=persons) for r in shown],
            "total": len(out), "stale": sum(1 for r in items if r.stale),
            "sources": sorted({r.source for r in items}),
            "source_names": {s: names.get(s, s) for s in {r.source for r in items}}}
