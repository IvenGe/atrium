"""Maintenance windows (collection ``maintenance_windows``, administrators): when approved network device changes are
applied while the guardrail ``device_changes_need_maintenance_window`` is on. An approved change outside every window
that covers its device waits in status ``scheduled`` and the Network Supervisor applies it when the next window starts
(``integration/changes.py``); an administrator may apply it at once as an emergency, with a justification.

A window covers some devices (tool ids) or, with an empty list, every device, and is either

``weekly``  on some days of the week, from ``start_time`` to ``end_time`` ("HH:MM", local time in ``timezone``; an end
            at or before the start ends on the next day: 22:00-02:00 on "sat" runs Saturday night into Sunday)
``once``    from ``start`` to ``end`` (ISO 8601 date-times; without an offset they are local time in ``timezone``)

Document: {id "mw_...", name, devices, recurrence, days, start_time, end_time, start, end, start_at, end_at (epoch
seconds of a one-off window), timezone (IANA name, default UTC), enabled, created_by, created_at, updated_by,
updated_at}. SSE event ``maintenance_window`` {id, deleted}.
"""

from __future__ import annotations

import time
from datetime import date, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..connectors.netmodel import display_id
from ..store import new_id

if TYPE_CHECKING:
    from ..core import Hub

WINDOWS = "maintenance_windows"
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_WINDOWS = 200
HORIZON_DAYS = 400  # how far ahead the next start is looked for (a one-off window can be planned a year ahead)
Day = Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _hhmm(value: Any) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.strptime(text, "%H:%M")
    except ValueError as exc:
        raise ValueError("times are HH:MM (24-hour clock)") from exc
    return parsed.strftime("%H:%M")


def _zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"unknown time zone {display_id(name, 60)!r} (use an IANA name such as Europe/Brussels)") from exc


class WindowBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    devices: list[str] = Field([], max_length=200)
    recurrence: Literal["weekly", "once"]
    days: list[Day] = Field([], max_length=7)
    start_time: str | None = None
    end_time: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    timezone: str = Field("UTC", max_length=64)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        text = " ".join(value.split())
        if not text:
            raise ValueError("name is required")
        return text

    @field_validator("timezone")
    @classmethod
    def _tz(cls, value: str) -> str:
        _zone(value)
        return value

    @model_validator(mode="after")
    def _shape(self) -> "WindowBody":
        if self.recurrence == "weekly":
            if not self.days or not self.start_time or not self.end_time:
                raise ValueError("a weekly window needs days, start_time and end_time")
            if self.start is not None or self.end is not None:
                raise ValueError("a weekly window has no start / end date-times")
            self.start_time, self.end_time = _hhmm(self.start_time), _hhmm(self.end_time)
            if self.start_time == self.end_time:
                raise ValueError("start_time and end_time must differ")
            self.days = sorted(set(self.days), key=DAYS.index)
        else:
            if self.start is None or self.end is None:
                raise ValueError("a one-off window needs start and end")
            if self.days or self.start_time or self.end_time:
                raise ValueError("a one-off window has no days or times of day")
            tz = _zone(self.timezone)
            self.start = self.start if self.start.tzinfo else self.start.replace(tzinfo=tz)
            self.end = self.end if self.end.tzinfo else self.end.replace(tzinfo=tz)
            if self.end <= self.start:
                raise ValueError("end must be after start")
            if (self.end - self.start) > timedelta(days=14):
                raise ValueError("a one-off window lasts at most 14 days")
        return self


class WindowPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(None, min_length=1, max_length=80)
    devices: list[str] | None = Field(None, max_length=200)
    recurrence: Literal["weekly", "once"] | None = None
    days: list[Day] | None = Field(None, max_length=7)
    start_time: str | None = None
    end_time: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    timezone: str | None = Field(None, max_length=64)
    enabled: bool | None = None


# --------------------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------------------


def windows(hub: "Hub") -> list[dict[str, Any]]:
    return sorted(hub.store.list(WINDOWS), key=lambda w: (w.get("name") or "", w["id"]))


def get(hub: "Hub", window_id: str) -> dict[str, Any] | None:
    return hub.store.get(WINDOWS, window_id)


def _doc(body: WindowBody) -> dict[str, Any]:
    data = body.model_dump(mode="json")
    if body.recurrence == "once":
        assert body.start is not None and body.end is not None
        data.update({"start_at": body.start.timestamp(), "end_at": body.end.timestamp()})
    else:
        data.update({"start": None, "end": None, "start_at": None, "end_at": None})
    data["devices"] = sorted(dict.fromkeys(str(d) for d in body.devices))
    return data


def _check_devices(hub: "Hub", devices: list[str]) -> None:
    from . import network

    known = set(network.device_ids(hub))
    unknown = [d for d in devices if d not in known]
    if unknown:
        raise ValueError(f"not a network device: {display_id(unknown[0])}")


def create(hub: "Hub", body: WindowBody, actor: str) -> dict[str, Any]:
    if len(hub.store.list(WINDOWS)) >= MAX_WINDOWS:
        raise ValueError(f"at most {MAX_WINDOWS} maintenance windows")
    _check_devices(hub, body.devices)
    now = time.time()
    doc = {"id": new_id("mw_"), **_doc(body), "created_by": actor, "created_at": now, "updated_by": actor,
           "updated_at": now}
    hub.store.put(WINDOWS, doc)
    hub.activity(actor, "info", f"Maintenance window '{doc['name']}' created ({describe(doc)})", window_id=doc["id"])
    hub.bus.publish("maintenance_window", {"id": doc["id"], "deleted": False})
    return doc


def update(hub: "Hub", window_id: str, patch: WindowPatch, actor: str) -> dict[str, Any]:
    """KeyError unknown; ValueError (or pydantic ValidationError) when the result is not a valid window."""
    current = get(hub, window_id)
    if current is None:
        raise KeyError(window_id)
    changes = patch.model_dump(exclude_unset=True)
    base = {k: current.get(k) for k in WindowBody.model_fields}
    merged = {**base, **changes}
    if changes.get("recurrence") == "weekly":
        merged.update({k: changes.get(k) for k in ("start", "end")})
    elif changes.get("recurrence") == "once":
        merged.update({"days": changes.get("days") or [], "start_time": changes.get("start_time"),
                       "end_time": changes.get("end_time")})
    body = WindowBody.model_validate(merged)
    _check_devices(hub, [d for d in body.devices if d not in (current.get("devices") or [])])
    doc = {**current, **_doc(body), "updated_by": actor, "updated_at": time.time()}
    hub.store.put(WINDOWS, doc)
    hub.activity(actor, "info", f"Maintenance window '{doc['name']}' changed ({describe(doc)})", window_id=window_id)
    hub.bus.publish("maintenance_window", {"id": window_id, "deleted": False})
    return doc


def delete(hub: "Hub", window_id: str, actor: str) -> bool:
    doc = get(hub, window_id)
    if doc is None:
        return False
    hub.store.delete(WINDOWS, window_id)
    hub.activity(actor, "info", f"Maintenance window '{doc['name']}' removed", window_id=window_id)
    hub.bus.publish("maintenance_window", {"id": window_id, "deleted": True})
    return True


# --------------------------------------------------------------------------------------
# when windows are open
# --------------------------------------------------------------------------------------


def describe(doc: dict[str, Any]) -> str:
    where = "every device" if not doc.get("devices") else f"{len(doc['devices'])} device(s)"
    if doc.get("recurrence") == "weekly":
        when = f"{','.join(doc.get('days') or [])} {doc.get('start_time')}-{doc.get('end_time')} {doc.get('timezone')}"
    else:
        when = f"{doc.get('start')} to {doc.get('end')}"
    return f"{when}, {where}" + ("" if doc.get("enabled", True) else ", disabled")


def covers(doc: dict[str, Any], tool_id: str) -> bool:
    return bool(doc.get("enabled", True)) and (not doc.get("devices") or tool_id in doc["devices"])


def occurrences(doc: dict[str, Any], start: float, end: float) -> list[tuple[float, float]]:
    """The window's (start, end) intervals in epoch seconds that overlap [start, end]."""
    if doc.get("recurrence") == "once":
        a, b = float(doc.get("start_at") or 0), float(doc.get("end_at") or 0)
        return [(a, b)] if a < end and b > start else []
    tz = _zone(doc.get("timezone") or "UTC")
    days = {DAYS.index(d) for d in doc.get("days") or [] if d in DAYS}
    h1, m1 = (int(x) for x in str(doc["start_time"]).split(":"))
    h2, m2 = (int(x) for x in str(doc["end_time"]).split(":"))
    first = datetime.fromtimestamp(start, tz).date() - timedelta(days=1)
    last = datetime.fromtimestamp(end, tz).date()
    out = []
    day: date = first
    while day <= last:
        if day.weekday() in days:
            opens = datetime(day.year, day.month, day.day, h1, m1, tzinfo=tz)
            closes = datetime(day.year, day.month, day.day, h2, m2, tzinfo=tz)
            if closes <= opens:
                closes += timedelta(days=1)
            a, b = opens.timestamp(), closes.timestamp()
            if a < end and b > start:
                out.append((a, b))
        day += timedelta(days=1)
    return out


def active(hub: "Hub", tool_id: str, now: float | None = None) -> dict[str, Any] | None:
    """The open window covering the device now: {"window_id", "name", "start", "end"}, else None."""
    now = time.time() if now is None else now
    best = None
    for doc in windows(hub):
        if not covers(doc, tool_id):
            continue
        for a, b in occurrences(doc, now, now):
            if a <= now < b and (best is None or b > best["end"]):
                best = {"window_id": doc["id"], "name": doc["name"], "start": a, "end": b}
    return best


def next_start(hub: "Hub", tool_id: str, now: float | None = None) -> dict[str, Any] | None:
    """The next window that opens for the device after `now`: {"window_id", "name", "start", "end"}, else None."""
    now = time.time() if now is None else now
    best = None
    for doc in windows(hub):
        if not covers(doc, tool_id):
            continue
        horizon = now + (HORIZON_DAYS if doc.get("recurrence") == "once" else 8) * 86400
        for a, b in occurrences(doc, now, horizon):
            if a > now and (best is None or a < best["start"]):
                best = {"window_id": doc["id"], "name": doc["name"], "start": a, "end": b}
    return best


def public(hub: "Hub", doc: dict[str, Any], now: float | None = None) -> dict[str, Any]:
    now = time.time() if now is None else now
    upcoming = [(a, b) for a, b in occurrences(doc, now, now + (HORIZON_DAYS if doc.get("recurrence") == "once" else 8)
                                               * 86400) if b > now]
    first = min(upcoming, default=None)
    return {**doc, "summary": describe(doc),
            "open_now": bool(first and first[0] <= now < first[1] and doc.get("enabled", True)),
            "next": {"start": first[0], "end": first[1]} if first else None}
