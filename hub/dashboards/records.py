"""The record widgets (round4-dashboard-spec.md 6.2 "Records", stage D3): ``domain_count``, ``domain_list`` and
``domain_timeline``. They work with every domain spec (hub/dashboards/domains.py) - the canonical domains and every
extension data type - so every connector Atrium has today, and every one it gets later, feeds them without
per-product code. Their configs name only whitelisted fields; ``check`` binds them to the domain at save time.
"""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING, Any, Literal

from pydantic import Field

from . import domains
from .domains import DomainQuery, QueryError, check_field, query, tool_names
from .registry import FieldSpec, Outcome, WidgetType, options, register
from .resolve import ResolveContext, clean

if TYPE_CHECKING:
    from ..core import Hub

DAY = 86400
VIEWS = ("number", "bars", "list")
# every event a record widget may depend on (the catalog's static list; events_for narrows it per config)
ALL_EVENTS = tuple(dict.fromkeys(e for key in [*domains.BUILTIN, "x:any"] for e in domains.events_of(key)))


def _noun(q: domains.Query) -> str:
    return q.spec.noun


def _base(q: domains.Query) -> dict[str, Any]:
    return {"domain": q.spec.key, "domain_label": q.spec.label, "noun": _noun(q), "icon": q.spec.icon,
            "source": q.source, "source_label": q.source_label, "href": q.link()}


# -- domain_count ---------------------------------------------------------------------------------


class CountConfig(DomainQuery):
    group_by: str | None = Field(None, pattern=domains.FIELD_NAME)
    view: Literal["number", "bars", "list"] = "bars"

    def check(self, hub: "Hub") -> None:
        q = domains.bind(hub, self)
        _count_fields(q, self)


def _count_fields(q: domains.Query, cfg: CountConfig) -> None:
    if cfg.group_by is not None or cfg.view != "number":
        check_field(q.spec, "group_by", cfg.group_by, q.spec.group_by, "group by (bars and lists need one)")


def resolve_count(ctx: ResolveContext, cfg: CountConfig) -> dict[str, Any] | Outcome:
    q = query(ctx, cfg)
    try:
        _count_fields(q, cfg)
    except QueryError as exc:
        raise exc.unavailable() from exc
    base = q.scoped(q.spec.rows(ctx.snap))
    rows = q.apply(base)
    data = {**_base(q), "view": cfg.view, "total": len(rows), "groups": [], "other": 0, "group_by": cfg.group_by,
            "group_label": None, "ordinal": False}
    if cfg.group_by:
        field = q.spec.fields[cfg.group_by]
        data["groups"], data["other"] = domains.groups(q, rows, cfg.group_by, tool_names(ctx.snap))
        data.update(group_label=field.label, ordinal=field.ordinal)
    return Outcome("empty", data, hint=q.hint()) if not base else data


def domain_label(key: str) -> str:
    """A domain's name without the hub (the generated title): "Assets", "Alerts" for x:alerts."""
    spec = domains.BUILTIN.get(key)
    return spec.label if spec else key.removeprefix("x:").replace("_", " ").capitalize()


def count_title(cfg: CountConfig) -> str:
    label = domain_label(cfg.domain)
    if cfg.group_by:
        field = domains.BUILTIN[cfg.domain].fields.get(cfg.group_by) if cfg.domain in domains.BUILTIN else None
        return f"{label} by {(field.label if field else cfg.group_by.replace('_', ' ')).lower()}"
    return label


# -- domain_list ----------------------------------------------------------------------------------


class ListConfig(DomainQuery):
    sort: str | None = Field(None, pattern=domains.FIELD_NAME)  # default: the domain's first sortable field
    order: Literal["asc", "desc"] = "desc"
    limit: int = Field(8, ge=1, le=25)
    columns: list[str] = Field(default_factory=list, max_length=4)  # default: the domain's first four columns

    def check(self, hub: "Hub") -> None:
        _list_fields(domains.bind(hub, self), self)


def _list_fields(q: domains.Query, cfg: ListConfig) -> tuple[str, list[str]]:
    spec = q.spec
    sort = check_field(spec, "sort", cfg.sort or spec.sort[0], spec.sort, "sort by")
    columns = list(dict.fromkeys(cfg.columns)) or list(spec.columns[:4])
    for name in columns:
        check_field(spec, "columns", name, spec.columns, "show as a column")
    return sort, columns


def resolve_list(ctx: ResolveContext, cfg: ListConfig) -> dict[str, Any] | Outcome:
    q = query(ctx, cfg)
    try:
        sort, columns = _list_fields(q, cfg)
    except QueryError as exc:
        raise exc.unavailable() from exc
    spec, names = q.spec, tool_names(ctx.snap)
    base = q.scoped(spec.rows(ctx.snap))
    rows = domains.sorted_rows(spec, q.apply(base), sort, cfg.order)
    data = {**_base(q), "total": len(rows), "sort": sort, "order": cfg.order, "title_field": spec.title_field,
            "columns": [{"field": n, "label": spec.fields[n].label, "type": spec.fields[n].type} for n in columns],
            "rows": [{"id": clean(r.get("id"), 120), "title": clean(spec.title(r) or "(untitled)", 200),
                      "href": spec.href(r), "tone": domains.row_tone(spec, r),
                      "cells": {n: domains.cell(spec.fields[n], spec.fields[n].get(r), names) for n in columns}}
                     for r in rows[:cfg.limit]]}
    return Outcome("empty", data, hint=q.hint()) if not base else data


def list_title(cfg: ListConfig | TimelineConfig) -> str:
    return domain_label(cfg.domain)


# -- domain_timeline ------------------------------------------------------------------------------


class TimelineConfig(DomainQuery):
    date_field: str | None = Field(None, pattern=domains.FIELD_NAME)  # default: the domain's first date field
    days: int = Field(30, ge=7, le=90)

    def check(self, hub: "Hub") -> None:
        _date_field(domains.bind(hub, self), self)


def _date_field(q: domains.Query, cfg: TimelineConfig) -> str:
    return check_field(q.spec, "date_field", cfg.date_field or next(iter(q.spec.date_fields), None),
                       q.spec.date_fields, "count by")


def utc_day(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d")


def resolve_timeline(ctx: ResolveContext, cfg: TimelineConfig) -> dict[str, Any] | Outcome:
    """Records per UTC day over the last `days` days, by one of their dates; records without it are counted in
    ``skipped``."""
    q = query(ctx, cfg)
    try:
        name = _date_field(q, cfg)
    except QueryError as exc:
        raise exc.unavailable() from exc
    field = q.spec.fields[name]
    today = dt.datetime.fromtimestamp(ctx.now, dt.timezone.utc).date()
    days = [(today - dt.timedelta(days=n)).isoformat() for n in range(cfg.days - 1, -1, -1)]
    counts = dict.fromkeys(days, 0)
    base = q.scoped(q.spec.rows(ctx.snap))
    skipped = 0
    for r in q.apply(base):
        value = field.get(r)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            skipped += 1
            continue
        day = utc_day(value)
        if day in counts:
            counts[day] += 1
    data = {**_base(q), "date_field": name, "date_label": field.label, "days": cfg.days,
            "buckets": [{"day": d, "count": counts[d]} for d in days], "total": sum(counts.values()),
            "skipped": skipped}
    return Outcome("empty", data, hint=q.hint()) if not base else data


# -- registration ---------------------------------------------------------------------------------

DOMAIN_FIELDS = (FieldSpec("domain", "Data", "domain"),
                 FieldSpec("source", "From", "tool", depends_on="domain"),
                 FieldSpec("filters", "Only records where", "filters", depends_on="domain", max=5))
events_for = lambda c: domains.events_of(c.domain)  # noqa: E731
role_for = lambda c: domains.role_of(c.domain)  # noqa: E731

register(WidgetType(
    "domain_count", "Count of records", "How many records of any kind there are - from every tool or one - as a "
    "number, bars or a list of groups.", "records", CountConfig, resolve_count, (2, 1), (4, 3), (12, 6),
    fields=(*DOMAIN_FIELDS,
            FieldSpec("group_by", "Group by", "field", options="group_by", depends_on="domain"),
            FieldSpec("view", "Show as", "select", options=options(("bars", "Bars"), ("number", "One number"),
                                                                   ("list", "A list of the groups")))),
    events=ALL_EVENTS, events_for=events_for, role_for=role_for, ttl=30, title_for=count_title))
register(WidgetType(
    "domain_list", "List of records", "Records of any kind, sorted and with the columns you choose.", "records",
    ListConfig, resolve_list, (3, 2), (6, 4), (12, 8),
    fields=(*DOMAIN_FIELDS,
            FieldSpec("sort", "Sort by", "field", options="sort", depends_on="domain"),
            FieldSpec("order", "Order", "select", options=options(("desc", "Highest or newest first"),
                                                                  ("asc", "Lowest or oldest first"))),
            FieldSpec("columns", "Columns", "field", options="columns", depends_on="domain", max=4,
                      hint="None selected: the first four"),
            FieldSpec("limit", "Rows", "number", min=1, max=25)),
    events=ALL_EVENTS, events_for=events_for, role_for=role_for, ttl=30, refresh=60, title_for=list_title))
register(WidgetType(
    "domain_timeline", "Records over time", "How many records per day, by one of their dates (added, seen, fixed...).",
    "records", TimelineConfig, resolve_timeline, (4, 2), (6, 3), (12, 6),
    fields=(*DOMAIN_FIELDS,
            FieldSpec("date_field", "Count by", "field", options="date_fields", depends_on="domain"),
            FieldSpec("days", "Days", "number", min=7, max=90)),
    events=ALL_EVENTS, events_for=events_for, role_for=role_for, ttl=60, refresh=3600,
    title_for=lambda c: f"{list_title(c)} over time"))
