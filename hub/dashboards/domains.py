"""Domain specs: how the record widgets work with every tool (round4-dashboard-spec.md 6.4).

A ``DomainSpec`` is the whitelist of one kind of record - a canonical domain (assets, vulnerabilities, risks, controls,
people, accounts, network devices) or an extension pack's data type ``x:<key>``: the fields a widget may group by,
filter, sort and show, how a record maps to the tool it came from (``tools_of``, the record provenance) and to its
page. A widget can only name what is listed here, so it can never read e.g. an asset's facts or a person's raw source
records.

Records are read as rows (dicts) of a few scalar fields inside SQLite (``Snapshot.facts``), once per request and domain,
so a 20-widget request over tens of thousands of records stays cheap (8.3). ``x:<key>`` specs are built from the
enabled pack's ``DomainItem`` when they are needed.

``bind`` checks a widget's domain, source and filters against the spec: a name that is not whitelisted, a value outside
an enum or a removed tool raises ``QueryError`` - a 422 when saving, "unavailable" when a stored widget is resolved.
Messages name the setting and the problem, never the value that was given.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Literal
from urllib.parse import urlencode

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..extensions.pack import _text
from ..models import OPEN_STATES, SEVERITY_ORDER
from .registry import CATALOG_DOMAINS, Role, Unavailable, allowed
from .resolve import Snapshot, clean
from .widgets import route

if TYPE_CHECKING:
    from ..core import Hub
    from ..extensions.pack import DomainItem

Row = dict[str, Any]
FieldType = Literal["text", "enum", "severity", "number", "date", "bool", "link", "source"]
FIELD_NAME = r"^[a-z][a-z0-9_]{0,39}$"
DOMAIN_KEY = r"^([a-z]{2,20}|x:[a-z][a-z0-9_]{1,31})$"
SOURCE = r"^(all|manual|tool:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})$"
TOOL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_GROUPS = 12
NONE_LABEL = "Not set"
MANUAL_LABEL = "Added by hand"
X_EVENTS = ("x_record", "x_record_removed", "extension", "extension_removed")
SEVERITIES = tuple(SEVERITY_ORDER)


class QueryError(ValueError):
    """A widget config that does not fit its domain: ``setting: problem`` (a 422 on save). ``code``/``reason`` are what
    a stored widget shows when it is resolved ("unavailable")."""

    def __init__(self, setting: str, problem: str, code: str = "invalid_config", reason: str | None = None):
        super().__init__(f"{setting}: {problem}")
        self.code = code
        self.reason = reason or "This widget's settings no longer fit its data; configure it again or remove it."

    def unavailable(self) -> Unavailable:
        return Unavailable(self.reason, self.code)


# -- fields and specs ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldDef:
    label: str
    type: FieldType
    get: Callable[[Row], Any]
    values: tuple[str, ...] = ()  # enum and severity: the allowed values, in their order
    ordinal: bool = False  # breakdowns keep the values' order (severities, criticality, risk levels)
    tone: bool = False  # groups and list rows are toned sev-<value>
    multi: bool = False  # get() gives a list: a record counts in the group of each value (a person's sources)

    def view(self, tool_ids: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {"label": self.label, "type": self.type}
        if self.values:
            out["values"] = list(self.values)
        elif self.type == "bool":
            out["values"] = ["yes", "no"]
        elif self.type == "source":
            out["values"] = ["manual", *tool_ids]
        return out


def col(name: str) -> Callable[[Row], Any]:
    return lambda r: r.get(name)


def text(label: str, name: str) -> FieldDef:
    return FieldDef(label, "text", col(name))


def date(label: str, name: str) -> FieldDef:
    return FieldDef(label, "date", col(name))


def flag(label: str, name: str) -> FieldDef:
    return FieldDef(label, "bool", lambda r: bool(r.get(name)))


def enum(label: str, name: str, values: tuple[str, ...], ordinal: bool = False) -> FieldDef:
    return FieldDef(label, "enum", col(name), values, ordinal=ordinal, tone=ordinal)


def severity(label: str, name: str) -> FieldDef:
    return FieldDef(label, "severity", col(name), SEVERITIES, ordinal=True, tone=True)


@dataclass(frozen=True)
class DomainSpec:
    key: str
    label: str  # "Assets"
    noun: str  # what a count counts: "assets"
    icon: str  # an ICONS key of hub/web/js/ui.js
    events: tuple[str, ...]
    load: Callable[[Snapshot], list[Row]]  # the default view (assets: not retired; x: not stale); every row has "id"
    tools_of: Callable[[Row], tuple[str, ...]]  # provenance: the tools a record came from (none: added by hand)
    fields: dict[str, FieldDef]
    group_by: tuple[str, ...]
    filters: tuple[str, ...]
    sort: tuple[str, ...]
    columns: tuple[str, ...]
    date_fields: tuple[str, ...]
    title: Callable[[Row], Any]
    href: Callable[[Row], str]
    app_href: str
    link: Callable[[dict[str, Any]], str] | None = None  # the app filtered on {field: value} (what it supports)
    min_role: Role = "viewer"
    hub_evaluated: bool = False  # no tool brings these records (controls)
    title_field: str = "title"  # the field that is the record's title (lists link it)

    def rows(self, snap: Snapshot) -> list[Row]:
        key = ("domain_rows", self.key)
        if key not in snap.memo:
            snap.memo[key] = self.load(snap)
        return snap.memo[key]

    def view(self, tool_ids: list[str]) -> dict[str, Any]:
        """The catalog entry (7.2)."""
        return {"key": self.key, "label": self.label, "noun": self.noun, "icon": self.icon, "min_role": self.min_role,
                "fields": {n: f.view(tool_ids) for n, f in self.fields.items()}, "group_by": list(self.group_by),
                "filters": list(self.filters), "sort": list(self.sort), "columns": list(self.columns),
                "date_fields": list(self.date_fields), "app_href": self.app_href}


def tool_from(source: Any) -> str | None:
    """The tool of a "sync:<id>" / "tool:<id>" provenance."""
    if isinstance(source, str) and source.startswith(("sync:", "tool:")):
        return source.split(":", 1)[1] or None
    return None


def one(value: Any) -> tuple[str, ...]:
    return (value,) if isinstance(value, str) and value and value != "manual" else ()


def source_field(label: str, tools_of: Callable[[Row], tuple[str, ...]], multi: bool = False) -> FieldDef:
    """Where a record came from: a tool id, or "manual"."""
    if multi:
        return FieldDef(label, "source", lambda r: list(tools_of(r)) or ["manual"], multi=True)
    return FieldDef(label, "source", lambda r: (tools_of(r) or ("manual",))[0])


# -- the canonical domains ----------------------------------------------------------------------

ASSET_TYPES = ("server", "workstation", "network", "software", "saas", "cloud", "data", "other")
CRITICALITY = ("critical", "high", "medium", "low")
ASSET_COLS = ("id", "name", "type", "status", "criticality", "source", "owner", "scan_scope", "created_at",
              "updated_at", "last_scanned_at")
VULN_COLS = ("id", "title", "severity", "status", "source", "host", "due_at", "first_seen", "fixed_at", "cvss")
VULN_STATES = ("open", "in_progress", "accepted", "false_positive", "fixed")
RISK_COLS = ("id", "title", "status", "source", "owner", "likelihood", "impact", "category", "treatment", "created_at",
             "reviewed_at")
RISK_LEVELS = ("critical", "high", "medium", "low")
PEOPLE_COLS = ("id", "display_name", "title", "department", "status", "sources", "terminated_at", "created_at",
               "updated_at")
ACCOUNT_COLS = ("id", "tool_id", "login", "display_name", "app", "active", "last_login")
CONTROL_STATES = ("pass", "partial", "fail", "manual", "na")


def risk_level(score: int) -> str:
    """The band of a likelihood x impact score, as the risk matrix colours it."""
    return "critical" if score >= 15 else "high" if score >= 10 else "medium" if score >= 5 else "low"


def load_assets(snap: Snapshot) -> list[Row]:
    return [r for r in snap.facts("assets", ASSET_COLS) if r["status"] != "retired"]


def load_vulns(snap: Snapshot) -> list[Row]:
    now = time.time()
    return [{**r, "overdue": r["status"] in OPEN_STATES and r["due_at"] is not None and r["due_at"] < now}
            for r in snap.facts("vulnerabilities", VULN_COLS)]


def load_risks(snap: Snapshot) -> list[Row]:
    out = []
    for r in snap.facts("risks", RISK_COLS):
        score = int(r["likelihood"] or 3) * int(r["impact"] or 3)
        out.append({**r, "score": score, "level": risk_level(score)})
    return out


def load_controls(snap: Snapshot) -> list[Row]:
    from ..agents.grc import control_catalog

    return [{"id": c["id"], "title": c["title"], "family": c["family"], "status": c["status"],
             "evaluated_at": c.get("evaluated_at")} for c in control_catalog(snap.controls)]


def _json(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def load_people(snap: Snapshot) -> list[Row]:
    out = []
    for r in snap.facts("people", PEOPLE_COLS):
        sources = _json(r["sources"])
        out.append({**r, "sources": tuple(k for k in (sources if isinstance(sources, dict) else {}) if k != "manual")})
    return out


def load_accounts(snap: Snapshot) -> list[Row]:
    return snap.facts("accounts", ACCOUNT_COLS)


def devices(snap: Snapshot) -> list[dict[str, Any]]:
    """The Network app's device summaries, once per request."""
    if "network_devices" not in snap.memo:
        from ..integration import network

        snap.memo["network_devices"] = network.devices(snap.hub)
    return snap.memo["network_devices"]


def load_network(snap: Snapshot) -> list[Row]:
    out = []
    for d in devices(snap):
        snapshot = d.get("snapshot") or {}
        product = " ".join(x for x in (d.get("vendor"), d.get("model")) if x) or d.get("kind")
        out.append({"id": d["tool_id"], "name": d.get("name"), "product": product,
                    "snapshot_at": snapshot.get("read_at"), "stale": bool(snapshot.get("stale", True)),
                    "writable": bool((d.get("write") or {}).get("writable")),
                    "open_drift": (d.get("drift") or {}).get("open", 0),
                    "critical_drift": (d.get("drift") or {}).get("critical", 0)})
    return out


VULN_PAGE_STATES = {"open": "active", "in_progress": "active", "accepted": "accepted",
                    "false_positive": "false_positive", "fixed": "fixed"}  # the page's status filter ("active": both open)


def vuln_link(params: dict[str, Any]) -> str:
    """The Vulnerabilities page filtered (its ?query: severity, status, source, overdue). Its status filter knows
    "active" (open and in progress), not each of the two."""
    q: dict[str, str] = {}
    sev = params.get("severity")
    if isinstance(sev, str) and sev in SEVERITIES:
        q["severity"] = sev
    status = params.get("status")
    states = {VULN_PAGE_STATES.get(x) for x in (status if isinstance(status, list) else [status])}
    if len(states) == 1 and None not in states:
        q["status"] = states.pop()  # type: ignore[assignment]
    source = params.get("source")
    if isinstance(source, str) and (source == "manual" or TOOL_ID.match(source)):
        q["source"] = source
    if params.get("overdue") is True:
        q["overdue"] = "true"
    return "#/vulnerabilities" + (f"?{urlencode(q)}" if q else "")


def _assets() -> DomainSpec:
    tools_of = lambda r: one(tool_from(r["source"]))  # noqa: E731
    return DomainSpec(
        "assets", "Assets", "assets", "box", ("asset", "asset_removed"), load_assets, tools_of,
        {"name": text("Name", "name"), "type": enum("Type", "type", ASSET_TYPES),
         "status": enum("Status", "status", ("active", "maintenance")),
         "criticality": enum("Criticality", "criticality", CRITICALITY, ordinal=True),
         "source": source_field("Source", tools_of), "owner": text("Owner", "owner"),
         "scan_scope": flag("In scan scope", "scan_scope"), "created_at": date("Added", "created_at"),
         "updated_at": date("Updated", "updated_at"), "last_scanned_at": date("Last scanned", "last_scanned_at")},
        group_by=("type", "status", "criticality", "source"), filters=("type", "status", "criticality", "scan_scope"),
        sort=("name", "criticality", "updated_at", "last_scanned_at"),
        columns=("name", "type", "criticality", "owner", "status", "last_scanned_at"),
        date_fields=("created_at", "updated_at", "last_scanned_at"),
        title=col("name"), href=lambda r: route("assets", r["id"]), app_href="#/assets", title_field="name")


def _vulnerabilities() -> DomainSpec:
    tools_of = lambda r: one(r["source"])  # noqa: E731
    return DomainSpec(
        "vulnerabilities", "Vulnerabilities", "findings", "bug", ("vulnerability",), load_vulns, tools_of,
        {"title": text("Title", "title"), "severity": severity("Severity", "severity"),
         "status": enum("Status", "status", VULN_STATES), "source": source_field("Source", tools_of),
         "host": text("Host", "host"), "overdue": flag("Past its deadline", "overdue"),
         "due_at": date("Deadline", "due_at"), "first_seen": date("First seen", "first_seen"),
         "fixed_at": date("Fixed", "fixed_at"), "cvss": FieldDef("CVSS", "number", col("cvss"))},
        group_by=("severity", "status", "source", "overdue"), filters=("severity", "status", "overdue"),
        sort=("severity", "due_at", "first_seen", "cvss"), columns=("title", "severity", "host", "status", "due_at"),
        date_fields=("first_seen", "fixed_at", "due_at"),
        title=col("title"), href=lambda r: "#/vulnerabilities", app_href="#/vulnerabilities", link=vuln_link)


def _risks() -> DomainSpec:
    tools_of = lambda r: one(tool_from(r["source"]))  # noqa: E731
    return DomainSpec(
        "risks", "Risks", "risks", "flag", ("risk", "risk_removed"), load_risks, tools_of,
        {"title": text("Title", "title"), "status": enum("Status", "status", ("open", "in_treatment", "closed")),
         "level": enum("Level", "level", RISK_LEVELS, ordinal=True),
         "score": FieldDef("Score", "number", col("score")), "owner": text("Owner", "owner"),
         "category": text("Category", "category"),
         "treatment": enum("Treatment", "treatment", ("mitigate", "accept", "transfer", "avoid")),
         "source": source_field("Source", tools_of), "created_at": date("Added", "created_at"),
         "reviewed_at": date("Reviewed", "reviewed_at")},
        group_by=("status", "level", "treatment", "source"), filters=("status", "level", "treatment"),
        sort=("score", "created_at", "reviewed_at"), columns=("title", "score", "level", "status", "owner"),
        date_fields=("created_at", "reviewed_at"),
        title=col("title"), href=lambda r: "#/compliance/risks", app_href="#/compliance/risks")


def _controls() -> DomainSpec:
    from ..grc.baseline import CONTROLS

    families = tuple(dict.fromkeys(c.family for c in CONTROLS))
    return DomainSpec(
        "controls", "Controls", "controls", "shield", ("grc",), load_controls, lambda r: (),
        {"id": text("Control", "id"), "title": text("Title", "title"),
         "family": enum("Family", "family", families), "status": enum("Status", "status", CONTROL_STATES),
         "evaluated_at": date("Evaluated", "evaluated_at")},
        group_by=("status", "family"), filters=("status", "family"), sort=("id", "status"),
        columns=("id", "title", "family", "status"), date_fields=("evaluated_at",),
        title=col("title"), href=lambda r: "#/compliance/controls", app_href="#/compliance/controls",
        hub_evaluated=True)


def _people() -> DomainSpec:
    tools_of = lambda r: r["sources"]  # noqa: E731
    return DomainSpec(
        "people", "People", "people", "contact", ("person", "person_removed"), load_people, tools_of,
        {"display_name": text("Name", "display_name"), "title": text("Job title", "title"),
         "department": text("Department", "department"),
         "status": enum("Status", "status", ("active", "suspended", "terminated")),
         "source": source_field("Source", tools_of, multi=True), "terminated_at": date("Left", "terminated_at"),
         "created_at": date("Added", "created_at"), "updated_at": date("Updated", "updated_at")},
        group_by=("status", "department", "source"), filters=("status", "department"),
        sort=("display_name", "terminated_at", "updated_at"),
        columns=("display_name", "title", "department", "status", "terminated_at"),
        date_fields=("terminated_at", "created_at", "updated_at"),
        title=col("display_name"), href=lambda r: route("people", r["id"]), app_href="#/people",
        title_field="display_name")


def _accounts() -> DomainSpec:
    tools_of = lambda r: one(r["tool_id"])  # noqa: E731
    return DomainSpec(
        "accounts", "Accounts", "accounts", "users", ("account", "accounts_removed"), load_accounts, tools_of,
        {"login": text("Login", "login"), "display_name": text("Name", "display_name"), "app": text("App", "app"),
         "active": flag("Active", "active"), "last_login": date("Last sign-in", "last_login"),
         "tool": source_field("Tool", tools_of)},
        group_by=("tool", "active"), filters=("active", "tool"), sort=("last_login", "login"),
        columns=("login", "app", "tool", "active", "last_login"), date_fields=("last_login",),
        title=lambda r: r.get("login") or r.get("display_name"), href=lambda r: "#/people/accounts",
        app_href="#/people/accounts", title_field="login")


def _network() -> DomainSpec:
    tools_of = lambda r: one(r["id"])  # noqa: E731
    return DomainSpec(
        "network", "Network devices", "devices", "network",
        ("network_snapshot", "network_drift", "network_baseline", "firewall_change", "connection", "settings"),
        load_network, tools_of,
        {"name": text("Name", "name"), "product": text("Product", "product"),
         "snapshot_at": date("Last read", "snapshot_at"), "stale": flag("Out of date", "stale"),
         "writable": flag("Changes allowed", "writable"),
         "open_drift": FieldDef("Open drift", "number", col("open_drift")),
         "critical_drift": FieldDef("Critical drift", "number", col("critical_drift"))},
        group_by=("product", "writable", "stale"), filters=("writable", "stale"),
        sort=("name", "snapshot_at", "open_drift"), columns=("name", "product", "snapshot_at", "open_drift"),
        date_fields=("snapshot_at",),
        title=col("name"), href=lambda r: route("network", r["id"]), app_href="#/network", title_field="name")


BUILTIN: dict[str, DomainSpec] = {s.key: s for s in (_assets(), _vulnerabilities(), _risks(), _controls(), _people(),
                                                     _accounts(), _network())}


# -- extension data types (x:<key>) ---------------------------------------------------------------


X_BASE = ("id", "title", "source", "stale", "created_at", "updated_at")  # and each declared field of "fields"
X_TYPES: dict[str, FieldType] = {"text": "text", "number": "number", "date": "date", "severity": "severity",
                                 "link": "link", "enum": "enum"}


def x_spec(defn: "DomainItem") -> DomainSpec:
    """The spec of an extension pack's data type, from its field definitions."""
    key = f"x:{defn.key}"

    paths = tuple(f"fields.{f.name}" for f in defn.fields)

    def load(snap: Snapshot) -> list[Row]:
        # each declared field read inside SQLite, as the row's "fields.<name>": no JSON object to serialise there and
        # parse here, and no second dict per record (spec 8.3)
        return [r for r in snap.facts(f"x:{defn.key}", X_BASE + paths) if not r["stale"]]

    def value(name: str) -> Callable[[Row], Any]:
        path = f"fields.{name}"
        return lambda r: r[path]

    tools_of = lambda r: one(r["source"])  # noqa: E731
    fields: dict[str, FieldDef] = {}
    for f in defn.fields:
        kind = X_TYPES[f.type]
        fields[f.name] = (FieldDef(f.label, "severity", value(f.name), SEVERITIES, ordinal=True, tone=True)
                          if kind == "severity" else FieldDef(f.label, kind, value(f.name), tuple(f.values)))
    # the record's own title, source and times, unless the pack uses those names for its fields
    for name, made in (("title", lambda: text("Title", "title")), ("source", lambda: source_field("Source", tools_of)),
                       ("created_at", lambda: date("Added", "created_at")),
                       ("updated_at", lambda: date("Updated", "updated_at"))):
        fields.setdefault(name, made())
    pack_names = [f.name for f in defn.fields]
    typed = lambda *kinds: tuple(n for n in pack_names if fields[n].type in kinds)  # noqa: E731
    group_by = typed("severity", "enum") + (("source",) if fields["source"].type == "source" else ())
    columns = tuple(dict.fromkeys(["title", *(n for n in pack_names if n != defn.title_field)]))
    date_fields = tuple(dict.fromkeys([*typed("date"), "created_at", "updated_at"]))
    sort = tuple(dict.fromkeys([*typed("date", "number"), *(("updated_at",) if fields["updated_at"].type == "date"
                                                           else ())]))
    return DomainSpec(
        key, clean(defn.title, 60), clean(defn.title, 60).lower(), "puzzle", X_EVENTS, load, tools_of, fields,
        group_by=group_by, filters=typed("severity", "enum", "text"), sort=sort, columns=columns,
        date_fields=tuple(n for n in date_fields if fields[n].type == "date"),
        title=col("title"), href=lambda r: route("x", defn.key, r["id"]), app_href=route("x", defn.key))


def ext_domains(hub: "Hub", snap: Snapshot | None = None) -> dict[str, Any]:
    if snap is not None:
        return snap.ext_domains
    from ..extensions import registry as ext_registry

    return ext_registry.active_domains(hub)


def lookup(hub: "Hub", key: str, snap: Snapshot | None = None) -> DomainSpec | None:
    """The spec of a domain key, None when it is not a domain widgets show (or its pack is not enabled)."""
    if key in BUILTIN:
        return BUILTIN[key]
    if key.startswith("x:"):
        found = ext_domains(hub, snap).get(key[2:])
        if found is None:
            return None
        memo = snap.memo if snap is not None else {}
        if ("x_spec", key) not in memo:
            memo[("x_spec", key)] = x_spec(found[0])
        return memo[("x_spec", key)]
    return None


def all_specs(hub: "Hub", snap: Snapshot | None = None) -> list[DomainSpec]:
    return [*BUILTIN.values(), *(x_spec(defn) for _, (defn, _) in sorted(ext_domains(hub, snap).items()))]


def events_of(key: str) -> tuple[str, ...]:
    """The bus events that change a domain's records (x: domains share theirs), plus a removed tool."""
    spec = BUILTIN.get(key)
    return (*(spec.events if spec else X_EVENTS), "tool_removed")


def role_of(key: str) -> Role:
    spec = BUILTIN.get(key)
    return spec.min_role if spec else "viewer"


def catalog(hub: "Hub", role: str) -> list[dict[str, Any]]:
    """The catalog's "domains" (7.2): every domain the role may see."""
    tool_ids = sorted(t.id for t in hub.tools())
    return [s.view(tool_ids) for s in all_specs(hub) if allowed(role, s.min_role)]


CATALOG_DOMAINS.append(catalog)


# -- configs: source and filters ------------------------------------------------------------------


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Filter(Strict):
    """One condition on a whitelisted field (6.2): eq / ne one value, in up to 20."""

    field: str = Field(pattern=FIELD_NAME)
    op: Literal["eq", "ne", "in"] = "eq"
    value: bool | int | float | str | list[str]

    @field_validator("value")
    @classmethod
    def _value(cls, v: Any) -> Any:
        if isinstance(v, str):
            return _text(v, 120)
        if isinstance(v, list):
            if not 1 <= len(v) <= 20:
                raise ValueError("lists 1 to 20 values")
            return [_text(x, 120) for x in v]
        return v

    @model_validator(mode="after")
    def _op(self) -> "Filter":
        if (self.op == "in") != isinstance(self.value, list):
            raise ValueError("'in' takes a list of values, 'eq' and 'ne' one value")
        return self


class DomainQuery(Strict):
    """What every record widget names: a domain, where its records come from and up to 5 filters."""

    domain: str = Field(pattern=DOMAIN_KEY)
    source: str = Field("all", pattern=SOURCE)
    filters: list[Filter] = Field(default_factory=list, max_length=5)

    def check(self, hub: "Hub") -> None:
        bind(hub, self)


def _truth(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    word = str(value).strip().lower()
    return True if word in ("yes", "true", "1") else False if word in ("no", "false", "0") else None


def normalize(d: FieldDef, value: Any) -> Any:
    """A filter value in the field's type, or None when it does not fit."""
    if d.type in ("enum", "severity"):
        if not isinstance(value, str):
            return None
        by_lower = {v.lower(): v for v in d.values}
        return by_lower.get(value.strip().lower())
    if d.type == "bool":
        return _truth(value)
    if d.type == "source":
        return value if isinstance(value, str) and (value == "manual" or TOOL_ID.match(value)) else None
    if d.type == "number":
        if isinstance(value, bool):
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
    if d.type == "text":
        text_value = str(value).strip().casefold()
        return text_value or None
    return None


@dataclass
class Condition:
    name: str
    field: FieldDef
    op: str
    wanted: list[Any]

    def match(self, row: Row) -> bool:
        got = self.field.get(row)
        got = got if self.field.multi else [got]
        if self.field.type == "text":
            got = [str(x).casefold() for x in got if x is not None]
        elif self.field.type == "number":
            got = [float(x) for x in got if isinstance(x, (int, float)) and not isinstance(x, bool)]
        hit = any(x in self.wanted for x in got)
        return hit if self.op in ("eq", "in") else not hit


@dataclass
class Query:
    spec: DomainSpec
    source: str
    tool_id: str | None
    tool_name: str | None
    conditions: list[Condition]

    def scoped(self, rows: list[Row]) -> list[Row]:
        if self.tool_id:
            return [r for r in rows if self.tool_id in self.spec.tools_of(r)]
        if self.source == "manual":
            return [r for r in rows if not self.spec.tools_of(r)]
        return rows

    def apply(self, rows: list[Row]) -> list[Row]:
        return [r for r in rows if all(c.match(r) for c in self.conditions)] if self.conditions else rows

    @property
    def source_label(self) -> str:
        return self.tool_name or (MANUAL_LABEL if self.source == "manual" else "All sources")

    def params(self) -> dict[str, Any]:
        """The simple constraints (eq, or in) and the source, for a link to the filtered app."""
        out: dict[str, Any] = {c.name: (c.wanted[0] if len(c.wanted) == 1 else c.wanted)
                               for c in self.conditions if c.op in ("eq", "in")}
        if self.source != "all":
            out["source"] = self.tool_id or "manual"
        return out

    def link(self, extra: dict[str, Any] | None = None) -> str:
        if self.spec.link is None:
            return self.spec.app_href
        return self.spec.link({**self.params(), **(extra or {})})

    def hint(self) -> dict[str, Any]:
        """What an empty widget suggests (7.2 "empty")."""
        if self.tool_id:
            return {"text": f"Set up a data flow from {self.tool_name}", "href": route("tools", self.tool_id, "connection"),
                    "min_role": "admin"}
        if self.spec.hub_evaluated:
            return {"text": "Evaluate the controls", "href": self.spec.app_href, "min_role": "operator"}
        if self.spec.key.startswith("x:"):
            return {"text": f"Set up a data flow that brings {self.spec.noun}", "href": "#/integration",
                    "min_role": "operator"}
        return {"text": f"Connect a tool that brings {self.spec.noun}", "href": "#/integration", "min_role": "operator"}


def bind(hub: "Hub", cfg: DomainQuery, snap: Snapshot | None = None) -> Query:
    """The config checked against its domain spec (QueryError otherwise)."""
    spec = lookup(hub, cfg.domain, snap)
    if spec is None:
        if cfg.domain.startswith("x:"):
            raise QueryError("domain", "this extension data type is not active (its pack is disabled or removed)",
                             "domain_inactive", "This data type is not active: its extension pack is disabled or removed.")
        raise QueryError("domain", "is not a data type widgets can show", "domain_unknown",
                         "This data type is not available.")
    tool_id = cfg.source.removeprefix("tool:") if cfg.source.startswith("tool:") else None
    tool_name = None
    if tool_id is not None:
        tool = (snap.tools_by_id.get(tool_id) if snap is not None else hub.get_tool(tool_id))
        if tool is None:
            raise QueryError("source", "names a tool that does not exist (it may have been removed)", "tool_removed",
                             "The tool this widget shows was removed.")
        tool_name = clean(tool.name, 80)
    conditions = []
    for n, f in enumerate(cfg.filters, 1):
        if f.field not in spec.filters:
            raise QueryError("filters", f"filter {n} uses a field of {spec.label} that cannot be filtered on")
        d = spec.fields[f.field]
        wanted = [normalize(d, v) for v in (f.value if isinstance(f.value, list) else [f.value])]
        if any(w is None for w in wanted):
            raise QueryError("filters", f"filter {n}: a value is not valid for {d.label}"
                             + (f" (one of: {', '.join(d.values)})" if d.values else ""))
        conditions.append(Condition(f.field, d, f.op, wanted))
    return Query(spec, cfg.source, tool_id, tool_name, conditions)


def query(ctx: Any, cfg: DomainQuery) -> Query:
    """``bind`` for a resolver: a config that no longer fits makes the widget unavailable."""
    try:
        return bind(ctx.hub, cfg, ctx.snap)
    except QueryError as exc:
        raise exc.unavailable() from exc


def check_field(spec: DomainSpec, setting: str, name: str | None, allowed_names: tuple[str, ...], what: str) -> str:
    if name is None or name not in allowed_names:
        raise QueryError(setting, f"choose one of the fields of {spec.label} to {what}")
    return name


# -- grouping, sorting and cells ------------------------------------------------------------------


def tool_names(snap: Snapshot) -> dict[str, str]:
    return {t.id: clean(t.name, 80) for t in snap.tools}


def group_key(d: FieldDef, value: Any) -> Any:
    if value is None or value == "":
        return None
    if d.type == "bool":
        return bool(value)
    if d.type == "text":
        return clean(value, 120)
    return value


def group_label(d: FieldDef, key: Any, names: dict[str, str]) -> str:
    if key is None:
        return NONE_LABEL
    if d.type == "bool":
        return "Yes" if key else "No"
    if d.type == "source":
        return MANUAL_LABEL if key == "manual" else names.get(key, clean(key, 80))
    return clean(key, 120)


def groups(q: Query, rows: list[Row], name: str, names: dict[str, str]) -> tuple[list[dict[str, Any]], int]:
    """The breakdown of `rows` by a field: up to 12 groups (by count; ordinal fields keep their order) and the count of
    the rest ("Other")."""
    d = q.spec.fields[name]
    counts: dict[Any, int] = {}
    for r in rows:
        value = d.get(r)
        for x in (value if d.multi else [value]):
            k = group_key(d, x)
            counts[k] = counts.get(k, 0) + 1
    by_count = sorted(counts, key=lambda k: (-counts[k], group_label(d, k, names).casefold()))
    top, rest = by_count[:MAX_GROUPS], by_count[MAX_GROUPS:]
    if d.ordinal:
        rank = {v: i for i, v in enumerate(d.values)}
        top.sort(key=lambda k: rank.get(k, len(rank)))
    out = []
    for k in top:
        tone = f"sev-{k}" if d.tone and k in SEVERITIES else None
        out.append({"key": k, "label": group_label(d, k, names), "count": counts[k], "tone": tone,
                    "href": q.link({name: k}) if k is not None else q.link()})
    return out, sum(counts[k] for k in rest)


def sort_key(d: FieldDef, value: Any) -> tuple[int, Any]:
    """Missing values sort lowest: first ascending ("accounts never used"), last descending ("latest")."""
    if value is None or value == "":
        return (0, 0)
    if d.ordinal:
        return (1, len(d.values) - d.values.index(value) if value in d.values else 0)
    if d.type in ("number", "date"):
        return (1, float(value)) if isinstance(value, (int, float)) and not isinstance(value, bool) else (0, 0)
    if d.type == "bool":
        return (1, int(bool(value)))
    return (1, str(value).casefold())


def sorted_rows(spec: DomainSpec, rows: list[Row], name: str, order: str) -> list[Row]:
    d = spec.fields[name]
    return sorted(rows, key=lambda r: sort_key(d, d.get(r)), reverse=order == "desc")


def cell(d: FieldDef, value: Any, names: dict[str, str]) -> Any:
    """A list cell: text cut to 200 characters, booleans, numbers and timestamps as they are (the UI formats them),
    http(s) links only, tool names for sources."""
    if value is None or value == "":
        return None
    if d.multi:
        return ", ".join(str(cell(FieldDef(d.label, d.type, d.get), v, names)) for v in value)[:200]
    if d.type == "bool":
        return bool(value)
    if d.type in ("number", "date"):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    if d.type == "link":
        return clean(value, 500) if isinstance(value, str) and value.startswith(("http://", "https://")) else None
    if d.type == "source":
        return group_label(d, value, names)
    return clean(value, 200)


def row_tone(spec: DomainSpec, row: Row) -> str | None:
    for d in spec.fields.values():
        if d.tone:
            value = d.get(row)
            if value in SEVERITIES:
                return f"sev-{value}"
    return None
