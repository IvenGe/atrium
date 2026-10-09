"""Extension packs: data-only additions to Atrium (strict pydantic models, nothing in a pack is executed or evaluated).

A pack (JSON) has an id, a name, a version, a description, the tool it was made for (``source_tool``) and items:

``domain``    a new data type, e.g. "alerts" from a SIEM or "tickets" from a service desk::

                {"kind": "domain", "key": "alerts", "title": "Alerts", "singular": "Alert", "icon": "bell",
                 "fields": [{"name": "title", "label": "Title"},
                            {"name": "severity", "label": "Severity", "type": "severity"},
                            {"name": "status", "label": "Status", "type": "enum", "values": ["open", "closed"]},
                            {"name": "host", "label": "Host"}, {"name": "detected", "label": "Detected", "type": "date"}],
                 "title_field": "title",
                 "links": [{"target": "asset", "field": "host"}, {"target": "person", "field": "user"}]}

              Field types: text, number, date, severity (critical|high|medium|low|info), link (http/https URL only),
              enum (+ values). Records live in the collection "x:<key>"; connectors pull and push the domain "x:<key>"
              like a built-in one. Link rules: an asset by the address or hostname in a field, a person by the email
              (or login) in a field.
``connector`` a generic REST connection mapping for a tool (hub/connectors/generic_rest.py), may map "x:<key>":
              {"kind": "connector", "tool": "<tool id>", "base_url": "https://...", "auth": "bearer", "mapping": {...}}
``sso``       a single sign-on recipe for tools the built-in catalog does not know (hub/integration/sso_catalog.py):
              {"kind": "sso", "key": "acme", "name": "Acme", "match": ["acme"], "protocol": "oidc",
               "redirect_path": "/oauth/callback", "file": "sso/acme.env", "template": "ACME_OIDC_ISSUER={issuer}\\n..."}
              Placeholders (plain text substitution, nothing else): {url} {issuer} {discovery} {client_id}
              {client_secret} {provider_name} {scopes} {redirect_uri} {authorize_endpoint} {token_endpoint}
              {userinfo_endpoint} {tool_name}.
``controls``  compliance evidence from a domain: rules that count matching records and set a control's status:
              {"kind": "controls", "rules": [{"control": "HB-IR-1", "domain": "alerts",
               "title": "Critical alerts open for more than 7 days",
               "where": [{"field": "severity", "op": "eq", "value": "critical"},
                         {"field": "status", "op": "ne", "value": "closed"}],
               "age_field": "detected", "older_than_days": 7, "fail_above": 0}]}
              ops: eq ne in not_in gte lte empty not_empty. More than fail_above records -> fail, more than
              partial_above -> partial, else pass; the control gets the worse of its own check and the rules.
``team``      an agent-team template for a kind of tool (hub/agents/teams.py):
              {"kind": "team", "category": "ticketing", "title": "Service desk",
               "match": {"names": ["zammad"], "capabilities": ["ticketing"], "connector_kinds": []},
               "roles": [{"role": "ticket-triage", "title": "Ticket triage", "permissions": ["read"], ...}]}
              "{tool}" in a role's texts becomes the tool's name.

Unknown keys, unknown item kinds, control characters, unsafe URLs and paths are rejected.
"""

from __future__ import annotations

import json
import re
import time
from typing import Annotated, Any, Literal, Union
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..connectors.base import DOMAINS
from ..models import AGENT_PERMISSIONS, MIN_SCHEDULE, AgentPermission

MAX_PACK_BYTES = 512_000
PACK_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,47}$")
VERSION = re.compile(r"^\d{1,6}(\.\d{1,6}){0,2}([-+][0-9A-Za-z.-]{1,20})?$")
KEY = re.compile(r"^[a-z][a-z0-9_]{1,31}$")
FIELD = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
ICON = re.compile(r"^[a-z0-9-]{1,32}$")
TOOL_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
ALIAS = re.compile(r"^[a-z0-9][a-z0-9 ._-]{1,59}$")
CAPABILITY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,39}$")
URL_PATH = re.compile(r"^/[A-Za-z0-9._~%:@+,;=/<>-]{0,299}$")
SSO_FILE = re.compile(r"^sso/[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
RESERVED_FIELDS = {"id", "external_id", "hub_id"}
FieldType = Literal["text", "number", "date", "severity", "link", "enum"]
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _text(value: str, limit: int, *, multiline: bool = False, required: bool = False) -> str:
    if CONTROL_CHARS.search(value) or (not multiline and ("\n" in value or "\r" in value)):
        raise ValueError("contains control characters" if CONTROL_CHARS.search(value) else "must be a single line")
    value = value.strip() if not multiline else value
    if required and not value.strip():
        raise ValueError("must not be empty")
    if len(value) > limit:
        raise ValueError(f"is longer than {limit} characters")
    return value


def _match(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.match(value):
        raise ValueError(f"is not a valid {what}")
    return value


def _http_url(value: str) -> str:
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http:// or https:// URL")
    if parts.username or parts.password or parts.query or parts.fragment or len(value) > 500:
        raise ValueError("must be a plain URL (no credentials, query or fragment, at most 500 characters)")
    return value.strip().rstrip("/")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


# --------------------------------------------------------------------------------------
# items
# --------------------------------------------------------------------------------------


class DomainField(Strict):
    name: str
    label: str
    type: FieldType = "text"
    values: list[str] = Field(default_factory=list, max_length=50)  # enum only
    required: bool = False
    description: str = ""

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        _match(FIELD, v, "field name (lowercase letters, digits and _, starting with a letter)")
        if v in RESERVED_FIELDS:
            raise ValueError(f"'{v}' is reserved")
        return v

    _label = field_validator("label")(lambda cls, v: _text(v, 80, required=True))
    _description = field_validator("description")(lambda cls, v: _text(v, 300))

    @field_validator("values")
    @classmethod
    def _values(cls, v: list[str]) -> list[str]:
        out = [_text(x, 60, required=True) for x in v]
        if len({x.lower() for x in out}) != len(out):
            raise ValueError("enum values must be unique")
        return out

    @model_validator(mode="after")
    def _enum(self) -> "DomainField":
        if self.type == "enum" and not self.values:
            raise ValueError(f"enum field '{self.name}' needs values")
        if self.type != "enum" and self.values:
            raise ValueError(f"only enum fields have values ('{self.name}' is {self.type})")
        return self


class LinkRule(Strict):
    target: Literal["asset", "person"]
    field: str

    _field = field_validator("field")(lambda cls, v: _match(FIELD, v, "field name"))


class DomainItem(Strict):
    kind: Literal["domain"]
    key: str
    title: str
    singular: str = ""
    icon: str = "box"
    description: str = ""
    fields: list[DomainField] = Field(min_length=1, max_length=60)
    title_field: str
    links: list[LinkRule] = Field(default_factory=list, max_length=4)

    @field_validator("key")
    @classmethod
    def _key(cls, v: str) -> str:
        _match(KEY, v, "domain key (2-32 lowercase letters, digits and _, starting with a letter)")
        if v in DOMAINS:
            raise ValueError(f"'{v}' is a built-in domain")
        return v

    _title = field_validator("title")(lambda cls, v: _text(v, 60, required=True))
    _singular = field_validator("singular")(lambda cls, v: _text(v, 60))
    _icon = field_validator("icon")(lambda cls, v: _match(ICON, v, "icon name"))
    _description = field_validator("description")(lambda cls, v: _text(v, 1000, multiline=True))

    @model_validator(mode="after")
    def _consistent(self) -> "DomainItem":
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValueError(f"domain '{self.key}' has duplicate field names")
        types = {f.name: f.type for f in self.fields}
        if self.title_field not in types:
            raise ValueError(f"title_field '{self.title_field}' is not a field of '{self.key}'")
        for link in self.links:
            if types.get(link.field) not in ("text", "link"):
                raise ValueError(f"link field '{link.field}' must be a text field of '{self.key}'")
        return self

    def field(self, name: str) -> DomainField | None:
        return next((f for f in self.fields if f.name == name), None)


class ConnectorItem(Strict):
    kind: Literal["connector"]
    tool: str | None = None  # default: the pack's source tool
    base_url: str | None = None  # default: the tool's API base URL from its manifest
    auth: Literal["bearer", "token", "header", "basic", "none"] = "bearer"
    auth_header: str = "X-API-Key"
    verify_tls: bool = True
    mapping: dict[str, Any]
    note: str = ""

    @field_validator("tool")
    @classmethod
    def _tool(cls, v: str | None) -> str | None:
        return _match(TOOL_ID, v, "tool id") if v is not None else None

    _base = field_validator("base_url")(lambda cls, v: _http_url(v) if v is not None else None)
    _header = field_validator("auth_header")(lambda cls, v: _match(HEADER, v, "header name"))
    _note = field_validator("note")(lambda cls, v: _text(v, 1000, multiline=True))

    @field_validator("mapping")
    @classmethod
    def _mapping(cls, v: dict[str, Any]) -> dict[str, Any]:
        from ..connectors.base import ConnectorError
        from ..connectors.generic_rest import validate_mapping

        try:
            return validate_mapping(json.loads(json.dumps(v)))
        except ConnectorError as exc:
            raise ValueError(exc.message) from exc

    @property
    def domains(self) -> list[str]:
        return list(self.mapping)


class SsoItem(Strict):
    kind: Literal["sso"]
    key: str
    name: str
    match: list[str] = Field(min_length=1, max_length=10)  # matched against the tool's id, name and source
    protocol: Literal["oidc", "saml"] = "oidc"
    redirect_path: str  # the tool's callback, relative to its base URL
    acs_path: str | None = None  # SAML
    slo_path: str | None = None
    file: str  # where the configuration lands in the tool's adapter folder ("sso/<name>")
    template: str
    steps: list[str] = Field(default_factory=list, max_length=10)
    public_client: bool = False

    _key = field_validator("key")(lambda cls, v: _match(SLUG, v, "key"))
    _name = field_validator("name")(lambda cls, v: _text(v, 80, required=True))
    _file = field_validator("file")(lambda cls, v: _match(SSO_FILE, v, "file name under sso/"))
    _template = field_validator("template")(lambda cls, v: _text(v, 20_000, multiline=True, required=True))

    @field_validator("match")
    @classmethod
    def _aliases(cls, v: list[str]) -> list[str]:
        return [_match(ALIAS, x, "match text (2-60 lowercase letters, digits, spaces, '.', '_' or '-')") for x in v]

    @field_validator("redirect_path", "acs_path", "slo_path")
    @classmethod
    def _path(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if ".." in v.split("/"):
            raise ValueError("must not contain '..'")
        return _match(URL_PATH, v, "path relative to the tool's URL (starting with '/')")

    @field_validator("steps")
    @classmethod
    def _steps(cls, v: list[str]) -> list[str]:
        return [_text(x, 500, required=True) for x in v]

    @model_validator(mode="after")
    def _saml(self) -> "SsoItem":
        if self.protocol == "saml" and not self.acs_path:
            raise ValueError("a SAML recipe needs acs_path")
        return self


class Condition(Strict):
    field: str
    op: Literal["eq", "ne", "in", "not_in", "gte", "lte", "empty", "not_empty"] = "eq"
    value: str | int | float | list[str] | None = None

    _field = field_validator("field")(lambda cls, v: _match(FIELD, v, "field name"))

    @model_validator(mode="after")
    def _value(self) -> "Condition":
        if self.op in ("in", "not_in") and not isinstance(self.value, list):
            raise ValueError(f"'{self.op}' needs a list of values")
        if self.op in ("gte", "lte") and (isinstance(self.value, bool) or not isinstance(self.value, (int, float, str))):
            raise ValueError(f"'{self.op}' needs a number (or a severity)")
        if isinstance(self.value, str):
            _text(self.value, 200)
        if isinstance(self.value, list):
            if len(self.value) > 50:
                raise ValueError("at most 50 values")
            for x in self.value:
                _text(x, 200)
        return self


class ControlRule(Strict):
    control: str
    domain: str
    title: str
    where: list[Condition] = Field(default_factory=list, max_length=10)
    age_field: str | None = None  # a date field; default: when the hub first stored the record
    older_than_days: int | None = Field(None, ge=0, le=3650)
    fail_above: int | None = Field(None, ge=0)
    partial_above: int | None = Field(None, ge=0)

    @field_validator("control")
    @classmethod
    def _control(cls, v: str) -> str:
        from ..grc.baseline import CONTROLS_BY_ID

        if v not in CONTROLS_BY_ID:
            raise ValueError(f"unknown control '{v}'")
        return v

    _domain = field_validator("domain")(lambda cls, v: _match(KEY, v, "domain key"))
    _title = field_validator("title")(lambda cls, v: _text(v, 200, required=True))

    @field_validator("age_field")
    @classmethod
    def _age(cls, v: str | None) -> str | None:
        return _match(FIELD, v, "field name") if v is not None else None

    @model_validator(mode="after")
    def _thresholds(self) -> "ControlRule":
        if self.fail_above is None and self.partial_above is None:
            raise ValueError("a rule needs fail_above and/or partial_above")
        return self


class ControlsItem(Strict):
    kind: Literal["controls"]
    rules: list[ControlRule] = Field(min_length=1, max_length=20)


class TeamMatch(Strict):
    names: list[str] = Field(default_factory=list, max_length=20)
    capabilities: list[str] = Field(default_factory=list, max_length=20)
    connector_kinds: list[str] = Field(default_factory=list, max_length=10)

    _names = field_validator("names")(lambda cls, v: [_match(ALIAS, x, "name") for x in v])
    _caps = field_validator("capabilities", "connector_kinds")(lambda cls, v: [_match(CAPABILITY, x, "capability") for x in v])


class TeamRole(Strict):
    role: str
    title: str
    description: str = ""
    instructions: str = ""
    permissions: list[AgentPermission] = Field(default_factory=lambda: ["read"])
    schedule_minutes: int = Field(0, ge=0, le=525_600)
    task: str = ""
    rules_ok: bool = False  # a rules agent can do the standing task (health check, data flows, summary)

    _role = field_validator("role")(lambda cls, v: _match(SLUG, v, "role id"))
    _title = field_validator("title")(lambda cls, v: _text(v, 80, required=True))
    _description = field_validator("description")(lambda cls, v: _text(v, 1000, multiline=True))
    _instructions = field_validator("instructions")(lambda cls, v: _text(v, 20_000, multiline=True))
    _task = field_validator("task")(lambda cls, v: _text(v, 4000, multiline=True))

    @field_validator("permissions")
    @classmethod
    def _permissions(cls, v: list[str]) -> list[str]:
        return [p for p in AGENT_PERMISSIONS if p in set(v)]

    @field_validator("schedule_minutes")
    @classmethod
    def _schedule(cls, v: int) -> int:
        if 0 < v < MIN_SCHEDULE:
            raise ValueError(f"is 0 (no schedule) or at least {MIN_SCHEDULE}")
        return v


class TeamItem(Strict):
    kind: Literal["team"]
    category: str
    title: str
    match: TeamMatch = Field(default_factory=TeamMatch)
    roles: list[TeamRole] = Field(min_length=1, max_length=6)

    _category = field_validator("category")(lambda cls, v: _match(SLUG, v, "category"))
    _title = field_validator("title")(lambda cls, v: _text(v, 80, required=True))

    @model_validator(mode="after")
    def _unique(self) -> "TeamItem":
        roles = [r.role for r in self.roles]
        if len(set(roles)) != len(roles):
            raise ValueError(f"team '{self.category}' has duplicate roles")
        return self


Item = Annotated[Union[DomainItem, ConnectorItem, SsoItem, ControlsItem, TeamItem], Field(discriminator="kind")]
KINDS = ("domain", "connector", "sso", "controls", "team")


# --------------------------------------------------------------------------------------
# the pack
# --------------------------------------------------------------------------------------


class ExtensionPack(Strict):
    id: str
    name: str
    version: str = "1.0.0"
    description: str = ""
    source_tool: str | None = None
    created_by: str = ""
    status: Literal["proposed", "enabled", "disabled"] = "disabled"
    created_at: float = Field(default_factory=time.time)
    items: list[Item] = Field(min_length=1, max_length=50)

    _id = field_validator("id")(lambda cls, v: _match(PACK_ID, v, "pack id (2-48 lowercase letters, digits and dashes)"))
    _name = field_validator("name")(lambda cls, v: _text(v, 80, required=True))
    _version = field_validator("version")(lambda cls, v: _match(VERSION, v, "version (e.g. 1.0.0)"))
    _description = field_validator("description")(lambda cls, v: _text(v, 4000, multiline=True))
    _creator = field_validator("created_by")(lambda cls, v: _text(v, 120))

    @field_validator("source_tool")
    @classmethod
    def _source(cls, v: str | None) -> str | None:
        return _match(TOOL_ID, v, "tool id") if v is not None else None

    @model_validator(mode="after")
    def _consistent(self) -> "ExtensionPack":
        for kind, attr in (("domain", "key"), ("sso", "key"), ("team", "category")):
            keys = [getattr(i, attr) for i in self.items if i.kind == kind]
            if len(set(keys)) != len(keys):
                raise ValueError(f"the pack defines the same {kind} {attr} twice")
        for item in self.of("connector"):
            if not (item.tool or self.source_tool):
                raise ValueError("a connector item needs a tool (or the pack's source_tool)")
        for rule in (r for c in self.of("controls") for r in c.rules):
            domain = next((d for d in self.of("domain") if d.key == rule.domain), None)
            if domain is None:
                continue  # a domain of another pack: checked when the pack is enabled
            for name in [c.field for c in rule.where] + ([rule.age_field] if rule.age_field else []):
                if domain.field(name) is None:
                    raise ValueError(f"control rule '{rule.title}': '{name}' is not a field of '{rule.domain}'")
            if rule.age_field and domain.field(rule.age_field).type != "date":  # type: ignore[union-attr]
                raise ValueError(f"control rule '{rule.title}': age_field must be a date field")
        return self

    def of(self, kind: str) -> list[Any]:
        return [i for i in self.items if i.kind == kind]

    @property
    def domains(self) -> list[DomainItem]:
        return self.of("domain")

    def summary(self) -> dict[str, Any]:
        """What the pack adds, for lists and approval texts."""
        return {"kinds": {k: len(self.of(k)) for k in KINDS if self.of(k)},
                "domains": [d.key for d in self.domains],
                "connectors": [c.tool or self.source_tool for c in self.of("connector")],
                "sso": [s.name for s in self.of("sso")],
                "controls": sorted({r.control for c in self.of("controls") for r in c.rules}),
                "teams": [t.category for t in self.of("team")]}


def describe_errors(exc: ValidationError, limit: int = 5) -> str:
    parts = []
    for error in exc.errors()[:limit]:
        where = ".".join(str(x) for x in error.get("loc", ()))
        parts.append(f"{where}: {str(error.get('msg', 'invalid')).removeprefix('Value error, ')}" if where
                     else str(error.get("msg", "invalid")).removeprefix("Value error, "))
    more = len(exc.errors()) - limit
    return "; ".join(parts) + (f" (and {more} more)" if more > 0 else "")


def parse(data: Any) -> ExtensionPack:
    """A validated pack from JSON text or a parsed object; ValueError with readable messages otherwise."""
    if isinstance(data, (bytes, str)):
        if len(data) > MAX_PACK_BYTES:
            raise ValueError(f"The pack is larger than {MAX_PACK_BYTES // 1000} KB")
        try:
            data = json.loads(data)
        except ValueError as exc:
            raise ValueError(f"The pack is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("A pack is a JSON object")
    if len(json.dumps(data, default=str)) > MAX_PACK_BYTES:
        raise ValueError(f"The pack is larger than {MAX_PACK_BYTES // 1000} KB")
    try:
        return ExtensionPack.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid extension pack: {describe_errors(exc)}") from exc


def fill(text: str, values: dict[str, str]) -> str:
    """Replace "{name}" for the given names only - plain text substitution, never str.format."""
    return re.sub(r"\{([a-z_]{1,40})\}", lambda m: values.get(m.group(1), m.group(0)), text)
