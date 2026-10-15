"""The stored dashboard documents, the request bodies and the limits (round4-dashboard-spec.md 5.2, 5.4, 7.2).

Every model is strict (``extra="forbid"``). Titles and descriptions follow the extension packs' text rules
(``pack._text``: no control characters, single-line titles, stripped). A widget's ``config`` is a plain dict here; it is
validated against its widget type's config model on every save (``store.check_widgets``).
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..extensions.pack import _text

DASH_ID = r"^[ps]_[0-9a-f]{10}$"
PERSONAL_ID = r"^p_[0-9a-f]{10}$"
SHARED_ID = r"^s_[0-9a-f]{10}$"
WIDGET_ID = r"^w_[0-9a-z]{8,10}$"
TYPE_KEY = r"^[a-z][a-z0-9_]{1,31}$"
ICON = r"^[a-zA-Z]{1,24}$"
FROM = r"^(template:[a-z][a-z0-9_]{1,31}|[ps]_[0-9a-f]{10})$"
COLS, MAX_ROWS, MAX_H = 12, 200, 12

LIMITS: dict[str, int] = {
    "personal_dashboards": 20, "shared_dashboards": 30, "widgets": 40, "cols": COLS, "max_rows": MAX_ROWS,
    "max_h": MAX_H, "config_bytes": 4096, "dashboard_bytes": 65536, "widgets_per_request": 40, "list_rows": 25,
    "list_rows_default": 8, "groups": 12, "filters": 5, "note_chars": 2000, "links": 12, "tool_health_tools": 20,
    "embed_tools": 50,
}


def canonical(value: Any) -> str:
    """Canonical JSON: the cache key, the "unchanged widget" comparison and the size limits use it."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


class WidgetInstance(BaseModel):
    """One tile: a widget type, its grid cell (x, y) and size (w, h) in a 12-column grid, an optional title and its
    type's config. The client makes the id; the server checks it is unique in the dashboard."""

    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=WIDGET_ID)
    type: str = Field(pattern=TYPE_KEY)
    x: int = Field(ge=0, le=COLS - 1)
    y: int = Field(ge=0, le=MAX_ROWS - 1)
    w: int = Field(ge=1, le=COLS)
    h: int = Field(ge=1, le=MAX_H)
    title: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("title")
    @classmethod
    def _title(cls, v: str | None) -> str | None:
        return (_text(v, 80) or None) if v is not None else None

    @field_validator("config")
    @classmethod
    def _config(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(canonical(v)) > LIMITS["config_bytes"]:
            raise ValueError("is larger than 4 KB")
        return v

    def content(self) -> str:
        """What a widget shows, without where it sits: an unavailable widget may move but not change (store 5.3)."""
        return canonical({"type": self.type, "title": self.title, "config": self.config})


class Dashboard(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=DASH_ID)
    scope: Literal["personal", "shared"]
    owner_id: str | None = None  # the user id for a personal dashboard, None for a shared one
    title: str
    icon: str = Field("home", pattern=ICON)  # an ICONS key; the UI falls back to "grid"
    description: str = ""
    widgets: list[WidgetInstance] = Field(default_factory=list, max_length=LIMITS["widgets"])
    based_on: str | None = None  # a personal copy: the shared dashboard it started from
    based_on_version: int | None = None  # that dashboard's version at copy time
    template: str | None = None  # the template it was created from
    version: int = 0  # +1 on every write; only grows
    created_at: float
    updated_at: float
    updated_by: str

    _title = field_validator("title")(lambda cls, v: _text(v, 60, required=True))
    _description = field_validator("description")(lambda cls, v: _text(v, 300))


class DashboardPrefs(BaseModel):
    """Per user: tab order, hidden shared dashboards and the dashboard Home opens."""

    model_config = ConfigDict(extra="forbid")
    order: list[str] = Field(default_factory=list, max_length=60)
    hidden: list[str] = Field(default_factory=list, max_length=40)
    home: str | None = None
    version: int = 0


class DashboardSettings(BaseModel):
    """One document, administrators': the default dashboard. ``embed_tools`` and ``embed_checks`` belong to the
    optional stage D5 (tools' own pages in widgets), which is not built: they stay empty."""

    model_config = ConfigDict(extra="forbid")
    default_id: str | None = None
    embed_tools: list[str] = Field(default_factory=list, max_length=LIMITS["embed_tools"])
    embed_checks: dict[str, dict[str, Any]] = Field(default_factory=dict)
    version: int = 0


# -- request bodies -------------------------------------------------------------------------


class DashboardCreate(BaseModel):
    """POST /api/dashboards/mine and /shared: blank, from a template ("template:<key>") or a copy of a dashboard the
    caller can see."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)
    title: str
    icon: str = Field("home", pattern=ICON)
    description: str = ""
    from_: str | None = Field(None, alias="from", pattern=FROM)

    _title = field_validator("title")(lambda cls, v: _text(v, 60, required=True))
    _description = field_validator("description")(lambda cls, v: _text(v, 300))


class DashboardPut(BaseModel):
    """PUT .../{dash_id}: the whole dashboard as the client has it, against the version it started from."""

    model_config = ConfigDict(extra="forbid")
    title: str
    icon: str = Field("home", pattern=ICON)
    description: str = ""
    # more than 40 are refused by the layout check with a readable code (invalid_layout); this only bounds parsing
    widgets: list[WidgetInstance] = Field(default_factory=list, max_length=100)
    base_version: int = Field(ge=0)
    # "Reset to the shared version" of a personal copy: the shared dashboard's version the widgets were taken from
    based_on_version: int | None = Field(None, ge=1)

    _title = field_validator("title")(lambda cls, v: _text(v, 60, required=True))
    _description = field_validator("description")(lambda cls, v: _text(v, 300))


class PrefsPut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: list[str] = Field(default_factory=list, max_length=60)
    hidden: list[str] = Field(default_factory=list, max_length=40)
    home: str | None = Field(None, pattern=DASH_ID)
    base_version: int | None = Field(None, ge=0)

    @field_validator("order", "hidden")
    @classmethod
    def _ids(cls, v: list[str]) -> list[str]:
        if any(not re.match(DASH_ID, x) for x in v):
            raise ValueError("holds an invalid dashboard id")
        return list(dict.fromkeys(v))


class DefaultPut(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dashboard_id: str = Field(pattern=SHARED_ID)
