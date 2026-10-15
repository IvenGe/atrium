"""Dashboards on Home (round4-dashboard-spec.md): widget grids people arrange, from every connected tool.

- ``models``: the stored documents, request bodies and limits; ``store``: reads, validated writes, preferences and
  settings; ``layout``: the grid math shared with the browser.
- ``registry``: widget types and suggestion providers; ``widgets`` and ``metrics``: the stage-D1 types; ``resolve`` and
  ``cache``: server-side widget data, cached across viewers.
- Stage D3: ``domains`` (what record widgets may read of every domain and extension data type), ``records`` (counts,
  lists and timelines of records), ``apps`` (compliance, network and people widgets), ``suggest`` (per-tool presets) and
  ``declared`` (widgets declared as data by extension packs and tool manifests).
- Stage D4: ``settings_widgets`` (the AI models widget where administrators drag agents between providers, the
  safety settings and the hub accounts) and the ``llm_spend_today`` metric.
- ``templates``: ready-made dashboards and the first-start migration.
- The REST routes are in ``hub/dashboards_api.py``.

Importing the package registers the widget types (later stages add their modules below).
"""

from __future__ import annotations

from . import widgets as _widgets  # noqa: F401  (registers the D1 widget types)
from . import apps as _apps  # noqa: F401  (D3: compliance, network and people widgets)
from . import records as _records  # noqa: F401  (D3: record widgets over every domain)
from . import suggest as _suggest  # noqa: F401  (D3: per-tool suggestions)
from . import declared as _declared  # noqa: F401  (D3: widgets declared by packs and tool manifests)
from . import settings_widgets as _settings  # noqa: F401  (D4: AI models, safety settings, hub accounts)
from .store import forget_user  # an account was deleted: its personal dashboards and preferences go (5.5)
from .templates import migrate  # at hub start: the shared Overview dashboard, once

__all__ = ["forget_user", "migrate"]
