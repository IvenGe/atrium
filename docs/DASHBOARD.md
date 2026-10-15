# Home dashboards

**Home** (`#/`) is a grid of **widgets**: numbers, lists, charts and settings from the hub and from every connected
tool. Everyone can arrange their own dashboards by dragging, and every drag has a click and a keyboard way to do the
same thing. Administrators publish shared dashboards for everyone and choose the default one.

- [Using dashboards](#using-dashboards): tabs, customizing, shared dashboards, live updates.
- [Moving and resizing without a mouse](#moving-and-resizing-without-a-mouse): the keyboard model and the menu
  alternatives.
- [Widgets](#widgets): the catalog, record widgets that work with every tool, the per-tool suggestions.
- [Settings on the dashboard](#settings-on-the-dashboard): the AI models widget (drag agents between model providers),
  the safety settings and hub accounts widgets, and **Add to Home** on the Settings page.
- [Widgets declared by packs and tools](#widgets-declared-by-packs-and-tools): `widget` pack items and a manifest's
  `ui.widgets`.
- [Roles](#roles), [Security](#security), [Performance](#performance), [Endpoints](#endpoints).
- [Not built: tools' own pages inside widgets](#not-built-tools-own-pages-inside-widgets): a possible later option and
  its risks.

## Using dashboards

### Tabs

Each dashboard is a tab above the grid. A tab marked **Shared** is published by an administrator and is the same for
everyone; the others are your own and nobody else can see them, administrators included. The tab marked "your home"
opens when you go to `#/`: your own choice ("Set as my home"), else the administrators' default, else the first tab.
`#/d/<dashboard id>` links to a tab.

- **+** (New dashboard): a name, an icon, and **Start from**: blank, one of the templates (Overview, Security
  operations, Compliance, IT & people, Settings & AI) or a copy of a dashboard you can see. A blank dashboard opens in
  edit mode.
- **⋯** (Dashboard options): Rename, Set as my home, Make a personal copy and Hide from my tabs (shared dashboards),
  Move tab left / right, Reset to the shared version (a copy whose shared dashboard was published again), Show hidden
  dashboards, Delete this dashboard (your own). Administrators also get Make it the default for everyone, Publish as a
  shared dashboard (from one of their own) and Delete for everyone (refused for the default, which must be replaced
  first).
- Tabs can also be dragged into another order. The keyboard moves between tabs with Left, Right, Home and End, and
  Enter or Space opens one (moving the focus does not load every dashboard on the way).

Your tab order, hidden shared dashboards and home are saved for your account, not per browser.

On a fresh hub (or one upgraded from before dashboards) Atrium creates one shared dashboard, **Overview**, and makes it
the default. It shows the same seven tiles and two cards as the Home page had before: Apps integrated, Agents,
Awaiting approval, Assets, People, Vulnerabilities and Compliance, then Apps and Live agent activity. It is created
once; an administrator who deletes it keeps it deleted.

### Customizing

**Customize** turns on edit mode:

- on your own dashboard straight away;
- on a shared dashboard, as a non-administrator, it first offers **Make a personal copy to customize** (and to hide
  the shared one from your tabs). Widgets in the shared dashboard that need a higher role than yours are left out of
  the copy, and the message says how many;
- on a shared dashboard, as an administrator, the button reads **Edit shared dashboard** and the changes are a draft
  (below).

In edit mode every widget has a **move handle** (top left), its **options** button (⋯, top right) and a **resize
handle** (bottom right), and the toolbar above the grid stays in view: **Add widget**, **Undo**, **Redo**
(Ctrl+Z / Ctrl+Shift+Z, Cmd on a Mac, while the focus is in the dashboard and not in a text field), **Reset...**
(back to the shared version or to the template the dashboard came from) and **Done**.

- **Drag** a widget by its handle (or its title bar) to move it: the others make room and everything falls up into
  free space. Drag the corner handle to resize: a tip shows the new size in columns and rows. Esc cancels a drag.
- **Add widget** opens the gallery: a search field, categories (From your tools, Overview, Tools, Records, Agents,
  Compliance, Network, People, Settings, Notes), the suggestions for each connected tool, the hub's own suggestions,
  and "Build your own" cards that open the configure dialog first. **Add** puts the widget in the first free place;
  on a wide screen the gallery is a drawer beside the grid and its cards can also be dragged onto the grid by their
  grip. A dashboard holds at most 40 widgets.
- **Configure...** (options menu) shows the widget's settings as a form with a live preview of the data, and an
  optional title.
- **Remove** (options menu) can be undone.

**Your own dashboards save themselves** about a second after each change ("Saving...", "Saved", or "Not saved -
Retry"). If the same dashboard changed in another window, you choose: **Reload** (your last change is dropped) or
**Keep mine** (saved over the other version).

**Shared dashboards are drafts until published.** Nobody else sees the changes until **Publish** (the toolbar counts
the unpublished changes); **Discard** throws them away, and **Done** asks which. If you leave the page with unpublished
changes, the draft stays in that browser tab and is offered back when you return. Publishing is logged in the activity
log ("Published the shared dashboard Security") and everyone who has that dashboard open sees the new version within
seconds ("Dashboard updated by ava"); an administrator editing the same dashboard is told that a newer version was
published and can reload or keep editing (the next Publish then asks).

### In view mode

The options button of a widget offers Refresh, **Show as table** (charts; remembered per widget in this browser), Open
in the app the widget comes from, **Copy to dashboard...** (one of your own) and Configure... where you may edit. KPI
tiles are links as a whole. Bar rows, matrix cells and list rows link to the app, filtered where the app supports it
(the Vulnerabilities page reads `severity`, `status`, `source` and `overdue` from links such as
`#/vulnerabilities?severity=high&status=active&source=openvas`).

### Live updates

Widgets refresh themselves over the event stream the rest of the UI uses (`/api/events`): each widget type names the
events that change its data, and only the affected widgets are fetched again, in one request. Widgets whose data ages
with time (activity, approvals, scan coverage) also refresh every 1, 5 or 60 minutes while the page is visible.
Widgets below the fold load when they are scrolled near. When the stream is down, the tab bar shows **Live updates
paused**; a widget whose data is older than it should be shows **Updated 12m ago** with a refresh button. A refresh
never moves the focus or the scroll position.

### Narrow screens

Below 960 pixels of dashboard width (a phone, or a small window with the sidebar open) the grid becomes one column
(two for small tiles) in the dashboard's reading order. Moving still works with the handle, the keyboard and the menu
(up and down); resizing waits for a wider screen. Reordering there changes the order wide screens show too, and the
first time a toast says so. The gallery is a full-screen dialog. Nothing scrolls sideways at 320 pixels.

## Moving and resizing without a mouse

Every drag has a keyboard way and a click (or tap) way that needs no dragging.

| Drag | Keyboard | Click or tap |
| --- | --- | --- |
| Move a widget | Focus its move handle: Space or Enter picks it up, arrow keys move it a cell (on a narrow screen Up / Down move it a position), Home / End to the start / end of the row, Space or Enter drops it, Esc cancels | Options: Move up / down / left / right, Move to start, Move to end, **Move to...** (row and column, or a position) |
| Resize a widget | Focus its resize handle: Space or Enter starts, arrow keys change width and height within the widget's bounds, Space or Enter finishes, Esc cancels | Options: Small, Medium, Large, Wide, Tall, and Narrower, Wider, Shorter, Taller |
| Add from the gallery | **Add** on the card (Tab to it) | **Add** on the card |
| Reorder tabs | - | ⋯: Move tab left / Move tab right |
| Move an agent to another model provider (AI models widget) | Focus the agent: Space picks it up, arrow keys go through the providers it may go to, Space or Enter drops, Esc cancels | **Change...** on the agent (provider and model) |
| Change the suite default (AI models widget) | The **Default** marker: as an agent | **Set as default...** on a provider, **Use automatic** |
| Move a widget to another dashboard | - (no drag either) | Options: Copy to dashboard..., Move to dashboard... |

- Every step is announced in a polite live region: "Picked up Assets. Row 1, column 1, 3 by 1.", "Row 2, column 4",
  "Dropped at row 2, column 4.", "Move cancelled", "Assets is now 4 columns wide, 2 rows tall", "Added OpenVAS: overdue
  findings at row 3, column 7". The handles describe these keys to screen readers.
- Single keys act only while a handle has the focus. After a drop or resize the focus stays on the handle; after
  Add it goes to the new widget's handle, unless the gallery drawer covers that widget, in which case it stays in the
  drawer and the announcement says where the widget went. After Remove it goes to the next widget.
- The options menus are lists of buttons: arrow keys, Home and End move between them, Esc or Tab closes the menu and
  returns to its button, which says whether it is open (`aria-expanded`).
- Handles, options buttons and tabs are at least 24 pixels (32 on touch screens). Touch scrolling is never captured
  outside edit mode, and in edit mode only on the handles.
- The dashboard follows the light and dark themes, reduced motion (no movement animations) and forced colours
  (outlines and the drop placeholder in system colours).

## Widgets

The server computes every widget's data from its stored settings: the browser never sends a query, only which widgets
it wants (the configure dialog's preview sends a widget's settings, checked the same way). Settings are checked against
a whitelist when they are saved and again on every read.

| Widget | Category | Shows | Settings |
| --- | --- | --- | --- |
| Metric | Overview | one number (17 metrics, below) as a tile linking to its app | which metric |
| Apps | Tools | every tool, or the ones picked, with its status, health, connection and data flows | tools (all or up to 20), only problems |
| Tool overview | Tools | one tool: status, the records it brings per data type, its data flows, recent activity | the tool |
| Agent activity | Agents | the live activity log (never its data) | agents, people or both, lowest level, one actor, how many |
| Agents | Agents | agents with their status and the model they use | a team or all, show the model |
| Approvals | Agents | decisions waiting for a person (read-only: decide on the Approvals page) | kinds, how many |
| Count of records | Records | how many records of any data type, as a number, bars or a list of groups | data type, source, filters, group by, view |
| List of records | Records | records of any data type, sorted, with chosen columns | data type, source, filters, sort, order, up to 4 columns, up to 25 rows |
| Records over time | Records | records per day by one of their dates | data type, source, filters, date, 7-90 days |
| Compliance | Compliance | framework scores, the latest CyFun self-assessment, frameworks from GRC tools | frameworks, GRC tools, CyFun |
| Controls | Compliance | baseline controls by status, failing first | statuses, family, how many |
| Risk matrix | Compliance | risks by likelihood and impact (5 x 5) | source, statuses |
| Vulnerability deadlines | Compliance | open and overdue findings per severity, fixes in 30 days, scan coverage | source |
| Network devices | Network | firewalls and devices: last read, drift, device changes | devices |
| Leavers | People | people who left but still hold assets, tool accounts or an Atrium sign-in | how many |
| Note | Notes | your own text (Markdown) | text (2000 characters) |
| Links | Notes | shortcuts to Atrium pages and tools' portals | up to 12 links |
| AI models | Settings | which model every agent runs on, one lane per provider | all, custom or core agents |
| Safety settings | Settings | autonomy and the guardrails relaxed from their safe default | - |
| Hub accounts | Settings | accounts by role, disabled and dormant accounts, active API tokens (administrators) | - |
| Declared widget | Records | a widget a pack or a tool's manifest declares ([below](#widgets-declared-by-packs-and-tools)) | - |

**Metrics**: Apps integrated, Agents, Awaiting approval, Assets, People, Leavers holding something, Vulnerabilities, Past
their deadline, Compliance, Open risks, Data flows, Failing data flows, Configuration drift, Critical drift, Device
changes waiting, Extension apps and AI spending today. They are the same numbers as the badges and `/api/overview`.
AI spending today is an estimate (it says so): "of $20 daily limit" while the spending cap is on, a warning at 80 %
and a problem at the limit.

Charts follow one rule set: a single count is a number, a breakdown is horizontal bars in one colour (severity and
status use their own colours, always beside their names), time is columns, risk is a 5 x 5 matrix. Every bar, column
and cell has a full accessible name ("High: 12 open findings, 30%") and **Show as table** turns any chart into a table.

### Records from every tool

Record widgets (count, list, over time) read the hub's canonical data types and every extension data type, so every
connector Atrium has now - and any it gets later - feeds them without code:

| Data type | Group by | Filter by | Sort by |
| --- | --- | --- | --- |
| Assets | type, status, criticality, source | type, status, criticality, scan scope | name, criticality, updated, last scanned |
| Vulnerabilities | severity, status, source, overdue | severity, status, overdue | severity, deadline, first seen, CVSS |
| Risks | status, level, treatment, source | status, level, treatment | score, created, reviewed |
| Controls | status, family | status, family | id, status |
| People | status, department, source | status, department | name, terminated, updated |
| Accounts | tool, active | active, tool | last sign-in, login |
| Network devices | product, changes allowed, out of date | changes allowed, out of date | name, last read, open drift |
| Extension data types (`x:<key>`) | every severity and enum field, source | every severity, enum and text field | every date and number field, updated |

- **Source**: all sources, one tool (`tool:<id>`: the records that tool brought, by the provenance each record keeps)
  or "added by hand". A person counts in each directory they come from.
- **Filters**: up to 5, each "is", "is not" or "is one of" on a whitelisted field; enum and severity values must be
  among the field's own. Any other field is refused (422), so a widget can never show, say, an asset's raw facts or a
  person's email address.
- Breakdowns show the 12 largest groups and "Other"; severities, criticalities and statuses keep their natural order.
- A record widget whose tool is removed or whose data type is no longer active says so and offers **Remove widget** and
  **Choose another tool**; it stays on the dashboard until someone changes it.

### Suggestions for each tool

The gallery's **From your tools** lists ready-made widgets per tool, generated from what its connection reads, with no
per-product code: an overview for every tool, then for each data type the connection reads, the presets below scoped
to that tool. For example "Snipe-IT: assets by type", "OpenVAS: overdue findings", "CISO Assistant: risk matrix",
"Okta: suspended or terminated", or "Wazuh: Alerts by severity" for an extension data type.

| Data type | Presets |
| --- | --- |
| Assets | assets by type; recently updated assets |
| Vulnerabilities | open findings by severity; overdue findings; SLA |
| Risks | risk matrix; top risks |
| Controls, frameworks | frameworks; failing controls |
| People | people by status; suspended or terminated |
| Accounts | active accounts; accounts by last sign-in |
| Network | device status |
| Extension data types | `<type>` by its first severity (else enum) field; latest `<type>` |

The hub's own suggestions add one "all sources" count per data type, every metric, approvals, activity, leavers,
network devices and the settings widgets.

### What a widget may show

- A widget's data never contains a credential, an API key, a key source, a base URL, a webhook URL, a connection's
  settings, a record's raw facts or payload, an activity entry's data or a device backup. Each widget type builds its
  data from named fields only; a test walks the data of every type, the catalog and the previews for forbidden keys and
  for secrets seeded in the hub.
- Text that comes from tools (record titles, names, cells) is shortened and stripped on the server of control
  characters and of the characters that could disguise it (bidi overrides and isolates, zero-width characters, line
  and paragraph separators, C1 controls), and escaped by the UI. Links in widget data are internal routes built by the server; external links (an
  extension field of type `link`) are http(s) only and open in a new tab without a referrer.
- A widget shows the same data to everyone who may see it: results are computed without knowing who asks and cached
  for everyone (the role is checked before). The AI models widget therefore carries no "can edit" flag; the browser
  shows the edit controls by role and the server checks every write.
- Widgets that need a higher role than yours are not offered, are refused when you save them, and show "Needs the
  admin role" if your role was lowered since. A shared dashboard shows a non-administrator only the widgets their
  role allows (their number is counted, their titles are not shown).

## Settings on the dashboard

### AI models

The **AI models** widget shows which model every agent that uses one runs on, in one lane per provider:
**Inherits** (agents without a choice of their own; each says where its model comes from, e.g. "Compliance team
default" or "Suite default (automatic)"), Claude (Anthropic), OpenAI (ChatGPT models), each local model server and
Rules (no model). Each lane says its status in words ("connected", "not connected: no API key", "blocked: cloud
providers are switched off") and "Cloud" for a third-party service. The header says the suite default, e.g.
"Automatic (now Claude Opus 5.5)". Agents that work without a model (the Operator and the module supervisors) are
counted in the footer.

Administrators change the choice by dragging (everyone else sees the same lanes, read-only):

- **Drag an agent** onto another lane to make that provider the agent's own choice, or onto **Inherits** to remove it.
  Lanes the agent may not go to do not light up and refuse the drop with the reason: a provider that is not available
  ("OpenAI (ChatGPT models) is not connected: no API key"), or a cloud provider for a local-only agent ("Hub Supervisor is
  local-only"). When the provider has no default model, a dialog asks for one.
- **Drag the Default marker** onto a lane (or onto Automatic) to change the suite default. Making Rules the default
  asks first, because agents without their own choice then stop using an AI model.
- Without dragging: **Change...** on an agent (provider and model), **Set as default...** on a lane, **Use automatic**
  in the header, or the keyboard (focus an agent or the marker, Space, arrow keys through the allowed lanes, Space).
- Writes go through the same routes and checks as the Agents and Settings pages: `PATCH /api/agents/{id}/settings`
  and `PATCH /api/llm/selection` (administrators; the cloud-provider guardrail and local-only rule apply there). Each
  sends the version shown when the agent was picked up: if someone changed it meanwhile, the widget reloads ("Changed
  elsewhere; the widget was reloaded") instead of overwriting their change.
- A per-task choice (the Patch Agent's code changes, for example) is shown as "+1 per task" with a link to the agent's
  model settings; dragging changes only the agent-level choice and the announcement says the per-task one still
  applies.
- While an agent or the marker is picked up, new data for the widget waits until the drop or cancel, so agents
  reporting their status do not interrupt a move.

### Safety settings and hub accounts

- **Safety settings** shows the autonomy level, the guardrails relaxed from their safe default (with the control each
  weakens), whether device changes are on, whether cloud AI is allowed and the AI spending cap. It is read-only: its
  link opens Settings, which keeps the risk confirmations.
- **Hub accounts** (administrators only) shows accounts per role, disabled accounts, accounts not used for 90 days and
  active API tokens.

### Add to Home

The Settings cards Agent autonomy, Agent guardrails, AI providers, Model choice, AI usage and spending and Network
changes have an **Add to Home** button (every role). It adds the matching widget (safety settings, AI models, AI
spending today or network devices) to your home dashboard if it is your own, else to your first own dashboard, else to
a new "My dashboard" copied from the default. The toast says where ("Added to Ops board", or "Already on Ops board"
when the same widget is there) with an **Open** link.

### The Settings & AI template

New dashboard > Start from > **Settings & AI**: the AI models widget across the full width, AI spending today, safety
settings, apps and agents.

## Widgets declared by packs and tools

An extension pack and a tool's manifest can declare widgets as data. The hub compiles a declaration to its own count,
breakdown or list widget: no code, HTML, colours or URLs.

```json
{"kind": "widget", "key": "open_alerts", "title": "Open alerts by severity", "view": "breakdown",
 "domain": "x:alerts", "where": [{"field": "status", "op": "eq", "value": "open"}], "group_by": "severity"}
```

| Field | Meaning |
| --- | --- |
| `key` | 2-32 lowercase letters, digits and `_` |
| `title`, `description` | plain text, at most 60 and 200 characters (no markup, no URLs) |
| `view` | `count` (one number), `breakdown` (bars; needs `group_by`), `list` (rows; may have `columns` and `sort`), `metric` (one number, small) |
| `domain` | `assets`, `vulnerabilities`, `risks`, `controls`, `people`, `accounts`, `network` or `x:<extension data type>` |
| `where` | up to 5 conditions with `eq`, `ne` or `in` (1-20 values) |
| `group_by`, `columns` (up to 4), `sort`, `order` (`asc` / `desc`), `limit` (1-25, default 8) | fields the data type whitelists ([above](#records-from-every-tool)) |
| `size` | `s` (3 x 2), `m` (4 x 3, default) or `l` (6 x 4) grid cells; a metric is always small |

- **In a pack** it is an item of kind `widget` ([AGENTS.md](AGENTS.md#what-a-pack-can-contain)): its field names are
  checked against the pack's own data types when the pack is uploaded, and the widget is offered in the gallery as
  "From <pack>" while the pack is enabled.
- **In a tool's manifest** it goes in `ui.widgets` (at most 10, [MANIFEST.md](MANIFEST.md#dashboard-widgets)). A
  manifest comes from the tool's repository, so its widgets are untrusted: they are only suggestions ("Suggested by
  <tool>"), never added to a dashboard by themselves, always limited to that tool's own records, and only for data
  types its connection reads now. An invalid declaration is left out with its reason in the analysis notes; the rest
  of the manifest still applies.
- A widget added from a declaration keeps its reference (`pack:<id>/<key>` or `tool:<id>/<key>`), so a pack or
  manifest update applies to it. When the declaration disappears or no longer fits, the widget says so.

## Roles

| Who | May |
| --- | --- |
| Anyone signed in (viewer and up) | read the shared dashboards and the widgets their role allows; create, change, reorder, hide and delete **their own** dashboards and tab preferences (`/api/dashboards/mine`, `/api/dashboards/prefs`) |
| Administrators | also create, publish and delete shared dashboards and choose the default; add the Hub accounts widget; edit in the AI models widget |
| API tokens | read the shared dashboards and their data; never personal dashboards (403 `person_required`: a token has no Home) |
| Integration tokens | nothing here (they may only publish events) |

Personal dashboards are private: they are always looked up under the caller's own account, so another person - an
administrator too - gets 404. They are never sent on the event stream (which every signed-in principal receives) and
changing them is not logged. Deleting an account deletes its dashboards and preferences.

## Security

- **Policy.** The personal dashboard routes are a self-service list in `auth/policy.py` (`SELF_SERVICE_ROUTES`,
  viewer); shared dashboards and the default are administrator routes. Every route is in the permission-matrix tests.
  Writes need the `X-Hub-Request` header like every other change.
- **Validation.** Every model is strict; titles follow the extension packs' text rules; a widget's settings are at most
  4 KB and validated against its type on every save; a dashboard is at most 64 KB and 40 widgets in a 12-column grid
  without overlaps; at most 20 personal dashboards per person and 30 shared ones. A widget whose type or tool is gone
  can stay only unchanged.
- **Versions.** Every save names the version it started from; a stale one gets 409 with the current document.
- **Errors** never repeat a widget's settings or record contents; a widget that fails to compute shows "Could not
  compute this widget" and the log names only its type and id.
- **Bounded work.** A data request asks for at most 40 widgets; results are cached (512 entries, per widget type and
  settings) until an event they depend on or their time-to-live; concurrent requests for the same widget compute it
  once; the configure dialog's fresh previews recompute at most every 5 seconds.

## Performance

Measured on the 4-CPU development container with 10 000 vulnerabilities, 5 000 assets, 2 000 people, 20 000
extension records and 100 tools (`tests/test_dashboards_perf.py`, run with `HUB_SLOW_TESTS=1`):

| Request | Spec budget | Measured |
| --- | --- | --- |
| 20 widgets, from the cache | 30 ms | about 5 ms |
| The widget catalog with 100 tools | 100 ms | about 12 ms |
| 20 widgets, nothing cached | 300 ms | about 450-650 ms |

The cold request misses its budget: about 250 ms of it is SQLite reading fields out of 37 000 JSON documents. Widgets
read only the fields they need inside SQLite and each collection once per request, and leavers are found over the
people who left only (that alone took 300 ms before). The next step would be keeping the counted fields in columns of
their own. Cached results serve every viewer, so a cold request happens after an event that touches a widget's data
or when its time-to-live (5 to 300 seconds) ends.

## Endpoints

| Route | Role | Does |
| --- | --- | --- |
| `GET /api/widgets/catalog` | viewer | widget types, data types and their whitelists, metrics, tools and what they read, suggestions, templates and limits, filtered by role |
| `GET /api/widgets/preview?type=&config=` | viewer | one widget's data for the configure dialog (`fresh=1` recomputes) |
| `GET /api/widgets/templates/{key}` | viewer | a template's widgets as the caller may have them ("Reset to template") |
| `GET /api/dashboards` | viewer | the caller's tabs (shared and own), preferences, the default and the resolved home |
| `GET /api/dashboards/settings` | viewer | the default dashboard |
| `GET /api/dashboards/{id}` | viewer | one dashboard; a personal one only the caller's own; widgets above the caller's role left out of a shared one |
| `GET /api/dashboards/{id}/data?widgets=` | viewer | `{generated_at, widgets: {id: result}}` with each result's `status` (`ok`, `empty`, `forbidden`, `unavailable`, `error`), data, version and staleness |
| `POST /api/dashboards/mine` | viewer, people only | a personal dashboard: blank, `template:<key>` or a copy (`dropped` counts the widgets left out) |
| `PUT /api/dashboards/mine/{id}` | viewer, people only | replace it (`base_version`) |
| `DELETE /api/dashboards/mine/{id}` | viewer, people only | |
| `PUT /api/dashboards/prefs` | viewer, people only | tab order, hidden shared dashboards, home |
| `POST /api/dashboards/shared` | admin | a shared dashboard (logged) |
| `PUT /api/dashboards/shared/{id}` | admin | publish (logged; event `dashboard`) |
| `DELETE /api/dashboards/shared/{id}` | admin | 409 `is_default` for the default (logged) |
| `PUT /api/dashboards/default` | admin | `{dashboard_id}` of a shared dashboard (logged; event `dashboard_settings`) |

Errors carry `detail = {code, message, ...}`: `version_conflict` (409, with the current `dashboard` or `prefs`),
`invalid_layout` and `invalid_widget` (422, with `widget_id`), `role_required` (403), `person_required` (403),
`limit` (409), `is_default` (409), `too_large` (413), `not_found` (404).

**Events**: `dashboard {id, scope: "shared", version, updated_by, removed}` and `dashboard_settings {version}`; widgets
also listen to `settings {keys}` (published by `PATCH /api/settings` and `PATCH /api/settings/guardrails` with the
changed key names only, never values).

**Code**: `hub/dashboards/` (models, store, layout, registry, the widget types in `widgets.py`, `records.py`,
`apps.py`, `declared.py` and `settings_widgets.py`, metrics, domains, suggestions, resolution, the cache and templates),
`hub/dashboards_api.py`; in the UI `hub/web/js/views/home.js` and `hub/web/js/dashboard/` (`grid.js` is the pure layout
math, shared with `hub/dashboards/layout.py` through `tests/data/dashboard_layouts.json`).

## Not built: tools' own pages inside widgets

A widget that shows a tool's own web page (a Grafana or Wazuh dashboard, say) was designed but **not built**; the
Portal (`#/portal/<tool>`) remains the way to open a tool's page inside Atrium. If it is wanted later, the design is:

- a new guardrail, off by default, plus an administrator's list of the tools allowed; switching it on would make
  control HB-AC-4 partial, because pages Atrium does not control would appear inside its interface;
- a sandboxed frame (`allow-scripts allow-same-origin allow-forms`: no top-level navigation, pop-ups, downloads or
  delegated device features), refused when the page's origin is Atrium's own (a same-origin page could lift the
  sandbox), no credentials or tokens in the URL, `referrerpolicy="no-referrer"`;
- a `Content-Security-Policy: frame-src` on Atrium's page listing only the registered tools' origins;
- visible chrome outside the frame: the tool's name and origin, "External page - not part of Atrium" and "Open in new
  tab", so a compromised tool page cannot pass for an Atrium sign-in prompt;
- an administrator-triggered check of whether the tool forbids framing (`X-Frame-Options`, `frame-ancestors`), which
  refuses link-local and metadata addresses;
- known limits: an http tool page cannot be shown inside https Atrium, and browsers that block third-party cookies show
  the tool's own sign-in when the tool is on another site.

A manifest's `ui.embed: true` is only a hint and allows nothing. The Portal already refuses a tool address that is
Atrium's own origin, carries a user name and password or has a credential-like query parameter (`js/frameurl.js`).
