# People

The **People** app (`#/people`, sidebar under Govern, also in Portals and Ctrl K) is the workforce directory of the
suite: everyone the connected directories know, merged into one person each, with the accounts they hold in the tools,
the assets they own or use, and the risks and policies they own. It finds **leavers**: people who left or are
suspended but still have access or company devices.

The **People Supervisor** (`module:people`) runs the people and accounts data flows, re-links people to accounts and
assets after every pull, and reports leavers. Control **HB-AC-7** checks the leavers.

## Sources

| Source | What it brings | Set up |
| --- | --- | --- |
| Okta | people (status, manager, groups, profile) and their app assignments as accounts | a connection of kind `okta` on the Okta tool (import it as a SaaS service) |
| Keycloak admin API | a realm's people (enabled or not, groups, attributes) | a connection of kind `keycloak` on the Keycloak tool |
| SCIM 2.0 | people from any SCIM directory or HR system, or an application's own users as its accounts | a connection of kind `scim`, with "The users are" set to people or accounts |
| Snipe-IT | user accounts (with **Read user accounts** on) and the assigned user of each device | its `snipeit` connection |
| Generic REST | `people` and `accounts` from any JSON API | a `generic_rest` mapping for those domains |
| By hand | anyone you add on the People page (source `manual`) | **Add person** (operator) |

The connectors and their settings are described in [INTEGRATIONS.md](INTEGRATIONS.md#connectors). Once a connection
can read people or accounts, the Hub Supervisor proposes a **people** or **accounts** flow (an approval of kind
`flow`); approving it enables it, and the People Supervisor runs it on its schedule. People flows only pull.

## How people are merged

A pulled directory entry is matched to a person in this order:

1. the person this directory entry was matched to before (its id in that tool),
2. the same email address (case-insensitive),
3. the same login, or a login that is the person's email address.

Two entries of the same directory with the same email address stay two people. Then:

- **Profile fields** (display name, email, login, title, department, location, phone) a source sends overwrite the
  person's; empty ones never erase what another source said.
- **Groups** are kept per source and combined.
- **Managers** are resolved from the directory's manager reference: its id in that directory, else a login or email.
  (Okta's `managerId` is free text; see the [unverified note](INTEGRATIONS.md#okta).)
- **Status** is the most "left" of every source's status and the status set by hand: terminated beats suspended beats
  active. A status set by hand can mark someone as left, but a hand-set "active" cannot hide a directory that says the
  person left. `terminated_at` records when the person became terminated.
- **Leaving a directory**: a person a directory no longer lists counts as terminated there (flow option
  `retire_missing`, on by default). Keycloak has no terminated state, so this is how a deleted Keycloak user shows up.
- **Removing a tool**: its accounts are deleted and people lose it as a source, but what it said about leavers is kept
  as a hand-set status.

Edits by hand (operator): **Add person**, **Edit** and **Remove** on the People page. Each email address belongs to one
person, and managers cannot form a loop. A directory's next pull overwrites the fields it sends, and a person removed by
hand comes back while a directory still lists them; the edit form says so.

## Accounts

An **account** is a user account in a tool (collection `accounts`, id `<tool id>|<external id>`): login, email, display
name, the application (Okta app assignments), whether it is active and its last sign-in. A directory's own entries are
stored as accounts too (origin `people`), so an enabled Okta or Keycloak user is an active account.

Accounts are linked to a person by email, then login. **Accounts in tools** (`#/people/accounts`) lists them, filtered by
tool or **Not linked only**; operators can link an account to a person by hand, unlink it, or set it back to automatic. A
link made by hand sticks until someone sets it back to automatic.

## People and assets

Assets have two links to people besides the free-text owner (kept for display and older data):

| Field | Meaning | Set by |
| --- | --- | --- |
| `owner_person_id` | the accountable person | people (asset edit dialog, **Owner**) |
| `assigned_person_id` | who uses the device | the inventory, or people (**Used by**) |
| `assigned_source` | `auto`: follow the inventory's assigned user; `manual`: a person's choice | |

Asset pulls keep the inventory's assigned user in the asset's facts (`assigned_email`, `assigned_username`; Snipe-IT
does this), and while `assigned_source` is `auto` the hub links the asset to the person with that email or login. A
person picked by hand sticks until someone chooses **Automatic - follow the inventory** again. Picking an owner also
fills the free-text owner when none was given.

Risks and policies can name an owner person too (`owner_person_id`), and Atrium accounts are linked to the person with
the same email. **Users & access** shows each account's person and warns when a person who left still has an enabled
account.

## The person page

`#/people/<id>` shows:

- the profile, status and sources (with the status each source reports), manager and direct reports, groups by source;
- assets owned and used (unassign one or all), accounts per tool, the Atrium account and role;
- risks and policies they own, open vulnerabilities on their assets (at most 100), recent activity;
- a leaver warning with the one-click actions, when it applies;
- a relationship map: the person in the middle, their assets, tools, groups, manager and Atrium account around them.
  Clicking an asset, tool or manager opens it. It shows at most 24 items ("+N more").

The list has search (name, email, login, title, department, groups), filters for status, department and source,
initials avatars, asset counts and active / total tool accounts.

## Leavers

A **leaver finding** is a suspended or terminated person who still has any of:

- an asset (not retired) they own or use,
- an enabled Atrium account with their email,
- an active account in a tool.

A finding with access (an Atrium account or a tool account) has severity `fail`; one with only assets is `partial`.
**Leavers** (`#/people/leavers`) shows one card per finding with what to clean up, and the People Supervisor writes each
new finding once to the activity log (again when its severity changes), after every people or accounts pull, with the
one-click actions it offers and the accounts to close in the tools.

| Action | Role | What it does |
| --- | --- | --- |
| Unassign assets | operator | takes the person off the assets they own or use (all, or the ones chosen). Devices the inventory assigned get `assigned_source: manual`, so the next pull does not link them again |
| Disable Atrium account | admin | disables the Atrium account with the person's email and ends its sessions, through the normal account update: you cannot disable yourself or the last admin |

Both ask for confirmation. Atrium does not change anything in the tools: unassigning only removes the hub's links (the
answer names the devices still checked out in the inventory tool), and accounts in tools have to be disabled there.

### Control HB-AC-7

| Status | When |
| --- | --- |
| `pass` | no leaver finding |
| `fail` | a leaver still has an enabled Atrium account or an active tool account |
| `partial` | leavers only still have assets |
| `na` | there are no people yet |

"Leavers lose access and return assets", family Access control; ISO 27001 A.5.18 / A.5.11, SOC 2 CC6.2 / CC6.3, NIS2
21(2)(i). A failing control raises the risk "Former staff keep access or company devices" (likelihood 3, impact 4).

## Roles

| Role | May |
| --- | --- |
| viewer | see people, accounts, leavers and person pages |
| operator | add, edit and remove people; link accounts; set asset, risk and policy owners; unassign assets |
| admin | also disable a leaver's Atrium account, and manage the directory connections (they hold credentials) |

## API

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/people?q=&status=&department=&source=` | viewer | the list (status takes comma-separated values; source is a tool id or `manual`), with counts by status, departments, sources and the number of leavers |
| `GET /api/people/leavers` | viewer | leaver findings with their actions |
| `GET /api/people/{id}` | viewer | the person page: reports, assets, accounts per tool, Atrium account, risks, policies, vulnerabilities, activity, leaver finding, relationship graph |
| `POST /api/people` | operator | add a person (`display_name` required); 409 when the email is taken |
| `PATCH /api/people/{id}` | operator | change fields; `status: null` clears the hand-set status |
| `DELETE /api/people/{id}` | operator | remove a person and every link to them |
| `POST /api/people/{id}/actions/unassign_assets` | operator | optional `{asset_ids}` |
| `POST /api/people/{id}/actions/disable_atrium_account` | admin | |
| `GET /api/accounts?tool_id=&person_id=&unlinked=true` | viewer | accounts with their person |
| `PATCH /api/accounts/{id}` | operator | `{person_id}` (a link or unlink by hand) or `{auto: true}` |

Assets (`POST` / `PATCH /api/assets`) accept `owner_person_id`, `assigned_person_id` and `assigned_source`; risks and
policies (`/api/grc/risks`, `/api/grc/policies`) accept `owner_person_id`. `GET /api/users` (admin) includes each
account's person, and `GET /api/overview` counts people and leavers.

## Limits

- Lists are loaded whole: there is no paging on `GET /api/people`, and the UI shows at most 500 rows (search to
  narrow). Very large directories will feel slow.
- Okta groups and app assignments, and Keycloak groups, cost one request per person; switch them off for very large
  directories.
- Snipe-IT accounts are off by default (**Read user accounts**), so its accounts flow is only proposed once an admin
  turns the option on.
