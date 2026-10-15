# Hub manifest

The hub manifest is the integration contract of a tool. The hub infers one for every tool it
imports; a tool can also ship its own `hub.manifest.yaml` (or `.yml` / `.json`) at the root of
its repository. A shipped manifest makes the tool **native**: its values override what the hub
infers, and anything it leaves out is still inferred.

The hub reads a repository's files only when they are regular files inside the repository. It does not follow a
symbolic link, whether a `README.md` pointing at `../../secret.key` or a `docs/` folder pointing at `/`. This applies
to the analysis (README, licence, manifest, compose and `.env` files), the README the Tool Supervisor gives the model,
the compose file used for SSO registration, the OpenAPI spec named in `api.spec`, and the files shown in patch diffs.
A linked file counts as missing.

A SaaS tool has no repository: its manifest comes from the OpenAPI spec given at import (API, sign-in, webhooks) and,
as for a repository, from what a well-known tool recognised by its id, name or host name provides - a hosted Keycloak
or Okta is an identity provider (`auth.oidc`, `auth.saml`, `identity.source`), Snipe-IT an asset inventory
(`assets.inventory`).

## Where the values come from

Four layers make a tool's manifest, from low to high; a higher one wins:

1. **The analyzer's generic heuristics**: the stack, dependencies, ports, launch rules (`package.json`, a Python
   entry point, a `bin/*.sh` launcher, ...), a health route found in the code, an OpenAPI spec in the folder.
2. **A known-product profile** ([INTEGRATIONS.md](INTEGRATIONS.md#known-products)): when the analyzer recognises a
   well-known product (Keycloak by its `bin/kc.sh` or its parent `pom.xml`, Grafana by its name, ...), the profile fills
   the fields that are still **empty**: how it starts, its port, its health check, its API, its capabilities.
3. **The tool's own `hub.manifest.*`**: always beats 1 and 2.
4. **Hub-side settings** (`Tool.manifest_overrides`): what applied patches set (a launch command, a health URL, a moved
   port, single sign-on) and what administrators set in the [manifest editor](#editing-it-by-hand). They are applied
   again after every analysis, so a **Re-analyse** never loses them. The API lists their paths as `overridden`
   (`launch.env.<KEY>` names a key, never its value).

Rules that keep the manifest honest:

- **Hub-only keys.** `id`, `native`, `known` and `adopted` are set by the hub only; a tool's own file cannot claim them
  (they are dropped from it). `native` is true only while the folder ships its own manifest, recomputed by every
  analysis. `known` names the recognised product: `{profile, shape, by, version}` - `shape` is `release`, `source`,
  `compose`, `saas` or `other`, `by` is `marker`, `name`, `image` (the image its compose file's main service runs) or
  `host`. `adopted` says where a manifest the hub drafted
  (the `add_manifest` patch) waits - its branch (`hub/add-manifest-...`) or folder - until someone merges it; until
  then the tool is not native, and the **Hub manifest** check says so.
- **`TODO` placeholders are no value.** A string starting with `TODO` (any case) at `launch.command`, `launch.setup`,
  `health.url`, `api.base_url`, `api.spec` or `ui.url` is ignored, with the note
  `Ignored a TODO placeholder in hub.manifest.yaml: <path>`; the checks treat it as missing.
- **Secrets never live in a manifest.** `launch.secret_env` lists environment variable *names* whose values the hub
  keeps in its private `adapters/<id>/launch/secrets.env` (mode 0600, folder 0700): an admin password a
  `launch_command` patch generates when it is applied, or a value an administrator marks as secret in the editor (a
  variable named like a credential - `PASSWORD`, `TOKEN`, `API_KEY`, `SECRET`, ... - always is). The file is listed in
  `launch.env_files`, so the Operator puts the values into the tool's environment when it starts the tool; they appear
  nowhere else (API answers, the activity log, the bus, patches, prompts - and command output and the tool's process
  log mask them). A plain constant an administrator sets (`LOG_LEVEL=info`) is a hub-side `launch.env` value instead:
  never shown either, but no secret. A secret shorter than 8 characters or of one kind of character (`admin`, `8080`)
  is kept just as private but not masked in texts - masking such a word would rewrite every text that contains it.
  The API shows `launch.env_keys`: the names of `launch.env` and `launch.secret_env`, never their values.

### Editing it by hand

Administrators set how the hub starts and reaches a tool in **Integration > Launch / Health / API > Edit** (the
**Edit** button on those check rows, or **Edit** on the Adapters card): the launch command, port, working folder and
environment (not for SaaS), the health URL, the API type, base URL and spec, and the portal URL. Each value becomes a
hub-side setting (layer 4 above). A field set by an administrator or an approved patch shows that, with a **Reset**
that puts it back to what the analysis finds (the tool is analysed again). Environment values are write-only: the
editor shows the names with a "set" badge and an empty "unchanged" input.

`PATCH /api/tools/{id}/manifest` (administrators only; body and checks in
[INTEGRATIONS.md](INTEGRATIONS.md#setting-it-by-hand)).

## The fields

A complete manifest; every field is optional, and what a tool leaves out is inferred.

```yaml
name: CRM App
description: Tracks customers, deals and follow-ups.
kind: oss                 # oss (source available) | closed | saas
version: 1.4.0
license: MIT
stack: [node, docker]

launch:
  setup: npm install      # run once before the first start
  command: npm start
  cwd: .
  port: 4000
  env: {NODE_ENV: production}
  env_files: [subsidiary/bridge.env]   # adapter files of public KEY=value lines merged into the environment
  secret_env: [CRM_ADMIN_PASSWORD]     # names only: the values stay in the hub's adapters/<id>/launch/secrets.env
  test: npm test --silent              # the tool's own tests (a bridge patch runs them in a container only)

health:
  url: http://localhost:4000/healthz   # http(s)://... or tcp://host:port
  expect_status: 200

api:
  type: rest              # rest | graphql | grpc | none
  spec: openapi.yaml      # path or URL
  base_url: http://localhost:4000

auth:
  sso: oidc               # oidc | saml | oauth2 | ldap | none | unknown
  provider: keycloak      # tool id of the suite's identity provider this tool signs in through (optional)

provides: [api.rest, crm.customers, webhooks]
consumes: [auth.oidc, db.postgres]

events:
  emits: [crm.deal.won, crm.customer.created]
  listens: [billing.invoice.*]             # glob patterns
  webhook_url: http://localhost:4000/hub/events

ui:
  url: http://localhost:4000               # opened from Portals
  icon: C                                  # one or two letters, or an emoji
  color: "#0d9488"                         # a hex colour: #rgb, #rgba, #rrggbb or #rrggbbaa
  embed: true                              # a hint only; allows nothing by itself
  widgets:                                 # dashboard widgets the tool suggests (at most 10)
    - key: open_deals
      title: Open deals by stage
      view: breakdown                      # count | breakdown | list | metric
      domain: x:deals                      # a data type the tool's connection reads
      where: [{field: status, op: eq, value: open}]
      group_by: stage

bridge:                                    # set by Atrium when an approved bridge patch is applied
  contract: atrium-bridge/1
  stack: node-express
  core: node/1.0.0
  manifest_path: atrium-bridge.json
  manifest_sha256: 9f2c...                 # SHA-256 of the committed file's raw bytes (64 hex digits)
```

`ui.icon` and `ui.color` style the tool's tile on Home, Apps, Portals and the Integration map. The hub keeps
`ui.color` only when it is a hex colour, and `ui.icon` only when it shows one or two characters and contains no spaces
or control characters (an emoji made of several code points counts as one). Any other value is dropped, so the
tile uses the hub's own colour and the tool's first letter, and the rest of the manifest still applies. The UI checks
both again before it draws the tile. This stops a repository from adding CSS through the colour, for example
`"#000;position:fixed;inset:0"`, which would cover the page and its Remove button, or `url(...)`, which would tell a
remote server each time someone views the page. It also stops a repository from putting a message such as "session
expired, sign in at ..." in the icon.

`ui.url` is the page Portals and the Portal (`#/portal/<tool>`) open. The Portal refuses an address that is Atrium's
own origin, carries a user name and password, or has a query parameter named like a credential. `ui.embed: true` (set
by the tool, or by the analysis for a web UI) is only a hint that the page may be shown inside another site; it allows
nothing by itself (Atrium does not show tools' own pages inside dashboard widgets:
[DASHBOARD.md](DASHBOARD.md#not-built-tools-own-pages-inside-widgets)).

### Dashboard widgets

`ui.widgets` lists up to 10 widgets the tool suggests for Home dashboards, declared as data
([DASHBOARD.md](DASHBOARD.md#widgets-declared-by-packs-and-tools) has every field). They come from the tool's
repository, so Atrium treats them as untrusted:

- they appear in the widget gallery as suggestions ("Suggested by CRM App") and are never added to a dashboard by
  themselves;
- they only ever count or list the tool's own records, and only for data types its connection reads now (otherwise
  the gallery shows the reason and they cannot be added);
- a declaration with markup, a URL, an unknown field or too many conditions is left out with its reason in the
  analysis notes, and the rest of the manifest still applies; entries after the tenth are ignored;
- the hub's analysis never invents `ui.widgets` for a tool that does not ship them.

## An Atrium bridge

A tool can host an agent team of its own, a *subsidiary* ([SUBSIDIARIES.md](SUBSIDIARIES.md)), through an Atrium
bridge that a bridge patch adds to its code. Applying an approved bridge patch updates the manifest:

- **`bridge`**: the contract the bridge speaks, its stack, the vendored (or model-written) core, and the path and
  SHA-256 of the committed `atrium-bridge.json`. Atrium compares this hash with what the running bridge reports
  (`bridge_mismatch` when they differ) and with conformance vector V19. A tool's own manifest never sets it.
- **`launch.env_files`**: `subsidiary/bridge.env` is added, so a tool Atrium starts gets the bridge's public
  configuration (`ATRIUM_BRIDGE_KEYS`, `ATRIUM_TOOL_ID`, `ATRIUM_SUBSIDIARY_ID`, `ATRIUM_PANEL`) in its environment.
  The entries are paths relative to the tool's adapter folder (at most 8, no `..`); Atrium reads them only from that
  folder and never through a symbolic link, and the API shows the file names only.
- **`events.emits`**: the events the bridge declares (`<tool id>.<event>`).
- **`health.url`**: the bridge's public health route on the tool's web address (`ui.url`, else `api.base_url`),
  `<address>/.atrium/v1/health`, when the manifest had no health check yet.

`launch.test` (at most 500 characters) is the command that runs the tool's own tests. A bridge patch runs it on a
copy of its branch inside a container with the network off, never on the hub machine itself; without it the stack's
default is used (`python -m pytest`, `npm test`, `go test ./...`; other stacks need it, or their tests are "not
run").

## Capabilities

Capabilities are dotted names. Tools connect when one **provides** what another **consumes**.
Common names the analyzer understands:

| Capability | Meaning |
| --- | --- |
| `auth.oidc`, `auth.saml`, `directory.ldap` | Identity provider / directory |
| `api.rest`, `api.graphql` | Programmable API |
| `webhooks` | Emits webhooks |
| `db.postgres`, `db.mysql`, `db.mongo` | Databases |
| `cache.redis`, `queue.amqp`, `search.index` | Infrastructure services |
| `storage.s3`, `storage.files` | Object / file storage |
| `notify.email` | Outgoing mail |
| `git.hosting`, `ci`, `chat`, `docs.wiki`, `ticketing`, `helpdesk`, `assets.inventory` | Application domains |
| `vuln.scanner`, `grc.compliance`, `grc.risks`, `identity.source`, `directory.users` | Security domains: vulnerability scanners (OpenVAS / Greenbone), GRC tools (CISO Assistant), directories people come from (Keycloak, Okta) |
| `siem`, `monitoring.alerts`, `logs.search`, `security.events` | Security monitoring (Wazuh, Graylog, ...) |
| `monitoring.metrics`, `monitoring.dashboards`, `monitoring.uptime`, `monitoring.incidents` | Observability |

The hub itself provides `events.bus` and `notify.webhook` to every tool.

Some capabilities also decide what the hub offers a tool (besides its name):

| Capability | Effect |
| --- | --- |
| `assets.inventory`, `vuln.scanner`, `grc.compliance` / `grc.risks`, `directory.users`, `scim` | the built-in connector detected for the tool (Snipe-IT, OpenVAS, CISO Assistant, Okta, SCIM), see [INTEGRATIONS.md](INTEGRATIONS.md#connectors) |
| `siem`, `monitoring.alerts`, `monitoring.metrics`, `monitoring.uptime`, `monitoring.dashboards`, `logs.search`, `assets.inventory`, `vuln.scanner`, `grc.compliance`, `grc.risks` | the agent-team template proposed for the tool, see [AGENTS.md](AGENTS.md#proposals) |
| `siem`, `monitoring.alerts`, `logs.search`, `security.events`; `ticketing`, `helpdesk`; `monitoring.uptime`, `monitoring.metrics`, `monitoring.incidents` | the hub-side gap (alerts, tickets, incidents) an extension pack can close, see [AGENTS.md](AGENTS.md#generated-packs) |

## Single sign-on

A tool whose manifest provides `auth.oidc` or `auth.saml` is an **identity provider** of the suite (Keycloak,
authentik, Zitadel and Authelia are recognised by name; any other tool can declare it). Every other tool should sign
in through one of them:

- `auth.provider` names the provider the tool signs in through. A tool can declare it; the Patch Agent sets it (with
  `auth.sso`) when an SSO patch is applied. The **Single sign-on** check passes once `auth.provider` is the provider
  selected for the tool.
- `auth.env_keys` is filled by the analyzer: the `OIDC_*`, `OPENID_*`, `OAUTH_*` and `OAUTH2_*` keys of the tool's
  `.env` example. For a tool the hub does not know, the Patch Agent fills exactly these keys.

The provider for a tool is chosen in this order: the choice made for that tool (Integration hub > Identity, or
`POST /api/tools/{id}/sso`), the tool's `auth.provider`, the suite default, the only provider in the suite. With two or
more providers and none of these, someone has to choose. See
[INTEGRATIONS.md](INTEGRATIONS.md#single-sign-on-to-the-suites-identity-provider).

## Events

Tools (or their adapters) publish events to the hub with an API token. An admin creates one
under **Users & access -> API tokens** with the role `integration`: it can publish events
(and call `GET /api/health`) but nothing else. The secret (`atr_...`) is shown once; give it to
the tool, for example as the `HUB_TOKEN` environment variable.

```http
POST /api/bus/publish
Authorization: Bearer atr_...
Content-Type: application/json

{"source": "crm-app", "event": "crm.deal.won", "payload": {"deal": 42}}
```

```bash
curl -X POST http://127.0.0.1:8710/api/bus/publish \
  -H "Authorization: Bearer $HUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "crm-app", "event": "crm.deal.won", "payload": {"deal": 42}}'
```

Calls without a valid token are refused (`401 Sign in required` for an unknown, revoked or
expired token). Requests with a Bearer token do not need the `X-Hub-Request` header (sending it
does no harm). The event adapters the Patch Agent generates
read `HUB_TOKEN` and send it this way. Tokens are covered in [AUTH.md](AUTH.md#api-tokens).

A tool with an Atrium bridge needs no token for its events: it emits them into the bridge's outbox, and the
subsidiary's sidecar relays the declared ones, published as `subsidiary:<tool id>`
([INTEGRATIONS.md](INTEGRATIONS.md#bridge-events-on-the-tool-bus)).

The hub delivers the envelope `{source, event, payload, ts}` as a JSON `POST` to the
`events.webhook_url` of every tool whose `events.listens` matches the event name. The API and the UI
never show that URL (only `events.has_webhook`), nor the values of `launch.env` or `launch.secret_env` (only
`launch.env_keys`).
