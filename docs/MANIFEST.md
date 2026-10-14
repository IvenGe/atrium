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
  embed: true
```

`ui.icon` and `ui.color` style the tool's tile on Home, Apps, Portals and the Integration map. The hub keeps
`ui.color` only when it is a hex colour, and `ui.icon` only when it shows one or two characters and contains no spaces
or control characters (an emoji made of several code points counts as one). Any other value is dropped, so the
tile uses the hub's own colour and the tool's first letter, and the rest of the manifest still applies. The UI checks
both again before it draws the tile. This stops a repository from adding CSS through the colour, for example
`"#000;position:fixed;inset:0"`, which would cover the page and its Remove button, or `url(...)`, which would tell a
remote server each time someone views the page. It also stops a repository from putting a message such as "session
expired, sign in at ..." in the icon.

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

The hub delivers the envelope `{source, event, payload, ts}` as a JSON `POST` to the
`events.webhook_url` of every tool whose `events.listens` matches the event name. The API and the UI
never show that URL (only `events.has_webhook`), nor the values of `launch.env` (only `launch.env_keys`).
