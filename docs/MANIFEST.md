# Hub manifest

The hub manifest is the integration contract of a tool. The hub infers one for every tool it
imports; a tool can also ship its own `hub.manifest.yaml` (or `.yml` / `.json`) at the root of
its repository. A shipped manifest makes the tool **native**: its values override what the hub
infers, and anything it leaves out is still inferred.

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
  icon: C                                  # a letter or emoji
  color: "#0d9488"
  embed: true
```

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
| `git.hosting`, `ci`, `chat`, `docs.wiki`, `ticketing`, `assets.inventory` | Application domains |
| `vuln.scanner`, `grc.compliance`, `grc.risks`, `identity.source` | Security domains: vulnerability scanners (OpenVAS / Greenbone), GRC tools (CISO Assistant), directories people come from (Keycloak, Okta) |
| `monitoring.metrics`, `monitoring.dashboards`, `monitoring.uptime` | Observability |

The hub itself provides `events.bus` and `notify.webhook` to every tool.

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
more providers and none of these, someone has to choose. See [ARCHITECTURE.md](ARCHITECTURE.md#single-sign-on).

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
`events.webhook_url` of every tool whose `events.listens` matches the event name.
