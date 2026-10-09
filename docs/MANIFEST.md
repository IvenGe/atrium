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
| `monitoring.metrics`, `monitoring.dashboards`, `monitoring.uptime` | Observability |

The hub itself provides `events.bus` and `notify.webhook` to every tool.

## Events

Tools (or their adapters) publish events to the hub:

```http
POST /api/bus/publish
Content-Type: application/json
X-Hub-Request: 1

{"source": "crm-app", "event": "crm.deal.won", "payload": {"deal": 42}}
```

The hub delivers the envelope `{source, event, payload, ts}` as a JSON `POST` to the
`events.webhook_url` of every tool whose `events.listens` matches the event name.
