# Keycloak

Single sign-on for every tool in the suite. Start it with `docker compose up` and
create a realm called `hub`.

Atrium recognises this folder as Keycloak (its built-in profile: capabilities, single sign-on, the admin API
connector), starts it with `docker compose up`, and reads the addresses from `hub.manifest.yaml`: the health check
on the management port 9000 and the admin REST API under `/admin/realms`. Every check passes except **Emits events**:
Keycloak records admin and login events only when they are switched on per realm and serves them through its admin
API with a token, which the hub's event poller cannot read yet.

Notes:

- **Version 25 or later.** The compose file runs `quay.io/keycloak/keycloak:26.0`. Since Keycloak 25 the health
  endpoints (`/health/ready`, `/health/live`) are served on the management port 9000, and only with
  `KC_HEALTH_ENABLED=true`. On Keycloak 24 or older they are on port 8080: change `health.url` in
  `hub.manifest.yaml` and drop the `9000:9000` port.
- **The bootstrap administrator.** Keycloak 26 creates the first administrator from `KC_BOOTSTRAP_ADMIN_USERNAME`
  and `KC_BOOTSTRAP_ADMIN_PASSWORD` (`admin` / `change-me` here) on its first start only; Keycloak 25 and older use
  `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD`. It is a temporary account for development: change the password
  (or create a permanent administrator) right after the first sign-in, and never reuse `change-me` anywhere else.
- **Imported from Keycloak's source code instead?** A checkout of the keycloak/keycloak repository is recognised too;
  the hub does not build it but proposes one `launch_command` patch that runs the official container image (an
  administrator approves it), with a generated admin password kept in the hub's private
  `adapters/<id>/launch/secrets.env` - see [docs/INTEGRATIONS.md](../../docs/INTEGRATIONS.md#known-products).
