# Example tools

Three small projects to try the hub with. Import each one as a **Local project**
(Get Started -> Import, or `import <path>` in the supervisor chat):

| Folder | What it shows |
| --- | --- |
| `keycloak/` | A Keycloak compose file (development mode, admin `admin` / `change-me`). The hub recognises it as the suite's identity provider (`auth.oidc`). |
| `crm-app/` | A Node.js app that ships a native `hub.manifest.yaml` - it integrates out of the box and listens to `notes-app.*` events. |
| `notes-app/` | A Flask app with no SSO, no health check and no events. The Patch Agent proposes fixes for each gap. |

Things to try once they are imported (start Keycloak first: `cd keycloak && docker compose up -d`):

- **Single sign-on for tools.** With Keycloak in the suite, the **Single sign-on** check of `crm-app` gets an
  `sso_connect` patch: its `.env` example has `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID`, so the Patch Agent fills exactly
  those keys and writes a Keycloak client registration (`keycloak-client.json` and a `kcadm.sh` script, plus a
  `docker compose exec` variant). `notes-app` has no native SSO: with Claude it gets an `sso_code` patch (OIDC login
  added to its code), without Claude an oauth2-proxy in front of it. After approving, **Run provider registration**
  registers the client in Keycloak. See [docs/INTEGRATIONS.md](../docs/INTEGRATIONS.md#single-sign-on-to-the-suites-identity-provider).
- **Atrium's own sign-in.** **Integration hub > Identity > Atrium sign-in** generates Atrium's client at Keycloak;
  **Settings > Sign-in & SSO** then offers Keycloak prefilled. The step-by-step version is the Keycloak walkthrough in
  [docs/AUTH.md](../docs/AUTH.md#keycloak-walkthrough).
- **People.** Give the Keycloak tool a **Connection** of kind "Keycloak (admin API)" (a confidential client with
  service accounts and the realm-management roles `view-users` and `query-groups`), test it and approve the proposed
  people flow: the realm's users appear in **People**. Make one of them the owner or user of an asset, then disable
  them in Keycloak: after the next pull they are suspended and show up under **Leavers** (control HB-AC-7). See
  [docs/PEOPLE.md](../docs/PEOPLE.md).

The compose file starts an empty Keycloak: create the realm (`hub`) by hand as in the Keycloak walkthrough, or let a
registration script create it when it is missing.
