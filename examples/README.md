# Example tools

Three small projects to try the hub with. Import each one as a **Local project**
(Get Started -> Import, or `import <path>` in the supervisor chat):

| Folder | What it shows |
| --- | --- |
| `keycloak/` | A Keycloak compose file. The hub recognises it as the suite's identity provider (`auth.oidc`). |
| `crm-app/` | A Node.js app that ships a native `hub.manifest.yaml` - it integrates out of the box and listens to `notes-app.*` events. |
| `notes-app/` | A Flask app with no SSO, no health check and no events. The Patch Agent proposes fixes for each gap. |
