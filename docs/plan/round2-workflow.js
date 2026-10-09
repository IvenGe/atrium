export const meta = {
  name: 'atrium-round-2',
  description: 'SSO to IdP, integration fabric, agent teams, People + SSO settings, self-extension, installer and docs for Atrium',
  phases: [
    { title: 'SSO', detail: 'connect tools to the selected identity provider' },
    { title: 'Fabric', detail: 'connector SDK, flows, vulnerabilities; Snipe-IT, CISO Assistant, OpenVAS connectors and UI' },
    { title: 'Teams', detail: 'agent teams, agent management, local models, guardrail toggles' },
    { title: 'People', detail: 'People app, Okta/Keycloak/SCIM sources, person-asset links, Sign-in & SSO settings' },
    { title: 'Extend', detail: 'Atrium extensions and self-patching' },
    { title: 'Installer', detail: 'install.ps1, install.sh, Docker (runs alongside)' },
    { title: 'Docs', detail: 'README and docs for everything new' },
  ],
}

const CONTEXT = `
# Project: Atrium (Python package "hub") - C:\\Users\\test\\Downloads\\hub program (Windows 11, path has a space; Git Bash and PowerShell available)
An agent-run "office suite" for tools: FastAPI app (hub/app.py, hub/api.py), agents on a message bus (hub/bus.py, hub/agents/*), SQLite doc store
(hub/store.py), integration engine (hub/integration/*: analyzer, compatibility, importer, patches, toolbus), execution (hub/execution/*: policy,
runner, processes), GRC (hub/grc/*), built-in login (hub/auth/*: users, sessions, API tokens, OIDC, role policy in hub/auth/policy.py), and a
no-build vanilla-JS UI (hub/web: js/app.js shell + router + APPS list, js/ui.js helpers, js/api.js, js/auth.js, js/views/*.js). Read the code you
build on before changing it, and match its style (concise, typed, pydantic models, sparse comments; UI: html\`\` auto-escaping templates, setHTML,
actions(), modal(), toast(), field(), options(), badge(), icon(); data-min-role="operator"/"admin" on mutation controls; CSS custom properties only).
Docs to orient yourself: README.md, docs/ARCHITECTURE.md, docs/AUTH.md, docs/MANIFEST.md. The git branch is feature/login-sso-integrations-agent-teams.

Rules for every agent:
- Run the tests with: .venv/Scripts/python.exe -m pytest -q   (from the project root). They must be green when you finish. Never weaken or delete
  an existing test to make it pass; fix the code (or the test only if the test is genuinely wrong, and say so).
- Edit files with the Edit/Write tools, never through python/bash heredocs (escape sequences get mangled).
- Do not commit, push, or touch .hub-dev/ or port 8710 (a preview server with the user's data runs there). Use another port and a temporary
  --data-dir if you must run a server (create a test admin with the offline CLI: .venv/Scripts/atrium user create NAME --role admin --password-stdin).
- Every new HTTP endpoint must be classified in hub/auth/policy.py (viewer for reads, operator for state changes, admin for credentials, users,
  settings, agent definitions, extensions and guardrails) and covered by the existing permission-matrix tests (extend their expectations if needed).
- Secrets (passwords, API tokens, client secrets) are never returned by the API, never logged, never put in activity entries, bus messages, patch
  diffs committed to a tool's repository, or error messages.
- When you rely on an external product's API or config format (Keycloak, Authentik, Okta, Grafana, Snipe-IT, CISO Assistant, Greenbone/OpenVAS GMP,
  SCIM, Ollama, ...), verify the details against official documentation with WebSearch/WebFetch where possible. Where you remain unsure, design
  defensively (clear error messages, configurable paths/fields), mark the assumption in a code comment, and list it in open_issues.
- Report honestly: what works, what you verified and how, what you could not verify.
`

const RESULT = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    files_changed: { type: 'array', items: { type: 'string' } },
    api_added: { type: 'array', items: { type: 'string' }, description: 'METHOD /path - role - purpose' },
    tests: { type: 'string', description: 'exact final pytest summary line' },
    open_issues: { type: 'array', items: { type: 'string' } },
  },
  required: ['summary', 'files_changed', 'api_added', 'tests', 'open_issues'],
}

const SSO_SPEC = `
## Feature: connect tools to the suite's identity provider (SSO)
Today a tool failing the "Single sign-on" check gets fix "sso_proxy" (an oauth2-proxy adapter). The user wants: when the suite contains an identity
provider (Keycloak, Authentik, Zitadel, Authelia, or any tool whose manifest provides auth.oidc / auth.saml), the Patch Agent connects the tool
NATIVELY to that provider; with two or more providers the user selects which one (a suite default plus a per-tool choice).
1. hub/integration/identity.py: list identity providers from the tools (tool_id, name, kind keycloak|authentik|zitadel|authelia|generic, base URL,
   protocols oidc/saml, issuer: Keycloak {base}/realms/{realm}, Authentik {base}/application/o/{slug}/, others {base}); per-provider settings
   (Keycloak realm, default "hub"; Authentik application slug) stored in hub prefs; suite default provider in prefs "identity_provider";
   selection: explicit per-tool choice > suite default > the only provider > none (needs a choice). Add Manifest.auth.provider (IdP tool id).
2. hub/integration/sso_catalog.py: how known tools do SSO natively, with accurate config generators (verify each against official docs): Grafana
   (GF_AUTH_GENERIC_OAUTH_* env), Gitea/Forgejo (admin auth add-oauth CLI with auto-discover URL), MinIO (MINIO_IDENTITY_OPENID_* env), BookStack
   (AUTH_METHOD=oidc + OIDC_* env), Outline (OIDC_* env), Nextcloud (user_oidc app via occ), Wazuh dashboard / OpenSearch Dashboards (OpenSearch
   security openid auth domain + opensearch_dashboards.yml openid settings + securityadmin), CISO Assistant (SSO configured in its UI: generate the
   values to paste), Snipe-IT (SAML only: IdP metadata URL, SP entity/ACS), Zammad (OIDC in its UI), plus a generic strategy for any tool whose .env
   example exposes OIDC_*/OAUTH2_* keys (fill exactly those keys). Tools without OIDC in their free edition (Uptime Kuma, n8n community, Mattermost
   Team) fall back to the proxy. Each entry: protocols, redirect/callback URI pattern, generator returning files + human steps.
3. Strategies chosen by hub/integration/compatibility.py for a failing SSO check, implemented in hub/integration/patches.py + hub/agents/patcher.py:
   - "sso_connect": provider selected and the tool supports OIDC/SAML natively -> adapter patch with the tool-side config AND the provider-side client
     registration (Keycloak client JSON for OIDC or SAML + a kcadm.sh registration script with a docker compose exec variant; Authentik blueprint
     YAML; generic instructions). A random client secret is generated once and written only into hub workspace adapter files (never into a
     repo-target patch). manifest_update sets auth.sso and auth.provider.
   - "sso_code": provider exists, tool has source and no native SSO, Claude available -> Patch Agent code_patch adding OIDC login that reads
     OIDC_ISSUER / OIDC_CLIENT_ID / OIDC_CLIENT_SECRET from the environment, plus the provider-side registration adapter.
   - "sso_proxy": fallback; now uses the selected provider's issuer and emits the provider-side registration too.
   - No provider in the suite: the check stays failing with fix "sso_proxy" and a detail suggesting importing an identity provider.
4. POST /api/tools/{id}/sso {"provider": tool_id} (operator) replaces a pending SSO patch with one for the chosen provider (the superseded approval
   is rejected with a note). POST /api/tools/{id}/sso/register (operator) asks the Operator Agent to run the provider registration script of an
   applied SSO patch (policy still applies). GET /api/identity-providers (viewer): providers, default, needs_choice, per-tool SSO status.
   PUT /api/identity-providers/default {"tool_id"} (admin); PATCH /api/identity-providers/{tool_id} {settings} (admin). Re-score after changes; the
   Integration map draws identity links from auth.provider.
5. Wanted: "Use this provider for Atrium sign-in" - generate the Keycloak/Authentik client for Atrium itself (redirect {public_url}/api/auth/oidc/callback)
   and show the values; a later stage adds a Sign-in & SSO settings screen that will consume them, so expose a function that returns them.
6. UI (hub/web): Integration hub "Identity" card (providers, default selector for admins, per-tool SSO status with Connect buttons); tool detail
   Integration tab SSO row "Connect to [provider]" with a picker; approvals for SSO patches show the provider and "Change provider"; tool page offers
   "Run provider registration" after an SSO patch is applied.
7. Tests: provider detection/selection (0, 1, 2 providers, default, per-tool choice), catalog generators (golden checks on config keys and redirect
   URIs), strategy selection per case, secret never in repo patches/diffs/API output, replanning supersedes the old approval, end to end via the API.
`

const FABRIC_SPEC = `
## Feature: integration fabric - tools exchange data through the hub
Tools declare what data they produce/consume; the hub proposes data flows between tools and its built-in apps, runs them, and repairs them.
The hub's built-in apps are the canonical data model: Assets (assets), a NEW Vulnerabilities app (vulnerabilities), Compliance (risks, controls +
evidence). The user's example: Snipe-IT assets -> Hub Assets -> OpenVAS scans in-scope assets -> findings -> Hub Vulnerabilities -> CISO Assistant
(+ critical findings raise hub risks; scan coverage and SLA feed compliance controls); Hub controls/evidence -> CISO Assistant applied controls and
evidence; CISO Assistant risk scenarios -> hub risk register.

### Core (fabric-core agent)
- hub/secrets.py: SecretBox (cryptography Fernet). Key from HUB_SECRET_KEY, else a key file {data_dir}/secret.key created on first use with owner-only
  permissions where the OS supports it. encrypt/decrypt strings. Add HUB_SECRET_KEY to settings.
- hub/connectors/base.py: Connector SDK. ConnectorError(Exception) with a user-safe message (+ optional http status, response excerpt without secrets).
  ConnectorField(name, label, kind "text"|"url"|"secret"|"select"|"number"|"bool", required, default, help, options: bool).
  class Connector: kind, title, fields, capabilities: dict[domain, set["read","write"]], actions: set[str];
    __init__(self, config: dict, secrets: dict, transport: httpx.AsyncBaseTransport | None = None)
    async test() -> {"ok", "detail", "checks": [{"name","ok","detail"}], "domains": {domain: [ops]}}
    async options(field_name) -> [{"value","label"}]
    async pull(domain, since=None) -> list[dict]   (canonical records, each with "external_id")
    async push(domain, records, links: dict[hub_id, external_id]) -> list[{"hub_id","external_id","action": created|updated|skipped|failed,"error"}]
    async action(name, params) -> dict   (scanners: "scan" -> {"job_id"}, "scan_status" -> {"status","progress","done"})
    @classmethod detect(cls, tool) -> int  (0..100 confidence)
  Registry with lazy import strings: snipeit, ciso_assistant, openvas, generic_rest (hub.connectors.<module>:<Class>). Later stages add more kinds
  (okta, keycloak_admin, scim) - make adding one a single registry line. The three product connectors are written by other agents right after you,
  in parallel: create hub/connectors/snipeit.py, ciso_assistant.py and openvas.py as SMALL STUBS (correct class names SnipeItConnector,
  CisoAssistantConnector, OpenVasConnector, kind, title, detect(), capabilities, methods raising ConnectorError("not implemented yet")).
- Canonical record shapes (document them in base.py):
  assets: external_id, name, type (server|workstation|network|software|saas|cloud|data|other), owner, status (active|maintenance|retired), addresses
    (IPs/hostnames), facts (dict), updated_at
  vulnerabilities: external_id, title, severity (critical|high|medium|low|info), cvss, cves, host, port, description, solution, detected_at, scanner
  risks: external_id, title, description, likelihood 1-5, impact 1-5, status (open|in_treatment|closed), treatment
  controls: external_id (hub control id), ref_id, name, description, status (pass|partial|fail|manual|na), evidence (list), refs (dict)
- hub/connectors/generic_rest.py: GenericRestConnector driven by a declarative JSON mapping per domain: list path, items path (dotted, empty = root
  list), pagination (none | offset/limit | page | next-url), field map (canonical field -> dotted remote path), optional create/update path+method+body
  template; auth bearer|token|header|basic|none. Validate strictly (relative paths only; never let a mapping change the configured scheme/host).
- Connections: collection "connections" keyed by tool id: kind, config (non-secret), secrets (encrypted), created_by, updated_at, last_test.
  GET /api/connectors (viewer; catalog), GET /api/tools/{id}/connection (viewer; kind, config, which secrets are set, detected kinds with scores,
  capabilities, last_test), PUT /api/tools/{id}/connection {kind, config, secrets} (admin; empty secret keeps the stored one), DELETE (admin),
  POST /api/tools/{id}/connection/test (operator), GET /api/tools/{id}/connection/options/{field} (operator). The Tool Supervisor handles
  "connector.test|pull|push|action|options" by building its tool's connector with decrypted secrets.
- Flows: collection "flows": id, domain, source ("tool:<id>"|"hub"), target ("hub"|"tool:<id>"), action (optional, e.g. "scan"), schedule_minutes,
  status proposed|enabled|disabled, strategy (connector|generated), options, created_by, last_run, last_result {ok, counts, error}, failures.
  Sync links map (tool, domain, hub id) <-> external id plus a content hash so unchanged records are skipped on push.
- hub/integration/strategies.py: strategy planner. From tools, connections/capabilities and the hub apps, propose flows (tool assets read -> pull
  into Hub Assets; tool assets write and not a system of record -> push hub assets; scanner -> scan in-scope assets + pull findings; vulnerabilities
  write -> push findings; controls write -> push controls+evidence; risks read -> pull risks). Proposals are approvals of kind "flow" (auto-enabled
  in autonomous mode). Also per-tool strategy overview for the UI (identity/SSO, events, data flows, generated connector, adapter/patch) with state.
- Flow execution by the domain-owning module agents talking to the tool supervisors: Asset Supervisor (merge pulled assets with existing ones by
  address/hostname/serial instead of duplicating), NEW Vulnerability Supervisor "module:vulns" (scan flows, vulnerability flows, SLA), GRC
  Supervisor (controls push, risks pull). A background scheduler in the Hub runtime triggers due flows (off when Settings.start_background_tasks is
  false). Scans need approval (kind "scan") unless autonomous mode or the prefs guardrail "scans_need_approval" is false. Only assets with
  scan_scope=true are ever scanned (Asset gains scan_scope: bool = False and last_scanned_at).
- Repair loop: after 3 consecutive failures of a flow, the Hub Supervisor sends "integration.repair" to the Patch Agent with the error and a
  sanitized sample (no secrets). The Patch Agent proposes a fix (approval kind "repair"): with Claude, a changed generic_rest mapping or connection
  config; without Claude, heuristics (auth errors -> check credentials; 404 -> base-path variants such as adding/removing /api; validation errors
  surfaced verbatim). Approving applies the change and re-runs the flow. With Claude, for a tool without a built-in connector but with an OpenAPI
  spec, the Patch Agent can generate a generic_rest mapping ("generated connector" strategy) as an approval.
- Vulnerabilities app backend: model Vulnerability (id, title, severity, cvss, cves, asset_id, host, port, source tool id, external_id, status
  open|in_progress|accepted|false_positive|fixed, first_seen, last_seen, due_at, description, solution, note); SLA days in prefs (critical 7, high
  30, medium 90, low 180); a finding missing from a completed rescan of the same host is marked fixed automatically; open critical findings past due
  raise hub risks. API: GET /api/vulnerabilities (filters), GET /api/vulnerabilities/summary, PATCH /api/vulnerabilities/{id} {status, note}
  (operator), POST /api/vulnerabilities/scan {scanner_tool_id?, asset_ids?} (operator), POST /api/assets/scan-scope {asset_ids, in_scope}
  (operator); GET /api/flows, POST /api/flows/plan, PATCH /api/flows/{id} {status, schedule_minutes, options}, POST /api/flows/{id}/run,
  DELETE /api/flows/{id} (operator for changes, viewer for reads).
- GRC: HB-VM-2 "In-scope assets are scanned for vulnerabilities" (each in-scope asset scanned within 30 days; none in scope -> manual) refs
  ISO27001 "A.8.8", SOC2 "CC7.1", NIS2 "21(2)(e)", risk ("Vulnerabilities on unscanned assets go unnoticed", 3, 4); HB-VM-3 "Critical and high
  vulnerabilities are fixed within SLA" same refs, risk ("Known critical vulnerabilities remain exploitable", 4, 5). Analyzer KNOWN_TOOLS: add
  openvas/greenbone/gvm (vuln.scanner), ciso-assistant (grc.compliance, grc.risks), snipe-it (assets.inventory), okta/keycloak (identity sources).
- Tests for all of the above with fake connectors (no network).

### Product connectors (one agent each, in parallel; each owns ONLY hub/connectors/<name>.py and tests/test_connector_<name>.py)
- Snipe-IT (REST API v1, Bearer token, Accept: application/json): assets read (GET /api/v1/hardware, limit/offset paging over rows/total; map
  name/asset_tag/serial/model/manufacturer/category/location/assigned_to/status label + custom fields holding IP/hostname/FQDN/MAC; keep the
  assigned user's username and email in facts so a later People feature can link persons) and write (create/update hardware; model_id and
  status_id chosen in the connection settings via options() from /api/v1/models and /api/v1/statuslabels). Snipe-IT can answer HTTP 200 with
  {"status":"error","messages":...}: treat that as an error.
- CISO Assistant (Django REST API under /api, "Authorization: Token <token>"; accept a base URL with or without /api; responses may be a list or
  {count,next,previous,results}): assets read/write (supporting assets, folder chosen via options() from /api/folders/), controls write (applied
  controls + evidences), risks read (risk scenarios), vulnerabilities write (only if the instance has that endpoint; test() reports which domains this
  instance supports). Surface 400 validation messages verbatim (minus secrets).
- OpenVAS / Greenbone (GMP XML): connection kinds tls (default port 9390, verify_tls toggle, optional CA file), unix socket (POSIX only), plain tcp
  (labs/tests only, labelled insecure). Minimal async GMP client (asyncio streams + xml.etree XMLPullParser reading one complete response; escape
  every value placed in XML; validate scan hosts as IPs/CIDRs/hostnames only): authenticate, get_version, create_target, create_task, start_task,
  get_tasks (status, progress), get_results/get_reports. Defaults: scan config "Full and fast", default OpenVAS scanner, "All IANA assigned TCP" port
  list - verify their well-known UUIDs against Greenbone docs; selectable via options(). Actions "scan" and "scan_status"; vulnerabilities read maps
  results (host, port, NVT name/OID, severity score -> critical >=9, high >=7, medium >=4, low >0, info 0, CVE refs, description, solution);
  external_id "<nvt oid>|<host>|<port>". Tests with a fake GMP server over plain tcp.

### Fabric UI (one agent, in parallel with the connectors; owns ONLY hub/web/**)
- Tool page "Connection" tab: connector kind (detected first), settings form from field definitions (secrets masked, "leave empty to keep"), Test
  connection with per-check results, options dropdowns, capabilities, this tool's flows; admins save; "Generate connector with Claude" when no
  built-in connector.
- Integration hub: "Data flows" (proposed/enabled/disabled; enable toggle, schedule, run now, last result, failures, "Repair"), per-tool strategy
  overview, flow links on the map.
- New built-in app "Vulnerabilities" (#/vulnerabilities, sidebar under Govern, Portals, Ctrl K): severity tiles, filters, table, detail modal (CVE
  links to https://nvd.nist.gov/vuln/detail/<CVE>, solution, status change), "Scan now" (scanner + in-scope assets), scan-scope management.
- Assets: "In scan scope" toggle in the edit modal, a column badge and bulk set. Approvals: render kinds flow, scan, repair.
`

const TEAMS_SPEC = `
## Feature: agent teams, agent management, local models, guardrail toggles
- Supervisors can build an AI agent team for their tool when needed: a Tool Supervisor proposes a team from templates keyed by what the tool is
  (SIEM/monitoring e.g. Wazuh: alert triage analyst + health watcher; GRC e.g. CISO Assistant: compliance analyst + evidence collector; asset
  inventory e.g. Snipe-IT: inventory reconciler; vulnerability scanner e.g. OpenVAS: vulnerability triage analyst; any tool: maintainer) or designed
  by Claude (structured output) when available. The proposal is an approval of kind "agent_team" (auto-created only if autonomous mode or guardrail
  team_requires_approval is off). Proposed automatically when a tool gets a connection/flows or is a known complex tool; on demand via
  POST /api/tools/{id}/team (operator).
- Agent management (admins): create, edit, remove agents. CustomAgent definition (collection "agent_defs"): id "agent:<slug>", name, title/role,
  description, instructions, provider ("anthropic" | a configured local provider id | "rules"), model, permissions (subset of: read, tool_api,
  commands, patches, flows, assets_write, grc_write, agents), team (tool id | "hub" | module id), parent (creator), depth, schedule_minutes (min 5) +
  standing task, enabled, created_by. Core agents can be paused and reconfigured but not deleted. API: POST /api/agents, PATCH /api/agents/{id}
  (all fields for custom agents; existing fields for core agents), DELETE /api/agents/{id} - admin; POST /api/agents/{id}/chat {text} and
  POST /api/agents/{id}/run - operator; GET /api/agents/teams - viewer.
- Shared agent toolkit (hub/agents/toolkit.py): tool definitions tagged with the permission they need, used by the Hub Supervisor chat and custom
  agents (filtered by permissions), plus loop runners for Claude (existing hub/llm.py Anthropic SDK usage: keep claude-opus-5-5 default and the
  existing request options) and for local models.
- Local models: provider kind "openai_compatible" (Ollama, LM Studio, vLLM, llama.cpp server) called with httpx (POST {base_url}/chat/completions
  with tools; GET {base_url}/models), optional API key encrypted with hub/secrets.py. GET /api/llm/providers (viewer, keys masked),
  POST/PATCH/DELETE (admin), POST /api/llm/providers/{id}/test (admin; lists models). "rules" agents run deterministic template actions only
  (health check, run flows, summarize state) and say so if a task needs a model.
- Guardrails are SETTINGS (admin toggles, prefs "guardrails"), defaults: limit_to_parent_permissions on; allow_nested_teams off, max_team_depth 1;
  limit_team_size on, max_team_size 5; team_actions_need_approval on (team agents follow the autonomy level; off = they act without approval);
  block_catastrophic_commands on (wire into hub/execution/policy.py: off means blocked patterns become "change" risk); scans_need_approval on;
  team_requires_approval on. GET /api/settings includes them; PATCH /api/settings/guardrails admin. Every change is logged with the actor; the UI
  asks for confirmation with a clear risk explanation before switching a protection off. Design the guardrails model so later stages can add keys
  (extensions and self-patching come next). GRC control HB-AC-6 "AI agent guardrails are enforced": fail if block_catastrophic_commands,
  team_actions_need_approval or limit_to_parent_permissions is off; partial if size limit off or nested teams on; refs ISO27001 "A.8.2 / A.8.32",
  SOC2 "CC6.1 / CC8.1", NIS2 "21(2)(i)"; risk ("AI agents operate without guardrails", 3, 5).
- Enforcement: team members' permissions clamped to the parent's when that guardrail is on; team size and depth enforced; every command/patch from any
  agent still goes through the Operator policy and the Patch Agent approval flow.
- Scheduler: agents with a schedule run their standing task when due (same background loop as flows; off when start_background_tasks is false).
- UI (hub/web): Agents tab "New agent" (admins), edit/remove, provider badge (Claude / Local / Rules), team grouping with the tool supervisor as lead
  and "Propose team" per tool, chat with any LLM agent (agent selector), run now. Settings: "AI providers" card (add local provider, base URL default
  http://localhost:11434/v1, test, model list) and "Agent guardrails" card (toggles + numbers + confirmation). Approvals render "agent_team".
- Tests: definitions CRUD, permission clamping, size/depth limits, guardrail toggles and GRC effect, policy wiring of block_catastrophic_commands,
  toolkit permission filtering, the OpenAI-compatible loop with httpx MockTransport (tool-call round trip), team proposal approval -> agents created,
  scheduler due logic.
`

const PEOPLE_SPEC = `
## Feature: People (workforce directory) + Sign-in & SSO settings for Atrium
The user: "a way to manage people, for example from Okta, link person to asset etc, and it should be visible in the program"; and SSO for Atrium.
- New built-in app "People" (#/people) and a "People Supervisor" agent (module:people). Person model: id ("p_"), display_name, email, login, title,
  department, manager_id, status active|suspended|terminated, sources {tool id: external id}, groups, location, phone, created_at, updated_at,
  terminated_at. Merge identities from several sources by email, then login.
- New canonical connector domains: "people" (external_id, display_name, email, login, title, department, manager_external_id, status, groups) and
  "accounts" (tool user accounts: external_id, login, email, display_name, active, last_login) - documented in hub/connectors/base.py.
- New connectors (registry entries): Okta (API token header "Authorization: SSWS <token>", GET /api/v1/users with Link-header pagination, status
  mapping incl. SUSPENDED and DEPROVISIONED, profile fields, groups, app links as accounts; verify against Okta docs), Keycloak admin API (service
  account client-credentials token on {base}/realms/{realm}/protocol/openid-connect/token, GET {base}/admin/realms/{realm}/users paging, groups,
  enabled), generic SCIM 2.0 (Bearer, /Users with startIndex/count, ListResponse, active, emails, enterprise extension department/manager). Extend the
  Snipe-IT connector with "accounts" read (GET /api/v1/users) and make asset pulls keep the assigned user's email/username. The strategy planner
  proposes people/accounts flows into the People app.
- Links: Asset gains owner_person_id and assigned_person_id (keep the free-text owner for display/back-compat); asset pulls link assigned users to
  persons automatically (email/login); risks and policies can reference an owner person too; Atrium users link to persons by email.
- Person page: profile, manager and direct reports, groups, assets owned/assigned, accounts per tool, Atrium account and role, risks/policies owned,
  open vulnerabilities on their assets, recent activity, and a small relationship map (SVG: person in the middle; assets, tools, groups around).
  People list: search, filters (status, department, source), avatars with initials, asset counts. Asset edit modal: person pickers for owner and
  assigned user. All of it role-aware (viewers read, operators edit people/links, admins manage sources).
- Leavers: control HB-AC-7 "Leavers lose access and return assets" - terminated or suspended people who still have assigned/owned active assets,
  enabled Atrium accounts, or active tool accounts -> fail (partial when only assets); refs ISO27001 "A.5.18 / A.5.11", SOC2 "CC6.2 / CC6.3", NIS2
  "21(2)(i)"; risk ("Former staff keep access or company devices", 3, 4). The People Supervisor reports leaver findings and offers one-click actions
  (unassign assets - operator; disable the Atrium account - admin).
- API (classify in policy.py): GET /api/people, GET /api/people/{id} (with linked assets/accounts/etc.), POST/PATCH/DELETE /api/people (operator),
  POST /api/people/{id}/actions/{action} (role per action), GET /api/people/leavers.
- Atrium Sign-in & SSO settings (admin): manage the OIDC sign-in from the UI instead of only HUB_OIDC_* env vars. Presets: Okta (issuer
  https://<your-domain>/oauth2/default or the org server; note the groups claim must be added in Okta), Microsoft Entra ID
  (https://login.microsoftonline.com/<tenant>/v2.0; groups or app roles claim), Google (https://accounts.google.com; no groups -> default role),
  an imported Keycloak/Authentik (prefill from hub/integration/identity.py, incl. the "use for Atrium sign-in" values), generic. Stored in the
  database with the client secret encrypted (hub/secrets.py); environment variables still win (UI shows them read-only as "set by environment").
  "Test" runs discovery without saving. hub.auth.oidc is rebuilt on save (no restart). API: GET /api/auth/sso (admin, secret masked),
  PUT /api/auth/sso (admin), POST /api/auth/sso/test (admin), DELETE /api/auth/sso (admin). The sign-in screen label becomes e.g.
  "Sign in with Okta". Keep every OIDC security check from hub/auth/oidc.py.
- UI: People app (sidebar under Govern, Portals, Ctrl K), person page, pickers in Assets (and risk/policy owners), Settings "Sign-in & SSO" card,
  Users & access shows the linked person.
- Tests: Okta/Keycloak/SCIM connectors with httpx MockTransport (pagination, status mapping), identity merging, asset linking from Snipe-IT pulls,
  leaver control and actions, SSO settings precedence (env > db), secret masking, test endpoint, OIDC client rebuilt after save.
`

const EXTEND_SPEC = `
## Feature: Atrium extends and patches itself when a new tool needs it
The user: "if a new tool is imported it could also patch Atrium". Two levels, the safe one first.
1. Extensions (no code, preferred). hub/extensions/: ExtensionPack (pydantic, strict): id, name, version, description, source tool id, created_by,
   status proposed|enabled|disabled, created_at, items. Item kinds (data only - nothing in a pack is ever executed or evaluated as code):
   - "domain": a new data type (e.g. "alerts" from Wazuh, "tickets" from a service desk): key, title, icon, fields (name, label, type
     text|number|date|severity|link|enum + values), title field, link rules (asset by address/hostname field, person by email field). Records live in
     collection "x:<key>"; connectors can pull/push the domain like built-in ones.
   - "connector": a generic_rest connection mapping for a tool (may include the new domain).
   - "sso": an SSO catalog entry (tool match, protocol, config template text) consumed by hub/integration/sso_catalog.py.
   - "controls": map a domain to compliance controls as evidence (e.g. count of open critical alerts older than N days -> control status).
   - "team": an agent-team template for a kind of tool.
   Versioned (previous versions kept), enable/disable/rollback in-process without restart. API: GET /api/extensions (viewer),
   POST /api/extensions (admin, upload a JSON pack), PATCH /api/extensions/{id} {status} (admin), POST /api/extensions/{id}/rollback (admin),
   DELETE (admin); GET /api/x/{domain} and GET /api/x/{domain}/{id} (viewer), PATCH (operator).
   Generation: after an import the Hub Supervisor detects hub-side gaps (a data domain the hub does not model, e.g. a SIEM's alerts or a service
   desk's tickets; no connector; unknown SSO) and asks the Patch Agent to extend Atrium: with Claude it generates the pack (structured output) from
   the manifest/OpenAPI spec; without Claude it uses templates for well-known categories (SIEM alerts, ticketing tickets, monitoring incidents).
   Proposal = approval kind "extension" with a preview (auto-enabled only if the guardrail extensions_need_approval is off).
2. Self-patching (code, needs Claude). When an extension cannot express it, the Patch Agent proposes a change to Atrium's own repository - only if
   Atrium runs from a git checkout: git worktree on a new branch "atrium/self-<id>" under the workspace; validated paths inside the repo (never
   .env, .hub*, .venv, .git); runs the test suite in the worktree with the current interpreter (timeout, output tail attached); approval kind
   "self_patch" shows the diff and test result. Failing tests -> not approvable while self_patch_requires_tests is on. On approval: if
   self_patch_via_pull_request is on and GitHub CLI is authenticated with an origin remote, push the branch and open a pull request (gh pr create;
   this outward action happens only on a person's explicit approval, never automatically); otherwise merge into the current branch only when the
   working tree is clean, then show "restart required". Make the test command and git/gh calls injectable so tests never recurse into the real suite
   or touch the network.
3. Guardrails (extend the guardrail settings from the Teams stage): allow_extensions on, extensions_need_approval on, allow_self_patching on,
   self_patch_requires_tests on, self_patch_requires_approval on, self_patch_via_pull_request on. GRC: under change management (HB-CM-2) - fail if
   self_patch_requires_approval or self_patch_requires_tests is off; partial if extensions_need_approval is off.
4. UI: "Extensions" page (#/extensions; admins manage, others read): packs with their items, status toggles, versions/rollback, JSON preview;
   enabled extension domains appear as apps (sidebar group "Extensions", Portals, Ctrl K) with a generic table + detail view and links to
   assets/people; approvals render "extension" (pack preview) and "self_patch" (diff, test results, PR or merge mode). A "Restart required" banner
   when a self-patch was merged.
5. Tests: pack validation (reject unknown kinds, unsafe values; no code execution), enable/disable/rollback, domain records + links, template
   generation without Claude, a gap after importing a SIEM-like tool -> extension approval, self-patch flow against a temporary git repo with an
   injected fake test command (worktree, tests attached, approval merges, dirty tree refused, PR mode with a mocked gh).
`

const INSTALLER_SPEC = `
## Feature: simple installer (you own ONLY: install.ps1, install.sh, Dockerfile, docker-compose.yml, .dockerignore, scripts/, tests/test_installer.py)
A previous run of this task was interrupted. install.ps1 and scripts/install_copy.py already exist and look good: review them, keep what is right,
fix what is not, and finish the rest.
- install.ps1 (Windows PowerShell 5.1 compatible): finds Python >= 3.11, checks git, creates .venv, installs the project with the ai and ssh extras,
  copies .env.example to .env if missing (never overwrites), writes start-atrium.cmd / start-atrium.ps1, desktop shortcut unless -NoShortcut;
  -InstallDir, -Port, -NoShortcut, -Dev; idempotent; prints next steps (start, then open the first-run setup link the server prints).
- install.sh (bash, Linux/macOS; also under Git Bash on Windows where the venv uses Scripts/ not bin/): same steps, ./start-atrium.sh, optional
  --service to write (not enable) a systemd user unit and print how to enable it; set -euo pipefail; quoted paths (spaces).
- Dockerfile: slim official Python 3.12+ image, git and openssh-client, non-root user, project installed with ai and ssh extras, HUB_HOST=0.0.0.0
  inside the container, data in /data (HUB_DATA_DIR), EXPOSE 8710, HEALTHCHECK with python against /api/health. docker-compose.yml publishes
  127.0.0.1:8710:8710, named volume for /data, optional env_file .env, HUB_ALLOWED_HOSTS so the Host check accepts localhost. .dockerignore excludes
  .venv, .hub*, .git, caches, .env.
- Verify: run install.ps1 for real into a temporary folder (-InstallDir <temp> -NoShortcut) and confirm the installed "atrium --help" works; run
  install.sh under Git Bash the same way; read the Dockerfile carefully (docker may not be installed - say so). tests/test_installer.py: static
  checks (files exist, no secrets, PowerShell parses via [System.Management.Automation.Language.Parser]::ParseFile with no errors, bash -n
  install.sh, install_copy.py unit tests on temp folders). Never create shortcuts or files outside temporary folders during verification.
- Note: other agents are changing Python code at the same time; your installer must not depend on their unfinished work (just pip install -e).
`

const DOCS_SPEC = `
## Docs (you own ONLY README.md, docs/*.md (not docs/screenshots), .env.example, examples/README.md)
Document everything added in this round, accurately to the code (read it): connecting tools to the identity provider (provider selection, native
strategies per known tool, provider registration, Atrium sign-in via the provider); the integration fabric (connectors for Snipe-IT, CISO Assistant,
OpenVAS, Okta, Keycloak admin, SCIM, generic REST; connection settings and secret storage incl. HUB_SECRET_KEY and backing up secret.key; data
flows and strategies; the repair loop; the Vulnerabilities app; scan scope and approvals); People (sources, merging, person-asset links, person
page, leavers); Sign-in & SSO settings (presets Okta / Entra ID / Google / Keycloak, precedence of env vars); agent teams and agent management
(providers incl. local models via Ollama/LM Studio, permissions, schedules, guardrail settings and their compliance effect); extensions and
self-patching (what a pack can contain, approvals, tests, pull requests); new controls HB-VM-2, HB-VM-3, HB-AC-6, HB-AC-7 and the HB-CM-2 change;
installation (install.ps1, install.sh, Docker). New pages: docs/INTEGRATIONS.md (fabric, connectors, flows, strategies, SSO connection),
docs/AGENTS.md (agents, teams, providers, guardrails, extensions, self-patching), docs/PEOPLE.md. Update README (features table, Quick start with
the installers, safety model, layout, roadmap) and ARCHITECTURE (components, agents table, counts). Leave a "## Screenshots" section in README with
the placeholder comment <!-- screenshots --> right after the intro (screenshots are added later by someone else). Mark anything about third-party
products that code comments flag as unverified.
`

// ---------------------------------------------------------------- orchestration
const installer = agent(`${CONTEXT}\n${INSTALLER_SPEC}\nFinish the installer now. Report verification results precisely.`,
  { label: 'installer', phase: 'Installer', schema: RESULT })

phase('SSO')
const sso = await agent(`${CONTEXT}\n${SSO_SPEC}\nYou are the only agent changing Python and UI code right now (an installer agent edits only install
scripts/Docker files). Build this feature completely: backend, UI and tests.`, { label: 'sso-idp', phase: 'SSO', schema: RESULT })
const brief = (r) => JSON.stringify(r ? { summary: r.summary, api: r.api_added, open: r.open_issues } : 'FAILED - check the code yourself')

phase('Fabric')
const core = await agent(`${CONTEXT}\n${FABRIC_SPEC}\nThe SSO feature was just completed by another agent: ${brief(sso)}
NOTE: an earlier run of your role was interrupted part-way (the session ended). Partial work is on disk: hub/secrets.py and hub/connectors/
(__init__.py, base.py, generic_rest.py and stubs) and possibly edits in other files. The suite was green (269 passed) at that point. Read what
exists, keep what is right, and finish the role - do not start over blindly and do not leave duplicate implementations.
## Your role: FABRIC CORE (backend only). You own all Python files and tests for the core part of the spec, EXCEPT the bodies of
hub/connectors/snipeit.py, ciso_assistant.py and openvas.py (create them as the stubs described) and EXCEPT hub/web/**. Expose every API the Fabric
UI needs and list it precisely in api_added (another agent builds the UI from your list).`, { label: 'fabric-core', phase: 'Fabric', schema: RESULT })

const connectorJob = (name, file) => () => agent(`${CONTEXT}\n${FABRIC_SPEC}\nThe fabric core is done: ${brief(core)}
## Your role: the ${name} connector. Read hub/connectors/base.py, the registry and the stub ${file} first. You own ONLY ${file} (replace the stub
completely, same class name) and tests/test_connector_${file.split('/').pop().replace('.py', '')}.py. Other agents are writing the other connectors
and the UI at the same time. Use httpx.MockTransport (or a fake server) for tests; no real network. Make test() genuinely useful for a person
checking a real instance.`, { label: `connector-${name}`, phase: 'Fabric', schema: RESULT })

const fabricParts = await parallel([
  connectorJob('Snipe-IT', 'hub/connectors/snipeit.py'),
  connectorJob('CISO Assistant', 'hub/connectors/ciso_assistant.py'),
  connectorJob('OpenVAS / Greenbone', 'hub/connectors/openvas.py'),
  () => agent(`${CONTEXT}\n${FABRIC_SPEC}\nThe fabric core is done: ${brief(core)}
## Your role: FABRIC UI. You own ONLY hub/web/**. Build every UI item in the spec's Fabric UI section against the APIs listed above (read
hub/api.py and the new modules to confirm request/response shapes). Keep viewers/operators/admins in mind (data-min-role). Re-read your code for
syntax errors, broken imports and XSS; you may load pages in a browser against your own server on another port.`,
    { label: 'fabric-ui', phase: 'Fabric', schema: RESULT }),
])

phase('Teams')
const teamsBackend = await agent(`${CONTEXT}\n${TEAMS_SPEC}\nAlready built this round: SSO ${brief(sso)}; fabric ${brief(core)}.
## Your role: TEAMS BACKEND. You own the Python code and tests for this feature (not hub/web/**). List every API precisely in api_added for the UI
agent. The whole suite must be green at the end, including the fabric and connector tests.`, { label: 'teams-backend', phase: 'Teams', schema: RESULT })
const teamsUi = await agent(`${CONTEXT}\n${TEAMS_SPEC}\nThe backend is done: ${brief(teamsBackend)}
## Your role: TEAMS UI. You own ONLY hub/web/**. Build every UI item of this feature.`, { label: 'teams-ui', phase: 'Teams', schema: RESULT })

phase('People')
const peopleBackend = await agent(`${CONTEXT}\n${PEOPLE_SPEC}\nAlready built this round: SSO ${brief(sso)}; fabric ${brief(core)}; teams ${brief(teamsBackend)}.
## Your role: PEOPLE BACKEND. You own the Python code and tests for this feature (not hub/web/**), including the new connectors and the Snipe-IT
connector extension. List every API precisely in api_added. The whole suite must be green.`, { label: 'people-backend', phase: 'People', schema: RESULT })
const peopleUi = await agent(`${CONTEXT}\n${PEOPLE_SPEC}\nThe backend is done: ${brief(peopleBackend)}
## Your role: PEOPLE UI. You own ONLY hub/web/**. Build every UI item of this feature, including the person page with its relationship map and the
Sign-in & SSO settings card.`, { label: 'people-ui', phase: 'People', schema: RESULT })

phase('Extend')
const extendBackend = await agent(`${CONTEXT}\n${EXTEND_SPEC}\nAlready built this round: SSO ${brief(sso)}; fabric ${brief(core)}; teams ${brief(teamsBackend)};
people ${brief(peopleBackend)}.
## Your role: EXTENSIONS BACKEND. You own the Python code and tests for this feature (not hub/web/**). List every API precisely in api_added.
The whole suite must be green.`, { label: 'extend-backend', phase: 'Extend', schema: RESULT })
const extendUi = await agent(`${CONTEXT}\n${EXTEND_SPEC}\nThe backend is done: ${brief(extendBackend)}
## Your role: EXTENSIONS UI. You own ONLY hub/web/**. Build every UI item of this feature.`, { label: 'extend-ui', phase: 'Extend', schema: RESULT })

const installerResult = await installer

phase('Docs')
const docs = await agent(`${CONTEXT}\n${DOCS_SPEC}\nWhat was built this round (read the code to confirm every detail):
SSO: ${brief(sso)}
Fabric core: ${brief(core)}
Connectors and fabric UI: ${JSON.stringify(fabricParts.map((p) => p && p.summary))}
Teams: ${brief(teamsBackend)} / ${brief(teamsUi)}
People: ${brief(peopleBackend)} / ${brief(peopleUi)}
Extensions: ${brief(extendBackend)} / ${brief(extendUi)}
Installer: ${brief(installerResult)}`, { label: 'docs', phase: 'Docs', schema: RESULT })

return { sso, core, connectors_and_ui: fabricParts, teamsBackend, teamsUi, peopleBackend, peopleUi, extendBackend, extendUi, installer: installerResult, docs }
