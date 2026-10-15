# Atrium

**An office suite for your whole toolchain - run by AI agents.**

Atrium is the central hall every tool opens onto.

Atrium imports your tools - open-source projects from GitHub, local projects, closed-source
applications and SaaS services - and makes them work together like the apps of an office
suite. A team of agents does the integration work:

- a **Hub Supervisor** that talks to every other agent and keeps the suite integrated,
- one **Tool Supervisor per imported tool**, responsible for that application and the lead of its **agent team**,
- a **Patch Agent** that patches tools that don't fit (code patches on a git branch, or adapters
  for closed-source and SaaS tools) and, when a new tool needs it, extends Atrium itself,
- an **Operator Agent** that runs commands on this machine or on servers over SSH,
- an **Asset**, a **Vulnerability**, a **GRC**, a **People**, a **Network** and an **Extensions Supervisor** for the
  built-in apps - they also run the **data flows** that let tools exchange data through the hub (for example Snipe-IT
  assets -> Hub Assets -> OpenVAS scans -> Hub Vulnerabilities -> CISO Assistant, Okta people -> Hub People -> leavers
  found, or firewall rules -> Hub Network -> segmentation and compliance evidence),
- **team agents** that people or supervisors create, on Claude, on a local model or on rules,
- **subsidiaries**: agent teams that work *inside* a tool - through an Atrium bridge the Patch Agent adds to its code,
  or through its API - from a sidecar next to it, governed by Atrium like a parent company governs a daughter company
  (off until an administrator allows it).

Everything the agents say to each other is visible live - on the **Agent bus**, one conversation at a time, with
every error an agent ran into - and anything that changes state waits in an approval queue until a person approves it. People sign in to the hub and get a role -
viewer, operator or admin - that decides what they may do.

## Screenshots

A made-up company with Snipe-IT, Keycloak, OpenVAS, CISO Assistant, Grafana, Wazuh and an edge firewall imported, two
AI model servers (a cloud service and an Ollama on its own GPU server), an agent team inside CISO Assistant and a few
chats that set the agents asking each other (all demo data, and no real model: `scripts/screenshots.py` retakes these
from the current UI, see [Development](#development)).
Click a picture to see it full size.

| | |
| --- | --- |
| **Home** - the shared Overview dashboard<br>![Home](docs/screenshots/home.png) | **A dashboard of tool widgets** - OpenVAS findings and deadlines, Snipe-IT, Wazuh alerts, the firewall ([DASHBOARD.md](docs/DASHBOARD.md#widgets))<br>![A dashboard of tool widgets](docs/screenshots/home-dashboard.png) |
| **Arranging a dashboard** - a widget dragged to its new place (every drag has a keyboard and a click alternative: [DASHBOARD.md](docs/DASHBOARD.md#moving-and-resizing-without-a-mouse))<br>![Arranging a dashboard](docs/screenshots/dashboard-edit.png) | **Apps** - every imported tool, its integration score and health<br>![Apps](docs/screenshots/apps.png) |
| **Integration hub** - suite score, data flows, identity, event routes<br>![Integration hub overview](docs/screenshots/integration-overview.png) | **Integration map** - tools and hub apps linked by data flows<br>![Integration map](docs/screenshots/integration-map.png) |
| **Segmentation map** - zones, assets and the traffic the firewall may allow ([NETWORK.md](docs/NETWORK.md#segmentation-map))<br>![Segmentation map](docs/screenshots/segmentation-map.png) | **Network** - devices, drift, changes ([NETWORK.md](docs/NETWORK.md#the-network-app))<br>![Network](docs/screenshots/network.png) |
| **A network device** - rules, interfaces, history, backups<br>![Network device](docs/screenshots/network-device.png) | **Approvals** - a firewall change waiting for a second administrator<br>![Approvals](docs/screenshots/approvals.png) |
| **CyFun self-assessment** - maturity and conformity per level ([COMPLIANCE.md](docs/COMPLIANCE.md#self-assessments))<br>![CyFun self-assessment](docs/screenshots/compliance-frameworks.png) | **Controls** - checked against live hub state, mapped to ISO 27001, SOC 2, NIS2 and CyFun ([COMPLIANCE.md](docs/COMPLIANCE.md#hub-security-baseline))<br>![Compliance controls](docs/screenshots/compliance-controls.png) |
| **People** - the directory merged from Keycloak and Snipe-IT<br>![People](docs/screenshots/people.png) | **A leaver** - still holding a laptop and a login<br>![Person](docs/screenshots/person.png) |
| **Vulnerabilities** - findings of an OpenVAS scan with deadlines<br>![Vulnerabilities](docs/screenshots/vulnerabilities.png) | **Agents** - supervisors, teams, the model each agent runs on and the chat<br>![Agents](docs/screenshots/agents.png) |
| **Agent bus** - one conversation: a person's question, what the Hub Supervisor asked the other agents, their answers and the Operator Agent's failure ([AGENTS.md](docs/AGENTS.md#conversations-and-errors))<br>![Agent bus](docs/screenshots/agent-bus.png) | **An agent's errors** - opened from its error count on the Agents page, each with who asked and the conversation it happened in<br>![An agent's errors](docs/screenshots/agent-errors.png) |
| **AI models** - a cloud provider and a self-hosted Ollama next to the suite's model choice ([AGENTS.md](docs/AGENTS.md#models-and-providers))<br>![AI models](docs/screenshots/ai-models.png) | **Agent settings** - one agent's model, parameters, instructions, tools, limits and escalation ([AGENTS.md](docs/AGENTS.md#agent-settings))<br>![Agent settings](docs/screenshots/agent-settings.png) |
| **A subsidiary** - an agent team working inside CISO Assistant from its sidecar, governed by Atrium ([SUBSIDIARIES.md](docs/SUBSIDIARIES.md#working-with-a-team))<br>![A subsidiary](docs/screenshots/subsidiaries.png) | **A change inside a tool** - the team's request, waiting for a person who did not ask for it ([SUBSIDIARIES.md](docs/SUBSIDIARIES.md#in-tool-actions-and-grants))<br>![A change inside a tool waiting for approval](docs/screenshots/subsidiary-approval.png) |
| **Agent guardrails** - in Settings<br>![Agent guardrails](docs/screenshots/settings-guardrails.png) | **Users & access** - accounts, roles and API tokens<br>![Users and access](docs/screenshots/users.png) |
| **Dark theme**<br>![Home in the dark theme](docs/screenshots/home-dark.png) | **Phone**<br><img src="docs/screenshots/home-phone.png" alt="Home on a phone" width="220"> |

## What's inside

| App | What it does |
| --- | --- |
| **Home** | Dashboards of widgets as tabs: numbers, charts and lists from the hub and from every connected tool (any data type a connection reads, and suggestions per tool), approvals, agent activity, compliance, network devices and leavers. Everyone arranges their own dashboards by **drag and drop** - with a keyboard and a click alternative for every drag - and administrators publish shared dashboards and pick the default. **Settings on the dashboard**: the AI models widget shows which model every agent runs on, one lane per provider, and administrators drag agents between providers or change the suite default; safety settings and hub accounts widgets; **Add to Home** on the Settings cards. Packs and tool manifests can declare widgets as data ([docs/DASHBOARD.md](docs/DASHBOARD.md)). |
| **Portals** | App launcher (top bar) for the built-in apps and every imported tool. Tools open inside the hub. |
| **Apps** | Import from GitHub / local folder / SaaS URL (+ OpenAPI spec). Each tool gets a manifest, an integration score, health checks, start/stop, logs, its own supervisor agent and a **Connection** to its API. |
| **Integration hub** | Three tabs. **Overview**: how tools connect - shared capabilities, single sign-on, event routes, data flows - plus port conflicts and missing dependencies. **Map**: the visual management panel - every tool and hub app in lanes, linked by data flows, single sign-on and event routes; drag from a tool to an app or another tool to propose a data flow (the Connect panel shows what is possible, recommends what the planner would propose and refuses loops). **Segmentation**: a firewall's zones, the assets inside them and the traffic its rules may allow, with compliance and vulnerability overlays and guarded change proposals. The **Identity** card lists the suite's identity providers (Keycloak, authentik, Zitadel, Authelia, ...) and each tool's single sign-on: the Patch Agent connects tools to the chosen provider natively (Grafana, Gitea, Forgejo, MinIO, BookStack, Outline, Nextcloud, Wazuh, CISO Assistant, Snipe-IT, Zammad, ...) and registers them there. **Data flows** move assets, vulnerabilities, controls and evidence, risks, people and accounts, compliance frameworks and self-assessments, and network device snapshots between tools and the hub's apps through built-in connectors (Snipe-IT, CISO Assistant, OpenVAS / Greenbone, Okta, Keycloak, SCIM 2.0, and the network device connectors) or a generic REST mapping, on a schedule, with a repair proposal after three failures. |
| **Agents** | Manage the agents, chat with the Hub Supervisor or any team agent, and watch agent-to-agent messages live. Each tool's supervisor can lead an **agent team** - proposed from templates for what the tool is (SIEM, GRC, asset inventory, vulnerability scanner, plus a maintainer) or designed by Claude - and admins create, edit and remove team agents running on Claude, on a **local model** (Ollama, LM Studio, vLLM, llama.cpp - any OpenAI-compatible server) or on rules, with permissions, a schedule and a standing task. |
| **Agent bus** | Every conversation on the agent bus, live: what one chat message, one person's action or one scheduled run made the agents ask each other - who asked whom, what they answered, how long it took and what failed - as a chat-style transcript, with filters (agent, status, errors only, my chats) and search. Each agent's errors are kept with the conversation they happened in, for operators to acknowledge. Viewers read routing, status and error texts, operators and administrators the messages (secrets masked), and a person's chat stays theirs ([docs/AGENTS.md](docs/AGENTS.md#conversations-and-errors)). |
| **Approvals** | Review and approve or reject agent commands, patches, data flows, scans, repairs, agent teams, extension packs, changes to Atrium itself, network device changes, and a subsidiary's bridge patch, charter and in-tool changes, with diffs, test results, policy violations and expiry countdowns. Device changes need a second administrator. Full audit history. |
| **Subsidiaries** | Agent teams inside tools ([docs/SUBSIDIARIES.md](docs/SUBSIDIARIES.md)). **Give it a team inside** on a tool's page: the Patch Agent adds an Atrium bridge to its code (typed actions, an "Ask the team" panel for the tool's users, events) through an approved patch, or the team works through the tool's API. The team runs in a **sidecar** next to the tool and thinks through Atrium's model gateway; Atrium approves its **charter** (actions, staff, budgets, model routing), every change it wants to make in the tool, and can pause, stop or kill-switch it. A group dashboard, an org chart per team, the charter with its versions, a hash-chained audit trail, reports and the setup steps. |
| **Operator** | Run commands locally or over SSH, manage hosts, discover host facts. |
| **Network** | Firewalls, routers, switches and host firewalls read through their own APIs (OPNsense, pfSense, MikroTik RouterOS, FortiGate, PAN-OS, Cisco IOS-XE, Linux nftables / ufw / firewalld, Windows Defender Firewall): rules, interfaces and zones, snapshot history with diffs, **drift** (changes made outside Atrium) with baselines, and encrypted configuration **backups**. **Device changes are off by default**; switched on, every change is a proposal a second administrator approves, applied in a maintenance window after a backup, verified and rolled back unless it passes. |
| **Assets** | Asset register kept in sync automatically (tools, SaaS services, hosts, inventories such as Snipe-IT - merged by address, hostname or serial) plus manual assets, owner and user (people), criticality and vulnerability-scan scope. |
| **People** | The workforce directory merged from Okta, Keycloak and SCIM (by email, then login), the accounts people hold in the tools, the assets they own or use, and a person page with a relationship map. **Leavers** who still have access or devices are flagged, with one-click actions. |
| **Vulnerabilities** | Findings from scanners and other tools: scans of in-scope assets (with approval), severity, CVEs, remediation deadlines per severity (SLA), automatic "fixed" when a rescan no longer finds them, and risks for critical findings past their deadline. |
| **Compliance hub** | GRC: 30 controls evaluated against live hub state (including network segmentation, drift, device backups and device-change control), mapped to ISO/IEC 27001:2022, SOC 2, NIS2 and CyFun; risk register with heatmap (risks open and close automatically); policies with templates. **Frameworks**: CyberFundamentals (CyFun) 2025 and 2023 built in - catalog browser, self-assessments with two maturity scores per requirement, conformity per level (Basic, Important, Essential) with its reasons, and a verifiable **audit pack** (ZIP with SHA-256 manifest) - plus frameworks read from CISO Assistant, such as the EU Cyber Resilience Act. |
| **Extensions** | Packs that add data types (alerts, tickets, incidents, ...) with their own apps, connector mappings, SSO recipes, compliance rules and team templates - data only, versioned, enabled without a restart. Generated after an import from templates or by Claude, and approved by an admin. When only code can help, a **self-patch** of Atrium is tested on its own branch and opened as a pull request after approval. |
| **Settings** | Autonomy level, default model, vulnerability deadlines, **Agent guardrails**, **Network changes** (device-change guardrails and maintenance windows), **AI providers** (local models) and **Sign-in & SSO** (presets for Okta, Microsoft Entra ID, Google, Keycloak, authentik). |
| **Users & access** | Admins only. Accounts (local passwords or single sign-on), roles, password resets, API tokens for scripts and tools, and the person each account belongs to. Everyone can change their password and sign out other sessions from the user menu. |

## Quick start

Requires Python 3.11+ and git.

### With the installer

Linux and macOS (also Git Bash on Windows), from a clone of the repository:

```bash
bash install.sh                # options: --install-dir DIR  --port PORT  --dev  --service
./start-atrium.sh
```

Windows (PowerShell 5.1 or later):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1     # options: -InstallDir DIR -Port PORT -NoShortcut -Dev
.\start-atrium.cmd             # or the "Atrium" shortcut on the desktop
```

The installers find Python 3.11 or newer (set `ATRIUM_PYTHON` to choose one), check for git, create `.venv`, install
Atrium with the `ai` and `ssh` extras, copy `.env.example` to `.env` when there is none, and write the start scripts.
They are safe to run again (after `git pull`, say): an existing `.env` and the hub's data are never touched.
`--install-dir` / `-InstallDir` copies the program to another folder first (without local state such as `.venv`,
`.env` and `.hub`). `--service` writes a systemd user unit on Linux (`~/.config/systemd/user/atrium.service`) but does
not enable it; enable it with `systemctl --user daemon-reload && systemctl --user enable --now atrium.service`, and
read the setup link with `systemctl --user status atrium.service`.

### With Docker

```bash
docker compose up -d --build
docker compose logs atrium     # shows the first-run setup link
```

The image (Python 3.13 slim, git and the SSH client, a non-root user) keeps the hub's data in the `atrium-data`
volume at `/data` and is published on `127.0.0.1:8710` only. Settings come from `.env` when it exists (Docker Compose
2.24 or newer); add other host names people use to `HUB_ALLOWED_HOSTS` there. To run commands over SSH, mount your
keys into the container (see the comment in `docker-compose.yml`). Account commands run inside the container:
`docker compose exec atrium atrium user list`. Tools that Atrium would start
itself (for example `npm start`) need their runtime in the image too; SaaS tools and tools on other hosts work as usual.
Self-patching needs a git checkout, so it is not available in the container.

### By hand

```bash
python -m venv .venv
.venv/bin/pip install -e ".[ai,ssh,dev]"    # Windows: .venv\Scripts\pip install -e ".[ai,ssh,dev]"
.venv/bin/atrium                            # Windows: .venv\Scripts\atrium
```

### First run

On the first start there are no accounts yet, so the hub prints a one-time setup link:

```
First run: create the administrator at http://127.0.0.1:8710/#/setup?token=...
```

Open it, choose an administrator username and password (at least 12 characters), and you are
signed in. Then click **Get Started** and import the projects in [`examples/`](examples/) to see
the agents at work. Add colleagues under **Users & access**.

To skip the link, set `HUB_ADMIN_USERNAME` and `HUB_ADMIN_PASSWORD` before the first start, or
create the account offline with `atrium user create alice --role admin`. The same command line is
the way back in if every administrator is locked out:

```bash
.venv/bin/atrium user passwd alice           # set a new password, sign out all of alice's sessions
.venv/bin/atrium user create rescue --role admin
```

Roles, sessions, API tokens and single sign-on are described in [docs/AUTH.md](docs/AUTH.md).

### Turn on an AI model (optional)

Without an AI model provider the agents run in **rules mode**: imports, analysis, scoring, template
patches, adapters, commands, assets, data flows, people, template extensions and compliance all work
deterministically. With an AI model - Claude, OpenAI (or Azure OpenAI), or a local model server:

- the Hub Supervisor understands plain language and plans multi-step work using the other agents,
- the Patch Agent writes real source-code patches (e.g. adds a `/healthz` endpoint in the
  project's own framework), generic REST connectors from OpenAPI specs, extension packs and self-patches,
- Tool Supervisors refine descriptions and capabilities from the README and can design agent teams.

For Claude, set `ANTHROPIC_API_KEY` (or run `ant auth login`) before starting the hub, or put it in a `.env`
file - see [`.env.example`](.env.example) - or store a key on Claude's card under **Settings > AI providers**. The
default model is `claude-opus-5-5`; change it on that card or per agent. Requests opt into server-side refusal
fallbacks (`server-side-fallback-2026-07-01`, `fallbacks: "default"`). For OpenAI ("ChatGPT models", through the
Responses API with `store: false`), set `OPENAI_API_KEY` or store a key on OpenAI's card and choose its default model;
a ChatGPT subscription does not include API access. Azure OpenAI resources are added there too. Every model call goes
through one provider layer that picks the model per agent (Claude first, else OpenAI, else a local model, else rules),
masks the hub's secrets in what it sends and meters the tokens and estimated cost; a person's chat with an agent stays
theirs (see [docs/AGENTS.md](docs/AGENTS.md#models-and-providers)).

Which model runs where is yours to choose: **Settings > AI models > Model choice** sets the suite default, a default per
task (chat, code changes, structured generation) and a fallback chain; each team can have its own default (Agents
page), and every agent - core or team agent - can choose its own provider and model, or be **local only**, on its
settings page (`#/agents/<id>/settings`), which also shows where its model comes from. The guardrail "Agents may send
data to cloud AI providers" switches every cloud provider off at once; cloud providers in use count as suppliers for
compliance control HB-SC-1 (an owner and a yearly terms review on their card).

The same settings page holds the rest of an agent's customization: effort, temperature (where the model takes it),
output and tool-round limits; instructions added to the built-in ones (or replacing them); its reply language; the
tools it may use; daily and monthly budgets with a hard stop, and rate limits; whether it remembers each person's
conversation (off, for the session, or stored encrypted with a retention); a **playground** to try a prompt on unsaved
changes against a second model; when it escalates to a person (an approval an operator acknowledges or dismisses
with an answer the agent reads next), pausing its schedule after failed runs, and which of its events are
notifications (highlighted in the Agents page's "Needs attention" strip, optionally sent to integrated tools on the tool
bus); and a history to restore earlier versions. The suite's AI spending is capped at
20 USD per day by default (guardrail "Cap the AI model spending per day"); **Settings > AI models > AI usage and
spending** shows the calls, tokens and estimated cost per agent and provider
([docs/AGENTS.md](docs/AGENTS.md#agent-settings)).

Team agents can also run on a **local model**: add a provider under **Settings > AI providers** (any server with an
OpenAI-compatible API; the default base URL `http://localhost:11434/v1` is Ollama's), test it to list its models, and
pick it for the agent, its team or the whole suite. Tool calling needs a model and server that support it (vLLM: `--enable-auto-tool-choice` with a
`--tool-call-parser`; llama.cpp: `--jinja`); otherwise switch the provider's tools off and its agents answer in plain
text. See [docs/AGENTS.md](docs/AGENTS.md#local-models).

## How it works

```mermaid
flowchart LR
  user([You]) -- chat / UI --> sup[Hub Supervisor]
  sup <--> ts1[Tool Supervisor: app A]
  sup <--> ts2[Tool Supervisor: app B]
  ts1 <--> team[Team agents]
  sup <--> pa[Patch Agent]
  sup <--> op[Operator Agent]
  sup <--> mods[Asset, Vulnerability, GRC, People, Network, Extensions Supervisors]
  pa -- patches, extensions, self-patches --> q{{Approval queue}}
  op -- commands --> q
  mods -- flows, scans, device changes --> q
  q -- approved --> pa & op & mods
  op -- local shell / SSH --> hosts[(Machines)]
  ts1 -- connector --> api1[(App A's API)]
  ts2 -- device connector --> fw[(Firewall / router / switch)]
```

1. **Import** - the Hub Supervisor clones the repo (or points at the folder / SaaS URL) and
   assigns a Tool Supervisor.
2. **Analyse** - the Tool Supervisor infers a [hub manifest](docs/MANIFEST.md): stack, launch
   command, port, health endpoint, API, SSO, capabilities provided/consumed, events. A tool that
   ships its own `hub.manifest.yaml` is *native*.
3. **Score** - the Hub Supervisor scores every tool against the rest of the suite (manifest,
   launchable, health, API, SSO, events, port conflicts, dependencies).
4. **Patch** - each gap goes to the Patch Agent, which proposes a patch: a commit on a new branch
   in a separate git worktree (your checkout is never touched), an adapter kept by the hub
   (health probe, native SSO configuration plus the client registration at the identity provider, oauth2-proxy, event
   poller, API wrapper), or a manifest override (new port).
5. **Extend** - when Atrium itself lacks something for the tool (a place for a SIEM's alerts or a service desk's
   tickets, a connector, an SSO recipe), the Patch Agent proposes an extension pack; when only code can help, a
   tested change to Atrium on its own branch.
6. **Approve** - patches, extensions and state-changing commands wait for you. Approved patches are applied
   and the suite is re-scored.
7. **Exchange data** - once a tool has a connection, the Hub Supervisor proposes data flows
   between it and the hub's apps; the module supervisors run them through the tool's supervisor
   (the only agent that decrypts its credentials), and failing flows get a repair proposal.
8. **Govern** - the Asset Supervisor registers everything as assets, the People Supervisor links people to their
   accounts and devices, the Network Supervisor keeps device snapshots, drift and backups, and the GRC Supervisor
   re-evaluates controls, collects evidence and opens/closes risks. People score themselves against CyFun in the
   Compliance hub and export an audit pack.
9. **Change the network (off by default)** - with device changes switched on, an operator proposes an allow rule
   between two zones (or disabling rules) on the segmentation map; a second administrator approves it on the
   Approvals page; the Network Supervisor applies it in a maintenance window after a backup, verifies it over a new
   connection and confirms it, or rolls it back.
10. **Put a team inside a tool (off by default)** - an operator asks for one; an administrator approves the Patch
    Agent's bridge patch; the tool is deployed with its public `bridge.env`; the sidecar enrolls with a one-time code;
    Atrium proves the bridge with its conformance vectors; another administrator approves the charter. From then on
    the team answers the tool's users and works on its tasks, and every change it wants to make waits for a person.

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety model

- **Sign-in and roles**: every API call needs a signed-in person or an API token, checked on the
  server. `viewer` reads everything, `operator` may also change things (import, approve, run
  commands, edit people, propose device changes, ...), `admin` also manages accounts, tokens, settings, agents,
  credentials, extensions and self-patches, and decides device changes and a subsidiary's bridge patch and charter. Tokens with the `integration` role can only publish events, and a subsidiary's sidecar token reaches only the sidecar API of its own subsidiary. Sign in with a local password
  (scrypt-hashed, 12+ characters, throttled after repeated failures) or through single sign-on (OIDC) - configured in
  **Settings > Sign-in & SSO** or with `HUB_OIDC_*` variables, which win - against the identity provider, which is
  where MFA belongs. By default sessions expire after 12 hours idle and 7 days at most. Details in
  [docs/AUTH.md](docs/AUTH.md).
- **Autonomy levels** (Settings): `manual` - every agent command and patch needs approval;
  `assisted` (default) - agents may run known read-only commands, everything else needs approval;
  `autonomous` - agents act alone (the GRC Supervisor flags this as a failing control).
- **People and automation**: commands an administrator types run directly; an operator's run
  directly on SSH hosts, but on the hub machine only read-only ones do - anything else, and starting
  a tool, waits for an administrator (it would run with Atrium's own privileges). Commands from
  agents and API tokens follow the autonomy level, and what an agent does on a person's chat request
  counts as that person's. Approvals record who decided them.
- **Blocked commands** (wiping disks, `rm -rf /`, shutdown, piping downloads into a shell, ...)
  are refused for everyone, people included (guardrail `block_catastrophic_commands`).
- **Agent guardrails** (Settings > Agent guardrails, admins): team agents never get more permissions than the agent
  that created them, teams are limited in size (5) and do not nest, team agents' actions follow the autonomy level,
  new teams and scheduled scans wait for approval, generated extensions wait for approval, and self-patches must pass
  the tests, be approved and go through a pull request. Relaxing one asks for confirmation, is logged as a warning,
  and makes control HB-AC-6, HB-AC-2 or HB-CM-2 fail or go partial ([docs/AGENTS.md](docs/AGENTS.md#guardrails)).
- **Second person and expiry**: device changes can only be approved by an administrator who did not propose them
  (guardrail `device_changes_need_second_person`, on); `approvals_need_second_person` (off by default) extends the
  rule to self-patches and flows drawn on the integration map. Device-change and self-patch approvals are bound to
  what was reviewed (the device revision and the operations' hash, the self-patch's commit) and expire after
  `approval_expiry_hours` (24).
- **Extensions are data**: packs are validated strictly and nothing in them is executed; packs an agent generates and
  changes to Atrium's code are decided by admins only. A self-patch is committed on its own branch in a separate
  worktree and tested there. Its tests run before anyone approves it, without credentials in their environment but
  not sandboxed: switch `allow_self_patching` off if that is too much.
- **SSH** for the Operator Agent uses keys only - the hub never stores those passwords - and verifies host keys by
  default. Device connections over SSH prefer keys (a password only for devices that cannot use them, encrypted like
  every credential), always check host keys strictly, and use `sudo -n` with fixed commands on Linux hosts.
- **Credentials** (API tokens and passwords of tool connections, local model API keys, the SSO client secret) are
  encrypted with `HUB_SECRET_KEY` (or a generated `secret.key` in the data folder - back it up separately), never
  returned by the API or logged, and only sent to the address they were entered for: a changed address, or a repair,
  cannot redirect them. Only admins edit them. Device configuration backups are encrypted with the same key, checked
  by SHA-256, and only an admin can download one.
- **Network devices are read-only by default**: the guardrail `device_changes` is off. Switched on, a change is
  possible only through the change path ([docs/NETWORK.md](docs/NETWORK.md#device-changes)):
  - a person's proposal;
  - a second administrator's approval on the Approvals page;
  - a maintenance window (or an admin's justified emergency);
  - an encrypted backup first;
  - the device's own rollback armed before writing;
  - verification over a new connection, else rollback, else restore of the backup.

  Atrium never opens "any", refuses changes that could cut it off from the device, and switching `device_changes`
  off blocks every approved change at once. The write methods can never be called as connector actions.
- **Agent teams inside tools (subsidiaries)** are off until an administrator allows them. The bridge in the tool holds
  no secret: it only verifies Atrium's signatures. The sidecar connects outbound only and never holds a model key:
  Atrium composes every prompt and tool list. A sidecar may call only what its short-lived ticket lists, every change
  needs a person's approval and then runs once with exactly the approved bytes (a single-use grant bound to their
  hash), tool data reaches the model only delimited as untrusted, and pausing, stopping or the kill switch takes
  effect without the sidecar's cooperation ([docs/SUBSIDIARIES.md](docs/SUBSIDIARIES.md#the-security-model)).
- **Untrusted text**: rule descriptions and names read from devices, and requirement text read from GRC tools, are
  shown as text only, never used in commands, and never handed to agents or models. Agents see network counts only.
- **Side-effecting connector actions** (an OpenVAS scan) run only for a person or through their approval path, never
  for a team agent or another module.
- **Viewers never see webhook URLs, connection settings or tool-event payloads** in the Integration hub and on the
  map (the tool pages still show the manifest's webhook URL - see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md#integration-map)).
- **Scans** only ever target assets in scan scope; scheduled and agent-initiated scans wait for
  approval (guardrail `scans_need_approval`, on by default) unless the hub runs autonomously.
- **Compliance claims**: control-to-framework references are analyst mappings, and the CyFun conformity thresholds
  come from the CISO Assistant library copy (the CCB originals were unreachable). Both are labelled as unverified in
  the UI and the audit pack ([docs/COMPLIANCE.md](docs/COMPLIANCE.md)).
- **Leavers**: Atrium flags people who left but still have access or devices; it never changes accounts in the tools
  itself, and disabling a leaver's Atrium account is an admin action.
- **Patches** to source code land on a new branch in a separate worktree.
- **Web hardening**: binds to `127.0.0.1` by default, rejects unknown `Host` headers
  (DNS rebinding), uses `HttpOnly`, `SameSite=Lax` session cookies, and requires an
  `X-Hub-Request: 1` header on every state-changing browser call (cross-site request forgery).
  Responses send `X-Frame-Options: DENY` and `frame-ancestors 'none'` so the UI cannot be embedded. An imported
  tool's manifest can set only a hex colour and a one- or two-character icon for its tile
  ([docs/MANIFEST.md](docs/MANIFEST.md)). The sign-in screen never shows text taken from the address
  ([docs/AUTH.md](docs/AUTH.md#single-sign-on-oidc)). If other people reach the hub over a network, put a TLS
  reverse proxy in front and set `HUB_PUBLIC_URL`, `HUB_ALLOWED_HOSTS` and `HUB_COOKIE_SECURE=1`.

## Documentation

| Page | Covers |
| --- | --- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | components, request pipeline, the agent bus and its conversations, agents, approvals, network, compliance, state and files, events, endpoints, extending |
| [docs/AUTH.md](docs/AUTH.md) | sign-in, roles, sessions, API tokens, single sign-on for Atrium and the Sign-in & SSO settings |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | connections and connectors, credentials and the secret key, data flows, the Integration map, repairs, vulnerabilities and scans, single sign-on for tools |
| [docs/AGENTS.md](docs/AGENTS.md) | agents, team agents and teams, models and providers, agent settings, chat privacy, the Agent bus (conversations and agents' errors), local models, guardrails, extensions, self-patching |
| [docs/PEOPLE.md](docs/PEOPLE.md) | the People app, directories, accounts, person-asset links, leavers |
| [docs/NETWORK.md](docs/NETWORK.md) | the Network app, device connectors per vendor (what is verified, least-privilege setup), drift, backups, the segmentation map, guarded device changes and maintenance windows |
| [docs/COMPLIANCE.md](docs/COMPLIANCE.md) | the control baseline with its references, CyFun 2025 / 2023 self-assessments and conformity, the audit pack, CISO Assistant framework sync, the CRA |
| [docs/SUBSIDIARIES.md](docs/SUBSIDIARIES.md) | agent teams inside tools: setting one up, working with it, the bridge patch, the sidecar, the charter, in-tool changes and grants, the security model, troubleshooting, and the bridge contract `atrium-bridge/1` |
| [docs/DASHBOARD.md](docs/DASHBOARD.md) | Home dashboards: tabs, drag and drop and its keyboard and click alternatives, the widget catalog, widgets from every tool, the AI models and settings widgets, Add to Home, widgets declared by packs and manifests, roles, performance |
| [docs/MANIFEST.md](docs/MANIFEST.md) | the hub manifest of a tool, capabilities, dashboard widgets, events |

## Project layout

```
hub/
  agents/          Hub Supervisor, Tool Supervisor, Patch Agent, Operator, Asset, Vulnerability, GRC, People, Network
                   and Extensions Supervisors, agent teams and team agents, the shared agent toolkit
  auth/            accounts, passwords, sessions, API tokens, role policy, single sign-on (OIDC), Sign-in & SSO settings
  connectors/      connector SDK and connectors to tools' own APIs (Snipe-IT, CISO Assistant, OpenVAS, Okta,
                   Keycloak admin, SCIM 2.0, generic REST), the network device model (netmodel.py) and device
                   connectors (OPNsense, pfSense, MikroTik, FortiGate, PAN-OS, Cisco IOS-XE, Linux host firewalls,
                   Windows Defender Firewall, and a fake firewall for development)
  extensions/      extension packs, their registry and records, compliance rules, gap detection and templates,
                   packs written by Claude, self-patching
  integration/     analyzer, compatibility scoring, importer, patch planner, identity providers and the SSO catalog,
                   tool event bus, connections, data flows, strategy planner, the integration map (canvas.py), the
                   network read model, segmentation, device changes and maintenance windows
  execution/       command policy, local/SSH runners and SSH sessions for device connectors, tool process manager
  dashboards/      Home dashboards: stored layouts, widget types and their data (computed and cached on the server),
                   metrics, data types widgets may read, per-tool suggestions, declared widgets, templates
  subsidiary/      agent teams inside tools: governance, charters, the model gateway, in-tool actions and grants,
                   the audit trail, bridge patches, the bridge contract, the vendored bridge cores (templates/) and
                   the sidecar (sidecar/, the atrium-sidecar command)
  grc/             control baseline (ISO 27001 / SOC 2 / NIS2 / CyFun mapping) and automated checks
    frameworks/    CyFun 2025 and 2023 catalogs, self-assessments, scoring, audit pack, CISO Assistant sync
  web/             the UI (vanilla JS modules, no build step; js/canvas/ is the map engine, js/dashboard/ the
                   dashboard grid, widgets, gallery and the AI models widget)
  api.py           REST + Server-Sent Events API (docs at /api/docs)
  network_api.py, network_changes_api.py, canvas_api.py   routes of the Network app, device changes and the maps
  dashboards_api.py  routes of the Home dashboards and widgets
  bus.py           agent message bus: messages, conversations (threads), the privacy of a person's chat
  conversations.py, agent_errors.py, bus_api.py   the Agent bus page: conversations, agents' errors, routes
  core.py          the Hub runtime (and the scheduler for data flows, agents and device changes)
  people.py        the People app: merging, accounts, links, leavers
  secrets.py       encryption of stored credentials and device backups
  guardrails.py    the guardrails admins can relax (agents, extensions, approvals, network changes)
  llm_providers.py local models with an OpenAI-compatible API (Ollama, LM Studio, vLLM, llama.cpp)
docs/              architecture, sign-in and access control, integrations, agents and extensions, people, network,
                   compliance, Home dashboards, manifest; research/ holds the vendor and framework research behind them
examples/          sample tools to import
scripts/           install_copy.py (used by the installers), build_cyfun_catalog.py (regenerates the CyFun catalogs),
                   demo_hub.py (a demo hub with fake tool APIs, fake model servers, a scripted subsidiary sidecar
                   and made-up data), screenshots.py (retakes
                   docs/screenshots from it and checks every page per role), build_bridge_vectors.py,
                   build_bridge_cores.py and sync_contract_doc.py (the bridge contract's test vectors, the vendored
                   cores' pinned widget hash, and its copy in docs/SUBSIDIARIES.md; each has --check)
tests/             pytest suite; tests/js/ holds the map engine's Node tests (run by tests/test_js.py when node exists)
install.sh         installer for Linux and macOS (and Git Bash)
install.ps1        installer for Windows
Dockerfile, docker-compose.yml   the container image and its Compose file (`--target sidecar`: a subsidiary's sidecar)
```

## Development

```bash
.venv/bin/pytest            # run the tests
.venv/bin/atrium --port 8711 --data-dir .hub-dev
```

A fresh data directory prints its own setup link; set `HUB_ADMIN_USERNAME` and
`HUB_ADMIN_PASSWORD` to get an administrator without it. The UI is plain ES modules served by the
API - edit `hub/web/` and reload. The tests use mocked HTTP transports, fake models and temporary git
repositories, and `tests/conftest.py` sets `HUB_LLM=off` and `HUB_SELF_PATCH=off`, so no test calls a model or
patches the real checkout. Device connectors are tested against fake devices (`httpx.MockTransport`, a fake SSH
transport, a NETCONF fake); no test contacts a real device. With Node installed, `tests/test_js.py` also checks every
UI module with `node --check` and runs the unit tests of the map engine and the UI toolkit
(`node --test tests/js/*.test.mjs`); without Node those tests are skipped. When Playwright and its Chromium are
installed, `tests/test_ui_browser.py` checks in a headless browser that dialogs keep the keyboard inside, close when
the page changes, and give the focus back, that the Approvals page states which Operator commands wait for an
administrator, and that wide content stays inside its card and the window; `tests/test_dashboard_browser.py` checks
the Home dashboards' keyboard moves, menus and tabs, the gallery drawer's focus and the phone layout; otherwise they
are skipped. `HUB_SLOW_TESTS=1` also runs the tests marked `slow` (the dashboards' performance budget over a large
hub, `tests/test_dashboards_perf.py`).
`tests/test_demo_hub.py` runs the real connectors against the demo hub's fake tool APIs. Some host-firewall tests need root, `unshare` or PowerShell (`pwsh` or `ATRIUM_TEST_PWSH`)
and skip elsewhere.

To try the Network app without a device, start a development hub with `HUB_DEV_FAKE_DEVICES=1`: it registers an
in-memory **fake firewall** connector (never set this in production).

After a change to a screen, retake the screenshots with `.venv/bin/python scripts/screenshots.py` (Playwright and its
Chromium; `--chromium PATH` picks another build). It starts the demo hub of `scripts/demo_hub.py` on port 8790 with a
temporary data directory - small fake Snipe-IT, Keycloak, Greenbone (GMP), CISO Assistant, Grafana and Wazuh APIs on
127.0.0.1, two fake AI model servers with an OpenAI-compatible API (canned answers; `HUB_LLM=off` keeps Claude and
OpenAI off, so no real model is called) and the fake firewall, filled with made-up people, assets, findings, dashboards,
agents on different models and proposals through the hub's own API, plus an API-only subsidiary of CISO Assistant whose
scripted sidecar enrolls and asks for a change in the tool - replaces the PNG files in `docs/screenshots` (256-colour
PNGs when Pillow is installed), then visits every page and tab as an administrator, an operator and a viewer, and at
phone width, and reports console errors, failed API calls and content wider than its card or the window (exit status
1). `--check-only` runs only that check. The fake tools and the sidecar are stopped, the hub by its PID, and the data
directory is removed. To try the same demo by hand, run `.venv/bin/python scripts/demo_hub.py` and sign in as `ava` or
`noah` (admin), `jonas` (operator) or `lena` (viewer) with the password it prints; Ctrl+C (or `kill` of the PID it
prints) stops it.

## Roadmap

- Testing the device connectors against real devices, and closing the items they mark unverified
  ([docs/NETWORK.md](docs/NETWORK.md))
- First-match evaluation of firewall rules on the segmentation map (block rules, rule order, NAT), and more device
  change kinds (editing and removing rules; a `remove_rules` operation so Cisco IOS-XE allows can be reverted)
- Confirming the CyFun conformity thresholds and the control mappings against the CCB's and the standards' own texts
- Faster cold dashboard data on large hubs (counted fields kept in columns of their own), and, if wanted, tools' own
  pages inside dashboard widgets behind a guardrail ([docs/DASHBOARD.md](docs/DASHBOARD.md#not-built-tools-own-pages-inside-widgets))
- Sandboxed test runs for self-patches (a container or a separate user)
- Pull requests for patches to GitHub-hosted tools (self-patches of Atrium already use them)
- Matching tool versions against security advisories, and backup orchestration
- Container-based tool runtime and secrets vault integration
- Subsidiaries: Atrium-managed sidecars, vendored PHP and Java bridge cores, runs started by tool events, panel
  confirmations, scheduled reports ([docs/SUBSIDIARIES.md](docs/SUBSIDIARIES.md#not-built-in-round-4))
- Connector catalogue for popular SaaS services
