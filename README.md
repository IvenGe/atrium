# Atrium

**An office suite for your whole toolchain - run by AI agents.**

Atrium is the central hall every tool opens onto.

Atrium imports your tools - open-source projects from GitHub, local projects, closed-source
applications and SaaS services - and makes them work together like the apps of an office
suite. A team of agents does the integration work:

- a **Hub Supervisor** that talks to every other agent and keeps the suite integrated,
- one **Tool Supervisor per imported tool**, responsible for that application,
- a **Patch Agent** that patches tools that don't fit (code patches on a git branch, or adapters
  for closed-source and SaaS tools),
- an **Operator Agent** that runs commands on this machine or on servers over SSH,
- an **Asset Supervisor** and a **GRC Supervisor** for the built-in Assets and Compliance apps.

Everything the agents say to each other is visible live, and anything that changes state waits
in an approval queue until a person approves it.

## What's inside

| App | What it does |
| --- | --- |
| **Portals** | App launcher (top bar) for the built-in apps and every imported tool. Tools open inside the hub. |
| **Apps** | Import from GitHub / local folder / SaaS URL (+ OpenAPI spec). Each tool gets a manifest, an integration score, health checks, start/stop, logs and its own supervisor agent. |
| **Integration hub** | Map of how tools connect - shared capabilities, single sign-on, event routes - plus port conflicts and missing dependencies. |
| **Agents** | Manage the agents (pause/resume, model, instructions), chat with the Hub Supervisor, and watch agent-to-agent messages live. |
| **Approvals** | Review and approve or reject agent commands and patches, with diffs. Full audit history. |
| **Operator** | Run commands locally or over SSH, manage hosts, discover host facts. |
| **Assets** | Asset register kept in sync automatically (tools, SaaS services, hosts) plus manual assets, owners and criticality. |
| **Compliance hub** | GRC: a control baseline evaluated against live hub state, mapped to ISO/IEC 27001:2022, SOC 2 and NIS2; risk register with heatmap (risks open and close automatically); policies with templates. |

## Quick start

Requires Python 3.11+ and git.

```bash
python -m venv .venv
.venv/bin/pip install -e ".[ai,ssh,dev]"    # Windows: .venv\Scripts\pip install -e ".[ai,ssh,dev]"
.venv/bin/atrium                            # Windows: .venv\Scripts\atrium
```

Open <http://127.0.0.1:8710>, click **Get Started**, and import the projects in
[`examples/`](examples/) to see the agents at work.

### Turn on Claude (optional)

Without credentials the agents run in **rules mode**: imports, analysis, scoring, template
patches, adapters, commands, assets and compliance all work deterministically. With Claude:

- the Hub Supervisor understands plain language and plans multi-step work using the other agents,
- the Patch Agent writes real source-code patches (e.g. adds a `/healthz` endpoint in the
  project's own framework),
- Tool Supervisors refine descriptions and capabilities from the README.

Set `ANTHROPIC_API_KEY` (or run `ant auth login`) before starting the hub, or put it in a `.env`
file - see [`.env.example`](.env.example). The default model is `claude-opus-5-5`; change it in
**Settings** or per agent. Requests opt into server-side refusal fallbacks
(`server-side-fallback-2026-07-01`, `fallbacks: "default"`).

## How it works

```mermaid
flowchart LR
  user([You]) -- chat / UI --> sup[Hub Supervisor]
  sup <--> ts1[Tool Supervisor: app A]
  sup <--> ts2[Tool Supervisor: app B]
  sup <--> pa[Patch Agent]
  sup <--> op[Operator Agent]
  sup <--> as[Asset Supervisor]
  sup <--> grc[GRC Supervisor]
  pa -- patches --> q{{Approval queue}}
  op -- commands --> q
  q -- approved --> pa & op
  op -- local shell / SSH --> hosts[(Machines)]
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
   (health probe, oauth2-proxy SSO, event poller, API wrapper), or a manifest override (new port).
5. **Approve** - patches and state-changing commands wait for you. Approved patches are applied
   and the suite is re-scored.
6. **Govern** - the Asset Supervisor registers everything as assets; the GRC Supervisor
   re-evaluates controls, collects evidence and opens/closes risks.

More detail in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Safety model

- **Autonomy levels** (Settings): `manual` - every agent command and patch needs approval;
  `assisted` (default) - agents may run known read-only commands, everything else needs approval;
  `autonomous` - agents act alone (the GRC Supervisor flags this as a failing control).
- **Blocked commands** (wiping disks, `rm -rf /`, shutdown, piping downloads into a shell, ...)
  are refused for everyone, people included.
- **SSH** uses keys only - the hub never stores passwords - and verifies host keys by default.
- **Patches** to source code land on a new branch in a separate worktree.
- **Web hardening**: binds to `127.0.0.1` by default, rejects unknown `Host` headers
  (DNS rebinding), and requires an `X-Hub-Request: 1` header on every state-changing API call
  (cross-site request forgery). There is no built-in login yet - if you expose the hub, put it
  behind an authenticating reverse proxy and list its hostname in `HUB_ALLOWED_HOSTS`.

## Project layout

```
hub/
  agents/          Hub Supervisor, Tool Supervisor, Patch Agent, Operator, Asset & GRC Supervisors
  integration/     analyzer, compatibility scoring, importer, patch planner, tool event bus
  execution/       command policy, local/SSH runners, tool process manager
  grc/             control baseline (ISO 27001 / SOC 2 / NIS2 mapping) and automated checks
  web/             the UI (vanilla JS modules, no build step)
  api.py           REST + Server-Sent Events API (docs at /api/docs)
  bus.py           agent message bus
  core.py          the Hub runtime
docs/              architecture and manifest specification
examples/          sample tools to import
tests/             pytest suite
```

## Development

```bash
.venv/bin/pytest            # run the tests
.venv/bin/atrium --port 8711 --data-dir .hub-dev
```

The UI is plain ES modules served by the API - edit `hub/web/` and reload.

## Roadmap

- Built-in login and roles (OIDC against the suite's identity provider)
- More built-in apps: service desk / ticketing, vulnerability management (match tool versions
  against advisories), backup orchestration
- Pull requests for patches on GitHub-hosted tools
- Container-based tool runtime and secrets vault integration
- Connector catalogue for popular SaaS services
