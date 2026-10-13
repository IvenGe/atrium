# Agents, teams and extensions

Atrium's work is done by agents that talk to each other on the message bus ([ARCHITECTURE.md](ARCHITECTURE.md#the-agent-bus)).
This page covers the agents, the agent teams people and agents build, the model providers they run on, the guardrails
that bound them, and how Atrium extends and patches itself when a new tool needs it.

## Core agents

| Agent | Id | Permissions | Responsibilities |
| --- | --- | --- | --- |
| Hub Supervisor | `supervisor` | all | imports tools, scores the suite, sends gaps to the Patch Agent, plans data flows, health sweeps, chat |
| Tool Supervisor | `tool:<id>` | all | one per tool: analysis, health, start/stop, the tool's connector (the only agent that decrypts its credentials), lead of the tool's team |
| Patch Agent | `patcher` | `read`, `patches` | patches to tools, flow repairs, generated connectors, extension packs and self-patches |
| Operator Agent | `operator` | `read`, `commands` | commands on this machine or over SSH, under the command policy |
| Asset Supervisor | `module:assets` | `read`, `tool_api`, `flows`, `assets_write`, `agents` | the asset register and asset flows |
| Vulnerability Supervisor | `module:vulns` | `read`, `tool_api`, `flows`, `assets_write`, `grc_write`, `agents` | scans, findings, deadlines, vulnerability flows |
| GRC Supervisor | `module:grc` | `read`, `tool_api`, `flows`, `grc_write`, `agents` | controls, evidence, risks, GRC flows |
| People Supervisor | `module:people` | `read`, `tool_api`, `flows`, `assets_write`, `agents` | the People app, people and accounts flows, leavers ([PEOPLE.md](PEOPLE.md)) |
| Extensions Supervisor | `module:extensions` | `read`, `tool_api`, `flows`, `agents` | the apps extension packs add and their flows ([below](#extensions)) |

On the **Agents** page admins pause and resume core agents and give them another model or extra instructions
(collection `agents`). Core agents cannot be removed. Operators chat with the Hub Supervisor (`POST /api/chat`).

## Team agents

People and agents can add **team agents** (custom agents): a role, instructions, a model provider, permissions, a team
and an optional schedule with a standing task. They are data, not code (collection `agent_defs`, `AgentDef` in
`hub/models.py`):

| Field | Meaning |
| --- | --- |
| `id` | `agent:<slug>` |
| `name`, `title`, `description` | who it is; the title is its role |
| `instructions` | its system prompt |
| `provider` | `anthropic` (Claude), the id of a [ChatGPT, Grok or local provider](#local-and-hosted-models), or `rules`. Default: Claude when it is available, else the first provider with a default model, else rules |
| `model` | empty: the provider's default model |
| `permissions` | a subset of the [permissions](#permissions) below (default `read`) |
| `team`, `parent`, `depth` | see [Teams](#teams) |
| `schedule_minutes`, `task` | 0 (no schedule) or 5 to 525,600 minutes, and the standing task it runs then |
| `enabled` | a disabled agent is paused |

**Agents page** (admins): **New agent**, **Edit** and **Remove** (with confirmation). Each team agent shows a provider
badge (Claude, the provider's name, or Rules, amber when that provider cannot be used), its model, effective
permissions, a "not granted" badge for permissions its parent lacks, the schedule, the next and the last run. Viewers
and operators get a read-only details view.

Operators **chat** with any agent (the Hub Supervisor, the Patch Agent, the Operator, a module supervisor, a tool
supervisor, or a team agent). The chat panel has an agent selector and each agent keeps its own conversation. A
specialist does the work and reports it to the Hub Supervisor. With ChatGPT, Grok or a local model selected, a
maintenance request (a plan, a fix, a patch, or assembling AI teams) comes back as a cycle: the model writes the
plan, the supervisor dispatches each item, and the chat shows the handoff and that agent's report. **Stop** ends
the request that is running, and a new instruction stops it too. **New conversation** starts again. A down tool
(connection refused, a failed health check, or a stored error) is started, and the error is cleared once the check
passes. **Run** starts a team agent's standing task now, optionally with a one-off task.
A reply says whether it came from a model (`llm`), a local model (`local`), the team (`team`) or rules (`rules`).

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/agents` | viewer | every agent with its state; team agents with provider, effective permissions, team, schedule, last result and `outside_guardrails` |
| `GET /api/agents/teams` | viewer | agents grouped into teams with their lead, size and limit, pending proposal, suggested roles; the permission list, providers and limits |
| `POST /api/agents` | admin | create a team agent; the answer lists permissions that were not granted (`clamped`) |
| `PATCH /api/agents/{id}` | admin | team agents: any field; core agents: only `paused`, `model`, `instructions` |
| `DELETE /api/agents/{id}` | admin | remove a team agent (its members move to its parent; its pending proposals are withdrawn) |
| `POST /api/agents/{id}/chat` | operator | `{text, client_id?}` to any agent that chats |
| `POST /api/agents/{id}/chat/stop` | operator | stop the chat in progress (`{client_id}` matches the message) |
| `POST /api/agents/{id}/chat/reset` | operator | start a new conversation |
| `POST /api/agents/{id}/run` | operator | `{task?}`: run the standing task (or a one-off task) now |

### Permissions

| Permission | Lets an agent |
| --- | --- |
| `read` | read the hub's state: tools, assets, findings, risks, flows, approvals, people, extension records |
| `tool_api` | use a tool's own API through its connection (test it, read records) |
| `commands` | run commands through the Operator Agent (the command policy and approvals apply) |
| `patches` | ask the Patch Agent for patches and re-analysis (its approval flow applies) |
| `flows` | run and plan data flows, and request vulnerability scans |
| `assets_write` | change assets and their vulnerability-scan scope |
| `grc_write` | record and update risks, triage vulnerabilities, re-evaluate controls |
| `agents` | propose agent teams and team members (the guardrails apply) |

### The toolkit

Agents that run on a model act through a shared toolkit (`hub/agents/toolkit.py`). Every tool is tagged with the
permission it needs; a team agent only gets the tools its effective permissions allow, and an agent of a tool's team
can only act on that tool. Tools never bypass the hub: commands go through the Operator Agent, patches through the
Patch Agent's approval flow and scans through the Vulnerability Supervisor, always with the team agent as the sender
(`agent:<slug>`), so the command policy, the approval queue and the guardrails apply.

| Permission | Tools |
| --- | --- |
| `read` | `list_tools`, `get_tool`, `integration_overview`, `identity_overview`, `list_hosts`, `tool_health`, `asset_summary`, `people_summary`, `compliance_summary`, `data_flows`, `vulnerability_summary`, `list_vulnerabilities`, `list_risks`, `extension_records`, `list_approvals`, `agent_teams` |
| `tool_api` | `test_tool_connection`, `read_tool_records` |
| `commands` | `run_command`, `start_tool`, `stop_tool` (starting and stopping a tool wait for approval like a state-changing command) |
| `patches` | `import_tool`, `reanalyze_tool`, `propose_patches`, `request_code_patch` |
| `flows` | `run_flow`, `plan_flows`, `request_scan` |
| `assets_write` | `update_asset`, `set_scan_scope`, `sync_assets` |
| `grc_write` | `create_risk`, `update_risk`, `update_vulnerability`, `evaluate_controls` |
| `agents` | `ask_agent`, `propose_team`, `create_team_member` |

The Hub Supervisor's chat gets every tool. The Claude loop goes through `hub.llm.create`, so the default model
(`claude-opus-5-5`) and the hub's request options apply.

### Rules agents

An agent on `rules` runs deterministic template actions only: a health check of its tool, its team's data flows, and
a summary of the state. When a task needs a model (triage, analysis, recommendations), it says so instead: "I run on
rules, so I can only check health, run data flows and summarize the state." Team proposals give rules agents a
schedule only for roles that rules can do.

### Schedules

`Hub.tick_agents` runs in the same background loop as the data flows (every `HUB_FLOW_INTERVAL` seconds; off when
`start_background_tasks` is false). An enabled agent with a schedule and a standing task runs it one interval after
its last run (or its creation), as a message to itself, so a slow model never blocks the loop. An agent the guardrails
currently hold back (see `outside_guardrails`) is skipped.

## Teams

A team belongs to:

| Team | Id | Lead |
| --- | --- | --- |
| a tool | the tool id | its Tool Supervisor |
| the hub | `hub` | the Hub Supervisor |
| a built-in app | `module:assets`, `module:vulns`, `module:grc`, `module:people`, `module:extensions` | that app's supervisor |

Every team agent has a **parent**: the agent that created it or, for an agent a person creates, the team's lead (or
another agent of the same team the person picks). **Depth** counts levels below the core agents: a lead's members
have depth 1. While `limit_to_parent_permissions` is on, a member's effective permissions are its own clamped to its
parent's effective permissions, checked every time it acts, so narrowing a parent narrows its members at once.

**Agent teams** on the Agents page show one card per tool (plus the Hub team and built-in app teams that have members
or a pending proposal) with the tool's category, the size against the limit ("4 of 7"), the lead with its controls, and
**Propose team** (operator) or **Add** (admin; disabled when the team is full).

### Proposals

A Tool Supervisor proposes a team for its tool from **templates** keyed by what the tool is, or with **Claude**
(structured output) when it is available and a person asked for it:

| Category | Recognised by | Roles (permissions, schedule) |
| --- | --- | --- |
| SIEM / monitoring | e.g. Wazuh, Graylog, Splunk, Zabbix, Prometheus, Grafana, Uptime Kuma | alert triage analyst (`read`, `tool_api`, `grc_write`; hourly; needs a model), health watcher (`read`, `commands`; every 15 min) |
| GRC / compliance | CISO Assistant, eramba, SimpleRisk | compliance analyst (`read`, `tool_api`, `grc_write`, `flows`; daily; needs a model), evidence collector (`read`, `flows`, `grc_write`; daily) |
| Asset inventory | Snipe-IT, GLPI, NetBox | inventory reconciler (`read`, `tool_api`, `flows`, `assets_write`; every 6 h) |
| Vulnerability scanner | OpenVAS / Greenbone, Nessus, Trivy, ZAP | vulnerability triage analyst (`read`, `flows`, `grc_write`; daily; needs a model) |
| any tool | | maintainer (`read`, `commands`, `patches`; daily) |

The category comes from the tool's connection kind, its manifest capabilities, its name, its detected connector, and
the team templates of enabled [extension packs](#extensions) (which can add categories or roles).

The hub proposes a team by itself, once per tool and from the templates, when a tool gets a connection, when flows are
planned for a connected tool, and when a known complex tool (one of the categories above) is imported. Operators ask
for one with **Propose team** (`POST /api/tools/{id}/team {designer: auto | templates | claude}`), and team agents with
the `agents` permission can propose members of their own team (`create_team_member`) or ask their lead
(`propose_team`) - clamped to their own permissions while `limit_to_parent_permissions` is on.

A proposal is an approval of kind `agent_team` (team, lead, depth, members with their permissions, schedule and task,
how it was designed, the rationale, and who asked). Only administrators decide it, since it creates agent definitions
(operators may ask for one). Approving it creates the members, checked against the guardrails
as they are then. In autonomous mode, or with `team_requires_approval` off, the members are created at once.

## Local and hosted models

Team agents can run on any server with an OpenAI-compatible API (`hub/llm_providers.py`, collection
`llm_providers`). Add one under **Settings > AI providers** (admin).

The default is chosen under **Settings > AI model**: Claude, ChatGPT, Grok, a local provider, or rules, plus the
model name. New team agents use that provider. The Hub Supervisor's chat uses it too, and the chat badge names that
provider. With that model selected, a maintenance request is a cycle. The model returns a JSON plan (agent, goal,
priority). The supervisor dispatches up to six items and the chat shows each handoff: the GRC Supervisor evaluates
controls, the Asset Supervisor summarizes assets, a tool supervisor assembles its template team when the request
asks for a team or for the installed software, and the Patch Agent starts a down tool or files a patch. If the
selected model does not answer, the same plan is built from the suite and the work still runs. Without a model, a
message about a fix, a bug, a patch or an error still goes to each tool's supervisor and then to the Patch Agent
(up to five tools). When the tool is down — connection refused, a failed health check, or a stored error — the
Patch Agent starts it and clears the error once the check passes. A Python project on disk with no launch command is
installed into an adapter environment and served from there; the tool's own repository is not changed. A patch is
filed only when the tool cannot be started. You can talk to
the Patch Agent, the Operator, a module supervisor or a tool supervisor directly; they do the work and report it to
the Hub Supervisor. **Stop** ends the request that is running, and **New conversation** starts again. Code patches, extension packs
and self-patches still call Claude, and they stay on rules when no Claude key is set. The home page says agents are
in rules mode only when nothing can plan: a selected ChatGPT, Grok or local provider (a hosted one needs its API key)
is enough, and that notice does not ask for `ANTHROPIC_API_KEY`. A team agent can still name
its own provider and model.

**ChatGPT** and **Grok** are presets. ChatGPT calls `https://api.openai.com/v1` and starts on `gpt-5.6-terra`. Grok
calls `https://api.x.ai/v1` and starts on `grok-4.7`. Both need an API key. Those defaults were taken from the
vendors' docs in October 2026; **Test** lists the models the key can actually call, and you can pick another.

A local server takes a name, base URL (default `http://localhost:11434/v1`, Ollama's), default model, optional API key,
tool calling on or off, and a timeout (default 300 seconds). **Test** lists the server's models
(`GET {base_url}/models`); the agent loop sends `POST {base_url}/chat/completions` with `tools` (at most 12 turns)
and never `tool_choice`. The same call is used for ChatGPT and Grok.

| Server | Base URL | Tool calling |
| --- | --- | --- |
| ChatGPT (OpenAI) | `https://api.openai.com/v1` | supported; an API key is required |
| Grok (xAI) | `https://api.x.ai/v1` | supported on Chat Completions; an API key is required |
| Ollama | `http://localhost:11434/v1` | supported on `/v1/chat/completions`; `tool_choice` is not; the API key is ignored locally |
| LM Studio | `http://localhost:1234/v1` | supported (`tools` on `/v1/chat/completions`) |
| vLLM | `http://<host>:8000/v1` | needs `--enable-auto-tool-choice` and a `--tool-call-parser` for the model |
| llama.cpp `llama-server` | `http://<host>:<port>/v1` | needs `--jinja` |

These details were checked against the vendors' documentation in October 2026. Current llama.cpp documentation gives
`llama-server`'s default port as 9931 (its Docker examples use 8080), so use the port you started it on. A model or
server without tool calling answers with an error or ignores the tools: switch the provider's **tools** option off and
its agents answer in plain text.

The API key is encrypted with the hub's secret key ([INTEGRATIONS.md](INTEGRATIONS.md#credentials-and-the-secret-key)),
never returned or logged, only sent to the endpoint it was entered for, and redirects are not followed. Moving the
base URL to another address while a key is stored means entering the key again. A provider that agents still use
cannot be removed.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/llm/providers` | viewer | providers (keys only as "set"), presets (ChatGPT, Grok), the provider choices for agents, Claude's status |
| `POST /api/llm/providers` | admin | add one |
| `PATCH /api/llm/providers/{id}` | admin | change it; an empty `api_key` keeps the stored one, `clear_api_key` removes it |
| `DELETE /api/llm/providers/{id}` | admin | remove it (409 while agents use it) |
| `POST /api/llm/providers/{id}/test` | admin | list its models |

## Guardrails

Guardrails are safety switches and limits for the agents, in **Settings > Agent guardrails** (admins; `hub/guardrails.py`,
preference `guardrails`). Each shows what it protects against, the compliance control it affects, and a "relaxed" badge
when loosened. Relaxing one (switching a protection off, allowing nested teams, raising a limit) first shows the risk and
asks for confirmation; tightening applies at once. Every change is written to the activity log with the actor -
relaxing as a warning - and the GRC Supervisor re-evaluates the controls.

| Guardrail | Default | Effect | Relaxed |
| --- | --- | --- | --- |
| `limit_to_parent_permissions` | on | team agents never exceed their parent's effective permissions | HB-AC-6 fails |
| `allow_nested_teams` / `max_team_depth` | off / 1 | whether team agents may have members of their own, and how deep (1-5) | HB-AC-6 partial |
| `limit_team_size` / `max_team_size` | on / 5 | team agents per team (1-50); lowering it holds back a team's newest members until it shrinks | off: HB-AC-6 partial |
| `team_actions_need_approval` | on | team agents' commands and patches follow the autonomy level; off = they act without approval | HB-AC-6 fails |
| `block_catastrophic_commands` | on | blocked command patterns are refused for everyone; off = they become `change` commands | HB-AC-6 fails |
| `scans_need_approval` | on | scheduled and agent-started scans wait for approval (unless the hub is autonomous) | HB-AC-2 partial |
| `team_requires_approval` | on | team proposals wait for approval (unless the hub is autonomous) | HB-AC-2 partial |
| `allow_extensions` | on | extension packs can be active and proposed; off: none is | (off is the safe side) |
| `extensions_need_approval` | on | packs the Patch Agent generates wait for approval | HB-CM-2 partial |
| `allow_self_patching` | on | the Patch Agent may propose changes to Atrium's own code; off: it never does | (off is the safe side) |
| `self_patch_requires_tests` | on | a self-patch can only be approved when the test suite passed on its branch | HB-CM-2 fails |
| `self_patch_requires_approval` | on | self-patches wait for an administrator's approval | HB-CM-2 fails |
| `self_patch_via_pull_request` | on | an approved self-patch is opened as a pull request instead of merged locally | |

For `allow_extensions` and `allow_self_patching` off is the protective position, so switching them back on is logged
as relaxing (a warning). When `max_team_size` is lowered below a team's size, the team's oldest members keep acting and
the newest ones may not act (chat, runs and the scheduler refuse them) until the team shrinks or the limit is raised;
the agent's `outside_guardrails` says why.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/settings` | viewer | includes `guardrails` (values) and `guardrail_catalog` (title, description, group, default, value, risk, control, bounds, relaxed) |
| `PATCH /api/settings/guardrails` | admin | `{key: value, ...}`; 400 for an unknown key, a wrong type or an out-of-range value (nothing is stored) |

`PATCH /api/settings {guardrails: {...}}` (admin) does the same. A later feature adds a guardrail with
`guardrails.register(Guardrail(..., control="HB-...", weakens="fail" | "partial", finding="..."))`; the settings screen,
validation, logging and the compliance check pick it up.

### Compliance effect

| Control | Fails when | Partial when |
| --- | --- | --- |
| HB-AC-2 Privileged agent actions are approved | the hub runs in autonomous mode | `scans_need_approval` or `team_requires_approval` is off |
| HB-AC-6 AI agent guardrails are enforced | `block_catastrophic_commands`, `team_actions_need_approval` or `limit_to_parent_permissions` is off | team size is unlimited or nested teams are allowed |
| HB-CM-2 Changes to tools are reviewed | `self_patch_requires_approval` or `self_patch_requires_tests` is off | `extensions_need_approval` is off, or the hub runs in autonomous mode |

HB-AC-6 maps to ISO 27001 A.8.2 / A.8.32, SOC 2 CC6.1 / CC8.1, NIS2 21(2)(i), with the risk "AI agents operate
without guardrails" (3 x 5). HB-CM-2 maps to ISO 27001 A.8.32, SOC 2 CC8.1, NIS2 21(2)(e).

## Extensions

When a new tool brings data or a sign-in method Atrium does not know, Atrium can extend itself at two levels: an
**extension pack** (data only, preferred) and, when a pack cannot express it, a **self-patch** of its own code.

### What a pack can contain

A pack is JSON (`hub/extensions/pack.py`): `id` (2-48 lowercase letters, digits and dashes), `name`, `version`,
`description`, `source_tool` (the tool it was made for) and `items`. Nothing in a pack is ever executed or evaluated
as code.

| Item kind | Adds |
| --- | --- |
| `domain` | a data type, e.g. alerts from a SIEM or tickets from a service desk: key, title, icon, fields (`text`, `number`, `date`, `severity`, `link`, `enum` with values), title field, and link rules (an asset by an address or hostname field, a person by an email or login field) |
| `connector` | a generic REST mapping for a tool ([INTEGRATIONS.md](INTEGRATIONS.md#generic-rest)), which may map the new domain as `x:<key>` |
| `sso` | a single sign-on recipe for tools the built-in catalog does not know: name match, protocol (`oidc` or `saml`), callback path, the file it writes under `sso/`, and a template |
| `controls` | rules that count matching records of a domain and rate a compliance control |
| `team` | an agent-team template for a kind of tool: a category, how to recognise it, and up to six roles |

```json
{
  "id": "wazuh-alerts", "name": "Alerts from Wazuh", "version": "1.0.0", "source_tool": "wazuh",
  "items": [
    {"kind": "domain", "key": "alerts", "title": "Alerts", "singular": "Alert", "icon": "bell",
     "fields": [{"name": "title", "label": "Title", "required": true},
                {"name": "severity", "label": "Severity", "type": "severity"},
                {"name": "status", "label": "Status", "type": "enum", "values": ["open", "closed"]},
                {"name": "host", "label": "Host"}, {"name": "detected", "label": "Detected", "type": "date"}],
     "title_field": "title", "links": [{"target": "asset", "field": "host"}]},
    {"kind": "controls", "rules": [
      {"control": "HB-IR-1", "domain": "alerts", "title": "Critical alerts open for more than 7 days",
       "where": [{"field": "severity", "op": "eq", "value": "critical"}, {"field": "status", "op": "ne", "value": "closed"}],
       "age_field": "detected", "older_than_days": 7, "fail_above": 0}]}
  ]
}
```

Control rules: conditions use `eq`, `ne`, `in`, `not_in`, `gte`, `lte`, `empty`, `not_empty`; more than `fail_above`
matching records fail the control, more than `partial_above` make it partial. The control gets the worse of its own
check and the rules, and each rule adds a line of evidence; a control the hub cannot check itself is only changed by a
rule that finds a problem. Records a tool stopped reporting (stale) are never counted.

SSO templates are filled by plain text substitution of `{url}`, `{issuer}`, `{discovery}`, `{client_id}`,
`{client_secret}`, `{provider_name}`, `{scopes}`, `{redirect_uri}`, `{authorize_endpoint}`, `{token_endpoint}`,
`{userinfo_endpoint}` and `{tool_name}`; the client secret only ever appears as the placeholder the hub fills when it
writes the adapter files. In team roles, `{tool}` becomes the tool's name.

**Validation.** Packs are parsed by strict models: unknown keys and item kinds are rejected, values are not coerced,
and so are control characters, `javascript:` and other non-http(s) URLs, URLs with credentials, mapping paths that are
absolute, point elsewhere or contain `..`, SSO files outside `sso/`, unknown control ids, permissions outside the
agent permission list, credential-looking query parameters in a mapping (credentials belong in the tool's connection),
built-in domain names as keys, and packs over 512 KB.

### Lifecycle

**Extensions** (`#/extensions`; admins manage, everyone else reads) lists the packs with what they add, which tool
connections they changed, notes, every version and the history, the JSON with a download, and **Upload pack** (from a
file or pasted JSON, optionally enabled at once).

- **Versions**: every version is kept. Uploading a new version of an enabled pack makes it active at once; **Roll back**
  (or **Make current** on a version) switches back.
- **Enable / disable** takes effect in the running process, without a restart. Enabling checks the pack against the
  other enabled packs: one owner per domain key and SSO recipe, and every domain its mappings and rules use must
  exist.
- **Connector items** are merged into the tool's generic REST connection when the pack is enabled, creating one when
  the tool has none (an admin then enters the credentials in the tool's Connection tab). A tool with a built-in
  connector keeps it, and an existing connection keeps its base URL. Disabling restores each domain's previous mapping,
  removes the flows of dropped domains, and removes a connection the pack created if nothing else is left in it. A
  connection that holds credentials stays, without the pack's domains (it reads nothing until a domain is mapped again).
- **Remove** deletes the pack; optionally also the records of its domains that no other enabled pack defines (enabled
  packs count while `allow_extensions` is off too).
- **`allow_extensions` off** makes every pack inactive at once: their apps leave the sidebar, their flows refuse to
  run, and their recipes, rules and team templates stop applying. Packs and records are kept, and mappings already
  merged into connections stay until a pack is disabled.

### Extension apps and their records

Every enabled domain becomes an app (`#/x/<key>`) in the sidebar group **Extensions**, in Portals and in Ctrl K, with a
table (severity tiles, search, source and stale filters) and a record page. Records live in the collection
`x:<key>`, typed by the domain's fields (a `link` must be http or https; an `enum` value also matches whole words, so
"2 normal" becomes `normal`; `severity` accepts words and 0-10 scores read as CVSS). They link automatically to an
asset by an address or hostname field and to a person by an email or login field; links set by hand stick until
someone sets them back to automatic. Operators add, edit and remove records.

Connectors pull and push `x:<key>` like a built-in domain. The planner proposes a pull flow for a tool that reads an
enabled domain (a push for one that only writes it), and the Extensions Supervisor runs them: unchanged records are
skipped, and records a tool stops reporting are kept as stale. A pull overwrites fields edited by hand when the tool's
record changes. Agents read the records with the `extension_records` tool.

### Generated packs

After an import, the Hub Supervisor looks for **hub-side gaps** - things Atrium itself lacks for the tool, once per
tool:

| Gap | When |
| --- | --- |
| `domain` | the tool's main data has no home in Atrium: a SIEM's alerts, a service desk's tickets, a monitoring tool's incidents |
| `connector` | no built-in connector and no connection, or a generic REST connection that does not map the domain. A REST API can be mapped; GraphQL, gRPC or no API needs code |
| `sso` | the tool signs in with OIDC or SAML in a way the SSO catalog does not know |

It asks the Patch Agent to extend Atrium. With Claude, the Patch Agent writes the pack with structured output, and it
is validated like an upload (a connector item always maps the tool itself, and its base URL is pinned to the tool's
known API address - the OpenAPI document's, the manifest's or the SaaS URL; with none known, it carries no base URL and
an admin sets the connection up). Without Claude, or if
Claude's answer is unusable, it uses templates:

| Kind | Domain | Template control rules | Template connector |
| --- | --- | --- | --- |
| SIEM (Wazuh, Graylog, Splunk, Security Onion, ...) | `alerts` | HB-IR-1: open critical alerts older than 7 days fail it, open high ones make it partial | none |
| Service desk (Zammad, osTicket, FreeScout, GLPI, ...) | `tickets` | none | Zammad: `GET /api/v1/tickets?expand=true`, `page` / `per_page`, `Authorization: Token token=<token>` |
| Monitoring (Alertmanager, Zabbix, Nagios, Uptime Kuma, ...) | `incidents` | HB-OP-1: critical incidents unresolved for more than a day fail it, any unresolved for more than 7 days make it partial | Prometheus Alertmanager: `GET /api/v2/alerts` |

Each template also brings a team role (alert reviewer, ticket triage, incident watcher). The Zammad and Alertmanager
mappings were checked against their official documentation; **unverified**: that Zammad expands the ticket's owner
and group to names with `expand=true` (otherwise those fields stay empty). Wazuh gets no connector template: its alerts
live in the indexer behind a search request a GET-based mapping cannot express.

The result is an approval of kind `extension` with a preview of the pack. Only administrators decide it (others get
403); approving enables the pack. With `extensions_need_approval` off, a generated pack is enabled at once (HB-CM-2 goes
partial). Admins can also ask for an extension with **Extend Atrium** on a tool's page or in the Extensions page's
**Gaps** tab (`POST /api/tools/{id}/extend`).

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/extensions` | viewer | packs, extension domains, gaps per tool, guardrails, self-patching availability, `restart_required` |
| `GET /api/extensions/{id}` | viewer | a pack with its JSON, every version and the history |
| `POST /api/extensions?enable=false` | admin | upload a pack (a new version of an existing id adds that version); 400 with the validation errors |
| `PATCH /api/extensions/{id}` | admin | `{status: enabled or disabled}`; enabling a proposed pack approves its approval |
| `POST /api/extensions/{id}/rollback` | admin | `{version?}`: default the version before the current one |
| `DELETE /api/extensions/{id}?purge=false` | admin | remove the pack (and with `purge`, its records) |
| `POST /api/tools/{id}/extend` | admin | `{designer: auto, templates or claude}`: close the tool's hub-side gaps |
| `GET /api/x` | viewer | the enabled extension domains |
| `GET /api/x/{key}` | viewer | records, with `q`, `asset_id`, `person_id`, `source`, `stale`, `limit` |
| `POST /api/x/{key}` | operator | `{fields, asset_id?, person_id?}`: add a record |
| `GET /api/x/{key}/{id}` | viewer | a record with its domain definition |
| `PATCH /api/x/{key}/{id}` | operator | `{fields?, asset_id?, person_id?, relink?}` |
| `DELETE /api/x/{key}/{id}` | operator | remove a record |

## Self-patching

When an extension cannot express what a tool needs - a GraphQL or gRPC API, or Claude says code is needed - the Patch
Agent can propose a change to **Atrium's own repository**. Admins can also ask for one directly (**Ask for a change** in
the Extensions page's **Self-patches** tab).

Requirements: the guardrail `allow_self_patching` is on, Claude is available (`ANTHROPIC_API_KEY`), and Atrium runs
from a **git checkout**. An install with `install.sh` / `install.ps1` in the repository folder qualifies; a copy made
with `--install-dir` / `-InstallDir` and the Docker image do not (they have no `.git`). `HUB_SELF_PATCH=off` turns the
detection of the checkout off; the test suite sets it.

How it works (`hub/extensions/selfpatch.py`):

1. Claude writes the change (structured output; it may only rewrite files of Atrium it was shown).
2. The paths are checked: inside the repository, never `.git`, `.env*`, `.hub*`, `.venv` / `venv` or the data
   directory, never through a symbolic link; at most 20 files. A change containing a secret value the hub knows is
   refused.
3. The change is committed on a new branch `atrium/self-<id>` in a git worktree under
   `workspace/self-patches/<id>`. Your checkout is not touched.
4. Atrium's test suite runs in the worktree with the current Python (`pytest -q -x`, 30-minute timeout), in an
   environment without the hub's settings and credentials (`HUB_*`, `ANTHROPIC_*`, `GH_*`, `GITHUB_*` and
   secret-looking variables removed; `HUB_LLM=off`). The diff and the tail of the test output are attached.
5. An approval of kind `self_patch` shows the diff, the files, the test result and how it will be applied. Only
   administrators decide it, and while `self_patch_requires_tests` is on a patch whose tests failed cannot be approved
   (409). Rejecting removes the branch and the worktree.
6. On approval:
   - **Pull request**, when `self_patch_via_pull_request` is on, the repository has an `origin` remote and the GitHub
     CLI is signed in (`gh auth status`): the branch is pushed and `gh pr create` opens a pull request. This outward
     action only ever follows a person's approval.
   - **Merge** otherwise: the branch is merged into the current branch, only when there are no uncommitted changes to
     tracked files and a branch (not a detached HEAD) is checked out. Atrium then shows **Restart required** until it
     is restarted: Python code loads at the next start, while the UI files in `hub/web` change at once. If the merge is
     refused, the patch stays approved and **Apply again** retries it.

With `self_patch_requires_approval` off, a change that would be merged locally and whose tests passed is applied at
once (HB-CM-2 fails); a pull request always waits for a person.

**Remaining risk**: the tests of a Claude-written change run before anyone approves it, as the same operating-system
user as Atrium. Their environment holds no credentials, but files stay readable (the data directory with
`secret.key` and `hub.db`, the user's home) and the network is not blocked. Real isolation needs a sandbox (a
container or a separate user). Switch `allow_self_patching` off if that is not acceptable.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/self-patches` | viewer | patches (without diff), `restart_required`, whether self-patching is possible now |
| `GET /api/self-patches/{id}` | viewer | one patch with its diff and test result |
| `POST /api/self-patches` | admin | `{goal, tool_id?}`: ask the Patch Agent for a change (202) |
| `POST /api/self-patches/{id}/apply` | admin | apply an approved patch again |

`GET /api/overview` reports `restart_required`, and the event stream sends `restart_required` when a self-patch is
merged; the UI shows a banner.
