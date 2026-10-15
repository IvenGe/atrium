# Agents, teams and extensions

Atrium's work is done by agents that talk to each other on the message bus ([ARCHITECTURE.md](ARCHITECTURE.md#the-agent-bus)).
This page covers the agents, the agent teams people and agents build, the model providers they run on, the guardrails
that bound them, and how Atrium extends and patches itself when a new tool needs it.

## Core agents

| Agent | Id | Permissions | Responsibilities |
| --- | --- | --- | --- |
| Hub Supervisor | `supervisor` | all | imports tools, scores the suite, sends gaps to the Patch Agent, plans data flows, health sweeps, chat |
| Tool Supervisor | `tool:<id>` | all | one per tool: analysis, health, start/stop, the tool's connector (the only agent that decrypts its credentials), lead of the tool's team, managing director of its [subsidiary](#subsidiary-staff) |
| Patch Agent | `patcher` | `read`, `patches` | patches to tools, flow repairs, generated connectors, extension packs, self-patches and subsidiaries' bridge patches |
| Operator Agent | `operator` | `read`, `commands` | commands on this machine or over SSH, under the command policy |
| Asset Supervisor | `module:assets` | `read`, `tool_api`, `flows`, `assets_write`, `agents` | the asset register and asset flows |
| Vulnerability Supervisor | `module:vulns` | `read`, `tool_api`, `flows`, `assets_write`, `grc_write`, `agents` | scans, findings, deadlines, vulnerability flows |
| GRC Supervisor | `module:grc` | `read`, `tool_api`, `flows`, `grc_write`, `agents` | controls, evidence, risks, GRC flows, frameworks read from GRC tools and the self-assessment push ([COMPLIANCE.md](COMPLIANCE.md)) |
| People Supervisor | `module:people` | `read`, `tool_api`, `flows`, `assets_write`, `agents` | the People app, people and accounts flows, leavers ([PEOPLE.md](PEOPLE.md)) |
| Extensions Supervisor | `module:extensions` | `read`, `tool_api`, `flows`, `agents` | the apps extension packs add and their flows ([below](#extensions)) |
| Network Supervisor | `module:network` | `read`, `tool_api`, `flows`, `grc_write` | the Network app: device reads, snapshots, drift, backups, the segmentation map's data; the only agent that applies approved device changes ([NETWORK.md](NETWORK.md)) |

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
| `provider` | `""` (the default: the hub's [model choice](#models-and-providers), resolved at every call), `anthropic` (Claude), `openai`, the id of an [Azure OpenAI resource](#openai-and-azure-openai) or a [local model provider](#local-models), or `rules` |
| `model` | empty: the provider's default model |
| `permissions` | a subset of the [permissions](#permissions) below (default `read`) |
| `team`, `parent`, `depth` | see [Teams](#teams) |
| `schedule_minutes`, `task` | 0 (no schedule) or 5 to 525,600 minutes, and the standing task it runs then |
| `enabled` | a disabled agent is paused |
| `placement` | `hub` (the default) or `sidecar`: a [subsidiary's staff](#subsidiary-staff), set only by an approved charter |

**Agents page** (admins): **New agent** (name, role, description, team, reporting line and permissions; its settings
page opens next for the rest) and **Remove** (with confirmation); the sliders icon opens an agent's
[settings page](#agent-settings), where everything else is edited (viewers and operators read it). Each team agent
shows a model badge (amber when no model can run; its tooltip says where the model comes from and which levels were
skipped, see [Models and providers](#models-and-providers)), a "budget reached" badge while a budget of it is reached,
effective permissions, a "not granted" badge for permissions its parent lacks, the schedule, the next and the last run.
Core agents have **Pause** / **Resume** and **Settings**. A subsidiary's staff carry a "works inside {tool}" badge, a
"Held" reason while their subsidiary is not active, and a link to its charter instead of **Remove**.

Operators **chat** with any team agent (the chat panel has an agent selector; each agent keeps a separate conversation
with each person - see [Chat memory and privacy](#chat-memory-and-privacy)) and **run** its standing task now,
optionally with a one-off task. A reply says whether it came from a cloud model (`llm`), a local model (`local`) or
rules (`rules`).

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/agents` | viewer | every agent with its state; team agents with provider, effective permissions, team, schedule, last result and `outside_guardrails` |
| `GET /api/agents/teams` | viewer | agents grouped into teams with their lead, size and limit, pending proposal, suggested roles; the permission list, providers and limits |
| `POST /api/agents` | admin | create a team agent; the answer lists permissions that were not granted (`clamped`) |
| `PATCH /api/agents/{id}` | admin | team agents: any field; core agents: only `paused`, `model`, `instructions` |
| `DELETE /api/agents/{id}` | admin | remove a team agent (its members move to its parent; its pending proposals are withdrawn) |
| `POST /api/agents/{id}/chat` | operator | `{text}`; the Hub Supervisor or a team agent |
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
| `tool_actions` | work inside the team's own tool through its Atrium bridge or sidecar, within the charter (changes wait for approval); only a [subsidiary's staff](#subsidiary-staff) use it |

### The toolkit

Agents that run on a model act through a shared toolkit (`hub/agents/toolkit.py`). Every tool is tagged with the
permission it needs; a team agent only gets the tools its effective permissions allow, and an agent of a tool's team
can only act on that tool. That covers the hub's records too. Such an agent may change, with `update_risk`,
`update_asset`, `set_scan_scope` and `update_vulnerability`, only the records its tool supplied (`source`
`sync:<tool>`, `tool:<tool>` or the tool id) and the risks an agent of its own team recorded. Anything else is
refused with a permission error, including people's entries, automatic risks and other teams' records. A scan-scope
change touching one such asset changes nothing at all. Agents of the hub's or a module's team keep hub-wide reach.
Tools never bypass the hub: commands go through the Operator Agent, patches through the
Patch Agent's approval flow and scans through the Vulnerability Supervisor, always with the team agent as the sender
(`agent:<slug>`), so the command policy, the approval queue and the guardrails apply. When an agent acts on a person's
chat message or manual run, its commands on the hub machine and tool starts are judged by that person's role: an
operator's wait for an administrator even in autonomous mode ([AUTH.md](AUTH.md#commands-on-the-hub-machine)).

| Permission | Tools |
| --- | --- |
| `read` | `list_tools`, `get_tool`, `integration_overview`, `identity_overview`, `list_hosts`, `tool_health`, `asset_summary`, `people_summary`, `network_summary`, `compliance_summary`, `data_flows`, `vulnerability_summary`, `list_vulnerabilities`, `list_risks`, `extension_records`, `list_approvals`, `agent_teams`, `subsidiary_summary` (the subsidiaries' statuses, flags and counts - never text from the tools), `escalate` (asks a person, see [Escalation and notifications](#escalation-and-notifications)) |
| `tool_api` | `test_tool_connection`, `read_tool_records` |
| `commands` | `run_command`, `start_tool`, `stop_tool` (starting and stopping a tool wait for approval like a state-changing command) |
| `patches` | `import_tool`, `reanalyze_tool`, `propose_patches`, `request_code_patch` |
| `flows` | `run_flow`, `plan_flows`, `request_scan` |
| `assets_write` | `update_asset`, `set_scan_scope`, `sync_assets` |
| `grc_write` | `create_risk`, `update_risk`, `update_vulnerability`, `evaluate_controls` |
| `agents` | `propose_team`, `create_team_member` |

Every tool call is checked against the tool's schema by the hub before it runs (types and allowed values; unknown
keys are dropped), not only by the model provider: local models get no strict schemas. `read_tool_records` reads
only assets, vulnerabilities, risks, controls, people and accounts.

`network_summary` returns counts only: devices, devices without a current snapshot, unexplained drift, and devices
that accept changes now. Text read from devices (rule descriptions, interface and zone names) never reaches an agent
or a model: `read_tool_records` cannot read the `network` domain and a tool's supervisor answers a `network` pull only
to the Network Supervisor. No agent tool changes a network device: device changes are proposed by people only and approved by an
administrator ([NETWORK.md](NETWORK.md#device-changes)). Likewise, team agents and other modules cannot start a scan
through a tool's connector; scans go through the Vulnerability Supervisor (`request_scan`) and its approval policy.

The Hub Supervisor's chat gets every tool. The conversation runs through the provider layer (`hub.llm.converse`,
[Models and providers](#models-and-providers)) on whatever model the agent resolves to; the tools of one round run
concurrently and at most 12 rounds run per message.

### Rules agents

An agent on `rules` runs deterministic template actions only: a health check of its tool, its team's data flows, and
a summary of the state. When a task needs a model (triage, analysis, recommendations), it says so instead: "I run on
rules, so I can only check health, run data flows and summarize the state." Team proposals give rules agents a
schedule only for roles that rules can do.

### Schedules

`Hub.tick_agents` runs in the same background loop as the data flows (every `HUB_FLOW_INTERVAL` seconds; off when
`start_background_tasks` is false). An enabled agent with a schedule and a standing task runs it one interval after
its last run (or its creation), as a message to itself, so a slow model never blocks the loop. An agent the guardrails
currently hold back (see `outside_guardrails`) is skipped, and so is an agent whose schedule was paused after failed
runs in a row (`schedule_paused`, [Escalation and notifications](#escalation-and-notifications)) until an
administrator resumes it.

## Teams

A team belongs to:

| Team | Id | Lead |
| --- | --- | --- |
| a tool | the tool id | its Tool Supervisor |
| the hub | `hub` | the Hub Supervisor |
| a built-in app | `module:assets`, `module:vulns`, `module:grc`, `module:people`, `module:extensions`, `module:network` | that app's supervisor |

Every team agent has a **parent**: the agent that created it or, for an agent a person creates, the team's lead (or
another agent of the same team the person picks). **Depth** counts levels below the core agents: a lead's members
have depth 1. While `limit_to_parent_permissions` is on, a member's effective permissions are its own clamped to its
parent's effective permissions, checked every time it acts, so narrowing a parent narrows its members at once.

**Agent teams** on the Agents page show one card per tool (plus the Hub team and built-in app teams that have members
or a pending proposal) with the tool's category, the size against the limit ("4 of 7"), the lead with its controls, and
**Propose team** (operator) or **Add** (admin; disabled when the team is full).

### Proposals

A Tool Supervisor proposes a team for its tool from **templates** keyed by what the tool is, or with **the AI model**
(structured output) when one is available and a person asked for it. Proposed members inherit the hub's model choice
(`provider: ""`); the approval records which model designed the team (`generated_by`):

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
for one with **Propose team** (`POST /api/tools/{id}/team {designer: auto | templates | model}`; `claude` is accepted
for `model`), and team agents with
the `agents` permission can propose members of their own team (`create_team_member`) or ask their lead
(`propose_team`) - clamped to their own permissions while `limit_to_parent_permissions` is on.

A proposal is an approval of kind `agent_team` (team, lead, depth, members with their permissions, schedule and task,
how it was designed, the rationale, and who asked). Only administrators decide it, since it creates agent definitions
(operators may ask for one). Approving it creates the members, checked against the guardrails
as they are then. In autonomous mode, or with `team_requires_approval` off, the members are created at once.

### Subsidiary staff

A tool's team can also work *inside* the tool, as a **subsidiary** ([SUBSIDIARIES.md](SUBSIDIARIES.md)): its staff
run in a sidecar next to the tool and act through an Atrium bridge in the tool's code (or its API connection), and the
Tool Supervisor is their managing director. They are team agents of the tool's team with `placement="sidecar"`:

- **Only an approved charter creates them** (approval kind `subsidiary_charter`, decided by an administrator in person),
  never `POST /api/agents`, whatever the autonomy level or `team_requires_approval`; the team size limit and the
  parent clamp apply. Their team, parent and placement never change outside the charter, which also sets the actions
  each may use; members a narrower charter removes are disabled, never deleted.
- **Two roles**, offered only for sidecar staff: a **front desk** (`read`, `tool_actions`; answers the tool users'
  "Ask the team" questions with read and draft actions, escalates the rest) and a **clerk** (`read`, `tool_actions`; a
  standing task every 4 hours; its changes wait for approval). An AI model may design them instead, within the tool's
  catalog.
- **Permissions** are clamped to `read`, `tool_actions` and `patches`, on top of the parent clamp. Their hub-side
  requests always wait for a person (`guardrails.effective_autonomy` answers `manual`), even on an autonomous hub and
  with `team_actions_need_approval` off.
- **Their hub tools** are a relay of five, those the charter gives each member: `get_tool`, `tool_health`,
  `data_flows`, `propose_patches` and `request_code_patch`, always for their own tool (`tool_id` is forced), never
  from a tool user's question. A code patch they ask for is refused for the bridge's own files, and its goal reaches
  the model as untrusted text.
- **They run in the sidecar.** The scheduler, **Run now** and chat reach them through a `SubsidiaryAgent` proxy that
  posts the run to the sidecar and records the reply (plain text, "Written by the subsidiary team (untrusted)"); chat
  answers 503 while the sidecar is offline. Their model calls come back to Atrium's model gateway, which composes every
  prompt and tool list itself, runs them through the provider layer (purpose chat, effort medium, at most 8,000 output
  tokens) on a provider the charter allows, and books the charter's budgets on top of the agent's own.
- **Held** (`outside_guardrails`) while their subsidiary is not active or `allow_subsidiaries` is off: the scheduler,
  chat and runs refuse them without changing their definition.

## Models and providers

Every model call goes through the provider layer `hub/llm/` (the gateway `hub.llm`): the Hub Supervisor's chat, team
agents' chats and runs, the Patch Agent's code patches, connector mappings, repairs, extension packs and self-patches,
and the Tool Supervisors' analysis and team designs. The providers:

- **Claude**, the built-in provider `anthropic` (Anthropic SDK: `pip install "atrium[ai]"`). Credentials from the
  environment win (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, an `ant auth login` profile); otherwise an administrator
  can store a key on the provider (`PATCH /api/llm/providers/anthropic {api_key}`): encrypted, never returned, and only
  ever sent to `https://api.anthropic.com`. The built-in provider cannot be removed (remove its key instead).
  `HUB_LLM=off` switches the cloud providers off; local providers keep working. Its default model is set on its card
  under **Settings > AI providers** (empty: `HUB_MODEL`, default `claude-opus-5-5`).
- **[OpenAI and Azure OpenAI](#openai-and-azure-openai)** ("ChatGPT models"), on the Responses API.
- **[Local models](#local-models)**: servers with an OpenAI-compatible API.
- **Rules**: deterministic, always there, the last resort.

Code that calls a model goes through the gateway with the agent's id and the purpose: `hub.llm.converse(...)` for a
conversation with tools, `hub.llm.json(...)` for a structured answer (`hub.llm.ready(agent_id, purpose)` says whether a
model can take it). The Anthropic-shaped `hub.llm.create` and `toolkit.claude_loop` / `local_loop` of earlier versions,
and the old names `claude_pack`, `claude_self_patch` and `design_with_claude`, are gone.

**Secrets never reach a model.** Every secret the hub holds (tool connections, provider keys, the SSO client secret,
credential-looking environment variables, ...) is masked in everything sent to any provider, local ones included: the
system prompt, messages, tool results and tool-call arguments - as written and as JSON spells it inside a string
(escaped quotes, backslashes and non-ASCII characters). A tool's result is masked before it is turned into JSON and
cut at 20,000 characters, so a cut never leaves half a secret. Provider error texts never quote a provider's answer
and pass through the same mask before they reach a chat, the activity log or the event stream.

Every provider has a card under **Settings > AI providers** (`#/settings/ai`): its kind, whether it runs in the cloud or
on your own hardware, its status (connected, not connected, key from the environment, switched off,
off (`HUB_LLM=off`), failing), where its key comes from (never the key), its default model, its models with what each
supports ("tools", "JSON", the effort levels, the output limit, "deprecated - retires ..."), its last test, and - for
administrators - **Test**, **Edit**, **Remove** (not the built-in ones) and **Check tools and JSON** per model.
**Add provider** offers a local model server, an Azure OpenAI resource or another OpenAI-compatible cloud service.
Viewers and operators see the cards without key fields or buttons. A cloud provider is a supplier: its card shows who
owns that relationship and when its terms (data processing agreement) were last reviewed, set in its Edit dialog
(`PATCH /api/llm/providers/{id} {supplier: {owner, reviewed_at, notes}}`, logged as "supplier owner j.doe, terms
reviewed 2026-09-30"); compliance control HB-SC-1 counts the cloud providers agents use
([COMPLIANCE.md](COMPLIANCE.md)).

### How a model is chosen

Per agent and purpose (`hub/llm/resolve.py`), the first level that is set and usable wins:

1. the agent's own choice for that task (the Patch Agent: code changes and structured generation separately),
2. the agent's own choice: provider and model on its settings page (a team agent's `provider`/`model`; a core
   agent's model override, `PATCH /api/agents/{id} {model}`, is a Claude model unless it chose another provider),
3. its team's default (team agents, and a tool team's Tool Supervisor - not the Hub Supervisor or the built-in apps'
   supervisors),
4. the default for the purpose (chat, code changes, structured generation),
5. the suite default - **automatic**: Claude when it is usable, else OpenAI, else the first self-hosted model server
   with a default model (by name), then OpenAI-compatible cloud services, else rules (Azure OpenAI resources are used
   only when chosen). That is the order team agents were given before, with OpenAI added, now applied at every call
   instead of being stored when an agent was created,
6. the fallback chain (used when the chosen provider fails during a call),
7. rules.

A level is skipped when its provider was removed, is switched off or not configured, is a cloud provider while the
agent (or its team) is **local only** or the guardrail `allow_cloud_llm` is off, has no model (empty model: the
provider's default model, else its first pinned model), or failed 5 times in 5 minutes (unreachable, timed out,
HTTP 429 or 5xx; it is tried again after 60 seconds). Every agent record says where its model comes from:
`llm.purposes.<purpose>` = provider, model, location, source (`agent_purpose`, `agent`, `team`, `purpose`, `suite`,
`fallback`, `rules`) with a label, and the levels that were skipped with the reason; `llm.local_only` (and
`local_only_from`: `agent` or `team`), `llm.choice` (the agent's own choice, `provider: ""` = inherit) and
`llm.settings_version`. `provider`, `provider_label` and `model` of a record are those of its main purpose (what runs,
or - while nothing can - what was chosen for it).

Examples:

1. Nothing set, Claude configured: everything runs on "Claude Opus 5.5 · Suite default (automatic)".
2. Code changes default = `openai/gpt-6.1-sol`: the Patch Agent's code patches use it ("Code changes default"); its
   connector mappings still use the suite default.
3. The Compliance team's default = a local `ollama-gpu`, local only: its team agents and nothing else run locally. The
   GRC Supervisor (the app's lead) is not affected.
4. A local-only agent with the automatic suite default skips Claude and OpenAI and takes the first self-hosted model
   server, else the fallback chain, else rules. With an **explicit** suite default (say Claude) and an empty fallback
   chain the next level is rules: add a local provider to the fallback chain for a local fallback.

**Local only** keeps an agent on self-hosted models: every third-party provider (Claude, OpenAI, Azure OpenAI, an
OpenAI-compatible cloud service) is skipped at every level, the fallback chain included: when its model server fails
during a call, only a self-hosted entry of the chain may take over, else the call fails (chat says the model is
unavailable) - the conversation never moves to the cloud. It binds the agent, not the data: an agent on a cloud
model can still read the same hub data through its tools. For strict locality switch `allow_cloud_llm` off (below) or
make the Hub Supervisor local only too.

### Choosing models

**Settings > AI models > Model choice** (`#/settings/ai`, administrators edit, everyone reads) holds the suite
default (Automatic, a provider and model, or rules only), a default per task ("Chat and agent tasks", "Code changes",
"Structured generation"; "Same as the suite default" unsets one), and the fallback chain, ordered with **Up** / **Down**
buttons (no dragging; the last entry is always "then rules"). Below it, "Effective model per agent" lists what every
model-using agent runs on, where that comes from and what was skipped. Saving sends the version that was read: when
someone else saved in between the panel reloads ("Someone else changed the model choice").

**A team's default** is set with **Change** next to "Model:" on its card on the Agents page: a provider and model (or
the suite default) and **local only**.

**On Home**, the **AI models** dashboard widget shows every model-using agent in the lane of the provider it runs on;
administrators drag an agent to another lane (or use its **Change...** button or the keyboard) to set its own choice,
and drag the Default marker to change the suite default, through the same routes and checks
([DASHBOARD.md](DASHBOARD.md#ai-models)).

**An agent's own choice** is on its settings page, `#/agents/<id>/settings` (the **Settings** button of a core agent,
the sliders icon of a team agent; a new team agent opens it after it is created). **Overview** shows the effective model
per purpose with the levels in order ("1. This agent: not set - 2. Compliance team: not set - 3. Code changes
default: GPT-6.1 Sol (OpenAI) - used"; skipped levels are struck through with their reason), and the agent's model
calls of the last 30 days (UTC days; costs are estimates). **Model** offers "Inherit (currently ...)" or a provider and
model, **Local only**, and for the Patch Agent a model per task. Providers this agent may not use (local only, cloud
switched off) are listed but disabled with the reason. Changes collect in one draft with a sticky "Unsaved changes"
bar; leaving the page asks first, and a version conflict offers "Reload" or "Keep editing". Agents without a model
(Operator, the apps' supervisors) show only an Overview, their Notifications and their History. Chat replies say which model answered ("via
GPT-6 Luna"). The other tabs are described under [Agent settings](#agent-settings).

| Call | Purpose | Effort / max output tokens | Agent |
| --- | --- | --- | --- |
| Hub Supervisor chat, team agent chats and runs | chat | medium / 16,000 | `supervisor`, `agent:*` |
| Code patches (health endpoint, OIDC login, custom), self-patches | code | high / 16,000 (self-patches 64,000) | `patcher` |
| Connector generation, flow repairs, extension packs | generate | high / 16,000 (repairs medium, packs 32,000) | `patcher` |
| Tool analysis, team designs | generate | low / 4,000 and 8,000 | `tool:<id>` |
| A subsidiary's bridge patch: the survey and the glue | code | high / 16,000 and 32,000 | `patcher` |
| A subsidiary's staff design | generate | low / 6,000 | `tool:<id>` |
| A subsidiary's staff turns, through Atrium's model gateway | chat | medium / 8,000 | the sidecar staff `agent:*` |

**What is sent.** Every secret the hub knows - connection credentials, provider keys, the SSO client secret, the
hub's own key and secret-looking environment variables - is replaced by `***` in every system prompt, message, tool
result and tool-call argument before it leaves, also for local providers (they often log prompts). Claude
(`metadata.user_id`) and OpenAI (`safety_identifier`) get a salted hash of the person who asked, never a name, an
email or an account id.

**Structured answers** (patches, mappings, packs, team designs) use the provider's JSON-schema output where it has one,
else JSON mode, else the schema in the prompt. The hub validates every answer against the schema, gives the model one
repair round with what was wrong, and otherwise the caller falls back to its templates or rules. When a provider
refuses a mode, the hub remembers it for that model (`capabilities` on the provider record, an activity entry) and
starts with the next mode from then on (Claude: its JSON-schema output, then the schema in the prompt); a refusal of
the schema itself ("Schema is too complex for compilation") moves on to the next mode without remembering anything.
The same learning applies to a temperature, a reasoning effort, strict tool schemas or tool definitions a model
refuses - an HTTP 400 naming the parameter as not supported, not permitted ("output_config.effort: Extra inputs are
not permitted"), unknown or unrecognized: the call is repeated once without it, and later calls leave it out (a refused
effort level whose refusal lists the levels the model takes keeps those). Claude gets strict tool schemas only within
its structured-output limits per request (20 strict tools, 24 optional and 16 union-typed parameters across them);
otherwise its tools go without `strict` - the hub validates every tool call's arguments itself.

**When a call fails** (after the fallback chain), the person sees the provider's own message - "Claude answered HTTP
400: ...", every hub secret and credential-looking pair masked, the provider's text cut at about 200 characters - in
the Hub Supervisor's note above its built-in answer, a team agent's error, or the playground. The activity log gets it
once per provider, model and message (again only after a call to that model worked), and the agent's errors record it
(code `llm_<kind>`, e.g. `llm_http_400`). The model status every signed-in account reads (`llm.last_error` in
`GET /api/overview` and `GET /api/llm/providers`) says the HTTP status only ("Claude answered HTTP 400"): the
provider's message may quote the request, a person's chat.

**Capabilities.** What a model supports - tools, JSON-schema output, JSON mode, temperature, effort levels, output and
context sizes - comes from the provider's model list (Claude's lists them; an effort entry that says "not supported"
means no effort is ever sent), OpenAI's models pages (for `gpt-6-luna`, `gpt-6-astra` and `gpt-6.1-sol`), Claude's
model families as the Claude API reference describes them (`KNOWN_MODELS` in `hub/llm/adapters/anthropic.py`, matched
by family so dated snapshots and Bedrock / Google Cloud ids count: no effort parameter on Claude Haiku 4.5, Sonnet 4.5
and older, `low`-`high` on Opus 4.5, no `xhigh` on the 4.6 models; used only where nothing else is known, so the first
call to such a model is already right), what the hub learned from a refusal, or **Check tools and JSON**
(`POST /api/llm/providers/{id}/probe {model}`): two tiny calls - one asking for a call of a dummy tool, one asking for
a one-field JSON answer, at most 256 output tokens each (reasoning models count their reasoning toward that limit) -
whose result is stored with the source `probe` and logged with the tokens used.

**Usage.** Every model call writes a usage record (`llm_usage`: agent, purpose, trigger, person, provider, model,
token counts, estimated cost, latency and outcome - never prompt or reply text) and adds to a daily aggregate per UTC
day, agent, provider and model (`llm_usage_daily`, kept 400 days). Cost is an estimate from the price table
`hub/llm/prices.json` (USD per 1M tokens, each entry dated and sourced: the Claude models from
platform.claude.com/docs/en/about-claude/pricing and `gpt-6-luna` from developers.openai.com, as of 2026-10-14; the
prices of `gpt-6-astra` and `gpt-6.1-sol` were not checked and are not shipped). Administrators override prices with
`PUT /api/llm/prices {"overrides": {"<provider id>:<model>": {input, cached_input, cache_write, output, tiers?} | null}}`
(0-10,000 USD; `null` goes back to the shipped price; logged as "AI prices changed: openai:gpt-6-astra input 0 ->
1.25"); `GET /api/llm/prices` (viewers) shows the shipped prices, the overrides and what applies. Calls to a local
server cost 0 unless an administrator sets a price, and a model without a price has no cost. **Provenance**: patches, repairs, extension packs, self-patches and team proposals record which model
wrote them (`generated_by: {provider, model}`), and Approvals shows "Written by <model> (<provider>)".

### Agent settings

The settings page has, besides **Overview** and **Model**, the tabs **Behaviour**, **Tools**, **Limits**,
**Escalation** ("Notifications" for agents that do not chat), **Playground** and **History** (agents without a model:
Overview, Notifications and History). The same settings exist for core and
custom agents (`AgentConfig`: in a core agent's `agents` document, in a custom agent's definition); every save is one
`PATCH /api/agents/{id}/settings` with the version that was read, kept in the history and logged - instructions only as
their length and a hash ("additional instructions changed (34 chars, sha256 05f60020)"), never their text.

- **Model parameters** (Model tab): **effort** (the levels the model supports; "Default for each task" keeps each
  call's own, see the table above), **temperature** - only where the model accepts it (local models; OpenAI at effort
  `none`); Claude models refuse any temperature, so the page says "<model> sets its own sampling - use effort instead"
  and a save that sets one is refused (400 naming the model) - **max output tokens** (a cap: no call of the agent asks
  for more; the page warns when a task of the agent asks for more, e.g. self-patches 64,000) and, for chat agents,
  **max tool rounds** (1-30, default 12). They apply to every model call of the agent, also structured ones.
- **Behaviour**: core agents keep their built-in instructions (shown read-only) and get **additional instructions**,
  added after them in every model call - improvements to the built-in text in later versions still apply. "Advanced:
  replace the built-in instructions" (after a confirmation) makes the agent run on your text only (the older
  `PATCH /api/agents/{id} {instructions}` does the same); switching back drops the replacement (the history keeps
  it). A custom agent's name, role, description, instructions, standing task, schedule and enabled switch are edited
  here too (the New agent dialog only creates one). Chat agents (the Hub Supervisor and custom agents) have a **reply
  language** - the suite default (**Settings > AI models > Model choice**, "Automatic" = the language people write
  in), Automatic, or a language code such as `nl`, `fr`, `de` or `fr-BE`: the model is told "Answer in Dutch. Keep
  ids, commands, code and quoted tool output unchanged." Rules-mode text stays English - and a **memory** setting
  (below).
- **Tools** (chat agents): a custom agent's permissions, and **All tools these permissions allow** or a checklist per
  permission (tools its permissions do not grant are listed but disabled, "needs commands"). The model is offered
  only the allowed tools, and a call to another tool it has the permission for is refused ("... is not among the tools
  an administrator allows ..."). The Patch Agent and Tool Supervisors write structured results reviewed through
  approvals, so they have no tool list.
- **Limits**: **daily tokens**, **daily cost** and **monthly cost** (USD, estimated from the price table; empty = no
  limit), **Stop the agent when a budget is reached** (on by default; off - after a confirmation, logged as a warning -
  a reached budget is only reported), **model calls per minute** and **chats and runs per hour**. The tab shows
  today's spending against each limit and, while the agent is stopped, **Lift today's stop**
  (`POST /api/agents/{id}/budget/override {reason, extra_usd?, extra_tokens?}`: raises today's limits, or with neither
  amount removes the stop for the rest of the day; logged as a warning with the reason; it ends with the UTC day). A
  model without a price has no cost: cost budgets cannot stop it (the tab says so), token budgets still can.
- **Escalation**: the escalate tool, escalation rules, pausing the schedule after failed runs and the notifications
  ([below](#escalation-and-notifications)).
- **Playground** (administrators): a prompt run on the saved settings or the unsaved draft ("Use my unsaved
  changes"), optionally **compared with** a second provider and model; results side by side with the reply, the
  model, tokens, estimated cost, time and the tool calls (arguments and results shortened and masked). Tools that
  only read are offered unless **Allow actions** is checked (commands and patches then go through the approvals, as
  you; the escalate tool counts as an action, since it creates an approval). The Patch Agent and Tool Supervisors answer without tools. Nothing is saved or remembered, the prompt is not
  logged (the activity entry names the models and tokens), and the calls do not use the bus, so they are not in the
  message log. A draft is checked like a save; a local-only draft cannot compare with a cloud provider, and with
  `allow_cloud_llm` off cloud providers stay blocked.
- **History**: the last 20 versions (who, when, what changed) with **Restore** (administrators; restoring a version
  saves it as a new version - a custom agent's team and reporting line stay as they are).

**Budgets and the suite cap.** Before every model call (and every round of a tool loop) the hub checks the agent's
own budgets and the suite's daily cap: the guardrail `limit_llm_spend` (on) with `max_daily_llm_spend` (20 USD, 1 -
100,000) - the estimated cost of all agents' calls in one UTC day, playground calls included. A reached budget stops
**new** calls; a call already running finishes, so one call can go over. Calls running at the same time count at an
upper estimate (their input and their whole output cap, at the model's price) until they are metered: while they
could reach a budget together, a new call waits for them and is then checked again, so parallel chats or runs cannot
pass a budget together either. What happens then:

- **Chat** answers HTTP 429 `{detail, code: "budget_exceeded", retry_after}` (seconds to 00:00 UTC; also a
  `Retry-After` header) - never a rules answer instead, so the person sees why. A rate limit answers 429
  `rate_limited` with the seconds to wait. A budget reached during a tool loop ends the answer with what the model said
  so far and "(Stopped: Hub Supervisor's daily AI budget ($5.00 of $5.00) is reached - an administrator can raise it
  or lift today's stop.)".
- **Runs** (scheduled or Run now) are skipped and recorded: `{ok: false, skipped: true, reply: "Skipped: ..."}`.
- **Structured calls** (patches, connector mappings, extension packs, tool analysis, team designs) fall back to their
  templates or rules, with the reason in their result.
- The first stop of the day is logged once as a warning by `hub` ("Hub Supervisor reached its daily AI budget ($5.00 of
  $5.00): its new model calls are stopped until 00:00 UTC"; "AI spending reached the daily cap ..."), and the
  refused call is metered with the outcome `budget_stopped` or `rate_limited` (no tokens).

Playground calls count toward the suite cap only, never toward an agent's budget. An install that ran before the cap
existed gets one activity entry at its first start: "AI spending is now capped at $20 per day (Settings > Agent
guardrails > AI models and spending)". A provider can also have its own **requests per minute** (more wait up to 30
seconds, then fail as rate-limited) and **max concurrency** (calls at a time, default 4; more wait their turn), set on
its card.

**Settings > AI models > AI usage and spending** (everyone reads) shows the model calls, tokens and estimated cost of
today, the last 7 or 30 days by agent and by provider (sortable), the suite cap against today's spending, a 30-day
chart of the daily cost (with the same numbers as a table for screen readers) and, for administrators, **Edit prices**.

### Chat memory and privacy

Each person has their own conversation with each agent: the memory is kept per agent and person (an API token shares
its owner's). How long depends on the agent's **memory** setting (Behaviour tab):

- **Off**: every message starts afresh.
- **Session** (the default): kept in the hub process, lost on a restart.
- **Kept** (`persisted`): also stored, Fernet-encrypted, in `agent_conversations` (one document per agent and person,
  without the providers' raw output) and deleted after **retention** days without a message (1-365, default 30);
  switching away from it deletes the stored conversations.

A conversation starts afresh, with the notice "(Started a new conversation: the earlier one reached this agent's
memory limit.)", after **max turns** messages from the person (2-200, default 40); also when the agent's model
changes, or with **New conversation** (which clears only your own, also the stored copy). Conversations are dropped
when the account or the agent is deleted. Runs always start fresh. `GET /api/agents/{id}/conversation` (operators)
returns only the caller's own conversation (their messages and the agent's answers) and the memory setting; the chat
panel shows "Memory: this conversation is kept for you only (30 days)". `DELETE /api/agents/{id}/conversation` deletes
your own; administrators can delete anyone's with `?user_id=` (logged) but never read them - the settings page shows
counts only.

Chat text never reaches other accounts: the message log and the event stream every signed-in account reads keep a
chat's routing (sender, recipient, subject) and the length of its text (`{"redacted": "chat", "chars": n}`) - never
the text. `GET /api/messages` and `GET /api/agents/{id}/messages` redact older rows on the way out as well. The person
who asked gets the reply in the answer to their request. A chat message is at most 20,000 characters.

### Conversations and errors

The **Agent bus** page shows the agents' conversations: everything one chat message, one person's action or one
scheduled run caused on the bus, grouped by its root message ([ARCHITECTURE.md](ARCHITECTURE.md#the-agent-bus)), with
its errors. Viewers read routing, subjects, status and error texts; operators and administrators read message bodies
too (hub secrets masked, bodies over 32 KB as the log keeps them). The plain message log follows the same rule:
`GET /api/messages`, `GET /api/agents/{id}/messages` and the live `message` event give viewers a body of
`{"redacted": "role"}` (plus `failed` and `error` for a reply with an error), and the log itself is stored with every
hub secret masked. A person's chat stays theirs: others see the chat messages' size only, other messages of that
conversation with every string that quotes the person's words - this turn's or, when the agent remembers them, an
earlier one's - replaced by `[private: quotes a person's chat]`, and no error text for the chat itself; the person
reads it all (also the title of the conversation: their first words) while their account exists. The same holds for
the activity log and the command history (and their live events): what an agent writes there while it works on a
person's chat - "Ran on local: ...", "Awaiting approval: ...", "Recorded risk: ..." - is stored without the strings
that quote the chat, and its person reads the original. An approval an agent asks for in a chat keeps the chat's
conversation: once an administrator decides it, the agents carry it out there, under the same rule.

Every failure of an agent is recorded - an exception, an error reply, a request nobody answered in time or no agent
could receive, a failed AI model call - with whom it was for and in which conversation; an error reply is not
recorded again when the exception or model failure behind it was. The Agents page's error count
opens them; operators acknowledge them, administrators clear an agent's (which also resets its errors since start).

**The page** (`#/bus`: in the sidebar after Agents, in Portals, and in the Ctrl K palette with the shortcuts
"Conversations with errors" and "My chats with agents"). On the left, the conversations, latest activity first and
live: who started it (a person, an agent, or **Scheduled** for the hub's own background work), its title (the subject
of its first message; your own chat shows your first words, someone else's reads "Private chat with <agent>"), the
agents taking part as icons, a status chip (**working** while a request waits for its answer or an agent works on it,
**answered**, **failed** when its first request got an error or no answer), its errors and the time. Filter by agent,
status, **Errors only** and **My chats** (the ones you started), or search; the filters stay in the address
(`#/bus?agent=supervisor&status=failed&errors=1&mine=1&q=...`), and Up and Down move through the list. On the right,
one conversation (`#/bus/<id>`, a link to share) as a transcript: one numbered bubble per message with sender ->
recipient, subject and kind, indented under the message whose handling sent it; a request paired with its answer
("answered in #4 after 1.2 s", "waiting for the answer", "no answer"); the body under a one-line preview, pretty-printed
when opened - or "hidden: your role" and "private chat" - and failures in red with their error text and
**Acknowledge**. The open conversation updates while the agents work. On a narrow screen the list and the conversation
take turns (**All conversations** goes back).

The other ways in: on the Agents page an agent's error count is a button (red "2 errors" while some are not
acknowledged, grey "2 errors, acknowledged" otherwise) that opens its errors in a drawer - newest first, each with its
subject, who asked, the error text, the time and **Open conversation**; **Acknowledge** and **Acknowledge all**
(operators), **Clear all** (administrators), **Not acknowledged only**, and a link to the agent's conversations with
errors. Every row of the page's **Agent conversations** stream opens its conversation, and the chat panel links **Show
how the agents worked on this** while the agent is thinking and under each answer. A notification about an agent's
failure (the bell) opens the conversation it happened in.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/bus/threads` | viewer | conversations, latest activity first: `{threads, total, next_before}`; filters `agent`, `subject`, `errors_only`, `person_only` (the caller's own), `status` (`open`, `answered`, `failed`), `q` (subjects, participants, the caller's own chat words, and - for operators and administrators - bodies as they read them), `limit` (1-200, 50), `before` (the previous page's `next_before`) |
| `GET /api/bus/threads/{id}` | viewer | one conversation: `{thread, messages (oldest first, the last `limit`, 1-2000, 500), errors, truncated}`; 404 when unknown |
| `GET /api/agents/{id}/errors` | viewer | the agent's recorded failures, newest first: `{agent, errors, total, unacknowledged, since_start, next_before}`; `unacknowledged=true`, `limit` (1-500, 100), `before` (a record's `ts`) |
| `POST /api/agents/{id}/errors/{error_id}/ack` | operator | acknowledge one -> the record |
| `POST /api/agents/{id}/errors/ack` | operator | acknowledge all of the agent's -> `{acknowledged, unacknowledged}` (logged) |
| `DELETE /api/agents/{id}/errors` | admin | delete the agent's records -> `{cleared}` (logged) |

### Escalation and notifications

**Escalate.** A chat agent (the Hub Supervisor, team agents) can ask a person instead of deciding itself: its
`escalate` tool (`{summary, severity: info | warning | critical, needs: decision | information}`) creates an approval
of kind `agent_escalation` titled "<agent>: <first line of the summary>", with the summary - masked like everything sent
to a model - as its text (`hub/agents/notify.py`). Operators decide it on the Approvals page, administrators too:
**Acknowledge** (approve) or **Dismiss** (reject), each with an optional answer. The answer waits in the agent's inbox
(its last 10) and is added to the instructions of its next chat turn or run - 'A person answered your escalation
"<title>" (acknowledged): <answer>' - and then cleared; an acknowledged escalation is marked done. The model is told
when to use the tool: always when it is blocked or unsure whether an action is safe, and whenever one of the agent's
**escalation rules** applies (Escalation tab: at most 20 lines of 300 characters, e.g. "A firewall rule would open a
port to the internet"). The tool is on by default and can be switched off per agent; when the Tools tab narrows the
allowed tools, `escalate` must be among them too. An agent escalates at most **escalations per day** times (1-50,
default 5, per UTC day): beyond that the tool answers "escalation limit reached - put it in your reply instead" and
the first refusal of the day is logged, so text a model reads in a tool result cannot flood the approval queue. The
playground offers the tool only with **Allow actions**.

**Failed runs.** A team agent whose runs fail **failed runs before pausing** times in a row (0-20, default 3; 0 =
never) gets its schedule paused (with **Pause the schedule**, on by default): `schedule_paused` on its record, a
"schedule paused after 3 failures" badge on the Agents page, and the scheduler leaves it alone. A person can still run it
by hand. **Resume schedule** (administrators; `POST /api/agents/{id}/schedule/resume`) runs it on its schedule again
and starts the count afresh ("Resumed Triage's schedule (it was paused after 3 failed runs in a row)"). A successful run
resets the count; a run skipped for a budget or rate limit does not count.

**Notifications.** Atrium has no email. An agent's events - **a run failed**, **a budget is reached**, **it escalates
to a person**, **it asks for an approval**, **a run finished** - are entries in the activity log, as before; for the
events an agent's notification settings name (default: run failed, budget reached, escalation) the entry is a
notification: `data.event`, `data.severity` and `data.notify` = the targets (`role:admin` - the default -,
`role:operator`, which includes administrators, or `user:<account id>`). The activity log and its event stream reach
every signed-in account, so a notification carries the agent, the event, a severity and a masked summary - nothing a
viewer may not read; the targets only decide whom it is highlighted for. Which events an agent can have depends on
it: team agents all five, the Hub Supervisor no runs, the Patch Agent and Tool Supervisors budgets and approvals, agents
without a model only the approvals they ask for. With **Also send to integrated tools** on (off by default; switching
it on is logged as a warning) the notification is also published on the tool bus as `hub.agent.<event>` (source
`hub`) to the tools whose manifest listens for it (e.g. `events.listens: ["hub.agent.*"]`, the Escalation tab names
them): `{agent_id, agent_name, event, severity, summary (masked, at most 500 characters), link: "<HUB_PUBLIC_URL>/#/agents/<id>/settings", at}`.
That is how a chat or ticketing tool hears about it.

**Needs attention.** The Agents page starts with a "Needs attention" strip (when something does): pending
escalations (with a link to Approvals), budgets reached, paused schedules (with **Resume schedule** for
administrators), agents the guardrails hold back, and agents whose chosen model cannot run (grouped by the reason). An
item is marked "(for you)" and highlighted when the agent's notifications for that event target you
(`GET /api/agents/attention`, viewers; `for_you` per item).

Escalation and notification settings are part of the agent's settings: saved with the version, kept in the history
and logged ("Configured Triage: escalation rules: 2; notification targets: role:operator"; the tool bus switched on,
pausing switched off, or a limit raised as a warning).

## OpenAI and Azure OpenAI

**OpenAI** is the built-in provider `openai` (`hub/llm/adapters/openai.py`, plain HTTP, no SDK). It uses the
**Responses API**, which OpenAI recommends for new projects and which allows tool calls together with reasoning on the
current models (Chat Completions allows function calling on `gpt-6-luna` only without reasoning). The record is
switched off until a key is stored (`PATCH /api/llm/providers/openai {api_key}` - storing a key switches it on) or
`OPENAI_API_KEY` is set on the hub machine (which wins over a stored key). The address is fixed:
`https://api.openai.com/v1`; `OPENAI_BASE_URL` is ignored on purpose, so a stray environment variable cannot send the
key elsewhere. Choose its default model on its card (**Test** lists the account's models; embedding, audio, image,
moderation and realtime models are left out of the list; `gpt-6-astra`, `gpt-6.1-sol` and `gpt-6-luna` come first
when the account has them). A ChatGPT subscription (Plus, Pro, Business) does not include API access: API usage is
billed separately, with an API key and billing on platform.openai.com.

Every request sends `store: false` (OpenAI keeps no response) and asks for the encrypted reasoning
(`include: ["reasoning.encrypted_content"]`), so a model's reasoning goes back with the tool results without anything
being stored at OpenAI. Tools are sent with `strict: false` (the hub validates the arguments itself), structured
answers use `text.format` with a strict schema (optional fields become nullable and the nulls are dropped again), a
reasoning effort goes in `reasoning.effort`, and a temperature only with effort `none` (OpenAI rejects it with
reasoning). A rate limit or an overloaded server (HTTP 429, 503, 529) is retried twice, after 1 and 4 seconds or after
the server's `Retry-After` (at most 30 seconds); redirects are never followed and error texts never contain the key.
Assumptions marked UNVERIFIED in the code: that `cached_tokens` are part of `input_tokens` (as in Chat Completions),
and the smallest `max_output_tokens` (16 is used).

**Azure OpenAI** resources are added as providers of kind `openai`, variant `azure` (**Add provider > Azure OpenAI**,
any id such as `azure-prod`): the v1 address `https://<resource>.openai.azure.com/openai/v1` (or
`<resource>.services.ai.azure.com`; nothing else is accepted, so the key cannot be sent elsewhere), an API key (sent in
the `api-key` header, bound to that address) and the deployment names (models are deployments; the list is fetched
when Azure provides one, otherwise the names typed on the provider are used). **Test** makes the smallest Responses
call on the default deployment. Azure resources count as cloud providers and are used only when chosen (never by the
automatic default). Microsoft Entra ID tokens are not supported (an API key only).

**Sign in with ChatGPT** (paying model calls from one person's ChatGPT plan) is not built: it suits a single-person,
locally run Atrium rather than a shared hub server (a browser on the hub machine for the sign-in, a Plus plan's shared
5-hour limit, a streaming-only preview). If it is ever added it would be a separate, admin-only variant behind its own
guardrail.

## Local models

Team agents can run on any server with an OpenAI-compatible API (`hub/llm_providers.py`, collection
`llm_providers`). Add one under **Settings > AI providers** (admin): name, base URL (default
`http://localhost:11434/v1`, Ollama's), default model, optional API key, tool calling on or off, how to ask for JSON
(`structured_output`: automatic, JSON schema, JSON mode or instructions only), whether to send the reasoning effort
(`send_effort`), timeout (default 300 seconds). **Test** lists the server's models (`GET {base_url}/models`); the agent
loop sends `POST {base_url}/chat/completions` with `tools` (at most 12 rounds) and never `tool_choice`. A local
provider is `self_hosted` when its address is a loopback, private or link-local address, a `.local` or a single-label
host name, and a `third_party` (cloud) service otherwise. A server on a public address must use `https://`, unless an
administrator confirms it is their own server ("This server is ours", `confirm_self_hosted: true`, logged as a
warning: "Marked <name> as self-hosted (public address <host>)"); the confirmation holds for that host only. A server
on your own network that forwards to a cloud service can be marked a cloud provider (`location: "third_party"`). A
self-hosted server reached over plain http on another machine shows an "unencrypted (http)" badge. Through the
automatic suite default, a local provider with a default model also serves the core agents when neither Claude nor
OpenAI is configured.

| Server | Base URL | Tool calling |
| --- | --- | --- |
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
| `GET /api/llm/providers` | viewer | every provider in card order (`records`, with `key_source` and what is known per model in `caps`; keys only as "set"), the local ones (`providers`), the built-in ones (`builtin`), what agents can run on (`choices`: availability and reason, location, default model, models, pinned models, capabilities), the provider layer's status (`llm`; `anthropic` is the same, its earlier name), `kinds` and `known_models` |
| `POST /api/llm/providers` | admin | add a local server (`kind: "openai_compatible"`) or an Azure OpenAI resource (`kind: "openai", variant: "azure"`) |
| `PATCH /api/llm/providers/{id}` | admin | change it (`enabled`, `default_model`, `pinned_models`, key, address, options, `supplier`); an empty `api_key` keeps the stored one, `clear_api_key` removes it; the built-in providers' name and address are fixed |
| `DELETE /api/llm/providers/{id}` | admin | remove it (409 for the built-in ones, and while an agent, a team, a purpose, the suite default or the fallback chain uses it) |
| `POST /api/llm/providers/{id}/test` | admin | list its models and what the list says about them (Azure: and the smallest call on the default deployment) |
| `POST /api/llm/providers/{id}/probe` | admin | check one model's tools and JSON support (`{model}` -> `{model, caps, tokens}`; 409 when the provider cannot take calls) |
| `GET /api/llm/prices` | viewer | the price table: shipped, overrides, effective |
| `PUT /api/llm/prices` | admin | set or drop price overrides |
| `GET /api/llm/selection` | viewer | `{selection, effective, deterministic, suite}`: the suite default, task and team defaults, the fallback chain and its `version`; every model-using agent with its `llm` block; how many agents use no model; what the suite default resolves to |
| `PATCH /api/llm/selection` | admin | `{default?, purposes?: {chat\|code\|generate: choice \| null}, teams?: {<team>: {provider, model, local_only} \| null}, fallback?: [ids], version?}`; 400 for an unknown provider, purpose or team, a model without a provider, `auto` outside the suite default, a local-only team with a cloud provider, or a fallback chain with duplicates, `rules` or more than 8 entries; 409 `{code: "version_conflict", selection}` for a stale `version`; logged ("AI model selection: suite default automatic -> ollama (default model); Compliance team: local-only on" - a team losing local-only as a warning); event `llm_selection` |
| `GET /api/agents/{id}/settings` | viewer | `{settings: {llm, config, instructions, + a custom agent's name, title, description, permissions, team, parent, schedule_minutes, task, enabled}, version, tabs, chats, purposes, per_task, builtin_instructions, effective, chain, inherited, inherited_task, team_default, models (per purpose: provider, model, caps, priced), call_tokens, language, tools_catalog, permissions_catalog, effective_permissions, budget_state, suite_budget, memory (counts), usage, history_versions, escalation (pending, today, limit, answers waiting), schedule (paused, failures), notify_events, notify_targets (with names), target_roles, toolbus_listeners (tool names)}` |
| `PATCH /api/agents/{id}/settings` | admin | a partial of `settings` with `version`: `config` groups (`params`, `budget`, `rate`, `memory`, `escalation`, `notify`) merge key by key (agents without a model: `config.notify` only), `config.purposes` per task (`null` unsets one); 400 naming the setting ("Daily cost: ...", "Allowed tools: unknown tool 'x'", "Temperature: ... sets its own sampling", "Memory: Patch Agent does not chat", a core agent's `name`, ...); 409 `{code: "version_conflict", settings, version}`; logged ("Configured Hub Supervisor: effort none -> high; budget daily_cost_usd none -> 5.0") - local only off, more tools or permissions, the hard stop off or a limit raised or removed as a warning; events `agent` and `agent_settings {id, version}` |
| `GET /api/agents/{id}/settings/history` | viewer | the kept versions, newest first: `[{version, actor, at, changed, restored_from}]` |
| `POST /api/agents/{id}/settings/restore` | admin | `{version, base_version?}` -> the settings view (a new version; 404 unknown version, 409 when `base_version` is stale, 400 when it no longer validates, e.g. its provider was removed) |
| `POST /api/agents/{id}/playground` | admin | `{prompt (<= 8,000 chars), draft?, compare_with?: {provider, model}, allow_actions?}` -> `{runs: [{source: "draft" \| "compare", provider, model, reply, mode, usage, tokens, cost_usd, latency_ms, tool_calls, error}]}` (300 s per run) |
| `POST /api/agents/{id}/budget/override` | admin | `{reason (>= 5 chars), extra_usd?, extra_tokens?}` -> the budget state |
| `GET /api/agents/{id}/usage?days=` | viewer | per-day calls, errors, stopped calls, tokens and estimated cost (1-400 days) and the budget state |
| `GET /api/llm/usage?days=&group=&agent_id=` | viewer | `{from, to, totals, rows, suite_budget: {enabled, limit, spent_today, stopped}, unpriced, prices_as_of}`, rows grouped by `agent` (default), `provider`, `model` or `day` |
| `GET /api/agents/{id}/conversation` | operator | the caller's own conversation and the agent's memory setting |
| `DELETE /api/agents/{id}/conversation` | operator | delete your own (`?user_id=`: anyone's, administrators only) |
| `POST /api/agents/{id}/schedule/resume` | admin | a team agent's schedule paused after failed runs runs again (the count starts afresh) -> its record; 400 for a core agent |
| `GET /api/agents/attention` | viewer | `{items: [{kind: escalation \| budget \| paused \| held \| blocked, ..., for_you}]}`: the Agents page's "Needs attention" strip |

`agent_settings {id, version}` is also published when a team agent is created, when settings are restored or a
budget stop is lifted, and when `PATCH /api/agents/{id}` changes a model, instructions or (custom agents) any part of the
definition (which moves the settings version too and keeps a history entry); views that show configuration listen to it instead of
`agent`, which fires after every handled message.

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
| `approvals_need_second_person` | off | an approval that records who proposed it (a self-patch a person asked for, a data flow drawn on the integration map) must be approved by someone else; the proposer can still reject it (403 `same_person`) | (on is the safe side) |
| `allow_cloud_llm` | on | agents may run on third-party AI providers (Claude, OpenAI, Azure OpenAI, OpenAI-compatible clouds); off: they move at once to a self-hosted model or rules, and a running tool loop sends no further round to the cloud | (off is the safe side; HB-SC-1 covers the providers in use) |
| `limit_llm_spend` / `max_daily_llm_spend` | on / 20 | the suite's daily AI spending cap in USD (1-100,000; estimated, UTC days): new model calls stop once it is reached ([Agent settings](#agent-settings)) | off: HB-AC-6 partial ("agents' AI model spending has no daily limit"); raising the cap is logged as relaxing |

The network guardrails - `device_changes` (off by default), `device_changes_need_second_person`,
`device_changes_need_maintenance_window`, `device_changes_need_backup` and `approval_expiry_hours` - are in
**Settings > Network changes** and described in [NETWORK.md](NETWORK.md#guardrails). `approval_expiry_hours` (default
24, 1-72) also limits how long a self-patch approval, a subsidiary's charter or one of its in-tool changes can be
decided.

The group **Subsidiaries** (agent teams inside tools, [SUBSIDIARIES.md](SUBSIDIARIES.md#guardrails-and-hb-ac-8)):

| Guardrail | Default | Effect | Relaxed |
| --- | --- | --- | --- |
| `allow_subsidiaries` | off | agent teams may work inside tools through bridges and sidecars; switching it off is the kill switch (every subsidiary paused, its pending approvals withdrawn) | on is logged as relaxing |
| `subsidiary_tool_writes_need_approval` | on | every change a team wants to make inside its tool waits for a person; off: a charter may let reversible changes without external effect run at once (never from the panel) | HB-AC-2 partial |
| `subsidiary_panel_actions` | off | questions tool users ask inside the tool may lead to change requests (always approved, marked user-steered) | HB-AC-8 partial |
| `subsidiary_bridge_requires_tests` | on | a bridge patch is approved only when its static checks passed and the tool's tests did not fail | HB-CM-2 fails |
| `subsidiary_bridge_requires_conformance` | on | a charter is approved, and a subsidiary active, only after the bridge passed the conformance vectors | HB-AC-8 fails |
| `subsidiary_separate_credential` | on | an API-only team reads with its own read-only credential, never the hub's | HB-AC-8 partial |
| `subsidiary_ticket_minutes` | 10 (1-60) | the lifetime of the tickets that let a sidecar call a bridge: the longest bridge reads continue after a pause, a stop or the kill switch | above 10: HB-AC-8 partial |
| `subsidiary_max_tokens_per_day` | 300 (thousands; 10-20,000) | the ceiling on every charter's daily model budget | raising it is logged as relaxing |

For `allow_extensions`, `allow_self_patching` and `allow_cloud_llm` off is the protective position, so switching them
back on is logged as relaxing (a warning, after showing the risk); switching `allow_cloud_llm` off asks first because
agents change model at once (it is on by default because nothing reaches a cloud provider until an administrator adds
a key); for `approvals_need_second_person` on is the protective position, so switching it off is. When `max_team_size` is lowered below a team's size, the team's oldest members keep acting and
the newest ones may not act (chat, runs and the scheduler refuse them) until the team shrinks or the limit is raised;
the agent's `outside_guardrails` says why.

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/settings` | viewer | includes `guardrails` (values) and `guardrail_catalog` (title, description, group, default, safe side, value, risk, control, bounds, relaxed) |
| `PATCH /api/settings/guardrails` | admin | `{key: value, ...}`; 400 for an unknown key, a wrong type or an out-of-range value (nothing is stored) |

`PATCH /api/settings {guardrails: {...}}` (admin) does the same. A later feature adds a guardrail with
`guardrails.register(Guardrail(..., control="HB-...", weakens="fail" | "partial", finding="..."))`; the settings screen,
validation, logging and the compliance check pick it up.

### Compliance effect

| Control | Fails when | Partial when |
| --- | --- | --- |
| HB-AC-2 Privileged agent actions are approved | the hub runs in autonomous mode | `scans_need_approval`, `team_requires_approval` or `subsidiary_tool_writes_need_approval` is off |
| HB-AC-6 AI agent guardrails are enforced | `block_catastrophic_commands`, `team_actions_need_approval` or `limit_to_parent_permissions` is off | team size is unlimited, nested teams are allowed, or AI spending has no daily cap (`limit_llm_spend` off) |
| HB-CM-2 Changes to tools are reviewed | `self_patch_requires_approval`, `self_patch_requires_tests` or `subsidiary_bridge_requires_tests` is off | `extensions_need_approval` is off, or the hub runs in autonomous mode |
| HB-SC-1 SaaS and supplier inventory | no SaaS service and no cloud AI provider in use has an owner (and, for AI providers, a terms review within 12 months) | some have |
| HB-CM-3 Network device changes are controlled | `device_changes_need_second_person` or `device_changes_need_backup` is off, or a change left a device in an unknown state | `device_changes_need_maintenance_window` is off, or in the last 90 days there were emergency changes, changes approved by their own proposer or changes applied without a backup (even if the guardrails are on again now) |
| HB-AC-8 AI agent teams inside tools are governed | `subsidiary_bridge_requires_conformance` is off, or an active subsidiary lacks an approved charter, passing conformance (while required) or an enabled owner of its sidecar's token, or had an alarm in 90 days | `subsidiary_panel_actions` on, `subsidiary_separate_credential` off, `subsidiary_ticket_minutes` above 10, a changed bridge, a sidecar offline for over a day, conformance only claimed, or a bridge approved without the tool's tests ([COMPLIANCE.md](COMPLIANCE.md#hb-ac-8-ai-agent-teams-inside-tools-are-governed)) |

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
| `widget` | a Home dashboard widget over a data type (a count, breakdown, list or metric with whitelisted fields and conditions; no markup or URLs), offered in the widget gallery while the pack is enabled ([DASHBOARD.md](DASHBOARD.md#widgets-declared-by-packs-and-tools)) |

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

It asks the Patch Agent to extend Atrium. With an AI model, the Patch Agent writes the pack with structured output, and it
is validated like an upload (a connector item always maps the tool itself, and its base URL is pinned to the tool's
known API address - the OpenAPI document's, the manifest's or the SaaS URL; with none known, it carries no base URL and
an admin sets the connection up). Without an AI model, or if
the model's answer is unusable, it uses templates:

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
| `POST /api/tools/{id}/extend` | admin | `{designer: auto, templates or model}` (`claude` is accepted for `model`): close the tool's hub-side gaps |
| `GET /api/x` | viewer | the enabled extension domains |
| `GET /api/x/{key}` | viewer | records, with `q`, `asset_id`, `person_id`, `source`, `stale`, `limit` |
| `POST /api/x/{key}` | operator | `{fields, asset_id?, person_id?}`: add a record |
| `GET /api/x/{key}/{id}` | viewer | a record with its domain definition |
| `PATCH /api/x/{key}/{id}` | operator | `{fields?, asset_id?, person_id?, relink?}` |
| `DELETE /api/x/{key}/{id}` | operator | remove a record |

## Self-patching

When an extension cannot express what a tool needs - a GraphQL or gRPC API, or the AI model says code is needed - the Patch
Agent can propose a change to **Atrium's own repository**. Admins can also ask for one directly (**Ask for a change** in
the Extensions page's **Self-patches** tab).

Requirements: the guardrail `allow_self_patching` is on, the Patch Agent has an AI model for code changes (see
[Models and providers](#models-and-providers)), and Atrium runs
from a **git checkout**. An install with `install.sh` / `install.ps1` in the repository folder qualifies; a copy made
with `--install-dir` / `-InstallDir` and the Docker image do not (they have no `.git`). `HUB_SELF_PATCH=off` turns the
detection of the checkout off; the test suite sets it.

How it works (`hub/extensions/selfpatch.py`):

1. The AI model writes the change (structured output; it may only rewrite files of Atrium it was shown); the
   self-patch records which model (`generated_by`).
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
   (409). The approval is bound to the branch's commit and expires after `approval_expiry_hours` (default 24): it is
   refused once expired or when the commit moved, and the worktree's commit is checked again before merging or
   pushing. While `approvals_need_second_person` is on, the admin who asked for the patch cannot
   approve it. Rejecting removes the branch and the worktree.
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

**Remaining risk**: the tests of a model-written change run before anyone approves it, as the same operating-system
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
