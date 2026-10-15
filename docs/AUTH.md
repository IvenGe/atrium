# Sign-in and access control

Every `/api` call, apart from a handful of public endpoints, needs a signed-in person or an API
token. People sign in with a local account (username and password) or through single sign-on
with an OpenID Connect identity provider. Programs use API tokens. What each caller may do is
decided by its role, on the server, for every request.

The UI files themselves (everything outside `/api`) are public: they contain no data, and the UI
shows the sign-in screen until you are signed in.

## Roles

Roles are ordered `viewer` < `operator` < `admin`; each role can do everything the roles before it
can. `integration` is a separate role that exists only for API tokens, and `subsidiary` one that exists only for the
token of a subsidiary's sidecar ([Subsidiary tokens](#subsidiary-tokens)).

| Role | May do |
| --- | --- |
| `viewer` | Read everything: every page, every `GET /api` endpoint, the live event stream (`/api/events`) and the API docs (`/api/docs`). Changes nothing. One exception by design: other people's chats with agents - the message log and the event stream keep only who chatted with which agent and the length of the text ([AGENTS.md](AGENTS.md#chat-memory-and-privacy)). On the Agent bus page (`GET /api/bus/threads*`), in the message log (`GET /api/messages`, `GET /api/agents/{id}/messages`) and in the event stream's `message` events viewers read the agents' conversations without message bodies: routing, subjects, status and error texts ([AGENTS.md](AGENTS.md#conversations-and-errors)). |
| `operator` | Everything a viewer can, plus every state-changing call: import and remove tools, analyse, start (an administrator approves it) and stop tools, propose patches, approve or reject (except extensions, self-patches, agent teams and device changes, and never their own proposal while a second-person guardrail applies; an agent's escalation (`agent_escalation`) they acknowledge or dismiss with an answer the agent reads in its next turn; commands on the hub machine, tool starts and repairs of a network device's connection they may reject but not approve), run commands on SSH hosts and read-only commands on the hub machine (anything else there waits for an administrator, see [Commands on the hub machine](#commands-on-the-hub-machine)), add/remove/discover hosts, add and edit assets, sync, edit compliance controls, risks and policies, chat with the Hub Supervisor and any team agent (`POST /api/agents/{id}/chat`; a reached AI budget or rate limit
answers 429), read and delete their own conversation with an agent (`GET` / `DELETE /api/agents/{id}/conversation`:
only the caller's own - administrators may delete, never read, another person's), run a team agent's task (`POST /api/agents/{id}/run`), acknowledge agents' recorded errors (`POST /api/agents/{id}/errors/{error_id}/ack`, `POST /api/agents/{id}/errors/ack`), ask a tool's supervisor for an agent team (`POST /api/tools/{id}/team`; an administrator decides the proposal), choose a tool's identity provider (`POST /api/tools/{id}/sso`) and run provider registrations (`POST /api/tools/{id}/sso/register`), test connections and list a connection field's choices (`GET /api/tools/{id}/connection/options/{field}`, which uses the stored credentials), run, schedule and repair data flows, request scans and triage vulnerabilities, add, edit and remove people, link accounts, unassign a leaver's assets (`POST /api/people/{id}/actions/unassign_assets`), add, edit and remove records of extension apps (`/api/x/{key}`), draw data flows and arrange the shared map layouts (`POST /api/flows`, `PATCH` / `DELETE /api/layouts/{view}`), start and score framework self-assessments (`/api/frameworks/{id}/assessments`), refresh network devices, take device backups, acknowledge drift, place assets on the segmentation map, and preview, propose, withdraw (their own) and revert device changes and propose backup restores ([NETWORK.md](NETWORK.md#roles)), and for agent teams inside tools ([SUBSIDIARIES.md](SUBSIDIARIES.md#working-with-a-team)): ask a tool for a team (`POST /api/tools/{id}/subsidiary`), pause one subsidiary or all (`POST /api/subsidiaries/{id}/pause`, `POST /api/subsidiaries/pause-all`), give its staff a task (`POST /api/subsidiaries/{id}/tasks`), read its audit trail's detail and verify the chain (`GET /api/subsidiaries/{id}/audit?detail=1`, `POST /api/subsidiaries/{id}/audit/verify`), read, close and promote its reports, and approve its ordinary in-tool changes (`subsidiary_action`; signed in as a person, never a change their own task or chat led to). |
| `admin` | Everything an operator can, plus accounts (`/api/users`), API tokens (`/api/tokens`), hub settings (`PATCH /api/settings`: autonomy level, Claude's default model, vulnerability SLA days, guardrails), the agent guardrails (`PATCH /api/settings/guardrails`), agent definitions (`POST /api/agents`, `PATCH` / `DELETE /api/agents/{id}`: create, configure and remove agents; core agents can only be paused and reconfigured), clearing an agent's recorded errors (`DELETE /api/agents/{id}/errors`), the AI model providers, which may hold API keys (`POST /api/llm/providers`, `PATCH` / `DELETE /api/llm/providers/{id}`, `POST /api/llm/providers/{id}/test`, and `POST /api/llm/providers/{id}/probe`, which spends a few tokens to check a model's tools and JSON support), the AI price table behind the cost estimates (`PUT /api/llm/prices`; viewers read it), which model agents use (`PATCH /api/llm/selection`: the suite, task and team defaults and the fallback chain; `PATCH /api/agents/{id}/settings`: an agent's own model, instructions, tools, budgets, limits, memory, escalation and notifications, and
`POST /api/agents/{id}/settings/restore` to bring back an earlier version; viewers read both and the history), the agent
playground, which spends tokens and may act (`POST /api/agents/{id}/playground`), lifting an agent's budget stop for
the day (`POST /api/agents/{id}/budget/override`), resuming a team agent's schedule paused after failed runs (`POST /api/agents/{id}/schedule/resume`), the suite's identity providers (`PUT /api/identity-providers/default`, `PATCH /api/identity-providers/{id}`, `POST /api/identity-providers/{id}/atrium`), tool connections, which hold the tools' API credentials (`PUT` / `DELETE /api/tools/{id}/connection`), the [Sign-in & SSO settings](#sign-in--sso-settings) (`GET` / `PUT` / `DELETE /api/auth/sso`, `POST /api/auth/sso/test`), disabling a leaver's Atrium account (`POST /api/people/{id}/actions/disable_atrium_account`), extension packs (`POST /api/extensions`, `PATCH` / `DELETE /api/extensions/{id}`, `POST /api/extensions/{id}/rollback`, `POST /api/tools/{id}/extend`), self-patches (`POST /api/self-patches`, `POST /api/self-patches/{id}/apply`), the Network app's baselines, backup downloads and settings (`POST` / `DELETE /api/network/devices/{id}/baseline`, `GET /api/network/backups/{id}/download`, `PATCH /api/network/settings`), segmentation zone roles and policy (`PATCH /api/segmentation/zones/{id}`, `PUT /api/segmentation/policy`), emergency device changes (`POST /api/segmentation/changes/{id}/emergency`), maintenance windows (`POST` / `PATCH` / `DELETE /api/network/maintenance-windows[/{id}]`), deleting framework self-assessments (`DELETE /api/frameworks/{id}/assessments/{aid}`), shared Home dashboards and the default one (`POST /api/dashboards/shared`, `PUT` / `DELETE /api/dashboards/shared/{id}`, `PUT /api/dashboards/default`), and deciding approvals of kind `extension` and `self_patch` (changes to Atrium itself), `agent_team` (they create agent definitions) and `firewall` (device changes, `code: admin_required`), a subsidiary's charter (`subsidiary_charter`), its bridge patch (`patch` with the strategy `atrium_bridge`) and its in-tool changes of `admin` risk or with an external effect (`code: admin_required`; approving any subsidiary approval needs a signed-in person, `code: person_required` for a token), the subsidiaries' charters, dedicated credentials, enrollments, conformance runs, signing keys, resume, stop and archive (`PUT /api/subsidiaries/{id}/charter`, `PUT` / `DELETE /api/subsidiaries/{id}/credential`, `POST /api/subsidiaries/{id}/enrollment`, `/conformance`, `/rotate-key`, `/resume`, `/stop`, `DELETE /api/subsidiaries/{id}`; enrollment, resume and stop signed in as a person), and approving a `command` on the hub machine or a `process` that starts a tool (`code: admin_required`) - checked by `POST /api/approvals/{id}`, 403 for others. Running commands on the hub machine directly and starting tools directly. |
| `integration` | API tokens only. Exactly two calls: `POST /api/bus/publish` and `GET /api/health`. |
| `subsidiary` | The token of a subsidiary's sidecar only, created by its enrollment. Only `/api/subsidiary/v1/*`, and only for its own subsidiary ([below](#subsidiary-tokens)). |

Endpoints outside the role ladder:

| Endpoints | Who |
| --- | --- |
| `GET /api/health`, `GET /api/auth/me`, `POST /api/auth/login`, `POST /api/auth/setup`, `GET /api/auth/oidc/login`, `GET /api/auth/oidc/callback` | Anyone (public) |
| `POST /api/auth/logout`, `POST /api/auth/password`, `GET` and `DELETE /api/auth/sessions` | Any signed-in person (self-service) |
| `POST /api/dashboards/mine`, `PUT` / `DELETE /api/dashboards/mine/{id}`, `PUT /api/dashboards/prefs` | Any signed-in person, for their own Home dashboards and tabs only (self-service; API tokens get 403 `person_required`; [DASHBOARD.md](DASHBOARD.md#roles)) |
| `POST /api/subsidiary/v1/enroll` | Anyone with a subsidiary's one-time enrollment code (public, throttled like sign-ins) |
| every other `/api/subsidiary/v1/*` route | A `subsidiary` token only, for its own subsidiary (401 without a token; 403 for people and other tokens) |

The UI hides controls your role cannot use, but that is a convenience only: the server checks the
role on every call.

Refusals:

| Status | Body | When |
| --- | --- | --- |
| 401 | `{"detail": "Sign in required"}` | No valid session or token on a protected endpoint. |
| 403 | `{"detail": "Your role (viewer) cannot do this."}` | The role is too low. |
| 403 | `{"detail": "Change your password first.", "code": "password_change_required"}` | The account must change its password; only `GET /api/auth/me`, `POST /api/auth/logout` and `POST /api/auth/password` work until it does. |
| 403 | | An `integration` token on anything other than its two endpoints. |
| 403 | `{"detail": "Subsidiary tokens can only use the subsidiary API."}` | A `subsidiary` token outside `/api/subsidiary/v1/*`; people and other tokens on that API get `{"detail": "Only a subsidiary's sidecar calls this API."}`. |
| 403 | `{"detail": "Missing X-Hub-Request header"}` | A state-changing browser request without `X-Hub-Request: 1` (see [Security notes](#security-notes)). |

## First-run setup

When the hub starts and there are no accounts yet, it needs a first administrator. Pick one of
three ways.

**Setup link (default).** The hub generates a one-time setup token, keeps it in memory and prints
a link before it starts serving:

```
Atrium running at http://127.0.0.1:8710  (data: /srv/atrium/.hub)
First run: create the administrator at http://127.0.0.1:8710/#/setup?token=...
```

Open the link, choose a username and a password (see [Password policy](#password-policy)), and
optionally a display name and email. This creates an `admin` account and signs you in.

- The token stops working as soon as any account exists; after that, setup answers `409`.
- Wrong tokens are throttled like failed sign-ins.
- Because the token lives in memory, every restart prints a new one. Set `HUB_SETUP_TOKEN` to use a
  fixed token instead.
- The link starts with `HUB_PUBLIC_URL`. If people reach the hub through another address (a
  reverse proxy, a hostname), set `HUB_PUBLIC_URL` so the printed link is right.

**From the environment.** Set `HUB_ADMIN_USERNAME` and `HUB_ADMIN_PASSWORD` before the first start.
The hub creates that administrator at start-up and logs it to the activity log. The password must
meet the password policy, otherwise the hub refuses to start. The variables are only read while
there are no accounts, so remove the password from the environment once the account exists.

**From the command line.** Create the administrator offline before starting the hub:

```bash
atrium user create alice --role admin
```

## Signing in

Usernames are case-insensitive (stored in lowercase), 2 to 64 characters long, and may contain
`a-z`, `0-9`, `.`, `_` and `-`, starting with a letter or digit.

| Response | Meaning |
| --- | --- |
| `200` + session cookie | Signed in. |
| `401 Invalid username or password.` | Unknown username or wrong password; the hub does not say which. |
| `403 This account is disabled.` | The password was right but an admin disabled the account. |
| `429 Too many failed sign-ins. Try again in N minutes.` | Throttled, see below. |

Unknown usernames are checked against a dummy password hash, so the response takes as long as for
a real account and does not reveal which usernames exist.

### Login throttling

Failed sign-ins are counted in memory over a sliding 15-minute window:

- **5 failures for the same username from the same IP address** lock that username out from that
  address;
- **20 failures from one IP address**, for any usernames, lock that address out entirely.

While locked out, sign-in answers `429` with a `Retry-After` header (seconds) and the detail
`Too many failed sign-ins. Try again in N minutes.`. The lockout lifts once enough failures have
aged out of the window. A successful sign-in clears the counter for that username and address.
Wrong setup tokens and a wrong current password in **Change password** count as failures too.

The counters are not persisted: restarting the hub clears every lockout.

The address is the one the hub sees on the connection. Behind a reverse proxy that is the proxy's
address, unless the hub trusts the proxy's `X-Forwarded-For` header: list the proxy in
`HUB_TRUSTED_PROXIES` (addresses or networks, comma separated; default `127.0.0.1` only, or uvicorn's
`FORWARDED_ALLOW_IPS`). In Docker the proxy is never `127.0.0.1` as the container sees it: it is the
bridge gateway (a proxy on the host, e.g. `172.18.0.1`) or the proxy container's address, so set
`HUB_TRUSTED_PROXIES` in `.env` to that address or network. Trust only the proxy: a trusted address
can claim any client address.

When every client still appears as one address, an anonymous client could lock everyone out with
the per-address limits. A browser that signed in successfully before therefore keeps its own count:
a successful password sign-in sets the `atrium_device` cookie (encrypted with the hub's key,
`HttpOnly`, `SameSite=Strict`, `Path=/api/auth`, 180 days), and that browser's attempts for that
username count against that browser alone (5 failures lock it), never against the address. So an
attacker's failures cannot lock the administrator out of their usual browser; new browsers wait for
the lockout to lift (or for `HUB_TRUSTED_PROXIES`).

### Activity log

| Event | Actor | Level |
| --- | --- | --- |
| Successful sign-in (password, setup or SSO) | the username | info |
| Failed sign-in, with username and IP | `auth` | warn |
| Lockout | `auth` | warn |
| Failed single sign-on (the provider's error code, never its text; at most 20 per address and 200 in all per 15 minutes, then one note that further ones are not logged) | `auth` | warn |
| Sign-out | the username | info |
| Account and token changes | the acting admin (`cli` for the command line, `hub` for the administrator from the environment) | info |

Every activity entry is stored with the hub's secrets and credential-looking pairs (`password=...`,
`Authorization: Bearer ...`) masked, whoever wrote it. An entry an agent writes while it works on a person's private
chat (or on an approval asked for in one) is stored without the strings that quote the chat; that person reads the
original.

Approval decisions record who decided them (`decided_by`) in the approval history. The person who proposed an
approval cannot approve it while its second-person guardrail is on (403, `code: same_person`; they can still reject
it): `device_changes_need_second_person` (default on) for device changes, `approvals_need_second_person` (default off)
for self-patches and other approvals that record their proposer. An API token counts as the person who created it,
so an administrator cannot approve their own proposal with a token they made (nor the other way round), and device
changes are approved by people only: a token gets 403 `person_required` (it can still reject). An approval past its
`expires_at` can only be rejected.

## Sessions and cookies

Signing in creates a session and sets the cookie `atrium_session`:

| Property | Value |
| --- | --- |
| Value | 256 random bits (`secrets.token_urlsafe(32)`) |
| Flags | `HttpOnly`, `SameSite=Lax`, `Path=/` |
| `Max-Age` | the absolute session lifetime |
| `Secure` | when the request reached the hub over `https`, or always with `HUB_COOKIE_SECURE=1` |

The hub stores only the SHA-256 hash of the cookie value, in the `sessions` collection, together
with the account, creation time, last activity, expiry, IP address and user agent. A copy of the
database is therefore not enough to take over a session.

A session ends when either limit is reached:

| Limit | Setting | Default |
| --- | --- | --- |
| Idle timeout: no request for this long | `HUB_SESSION_IDLE_MINUTES` | 720 (12 hours) |
| Absolute lifetime, however active | `HUB_SESSION_DAYS` | 7 |

Activity refreshes a session's last-seen time at most once a minute. Expired and idle sessions are
deleted when they are next presented, and at start-up. The live event stream re-checks its session
or token every 15 seconds and closes once it is no longer valid; the UI then shows the sign-in
screen with "Your session ended. Sign in again."

Each person can see their own sessions under **user menu -> Sessions** (`GET /api/auth/sessions`)
and sign out all the others (`DELETE /api/auth/sessions`).

What ends sessions:

| Action | Sessions ended |
| --- | --- |
| Sign out | this session |
| Change your own password | all your other sessions (the current one stays) |
| Sessions -> Sign out other sessions | all your other sessions |
| Admin resets the password | all of that person's sessions |
| Admin disables or deletes the account (also the People leaver action) | all of that person's sessions, and the API tokens the account owns are revoked |
| `atrium user passwd` | all of that person's sessions |
| Single sign-on refuses the person (no Atrium group any more, default role `none`) | all of that person's sessions |

An API token acts for the account that created it (see [API tokens](#api-tokens)): demoting that
account lowers what its tokens may do at once, and disabling or deleting it revokes them.

## Password policy

Passwords must

- be 12 to 256 characters long,
- not contain the username (case-insensitive),
- contain at least 5 different characters.

A passphrase of several unrelated words is the easiest way to meet the policy. Violations are
reported with a message that says which rule failed.

Passwords are hashed with scrypt (`N=2^14`, `r=8`, `p=1`, 32-byte key, 16-byte random salt per
password). No endpoint ever returns a password hash.

## Changing and resetting passwords

- **Your own password**: user menu -> **Change password**, with your current password and a new
  one. The new password must differ from the current one. Your other sessions are signed out.
  Accounts that sign in through single sign-on have no hub password; the option is hidden and the
  API answers `400 Your account signs in through single sign-on.`
- **Someone else's password** (admins): **Users & access** -> **Reset password**. You set a
  temporary password; by default the person must change it at their next sign-in. All of their
  sessions are signed out. Admins change their own password through Change password, not here.
  SSO accounts cannot be reset.
- **Forced change**: an account flagged "must change password" (new accounts and resets by default)
  sees only the change-password screen after signing in. Until it changes the password, the API
  refuses everything except `GET /api/auth/me`, `POST /api/auth/logout` and
  `POST /api/auth/password` with `403` and `"code": "password_change_required"`.
- **Locked out of every admin account**: use the command line, see [below](#command-line).

## Managing accounts

Admins manage accounts under **Users & access** (`#/users`; also in Portals and Ctrl K):

- **Add user**: username, role, optional display name and email, and a temporary password the
  person must change at first sign-in (`POST /api/users`, `must_change_password` defaults to true).
- **Role**: change it in the table (`PATCH /api/users/{id}`).
- **Disable / enable**: a disabled account cannot sign in and all its sessions end at once. Its
  name stays in the activity log and approval history.
- **Reset password**: see above.
- **Delete**: removes the account and its sessions.

The table also shows the person (People app) with the same email address, and warns when that person has left but the
account is still enabled ([PEOPLE.md](PEOPLE.md#leavers)).

Guards (`400` with an explanation):

- you cannot disable, demote or delete your own account;
- the last enabled admin can never be disabled, demoted or deleted.

A duplicate username answers `409`. Every change is written to the activity log under the acting
admin's name, and the GRC Supervisor re-evaluates the compliance controls afterwards.

## API tokens

API tokens let scripts, adapters and other tools call the API without a session.

**Create** one under **Users & access -> API tokens** (`POST /api/tokens`):

| Field | Meaning |
| --- | --- |
| Name | Unique; shows up in the activity log as `token:<name>`. |
| Role | `viewer`, `operator`, `admin` or `integration`. |
| Expiry | 1 to 3650 days, or never. |

The secret, `atr_` followed by a random string, is shown **once**, right after creation. Copy it
then: the hub stores only its SHA-256 hash and the first 8 characters after `atr_` (the prefix
shown in the token list so you can tell tokens apart). The list also shows who created each token,
when, its expiry and when it was last used (updated at most once a minute). **Revoke** deletes a
token; it stops working immediately.

**A token acts for the account that created it** (its owner: that person, or the person behind the
token that created it - stored as the account's id, so a later account with the same name is
someone else). It works only while that account exists and is enabled, and never with more than
the account's current role: an admin token of someone demoted to viewer acts as a viewer, and
disabling or deleting the account (on **Users & access**, or with the People app's leaver action)
revokes its tokens. Create tokens for shared automation from an account that stays. Tokens stored
before this rule are bound to the account named by their creator at their first use, and refused
when there is none.

**Use** it in the `Authorization` header:

```bash
curl -H "Authorization: Bearer $HUB_TOKEN" http://127.0.0.1:8710/api/tools
```

- A request with a Bearer token is judged by that token alone; a session cookie on the same request
  is ignored. An unknown, revoked or expired token gets `401` on protected endpoints.
- Bearer requests do not need the `X-Hub-Request` header (browsers never add `Authorization`
  headers on their own, so there is no cross-site request to guard against).
- A token acts with its role, capped by its owner's. On the agent bus and in the activity log it
  appears as `token:<name>`.
- Tokens are automation, not people: commands a token sends to the Operator Agent follow the
  autonomy level exactly like agent commands (in `assisted`, only known read-only commands run
  without approval), and a command on the hub machine from a token without the admin role always
  waits for an administrator. Commands a signed-in person types run directly, within
  [Commands on the hub machine](#commands-on-the-hub-machine).
- Tokens cannot use the self-service endpoints (passwords, sessions, personal dashboards); they read the shared
  dashboards only.

### Integration tokens for tools that publish events

Tools and adapters that publish events to the hub bus should use a token with the `integration`
role. It can call `POST /api/bus/publish` and `GET /api/health` and nothing else, so a leaked
token cannot read hub data or change anything.

```bash
curl -X POST http://127.0.0.1:8710/api/bus/publish \
  -H "Authorization: Bearer $HUB_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source": "crm-app", "event": "crm.deal.won", "payload": {"deal": 42}}'
```

The event adapters the Patch Agent generates read the token from the `HUB_TOKEN` environment
variable and send it this way. The event format is described in [MANIFEST.md](MANIFEST.md#events).

An integration token speaks for **one tool**: the tool id given when it is created (**Publishes
events as tool**, `tool_id` in `POST /api/tokens`; default: the token's name). An event with any
other `source` is refused with `403`, so a leaked or misbehaving adapter cannot forge another tool's
events (an identity provider's `user.deleted`, say). Integration tokens from before this rule are
bound to the first source they publish as. The delivery log records who published each event
(`by`, e.g. `token:grafana-events`).

### Subsidiary tokens

The sidecar of an agent team inside a tool ([SUBSIDIARIES.md](SUBSIDIARIES.md)) has a token of its own role,
`subsidiary`. It is never created on **Users & access** (`POST /api/tokens` refuses the role):

- **Enrollment.** An administrator, signed in as a person, issues a one-time code on the subsidiary's Setup tab
  (`POST /api/subsidiaries/{tool}/enrollment`): 32 random bytes, valid 30 minutes, shown once, of which Atrium keeps
  only the SHA-256. The sidecar sends it with its own public key to `POST /api/subsidiary/v1/enroll` (public, single
  use, throttled per address like sign-ins) and receives the token. Issuing a new enrollment revokes the current
  token.
- **Owner binding.** The token is owned by the administrator who issued the enrollment and works only while that
  account exists, is enabled and is an administrator; disabling, deleting or demoting it revokes the token, and the
  subsidiary shows the flag `owner_disabled` until another administrator enrolls the sidecar again.
- **Lifetime.** 30 days; the sidecar asks for a new one at half-life (`POST /api/subsidiary/v1/rotate`), and the old one
  works until the new one is first used.
- **Reach.** Only `/api/subsidiary/v1/*`, and only its own subsidiary: everywhere else 403. Its actor and bus id are
  `subsidiary:<tool>`, never a person, so it can neither propose nor decide approvals.

## Commands on the hub machine

Commands on the machine Atrium runs on run as Atrium's own OS account: they can read and write its
data directory (`hub.db`, `secret.key`) and so every stored credential, and change accounts and
roles. Running code there is therefore an **administrator's** power:

| Who | Command on the hub machine (`POST /api/commands` with target `local`, the provider registrations) | Starting a tool (`POST /api/tools/{id}/start`: its launch command) |
| --- | --- | --- |
| Administrator (signed in) | runs directly (blocked patterns are refused) | runs directly |
| Operator (signed in), or a token without the admin role | read-only commands run; anything else becomes a `command` approval that only an administrator can approve | becomes a `process` approval that only an administrator can approve |
| Agents | follow the autonomy level; an approval for a command on the hub machine or a tool start needs an administrator. An agent acting on a person's chat message or manual run (the Hub Supervisor's chat, a team agent's chat or `POST /api/agents/{id}/run`) acts for that person: their commands and tool starts follow the rows above, in any autonomy level | the same |

Operators keep running commands on SSH hosts as before. The read-only list (the same one agents use
in `assisted`) accepts only display options: `git status/log/diff/show/rev-parse/describe` take
their listing and formatting options and revisions or paths in the repository - not `--output`,
`--no-index`, external diff or textconv drivers, `-O` / `--pathspec-from-file`, or `<rev>:<path>`;
`git diff` takes at most one revision or path (`a..b` for two revisions; with two paths git compares
any two files outside a repository); `git branch` / `git tag` only list, and `git remote -v` (which
may print a credential in a remote's URL) is not on the list. `hostname`, `date`, `ifconfig` and
`ipconfig` are read-only only in their display forms (`hostname -f`, `date -u`, `ifconfig -a`,
`ifconfig eth0`, `ipconfig /all`): with a name, `-s` / `--set`, `-f FILE` (GNU `date` prints the
file's lines in its errors), `eth0 down` or `/release` they need approval. `kubectl get/describe/top`
take names, `-n`, `-l`, `-A` and the `wide/name/json/yaml` outputs - never secrets, `--server`,
`--raw`, `--kubeconfig`, `-f` or a template file. `type` is not on the list (on Windows it prints a
file). No read-only command may name the data directory, `secret.key`, `hub.db`, `.env`, `.hub`,
`.ssh`, `.kube` or an SSH key.

Whatever a command prints is masked before it is stored in the command history, published or
returned to the agent (and its model) that ran it: every secret value the hub holds (the encryption
key from `HUB_SECRET_KEY` or `secret.key`, the settings from the environment, the stored tool, AI
provider and SSO credentials), credential-looking `key=value` pairs and the user info of URLs
(`https://user:token@host`) become `***`. Viewers read the command history and the agents' messages; a command run
for a person's private chat is stored there without the strings that quote the chat (its person reads the original). `autonomous` lets agents run anything that is not blocked on their own (scheduled tasks, the
hub's own work), but not on an operator's behalf: what an operator asks an agent for in chat or in a
manual run carries the operator's identity to the Operator Agent (`requested_by` in the approval)
and waits for an administrator like the operator's own command.

Commands and tool processes started from the hub never inherit Atrium's own settings and
credentials: variables starting with `HUB_`, `ANTHROPIC_`, `GH_` or `GITHUB_`, or named like a
credential (`*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*KEY`-style API keys, `*AUTH*`, ...), are removed
from their environment. A tool gets the variables of its manifest's `launch.env`; a registration
script reads the credentials it needs from the `.env` file next to it.

## Command line

Account management also works from the command line, directly against the database in the data
directory. The hub does not need to be running, which makes this the recovery path when nobody can
sign in.

```
atrium user list                [--data-dir DIR]
atrium user create USERNAME     [--role viewer|operator|admin] [--display-name NAME] [--email EMAIL]
                                [--password-stdin] [--data-dir DIR]
atrium user passwd USERNAME     [--password-stdin] [--data-dir DIR]
```

- `--data-dir` defaults to `HUB_DATA_DIR` (from the environment or `.env`), else `./.hub`. Point it
  at the same directory the hub uses.
- Passwords are asked for twice on the terminal. With `--password-stdin` the first line of standard
  input is used instead, for scripts.
- `user list` prints username, role, sign-in method (`local` or `oidc`), status and last sign-in.
- `user create` creates a local account; the role defaults to `viewer`. The account is not asked to
  change its password.
- `user passwd` sets a new password, clears "must change password" and signs out all of the
  account's sessions.
- Changes are logged to the activity log with the actor `cli`.

Recovery when every admin is locked out or has forgotten their password:

```bash
atrium user passwd alice --data-dir /srv/atrium/.hub
# or create a second administrator
atrium user create rescue --role admin --data-dir /srv/atrium/.hub
```

A sign-in lockout (`429`) also clears when the hub restarts.

`atrium` with no subcommand still runs the hub; `atrium serve` is the same.

## Single sign-on (OIDC)

The hub can sign people in through the suite's identity provider (Keycloak, Microsoft Entra ID,
Okta, Authentik, ...) with the OpenID Connect authorization code flow. MFA, password rules and
joiner/mover/leaver processes then live in the identity provider.

When SSO is configured, the sign-in screen shows a button ("Sign in with <provider>" when it is set
up in the [Sign-in & SSO settings](#sign-in--sso-settings), else `HUB_OIDC_LABEL`, default "Sign in
with SSO"). It goes to `/api/auth/oidc/login`, which redirects to the identity provider; the provider
sends the browser back to `/api/auth/oidc/callback`, where the hub checks the response, verifies
the ID token's signature, creates the session and returns to the hub. A short-lived cookie,
`atrium_oidc_state` (`HttpOnly`, `SameSite=Lax`, 10 minutes, `Path=/api/auth/oidc`), ties the
callback to the browser that started the sign-in and is deleted in the callback. The state value
itself carries the sign-in's nonce, PKCE verifier and expiry, encrypted with a key of the running
hub, so the hub keeps nothing per started sign-in and a flood of anonymous starts cannot push anyone's
sign-in out; each state works once. If anything fails, the browser lands on the sign-in screen
(`/#/login`) with the reason, and the failure is logged under `auth` - with the provider's error code only, never its
free text, and at most 20 entries per address and 200 in all per 15 minutes (the callback is public).

The reason never travels in the URL. The callback puts it in the cookie `atrium_sso_notice` (`HttpOnly`,
`SameSite=Lax`, 5 minutes, `Path=/api/auth`), encrypted with a key of the running hub. The next
`GET /api/auth/me` returns it once as `sso_error` and deletes the cookie, and the sign-in screen shows only that
value. The screen ignores any `?error=` in the address. So a link like `/#/login?error=Reset your password at ...`,
or a cookie set by a page on another port of the same host (cookies do not separate ports), cannot make the hub's
sign-in page show someone else's text. When the identity provider sends back an error, the person sees "The
identity provider refused the sign-in", with the code added when it is a standard OAuth 2.0 or OpenID Connect
error code such as `access_denied`. The provider's `error_description` is never shown, because anyone can send a
browser to the callback with a description of their own.
The activity log pages back with `GET /api/activity?before=<seq>`, so a burst of entries never puts
older ones out of reach.

Before first-run setup (no account yet), single sign-on only lets in someone the provider maps to
`admin`: anyone else is refused, so the setup link keeps working until an administrator exists.

### Configuration

SSO is enabled when an issuer and a client id are both set: in **Settings > Sign-in & SSO** (stored in
the database, effective at once; see [below](#sign-in--sso-settings)) or with these environment variables
(read at start-up: restart the hub after changing them). A variable that is set wins over the stored value
for that field.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_OIDC_ISSUER` | | Issuer URL of the provider, e.g. `https://sso.example.com/realms/hub`. |
| `HUB_OIDC_CLIENT_ID` | | Client id registered for the hub. |
| `HUB_OIDC_CLIENT_SECRET` | | Client secret (confidential client). |
| `HUB_OIDC_SCOPES` | `openid profile email` | Scopes to request. |
| `HUB_OIDC_ROLE_CLAIM` | `groups` | Claim that carries the role information. Dotted paths reach into nested claims, e.g. `realm_access.roles`. |
| `HUB_OIDC_ADMIN_VALUES` | `atrium-admins` | Comma-separated claim values that grant `admin`. |
| `HUB_OIDC_OPERATOR_VALUES` | `atrium-operators` | Comma-separated claim values that grant `operator`. |
| `HUB_OIDC_VIEWER_VALUES` | | Comma-separated claim values that grant `viewer` (useful with the default role `none`). |
| `HUB_OIDC_DEFAULT_ROLE` | `viewer` | Role for everyone else (`viewer`, `operator` or `admin`), or `none`: refuse their sign-in, so only members of the Atrium groups get in. Settings saved in the UI start with `none`. |
| `HUB_OIDC_ALLOWED_DOMAINS` | | Comma-separated email domains whose accounts may sign in: Google's hosted-domain (`hd`) claim, else the domain of an email the provider marks verified. Empty: any. |
| `HUB_OIDC_LABEL` | `Sign in with SSO` | Text of the sign-in button. Without it, Sign-in & SSO settings that name a provider make it "Sign in with <provider>". |
| `HUB_OIDC_ALLOW_HTTP` | off | Allow a plain-`http` issuer that is not on `localhost` / `127.0.0.1`. Leave it off outside a lab. |

Register this **redirect URI** with the provider:

```
{HUB_PUBLIC_URL}/api/auth/oidc/callback        e.g. https://hub.example.com/api/auth/oidc/callback
```

Open the hub at exactly the `HUB_PUBLIC_URL` address. The state cookie is set for the host you
started the sign-in on; if the provider then returns to a different host (`localhost` versus
`127.0.0.1`, say), the cookie is missing and the sign-in fails.

### Sign-in & SSO settings

Administrators manage the OIDC sign-in from the UI: **Settings > Sign-in & SSO** (`#/settings/sso`, also linked from
the Users & access card). The settings are stored in the database (`settings` collection, document `sso`) with the
client secret encrypted with the hub's secret key ([INTEGRATIONS.md](INTEGRATIONS.md#credentials-and-the-secret-key)).
Saving rebuilds the hub's OIDC client at once, with every check described above; sign-ins already started at that
moment are dropped and have to start again.

**Presets** fill in the issuer pattern, scopes, role claim and role values, and show setup notes:

| Preset | Issuer | Roles from |
| --- | --- | --- |
| Okta | `https://<your-domain>/oauth2/default` (the default custom authorization server) or `https://<your-domain>` (the org server) | `groups`; Okta does not add a groups claim by itself: add one (custom server: Security > API > Authorization Servers > Claims; org server: the app's Sign On tab), filtered e.g. to groups starting with `atrium-`, and request the `groups` scope |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` (the tenant id, not `common`) | app roles `atrium-admins` / `atrium-operators` in the `roles` claim, or a `groups` claim, which carries group object IDs: enter those IDs as the values. Set **Assignment required** to Yes on the enterprise application: otherwise every member and guest of the tenant can sign in |
| Google | `https://accounts.google.com` | none: Google ID tokens carry no groups, so everyone allowed in gets the default role. With an External consent screen any Google account can authenticate: use an Internal one (Google Workspace), list your domains under **Allowed domains**, then set the default role to `viewer`. Keep a local administrator |
| Keycloak | `https://<host>/realms/<realm>` | `groups` (a group membership mapper without the full path; Atrium's generated client sets this up) |
| authentik | `https://<host>/application/o/<slug>/` | `groups` (sent by default) |
| Other | any provider with OpenID Connect discovery | `groups` |

The Okta, Entra ID and Google notes were checked against the vendors' documentation in October 2026.

Identity providers already **imported into the suite** (Keycloak, authentik) appear as prefilled choices. When Atrium's
own client was generated there (Integration hub > Identity > **Atrium sign-in**, see
[below](#generating-atriums-client-from-the-integration-hub)), **Use the client secret Atrium generated at
<provider>** takes that secret without showing it.

Rules:

- **Environment variables win.** Every field set by a `HUB_OIDC_*` variable (one with a value; `.env` counts) is
  shown read-only with the variable's name, and saving leaves it alone. Remove the variable or leave it empty (and
  restart) to manage the field from the UI. A `.env` copied from an older `.env.example` sets `HUB_OIDC_SCOPES`,
  `HUB_OIDC_ROLE_CLAIM`, `HUB_OIDC_ADMIN_VALUES`, `HUB_OIDC_OPERATOR_VALUES`, `HUB_OIDC_DEFAULT_ROLE` and
  `HUB_OIDC_LABEL` to their defaults, which locks those fields: empty those lines.
- **The secret is write-only.** The field never shows the stored value: leave it empty to keep it, enter a new one, or
  clear it. A stored secret is only sent to the issuer it was entered for: changing the issuer means entering the
  secret again.
- **The label** becomes "Sign in with <provider name>" (unless `HUB_OIDC_LABEL` is set).
- **Validation**: the issuer must be `https` (plain `http` only on `localhost` / `127.0.0.1`, or with **Allow a
  plain-http issuer**, which asks for confirmation and is logged as a warning); `<placeholders>` left in the issuer
  are refused.
- **Test** runs OpenID Connect discovery and fetches the signing keys for the values in the form, without saving
  anything or sending the secret. It applies the same discovery checks as sign-in and reports the endpoints, the number
  of signing keys, PKCE support, and whether the provider advertises the role claim.
- **Remove** deletes the stored settings; environment variables still apply.
- Every change is written to the activity log with the admin's name, and the compliance controls are re-evaluated
  (HB-AC-4 passes once SSO is configured).

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/auth/sso` | admin | the effective values and where each comes from (`environment`, `database` or `default`), whether a secret is set, the redirect URI, presets and imported providers; never the secret |
| `PUT /api/auth/sso` | admin | change the fields sent (`preset`, `provider_name`, `issuer`, `client_id`, `client_secret`, `clear_client_secret`, `generated_secret_from`, `scopes`, `role_claim`, `admin_values`, `operator_values`, `viewer_values`, `default_role` (`none` refuses), `allowed_domains`, `allow_http`) |
| `POST /api/auth/sso/test` | admin | the same body: discovery and signing keys, nothing saved |
| `DELETE /api/auth/sso` | admin | remove the stored settings |

### Role mapping

At every SSO sign-in the hub reads the claim named by `HUB_OIDC_ROLE_CLAIM`. A value listed in
`HUB_OIDC_ADMIN_VALUES` makes the person an `admin`, one in `HUB_OIDC_OPERATOR_VALUES` an
`operator`, one in `HUB_OIDC_VIEWER_VALUES` a `viewer`; everyone else gets `HUB_OIDC_DEFAULT_ROLE` -
or, with `none`, is refused ("Your account is not in an Atrium group at the identity provider") and
the sessions of their existing account end. Every account the provider authenticates otherwise
becomes at least a viewer, and viewers read people, assets, vulnerabilities and the activity log:
pick `none`, or restrict who the provider lets into the application.

The sync never demotes the **last enabled administrator**: when the provider gives them a lower
role, they keep `admin` and a warning is logged (make someone else an admin first), as for the
Users & access page.

### SSO accounts

- The first SSO sign-in creates a hub account with sign-in method `oidc` and no password. Its
  username comes from the identity the provider returns; if that name is taken, `-2`, `-3`, ... is
  appended.
- The account is linked by issuer and subject (`<issuer>|<sub>`), not by username. An existing
  local account with the same name stays a separate account.
- The role is synced from the provider at every sign-in. Manage SSO roles in the provider: a role
  changed in the hub is overwritten the next time the person signs in.
- The email is synced too, but only one the provider does not mark unverified (`email_verified:
  false`, e.g. after a self-service change at Keycloak) - otherwise the account keeps its email. When
  the email changes, a warning is logged and the account stays linked to the person with the old
  address in the People app (`previous_emails`), so an address change at the provider never hides
  a leaver.
- Disabling the account in the hub blocks it whatever the provider says.
- Signing out of the hub ends the hub session only, not the session at the identity provider.
- Local password sign-in stays available. Keep one local admin account with a strong password as a
  way in when the identity provider is down. HB-AC-5 (dormant accounts) flags it once it has not
  signed in for 90 days: sign in with it now and then, or record an override with a justification
  in the Compliance hub.

### Generating Atrium's client from the Integration hub

When the suite contains an identity provider (Keycloak, authentik, or any OIDC provider), an administrator can let
the hub prepare Atrium's own client: **Integration hub > Identity > Atrium sign-in** (`POST
/api/identity-providers/{id}/atrium`). The hub writes into `HUB_DATA_DIR/workspace/identity/atrium/<provider>/`:

- the client registration (`keycloak-client.json` with a kcadm.sh script, or an authentik blueprint), with redirect
  URI `{HUB_PUBLIC_URL}/api/auth/oidc/callback`, a `groups` claim and the groups `atrium-admins` and `atrium-operators`;
- `atrium-oidc.env` with the `HUB_OIDC_*` settings, including a client secret generated once by the hub.

The secret is never shown in the UI or returned by the API. Then either choose the provider under **Settings > Sign-in &
SSO** (it is listed as imported, and the generated secret can be used without being shown; no restart), or copy the
lines from `atrium-oidc.env` into Atrium's `.env` and restart Atrium. **Register at <provider>** has the Operator
Agent run the registration script (docker compose exec
into the provider when the hub knows its compose file; otherwise set `KEYCLOAK_ADMIN_USER` and
`KEYCLOAK_ADMIN_PASSWORD` for `register-keycloak.sh`). The walkthrough below does the same by hand.

### Keycloak walkthrough

[`examples/keycloak`](../examples/keycloak) runs Keycloak in development mode on
`http://localhost:8080` (admin console login `admin` / `change-me`; development only). The steps
below assume the hub runs at `http://127.0.0.1:8710`.

1. **Start Keycloak.**
   ```bash
   cd examples/keycloak
   docker compose up -d
   ```
   Open <http://localhost:8080> and sign in to the administration console.
2. **Create the realm.** Realm drop-down -> **Create realm**, name `hub`, **Create**.
3. **Create the client.** In realm `hub`: **Clients -> Create client**.
   - Client type `OpenID Connect`, Client ID `atrium` -> **Next**.
   - **Client authentication** On (this makes it a confidential client); authentication flow
     **Standard flow** only -> **Next**.
   - **Valid redirect URIs** `http://127.0.0.1:8710/api/auth/oidc/callback`; **Root URL** and
     **Home URL** `http://127.0.0.1:8710` -> **Save**.
   - Tab **Credentials**: copy the **Client secret**.
4. **Create the groups.** **Groups -> Create group** `atrium-admins`, then `atrium-operators`.
5. **Add a groups mapper.** **Clients -> atrium -> Client scopes -> atrium-dedicated -> Configure a
   new mapper** (or **Add mapper -> By configuration**) **-> Group Membership**:
   - Name `groups`, Token Claim Name `groups`,
   - **Full group path** Off (otherwise the values are `/atrium-admins` and do not match),
   - **Add to ID token**, **Add to access token** and **Add to userinfo** On -> **Save**.
6. **Create people.** **Users -> Create new user** (username, email, first and last name, Email
   verified On) -> **Create**. Tab **Credentials -> Set password**. Tab **Groups -> Join group** ->
   `atrium-admins` or `atrium-operators` (no group: `HUB_OIDC_DEFAULT_ROLE`).
   To require MFA: **Authentication -> Required actions**, set **Configure OTP** as a default
   action, or add it to a user's **Required user actions**.
7. **Configure the hub** in `.env` and restart it:
   ```
   HUB_OIDC_ISSUER=http://localhost:8080/realms/hub
   HUB_OIDC_CLIENT_ID=atrium
   HUB_OIDC_CLIENT_SECRET=<client secret from step 3>
   ```
   Plain `http` is accepted here because the issuer is on `localhost`.
8. **Sign in.** Open <http://127.0.0.1:8710>, sign out, and choose **Sign in with SSO**. The person
   gets the role of their group; the Compliance hub now shows HB-AC-4 as passing.

To map Keycloak realm roles instead of groups, create realm roles named `atrium-admins` and
`atrium-operators` (or list your own names in `HUB_OIDC_ADMIN_VALUES` / `HUB_OIDC_OPERATOR_VALUES`),
set `HUB_OIDC_ROLE_CLAIM=realm_access.roles`, and make sure the realm roles mapper adds the claim to
the ID token and userinfo.

## Compliance

Two controls of the Hub Security Baseline check the hub's own access control:

| Control | Passes when | Otherwise |
| --- | --- | --- |
| HB-AC-4 Authenticated, role-based access to the hub | SSO (OIDC) is configured, with environment variables or the Sign-in & SSO settings. | `partial` with local passwords only ("connect the suite's identity provider (OIDC) to enforce MFA"); `fail` when there is no enabled admin. |
| HB-AC-5 Dormant hub accounts are disabled | No enabled account has gone 90 days without signing in (accounts that never signed in count from their creation). | `partial` when some enabled accounts are dormant, `fail` when all are; `manual` when there are no accounts. |

Both are re-evaluated after account changes. Failing controls open the risks "Hub accounts are
protected by passwords only" and "Dormant accounts could be misused".

A third, HB-AC-7 "Leavers lose access and return assets", fails while a person the People app knows as suspended or
terminated still has an enabled Atrium account with their email address (or an active account in a tool). The
**Disable Atrium account** action on the leaver (admin) disables it through the normal account update. See
[PEOPLE.md](PEOPLE.md#leavers).

## Security notes

- **Chats are private.** A person's chat with an agent reaches no other account: the agent keeps a separate memory per
  person (an API token shares its owner's; deleting an account drops its conversations), and the message log and the
  event stream carry a chat's routing and size, never its text. Where agents pass the person's words on to each other
  (also words from an earlier turn the agent remembers), the log keeps those strings replaced, and the Agent bus page
  shows the originals to that person only
  ([AGENTS.md](AGENTS.md#conversations-and-errors)). What is sent to an AI model has every secret the hub knows masked
  ([AGENTS.md](AGENTS.md#models-and-providers)).

- **Put TLS in front.** Without TLS, passwords and session cookies cross the network in clear text.
  Keep the hub bound to `127.0.0.1` and put a reverse proxy (Caddy, nginx, Traefik, ...) in front that
  terminates TLS. Then set:
  - `HUB_PUBLIC_URL=https://hub.example.com` - used for the setup link and the SSO redirect URI;
  - `HUB_ALLOWED_HOSTS=hub.example.com` - the hub rejects other `Host` headers;
  - `HUB_COOKIE_SECURE=1` - marks the session cookie `Secure` even though the proxy talks plain
    `http` to the hub (the hub only sees `https` itself when uvicorn trusts the proxy's
    `X-Forwarded-Proto` header).

  Binding to another interface (`atrium --host 0.0.0.0`) prints a warning, because the hub can run
  commands on its machine.
- **X-Hub-Request header.** Browser requests that change state (anything but `GET`, `HEAD` and
  `OPTIONS`) must carry `X-Hub-Request: 1`, or they get `403`. A page on another site cannot add a
  custom header without a CORS preflight, which the hub never grants; together with the
  `SameSite=Lax` cookie this stops cross-site request forgery. Requests with a Bearer token are
  exempt.
- **Host checking.** Requests whose `Host` header is not `127.0.0.1`, `localhost` or listed in
  `HUB_ALLOWED_HOSTS` are rejected before anything else runs, which defeats DNS rebinding.
- **No framing.** Every response carries `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors
  'none'`, so another site cannot embed the hub to trick a signed-in person into clicking (clickjacking).
  This includes a tool's page on another port of the same host, which counts as the same site for cookies.
- **What others write stays in its place.** The UI escapes everything it shows. A tool's own manifest can set
  only a hex colour and an icon of one or two characters for its tile ([MANIFEST.md](MANIFEST.md)), so it cannot add
  CSS that covers the page. The sign-in screen shows only notices the hub sealed itself, never text from the
  address (see [Single sign-on](#single-sign-on-oidc)). While a dialog is open, the rest of the page is inert, so
  Tab, clicks and screen readers stay inside the dialog. Following a link inside a dialog closes the dialog.
- **Secrets at rest.** Passwords are stored as scrypt hashes, session cookies and API tokens as
  SHA-256 hashes, and the API never returns any of them. Credentials the hub must use itself (tool
  connections, local model API keys, the stored SSO client secret) are encrypted with `HUB_SECRET_KEY` or
  `HUB_DATA_DIR/secret.key`. The database (`HUB_DATA_DIR/hub.db`) still holds everything else the hub knows
  (password hashes, rule bases, tools' launch environments): the hub creates the data directory and its
  workspace owner-only (`0700`, tightened at every start), `hub.db` with its `-wal` and `-shm` files `0600`, and
  secret files `0600` from the first byte. Keep it that way, include it in backups, and back up the key separately
  ([INTEGRATIONS.md](INTEGRATIONS.md#credentials-and-the-secret-key)).
- **Least privilege.** Give people the lowest role that fits, give event publishers
  `integration` tokens, set expiry dates on tokens, and revoke tokens and disable accounts that are
  no longer used.
- **Setup token.** The first-run link grants an admin account to whoever opens it first. Use it
  promptly, and do not paste it where others can read it.
