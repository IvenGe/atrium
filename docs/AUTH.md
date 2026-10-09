# Sign-in and access control

Every `/api` call, apart from a handful of public endpoints, needs a signed-in person or an API
token. People sign in with a local account (username and password) or through single sign-on
with an OpenID Connect identity provider. Programs use API tokens. What each caller may do is
decided by its role, on the server, for every request.

The UI files themselves (everything outside `/api`) are public: they contain no data, and the UI
shows the sign-in screen until you are signed in.

## Roles

Roles are ordered `viewer` < `operator` < `admin`; each role can do everything the roles before it
can. `integration` is a separate role that exists only for API tokens.

| Role | May do |
| --- | --- |
| `viewer` | Read everything: every page, every `GET /api` endpoint, the live event stream (`/api/events`) and the API docs (`/api/docs`). Changes nothing. |
| `operator` | Everything a viewer can, plus every state-changing call: import and remove tools, analyse, start/stop, propose patches, approve or reject, run commands, add/remove/discover hosts, add and edit assets, sync, edit compliance controls, risks and policies, chat with the Hub Supervisor and any team agent (`POST /api/agents/{id}/chat`), run a team agent's task (`POST /api/agents/{id}/run`) and ask a tool's supervisor for an agent team (`POST /api/tools/{id}/team`). |
| `admin` | Everything an operator can, plus accounts (`/api/users`), API tokens (`/api/tokens`), hub settings (`PATCH /api/settings`: autonomy level, default model, vulnerability SLA days, guardrails), the agent guardrails (`PATCH /api/settings/guardrails`), agent definitions (`POST /api/agents`, `PATCH` / `DELETE /api/agents/{id}`: create, configure and remove agents; core agents can only be paused and reconfigured), the AI model providers, which may hold API keys (`POST /api/llm/providers`, `PATCH` / `DELETE /api/llm/providers/{id}`, `POST /api/llm/providers/{id}/test`), the suite's identity providers (`PUT /api/identity-providers/default`, `PATCH /api/identity-providers/{id}`, `POST /api/identity-providers/{id}/atrium`) and tool connections, which hold the tools' API credentials (`PUT` / `DELETE /api/tools/{id}/connection`). Operators choose the provider per tool (`POST /api/tools/{id}/sso`) and run provider registrations (`POST /api/tools/{id}/sso/register`); they test connections, list a connection field's choices (`GET /api/tools/{id}/connection/options/{field}`, which uses the stored credentials), run, schedule and repair data flows, request scans and triage vulnerabilities. |
| `integration` | API tokens only. Exactly two calls: `POST /api/bus/publish` and `GET /api/health`. |

Endpoints outside the role ladder:

| Endpoints | Who |
| --- | --- |
| `GET /api/health`, `GET /api/auth/me`, `POST /api/auth/login`, `POST /api/auth/setup`, `GET /api/auth/oidc/login`, `GET /api/auth/oidc/callback` | Anyone (public) |
| `POST /api/auth/logout`, `POST /api/auth/password`, `GET` and `DELETE /api/auth/sessions` | Any signed-in person (self-service) |

The UI hides controls your role cannot use, but that is a convenience only: the server checks the
role on every call.

Refusals:

| Status | Body | When |
| --- | --- | --- |
| 401 | `{"detail": "Sign in required"}` | No valid session or token on a protected endpoint. |
| 403 | `{"detail": "Your role (viewer) cannot do this."}` | The role is too low. |
| 403 | `{"detail": "Change your password first.", "code": "password_change_required"}` | The account must change its password; only `GET /api/auth/me`, `POST /api/auth/logout` and `POST /api/auth/password` work until it does. |
| 403 | | An `integration` token on anything other than its two endpoints. |
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
address, unless uvicorn trusts the proxy's `X-Forwarded-For` header (by default it does so only for
a proxy on `127.0.0.1`; see uvicorn's `FORWARDED_ALLOW_IPS`). When every client appears as the
same address, the 20-failure limit applies to all of them together.

### Activity log

| Event | Actor | Level |
| --- | --- | --- |
| Successful sign-in (password, setup or SSO) | the username | info |
| Failed sign-in, with username and IP | `auth` | warn |
| Lockout | `auth` | warn |
| Sign-out | the username | info |
| Account and token changes | the acting admin (`cli` for the command line, `hub` for the administrator from the environment) | info |

Approval decisions record who decided them (`decided_by`) in the approval history.

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
| Admin disables or deletes the account | all of that person's sessions |
| `atrium user passwd` | all of that person's sessions |

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

**Use** it in the `Authorization` header:

```bash
curl -H "Authorization: Bearer $HUB_TOKEN" http://127.0.0.1:8710/api/tools
```

- A request with a Bearer token is judged by that token alone; a session cookie on the same request
  is ignored. An unknown, revoked or expired token gets `401` on protected endpoints.
- Bearer requests do not need the `X-Hub-Request` header (browsers never add `Authorization`
  headers on their own, so there is no cross-site request to guard against).
- A token acts with its role. On the agent bus and in the activity log it appears as
  `token:<name>`.
- Tokens are automation, not people: commands a token sends to the Operator Agent follow the
  autonomy level exactly like agent commands (in `assisted`, only known read-only commands run
  without approval). Commands a signed-in person types run directly.
- Tokens cannot use the self-service endpoints (passwords, sessions).

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

When SSO is configured, the sign-in screen shows a button (`HUB_OIDC_LABEL`, default "Sign in with
SSO"). It goes to `/api/auth/oidc/login`, which redirects to the identity provider; the provider
sends the browser back to `/api/auth/oidc/callback`, where the hub checks the response, verifies
the ID token's signature, creates the session and returns to the hub. A short-lived cookie,
`atrium_oidc_state` (`HttpOnly`, `SameSite=Lax`, 10 minutes, `Path=/api/auth/oidc`), ties the
callback to the browser that started the sign-in and is deleted in the callback. If anything fails,
the browser lands on the sign-in screen with the reason, and the failure is logged under `auth`.

### Configuration

SSO is enabled when `HUB_OIDC_ISSUER` and `HUB_OIDC_CLIENT_ID` are both set. Restart the hub after
changing these.

| Variable | Default | Meaning |
| --- | --- | --- |
| `HUB_OIDC_ISSUER` | | Issuer URL of the provider, e.g. `https://sso.example.com/realms/hub`. |
| `HUB_OIDC_CLIENT_ID` | | Client id registered for the hub. |
| `HUB_OIDC_CLIENT_SECRET` | | Client secret (confidential client). |
| `HUB_OIDC_SCOPES` | `openid profile email` | Scopes to request. |
| `HUB_OIDC_ROLE_CLAIM` | `groups` | Claim that carries the role information. Dotted paths reach into nested claims, e.g. `realm_access.roles`. |
| `HUB_OIDC_ADMIN_VALUES` | `atrium-admins` | Comma-separated claim values that grant `admin`. |
| `HUB_OIDC_OPERATOR_VALUES` | `atrium-operators` | Comma-separated claim values that grant `operator`. |
| `HUB_OIDC_DEFAULT_ROLE` | `viewer` | Role for everyone else (`viewer`, `operator` or `admin`). |
| `HUB_OIDC_LABEL` | `Sign in with SSO` | Text of the sign-in button. |
| `HUB_OIDC_ALLOW_HTTP` | off | Allow a plain-`http` issuer that is not on `localhost` / `127.0.0.1`. Leave it off outside a lab. |

Register this **redirect URI** with the provider:

```
{HUB_PUBLIC_URL}/api/auth/oidc/callback        e.g. https://hub.example.com/api/auth/oidc/callback
```

Open the hub at exactly the `HUB_PUBLIC_URL` address. The state cookie is set for the host you
started the sign-in on; if the provider then returns to a different host (`localhost` versus
`127.0.0.1`, say), the cookie is missing and the sign-in fails.

### Role mapping

At every SSO sign-in the hub reads the claim named by `HUB_OIDC_ROLE_CLAIM`. A value listed in
`HUB_OIDC_ADMIN_VALUES` makes the person an `admin`, one in `HUB_OIDC_OPERATOR_VALUES` an
`operator`; everyone else gets `HUB_OIDC_DEFAULT_ROLE`.

### SSO accounts

- The first SSO sign-in creates a hub account with sign-in method `oidc` and no password. Its
  username comes from the identity the provider returns; if that name is taken, `-2`, `-3`, ... is
  appended.
- The account is linked by issuer and subject (`<issuer>|<sub>`), not by username. An existing
  local account with the same name stays a separate account.
- The role is synced from the provider at every sign-in. Manage SSO roles in the provider: a role
  changed in the hub is overwritten the next time the person signs in.
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

The secret is never shown in the UI or returned by the API; copy the lines from `atrium-oidc.env` into Atrium's `.env`
and restart Atrium. **Register at <provider>** has the Operator Agent run the registration script (docker compose exec
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
| HB-AC-4 Authenticated, role-based access to the hub | SSO (OIDC) is configured. | `partial` with local passwords only ("connect the suite's identity provider (OIDC) to enforce MFA"); `fail` when there is no enabled admin. |
| HB-AC-5 Dormant hub accounts are disabled | No enabled account has gone 90 days without signing in (accounts that never signed in count from their creation). | `partial` when some enabled accounts are dormant, `fail` when all are; `manual` when there are no accounts. |

Both are re-evaluated after account changes. Failing controls open the risks "Hub accounts are
protected by passwords only" and "Dormant accounts could be misused".

## Security notes

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
- **Secrets at rest.** Passwords are stored as scrypt hashes, session cookies and API tokens as
  SHA-256 hashes, and the API never returns any of them. The database (`HUB_DATA_DIR/hub.db`) still
  holds everything else the hub knows; protect it with file permissions and include it in backups.
- **Least privilege.** Give people the lowest role that fits, give event publishers
  `integration` tokens, set expiry dates on tokens, and revoke tokens and disable accounts that are
  no longer used.
- **Setup token.** The first-run link grants an admin account to whoever opens it first. Use it
  promptly, and do not paste it where others can read it.
