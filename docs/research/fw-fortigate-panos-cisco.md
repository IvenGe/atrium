# Firewall and switch automation APIs: FortiGate, PAN-OS and IOS-XE (reference for Atrium connectors)

Research date: 2026-10-09. Read-only research. No repository files were changed.

## 0. How to read this

Each fact carries a tag and one or more source IDs. The IDs resolve in section 8.

| Tag | Meaning |
|---|---|
| **[V]** | Seen in official vendor documentation, vendor-maintained code (Fortinet Ansible collection, PANW `pan-os-python`, Cisco YANG models in `YangModels/yang`), or an IETF RFC. I fetched the page on 2026-10-09. |
| **[K]** | A vendor knowledge-base or technical-tip article written by vendor staff (Fortinet Community "Technical Tip", pan.dev tutorial). Official-ish, but not reference documentation. |
| **[S]** | An official page that I saw only as a search-result excerpt, not as a full page. |
| **[U]** | Unverified: third-party library, forum post or memory. |
| **[I]** | My own inference from verified facts. |

"Not found" means I looked and found no documented mechanism. It does not mean the mechanism cannot exist.

Context in this repo: connectors subclass `hub/connectors/base.py:Connector`. `http(verify=...)` accepts a CA-bundle path and never follows redirects. Errors are raised as `ConnectorError`. The current data domains are `assets`, `vulnerabilities`, `risks` and `controls`, so firewall and switch policy needs a new domain or new `action`s (see §6).

---

## 1. Cross-vendor summary

| | FortiGate (FortiOS) | PAN-OS | Cisco IOS-XE |
|---|---|---|---|
| Automation API | REST/JSON `/api/v2/cmdb/...` for config and `/api/v2/monitor/...` for state and actions [V F2][K F16] | XML API `/api/?type=...`, plus REST/JSON `/restapi/v{ver}/...` for objects and policies only [V P1][V P13] | RESTCONF `/restconf/data/...` and NETCONF over SSH port 830 [V C1][V C2] |
| Credential | REST API admin token in `Authorization: Bearer` [V F2] | API key from `type=keygen`, sent as `X-PAN-KEY` [V P6][V P8] | HTTP Basic or SSH with an AAA user at privilege 15; token auth not supported [V C1][V C2] |
| Read-only possible? | Yes, with a custom `accprofile` or `super_admin_readonly` [V F1] | Yes, with the dynamic roles Superuser (readonly) or Device admin (readonly) [V P7] | No documented read-only role for RESTCONF/NETCONF: privilege 15 is required [V C1][V C2] |
| Write lands in | Live config immediately; workspace "transactions" can stage a batch [V F4][V F5] | Candidate config, which needs a commit [V P1][V P2] | RESTCONF: running config immediately. NETCONF: candidate if enabled, otherwise running [V C2] |
| Apply step | None, or `transaction-commit` [V F4] | `type=commit` (async job), then poll `show jobs` [V P2] | None (RESTCONF). NETCONF `<commit>`. Persist with `cisco-ia:save-config` [V C2][V C6] |
| Native auto-rollback | `cfg-save revert`: global setting, unit reboots or reloads on timeout [K F7][S F6] | None for general commits (feature request FR 204 [U P32]). Panorama-managed firewalls get "automated commit recovery" for the Panorama connection only [V P29] | NETCONF confirmed commit, default 600 s [V C2]. CLI `configure terminal revert timer`, `configure replace ... time`, then `configure confirm` [S C5][V C3][V C4] |
| TLS default | HTTPS enforced [V F2]. From 7.2.1 the default cert is `Fortinet_GUI_Server`, signed by the built-in `Fortinet_CA_SSL`; earlier releases used a self-signed cert [S F17] | Self-signed by default [V P13] | Auto-generated self-signed `TP-self-signed-<n>` when no trustpoint is set [S C16] |
| Paging | `start` and `count`; some monitor endpoints cap at 1000 per call [K F11] | None documented for REST [V P14] | None in RFC 8040. `depth` and `fields` are supported [V C1] |
| Rate limit | Not found | REST: keep concurrent calls at 5 or fewer [V P13] | Not found |

---

## 2. Fortinet FortiGate (FortiOS 7.x; docs seen for 7.0.2–7.6.5 and 8.0.0)

### 2.1 Authentication and least privilege

- **REST API admin.** Create it in GUI under System > Administrators > Create New > REST API Admin, or in the CLI under `config system api-user` [V F1].
  - Only a `super_admin` can create one [V F1].
  - The token is shown once [V F1][V F2].
  - CLI sketch (exact leaf syntax is from Fortinet's Ansible module and the admin-guide summary, not a verbatim CLI page) [V F1][U]:
    ```
    config system api-user
      edit "atrium"
        set accprofile "atrium_ro"
        set vdom "root"
        config trusthost
          edit 1
            set ipv4-trusthost 10.20.0.5 255.255.255.255
          next
        end
      next
    end
    execute api-user generate-key atrium [expiry-minutes]
    ```
  - The expiry argument is optional, 1–10080 minutes (FortiOS 7.6.5) [V F2].
- **Sending the token.** Use the header `Authorization: Bearer <token>` (recommended) [V F2].
  - URL-query tokens need `config system global` / `set rest-api-key-url-query enable` [V F2].
  - URL-query tokens are disabled by default from FortiOS 7.4.5 [S/K F18]. Never use them.
  - HTTPS only; HTTP cannot be used [V F2].
  - REST API tokens cannot be used in FIPS-CC mode [K F16][V F4].
- **Trusted hosts.** You can configure several hosts or subnets, including IPv6. `0.0.0.0/0` is not permitted [V F1].
  - Before 7.4.1, the client IP also had to be in some `system admin` trusthost list, because admin trusthosts are enforced as kernel local-in policy and take precedence [K F10].
  - Pre-7.4.1 workaround: add the IP to a no-access admin account's trusthost [K F10].
- **Optional hardening.** A PKI group (client certificate and token must both match) and CORS allow-origin [V F1][V F2].
- **Read-only profiles.** Fortinet recommends a custom least-privilege `accprofile`. For generic read-only it names `admin_no_access` or `super_admin_readonly` [V F1].
  - `accprofile` groups: `scope` (vdom|global), `fwgrp`, `netgrp`, `sysgrp`, `loggrp`, `utmgrp`, `secfabgrp` take none|read|read-write|custom; `authgrp`, `vpngrp`, `wanoptgrp`, `wifi`, `ftviewgrp` take none|read|read-write [V F14].
  - Custom sub-permissions [V F14]:
    - `fwgrp-permission`: policy, address, service, schedule, others
    - `netgrp-permission`: cfg, packet-capture, route-cfg
    - `sysgrp-permission`: admin, upd, cfg, mnt
  - Ansible spells these with underscores; FortiOS uses hyphens [I].
- **Proposed read profile [I]:** `fwgrp=read`, `netgrp=read`, `sysgrp=read`, everything else `none`.
- **Proposed write profile [I]:** `fwgrp=custom` with policy, address and service read-write, schedule read, others read; `netgrp=read`; `sysgrp=read`.
- **Backups need more.** Fortinet KB says the API admin needs `super_admin` for `/monitor/system/config/backup` [K F8]. A read-only profile is not enough for backups [S, FortiSIEM guide excerpt].
  - Consequence [I]: either accept a super_admin token for backups only (separate secret, narrow trusthost), or skip full backups and rely on hub-recorded inverse operations plus config revisions (§2.4).
- **Workspace transactions** can be used by any admin within their profile's permissions [V F5].

### 2.2 Reading

URL root is `https://<fgt>[:port]/api/v2/`. Add `?vdom=<name>` for VDOM-scoped data [V F4][K F11].

Generic query parameters:
- `format=name|comment` limits returned fields [V F2].
- `filter=name=@SSLVPN` filters results [V F2].
- `start` and `count` page results; `summary_only=1` returns totals [K F11].

| Data | Request | Status |
|---|---|---|
| Firmware/OS version | `GET /api/v2/monitor/system/status`. The envelope carries `version` (e.g. `"v7.4.4"`), `build`, `serial`. `results` has `model`, `hostname`. `/api/v2/cmdb/system/status` was removed in 7.4.4 | [K F9] |
| Interfaces, VLAN subinterfaces, IP/mask, management access | `GET /api/v2/cmdb/system/interface`. VLAN subinterfaces carry `vlanid` and parent `interface`; management access is the space-separated `allowaccess` string | Path [U, third-party lib]; field names [U, forum F20] |
| Interface runtime state | `GET /api/v2/monitor/system/interface` | Selector `system_interface` [V F22]; URL mapping [I] |
| Zones | `GET /api/v2/cmdb/system/zone` | [U] |
| Address objects / groups | `GET /api/v2/cmdb/firewall/address` [V F2][V F3]; `GET /api/v2/cmdb/firewall/addrgrp` | addrgrp [U] |
| Service objects / groups | `GET /api/v2/cmdb/firewall.service/custom`, `.../firewall.service/group` | [U] (PowerFGT path, Ansible module names) |
| Firewall policies (ordered) | `GET /api/v2/cmdb/firewall/policy`. List order is evaluation order. `policyid` is an ID, not the position: the GUI "Seq#" differs from policy ID | Path [U, multiple consistent sources incl. Fortinet Terraform provider F15]; seq vs id [K, F19 search excerpt] |
| Policy fields | `policyid`, `name`, `uuid`, `status` (enable/disable), `action` (accept/deny/ipsec), `srcintf`/`dstintf`/`srcaddr`/`dstaddr`/`service` (lists of `{"name": ...}`), `schedule`, `logtraffic` (all/utm/disable), `logtraffic-start`, `nat`, `comments`, `srcaddr-negate` | Names [V F13] (Ansible underscore form); hyphenated wire form [I] |
| Hit counts | `GET /api/v2/monitor/firewall/policy`. Per policy: `policyid`, `hit_count`, `last_used`, `first_used` (epoch), `bytes`, `packets`, `active_sessions` | Selector `firewall_policy` [V F22]; field names [U, forum]. Hit count does not increase while sessions are still being handled by a policy [K F19] |
| NAT (cheap) | `GET /api/v2/cmdb/firewall/vip`, `.../firewall/ippool`; central NAT `.../firewall/central-snat-map` | [U] |
| Config backup | `.../api/v2/monitor/system/config/backup?scope=global`. GET before 7.6.0; POST from 7.6.0 (GET returns 405). Response body is the config file | [K F8] |
| Backup parameters | `scope` (required), `vdom`, `destination`, `usb_filename`, `password`, `password_mask`, `file_format` | [V F12] |
| Config revisions | Read: monitor selector `system_config-revision` (+ `_file`, `_info`). Actions: `system/config-revision/save` (`comments`), `/delete` (`config_ids`), `/update-comments` (`config_id`, `comments`) under `/api/v2/monitor/` | Selectors and URLs [V F12][V F22]; `/api/v2/monitor/` prefix [I] (consistent with the backup URL in F8) |

Response envelope, verbatim keys [V F3]: `http_method`, `revision`, `results`, `vdom`, `path`, `name`, `status`, `http_status`, `serial`, `version`, `build`. Address objects carry `q_origin_key` and `name` [V F3].

### 2.3 Writing one policy

There is no separate commit. Every cmdb write is live, and saved to flash when `cfg-save` is `automatic` (the default) [K F7][S F6].

| Operation | Request | Status |
|---|---|---|
| Create | `POST /api/v2/cmdb/firewall/policy?vdom=root` with body `{"policyid":0,"name":"atrium-123","srcintf":[{"name":"port2"}],"dstintf":[{"name":"port1"}],"srcaddr":[{"name":"LAN-net"}],"dstaddr":[{"name":"web-srv"}],"service":[{"name":"HTTPS"}],"schedule":"always","action":"accept","logtraffic":"all","status":"enable"}`. `policyid` 0 = next free ID [V F13] | [U] |
| Update | `PUT /api/v2/cmdb/firewall/policy/{policyid}?vdom=...` with changed attributes. List attributes are sent whole [I] | [U] |
| Delete | `DELETE /api/v2/cmdb/firewall/policy/{policyid}?vdom=...` | [U] |
| Move | `PUT /api/v2/cmdb/firewall/policy/{policyid}?action=move&after={otherid}` (or `&before={otherid}`), empty body | `after` [V F15, Fortinet Terraform provider example]; `before`/`after` [V F13] |

Notes on writing:
- The POST response is believed to contain `mkey` (the new key) and revision info [U]. Libraries disagree on whether re-creating an existing key returns HTTP 500 or 200 [U].
- **Implement create as GET-by-name, then POST only if absent [I].**
- A new policy most likely lands at the end of the sequence, just above the implicit deny [U]. Always follow a create with a move to the intended anchor [I].
- FortiOS 5.4 needed the body wrapped in `{"json": {...}}` when it contained `name`/`action`, otherwise HTTP 405 [U, forum citing the 5.4 guide]. Not expected on 7.x.

Batched / staged write (workspace transaction). Verified example from FortiOS 7.4.2 [V F4]:
1. `POST /api/v2/cmdb?action=transaction-start&vdom=vdom1` with body `{"timeout": 60}` → `{"transaction-id": 1, "status": "success", ...}`. The unit of `timeout` is not stated [U].
2. Send each cmdb write with header `X-TRANSACTION-ID: 1`.
3. Preview with `GET /api/v2/cmdb?action=transaction-show&transaction-id=1`. It returns the staged CLI lines in `results`. Available since 7.4.1.
4. `POST /api/v2/cmdb?action=transaction-commit&vdom=vdom1` with body `{"transaction-id": 1}`.
5. After commit, `transaction-show` returns `"error": -651`.

Abort: the CLI is `execute config-transaction abort` [V F5]. The REST action name `transaction-abort` is not documented in what I saw [U].

Transaction semantics [V F5]:
- Changes are invisible to other processes until commit.
- Edited objects are locked for other admins.
- The transaction expires after 5 minutes of inactivity, and uncommitted changes are discarded.
- Some settings are excluded: parts of `system global` (e.g. vdom-admin, management-vdom), `system settings` opmode, `npu`, `vdom-property`, `storage`, and others.
- `execute batch` cannot be used in workspace mode.

Transactions give atomic staging, not commit-confirm. After commit there is no automatic revert [I].

### 2.4 Safe-change mechanisms

1. **Config save mode `revert`** (the closest native commit-confirm):
   - CLI: `config system global` / `set cfg-save revert` / `set cfg-revert-timeout <s>`. Default 600 s, minimum 10 [S F6, 7.0.x CLI excerpt].
   - Changes run immediately but must be saved with `execute cfg save` before the timeout. Otherwise the unit reboots (KB 2009; 7.0.2 guide) or reverts in place with brief unresponsiveness (7.0.13 guide text) [K F7][S F6].
   - On HA, all members reboot [K F7].
   - The GUI equivalent ("Configuration save mode", "Revert upon timeout") has existed since 7.0.2. 8.0 lists Automatic/Manual/Revert [S F6][V, 8.0.0 Preference page].
   - The REST equivalent of `execute cfg save` is probably monitor `system/config/save` (selector `save.system.config`, no params) [V F12 selector; I that it maps to `cfg save`].
   - **Assessment [I]:** it is a global, all-admin setting with a disruptive timeout action. Atrium must not toggle it. At most, document it as an operator-enabled dead-man switch.
2. **Revision before change.**
   - `POST /api/v2/monitor/system/config-revision/save` with `{"comments":"atrium change <id>"}` [V F12 url/param; I prefix].
   - Restore: `POST /api/v2/monitor/system/config/restore` with params `source` (required), `scope` (required), `config_id` (revision), `file_content`, `vdom`, `password`, `confirm_password_mask`, `usb_filename` [V F12].
   - The accepted `source` values (e.g. upload/revision/usb) are not documented in what I saw [U].
   - A restore reboots the unit; in HA all members reboot together [U, old 5.0 guide, KB excerpt]. Treat restore as a last resort.
3. **Full backup** with `monitor/system/config/backup?scope=global` before every change (super_admin; §2.1). Store it encrypted; it contains secrets [I].
4. **Recommended primary rollback [I]:** the hub records the inverse operation of every change before applying it, then reverts with one API call. Inverses: delete the created policy, PUT the previous attribute values, or move back to the previous anchor. A reboot-based restore is only the fallback.

### 2.5 Transport details

- **TLS:** see §1. Pin the exported `Fortinet_CA_SSL` (7.2.1+) or a customer CA via `verify=<ca path>`. Do not disable verification [I].
- **Paging:** `start`/`count` [K F11]. Monitor endpoints can cap at 1000 entries per call; use `summary_only=1` to get the total first [K F11]. Whether cmdb tables page by default is unverified; FortiOS 5.6 reference lists `start`/`count` for cmdb [U].
- **Rate limits:** not found.
- **Errors:** JSON with `"status":"error"`, `http_status` (e.g. 404 for removed/unknown paths [K F9], 405 for wrong method [K F8], 500), and a negative `error` code.
  - Example: `-651` = transaction already finished [V F4].
  - Forum examples show `-3` with a `cli_error` string on bad values [U F20].
  - `-5` = duplicate entry, per a third-party library [U].
  - 401 means a bad token or a trusthost mismatch [I][K F10].
- **Idempotency:** none built in for POST. Use GET → POST/PUT (§2.3).

### 2.6 Minimal policy read example

Request: `GET /api/v2/cmdb/firewall/policy?vdom=root`.

The envelope keys are [V F3]. The policy keys are [V F13] in hyphenated form [I]. `q_origin_key` inside member lists is [U].

```json
{
  "http_method": "GET",
  "revision": "…",
  "results": [
    {
      "policyid": 1,
      "q_origin_key": 1,
      "name": "lan-to-web",
      "uuid": "…",
      "status": "enable",
      "srcintf": [{"name": "port2", "q_origin_key": "port2"}],
      "dstintf": [{"name": "port1", "q_origin_key": "port1"}],
      "srcaddr": [{"name": "LAN-net", "q_origin_key": "LAN-net"}],
      "dstaddr": [{"name": "all", "q_origin_key": "all"}],
      "service": [{"name": "HTTPS", "q_origin_key": "HTTPS"}],
      "schedule": "always",
      "action": "accept",
      "logtraffic": "all",
      "nat": "enable",
      "comments": ""
    }
  ],
  "vdom": "root", "path": "firewall", "name": "policy",
  "status": "success", "http_status": 200,
  "serial": "FGVM…", "version": "v7.4.4", "build": 2662
}
```

Hit counts are joined by `policyid` from `GET /api/v2/monitor/firewall/policy` [U fields].

### 2.7 Lock-out gotchas

1. **Trusthost.** The API user's trusthost must contain the hub's source IP (after NAT). Before 7.4.1 an admin trusthost must too [K F10].
2. **Interface `allowaccess`.** It is a single space-separated string. A PUT with an incomplete value can drop `https`/`ssh` on the management interface [I].
   - Atrium should never write `system interface`, `system global` (admin ports, `admin-https-*`), `system admin`, `system api-user`, `system accprofile` or `firewall local-in-policy` [I].
3. **Path to other managed devices.** Firewall policies govern traffic through the FortiGate. Admin access to the FortiGate itself is governed by allowaccess, trusthost and local-in [U].
   - But the hub's path to other devices (switches and firewalls behind this FortiGate) can be cut by a deny or move.
   - Add a pre-apply "management-path guard": does the new rule set, in evaluation order, deny hub IP ↔ any managed device's management IP? [I]
4. **Implicit deny.** It sits at the end of the sequence. A move that places a broad deny above existing allows is the classic outage [I].
5. **`cfg-save revert`.** If an operator enabled it, unsaved API changes will be reverted with a reboot or reload after the timeout. Detect it by reading `cmdb/system/global` `cfg-save` [I][K F7].
6. **Version drift.** `cmdb/system/status` → `monitor/system/status` (7.4.4) [K F9]. Backup method GET → POST (7.6.0) [K F8]. URL token disabled (7.4.5) [S F18]. Probe the version first and branch.
7. **Counter resets.** Monitor actions `reset.firewall.policy` and `clear_counters.firewall.policy` exist [V F12]. Never call them; they destroy hit-count evidence.
8. **FortiManager-managed units.** Local API changes create drift and can be overwritten by the next package install [U]. See §2.8.
9. **VDOMs.** Every call needs the right `vdom`. Global objects and backups use `scope=global` [K F8][I].
10. **Workspace timeout.** A transaction idle for more than 5 minutes is silently discarded [V F5]. Keep the commit in the same job.

### 2.8 Policy packages (FortiManager only)

Policy packages are a FortiManager concept, not a FortiGate one [I].
- Per-rule JSON-RPC URL: `/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy/{policy}` [U, Fortinet Ansible FMG docs F21].
- Install: `exec` on `/securityconsole/install/package` with `adom`, `pkg`, `scope`, `flags` (e.g. `preview`) [U F21].
- If a FortiGate is centrally managed, Atrium should write through FortiManager, or at least warn. Detection: read `cmdb/system/central-management` [U].

---

## 3. Palo Alto Networks PAN-OS (docs: ngfw API pages updated 2025-08-28; admin pages 2026-10-07)

### 3.1 Authentication and least privilege

- **API key.** Request: `POST https://fw/api/?type=keygen`, `Content-Type: application/x-www-form-urlencoded`, body `user=<u>&password=<p>` (percent-encode special characters) [V P8].
  - Response: `<response status="success"><result><key>…</key></result></response>` [S P6 excerpt].
  - Send the key in header `X-PAN-KEY: <key>`. The XML API also accepts `key=` in the query, and Basic auth is accepted, but not for keygen [V P6].
  - Use POST for anything sensitive [V P7].
- **Key invalidation** happens when [V P8]:
  - the user is deleted;
  - the user's password changes;
  - the key lifetime elapses;
  - the API-key certificate is reconfigured or expires;
  - Panorama takes precedence (its key invalidates existing keys);
  - API-key encryption with a certificate is enabled (invalidates all keys).
- **Generating a new key for the same user** ends all that user's sessions and deletes its previous API sessions [S P6 excerpt].
- **Practical consequences [I]:**
  - Use one dedicated admin account per hub instance and keygen once.
  - Store the key, not the password.
  - Never run keygen concurrently.
- **Key lifetime:** Device > Setup > Management > Authentication Settings > "API Key Lifetime (min)", range 0–525600, default 0 (never expires). It needs a commit [S P9]. "Expire all API keys" exists [S P9][V P6].
- **Roles.** Admin Role profiles apply per interface: Web UI and REST API tabs take Enable/Read Only/Disable per feature; the XML API tab takes Enable/Disable only [V P10][S P10-snippet].
  - XML API features: Report, Log, Configuration, Operational Requests, Commit, User-ID Agent, Import, Export [U P11 (pan.dev Ansible RBAC page)]. P7 names only "such as Report, Log, and Configuration".
  - Supported dynamic roles for API access: Superuser, Superuser (readonly), Device admin, Device admin (readonly), Vsys admin, Vsys admin (readonly) [V P7].
  - A separate admin account for XML API access is best practice [V P7].
- **Read connector:** use the dynamic role **Device admin (readonly)** or **Superuser (readonly)** [V P7].
  - Whether a custom XML-API role with Configuration enabled can be read-only (the XML tab has no read-only setting) is not documented [U]. Avoid relying on it.
- **Write connector (least privilege) [I]:** custom role with:
  - XML API: Configuration, Operational Requests, Commit. Export only if config export is used.
  - Web UI Commit: Device enabled, "Commit For Other Admins" disabled.
  - Semantics [V P12]: disabling Device blocks commit/revert of your own changes; disabling Commit For Other Admins blocks committing or reverting others' changes. Whether the Web UI commit sub-privileges also gate XML-API commits is not verified [U].
  - Locks and op commands need Operational Requests [U P11].
  - Vsys-scoped roles cannot load, save or revert configurations [S excerpt].

### 3.2 Reading

`type=config&action=show` returns the **active (running)** config; `action=get` returns the **candidate** [V P1][V P3].

Base xpath on a firewall: `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']` [V P20].

| Data | XML API | REST API (`/restapi/v{maj.min}/...`, `location=vsys&vsys=vsys1`) |
|---|---|---|
| Version | `type=version`: PAN-OS version, serial, model [V P1] | n/a |
| Interfaces | xpath `/config/devices/entry[@name='localhost.localdomain']/network/interface/ethernet` (layer3 `ip` entries) [V P23]. Runtime: op `<show><interface>all</interface></show>` [U] | `Network/EthernetInterfaces` [U] |
| VLANs / subnets | Subinterfaces `.../network/interface/ethernet/entry[@name='ethernet1/1']/layer3/units`, VLAN tag leaf `tag`, `ip` entries; VLAN interfaces `.../network/interface/vlan/units` [V P23] | [U] |
| Zones | `<base>/zone`, members under `network/layer3` (or other mode) [V P23] | `GET /restapi/v11.0/network/zones?location=vsys&vsys=vsys1` [V P18] |
| Address objects | `<base>/address`, `<base>/address-group` [V P3] | `GET /restapi/v11.0/Objects/Addresses?location=vsys&vsys=vsys1`. Entries have `@name`, `@location`, `@vsys`, `ip-netmask` or `fqdn` [V P17] |
| Service objects | `<base>/service`, `<base>/service-group` [U] | `Objects/Services` [U] |
| Security rules (ordered) | `<base>/rulebase/security/rules` [V P20][V P22] | `GET /restapi/v11.0/Policies/SecurityRules?location=vsys&vsys=vsys1` [V P16] |
| NAT | `<base>/rulebase/nat/rules` [V P22 suffix; I full path] | `Policies/NatRules` [U] |
| Hit counts | op `<show><rule-hit-count><vsys><vsys-name><entry name='vsys1'><rule-base><entry name='security'><rules><all/></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>`. Per rule `entry name=`: `hit-count`, `last-hit-timestamp`, `last-reset-timestamp`, `first-hit-timestamp`, `rule-creation-timestamp`, `rule-modification-timestamp` (epoch) [K P19]. PAN-OS 8.1+ [K P19] | n/a |
| Config export | `type=export&category=configuration` (save with `-o`) [V P24 category; I exact form]. Whether it exports running or candidate is not stated [U] | n/a |
| Named snapshot | op `<save><config><to>name.xml</to></config></save>` [V P5] | n/a |
| Pending / locks | op `<check><pending-changes/></check>`, `<show><config-locks/></show>`, `<show><commit-locks/></show>` [V P21][V P5] | n/a |
| Change preview | op `<show><config><list><change-summary/></list></config></show>` [V P5] | n/a |

Security-rule element names [V P22]:
- Member lists: `from`, `to`, `source`, `destination`, `source-user`, `application`, `service` (default `application-default`), `category`, `tag`.
- Leaves: `action`, `log-setting`, `log-start`/`log-end` (yes/no), `disabled` (yes/no), `negate-source`, `negate-destination`, `description`, `schedule`, `rule-type`.
- Attribute `uuid` (9.0+), `group-tag` (9.0+).

### 3.3 Writing one rule (all writes go to the candidate)

XML API, POST form-encoded to `/api/` [V P3][V P4]:

- **Create / merge:**
  ```
  type=config&action=set
  &xpath=<base>/rulebase/security/rules/entry[@name='atrium-123']
  &element=<from><member>trust</member></from><to><member>dmz</member></to>
           <source><member>10.10.20.0/24</member></source><destination><member>web-srv</member></destination>
           <source-user><member>any</member></source-user><application><member>ssl</member></application>
           <service><member>application-default</member></service><category><member>any</member></category>
           <action>allow</action><log-end>yes</log-end>
  ```
- **Replace:** `action=edit` with the same xpath and a complete `<entry name='atrium-123'>…</entry>` element. Build it from an `action=show` read [V P3].
- **Delete:** `action=delete&xpath=…/rules/entry[@name='atrium-123']` [V P1].
- **Move:** `action=move&xpath=…/rules/entry[@name='atrium-123']&where=before&dst=<other-rule-name>` [V P4].
  - `where` is after|before|top|bottom; `dst` is required for after/before.
  - The doc calls `dst` a "destination path", but the example passes a bare rule name (`dst=rule2`) [V P4].
- **Rename:** `action=rename&newname=` [V P3].

REST API (objects and policies only) [V P14][V P16]:
- Create: `POST /restapi/v11.0/Policies/SecurityRules?location=vsys&vsys=vsys1&name=atrium-123` with body `{"entry":[{"@name":"atrium-123","@location":"vsys","@vsys":"vsys1","from":{"member":["trust"]},"to":{"member":["dmz"]},"source":{"member":["any"]},"destination":{"member":["any"]},"source-user":{"member":["any"]},"application":{"member":["ssl"]},"service":{"member":["application-default"]},"category":{"member":["any"]},"action":"allow"}]}`.
- Update: `PUT` with the same query and the **full** entry. Read first: omitting existing members loses data [V P18].
- Delete: `DELETE ?location=vsys&vsys=vsys1&name=…`.
- Move: `POST …/SecurityRules:move?location=vsys&vsys=vsys1&name=atrium-123&where=before&dst=<rule>`.
- Rename: `POST …:rename?…&newname=`.
- The REST API cannot commit. Use the XML API [V P13].

**Apply (commit).** Commit only your own admin's changes [V P2]:
```
POST /api/?type=commit&action=partial&cmd=<commit><partial><admin><member>atrium-api</member></admin></partial></commit>
```
- Responses [V P2]:
  - `code="19"` with "There are no changes to commit"; or
  - `code="19"` with `<job>N</job>` and "Commit job enqueued with jobid N".
- Poll with `type=op&cmd=<show><jobs><id>N</id></jobs></show>` until done [V P2]. The doc example shows `<status>ACT</status><result>PEND</result><progress>55</progress>`. Final values `FIN`/`OK`/`FAIL` are [U].
- Other variants [V P2]: full `<commit></commit>`, force `<commit><force></force></commit>`, partial excluding `device-and-network`/`shared-object`.
- Validate before commit: op `<validate><full></full></validate>` (async job) [V P5].
- Commits are queued; firewall auto-commits (e.g. FQDN refresh) take priority [V P27].

### 3.4 Safe-change mechanisms

- **No native commit-confirm or auto-revert timer** for ordinary commits. This is a long-standing feature request (FR 204) [U P32]. I found no 11.2/12.1 feature that adds one [U].
- **Panorama-managed firewalls only: "Automated commit recovery."** Enabled by default. Device > Setup > Management in the template [V P29].
  - Defaults: 1 connectivity attempt, 10 s retry interval (set 5 attempts for ZTP).
  - Covers pushes and local commits.
  - If a commit breaks the firewall→Panorama connection, the firewall reverts to its previous running config. It also tests the connection every 60 min [V P29][V P27].
  - It protects only the Panorama path, not the hub's path [I].
- **Candidate + revert (pre-commit undo):**
  - Partial revert of your own changes: op `<revert><config><partial><admin><member>atrium-api</member></admin></partial></config></revert>` [V P5]. CLI `revert config partial ... admin [...]` since 10.0 [V P31].
  - Full discard of everyone's candidate changes: op `<load><config><from>running-config.xml</from></config></load>`. This is what `pan-os-python` `revert_to_running_configuration()` sends [V P21].
- **Locks:**
  - Add: `<request><config-lock><add><comment>atrium</comment></add></config-lock></request>`, `<request><commit-lock><add/></commit-lock></request>`.
  - Remove: `<request><config-lock><remove/></config-lock></request>`, `<request><commit-lock><remove/></commit-lock></request>` [V P21; comment child per P21].
  - Only the owner or a superuser can remove a lock. The firewall removes a lock automatically after a commit [V P28].
  - "Automatically Acquire Commit Lock" (Device > Setup > Management > General) puts a commit lock on any candidate change, for all admins [V P28].
- **Post-commit rollback:**
  1. Before the change, save a named snapshot: `<save><config><to>atrium-pre-<id>.xml</to></config></save>` [V P5].
  2. To roll back: `<load><config><from>atrium-pre-<id>.xml</from></config></load>` [V P5], then commit.
  - Alternative: load a previous running-config version. The GUI "Load configuration version" is [V P26]; the XML form `<load><config><version>N</version></config></load>` is [U].
  - A load only changes the candidate; a commit is required to activate it [V P26].
  - Off-box copy: `type=export&category=configuration` [V P24]. Import: `type=import&category=configuration`, multipart `file=@…` [V P25 category; I form], then load and commit.
- **Recommended hub-side "commit-confirm" emulation [I]:**
  1. Snapshot.
  2. Partial commit.
  3. Health probe from the hub (API reachable, and optionally a TCP probe through the new rule).
  4. If the probe fails within N seconds: load snapshot → partial or full commit.
  - If the hub itself lost reachability, this cannot run. Keep the management-path guard (§3.7) as the primary protection.

### 3.5 Transport details

- **TLS:** self-signed by default; install a CA-issued cert or pin [V P13].
- **HTTP:** requires an interface management profile [V P7].
- **Paging:** REST methods document none [V P14]. XML config reads return the whole subtree [I]. For large rulebases, read per rule by name or use REST with `name=` [I].
- **Concurrency:** REST, 5 concurrent calls or fewer, possibly varying by request type [V P13]. Commits are serialized in a queue [V P27].
- **XML success:** `<response status="success" code="19|20">` (19/20 = success) [S P30].
- **XML errors** `<response status="error" code="N">` [S P30]:

  | Code | Meaning |
  |---|---|
  | 400 | Bad or missing parameter |
  | 403 | Bad key or insufficient rights |
  | 1, 17 | Unknown/invalid command |
  | 18 | Malformed XML |
  | 6 | Bad xpath |
  | 7 | Object not present |
  | 8 | Not unique |
  | 10 | Referenced, cannot delete |
  | 12 | Incomplete xpath/element |
  | 13 | Object not found |
  | 14 | Operation not possible (e.g. rule already at top) |
  | 15 | Not allowed (e.g. on HA passive) |
  | 16 | Role lacks rights |
  | 22 | Session timed out |

- **REST:**
  - Success: `{"@status":"success","@code":"19","result":{"@total-count":…,"@count":…,"entry":[…]}}`. Edit returns `"@code":"20","msg":"command succeeded"` [V P15][V P17].
  - Error: `{"code":N,"message":"…","details":[{"@type":"CauseInfo","causes":[{"code":…,"module":"…","description":"…"}]}]}`. Do not parse `details.causes`; it can change between releases [V P15].
  - REST codes differ from XML codes (e.g. REST 3 = bad request, REST 7 = forbidden) [S P30-adjacent REST codes page].
- **Idempotency:**
  - XML `set` merges, so repeating it is harmless for scalar values and union for member lists [I].
  - `edit` replaces the node [V P3].
  - REST PUT replaces the entry [V P18]. REST POST on an existing name fails [U].
  - Use read → diff → set/edit [I].

### 3.6 Minimal rules read example (REST)

Request: `GET /restapi/v11.1/Policies/SecurityRules?location=vsys&vsys=vsys1`.

Envelope keys [V P15/P17]. Rule keys `from`…`action` [V P16]. `log-end` and `disabled` JSON keys are [I] from the XML element names [V P22]. JSON types of the count fields are [U].

```json
{
  "@status": "success",
  "@code": "19",
  "result": {
    "@total-count": "1",
    "@count": "1",
    "entry": [
      {
        "@name": "allow-web",
        "@location": "vsys",
        "@vsys": "vsys1",
        "from": {"member": ["trust"]},
        "to": {"member": ["untrust"]},
        "source": {"member": ["any"]},
        "destination": {"member": ["any"]},
        "source-user": {"member": ["any"]},
        "application": {"member": ["web-browsing", "ssl"]},
        "service": {"member": ["application-default"]},
        "category": {"member": ["any"]},
        "action": "allow",
        "log-end": "yes",
        "disabled": "no"
      }
    ]
  }
}
```

XML equivalent of `action=show` on `<base>/rulebase/security` [K P20]:
`<response status="success"><result><security><rules><entry name="…" uuid="…"><to><member>…</member></to>…</entry></rules></security></result></response>`

### 3.7 Lock-out gotchas

1. **A plain `<commit/>` commits every pending change** the account may commit, including other admins' half-finished work if it has "Commit For Other Admins" [V P27]. Always use the partial commit with `<admin><member>own-account</member></admin>` [V P2]. Check `<check><pending-changes/></check>` first [V P21].
2. **`load config from running-config.xml` discards all admins' candidate edits** [I from P21/P26]. Use the partial revert for your own admin instead [V P5].
3. **Management reachability.**
   - The dedicated MGT port is not subject to security rules [U].
   - If the hub reaches a dataplane interface (via an interface management profile) across zones, a security rule must permit it [I], so a move or deny can cut the hub.
   - Service-route changes can cut Panorama, update and API paths [V P29 mentions service-route breakage].
   - Atrium must never write `deviceconfig/system` (permitted IPs, service routes), interface management profiles, admin accounts or roles [I].
4. **Keygen side effects:** regenerating the key kills the account's sessions [S P6]. A password change invalidates the key [V P8].
5. **Panorama-managed:** local edits can conflict with pushed config [U]. Automated commit recovery protects only the Panorama connection, and enabling it in the same commit as a breaking change prevents the automatic revert [V P29].
6. **`where=top` moves** put a rule above every allow/deny. Prefer an explicit `before`/`after` anchor [I]. Code 14 means the move is impossible [S P30].
7. **Locks:** another admin's config or commit lock blocks the hub. Only the owner or a superuser can remove it [V P28]. Never force-remove another admin's lock automatically [I].
8. **HA:** run writes on the active peer. Some commands are refused on the passive peer (code 15) [S P30].
9. **Asynchronous jobs:** a commit job can fail after "enqueued". Always poll to completion before declaring success [V P2][I].

---

## 4. Cisco IOS-XE (Programmability CG 17.13/17.15; Config Replace article 2025-09-25 covering 17.18.1; YANG models from `YangModels/yang` `vendor/cisco/xe/17151`, rev 2024-07-01)

### 4.1 Authentication and least privilege

- **Enable RESTCONF** [V C1]:
  ```
  aaa new-model
  aaa authentication login default group <grp> local
  aaa authorization exec default group <grp> local
  username atrium privilege 15 secret …
  ip http secure-server
  restconf
  ```
  - RESTCONF runs on HTTPS 443 (or 80 with `ip http server`; do not enable that) [V C1].
  - It is not supported with dual IOSd or software redundancy [V C1].
- **Enable NETCONF** with `netconf-yang` (up to 90 s to come up), SSH port 830 [V C2].
  - Only the default AAA login/exec methods are supported [V C2].
  - Run `no netconf legacy` [V C2].
  - Public-key login via `ip ssh pubkey-chain` [V C2].
- **Privilege 15 is mandatory** for RESTCONF and NETCONF [V C1][V C2]. Token-based RESTCONF authentication is not supported [V C2].
- **NACM (RFC 6536/8341)** places users in groups `PRIV00`–`PRIV15` by privilege level [V C2]. Whether NACM rules can make a priv-15 API user read-only on IOS-XE is not documented in the guides I read [U]. **Assume no read-only API role.**
- **Mitigations [I]:**
  - Use a dedicated account.
  - Restrict the HTTPS server's sources with an `ip http access-class` ACL [U].
  - Use TACACS+ authorization and accounting for the account.
  - Keep the credential only in the hub's secret store.

### 4.2 Reading (RESTCONF)

Headers: `Accept: application/yang-data+json`. XML (`application/yang-data+xml`) is also supported [V C1]. Root discovery: `/.well-known/host-meta` [V C1].

List keys are percent-encoded in the URI, and multiple keys are comma-separated [V C18 §3.5.3]. Example: `interface=GigabitEthernet1%2F0%2F1` [I].

| Data | Path under `/restconf/data/` | Status |
|---|---|---|
| OS version | `Cisco-IOS-XE-device-hardware-oper:device-hardware-data/device-hardware/device-system-data/software-version` (also `boot-time`, `rommon-version`, `last-reboot-reason`) | [V C14] |
| Interfaces (oper, incl. IPv4 and mask) | `Cisco-IOS-XE-interfaces-oper:interfaces/interface=<name>`. Leaves: `name`, `interface-type`, `admin-status`, `oper-status`, `ipv4`, `ipv4-subnet-mask`, `description`, `mtu`, `vrf`, `phys-address`, `speed`, `statistics` | [V C13] |
| Interfaces (config) | `Cisco-IOS-XE-native:native/interface` (per-type lists such as `GigabitEthernet`, `Vlan`); `ietf-interfaces:interfaces` also exists | [U] |
| VLANs (config) | `Cisco-IOS-XE-native:native/vlan/Cisco-IOS-XE-vlan:vlan-list=<id>`. Leaves: `id` (1–4094), `name`, `state`, `shutdown` | [V C11] |
| VLANs (oper, ports) | `Cisco-IOS-XE-vlan-oper:vlans/vlan=<id>`. Leaves: `id`, `name`, `status`; lists `ports` (`interface`, `subinterface`) and `vlan-interfaces` | [V C12] |
| Switchport membership | Under an interface: `switchport/access/vlan/vlan`, `switchport/mode/access` or `switchport/mode/trunk`, `switchport/trunk/native/vlan/vlan-id`, trunk allowed (v2 grouping since 2023-11-01) | Leaves [V C15]; augment target [U]. GET one port to confirm |
| Zones | Switches have no zones: VLAN/SVI/VRF are the segments [I]. Routers with zone-based firewall: `native/zone/security`, `native/zone-pair/security` | [U] |
| Address/service objects | `object-group` exists in the ACL model (`object-group-str`, `src-fqdn-group`, `dst-object-group`) | [V C9] |
| ACLs (ordered rules) | `Cisco-IOS-XE-native:native/ip/access-list/Cisco-IOS-XE-acl:extended=<name>/access-list-seq-rule=<seq>` | [V C9] |
| ACL entry fields | `sequence` (1–2147483647; order = sequence), `remark`, `ace-rule/{action (permit/deny), protocol, ipv4-address, mask, any, host-address, object-group, src-eq…, dest-ipv4-address, dest-mask, dst-any, dst-host-address, dst-object-group, dst-eq/dst-range1/…, established, log, log-input, time-range}`. Standard ACLs: `standard=<name>/access-list-seq-rule/{deny/permit}/std-ace`. Deprecated: `host` → `host-address`, `dst-host` → `dst-host-address` | [V C9] |
| ACL hit counts | `Cisco-IOS-XE-acl-oper:access-lists/access-list=<name>/access-list-entries/access-list-entry=<seq>/access-list-entries-oper-data/match-counter` (counter64) | [V C10] |
| Where an ACL is applied | `ip access-group … in/out` on an interface/SVI, and `access-class` on VTY | Model path [U]; read by GET on the interface |
| NAT (cheap) | `native/ip/nat` | [U] |
| Config in CLI form | RPC `Cisco-IOS-XE-cli-rpc:get-modelled-config-clis` (input `datastore` running/candidate). Modelled config only; wireless, app-hosting and telemetry excluded | [V C8] |
| Config backup to file | RPC `Cisco-IOS-XE-rpc:copy` with `source-drop-node-name` = `running-config`, `destination-drop-node-name` = `flash:…` (or `bootflash:`, `scp:`, `https:` …), both pattern-checked | [V C7] |
| Archive checkpoint | RPC `cisco-ia:checkpoint` = CLI `archive config` | [V C6] |

Query parameters: `depth` and `fields` are supported. `filter`, `start-time`, `stop-time`, `replay` and `action` are not [V C1]. There is no paging [I].

RPC calls: `POST /restconf/operations/<module>:<rpc>` with body `{"<module>:input": {...}}` [I from RFC 8040 §3.6; C1 lists the `operations` resource].

### 4.3 Writing one ACL entry (RESTCONF: live immediately, no commit)

| Operation | Request | Status |
|---|---|---|
| Create entry | `POST /restconf/data/Cisco-IOS-XE-native:native/ip/access-list/Cisco-IOS-XE-acl:extended=HUB-IN` with body `{"Cisco-IOS-XE-acl:access-list-seq-rule":[{"sequence":"25","ace-rule":{"action":"permit","protocol":"tcp","ipv4-address":"10.10.20.0","mask":"0.0.0.255","dst-host-address":"10.10.30.10","dst-eq":"443","log":[null]}}]}`. Fails with 409 `resource-denied` if the entry exists | [V C18 §4.4.1][V C9 names][V C19 encodings]; `dst-eq` value form [U] |
| Idempotent create/update (merge) | `PATCH` on the ACL resource with the entry | [V C18 §4 table] |
| Replace entry | `PUT …/extended=HUB-IN/access-list-seq-rule=25` with the full entry | [V C18] |
| Delete entry | `DELETE …/extended=HUB-IN/access-list-seq-rule=25` | [V C18] |
| Move | No move operation: order is `sequence`. Delete and re-create with a new sequence, or `ip access-list resequence` (CLI) [I] | Do it atomically with NETCONF candidate (§4.4) or YANG-Patch |
| Persist | `POST /restconf/operations/cisco-ia:save-config` (running → startup) | [V C6] |

JSON encoding rules [V C19]:
- `uint64` (`sequence`) is encoded as a string.
- `empty` leaves (`any`, `dst-any`, `log`) are `[null]`.
- Top-level members are module-qualified (`Cisco-IOS-XE-acl:…`).

YANG-Patch (RFC 8072, `application/yang-patch+json`) could carry several edits in one request. The 17.15 guide lists it both as a feature and as a restriction [V C1]. Test before relying on it.

### 4.4 Safe-change mechanisms

1. **NETCONF candidate + confirmed commit (preferred for writes).**
   - Enable with `netconf-yang feature candidate-datastore` [V C2].
     - When enabled, the running datastore is not writable over NETCONF.
     - Enabling or disabling it terminates all NETCONF sessions and restarts confd. This is an operator action in a maintenance window.
   - Flow:
     1. `<lock><target><candidate/></target></lock>` (discard leftovers first).
     2. `<edit-config><target><candidate/>…`
     3. `<validate>`
     4. `<commit><confirmed/><confirm-timeout>120</confirm-timeout></commit>` (default 600 s).
     5. Probe reachability from the hub.
     6. `<commit/>` to make it permanent. Re-sending `<confirmed/>` extends the timer.
     - [V C2][V RFC 6241 §8.4]
   - If the issuing session dies before the confirming commit, the device restores the previous config [V C2]. RFC 6241 behaves the same unless `<persist>` is used [V RFC6241]. **Keep the NETCONF session open across the probe.**
   - `<cancel-commit>` reverts immediately per RFC 6241 [V RFC6241]. IOS-XE support for it and for `<persist>` is [U].
   - Commit fails with `in-use` if another session or a CLI config lock (session-id 0) holds running or candidate [V C2].
   - Confirmed commit is **not** supported over RESTCONF [V C2].
   - Then call `cisco-ia:save-config` [V C2][V C6].
   - Needs an SSH NETCONF client library on the hub, e.g. ncclient [U, not evaluated].
2. **Checkpoint + rollback over RESTCONF (no timer).**
   - Before the change: `cisco-ia:checkpoint` [V C6] or `Cisco-IOS-XE-rpc:copy` running-config → `flash:atrium/pre-<id>.cfg` [V C7]. With `copy`, the file name is known to the hub.
   - Rollback RPC `cisco-ia:rollback` inputs [V C6]: `target-url` (mandatory), `verbose`, `nolock`, `revert-on-error` (empty), `revert-timer` (1–120). It is the RPC form of `configure replace`.
   - The `revert-timer` unit is not stated; minutes is consistent with the CLI [I].
   - `cisco-ia:revert` inputs: `now`, `timer` (1–120), `idle` (1–120) [V C6].
   - No RPC equivalent of `configure confirm` exists in `cisco-ia` or `Cisco-IOS-XE-rpc` (rev 2024-07-01) [V C6][V C7, negative]. A timed rollback started over the API can only be confirmed through the CLI.
3. **CLI timed revert (SSH):**
   - Option a: `configure terminal revert timer <1-120>` (minutes) or `revert idle <1-120>` [S C5].
   - Option b: `configure replace <url> [list] [force] [nolock] [revert trigger [error] [timer <min>] | time <min>]` [V C3][V C4].
   - Confirm either with `configure confirm` [V C4]. `configure revert {now | timer <min> | timer idle <min>}` [V C4].
   - A configuration archive (`archive` / `path …` / `maximum 1-14`, default 10 / `time-period`) is a prerequisite [V C3][V C4].
   - Only the user who started a timed rollback can confirm, reset or cancel it [S C5].
   - Community reports: the revert timer sometimes did not fire and left a config lock [U C17]. Multi-pass reverts may miss partial config [V C3].
4. **Last resort:** running-config changes are lost on reload unless saved [I]. Never call `save-config` until the change is verified.

**Recommendation [I]:**
- Read over RESTCONF.
- Write over NETCONF with candidate + confirmed commit.
- If the operator will not enable the candidate datastore: copy running-config to a named file, write over RESTCONF, probe, and call `cisco-ia:rollback target-url=<file>` (with `revert-on-error`) on failure.

### 4.5 Transport details

- **TLS:** self-signed `TP-self-signed-<n>` unless `ip http secure-trustpoint` points at a CA trustpoint [S C16]. Pin it or install a CA cert [I].
- **Errors:** RFC 8040 `{"ietf-restconf:errors":{"error":[{"error-type","error-tag","error-path","error-message"}]}}` [V C18]. IOS-XE adherence [I]. YANG-Patch errors carry `error-type`, `error-tag`, `error-path`, `error-message` [V C1].
- **Status codes:** POST on an existing resource → 409 `resource-denied` [V C18].
- **Idempotency:** PUT is create-or-replace; PATCH is merge [V C18].
- **Paging and rate limits:** not found.
- **Sync lag:** after CLI changes, model data may lag. The RPC `cisco-ia:is-syncing` reports `syncing`, `syncs-pending`, `running-datastore-locked`, `candidate-datastore-locked`, `candidate-datastore-dirty` [V C6]. Check it before reads that must be fresh and before writes.

### 4.6 Minimal ACL read example

Request: `GET /restconf/data/Cisco-IOS-XE-native:native/ip/access-list/Cisco-IOS-XE-acl:extended=HUB-IN`.

Field names [V C9]; encodings [V C19]; `dst-eq` value form [U].

```json
{
  "Cisco-IOS-XE-acl:extended": [
    {
      "name": "HUB-IN",
      "access-list-seq-rule": [
        {
          "sequence": "10",
          "ace-rule": {
            "action": "permit",
            "protocol": "tcp",
            "ipv4-address": "10.10.20.0",
            "mask": "0.0.0.255",
            "dst-host-address": "10.10.30.10",
            "dst-eq": "443",
            "log": [null]
          }
        },
        {
          "sequence": "20",
          "ace-rule": {"action": "deny", "protocol": "ip", "any": [null], "dst-any": [null], "log": [null]}
        }
      ]
    }
  ]
}
```

Hit counters: `GET /restconf/data/Cisco-IOS-XE-acl-oper:access-lists/access-list=HUB-IN` → `access-list-entries/access-list-entry[]` with `rule-name` (uint32, a JSON number) and `access-list-entries-oper-data/match-counter` (counter64, a JSON string) [V C10][V C19].

### 4.7 Lock-out gotchas

1. **Implicit deny** at the end of every ACL. Editing the ACL on the SVI or uplink the hub uses, or the `ip http access-class` / VTY `access-class` ACL, cuts RESTCONF and SSH [I]. Apply the management-path guard (§5).
2. **PUT replaces.** A PUT on `extended=NAME` with one entry deletes all other entries. A PUT on an interface can drop its IP or `ip access-group` [V C18 semantics][I].
3. **Never write these** (hub-side deny list) [I]: `aaa`, `username`, `ip http`, `restconf`, `netconf-yang`, `line vty`, management-VRF interfaces.
4. **NETCONF global lock on running** locks the CLI parser for all users. Recovery: `clear configuration lock` (parser only) or `clear netconf-yang session` [V C2]. Locks must be short-lived.
5. **Toggling the candidate datastore** restarts confd and drops all sessions [V C2].
6. **Revert timers** may not fire, and multi-pass replace may not fully revert [U C17][V C3]. `configure replace` needs a complete, correctly indented config file and enough free memory; some lines need a reload [V C3].
7. **Unsaved changes** survive until reload. Calling `save-config` too early removes the reload safety net [I].
8. **Priv-15 credentials** are full admin [V C1/C2]. Their leakage is equivalent to device takeover [I].

---

## 5. Implementation recipe (all vendors) [I unless tagged]

1. **Preflight:**
   - Read the version: FortiOS `monitor/system/status`; PAN-OS `type=version`; IOS-XE `device-system-data/software-version`.
   - Branch on known API changes (§2.7.6).
   - Detect central management: FortiManager, Panorama.
   - Detect pending changes and locks: PAN-OS pending-changes/locks [V P21]; IOS-XE `is-syncing` [V C6].
2. **Management-path guard (the main anti-lockout control).** Before applying, evaluate the rule set in order:
   - Inputs: the hub's source IP(s) and each managed device's management IP and port (443/830/22).
   - Refuse (or require an extra approval) if the change can deny any hub ↔ device management flow, if it touches the interface or ACL bound to the management path, or if it uses `where=top` / a broad deny.
3. **Snapshot:**
   - FortiOS: config-revision save + backup [V F12][K F8].
   - PAN-OS: `save config to atrium-pre-<id>.xml` [V P5].
   - IOS-XE: `copy running-config flash:atrium/pre-<id>.cfg` [V C7].
   - Record the inverse operations in Atrium's own store.
4. **Stage and preview:**
   - FortiOS: `transaction-show` [V F4].
   - PAN-OS: `change-summary` and `validate` [V P5].
   - IOS-XE: NETCONF candidate + `<validate>` [V C2].
   - Feed the preview into the existing approvals flow before apply.
5. **Apply:**
   - FortiOS: `transaction-commit`.
   - PAN-OS: partial commit for own admin, then poll the job.
   - IOS-XE: confirmed commit (NETCONF), or a direct write (RESTCONF).
6. **Verify within N seconds:** the API is still reachable from the hub, and an optional synthetic probe through the new rule passes.
7. **Confirm or roll back:**
   - IOS-XE NETCONF: confirming `<commit/>` or let the timer revert.
   - Others: apply the recorded inverse operations. Last resort:
     - PAN-OS: `load config from` snapshot + commit.
     - IOS-XE: `cisco-ia:rollback`.
     - FortiOS: restore (reboots).
8. **Persist:**
   - IOS-XE: `cisco-ia:save-config` only after verification.
   - FortiOS: automatic save mode persists already. If `cfg-save` is manual/revert, `monitor/system/config/save` [V F12 selector; I mapping].

---

## 6. Normalized model for the requested segmentation panel [I]

The user asked for a management panel with drag-and-drop arrows and a segmentation view. This maps each vendor onto one graph model.

| Concept | FortiGate | PAN-OS | IOS-XE switch |
|---|---|---|---|
| **Segment node** | Zone (`system/zone`), else interface/VLAN subinterface (`vlanid`, IP/mask) | Zone (`zone/network/layer3` → interfaces → `ip`, subinterface `tag`) [V P23] | VLAN (`vlan-list` id/name [V C11]) + SVI `Vlan<id>` IPv4/mask (`interfaces-oper` `ipv4`/`ipv4-subnet-mask` [V C13]), member ports (`vlan-oper ports` [V C12]) |
| **Edge (arrow)** | Policy `srcintf`→`dstintf`, ordered by sequence | Rule `from`→`to`, ordered by rulebase position | ACE in an ACL bound to an SVI/interface (`ip access-group` in/out): segment ↔ CIDRs. No zones |
| **Edge attributes** | `srcaddr`/`dstaddr`/`service`/`action`/`status`/`logtraffic`, hit count | `source`/`destination`/`application`/`service`/`action`/`disabled`/`log-end`, hit count [V P19] | `ace-rule` fields, `match-counter` [V C10] |
| **Stable rule ID** | `policyid` (+ `uuid`) | rule `name` (+ `uuid`) | ACL name + `sequence` |
| **Drag A→B** | POST policy + move to anchor | `set` rule + `move` + partial commit | New ACE with sequence between neighbours, via NETCONF candidate |

- **Physical stitching** ("a firewall is connected to this switch") can be inferred by matching SVI subnets to firewall interface subnets.
  - LLDP neighbour tables would be more exact, but I did not research those endpoints: FortiOS LLDP monitor, PAN-OS `<show><lldp>…`, IOS-XE `Cisco-IOS-XE-lldp-oper` [U, not researched].
- **Connector shape:** a dedicated domain (e.g. `network_policy`) with records for segments, objects and rules, plus connector `action`s `plan_change`, `apply_change`, `confirm_change`, `rollback_change`. That fits the current `Connector.action()` hook better than overloading `push()`.

---

## 7. Not found / open questions

- **FortiOS:**
  - The official REST reference is on FNDN, which requires login, so many cmdb paths and fields are [U].
  - Not documented in what I saw: the REST `transaction-abort` name, the unit of `{"timeout":…}`, and transaction support before 7.4.1.
  - Restore `source` enum values and the reboot behaviour of restores on 7.4/7.6/8.0.
  - Whether `cfg-save revert` reboots or reloads in place on current builds (docs conflict).
  - Rate limits: not found.
- **PAN-OS:**
  - Exact XML for `load config version N` and for read-only behaviour of custom XML-API roles.
  - Whether Web UI commit sub-privileges gate XML-API commits.
  - REST resource names for NAT/services/interfaces in v11.x/12.x.
  - Final `show jobs` status/result values.
  - Any 12.x commit-confirm feature: none found.
- **IOS-XE:**
  - No API equivalent of `configure confirm`.
  - NACM read-only configuration for a priv-15 user.
  - Whether RESTCONF writes go to running when the candidate datastore is enabled.
  - Support for `<persist>`/`<cancel-commit>`.
  - YANG path of `ip access-group` on interfaces and the switchport augment target.
  - Rate limits: not found.
- **Field formats:** test every example response on a lab unit of the exact target release before coding parsers. Vendors change field sets between releases.

---

## 8. Sources (fetched or searched 2026-10-09)

**Fortinet**
- F1 FortiOS 7.4.0 Admin Guide, REST API administrator: https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023
- F2 FortiOS 7.6.5 Admin Guide, Using APIs: https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/940602
- F3 FortiOS 7.4.0 Admin Guide, REST API example output: https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/940602/rest-api
- F4 FortiOS 7.4 New Features, View batch transaction commands through the REST API 7.4.1: https://docs.fortinet.com/document/fortigate/7.4.0/new-features/174532/view-batch-transaction-commands-through-the-rest-api-7-4-1
- F5 FortiOS 7.6.4 Admin Guide, Workspace mode: https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/530847
- F6 FortiOS 7.0.2 Configuration save mode (search excerpt; also 7.0.13): https://docs.fortinet.com/document/fortigate/7.0.2/administration-guide/228450
- F7 KB, cfg-save revert (2009): https://community.fortinet.com/fortigate-3/technical-tip-using-the-save-option-set-cfg-save-revert-to-automatically-reboot-and-revert-to-a-previous-configuration-of-a-fortigate-93653
- F8 KB, backup 405 on 7.6.0 (2025-11-11): https://community.fortinet.com/fortigate-3/troubleshooting-tip-resolving-405-method-not-allowed-error-when-generating-system-backup-via-api-on-fortigate-7-6-0-217301
- F9 KB, API 404 after 7.4.4 (2024-09-26): https://community.fortinet.com/fortigate-3/technical-tip-api-error-404-after-upgrading-to-7-4-4-183322
- F10 KB, admin trusthost precedence (2020-06-03): https://community.fortinet.com/fortigate-3/technical-tip-system-admin-s-trusthost-setting-takes-precedence-over-system-api-user-s-trusthost-98727
- F11 KB, API pagination (2025-05-13): https://community.fortinet.com/fortigate-3/technical-tip-fortigate-api-handling-result-limits-with-pagination-205682
- F12 Fortinet Ansible collection, fortios_monitor.py: https://raw.githubusercontent.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/main/plugins/modules/fortios_monitor.py
- F13 fortinet.fortios 2.6.0, fortios_firewall_policy: https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_firewall_policy_module.html
- F14 fortinet.fortios 2.6.0, fortios_system_accprofile: https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_system_accprofile_module.html
- F15 Pulumi fortios genericapi (based on Fortinet Terraform provider): https://www.pulumi.com/registry/packages/fortios/api-docs/json/genericapi
- F16 KB, About REST API: https://community.fortinet.com/t5/FortiGate/Technical-Tip-About-REST-API/ta-p/195425
- F17 FortiOS 7.2.2 default HTTPS admin certificate (search excerpt): https://docs.fortinet.com/document/fortigate/7.2.2/administration-guide/499047
- F18 KB (FortiNAC), URL token disabled from FortiOS 7.4.5 (search excerpt): https://community.fortinet.com/fortinac-f-57/technical-tip-how-to-fix-rest-api-failure-218848
- F19 KB, hit count behaviour: https://community.fortinet.com/fortigate-3/technical-tip-last-used-and-hit-count-do-not-increase-while-sessions-are-still-being-handled-by-a-firewall-policy-206018
- F20 Forum, VLAN create error -3: https://community.fortinet.com/t5/Support-Forum/REST-API-unable-to-create-interface/m-p/218064
- F21 FortiManager Ansible docs, install package: https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/galaxy-1.0.3/docgen/fmgr_securityconsole_install_package.html
- F22 fortinet.fortios 2.6.0, fortios_monitor_fact: https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_fact_module.html

**Palo Alto Networks**
- P1 XML API request types and actions: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- P2 Commit: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit
- P3 Configuration (API): https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api
- P4 Move configuration (10.2): https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api/pan-os-xml-api-request-types/configuration-api/move-configuration
- P5 Run operational mode commands: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/run-operational-mode-commands-api
- P6 API authentication and security: https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security
- P7 Enabling API access: https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/pan-os-api-authentication
- P8 Get your API key: https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key
- P9 Configure API key lifetime (search excerpt): https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/firewall-administration/manage-firewall-administrators/configure-administrative-accounts-and-authentication/configure-api-key-lifetime
- P10 Configure an admin role profile: https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators/configure-an-admin-role-profile
- P11 pan.dev PAN-OS RBAC: https://pan.dev/ansible/docs/panos/info/pan-os-rbac/
- P12 Restrict commit/validate: https://origin-docs.paloaltonetworks.com/ngfw/administration/firewall-administration/reference-web-interface-administrator-access/web-interface-access-privileges/restrict-administrator-access-to-commit-and-validate-functions
- P13 Get started with the REST API: https://docs.paloaltonetworks.com/ngfw/api/get-started-with-the-pan-os-rest-api
- P14 REST methods and query parameters (11.1): https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/methods-supported-rest-api
- P15 REST request/response structure (11.1): https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/pan-os-rest-api-request-response-structure
- P16 Create security rule (REST, 11.1): https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/create-security-policy-rule-rest-api
- P17 Work with objects (REST, 10.1): https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/work-with-address-objects-rest-api
- P18 Configure a security zone (REST): https://docs.paloaltonetworks.com/ngfw/api/pan-os-rest-api-use-cases/configure-a-security-zone-rest-api
- P19 pan.dev rule hit counts: https://pan.dev/panos/docs/tutorials/rule-hit-counts/
- P20 pan.dev rulebase to CSV: https://pan.dev/panos/docs/tutorials/rulebase-to-csv/
- P21 pan-os-python base.py: https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/base.py
- P22 pan-os-python policies.py: https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/policies.py
- P23 pan-os-python network.py: https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/network.py
- P24 Export files API (11.1): https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/export-files-api
- P25 Import files API: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/import-files-api
- P26 Revert firewall configuration changes: https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-configuration-backups/revert-firewall-configuration-changes
- P27 Commit, validate, preview: https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/commit-validate-and-preview-firewall-configuration-changes
- P28 Manage locks: https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/manage-locks-for-restricting-configuration-changes
- P29 Enable automated commit recovery (Panorama 10.2): https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/administer-panorama/enable-automated-commit-recovery
- P30 XML API error codes (10.1, search excerpt): https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/pan-os-xml-api-error-codes
- P31 Revert commands changed in 10.0: https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-cli-quick-start/cli-changes/modified-revert-commands
- P32 LIVE forum, automated rollback / FR 204: https://live.paloaltonetworks.com/t5/general-topics/any-chance-of-an-automated-rollback-on-palo-alto-firewalls/td-p/199864

**Cisco and IETF**
- C1 Programmability CG 17.15.x, RESTCONF: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1715/b_1715_programmability_cg/m_1715_prog_restconf.html
- C2 Programmability CG 17.13.x, NETCONF: https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1713/b_1713_programmability_cg/m_1712_prog_yang_netconf.html
- C3 IOS XE 17 Configuration Replace: https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/mgmt/config-replace/configuration-replace.html
- C4 IOS XE 17 Configuration Rollback Confirmed Change: https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_cm-config-rollback-confirmed-change.html
- C5 Configuration Fundamentals Command Reference, C commands (search excerpt): https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/C_commands.html
- C6 cisco-ia.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/cisco-ia.yang
- C7 Cisco-IOS-XE-rpc.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-rpc.yang
- C8 Cisco-IOS-XE-cli-rpc.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-cli-rpc.yang
- C9 Cisco-IOS-XE-acl.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-acl.yang
- C10 Cisco-IOS-XE-acl-oper.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-acl-oper.yang
- C11 Cisco-IOS-XE-vlan.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-vlan.yang
- C12 Cisco-IOS-XE-vlan-oper.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-vlan-oper.yang
- C13 Cisco-IOS-XE-interfaces-oper.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-interfaces-oper.yang
- C14 Cisco-IOS-XE-device-hardware-oper.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-device-hardware-oper.yang
- C15 Cisco-IOS-XE-switch.yang: https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-switch.yang
- C16 Catalyst 9300 17.15 Secure HTTP (search excerpt): https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/sec/b_1715_sec_9300_cg/configuring_secure_socket_layer_http.html
- C17 Cisco Community, revert timer leaves lock: https://community.cisco.com/t5/routing-and-sd-wan/revert-timer-will-not-complete-and-leaves-a-configuration-lock/td-p/3824757
- C18 RFC 8040 RESTCONF: https://www.rfc-editor.org/rfc/rfc8040.html
- C19 RFC 7951 JSON encoding of YANG: https://www.rfc-editor.org/rfc/rfc7951.html
- RFC 6241 NETCONF (§8.3 candidate, §8.4 confirmed commit): https://www.rfc-editor.org/rfc/rfc6241.html


## Confidence notes
- FortiOS: the official REST API reference is behind the Fortinet Developer Network login (fndn.fortinet.net), so many cmdb paths and field names are tagged [U]. Examples: system/interface, system/zone, firewall.service/custom, firewall/policy create/update/delete, and the POST 'mkey' response. The verified parts are: the response envelope, firewall/address, query params (format/filter/vdom), Bearer auth, trusthost rules, api-user creation, token expiry, transaction start/show/commit with the X-TRANSACTION-ID header, workspace semantics, backup/restore/revision parameter names (from Fortinet's own Ansible collection) and policy attribute names (Fortinet Ansible module).
- FortiOS cfg-save revert behaviour conflicts across Fortinet sources. The 2009 KB and the 7.0.2 guide say the unit reboots; the 7.0.13 guide says it reverts in place with brief unresponsiveness. Test on the target build. Fetching the 8.0.0 page did not return the full article body.
- FortiOS: whether a config restore reboots on 7.4/7.6/8.0, the REST name for transaction abort, and the unit of the transaction 'timeout' body field are all unverified.
- FortiOS: config backup needs a super_admin API profile per a Fortinet KB article. This conflicts with a read-only connector. I describe an alternative (hub-recorded inverse operations plus config revisions), but the permission needed to save a revision is unverified.
- PAN-OS: the XML for commit, partial commit, validate, save, load, partial revert, locks, move, set/edit and keygen is verified from official docs or the official pan-os-python SDK. Unverified: the XML form of 'load config version N', the final show-jobs status values (FIN/OK/FAIL), REST resource names for NAT, services and interfaces, and the JSON types of @count/@total-count.
- PAN-OS has no native commit-confirm. That claim rests on the absence of any such feature in the docs I reviewed and on a forum thread about feature request FR 204. Automated commit recovery is verified, but it applies only to Panorama-managed firewalls and only protects the Panorama connection.
- PAN-OS: the custom XML API role privilege list (Report, Log, Configuration, Operational Requests, Commit, User-ID Agent, Import, Export) comes from pan.dev, not a full official page. Whether Web UI commit sub-privileges gate XML API commits is unverified.
- IOS-XE: the cisco-ia RPCs (save-config, checkpoint, revert, rollback, is-syncing), Cisco-IOS-XE-rpc:copy, cli-rpc, and the ACL, ACL-oper, VLAN, VLAN-oper, interfaces-oper and device-hardware-oper paths are verified from Cisco's published YANG models (17.15.1 directory, revision 2024-07-01). Field availability on older releases may differ.
- IOS-XE: I found no API equivalent of 'configure confirm'. The 'configure terminal revert timer' syntax is from a command-reference search excerpt, not a full fetched page. Community threads report revert timers that did not fire. NETCONF confirmed commit (default 600 s, reverts if the session drops) is verified in the 17.13 guide.
- IOS-XE: no read-only RESTCONF/NETCONF role is documented, because privilege 15 is required. NACM groups PRIV00-PRIV15 exist, but whether NACM can make a priv-15 user read-only is unverified.
- Some facts come only from search-result excerpts of official pages, tagged [S]. These include the FortiOS default certificate change in 7.2.1, the FortiOS 7.4.5 URL-token default, the PAN-OS API key lifetime default and range, the PAN-OS XML error code table, and the IOS-XE self-signed trustpoint behaviour.
- I could not extract the PAN-OS API PDF (ngfw-api.pdf) because no PDF tooling is installed locally, so I used the HTML pages instead.
- The JSON examples combine verified envelope keys with verified field names, with the tagging explained in each section. Validate the exact shapes against a lab device on the target release before writing parsers.

## Sources
- https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/399023
- https://docs.fortinet.com/document/fortigate/7.6.5/administration-guide/940602
- https://docs.fortinet.com/document/fortigate/7.4.0/administration-guide/940602/rest-api
- https://docs.fortinet.com/document/fortigate/7.4.0/new-features/174532/view-batch-transaction-commands-through-the-rest-api-7-4-1
- https://docs.fortinet.com/document/fortigate/7.6.4/administration-guide/530847
- https://docs.fortinet.com/document/fortigate/7.0.2/administration-guide/228450
- https://docs.fortinet.com/document/fortigate/8.0.0/administration-guide/400334
- https://community.fortinet.com/fortigate-3/technical-tip-using-the-save-option-set-cfg-save-revert-to-automatically-reboot-and-revert-to-a-previous-configuration-of-a-fortigate-93653
- https://community.fortinet.com/fortigate-3/troubleshooting-tip-resolving-405-method-not-allowed-error-when-generating-system-backup-via-api-on-fortigate-7-6-0-217301
- https://community.fortinet.com/fortigate-3/technical-tip-api-error-404-after-upgrading-to-7-4-4-183322
- https://community.fortinet.com/fortigate-3/technical-tip-system-admin-s-trusthost-setting-takes-precedence-over-system-api-user-s-trusthost-98727
- https://community.fortinet.com/fortigate-3/technical-tip-fortigate-api-handling-result-limits-with-pagination-205682
- https://raw.githubusercontent.com/fortinet-ansible-dev/ansible-galaxy-fortios-collection/main/plugins/modules/fortios_monitor.py
- https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_firewall_policy_module.html
- https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_system_accprofile_module.html
- https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_module.html
- https://docs.ansible.com/ansible/latest/collections/fortinet/fortios/fortios_monitor_fact_module.html
- https://www.pulumi.com/registry/packages/fortios/api-docs/json/genericapi
- https://community.fortinet.com/t5/FortiGate/Technical-Tip-About-REST-API/ta-p/195425
- https://docs.fortinet.com/document/fortigate/7.2.2/administration-guide/499047
- https://community.fortinet.com/fortinac-f-57/technical-tip-how-to-fix-rest-api-failure-218848
- https://community.fortinet.com/fortigate-3/technical-tip-last-used-and-hit-count-do-not-increase-while-sessions-are-still-being-handled-by-a-firewall-policy-206018
- https://community.fortinet.com/t5/Support-Forum/REST-API-unable-to-create-interface/m-p/218064
- https://ansible-galaxy-fortimanager-docs.readthedocs.io/en/galaxy-1.0.3/docgen/fmgr_securityconsole_install_package.html
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/configuration-api
- https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-panorama-api/pan-os-xml-api-request-types/configuration-api/move-configuration
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/run-operational-mode-commands-api
- https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security
- https://docs.paloaltonetworks.com/ngfw/api/api-authentication-and-security/pan-os-api-authentication
- https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/get-your-api-key
- https://docs.paloaltonetworks.com/pan-os/10-2/pan-os-admin/firewall-administration/manage-firewall-administrators/configure-administrative-accounts-and-authentication/configure-api-key-lifetime
- https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-firewall-administrators/configure-an-admin-role-profile
- https://pan.dev/ansible/docs/panos/info/pan-os-rbac/
- https://origin-docs.paloaltonetworks.com/ngfw/administration/firewall-administration/reference-web-interface-administrator-access/web-interface-access-privileges/restrict-administrator-access-to-commit-and-validate-functions
- https://docs.paloaltonetworks.com/ngfw/api/get-started-with-the-pan-os-rest-api
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/methods-supported-rest-api
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/pan-os-rest-api-request-response-structure
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/create-security-policy-rule-rest-api
- https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-rest-api/work-with-address-objects-rest-api
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-rest-api-use-cases/configure-a-security-zone-rest-api
- https://pan.dev/panos/docs/tutorials/rule-hit-counts/
- https://pan.dev/panos/docs/tutorials/rulebase-to-csv/
- https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/base.py
- https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/policies.py
- https://raw.githubusercontent.com/PaloAltoNetworks/pan-os-python/develop/panos/network.py
- https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api/pan-os-xml-api-request-types/export-files-api
- https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/import-files-api
- https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/manage-configuration-backups/revert-firewall-configuration-changes
- https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/commit-validate-and-preview-firewall-configuration-changes
- https://docs.paloaltonetworks.com/ngfw/administration/firewall-administration/launch-the-web-interface/manage-locks-for-restricting-configuration-changes
- https://docs.paloaltonetworks.com/panorama/10-2/panorama-admin/administer-panorama/enable-automated-commit-recovery
- https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-panorama-api/get-started-with-the-pan-os-xml-api/pan-os-xml-api-error-codes
- https://docs.paloaltonetworks.com/pan-os/10-0/pan-os-cli-quick-start/cli-changes/modified-revert-commands
- https://live.paloaltonetworks.com/t5/general-topics/any-chance-of-an-automated-rollback-on-palo-alto-firewalls/td-p/199864
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1715/b_1715_programmability_cg/m_1715_prog_restconf.html
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/prog/configuration/1713/b_1713_programmability_cg/m_1712_prog_yang_netconf.html
- https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/mgmt/config-replace/configuration-replace.html
- https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_cm-config-rollback-confirmed-change.html
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/xe-16-6/config-mgmt-xe-16-6-book/cm-config-rollback-confirmed-change.html
- https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/C_commands.html
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/cisco-ia.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-rpc.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-cli-rpc.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-acl.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-acl-oper.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-vlan.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-vlan-oper.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-interfaces-oper.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-device-hardware-oper.yang
- https://raw.githubusercontent.com/YangModels/yang/main/vendor/cisco/xe/17151/Cisco-IOS-XE-switch.yang
- https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/sec/b_1715_sec_9300_cg/configuring_secure_socket_layer_http.html
- https://community.cisco.com/t5/routing-and-sd-wan/revert-timer-will-not-complete-and-leaves-a-configuration-lock/td-p/3824757
- https://developer.cisco.com/site/odp/documents/xe-user-guide-xconf-aaa/
- https://www.rfc-editor.org/rfc/rfc8040.html
- https://www.rfc-editor.org/rfc/rfc7951.html
- https://www.rfc-editor.org/rfc/rfc6241.html