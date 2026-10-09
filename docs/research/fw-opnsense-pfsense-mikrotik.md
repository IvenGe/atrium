# Open-source and SOHO firewalls: automation reference for Atrium

Research date: 2026-10-09. This is read-only research. No repository files were changed.

**Versions current at research time**
- OPNsense CE 26.7.6 (2026-10-08) and 26.1.11 (2026-07-01) [O9, O10].
- pfSense Plus 26.07 and pfSense CE 2.9.0 [P13].
- MikroTik RouterOS manual 7.26 [M1].
- pfSense REST API package (unofficial) v2.10.2 [R9].

**Confidence tags**
- **[V]**: seen in official vendor documentation or in the vendor's own source code (opnsense/core, pfsense/pfsense). The reference ID points to the exact page or file.
- **[V-src]**: verified in vendor source code but not in prose documentation. It may change without notice.
- **[U]**: unverified. Comes from memory, a forum or a third party.
- **[I]**: inferred from verified facts. Not stated anywhere.

Reference IDs (O*, P*, R*, M*, C*) are listed at the end.

---

## 0. Summary

| | OPNsense | pfSense CE / Plus | MikroTik RouterOS v7 |
|---|---|---|---|
| Official API | REST/JSON `https://<fw>/api/<module>/<controller>/<command>[/params]` [V O2] | CE: none. Plus 25.07+: the Nexus / Multi-Instance Management (MIM) controller API [V P1, P3]. HA XMLRPC exists but is meant for sync [V-src P14]. | REST/JSON `https://<router>/rest/<menu path>`, since v7.1beta4 [V M3] |
| Auth | API key and secret over HTTP Basic [V O1, O21] | SSH (admin or root) for config.xml. Nexus uses User Manager credentials [V P2]. | HTTP Basic with a RouterOS user. The group needs both `api` and `rest-api` [V M1] |
| Read-only | Page privileges plus `user-config-readonly` ("System: Deny config write") [V O19, O21] | `User - Config - Deny Config Write` (GUI only) [V P9]. Nexus `mim_read_<role>` [V P2] | A custom group with `read,api,rest-api` [V M1, M8] |
| Write + activate | `add_rule` / `set_rule` / ..., then `POST /api/firewall/filter/apply` [V O3] | Edit config.xml, run `write_config()`, then `filter_configure()` (`/etc/rc.filter_configure`) [V-src P16, P17] | Changes apply immediately. There is no commit step [I] |
| Native auto-rollback | **24.1 to 26.1.x only:** `savepoint`, `apply/<rev>`, then `cancelRollback/<rev>` within 60 s [V-src O12, O13]. **Removed in 26.7** [V O14, O15] | None. Config history plus console restore only [V P8] | Safe Mode, in the CLI and WinBox only. There is no documented REST equivalent [V M4, M5; U M11] |
| TLS default | Self-signed [V O8] | Self-signed [V P10] | No certificate. HTTPS fails until one is assigned to `www-ssl` [V M1] |

---

## 1. OPNsense

### 1.1 Which API applies to which version
- **24.1:** the former `os-firewall` plugin ("Firewall > Automation") was imported into core in January 2024 [V O36, commit 8e299d3]. Before 24.1, the plugin had to be installed [I].
- **26.1 (2026-01-28):** introduces "a new consistent rules GUI using MVC/API (formerly known as 'Automation')". It also adds a rule migration page, marked "use with care" [V O10].
- **Classic vs MVC rules:** the classic Rules page is "a static PHP page with no API support". Only "Rules [new]" (MVC) rules can be created or changed through the API [V O7].
- **26.7 (2026-07-15):** "firewall rules now defaulting to MVC/API". The legacy rules pages moved to the `os-firewall-legacy` plugin [V O9].
- **26.7 removed the savepoint actions.** Commit 17b8461 (merged 2026-06-18, PR #10411) is titled "Remove safepoint actions, no consumers in GUI are left, and we don't know of any external API consumers" [V O14, O15].
  - On 26.7.x, `/api/firewall/filter/savepoint`, `cancelRollback` and `revert` return 404 `{"errorMessage":"Endpoint not found"}` [U C1, C2. The 404 body format is V-src O24].
- **Read-order impact** (Rules [new] evaluation order) [V O7]:
  1. System rules (start).
  2. Floating rules (both implementations).
  3. Group rules (both implementations).
  4. Single-interface Rules [new].
  5. Single-interface classic Rules.
  6. System rules (end).

  Internal priorities: floating 200000, groups 300000, interfaces 400000. NAT is processed before filter rules [V O7].

### 1.2 Authentication
- **Creating keys:** in the user manager, select a user, then use the API section and "+". You receive an ini file with `key=` and `secret=`. "Secrets are not stored on OPNsense and can be downloaded only once." A user can have several keys; use one key per application [V O1].
- **Sending credentials:** HTTP Basic with the key as username and the secret as password [V O1, O2]. The server reads the `Authorization` header, base64-decodes it, splits on `:` and authenticates with the "Local API" authenticator [V-src O21].
- **Permissions:** a key has exactly the privileges of its owner user and that user's groups. Check them under the user's "Effective Privileges" [V O2].
- **Failure responses** [V-src O21]:
  - Bad credentials: HTTP 401 `{"status":401,"message":"Authentication Failed"}`.
  - Authenticated but the URL is not permitted: HTTP 403 `{"status":403,"message":"Forbidden"}`.
  - Invalid JSON body: HTTP 400 "Invalid JSON syntax".
- **CSRF** applies only to session (GUI) requests, not to API-key requests [V-src O21].
- **Group source restriction:** a group's privileges are skipped when the client IP is outside the group's `source_networks` [V-src O26]. Use this to pin the Atrium key to Atrium's address.
- **ACL matching** [V-src O26]:
  - Matching is a case-sensitive regular expression on the request path. It is not normalised.
  - `*` matches anything. A trailing `/*` also matches the bare path.

### 1.3 Least-privilege groups
Privilege IDs and their URL patterns [V-src O18, O19, O20]:

| Purpose | Privilege ID ("name") | Grants |
|---|---|---|
| Rules (read **and** write; the ACL has no method distinction) | `page-filter-api` ("Firewall: Rules [new]") | `api/firewall/filter/*` |
| Rule statistics | `page-firewall-rules` ("Firewall: Rules") | `api/firewall/filter_util/rule_stats*`, `api/firewall/category/search_item*`, `firewall_rules.php*` |
| Aliases (read-only) | `page-firewall-aliases` | `api/firewall/alias/search*`, `.../get*`, `.../list*`, `.../export` |
| Aliases (write) | `page-firewall-alias-edit` | `api/firewall/alias/*` |
| Interface groups (zone equivalent) | `page-interfaces-groups-edit` ("Firewall: Groups") | `api/firewall/group/*` |
| Categories | `page-firewall-categories` | `api/firewall/category/*` |
| Interfaces overview | `page-status-interfaces` | `api/interfaces/overview/*` |
| VLANs | `page-interfaces-vlan-edit` | `api/interfaces/vlan_settings/*` |
| Version (safe) | `page-system-login-logout` ("Lobby: Dashboard") | includes `api/diagnostics/system/system_information` |
| Config history / backup download | `page-diagnostics-configurationhistory` | `api/core/backup/*`, which **also includes `revert_backup` and `delete_backup`** |
| NAT | `page-filter-snat-api`, `page-firewall-nat-portforward-edit`, `page-firewall-nat-1-1-edit`, `page-firewall-nat-npt` | source_nat, d_nat, one_to_one, npt |
| Deny writes | `user-config-readonly` ("System: Deny config write") | No URLs. Write paths call `throwReadOnly()` |

- **Read-only Atrium group:**
  - All read rows above, plus `user-config-readonly`.
  - `throwReadOnly()` throws "User %s denied for write access (user-config-readonly set)" [V-src O21].
  - It is called from `ApiMutableModelControllerBase::save()` (all add, set, del and toggle calls) [V-src O22].
  - It is also called from `revert_backup` and `delete_backup` [V-src O27], and from `apply` on 26.1 [V-src O12].
  - Do **not** grant `page-system-firmware-manualupdate` just to read the version. It also grants `api/core/firmware/*`, which includes update, upgrade, reboot and poweroff [V-src O19, V O6].
- **Write group:** the same group without `user-config-readonly`. Use `page-firewall-alias-edit` instead of `page-firewall-aliases` only if Atrium must create aliases.
- **Casing (affects the ACL):**
  - The router maps both `search_rule` and `searchRule` to `searchRuleAction` [V-src O25].
  - The ACL is case-sensitive, so `api/firewall/category/searchItem` does **not** match the pattern `api/firewall/category/search_item*` [I from V-src O26 and O19].
  - The docs list snake_case, but their examples use camelCase (`/api/firewall/filter/searchRule`) [V O3].
  - Community sources say endpoints were renamed to snake_case in 25.7 and that older firmware needs camelCase [U, hass-opnsense].
  - Rule for Atrium: use snake_case on 25.7 or later, and camelCase before that.

### 1.4 Reading
Endpoints from the official reference [V O3, O4, O5, O6]. Signatures and semantics are [V-src] where noted.

| Data | Call | Notes |
|---|---|---|
| Interfaces | `GET /api/interfaces/overview/interfaces_info` (param `$details=false`) | Rows include `identifier` (wan/lan/optN), `description`, `device`, `enabled`, `addr4`, `addr6`, `ipv4[]`/`ipv6[]` (`ipaddr` = "ip/bits"), `vlan_tag`, `gateways`, `status`, `routes` [V-src O31]. `GET /api/interfaces/overview/export` returns a bare JSON array with statistics [V-src O31] |
| Interfaces as a picker | `GET /api/firewall/filter/get_interface_list` | Sections `floating`, `groups`, `interfaces`, `any`, each with `label`, `icon`, `items` [V-src O16] |
| VLANs | `GET/POST /api/interfaces/vlan_settings/search_item` | Fields `if`, `tag`, `pcp`, `proto`, `descr`, `vlanif` [V-src O35] |
| Zones (equivalent) | `GET/POST /api/firewall/group/search_item` | OPNsense has no zones. Interface groups are the closest construct [I] |
| Aliases (address and port objects) | `GET/POST /api/firewall/alias/search_item`, `GET /api/firewall/alias/get_item/{uuid}`, `GET /api/firewall/alias/list_network_aliases` | Model fields: `enabled`, `name`, `type` (host, network, port, url, urltable, urljson, geoip, networkgroup, mac, asn, dynipv6host, authgroup, internal, external), `proto`, `content`, `categories`, `description`, plus volatile `current_items`, `last_updated` and in/out pass/block counters [V-src O34] |
| Service objects | none | Ports are inline in `destination_port`, or a `port`-type alias [I from O17 and O34] |
| Network and port pickers | `GET /api/firewall/filter_base/list_network_select_options`, `.../list_port_select_options` | Abstract base. Call them under `filter/` [V O3; I that the `filter/` prefix is required] |
| Rules | `GET /api/firewall/filter/search_rule?current=1&rowCount=-1&searchPhrase=` (docs example uses GET with these query params [V O3]) | Optional params [V-src O16]: `interface` (absent = all rules; empty = floating view), `category`, `show_all`. **On 26.x the result also includes non-MVC (legacy) rules**, marked by a non-empty `legacy` field; these may lack `uuid` [V-src O16] |
| One rule | `GET /api/firewall/filter/get_rule/{uuid}` | Wrapped as `{"rule":{...}}` [I from `getBase("rule", ...)` in O16] |
| Hit counts | `GET /api/firewall/filter_util/rule_stats` returns `{"status":"ok","stats":{<uuid>:{...}}}`. Alternatively `search_rule?show_all=1` merges stats into rows | Stats are keyed by the pf label (= rule uuid). Keys: `pf_rules` plus the lowercased pfctl counters (typically `evaluations`, `packets`, `bytes`, `states`) [V-src O29, O30] |
| Rule export | `GET /api/firewall/filter/download_rules` | CSV with an `@uuid` key column. Category and alias references become names [V-src O11] |
| NAT | `search_rule` on `source_nat`, `d_nat`, `one_to_one`, `npt` | [V O3] |
| Version | `GET /api/diagnostics/system/system_information` | Returns `name`, `versions[]` (product name, version and arch; kernel; OpenSSL) and `updates` [V-src O32]. `GET /api/core/firmware/info` returns top-level `product_version`, but needs the firmware privilege [V-src O33] |
| Config backup | `GET /api/core/backup/backups/this` returns `{"items":[{"time","time_iso","description","username","filesize","id"}]}`, newest first. `GET /api/core/backup/download/this[/<id>]` returns raw XML as `application/octet-stream` (newest if no id) | [V O5, V-src O27]. Every `Config::save()` writes `/conf/backup/config-<microtime>.xml`. Retention is `system/backupcount`, default **100** [V-src O28] |

**Rule model** (`//OPNsense/Firewall/Filter`, model version 1.0.9) [V-src O17]. Main fields:
- `enabled` (default 1), `sequence` (1–999999), `action` (pass/block/reject/match), `quick` (default 1).
- `interface` (multiple), `interfacenot`, `direction` (in/out/any), `ipprotocol` (inet/inet6/inet46), `protocol` (default any).
- `source_net` (default any, multiple, alias allowed), `source_not`, `source_port`; `destination_net`, `destination_not`, `destination_port`.
- `log` (default 0), `categories`, `description`, `gateway`, `statetype` (keep/sloppy/modulate/synproxy/none).
- `sort_order` and `prio_group` (volatile), `audit` (JsonAuditField).

**Search grid paging** [V O2, V-src O23]:
- Parameters: `current` (1-based, default 1), `rowCount` (default -1 = all; 0 returns no rows), `sort` (`{"field":"asc|desc"}`, POST only), `searchPhrase` (space-separated tokens, case-insensitive substring, all tokens must match).
- Response: `{"total","rowCount","current","rows":[...]}`. Each row has `uuid`, the field values, and `%<field>` display labels when they differ from the raw value.

### 1.5 Writing a single rule (current API) [V O3; V-src O11, O16, O22]
| Operation | Call | Body | Success response |
|---|---|---|---|
| Create | `POST /api/firewall/filter/add_rule` | `{"rule":{"description":"...","interface":"lan","source_net":"lan","destination_net":"10.0.0.0/24","protocol":"TCP","destination_port":"443","action":"pass"}}` | `{"result":"saved","uuid":"..."}` |
| Update | `POST /api/firewall/filter/set_rule/{uuid}` | `{"rule":{...partial fields...}}` | `{"result":"saved"}` |
| Delete | `POST /api/firewall/filter/del_rule/{uuid}` | none | `{"result":"deleted"}` or `{"result":"not found"}` |
| Enable/disable | `POST /api/firewall/filter/toggle_rule/{uuid}/{0or1}` | none | `{"result":"Enabled"/"Disabled","changed":true}` |
| Move | `POST /api/firewall/filter/move_rule_before/{selected_uuid}/{target_uuid}` (POST required) | none | `{"status":"ok"}` |
| Activate | `POST /api/firewall/filter/apply` | none | `{"status":"<configd output>"}`. Runs `configd filter reload skip_alias` |

- Validation failures still return HTTP 200, with `{"result":"failed","validations":{"rule.<field>":"message"}}` [V-src O22].
- **Move:** the moved rule gets the midpoint sequence when the gap is greater than 2. Otherwise later rules are shifted up in steps of 50 [V-src O11].
  - The docs list `move_rule_before` as GET for the NAT controllers, but the shared base implementation requires POST [V O3 vs V-src O11]. Always use POST.
- **Activation:**
  - Every add, set, del or toggle writes config.xml immediately (`Config::save` creates a backup revision) [V-src O22, O28].
  - The running pf ruleset does not change until `apply` [V O3].
  - `apply` skips alias reload, so call `POST /api/firewall/alias/reconfigure` after creating or changing aliases [V-src O11; I].

### 1.6 Safe change
**A. OPNsense 24.1 to 26.1.x: native savepoint with a 60 s auto-revert** [V-src O12, O13]

| Step | Call | Response / effect |
|---|---|---|
| 1 | `POST /api/firewall/filter/savepoint` | `{"status":"ok","retention":"<backupCount>","revision":"<config revision time>"}` |
| 2 | Make changes with `add_rule` / `set_rule` / ... | |
| 3 | `POST /api/firewall/filter/apply/{revision}` | Reloads the filter and starts configd `filter rollback_timer <revision>`. The timer loops 60 times with 1 s sleeps. If not cancelled, it runs `$mdlFilter->rollback($revision)` and then `filter reload` |
| 4 | Open a **new** connection and verify reachability. Then `POST /api/firewall/filter/cancelRollback/{revision}` before the 60 s run out | |
| 5 (manual) | `POST /api/firewall/filter/revert/{revision}` | Returns `{"status":"ok"}`, or `{"status":"unknown (or removed) savepoint"}` |

- **Scope:** rollback restores the **Filter model only** (rules), not aliases, interfaces or the whole config [V-src O12, O13].
- **Revision format:** `revision` is digits and dots only; other characters are stripped [V-src O13].
- **Probe:** `GET /api/firewall/filter/savepoint` returning 404 means the feature is absent [U C1].

**B. OPNsense 26.7 and later: no native commit-confirm** [V O14]. The maintainers say "eventually we need to put a more generic mechanism in place" [V O15]. Most reliable programmatic substitute:
1. `GET /api/core/backup/backups/this` and store `items[0].id` (the current revision). Optionally download it with `GET /api/core/backup/download/this/<id>` [V-src O27].
2. Make the change, then `POST /api/firewall/filter/apply`.
3. Verify with a fresh TCP/TLS connection (new client, no keep-alive) [I].
4. To roll back while the API is reachable: `POST /api/core/backup/revert_backup/<id>`, which returns `{"status":"reverted"}`. Then `POST /api/firewall/filter/apply` [V-src O27; I for the apply step].
   - `revert_backup` restores the **entire** config.xml and does not reload services itself [V-src O27, O28].
5. If unreachable, there is no automatic recovery. Raise an operator alert with the revision id to restore at the console.
- **Heavier option:** ZFS snapshots API `core/snapshots/add|activate`. Activation implies a reboot [V O5 for endpoints; I/U for the reboot semantics].

### 1.7 Transport
- **TLS:** "By default, a self-signed certificate is used" [V O8]. The docs' own samples use `verify='OPNsense.pem'` or curl `-k` [V O1]. Pin the CA or certificate. Atrium `Connector.http(verify=<ca path>)` already supports this.
- **Redirects:** the GUI may redirect HTTP to HTTPS. Atrium's client does not follow redirects, so configure `https://` explicitly [I].
- **Rate limits:** none documented [V: not found in O1 or O2].
- **Error bodies** [V-src O24]:
  - Unknown route: 404 `{"errorMessage":"Endpoint not found"}`.
  - User exception: HTTP code taken from the exception, with `errorMessage` and optional `errorTitle`.
  - Other errors: 500 `{"errorMessage":"Unexpected error, check log for details"}`.
  - Auth errors: see 1.2.
- **Idempotency** [I from V-src O22]:
  - `add_rule` creates a new uuid on every call. Search by a marker in `description`, or by a category, before adding.
  - `set_rule` and `toggle_rule/{uuid}/{0|1}` are idempotent.
  - A repeat `del_rule` returns `"not found"`.

### 1.8 Example: `search_rule` response
Shape is [V-src O16, O23]. Values are illustrative. String encoding of booleans and numbers is [U].
```json
{
  "total": 1,
  "rowCount": 1,
  "current": 1,
  "rows": [
    {
      "uuid": "3f2a9c1e-7b4d-4e8a-9c0f-1a2b3c4d5e6f",
      "enabled": "1",
      "sequence": "100",
      "action": "pass",
      "%action": "Pass",
      "quick": "1",
      "interface": "lan",
      "interfacenot": "0",
      "direction": "in",
      "ipprotocol": "inet",
      "protocol": "TCP",
      "source_net": "lan",
      "source_not": "0",
      "source_port": "",
      "destination_net": "web_servers",
      "destination_not": "0",
      "destination_port": "443",
      "log": "1",
      "categories": "",
      "description": "atrium:edge-17 LAN to web",
      "category_colors": [],
      "alias_meta_destination_net": {}
    }
  ]
}
```
With `show_all=1`, matching rows gain `pf_rules`, `evaluations`, `packets`, `bytes` and `states` [V-src O16, O30].

### 1.9 Lockout gotchas (OPNsense)
- **MVC rules come first.** Interface rules in Rules [new] are evaluated **before** classic interface rules [V O7]. A new MVC `block` on LAN overrides legacy LAN allow rules.
- **Empty interface.** A rule with no interface behaves as floating and matches everywhere [V-src O16 search semantics; I for pf behaviour]. Always set `interface`.
- **Quick by default.** `quick` defaults to 1 (first match wins) [V-src O17].
- **26.7 has no automatic revert.** See 1.6.B.
- **26.1 window.** The 60 s rollback window is short. Verify with a lightweight call such as `GET /api/diagnostics/system/system_information`, then cancel at once [I].
- **Anti-lockout rule.** OPNsense creates an automatic anti-lockout rule on LAN for web GUI and SSH access. It can be disabled under System > Settings > Administration [U, forum and opnsense/core PR #7381]. Never disable it from Atrium.
- **Web GUI listen interfaces.** These can be limited. The docs warn that misconfiguration can make the web interface or SSH inaccessible [V O8]. Treat these settings as out of scope for automation.
- **Aliases.** Deleting an alias referenced by a rule, or a rule referencing an alias that has not been reconfigured yet, changes matching [I]. `POST /api/firewall/alias_util/find_references` exists [V O3]; semantics [U].
- **Legacy-rule migration.** `/api/firewall/migration/flush` exists [V O3]. Its effect on legacy rules is [U]. Never automate it.
- **HA.** Config sync to a peer may propagate a bad rule [U].

---

## 2. pfSense CE and pfSense Plus

### 2.1 What official automation exists
1. **pfSense CE: no official REST API** [I: none found in Netgate docs P1–P12].
2. **pfSense Plus 25.07+: Netgate Nexus** (multi-instance management controller) [V P1]. It is a "GUI configuration interface and API for pfSense Plus software", available in "versions 25.07 and later", and it can manage the host it runs on [V P1].
   - **Auth:** pfSense User Manager accounts [V P2].
   - **Authorization groups:** names are `mim_<capability>_<role>`.
     - Capabilities: `read` (GET), `modify` (POST, PUT, PATCH), `delete` (DELETE).
     - Roles include `firewall`, `interfaces`, `system`, `superuser`.
     - The `admins` group is full superuser [V P2].
     - A read-only firewall group would be `mim_read_firewall` [I from P2].
   - **OpenAPI spec:** `pfapi_openapi.yml` (info.title "pfSense API", version "1.0") in github.com/Netgate/pfsense-api, Apache-2.0 [V P3]. Paths seen in the spec [V P3]:
     - `/firewall/rules/interface`
     - `/firewall/rules/interface/{interface}` (GET, POST)
     - `/firewall/rules/interface/{interface}/{id}` (PATCH, POST, DELETE)
     - `.../toggle/{id}`, `.../reorder`, `.../copy`, `.../separators`
     - `/aliases`, `/aliases/{id}`
     - `/interfaces`, `/interfaces/assigned`
     - `/firewall/nat/port-forward|outbound|onetoone|npt`
     - `/diag/backup` with `/restore`, `/prior`, `/diff`
   - **Not found in the parts of the spec read:** the server base URL and per-device path prefix, the security scheme, the login endpoint, the rule schema and an apply/commit call. Inspect `pfapi_openapi.yml` fully before implementing.
3. **XMLRPC (`/xmlrpc.php`)**, intended for HA sync [V-src P14].
   - Methods: `pfsense.host_firmware_version`, `exec_php`, `exec_shell`, `backup_config_section`, `restore_config_section`, `merge_installedpackages_section`, `merge_config_section`, `captive_portal_sync`, `interfaces_carp_configure`, `reboot`.
   - Auth: HTTP Basic. Allowed accounts are the admin account (uid 0) or a user holding `system-xmlrpc-ha-sync`.
   - `restore_config_section` replaces whole sections, including `filter`, `aliases` and `nat`, then runs `filter_configure` and restarts dependent services.
   - Not suitable for single-rule changes. `exec_*` is root-equivalent [I]. Not recommended.
4. **SSH plus config.xml (recommended fallback).**
   - The live file is `/conf/config.xml` [V P7]. Writes go to `<cf_conf_path>/config.xml`, and backups to `/cf/conf/backup/*.xml` [V-src P16].
   - A full download is supported: `ssh root@<fw> cat /cf/conf/config.xml > backup.xml` [V P6].
5. **GUI scraping of `diag_backup.php`** [V P6]:
   1. Get the `__csrf_magic` token.
   2. POST `login=Login`, `usernamefld`, `passwordfld` and the token.
   3. POST `download=download`, `donotbackuprrd=yes` and a fresh token.

   This is fragile. Use it only if SSH is unavailable.
6. **Other CLI tools:** `easyrule` [V P4] and `pfSsh.php playback <script>` [V P12].

### 2.2 Authentication and least privilege
- **SSH:** the privilege "User - System - Shell account access" allows SSH login "though the user will not have root-level access" [V P9]. Reading `/cf/conf/config.xml` as a non-root user is [U].
  - In practice, automation that writes config needs `admin`/root. Netgate's own backup examples use root SSH [V P6].
  - SSH key-only auth is available under System > Advanced > Admin Access ("Public Key Only") [V P10].
- **Read-only:** "User - Config - Deny Config Write" blocks config.xml writes but "does not prevent the user from taking other actions" [V P9]. There is no general read-only mode for SSH [I].
- **Nexus:** `mim_read_<role>` for reads, and `mim_modify_firewall` plus `mim_delete_firewall` for rule writes [V P2 for the group syntax; I for this combination].

### 2.3 Reading (config.xml)
| Data | Location | Status |
|---|---|---|
| Interfaces | `interfaces/<wan\|lan\|optN>`: `if`, `enable`, `descr`, `ipaddr` (IP, or e.g. `dhcp`), `subnet`, `ipaddrv6`, `subnetv6`, `gateway`, `blockpriv`, `blockbogons` | [V-src via R8 NetworkInterface model, config path `interfaces`; the `dhcp` value is U] |
| VLANs | `vlans/vlan`: `if`, `tag`, `vlanif`, `pcp`, `descr` | [V-src via R8] |
| Zones | none. Interfaces and interface groups (`ifgroups`) | [U] |
| Aliases | `aliases/alias`: `name`, `type`, `address` (space-separated), `detail` (`\|\|`-separated), `descr` | [V-src via R8]. Core alias types beyond host, network and port (url, urltable, ...) are [U] |
| Rules | `filter/rule[]`, in evaluation order per interface (floating first) | Keys read by `filter_generate_user_rule()` [V-src P15]: `type` (pass/block/reject), `interface`, `ipprotocol`, `protocol`, `source`/`destination` (`any`/`network`/`address`, `not`, `port`), `disabled`, `log`, `descr`, `tracker`, `floating`, `quick`, `direction`, `statetype`, `gateway`, `icmptype`, `sched`, `tag`, `tagged`. Element-order-as-evaluation-order is [I] |
| Rule identity | `tracker` | Becomes pf `ridentifier <tracker>` and a label item [V-src P15]. pfrest sets it to a Unix timestamp at creation [V-src R8] |
| Hit counts | `pfctl -vvsr`, matching `ridentifier <tracker>` | [I. The pf counters "Evaluations/Packets/Bytes/States" are parsed the same way by OPNsense, V-src O30] |
| NAT | `nat/rule` (port forward), `nat/outbound/rule`, `nat/onetoone` | [U] |
| Product version | `/etc/version` (e.g. `2.9.0-DEVELOPMENT` on master) | [V-src P18]. The `<version>` element in config.xml is the config schema version, not the product version [I] |
| Backup | `cat /cf/conf/config.xml`, or `diag_backup.php` | [V P6]. Config History keeps the previous 30 configs by default; adjust with "Backup Count" [V P8] |

### 2.4 Writing a single rule (official primitives, via SSH) [V-src P16, P17; V P12 for `write_config`]
1. Back up first: `cp /cf/conf/config.xml /root/atrium-pre-<changeid>.xml` [I].
2. Run a PHP script with `/usr/local/bin/php -f <script>` [U path]. The script should:
   - `require_once("config.inc"); require_once("filter.inc");`
   - `$rules = config_get_path('filter/rule', []);`
   - Insert, update or delete the target, located by `tracker`.
   - `config_set_path('filter/rule', $rules);`
   - `write_config("Atrium: <change>");`
   - `filter_configure();`

   Function signatures [V-src P16]:
   - `config_get_path(string $path, $default = null)`
   - `config_set_path(string $path, $value, $default = null)`
   - `config_del_path(...)`
   - `write_config($desc="Unknown", $backup = true, $write_config_only = false)`

   `write_config` backs up the previous file to `/cf/conf/backup/config-<time>.xml` and records the username in the revision [V-src P16].
3. **Activation:** `filter_configure()` sends the "filter reload" event [V-src P15]. From the shell, `/etc/rc.filter_configure` calls `filter_configure()` [V-src P17].
4. **When editing XML text instead of using PHP:** run `rm /tmp/config.cache`, then reload. `viconfig` clears the cache automatically [V P7].
5. **New rule fields** (`created`/`updated` = `{time, username}`) [V-src R8]:
   - `tracker`: a unique integer.
   - `type`, `interface`, `ipprotocol`, `protocol`, `source`, `destination`, `descr`.
   - Presence-flag semantics for `disabled` and `log` (presence = true) are [U].
6. **Ordering:** insert the element before the target rule's index. Interface **separators** store row positions and may need adjusting [U].
- **`easyrule` alternative** (pass/block only) [V P4]:
  - `easyrule pass <if> <proto> <src> <dst> [port]`
  - `easyrule block <if> <src>` (adds the source to an EasyRule block alias)
  - `easyrule unblock <if> <src>`, `easyrule showblock <if>`
  - It cannot delete or move arbitrary rules. Whether it reloads the filter is not stated.

### 2.5 Safe change (pfSense)
- **No native commit-confirm or auto-rollback** [I: none found in P5, P8, P11].
- **Native recovery:**
  - Config History restore in the GUI. It does not reboot; reload the filter after restoring rules [V P8].
  - Console option 15, "Restore Recent Configuration" [V P8].
  - Restoring a full config through Backup/Restore **reboots** [V P7].
- **Programmatic dead-man pattern** [I; availability of `daemon(8)` is U]:
  1. Back up config.xml (2.4 step 1).
  2. Arm the timer: `daemon -f sh -c 'sleep 120; [ -f /tmp/atrium-arm-<id> ] && cp /root/atrium-pre-<id>.xml /cf/conf/config.xml && rm -f /tmp/config.cache && /etc/rc.filter_configure'`, after `touch /tmp/atrium-arm-<id>`.
  3. Apply the change.
  4. Verify over a **new** SSH or HTTPS connection.
  5. `rm /tmp/atrium-arm-<id>`.
  - Restoring the whole file also reverts concurrent edits made by others. A tracker-scoped inverse PHP script is more precise.
- **pfSense Plus only:** ZFS Boot Environments allow snapshots [V P5 lists "ZFS Boot Environments (Plus Only)"]. Activation semantics (reboot) are [U].
- **Recovery commands from the docs** [V P11]:
  - `pfctl -d` disables the firewall, and NAT with it; `pfctl -e` re-enables it.
  - `easyrule pass wan tcp <client> <fw> 443`.
  - `pfSsh.php playback enableallowallwan` (dangerous; remove afterwards).
  - `pfctl -T flush -t sshguard`.

### 2.6 Transport (pfSense)
- **TLS:** the GUI generates a default self-signed certificate on first boot [V P10]. SSH host keys should be pinned [I].
- **Login protection (sshguard)** covers both GUI and SSH: threshold 30, block time 120 s, detection time 1800 s, with a pass list [V P10]. Add the Atrium host to the pass list or keep credentials correct. Repeated failures block Atrium's IP.
- **Pagination, rate limits, error format:** not applicable to SSH. XMLRPC faults are -1 "Authentication failed: Invalid username or password" and -2 "...not enough privileges" [V-src P14].

### 2.7 Example rule in config.xml
Keys are [V-src P15, R8]. Values and empty-element flags are illustrative [U].
```xml
<rule>
  <tracker>1760000000</tracker>
  <type>pass</type>
  <interface>lan</interface>
  <ipprotocol>inet</ipprotocol>
  <protocol>tcp</protocol>
  <source><network>lan</network></source>
  <destination><address>web_servers</address><port>443</port></destination>
  <log></log>
  <descr><![CDATA[atrium:edge-17 LAN to web]]></descr>
  <created><time>1760000000</time><username>atrium@10.0.0.5</username></created>
</rule>
```

### 2.8 UNOFFICIAL: pfSense REST API package (pfrest)
This package "is not affiliated or supported by Netgate or the pfSense team" [V R1]. Maintainer: Jared Hendrickson [V R1].
- **Install:**
  - CE: `pkg-static add https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-<version>-pkg-RESTAPI.pkg`
  - Plus: the same command with `pkg-static -C /dev/null add ...`
  - Supported: CE 2.8.1 and 2.9.0; Plus 25.11.1, 26.03, 26.03.1 and 26.07 [V R7].
  - "pfSense removes unofficial packages during system updates", so reinstall after every upgrade [V R7].
- **Auth** [V R2]:
  - Basic (local database only).
  - API key in the `X-API-Key` header. Create keys under System > REST API > Keys or with `POST /api/v2/auth/key`.
  - JWT: `POST /api/v2/auth/jwt`, then `Authorization: Bearer`. Default lifetime 1 h (`jwt_exp`).
  - Login protection is on by default.
- **Privileges** [V-src R8 Endpoint.inc]:
  - One privilege per endpoint and method, named from the URL, e.g. `api-v2-firewall-rule-get` and `api-v2-firewall-rules-get`.
  - "WebCfg - All pages" grants everything.
  - There is a global `read_only` setting: non-GET requests then fail with `ENDPOINT_METHOD_NOT_ALLOWED_IN_READ_ONLY_MODE`.
  - "User - Config: Deny Config Write" is honoured [V R2].
- **Endpoints** [V-src R8]:
  - `/api/v2/firewall/rule` (GET, POST, PATCH, DELETE; singular, needs `id`).
  - `/api/v2/firewall/rules` (GET, PUT replaces all, DELETE by query).
  - `/api/v2/firewall/apply`: GET returns `applied` and `pending_subsystems`; POST applies.
  - Other models: `vlans/vlan`, `aliases/alias` and `interfaces`.
- **Control parameters** [V R4]:
  - `apply` (default false) applies immediately.
  - `async` (default true): poll `GET /api/v2/firewall/apply`.
  - `dry_run` validates only.
  - `placement` sets the position. Ordering is sensitive: "wrong placement may block or allow all traffic".
- **IDs** are array indexes. They "can change if objects are reordered or deleted" [V R6]. Always re-query, and match on `tracker` or a `descr` marker [I].
- **Pagination and filtering** [V R3]:
  - `limit` and `offset` on GET and DELETE of plural endpoints.
  - Filters use the form `field__contains`, `__exact`, `__startswith`, `__in`, `__lt`, `__regex`, ...
  - Sorting: `sort_by`, `sort_order` (SORT_ASC/SORT_DESC), `sort_flags`.
- **Envelope:** `{"code","status","response_id","message","data"[,"_links"]}`. `status` is the lowercase HTTP reason [V-src R8 Response.inc].
- **Rule fields** [V-src R8 FirewallRule.inc]:
  - `type` (pass/block/reject), `interface` (list), `ipprotocol` (inet/inet6/inet46), `protocol`, `icmptype`.
  - `source`, `source_port`, `destination`, `destination_port`, `descr`, `disabled`, `log`, `statetype`, `gateway`, `sched`.
  - `floating` (read-only), `quick`, `direction`, `tracker` (read-only).
  - `associated_rule_id`, `created_time`, `created_by`, `updated_time`, `updated_by`.

Example `GET /api/v2/firewall/rules?limit=50&offset=0`. Keys are [V-src R8]. The `response_id` value and the data values are [U].
```json
{"code":200,"status":"ok","response_id":"SUCCESS","message":"",
 "data":[{"id":0,"type":"pass","interface":["lan"],"ipprotocol":"inet","protocol":"tcp",
          "source":"lan","source_port":null,"destination":"web_servers","destination_port":"443",
          "descr":"atrium:edge-17","disabled":false,"log":true,"statetype":"keep state",
          "floating":false,"tracker":1760000000}]}
```

### 2.9 Lockout gotchas (pfSense)
- **Anti-lockout rule:**
  - On LAN, or on WAN in single-interface appliance mode. It allows TCP 443, TCP 80 (redirect) and TCP 22 (if SSH is enabled) to the firewall, and follows a changed GUI port. It overrides user rules [V P10 plus official page excerpt, P19].
  - It is disabled under System > Advanced > Admin Access, "Disable webConfigurator anti-lockout rule" [V P19]. Atrium must never set this.
  - Re-enable it from the console by re-setting the LAN IP [V P19].
- **No rollback timer.** Use the dead-man pattern in 2.5.
- **Full config restore reboots** [V P7]. Prefer section-level reload.
- **XMLRPC section replacement** wipes the whole `filter` section on the target [V-src P14].
- **Changing IDs.** pfrest ids shift after deletes [V R6]. GUI separators shift with inserted rows [U].
- **sshguard** can block the Atrium host after bad credentials [V P10].
- **Upgrades remove pfrest** [V R7]. Detect its absence and fall back to read-only over SSH.

---

## 3. MikroTik RouterOS v7

### 3.1 Authentication and least privilege
- **Requirements:**
  - HTTP Basic with a RouterOS user [V M1, M3].
  - The `www-ssl` service with a certificate. Plain `www` works from v7.9 but is discouraged [V M1, M3].
  - The REST server logs in through the API, so the user's group needs **both `rest-api` and `api`** [V M1, M2].
- **Group policies** [V M1, M8]:
  - **Read-only:** `read,api,rest-api`. Create a custom group: the built-in `read` group also includes `sensitive`, `reboot`, `ssh` and others [V M8].
  - **Rule writes:** add `write`.
  - **Export to file:** `ftp`. Reading files with `/file/read` needs `ftp` and `test`.
  - **Revealing secrets in exports:** `sensitive`.
  - **Full export and read flow:** `read,write,ftp,test,api,rest-api` [V M1].
- **Group-change caveat:** `/user/group/add` drops unlisted policies. Policy changes take effect when the cached login renews, **within 10 minutes** [V M1].
- **Restricting access:**
  - The user's `address` property limits login source [V M8].
  - `available-from` on `www-ssl`.
  - `rest-plain=no` under `/ip/service/webserver` [V M1].
- **Errors** [V M1]:
  - 401: bad credentials, missing `rest-api`, or `address` mismatch.
  - 500 `std failure: not allowed (9)`: `api` missing.
  - 500 `not enough permissions (9)`: a command policy is missing.

### 3.2 Reading
GET maps to `print` [V M1].

| Data | Call | Status |
|---|---|---|
| Interfaces | `GET /rest/interface` (e.g. `?type=ether&running=true`) | [V M1] |
| IP addresses / subnets | `GET /rest/ip/address`, returning `.id`, `address`, `network`, `interface`, `actual-interface`, `disabled` | [V M3] |
| VLANs | `GET /rest/interface/vlan` (`vlan-id`, `interface`). Bridge VLAN filtering: `GET /rest/interface/bridge/vlan` | [U] |
| Zones (equivalent) | Interface lists: `GET /rest/interface/list` and `GET /rest/interface/list/member` | [U] |
| Address objects | `GET /rest/ip/firewall/address-list` | [V M1 shows address-list usage; field names U] |
| Service objects | none. Ports are inline (`protocol`, `dst-port`, `src-port`) | [V M6 for the properties; I for "none"] |
| Rules | `GET /rest/ip/firewall/filter` (IPv6: `/rest/ipv6/firewall/filter`). Filter with `?chain=input` | Properties [V M6]: `chain`, `action` (accept, jump, return, log, passthrough, add-src-to-address-list, add-dst-to-address-list, drop, reject, tarpit, fasttrack-connection), `src-address`, `dst-address`, `src-address-list`, `dst-address-list`, `protocol`, `src-port`, `dst-port`, `in-interface`, `out-interface`, `in-interface-list`, `out-interface-list`, `connection-state`, `log`, `log-prefix`, `jump-target`. Plus `comment`, `bytes`, `packets` [V M7]. List order is evaluation order within a chain [I] |
| Hit counts | `bytes` and `packets` per rule (CLI: `print stats`) | [V M7]. Their presence in plain REST GET output is [U]. Fallback: `POST /rest/ip/firewall/filter/print` with `{"stats":""}` [U] |
| Dynamic rules | Shown only by `print dynamic` | [V M7] |
| NAT | `GET /rest/ip/firewall/nat` | [V M1, M3] |
| Version | `GET /rest/system/resource` (`board-name`, `architecture-name`, ...). Also `/rest/system/package`, `/rest/system/routerboard` | [V M3 for resource; the field `version` and other menus are U] |
| Export | `POST /rest/export` with `{"file":"atrium-pre-<id>"}`. Then `POST /rest/file/read` with `{"file":"atrium-pre-<id>.rsc","chunk-size":32768,"offset":0}`, repeated until `data` is empty. Then `DELETE /rest/file/atrium-pre-<id>.rsc` | [V M1]. Passwords and keys are excluded unless `"show-sensitive":""` is sent with the `sensitive` policy [V M1]. `path=` limits the export to menus [V M4] |
| Projection and complex queries | `?.proplist=a,b` on GET. `POST .../print` with `{".proplist":"...",".query":["type=ether","type=vlan","#\|!"]}` | [V M1] |

### 3.3 Writing a single rule [V M1]
| Operation | Call | Result |
|---|---|---|
| Create | `PUT /rest/ip/firewall/filter` with `{"chain":"forward","action":"accept","src-address-list":"seg-users","dst-address-list":"seg-servers","protocol":"tcp","dst-port":"443","comment":"atrium:edge-17","place-before":"*7"}` | 201. Returns the created record with `.id` and a `Location` header. Without `place-before` the rule is appended [I] |
| Update | `PATCH /rest/ip/firewall/filter/*A` with partial JSON | 200 with the changed record |
| Delete | `DELETE /rest/ip/firewall/filter/*A` | 204. A repeat returns 404 |
| Move | `POST /rest/ip/firewall/filter/move` with `{".id":"*A","destination":"*7"}` | The documented example is on `/ip/firewall/nat/move` [V M1]. Use on `filter` is [I]. The frozen old page shows a malformed body `{".id":"*9",".id":"*C"}` [V M3]. Use the 7.26 form |
| Disable | `PATCH .../*A` with `{"disabled":"true"}` | [I] |

- **Activation:** there is no apply or commit step. Each request runs the console command, which takes effect immediately [I from M1/M3: "JSON wrapper of the console API"].
- **Request header:** `Content-Type: application/json` is required, otherwise 415 [V M1].
- **Value encoding:** replies encode every value as a string. Requests accept `"yes"`, `true`, numbers or strings. Flags take `""` [V M1].

### 3.4 Safe change (RouterOS)
- **Safe Mode** [V M4]:
  - Entered with F4 or Ctrl+X in the CLI, or the WinBox button.
  - Changes made in safe mode, including from other sessions, are undone if the safe-mode session ends abnormally. For a dropped connection this happens after the 9-minute TCP timeout.
  - Ctrl+D undoes the changes; `/quit` keeps them.
  - History holds 100 actions. On overflow, safe mode ends **without** undo.
- **Safe Mode and REST:**
  - A `safe-mode` settings menu exists with read-only properties `enabled`, `user`, `current`, `owner` (manual 7.24–7.26) [V M5].
  - **No documented way to enter safe mode over REST or API** [V: absent from M1. A forum request says it is not implemented, U M11].
  - Do not rely on it from Atrium.
- **Undo / redo:** `/undo`, `/redo`, `/system/history/print` [V M4]. Running `/undo` over REST is [U]. It acts on the global history, which may hold other users' actions [I].
- **Backup:** `/system/backup/save name=<n> password=<p>` saves a binary backup. `/system/backup/load name=<n>` restores it **and reboots**. Restore on the same RouterOS version only [V M10].
- **Import:** `import <file>.rsc` with `verbose`, `dry-run` and `from-line` (verbose mode only) [V M4]. Importing a full export onto a live config does not cleanly revert it (duplicates) [I].
- **Recommended dead-man switch** [I. Scheduler properties V M9]:
  1. `GET /rest/system/clock` to read router time [U path].
  2. `PUT /rest/system/scheduler` with:
     ```json
     {"name":"atrium-rb-<id>","start-date":"<YYYY-MM-DD>","start-time":"<now+120s>","interval":"0s",
      "on-event":"/ip/firewall/filter/remove [find comment=\"atrium:<id>\"]; /system/scheduler/remove [find name=\"atrium-rb-<id>\"]"}
     ```
     This is the inverse of the planned change. For an update, use `set` with the old values. For a delete, use `add` with `place-before`.
     - The scheduler `policy` defaults to the adding user's policies [V M9]. The user needs `write`.
     - `interval=0s` runs it once [V M9].
  3. Apply the change.
  4. Verify with a **new** connection.
  5. `DELETE /rest/system/scheduler/<.id>`.
  - Caveat: requests of one user run serially, and a request keeps running after the client disconnects [V M1]. Use a separate verification user, or account for queueing [I].

### 3.5 Transport (RouterOS)
- **TLS:** no certificate by default. `certificate=none` makes HTTPS fail. Self-signed certificates need their CA trusted by the client. `tls-version=only-1.2` is available [V M1].
- **Pagination:** none documented. Narrow results with query params and `.proplist` [V M1: none described].
- **Rate limits:** none documented [V M3]. Concurrency is serial per user, parallel across users. Logins are cached for 10 minutes [V M1].
- **Timeout:** 60 s per request. Longer requests end with 400 `{"detail":"Session closed",...}` [V M1, M2].
- **Errors** [V M1]: JSON `{"detail":"...","error":400,"message":"Bad Request"}`.
  - 400 `no such command or directory (x)`.
  - 400 `Failed to parse json`.
  - 404: unknown `.id`.
  - 403: HTML page, returned when the REST part of the web server is disabled.
  - 415: wrong content type.
- **Idempotency:** none [V M1].
  - PUT always creates a new record.
  - A duplicate address-list entry returns 400 `failure: already have such entry`.
  - A repeat DELETE returns 404.
  - Use a `comment` marker (`atrium:<edge-id>`) and look it up before writing [I].

### 3.6 Example: `GET /rest/ip/firewall/filter?chain=input`
`.id` and string-encoded values are [V M3, M1]. Property names are [V M6, M7]. `dynamic`/`invalid` keys and the values are [U].
```json
[
  {".id":"*2","chain":"input","action":"accept",
   "connection-state":"established,related,untracked",
   "comment":"defconf: accept established,related,untracked",
   "disabled":"false","dynamic":"false","invalid":"false",
   "log":"false","log-prefix":"","bytes":"1048576","packets":"9000"}
]
```

### 3.7 Lockout gotchas (RouterOS)
- **Append position.** A rule PUT without `place-before` is appended [I]. A `drop` placed above the management `accept` in chain `input`, or an `in-interface-list` mismatch, cuts access instantly. There is no commit step to catch it.
- **Default config.** The default firewall drops `input` from anything not in interface list `LAN` ("defconf: drop all not coming from LAN"). A new VLAN not added to `LAN` cannot reach the router [U, forum].
- **No Safe Mode over REST.** Use the scheduler dead-man switch.
- **Requests can't be cancelled.** A request keeps running after the client disconnects [V M1].
- **Service and user restrictions.** Editing `/ip/service` (`www-ssl` `available-from`, port, certificate) or `/user` `address` can lock Atrium out [V M1, M8 for the properties; I for the risk]. Keep these out of scope.
- **Policy-change delay.** Group policy changes lag up to 10 minutes [V M1].
- **Backup restore reboots** [V M10].
- **Opaque IDs.** `.id` values (`*A`) are internal. Do not persist them as stable identity; match on `comment` [I. Stability across reboots is U].

---

## 4. Implementation notes for Atrium (segmentation panel)

These notes cover the "drag an arrow between segments" feature.

### 4.1 Normalised model and per-product mapping
- **Segment.** OPNsense: an interface `identifier`, an interface group, or a network alias. pfSense: an interface key, or a network alias. RouterOS: an interface list, or an address-list.
- **Edge.** One pass rule: src segment network, dst segment network, service (protocol + port), action, log. It is tagged with an Atrium marker [I]:
  - OPNsense: `description` prefix `atrium:<edge-id>`, or an Atrium category.
  - pfSense: `descr` prefix.
  - RouterOS: `comment`.
- **Hit counts.** OPNsense `rule_stats` keyed by uuid. pfSense `pfctl -vvsr` by tracker. RouterOS `bytes`/`packets`.

### 4.2 Change protocol for every product [I]
1. **Preflight.** Re-read the rules. Refuse a change whose match set includes the Atrium host to firewall management tuple (OPNsense/pfSense 443/22; RouterOS `www-ssl` port), or any `block` on the management interface.
2. **Backup.** Take the native backup or savepoint.
3. **Write.** One rule only.
4. **Apply.**
5. **Verify** with a fresh connection.
6. **Confirm**: cancel the rollback or disarm the timer.
7. **Otherwise roll back**, and alert with manual steps.

Per product:
- OPNsense 24.1–26.1: native savepoint (1.6.A).
- OPNsense 26.7+: backup id plus `revert_backup` (1.6.B).
- pfSense: dead-man shell script (2.5).
- RouterOS: scheduler dead-man (3.4).

Writes stay behind Atrium's human approval flow.

### 4.3 Connector pitfalls against `hub/connectors/base.py`
- `request_json` treats only HTTP status as failure. OPNsense returns 200 with `{"result":"failed","validations":{...}}` [V-src O22], so the connector must check `result`.
- RouterOS returns all values as strings [V M1].
- `http()` does not follow redirects, so configure the `https://` URL exactly.
- Use `verify=<CA file>` for the self-signed certificates.
- Rules and segments are not among the current `DOMAINS` (assets, vulnerabilities, risks, controls). A new domain or an action set is needed [V: repo file `C:\Users\test\Downloads\hub program\hub\connectors\base.py`].

---

## 5. Not found / open
- **OPNsense:**
  - A replacement automatic-rollback API in 26.7.x: not found [O9, O15].
  - A documented API rate limit: not found.
  - Whether API auth failures feed the GUI login lockout: not found.
  - The exact casing cut-over version (25.7) is from the community only.
- **pfSense:**
  - The Nexus API base path, security scheme, login call, rule schema and apply semantics: not found in the portions of `pfapi_openapi.yml` read [P3].
  - An official REST API for CE: not found.
  - Exact config.xml tags for NAT and the alias types beyond host, network and port: [U].
- **RouterOS:**
  - The version that introduced the `rest-api` policy: not found.
  - REST access to Safe Mode: not found.
  - Whether plain GET on `/ip/firewall/filter` includes `bytes`/`packets`: [U].
  - Stability of `.id` across reboots: [U].

---

## References
**OPNsense (official docs; pages show "© 2016-2026 Deciso B.V.", no version label; fetched 2026-10-09)**
- O1 https://docs.opnsense.org/development/how-tos/api.html
- O2 https://docs.opnsense.org/development/api.html
- O3 https://docs.opnsense.org/development/api/core/firewall.html
- O4 https://docs.opnsense.org/development/api/core/interfaces.html
- O5 https://docs.opnsense.org/development/api/core/core.html
- O6 https://docs.opnsense.org/development/api/core/firmware.html
- O7 https://docs.opnsense.org/manual/firewall.html
- O8 https://docs.opnsense.org/manual/settingsmenu.html
- O9 https://docs.opnsense.org/releases/CE_26.7.html (26.7 released 2026-07-15; 26.7.6 on 2026-10-08)
- O10 https://docs.opnsense.org/releases/CE_26.1.html (26.1 released 2026-01-28)

**OPNsense (opnsense/core source)**
- O11 https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php
- O12 https://raw.githubusercontent.com/opnsense/core/stable/26.1/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php
- O13 https://raw.githubusercontent.com/opnsense/core/stable/26.1/src/opnsense/scripts/filter/rollback_timer.php
- O14 https://github.com/opnsense/core/commit/17b8461
- O15 https://github.com/opnsense/core/pull/10411
- O16 .../Firewall/Api/FilterController.php (master)
- O17 .../models/OPNsense/Firewall/Filter.xml (master)
- O18 .../models/OPNsense/Firewall/ACL/ACL.xml
- O19 .../models/OPNsense/Core/ACL/ACL.xml
- O20 .../models/OPNsense/Interfaces/ACL/ACL.xml
- O21 .../controllers/OPNsense/Base/ApiControllerBase.php
- O22 .../Base/ApiMutableModelControllerBase.php
- O23 .../library/OPNsense/Base/UIModelGrid.php
- O24 src/opnsense/www/api.php
- O25 .../library/OPNsense/Mvc/Router.php
- O26 .../models/OPNsense/Core/ACL.php
- O27 .../Core/Api/BackupController.php
- O28 .../library/OPNsense/Core/Config.php
- O29 .../Firewall/Api/FilterUtilController.php
- O30 src/opnsense/scripts/filter/rule_stats.py
- O31 .../Interfaces/Api/OverviewController.php
- O32 .../Diagnostics/Api/SystemController.php
- O33 .../Core/Api/FirmwareController.php
- O34 .../Firewall/Alias.xml
- O35 .../Interfaces/Vlan.xml
- O36 https://github.com/opnsense/core/commits/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php

**Community (unofficial)**
- C1 https://github.com/coreyhines/opnsense-mcp/issues/30
- C2 https://github.com/deevnet/ansible-collection-deevnet.net/pull/28

**pfSense (Netgate docs and pfsense/pfsense source)**
- P1 https://docs.netgate.com/pfsense/en/latest/nexus/index.html (updated 2026-08-25)
- P2 https://docs.netgate.com/pfsense/en/latest/nexus/auth.html (2026-04-22)
- P3 https://github.com/Netgate/pfsense-api and https://raw.githubusercontent.com/Netgate/pfsense-api/main/pfapi_openapi.yml
- P4 https://docs.netgate.com/pfsense/en/latest/firewall/easyrule.html (2025-08-25)
- P5 https://docs.netgate.com/pfsense/en/latest/backup/index.html (2025-08-22)
- P6 https://docs.netgate.com/pfsense/en/latest/backup/remote-backup.html (2025-12-16)
- P7 https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html (2022-06-21)
- P8 https://docs.netgate.com/pfsense/en/latest/backup/restore.html (2025-12-15)
- P9 https://docs.netgate.com/pfsense/en/latest/usermanager/privileges.html (2025-09-03)
- P10 https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html (2025-08-25)
- P11 https://docs.netgate.com/pfsense/en/latest/troubleshooting/locked-out.html (2026-01-05)
- P12 https://docs.netgate.com/pfsense/en/latest/development/php-shell.html (2025-12-16)
- P13 https://docs.netgate.com/pfsense/en/latest/releases/index.html (2026-10-01)
- P14 https://raw.githubusercontent.com/pfsense/pfsense/master/src/usr/local/www/xmlrpc.php
- P15 .../src/etc/inc/filter.inc
- P16 .../src/etc/inc/config.lib.inc
- P17 .../src/etc/rc.filter_configure
- P18 .../src/etc/version
- P19 https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html (anti-lockout ports, the disable checkbox and console re-enable; seen as search-result excerpts of the official pages, not fetched in full)

**pfrest (unofficial)**
- R1 https://pfrest.org/
- R2 https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/
- R3 https://pfrest.org/QUERIES_FILTERS_AND_SORTING/
- R4 https://pfrest.org/COMMON_CONTROL_PARAMETERS/
- R5 https://pfrest.org/ENDPOINT_TYPES/
- R6 https://pfrest.org/WORKING_WITH_OBJECT_IDS/
- R7 https://pfrest.org/INSTALL_AND_CONFIG/
- R8 https://github.com/jaredhendrickson13/pfsense-api (master: Models/FirewallRule.inc, FirewallApply.inc, InterfaceVLAN.inc, FirewallAlias.inc, NetworkInterface.inc; Endpoints/FirewallRuleEndpoint.inc, FirewallRulesEndpoint.inc, FirewallApplyEndpoint.inc; Core/Response.inc, Endpoint.inc)
- R9 https://github.com/jaredhendrickson13/pfsense-api/releases

**MikroTik**
- M1 https://manual.mikrotik.com/docs/developer-guides/rest-api/ (manual 7.26)
- M2 https://manual.mikrotik.com/docs/7.25/developer-guides/rest-api/
- M3 https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API (frozen; updated 2025-08-12)
- M4 https://manual.mikrotik.com/docs/getting-started/configuration-management/ (7.26)
- M5 https://manual.mikrotik.com/docs/cli-reference/safe-mode/ (7.26)
- M6 https://manual.mikrotik.com/docs/cli-reference/ip/firewall/filter/ (7.26)
- M7 https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions
- M8 https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User (2026-04-15)
- M9 https://manual.mikrotik.com/docs/cli-reference/system/scheduler/ (7.26)
- M10 https://manual.mikrotik.com/docs/getting-started/configuration-management/backup/ (7.26)
- M11 https://forum.mikrotik.com/t/safe-mode-api/55104 (unofficial)


## Confidence notes
- OPNsense: the savepoint, apply/{revision} and cancelRollback/{revision} flow and its 60 s timer are verified only in vendor source (stable/26.1 FilterBaseController.php and rollback_timer.php). The official API reference pages no longer list these endpoints, and the source shows them removed by commit 17b8461 / PR #10411, merged 2026-06-18 and shipped in 26.7. The live 404 on 26.7.x is reported only by community sources (C1, C2).
- OPNsense: most endpoint behaviour is verified in opnsense/core master or stable/26.1 source rather than prose docs. This includes response bodies, ACL privilege IDs, case-sensitive ACL matching, the user-config-readonly enforcement points, BackupController semantics and the backup retention default of 100. Source on master may differ from the version a given customer runs.
- OPNsense: the claim that endpoint casing switched to snake_case in 25.7 comes from community sources (hass-opnsense, MCP servers). The router accepting both casings, and the ACL not normalising case, are verified in source. 'Use snake_case on 25.7+' is an inference.
- OPNsense: the JSON example for search_rule has a verified shape (UIModelGrid and FilterController), but the values, and whether booleans are encoded as the strings '1'/'0', are illustrative and unverified.
- OPNsense: the anti-lockout rule's location and settings are from forum posts and an opnsense/core PR, not official docs.
- pfSense: there is no official REST API for CE. The Netgate Nexus/MIM API (Plus 25.07+) is confirmed, but its base path, security scheme, login call and rule schema were not found in the portions of the 1.2 MB OpenAPI file that were read.
- pfSense: the config.xml rule keys are verified from filter.inc. The interface, VLAN and alias keys are verified indirectly through the unofficial pfrest models' config paths. The NAT tags, alias types beyond host/network/port, disabled/log presence semantics, separator handling and the dead-man script (daemon(8)) are unverified or inferred.
- pfSense: the anti-lockout ports (443/80/22), the disable checkbox name and the console re-enable procedure come from search-result excerpts of official Netgate pages (rule-methodology / advanced-admin / locked-out), not from full-page fetches. advanced-admin and locked-out were fetched for other details.
- pfrest (unofficial) facts are verified against its own docs and GitHub source. The response_id value 'SUCCESS' is a guess.
- MikroTik: the REST API facts come from the 7.26 manual. These include the api+rest-api policies, methods, errors, the 60 s timeout, the 10-minute session cache, place-before and export/file-read. No REST or API way to enter Safe Mode is documented. The scheduler-based dead-man switch is an inferred design, not vendor guidance.
- MikroTik: these are unverified: the field names for /interface/vlan, /interface/list/member and address-list; whether bytes/packets appear in plain GET output; .id stability; and whether the move command works on /ip/firewall/filter (it is documented only for /ip/firewall/nat).
- Version and dates: OPNsense 26.7.6 (2026-10-08), pfSense Plus 26.07 / CE 2.9.0, RouterOS manual 7.26 and pfrest v2.10.2 were current per the sources fetched on 2026-10-09.

## Sources
- https://docs.opnsense.org/development/how-tos/api.html
- https://docs.opnsense.org/development/api.html
- https://docs.opnsense.org/development/api/core/firewall.html
- https://docs.opnsense.org/development/api/core/interfaces.html
- https://docs.opnsense.org/development/api/core/core.html
- https://docs.opnsense.org/development/api/core/firmware.html
- https://docs.opnsense.org/manual/firewall.html
- https://docs.opnsense.org/manual/settingsmenu.html
- https://docs.opnsense.org/releases/CE_26.7.html
- https://docs.opnsense.org/releases/CE_26.1.html
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php
- https://raw.githubusercontent.com/opnsense/core/stable/26.1/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php
- https://raw.githubusercontent.com/opnsense/core/stable/26.1/src/opnsense/scripts/filter/rollback_timer.php
- https://github.com/opnsense/core/commit/17b8461
- https://github.com/opnsense/core/pull/10411
- https://github.com/opnsense/core/commits/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterBaseController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Firewall/Filter.xml
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Firewall/ACL/ACL.xml
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Core/ACL/ACL.xml
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Interfaces/ACL/ACL.xml
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Base/ApiControllerBase.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Base/ApiMutableModelControllerBase.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/library/OPNsense/Base/UIModelGrid.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/www/api.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/library/OPNsense/Mvc/Router.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Core/ACL.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Core/Api/BackupController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/library/OPNsense/Core/Config.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterUtilController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/scripts/filter/rule_stats.py
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Interfaces/Api/OverviewController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Diagnostics/Api/SystemController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/controllers/OPNsense/Core/Api/FirmwareController.php
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Firewall/Alias.xml
- https://raw.githubusercontent.com/opnsense/core/master/src/opnsense/mvc/app/models/OPNsense/Interfaces/Vlan.xml
- https://github.com/coreyhines/opnsense-mcp/issues/30
- https://github.com/deevnet/ansible-collection-deevnet.net/pull/28
- https://docs.netgate.com/pfsense/en/latest/nexus/index.html
- https://docs.netgate.com/pfsense/en/latest/nexus/auth.html
- https://github.com/Netgate/pfsense-api
- https://raw.githubusercontent.com/Netgate/pfsense-api/main/pfapi_openapi.yml
- https://docs.netgate.com/pfsense/en/latest/firewall/easyrule.html
- https://docs.netgate.com/pfsense/en/latest/backup/index.html
- https://docs.netgate.com/pfsense/en/latest/backup/remote-backup.html
- https://docs.netgate.com/pfsense/en/latest/config/xml-configuration-file.html
- https://docs.netgate.com/pfsense/en/latest/backup/restore.html
- https://docs.netgate.com/pfsense/en/latest/usermanager/privileges.html
- https://docs.netgate.com/pfsense/en/latest/config/advanced-admin.html
- https://docs.netgate.com/pfsense/en/latest/troubleshooting/locked-out.html
- https://docs.netgate.com/pfsense/en/latest/development/php-shell.html
- https://docs.netgate.com/pfsense/en/latest/releases/index.html
- https://docs.netgate.com/pfsense/en/latest/firewall/rule-methodology.html
- https://raw.githubusercontent.com/pfsense/pfsense/master/src/usr/local/www/xmlrpc.php
- https://raw.githubusercontent.com/pfsense/pfsense/master/src/etc/inc/filter.inc
- https://raw.githubusercontent.com/pfsense/pfsense/master/src/etc/inc/config.lib.inc
- https://raw.githubusercontent.com/pfsense/pfsense/master/src/etc/rc.filter_configure
- https://raw.githubusercontent.com/pfsense/pfsense/master/src/etc/version
- https://pfrest.org/
- https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/
- https://pfrest.org/QUERIES_FILTERS_AND_SORTING/
- https://pfrest.org/COMMON_CONTROL_PARAMETERS/
- https://pfrest.org/ENDPOINT_TYPES/
- https://pfrest.org/WORKING_WITH_OBJECT_IDS/
- https://pfrest.org/INSTALL_AND_CONFIG/
- https://github.com/jaredhendrickson13/pfsense-api
- https://github.com/jaredhendrickson13/pfsense-api/releases
- https://manual.mikrotik.com/docs/developer-guides/rest-api/
- https://manual.mikrotik.com/docs/7.25/developer-guides/rest-api/
- https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API
- https://manual.mikrotik.com/docs/getting-started/configuration-management/
- https://manual.mikrotik.com/docs/cli-reference/safe-mode/
- https://manual.mikrotik.com/docs/cli-reference/ip/firewall/filter/
- https://help.mikrotik.com/docs/spaces/ROS/pages/250708064/Common+Firewall+Matchers+and+Actions
- https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User
- https://manual.mikrotik.com/docs/cli-reference/system/scheduler/
- https://manual.mikrotik.com/docs/getting-started/configuration-management/backup/
- https://forum.mikrotik.com/t/safe-mode-api/55104