# Host firewalls managed over SSH: implementation reference for Atrium

Scope: nftables, ufw, firewalld and Windows Defender Firewall, all reached over SSH. The document also covers how to read interfaces, IPs and listening ports so hosts can be placed into network zones. It is meant for the engineer building firewall connectors and the segmentation canvas, where an arrow between zones becomes an allow rule on a host firewall.

Researched on 2026-10-09. Nothing was changed in the repository.

**Legend**
- **[V Sx]**: verified in official documentation or upstream source code (Sx is in the source table at the end).
- **[U]**: unverified, from memory, a forum or a search excerpt only.
- **[I]**: inferred or a design recommendation. Not a vendor statement.

---

## 0. Cross-cutting facts and design that apply to every backend

### 0.1 Transport
- **No HTTP layer.** All four backends are reached over SSH. TLS, pagination, API rate limits and HTTP error envelopes do not apply.
- **What does apply:**
  - SSH host-key verification. The hub already has `strict_host_keys`.
  - Process exit codes.
  - stdout and stderr.
  - sshd-side connection throttling.
- **sshd throttling [V S43]:**
  - `MaxStartups` defaults to `10:30:100`, which throttles concurrent *unauthenticated* connections.
  - `MaxSessions` defaults to 10 per connection.
  - `PerSourcePenalties` is on by default in current OpenSSH. Penalties are `authfail` 5s, `noauth` 1s, `grace-exceeded` 10s, `crash` 90s and `invaliduser` 5s, with a maximum of 10 min.
  - A hub that fans out many connections, or retries with a bad key, can get its own IP refused temporarily.
- **Client identity on Linux [V S42].** The OpenSSH server exports `SSH_CONNECTION` = "client IP, client port, server IP, server port". Read it at the start of every change session to learn the hub's source IP and the sshd port as the host sees them. NAT can make this differ from what the hub thinks.
- **Client identity on Windows [U].** Whether Win32-OpenSSH sets `SSH_CONNECTION` was not verified. The fallback is `Get-NetTCPConnection -State Established -LocalPort <sshd port>` matched against the hub IP [V S32 for the cmdlet and parameters].

### 0.2 Constraints in Atrium's current SSH runner (verified in the repo, S45)
These come from `C:\Users\test\Downloads\hub program\hub\execution\runner.py`.
- **Output truncation.** `MAX_OUTPUT = 64_000`. `_decode()` keeps `text[-MAX_OUTPUT:]`, which is the **tail**. `nft -j list ruleset` on Docker or Kubernetes hosts, or `Get-NetFirewallRule` JSON on Windows (hundreds of built-in rules [U]), can exceed 64 KB. The result is silently corrupted JSON.
- **stdout and stderr are concatenated.** `run_ssh` returns `_decode(res.stdout) + _decode(res.stderr)`. nft prints warnings to stderr, such as the iptables-nft "do not touch" warning, see 1.7. Mixed into stdout, they break JSON parsing.
- **One connection per command.** Each `run_ssh` call opens a new connection (`async with asyncssh.connect(...)`). This hits `ufw limit` (see 2.7), fail2ban-style tools [U] and `MaxStartups`.

**Recommendation [I]:** add a firewall-specific session API to the runner that:
- keeps one SSH connection for the whole change session;
- returns stdout and stderr separately along with the exit status;
- has no truncation, or uses `| gzip | base64` for reads larger than a threshold;
- passes scripts on stdin, not on the command line. Whether asyncssh's `conn.run(..., input=...)` is the right parameter was not verified [U].

**The confirmation probe must use a NEW connection (see 0.4).**

### 0.3 Detecting the manager on a host [I]
Linux, in this order:
1. `systemctl is-active firewalld` returns `active`: the manager is **firewalld**. Write only through `firewall-cmd`.
2. `ufw status` first line is `Status: active` [V S11 for the string]: the manager is **ufw**. Write only through `ufw`.
3. `nft` exists (`command -v nft`): the manager is **raw nftables**. Write only inside an Atrium-owned table.
4. Otherwise, legacy iptables only. Out of scope. Show the host as read-only.

Windows: if `powershell.exe` runs (the default OpenSSH shell is `cmd.exe` [V S28]), the manager is **Windows Defender Firewall**.

Also record:
- OS: `/etc/os-release`, fields `ID`, `VERSION_ID`, `PRETTY_NAME` [V S40]; kernel from `uname -r`.
- Firewall tool version: `nft --version` [V S1 lists -v/-V], `ufw version` [U], `firewall-cmd --version` [V S13].

### 0.4 Safe-change protocol (dead-man switch) [I], identical for all four backends
None of the four products has a native commit-confirm or rollback timer. The only native piece is firewalld's `--timeout`, for additions only (see 3.4). Atrium builds its own:

1. **Pre-flight**, over the session connection:
   - read `SSH_CONNECTION` to get `hub_ip` and `ssh_port`;
   - read the current rules;
   - **lockout lint** the proposed change (per-backend lists in sections x.7). Refuse the change if it could block `hub_ip -> ssh_port`.
2. **Snapshot on the host**, to a root-only directory: `/var/lib/atrium/fw/<change-id>/` or `C:\ProgramData\Atrium\fw\<change-id>\`. Also keep a JSON copy in the hub DB.
3. **Arm a revert timer on the host**, using a *relative* time so clock skew between hub and host does not matter. Use `systemd-run --on-active=` on Linux or a Scheduled Task with `(Get-Date).AddMinutes(n)` computed on the host. Default window: 120 to 300 s.
4. **Apply atomically** (backend specific).
5. **Verify from the hub over a NEW SSH connection**, with a short connect timeout, then re-read the rules.
   - The existing session is no proof. Stateful rulesets normally accept established flows, so the old TCP session usually survives a rule that blocks new connections [I].
6. **Confirm:**
   - cancel the timer;
   - persist the change (firewalld `--permanent`, or writing the nft persistence file);
   - record the change in the audit log.
7. **If step 5 fails, or the hub loses contact:** do nothing. The timer restores the snapshot. Reconnect after the window and verify the restore.

**Persist only after confirmation** wherever the backend allows it (nftables, firewalld). A reboot is then an extra out-of-band rollback [I]. ufw and Windows write persistently on every change, so a reboot does **not** roll them back [I].

### 0.5 Least-privilege model [I]
- **The firewall is an all-or-nothing privilege on every OS.** Anything that can change it can cut off the host.
- **Separate SSH identities.** Use separate SSH keys and accounts for read (inventory) and write (change).
- **Linux reads.** Allow exact command lines in sudoers. Arguments must match exactly, and `""` means no arguments [V S41]. Avoid wildcards in arguments: "Wildcards can match any character, including white space" [V S41].
- **Linux writes.** Give sudo access to one root-owned wrapper script with fixed verbs: `snapshot`, `arm-revert`, `apply`, `confirm` and `revert-now`. The wrapper reads the staged change from stdin into a root-owned spool directory and validates it (`nft -c`, `ufw --dry-run`, `firewall-cmd --check-config`) before applying. Do not give `nft -f <user-writable path>`.
- **Never store sudo passwords.** Use `NOPASSWD` for these specific commands only [V S41], and always call `sudo -n` so a missing rule fails instead of hanging [I].

---

## 1. nftables (raw `nft`)

Docs: nft(8) page "Updated 07/02/2026" [S1]; libnftables-json(5) from Debian libnftables1 1.1.7-2, 2025-12-05 [S2]; nftables wiki [S3, S4, S5].

### 1.1 Authentication and privileges
- **Transport.** SSH key, the hub's existing model.
- **Kernel privilege.** nf_tables is driven over netlink, which checks `CAP_NET_ADMIN`. No official page states that *listing* also needs it [U]. Netfilter's bugzilla and the osmocom reports indicate that non-root `nft list ...` fails without `CAP_NET_ADMIN`. Treat reads as needing root through sudo.
- **No read-only privilege level.** nftables has no separate read-only level. `CAP_NET_ADMIN` permits both reading and writing [I]. Least privilege therefore has to come from sudoers command restriction (0.5).
- **Read-only sudoers example** [V S41 semantics; paths U, check with `command -v`]:
  ```
  Cmnd_Alias ATRIUM_FW_READ = /usr/sbin/nft -j list ruleset, /usr/sbin/nft --version, /usr/sbin/ss -H -tulnp
  atrium-ro ALL=(root) NOPASSWD: ATRIUM_FW_READ
  ```
- **Writes.** Only via the wrapper (0.5).

### 1.2 Reading
- **Full ruleset as JSON:** `nft -j list ruleset` [V S1: "-j/--json Format output in JSON. See libnftables-json(5)"].
  - Top level: `{"nftables":[ ... ]}`. The first element is `{"metainfo":{"version","release_name","json_schema_version"}}` [V S2].
  - Every published example has `json_schema_version` = 1 [U for current builds].
- **Other output modifiers.**
  - `-s` omits stateful information such as counters [V S1/S4].
  - `-t` omits set contents [V S1/S4]. **Never use `-t` or `-s` for backups.**
  - `-a` shows handles in text output [V S1]. JSON output already includes `handle` [V S4 example].
- **Interfaces, VLANs and subnets.** Not part of nft. Use `ip -j` (section 5). Rules reference interfaces through `meta` keys such as `iifname` [V S2 lists `iifname` as a meta key].
- **Zones.** nftables has no zone concept. The equivalent is a base chain (`type`/`hook`/`prio`/`policy` [V S2]) plus rules that match `iifname`, `oifname` or address sets. Families are `ip`, `ip6`, `inet`, `arp`, `bridge` and `netdev` [U for the full list; `inet` V S4].
- **Address and service objects.** These are named sets: `{"set":{"family","table","name","handle","type","policy","flags","elem","timeout",...}}` [V S2].
  - The wiki example shows `"type":"inet_service"` with `"elem":[80,443]` [V S4].
  - Address set types are `ipv4_addr` and `ipv6_addr`, with `flags interval` for CIDRs [U].
  - Rules reference sets as `"@name"` [V S2].
- **Rules.** Objects have the form `{"rule":{"family","table","chain","handle","index","comment","expr":[...]}}` [V S2].
  - **Order:** the order of `rule` objects for one chain in the listing [I]. Chains on the same hook run in ascending `prio` order [V S5].
  - **Action:** the verdict statement inside `expr`.
    - `{"accept":null}` and `{"drop":null}` [V S2].
    - `{"reject":{"type","expr"}}` [V S2].
    - jump, goto and return [U for their JSON shape].
  - **Source and destination:** `{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.0.0.0","len":8}}}}`. The `match`, `payload` and `prefix` shapes are [V S2]. The field names `saddr` and `daddr` are [U].
  - **Service:** `payload` with `"protocol":"tcp","field":"dport"` [V S2 example]. The right-hand side can be a number, `{"set":[...]}`, `{"range":[lo,hi]}` or `"@setname"` [V S2].
  - **Connection-tracking state:** `{"ct":{"key":"state"}}`, usually with `"op":"in"` [U for the exact shape; the ct object and the `in` op are V S2].
  - **Enabled:** nftables has **no disabled-rule state** (not found). "Disable" means delete the rule and keep its body in the hub.
  - **Logging:** `{"log":{"prefix","group","snaplen","queue-threshold","level","flags"}}`; the default level is warn [V S2].
  - **Hit counts:** only when the rule contains a counter statement. The shape is `{"counter":{"packets":N,"bytes":N}}` [V S2, S4]. `nft reset counters` zeroes named counters [V S1].
  - **Comment:** the `comment` field [V S2].
- **NAT.** Chains with `"type":"nat"` (the `type` field is [V S2]; the value `nat` is [V S1 example `type nat hook prerouting`]). Statements are `snat`, `dnat` and `masquerade` [U for their JSON shape]. Showing NAT read-only is cheap.
- **Versions.** `nft --version` and `metainfo.version` [V S2]. Kernel from `uname -r`. OS from `/etc/os-release` [V S40].
- **Backup.** `nft list ruleset > /var/lib/atrium/fw/<id>/ruleset.nft`. The documented round-trip pattern is `nft list table filter > f; nft -f f` [V S3].
  - For a whole-ruleset restore, prepend `flush ruleset`. `flush table` does not flush sets [V S3].
  - See the iptables-nft caveat in 1.7.

### 1.3 Writing a single rule
Prefer the **text syntax in a file applied with `nft -f`**. A file is applied as one transaction (see below).

| Operation | Command | Status |
|---|---|---|
| Create (append) | `add rule inet atrium input ip saddr 10.20.0.0/24 tcp dport 443 counter log prefix "atrium:r-7f3a " accept comment "atrium:r-7f3a"` | Grammar [V S1]: `{add \| insert} rule [family] table chain [handle handle \| index index] statement ... [comment comment]` |
| Create at a position | `add rule ... handle 7 ...` appends after rule 7. `insert rule ... handle 7 ...` puts it before rule 7. `index N` is zero-based. | [V S1, S2] |
| Update | `replace rule inet atrium input handle 4 <statements> comment "..."` | [V S1] |
| Delete | `delete rule inet atrium input handle 4` | [V S1] |
| Move | No native move (not found). Put `delete rule ... handle 4` and `insert rule ... handle 9 ...` in **one** file so they form one transaction. | [I] |

- **Commit step.** There is no separate commit. Each `nft -f file` is one netlink batch.
  - The kernel commits the batch at its end marker, or calls abort on error [V S6 kernel commit].
  - The wiki states that `-f` performs atomic replacement [V S3].
  - Validate first with `nft -c -f file` ("Check commands validity without actually applying the changes") [V S1].
- **Use handles, not indexes.** An index is converted to a handle in userspace, so a concurrent change can move the effective position [V S1].
- **Learning the new handle.** `-e/--echo` prints add, insert and replace notifications [V S1]. Combined with `-a` it should show the handle [U]. A more robust way is to re-read and match on the `comment` tag [I].
- **JSON input.** libnftables accepts JSON commands, in order of appearance, through `nft_run_cmd_from_buffer()` and `nft_run_cmd_from_filename()` [V S2]. The CLI form `nft -j -f file.json` is [U]. Prefer the text syntax.

### 1.4 Safe change
- **Native mechanism: none.** nft has no commit-confirm or rollback timer (not found in S1, S2 or the wiki).
- **Atrium-owned table pattern [I].** Atrium never edits other tables; it only replaces `table inet atrium`.
  - Revert file, generic form for any kernel. The add-then-delete idiom is referenced in the Arch nftables packaging issue [V S8]:
    ```
    table inet atrium {}
    delete table inet atrium
    <contents of: nft list table inet atrium, taken before the change>
    ```
  - On kernel 6.3 or later, `destroy table inet atrium` deletes the table without failing when it is missing [V S8, kernel netlink spec: "destroy semantics (ignoring ENOENT errors)"]. On older kernels it fails with an unclear error [V S8 search excerpt].
- **Timer and sequence:**
  ```
  nft -c -f /var/lib/atrium/fw/<id>/revert.nft
  systemd-run --unit=atrium-fw-revert-<id> --on-active=180 --timer-property=AccuracySec=1s \
      /usr/sbin/nft -f /var/lib/atrium/fw/<id>/revert.nft
  nft -c -f /var/lib/atrium/fw/<id>/change.nft && nft -f /var/lib/atrium/fw/<id>/change.nft
  # verify via NEW ssh connection, then:
  systemctl stop atrium-fw-revert-<id>.timer
  ```
  - `--on-active` creates a transient `.timer` and `.service` with a shared base name. In the doc example they are `run-71.timer` and `run-71.service` [V S38].
  - `AccuracySec` **defaults to 1 min** [V S39]. Without `AccuracySec=1s` the revert can fire up to a minute late.
  - Stopping the `.timer` cancels the pending run [I, systemctl semantics; the page does not say so].
- **Whole-ruleset fallback**, only when the host has no other managers: revert file = `flush ruleset` + the full `nft list ruleset` snapshot [V S3].
- **Without systemd:** `at` [U], or `nohup sh -c 'sleep 180; nft -f revert.nft' &`, keeping the PID [I].
- **Persistence after confirmation.** Write `table inet atrium` into an include file of the distro's nftables service config [U for paths: Debian `/etc/nftables.conf`, RHEL `/etc/sysconfig/nftables.conf`]. Until then a reboot discards the change [I].

### 1.5 Transport and format details
- SSH only. There is no TLS, pagination or rate limiting at the nft level.
- **Errors.** nft writes `Error: ...` to stderr, with a caret line under the offending token, and exits non-zero [U]. Capture stderr separately (0.2).
- **Idempotency.** `add rule` is **not** idempotent. Reloading a file without a flush duplicates rules [V S3]. Tag rules with `comment "atrium:<rule-id>"` and read before writing [I].
- **Output size.** Rulesets on Docker or Kubernetes hosts can be large. See the runner truncation issue in 0.2.

### 1.6 Minimal JSON returned by `nft -j list ruleset`
The structure and field names are from S2 and S4. The metainfo values are the wiki's example (0.9.6). The rule `expr` follows the S2 shapes, with payload field names [U].
```json
{"nftables":[
 {"metainfo":{"json_schema_version":1,"release_name":"Capital Idea #2","version":"0.9.6"}},
 {"table":{"family":"inet","handle":5,"name":"atrium"}},
 {"set":{"family":"inet","table":"atrium","name":"zone_dmz","handle":9,"type":"ipv4_addr","flags":["interval"],
         "elem":[{"prefix":{"addr":"10.20.0.0","len":24}}]}},
 {"chain":{"family":"inet","table":"atrium","name":"input","handle":1,"type":"filter","hook":"input","prio":0,"policy":"accept"}},
 {"rule":{"family":"inet","table":"atrium","chain":"input","handle":7,"comment":"atrium:r-7f3a","expr":[
   {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"@zone_dmz"}},
   {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},
   {"counter":{"packets":8062,"bytes":37707381}},
   {"log":{"prefix":"atrium:r-7f3a "}},
   {"accept":null}]}}
]}
```

### 1.7 Lockout gotchas
- **An accept is not final across base chains; a drop is.**
  - "an accept verdict ... isn't necessarily final" and "drops take immediate effect, with no further rules or chains being evaluated" [V S5].
  - So an Atrium `accept` cannot override a `drop` in another table, for example firewalld's.
  - Any Atrium `drop` or `reject`, at any priority, is final.
  - A base chain with `policy drop` must itself accept the SSH traffic [V S5 / man page drafts].
- **`flush ruleset` wipes every table:** Docker, libvirt, firewalld, Kubernetes. Never use it on hosts with other managers. Use the Atrium-owned table pattern [I].
- **iptables-nft tables** (ufw, Docker, Kubernetes on iptables-nft):
  - `nft list ruleset` prints `# Warning: table ip filter is managed by iptables-nft, do not touch!`.
  - Round-tripping those tables through `nft -f` can turn compat expressions into native ones iptables-nft cannot read, or **drop them** [V S7, nftables patch quoted in the netfilter bug thread].
  - Older nft builds crash on `nft --json list ruleset` with such tables (bug 1463, fixed upstream November 2022 [V S7]).
  - Rule: never include iptables-nft-managed tables in nft backups or restores [I].
- **Timer late by up to a minute.** Set `AccuracySec=1s` [V S39].
- **Index races.** Use handles [V S1].
- **False confidence.** The existing SSH session survives through established-state accept rules. Verify over a new connection [I].

---

## 2. ufw

Docs: ufw(8) and ufw-framework(8), Ubuntu 24.04 "noble", package 0.36.2-6 [S9, S10]; upstream source on git.launchpad.net/ufw [S11]; Ubuntu Server firewall guide [S12].

### 2.1 Authentication and privileges
- **Transport.** SSH key.
- **Privilege.** ufw drives iptables-restore [V S10] and keeps a lock at `/run/ufw.lock` when running as root [V S11 `src/ufw`]. In practice every useful command needs root [U for the exact non-root error text].
- **Read-only sudoers** [V S41 semantics]:
  `/usr/sbin/ufw status verbose`, `/usr/sbin/ufw status numbered`, `/usr/sbin/ufw show added`, `/usr/sbin/ufw version`, plus `cat /etc/ufw/user.rules /etc/ufw/user6.rules`. The file permissions are typically root-only [U].
- **Writes.** Through the wrapper (0.5).
- **Locale.** The status strings are gettext-translated (`_("To")`, `_("Status: active")`) [V S11]. Always run with `LC_ALL=C`.

### 2.2 Reading
- **Status and defaults.** `ufw status verbose`. Its lines are `Status: active` and `Default: %(in)s (incoming), %(out)s (outgoing), %(routed)s (routed)` [V S11], plus a `Logging:` line [U for the exact text].
  - `ufw status` "does not show rules from the rules files in /etc/ufw" [V S9/S10]. `before.rules` and `after.rules` content, including NAT under `*nat`, is invisible there.
- **Rules, numbered.** `ufw status numbered` [V S9].
  - Format from source: header `"%-26s %-12s%s"` with "To", "Action", "From"; prefix `"[%2d] "`; IPv6 rules suffixed `" (v6)"`; anywhere shown as `"Anywhere"`; comments appended as `" # <comment>"` [V S11].
  - The action column is `ACTION DIRECTION`, for example `ALLOW IN`, `DENY OUT` or `ALLOW FWD`. The direction is shown only in numbered or verbose output [V S11].
  - The fixed width (26) makes long "To" fields hard to parse [I].
- **Machine-readable source of truth.** Parse the `### tuple ###` lines in `/etc/ufw/user.rules` and `/etc/ufw/user6.rules`, the "UI added rules" files [V S10].
  - Tuple field order (source): action, protocol, dport, dst, sport, src, [dapp, sapp], then direction/interface, optionally followed by ` comment=<value>` [V S11].
  - Ubuntu's docs show a tuple without the direction field: `### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0` [V S12]. Accept both forms.
  - Whether the comment value is hex-encoded is [U]. Decode only if it is valid even-length hex [I].
- **Commands as typed.** `ufw show added` lists them, and `ufw show raw` shows the complete firewall. The report names are raw, builtins, before-rules, user-rules, after-rules, logging-rules, listening and added [V S9].
- **Zones and interfaces.** None. Rules can carry `in on <iface>` / `out on <iface>` [U for the syntax]. Use `ip -j` (section 5) for interfaces.
- **Address objects:** none. **Service objects:** application profiles in `/etc/ufw/applications.d`, via `ufw app list` and `ufw app info <name>` [V S9].
- **Order:** "the first match wins" [V S9]. Rule numbers come from `status numbered`.
- **Logging per rule:** `log` logs new connections and `log-all` logs all packets; nothing is logged by default [V S9].
- **Hit counts.** No ufw command. The underlying iptables chains have counters, for example `iptables -L ufw-user-input -n -v -x` [U].
- **Versions.** `ufw version` [U]. OS and kernel as in 0.3.
- **Backup.** Tar `/etc/ufw/` and `/etc/default/ufw` (the files are listed in [V S10]). Restore by copying back and running `ufw reload` [V S10: "After modifying any of these files, you must reload ufw"].

### 2.3 Writing a single rule
| Operation | Command | Status |
|---|---|---|
| Create (append) | `ufw allow from 10.20.0.0/24 to any port 443 proto tcp comment 'atrium:r-7f3a'` | `from ... to any app Samba` form [V S12]; port/proto form [U]; comments [V S9] |
| Create at a position | `ufw insert 1 allow ...`, or `ufw prepend ...` | [V S9, S12] |
| Update | No in-place update. Use delete plus insert at the same number. Only the comment can be changed in place by re-issuing the rule with a new comment; `insert` and `prepend` cannot update comments. | [V S9] |
| Delete | `ufw delete allow from 10.20.0.0/24 to any port 443 proto tcp`, i.e. prefix the original rule with `delete` | [V S9, S12] |
| Delete by number | `ufw delete 3`. This removes only that rule (IPv4 or IPv6), not its v4/v6 twin. | [V S9]. It prompts for confirmation [U]; use `--force` [U]. |
| Dry run | `ufw --dry-run <command>`: "don't modify anything, just show the changes" | [V S9, S12] |

- **Commit step.** None. When ufw is enabled, each command writes `user*.rules` and applies the change immediately [I]. That means every change is **persistent at once**.

### 2.4 Safe change
- **Native mechanism:** none, apart from `--dry-run` for previews [V S9].
- **Pattern [I]:**
  1. Copy `user.rules` and `user6.rules` to `/var/lib/atrium/fw/<id>/`.
  2. Arm `systemd-run --unit=atrium-fw-revert-<id> --on-active=180 --timer-property=AccuracySec=1s /bin/sh -c 'cp /var/lib/atrium/fw/<id>/user.rules /etc/ufw/user.rules && cp /var/lib/atrium/fw/<id>/user6.rules /etc/ufw/user6.rules && ufw reload'` [V S38, S39 for the timer; V S10 for the reload requirement].
  3. Apply the change.
  4. Verify over a new connection.
  5. `systemctl stop atrium-fw-revert-<id>.timer`.

### 2.5 Transport and format details
- Text output only; there is **no JSON**.
- Errors are printed as `ERROR: ...` [U]. Exit code 1 on argument errors [V S11: `sys.exit(1)` for parse errors].
- **Idempotency.** Adding an existing rule prints a "skipping" message rather than duplicating it [U]. Read before writing anyway.

### 2.6 Minimal example of what reading returns
`ufw status numbered` (format per S11; the header indentation is [U]):
```
Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    10.20.0.5
[ 2] 443/tcp                    ALLOW IN    10.20.0.0/24               # atrium:r-7f3a
[ 3] 22/tcp (v6)                ALLOW IN    Anywhere (v6)
```
`/etc/ufw/user.rules` tuple (field order per S11):
```
### tuple ### allow tcp 443 0.0.0.0/0 any 10.20.0.0/24 in comment=<value>
```
Atrium should normalise both into its own record: `{number, action, direction, proto, dport, dst, sport, src, iface, v6, comment, log}` [I].

### 2.7 Lockout gotchas
- **`ufw enable` without an SSH allow rule.** ufw prompts when it is enabled over SSH because it "may drop existing connections (eg ssh)". `--force` skips the prompt [V S9]. Atrium must only call `ufw --force enable` after confirming an allow rule for `hub_ip -> ssh_port`.
- **`ufw limit` versus the hub's connection pattern.** `ufw limit` denies "an IP address [that] attempts to initiate 6 or more connections within 30 seconds" [V S9]. Atrium's runner opens one connection per command (0.2), so a `limit` on the SSH port will lock out the hub itself.
- **IPv4/IPv6 twins.** Deleting by number removes only one of the pair [V S9]. Stale v6 rules stay behind.
- **Default policy changes.** `ufw default deny|reject ...` "existing rules will have to be migrated manually" [V S9].
- **Docker bypasses ufw.** For published ports, traffic is diverted "before it goes through the ufw firewall settings" [V S44]. ufw rules do not segment Docker-published services; show this in the UI.
- **No reboot safety net.** Changes are persistent immediately [I].

---

## 3. firewalld

Docs: firewall-cmd(1), firewalld.richlanguage(5), firewalld.policies(5), firewalld.zone(5) and firewalld.dbus(5) on firewalld.org. The pages state no version; the site's latest news is dated 2025-10 [S13–S17]. Polkit policy from firewalld git main [S18].

### 3.1 Authentication and privileges
- **Transport.** SSH key. firewall-cmd talks to firewalld over D-Bus, authorised by polkit.
- **Polkit defaults in the "server" policy** [V S18]:

| Action | Default (allow_any / inactive / active) |
|---|---|
| `org.fedoraproject.FirewallD1.info` | `yes` / `yes` / `yes` |
| `.all` | `auth_admin_keep` |
| `.config` | `auth_admin_keep` |
| `.config.info` | `auth_admin_keep` |
| `.direct` | `auth_admin_keep` |
| `.direct.info` | `auth_admin_keep` |
| `.policies` | `auth_admin_keep` |
| `.policies.info` | `auth_admin_keep` |

- **Least-privilege read.** Use an unprivileged account plus a polkit rule granting `org.fedoraproject.FirewallD1.info`, `.config.info` and `.policies.info` to an `atrium-ro` group [I].
  - Which firewall-cmd query maps to which action was not verified [U]. Test `firewall-cmd --list-all-zones` and `firewall-cmd --permanent --list-all-zones` as that user.
  - The alternative is sudoers with exact command lines [V S41].
- **Writes.** Root through the wrapper, or a polkit grant of `.config` / `.all` [I]. Polkit grants cannot restrict arguments, so the wrapper is tighter [I].

### 3.2 Reading
All of these are text output; firewall-cmd has no JSON.
- `firewall-cmd --state`: is the daemon running. Exit code 0, or 252 `NOT_RUNNING` [V S13].
- `firewall-cmd --version` [V S13].
- `firewall-cmd --get-default-zone` [V S13].
- `firewall-cmd --get-active-zones`. Documented format [V S13]:
  ```
  zone1
    interfaces: interface1 interface2 ..
    sources: source1 ..
  ```
  Empty lines are omitted.
- `firewall-cmd --list-all-zones` and `--info-zone=<z>`. Documented `--info-zone` format [V S13]:
  ```
  zone
    interfaces: ..
    sources: ..
    services: ..
    ports: ..
    protocols: ..
    forward-ports:
          ..
    source-ports: ..
    icmp-blocks: ..
    rich rules:
          rich-rule1
  ```
  Real output also has `target:`, `masquerade:` and `forward:` lines [U].
- **Zone-to-zone segmentation:** `--get-policies`, `--info-policy=<p>`, `--list-all-policies` [V S13].
  - A policy applies rules to traffic **from ingress zones to egress zones**. It is stateful and one-directional [V S15].
  - Symbolic zones: `HOST` for traffic to or from the firewall host, and `ANY` [V S15].
  - This maps directly to canvas arrows.
- **Address objects:** ipsets, via `--get-ipsets` and `--info-ipset=<name>` [V S13]. Zone `sources` (CIDRs) bind addresses to zones [V S13].
- **Service objects:** firewalld services, via `--get-services` [U] and `--info-service=<s>` [U].
- **Rules.** Rich rules per zone or policy, from `--list-rich-rules` [V S13].
  - Order: rich rules sort by `priority` (-32768..32767, lower first). At priority 0 the chain order is `_pre`, `_log`, `_deny`, `_allow`, `_post`, so **deny is evaluated before allow**. The order of rules with equal priority is undefined [V S14].
  - Action: `accept | reject | drop | mark` [V S14].
  - Source: `source [not] address=|mac=|ipset=`. Destination: `destination [not] address=|ipset=` [V S14].
  - Logging: `log [prefix=] [level=] [limit value="rate/duration"]` [V S14].
- **Enabled.** Rich rules have no disabled state and no comment field (not found).
- **Hit counts:** not found in firewalld.
- **Runtime versus permanent.** Read both, `--list-all-zones` and `--permanent --list-all-zones`, and show drift [I]. "The runtime configuration in firewalld is separated from the permanent configuration" [V S13].
- **Logging of denied packets:** `--get-log-denied` [V S13].
- **NAT:** `masquerade` and `forward-ports` in zone info [V S13]. Cheap to read.
- **D-Bus alternative.** `org.fedoraproject.FirewallD1.zone.getZoneSettings2(zone)` returns a dict and `getActiveZones()` returns bindings [V S17]. It could be called with `busctl --json=short call ...` [U]. That avoids text parsing but is not needed for a first version.
- **Backup.**
  - Permanent configuration lives in `/etc/firewalld/` (zones in `/etc/firewalld/zones/<zone>.xml`; vendor defaults in `/usr/lib/firewalld/zones/`) [V S16].
  - Tar `/etc/firewalld/`. Restore: copy back, run `firewall-cmd --check-config` ("XML validity and semantics") [V S13], then `firewall-cmd --reload`.

### 3.3 Writing a single rule
| Operation | Command | Status |
|---|---|---|
| Create (runtime) | `firewall-cmd --zone=public --add-rich-rule='rule family="ipv4" source address="10.20.0.0/24" port port="443" protocol="tcp" log prefix="atrium:r-7f3a " level="info" accept'` | Rule grammar [V S14]; `port port= protocol=` element [U] |
| Create (permanent) | Same command with `--permanent`: "use the same call with and without the --permanent option" | [V S13] |
| Update | `--remove-rich-rule='<old exact string>'` then `--add-rich-rule='<new>'` | [V S13 for both options; I for the sequence] |
| Delete | `--remove-rich-rule='<rule>'`. It can be given multiple times. Use the canonical string exactly as `--list-rich-rules` prints it. | [V S13; canonical form I] |
| Position | `priority="N"` attribute in the rule | [V S14] |
| Zone-to-zone (canvas arrow) | `--permanent --new-policy p`, `--policy p --add-ingress-zone A`, `--add-egress-zone B`, `--set-target ACCEPT\|REJECT`, then `--reload` | [V S15] |
| Bind addresses to a zone | `--zone=dmz --add-source=10.20.0.0/24` | [V S13] |
| Check existence | `--query-rich-rule='<rule>'` returns 0 or 1 | [V S13] |

- **Commit step.**
  - Runtime changes take effect immediately.
  - `--permanent` changes take effect "only after service restart/reload" [V S13].
  - `--runtime-to-permanent` "Save[s] active runtime configuration and overwrite[s] permanent configuration with it" [V S13]. This also captures **other** people's runtime-only changes. Prefer repeating the exact change with `--permanent` [I].

### 3.4 Safe change
- **Native timed additions.** `--add-rich-rule`, `--add-service`, `--add-port` and similar accept `--timeout=<n|ns|nm|nh>`. "the rule will be active for the specified amount of time and will be removed automatically afterwards". It is **not combinable with `--permanent`** [V S13].
  - Use it as a probe: add with a timeout, verify, then confirm with the `--permanent` add plus `--reload`.
  - Do not re-add the same runtime rule without the timeout: when the timed entry expires it may remove the rule [I].
- **Generic revert for any runtime-only change.** `--reload`: "Current permanent configuration will become new runtime configuration ... all runtime only changes done until reload are lost" [V S13].
  - Arm `systemd-run --on-active=180 --timer-property=AccuracySec=1s firewall-cmd --reload`.
  - Make the change at runtime only, verify, then cancel the timer and repeat the change with `--permanent`.
- **Changes that `--reload` cannot revert (must be reverted explicitly):**
  - `--set-default-zone` is "a runtime and permanent change" [V S13].
  - `--set-log-denied` is "a runtime and permanent change and will also reload the firewall" [V S13].
  - For these, the revert job must run the inverse command, for example `--set-default-zone=<old>`.
- **Permanent-only edits** (policies, ipsets): back up `/etc/firewalld`, apply with `--permanent`, `--check-config`, then `--reload` [V S13]. The revert timer restores the tarball, runs `--reload` [I], and leaves the runtime from before.

### 3.5 Transport and format details
- Text output; set `LC_ALL=C` [I].
- **Exit codes [V S13]:** 0 on success; 2 for bad options; query options return 0 or 1; plus named codes, for example `ALREADY_ENABLED` 11, `NOT_ENABLED` 12, `INVALID_ZONE` 112, `RUNNING_BUT_FAILED` 251, `NOT_RUNNING` 252.
- **Idempotency.** Adding an existing item yields `ALREADY_ENABLED`. Firewall-cmd may print it as a warning and return 0 [U]. Treat both exit 0 with a `Warning: ALREADY_ENABLED` and exit 11 as success [I].
- **Direct interface.** `--direct` is deprecated and "will be removed", superseded by policies [V S13]. Do not use it.

### 3.6 Minimal example of what reading returns
Format per S13 `--info-zone`. The `target` line is [U].
```
public (active)
  target: default
  interfaces: eth0
  sources:
  services: ssh dhcpv6-client
  ports:
  protocols:
  forward-ports:
  source-ports:
  icmp-blocks:
  rich rules:
        rule family="ipv4" source address="10.20.0.0/24" port port="443" protocol="tcp" log prefix="atrium:r-7f3a " level="info" accept
```
Normalised record Atrium should produce [I]:
`{zone, runtime: bool, permanent: bool, priority, family, source, destination, service|port|protocol, log, action, raw}`

### 3.7 Lockout gotchas
- **Panic mode.** `--panic-on`: "All incoming and outgoing packets are dropped, active connections will expire" [V S13]. It is runtime-only, so a reboot or console `--panic-off` clears it. Never call it from Atrium.
- **`--complete-reload`** "will most likely terminate active connections, because state information is lost" [V S13]. Use `--reload`.
- **`--set-default-zone=drop|block`, or moving the SSH interface to another zone.** `--change-interface` goes through NetworkManager when it manages the interface [V S13]. Both are runtime+permanent or connection-level changes; `--reload` does not undo them.
- **Removing `ssh`** from the zone that holds the interface or source matching `SSH_CONNECTION`'s server IP [I].
- **Deny before allow.** At priority 0, a broad deny rich rule overrides a specific allow [V S14].
- **Docker** creates a `docker` zone with target `ACCEPT` and a `docker-forwarding` policy [V S44]. Show it, but do not edit it.

---

## 4. Windows Defender Firewall over OpenSSH and PowerShell

Docs (Microsoft Learn): NetSecurity cmdlets [S19–S22] (ms.date 2016-12-27, updated 2025-05-14); MSFT_NetFirewallRule and MSFT_NetAddressFilter WMI classes [S23, S24] (2018-05-31); firewall rules article [S25] (ms.date 2025-06-06); netsh advfirewall reference [S26] (archived 2008 R2 doc, ms.date 2012-07-02); OpenSSH for Windows [S27, S28] (2025-09-04, 2025-08-05).

### 4.1 Authentication and privileges
- **Keys.** For members of Administrators, sshd uses `%programdata%/ssh/administrators_authorized_keys` instead of the user's file. That file must be ACL'd to SYSTEM and Administrators only [V S28].
- **Authentication methods.** Only `password` and `publickey` are available. Entra ID accounts are not supported [V S28].
- **Default shell is `cmd.exe`**, configurable through `HKLM\SOFTWARE\OpenSSH\DefaultShell` [V S28]. Always invoke `powershell.exe -NoProfile -NonInteractive ...` explicitly [I].
- **Restricting who can log in.** `AllowGroups`, `AllowUsers` and the deny variants. Account names must be lower-case; domain accounts are written `domain\user`; patterns use `user?domain*` [V S28].
- **Permissions [V S26, Windows 7 / 2008 R2 era]:**
  - Administrators (elevated) and the "Network Operators" group can change settings.
  - Other users "can run only those commands that display, but do not change settings".
  - Whether the same holds for the NetSecurity cmdlets on current Windows is [U].
- **Elevation over SSH [U].** Whether an admin's SSH session gets a full (elevated) token was not verified. Add a pre-flight check: `whoami /groups` contains the High Mandatory Level (`S-1-16-12288`) [U]. Refuse writes otherwise.
- **Recommendation [I]:**
  - A dedicated local admin account for writes, key-only, restricted with `AllowUsers` from the hub IP.
  - A separate non-admin account for reads, if the read cmdlets work unelevated on the target build [U].

### 4.2 Reading
- **Rules.** `Get-NetFirewallRule -PolicyStore ActiveStore`. Without `-PolicyStore` the cmdlet reads only the **PersistentStore** [V S19].
  - ActiveStore is the "sum of all policy stores", GPOs included [V S19].
  - Add `-TracePolicyStore` to fill `PolicyStoreSource` [V S19].
- **Conditions live in separate filter objects** ("The filter-to-rule relationship is always one-to-one") [V S19]:
  - `Get-NetFirewallPortFilter`: Protocol, LocalPort, RemotePort, IcmpType, DynamicTarget [V S21];
  - `Get-NetFirewallAddressFilter`: `LocalAddress[]`, `RemoteAddress[]`, `InstanceID` [V S24];
  - also application, service and interface filters [V S19].
  - **Bulk join:** `Get-NetFirewallPortFilter -All -PolicyStore ActiveStore` [V S21 has `-All`; AddressFilter `-All` U]. Join to rules on `InstanceID`, which "uniquely identifies this instance within the PolicyStore" [V S23/S24]. That a filter's InstanceID equals its rule's InstanceID is [U]; test it.
  - Piping each rule into a filter cmdlet is much slower [U].
- **Rule properties and enums** (MSFT_NetFirewallRule) [V S23]:

| Property | Values |
|---|---|
| `Action` | 2 = Allow, 3 = AllowBypass, 4 = Block |
| `Direction` | 1 = Inbound, 2 = Outbound |
| `Enabled` | 1 = Enabled, 2 = Disabled |
| `Profiles` (bitmask) | 0 = Any, 1 = Domain, 2 = Private, 4 = Public |
| `EdgeTraversalPolicy` | 0..3 |
| `PrimaryStatus` | 0 = Unknown, 1 = OK, 2 = Degraded, 3 = Error |
| `EnforcementStatus[]` | 0..23, including 16 = LocalFirewallRulesDisallowed, 5 = InactiveProfile, 4 = DisabledObject |
| Other fields | `PolicyStoreSourceType`, `RuleGroup`, `DisplayGroup`, `DisplayName`, `ElementName`, `Owner`, `InstanceID`, `Description` |

- **Order:** none. "Windows Firewall doesn't support weighted, administrator-assigned rule ordering" [V S25]. Precedence instead:
  1. explicit allow beats the default block;
  2. explicit block beats a conflicting allow;
  3. more specific beats less specific, except for explicit blocks.
  [V S25]. The UI should show "effective" results, not an order.
- **Zones equivalent:** profiles Domain, Private and Public [V S22, S23]. An interface's profile comes from `Get-NetConnectionProfile`, property `NetworkCategory` [U].
- **Address objects:** none. Use the keywords `Any, LocalSubnet, DNS, DHCP, WINS, DefaultGateway, Internet, Intranet, IntranetRemoteAccess, PlayToDevice, CaptivePortal`, with an optional 4 or 6 suffix [V S20].
  - Address formats: single IP, CIDR, `ip/mask`, range `a-b` [V S20].
- **Service objects:** none. Use rule groups (`Group`) and service filters [V S19].
- **Logging.** Per profile only: `LogAllowed`, `LogBlocked`, `LogIgnored`, `LogFileName`, `LogMaxSizeKilobytes` [V S22]. Per-rule logging: not found.
- **Hit counts:** not found as a per-rule counter.
  - The closest is WFP audit events 5152 and 5157 with Filter Run-Time ID; on Windows 11 / Server 2022 they also carry a "Filter Origin" field that names the rule ID [V via search excerpts of S34 only, not opened].
  - That is an approximation for a later version; skip it in the first implementation.
- **Profiles and defaults.** `Get-NetFirewallProfile`: `Enabled`, `DefaultInboundAction` (default Block), `DefaultOutboundAction` (default Allow), `AllowLocalFirewallRules`, `AllowInboundRules` [V S22].
- **NAT:** not part of Defender Firewall. `Get-NetNat` exists for Hyper-V/containers [U]. Skip.
- **Versions.** `$PSVersionTable.PSVersion` [V S27]. `Get-CimInstance Win32_OperatingSystem` (Caption, Version, BuildNumber) [U].
- **Backup.** `netsh advfirewall export "C:\ProgramData\Atrium\fw\<id>.wfw"` exports the current store [V S26].

### 4.3 Writing a single rule
- **Create:**
  ```
  New-NetFirewallRule -Name 'atrium-r-7f3a' -DisplayName 'Atrium r-7f3a' -Group 'Atrium' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 443 -RemoteAddress 10.20.0.0/24 -Profile Any -Enabled True
  ```
  - Pass `-Enabled` as the strings "True" or "False", not `$true` [V S20]. `-Enabled` defaults to True and `-Profile` defaults to Any [V S20].
  - `-Name` "acts just like a filename": only one rule per name per store. The default name is a random value [V S20]. Always set `-Name atrium-<id>`, because `DisplayName` is localised and may change [V S19].
  - `-Group` can be set at creation; `DisplayGroup` cannot [V S20].
- **Update.** `Set-NetFirewallRule -Name 'atrium-r-7f3a' -RemoteAddress 10.20.0.0/24,10.30.0.0/24` [V S21 shows `Set-NetFirewallRule -DisplayName ... -LocalPort` updating a filter field].
- **Enable or disable.** `Enable-NetFirewallRule` / `Disable-NetFirewallRule -Name ...` [V S27 uses `Disable-NetFirewallRule -Name`].
- **Delete.** `Remove-NetFirewallRule -Name 'atrium-r-7f3a'` [V S27].
- **Move:** not applicable (no ordering) [V S25].
- **Commit step.** None. PersistentStore rules "are attached to the ActiveStore and activated on the computer immediately" [V S19].
- **Dry run.** `-WhatIf` exists on `New-NetFirewallRule` and `Set-NetFirewallProfile` [V S20, S22].
- **Idempotency.** Creating an existing `-Name` fails (one per store) [V S20]. Use "Get, then Set or New" [I].
- **Batching.** `-GPOSession` with `Open-NetGPO`/`Save-NetGPO` batches **GPO** edits only [V S20]. It is not a local commit mechanism.

### 4.4 Safe change
- **Native mechanism:** none (not found).
- **Import is a full replace.** `netsh advfirewall import` "overwrites the existing contents of the store. The utility does not ask for confirmation" [V S26].
- **Pattern [I].** The cmdlets are [V S31] for `New-ScheduledTaskTrigger -Once -At`; `New-ScheduledTaskPrincipal` and `Unregister-ScheduledTask` parameters are [U].
  ```powershell
  $id  = 'atrium-fw-revert-7f3a'; $f = 'C:\ProgramData\Atrium\fw\7f3a.wfw'
  netsh advfirewall export $f
  $act = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument "advfirewall import `"$f`""
  $trg = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(3)
  $prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $id -Action $act -Trigger $trg -Principal $prn | Out-Null
  # apply the change, verify from the hub over a NEW ssh connection, then:
  Unregister-ScheduledTask -TaskName $id -Confirm:$false
  ```
  - A full import also discards anything other software changed during the window. Keep the window short.
  - A more precise alternative: the task runs a generated `revert.ps1` holding the inverse operation (Remove or Set back to the snapshot values) [I].
  - Policy files carry a version number; importing a newer policy onto an older OS silently drops unsupported elements [V S26]. That does not matter for a same-host revert.

### 4.5 Transport and format details
- **Shell.** Run commands as `powershell.exe -NoProfile -NonInteractive -EncodedCommand <base64 of UTF-16LE script>` [V S30].
  - Base64 contains no characters the outer shell (cmd.exe or a PowerShell DefaultShell) would reinterpret [I].
  - The cmd.exe command-line limit (8191 characters) is [U]. For long scripts use `-Command -` with the script on stdin. Input is then executed statement by statement, and the exit code is that of the last statement [V S30].
- **Exit codes.** With `-Command`, the exit code is 1 when the last statement failed or a script-terminating error occurred. Use `exit <n>` to set it explicitly [V S30].
- **Error format [I].** Set `$ErrorActionPreference='Stop'` and wrap the script in try/catch. Emit JSON such as `{"ok":false,"error":$_.Exception.Message,"fqid":$_.FullyQualifiedErrorId}`, then `exit 1`.
- **JSON quirks in Windows PowerShell 5.1** [V S29]:
  - `ConvertTo-Json` has **no** `-EnumsAsStrings` and **no** `-AsArray`. Enums serialise as numbers; map them with the S23 table, or cast to `[string]` before serialising.
  - `-Depth` defaults to 2.
  - Use `ConvertTo-Json -InputObject @($items) -Depth 4 -Compress` so a single rule still comes out as an array [I].
  - PowerShell 7 has both switches [V S29 7.5].

### 4.6 Minimal JSON example
Atrium-defined output of the read script below. The property sources are [V S19, S21, S23, S24]; the join is [U].
```powershell
$ErrorActionPreference='Stop'; $s='ActiveStore'
$pf=@{}; Get-NetFirewallPortFilter -All -PolicyStore $s | % { $pf[$_.InstanceID]=$_ }
$af=@{}; Get-NetFirewallAddressFilter -All -PolicyStore $s | % { $af[$_.InstanceID]=$_ }
$out = foreach($r in Get-NetFirewallRule -PolicyStore $s -TracePolicyStore){ $p=$pf[$r.InstanceID]; $a=$af[$r.InstanceID]
  [pscustomobject]@{ name=$r.Name; display_name=$r.DisplayName; group=$r.Group; enabled=[string]$r.Enabled
    direction=[string]$r.Direction; action=[string]$r.Action; profile=[string]$r.Profile
    primary_status=[string]$r.PrimaryStatus; enforcement=@($r.EnforcementStatus|%{[string]$_})
    source=$r.PolicyStoreSource; source_type=[string]$r.PolicyStoreSourceType
    protocol=$p.Protocol; local_port=@($p.LocalPort); remote_port=@($p.RemotePort)
    local_address=@($a.LocalAddress); remote_address=@($a.RemoteAddress) } }
ConvertTo-Json -InputObject @($out) -Depth 4 -Compress
```
```json
[{"name":"OpenSSH-Server-In-TCP","display_name":"OpenSSH Server (sshd)","group":null,"enabled":"True",
  "direction":"Inbound","action":"Allow","profile":"Any","primary_status":"OK","enforcement":["Full"],
  "source":"PersistentStore","source_type":"Local","protocol":"TCP","local_port":["22"],"remote_port":["Any"],
  "local_address":["Any"],"remote_address":["Any"]}]
```

### 4.7 Lockout gotchas
- **The OpenSSH rule.** Installing OpenSSH Server creates the rule `OpenSSH-Server-In-TCP` (TCP 22 inbound). If it is missing or disabled, "connections are refused or reset" [V S27]. Atrium must refuse to disable or remove it, or to narrow it so that it excludes `hub_ip`.
- **Block rules always win** [V S25]. Any Block rule whose remote address and port match `hub_ip -> 22`, even a broad subnet block, cuts SSH. The lint must refuse it.
- **Shields-Up.** `Set-NetFirewallProfile -AllowInboundRules False` combined with `DefaultInboundAction Block` puts the firewall in "Shields-Up mode" and ignores every inbound allow [V S22]. Refuse it.
- **GPO precedence.**
  - If GPO sets `AllowLocalFirewallRules False`, local rules (Atrium's included) are ignored [V S22, S25]. Rules then show `EnforcementStatus` = LocalFirewallRulesDisallowed [V S23].
  - Rules sourced from GPO cannot be changed locally [I].
  - Show both cases in the UI.
- **Profile changes.** If the network category changes (Public / Private / Domain), profile-scoped rules stop applying [V S22/S25 profile semantics].
- **Full replace without confirmation.** `netsh advfirewall import` replaces the whole store [V S26].

---

## 5. Network facts for placing hosts into zones

### 5.1 Linux
- **Addresses:** `ip -j addr show` (`-j` "Output results in JavaScript Object Notation"; `-p` pretty-prints) [V S36].
  - Keys present in the iproute2 source: `ifindex`, `operstate`, `mtu`, `link_type`, `master`, the `flags` array, the `addr_info` array with `family`, `local`, `prefixlen`, `broadcast`, `scope`, `label`, `valid_life_time` [V S37 ipaddress.c].
  - `ifname` and `address` (MAC) are expected [U for exact keys].
- **VLANs:** `ip -j -d link show type vlan` [U for the filter]. The `linkinfo` object holds `info_kind` = "vlan" and `info_data` with `protocol` and `id` [V S37 ipaddress.c, iplink_vlan.c].
- **Default route and subnets:** `ip -j route show`. Keys: `dst` ("default" for the default route [U]), `gateway`, `dev`, `protocol`, `scope`, `prefsrc`, `metric`, `type` [V S37 iproute.c].
- **Listening ports.** `ss` has **no JSON option** [V S35, man page as of the 2026-07-28 upstream commit]. Use `ss -H -tuln`; add `-p` for process names (root needed to see other users' processes [U]).
  - `-H` suppresses the header and `-O` gives one line per socket [V S35].
  - Columns: Netid, State, Recv-Q, Send-Q, Local:Port, Peer:Port [U].
  - Local address forms to handle: `0.0.0.0:22`, `[::]:22`, `*:22`, and interface-scoped forms such as `127.0.0.53%lo:53` [U].
- **Classification [I]:**
  - a bind to `0.0.0.0`, `::` or `*` is exposed on every interface;
  - a bind to loopback is local-only;
  - a bind to a specific IP is exposed only in the zone that IP belongs to.

### 5.2 Windows
- **Addresses:** `Get-NetIPAddress`. Properties: `IPAddress`, `InterfaceIndex`, `InterfaceAlias`, `AddressFamily` (IPv4/IPv6), `PrefixLength`, `PrefixOrigin` (Manual/Dhcp/...), `AddressState` [V S33].
- **Listening TCP:** `Get-NetTCPConnection -State Listen`. Properties: `LocalAddress`, `LocalPort`, `OwningProcess` [V S32].
- **UDP:** `Get-NetUDPEndpoint` [U].
- **Default gateway:** `Get-NetRoute -DestinationPrefix 0.0.0.0/0` [U].
- **VLAN:** `Get-NetAdapter` property `VlanID` [U].
- **Profile per interface:** `Get-NetConnectionProfile`, property `NetworkCategory` [U].

### 5.3 Zone assignment [I]
1. Atrium zones are defined as CIDR lists plus optional VLAN IDs.
2. A host interface belongs to the zone whose CIDR contains its address.
3. A host with interfaces in several zones is a multi-homed or edge node. Flag it.
4. Listening sockets give the candidate services, i.e. the possible arrow targets.
5. Firewall rules give the *permitted* edges. Compare them with the arrows drawn on the canvas, and show:
   - edges that are drawn but not enforced;
   - edges that are enforced but not drawn.

---

## 6. Mapping a canvas arrow (zone A to host H, service S) to one rule [I]
- **Prerequisite.** Show each host's default inbound posture:
  - nft chain `policy`;
  - ufw `Default:` line;
  - firewalld zone target;
  - Windows `DefaultInboundAction`.

  An "allow" arrow only means something when the default is deny.
- **nftables.** Keep one named set per Atrium zone in `table inet atrium` (`type ipv4_addr; flags interval`). The arrow becomes `add rule inet atrium input ip saddr @zone_A tcp dport S accept comment "atrium:edge-<id>"`. Editing a zone's CIDRs then only changes set elements, not rules.
- **ufw.** One `ufw allow from <cidr> to any port S proto tcp comment 'atrium:edge-<id>'` per CIDR.
- **firewalld.** Most native: an Atrium zone with `--add-source=<cidr>` and `--add-service`/`--add-port`. Alternatively a rich rule with `source ipset="atrium_zone_A"` [V S14 ipset source]. For routed segmentation on a firewalld gateway, use a policy with ingress zone A and egress zone B [V S15].
- **Windows.** One rule `atrium-edge-<id>` with `-RemoteAddress <all CIDRs of zone A>` and `-LocalPort S` [V S20].

---

## 7. Not found or open
- **Native commit-confirm / automatic rollback:** none in nftables, ufw, firewalld (except `--timeout` for additions) or Windows Defender Firewall.
- **Per-rule hit counters:** none in ufw (only underlying iptables counters [U]), firewalld or Windows. nftables has them only with `counter` statements.
- **"Disabled" rule state:** none in nftables, ufw or firewalld rich rules. Windows has one (`Enabled`).
- **Rule comments:** none in firewalld rich rules. Windows uses `Description` and `Group` instead [V S19].
- **Least privilege:** no documented read-only capability for nftables or ufw.

---

## Source table
| ID | Source | Version / date |
|---|---|---|
| S1 | https://www.netfilter.org/projects/nftables/manpage.html | Updated 07/02/2026 |
| S2 | https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html (also https://www.mankier.com/5/libnftables-json) | libnftables1 1.1.7-2, 2025-12-05 |
| S3 | https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement | edited 2021-02-13 |
| S4 | https://wiki.nftables.org/wiki-nftables/index.php/Output_text_modifiers | edited 2020-07-22 |
| S5 | https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains | edited 2024-10-08 |
| S6 | https://lab.nexedi.cn/kirr/linux/-/commit/0628b123c96d126e617beb3b4fd63b874d0e4f17 | kernel commit (nfnetlink batch) |
| S7 | https://lists.netfilter.org/pipermail/netfilter-buglog/2023-September/005521.html | bug 1463, 2020–2023 |
| S8 | https://kernel.org/doc/html/v6.19-rc3/netlink/specs/nftables.html and https://gitlab.archlinux.org/archlinux/packaging/packages/nftables/-/issues/1 | kernel 6.3+ destroy |
| S9 | https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html | ufw 0.36.2-6 |
| S10 | https://manpages.ubuntu.com/manpages/noble/en/man8/ufw-framework.8.html | ufw 0.36.2-6 |
| S11 | https://git.launchpad.net/ufw/tree/src/backend_iptables.py and https://git.launchpad.net/ufw/tree/src/ufw | upstream main, read 2026-10-09 |
| S12 | https://ubuntu.com/server/docs/how-to/security/firewalls/ | undated |
| S13 | https://firewalld.org/documentation/man-pages/firewall-cmd.html | no version stated |
| S14 | https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html | no version stated |
| S15 | https://firewalld.org/documentation/man-pages/firewalld.policies.html | no version stated |
| S16 | https://firewalld.org/documentation/man-pages/firewalld.zone.html | no version stated |
| S17 | https://firewalld.org/documentation/man-pages/firewalld.dbus.html | no version stated |
| S18 | https://raw.githubusercontent.com/firewalld/firewalld/main/config/org.fedoraproject.FirewallD1.server.policy.in | main, read 2026-10-09 |
| S19 | https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps | ms.date 2016-12-27, updated 2025-05-14 |
| S20 | https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps | same |
| S21 | https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps | same |
| S22 | https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps | same |
| S23 | https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule | ms.date 2018-05-31 |
| S24 | https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netaddressfilter | ms.date 2018-05-31 |
| S25 | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules | ms.date 2025-06-06 |
| S26 | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10) | archived, ms.date 2012-07-02 |
| S27 | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse | ms.date 2025-09-04 |
| S28 | https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration | ms.date 2025-08-05 |
| S29 | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-5.1 (and ?view=powershell-7.5) | 2022-12-12 / 2026-04-08 |
| S30 | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1 | ms.date 2024-07-23 |
| S31 | https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps | ms.date 2016-12-20 |
| S32 | https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps | ms.date 2016-12-20 |
| S33 | https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2025-ps | ms.date 2021-06-23 |
| S34 | https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation and https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging | search excerpts only |
| S35 | https://man7.org/linux/man-pages/man8/ss.8.html | iproute2, upstream commit 2026-07-28 |
| S36 | https://man7.org/linux/man-pages/man8/ip.8.html | iproute2, upstream commit 2026-07-28 |
| S37 | https://raw.githubusercontent.com/iproute2/iproute2/main/ip/ipaddress.c, .../iplink_vlan.c, .../iproute.c | main, read 2026-10-09 |
| S38 | https://man7.org/linux/man-pages/man1/systemd-run.1.html | systemd 262~devel |
| S39 | https://man7.org/linux/man-pages/man5/systemd.timer.5.html | same |
| S40 | https://man7.org/linux/man-pages/man5/os-release.5.html | current |
| S41 | https://www.sudo.ws/docs/man/sudoers.man/ | sudo 1.9.16-era |
| S42 | https://man.openbsd.org/ssh | current |
| S43 | https://man.openbsd.org/sshd_config | current |
| S44 | https://docs.docker.com/engine/network/packet-filtering-firewalls/ | undated |
| S45 | C:\Users\test\Downloads\hub program\hub\execution\runner.py | repo working tree, 2026-10-09 |


## Confidence notes
- Nothing in the repo was changed. The only file read for repo context was hub/execution/runner.py, plus a grep for SSH usage. Its 64,000-character tail truncation, stdout+stderr concatenation and one connection per command are verified by reading the code.
- None of the four firewalls has a native commit-confirm or rollback timer. firewalld --timeout (additions only, not combinable with --permanent) is the only native auto-expiry. Every timed-revert recipe here is an Atrium design built from verified primitives (systemd-run --on-active, systemd AccuracySec default 1 min, Scheduled Tasks -Once -At, netsh export/import).
- nftables: that nft -f applies a file atomically is verified on the wiki and in the kernel batch commit. That a kernel-side error rolls back the whole file is inferred from the commit/abort semantics, not stated in user docs. That 'nft list' needs CAP_NET_ADMIN/root was not found in official docs (unverified). The JSON shapes for jump/goto, snat/dnat and ct state, and the payload field names saddr/daddr, are unverified. The 'nft -j -f file.json' CLI form is unverified; libnftables JSON input via the API is verified.
- ufw: the status output format strings and the tuple field order were verified from upstream source (backend_iptables.py), not from the man page. Whether tuple comments are hex-encoded is unverified. The exact header indentation of 'status numbered' is unverified. Whether 'ufw delete NUM' prompts and needs --force is unverified. Root being required is inferred.
- firewalld: the polkit defaults are verified from the upstream server policy file, but which firewall-cmd query needs which polkit action was not verified; test empirically. Whether 'already enabled' returns exit 0 with a warning or exit 11 is unverified. The 'port port= protocol=' rich-rule element syntax is unverified. The busctl --json D-Bus route is unverified.
- Windows: the cmdlet parameters, store semantics, precedence rules, the MSFT_NetFirewallRule enum numbers, the netsh import overwrite warning and the OpenSSH rule name are verified on Microsoft Learn. Still unverified: that filter InstanceID equals rule InstanceID (used for the bulk join), Get-NetFirewallAddressFilter -All, whether SSH admin sessions get an elevated token, whether Win32-OpenSSH sets SSH_CONNECTION, whether standard users can run the read cmdlets, the New-ScheduledTaskPrincipal parameters, and the cmd.exe 8191-character limit. The netsh permissions statement comes from an archived 2008 R2 era document.
- Hit counts on Windows: no per-rule counter was found. The WFP audit 5152/5157 Filter Origin approach is known only from search excerpts of Microsoft docs, which were not opened.
- ss has no JSON output (verified on the man7 page as of the 2026-07-28 upstream commit). The ip -j keys were verified in iproute2 source on the GitHub mirror (ipaddress.c, iplink_vlan.c, iproute.c), except 'ifname' and 'address', which were not confirmed as exact keys.
- Doc versions: firewalld.org pages state no version. Several Microsoft cmdlet pages carry ms.date 2016 with a 2025 update. The ufw docs are for Ubuntu 24.04 (0.36.2-6). The libnftables-json page is Debian 1.1.7-2. Behaviour on older distros (for example nft 'destroy' on kernels before 6.3, and nft --json crashing on iptables-nft tables in builds before the late-2022 fix) differs, as noted in the document.

## Sources
- https://www.netfilter.org/projects/nftables/manpage.html
- https://manpages.debian.org/testing/libnftables1/libnftables-json.5.en.html
- https://www.mankier.com/5/libnftables-json
- https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
- https://wiki.nftables.org/wiki-nftables/index.php/Scripting
- https://wiki.nftables.org/wiki-nftables/index.php/Output_text_modifiers
- https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains
- https://lab.nexedi.cn/kirr/linux/-/commit/0628b123c96d126e617beb3b4fd63b874d0e4f17
- https://lists.netfilter.org/pipermail/netfilter-buglog/2023-September/005521.html
- https://lists.netfilter.org/pipermail/netfilter-buglog/2020-September/005066.html
- https://kernel.org/doc/html/v6.19-rc3/netlink/specs/nftables.html
- https://gitlab.archlinux.org/archlinux/packaging/packages/nftables/-/issues/1
- https://manpages.ubuntu.com/manpages/noble/en/man8/ufw.8.html
- https://manpages.ubuntu.com/manpages/noble/en/man8/ufw-framework.8.html
- https://git.launchpad.net/ufw/tree/src/backend_iptables.py
- https://git.launchpad.net/ufw/tree/src/ufw
- https://git.launchpad.net/ufw/tree/src/backend.py
- https://ubuntu.com/server/docs/how-to/security/firewalls/
- https://firewalld.org/documentation/man-pages/firewall-cmd.html
- https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html
- https://firewalld.org/documentation/man-pages/firewalld.policies.html
- https://firewalld.org/documentation/man-pages/firewalld.zone.html
- https://firewalld.org/documentation/man-pages/firewalld.dbus.html
- https://raw.githubusercontent.com/firewalld/firewalld/main/config/org.fedoraproject.FirewallD1.server.policy.in
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallrule?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallportfilter?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netfirewallrule
- https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/wfascimprov/msft-netaddressfilter
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771920(v=ws.10)
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse
- https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-5.1
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/convertto-json?view=powershell-7.5
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1
- https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation
- https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging
- https://man7.org/linux/man-pages/man8/ss.8.html
- https://man7.org/linux/man-pages/man8/ip.8.html
- https://raw.githubusercontent.com/iproute2/iproute2/main/ip/ipaddress.c
- https://raw.githubusercontent.com/iproute2/iproute2/main/ip/iplink_vlan.c
- https://raw.githubusercontent.com/iproute2/iproute2/main/ip/iproute.c
- https://man7.org/linux/man-pages/man1/systemd-run.1.html
- https://man7.org/linux/man-pages/man5/systemd.timer.5.html
- https://man7.org/linux/man-pages/man5/os-release.5.html
- https://www.sudo.ws/docs/man/sudoers.man/
- https://man.openbsd.org/ssh
- https://man.openbsd.org/sshd_config
- https://docs.docker.com/engine/network/packet-filtering-firewalls/
- C:\Users\test\Downloads\hub program\hub\execution\runner.py