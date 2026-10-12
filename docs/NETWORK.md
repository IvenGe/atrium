# Network

Atrium reads firewalls, routers, switches and host firewalls into one snapshot per connection. It does not change a device unless an administrator turns device changes on, and even then only through an approval.

## What a snapshot holds

Each pull stores one normalised record: device facts, interfaces, zones, aliases, rules and the default policy. History keeps the last 50 content changes. Drift is the difference from the previous snapshot. A change Atrium applied itself is attributed to that change. Anything else stays open until an operator acknowledges it. An administrator can accept the current snapshot as the baseline.

Configuration backups are encrypted at rest. The list shows metadata. Only an administrator can download the bytes. Restoring a backup is a new approved change, not a button that writes immediately.

## Connectors

| Kind | Reads | Writes |
|---|---|---|
| OPNsense | REST with an API key and secret | Savepoint on 24.1–26.1. Backup and revert on 26.7 and later. HTTP 200 with `result: failed` is a failure. |
| pfSense | CE over SSH. Plus and the unofficial pfrest package are read-only where the API is not verified. | CE: a dead-man script. Plus writes stay off until the vendor API is verified. |
| MikroTik | RouterOS v7 REST. Values are strings. | A scheduler dead-man. There is no safe mode over REST. |
| FortiGate | REST token | Only when workspace transactions exist (FortiOS 7.4.1 and later). Otherwise read-only. Rollback is the inverse operation. |
| PAN-OS | XML API key | Candidate config, a saved `atrium-pre-<id>.xml`, then a partial commit. |
| IOS-XE | RESTCONF | NETCONF confirmed commit only when the device advertises it. Otherwise read-only. |
| Linux host firewall | SSH. nftables, ufw or firewalld, detected on the host. | An Atrium-owned nft table and a systemd-run dead-man. Persist only after confirm. |
| Windows Defender Firewall | OpenSSH and PowerShell | A scheduled task dead-man. Persist only after confirm. |

Unverified third-party details are marked `UNVERIFIED` in the connector source. `test()` checks reachability, TLS, authentication, privileges, version and the API features the connector uses. When the credential can write, the result says a read-only key is preferable until device changes are enabled.

Host firewalls use `sudo -n` and fixed commands. Atrium never stores a sudo password. The sudoers lines are in the connector docstrings.

## Changing a device

Device changes follow one path:

1. Device changes are off by default.
2. The connector must declare a rollback mode other than `none`, the last connection test must have passed, and the snapshot must be fresher than 15 minutes.
3. Every change is a proposal, including in autonomous mode. The approval is bound to the device revision and a hash of the operations.
4. Only an administrator can approve it, and not the person who proposed it, while "a second person approves device changes" is on.
5. With the maintenance-window guardrail on, an approved change waits until a window. An administrator can mark it an emergency; that is logged and counted on control HB-CM-3.
6. Atrium takes an encrypted backup first when that guardrail is on. Apply is refused if the backup fails.
7. The Network Supervisor applies the change through the tool supervisor, on a new connection. It then re-reads the device. It confirms only when the hub can still authenticate and the change is visible. Otherwise it rolls back.
8. Reverting an applied change is a new proposal.

Approvals expire after `approval_expiry_hours` (default 24, range 1–72). Turning device changes off blocks approved changes that have not started. A change already being verified finishes or rolls back.

The other guardrail, "a second person approves other requests", is off by default. It covers approvals that name a proposer, including self-patches. Firewall changes use the device-change switch, which is on.

## Screens

The Network app lists devices and, for each one, rules, interfaces, history, drift, backups and changes. The segmentation map and the Integration map read the same snapshots. Rule text from a device is shown as text.
