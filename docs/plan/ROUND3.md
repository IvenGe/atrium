# Round 3 specification

Source of truth for details: `docs/research/*.md`. Those documents were written before round 2 landed, so their
"repository facts" and line numbers are partly stale: **the current code wins** (for example: a People app now
exists; guardrails live in the registry in `hub/guardrails.py`, not in `DEFAULT_GUARDRAILS`; approval kinds include
`agent_team`, `extension`, `self_patch`). Where research and this file disagree, this file wins.

Cross-cutting rules (all stages):
- Guardrails are toggle settings registered in `hub/guardrails.py` with safe defaults, every change logged with the
  actor, and a weakened guardrail reflected in a compliance control (`control`, `weakens`, `finding`).
- Third-party API details: follow the research docs' verification labels. Anything labelled [U] or not verified
  against official documentation gets an `UNVERIFIED:` code comment and is listed in open_issues. Design defensively
  (clear errors, configurable paths). No real devices are available: test with `httpx.MockTransport`, fake SSH
  runners, and fake GMP/XML servers. Make `test()` genuinely useful for a person checking a real device (per-check
  results: reachability, TLS, auth, privileges/read-only role, version, API features).
- Text read from devices (rule descriptions, interface names, comments) is untrusted: never rendered as HTML, never
  added to agent/LLM tool output without being clearly delimited data, never used to build shell commands without
  strict validation/quoting.
- Secrets never in API output, logs, activity, bus messages, error messages.
- Every new endpoint classified in `hub/auth/policy.py` and covered by the permission-matrix tests.

---

## R3-CYFUN: CyFun 2025 + 2023 in the Compliance hub, audit pack, CISO Assistant framework sync

Read `docs/research/cyfun-cra-ciso.md` in full.

1. **Framework catalogs** (`hub/grc/frameworks/`): build-time-generated JSON catalogs for CyFun 2025 and CyFun 2023,
   produced by a script `scripts/build_cyfun_catalog.py` from the CISO Assistant library files
   (`https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/cyfun2025.yaml`
   and `ccb-cff-2023-03-01.yaml`; reachable from this container). Store per requirement ONLY: ref_id, parent
   function/category/subcategory ids, level tags (`B`/`I`/`E`, key measures `BK`/`IK`/`EK`, management aspects
   `BG`/`IG`/`EG` for 2025), and a short title. **Licensing:** do not ship CCB requirement text, descriptions or
   annotations. Titles: use the NIST CSF subcategory/category names (NIST CSF 2.0 for 2025, CSF 1.1 for 2023; US
   government works, public domain) or short neutral titles you write; each requirement links to cyfun.eu for the
   text. Record source library URN, version and publication date in the catalog header. CyFun 2023 ids follow the
   library (e.g. `ID.AM-1.1`; strip CISO Assistant's `BASIC_`/`IMPORTANT_` prefixes into tags). Expect ~218 / ~219
   assessable requirements; the script verifies counts and that levels are cumulative.
2. **Assessments** (collection `framework_assessments`): an organisation chooses edition (2025 default, 2023 allowed
   until 18 April 2027 - show the transition note) and target level (Basic / Important / Essential). Per requirement:
   implementation maturity 1-5 and documentation maturity 1-5 (CyFun 2025 scale names Initial / Repeatable / Defined
   / Managed / Optimizing with your own one-line descriptions), N/A with mandatory justification, owner (person id
   from the People app), notes, evidence links (hub controls, evidence items, files/URLs), updated_by/at. Hub
   controls map to CyFun requirements (add `CyFun2025` and `CyFun2023` refs to the baseline controls using section 2 of
   the research doc; mark the analyst-judgement rows as such) so automated control results appear as suggested
   evidence; maturity stays a human judgement (never auto-set scores).
3. **Scoring and conformity** per the library's outcome rules (research 1.3): requirement maturity = average of the
   two dimensions; group scores (B/I/E, key-measure min, category averages for Essential); N/A limits per level;
   targets B 2.5, I and E per table; verdict per level with the reasons (which key measures are below, which
   categories fail, too many N/A). Label the thresholds as taken from the CISO Assistant library copy (the CCB
   originals were unreachable) in code and UI.
4. **Audit pack**: `GET /api/frameworks/{id}/assessments/{aid}/audit-pack` (viewer) returns a ZIP: `summary.html`
   (self-contained, printable; scores per function/category/level, conformity verdict, gaps, key measures), `requirements.csv`,
   `evidence/` index with hub control results and evidence metadata (no secrets), `assessment.json`, and a manifest with
   SHA-256 of every file. Activity entry on export.
5. **CRA**: available through CISO Assistant sync (below) - not built in. Note in docs that the library appears to be
   built from the Parliament text, not the OJ text.
6. **CISO Assistant framework sync** (extend `hub/connectors/ciso_assistant.py` and the flows): new domain
   `frameworks` (read: loaded frameworks, compliance assessments, requirement assessments, mapping sets per research
   4.2-4.7); push hub assessment results (result + scores) into a CISO Assistant compliance assessment only when an
   admin enables it; fix the 4.9 discrepancies (`degraded` status, evidence with `link`/`observation`). Library
   import into CISO Assistant is never automatic: `test()` reports which libraries (CyFun 2025/2023, CRA) are loaded.
   Imported frameworks other than CyFun (e.g. CRA) appear read-only in the Compliance hub with their requirement
   tree and the CISO Assistant assessment status.
7. **API** (all classified): `GET /api/frameworks` (viewer), `GET /api/frameworks/{id}` (viewer; tree with tags),
   `GET/POST /api/frameworks/{id}/assessments` (viewer/operator), `GET/PATCH /api/frameworks/{id}/assessments/{aid}`
   (viewer/operator), `PATCH /api/frameworks/{id}/assessments/{aid}/requirements/{ref}` (operator), the audit pack,
   `DELETE` assessment (admin).
8. **Controls**: GRC control for "Compliance framework self-assessment is current" (partial when older than 12
   months or below target in key measures; manual when none). Pick the next free HB id in the right family.
9. **UI** (Compliance hub, hub/web only): Frameworks tab - catalog browser (function -> category -> requirement, level
   tag chips, key-measure badge, filter by level/key measures/status), assessment workspace (scoring per requirement
   with two 1-5 selectors, N/A + justification, owner picker, evidence linking with suggested hub controls), progress
   and conformity panel per level with reasons, edition switch with transition note, audit pack download, CISO
   Assistant sync status. Viewers read; operators score; admins delete.
10. **Tests**: catalog integrity (counts, cumulative tags, key measures present, no CCB description text shipped -
    assert no catalog title equals the library `description`), scoring/conformity golden cases incl. N/A limits and
    Essential category rule, audit pack contents + hashes + no secrets, CISO Assistant framework reads/pushes with
    MockTransport, permissions.

---

## R3-NETCORE: network read model, segmentation model, drift, compliance evidence, connector contract

Read `docs/research/canvas-design.md` sections 6 and 7.5-7.6 and 8, and section 4/5/6 of each `fw-*.md`.

1. **Domain `network`** (read): extend the closed domain set (`Domain` in models, `DOMAINS` in connectors/base.py,
   flows OWNERS/APPS, planner rule "reads network -> pull"). New agent `module:network` (Network Supervisor) runs the
   pull and stores one snapshot per device in `network_snapshots` (current) plus history `network_snapshot_history`
   (bounded, e.g. last 50 per device, with revision + hash). Normalised record per canvas-design 6.1, extended with
   `device` (vendor, model, version, hostname, management address), `kind` (`firewall` | `router` | `switch` | `host`),
   and per-rule `vendor_ref` (stable native id: OPNsense uuid, FortiGate policyid, PAN-OS rule name, IOS-XE ACL
   name+sequence, nft handle, ufw number+tuple, firewalld zone+rich rule, Windows rule Name).
2. **Connector contract** in `hub/connectors/base.py` (document it): read via `pull("network")`; write capability is
   declared as class attribute `network_write = {"ops": [...], "rollback": "savepoint"|"backup_restore"|"deadman"|
   "commit_confirm"|"none", "window_s": int}` and methods `backup() -> {backup_id, taken_at, size, sha256}` (content
   stored encrypted by the hub, see below), `preview_change(ops, snapshot)`, `apply_change(ops, base_revision, backup)`,
   `confirm_change(token)`, `rollback_change(token, backup)`, `restore_backup(backup)`. These are **never** in
   `Connector.actions` (so `connector.action` cannot reach them). Generated/generic connectors are never write-capable.
3. **SSH session API** in `hub/execution/runner.py` for host firewalls and pfSense CE / IOS-XE CLI (research
   fw-hosts 0.2): one connection per session, stdout/stderr separate + exit status, no tail truncation for reads (or
   a configurable larger cap with an explicit "truncated" flag - never silently corrupt JSON), scripts on stdin,
   strict host keys honoured. Injectable for tests (fake session).
4. **Atrium-managed backups** (collection `device_backups`): content encrypted with `hub/secrets.py`, SHA-256,
   device, revision, reason (`pre-change`, `manual`, `scheduled`), retention (keep last N, default 20; admin setting).
   API: list (viewer, metadata only), take now (operator), download (admin), restore = proposes a change (see
   R3-NETCHANGE; never restores directly).
5. **Segmentation read model** (`hub/integration/segmentation.py`) per canvas-design 6.2-6.5 and 7.5-7.6: zones,
   longest-prefix asset placement (multi-homed, external, unplaced, retired excluded, manual override), allowed traffic
   aggregated per interface (no first-match evaluation; label it an approximation), unresolved aliases, policy
   (allowed/restricted/forbidden zone pairs, admin), overlays (open vulnerabilities by severity, compliance verdicts).
   Endpoints per canvas-design section 8 (map, segmentation, zones PATCH admin, placements PUT, policy GET/PUT admin,
   refresh). SSE events `segmentation`.
6. **Drift detection**: each pull compares with the previous snapshot and with an optional approved **baseline**
   (admin "accept current as baseline" per device). Drift items: rule added/removed/changed/enabled/disabled,
   interface/zone changes, any-any or management exposure introduced, changes not made through Atrium (no matching
   applied FirewallChange). Stored in `network_drift`; activity + notification on new drift; acknowledge (operator).
   Changes Atrium applied itself are attributed to their change id, not reported as unexplained drift.
7. **Compliance**: controls `HB-NW-1..5` per canvas-design 6.5 (segmentation policy respected, no unexplained drift
   in 30 days / drift acknowledged, management interfaces not exposed to WAN/any, device configs backed up within 7
   days, rules have descriptions/owners or logging on pass rules - pick five that the read model can evidence) with
   refs ISO27001/SOC2/NIS2 and CyFun2025 ids from cyfun research section 2.1 (mark [U] reference strings). Evidence
   from snapshots.
8. **Network app** backend needs: `GET /api/network/devices` (viewer: device, kind, vendor, version, connection
   state, last snapshot age, counts, drift count, backup age, write capability + rollback mode), `GET
   /api/network/devices/{tool_id}` (snapshot, rules, interfaces, zones, history list), `GET
   /api/network/devices/{tool_id}/history/{rev}`, `GET /api/network/drift`, `POST /api/network/drift/{id}/ack`,
   `POST /api/network/devices/{tool_id}/baseline` (admin), backups endpoints.
9. A **fake firewall connector** for tests and for the UI agents' manual testing (`hub/connectors/fake_firewall.py`,
   registered only when `HUB_DEV_FAKE_DEVICES=1` or by tests) with mutable in-memory rules, revisions, write ops,
   backup/restore, a switch to simulate lockout/verification failure.
10. Tests: snapshot storage + history bound, normalisation of the fake, segmentation placement + aggregation cases
    from canvas-design 13/B2, drift detection incl. attribution, backups encrypted at rest (assert plaintext absent in
    the DB file), permissions, `connector.action` cannot reach write methods.

---

## R3-FW: device connectors (one agent per file group; each owns only its files + tests + one REGISTRY line)

All read the normalised model from R3-NETCORE and implement `pull("network")`, `test()`, `detect()`, options, and,
where the research shows a safe mechanism, the write contract (`allow` = add one pass rule between two zone networks
with explicit services, `disable_rules`), `backup()` and `restore_backup()`. Follow the research doc's change protocol
for the product exactly (preflight + management-path guard, backup, write one rule, apply, verify over a NEW
connection, confirm, else roll back). Atrium-side marker on rules it creates (`atrium:<change-id>` in description /
comment). Least-privilege notes surfaced in `test()` (e.g. "this API key can write; a read-only key is recommended
until device changes are enabled").

- **opnsense.py**: OPNsense REST (key/secret Basic), versions: savepoint flow for <= 26.1, backup id +
  `revert_backup` for >= 26.7 (research 1.6.A/B; savepoint removed in 26.7), result `failed` with 200 handled.
- **pfsense.py**: CE via SSH (config.xml read; rule write via official PHP primitives; dead-man script) and Plus via
  its API only where research has verified details - otherwise read-only with `UNVERIFIED` notes. The unofficial
  pfrest package is supported read-only at most, labelled unofficial.
- **mikrotik.py**: RouterOS v7 REST (strings everywhere), scheduler dead-man rollback (no safe mode over REST).
- **fortigate.py**: FortiOS REST token, read policies/zones/interfaces/addresses/services; writes only with
  transaction support (>= 7.4.1 per research) + Atrium inverse-op rollback; otherwise read-only.
- **panos.py**: XML/REST API key; candidate config + partial commit for the API admin, `save config to
  atrium-pre-<id>.xml` backup, rollback via inverse ops then `load config from` + commit as last resort.
- **cisco_iosxe.py**: RESTCONF reads (ACLs, VLANs, SVIs, interfaces); writes only via NETCONF confirmed commit when
  the device supports candidate + confirmed-commit (detect via capabilities); otherwise read-only. If no NETCONF
  library is installed, writes are reported as unavailable (do not add heavy dependencies without need; `asyncssh`
  is already an extra and can carry NETCONF over SSH subsystem framing if you implement minimal RFC 6242 framing -
  your call, keep it small and tested).
- **hostfw.py** (Linux nftables / ufw / firewalld) and **windows_firewall.py** (Windows Defender Firewall over
  OpenSSH + PowerShell): via the R3-NETCORE SSH session API, manager detection (fw-hosts 0.3), Atrium-owned nft table,
  dead-man revert timer on the host (systemd-run / Scheduled Task), persist only after confirm, sudo -n with fixed
  wrapper verbs (document the sudoers lines; never store sudo passwords).

Tests per connector with recorded/fabricated responses based on the research doc's documented examples.

---

## R3-NETCHANGE: guarded network changes (backend)

Read `docs/research/canvas-design.md` 6.6, 7.7, 8 and `docs/plan/review-notes.md`.

1. Guardrails (registry, group "network"): `device_changes` (default **off**, safe side off; turning it on is logged
   as relaxing but is not a compliance weakness by itself), `device_changes_need_second_person` (on; off weakens the
   network change-management control to `fail`), `device_changes_need_maintenance_window` (on; off -> `partial`),
   `device_changes_need_backup` (on; off -> `fail`; with it on, apply is refused when the backup failed),
   `approval_expiry_hours` (number, default 24, 1-72). The network change-management control is a new HB control (or
   HB-CM-x) evaluated from these guardrails plus change history (emergency applies, rollbacks). Kill switch S14.
2. `FirewallChange` lifecycle exactly as canvas-design 6.6/7.7 (S1-S16), with these additions:
   - Rollback modes from the connector (`savepoint`, `backup_restore`, `deadman`, `commit_confirm`); `none` = not writable.
   - **Atrium-managed backup** before every apply (stored per R3-NETCORE 4); its id recorded on the change; restore
     on failed verification when the connector's own rollback did not revert (re-read proves it).
   - **Maintenance windows** (collection `maintenance_windows`, admin CRUD: device(s) or all, weekly recurrence or
     one-off, start/end, timezone): with the guardrail on, an approved change outside a window waits in status
     `scheduled` and is applied by `module:network` at the window start (re-checking revision, expiry, guardrail,
     approval binding); an admin may mark an approved change "emergency - apply now" with a justification (logged,
     reflected in the change-management control as an exception count).
   - Approval binding: approval payload carries `base_revision` + `ops_hash`; approval expires 24 h after creation
     (configurable 1-72 h, admin); apply re-checks everything (S6-S8).
   - Revert after applied = new proposal (S10). Restore of an Atrium backup = new proposal of op `restore` with the
     backup id, same approval rules.
3. **Review-notes fixes** (this stage owns them): F1 (Approvals.decide refuses decider == proposer for kinds
   `firewall`, `self_patch`, and any approval whose payload has `proposed_by`, when the second-person guardrail applies;
   add a general guardrail `approvals_need_second_person` default off for other kinds, documented; 403 `same_person`),
   F2 (binding + expiry for firewall; also expiry for `self_patch` approvals bound to the worktree commit), F3
   (`ToolSupervisor.on_connector_action` refuses side-effecting actions from non-person senders unless routed through
   their approval kind - e.g. OpenVAS `scan` only via the scan approval path; read-only actions like `scan_status`
   stay open; mark actions as side-effecting in the connector class), F4 (rollback of an applied change is a new
   approved change).
4. Endpoints per canvas-design section 8 (preview, create, list, get, withdraw, revert) plus maintenance windows CRUD
   and `POST /api/segmentation/changes/{id}/emergency` (admin). SSE `firewall_change`.
5. Tests: every case listed in canvas-design 13/B4 plus maintenance window scheduling (outside window -> scheduled ->
   applied at window start; guardrail off -> immediate), backup taken before apply and restore on failed verify,
   emergency apply, approval expiry, restore-as-proposal, F1/F3 regressions.

---

## R3-NETUI: Network app and change approvals (hub/web only)

- New built-in app **Network** (`#/network`, sidebar under Run/Integrate group as fits, Portals, Ctrl K): devices list
  (kind/vendor icons, connection and snapshot state, drift and backup badges, write capability + rollback mode),
  device page with tabs Rules (read-only table; untrusted text via `html`/`textContent`), Interfaces & zones, History
  (snapshot revisions, diff between two revisions with `diffView`), Drift (acknowledge; accept as baseline for
  admins), Backups (take now, list; download admin; "Restore..." opens a restore proposal), Changes (lifecycle chips,
  countdown during verifying, links to approvals). Empty states that explain how to connect a device and that changes
  are off by default.
- Settings: "Network changes" card - guardrail toggles (device_changes, second person, maintenance window, backup,
  approval expiry hours) with the confirmation-with-risk pattern; maintenance windows editor (admin).
- Approvals: kind `firewall` card per canvas-design section 8 (diff, violations banner, proposer, justification,
  window/scheduled info, expiry countdown); hide Approve for the proposer and for non-admins (server enforces).
- `ui.js`: `modal({onClose})` and focus return to the opener on close (review-notes F14) - global fix.

## R3-CANVAS-BE: canvas backend (Python)

canvas-design A2, A3 and section 7.1-7.4: `hub/integration/canvas.py`, `GET /api/integration/map`, `GET
/api/integration/map/options`, layouts (`/api/layouts/{view}`, SSE `canvas_layout`), `POST /api/flows` with the loop
rule (409 `flow_conflict`, also on PATCH enable; review-notes F7), planner helpers shared by `proposals()` and
`connect_options()`. Review-notes F24: viewer payloads of `/api/integration` and the map never carry webhook URLs,
connection config or toolbus event payloads (walk the JSON in tests). Include the People app and the Network app as
spine nodes where meaningful.

## R3-CANVAS-UI: the visual management panel (hub/web only; two sequential agents)

- **Agent 1 - engine + Integration map**: canvas-design A1 (shell changes; the `modal({onClose})` part may already
  exist from R3-NETUI - reuse), A4 (pure JS modules + `node --test` tests in `tests/js/` + `tests/test_js.py` runner
  that skips without node), A5, A6, A7, A8 for the Integration map (tabs Overview | Map | Segmentation).
- **Agent 2 - Segmentation map**: B3 and the UI half of B4 (Change panel with live preview, ghost edges, lifecycle
  chips, verifying banner), accessibility per section 9, List views, empty/stale states, deep links.

## R3-DOCS

`docs/NETWORK.md` (devices, connectors per vendor with what is verified/unverified, least-privilege setup per vendor
incl. sudoers lines, read model, drift, backups, the change safety model S1-S16 + maintenance windows + backups,
guardrails), `docs/COMPLIANCE.md` (frameworks: CyFun 2025/2023, levels, key measures, maturity, conformity rules and
their source, audit pack, CISO Assistant sync, CRA via sync, all HB controls with refs), canvas usage in
`docs/INTEGRATIONS.md`, README features/safety/roadmap/layout, ARCHITECTURE (components, agents, endpoints, SSE events).
