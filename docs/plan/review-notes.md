# Issues found by the round-3 design critique in EXISTING code (fix in the review phase)

- F1 (critical): the same person can propose and approve. Approvals.decide never compares decider with requester;
  POST /api/approvals/{id} needs only operator. Firewall/device changes need a two-person rule (toggle).
- F3 (critical): ToolSupervisor.on_connector_action runs any connector action for any bus sender - side-effecting
  actions (e.g. OpenVAS "scan") can bypass the scan approval. Route side-effecting actions through approvals.
- F4 (high): design-level - rollback of an applied change must itself be an approved change.
- F2 (critical, design): approvals must bind to the exact revision they approved and expire.
- F7 (high): connect panel / API could create pull and push of the same domain for the same tool (loop) - the
  planner avoids it; any new POST /api/flows must enforce the same rule.
- F14: ui.js modal() never returns focus to the opener on close.
- F24: viewer payloads of /api/integration carry raw webhook URLs (may contain tokens); toolbus log entries carry
  event payloads to viewers.

# Corrections to what I told the user
- CyFun current edition is CyFun 2025 (1 Oct 2025), based on NIST CSF 2.0 (IDs like PR.AA-01.1, ID.AM-08.2);
  CyFun 2023 (CSF 1.1 IDs) coexists until 18 April 2027. Levels are tags B/I/E with key measures BK/IK/EK; maturity
  1-5, target 3.0. CCB site refused automated fetches (403): CyFun facts come from CISO Assistant's library copy.
- OPNsense removed the native savepoint/cancelRollback auto-rollback in 26.7 (2026-07); Atrium must do backup +
  restore itself on current versions. pfSense CE has no official API (SSH + config.xml); pfSense Plus has the
  Nexus/MIM API. MikroTik REST has no safe mode.
