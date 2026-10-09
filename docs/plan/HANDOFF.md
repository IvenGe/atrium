# Work in progress - handoff

Branch: `feature/login-sso-integrations-agent-teams`. `main` already has the hub and the built-in login (PR #1).
This folder holds the plan for the work that is not finished yet. Remove `docs/plan/` before the final merge
(the research in `docs/research/` can stay as reference documentation).

## State of round 2 (this commit)

| Step | Status |
|---|---|
| SSO to the selected identity provider (identity.py, sso_catalog.py, sso_connect / sso_code / sso_proxy strategies, UI) | done |
| Installer (install.ps1, install.sh, Dockerfile, docker-compose.yml, scripts/install_copy.py, tests/test_installer.py) | done |
| Integration fabric core (secrets.py, connectors SDK + generic REST, connections, flows, strategies, repair loop, Vulnerabilities app + module:vulns, HB-VM-2/3) | done |
| Snipe-IT, CISO Assistant, OpenVAS connectors; fabric UI (Connection tab, Data flows, Vulnerabilities app, scan scope) | done |
| Agent teams BACKEND (toolkit.py, custom.py, teams.py, llm_providers.py, guardrails, HB-AC-6) | **interrupted part-way** - the suite was green (464 passed) when it stopped; review what exists against TEAMS_SPEC and finish it |
| Agent teams UI | not started |
| People + Sign-in & SSO settings (backend, UI) | not started |
| Extensions and self-patching (backend, UI) | not started |
| Docs for round 2 | not started |

The exact specifications for every remaining step are the `*_SPEC` strings in `round2-workflow.js` (it is the workflow
script that was running). Its CONTEXT block was written for the original Windows machine: on another machine use the
local virtualenv/python and the repository path you have, and ignore the notes about `.hub-dev/` and port 8710.

## After round 2

1. Tests green, commit, push, open PR #2 into `main` and merge it (the user asked for this).
2. Round 3, using `docs/research/` as the source of truth:
   - Compliance frameworks: CyFun 2025 (NIST CSF 2.0 IDs) and CyFun 2023 built in (assurance levels as tags B/I/E,
     key measures BK/IK/EK, maturity 1-5, target 3.0), audit-pack export; framework sync with CISO Assistant
     (frameworks, compliance assessments, requirement assessments, mapping sets) - see `cyfun-cra-ciso.md`.
   - Network & devices read-only: OPNsense, pfSense (CE via SSH/config.xml, Plus via its API), MikroTik, FortiGate,
     PAN-OS, Cisco IOS-XE, Linux nftables/ufw/firewalld, Windows Defender Firewall - see the three `fw-*.md` files.
     Network app, drift detection, compliance evidence.
   - Network changes (guardrail OFF by default): Atrium-managed backup + automatic restore (OPNsense 26.7 removed its
     native savepoint rollback), two-person approval, approval bound to the exact revision with expiry, maintenance
     windows, the management rule protected.
   - Visual management panel: integration canvas (drag to connect -> proposed flow) and segmentation canvas (zones,
     assets by IP, allowed traffic aggregated per interface, compliance and vulnerability overlays) - implement the
     corrected design in `canvas-design.md`.
3. Adversarial review of everything (security, permissions, connectors, OIDC, UI, installer), including the issues
   already found in `review-notes.md`; fix, re-test.
4. Browser test of the whole app, screenshots into `docs/screenshots/`, README with the screenshots.
5. Commit, push, PR, merge into `main`.
