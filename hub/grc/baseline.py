"""The Hub Security Baseline: a compact control set the hub can verify on its own.

Each control maps to clause/control identifiers of common frameworks so one
piece of evidence counts everywhere. Descriptions are written for this project;
consult the official framework texts for the authoritative requirements.
"""

from __future__ import annotations

from dataclasses import dataclass, field

FRAMEWORKS = {
    "ISO27001": "ISO/IEC 27001:2022",
    "SOC2": "SOC 2 (Trust Services Criteria)",
    "NIS2": "NIS2 Directive, Art. 21",
    "CyFun2025": "CyberFundamentals 2025 (CCB)",
    "CyFun2023": "CyberFundamentals 2023 (CCB)",
}
# CyFun refs: requirement ids of the CCB CyberFundamentals (hub/grc/frameworks/). ANALYST JUDGEMENT, not CCB guidance:
# the CyFun2025 ids per control are the primary and supporting rows of docs/research/cyfun-cra-ciso.md section 2
# (ids and level tags checked against the CISO Assistant library copy; the fit of each row - primary, supporting,
# weak - is in hub/grc/frameworks/mapping.py); the CyFun2023 ids are derived from them through CISO Assistant's
# CyFun 2023 - 2025 mapping library. tests/test_frameworks.py keeps these strings equal to mapping.refs_text().


@dataclass(frozen=True)
class Control:
    id: str
    family: str
    title: str
    description: str
    check: str | None  # automated check key, None = manual
    refs: dict[str, str] = field(default_factory=dict)
    risk: tuple[str, int, int] | None = None  # (risk title, likelihood, impact) raised when the control fails


CONTROLS: list[Control] = [
    Control("HB-AM-1", "Asset management", "Asset inventory is complete",
            "Every server, tool and SaaS service the organisation relies on is recorded in the asset register.",
            "assets_inventory", {"ISO27001": "A.5.9", "SOC2": "CC6.1", "NIS2": "21(2)(i)",
                                 "CyFun2025": "ID.AM-01.1 / ID.AM-02.1 / ID.AM-01.2 / ID.AM-02.2",
                                 "CyFun2023": "ID.AM-1.1 / ID.AM-1.2 / ID.AM-2.1"},
            ("Unknown assets are not protected or monitored", 3, 3)),
    Control("HB-AM-2", "Asset management", "Assets have owners and a criticality",
            "Each active asset has an accountable owner and a business criticality rating.",
            "assets_owned", {"ISO27001": "A.5.9", "SOC2": "CC6.1",
                             "CyFun2025": "ID.AM-05.1 / ID.AM-02.3 / ID.AM-01.2",
                             "CyFun2023": "ID.AM-1.2 / ID.AM-2.3 / ID.AM-5.1"},
            ("Assets without owners are not maintained", 3, 2)),
    Control("HB-AC-1", "Access control", "Central identity and single sign-on",
            "Tools authenticate users through the suite's identity provider (OIDC, SAML or LDAP) instead of local accounts.",
            "tools_sso", {"ISO27001": "A.5.16 / A.8.5", "SOC2": "CC6.1 / CC6.2", "NIS2": "21(2)(i) / 21(2)(j)",
                          "CyFun2025": "PR.AA-01.1 / PR.AA-05.5 / PR.AA-01.2 / PR.AA-02.2",
                          "CyFun2023": "PR.AC-1.1"},
            ("Local accounts in tools escape joiner/mover/leaver control", 4, 4)),
    Control("HB-AC-2", "Access control", "Privileged agent actions are approved",
            "State-changing commands and code patches made by AI agents require human approval.",
            "agent_approvals", {"ISO27001": "A.8.2 / A.8.32", "SOC2": "CC8.1",
                                "CyFun2025": "PR.AA-05.7 / PR.AA-05.6 / PR.PS-06.2 / PR.AA-05.3",
                                "CyFun2023": "PR.AC-4.6 / PR.AC-4.7"},
            ("AI agents can change systems without human review", 3, 5)),
    Control("HB-AC-3", "Access control", "Hardened remote access",
            "Remote hosts are reached over SSH with key-based authentication and verified host keys.",
            "ssh_hardening", {"ISO27001": "A.8.5 / A.8.20", "SOC2": "CC6.6", "NIS2": "21(2)(i)",
                              "CyFun2025": "PR.AA-03.3 / ID.AM-08.12 / PR.AA-01.4 / PR.AA-03.5 / PR.DS-02.2",
                              "CyFun2023": "PR.AC-3.3 / PR.AC-3.5"},
            ("Remote sessions are open to interception or password guessing", 2, 4)),
    Control("HB-AC-4", "Access control", "Authenticated, role-based access to the hub",
            "People sign in to the hub and get the least role they need (viewer, operator or admin); "
            "single sign-on through the suite's identity provider enforces MFA.",
            "hub_auth", {"ISO27001": "A.5.15 / A.8.5", "SOC2": "CC6.1", "NIS2": "21(2)(i) / 21(2)(j)",
                         "CyFun2025": "PR.AA-01.1 / PR.AA-05.1 / PR.AA-05.3 / PR.AA-05.4 / PR.AA-03.2",
                         "CyFun2023": "PR.AC-1.1 / PR.AC-4.1 / PR.AC-4.3 / PR.AC-4.4"},
            ("Hub accounts are protected by passwords only", 2, 4)),
    Control("HB-AC-5", "Access control", "Dormant hub accounts are disabled",
            "Accounts that have not signed in for 90 days are reviewed and disabled.",
            "dormant_accounts", {"ISO27001": "A.5.18", "SOC2": "CC6.2", "NIS2": "21(2)(i)",
                                 "CyFun2025": "PR.AA-01.3 / PR.AA-05.1",
                                 "CyFun2023": "PR.AC-1.3"},
            ("Dormant accounts could be misused", 2, 3)),
    Control("HB-AC-6", "Access control", "AI agent guardrails are enforced",
            "Catastrophic commands are blocked, team agents' actions follow the approval policy, team agents never "
            "hold more permissions than the agent that created them, and agent teams are bounded in size and depth.",
            "agent_guardrails", {"ISO27001": "A.8.2 / A.8.32", "SOC2": "CC6.1 / CC8.1", "NIS2": "21(2)(i)",
                                 "CyFun2025": "ID.RA-01.5 / ID.RA-01.4 / PR.AA-05.7",
                                 "CyFun2023": "DE.CM-8.1 / ID.RA-1.3 / PR.AC-4.7"},
            ("AI agents operate without guardrails", 3, 5)),
    Control("HB-AC-7", "Access control", "Leavers lose access and return assets",
            "People who left or are suspended have no enabled Atrium account and no active account in the tools, and "
            "no longer own or use company assets.",
            "leavers", {"ISO27001": "A.5.18 / A.5.11", "SOC2": "CC6.2 / CC6.3", "NIS2": "21(2)(i)",
                        "CyFun2025": "GV.RR-04.2 / PR.AA-01.1 / PR.AA-05.1 / GV.SC-02.1",
                        "CyFun2023": "PR.AC-1.1 / PR.AT-3.2 / PR.IP-11.2"},
            ("Former staff keep access or company devices", 3, 4)),
    Control("HB-CM-1", "Configuration management", "Integration configuration as code",
            "Every tool's integration contract (hub manifest) is explicit and versioned.",
            "tools_manifest", {"ISO27001": "A.8.9", "SOC2": "CC7.1",
                               "CyFun2025": "PR.PS-01.1 / ID.AM-03.2",
                               "CyFun2023": "ID.AM-3.2 / PR.IP-1.1"}, None),
    Control("HB-CM-3", "Change management", "Network device changes are controlled",
            "Firewall and host-firewall changes need a second person, a configuration backup, and a maintenance "
            "window unless an administrator records an emergency. Turning those protections off is reflected here.",
            "network_change_management",
            {"ISO27001": "A.8.9 / A.8.32", "SOC2": "CC8.1", "NIS2": "21(2)(e)",
             "CyFun2025": "PR.PS-01.1", "CyFun2023": "PR.IP-3.1"},
            ("An unreviewed firewall change opens the network", 3, 4)),
    Control("HB-CM-2", "Change management", "Changes to tools are reviewed",
            "Patches to tools are proposed on branches or adapters and applied only after review; changes to Atrium "
            "itself - generated extension packs and self-patches of its code - are reviewed too, and its code only "
            "after its tests passed.",
            "patch_review", {"ISO27001": "A.8.32", "SOC2": "CC8.1", "NIS2": "21(2)(e)",
                             "CyFun2025": "PR.PS-06.2 / PR.PS-06.4 / PR.PS-01.5 / ID.AM-08.10",
                             "CyFun2023": "DE.CM-7.2 / PR.IP-3.1 / PR.IP-3.2 / PR.MA-1.7"}, None),
    Control("HB-OP-1", "Operations", "Health monitoring for every tool",
            "Each integrated tool exposes a health check the hub monitors.",
            "tools_health", {"ISO27001": "A.8.16", "SOC2": "CC7.2", "NIS2": "21(2)(b)",
                             "CyFun2025": "PR.IR-04.1",
                             "CyFun2023": "PR.DS-4.1"},
            ("Outages go unnoticed until users report them", 3, 3)),
    Control("HB-OP-2", "Operations", "Audit trail of agent and operator activity",
            "All agent messages, commands and decisions are logged and retained.",
            "audit_log", {"ISO27001": "A.8.15", "SOC2": "CC7.2", "NIS2": "21(2)(f)",
                          "CyFun2025": "PR.PS-04.1 / PR.AA-05.7 / PR.PS-04.3 / PR.PS-04.2 / DE.AE-03.1",
                          "CyFun2023": "PR.AC-4.7 / PR.DS-4.2 / PR.PT-1.1 / PR.PT-1.2"}, None),
    Control("HB-VM-1", "Vulnerability management", "Software inventory with versions",
            "Each tool's version is known so vulnerabilities can be matched against it.",
            "software_versions", {"ISO27001": "A.8.8", "SOC2": "CC7.1", "NIS2": "21(2)(e)",
                                  "CyFun2025": "ID.AM-02.1 / ID.AM-08.2 / PR.PS-02.1",
                                  "CyFun2023": "ID.AM-2.1 / PR.MA-1.1"},
            ("Vulnerable versions cannot be identified", 3, 4)),
    Control("HB-VM-2", "Vulnerability management", "In-scope assets are scanned for vulnerabilities",
            "Every asset in vulnerability-scan scope is scanned at least every 30 days.",
            "scan_coverage", {"ISO27001": "A.8.8", "SOC2": "CC7.1", "NIS2": "21(2)(e)",
                              "CyFun2025": "ID.RA-01.1 / ID.RA-01.2 / ID.RA-01.6 / ID.RA-01.5 / ID.IM-03.9",
                              "CyFun2023": "DE.DP-5.2 / ID.RA-1.1 / ID.RA-1.2"},
            ("Vulnerabilities on unscanned assets go unnoticed", 3, 4)),
    Control("HB-VM-3", "Vulnerability management", "Critical and high vulnerabilities are fixed within SLA",
            "Open critical and high findings are fixed (or formally accepted) before their remediation deadline.",
            "vuln_sla", {"ISO27001": "A.8.8", "SOC2": "CC7.1", "NIS2": "21(2)(e)",
                         "CyFun2025": "ID.AM-08.2 / ID.RA-01.3 / ID.RA-06.1 / ID.RA-08.1 / ID.RA-08.2",
                         "CyFun2023": "PR.IP-12.1 / PR.MA-1.1"},
            ("Known critical vulnerabilities remain exploitable", 4, 5)),
    # Network security: evidence from the firewalls' and network devices' snapshots (hub/integration/network.py,
    # segmentation.py). UNVERIFIED: these reference strings (ISO/IEC 27001:2022 Annex A, SOC 2, NIS2 Art. 21(2), CIR
    # (EU) 2024/2690 Annex 6.8, CyFun 2025 ids from the CISO Assistant library copy) are analyst mappings that were
    # not checked against the licensed / official texts.
    Control("HB-NW-1", "Network security", "Network segmentation follows the policy",
            "Firewall rules allow traffic between zones only where the segmentation policy does: untrusted zones do "
            "not reach management, internet traffic ends in a DMZ, guest and IoT networks are isolated, development is "
            "separated from production (CIR (EU) 2024/2690 Annex 6.8 network segmentation). Evaluated approximately "
            "from the firewalls' rules.",
            "network_segmentation", {"ISO27001": "A.8.22 / A.8.20", "SOC2": "CC6.6", "NIS2": "21(2)(e)",
                                     "CyFun2025": "PR.IR-01.2 / PR.IR-01.3 / PR.IR-01.8 / ID.AM-03.2",
                                     "CyFun2023": "ID.AM-3.2"},
            ("Attackers can move freely between network zones", 3, 4)),
    Control("HB-NW-2", "Network security", "Device configuration changes are explained",
            "Firewall and network device configurations change through approved changes; changes made elsewhere "
            "(drift) are reviewed and acknowledged, against an approved baseline configuration.",
            "network_drift", {"ISO27001": "A.8.9 / A.8.32", "SOC2": "CC7.1 / CC8.1", "NIS2": "21(2)(e)",
                              "CyFun2025": "PR.PS-01.1 / PR.PS-01.5", "CyFun2023": "DE.CM-7.2 / PR.IP-1.1"},
            ("Unreviewed firewall changes open the network", 3, 4)),
    Control("HB-NW-3", "Network security", "Device management is not exposed to the internet",
            "No firewall rule lets traffic from anywhere (any source on a WAN interface, or a floating rule) reach a "
            "network device's own management services.",
            "network_management", {"ISO27001": "A.8.20", "SOC2": "CC6.6", "NIS2": "21(2)(i)",
                                   "CyFun2025": "PR.IR-01.4 / PR.PS-01.3", "CyFun2023": "PR.AC-5.4 / PR.PT-3.2"},
            ("Device management is reachable from the internet", 3, 5)),
    Control("HB-NW-4", "Network security", "Device configurations are backed up",
            "Every firewall and network device has a configuration backup from the last 7 days, stored encrypted and "
            "verified by its SHA-256.",
            "network_backups", {"ISO27001": "A.8.13", "SOC2": "A1.2", "NIS2": "21(2)(c)", "CyFun2025": "PR.DS-11.1",
                                "CyFun2023": "PR.IP-4.1"},
            ("A failed device cannot be restored to a known configuration", 2, 4)),
    Control("HB-NW-5", "Network security", "Firewall rules are least-privilege and documented",
            "No pass rule allows any source to reach any destination on any service, and every pass rule says what it "
            "is for.",
            "network_rules", {"ISO27001": "A.8.20 / A.8.22", "SOC2": "CC6.6", "NIS2": "21(2)(e)",
                              "CyFun2025": "PR.IR-01.1 / PR.IR-01.8 / PR.PS-01.3", "CyFun2023": "PR.PT-3.2"},
            ("Overly broad firewall rules expose systems", 3, 4)),
    Control("HB-SC-1", "Supplier management", "SaaS and supplier inventory",
            "Every SaaS service is registered as an asset with an owner responsible for the supplier relationship.",
            "saas_inventory", {"ISO27001": "A.5.19 / A.5.23", "SOC2": "CC9.2", "NIS2": "21(2)(d)",
                               "CyFun2025": "ID.AM-04.1 / GV.SC-07.2 / GV.OC-05.1",
                               "CyFun2023": "ID.AM-4.1 / ID.SC-2.2"},
            ("Unmanaged SaaS suppliers hold company data", 3, 4)),
    Control("HB-RM-1", "Risk management", "Risk register maintained",
            "Risks are recorded, scored and reviewed at least every 90 days.",
            "risk_review", {"ISO27001": "6.1.2 / 8.2", "SOC2": "CC3.2", "NIS2": "21(2)(a)",
                            "CyFun2025": "ID.RA-05.1 / GV.RM-03.2 / GV.RM-03.1 / ID.RA-05.2 / ID.RA-06.1",
                            "CyFun2023": "ID.GV-4.1 / ID.GV-4.2 / ID.RA-5.1 / ID.RA-5.2"}, None),
    Control("HB-PO-1", "Governance", "Information security policy approved",
            "An information security policy is approved and assigned an owner.",
            "policy:security", {"ISO27001": "A.5.1", "SOC2": "CC5.3", "NIS2": "21(2)(a)",
                                "CyFun2025": "GV.PO-01.1 / GV.PO-01.2",
                                "CyFun2023": "ID.GV-1.1"},
            ("Security expectations are undefined", 2, 3)),
    Control("HB-PO-2", "Governance", "Access control policy approved",
            "Rules for granting, reviewing and revoking access are approved.",
            "policy:access", {"ISO27001": "A.5.15", "SOC2": "CC6.2", "NIS2": "21(2)(i)",
                              "CyFun2025": "GV.PO-01.1 / PR.AA-05.1 / PR.AA-05.2",
                              "CyFun2023": "ID.GV-1.1 / PR.AC-4.1 / PR.AC-4.2"}, None),
    # UNVERIFIED: analyst mapping (ISO/IEC 27001:2022 clause 9.1 and A.5.36, SOC 2 CC4.1, NIS2 Art. 21(2)(f), CyFun 2025
    # GV.OV-03.1); not checked against the licensed / official texts. CyFun 2023 has no equivalent (GV is new in CSF 2.0).
    Control("HB-PO-3", "Governance", "Compliance framework self-assessment is current",
            "The organisation assesses itself against a compliance framework (CyberFundamentals 2025 or 2023) at least "
            "every 12 months, and the key measures of its target level reach their thresholds. Scores are people's "
            "judgement; the hub only checks that the assessment is current and what it says about key measures.",
            "framework_assessment", {"ISO27001": "9.1 / A.5.36", "SOC2": "CC4.1", "NIS2": "21(2)(f)",
                                     "CyFun2025": "GV.OV-03.1"},
            ("Compliance gaps go unnoticed until an external assessment", 2, 3)),
    Control("HB-IR-1", "Incident management", "Incident response plan",
            "An approved plan describes how incidents are detected, escalated, handled and reported.",
            "policy:incident", {"ISO27001": "A.5.24", "SOC2": "CC7.4", "NIS2": "21(2)(b)",
                                "CyFun2025": "RS.MA-01.1 / ID.IM-04.1 / RS.CO-02.2 / DE.AE-08.1 / RS.CO-02.1 / "
                                             "ID.IM-03.1",
                                "CyFun2023": "PR.IP-9.1 / RS.CO-3.1 / RS.CO-3.2 / RS.IM-1.1 / RS.RP-1.1"},
            ("Incidents are handled ad hoc and reporting deadlines are missed", 3, 4)),
    Control("HB-BC-1", "Business continuity", "Backup and recovery policy",
            "Backups of critical tools and data are defined, protected and restore-tested.",
            "policy:backup", {"ISO27001": "A.8.13", "SOC2": "A1.2", "NIS2": "21(2)(c)",
                              "CyFun2025": "PR.DS-11.1 / PR.DS-11.2 / PR.DS-11.3 / PR.DS-11.4 / RC.RP-01.1 / "
                                           "RC.RP-05.1",
                              "CyFun2023": "PR.IP-4.1 / PR.IP-4.2 / PR.IP-4.3 / RC.RP-1.1"},
            ("Data loss cannot be recovered from", 2, 5)),
]

CONTROLS_BY_ID = {c.id: c for c in CONTROLS}

POLICY_TEMPLATES: dict[str, dict[str, str]] = {
    "security": {
        "title": "Information Security Policy",
        "body": (
            "# Information Security Policy\n\n"
            "## Purpose\nProtect the confidentiality, integrity and availability of the information and tools the "
            "organisation runs through the hub.\n\n"
            "## Scope\nAll tools, hosts, SaaS services and people with access to them.\n\n"
            "## Principles\n- Every asset has an owner.\n- Access goes through the central identity provider.\n"
            "- Changes are reviewed before they reach production; AI agent actions follow the same rule.\n"
            "- Activity is logged and logs are retained.\n\n"
            "## Responsibilities\nThe policy owner reviews this policy at least yearly.\n"
        ),
    },
    "access": {
        "title": "Access Control Policy",
        "body": (
            "# Access Control Policy\n\n"
            "- Access is granted on least privilege and requested through a ticket.\n"
            "- Tools use single sign-on; local accounts are exceptions with an owner and an expiry.\n"
            "- Privileged access is reviewed quarterly and removed within one working day of a leaver.\n"
            "- SSH access uses keys; passwords are disabled.\n"
        ),
    },
    "incident": {
        "title": "Incident Response Plan",
        "body": (
            "# Incident Response Plan\n\n"
            "1. **Detect** - alerts from hub health checks, monitoring and user reports.\n"
            "2. **Triage** - classify severity; open an incident record.\n"
            "3. **Contain and eradicate** - isolate affected tools; agents act only with approval.\n"
            "4. **Recover** - restore from backup, verify health.\n"
            "5. **Report** - notify authorities and customers within the deadlines that apply to you.\n"
            "6. **Learn** - hold a review and record new risks.\n"
        ),
    },
    "backup": {
        "title": "Backup and Recovery Policy",
        "body": (
            "# Backup and Recovery Policy\n\n"
            "- Critical tools and their data are backed up daily; backups are encrypted and kept off-site.\n"
            "- Retention: 30 daily, 12 monthly.\n"
            "- A restore test is performed and recorded every quarter.\n"
        ),
    },
    "acceptable-use": {
        "title": "Acceptable Use Policy",
        "body": (
            "# Acceptable Use Policy\n\n"
            "- Use company tools for business purposes and keep credentials private.\n"
            "- Do not install unapproved software or connect unapproved SaaS services; import them through the hub.\n"
            "- Report suspected incidents immediately.\n"
        ),
    },
    "supplier": {
        "title": "Supplier Security Policy",
        "body": (
            "# Supplier Security Policy\n\n"
            "- Every SaaS supplier is registered in the hub with an owner.\n"
            "- Suppliers handling personal or confidential data are assessed before onboarding and yearly after.\n"
            "- Contracts include security, breach-notification and exit clauses.\n"
        ),
    },
}
