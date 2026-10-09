# CyFun 2025, CRA and CISO Assistant: reference for Atrium

Research date: 2026-10-09. Read-only research; no repository files were changed.

## Verification labels

| Label | Meaning |
|---|---|
| **V-off** | Seen on an official public-authority page: BELAC/FPS Economy, the European Commission, ENISA, NCSC Ireland, or EUR-Lex text shown in search results. |
| **V-lib** | Seen in the CyFun library that ships with CISO Assistant (`backend/library/libraries/cyfun2025.yaml`, library `version: 10`, `publication_date: 2026-10-05`, `provider: CCB`, `packager: intuitem`). This is a machine-readable copy of the CCB text, not the CCB's own file. |
| **V-src** | Seen in the CISO Assistant community source code on GitHub, `main` branch, read on 2026-10-09. |
| **U** | Unverified: secondary source (law firm, certification body, vendor), memory, or my own inference. |

**Access limits.** Every CCB host refused the fetcher with HTTP 403: `ccb.belgium.be`, `atwork.safeonweb.be`, `cyfun.eu`, `cyfun.be`, and the booklet PDF `https://cyfun.eu/sites/default/files/2026-03/CyFun2025_Booklet_ESSENTIAL_E.pdf`. EUR-Lex returned empty pages. So:
- No CyFun fact below was read from a CCB document. Level, key-measure and threshold data come from the CISO Assistant library (V-lib).
- CRA facts come from Commission and ENISA pages (V-off), plus EUR-Lex text shown in search results.

---

## 1. CyberFundamentals (CyFun)

### 1.1 Current edition and transition
- **The current edition is CyFun®2025**, which the CCB published on **1 October 2025**. The previous edition, dated 1 March 2023, is called **CyFun®2023**. Documentation for both editions is on www.cyfun.eu. [V-off, BELAC news item of 10.12.2025]
- **Both editions coexist until 18 April 2027.** [V-off, BELAC]
  - Entities may choose which edition to apply until then.
  - Verification and certification bodies may run CyFun®2023 assessments until 18 April 2027 at the latest.
  - CyFun®2023 statements and certificates stay valid until 18 April 2028 at the latest.
  - Bodies must hold accreditation for CyFun®2025 by 18 April 2027.
- **The Conformity Assessment Scheme (CAS) and its Clarifications are at version 2025-11-26.** That version replaced 2025-03-07 and applies to both editions. [V-off, BELAC]
- **CyFun 2025 is based on NIST CSF 2.0; CyFun 2023 was based on NIST CSF 1.1.** [V-off, NCSC Ireland CyFun FAQ, updated 23/6/2025] The library description also lists NIST CSF, ISO/IEC 27001/27002, IEC 62443 and the CIS Controls as underlying sources. [V-lib]
- **What changed in 2025** [U, CCB news page known only from search snippets; the page returned 403]:
  - more focus on the supply chain and on OT;
  - clearer, more auditable controls;
  - governance measures starting at the Important level.

### 1.2 Structure and requirement IDs (CyFun 2025) [V-lib]
- **The tree has four depths:**
  - depth 1: function, e.g. `GV` (GOVERN), `ID`, `PR`, `DE`, `RS`, `RC`;
  - depth 2: category, e.g. `GV.OC`;
  - depth 3: NIST CSF 2.0 subcategory, e.g. `GV.OC-01`;
  - depth 4: assessable CyFun requirement, e.g. `GV.OC-01.1`.
- **Requirement ID = CSF 2.0 subcategory ID + `.n`**, for example `PR.AA-01.1` or `ID.AM-08.2`.
- **Numbering has gaps.** For example, `ID.AM-08` starts at `.2` and `ID.AM-03` starts at `.2`.
- **Some CSF 2.0 subcategories are not in CyFun 2025 at all.** The framework tree and the CyFun 2025 to ISO 27001 mapping both skip from GV.SC-03 to GV.SC-05, from ID.RA-06 to ID.RA-08, and stop GV.PO at GV.PO-01. Absent:
  - `GV.SC-04` (suppliers prioritised by criticality);
  - `ID.RA-07` (change management);
  - `GV.PO-02`;
  - `ID.AM-08.1`.
- **Assurance levels are tags on each requirement, not part of the ID.** The tag field is `implementation_groups`:
  - `B` basic, `I` important, `E` essential;
  - `BK` / `IK` / `EK` mark **key measures** at each level;
  - `BG` / `IG` / `EG` mark **management aspects** (governance) at each level.
- **Levels are cumulative.** Every requirement tagged `B` is also tagged `I` and `E`, and a Basic key measure carries `BK, IK, EK`.
- **There is also a "Small" self-assessment level.** CISO Assistant ships `cyfun-small-self-assessment_new.yaml` for it [V-src, file list]. NCSC Ireland names three assurance levels: Basic, Important and Essential [V-off].
- **CyFun 2023 for comparison** (`ccb-cff-2023-03-01.yaml`, library version 8) [V-lib]:
  - IDs follow CSF 1.1 (`ID.AM-1.1`);
  - CISO Assistant prefixes them with the level, e.g. `BASIC_ID.AM-1.1` or `IMPORTANT_ID.AM-1.2`;
  - key measures carry `[KEY MEASURE]` in the description plus `BK`/`IK`/`EK` tags;
  - only six groups exist: B/I/E/BK/IK/EK, with no management-aspect groups.

### 1.3 Maturity scoring (CyFun 2025) [V-lib]
- **Scale:** `min_score 1`, `max_score 5`, `target_score 3.0`, `score_calculation_method: average_of_averages`, `anchor_na_to_target: true`, `score_scale_locked: true`.
- **Two dimensions are scored per requirement.** Each score level has a `description` for implementation and a `description_doc` for documentation.

  | Score | Name | Documentation / implementation (paraphrased) |
  |---|---|---|
  | 1 | Initial | No standard process; documentation missing or not approved. |
  | 2 | Repeatable | Process is informal and ad hoc; approved documentation is more than two years old. |
  | 3 | Defined | Formal, implemented process with evidence for most activities. Documented, approved exceptions under 5%; process exceptions under 10%. |
  | 4 | Managed | Evidence for all activities; metrics with minimum targets; exceptions under 3%. |
  | 5 | Optimizing | As level 4, with continually improving targets; exceptions under 0.5%. |

- **How CISO Assistant combines the two dimensions.** A requirement's maturity is the average of the enabled layers (implementation `score` and `documentation_score`). [V-src, `ComplianceAssessment.get_global_score` docstring in `backend/core/models.py`]
- That the CCB's method uses the same averaging is **U**. I could not reach the CCB scoring guide.

- **Group target scores:** B, BK and BG = 2.5. I, IK, IG, E, EK and EG = 3.0.

**Conformity rules per level.** These are the library's `outcomes_definition` expressions; `groups[...]` is computed over the requirements tagged with that group. [V-lib; the CCB original is **U**]

| Level | Overall maturity | Key measures | Other | Exclusions (N/A) allowed |
|---|---|---|---|---|
| Basic | `groups["B"].maturity_score >= 2.5` | `groups["BK"].min_maturity_score >= 2.5` (every Basic key measure) | - | At most 1 in B; 0 in BK |
| Important | `groups["I"].maturity_score >= 3.0` | `groups["IK"].min_maturity_score >= 3.0` | - | At most 3 in I; 0 in IK |
| Essential | `groups["E"].maturity_score >= 3.5` | `groups["EK"].min_maturity_score >= 3.0` | Every depth-2 category has maturity ≥ 3.0 | At most 5 in E; 0 in EK; 0 in EG |

### 1.4 Relation to the Belgian NIS2 law
- **BELAC drafted the CyFun transition with the CCB's national cybersecurity certification authority (NCCA).** It takes into account that CyFun is used to determine **presumption of conformity** with the Belgian NIS2 legislation. [V-off, BELAC]
- **Verification versus certification.** For Basic and Important, a body issues a *verification statement* of the self-assessment. Accredited verification bodies exist, e.g. Vinçotte's "Verifications CyFun (Basic – Important)" regulations of January 2026, which refer to the CAS published on www.cyfun.be and www.cyfun.eu. [U, certification body]
  - Essential leads to *certification*.
  - Bodies are accredited by BELAC and authorised by the CCB.
  - Brand Compliance reported its first BELAC accreditation for CyFun verification on 4 September 2025. [U]
- **The law and its decree.** The Law of 26 April 2024 was published in the Belgian Official Journal on 17 May 2024 and has been in force since 18 October 2024. The Royal Decree of 9 June 2024 adds detail. [U, law-firm summaries]
  - The decree makes the CCB the national authority.
  - It makes regular conformity assessment **mandatory for essential entities** and voluntary for others.
  - Accepted reference frameworks are **CyFun or ISO/IEC 27001**.
- **Routes for essential entities** [U]:
  - CyFun certification at Essential, or verification at Important or Basic, by a BELAC-accredited, CCB-approved body;
  - ISO/IEC 27001 certification;
  - inspection by the CCB.
- **Deadlines** [U]:
  - 18 April 2026: interim checkpoint;
  - 18 April 2027: conformity assessment due.
  - A reported CCB letter of 11 August 2026 says inspection will first check Important-level equivalence by 18 April 2027 and Essential by 18 April 2028. Vinçotte argues Article 22 of the Royal Decree still requires Essential by 2027.
  - **Treat these deadlines as unverified until checked against the Belgian Official Journal (Justel).**
- **Other countries.** NCSC Ireland says Ireland will adopt CyFun as its national NIS2 assessment and certification scheme and is a joint owner. It also says CyFun on its own does not prove NIS2 compliance. [V-off]

### 1.5 Licensing and reuse
- **No licence or terms-of-use statement was found** in the CyFun 2025 library description. Its `copyright` field is simply "Ⓒ Centre for Cybersecurity Belgium (CCB)". [V-lib]
- **The CyFun 2023 library copies the CCB's copyright notice:** texts, layouts and designs are subject to copyright law. [V-lib]
- **The CCB's announcement says the framework is free to use.** Its website disclaimer forbids reworking a substantial part of its pages without prior approval. [U, search snippets; pages returned 403]
- **Recommendation (inference):**
  - Store **requirement IDs plus short titles you write yourself**. Do not ship the CCB requirement text or annotations inside Atrium.
  - Link to cyfun.eu for the text.
  - Get written confirmation from the CCB before redistributing the text. CISO Assistant does redistribute it (EN/NL/FR), so tolerance is likely, but that is unconfirmed.

### 1.6 Where machine-readable versions are published
- **CCB:** Excel self-assessment tools and booklets are on www.cyfun.eu and on the Safeonweb@work CyberFundamentals page. File names and URLs could not be listed because of the 403s. The library cites `https://cyfun.eu/sites/default/files/2026-03/CyFun2025_Booklet_ESSENTIAL_E.pdf`. [V-lib]
- **CISO Assistant library files in `backend/library/libraries/`** [V-src]:

  | File | What it is |
  |---|---|
  | `cyfun2025.yaml` | Library URN `urn:intuitem:risk:library:ccb-cyfun2025`; framework URN `urn:intuitem:risk:framework:ccb-cyfun2025`. Includes NL/FR translations and one reference control per requirement. |
  | `ccb-cff-2023-03-01.yaml` | CyFun 2023. |
  | `cyfun-small-self-assessment_new.yaml` | Small level. |
  | `preset-belgian-cyfun.yaml` | Preset. |
  | `mapping-ccb-cff-2023-03-01-and-ccb-cyfun2025.yaml` | CyFun 2023 to 2025 mapping. |
  | `mapping-ccb-cyfun2025-and-iso27001-2022.yaml` | URN `urn:intuitem:risk:library:mapping-ccb-cyfun2025-and-iso27001-2022`, version 1, 2026-08-10; relationships seen were "intersect". |
  | `mapping-ccb-cff-2023-03-01-to-iso27001-2022.yaml` | CyFun 2023 to ISO 27001 mapping. |
  | `mapping-annex-technical-and-methodological-requirements-nis2-and-ccb-cff-2023-03-01.yaml` | NIS2 implementing regulation to CyFun 2023 mapping. |

- **Requirement-node URNs cannot always be derived from the ref_id.** The usual pattern is `urn:intuitem:risk:req_node:ccb-cyfun2025:<lower-case ref_id>`, but there are exceptions [V-lib]:
  - `ID.AM-03.2` has URN `…:id.am-03-2`;
  - `ID.AM-03.3` has URN `…:id.am-03-3`;
  - `ID.AM-08.10` has a URN reading `d.am-08.10`.
  - Always resolve ref_id to node through the framework tree (section 4.3).

---

## 2. Atrium controls mapped to CyFun 2025

**How to read the tables.**
- The ID, level and key-measure data in every row are **V-lib**, checked against `cyfun2025.yaml`.
- The *fit* column is my analyst judgement (**U**):
  - **P** = primary evidence;
  - **S** = supporting / partial;
  - **W** = weak (the control only touches part of the requirement).
- Levels are cumulative (B ⊂ I ⊂ E). "Key" names the key-measure tags.
- Descriptions are my paraphrases, not CCB text.

**Gaps in the baseline.** Atrium's `hub/grc/baseline.py` has no "guardrails" or "leavers" control yet:
- Guardrails exist only as `prefs["guardrails"]["scans_need_approval"]` in `hub/core.py:30` and `hub/agents/vulns.py`.
- Leavers appear only in policy template text.
- Those two rows below are proposals for new controls.

| Atrium control | CyFun 2025 req | Levels | Key | What the requirement covers (paraphrase) | Fit |
|---|---|---|---|---|---|
| HB-AM-1 Asset inventory | ID.AM-01.1 | B,I,E | - | Hardware/infrastructure inventory documented, reviewed, updated | P |
| | ID.AM-02.1 | B,I,E | - | Software, service and system inventory documented and updated | P |
| | ID.AM-01.2 / ID.AM-02.2 | I,E | - | Inventories reflect changes and hold accountability details | S |
| | ID.AM-01.3 / ID.AM-02.4 | I,E | - | Unauthorised hardware/software removed and inventory updated | W |
| HB-AM-2 Owners and criticality | ID.AM-05.1 | B,I,E | - | Assets prioritised by classification, criticality, business value | P |
| | ID.AM-02.3 | I,E | - | Named manager and accountable owner for software platforms | P |
| | ID.AM-01.2 | I,E | - | Accountability details in inventories | S |
| HB-AC-1 Central identity / SSO | PR.AA-01.1 | B,I,E | BK,IK,EK | Identities and credentials of users, services, hardware managed | P |
| | PR.AA-05.5 | I,E | - | Account management automated where feasible | S |
| | PR.AA-01.2 | I,E | - | Automated credential issuance/revocation; MFA for remote access | S |
| | PR.AA-02.2 | E | - | Unique credentials per user/device/process; controlled break-glass | S |
| HB-AC-2 Agent actions approved | PR.AA-05.7 | I,E | - | Privileged users managed, logged, overseen | P |
| | PR.AA-05.6 | I,E | - | Separation of duties for critical processes | S |
| | PR.PS-06.2 | I,E | - | Changes tested and validated before deployment | S |
| | PR.AA-05.3 | B,I,E | BK,IK,EK | Least privilege | S |
| | *(no AI-agent-specific CyFun requirement found)* | | | | |
| HB-AC-3 Hardened remote access (SSH) | PR.AA-03.3 | I,E | IK,EK | Remote access limits, secure connections, approvals for critical systems | P |
| | PR.AA-03.2 | B,I,E | BK,IK,EK | MFA for remote network access. SSH keys alone are not MFA. | W |
| | ID.AM-08.12 | I,E | - | Strong authentication for remote maintenance sessions; terminate them after use | S |
| | PR.AA-01.4 | E | - | Keys/certificates/tokens for critical-system transactions | S |
| | PR.AA-03.5 | E | - | External system connections verified (host-key verification fits) | S |
| | PR.DS-02.2 | E | - | Sensitive information protected in transit | S |
| HB-AC-4 Authenticated, role-based hub access | PR.AA-01.1 | B,I,E | BK,IK,EK | see above | P |
| | PR.AA-05.1 | B,I,E | BK,IK,EK | Permissions defined, administered, periodically reviewed | P |
| | PR.AA-05.3 | B,I,E | BK,IK,EK | Least privilege | P |
| | PR.AA-05.4 | B,I,E | BK,IK,EK | No routine work under admin accounts | S |
| | PR.AA-03.2 | B,I,E | BK,IK,EK | MFA for remote access (via SSO with MFA) | S |
| HB-AC-5 Dormant accounts disabled | PR.AA-01.3 | E | - | Credentials deactivated after a period of inactivity | P |
| | PR.AA-05.1 | B,I,E | BK,IK,EK | Periodic permission review | S |
| HB-CM-1 Integration configuration as code | PR.PS-01.1 | I,E | IK,EK | Approved baseline configurations maintained | S |
| | ID.AM-03.2 | I,E | - | Internal network/data flows mapped and authorised | S |
| | ID.AM-04.2 | E | - | Flows to and from external systems mapped and authorised | W |
| HB-CM-2 Changes to tools reviewed | PR.PS-06.2 | I,E | - | Changes/exceptions tested and validated before deployment | P |
| | PR.PS-06.4 | E | - | Security impact analysis of critical changes in a test environment | S |
| | PR.PS-01.5 | E | - | Unauthorised configuration changes detected and handled | S |
| | ID.AM-08.10 | E | EK | Protective measures re-checked after maintenance/patches | S |
| | *(CSF 2.0 ID.RA-07 change management: not in CyFun 2025)* | | | | |
| HB-OP-1 Health monitoring | DE.CM-09.1 | I,E | - | Logging enabled, reviewed, monitoring assigned | W |
| | PR.IR-04.1 | I,E | IG,EG | Capacity planning for critical systems | S |
| | PR.IR-03.1 | E | - | Resilience in normal and adverse conditions | W |
| HB-OP-2 Audit trail | PR.PS-04.1 | B,I,E | BK,IK,EK | Logs maintained, documented, monitored | P |
| | PR.AA-05.7 | I,E | - | Privileged actions logged | P |
| | PR.PS-04.3 | I,E | - | Audit data moved to a separate tamper-resistant system | S |
| | PR.PS-04.2 | I,E | - | Synchronised, trusted time source | S |
| | DE.AE-03.1 | B,I,E | BK,IK,EK | Protection tools keep and retain logs, which are reviewed | S |
| HB-VM-1 Software inventory with versions | ID.AM-02.1 | B,I,E | - | Software inventory | P |
| | ID.AM-08.2 | B,I,E | BK,IK,EK | Patches/security updates installed for OS and critical components | S |
| | PR.PS-02.1 | I,E | - | Software lifecycle managed by risk | S |
| HB-VM-2 In-scope assets scanned | ID.RA-01.1 | B,I,E | - | Vulnerabilities identified across software, networks, architectures | P |
| | ID.RA-01.2 | I,E | - | Continuous identification process for critical systems | P |
| | ID.RA-01.6 | I,E | - | Weaknesses managed across all relevant assets | S |
| | ID.RA-01.5 | I,E | - | Scanning must not degrade normal operation | S |
| | ID.IM-03.9 | E | EG | Specialised assessments incl. scanning | S |
| HB-VM-3 Critical/high fixed within SLA | ID.AM-08.2 | B,I,E | BK,IK,EK | Patches installed (timeliness) | P |
| | ID.RA-01.3 | I,E | - | Documented review/analysis/remediation process | P |
| | ID.RA-06.1 | I,E | IG,EG | Risk responses chosen, planned, tracked (formal acceptance) | S |
| | ID.RA-08.1 | I,E | IK,EK | Vulnerability-handling plan incl. coordinated disclosure | S |
| | ID.RA-08.2 | E | - | Automated tracking/reporting of remediation | S |
| HB-SC-1 SaaS and supplier inventory | ID.AM-04.1 | I,E | - | Inventory of external services and their connections | P |
| | GV.SC-07.2 | E | - | Current list of critical suppliers, available online and offline | P |
| | GV.OC-05.1 | I,E | - | Upstream/downstream dependencies documented | S |
| | GV.SC-07.1 | I,E | - | Supplier risk assessed yearly and on change | W |
| | *(CSF 2.0 GV.SC-04: not in CyFun 2025)* | | | | |
| HB-RM-1 Risk register maintained | ID.RA-05.1 | B,I,E | - | Risk derived from threats, vulnerabilities, impact | P |
| | GV.RM-03.2 | I,E | IG,EG | Cyber risks documented, approved, updated within enterprise risk management | P |
| | GV.RM-03.1 | B,I,E | - | Risk strategy developed and updated | S |
| | ID.RA-05.2 | I,E | IG,EG | Documented assessments including likelihood | S |
| | ID.RA-06.1 | I,E | IG,EG | Risk responses planned and tracked | S |
| | GV.OV-02.1 | E | - | Strategy reviewed at intervals and after incidents | W |
| HB-PO-1 Information security policy | GV.PO-01.1 | B,I,E | - | Policies documented, approved, updated, communicated, enforced | P |
| | GV.PO-01.2 | I,E | - | Organisation-wide policy set, change-tracked, senior approval | S |
| HB-PO-2 Access control policy | GV.PO-01.1 | B,I,E | - | as above | P |
| | PR.AA-05.1 | B,I,E | BK,IK,EK | Permissions defined and reviewed | P |
| | PR.AA-05.2 | B,I,E | BK,IK,EK | Who needs business-critical access, and how granted | S |
| | PR.AA-05.8 | E | - | Time/location account restrictions in the access policy | W |
| HB-IR-1 Incident response plan | RS.MA-01.1 | B,I,E | - | Plan with defined roles executed during events | P |
| | ID.IM-04.1 | I,E | IG,EG | Response/continuity plans established, tested, improved | P |
| | RS.CO-02.2 | I,E | IK,EK | External notification incl. authorities within plan deadlines | P |
| | DE.AE-08.1 | I,E | - | Incident declaration criteria | S |
| | RS.CO-02.1 | B,I,E | - | Internal incident communication | S |
| | ID.IM-03.1 | B,I,E | - | Post-incident lessons learned | S |
| HB-BC-1 Backup and recovery policy | PR.DS-11.1 | B,I,E | BK,IK,EK | Backups of critical data on a separate system | P |
| | PR.DS-11.2 | I,E | - | Backups tested for reliability and integrity | P |
| | PR.DS-11.3 | I,E | - | Separate, equally protected backups | S |
| | PR.DS-11.4 | E | - | Restore tests coordinated with continuity/incident response | S |
| | RC.RP-01.1 | B,I,E | - | Recovery process developed and executed | S |
| | RC.RP-05.1 | I,E | - | Integrity of restored systems verified | S |
| | GV.OC-04.4 | E | - | RTO/RPO set and monitored | W |
| *(proposed)* Guardrails (scans need approval) | ID.RA-01.5 | I,E | - | Scanning must not degrade operations | P |
| | ID.RA-01.4 | E | - | Performance/load/penetration tests run carefully | S |
| | PR.AA-05.7 | I,E | - | Privileged actions overseen | S |
| *(proposed)* Leavers | GV.RR-04.2 | I,E | - | HR process covers hiring, employment, termination | P |
| | PR.AA-01.1 | B,I,E | BK,IK,EK | Credential lifecycle (revocation) | P |
| | PR.AA-05.1 | B,I,E | BK,IK,EK | Permission review | S |
| | GV.SC-02.1 | I,E | - | Third parties report staff changes affecting access | S |

**Cross-check with the ISO 27001 mapping.** `mapping-ccb-cyfun2025-and-iso27001-2022.yaml` maps [V-lib]:
- ID.AM-01.1 to A.5.9 (among others);
- ID.AM-04.1 to A.5.19–A.5.23;
- ID.AM-08.2 to A.8.8 and A.8.32;
- GV.PO-01.1 to A.5.1;
- GV.RR-04.2 to A.6.1–A.6.4 and A.5.17.

These agree with the ISO refs already in `baseline.py` for HB-AM-1, HB-SC-1, HB-VM-* and HB-PO-1.

### 2.1 CyFun 2025 requirements a network/firewall integration could evidence (V-lib)

| Area | Req | Levels | Key | Paraphrase |
|---|---|---|---|---|
| Firewalls | PR.IR-01.1 | B,I,E | BK,IK,EK | Firewalls installed, configured, maintained on all networks |
| Segmentation | PR.IR-01.2 | B,I,E | BK,IK,EK | Segmentation/segregation by trust boundary and asset criticality |
| Segmentation | PR.IR-01.3 | I,E | IK,EK | Connections between critical-system components identified, documented, controlled |
| Boundary protection | PR.IR-01.4 | I,E | IK,EK | Boundary devices, zoning, encryption, monitoring at network edges |
| Boundary protection | PR.IR-01.5 | E | - | Authenticated proxies/firewalls between critical systems and external networks |
| Boundary protection | PR.IR-01.6 | E | - | Boundary devices fail safe |
| Segmentation | PR.IR-01.7 | E | - | Development/test strictly separated from production (OT) |
| Flow control | PR.IR-01.8 | E | - | Only authorised information flows allowed |
| Flow control | PR.IR-01.9 | E | - | External telecom interfaces: traffic rules, protections, documented exceptions |
| Flow documentation | ID.AM-03.2 | I,E | - | Internal network flows mapped and authorised, updated on change |
| Flow documentation | ID.AM-03.3 | E | EK | External network/data flows mapped and authorised |
| Flow documentation | ID.AM-04.2 | E | - | Flows to and from external systems mapped and authorised |
| Remote access | PR.AA-03.2 | B,I,E | BK,IK,EK | MFA for remote network access (VPN) |
| Remote access | PR.AA-03.3 | I,E | IK,EK | Remote access limits, secure connections, approvals |
| Remote access | PR.AA-03.4 | E | - | Remote access to critical systems monitored and cryptographically protected |
| Remote access | PR.AA-03.5 | E | - | External connections verified and covered by agreements |
| Wireless | PR.AA-03.1 | B,I,E | - | Wireless access points (incl. guest) secured and monitored |
| Baseline configuration | PR.PS-01.1 | I,E | IK,EK | Approved baseline configurations |
| Baseline configuration | PR.PS-01.3 | E | - | Unnecessary ports, protocols, services disabled |
| Baseline configuration | PR.PS-01.5 | E | - | Unauthorised configuration changes monitored |
| Network monitoring | DE.CM-01.1 | B,I,E | - | Firewalls at boundaries and endpoints used to detect threats |
| Network monitoring | DE.CM-01.3 | I,E | IK,EK | Critical systems monitored for unauthorised local, network, remote connections |
| Network monitoring | DE.CM-01.4 | E | - | Continuous network monitoring against defined incident criteria |
| Logs | DE.AE-03.1 | B,I,E | BK,IK,EK | Protection-tool logs kept, retained, reviewed |
| Analysis | DE.AE-02.1 | I,E | - | Security events analysed |
| Capacity | PR.IR-04.1 | I,E | IG,EG | Capacity including network/telecom |

**How a drag-and-drop connection panel could produce evidence** (design inference, U):
- The panel's graph of allowed tool-to-tool and tool-to-external connections is the "authorised flows" record for **ID.AM-03.2** (internal) and **ID.AM-03.3** (external; an Essential key measure).
- Zones or segments drawn in the panel, compared with the firewall's actual rules, evidence **PR.IR-01.2**, **PR.IR-01.3** and **PR.IR-01.8**.
- Flows that are drawn but not allowed by the firewall, or allowed but not drawn, are findings against those requirements.
- Firewall config drift checks evidence **PR.PS-01.1** and **PR.PS-01.5**.
- VPN and remote-access settings evidence **PR.AA-03.2** and **PR.AA-03.3**.

### 2.2 Level tags for every requirement referenced above (V-lib)
Paste-ready Python dict:

```python
CYFUN2025_TAGS = {
 "GV.OC-04.4":"E","GV.OC-05.1":"I,E","GV.RM-03.1":"B,I,E","GV.RM-03.2":"I,E,IG,EG","GV.RR-04.2":"I,E",
 "GV.PO-01.1":"B,I,E","GV.PO-01.2":"I,E","GV.OV-02.1":"E","GV.SC-02.1":"I,E","GV.SC-07.1":"I,E","GV.SC-07.2":"E",
 "ID.AM-01.1":"B,I,E","ID.AM-01.2":"I,E","ID.AM-01.3":"I,E","ID.AM-02.1":"B,I,E","ID.AM-02.2":"I,E",
 "ID.AM-02.3":"I,E","ID.AM-02.4":"I,E","ID.AM-03.2":"I,E","ID.AM-03.3":"E,EK","ID.AM-04.1":"I,E",
 "ID.AM-04.2":"E","ID.AM-05.1":"B,I,E","ID.AM-08.2":"B,I,E,BK,IK,EK","ID.AM-08.10":"E,EK","ID.AM-08.12":"I,E",
 "ID.RA-01.1":"B,I,E","ID.RA-01.2":"I,E","ID.RA-01.3":"I,E","ID.RA-01.4":"E","ID.RA-01.5":"I,E",
 "ID.RA-01.6":"I,E","ID.RA-05.1":"B,I,E","ID.RA-05.2":"I,E,IG,EG","ID.RA-06.1":"I,E,IG,EG",
 "ID.RA-08.1":"I,E,IK,EK","ID.RA-08.2":"E","ID.IM-03.1":"B,I,E","ID.IM-03.9":"E,EG","ID.IM-04.1":"I,E,IG,EG",
 "PR.AA-01.1":"B,I,E,BK,IK,EK","PR.AA-01.2":"I,E","PR.AA-01.3":"E","PR.AA-01.4":"E","PR.AA-02.2":"E",
 "PR.AA-03.1":"B,I,E","PR.AA-03.2":"B,I,E,BK,IK,EK","PR.AA-03.3":"I,E,IK,EK","PR.AA-03.4":"E","PR.AA-03.5":"E",
 "PR.AA-05.1":"B,I,E,BK,IK,EK","PR.AA-05.2":"B,I,E,BK,IK,EK","PR.AA-05.3":"B,I,E,BK,IK,EK",
 "PR.AA-05.4":"B,I,E,BK,IK,EK","PR.AA-05.5":"I,E","PR.AA-05.6":"I,E","PR.AA-05.7":"I,E","PR.AA-05.8":"E",
 "PR.DS-02.2":"E","PR.DS-11.1":"B,I,E,BK,IK,EK","PR.DS-11.2":"I,E","PR.DS-11.3":"I,E","PR.DS-11.4":"E",
 "PR.PS-01.1":"I,E,IK,EK","PR.PS-01.3":"E","PR.PS-01.5":"E","PR.PS-02.1":"I,E","PR.PS-04.1":"B,I,E,BK,IK,EK",
 "PR.PS-04.2":"I,E","PR.PS-04.3":"I,E","PR.PS-06.2":"I,E","PR.PS-06.4":"E",
 "PR.IR-01.1":"B,I,E,BK,IK,EK","PR.IR-01.2":"B,I,E,BK,IK,EK","PR.IR-01.3":"I,E,IK,EK","PR.IR-01.4":"I,E,IK,EK",
 "PR.IR-01.5":"E","PR.IR-01.6":"E","PR.IR-01.7":"E","PR.IR-01.8":"E","PR.IR-01.9":"E","PR.IR-03.1":"E",
 "PR.IR-04.1":"I,E,IG,EG","DE.CM-01.1":"B,I,E","DE.CM-01.3":"I,E,IK,EK","DE.CM-01.4":"E","DE.CM-09.1":"I,E",
 "DE.AE-02.1":"I,E","DE.AE-03.1":"B,I,E,BK,IK,EK","DE.AE-08.1":"I,E","RS.MA-01.1":"B,I,E",
 "RS.CO-02.1":"B,I,E","RS.CO-02.2":"I,E,IK,EK","RC.RP-01.1":"B,I,E","RC.RP-05.1":"I,E",
}
```

**Suggested baseline change** (design, U):
- Add `"CYFUN": "CyberFundamentals 2025 (CCB)"` to `FRAMEWORKS` in `hub/grc/baseline.py`.
- Put the P and S IDs into each control's `refs["CYFUN"]` using the same `" / "` separator the other frameworks use.
- Keep the tags dict separate so the UI can show "Basic / Important / Essential" readiness and flag key measures.

---

## 3. EU Cyber Resilience Act: Regulation (EU) 2024/2847 (short)

- **Dates** [V-off: Commission CRA page updated 7 Sep 2026; CRA summary updated 3 Dec 2025; reporting page updated 11 Sep 2026]:
  - published in the Official Journal on 20.11.2024 (EUR-Lex consolidated-text listing);
  - in force since **10 Dec 2024**;
  - Chapter IV (notification of conformity assessment bodies) applies from **11 Jun 2026**;
  - Art. 14 reporting applies from **11 Sep 2026**;
  - full application from **11 Dec 2027**;
  - open-source steward reporting (Art. 24(3)) from 11 Dec 2027.
- **Art. 14 reporting**, for actively exploited vulnerabilities and severe incidents [V-off: Commission and ENISA]:
  - early warning within **24 h** of becoming aware;
  - notification within **72 h**;
  - final report **14 days** after a corrective or mitigating measure is available (vulnerabilities), or **1 month** after the 72 h notification (incidents);
  - submitted once through ENISA's **Single Reporting Platform** (`https://portal.cra-srp.enisa.europa.eu`) to the CSIRT coordinator of the main-establishment Member State, with ENISA receiving it at the same time;
  - the platform has **no API at initial release**;
  - reporting also covers products placed on the market before 11 Dec 2027 [V-off, CRA summary].
- **Support period, Art. 13(8):** at least **five years**, or shorter if the product's expected use is shorter. The manufacturer sets it according to expected use time. [V-off, EUR-Lex text seen in search results]
- **Annex I Part II vulnerability handling**, paraphrased from CISO Assistant's packaged CRA annexes (`cra-regulation-annexes.yaml`) [V-lib-equivalent, U against the final OJ text]:
  1. identify and document vulnerabilities and components, including an **SBOM in a commonly used, machine-readable format covering at least top-level dependencies**;
  2. remediate without delay, with security updates separate from feature updates where technically feasible;
  3. test and review regularly;
  4. publicly disclose fixed vulnerabilities once an update is available, with a justified delay allowed;
  5. have a coordinated vulnerability disclosure policy;
  6. provide a contact address and a way to share vulnerability information, including about third-party components;
  7. distribute updates securely, automatically where applicable;
  8. issue security updates without delay and free of charge, with advisory messages.
- **Scope for Atrium** [V-off: CRA open-source page updated 31 Jul 2026]:
  - FOSS is in scope only when made available in the course of a commercial activity. Unmonetised FOSS is not.
  - Remote data processing is in scope only as part of a product with digital elements [V-off, summary]. The summary does not address pure SaaS.
- **Possible "important product" classification** [U, secondary sources quoting Annex III]:
  - Annex III Class I lists identity management and privileged access management software, and network management systems.
  - Class II lists firewalls and IDS/IPS.
  - Implementing Regulation (EU) 2025/2392 holds the technical descriptions [V-off, CRA summary].
  - If Atrium is sold, its core functionality (SSO/roles, approval-gated privileged agent actions, firewall/connection management) needs a legal classification check. Class I allows self-assessment only with harmonised standards; otherwise a third party assesses.
- **Uses Atrium could support for manufacturers** (inference): SBOM ingestion, an Annex I Part II checklist, and timers for the Art. 14 24 h / 72 h / 14 day / 1 month deadlines. Report submission itself stays manual because the platform has no API.

---

## 4. CISO Assistant (intuitem/ciso-assistant-community), main branch, read 2026-10-09

### 4.1 Authentication [V-src]
- **Settings** (`backend/ciso_assistant/settings.py`):
  - `DEFAULT_AUTHENTICATION_CLASSES` = `knox.auth.TokenAuthentication` and `iam.authentication.OIDCServiceAccountAuthentication`;
  - permissions = `IsAuthenticated` + `core.permissions.RBACPermissions`;
  - `REST_KNOX` does not set `AUTH_HEADER_PREFIX`, so knox's default `Token` applies, i.e. the header is `Authorization: Token <token>`. That knox's default is `Token` is from memory; Atrium's connector already uses it.
- **Session token lifetime:** `AUTH_TOKEN_TTL` defaults to 3600 s, with auto-refresh up to `AUTH_TOKEN_AUTO_REFRESH_MAX_TTL` (36000 s).
- **Personal access tokens** (`backend/iam/urls.py` and `iam/views.py`):
  - `GET/POST /api/iam/auth-tokens/` (`PersonalAccessTokenViewSet`, an APIView).
  - POST body: `name`, `expiry` (integer days, default 30, must be > 0, no maximum).
  - Response: `name`, `expiry`, `token`.
  - Limit: 5 unexpired PATs per user (`errorMaxPatAmountExceeded`); third-party users get 403.
  - Delete: `DELETE /api/iam/auth-tokens/<digest>/` (`AuthTokenDetailView`; the path key is the token **digest**, own tokens only).
- **Other iam routes:** `current-user/`, `logout/`, `logoutall/`, `session-token/`, `sso/`, `scim-token/`.
- **Service accounts:** `/api/iam/service-accounts/` (list/create, `permissions/`, `roles/`, `<uuid>/`, `<uuid>/rotate-secret/`).
  - Global-admin only, behind feature flag `service_accounts`.
  - Create returns `client_id`/`client_secret` once.
  - How a service account actually obtains a token (OAuth2 client credentials, token endpoint) was **not found** in the files read.
- **Pagination:** `core.pagination.CustomLimitOffsetPagination` (`limit`/`offset`); `PAGINATE_BY` and `PAGINATE_MAX` default to 5000.

### 4.2 Libraries: stored versus loaded [V-src, `backend/library/views.py`; routes registered in `backend/core/urls.py`]
- **Stored library** = a parsed YAML available in the catalogue. **Loaded library** = imported into the database, which creates `Framework`, `RequirementNode`, `ReferenceControl` and `RequirementMappingSet` rows.
- **Both viewsets accept either the UUID or the URN as `pk`** (regex `[\w.:-]+`; the highest stored version wins).
- **`/api/stored-libraries/`** (`StoredLibraryViewSet`):
  - filters: `urn`, `locale`, `version`, `packager`, `provider`, `object_type`, `filtering_labels`, `is_loaded`, `is_custom`, `is_update`, `is_preset`;
  - search: name, description, urn, ref_id;
  - actions:
    - `GET {pk}/content/`
    - `GET {pk}/tree/`
    - `POST {pk}/import/`: loads the library; needs `add_loadedlibrary` on the root folder; returns `{"status":"success"}`, 400 `{"status":"error","error":…}`, or 422.
    - `POST {pk}/unload/`
    - `DELETE {pk}/`
    - `POST upload/`: multipart `file`, YAML or .xlsx, ≤ 10 MB, `dry_run` query parameter; returns 201, with warning `libraryStoredForUpdate` when an older version is loaded.
    - `GET provider/`, `GET locale/`, `GET object_type/`
- **`/api/loaded-libraries/`** (`LoadedLibraryViewSet`):
  - filters: `urn`, `locale`, `version`, `packager`, `provider`, `object_type`, `has_update`;
  - actions:
    - `GET {pk}/` (includes `objects`)
    - `GET {pk}/content/`, `GET {pk}/tree/`
    - `GET {pk}/update/?action=rule_of_three|reset|clamp`: 409 `score_change_detected` when scores change
    - `GET available-updates/`
    - `DELETE {pk}/`: 400 if the library is still referenced
- **`GET /api/mapping-libraries/`** (`MappingLibrariesList`) lists stored libraries that contain a mapping set.
- **`LoadedLibrary.dependencies`** is a many-to-many to itself. Whether `import` auto-loads dependencies (e.g. both frameworks of a mapping library) was **not verified**.

### 4.3 Frameworks and requirement nodes [V-src, `core/models.py`, `core/views.py`, `core/serializers.py`]
- **`Framework` fields:**
  - `min_score` (default 0), `max_score` (100), `scores_definition`, `implementation_groups_definition`, `outcomes_definition`;
  - `field_visibility`, `score_scale_locked`, `score_calculation_method` (`average` | `sum` | `average_of_averages`), `anchor_na_to_target`, `target_score`, `urn_namespace`;
  - `library` → LoadedLibrary (`related_name="frameworks"`).
- **`/api/frameworks/`:**
  - filters: `folder`, `library__isnull`, `baseline`, `provider`; search: name, description;
  - actions: `GET names/?id[]=`, `GET {id}/tree/`, `GET {id}/report/`, `GET used/`, `GET {id}/mapping_stats/`, `GET {id}/mappings/`, `GET provider/`, `GET {id}/excel_template/`.
- **`RequirementNode` fields:**
  - `framework` (`related_name="requirement_nodes"`), `parent_urn`, `order_id`, `implementation_groups` (JSON list), `assessable`, `typical_evidence`;
  - `weight` (default 1), `importance` (`mandatory` | `recommended` | `nice_to_have` | `undefined`), `display_mode`, `visibility_expression`;
  - `min_score`, `max_score`, `scores_definition_ref`, `target_score`;
  - many-to-many `reference_controls` and `threats`;
  - `urn`, `ref_id`, `name`, `description` come from mixins.
- **`/api/requirement-nodes/`:** filter fields are **only `framework` and `urn`**; search is `name` only. **There is no ref_id filter.**
  - To resolve a CyFun ID: list `?framework=<id>` (or `GET /api/frameworks/{id}/tree/`) once and build a `ref_id → {id, urn}` map.
  - This also handles the irregular URNs in section 1.6.

### 4.4 Compliance assessments [V-src]
- **`ComplianceAssessment` fields** (inherits abstract `Assessment`):
  - from `Assessment`: `perimeter` (FK, nullable), `version` ("1.0"), `status` (`planned` | `in_progress` | `in_review` | `done` | `deprecated`), `authors`, `reviewers`, `observation`, `is_locked`;
  - `framework` (FK), `selected_implementation_groups` (JSON), `ref_id`, `min_score`, `max_score`, `scores_definition`, `score_scale_preset` (`0-100` | `0-5` | `1-5` | `1-4` | `0-3`);
  - `computed_outcome`, `computed_values` (read-only on write);
  - `assets`, `campaign`, `evidences` (many-to-many, `related_name="compliance_assessments"`);
  - `field_visibility`, `score_calculation_method`, `target_score`, `anchor_na_to_target`, `auto_sync`.
- **Create: `POST /api/compliance-assessments/`** (`ComplianceAssessmentWriteSerializer`, `fields="__all__"`):
  - Extra write-only fields: `baseline` (another audit's id), `create_applied_controls_from_suggestions` (bool), `confirm_rescale`, `ebios_rm_studies`.
  - Implementation groups not defined by the framework are dropped. If none are given, the framework's defaults apply.
  - `perform_create` calls `instance.create_requirement_assessments(baseline)`, which bulk-creates **one RequirementAssessment per node of the framework, assessable or not**. Implementation-group scope is applied when reading, not stored per row.
  - Same-framework `baseline`: copies `result`, `status`, `score`, `documentation_score`, `is_scored`, `is_score_overridden`, `observation`, evidences and applied controls.
  - **Different-framework `baseline`:** `MappingEngine.best_mapping_inferences(...)` copies inferred `result`, `status`, `observation`, `score`, `is_scored`, `documentation_score` and `mapping_inference`, and adds applied controls, evidences and security exceptions.
    - Example: an ISO 27001 audit can pre-fill a CyFun 2025 audit, provided the mapping library is loaded.
- **Required fields on create** (name, folder or perimeter) were **not confirmed**. `folder` is derived from `perimeter` only in `update()`.
- **Format of `selected_implementation_groups`:** a list of group ref_ids, e.g. `["I"]` for CyFun Important. This is **inferred**.
- **Filters:** `name`, `ref_id`, `folder`, `framework`, `perimeter`, `campaign`, `status`, `ebios_rm_studies`, `assets`, `evidences`, `authors`, `reviewers`, `genericcollection`, `due_date`, `eta`, `is_tprm`, plus query parameter `has_mapping_path_to`. Search: name, description, ref_id, framework__name.
- **Detail actions** (GET unless noted):
  - `tree/`, `combined_tree/`, `soa/`, `requirements_list/?assessable=true`, `global_score/`, `donut_data/`, `quality_check/`;
  - `section_compliance/`, `controls_coverage/`, `evidence_coverage/`, `exceptions_summary/`, `compliance_timeline/`, `implementation_groups_breakdown/`, `progress_ts/`, `threats_metrics/`;
  - `compliance_assessment_csv/`, `xlsx/`, `word_report/`, `posture-pdf/`, `export/` (zip), `action_plan_csv|xlsx|pdf/`;
  - `frameworks/`, `comparable_audits/`, `compare/`, `map_from_preview/?source_audit_id=`;
  - `POST map_from/`, `GET|POST syncToActions/`, `POST mailing/`, `POST update_requirement/`.
- **List actions:** `status/`, `score_calculation_method/`, `per_status/`, `quality_check/`, `recap/`, `analytics/`.
- **Extra paths:** `compliance-assessments/<id>/action-plan/`, `.../evidences-list/`, `.../suggestions/applied-controls/`.
- **`POST /api/compliance-assessments/{id}/update_requirement/`:**
  - body: `urn` (required), `result` (required), `observation`, `score` (int within scale), `status`, `is_score_overridden`;
  - finds the requirement assessment by `requirement__urn`; does not set `documentation_score`;
  - response: `message`, `urn`, `result` (+ `status`, `score`, `is_scored`, …); 403 if the user cannot change the audit.
- **`global_score`** returns the `get_global_score()` keys plus `min_score`, `max_score`, `total_max_score`, `scores_definition`, `score_scale_preset`, `framework`, `scoring_enabled`, `show_documentation_score`, `score_calculation_method`, `target_score`, `anchor_na_to_target`.
- **Outcomes** are evaluated as CEL expressions into `computed_outcome`, deferred after relevant saves. The evaluation code was not read.

### 4.5 Requirement assessments [V-src]
- **Fields:**
  - `status`: `to_do` | `in_progress` | `in_review` | `done`; default `to_do`.
  - `result`: `not_assessed` | `partially_compliant` | `non_compliant` | `compliant` | `not_applicable`; default `not_assessed`.
  - `extended_result`: `major_nonconformity` | `minor_nonconformity` | `observation_sensitive_point` | `opportunity_for_improvement` | `good_practice`; nullable.
  - Scoring: `is_scored`, `is_score_overridden`, `score` (int), `documentation_score` (int), `target_score`.
  - `observation`, `respondent_alignment`, `review_state`.
  - `compliance_assessment` (FK, `related_name="requirement_assessments"`), `requirement` (FK).
  - `applied_controls`, `evidences`, `security_exceptions`: many-to-many, each with `related_name="requirement_assessments"`.
  - `selected` (default True), `mapping_inference` (JSON); `eta`/`due_date` from a mixin.
- **`/api/requirement-assessments/`:**
  - filters: `folder`, `folder__name`, `evidences`, `compliance_assessment`, `applied_controls`, `security_exceptions`, `requirement__urn`, `result`, `extended_result`, `compliance_assessment__ref_id`, `compliance_assessment__perimeter`, `compliance_assessment__perimeter__name`, `compliance_assessment__assets__ref_id`, `requirement__assessable`, `created_at`/`updated_at` (gte, lt);
  - search: `requirement__name`, `requirement__description`, `requirement__urn`.
- **Write serializer** excludes only `created_at`/`updated_at`, so `applied_controls` and `evidences` are writable through `PATCH`.
  - `score` and `documentation_score` are validated against the resolved scale.
  - Writes are refused when the audit is locked or in review.
  - Extended-result rules: a nonconformity needs `non_compliant` or `partially_compliant`; `good_practice` needs `compliant`.

### 4.6 Applied controls and evidences [V-src]
- **`AppliedControl` fields:**
  - `ref_id`, `reference_control` (FK), `priority` (1–4), `category`, `csf_function`;
  - **`status`: `to_do` | `in_progress` | `on_hold` | `active` | `degraded` | `deprecated` | `--`** (default `--`);
  - `owner`, `start_date`, `eta`, `expiry_date`, `link`, `effort` (XS–XL), `control_impact` (1–5), `cost` (JSON), `progress_field` (0–100), `observation`;
  - many-to-many: `evidences` (`related_name="applied_controls"`), `assets`, `security_exceptions`, `objectives`.
- **`AppliedControlWriteSerializer`** (`fields="__all__"`) also accepts the many-valued **`requirement_assessments`**, plus `findings`, `stakeholders`, `incidents`, `task_templates` and `control_documents`.
  - So the link is `PATCH /api/applied-controls/{id}/ {"requirement_assessments": [...]}`.
  - Many-to-many writes **replace** the set, so read and merge first.
  - The filter `/api/applied-controls/?requirement_assessments=<id>` exists. Search: name, description, ref_id.
- **`Evidence`:**
  - `status`: `draft` | `missing` | `in_review` | `approved` | `rejected` | `expired`; default `draft`;
  - `expiry_date`, `owner`;
  - attachments and links now live on **`EvidenceRevision`** (`evidence`, `version`, `attachment`, `attachment_hash`, `original_filename`, `link`, `observation`, `task_node`).
- **`EvidenceWriteSerializer`** accepts `applied_controls`, `requirement_assessments`, `findings`, `owner` and others, plus optional `attachment`, `link`, `observation`.
  - A revision is created only when one of those three is supplied.
  - Creating a revision through `EvidenceRevisionWriteSerializer` sets the evidence to `in_review`.
- **Upload paths:** `POST /api/evidences/<uuid>/upload/` and `/api/evidence-revisions/<uuid>/upload/`.
- **Evidence filters:** `folder`, `applied_controls`, `requirement_assessments`, `name`, `status`, `expiry_date`, and others.
- **Evidence actions:** `GET {id}/attachment/`, `POST batch-upload/`.

### 4.7 Requirement mapping sets [V-src]
- **`RequirementMappingSet` fields:** `library` (`related_name="requirement_mapping_sets"`), `source_framework`, `target_framework`.
- **`RequirementMapping` fields:**
  - `mapping_set` (`related_name="mappings"`), `source_requirement`, `target_requirement`;
  - `relationship`: `subset` | `intersect` | `equal` | `superset` | `not_related`;
  - `rationale`: `syntactic` | `semantic` | `functional`;
  - `strength_of_relationship` (≤ 10), `annotation`; derived `coverage`.
- **`/api/requirement-mapping-sets/`:** filter `provider`; search name, provider; actions `GET graph-data/`, `GET {id}/graph_data/`, `GET {id}/table_data/`.

### 4.8 Do CyFun and CRA libraries ship?
- **CyFun: yes**: `cyfun2025.yaml`, `ccb-cff-2023-03-01.yaml`, the Small level, a preset, and mappings (section 1.6). [V-src]
- **CRA: yes**, as `cra-regulation-annexes.yaml`. [V-src]
  - Its library URN is `urn:intuitem:risk:library:cra-resolution-annexes`, ref_id `CRA-resolution-annexes`, version 3, `publication_date` 2024-06-25, provider EU.
  - It contains 166 assessable nodes, by the fetch tool's count.
  - The "resolution" name and the 2024-06-25 date suggest it was built from the European Parliament text, not the final OJ text.
  - Also present: `enisa-sme-cra-maturity.yaml` and `preset-cyber-resilience.yaml`.

### 4.9 Discrepancies with Atrium's existing connector (`hub/connectors/ciso_assistant.py`)
- **Line 21 (docstring) and `CONTROL_STATUS` (line 60):** applied-control statuses now include `degraded`. Reads should accept it; mapping a hub `partial` to `degraded` is an option.
- **Lines 723–730 (`_push_control`):** evidences are created with name and description only. That is still valid, but the evidence stays `draft` and has no revision. To get an `in_review` state and a visible record, send `observation` or `link`.
- **Suggested CyFun linkage** (design, U):
  1. Ensure the CyFun library is loaded: `GET /api/loaded-libraries/?urn=urn:intuitem:risk:library:ccb-cyfun2025`. If it is missing, ask an admin to import it, since `POST /api/stored-libraries/<urn>/import/` needs root-folder rights.
  2. Find or create a compliance assessment with `selected_implementation_groups=["B"|"I"|"E"]`.
  3. Build the ref_id map from `requirement-nodes?framework=`.
  4. For each hub control, PATCH its applied control with the merged `requirement_assessments` ids of its CyFun refs.
  5. Leave `result`, `score` and `documentation_score` to the human assessor. CyFun maturity is a judgement on two dimensions, and essential-level conformity is certified externally.

---

## 5. Open items for the implementer
1. Confirm the CyFun 2025 thresholds and key-measure list against the CCB booklets and Excel tool on cyfun.eu; every CCB host returned 403 to the fetcher.
2. Confirm the CCB's terms for reusing requirement IDs and text.
3. Confirm Belgian Royal Decree Article 22 and the 2027/2028 deadlines in Justel.
4. Pin the CISO Assistant version or commit you integrate against. `main` moves quickly (the CyFun library was repackaged on 2026-10-05).
5. Get a legal opinion on whether Atrium is a CRA "important product" (Class I identity/PAM or network management) once firewall and connection management ships.


## Confidence notes
- The research covered all four topics. Every CCB host (ccb.belgium.be, atwork.safeonweb.be, cyfun.eu, cyfun.be) returned HTTP 403, so no CyFun fact was read from a CCB document. Levels, key measures, scoring definitions and conformity thresholds come from the CISO Assistant library cyfun2025.yaml (version 10, packaged 2026-10-05). That file is a faithful-looking machine-readable copy of the CCB text, but it is not the CCB's own file.
- Each row in the CyFun mapping tables has two parts. The requirement ID, level tags (B/I/E) and key-measure tags (BK/IK/EK) were checked against the library. The fit rating (P/S/W) and the choice of requirements per Atrium control are my analyst judgement.
- Most level tags came from a summariser reading 100k-character slices of a 3.4 MB YAML file. I spot-checked the key-measure-heavy rows and both matched: PR.AA-01.1/01.2/01.3/02.2/03.2, PR.PS-01.1/04.1/04.3, PR.IR-01.1–01.5, ID.AM-08.2/08.12 and ID.AM-03.2/03.3. A few tags read from slice boundaries are slightly less certain: PR.PS-04.1, PR.DS-10.1, DE.CM-09.4 and RS.MA-03.1.
- Three CSF 2.0 subcategories (GV.SC-04, ID.RA-07, GV.PO-02) and the requirement ID.AM-08.1 are absent from CyFun 2025. Both the framework tree and the CyFun 2025 to ISO 27001 mapping file skip them. Fetch truncation markers mean a full parse would give a definitive answer.
- The Essential maturity threshold of 3.5 (overall), with key measures and categories at ≥ 3.0, comes from the library's outcome expressions. No CCB source was reachable, and no public secondary source I found states 3.5.
- On the Belgian NIS2 law, only the BELAC facts are official: transition dates, CAS version 2025-11-26, and the presumption of conformity. The conformity routes and the 2026/2027/2028 deadlines rely on law-firm and certification-body summaries, and those sources disagree on 2027 versus 2028.
- The CRA dates and Art. 14 deadlines are confirmed on Commission and ENISA pages. The Art. 13(8) five-year support period comes from EUR-Lex text shown in search results, because EUR-Lex returned empty pages to the fetcher. Annex I Part II is paraphrased from CISO Assistant's CRA library, which appears to be built from the June 2024 Parliament text rather than the final OJ text.
- The Annex III placements (identity/PAM and network management systems in Class I, firewalls in Class II) come from secondary sources. Whether they apply to Atrium is a legal question.
- The CISO Assistant API details come from reading the source on the main branch on 2026-10-09: core/urls.py, core/models.py, core/serializers.py, core/views.py, library/views.py, iam/urls.py, iam/views.py and settings.py. These files are large and were read in summarised chunks, so exact action url_paths could differ slightly from method names where the decorator was not visible.
- Some CISO Assistant points were not verified: the knox default header prefix 'Token' (memory, matching Atrium's existing connector), how service accounts obtain OAuth2 tokens, whether importing a library auto-loads its dependencies, the required fields when creating a compliance assessment, and the format of selected_implementation_groups (inferred as a list of group ref_ids).
- Two baseline gaps: hub/grc/baseline.py has no 'guardrails' or 'leavers' control, so those mapping rows are proposals. Two connector discrepancies: hub/connectors/ciso_assistant.py omits the applied-control status 'degraded', and evidence pushed without link or observation creates no revision and stays in draft.

## Sources
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/cyfun2025.yaml (library version 10, publication_date 2026-10-05; read 2026-10-09)
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/ccb-cff-2023-03-01.yaml (library version 8)
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/mapping-ccb-cyfun2025-and-iso27001-2022.yaml (version 1, 2026-08-10)
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/libraries/cra-regulation-annexes.yaml (version 3, 2024-06-25)
- https://api.github.com/repos/intuitem/ciso-assistant-community/contents/backend/library/libraries (directory listing, 2026-10-09)
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/core/urls.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/core/models.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/core/serializers.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/core/views.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/library/views.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/iam/urls.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/iam/views.py
- https://raw.githubusercontent.com/intuitem/ciso-assistant-community/main/backend/ciso_assistant/settings.py
- https://economie.fgov.be/en/themes/quality-and-safety/accreditation-belac/news-belac (BELAC transition plan CyberFundamentals, 10.12.2025)
- https://ncsc.gov.ie/CyFun/CyFunFAQ (last updated 23/6/2025)
- https://www.vincotte.be/uploads/TD-I02-01E-General-regulations-CyFun.pdf (Vinçotte CyFun verification regulations, January 2026; secondary)
- https://ccb.belgium.be/news/cyfunr-2025-here (CCB CyFun 2025 announcement; HTTP 403, known only via search snippets)
- https://atwork.safeonweb.be/tools-resources/cyberfundamentals-framework (HTTP 403)
- https://cyfun.eu/sites/default/files/2026-03/CyFun2025_Booklet_ESSENTIAL_E.pdf (cited by the library; HTTP 403)
- https://cadeproject.org/?p=155136 (Belgian NIS2 assessment deadlines; secondary)
- https://www.lexmundi.com/guides/status-of-the-nis2-implementation-act-in-the-european-union/jurisdictions/europe/belgium/ (secondary)
- https://brandcompliance.com/en/cyfun-verification/ (secondary)
- https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act (updated 7 Sep 2026)
- https://digital-strategy.ec.europa.eu/en/policies/cra-summary (updated 3 Dec 2025)
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting (updated 11 Sep 2026)
- https://digital-strategy.ec.europa.eu/en/policies/cra-open-source (updated 31 Jul 2026)
- https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched
- https://www.enisa.europa.eu/topics/product-security/single-reporting-platform-srp/frequently-asked-questions
- https://eur-lex.europa.eu/eli/reg/2024/2847/oj/eng (Regulation (EU) 2024/2847; empty page via fetcher, Art. 13(8) text seen via search results)
- https://www.springlex.eu/en/packages/cra/cra-regulation/annex-3/ (Annex III text mirror; secondary)
- https://www.hsfkramer.com/notes/cybersecurity/2026-posts/cyber-resilience-act-commission-clarifies-important-and-critical-product-categories (Implementing Regulation 2025/2392; secondary)
- C:\Users\test\Downloads\hub program\hub\grc\baseline.py
- C:\Users\test\Downloads\hub program\hub\grc\checks.py
- C:\Users\test\Downloads\hub program\hub\connectors\ciso_assistant.py
- C:\Users\test\Downloads\hub program\hub\core.py (DEFAULT_GUARDRAILS, line 30)