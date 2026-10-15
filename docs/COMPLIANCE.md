# Compliance

The **Compliance hub** (`#/compliance`) holds:

- the **Hub Security Baseline**: controls evaluated against live hub state, mapped to ISO/IEC 27001:2022, SOC 2,
  NIS2, CyFun 2025 and CyFun 2023;
- the **risk register** and **policies**;
- the **Frameworks** tab: the CyberFundamentals (CyFun) catalogs built in, self-assessments with scoring,
  conformity per level and an audit pack, and frameworks read from CISO Assistant (such as the EU Cyber Resilience
  Act).

The GRC Supervisor (`module:grc`) evaluates the controls, keeps the evidence, opens and closes automatic risks, and
runs the GRC data flows ([INTEGRATIONS.md](INTEGRATIONS.md#ciso-assistant)).

**Mappings are analyst judgement.** Which Atrium control maps to which clause of ISO 27001, SOC 2, NIS2 or CyFun was
not checked against the licensed or official texts. Neither were the network and change-management references,
which the code marks UNVERIFIED. Use the references as a starting point for your own mapping, not as a certification
claim.

## Hub Security Baseline

30 controls (`hub/grc/baseline.py`). Automated checks are pure functions over a snapshot of hub state
(`hub/grc/checks.py`).

- **Manual override**: people can override any control with a justification (`PATCH /api/grc/controls/{id}`, operator).
- **Risks**: controls with a risk template raise a risk when they fail and close it when they pass again.
- **Score tiles**: `GET /api/grc` returns one tile for the baseline and one per framework (ISO27001, SOC2, NIS2,
  CyFun2025, CyFun2023). A tile scores the controls that reference that framework: pass 1, partial 0.5, fail and
  manual 0; `na` is not counted. The CyFun tiles therefore measure the hub's own controls. They are **not** a CyFun
  conformity result; that comes from a [self-assessment](#self-assessments).

| Control | Family | ISO 27001 | SOC 2 | NIS2 | CyFun 2025 | CyFun 2023 |
| --- | --- | --- | --- | --- | --- | --- |
| HB-AM-1 Asset inventory is complete | Asset management | A.5.9 | CC6.1 | 21(2)(i) | ID.AM-01.1 / ID.AM-02.1 / ID.AM-01.2 / ID.AM-02.2 | ID.AM-1.1 / ID.AM-1.2 / ID.AM-2.1 |
| HB-AM-2 Assets have owners and a criticality | Asset management | A.5.9 | CC6.1 | - | ID.AM-05.1 / ID.AM-02.3 / ID.AM-01.2 | ID.AM-1.2 / ID.AM-2.3 / ID.AM-5.1 |
| HB-AC-1 Central identity and single sign-on | Access control | A.5.16 / A.8.5 | CC6.1 / CC6.2 | 21(2)(i) / 21(2)(j) | PR.AA-01.1 / PR.AA-05.5 / PR.AA-01.2 / PR.AA-02.2 | PR.AC-1.1 |
| HB-AC-2 Privileged agent actions are approved | Access control | A.8.2 / A.8.32 | CC8.1 | - | PR.AA-05.7 / PR.AA-05.6 / PR.PS-06.2 / PR.AA-05.3 | PR.AC-4.6 / PR.AC-4.7 |
| HB-AC-3 Hardened remote access | Access control | A.8.5 / A.8.20 | CC6.6 | 21(2)(i) | PR.AA-03.3 / ID.AM-08.12 / PR.AA-01.4 / PR.AA-03.5 / PR.DS-02.2 | PR.AC-3.3 / PR.AC-3.5 |
| HB-AC-4 Authenticated, role-based access to the hub | Access control | A.5.15 / A.8.5 | CC6.1 | 21(2)(i) / 21(2)(j) | PR.AA-01.1 / PR.AA-05.1 / PR.AA-05.3 / PR.AA-05.4 / PR.AA-03.2 | PR.AC-1.1 / PR.AC-4.1 / PR.AC-4.3 / PR.AC-4.4 |
| HB-AC-5 Dormant hub accounts are disabled | Access control | A.5.18 | CC6.2 | 21(2)(i) | PR.AA-01.3 / PR.AA-05.1 | PR.AC-1.3 |
| HB-AC-6 AI agent guardrails are enforced | Access control | A.8.2 / A.8.32 | CC6.1 / CC8.1 | 21(2)(i) | ID.RA-01.5 / ID.RA-01.4 / PR.AA-05.7 | DE.CM-8.1 / ID.RA-1.3 / PR.AC-4.7 |
| HB-AC-7 Leavers lose access and return assets | Access control | A.5.18 / A.5.11 | CC6.2 / CC6.3 | 21(2)(i) | GV.RR-04.2 / PR.AA-01.1 / PR.AA-05.1 / GV.SC-02.1 | PR.AC-1.1 / PR.AT-3.2 / PR.IP-11.2 |
| HB-AC-8 AI agent teams inside tools are governed | Access control | A.5.15 / A.8.2 / A.8.15 / A.8.32 | CC6.1 / CC6.3 / CC8.1 | 21(2)(i) | PR.AA-05.3 / PR.AA-05.7 | PR.AC-4.7 |
| HB-CM-1 Integration configuration as code | Configuration management | A.8.9 | CC7.1 | - | PR.PS-01.1 / ID.AM-03.2 | ID.AM-3.2 / PR.IP-1.1 |
| HB-CM-2 Changes to tools are reviewed | Change management | A.8.32 | CC8.1 | 21(2)(e) | PR.PS-06.2 / PR.PS-06.4 / PR.PS-01.5 / ID.AM-08.10 | DE.CM-7.2 / PR.IP-3.1 / PR.IP-3.2 / PR.MA-1.7 |
| HB-CM-3 Network device changes are controlled | Change management | A.8.32 | CC8.1 | 21(2)(e) | PR.PS-06.2 / PR.PS-01.5 / PR.IR-01.1 | DE.CM-7.2 |
| HB-OP-1 Health monitoring for every tool | Operations | A.8.16 | CC7.2 | 21(2)(b) | PR.IR-04.1 | PR.DS-4.1 |
| HB-OP-2 Audit trail of agent and operator activity | Operations | A.8.15 | CC7.2 | 21(2)(f) | PR.PS-04.1 / PR.AA-05.7 / PR.PS-04.3 / PR.PS-04.2 / DE.AE-03.1 | PR.AC-4.7 / PR.DS-4.2 / PR.PT-1.1 / PR.PT-1.2 |
| HB-VM-1 Software inventory with versions | Vulnerability management | A.8.8 | CC7.1 | 21(2)(e) | ID.AM-02.1 / ID.AM-08.2 / PR.PS-02.1 | ID.AM-2.1 / PR.MA-1.1 |
| HB-VM-2 In-scope assets are scanned for vulnerabilities | Vulnerability management | A.8.8 | CC7.1 | 21(2)(e) | ID.RA-01.1 / ID.RA-01.2 / ID.RA-01.6 / ID.RA-01.5 / ID.IM-03.9 | DE.DP-5.2 / ID.RA-1.1 / ID.RA-1.2 |
| HB-VM-3 Critical and high vulnerabilities are fixed within SLA | Vulnerability management | A.8.8 | CC7.1 | 21(2)(e) | ID.AM-08.2 / ID.RA-01.3 / ID.RA-06.1 / ID.RA-08.1 / ID.RA-08.2 | PR.IP-12.1 / PR.MA-1.1 |
| HB-NW-1 Network segmentation follows the policy | Network security | A.8.22 / A.8.20 | CC6.6 | 21(2)(e) | PR.IR-01.2 / PR.IR-01.3 / PR.IR-01.8 / ID.AM-03.2 | ID.AM-3.2 |
| HB-NW-2 Device configuration changes are explained | Network security | A.8.9 / A.8.32 | CC7.1 / CC8.1 | 21(2)(e) | PR.PS-01.1 / PR.PS-01.5 | DE.CM-7.2 / PR.IP-1.1 |
| HB-NW-3 Device management is not exposed to the internet | Network security | A.8.20 | CC6.6 | 21(2)(i) | PR.IR-01.4 / PR.PS-01.3 | PR.AC-5.4 / PR.PT-3.2 |
| HB-NW-4 Device configurations are backed up | Network security | A.8.13 | A1.2 | 21(2)(c) | PR.DS-11.1 | PR.IP-4.1 |
| HB-NW-5 Firewall rules are least-privilege and documented | Network security | A.8.20 / A.8.22 | CC6.6 | 21(2)(e) | PR.IR-01.1 / PR.IR-01.8 / PR.PS-01.3 | PR.PT-3.2 |
| HB-SC-1 SaaS and supplier inventory | Supplier management | A.5.19 / A.5.23 | CC9.2 | 21(2)(d) | ID.AM-04.1 / GV.SC-07.2 / GV.OC-05.1 | ID.AM-4.1 / ID.SC-2.2 |
| HB-RM-1 Risk register maintained | Risk management | 6.1.2 / 8.2 | CC3.2 | 21(2)(a) | ID.RA-05.1 / GV.RM-03.2 / GV.RM-03.1 / ID.RA-05.2 / ID.RA-06.1 | ID.GV-4.1 / ID.GV-4.2 / ID.RA-5.1 / ID.RA-5.2 |
| HB-PO-1 Information security policy approved | Governance | A.5.1 | CC5.3 | 21(2)(a) | GV.PO-01.1 / GV.PO-01.2 | ID.GV-1.1 |
| HB-PO-2 Access control policy approved | Governance | A.5.15 | CC6.2 | 21(2)(i) | GV.PO-01.1 / PR.AA-05.1 / PR.AA-05.2 | ID.GV-1.1 / PR.AC-4.1 / PR.AC-4.2 |
| HB-PO-3 Compliance framework self-assessment is current | Governance | 9.1 / A.5.36 | CC4.1 | 21(2)(f) | GV.OV-03.1 | - |
| HB-IR-1 Incident response plan | Incident management | A.5.24 | CC7.4 | 21(2)(b) | RS.MA-01.1 / ID.IM-04.1 / RS.CO-02.2 / DE.AE-08.1 / RS.CO-02.1 / ID.IM-03.1 | PR.IP-9.1 / RS.CO-3.1 / RS.CO-3.2 / RS.IM-1.1 / RS.RP-1.1 |
| HB-BC-1 Backup and recovery policy | Business continuity | A.8.13 | A1.2 | 21(2)(c) | PR.DS-11.1 / PR.DS-11.2 / PR.DS-11.3 / PR.DS-11.4 / RC.RP-01.1 / RC.RP-05.1 | PR.IP-4.1 / PR.IP-4.2 / PR.IP-4.3 / RC.RP-1.1 |

Notes on the references:

- **CyFun 2025**: the primary and supporting rows of the analyst mapping (`hub/grc/frameworks/mapping.py`). The
  requirement ids and their level tags were checked against the CISO Assistant library copy.
- **CyFun 2023**: derived through CISO Assistant's CyFun 2023 - 2025 mapping library, which is aligned on the CCB
  transposition table.
- **Marked UNVERIFIED in the code**: HB-AC-8, HB-CM-3, HB-NW-1..5 and HB-PO-3. CyFun 2023 has no equivalent for HB-PO-3,
  because GV (Govern) is new in NIST CSF 2.0.

### How the controls are evaluated

| Control | Evaluated from |
| --- | --- |
| HB-AM-1, HB-AM-2 | the asset register: every tool and host registered, owners |
| HB-SC-1 | SaaS tools with an owner in the asset register, and the cloud AI providers agents use with a supplier owner and a terms review within 12 months ([below](#hb-sc-1-cloud-ai-providers-are-suppliers)) |
| HB-AC-1, HB-CM-1, HB-OP-1, HB-VM-1 | the tools' manifests: SSO, adopted manifest, health check, version |
| HB-AC-2, HB-AC-6, HB-CM-2 | the autonomy level and the agent guardrails ([AGENTS.md](AGENTS.md#compliance-effect)) |
| HB-AC-3 | SSH hosts with key authentication and host-key checking |
| HB-AC-4, HB-AC-5 | the hub's accounts: an admin exists, OIDC sign-in, accounts signed in within 90 days |
| HB-AC-7 | leavers who still have access or assets ([PEOPLE.md](PEOPLE.md)) |
| HB-AC-8 | the subsidiaries (agent teams inside tools): their statuses, flags, charters, conformance and alarms, and their guardrails ([below](#hb-ac-8-ai-agent-teams-inside-tools-are-governed)) |
| HB-OP-2 | the activity and agent message logs, and the subsidiaries' audit trails (counted) |
| HB-VM-2, HB-VM-3 | scan coverage within 30 days and findings within their SLA ([INTEGRATIONS.md](INTEGRATIONS.md#vulnerabilities-and-scans)) |
| HB-RM-1 | risks reviewed within 90 days |
| HB-PO-1, HB-PO-2, HB-IR-1, HB-BC-1 | an approved policy of the category (a draft is partial) |
| HB-NW-1 .. HB-NW-5, HB-CM-3 | the network devices' snapshots, drift, backups, segmentation and change history ([NETWORK.md](NETWORK.md#network-compliance-controls)) |
| HB-PO-3 | the latest framework self-assessment ([below](#hb-po-3-self-assessment-is-current)) |

Extension packs can add control rules that make a control worse, never better ([AGENTS.md](AGENTS.md#what-a-pack-can-contain)).

### HB-SC-1: cloud AI providers are suppliers

Agents send prompts, the hub data their tools read and tool results to the AI providers they run on. A third-party
provider - Claude, OpenAI, an Azure OpenAI resource, an OpenAI-compatible cloud service - that agents use is therefore
a supplier like a SaaS tool. "In use" means: chosen at any level of the model choice (an agent, a team, a task or the
suite default, the fallback chain), what an agent resolves to now, or called in the last 30 days
([AGENTS.md](AGENTS.md#how-a-model-is-chosen)). Self-hosted model servers are not suppliers.

HB-SC-1 counts the SaaS tools and the AI providers in use together: each SaaS tool needs an owner in the asset
register, each AI provider a **supplier owner** and a **terms / data processing agreement review** within the last 12
months (set on its card under Settings > AI providers). All of them: pass; some: partial; none: fail; neither SaaS
tools nor AI providers in use: not applicable. The detail names what is missing ("AI provider OpenAI has no supplier
owner"); the evidence lists "AI provider: Anthropic - owner j.doe, terms reviewed 2026-09-30".

The guardrail `allow_cloud_llm` ("Agents may send data to cloud AI providers", on by default) blocks every third-party
provider when it is off, so none counts as in use. It is on by default because nothing reaches a cloud provider until
an administrator stores a key or sets one in the environment; switching it back on is logged as relaxing. The control
description and its references are unchanged otherwise. UNVERIFIED analyst note: ISO/IEC 27001:2022 A.5.19 / A.5.23
and NIS2 21(2)(d), already mapped to HB-SC-1, also cover AI processors; this was not checked against the licensed
texts.

**AI spending (HB-AC-6).** The guardrail `limit_llm_spend` ("Cap the AI model spending per day", on by default) with
`max_daily_llm_spend` (20 USD) caps the agents' estimated AI spending per UTC day: new model calls stop once it is
reached. Switching it off makes HB-AC-6 partial with the finding "agents' AI model spending has no daily limit"; while it
is on, the pass text ends with "AI spending is capped at $20 per day" and the evidence names `max_daily_llm_spend`.
Raising the cap is logged as relaxing. Each agent's own budgets and rate limits (its settings page) come on top
([AGENTS.md](AGENTS.md#agent-settings)).

**Escalations (HB-AC-2, HB-OP-2 evidence).** A chat agent that is blocked or unsure, or whose escalation rules apply,
asks a person through an `agent_escalation` approval; an operator acknowledges or dismisses it with an answer. The
request, the decision, who made it and the agent's runs (a team agent's schedule pauses after failed runs in a row
until an administrator resumes it) are in the activity log and the approval history, with the agent's notifications
marked there ([AGENTS.md](AGENTS.md#escalation-and-notifications)). They add audit evidence; no control is scored on
them.

### HB-AC-8: AI agent teams inside tools are governed

Agent teams that work inside a tool ([SUBSIDIARIES.md](SUBSIDIARIES.md)) act only within a charter an administrator
approved, through a bridge that verifies Atrium's signatures, with budgets, a kill switch, a hash-chained audit trail
and a person's approval for in-tool changes, code and patches. The check (`check_subsidiaries`) reads ids, statuses,
flags and counts only - never text from the tools:

| Result | When |
| --- | --- |
| `na` | no subsidiary is on probation, active or paused |
| `fail` | a fail-level guardrail is relaxed (`subsidiary_bridge_requires_conformance`), or an active subsidiary has no approved charter, no passing conformance for its approved bridge (while required), a sidecar token without an enabled administrator owner, or a reconciliation alarm or broken audit chain in the last 90 days |
| `partial` | `subsidiary_panel_actions` on, `subsidiary_separate_credential` off or `subsidiary_ticket_minutes` above 10 (each named in the finding), a bridge that changed since it was approved, a sidecar offline for more than a day, conformance only claimed by the sidecar, or a bridge patch approved without the tool's tests (no container runtime) |
| `pass` | otherwise |

Two subsidiary guardrails weaken other controls: `subsidiary_tool_writes_need_approval` off makes HB-AC-2 partial
("reversible in-tool writes of subsidiary teams run without approval"), and `subsidiary_bridge_requires_tests` off
makes HB-CM-2 fail; HB-CM-2 counts bridge patches like other patches. The master switch `allow_subsidiaries` maps to
no control: off is the safe side, and switching it on is logged as relaxing. The GRC Supervisor re-evaluates after
status, charter and conformance changes, alarms and guardrail changes. The references are an UNVERIFIED analyst
mapping (ISO/IEC 27001:2022 A.5.15 / A.8.2 / A.8.15 / A.8.32, SOC 2 CC6.1 / CC6.3 / CC8.1, NIS2 21(2)(i), CyFun 2025
PR.AA-05.3 / PR.AA-05.7, CyFun 2023 PR.AC-4.7), not checked against the licensed texts. Its risk template: "AI agents
act inside business tools beyond the parent's control" (likelihood 3, impact 4).

## Frameworks: CyberFundamentals (CyFun)

The CyberFundamentals framework of the Centre for Cybersecurity Belgium (CCB) is built in, in two editions:

| | CyFun 2025 (default) | CyFun 2023 |
| --- | --- | --- |
| Based on | NIST CSF 2.0 (ids like `PR.AA-01.1`) | NIST CSF 1.1 (ids like `ID.AM-1.1`) |
| Requirements | 218 (6 functions, 22 categories, 90 subcategories) | 219 (5 functions, 23 categories, 99 subcategories) |
| Basic / Important / Essential | 34 / 133 / 218 | 34 / 140 / 219 |
| Key measures BK / IK / EK | 13 / 22 / 29 | 13 / 21 / 29 |
| Management aspects BG / IG / EG | 0 / 9 / 15 | none |
| Source library | `urn:intuitem:risk:library:ccb-cyfun2025`, version 10, published 2026-10-05 | `urn:intuitem:risk:library:ccb-cff-2023-03-01`, version 8, published 2026-10-04 |

**Levels are cumulative tags.** A Basic requirement is also Important and Essential. Key measures (`BK`, `IK`, `EK`)
are the requirements a level cannot do without. Management aspects (`BG`, `IG`, `EG`, CyFun 2025 only) are
governance requirements.

**Transition.** CyFun 2023 may still be applied, verified and certified until **18 April 2027**. Its statements and
certificates stay valid until 18 April 2028 at the latest. New assessments should use CyFun 2025. Atrium refuses new
CyFun 2023 assessments after 18 April 2027, and the Frameworks tab shows the transition note.

### What the catalogs contain (licensing)

The catalogs (`hub/grc/frameworks/cyfun2025.json`, `cyfun2023.json`) are generated at build time by
`scripts/build_cyfun_catalog.py` from the CISO Assistant library files. For each requirement they keep only:

- its `ref_id`;
- its function, category and subcategory ids;
- its level tags;
- a short title.

**The CCB's requirement text, guidance and annotations are not shipped.** Every requirement links to
[cyfun.eu](https://cyfun.eu) for the text.

Titles are the NIST CSF category names and subcategory statements: NIST CSF 2.0 (NIST CSWP 29) for 2025 and CSF 1.1
for 2023. These are US government works in the public domain. One short title was written for Atrium (`ID.BE-3` in
2023), where the NIST statement equalled the library text.

The build refuses to write a catalog in which any title equals or contains a library text. The tests prove the same
with SHA-256 fingerprints of the library texts (`tests/data/cyfun_library_fingerprints.json`), so the test data does
not ship the text either.

CyFun 2023 details:

- CISO Assistant's `BASIC_` / `IMPORTANT_` id prefixes are turned into level tags.
- The library's `R.AC-3.4` / `R.AC-3.5` typos are corrected to `PR.AC-3.4` / `PR.AC-3.5`.
- Each 2023 requirement lists the 2025 requirements it maps to.

The CCB's terms for reusing the ids and structure were not confirmed.

**Rebuilding.** Rebuild after a CISO Assistant library update with:

```bash
.venv/bin/python scripts/build_cyfun_catalog.py --check     # downloads to a cache outside the repository
.venv/bin/python scripts/build_cyfun_catalog.py             # writes the catalogs and the fingerprints
```

Options: `--cache-dir DIR`, `--offline` (cached files only), `--refresh`. The script fails loudly when counts, the
tree, id formats, cumulative levels, key measures, the scale names or the conformity rules change.

### Maturity scale

Each requirement gets two scores from 1 to 5: **implementation maturity** and **documentation maturity**. The level
names are CyFun 2025's; the one-line descriptions are Atrium's own wording.

| Score | Name | Implementation | Documentation |
| --- | --- | --- | --- |
| 1 | Initial | Done ad hoc or not at all; no standard process. | Not documented, or not approved. |
| 2 | Repeatable | Done informally and repeated, but not consistently or completely. | Documented and approved, but outdated (more than two years old) or incomplete. |
| 3 | Defined | A formal process is in place and followed, with evidence for most activities. | Approved, current documentation that is communicated to the people concerned. |
| 4 | Managed | Followed everywhere with evidence, measured against targets, few exceptions. | Reviewed regularly; metrics and targets are documented. |
| 5 | Optimizing | Measured and continually improved; exceptions are rare. | Continually improved from measurements and lessons learned. |

### Scoring and conformity

**Source.** The thresholds and the method come from the **CyFun 2025 library that ships with CISO Assistant**:
`outcomes_definition`, `implementation_groups_definition`, `anchor_na_to_target` and
`score_calculation_method: average_of_averages`. The build script checks them on every build. The CCB's own documents
(booklets, self-assessment tool) answered HTTP 403, so they are **unverified** against the CCB originals. That
includes whether the CCB averages implementation and documentation maturity the way CISO Assistant does. The CyFun
2023 library defines no conformity rules: **Atrium applies the 2025 rules to CyFun 2023, unverified**. The code, the
API (`conformity_source`, `evaluation.method.source`), the Frameworks tab and the audit pack all say so.

**How scores are computed:**

- A requirement counts once its implementation maturity is set. Its maturity is the average of implementation and
  documentation maturity; a missing documentation maturity counts as 1.
- A requirement marked **N/A** (with a mandatory justification) counts at the framework target, 3.0.
- A group's score (all Basic requirements, the Important key measures, ...) is an **average of averages**:
  requirements per subcategory, subcategories per category, and every category weighs the same.
- Requirements that are not scored are left out of averages but count as missing in a group's minimum, so an
  unscored key measure fails the key-measure rule.
- Scores are compared unrounded and shown with two decimals, rounded half up.

**Rules per level:**

| Level | Overall maturity of the level's requirements | Every key measure of the level | Every category | N/A at most | Key measures N/A | Management aspects N/A |
| --- | --- | --- | --- | --- | --- | --- |
| Basic (B) | >= 2.5 | >= 2.5 | - | 1 | none | - |
| Important (I) | >= 3.0 | >= 3.0 | - | 3 | none | - |
| Essential (E) | >= 3.5 | >= 3.0 | >= 3.0 | 5 | none | none |

A level is **met** only when its rules hold **and** every requirement of the level is scored or N/A. It is
**incomplete** when nothing fails but something is still missing, and **not met** otherwise. Each verdict lists its
reasons: which key measures are below or unscored, which categories fail (Essential), and too many N/A.

The **gaps** list compares each requirement with what it should reach at the target level. That is the key-measure
threshold for key measures; for other requirements it is the level's group target (B 2.5, I and E 3.0).

### Self-assessments

Self-assessments are stored in collection `framework_assessments`:

- An operator starts one for an edition (CyFun 2025 by default) with a name, a **target level** (Basic, Important or
  Essential), an optional scope and notes. The name must not be blank (400). It can copy the scores of an earlier
  assessment of the same edition; the copy keeps their age (its "last scored" time is the original's), so copying an
  old assessment does not make HB-PO-3 pass until a person changes a requirement.
- Status is `in_progress`, `completed` or `archived`. An archived assessment is read-only: it cannot be scored, and
  its name, target level, scope and notes cannot change (409) until it is reopened (status `in_progress`).

**Per requirement:**

- implementation maturity and documentation maturity (1-5);
- **N/A**, with a justification of at least 3 characters;
- an **owner** from the People app;
- notes;
- up to 25 **evidence links**: a hub control (its automated result), a hub policy or risk, an http(s) URL without
  credentials, or a file kept elsewhere (a name or path; Atrium never stores the file).

Each change keeps who made it and when, with a short history of the last 20 changes.

**Suggested evidence.** The hub controls mapped to a requirement are listed as **suggested evidence**, with their
fit:

- **primary**: evidence for the requirement;
- **supporting**: partial evidence;
- **weak**: touches only part of the requirement.

The fit is analyst judgement, not CCB guidance. Atrium **never sets a score itself**: maturity stays a person's
judgement.

#### HB-PO-3 self-assessment is current

| Status | When |
| --- | --- |
| manual | no self-assessment exists |
| partial | the latest one was last scored more than 12 months ago, nothing is scored yet, or a key measure of its target level is below its threshold, N/A or not scored |
| pass | otherwise |

"Last scored" is the time of the last scoring change, not the `completed` status. The control is re-evaluated when an
assessment is created, changed, scored or deleted, and with the hourly scheduler pass (the vulnerability SLA check
re-evaluates compliance), so an assessment turns out of date after 12 months without anything else happening.

### Audit pack

`GET /api/frameworks/{id}/assessments/{aid}/audit-pack` (viewer) downloads a ZIP named
`atrium-<framework>-<assessment id>-<yyyymmdd>.zip`:

| File | Contents |
| --- | --- |
| `summary.html` | self-contained and printable (no scripts, no external files): scores per level, function and category, the conformity verdict per level with its reasons, gaps and key measures |
| `requirements.csv` | one row per requirement: both scores, maturity, N/A and justification, owner, notes, evidence (cells that start like a formula are quoted) |
| `evidence/index.csv` | every evidence link |
| `evidence/controls.json` | the hub controls' latest automated results and the requirements they map to |
| `evidence/items.json` | metadata of the linked policies, risks, URLs and files (never their content) |
| `assessment.json` | the assessment and its evaluation as data |
| `manifest.json` | SHA-256 and size of every file, the framework source and who exported it |
| `SHA256SUMS` | the same hashes, for `sha256sum -c` |

**No secrets.** The pack holds assessment data, control results and metadata only. Before any file is written, every
text taken from the hub's state is masked: the secret values the process knows, every tool connection's credentials,
and credential-looking `key=value` pairs. Each export writes an activity entry with the ZIP's SHA-256.

### The Frameworks tab

Routes: `#/compliance/frameworks[/<edition>[/<assessment>[/scores|gaps|details]]]` and
`#/compliance/frameworks/ext:<tool>:<id>` for a framework read from CISO Assistant. Ctrl K has "Frameworks (CyFun
self-assessment)".

**Edition page:**

- a switch between CyFun 2025 (current, the default) and CyFun 2023, with the transition note;
- the list of self-assessments with target level, status, progress, maturity, verdict per level and CISO Assistant
  sync state;
- the **catalog browser**: function, then category, then requirement, with B/I/E level tags and key-measure and
  management badges. It filters by level, key measures, management aspects, evidence status and text. For CyFun 2023
  it shows the 2025 requirements each one maps to.
- an **About** card: the source library, its version and date, the licensing notice and the conformity thresholds,
  labelled as taken from the CISO Assistant library copy (a warning style for 2023, which is unverified);
- a **CISO Assistant** card ([below](#ciso-assistant-framework-sync)).

**Assessment workspace:**

- a header with status actions (Mark completed, Reopen, Archive), Edit, **Audit pack** and Delete (admin);
- notices: archived, transition, older than 12 months (HB-PO-3), missing documentation scores;
- summary tiles, and a conformity card per level: verdict, maturity against its threshold, each rule with its value
  and reasons, and progress;
- views: **Requirements** (two 1-5 selectors per row that save at once), **Scores**, **Gaps & key measures** and
  **Details** (scoring method, scale, scope, notes, sync);
- a requirement editor: the scale descriptions, a live maturity preview, N/A with its justification, the owner picker,
  notes, evidence (add and remove), suggested hub controls with a **Link** button, and the change history.

Viewers read everything and download the audit pack. Operators start, edit and score assessments. Administrators
delete them. Changes made by others appear within about a second (SSE `framework_assessment`).

### Endpoints

| Endpoint | Role | Purpose |
| --- | --- | --- |
| `GET /api/frameworks` | viewer | the built-in catalogs (counts, transition, source, levels, conformity source, latest assessment) and the frameworks read from CISO Assistant, the maturity scale, the levels and the CISO Assistant sync status |
| `GET /api/frameworks/{id}` | viewer | a catalog's tree with tags and titles (never requirement text; `text_url` links to cyfun.eu), its conformity rules, suggested hub controls per requirement, assessments; for `ext:<tool>:<id>` the read-only framework from CISO Assistant |
| `GET /api/frameworks/{id}/assessments` | viewer | assessments of a catalog (brief: progress, verdict per level, stale) |
| `POST /api/frameworks/{id}/assessments` | operator | `{name, target_level, scope?, notes?, copy_from?}` -> 201; 400 for CyFun 2023 after 18 April 2027 |
| `GET /api/frameworks/{id}/assessments/{aid}` | viewer | the assessment with its full evaluation and every requirement |
| `PATCH /api/frameworks/{id}/assessments/{aid}` | operator | `{name?, target_level?, scope?, notes?, status?}`; 400 for a blank name; 409 for anything but `status` while archived |
| `PATCH /api/frameworks/{id}/assessments/{aid}/requirements/{ref}` | operator | only the fields sent change: `{implementation, documentation, na, na_justification, owner_person_id, notes, evidence}`; 409 when archived |
| `GET /api/frameworks/{id}/assessments/{aid}/audit-pack` | viewer | the ZIP (logged) |
| `DELETE /api/frameworks/{id}/assessments/{aid}` | admin | remove an assessment (logged as a warning) |
| `GET /api/grc` | viewer | control states and framework score tiles |
| `POST /api/grc/evaluate` | operator | re-evaluate now |
| `PATCH /api/grc/controls/{id}` | operator | `{status, note}` or `{clear: true}`: manual override |
| `GET` / `POST` / `PATCH` / `DELETE /api/grc/risks[/{id}]`, `/api/grc/policies[/{id}]` | viewer / operator | the risk register and policies |
| `GET /api/grc/policy-templates` | viewer | the policy templates |

SSE events: `framework_assessment`, `framework_assessment_removed`, `external_framework`,
`external_framework_removed`, `grc` (after control evaluation).

## CISO Assistant framework sync

A CISO Assistant connection ([INTEGRATIONS.md](INTEGRATIONS.md#ciso-assistant)) also carries two framework data
domains.

**`frameworks` (read).** The planner proposes a pull flow that reads every framework the instance has loaded:

- its requirement tree;
- its compliance assessments there, with the results per requirement and their scores (implementation,
  documentation, maturity);
- its mapping sets.

They are stored read-only in collection `external_frameworks` and removed with the tool or its connection. A tree is
shown at most 20 levels deep (a longer parent chain is flattened at the last level; nodes on a parent cycle appear at
the top), since the tool's data is untrusted.

- CyFun frameworks appear as the sync status of Atrium's own catalogs: which CyFun libraries are loaded, and the
  CISO Assistant assessments of them. The CCB's requirement text of the CyFun frameworks is not read into the hub.
- Every other framework (for example the CRA) appears in the Frameworks tab as a **read-only framework** with its
  requirement tree, its implementation groups, CISO Assistant's assessment status and results, and its mappings. Its
  names and descriptions are CISO Assistant's text, shown as text only.

**`assessments` (write), only when an administrator enables it.** The connection setting **Send CyFun
self-assessments** (`push_assessments`, off by default) makes the connector offer the domain, and only then does the
planner propose the push flow (after a successful connection test).

- Switching it off takes effect at once: the connection's capabilities are what the connector declares for its
  current settings, narrowed to what the last test reported, and saving the connection removes the push flow (an
  activity entry; sync links are kept). Switching it on again leads to a new proposal that needs a new approval.

- Each hub self-assessment that is not archived becomes a compliance assessment of the loaded CyFun framework in CISO
  Assistant, with `selected_implementation_groups` = the target level.
- Every requirement the hub scored is written with its result, both scores and an observation (N/A justification,
  notes, evidence references). Requirements the hub did not score are left alone.
- The result follows Atrium's own mapping:

  | Maturity | Result |
  | --- | --- |
  | N/A | not applicable |
  | at least the level's target (B 2.5, I and E 3.0) | compliant |
  | below 2.0 | non compliant |
  | in between | partially compliant |

**Libraries are never imported by Atrium.** Importing a library needs CISO Assistant rights. The connection test
reports which of CyFun 2025, CyFun 2023 and the CRA are loaded; import them in CISO Assistant yourself.

The round-3 corrections of the existing CISO Assistant connector:

- a hub control that is `partial` is sent as `in_progress`, or as `degraded` when the connection setting **Status of
  partially effective controls** says so (recent versions only; older ones refuse `degraded`);
- evidence is written with an observation holding the check result, so CISO Assistant keeps a revision (status in
  review) instead of an empty draft.

**Verified** against the CISO Assistant community source (main branch, read 2026-10-09): the `global_score` keys
(`implementation_score`, `documentation_score`, `maturity_score`), `computed_outcome` as a dict of rule results, and
`selected_implementation_groups` as a list of group ref_ids. **Unverified**: the fields CISO Assistant requires to
create a compliance assessment, and the folder it uses when none is sent. The connector sends name, framework,
version, status, observation, selected implementation groups and folder, and the first push shows a clear error if
they differ. Everything else ran only against `httpx.MockTransport` fakes; no real CISO Assistant instance was
contacted.

## Cyber Resilience Act (CRA)

The EU Cyber Resilience Act is **not built in**. It is available through the CISO Assistant sync: load CISO
Assistant's CRA library (`urn:intuitem:risk:library:cra-resolution-annexes`, version 3 of 2024-06-25) there, and it
appears read-only in the Frameworks tab.

**Caveat (unverified)**: the library's name and date suggest it was built from the **European Parliament's text**, not
the text published in the Official Journal (Regulation (EU) 2024/2847). Check requirement wording against the OJ text.
The API returns this as `caveat` on the framework, and the Frameworks tab shows it.

## Open points

- The CyFun conformity thresholds, the key-measure and management tags and the scoring method come from the CISO
  Assistant library copy. The CCB originals were unreachable (HTTP 403), so they are unverified, and the 2025 rules
  are applied to CyFun 2023 without a source.
- CISO Assistant's `main` branch moves quickly. Rerun `scripts/build_cyfun_catalog.py --check` after an update.
- The CCB's terms for reusing the CyFun ids and structure are unconfirmed (see [licensing](#what-the-catalogs-contain-licensing)).
