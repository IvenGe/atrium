# Compliance

## Frameworks

Atrium ships CyFun 2025 (the default) and CyFun 2023. Catalogs store a requirement id, its place in the tree, level tags and a short title. They do not ship the CCB requirement text. The text stays on cyfun.eu. Titles are NIST CSF names or short neutral titles.

CyFun 2023 stays available for new assessments until 18 April 2027. The catalog header records the source library URN, version and publication date. Conformity thresholds are taken from the CISO Assistant library copy of the rules, because the CCB originals were not reachable when the catalogs were built. The UI and the audit pack say so.

An assessment has a target level (Basic, Important or Essential). Each requirement has an implementation score and a documentation score from 1 to 5, or N/A with a justification, plus an owner, notes and evidence links. Maturity is the average of the two scores. The hub never sets a score from a control result. Mapped hub controls are suggested evidence only.

The audit pack is a ZIP: `summary.html`, `requirements.csv`, an evidence index, `assessment.json`, and a manifest of SHA-256 hashes. Export is logged. Deleting an assessment is an administrator action.

CRA is not built in. It appears when a CISO Assistant connection has the CRA library loaded. Other imported frameworks are read-only.

## Hub controls

Automated controls live in `hub/grc/baseline.py`. Each one names the ISO 27001, SOC 2 and NIS2 clauses it supports, and CyFun 2025 / 2023 requirement ids where a mapping exists. Those reference strings are analyst mappings; they are not a certification.

Network controls:

| Id | What it checks |
|---|---|
| HB-NW-1 | Segmentation policy, from an approximate reading of the rules |
| HB-NW-2 | Unexplained drift |
| HB-NW-3 | Management not exposed to the internet |
| HB-NW-4 | A configuration backup in the last 7 days |
| HB-NW-5 | No any-to-any pass rule, and pass rules have a description |
| HB-CM-3 | Network changes need a second person, a backup and a maintenance window |

HB-PO-3 checks that a framework self-assessment exists, is younger than a year, and is not below its key-measure target.

Relaxing a guardrail that names a control is reflected in that control. Turning device changes on is logged as a warning. It does not by itself fail a control. Turning off the second person or the backup fails HB-CM-3. Turning off the maintenance window makes it partial. An emergency apply is counted as an exception.
