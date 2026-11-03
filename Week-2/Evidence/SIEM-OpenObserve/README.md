# DEPI P5 — Week 2 SIEM / OpenObserve Evidence

## 1. Purpose

This directory documents the SIEM alert detection and AI-assisted triage evidence collected during Week 2 of DEPI Project 5.

Pipeline:

OpenObserve SIEM → Alert/Webhook → Python Receiver → Evidence Validation → Local Ollama/Mistral AI → SOC Triage Report → Human Review.

The project distinguishes observed log evidence, detection-rule matches, AI-generated interpretations, automated QA findings, and human analyst decisions.

**Important:** A generated SOC report or successful AI-triage execution does not automatically establish that an attack succeeded or that human review is complete.

## 2. Alert Evidence Index

| Alert | Primary AI Evidence | Final SOC Report |
|---|---|---|
| SIEM05 — High-Rate HTTP Requests | [AI JSON](SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json) | [Technical SOC Report](../../DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx) |
| Alert 002 — SSH Brute Force | [AI JSON](SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json) | [SOC Report](../../Alert002_SSH_BruteForce_SOC_Report.md) |
| Alert 003 — Malware | [AI JSON](SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json) | [SOC Report](../../Results/SIEM06_MAL_003_FINAL/SIEM06_MAL_003_Final_SOC_Report.md) |
| Alert 004 — XSS | [AI JSON](SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json) | [SOC Report](SIEM07_XSS_004_Final_SOC_Report.md) |
| Alert 005 — Exchange | [AI JSON](SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json) | [SOC Report](../../Results/SIEM_EXCHANGE_005_Final_SOC_Report.md) |

## 3. Alert 002 — SSH Brute Force Screenshots

Location: `Alert002_Evidence_and_SOC_Report/Screenshots/`

| Screenshot | Evidence Description |
|---|---|
| [01_OpenObserve_2000_SSH_Events.png](Alert002_Evidence_and_SOC_Report/Screenshots/01_OpenObserve_2000_SSH_Events.png) | OpenObserve SSH dataset containing 2,000 events. |
| [02_OpenObserve_SQL_Detection_Preview.png](Alert002_Evidence_and_SOC_Report/Screenshots/02_OpenObserve_SQL_Detection_Preview.png) | SQL detection query preview before saving the alert. |
| [03_Alert_002_Saved.png](Alert002_Evidence_and_SOC_Report/Screenshots/03_Alert_002_Saved.png) | Saved SSH brute-force alert configuration. |
| [04_SIEM06_AI_TRIAGE_PASS.png](Alert002_Evidence_and_SOC_Report/Screenshots/04_SIEM06_AI_TRIAGE_PASS.png) | Recorded AI-triage execution/validation result; does not independently imply human approval. |

Additional packaged documentation:
[Alert 002 README](Alert002_Evidence_and_SOC_Report/README.md).

## 4. Alert 003 — Malware Screenshots

Location: `Alert-003-Malware/Screenshots/`

| Screenshot | Evidence Description |
|---|---|
| [003-01-Malware-Dataset-Source.png](Alert-003-Malware/Screenshots/003-01-Malware-Dataset-Source.png) | Malware dataset source reference. |
| [003-02-EVTX-Initial-Inspection.png](Alert-003-Malware/Screenshots/003-02-EVTX-Initial-Inspection.png) | Initial inspection of Windows EVTX records. |
| [003-03-Sysmon-EventID-Distribution.png](Alert-003-Malware/Screenshots/003-03-Sysmon-EventID-Distribution.png) | Distribution of observed Sysmon event IDs. |
| [003-04-Key-Sysmon-Events.png](Alert-003-Malware/Screenshots/003-04-Key-Sysmon-Events.png) | Selected Sysmon records relevant to the investigation. |
| [003-05-Malware-JSON-Validation.png](Alert-003-Malware/Screenshots/003-05-Malware-JSON-Validation.png) | Validation of the prepared malware JSON evidence. |
| [003-07-Malware-Stream-Verified.png](Alert-003-Malware/Screenshots/003-07-Malware-Stream-Verified.png) | Verification of the malware log stream in OpenObserve. |
| [003-11-Malware-Final-Detection-SQL.png](Alert-003-Malware/Screenshots/003-11-Malware-Final-Detection-SQL.png) | Final recorded SQL detection query. |

Supporting dataset:
[Key Sysmon Events CSV](Alert-003-Malware/003-04-Key-Sysmon-Events.csv).

## 5. Alert 004 — XSS Screenshots

Location: `Screenshots/SIEM07_WEB_004_XSS/`

| Screenshot | Evidence Description |
|---|---|
| [SIEM07_01_XSS_Dataset_Analysis.png](Screenshots/SIEM07_WEB_004_XSS/SIEM07_01_XSS_Dataset_Analysis.png) | Inspection and analysis of the XSS dataset. |
| [SIEM07_02_XSS_Detection_Query.png](Screenshots/SIEM07_WEB_004_XSS/SIEM07_02_XSS_Detection_Query.png) | XSS detection query in OpenObserve. |
| [SIEM07_03_XSS_Detection_Preview_PASS.png](Screenshots/SIEM07_WEB_004_XSS/SIEM07_03_XSS_Detection_Preview_PASS.png) | Detection preview and recorded PASS result. |
| [SIEM07_02_XSS_Alert_Created.png](Screenshots/SIEM07_WEB_004_XSS/SIEM07_02_XSS_Alert_Created.png) | Creation of the XSS alert. |
| [SIEM07_02_XSS_Webhook_Delivery_SUCCESS.png](Screenshots/SIEM07_WEB_004_XSS/SIEM07_02_XSS_Webhook_Delivery_SUCCESS.png) | Recorded successful webhook delivery. |
| [Screenshot 2026-10-30 163152.png](Screenshots/SIEM07_WEB_004_XSS/Screenshot%202026-10-30%20163152.png) | Additional XSS workflow screenshot; exact content requires visual verification. |

Additional XSS triage records:

- [XSS Triage — 843425fa737b11ef71](SIEM07_XSS_004_AI_Triage_843425fa737b11ef71.json)
- [XSS Triage — fad10ea2b71bb2bc09](SIEM07_XSS_004_AI_Triage_fad10ea2b71bb2bc09.json)

These files represent distinct analysis records and must not be treated as exact duplicates without event-identity verification.

## 6. SIEM05 — HTTP Evidence

Primary evidence:
[SIEM05 AI Triage JSON](SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json).

Additional retained records:

- [SIEM04 Real Alert AI Triage](SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json)
- [SIEM05 Controlled AI Reanalysis](SIEM05_Controlled_AI_Reanalysis_20261023.json)

The HTTP case includes a controlled replay. A detection-rule match is not, by itself, proof of malicious intent or successful exploitation.

HTTP-related screenshots are maintained elsewhere in the Evidence tree and are not inventoried individually in this README.

## 7. Alert 005 — Exchange Evidence

Primary evidence:
[Exchange AI Triage JSON](SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json).

Final report:
[Exchange SOC Report](../../Results/SIEM_EXCHANGE_005_Final_SOC_Report.md).

A separate human-review record may be present under Results. Its existence must not be interpreted as analyst approval without checking its recorded decision.

No Exchange-specific screenshots were identified in the SIEM directory inventory used to prepare this README.

## 8. QA and Human Validation

AI output must be evaluated against the original log evidence.

Expected review controls include:

- Event and evidence-reference verification.
- Timestamp consistency.
- Unsupported inference detection.
- Semantic warnings and QA status.
- Human validation of conclusions and recommended actions.

`REVIEW_REQUIRED` and `human_validation_required=true` indicate that analyst validation is necessary; they are not automatically pipeline failures.

## 9. Evidence Preservation

Do not modify original AI-triage JSON files to improve report wording or remove QA warnings.

Do not replace distinct historical analysis records with a newer result.

Preserve original timestamps, event identifiers, and evidence provenance.

Historical replay evidence must be identified as replay rather than presented as live attack telemetry.

## 10. Archive and Restoration

Exact duplicate evidence files were archived after SHA256 verification.

Archive manifest:

`../../Archive/10-Evidence-Deduplication/Manifests/Evidence-Archive-20261103-002343.csv`

The archive operation preserved 71 files, with 71 successful post-archive integrity checks.

Archived files remain recoverable using their recorded original and archive paths.

## 11. Remaining Review Items

- Verify the exact contents of any screenshots whose names do not establish their meaning.
- Confirm the final human-review decisions for the five alerts.
- Validate the final Week-2 delivery package against project requirements.
- Do not represent pending human validation as completed approval.
