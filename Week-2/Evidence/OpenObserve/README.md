# DEPI P5 — Week 2 | OpenObserve & SIEM Evidence Guide

**Project:** AI-Assisted SOC Automation / SIEM Alert Triage  
**Evidence area:** `Week-2/Evidence/OpenObserve/`  
**Related machine-readable reports:** `Week-2/Evidence/SIEM-OpenObserve/`  
**Prepared:** 23 October 2026  
**Scope:** SIEM01–SIEM05 evidence inventory and presentation guide.

> **Evidence standard:** The entries below describe the *purpose and recorded result* of each named screenshot, using the screenshot inventory and the documented SIEM workflow. Individual screenshot pixels were not supplied separately for this audit, so do not treat these captions as an independent re-verification of every on-screen detail. Labels such as `PASS` describe the particular test in the filename, **not** blanket end-to-end acceptance.

## 1. Folder layout — keep BOTH folders

```text
Week-2/
└── Evidence/
    ├── OpenObserve/
    │   ├── README.md                    <-- this guide
    │   ├── Screenshots/                 <-- 25 visual evidence images
    │   └── Final-Verification/         <-- empty in the 23-Oct inventory
    └── SIEM-OpenObserve/               <-- 3 JSON reports (machine-readable evidence)
```

**Do not delete or merge these folders.** `OpenObserve/Screenshots/` contains visual proof of setup, detection, delivery, and receiver checks; `SIEM-OpenObserve/` contains the actual extracted AI / SOC data. They serve different purposes. The empty `Final-Verification/` folder can remain empty; it is not an additional test requirement.

## 2. The 25 screenshot records

Click a filename to open the image when viewing this README from `Evidence/OpenObserve/`.

### SIEM01 — Install and launch OpenObserve (4)

| Screenshot | What happened / why it was recorded |
|---|---|
| [SIEM01-OpenObserve-OSS-Windows-Selection-PASS.png](Screenshots/SIEM01-OpenObserve-OSS-Windows-Selection-PASS.png) | Selected the OpenObserve open-source Windows setup for the local SIEM laboratory. Documents the chosen platform and setup route. |
| [SIEM01-OpenObserve-Extraction-PASS.png](Screenshots/SIEM01-OpenObserve-Extraction-PASS.png) | Extracted/prepared OpenObserve files. Captures the local installation-preparation checkpoint. |
| [SIEM01-OpenObserve-First-Launch.png](Screenshots/SIEM01-OpenObserve-First-Launch.png) | Recorded the first-start process before confirming the usable interface; this is a progress screenshot, not the strongest completion proof. |
| [SIEM01-OpenObserve-First-Launch-PASS.png](Screenshots/SIEM01-OpenObserve-First-Launch-PASS.png) | Recorded successful first launch and accessibility of the OpenObserve interface. **Recommended setup evidence.** |

### SIEM02 — Prepare and ingest Apache access logs (6)

| Screenshot | What happened / why it was recorded |
|---|---|
| [SIEM02-Web-Logs-Source-Integrity-PASs.png](Screenshots/SIEM02-Web-Logs-Source-Integrity-PASs.png) | Checked the Apache dataset source and its integrity before replay. The ingestion script enforces a fixed ZIP SHA-256 and expected **3,872** records. |
| [SIEM02-Web-Logs-ZIP-Content-Inspection.png](Screenshots/SIEM02-Web-Logs-ZIP-Content-Inspection.png) | Inspected the ZIP structure and identified the target Apache `web-access.log` input without using ground-truth labels to instruct the AI. |
| [SIEM02-Web-Traffic-Behavioral-Inspection.png](Screenshots/SIEM02-Web-Traffic-Behavioral-Inspection.png) | Explored request patterns in the Apache logs to understand normal and high-volume web activity before selecting a detection rule. |
| [SIEM02-Web-Peak-Traffic-Verification-PASS.png](Screenshots/SIEM02-Web-Peak-Traffic-Verification-PASS.png) | Verified a concentrated HTTP request group used to motivate the high-rate rule. The later SIEM05 alert group contained **112 requests**. |
| [SIEM02-OpenObserve-Token-Management.png](Screenshots/SIEM02-OpenObserve-Token-Management.png) | Records local API/token setup for log ingestion. **Redact or omit this screenshot in public presentations if credentials are visible.** |
| [SIEM02-Apache-3872-Logs-Dashboard-PASS.png](Screenshots/SIEM02-Apache-3872-Logs-Dashboard-PASS.png) | Shows the OpenObserve logs/dashboard result after the **3,872-record** Apache replay workflow. **Recommended data-ingestion evidence.** |

### SIEM03 — Detection rule and alert delivery (4)

| Screenshot | What happened / why it was recorded |
|---|---|
| [SIEM03-SQL-Detection-Editor.png](Screenshots/SIEM03-SQL-Detection-Editor.png) | Configured the OpenObserve SQL alert on `depi_web_access`: group HTTP access events by `src_ip` and `original_minute_utc` and use **`HAVING COUNT(*) >= 80`**. The threshold was **not** lowered for the test. |
| [SIEM03-Local-Webhook-Connectivity-PASS.png](Screenshots/SIEM03-Local-Webhook-Connectivity-PASS.png) | Checked that the local webhook receiver endpoint could be reached. Connectivity alone does not prove finished AI processing. |
| [SIEM03-Webhook-Destination-Test-PASS.png](Screenshots/SIEM03-Webhook-Destination-Test-PASS.png) | Tested OpenObserve's webhook destination configuration. A destination test is distinct from proving a genuine rule-firing event was fully triaged. |
| [SIEM03-Alert-Webhook-Delivery-Verified-PASS.png](Screenshots/SIEM03-Alert-Webhook-Delivery-Verified-PASS.png) | Recorded successful alert/webhook delivery verification. **Recommended handoff evidence** for OpenObserve-to-receiver integration. |

### SIEM04 — Read-only alert investigation (3)

| Screenshot | What happened / why it was recorded |
|---|---|
| [SIEM04_Real_Alert_AI_Triage_PASS_ReviewRequired.png](Screenshots/SIEM04_Real_Alert_AI_Triage_PASS_ReviewRequired.png) | Demonstrates an alert investigation and Mistral-assisted triage output. The output still required **human review**; the filename does not mean the incident was confirmed malicious. |
| [SIEM04_STEP42_Receiver_Code_Inspection_PASS.png](Screenshots/SIEM04_STEP42_Receiver_Code_Inspection_PASS.png) | Documents inspection of the receiving/integration code in the earlier SIEM04 stage. Useful as engineering traceability, not essential for the main presentation. |
| [SIEM04_STEP42_Integration_Inspection_PASS.png](Screenshots/SIEM04_STEP42_Integration_Inspection_PASS.png) | Documents the SIEM04 integration inspection before the final SIEM05 automation. Historical intermediate-stage evidence. |

### SIEM05 — Automated AI alert triage (8)

| Screenshot | What happened / why it was recorded |
|---|---|
| [SIEM05_Structured_Alert_Template_Created_PASS.png](Screenshots/SIEM05_Structured_Alert_Template_Created_PASS.png) | Configured the structured webhook payload so the receiver can identify the rule, stream, and result rows. The deployed template contains `alert_name`, `stream_name` and a `rows` JSON string. |
| [SIEM05_Automation_Script_Syntax_PASS.png](Screenshots/SIEM05_Automation_Script_Syntax_PASS.png) | Checked the SIEM05 Python automation script's syntax. This is a code-health checkpoint, not proof that a new alert was analyzed. |
| [SIEM05_Automatic_Receiver_Startup_PASS.png](Screenshots/SIEM05_Automatic_Receiver_Startup_PASS.png) | Recorded startup of the local SIEM05 receiver at `127.0.0.1:8765/depi-alerts`, which queues valid webhook notifications for later processing. |
| [SIEM05_Automatic_AI_Triage_PASS.png](Screenshots/SIEM05_Automatic_AI_Triage_PASS.png) | Documents an automated alert-to-Mistral processing result. The stored report verifies **112 HTTP requests** and records **`qa_status=REVIEW_REQUIRED`**. **Recommended automation evidence.** |
| [SIEM05_Semantic_Validation_Receiver_Restart_PASS.png](Screenshots/SIEM05_Semantic_Validation_Receiver_Restart_PASS.png) | Shows receiver restart/check after semantic guardrails were updated. This does **not** alone prove a post-update alert was processed end to end. |
| [SIEM05_Payload_Regression_PASS.png](Screenshots/SIEM05_Payload_Regression_PASS.png) | Documents webhook payload-validation regression checks and the receiver's acceptance/rejection rules. A `202 queued` acknowledgment is not equivalent to completed AI triage. |
| [SIEM05_Final_Integration_Readiness_PASS.png](Screenshots/SIEM05_Final_Integration_Readiness_PASS.png) | Documents final **readiness** checks for the receiver/integration. Treat readiness as separate from a newly repeated end-to-end acceptance test. |
| [SIEM05_Authenticated_Webhook_Dedup_PASS.png](Screenshots/SIEM05_Authenticated_Webhook_Dedup_PASS.png) | Documents authenticated webhook handling and duplicate notification protection. The old event can return `200 duplicate` without creating another AI report. **Recommended security/reliability evidence.** |

**Screenshot count: 4 + 6 + 4 + 3 + 8 = 25.**

## 3. JSON evidence — the second folder is essential

The following files should remain **unchanged** under `../SIEM-OpenObserve/`:

| Report | Role | Interpretation |
|---|---|---|
| [SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json](../SIEM-OpenObserve/SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json) | Earlier SIEM04 real-alert triage result | Historical stage output; preserve as evidence of the progression to SIEM05. |
| [SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json](../SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json) | **Primary automated SIEM05 report** | Original automated detection + AI analysis; **112 verified requests**, **QA = `REVIEW_REQUIRED`**, human validation required. |
| [SIEM05_Controlled_AI_Reanalysis_20261023.json](../SIEM-OpenObserve/SIEM05_Controlled_AI_Reanalysis_20261023.json) | Separate controlled Mistral re-analysis | Records an improved description of the special-use/non-global source IP and remaining reasoning weaknesses. **Not** a new end-to-end webhook execution. |

The SIEM05 report links to an event group with **112 Apache requests** (88 `GET 200`, 14 `POST 200`, 10 `GET 302`) at original minute **2025-10-07 02:14 UTC**. The source IP is `255.102.154.224`, classified by Python as reserved/non-global. This was **replayed historical traffic**, not a verified real-world attack. The source-trigger record was `firing`, but an exact row-level trigger-to-group join was not proven.

**Do not present `REVIEW_REQUIRED` as `FAIL` or as `FULLY APPROVED`.** The workflow produced an analysis/report, while SOC analyst sign-off and the earlier correlation limitations remain separate concerns.

## 4. What to show in the DEPI presentation (minimal sequence)

The presentation does **not** need all 25 images. Use this small, logical chain; keep the rest in the evidence repository for questions.

1. **OpenObserve is running** — [`SIEM01-OpenObserve-First-Launch-PASS.png`](Screenshots/SIEM01-OpenObserve-First-Launch-PASS.png).
2. **Apache logs are available in SIEM** — [`SIEM02-Apache-3872-Logs-Dashboard-PASS.png`](Screenshots/SIEM02-Apache-3872-Logs-Dashboard-PASS.png).
3. **The detection rule exists** — [`SIEM03-SQL-Detection-Editor.png`](Screenshots/SIEM03-SQL-Detection-Editor.png); explain **80 requests** per grouped minute.
4. **Alert webhook delivery is demonstrated** — [`SIEM03-Alert-Webhook-Delivery-Verified-PASS.png`](Screenshots/SIEM03-Alert-Webhook-Delivery-Verified-PASS.png).
5. **Automatic Mistral triage runs** — [`SIEM05_Automatic_AI_Triage_PASS.png`](Screenshots/SIEM05_Automatic_AI_Triage_PASS.png); show the **primary SIEM05 JSON report** as the authoritative result.
6. **Reliability/security controls** — [`SIEM05_Authenticated_Webhook_Dedup_PASS.png`](Screenshots/SIEM05_Authenticated_Webhook_Dedup_PASS.png).
7. **Analyst conclusion** — the final SOC report: **detection of a request-rate anomaly, AI-assisted hypotheses, human review required, no proven compromise**.

**One-slide takeaway:** `Apache replay logs → OpenObserve alert (threshold 80) → authenticated webhook → SIEM05 evidence verification → local Mistral 7B triage → JSON/SOC report`.

## 5. Technical settings snapshot (read-only documentation)

| Item | Recorded configuration |
|---|---|
| Alert rule | `SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS` |
| Stream | `depi_web_access` |
| Detection condition | `COUNT(*) >= 80`, grouped by `src_ip` and `original_minute_utc` |
| Alert type | Scheduled; simple aggregation |
| Evaluation | Every 10 minutes; 2,880-minute (48-hour) lookback |
| Notification cooldown | 60 minutes |
| Destination | `DEPI_SOC_Webhook` → local HTTP POST `http://127.0.0.1:8765/depi-alerts` |
| Authentication | `X-DEPI-Webhook-Key` header; never disclose the value |
| Message template | `DEPI_SOC_Structured` |
| AI model | `mistral:7b-instruct-v0.3-q4_K_S` on local Ollama |

## 6. Data integrity, redaction and limitations

- **Preserve originals.** Do not rename/delete the three SIEM JSON files or the screenshot evidence during cleanup; they document different stages/results.
- **Mask secrets.** Before presenting or sharing, inspect images that show authentication headers, API tokens, or configuration panels; crop/redact any sensitive values.
- **Separate evidence from interpretation.** The 112-request count is log-derived; scraping/brute-force/host compromise are *unconfirmed hypotheses* unless further evidence is supplied.
- **Source-IP caution.** `255.102.154.224` is reserved/non-global; calling it a verified internal network host or attacker would overstate the evidence.
- **Replay caution.** The source event dates are historical; OpenObserve triggering/report generation occurred later, during replay/integration work.
- **Correlation caution.** Matching the alert rule and verified counts does not establish a unique alert-row ID join in the saved SIEM05 report.
- **Validation caution.** The separate Mistral re-analysis improved one IP-classification error but did not re-prove a complete post-update SIEM05 end-to-end run.

## 7. Evidence status and maintenance

**Workflow objective achieved in the recorded run:** OpenObserve alert was passed through the receiver, Mistral analyzed the evidence, and a JSON report was produced. **SOC verdict:** `REVIEW_REQUIRED`, with documented uncertainty and limitations. This README is an **index and presentation guide**, not a new acceptance certificate.

For future cleanup, keep one authoritative visual folder (`OpenObserve/Screenshots`) and one structured-results folder (`SIEM-OpenObserve`). Archive only genuinely redundant installation bundles or duplicate copies after hash/content comparison; do not discard the primary evidence above.
