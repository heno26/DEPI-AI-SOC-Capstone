# DEPI Project 5 — Week 2 | AI-Assisted SOC Log Analysis & SIEM Alert Triage

## Week-2 Final Implementation Status (2026-11-03)

**Status:** Five OpenObserve alert scenarios have primary AI-triage JSON evidence and SOC reports. Final Week-2 acceptance remains pending.

### Implemented workstreams

- **File-based SOC:** Windows, Linux and Network log analysis with local Ollama/Mistral, evidence grounding and validation.
- **Unified SOC:** Mixed-source log classification and analysis; v0.4 remains a QA candidate, not production-approved.
- **OpenObserve SIEM:** Historical lab/replay alerts delivered through authenticated webhooks to Python receivers for evidence verification, AI triage and SOC reporting.
- **Human-in-the-loop:** AI findings are advisory; analyst approval remains required.

### Five SIEM alert deliverables

| Alert | Detection rule | Primary evidence | SOC report |
|---|---|---|---|
| HTTP 001 | SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS | Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json | DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx |
| SSH 002 | SIEM_AUTH_002_SSH_BRUTE_FORCE | Evidence/SIEM-OpenObserve/SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json | Alert002_SSH_BruteForce_SOC_Report.md |
| Malware 003 | SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR | Evidence/SIEM-OpenObserve/SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json | Results/SIEM06_MAL_003_FINAL/SIEM06_MAL_003_Final_SOC_Report.md |
| XSS 004 | SIEM_WEB_004_XSS_ATTACK_DETECTED | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_Final_SOC_Report.md |
| Exchange 005 | SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT | Evidence/SIEM-OpenObserve/SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json | Results/SIEM_EXCHANGE_005_Final_SOC_Report.md |

See Evidence/SIEM-OpenObserve/README.md for the evidence index and screenshot descriptions.

### Receiver architecture

- SIEM05: HTTP 001; localhost port 8765, endpoint /depi-alerts.
- SIEM06: HTTP 001, SSH 002, Malware 003; same listener address and endpoint.
- SIEM07 candidate: HTTP 001, SSH 002, Malware 003, XSS 004; same listener address and endpoint.
- Exchange 005: separate localhost port 8766, endpoint /depi-exchange-alerts.

SIEM05, SIEM06 and SIEM07 are alternative listeners on the same address/port, not three simultaneously running services. SIEM07 contains outdated SIEM06 startup text. The currently active receiver process has not been established by this documentation audit.

### Outstanding acceptance items

- Human SOC analyst approval is pending; REVIEW_REQUIRED is an expected review state, not final approval.
- Updated SIEM05 end-to-end regression and exact alert-to-112-request-group correlation are not proven.
- Historical replay is not production monitoring; reports do not establish successful compromise.
- Wazuh is legacy/synthetic file-based context, not the demonstrated SIEM integration. OpenObserve is the actual SIEM used.
- Week 3 SOAR and Week 4 full incident response are not implemented here.

### Related technical documentation

- README_UNIFIED_SOC.md — Unified SOC intake design.
- README_V04.md — v0.4 candidate changes and QA limitations.
- Documentation/Integration-Workflow.md — workflow documentation (pending update).
- Documentation/Week-2-Testing-Guide.md — testing documentation (pending update).

---

> **Documentation draft for review — 24 October 2026.**
> This README describes the demonstrated workflow and the current project layout. It is **not** a certification of production readiness or a claim that every local test has been rerun after file organization.

## 1. Project objective

Build a human-in-the-loop SOC workflow that reads Windows, Linux, and network security evidence, analyses it with a **local Mistral model through Ollama**, checks AI-generated claims against source evidence, and produces structured triage reports. A separate OpenObserve integration demonstrates the path from a SIEM detection alert to an AI-assisted SOC report.

**Human review remains mandatory.** AI conclusions are advisory; the project does not autonomously block IPs, isolate systems, or remediate incidents.

## 2. What was implemented

| Workstream | Implemented / demonstrated | Important limitation |
|---|---|---|
| File-based log analysis | Python entry point, parsers, evidence-aware prompts, analysis, validation, review and report storage | Case and model results must be interpreted alongside their source evidence. |
| Windows cases | Attack and benign datasets, preparation scripts, evaluation and case evidence | Not all logs are live SIEM alerts. |
| Linux cases | SSH, privilege escalation, suspicious execution and benign-operation case work | Case datasets are collected/replayed, not proof of live compromise. |
| Network cases | Port scanning, DNS anomaly and C2-beaconing-related case work | Observed patterns are not inherently proof of malice. |
| OpenObserve SIEM demonstration | Apache access logs indexed, SQL alert configured, webhook delivered, local AI receiver and JSON triage produced | **Historical log replay**, not live production monitoring. |
| Wazuh | Guide and simulated Wazuh fixture workflow available | **Real Wazuh alert integration not demonstrated here.** |
| SOAR / full IR | Planned for subsequent project weeks | **Not implemented as part of Week 2.** |

## 3. Architecture

### A. File-based analysis

```text
Windows / Linux / Zeek network log files
    -> app.py + Core parsers and analysis
    -> Ollama (local Mistral 7B)
    -> evidence grounding + validation
    -> analyst review
    -> Results/ + Validation/ + case evidence
```

### B. SIEM alert-to-report demonstration

```text
Historical Apache access-log replay
    -> OpenObserve (depi_web_access)
    -> SQL alert: SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS
    -> authenticated local webhook
    -> Integrations/SIEM-OpenObserve/SIEM05_Auto_Triage_Receiver.py
    -> source-evidence lookup + local Ollama Mistral
    -> structured AI triage JSON
    -> REVIEW_REQUIRED / human SOC analyst
```

The SIEM detection uses an elevated request-rate threshold (**80 or more requests per original log minute**, grouped by source IP). The example reviewed contained **112 requests** for one original minute. A high request rate is an investigation lead, **not proof that the source is malicious**. The reported source address belongs to a special-use/non-global range; do not describe it as a normal public attack host or a confirmed internal workstation.

## 4. Where to find the important files

Paths below are relative to the `Week-2/` folder. The layout is intentionally preserved so work on the SIEM can resume without unnecessary path changes.

| Location | Purpose |
|---|---|
| [`app.py`](app.py), [`config.py`](config.py), [`requirements.txt`](requirements.txt) | File-analysis application entry point, settings and dependencies. |
| [`Core/`](Core/) | Active parsers, analysis, validator, AI client and related semantics. **Do not replace with old package payloads.** |
| [`Prompts/`](Prompts/) | Current prompt templates and change notes. |
| [`Data/`](Data/) | Original datasets, synthetic fixtures, Windows/Linux/network case studies. Preserve provenance. |
| [`Testing/`](Testing/) | Unit, regression and replay validators. |
| [`Validation/`](Validation/) | Hallucination checks and analyst review records. |
| [`Detection/`](Detection/) | Detection-improvement documentation. |
| [`Integrations/SIEM-OpenObserve/`](Integrations/SIEM-OpenObserve/) | SIEM pipeline and receiver scripts; SIEM05 is the main automated triage receiver. |
| [`Evidence/OpenObserve/Screenshots/`](Evidence/OpenObserve/Screenshots/) | SIEM setup, ingest, detection, webhook and automated-triage screenshots. |
| [`Evidence/SIEM-OpenObserve/`](Evidence/SIEM-OpenObserve/) | Original JSON outputs of SIEM04 and SIEM05, plus controlled reanalysis. |
| [`Results/`](Results/) | Stored analysis runs and reports; not all runs are final selections. |
| [`Documentation/`](Documentation/) | Workflow, Windows testing and review guides. |
| [`Archive/`](Archive/) | Historical backups and installer/development packages retained for recovery, not active code. |

### SIEM files to use in the presentation

**Primary automated JSON evidence** (shows the original automated result):

- [`Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json`](Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json) — primary SIEM05 result, **`qa_status: REVIEW_REQUIRED`**.

**Related outputs** (keep separate; do not swap them into the main evidence without explanation):

- [`Evidence/SIEM-OpenObserve/SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json`](Evidence/SIEM-OpenObserve/SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json) — earlier SIEM04 stage.
- [`Evidence/SIEM-OpenObserve/SIEM05_Controlled_AI_Reanalysis_20261023.json`](Evidence/SIEM-OpenObserve/SIEM05_Controlled_AI_Reanalysis_20261023.json) — controlled AI reanalysis, **not** a new end-to-end SIEM test (`end_to_end_acceptance: NOT_TESTED_IN_THIS_REANALYSIS`).

**Human-readable report:**

- [`DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx`](DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx) — presentation-ready technical writeup with documented limitations.
- [`DEPI_P5_SIEM05_SOC_Alert_Report_DRAFT.docx`](Documentation/Drafts/DEPI_P5_SIEM05_SOC_Alert_Report_DRAFT.docx) — older draft; retained for revision history.

**OpenObserve screenshot evidence:**

- `Evidence/OpenObserve/Screenshots/SIEM01-OpenObserve-First-Launch-PASS.png`
- `Evidence/OpenObserve/Screenshots/SIEM02-Apache-3872-Logs-Dashboard-PASS.png`
- `Evidence/OpenObserve/Screenshots/SIEM03-SQL-Detection-Editor.png`
- `Evidence/OpenObserve/Screenshots/SIEM03-Alert-Webhook-Delivery-Verified-PASS.png`
- `Evidence/OpenObserve/Screenshots/SIEM05_Automatic_AI_Triage_PASS.png`
- `Evidence/OpenObserve/Screenshots/SIEM05_Authenticated_Webhook_Dedup_PASS.png`

A detailed screenshot-by-screenshot index can be stored at [`Evidence/OpenObserve/README.md`](Evidence/OpenObserve/README.md). **Check that this file was copied into the local project before relying on the link.**

## 5. How to explore the existing application (PowerShell)

From the local Week 2 folder:

```powershell
Set-Location "D:\Desktop\w\Week-2"
python app.py check   # show current local model availability; requires Ollama
python app.py         # launch the file-analysis interface
```

Other commands already documented by the application include `analyze`, `triage`, `detect`, `review`, `list`, `export`, and `sanitize`. Consult `python app.py --help` or application help before invoking commands. **Do not replay SIEM log ingestion to tidy files**; 3,872 Apache records were previously ingested for the demonstration and replaying them blindly can duplicate events and alter alert counts.

The OpenObserve receiver requires its configured local environment, webhook authentication and model service. **It is not started during file cleanup.** Do not paste tokens, webhook credentials or secrets into this README, screenshots or shared reports.

## 6. Interpreting the final SIEM result

The automated report uses **`REVIEW_REQUIRED`**, meaning the AI analysis needs an analyst to validate source attribution, event semantics and the proposed severity. It does **not** mean an incident was proven malicious and does **not** mean an E2E acceptance test was passed after every subsequent code change.

The Apache data were a **replay dataset**, not live production traffic. Distinguish source-log timestamps from alert generation timestamps. Evidence matching does not automatically prove a unique row-by-row alert/group attribution unless that join is explicitly demonstrated.

## 7. Deliverable map

1. **AI-assisted analysis** — core file-based workflow; relevant case studies and stored results.
2. **Alert triage** — Wazuh synthetic examples in file-based mode, plus the OpenObserve webhook-to-AI demonstration.
3. **Detection improvements** — [`Detection/Detection-Improvement-Notes.md`](Detection/Detection-Improvement-Notes.md) and detection/validation code.
4. **Hallucination and validation records** — [`Validation/`](Validation/), regression tests and review metadata.
5. **SIEM supporting evidence** — `Evidence/OpenObserve/`, `Evidence/SIEM-OpenObserve/` and the SIEM05 technical report.

The older [`Week-2-Final-Report.md`](Week-2-Final-Report.md) and earlier README may describe the initial build phase and should **not** be treated as more recent evidence than the dated SIEM05 JSON and technical report without review.

## 8. Project organization and safeguards

- `Core/`, `Data/`, `Evidence/`, `Integrations/`, `Testing/`, `Results/` remain in place.
- Superseded `*.bak` files and selected installers/development packages are retained under `Archive/`; historical payloads are **not** the live application by default.
- The archive manifest records original locations and SHA-256 values. **Regenerate/refresh it after archiving additional packages**, because earlier manifests are snapshots and not self-updating.
- Keep original logs and evidence manifests. Do not change file paths used by case studies, regression tests or SIEM integrations without a dependency check.
- Before presenting screenshots, mask access tokens, webhook secrets and other credentials.

## 9. What remains

Week 2 SIEM **demonstration evidence exists**, while SIEM integration can still be refined and revalidated when active development resumes. Wazuh live integration and production deployment are not claimed. Later-week SOAR orchestration and full incident response are outside this Week 2 implementation and should not be represented as complete.
