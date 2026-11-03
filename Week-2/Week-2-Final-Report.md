# Week 2 Final Report - AI for Log Analysis, Triage & Detection

## Final Implementation & Acceptance Status - 03 November 2026

**Overall status: IMPLEMENTED / DOCUMENTED - FINAL ACCEPTANCE PENDING.**

This section records the later Week-2 implementation and evidence audit. The original sections below are retained as a historical development and testing record. Earlier PENDING statements describe their original checkpoints and do not automatically reflect the latest implementation.

### 1. Implemented architecture

Two distinct workflows were developed:

- **File-based SOC analysis:** Windows, Linux and Network logs are parsed, grounded against evidence, analyzed with local Ollama/Mistral and subjected to validation and human review.
- **OpenObserve SIEM alert triage:** Historical lab/replay data are indexed in OpenObserve. Detection alerts are delivered through authenticated webhooks to Python receivers, verified against source evidence and processed into AI-assisted SOC reports.

Wazuh was part of the initial architecture and synthetic file-based testing. **OpenObserve replaced Wazuh as the demonstrated SIEM platform.** Live Wazuh integration is not claimed.

Unified SOC v0.4 is a QA candidate for mixed-source file analysis. It is not the same pipeline as the OpenObserve receiver and is not production-approved.

### 2. Five alert scenarios and deliverables

| Alert | Detection rule | Primary JSON evidence | SOC report |
|---|---|---|---|
| HTTP high-rate 001 | SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS | Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json | DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx |
| SSH brute force 002 | SIEM_AUTH_002_SSH_BRUTE_FORCE | Evidence/SIEM-OpenObserve/SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json | Alert002_SSH_BruteForce_SOC_Report.md |
| Malware 003 | SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR | Evidence/SIEM-OpenObserve/SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json | Results/SIEM06_MAL_003_FINAL/SIEM06_MAL_003_Final_SOC_Report.md |
| XSS 004 | SIEM_WEB_004_XSS_ATTACK_DETECTED | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_Final_SOC_Report.md |
| Exchange mailbox export 005 | SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT | Evidence/SIEM-OpenObserve/SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json | Results/SIEM_EXCHANGE_005_Final_SOC_Report.md |

All five primary JSON files were parsed successfully during the final audit, and all five SOC report files were located and reviewed. Each alert retains a human-validation requirement. These checks establish artifact availability and review status, not proof of successful compromise or final SOC approval.

### 3. Receiver architecture

- SIEM05 handles HTTP 001 on 127.0.0.1:8765/depi-alerts.
- SIEM06 supports HTTP 001, SSH 002 and Malware 003 using the same endpoint.
- SIEM07 candidate defines support for HTTP 001, SSH 002, Malware 003 and XSS 004 using the same endpoint.
- Exchange 005 uses a separate receiver at 127.0.0.1:8766/depi-exchange-alerts.

SIEM05, SIEM06 and SIEM07 share the same listener address and port and therefore cannot all bind that address simultaneously. The currently active receiver process was not established by the documentation audit. SIEM07 also retains outdated SIEM06 startup wording.

### 4. Evidence and quality audit

- Five primary AI-triage JSON files and five SOC reports were located and reviewed.
- Evidence index: Evidence/SIEM-OpenObserve/README.md.
- Evidence README local links: 36/36 verified.
- Exact duplicate evidence files: 71 archived with matching SHA256 checks.
- Earlier development packages and backups were archived rather than deleted.
- XSS report formatting was corrected with the original preserved and hash-verified.
- Four documentation files were backed up and verified using SHA256 before final documentation updates.

These are documented audit results, not a fresh end-to-end execution of all receivers.

### 5. Open limitations and acceptance gates

1. **Human approval pending:** AI triage results require SOC analyst validation. REVIEW_REQUIRED and related review states are not final analyst sign-off.
2. **HTTP evidence correlation:** The HTTP case includes a 112-request source group against a threshold of 80. The exact row-level join between the saved firing trigger and that group has not been proven.
3. **Updated SIEM05 regression:** Controlled Ollama reanalysis does not constitute an updated receiver-to-report end-to-end regression. This acceptance check remains pending.
4. **Replay scope:** Historical lab datasets and replay timestamps must not be represented as production monitoring or confirmed incidents.
5. **Unified SOC candidate:** The v0.4 QA candidate and its recorded tests do not constitute production approval.
6. **No automatic remediation:** Week-3 SOAR and Week-4 full incident response have not been implemented in Week-2.

**Acceptance decision: PENDING.** The Week-2 technical artifacts are documented, but final sign-off requires resolution or explicit documented acceptance of the outstanding gates.

---

Project 5 - AI-Assisted SOC Automation & Full IR Capstone (DEPI, Cyber Security Incident Response Analyst)
**Report status: DRAFT. Week 2 is NOT declared complete: required local tests are PENDING LOCAL EXECUTION.**

## 1. Summary
Week 2 adds a command-line, local-only SOC assistant on top of the Week 1 work. It loads Windows, Linux, network logs and Wazuh-format alerts, sends them to local Mistral 7B through Ollama, produces summaries, evidence-referenced timelines, IOC context, triage recommendations and detection notes, validates the output deterministically against the source, and records human review. The design directly targets the Week 1 failure modes (altered IPs/timestamps, "None identified" on real risks, Event-ID misreads, ignoring approved-change context, truncated output).

## 2. Week 1 review (what was reused and what it taught)
Reviewed from the supplied archive: README, final report, review notes, benchmark script and results (41 raw outputs), accuracy reviews, 13-case dataset, prompts, privacy checklist.
- Reused unchanged as fixtures: TC-01, 02, 03, 04, 07, 08, 09, 10, 11, 12, 13 (11 cases, copied with a SYNTHETIC header). TC-05 and TC-06 (threat-intel / report-writing text) were not reused because Week 2 analyses logs and alerts.
- Prompts: Week 1 prompts untouched; Week 2 versions in `Prompts/` (changes in `Prompts/PROMPT-CHANGES.md`).
- Model note: the Week 1 report named Llama 3.2 as a provisional baseline, while Week 2 uses Mistral 7B as primary by project decision, based on Week 1 manual reviews of reasoning quality (Mistral was still wrong on TC-11 and TC-12 in Week 1). Llama is available only by the analyst's explicit choice.
- Week 1 evidence that automatic recall is not accuracy was applied: nothing in Week 2 reports a keyword score as accuracy.

## 3. What was built
| Requirement | Implementation | Verified how |
|---|---|---|
| Windows / Linux / network logs, Wazuh alerts (JSON, array, NDJSON, hits wrapper, .gz), generic alerts | `Core/log_parser.py` | Unit tests on fixtures (synthetic) |
| Local Ollama, Mistral primary, Llama backup by analyst choice, configurable settings, timeouts, one controlled retry, clear errors | `Core/ollama_client.py`, `config.py` | Unit tests against a **simulated** server; Ollama-down message seen for real |
| Log analysis (11 sections), timeline, IOC context | `analysis.py`, prompts, `validator.ioc_context` | Simulated + code tests; real model PENDING |
| Alert triage with separate original severity vs AI priority | `alert_triage.py` | Simulated; real model PENDING |
| Detection improvement notes with the 6 required fields | `analysis.py`, `Detection/` | Simulated; real model PENDING |
| Hallucination validation + manual review + statuses + log | `validator.py`, `store.py`, `app.py` | 49 tests; replay on 41 real Week 1 outputs |
| Offline operation | Local-only design; no network calls except loopback Ollama | Code review; offline demo PENDING |
| Sanitising copy, SHA-256, evidence class | `log_parser.py` | Unit tests |
| Wazuh Cloud guide (confirmed / permission / unverified) | `Documentation/Wazuh-Cloud-Guide.md` | Written from official docs; **not tested** |

## 4. Test evidence (types are NOT equivalent)
| Type | Result |
|---|---|
| Static code review | Done by the author during build; no independent review |
| Unit tests (real code, synthetic data) | 49 pass in sandbox |
| Simulated Ollama API tests | Included in the 49; **not Mistral** |
| Validator replay on real Week 1 outputs | All 8 corrupted values in 7 Phi-3 cases flagged; the Mistral TC-02 event-ID error flagged; 2 probable false alarms on Mistral; semantic "None identified"/policy errors not replayable. See `Validation/Hallucination-Validation-Log.md` section 5 |
| Actual local LLM execution | **PENDING LOCAL EXECUTION** |
| GPU / speed / memory | **PENDING LOCAL EXECUTION** |
| Genuine Wazuh alert testing | **PENDING (not started)** |

## 5. Completion checklist
| Item | Status |
|---|---|
| Windows log analysis supported | Implemented; model run PENDING |
| Linux log analysis supported | Implemented; model run PENDING |
| Network log analysis supported | Implemented; model run PENDING |
| Wazuh alert JSON import supported | Implemented and tested with synthetic fixtures; genuine alerts PENDING |
| Local Ollama integration | Implemented; tested against simulation; real run PENDING |
| Mistral primary configured | Done (`config.py`) |
| Alert triage functional | Implemented; real run PENDING |
| Security summaries / timelines | Implemented; real run PENDING |
| IOC context without fabricated reputation | Done and unit-tested |
| Detection notes generated | Implemented; Part A drafted by assistant (not AI); AI part PENDING |
| Hallucination validation | Implemented and replay-tested |
| Human analyst review | Implemented and unit-tested; real session PENDING |
| Results saved locally | Done and unit-tested |
| Missing data handled safely | Done and unit-tested |
| Offline demonstration supported | Supported by design; demo PENDING |
| Genuine Wazuh collection | **PENDING** (not performed) |
| Week 1 files unchanged | Yes (Week 1 archive was only read) |
| Weeks 3 and 4 not implemented | Yes |
| Tests reported honestly | Yes |
| Four official deliverables covered | Yes, with the PENDING parts above |

## 6. To complete on your machine (record results here)
1. Run unit tests locally; keep the output.
2. Run the 10 test categories and the batch run with Mistral; fill `manual_quality_1to5` and review each result.
3. Measure Mistral reliability (repeat-limit frequency with the new settings), `ollama ps` GPU offload, speed with `num_ctx` 6144 vs 4096. **Results: ______ (not measured).**
4. Review at least the Week 1 problem cases (TC-02, 04, 11, 12) and complete the table in the validation log section 6.
5. Run `python app.py detect ...` and `python app.py export`; validate the AI detection notes; sign the notes.
6. Offline demonstration with network off.
7. Collect screenshots 01-13 (and 14 only after real Wazuh collection).
8. Wazuh Cloud (separate decision): follow the guide only when the lab endpoint is ready (3-day inactivity rule); mark everything unverified until you test it.

## 7. Limitations
Small local models make mistakes; flags are heuristics (false alarms and misses both occur); long inputs are truncated and flagged; the larger context setting is untested on the 6 GB GPU; synthetic fixtures reflect Week 1 scenarios, not real traffic; genuine-Wazuh handling has only been tested on invented Wazuh-format data with placeholder IDs.

## 8. Handover to Weeks 3-4
Result files carry `alert_id`, reserved `incident_ref`, evidence, timestamps, IOCs, recommended priority, analyst decisions and validation status for later reuse. No SOAR or IR simulation logic exists yet.
