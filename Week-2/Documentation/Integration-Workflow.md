# Integration Workflow (Week 2)
rn## Implemented OpenObserve Integration - 03 November 2026

**Implementation status:** Five AI-assisted SIEM alert scenarios have been documented and evidenced. Final Week-2 acceptance remains pending.

The original architecture and 11-step workflow below are retained as historical design documentation. This section describes the later demonstrated implementation.

### 1. Actual Week-2 architecture

```text
Security Logs / Historical Lab Datasets
                  |
                  v
           OpenObserve SIEM
                  |
                  v
       Detection Rules / Alerts
                  |
                  v
       Authenticated Webhook
                  |
                  v
         Python SIEM Receiver
                  |
                  v
       Evidence Verification
                  |
                  v
       Local Ollama / Mistral 7B
                  |
                  v
       AI-Assisted SOC Triage
                  |
                  v
       QA / Semantic Validation
                  |
                  v
        SOC Report + Evidence
                  |
                  v
       Human Analyst Review
This represents the implemented lab/replay workflow and its intended review stage. It does not establish that every receiver is currently running or that every alert has received human approval.

Actual SIEM: OpenObserve.

Historical design: Wazuh and Wazuh-format synthetic fixtures remain relevant to earlier file-based testing, but live Wazuh integration is not demonstrated.

2. Separate analysis workflows

A. File-Based SOC Analysis

Windows, Linux and Network logs are processed locally using Python, evidence-grounded prompts, Ollama/Mistral analysis and validation.

B. Unified SOC Candidate

The unified analyzer classifies mixed-source log records and routes them for analysis. Version v0.4 remains a QA candidate. It is not demonstrated as part of the OpenObserve webhook receiver pipeline.

C. OpenObserve SIEM Alert Triage

OpenObserve detection alerts are sent to Python receivers through authenticated webhooks. The receivers validate incoming alert data, verify relevant evidence, invoke local AI analysis and generate reviewable SOC artifacts.

3. Receiver implementation
ReceiverSupported scenariosListener
SIEM05_Auto_Triage_Receiver.pyHTTP high-rate 001127.0.0.1:8765/depi-alerts
SIEM06_Multi_Alert_Receiver.pyHTTP 001, SSH brute force 002, Malware 003127.0.0.1:8765/depi-alerts
SIEM07_XSS_Receiver_Candidate.pyHTTP 001, SSH 002, Malware 003, XSS 004127.0.0.1:8765/depi-alerts
SIEM_EXCHANGE_005_AI_Receiver.pyExchange mailbox export 005127.0.0.1:8766/depi-exchange-alerts

All receiver scripts are located in Integrations/SIEM-OpenObserve/.

Port constraint: SIEM05, SIEM06 and SIEM07 use the same host and port and cannot listen simultaneously on that address. They represent successive/alternative receiver implementations.

The SIEM07 script is identified as a candidate and retains outdated SIEM06 startup wording. The active runtime receiver version has not been independently confirmed by the documentation audit.

4. Detection scenarios
ScenarioOpenObserve detection ruleStream
HTTP high-rate 001SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTSSee SIEM05 configuration
SSH brute force 002SIEM_AUTH_002_SSH_BRUTE_FORCEdepi_auth_logs
Malware 003SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIORdepi_malware_sysmon
XSS 004SIEM_WEB_004_XSS_ATTACK_DETECTEDdepi_web_xss
Exchange mailbox export 005SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORTdepi_exchange_events
5. Evidence and reporting

Each scenario has a primary AI-triage JSON artifact and a corresponding SOC report.

See:

Evidence/SIEM-OpenObserve/README.md for the evidence inventory and screenshots.
Week-2-Final-Report.md for the implementation audit and acceptance status.
README_UNIFIED_SOC.md for the separate unified-analysis workflow.
README_V04.md for v0.4 QA candidate history.

The reports distinguish observed evidence from AI hypotheses. A model-generated verdict is not a substitute for analyst approval.

6. Known limitations and pending acceptance
Human analyst validation and final sign-off remain pending.
Updated SIEM05 receiver-to-report end-to-end regression remains pending.
Exact row-level correlation between the HTTP firing alert and the saved 112-request evidence group has not been demonstrated.
Historical replay does not establish production monitoring or a confirmed compromise.
Simultaneous operation of all receiver versions is not supported on their shared listener address.
Unified SOC v0.4 is a separate QA candidate, not a production-approved OpenObserve component.
Week-3 SOAR actions and Week-4 full incident response are not implemented in this workflow.

Final Week-2 acceptance: PENDING.

## Architecture
```
 Wazuh Cloud (later, manual, optional)            Synthetic fixtures (today)
        |  alerts.json.gz via archive data               |
        v                                                 v
   Data\Wazuh\_raw_do_not_edit  --(sanitise copy)-->  Data\<Windows|Linux|Network|Wazuh|Generic>
                                                          |
                                         Core/log_parser.py  (hash, parse, E001.. refs, normalise - original text kept)
                                                          |
                                         Core/analysis.py    (prompt + reference notes + code-computed facts, random delimiter)
                                                          |
                                         Core/ollama_client.py -> LOCAL Ollama 127.0.0.1:11434 -> Mistral 7B
                                                          |
                                         Core/validator.py + alert_triage.py (deterministic checks -> flags)
                                                          |
                                         app.py (analyst reads output + flags, records review)
                                                          |
                                         Core/store.py -> Results\AN-*\{analysis.json, report.md, raw_ai_output.txt}
                                                          -> Validation\validation_log.csv
```
No component contacts the internet. The client refuses non-loopback Ollama addresses.

## The 11 workflow steps and where they happen
| Step | Code |
|---|---|
| 1 Choose data source | `app.py choose_file()` (menu lists `Data\*`) |
| 2 Load and validate | `log_parser.load_file()` - clear errors for empty, binary, invalid JSON, missing file, partial NDJSON |
| 3 Normalise | `log_parser` - `timestamp_raw` kept verbatim; `timestamp_utc` only when year and timezone are present; missing fields are `None` |
| 4 Choose task | menu 1 / 2 / 3 |
| 5 Load prompt | `Prompts\*.txt` (version `w2-1.0`, hash recorded) |
| 6 Send to Ollama | `ollama_client.generate()` - timeouts, one controlled retry, no silent model switch |
| 7 Receive | `analysis.run_task()` parses sections, timeline rows, triage fields, suggestions |
| 8 Validate | `validator.validate_output()`, `analysis.timeline_flags()`, `alert_triage.triage_flags()` |
| 9 Present | `app.show_result()` - AI output, code-built IOC context, flags |
| 10 Review | `app.review_interactive()` -> `store.apply_review()` |
| 11 Save | `store.save_result()` (+ CSV log) |

## Supported inputs
| Category | Formats | Fixtures |
|---|---|---|
| Windows | key=value lines with `EventID=` (4624, 4625, 4672, 4688, 4732, Sysmon/EDR style) | `Data\Windows\*` |
| Linux | syslog / auth.log (`sshd`, `sudo`, `pam_unix`) | `Data\Linux\*` |
| Network | key=value firewall / WAF / DNS / IDS lines | `Data\Network\*` |
| Wazuh | single alert JSON, JSON array, `hits.hits[]._source` wrapper, NDJSON, any of them `.gz` | `Data\Wazuh\SYNTHETIC_*` |
| Generic SIEM / cloud | `ALERT:` text blocks, other logs | `Data\Generic\*` |

Wazuh field handling is generic: all nested fields are flattened, so unknown rule/decoder fields are kept and shown to the analyst without assuming a schema. Specific fields read when present: `timestamp, id, rule.{id,level,description,groups}, agent.{id,name}, location, decoder.name, full_log, data.*`.

## Evidence and privacy controls
- Original files are only read. SHA-256 of the input is stored with every result.
- `evidence_class` is stored: `synthetic_fixture`, `user_supplied_unverified`, or `analyst_declared_genuine_wazuh_export` (analyst's declaration; the program cannot verify authenticity).
- Synthetic Wazuh-format fixtures use **placeholder** IDs (`SYNTH-0001`, `SYN-001`) and carry a `_synthetic_fixture` notice. No real Wazuh rule IDs are used or invented.
- Sanitising writes a **copy** (`Data\_sanitized`).
- Log text is wrapped in per-run random delimiters and declared untrusted; instruction-like text in logs is flagged (`prompt_injection_in_input`). This reduces, but cannot eliminate, prompt-injection risk with a 7B model; the validator and analyst remain the safeguard.
- Cloud SIEM privacy: events stored in Wazuh Cloud may include usernames, hosts, IPs and command lines. See `Wazuh-Cloud-Guide.md`.

## Offline demonstration (Plan B)
1. Start Ollama (no internet needed once the model is pulled). 2. `python app.py triage Data\Wazuh\<saved alert file>`. 3. Choose the alert. 4. Read the live AI output. 5. Show flags. 6. Record review. 7. Show `Results\...\report.md`.
Say: *"This alert was collected earlier; the AI analysis is running live, offline."* If no genuine alerts exist, say the file is a **synthetic Wazuh-format fixture**.

## Reuse by Weeks 3 and 4 (not implemented now)
Each `analysis.json` already contains stable fields a later playbook can read: `analysis_id`, `references.alert_id`, `references.incident_ref` (null; reserved), `input.sha256`, `events[]` (ref, raw, timestamps, host, user, IPs), `ioc_context[]`, `triage.recommended_priority`, `triage.original_severity`, `review.status/final_classification/final_priority`, `validation.flags`. No containment, ticketing, enrichment or SOAR logic exists in Week 2.

## Known limitations
- A 7B local model can still be wrong; every output is a draft.
- Input that exceeds the context budget is cut and flagged (`input_truncated`); long files must be split.
- `num_ctx=6144` is an untested candidate on a 6 GB GPU; confirm with `ollama ps`.
- Heuristic checks produce false alarms and cannot find every wrong conclusion.
- Genuine Wazuh alerts have never been processed by this application.
