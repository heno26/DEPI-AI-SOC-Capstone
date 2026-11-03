# Network Evidence — Screenshot Catalog (Week 2)

**Project:** DEPI P5 — AI-Assisted SOC Log Analysis  
**Scope:** NT-01 Port Scanning · NT-02 DNS Anomaly · NT-03 TCP Retry-Like / C2-Related Investigation  
**Evidence directory on the operator's machine:** `Week-2/Evidence/Network/Screenshots/`  
**Screenshots shown in the two File Explorer overviews:** **49** (17 NT-01, 12 NT-02, 20 NT-03)  
**Documentation status:** Network screenshot catalog completed; **no additional Network cases or tests are proposed**.

> **Source and fidelity note:** The supplied attachments are **two File Explorer overview images**, not the 49 full-resolution individual screenshots. This catalog transcribes each displayed file label and explains the operation using the titles **and the actual PowerShell outputs/results provided during the project**. Therefore this is a reliable **workflow/catalog summary**, not a direct pixel-by-pixel audit of the 49 screenshot files. File extensions are hidden in Explorer. Two long names are truncated in the Windows view and are marked explicitly; no unknown suffixes or image hashes have been fabricated.

## Executive overview

| Case | Investigation | Screenshot count | Verified investigation outcome | Documentation status |
|---|---|---:|---|---|
| **NT-01** | TCP vertical port scanning | **17** | 65,747 TCP flows from `192.168.16.132` to `192.168.16.130` across 65,535 distinct destination ports. Strong **scan pattern**, not independently verified attacker intent or compromise. | Completed |
| **NT-02** | Concentrated DNS chunk-style queries | **12** | 250 distinct `chunkNNN-hex.lab.test` A queries in **3.552866 seconds** from `192.168.16.132` to `192.168.16.131`. DNS-tunneling-like **indicator**, not proven exfiltration. | Completed |
| **NT-03** | Repeated TCP four-tuple / retry-like behavior | **20** | 24 TCP/80 target records; 4 reused source-port groups containing 17 source rows. Observed pattern grounded; periodic beaconing, C2 and compromise **not established independently**. | Completed |
| **Total** | Three Network test cases | **49** | Source evidence, AI outputs, grounded checks, human reviews and final case documentation preserved. | **Closed for this phase** |

The Network cases used **source-grounded detection** independently from the local Mistral model. Analyst corrections are retained rather than treating model text or automated flags as unquestionable truth. A final project-wide run after NT-03 showed **317 unit/regression tests passing**; this is a combined suite result, **not** 317 tests separately for each case.

---

## How to read this catalog

Each entry identifies the **visible screenshot name** and the **operation/result it documents**. In the tables below, `PASS` describes the reported tool/test result, **not** a claim that the depicted traffic is malicious. `Corrected` is the human review disposition, and `Runtime-Failure` records a failed local model attempt. Numerical results are taken from supplied console logs, not guessed from thumbnail text. Names are ordered **alphabetically as shown in Explorer**, not chronologically.

## NT-01 — TCP Port Scanning — 17 screenshots

| # | Screenshot name as displayed | Operation / what the evidence documents |
|---:|---|---|
| 01 | `NT01-Final-Documentation-PASS` | Final NT-01 case documentation and verified evidence closure; the port-scan investigation was recorded without altering source logs or historical results. |
| 02 | `NT01-Focused-Evidence-Verification-PASS` | Verified focused conn.log evidence, the computed aggregate, original-record mappings and their source-line hashes before AI triage. |
| 03 | `NT01-Mistral-Port-Scan-Analysis-1` | First capture of the initial local Mistral port-scan report; useful for assessing what the model recognized or omitted from the verified scan pattern. |
| 04 | `NT01-Mistral-Port-Scan-Analysis-2` | Continuation of the initial port-scan report and validation/review findings; preserves the baseline model's limitations. |
| 05 | `NT01-Network-Grounding-Persistence-Verification` | Confirmed that the independent `NETWORK_VERTICAL_PORT_SCAN` finding was persisted in the saved analysis rather than existing only in a console demo. |
| 06 | `NT01-Network-Grounding-Regression-PASS` | Shows installation/regression checks for grounded network detection, including the original tests and added network-specific coverage. |
| 07 | `NT01-Network-Semantic-V2-Regression-PASS & NT01-Network-… [display truncated]` | Semantic-attribution v2 regression and accompanying network verification (full screenshot filename is cut off in File Explorer); checks direction and port-role claims against Zeek evidence. |
| 08 | `NT01-Post-Grounding-Human-Review-Corrected` | Documents the analyst's corrected disposition of the post-grounding Mistral report, separating incorrect claims from verified source facts. |
| 09 | `NT01-Post-Grounding-Mistral-Analysis-1` | First part of the AI report after network grounding was added; captures behavior recognition and remaining narrative errors. |
| 10 | `NT01-Post-Grounding-Mistral-Analysis-2` | Second part of the post-grounding AI report and its validation results, including model mistakes requiring human review. |
| 11 | `NT01-Source-Discovery-PASS` | Identified the `Zeek-Logs/port_scan/conn.log` source in `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab` and its pinned Git object metadata. |
| 12 | `NT01-Source-Integrity-Verification-PASS` | Downloaded and SHA-256/Git-blob-verified the 8,200,705-byte source without modifying the core or prior evidence. |
| 13 | `NT01-Verified-Network-Direction-PASS-1` | Checked original source-to-destination IP direction for cited conn.log records, distinguishing TCP scan traffic from other contextual flows. |
| 14 | `NT01-Verified-Network-Direction-PASS-2` | Continuation of direct record checks, including source-port versus destination-port verification and correct Zeek event references. |
| 15 | `NT01-Zeek-Traffic-Inspection-1` | Beginning of original Zeek conn.log format/inventory inspection (header, parsing, counts and integrity). |
| 16 | `NT01-Zeek-Traffic-Inspection-2` | Continued traffic analysis: dominant 192.168.16.132 → 192.168.16.130 TCP activity, high distinct-port counts and scan windows. |
| 17 | `NT01-Zeek-Traffic-Inspection-3` | Final source-row samples, hashes and analytical limitations; shows why the vertical scan is a strong observed pattern but not proof of intent or compromise. |

## NT-02 — DNS Anomaly / Chunk-Style Burst — 12 screenshots

| # | Screenshot name as displayed | Operation / what the evidence documents |
|---:|---|---|
| 01 | `NT02-DNS-Grounding-Persistence-PASS` | Verified that the independent `NETWORK_DNS_CHUNK_BURST` finding was stored with the NT-02 analysis and retained its evidence references. |
| 02 | `NT02-DNS-Grounding-v1-247Tests-Detection-Replay-PASS` | Grounded DNS detection v1 installation/regression (223 → 247 tests) and read-only replay confirming the burst rule. |
| 03 | `NT02-DNS-Traffic-Inspection-Part-1` | Zeek dns.log source integrity, parser validation, 581 original records and initial query/client/resolver inventory. |
| 04 | `NT02-DNS-Traffic-Inspection-Part-2` | Continued analysis of domain diversity, query types, response codes and fixed 60-second DNS windows. |
| 05 | `NT02-DNS-Traffic-Inspection-Part-3` | Original DNS query examples, sequential `chunkNNN-hex.lab.test` names, source-line hashes and limits on inferring tunneling/exfiltration. |
| 06 | `NT02-Final-Documentation-PASS` | Completed NT-02 timeline, case study and verification documentation while preserving saved analyses and source evidence. |
| 07 | `NT02-Focused-Evidence-Verification-PASS` | Validated 26 focused events: 2 computed aggregates and 24 original DNS rows mapped back to their Zeek lines and hashes. |
| 08 | `NT02-Mistral-DNS-Baseline-Analysis-1` | First part of the baseline Mistral DNS analysis; model described chunk-like names but did not quantify the high-rate DNS cluster. |
| 09 | `NT02-Mistral-DNS-Baseline-Analysis-2` | Continuation of baseline output showing missing report sections and automated review requests (13 medium flags). |
| 10 | `NT02-PostGrounding-Mistral-CUDA500-Runtime-Failure` | A local inference failure (Ollama/CUDA HTTP 500) during a post-grounding attempt; this is an execution issue, not evidence of a network attack. |
| 11 | `NT02-Source-Acquisition-Integrity-PASS` | Acquired the 104,260-byte source Zeek dns.log and matched its SHA-256/Git-blob values and pinned repository commit. |
| 12 | `NT02-Validator-Fix-v1-Semantic-Replay-PASS` | Post-fix validator replay demonstrating removal of cross-rule false positives and detection of missing DNS-burst quantification; regression later reached 275 tests. |

## NT-03 — Repeated TCP / Retry-Like Communication — 20 screenshots

| # | Screenshot name as displayed | Operation / what the evidence documents |
|---:|---|---|
| 01 | `NT03-Baseline-Human-Review-Corrected` | Human review of the baseline Mistral run (`AN-20261021-121055-9c32`); documented omitted retry groups, unsupported scanning speculation and incomplete sections. |
| 02 | `NT03-Baseline-Mistral-Analysis` | Baseline Mistral report on 25 focused events, including seven structural `missing_section` flags before grounded retry rules. |
| 03 | `NT03-C2-Flow-Investigation` | Examined IoT-23 conn.log labels separately for evaluation and investigated 24 TCP/80 records; C&C labels were withheld from AI input. |
| 04 | `NT03-Connection-Retry-Pattern-Inspection-PASS` | Found four reused source-port groups (59224, 59228, 59236, 59240) with 17 S0-before-SF source records; retry/backoff remains a hypothesis. |
| 05 | `NT03-Connection-Timing-Inspection-PASS` | Measured per-flow inter-arrival intervals and variability; timing alone did not establish periodic beaconing or command-and-control. |
| 06 | `NT03-Final-Documentation-Closure-317Tests-PASS` | Created/verified the NT-03 README, checked eight prior artifacts, two corrected historical reviews and grounded findings; reran all 317 tests successfully. |
| 07 | `NT03-Final-Verification-Manifest-8Artifacts-PASS` | Verified SHA-256 integrity of eight existing NT-03 case artifacts and their manifest cross-references; generated the final manifest. |
| 08 | `NT03-Focused-Evidence-Candidate-Selection-PASS` | Selected 23 original Zeek connection rows, including reused-source-port rows and TCP/UDP context, without using dataset labels to select targets. |
| 09 | `NT03-Focused-Evidence-Preparation-PASS` | Created 25 model-safe focused events (2 aggregates plus 23 raw records) and source mapping/statistics manifests with SHA-256 checks. |
| 10 | `NT03-Focused-Evidence-Schema-Preflight-PASS` | Checked the JSON event container and aggregate schemas against the existing network parser before creating NT-03 focused data. |
| 11 | `NT03-Grounded-Detection-Replay-PASS` | Read-only grounded detection demonstration showing evidence-linked repeated-four-tuple TCP behavior, without automatic C2 attribution. |
| 12 | `NT03-Grounded-Retry-Historical-Replay-PASS` | Historical replay of post-grounding analysis `AN-20261021-132533-02e7` verified four groups, 17 rows and 17 source refs; no saved data changed. |
| 13 | `NT03-Grounded-Retry-Installation-293-Tests-PASS` | Installed the focused TCP retry grounding patch with backup and passing regression increase from 275 to 293 tests. |
| 14 | `NT03-Post-Grounding-Human-Review-Corrected-1` | First part of the analyst's corrected review of post-grounding Mistral output, including factual and structural issues. |
| 15 | `NT03-Post-Grounding-Human-Review-Corrected-2` | Continuation/final save of the corrected post-grounding review (`AN-20261021-132533-02e7`). |
| 16 | `NT03-Post-Grounding-Persistence-Verification` | Compared saved analyses: baseline grounded findings = 0, post-grounding grounded findings = 1; historical results were read without modification. |
| 17 | `NT03-Post-Grounding-Semantic-Replay` | Replayed NT-03 validator checks and examined how missing quantification, false connection-success claims and port-group mixups appeared in the AI narrative. |
| 18 | `NT03-Semantic-Validator-Gap-Audit` | Read-only gap audit found zero semantic review requests from the then-current validators despite observable text contradictions; identified parsing/coverage gaps. |
| 19 | `NT03-Semantic-Validator-v2-Installation-317Tests-Final-Replay-P… [display truncated]` | Guarded Semantic Validation v2 installation (293 → 317 passing tests) and read-only replay that flagged TCP data contradiction, source-port group mismatch and missing retry quantification; full filename is truncated in Explorer. |
| 20 | `NT03-Source-Acquisition-Verified-PASS` | Acquired and SHA-256-verified the 31,179-byte IoT-23 `CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled` source (237 records). |

---

## Verified results and evidence interpretation

### NT-01 — vertical TCP port-scan pattern

- **Source:** Zeek `conn.log` from `dikshitdhawan/NTA-Zeek-Threat-Detection-Lab`, pinned to commit `bb2817e4a783dd2578383aa6e3f0adab12052904`.
- **Integrity:** original bytes `8,200,705`; source records `65,895`; SHA-256 `f9282d987047ef37a807a575a353ff601ddbb1b389aa76e92214c302de2fbda9`.
- **Observed pair:** `192.168.16.132 → 192.168.16.130`, `65,747` TCP records, `65,535` distinct target ports; rejection-heavy behavior.
- **Deterministic rule:** `NETWORK_VERTICAL_PORT_SCAN`, with the source-derived aggregate clearly separated from raw Zeek rows.
- **Human-review lesson:** initial reports confused flow direction/source versus destination ports or understated the scan. Grounded analysis and semantic verification were checked against raw evidence; they did not establish open ports, attacker identity, approval status or successful compromise.
- **Outcome:** focused evidence, annotated review and final case/timeline documentation completed.

### NT-02 — rapid DNS chunk-query burst

- **Source:** pinned `Zeek-Logs/dns_anomaly/dns.log` from the same repository and commit. Original file SHA-256: `a5a31f5be2a6bfdcce1ab1f2d43e34a2b1ff49bee4d3737560c8b9b6e6775942`.
- **Inventory:** `581` Zeek DNS records; `258` distinct exact query strings; source inspection found no NXDOMAIN records in this file.
- **Key observation:** `250` distinct chunk-style A queries in **3.552866 s** (`2026-05-26T16:05:30.002227Z` to `16:05:33.555093Z`) from `192.168.16.132` to resolver `192.168.16.131`.
- **Focused evidence:** `26` events: `E001–E002` computed aggregates and `E003–E026` original, source-mapped DNS rows.
- **Deterministic rule:** `NETWORK_DNS_CHUNK_BURST`. Grounding v1 passed the `223 → 247` regression transition; a subsequent validator fix passed `247 → 275` tests, correcting cross-rule checks and identifying missing burst quantification.
- **Runtime note:** the CUDA/HTTP 500 screenshot is a **failed model execution**, not a finding from the DNS logs.
- **Conclusion:** source-confirmed unusual query burst requiring analysis; **no demonstrated payload reconstruction, successful tunneling, exfiltration or malicious intent**.

### NT-03 — repeated same-four-tuple TCP records

- **Source:** Stratosphere IPS IoT-23, `CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled`, `31,179` bytes, `237` parsed connections. SHA-256: `12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f`.
- **Target behavior:** `192.168.1.199 → 46.101.251.172:80/TCP`, `24` records (`13 S0`, `11 SF`). Four reused **source** ports (`59224`, `59228`, `59236`, `59240`) account for **17** Zeek rows.
- **Original-label control:** IoT-23's C&C/benign labels were held out of **blind AI focused evidence**; source-supplied annotations are separate evaluation metadata, **not proof of a beaconing pattern**.
- **Focused evidence:** 25 events (2 verified computed aggregates + 23 source-mapped Zeek rows); the verified chronological timeline has 23 raw rows.
- **Human reviews:** baseline `AN-20261021-121055-9c32` and post-grounding `AN-20261021-132533-02e7` were both saved as **Corrected**. The baseline had no persisted retry finding; post-grounding had one.
- **Independent rule:** `NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE`, high confidence in the **observed sequence**, not in C2. Historical replay confirmed 4 groups / 17 rows / 17 linked evidence references.
- **Validator gap and fix:** post-grounding Mistral wrongly denied evidence of established TCP sessions/data and grouped source port `51834` (actually a TCP/23 source port) under TCP/80; it also omitted retry-group quantification. Semantic Validation v2 read-only replay found the three corresponding requests: `network_observed_tcp_data_contradiction` (**high**), `network_source_port_group_mismatch` (**medium**) and `network_tcp_retry_missing_quantification` (**medium**).
- **Last regression:** `293 → 317` tests passing after Semantic Validation v2; a later independent full run again showed **317 PASS**.
- **Final documentation:** `NT-03-Verified-Timeline.csv`, `NT-03-Case-Study.md`, `NT-03-Final-Verification-Manifest.json`, and `README.md`. Eight pre-manifest files were SHA-256-verified; two saved human reviews remained unchanged; the final manifest SHA-256 was `927b1e879ee955f3303e1bc3855f62bef259ddd1a7c05a967f3ee60ea108ef37`.
- **Conclusion:** repeated/retry-like TCP record sequence **observed and supported**. It does **not by itself** establish independent connection attempts, exponential retry backoff, periodic beaconing, successful C2 operation, malware execution or compromise.

---

## Evidence workflow represented across the 49 screenshots

1. **Source discovery and acquisition:** record the original source location, provenance, size and cryptographic fingerprints before working on it.
2. **Read-only inspection:** validate Zeek schemas, timestamp treatment, connection/query distributions and original line-level mapping.
3. **Focused evidence generation:** keep full-source computed aggregates **separate** from raw Zeek events; preserve `E###`, original line numbers, Zeek UID, timestamps and hashes. Withhold IoT-23 labels from blind AI evidence.
4. **Baseline local-model analysis:** send the selected evidence to Mistral, save the answer and its automated review requests without assuming the model is accurate.
5. **Independent grounding:** use source-derived Python detections for port-scan patterns, DNS bursts and repeated TCP four-tuples; require original evidence references.
6. **Human review and semantic validation:** document false positives, unsupported statements, incorrect direction/port semantics and missing quantification. Replays are read-only and should not silently change historical analyses.
7. **Regression and case closure:** preserve backups and prior results, verify new checks against existing tests, then document the verified timeline, case study, manifest and README.

## What the screenshots do **not** prove

- The underlying 49 image **files**, extensions and individual screenshot SHA-256 values were not supplied; only their **File Explorer overview** was. This catalog does not assign invented image hashes or claim a pixel-level read of each screenshot.
- The two long filenames marked **`[display truncated]`** need no invented completion. The text above identifies their stages, but not their exact filesystem spellings.
- A source-supplied dataset label, a high-confidence **observed pattern**, a successful unit-test run and an AI security **verdict** are four different types of evidence; they must not be conflated.
- Network NT-01/NT-02/NT-03 have been **closed as project test cases**. Closure does not mean every uncertainty about attacker intent, tunneling, beaconing or compromise has been resolved.

## Current project state and handoff

**Network screenshots cataloged:** **49 / 49 visible items** — NT-01 **17**, NT-02 **12**, NT-03 **20**.  
**Network cases:** NT-01, NT-02 and NT-03 completed and documented.  
**Last observed complete regression:** **317 tests PASS**.  
**Preservation policy:** keep the original logs, focused datasets, source manifests, timelines, saved AI reports, human corrections and screenshot files unchanged.  
**Scope limit:** **No NT-04, no additional Network testing, and no Week-2 cleanup is performed by this catalog.**

*End of Network Evidence Screenshot Catalog.*
