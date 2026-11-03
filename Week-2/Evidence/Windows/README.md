# Windows Security Testing — Evidence Guide

**Project:** DEPI P5 — AI-Assisted SOC Automation & Incident Response  
**Phase:** Week 2 — Windows Log Analysis, Semantic Validation, and Human Review  
**Scope:** 4 recorded attack-scenario cases (RT-01–RT-04) and 3 benign-candidate cases (BT-01–BT-03)  
**Evidence inventory:** 42 classified screenshots  
**Status:** Windows testing and documentation complete; Linux and Wazuh are separate workstreams.

> **How to use this file:** Save it as `Evidence/Windows/README.md` in the Week-2 project. Screenshot links below are **relative to this file**. This is a navigational/evidence guide, not a substitute for original EVTX files, focused datasets, analysis records, analyst reviews, or source-integrity manifests.
>
> **Evidence interpretation:** Descriptions are based on the screenshot filenames and the recorded test outputs supplied during the project walkthrough. Where an image has a generic filename or its exact contents have not been individually verified, the description deliberately avoids assigning it to a particular test or claiming a particular result. Always use the underlying logs and saved review to establish factual conclusions.

## 1. Directory Map

```text
Evidence/
├── Windows/
│   ├── README.md                       <-- this guide
│   ├── Screenshots/
│   │   ├── RT-01/                      Command & Control / C2 investigation
│   │   ├── RT-02/                      Discovery / audit log and IPC$ checks
│   │   ├── RT-03/                      WinRM-related process chain
│   │   ├── RT-04/                      Winlogon Shell persistence
│   │   ├── BT-01/                      .NET optimization process activity
│   │   ├── BT-02/                      SYSTEM service logons and privileges
│   │   ├── BT-03/                      Windows service state changes
│   │   └── General-Review/            Screenshots with ambiguous case names
│   └── Final-Verification/            Windows-wide parser/test evidence
├── Shared/
│   ├── Regression-Tests/               Reusable validation/regression evidence
│   └── Setup-Verification/             Local AI environment evidence
├── Benign-Analysis/                    Existing console outputs; path retained
├── Linux/                              Separate Linux evidence
└── Wazuh/                              Separate Wazuh evidence
```

The `Shared` screenshots physically live in `Evidence/Shared`, **not** under `Evidence/Windows`. Their links from this README use `../Shared/...`.

## 2. Test-Case Overview

| ID | Scenario | Evidence-based observation | Final human-review status | Case documentation |
|---|---|---|---|---|
| **RT-01** | Command & Control (C2) investigation | Four selected Sysmon events were traced to one recorded EVTX source; the source-to-focused evidence IDs required an explicit mapping. Scenario label does not, by itself, prove successful C2 activity. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Case-Study.md) · [Verified timeline](../../Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Verified-Timeline.csv) |
| **RT-02** | Discovery | Security Event ID **1102** recorded Security Audit Log clearing; three Event ID **5145** events recorded IPC$ named-pipe access checks (`winreg`, `lsarpc`, `srvsvc`). Access checks alone do not prove malicious success. | Approved | [Case study](../../Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Case-Study.md) · [Verified timeline](../../Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Verified-Timeline.csv) |
| **RT-03** | WinRM-related execution / possible lateral movement | Sysmon process chain `winrshost.exe → cmd.exe → ipconfig.exe` observed on `DC1.insecurebank.local`. A remote session's origin or malicious lateral movement was **not independently proven** by these three events. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Case-Study.md) · [Verified timeline](../../Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Verified-Timeline.csv) |
| **RT-04** | Persistence | File creation, `Winlogon\Shell` registry value change, and later payload execution form a supported persistence-related sequence. Malicious attribution and persistence across multiple reboots remain unproven. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Case-Study.md) · [Verified timeline](../../Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Verified-Timeline.csv) |
| **BT-01** | Benign candidate — .NET optimization | Six Sysmon Event ID 1 records showed `mscorsvw.exe` launched by `ngen.exe` under `NT AUTHORITY\SYSTEM`. An AI claim locating it in `System32` conflicted with the recorded `.NET Framework` path. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Benign/BT-01/BT-01-Case-Study.md) |
| **BT-02** | Benign candidate — service authentication | Two Security Event ID 4624 **Logon Type 5** records and two Event ID 4672 privilege-assignment records for SYSTEM. Privilege presence alone is not proof of abuse. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Benign/BT-02/BT-02-Case-Study.md) |
| **BT-03** | Benign candidate — service control | Six Event ID 7036 service-state records. Only **Software Protection** had one observed `running` transition followed by one `stopped` transition; multiple start/stop cycles were not shown. | Corrected | [Case study](../../Data/Real-Datasets/Windows-Benign/BT-03/BT-03-Case-Study.md) |

**Windows-wide documents:** [Attack evaluation](../../Documentation/Windows/Windows-Attack-Evaluation.md) · [Benign evaluation](../../Documentation/Windows/Windows-Benign-Evaluation.md) · [Testing summary](../../Documentation/Windows/Windows-Testing-Summary.md) · [Finalization manifest](../../Documentation/Windows/Windows-Finalization-Manifest.json).

## 3. Screenshot Catalog — Attack Scenarios (23 images)

### RT-01 — Command & Control / C2 (5 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [C2-EVTX-Verification.png](Screenshots/RT-01/C2-EVTX-Verification.png) | Original Windows **EVTX inspection**: checking that the acquired Sysmon event records exist and can be read before analysis. This belongs to source-evidence verification. |
| [C2-EVTX-Conversion.png](Screenshots/RT-01/C2-EVTX-Conversion.png) | **EVTX-to-JSON preparation**: recorded Windows events were converted into a machine-readable format for the local analysis pipeline. |
| [C2-JSON-Validation.png](Screenshots/RT-01/C2-JSON-Validation.png) | **Converted dataset check**: the JSON structure and parsed event fields were validated before downstream model use. |
| [Real-C2-Mistral-Analysis.png](Screenshots/RT-01/Real-C2-Mistral-Analysis.png) | **Local Mistral security-log analysis** of the selected recorded C2-scenario evidence; the model's interpretation is an analyst-review candidate, not an independently confirmed attack outcome. |
| [C2-Automated-Valida.png](Screenshots/RT-01/C2-Automated-Valida.png) | **Automated validation** of the model report, including evidence-reference and factual-consistency checks; flagged items require human adjudication. |

**Important evidence mapping:** The original selections `E003`, `E004`, `E005`, `E023` were renumbered `E001`, `E002`, `E003`, `E004` in the focused dataset. Use [RT-01 evidence mapping](../../Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-C2-evidence-mapping.csv) before comparing reports or timelines.

### RT-02 — Discovery / IPC$ (3 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [RT02-1102-Account-Verification.png](Screenshots/RT-02/RT02-1102-Account-Verification.png) | **Event 1102 source-field recovery and account verification**: the missing original `UserData` fields were recovered from EVTX, and `SubjectUserName=Administrator` was confirmed. Event 1102 means **Security Audit Log Cleared**, not “Administrator logged on.” |
| [RT02-Semantic-Fix-Validation-PASS.png](Screenshots/RT-02/RT02-Semantic-Fix-Validation-PASS.png) | **Semantic-validator patch/replay verification**: a stored incorrect interpretation was rechecked without rewriting its original report. The replay exposed previously missed misleading claims (including Event ID 1102 semantics and unsupported access/authorization assertions). |
| [RT02-Final-Human-Review-Approved.png](Screenshots/RT-02/RT02-Final-Human-Review-Approved.png) | **Final analyst approval** of the corrected four-event discovery analysis, after interpreting the IPC$ `winreg`, `lsarpc`, and `srvsvc` records as access checks rather than proof of malicious file access. |

**Evidence context:** The source IP was `10.0.2.17` (private address). External reputation was **not** checked. The final RT-02 analysis was reviewed as **Approved**; an earlier inaccurate version was separately retained for auditability.

### RT-03 — WinRM-Related Execution / Possible Lateral Movement (5 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [RT03-WinRM-Mistral-Analysis.png](Screenshots/RT-03/RT03-WinRM-Mistral-Analysis.png) | **Initial Mistral review** of three Sysmon Event ID 1 process-creation records showing `winrshost.exe → cmd.exe → ipconfig.exe`. |
| [RT03-Automated-Validation.png](Screenshots/RT-03/RT03-Automated-Validation.png) | **Initial automated findings** on the WinRM analysis, including missing evidence references on potentially suspicious claims. |
| [RT03-Semantic-Fix-Regression-Replay.png](Screenshots/RT-03/RT03-Semantic-Fix-Regression-Replay.png) | **Semantic-validation regression and replay**: test-suite success and comparison of validator findings before/after additional checks for unsupported authorization or remote-execution conclusions. The recorded patch run passed **76 tests**. |
| [RT03-Postfix-Mistral-Analysis.png](Screenshots/RT-03/RT03-Postfix-Mistral-Analysis.png) | **Post-fix local Mistral analysis** after prompt/validator improvements. It better qualified the process-chain interpretation, but contained invalid placeholder-style timeline timestamps requiring correction. |
| [RT03-Postfix-Automated-Validation.png](Screenshots/RT-03/RT03-Postfix-Automated-Validation.png) | **Post-fix validator output**: raised timeline timestamp mismatches and unsupported-assumption concerns for analyst review. |

**Analyst conclusion:** Process-chain evidence supports a WinRM-related execution pattern, **not proof** of a confirmed attacker, unauthorized remote session, or completed lateral movement. Verified timestamps came from original Sysmon records, not AI-created placeholders.

### RT-04 — Winlogon Shell Persistence (10 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [RT-04 PERSISTENCE DATASETS.png](Screenshots/RT-04/RT-04%20PERSISTENCE%20DATASETS.png) | **Dataset discovery/inventory**: candidate Windows persistence EVTX samples were listed before choosing a relevant recorded scenario. |
| [RT04-Initial-Mistral-Analysis.png](Screenshots/RT-04/RT04-Initial-Mistral-Analysis.png) | **Initial local Mistral analysis** of selected persistence events involving `a.exe`, a created payload, and a `Winlogon\Shell` registry modification. |
| [RT04-Initial-Validation-9Flags.png](Screenshots/RT-04/RT04-Initial-Validation-9Flags.png) | **Initial automated validation** identified **9 flags**, including an output-length/truncation problem and evidence-grounding concerns; not all flags represent confirmed hallucinations. |
| [RT04-Post-Truncation-Validation.png](Screenshots/RT-04/RT04-Post-Truncation-Validation.png) | **Output-budget retest** after raising model context/output-token limits to obtain a complete report; later checks could assess the missing sections. |
| [RT04-Semantic-Fix-Regression-Replay.png](Screenshots/RT-04/RT04-Semantic-Fix-Regression-Replay.png) | **Persistence-specific semantic fix**: replay of stored outputs with new checks on Sysmon event meanings, timestamps, unsupported download origins, and unproven multi-session claims. The recorded patch run passed **92 tests**. |
| [RT04-Postfix-Mistral-Analysis.png](Screenshots/RT-04/RT04-Postfix-Mistral-Analysis.png) | **Post-fix live Mistral output** describing the registry persistence mechanism and execution evidence; remaining assertions still required human validation. |
| [RT04-Postfix-Validation.png](Screenshots/RT-04/RT04-Postfix-Validation.png) | **Post-fix automated validation** highlighted an unsupported statement about a file being downloaded merely because it executed from a Downloads directory. |
| [RT04-Human-Review-Corrected.png](Screenshots/RT-04/RT04-Human-Review-Corrected.png) | **Analyst correction** distinguished observed file/process/registry events from unsupported download-source, malicious-attribution, and multiple-session/reboot claims. |
| [RT04-Final-Evidence-Verification.png](Screenshots/RT-04/RT04-Final-Evidence-Verification.png) | **Final source verification** of the original **25** Sysmon events, the **7** focused events, evidence mapping, GUID-linked process relationships, and evidence-derived full-precision timeline. |
| [26-RT04-Complete-Mistral-Analysis.png](Screenshots/RT-04/26-RT04-Complete-Mistral-Analysis.png) | **Additional complete RT-04 model-output screenshot** retained as a visual record of the analysis. Its exact run/version should be checked against the saved analysis ID before citing it as the final version. |

**Key sequence:** `a.exe` executed; a file was created in `AppData\Roaming`; the user `Winlogon\Shell` registry value referenced the new executable alongside `explorer.exe`; later process-creation events showed execution of that payload. This supports a **persistence mechanism observed**, without asserting malware attribution or survival of multiple separate reboots.

## 4. Screenshot Catalog — Benign Candidates (7 images)

### BT-01 — .NET Runtime Optimization (3 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [BT01-Benign-Mistral-Analysis.png](Screenshots/BT-01/BT01-Benign-Mistral-Analysis.png) | **Initial benign-candidate analysis** of six Sysmon process-creation events for `mscorsvw.exe` under `NT AUTHORITY\SYSTEM`; the model suggested ordinary .NET optimization but included unsupported statements about termination/path. |
| [BT01-Human-Review.png](Screenshots/BT-01/BT01-Human-Review.png) | **Analyst review** of claims about process execution, source Image/ParentImage, and whether any termination or confirmed benign baseline had actually been documented. |
| [BT01-PostFix-Validation.png](Screenshots/BT-01/BT01-PostFix-Validation.png) | **Post-fix validator check** caught **2 medium-severity path-mismatch flags**: the report claimed `C:\Windows\System32` whereas the source Image field showed `C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe`. |

### BT-02 — SYSTEM Service Logons and Privileges (2 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [BT02-Benign-Validation-3Flags.png](Screenshots/BT-02/BT02-Benign-Validation-3Flags.png) | **Initial validator result** with **3 flags** on the four-event authentication/privilege report, including evidence-referencing and interpretation-consistency issues. |
| [BT02-PostFix-Validation.png](Screenshots/BT-02/BT02-PostFix-Validation.png) | **Post-fix validator result** with **1 medium flag**: an unsupported, unreferenced claim that special privileges granted to the SYSTEM account were inherently unusual. The analyst marked the flag for follow-up, rather than treating privilege assignment as proven abuse. |

**Key events:** `4624 / Logon Type 5` = service logon; `4672` = special privileges assigned to a new logon. Neither alone proves privilege escalation or compromise.

### BT-03 — Routine Windows Service Changes (2 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [BT03-Benign-Mistral-Analysis.png](Screenshots/BT-03/BT03-Benign-Mistral-Analysis.png) | **Initial Mistral review** of six Windows System Event ID **7036** service-state changes; the model speculated about malicious concealment without corroborating evidence. |
| [BT03-PostFix-Validation.png](Screenshots/BT-03/BT03-PostFix-Validation.png) | **Post-fix validator result** with **2 low-severity overgeneralization flags**: the evidence did not show repeated start/stop cycles across several services. The analyst corrected both claims. |

**Key distinction:** One `Software Protection` running→stopped sequence was recorded. Other selected services were shown stopping; the six records do not establish repeated starts/stops across all services or malicious intent.

## 5. Windows-Wide and Shared Screenshots (12 images)

### `Windows/Final-Verification` (2 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [BT-PostFix-Test-Summary.png](Final-Verification/BT-PostFix-Test-Summary.png) | **Three-case post-fix live-test comparison**: BT-01 reported **2**, BT-02 **1**, and BT-03 **2** automated flags. Counts measure validator findings, **not** the number of confirmed AI hallucinations. |
| [Sysmon-Parser-Compatibility.png](Final-Verification/Sysmon-Parser-Compatibility.png) | **Parser interoperability check**: demonstrates that Windows/Sysmon fields can be ingested for downstream event analysis. Consult the run log for the exact schema/assertions tested. |

### `Windows/Screenshots/General-Review` (6 images)

These screenshots carry non-unique filenames, so their **exact case association is not proven by filename**. Preserve them as supporting UI/run evidence and inspect the visible analysis ID before citing a particular case.

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [1-Mistral-Windows-Log-Analysis.png](Screenshots/General-Review/1-Mistral-Windows-Log-Analysis.png) | **Mistral Windows-log analysis screenshot, segment 1**; captures part of a model-generated Windows security report. Case/run ID requires visual confirmation. |
| [2-Mistral-Windows-Log-Analysis.png](Screenshots/General-Review/2-Mistral-Windows-Log-Analysis.png) | **Mistral Windows-log analysis screenshot, segment 2**; continuation of a report/output view. Exact case/run ID requires visual confirmation. |
| [3-Mistral-Windows-Log-Analysis.png](Screenshots/General-Review/3-Mistral-Windows-Log-Analysis.png) | **Mistral Windows-log analysis screenshot, segment 3**; additional model output. Exact case/run ID requires visual confirmation. |
| [1-Human-Analyst-Review.png](Screenshots/General-Review/1-Human-Analyst-Review.png) | **Human-in-the-loop review screenshot, segment 1**; shows the analyst-review workflow rather than an automatically approved conclusion. Exact case requires visual confirmation. |
| [3-Human-Analyst-Review.png](Screenshots/General-Review/3-Human-Analyst-Review.png) | **Human-in-the-loop review screenshot, segment 3**; review status or findings should be checked against the saved review record. |
| [Human-Analyst-Review.png](Screenshots/General-Review/Human-Analyst-Review.png) | **General human-review workflow illustration**; retained as supporting proof that findings were subject to analyst decision. |

### `Shared/Regression-Tests` (3 images)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [Full-Regression-Testing.png](../Shared/Regression-Tests/Full-Regression-Testing.png) | **End-to-end automated regression testing** of the Week-2 application. The full current suite subsequently passed **113/113 tests**; verify the screenshot's own displayed count before using it as proof of that specific run. |
| [Full-Regression-After-Timestamp-Fix.png](../Shared/Regression-Tests/Full-Regression-After-Timestamp-Fix.png) | **Regression rerun after timestamp-check changes**, demonstrating that earlier application behavior was retested following the time-comparison fix. |
| [Timestamp-Validation-Fix-Test.png](../Shared/Regression-Tests/Timestamp-Validation-Fix-Test.png) | **Timestamp validation fix**: tests for correct high-precision time matching, detection of genuinely incorrect times, and preservation of evidence-reference verification. |

### `Shared/Setup-Verification` (1 image)

| Screenshot | What happened / what operation the screenshot represents |
|---|---|
| [Ollama-Connection.png](../Shared/Setup-Verification/Ollama-Connection.png) | **Local AI connectivity/setup check** showing the application environment communicating with Ollama/Mistral; relates to private, local inference readiness rather than a security incident itself. |

**Catalog reconciliation:** Attack screenshots **23** + benign screenshots **7** + final verification **2** + general review **6** + shared regression **3** + shared setup **1** = **42 images**.

## 6. Evidence Verification and Analysis Workflow

1. **Acquisition & provenance:** Preserve recorded source EVTX files and their source metadata or checksums.
2. **Preparation:** Convert/select events for focused JSON; keep original fields and document any evidence-ID renumbering.
3. **Parser verification:** Assert event counts, IDs, timestamps, source types, and important semantic fields.
4. **Local AI analysis:** Pass selected events to Mistral running through Ollama; store the generated report and analysis ID.
5. **Automated validation:** Check references, event semantics, process paths, timestamps, unsupported conclusions, and output completeness. A zero-flag report is **not** automatically correct.
6. **Human analyst review:** Record `Approved`, `Corrected`, or other applicable dispositions with source-supported findings and uncertainty.
7. **Final documentation:** Produce evidence-derived timelines, case studies, evaluation reports, and integrity manifests without rewriting the original model output.

### Important safeguards

- A **validator flag is a request for review**, not proof of hallucination or malicious activity.
- **Benign candidate** means the selected records are consistent with a normal explanation; it does **not** establish that every activity was authorized or safe.
- Sysmon **Event ID 1** documents process creation, **not** process termination; **Event ID 11** documents file creation; **Event ID 13** documents a registry value set.
- Windows Security **Event ID 1102** is **audit-log clearing**, **5145** is a detailed network-share access check, **4624/Type 5** is service logon, and **4672** documents special privileges assigned to a logon.
- Windows System **Event ID 7036** records service-state changes; ordinary start/stop transitions alone do not prove tampering.
- Model-generated timestamps or source facts must **never** replace original event data.

## 7. Canonical Sources, Checksums, and Archiving

| Material | Canonical location (relative to Week-2 root) | Handling rule |
|---|---|---|
| Original attack/benign datasets | `Data/Real-Datasets/Windows-Attacks/` and `Data/Real-Datasets/Windows-Benign/` | **Do not move or modify** during screenshot cleanup. |
| Saved Mistral analyses and human reviews | `Results/AN-*/` | Keep original analysis and review records unchanged; screenshot files are not the source of truth. |
| Source-to-focused evidence maps | Inside each `Data/Real-Datasets/Windows-*/<case>/` directory | Preserve mappings and Record IDs. |
| Final Windows reports | `Documentation/Windows/` | Use alongside case studies and verified timelines. |
| Evidence classification manifest | `Documentation/Organization-Logs/Windows-Evidence-Classification-20261018-201854-286.csv` | Source of screenshot filename/category/SHA-256 mapping. |
| Canonical screenshots | `Evidence/Windows/Screenshots/<case>/`, `Evidence/Windows/Final-Verification/`, and `Evidence/Shared/` | Keep and reference these classified copies. |
| Legacy flat/root copies | `Evidence/*.png` and `Evidence/Windows/Screenshots/*.png` (if still present) | These are **duplicate working copies** once SHA-256-matched to canonical screenshots. Back them up externally before removal. |

**Current cleanup note (2026-10-18):** The attempted Python cleanup via `@' ... '@ | python -` stopped at `input()` with `EOFError` before the file-moving loop. Therefore, do **not** infer that the 84 legacy copies were archived. The recorded audit had verified **42/42** matching copies in each of the original, flat, and classified locations, and found zero explicit legacy-path references among 180 checked text files; this does not rule out dynamically constructed paths. If freeing disk space, copy the redundant flat/root images to a verified external backup first and remove only those duplicates after rechecking hashes. Never delete the 42 classified screenshots, the case source files, or the analysis records.

**Regression checkpoint:** After the Windows fixes and directory organization, the Week-2 test suite passed **113 tests**. The final Windows documentation stage created case studies for all 7 cases, verified timelines for all 4 attack cases, and three Windows evaluation/summary reports.

---

**Maintenance rule:** For future screenshots, choose the correct case directory *at capture time*, use descriptive unique filenames with the case ID, and update this index. Do not fabricate source timestamps, validation results, outcomes, or claims from screenshots alone.
