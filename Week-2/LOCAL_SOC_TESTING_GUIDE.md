# DEPI P5 — Week 2, Part 1: Local AI-Assisted SOC Triage

> **Scope:** File-based Windows, Linux, and Network log triage using a unified Python engine and a local Mistral model. This guide documents the tested workflow; it is **not** an approval of AI incident conclusions and does not replace the separate OpenObserve/SIEM component.

## 1. Project idea and Week-2 objectives

DEPI P5 aims to support a SOC analyst by combining deterministic log analysis with local AI-assisted triage, evidence validation, and structured reporting. The broader architecture is: security logs / SIEM alerts → Python orchestration → detection and evidence preparation → local AI → SOC draft → QA validation → human review → later SOAR / incident response.

**Week-2 goals relevant to this component:**

1. Gather representative security logs and identify their source family.
2. Parse the evidence, assign stable references (`E001`, `E002`, …), and perform pre-AI deterministic checks.
3. Send relevant events to local Mistral via Ollama.
4. Generate a SOC report with evidence references, uncertainty, and recommended investigation steps.
5. Validate AI output against the source and require analyst review when needed.

**Scope boundary:** This README covers local file-based testing only. The OpenObserve → webhook → AI alert-triage workflow is a separate Week-2 component. SOAR actions are Week-3 scope.

### Tested pipeline

```text
Input file (Windows / Linux / Network)
    → unified_soc_v04_candidate.py
    → parsing + classification + deterministic Python detection
    → evidence references / batches
    → Ollama: mistral:7b-instruct-v0.3-q4_K_S
    → AI SOC drafts
    → automated QA checks
    → Results/UNIFIED-*/manifest.json + report.md
    → human analyst review (required)
```

## 2. Environment and prerequisites

- **Project root:** `D:\Desktop\w\Week-2`
- **Engine:** `unified_soc_v04_candidate.py`
- **Tested engine version:** `unified-intake-0.4.0-candidate`
- **Local model:** `mistral:7b-instruct-v0.3-q4_K_S` (Ollama)
- **Shell:** Windows PowerShell
- **Output directory:** `Results`

Before `analyze`, make sure Python is available, Ollama is running, and the configured model is installed. The examples use `python -B` to avoid Python bytecode cache writes. Paths are relative to the project root.

## 3. Logs collected and selected for testing

| Family | Scenario | Selected input | Events | Evidence |
|---|---|---|---:|---|
| Windows | RT-02 Discovery | `Data\Real-Datasets\Windows-Attacks\RT-02-Discovery\RT-02-Discovery-focused-v2.json` | 4 | E001–E004 |
| Linux | LT-01 SSH Brute Force | `Data\Real-Datasets\Linux-Attacks\LT-01-SSH-Brute-Force\LT-01-focused.log` | 42 | E001–E042 |
| Network | NT-03 C2 Beaconing *candidate* | `Data\Real-Datasets\Network-Attacks\NT-03-C2-Beaconing\NT-03-focused.json` | 25 | E001–E025 |

### 3.1 Windows — RT-02 Discovery

- `E001`: Windows Security Event ID **1102**, audit log cleared.
- `E002`–`E004`: Event ID **5145**, remote-share access checks involving `winreg`, `lsarpc`, and `srvsvc`.
- Observed host: `WIN-77LTAPHIQ1R.example.corp`; observed source IP: `10.0.2.17`.
- **Investigation question:** Are the events consistent with suspicious discovery or legitimate administration? Authorization and compromise are **not** established by these records alone.

### 3.2 Linux — LT-01 SSH Brute Force

- SSH authentication and failed-password logs from host `LabSZ`.
- Observed source IP: `183.62.140.253`.
- Whole-family Python finding: `LINUX_SSH_REPEAT_FAILURE`.
- **13** `Failed password` records were identified from the source IP among the **42** parsed log events.
- **Investigation question:** Is this a password-guessing pattern? No successful unauthorized login is established by the tested evidence.

### 3.3 Network — NT-03 C2 Beaconing Candidate

- Zeek-style network records, including **derived aggregates** (`E001`, `E002`) and original connection records.
- Source `192.168.1.199` → destination `46.101.251.172:80/TCP`.
- Whole-family Python finding: `NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE`.
- **4** repeated source-port groups across **17** original `conn.log` rows, with `S0` records preceding an `SF` record per group.
- Median observed inter-arrival interval: **8.56 seconds**. Source ports: **59224, 59228, 59236, 59240**.
- **Investigation question:** What explains the repeated TCP four-tuple sequences? The records do **not** by themselves prove separate retry sessions, periodic beaconing, C2, malware, or compromise.

## 4. Pre-AI tests — `inspect`

**Purpose:** Check file parsing, log-family classification, event references, and deterministic Python findings **without calling the AI**. This is a read-only inspection, not a SOC report or incident verdict.

**General form:**

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py inspect "RELATIVE_PATH_TO_LOG"
```

### Windows: pre-AI

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py inspect "Data\Real-Datasets\Windows-Attacks\RT-02-Discovery\RT-02-Discovery-focused-v2.json"
```

Expected from the tested input: 4 parsed Windows events, E001–E004. No Python grounding finding in this case does **not** imply benign activity.

### Linux: pre-AI

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py inspect "Data\Real-Datasets\Linux-Attacks\LT-01-SSH-Brute-Force\LT-01-focused.log"
```

Expected: 42 parsed Linux events and `LINUX_SSH_REPEAT_FAILURE`.

### Network: pre-AI

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py inspect "Data\Real-Datasets\Network-Attacks\NT-03-C2-Beaconing\NT-03-focused.json"
```

Expected: 25 parsed Network events and `NETWORK_TCP_REPEATED_FOUR_TUPLE_SEQUENCE`.

**Pre-AI checklist:** Confirm expected event count; correct family; no unexplained parsing loss; and review findings as **indicators**, not proof of compromise.

## 5. AI tests — `analyze`

**Purpose:** Run the full local analysis: parse and classify → deterministic detection → Mistral AI batches → QA validation → save unified SOC report and manifest.

**General form:**

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py analyze "RELATIVE_PATH_TO_LOG"
```

### Windows: AI and SOC report

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py analyze "Data\Real-Datasets\Windows-Attacks\RT-02-Discovery\RT-02-Discovery-focused-v2.json"
```

### Linux: AI and SOC report

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py analyze "Data\Real-Datasets\Linux-Attacks\LT-01-SSH-Brute-Force\LT-01-focused.log"
```

### Network: AI and SOC report

```powershell
Set-Location "D:\Desktop\w\Week-2"
python -B unified_soc_v04_candidate.py analyze "Data\Real-Datasets\Network-Attacks\NT-03-C2-Beaconing\NT-03-focused.json"
```

**Important:** `analyze` writes new timestamped result folders. An exit code of zero means operational completion; **it does not mean** QA approval.

## 6. Copy/paste PowerShell examples — pre-AI + AI + SOC report

Each block can be copied as-is into PowerShell. It runs `inspect` first, stops if that process fails, then runs `analyze` to create a report under `Results`. These examples **do not overwrite source logs or modify the engine**.

### 6.1 Complete Windows test

```powershell
Set-Location "D:\Desktop\w\Week-2"
$log = "Data\Real-Datasets\Windows-Attacks\RT-02-Discovery\RT-02-Discovery-focused-v2.json"
python -B unified_soc_v04_candidate.py inspect $log
if ($LASTEXITCODE -ne 0) { throw "Windows inspect failed" }
python -B unified_soc_v04_candidate.py analyze $log
if ($LASTEXITCODE -ne 0) { throw "Windows analyze failed" }
Write-Host "Windows operational test completed. Review Results and QA gate."
```

### 6.2 Complete Linux test

```powershell
Set-Location "D:\Desktop\w\Week-2"
$log = "Data\Real-Datasets\Linux-Attacks\LT-01-SSH-Brute-Force\LT-01-focused.log"
python -B unified_soc_v04_candidate.py inspect $log
if ($LASTEXITCODE -ne 0) { throw "Linux inspect failed" }
python -B unified_soc_v04_candidate.py analyze $log
if ($LASTEXITCODE -ne 0) { throw "Linux analyze failed" }
Write-Host "Linux operational test completed. Review Results and QA gate."
```

### 6.3 Complete Network test

```powershell
Set-Location "D:\Desktop\w\Week-2"
$log = "Data\Real-Datasets\Network-Attacks\NT-03-C2-Beaconing\NT-03-focused.json"
python -B unified_soc_v04_candidate.py inspect $log
if ($LASTEXITCODE -ne 0) { throw "Network inspect failed" }
python -B unified_soc_v04_candidate.py analyze $log
if ($LASTEXITCODE -ne 0) { throw "Network analyze failed" }
Write-Host "Network operational test completed. Review Results and QA gate."
```

### 6.4 Optional: run all three sequentially

```powershell
Set-Location "D:\Desktop\w\Week-2"
$datasets = [ordered]@{
    Windows = "Data\Real-Datasets\Windows-Attacks\RT-02-Discovery\RT-02-Discovery-focused-v2.json"
    Linux   = "Data\Real-Datasets\Linux-Attacks\LT-01-SSH-Brute-Force\LT-01-focused.log"
    Network = "Data\Real-Datasets\Network-Attacks\NT-03-C2-Beaconing\NT-03-focused.json"
}
foreach ($family in $datasets.Keys) {
    $log = $datasets[$family]
    Write-Host "=== $family / PRE-AI ==="
    python -B unified_soc_v04_candidate.py inspect $log
    if ($LASTEXITCODE -ne 0) { throw "$family inspect failed" }
    Write-Host "=== $family / AI ==="
    python -B unified_soc_v04_candidate.py analyze $log
    if ($LASTEXITCODE -ne 0) { throw "$family analyze failed" }
}
Write-Host "Operational tests complete. Inspect QA acceptance gates before approving reports."
```

## 7. Locate and review generated SOC reports

A successful `analyze` run prints a path similar to:

```text
STATUS: UNIFIED AI DRAFT SAVED: D:\Desktop\w\Week-2\Results\UNIFIED-<timestamp>-<id>
```

Within that folder:

- **`manifest.json`** — input SHA256, event counts, family classification, batches, events sent to AI, whole-family Python findings, source-derived timeline, QA summary, acceptance gate.
- **`report.md`** — unified SOC draft, Python baseline, per-batch Mistral analysis, evidence references, timeline, uncertainties, recommendations, and limitations.
- **`Results\AN-*\analysis.json`** — per-model-run details and individual QA flags.

**Read the report from a known run (example):**

```powershell
Get-Content -LiteralPath "D:\Desktop\w\Week-2\Results\UNIFIED-20261103T013010Z-1dcd\report.md" -Raw -Encoding UTF8
```

**Read validation flags from a known run (example):**

```powershell
$j = Get-Content -LiteralPath "D:\Desktop\w\Week-2\Results\AN-20261103-012816-d2f7\analysis.json" -Raw -Encoding UTF8 | ConvertFrom-Json
$j.validation.flags | Format-List
```

## 8. Actual test results (2026-11-03)

| Measure | Windows RT-02 | Linux LT-01 | Network NT-03 |
|---|---:|---:|---:|
| Events parsed / sent to AI | 4 / 4 | 42 / 42 | 25 / 25 |
| AI batches | 1 | 3 | 2 |
| Whole-family Python findings | 0 | 1 | 1 |
| QA flags | 1 | 6 | 3 |
| High-severity QA flags | 0 | 5 | 2 |
| Operational execution | PASS | PASS | PASS |
| Analytical status | Review required | Blocked pending correction | Blocked pending correction |

**Totals:** 71 events, 6 AI batches, 10 QA flags, including 7 high-severity flags. No final human approval recorded. These are historical test observations, **not guaranteed results on a rerun**.

### 8.1 Windows reference output

- Unified: `Results\UNIFIED-20261103T011039Z-83e4`
- AI run: `AN-20261103-011039-c170`
- One medium QA flag: `unsupported_authorization_status`. Administrative authorization cannot be inferred from the logs alone.

### 8.2 Linux reference output

- Unified: `Results\UNIFIED-20261103T012225Z-3676`
- AI runs: `AN-20261103-011955-8006`, `AN-20261103-012133-14d3`, `AN-20261103-012225-6bcf`
- Five **confirmed** timestamp/citation mismatches (`E011`, `E017`, `E020`, `E023`, `E026`), checked against original log lines.
- One medium flag: `finding_without_evidence_ref`.
- Acceptance gate: `BLOCKED_PENDING_CORRECTION`.

### 8.3 Network reference output

- Unified: `Results\UNIFIED-20261103T013010Z-1dcd`
- AI runs: `AN-20261103-012816-d2f7`, `AN-20261103-013010-57df`
- Medium: `network_tcp_retry_missing_quantification` — AI omitted counts and intervals for the pattern in the first batch (2 groups, 8 rows available to that batch).
- High: `timeline_timestamp_mismatch` — the AI cited `E006` with `20:06:29.067208Z`, while the source-derived timestamp for `E006` is `20:06:46.194937Z`.
- High: `network_tcp_retry_pattern_not_identified` — AI did not explain the supported `S0-before-SF` repeated-four-tuple pattern.
- Acceptance gate: `BLOCKED_PENDING_CORRECTION`.

**Why the counts differ:** The Network Python baseline considers all 25 records (4 groups / 17 rows); the first AI batch and its validator see only a subset (2 groups / 8 rows).

## 9. QA rules and analyst interpretation

- A **flag** is a request for review, not automatic proof of hallucination.
- **High-severity** evidence/timeline issues block analytical acceptance until corrected or appropriately resolved.
- A successful `analyze` command does **not** mean a valid incident conclusion.
- Keep the original event reference and timestamp together; never borrow a timestamp from a nearby related event.
- Distinguish an **observable** (e.g., IP, port, event state) from a verified malicious IOC.
- Distinguish a **Zeek connection state** (`SF`) from an HTTP application-level response; HTTP success requires appropriate application evidence.
- Different TCP source ports do not alone establish evasion.
- Repeated connection rows do not alone establish C2 beaconing or compromise.
- When events are batched, the Python whole-family baseline is not equivalent to a consolidated AI synthesis.
- Source evidence is labeled `user_supplied_unverified`; external provenance and authorization are not automatically confirmed.

## 10. Outstanding improvements and next steps

1. Correct confirmed Linux and Network timestamp attribution errors.
2. Improve evidence references and explain security findings with precise supporting details.
3. Ensure network narratives quantify and interpret the detected repeated TCP sequences without overstating C2 conclusions.
4. Improve cross-batch synthesis while preserving the whole-family Python baseline.
5. Rerun regression and scenario tests, compare new QA results, and record human review decisions.
6. Document the separate OpenObserve/SIEM Week-2 component separately before declaring Week-2 complete.

**Current conclusion:** The local pipeline is **operationally functional** for all three tested log families, but the AI-generated security reports are **not yet fully accepted**. No SOAR actions were executed as part of these tests.
