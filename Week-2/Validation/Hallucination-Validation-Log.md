# Deliverable 4 - Hallucination / Validation Log

**Status:** Method and tooling COMPLETE. Live Week 2 model results: **PENDING LOCAL EXECUTION.**
Flags are **requests for human review**, not proof of hallucination. Passing every check is **not** proof of correctness.

## 1. Where the log lives
| Artifact | Created by | Content |
|---|---|---|
| `Validation/validation_log.csv` | Application, append-only | One row per automated flag, per analyst disposition and per analyst review (model, prompt version, input SHA-256, exact value, affected section) |
| `Results/<analysis_id>/analysis.json` | Application | Full record including flags, dispositions and review history |
| `Validation/Hallucination-Validation-Log.generated.md` | `python app.py export` | Summary table + flag detail built from all saved results |
| This file | Hand-maintained | Method, known limits, baseline replay, and the student's conclusions |

## 2. A - Automated checks (deterministic, in `Core/validator.py`)
| Check | What it tests | Severity | Known limit |
|---|---|---|---|
| `unsupported_ip`, `malformed_ip_like` | IPv4 in output must appear **character for character** in the input (defanged forms compared after re-fanging). Near-matches (e.g. `203.00.113.61`) are reported with the source value they resemble | high / medium | A real version number such as `10.0.19045` can look IP-like |
| `unsupported_url`, `unsupported_domain`, `unsupported_email`, `unsupported_filename` | Same for URLs, domains, emails, file names | high / medium | Ordinary text containing a dot can look like a domain |
| `unsupported_hash`, `unsupported_cve` | MD5/SHA-1/SHA-256 and CVE IDs must be in the input | high | - |
| `ioc_format_altered` | Defanged indicators (`[.]`, `hxxp`) must stay defanged | low | - |
| `unsupported_timestamp` | Dates and HH:MM:SS in the output must appear in the input (catches `20260-10-14`) | high / medium | Does not check that a *correct-looking* timestamp is attached to the correct event (timeline rows are checked separately) |
| `timeline_timestamp_mismatch`, `timeline_row_without_ref` | Each AI timeline row's timestamp must appear in the cited `E###` event | high / medium | Only checks rows that follow the requested table format |
| `unsupported_entity`, `possible_unsupported_hostname` | `Account=`/`User=`/`host=` style values, backtick-quoted tokens and host-like tokens must be in the input | medium / low | Heuristic; can fire on harmless words |
| `nonexistent_evidence_ref`, `finding_without_evidence_ref` | `[E###]` must exist; findings should cite one | high / medium | A citation proves the line exists, not that the finding is right |
| `possible_fabricated_rule_id`, `possible_fabricated_agent_id` | Rule/agent IDs mentioned must be in the input | high | - |
| `eventid_semantic_mismatch` | e.g. 4625 described as success, 4732 as removal | medium | Sentence-level heuristic |
| `unsupported_conclusion`, `unsupported_attribution` | "confirmed breach", "script was executed", actor/malware names that are not in the input | medium | Can flag legitimate statements (see replay) |
| `none_claim_vs_signals` | Output says nothing suspicious, but code found risk signals (blocked/prevented action, no-MFA, group change, SeDebugPrivilege, etc.) | high | Signal list is small and hand-written |
| `output_truncated`, `missing_section`, `input_truncated` | Output hit token limit, required headings missing, input did not fit in context | high / medium | - |
| `prompt_injection_in_input` | Instruction-like text inside the logs (treated as data) | medium | Pattern list only |
| Triage consistency checks | Verdict vs priority, FP verdict vs signals, benign context ignored, priority far below SIEM level | high / medium / low | Rules of thumb for the analyst, not policy |

**Not checked automatically (the analyst must do it):** whether the verdict is right, whether a conclusion follows from the events, whether a benign explanation was missed or invented, whether reasoning about attacker intent is sound.

## 3. B - Manual analyst review (in `python app.py review <id>` or menu 4)
For every flag the analyst records a disposition: **Confirmed hallucination / False alarm / Needs follow-up / Unreviewed**. Then:
| Field | Meaning |
|---|---|
| Review status | **Pending Review** (default) / **Approved** / **Corrected** / **Rejected** |
| Correct findings | Statements verified against the raw evidence |
| Incorrect findings | Statements that are wrong (even if no automatic flag fired) |
| Missing evidence | Relevant evidence the AI ignored |
| Hallucinations | Invented or altered values/claims, in the analyst's words |
| Final classification / priority | The **analyst's** decision (triage only), independent of the AI recommendation |
| Notes, analyst name, timestamp | Recorded with a history of earlier states |
The application will not approve a result by itself; approving with undispositioned flags needs the typed word `APPROVE`.

## 4. C - Final review status definitions
Pending Review = nobody has checked it. Approved = the analyst verified it against the evidence as is. Corrected = usable after the analyst's corrections (recorded). Rejected = not usable.

## 5. Baseline: validator replayed on REAL Week 1 model outputs (offline replay, no model run)
Script: `Testing/replay_week1_outputs.py` over the 41 raw output files in the Week 1 package. Full table: `Testing/test_results/week1_replay_validation.md`.
These outputs came from the **Week 1 prompts**, not the Week 2 prompts, and the Week 1 manual review is the reference. This is a check of the *validator*, not of any model.

| Week 1 manual finding (source: Week 1 review files) | Validator result on the raw output |
|---|---|
| Phi-3 TC-05 retry: invented IP `192.008.0.34` | Flagged `unsupported_ip` (high) |
| Phi-3 TC-07: invented `10.00.0.15` | Flagged `unsupported_ip` (high) |
| Phi-3 TC-08: `203.0.113.61` altered to `203.00.113.61` | Flagged `unsupported_ip` (high) |
| Phi-3 TC-11: `203.0.113.90` altered to `203.00113.90` | Flagged `malformed_ip_like` (medium) |
| Phi-3 TC-02 / TC-12 / TC-13: corrupted timestamps `20260-10-14`, `2026-100-14` | Flagged `unsupported_timestamp` (high), 4 values |
| Phi-3 TC-01: claims script ran | Flagged `unsupported_conclusion` ("downloads and runs", "downloaded and executed") |
| Mistral TC-02: failed logon described as success | Flagged `eventid_semantic_mismatch` (1 sentence) |
| Llama TC-05: defang removed | Low-severity `ioc_format_altered` flags (3) |
| Mistral TC-03 "script was executed"; Mistral TC-13 "file was executed" | Flagged `unsupported_conclusion`. **Probably false alarms** in context (the PowerShell did run in TC-03; the EDR logged an allowed file execution in TC-13): an analyst would mark them *False alarm* |
| Llama "None identified" errors (TC-01/08/09), Mistral "Low" for TC-11, Mistral TC-12 policy denial | **Not testable by replay** (Week 1 output headings differ). Covered by `none_claim_vs_signals` in Week 2 format; **PENDING LOCAL EXECUTION** |
Caveat: seven of the eight corrupted values were found in Phi-3 output, which is not the primary model. How often Mistral produces such corruption with the Week 2 prompt is unknown until run locally.

## 6. Week 2 live model results (Mistral 7B)
**PENDING LOCAL EXECUTION.** Fill after running `Testing/run_local_model_tests.py` and reviewing results.
| Analysis ID | Input | Flags H/M/L | Confirmed hallucinations | False alarms | Incorrect findings missed by automation | Final status |
|---|---|---|---|---|---|---|
| (pending) | | | | | | |

## 7. Student sign-off
Reviewer: ____________________  Date: ____________  (not signed)
