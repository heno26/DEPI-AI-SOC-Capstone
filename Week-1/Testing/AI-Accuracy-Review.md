# AI Accuracy Review — Reviewed from Actual Ollama Outputs

**Project:** DEPI Project 5 · **Week:** 1 · **Review date:** 16 October 2026

**Status:** Human review completed for 39 outputs (19 original baseline + 2 diagnostic retries + 18 additional baseline). Ratings are analyst judgments, not certified model accuracy. Evidence screenshots and final privacy sign-off are separate.

## Method and rating scale

- Ground truth: `Testing/Test-Cases.json`. Each answer was inspected in its `Benchmarks/results/<run>/raw/` text file.
- **Quality (1–5):** 1 = seriously wrong or unusable; 3 = mixed/usable only with careful correction; 5 = correct, complete, grounded, correctly formatted.
- **Unsupported-fact severity (0–3):** 0 = none observed; 1 = minor unsupported or altered fact; 2 = material false assertion; 3 = fabricated security indicator or severely corrupted evidence.
- Hallucination severity is **not a count of hallucinations**. An incorrect verdict, missing fact, or unsupported inference can reduce quality even when severity is 0.
- Original tests used `temperature=0`, `seed=42`, `num_ctx=4096`, `num_predict=800`; **Mistral TC-06 and Phi-3 TC-05 were retried with different settings**, therefore those scores must not be described as baseline run results.

## Original review — TC-01 through TC-07 (21 case/model combinations)

| Model | Case | Quality /5 | Unsupported-fact severity /3 | Review finding |
|---|---|---:|---:|---|
| Llama 3.2 | TC-01  | 1 | 0 | Critical miss: marks suspicious activity None despite brute-force pattern, successful deploy login and root-level wget script download. |
| Llama 3.2 | TC-02  | 1 | 2 | Mistakes Windows 4625 failed logons for successes; fails to use 4624; overlooks password spraying and misdescribes Administrators change. |
| Llama 3.2 | TC-03  | 1 | 1 | Does not choose a verdict (prints all options); incorrectly treats WINWORD parent as benign, assigns P3 and does not escalate. |
| Llama 3.2 | TC-04  | 2 | 0 | Recognizes authorized scanner and scan window, but does not select likely false positive and assigns unsupported P2 High priority. |
| Llama 3.2 | TC-05  | 4 | 1 | Correct campaign, IOCs and attribution; illegally alters exact defanged IOC strings (removes [.] tokens) despite extraction rule. |
| Llama 3.2 | TC-06  | 3 | 2 | Timeline and actions accurate; asserts Impact and Root Cause Confirmed without supporting details; omits explicit Unknown impact. |
| Llama 3.2 | TC-07  | 2 | 1 | Benign sudo maintenance and cron misconstrued as suspicious privilege escalation; output cut off by 800-token cap. |
| Mistral 7B | TC-01  | 3 | 0 | Correctly detects failures, successful login, and sudo wget; output truncated before required remaining sections. |
| Mistral 7B | TC-02  | 1 | 2 | Misreads 4625 failures as successes, invents a successful logoff, and misstates svc_backup event details; missed 4624. |
| Mistral 7B | TC-03  | 4 | 1 | Correct likely true positive with escalation; overstates encryption/exfiltration and recommends premature block actions. |
| Mistral 7B | TC-04  | 1 | 1 | Overreacts to authorized Nessus scan inside approved window, calls P2 and Tier-2 escalation; unsupported assertion about unusual scan speed. |
| Mistral 7B | TC-05  | 3 | 1 | Extracts IOCs correctly in defanged form, but output is repetitive, incomplete at token cap, and suggests unconfirmed attack success. |
| Mistral 7B | TC-06 (retry) | 4 | 0 | Retry only: all six times, actions, and unknowns are retained; suspect impact/root cause clearly labeled; not comparable to baseline settings. |
| Mistral 7B | TC-07  | 4 | 0 | Correctly describes routine admin activity as low severity and avoids incident escalation; some unnecessary follow-up. |
| Phi-3 Mini | TC-01  | 3 | 2 | Recognizes brute force and download, but falsely claims script executed; output stops early before all required headings. |
| Phi-3 Mini | TC-02  | 1 | 3 | Confuses failed and successful Windows logons, invents corrupted timestamp/status values, and misses 4624 plus administrator change significance. |
| Phi-3 Mini | TC-03  | 3 | 1 | Escalates to Tier 2, but fails to mention Word parent and claims destination information is missing despite supplied IP. |
| Phi-3 Mini | TC-04  | 2 | 1 | Does not select likely false positive and assigns P2; unsupported judgment that scan volume is unusually high for authorized scanning. |
| Phi-3 Mini | TC-05 (retry) | 2 | 3 | Retry only: fabricates 192.008.0.34 as sender IP while using correct 192.0.2.88 elsewhere; inconsistent IOC extraction. |
| Phi-3 Mini | TC-06  | 3 | 2 | Full correct incident timeline and unknown open questions; incorrectly labels impact and root cause Confirmed. |
| Phi-3 Mini | TC-07  | 3 | 2 | Correctly identifies routine activity, but invents 10.00.0.15 and falsely attributes sudo apt commands to CRON. |

## Per-case primary findings

**TC-01 (suspicious SSH):** Llama classified the activity as “None identified” and omitted the critical `sudo wget` download. Mistral extracted the significant sequence; Phi identified it but incorrectly said the script *ran* (the log only shows a download).

**TC-02 (Windows password spraying):** All three models mishandled Windows Event ID `4625` (failed authentication), and did not reliably correlate the subsequent `4624` successful logon with the `4732` Administrators membership change. **This is a blocking weakness for unsupervised SOC triage.**

**TC-03 (suspicious PowerShell):** Mistral recommended correct TP escalation. Phi called for investigation and escalation. Llama presented multiple contradictory verdict options and incorrectly selected no Tier-2 escalation.

**TC-04 (authorized Nessus scan):** None of the models confidently and correctly selected “Likely False Positive” with appropriately low priority. They missed/overrode scheduled-authorized context, with particularly concerning Mistral Tier-2 escalation.

**TC-05 (phishing indicators):** Llama extracted the indicators but removed defanging brackets, which violates exact-IOC extraction. Mistral mostly preserved the values. On its modified-settings retry, Phi invented sender IP `192.008.0.34` while also giving the actual `192.0.2.88` in another section.

**TC-06 (incident report):** All reproduced the event timeline, but Llama and Phi incorrectly labeled impact and root cause “Confirmed.” Mistral retry labeled uncertainty and open questions more appropriately.

**TC-07 (routine administration):** Llama falsely interpreted sudo maintenance and a normal cron session as suspicious escalation. Mistral largely accepted the benign context. Phi detected benign behavior but fabricated IP `10.00.0.15` and misattributed sudo commands to CRON.

## Provisional manual mean quality (not standardized benchmark accuracy)

| Model | Cases reviewed | Mean quality /5 | Key limitation |
|---|---:|---:|---|
| Llama 3.2 | 7 | 2.00 | Fast but major false negatives on TC-01 and TC-03 |
| Mistral 7B | 7 (includes 1 retry) | 2.86 | Wrong on Windows events and authorized Nessus scan; generation repetition in baseline |
| Phi-3 Mini | 7 (includes 1 retry) | 2.43 | Fabricated security indicators and erroneous log references |

**Interpretation:** Do not rank these numbers as an apples-to-apples accuracy benchmark. The successful retries used different decoding parameters, several original answers were truncated at 800 tokens, and the rating is a single-reviewer qualitative assessment.

## Corrective measures before Week 2

1. Add minimal ground-truth guardrails: Windows 4625=failure, 4624=success, 4732=group change; sudo apt and cron alone are not evidence of compromise.
2. Require exactly one triage verdict, quote supporting timestamps, and compare benign change/asset context before escalation.
3. Preserve IOCs **character for character** from source; reject any AI-produced IOC not present in provided data.
4. Increase output token limit only for lengthy tasks after checking context/resource fit; record all decoding settings.
5. Require human approval for all conclusions, escalations and response actions. Never let the current models autonomously block IPs or isolate hosts.

## Evidence examples

- `Benchmarks/results/run_20261016_061045/raw/llama3.2_3b__TC-01.txt` — critical false-negative.
- `Benchmarks/results/run_20261016_061045/raw/mistral_7b-instruct-v0.3-q4_K_S__TC-04.txt` — false escalation on authorized scan.
- `Benchmarks/results/run_20261016_063843/raw/phi3_mini__TC-05.txt` — invented IOC.
- Corresponding analyst scores and notes are written to the relevant run’s `results.csv` (columns `manual_quality_1to5`, `manual_hallucination_0to3`, `manual_notes`).

## Reviewer sign-off

Reviewer: ____________________   Date: ____________________   Status: **Reviewed draft; obtain student sign-off**


## Additional security cases — TC-08 through TC-13 (18 responses)

An additional six synthetic SOC log scenarios per model were evaluated using the same benchmark settings across all 18 new requests. **All 18 executed; 18/18 did not imply correct analysis**. The detailed per-case scores, evidence mistakes, and corrective actions are preserved in [`Additional-6-Accuracy-Review.md`](Additional-6-Accuracy-Review.md), with machine-readable manual notes in [`Additional-6-Manual-Review.csv`](Additional-6-Manual-Review.csv).

| Model | Additional manual quality mean / 5 | Notable serious errors |
|---|---:|---|
| Llama 3.2 3B | 1.50 | Incorrect `None identified` on WAF SQLi and EDR LSASS events; missed AWS no-MFA risk. |
| Mistral 7B | 2.67 | Calls AWS no-MFA + admin/key changes Low; falsely denies RDP standard-hours restriction. |
| Phi-3 Mini | 1.67 | Corrupts IOC and timestamps; missed DNS suspicion and false-positive patch activity. |

**Do not merge these qualitative review means with original-run values into a claimed standardized accuracy figure.** The original evaluation used two modified-parameter diagnostic retries and reflects different security scenarios.
