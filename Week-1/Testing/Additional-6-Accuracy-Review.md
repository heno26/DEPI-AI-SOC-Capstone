# Week 1 — Additional 6 SOC Logs: Manual Accuracy Review

**Project:** DEPI Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone  
**Review date:** 16 October 2026  
**Status:** Draft based on 18 raw local-model responses (six cases × three models); requires student verification and sign-off.

## Scope and methodology

- Compared each raw response in the uploaded results archive against `Testing/Test-Cases.json` cases `TC-08` through `TC-13` and their synthetic source log lines.
- All 18 additional requests executed with the original benchmark settings (`temperature=0`, `seed=42`, `num_ctx=4096`, `num_predict=800`). This makes these six-case runs internally comparable; they do **not** resolve baseline TC-01–TC-07 reliability problems.
- **Manual quality 1–5**: 1 = materially incorrect / unsafe to use as-is; 3 = mixed; 5 = evidence-grounded, complete and consistent. **Unsupported-fact severity 0–3**: 0 = none obvious; 1 = minor error; 2 = material false claim; 3 = altered identifier or corrupted evidence. Severity is *not a hallucination count*.
- The benchmark's expected-finding count is **keyword recall**, not a validated measure of correctness. In particular, source IP alterations can evade the simple IP regex.

## Six-case quantitative benchmark (baseline settings)

| Metric | Llama 3.2 3B | Mistral 7B | Phi-3 Mini |
|---|---:|---:|---:|
| Completed / attempted | 6 / 6 | 6 / 6 | 6 / 6 |
| Avg response time (s) | 12.11 | 32.19 | 22.56 |
| Avg generation speed (tokens/s) | 53.27 | 22.76 | 42.55 |
| Automatic expected-keyword recall | 0.92 | 0.92 | 0.88 |
| Auto-detected unsupported indicators | 0 | 0 | 1 |
| GPU offload (%) | 100 | 89 | 100 |

## Per-case manual assessment

| Model | Case | Quality / 5 | Unsupported-fact severity / 3 | Key finding |
|---|---|---:|---:|---|
| Llama 3.2 3B | TC-08 | 1 | 2 | Reports SUSPICIOUS ACTIVITY: None identified despite SQLi probes; incorrectly claims src IP and host are not provided; misstates two blocked attempts as additional blocked requests and suggests /health was blocked (it was HTTP 200). |
| Llama 3.2 3B | TC-09 | 1 | 1 | Identifies LSASS and EDR block/quarantine but says SUSPICIOUS ACTIVITY: None identified and assigns Low despite high-severity credential-access alert; incorrectly infers privilege elevation from Sysmon creation event. |
| Llama 3.2 3B | TC-10 | 1 | 2 | Does not identify possible DNS tunneling; claims queried domain names are not specified although qnames are present, suggests brute force without evidence, and proposes premature blocking. |
| Llama 3.2 3B | TC-11 | 1 | 2 | Notes group and key changes but misses explicit MFAUsed=No and reports None identified/Low instead of urgent authorization validation; assumes account and source are legitimate. |
| Llama 3.2 3B | TC-12 | 2 | 1 | Identifies approved jump host and two permitted servers, but treats LogonType 10 as normal logon, does not explicitly call out off-hours access or missing approved exception; recommends reviewing exceptions. |
| Llama 3.2 3B | TC-13 | 3 | 1 | Recognizes approved patch deployment and correctly avoids escalation; nonetheless calls an in-window patchsvc login suspicious in ASSUMPTIONS without justification and asks for facts available in the input. |
| Mistral 7B | TC-08 | 3 | 1 | Correctly identifies WAF-blocked SQL injection patterns and HTTP 403 with no confirmed compromise; some incorrect log-line references, unsupported benign labeling of health request, and 6 next steps despite max 5. |
| Mistral 7B | TC-09 | 4 | 0 | Correctly identifies suspicious helper.exe → LSASS access and EDR prevention/termination/quarantine; recognizes high priority and does not claim theft; output truncates immediately after NEXT STEPS heading. |
| Mistral 7B | TC-10 | 2 | 1 | Reports burst of 6 DNS queries but misses TXT record type and the core possible DNS-tunneling signal; speculates about reconnaissance/data gathering rather than evaluating tunneling; does not prove exfiltration. |
| Mistral 7B | TC-11 | 2 | 1 | Correctly extracts no-MFA login, group membership, access-key creation and bucket listing, but then says no suspicious activity/Low and calls events common admin work without authorization evidence. |
| Mistral 7B | TC-12 | 1 | 2 | Materially contradicts access_policy: asserts no standard-hours restriction though the policy is 09:00–17:00; conflates svc_ops account with approved jump host and overlooks off-hours exception requirement. |
| Mistral 7B | TC-13 | 4 | 0 | Correctly treats CHG-2048, patchsvc, signed MSI, and successful maintenance as benign; no unwarranted escalation; some repetitive/inappropriate requests for purpose already stated. |
| Phi-3 Mini | TC-08 | 2 | 3 | Correctly identifies WAF-blocked SQLi patterns, but alters 203.0.113.61 into 203.00.113.61 in missing-info section; output truncated during NEXT STEPS, despite automatic 4/4 keyword match. |
| Phi-3 Mini | TC-09 | 3 | 1 | Correctly explains LSASS access and EDR block/termination/quarantine; calls logged successful 4624 logon a generic attempt and response stops mid-ASSUMPTIONS without severity or steps. |
| Phi-3 Mini | TC-10 | 1 | 2 | Labels burst of six high-entropy TXT queries normal and None identified; claims no unusual frequency and timestamps missing even though timestamps appear, missing possible tunneling. |
| Phi-3 Mini | TC-11 | 1 | 3 | Correctly lists AWS actions/no MFA but changes 203.0.113.90 to 203.00113.90 inside quoted evidence; reports None identified/Low and assumes actions authorized despite absent change ticket. |
| Phi-3 Mini | TC-12 | 1 | 3 | Wrongly assigns FS01-hosted logon and privileges to jump host JUMP-02, fabricates malformed 20260-10-14 timestamp, treats 4672 as a new privilege-escalation grant; fails to emphasize off-hours exception. |
| Phi-3 Mini | TC-13 | 2 | 3 | Misclassifies approved signed monthly maintenance as suspicious; corrupts timestamps to 20260-10-14 and 2026-100-14, despite ground-truth approved change and successful patch. |

## Safety-critical conclusions

**TC-08 (SQL injection, blocked):** Llama prints `None identified` and states IP/host are missing even though the WAF includes both; this is a substantial false negative notwithstanding `found 4/4`. Mistral correctly treats it as blocked suspicious traffic. Phi modifies source IP `203.0.113.61` → `203.00.113.61` and its answer ends mid-section.

**TC-09 (LSASS access prevented by EDR):** Llama again prints `None identified` and `Low` despite a clear high-severity prevention event. Mistral catches and correctly characterizes the EDR intervention, but its output stops before next steps. Phi extracts the evidence but its answer is incomplete.

**TC-10 (DNS tunneling suspicion, not confirmed):** All three largely miss the intended hypothesis about repeated TXT queries to long unique subdomains. Phi goes further by claiming the pattern is normal and that timestamps were not provided, both at odds with the logs. Do **not** equate this to confirmed data exfiltration.

**TC-11 (AWS high-risk access):** None of the three assigns appropriate investigation priority. Llama misses the explicit `MFAUsed=No`; Mistral and Phi both call the activity routine/low risk. Phi corrupts `203.0.113.90` as `203.00113.90`, a second altered IP not caught by automated scoring.

**TC-12 (approved jump host, outside standard window):** Mistral falsely says there is *no* time restriction although `standard_window=09:00-17:00`. Phi changes log host attribution and a year. The correct conclusion is: approved source and hosts, but off-hours access requires checking an exception; compromise is not established.

**TC-13 (approved patch):** Mistral appropriately treats the change as routine. Llama recognizes it as benign but also calls an authorized in-window logon suspicious in assumptions. Phi treats signed scheduled patch activity as suspicious and alters timestamps.

## Manual score summary (subjective, no statistical accuracy claim)

| Model | Six cases reviewed | Mean manual quality / 5 | Automatic recall |
|---|---:|---:|---:|
| Llama 3.2 3B | 6 | 1.50 | 0.92 |
| Mistral 7B | 6 | 2.67 | 0.92 |
| Phi-3 Mini | 6 | 1.67 | 0.88 |

The difference between automatic recall and human-scored quality is a **major finding**: matching keywords does not guarantee safe SOC conclusions. Scores are one-reviewer judgments and need student validation; do not present them as standardized LLM accuracy.

## Evidence and integration

- `run_20261016_161056/` — Llama outputs, CSV/JSON and summaries for TC-08–13.
- `run_20261016_161459/` — Mistral outputs, CSV/JSON and summaries for TC-08–13.
- `run_20261016_162058/` — Phi-3 outputs, CSV/JSON and summaries for TC-08–13.
- Additional screenshots: `Evidence/13-Additional-Llama-Benchmark.png`, `Evidence/14-Additional-Mistral-Benchmark.png`, `Evidence/15-Additional-Phi3-Benchmark.png` (use your exact saved filenames).
- Structured per-case evaluations: `Testing/Additional-6-Manual-Review.csv`. This is a separate analyst-review artifact; original benchmark data must remain unchanged.

## Corrective actions for Week 2

1. Reject responses that invent or alter IPs, timestamps, hostnames or log fields (exact-string checks rather than permissive IPv4 regex only).
2. Flag mismatches between `SUMMARY`, `EVIDENCE`, `SUSPICIOUS ACTIVITY` and `SEVERITY`; demand human validation of all 'None identified' judgments.
3. Add minimal fixed reference semantics for `4624` success, `4625` failure, `4672` special privileges, and Sysmon `EventID=10` process access; constrain summaries to only evidenced actions.
4. Use the provided change ticket, approved asset and maintenance window, but still verify missing authorization exceptions before clearing off-hours events.
5. Distinguish *blocked attack attempt* from *successful compromise*; treat DNS tunneling as an investigation hypothesis, not proven exfiltration.
6. Respect output length; detect truncated responses, rerun with explicitly documented settings if necessary, and keep modified-settings results separate.

**Reviewer:** ____________________  **Student verified:** ____________________  **Date:** ____________________
