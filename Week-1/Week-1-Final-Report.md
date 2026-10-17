# Week 1 Final Report — Reviewed Draft

**Project:** Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone
**DEPI:** Cyber Security Incident Response Analyst
**Date of benchmark:** 16 October 2026
**Status:** Supplemental benchmark and review added; confirm evidence attachments and student sign-off before submission.

## 1. Objective
Set up a free local AI environment for SOC tasks, create four repeatable prompts, test the execution and privacy controls, benchmark three models and evaluate hallucination/accuracy before selecting a local model for Week 2.

## 2. Deliverables and progress

| Deliverable | Artifact | Status |
|---|---|---|
| AI lab setup | `Setup/Ollama-Setup-Guide.md` | Guide ready; user demonstrated local Ollama operation |
| SOC prompt library | `SOC-Prompts/*.txt` | 4 reusable prompts created |
| Local model benchmark | `Benchmarks/Model-Benchmark.md` + results | **Executed**: 19/21 original requests; 2 diagnostic retries completed; **18/18 additional requests completed** |
| AI accuracy review | `Testing/AI-Accuracy-Review.md` | **Reviewed**: 39 available outputs (19 baseline, 2 retries, 18 additional); student review/sign-off still needed |
| Privacy/ethics checklist | `Privacy/Privacy-Ethics-Checklist.md` | Partially verified; evidence attachments/sign-off pending |
| Final report | This document | Reviewed draft; sign-off pending |

## 3. Technical environment

- Windows 11, Intel Core i7, 16 GB RAM, NVIDIA RTX 3050 6 GB.
- Ollama 0.40.4 and Python 3.14.6 were shown in the user’s PowerShell screenshot.
- Installed models tested: `llama3.2:3b`, `mistral:7b-instruct-v0.3-q4_K_S`, and `phi3:mini`.
- Ollama API: local loopback `127.0.0.1:11434` (earlier screenshot).

## 4. Results of baseline run

| Model | Completed / 7 | Mean response (s) | Tokens/s | Auto keyword recall | GPU offload |
|---|---:|---:|---:|---:|---:|
| Llama 3.2 (3B) | 7 | 12.57 | 48.99 | 0.69 | 100% |
| Mistral 7B Instruct | 6 | 31.71 | 23.10 | 0.75 | 89% |
| Phi-3 Mini | 6 | 22.10 | 42.32 | 0.73 | 100% |

Automatic recall is keyword detection **not a true accuracy estimate**. The two failed baseline calls aborted with `prediction aborted, token repeat limit reached`. Re-running just those cases with `temperature=0.2` and `repeat_penalty=1.15` completed, but **does not change baseline test counts**.

## 5. Human review and major findings

Manual average scores (quality 1–5): Llama **2.00**, Mistral **2.86**, Phi-3 **2.43**. Mistral and Phi-3 values include 1 modified-parameter retry each, so they must not be interpreted as a controlled accuracy ranking.

- **Critical misses:** Llama overlooked a suspicious SSH-to-download sequence (TC-01) and failed to escalate likely malicious Word/PowerShell activity (TC-03).
- **Windows semantics:** all three models confused failed logons (`4625`) with successful events (`4624`) or missed the related admin-group change (TC-02).
- **False positives:** models overreacted to authorized Nessus scan inside a scheduled maintenance window (TC-04).
- **Hallucinations / fidelity:** Phi-3 invented a sender IP `192.008.0.34` in TC-05 and misreported an IP and CRON references in TC-07. Llama altered exact defanged IOC strings; Mistral produced excessive unsupported assumptions in its long threat summary.
- **Incident reporting:** Mistral retry preserved unknowns most clearly; Llama/Phi asserted impact and root cause as Confirmed without sufficient supporting evidence.

**Conclusion:** **No model is suitable for autonomous SOC decisions.** The outputs remain drafts requiring analyst review and validation against the original logs.

## 6. Provisional model selection for Week 2

- **Local development baseline:** Llama 3.2 (3B), for the simplest dependable setup and lowest tested response latency / GPU demand. This is an engineering convenience choice, **not** a claim of superior detection accuracy.
- **Follow-up candidate for comparison:** Mistral 7B, given stronger qualitative performance on the true-positive and incident-report examples but slower generation and repeat-abort issue.
- **Required:** fix prompt instructions and pass the acceptance gates in `Benchmarks/Model-Benchmark.md` before claiming reliable triage.

## 7. Privacy and ethics

Local Ollama scripts operate through localhost, and prior screenshots showed loopback listening and an offline-response demonstration. A refused connection to a single external IP is not alone proof the device was fully offline. Synthetic fixtures are used. Attach all saved screenshots, verify the offline network condition, and keep human approval mandatory.

## 8. Limitations

The baseline seven and supplemental six synthetic cases per model are still a small, non-representative sample; several baseline outputs were cut at the 800-token cap. Original success counts differ. Modified-parameter retries are diagnostic tests rather than a comparable repeat of the complete matrix. Manual scoring is subjective and must not be reported as benchmark accuracy.

## 9. Evidence checklist and submission readiness

- [ ] Place all 10 named screenshots, including screenshot 10 for RAM/GPU, inside `Evidence/`.
- [ ] Confirm screenshot 05 proves network adapters were actually disabled at inference time.
- [x] Preserve complete baseline and retest raw outputs and summary/result files.
- [x] Document benchmark failures and the local fix to benchmark error handling.
- [x] Add one-by-one manual quality/hallucination notes.
- [ ] Student verifies recorded findings and signs privacy and report cover pages.


## Supplementary security-log evaluation (TC-08–TC-13)

The initial 7 cases were expanded with **six additional synthetic log scenarios**: blocked SQL injection, blocked LSASS access, possible DNS tunneling, AWS privilege changes, off-hours approved-jump-host RDP, and scheduled patch maintenance. This created a 13-case dataset; the original seven-case backup was retained.

| Metric | Llama 3.2 3B | Mistral 7B | Phi-3 Mini |
|---|---:|---:|---:|
| Additional completed/attempted | 6/6 | 6/6 | 6/6 |
| Avg response time (s) | 12.11 | 32.19 | 22.56 |
| Avg tokens/second | 53.27 | 22.76 | 42.55 |
| Keyword-based recall | 0.92 | 0.92 | 0.88 |
| Unsupported indicators (automated flag) | 0 | 0 | 1 |
| **Manual quality mean /5 (subjective)** | **1.50** | **2.67** | **1.67** |

**Key security observation:** raw outputs are significantly less reliable than the keyword recall implies. Llama marks a blocked SQLi probe and an EDR-blocked LSASS access as `None identified`; Mistral mistakenly treats high-risk AWS key/admin changes as routine and denies the documented RDP time window; Phi corrupts IPs/timestamps and labels approved patch activity suspicious. Expanded tests reinforce the need for analyst validation, not unattended SOC deployment.

See `Testing/Additional-6-Accuracy-Review.md` and `Testing/Additional-6-Manual-Review.csv` for case-level evidence and reviewer notes. Additional results are separate folders in `Benchmarks/results/`, and screenshots 11–15 should be retained under `Evidence/` if available.

**Scoring limitation:** 13 different synthetic cases and 3 LLMs do not establish operational detection accuracy. Do not conflate keyword recall with factual reliability; also do not mix the earlier two diagnostic retries into a single same-settings success rate.

## 10. Ready for Week 2?

**Ready for a supervised Week-2 prototype after evidence is attached, but not for autonomous incident handling.** First revise prompt guardrails, validate Windows log semantics and false-positive triage, and document human analyst approval before any action.

Student: ___Mohammed-Walid____      Date: ____15/10/2026_____
