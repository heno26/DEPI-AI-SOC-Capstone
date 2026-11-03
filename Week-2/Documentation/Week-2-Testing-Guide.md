# Week 2 Testing Guide (Windows 11 / PowerShell)

## Updated Week-2 Test Matrix - 03 November 2026

**Overall status: IMPLEMENTED / EVIDENCE REVIEWED / FINAL ACCEPTANCE PENDING.**

This section documents the later Week-2 implementation and audit. The original testing instructions below are preserved as historical development guidance. Historical PENDING LOCAL labels must not be interpreted as evidence that the newer OpenObserve tests failed or passed.

### 1. Test status definitions

| Status | Meaning |
|---|---|
| PASS | The specified check was executed and its expected result was observed. |
| REVIEW_REQUIRED | Automated processing completed but human SOC validation remains necessary. |
| PENDING | A required test, review or acceptance step has not been completed. |
| NOT VERIFIED | Available evidence is insufficient to confirm the claimed behavior. |
| NOT APPLICABLE | The check does not apply to the demonstrated architecture. |

### 2. Implemented SIEM scenarios

| ID | Scenario | Primary AI evidence | SOC report | Artifact audit | Human approval |
|---|---|---|---|---|---|
| 001 | HTTP high-rate | Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json | DEPI_P5_SIEM05_SOC_Alert_Report_FINAL_Technical.docx | PASS | PENDING |
| 002 | SSH brute force | Evidence/SIEM-OpenObserve/SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json | Alert002_SSH_BruteForce_SOC_Report.md | PASS | PENDING |
| 003 | Malware | Evidence/SIEM-OpenObserve/SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json | Results/SIEM06_MAL_003_FINAL/SIEM06_MAL_003_Final_SOC_Report.md | PASS | PENDING |
| 004 | XSS | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json | Evidence/SIEM-OpenObserve/SIEM07_XSS_004_Final_SOC_Report.md | PASS | PENDING |
| 005 | Exchange mailbox export | Evidence/SIEM-OpenObserve/SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json | Results/SIEM_EXCHANGE_005_Final_SOC_Report.md | PASS | PENDING |

**Artifact audit PASS** means the primary JSON parsed successfully and its corresponding report was located and reviewed. It does not mean every end-to-end test or SOC decision passed.

### 3. Evidence integrity and documentation checks

| Check | Result | Status |
|---|---|---|
| Primary AI-triage JSON files | 5/5 parsed | PASS |
| SOC reports | 5/5 located and reviewed | PASS |
| Evidence README links | 36/36 valid | PASS |
| Exact duplicate evidence files | 71/71 SHA256-verified after archival | PASS |
| XSS report correction | Original archived; corrected report checked | PASS |
| Documentation backup | Four originals backed up and SHA256-verified | PASS |

### 4. Technical acceptance checks

| Test | Status | Required evidence |
|---|---|---|
| Updated SIEM05 receiver-to-report end-to-end regression | PENDING | New authenticated webhook run, verified evidence, AI output and QA report from the updated code |
| HTTP alert-to-request-group row-level correlation | NOT VERIFIED | Matching trigger and source rows with documented event identity and time relationship |
| Human SOC analyst sign-off for all five scenarios | PENDING | Recorded analyst decisions and rationale |
| Active SIEM receiver runtime/version | NOT VERIFIED | Process, port and startup verification |
| SIEM07 candidate regression | NOT VERIFIED | Reproducible execution results for the current candidate |
| Unified SOC v0.4 production acceptance | PENDING | Acceptance criteria and supported regression results |
| Genuine live Wazuh integration | NOT APPLICABLE | OpenObserve is the demonstrated SIEM |

### 5. Historical replay constraints

The OpenObserve alert scenarios use historical lab/replay evidence. Do not interpret replay timestamps as current production incidents.

For HTTP 001, the saved source group contains 112 requests against a configured threshold of 80. The exact row-level association with the saved firing alert has not been established.

AI-generated conclusions and severity assessments must be checked against source evidence. REVIEW_REQUIRED is an expected human-validation state, not proof of compromise or analyst approval.

### 6. Final acceptance decision

**Week-2 acceptance: PENDING.**

The five alert scenarios have documented AI-triage evidence and SOC reports. Final acceptance requires resolving the outstanding technical checks or recording explicit, justified acceptance of the remaining limitations.

Week-3 SOAR and Week-4 full incident response are outside this completed Week-2 documentation update.

---

Legend: **[DONE-SIM]** = already run in the build sandbox with a fake Ollama server (unit tests only; not Mistral). **[PENDING LOCAL]** = you must run it on your laptop.

## 0. One-time setup
```powershell
cd <path>\Week-2
python --version                      # Python 3.10 or newer
ollama --version
ollama list                           # must show mistral:7b-instruct-v0.3-q4_K_S (and optionally llama3.2:3b)
# if missing:  ollama pull mistral:7b-instruct-v0.3-q4_K_S
python app.py check                   # shows Ollama status and the generation settings
```
No `pip install` is needed (standard library only). Do not use a virtual environment unless you want one.

## 1. Automated tests [DONE-SIM in sandbox; re-run locally]
```powershell
python -m unittest Testing\test_week2.py -v
```
Expected: `OK` (49 tests in the build sandbox). These use a **simulated** Ollama server. Save the output to `Testing\test_results\unit_test_results_local.txt` (`... 2>&1 | Tee-Object ...`). **Do not present this as Mistral execution.**
```powershell
python Testing\replay_week1_outputs.py --week1 ..\Week-1 --out Testing\test_results\week1_replay_validation.md
```
Replays your real Week 1 outputs through the validator (no model is run).

## 2. Test matrix: the ten required categories
Run the commands from `Week-2`. Add `--no-review` to skip the review prompt; the result stays *Pending Review*. For each test, open `Results\<id>\report.md`, compare with the evidence, then record your findings (review) and fill the CSV/notes.
| # | Category | Command | What you should see | Status |
|---|---|---|---|---|
| 1 | Windows authentication | `python app.py analyze Data\Windows\SYNTHETIC_TC-02_windows_password_spray_admin_group.log` | 4625 treated as failures; six accounts, one source; success for svc_backup; group change flagged; no invented IPs | PENDING LOCAL |
| 2 | Linux authentication | `python app.py analyze Data\Linux\SYNTHETIC_TC-01_linux_ssh_bruteforce_then_wget.log` | Failures then success then `sudo wget`; download is **not** claimed as executed | PENDING LOCAL |
| 3 | Network security logs | `python app.py analyze Data\Network\SYNTHETIC_W2-02_network_firewall_ids.log` and `...TC-10...` | Denied scan pattern, periodic outbound allow, IDS alert; no "confirmed" breach | PENDING LOCAL |
| 4 | Wazuh-style JSON | `python app.py triage Data\Wazuh\SYNTHETIC_wazuh_alerts_array.json` (choose alert 2) | Alert ID `SYNTH-ALERT-0002`; original severity 10 shown **separately** from AI priority; labelled synthetic | PENDING LOCAL |
| 5 | Suspicious activity | `python app.py triage Data\Generic\SYNTHETIC_TC-03_siem_alert_office_encoded_powershell.log` | Likely True Positive / high priority expected by Week 1 ground truth (analyst decides) | PENDING LOCAL |
| 6 | Benign administrative | `python app.py analyze Data\Linux\SYNTHETIC_TC-07_linux_benign_admin.log` and `python app.py triage Data\Generic\SYNTHETIC_TC-04_siem_alert_authorized_scan.log` | Benign conclusion allowed; authorized scan not escalated blindly | PENDING LOCAL |
| 7 | Missing / incomplete data | `python app.py triage Data\Wazuh\SYNTHETIC_wazuh_alert_single.json` after removing a field in a **copy** (e.g. `agent`) | No crash; "Not provided" shown; missing items listed | PENDING LOCAL |
| 8 | Unsupported IOC generation | any run: check "Automated validation" list; also `python -m unittest` tests `ValidatorTests` | Invented/altered IP, date, hash flagged with the exact value and section | DONE-SIM (validator) / PENDING LOCAL (real model) |
| 9 | Invalid input files | `python app.py analyze Testing\test_cases\empty.log` ; `...invalid.json` ; `...binary.bin` ; `...only_comments.log` | `[INPUT ERROR] ...` message each time; no model call | DONE-SIM / re-run locally |
| 10 | Ollama connection failure | Quit Ollama (tray icon > Quit), then `python app.py analyze Data\Linux\SYNTHETIC_TC-07_linux_benign_admin.log` | `Cannot reach Ollama ...` message; nothing saved. Restart Ollama afterwards | DONE (real, in sandbox with no Ollama) / re-run locally |
Also try (not an official category): `python app.py analyze Testing\test_cases\SYNTHETIC_injection_attempt.log` - the injected sentence must not change the analysis, and a `prompt_injection_in_input` flag should appear.

## 3. Batch run of all fixtures with Mistral [PENDING LOCAL]
```powershell
python Testing\run_local_model_tests.py                      # primary model, all fixtures (takes a while)
python Testing\run_local_model_tests.py --only TC-02 TC-12   # subset
python Testing\run_local_model_tests.py --model llama3.2:3b  # explicit backup run (separate, recorded)
```
It writes `Testing\test_results\local_llm_run_<time>.csv`. Fill `manual_quality_1to5` and `manual_notes` yourself. The automatic columns (flags, truncation, speed) are **not accuracy**.

## 4. Mistral reliability and generation settings [PENDING LOCAL]
The settings `temperature=0.2`, `repeat_penalty=1.15` are initial candidates, **not proven**.
1. Run each of TC-06-style and TC-12 fixtures 3 times; record how often "token repeat limit" or a retry occurs (`retry_used` column / report "Retry used").
2. Check GPU use while it runs: `ollama ps` (look at the PROCESSOR column, e.g. `100% GPU` or `x% GPU`). Week 1 saw Mistral partially offloaded (about 89% GPU at 4096 context).
3. If it is much slower or offload drops with the default `num_ctx=6144`, retry with `--num-ctx 4096`; if outputs are cut, check `truncated=True` and raise `--num-predict`.
4. Record your final choice and numbers in `Week-2-Final-Report.md` section 6.

## 5. Full workflow test with human review [PENDING LOCAL]
```powershell
python app.py                     # menu: 2 (triage) -> pick the Wazuh array file -> alert 2 -> y (review now)
```
In the review: disposition for each flag (`h` hallucination / `f` false alarm / `n` follow-up), choose a status, name, final classification/priority, notes. Then check `Results\<id>\report.md`, `analysis.json`, and `Validation\validation_log.csv`. Finally `python app.py export`.

## 6. Offline demonstration test [PENDING LOCAL]
Disconnect Wi-Fi / unplug network, make sure Ollama is running, and repeat step 5. It must work. (Screenshot 13.)

## 7. Detection notes [PENDING LOCAL]
```powershell
python app.py detect Data\Windows\SYNTHETIC_TC-02_windows_password_spray_admin_group.log
python app.py export
```

## 8. Week 1 acceptance gates to judge Week 2 output (manual)
From the Week 1 ground truth and reviews. These are *your* checks, not automatic scores.
| Fixture | A good answer must |
|---|---|
| TC-02 | Treat 4625 as failed; one source, many accounts; note later success for svc_backup and the group change; not invent IPs |
| TC-01 | Report failures, success, `sudo wget`; state download is not proof of execution |
| TC-04 | Recognise the registered scanner/maintenance window; not escalate blindly; list what to confirm |
| TC-08, TC-09, TC-10 | Not say "None identified"; treat blocked attempts as stopped, not compromise |
| TC-11 | Not rate as routine; call out no-MFA + privilege + key creation and missing change ticket |
| TC-12 | Say approved source/hosts but outside the policy window with no exception recorded; not claim "no time restriction" |
| TC-13 | Allow a benign / approved-maintenance conclusion while noting what to verify |

## 9. Genuine Wazuh alert test [PENDING - not started]
Only after you complete `Wazuh-Cloud-Guide.md`. Until then, nothing may be described as tested with genuine Wazuh alerts.
