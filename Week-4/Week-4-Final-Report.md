# Week 4 Final Report — Full Capstone IR Simulation & Reporting

**Project:** Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone
**DEPI:** Cyber Security Incident Response Analyst
**Report status:** IMPLEMENTED / RUN / DOCUMENTED — ACCEPTANCE PENDING HUMAN SIGN-OFF
**Date:** 24 November 2026

---

## 1. Summary

Week 4 closes the capstone. It takes everything produced in Weeks 1–3 and runs it as **one
incident**, from detection to post-incident review, following the NIST SP 800-61 / SANS
incident-response lifecycle.

- **Scenario:** `W4-TT-01`, a *composite tabletop* intrusion in 9 stages across network, web,
  authentication, endpoint and email. Every stage is backed by evidence that already exists in
  the repository: Week-2 datasets, OpenObserve alert evidence and human reviews, plus Week-3
  tickets. Four benign cases are kept as false-positive controls.
- **Pipeline:** Python, standard library only, run with one command (`Week-4/IR/ir_cli.py`):
  correlate → NIST lifecycle → read-only checks → decision suggestions → local-AI drafts →
  validation → human review → 7 reports + an offline SOC dashboard.
- **AI assists, humans decide.** Local Mistral 7B (Ollama, loopback only) drafted 12 report
  sections. The Week-2 validator checked each one, and an analyst reviewed each one and
  recorded Approved or Corrected. No containment, eradication or recovery action is executed by
  code: every proposal has a recorded analyst decision, and Week-3 Tier-2 actions stay
  prohibited.
- **Nothing invented.** Every value in the outputs is read from a repository file by code. The
  test suite checks that every timestamp and every IP appears verbatim in the file it cites, and
  that every evidence file's SHA-256 re-verifies.

## 2. What the brief asked and where it is

> **Week 4: Full Capstone IR Simulation & Reporting.** Run full-scope simulation spanning
> network, endpoint, and web attack stages. Apply NIST/SANS IR lifecycle: detection, triage,
> containment, eradication, recovery, post-incident. Use AI for drafting; human-validate.

| Brief requirement | Week-4 artifact | Status |
|---|---|---|
| Full-scope simulation: network, endpoint, web | `Config/scenario.json` (9 stages, 15 attack cases + 4 benign controls), `IR/correlate.py` | Run |
| NIST/SANS lifecycle: detection, triage, containment, eradication, recovery, post-incident | `IR/ir_lifecycle.py` → `Output/ir_lifecycle.json`; status computed from data and decisions | Run |
| Use AI for drafting | `IR/ai_report_drafter.py` + `Prompts/` (IR report reuses the Week-1 Incident-Report prompt) | 12/12 drafts generated locally |
| Human-validate | `ir_cli.py review` / `decide` → append-only logs in `Simulation/` | Recorded |
| Final Capstone IR Report | `Reports/01_Final_Capstone_IR_Report.md` | Generated |
| Incident timeline | `Reports/02_Incident_Timeline.md` + `Output/incident_timeline.csv` | Generated |
| Forensic evidence summary | `Reports/03_Forensic_Evidence_Summary.md` (SHA-256 per evidence file) | Generated |
| Containment / recovery plan | `Reports/04_Containment_Recovery_Plan.md` | Generated |
| Executive briefing | `Reports/05_Executive_Briefing.md` | Generated |
| Lessons-learned | `Reports/06_Lessons_Learned.md` | Generated |
| AI-assisted reporting workflow | `Reports/07_AI_Assisted_Reporting_Workflow.md` + §6 below | Generated |
| SOC dashboard (team addition) | `Dashboard/index.html` — see `Documentation/Dashboard-Guide.md` | Generated |

## 3. Why a *composite tabletop*

The Week-2 data comes from separate public datasets recorded in different years (2019–2026), so
there is no single real attack that runs from the first stage to the last. Instead of inventing
one, Week 4 orders the real cases along the kill chain and runs the response as a tabletop
exercise:

| Stage | Name | Domain | Cases |
|---|---|---|---|
| S1 | Reconnaissance | network | NT-01 (port scan) |
| S2 | Web-tier attack | web | SIEM-WEB-001 (high-rate HTTP), SIEM-WEB-004 (XSS) |
| S3 | Credential attack | auth | SIEM-AUTH-002, LT-01 (SSH brute force) |
| S4 | Execution | endpoint | SIEM-MAL-003 (suspicious executable), LT-03 (bash reverse shell) |
| S5 | Persistence & privilege-sensitive activity | endpoint | RT-04 (Winlogon Shell), LT-02 (sudo) |
| S6 | Discovery & defense evasion | endpoint | RT-02 (Security log cleared) |
| S7 | Lateral movement | endpoint | RT-03 (WinRM on DC) |
| S8 | Command & control | network | NT-03 (periodic HTTP), NT-02 (DNS chunk burst), RT-01 (plink tunnel) |
| S9 | Collection / exfiltration (hypothesis) | email | SIEM-EXCH-005 (mailbox export to .aspx) |
| FP | Benign controls | — | BT-01, BT-02, BT-03, LT-04 |

**Boundary (repeated in every report and in the dashboard):** the links between stages are a
scenario construct, not observed causality. Timestamps are the original dataset times and are
never shifted. Nothing is live, and nothing is executed.

## 4. Architecture

```
Week-1 benchmark ─┐
Week-2 evidence, ─┼─► correlate.py ──► Output/incident.json, incident_timeline.csv, observables.csv
datasets, reviews │      (cases, timeline, observables, cross-dataset overlaps, ATT&CK)
Week-3 tickets ───┘
                         │
                         ▼
                   ir_lifecycle.py ─► Output/ir_lifecycle.json   (NIST phases, proposals, decisions)
                     ├─ t0_checks.py  ─► Output/t0_checks.json   (read-only checks on repo data)
                     └─ suggest.py                               (rule-based decision suggestions)
                         │
                         ▼
                ai_report_drafter.py ─► Output/ai_drafts/*.json  (local Mistral + Week-2 validator)
                         │
             human: ir_cli.py decide / accept-suggestions / review  ─► Simulation/*.jsonl
                         │
                         ▼
          build_reports.py ─► Reports/01..07     build_dashboard.py ─► Dashboard/dashboard_data.js
```

Week-2 code is **reused, not copied**: `Core/validator.py` extracts IOCs and validates drafts,
`Core/ollama_client.py` talks to the local model, and `Core/analysis.py` parses sections.
Weeks 1–3 are read-only, and a test proves that no Week 1–3 file changes during a run.

## 5. Incident-response lifecycle (how each phase is computed)

| Phase | What the code does | Result in this run |
|---|---|---|
| Preparation | Checks that the Week-1 lab guide, prompts and privacy checklist and the Week-3 playbooks and decision matrix exist | Complete (8/8 artifacts) |
| Detection | 5 OpenObserve alert rules with saved evidence + 10 dataset attack cases + 4 benign controls | Complete |
| Triage & analysis | Reads the Week-2 AI triage and human-review records per case | AI complete for 19/19; human review recorded for the 14 dataset cases; the SIEM alerts stay *Pending Review* from Weeks 2–3 |
| Containment / Eradication / Recovery | Builds proposals from Week-3 tickets + `Config/response_catalog.json` (values filled from evidence). A phase is complete only when every item has a recorded decision | 45 decidable items, all decided; 17 Tier-2 actions listed as prohibited |
| Post-incident | Local-AI drafts + recorded human review | 12 drafts generated and reviewed |

**Tiers** (same as the Week-3 decision matrix): **T0** = read-only check, **T1** = proposal that
needs a recorded analyst decision and is executed out-of-band by a human, **T2** = automation
prohibited by design (the CLI refuses to record a decision on it).

### 5.1 Read-only checks (T0) answered from repository data

`IR/t0_checks.py` answered 8 of the 16 T0 checks from data already in the repository. The other
8 need systems or records that the lab data does not contain (change records, endpoint
telemetry, the Exchange server itself), and each states the reason.

| Case | Check | Result (source) |
|---|---|---|
| SIEM-AUTH-002, LT-01 | Any successful SSH login from the brute-force source? | **No.** 0 `Accepted` logins from 183.62.140.253 in 2,000 lines (`OpenSSH_2k.log`) |
| NT-01 | Which probed ports are open? | Handshake completed on **11 ports**: 22, 135, 139, 445, 5040, 49664–49669 (Zeek `conn_state`) |
| SIEM-EXCH-005 | Status of the export requests | The cmdlet audit log shows the same sequence **twice**: *Mailbox Import Export* role assigned → export to `.aspx` → export request removed ~5 min later → `Search-Mailbox -DeleteContent` (`msexchangemanagement.log`). File creation on disk is not shown. |
| LT-03 | Did the reverse shell connect? | Cannot be established: the Sysmon file has no network-connection event |
| NT-02 | Do the DNS chunk labels carry readable data? | No: 3,000 decoded bytes, 38% printable, so the content is undetermined |
| RT-02 | Which session cleared the Security log? | Account Administrator; no LogonId in the record |
| RT-03 | Who ran the WinRM command? | `insecurebank\Administrator` (LogonId 0x12fe05); remote client not in the dataset |

The Exchange sequence was in the Week-2 data folder but was not used by the Week-2 alert. Week 4
adds it to the timeline and maps it to ATT&CK `T1098` (account manipulation) and `T1070.008`
(clear mailbox data).

### 5.2 Decisions

`IR/suggest.py` turns the evidence into a suggested decision for each item, using fixed rules
written at the top of the file:
- A T0 check answered from data → `done`. A T0 check that cannot be answered → `deferred`.
- A conditional proposal ("If …", "Only after …") → `deferred`.
- A disruptive action (block, isolate, remove …) → `approved` only when the case has an
  ATT&CK technique labelled *observed_pattern*; otherwise `deferred`.
- A low-impact review or hardening step → `approved`.

The analyst of record accepted the suggestions (`ir_cli.py accept-suggestions`): **45 decisions
— 19 approved, 18 deferred, 8 done.** Each one is logged with the analyst's name and
`via: accepted_rule_suggestion` in `Simulation/analyst_decisions.jsonl`. Any item can be
overridden through `Simulation/decisions_to_fill.csv` + `ir_cli.py import-decisions`, and the
import is all-or-nothing.

## 6. AI-assisted reporting workflow

1. `ai_report_drafter.py` builds a numbered **fact sheet** (`[E001]…`) per draft from
   `incident.json` and `ir_lifecycle.json`. Facts that are only hypotheses are labelled
   `NOT ESTABLISHED`.
2. The fact sheet fills a prompt. The IR report reuses `Week-1/SOC-Prompts/Incident-Report.txt`;
   the other prompts are in `Week-4/Prompts/`.
3. The prompt goes to **local** Ollama (`mistral:7b-instruct-v0.3-q4_K_S`, the Week-2 model)
   through the Week-2 client.
4. The output is validated by the Week-2 validator: unsupported IPs, hashes, timestamps,
   references, missing sections, truncation.
5. The draft is saved with its model, options, prompt hash, timing and flags, with status
   *Pending Review*.
6. An analyst records **Approved** or **Corrected** (`ir_cli.py review`). Corrected text lives
   in `<id>.corrected.md`; the original AI text stays in the JSON for audit.

### 6.1 Run record (analyst laptop, 24 Nov 2026)

| Item | Value |
|---|---|
| Drafts | 12 (incident report, executive briefing, lessons learned, 9 stage summaries) |
| Speed | ≈ 2 tokens/s; the model ran without GPU acceleration on this laptop (Week-1 GPU benchmark: 23.1 tokens/s) |
| Time per draft | 144–395 s for 8 of the 9 stage summaries and 243 s for the executive briefing; stage S9 was an outlier at 2,557 s (0.16 tokens/s); 689 s incident report; 462 s lessons learned |
| First attempt | 10/12 succeeded; the 2 longest drafts hit the Week-2 420 s request timeout and succeeded on re-run with a 1,800 s limit |
| Validator flags, first pass | 40 in total, of which 38 were `missing_section` false positives |
| Validator flags after re-validation | 2: one real (`T1098.Account` typo in stage S9) and one heuristic false positive (`llama3` read as a hostname) |
| Human review | 5 Approved (executive briefing, S1, S2, S6, S8); 7 Corrected (S3, S4, S5, S7, S9, incident report, lessons learned) |

### 6.2 What the run taught us about AI drafting

- **Parser false positives.** Mistral writes `1. STAGE SUMMARY: text` on one line, and the
  Week-2 parser expects the heading on its own line. Week 4 splits such lines before parsing
  (`normalize_headings`) and keeps the first validation as `validation_original`. That took the
  flags from 40 to 2.
- **The validator catches invented values, not wrong meaning.** 7 of 12 drafts had 0–1 flags
  but still needed meaning corrections, for example:
  - stating "unauthorized" as fact when the input marked it as a hypothesis;
  - writing that the Exchange role was assigned *after* each export when it was assigned
    *before*;
  - listing "did any SSH login succeed?" as open although the read-only check answered it;
  - calling a cross-dataset overlap something that "did not work".

  Human review is not optional.
- **CPU-only inference is slow but workable** for 12 drafts. Long prompts need a longer
  request timeout than the Week-2 default.

## 7. Dashboard

`Dashboard/index.html` is a single offline page with no server, no CDN and no network. It
reads `Dashboard/dashboard_data.js`, which `build_dashboard.py` regenerates on every
`ir_cli.py build`. Hovering any KPI shows the repository file it came from, and all data is
HTML-escaped (the XSS evidence contains `<script>` payloads). Each view is explained in
`Documentation/Dashboard-Guide.md`.

## 8. Tests

`python -B Week-4/IR/tests/run_all.py` → **18/18 passed** on a clean clone of the repository
(re-run it on the submitting machine before sign-off; the analyst laptop passed 17/17 before the
last test was added). The tests cover:
- read-only guarantee for Weeks 1–3;
- SHA-256 re-verification of every evidence file;
- every timestamp and IP verbatim in its source;
- observables traceable to their cases;
- the known cross-dataset overlap;
- no unresolved placeholders and nothing executed;
- T2 decisions refused;
- all-or-nothing CSV import;
- suggestion rules and logged acceptance;
- T0 checks reading real data;
- a simulated model response with an invented IP being flagged;
- inline-heading normalisation;
- dashboard data completeness and offline/escaping guards.

The simulated-model test checks the validator path only. It is not a test of Mistral quality.

## 9. What this package does NOT do

- It is not a live incident and not production monitoring; all data are historical lab datasets.
- The links between stages are not observed causality.
- ATT&CK mappings marked *candidate* or *hypothesis* are not confirmed techniques
  (21 mappings: 11 observed pattern, 9 candidate, 1 hypothesis).
- No action is executed. Approved means "the analyst would do this", recorded for the tabletop.
- Indicator reputation is never checked (no live threat-intelligence feed).
- Validator flags are review requests, not proof of hallucination, and zero flags is not proof
  of correctness (§6.2).

## 10. Open limitations and acceptance gates

1. Final human sign-off on the Week-4 reports (sign-off table at the end of each report).
2. The Week-2 gates remain open (human approval of the five alert scenarios, HTTP row-level
   correlation, SIEM05 end-to-end regression, replay scope, v0.4 QA candidate, no automatic
   remediation).
3. The Week-3 gates remain open (sign-off on the 7 tickets, PB-03/PB-04 limits, no live
   TheHive/TI, Exchange `event_id` instability, weaker XSS self-checks).
4. 8 of 16 T0 checks cannot be answered without systems that are not in the lab data.
5. Week-4 drafts were generated on a CPU-only laptop. Timings are not comparable with the
   Week-1 GPU benchmark.

## 11. Files delivered

| Path | Purpose |
|---|---|
| `README.md` | Quick start, commands, folder map |
| `README_AR.md` | Arabic guide for a first-time reader |
| `Week-4-Final-Report.md` | This report |
| `Documentation/Dashboard-Guide.md` | What each dashboard view shows and where its data comes from |
| `Config/scenario.json`, `attack_mapping.json`, `response_catalog.json` | Scenario, ATT&CK mapping, response proposals (team-reviewable) |
| `Prompts/*.txt` | Week-4 local-AI prompts |
| `IR/*.py`, `IR/tests/run_all.py` | Pipeline, CLI, tests |
| `Output/` | `incident.json`, `incident_timeline.csv`, `observables.csv`, `ir_lifecycle.json`, `t0_checks.json`, `ai_drafts/` |
| `Simulation/` | `analyst_decisions.jsonl`, `ai_draft_reviews.jsonl`, `decisions_to_fill.csv` |
| `Reports/01..07` | The seven brief deliverables |
| `Dashboard/` | `index.html` + generated `dashboard_data.js` |
