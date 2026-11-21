# DEPI Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone

**Track:** Cyber Security Incident Response Analyst
**Program:** Digital Egypt Pioneers Initiative (DEPI)
**Duration:** Four weeks
**Status:** Weeks 1–3 implemented and documented. Week 4 (full IR simulation) not yet started.

---

## TL;DR
A four-week capstone building a human-in-the-loop AI SOC pipeline. Weeks 1–3 implemented (local AI benchmark, SIEM alert triage via OpenObserve + Mistral, four SOAR playbooks). Week 4 pending. AI assists; humans decide. Every deliverable states what it proves and what it doesn't.


## 1. What this project is

A local-only, human-in-the-loop SOC automation pipeline built on a single laptop with a
6 GB GPU. No cloud services, no external APIs, no paid tooling. Every AI call goes to a
local Ollama instance; every containment action requires recorded analyst approval.

The project is built in four weekly stages:

| Week | Focus | Primary deliverables |
|---|---|---|
| **1** | Local AI setup & SOC prompt engineering | Ollama setup guide, model benchmark (Llama 3.2 / Mistral 7B / Phi-3 Mini), four reusable SOC prompts, privacy/ethics checklist, accuracy review |
| **2** | AI for log analysis, triage & detection | Five OpenObserve SIEM alert scenarios, AI-assisted SOC reports, hallucination/validation log, detection improvement notes, file-based log analysis tool |
| **3** | SOAR playbooks & automation | Four SOAR playbooks, dispatcher, decision matrix, manual-vs-automated table, integration diagrams, test results |
| **4** | Full capstone IR simulation & reporting | *(Not yet implemented)* Final IR report, incident timeline, forensic evidence summary, containment/recovery plan, executive briefing, lessons-learned, AI-assisted reporting workflow |

The unifying theme across all four weeks: **AI assists, humans decide.** The project's
recurring contribution is a rigorous honesty discipline — every deliverable states what it
proves and what it does not, and every PENDING or NOT VERIFIED item is labelled as such.

---

## 2. Repository structure

```
DEPI-AI-SOC-Capstone/
├── README.md                     ← this file
├── Week-1/                       ← Local AI setup & prompt engineering
│   ├── Week-1-Final-Report.md
│   ├── Setup/Ollama-Setup-Guide.md
│   ├── Benchmarks/               ← benchmark script + results
│   ├── SOC-Prompts/              ← four reusable prompts
│   ├── Privacy/Privacy-Ethics-Checklist.md
│   ├── Testing/                  ← accuracy review, test cases
│   └── Evidence/                 ← setup, benchmark, GPU, offline screenshots
├── Week-2/                       ← Log analysis, triage & detection
│   ├── Week-2-Final-Report.md
│   ├── README.md                 ← week-2 implementation overview
│   ├── Core/                     ← parsers, analysis, validator, AI client
│   ├── Data/                     ← Windows/Linux/Network/SIEM datasets
│   ├── Prompts/                  ← week-2 prompts and change notes
│   ├── Integrations/SIEM-OpenObserve/  ← five alert receivers
│   ├── Evidence/SIEM-OpenObserve/      ← per-alert AI-triage JSON + reports
│   ├── Documentation/            ← workflow, testing guide, Wazuh guide
│   ├── Detection/                ← detection improvement notes
│   ├── Validation/               ← hallucination validation log
│   └── Results/                  ← analysis runs and reports
└── Week-3/                       ← SOAR playbooks & automation
    ├── Week-3-Final-Report.md
    ├── README.md
    ├── SOAR/                     ← dispatcher, playbooks, tickets, tests
    ├── Documentation/            ← testing guide, workflow, runbook, change log
    └── Evidence/                 ← ticket/audit index + screenshots
```

Each week's folder contains a `Week-N-Final-Report.md` and a `README.md` for navigation.

---

## 3. What's been demonstrated (Weeks 1–3)

### Week 1 — Local AI setup

- **Ollama 0.40.4** installed locally; three models tested on an NVIDIA RTX 3050 (6 GB):
  `llama3.2:3b`, `mistral:7b-instruct-v0.3-q4_K_S`, `phi3:mini`.
- **Baseline benchmark:** 7 synthetic SOC test cases × 3 models, then expanded to 13 cases.
- **Manual accuracy review:** all three models produce wrong SOC conclusions at meaningful
  rates. Nobody is suitable for autonomous triage.
- **Model selection for Week 2:** Mistral 7B as primary by qualitative review (slower than
  Llama 3.2 but better on the true-positive and incident-report cases).

**Key finding:** keyword-based auto-recall scores look better than the actual model accuracy.
The project reports manual review as the real measure.

### Week 2 — AI-assisted triage

- **Five OpenObserve SIEM alert scenarios** implemented end-to-end:
  HTTP high-rate (001), SSH brute force (002), malware behavior (003), XSS (004), Exchange
  mailbox export (005).
- **Authenticated webhook receivers** (Python, localhost) verify evidence against the source
  logs before invoking local Mistral, then save a structured AI-triage JSON and a SOC
  report.
- **Deterministic validation** (`Core/validator.py`) flags unsupported IPs, timestamps, IOCs,
  event-ID misreads, and unsupported conclusions.
- **Human review** is mandatory: every alert retains `REVIEW_REQUIRED` or
  `SCHEMA_PASS_HUMAN_REVIEW_REQUIRED`.

**Key finding:** the validator catches real corruption (Phi-3 invented an IP and two
timestamps; Mistral misread a failed logon as success), but not every semantic error. The
human analyst remains the final gate.

### Week 3 — SOAR automation

- **Four SOAR playbooks** on top of Week-2 evidence:
  - **PB-01** SSH brute force → propose rate-limit
  - **PB-02** Malware → propose host isolation + hash blocklist
  - **PB-03** Web/XSS → propose WAF rule review
  - **PB-04** Exchange mailbox export → **Tier 0 only** (ticket + audit)
- **File-based dispatcher** reads saved Week-2 evidence JSON. No live SIEM, no model
  re-execution, no executed remediation.
- **Three-tier automation gate** enforced in code: Tier 0 (auto), Tier 1 (propose,
  analyst-gated), Tier 2 (prohibited, hard-blocked).
- **Seven real Week-2 alerts** dispatched into seven tickets and seven audit logs.

**Key finding:** the constitutional rule is that AI confidence never authorises action. No
playbook executes remediation; every containment is a *proposal* requiring recorded analyst
approval.

---

## 4. Design principles

1. **Local-only.** No cloud calls. Ollama runs on `127.0.0.1:11434`. The client refuses
   non-loopback addresses.
2. **Evidence-grounded.** Every AI claim is checked against the source log lines. Every
   ticket retains a link to its Week-2 evidence JSON.
3. **Human-in-the-loop.** The AI produces drafts. Humans decide. Week 3 encodes this as a
   three-tier gate; no playbook can execute containment.
4. **Honest taxonomy.** Every test, benchmark, and deliverable is labelled PASS,
   REVIEW_REQUIRED, PENDING, NOT VERIFIED, or NOT APPLICABLE. Keyword recall is never
   reported as accuracy.
5. **Reuse, don't rebuild.** Week 3 consumes Week 2 output; Week 4 will consume Week 3
   tickets and audits. Each week's artifacts are designed for the next.
6. **Preserve history.** Superseded code, drafts, and failed runs are archived, not deleted.
   Their presence is evidence of iteration.

---

## 5. How to navigate this repo

### If you want to see the AI benchmark
Start with `Week-1/Week-1-Final-Report.md` → `Benchmarks/Model-Benchmark.md` → `Testing/AI-Accuracy-Review.md`.

### If you want to see the SIEM pipeline
Start with `Week-2/Week-2-Final-Report.md` → `Documentation/Integration-Workflow.md` → `Evidence/SIEM-OpenObserve/README.md` → one of the five `SIEM*_Final_SOC_Report.md` files.

### If you want to see the SOAR layer
Start with `Week-3/Week-3-Final-Report.md` → `Week-3/SOAR/decision-matrix.md` → `Week-3/SOAR/tickets/` → `Week-3/Evidence/README.md`.

### If you want to see the honesty discipline
Read any "What this does NOT prove" section. They appear in:
- `Week-2/Validation/Hallucination-Validation-Log.md` §2, §5
- `Week-3/SOAR/decision-matrix.md` (constitutional rule)
- `Week-3/Documentation/Week-3-Testing-Guide.md` §8
- `Week-3/Evidence/README.md` §6

---

## 6. Current status

| Week | Implementation | Documentation | Acceptance |
|---|---|---|---|
| 1 | Complete | Complete | Pending student sign-off |
| 2 | Complete | Complete | PENDING (six open gates) |
| 3 | Complete | Complete | PENDING (human sign-off on all 7 tickets) |
| 4 | Not started | — | — |

### Week 2 open gates (documented in `Week-2/Week-2-Final-Report.md` §5)

1. Human SOC analyst approval of all five alert scenarios
2. HTTP alert-to-request-group row-level correlation (112-request group vs threshold 80)
3. Updated SIEM05 receiver-to-report end-to-end regression
4. Replay scope clearly identified (historical lab, not production monitoring)
5. Unified SOC v0.4 QA candidate (not production-approved)
6. No automatic remediation in Week 2 (SOAR is Week 3, full IR is Week 4)

### Week 3 open gates (documented in `Week-3/Week-3-Final-Report.md` §8)

Same six Week-2 gates remain open. Week-3 adds these specific items:

1. Human analyst sign-off on all seven Week-3 tickets
2. HTTP correlation gap limits PB-03 propose tier to WAF review
3. Exchange receiver hard-codes `REVIEW_REQUIRED` → PB-04 is Tier 0 only
4. No live TheHive, no live TI, no live SIEM, no executed remediation, no AI re-execution
5. Exchange `event_id` is replay-time-dependent; tickets not stable across replays
6. XSS receiver self-checks are weaker than AUTH/MAL; PB-03 has the strictest human gate

The stated policy across all weeks: **acceptance is pending until a human records the
decision.** The project never claims more than it can prove.

---

## 7. What this project is NOT

To prevent misinterpretation, this project is **not**:

- **A production SOC tool.** Everything is a lab/demo built on historical replay data, not
  live monitoring.
- **An autonomous AI analyst.** Every AI output requires human review. No action is
  auto-executed.
- **A live Wazuh integration.** Wazuh is legacy/synthetic file-based context. OpenObserve is
  the demonstrated SIEM.
- **A live TheHive deployment.** The TheHive adapter is a documented stub, not implemented.
- **A cloud-dependent system.** No internet connection is required after the initial model
  pull.
- **A completed capstone.** Week 4 (full IR simulation) is not yet started.

These boundaries are stated up front so a reader can calibrate what to expect before
opening any folder.

---

## 8. Technical environment

- **OS:** Windows 11
- **Hardware:** Intel Core i7, 16 GB RAM, NVIDIA RTX 3050 (6 GB VRAM)
- **Python:** 3.14 (Week-2 environment), 3.9+ for Week-3 scripts
- **Ollama:** 0.40.4
- **Models:** `llama3.2:3b`, `mistral:7b-instruct-v0.3-q4_K_S`, `phi3:mini`
- **SIEM:** OpenObserve (OSS, local Docker)
- **External dependencies:** standard library only for Week-1 and Week-2 code; `pyyaml` for
  Week-3 dispatcher
- **Network:** local loopback only; no external calls at any stage

---

## 9. Reproducing the pipeline

Each week's README has the exact commands. In summary:

**Week 1** — install Ollama, pull three models, run `Benchmarks/benchmark.py` on the 13 test
cases, review outputs manually.

**Week 2** — start OpenObserve, run one of the SIEM receivers (`SIEM06_Multi_Alert_Receiver.py`
or `SIEM07_XSS_Receiver_Candidate.py`) on `127.0.0.1:8765`, or the Exchange receiver on
`127.0.0.1:8766`; configure an OpenObserve alert to deliver to the receiver; the receiver
verifies evidence against OpenObserve, invokes local Ollama, and writes AI-triage JSON.

**Week 3** — run the SOAR dispatcher against the saved Week-2 evidence:
```powershell
python -B Week-3/SOAR/dispatcher.py --evidence Week-2/Evidence/SIEM-OpenObserve --playbooks Week-3/SOAR/playbooks --out Week-3/SOAR
```
Produces seven tickets and seven audit logs. Run the test suite:
```powershell
python -B Week-3/SOAR/tests/run_all.py
```
Expect `SUMMARY: 10/10 passed`.

**Week 4** — not yet implemented.

---

## 10. Deliverable map (aligned to the DEPI brief)

| Brief requirement | Where |
|---|---|
| AI lab setup guide | `Week-1/Setup/Ollama-Setup-Guide.md` |
| Local model benchmark | `Week-1/Benchmarks/Model-Benchmark.md` + results |
| SOC prompt library | `Week-1/SOC-Prompts/*.txt` |
| Privacy/ethics checklist | `Week-1/Privacy/Privacy-Ethics-Checklist.md` |
| AI accuracy review | `Week-1/Testing/AI-Accuracy-Review.md` |
| AI-assisted log analysis | `Week-2/Core/` + `Week-2/Results/AN-*` |
| Alert triage summaries | `Week-2/Evidence/SIEM-OpenObserve/` + SOC reports |
| Detection improvement notes | `Week-2/Detection/Detection-Improvement-Notes.md` |
| Hallucination/validation log | `Week-2/Validation/Hallucination-Validation-Log.md` |
| SOAR playbooks | `Week-3/SOAR/playbooks/` |
| Automation decision matrix | `Week-3/SOAR/decision-matrix.md` |
| Manual vs automated steps | `Week-3/SOAR/manual-vs-automated.md` |
| Integration diagram | `Week-3/SOAR/diagrams/` |
| SOAR test results | `Week-3/SOAR/test-results.md` + `Week-3/Evidence/Screenshots/` |
| Final Capstone IR Report | *(Week 4, not yet started)* |
| Incident timeline | *(Week 4)* |
| Forensic evidence summary | *(Week 4)* |
| Containment/recovery plan | *(Week 4)* |
| Executive briefing | *(Week 4)* |
| Lessons-learned | *(Week 4)* |
| AI-assisted reporting workflow | *(Week 4)* |

---

## 11. Contributing / acknowledgements

This is a course capstone project. It is not accepting external contributions. The
project's methodology, honesty taxonomy, and evidence-first approach were developed across
Weeks 1–3 and will carry through Week 4.

**Author:** Mohammed-Walid - Youssef Sherif
**Program:** DEPI — Cyber Security Incident Response Analyst
**Institution:** Digital Egypt Pioneers Initiative

---

## 12. License

Course project — not for production use. No license granted for commercial deployment.
