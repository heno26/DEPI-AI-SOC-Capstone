# Week 3 Final Report — SOAR Playbooks & Automation

**Project:** Project 5 — AI-Assisted SOC Automation & Full Incident Response Capstone
**DEPI:** Cyber Security Incident Response Analyst
**Report status:** IMPLEMENTED / DOCUMENTED — ACCEPTANCE PENDING HUMAN SIGN-OFF
**Date:** 18 November 2026

---

## 1. Summary

Week 3 adds a deterministic SOAR layer on top of the Week-2 AI-assisted triage pipeline.
It consumes the saved Week-2 evidence JSON files and drives four playbooks through three
automation tiers:

- **Tier 0 (auto):** parse, enrich (stub), create ticket, notify, audit.
- **Tier 1 (propose):** containment recommendation surfaced in the ticket; requires recorded analyst approval.
- **Tier 2 (prohibited):** hard-blocked in code (`dispatcher.PROHIBITED_ACTIONS`).

The layer does **not** re-run the AI, does **not** call a live SIEM, does **not** execute
remediation, and does **not** claim TheHive integration.

## 2. Scope and mapping to the project brief

| Brief requirement | Week-3 artifact | Status |
|---|---|---|
| SOAR playbooks | `SOAR/playbooks/PB-01..04.{yaml,md}` | ✅ complete |
| Automation decision matrix | `SOAR/decision-matrix.md` | ✅ complete |
| Manual vs automated steps | `SOAR/manual-vs-automated.md` | ✅ complete |
| Integration diagram | `SOAR/diagrams/{logical,deployment}.md` (mermaid) | ✅ complete |
| Test results | `SOAR/test-results.md` | ✅ complete (see §6) |

The brief names four scenarios: **phishing, malware, brute force, data exfiltration**.
Mapping to Week-2 evidence:

- **Phishing** → PB-04 (Exchange mailbox export targeting the admin mailbox — the closest
  Week-2 evidence gets to a credential/phishing narrative).
- **Malware** → PB-02.
- **Brute force** → PB-01.
- **Data exfiltration** → PB-04's *hypothesis* framing (explicitly unverified).

I state this mapping openly rather than overclaiming a true phishing-email case that
does not exist in the Week-2 evidence.

## 3. Architecture

See `SOAR/diagrams/deployment.md` (topology) and `SOAR/diagrams/logical.md` (flow).

Key design decisions:
1. **File-based, not socket-based.** The dispatcher reads `Evidence/SIEM-OpenObserve/*.json`.
   This avoids the Week-2 port collision (SIEM06 and SIEM07 both bind 127.0.0.1:8765)
   and matches the project's historical-replay posture.
2. **No AI re-execution.** Week-2 triage output is the input. This avoids resource cost
   and keeps the Week-3 test surface small.
3. **Correlation key = `event_id`.** Every ticket, audit line, and deduplication decision
   keys on the `event_id` computed by the Week-2 receivers. The playbook engine is
   effectively stateless.
4. **Three-tier gate enforced in code.** Tier-2 actions live in a module-level constant
   and are checked before ticket creation.

## 4. Playbooks and decision matrix

Four playbooks, one decision matrix. See `SOAR/decision-matrix.md` for the full
18-row table with evidence citations.

**The constitutional rule (matrix row 18):** AI confidence never authorises execution.
No action whose blast radius is non-zero runs without a recorded analyst decision.

**PB-04 exception:** The Exchange receiver (`SIEM_EXCHANGE_005_AI_Receiver.py`)
hard-codes `qa_status: "REVIEW_REQUIRED"`. PB-04 is therefore capped at Tier 0 in
`dispatcher.run_playbook()`.

## 5. Manual vs automated

See `SOAR/manual-vs-automated.md` for the per-playbook step table.

Summary: automation is confined to reversible, low-blast-radius steps (parse, extract
IOCs, create ticket, notify, audit). Containment proposals are Tier 1 (analyst decision).
Execution is Tier 2 (out-of-band, out of scope).

## 6. Test results

Run: `python -B Week-3/SOAR/tests/run_all.py`

See `SOAR/test-results.md` for the recorded output and the explicit "what these tests do
NOT prove" section.

**Test taxonomy (same as Week-2 §4):**
- Unit — real code, synthetic fixture data, no network. **10 tests.**
- Simulated end-to-end — real code, real Week-2 evidence abridged. **4 playbooks, one test each.**
- Negative — malformed input rejected. **2 tests.**
- Live integration — **PENDING, not attempted.**
- AI re-execution — **N/A by design.**

## 7. What this package does NOT do

| Excluded | Reason |
|---|---|
| Live TheHive | No server/DB in lab. `thehive_stub.py` documents the contract; not wired. |
| Live SIEM trigger | Port collision + historical-replay posture. |
| Executed remediation | Week-2 reports prohibit automatic containment. |
| Live TI lookup | No TI feed; stub returns `not_performed`. |
| AI re-execution | Week-2 output is the input. |
| PB-04 response actions | Exchange receiver hard-codes `REVIEW_REQUIRED`. |

## 8. Open limitations and acceptance gates

1. **Week-2 acceptance is PENDING (6 gates).** Week 3 automates *triage and enrichment*,
   not the acceptance-pending conclusions. PB-04 is Tier-0-only for this reason.
2. **HTTP correlation gap (Week-2 gate 2).** PB-03's propose tier is limited to WAF review,
   not source blocking.
3. **Exchange receiver hard-codes `REVIEW_REQUIRED`.** PB-04 cannot propose response actions.
4. **No live TheHive, no live TI, no live Wazuh.** All stubs; documented as untested.
5. **Exchange `event_id` is replay-time-dependent.** Exchange tickets are not stable across
   replays; documented, not fixed.
6. **XSS receiver self-checks are weaker than AUTH/MAL.** PB-03 gets the strictest human gate.

**Acceptance decision: PENDING.** The Week-3 artifacts are documented and testable, but
final sign-off requires resolution or explicit documented acceptance of the outstanding
gates — same standard as Week 2.

## 9. Handover to Week 4

The SOAR package provides:
- Four playbooks keyed on `event_id`, consumed by Week 4's incident timeline.
- Ticket schema (JSON) that Week 4 can read without a live backend.
- Decision matrix that Week 4 reuses for containment/eradication/recovery steps.
- Audit log format that Week 4 extends into a full IR timeline.

Week 4's full IR simulation becomes a **tabletop exercise** built on Week-2 evidence +
Week-3 playbooks. No live SIEM, no live TheHive, no remediation execution — same
simulation boundary, explicitly labelled.

## 10. Files delivered

```
Week-3/
├── SOAR/
│   ├── README.md
│   ├── dispatcher.py
│   ├── decision-matrix.md
│   ├── manual-vs-automated.md
│   ├── test-results.md
│   ├── enrichment/
│   │   └── stub.py
│   ├── ticketing/
│   │   ├── base.py
│   │   ├── local_json.py
│   │   └── thehive_stub.py
│   ├── playbooks/
│   │   ├── PB-01.yaml  PB-01.md
│   │   ├── PB-02.yaml  PB-02.md
│   │   ├── PB-03.yaml  PB-03.md
│   │   └── PB-04.yaml  PB-04.md
│   ├── diagrams/
│   │   ├── logical.md
│   │   └── deployment.md
│   ├── tests/
│   │   ├── run_all.py
│   │   └── fixtures/
│   │       ├── ssh_valid.json
│   │       ├── mal_valid.json
│   │       ├── xss_valid.json
│   │       └── exchange_valid.json
│   ├── tickets/   (4 pre-generated)
│   └── audit/     (4 pre-generated)
└── Week-3-Final-Report.md
```

<!-- SCENARIO-ORCHESTRATOR-V1.2.0 -->

---

## Additional Week 3 implementation report — V1.2.0

The extension adds ten core modules and a unified CLI without replacing the original team SOAR. Week 2 evidence is ingested, normalized, processed through local AI and semantic validation, then routed to incident management and five playbooks.

### Validation results

| Metric | Observed result |
|---|---:|
| Week 2 evidence records | 8 |
| Incidents / response plans | 7 / 7 |
| Manual review records | 1 |
| Reused / newly processed AI results | 5 / 2 |
| Semantic PASS / PASS_WITH_WARNINGS | 3 / 4 |
| Verified simulations / closed incidents | 1 / 1 |
| External response actions | 0 |

The development record reports 95 cumulative successful checks across versions, not 95 independent tests executed together on the final build. V1.2.0 security validation passed 22/22; the reported final regression passed 16/16. End-to-end execution and final smoke test passed. Cleanup validated 11 Python files and preserved 255 protected files.

Reference run: `ORCH-20261124T164149Z-0614ef17`; playbooks: `PB-RUN-68e243875bd3`.

| Incident | State | Approval | Response |
|---|---|---|---|
| SSH brute force | CLOSED | APPROVED | COMPLETED |
| Malware | UNDER_INVESTIGATION | REJECTED | CANCELLED |
| One XSS | PENDING_APPROVAL | PENDING | NOT_STARTED |
| Four remaining incidents | NEW | PENDING | NOT_STARTED |

The SSH simulation produced eight simulated steps and a verified receipt. The rejected malware response was blocked. Final SOC reporting succeeded.

### Challenges and controls

| Challenge | Resolution |
|---|---|
| Missing event identity | Manual review gate |
| AI inconsistencies | Schema and semantic checks |
| Premature closure | Receipt and lifecycle enforcement |
| Modified plan | Approval hash binding |
| Repeated execution | Persistent receipt and reservation |
| Concurrent writes | Incident store protection |
| Duplicate development artifacts | Safe cleanup and Git exclusions |

### Limitations

Historical evidence replay is not live SIEM streaming. All response actions are simulated. Interactive confirmation is not authenticated analyst identity. SHA256 checks depend on trusted reference hashes; replay protection is workspace-scoped. AI findings and warnings require analyst interpretation. Exchange alerts do not establish exfiltration or phishing. Clean-machine portability is not yet verified; historical artifacts may contain absolute paths. Fresh runs may produce different AI results and cache counts.

The extension is functionally validated in the documented lab scope. Original team deliverables remain preserved.


<!-- REPRODUCIBILITY-VALIDATION -->
## Clean Repository Execution Test

| Metric | Result |
|---|---|
| Python version | 3.14.6 |
| Pipeline version | 1.2.0 |
| Evidence records | 8 |
| Fresh AI analyses | 7 |
| Reused AI results | 0 |
| Semantic PASS | 3 |
| Semantic PASS_WITH_WARNINGS | 4 |
| Manual review records | 1 |
| Incidents created | 7 |
| SOAR plans generated | 7 |
| SOC report generation | PASS |
| External response actions | 0 |

Reference run: ORCH-20261124T172039Z-69be0b57

Reference playbook run: PB-RUN-8c3e261e00f9

The test was conducted from a clean repository working
copy on the same Windows development machine.

Cross-device and cross-platform execution have not been
independently verified.
