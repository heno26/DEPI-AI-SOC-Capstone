# Week 3 Testing Guide (Windows 11 / PowerShell)

## Test status definitions

| Status | Meaning |
|---|---|
| PASS | The specified check was executed and its expected result was observed. |
| REVIEW_REQUIRED | Automated processing completed but human SOC validation remains necessary. |
| PENDING | A required test, review or acceptance step has not been completed. |
| NOT VERIFIED | Available evidence is insufficient to confirm the claimed behavior. |
| NOT APPLICABLE | The check does not apply to the demonstrated architecture. |

## 1. Test status summary

| Category | Count | Status |
|---|---:|---|
| Unit tests (real code, synthetic fixtures, no network) | 4 | PASS |
| Simulated end-to-end (real code, real Week-2 evidence abridged) | 4 | PASS |
| Negative tests (malformed input rejected) | 2 | PASS |
| **Total tests in `run_all.py`** | **10** | **PASS** |
| Dispatcher run against real Week-2 evidence | 1 | PASS (7 tickets, 1 skip, 0 failures) |
| Live SIEM → SOAR integration | — | PENDING (not attempted) |
| TheHive API compatibility | — | PENDING (stub not tested) |
| Executed remediation | — | NOT APPLICABLE (prohibited by design) |
| AI re-execution | — | NOT APPLICABLE (Week-2 output is the input) |

## 2. Prerequisites

```
- Python 3.9 or newer
- pip install pyyaml
- Week-2/Evidence/SIEM-OpenObserve/ present (only if running the dispatcher against real evidence)
```

No Ollama, no OpenObserve, no network, no model, no TheHive server is required for any
Week-3 test. Everything is file-based.

## 3. Automated tests — `run_all.py`

Run from the repository root:

```powershell
python -B Week-3/SOAR/tests/run_all.py
```

Expected final line:

```
SUMMARY: 10/10 passed
```

### What each test proves

| Test | Category | What it proves |
|---|---|---|
| `test_unit_route_table` | Unit | Every alert rule maps to the correct playbook ID |
| `test_unit_prohibited_set` | Unit | All six prohibited actions are declared |
| `test_unit_envelope_rejects_no_human_validation` | Unit | Evidence with `human_validation_required != true` is refused |
| `test_unit_alert_rule_extraction` | Unit | Rule name extracted correctly from `source_trigger.key` |
| `test_e2e_ssh` | E2E | PB-01 produces a ticket with a `rate_limit_source_ip` proposal, no `execute_rate_limit` |
| `test_e2e_malware` | E2E | PB-02 produces a ticket with `propose_host_isolation`, no `execute_isolation` |
| `test_e2e_xss` | E2E | PB-03 produces a ticket with `propose_waf_rule_review` |
| `test_e2e_exchange_tier0_only` | E2E | PB-04 produces a Tier 0 ticket with **zero** proposed actions |
| `test_negative_bad_qa` | Negative | Unknown `qa_status` is refused |
| `test_negative_missing_evidence` | Negative | Empty evidence blob is refused |

### What these tests do NOT prove

- Live SIEM integration.
- TheHive API compatibility.
- Remediation execution.
- Fresh AI inference.
- That any Week-2 acceptance gate has been resolved.

## 4. Dispatcher run against real Week-2 evidence

Run from the repository root:

```powershell
python -B Week-3/SOAR/dispatcher.py --evidence Week-2/Evidence/SIEM-OpenObserve --playbooks Week-3/SOAR/playbooks --out Week-3/SOAR
```

Expected output (real, from the 2026-11-18 run):

```
SKIP SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json: legacy format without event_id (pre-SIEM05)
TICKET 469dc3deb13af639 -> PB-03 (Tier 1)
TICKET a823d14b61f061f7 -> PB-01 (Tier 1)
TICKET e05ccfe875e6a535 -> PB-02 (Tier 1)
TICKET 6ba5792eef667c9c -> PB-03 (Tier 1)
TICKET 843425fa737b11ef -> PB-03 (Tier 1)
TICKET fad10ea2b71bb2bc -> PB-03 (Tier 1)
TICKET 21c4515e439a0b3b -> PB-04 (Tier 0)
STATUS: DISPATCH COMPLETE | processed=7
```

If you see this exact output, the dispatcher is working correctly. The skip of SIEM04 is
expected (legacy format, not routable). The three XSS records are distinct by `event_id` and
correctly produce three separate tickets.

### Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `FAIL ... missing fields: ['event_id']` on SIEM04 | Legacy format, no `event_id` | Already handled as SKIP in v0.2 (see `Dispatcher-Change-Log.md` Fix 3) |
| Every SIEM06/07 file printed as `SKIP ... no route for rule '.../<suffix>'` | Rule suffix not stripped | Already handled in v0.2 (see Fix 1) |
| Exchange file `FAIL ... missing fields: ['source_trigger', 'evidence']` | Different envelope shape | Already handled in v0.2 (see Fix 2) |
| `ModuleNotFoundError: yaml` | `pyyaml` not installed | `pip install pyyaml` |
| `FileNotFoundError: Week-3/SOAR/playbooks` | Wrong working directory | Run from repo root, or adjust `--playbooks` path |

## 5. How to interpret a ticket

A ticket is a single JSON file at `Week-3/SOAR/tickets/<event_id>.json`. Key fields:

| Field | Meaning |
|---|---|
| `ticket_id` | The Week-2 `event_id` (correlation key, idempotency key) |
| `playbook_id` | PB-01 through PB-04 |
| `alert_rule` | The originating detection rule |
| `tier` | `Tier 0` or `Tier 1` (never `Tier 2` — that is blocked) |
| `qa_status` | `SCHEMA_PASS_HUMAN_REVIEW_REQUIRED` or `REVIEW_REQUIRED` |
| `ai_severity`, `ai_confidence` | From the Week-2 AI triage (unchanged, reused) |
| `enrichment.iocs_extracted` | Indicators pulled from verified evidence |
| `enrichment.reputation_lookup.performed` | Always `false` (no live TI) |
| `proposed_actions[]` | Tier-1 recommendations requiring analyst approval |
| `prohibited_actions[]` | Actions the playbook refuses to take, with reasons |
| `review_status` | Always `Pending Review` at creation |
| `analyst_decision` | Always `null` at creation; updated only by recorded analyst review |

## 6. How to interpret an audit log

An audit log is a JSONL file at `Week-3/SOAR/audit/<event_id>.jsonl`, one line per
dispatcher run. Format:

```
{"ts_utc": "...", "event_id": "...", "playbook_id": "PB-01", "tier": "Tier 1",
 "actions_auto": [...], "actions_proposed": [...], "actions_prohibited": [...],
 "review_status": "Pending Review"}
```

The audit trail is append-only. Re-running the dispatcher on the same evidence produces a
new ticket only if no ticket exists (idempotent by `event_id`), and appends one line to the
audit for each run.

## 7. Test matrix

| # | Category | What it proves | Status |
|---|---|---|---|
| 1 | Unit — route table | Every rule routes correctly | PASS |
| 2 | Unit — prohibited set | Six prohibited actions declared | PASS |
| 3 | Unit — envelope rejection | `human_validation_required` enforced | PASS |
| 4 | Unit — rule extraction | Suffix stripping works | PASS |
| 5 | E2E — PB-01 SSH | Tier 1 propose, no Tier 2 | PASS |
| 6 | E2E — PB-02 Malware | Tier 1 propose, no Tier 2 | PASS |
| 7 | E2E — PB-03 Web/XSS | Tier 1 propose (WAF review only) | PASS |
| 8 | E2E — PB-04 Exchange | Tier 0 cap enforced, zero proposals | PASS |
| 9 | Negative — bad QA status | Refused | PASS |
| 10 | Negative — empty evidence | Refused | PASS |
| — | Dispatcher against real Week-2 | 7 tickets, 1 skip, 0 failures | PASS |
| — | Live SIEM → SOAR | — | PENDING |
| — | TheHive API | — | PENDING |
| — | Remediation execution | — | NOT APPLICABLE |

## 8. What these tests do NOT prove

- That any remediation was executed.
- That any analyst has approved any ticket.
- That any Week-2 acceptance gate has been resolved.
- That any fresh AI inference occurred.
- That a live TheHive server receives or accepts the tickets.

These limitations are the honesty boundary, matching Week-2's §4 taxonomy.

## 9. Common questions

**Q: Why does the dispatcher skip SIEM04?**
A: The SIEM04 file predates the newer receivers and does not have an `event_id` field. It
is legitimately not routable. v0.2 of the dispatcher classifies this as SKIP rather than
FAIL (see `Dispatcher-Change-Log.md` Fix 3).

**Q: Why do three XSS records produce three tickets?**
A: They have different `event_id` values (different transaction IDs). They are distinct
records, not duplicates. This matches Week-2's evidence README §5, which states they must
not be treated as exact duplicates without event-identity verification.

**Q: Why does the Exchange ticket have a shorter ID (20 chars)?**
A: The Exchange receiver generates a 20-character event_id (`sha256(...)[:20]` in
`SIEM_EXCHANGE_005_AI_Receiver.py`, `queue_exchange_ai()`); all other receivers generate
64-character IDs. The difference is by receiver design, not by error.

**Q: Can I run the dispatcher against a live SIEM instead of saved files?**
A: No. The dispatcher is file-based by design. This avoids the port collision between
SIEM06 and SIEM07 (both bind 127.0.0.1:8765) and matches the project's historical-replay
posture. See `Integration-Workflow.md` for the rationale.