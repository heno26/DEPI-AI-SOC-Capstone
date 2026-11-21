# Integration Workflow (Week 3)

## Implemented SOAR Integration - 18 November 2026

**Implementation status:** Four SOAR playbooks have been documented and dispatched against
real Week-2 evidence. Seven tickets and seven audit logs produced. Final Week-3 acceptance
remains **pending human sign-off**.

The historical design and the original proposed flow are preserved below as design
documentation. The section above describes the demonstrated implementation.

### 1. Actual Week-3 architecture

```text
Week-2 Evidence JSON (immutable)
    Week-2/Evidence/SIEM-OpenObserve/*_AI_Triage*.json
                    |
                    v
        SOAR Dispatcher (file-based)
            SOAR/dispatcher.py
            - load evidence JSON
            - normalise envelope (per-receiver adapter)
            - strip rule-name suffix
            - validate envelope (human_validation_required == true)
                    |
                    v
        Playbook Router
            source_trigger.key -> PB-01 / PB-02 / PB-03 / PB-04
                    |
                    v
        Decision Gates
            Gate 1: envelope valid
            Gate 2: qa_status in {SCHEMA_PASS_HUMAN_REVIEW_REQUIRED, REVIEW_REQUIRED}
                    |
                    v
        Playbook Execution
            - Tier 0: parse + enrich (stub) + create ticket + notify + audit
            - Tier 1: append proposed actions (human-gated)
            - Tier 2: never reached (PROHIBITED_ACTIONS blocked in code)
                    |
                    v
        Local JSON Ticket Backend
            SOAR/tickets/<event_id>.json
                    |
                    v
        Audit Trail
            SOAR/audit/<event_id>.jsonl
                    |
                    v
        Human Analyst Review
            (recorded separately; not part of Week-3 automation)
```

This represents the implemented file-based workflow. It does **not** establish that any
analyst has reviewed any ticket, that any remediation has been executed, or that any live
SIEM is currently connected.

### 2. Three workflows

**A. Dispatcher run (batch):** reads all `*_AI_Triage*.json` in the evidence folder, routes
each to a playbook, creates tickets idempotently, appends audit lines.

**B. Ticket inspection (human):** an analyst opens `SOAR/tickets/<event_id>.json` and reads
the ticket, its proposed actions, and its prohibited actions.

**C. Audit review (human):** an analyst opens `SOAR/audit/<event_id>.jsonl` and reviews the
per-event decision record. The audit log is the authoritative record of what happened; the
ticket is the state record.

### 3. Evidence adapters

The four Week-2 receivers produce different envelope shapes. The dispatcher normalises them
into a common form before routing.

| Adapter | Source receiver | Envelope shape |
|---|---|---|
| `auth_002` | `SIEM06_Multi_Alert_Receiver.py` | Standard: `source_trigger`, `evidence`, `ai_triage`, `qa_status` |
| `mal_003` | `SIEM06_Multi_Alert_Receiver.py` | Same standard shape |
| `web_xss` | `SIEM06` + `SIEM07_XSS_Receiver_Candidate.py` | Same standard shape |
| `exchange_005` | `SIEM_EXCHANGE_005_AI_Receiver.py` | Different: `correlation`, `ai_result`, short `event_id` |

The Exchange adapter (`normalise_document()` in `dispatcher.py`) synthesises the standard
envelope from the Exchange shape so the rest of the playbook logic is uniform.

### 4. Playbook routing

| `source_trigger.key` prefix | Playbook | Tier max |
|---|---|---|
| `SIEM_AUTH_002_SSH_BRUTE_FORCE` | PB-01 | Tier 1 |
| `SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR` | PB-02 | Tier 1 |
| `SIEM_WEB_001_HIGH_RATE_HTTP_REQUESTS` | PB-03 | Tier 1 |
| `SIEM_WEB_004_XSS_ATTACK_DETECTED` | PB-03 | Tier 1 |
| `SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT` | PB-04 | **Tier 0 only** |

OpenObserve firing triggers append `/<uniqueId>` to the rule name. The dispatcher strips
this suffix before routing (see `Dispatcher-Change-Log.md` Fix 1).

### 5. Decision gates

**Gate 1 — Envelope validity.** The evidence must contain all required fields and
`human_validation_required` must be `true`. This is a hard refusal: evidence without an
explicit human-review requirement is not processed.

**Gate 2 — QA status.** The `qa_status` must be one of `SCHEMA_PASS_HUMAN_REVIEW_REQUIRED`
or `REVIEW_REQUIRED`. Unknown values are refused.

These gates encode the Week-2 finding that AI confidence is not authorisation.

### 6. What flows where

```
Evidence JSON   →  Dispatcher       →  Ticket JSON      →  Analyst reads
                 →  Playbook logic   →  Audit JSONL      →  Analyst reads
                                     →  (No execution)
```

Nothing flows outward. The SOAR layer is a terminal: it produces tickets and audit records
for human review; it does not call the SIEM, the model, or the network.

### 7. Known limitations

1. **Week-2 acceptance is PENDING** (six gates). Week 3 automates triage and enrichment, not
   the acceptance-pending conclusions.
2. **HTTP correlation gap** (Week-2 gate 2) limits PB-03's propose tier to WAF review.
3. **Exchange receiver hard-codes `REVIEW_REQUIRED`** → PB-04 is Tier 0 only.
4. **No live TheHive, no live TI, no live SIEM.** All stubs; documented as untested.
5. **Exchange `event_id` is replay-time-dependent.** Exchange tickets are not stable across
   replays.
6. **XSS receiver self-checks are weaker than AUTH/MAL.** PB-03 gets the strictest human
   gate.

---

## Architecture (historical design, preserved below)

```
Week-2 evidence JSON
    |
    v
dispatcher.py
    |
    +-> playbooks/PB-01..04.yaml
    +-> enrichment/stub.py
    +-> ticketing/local_json.py
    +-> audit/<event_id>.jsonl
    |
    v
tickets/<event_id>.json
```

## The workflow steps and where they happen

| Step | Code |
|---|---|
| 1 Load evidence JSON | `dispatcher.load_evidence()` |
| 2 Normalise envelope | `dispatcher.normalise_document()` |
| 3 Strip rule suffix | `dispatcher.alert_rule()` |
| 4 Validate envelope | `dispatcher.validate_envelope()` |
| 5 Route to playbook | `dispatcher.ROUTE` lookup |
| 6 Enrich (stub) | `enrichment.stub.EnrichmentStub.run()` |
| 7 Build ticket | `dispatcher.build_ticket()` |
| 8 Create ticket | `ticketing.local_json.LocalJSONBackend.create()` |
| 9 Append audit | `dispatcher.main()` (file append) |
| 10 Human review | External (not in this package) |

## Supported inputs

Only Week-2 `*_AI_Triage*.json` files in the evidence folder. Nothing else.

## Evidence and privacy controls

- No network calls.
- No model calls.
- No external API calls.
- The dispatcher reads evidence files read-only; it never modifies them.

## Offline demonstration

Run the dispatcher with no network connection. It must produce the same seven tickets and
seven audit lines. Since no network call is ever made, this always works.

## Reuse by Week 4

The ticket schema (`tickets/<event_id>.json`) and audit schema (`audit/<event_id>.jsonl`)
are the exact artefacts Week 4 will consume for the incident timeline. No changes needed.

## Known limitations

Same six as above. Stated here again so a reader who skips §7 still encounters them.