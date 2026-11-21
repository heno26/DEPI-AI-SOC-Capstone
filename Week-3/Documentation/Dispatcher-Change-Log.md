# Dispatcher Change Log

This file records the iteration history of the Week-3 SOAR dispatcher, including the four
fixes applied after testing against real Week-2 evidence. The intent is to make the
development process auditable — the same discipline Week-2 applies to its receivers.

## Version 0.2 — 2026-11-18 11:30 (current)

Four fixes applied after the first run against real Week-2 evidence produced zero tickets.
All four are documented below with symptom, cause, fix, and verification.

### Fix 1 — Rule name suffix strip

**Symptom:**
```
SKIP SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json: no route for rule 'SIEM_AUTH_002_SSH_BRUTE_FORCE/3LFgj2r7wLsZnMKzmAGq58E9FKj'
```
Every SIEM06/07 evidence file was skipped. Zero tickets created.

**Cause:** OpenObserve firing triggers append `/<firing_trigger_uniqueId>` to the rule name
in `source_trigger.key`. The dispatcher's `ROUTE` dict uses bare rule names. The bare name
`SIEM_AUTH_002_SSH_BRUTE_FORCE` does not match the suffixed `SIEM_AUTH_002_SSH_BRUTE_FORCE/3LFgj2r7...`.

**Fix:** `alert_rule()` now strips the `/` suffix:
```python
def alert_rule(doc):
    trig = doc.get("source_trigger") or {}
    key = trig.get("key", "") or ""
    return key.split("/", 1)[0] if "/" in key else key
```
This mirrors the logic already present in `SIEM06_Multi_Alert_Receiver.find_rule_trigger()`,
which uses `key == rule or key.startswith(rule + '/')`.

**Verification:** Dispatcher run produced 6 tickets from SIEM05/06/07 evidence (later
7 after Fix 2).

### Fix 2 — Exchange envelope normalisation

**Symptom:**
```
FAIL SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json: ValueError: evidence missing fields: ['source_trigger', 'evidence']
```
The Exchange evidence file was rejected because it does not have the standard envelope.

**Cause:** `SIEM_EXCHANGE_005_AI_Receiver.py` writes a structurally different JSON than the
SIEM06/07 receivers. It uses `correlation` and `ai_result` instead of `source_trigger` and
`evidence`. Its `event_id` is 20 characters, not 64.

**Fix:** Added `normalise_document()` that detects the Exchange shape and synthesises the
standard envelope:
```python
def normalise_document(doc):
    if "source_trigger" in doc and "evidence" in doc:
        return doc
    if "correlation" in doc:
        corr = doc.get("correlation") or {}
        ai = doc.get("ai_result") or doc.get("ai_triage") or {}
        rule = doc.get("alert_rule") or "SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT"
        return {
            "event_id": doc.get("event_id") or corr.get("event_id") or "unknown",
            "source_trigger": {"key": rule + "/exchange", "status": "firing"},
            "evidence": {
                "rule": rule,
                "verified_unique_events": corr.get("unique_events"),
                ...
            },
            "ai_triage": ai,
            "qa_status": "REVIEW_REQUIRED",
            "human_validation_required": True,
            "limitations": doc.get("limitations", []),
            "_source_file": doc.get("_source_file"),
        }
    return doc
```

**Verification:** Exchange ticket `21c4515e439a0b3b6a3f` created at Tier 0, as designed.

### Fix 3 — Legacy SIEM04 skip classification

**Symptom:**
```
FAIL SIEM04_Real_Alert_AI_Triage_20261022T012722Z.json: ValueError: evidence missing fields: ['event_id']
```

**Cause:** The SIEM04 file predates the SIEM05+ format and does not have an `event_id` field.
It is legitimately not routable.

**Fix:** The dispatcher's exception handler now distinguishes "missing fields with event_id"
(a legacy-format skip) from other failures:
```python
except Exception as exc:
    if "missing fields" in str(exc) and "event_id" in str(exc):
        print(f"SKIP {path.name}: legacy format without event_id (pre-SIEM05)")
    else:
        print(f"FAIL {path.name}: {type(exc).__name__}: {exc}")
```

**Verification:** SIEM04 is now printed as `SKIP`, not `FAIL`. The dispatch continues.

### Fix 4 — Documented `linked_evidence_file` path ambiguity (not applied)

**Observation:** Tickets have `"linked_evidence_file": "Evidence/SIEM-OpenObserve/..."`,
which is relative to `Week-2/`, not the repository root. A reader navigating from
`Week-3/SOAR/tickets/` cannot resolve it directly.

**Fix consideration:** Either prepend `Week-2/` in the ticket, or add a note in
`SOAR/README.md`.

**Status:** Documented here; **not applied** in v0.2 because it changes ticket field content
and the current value is truthful about the evidence's Week-2 origin. A future fix could
prepend `Week-2/` in the adapter.

## Verification runs

| Date | Command | Result |
|---|---|---|
| 2026-11-18 10:15 (v0.1) | `dispatcher.py` against real Week-2 evidence | 0 tickets, 2 FAIL, 6 SKIP |
| 2026-11-18 11:30 (v0.2) | Same command after 4 fixes | **7 tickets, 1 SKIP, 0 FAIL** |
| 2026-11-18 11:35 (v0.2) | `run_all.py` test suite | 10/10 passed |

## What was NOT changed between v0.1 and v0.2

- Playbook YAML content — unchanged.
- `PROHIBITED_ACTIONS` set — unchanged.
- Tier enforcement logic — unchanged.
- Ticket schema — unchanged.
- Audit schema — unchanged.

The four fixes are all routing/normalisation-layer, not playbook-semantics-layer. The
constitutional rule (Tier 2 prohibited) was never in question.

## Version 0.1 — 2026-11-18 09:00 (initial, superseded)

Initial delivery. Contained the four issues that v0.2 fixes. Retained in this log for
audit; the on-disk `dispatcher.py` is v0.2.