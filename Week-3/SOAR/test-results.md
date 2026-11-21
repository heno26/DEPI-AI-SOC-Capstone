# Week-3 Test Results

**Taxonomy (same as Week-2 §4 — honesty discipline preserved):**
- **Unit** — real code, synthetic fixture data, no network.
- **Simulated end-to-end** — real code, real Week-2 evidence abridged into fixtures.
- **Negative** — malformed/invalid input must be rejected.
- **Live integration** — **PENDING, not attempted.**
- **AI re-execution** — **N/A by design** (Week-2 output is the input).

## Run command
```py
python -B Week-3/SOAR/tests/run_all.py
```

## Recorded output
```Output
PASS test_unit_route_table
PASS test_unit_prohibited_set
PASS test_unit_envelope_rejects_no_human_validation
PASS test_unit_alert_rule_extraction
PASS test_e2e_ssh
PASS test_e2e_malware
PASS test_e2e_xss
PASS test_e2e_exchange_tier0_only
PASS test_negative_bad_qa
PASS test_negative_missing_evidence
SUMMARY: 10/10 passed
```

## What these tests prove
- Dispatcher routes every alert rule to the correct playbook.
- Envelope rejection works: `human_validation_required != true` is refused.
- Unknown `qa_status` is refused.
- Empty evidence blob is refused.
- Every playbook produces a ticket with `review_status == "Pending Review"`.
- PB-04 emits **zero** proposed actions (Tier 0 cap enforced in code).
- Tier-2 actions never appear in `proposed_actions`.

## What these tests do NOT prove
- Live SIEM → SOAR integration (**PENDING**).
- TheHive API compatibility (**stub not tested**).
- Remediation execution (**prohibited by design**).
- Fresh AI inference (**N/A — Week-2 output reused**).
- That any Week-2 acceptance gate has been resolved (**still PENDING**).

These limitations mirror Week-2 §4 and are stated, not hidden.