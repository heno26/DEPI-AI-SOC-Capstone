# Manual vs Automated Steps

Per-playbook step table. `Tier` uses the three-tier model from `README.md`.
`Approval` is the recorded artefact required before the step can proceed.

## PB-01 — SSH Brute Force

| Step | Actor | Tier | Approval | Evidence ref |
|---|---|---|---|---|
| Receive/parse evidence JSON | System | 0 | — | `event_id` |
| Verify count matches OpenObserve | System | 0 | — | `evidence.verified_failed_password_count` |
| Extract IOCs (IP, usernames) | System | 0 | — | `evidence.source_ip`, `evidence.top_usernames` |
| Reputation lookup | System (stub) | 0 | — | `enrichment.reputation_lookup.performed == false` |
| Create ticket | System | 0 | — | `tickets/<event_id>.json` |
| Notify analyst | System | 0 | — | `audit/<event_id>.jsonl` |
| Review AI triage | Analyst | 1 | required | `ai_triage.*` |
| Approve/reject rate-limit proposal | Analyst | 1 | required | `proposed_actions[0].decision` |
| Execute rate-limit at firewall | Analyst (manual) | 2 | explicit | out-of-band |
| Close ticket | Analyst | 1 | required | `review_status=Approved` |

## PB-02 — Malware Behavior

| Step | Actor | Tier | Approval | Evidence ref |
|---|---|---|---|---|
| Parse, verify, extract IOCs | System | 0 | — | `evidence.process_guid`, `destination_ip`, `verified_counts` |
| Create ticket + notify | System | 0 | — | `tickets/`, `audit/` |
| Review AI triage | Analyst | 1 | required | `ai_triage.*` |
| Approve/reject host isolation | Analyst | 1 | required | `proposed_actions[0].decision` |
| Approve/reject SHA256 blocklist | Analyst | 1 | required | `proposed_actions[1].decision` |
| Execute isolation | Analyst (manual) | 2 | explicit | out-of-band |
| Close ticket | Analyst | 1 | required | `review_status=Approved` |

## PB-03 — Web / XSS

| Step | Actor | Tier | Approval | Evidence ref |
|---|---|---|---|---|
| Parse, verify, extract IOCs | System | 0 | — | `evidence.transaction_id`, `source_ip` |
| Create ticket + notify | System | 0 | — | `tickets/`, `audit/` |
| Review AI triage | Analyst | 1 | required | `ai_triage.*` |
| Approve/reject WAF rule review | Analyst | 1 | required | `proposed_actions[0].decision` |
| Update WAF rule | Analyst (manual) | 2 | explicit | out-of-band |
| Close ticket | Analyst | 1 | required | `review_status=Approved` |

> **Note:** No source-block proposal for PB-03. The HTTP 001 correlation gap
> (Week-2 acceptance gate 2) means the trigger-to-row join is unproven; blocking on it
> would automate on an unverified detection.

## PB-04 — Exchange Mailbox Export (exfiltration hypothesis)

| Step | Actor | Tier | Approval | Evidence ref |
|---|---|---|---|---|
| Parse, verify, extract IOCs | System | 0 | — | `evidence.verified_unique_events` |
| Create ticket + notify | System | 0 | — | `tickets/`, `audit/` |
| Review AI triage | Analyst | 1 | required | `ai_triage.*` |
| **Any response action** | Analyst | **prohibited by dispatcher** | — | Exchange receiver hard-codes `REVIEW_REQUIRED`; report §11 |
| Close ticket | Analyst | 1 | required | `review_status=Approved` |

> **Note:** PB-04 is capped at Tier 0 in `dispatcher.run_playbook()`. Even if the
> YAML lists propose actions, they are ignored for PB-04.