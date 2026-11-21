# DEPI P5 — Week 3 SOAR Layer

## 1. Purpose
Week 3 adds a **SOAR (Security Orchestration, Automation and Response) layer** on top of
the Week-2 AI-assisted triage pipeline. It consumes the saved Week-2 evidence JSON files
and drives four playbooks: enrichment, ticketing, notification, and *proposed* (never
executed) response actions.

**What this layer is:** a deterministic, file-based automation engine that reads verified
Week-2 alert evidence, applies per-playbook decision gates, creates local tickets, writes
an audit trail, and surfaces containment actions for human approval.

**What this layer is not:** it does not re-run the AI, does not call a live SIEM, does not
execute remediation, and does not claim TheHive integration. Those are documented as
out-of-scope below.

## 2. Design constraints (inherited from Week 2)

- **Historical replay, not live monitoring.** Evidence files are from historical laboratory
  datasets replayed into OpenObserve.
- **No re-execution of the model.** Week-2 AI triage output is the input. This avoids the
  resource cost and the port-collision issue between SIEM06 and SIEM07 receivers
  (both bind 127.0.0.1:8765 and cannot run simultaneously).
- **No executed remediation.** Week-2 reports explicitly state that isolation and account
  disablement must not be automatic. This layer encodes that as a hard prohibition.
- **No live threat-intelligence lookup.** The enrichment backend is a stub that returns
  `not_performed`; tickets never display a fabricated reputation verdict.

## 3. Architecture

See `diagrams/deployment.md` and `diagrams/logical.md`.

## 4. Playbooks

| ID | Alert rule | Max tier | Rationale |
|---|---|---|---|
| PB-01 | SIEM_AUTH_002_SSH_BRUTE_FORCE | Tier 1 (propose rate-limit) | Successful login not established (Week-2 SSH report §5) |
| PB-02 | SIEM_MAL_003_SUSPICIOUS_MALWARE_BEHAVIOR | Tier 1 (propose isolate) | Malware report §6: containment only after impact evaluation |
| PB-03 | SIEM_WEB_001 + SIEM_WEB_004_XSS | Tier 1 (propose WAF review) | HTTP correlation gap (Week-2 acceptance gate 2); XSS receiver self-checks weaker |
| PB-04 | SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT | **Tier 0 only** | Receiver hard-codes `qa_status: REVIEW_REQUIRED`; no Exchange screenshots; review unconfirmed |

"Phishing" in the project brief is represented by PB-04 (mailbox export targeting the
Administrator mailbox — the closest Week-2 evidence gets to a credential/phishing narrative).
"Data exfiltration" is PB-04's *hypothesis* framing, explicitly labelled unverified.

## 5. Three automation tiers

- **Tier 0 — auto-execute:** reversible, low blast radius (parse, extract IOCs, create
  ticket, notify, write audit line).
- **Tier 1 — propose:** the action is written into the ticket as a pending decision;
  the analyst approves or rejects; nothing executes automatically.
- **Tier 2 — prohibited:** the playbook physically refuses to execute. Enforced in code
  (see `dispatcher.py`, `PROHIBITED_ACTIONS`).

## 6. What this package does NOT do

| Excluded | Reason |
|---|---|
| Live TheHive | No server/DB in lab. `thehive_stub.py` documents the API contract; not wired. |
| Live SIEM trigger | Receivers cannot co-bind port 8765; project is historical replay. |
| Executed remediation | Week-2 reports prohibit automatic containment. |
| Live TI lookup | No TI feed. Stub returns `not_performed`. |
| AI re-execution | Week-2 output is the input. |
| PB-04 response actions | Exchange receiver hard-codes review-required. |

## 7. Test results
See `test-results.md`.

## 8. Evidence preservation
Do not modify the Week-2 evidence JSON files. The dispatcher reads them read-only.