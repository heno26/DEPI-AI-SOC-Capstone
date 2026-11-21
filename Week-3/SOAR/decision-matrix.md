# SOAR Decision Matrix

Every action the dispatcher can take, by tier. **Tier 0 = auto; Tier 1 = propose (human
approval); Tier 2 = prohibited (hard-blocked in code).** Each cell cites the Week-2
evidence that justifies the tier.

| # | Action | Tier 0 (auto) | Tier 1 (propose) | Tier 2 (prohibited) | Evidence basis |
|---|---|---|---|---|---|
| 1 | Parse + validate evidence envelope | ✅ all playbooks | | | Week-2 receivers; envelope includes `human_validation_required: true` |
| 2 | Extract IOCs from verified evidence | ✅ all | | | Deterministic field extraction, no inference |
| 3 | Reputation lookup | ✅ stub only | | | Malware 003 §4: "No external threat-intelligence verdict is claimed" |
| 4 | Asset context lookup | ✅ stub only | | | No asset DB in lab |
| 5 | Create ticket (LocalJSON) | ✅ all | | | Reversible, low blast radius |
| 6 | Notify analyst | ✅ all | | | Reversible |
| 7 | Write audit line | ✅ all | | | Append-only, idempotent by `event_id` |
| 8 | Propose rate-limit source IP | | PB-01 | | SSH report §4 (model recommended); §5 (success unconfirmed) |
| 9 | Propose host isolation | | PB-02 | | Malware report §6 "consider containment only after operational-impact evaluation" |
| 10 | Propose SHA256 blocklist | | PB-02 | | Same |
| 11 | Propose WAF rule review | | PB-03 | | XSS report §8; HTTP correlation gap (gate 2) |
| 12 | Propose export-request revocation | | | **PB-04 refuses** | Exchange receiver hard-codes `REVIEW_REQUIRED`; report §11 |
| 13 | Execute rate-limit | | | ✅ all | Week-2 §5.1 human-approval pending; Tier 2 |
| 14 | Execute host isolation | | | ✅ all | Malware §6; Exchange §11 |
| 15 | Disable / lock account | | | ✅ all | Exchange report §11 explicit |
| 16 | Delete mailbox export request | | | ✅ all | Exchange evidence unverified |
| 17 | Close ticket as benign | | ✅ (analyst only) | | `REVIEW_REQUIRED` ≠ sign-off (Week-2 §5.1) |
| 18 | Auto-remediate on AI priority alone | | | ✅ all | Week-2 §5: "AI triage results require SOC analyst validation" |

**The constitutional rule (row 18):** AI confidence never authorises execution. No
action whose blast radius is non-zero runs without a recorded analyst decision.

**PB-04 exception (row 12):** The Exchange receiver (`SIEM_EXCHANGE_005_AI_Receiver.py`)
hard-codes `qa_status: "REVIEW_REQUIRED"` regardless of warnings. PB-04 is therefore
capped at Tier 0 in the dispatcher (`run_playbook` sets `proposed = []` for PB-04).