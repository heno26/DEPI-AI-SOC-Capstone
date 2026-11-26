# Executive Briefing

**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone
**Week:** 4 - Full Capstone IR Simulation & Reporting
**Scenario:** W4-TT-01 - Composite multi-stage intrusion - tabletop simulation
**Generated:** 2026-11-26T02:47:58+00:00 by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated 2026-11-26T02:47:58+00:00)
**Status:** DRAFT - acceptance pending human sign-off


## Key figures (generated from data)

|  |  |
|---|---|
| What was exercised | 9-stage composite intrusion (network, web, auth, endpoint, email) |
| Evidence | 15 attack cases + 4 benign controls, all from historical lab data |
| AI role | Local Mistral 7B drafts triage and reports; every output is validated and human-reviewed |
| Response status | 29 response proposals; 0 awaiting decision; nothing auto-executed |
| Impact | Unknown - no confirmed data loss, exploitation or account compromise in the evidence |

### Briefing text (local AI draft)

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 243.33 s | *tokens/s:* 2.06 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Approved** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/exec_briefing.json`

1. BRIEFING TITLE: Potential Security Incident - W4-TT-01 Tabletop Exercise Analysis

2. SITUATION: A simulated security incident involving multiple stages of an attack has been identified in the W4-TT-01 tabletop exercise, using historical lab datasets.

3. WHAT WE KNOW:
   - The attack progressed through 9 stages across network, endpoint, web, authentication and email [E001]
   - Suspicious activity was detected at the Malware (SIEM-MAL-003) and Exchange (SIEM-EXCH-005) stages [E011, E014]
   - Winlogon Shell persistence (RT-04) and read-only checks for authentication and email (SIEM-AUTH-002, SIEM-EXCH-005) have been identified [E015, E016, E017]

4. WHAT WE DO NOT KNOW:
   - The business impact of this incident is unknown [E018]
   - The identity of the attacker remains unverified

5. DECISIONS NEEDED:
   - Analyst validation of AI triage ratings for SIEM-MAL-003, SIEM-WEB-004 and SIEM-EXCH-005 [E011]
   - Investigation into the suspicious activity detected at the Malware (SIEM-MAL-003) and Exchange (SIEM-EXCH-005) stages [E011, E014]
   - Determination of business impact and data loss [E018]

6. RISK IF NO ACTION: Unknown, as this is a tabletop simulation

7. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.

## Human sign-off

| Role | Name | Decision (Approved / Corrected / Rejected) | Date | Signature |
|---|---|---|---|---|
| SOC analyst |  |  |  |  |
| IR lead |  |  |  |  |
| Project supervisor |  |  |  |  |
