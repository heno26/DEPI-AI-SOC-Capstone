# DEPI P5 — Week 2 SOC Alert Report

**Alert:** `SIEM_AUTH_002_SSH_BRUTE_FORCE`  
**Data source:** `depi_auth_logs` / source dataset `OpenSSH_2k.log`  
**Execution:** 2026-10-27 02:47:13 Africa/Cairo (auto AI triage after webhook)  
**Model:** `mistral:7b-instruct-v0.3-q4_K_S`  
**Analysis ID:** `a823d14b61f061f7954e2e3eb7f18d6af6280f53242fe8c711d5cd78bcefdbae`  
**Mode:** Historical log replay — **not live production activity**

## 1. Executive summary
The SIEM detected **30 failed SSH password attempts** from source IP **183.62.140.253**, targeting account **root** during the original log minute **Dec 10 11:01**. This is consistent with a **suspected SSH brute-force attempt**. The available evidence does **not establish a successful login or system compromise**.

## 2. Detection and evidence verification
| Field | Value |
|---|---|
| SIEM rule | `SIEM_AUTH_002_SSH_BRUTE_FORCE` |
| SIEM trigger status | `firing` |
| Source IP | `183.62.140.253` |
| Username | `root` |
| Original log minute | `Dec 10 11:01` (source year/timezone absent) |
| Detection threshold | 5 failed logins in same original minute |
| Webhook grouped count | 30 |
| Count independently checked against OpenObserve | 30 |
| Source log samples | 8 with line references and SHA-256 hashes |

## 3. Representative source evidence
| Original source line | Time (year unknown) | Username | Source port | Raw log SHA-256 (prefix) |
|---:|---|---|---:|---|
| 1621 | Dec 10 11:01:01 | root | 51395 | `197fb1b1bb4379f4…` |
| 1624 | Dec 10 11:01:02 | root | 51830 | `411330851efc9225…` |
| 1627 | Dec 10 11:01:04 | root | 52182 | `a235606397e8e086…` |
| 1630 | Dec 10 11:01:06 | root | 52545 | `46e88525dc20bc17…` |
| 1633 | Dec 10 11:01:08 | root | 52850 | `5b34d08afc64ce12…` |
| 1636 | Dec 10 11:01:10 | root | 53160 | `64bd060a4a68c22a…` |
| 1639 | Dec 10 11:01:13 | root | 53630 | `2edf664e1bd56696…` |
| 1642 | Dec 10 11:01:14 | root | 54049 | `28e64e86d1570611…` |

## 4. Mistral AI triage — recorded output
**Summary:** Potential SSH brute-force attack detected on IP address 183.62.140.253 targeting the 'root' user account.  
**Potential threat:** SSH Brute Force  
**Severity proposed by model:** Medium  
**Confidence proposed by model:** High (for suspicious activity, not proof of compromise)  
**False positive possibility proposed by model:** Low (requires analyst review)

**Model recommendations (verbatim):**
- Increase account lockout policies for the 'root' user.
- Implement rate limiting on SSH connections from IP address 183.62.140.253.
- Monitor logs for further attempts and adjust thresholds as necessary.

## 5. Quality assurance and limitations
- Result status: `SCHEMA_PASS_HUMAN_REVIEW_REQUIRED`. Human validation required: `true`.
- Schema missing fields: 0; automated semantic warnings: 0. **Zero warnings does not prove perfect analysis.**
- The original SSH timestamps have no year or timezone.
- Trigger correlation is at rule level: a row-level join between trigger key and matched row was not established.
- These are historical replay logs. No conclusion about a current attack or successful compromise is supported.
- Other notification attempts previously returned HTTP 422 `invalid_payload`; this successful run alone does not prove every webhook delivery succeeded.
- Analyst should confirm whether the source IP and attempts were authorized test activity, and verify successful SSH authentication separately before escalating severity.

## 6. Final triage disposition
**Classification:** Suspected SSH brute-force authentication attempts.  
**Disposition:** Human review required.  
**Incident success:** Unconfirmed.  
**Week 2 pipeline demonstrated:** OpenObserve detection → authenticated webhook → SIEM06 evidence verification → Mistral 7B analysis → structured JSON evidence/report.

**Authoritative machine-readable evidence:** `SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json`
