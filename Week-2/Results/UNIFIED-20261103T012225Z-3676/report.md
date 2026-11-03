# DEPI P5 — Unified Log Triage (AI draft)

**Human validation required — not an incident verdict.**

Input: `LT-01-focused.log`
SHA256: `8b3991a3e08962be1a1686e221d73ef40c6a08e145e618e24f8ca8684f44319b`

## Source attribution
- linux: 42 event(s)

**Canonical citation rule:** report `[E###]` IDs refer to this unified input; original per-file IDs are provenance metadata only.

**QA acceptance gate:** BLOCKED_PENDING_CORRECTION (human review still required).

## Whole-family Python baseline (NOT an AI verdict)
### LINUX — 42 input event(s)
- **LINUX_SSH_REPEAT_FAILURE**: 13 records with Failed password from 183.62.140.253 (refs: E003, E009, E012, E015, E018, E021, E024, E027, E030, E033, E036, E039, E042).
  - Boundary: Successful login and unauthorized access NOT established
- **Batching limitation:** AI summaries analyze portions of this family; the Python baseline above uses all its supplied events.

## Local Mistral analysis runs
- linux: `AN-20261103-011955-8006` | events 16/16 | flags 1 | Pending Review
  - QA checks: timeline_timestamp_mismatch
- linux: `AN-20261103-012133-14d3` | events 16/16 | flags 5 | Pending Review
  - QA checks: finding_without_evidence_ref, timeline_timestamp_mismatch
- linux: `AN-20261103-012225-6bcf` | events 10/10 | flags 0 | Pending Review

## Source-derived evidence timeline (Python, not AI)
Input record order is retained; times from unrelated hosts or years are not assumed to form one incident.
A record is not proof of successful execution, access, or compromise.

| Unified ref | Source timestamp (verbatim) | Family | Record type | Original source record |
|---|---|---|---|---|
| E001 | Dec 10 10:54:27 | linux | Linux log record | Not recorded |
| E002 | Dec 10 10:54:27 | linux | Linux log record | Not recorded |
| E003 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E004 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E005 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E006 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E007 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E008 | Dec 10 10:54:29 | linux | Linux log record | Not recorded |
| E009 | Dec 10 10:54:31 | linux | Linux log record | Not recorded |
| E010 | Dec 10 10:54:31 | linux | Linux log record | Not recorded |
| E011 | Dec 10 10:54:31 | linux | Linux log record | Not recorded |
| E012 | Dec 10 10:54:33 | linux | Linux log record | Not recorded |
| E013 | Dec 10 10:54:33 | linux | Linux log record | Not recorded |
| E014 | Dec 10 10:54:33 | linux | Linux log record | Not recorded |
| E015 | Dec 10 10:54:35 | linux | Linux log record | Not recorded |
| E016 | Dec 10 10:54:35 | linux | Linux log record | Not recorded |
| E017 | Dec 10 10:54:35 | linux | Linux log record | Not recorded |
| E018 | Dec 10 10:54:37 | linux | Linux log record | Not recorded |
| E019 | Dec 10 10:54:37 | linux | Linux log record | Not recorded |
| E020 | Dec 10 10:54:37 | linux | Linux log record | Not recorded |
| E021 | Dec 10 10:54:39 | linux | Linux log record | Not recorded |
| E022 | Dec 10 10:54:39 | linux | Linux log record | Not recorded |
| E023 | Dec 10 10:54:39 | linux | Linux log record | Not recorded |
| E024 | Dec 10 10:54:41 | linux | Linux log record | Not recorded |
| E025 | Dec 10 10:54:41 | linux | Linux log record | Not recorded |
| E026 | Dec 10 10:54:41 | linux | Linux log record | Not recorded |
| E027 | Dec 10 10:54:43 | linux | Linux log record | Not recorded |
| E028 | Dec 10 10:54:43 | linux | Linux log record | Not recorded |
| E029 | Dec 10 10:54:43 | linux | Linux log record | Not recorded |
| E030 | Dec 10 10:54:45 | linux | Linux log record | Not recorded |
| E031 | Dec 10 10:54:45 | linux | Linux log record | Not recorded |
| E032 | Dec 10 10:54:45 | linux | Linux log record | Not recorded |
| E033 | Dec 10 10:54:47 | linux | Linux log record | Not recorded |
| E034 | Dec 10 10:54:47 | linux | Linux log record | Not recorded |
| E035 | Dec 10 10:54:47 | linux | Linux log record | Not recorded |
| E036 | Dec 10 10:54:49 | linux | Linux log record | Not recorded |
| E037 | Dec 10 10:54:49 | linux | Linux log record | Not recorded |
| E038 | Dec 10 10:54:49 | linux | Linux log record | Not recorded |
| E039 | Dec 10 10:54:50 | linux | Linux log record | Not recorded |
| E040 | Dec 10 10:54:50 | linux | Linux log record | Not recorded |
| E041 | Dec 10 10:54:51 | linux | Linux log record | Not recorded |
| E042 | Dec 10 10:54:52 | linux | Linux log record | Not recorded |

## Per-family AI drafts (verbatim, not verified)

### LINUX — AN-20261103-011955-8006
Evidence refs sent: E001, E002, E003, E004, E005, E006, E007, E008, E009, E010, E011, E012, E013, E014, E015, E016
Human review: Pending Review
Automated validation flags: 1

## EXECUTIVE SUMMARY
Four failed login attempts were made by the IP address 183.62.140.253 against three distinct user accounts on host LabSZ, with repeated attempts to access the root account. The activity appears suspicious due to multiple failed logins from a single source within a short time frame.

## LOG SOURCE
Source type: SSH server logs
Hosts: LabSZ
Time span: Dec 10 10:54:27 - Dec 10 10:54:35

## SIGNIFICANT SECURITY EVENTS
- [E003] Failed password for invalid user zhangyan from 183.62.140.253
- [E009] Failed password for invalid user dff from 183.62.140.253
- [E012] Failed password for root from 183.62.140.253
- [E015] Failed password for root from 183.62.140.253

## SUSPICIOUS ACTIVITIES
- Multiple failed login attempts against three distinct user accounts within a short time frame, with repeated attempts to access the root account [E003, E009, E012, E015]

## EVIDENCE REFERENCES
- [E003] Shows a failed password attempt for an invalid user zhangyan from IP 183.62.140.253
- [E009] Shows a failed password attempt for an invalid user dff from IP 183.62.140.253
- [E012] Shows a failed password attempt for the root account from IP 183.62.140.253
- [E015] Shows a failed password attempt for the root account from IP 183.62.140.253

## INCIDENT TIMELINE
| Timestamp | Event | Source | Host/User | Evidence Ref |
|-----------|-------|--------|-----------|--------------|
| Dec 10 10:54:29 | Failed password for invalid user zhangyan from 183.62.140.253 [E003] | sshd[24868] | LabSZ        |
| Dec 10 10:54:29 | Received disconnect from 183.62.140.253 [preauth] [E004] | sshd[24868] | LabSZ        |
| Dec 10 10:54:29 | Invalid user dff from 183.62.140.253 [E005] | sshd[24870] | LabSZ        |
| Dec 10 10:54:29 | input_userauth_request: invalid user dff [preauth] [E006] | sshd[24870] | LabSZ        |
| Dec 10 10:54:31 | Failed password for invalid user dff from 183.62.140.253 [E009] | sshd[24870] | LabSZ        |
| Dec 10 10:54:31 | Received disconnect from 183.62.140.253 [preauth] [E010] | sshd[24870] | LabSZ        |
| Dec 10 10:54:33 | Failed password for root from 183.62.140.253 [E012] | sshd[24872] | LabSZ        |
| Dec 10 10:54:33 | Received disconnect from 183.62.140.253 [preauth] [E013] | sshd[24872] | LabSZ        |
| Dec 10 10:54:33 | pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=183.62.140.253 user=root [E011] | sshd[24872] | LabSZ        |
| Dec 10 10:54:35 | Failed password for root from 183.62.140.253 [E015] | sshd[24874] | LabSZ        |
| Dec 10 10:54:35 | Received disconnect from 183.62.140.253 [preauth] [E016] | sshd[24874] | LabSZ        |

## EXTRACTED IOCS
- None identified

## POTENTIAL ATTACK INDICATORS
- Multiple failed login attempts against three distinct user accounts within a short time frame [E003, E009, E012, E015]
- Repeated attempts to access the root account [E012, E015]

## CONFIDENCE AND UNCERTAINTY
Low: The activity is suspicious but further investigation is needed to confirm if it represents a targeted attack or just brute force attempts.

## MISSING INFORMATION
- Additional logs from other sources for context and potential correlation with other events.
- Information about the user accounts involved, such as their roles and privileges.
- The purpose of these login attempts.

## RECOMMENDED INVESTIGATION STEPS
1. Review system logs for any related activity before or after this event.
2. Investigate the IP address 183.62.140.253 to determine its origin and potential connection to any known threats.
3. Check if there are any unusual patterns in login attempts from this IP address over time.
4. Determine if these user accounts have been compromised or if they were targeted due to their roles or privileges.
5. Implement additional security measures, such as locking out accounts after a certain number of failed login attempts, to prevent brute force attacks.

Deterministic indicators: None detected by implemented rules
Review checks: timeline_timestamp_mismatch

### LINUX — AN-20261103-012133-14d3
Evidence refs sent: E017, E018, E019, E020, E021, E022, E023, E024, E025, E026, E027, E028, E029, E030, E031, E032
Human review: Pending Review
Automated validation flags: 5

## EXECUTIVE SUMMARY
Repeated failed login attempts for the root account from IP address 183.62.140.253 are observed, which may indicate a brute force attack or an attempt to gain unauthorized access. However, without additional context and evidence, it is not possible to confirm if this activity is malicious or benign.

## LOG SOURCE
Source type: SSH (sshd) logs from LabSZ server, time span: Dec 10 10:54:35 - Dec 10 10:54:45

## SIGNIFICANT SECURITY EVENTS
- [E018] Failed password for root from 183.62.140.253
- [E021] Failed password for root from 183.62.140.253
- [E024] Failed password for root from 183.62.140.253
- [E027] Failed password for root from 183.62.140.253
- [E030] Failed password for root from 183.62.140.253

## SUSPICIOUS ACTIVITIES
- Repeated failed login attempts for the root account from IP address 183.62.140.253, which may indicate a brute force attack or an attempt to gain unauthorized access [E018..E030].

## EVIDENCE REFERENCES
- [E017] Shows an authentication failure for the root account from IP address 183.62.140.253.
- [E018] Shows a failed password attempt for the root account from IP address 183.62.140.253.
- [E021] Shows a failed password attempt for the root account from IP address 183.62.140.253.
- [E024] Shows a failed password attempt for the root account from IP address 183.62.140.253.
- [E027] Shows a failed password attempt for the root account from IP address 183.62.140.253.
- [E030] Shows a failed password attempt for the root account from IP address 183.62.140.253.

## INCIDENT TIMELINE
| Timestamp | Event | Source | Host/User | Evidence Ref |
|-----------|-------|--------|-----------|--------------|
| Dec 10 10:54:37 | authentication failure for root from 183.62.140.253 [E017] | LabSZ sshd[24877] | root          |
| Dec 10 10:54:37 | Failed password for root from 183.62.140.253 [E018]   | LabSZ sshd[24877] |              |
| Dec 10 10:54:39 | authentication failure for root from 183.62.140.253 [E020] | LabSZ sshd[24879] | root          |
| Dec 10 10:54:39 | Failed password for root from 183.62.140.253 [E021]   | LabSZ sshd[24879] |              |
| Dec 10 10:54:41 | authentication failure for root from 183.62.140.253 [E023] | LabSZ sshd[24882] | root          |
| Dec 10 10:54:41 | Failed password for root from 183.62.140.253 [E024]   | LabSZ sshd[24882] |              |
| Dec 10 10:54:43 | authentication failure for root from 183.62.140.253 [E026] | LabSZ sshd[24884] | root          |
| Dec 10 10:54:43 | Failed password for root from 183.62.140.253 [E027]   | LabSZ sshd[24884] |              |
| Dec 10 10:54:43 | authentication failure for root from 183.62.140.253 [E029] | LabSZ sshd[24886] | root          |
| Dec 10 10:54:45 | Failed password for root from 183.62.140.253 [E030]   | LabSZ sshd[24886] |              |
| Dec 10 10:54:45 | authentication failure for root from 183.62.140.253 [E032] | LabSZ sshd[24888] | root          |

## EXTRACTED IOCS
- None identified

## POTENTIAL ATTACK INDICATORS
- Repeated failed login attempts for the same account and IP address may indicate a brute force attack or an attempt to gain unauthorized access [E018..E030].
- The source IP address 183.62.140.253 should be investigated further.

## CONFIDENCE AND UNCERTAINTY
Low | Medium | High
- Repeated failed login attempts are observed, but without additional context and evidence, it is not possible to confirm if this activity is malicious or benign.

## MISSING INFORMATION
- Additional logs from other sources may provide more context about the source IP address 183.62.140.253 and its activities.
- Information about any authorized maintenance windows, registered tools, or approved changes in the environment could help determine if this activity is legitimate.

## RECOMMENDED INVESTIGATION STEPS
1. Investigate the source IP address 183.62.140.253 to determine its origin and any potential malicious intent.
2. Check for any known compromised accounts or passwords that match the attempted login credentials.
3. Review logs from other sources, such as firewalls and intrusion detection systems, for related activity.
4. Determine if there are any authorized maintenance windows, registered tools, or approved changes in the environment that could explain this activity.
5. Implement rate limiting or lockout policies to prevent brute force attacks on sensitive accounts.

Deterministic indicators: LINUX_SSH_REPEAT_FAILURE
Review checks: finding_without_evidence_ref, timeline_timestamp_mismatch

### LINUX — AN-20261103-012225-6bcf
Evidence refs sent: E033, E034, E035, E036, E037, E038, E039, E040, E041, E042
Human review: Pending Review
Automated validation flags: 0

## EXECUTIVE SUMMARY
Four failed login attempts were made against the account 'root' from IP address 183.62.140.253 within a minute, which may indicate brute-force attack or misconfiguration. However, without further context, it is unclear if this activity is malicious.

## LOG SOURCE
Source type: SSHD logs from host 'LabSZ'. Time span: Dec 10 10:54:47 - Dec 10 10:54:52.

## SIGNIFICANT SECURITY EVENTS
- [E033] Failed password for root from 183.62.140.253
- [E039] Failed password for root from 183.62.140.253
- [E042] Failed password for root from 183.62.140.253

## SUSPICIOUS ACTIVITIES
- Four failed login attempts against the account 'root' within a minute, which is unusual and may indicate brute-force attack or misconfiguration [E033, E039, E042].

## EVIDENCE REFERENCES
[E033] Dec 10 10:54:47 LabSZ sshd[24888]: Failed password for root from 183.62.140.253 port 36961 ssh2

## INCIDENT TIMELINE
| Timestamp | Event | Source | Host/User | Evidence Ref |
|-----------|-------|--------|-----------|--------------|
| Dec 10 10:54:47 | Failed password for root | LabSZ sshd[24888] | 183.62.140.253 | [E033] |
| Dec 10 10:54:49 | Failed password for root | LabSZ sshd[24890] | 183.62.140.253 | [E036] |
| Dec 10 10:54:50 | Failed password for root | LabSZ sshd[24893] | 183.62.140.253 | [E039] |
| Dec 10 10:54:52 | Failed password for root | LabSZ sshd[24896] | 183.62.140.253 | [E042] |

## EXTRACTED IOCS
- None identified

## POTENTIAL ATTACK INDICATORS
- Multiple failed login attempts against a single account within a short period of time [E033, E039, E042].

## CONFIDENCE AND UNCERTAINTY
Low: The activity is unusual but could also be due to misconfiguration. More context is needed to confirm if this is an attack.

## MISSING INFORMATION
- Further analysis is required to determine the source of these login attempts and whether they are part of a larger pattern or campaign.

## RECOMMENDED INVESTIGATION STEPS
1. Investigate the IP address 183.62.140.253 for any known malicious activity.
2. Check system logs for other failed login attempts against 'root' account and compare with this incident.
3. Review system configuration to ensure it is secure and up-to-date.
4. Investigate if there are any unauthorized changes in the system that could have led to these failed login attempts.
5. Monitor network traffic for similar patterns or indicators of compromise (IOCs).

Deterministic indicators: None detected by implemented rules
Review checks: None raised (not proof of correctness)

## Evidence and limitations
- Exact per-event classifier decisions: `manifest.json`.
- Detailed AI outputs / deterministic findings / validation flags: respective `Results/AN-*` folders.
- No verification of successful compromise, authorization, or provenance is implied.
- This mixed QA fixture combines independent datasets; it is NOT evidence of a single correlated incident.
- Group analyses are not equivalent to end-to-end SIEM or cross-source correlation acceptance.
- No SOAR action was taken.
