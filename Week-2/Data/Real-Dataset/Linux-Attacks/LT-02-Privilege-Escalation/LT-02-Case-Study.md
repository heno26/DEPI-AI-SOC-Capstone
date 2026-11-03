# LT-02 — Linux Auditd Privilege-Sensitive Commands: Verified Case Study

## Executive Summary

An analyst reviewed **21 normalized Linux Auditd `PROCTITLE` records** sampled from an original **108-record** attack-range dataset. Twelve selected records contain privilege-sensitive **command-line arguments**: six for `sudo chmod u+s vuln` (E010, E011, E012, E013, E014, E015) and six for `sudo setcap cap_setuid+ep ./priv_esc` (E016, E017, E018, E019, E020, E021). Nine selected records describe service inspection or restart commands, providing operational context.

**Assessment:** Potential privilege-escalation preparation / privilege-sensitive commands requiring investigation. **Neither successful execution, authorization status, nor successful privilege escalation is established** by this `PROCTITLE`-only evidence. The number of audit records must **not** be equated with a confirmed number of independent command invocations.

## Dataset and Chain of Custody

- Scenario: LT-02 — Linux Privilege Escalation Investigation.
- Source: Recorded Splunk Attack Data auditd sample (original file preserved).
- Original source: `LT-02-Auditd-original.log` — 108 `PROCTITLE` records.
- Focused sample: `LT-02-normalized-focused.log` — 21 normalized records.
- Sample-selection strategy: deterministic time-stratified sampling across five command patterns.
- Evidence mapping: `LT-02-evidence-mapping.csv`; each `E001`–`E021` maps to the source line number, audit serial, original epoch, decoded arguments, and original raw-line SHA-256.
- Source SHA-256: `897cd0434f7c13f27b61bebc9bed66545506bee652c06554ebbbe1a7e21303e1`.
- Focused SHA-256: `c501231ef8a5409016f7db307b334806403f0660e95bf4fa934fb4e0bc9d8c81`.
- Mapping SHA-256: `9c7e87fe9aa6c80abc97ca7e5490b719d25b7e4cda6d3c9cdd8d4f5423c0de4a`.
- Original host and user identity: **not recorded** in these source records.

## Observed Commands (Focused Sample)

| Decoded argv / command | Audit records | Context category | Evidence refs |
|---|---:|---|---|
| `sudo chmod u+s vuln` | 6 | suid_change_candidate | E010, E011, E012, E013, E014, E015 |
| `sudo setcap cap_setuid+ep ./priv_esc` | 6 | capability_change_candidate | E016, E017, E018, E019, E020, E021 |
| `sudo /opt/splunkforwarder/bin/splunk restart` | 3 | service_restart_context | E005, E006, E007 |
| `sudo systemctl status SplunkForwarder.service` | 3 | service_status_context | E004, E008, E009 |
| `sudo systemctl status auditd.service` | 3 | service_status_context | E001, E002, E003 |

## Evidence-Derived Timeline

- Earliest selected timestamp (UTC): `2024-08-06T14:01:04.626000Z`.
- Latest selected timestamp (UTC): `2024-08-06T14:36:57.376000Z`.
- Verified, complete 21-row timeline: `LT-02-Verified-Timeline.csv`.
- Timestamps are converted from each original `msg=audit(<epoch>:<serial>)` value, retaining microsecond formatting. **No estimated event timestamps** are used.
- `PROCTITLE` reflects captured command arguments; it is **not** an execution-result or authentication-success record.

## Analysis and Human Review

- Original local AI analysis ID: `AN-20261018-221905-552c` (preserved; not rewritten here).
- Screenshot/CLI-observed human-review disposition: **Corrected**, with two medium validator findings categorized **Needs follow-up**.
- F001: Potential attack-indicator conclusion lacked explicit evidence references; the privilege-sensitive command records are cited above.
- F002: The model's incident timeline contained a placeholder (`...`) without evidence reference; the verified timeline CSV uses only source-derived records.
- Additional analyst findings: unsupported benign classification; unsupported attribution to administrators despite absent `uid` / `auid` / `euid`; repeated `PROCTITLE` records described as independently confirmed attempts; `auditd.service` and `SplunkForwarder.service` incorrectly treated as domains, and `auditd` source label treated as a confirmed hostname.
- **Scope of review check:** Human review status and decisions were observed in the interactive CLI. This finalization script does **not** independently inspect or certify the internal review storage schema.

## Missing Evidence / Recommended Investigation

1. Correlate the audit serials with `SYSCALL`, `EXECVE`, `PATH`, and appropriate audit-event records to investigate execution outcomes and affected files.
2. Retrieve sudo/authentication/audit user context, including `auid`, `uid`, `euid`, session information, and authorization/change records.
3. Verify target file metadata and mode bits for `vuln`, and file capabilities for `./priv_esc`; establish whether any modifications actually persisted.
4. Look for subsequent execution, `setuid` calls or effective-UID changes, and actual unauthorized access or privilege escalation.
5. Investigate SplunkForwarder/auditd service activity in context; do not infer maliciousness from use of `sudo` or an apparent restart alone.
6. Classify `*.service` values as systemd service-unit names unless independent evidence supports a domain interpretation. External reputation was **not** checked.

## Conclusion

The records demonstrate audit-log observation of potentially privilege-sensitive command arguments, **not** a confirmed successful privilege escalation or identified attacker. The original evidence, selected normalized sample, AI report, and analyst review remain unchanged. This case study and verified timeline provide an evidence-grounded companion to the preserved AI output.
