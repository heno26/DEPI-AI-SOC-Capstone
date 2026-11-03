# RT-02 — Windows Discovery / IPC$ Access Checks

**Status:** Evidence-verified case documentation; human review **Approved**.  **Dataset type:** Recorded lab Windows events, not production telemetry.

## Scope and source

- Original EVTX: `discovery_psloggedon.evtx` (SHA-256: `aa2f3ad059952502d159ead3225a6dac6f2903d76f2ce8f503933deb46af7f07`).
- Corrected focused JSON: `RT-02-Discovery-focused-v2.json` (SHA-256: `ea16f7b875c3425c17d741f295cd8a1b422d0a8bf1dd8978c63774ccf3bd029f`).
- Original-to-parsed evidence mapping: `RT-02-evidence-mapping.csv`.
- Saved AI analysis: `AN-20261018-002643-c097`; original analysis and human review unchanged.
- Four selected events were independently matched back to the original EVTX by Record ID, Event ID, host and original XML timestamp (< 1 ms tolerance).

## Verified evidence timeline (UTC)

| Original XML timestamp | Event ID | Record ID | Observation | Original / parsed evidence |
|---|---:|---:|---|---|
| 2019-01-20T07:29:57.8638931Z | 1102 | 32950 | Windows Security audit log cleared (Event 1102); account: Administrator | E001 / E001 |
| 2019-01-20T07:30:10.6451168Z | 5145 | 32951 | Network share access check (Event 5145): winreg, source 10.0.2.17 | E002 / E002 |
| 2019-01-20T07:30:10.6600994Z | 5145 | 32952 | Network share access check (Event 5145): lsarpc, source 10.0.2.17 | E003 / E003 |
| 2019-01-20T07:30:10.6600994Z | 5145 | 32953 | Network share access check (Event 5145): srvsvc, source 10.0.2.17 | E004 / E004 |

## Evidence-supported findings

- [E001] Event ID **1102** records that the Windows Security audit log was cleared. This is **not** an administrator logon event.
- [E002–E004] Event ID **5145** records network share access **checks** for IPC$ named-pipe paths including `winreg`, `lsarpc`, and `srvsvc` from an internal address, as present in the source events.
- Event ID 5145 does not, by itself, prove successful remote execution, reading/modification of system files, unauthorized access or lateral movement.
- This small window does not establish a causal relationship between the log-clear event and the subsequent access checks.

## Analyst disposition and limitations

- Human review of the saved AI report: **Approved**. This approves the reviewed interpretation, **not** the activity as proven benign.
- **Intent/authorization:** Undetermined from four selected events.
- **Recommended follow-up:** Correlate authentication/session logs and IPC$ access checks, verify the source host/account and authorized maintenance, and investigate the audit-log-clear event.
- **Reputation:** No external IP or file reputation lookup established by this case.

## Integrity notes

Original files and saved AI/human-review artifacts were read-only. The verified timeline was produced from original EVTX XML timestamps, not AI-generated timestamps.
