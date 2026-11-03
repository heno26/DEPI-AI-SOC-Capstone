# DEPI P5 — Unified Log Triage (AI draft)

**Human validation required — not an incident verdict.**

Input: `RT-01-C2-plink-focused.json`
SHA256: `1a5bee30293a99830627fd128d7aa003e4b6268bd722bdc3256c10f989cd62b7`

## Source attribution
- windows: 4 event(s)

## Local Mistral analysis runs
- windows: `AN-20261024-133457-88cf` | events 4/4 | flags 8 | Pending Review

## Per-family AI drafts (verbatim, not verified)

### WINDOWS — AN-20261024-133457-88cf
Evidence refs sent: E001, E002, E003, E004
Human review: Pending Review
Automated validation flags: 8

## EXECUTIVE SUMMARY
The activity shows a user running plink.exe, which is part of the PuTTY suite for SSH connections. The command includes reverse SSH forwarding and RDP port forwarding to an external IP address (10.0.2.18). While this could be legitimate use, it's unusual and warrants further investigation due to potential exposure of internal resources.

## LOG SOURCE
Source type: Microsoft-Windows-Sysmon
Host(s): PC01.example.corp
Time span: 2019-02-16T10:02:21.9344384Z - 2019-02-16T10:04:05.0927728Z

## SIGNIFICANT SECURITY EVENTS
- [E001] Command-line SSH, Telnet, and Rlogin client (plink.exe) launched by user PC01\\IEUser with a password argument. [E003]
- [E002] TCP connection initiated from 10.0.2.17 to 10.0.2.18 on port 80 (HTTP). [E004]
- [E003] TCP connection initiated from 127.0.0.1 to 127.0.0.2 on port 4444 and 3389 (RDP). [E005]
- [E004] TCP connection initiated from 127.0.0.1 to 127.0.0.2 on port 49187 and 3389 (RDP). [E023]

## SUSPICIOUS ACTIVITIES
- A user is running plink.exe with command line arguments suggesting reverse SSH forwarding, RDP port forwarding, and a password argument. This could potentially expose internal resources if the destination IP address (10.0.2.18) is not authorized. [E001]
- Multiple TCP connections are initiated from within the network to external destinations on ports 49185, 49186, 49187, and 3389 (RDP). These connections need verification as they could be part of the observed plink.exe activity or unrelated events. [E002, E003, E004, E005]

## EVIDENCE REFERENCES
- [E001] SHA1 hash for plink.exe: 7806AD24F669CD8BB9EBE16F87E90173047F8EE4
- [E002] TCP connection from 10.0.2.17 to 10.0.2.18 on port 80 (HTTP).
- [E003] TCP connection from 127.0.0.1 to 127.0.0.2 on port 49186 and 3389 (RDP).
- [E004] TCP connection from 127.0.0.1 to 127.0.0.2 on port 49187 and 3389 (RDP).
- [E005] TCP connection from 127.0.0.1 to 127.0.0.2 on port 49186 and 3389 (RDP).
- [E023] TCP connection from 127.0.0.1 to 127.0.0.2 on port 49187 and 3389 (RDP).

## INCIDENT TIMELINE
| Timestamp | Event | Source | Host/User | Evidence Ref |
|---|---|---|---|---|
| 2019-02-16T10:02:21.9344384Z | plink.exe launched by PC01\\IEUser | Microsoft-Windows-Sysmon | PC01.example.corp | [E001] |
| 2019-02-16T10:02:22.9659216Z | TCP connection from 10.0.2.17 to 10.0.2.18 on port 80 (HTTP) | Microsoft-Windows-Sysmon | PC01.example.corp | [E002] |
| 2019-02-16T10:02:48.5026416Z | TCP connection from 127.0.0.1 to 127.0.0.2 on port 49186 and 3389 (RDP) | Microsoft-Windows-Sysmon | PC01.example.corp | [E003] |
| 2019-02-16T10:02:48.5026416Z | plink.exe launched by PC01\\IEUser (repeat) | Microsoft-Windows-Sysmon | PC01.example.corp | [E004] |
| 2019-02-16T10:04:05.0927728Z | TCP connection from 127.0.0.1 to 127.0.0.2 on port 49187 and 3389 (RDP) | Microsoft-Windows-Sysmon | PC01.example.corp | [E023] |

## EXTRACTED IOCS
- Type: TCP connection
  - Value: 10.0.2.17 to 10.0.2.18 on port 80 (HTTP)
    - Evidence Ref: [E002]
- Type: TCP connection
  - Value: 127.0.0.1 to 127.0.0.2 on port 49186 and 3389 (RDP)
    - Evidence Ref: [E003, E005]
- Type: TCP connection
  - Value: 127.0.0.1 to 127.0.0.2 on port

Deterministic indicators: WINDOWS_PLINK_REVERSE_FORWARD
Review checks: missing_section, nonexistent_evidence_ref, output_truncated, timeline_timestamp_mismatch

## Evidence and limitations
- Exact per-event classifier decisions: `manifest.json`.
- Detailed AI outputs / deterministic findings / validation flags: respective `Results/AN-*` folders.
- No verification of successful compromise, authorization, or provenance is implied.
- Group analyses are not equivalent to end-to-end SIEM or cross-source correlation acceptance.
- No SOAR action was taken.
