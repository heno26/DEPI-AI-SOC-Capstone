1. INCIDENT TITLE: Composite Multi-stage Intrusion - Tabletop Simulation (Incident ID W4-TT-01)
2. EXECUTIVE SUMMARY: This incident involves a simulated multi-stage intrusion based on historical lab datasets, not a live production incident. The simulation includes various stages of reconnaissance, web-tier attacks, credential attacks, execution, persistence and privilege-sensitive activity, discovery and defense evasion, lateral movement, command and control, collection/exfiltration (hypothesis), containment, eradication, and recovery phases.
3. TIMELINE:
   | Time       | Event                                                                                                                                                      |
   |------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
   | 2026-05-26 | Stage S1 Reconnaissance: NT-01 Vertical TCP port scan                                                                                                |
   | 2025-10-07 | Stage S2 Web-tier attack: SIEM-WEB-001 High-rate HTTP requests from a single source                                                              |
   | 13/Oct/2024| Stage S2 Web-tier attack: SIEM-WEB-004 Cross-site scripting (XSS) payloads                                                                        |
   | Dec 10     | Stage S3 Credential attack: SIEM-AUTH-002 SSH brute force against root                                                                              |
   | Dec 10     | Stage S3 Credential attack: LT-01 SSH password guessing (verified timeline)                                                                      |
   | 2025-06-13 | Stage S4 Execution: SIEM-MAL-003 Suspicious executable with DNS + outbound connection                                                            |
   | 2024-05-31| Stage S4 Execution: LT-03 Bash reverse-shell command pattern                                                                                      |
   | 2019-06-14 | Stage S5 Persistence and privilege-sensitive activity: RT-04 Winlogon Shell persistence                                                             |
   | 2024-08-06 | Stage S5 Persistence and privilege-sensitive activity: LT-02 Privilege-sensitive sudo commands                                                      |
   | 2019-01-20 | Stage S6 Discovery and defense evasion: RT-02 Security log cleared + share access checks                                                          |
   | 2019-05-16 | Stage S7 Lateral movement: RT-03 WinRM remote command execution on DC                                                                              |
   | 2019-01-10 | Stage S8 Command and control: NT-03 Periodic HTTP connections to external host                                                                     |
   | 2026-05-26 | Stage S8 Command and control: NT-02 DNS chunk-style query burst                                                                                |
   | 2019-02-16 | Stage S8 Command and control: RT-01 plink.exe RDP tunnel                                                                                        |
   | 11/21/2022| Stage S9 Collection / exfiltration (hypothesis): SIEM-EXCH-005 Exchange mailbox export to OWA .aspx path                                |
4. IMPACT: Unknown [E032]
5. ROOT CAUSE: Unknown [E033]
6. ACTIONS TAKEN:
   - Week-3 SOAR dispatcher created 7 tickets automatically (Tier 0 actions: parse, enrich stub, create ticket, notify, audit) [E017]
   - Analyst decisions were recorded for every containment, eradication and recovery item; no proposal was executed [E018, E019, E020]
   - Read-only checks on the lab data:
     - SSH: 0 'Accepted' logins from 183.62.140.253 and 0 for root, dff or zhangyan [E024, E026]
     - NT-01: handshake completed on 11 ports (22, 135, 139, 445, 5040, 49664-49669) of 192.168.16.130 [E028]
     - Exchange: each export request followed a Mailbox Import Export role assignment and was later removed, with Search-Mailbox run afterwards; export file creation is not shown [E025]
     - RT-03: winrshost.exe ran as insecurebank\Administrator; the remote client is not in the dataset [E031]
     - LT-03: no network connection record, so reverse-shell success cannot be established [E027]
7. RECOMMENDATIONS:
   - Investigate the open questions listed under OPEN QUESTIONS section
8. OPEN QUESTIONS:
   - Is the vertical port scan from an authorized scanner? (S1; exposed services are listed under ACTIONS TAKEN) [E034]
   - Did any XSS payload execute in a browser, and is the high-rate HTTP source linked to the scan? (S2)
   - S3 answered in the lab data: no SSH password guess from 183.62.140.253 succeeded [E024, E026]
   - Is the dropped executable malicious (hash verdict), and did the reverse-shell connection succeed? (S4)
   - Is the Winlogon Shell modification authorized, and were the sudo commands approved administration? (S5)
   - Who cleared the Security log (Event 1102) and was it part of approved maintenance? (S6)
   - Which remote client initiated the WinRM command execution on the domain controller? (S7; account insecurebank\Administrator) [E031, E040]
   - Are the periodic connections, DNS chunk burst and plink tunnel C2 channels or approved tooling? (S8)
   - Were the .aspx export files written to the server before the export requests were removed? (S9) [E025, E042]
9. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.