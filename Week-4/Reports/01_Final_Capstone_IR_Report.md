# Final Capstone Incident Response Report

**Project:** DEPI Project 5 - AI-Assisted SOC Automation & Full Incident Response Capstone
**Week:** 4 - Full Capstone IR Simulation & Reporting
**Scenario:** W4-TT-01 - Composite multi-stage intrusion - tabletop simulation
**Generated:** 2026-11-26T02:47:58+00:00 by `Week-4/IR/build_reports.py` from `Week-4/Output/` (data generated 2026-11-26T02:47:58+00:00)
**Status:** DRAFT - acceptance pending human sign-off


## Simulation boundary

- Every stage is represented by real, hash-verifiable evidence that already exists in Week-2 (datasets, OpenObserve alert evidence, verified timelines) and Week-3 (tickets, audit logs).
- The datasets come from different public sources and different years. The chain that links the stages is a scenario construct for the tabletop exercise; causal links between stages are NOT observed in the data.
- Timeline order is the scenario stage order. Timestamps shown are the original dataset timestamps and are never shifted or invented.
- No live SIEM, no live TheHive, no live threat-intelligence feed, no remediation is executed. Containment/eradication/recovery items are proposals that require a recorded analyst decision.


## 1. Exercise at a glance

| Metric | Value | Source |
|---|---|---|
| Attack stages | 9 | Week-4/Config/scenario.json |
| Evidence-backed attack cases | 15 | Week-4/Output/incident.json |
| Benign controls | 4 | Week-4/Output/incident.json |
| Source events on the timeline | 192 | Week-4/Output/incident_timeline.csv |
| Indicators / context observables | 52 / 14 | Week-4/Output/observables.csv |
| Cross-dataset overlaps | 3 | Week-4/Output/observables.csv |
| Week-3 SOAR tickets | 7 | Week-3/SOAR/tickets/ |
| T1 response proposals / pending decision | 29 / 0 | Week-4/Output/ir_lifecycle.json |
| Week-2 local-AI analysis runs / human-reviewed | 53 / 27 | Week-2/Results/AN-*/analysis.json |
| Mean OpenObserve trigger -> AI triage (s) | 37.0 | Week-2/Evidence/SIEM-OpenObserve/ |

## 2. AI incident report draft (Week-1 Incident-Report prompt, local Mistral)

### Incident report draft

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 688.65 s | *tokens/s:* 1.96 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/incident_report.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/incident_report.corrected.md`). Original AI text kept in the JSON file.

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


## 3. Findings by stage


### S1 - Reconnaissance

*Analyst question:* Is the vertical port scan from an authorised scanner, and which hosts/services were exposed?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| NT-01 | Vertical TCP port scan | T1046 | - | Corrected | 65895 |

### AI stage summary - S1

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 291.86 s | *tokens/s:* 1.99 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Approved** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S1.json`

1. STAGE SUMMARY: During Stage S1 of scenario W4-TT-01, a vertical TCP port scan (NT-01) was observed on target host 192.168.16.130 from scanner 192.168.16.132.

2. EVIDENCE OBSERVED:
   - Scan initiator IP: [E001] 192.168.16.132
   - Target host IP: [E001] 192.168.16.130
   - Distinct ports scanned: [E002] 65535
   - TCP records: [E002] 65747
   - Rejected connections: [E002] 65620
   - Start and end timestamps: [E002] 2026-05-26T06:07:27.414749Z to 2026-05-26T06:19:45.683665Z
   - Events observed during the scan: [E002] provided in the input
   - Open services identified from read-only check: [E004] 22, 135, 139, 445, 5040, 49664, 49665, 49666, 49667, 49668, 49669

3. ATTACK TECHNIQUES:
   - T1046 Network Service Discovery (Discovery) [E003]

4. WHAT IS NOT ESTABLISHED:
   - Whether the vertical port scan is from an authorized scanner
   - The identity of the host initiating the scan

5. ANALYST QUESTION: Is the vertical port scan from an authorised scanner, and which hosts/services were exposed?

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S2 - Web-tier attack

*Analyst question:* Did any XSS payload execute in a browser, and is the high-rate HTTP source linked to the scan?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| SIEM-WEB-001 | High-rate HTTP requests from a single source | T1595 | Medium | PENDING (Week-2 REVIEW_REQUIRED; Week-3 tickets Pending Review) | 112 |
| SIEM-WEB-004 | Cross-site scripting (XSS) payloads | T1190 | High | PENDING (Week-2 REVIEW_REQUIRED; Week-3 tickets Pending Review) | 3 |

### AI stage summary - S2

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 270.98 s | *tokens/s:* 1.99 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Approved** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S2.json`

1. STAGE SUMMARY: During Stage S2 of scenario W4-TT-01, an Initial Access attempt was made on the web tier through potential Active Scanning (T1595) and Exploit Public-Facing Application (T1190). High-rate HTTP requests from a single source were observed, along with Cross-site scripting (XSS) payloads.

2. EVIDENCE OBSERVED:
   - 112 HTTP requests from 255.102.154.224 in one minute [E002]
   - Source IP is in reserved address space [E004]
   - A firing trigger is checked within a recent interval but lacks a proven row-level ID join [E005]
   - AI findings require human verification [E006]
   - 3 XSS payload instances from 192.168.171.129 [E008]
   - HTTP 500 for XSS payloads on /index.php [E008]
   - SIEM trigger does not independently prove browser-side execution [E012]

3. ATT&CK TECHNIQUES:
   - T1595 Active Scanning (Reconnaissance), confidence label: candidate [E003]
   - T1190 Exploit Public-Facing Application (Initial Access), confidence label: candidate [E009]

4. WHAT IS NOT ESTABLISHED:
   - Whether any XSS payload executed in a browser [E016]
   - If the high-rate HTTP source is linked to the scan [E016]

5. ANALYST QUESTION: Did any XSS payload execute in a browser, and is the high-rate HTTP source linked to the scan? [E016]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S3 - Credential attack

*Analyst question:* Did any SSH password guess succeed (Accepted password) for root or another account?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| SIEM-AUTH-002 | SSH brute force against root | T1110.001 | Medium | PENDING (Week-2 REVIEW_REQUIRED; Week-3 tickets Pending Review) | 30 |
| LT-01 | SSH password guessing (verified timeline) | T1110.001 | - | Corrected | 42 |

### AI stage summary - S3

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 230.39 s | *tokens/s:* 2.03 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S3.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/stage_S3.corrected.md`). Original AI text kept in the JSON file.

1. STAGE SUMMARY: During Stage S3, an SSH brute force against the root account was detected from IP address 183.62.140.253: 30 failed password attempts within one minute at Dec 10 11:01 (no year/timezone in the log) [E002].

2. EVIDENCE OBSERVED:
   - SSH brute force against root from IP address 183.62.140.253 [E002]
   - Repeated failed SSH password attempts for the same IP address in a lab environment [E010]
   - Read-only check of the 2000-line log: 0 'Accepted' logins from 183.62.140.253 and 0 for root, dff or zhangyan [E007, E012]

3. ATTACK TECHNIQUES:
   - T1110.001 Brute Force: Password Guessing (Credential Access) [E003, E011], confidence label: observed_pattern

4. WHAT IS NOT ESTABLISHED:
   - Whether any successful intrusion occurred as a result of the SSH brute force attack [E004]
   - The exact year and timezone for the original SSH event dates [E005]
   - Exact alert-row linkage between the rule-level trigger and the detected events [E006]

5. ANALYST QUESTION: Did any SSH password guess succeed (Accepted password) for root or another account? [E014]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S4 - Execution

*Analyst question:* Is the dropped executable malicious (hash verdict), and did the reverse-shell connection succeed?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| SIEM-MAL-003 | Suspicious executable with DNS + outbound connection | T1204.002, T1071.001 | High | PENDING (Week-2 REVIEW_REQUIRED; Week-3 tickets Pending Review) | 12 |
| LT-03 | Bash reverse-shell command pattern | T1059.004 | - | Corrected | 1 |

### AI stage summary - S4

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 359.34 s | *tokens/s:* 2.0 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S4.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/stage_S4.corrected.md`). Original AI text kept in the JSON file.

1. STAGE SUMMARY: During Stage S4 of scenario W4-TT-01, a suspicious executable was detected on a Windows endpoint, with 10 DNS queries and one outbound connection to 104.80.2.104:443 [E001]. A bash reverse-shell command pattern to 10.0.255.12:4444 was also recorded on Linux host ip-10-0-255-92 (LT-03) [E011]. Infection and network success are not confirmed [E005, E013].

2. EVIDENCE OBSERVED:
   - Process image: C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP001.TMP\2r8602.exe [E001]
   - Parent process: C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP000.TMP\N1F90.exe [E001]
   - SHA-256 hash: A1A79FEBE636F6AF95CA527BF37321A329F37BC2524414376F2727F4D9BD17C1 [E001]
   - IMP hash: 2EABE9054CAD5152567F0699947A2C5B [E001]
   - Destination IP: 104.80.2.104 [E001]
   - Destination port: 443 [E001]
   - DNS queries count: 10 [E001]
   - Domains (6 of the 10 queries): plodnittpw.lat, bloodyswif.lat, washyceehsu.lat, leggelatez.lat, miniatureyu.lat, kickykiduz.lat [E001]
   - LT-03: root ran bash -c with /dev/tcp/10.0.255.12/4444 redirection on ip-10-0-255-92 [E011]

3. ATTACK TECHNIQUES:
   - T1204.002 User Execution: Malicious File (Execution), confidence label: candidate [E003]
   - T1071.001 Application Layer Protocol: Web Protocols (Command and Control), confidence label: candidate [E004]
   - T1059.004 Command and Scripting Interpreter: Unix Shell (Execution), confidence label: observed_pattern [E012]

4. WHAT IS NOT ESTABLISHED:
   - Whether the dropped executable is malicious (hash verdict) [E005]
   - If the reverse-shell connection succeeded [E005]
   - The exact alert-row provenance of the trigger key [E007]
   - Network success in LT-03 incident [E013]

5. ANALYST QUESTION: Is the dropped executable malicious (hash verdict), and did the reverse-shell connection succeed? [E017]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S5 - Persistence and privilege-sensitive activity

*Analyst question:* Is the Winlogon Shell modification authorised, and were the sudo commands approved administration?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| RT-04 | Winlogon Shell persistence | T1547.004 | - | Corrected | 7 |
| LT-02 | Privilege-sensitive sudo commands | T1548.003 | - | Corrected | 21 |

### AI stage summary - S5

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 223.84 s | *tokens/s:* 2.16 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S5.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/stage_S5.corrected.md`). Original AI text kept in the JSON file.

1. STAGE SUMMARY: During Stage S5 of scenario W4-TT-01, a Winlogon Shell persistence entry was set on host IEWIN7 (RT-04) and privilege-sensitive sudo commands were recorded (LT-02); authorisation of both is not established [E002, E007, E009, E010].

2. EVIDENCE OBSERVED:
   - Execution of BRE6BgE2JubB.exe on host IEWIN7 [E002]
   - Creation of Winlogon Shell persistence entry in the registry [E003]
   - Five distinct sudo commands recorded in PROCTITLE audit records; execution outcome not established [E007, E009]
   - Abuse Elevation Control Mechanism: Sudo and Sudo Caching (Privilege Escalation) candidate technique for LT-02 [E008]

3. ATTACK TECHNIQUES:
   - T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL, Persistence) observed_pattern [E003]
   - T1548.003 (Abuse Elevation Control Mechanism: Sudo and Sudo Caching, Privilege Escalation), candidate [E008]

4. WHAT IS NOT ESTABLISHED:
   - Whether the Winlogon Shell modification was authorized [E010]
   - The outcome of the sudo commands execution [E009]
   - Successful privilege escalation through LT-02 [E009]

5. ANALYST QUESTION: Is the Winlogon Shell modification authorised, and were the sudo commands approved administration? [E010]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S6 - Discovery and defense evasion

*Analyst question:* Who cleared the Security log (Event 1102) and was it part of approved maintenance?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| RT-02 | Security log cleared + share access checks | T1070.001, T1033 | - | Approved | 4 |

### AI stage summary - S6

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 234.29 s | *tokens/s:* 2.34 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Approved** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S6.json`

1. STAGE SUMMARY: During Stage S6, an incident occurred involving the clearing of Windows Security logs and share access checks on host WIN-77LTAPHIQ1R.example.corp by the Administrator account.
2. EVIDENCE OBSERVED:
   - Event 1102 (Security audit log cleared) occurred at 2019-01-20T07:29:57.8638931Z on WIN-77LTAPHIQ1R.example.corp by the Administrator account [E002]
   - Network share access checks (Event 5145) for winreg, lsarpc, and srvsvc occurred at 2019-01-20T07:30:10.6451168Z on WIN-77LTAPHIQ1R.example.corp from source IP 10.0.2.17 [E002]
   - The clearing of Windows Event Logs (Defense Evasion, T1070.001) was observed based on the verified timeline [E003]
   - System Owner/User Discovery (Discovery, T1033) is a candidate technique due to network share access checks from 10.0.2.17 in the psloggedon dataset; intent undetermined [E004]
   - The session and approval cannot be established from the repository as the Event 1102 record carries no LogonId/session data [E005]
3. ATTACK TECHNIQUES:
   - T1070.001 (Clear Windows Event Logs) - observed_pattern
   - T1033 (System Owner/User Discovery) - candidate
4. WHAT IS NOT ESTABLISHED:
   - Whether the clearing of the Security log was part of approved maintenance
5. ANALYST QUESTION: Who cleared the Security log (Event 1102) and was it part of approved maintenance?
6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S7 - Lateral movement

*Analyst question:* Which client and account initiated the WinRM command execution on the domain controller?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| RT-03 | WinRM remote command execution on DC | T1021.006, T1016 | - | Corrected | 3 |

### AI stage summary - S7

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 144.14 s | *tokens/s:* 2.56 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S7.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/stage_S7.corrected.md`). Original AI text kept in the JSON file.

1. STAGE SUMMARY: During Stage S7, WinRM remote command execution (T1021.006) was observed on domain controller DC1.insecurebank.local, and ipconfig.exe ran from the WinRM-spawned cmd.exe (T1016) [E002, E003, E004].

2. EVIDENCE OBSERVED:
   - WinRM remote command execution occurred on DC1.insecurebank.local [E002]
   - winrshost.exe, cmd.exe, and ipconfig.exe were involved in the events [E002]
   - winrshost.exe ran as insecurebank\Administrator (LogonId 0x12fe05) [E005]

3. ATTACK TECHNIQUES:
   - T1021.006 Remote Services: Windows Remote Management (Lateral Movement) with observed_pattern confidence label [E003]
   - T1016 System Network Configuration Discovery (Discovery) with observed_pattern confidence label [E004]

4. WHAT IS NOT ESTABLISHED:
   - The remote client address is not verified in the dataset [E005]

5. ANALYST QUESTION: Which client and account initiated the WinRM command execution on the domain controller? [E007]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S8 - Command and control

*Analyst question:* Are the periodic connections, DNS chunk burst and plink tunnel C2 channels or approved tooling?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| NT-03 | Periodic HTTP connections to external host | T1071.001 | - | Corrected | 237 |
| NT-02 | DNS chunk-style query burst | T1071.004 | - | Corrected | 581 |
| RT-01 | plink.exe RDP tunnel | T1572 | - | Corrected | 4 |

### AI stage summary - S8

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 394.67 s | *tokens/s:* 1.99 | *validator flags:* 0 (high 0, medium 0, low 0) | *human review:* **Approved** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S8.json`

1. STAGE SUMMARY: The eighth stage of scenario W4-TT-01 involves repeated HTTP connections from a host (192.168.1.199) to an external IP address (46.101.251.172), which is suspected to be a command and control server based on the observed pattern of TCP/80 connections with retry attempts [E003]. Additionally, there are DNS chunk-style queries from another host (192.168.16.132) to the same resolver (192.168.16.131), potentially for command and control purposes due to a high number of queries within a short time frame [E006]. Lastly, there is evidence of an RDP tunnel using plink.exe on PC01.example.corp, which may also be related to command and control activities [E013].

2. EVIDENCE OBSERVED:
   - Periodic HTTP connections from 192.168.1.199 to 46.101.251.172:80 [E002]
   - DNS chunk-style queries from 192.168.16.132 to 192.168.16.131 for the lab.test zone [E005]
   - plink.exe RDP tunnel activity on PC01.example.corp [E012]

3. ATTACK TECHNIQUES:
   - T1071.001 Application Layer Protocol: Web Protocols (Command and Control) - candidate [E003]
   - T1071.004 Application Layer Protocol: DNS (Command and Control) - candidate [E006]
   - T1572 Protocol Tunneling (Command and Control) - observed_pattern [E013]

4. WHAT IS NOT ESTABLISHED:
   - The attribution of the command and control activities [E003, E006, E013]
   - Whether the DNS chunk burst is related to tunneling or exfiltration [E006]
   - The purpose of authorized lab/test activity in relation to the DNS queries [E007]
   - The meaning of the DNS payload [E008]
   - Whether NOERROR responses indicate exfiltration [E009]
   - The readability or content of the decoded bytes from the DNS queries [E010]
   - The purpose of plink.exe on PC01.example.corp [E012, E014, E015]

5. ANALYST QUESTION: Are the periodic connections, DNS chunk burst and plink tunnel C2 channels or approved tooling? [E016]

6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.


### S9 - Collection / exfiltration (hypothesis)

*Analyst question:* Did the mailbox export requests complete, and do the exported .aspx files exist on the server?

| Case | Finding | ATT&CK | AI severity | Human review | Records |
|---|---|---|---|---|---|
| SIEM-EXCH-005 | Exchange mailbox export to OWA .aspx path | T1114.002, T1505.003, T1098, T1070.008 | High | PENDING_HUMAN_APPROVAL | 8 |

### AI stage summary - S9

*Local model:* `Mistral:7b-instruct-v0.3-q4_K_S` | *time:* 2556.61 s | *tokens/s:* 0.16 | *validator flags:* 1 (high 0, medium 1, low 0) | *human review:* **Corrected** by Shahinda Gamal | *file:* `Week-4/Output/ai_drafts/stage_S9.json`

> Analyst-corrected version (`Week-4/Output/ai_drafts/stage_S9.corrected.md`). Original AI text kept in the JSON file.

1. STAGE SUMMARY: During Stage S9 of scenario W4-TT-01, the Exchange cmdlet audit log shows, twice, a Mailbox Import Export role assignment for Administrator@attackrange.local, a New-MailboxExportRequest targeting an .aspx path under the OWA auth directory, and then removal of the export request plus Search-Mailbox -DeleteContent [E003, E004, E005, E006]. Authorisation, export completion and web-shell deployment are not established [E007, E008].
2. EVIDENCE OBSERVED:
   - Two New-MailboxExportRequest cmdlets for Administrator@attackrange.local ([E003])
   - Export FilePath points to .aspx under OWA auth directory ([E004])
   - A Mailbox Import Export role assignment before each export ([E005])
   - Export request removal and Search-Mailbox -DeleteContent after each export ([E006])
3. ATTACK TECHNIQUES:
   - T1114.002 - Email Collection (Collection) - Candidate
   - T1505.003 - Server Software Component - Web Shell (Persistence) - Hypothesis
   - T1098 - Account Manipulation (Persistence) - Observed Pattern
   - T1070.008 - Indicator Removal: Clear Mailbox Data (Defense Evasion) - Observed Pattern
4. WHAT IS NOT ESTABLISHED:
   - Whether the mailbox export requests completed and .aspx files exist on the server
   - Whether the export requests were authorised [E007]
   - Whether the .aspx paths were intended for web-shell staging [E008]
   - The intended purpose of the ASPX destination paths
   - If actual files were created on disk as a result of the requested export operations
5. ANALYST QUESTION: Did the mailbox export requests complete, and do the exported .aspx files exist on the server?
6. REVIEW STATUS: DRAFT - AI-generated, requires human analyst validation before use.

<details><summary>Validator flags</summary>

| ID | Check | Severity | Value | Message |
|---|---|---|---|---|
| F001 | unsupported_domain | medium | t1098.account | Domain-like value not present in the source (may be ordinary text containing a dot). |

</details>



## 4. Read-only checks answered from repository data (T0)

These checks only read Week-2 datasets (`Week-4/IR/t0_checks.py`); the analyst still records the decision.

| Case | Check | Result | Source |
|---|---|---|---|
| SIEM-AUTH-002 | Search the full OpenSSH_2k.log for 'Accepted password' from 183.62.140.253; reset root credentials only if a success is found. | 2000 log lines searched; 867 lines mention 183.62.140.253; 'Accepted' logins from 183.62.140.253: 0; 'Accepted' logins for root: 0. The whole file contains 1 'Accepted' line(s), from other sources. | Week-2/Data/SIEM-BruteForce-SSH/OpenSSH_2k.log |
| SIEM-EXCH-005 | Run Get-MailboxExportRequest on win-dc-exch01.attackrange.local to check the status of the export requests (OnmrPW8m8Uv, dYbLTCleBT). | Get-MailboxExportRequest cannot be run (no server), but the Exchange cmdlet audit log answers the status question: RecordNumber 1788 11/21/2022 05:21:55 PM: New-ManagementRoleAssignment; RecordNumber 1789 11/21/2022 05:22:01 PM: New-MailboxExportRequest; RecordNumber 1793 11/21/2022 05:27:25 PM: Remove-MailboxExportRequest; RecordNumber 1794 11/21/2022 05:27:27 PM: Search-Mailbox; RecordNumber 1891 11/21/2022 08:03:50 PM: New-ManagementRoleAssignment; RecordNumber 1892 11/21/2022 08:03:51 PM: New-MailboxExportRequest; RecordNumber 1896 11/21/2022 08:09:02 PM: Remove-MailboxExportRequest; RecordNumber 1897 11/21/2022 08:09:04 PM: Search-Mailbox. Export requests later removed: OnmrPW8m8Uv, dYbLTCleBT. Cmdlet success is logged; export file creation on disk is NOT shown by this log. | Week-2/Data/Exchange/msexchangemanagement.log |
| LT-01 | Confirm no successful login exists for the targeted accounts (dff, root, zhangyan) on LabSZ. | 2000 log lines searched; 867 lines mention 183.62.140.253; 'Accepted' logins from 183.62.140.253: 0; 'Accepted' logins for dff, root, zhangyan: 0. The whole file contains 1 'Accepted' line(s), from other sources. | Week-2/Data/SIEM-BruteForce-SSH/OpenSSH_2k.log |
| LT-03 | Confirm whether the connection to 10.0.255.12:4444 succeeded (network_outcome is unknown in the evidence). | Original Sysmon-for-Linux file has 2 event(s), Event IDs ['1']; no Event ID 3 (network connection) record exists, so connection success cannot be established from this dataset. | Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution/LT-03-Sysmon-original.log |
| NT-01 | Review which of the 65535 probed ports on 192.168.16.130 are open and close unneeded services. | Zeek conn_state for 192.168.16.132 -> 192.168.16.130: REJ (closed) on 65524 ports; S0 (no reply) on 112 ports; handshake completed (RSTO/SF) on 11 ports: 22, 135, 139, 445, 5040, 49664, 49665, 49666, 49667, 49668, 49669. These are the candidate open services to review. | Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Zeek-conn-original.log |
| NT-02 | Decode the 250 chunk labels (chunkNNN-hex.lab.test) to determine whether they carry data. | 250 distinct chunk labels; hex parts decode to 3000 bytes, of which 38% are printable ASCII. The decoded bytes are not readable text (consistent with encoded/encrypted or random content); payload meaning remains undetermined. | Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Zeek-dns-original.log |
| RT-02 | Identify the session that cleared the Security log on WIN-77LTAPHIQ1R.example.corp and confirm whether Administrator activity was approved. | Event 1102 record 32950 at 2019-01-20T07:29:57.8638931Z: the verified timeline records account Administrator; the converted event carries no LogonId/session data (event_data is empty), so the session and approval cannot be established from the repository. | Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Discovery-converted.json |
| RT-03 | Identify the remote client and account behind winrshost.exe on DC1.insecurebank.local from authentication logs. | winrshost.exe ran as insecurebank\Administrator (LogonId 0x12fe05, IntegrityLevel High). The remote client address is not in the dataset (no Security 4624 record for that LogonId). | Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-converted.json |

## 5. NIST SP 800-61 lifecycle status

| Phase | Status | Detail |
|---|---|---|
| Preparation | COMPLETE | 8/8 preparation artifacts present (local AI lab, prompts, privacy checklist, SOAR playbooks). |
| Detection | COMPLETE | 5 OpenObserve alert rules fired with saved evidence; 10 dataset attack cases with verified timelines; 4 benign controls. |
| Triage & analysis | AI COMPLETE / HUMAN PARTIAL | AI triage present for 19/19 cases (local Mistral). Human review recorded for 14/14 dataset cases; all 5 SIEM alerts remain REVIEW_REQUIRED / Pending Review in Week-2/3. |
| Containment | COMPLETE | 21 items (16 T1 proposals, 5 T0 checks); 0 awaiting analyst decision. |
| Eradication | COMPLETE | 12 items (9 T1 proposals, 3 T0 checks); 0 awaiting analyst decision. |
| Recovery | COMPLETE | 12 items (4 T1 proposals, 8 T0 checks); 0 awaiting analyst decision. |
| Post-incident activity | COMPLETE | 12 local-AI report drafts found; 12 reviewed by an analyst. |

Detailed actions: `Reports/04_Containment_Recovery_Plan.md`.


## 6. AI assistance across the project

| Model | Manual quality /5 | Unsupported-fact severity /3 | Keyword recall (not accuracy) | Tokens/s |
|---|---|---|---|---|
| llama3.2:3b | 1.77 | 1.23 | 0.69 | 48.99 |
| mistral:7b-instruct-v0.3-q4_K_S | 2.77 | 0.77 | 0.75 | 23.1 |
| phi3:mini | 2.08 | 2.23 | 0.73 | 42.32 |

Week-2: 53 runs, 158 validator flags (46 high). Of 27 human-reviewed runs, 26 were Corrected and 1 Approved; analysts recorded 109 correct vs 68 incorrect AI findings. Source: `Week-2/Results/AN-*/analysis.json`.


## 7. Open acceptance gates carried into Week 4

- (Week-2) Human approval pending: AI triage results require SOC analyst validation. REVIEW_REQUIRED and related review states are not final analyst sign-off.
- (Week-2) HTTP evidence correlation: The HTTP case includes a 112-request source group against a threshold of 80. The exact row-level join between the saved firing trigger and that group has not been proven.
- (Week-2) Updated SIEM05 regression: Controlled Ollama reanalysis does not constitute an updated receiver-to-report end-to-end regression. This acceptance check remains pending.
- (Week-2) Replay scope: Historical lab datasets and replay timestamps must not be represented as production monitoring or confirmed incidents.
- (Week-2) Unified SOC candidate: The v0.4 QA candidate and its recorded tests do not constitute production approval.
- (Week-2) No automatic remediation: Week-3 SOAR and Week-4 full incident response have not been implemented in Week-2.

- (Week-3) Week-2 acceptance is PENDING (6 gates). Week 3 automates *triage and enrichment*, not the acceptance-pending conclusions. PB-04 is Tier-0-only for this reason.
- (Week-3) HTTP correlation gap (Week-2 gate 2). PB-03's propose tier is limited to WAF review, not source blocking.
- (Week-3) Exchange receiver hard-codes `REVIEW_REQUIRED`. PB-04 cannot propose response actions.
- (Week-3) No live TheHive, no live TI, no live Wazuh. All stubs; documented as untested.
- (Week-3) Exchange `event_id` is replay-time-dependent. Exchange tickets are not stable across replays; documented, not fixed.
- (Week-3) XSS receiver self-checks are weaker than AUTH/MAL. PB-03 gets the strictest human gate.


## 8. Deliverable index

| Deliverable | File |
|---|---|
| Final Capstone IR Report | Week-4/Reports/01_Final_Capstone_IR_Report.md |
| Incident timeline | Week-4/Reports/02_Incident_Timeline.md + Output/incident_timeline.csv |
| Forensic evidence summary | Week-4/Reports/03_Forensic_Evidence_Summary.md |
| Containment / recovery plan | Week-4/Reports/04_Containment_Recovery_Plan.md |
| Executive briefing | Week-4/Reports/05_Executive_Briefing.md |
| Lessons learned | Week-4/Reports/06_Lessons_Learned.md |
| AI-assisted reporting workflow | Week-4/Reports/07_AI_Assisted_Reporting_Workflow.md |
| SOC dashboard | Week-4/Dashboard/index.html |

## Human sign-off

| Role | Name | Decision (Approved / Corrected / Rejected) | Date | Signature |
|---|---|---|---|---|
| SOC analyst |  |  |  |  |
| IR lead |  |  |  |  |
| Project supervisor |  |  |  |  |
