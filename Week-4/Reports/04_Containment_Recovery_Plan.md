# Containment, Eradication & Recovery Plan

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


**Tiers** (from Week-3 decision matrix): T0 = read-only check; T1 = proposal, requires a recorded analyst decision, executed out-of-band by a human; T2 = automation prohibited by design.

Record a decision: `python -B Week-4/IR/ir_cli.py decide --item <ITEM_ID> --decision approved|rejected|done --analyst "Name" --note "..."` (append-only log `Week-4/Simulation/analyst_decisions.jsonl`). Rule-based suggestions (`Week-4/IR/suggest.py`) can be accepted with `ir_cli.py accept-suggestions --analyst "Name"`; the log marks those decisions as accepted suggestions.


## Phase status

| Phase | Status | Detail |
|---|---|---|
| Preparation | COMPLETE | 8/8 preparation artifacts present (local AI lab, prompts, privacy checklist, SOAR playbooks). |
| Detection | COMPLETE | 5 OpenObserve alert rules fired with saved evidence; 10 dataset attack cases with verified timelines; 4 benign controls. |
| Triage & analysis | AI COMPLETE / HUMAN PARTIAL | AI triage present for 19/19 cases (local Mistral). Human review recorded for 14/14 dataset cases; all 5 SIEM alerts remain REVIEW_REQUIRED / Pending Review in Week-2/3. |
| Containment | COMPLETE | 21 items (16 T1 proposals, 5 T0 checks); 0 awaiting analyst decision. |
| Eradication | COMPLETE | 12 items (9 T1 proposals, 3 T0 checks); 0 awaiting analyst decision. |
| Recovery | COMPLETE | 12 items (4 T1 proposals, 8 T0 checks); 0 awaiting analyst decision. |
| Post-incident activity | COMPLETE | 12 local-AI report drafts found; 12 reviewed by an analyst. |

## Containment

| Case | Stage | Tier | Action | Automated read-only check (T0) | Decision | Item ID |
|---|---|---|---|---|---|---|
| SIEM-WEB-001 | S2 | T1 | Propose WAF rule review for /3.php, /1.php, /40.php (top paths) (NOT executed) |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-001:containment:propose_waf_rule_review:469dc3de |
| SIEM-AUTH-002 | S3 | T1 | Propose 1h edge rate-limit for 183.62.140.253 (NOT executed) |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-AUTH-002:containment:rate_limit_source_ip:a823d14b |
| SIEM-MAL-003 | S4 | T1 | Propose isolation of host running C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP001.TMP\2r8602.exe (NOT executed) |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-MAL-003:containment:propose_host_isolation:e05ccfe8 |
| SIEM-MAL-003 | S4 | T1 | Propose blocklisting SHA256 A1A79FEBE636F6AF95CA527BF37321A329F37BC2524414376F2727F4D9BD17C1 (NOT executed) |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-MAL-003:containment:propose_hash_blocklist:e05ccfe8 |
| SIEM-WEB-004 | S2 | T1 | Propose WAF rule review for /index.php?p=... (NOT executed) |  | deferred (Mohammed walid) | SIEM-WEB-004:containment:propose_waf_rule_review:6ba5792e |
| SIEM-WEB-004 | S2 | T1 | Propose WAF rule review for /index.php (NOT executed) |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-004:containment:propose_waf_rule_review:843425fa |
| SIEM-WEB-004 | S2 | T1 | Propose WAF rule review for /index.php (NOT executed) |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-004:containment:propose_waf_rule_review:fad10ea2 |
| SIEM-EXCH-005 | S9 | T0 | Run Get-MailboxExportRequest on win-dc-exch01.attackrange.local to check the status of the export requests (OnmrPW8m8Uv, dYbLTCleBT). | [data] Get-MailboxExportRequest cannot be run (no server), but the Exchange cmdlet audit log answers the status question: RecordNumber 1788 11/21/2022 05:21:55 PM: New-ManagementRoleAssignment; RecordNumber 1789 11/21/2022 05:22:01 PM: New-MailboxExportRequest; RecordNumber 1793 11/21/2022 05:27:25 PM: Remove-MailboxExportRequest; RecordNumber 1794 11/21/2022 05:27:27 PM: Search-Mailbox; RecordNumber 1891 11/21/2022 08:03:50 PM: New-ManagementRoleAssignment; RecordNumber 1892 11/21/2022 08:03:51 PM: New-MailboxExportRequest; RecordNumber 1896 11/21/2022 08:09:02 PM: Remove-MailboxExportRequest; RecordNumber 1897 11/21/2022 08:09:04 PM: Search-Mailbox. Export requests later removed: OnmrPW8m8Uv, dYbLTCleBT. Cmdlet success is logged; export file creation on disk is NOT shown by this log. | done (Mohammed Walid, rule suggestion accepted) | SIEM-EXCH-005:containment:1-run-get-mailboxexportreq |
| SIEM-EXCH-005 | S9 | T0 | Check whether the export target files exist: \\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\ZnTQs2wv.aspx, \\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\43yYO1sP.aspx. | [not in repo] No filesystem, IIS or OWA access log for win-dc-exch01 is in the repository (ESI-HttpProxyLogs.json is from a different host/date and contains no request to the .aspx paths). | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-EXCH-005:containment:2-check-whether-the-export |
| LT-01 | S3 | T1 | Block SSH from 183.62.140.253 on host LabSZ (same source as SIEM-AUTH-002). |  | approved (Youssef Sherif, rule suggestion accepted) | LT-01:containment:1-block-ssh-from-source-ip |
| LT-02 | S5 | T0 | Match the 5 distinct sudo commands against change records; no action unless unauthorised. | [not in repo] No change-management records exist in the repository. | deferred (Youssef Sherif, rule suggestion accepted) | LT-02:containment:1-match-the-distinct-comma |
| LT-03 | S4 | T1 | Isolate ip-10-0-255-92 from the network and block egress to 10.0.255.12:4444. |  | approved (Youssef Sherif, rule suggestion accepted) | LT-03:containment:1-isolate-host-from-the-ne |
| NT-01 | S1 | T0 | Confirm whether 192.168.16.132 is an authorised scanner (scan window, change record). | [not in repo] Scanner authorisation is recorded as 'unknown' in NT-01 statistics; no scan schedule/change record in the repository. | deferred (Youssef Sherif, rule suggestion accepted) | NT-01:containment:1-confirm-whether-scanner- |
| NT-01 | S1 | T1 | If unauthorised: block 192.168.16.132 from reaching 192.168.16.130 at the internal firewall. |  | deferred (Youssef Sherif, rule suggestion accepted) | NT-01:containment:2-if-unauthorised-block-sc |
| NT-02 | S8 | T1 | Rate-limit / inspect DNS from 192.168.16.132 to 192.168.16.131 for the lab.test zone. |  | approved (Youssef Sherif, rule suggestion accepted) | NT-02:containment:1-rate-limit-inspect-dns-f |
| NT-03 | S8 | T1 | Block egress from 192.168.1.199 to 46.101.251.172:80. |  | deferred (Youssef Sherif, rule suggestion accepted) | NT-03:containment:1-block-egress-from-src-ip |
| RT-01 | S8 | T1 | Block C:\Users\IEUser\Desktop\plink.exe execution and the tunnel destinations (10.0.2.18:80, 127.0.0.2:3389) on PC01.example.corp. |  | approved (Youssef Sherif, rule suggestion accepted) | RT-01:containment:1-block-tool-path-executio |
| RT-02 | S6 | T0 | Identify the session that cleared the Security log on WIN-77LTAPHIQ1R.example.corp and confirm whether Administrator activity was approved. | [data] Event 1102 record 32950 at 2019-01-20T07:29:57.8638931Z: the verified timeline records account Administrator; the converted event carries no LogonId/session data (event_data is empty), so the session and approval cannot be established from the repository. | done (Youssef Sherif, rule suggestion accepted) | RT-02:containment:1-identify-the-session-tha |
| RT-02 | S6 | T1 | If unapproved: reset the Administrator password and restrict share access (winreg, lsarpc, srvsvc) from 10.0.2.17. |  | deferred (Youssef Sherif, rule suggestion accepted) | RT-02:containment:2-if-unapproved-reset-the- |
| RT-03 | S7 | T1 | Restrict WinRM on DC1.insecurebank.local to approved administration hosts. |  | approved (Youssef Sherif, rule suggestion accepted) | RT-03:containment:1-restrict-winrm-on-host-t |
| RT-04 | S5 | T1 | Isolate IEWIN7 until the persistence entry is removed. |  | approved (Shahinda Gamal, rule suggestion accepted) | RT-04:containment:1-isolate-host-until-the-p |

## Eradication

| Case | Stage | Tier | Action | Automated read-only check (T0) | Decision | Item ID |
|---|---|---|---|---|---|---|
| SIEM-WEB-001 | S2 | T0 | Resolve Week-2 gate 2: prove the row-level join between the firing trigger and the 112-request group from 255.102.154.224 before any source block. | [not in repo] Needs the live OpenObserve alert rows to prove the trigger-to-row join (Week-2 gate 2). | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-001:eradication:1-resolve-week-2-gate-2-pr |
| SIEM-AUTH-002 | S3 | T1 | Disable SSH password authentication for root (PermitRootLogin prohibit-password / key-only). |  | deferred (Youssef sherif) | SIEM-AUTH-002:eradication:1-disable-ssh-password-aut |
| SIEM-MAL-003 | S4 | T1 | Remove C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP001.TMP\2r8602.exe and its parent C:\Users\WDAGUtilityAccount\AppData\Local\Temp\IXP000.TMP\N1F90.exe from the affected host after evidence preservation. |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-MAL-003:eradication:1-remove-process-image-and |
| SIEM-MAL-003 | S4 | T1 | Add SHA256 A1A79FEBE636F6AF95CA527BF37321A329F37BC2524414376F2727F4D9BD17C1 to the endpoint blocklist (Week-3 PB-02 proposal) and sinkhole the queried .lat domains. |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-MAL-003:eradication:2-add-sha256-sha256-to-the |
| SIEM-WEB-004 | S2 | T1 | Fix output encoding / input validation for the parameter used on /index.php; add a Content-Security-Policy header. |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-004:eradication:1-fix-output-encoding-inpu |
| SIEM-EXCH-005 | S9 | T1 | Only after verification: remove the export requests and any created .aspx files on win-dc-exch01.attackrange.local (Week-3 lists automatic deletion as prohibited). |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-EXCH-005:eradication:3-only-after-verification- |
| LT-03 | S4 | T1 | Terminate the bash process tree (ProcessGuid {ec227f46-1086-665a-0dcf-bdc908560000}) and check root persistence (cron, shell rc files, authorized_keys). |  | approved (Youssef Sherif, rule suggestion accepted) | LT-03:eradication:2-terminate-the-bash-proce |
| NT-02 | S8 | T0 | Decode the 250 chunk labels (chunkNNN-hex.lab.test) to determine whether they carry data. | [data] 250 distinct chunk labels; hex parts decode to 3000 bytes, of which 38% are printable ASCII. The decoded bytes are not readable text (consistent with encoded/encrypted or random content); payload meaning remains undetermined. | done (Youssef Sherif, rule suggestion accepted) | NT-02:eradication:2-decode-the-burst-count-c |
| NT-03 | S8 | T0 | Attribute the 24 connections on 192.168.1.199 to a process (endpoint telemetry is not in the dataset). | [not in repo] No endpoint telemetry for 192.168.1.199 in the dataset. | deferred (Youssef Sherif, rule suggestion accepted) | NT-03:eradication:2-attribute-the-connection |
| RT-01 | S8 | T1 | Remove C:\Users\IEUser\Desktop\plink.exe from PC01.example.corp and review saved PuTTY/plink sessions. |  | approved (Youssef Sherif, rule suggestion accepted) | RT-01:eradication:2-remove-tool-path-from-ho |
| RT-04 | S5 | T1 | Restore HKU\S-1-5-21-3583694148-1414552638-2922671848-1000\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell to explorer.exe only and delete C:\Users\IEUser\AppData\Roaming\9QxTsAU9w8gyPj4w\BRE6BgE2JubB.exe. |  | approved (Shahinda Gamal, rule suggestion accepted) | RT-04:eradication:2-restore-registry-key-to- |
| RT-04 | S5 | T1 | Collect and hash C:\Users\IEUser\Downloads\a.exe before deletion for malware analysis. |  | approved (Shahinda Gamal, rule suggestion accepted) | RT-04:eradication:3-collect-and-hash-dropper |

## Recovery

| Case | Stage | Tier | Action | Automated read-only check (T0) | Decision | Item ID |
|---|---|---|---|---|---|---|
| SIEM-WEB-001 | S2 | T0 | Re-baseline the high-rate threshold (80 req/min) against normal traffic for /3.php and similar paths. | [not in repo] Needs a baseline of normal web traffic; only the alert group evidence is in the repository. | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-001:recovery:2-re-baseline-the-high-rat |
| SIEM-AUTH-002 | S3 | T0 | Search the full OpenSSH_2k.log for 'Accepted password' from 183.62.140.253; reset root credentials only if a success is found. | [data] 2000 log lines searched; 867 lines mention 183.62.140.253; 'Accepted' logins from 183.62.140.253: 0; 'Accepted' logins for root: 0. The whole file contains 1 'Accepted' line(s), from other sources. | done (Mohammed Walid, rule suggestion accepted) | SIEM-AUTH-002:recovery:2-search-the-full-dataset- |
| SIEM-MAL-003 | S4 | T1 | Re-image the affected host if the hash verdict is malicious; monitor for connections to 104.80.2.104:443. |  | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-MAL-003:recovery:3-re-image-the-affected-ho |
| SIEM-WEB-004 | S2 | T0 | Re-test /index.php with the 3 recorded payloads after the fix; confirm the WAF rule review outcome. | [not in repo] Needs the fixed web application to re-test; the lab application is not part of the repository. | deferred (Mohammed Walid, rule suggestion accepted) | SIEM-WEB-004:recovery:2-re-test-request-path-wit |
| SIEM-EXCH-005 | S9 | T1 | Review Exchange RBAC: remove the Mailbox Import Export role assignment made to Administrator@attackrange.local (2 assignments logged) unless it is approved. |  | approved (Mohammed Walid, rule suggestion accepted) | SIEM-EXCH-005:recovery:4-review-exchange-rbac-rem |
| SIEM-EXCH-005 | S9 | T1 | Reset Administrator@attackrange.local credentials if misuse of the account is confirmed. |  | deferred (Youssef Sherif, rule suggestion accepted) | SIEM-EXCH-005:recovery:5-reset-mailbox-credential |
| LT-01 | S3 | T0 | Confirm no successful login exists for the targeted accounts (dff, root, zhangyan) on LabSZ. | [data] 2000 log lines searched; 867 lines mention 183.62.140.253; 'Accepted' logins from 183.62.140.253: 0; 'Accepted' logins for dff, root, zhangyan: 0. The whole file contains 1 'Accepted' line(s), from other sources. | done (Youssef Sherif, rule suggestion accepted) | LT-01:recovery:2-confirm-no-successful-lo |
| LT-03 | S4 | T0 | Confirm whether the connection to 10.0.255.12:4444 succeeded (network_outcome is unknown in the evidence). | [data] Original Sysmon-for-Linux file has 2 event(s), Event IDs ['1']; no Event ID 3 (network connection) record exists, so connection success cannot be established from this dataset. | done (Youssef Sherif, rule suggestion accepted) | LT-03:recovery:3-confirm-whether-the-conn |
| NT-01 | S1 | T0 | Review which of the 65535 probed ports on 192.168.16.130 are open and close unneeded services. | [data] Zeek conn_state for 192.168.16.132 -> 192.168.16.130: REJ (closed) on 65524 ports; S0 (no reply) on 112 ports; handshake completed (RSTO/SF) on 11 ports: 22, 135, 139, 445, 5040, 49664, 49665, 49666, 49667, 49668, 49669. These are the candidate open services to review. | done (Youssef Sherif, rule suggestion accepted) | NT-01:recovery:3-review-which-of-the-dist |
| RT-02 | S6 | T1 | Forward Security logs from WIN-77LTAPHIQ1R.example.corp to the SIEM so a future log clear cannot remove the only copy. |  | approved (Youssef Sherif, rule suggestion accepted) | RT-02:recovery:3-forward-security-logs-fr |
| RT-03 | S7 | T0 | Identify the remote client and account behind winrshost.exe on DC1.insecurebank.local from authentication logs. | [data] winrshost.exe ran as insecurebank\Administrator (LogonId 0x12fe05, IntegrityLevel High). The remote client address is not in the dataset (no Security 4624 record for that LogonId). | done (Shahinda Gamal, rule suggestion accepted) | RT-03:recovery:2-identify-the-remote-clie |
| RT-04 | S5 | T0 | Verify the next logon on IEWIN7 starts only userinit.exe -> explorer.exe (no payload child process). | [not in repo] Requires a logon after eradication; the dataset ends before that. | deferred (Shahinda Gamal, rule suggestion accepted) | RT-04:recovery:4-verify-the-next-logon-on |

## Prohibited automation (Week-3 Tier 2)

| Case | Action | Reason | Tickets |
|---|---|---|---|
| SIEM-WEB-001 | execute_rate_limit | HTTP correlation gap (Week-2 acceptance gate 2) — cannot block source safely | 469dc3deb13a |
| SIEM-WEB-001 | execute_isolation | Tier 2 prohibited | 469dc3deb13a |
| SIEM-WEB-001 | disable_account | Week-2 reports prohibit automatic account action | 469dc3deb13a |
| SIEM-AUTH-002 | lock_account | Successful login not established (Week-2 SSH report §5) | a823d14b61f0 |
| SIEM-AUTH-002 | execute_rate_limit | Tier 2 prohibited; requires recorded analyst decision | a823d14b61f0 |
| SIEM-AUTH-002 | isolate_host | No host evidence in this alert type | a823d14b61f0 |
| SIEM-MAL-003 | execute_isolation | Tier 2 prohibited; requires recorded analyst decision | e05ccfe875e6 |
| SIEM-MAL-003 | execute_rate_limit | Tier 2 prohibited | e05ccfe875e6 |
| SIEM-MAL-003 | disable_account | Week-2 reports prohibit automatic account action | e05ccfe875e6 |
| SIEM-WEB-004 | execute_rate_limit | HTTP correlation gap (Week-2 acceptance gate 2) — cannot block source safely | 6ba5792eef66, 843425fa737b, fad10ea2b71b |
| SIEM-WEB-004 | execute_isolation | Tier 2 prohibited | 6ba5792eef66, 843425fa737b, fad10ea2b71b |
| SIEM-WEB-004 | disable_account | Week-2 reports prohibit automatic account action | 6ba5792eef66, 843425fa737b, fad10ea2b71b |
| SIEM-EXCH-005 | propose_export_revocation | Exchange receiver hard-codes qa_status=REVIEW_REQUIRED; no proposed response actions permitted | 21c4515e439a |
| SIEM-EXCH-005 | execute_isolation | Tier 2 prohibited | 21c4515e439a |
| SIEM-EXCH-005 | disable_account | Exchange report §11: 'Do not automatically isolate hosts or disable accounts' | 21c4515e439a |
| SIEM-EXCH-005 | delete_export_request | Evidence unverified; no filesystem/IIS proof of completion | 21c4515e439a |
| SIEM-EXCH-005 | execute_rate_limit | Tier 2 prohibited | 21c4515e439a |
## Human sign-off

| Role | Name | Decision (Approved / Corrected / Rejected) | Date | Signature |
|---|---|---|---|---|
| SOC analyst |  |  |  |  |
| IR lead |  |  |  |  |
| Project supervisor |  |  |  |  |
