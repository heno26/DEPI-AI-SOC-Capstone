# Deliverable 3 - Detection Improvement Notes

**Status: DRAFT - PENDING LOCAL EXECUTION for the AI-generated part. Analyst validation required for everything.**
No Wazuh rule is modified, created or deployed by this project in Week 2. These are conceptual notes only.

## How this document is built (honest provenance)
| Part | Author | Status |
|---|---|---|
| **Part A - Baseline notes (below)** | Drafted by the project assistant from the *synthetic* fixtures in `Data/` and from Week 1 review findings. **Not AI-model output.** | DRAFT - student must verify each note against the cited evidence and sign off |
| **Part B - AI-generated notes** | Local Mistral 7B via `python app.py detect <file>` | **PENDING LOCAL EXECUTION.** After you run it and review it, `python app.py export` writes `Detection-Improvement-Notes.generated.md` (shows each note with its review status). |

Evidence references use `[fixture file : E###]` (event numbers shown in the application and in each `report.md`). All fixtures are **synthetic**; no claim is made about any real Wazuh rule. Wazuh rule IDs are deliberately not named.

## Part A - Baseline detection improvement notes (human-drafted, unverified)

### D1 - Correlate failed logons by source and by number of distinct accounts
- **Observed detection gap:** Individual failed logons (EventID 4625 / sshd "Failed password") look unremarkable one by one. The pattern (one source, many accounts, seconds apart) only appears when events are grouped.
- **Supporting evidence:** `Windows/SYNTHETIC_TC-02... : E001-E006` (six 4625 events, same SourceIP, six different accounts, about 15 s). `Linux/SYNTHETIC_TC-01... : E001-E007` (seven failures, same IP, several user names).
- **Suggested improvement:** Add a correlation condition: N failures from one source within a short window **and** M distinct target accounts => "possible password spraying / brute force", separate from a simple per-account lockout alert.
- **Expected benefit:** Surfaces spraying that stays below per-account thresholds.
- **Potential false-positive risk:** Shared NAT/proxy addresses, misconfigured services retrying with stale credentials, vulnerability scanners (see D5). Thresholds need tuning on real baseline data.
- **Human review requirement:** Required. Analyst validates thresholds; nothing is deployed.

### D2 - Link a successful logon that follows a failure burst from the same source
- **Observed detection gap:** The most important fact (a success after many failures) is a different event type from the failures and is not tied to them.
- **Supporting evidence:** `TC-02 : E007` (4624 for svc_backup from the same source after E001-E006); `TC-01 : E008` (Accepted password for deploy from the failing IP).
- **Suggested improvement:** Raise priority when a success for any targeted account occurs from the same source within a defined period after a failure burst.
- **Expected benefit:** Highlights likely account takeover instead of leaving it as a low-level login event.
- **Potential false-positive risk:** A legitimate user who mistyped a password repeatedly then succeeded; check the number of *distinct* accounts to separate this case.
- **Human review requirement:** Required.

### D3 - Account adds itself to a privileged group soon after logging on
- **Observed detection gap:** A group-membership change (4732) is evaluated alone, without the actor's recent logon history.
- **Supporting evidence:** `TC-02 : E008` (svc_backup added to Administrators, ChangedBy=svc_backup, after E007). `Windows/SYNTHETIC_W2-01... : E005` (dev1 added to Administrators by dev1).
- **Suggested improvement:** Flag privileged-group additions where the actor equals the added member, or where the actor logged on recently from an unusual source.
- **Expected benefit:** Early privilege-escalation signal.
- **Potential false-positive risk:** Break-glass or installer workflows that elevate their own service account; allow-list only with an approved change record.
- **Human review requirement:** Required.

### D4 - Office application spawning encoded PowerShell followed by outbound traffic
- **Observed detection gap:** Context such as "finance workstation, no approved scripts from Office" is in the asset note, not in the detection logic.
- **Supporting evidence:** `Generic/SYNTHETIC_TC-03... : E001` (WINWORD.EXE -> powershell.exe -nop -w hidden -enc, outbound TCP 443 five seconds later).
- **Suggested improvement:** Combine parent-process (Office), PowerShell flags (hidden window, encoded command) and a near-time outbound connection into one higher-priority detection; include asset criticality in priority.
- **Expected benefit:** Fewer missed true positives; consistent P1/P2 handling.
- **Potential false-positive risk:** Legitimate Office macros/add-ins in some departments; requires an asset/department allow-list with owner approval.
- **Human review requirement:** Required.

### D5 - Suppress or down-rank alerts from a registered scanner inside its approved window
- **Observed detection gap:** The port-scan alert fired although the source is the registered scanner within its change-calendar window.
- **Supporting evidence:** `Generic/SYNTHETIC_TC-04... : E001` (nessus-scan01, window Tuesday 01:00-04:00, alert 01:35).
- **Suggested improvement:** Enrich alerts with asset inventory and change calendar; down-rank (do not delete) when both match. Keep a separate alert when the scanner is active **outside** its window or targets networks not in scope.
- **Expected benefit:** Reduces analyst workload from expected activity.
- **Potential false-positive risk (i.e. risk of missing a real attack):** An attacker spoofing or abusing the scanner address; keep logging and alert on out-of-window or out-of-scope use.
- **Human review requirement:** Required.

### D6 - Compare privileged remote logons with the access-policy time window
- **Observed detection gap:** The logons came from an approved jump host to permitted servers, but outside the allowed window with no exception recorded; a reader can easily treat "approved host" as "approved activity".
- **Supporting evidence:** `Windows/SYNTHETIC_TC-12... : E001, E003` (LogonType 10 at 02:10:10 and 02:13:22), `E002, E004` (4672 with SeDebugPrivilege), `E006` (standard_window=09:00-17:00, change_exception=NotProvided).
- **Suggested improvement:** Add a check that compares logon time with the account's permitted window and the presence of an approved exception; label the result "approved source, outside window, exception missing" rather than benign or malicious.
- **Expected benefit:** Clear "needs verification" outcome instead of silent clearance.
- **Potential false-positive risk:** Legitimate on-call work; requires a quick way to attach exceptions.
- **Human review requirement:** Required.

### D7 - Console login without MFA followed by privilege and credential changes
- **Observed detection gap:** Each CloudTrail-style event (login, group change, key creation) is individually routine; the sequence is high risk.
- **Supporting evidence:** `Generic/SYNTHETIC_TC-11... : E001` (MFAUsed=No), `E002` (AddUserToGroup SecurityAdmins), `E003` (CreateAccessKey), `E005` (no change ticket, owner or known source).
- **Suggested improvement:** Correlate no-MFA login + privileged-group change + access-key creation by the same user within a short window; require change-ticket context in the alert.
- **Expected benefit:** Early detection of cloud account misuse; avoids Week 1's observed "routine admin work" misjudgement.
- **Potential false-positive risk:** Planned onboarding by administrators; mitigated by checking change tickets.
- **Human review requirement:** Required.

### D8 - Repeated unique-subdomain TXT queries; repeated blocked web attacks
- **Observed detection gap:** Short bursts of TXT queries to many unique, random-looking subdomains and repeated blocked injection attempts are low-level individually.
- **Supporting evidence:** `Network/SYNTHETIC_TC-10... : E001-E007` (six TXT queries to unique subdomains of one parent in 12 s). `Network/SYNTHETIC_TC-08... : E001, E003, E006` (two SQLi-pattern requests blocked, 403).
- **Suggested improvement:** Track unique-subdomain count and TXT share per client and parent domain over a window (investigation lead, not an incident). For blocked web attacks, raise priority only if the same source also has *allowed* requests or later successes.
- **Expected benefit:** Possible tunnelling and probing become visible while avoiding "confirmed breach" wording for stopped attempts.
- **Potential false-positive risk:** CDN/telemetry/anti-virus domains use similar naming; baseline needed. Six queries do not prove tunnelling.
- **Human review requirement:** Required.

## Part B - AI-generated detection notes
**PENDING LOCAL EXECUTION.** Run `python app.py detect Data\Windows\SYNTHETIC_TC-02_windows_password_spray_admin_group.log`, review the output, then `python app.py export`.
