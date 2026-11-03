# DEPI-P5 | Week 2 | Exchange 005
## Final SOC Incident Analysis Report - Analyst Review Draft

**Report generated (UTC):** 2026-11-02T18:46:36.906959+00:00
**Event ID:** `21c4515e439a0b3b6a3f`
**Detection rule:** `SIEM_EXCHANGE_005_SUSPICIOUS_MAILBOX_EXPORT`
**SIEM stream:** `depi_exchange_events`
**Analysis model:** `mistral:7b-instruct-v0.3-q4_K_S`
**Classification:** Suspicious Exchange mailbox export activity
**Severity:** HIGH (provisional)
**Confidence:** MEDIUM
**Disposition:** Investigation required; compromise not confirmed
**QA:** REVIEW_REQUIRED
**Human validation:** REQUIRED - pending analyst approval

## 1. Executive Summary

An authenticated OpenObserve alert was correlated against two distinct Microsoft Exchange New-MailboxExportRequest command records from a historical lab dataset. Both records reference the Administrator mailbox and specify ASPX destination paths under the Exchange OWA auth directory. These paths warrant investigation for possible web-shell staging. The available logs do not independently establish completed mailbox exports, files created on disk, web-shell execution, unauthorized access, or data exfiltration.

## 2. Detection and Pipeline

OpenObserve scheduled alert -> authenticated webhook -> Python receiver -> exact evidence correlation -> event deduplication -> local Mistral AI triage -> saved JSON -> analyst semantic review.

- Alert rows received: **2**
- Matched SIEM replay rows: **2**
- Unique correlated events: **2**
- Duplicates within this notification: **0**
- Dataset mode: **Historical lab replay**

## 3. Verified Evidence Timeline

| Record | Original source time | SIEM replay time (UTC) | Host | Command |
|---|---|---|---|---|
| 1789 | 2022-11-21T17:22:01 | 2026-11-02T11:34:59.191000+00:00 | win-dc-exch01.attackrange.local | New-MailboxExportRequest |
| 1892 | 2022-11-21T20:03:51 | 2026-11-02T14:16:49.191000+00:00 | win-dc-exch01.attackrange.local | New-MailboxExportRequest |

### Evidence details

- Mailbox referenced: `Administrator@attackrange.local`.
- Included folder: `#Drafts#`.
- Both commands include subject filters and ExcludeDumpster=True.
- Both specify `.aspx` destinations beneath the Exchange OWA auth directory.
- Source log wording reports `Cmdlet suceeded`; this is not independent proof of file creation.

### Original evidence (verbatim)

**Record 1789**

```text
Cmdlet suceeded. Cmdlet New-MailboxExportRequest, parameters -Name "OnmrPW8m8Uv" -Mailbox "Administrator@attackrange.local" -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq 'AvcMRhPdI')" -ExcludeDumpster "True" -FilePath "\\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\ZnTQs2wv.aspx".
```

**Record 1892**

```text
Cmdlet suceeded. Cmdlet New-MailboxExportRequest, parameters -Name "dYbLTCleBT" -Mailbox "Administrator@attackrange.local" -IncludeFolders ("#Drafts#") -ContentFilter "(Subject -eq 'Fay10dOWecFg')" -ExcludeDumpster "True" -FilePath "\\win-dc-exch01.attackrange.local\C$\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\43yYO1sP.aspx".
```

## 4. Confirmed Observations

- Two distinct New-MailboxExportRequest command records are present in the verified SIEM evidence.
- Both records identify the Exchange host win-dc-exch01.attackrange.local.
- Both commands reference the Administrator@attackrange.local mailbox and the Drafts folder.
- Both command lines specify ASPX destination paths under the Exchange OWA auth directory.
- The original event timestamps are from 2022-11-21; SIEM replay timestamps are from 2026.
- The source messages report cmdlet success; export completion is not independently established.

## 5. Suspicious Indicators and Threat Assessment

- Administrative mailbox targeted by mailbox export commands.
- Repeated export requests with separate original timestamps.
- Destination filenames use the ASPX extension under an Exchange web directory.
- Possible web-shell staging is a hypothesis, not an observed deployment.
- Unauthorized activity and exfiltration remain unverified.

**Severity rationale:** HIGH is a provisional investigative priority based on the Exchange export commands, administrative mailbox, and ASPX destinations.

**Confidence rationale:** MEDIUM reflects strong evidence for the logged commands but missing corroboration for impact or compromise.

## 6. Unverified Hypotheses

- The export requests were unauthorized.
- The ASPX destination paths were intended for web-shell staging.
- The requested export operations resulted in actual files on disk.
- Any web shell was deployed, accessed, or executed.
- Any mailbox data was successfully exfiltrated.

## 7. Missing Evidence

- Exchange export-request status and completion records.
- Filesystem metadata and file hashes for the specified ASPX paths.
- IIS logs proving or disproving HTTP access to those paths.
- Account authorization, authentication, and administrative audit context.
- Network and endpoint telemetry supporting or refuting exfiltration.

## 8. AI Triage Evaluation

- Model: `mistral:7b-instruct-v0.3-q4_K_S`.
- Original QA status: `REVIEW_REQUIRED`.
- Original semantic warnings: **0**.
- AI output retained unchanged in the original evidence JSON.
- Human review identified the following semantic issues:

  1. The original AI summary suggests possible unauthorized data exfiltration; no unauthorized access or exfiltration is confirmed.
  2. The AI omitted the key indicator: ASPX export destinations within the Exchange OWA web directory.
  3. The source log reports cmdlet success, but actual export completion and file creation are not independently verified.
  4. The AI incorrectly categorized the original-versus-replay timestamp distinction as an unverified hypothesis.
  5. The AI repeated missing-evidence items under unverified hypotheses instead of separating hypotheses from verification requirements.
  6. The original semantic_warnings array was empty despite these review findings.

## 9. Recommended SOC Investigation

1. Confirm whether the export requests were authorized and identify the initiating account.
2. Review Exchange administrative audit logs and related RBAC role assignments.
3. Inspect the specified OWA auth paths for file existence, metadata, and hashes.
4. Review IIS access logs for requests to the specified ASPX filenames.
5. Correlate host, process, authentication, and network telemetry around the original event times.
6. Determine whether export jobs completed and whether any mailbox data left the environment.
7. Escalate for incident-response containment only if corroborating evidence justifies it.

## 10. Limitations and Human Validation

- Historical lab data replayed into OpenObserve; not a live production compromise.
- No independent filesystem or IIS execution evidence is supplied.
- The verified event count describes the correlated alert rows, not all possible historical activity.
- This document is a prepared analyst-review draft, not a signed human approval.

## 11. SOC Disposition

**SUSPICIOUS ACTIVITY - INVESTIGATION REQUIRED.**

No confirmed compromise, web-shell execution, or data exfiltration can be concluded from the available evidence. Do not automatically isolate hosts or disable accounts on this evidence alone.

**Analyst approval:** PENDING HUMAN APPROVAL.

## 12. Evidence Integrity and Traceability

- Original report: `SIEM_EXCHANGE_005_21c4515e439a0b3b6a3f_AI_Triage.json`
- Original report SHA-256: `c1a8ccc7d28eeb8d760afdcdda9ccb4d615e4da32818158d033e8e422c75dbad`
- Event ID: `21c4515e439a0b3b6a3f`
- Original AI output was not modified.
- Review findings are stored separately.
