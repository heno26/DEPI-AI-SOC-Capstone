# BT-02 — SYSTEM service logons / special privileges

**Scope:** Windows baseline *candidate*, not ground-truth-confirmed benign behavior.  
**Model:** local Mistral 7B Instruct.  
**Post-fix analysis:** `AN-20261018-160835-f96a`.  
**Analyst review:** **Corrected**.  
**Saved validator flags:** 1 (review requests, not proven incidents).

## Evidence sources and verification

- `BT-02-focused.json`: 4 selected Windows events.
- `BT-02-evidence-mapping.csv`: verified evidence references, record IDs, hosts and timestamps against focused JSON (<1 ms).
- `BT-02-source-manifest.json`: verified SHA-256 of focused JSON, original EVTX sources and original archive (when recorded).
- The manifest and event mapping provide provenance, but this script **does not independently reparse each source EVTX event**.
- Original AI output, review, project source code and evidence were not modified.

## Selected evidence timeline (UTC)

| Timestamp | Event ID | Source Record ID | Evidence Ref | Observed event |
|---|---:|---:|---|---|
| `2022-04-04T14:06:06.7223244Z` | 4624 | 33788 | E001 | Logon Type 5 for SYSTEM |
| `2022-04-04T14:06:06.7223631Z` | 4672 | 33790 | E002 | Special privileges assigned to SYSTEM |
| `2022-04-04T14:06:11.2761279Z` | 4624 | 33813 | E003 | Logon Type 5 for SYSTEM |
| `2022-04-04T14:06:11.2761733Z` | 4672 | 33815 | E004 | Special privileges assigned to SYSTEM |

## Evidence-supported findings

- Two Security Event ID 4624 records are **Logon Type 5 (service)** for `SYSTEM`.
- Two Event ID 4672 records enumerate special privileges for `SYSTEM`, including `SeDebugPrivilege`.
- The selected records share logon identifier `0x3e7`, which provides context, not proof of abuse.

**Interpretation boundary:** Service logons and privileges are compatible with routine SYSTEM service execution. Abnormality or unauthorized use is not established by these records.

## AI quality and validation

- **Incorrect or unsupported claims:** The new analysis correctly identifies service logons, but calls SYSTEM privilege assignment unusual without a historical baseline.
- **Validator results and analyst adjudication:** One medium finding_without_evidence_ref flag was reviewed as Needs Follow-up; the unsupported abnormality assessment remains unverified.
- **Missing information:** Service identity, detailed authorization context, long-term baseline, and evidence of actual privileged misuse.
- **Final analyst disposition:** Corrected (approval of a corrected report does not prove the events benign).

## False-positive assessment limitations

The sample is intentionally small and hand-selected, without independently established ground-truth benign labels. It can demonstrate specific false-positive *risks* and unsupported model inferences, **not an operational false-positive rate** or general detection accuracy.
