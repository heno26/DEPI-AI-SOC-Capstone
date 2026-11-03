# BT-03 — Windows service state transitions

**Scope:** Windows baseline *candidate*, not ground-truth-confirmed benign behavior.  
**Model:** local Mistral 7B Instruct.  
**Post-fix analysis:** `AN-20261018-160932-6d1c`.  
**Analyst review:** **Corrected**.  
**Saved validator flags:** 2 (review requests, not proven incidents).

## Evidence sources and verification

- `BT-03-focused.json`: 6 selected Windows events.
- `BT-03-evidence-mapping.csv`: verified evidence references, record IDs, hosts and timestamps against focused JSON (<1 ms).
- `BT-03-source-manifest.json`: verified SHA-256 of focused JSON, original EVTX sources and original archive (when recorded).
- The manifest and event mapping provide provenance, but this script **does not independently reparse each source EVTX event**.
- Original AI output, review, project source code and evidence were not modified.

## Selected evidence timeline (UTC)

| Timestamp | Event ID | Source Record ID | Evidence Ref | Observed event |
|---|---:|---:|---|---|
| `2022-04-04T14:09:49.5384871Z` | 7036 | 1858 | E001 | Windows Biometric Service → stopped |
| `2022-04-04T14:11:00.1552809Z` | 7036 | 1860 | E002 | Background Intelligent Transfer Service → stopped |
| `2022-04-04T14:11:28.7125046Z` | 7036 | 1861 | E003 | Microsoft Passport → stopped |
| `2022-04-04T14:11:47.8527230Z` | 7036 | 1862 | E004 | Software Protection → running |
| `2022-04-04T14:12:18.3477921Z` | 7036 | 1863 | E005 | Software Protection → stopped |
| `2022-04-04T14:13:44.1240769Z` | 7036 | 1864 | E006 | AppX Deployment Service (AppXSVC) → stopped |

## Evidence-supported findings

- Six System Event ID 7036 records describe service state transitions.
- Software Protection is observed **running once and stopped once** in this selected window.
- Windows Biometric Service, BITS, Microsoft Passport and AppX Deployment Service have recorded **stop** events; no start event is present for those services in this selection.

**Interpretation boundary:** The selection is consistent with ordinary service state changes; intent, authorization, and full lifecycle are not proven by this small window.

## AI quality and validation

- **Incorrect or unsupported claims:** The post-fix report generalized single transitions to repeated start/stop cycles and speculated about malicious concealment without independent support.
- **Validator results and analyst adjudication:** Both low service_start_stop_overgeneralization flags were confirmed by the analyst for the unsupported repetition claims; conditional hypotheses alone are not fabricated events.
- **Missing information:** Surrounding service history, SCM process/actor evidence, approved maintenance context and security correlation.
- **Final analyst disposition:** Corrected (approval of a corrected report does not prove the events benign).

## False-positive assessment limitations

The sample is intentionally small and hand-selected, without independently established ground-truth benign labels. It can demonstrate specific false-positive *risks* and unsupported model inferences, **not an operational false-positive rate** or general detection accuracy.
