# BT-01 — .NET Runtime Optimization / process creation

**Scope:** Windows baseline *candidate*, not ground-truth-confirmed benign behavior.  
**Model:** local Mistral 7B Instruct.  
**Post-fix analysis:** `AN-20261018-160709-eabf`.  
**Analyst review:** **Corrected**.  
**Saved validator flags:** 2 (review requests, not proven incidents).

## Evidence sources and verification

- `BT-01-focused.json`: 6 selected Windows events.
- `BT-01-evidence-mapping.csv`: verified evidence references, record IDs, hosts and timestamps against focused JSON (<1 ms).
- `BT-01-source-manifest.json`: verified SHA-256 of focused JSON, original EVTX sources and original archive (when recorded).
- The manifest and event mapping provide provenance, but this script **does not independently reparse each source EVTX event**.
- Original AI output, review, project source code and evidence were not modified.

## Selected evidence timeline (UTC)

| Timestamp | Event ID | Source Record ID | Evidence Ref | Observed event |
|---|---:|---:|---|---|
| `2022-04-04T14:05:42.0544347Z` | 1 | 512304 | E001 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |
| `2022-04-04T14:05:42.1749967Z` | 1 | 512366 | E002 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |
| `2022-04-04T14:05:42.4217019Z` | 1 | 512447 | E003 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |
| `2022-04-04T14:05:42.6819078Z` | 1 | 512513 | E004 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |
| `2022-04-04T14:05:44.2481373Z` | 1 | 512613 | E005 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |
| `2022-04-04T14:05:44.4604920Z` | 1 | 512678 | E006 | Process creation: C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe |

## Evidence-supported findings

- Six Sysmon Event ID 1 records establish **process creation**, not termination.
- `mscorsvw.exe` ran under `NT AUTHORITY\SYSTEM`, with `ngen.exe` as the parent process.
- The recorded image path is under `C:\Windows\Microsoft.NET\Framework\v4.0.30319`, not `C:\Windows\System32`.

**Interpretation boundary:** The activity is compatible with .NET native-image optimization, but approved/benign operation is not independently proven.

## AI quality and validation

- **Incorrect or unsupported claims:** The post-fix report twice claimed that the executable ran under System32; both path assertions contradict the Image fields.
- **Validator results and analyst adjudication:** Both medium process_image_path_mismatch flags were confirmed by the analyst. A prior report also inferred process stops from Event ID 1 alone.
- **Missing information:** Signed-binary / hash verification, process termination data, host baseline and maintenance records.
- **Final analyst disposition:** Corrected (approval of a corrected report does not prove the events benign).

## False-positive assessment limitations

The sample is intentionally small and hand-selected, without independently established ground-truth benign labels. It can demonstrate specific false-positive *risks* and unsupported model inferences, **not an operational false-positive rate** or general detection accuracy.
