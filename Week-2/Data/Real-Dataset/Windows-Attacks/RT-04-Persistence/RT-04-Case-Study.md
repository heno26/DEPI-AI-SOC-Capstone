# RT-04 — Winlogon Shell Persistence | Final Case Study

> Recorded laboratory telemetry. Source-derived evidence is authoritative; AI analysis is reviewed, not treated as proof.

## Case information
- Original EVTX: `sysmon_13_1_persistence_via_winlogon_shell.evtx` (25 recorded Sysmon events).
- Original EVTX SHA-256: `78592aa982a478d1a65f56853bdf3817a3d5c79db3b1ca64642e1a2e16064423` (matches provenance manifest).
- Original EVTX Git blob hash: `1eac3dc52de5cc5088dda0692fa11451f7eb9720` (matches provenance manifest).
- Focused input: `RT-04-focused.json` — 7 selected events; SHA-256 `bd208d8033b398d1bebe4122968b4b203af92e806863b1fd794015fff31f550c`.
- Evidence crosswalk: `RT-04-evidence-mapping.csv` (original references preserved).
- Original truncated report: `AN-20261018-014225-d45b` — 9 flags, output truncated at generation limit.
- Complete pre-patch report: `AN-20261018-015226-37b2` — 2 flags, human review Corrected.
- Post-patch report: `AN-20261018-022126-c65b` — 1 flag, human review Corrected.
- Local model: `mistral:7b-instruct-v0.3-q4_K_S`.

## Verified evidence timeline (NOT the generated AI timeline)
| Original UTC timestamp | Model evidence | Original evidence | Sysmon ID | Observed record |
|---|---|---|---:|---|
| `2019-06-14T22:22:17.9883707Z` | `E001` | `E001` | 1 | a.exe process creation |
| `2019-06-14T22:22:21.5039957Z` | `E002` | `E002` | 11 | BRE6BgE2JubB.exe file creation |
| `2019-06-14T22:22:21.5352457Z` | `E003` | `E003` | 13 | Winlogon\Shell registry value set |
| `2019-06-14T22:23:13.8946207Z` | `E004` | `E017` | 1 | userinit.exe process creation |
| `2019-06-14T22:23:13.9571207Z` | `E005` | `E018` | 1 | BRE6BgE2JubB.exe started by userinit.exe |
| `2019-06-14T22:23:13.9727457Z` | `E006` | `E019` | 1 | explorer.exe started by userinit.exe |
| `2019-06-14T22:23:16.5928629Z` | `E007` | `E021` | 1 | additional BRE6BgE2JubB.exe process creation |

## Process relationship verification
- E004 -> E005: GUID MATCH
- E004 -> E006: GUID MATCH
- E005 -> E007: GUID MATCH

## Evidence-backed security interpretation
- [E001] Sysmon ID 1 documents execution of `a.exe` from a local `Downloads` path, not where it came from.
- [E002] Sysmon ID 11 documents creation of the executable subsequently configured in `Winlogon\Shell`.
- [E003] Sysmon ID 13 documents modification of the user-level Winlogon Shell registry value, including the created executable and `explorer.exe`.
- [E004–E006] The later logon sequence includes `userinit.exe`, the configured payload, and `explorer.exe`.
- [E007] A further process creation for the payload was observed; this does not alone establish a separate logon session.
- **Supported finding:** the observed sequence is consistent with activation of Winlogon Shell persistence during a later logon.
- **Unverified:** malicious intent, confirmed malware identity, download origin, repeated persistence across several reboots, and distinct user sessions.

## AI performance, validator improvement, and regression
- First analysis: 9 flags and incomplete/truncated output with 1500-token generation limit.
- Complete pre-patch analysis: 2 flags after using `--num-ctx 8192 --num-predict 3000`.
- Deterministic post-patch replay of that saved pre-patch report: 10 flags (not necessarily 10 unique semantic errors).
- Post-patch live analysis: 1 medium flag for unsupported inference that `a.exe` had been downloaded.
- Previous 1 high-severity timeline mismatch was absent in the post-patch output; all seven source timestamps remain available in the canonical timeline.
- Semantic patch: 92/92 unit tests passed on the analyst machine (as recorded in the terminal output).
- A reduced validation-flag count is not a guarantee of correctness; human review remains mandatory.

## Human review of post-patch report
- Analyst: Mohammed walid.
- Status: **Corrected**.
- F001 (`unsupported_download_origin`): analyst classified the unsupported download claim as a hallucination.

**Correct findings**
- Sysmon Event ID 1 confirms execution of a.exe from the Downloads directory [E001]
- Sysmon Event ID 11 records creation of BRE6BgE2JubB.exe [E002]
- Sysmon Event ID 13 records modification of the Winlogon Shell registry value to include BRE6BgE2JubB.exe alongside explorer.exe [E003]
- A subsequent logon sequence includes userinit.exe [E004]
- BRE6BgE2JubB.exe was executed by userinit.exe [E005]
- explorer.exe was also launched by userinit.exe [E006]
- Additional execution of BRE6BgE2JubB.exe was observed [E007]
- The evidence supports execution through a Winlogon Shell persistence mechanism.

**Incorrect findings**
- Mistral claimed that a.exe was downloaded from an unspecified source, although only local process execution is established [E001]
- Mistral suggested execution across different logon sessions without verified session correlation [E005, E007]
- Malicious intent and confirmed persistence across multiple system reboots are not established by the available events.

**Missing evidence**
- Original download-source telemetry for a.exe
- File reputation and malware analysis of a.exe and BRE6BgE2JubB.exe
- Authentication and session records to determine whether executions occurred across different logon sessions
- Additional reboot and logon telemetry to establish persistence across multiple restarts
- Authorization context for the registry modification and payload execution.

**Hallucinations and unsupported statements**
- Unsupported assertion that a.exe was downloaded from an unspecified source when the evidence only confirms execution from a local Downloads directory [E001]
- Unsupported implication that the repeated executions occurred across different logon sessions without validated session identifiers [E005, E007].

**Analyst notes**
RT-04 Final Human Review by Mohammed walid. Analysis AN-20261018-022126-c65b examined seven selected events from a recorded Windows Sysmon dataset containing 25 events. The post-fix model correctly identified Winlogon Shell persistence, file creation, registry modification, and subsequent payload execution. The incident timeline contains valid timestamps matching the cited evidence. The previous semantic validation improvements passed 92 regression tests. Replaying the earlier analysis increased detected validation flags from 2 to 10, demonstrating improved detection of unsupported claims. The new analysis generated one medium-severity flag concerning unsupported download attribution. The analyst confirmed this issue and documented an additional unsupported multiple-session interpretation. The available evidence supports observed activation of a Winlogon Shell persistence mechanism but does not independently establish malicious attribution or persistence across multiple reboots. Human Review Status: Corrected.

## Final disposition
**Completed — Corrected.** The reported Winlogon Shell modification and subsequent payload execution are evidenced by the recorded events. This case does not independently prove malicious intent or persistence across multiple reboots. Stored AI output and human review are retained without editing.

## Retained evidence
- `Results/AN-20261018-014225-d45b/analysis.json`
- `Results/AN-20261018-015226-37b2/analysis.json`
- `Results/AN-20261018-022126-c65b/analysis.json`
- `RT-04-postfix-validator-replay.json`
- `RT-04-evidence-mapping.csv`
- `RT-04-Verified-Timeline.csv`
- `RT-04-Source-Manifest.json`
