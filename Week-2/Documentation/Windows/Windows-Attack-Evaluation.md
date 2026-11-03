# Windows Attack Evaluation — RT-01 through RT-04

**Scope:** Four focused recorded-lab Windows cases. This is a qualitative case-study review, not a population-level detection-rate experiment.

| Test | Focus | Verified timeline rows | Human-review status |
|---|---|---:|---|
| RT-01 | RT-01-C2 | 4 | Corrected |
| RT-02 | RT-02-Discovery | 4 | Approved |
| RT-03 | RT-03-Lateral-Movement | 3 | Corrected |
| RT-04 | RT-04-Persistence | 7 | Corrected |

## Evidence-supported observations

- **RT-01:** Plink process and network connection telemetry; configuration and observed connections do not by themselves prove fully established remote access or malicious intent.
- **RT-02:** Security Event ID 1102 records audit-log clearing, followed by IPC$ named-pipe access checks (Event ID 5145); success, authorization and causal linkage remain unproven.
- **RT-03:** WinRM-related winrshost.exe → cmd.exe → ipconfig.exe process chain; alone it does not establish attacker lateral movement.
- **RT-04:** Executable creation, Winlogon Shell registry modification and subsequent payload execution support a persistence mechanism, not independently malware attribution.

## Method and limitations

- Reviewed reports and source-linked timelines are preserved as separate case artifacts.
- AI hallucinations and uncertainty were addressed via analyst review and semantic validation enhancements.
- A reviewed security finding is not an independent proof of unauthorized activity, attack success or attacker identity.
- Four selected cases cannot support a generalized true-positive rate.
