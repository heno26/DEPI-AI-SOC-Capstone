# RT-01 — SSH Remote Port Forwarding Analysis

## 1. Test Information
- Test ID: RT-01
- Category: Command and Control / Remote Access Investigation
- Dataset: Recorded Windows Sysmon EVTX (lab attack sample)
- Original Events: 73
- Selected Events: 4
- Model: mistral:7b-instruct-v0.3-q4_K_S
- Analysis ID: AN-20261017-222659-f35b
- Human Review Status: Corrected

## 2. Objective
Evaluate the local AI SOC analyst's ability to interpret recorded
Sysmon telemetry, correlate evidence, identify suspicious behavior,
and distinguish observed facts from unsupported conclusions.

This is a focused analytical test, not an automatic detection test
across all 73 events.

## 3. Observed Evidence
- E001 (Original E003): plink.exe process creation with SSH
  remote port forwarding configuration using the -R option.
- E002 (Original E004): Network connection from 10.0.2.17
  to 10.0.2.18:80.
- E003 (Original E005): Local connection to 127.0.0.2:3389.
- E004 (Original E023): Additional local connection
  to 127.0.0.2:3389.

Evidence mapping is preserved in RT-01-C2-evidence-mapping.csv.

## 4. AI Analysis
Mistral identified:
- plink.exe execution.
- SSH remote port forwarding indicators.
- Network activity involving ports 80 and 3389.
- Possible remote access or C2-related behavior.

The model did not establish malicious intent.

## 5. Human Analyst Findings
The AI output contained unsupported assertions, including:
- Successful tunnel establishment without sufficient proof.
- Identification of the destination as PC02 without verified mapping.
- Interpretation of TCP port 80 as confirmed HTTP traffic.
- Description of configured port 4444 as an established connection.

The evidence supports suspicious remote forwarding activity.
It does not conclusively establish successful C2 communication,
successful RDP access, or data exfiltration.

## 6. Automated Validation — Before Fix
Total Flags: 6
- F001-F002: Missing evidence references (Medium).
- F003-F006: Timestamp precision mismatches (High).

Human Decisions:
- Needs Follow-up: 2
- False Alarms: 4

## 7. Timestamp Validation Improvement
Root Cause:
The original validator used exact string matching for timestamps.

Implemented Improvement:
Datetime-aware comparison with sub-millisecond tolerance,
while preserving evidence reference checks.

Targeted Test Results:
- 4 rounded timestamps accepted.
- Incorrect timestamp detected.
- Wrong evidence reference detected.

Full Regression Results:
- 49 tests executed.
- 49 tests passed.
- 0 failures.

The original analysis and review records remain unchanged.

## 8. Final Assessment
Test Result: Successful with analyst corrections.

The pipeline successfully processed recorded Windows Sysmon
telemetry using a local language model and human validation.

Limitations:
- Only four manually selected events were analyzed.
- Successful tunnel establishment was not independently confirmed.
- Malicious C2 activity was not conclusively established.
- Broader automatic detection capability remains untested.

## 9. Workflow
EVTX -> JSON -> Parser -> Mistral -> Automated Validation
-> Human Analyst Review -> Validator Improvement -> Regression Tests

## 10. Next Steps
- Persist targeted timestamp tests in the regression suite.
- Evaluate additional recorded attack categories.
- Test benign Windows datasets for false-positive behavior.
- Evaluate full-dataset analysis and automatic threat discovery.
