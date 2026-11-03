RT-03 — Lateral Movement
Overview
This dataset supports the investigation of Windows-based lateral movement activity within an enterprise environment.

The scenario contains original Windows event log evidence, converted investigation datasets, focused evidence collections, traceability artifacts, timeline validation files, and supporting documentation intended for SOC investigations, incident response workflows, AI-assisted threat classification, and analyst validation.

Dataset Information
Field	Value
Scenario ID	RT-03
Scenario Name	Lateral Movement
Category	Windows-Attacks
Platform	Microsoft Windows
Investigation Domain	Security Monitoring and Incident Response
Repository	DEPI-AI-SOC-Capstone
File Inventory
File Name	Type	Purpose
LM_winrm_exec_sysmon_1_winrshost.evtx*	Windows Event Log	Original event log evidence used as the primary investigation source.
RT-03-Case-Study.md	Case Study Documentation	Investigation notes, scenario context, and supporting documentation.
RT-03-converted.json	Converted Dataset	Structured dataset derived from the original evidence source for investigation workflows.
RT-03-evidence-mapping.xlsx*	Evidence Mapping Spreadsheet	Maps investigation artifacts to original evidence and supports traceability.
RT-03-focused.json	Focused Investigation Dataset	Filtered dataset containing investigation-relevant events.
RT-03-postfix-validator-replay.json	Validation Dataset	Supporting dataset used for validation and investigation workflows.
RT-03-Source-Manifest.json	Source Manifest	Documents dataset source information and evidence traceability.
RT-03-Verified-Timeline.xlsx*	Investigation Timeline Spreadsheet	Verified timeline used for event sequencing and incident reconstruction.
* File extensions are inferred from the file types visible in Windows Explorer.

Investigation Objectives
This dataset supports:

Analysis of potential lateral movement activity.
Review of Windows and Sysmon event data.
Event correlation and timeline reconstruction.
Evidence-based SOC investigations.
Threat classification workflows.
AI-assisted security analysis.
Human analyst validation and reporting.
Evidence Integrity
The original Windows event log serves as the primary evidence source for this scenario.

Evidence mapping, source manifests, case study documentation, and verified timelines support traceability between original evidence and derived investigation datasets.

AI-Assisted SOC Integration
This dataset supports the DEPI-P5 AI-assisted SOC workflow, including:

Security event analysis
Threat classification
Incident timeline reconstruction
Event correlation
False-positive assessment
SOC reporting
Human analyst review
AI-generated findings should be reviewed and validated by human analysts before operational use.

Project Identification
Project: DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone

Dataset Category: Windows-Attacks

Scenario: RT-03-Lateral-Movement

Repository: DEPI-AI-SOC-Capstone
