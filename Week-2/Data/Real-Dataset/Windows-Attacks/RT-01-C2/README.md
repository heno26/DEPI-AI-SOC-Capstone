RT-01 — Command and Control (C2)
Overview
This dataset supports the investigation of Windows-based Command and Control (C2) activity within an enterprise environment.

The scenario contains original Windows event log evidence, converted investigation datasets, focused evidence extracts, traceability artifacts, and investigation documentation intended to support SOC analysis, incident reconstruction, AI-assisted threat classification, and analyst validation.

Dataset Information
Field	Value
Scenario ID	RT-01
Scenario Name	Command and Control (C2)
Category	Windows-Attacks
Platform	Microsoft Windows
Investigation Domain	Security Monitoring and Incident Response
Repository	DEPI-AI-SOC-Capstone
File Inventory
File Name	Type	Purpose
DE_sysmon-3-rdp-tun.evtx*	Windows Event Log	Original Windows event log evidence used as the primary investigation source.
RT-01-C2-converted.json	JSON Dataset	Converted investigation dataset derived from the original evidence for analysis workflows.
RT-01-C2-evidence-mapping.xlsx*	Evidence Mapping Spreadsheet	Maps investigation artifacts to original evidence sources and supports traceability.
RT-01-C2-plink-focused.json	Focused Investigation Dataset	Filtered dataset containing investigation-relevant events associated with the scenario.
RT-01-Case-Study.md	Case Study Documentation	Scenario documentation and investigation guidance.
RT-01-Verified-Timeline.xlsx*	Investigation Timeline Spreadsheet	Verified timeline used to support event correlation and incident reconstruction.
* File extensions are inferred from the file types visible in Windows Explorer.

Investigation Objectives
This dataset supports:

Analysis of potentially suspicious command-and-control activity.
Review of Windows security and Sysmon event data.
Event correlation and timeline reconstruction.
Evidence-based SOC investigations.
AI-assisted threat classification workflows.
Human analyst validation of investigative findings.
Evidence Integrity
The original Windows event log serves as the primary evidence source for this scenario.

Supporting datasets, evidence mapping files, case study documentation, and verified timelines help maintain traceability between original evidence and derived investigation artifacts.

AI-Assisted SOC Integration
This dataset supports the DEPI-P5 AI-assisted SOC workflow, including:

Security log analysis
Threat classification
Event correlation
Timeline reconstruction
False-positive assessment
SOC reporting
Human analyst review
AI-generated findings should always be validated by human analysts before operational or investigative use.

Project Identification
Project: DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone

Dataset Category: Windows-Attacks

Scenario: RT-01-C2

Repository: DEPI-AI-SOC-Capstone
