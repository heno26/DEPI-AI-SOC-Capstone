RT-04 — Persistence
Overview
This dataset supports the investigation of Windows-based Persistence activity.

The scenario contains original Sysmon event log evidence, converted investigation datasets, focused evidence collections, source inventories, evidence mapping artifacts, timeline validation files, and supporting documentation intended for SOC investigations, incident response workflows, AI-assisted threat classification, and analyst validation.

Dataset Information
Field	Value
Scenario ID	RT-04
Scenario Name	Persistence
Category	Windows-Attacks
Platform	Microsoft Windows
Investigation Domain	Security Monitoring and Incident Response
Repository	DEPI-AI-SOC-Capstone
File Inventory
File Name	Type	Purpose
RT-04-Case-Study.md	Case Study Documentation	Investigation notes, scenario context, and supporting documentation.
RT-04-converted.json	Converted Dataset	Structured dataset derived from original evidence for investigation workflows.
RT-04-evidence-mapping.xlsx*	Evidence Mapping Spreadsheet	Maps investigation artifacts to original evidence and supports traceability.
RT-04-focused.json	Focused Investigation Dataset	Filtered dataset containing investigation-relevant events.
RT-04-postfix-validator-replay.json	Validation Dataset	Supporting dataset used for validation and investigation workflows.
RT-04-Source-Inventory.xlsx*	Source Inventory Spreadsheet	Documents evidence sources and investigation references.
RT-04-Source-Manifest.json	Source Manifest	Maintains source traceability and dataset documentation.
RT-04-Verified-Timeline.xlsx*	Investigation Timeline Spreadsheet	Verified timeline used for event correlation and incident reconstruction.
sysmon_13_1_persistence_via_winlogon_shell.evtx*	Windows Event Log	Original Sysmon event log evidence used as the primary investigation source.
* File extensions are inferred from the file types visible in Windows Explorer.

Investigation Objectives
This dataset supports:

Investigation of persistence-related activity in Windows environments.
Analysis of Sysmon event data.
Event correlation and timeline reconstruction.
Evidence-based SOC investigations.
AI-assisted threat classification workflows.
Human analyst validation and reporting.
Evidence Integrity
The original Sysmon event log serves as the primary evidence source for this scenario.

Evidence mapping files, source manifests, inventory records, case study documentation, and verified timelines help maintain traceability between original evidence and derived investigation datasets.

AI-Assisted SOC Integration
This dataset supports the DEPI-P5 AI-assisted SOC workflow, including:

Security log analysis
Threat classification
Event correlation
Timeline reconstruction
False-positive assessment
SOC reporting
Human analyst review
AI-generated findings should be reviewed and validated by human analysts before operational use.

Project Identification
Project: DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone

Dataset Category: Windows-Attacks

Scenario: RT-04-Persistence

Repository: DEPI-AI-SOC-Capstone
