RT-02 — Discovery
Overview
This dataset supports the investigation of Windows-based Discovery activity.

The scenario contains original event log evidence, converted datasets, focused investigation datasets, source manifests, evidence mapping artifacts, inventory records, timeline validation files, and supporting documentation intended for SOC investigations, incident reconstruction, AI-assisted threat classification, and analyst validation workflows.

Dataset Information
Field	Value
Scenario ID	RT-02
Scenario Name	Discovery
Category	Windows-Attacks
Platform	Microsoft Windows
Investigation Domain	Security Monitoring and Incident Response
Repository	DEPI-AI-SOC-Capstone
File Inventory
File Name	Type	Purpose
Failed-Attempts	Folder	Contains supporting investigation artifacts related to failed activity observed during the scenario.
discovery_psloggedon.evtx*	Windows Event Log	Original event log evidence collected for the investigation.
RT-02-Case-Study.md	Case Study Documentation	Investigation notes and scenario documentation.
RT-02-Discovery-converted.json	Converted Dataset	Structured investigation dataset derived from the original evidence source.
RT-02-Discovery-focused.json	Focused Investigation Dataset	Filtered dataset containing investigation-relevant events.
RT-02-Discovery-focused-v2.json	Focused Investigation Dataset	Additional refined investigation dataset used for analysis.
RT-02-evidence-mapping.xlsx*	Evidence Mapping Spreadsheet	Maps derived artifacts to original evidence sources and supports traceability.
RT-02-postfix-validator-replay.json	Investigation Dataset	Supporting investigation dataset retained for validation and analysis workflows.
RT-02-Source-Inventory.xlsx*	Source Inventory Spreadsheet	Records dataset sources and investigation references.
RT-02-Source-Manifest.json	Source Manifest	Maintains dataset traceability and source documentation.
RT-02-UserData-Fix-Manifest.json	Verification Manifest	Documents dataset adjustment and integrity tracking information.
RT-02-Verified-Timeline.xlsx*	Investigation Timeline Spreadsheet	Verified timeline used for event correlation and incident reconstruction.
* File extensions are inferred from the file types visible in Windows Explorer.

Investigation Objectives
This dataset supports:

Analysis of Windows discovery-related activity.
Security event correlation and investigation.
Evidence-based SOC workflows.
Activity timeline reconstruction.
Source traceability and validation.
AI-assisted threat classification.
Human analyst review of investigation findings.
Evidence Integrity
The original Windows event log serves as the primary evidence source for this scenario.

Evidence mapping spreadsheets, source manifests, inventory records, verification manifests, and timeline documentation support traceability between original evidence and derived investigation datasets.

AI-Assisted SOC Integration
This dataset supports the DEPI-P5 AI-assisted SOC workflow, including:

Security log analysis
Threat classification assistance
Event correlation
Timeline reconstruction
False-positive assessment
Investigation documentation
SOC reporting workflows
AI-generated findings should be reviewed and validated by human analysts before operational use.

Project Identification
Project: DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone

Dataset Category: Windows-Attacks

Scenario: RT-02-Discovery

Repository: DEPI-AI-SOC-Capstone
