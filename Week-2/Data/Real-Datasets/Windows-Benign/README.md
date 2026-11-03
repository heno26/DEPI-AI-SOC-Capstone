Windows Benign Datasets
Overview
This directory contains benign Windows activity datasets used in the DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone.

The datasets represent normal administrative, operational, and system activity collected from Windows environments. They are intended to support baseline analysis, false-positive assessment, AI-assisted classification testing, and analyst validation workflows.

Dataset Collection
The Windows-Benign directory currently contains the following datasets and supporting resources.

File Inventory
Name	Type	Purpose
BT-01	Folder	Benign Windows activity dataset scenario.
BT-02	Folder	Benign Windows activity dataset scenario.
BT-03	Folder	Benign Windows activity dataset scenario.
Selected-Channels	Folder	Preserved Windows event log channel selections used during dataset preparation and analysis workflows.
BT-Archive-Contents.txt*	Text Document	Documents archive contents and dataset structure.
BT-Source-Inventory.xlsx*	Spreadsheet	Source inventory and dataset traceability information.
win2022-evtx.tgz	Archive	Archived Windows event log collection used as a source dataset.
* File extensions are inferred from the file types visible in Windows Explorer.

Investigation Objectives
These datasets support:

Baseline Windows activity analysis.
False-positive assessment workflows.
Security event validation.
AI-assisted classification testing.
Event correlation and timeline review.
Human analyst validation.
SOC training and investigation exercises.
Directory Structure
Windows-Benign/
├── BT-01/
├── BT-02/
├── BT-03/
├── Selected-Channels/
├── BT-Archive-Contents.txt
├── BT-Source-Inventory.xlsx
└── win2022-evtx.tgz
Evidence Integrity
The dataset preserves original benign Windows activity sources and supporting inventory documentation.

Source inventories, archive documentation, and channel selections help maintain traceability and reproducibility throughout analysis workflows.

AI-Assisted SOC Integration
These datasets support the DEPI-P5 AI-assisted SOC workflow, including:

Baseline behavior analysis
False-positive reduction
Threat classification testing
Event correlation
Investigation validation
SOC report generation
AI-generated findings should always be reviewed and validated by human analysts before operational use.

Project Information
Project: DEPI-P5 AI-Assisted SOC Automation & Incident Response Capstone

Repository: DEPI-AI-SOC-Capstone

Dataset Category: Windows-Benign

Status: Dataset Collection and Documentation
