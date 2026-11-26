# DEPI Project 5 – Week 4
# Full Capstone Incident Response Simulation & Reporting

## 1. Project Overview

Week 4 represents the final integration and incident response simulation
phase of DEPI Project 5: AI-Assisted SOC Automation.

It integrates the capabilities developed throughout Weeks 1, 2, and 3
into an evidence-based, multi-stage tabletop incident response exercise.

The project demonstrates how a SOC analyst can investigate security
events, correlate evidence, review AI-assisted analysis, evaluate
response recommendations, document analyst decisions, and generate
professional incident response reports.

## 2. System Architecture

The overall project architecture:

Security Datasets and Lab Evidence
        |
        v
Week 1 – AI-Assisted Analysis and Validation
        |
        v
Week 2 – SIEM Detection and Alert Evidence
        |
        v
Week 3 – SOAR Integration and Response Workflows
        |
        v
Week 4 – Incident Correlation and Lifecycle
        |
        v
Evidence-Based Investigation
        |
        v
Local AI-Assisted Reporting
        |
        v
Human Analyst Validation
        |
        v
Decision Center and Incident Lifecycle
        |
        v
Final IR Reports and SOC Dashboard

## 3. Week 4 Objectives

- Integrate previous project deliverables.
- Simulate a composite multi-stage security incident.
- Correlate network, endpoint, authentication, web, and email evidence.
- Preserve original evidence timestamps and source references.
- Apply an evidence-based incident response lifecycle.
- Use local AI to assist report drafting.
- Maintain human analyst decision authority.
- Generate seven final incident response reports.
- Present investigation results through the SOC dashboard.

## 4. Incident Simulation

Scenario: W4-TT-01

The simulation contains 19 security cases distributed across nine
attack stages and benign control cases.

The stages include:

1. Reconnaissance
2. Web-tier attack
3. Credential attack
4. Execution
5. Persistence and privilege-sensitive activity
6. Discovery and defense evasion
7. Lateral movement
8. Command and control
9. Collection / exfiltration hypothesis

The scenario combines historical datasets from different sources.
The relationship between stages is a tabletop scenario construct,
not independently established causal evidence.

## 5. Incident Response Lifecycle

The simulation covers:

- Preparation
- Detection
- Triage and Analysis
- Containment
- Eradication
- Recovery
- Post-Incident Activity

Containment, eradication, and recovery recommendations are
documented for simulation and analyst review.

No real endpoint, account, firewall, or network remediation
is executed by the system.

AI assists the analyst. Human decisions remain authoritative.

## Runtime Dependencies

Flask is the direct Python dependency listed in requirements.txt.

Ollama is a separate local service used by AI-assisted functionality.
The core dashboard and evidence-based reporting data do not require
Ollama to be continuously available.

AI features require Ollama and a compatible locally installed model.
## 6. AI Integration

Week 4 uses local Ollama models for AI-assisted analysis and
incident report drafting.

The AI workflow includes:

- Evidence-grounded fact sheets.
- Local model-based report generation.
- Evidence validation.
- Hallucination and unsupported-fact checks.
- Human review and approval.

AI-generated content is not automatically treated as verified fact.

## 7. Decision Center

The Decision Center records analyst decisions.

Supported decision states include:

- Approved
- Rejected
- Deferred
- Done

Approval represents acceptance of a recommendation, not execution
of the proposed response action.

The system maintains analyst attribution and decision history.

## 8. Final Reports

Seven final reports are provided under Reports/:

1. Final Capstone IR Report
2. Incident Timeline
3. Forensic Evidence Summary
4. Containment, Eradication and Recovery Plan
5. Executive Briefing
6. Lessons Learned
7. AI-Assisted Reporting Workflow

## 9. Dashboard

The primary operational interface is Dashboard-V2.

It includes:

- Command Center
- Alerts and Cases
- Investigations
- Incident Timeline
- AI Operations
- MITRE ATT&CK
- SOAR Playbooks
- Incident Response
- Evidence and IOCs
- Reports Center
- Unified Report Center
- SOC Analytics
- Activity and Audit
- System Health

The application uses a Flask backend and a web frontend.

A separate legacy Dashboard directory is retained as an offline
dashboard implementation.

## 10. Testing

The Week 4 IR test suite is located at:

IR/tests/run_all.py

Recorded test result:

18/18 tests passed.

Tests cover evidence integrity, timestamps, case mapping,
decision handling, lifecycle behavior, AI validation,
report generation, and dashboard data integrity.

## 11. Project Limitations

- The environment is a tabletop simulation.
- Historical datasets do not establish a single real-world intrusion.
- No production systems are connected for remediation.
- Response recommendations are not automatically executed.
- Live threat-intelligence reputation verification is not performed.
- AI output requires human validation.
- Earlier project acceptance gates are documented where applicable.

## 12. Operational Documentation

For installation, startup, usage, troubleshooting, and shutdown,
refer to:

OPERATION_GUIDE.md

## 13. Project Directory

Week-4/
    Backups/
    Config/
    Dashboard/
    Dashboard-V2/
        Backend/
        Frontend/
            css/
            js/
            assets/
        Tests/
        requirements.txt
    Documentation/
    IR/
        tests/
    Logs/
    Output/
    Prompts/
    Reports/
    Simulation/
    Start-SOC.ps1
    README.md
    OPERATION_GUIDE.md

## 14. Project Identity

DEPI Project 5
AI-Assisted SOC Automation & Full Incident Response Capstone

Week 4 – Full Capstone IR Simulation & Reporting