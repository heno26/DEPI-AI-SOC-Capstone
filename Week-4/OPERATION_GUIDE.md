# Week 4 – Operational Guide
# DEPI Project 5 – AI-SOC Command Center

## 0. Project Path Configuration

The project can be stored in any local directory.

Before following the commands in this guide, define the actual
Week-4 directory in PowerShell:

    $W4 = "D:\Desktop\w\Week-4"

Replace the example path with the actual location on the computer
where the project has been extracted.

The Start-SOC.ps1 launcher uses its own script directory and does
not depend on the original developer's computer path.
## 1. Purpose

This document explains how to prepare, start, access, and stop
the Week 4 SOC Command Center.

The application operates in SIMULATION_ONLY mode.

No real incident response actions are executed.

## 2. Requirements

Required software:

- Windows 10 or Windows 11
- Python 3.9 or later
- Flask 3.1.3
- Ollama (for local AI functionality)
- A compatible local Ollama model

Python dependency file:

Dashboard-V2/requirements.txt

Install dependencies:

    Set-Location "$W4\Dashboard-V2"
    python -m pip install -r requirements.txt

## 3. Ollama Preparation

Ollama is a separate local service.

It is required for AI-assisted functionality but is not required
for basic dashboard access and reading existing incident data.

Ollama must be running independently when AI functionality is used.

Verify the local service:

    Invoke-RestMethod http://127.0.0.1:11434/api/tags

Verify available models:

    ollama list

The installed environment should contain the model required by
the AI functionality.

The exact model configuration is managed by the backend.

## 4. Starting the SOC Command Center

Open PowerShell.

Execute:

    & "$W4\Start-SOC.ps1"

The launcher performs the following:

1. Checks whether an existing backend is healthy.
2. Checks port 5050.
3. Starts the Flask backend if necessary.
4. Waits for backend health confirmation.
5. Opens the dashboard in the default browser.

The backend runs independently of the browser session.

## 5. Dashboard Access

Local dashboard address:

    http://127.0.0.1:5050/

Backend health:

    http://127.0.0.1:5050/api/health

The application should report:

- Backend: ONLINE
- Data Ready: true
- Mode: SIMULATION_ONLY
- Real Response Execution: false

## 6. Main Dashboard Sections

Command Center:
Provides an overview of security cases, timeline events,
observables, response items, analyst decisions, and reports.

Alerts & Cases:
Provides access to the incident cases.

Investigations:
Supports evidence-based investigation workflows.

Incident Timeline:
Displays the correlated incident timeline.

AI Operations:
Provides access to AI-assisted analysis functionality.

MITRE ATT&CK:
Displays technique mapping.

SOAR Playbooks:
Provides access to response playbooks and recommendations.

Incident Response:
Provides lifecycle items and analyst decision functionality.

Evidence & IOCs:
Provides access to evidence and observable information.

Reports Center:
Provides access to generated incident reports.

Unified Report Center:
Provides consolidated reporting functionality.

SOC Analytics:
Provides analytical views.

Activity & Audit:
Provides activity and decision history.

System Health:
Displays application and integration health information.

## 7. Starting the Backend Manually

If the launcher cannot start the backend:

    Set-Location "$W4\Dashboard-V2"\Backend

    python -B app.py

The default application port is 5050.

## 8. Stopping the Backend

Closing the browser does not stop the backend.

To identify the process:

    $PORT = Get-NetTCPConnection -LocalPort 5050 -State Listen

    $PORT | Select-Object LocalAddress,LocalPort,OwningProcess

Inspect the process:

    Get-CimInstance Win32_Process `
        -Filter "ProcessId = <PID>"

Confirm that the process is the Week 4 Python app.py process.

Then stop that specific process:

    Stop-Process -Id <PID> -Force

Replace <PID> with the verified process ID.

Do not terminate unrelated Python processes.

## 9. Troubleshooting

### Port 5050 is occupied

Check the process listening on port 5050.

Do not terminate an unidentified process.

### Backend is unavailable

Check:

- Python installation.
- Flask installation.
- Backend logs.
- Port availability.
- Required data files.

### Ollama is unavailable

Check whether the local Ollama service is running.

Verify its available models.

### Dashboard does not load

Verify:

    http://127.0.0.1:5050/api/health

If the backend is healthy, refresh the browser.

### Missing Python dependency

Run:

    python -m pip install -r requirements.txt

## 10. Runtime Logs

Backend logs are stored under:

    Week-4/Logs/

Backend diagnostic logs may also exist under:

    Week-4/Dashboard-V2/Backend/

These files are useful for troubleshooting.

They are not required as permanent submission artifacts.

## 11. Data and Decision Safety

Important data locations:

    Week-4/Output/
    Week-4/Simulation/
    Week-4/Reports/

Do not manually modify analyst_decisions.jsonl.

Do not delete generated evidence or final reports.

Keep an independent backup before performing maintenance.

All response actions remain simulation recommendations.

## 12. Important Runtime Behavior

The launcher does not automatically stop the backend when the
browser is closed.

The backend continues running independently.

Running Start-SOC.ps1 again checks the existing backend before
attempting to start another instance.

Ollama is an independent service and must be available separately.

## 13. Application Configuration

Backend:

    Dashboard-V2/Backend/app.py

Frontend:

    Dashboard-V2/Frontend/

Dependencies:

    Dashboard-V2/requirements.txt

Startup launcher:

    Start-SOC.ps1

## 14. Simulation Boundary

The system is designed for educational and demonstration purposes.

It does not perform actual containment, eradication, recovery,
account disabling, firewall changes, or endpoint isolation.

Human analyst approval records acceptance of recommendations
and does not represent real-world remediation.

---

DEPI Project 5
Week 4 – Full Capstone IR Simulation & Reporting