# Week 3 Operational Guide

## 1. Prerequisites

Use Windows PowerShell, Python 3 and local Ollama. Verify:

```powershell
python --version
ollama --version
ollama list
ollama pull mistral:7b-instruct-v0.3-q4_K_S
```

If the Ollama service is not running, use `ollama serve` in a separate terminal. Expected endpoint: localhost:11434.

## 2. Locate the project and evidence

From the repository root:

```powershell
Set-Location .\Week-3\Scenario-Orchestrator
python main.py --version
python main.py --help
$Evidence = (Resolve-Path '..\..\Week-2\Evidence\SIEM-OpenObserve').Path
Get-ChildItem $Evidence -Filter '*.json'
```

Expected version: 1.2.0. The evidence path is the original lab layout; if absent, supply the actual directory containing compatible Week 2 JSON files. Do not modify original evidence to force acceptance.

## 3. Prepare and review

```powershell
python main.py prepare --evidence $Evidence
```

This discovers and normalizes evidence, processes or reuses AI results, validates findings, creates incidents and generates plans. Use `--force-ai` to request fresh processing. Record the printed IDs:

```powershell
$Run = '<ORCH-RUN-ID>'
$PB = '<PB-RUN-ID>'
python main.py status --run $Run
$Incident = '<INCIDENT-ID>'
python main.py review --run $Run --incident-id $Incident
```

Replace placeholders with actual IDs. Review evidence, AI analysis, semantic findings and proposed actions before deciding.

## 4. Human decision and simulation

```powershell
python main.py approve --run $Run --incident-id $Incident --playbooks $PB
```

Inspect the plan and hash; type APPROVE only if acceptable. Then:

```powershell
python main.py respond --run $Run --incident-id $Incident --playbooks $PB
python main.py close --run $Run --incident-id $Incident --playbooks $PB
```

Type CLOSE after verified completion. For a different incident pending approval, reject instead:

```powershell
python main.py reject --run $Run --incident-id $Incident
```

Type REJECT. Its response must be blocked. Do not bypass controls.

## 5. Reporting

```powershell
python main.py report --run $Run --playbooks $PB
$Latest = Get-ChildItem '.\Reports\HISTORICAL_LAB' -Directory | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Invoke-Item (Join-Path $Latest.FullName 'Executive_Summary.html')
```

Outputs: Executive_Summary.html, SOC_Final_Report.json, Incident_Register.csv, individual incident HTML reports and report_manifest.json.

Workspace: Runs/Orchestration/<run>/execution_report.json and nested Runs/Incidents, Playbooks, Responses and ExecutionReceipts. Each preparation creates a separate workspace.

## 6. Troubleshooting

| Issue | Action |
|---|---|
| Python unavailable | Check installation and PATH |
| Ollama unavailable | Check service and model |
| Missing evidence | Set correct directory |
| Manual review | Investigate missing identity or invalid fields |
| Semantic failure | Review source and AI findings |
| Approval required | Complete investigation and human review |
| Plan or receipt mismatch | Investigate integrity; do not bypass |
| Existing receipt | Do not repeat response |

## 7. Reference demonstration and limitations

SSH brute force was approved, simulated and closed; malware was rejected; one XSS remained pending approval. Four other incidents remained new. One evidence record required manual review.

Historical evidence replay is not live SIEM streaming. All response actions are simulated. Interactive confirmation is not authenticated analyst identity. SHA256 checks depend on trusted reference hashes; replay protection is workspace-scoped. AI findings and warnings require analyst interpretation. Exchange alerts do not establish exfiltration or phishing. Clean-machine portability is not yet verified; historical artifacts may contain absolute paths. Fresh runs may produce different AI results and cache counts.


<!-- REPRODUCIBILITY-VALIDATION -->
## Reference Evidence Selection

The repository contains nine Week 2 JSON evidence files.
The validated reference workflow uses eight of them.

The controlled reanalysis artifact is excluded from the
reference dataset without deleting or modifying it.

From the Scenario-Orchestrator directory, run:

    $Source = (Resolve-Path "../../Week-2/Evidence/SIEM-OpenObserve").Path
    $Evidence = Join-Path $HOME ("DEPI-Evidence-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $Evidence
    Get-ChildItem $Source -File -Filter "*.json" |
        Where-Object { $_.Name -ne "SIEM05_Controlled_AI_Reanalysis_20261023.json" } |
        Copy-Item -Destination $Evidence

    python main.py prepare --evidence $Evidence --force-ai

Keep the evidence directory available and unchanged
throughout investigation, approval, simulation and reporting.

The validated clean execution produced seven incidents,
seven SOAR plans and a successful SOC report.

AI findings and validation outcomes may vary between runs.
