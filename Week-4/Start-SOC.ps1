$ErrorActionPreference = "Stop"

$W4 = $PSScriptRoot
$BACKEND = "$W4\Dashboard-V2\Backend"
$LOGDIR = "$W4\Logs"
$URL = "http://127.0.0.1:5050"

New-Item -ItemType Directory -Path $LOGDIR -Force | Out-Null

Write-Host "`n===== DEPI-P5 AI-SOC COMMAND CENTER =====" -ForegroundColor Cyan

# Check existing backend
try {
    $HEALTH = Invoke-RestMethod "$URL/api/health" -TimeoutSec 3

    if ($HEALTH.backend -eq "ONLINE" -and $HEALTH.data_ready) {
        Write-Host "[PASS] Existing backend is healthy." -ForegroundColor Green
        Start-Process $URL
        exit 0
    }
}
catch {}

# Check port ownership
$PORT = Get-NetTCPConnection -LocalPort 5050 `
    -State Listen -ErrorAction SilentlyContinue

if ($PORT) {
    throw "Port 5050 is occupied but the expected backend is not healthy. No process was stopped."
}

# Start backend
$PYTHON = (Get-Command python.exe).Source
$STAMP = Get-Date -Format "yyyyMMdd-HHmmss"

$OUT = "$LOGDIR\backend-$STAMP.log"
$ERR = "$LOGDIR\backend-error-$STAMP.log"

$PROCESS = Start-Process `
    -FilePath $PYTHON `
    -ArgumentList @("-B", "app.py") `
    -WorkingDirectory $BACKEND `
    -RedirectStandardOutput $OUT `
    -RedirectStandardError $ERR `
    -PassThru `
    -WindowStyle Hidden

Write-Host "[INFO] Backend starting. PID: $($PROCESS.Id)"

# Wait for health
$READY = $false

for ($I = 1; $I -le 20; $I++) {
    Start-Sleep -Seconds 1

    try {
        $HEALTH = Invoke-RestMethod "$URL/api/health" -TimeoutSec 2

        if ($HEALTH.backend -eq "ONLINE" -and $HEALTH.data_ready) {
            $READY = $true
            break
        }
    }
    catch {}
}

if (!$READY) {
    Write-Host "[FAIL] Backend did not become healthy." -ForegroundColor Red
    Write-Host "Check: $ERR"
    exit 1
}

Write-Host "[PASS] Backend ONLINE" -ForegroundColor Green
Write-Host "[PASS] Data READY" -ForegroundColor Green

Start-Process $URL

Write-Host "`nSOC COMMAND CENTER STARTED." -ForegroundColor Green