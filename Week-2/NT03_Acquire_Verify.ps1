<#
.SYNOPSIS
  DEPI P5 NT-03: safe source acquisition, SHA-256 verified against the
  successful discovery observation. Windows PowerShell 5.1 compatible.
.EXAMPLE
  .\NT03_Acquire_Verify.ps1 -Mode Check
  .\NT03_Acquire_Verify.ps1 -Mode Acquire
.NOTES
  --Check downloads to a unique TEMP file and deletes it afterwards.
  --Acquire downloads and validates again, then creates exactly two files:
  original labeled Zeek conn.log and a JSON provenance manifest.
  No TLS certificate verification bypass. Does not edit prior project artifacts.
#>
[CmdletBinding()]
param(
    [ValidateSet('Check', 'Acquire')]
    [string] $Mode = 'Check'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Get-Location).Path
if (-not (Test-Path -LiteralPath (Join-Path $root 'app.py') -PathType Leaf)) {
    throw 'STOP: Run from the Week-2 project root (app.py missing).'
}
$networkRoot = Join-Path $root 'Data\Real-Datasets\Network-Attacks'
if (-not (Test-Path -LiteralPath $networkRoot -PathType Container)) {
    throw 'STOP: Existing Data\Real-Datasets\Network-Attacks folder not found.'
}

$url = 'https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/CTU-IoT-Malware-Capture-44-1/bro/conn.log.labeled'
$expectedSize = 31179
$expectedSha = '12cd99bcda78140dd5f31cf3d786642f150e42e0ebc3599190f35314e406f71f'
$expectedPhysicalLines = 246
$expectedRecords = 237
$destination = Join-Path $networkRoot 'NT-03-C2-Beaconing'
$sourcePath = Join-Path $destination 'NT-03-Zeek-conn-original.labeled.log'
$manifestPath = Join-Path $destination 'NT-03-Source-Manifest.json'

$expectedCounts = @{}
$expectedCounts['Benign|-'] = 211
$expectedCounts['Malicious|C&C'] = 14
$expectedCounts['Malicious|C&C-FileDownload'] = 11
$expectedCounts['Malicious|DDoS'] = 1

# Fail early if either destination file exists. No overwrites.
if ((Test-Path -LiteralPath $sourcePath) -or (Test-Path -LiteralPath $manifestPath)) {
    throw "STOP: NT-03 source or manifest already exists under $destination. No overwrite performed."
}

$tempFile = Join-Path $env:TEMP ("NT03-Pinned-" + [guid]::NewGuid().ToString('N') + '.log')
$created = New-Object 'System.Collections.Generic.List[string]'

try {
    Write-Host '=== NT-03 SOURCE ACQUISITION & INTEGRITY ===' -ForegroundColor Cyan
    Write-Host "Mode: $Mode"
    Write-Host 'Dataset: Stratosphere IPS IoT-23 | CTU-IoT-Malware-Capture-44-1'
    Write-Host 'Original remote file: bro/conn.log.labeled'
    Write-Host 'HTTPS certificate verification: ENABLED (default)'
    Write-Host 'Downloading into a temporary file ...'
    Invoke-WebRequest -Uri $url -OutFile $tempFile -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop

    $bytes = [System.IO.File]::ReadAllBytes($tempFile)
    $actualSha = (Get-FileHash -LiteralPath $tempFile -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($bytes.Length -ne $expectedSize -or $actualSha -ne $expectedSha) {
        throw "STOP: Remote contents changed. Expected $expectedSize bytes/$expectedSha; found $($bytes.Length) bytes/$actualSha."
    }
    $text = [System.Text.Encoding]::UTF8.GetString($bytes)
    $lines = @([regex]::Split($text, '\r\n|\n|\r') | Where-Object { $_.Length -gt 0 })
    if ($lines.Count -ne $expectedPhysicalLines) {
        throw "STOP: Expected $expectedPhysicalLines physical lines but found $($lines.Count)."
    }
    $pathHeader = @($lines | Where-Object { $_ -match '^#path\s+conn\s*$' })
    if ($pathHeader.Count -ne 1) { throw 'STOP: Invalid or missing Zeek #path conn header.' }
    $fieldsLine = @($lines | Where-Object { $_ -match '^#fields\s+' })
    if ($fieldsLine.Count -ne 1) { throw 'STOP: Invalid/missing Zeek #fields header.' }
    $fields = @(($fieldsLine[0] -split '\s+') | Select-Object -Skip 1)
    if ($fields.Count -ne 23 -or $fields[0] -ne 'ts' -or
        $fields[2] -ne 'id.orig_h' -or $fields[4] -ne 'id.resp_h' -or
        $fields[21] -ne 'label' -or $fields[22] -ne 'detailed-label') {
        throw 'STOP: Unexpected Zeek source schema/field order.'
    }

    $records = @($lines | Where-Object { -not $_.StartsWith('#') })
    if ($records.Count -ne $expectedRecords) {
        throw "STOP: Expected $expectedRecords connection rows; found $($records.Count)."
    }
    $distribution = @{}
    foreach ($line in $records) {
        $cols = @($line -split "`t")
        if ($cols.Count -ne $fields.Count) {
            # Previous read-only discovery accepted whitespace separated records.
            $cols = @($line -split '\s+')
        }
        if ($cols.Count -ne $fields.Count) { throw 'STOP: Malformed Zeek record.' }
        if ($cols[0] -notmatch '^\d+\.\d+$') { throw 'STOP: Invalid Zeek timestamp.' }
        $key = $cols[21] + '|' + $cols[22]
        if (-not $distribution.ContainsKey($key)) { $distribution[$key] = 0 }
        $distribution[$key]++
    }
    if ($distribution.Count -ne $expectedCounts.Count) { throw 'STOP: Unexpected number of source label categories.' }
    foreach ($key in $expectedCounts.Keys) {
        if (-not $distribution.ContainsKey($key) -or $distribution[$key] -ne $expectedCounts[$key]) {
            throw "STOP: Label inventory mismatch: $key"
        }
    }

    Write-Host "`n=== SOURCE VERIFICATION ===" -ForegroundColor Cyan
    Write-Host "Bytes: $($bytes.Length) / $expectedSize | MATCH"
    Write-Host "SHA256: $actualSha | MATCH"
    Write-Host "Physical lines: $($lines.Count) / $expectedPhysicalLines | MATCH"
    Write-Host "Zeek #path: conn | Fields: $($fields.Count) | Connection records: $($records.Count)"
    Write-Host "Original source labels (held OUT of future AI evidence):"
    foreach ($key in @($expectedCounts.Keys | Sort-Object)) {
        Write-Host "  $key : $($distribution[$key])"
    }
    Write-Host 'Source provenance: URL plus SHA-256 observed in successful discovery; NOT a Git pinned commit.'
    Write-Host 'C2 labels are source-supplied annotations; beacon periodicity NOT yet verified.'

    Write-Host "`n=== OUTPUT PLAN (EXCLUSIVE; NO OVERWRITES) ===" -ForegroundColor Cyan
    Write-Host "CREATE: $sourcePath"
    Write-Host "CREATE: $manifestPath"
    if ($Mode -eq 'Check') {
        Write-Host 'Project Data / Core / Results / Reviews: UNCHANGED'
        Write-Host 'STATUS: NT-03 ACQUISITION READY - READ-ONLY PROJECT CHECK PASS' -ForegroundColor Green
        return
    }

    $answer = Read-Host "Type ACQUIRE to save original source + manifest (Enter cancels)"
    if ($answer -cne 'ACQUIRE') {
        Write-Host 'CANCELLED: no project files created'
        return
    }
    # Recheck before writing anything into the project.
    if ((Test-Path -LiteralPath $sourcePath) -or (Test-Path -LiteralPath $manifestPath)) {
        throw 'STOP: Destination appeared during verification; refusing overwrite.'
    }
    if (-not (Test-Path -LiteralPath $destination)) {
        New-Item -ItemType Directory -Path $destination -ErrorAction Stop | Out-Null
    }

    $stream = [System.IO.File]::Open($sourcePath,
        [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    $created.Add($sourcePath)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush() }
    finally { $stream.Dispose() }
    $savedSha = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($savedSha -ne $expectedSha -or (Get-Item -LiteralPath $sourcePath).Length -ne $expectedSize) {
        throw 'STOP: Saved source integrity mismatch.'
    }

    $manifest = [ordered]@{
        case_id = 'NT-03'
        dataset = 'Stratosphere IPS IoT-23'
        capture_id = 'CTU-IoT-Malware-Capture-44-1'
        source_url = $url
        upstream_file_path = 'bro/conn.log.labeled'
        provenance_pin_type = 'discovery-observed SHA256 (not Git commit pin)'
        discovery_sha256 = $expectedSha
        saved_sha256 = $savedSha
        byte_count = $bytes.Length
        physical_line_count = $lines.Count
        zeek_path = 'conn'
        zeek_field_count = $fields.Count
        zeek_fields = $fields
        connection_records = $records.Count
        source_supplied_label_counts = [ordered]@{
            benign = 211
            c2 = 14
            c2_file_download = 11
            ddos = 1
        }
        labels_must_be_withheld_from_blind_ai_analysis = $true
        c2_beaconing_confirmed_by_this_step = $false
        imported_at_utc = [datetime]::UtcNow.ToString('o')
        original_file_name = (Split-Path -Path $sourcePath -Leaf)
    }
    $json = (ConvertTo-Json -InputObject $manifest -Depth 8) + "`n"
    $jsonBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json)
    $stream = [System.IO.File]::Open($manifestPath,
        [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    $created.Add($manifestPath)
    try { $stream.Write($jsonBytes, 0, $jsonBytes.Length); $stream.Flush() }
    finally { $stream.Dispose() }
    if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -eq '') {
        throw 'STOP: Cannot compute manifest hash.'
    }
    Write-Host "`nSaved original SHA256: $savedSha"
    Write-Host "Manifest SHA256: $((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant())"
    Write-Host 'Original evidence, Core, Results, historical reviews: UNCHANGED'
    Write-Host 'STATUS: NT-03 SOURCE ACQUISITION VERIFIED - PATTERN INSPECTION NEXT' -ForegroundColor Green
}
catch {
    # Delete only files exclusively created during THIS run; leave other files alone.
    for ($i = $created.Count - 1; $i -ge 0; $i--) {
        Remove-Item -LiteralPath $created[$i] -Force -ErrorAction SilentlyContinue
    }
    throw
}
finally {
    Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
}
