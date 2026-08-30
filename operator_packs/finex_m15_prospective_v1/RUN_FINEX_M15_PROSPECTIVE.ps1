[CmdletBinding()]
param(
    [string]$ProjectRoot,
    [string]$PrivateRoot,
    [string]$TerminalPath = 'C:\Program Files\Finex Bisnis Solusi MT5 Terminal\terminal64.exe'
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
    $ProjectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
}
if ([string]::IsNullOrWhiteSpace($PrivateRoot)) {
    $PrivateRoot = Join-Path (Split-Path $ProjectRoot -Parent) 'AI_SCALPER_PRIVATE\finex'
}

$python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$discoveryRoot = Join-Path $ProjectRoot 'runtime_evidence\finex_readonly_precollection_v1'
$artifactRoot = Join-Path $PrivateRoot 'validation-artifacts-v1'
$baseline = Join-Path $artifactRoot 'prospective-baselines\finex-m15-development-baseline-20260830-v1.json'
$captureParent = Join-Path $PrivateRoot 'prospective-captures-v1'
$logRoot = Join-Path $PrivateRoot 'prospective-logs-v1'

foreach ($required in @($python, $baseline, $TerminalPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "FINEX prospective prerequisite missing: $required"
    }
}
$discovery = Get-ChildItem -LiteralPath $discoveryRoot -Filter 'finex_mt5_readonly_discovery_*.json' -File |
    Sort-Object LastWriteTimeUtc -Descending |
    Select-Object -First 1
if ($null -eq $discovery) {
    throw 'No FINEX read-only discovery receipt is available.'
}

$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ')
$captureRoot = Join-Path $captureParent $stamp
$logPath = Join-Path $logRoot ($stamp + '.log')
New-Item -ItemType Directory -Path $captureParent -Force | Out-Null
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null

try {
    Push-Location $ProjectRoot
    & $python '.\collect_finex_m15_snapshot.py' `
        --discovery $discovery.FullName `
        --terminal-path $TerminalPath `
        --bars 5000 `
        --output-root $captureRoot 2>&1 | Tee-Object -FilePath $logPath
    if ($LASTEXITCODE -ne 0) {
        throw "FINEX read-only snapshot failed with exit code $LASTEXITCODE"
    }

    & $python '.\collect_finex_m15_prospective_partition.py' `
        --baseline $baseline `
        --source-root $captureRoot `
        --artifact-root $artifactRoot 2>&1 | Tee-Object -FilePath $logPath -Append
    if ($LASTEXITCODE -ne 0) {
        throw "FINEX prospective ingest failed with exit code $LASTEXITCODE"
    }
    'FINEX_M15_PROSPECTIVE_RUN=PASS' | Tee-Object -FilePath $logPath -Append
    'BROKER_FORWARD_CREDIT=false' | Tee-Object -FilePath $logPath -Append
    'PROMOTION_ELIGIBLE=false' | Tee-Object -FilePath $logPath -Append
    'ORDER_CAPABILITY=DISABLED' | Tee-Object -FilePath $logPath -Append
}
catch {
    ("FINEX_M15_PROSPECTIVE_RUN=BLOCKED:{0}" -f $_.Exception.Message) |
        Tee-Object -FilePath $logPath -Append
    'ORDER_CAPABILITY=DISABLED' | Tee-Object -FilePath $logPath -Append
    throw
}
finally {
    Pop-Location
}

