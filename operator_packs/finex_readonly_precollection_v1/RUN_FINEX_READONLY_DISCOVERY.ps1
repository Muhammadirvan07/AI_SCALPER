[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$DiscoveryScript = Join-Path $ProjectRoot 'mt5_readonly_discovery.py'
$Terminal = 'C:\Program Files\Finex Bisnis Solusi MT5 Terminal\terminal64.exe'
$EvidenceRoot = Join-Path $ProjectRoot 'runtime_evidence\finex_readonly_precollection_v1'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Project Python is unavailable: $Python"
}
if (-not (Test-Path -LiteralPath $Terminal -PathType Leaf)) {
    throw "FINEX terminal is unavailable: $Terminal"
}

New-Item -ItemType Directory -Path $EvidenceRoot -Force | Out-Null
$Timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$Output = Join-Path $EvidenceRoot "finex_mt5_readonly_discovery_$Timestamp.json"

& $Python $DiscoveryScript `
    --candidate finex `
    --terminal-path $Terminal `
    --output $Output

if ($LASTEXITCODE -ne 0) {
    throw "FINEX read-only discovery failed with exit code $LASTEXITCODE"
}

Write-Output 'FINEX_READONLY_PRECOLLECTION=PASS'
Write-Output "OUTPUT=$Output"
Write-Output 'EVIDENCE_CLASS=DIAGNOSTIC_ONLY'
Write-Output 'BROKER_FORWARD_CREDIT=false'
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
