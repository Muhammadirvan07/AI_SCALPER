[CmdletBinding()]
param(
    [string]$TaskName = 'AI_SCALPER_FINEX_READONLY_DISCOVERY_V1'
)

$ErrorActionPreference = 'Stop'
$Worker = Join-Path $PSScriptRoot 'RUN_FINEX_READONLY_DISCOVERY.ps1'
if (-not (Test-Path -LiteralPath $Worker -PathType Leaf)) {
    throw "Worker script is unavailable: $Worker"
}

$PowerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Action = New-ScheduledTaskAction `
    -Execute $PowerShell `
    -Argument "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Worker`""
$Trigger = New-ScheduledTaskTrigger `
    -Once `
    -At ([DateTime]::Now.AddMinutes(1)) `
    -RepetitionInterval (New-TimeSpan -Minutes 15) `
    -RepetitionDuration (New-TimeSpan -Days 3650)
$Settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Principal $Principal `
    -Description 'FINEX signed read-only discovery; diagnostic only; no order capability.' `
    -Force | Out-Null

Write-Output 'FINEX_READONLY_DISCOVERY_TASK_INSTALL=PASS'
Write-Output "TASK_NAME=$TaskName"
Write-Output 'RUN_INTERVAL_MINUTES=15'
Write-Output 'EVIDENCE_CLASS=DIAGNOSTIC_ONLY'
Write-Output 'BROKER_FORWARD_CREDIT=false'
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
