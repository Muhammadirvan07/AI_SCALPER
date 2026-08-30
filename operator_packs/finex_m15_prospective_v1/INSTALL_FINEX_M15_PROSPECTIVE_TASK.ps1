[CmdletBinding()]
param(
    [string]$TaskName = 'AI_SCALPER_FINEX_M15_PROSPECTIVE_RESEARCH_V1',
    [datetime]$FirstRun = [datetime]'2026-08-31T21:15:00'
)

$ErrorActionPreference = 'Stop'
$runner = Join-Path $PSScriptRoot 'RUN_FINEX_M15_PROSPECTIVE.ps1'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "Runner is missing: $runner"
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $runner
$action = New-ScheduledTaskAction -Execute $powerShell -Argument $arguments
$trigger = New-ScheduledTaskTrigger -Daily -At $FirstRun
$principal = New-ScheduledTaskPrincipal `
    -UserId $identity `
    -LogonType Interactive `
    -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 20)

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description 'FINEX read-only M15 prospective research capture; no broker-forward or order authority.' `
    -Force | Out-Null

Write-Output 'FINEX_M15_PROSPECTIVE_TASK_INSTALL=PASS'
Write-Output "TASK_NAME=$TaskName"
Write-Output "RUN_AS=$identity"
Write-Output "FIRST_RUN_LOCAL=$($FirstRun.ToString('o'))"
Write-Output 'SCHEDULE=DAILY'
Write-Output 'LOGON_REQUIREMENT=MUHAM_INTERACTIVE_SESSION_AND_FINEX_TERMINAL_OPEN'
Write-Output 'BROKER_FORWARD_CREDIT=false'
Write-Output 'PROMOTION_ELIGIBLE=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'

