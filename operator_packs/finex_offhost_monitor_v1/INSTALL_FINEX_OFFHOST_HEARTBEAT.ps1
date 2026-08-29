[CmdletBinding()]
param(
    [string]$PrivateKeyPath = '',
    [string]$ServiceScript = '',
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$taskName = 'AI_SCALPER_FINEX_OFFHOST_HEARTBEAT_V1'
$firewallName = 'AI_SCALPER FINEX Offhost Heartbeat V1'
$localIp = '100.121.177.7'
$hostIp = '100.80.180.13'
$port = 43129
$installRoot = Join-Path $env:ProgramData 'AI_SCALPER\FinexOffhostHeartbeatV1'
if ([string]::IsNullOrWhiteSpace($PrivateKeyPath)) { $PrivateKeyPath = Join-Path $HOME '.ssh\finex_runtime_health_offhost_v1' }
if ([string]::IsNullOrWhiteSpace($ServiceScript)) { $ServiceScript = Join-Path $PSScriptRoot 'FINEX_OFFHOST_HEARTBEAT_SERVICE.ps1' }

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_REQUIRED' }
if ($env:COMPUTERNAME.ToLowerInvariant() -cne 'desktop-8cc1fnj') { throw 'OFFHOST_COMPUTER_IDENTITY_MISMATCH' }
if (-not (Test-Path -LiteralPath $ServiceScript -PathType Leaf)) { throw 'HEARTBEAT_SERVICE_SCRIPT_MISSING' }
if (-not (Test-Path -LiteralPath $PrivateKeyPath -PathType Leaf)) { throw 'OFFHOST_PRIVATE_KEY_MISSING' }

$preflightRoot = Join-Path ([IO.Path]::GetTempPath()) ('finex-heartbeat-preflight-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $preflightRoot -Force | Out-Null
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ServiceScript -PrivateKeyPath $PrivateKeyPath -StateDirectory $preflightRoot -SelfTest
if ($LASTEXITCODE -ne 0) { throw 'HEARTBEAT_PREFLIGHT_FAILED' }
if ($PreflightOnly) {
    Write-Output 'FINEX_OFFHOST_HEARTBEAT_PREFLIGHT=PASS'
    Write-Output 'SYSTEM_MUTATION=false'
    Write-Output 'ORDER_CAPABILITY=DISABLED'
    exit 0
}

New-Item -ItemType Directory -Path $installRoot -Force | Out-Null
$installedService = Join-Path $installRoot 'FINEX_OFFHOST_HEARTBEAT_SERVICE.ps1'
Copy-Item -LiteralPath $ServiceScript -Destination $installedService -Force
$account = [Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $installRoot /inheritance:r /grant:r "${account}:(OI)(CI)M" 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'HEARTBEAT_ACL_CONFIGURATION_FAILED' }

$url = "http://${localIp}:$port/"
& netsh.exe http delete urlacl url=$url | Out-Null
& netsh.exe http add urlacl url=$url user=$account listen=yes delegate=no | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'HEARTBEAT_URLACL_CONFIGURATION_FAILED' }

Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction Stop
New-NetFirewallRule -DisplayName $firewallName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $port -LocalAddress $localIp -RemoteAddress $hostIp -Profile Any | Out-Null

if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$installedService`" -PrivateKeyPath `"$PrivateKeyPath`" -StateDirectory `"$installRoot`""
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $account
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $account -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $taskPrincipal | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2
$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
if ($task.State -notin @('Running','Ready')) { throw 'HEARTBEAT_TASK_NOT_ACTIVE' }

Write-Output 'FINEX_OFFHOST_HEARTBEAT_INSTALL=PASS'
Write-Output "ENDPOINT=http://${localIp}:$port/heartbeat"
Write-Output "TASK_NAME=$taskName"
Write-Output "RUN_AS=$account"
Write-Output 'LOGON_REQUIREMENT=PUTRA_INTERACTIVE_SESSION'
Write-Output 'RUNTIME_HEALTH_VERIFIED=false'
Write-Output 'AUTHORIZATION_GRANTED=false'
Write-Output 'ORDER_CAPABILITY=DISABLED'
