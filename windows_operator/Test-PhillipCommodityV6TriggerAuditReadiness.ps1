[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter()]
  [string]$ReleasePython = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-ecedec9-venv\Scripts\python.exe"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolkitSourceCommit = "__TOOLKIT_SOURCE_COMMIT__"
$toolkitSourceTree = "__TOOLKIT_SOURCE_TREE__"
$expectedToolSHA256 = "__POSTRUN_TOOL_SHA256__"
$taskName = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
$v4TaskName = "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow"
$v5TaskName = "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow"
$taskSchedulerChannel = "Microsoft-Windows-TaskScheduler/Operational"
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-task-review"
)
$installationReceiptPath = Join-Path $taskReviewRoot (
  "$taskName.installation-receipt.json"
)
$toolPath = Join-Path $PSScriptRoot (
  "phillip_commodity_v6_postrun_acceptance.py"
)
$firstBoundary = [DateTimeOffset]::Parse("2026-07-30T06:45:00+09:00")

function Assert-RegularNonReparseFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Required regular file is unavailable: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (
    ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
  ) {
    throw "Required file must not be a reparse point: $Path"
  }
}

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
foreach ($path in @(
  $ToolkitArchive,
  $ReleasePython,
  $toolPath,
  $installationReceiptPath
)) {
  Assert-RegularNonReparseFile -Path $path
}

$expectedArchiveHash = $ExpectedToolkitArchiveSHA256.ToLowerInvariant()
$observedArchiveHash = (
  Get-FileHash -LiteralPath $ToolkitArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
$observedToolHash = (
  Get-FileHash -LiteralPath $toolPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observedArchiveHash -ne $expectedArchiveHash) {
  throw "Post-run toolkit archive SHA-256 mismatch."
}
if ($observedToolHash -ne $expectedToolSHA256) {
  throw "Post-run Python tool SHA-256 mismatch."
}

$verificationOutput = @(
  & $ReleasePython `
    -I `
    -S `
    -B `
    $toolPath `
    verify-toolkit `
    --archive $ToolkitArchive `
    --expected-archive-sha256 $expectedArchiveHash `
    --expected-source-commit $toolkitSourceCommit `
    --expected-source-tree $toolkitSourceTree `
    2>&1
)
if ($LASTEXITCODE -ne 0) {
  $verificationOutput
  throw "Post-run toolkit verification failed."
}
$verification = (
  $verificationOutput -join [Environment]::NewLine
) | ConvertFrom-Json
if (
  $verification.status -ne
    "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_VERIFIED" -or
  $verification.order_capability -ne "DISABLED" -or
  $verification.live_allowed -ne $false -or
  $verification.task_scheduler_mutation -ne "NOT_PERFORMED" -or
  $verification.broker_mutation -ne "NOT_PERFORMED"
) {
  throw "Post-run toolkit verification projection mismatch."
}

$log = Get-WinEvent -ListLog $taskSchedulerChannel -ErrorAction Stop
if (
  $null -eq $log -or
  $null -eq $log.PSObject.Properties["IsEnabled"] -or
  [bool]$log.IsEnabled -ne $true
) {
  throw "Task Scheduler Operational log must already be enabled."
}

$task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
$v4Task = Get-ScheduledTask -TaskName $v4TaskName -ErrorAction Stop
$v5Task = Get-ScheduledTask -TaskName $v5TaskName -ErrorAction Stop
$receipt = Get-Content -LiteralPath $installationReceiptPath -Raw |
  ConvertFrom-Json
if (
  [string]$receipt.task_name -ne $taskName -or
  [string]$receipt.start_boundary -ne "2026-07-30T06:45:00+09:00" -or
  [bool]$receipt.task_started_manually -ne $false -or
  [string]$receipt.order_capability -ne "DISABLED" -or
  [bool]$receipt.live_allowed -ne $false -or
  [bool]$receipt.safe_to_demo_auto_order -ne $false -or
  [string]$receipt.broker_mutation -ne "NOT_PERFORMED" -or
  [string]$v4Task.State -ne "Disabled" -or
  [string]$v5Task.State -ne "Disabled" -or
  [string]$task.State -notin @("Ready", "Running")
) {
  throw "Installed scheduler readiness projection mismatch."
}

$now = [DateTimeOffset]::Now
if ($now -lt $firstBoundary) {
  $expectedNextRun = [DateTime]::ParseExact(
    "2026-07-30T06:45:00",
    "yyyy-MM-ddTHH:mm:ss",
    [Globalization.CultureInfo]::InvariantCulture
  )
  if (
    [string]$task.State -ne "Ready" -or
    [DateTime]$taskInfo.NextRunTime -ne $expectedNextRun
  ) {
    throw "Pre-boundary task state or exact next run time mismatch."
  }
}

[PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_V6_TRIGGER_AUDIT_READY"
  ObservedAtUtc = [DateTimeOffset]::UtcNow.ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ"
  )
  TaskName = $taskName
  TaskState = $task.State
  NextRunTime = $taskInfo.NextRunTime
  OperationalLog = $taskSchedulerChannel
  OperationalLogEnabled = $true
  AutomaticBoundary = "2026-07-30T06:45:00+09:00"
  ManualStartRequired = $false
  TriggerEvidenceCollection = "PENDING_AUTOMATIC_RUN"
  ProvenanceScope = "LOCAL_HOST_EVENT_LOG"
  IndependentAttestationPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
