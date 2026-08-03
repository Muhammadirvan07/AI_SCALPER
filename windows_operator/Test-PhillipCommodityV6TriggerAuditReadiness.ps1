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

function Get-ExactRootScheduledTask {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $matches = @(
    Get-ScheduledTask -TaskName $Name -ErrorAction Stop
  )
  if ($matches.Count -ne 1) {
    throw "Scheduled task name is not unique: $Name"
  }
  $task = $matches[0]
  $taskPathProperty = $task.PSObject.Properties["TaskPath"]
  if ($null -eq $taskPathProperty) {
    throw "Scheduled task path is unavailable: $Name"
  }
  $taskPath = [string]$taskPathProperty.Value
  if ($taskPath -ne "\") {
    throw "Scheduled task is not registered at the root path: $Name"
  }
  return $task
}

function Get-RequiredObjectPropertyValue {
  param(
    [Parameter(Mandatory = $true)]
    [object]$InputObject,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $property = $InputObject.PSObject.Properties[$Name]
  if ($null -eq $property) {
    throw "Required scheduled-task property is unavailable: $Name"
  }
  return $property.Value
}

function Get-RequiredBooleanObjectPropertyValue {
  param(
    [Parameter(Mandatory = $true)]
    [object]$InputObject,

    [Parameter(Mandatory = $true)]
    [string]$Name
  )
  $value = Get-RequiredObjectPropertyValue `
    -InputObject $InputObject `
    -Name $Name
  if ($value -isnot [bool]) {
    throw "Required scheduled-task property is not boolean: $Name"
  }
  return [bool]$value
}

function Convert-TokyoLocalDateTimeToUtcText {
  param(
    [Parameter(Mandatory = $true)]
    [DateTime]$Value
  )
  $unspecified = [DateTime]::SpecifyKind(
    $Value,
    [DateTimeKind]::Unspecified
  )
  return [DateTimeOffset]::new(
    $unspecified,
    [TimeSpan]::FromHours(9)
  ).ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ss.fffffffZ",
    [Globalization.CultureInfo]::InvariantCulture
  )
}

function Convert-TokyoLocalDateTimeToOffsetText {
  param(
    [Parameter(Mandatory = $true)]
    [DateTime]$Value
  )
  $unspecified = [DateTime]::SpecifyKind(
    $Value,
    [DateTimeKind]::Unspecified
  )
  return [DateTimeOffset]::new(
    $unspecified,
    [TimeSpan]::FromHours(9)
  ).ToString(
    "yyyy-MM-ddTHH:mm:ss.fffffffzzz",
    [Globalization.CultureInfo]::InvariantCulture
  )
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

$task = Get-ExactRootScheduledTask -Name $taskName
$taskInfo = Get-ScheduledTaskInfo -InputObject $task -ErrorAction Stop
$v4Task = Get-ExactRootScheduledTask -Name $v4TaskName
$v5Task = Get-ExactRootScheduledTask -Name $v5TaskName
$taskEnabled = Get-RequiredBooleanObjectPropertyValue `
  -InputObject $task.Settings `
  -Name "Enabled"
$allowStartOnDemand = Get-RequiredBooleanObjectPropertyValue `
  -InputObject $task.Settings `
  -Name "AllowDemandStart"
$startWhenAvailable = Get-RequiredBooleanObjectPropertyValue `
  -InputObject $task.Settings `
  -Name "StartWhenAvailable"
$multipleInstances = [string](
  Get-RequiredObjectPropertyValue `
    -InputObject $task.Settings `
    -Name "MultipleInstances"
)
$principalLogonType = [string](
  Get-RequiredObjectPropertyValue `
    -InputObject $task.Principal `
    -Name "LogonType"
)
$principalUserId = [string](
  Get-RequiredObjectPropertyValue `
    -InputObject $task.Principal `
    -Name "UserId"
)
if (
  -not $taskEnabled -or
  $allowStartOnDemand -or
  $startWhenAvailable -or
  $multipleInstances -ne "IgnoreNew" -or
  $principalLogonType -notin @("Interactive", "InteractiveToken") -or
  [string]::IsNullOrWhiteSpace($principalUserId)
) {
  throw "Installed scheduler safety or interactive-session guard drift."
}
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

$observedAt = [DateTimeOffset]::UtcNow
$observedAtUtcText = $observedAt.ToString(
  "yyyy-MM-ddTHH:mm:ss.fffffffZ",
  [Globalization.CultureInfo]::InvariantCulture
)
$lastRunAtUtc = Convert-TokyoLocalDateTimeToUtcText `
  -Value ([DateTime]$taskInfo.LastRunTime)
$nextRunTimeLocal = Convert-TokyoLocalDateTimeToOffsetText `
  -Value ([DateTime]$taskInfo.NextRunTime)
$lastTaskResult = [Int64]$taskInfo.LastTaskResult
$taskState = [string]$task.State
$allowStartOnDemandText = if ($allowStartOnDemand) {
  "true"
}
else {
  "false"
}
$diagnosticOutput = @(
  & $ReleasePython `
    -I `
    -S `
    -B `
    $toolPath `
    diagnose-readiness `
    --observed-at-utc $observedAtUtcText `
    --last-run-at-utc $lastRunAtUtc `
    --last-task-result $lastTaskResult `
    --task-state $taskState `
    --next-run-time-local $nextRunTimeLocal `
    --allow-start-on-demand $allowStartOnDemandText `
    2>&1
)
if ($LASTEXITCODE -ne 0) {
  $diagnosticOutput
  throw "Trigger readiness diagnosis failed."
}
$diagnostic = (
  $diagnosticOutput -join [Environment]::NewLine
) | ConvertFrom-Json
if (
  [string]$diagnostic.status -ne
    "PHILLIP_COMMODITY_V6_TRIGGER_DIAGNOSTIC_READY" -or
  [bool]$diagnostic.acceptance_ready -ne $false -or
  [string]$diagnostic.order_capability -ne "DISABLED" -or
  [bool]$diagnostic.live_allowed -ne $false -or
  [string]$diagnostic.task_scheduler_mutation -ne "NOT_PERFORMED" -or
  [string]$diagnostic.broker_mutation -ne "NOT_PERFORMED"
) {
  throw "Trigger readiness diagnosis projection mismatch."
}

[PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_V6_TRIGGER_AUDIT_READY"
  ObservedAtUtc = $observedAt.ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ"
  )
  TaskName = $taskName
  TaskState = $task.State
  TaskEnabled = $taskEnabled
  TaskPrincipalUserId = $principalUserId
  TaskPrincipalLogonType = $principalLogonType
  AllowStartOnDemand = $allowStartOnDemand
  StartWhenAvailable = $startWhenAvailable
  MultipleInstances = $multipleInstances
  LastRunTime = $taskInfo.LastRunTime
  LastTaskResult = $taskInfo.LastTaskResult
  LastTaskResultHex = $diagnostic.last_task_result_hex
  LastRunClassification = $diagnostic.last_run_classification
  LatestExpectedBoundaryUtc = $diagnostic.latest_expected_boundary_utc
  LatestBoundaryStatus = $diagnostic.latest_boundary_status
  LatestBoundaryObserved = $diagnostic.latest_boundary_observed
  NextRunTime = $taskInfo.NextRunTime
  OperationalLog = $taskSchedulerChannel
  OperationalLogEnabled = $true
  AutomaticBoundary = "2026-07-30T06:45:00+09:00"
  ManualStartRequired = $false
  ManualStartProvenanceObserved = $false
  EventProvenanceInspected = $false
  TriggerEvidenceCollection = $diagnostic.trigger_evidence_collection
  AcceptanceReady = $false
  ProvenanceScope = "LOCAL_HOST_EVENT_LOG"
  IndependentAttestationPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
