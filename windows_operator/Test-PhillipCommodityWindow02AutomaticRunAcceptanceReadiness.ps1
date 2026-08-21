[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [string]$TargetBoundary,

  [Parameter()]
  [string]$SchedulerOperatorRoot = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-window-02-scheduler-operator-7416ce02"
  ),

  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER",

  [Parameter()]
  [string]$RuntimeRepo = (
    "C:\AI_SCALPER_RELEASES\" +
    "da319001-phillip-commodity-window-02-shadow-source-r6"
  ),

  [Parameter()]
  [string]$ReleasePython = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-ecedec9-venv\Scripts\python.exe"
  ),

  [Parameter()]
  [string]$CommodityTerminal = (
    "C:\Program Files\Phillip Securities Japan MT5 Terminal Commodity\" +
    "terminal64.exe"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolkitSourceCommit = "__TOOLKIT_SOURCE_COMMIT__"
$toolkitSourceTree = "__TOOLKIT_SOURCE_TREE__"
$expectedToolSHA256 = "__ACCEPTANCE_TOOL_SHA256__"
$expectedHealthSHA256 = (
  "27ea33b4d87d7b69b4c58fe91412bd77" +
  "4f584a22205cca305fb5246f0ce5eb3a"
)
$taskName = "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"
$priorTaskNames = @(
  "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
)
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-task-review-r6"
)
$installationReceiptPath = Join-Path $taskReviewRoot (
  "$taskName.installation-receipt.json"
)
$toolPath = Join-Path $PSScriptRoot (
  "phillip_commodity_window_02_automatic_run_acceptance.py"
)
$manifestPath = Join-Path $PSScriptRoot (
  "PHILLIP_COMMODITY_WINDOW_02_ACCEPTANCE_TOOLKIT.json"
)
$healthPath = Join-Path $SchedulerOperatorRoot (
  "Test-PhillipCommodityWindow02TaskHealth.ps1"
)
$operationalLog = "Microsoft-Windows-TaskScheduler/Operational"

function Assert-RegularNonReparseFile {
  param([Parameter(Mandatory = $true)][string]$Path)
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

function Assert-NonReparseDirectory {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Required directory is unavailable: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (
    ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
  ) {
    throw "Required directory must not be a reparse point: $Path"
  }
}

function Invoke-CheckedNative {
  param(
    [Parameter(Mandatory = $true)][string]$FilePath,
    [Parameter(Mandatory = $true)][string[]]$Arguments,
    [Parameter(Mandatory = $true)][string]$Operation
  )
  $records = @()
  $nativeExit = $null
  $oldErrorPreference = $ErrorActionPreference
  $hasNativePreference = Test-Path Variable:PSNativeCommandUseErrorActionPreference
  if ($hasNativePreference) {
    $oldNativePreference = $PSNativeCommandUseErrorActionPreference
  }
  try {
    $ErrorActionPreference = "Continue"
    if ($hasNativePreference) {
      $PSNativeCommandUseErrorActionPreference = $false
    }
    $records = @(& $FilePath @Arguments 2>&1)
    $nativeExit = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $oldErrorPreference
    if ($hasNativePreference) {
      $PSNativeCommandUseErrorActionPreference = $oldNativePreference
    }
  }
  $text = (@($records | ForEach-Object { $_.ToString() }) -join "`n").Trim()
  if ($null -eq $nativeExit -or $nativeExit -ne 0) {
    throw "$Operation failed with exit code $nativeExit. $text"
  }
  return $text
}

function Get-ExactRootTask {
  $matches = @(
    Get-ScheduledTask -TaskName $taskName -ErrorAction Stop |
      Where-Object { $_.TaskPath -eq "\" }
  )
  if ($matches.Count -ne 1) {
    throw "Window 02 task is not unique at the root path."
  }
  return $matches[0]
}

function Get-EffectiveTaskSetting {
  param(
    [Parameter(Mandatory = $true)][object]$Settings,
    [Parameter(Mandatory = $true)][string]$PropertyName
  )
  $cimProperty = $Settings.PSObject.Properties["CimInstanceProperties"]
  if ($null -ne $cimProperty -and $null -ne $cimProperty.Value) {
    $entry = $cimProperty.Value[$PropertyName]
    if ($null -ne $entry) {
      return [PSCustomObject]@{ Found = $true; Value = $entry.Value }
    }
  }
  $direct = $Settings.PSObject.Properties[$PropertyName]
  if ($null -ne $direct) {
    return [PSCustomObject]@{ Found = $true; Value = $direct.Value }
  }
  return [PSCustomObject]@{ Found = $false; Value = $null }
}

function Assert-ReceiptAcl {
  param([Parameter(Mandatory = $true)][object]$Receipt)
  $acl = Get-Acl -LiteralPath $installationReceiptPath -ErrorAction Stop
  if (-not [bool]$acl.AreAccessRulesProtected) {
    throw "READINESS_RECEIPT_ACL_REJECTED"
  }
  $owner = [System.Security.Principal.NTAccount]::new([string]$acl.Owner)
  $ownerSid = [string](
    $owner.Translate(
      [System.Security.Principal.SecurityIdentifier]
    ).Value
  )
  $authorized = @(
    "S-1-5-18", "S-1-5-32-544", [string]$Receipt.windows_sid
  ) | Sort-Object -Unique
  $writeMask = (
    [int64][System.Security.AccessControl.FileSystemRights]::Write -bor
    [int64][System.Security.AccessControl.FileSystemRights]::Modify -bor
    [int64][System.Security.AccessControl.FileSystemRights]::FullControl -bor
    [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor
    [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
  )
  $observed = @()
  $unauthorized = @()
  foreach ($rule in @($acl.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
  ))) {
    if (
      $rule.AccessControlType -ne
        [System.Security.AccessControl.AccessControlType]::Allow -or
      (([int64]$rule.FileSystemRights -band $writeMask) -eq 0)
    ) {
      continue
    }
    $sid = [string]$rule.IdentityReference.Value
    if ($sid -in $authorized) { $observed += $sid }
    else { $unauthorized += $sid }
  }
  if (
    $ownerSid -notin $authorized -or
    @($unauthorized | Sort-Object -Unique).Count -ne 0 -or
    @(Compare-Object `
      $authorized `
      @($observed | Sort-Object -Unique)
    ).Count -ne 0
  ) {
    throw "READINESS_RECEIPT_ACL_REJECTED"
  }
}

foreach ($path in @(
  $ToolkitArchive,
  $ReleasePython,
  $CommodityTerminal,
  $toolPath,
  $manifestPath,
  $healthPath,
  $installationReceiptPath
)) {
  Assert-RegularNonReparseFile -Path $path
}
foreach ($path in @($PSScriptRoot, $SchedulerOperatorRoot, $RuntimeRepo)) {
  Assert-NonReparseDirectory -Path $path
}
if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
$archiveHash = (
  Get-FileHash -LiteralPath $ToolkitArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($archiveHash -ne $ExpectedToolkitArchiveSHA256.ToLowerInvariant()) {
  throw "Acceptance toolkit archive SHA-256 mismatch."
}
$toolHash = (
  Get-FileHash -LiteralPath $toolPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($toolHash -ne $expectedToolSHA256) {
  throw "Acceptance Python tool SHA-256 mismatch."
}
$toolkitText = Invoke-CheckedNative `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $toolPath,
    "validate-toolkit",
    "--toolkit-manifest", $manifestPath,
    "--tool-path", $toolPath
  ) `
  -Operation "Extracted acceptance toolkit validation"
$toolkit = $toolkitText | ConvertFrom-Json
$archiveToolkitText = Invoke-CheckedNative `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $toolPath,
    "verify-toolkit-archive",
    "--archive", $ToolkitArchive,
    "--expected-archive-sha256", $ExpectedToolkitArchiveSHA256,
    "--expected-source-commit", $toolkitSourceCommit,
    "--expected-source-tree", $toolkitSourceTree
  ) `
  -Operation "Acceptance toolkit archive validation"
$archiveToolkit = $archiveToolkitText | ConvertFrom-Json
if (
  $toolkit.source_commit -ne $toolkitSourceCommit -or
  $toolkit.source_tree -ne $toolkitSourceTree -or
  $archiveToolkit.source_commit -ne $toolkit.source_commit -or
  $archiveToolkit.source_tree -ne $toolkit.source_tree -or
  $archiveToolkit.toolkit_identity_sha256 -ne
    $toolkit.toolkit_identity_sha256 -or
  $toolkit.order_capability -ne "DISABLED" -or
  $toolkit.live_allowed -ne $false
) {
  throw "Extracted acceptance toolkit identity mismatch."
}
$installationText = Invoke-CheckedNative `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $toolPath,
    "validate-installation-artifacts",
    "--installation-receipt", $installationReceiptPath,
    "--installed-task-xml", (Join-Path $taskReviewRoot "$taskName.installed.xml")
  ) `
  -Operation "Window 02 installation artifact validation"
$installation = $installationText | ConvertFrom-Json
if (
  $installation.status -ne
    "PHILLIP_COMMODITY_WINDOW_02_INSTALLATION_ARTIFACTS_VERIFIED" -or
  $installation.order_capability -ne "DISABLED" -or
  $installation.live_allowed -ne $false
) {
  throw "Window 02 installation artifact projection mismatch."
}
$boundaryText = Invoke-CheckedNative `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $toolPath,
    "boundary-info", "--target-boundary-local", $TargetBoundary
  ) `
  -Operation "Target automatic boundary validation"
$boundary = $boundaryText | ConvertFrom-Json
$receipt = Get-Content `
  -LiteralPath $installationReceiptPath `
  -Raw `
  -ErrorAction Stop |
  ConvertFrom-Json
Assert-ReceiptAcl -Receipt $receipt
$healthHash = (
  Get-FileHash -LiteralPath $healthPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($healthHash -ne $expectedHealthSHA256) {
  throw "Installed Window 02 health checker SHA-256 mismatch."
}
$task = Get-ExactRootTask
$taskInfo = Get-ScheduledTaskInfo `
  -TaskName $taskName `
  -TaskPath "\" `
  -ErrorAction Stop
$allowDemandStart = Get-EffectiveTaskSetting `
  -Settings $task.Settings `
  -PropertyName "AllowDemandStart"
if (
  -not $allowDemandStart.Found -or
  -not ($allowDemandStart.Value -is [bool]) -or
  [bool]$allowDemandStart.Value -ne $false
) {
  throw "Window 02 task must retain AllowStartOnDemand=false."
}
if ([string]$task.State -eq "Disabled") {
  throw "Window 02 task is disabled."
}
$targetLocal = [DateTimeOffset]::Parse([string]$boundary.local)
$targetUtc = [DateTimeOffset]::Parse([string]$boundary.utc)
$nowUtc = [DateTimeOffset]::UtcNow
if ($nowUtc -lt $targetUtc) {
  if (
    [string]$task.State -ne "Ready" -or
    $taskInfo.NextRunTime -ne $targetLocal.DateTime
  ) {
    throw "READINESS_TARGET_BOUNDARY_REJECTED"
  }
}
elseif ($nowUtc -lt $targetUtc.AddMinutes(5)) {
  if ([string]$task.State -notin @("Ready", "Queued", "Running")) {
    throw "READINESS_TARGET_BOUNDARY_REJECTED"
  }
}
else {
  $tokyo = [TimeZoneInfo]::FindSystemTimeZoneById("Tokyo Standard Time")
  $lastRunUnspecified = [DateTime]::SpecifyKind(
    $taskInfo.LastRunTime,
    [DateTimeKind]::Unspecified
  )
  $lastRunUtc = [DateTimeOffset]::new(
    [TimeZoneInfo]::ConvertTimeToUtc($lastRunUnspecified, $tokyo)
  )
  if (
    $lastRunUtc -lt $targetUtc.AddMinutes(-1) -or
    $lastRunUtc -gt $targetUtc.AddMinutes(5)
  ) {
    throw "READINESS_TARGET_BOUNDARY_REJECTED"
  }
}
$obsoleteWindow02Tasks = @(
  Get-ScheduledTask -ErrorAction Stop |
    Where-Object {
      $_.TaskPath -eq "\" -and
      $_.TaskName -like "AI_SCALPER-PhillipCommodityWindow02*" -and
      $_.TaskName -ne $taskName
    }
)
if (@($obsoleteWindow02Tasks | Where-Object {
  [string]$_.State -ne "Disabled"
}).Count -ne 0) {
  throw "READINESS_OBSOLETE_WINDOW_02_TASK_REJECTED"
}
$log = Get-WinEvent -ListLog $operationalLog -ErrorAction Stop
if ($null -eq $log -or [bool]$log.IsEnabled -ne $true) {
  throw "Task Scheduler Operational log must already be enabled."
}
$terminalProcesses = @(
  Get-CimInstance Win32_Process -Filter "Name='terminal64.exe'" |
    Where-Object { $_.ExecutablePath -eq $CommodityTerminal }
)
if ($terminalProcesses.Count -ne 1) {
  throw "Exact Phillip Commodity MT5 process count must be one."
}
$healthOutput = @(
  & $healthPath `
    -Repo $Repo `
    -RuntimeRepo $RuntimeRepo `
    -ReleasePython $ReleasePython `
    -CommodityTerminal $CommodityTerminal `
    -TaskName $taskName `
    2>&1
)
if (-not $?) {
  $healthOutput
  throw "Installed Window 02 health verification failed."
}
$healthText = ($healthOutput | Out-String -Width 4096)
if (
  $healthText -notmatch "PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY" -or
  $healthText -notmatch "OrderCapability\s*:\s*DISABLED" -or
  $healthText -notmatch "LiveAllowed\s*:\s*False"
) {
  throw "Installed Window 02 health projection mismatch."
}
$historicalBoundaryMatch = [regex]::Match(
  $healthText,
  "(?m)^HistoricalBoundaryStatus\s*:\s*(\S+)\s*$"
)
if (-not $historicalBoundaryMatch.Success) {
  throw "Installed Window 02 historical-boundary projection is missing."
}
$historicalBoundaryStatus = $historicalBoundaryMatch.Groups[1].Value
if ($historicalBoundaryStatus -notin @(
  "NOT_APPLICABLE",
  "MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY"
)) {
  throw "Installed Window 02 historical-boundary projection mismatch."
}
if (
  $historicalBoundaryStatus -eq
    "MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY" -and
  $nowUtc -ge $targetUtc
) {
  throw "Historical missed-boundary evidence cannot accept a current run."
}

[PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_READY"
  ObservedAtUtc = [DateTimeOffset]::UtcNow.ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ"
  )
  TaskName = $taskName
  TaskState = [string]$task.State
  LastRunTime = $taskInfo.LastRunTime
  LastTaskResult = $taskInfo.LastTaskResult
  NextRunTime = $taskInfo.NextRunTime
  TargetBoundaryLocal = [string]$boundary.local
  TargetBoundaryUtc = [string]$boundary.utc
  HistoricalBoundaryStatus = $historicalBoundaryStatus
  HistoricalMissedBoundaryVerified = (
    $historicalBoundaryStatus -eq
      "MISSED_SCHEDULE_VERIFIED_NEXT_BOUNDARY_READY"
  )
  OperationalLogEnabled = [bool]$log.IsEnabled
  CommodityMT5ProcessId = [int]$terminalProcesses[0].ProcessId
  ToolkitSourceCommit = $toolkitSourceCommit
  ToolkitSourceTree = $toolkitSourceTree
  ManualStartPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  SafeToDemoAutoOrder = $false
  PromotionEligible = $false
  BrokerOrderCount = 0
  BrokerOrderSubmissionPerformed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
