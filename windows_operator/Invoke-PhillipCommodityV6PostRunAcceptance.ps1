[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter()]
  [string]$OperatorRoot = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-v6-scheduler-operator-14762eac"
  ),

  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER",

  [Parameter()]
  [string]$RuntimeRepo = (
    "C:\AI_SCALPER_RELEASES\" +
    "290cc23d-phillip-commodity-shadow-source"
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
  ),

  [Parameter()]
  [string]$Output = (
    "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-postrun-acceptance\" +
    "phillip-commodity-v6-postrun-" +
    [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
    ".zip"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolkitSourceCommit = "__TOOLKIT_SOURCE_COMMIT__"
$toolkitSourceTree = "__TOOLKIT_SOURCE_TREE__"
$expectedToolSHA256 = "__POSTRUN_TOOL_SHA256__"
$expectedHealthSHA256 = (
  "29b1cc9958d9f471a6664eea449f272c" +
  "a539d750fa5778586303c7272990c1e5"
)
$taskName = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
$v4TaskName = "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow"
$v5TaskName = "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow"
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-task-review"
)
$auditRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-v5-290cc23-audit-exports"
)
$healthPath = Join-Path $OperatorRoot (
  "Test-PhillipCommodityV6TaskHealth.ps1"
)
$toolPath = Join-Path $PSScriptRoot (
  "phillip_commodity_v6_postrun_acceptance.py"
)
$toolkitManifestPath = Join-Path $PSScriptRoot (
  "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT.json"
)
$installationReceiptPath = Join-Path $taskReviewRoot (
  "$taskName.installation-receipt.json"
)
$installedTaskXmlPath = Join-Path $taskReviewRoot (
  "$taskName.installed.xml"
)
$checkpointRoot = Join-Path $taskReviewRoot "evidence-checkpoints"
$healthTranscriptPath = Join-Path ([System.IO.Path]::GetTempPath()) (
  "ai-scalper-phillip-v6-health-" +
  [Guid]::NewGuid().ToString("N") +
  ".txt"
)

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

function Assert-NonReparseDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
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

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
foreach ($path in @(
  $ToolkitArchive,
  $ReleasePython,
  $healthPath,
  $toolPath,
  $toolkitManifestPath,
  $installationReceiptPath,
  $installedTaskXmlPath
)) {
  Assert-RegularNonReparseFile -Path $path
}
foreach ($path in @($PSScriptRoot, $OperatorRoot, $checkpointRoot, $auditRoot)) {
  Assert-NonReparseDirectory -Path $path
}

$expectedArchiveHash = $ExpectedToolkitArchiveSHA256.ToLowerInvariant()
$observedArchiveHash = (
  Get-FileHash -LiteralPath $ToolkitArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observedArchiveHash -ne $expectedArchiveHash) {
  throw "Post-run toolkit archive SHA-256 mismatch."
}
$observedToolHash = (
  Get-FileHash -LiteralPath $toolPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observedToolHash -ne $expectedToolSHA256) {
  throw "Post-run Python tool SHA-256 mismatch."
}
$observedHealthHash = (
  Get-FileHash -LiteralPath $healthPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observedHealthHash -ne $expectedHealthSHA256) {
  throw "Installed V6.3 health checker SHA-256 mismatch."
}

$toolkitVerificationOutput = @(
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
  $toolkitVerificationOutput
  throw "Post-run toolkit verification failed."
}
$toolkitVerification = (
  $toolkitVerificationOutput -join [Environment]::NewLine
) | ConvertFrom-Json
if (
  $toolkitVerification.status -ne
    "PHILLIP_COMMODITY_V6_POSTRUN_TOOLKIT_VERIFIED" -or
  $toolkitVerification.archive_sha256 -ne $expectedArchiveHash -or
  $toolkitVerification.source_commit -ne $toolkitSourceCommit -or
  $toolkitVerification.source_tree -ne $toolkitSourceTree -or
  $toolkitVerification.order_capability -ne "DISABLED" -or
  $toolkitVerification.live_allowed -ne $false -or
  $toolkitVerification.task_scheduler_mutation -ne "NOT_PERFORMED" -or
  $toolkitVerification.broker_mutation -ne "NOT_PERFORMED"
) {
  throw "Post-run toolkit verification projection mismatch."
}

try {
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
    throw "Exact V6.3 health verification failed."
  }
  $healthRecords = @(
    $healthOutput | Where-Object {
      $null -ne $_.PSObject.Properties["Status"] -and
      [string]$_.Status -eq "PHILLIP_COMMODITY_V6_TASK_HEALTHY"
    }
  )
  if ($healthRecords.Count -ne 1) {
    throw "V6.3 health result count is not exactly one."
  }
  $healthResult = $healthRecords[0]
  if (
    [string]$healthResult.TaskName -ne $taskName -or
    [string]$healthResult.RemediationSourceCommit -ne
      "14762eac7e991fee8818ee20816709066f457f06" -or
    [string]$healthResult.FrozenWorkerCommit -ne
      "290cc23d9d87f93e914612afdfecfc481d2c232f" -or
    [string]$healthResult.FrozenWorkerTree -ne
      "ef568ae39aa4c51d9afe738badbb86d2c45e9a58" -or
    [string]$healthResult.Contract -ne
      "phillip-commodity-window-01-diagnostic-v5" -or
    [string]$healthResult.OrderCapability -ne "DISABLED" -or
    [bool]$healthResult.LiveAllowed -ne $false -or
    [string]$healthResult.TaskSchedulerMutation -ne "NOT_PERFORMED" -or
    [string]$healthResult.BrokerMutation -ne "NOT_PERFORMED" -or
    [bool]$healthResult.HealthMutexAbandoned -ne $false
  ) {
    throw "V6.3 health result projection mismatch."
  }
  $healthText = $healthResult | Format-List * | Out-String -Width 4096
  [System.IO.File]::WriteAllText(
    $healthTranscriptPath,
    $healthText,
    [System.Text.UTF8Encoding]::new($false)
  )
  Assert-RegularNonReparseFile -Path $healthTranscriptPath

  $v4Task = Get-ScheduledTask -TaskName $v4TaskName -ErrorAction Stop
  $v5Task = Get-ScheduledTask -TaskName $v5TaskName -ErrorAction Stop
  $tokyo = [TimeZoneInfo]::FindSystemTimeZoneById(
    "Tokyo Standard Time"
  )
  $lastRunLocal = [DateTime]::SpecifyKind(
    [DateTime]$healthResult.LastRunTime,
    [DateTimeKind]::Unspecified
  )
  $lastRunUtc = [TimeZoneInfo]::ConvertTimeToUtc(
    $lastRunLocal,
    $tokyo
  ).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
  $observedAtUtc = [string]$healthResult.ObservedAtUtc
  $nextRunLocal = ([DateTime]$healthResult.NextRunTime).ToString(
    "yyyy-MM-ddTHH:mm:ss"
  )

  $collectOutput = @(
    & $ReleasePython `
      -I `
      -S `
      -B `
      $toolPath `
      collect `
      --toolkit-manifest $toolkitManifestPath `
      --installation-receipt $installationReceiptPath `
      --checkpoint-root $checkpointRoot `
      --audit-root $auditRoot `
      --installed-task-xml $installedTaskXmlPath `
      --health-transcript $healthTranscriptPath `
      --task-state ([string]$healthResult.TaskState) `
      --last-run-at-utc $lastRunUtc `
      --last-task-result ([int]$healthResult.LastTaskResult) `
      --next-run-time-local $nextRunLocal `
      --v4-task-state ([string]$v4Task.State) `
      --v5-task-state ([string]$v5Task.State) `
      --observed-at-utc $observedAtUtc `
      --output $Output `
      2>&1
  )
  if ($LASTEXITCODE -ne 0) {
    $collectOutput
    throw "Phillip Commodity V6 post-run collection failed."
  }
  $collection = (
    $collectOutput -join [Environment]::NewLine
  ) | ConvertFrom-Json
  if (
    $collection.status -ne
      "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_VERIFIED" -or
    $collection.order_capability -ne "DISABLED" -or
    $collection.live_allowed -ne $false -or
    $collection.offhost_custody_performed -ne $false
  ) {
    throw "Post-run collection projection mismatch."
  }

  Assert-RegularNonReparseFile -Path $Output
  $acceptanceArchiveSHA256 = (
    Get-FileHash -LiteralPath $Output -Algorithm SHA256
  ).Hash.ToLowerInvariant()
  $acceptanceVerificationOutput = @(
    & $ReleasePython `
      -I `
      -S `
      -B `
      $toolPath `
      verify `
      --archive $Output `
      --expected-archive-sha256 $acceptanceArchiveSHA256 `
      --expected-toolkit-source-commit $toolkitSourceCommit `
      --expected-toolkit-source-tree $toolkitSourceTree `
      2>&1
  )
  if ($LASTEXITCODE -ne 0) {
    $acceptanceVerificationOutput
    throw "Post-run acceptance archive verification failed."
  }
  $acceptance = (
    $acceptanceVerificationOutput -join [Environment]::NewLine
  ) | ConvertFrom-Json
  if (
    $acceptance.status -ne
      "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_VERIFIED" -or
    $acceptance.archive_sha256 -ne $acceptanceArchiveSHA256 -or
    $acceptance.order_capability -ne "DISABLED" -or
    $acceptance.live_allowed -ne $false -or
    $acceptance.promotion_eligible -ne $false -or
    $acceptance.offhost_custody_performed -ne $false
  ) {
    throw "Post-run acceptance verification projection mismatch."
  }

  [PSCustomObject]@{
    Status = "PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_READY"
    Archive = $Output
    ArchiveSHA256 = $acceptanceArchiveSHA256
    BundleIdentitySHA256 = $acceptance.bundle_identity_sha256
    ToolkitSourceCommit = $toolkitSourceCommit
    ToolkitSourceTree = $toolkitSourceTree
    CheckpointHMACSHA256 = $acceptance.checkpoint_hmac_sha256
    LatestHeartbeatAtUtc = $acceptance.latest_heartbeat_at_utc
    SourceEventCount = $acceptance.source_event_count
    TaskState = $healthResult.TaskState
    LastTaskResult = $healthResult.LastTaskResult
    CopyInstruction = "COPY_ZIP_TO_INDEPENDENT_OFFHOST_WORM"
    OffhostCustodyPerformed = $false
    OrderCapability = "DISABLED"
    LiveAllowed = $false
    PromotionEligible = $false
    TaskSchedulerMutation = "NOT_PERFORMED"
    BrokerMutation = "NOT_PERFORMED"
  } | Format-List
}
finally {
  if (Test-Path -LiteralPath $healthTranscriptPath) {
    Remove-Item `
      -LiteralPath $healthTranscriptPath `
      -Force `
      -ErrorAction Stop
  }
}
