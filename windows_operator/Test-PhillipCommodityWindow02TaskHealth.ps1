[CmdletBinding()]
param(
  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER",

  [Parameter()]
  [string]$RuntimeRepo = (
    "C:\AI_SCALPER_RELEASES\" +
    "da319001-phillip-commodity-window-02-shadow-source-r5"
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
  [string]$TaskName = (
    "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$packageSourceCommit = "__PACKAGE_SOURCE_COMMIT__"
$packageSourceTree = "__PACKAGE_SOURCE_TREE__"
$workerCommit = "da3190013d86426533019d6927a58181c624b1f8"
$workerTree = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"
$contractId = "phillip-commodity-window-02-diagnostic-v1"
$snapshotId = "phillip-commodity-dev-pre-window-02-v1"
$expectedContractPayloadSha256 = (
  "cbfd753b0aed2d66af56446adc734ce8" +
  "d62666e309e91bf74d24b4cc56b613a2"
)
$expectedContractFileSha256 = (
  "ad4fd8853563976483fbffbd3bd97847" +
  "f7e05c8a4194afd10fa95832e2fe485b"
)
$expectedBuildIdentitySha256 = (
  "9d64b8c9be0b42bdc991b767a7452587" +
  "74a57f80613e2fd322791d6d18cc6287"
)
$expectedSigningKeyId = "105e393cd619804e"
$expectedDependencyLockSha256 = (
  "34087f736724e7d92591f7886f565b15" +
  "436c59de0d4e80a59e42b04f2851d862"
)
$expectedTaskContractSha256 = "__TASK_CONTRACT_SHA256__"
$expectedContractVerifierSha256 = "__CONTRACT_VERIFIER_SHA256__"
$firstScheduledStart = [datetime]::Parse("2026-08-17T06:45:00")
$scheduleEndBoundary = [datetime]::Parse("2026-10-13T00:16:00")
$workerDurationSeconds = 84300
$startupAllowanceSeconds = 300
$priorTaskNames = @(
  "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
)

$runtimeStateRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-runtime-r5"
)
$journal = Join-Path $runtimeStateRoot (
  "phillip-commodity-shadow-cycles-window-02.sqlite3"
)
$auditRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-audit-exports-r5"
)
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-task-review-r5"
)
$reviewXmlPath = Join-Path $taskReviewRoot "$TaskName.review.xml"
$registeredDisabledXmlPath = Join-Path $taskReviewRoot (
  "$TaskName.registered-disabled.xml"
)
$installedXmlPath = Join-Path $taskReviewRoot "$TaskName.installed.xml"
$receiptPath = Join-Path $taskReviewRoot (
  "$TaskName.installation-receipt.json"
)
$artifactRoot = Join-Path $Repo "validation_artifacts"
$taskContract = Join-Path $PSScriptRoot "PhillipCommodityTaskContract.ps1"
$contractVerifier = Join-Path $PSScriptRoot (
  "verify_phillip_commodity_window_02_contract.py"
)

function Assert-RegularNonReparseFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Required file is unavailable: $Path"
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

function Invoke-CheckedGit {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$Operation
  )
  $records = @()
  $exitCode = $null
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    # Windows PowerShell 5.1 surfaces native stderr as ErrorRecord objects.
    # Capture Git progress without allowing benign stderr to terminate health.
    $ErrorActionPreference = "Continue"
    $LASTEXITCODE = $null
    $records = @(& git @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  $outputLines = @($records | ForEach-Object { $_.ToString() })
  $output = ($outputLines -join [Environment]::NewLine).Trim()
  if ($null -eq $exitCode) {
    throw "$Operation did not report a native process exit code."
  }
  if ($exitCode -ne 0) {
    throw "$Operation failed with exit code $exitCode."
  }
  return $output
}

function Invoke-CheckedNativeProcess {
  param(
    [Parameter(Mandatory = $true)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$Operation
  )
  $records = @()
  $exitCode = $null
  $previousErrorActionPreference = $ErrorActionPreference
  try {
    # Windows PowerShell 5.1 promotes native stderr to ErrorRecord. Native
    # success is decided only by the freshly captured process exit code.
    $ErrorActionPreference = "Continue"
    $LASTEXITCODE = $null
    $records = @(& $FilePath @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
  }
  finally {
    $ErrorActionPreference = $previousErrorActionPreference
  }
  $outputLines = @($records | ForEach-Object { $_.ToString() })
  $output = ($outputLines -join [Environment]::NewLine).Trim()
  if ($null -eq $exitCode) {
    throw "$Operation did not report a native process exit code."
  }
  if ($exitCode -ne 0) {
    if ([string]::IsNullOrWhiteSpace($output)) {
      throw "$Operation failed with exit code $exitCode."
    }
    throw "$Operation failed with exit code $exitCode. Native output: $output"
  }
  return $output
}

function Get-ExactRootTask {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Name,

    [Parameter()]
    [switch]$Optional
  )
  $matches = @(
    Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
  )
  if (
    $matches.Count -gt 1 -or
    ($matches.Count -eq 1 -and $matches[0].TaskPath -ne "\")
  ) {
    throw "Task identity is not unique at the root path: $Name"
  }
  if ($matches.Count -eq 0) {
    if ($Optional) {
      return $null
    }
    throw "Task is unavailable at the root path: $Name"
  }
  return $matches[0]
}

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
foreach ($path in @(
  $PSCommandPath,
  $taskContract,
  $contractVerifier,
  $ReleasePython,
  $CommodityTerminal,
  $reviewXmlPath,
  $registeredDisabledXmlPath,
  $installedXmlPath,
  $receiptPath
)) {
  Assert-RegularNonReparseFile -Path $path
}
foreach ($path in @($RuntimeRepo, $runtimeStateRoot, $auditRoot, $taskReviewRoot)) {
  Assert-NonReparseDirectory -Path $path
}

$taskContractSha256 = (
  Get-FileHash -LiteralPath $taskContract -Algorithm SHA256
).Hash.ToLowerInvariant()
$contractVerifierSha256 = (
  Get-FileHash -LiteralPath $contractVerifier -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($taskContractSha256 -ne $expectedTaskContractSha256) {
  throw "Shared Task Scheduler contract hash mismatch."
}
if ($contractVerifierSha256 -ne $expectedContractVerifierSha256) {
  throw "Window 02 contract verifier hash mismatch."
}
. $taskContract
Assert-PhillipCommodityTaskContractSelfTest

$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
$expectedReceiptFields = @(
  "arguments",
  "audit_export_root",
  "broker_mutation",
  "build_identity_sha256",
  "command",
  "contract_artifact_files_verified",
  "contract_file_sha256",
  "contract_payload_sha256",
  "contract_verifier_sha256",
  "dependency_lock_sha256",
  "end_boundary",
  "evidence_root_sha256",
  "exported_task_xml_sha256",
  "frozen_runtime_repo",
  "frozen_runtime_worktree_lock",
  "health_checker_sha256",
  "installed_at_utc",
  "live_allowed",
  "minimum_installation_lead_seconds",
  "order_capability",
  "package_source_commit",
  "package_source_tree",
  "preserved_tasks",
  "registered_disabled_xml_sha256",
  "runtime_journal",
  "safe_to_demo_auto_order",
  "schema_version",
  "signing_key_id",
  "start_boundary",
  "task_contract_sha256",
  "task_definition_sha256",
  "task_name",
  "task_started_manually",
  "verified_next_run_time",
  "windows_sid",
  "worker_contract_id",
  "worker_duration_seconds",
  "worker_snapshot_id",
  "worker_source_commit",
  "worker_source_tree",
  "working_directory"
) | Sort-Object
$observedReceiptFields = @(
  $receipt.PSObject.Properties.Name | Sort-Object
)
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $currentIdentity.User) {
  throw "Current Windows SID is unavailable."
}
try {
  $installedAt = [DateTimeOffset]::Parse(
    [string]$receipt.installed_at_utc
  )
}
catch {
  throw "Window 02 installation timestamp is invalid."
}
$healthCheckerSha256 = (
  Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  ($observedReceiptFields -join ",") -cne
    ($expectedReceiptFields -join ",") -or
  $receipt.schema_version -ne
    "phillip-commodity-window-02-scheduler-installation-receipt-v1" -or
  $receipt.task_name -ne $TaskName -or
  $receipt.windows_sid -ne $currentIdentity.User.Value -or
  $installedAt -ge [DateTimeOffset]::Parse(
    "2026-08-16T21:45:00Z"
  ) -or
  $installedAt -gt [DateTimeOffset]::UtcNow -or
  $receipt.package_source_commit -ne $packageSourceCommit -or
  $receipt.package_source_tree -ne $packageSourceTree -or
  $receipt.worker_source_commit -ne $workerCommit -or
  $receipt.worker_source_tree -ne $workerTree -or
  $receipt.worker_contract_id -ne $contractId -or
  $receipt.worker_snapshot_id -ne $snapshotId -or
  $receipt.contract_payload_sha256 -ne $expectedContractPayloadSha256 -or
  $receipt.contract_file_sha256 -ne $expectedContractFileSha256 -or
  $receipt.build_identity_sha256 -ne $expectedBuildIdentitySha256 -or
  $receipt.signing_key_id -ne $expectedSigningKeyId -or
  $receipt.dependency_lock_sha256 -ne $expectedDependencyLockSha256 -or
  [int]$receipt.contract_artifact_files_verified -ne 9 -or
  $receipt.task_contract_sha256 -ne $taskContractSha256 -or
  $receipt.contract_verifier_sha256 -ne $contractVerifierSha256 -or
  $receipt.health_checker_sha256 -ne $healthCheckerSha256 -or
  $receipt.start_boundary -ne "2026-08-17T06:45:00+09:00" -or
  $receipt.end_boundary -ne "2026-10-13T00:16:00+09:00" -or
  [int]$receipt.worker_duration_seconds -ne $workerDurationSeconds -or
  [int]$receipt.minimum_installation_lead_seconds -ne 900 -or
  $receipt.verified_next_run_time -ne "2026-08-17T06:45:00" -or
  (@($receipt.preserved_tasks) -join ",") -cne
    ($priorTaskNames -join ",") -or
  $receipt.task_started_manually -ne $false -or
  $receipt.order_capability -ne "DISABLED" -or
  $receipt.live_allowed -ne $false -or
  $receipt.safe_to_demo_auto_order -ne $false -or
  $receipt.broker_mutation -ne "NOT_PERFORMED"
) {
  throw "Window 02 installation receipt identity or safety mismatch."
}
foreach ($hashValue in @(
  $receipt.contract_payload_sha256,
  $receipt.contract_file_sha256,
  $receipt.build_identity_sha256,
  $receipt.dependency_lock_sha256,
  $receipt.evidence_root_sha256,
  $receipt.task_contract_sha256,
  $receipt.contract_verifier_sha256,
  $receipt.health_checker_sha256,
  $receipt.task_definition_sha256,
  $receipt.registered_disabled_xml_sha256,
  $receipt.exported_task_xml_sha256
)) {
  if ([string]$hashValue -notmatch '^[0-9a-f]{64}$') {
    throw "Window 02 installation receipt hash is not canonical."
  }
}

$reviewSha256 = (
  Get-FileHash -LiteralPath $reviewXmlPath -Algorithm SHA256
).Hash.ToLowerInvariant()
$registeredDisabledSha256 = (
  Get-FileHash `
    -LiteralPath $registeredDisabledXmlPath `
    -Algorithm SHA256
).Hash.ToLowerInvariant()
$installedSha256 = (
  Get-FileHash -LiteralPath $installedXmlPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $reviewSha256 -ne $receipt.task_definition_sha256 -or
  $registeredDisabledSha256 -ne
    $receipt.registered_disabled_xml_sha256 -or
  $installedSha256 -ne $receipt.exported_task_xml_sha256
) {
  throw "Window 02 Task Scheduler XML evidence hash mismatch."
}

$runtimeHead = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD^{commit}") `
  -Operation "Frozen worker commit inspection"
$runtimeTree = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD^{tree}") `
  -Operation "Frozen worker tree inspection"
$runtimeDirty = Invoke-CheckedGit `
  -Arguments @(
    "-C", $RuntimeRepo, "status", "--porcelain=v1", "--untracked-files=all"
  ) `
  -Operation "Frozen worker status inspection"
if (
  $runtimeHead -ne $workerCommit -or
  $runtimeTree -ne $workerTree -or
  -not [string]::IsNullOrEmpty($runtimeDirty)
) {
  $runtimeDirty
  throw "Frozen Window 02 worker identity is invalid."
}
$worktreeLock = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "--git-path", "locked") `
  -Operation "Frozen runtime lock path inspection"
if (-not [System.IO.Path]::IsPathRooted($worktreeLock)) {
  $worktreeLock = Join-Path $RuntimeRepo $worktreeLock
}
Assert-RegularNonReparseFile -Path $worktreeLock
if ($receipt.frozen_runtime_worktree_lock -ne $worktreeLock) {
  throw "Frozen runtime lock binding mismatch."
}

$lock = Join-Path $RuntimeRepo "pylock.windows-cp312.toml"
Assert-RegularNonReparseFile -Path $lock
$verificationOutput = Invoke-CheckedNativeProcess `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $contractVerifier,
    "--runtime-repo", $RuntimeRepo,
    "--artifact-root", $artifactRoot,
    "--lock", $lock
  ) `
  -Operation "Window 02 contract health verification"
$contractVerification = $verificationOutput | ConvertFrom-Json
if (
  $contractVerification.status -ne
    "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED" -or
  $contractVerification.contract_id -ne $contractId -or
  $contractVerification.snapshot_id -ne $snapshotId -or
  $contractVerification.contract_payload_sha256 -ne
    $expectedContractPayloadSha256 -or
  $contractVerification.contract_file_sha256 -ne
    $expectedContractFileSha256 -or
  $contractVerification.build_identity_sha256 -ne
    $expectedBuildIdentitySha256 -or
  $contractVerification.signing_key_id -ne $expectedSigningKeyId -or
  $contractVerification.dependency_lock_sha256 -ne
    $expectedDependencyLockSha256 -or
  $contractVerification.order_capability -ne "DISABLED" -or
  $contractVerification.live_allowed -ne $false
) {
  throw "Window 02 contract health projection mismatch."
}

foreach ($priorTaskName in $priorTaskNames) {
  $priorTask = Get-ExactRootTask -Name $priorTaskName -Optional
  if ($null -ne $priorTask -and $priorTask.State -ne "Disabled") {
    throw "Historical task is no longer Disabled: $priorTaskName"
  }
}

$expectedArguments = @(
  "-I"
  "-S"
  "-B"
  "`"$RuntimeRepo\run_broker_shadow_once.py`""
  "--candidate phillip-commodity"
  "--terminal-path `"$CommodityTerminal`""
  "--artifact-root `"$artifactRoot`""
  "--journal `"$journal`""
  "--audit-export-dir `"$auditRoot`""
  "--worker"
  "--worker-duration-seconds $workerDurationSeconds"
) -join " "
if (
  $receipt.command -ne $ReleasePython -or
  $receipt.arguments -ne $expectedArguments -or
  $receipt.working_directory -ne $RuntimeRepo -or
  $receipt.frozen_runtime_repo -ne $RuntimeRepo -or
  $receipt.runtime_journal -ne $journal -or
  $receipt.audit_export_root -ne $auditRoot
) {
  throw "Window 02 installation receipt command binding mismatch."
}

$task = Get-ExactRootTask -Name $TaskName
$taskInfo = Get-ScheduledTaskInfo `
  -TaskName $TaskName `
  -TaskPath "\" `
  -ErrorAction Stop
$currentXmlText = Export-ScheduledTask `
  -TaskName $TaskName `
  -TaskPath "\" `
  -ErrorAction Stop
$currentBytes = [byte[]](
  [System.Text.Encoding]::Unicode.GetPreamble() +
  [System.Text.Encoding]::Unicode.GetBytes($currentXmlText)
)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
  $currentSha256 = (
    [System.BitConverter]::ToString(
      $sha256.ComputeHash($currentBytes)
    ).Replace("-", "").ToLowerInvariant()
  )
}
finally {
  $sha256.Dispose()
}
if ($currentSha256 -ne $installedSha256) {
  throw "Installed Window 02 Task Scheduler XML drift detected."
}
[xml]$currentXml = $currentXmlText
$semanticFailures = @(
  Get-PhillipCommodityTaskDefinitionFailures `
    -Task $task `
    -TaskXml $currentXml `
    -ExpectedSid ([string]$receipt.windows_sid) `
    -ExpectedCommand $ReleasePython `
    -ExpectedArguments $expectedArguments `
    -ExpectedWorkingDirectory $RuntimeRepo `
    -ExpectedStart ([DateTimeOffset]::Parse(
      "2026-08-17T06:45:00+09:00"
    )) `
    -ExpectedEnd ([DateTimeOffset]::Parse(
      "2026-10-13T00:16:00+09:00"
    ))
)
if ($semanticFailures.Count -ne 0) {
  throw "Window 02 task semantic drift: $($semanticFailures -join ', ')"
}

$now = Get-Date
$schedulePhase = Get-PhillipCommodityV6SchedulePhase `
  -Now $now `
  -FirstStart $firstScheduledStart `
  -EndBoundary $scheduleEndBoundary `
  -DurationSeconds $workerDurationSeconds `
  -StartupSeconds $startupAllowanceSeconds
$activeInterval = [bool]$schedulePhase.ActiveInterval
$startupAllowance = [bool]$schedulePhase.StartupAllowance
$lastScheduledStart = $schedulePhase.LastScheduledStart
$runtimeStatus = "NOT_YET_REQUIRED"

if ($task.State -eq "Disabled") {
  throw "Window 02 scheduled task is disabled."
}
if ($schedulePhase.Phase -eq "PRE_START") {
  if ($task.State -ne "Ready") {
    throw "Window 02 task is not Ready before its first boundary."
  }
  $expectedNextRun = [datetime]::Parse("2026-08-17T06:45:00")
  if ($taskInfo.NextRunTime -ne $expectedNextRun) {
    throw "Window 02 pre-start NextRunTime drift detected."
  }
}
else {
  $attemptedThisBoundary = (
    $taskInfo.LastRunTime -ge $lastScheduledStart.AddMinutes(-1) -and
    $taskInfo.LastRunTime -le $now.AddMinutes(1)
  )
  if ($activeInterval) {
    if ($startupAllowance) {
      if ($task.State -eq "Running" -and -not $attemptedThisBoundary) {
        throw "Window 02 running state lacks the current boundary start."
      }
      if ($task.State -eq "Queued" -and $attemptedThisBoundary) {
        throw "Window 02 queued state follows a recorded start attempt."
      }
      if ($task.State -eq "Ready" -and $attemptedThisBoundary) {
        throw "Window 02 worker exited during startup allowance."
      }
      if ($task.State -notin @("Running", "Queued", "Ready")) {
        throw "Window 02 task state is invalid during startup allowance."
      }
    }
    elseif ($task.State -ne "Running") {
      throw "Window 02 task is not Running during its active interval."
    }
  }
  elseif ($task.State -ne "Ready") {
    throw "Window 02 task is not Ready outside its active interval."
  }

  if (-not $startupAllowance) {
    if (
      $taskInfo.LastRunTime -lt $lastScheduledStart.AddMinutes(-1) -or
      $taskInfo.LastRunTime -gt $lastScheduledStart.AddMinutes(5)
    ) {
      throw "Last Window 02 task start is outside its scheduler boundary."
    }
    if (-not $activeInterval -and $taskInfo.LastTaskResult -ne 0) {
      throw "Last completed Window 02 worker returned a nonzero result."
    }
  }

  if ($activeInterval -and -not $startupAllowance) {
    Assert-RegularNonReparseFile -Path $journal
    $statusOutput = Invoke-CheckedNativeProcess `
      -FilePath $ReleasePython `
      -Arguments @(
        "-I", "-S", "-B",
        (Join-Path $RuntimeRepo "run_broker_shadow_once.py"),
        "--candidate", "phillip-commodity",
        "--artifact-root", $artifactRoot,
        "--journal", $journal,
        "--heartbeat-stale-seconds", "180",
        "--status-only"
      ) `
      -Operation "Authenticated Window 02 runtime status"
    $runtimeStatus = "AUTHENTICATED_HEALTHY"
  }
}

[PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY"
  ObservedAtUtc = [DateTimeOffset]::UtcNow.ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ"
  )
  TaskName = $TaskName
  TaskState = $task.State
  LastRunTime = $taskInfo.LastRunTime
  LastTaskResult = $taskInfo.LastTaskResult
  NextRunTime = $taskInfo.NextRunTime
  SchedulePhase = $schedulePhase.Phase
  ExpectedActiveInterval = $activeInterval
  StartupAllowance = $startupAllowance
  RuntimeStatus = $runtimeStatus
  PackageSourceCommit = $packageSourceCommit
  FrozenWorkerCommit = $runtimeHead
  FrozenWorkerTree = $runtimeTree
  Contract = $contractId
  ContractPayloadSHA256 = $expectedContractPayloadSha256
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
