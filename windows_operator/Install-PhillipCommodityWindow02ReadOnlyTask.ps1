[CmdletBinding()]
param(
  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER",

  [Parameter()]
  [string]$RuntimeRepo = (
    "C:\AI_SCALPER_RELEASES\" +
    "da319001-phillip-commodity-window-02-shadow-source-r4"
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
$branch = "agent/live-grade-phase3"
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
$expectedHealthCheckerSha256 = "__HEALTH_CHECKER_SHA256__"
$firstTaskStart = [DateTimeOffset]::Parse("2026-08-16T21:45:00Z")
$firstTaskStartLocal = [DateTimeOffset]::Parse(
  "2026-08-17T06:45:00+09:00"
)
$scheduleEndLocal = [DateTimeOffset]::Parse(
  "2026-10-13T00:16:00+09:00"
)
$minimumInstallationLeadSeconds = 900
$workerDurationSeconds = 84300
$priorTaskNames = @(
  "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
)

$runtimeStateRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-runtime-r4"
)
$journal = Join-Path $runtimeStateRoot (
  "phillip-commodity-shadow-cycles-window-02.sqlite3"
)
$auditRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-audit-exports-r4"
)
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-task-review-r4"
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
$contractFile = Join-Path $artifactRoot "forward\$contractId\contract.json"
$taskContract = Join-Path $PSScriptRoot "PhillipCommodityTaskContract.ps1"
$contractVerifier = Join-Path $PSScriptRoot (
  "verify_phillip_commodity_window_02_contract.py"
)
$healthChecker = Join-Path $PSScriptRoot (
  "Test-PhillipCommodityWindow02TaskHealth.ps1"
)

function Write-CreateExclusiveFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [byte[]]$Bytes
  )
  $stream = [System.IO.File]::Open(
    $Path,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None
  )
  try {
    $stream.Write($Bytes, 0, $Bytes.Length)
    $stream.Flush($true)
  }
  finally {
    $stream.Dispose()
  }
}

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
    # Windows PowerShell 5.1 converts native stderr into ErrorRecord objects.
    # Git writes normal progress (for example, "Preparing worktree") there,
    # so Stop would incorrectly turn a successful native process into a
    # terminating NativeCommandError before LASTEXITCODE can be inspected.
    $ErrorActionPreference = "Continue"
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

function Assert-MinimumInstallationLead {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Operation
  )
  $remainingSeconds = (
    $firstTaskStart - [DateTimeOffset]::UtcNow
  ).TotalSeconds
  if ($remainingSeconds -lt $minimumInstallationLeadSeconds) {
    throw (
      "$Operation requires at least " +
      "$minimumInstallationLeadSeconds seconds before the first boundary."
    )
  }
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

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
  throw "Current Windows SID is unavailable."
}
$windowsPrincipal = [System.Security.Principal.WindowsPrincipal]::new(
  $identity
)
if ($windowsPrincipal.IsInRole(
  [System.Security.Principal.WindowsBuiltInRole]::Administrator
)) {
  throw (
    "Run Window 02 installation from non-Administrator PowerShell so " +
    "contract ACL verification uses the same limited token as the task."
  )
}
$sid = $identity.User.Value

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
Assert-MinimumInstallationLead -Operation "Window 02 installation"
foreach ($path in @(
  $ReleasePython,
  $CommodityTerminal,
  $contractFile,
  $taskContract,
  $contractVerifier,
  $healthChecker
)) {
  Assert-RegularNonReparseFile -Path $path
}
Assert-NonReparseDirectory -Path $Repo

$taskContractSha256 = (
  Get-FileHash -LiteralPath $taskContract -Algorithm SHA256
).Hash.ToLowerInvariant()
$contractVerifierSha256 = (
  Get-FileHash -LiteralPath $contractVerifier -Algorithm SHA256
).Hash.ToLowerInvariant()
$healthCheckerSha256 = (
  Get-FileHash -LiteralPath $healthChecker -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($taskContractSha256 -ne $expectedTaskContractSha256) {
  throw "Shared Task Scheduler contract hash mismatch."
}
if ($contractVerifierSha256 -ne $expectedContractVerifierSha256) {
  throw "Window 02 contract verifier hash mismatch."
}
if ($healthCheckerSha256 -ne $expectedHealthCheckerSha256) {
  throw "Window 02 health checker hash mismatch."
}
. $taskContract
Assert-PhillipCommodityTaskContractSelfTest

$packageCommitObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$packageSourceCommit^{commit}") `
  -Operation "Package source commit inspection"
$packageTreeObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$packageSourceCommit^{tree}") `
  -Operation "Package source tree inspection"
$workerCommitObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$workerCommit^{commit}") `
  -Operation "Worker source commit inspection"
$workerTreeObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$workerCommit^{tree}") `
  -Operation "Worker source tree inspection"
if (
  $packageCommitObject -ne $packageSourceCommit -or
  $packageTreeObject -ne $packageSourceTree -or
  $workerCommitObject -ne $workerCommit -or
  $workerTreeObject -ne $workerTree
) {
  throw "Package or worker source identity mismatch."
}
foreach ($sourceCommit in @($packageSourceCommit, $workerCommit)) {
  & git -C $Repo merge-base --is-ancestor $sourceCommit "origin/$branch"
  if ($LASTEXITCODE -ne 0) {
    throw "Required source commit is not on the official branch."
  }
}

foreach ($priorTaskName in $priorTaskNames) {
  $priorTask = Get-ExactRootTask -Name $priorTaskName -Optional
  if ($null -ne $priorTask -and $priorTask.State -ne "Disabled") {
    throw "Historical task must remain Disabled: $priorTaskName"
  }
}
if ($null -ne (Get-ExactRootTask -Name $TaskName -Optional)) {
  throw "Window 02 task already exists; it will not be overwritten."
}
foreach ($path in @(
  $RuntimeRepo,
  $runtimeStateRoot,
  $auditRoot,
  $taskReviewRoot
)) {
  if (Test-Path -LiteralPath $path) {
    throw "Window 02 output already exists; preserve it: $path"
  }
}

Assert-MinimumInstallationLead -Operation "Window 02 worktree creation"
Invoke-CheckedGit `
  -Arguments @(
    "-C", $Repo, "worktree", "add", "--detach", $RuntimeRepo,
    $workerCommit
  ) `
  -Operation "Frozen Window 02 worktree creation" |
  Out-Null
Invoke-CheckedGit `
  -Arguments @(
    "-C", $Repo, "worktree", "lock", "--reason",
    "Phillip Commodity Window 02 immutable worker", $RuntimeRepo
  ) `
  -Operation "Frozen Window 02 worktree lock" |
  Out-Null
Assert-NonReparseDirectory -Path $RuntimeRepo
$runtimeHead = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD^{commit}") `
  -Operation "Frozen worker commit verification"
$runtimeTree = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD^{tree}") `
  -Operation "Frozen worker tree verification"
$runtimeDirty = Invoke-CheckedGit `
  -Arguments @(
    "-C", $RuntimeRepo, "status", "--porcelain=v1", "--untracked-files=all"
  ) `
  -Operation "Frozen worker status verification"
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
  -Operation "Frozen worktree lock inspection"
if (-not [System.IO.Path]::IsPathRooted($worktreeLock)) {
  $worktreeLock = Join-Path $RuntimeRepo $worktreeLock
}
Assert-RegularNonReparseFile -Path $worktreeLock

$lock = Join-Path $RuntimeRepo "pylock.windows-cp312.toml"
Assert-RegularNonReparseFile -Path $lock
$verificationOutput = @()
$verificationExitCode = $null
$previousErrorActionPreference = $ErrorActionPreference
try {
  $ErrorActionPreference = "Continue"
  $verificationOutput = @(
    & $ReleasePython -I -S -B `
      $contractVerifier `
      --runtime-repo $RuntimeRepo `
      --artifact-root $artifactRoot `
      --lock $lock 2>&1
  )
  $verificationExitCode = $LASTEXITCODE
}
finally {
  $ErrorActionPreference = $previousErrorActionPreference
}
if ($null -eq $verificationExitCode) {
  throw "Window 02 contract preflight did not report an exit code."
}
if ($verificationExitCode -ne 0) {
  $verificationOutput
  throw "Window 02 contract preflight failed under the limited token."
}
$contractVerification = (
  $verificationOutput -join [Environment]::NewLine
) | ConvertFrom-Json
if (
  $contractVerification.status -ne
    "PHILLIP_COMMODITY_WINDOW_02_CONTRACT_AUTHENTICATED" -or
  $contractVerification.contract_id -ne $contractId -or
  $contractVerification.snapshot_id -ne $snapshotId -or
  $contractVerification.worker_source_commit -ne $workerCommit -or
  $contractVerification.worker_source_tree -ne $workerTree -or
  $contractVerification.contract_payload_sha256 -ne
    $expectedContractPayloadSha256 -or
  $contractVerification.contract_file_sha256 -ne
    $expectedContractFileSha256 -or
  $contractVerification.build_identity_sha256 -ne
    $expectedBuildIdentitySha256 -or
  $contractVerification.signing_key_id -ne $expectedSigningKeyId -or
  $contractVerification.dependency_lock_sha256 -ne
    $expectedDependencyLockSha256 -or
  [int]$contractVerification.artifact_files_verified -ne 9 -or
  [int]$contractVerification.initial_segment_count -ne 0 -or
  [int]$contractVerification.initial_raw_tick_partition_count -ne 0 -or
  $contractVerification.order_capability -ne "DISABLED" -or
  $contractVerification.live_allowed -ne $false -or
  $contractVerification.safe_to_demo_auto_order -ne $false
) {
  throw "Window 02 contract preflight projection mismatch."
}

New-Item -ItemType Directory -Path $runtimeStateRoot -ErrorAction Stop |
  Out-Null
New-Item -ItemType Directory -Path $auditRoot -ErrorAction Stop |
  Out-Null
New-Item -ItemType Directory -Path $taskReviewRoot -ErrorAction Stop |
  Out-Null
foreach ($path in @($runtimeStateRoot, $auditRoot, $taskReviewRoot)) {
  Assert-NonReparseDirectory -Path $path
}

$workerArguments = @(
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

$xmlCommand = [System.Security.SecurityElement]::Escape($ReleasePython)
$xmlArguments = [System.Security.SecurityElement]::Escape($workerArguments)
$xmlWorkingDirectory = [System.Security.SecurityElement]::Escape($RuntimeRepo)
$xmlSid = [System.Security.SecurityElement]::Escape($sid)
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AI_SCALPER Phillip Commodity Window 02 diagnostic read-only shadow worker; no order capability.</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-08-17T06:45:00+09:00</StartBoundary>
      <EndBoundary>2026-10-13T00:16:00+09:00</EndBoundary>
      <Enabled>true</Enabled>
      <ScheduleByWeek>
        <DaysOfWeek>
          <Monday />
          <Tuesday />
          <Wednesday />
          <Thursday />
          <Friday />
        </DaysOfWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$xmlSid</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>false</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>false</AllowStartOnDemand>
    <Enabled>false</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$xmlCommand</Command>
      <Arguments>$xmlArguments</Arguments>
      <WorkingDirectory>$xmlWorkingDirectory</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$unicode = [System.Text.Encoding]::Unicode
$reviewBytes = [byte[]](
  $unicode.GetPreamble() + $unicode.GetBytes($taskXml)
)
Write-CreateExclusiveFile -Path $reviewXmlPath -Bytes $reviewBytes
$reviewSha256 = (
  Get-FileHash -LiteralPath $reviewXmlPath -Algorithm SHA256
).Hash.ToLowerInvariant()

$taskRegistered = $false
try {
  Assert-MinimumInstallationLead -Operation "Window 02 disabled registration"
  Register-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath "\" `
    -Xml (Get-Content -LiteralPath $reviewXmlPath -Raw) `
    -ErrorAction Stop |
    Out-Null
  $taskRegistered = $true

  $registeredTask = Get-ExactRootTask -Name $TaskName
  $registeredXmlText = Export-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath "\" `
    -ErrorAction Stop
  $registeredBytes = [byte[]](
    $unicode.GetPreamble() + $unicode.GetBytes($registeredXmlText)
  )
  Write-CreateExclusiveFile `
    -Path $registeredDisabledXmlPath `
    -Bytes $registeredBytes
  [xml]$registeredXml = $registeredXmlText
  $registeredFailures = @(
    Get-PhillipCommodityTaskDefinitionFailures `
      -Task $registeredTask `
      -TaskXml $registeredXml `
      -ExpectedSid $sid `
      -ExpectedCommand $ReleasePython `
      -ExpectedArguments $workerArguments `
      -ExpectedWorkingDirectory $RuntimeRepo `
      -ExpectedStart $firstTaskStartLocal `
      -ExpectedEnd $scheduleEndLocal `
      -ExpectedEnabled $false
  )
  if ($registeredTask.State -ne "Disabled") {
    $registeredFailures += "InitialDisabledState"
  }
  if ($registeredFailures.Count -ne 0) {
    throw (
      "Window 02 disabled-registration mismatch: " +
      ($registeredFailures -join ", ")
    )
  }

  Assert-MinimumInstallationLead -Operation "Window 02 enablement"
  Enable-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath "\" `
    -ErrorAction Stop |
    Out-Null
  $installedTask = Get-ExactRootTask -Name $TaskName
  $installedInfo = Get-ScheduledTaskInfo `
    -TaskName $TaskName `
    -TaskPath "\" `
    -ErrorAction Stop
  $installedXmlText = Export-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath "\" `
    -ErrorAction Stop
  $installedBytes = [byte[]](
    $unicode.GetPreamble() + $unicode.GetBytes($installedXmlText)
  )
  Write-CreateExclusiveFile -Path $installedXmlPath -Bytes $installedBytes
  [xml]$installedXml = $installedXmlText
  $installedFailures = @(
    Get-PhillipCommodityTaskDefinitionFailures `
      -Task $installedTask `
      -TaskXml $installedXml `
      -ExpectedSid $sid `
      -ExpectedCommand $ReleasePython `
      -ExpectedArguments $workerArguments `
      -ExpectedWorkingDirectory $RuntimeRepo `
      -ExpectedStart $firstTaskStartLocal `
      -ExpectedEnd $scheduleEndLocal `
      -ExpectedEnabled $true
  )
  if ($installedTask.State -ne "Ready") {
    $installedFailures += "FinalReadyState"
  }
  $expectedNextRun = [datetime]::ParseExact(
    "2026-08-17T06:45:00",
    "yyyy-MM-ddTHH:mm:ss",
    [System.Globalization.CultureInfo]::InvariantCulture
  )
  if ($installedInfo.NextRunTime -ne $expectedNextRun) {
    $installedFailures += "NextRunTime"
  }
  foreach ($priorTaskName in $priorTaskNames) {
    $priorTask = Get-ExactRootTask -Name $priorTaskName -Optional
    if ($null -ne $priorTask -and $priorTask.State -ne "Disabled") {
      $installedFailures += "HistoricalTaskState:$priorTaskName"
    }
  }
  if ($installedFailures.Count -ne 0) {
    throw "Window 02 final task mismatch: $($installedFailures -join ', ')"
  }

  $registeredDisabledSha256 = (
    Get-FileHash `
      -LiteralPath $registeredDisabledXmlPath `
      -Algorithm SHA256
  ).Hash.ToLowerInvariant()
  $installedSha256 = (
    Get-FileHash -LiteralPath $installedXmlPath -Algorithm SHA256
  ).Hash.ToLowerInvariant()
  $receipt = [ordered]@{
    schema_version = (
      "phillip-commodity-window-02-scheduler-installation-receipt-v1"
    )
    task_name = $TaskName
    installed_at_utc = [DateTimeOffset]::UtcNow.ToString(
      "yyyy-MM-ddTHH:mm:ss.fffZ"
    )
    windows_sid = $sid
    package_source_commit = $packageSourceCommit
    package_source_tree = $packageSourceTree
    worker_source_commit = $workerCommit
    worker_source_tree = $workerTree
    worker_contract_id = $contractId
    worker_snapshot_id = $snapshotId
    contract_payload_sha256 = $expectedContractPayloadSha256
    contract_file_sha256 = $expectedContractFileSha256
    build_identity_sha256 = $expectedBuildIdentitySha256
    signing_key_id = $expectedSigningKeyId
    contract_artifact_files_verified = [int](
      $contractVerification.artifact_files_verified
    )
    dependency_lock_sha256 = [string](
      $contractVerification.dependency_lock_sha256
    )
    evidence_root_sha256 = [string](
      $contractVerification.evidence_root_sha256
    )
    task_contract_sha256 = $taskContractSha256
    contract_verifier_sha256 = $contractVerifierSha256
    health_checker_sha256 = $healthCheckerSha256
    task_definition_sha256 = $reviewSha256
    registered_disabled_xml_sha256 = $registeredDisabledSha256
    exported_task_xml_sha256 = $installedSha256
    command = $ReleasePython
    arguments = $workerArguments
    working_directory = $RuntimeRepo
    frozen_runtime_repo = $RuntimeRepo
    frozen_runtime_worktree_lock = $worktreeLock
    runtime_journal = $journal
    audit_export_root = $auditRoot
    start_boundary = "2026-08-17T06:45:00+09:00"
    end_boundary = "2026-10-13T00:16:00+09:00"
    worker_duration_seconds = $workerDurationSeconds
    minimum_installation_lead_seconds = $minimumInstallationLeadSeconds
    verified_next_run_time = $installedInfo.NextRunTime.ToString(
      "yyyy-MM-ddTHH:mm:ss"
    )
    preserved_tasks = $priorTaskNames
    task_started_manually = $false
    order_capability = "DISABLED"
    live_allowed = $false
    safe_to_demo_auto_order = $false
    broker_mutation = "NOT_PERFORMED"
  }
  $receiptBytes = (
    [System.Text.UTF8Encoding]::new($false)
  ).GetBytes(
    ($receipt | ConvertTo-Json -Depth 8) + [Environment]::NewLine
  )
  Write-CreateExclusiveFile -Path $receiptPath -Bytes $receiptBytes
  $receiptSha256 = (
    Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256
  ).Hash.ToLowerInvariant()

  [PSCustomObject]@{
    Status = "PHILLIP_COMMODITY_WINDOW_02_TASK_INSTALLED_VERIFIED"
    TaskName = $TaskName
    State = $installedTask.State
    NextRunTime = $installedInfo.NextRunTime
    InstallationReceipt = $receiptPath
    InstallationReceiptSHA256 = $receiptSha256
    PackageSourceCommit = $packageSourceCommit
    FrozenWorkerCommit = $workerCommit
    Contract = $contractId
    ContractPayloadSHA256 = $expectedContractPayloadSha256
    OrderCapability = "DISABLED"
    LiveAllowed = $false
    StartScheduledTask = "NOT_PERFORMED"
    BrokerMutation = "NOT_PERFORMED"
  } | Format-List
}
catch {
  $originalError = $_
  if ($taskRegistered) {
    Invoke-PhillipCommodityFailClosedRollback `
      -DisableOperation {
        Disable-ScheduledTask `
          -TaskName $TaskName `
          -TaskPath "\" `
          -ErrorAction Stop |
          Out-Null
      } `
      -StopOperation {
        Stop-ScheduledTask `
          -TaskName $TaskName `
          -TaskPath "\" `
          -ErrorAction Stop |
          Out-Null
      } `
      -ReadStateOperation {
        return (Get-ExactRootTask -Name $TaskName).State
      } `
      -OriginalFailure $originalError.Exception.Message
  }
  throw $originalError
}
