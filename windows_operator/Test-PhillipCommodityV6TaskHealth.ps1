[CmdletBinding()]
param(
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
  [string]$TaskName = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",

  [Parameter()]
  [switch]$FullArchiveAudit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$remediationCommit = "__REMEDIATION_COMMIT__"
$remediationTree = "__REMEDIATION_TREE__"
$workerCommit = "290cc23d9d87f93e914612afdfecfc481d2c232f"
$workerTree = "ef568ae39aa4c51d9afe738badbb86d2c45e9a58"
$contractId = "phillip-commodity-window-01-diagnostic-v5"
$expectedProofReceiptSha256 = (
  "29e14f81bbd87d460f171484d59a40e9" +
  "bdd6ae00611c3453ade4aa6c846b3aec"
)
$expectedTaskContractSha256 = "__TASK_CONTRACT_SHA256__"
$expectedEvidenceVerifierSha256 = "__EVIDENCE_VERIFIER_SHA256__"
$priorTaskNames = @(
  "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow"
)
$firstScheduledStart = [datetime]::Parse("2026-07-27T06:45:00")
$scheduleEndBoundary = [datetime]::Parse("2026-09-22T00:16:00")
$workerDurationSeconds = 84300
$startupAllowanceSeconds = 300
$fullArchiveQuiescenceLeadSeconds = 3600
$healthMutexName = (
  "Global\AI_SCALPER-PhillipCommodityV6-HealthCheckpoint-v1"
)
$healthMutexWaitSeconds = 300

$runtimeStateRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v5-290cc23-runtime"
)
$journal = Join-Path $runtimeStateRoot (
  "phillip-commodity-shadow-cycles-v5.sqlite3"
)
$auditRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-v5-290cc23-audit-exports"
)
$taskReviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-task-review"
)
$reviewXmlPath = Join-Path $taskReviewRoot "$TaskName.review.xml"
$installedXmlPath = Join-Path $taskReviewRoot "$TaskName.installed.xml"
$registeredDisabledXmlPath = Join-Path $taskReviewRoot (
  "$TaskName.registered-disabled.xml"
)
$receiptPath = Join-Path $taskReviewRoot (
  "$TaskName.installation-receipt.json"
)
$checkpointRoot = Join-Path $taskReviewRoot "evidence-checkpoints"
$taskContract = Join-Path $PSScriptRoot (
  "PhillipCommodityTaskContract.ps1"
)
$evidenceVerifier = Join-Path $PSScriptRoot (
  "verify_phillip_commodity_v5_scheduler_evidence.py"
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

function Publish-AtomicCreateExclusiveFile {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [byte[]]$Bytes
  )
  $directory = [System.IO.Path]::GetDirectoryName($Path)
  $leaf = [System.IO.Path]::GetFileName($Path)
  $temporaryPath = Join-Path $directory (
    ".$leaf.$([Guid]::NewGuid().ToString('N')).tmp"
  )
  try {
    Write-CreateExclusiveFile -Path $temporaryPath -Bytes $Bytes
    [System.IO.File]::Move($temporaryPath, $Path)
  }
  finally {
    if (Test-Path -LiteralPath $temporaryPath) {
      Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction Stop
    }
  }
}

function Test-ExactByteSequence {
  param(
    [Parameter(Mandatory = $true)]
    [byte[]]$Expected,

    [Parameter(Mandatory = $true)]
    [byte[]]$Observed
  )
  if ($Expected.Length -ne $Observed.Length) {
    return $false
  }
  for ($index = 0; $index -lt $Expected.Length; $index += 1) {
    if ($Expected[$index] -ne $Observed[$index]) {
      return $false
    }
  }
  return $true
}

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
foreach ($path in @(
  $taskContract,
  $evidenceVerifier,
  $ReleasePython,
  $CommodityTerminal,
  $journal,
  $reviewXmlPath,
  $registeredDisabledXmlPath,
  $installedXmlPath,
  $receiptPath
)) {
  Assert-RegularNonReparseFile -Path $path
}
Assert-NonReparseDirectory -Path $auditRoot
Assert-NonReparseDirectory -Path $checkpointRoot

$taskContractSha256 = (
  Get-FileHash -LiteralPath $taskContract -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($taskContractSha256 -ne $expectedTaskContractSha256) {
  throw "Shared Task Scheduler contract hash mismatch."
}
$evidenceVerifierSha256 = (
  Get-FileHash -LiteralPath $evidenceVerifier -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($evidenceVerifierSha256 -ne $expectedEvidenceVerifierSha256) {
  throw "Authoritative evidence verifier hash mismatch."
}
. $taskContract
Assert-PhillipCommodityTaskContractSelfTest

$receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
if (
  $receipt.schema_version -ne
    "phillip-commodity-v6-scheduler-installation-receipt-v1" -or
  $receipt.task_name -ne $TaskName -or
  $receipt.remediation_source_commit -ne $remediationCommit -or
  $receipt.remediation_source_tree -ne $remediationTree -or
  $receipt.worker_source_commit -ne $workerCommit -or
  $receipt.worker_source_tree -ne $workerTree -or
  $receipt.worker_contract_id -ne $contractId -or
  $receipt.task_contract_sha256 -ne $taskContractSha256 -or
  $receipt.evidence_verifier_sha256 -ne $evidenceVerifierSha256 -or
  $receipt.evidence_checkpoint_root -ne $checkpointRoot -or
  [string]::IsNullOrWhiteSpace(
    [string]$receipt.initial_evidence_checkpoint_path
  ) -or
  [string]::IsNullOrWhiteSpace(
    [string]$receipt.initial_evidence_checkpoint_file_sha256
  ) -or
  [string]::IsNullOrWhiteSpace(
    [string]$receipt.initial_evidence_checkpoint_hmac_sha256
  ) -or
  $receipt.start_boundary -ne "2026-07-27T06:45:00+09:00" -or
  $receipt.end_boundary -ne "2026-09-22T00:16:00+09:00" -or
  [int]$receipt.worker_duration_seconds -ne 84300 -or
  [int]$receipt.minimum_installation_lead_seconds -ne 900 -or
  $receipt.verified_next_run_time -ne "2026-07-27T06:45:00" -or
  $receipt.task_started_manually -ne $false -or
  $receipt.order_capability -ne "DISABLED" -or
  $receipt.live_allowed -ne $false -or
  $receipt.safe_to_demo_auto_order -ne $false -or
  $receipt.broker_mutation -ne "NOT_PERFORMED"
) {
  throw "V6 installation receipt identity or safety mismatch."
}

$initialCheckpointPath = [string]$receipt.initial_evidence_checkpoint_path
Assert-RegularNonReparseFile -Path $initialCheckpointPath
$initialCheckpointFileSha256 = (
  Get-FileHash -LiteralPath $initialCheckpointPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  [System.IO.Path]::GetDirectoryName($initialCheckpointPath) -ne
    $checkpointRoot -or
  $initialCheckpointFileSha256 -ne
    [string]$receipt.initial_evidence_checkpoint_file_sha256
) {
  throw "Initial evidence checkpoint path or hash mismatch."
}

$reviewSha256 = (
  Get-FileHash -LiteralPath $reviewXmlPath -Algorithm SHA256
).Hash.ToLowerInvariant()
$installedSha256 = (
  Get-FileHash -LiteralPath $installedXmlPath -Algorithm SHA256
).Hash.ToLowerInvariant()
$registeredDisabledSha256 = (
  Get-FileHash `
    -LiteralPath $registeredDisabledXmlPath `
    -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $reviewSha256 -ne $receipt.task_definition_sha256 -or
  $registeredDisabledSha256 -ne
    $receipt.registered_disabled_xml_sha256 -or
  $installedSha256 -ne $receipt.exported_task_xml_sha256
) {
  throw "V6 Task Scheduler XML evidence hash mismatch."
}

Assert-NonReparseDirectory -Path $RuntimeRepo
$runtimeHead = (& git -C $RuntimeRepo rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $runtimeHead -ne $workerCommit) {
  throw "Frozen worker commit mismatch."
}
$runtimeTree = (& git -C $RuntimeRepo rev-parse "HEAD^{tree}").Trim()
if ($LASTEXITCODE -ne 0 -or $runtimeTree -ne $workerTree) {
  throw "Frozen worker tree mismatch."
}
$runtimeDirty = @(
  & git -C $RuntimeRepo status --porcelain=v1 --untracked-files=all
)
if ($LASTEXITCODE -ne 0 -or $runtimeDirty.Count -ne 0) {
  $runtimeDirty
  throw "Frozen worker worktree is not clean."
}
$worktreeLock = (& git -C $RuntimeRepo rev-parse --git-path locked).Trim()
if ($LASTEXITCODE -ne 0) {
  throw "Frozen runtime lock path is unavailable."
}
if (-not [System.IO.Path]::IsPathRooted($worktreeLock)) {
  $worktreeLock = Join-Path $RuntimeRepo $worktreeLock
}
Assert-RegularNonReparseFile -Path $worktreeLock
if ($receipt.frozen_runtime_worktree_lock -ne $worktreeLock) {
  throw "Frozen runtime lock binding mismatch."
}

$proofPath = [string]$receipt.proof_receipt_path
Assert-RegularNonReparseFile -Path $proofPath
$proofSha256 = (
  Get-FileHash -LiteralPath $proofPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $proofSha256 -ne $expectedProofReceiptSha256 -or
  $proofSha256 -ne $receipt.proof_receipt_sha256
) {
  throw "Bound V5 proof receipt hash mismatch."
}
$proof = Get-Content -LiteralPath $proofPath -Raw | ConvertFrom-Json
if (
  $proof.status -ne "PHILLIP_COMMODITY_V5_PROOF_VERIFIED" -or
  $proof.contract_id -ne $contractId -or
  $proof.source_commit -ne $workerCommit -or
  $proof.source_tree -ne $workerTree -or
  $proof.contract_payload_sha256 -ne $receipt.contract_payload_sha256 -or
  $proof.build_identity_sha256 -ne $receipt.build_identity_sha256 -or
  $proof.source_chain_from_genesis -ne $true -or
  $proof.forward_evidence_valid -ne $true -or
  $proof.runtime_key -ne "phillip-commodity-broker-shadow-v1" -or
  $proof.authenticity -ne "HMAC_SHA256" -or
  [string]::IsNullOrWhiteSpace([string]$proof.signing_key_id) -or
  [int]$proof.children_verified -lt 2 -or
  @($proof.children).Count -ne [int]$proof.children_verified -or
  [int]$proof.dependency_sessions_verified -lt 1 -or
  $proof.order_capability -ne "DISABLED" -or
  $proof.live_allowed -ne $false -or
  $proof.safe_to_demo_auto_order -ne $false
) {
  throw "Bound V5 proof receipt is invalid."
}

$artifactRoot = Join-Path $Repo "validation_artifacts"
$lock = Join-Path $RuntimeRepo "pylock.windows-cp312.toml"
Assert-RegularNonReparseFile -Path $lock
$healthMutex = $null
$healthMutexAcquired = $false
$healthMutexAbandoned = $false
$healthResult = $null
try {
  $healthMutex = [System.Threading.Mutex]::new(
    $false,
    $healthMutexName
  )
  try {
    $healthMutexAcquired = $healthMutex.WaitOne(
      [TimeSpan]::FromSeconds($healthMutexWaitSeconds)
    )
  }
  catch [System.Threading.AbandonedMutexException] {
    # WaitOne grants ownership when it reports abandonment.  Continue only
    # after recording that the prior health process did not release cleanly;
    # the signed checkpoint verifier below still rejects any partial state.
    $healthMutexAcquired = $true
    $healthMutexAbandoned = $true
  }
  if (-not $healthMutexAcquired) {
    throw (
      "Timed out waiting $healthMutexWaitSeconds seconds for the " +
      "V6 health checkpoint mutex."
    )
  }

$verificationBaseArguments = @(
  "-I"
  "-S"
  "-B"
  $evidenceVerifier
  "--runtime-repo"
  $RuntimeRepo
  "--artifact-root"
  $artifactRoot
  "--audit-root"
  $auditRoot
  "--journal"
  $journal
  "--proof-receipt"
  $proofPath
  "--lock"
  $lock
  "--contract-id"
  $contractId
  "--snapshot-retry-seconds"
  "10"
)
$historicalArchiveAudit = "NOT_REQUESTED"
if ($FullArchiveAudit) {
  $fullAuditNow = Get-Date
  $fullAuditPhase = Get-PhillipCommodityV6SchedulePhase `
    -Now $fullAuditNow `
    -FirstStart $firstScheduledStart `
    -EndBoundary $scheduleEndBoundary `
    -DurationSeconds $workerDurationSeconds `
    -StartupSeconds $startupAllowanceSeconds
  $fullAuditTask = Get-ScheduledTask `
    -TaskName $TaskName `
    -ErrorAction Stop
  $nextScheduledStart = $null
  $candidateDate = $fullAuditNow.Date
  for ($offset = 0; $offset -le 8; $offset += 1) {
    $candidate = $candidateDate.AddDays($offset).AddHours(6).AddMinutes(45)
    if (
      $candidate -gt $fullAuditNow -and
      $candidate -ge $firstScheduledStart -and
      $candidate -lt $scheduleEndBoundary -and
      $candidate.DayOfWeek -in @(
        [DayOfWeek]::Monday,
        [DayOfWeek]::Tuesday,
        [DayOfWeek]::Wednesday,
        [DayOfWeek]::Thursday,
        [DayOfWeek]::Friday
      )
    ) {
      $nextScheduledStart = $candidate
      break
    }
  }
  $insufficientQuiescenceLead = (
    $null -ne $nextScheduledStart -and
    ($nextScheduledStart - $fullAuditNow).TotalSeconds -lt
      $fullArchiveQuiescenceLeadSeconds
  )
  if (
    $fullAuditPhase.ActiveInterval -or
    $fullAuditTask.State -ne "Ready" -or
    $insufficientQuiescenceLead
  ) {
    throw (
      "Full historical archive audit requires a Ready task outside the " +
      "worker interval with at least " +
      "$fullArchiveQuiescenceLeadSeconds seconds before the next start."
    )
  }
  $fullArchiveArguments = @(
    $verificationBaseArguments + @("--full-archive-audit")
  )
  $fullArchiveOutput = @(
    & $ReleasePython @fullArchiveArguments 2>&1
  )
  if ($LASTEXITCODE -ne 0) {
    $fullArchiveOutput
    throw "Full historical V5 archive verification failed."
  }
  $fullArchiveVerification = (
    $fullArchiveOutput -join [Environment]::NewLine
  ) | ConvertFrom-Json
  if (
    $fullArchiveVerification.status -ne
      "PHILLIP_COMMODITY_V5_EVIDENCE_AUTHENTICATED" -or
    $fullArchiveVerification.contract_payload_sha256 -ne
      $receipt.contract_payload_sha256 -or
    $fullArchiveVerification.build_identity_sha256 -ne
      $receipt.build_identity_sha256 -or
    [int]$fullArchiveVerification.audit_pairs_verified -lt
      [int]$receipt.authenticated_audit_pairs -or
    [int]$fullArchiveVerification.audit_pairs_verified_this_run -ne
      [int]$fullArchiveVerification.audit_pairs_verified -or
    $fullArchiveVerification.verification_mode -ne
      "FULL_ARCHIVE_AUDIT" -or
    $fullArchiveVerification.historical_archive_revalidated -ne $true -or
    $fullArchiveVerification.live_journal_head_authenticated -ne $true -or
    $fullArchiveVerification.source_chain_from_genesis -ne $true -or
    $fullArchiveVerification.order_capability -ne "DISABLED" -or
    $fullArchiveVerification.live_allowed -ne $false -or
    $fullArchiveVerification.safe_to_demo_auto_order -ne $false
  ) {
    throw "Full historical V5 archive projection mismatch."
  }
  $historicalArchiveAudit = "FULL_ARCHIVE_AUTHENTICATED"
}
$verificationArguments = @(
  $verificationBaseArguments + @(
  "--checkpoint-root"
  $checkpointRoot
  )
)
$verificationOutput = @(
  & $ReleasePython @verificationArguments 2>&1
)
if ($LASTEXITCODE -ne 0) {
  $verificationOutput
  throw "Authoritative V5 evidence verification failed."
}
$evidenceVerification = (
  $verificationOutput -join [Environment]::NewLine
) | ConvertFrom-Json
$checkpointProperty = $evidenceVerification.PSObject.Properties[
  "checkpoint"
]
$checkpointNameProperty = $evidenceVerification.PSObject.Properties[
  "checkpoint_file_name"
]
$checkpointGenesisProperty = $evidenceVerification.PSObject.Properties[
  "checkpoint_genesis_hmac_sha256"
]
$checkpointBaseProperty = $evidenceVerification.PSObject.Properties[
  "checkpoint_base_file_name"
]
if (
  $null -eq $checkpointProperty -or
  $null -eq $checkpointNameProperty -or
  $null -eq $checkpointGenesisProperty -or
  $null -eq $checkpointBaseProperty -or
  $evidenceVerification.status -ne
    "PHILLIP_COMMODITY_V5_EVIDENCE_AUTHENTICATED" -or
  $evidenceVerification.contract_payload_sha256 -ne
    $receipt.contract_payload_sha256 -or
  $evidenceVerification.build_identity_sha256 -ne
    $receipt.build_identity_sha256 -or
  $evidenceVerification.verification_mode -ne
    "ONLINE_SOURCE_CHAIN_JOURNAL_HEALTH" -or
  $evidenceVerification.live_journal_head_authenticated -ne $true -or
  [int]$evidenceVerification.audit_pairs_verified -lt
    [int]$receipt.authenticated_audit_pairs -or
  [int]$evidenceVerification.audit_pairs_verified_this_run -lt 0 -or
  [string]::IsNullOrWhiteSpace(
    [string]$checkpointBaseProperty.Value
  ) -or
  $checkpointGenesisProperty.Value -ne
    $receipt.initial_evidence_checkpoint_hmac_sha256 -or
  $checkpointProperty.Value.signing_key_id -ne $proof.signing_key_id -or
  -not ([string]$checkpointNameProperty.Value).EndsWith(
    "-$($checkpointProperty.Value.checkpoint_hmac_sha256).json"
  ) -or
  $evidenceVerification.source_chain_from_genesis -ne $true -or
  $evidenceVerification.order_capability -ne "DISABLED" -or
  $evidenceVerification.live_allowed -ne $false -or
  $evidenceVerification.safe_to_demo_auto_order -ne $false
) {
  throw "Authoritative V5 evidence projection mismatch."
}
$heartbeatProperty = $evidenceVerification.PSObject.Properties[
  "latest_heartbeat_at_utc"
]
$sourceEventProperty = $evidenceVerification.PSObject.Properties[
  "latest_source_event_count"
]
if ($null -eq $heartbeatProperty -or $null -eq $sourceEventProperty) {
  throw "Authenticated heartbeat projection is incomplete."
}
$latestHeartbeatAt = [DateTimeOffset]::Parse(
  [string]$heartbeatProperty.Value
).ToUniversalTime()
$authenticatedHeartbeatAgeSeconds = (
  [DateTimeOffset]::UtcNow - $latestHeartbeatAt
).TotalSeconds
if ($authenticatedHeartbeatAgeSeconds -lt -60) {
  throw "Authenticated heartbeat exceeds future clock skew."
}

foreach ($priorTaskName in $priorTaskNames) {
  $priorTask = Get-ScheduledTask `
    -TaskName $priorTaskName `
    -ErrorAction SilentlyContinue
  if ($null -eq $priorTask -or $priorTask.State -ne "Disabled") {
    throw "Preserved task is missing or enabled: $priorTaskName"
  }
}

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
$taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
$currentXmlText = Export-ScheduledTask `
  -TaskName $TaskName `
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
  throw "Installed V6 Task Scheduler XML drift detected."
}

$expectedArguments = @(
  "-I"
  "-S"
  "-B"
  "`"$RuntimeRepo\run_broker_shadow_once.py`""
  "--candidate phillip-commodity"
  "--terminal-path `"$CommodityTerminal`""
  "--artifact-root `"$Repo\validation_artifacts`""
  "--journal `"$journal`""
  "--audit-export-dir `"$auditRoot`""
  "--worker"
  "--worker-duration-seconds 84300"
) -join " "
if (
  $receipt.command -ne $ReleasePython -or
  $receipt.arguments -ne $expectedArguments -or
  $receipt.working_directory -ne $RuntimeRepo -or
  $receipt.frozen_runtime_repo -ne $RuntimeRepo
) {
  throw "V6 installation receipt command binding mismatch."
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
      "2026-07-27T06:45:00+09:00"
    )) `
    -ExpectedEnd ([DateTimeOffset]::Parse(
      "2026-09-22T00:16:00+09:00"
    ))
)
if ($semanticFailures.Count -ne 0) {
  throw "V6 task semantic drift: $($semanticFailures -join ', ')"
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
if (
  $activeInterval -and
  -not $startupAllowance -and
  $authenticatedHeartbeatAgeSeconds -gt 180
) {
  throw "Authenticated V5 worker heartbeat is stale."
}

if ($task.State -eq "Disabled") {
  throw "V6 scheduled task is disabled."
}
$attemptedThisBoundary = $false
if ($activeInterval) {
  $attemptedThisBoundary = (
    $taskInfo.LastRunTime -ge $lastScheduledStart.AddMinutes(-1) -and
    $taskInfo.LastRunTime -le $now.AddMinutes(1)
  )
  if ($startupAllowance) {
    if ($task.State -eq "Running") {
      if (-not $attemptedThisBoundary) {
        throw "V6 running state lacks the current boundary start."
      }
    }
    elseif ($task.State -eq "Ready") {
      if ($attemptedThisBoundary) {
        if ($taskInfo.LastTaskResult -ne 0) {
          throw "V6 worker exited nonzero during startup allowance."
        }
        throw "V6 worker exited unexpectedly during startup allowance."
      }
    }
    elseif ($task.State -eq "Queued") {
      if ($attemptedThisBoundary) {
        throw "V6 queued state follows a recorded current-boundary attempt."
      }
    }
    else {
      throw "V6 task state is invalid during startup allowance."
    }
  }
  elseif ($task.State -ne "Running") {
    throw "V6 task is not running during its active interval."
  }
}
if (-not $activeInterval -and $task.State -ne "Ready") {
  throw "V6 task is not ready outside its active interval."
}
if (
  $schedulePhase.Phase -in @("ACTIVE", "GAP", "EXPIRED") -and
  -not $startupAllowance
) {
  if (
    $taskInfo.LastRunTime -lt $lastScheduledStart.AddMinutes(-1) -or
    $taskInfo.LastRunTime -gt $lastScheduledStart.AddMinutes(5)
  ) {
    throw "Last V6 task start is outside the scheduler boundary."
  }
  if (-not $activeInterval -and $taskInfo.LastTaskResult -ne 0) {
    throw "Last completed V6 worker returned a nonzero result."
  }
}

$checkpointMutation = "NOT_PERFORMED"
$persistedCheckpointPath = $null
if ($evidenceVerification.checkpoint_advanced -eq $true) {
  $checkpointName = [string]$checkpointNameProperty.Value
  if (
    [System.IO.Path]::GetFileName($checkpointName) -ne $checkpointName -or
    -not $checkpointName.StartsWith("checkpoint-") -or
    -not $checkpointName.EndsWith(
      "-$($checkpointProperty.Value.checkpoint_hmac_sha256).json"
    )
  ) {
    throw "Advanced evidence checkpoint filename is invalid."
  }
  $persistedCheckpointPath = Join-Path $checkpointRoot $checkpointName
  $checkpointBytes = (
    [System.Text.UTF8Encoding]::new($false)
  ).GetBytes(
    ($checkpointProperty.Value | ConvertTo-Json -Depth 10) +
      [Environment]::NewLine
  )
  $checkpointCommitDisposition = "CREATED"
  try {
    Publish-AtomicCreateExclusiveFile `
      -Path $persistedCheckpointPath `
      -Bytes $checkpointBytes
  }
  catch [System.IO.IOException] {
    if (-not (
      Test-Path -LiteralPath $persistedCheckpointPath -PathType Leaf
    )) {
      throw
    }
    Assert-RegularNonReparseFile -Path $persistedCheckpointPath
    $collisionBytes = [System.IO.File]::ReadAllBytes(
      $persistedCheckpointPath
    )
    if (-not (
      Test-ExactByteSequence `
        -Expected $checkpointBytes `
        -Observed $collisionBytes
    )) {
      throw "Advanced evidence checkpoint collision is not identical."
    }
    $checkpointCommitDisposition = "ALREADY_COMMITTED_IDENTICAL"
  }
  Assert-RegularNonReparseFile -Path $persistedCheckpointPath
  $persistedCheckpointBytes = [System.IO.File]::ReadAllBytes(
    $persistedCheckpointPath
  )
  if (-not (
    Test-ExactByteSequence `
      -Expected $checkpointBytes `
      -Observed $persistedCheckpointBytes
  )) {
    throw "Persisted evidence checkpoint bytes do not match verification."
  }
  $persistedCheckpoint = Get-Content `
    -LiteralPath $persistedCheckpointPath `
    -Raw |
    ConvertFrom-Json
  if (
    $persistedCheckpoint.checkpoint_hmac_sha256 -ne
      $checkpointProperty.Value.checkpoint_hmac_sha256 -or
    [int]$persistedCheckpoint.source_operational_event_count -ne
      [int]$sourceEventProperty.Value
  ) {
    throw "Persisted evidence checkpoint projection mismatch."
  }
  $checkpointMutation = if ($checkpointCommitDisposition -eq "CREATED") {
    "APPENDED_SIGNED_CHECKPOINT"
  }
  else {
    "SIGNED_CHECKPOINT_ALREADY_COMMITTED_IDENTICAL"
  }
}
$effectiveCheckpointPath = if ($null -eq $persistedCheckpointPath) {
  Join-Path $checkpointRoot ([string]$checkpointBaseProperty.Value)
}
else {
  $persistedCheckpointPath
}

$healthResult = [PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_V6_TASK_HEALTHY"
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
  AuthenticatedHeartbeatAtUtc = $latestHeartbeatAt.ToString(
    "yyyy-MM-ddTHH:mm:ss.ffffffZ"
  )
  AuthenticatedHeartbeatAgeSeconds = [math]::Round(
    $authenticatedHeartbeatAgeSeconds,
    1
  )
  AuthenticatedSourceEventCount = [int]$sourceEventProperty.Value
  AuditPairs = [int]$evidenceVerification.audit_pairs_verified
  AuditPairsVerifiedThisRun = [int](
    $evidenceVerification.audit_pairs_verified_this_run
  )
  EvidenceCheckpoint = $effectiveCheckpointPath
  EvidenceCheckpointMutation = $checkpointMutation
  HistoricalArchiveAudit = $historicalArchiveAudit
  HealthMutexName = $healthMutexName
  HealthMutexAbandoned = $healthMutexAbandoned
  RemediationSourceCommit = $remediationCommit
  FrozenWorkerCommit = $runtimeHead
  FrozenWorkerTree = $runtimeTree
  Contract = $contractId
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
}
}
finally {
  if ($null -ne $healthMutex) {
    try {
      if ($healthMutexAcquired) {
        $healthMutex.ReleaseMutex()
      }
    }
    finally {
      $healthMutex.Dispose()
    }
  }
}

$healthResult | Format-List
