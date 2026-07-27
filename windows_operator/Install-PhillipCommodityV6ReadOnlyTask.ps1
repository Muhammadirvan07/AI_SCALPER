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
  [string]$ProofReceipt = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-v5-290cc23-proof-receipts\" +
    "phillip-commodity-v5-proof-20260726T120439756Z-" +
    "fa6ee91750cb.json"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$remediationCommit = "__REMEDIATION_COMMIT__"
$remediationTree = "__REMEDIATION_TREE__"
$workerCommit = "290cc23d9d87f93e914612afdfecfc481d2c232f"
$workerTree = "ef568ae39aa4c51d9afe738badbb86d2c45e9a58"
$branch = "agent/live-grade-phase3"
$contractId = "phillip-commodity-window-01-diagnostic-v5"
$expectedProofReceiptSha256 = (
  "29e14f81bbd87d460f171484d59a40e9" +
  "bdd6ae00611c3453ade4aa6c846b3aec"
)
$expectedTaskContractSha256 = "__TASK_CONTRACT_SHA256__"
$expectedEvidenceVerifierSha256 = "__EVIDENCE_VERIFIER_SHA256__"
$firstTaskStart = [DateTimeOffset]::Parse("2026-07-29T21:45:00Z")
$minimumInstallationLeadSeconds = 900
$priorTaskNames = @(
  "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
  "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow"
)

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
$artifactRoot = Join-Path $Repo "validation_artifacts"
$contractFile = Join-Path $artifactRoot "forward\$contractId\contract.json"
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
  $output = (& git @Arguments 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "$Operation failed with exit code $LASTEXITCODE."
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
      "$minimumInstallationLeadSeconds seconds before the first boundary; " +
      "only $([math]::Floor($remainingSeconds)) seconds remain."
    )
  }
}

Assert-RegularNonReparseFile -Path $taskContract
Assert-RegularNonReparseFile -Path $evidenceVerifier
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

if ((Get-TimeZone).Id -ne "Tokyo Standard Time") {
  throw "Windows timezone must be Tokyo Standard Time."
}
Assert-MinimumInstallationLead -Operation "V6 installation"
if (-not (Test-Path -LiteralPath $Repo -PathType Container)) {
  throw "Repository is unavailable: $Repo"
}

$remediationObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$remediationCommit^{commit}") `
  -Operation "Remediation source commit inspection"
$remediationTreeObject = Invoke-CheckedGit `
  -Arguments @("-C", $Repo, "rev-parse", "$remediationCommit^{tree}") `
  -Operation "Remediation source tree inspection"
if (
  $remediationObject -ne $remediationCommit -or
  $remediationTreeObject -ne $remediationTree
) {
  throw "Remediation source identity mismatch."
}
& git -C $Repo merge-base --is-ancestor `
  $remediationCommit `
  "origin/$branch"
if ($LASTEXITCODE -ne 0) {
  throw "Remediation source is not on the official branch."
}

Assert-NonReparseDirectory -Path $RuntimeRepo
$runtimeHead = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD") `
  -Operation "Frozen runtime commit inspection"
$runtimeTree = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "HEAD^{tree}") `
  -Operation "Frozen runtime tree inspection"
if ($runtimeHead -ne $workerCommit -or $runtimeTree -ne $workerTree) {
  throw "Frozen worker source identity mismatch."
}
$runtimeDirty = @(
  & git -C $RuntimeRepo status --porcelain=v1 --untracked-files=all
)
if ($LASTEXITCODE -ne 0 -or $runtimeDirty.Count -ne 0) {
  $runtimeDirty
  throw "Frozen worker worktree is not clean."
}
$worktreeLock = Invoke-CheckedGit `
  -Arguments @("-C", $RuntimeRepo, "rev-parse", "--git-path", "locked") `
  -Operation "Frozen runtime lock inspection"
if (-not [System.IO.Path]::IsPathRooted($worktreeLock)) {
  $worktreeLock = Join-Path $RuntimeRepo $worktreeLock
}
Assert-RegularNonReparseFile -Path $worktreeLock

foreach ($path in @(
  $ReleasePython,
  $CommodityTerminal,
  $journal,
  $contractFile,
  $ProofReceipt
)) {
  Assert-RegularNonReparseFile -Path $path
}
Assert-NonReparseDirectory -Path $auditRoot

$proofReceiptSha256 = (
  Get-FileHash -LiteralPath $ProofReceipt -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($proofReceiptSha256 -ne $expectedProofReceiptSha256) {
  throw "Bound V5 proof receipt hash mismatch."
}
$proof = Get-Content -LiteralPath $ProofReceipt -Raw | ConvertFrom-Json
if (
  $proof.status -ne "PHILLIP_COMMODITY_V5_PROOF_VERIFIED" -or
  $proof.contract_id -ne $contractId -or
  $proof.source_commit -ne $workerCommit -or
  $proof.source_tree -ne $workerTree -or
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

$contract = Get-Content -LiteralPath $contractFile -Raw | ConvertFrom-Json
if (
  $contract.contract_id -ne $contractId -or
  $contract.validation_profile -ne "DIAGNOSTIC" -or
  $contract.observation_start_at_utc -ne "2026-07-26T16:00:00Z" -or
  $contract.blind_until_utc -ne "2026-09-21T15:00:00Z" -or
  $contract.promotion_profile_eligible -ne $false -or
  $contract.contract_payload_sha256 -ne $proof.contract_payload_sha256 -or
  $contract.build_identity_sha256 -ne $proof.build_identity_sha256
) {
  throw "Bound V5 forward contract is invalid."
}

$lock = Join-Path $RuntimeRepo "pylock.windows-cp312.toml"
Assert-RegularNonReparseFile -Path $lock
$verificationOutput = @(
  & $ReleasePython -I -S -B `
    $evidenceVerifier `
    --runtime-repo $RuntimeRepo `
    --artifact-root $artifactRoot `
    --audit-root $auditRoot `
    --journal $journal `
    --proof-receipt $ProofReceipt `
    --lock $lock `
    --contract-id $contractId `
    --full-archive-audit 2>&1
)
if ($LASTEXITCODE -ne 0) {
  $verificationOutput
  throw "Authoritative V5 evidence verification failed."
}
$evidenceVerification = (
  $verificationOutput -join [Environment]::NewLine
) | ConvertFrom-Json
$verificationHeartbeatProperty = (
  $evidenceVerification.PSObject.Properties[
    "latest_heartbeat_at_utc"
  ]
)
$verificationSourceEventProperty = (
  $evidenceVerification.PSObject.Properties[
    "latest_source_event_count"
  ]
)
$verificationCheckpointProperty = (
  $evidenceVerification.PSObject.Properties["checkpoint"]
)
$verificationCheckpointNameProperty = (
  $evidenceVerification.PSObject.Properties["checkpoint_file_name"]
)
$verificationGenesisProperty = (
  $evidenceVerification.PSObject.Properties[
    "checkpoint_genesis_hmac_sha256"
  ]
)
if (
  $null -eq $verificationHeartbeatProperty -or
  $null -eq $verificationSourceEventProperty -or
  $null -eq $verificationCheckpointProperty -or
  $null -eq $verificationCheckpointNameProperty -or
  $null -eq $verificationGenesisProperty -or
  $evidenceVerification.status -ne
    "PHILLIP_COMMODITY_V5_EVIDENCE_AUTHENTICATED" -or
  $evidenceVerification.contract_payload_sha256 -ne
    $proof.contract_payload_sha256 -or
  $evidenceVerification.build_identity_sha256 -ne
    $proof.build_identity_sha256 -or
  [int]$evidenceVerification.audit_pairs_verified -lt 2 -or
  [int]$evidenceVerification.audit_pairs_verified_this_run -ne
    [int]$evidenceVerification.audit_pairs_verified -or
  $evidenceVerification.verification_mode -ne "FULL_ARCHIVE_AUDIT" -or
  $evidenceVerification.historical_archive_revalidated -ne $true -or
  $evidenceVerification.live_journal_head_authenticated -ne $true -or
  [int]$evidenceVerification.live_journal_source_event_count -ne
    [int]$verificationSourceEventProperty.Value -or
  $evidenceVerification.checkpoint_advanced -ne $true -or
  $verificationCheckpointProperty.Value.checkpoint_hmac_sha256 -ne
    $verificationGenesisProperty.Value -or
  $verificationCheckpointProperty.Value.predecessor_checkpoint_hmac_sha256 `
    -ne $null -or
  $verificationCheckpointProperty.Value.signing_key_id -ne
    $proof.signing_key_id -or
  $evidenceVerification.source_chain_from_genesis -ne $true -or
  $evidenceVerification.order_capability -ne "DISABLED" -or
  $evidenceVerification.live_allowed -ne $false -or
  $evidenceVerification.safe_to_demo_auto_order -ne $false
) {
  throw "Authoritative V5 evidence projection mismatch."
}

foreach ($priorTaskName in $priorTaskNames) {
  $priorTask = Get-ScheduledTask `
    -TaskName $priorTaskName `
    -ErrorAction SilentlyContinue
  if ($null -eq $priorTask -or $priorTask.State -ne "Disabled") {
    throw "Preserved task must exist and remain disabled: $priorTaskName"
  }
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  throw "V6 task already exists; it will not be overwritten."
}
if (Test-Path -LiteralPath $taskReviewRoot) {
  throw "V6 task review root already exists; preserve it for review."
}
Assert-MinimumInstallationLead -Operation "V6 task evidence creation"

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
if ($null -eq $identity.User) {
  throw "Current Windows SID is unavailable."
}
$sid = $identity.User.Value

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
  "--worker-duration-seconds 84300"
) -join " "

$xmlCommand = [System.Security.SecurityElement]::Escape($ReleasePython)
$xmlArguments = [System.Security.SecurityElement]::Escape($workerArguments)
$xmlWorkingDirectory = [System.Security.SecurityElement]::Escape($RuntimeRepo)
$xmlSid = [System.Security.SecurityElement]::Escape($sid)
$taskXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>AI_SCALPER Phillip Commodity v6 scheduler-only remediation for the proof-verified v5 read-only worker; no order capability.</Description>
    <URI>\$TaskName</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2026-07-30T06:45:00+09:00</StartBoundary>
      <EndBoundary>2026-09-22T00:16:00+09:00</EndBoundary>
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

New-Item -ItemType Directory -Path $taskReviewRoot -ErrorAction Stop |
  Out-Null
Assert-NonReparseDirectory -Path $taskReviewRoot
New-Item -ItemType Directory -Path $checkpointRoot -ErrorAction Stop |
  Out-Null
Assert-NonReparseDirectory -Path $checkpointRoot
$initialCheckpointName = [string]$verificationCheckpointNameProperty.Value
if (
  [System.IO.Path]::GetFileName($initialCheckpointName) -ne
    $initialCheckpointName -or
  -not $initialCheckpointName.StartsWith("checkpoint-") -or
  -not $initialCheckpointName.EndsWith(".json")
) {
  throw "Initial evidence checkpoint filename is invalid."
}
$initialCheckpointPath = Join-Path $checkpointRoot $initialCheckpointName
$initialCheckpointBytes = (
  [System.Text.UTF8Encoding]::new($false)
).GetBytes(
  ($verificationCheckpointProperty.Value | ConvertTo-Json -Depth 10) +
    [Environment]::NewLine
)
Publish-AtomicCreateExclusiveFile `
  -Path $initialCheckpointPath `
  -Bytes $initialCheckpointBytes
Assert-RegularNonReparseFile -Path $initialCheckpointPath
$initialCheckpointFileSha256 = (
  Get-FileHash -LiteralPath $initialCheckpointPath -Algorithm SHA256
).Hash.ToLowerInvariant()
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
  Assert-MinimumInstallationLead -Operation "V6 disabled registration"
  Register-ScheduledTask `
    -TaskName $TaskName `
    -Xml (Get-Content -LiteralPath $reviewXmlPath -Raw) `
    -ErrorAction Stop |
    Out-Null
  $taskRegistered = $true

  $registeredTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $registeredXmlText = Export-ScheduledTask `
    -TaskName $TaskName `
    -ErrorAction Stop
  $registeredBytes = [byte[]](
    $unicode.GetPreamble() + $unicode.GetBytes($registeredXmlText)
  )
  Write-CreateExclusiveFile `
    -Path $registeredDisabledXmlPath `
    -Bytes $registeredBytes
  [xml]$registeredXml = $registeredXmlText

  $semanticFailures = @(
    Get-PhillipCommodityTaskDefinitionFailures `
      -Task $registeredTask `
      -TaskXml $registeredXml `
      -ExpectedSid $sid `
      -ExpectedCommand $ReleasePython `
      -ExpectedArguments $workerArguments `
      -ExpectedWorkingDirectory $RuntimeRepo `
      -ExpectedStart ([DateTimeOffset]::Parse(
        "2026-07-30T06:45:00+09:00"
      )) `
      -ExpectedEnd ([DateTimeOffset]::Parse(
        "2026-09-22T00:16:00+09:00"
      )) `
      -ExpectedEnabled $false
  )
  if ($registeredTask.State -ne "Disabled") {
    $semanticFailures += "InitialDisabledState"
  }
  foreach ($priorTaskName in $priorTaskNames) {
    $priorTask = Get-ScheduledTask `
      -TaskName $priorTaskName `
      -ErrorAction SilentlyContinue
    if ($null -eq $priorTask -or $priorTask.State -ne "Disabled") {
      $semanticFailures += "PreservedTaskState:$priorTaskName"
    }
  }
  if ($semanticFailures.Count -ne 0) {
    throw (
      "V6 disabled-registration semantic mismatch: " +
      ($semanticFailures -join ", ")
    )
  }

  Assert-MinimumInstallationLead -Operation "V6 enablement"
  Enable-ScheduledTask -TaskName $TaskName -ErrorAction Stop | Out-Null
  $installedTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $installedTaskInfo = Get-ScheduledTaskInfo `
    -TaskName $TaskName `
    -ErrorAction Stop
  $installedXmlText = Export-ScheduledTask `
    -TaskName $TaskName `
    -ErrorAction Stop
  $installedBytes = [byte[]](
    $unicode.GetPreamble() + $unicode.GetBytes($installedXmlText)
  )
  Write-CreateExclusiveFile -Path $installedXmlPath -Bytes $installedBytes
  [xml]$installedXml = $installedXmlText
  $finalFailures = @(
    Get-PhillipCommodityTaskDefinitionFailures `
      -Task $installedTask `
      -TaskXml $installedXml `
      -ExpectedSid $sid `
      -ExpectedCommand $ReleasePython `
      -ExpectedArguments $workerArguments `
      -ExpectedWorkingDirectory $RuntimeRepo `
      -ExpectedStart ([DateTimeOffset]::Parse(
        "2026-07-30T06:45:00+09:00"
      )) `
      -ExpectedEnd ([DateTimeOffset]::Parse(
        "2026-09-22T00:16:00+09:00"
      )) `
      -ExpectedEnabled $true
  )
  if ($installedTask.State -ne "Ready") {
    $finalFailures += "FinalReadyState"
  }
  $expectedNextRunTime = [datetime]::ParseExact(
    "2026-07-30T06:45:00",
    "yyyy-MM-ddTHH:mm:ss",
    [System.Globalization.CultureInfo]::InvariantCulture
  )
  if ($installedTaskInfo.NextRunTime -ne $expectedNextRunTime) {
    $finalFailures += "NextRunTime"
  }
  if ($finalFailures.Count -ne 0) {
    throw "V6 final task mismatch: $($finalFailures -join ', ')"
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
      "phillip-commodity-v6-scheduler-installation-receipt-v1"
    )
    task_name = $TaskName
    installed_at_utc = [DateTimeOffset]::UtcNow.ToString(
      "yyyy-MM-ddTHH:mm:ss.fffZ"
    )
    windows_sid = $sid
    remediation_source_commit = $remediationCommit
    remediation_source_tree = $remediationTree
    worker_source_commit = $workerCommit
    worker_source_tree = $workerTree
    worker_contract_id = $contractId
    proof_receipt_path = $ProofReceipt
    proof_receipt_sha256 = $proofReceiptSha256
    task_contract_sha256 = $taskContractSha256
    evidence_verifier_sha256 = $evidenceVerifierSha256
    contract_payload_sha256 = $proof.contract_payload_sha256
    build_identity_sha256 = $proof.build_identity_sha256
    authenticated_audit_pairs = [int](
      $evidenceVerification.audit_pairs_verified
    )
    authenticated_heartbeat_at_install_utc = (
      [string]$verificationHeartbeatProperty.Value
    )
    authenticated_source_event_count = [int](
      $verificationSourceEventProperty.Value
    )
    evidence_checkpoint_root = $checkpointRoot
    initial_evidence_checkpoint_path = $initialCheckpointPath
    initial_evidence_checkpoint_file_sha256 = (
      $initialCheckpointFileSha256
    )
    initial_evidence_checkpoint_hmac_sha256 = [string](
      $verificationGenesisProperty.Value
    )
    task_definition_sha256 = $reviewSha256
    registered_disabled_xml_sha256 = $registeredDisabledSha256
    exported_task_xml_sha256 = $installedSha256
    command = $ReleasePython
    arguments = $workerArguments
    working_directory = $RuntimeRepo
    frozen_runtime_repo = $RuntimeRepo
    frozen_runtime_worktree_lock = $worktreeLock
    start_boundary = "2026-07-30T06:45:00+09:00"
    end_boundary = "2026-09-22T00:16:00+09:00"
    worker_duration_seconds = 84300
    minimum_installation_lead_seconds = $minimumInstallationLeadSeconds
    verified_next_run_time = $installedTaskInfo.NextRunTime.ToString(
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
    Status = "PHILLIP_COMMODITY_V6_TASK_INSTALLED_VERIFIED"
    TaskName = $TaskName
    State = $installedTask.State
    NextRunTime = $installedTaskInfo.NextRunTime
    EvidenceCheckpoint = $initialCheckpointPath
    EvidenceCheckpointHMAC = [string]$verificationGenesisProperty.Value
    TaskDefinitionSHA256 = $reviewSha256
    ExportedTaskSHA256 = $installedSha256
    InstallationReceipt = $receiptPath
    InstallationReceiptSHA256 = $receiptSha256
    RemediationSourceCommit = $remediationCommit
    FrozenWorkerCommit = $workerCommit
    Contract = $contractId
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
          -ErrorAction Stop |
          Out-Null
      } `
      -StopOperation {
        Stop-ScheduledTask `
          -TaskName $TaskName `
          -ErrorAction Stop |
          Out-Null
      } `
      -ReadStateOperation {
        return (
          Get-ScheduledTask `
            -TaskName $TaskName `
            -ErrorAction Stop
        ).State
      } `
      -OriginalFailure $originalError.Exception.Message
  }
  throw $originalError
}
