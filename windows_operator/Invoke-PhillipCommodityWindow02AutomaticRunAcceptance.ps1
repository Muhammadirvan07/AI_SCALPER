[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter()]
  [ValidateSet("Watch", "CollectStart", "CollectCompletion")]
  [string]$Mode = "Watch",

  [Parameter()]
  [string]$TargetBoundaryLocal = "2026-08-17T06:45:00+09:00",

  [Parameter()]
  [string]$SchedulerOperatorRoot = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-window-02-scheduler-operator-84f6ea1c"
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
  ),

  [Parameter()]
  [string]$OutputRoot = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-window-02-automatic-run-acceptance"
  ),

  [Parameter()]
  [string]$StartArchive = "",

  [Parameter()]
  [ValidatePattern("^$|^[0-9a-fA-F]{64}$")]
  [string]$ExpectedStartArchiveSHA256 = "",

  [Parameter()]
  [ValidateRange(15, 300)]
  [int]$WatchPollSeconds = 30,

  [Parameter()]
  [int]$WatchTimeoutSeconds = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolkitSourceCommit = "__TOOLKIT_SOURCE_COMMIT__"
$toolkitSourceTree = "__TOOLKIT_SOURCE_TREE__"
$expectedToolSHA256 = "__ACCEPTANCE_TOOL_SHA256__"
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
$installedTaskXmlPath = Join-Path $taskReviewRoot "$taskName.installed.xml"
$auditRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-audit-exports-r6"
)
$runtimeStateRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-window-02-da319001-runtime-r6"
)
$journal = Join-Path $runtimeStateRoot (
  "phillip-commodity-shadow-cycles-window-02.sqlite3"
)
$artifactRoot = Join-Path $Repo "validation_artifacts"
$healthPath = Join-Path $SchedulerOperatorRoot (
  "Test-PhillipCommodityWindow02TaskHealth.ps1"
)
$contractVerifier = Join-Path $SchedulerOperatorRoot (
  "verify_phillip_commodity_window_02_contract.py"
)
$toolPath = Join-Path $PSScriptRoot (
  "phillip_commodity_window_02_automatic_run_acceptance.py"
)
$manifestPath = Join-Path $PSScriptRoot (
  "PHILLIP_COMMODITY_WINDOW_02_ACCEPTANCE_TOOLKIT.json"
)
$readinessPath = Join-Path $PSScriptRoot (
  "Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1"
)
$operationalLog = "Microsoft-Windows-TaskScheduler/Operational"
$eventProvider = "Microsoft-Windows-TaskScheduler"
$eventIds = @(100, 102, 107, 110)

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

function Write-Utf8Json {
  param(
    [Parameter(Mandatory = $true)][object]$Value,
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter()][int]$Depth = 12
  )
  [System.IO.File]::WriteAllText(
    $Path,
    (($Value | ConvertTo-Json -Depth $Depth) + "`n"),
    [System.Text.UTF8Encoding]::new($false)
  )
  Assert-RegularNonReparseFile -Path $Path
}

function Write-Utf8Text {
  param(
    [Parameter(Mandatory = $true)][string]$Value,
    [Parameter(Mandatory = $true)][string]$Path
  )
  [System.IO.File]::WriteAllText(
    $Path,
    $Value,
    [System.Text.UTF8Encoding]::new($false)
  )
  Assert-RegularNonReparseFile -Path $Path
}

function Get-TextSHA256 {
  param([Parameter(Mandatory = $true)][string]$Value)
  $algorithm = [System.Security.Cryptography.SHA256]::Create()
  try {
    return [BitConverter]::ToString(
      $algorithm.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Value))
    ).Replace("-", "").ToLowerInvariant()
  }
  finally {
    $algorithm.Dispose()
  }
}

function Get-ExactRootTask {
  param([Parameter(Mandatory = $true)][string]$Name)
  $matches = @(
    Get-ScheduledTask -TaskName $Name -ErrorAction Stop |
      Where-Object { $_.TaskPath -eq "\" }
  )
  if ($matches.Count -ne 1) {
    throw "Scheduled task is not unique at the root path: $Name"
  }
  return $matches[0]
}

function Get-EventDataValue {
  param(
    [Parameter(Mandatory = $true)][xml]$EventXml,
    [Parameter(Mandatory = $true)][string]$Name
  )
  $namespace = New-Object System.Xml.XmlNamespaceManager(
    $EventXml.NameTable
  )
  $namespace.AddNamespace(
    "event", "http://schemas.microsoft.com/win/2004/08/events/event"
  )
  $nodes = @(
    $EventXml.SelectNodes(
      "/event:Event/event:EventData/event:Data[@Name='$Name']",
      $namespace
    )
  )
  if ($nodes.Count -gt 1) {
    throw "Task Scheduler event has duplicate $Name data."
  }
  if ($nodes.Count -eq 0) {
    return $null
  }
  return [string]$nodes[0].InnerText
}

function Convert-LocalTaskTimeToUtcText {
  param([Parameter(Mandatory = $true)][datetime]$Value)
  $tokyo = [TimeZoneInfo]::FindSystemTimeZoneById("Tokyo Standard Time")
  $unspecified = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Unspecified)
  return [TimeZoneInfo]::ConvertTimeToUtc(
    $unspecified, $tokyo
  ).ToString(
    "yyyy-MM-ddTHH:mm:ss.fffffffZ",
    [Globalization.CultureInfo]::InvariantCulture
  )
}

function Convert-LocalTaskTimeToJstText {
  param([Parameter(Mandatory = $true)][datetime]$Value)
  $tokyo = [TimeZoneInfo]::FindSystemTimeZoneById("Tokyo Standard Time")
  $unspecified = [DateTime]::SpecifyKind($Value, [DateTimeKind]::Unspecified)
  return [DateTimeOffset]::new(
    $unspecified, $tokyo.GetUtcOffset($unspecified)
  ).ToString(
    "yyyy-MM-ddTHH:mm:sszzz",
    [Globalization.CultureInfo]::InvariantCulture
  )
}

function New-ReceiptAclEvidence {
  param(
    [Parameter(Mandatory = $true)][object]$Receipt,
    [Parameter(Mandatory = $true)][string]$CapturedAtUtc
  )
  $acl = Get-Acl -LiteralPath $installationReceiptPath
  if (-not [bool]$acl.AreAccessRulesProtected) {
    throw "Installation receipt ACL inheritance must be disabled."
  }
  $owner = [System.Security.Principal.NTAccount]::new([string]$acl.Owner)
  $ownerSid = [string](
    $owner.Translate([System.Security.Principal.SecurityIdentifier]).Value
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
    $true, $true, [System.Security.Principal.SecurityIdentifier]
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
  $observed = @($observed | Sort-Object -Unique)
  $unauthorized = @($unauthorized | Sort-Object -Unique)
  if (
    $ownerSid -notin $authorized -or
    $unauthorized.Count -ne 0 -or
    @(Compare-Object $authorized $observed).Count -ne 0
  ) {
    throw "Installation receipt ACL write authority mismatch."
  }
  $sddl = $acl.GetSecurityDescriptorSddlForm(
    [System.Security.AccessControl.AccessControlSections]::Access
  )
  return [ordered]@{
    schema_version = "phillip-commodity-window-02-receipt-acl-evidence-v1"
    captured_at_utc = $CapturedAtUtc
    receipt_path = $installationReceiptPath
    receipt_sha256 = (
      Get-FileHash -LiteralPath $installationReceiptPath -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    owner_sid = $ownerSid
    acl_protected = $true
    authorized_write_sids = $observed
    unauthorized_write_sids = $unauthorized
    acl_sddl_sha256 = Get-TextSHA256 -Value $sddl
    collection = [ordered]@{
      api = "Get-Acl"
      access_rules_translated_to_sid = $true
      task_scheduler_mutation = "NOT_PERFORMED"
      broker_mutation = "NOT_PERFORMED"
    }
  }
}

function Get-HealthTranscript {
  $records = @(
    & $healthPath `
      -Repo $Repo `
      -RuntimeRepo $RuntimeRepo `
      -ReleasePython $ReleasePython `
      -CommodityTerminal $CommodityTerminal `
      -TaskName $taskName `
      2>&1
  )
  if (-not $?) {
    $records
    throw "Installed Window 02 health verification failed."
  }
  $text = $records | Out-String -Width 4096
  if (
    $text -notmatch "PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY" -or
    $text -notmatch "OrderCapability\s*:\s*DISABLED" -or
    $text -notmatch "LiveAllowed\s*:\s*False"
  ) {
    throw "Installed Window 02 health transcript projection mismatch."
  }
  return $text
}

function Get-RuntimeStatusTranscript {
  $worker = Join-Path $RuntimeRepo "run_broker_shadow_once.py"
  Assert-RegularNonReparseFile -Path $worker
  return Invoke-CheckedNative `
    -FilePath $ReleasePython `
    -Arguments @(
      "-I", "-S", "-B", $worker,
      "--candidate", "phillip-commodity",
      "--artifact-root", $artifactRoot,
      "--journal", $journal,
      "--heartbeat-stale-seconds", "180",
      "--status-only"
    ) `
    -Operation "Authenticated Window 02 runtime status"
}

function Get-ContractAuthentication {
  $lock = Join-Path $RuntimeRepo "pylock.windows-cp312.toml"
  Assert-RegularNonReparseFile -Path $lock
  return Invoke-CheckedNative `
    -FilePath $ReleasePython `
    -Arguments @(
      "-I", "-S", "-B", $contractVerifier,
      "--runtime-repo", $RuntimeRepo,
      "--artifact-root", $artifactRoot,
      "--lock", $lock
    ) `
    -Operation "Authenticated Window 02 contract verification"
}

function Export-CurrentTaskXml {
  param([Parameter(Mandatory = $true)][string]$Path)
  $text = Export-ScheduledTask `
    -TaskName $taskName `
    -TaskPath "\" `
    -ErrorAction Stop
  $bytes = [byte[]](
    [System.Text.Encoding]::Unicode.GetPreamble() +
    [System.Text.Encoding]::Unicode.GetBytes($text)
  )
  [System.IO.File]::WriteAllBytes($Path, $bytes)
  Assert-RegularNonReparseFile -Path $Path
}

function New-TaskObservation {
  param(
    [Parameter(Mandatory = $true)][object]$Receipt,
    [Parameter(Mandatory = $true)][object]$Boundary,
    [Parameter(Mandatory = $true)][string]$CapturedAtUtc
  )
  $task = Get-ExactRootTask -Name $taskName
  $info = Get-ScheduledTaskInfo `
    -TaskName $taskName `
    -TaskPath "\" `
    -ErrorAction Stop
  $priorStates = [ordered]@{}
  foreach ($name in $priorTaskNames) {
    $prior = Get-ExactRootTask -Name $name
    $priorStates[$name] = [string]$prior.State
  }
  foreach ($obsolete in @(
    Get-ScheduledTask -ErrorAction Stop |
      Where-Object {
        $_.TaskPath -eq "\" -and
        $_.TaskName -like "AI_SCALPER-PhillipCommodityWindow02*" -and
        $_.TaskName -ne $taskName
      }
  )) {
    if ($priorStates.Contains([string]$obsolete.TaskName)) {
      throw "Obsolete Window 02 task inventory is ambiguous."
    }
    $priorStates[[string]$obsolete.TaskName] = [string]$obsolete.State
  }
  return [ordered]@{
    schema_version = "phillip-commodity-window-02-task-observation-v1"
    captured_at_utc = $CapturedAtUtc
    target_boundary_utc = [string]$Boundary.utc
    task_name = $taskName
    task_state = [string]$task.State
    last_run_at_utc = Convert-LocalTaskTimeToUtcText -Value $info.LastRunTime
    last_task_result = [long]$info.LastTaskResult
    next_run_time_local = Convert-LocalTaskTimeToJstText -Value $info.NextRunTime
    principal = [ordered]@{
      user_id = [string]$Receipt.windows_sid
      logon_type = "InteractiveToken"
      run_level = "LeastPrivilege"
    }
    action = [ordered]@{
      execute = [string]$Receipt.command
      arguments = [string]$Receipt.arguments
      working_directory = [string]$Receipt.working_directory
    }
    prior_task_states = $priorStates
    collection = [ordered]@{
      apis = @(
        "Export-ScheduledTask",
        "Get-ScheduledTask",
        "Get-ScheduledTaskInfo"
      )
      task_path = "\"
      task_scheduler_mutation = "NOT_PERFORMED"
      broker_mutation = "NOT_PERFORMED"
    }
  }
}

function New-TaskSchedulerEvidence {
  param(
    [Parameter(Mandatory = $true)][object]$Boundary,
    [Parameter(Mandatory = $true)][string]$CapturedAtUtc
  )
  $captured = [DateTimeOffset]::Parse($CapturedAtUtc)
  $boundaryUtc = [DateTimeOffset]::Parse([string]$Boundary.utc)
  $queryStart = $boundaryUtc.AddMinutes(-5)
  $log = Get-WinEvent -ListLog $operationalLog -ErrorAction Stop
  if ($null -eq $log -or [bool]$log.IsEnabled -ne $true) {
    throw "Task Scheduler Operational log must already be enabled."
  }
  $filter = @{
    LogName = $operationalLog
    Id = $eventIds
    StartTime = $queryStart.UtcDateTime
    EndTime = $captured.UtcDateTime
  }
  $rows = @(
    foreach ($event in @(
      Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    )) {
      $rawXml = [string]$event.ToXml()
      [xml]$parsed = $rawXml
      $observedTask = Get-EventDataValue -EventXml $parsed -Name "TaskName"
      if ($observedTask -ne "\$taskName") {
        continue
      }
      if (
        [string]$event.ProviderName -ne $eventProvider -or
        [string]$event.LogName -ne $operationalLog -or
        $null -eq $event.TimeCreated -or
        $null -eq $event.RecordId
      ) {
        throw "Task Scheduler event projection is incomplete."
      }
      [PSCustomObject][ordered]@{
        event_id = [int]$event.Id
        event_record_id = [long]$event.RecordId
        time_created_utc = $event.TimeCreated.ToUniversalTime().ToString(
          "yyyy-MM-ddTHH:mm:ss.fffffffZ",
          [Globalization.CultureInfo]::InvariantCulture
        )
        raw_xml = $rawXml
        raw_xml_sha256 = Get-TextSHA256 -Value $rawXml
      }
    }
  )
  $rows = @($rows | Sort-Object event_record_id)
  if ($rows.Count -lt 2) {
    throw "Correlated Task Scheduler automatic-run evidence is unavailable."
  }
  return [ordered]@{
    schema_version = (
      "phillip-commodity-window-02-task-scheduler-events-v1"
    )
    captured_at_utc = $CapturedAtUtc
    channel = $operationalLog
    provider = $eventProvider
    task_name = "\$taskName"
    query = [ordered]@{
      event_ids = $eventIds
      start_at_utc = $queryStart.ToString(
        "yyyy-MM-ddTHH:mm:ssZ",
        [Globalization.CultureInfo]::InvariantCulture
      )
      end_at_utc = $CapturedAtUtc
      operational_log_enabled = $true
    }
    events = $rows
    collection = [ordered]@{
      api = "Get-WinEvent"
      event_messages_used_for_validation = $false
      task_scheduler_mutation = "NOT_PERFORMED"
    }
  }
}

function Assert-Readiness {
  $records = @(
    & $readinessPath `
      -ToolkitArchive $ToolkitArchive `
      -ExpectedToolkitArchiveSHA256 $ExpectedToolkitArchiveSHA256 `
      -TargetBoundary $TargetBoundaryLocal `
      -SchedulerOperatorRoot $SchedulerOperatorRoot `
      -Repo $Repo `
      -RuntimeRepo $RuntimeRepo `
      -ReleasePython $ReleasePython `
      -CommodityTerminal $CommodityTerminal `
      2>&1
  )
  if (-not $?) {
    $records
    throw "Window 02 automatic-run acceptance readiness failed."
  }
}

function Invoke-PhaseCapture {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Start", "Completion")]
    [string]$Phase,
    [Parameter(Mandatory = $true)][object]$Boundary,
    [Parameter()][string]$VerifiedStartArchive = "",
    [Parameter()][string]$VerifiedStartSHA256 = ""
  )
  $captureStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  $eventLogElapsedSeconds = 0.0
  Assert-Readiness
  $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    "ai-scalper-window02-acceptance-" + [Guid]::NewGuid().ToString("N")
  )
  [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
  Assert-NonReparseDirectory -Path $tempRoot
  try {
    $receipt = Get-Content `
      -LiteralPath $installationReceiptPath `
      -Raw `
      -ErrorAction Stop |
      ConvertFrom-Json
    $healthTranscript = Join-Path $tempRoot "health.txt"
    $statusTranscript = Join-Path $tempRoot "runtime-status.txt"
    $taskObservationPath = Join-Path $tempRoot "task-observation.json"
    $aclEvidencePath = Join-Path $tempRoot "receipt-acl.json"
    $eventEvidencePath = Join-Path $tempRoot "task-events.json"
    $currentTaskXmlPath = Join-Path $tempRoot "installed-task.xml"
    $contractPath = Join-Path $tempRoot "contract-authentication.json"

    Write-Utf8Text -Value (Get-HealthTranscript) -Path $healthTranscript
    Write-Utf8Text `
      -Value ((Get-RuntimeStatusTranscript) + "`n") `
      -Path $statusTranscript
    $capturedAtUtc = [DateTimeOffset]::UtcNow.ToString(
      "yyyy-MM-ddTHH:mm:ss.fffffffZ",
      [Globalization.CultureInfo]::InvariantCulture
    )
    $taskObservation = New-TaskObservation `
      -Receipt $receipt `
      -Boundary $Boundary `
      -CapturedAtUtc $capturedAtUtc
    Write-Utf8Json -Value $taskObservation -Path $taskObservationPath
    $aclEvidence = New-ReceiptAclEvidence `
      -Receipt $receipt `
      -CapturedAtUtc $capturedAtUtc
    Write-Utf8Json -Value $aclEvidence -Path $aclEvidencePath
    $eventStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $eventEvidence = New-TaskSchedulerEvidence `
        -Boundary $Boundary `
        -CapturedAtUtc $capturedAtUtc
    }
    finally {
      $eventStopwatch.Stop()
      $eventLogElapsedSeconds = $eventStopwatch.Elapsed.TotalSeconds
    }
    Write-Utf8Json -Value $eventEvidence -Path $eventEvidencePath
    Export-CurrentTaskXml -Path $currentTaskXmlPath

    $auditSelectionText = Invoke-CheckedNative `
      -FilePath $ReleasePython `
      -Arguments @(
        "-I", "-S", "-B", $toolPath,
        "select-audit-pair",
        "--audit-root", $auditRoot,
        "--runtime-status-transcript", $statusTranscript
      ) `
      -Operation "Authenticated audit pair selection"
    $auditSelection = $auditSelectionText | ConvertFrom-Json
    Assert-RegularNonReparseFile -Path $auditSelection.audit_export
    Assert-RegularNonReparseFile -Path $auditSelection.audit_manifest

    $stamp = ([DateTimeOffset]::Parse([string]$Boundary.utc)).ToString(
      "yyyyMMddTHHmmssZ",
      [Globalization.CultureInfo]::InvariantCulture
    )
    if (-not (Test-Path -LiteralPath $OutputRoot)) {
      [System.IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
    }
    Assert-NonReparseDirectory -Path $OutputRoot

    if ($Phase -eq "Start") {
      Write-Utf8Text `
        -Value ((Get-ContractAuthentication) + "`n") `
        -Path $contractPath
      $output = Join-Path $OutputRoot (
        "phillip-commodity-window-02-automatic-start-$stamp.zip"
      )
      $resultText = Invoke-CheckedNative `
        -FilePath $ReleasePython `
        -Arguments @(
          "-I", "-S", "-B", $toolPath,
          "collect-start",
          "--toolkit-manifest", $manifestPath,
          "--tool-path", $toolPath,
          "--installation-receipt", $installationReceiptPath,
          "--installed-task-xml", $currentTaskXmlPath,
          "--receipt-acl-evidence", $aclEvidencePath,
          "--contract-authentication", $contractPath,
          "--health-transcript", $healthTranscript,
          "--runtime-status-transcript", $statusTranscript,
          "--task-observation", $taskObservationPath,
          "--task-scheduler-events", $eventEvidencePath,
          "--audit-export", [string]$auditSelection.audit_export,
          "--audit-manifest", [string]$auditSelection.audit_manifest,
          "--target-boundary-local", $TargetBoundaryLocal,
          "--output", $output
        ) `
        -Operation "Automatic start acceptance collection"
    }
    else {
      if (
        [string]::IsNullOrWhiteSpace($VerifiedStartArchive) -or
        [string]::IsNullOrWhiteSpace($VerifiedStartSHA256)
      ) {
        throw "Completion collection requires the exact start archive and hash."
      }
      Assert-RegularNonReparseFile -Path $VerifiedStartArchive
      $output = Join-Path $OutputRoot (
        "phillip-commodity-window-02-automatic-completion-$stamp.zip"
      )
      $resultText = Invoke-CheckedNative `
        -FilePath $ReleasePython `
        -Arguments @(
          "-I", "-S", "-B", $toolPath,
          "collect-completion",
          "--toolkit-manifest", $manifestPath,
          "--tool-path", $toolPath,
          "--start-archive", $VerifiedStartArchive,
          "--expected-start-archive-sha256", $VerifiedStartSHA256,
          "--installation-receipt", $installationReceiptPath,
          "--installed-task-xml", $currentTaskXmlPath,
          "--receipt-acl-evidence", $aclEvidencePath,
          "--health-transcript", $healthTranscript,
          "--runtime-status-transcript", $statusTranscript,
          "--task-observation", $taskObservationPath,
          "--task-scheduler-events", $eventEvidencePath,
          "--audit-export", [string]$auditSelection.audit_export,
          "--audit-manifest", [string]$auditSelection.audit_manifest,
          "--target-boundary-local", $TargetBoundaryLocal,
          "--output", $output
        ) `
        -Operation "Automatic completion acceptance collection"
    }
    $result = $resultText | ConvertFrom-Json
    $captureStopwatch.Stop()
    $effectiveCaptureSeconds = (
      $captureStopwatch.Elapsed.TotalSeconds - $eventLogElapsedSeconds
    )
    if ($effectiveCaptureSeconds -gt 120) {
      throw (
        "ACCEPTANCE_CAPTURE_DEADLINE_EXCEEDED: locally verified archive " +
        "preserved at $output"
      )
    }
    $result | Add-Member `
      -NotePropertyName collection_elapsed_seconds `
      -NotePropertyValue ([Math]::Round(
        $effectiveCaptureSeconds,
        3
      ))
    $result | Add-Member `
      -NotePropertyName event_log_elapsed_seconds `
      -NotePropertyValue ([Math]::Round($eventLogElapsedSeconds, 3))
    return $result
  }
  finally {
    if (
      (Test-Path -LiteralPath $tempRoot -PathType Container) -and
      ([System.IO.Path]::GetFileName($tempRoot) -like
        "ai-scalper-window02-acceptance-*")
    ) {
      Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction Stop
    }
  }
}

foreach ($path in @(
  $ToolkitArchive,
  $ReleasePython,
  $toolPath,
  $manifestPath,
  $readinessPath
)) {
  Assert-RegularNonReparseFile -Path $path
}
$observedArchiveHash = (
  Get-FileHash -LiteralPath $ToolkitArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $observedArchiveHash -ne
    $ExpectedToolkitArchiveSHA256.ToLowerInvariant()
) {
  throw "Acceptance toolkit archive SHA-256 mismatch."
}
$observedToolHash = (
  Get-FileHash -LiteralPath $toolPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observedToolHash -ne $expectedToolSHA256) {
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

$boundaryText = Invoke-CheckedNative `
  -FilePath $ReleasePython `
  -Arguments @(
    "-I", "-S", "-B", $toolPath,
    "boundary-info", "--target-boundary-local", $TargetBoundaryLocal
  ) `
  -Operation "Target automatic boundary validation"
$boundary = $boundaryText | ConvertFrom-Json

if ($Mode -eq "CollectStart") {
  Invoke-PhaseCapture -Phase "Start" -Boundary $boundary | Format-List
  return
}
if ($Mode -eq "CollectCompletion") {
  Invoke-PhaseCapture `
    -Phase "Completion" `
    -Boundary $boundary `
    -VerifiedStartArchive $StartArchive `
    -VerifiedStartSHA256 $ExpectedStartArchiveSHA256 |
    Format-List
  return
}

Assert-Readiness
$boundaryAt = [DateTimeOffset]::Parse([string]$boundary.utc)
$startEligibleAt = $boundaryAt.AddSeconds(300)
$expectedEnd = [DateTimeOffset]::Parse(
  [string]$boundary.expected_worker_end_utc
)
$captureEnd = [DateTimeOffset]::Parse(
  [string]$boundary.completion_capture_end_utc
)
$watchStartedAt = [DateTimeOffset]::UtcNow
$watchDeadline = $captureEnd
if ($PSBoundParameters.ContainsKey("WatchTimeoutSeconds")) {
  if ($WatchTimeoutSeconds -lt 1) {
    throw "WATCH_TIMEOUT_SECONDS_REJECTED"
  }
  $requestedDeadline = $watchStartedAt.AddSeconds($WatchTimeoutSeconds)
  if ($requestedDeadline -lt $watchDeadline) {
    $watchDeadline = $requestedDeadline
  }
}
[PSCustomObject]@{
  Status = "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_WATCHING"
  TargetBoundaryLocal = [string]$boundary.local
  TargetBoundaryUtc = [string]$boundary.utc
  WatchStartedAtUtc = $watchStartedAt.ToString("o")
  WatchDeadlineUtc = $watchDeadline.ToString("o")
  PollSeconds = $WatchPollSeconds
  ManualStartPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  TaskSchedulerMutation = "NOT_PERFORMED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
$startResult = $null
while ($null -eq $startResult) {
  $now = [DateTimeOffset]::UtcNow
  if ($now -ge $watchDeadline) {
    throw "AUTOMATIC_RUN_ACCEPTANCE_WATCH_TIMEOUT_BEFORE_START"
  }
  if ($now -ge $expectedEnd) {
    throw "Start acceptance was not captured before the worker end boundary."
  }
  $task = Get-ExactRootTask -Name $taskName
  if ($now -ge $startEligibleAt) {
    if ([string]$task.State -ne "Running") {
      throw "AUTOMATIC_START_STATE_REJECTED_AFTER_STARTUP_ALLOWANCE"
    }
    else {
      $startResult = Invoke-PhaseCapture -Phase "Start" -Boundary $boundary
      break
    }
  }
  Start-Sleep -Seconds $WatchPollSeconds
}
$startArchivePath = [string]$startResult.archive
$startArchiveHash = [string]$startResult.archive_sha256
while ($true) {
  $now = [DateTimeOffset]::UtcNow
  if ($now -ge $watchDeadline) {
    throw (
      "AUTOMATIC_RUN_ACCEPTANCE_WATCH_TIMEOUT_AFTER_START: " +
      "verified start preserved at $startArchivePath with SHA-256 " +
      $startArchiveHash
    )
  }
  if ($now -ge $captureEnd) {
    throw "Completion acceptance capture window expired."
  }
  $task = Get-ExactRootTask -Name $taskName
  $info = Get-ScheduledTaskInfo `
    -TaskName $taskName `
    -TaskPath "\" `
    -ErrorAction Stop
  if (
    $now -ge $expectedEnd -and
    [string]$task.State -eq "Ready"
  ) {
    if ([long]$info.LastTaskResult -ne 0) {
      throw "AUTOMATIC_COMPLETION_RESULT_REJECTED"
    }
    $completion = Invoke-PhaseCapture `
      -Phase "Completion" `
      -Boundary $boundary `
      -VerifiedStartArchive $startArchivePath `
      -VerifiedStartSHA256 $startArchiveHash
    [PSCustomObject]@{
      Status = "PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_COMPLETE"
      StartArchive = $startArchivePath
      StartArchiveSHA256 = $startArchiveHash
      CompletionArchive = [string]$completion.archive
      CompletionArchiveSHA256 = [string]$completion.archive_sha256
      ProcessExitCode = [int]$completion.process_exit_code
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
    break
  }
  Start-Sleep -Seconds $WatchPollSeconds
}
