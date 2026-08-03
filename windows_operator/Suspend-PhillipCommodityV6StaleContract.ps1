[CmdletBinding()]
param(
  [Parameter()]
  [string]$TaskName = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow",

  [Parameter()]
  [string]$SnapshotRoot = (
    "C:\AI_SCALPER\validation_artifacts\snapshots\" +
    "phillip-commodity-dev-pre-window-01-v1"
  ),

  [Parameter()]
  [string]$ReceiptRoot = (
    "C:\AI_SCALPER_PRIVATE\phillip-v6-stale-contract-quiesce-" +
    [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ")
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedExecute = (
  "C:\AI_SCALPER_PRIVATE\" +
  "phillip-commodity-ecedec9-venv\Scripts\python.exe"
)
$expectedWorkingDirectory = (
  "C:\AI_SCALPER_RELEASES\" +
  "290cc23d-phillip-commodity-shadow-source"
)
$expectedWorker = Join-Path $expectedWorkingDirectory (
  "run_broker_shadow_once.py"
)

function Assert-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
  )) {
    throw "Run this quiesce operation from Administrator PowerShell."
  }
}

function Assert-RealDirectory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "Required directory is unavailable: $Path"
  }
  $item = Get-Item -LiteralPath $Path -Force
  if (
    ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
  ) {
    throw "Required directory must not be a reparse point: $Path"
  }
}

function Get-SHA256Text {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Text
  )
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
  $algorithm = [Security.Cryptography.SHA256]::Create()
  try {
    return ([BitConverter]::ToString(
      $algorithm.ComputeHash($bytes)
    )).Replace("-", "").ToLowerInvariant()
  }
  finally {
    $algorithm.Dispose()
  }
}

function Write-JsonExclusive {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $true)]
    [object]$Value
  )
  $json = $Value | ConvertTo-Json -Depth 12
  $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json + "`n")
  $stream = [IO.File]::Open(
    $Path,
    [IO.FileMode]::CreateNew,
    [IO.FileAccess]::Write,
    [IO.FileShare]::None
  )
  try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
  }
  finally {
    $stream.Dispose()
  }
}

function Get-SnapshotInventory {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root
  )
  Assert-RealDirectory -Path $Root
  $rootItem = Get-Item -LiteralPath $Root -Force
  $rootFull = $rootItem.FullName.TrimEnd("\")
  $entries = @()
  foreach ($item in @(
    Get-ChildItem -LiteralPath $Root -Force -Recurse |
      Sort-Object -Property FullName
  )) {
    if (
      ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    ) {
      throw "Snapshot inventory contains a reparse point: $($item.FullName)"
    }
    $relative = $item.FullName.Substring($rootFull.Length).TrimStart("\")
    if ($item.PSIsContainer) {
      $entries += [ordered]@{
        path = $relative.Replace("\", "/")
        type = "DIRECTORY"
        size_bytes = $null
        sha256 = $null
      }
    }
    else {
      $entries += [ordered]@{
        path = $relative.Replace("\", "/")
        type = "FILE"
        size_bytes = [int64]$item.Length
        sha256 = (
          Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
        ).Hash.ToLowerInvariant()
      }
    }
  }
  $json = $entries | ConvertTo-Json -Depth 6 -Compress
  return [PSCustomObject]@{
    Entries = $entries
    Count = $entries.Count
    SHA256 = Get-SHA256Text -Text $json
  }
}

function Get-ExactTask {
  $matches = @(
    Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop |
      Where-Object { $_.TaskPath -eq "\" }
  )
  if ($matches.Count -ne 1) {
    throw "V6 scheduled task is not unique at the root task path."
  }
  return $matches[0]
}

function Get-TaskXmlAndPrincipalSid {
  $xmlText = Export-ScheduledTask `
    -TaskName $TaskName `
    -TaskPath "\" `
    -ErrorAction Stop
  [xml]$document = $xmlText
  $nodes = @($document.SelectNodes(
    "/*[local-name()='Task']" +
    "/*[local-name()='Principals']" +
    "/*[local-name()='Principal']" +
    "/*[local-name()='UserId']"
  ))
  if ($nodes.Count -ne 1) {
    throw "Task XML must contain exactly one principal UserId."
  }
  $userId = ([string]$nodes[0].InnerText).Trim()
  if ([string]::IsNullOrWhiteSpace($userId)) {
    throw "Task principal UserId is empty."
  }
  try {
    $sid = [Security.Principal.SecurityIdentifier]::new($userId)
  }
  catch {
    $account = [Security.Principal.NTAccount]::new($userId)
    $sid = $account.Translate(
      [Security.Principal.SecurityIdentifier]
    )
  }
  return [PSCustomObject]@{
    XmlText = $xmlText
    XmlSHA256 = Get-SHA256Text -Text $xmlText
    UserId = $userId
    Sid = $sid.Value
  }
}

function Assert-ExpectedTaskAction {
  param(
    [Parameter(Mandatory = $true)]
    [object]$Task
  )
  $actions = @($Task.Actions)
  if ($actions.Count -ne 1) {
    throw "V6 task must have exactly one action."
  }
  $action = $actions[0]
  $arguments = [string]$action.Arguments
  if (
    [string]$action.Execute -cne $expectedExecute -or
    [string]$action.WorkingDirectory -cne $expectedWorkingDirectory -or
    $arguments -notlike "*$expectedWorker*" -or
    $arguments -notlike "*--candidate phillip-commodity*" -or
    $arguments -notlike "*--worker*"
  ) {
    throw "V6 task action does not match the frozen Phillip worker."
  }
}

function Assert-SidReadExecuteOnTree {
  param(
    [Parameter(Mandatory = $true)]
    [string]$Root,

    [Parameter(Mandatory = $true)]
    [string]$Sid
  )
  $targets = @(
    Get-Item -LiteralPath $Root -Force
    Get-ChildItem -LiteralPath $Root -Force -Recurse
  )
  foreach ($target in $targets) {
    $acl = Get-Acl -LiteralPath $target.FullName
    $allowed = $false
    foreach ($rule in @($acl.Access)) {
      try {
        $ruleSid = $rule.IdentityReference.Translate(
          [Security.Principal.SecurityIdentifier]
        ).Value
      }
      catch {
        continue
      }
      $rights = [Security.AccessControl.FileSystemRights]$rule.FileSystemRights
      if (
        $ruleSid -eq $Sid -and
        $rule.AccessControlType -eq "Allow" -and
        ($rights -band (
          [Security.AccessControl.FileSystemRights]::ReadAndExecute
        )) -eq [Security.AccessControl.FileSystemRights]::ReadAndExecute
      ) {
        $allowed = $true
        break
      }
    }
    if (-not $allowed) {
      throw "Task principal read/execute ACL is missing: $($target.FullName)"
    }
  }
  return $targets.Count
}

Assert-Administrator
Assert-RealDirectory -Path $SnapshotRoot
if (Test-Path -LiteralPath $ReceiptRoot) {
  throw "Receipt root already exists; preserve prior evidence: $ReceiptRoot"
}

$task = Get-ExactTask
Assert-ExpectedTaskAction -Task $task
if ([string]$task.State -eq "Running") {
  throw "V6 task is running; do not interrupt an active evidence process."
}
$taskIdentity = Get-TaskXmlAndPrincipalSid
$beforeState = [string]$task.State
$beforeInventory = Get-SnapshotInventory -Root $SnapshotRoot
$beforeAclSddl = (Get-Acl -LiteralPath $SnapshotRoot).Sddl

New-Item -ItemType Directory -Path $ReceiptRoot -ErrorAction Stop |
  Out-Null
Write-JsonExclusive `
  -Path (Join-Path $ReceiptRoot "snapshot-inventory-before.json") `
  -Value $beforeInventory.Entries
[IO.File]::WriteAllText(
  (Join-Path $ReceiptRoot "scheduled-task-before.xml"),
  $taskIdentity.XmlText,
  [Text.UTF8Encoding]::new($false)
)

if ($beforeState -ne "Disabled") {
  Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
}
$disabledTask = Get-ExactTask
if ([string]$disabledTask.State -ne "Disabled") {
  throw "V6 task did not enter the fail-closed Disabled state."
}

$icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
$grant = "*$($taskIdentity.Sid):(OI)(CI)(RX)"
& $icacls $SnapshotRoot /grant:r $grant /T /Q
if ($LASTEXITCODE -ne 0) {
  throw "Snapshot read/execute ACL remediation failed."
}

$verifiedAclTargetCount = Assert-SidReadExecuteOnTree `
  -Root $SnapshotRoot `
  -Sid $taskIdentity.Sid
$afterInventory = Get-SnapshotInventory -Root $SnapshotRoot
if (
  $afterInventory.Count -ne $beforeInventory.Count -or
  $afterInventory.SHA256 -ne $beforeInventory.SHA256
) {
  throw "Snapshot bytes changed during ACL remediation."
}
$afterAclSddl = (Get-Acl -LiteralPath $SnapshotRoot).Sddl
Write-JsonExclusive `
  -Path (Join-Path $ReceiptRoot "snapshot-inventory-after.json") `
  -Value $afterInventory.Entries

$receipt = [ordered]@{
  schema_version = "phillip-v6-stale-contract-quiesce-v1"
  status = "PHILLIP_COMMODITY_V6_STALE_CONTRACT_QUIESCED"
  observed_at_utc = [DateTimeOffset]::UtcNow.ToString(
    "yyyy-MM-ddTHH:mm:ss.fffZ"
  )
  task_name = $TaskName
  task_state_before = $beforeState
  task_state_after = [string]$disabledTask.State
  task_principal_user_id = $taskIdentity.UserId
  task_principal_sid = $taskIdentity.Sid
  task_xml_sha256 = $taskIdentity.XmlSHA256
  snapshot_root = $SnapshotRoot
  snapshot_inventory_count = $afterInventory.Count
  snapshot_inventory_sha256_before = $beforeInventory.SHA256
  snapshot_inventory_sha256_after = $afterInventory.SHA256
  snapshot_bytes_changed = $false
  snapshot_acl_sddl_before = $beforeAclSddl
  snapshot_acl_sddl_after = $afterAclSddl
  acl_targets_verified = $verifiedAclTargetCount
  task_started = $false
  acceptance_performed = $false
  old_contract_reusable = $false
  replacement_contract_required = $true
  order_capability = "DISABLED"
  live_allowed = $false
  task_scheduler_mutation = "DISABLE_STALE_TASK_ONLY"
  broker_mutation = "NOT_PERFORMED"
}
$receiptPath = Join-Path $ReceiptRoot "QUIESCE_RECEIPT.json"
Write-JsonExclusive -Path $receiptPath -Value $receipt
$receiptHash = (
  Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256
).Hash.ToLowerInvariant()

[PSCustomObject]@{
  Status = $receipt.status
  TaskStateBefore = $receipt.task_state_before
  TaskStateAfter = $receipt.task_state_after
  SnapshotInventorySHA256 = $afterInventory.SHA256
  SnapshotBytesChanged = $false
  ACLTargetsVerified = $verifiedAclTargetCount
  Receipt = $receiptPath
  ReceiptSHA256 = $receiptHash
  ReplacementContractRequired = $true
  TaskStarted = "NO"
  AcceptancePerformed = "NO"
  OrderCapability = "DISABLED"
  BrokerMutation = "NOT_PERFORMED"
} | Format-List
