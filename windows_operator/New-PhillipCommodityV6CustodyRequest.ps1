[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [string]$AcceptanceArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedAcceptanceArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")]
  [string]$DestinationId,

  [Parameter()]
  [string]$MinimumRetainUntilUtc = "",

  [Parameter()]
  [string]$ReleasePython = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-ecedec9-venv\Scripts\python.exe"
  ),

  [Parameter()]
  [string]$Output = (
    "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-custody-requests\" +
    "phillip-commodity-v6-custody-request-" +
    [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
    ".zip"
  )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$toolkitSourceCommit = "__TOOLKIT_SOURCE_COMMIT__"
$toolkitSourceTree = "__TOOLKIT_SOURCE_TREE__"
$expectedToolSHA256 = "__POSTRUN_TOOL_SHA256__"
$toolPath = Join-Path $PSScriptRoot (
  "phillip_commodity_v6_postrun_acceptance.py"
)

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

foreach ($path in @(
  $ToolkitArchive,
  $AcceptanceArchive,
  $ReleasePython,
  $toolPath
)) {
  Assert-RegularNonReparseFile -Path $path
}

$toolkitHash = (
  Get-FileHash -LiteralPath $ToolkitArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($toolkitHash -ne $ExpectedToolkitArchiveSHA256.ToLowerInvariant()) {
  throw "Post-run toolkit archive SHA-256 mismatch."
}
$toolHash = (
  Get-FileHash -LiteralPath $toolPath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($toolHash -ne $expectedToolSHA256) {
  throw "Post-run Python tool SHA-256 mismatch."
}
$acceptanceHash = (
  Get-FileHash -LiteralPath $AcceptanceArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $acceptanceHash -ne
    $ExpectedAcceptanceArchiveSHA256.ToLowerInvariant()
) {
  throw "Acceptance archive SHA-256 mismatch."
}

$toolkitCheck = @(
  & $ReleasePython -I -S -B $toolPath verify-toolkit `
    --archive $ToolkitArchive `
    --expected-archive-sha256 $toolkitHash `
    --expected-source-commit $toolkitSourceCommit `
    --expected-source-tree $toolkitSourceTree 2>&1
)
if ($LASTEXITCODE -ne 0) {
  $toolkitCheck
  throw "Post-run toolkit verification failed."
}

$requestedAt = [DateTimeOffset]::UtcNow
$engineeringFloor = [DateTimeOffset]::Parse(
  "2027-09-21T15:16:00Z"
)
if ([string]::IsNullOrWhiteSpace($MinimumRetainUntilUtc)) {
  $retainUntil = $requestedAt.AddDays(365)
  if ($retainUntil -lt $engineeringFloor) {
    $retainUntil = $engineeringFloor
  }
}
else {
  $retainUntil = [DateTimeOffset]::Parse($MinimumRetainUntilUtc)
  if ($retainUntil.Offset -ne [TimeSpan]::Zero) {
    throw "Minimum retention timestamp must use UTC."
  }
}
$requestedAtText = $requestedAt.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ")
$retainUntilText = $retainUntil.ToUniversalTime().ToString(
  "yyyy-MM-ddTHH:mm:ss.ffffffZ"
)

$resultText = @(
  & $ReleasePython -I -S -B $toolPath prepare-custody `
    --acceptance-archive $AcceptanceArchive `
    --expected-acceptance-archive-sha256 $acceptanceHash `
    --expected-toolkit-source-commit $toolkitSourceCommit `
    --expected-toolkit-source-tree $toolkitSourceTree `
    --destination-id $DestinationId `
    --requested-at-utc $requestedAtText `
    --minimum-retain-until-utc $retainUntilText `
    --output $Output 2>&1
)
if ($LASTEXITCODE -ne 0) {
  $resultText
  throw "WORM custody request preparation failed."
}
$result = ($resultText -join [Environment]::NewLine) | ConvertFrom-Json
if (
  $result.status -ne
    "PHILLIP_COMMODITY_V6_WORM_CUSTODY_REQUEST_READY" -or
  $result.acceptance_archive_sha256 -ne $acceptanceHash -or
  $result.offhost_custody_performed -ne $false -or
  $result.order_capability -ne "DISABLED" -or
  $result.live_allowed -ne $false -or
  $result.promotion_eligible -ne $false
) {
  throw "WORM custody request projection mismatch."
}

[PSCustomObject]@{
  Status = $result.status
  Archive = $result.archive
  ArchiveSHA256 = $result.archive_sha256
  RequestIdentitySHA256 = $result.request_identity_sha256
  AcceptanceArchiveSHA256 = $result.acceptance_archive_sha256
  DestinationId = $result.destination_id
  MinimumRetainUntilUtc = $result.minimum_retain_until_utc
  CopyInstruction = "COPY_REQUEST_ZIP_TO_INDEPENDENT_WORM_CUSTODIAN"
  OffhostCustodyPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  PromotionEligible = $false
} | Format-List
