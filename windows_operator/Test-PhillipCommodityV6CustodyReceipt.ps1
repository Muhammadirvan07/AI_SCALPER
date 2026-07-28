[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$ToolkitArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedToolkitArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [string]$CustodyRequestArchive,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedCustodyRequestArchiveSHA256,

  [Parameter(Mandatory = $true)]
  [string]$Policy,

  [Parameter(Mandatory = $true)]
  [ValidatePattern("^[0-9a-fA-F]{64}$")]
  [string]$ExpectedPolicySHA256,

  [Parameter(Mandatory = $true)]
  [string]$Receipt,

  [Parameter()]
  [string]$ReleasePython = (
    "C:\AI_SCALPER_PRIVATE\" +
    "phillip-commodity-ecedec9-venv\Scripts\python.exe"
  ),

  [Parameter()]
  [string]$AssessmentOutput = (
    "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-custody-assessments\" +
    "phillip-commodity-v6-custody-assessment-" +
    [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
    ".json"
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
  $CustodyRequestArchive,
  $Policy,
  $Receipt,
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
$requestHash = (
  Get-FileHash -LiteralPath $CustodyRequestArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if (
  $requestHash -ne
    $ExpectedCustodyRequestArchiveSHA256.ToLowerInvariant()
) {
  throw "Custody request archive SHA-256 mismatch."
}
$policyHash = (
  Get-FileHash -LiteralPath $Policy -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($policyHash -ne $ExpectedPolicySHA256.ToLowerInvariant()) {
  throw "Custodian trust policy SHA-256 mismatch."
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

$verifiedAtUtc = [DateTimeOffset]::UtcNow.ToString(
  "yyyy-MM-ddTHH:mm:ss.ffffffZ"
)
$resultText = @(
  & $ReleasePython -I -S -B $toolPath verify-custody-receipt `
    --custody-request-archive $CustodyRequestArchive `
    --expected-custody-request-archive-sha256 $requestHash `
    --expected-toolkit-source-commit $toolkitSourceCommit `
    --expected-toolkit-source-tree $toolkitSourceTree `
    --policy $Policy `
    --expected-policy-sha256 $policyHash `
    --receipt $Receipt `
    --verified-at-utc $verifiedAtUtc `
    --assessment-output $AssessmentOutput 2>&1
)
if ($LASTEXITCODE -ne 0) {
  $resultText
  throw "Signed WORM custody receipt verification failed."
}
$result = ($resultText -join [Environment]::NewLine) | ConvertFrom-Json
if (
  $result.status -ne
    "PHILLIP_COMMODITY_V6_WORM_CUSTODY_ATTESTATION_VERIFIED" -or
  $result.signed_custodian_attestation_accepted -ne $true -or
  $result.direct_storage_api_inspection_performed -ne $false -or
  $result.order_capability -ne "DISABLED" -or
  $result.live_allowed -ne $false -or
  $result.promotion_eligible -ne $false
) {
  throw "Signed WORM custody assessment projection mismatch."
}

[PSCustomObject]@{
  Status = $result.status
  Assessment = $result.assessment
  AssessmentSHA256 = $result.assessment_sha256
  AssessmentIdentitySHA256 = $result.assessment_identity_sha256
  CustodyRequestArchiveSHA256 = $result.custody_request_archive_sha256
  AcceptanceArchiveSHA256 = $result.acceptance_archive_sha256
  ReceiptSHA256 = $result.receipt_sha256
  PolicySHA256 = $result.policy_sha256
  RetainUntilUtc = $result.retain_until_utc
  SignedCustodianAttestationAccepted = $true
  DirectStorageApiInspectionPerformed = $false
  OrderCapability = "DISABLED"
  LiveAllowed = $false
  PromotionEligible = $false
} | Format-List
