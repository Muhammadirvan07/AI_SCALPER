[CmdletBinding()]
param(
  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedCommit = "__EXPECTED_COMMIT__"
$expectedTree = "__EXPECTED_TREE__"
$officialBranch = "__OFFICIAL_BRANCH__"
$expectedCandidate = "xm"
$expectedEligibility = "LEGAL_BLOCKED_CURRENT_JAPAN"
$requiredFilesJsonBase64 = "__REQUIRED_FILES_JSON_BASE64__"

function Invoke-CheckedGit {
  param(
    [Parameter(Mandatory = $true)]
    [string[]]$Arguments,

    [Parameter(Mandatory = $true)]
    [string]$Operation
  )
  $value = (& git @Arguments 2>&1 | Out-String).Trim()
  if ($LASTEXITCODE -ne 0) {
    throw "$Operation failed with exit code $LASTEXITCODE."
  }
  return $value
}

if (-not [System.IO.Path]::IsPathFullyQualified($Repo)) {
  throw "XM_REPO_PATH_INVALID"
}
$repoItem = Get-Item -LiteralPath $Repo -ErrorAction Stop
if (-not $repoItem.PSIsContainer) {
  throw "XM_REPO_PATH_INVALID"
}

Push-Location $repoItem.FullName
try {
  $head = Invoke-CheckedGit -Arguments @("rev-parse", "HEAD") -Operation "HEAD inspection"
  $tree = Invoke-CheckedGit -Arguments @("rev-parse", "HEAD^{tree}") -Operation "tree inspection"
  if ($head -ne $expectedCommit -or $tree -ne $expectedTree) {
    throw "XM_SOURCE_IDENTITY_MISMATCH"
  }
  & git show-ref --verify --quiet "refs/remotes/origin/$officialBranch"
  if ($LASTEXITCODE -ne 0) {
    throw "XM_OFFICIAL_BRANCH_REFERENCE_MISSING"
  }
  & git merge-base --is-ancestor $expectedCommit "origin/$officialBranch"
  if ($LASTEXITCODE -ne 0) {
    throw "XM_SOURCE_NOT_ON_OFFICIAL_BRANCH"
  }

  $requiredJson = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($requiredFilesJsonBase64)
  )
  $requiredFiles = @($requiredJson | ConvertFrom-Json)
  foreach ($file in $requiredFiles) {
    $relative = ([string]$file.path).Replace("/", "\")
    $path = Join-Path $repoItem.FullName $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "XM_REQUIRED_SOURCE_MISSING: $($file.path)"
    }
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $observedHash = (
      Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($item.Length -ne [long]$file.size_bytes) {
      throw "XM_REQUIRED_SOURCE_SIZE_MISMATCH: $($file.path)"
    }
    if ($observedHash -ne [string]$file.sha256) {
      throw "XM_REQUIRED_SOURCE_HASH_MISMATCH: $($file.path)"
    }
  }

  $candidateConfigPath = Join-Path $repoItem.FullName (
    "config\broker_candidates.phase3.json"
  )
  $candidateConfig = Get-Content $candidateConfigPath -Raw | ConvertFrom-Json
  $matches = @(
    $candidateConfig.candidates |
      Where-Object { $_.candidate_id -eq $expectedCandidate }
  )
  if ($matches.Count -ne 1) {
    throw "XM_CANDIDATE_BINDING_INVALID"
  }
  $candidate = $matches[0]
  if (
    $candidate.regulatory_observation.legal_eligible -ne $false -or
    $candidate.regulatory_observation.decision -ne
      "BLOCK_XM_WINDOW_02_WHILE_OPERATING_FROM_JAPAN"
  ) {
    throw "XM_LEGAL_HOLD_POLICY_DRIFT"
  }
  $discoveryProperty = $candidate.PSObject.Properties["read_only_discovery_allowed"]
  if ($null -ne $discoveryProperty -and $discoveryProperty.Value -eq $true) {
    throw "XM_DISCOVERY_MUST_REMAIN_DISABLED"
  }

  [PSCustomObject]@{
    Status = "XM_PREPARATION_GATE_VERIFIED"
    Candidate = $expectedCandidate
    Eligibility = $expectedEligibility
    SourceCommit = $expectedCommit
    SourceTree = $expectedTree
    MT5Initialization = "NOT_PERFORMED"
    CredentialAccess = "NOT_PERFORMED"
    Discovery = "DISABLED"
    ContractRegistration = "DISABLED"
    TaskInstallation = "DISABLED"
    OrderCapability = "DISABLED"
    LiveAllowed = $false
    CryptoBinding = "ACCOUNT_ENTITY_DISCOVERY_REQUIRED_AFTER_LEGAL_APPROVAL"
  } | Format-List
}
finally {
  Pop-Location
}
