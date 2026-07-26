[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$TerminalPath,

  [Parameter()]
  [string]$Repo = "C:\AI_SCALPER",

  [Parameter()]
  [string]$Python = "C:\AI_SCALPER\.venv\Scripts\python.exe"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$expectedCommit = "__EXPECTED_COMMIT__"
$expectedTree = "__EXPECTED_TREE__"
$officialBranch = "__OFFICIAL_BRANCH__"
$expectedCandidate = "finex"
$expectedEligibility = "PREPARATION_ONLY_ELIGIBILITY_PENDING"
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

if (-not [System.IO.Path]::IsPathFullyQualified($TerminalPath)) {
  throw "FINEX_TERMINAL_PATH_INVALID"
}
if (-not (Test-Path -LiteralPath $TerminalPath -PathType Leaf)) {
  throw "FINEX_TERMINAL_PATH_INVALID"
}
$terminalItem = Get-Item -LiteralPath $TerminalPath -Force -ErrorAction Stop
$linkTypeProperty = $terminalItem.PSObject.Properties["LinkType"]
$isLink = (
  $null -ne $linkTypeProperty -and
  -not [string]::IsNullOrWhiteSpace([string]$linkTypeProperty.Value)
)
$isReparse = (
  $terminalItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint
) -ne 0
if (
  $terminalItem.Name.ToLowerInvariant() -ne "terminal64.exe" -or
  $isLink -or
  $isReparse
) {
  throw "FINEX_TERMINAL_PATH_INVALID"
}
$resolvedTerminal = $terminalItem.FullName

foreach ($pathValue in @($Repo, $Python)) {
  if (-not [System.IO.Path]::IsPathFullyQualified($pathValue)) {
    throw "FINEX_LOCAL_PATH_INVALID"
  }
}
$repoItem = Get-Item -LiteralPath $Repo -ErrorAction Stop
$pythonItem = Get-Item -LiteralPath $Python -ErrorAction Stop
if (-not $repoItem.PSIsContainer -or $pythonItem.PSIsContainer) {
  throw "FINEX_LOCAL_PATH_INVALID"
}

Push-Location $repoItem.FullName
try {
  $head = Invoke-CheckedGit -Arguments @("rev-parse", "HEAD") -Operation "HEAD inspection"
  $tree = Invoke-CheckedGit -Arguments @("rev-parse", "HEAD^{tree}") -Operation "tree inspection"
  if ($head -ne $expectedCommit -or $tree -ne $expectedTree) {
    throw "FINEX_SOURCE_IDENTITY_MISMATCH"
  }
  & git show-ref --verify --quiet "refs/remotes/origin/$officialBranch"
  if ($LASTEXITCODE -ne 0) {
    throw "FINEX_OFFICIAL_BRANCH_REFERENCE_MISSING"
  }
  & git merge-base --is-ancestor $expectedCommit "origin/$officialBranch"
  if ($LASTEXITCODE -ne 0) {
    throw "FINEX_SOURCE_NOT_ON_OFFICIAL_BRANCH"
  }

  $requiredJson = [System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String($requiredFilesJsonBase64)
  )
  $requiredFiles = @($requiredJson | ConvertFrom-Json)
  foreach ($file in $requiredFiles) {
    $relative = ([string]$file.path).Replace("/", "\")
    $path = Join-Path $repoItem.FullName $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
      throw "FINEX_REQUIRED_SOURCE_MISSING: $($file.path)"
    }
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    $observedHash = (
      Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($item.Length -ne [long]$file.size_bytes) {
      throw "FINEX_REQUIRED_SOURCE_SIZE_MISMATCH: $($file.path)"
    }
    if ($observedHash -ne [string]$file.sha256) {
      throw "FINEX_REQUIRED_SOURCE_HASH_MISMATCH: $($file.path)"
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
    throw "FINEX_CANDIDATE_BINDING_INVALID"
  }
  $candidate = $matches[0]
  if (
    $candidate.read_only_discovery_allowed -ne $false -or
    $candidate.regulatory_observation.legal_eligible -ne $false -or
    $candidate.regulatory_observation.decision -ne
      "SELECTED_BY_OPERATOR_PREPARE_ONLY_NO_CURRENT_JAPAN_OPERATION"
  ) {
    throw "FINEX_PREPARATION_POLICY_DRIFT"
  }

  & $pythonItem.FullName -I -S -B (
    Join-Path $repoItem.FullName "verify_windows_dependency_lock.py"
  ) --require-current-runtime
  if ($LASTEXITCODE -ne 0) {
    throw "FINEX_DEPENDENCY_LOCK_REJECTED"
  }

  & $pythonItem.FullName -B (
    Join-Path $repoItem.FullName "run_mt5_readonly_preflight.py"
  ) --candidate "finex" --terminal-path $resolvedTerminal
  if ($LASTEXITCODE -ne 0) {
    throw "FINEX_READ_ONLY_PREFLIGHT_REJECTED"
  }

  [PSCustomObject]@{
    Status = "FINEX_PREPARATION_PREFLIGHT_VERIFIED"
    Candidate = $expectedCandidate
    Eligibility = $expectedEligibility
    SourceCommit = $expectedCommit
    SourceTree = $expectedTree
    Terminal = $resolvedTerminal
    CredentialAccess = "NOT_PERFORMED"
    Discovery = "DISABLED"
    ContractRegistration = "DISABLED"
    TaskInstallation = "DISABLED"
    PromotionEvidence = "DISABLED"
    OrderCapability = "DISABLED"
    LiveAllowed = $false
    CryptoBinding = "NOT_LISTED_IN_REVIEWED_OFFICIAL_INVENTORY"
  } | Format-List
}
finally {
  Pop-Location
}
