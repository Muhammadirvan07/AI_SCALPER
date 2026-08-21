# Phillip Commodity Window 02 Scheduler

This is transport revision `WINDOW02.V9`, an operator-only health remediation
for the already installed least-privilege Window 02 task. It does not install,
register, enable, disable, rename, start, stop, or delete any Scheduled Task.
The installed `WINDOW02.V6` task definition, frozen worker, runtime, journal,
audit root, task-review evidence, and installation receipt remain immutable.

V9 replaces only the extracted operator verifier and health checker. The
health checker separately binds the installed V6 package commit/tree and the
new V8 package commit/tree. It continues to authenticate the exact V6
installation receipt, task XML, frozen `r6` worker, contract, dependency lock,
runtime status, and audit paths before reporting health.

The persistent root-level `.shadow-worker.lock` and `.shadow-cycle.lock`
files are runtime synchronization sidecars, not contract evidence. Health
verification accepts either sidecar only at its exact allowlisted path and
only as a stable, one-byte, regular non-reparse file. It verifies metadata
without opening the carrier because an active Windows byte-range lock may
legitimately deny reads. These sidecars do not change the nine-file verified
artifact count, and every other unexpected path still fails closed.

V9 recognizes one exact historical Windows missed-schedule state during the
missed boundary's active interval or the following gap. It requires task state
`Ready`, result `0x800710E0`, the exact derived next `06:45` run time, and one
correlated Operational Event 153 whose XML is exactly
`MissedTaskRejected` for this root task. Any automatic-start/completion/manual
event in the same interval, duplicate/malformed event data, missing log,
startup allowance, or next-boundary drift still fails closed. An active
interval with verified missed evidence does not require a nonexistent journal
or runtime heartbeat. This classification is
readiness for a future scheduler attempt; it is never acceptance of the missed
boundary.

## Bound identity

- package source commit: `__PACKAGE_SOURCE_COMMIT__`
- package source tree: `__PACKAGE_SOURCE_TREE__`
- worker commit: `da3190013d86426533019d6927a58181c624b1f8`
- worker tree: `9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10`
- contract: `phillip-commodity-window-02-diagnostic-v1`
- contract payload SHA-256:
  `cbfd753b0aed2d66af56446adc734ce8d62666e309e91bf74d24b4cc56b613a2`
- physical `contract.json` SHA-256:
  `ad4fd8853563976483fbffbd3bd97847f7e05c8a4194afd10fa95832e2fe485b`
- dependency-lock SHA-256:
  `34087f736724e7d92591f7886f565b15436c59de0d4e80a59e42b04f2851d862`
- first automatic run: `2026-08-17T06:45:00+09:00`
- task: `AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow`
- order capability: `DISABLED`

The `2026-10-13T00:16:00+09:00` end boundary includes only the contract's
15-minute final-candle finalization and 60-second ingestion grace after
`blind_until_utc`. No observation bucket after the blind boundary is valid.

## Transfer inventory

Copy these three sibling files into one new Windows transfer directory:

1. `__PACKAGE_NAME__`
2. `__PACKAGE_NAME__.manifest.json`
3. `Expand-PhillipCommodityWindow02SchedulerPackage.ps1`

Do not rename them. Do not place them inside an earlier V6 transfer or
operator directory.

## Pre-remediation checks

Run in a normal, non-Administrator PowerShell session under the same Windows
account that owns the Phillip evidence key:

```powershell
$repo = "C:\AI_SCALPER"
$branch = "codex/phillip-v6-observability"
$packageCommit = "__PACKAGE_SOURCE_COMMIT__"
$packageTree = "__PACKAGE_SOURCE_TREE__"
$workerCommit = "da3190013d86426533019d6927a58181c624b1f8"
$workerTree = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"

Set-Location $repo

if (git status --porcelain) {
  git status --short
  throw "Repository must be clean before Window 02 remediation."
}

git fetch --no-tags origin $branch
if ($LASTEXITCODE -ne 0) { throw "Official branch fetch failed." }

foreach ($identity in @(
  [PSCustomObject]@{ Commit = $packageCommit; Tree = $packageTree },
  [PSCustomObject]@{ Commit = $workerCommit; Tree = $workerTree }
)) {
  $commit = (git rev-parse "$($identity.Commit)^{commit}").Trim()
  $tree = (git rev-parse "$($identity.Commit)^{tree}").Trim()
  if ($commit -ne $identity.Commit -or $tree -ne $identity.Tree) {
    throw "Required source identity mismatch."
  }
  git merge-base --is-ancestor $identity.Commit "origin/$branch"
  if ($LASTEXITCODE -ne 0) {
    throw "Required source is not on the official branch."
  }
}

$historical = @(
  Get-ScheduledTask -ErrorAction Stop |
    Where-Object {
      $_.TaskPath -eq "\" -and
      $_.TaskName -in @(
        "AI_SCALPER-PhillipCommodityV4-ReadOnlyShadow",
        "AI_SCALPER-PhillipCommodityV5-ReadOnlyShadow",
        "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
      )
    }
)

$unsafe = @($historical | Where-Object { $_.State -ne "Disabled" })
if ($unsafe.Count -ne 0) {
  $unsafe | Select-Object TaskName, State
  throw "Every existing historical Phillip task must remain Disabled."
}

$historical | Select-Object TaskName, State

$window02 = @(
  Get-ScheduledTask `
    -TaskName "AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow" `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.TaskPath -eq "\" }
)
if ($window02.Count -ne 1) {
  throw "The installed Window 02 task is not unique at the root path."
}
$window02 | Select-Object TaskName, State
```

## Verify and extract

Set `$transferRoot` to the new directory containing the three transfer files:

```powershell
$transferRoot = "C:\AI_SCALPER_TRANSFER\phillip-window-02-scheduler"

Get-ChildItem $transferRoot -File |
  Get-FileHash -Algorithm SHA256

Unblock-File -LiteralPath (
  Join-Path $transferRoot "__PACKAGE_NAME__"
)
Unblock-File -LiteralPath (
  Join-Path $transferRoot "__PACKAGE_NAME__.manifest.json"
)
Unblock-File -LiteralPath (
  Join-Path $transferRoot (
    "Expand-PhillipCommodityWindow02SchedulerPackage.ps1"
  )
)

& (Join-Path $transferRoot (
  "Expand-PhillipCommodityWindow02SchedulerPackage.ps1"
))

if (-not $?) {
  throw "Window 02 package extraction failed."
}
```

Expected extraction status:

```text
PHILLIP_COMMODITY_WINDOW_02_SCHEDULER_TRANSFER_VERIFIED
TaskSchedulerMutation : NOT_PERFORMED
OrderCapability       : DISABLED
```

## Verify the remediated operator without task mutation

The exact operator root is:

```powershell
$operatorRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "__OPERATOR_ROOT_NAME__"
)

& "$operatorRoot\Test-PhillipCommodityWindow02TaskHealth.ps1"

if (-not $?) {
  throw "Window 02 V8 operator health verification failed."
}
```

Expected health status:

```text
PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY
InstalledPackageSourceCommit : 6bdd426ba02818bf3e3669a68820c027b3f6f25a
OrderCapability              : DISABLED
TaskSchedulerMutation        : NOT_PERFORMED
```

Do not run `Start-ScheduledTask`. The task XML has
`AllowStartOnDemand=false`; acceptance requires the Task Scheduler automatic
boundary.

## Failure and rollback rules

- If extraction fails, preserve the partial operator root and all three
  transfer files.
- Preserve every V1--V7 worktree, runtime, audit, task-review, receipt, and
  operator directory. V8 reads the exact `r6` installation evidence and never
  repairs or replaces it.
- If source, dependency, contract, snapshot, HMAC, ACL, profile, task XML, or
  receipt verification fails, preserve the output and do not mutate the task.
- V8 has no task-registration or rollback path because it performs no
  Task Scheduler mutation.
- Never delete, rename, enable, or start a historical task to repair Window
  02.
- Never overwrite the worktree, runtime, audit, task-review, operator, or
  transfer directory after a failed attempt.

Escalate with the complete console output, V8 operator-root inventory, task
state, and existing V6 installation receipt path. Secret material must not be
exported.
