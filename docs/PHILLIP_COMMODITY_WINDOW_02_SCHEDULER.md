# Phillip Commodity Window 02 Scheduler

This package installs a new least-privilege, read-only Scheduled Task for the
registered Window 02 diagnostic contract. It does not reuse, enable, rename,
start, or delete the historical V6 task.

This is transport revision `WINDOW02.V6`. Windows verified the V5 transfer,
but its installer stopped on the first Git inspection because assigning to the
automatic `$LASTEXITCODE` variable inside a function created a local Windows
PowerShell 5.1 scope shadow. Preserve all earlier operator and worktree
directories. V6 uses new runtime, audit, and task-review paths ending in `-r6`.

V6 retains V5's exact two-phase contract proof: it accepts either legitimate
contract state at entry, the eight-file
registration genesis or the nine-file operational inventory containing the
authenticated one-byte `.contract-write.lock`. It then runs the frozen
authoritative verifier and requires the exact nine-file operational inventory
afterward. All native Git and Python calls capture stderr safely and read the
native exit code immediately without assigning to the automatic variable.

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

## Pre-install checks

Run in a normal, non-Administrator PowerShell session under the same Windows
account that owns the Phillip evidence key:

```powershell
$repo = "C:\AI_SCALPER"
$branch = "agent/live-grade-phase3"
$packageCommit = "__PACKAGE_SOURCE_COMMIT__"
$packageTree = "__PACKAGE_SOURCE_TREE__"
$workerCommit = "da3190013d86426533019d6927a58181c624b1f8"
$workerTree = "9e84a0d7c9a5b3d4213c6abf0fdf1c8770361d10"

Set-Location $repo

if (git status --porcelain) {
  git status --short
  throw "Repository must be clean before Window 02 installation."
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

## Install without manual start

The exact operator root is:

```powershell
$operatorRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "__OPERATOR_ROOT_NAME__"
)

& "$operatorRoot\Install-PhillipCommodityWindow02ReadOnlyTask.ps1"

if (-not $?) {
  throw "Window 02 task installation failed."
}

& "$operatorRoot\Test-PhillipCommodityWindow02TaskHealth.ps1"

if (-not $?) {
  throw "Window 02 pre-start health verification failed."
}
```

Expected installation and pre-start health statuses:

```text
PHILLIP_COMMODITY_WINDOW_02_TASK_INSTALLED_VERIFIED
PHILLIP_COMMODITY_WINDOW_02_TASK_HEALTHY
TaskState       : Ready
SchedulePhase   : PRE_START
NextRunTime     : 8/17/2026 6:45:00 AM
OrderCapability : DISABLED
```

Do not run `Start-ScheduledTask`. The task XML has
`AllowStartOnDemand=false`; acceptance requires the Task Scheduler automatic
boundary.

## Failure and rollback rules

- If extraction fails, preserve the partial operator root and all three
  transfer files.
- Preserve the V1, V2, V3, and any V4/V5 worktrees. Their paths end in
  `shadow-source`, `shadow-source-r2`, `shadow-source-r3`, and
  `shadow-source-r4`/`shadow-source-r5`. The V6 installer uses the separate
  `shadow-source-r6` path and never repairs or removes an earlier worktree in
  place.
- If source, dependency, contract, snapshot, HMAC, ACL, or profile
  verification fails, do not register a task manually.
- If failure occurs after task registration, the installer attempts a
  fail-closed disable. Confirm the new task is `Disabled` and preserve the
  task-review directory.
- Never delete, rename, enable, or start a historical task to repair Window
  02.
- Never overwrite the worktree, runtime, audit, task-review, operator, or
  transfer directory after a failed attempt.

Escalate with the complete console output, operator-root inventory, task
state, and installation receipt path. Secret material must not be exported.
