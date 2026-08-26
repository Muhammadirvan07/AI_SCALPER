# Phillip Commodity Window 02 Automatic-Run Acceptance

## Purpose

This toolkit records and independently re-verifies the first automatic Window
02 scheduler run. It is observation-only. It cannot start, register, enable,
disable, or modify a scheduled task; it cannot submit a broker order.

The first reviewed boundary is:

- historical local, never reuse: `2026-08-17T06:45:00+09:00` (Tokyo Standard Time)
- UTC: `2026-08-16T21:45:00Z`
- bounded worker duration: `84300` seconds
- expected completion: `2026-08-18T06:10:00+09:00`
- completion capture closes 30 minutes later

Acceptance is evidence of scheduler and read-only shadow-worker operation. It
does not enable live trading or satisfy the later blinded evaluation and
promotion gates.

The toolkit keeps the installed V6 receipt immutable while invoking the
operator-only V9 health remediation from
`C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-scheduler-operator-1194212f`,
derived from the exact scheduler package commit prefix. Both acceptance entry
points receive this value from the package builder; do not substitute an
archive filename suffix or an older operator root.
The V9 operator identity, corrected lock verifier, missed-schedule verifier,
and health-script hashes are
validated independently from the installed V6 scheduler identity.

V9 can classify an earlier missed boundary only when the exact Task Scheduler
Event 153 is verified and the next eligible boundary remains intact. That
classification permits readiness for a future boundary; it can never satisfy
automatic start or completion acceptance.

## Package

Only one transfer file is required:

`phillip-commodity-window-02-automatic-run-acceptance-<commit>.zip`

The ZIP contains the two PowerShell entry points, the isolated Python verifier,
this runbook, and an embedded self-authenticating inventory. Preserve the ZIP
at its transfer location because every operator command rechecks its supplied
SHA-256.

## Extract on Windows

Open an ordinary PowerShell session under the same interactive account used by
the installed task. Replace the two values with the delivered file and hash.

```powershell
$ErrorActionPreference = "Stop"
$zip = "C:\AI_SCALPER_TRANSFER\window02-acceptance\phillip-commodity-window-02-automatic-run-acceptance-<commit>.zip"
$expectedZipSHA256 = "<sha256-from-handoff>"
$operatorRoot = "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-automatic-run-acceptance-<commit>"

if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedZipSHA256) {
  throw "Transfer ZIP SHA-256 mismatch."
}
if (Test-Path -LiteralPath $operatorRoot) {
  throw "Operator root already exists; preserve it and investigate."
}

New-Item -ItemType Directory -Path $operatorRoot | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $operatorRoot
```

Do not copy extra files into the extracted root. Exact inventory validation
will reject them.

## Readiness check

Run this before leaving the watcher active:

```powershell
& "$operatorRoot\Test-PhillipCommodityWindow02AutomaticRunAcceptanceReadiness.ps1" `
  -ToolkitArchive $zip `
  -ExpectedToolkitArchiveSHA256 $expectedZipSHA256 `
  -TargetBoundary "<EXACT_FUTURE_NEXT_RUN_TIME_LOCAL>"
```

The expected status is:

`PHILLIP_COMMODITY_WINDOW_02_AUTOMATIC_RUN_ACCEPTANCE_READY`

Readiness requires the exact installed scheduler/worker/contract identities,
`AllowStartOnDemand=false`, an enabled Task Scheduler Operational log, one
exact Phillip Commodity MT5 process, and the existing health checker to pass.
It performs no scheduler or broker mutation.

After a verified missed boundary, use the next scheduled weekday boundary
(in canonical ISO 8601 form with `+09:00`) as `-TargetBoundary`. Do not reuse
the missed timestamp and do not start the task manually.

If readiness reports `READINESS_RECEIPT_ACL_REJECTED`, stop there and preserve
the output. The installed receipt does not yet have the reviewed ownership and
write boundary. Do not weaken or bypass this check; ACL repair is a separate,
reviewed host-remediation action and is intentionally absent from this toolkit.

## Recommended unattended watcher

Start the watcher before the first boundary and leave that PowerShell process
running through completion:

```powershell
& "$operatorRoot\Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1" `
  -ToolkitArchive $zip `
  -ExpectedToolkitArchiveSHA256 $expectedZipSHA256 `
  -Mode Watch `
  -TargetBoundaryLocal "<EXACT_FUTURE_NEXT_RUN_TIME_LOCAL>" `
  -WatchPollSeconds 30
```

The watcher does not initiate the task. It waits for the scheduled state
transition, accepts start only after the five-minute startup allowance, and
then accepts completion only when the same instance is `Ready` with result
`0` and a correlated event `102`.

The command prints its calculated UTC deadline before polling. An optional
`-WatchTimeoutSeconds` may shorten that deadline; it can never extend the
reviewed completion-capture boundary. A timeout after start preserves and
reports the already verified start ZIP.

It creates two collision-resistant evidence artifacts:

- `phillip-commodity-window-02-automatic-start-20260816T214500Z.zip`
- `phillip-commodity-window-02-automatic-completion-20260816T214500Z.zip`

The completion ZIP embeds the exact start ZIP, so provenance cannot be mixed
between scheduler instances.

## Recovery modes

If the watcher stops after the scheduler has already started, collect the
start phase during the active interval:

```powershell
& "$operatorRoot\Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1" `
  -ToolkitArchive $zip `
  -ExpectedToolkitArchiveSHA256 $expectedZipSHA256 `
  -Mode CollectStart `
  -TargetBoundaryLocal "<EXACT_OBSERVED_BOUNDARY_LOCAL>"
```

If the start ZIP exists and the worker later completed, collect completion:

```powershell
$startZip = "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-automatic-run-acceptance\phillip-commodity-window-02-automatic-start-20260816T214500Z.zip"
$startHash = (Get-FileHash -LiteralPath $startZip -Algorithm SHA256).Hash.ToLowerInvariant()

& "$operatorRoot\Invoke-PhillipCommodityWindow02AutomaticRunAcceptance.ps1" `
  -ToolkitArchive $zip `
  -ExpectedToolkitArchiveSHA256 $expectedZipSHA256 `
  -Mode CollectCompletion `
  -TargetBoundaryLocal "<EXACT_OBSERVED_BOUNDARY_LOCAL>" `
  -StartArchive $startZip `
  -ExpectedStartArchiveSHA256 $startHash
```

Collection deliberately fails if invoked in the wrong scheduler phase. A
`Running` task or a nonzero result can never become completion acceptance.

## Offline re-verification

Start evidence:

```powershell
$startZip = "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-automatic-run-acceptance\phillip-commodity-window-02-automatic-start-20260816T214500Z.zip"
$evidence = $startZip
$evidenceHash = (Get-FileHash -LiteralPath $evidence -Algorithm SHA256).Hash.ToLowerInvariant()
$releasePython = "C:\AI_SCALPER_PRIVATE\phillip-commodity-ecedec9-venv\Scripts\python.exe"
$manifest = Get-Content `
  -LiteralPath "$operatorRoot\PHILLIP_COMMODITY_WINDOW_02_ACCEPTANCE_TOOLKIT.json" `
  -Raw |
  ConvertFrom-Json

& $releasePython -I -S -B `
  "$operatorRoot\phillip_commodity_window_02_automatic_run_acceptance.py" `
  verify-start `
  --archive $evidence `
  --expected-archive-sha256 $evidenceHash `
  --expected-toolkit-source-commit $manifest.source.commit `
  --expected-toolkit-source-tree $manifest.source.tree
```

Completion evidence uses the same Python command with `verify-completion` and
the completion ZIP/hash:

```powershell
$completionZip = "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-automatic-run-acceptance\phillip-commodity-window-02-automatic-completion-20260816T214500Z.zip"
$evidence = $completionZip
$evidenceHash = (Get-FileHash -LiteralPath $evidence -Algorithm SHA256).Hash.ToLowerInvariant()

& $releasePython -I -S -B `
  "$operatorRoot\phillip_commodity_window_02_automatic_run_acceptance.py" `
  verify-completion `
  --archive $evidence `
  --expected-archive-sha256 $evidenceHash `
  --expected-toolkit-source-commit $manifest.source.commit `
  --expected-toolkit-source-tree $manifest.source.tree
```

Offline verification makes no network request and does not require MT5 or
Task Scheduler access.

## Acceptance meaning

A valid start bundle proves all of the following together:

- Task Scheduler event `107` preceded event `100` for one nonzero instance ID;
- no manual event `110` was observed for that start;
- the task was still `Running` after the startup allowance;
- the exact installed receipt, task XML, ACL, contract, health output, runtime
  status, and authenticated audit pair remained mutually consistent.

A valid completion bundle additionally proves:

- the exact accepted start bundle was nested byte-for-byte;
- the task returned to `Ready` with result `0`;
- event `102` completed the same scheduler instance;
- final authenticated runtime evidence was healthy and fresh.

Both results retain `OrderCapability=DISABLED`, `LiveAllowed=false`, and
`TaskSchedulerMutation=NOT_PERFORMED`.
