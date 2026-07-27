# Phillip Commodity V6 Scheduler-Only Remediation

Status: **PREPARED / READ-ONLY / ORDER CAPABILITY DISABLED**

Transport revision V6.2 retains the corrected Windows PowerShell 5.1
extraction boundary from V6.1 and moves only the immutable first scheduler
boundary. V6.1 was not copied and installed before its reviewed start, so its
late-install guard correctly made that package unusable. V6.2 starts on
`2026-07-30T06:45:00+09:00`; installation must finish before
`2026-07-30T06:30:00+09:00`.

The original V6 ZIP used a Windows PowerShell 5.1-incompatible top-level
JSON-array pipeline and observed the six extracted files as an expected
inventory count of one. Preserve any V6 or V6.1 transfer/operator path that
is present for forensic review. A path that was never created is explicitly
`PRESERVE_IF_PRESENT` and its absence does not block V6.2. V6.2 uses a new
commit-specific operator root.

V5 proof is valid. V5 task installation failed only because
`Export-ScheduledTask` omitted the schema-default
`StartWhenAvailable=false` node and the StrictMode validator read that
optional XML child dynamically. The V5 catch handler disabled the task before
its scheduled run.

Install V6.2 only while at least 900 seconds remain before the first boundary.
The installer enforces that lead before registration and again before
enablement; a late installation remains blocked and disabled.

V6 changes only the scheduler boundary. It retains:

- frozen worker commit `290cc23d9d87f93e914612afdfecfc481d2c232f`;
- frozen worker tree `ef568ae39aa4c51d9afe738badbb86d2c45e9a58`;
- contract `phillip-commodity-window-01-diagnostic-v5`;
- the existing V5 journal and HMAC audit chain; and
- proof receipt SHA-256
  `29e14f81bbd87d460f171484d59a40e9bdd6ae00611c3453ade4aa6c846b3aec`.

V4 and V5 tasks and evidence must remain present and disabled. V6 does not
delete, overwrite, or enable either prior task. It does not register a new
forward contract, manually start a task, initialize an order API, or mutate
the broker.

## Transfer files

Copy these three files into one new Windows directory:

1. `__PACKAGE_NAME__`
2. `__PACKAGE_NAME__.manifest.json`
3. `Expand-PhillipCommodityV6SchedulerPackage.ps1`

Do not place them in the existing V5 operator directory.
Do not delete, rename, or reuse either failed V6 location:

- `C:\AI_SCALPER_TRANSFER\phillip-v6-scheduler`
- `C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-scheduler-operator`

Also preserve these V6.1 locations if they exist; do not create them merely
to satisfy the check:

- `C:\AI_SCALPER_TRANSFER\phillip-v6r1-scheduler`
- `C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-scheduler-operator-3ebb8576`

## Source and package verification

Run PowerShell from `C:\AI_SCALPER`:

```powershell
$repo = "C:\AI_SCALPER"
$branch = "agent/live-grade-phase3"
$expectedCommit = "__REMEDIATION_COMMIT__"
$expectedTree = "__REMEDIATION_TREE__"
$transferRoot = "C:\AI_SCALPER_TRANSFER\phillip-v6r2-scheduler"

Set-Location $repo
git fetch --no-tags origin $branch

if ($LASTEXITCODE -ne 0) {
  throw "Fetch V6 remediation source failed."
}

$commit = (git rev-parse "$expectedCommit^{commit}").Trim()
$tree = (git rev-parse "$expectedCommit^{tree}").Trim()

if ($commit -ne $expectedCommit -or $tree -ne $expectedTree) {
  throw "V6 remediation source identity mismatch."
}

git merge-base --is-ancestor $expectedCommit "origin/$branch"

if ($LASTEXITCODE -ne 0) {
  throw "V6 remediation source is not on the official branch."
}

Get-ChildItem -LiteralPath $transferRoot -File | Unblock-File
& "$transferRoot\Expand-PhillipCommodityV6SchedulerPackage.ps1"

if (-not $?) {
  throw "V6 scheduler package extraction failed."
}
```

The extractor verifies archive filename, archive SHA-256, source identity,
member inventory, every member size/hash, safety flags, exact V5 proof hash,
and the frozen worker identity before creating the fresh, commit-bound root
`C:\AI_SCALPER_PRIVATE\__OPERATOR_ROOT_NAME__`.

## Install and health check

```powershell
$operatorRoot = (
  "C:\AI_SCALPER_PRIVATE\" +
  "__OPERATOR_ROOT_NAME__"
)

& "$operatorRoot\Install-PhillipCommodityV6ReadOnlyTask.ps1"

if (-not $?) {
  throw "V6 task installation failed."
}

& "$operatorRoot\Test-PhillipCommodityV6TaskHealth.ps1"

if (-not $?) {
  throw "V6 task health check failed."
}
```

The installer performs the mandatory full historical archive audit before it
creates the genesis checkpoint. Later health checks use the bounded online
mode. To explicitly re-read and re-authenticate every historical audit pair,
run the same health command with `-FullArchiveAudit`; it performs that full
gate first and then performs the normal checkpoint/journal health pass.
The explicit full scan is accepted only while the task is `Ready`, outside an
active worker interval, and at least 3600 seconds before the next scheduled
start. Use a pre-start or long weekend gap; the gate rejects a scan while the
worker could still append evidence.

Expected installation status:

```text
PHILLIP_COMMODITY_V6_TASK_INSTALLED_VERIFIED
State: Ready
NextRunTime: 2026-07-30 06:45:00
OrderCapability: DISABLED
LiveAllowed: False
StartScheduledTask: NOT_PERFORMED
BrokerMutation: NOT_PERFORMED
```

Expected health status before the first scheduled start:

```text
PHILLIP_COMMODITY_V6_TASK_HEALTHY
TaskState: Ready
SchedulePhase: PRE_START
EvidenceCheckpointMutation: NOT_PERFORMED
HistoricalArchiveAudit: NOT_REQUESTED
OrderCapability: DISABLED
LiveAllowed: False
TaskSchedulerMutation: NOT_PERFORMED
BrokerMutation: NOT_PERFORMED
```

Do not run `Start-ScheduledTask`. The first start is the reviewed calendar
boundary `2026-07-30T06:45:00+09:00`.

## Validator behavior

The package binds one shared validator into both installer and health check.
It accepts omitted XML only when the official Task Scheduler XSD default
equals the reviewed value and the effective CIM value independently agrees.
The installer registers V6 disabled, validates the disabled export, enables
it only after that gate passes, then validates the final enabled export and
the exact first `NextRunTime`. Any later failure unconditionally attempts to
disable and stop V6, then requires an effective `Disabled` state; a disable or
state-query failure is reported as `V6_FAIL_CLOSED_DISABLE_FAILED`.
Before installation and on every health check, the package also uses the
Windows evidence key to re-run authoritative forward-contract and HMAC audit
verification and binds the contract payload/build identities, runtime key,
signing-key ID, and every proof child hash to the exact V5 proof receipt. The
initial install performs a full chain walk. It then writes a create-exclusive,
HMAC-signed genesis checkpoint. Health checks authenticate that append-only
checkpoint chain and verify only the exact new suffix, including predecessor
sequence, event hash, and signed-head HMAC continuity. The committed audit head
must also equal the read-only, HMAC-authenticated live SQLite journal head
(event count, event hash, signed-head HMAC, status HMAC, and heartbeat), so
deleting a checkpoint and its audit suffix cannot roll health back to an older
valid prefix. A named cross-process mutex serializes verify, task validation,
and checkpoint commit. Each checkpoint is flushed under a non-chain temporary
name and then atomically moved to its create-exclusive final name; a power loss
can leave only an ignored temporary file, never a partial final checkpoint. An
existing final checkpoint is idempotent only when its bytes are exactly
identical. This prevents an eight-week soak
from rescanning the complete audit payload history each time or forking the
checkpoint chain under concurrent health checks.
The manifest is the publication commit marker, so a just-written audit that
does not yet have its manifest is ignored until the next check. A bounded
10-second snapshot retry covers the normal journal-ahead publication interval;
after that, mismatch fails closed. A committed manifest with missing or invalid
audit bytes is rejected.

Default online health does not re-read archive bytes already authenticated by
a signed checkpoint. Historical storage-byte integrity is a separate explicit
gate: installation and `-FullArchiveAudit` re-read and authenticate every
committed pair. The explicit switch additionally requires a `Ready` task, no
active worker interval, and at least 3600 seconds before the next trigger.
This distinction is reported in `HistoricalArchiveAudit`.

Active-window freshness is derived only from the HMAC-verified
`runtime_status.heartbeat_at_utc`, with monotonic source-event and heartbeat
checks, a 60-second future-clock-skew ceiling, and a 180-second stale ceiling.
File mtimes and the SQLite main-file timestamp are not trusted (the journal
uses WAL and those timestamps are not authenticated).
Schedule phase is sampled after evidence verification as `PRE_START`,
`ACTIVE`, `GAP`, or `EXPIRED`. The five-minute startup allowance permits
`Ready` or the scheduler's transient `Queued` state only before the current
boundary has actually attempted a run; an immediate exit, including a nonzero
exit, is rejected. The final Monday worker
may remain active past the trigger end boundary, but no impossible Tuesday
start is inferred after expiry.
It rejects:

- wrong or unreadable effective settings;
- missing non-default settings;
- duplicate or invalid XML values;
- elevated run level;
- extra actions or triggers;
- changed command, arguments, working directory, schedule, SID, or source;
- any V4/V5 task that is no longer disabled; and
- a late install, wrong first `NextRunTime`, stale/future/non-monotonic signed
  heartbeat, or fail-closed rollback that cannot prove `Disabled`; and
- any V5 proof, contract, authenticated live-journal head, signed-checkpoint,
  predecessor-chain, or frozen-runtime identity drift; and
- any historical audit-byte drift when the installation or explicit full
  archive audit gate runs.

Any installer failure disables only the new V6 task and preserves all
evidence for review.
