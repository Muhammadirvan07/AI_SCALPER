# Phillip Commodity Window 02 Recovery

## Status and decision

The 4 August 2026 automatic V6 run is **not acceptance evidence**.  The
limited Task Scheduler principal reproduced this exact verifier failure:

```text
SNAPSHOT:SNAPSHOT_INVALID:PermissionError
```

An Administrator diagnostic passed because the elevated token could read the
frozen snapshot.  The same diagnostic failed under a normal token, proving
that the failure is an ACL defect rather than snapshot-byte corruption.

The V5 contract cannot be resumed after the ACL repair.  Its observation
window started on 26 July 2026, it has zero appended XAUUSD segments, and the
collector accepts only the next bar within its append grace period.  Its first
bar is therefore permanently `APPEND_DEADLINE_MISSED`.  V5 and its V6
scheduler evidence remain immutable failed history.

Safety state throughout this recovery:

- `order_capability=DISABLED`
- `live_allowed=false`
- no broker mutation
- no manual start of the V6 task
- no acceptance claim for the failed V5/V6 run

## 1. Quiesce the stale task and repair snapshot read access

Run from **Administrator PowerShell** after checking out the remediation
commit:

```powershell
cd C:\AI_SCALPER

& .\windows_operator\Suspend-PhillipCommodityV6StaleContract.ps1

if (-not $?) {
  throw "V6 stale-contract quiesce failed."
}
```

The script performs only two Windows mutations:

1. disables `AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow`; and
2. grants its exact principal SID read/execute access to the exact frozen
   snapshot tree.

It hashes the complete snapshot inventory before and after the ACL change,
writes a create-exclusive receipt, refuses to interrupt a running task, and
never starts a scheduled task.

After it succeeds, repeat the frozen contract diagnostic from a
**non-Administrator PowerShell**.  It should report
`FORWARD_CONTRACT_VALID`.  This proves the ACL repair only; it does not make
V5 reusable and must not be followed by `Start-ScheduledTask`.

## 2. Window 02 review boundary

The review-only template is
`config/phillip_commodity_calendar_window_02.review-template.json`:

- calendar version: `phillip-commodity-window-02-v1`
- observation start: `2026-08-16T16:00:00Z` (17 August 01:00 JST)
- first regular XAUUSD open: 17 August 07:00 JST
- blind-until: `2026-10-12T15:00:00Z`
- validation profile: `DIAGNOSTIC`

The gap before the first session provides time for fresh regulatory and
calendar evidence, human signatures, a committed configuration after-image,
an immutable contract, and a least-privilege scheduler installation.

The template is intentionally not active and contains no embedded approval.
The active profile remains bound to V5 until all Window 02 artifacts have
been produced and reviewed.

## 3. Prepare the Window 02 calendar review on Windows

Reuse captured source bytes only if their manifest observation time remains
within the 30-day review age and the reviewer confirms that the bytes still
support the Window 02 schedule.  Write every output into a new directory.

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

$template = (
  "C:\AI_SCALPER\config\" +
  "phillip_commodity_calendar_window_02.review-template.json"
)
$sourceRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-calendar-review"
)
$reviewRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-calendar-review"
)

if (Test-Path $reviewRoot) {
  throw "Window 02 calendar review root already exists; preserve it."
}
New-Item -ItemType Directory -Path $reviewRoot | Out-Null

python -B .\prepare_prewindow_calendar_review.py `
  --candidate phillip-commodity `
  --template $template `
  --source-manifest "$sourceRoot\source-manifest.json" `
  --source-root $sourceRoot `
  --output "$reviewRoot\calendar-evidence.json"

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 calendar evidence preparation failed."
}

$reviewerId = Read-Host "Enter the actual calendar reviewer ID"
if (
  [string]::IsNullOrWhiteSpace($reviewerId) -or
  $reviewerId -match "^(?i:approve|confirm|reject|cancel)(?:$|[._-])"
) {
  throw "Reviewer ID must identify the human reviewer, not a control token."
}
$confirmation = Read-Host (
  "Type APPROVE-PHILLIP-COMMODITY-WINDOW-02-CALENDAR"
)
if ($confirmation -cne "APPROVE-PHILLIP-COMMODITY-WINDOW-02-CALENDAR") {
  throw "Calendar approval cancelled."
}

python -B .\sign_prewindow_calendar_review.py `
  --candidate phillip-commodity `
  --reviewer-id $reviewerId `
  --evidence "$reviewRoot\calendar-evidence.json" `
  --output "$reviewRoot\calendar-approval.json"

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 calendar approval failed."
}

python -B .\assemble_prewindow_calendar_review.py `
  --candidate phillip-commodity `
  --template $template `
  --evidence "$reviewRoot\calendar-evidence.json" `
  --approval "$reviewRoot\calendar-approval.json" `
  --output "$reviewRoot\prewindow-calendar-review.json"

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 calendar review assembly failed."
}

python -B .\assemble_signed_broker_calendar_template.py `
  --candidate phillip-commodity `
  --template $template `
  --calendar-review "$reviewRoot\prewindow-calendar-review.json" `
  --output "$reviewRoot\phillip_commodity_calendar_window_02.template.json"

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 signed template assembly failed."
}

Get-FileHash "$reviewRoot\*.json" -Algorithm SHA256
```

## 4. Reviewed external artifact state on 4 August 2026

The first Window 02 calendar approval used the confirmation token as its
reviewer ID. It is rejected history and must not be copied, renamed, or used as
authority. The corrected R2 calendar review has:

- reviewer `muhammad-irvan`;
- calendar version `phillip-commodity-window-02-v1`;
- review artifact SHA-256
  `0cf22f0cb386e8336248ba288137a21de8b4fcb35b750b8e77fcd46274e71822`;
- observation start `2026-08-16T16:00:00Z`;
- `live_allowed=false` and `order_capability=DISABLED`.

The corrected R2 regulatory review has:

- Compliance reviewer `muhammad-irvan`;
- Legal reviewer `maulana-putra`;
- evidence bundle SHA-256
  `b9bed0b48b175a2fb7eefebfd50700e94f782515afbb6dd4890cbc389a3b39f3`;
- calendar template SHA-256
  `147425d9d336f80735344324f6c2ba5e8c751cb4646d2a4d2b426890b778285c`;
- regulatory observation SHA-256
  `de0a570c463155e302c422e6029faa9903076927d43dcefc0b1eaa1c7fa50e9f`;
- `live_allowed=false` and `order_capability=DISABLED`.

The R2 files are authoritative only when the complete signature and lane
verification succeeds. A matching displayed hash alone is not approval.

## 5. Build the non-mutating rollover review pack

After checking out the release commit containing the Window 02 rollover
tooling, use a normal PowerShell session. This command discovers the corrected
R2 files by their reviewed identities so the earlier rejected artifacts cannot
be selected accidentally.

```powershell
cd C:\AI_SCALPER
.\.venv\Scripts\Activate.ps1

$discovery = (
  "C:\AI_SCALPER\runtime_state\broker_discovery\" +
  "phillip-commodity-window-01-v3.json"
)
$calendarRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-calendar-review"
)
$regulatoryRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-regulatory-review"
)
$outputRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-window-02-rollover-review"
)
$output = Join-Path $outputRoot "window-02-rollover-review-v1.json"

if (git status --porcelain) {
  git status --short
  throw "Git worktree must be clean before rollover review."
}

if (-not (Test-Path $discovery -PathType Leaf)) {
  throw "Exact discovery-v3 receipt is missing."
}

$regulatory = @(
  Get-ChildItem $regulatoryRoot -File -Filter "*.json" |
    Where-Object {
      (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -eq
      "de0a570c463155e302c422e6029faa9903076927d43dcefc0b1eaa1c7fa50e9f"
    }
)
if ($regulatory.Count -ne 1) {
  throw "Corrected R2 regulatory observation is not unique."
}

$calendar = @(
  Get-ChildItem $calendarRoot -File -Filter "*.json" |
    Where-Object {
      try {
        $payload = Get-Content $_.FullName -Raw | ConvertFrom-Json
        (
          $payload.schema_version -eq "prewindow-calendar-review-v1" -and
          $payload.review_artifact_sha256 -eq
          "0cf22f0cb386e8336248ba288137a21de8b4fcb35b750b8e77fcd46274e71822"
        )
      }
      catch {
        $false
      }
    }
)
if ($calendar.Count -ne 1) {
  throw "Corrected R2 calendar review is not unique."
}

if (Test-Path $outputRoot) {
  throw "Rollover review root already exists; preserve existing evidence."
}
New-Item -ItemType Directory -Path $outputRoot | Out-Null

python -B .\prepare_phillip_commodity_window_02_rollover_review.py `
  --candidate phillip-commodity `
  --discovery $discovery `
  --regulatory-observation $($regulatory[0].FullName) `
  --calendar-review $($calendar[0].FullName) `
  --output $output

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 rollover review preparation failed."
}

python -B .\verify_phillip_commodity_window_02_rollover_review.py `
  --input $output

if ($LASTEXITCODE -ne 0) {
  throw "Window 02 rollover review static verification failed."
}

Get-FileHash $output -Algorithm SHA256
```

Successful output must report all of the following:

- `Manual rollover required: true`;
- `Configuration mutated: false`;
- `Registration enabled: true` (the existing Window 01 state is preserved);
- `Contract registration: NOT_PERFORMED`;
- `Scheduler mutation: NOT_PERFORMED`;
- `Broker mutation: NOT_PERFORMED`;
- `Order capability: DISABLED`.

The pack proposes exactly three replacements and one creation: the candidate
config, profile config, Windows release allowlist, and new signed Window 02
template. The allowlist delta adds only the new signed template so a future
release cannot omit its active calendar. The pack does not apply any of them.

## 6. Remaining gates after the review pack

Before active configuration can roll over, Window 02 still requires:

1. project-owner review of the exact pack and explicit approval to apply its
   four after-images;
2. a clean Git commit and tree containing only those reviewed after-images;
3. a newly registered immutable
   `phillip-commodity-window-02-diagnostic-v1` contract;
4. a new frozen read-only worker/task whose principal has read access to both
   the contract and snapshot before the first automatic boundary;
5. automatic-run and post-window acceptance evidence.

Do not apply the pack, register the replacement contract, or install the
replacement scheduler without the next explicit approval. The old V6 task
must remain disabled.

## 7. Verified external state after approved apply

On 5 August 2026, the operator reported a successful reviewed apply and exact
Window 02 contract registration. The immutable Windows result is:

- contract `phillip-commodity-window-02-diagnostic-v1`;
- snapshot `phillip-commodity-dev-pre-window-02-v1`;
- registered at `2026-08-05T07:16:19.157743Z`;
- observation start `2026-08-16T16:00:00Z`;
- blind boundary `2026-10-12T15:00:00Z`;
- contract payload SHA-256
  `cbfd753b0aed2d66af56446adc734ce8d62666e309e91bf74d24b4cc56b613a2`;
- physical `contract.json` SHA-256
  `ad4fd8853563976483fbffbd3bd97847f7e05c8a4194afd10fa95832e2fe485b`;
- build identity SHA-256
  `9d64b8c9be0b42bdc991b767a745258774a57f80613e2fd322791d6d18cc6287`;
- signing-key ID `105e393cd619804e`;
- exactly eight initial contract artifacts; and
- historical V6 task state `Disabled`.

This supersedes the pending apply/registration items in section 6. The next
gate is the separate Window 02 scheduler package described in
`PHILLIP_COMMODITY_WINDOW_02_SCHEDULER.md`. It creates a new task named
`AI_SCALPER-PhillipCommodityWindow02-ReadOnlyShadow`; it must not start or
modify the historical V6 task. Automatic-run and post-window acceptance
remain pending, and order capability remains `DISABLED`.

## 8. Scheduler transfer V1 diagnostic and V2 remediation

Windows verified the complete `WINDOW02.V1` transfer, package source
`ad180d960d8848cb176616bbd44e8c673352eb2c`, frozen worker, contract payload,
and all six operator members. Task Scheduler and broker mutation were not
performed during extraction.

Installation then stopped while creating the frozen worktree because Git's
normal `Preparing worktree (detached HEAD da31900)` progress was written to
native `stderr`. Windows PowerShell 5.1 promoted that informational stream to
`NativeCommandError` under the installer's fail-fast preference. The Git
operation may have left a valid but unlocked partial V1 worktree; it remains
for forensic review.

The V2 remediation evaluates Git success by captured native exit code while
temporarily preventing benign native `stderr` from terminating the wrapper.
It uses fresh create-exclusive `-r2` worktree, runtime, audit, and task-review
paths. It does not delete or overwrite V1 output, register or start a task
during transfer, contact the broker, or enable order capability.

## 9. Scheduler transfer V2 diagnostic and V3 remediation

Windows verified `WINDOW02.V2` and successfully passed the Git worktree stage.
The installer then stopped before task registration with
`authoritative contract projection mismatch`. Source inspection at the exact
frozen worker commit confirmed that the verifier fixture expected three
CLI-only fields absent from the library return mapping.

V3 binds the exact raw `verify_forward_evidence()` key set from the frozen
worker and validates only fields actually authenticated by that API. The
disabled order/live projection remains hardcoded after successful contract
authentication. Its create-exclusive worktree, runtime, audit, and review
paths end in `-r3`; V1/V2 paths remain untouched.

## 10. Scheduler transfer V3 diagnostic and V4 remediation

Windows verified `WINDOW02.V3`, and its corrected projection verifier reached
the physical contract inventory check. It stopped before task registration
because V2's successful call into the frozen `verify_forward_evidence()` API
had created the API's intentional persistent `.contract-write.lock`. The V3
verifier still required the pristine eight-file registration inventory and
therefore misclassified that authenticated operational lock as drift.

V4 adds the exact one-byte NUL lock artifact and its SHA-256 to the expected
operational inventory while keeping the eight registered genesis artifacts
individually byte-bound. Inventory failures now report explicit missing and
unexpected relative paths. V4 uses fresh create-exclusive `-r4` paths; all
V1--V3 outputs remain untouched.
