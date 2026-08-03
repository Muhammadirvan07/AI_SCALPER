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

## 4. Remaining external artifacts

Before active configuration can roll over, Window 02 still requires:

1. fresh regulatory evidence bound to the unsigned Window 02 template;
2. distinct Compliance and Legal approvals for that evidence;
3. an assembled regulatory observation;
4. review of the exact candidate/profile/template after-images;
5. a clean Git commit and tree containing those after-images;
6. a newly registered immutable contract such as
   `phillip-commodity-window-02-diagnostic-v1`;
7. a new frozen read-only worker/task whose principal has read access to both
   the contract and snapshot before the first automatic boundary.

Do not enable or install the replacement scheduler until all seven items are
complete.  The old V6 task must remain disabled.
