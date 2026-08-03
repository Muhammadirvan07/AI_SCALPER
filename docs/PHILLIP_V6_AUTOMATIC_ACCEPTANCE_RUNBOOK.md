# Phillip V6 Automatic Acceptance Runbook

Status repository saat ini:

```text
AUTOMATIC_ACCEPTANCE: BLOCKED_EXTERNAL_SCHEDULED_RUN
LIVE_TRADING: DO_NOT_SHIP
ORDER_CAPABILITY: DISABLED
```

Runbook ini hanya untuk lane read-only
`phillip-commodity-window-01-diagnostic-v5`. Ia tidak memberikan authority
order, tidak memulai task, dan tidak dapat mengganti bukti automatic scheduler
dengan manual invocation.

## Snapshot operasional yang belum menjadi evidence repository

Output Windows yang dilaporkan operator pada 3 Agustus 2026 menunjukkan task
`Ready`, `LastRunTime=2026-08-03T11:14:39+09:00`, result
`2147946720/0x800710E0`, Operational log aktif, dan
`NextRunTime=2026-08-04T06:45:00+09:00`. Installed task melaporkan
`AllowStartOnDemand=false`, `StartWhenAvailable=false`,
`MultipleInstances=IgnoreNew`, dan principal interaktif. Query pukul
06:35--07:05 tidak menemukan event Task Scheduler. Karena last-run tidak
sejajar dengan boundary 06:45 dan event provenance tidak ada, snapshot ini
tidak membuktikan automatic run maupun manual invocation. Kombinasi
non-boundary `0x800710E0` dan demand-start disabled hanya boleh dilabeli
request refused yang memerlukan event review.

Artifact acceptance dari run otomatis yang selesai belum disalin ke repository
ini, sehingga informasi tersebut tetap **operator-reported** dan tidak menutup
gate. Tanggal 30 Juli, 31 Juli, dan 3 Agustus tetap historical schedule.
Percobaan berikutnya hanya boleh disebut `2026-08-04T06:45:00+09:00` jika
`Get-ScheduledTaskInfo` pada host yang sama masih melaporkan nilai itu segera
sebelum boundary.

## Identitas dan prasyarat

- timezone Windows exact `Tokyo Standard Time`;
- task exact-root `\AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow`;
- task V4 dan V5 exact-root tetap `Disabled`;
- Task Scheduler Operational log sudah `Enabled` sebelum boundary;
- source worker tetap commit `290cc23d9d87f93e914612afdfecfc481d2c232f`
  dan tree `ef568ae39aa4c51d9afe738badbb86d2c45e9a58`;
- contract tetap `phillip-commodity-window-01-diagnostic-v5`;
- receipt ACL inheritance disabled dan writer hanya SID installer,
  `S-1-5-18`, serta `S-1-5-32-544`;
- central safety tetap `live_allowed=false`, `max_lot=0.01`, dan
  `order_capability=DISABLED`;
- toolkit post-run harus dibangun ulang dari source commit/tree yang memuat
  bundle schema v3. Toolkit lama yang menerima state `Running` tidak boleh
  digunakan sebagai final acceptance.

## Readiness sebelum boundary

Jalankan sebagai inspeksi read-only. Jangan menjalankan
`Start-ScheduledTask`.

```powershell
$taskName = "AI_SCALPER-PhillipCommodityV6-ReadOnlyShadow"
$task = @(
  Get-ScheduledTask -TaskName $taskName |
    Where-Object { $_.TaskPath -eq "\" }
)
if ($task.Count -ne 1) { throw "Task V6 tidak exact satu di root." }

$info = Get-ScheduledTaskInfo -InputObject $task[0]
$log = Get-WinEvent `
  -ListLog "Microsoft-Windows-TaskScheduler/Operational"

[PSCustomObject]@{
  TimeZone       = (Get-TimeZone).Id
  TaskState      = $task[0].State
  LastRunTime    = $info.LastRunTime
  LastTaskResult = $info.LastTaskResult
  NextRunTime    = $info.NextRunTime
  OperationalLog = $log.IsEnabled
} | Format-List
```

PASS readiness memerlukan timezone benar, task unik, log aktif, task tidak
disabled, dan `NextRunTime` masih cocok dengan boundary yang hendak diamati.
Readiness bukan acceptance.

Toolkit build berikutnya juga memproyeksikan guard dan diagnosis read-only:
`AllowStartOnDemand`, `StartWhenAvailable`, `MultipleInstances`, result hex,
latest expected boundary, boundary alignment, serta last-run classification.
Classifier tidak membaca event provenance dan selalu menghasilkan
`AcceptanceReady=False`; final acceptance tetap hanya dimiliki verifier
post-run.

## Biarkan run otomatis selesai

Worker berdurasi maksimum 84.300 detik. State `Running` dan result in-progress
tidak boleh dipromosikan menjadi PASS. Tunggu sampai task kembali `Ready`.
Jangan reinstall task, menghapus lock, mengubah trigger, atau melakukan manual
start selama window.

## Evidence yang wajib tersedia

1. installation receipt dan hash;
2. ACL attestation receipt dengan DACL protected dan tanpa unauthorized writer;
3. exact installed task XML dan hash;
4. advanced signed checkpoint yang bukan checkpoint instalasi;
5. audit export dan manifest dengan invocation ID yang sama;
6. heartbeat autentik maksimal lima menit sebelum observasi;
7. Task Scheduler raw XML event 107, 100, dan 102 dengan `InstanceId` sama;
8. tidak ada event 110 untuk instance/window tersebut;
9. `LastTaskResult=0`, process exit code `0`, dan state `Ready`;
10. audit safety `max_lot=0.01`, `order_capability=DISABLED`,
    `live_allowed=false`, dan broker order count `0`.

Seluruh timestamp harus menyertakan `Z` atau offset `+09:00` yang eksplisit.

## Collection dan independent verification

Gunakan exact toolkit ZIP, SHA-256, source commit, dan source tree dari build
baru. Ikuti ekstraksi di
`PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE.md`, lalu jalankan:

```powershell
& "$toolkitRoot\Invoke-PhillipCommodityV6PostRunAcceptance.ps1" `
  -ToolkitArchive $archive `
  -ExpectedToolkitArchiveSHA256 $expectedArchiveSHA256 `
  -Output $output
if (-not $?) { throw "Automatic post-run acceptance gagal." }

$outputSHA256 = (
  Get-FileHash -LiteralPath $output -Algorithm SHA256
).Hash.ToLowerInvariant()

& $releasePython -I -S -B `
  "$toolkitRoot\phillip_commodity_v6_postrun_acceptance.py" `
  verify `
  --archive $output `
  --expected-archive-sha256 $outputSHA256 `
  --expected-toolkit-source-commit $expectedCommit `
  --expected-toolkit-source-tree $expectedTree
if ($LASTEXITCODE -ne 0) { throw "Independent verification gagal." }
```

## PASS dan FAIL

PASS hanya jika output memuat semuanya:

```text
Status                 = PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_READY
TaskState              = Ready
LastTaskResult         = 0
ProcessExitCode        = 0
ReceiptAclValidated    = True
BrokerOrderCount       = 0
OffhostCustodyPerformed = False
OrderCapability        = DISABLED
LiveAllowed            = False
```

FAIL bila ada event 110, event 102 hilang/duplikat, timestamp di luar boundary,
heartbeat stale, checkpoint tidak maju, receipt/hash/ACL drift, task masih
`Running`, result nonzero, unauthorized writer, safety drift, atau archive
tidak lolos independent verification.

## Manual run dan stale receipt

- Event 110 berarti manual invocation dan selalu menggagalkan final acceptance.
- Event 107 harus mendahului event 100; event 102 harus mengikuti event 100.
- Ketiga event harus memakai satu `InstanceId` unik.
- Last run, heartbeat, checkpoint, audit invocation, dan receipt harus berada
  pada chain yang sama. Checkpoint/event counts wajib lebih tinggi daripada
  installation baseline.
- Receipt atau checkpoint dari run sebelumnya tidak boleh disalin atau diberi
  nama baru. Reuse akan gagal karena time, count, invocation, dan hash binding.
- Preflight manual harus dilabeli `MANUAL_PREFLIGHT` dan tidak menghasilkan
  klaim automatic acceptance.

## Containment

Jika verifier gagal, pertahankan seluruh artifact untuk forensic review,
jangan overwrite output, jangan menjalankan task manual, dan jangan mengubah
safety policy. Bila ada indikasi ACL/safety drift, disable lane melalui
prosedur operator yang telah direview; jangan menghapus task atau evidence.

Hingga ZIP acceptance otomatis aktual lolos verifikasi dan custody eksternal
selesai, keputusan tetap:

```text
AUTOMATIC_ACCEPTANCE: BLOCKED_EXTERNAL_SCHEDULED_RUN
LIVE_TRADING: DO_NOT_SHIP
ORDER_CAPABILITY: DISABLED
```
