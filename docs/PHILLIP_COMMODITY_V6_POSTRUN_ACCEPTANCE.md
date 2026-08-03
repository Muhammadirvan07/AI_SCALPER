# Phillip Commodity V6 Post-Run Acceptance

Status: **READ-ONLY / POST-SCHEDULED-RUN ONLY / ORDER DISABLED**

Kontrak baru memakai
`specs/phillip_commodity_v6_postrun_acceptance_v3.md`. Status operasional dan
urutan boundary terbaru ada di
`docs/PHILLIP_V6_AUTOMATIC_ACCEPTANCE_RUNBOOK.md`.

Toolkit ini menutup handoff setelah pemicu otomatis V6.3. Ia menjalankan exact
health checker yang sudah terpasang, memverifikasi task dan signed checkpoint,
family ACL installation receipt yang tertutup, lalu mengikat checkpoint
terbaru, exact audit pair, installation receipt, installed task XML, ACL
attestation, health transcript, dan raw XML Task Scheduler Operational
event ke satu ZIP create-exclusive. Event 107 dan 100 harus berkorelasi pada
`InstanceId` yang sama; event 110 pada instance atau launch window yang sama
membatalkan acceptance. Toolkit yang sama juga membuat custody-request ZIP
deterministik dan memverifikasi receipt RSA dari kustodian WORM independen.

Toolkit ini tidak:

- menjalankan `Start-ScheduledTask`;
- mendaftarkan, mengaktifkan, menonaktifkan, atau menghapus task;
- mengakses credential secara langsung;
- mengimpor MetaTrader5 atau membawa primitive order;
- menyalin bukti ke storage off-host;
- menyimpan private key kustodian;
- menganggap receipt tanpa tanda tangan sebagai bukti;
- menganggap event log lokal sebagai attestation independen;
- mengklaim inspeksi langsung API storage;
- membuka demo-auto, promotion, atau live trading.

Semua output bersifat create-exclusive dengan pemeriksaan no-follow. File,
folder, symlink valid, maupun dangling symlink yang sudah ada akan ditolak dan
tidak dihapus. Gunakan nama output baru; jangan membersihkan path evidence
secara otomatis setelah collision.

Seluruh JSON toolkit/evidence dibaca dengan duplicate-key rejection sebelum
proyeksi. Setiap input regular dibaca melalui satu handle yang identitas,
ukuran, dan modification time-nya harus tetap sama dengan inspeksi path
no-follow. Bila verifikasi setelah publikasi gagal, cleanup hanya boleh
menghapus inode/file-index output yang dibuat invocation itu sendiri; file
pengganti dari proses lain dipertahankan dan proses gagal tertutup.

## Kapan dijalankan

Jangan jalankan sebelum boundary otomatis
`2026-07-30T06:45:00+09:00`. Manual start bukan pengganti bukti scheduler.
Jalankan final acceptance hanya setelah run terjadwal selesai sehat, task
kembali `Ready`, event completion 102 tersedia, dan `LastTaskResult=0`.
Pemeriksaan ketika task masih `Running` hanya boleh dilabeli
`MANUAL_PREFLIGHT`; keadaan itu ditolak sebagai final acceptance walaupun
heartbeat masih segar.

Task Scheduler Operational log harus sudah aktif sebelum boundary. Toolkit
tidak mengaktifkannya karena perubahan konfigurasi log harus tetap merupakan
aksi operator yang eksplisit dan tercatat.

Nama task V6.3, V4, dan V5 masing-masing harus unik dan berada tepat di root
Task Scheduler (`\`). Acceptance hanya menerima event 107 yang mempunyai
EventRecordID lebih rendah daripada event start 100 pada instance yang sama.
Event completion 102 wajib mempunyai EventRecordID lebih tinggi daripada event
start tersebut. Event 107/100/102 harus unik untuk satu `InstanceId`; duplicate
atau stale run ditolak.

## Verifikasi dan ekstraksi toolkit

Salin satu ZIP toolkit ke Windows. Gunakan hash, commit, dan tree yang diberikan
bersama build final. Jangan menggunakan contoh nilai di bawah sebagai pin.

```powershell
$transferRoot = "C:\AI_SCALPER_TRANSFER\phillip-v6-postrun"
$archive = "$transferRoot\phillip-commodity-v6-postrun-toolkit-<commit>.zip"
$expectedArchiveSHA256 = "<64_HEX_FROM_BUILD>"
$expectedCommit = "<40_HEX_FROM_BUILD>"
$expectedTree = "<40_HEX_FROM_BUILD>"
$toolkitRoot = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-postrun-toolkit-" +
  $expectedCommit.Substring(0, 8)
)

if (Test-Path $toolkitRoot) {
  throw "Toolkit root sudah ada; jangan overwrite evidence."
}

$observed = (
  Get-FileHash -LiteralPath $archive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($observed -ne $expectedArchiveSHA256) {
  throw "Toolkit archive hash mismatch."
}

Expand-Archive -LiteralPath $archive -DestinationPath $toolkitRoot

& "C:\AI_SCALPER_PRIVATE\phillip-commodity-ecedec9-venv\Scripts\python.exe" `
  -I -S -B `
  "$toolkitRoot\phillip_commodity_v6_postrun_acceptance.py" `
  verify-toolkit `
  --archive $archive `
  --expected-archive-sha256 $expectedArchiveSHA256 `
  --expected-source-commit $expectedCommit `
  --expected-source-tree $expectedTree

if ($LASTEXITCODE -ne 0) {
  throw "Toolkit verification gagal."
}
```

## Preflight trigger audit sebelum boundary

Jalankan checker read-only ini segera setelah ekstraksi dan ulangi sebelum
boundary. Ia tidak memulai atau mengubah task.

```powershell
& "$toolkitRoot\Test-PhillipCommodityV6TriggerAuditReadiness.ps1" `
  -ToolkitArchive $archive `
  -ExpectedToolkitArchiveSHA256 $expectedArchiveSHA256

if (-not $?) {
  throw "Trigger-audit readiness gagal; jangan menunggu boundary tanpa fix."
}
```

Output yang sah harus memuat:

```text
Status                        = PHILLIP_COMMODITY_V6_TRIGGER_AUDIT_READY
OperationalLogEnabled         = True
TaskEnabled                   = True
AllowStartOnDemand            = False
StartWhenAvailable            = False
MultipleInstances             = IgnoreNew
LastTaskResultHex             = 0x........
LastRunClassification         = <diagnostic classification>
LatestExpectedBoundaryUtc     = <UTC boundary or null>
LatestBoundaryStatus          = <diagnostic boundary status>
LatestBoundaryObserved        = <True or False>
ManualStartRequired           = False
ManualStartProvenanceObserved = False
EventProvenanceInspected      = False
TriggerEvidenceCollection     = <diagnostic evidence state>
AcceptanceReady               = False
TaskSchedulerMutation         = NOT_PERFORMED
OrderCapability               = DISABLED
LiveAllowed                   = False
```

Readiness diagnostic tidak membaca event provenance dan tidak dapat memberikan
acceptance. `NON_BOUNDARY_REQUEST_REFUSED_WITH_DEMAND_START_DISABLED` hanya
berarti last-run berada di luar toleransi boundary, result ternormalisasi
`0x800710E0`, dan installed task melarang demand start. Nilai itu tidak boleh
diubah menjadi klaim manual invocation tanpa event 110. Demikian pula
`AUTOMATIC_RUN_COMPLETED_PENDING_EVIDENCE` tetap memerlukan korelasi event
107/100/102 serta seluruh acceptance evidence.

`TriggerEvidenceCollection` bersifat informatif dan deny-only:

- `PENDING_AUTOMATIC_RUN` berarti latest boundary belum teramati;
- `PENDING_AUTOMATIC_COMPLETION` berarti task boundary-aligned masih berjalan;
- `PENDING_EVENT_CORRELATION_AND_ACCEPTANCE` berarti result boundary-aligned
  sudah `0`, tetapi event dan seluruh bundle acceptance belum diverifikasi;
- `FORENSIC_REVIEW_REQUIRED` berarti boundary-aligned berakhir nonzero.

Tidak satu pun nilai tersebut memberikan acceptance, promotion, atau order
authority.

Jika checker menyatakan log belum aktif, hentikan alur dan aktifkan Task
Scheduler history melalui prosedur administrator Windows yang disetujui,
kemudian jalankan checker ulang. Jangan men-start task untuk menghasilkan
event pengganti.

## Buat acceptance ZIP

Perintah ini menjalankan health checker, tetapi tidak memulai task. Wrapper
juga memerlukan DACL receipt yang protected dan hanya memberikan write kepada
SID installer yang terikat di receipt, `LocalSystem`, dan
`BUILTIN\\Administrators`. Grant tulis untuk principal lain menggagalkan
collection sebelum ZIP dibuat.

```powershell
$output = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-postrun-acceptance\" +
  "phillip-commodity-v6-postrun-" +
  [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
  ".zip"
)

& "$toolkitRoot\Invoke-PhillipCommodityV6PostRunAcceptance.ps1" `
  -ToolkitArchive $archive `
  -ExpectedToolkitArchiveSHA256 $expectedArchiveSHA256 `
  -Output $output

if (-not $?) {
  throw "Post-run acceptance gagal."
}
```

Output sukses harus menyatakan:

```text
Status                  = PHILLIP_COMMODITY_V6_POSTRUN_ACCEPTANCE_READY
SchedulerInstanceId     = <CORRELATED_GUID>
ScheduledTriggerRecordId = <EVENT_107_RECORD_ID>
TaskStartRecordId       = <EVENT_100_RECORD_ID>
TaskCompletionRecordId  = <EVENT_102_RECORD_ID>
ProcessExitCode         = 0
ReceiptAclValidated     = True
BrokerOrderCount        = 0
TriggerProvenanceScope  = LOCAL_HOST_EVENT_LOG
OffhostCustodyPerformed = False
OrderCapability         = DISABLED
LiveAllowed             = False
PromotionEligible       = False
TaskSchedulerMutation   = NOT_PERFORMED
BrokerMutation          = NOT_PERFORMED
```

## Verifikasi ulang dan custody

Simpan `ArchiveSHA256`, `BundleIdentitySHA256`, checkpoint HMAC, heartbeat,
source event count, task state, scheduler result, correlated instance ID, dan
record ID event 107/100/102 dari output. Verifikasi ulang ZIP sebelum transfer:

```powershell
$acceptanceSHA256 = (
  Get-FileHash -LiteralPath $output -Algorithm SHA256
).Hash.ToLowerInvariant()

& "C:\AI_SCALPER_PRIVATE\phillip-commodity-ecedec9-venv\Scripts\python.exe" `
  -I -S -B `
  "$toolkitRoot\phillip_commodity_v6_postrun_acceptance.py" `
  verify `
  --archive $output `
  --expected-archive-sha256 $acceptanceSHA256 `
  --expected-toolkit-source-commit $expectedCommit `
  --expected-toolkit-source-tree $expectedTree

if ($LASTEXITCODE -ne 0) {
  throw "Acceptance ZIP verification gagal."
}
```

Setelah itu salin exact ZIP ke Object Lock/WORM di luar VPS. Acceptance ZIP
tetap menyatakan `offhost_custody_performed=false`; klaim itu hanya dapat
ditutup oleh acknowledgement receipt dari provider/custodian independen.
Jangan mengedit ZIP lokal untuk mengubah status tersebut.

## Buat satu custody-request ZIP

`New-PhillipCommodityV6CustodyRequest.ps1` membungkus exact acceptance ZIP dan
manifest permintaan ke satu ZIP create-exclusive. Dengan input, timestamp,
tujuan, dan retention yang sama, byte output harus identik. Nilai minimum
engineering adalah 365 hari dari waktu permintaan dan tidak boleh lebih awal
dari `2027-09-21T15:16:00Z`. Ini adalah lantai engineering untuk custody
evidence, bukan penetapan kewajiban hukum.

```powershell
$custodyRequest = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-custody-requests\" +
  "phillip-commodity-v6-custody-request-" +
  [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
  ".zip"
)

& "$toolkitRoot\New-PhillipCommodityV6CustodyRequest.ps1" `
  -ToolkitArchive $archive `
  -ExpectedToolkitArchiveSHA256 $expectedArchiveSHA256 `
  -AcceptanceArchive $output `
  -ExpectedAcceptanceArchiveSHA256 $acceptanceSHA256 `
  -DestinationId "independent-worm-jp-01" `
  -Output $custodyRequest

if (-not $?) {
  throw "Custody request gagal."
}
```

Output yang benar masih menyatakan:

```text
OffhostCustodyPerformed = False
OrderCapability         = DISABLED
LiveAllowed             = False
PromotionEligible       = False
```

Kirim exact custody-request ZIP beserta SHA-256 luarnya ke kustodian. Kustodian
harus menyimpan member `phillip-commodity-v6-postrun-acceptance.zip` tanpa
perubahan byte, mengaktifkan versioning dan Object Lock mode `COMPLIANCE`, lalu
mengembalikan policy serta receipt JSON kanonis.

## Kontrak policy dan receipt eksternal

Policy harus berasal dari pihak independen, berisi public key RSA 3072–8192
bit dengan exponent 65537, dan dipin melalui exact SHA-256. Private key tidak
boleh berada di repository, toolkit, VPS, atau assessment. JSON policy dan
receipt harus berupa UTF-8 canonical JSON: key terurut, tanpa whitespace
tambahan, tanpa duplicate key, dan tanpa newline akhir.

Policy juga mengikat exact destination ID, storage-provider ID, dan minimum
retain-until yang diizinkan; receipt dari provider atau tujuan lain ditolak.

Policy schema:

```text
phillip-commodity-v6-worm-custody-rsa-policy-v1
```

Receipt schema:

```text
phillip-commodity-v6-worm-custody-receipt-v1
```

Receipt wajib mengikat:

- SHA-256 custody-request ZIP;
- request identity;
- SHA-256 dan bundle identity acceptance ZIP;
- destination ID yang sama dengan policy;
- provider ID serta hash bucket, object key, dan object version;
- exact content SHA-256 dan size acceptance ZIP;
- Object Lock `COMPLIANCE`, versioning, WORM, dan retain-until;
- policy SHA-256, custodian ID, key ID, dan public-key fingerprint;
- seluruh safety field tetap deny-only.

Tanda tangan dihitung oleh kustodian atas canonical receipt tanpa field
signature, diawali domain berikut:

```text
AI_SCALPER:PHILLIP_COMMODITY_V6_WORM_CUSTODY_RECEIPT:v1\0
```

Algoritma yang diterima hanya `RSASSA-PKCS1-v1_5-SHA256`.

## Verifikasi receipt dan buat assessment

Salin policy dan receipt dari kustodian ke Windows, hitung dan konfirmasi hash
policy melalui kanal independen, lalu jalankan:

```powershell
$policy = "C:\AI_SCALPER_PRIVATE\custodian\worm-policy.json"
$receipt = "C:\AI_SCALPER_PRIVATE\custodian\worm-receipt.json"
$expectedPolicySHA256 = "<64_HEX_FROM_INDEPENDENT_CHANNEL>"
$custodyRequestSHA256 = (
  Get-FileHash -LiteralPath $custodyRequest -Algorithm SHA256
).Hash.ToLowerInvariant()
$assessment = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-custody-assessments\" +
  "phillip-commodity-v6-custody-assessment-" +
  [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
  ".json"
)

& "$toolkitRoot\Test-PhillipCommodityV6CustodyReceipt.ps1" `
  -ToolkitArchive $archive `
  -ExpectedToolkitArchiveSHA256 $expectedArchiveSHA256 `
  -CustodyRequestArchive $custodyRequest `
  -ExpectedCustodyRequestArchiveSHA256 $custodyRequestSHA256 `
  -Policy $policy `
  -ExpectedPolicySHA256 $expectedPolicySHA256 `
  -Receipt $receipt `
  -AssessmentOutput $assessment

if (-not $?) {
  throw "Receipt custody tidak sah."
}
```

Assessment sukses membuktikan bahwa signed attestation kustodian diterima dan
terikat ke exact acceptance bytes. Ia secara eksplisit menyatakan
`direct_storage_api_inspection_performed=false`; verifier lokal tidak
menyamakan verifikasi tanda tangan dengan akses langsung ke API cloud. Hasil
ini tetap tidak memberi authority untuk demo-auto, promotion, atau live order.

## Bentuk semantic evidence untuk gate LIVE-canary

Assessment JSON tidak boleh langsung dipakai sebagai `WORM_CUSTODY` evidence.
Gabungkan empat source autentik menjadi ZIP bridge yang dapat direkonstruksi
ulang pada setiap boundary. Output harus baru dan policy hash tetap berasal
dari kanal independen.

```powershell
$wormGateEvidence = (
  "C:\AI_SCALPER_PRIVATE\phillip-commodity-v6-custody-assessments\" +
  "phillip-v6-live-canary-worm-gate-evidence-" +
  [DateTimeOffset]::UtcNow.ToString("yyyyMMddTHHmmssfffZ") +
  ".zip"
)

& "C:\AI_SCALPER\.venv\Scripts\python.exe" -B `
  .\prepare_phillip_v6_live_canary_worm_gate_evidence.py `
  --custody-request $custodyRequest `
  --expected-custody-request-sha256 $custodyRequestSHA256 `
  --expected-toolkit-source-commit $expectedCommit `
  --expected-toolkit-source-tree $expectedTree `
  --policy $policy `
  --expected-policy-sha256 $expectedPolicySHA256 `
  --receipt $receipt `
  --assessment $assessment `
  --output $wormGateEvidence
if ($LASTEXITCODE -ne 0) {
  throw "Semantic WORM gate evidence gagal."
}
```

Paket tersebut masih deny-only. Ia baru dapat dipakai oleh runbook
`LIVE_CANARY_GATE_RECEIPT_OPERATOR.md`, yang kembali memerlukan exact policy
SHA-256 dan tidak membuka central lock atau authority order.
