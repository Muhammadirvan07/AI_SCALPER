# Phillip Commodity V6 Post-Run Acceptance

Status: **READ-ONLY / POST-SCHEDULED-RUN ONLY / ORDER DISABLED**

Toolkit ini menutup handoff setelah pemicu otomatis V6.3. Ia menjalankan exact
health checker yang sudah terpasang, memverifikasi task dan signed checkpoint,
lalu mengikat checkpoint terbaru, exact audit pair, installation receipt,
installed task XML, dan health transcript ke satu ZIP create-exclusive.

Toolkit ini tidak:

- menjalankan `Start-ScheduledTask`;
- mendaftarkan, mengaktifkan, menonaktifkan, atau menghapus task;
- mengakses credential secara langsung;
- mengimpor MetaTrader5 atau membawa primitive order;
- menyalin bukti ke storage off-host;
- membuka demo-auto, promotion, atau live trading.

## Kapan dijalankan

Jangan jalankan sebelum boundary otomatis
`2026-07-30T06:45:00+09:00`. Manual start bukan pengganti bukti scheduler.
Jalankan toolkit ketika V6 sedang `Running` dengan heartbeat segar, atau setelah
run terjadwal selesai sehat dan task kembali `Ready` dengan result `0`.

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

## Buat acceptance ZIP

Perintah ini menjalankan health checker, tetapi tidak memulai task.

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
OffhostCustodyPerformed = False
OrderCapability         = DISABLED
LiveAllowed             = False
PromotionEligible       = False
TaskSchedulerMutation   = NOT_PERFORMED
BrokerMutation          = NOT_PERFORMED
```

## Verifikasi ulang dan custody

Simpan `ArchiveSHA256`, `BundleIdentitySHA256`, checkpoint HMAC, heartbeat,
source event count, task state, dan scheduler result dari output. Verifikasi
ulang ZIP sebelum transfer:

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
