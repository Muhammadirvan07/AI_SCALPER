# FBS Broker Crypto Shadow

BTCUSD dan ETHUSD dibaca langsung dari terminal MT5 `FBS-Demo` sebagai CFD
broker. Runtime ini tidak memakai feed Binance/Coinbase dan tidak berbagi
journal dengan lane XAU/FX.

Bar runtime menunjukkan waktu server FBS UTC+3 pada 2026-07-18. Offset ini
terdaftar hanya untuk diagnostic dan diverifikasi ulang terhadap trusted UTC;
runtime berhenti fail-closed bila alignment berubah. Session calendar dan DST
policy resmi masih pending sehingga hasil belum menjadi evidence.

Status permanen:

```text
order_capability = DISABLED
live_allowed = false
safe_to_demo_auto_order = false
promotion_eligible = false
validation_evidence = false
max_lot = 0.01
```

## M5 challenger — rekomendasi weekend

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1

python -B .\run_fbs_crypto_m5_challenger.py `
  --candidate fbs `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 2
```

Output:

```text
runtime_state\diagnostic\fbs-broker-crypto-m5.sqlite3
runtime_state\diagnostic\fbs-broker-crypto-m5-summary.json
```

## M15 champion — pembanding terpisah

```powershell
python -B .\run_fbs_crypto_m15_shadow.py `
  --candidate fbs `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 5
```

Jangan menjalankan M5 dan M15 bersamaan pada akun yang sama. Account-wide
singleton fence akan menolak proses kedua. Jalankan M5 sebagai lane aktif dan
gunakan M15 pada periode observasi terpisah.

## Laporan

```powershell
python -B .\generate_fbs_crypto_broker_report.py `
  --timeframe M5 `
  --acknowledge-diagnostic-only
```

Ganti `M5` dengan `M15` untuk laporan champion. Win rate, PF, dan expectancy
baru bermakna setelah terdapat cukup posisi paper yang tertutup. Hasil ini
tetap diagnostic dan tidak dapat membuka gate order/live.

Lihat segmentasi strategi dan arah tanpa mengubah journal:

```powershell
$r = Get-Content `
  .\runtime_state\diagnostic\fbs-broker-crypto-m5-performance.json `
  -Raw | ConvertFrom-Json

$r.per_strategy | Format-List
$r.per_side | Format-List
$r.trades | Format-Table symbol,side,strategy,exit_reason,outcome,r_multiple
```
