# Crypto M5 Challenger — BTCUSD / ETHUSD

Status: **DIAGNOSTIC-ONLY / CHALLENGER / NO CREDENTIALS / NO ORDERS**

M5 berjalan berdampingan dengan M15. M15 tetap champion; M5 tidak mengganti,
mempromosikan, atau mencampur statistik dengan M15. Keduanya memakai Binance
spot public sebagai primary dan Coinbase public sebagai validator.

## Isolasi domain

| Artefak | M15 champion | M5 challenger |
|---|---|---|
| Config | `config/crypto_weekend_shadow.json` | `config/crypto_m5_challenger.json` |
| Runner | `run_crypto_weekend_shadow.py` | `run_crypto_m5_challenger.py` |
| Journal | `crypto-weekend-shadow.sqlite3` | `crypto-m5-challenger.sqlite3` |
| Summary | `crypto-weekend-summary.json` | `crypto-m5-challenger-summary.json` |
| Report | `crypto-weekend-performance.json` | `crypto-m5-challenger-performance.json` |
| Profile | `CRYPTO_WEEKEND_DIAGNOSTIC_ONLY` | `CRYPTO_M5_CHALLENGER_DIAGNOSTIC_ONLY` |

Profile, schema, source-binding hash, timeframe, decision key, dan hash chain
berbeda. Journal dari satu lane ditolak ketika dibuka sebagai lane lain.

## Semantik M5

- Hanya finalized UTC M5 yang unique, contiguous, dan OHLC-valid.
- Entry quote wajib diterima maksimal 10 detik setelah M5 close.
- BTCUSD dan ETHUSD memakai strategi crypto yang sama sebagai baseline
  perbandingan, dengan maksimum 72 bar agar horizon enam jam M15 tetap sama.
- ATR/EMA/ADX/RSI dihitung dari M5. Karena horizon indikator berubah, hasil M5
  adalah challenger yang harus dievaluasi, bukan bukti bahwa M5 lebih unggul.
- Snapshot M5 tidak dapat membentuk `TradeIntent`; jalur execution hanya
  menerima snapshot M15.

## Jalankan di Windows

Jalankan M5 di terminal terpisah dari M15:

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1

python -B .\run_crypto_m5_challenger.py `
  --acknowledge-diagnostic-only `
  --continuous `
  --poll-seconds 2
```

Default weekend window tetap Jumat 21:00 UTC sampai Minggu 22:00 UTC. Untuk
smoke test eksplisit di luar window, tambahkan `--allow-weekday-diagnostic`.
Flag tersebut tidak membuka credential, order, promotion, atau live.

Hentikan dengan `Ctrl+C`, lalu buat report:

```powershell
python -B .\generate_crypto_m5_challenger_report.py `
  --acknowledge-diagnostic-only
```

Jangan menghapus, mengedit, atau menukar nama database M5 dan M15.

## Cara membandingkan

Bandingkan per timeframe dan per simbol:

- closed trades dan frekuensi setup;
- expectancy R dan profit factor;
- max drawdown R serta consecutive losses;
- win rate sebagai metrik pendukung, bukan gate tunggal;
- timeout dan holding duration;
- wait reasons, regime distribution, dan strategy distribution.

Keputusan champion/challenger hanya boleh dilakukan offline setelah sampel
memadai. M5 tidak boleh mempromosikan dirinya sendiri.
