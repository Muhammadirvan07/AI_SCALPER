# FBS Read-Only Preparation

FBS adalah broker pengganti yang diminta operator. Exact terminal binding telah
diterima melalui probe sanitasi:

- server: `FBS-Demo`;
- company: `FBS Markets Inc.`;
- account: demo USD, leverage 500:1, retail hedging;
- symbol map: XAUUSD, EURUSD, USDJPY, AUDUSD tanpa suffix.

Probe hanya membaca company, exact server, mata uang akun, leverage, margin
mode, dan kemungkinan nama empat simbol. Login, nama pemilik, saldo, equity,
dan password tidak dibaca ke output. Tidak ada order API pada facade.
Probe juga melaporkan kandidat opsional BTCUSD/ETHUSD secara terpisah untuk
onboarding crypto CFD; hasil itu tidak otomatis mencampur lane forex.

## Menjalankan probe

Tutup terminal XM/FINEX dan buka hanya terminal MT5 FBS yang sudah login ke
akun demo memakai investor/read-only password. Algo Trading harus OFF dan
external Python trading API harus disabled.

Di PowerShell:

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1

python -B .\run_mt5_binding_probe.py --candidate fbs
```

Probe dapat diulang jika binding terminal berubah. Jangan kirim login atau
password. `binding_ready=true` belum mengaktifkan discovery evidence, demo
order, atau live trading.

## Preflight setelah binding

```powershell
python -B .\run_mt5_readonly_preflight.py `
  --candidate fbs `
  --output .\runtime_state\broker_discovery\fbs-preflight-01.json
```

Realtime diagnostic baru boleh dimulai setelah output
`MT5_READ_ONLY_PREFLIGHT_PASS`. Semua hasil tetap paper/non-promotional.
Receipt yang ditulis bersifat sanitasi dan create-exclusive: ia menyimpan
server, currency, leverage, symbol map, serta safety booleans, tetapi tidak
menyimpan login, nama, balance, equity, atau credential. Receipt ini berguna
untuk audit operasi, namun secara eksplisit tetap
`validation_evidence=false`, `promotion_eligible=false`, dan tidak menggantikan
discovery v3 bertanda tangan.

Binding crypto CFD FBS juga telah dikonfirmasi sebagai `BTCUSD` dan `ETHUSD`.
Gunakan `docs/FBS_CRYPTO_SHADOW.md`; jangan mencampur journal crypto broker
dengan journal forex atau public exchange.
