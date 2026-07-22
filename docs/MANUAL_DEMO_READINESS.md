# Manual-Demo Readiness (Locked)

Status: **BLOCKED / REPORT-ONLY / ORDER CAPABILITY DISABLED**

Dokumen ini menjelaskan reporter persiapan manual-demo. Reporter bukan executor,
tidak memeriksa atau mengirim order, tidak mengaktifkan terminal, dan tidak
mengubah konfigurasi. Seluruh safety lock proyek tetap aktif.

## Menjalankan reporter

Di PowerShell Windows dari `C:\AI_SCALPER`:

```powershell
.\.venv\Scripts\Activate.ps1

python -B .\run_manual_demo_readiness.py --candidate phillip-fx
python -B .\run_manual_demo_readiness.py --candidate phillip-commodity
```

Opsional, buat satu artefak audit baru di luar repository:

```powershell
python -B .\run_manual_demo_readiness.py `
  --candidate phillip-fx `
  --output C:\AI_SCALPER_PRIVATE\manual-demo-readiness\phillip-fx-01.json
```

Output existing tidak pernah ditimpa. Command tidak menerima login, password,
secret, terminal path, volume, arm token, permit, atau approval.

## Arti hasil

`ready=false` adalah hasil yang benar pada fase sekarang. Blocker berasal dari:

- policy global, seperti clean release, Windows hardening, news provider,
  failure drills, journal/reconciliation drill, dan independent approver;
- policy lane, seperti 20 broker sessions, broker-forward sample, delapan minggu
  observasi, exact terminal fence, serta runtime currency-conversion attestation;
- candidate plan, termasuk instrument specification, session calendar, exact
  binding, dan legal eligibility;
- evidence profile, termasuk registration yang masih disabled.

Reporter tidak dapat mengubah blocker menjadi `true`. Penyelesaian tiap blocker
harus melalui workflow evidence/review yang sesuai dan clean commit terpisah.

## Konversi batas risiko akun JPY

MetaTrader 5 mengembalikan profit/loss, margin, dan equity dalam mata uang akun.
Hard cap AI_SCALPER tetap:

- XAU: `$0.20` per trade;
- FX: `$0.25` per trade;
- maksimum `0.25%` equity;
- maksimum `0.01` lot.

Untuk akun JPY, cap USD diubah ke JPY menggunakan quote broker yang terikat exact
account/server/symbol dan berumur maksimum satu detik. `USDJPY` direct memakai
bid; pasangan inverse memakai `1 / ask`. Quote hilang, stale, future, metadata
currency mismatch, atau berasal dari account/server lain menghasilkan WAIT dan
lot nol.

## Batas tahap ini

Walau semua unit test hijau, reporter bukan bukti 20 sesi, 50 broker-forward
trade, delapan minggu observasi, 10 controlled manual-demo order, atau 30-day
demo-auto soak. Tidak ada order yang boleh dikirim sampai profile/runner fase
manual-demo dibuat melalui security review dan approval terpisah.
