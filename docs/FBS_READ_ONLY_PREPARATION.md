# FBS Read-Only Preparation

FBS adalah broker pengganti yang diminta operator. Pergantian dilakukan dua
tahap agar exact terminal binding tidak ditebak:

1. probe aman pada terminal demo FBS;
2. review hasil, lalu binding config dan preflight kandidat.

Probe hanya membaca company, exact server, mata uang akun, leverage, margin
mode, dan kemungkinan nama empat simbol. Login, nama pemilik, saldo, equity,
dan password tidak dibaca ke output. Tidak ada order API pada facade.

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

Kirim output JSON probe untuk direview. Jangan kirim login atau password.
`binding_ready=true` hanya berarti setiap canonical symbol memiliki tepat satu
alias yang ditemukan; itu belum mengaktifkan discovery evidence, demo order,
atau live trading.

Sampai binding FBS dipatch dan preflight FBS lulus, jangan menjalankan realtime
diagnostic dengan `--candidate fbs`.
