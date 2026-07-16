# XM Read-Only Shadow Runbook — Window 01 v2

Status fase ini adalah `DIAGNOSTIC`, `NOT_READY`, dan read-only. Runner tidak
memiliki API order. Lock berikut tidak boleh diubah:

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `max_lot=0.01`
- GBPUSD blocked
- BTCUSD shadow-only

## Prasyarat

- Windows x86-64, Python 3.12, dan MT5 XM sudah terbuka serta login ke akun
  demo pada server `XMTrading-MT5 3`.
- Branch `agent/live-grade-phase3` sudah ditarik ke `C:\AI_SCALPER`.
- Worktree Git harus bersih. Kontrak menolak commit/tree yang berubah.
- Waktu Windows tersinkron dan drift maksimum satu detik.
- Jalankan seluruh perintah dari PowerShell di `C:\AI_SCALPER` dengan venv
  aktif.

## 1. Sinkronkan build dan dependency

```powershell
git pull origin agent/live-grade-phase3
.\.venv\Scripts\Activate.ps1
python -m pip install -r .\requirements-live-windows.txt
git status --short
```

`git status --short` wajib tidak menghasilkan output. File di
`runtime_state/` dan `validation_artifacts/` sengaja tidak dilacak Git.

## 2. Bangun ulang kalender v2

Bundle v1 tidak dapat digunakan karena memakai ID source berbeda per simbol.
Jangan menimpa atau menghapus bundle lama; buat artefak baru:

```powershell
python .\build_xm_calendar.py `
  --output .\runtime_state\broker_discovery\xm-calendar-window-01-v2.json
```

Hash yang diharapkan untuk config v2:

- Bundle: `e050ee791db7c6ec4c5f506d0dcbc0bdba8f09aad681e371a48c9c78eca452df`
- AUDUSD: `38aa4547a1c93e29eb86833c73962eb11204b061aec0d1e74663ef43d1933756`
- EURUSD: `53cfdff4833abe8a8916e7883bc3235fb64a0b1ee0daad76c465bf40f9a050f8`
- USDJPY: `01a85c0635001e037971db5048b8e7cec3d469f0118e0d6e282f634b2414c043`
- XAUUSD: `ee61ef834af5c7378324841992fe14cea07e99c6cfb631bffe720df20f10104e`

Keempat kalender wajib menampilkan source cohort yang sama:
`xm-a53b6c55e91c6afb-window-01`.

## 3. Provision kunci evidence

```powershell
python .\setup_xm_evidence_key.py
```

Kunci 256-bit disimpan di Windows Credential Manager dengan service
`AI_SCALPER_PHASE3_EVIDENCE`. CLI hanya mencetak fingerprint; secret tidak
pernah dicetak atau ditulis ke repository.

## 4. Daftarkan kontrak sebelum observation start

```powershell
python .\register_xm_forward_contract.py `
  --discovery .\runtime_state\broker_discovery\xm-first.json `
  --calendar .\runtime_state\broker_discovery\xm-calendar-window-01-v2.json `
  --artifact-root .\validation_artifacts
```

Kontrak yang dibuat adalah `xm-window-01-diagnostic-v2`. Registrasi bersifat
create-once dan akan gagal jika snapshot/contract sudah ada tetapi tidak valid,
Git kotor, hash drift, server/simbol berubah, atau waktu registrasi sudah
melewati observation start.

## 5. Uji read-only sebelum window

```powershell
python .\run_xm_shadow_once.py
```

Sebelum window, hasil normal adalah `IDLE` dengan simbol `NOT_DUE`. Output
selalu mencetak `Order capability: DISABLED`. `HOLD` harus diperiksa; jangan
menghapus evidence atau memaksa backfill.

## 6. Jadwal collection

Window terdaftar:

- Start: `2026-07-19 21:00 UTC` / `2026-07-20 06:00 JST`
- Blind: `2026-08-01 21:00 UTC` / `2026-08-02 06:00 JST`
- Final ingestion deadline: `2026-08-01 21:16 UTC` / `2026-08-02 06:16 JST`

Buat Windows Task Scheduler yang menjalankan setiap satu menit, tepat pada
detik `00`, mulai sebelum `2026-07-20 06:30 JST`:

- Program: `C:\AI_SCALPER\.venv\Scripts\python.exe`
- Arguments: `C:\AI_SCALPER\run_xm_shadow_once.py`
- Start in: `C:\AI_SCALPER`
- Repeat: setiap 1 menit
- Stop schedule: setelah `2026-08-02 06:16 JST`

Bar M15 baru hanya boleh di-append pada waktu finalisasinya dengan grace 60
detik. Jika runner terlambat, hasilnya `HOLD/APPEND_DEADLINE_MISSED`; sistem
menolak backfill agar forward test tetap jujur.

## Larangan selama kontrak aktif

- Jangan `git pull`, switch branch, edit source/config, atau update dependency.
- Jangan mengganti akun/server/symbol mapping MT5.
- Jangan menyalin kunci ke `.env`, PowerShell history, atau file teks.
- Jangan menghapus `validation_artifacts/` atau SQLite shadow journal.
- Jangan menjalankan order demo-auto/live dari proyek ini.

Insiden integritas, clock, MT5 binding, atau append deadline membuat window ini
diagnostic-invalid dan harus dimulai ulang dengan kontrak/window baru.
