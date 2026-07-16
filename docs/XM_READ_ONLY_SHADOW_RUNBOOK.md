# XM Read-Only Shadow Runbook — Window 02 v3

Status fase ini adalah `LEGAL_BLOCKED`, `DIAGNOSTIC`, `NOT_READY`, dan
read-only. Runtime tidak memiliki kapabilitas order efektif karena login akun
dan terminal wajib menolak trading sebelum collector boleh berjalan. Lock
berikut tidak boleh diubah:

- `live_allowed=false`
- `safe_to_demo_auto_order=false`
- `max_lot=0.01`
- GBPUSD blocked
- BTCUSD shadow-only

Kontrak lama `xm-window-01-diagnostic-v2` adalah artefak diagnostic yang sudah
ditutup untuk pengembangan lanjutan. Jangan hapus, timpa, backfill, atau
memakainya dengan runtime v3. Window 02 harus memakai discovery, plan,
calendar, snapshot, contract, dan key baru.

## Hard stop hukum saat ini

Untuk operating jurisdiction `JP`, XM/Tradexfin Limited telah ditandai
`VERIFIED_INELIGIBLE` di konfigurasi kandidat berdasarkan sumber resmi Japan
FSA. Karena itu template Window 02 Jepang tidak boleh dipersiapkan,
didaftarkan, atau dijalankan. Legal gate akan menolak plan walaupun discovery
dan seluruh tes teknis valid.

Langkah di bawah dipertahankan sebagai prosedur masa depan. Prosedur baru hanya
boleh dimulai setelah exact broker dan yurisdiksi operasi dinyatakan eligible
melalui sumber regulator independen dan konfigurasi baru direview. Jangan
mengubah flag legal hanya agar plan lolos.

## Prasyarat

- Windows x86-64, CPython 3.12, dan MT5 XM sudah terbuka serta login ke akun
  demo pada server exact `XMTrading-MT5 3` menggunakan investor/read-only
  password, bukan master trading password.
- Release berasal dari commit bersih pada branch yang disetujui.
- Waktu Windows tersinkron; drift terhadap trusted UTC maksimum satu detik.
- Semua perintah dijalankan dari PowerShell di `C:\AI_SCALPER`.
- Tombol Algo Trading/AutoTrading pada MT5 tetap OFF.
- Opsi MT5 untuk menonaktifkan automated trading melalui external Python API
  wajib ON. Discovery gagal bila `terminal.tradeapi_disabled` bukan `true`.
- `account.trade_allowed=false`, `account.trade_expert=false`, dan
  `terminal.trade_allowed=false` wajib terbukti dari API MT5.

## 1. Sinkronkan release dan dependency

```powershell
cd C:\AI_SCALPER
git pull origin agent/live-grade-phase3
python -m venv --without-pip .venv-release
.\.venv-release\Scripts\python.exe -I -S -B `
  .\verify_windows_dependency_lock.py --require-current-runtime
.\.venv-release\Scripts\python.exe -I -S -B `
  .\bootstrap_windows_dependencies.py `
  --wheelhouse .\release-wheelhouse
.\.venv-release\Scripts\python.exe -I -S -B `
  .\verify_windows_dependency_lock.py `
  --require-current-runtime `
  --check-installed
git status --short
```

`git status --short` wajib kosong. `runtime_state/` dan
`validation_artifacts/` adalah runtime evidence, bukan source release.
Aturan lock lengkap ada di `docs/WINDOWS_DEPENDENCY_LOCK.md`.

## 2. Verifikasi clock

Jalankan sebelum discovery, sebelum registrasi, dan setiap hari selama window:

```powershell
w32tm /query /status
w32tm /resync
w32tm /query /status
```

Jika sinkronisasi gagal, source time tidak dipercaya, atau measured drift lebih
dari satu detik, jangan registrasi dan jangan menjalankan collector. Perbaiki
clock terlebih dahulu; jangan memalsukan timestamp artefak.

## 3. Provision key Window 02

```powershell
python .\setup_xm_evidence_key.py
```

Key name wajib `xm-window-02-v3`. Secret 256-bit disimpan di Windows
Credential Manager dan tidak boleh dicetak, disalin ke `.env`, atau ditulis ke
repository.

## 4. Buat discovery akun baru

Discovery lama `xm-first.json` tidak boleh dipakai oleh Window 02.

```powershell
python .\mt5_readonly_discovery.py `
  --candidate xm `
  --output .\runtime_state\broker_discovery\xm-window-02-v3.json
```

Receipt v3 mengikat exact akun dan read-only account/terminal attestation
melalui HMAC tanpa menyimpan MT ID/login mentah,
nama akun, balance, equity, atau credential. Output dibuat create-exclusive.
Jika file sudah ada, jangan overwrite; hentikan dan review provenance-nya.
Sesudah discovery, tunggu sampai UTC melewati boundary M15 berikutnya sebelum
menjalankan `prepare_xm_window.py`; plan tidak boleh mengklaim timestamp yang
lebih awal daripada receipt discovery.

## 5. Siapkan plan immutable dan kalender

```powershell
python .\prepare_xm_window.py
python .\build_xm_calendar.py
```

Perintah pertama memverifikasi HMAC discovery, legal entity, exact server,
empat symbol mapping, safety lock, dan template tracked. Perintah kedua hanya
menerima plan yang tetap identik dengan template Window 02 v3.

Artefak yang dihasilkan:

- `runtime_state\broker_discovery\xm-calendar-window-02-plan-v3.json`
- `runtime_state\broker_discovery\xm-calendar-window-02-v3.json`

Keduanya create-exclusive dan terikat ke discovery receipt yang sama.

## 6. Daftarkan kontrak sebelum window dimulai

```powershell
python .\register_xm_forward_contract.py
```

Hasil yang benar:

- Contract: `xm-window-02-diagnostic-v3`
- Profile: `DIAGNOSTIC`
- Order capability: `DISABLED`

Registrasi gagal tertutup jika Git kotor, dependency/config/profile hash drift,
snapshot tidak valid, clock claim basi, account/server/symbol berubah, key
berbeda, atau observation start sudah terlewati.

## 7. Uji satu read-only cycle

```powershell
python -I -S -B .\run_xm_shadow_once.py
```

Sebelum bar due, hasil normal adalah `IDLE` dengan status `NOT_DUE`. Runner
tetap mengulang read-only attestation segera setelah MT5 initialize, sehingga
cycle tanpa bar due pun gagal tertutup jika investor login, Algo Trading, atau
external Python API berubah. Kode keluar
`3` dengan `SHADOW_CYCLE_ALREADY_RUNNING` berarti instance sebelumnya masih
memegang singleton fence; jangan memulai instance kedua. `HOLD` wajib
diinvestigasi dan tidak boleh diperbaiki dengan backfill.

Setiap invocation terlebih dahulu memverifikasi target Windows, exact package
set, versi bootstrap pip, dan hash/size file wheel dari `RECORD`. Pemeriksaan
terjadi sebelum credential keyring, MT5, dan evidence runtime dimuat. Receipt
PASS/HOLD ditulis durable ke tabel `shadow_startup_guards` pada journal SQLite.
`DEPENDENCY_INTEGRITY_REJECTED` atau `STARTUP_GUARD_JOURNAL_FAILED` selalu
menghasilkan `HOLD` dengan order capability tetap disabled.

Runner juga menulis hash-chained append-only receipt ke
`shadow_operational_events` untuk setiap tahap penting:

- dependency integrity dan startup guard;
- runtime import dan credential load;
- import serta inisialisasi MT5;
- attestation read-only account+terminal, termasuk saat semua bar `NOT_DUE`;
- verifikasi exact forward contract;
- pemeriksaan free disk sebelum setiap kemungkinan append;
- hasil cycle, unexpected exception, cleanup, dan audit export.

`shadow_runtime_status` adalah proyeksi lokal heartbeat/last-success. Status
akhir eksplisit adalah `HEALTHY`, `FAILED`, `BUSY`, atau `STALE`. Stdout hanya
informasi tambahan; SQLite adalah sumber receipt operasional.

Free disk minimum default adalah 1 GiB. Runner memeriksanya saat startup dan
lagi tepat sebelum setiap exporter yang due. Jangan menurunkan floor ini selama
window aktif. `MINIMUM_FREE_DISK_NOT_SATISFIED` mencegah append dan menghasilkan
`HOLD`.

Sesudah `mt5.initialize()`, runner wajib menerima empat fakta exact:

- `account.trade_allowed=false`
- `account.trade_expert=false`
- `terminal.trade_allowed=false`
- `terminal.tradeapi_disabled=true`

Flag yang hilang atau berbeda menghasilkan
`MT5_READ_ONLY_ATTESTATION_FAILED` sebelum verifikasi/collection cycle, bahkan
bila hasil kalender seharusnya `IDLE`. Exporter mengulang attestation sebelum
dan sesudah setiap capture. Facade read-only tidak menyimpan raw MT5 module dan
tidak mengekspos order, position, deal, atau mutation API.

Bar di boundary sesi hanya mendapat `session_open_boundary` atau
`session_close_boundary` jika timestamp-nya persis sama dengan interval
`market_open_intervals` pada exact signed contract. Runtime tidak menebak
boundary dari jam lokal atau nama simbol.

Setelah setiap invocation, runner membuat audit export ringkas dan
create-exclusive. Bentuk ini dipakai agar jadwal satu menit tidak menghasilkan
snapshot penuh SQLite yang tumbuh kuadratik dan memenuhi disk:

- `runtime_state\shadow\audit_exports\<invocation_id>.audit.json`
- `runtime_state\shadow\audit_exports\<invocation_id>.manifest.json`

Sebelum menulis export, runtime memverifikasi seluruh operational chain dari
sequence `1`, genesis previous-hash nol, sampai global head pada satu snapshot
SQLite yang konsisten. Export ringkas dapat berupa suffix, tetapi manifest
mengikat predecessor sequence/hash, jumlah event source, source head, receipt
invocation, startup guard, cycle receipt, heartbeat projection, file SHA-256,
dan manifest SHA-256. Invocation yang overlap tetap disertakan agar sequence
dan hash chain tidak terputus.

`AUDIT_EXPORT_FAILED` atau `AUDIT_EXPORT_RECEIPT_FAILED` selalu `HOLD`. Pair
immutable dibuat sebelum receipt `AUDIT_EXPORT=PASS` dapat ditulis, jadi pair
tersebut tidak dan tidak boleh diklaim memuat receipt sukses pembuatannya
sendiri. Receipt setelah export tetap berada di operational journal; keberadaan
pair saja bukan bukti bahwa invocation akhirnya sukses. Watchdog/off-host
operator wajib memeriksa exit code, runtime status, dan journal/backup sebelum
menandai transfer lengkap.

Export lokal belum memenuhi off-host requirement: salin file audit dan
manifest sebagai satu pasangan ke storage off-host append-only/WORM. Jangan
menyalin salah satunya saja, menimpa nama lama, atau mengedit permission
read-only.
Full SQLite backup untuk restore tetap merupakan operasi terpisah dari export
per-invocation; lakukan sesuai jadwal backup VPS tanpa mengganti source journal.

Untuk pemeriksaan watchdog tanpa memuat credential atau MT5:

```powershell
python -I -S -B .\run_xm_shadow_once.py `
  --status-only `
  --heartbeat-stale-seconds 180
```

Exit `0` berarti heartbeat belum stale dan recorded state bukan failed. Exit
`2` berarti `FAILED`, `STALE`, status hilang, atau status tidak dapat
diverifikasi. Last-success cycle dan timestamp juga dicetak bila tersedia.

## 8. Jadwal collection

Window terdaftar:

- Start: `2026-07-19 21:00 UTC` / `2026-07-20 06:00 JST`
- Blind: `2026-08-01 21:00 UTC` / `2026-08-02 06:00 JST`
- Final ingestion deadline: `2026-08-01 21:16 UTC` /
  `2026-08-02 06:16 JST`

Batas 10 sesi pada template ini hanya merupakan batch diagnostic pertama.
Benchmark kandidat tetap membutuhkan minimal 20 sesi sehingga, bila legal gate
kelak dibuka, batch kedua harus memakai kontrak baru yang didaftarkan sebelum
observasi. Hasil dua broker tidak boleh dicampur.

Buat Windows Task Scheduler yang menjalankan setiap satu menit, mulai sebelum
`2026-07-20 05:59 JST`:

- Program: `C:\AI_SCALPER\.venv-release\Scripts\python.exe`
- Arguments: `-I -S -B C:\AI_SCALPER\run_xm_shadow_once.py`
- Start in: `C:\AI_SCALPER`
- Repeat task: setiap 1 menit
- Stop schedule: setelah `2026-08-02 06:16 JST`
- If the task is already running: `Do not start a new instance`
  (`MultipleInstances=IgnoreNew`)
- Jangan memilih queue, parallel instance, atau stop existing instance.

Runtime juga memiliki persistent OS singleton fence untuk seluruh proses
verify → collect → append → journal. Fence dilepas otomatis oleh kernel jika
proses atau VPS crash.

Buat task monitoring terpisah yang menjalankan `--status-only` dan mengirim
alarm off-host bila exit code bukan `0`. Heartbeat lokal dianggap stale setelah
180 detik; alert tidak boleh bergantung pada jendela PowerShell atau isi
stdout runner utama. Salin audit export+manifest terbaru off-host setelah
setiap invocation dan verifikasi hash manifest di tujuan.

## Larangan selama kontrak aktif

- Jangan `git pull`, switch branch, edit source/config, atau update dependency.
- Jangan mengganti akun, server, account currency, atau symbol mapping MT5.
- Jangan menjalankan dua collector paralel.
- Jangan menghapus evidence, SQLite journal, lock file, atau contract lama.
- Jangan menghapus, menimpa, atau mengedit audit export/manifest invocation
  lama.
- Jangan menyalakan Algo Trading atau menjalankan order demo-auto/live.
- Jangan membuka hasil PnL sebelum blind period berakhir.

Insiden integrity, clock, account binding, deadline, disk, credential, MT5,
heartbeat, audit export, backup, scheduler overlap, atau security membuat
status `HOLD`.
Insiden critical membuat window diagnostic-invalid. Sistem tetap `NOT_READY`
dan window baru harus didaftarkan secara eksplisit; tidak ada recovery otomatis
yang membuka izin trading.
