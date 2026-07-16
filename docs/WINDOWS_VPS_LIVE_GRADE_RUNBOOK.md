# Windows VPS Live-Grade Runbook

Runbook ini hanya untuk menyiapkan dan memvalidasi shadow/manual-demo. Jangan
aktifkan live atau demo-auto selama repository policy masih terkunci.

## Prasyarat

1. Windows Server x86-64 dengan Python 3.12 dan terminal MT5 resmi.
2. Satu exact broker server dan account type yang sudah lolos legal review serta
   benchmark minimal 20 sesi.
3. Clean Git commit; hash commit/tree, config, dependency lock, dan profile
   tercatat dalam forward contract.
4. `requirements-live-windows.txt` hanya direct-pin manifest. Install release
   hanya dari hashed offline wheelhouse yang diikat
   `pylock.windows-cp312.toml` dan immutable wheel-tree manifest. Jalankan
   verification/runtime memakai `python -I -S -B`. Buat venv dengan
   `--without-pip`, lalu instal hanya melalui
   `bootstrap_windows_dependencies.py`; bootstrapper memuat exact pip vendored
   setelah wheelhouse terverifikasi dan menerapkan
   `--no-index --require-hashes --no-deps --no-compile --force-reinstall`.
   Prosedur lengkap ada di `docs/WINDOWS_DEPENDENCY_LOCK.md`.
5. Service account least privilege, bukan administrator harian.
6. Untuk shadow, MT5 login memakai investor/read-only password,
   Algo Trading OFF, dan opsi disable automated trading through external
   Python API ON. Startup wajib membuktikan account/terminal flags tersebut.

## Credentials dan jaringan

- Simpan login broker, permit HMAC secret, manual-approval key, dan
  promotion-evidence verification key di Windows Credential Manager.
- Gunakan key evidence berbeda dari permit key, pisahkan role/custody, dan
  ekspor signed chain head ke Object Lock/WORM di luar VPS.
- Jangan masukkan credential ke `.env`, repository, command history, log, atau
  Task Scheduler argument.
- RDP tidak boleh terbuka ke internet. Gunakan VPN, MFA, IP restriction, dan
  account terpisah.
- Firewall hanya membuka koneksi outbound yang dibutuhkan terminal broker,
  heartbeat, audit export, backup, dan update yang disetujui.
- Challenger process tidak memiliki akses Credential Manager entry milik
  executor dan tidak memiliki filesystem write ke journal/outbox.
- Release source, lock, manifest, dan wheelhouse dimiliki release account dan
  read-only bagi runtime service account. Tidak boleh ada writer bersamaan saat
  dependency bootstrap atau startup verification.

## Layout proses

- Proses A: read-only broker exporter + decision/shadow runtime.
- Proses B: executor + reconciliation. Untuk fase shadow, proses B hanya
  reconcile/read dan policy tetap locked.
- SQLite journal berada di disk lokal NTFS; WAL/shm tidak diletakkan di network
  share. Backup memakai snapshot konsisten, bukan menyalin file database aktif
  secara sembarang.
- Audit bundle diekspor append-only ke host lain. Alarm heartbeat juga harus
  berada off-host agar VPS mati tetap terdeteksi.

### Legacy MQL5 file bridge

- `AI_SCALPER_DemoBridgeReader.mq5` sudah didekomisi menjadi diagnostic reader
  inert. Source tersebut tidak memiliki primitive order dan bukan executor.
- Saat shadow, jangan attach reader lama dan pertahankan Algo Trading `OFF`.
- Hapus/overwrite setiap `AI_SCALPER_DemoBridgeReader.ex5` lama karena binary
  hasil compile terdahulu dapat tetap berisi logika eksekusi yang sudah dicabut.
- `mt5_demo_bridge_outbox.json` wajib tetap
  `safe_to_demo_auto_order=false`, `live_allowed=false`, `max_lot=0.01`, dan
  `order_count=0`.
- Hanya adapter Python MT5 resmi yang boleh menjadi jalur eksekusi setelah gate
  manual-demo terpisah lolos. Decommission legacy reader tidak membuka gate itu.

## Startup dan watchdog

Task Scheduler dijalankan dengan service account saat boot dan mengikuti aturan:

1. Sinkronisasi waktu berhasil dan measured drift maksimal 1 detik.
2. Disk bebas minimal 1 GiB, SQLite `integrity_check` lulus, backup terakhir
   valid, dan off-host audit endpoint sehat.
3. MT5 terhubung ke exact keyed account identity/server yang diikat dalam
   release manifest; raw login tidak disimpan.
4. Read-only account/terminal attestation lulus:
   `account.trade_allowed=false`, `account.trade_expert=false`,
   `terminal.trade_allowed=false`, dan `terminal.tradeapi_disabled=true`.
5. Reconciliation penuh berjalan sebelum entry baru dipertimbangkan.
6. Jika journal state `SUBMITTING`, `ACKNOWLEDGED`, `PARTIAL`, `FILLED`, atau
   `UNCERTAIN`, jangan submit ulang; reconcile orders, positions, dan deals.
7. Kill switch yang latched tidak boleh di-reset oleh startup script.
8. Account environment, canonical/broker symbol map, instrument specification,
   news-feed signature/coverage, dan first post-close tick history harus lolos
   fail-closed validation.
9. Journal incarnation dan high-water anchor harus cocok dengan latest off-host
   audit export. Fresh DB replacement memerlukan permit baru dan manual review;
   restore backup lama tidak boleh start bila anchor off-host lebih maju.

Task harus memiliki restart backoff, maksimum restart per jam, stdout/stderr ke
event log terproteksi, dan alert bila proses terus crash. Jangan menaruh exact
`AI_SCALPER_EXECUTION_ARM` token sebagai default permanen di Task Scheduler.
Token harus terikat account/server/mode/journal yang aktif dan dibaca ulang oleh
executor; manual demo juga membutuhkan signed approval baru untuk exact intent.

## Release dan rollback

- Bangun release hanya dari clean commit dan simpan hash seluruh file.
- Verifikasi `pylock.windows-cp312.toml`, direct-pin manifest,
  config/profile hash, account alias, server, broker symbols, session calendar
  hash, journal identity, promotion evidence, dan permit sebelum start.
- Model champion immutable; challenger hanya shadow/offline.
- Rollback hanya ke release yang hash dan database migration-nya sudah diuji.
- Sebelum rollback, demote ke shadow, hentikan entry baru, reconcile broker, dan
  ekspor audit snapshot. Rollback tidak pernah mereset kill switch.

## Failure drills wajib

Jalankan di demo terisolasi dan simpan receipt:

- reboot VPS pada setiap state journal;
- restart MT5 dan executor;
- network partition sebelum dan sesudah `order_send`;
- order check sukses tetapi send reject/requote/partial/timeout;
- disk penuh dan SQLite contention/corruption simulation pada salinan;
- clock drift di atas 1 detik;
- orphan position, delayed deal history, externally closed position, missing
  SL/TP, dan duplicate intent;
- heartbeat/audit/backup endpoint gagal;
- wrong account/server, expired/tampered permit, missing credential, dan build
  hash mismatch.

Hasil aman berarti nol duplicate order, nol unexplained position, semua kondisi
ambigu menjadi `UNCERTAIN`, entry baru berhenti, dan alert sampai ke operator.

## Rollout

1. Shadow broker read-only.
2. Sepuluh manual-demo order terkontrol.
3. Demo-auto hanya setelah policy review terpisah; minimal 30 hari/50 fill dan
   minimal 20 XAU, tanpa incident critical.
4. XAUUSD live canary hanya setelah promotion permit baru dan approval manual.
5. EURUSD, USDJPY, lalu AUDUSD satu per tahap, masing-masing mengulang gate.

Tidak ada scaling otomatis di v1. Kenaikan lot atau risk cap memerlukan rencana
dan approval baru.
