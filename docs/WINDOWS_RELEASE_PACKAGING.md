# Windows Release Packaging

Status saat ini tetap **READ-ONLY SHADOW / NOT_READY**. Builder mempertahankan
profile terisolasi untuk deployment/tooling, minimal read-only broker shadow,
brokerless decision-only service, dan external status-only monitor. Tidak satu
pun profile tersebut membuka manual-demo, demo-auto, atau live.

## Mengapa repository tidak boleh langsung diarsipkan

Repository development masih memiliki data cache CSV, status JSON, histori
paper/demo, backup, snapshot runtime, evidence store, dan ZIP lama. Sebagian
bahkan masih tracked karena berasal dari fase proyek sebelumnya. `git archive`,
`Compress-Archive *`, atau builder migration/context tidak boleh digunakan
sebagai release Windows.

Deployment/tooling bundle Windows hanya boleh dibuat oleh
`build_windows_release.py` berdasarkan daftar exact di
`config/windows_release_allowlist.v1.json`. Tidak ada glob, scan extension,
atau fallback yang otomatis menambahkan file baru.

Bundle ini memiliki generator, bootstrapper, setup credential, registration
tool, dan network-capable vulnerability collector karena current build identity
masih mengikat source tooling tersebut. Karena itu:

- bundle hanya boleh dipegang/dijalankan release operator;
- production service account tidak boleh menjalankan bundle ini;
- source tree tidak boleh langsung dijadikan Task Scheduler working directory;
- service account hanya boleh menerima profile service terpisah, bukan bundle
  tooling ini.

Profile tooling juga membawa runner crypto weekend read-only. Runner tersebut
hanya memakai allowlisted public GET Binance/Coinbase, tanpa credential maupun
order API, dan tetap bukan service-runtime production.
M15 champion dan M5 challenger dibundel sebagai entrypoint diagnostic berbeda;
keduanya memiliki config serta journal domain terpisah dan tidak memiliki
primitive execution.

Bundle juga membawa `run_mt5_readonly_preflight.py`. Tool preparation-only ini
memeriksa binding kandidat dan safety flags terminal tanpa credential dan
tanpa membuka full discovery gate. Opsi `--output` dapat menulis receipt
sanitasi create-exclusive untuk audit operator; receipt tersebut tetap
non-evidence dan non-promotional.

Bundle operator juga membawa pipeline evidence broker-neutral:
`setup_broker_evidence_key.py`, `mt5_readonly_discovery.py`,
`prepare_broker_window.py`, `build_broker_calendar.py`,
`register_broker_forward_contract.py`, dan `run_broker_shadow_once.py`.
Tooling review regulatory (`setup_regulatory_review_key.py`,
`prepare_broker_registration_review.py`,
`sign_broker_registration_review.py`, dan
`assemble_broker_registration_review.py`) juga hanya berada di bundle
operator; ia tidak masuk minimal shadow service. Reviewer key tetap berada di
Windows Credential Manager dan semua output review mempertahankan registration
serta order capability disabled.
`run_manual_demo_readiness.py` juga hanya berada di bundle operator. Ia membaca
tracked candidate/profile/readiness policy dan menghasilkan daftar blocker
non-mutating. Modul/command ini sengaja tidak masuk allowlist minimal shadow
service dan tidak membawa MT5 adapter, executor, permit issuer, approval signer,
atau order primitive.
Masing-masing mengikat exact candidate profile. FBS saat ini sengaja ditolak
oleh external/registration gate, sehingga keberadaan file di bundle tidak
mengaktifkan evidence maupun order.

Build identity shadow kini dapat dikomposisikan per broker dari exact config
files. Profile `WINDOWS_READ_ONLY_SHADOW_SERVICE_V1` memakai exact allowlist
`config/windows_shadow_service_allowlist.v1.json`. Ia memuat 25 file closure
runtime read-only yang telah direview dan tidak membawa setup/generator,
credential bootstrap, executor, MT5 mutation adapter, atau order primitive.
Actual clean-checkout build dan two-host/two-build reproducibility receipt tetap
harus dikumpulkan pada exact Windows target sebelum service dipasang.

Profile `WINDOWS_DECISION_SERVICE_V1` dibangun oleh dedicated
`build_windows_decision_release.py` dari
`config/windows_decision_service_allowlist.v1.json`. Profile ini memuat
brokerless finalized-M15 producer, shared decision core, signed decision IPC,
exact strategy dependencies, static factory contract, validate-only runner,
dan dependency lock khusus tanpa MetaTrader5/keyring. Executor, risk, permit,
reconciliation, broker adapter, credential, data, dan runtime state ditolak.
Panduan lengkap ada di `docs/WINDOWS_DECISION_SERVICE_RELEASE.md`.

Profile `WINDOWS_EXTERNAL_STATUS_MONITOR_V1` dibangun oleh dedicated
`build_windows_status_monitor_release.py` dari
`config/windows_status_monitor_allowlist.v1.json`. Release stdlib-only ini
memuat status snapshot/assessment/checkpoint/incident contract, static
12-provider factory template, exact configured-release verifier, public RSA
launcher verifier, production loader, validator, dan bounded runner. Profile
ini tidak membawa MetaTrader5, risk, permit, executor, reconciliation,
credential resolver, process/network tooling, maupun order primitive.

Factory/config/provider deployment-specific tidak boleh disalin ke base
decision atau execution release setelah ekstraksi. Repository menyediakan
profile operator terpisah
`WINDOWS_CONFIGURED_RELEASE_OPERATOR_TOOLING_V1`, dibangun oleh
`build_windows_configured_release_tooling.py` dari exact allowlist
`config/windows_configured_release_tooling_allowlist.v1.json`. Bundle
stdlib-only ini membuat dan memverifikasi configured release dengan identity
baru tanpa mengimpor provider, membaca credential, menginisialisasi MT5,
memasang task, atau melakukan broker mutation. Generic operator bundle tetap
mempertahankan byte-level order-primitive prohibition dan tidak dilonggarkan.
Panduan lengkap ada di
`docs/WINDOWS_CONFIGURED_SERVICE_RELEASE.md`.

## Gate builder

Builder menolak release bila:

- Git worktree tidak bersih atau ada file untracked;
- file allowlist tidak tracked, hilang, berubah selama build, terlalu besar,
  bukan regular file, atau melalui symlink;
- path absolut, traversal, collision case-insensitive, runtime/evidence/data
  directory, backup, history, CSV, ZIP, database, log, bytecode, credential,
  private key, atau JSON sensitif ditemukan;
- modul/cabang legacy yang memiliki execution capability, termasuk executor,
  MT5 adapter, reconciliation runtime, MQL5, VPS package, dan paper executor;
- primitive order ditemukan dalam source profile read-only, termasuk
  `order_send`, `order_check`, `TRADE_ACTION_*`, `ORDER_TYPE_BUY/SELL`,
  `CTrade`, atau pemanggilan `Buy`/`Sell`;
- root field allowlist bertambah, berkurang, atau berubah dari schema exact;
- import Python lokal tidak ikut dalam allowlist;
- safety lock bukan persis `live_allowed=false`,
  `safe_to_demo_auto_order=false`, `max_lot=0.01`, dan
  `order_capability=DISABLED`;
- usage policy tidak persis sama dengan policy profile terpilih: operator
  tooling tetap `RELEASE_OPERATOR_ONLY` dan service profile tetap
  `READ_ONLY_SHADOW_SERVICE` dengan broker mutation disabled;
- output ditempatkan di dalam repository atau destination sudah ada.

ZIP dan `RELEASE_MANIFEST.json` dibuat deterministik. Manifest mengikat exact
Git commit/tree, hash raw allowlist, hash dan ukuran setiap source file, safety
policy, serta `release_identity_sha256`. Manifest sidecar sama persis dengan
manifest di dalam ZIP.

Source yang masuk ke ZIP dibaca dari immutable Git blob pada exact release
commit, bukan dari byte worktree. Ini mempertahankan identitas yang sama pada
checkout Windows yang secara sah mematerialisasi file teks sebagai CRLF,
sementara commit Git menyimpannya sebagai LF. Git worktree tetap wajib bersih
sebelum dan sesudah build; symlink, file yang hilang, path tidak tracked, dan
perubahan commit/tree tetap ditolak.

## Build

Jalankan dari clean checkout. Tulis output di luar repository:

```powershell
python -I -S -B .\build_windows_release.py `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-deployment-tooling-v1.zip
```

Simpan SHA-256 ZIP dan release identity ke release receipt/off-host audit.
Jangan menjalankan ZIP ini sebagai service runtime. Wheelhouse lengkap, broker
discovery/calendar, forward contract, journal, credential, dan validation
evidence adalah artefak terpisah. Jangan menyalin `data/`, `runtime_state/`,
`runtime_snapshots/`, atau `validation_artifacts/` ke release source.

Untuk menghasilkan minimal read-only service bundle dari clean checkout:

```powershell
python -I -S -B .\build_windows_release.py `
  --allowlist .\config\windows_shadow_service_allowlist.v1.json `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-readonly-shadow-service-v1.zip
```

Untuk menghasilkan decision-only service sebagai release yang terpisah:

```powershell
python -B .\build_windows_decision_release.py `
  --allowlist .\config\windows_decision_service_allowlist.v1.json `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-decision-service-v1.zip
```

Untuk menghasilkan external status-monitor service sebagai release ketiga:

```powershell
python -B .\build_windows_status_monitor_release.py `
  --allowlist .\config\windows_status_monitor_allowlist.v1.json `
  --output C:\AI_SCALPER_RELEASES\ai-scalper-status-monitor-v1.zip
```

Bangun bundle operator configured-release yang minimal:

```powershell
python -B .\build_windows_configured_release_tooling.py `
  --output C:\AI_SCALPER_RELEASES\configured-release-tooling-v1.zip
```

Gunakan bundle tersebut untuk mengikat masing-masing base release dengan exact
secret-free reviewed overlay. Hasilnya adalah decision-configured dan
execution-configured ZIP dengan identity baru. Verifikasi keduanya terhadap
configured identity dan base identity yang dipin off-host. Extract dan jalankan
configured ZIP; jangan menyalin factory ke base release setelah ekstraksi.

Decision, execution, dan status-monitor bundle wajib menggunakan configured
release identity, service account, root, state directory, dan in-release
factory manifest yang berbeda. Monitor juga wajib memakai checkpoint/latch
custody serta heartbeat/alert destination yang terpisah dari authority
execution. Base identity dipertahankan sebagai provenance, bukan identity
proses akhir.

Bangun artefak yang sama pada dua clean Windows CPython 3.12 environments.
Masukkan kedua observasi exact ke `live_runtime.release_reproducibility`, lalu
simpan signed comparison receipt. Receipt membuktikan kesamaan build; ia tidak
membuktikan broker evidence, OS hardening, WORM custody, atau live readiness.

## Perubahan allowlist

Penambahan file adalah perubahan security-sensitive:

1. Tambahkan path exact; jangan menambah prefix atau wildcard.
2. Pastikan local-import closure dan seluruh test lulus.
3. Review bahwa file bukan state, history, backup, credential, atau evidence.
   Builder tetap akan menolak execution path dan order primitive walaupun path
   tersebut sengaja dimasukkan ke allowlist.
4. Buat clean commit baru; release lama tidak boleh ditimpa.
5. Jika service profile berubah, pertahankan minimal import closure; jangan
   mewariskan generator, setup, executor, atau operator-only tooling.
6. Untuk fase manual-demo atau live, buat versi/profile baru dan approval
   terpisah. Jangan menambahkan executor ke deployment profile ini.
