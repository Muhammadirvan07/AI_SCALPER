# AI_SCALPER Progress — 2026-07-25

Status: **ATOMIC FIVE-ROLE BASE SUITE, CONFIGURED ANCESTRY, SHARED WINDOWS
PROVIDER PRIMITIVES, AND DECISION/EXECUTION/STATUS MONITOR PROVIDER
CANDIDATES COMPLETE LOCALLY / WINDOWS RUNTIME ACCEPTANCE PENDING /
DEMO-AUTO BLOCKED / LIVE DO NOT SHIP**

## Hasil pengembangan hari ini

Fondasi packaging candidate Windows sekarang memiliki satu entrypoint
fail-closed:

```text
build_windows_base_release_suite.py
```

Entrypoint tersebut membangun tepat lima base artifact dari satu clean Git
commit/tree:

- decision service;
- gated execution service;
- external status monitor;
- read-only shadow service yang memuat finalized-M15 publisher;
- configured-release operator tooling.

Setiap ZIP dan sidecar diverifikasi ulang dari bytes staging. Satu
`BASE_RELEASE_SUITE.json` mengikat seluruh hash, ukuran, release identity,
profile, commit/tree, effect, dan safety state. Final directory hanya terbit
melalui OS-level atomic no-replace rename. Destination concurrent tidak dapat
ditimpa.

Audit juga menemukan dan memperbaiki dua cacat sebelum operator Windows
memakai tool:

1. nama allowlist status monitor semula tidak sesuai file versioned resmi;
2. effect manifest semula tidak mengakui subprocess Git yang memang dibutuhkan
   untuk pemeriksaan packaging.

Manifest sekarang transparan: `git_subprocess=true` hanya untuk packaging,
sementara network, provider, credential, task, runtime/service process, MT5,
broker, activation, permit, dan order effect tetap false.

Audit lanjutan menemukan satu celah provenance pada jalur configured release.
Admission sebelumnya dapat membuktikan tiga configured archive memakai
commit/tree yang sama, tetapi belum membuktikan bahwa tiga base archive
tersebut merupakan role exact dari satu `BASE_RELEASE_SUITE.json`. Celah itu
sekarang ditutup:

1. verifier baru memverifikasi ulang tepat lima ZIP, lima sidecar, dan manifest
   suite dari bytes;
2. configured-release builder wajib menerima root suite dan hanya menerima
   canonical archive path untuk role yang sedang dibangun;
3. configured manifest mengikat suite identity, suite-manifest hash, role,
   base archive hash, dan base sidecar hash;
4. pre-manual admission mengulang verifikasi seluruh suite dan menolak
   configured release legacy, mixed-suite, role mismatch, atau supporting-role
   tamper.

Audit activation berikutnya menemukan siklus bukti pada provider-conformance
v1: packet meminta admission hash, sedangkan admission yang tersedia baru
dapat dibuat setelah provider evidence ditandatangani. Provider-conformance v2
sekarang menghapus input masa depan tersebut, menurunkan configured-release
set dari tiga exact identity, mempertahankan byte/hash v1 historis, dan
menetapkan urutan operator non-sirkular. Packet v2 tetap deny-only dan bukan
provider acceptance.

Regression paralel kemudian menemukan satu flake pada acceptance demo-auto
dormant. Fake adapter di test menggunakan account-runtime identity tetap,
sehingga proses regression normal dan optimized yang berjalan bersamaan saling
ditolak oleh production split-brain fence. Fence production terbukti bekerja
sesuai kontrak; fixture sekarang memakai identity sintetis unik per test
instance. Dua belas acceptance process paralel seluruhnya kembali `FILLED`,
sedangkan dedicated split-brain test tetap memakai identity bersama dan tetap
membuktikan runtime kedua ditolak.

Slice berikutnya menutup provider nyata untuk role `DECISION` tanpa membuka
broker authority:

1. strict public parser/verifier merekonstruksi external IPC dan producer
   checkpoint/CAS acknowledgement tanpa mengekspos minting seal;
2. Windows Credential Manager provider hanya dapat membaca exact
   prefix/key/fingerprint yang direview;
3. trusted UTC membutuhkan fresh signed external attestation dan menolak
   regression/drift;
4. external directory CAS memisahkan domain IPC dan producer, menolak
   symlink/reparse/tamper/fork/rollback/timeout, dan tidak pernah membuat
   custody signature sendiri;
5. provider composition memverifikasi seluruh cross-binding dan semua path
   sebelum credential atau SQLite dibuka;
6. offline operator tooling menghasilkan tepat empat file overlay secara
   deterministic/create-exclusive dan memvalidasinya tanpa mengimpor factory
   atau menyentuh provider;
7. runtime foundation hanya masuk base release `DECISION`; generator/validator
   hanya masuk configured-release tooling.

Status pack tetap `EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED`. Implementasi lokal
ini belum membuktikan Credential Manager ACL, off-host/WORM custody, signed
clock issuer, exact Windows configured release, launcher attestation, atau
Task Scheduler service identity.

Audit integrasi berikutnya menemukan dua gap pada jalur configured Decision:

1. generic preparer mengikat `reviewed_factory_template_sha256` ke exact bytes
   member template pada base archive, sedangkan loader Decision dan Status
   Monitor membandingkannya dengan semantic contract projection yang berbeda;
2. alur operator sebelumnya menambahkan factory manifest langsung ke root
   provider pack sehingga exact evidence empat-file tidak lagi immutable.

Keduanya sekarang ditutup. Loader menurunkan expected template hash dari exact
nested base inventory yang sudah diverifikasi. Assembler Decision baru
mempertahankan immutable `provider-pack/`, memakai working
`configured-overlay/` terpisah, menurunkan bootstrap binding, membangun dan
memverifikasi suite-bound configured ZIP, menghasilkan exact seven-provider
factory template, lalu menulis closed receipt terakhir. Assembler dan
validator hanya berada dalam configured-release operator tooling dan seluruh
authority tetap false.

Review boundary lintas service selanjutnya menemukan bahwa credential lookup
dan trusted-clock implementation masih melekat pada Decision foundation.
Menyalin logika tersebut ke Status Monitor akan menciptakan drift security,
sedangkan mengimpor seluruh Decision provider pack akan melanggar service
isolation. Prasyarat ini sekarang ditutup:

1. satu modul standard-library-only menjadi implementasi tunggal exact
   read-only Windows Credential Manager dan signed monotonic UTC;
2. Decision mempertahankan import lama dengan exact type identity, schema,
   HMAC domain, reason code, freshness, drift, dan monotonic behavior;
3. key ID maupun target Credential Manager yang bertabrakan secara
   case-insensitive ditolak sebelum backend dibaca;
4. primitive hanya masuk base release `DECISION`, `EXECUTION`, dan
   `STATUS_MONITOR`, tidak masuk shadow atau configured tooling;
5. Status Monitor builder memberi exception `ctypes` hanya pada exact shared
   primitive file, sementara import terlarang di file lain tetap ditolak;
6. provider implementation hash v2 mengikat exact path+SHA-256 Decision
   foundation dan shared primitive bytes dari verified base ZIP, serta
   menolak member hilang/duplikat sebelum menulis output.

Ekstraksi primitive tidak membaca credential saat build/validation. Slice
berikutnya sekarang sudah menutup Status Monitor provider boundary:

1. dua belas exact provider role memakai shared credential/trusted-clock,
   signed snapshot, external checkpoint CAS, incident latch, serta strict
   preprovisioned outbox/transport;
2. seluruh path/key/identity/provider hash divalidasi sebelum credential,
   SQLite, atau provider access;
3. outbox/transport production menolak state yang belum diprovision,
   symlink/reparse, schema drift, dan integrity failure tanpa membuat state;
4. offline generator membuat exact four-file secret-free pack secara
   deterministic/create-exclusive tanpa mengimpor generated factory;
5. assembler menjaga pack asli immutable, membuat working overlay, membangun
   suite-bound configured ZIP, menurunkan twelve-provider factory template,
   dan menyegel exact 15-file candidate;
6. assembler/validator hanya berada di configured-release tooling dan tidak
   memiliki provider, task, MT5, broker, atau order effect.

Status pack tetap `EXTERNAL_PROVIDER_ACCEPTANCE_REQUIRED`; candidate tetap
`EXTERNAL_PROVIDER_CONFORMANCE_REQUIRED`.

Execution provider boundary berikutnya juga sudah ditutup secara source lokal:

1. exact 46-port inventory direkonstruksi dari authoritative factory contract,
   termasuk 37 role wajib DEMO, sembilan role opsional, dan dua belas purpose
   Credential Manager;
2. signed clock memakai trust domain independen dan tidak boleh memakai ulang
   key ID maupun fingerprint Execution;
3. service config, production config, bootstrap binding, mode, policy lock,
   credential backend, provider value, dan heartbeat custody diverifikasi
   sebelum factory result disegel;
4. `mt5_module` selalu `None` saat composition; hanya production bootstrap
   yang kelak boleh melakukan import/attestation MT5;
5. generated factory tanpa externally reviewed Windows runtime menolak dengan
   `EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`;
6. offline four-file generator/validator dan suite-bound configured-candidate
   assembler/validator tidak melakukan credential, SQLite, network, task,
   process, MT5, atau broker effect.

Status lokal Execution adalah
`PASS_LOCALLY_EXTERNAL_RUNTIME_REQUIRED`. Exact Windows provider state,
credential custody, CAS/WORM/clock/news/reconciliation authority, dan
independent conformance tetap pekerjaan eksternal.

Execution launcher sekarang menutup satu boundary tambahan sebelum service
startup:

1. `--validate-only` tetap pure static dan tidak membaca trust/provider;
2. `--materialize-only` wajib memiliki external RSA launcher attestation
   yang dipin ke `WINDOWS_GATED_EXECUTION_SERVICE_V1`;
3. exact reviewed factory dipanggil dan provider composition dapat dibuktikan,
   tetapi production bootstrap tidak dimaterialisasi;
4. runner, signal handler, MT5 import/initialize, authorization consumption,
   dan broker mutation tetap tidak dijalankan;
5. trust expiry setelah factory invocation tetap ditolak sebelum runner;
6. exact bootstrap/config/ports dan execution locks diperiksa ulang; bahkan
   injeksi MT5 pascakonstruksi ditolak sebelum runner;
7. output sukses hanya
   `FACTORY_MATERIALIZED_BROKER_NOT_INITIALIZED`.

Semantik ini lulus lokal; Windows receipt aktual masih menunggu externally
reviewed provider runtime. Default generated factory tetap menolak
`EXECUTION_PROVIDER_RUNTIME_NOT_CONFIGURED`.

## Aktivasi registrasi evidence Phillip Commodity

Proposal manual
`597b4c5a1c20c836c468652019bc1e50d4545912c4b96920494fef62805421e4`
telah diterapkan sebagai perubahan exact pada tiga file konfigurasi:

1. signed regulatory observation Commodity menggantikan observation lama;
2. hanya profile `phillip-commodity` berubah menjadi
   `registration_enabled=true`;
3. template Commodity berubah ke schema v3 dan mengikat signed pre-window
   calendar review.

Canonical SHA-256 after-image yang diverifikasi:

```text
broker_candidates.phase3.json =
856a980af52bc01f17f0185e7cdf35572fa06785e2beb39b758ffcd30e93519e
broker_evidence_profiles.v1.json =
0a6b3cb4abe05689dd67dfe363728eb53b4ce822e17f22618f5e6f84f6fcf7cf
phillip_commodity_calendar_window_01.template.json =
1c24fc974f08cd602dc6462ada165a572f182abea685aa0e44f17a6f8a4ef871
```

Aktivasi ini hanya membuka pembuatan immutable diagnostic forward contract.
Ia tidak memberi credential broker, permit, arm flag, order, demo-auto,
promotion, atau live authority. Profile `phillip-fx` tetap disabled dan
memerlukan review lane terpisah.

Bootstrap registrasi juga telah di-hardening: Git identity sekarang wajib
berasal dari exact repository root yang eksplisit dan absolut, worktree harus
tetap bersih, serta commit/tree harus berupa object ID valid dan stabil selama
registrasi. Validasi Git, ruleset, broker binding, dan batas waktu pre-window
diselesaikan sebelum frozen snapshot dibuat. Invokasi dari repository lain,
identity kosong/malformed, identity drift, atau registrasi pada/sesudah
observation start gagal tanpa membuat snapshot baru.

Aktivasi tersebut sudah masuk commit `334d61c` dan dipush ke
`agent/live-grade-phase3`. Audit pra-registrasi selanjutnya menemukan bahwa
entry point broker-neutral masih mewarisi autodiscovery terminal dari jalur XM
lama. Gap multi-terminal itu sekarang ditutup secara lokal:

1. seluruh kandidat non-XM wajib memberikan exact absolute
   `--terminal-path`;
2. missing, relative, directory, symlink, wrong-name, atau missing executable
   ditolak sebelum operational journal, dependency runtime, credential, atau
   MT5 digunakan;
3. `MetaTrader5.initialize()` menerima hanya exact resolved path;
4. operational receipt mengikat mode `EXACT_PATH` dan SHA-256 path
   ternormalisasi tanpa menyimpan raw path;
5. zero-argument autodiscovery hanya dipertahankan untuk backward-compatible
   XM legacy.

## Bukti lokal

- Shared-provider-primitives spec validator: `98/100`, grade A, nol error.
  Satu warning generik meminta HTTP endpoint meskipun kontrak ini secara
  eksplisit bukan HTTP.
- Shared primitive/provider/release/candidate focused suite:
  `61/61 PASS` normal dan optimized.
- Decision-provider-pack spec validator: `100/100`, grade A, tanpa
  error/warning.
- Decision-provider focused suite: `28/28 PASS` normal dan optimized.
- Decision/configured/suite integration suite: `196/196 PASS` normal dan
  optimized.
- Configured-template parity and Decision-candidate cluster: `169/169 PASS`
  normal dan optimized.
- Decision configured-candidate focused suite: `7/7 PASS` normal dan
  optimized.
- Status Monitor provider-pack spec validator: `100/100`, grade A, tanpa
  error/warning.
- Status Monitor candidate/pack/runtime lintas-batas: `143/143 PASS` normal
  dan optimized.
- Status Monitor configured-candidate focused suite: `5/5 PASS`.
- Execution provider/release/candidate focused suite: `87/87 PASS` normal dan
  optimized.
- Execution-provider-pack spec validator: `98/100`, grade A, nol error; satu
  warning generik non-applicable karena kontraknya bukan HTTP.
- Execution factory materialization probe/bootstrap/release-builder cluster:
  `50/50 PASS` normal dan optimized.
- Execution factory materialization probe spec validator: `98/100`, grade A,
  nol error; satu warning HTTP generik yang tidak applicable untuk CLI lokal.
- Configured-release tooling suite: `10/10 PASS` normal dan optimized.
- Acceptance/adversarial suite: `19/19 PASS` normal dan optimized.
- Suite-binding/provider-v2 focused regression: `95/95 PASS` normal dan
  optimized.
- Full project regression termasuk registration dan exact-terminal
  hardening: `1.562/1.562 PASS` normal.
- Full tracked-project regression dengan optimization enabled:
  `1.562/1.562 PASS`.
- Focused post-activation evidence integration regression:
  `100/100 PASS`.
- Exact-terminal collector dan broker evidence CLI regression:
  `30/30 PASS`.
- Windows decision/execution/status/base/tooling packaging regression yang
  aktual: `87/87 PASS`.
- Focused activation/packaging regression normal dan optimized dijalankan
  bersamaan: `155/155 PASS` pada masing-masing proses.
- Dormant demo-auto acceptance dijalankan dalam 12 proses paralel:
  `12/12 FILLED`, tanpa `ACCOUNT_RUNTIME_FENCE_UNAVAILABLE`.
- Dua independent clean-repository build menggunakan kelima builder nyata:
  seluruh 5 ZIP, 5 sidecar, dan suite manifest byte-identical.
- Windows dependency lock, install manifest, dan CycloneDX SBOM: PASS.
- Decision, execution, dan status-monitor port validator: PASS dengan
  `production_execution_ready=false`.
- Secret/private-key, unsafe eval/deserialization, `shell=True`, network,
  credential, MT5, dan order-capability scan pada surface baru: tidak ada
  finding.

Direktori dashboard yang belum masuk fase integrasi tidak dibaca, dimodifikasi,
atau dimasukkan ke test/release.

## Safety state

```text
live_allowed = false
safe_to_demo_auto_order = false
max_lot = 0.01
promotion_eligible = false
```

Execution ZIP tetap memiliki `order_capability=GATED_PRESENT` secara dormant.
Suite boundary, empat role lain, seluruh execution/promotion state, dan semua
broker-order authority tetap tertutup. Satu-satunya gate yang terbuka adalah
registrasi evidence diagnostic untuk `phillip-commodity`.

## Posisi roadmap

Software foundation dan packaging lokal sudah cukup untuk membuat candidate
baru. Demo-auto soak belum boleh dimulai hanya karena test lokal hijau.
Urutan berikutnya:

1. commit/push exact-terminal collector hardening tanpa direktori dashboard;
2. clean pull commit baru pada Windows, prepare signed Commodity plan/calendar, lalu
   register immutable diagnostic forward contract;
3. mulai read-only Commodity evidence collection pada eligible M15 boundary;
4. build ulang atomic five-role suite dari commit baru dan verifikasi SHA-256
   serta suite manifest;
5. siapkan canonical secret-free Decision, Execution, dan Status Monitor
   provider input dari exact reviewed Windows custody paths/key fingerprints;
6. generate/validate ketiga provider pack dan assemble/validate ketiga
   immutable configured candidate;
7. provision externally reviewed Execution provider state/hooks pada Windows,
   jalankan exact RSA-bound `--materialize-only` probe, lalu buktikan restart
   behavior tanpa membuka policy;
8. verifikasi ketiga configured identity dan buat operations plan/review,
   provider-conformance v2, serta independent validation receipt;
9. kumpulkan sembilan signed pre-manual observations lalu luluskan exact
   configured-release admission;
10. jalankan 10 controlled manual-demo lifecycles dengan review manusia;
11. setelah hasil manual-demo diterima, lakukan demo-auto activation review
    terpisah;
12. baru mulai demo-auto soak 30 hari, 50 broker-reconciled closed fills, dan
   minimal 20 XAUUSD closed fills.

Live trading tetap tahap sesudah soak, statistical lane gates, failure drills,
dan approval manual. Frontend dashboard baru akan dihubungkan ke read-only
status/receipt surface setelah demo soak berfungsi; dashboard tidak akan
mendapat credential, permit, arm, atau order authority.
